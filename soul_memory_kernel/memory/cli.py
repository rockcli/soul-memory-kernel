"""``family-ai-memory`` —— 成人本机控制面 CLI（W5）。

契约依据：``docs/M2-CONTRACT.md`` §116-121（D3：确认 / 纠正 / 删除**只能**由成人经本
CLI 完成）、§2.4（actor 权限边界）、§3.7（M2.1 写门禁）、§5.1（记录 id 与正文不进日志）、
§6.1.1（grant store 与控制面**同一个时钟**）、§7.3（删除报告）、§10.1（接缝）。

## 四条硬约束，逐条说明实现方式

**1. 身份只来自进程本身。** ``adult_control_plane`` 由 :func:`_adult_actor` **固定构造**，
:data:`ADULT_ACTOR_ID` 是模块常量。argparse **没有任何**接受 actor kind / actor id 的
参数 —— 「冒充 actor」不是一个可以被拒绝的输入，而是一个**不存在**的输入。
（D1：grant 与 actor 都不是身份认证；它们只约束「应用这次能做什么」。）

**2. 不读凭证。** 本模块**不调用** :func:`soul_memory_kernel.config.load_settings` ——
那会要求 API key。它对 ``--env`` / 仓库根的 ``.env`` 的处理是
**只解析两个记忆键（``MEMORY_DB_PATH`` / ``MEMORY_DB``），不使用也不保留其他键**：
逐行流式读取，命中白名单以外的行**立刻丢弃**，既不拼进任何字典也不进任何变量。
进程环境同理 —— 只按名字取那两个键，**不复制整个 ``os.environ``**。
控制面工具与实时语音会话无关，让它持有 provider 凭证没有收益，只有风险。

**3. 不写日志。** 本模块**不创建任何 JSONL / 日志文件**，只写 stdout / stderr。
契约 §5.1 的纪律是「记录 id 与正文不进日志」；**不写日志**是这条纪律的最强形式。
``list`` / ``inspect`` 会把正文打到**终端**（成人自查），这是设计允许的 ——
终端不是日志。错误输出**只打异常类型 + 固定指引**，不打异常消息
（``RecordNotFound`` 的消息里带 record id，``StoreError`` 可能带后续实现细节）。

**4. 同一个时钟。** :func:`_open` 构造一个 ``clock`` 并**同时**交给
``SqliteGrantStore`` 与 ``MemoryService``（§6.1.1：两侧判定必须同源，否则要么合法
grant 签不出来，要么超前 grant 被放行）。

**打开即迁移。** 任何写连接打开 v1 库都会就地升到 v2（§9.0）。因此
``family-ai-memory list`` 也是完成迁移的标准动作 —— 它在读取前先开一次写连接完成迁移。
``console`` 的只读接缝做不到这件事，遇到 v1 会 fail-loud 并提示先跑这个命令。
只读命令不**创建**库（路径写错不该表现成「库是空的」），但会**迁移**已存在的旧库。

## 子命令与契约的对应

| 子命令 | 契约 | 说明 |
|---|---|---|
| ``propose`` | §3.7（A12） | **W5 增补**：契约的子命令清单没有它，但 A12 的「成人 CLI 走 ``adult_control_plane``」要求它存在 |
| ``list`` / ``inspect`` | D3 / §4.3 | 成人自查；``adult_list`` 只出元数据，``adult_inspect`` 出正文；候选在 ``inspect`` 下追加一次控制面复审读取（M2.2） |
| ``confirm`` / ``correct`` / ``delete`` | D3 / §2.4 | 只能由成人完成的三件事；``confirm`` 可带 ``--reassign-owner``（D13；M2.3 起改归属与确认是**同一次写入**，不存在「归属已改、确认未完成」的中间态） |
| ``sweep`` | §4.6 / §6.2 | 把到期状态落成 ``DECAYED`` / 硬删到期候选 |
| ``grant issue`` / ``grant revoke`` | D1 / §2.4 | 签发与撤销短期会话授权；``--action`` 只接受**可签发**动作（免 grant 的动作除外，E4） |

## 控制面访问（M2.2 §4.2）

`list` / `inspect` 的查询走 ``SessionAccess.for_control_plane()`` —— 契约指定的
**唯一**控制面访问构造入口（``SessionAccess`` 的第三个 ``session_mode`` 取值）。
它不改 `list` 的判定（动作仍是 `read_model`），只是让 CLI 真的是控制面；
`inspect` 命中的候选正文来自 §4.3 新增的 ``control_plane_review`` purpose
（动作 `review_control_plane`，免 grant、只跳过 `status_denied`）。
「只能由本机 CLI 构造」由 AST 契约测试锁死（``tests/test_control_plane_review.py``）。

## 破坏性操作一律二次确认

``delete`` / ``sweep`` / ``grant revoke`` 需要 ``--yes`` 或交互式确认。
非 TTY 且没有 ``--yes`` 时**直接拒绝**（退出码 3），不静默执行 ——
「没人可问」不等于「可以默认同意」。
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from soul_memory_kernel.memory.grants import GRANTABLE_ACTIONS, SqliteGrantStore
from soul_memory_kernel.memory.model import (
    DEFAULT_TTL_CANDIDATE_DAYS,
    M2_1_ALLOWED_SCOPES,
    Actor,
    MemoryCandidate,
    MemoryCorrection,
    MemoryRecord,
    RetentionPolicy,
    SnapshotEntry,
    SourceSession,
)
from soul_memory_kernel.memory.pending import (
    MAX_PENDING_FIELD_CHARS,
    PENDING_STATUSES,
    PendingCandidate,
    PendingItem,
    SqlitePendingStore,
)
from soul_memory_kernel.memory.projection import MAX_PROJECTED_MEMORIES
from soul_memory_kernel.memory.service import (
    MAX_CONTENT_CHARS,
    MemoryService,
    MemoryServiceError,
    MemoryValidationError,
    RecordNotFound,
    StoreError,
)
from soul_memory_kernel.memory.store import MAX_GRANT_TTL_SECONDS, SqliteMemoryStore
from soul_memory_kernel.soul.core import SHARED_SESSION_AUDIENCE_ID
from soul_memory_kernel.soul.policy import SessionAccess

#: 控制面 actor 的固定标识。**唯一来源** —— 不接受任何 argv / env 输入（约束 1）。
ADULT_ACTOR_ID = "family-ai-memory"

#: 非交互场景必须显式给出的开关（约束：破坏性操作二次确认）。
CONFIRM_FLAG = "--yes"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = REPO_ROOT / "data" / "memory.sqlite3"

#: ``.env`` 里**只**读这两个键。顺序即优先级。
_MEMORY_ENV_KEYS: tuple[str, ...] = ("MEMORY_DB_PATH", "MEMORY_DB")

#: 退出码：与 console 对齐 —— 2 = 配置/用法问题，1 = 操作失败，3 = 用户放弃。
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2
EXIT_ABORTED = 3

#: 异常类型 → **固定指引**。错误输出只说类型与这一行，不回显异常消息（约束 3）。
_GUIDANCE: dict[str, str] = {
    "ConfigError": "请检查记忆库路径(`--db`/`MEMORY_DB_PATH`)与目录权限后重试。",
    "MemoryValidationError": "输入不满足契约约束,请检查参数后重试。",
    "AuthorizationError": "本次操作未被授权,或目标记录的 scope 在 M2.1 未启用。",
    "IllegalTransition": "目标记录当前状态不允许该操作,请先 `list` 查看状态。",
    "RecordNotFound": "目标记录不存在,请用 `list` 重新获取 id。",
    "StoreError": "记忆库不可用或完整性检查未通过,请检查文件与权限后重试。",
    "CliError": "请检查记忆库路径(`--db`/`MEMORY_DB_PATH`)，或先用写命令创建它。",
    "MemoryServiceError": "记忆操作失败,请检查参数与记忆库状态。",
}


class CliError(Exception):
    """CLI 自身的用法/配置错误（不是记忆层的异常）。"""


def _system_clock() -> str:
    """控制面时钟：当前 UTC 时刻，ISO-8601。**同一个实例**交给 grants 与 service。"""

    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# 配置解析（只认记忆相关的两个键，绝不读凭证）
# ---------------------------------------------------------------------------


def _env_file_value(path: Path, keys: Sequence[str]) -> str | None:
    """**只解析 ``keys`` 里的键，不使用也不保留其他键**（B5）。

    逐行流式读取（不把整份文件读进内存），命中白名单以外的行立刻丢弃 ——
    既不入字典也不入变量，因此凭证键不可能被带出这个函数。返回第一个命中的非空值。

    只做最小解析：``KEY=VALUE``、忽略空行与 ``#`` 注释、去掉值两侧的成对引号。
    不是通用 dotenv —— 通用实现会引入「把整份文件读进环境」的行为，那正是要避免的。
    """

    wanted = set(keys)
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return None
    with handle:
        for line in handle:  # 流式：一行一行过，不 read_text()
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            if key not in wanted:
                continue  # 白名单之外：立刻丢弃
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                return value
    return None


def resolve_db_path(
    *, explicit: Path | None, env_file: Path | None, environ: Mapping[str, str]
) -> Path:
    """``--db`` → 进程环境 → ``.env`` 的记忆键 → 仓库默认。三条来源都 ``expanduser()``。

    ``environ`` 只要 mapping（**不要求也不复制**一份完整环境，B5）。
    """

    # A3：三条来源都要 ``expanduser()`` —— ``~`` 在 shell 里可能没被展开
    # （引号里的 ``~/x``、``.env`` 里写的 ``~/x`` 都不会），不展开就会在 cwd 下
    # 造出一个名字叫 ``~`` 的目录，而用户以为写到了家目录。
    if explicit is not None:
        return explicit.expanduser()
    for key in _MEMORY_ENV_KEYS:
        value = environ.get(key)
        if value:
            return Path(value).expanduser()
    if env_file is not None and env_file.exists():
        value = _env_file_value(env_file, _MEMORY_ENV_KEYS)
        if value:
            return Path(value).expanduser()
    return DEFAULT_DB_PATH.expanduser()


# ---------------------------------------------------------------------------
# 记忆层的装配
# ---------------------------------------------------------------------------


class _Runtime:
    """CLI 一次调用用到的三个真实对象 + **同一个**时钟。"""

    def __init__(self, db_path: Path, clock: Callable[[], str]) -> None:
        self.db_path = db_path
        self.clock = clock
        self.store = SqliteMemoryStore(db_path)
        # §6.1.1：显式注入**同一个** clock。默认的系统时刻会让 issue() 的「不得超前」
        # 判定与 authorize() 的 expired/not_yet_valid 判定各自读一次墙钟。
        self.grants = SqliteGrantStore(db_path, clock=clock)
        self.pending = SqlitePendingStore(db_path, clock=clock)
        self.service = MemoryService(
            store=self.store, grants=self.grants, clock=clock, retention=RetentionPolicy()
        )

    def session_id(self) -> str:
        """控制面**不是**会话：每次调用一个新的、不参与任何 grant 的标识。"""

        return f"cli-{uuid4().hex[:12]}"


def _adult_actor() -> Actor:
    """控制面 actor。**固定构造**，不存在从外部指定 kind/id 的路径（约束 1）。"""

    return Actor(kind="adult_control_plane", actor_id=ADULT_ACTOR_ID)


def _open(db_path: Path, *, create: bool) -> _Runtime:
    """打开记忆库。``create=True``（写命令）时按 0600 新建；只读命令**不建库**。

    只读命令不建库是刻意的：``list`` 不该在用户只是「看一眼」时凭空产生一个文件，
    更不该让「路径写错了」表现为「库是空的」。
    """

    runtime = _Runtime(db_path, _system_clock)
    if not db_path.exists() and not create:
        raise CliError(f"记忆库不存在：{db_path}")
    runtime.store.create_schema()
    return runtime


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def _out(text: str = "") -> None:
    print(text)


#: ``--content`` 取这个值时从 **stdin** 读正文（B1）。
STDIN_SENTINEL = "-"


def _resolve_content(raw: str | None, content_file: Path | None) -> str | None:
    """把 ``--content`` / ``--content-file`` 归一成正文（B1）。

    ``--content -`` 从 stdin 读、``--content-file`` 从文件读。两者都是为了让**敏感正文
    不进 shell 历史**：``family-ai-memory propose --content "孩子对花生过敏"`` 会把
    儿童健康信息落到 ``~/.zsh_history`` 里，而那不是本项目掌控的存储。
    ``--content-file`` 的路径本身仍会进历史，但它不含正文。
    """

    if content_file is not None:
        if raw is not None:
            raise CliError("--content 与 --content-file 不能同时给")
        try:
            return content_file.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise CliError(f"无法读取 --content-file：{content_file}") from exc
    if raw == STDIN_SENTINEL:
        return sys.stdin.read().strip()
    return raw


def _fail(exc: BaseException) -> int:
    """**只打异常类型 + 固定指引**（约束 3），绝不回显异常消息。"""

    name = type(exc).__name__
    print(f"操作失败（{name}）。", file=sys.stderr)
    print(_GUIDANCE.get(name, _GUIDANCE["MemoryServiceError"]), file=sys.stderr)
    return EXIT_FAILED


def _reassign_failed(exc: BaseException) -> None:
    """``confirm --reassign-owner`` 失败的**固定**提示：说清没有中间态（§7.5 第 6 项）。

    与 :func:`_fail` 一样只打异常类型，绝不回显异常消息（约束 3）；多出来的这一行是
    给操作者的**语义**说明 —— 改归属与确认共享是同一次写入，失败时两步都没有生效。
    """

    print(
        f"操作失败（{type(exc).__name__}）：归属变更与确认共享是同一次写入，"
        "两者都没有生效（owner / status / consent_version 保持原值），修正后可直接重跑。",
        file=sys.stderr,
    )


def _confirm(prompt: str, *, assume_yes: bool) -> bool:
    """二次确认。非 TTY 且没有 ``--yes`` → 拒绝（不默认同意）。"""

    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(f"这是破坏性操作，需要 {CONFIRM_FLAG} 或在终端交互确认。", file=sys.stderr)
        return False
    try:
        answer = input(f"{prompt} 输入 yes 继续：")
    except (KeyboardInterrupt, EOFError):
        print()
        return False
    return answer.strip().lower() in {"yes", "y"}


def _describe(record: MemoryRecord) -> str:
    # T9c / 勘误 E3：flagged 行在任何列出它的地方都带标记（`list` / `inspect` / ……），
    # 免得「这条为什么确认不了」只能靠看正文长度猜。
    marker = "  [历史超长]" if record.content_over_length == 1 else ""
    return (
        f"{record.id}  [{record.status}]  {record.memory_class}  "
        f"owner={record.owner_id}  audiences={','.join(sorted(record.audiences)) or '-'}  "
        f"importance={record.importance:g}  updated={record.updated_at}  "
        f"writer={record.actor_kind}:{record.actor_id}{marker}"
    )


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------


def _cmd_propose(runtime: _Runtime, args: argparse.Namespace) -> int:
    # FAMILY 必须有显式受众（契约 §4.1）。默认给家庭共享受众 —— 成人不写 --audience
    # 时得到的是「全家可读」这个最保守的常见选择，而不是空受众报错。
    audiences = frozenset(args.audience) or frozenset({SHARED_SESSION_AUDIENCE_ID})
    content = _resolve_content(args.content, args.content_file)
    if content is None or not content.strip():
        print("用法错误: 正文为空（--content / --content-file / stdin）。", file=sys.stderr)
        return EXIT_CONFIG
    record = runtime.service.propose(
        MemoryCandidate(
            content=content,
            scope="FAMILY",
            memory_class=args.memory_class,
            owner_id=args.owner,
            source_type="explicit_user",
            source_member_id=args.owner,
            confidence=1.0,
            importance=args.importance,
            audiences=audiences,
        ),
        SourceSession(
            session_id=args.source_session or runtime.session_id(),
            owner_id=args.owner,
            audience_id=sorted(audiences)[0],
            session_mode="shared",
            identity_assurance="unknown",
            grant_id=None,
        ),
        actor=_adult_actor(),  # A12：成人提议必须显式归属
    )
    if record is None:
        _out("未写入（memory_policy=do_not_persist）。")
        return EXIT_OK
    _out("已记录候选（需要确认后才会被召回）：")
    _out(_describe(record))
    _out("用 `confirm` 确认共享后它才可召回。")
    return EXIT_OK


def _cmd_list(runtime: _Runtime, args: argparse.Namespace) -> int:
    snapshot = runtime.service.query(
        # §4.2：控制面访问的**唯一**构造入口是 `SessionAccess.for_control_plane()`
        # （AST 契约测试锁死调用点集合）。`list` 的动作仍是 `read_model`，
        # 这里换访问形态只是「CLI 真的是控制面」，不改变判定结果。
        SessionAccess.for_control_plane(),
        "adult_list",  # 只出元数据；正文走 `inspect`
        session_id=runtime.session_id(),
        audience_id=args.audience,
        grant=None,
    )
    # T9c / 勘误 E3：历史超长行数的**唯一**权威可见面之一就是这里（另一个是迁移报告）。
    # 直接用具体类的 `count_over_length()`（该实现方法本轮不进 `MemoryStore` Protocol）。
    over_length = runtime.store.count_over_length()
    _out(f"记忆库：{runtime.db_path}")
    _out(f"受众：{args.audience}")
    _out(f"历史超长行（content_over_length=1，不能确认，只能改短或删除）：{over_length} 条")
    _out()
    _out(f"本次可读（{len(snapshot.entries)} 条）")
    for entry in snapshot.entries:
        record = runtime.store.read_record(entry.record_id)
        _out("  " + (record and _describe(record) or entry.record_id))
    if not snapshot.entries:
        _out("  （无）")
    _out()
    _out(f"本次不可读 / 不可召回（{len(snapshot.denied)} 条）")
    for record_id, reason in snapshot.denied:
        _out(f"  {record_id}  denied={reason}")
    if not snapshot.denied:
        _out("  （无）")
    if any(reason == "status_denied" for _, reason in snapshot.denied):
        _out()
        _out("提示：候选（status_denied）需先用 `confirm` 确认才可召回；")
        _out("      用 `inspect <id>` 可以直接读候选正文（成人复审，M2.2）。")
    return EXIT_OK


def _cmd_inspect(runtime: _Runtime, args: argparse.Namespace) -> int:
    # 一次调用用**同一个** session id 跑两次 query：控制面不是会话，两次都不带 grant，
    # 同一个 id 只是让两条快照在审计上可对账。
    session_id = runtime.session_id()
    access = SessionAccess.for_control_plane()
    snapshot = runtime.service.query(
        access,
        "adult_inspect",  # 带正文：成人自查
        session_id=session_id,
        audience_id=args.audience,
        grant=None,
    )
    entry = next((e for e in snapshot.entries if e.record_id == args.record_id), None)
    if entry is not None:
        _show_entry(runtime, entry)
        return EXIT_OK

    reason = dict(snapshot.denied).get(args.record_id)
    if reason == "status_denied":
        # §4.3 第 2 步（M2.2）：候选（以及 DECAYED / 墓碑）在 `read_model` 下是
        # `status_denied`，成人因此读不到正文 —— 复审是**追加一次**查询，
        # 动作由 purpose 决定（`control_plane_review` → `review_control_plane`），
        # 正文仍然只从 `query()` 的 snapshot 出，不新增第二条读路径。
        review = runtime.service.query(
            access,
            "control_plane_review",
            session_id=session_id,
            audience_id=args.audience,
            grant=None,
        )
        entry = next((e for e in review.entries if e.record_id == args.record_id), None)
        if entry is not None:
            _show_entry(runtime, entry, review=True)
            return EXIT_OK
        # 复审同样拒绝（过期 / 缺源 / 越 scope / 受众不命中 / 策略损坏）：
        # 保持现状 —— 固定枚举 reason + 既有指引。
        reason = dict(review.denied).get(args.record_id) or reason

    _out(f"{args.record_id} 不在本次可读范围内。")
    if reason == "status_denied":
        _out("原因：该状态（status_denied）在确认之前不可召回，因此也不可读。")
    elif reason:
        _out(f"原因：{reason}")
        _out(_GUIDANCE.get("AuthorizationError", ""))
    else:
        _out("原因：该记录不在本受众的候选集里（可能受众不同或已删除）。")
    return EXIT_FAILED


#: 复审读到的非 `ACTIVE` 行的**状态标注**（§4.3 / 勘误 E8）。
#:
#: `review_control_plane` 只跳过 `status_denied`，因此它也会读到 `DECAYED` / `DELETED`。
#: 文案必须如实说明状态：**墓碑不是「待确认的候选」**（E8），只是它本来就没有正文
#: （DDL 冻结 `status <> 'DELETED' OR content = ''`）。
_REVIEW_STATUS_LABELS: dict[str, str] = {
    "PENDING_CONFIRMATION": "候选（尚未确认，不会被召回）",
    "DECAYED": "已衰减（DECAYED）：不再召回，等留存期结束",
    "DELETED": "墓碑（DELETED）：已删除（M2.1 的删除是硬删，不产墓碑；无正文可显示）",
}


def _review_label(record: MemoryRecord | None) -> str:
    """复审通过时的状态标注。**不把非候选说成候选**（E8）。"""

    if record is None:
        return "非 ACTIVE 记录（不会被召回）"
    return _REVIEW_STATUS_LABELS.get(
        record.status, f"{record.status}（不会被召回）"
    )


def _show_entry(runtime: _Runtime, entry: SnapshotEntry, *, review: bool = False) -> None:
    """打印一条可读记录。``review=True`` 时加控制面复审的标注（§4.3 第 3 步）。"""

    record = runtime.store.read_record(entry.record_id)
    if record is not None:
        _out(_describe(record))
        if record.content_over_length == 1:
            # W9 审阅 B 建议 1：flagged 行的提示必须**可执行**，不能只留一个标记。
            _out(
                f"[历史超长] 该行正文超过 {MAX_CONTENT_CHARS} 字上限（历史遗留）："
                "不能用 confirm 确认；请用 correct 把正文改短，或 delete（等它过期也可以）。"
            )
    if review:
        _out(f"⚠ {_review_label(record)}")
        if record is not None and record.source_type == "auto_extracted":
            # 契约 §3 约束 1：自动提取的候选在复审时**必须标明来源**。
            # 落库面上 `MemoryCandidate.origin="auto_extracted"` 是与
            # `source_type="auto_extracted"` **同时写**的（§3.6 T22），
            # 而记录行只持久化 `source_type`（`MemoryRecord` 没有 origin 列）。
            _out("来源：会话自动提取")
    _out()
    if entry.content is None:
        _out("（该 purpose 不携带正文）")
    elif not entry.content:
        _out("（该记录无正文）")
    else:
        _out(entry.content)


def _cmd_confirm(runtime: _Runtime, args: argparse.Namespace) -> int:
    actor = _adult_actor()
    # 「不做半个确认」（§2.4）要求**第二步的输入**也在第一步写入之前校验掉：
    # `--audience ""` 会在 `confirm_shared` 里才报错，那时归属已经改完。
    # 用法错误（退出码 2）在这里就退，一行都不写。
    audiences = frozenset(item for item in args.audience if item and item.strip())
    if not audiences:
        print("用法错误: --audience 不能为空。", file=sys.stderr)
        return EXIT_CONFIG
    # W9 审阅 B 建议 1：**flagged 候选**的拒绝必须给出**可执行**的提示。
    # 这条前置检查同时保证 `--reassign-owner` 不会留下「归属改了、但没确认」的半成品
    # （契约 §2.4：前一步失败就不执行后一步，不做「半个确认」）。
    existing = runtime.store.read_record(args.record_id)
    if existing is not None and existing.content_over_length == 1:
        print("操作失败（历史超长行）：该记录是历史超长行，不能被确认。", file=sys.stderr)
        if existing.status == "PENDING_CONFIRMATION":
            # 候选走不了 `correct`（(PENDING,PENDING) 不在 LEGAL_TRANSITIONS 里），
            # 因此出路只有两条 —— 文案必须把它们写出来。
            print(
                "候选只能删除（`delete <id> --yes`），或等它过期"
                f"（候选期 {DEFAULT_TTL_CANDIDATE_DAYS} 天后硬删）。",
                file=sys.stderr,
            )
        else:
            print(
                f"请先用 `correct` 把正文改到 {MAX_CONTENT_CHARS} 字以内（标记会自动清零）再确认。",
                file=sys.stderr,
            )
        return EXIT_FAILED
    if args.reassign_owner is not None:
        # §2.4 T26' + §7.5 第 6 项（M2.3）：**改归属与确认共享是同一次写入**
        # （`MemoryService.confirm_shared_with_owner_reassign` 里的一次 `write_record`，
        # 也就是一个事务）—— 不再有「归属已改、确认未完成」的中间态：任何一步的校验或
        # 那次写入失败，`owner` / `status` / `consent_version` 一起保持原值，重跑安全。
        # 归属变更只用**固定的**控制面 actor，不新增任何 actor 输入（约束 1）。
        try:
            record = runtime.service.confirm_shared_with_owner_reassign(
                args.record_id, audiences, args.reassign_owner, actor=actor
            )
        except MemoryServiceError as exc:
            _reassign_failed(exc)
            raise
    else:
        record = runtime.service.confirm_shared(args.record_id, audiences, actor)
    _out("已确认共享：")
    _out(_describe(record))
    return EXIT_OK


def _cmd_correct(runtime: _Runtime, args: argparse.Namespace) -> int:
    if (
        args.content is None
        and args.content_file is None
        and args.importance is None
        and args.audience is None
    ):
        # A1：什么都没指定时**不写入**。放过去会递增 consent_version、刷新时间戳，
        # 让一条本来有效的 grant 因为 stale_consent 失效 —— 一次空操作产生真实副作用。
        print("用法错误: 未指定任何改动（--content / --importance / --audience 至少给一个）。", file=sys.stderr)
        return EXIT_CONFIG
    content = _resolve_content(args.content, args.content_file)
    record = runtime.service.correct(
        args.record_id,
        MemoryCorrection(
            content=content,
            importance=args.importance,
            audiences=frozenset(args.audience) if args.audience else None,
        ),
        _adult_actor(),
    )
    _out("已修正：")
    _out(_describe(record))
    return EXIT_OK


def _cmd_delete(runtime: _Runtime, args: argparse.Namespace) -> int:
    if not _confirm(f"将永久删除 {args.record_id} 及其受众/血缘/授权行。", assume_yes=args.yes):
        _out("已取消，未做任何改动。")
        return EXIT_ABORTED
    report = runtime.service.delete(args.record_id, _adult_actor())
    _out("已删除（磁盘删除，不是「不再召回」）：")
    _out(f"  记录：{', '.join(report.record_ids)}")
    _out(f"  触及的表：{', '.join(report.tables_touched)}")
    _out(f"  派生记录（已删除）：{', '.join(report.derived_removed) or '（无）'}")
    _out(
        "  派生记录（仍在盘上、已永久不可召回）："
        f"{', '.join(report.derived_unreachable) or '（无）'}"
    )
    _out(f"  可重写产物：{', '.join(report.fulltext_eval_copies_removed) or '（无）'}")
    _out("  **删不掉、也不承诺删除**的位置（未知副本）：")
    for location in report.unknown_copies:
        _out(f"    - {location}")
    _out(f"  审计 id：{report.audit_id}（{report.deleted_at}）")
    return EXIT_OK


def _cmd_sweep(runtime: _Runtime, args: argparse.Namespace) -> int:
    if not _confirm(
        "将把到期记录落成 DECAYED（不删盘），并永久删除到期候选。", assume_yes=args.yes
    ):
        _out("已取消，未做任何改动。")
        return EXIT_ABORTED
    results = runtime.service.sweep_expired(Actor(kind="ttl_expiry", actor_id="family-ai-memory"))
    if not results:
        _out("没有到期的记录。")
        return EXIT_OK
    for item in results:
        if isinstance(item, MemoryRecord):
            _out(f"转 DECAYED（不删盘）：{_describe(item)}")
        else:
            _out(f"已永久删除到期候选：{', '.join(item.record_ids)}（审计 id {item.audit_id}）")
    return EXIT_OK


def _cmd_grant_issue(runtime: _Runtime, args: argparse.Namespace) -> int:
    from soul_memory_kernel.memory.model import Grant

    expires_at = (
        datetime.fromisoformat(runtime.clock().replace("Z", "+00:00"))
        + timedelta(hours=args.ttl_hours)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    resources = tuple(args.resource) if args.resource else _default_resources(runtime, args)
    if not resources:
        _out("没有可授权的记录（该 owner/受众下没有 ACTIVE 记录）。")
        return EXIT_FAILED
    records = {r.id: r for r in runtime.store.read_records(resources)}
    missing = [rid for rid in resources if rid not in records]
    if missing:
        print(f"操作失败（{RecordNotFound.__name__}）。", file=sys.stderr)
        print(_GUIDANCE["RecordNotFound"], file=sys.stderr)
        return EXIT_FAILED
    # B2：**显式 --resource 与默认枚举走同一条合规检查**。否则 `--resource` 会成为
    # 一条绕过「只授权可召回记录」的后门：候选 / DECAYED / 墓碑都能被写进
    # grant_resource，而 `authorize()` 的 `stale_consent` 与状态检查都在更后面才拦。
    # 不合规按**用法错误**处理（退出码 2）—— 这是调用方给错了输入，不是运行时故障。
    non_active = sorted(rid for rid, rec in records.items() if rec.status != "ACTIVE")
    if non_active:
        print(
            "用法错误: --resource 只接受 ACTIVE 记录，以下不是：" + ", ".join(non_active),
            file=sys.stderr,
        )
        return EXIT_CONFIG
    wrong_audience = sorted(
        rid
        for rid, rec in records.items()
        if args.audience not in rec.audiences or rec.scope not in M2_1_ALLOWED_SCOPES
    )
    if wrong_audience:
        print(
            f"用法错误: --resource 只接受 scope 已启用且受众含 {args.audience!r} 的记录，"
            "以下不是：" + ", ".join(wrong_audience),
            file=sys.stderr,
        )
        return EXIT_CONFIG
    runtime.grants.issue(
        Grant(
            grant_id=args.grant_id or f"grant-{uuid4().hex[:12]}",
            version=1,
            session_id=args.session_id,
            subject_id=args.subject or args.owner,
            owner_id=args.owner,
            audience_id=args.audience,
            actions=frozenset(args.action),
            resource_ids=frozenset(resources),
            consent_versions=tuple((rid, records[rid].consent_version) for rid in resources),
            expires_at=expires_at,
            issuer=ADULT_ACTOR_ID,
            issued_at=runtime.clock(),
        )
    )
    _out(f"已签发（有效期 {args.ttl_hours:g} 小时，上限 {MAX_GRANT_TTL_SECONDS // 3600} 小时）。")
    _out(f"  会话：{args.session_id}  受众：{args.audience}  动作：{', '.join(sorted(args.action))}")
    _out(f"  覆盖记录：{', '.join(resources)}")
    return EXIT_OK


def _default_resources(runtime: _Runtime, args: argparse.Namespace) -> tuple[str, ...]:
    ids = runtime.store.list_eligible(
        owner_id=args.owner,
        audience_id=args.audience,
        scopes=("FAMILY",),
        statuses=("ACTIVE",),
    )
    return tuple(sorted(ids))


def _cmd_grant_revoke(runtime: _Runtime, args: argparse.Namespace) -> int:
    if not _confirm(f"将撤销 {args.grant_id} 的全部版本。", assume_yes=args.yes):
        _out("已取消，未做任何改动。")
        return EXIT_ABORTED
    runtime.grants.revoke(args.grant_id, revoked_at=runtime.clock(), actor=_adult_actor())
    _out(f"已撤销 {args.grant_id}（撤销后 store 返回 None，判权落成 no_grant）。")
    return EXIT_OK


def _describe_pending(item: PendingItem) -> str:
    src = f"  source={item.source_record_id}" if item.source_record_id else ""
    exp = f"  expires_at={item.expires_at}" if item.expires_at else ""
    res = f"  resolved_at={item.resolved_at}" if item.resolved_at else ""
    return (
        f"{item.id}  [{item.status}]  scope={item.scope}  owner={item.owner_id}  "
        f"audiences={','.join(sorted(item.audiences)) or '-'}  "
        f"expected_after={item.expected_after}{exp}{res}{src}  "
        f"topic={item.topic}"
    )


def _cmd_pending_create(runtime: _Runtime, args: argparse.Namespace) -> int:
    audiences = frozenset(args.audience) or frozenset({SHARED_SESSION_AUDIENCE_ID})
    item = runtime.pending.create(
        PendingCandidate(
            owner_id=args.owner,
            topic=args.topic,
            context=args.context,
            expected_after=args.expected_after,
            followup_action=args.followup_action,
            scope=args.scope,
            audiences=audiences,
            source_record_id=args.source_record,
            expires_at=args.expires_at,
        ),
        actor=_adult_actor(),
    )
    if item is None:
        _out("未写入待跟进项（memory_policy=do_not_persist）。")
        return EXIT_OK
    _out("已创建待跟进项（到达 expected_after 后会在下次会话会前投影中顺带关心一次）：")
    _out(_describe_pending(item))
    return EXIT_OK


def _cmd_pending_list(runtime: _Runtime, args: argparse.Namespace) -> int:
    statuses = (args.status,) if args.status else ()
    items = runtime.pending.list_items(audience_id=args.audience, statuses=statuses)
    _out(f"记忆库：{runtime.db_path}")
    _out(f"受众：{args.audience}")
    _out(f"待跟进项（{len(items)} 条）")
    for item in items:
        _out("  " + _describe_pending(item))
    if not items:
        _out("  （无）")
    return EXIT_OK


def _cmd_pending_resolve(runtime: _Runtime, args: argparse.Namespace) -> int:
    item = runtime.pending.resolve(args.pending_id, actor=_adult_actor())
    _out("已结项（RESOLVED）：")
    _out(_describe_pending(item))
    return EXIT_OK


def _cmd_pending_cancel(runtime: _Runtime, args: argparse.Namespace) -> int:
    if not _confirm(f"将取消待跟进项 {args.pending_id}（置为 CANCELLED）。", assume_yes=args.yes):
        _out("已取消，未做任何改动。")
        return EXIT_ABORTED
    item = runtime.pending.cancel(args.pending_id, actor=_adult_actor())
    _out("已取消跟进（CANCELLED）：")
    _out(_describe_pending(item))
    return EXIT_OK


def _cmd_pending_skip(runtime: _Runtime, args: argparse.Namespace) -> int:
    item = runtime.pending.skip(args.pending_id, until=args.until, actor=_adult_actor())
    _out("已延后跟进时间（保持 OPEN）：")
    _out(_describe_pending(item))
    return EXIT_OK


def _cmd_pending_sweep(runtime: _Runtime, args: argparse.Namespace) -> int:
    if not _confirm("将把已超过 expires_at 的 OPEN 待跟进项置为 EXPIRED。", assume_yes=args.yes):
        _out("已取消，未做任何改动。")
        return EXIT_ABORTED
    expired = runtime.pending.sweep_expired(
        actor=Actor(kind="ttl_expiry", actor_id=ADULT_ACTOR_ID)
    )
    if not expired:
        _out("没有到期的待跟进项。")
        return EXIT_OK
    for item in expired:
        _out(f"转 EXPIRED：{_describe_pending(item)}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------


def _add_db_options(parser: argparse.ArgumentParser) -> None:
    """连接参数。``--audience`` 由各子命令自己加 —— 读取类要单值，写入类要可重复。"""

    # SUPPRESS：写在子命令**之后**时才覆盖顶层值；不写就保留顶层给的值。
    # 这样 `--db X list` 与 `list --db X` 两种写法都成立。
    parser.add_argument(
        "--db", type=Path, default=argparse.SUPPRESS, help="记忆库路径(优先于环境与 .env)"
    )
    parser.add_argument(
        "--env", type=Path, default=argparse.SUPPRESS, help=".env 路径(只读记忆相关的键)"
    )


def _add_single_audience(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--audience", default=SHARED_SESSION_AUDIENCE_ID, help="受众(默认家庭共享受众)"
    )


def _add_multi_audience(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--audience", action="append", default=[], help="共享受众(可重复)")


def build_parser() -> argparse.ArgumentParser:
    """构造参数解析器。**没有任何 actor kind / actor id 参数**（约束 1）。"""

    parser = argparse.ArgumentParser(
        prog="family-ai-memory",
        description=(
            "家庭 AI 记忆的成人本机控制面：列出/查看/确认/纠正/删除共享记忆，"
            "管理会话授权与到期扫描。"
        ),
    )
    # 顶层也放一份，允许 `family-ai-memory --db X list`。
    parser.add_argument("--db", type=Path, default=None, help="记忆库路径(优先于环境与 .env)")
    parser.add_argument("--env", type=Path, default=None, help=".env 路径(只读记忆相关的键)")
    sub = parser.add_subparsers(dest="command", required=True)

    propose = sub.add_parser("propose", help="记录一条候选（需 confirm 后才可召回）")
    _add_db_options(propose)
    propose.add_argument(
        "--content",
        default=None,
        help=(
            f"正文（≤{MAX_CONTENT_CHARS} 字）。取 `-` 从 stdin 读；"
            "注意：写在命令行里的正文会进 shell 历史，敏感内容请用 `--content -` "
            "或 `--content-file`"
        ),
    )
    propose.add_argument("--content-file", type=Path, default=None, help="从文件读正文")
    propose.add_argument("--owner", required=True, help="资料归属的成员 id")
    propose.add_argument(
        "--memory-class", default="EVENT", choices=("EVENT", "PREFERENCE", "SAFETY")
    )
    _add_multi_audience(propose)
    propose.add_argument("--importance", type=float, default=0.5)
    propose.add_argument("--source-session", default=None, help="来源会话 id(默认自动生成)")
    propose.set_defaults(handler=_cmd_propose)

    listing = sub.add_parser("list", help="列出可读/不可读的记忆(只出元数据)")
    _add_db_options(listing)
    _add_single_audience(listing)
    listing.set_defaults(handler=_cmd_list)

    inspect = sub.add_parser("inspect", help="查看一条记忆的正文")
    _add_db_options(inspect)
    _add_single_audience(inspect)
    inspect.add_argument("record_id")
    inspect.set_defaults(handler=_cmd_inspect)

    confirm = sub.add_parser("confirm", help="确认候选为可共享（唯一让记录可召回的路径）")
    _add_db_options(confirm)
    confirm.add_argument("record_id")
    confirm.add_argument("--audience", action="append", required=True, help="共享受众(可重复；必填)")
    confirm.add_argument(
        "--reassign-owner",
        default=None,
        metavar="MEMBER_ID",
        help=(
            "确认前先把候选的归属定到该成员（D13；只对候选生效）。M2.3 起与确认共享是"
            "**同一次写入**：要么两步都成，要么两步都不成。归属定型后不可再改"
        ),
    )
    confirm.set_defaults(handler=_cmd_confirm)

    correct = sub.add_parser("correct", help="修正正文/重要度/受众（改不了归属与来源）")
    _add_db_options(correct)
    correct.add_argument("record_id")
    correct.add_argument(
        "--content",
        default=None,
        help=(
            "新正文。取 `-` 从 stdin 读；"
            "注意：写在命令行里的正文会进 shell 历史，敏感内容请用 `--content -` "
            "或 `--content-file`"
        ),
    )
    correct.add_argument("--content-file", type=Path, default=None, help="从文件读新正文")
    correct.add_argument("--importance", type=float, default=None)
    correct.add_argument(
        "--audience", action="append", default=None, help="替换受众(可重复；不给则不动)"
    )
    correct.set_defaults(handler=_cmd_correct)

    delete = sub.add_parser("delete", help="磁盘删除一条记忆（需二次确认）")
    _add_db_options(delete)
    delete.add_argument("record_id")
    delete.add_argument("--yes", action="store_true", help="跳过交互确认")
    delete.set_defaults(handler=_cmd_delete)

    sweep = sub.add_parser("sweep", help="执行到期动作（需二次确认）")
    _add_db_options(sweep)
    sweep.add_argument("--yes", action="store_true", help="跳过交互确认")
    sweep.set_defaults(handler=_cmd_sweep)

    grant = sub.add_parser("grant", help="会话授权的签发与撤销")
    grant_sub = grant.add_subparsers(dest="grant_command", required=True)
    issue = grant_sub.add_parser("issue", help="签发一个短期会话授权")
    _add_db_options(issue)
    _add_single_audience(issue)
    issue.add_argument("--session-id", required=True)
    issue.add_argument("--owner", required=True)
    issue.add_argument("--subject", default=None, help="操作主体(默认与 owner 相同)")
    issue.add_argument("--grant-id", default=None, help="显式 grant id(默认自动生成)")
    issue.add_argument(
        "--action",
        action="append",
        default=None,
        # 契约 §4.1 勘误 E4：choices 来自**可签发动作集**（`ACTIONS` 减去免 grant 的
        # `review_control_plane`），不是手抄一份、也不是整个 `ACTIONS`。
        choices=sorted(GRANTABLE_ACTIONS),
        help=(
            "允许的动作(可重复；取值来自契约的可签发动作集)。"
            "`review_control_plane` 是免 grant 的复审动作，不可签发"
        ),
    )
    issue.add_argument("--resource", action="append", default=None, help="覆盖的记录 id(可重复)")
    issue.add_argument(
        "--ttl-hours",
        type=float,
        default=1.0,
        help=f"有效期小时数(上限 {MAX_GRANT_TTL_SECONDS // 3600})",
    )
    issue.set_defaults(handler=_cmd_grant_issue)
    revoke = grant_sub.add_parser("revoke", help="撤销一个会话授权的全部版本")
    _add_db_options(revoke)
    revoke.add_argument("grant_id")
    revoke.add_argument("--yes", action="store_true", help="跳过交互确认")
    revoke.set_defaults(handler=_cmd_grant_revoke)

    pending = sub.add_parser("pending", help="管理待跟进项（W0'-P 机会式会前跟进）")
    pending_sub = pending.add_subparsers(dest="pending_command", required=True)

    p_create = pending_sub.add_parser("create", help="创建一条待跟进项")
    _add_db_options(p_create)
    p_create.add_argument("--owner", required=True, help="待跟进项归属的成员 id")
    p_create.add_argument(
        "--topic", required=True, help=f"跟进主题摘要（≤{MAX_PENDING_FIELD_CHARS} 字）"
    )
    p_create.add_argument(
        "--context", required=True, help=f"背景说明（≤{MAX_PENDING_FIELD_CHARS} 字）"
    )
    p_create.add_argument(
        "--expected-after", required=True, help="最早可跟进的 ISO-8601 时间（带时区）"
    )
    p_create.add_argument(
        "--followup-action", required=True, help=f"建议跟进方式（≤{MAX_PENDING_FIELD_CHARS} 字）"
    )
    p_create.add_argument(
        "--scope", default="FAMILY", choices=("FAMILY", "PERSONAL", "SAFETY")
    )
    p_create.add_argument("--source-record", default=None, help="关联的来源记忆 record_id")
    p_create.add_argument("--expires-at", default=None, help="显式过期时间（默认 expected_after+14d）")
    _add_multi_audience(p_create)
    p_create.set_defaults(handler=_cmd_pending_create)

    p_list = pending_sub.add_parser("list", help="列出待跟进项（只读，不建库）")
    _add_db_options(p_list)
    _add_single_audience(p_list)
    p_list.add_argument(
        "--status", default=None, choices=sorted(PENDING_STATUSES), help="按状态过滤"
    )
    p_list.set_defaults(handler=_cmd_pending_list)

    p_resolve = pending_sub.add_parser("resolve", help="将待跟进项标记为已结项（RESOLVED）")
    _add_db_options(p_resolve)
    p_resolve.add_argument("pending_id")
    p_resolve.set_defaults(handler=_cmd_pending_resolve)

    p_cancel = pending_sub.add_parser("cancel", help="取消一条待跟进项（需二次确认）")
    _add_db_options(p_cancel)
    p_cancel.add_argument("pending_id")
    p_cancel.add_argument("--yes", action="store_true", help="跳过交互确认")
    p_cancel.set_defaults(handler=_cmd_pending_cancel)

    p_skip = pending_sub.add_parser("skip", help="延后一条待跟进项的 expected_after")
    _add_db_options(p_skip)
    p_skip.add_argument("pending_id")
    p_skip.add_argument("--until", required=True, help="推迟到的新 ISO-8601 时间（带时区）")
    p_skip.set_defaults(handler=_cmd_pending_skip)

    p_sweep = pending_sub.add_parser("sweep", help="将已过期的 OPEN 待跟进项置为 EXPIRED（需二次确认）")
    _add_db_options(p_sweep)
    p_sweep.add_argument("--yes", action="store_true", help="跳过交互确认")
    p_sweep.set_defaults(handler=_cmd_pending_sweep)

    return parser


#: 只读命令：不建库、不改任何行。
_READ_ONLY_COMMANDS: frozenset[str] = frozenset({"list", "inspect"})


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "action", None) is None and args.command == "grant":
        args.action = ["read_model"]
    if getattr(args, "ttl_hours", None) is not None and not 0 < args.ttl_hours <= (
        MAX_GRANT_TTL_SECONDS / 3600
    ):
        print(f"用法错误: --ttl-hours 必须在 (0, {MAX_GRANT_TTL_SECONDS // 3600}] 之间。", file=sys.stderr)
        return EXIT_CONFIG

    # 不 ``dict(os.environ)``（B5）：那会在进程里复制一份完整环境。resolve_db_path
    # 只按名字取两个键，直接给 mapping 就够。
    db_path = resolve_db_path(
        explicit=args.db,
        env_file=args.env if args.env is not None else REPO_ROOT / ".env",
        environ=os.environ,
    )
    is_read_only = args.command in _READ_ONLY_COMMANDS or (
        args.command == "pending" and getattr(args, "pending_command", None) == "list"
    )
    create = not is_read_only
    try:
        runtime = _open(db_path, create=create)
    except CliError as exc:
        print(f"操作失败（{type(exc).__name__}）。", file=sys.stderr)
        print("请检查记忆库路径(`--db`/`MEMORY_DB_PATH`)，或先用写命令创建它。", file=sys.stderr)
        return EXIT_CONFIG
    except (StoreError, MemoryValidationError, MemoryServiceError) as exc:
        return _fail(exc)
    except OSError as exc:
        return _fail(exc)

    try:
        return int(args.handler(runtime, args))
    except CliError as exc:
        # 用法/输入问题：固定指引 + 退出码 2（与 argparse 的用法错误一致）。
        print(f"用法错误（{type(exc).__name__}）。", file=sys.stderr)
        print(_GUIDANCE["CliError"], file=sys.stderr)
        return EXIT_CONFIG
    except (
        MemoryServiceError,
        RecordNotFound,
        MemoryValidationError,
        StoreError,
    ) as exc:
        return _fail(exc)
    except KeyboardInterrupt:
        print()
        return EXIT_ABORTED


if __name__ == "__main__":  # pragma: no cover —— 入口由 console_scripts 提供
    sys.exit(main())
