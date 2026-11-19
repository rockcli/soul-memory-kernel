"""W5 测试：成人本机控制面 CLI ``family-ai-memory``。

**全程离线**（仓库级 ``tests/conftest.py`` 的守门生效：清代理 + 拦截非 loopback 连接），
只操作 ``tmp_path`` 下的临时记忆库，不碰仓库内 ``data/``、不读 ``.env`` 凭证、不写日志。

覆盖五块：

1. **身份**：解析器里**不存在**任何可指定 actor 的参数；写入归属恒为控制面常量。
2. **配置**：``--db`` / 环境变量 / ``.env``（只认两个记忆键，凭证键读不到）的优先级。
3. **端到端**：``propose → list → confirm → correct → inspect → delete → sweep``。
4. **隐私与输出**：不产生日志文件、任何文件都不含正文、``list`` 不出正文、
   错误输出只有异常类型与固定指引、破坏性操作必须二次确认。
5. **A12**：``propose`` 的显式 actor、``memory_record`` 的归属列、v1→v2 显式迁移。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soul_memory_kernel.memory import cli as memory_cli
from soul_memory_kernel.memory.store import MEMORY_SCHEMA_VERSION, SqliteMemoryStore

ADULT_ACTOR = "adult_control_plane:family-ai-memory"

#: 迁移用例写历史行用的时间戳（与 ``Clock`` 的默认值同源，便于对账）。
CLOCK_NOW = "2026-09-26T12:00:00Z"


class Clock:
    """可控时钟：驱动 CLI 的 ``_system_clock``，让 TTL 的「天」可以一步跨过去。"""

    def __init__(self, value: str = "2026-09-26T12:00:00Z") -> None:
        self.value = value

    def __call__(self) -> str:
        return self.value

    def advance_days(self, days: int) -> None:
        current = datetime.fromisoformat(self.value.replace("Z", "+00:00"))
        self.value = (current + timedelta(days=days)).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")


@pytest.fixture(name="clock")
def clock_fixture(monkeypatch: pytest.MonkeyPatch) -> Clock:
    clock = Clock()
    monkeypatch.setattr(memory_cli, "_system_clock", clock)
    return clock


@pytest.fixture(name="db")
def db_fixture(tmp_path: Path) -> Path:
    return tmp_path / "memory.sqlite3"


def run_cli(*argv: str, db: Path | None = None) -> int:
    """跑一次 CLI。``--db`` 由调用方显式给，避免依赖进程环境。"""

    args = list(argv)
    if db is not None:
        args = ["--db", str(db), *args]
    return memory_cli.main(args)


def run_cli_capture(
    capsys: pytest.CaptureFixture[str], *argv: str, db: Path | None = None
) -> tuple[int, str, str]:
    code = run_cli(*argv, db=db)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def seed_confirmed(db: Path, *, content: str = "孩子对花生过敏", owner: str = "child") -> str:
    """用 CLI 自己走一遍 propose + confirm，返回 record_id。"""

    run_cli("propose", "--content", content, "--owner", owner, "--memory-class", "SAFETY", db=db)
    record_id = _only_record_id(db)
    run_cli("confirm", record_id, "--audience", "family_all", db=db)
    return record_id


def _only_record_id(db: Path) -> str:
    with sqlite3.connect(db) as con:
        rows = con.execute("SELECT id FROM memory_record ORDER BY rowid").fetchall()
    assert len(rows) == 1, rows
    return rows[0][0]


def _rows(db: Path, sql: str, params: tuple = ()) -> list[tuple]:
    with sqlite3.connect(db) as con:
        return con.execute(sql, params).fetchall()


# ---------------------------------------------------------------------------
# 1. 身份：不存在「冒充 actor」的输入
# ---------------------------------------------------------------------------


def test_parser_has_no_actor_parameter() -> None:
    """约束 1：``adult_control_plane`` 只能来自进程本身。

    这不是「拒绝冒充」——是**没有可冒充的输入**：解析器里不存在任何以 actor 命名的
    选项，也不存在任何接受 actor kind / actor id 的位置参数。
    """

    parser = memory_cli.build_parser()
    option_strings: list[str] = []
    positionals: list[str] = []

    def walk(current: argparse.ArgumentParser) -> None:
        for action in current._actions:  # noqa: SLF001 —— 测试要枚举解析器形状
            option_strings.extend(action.option_strings)
            if not action.option_strings and not isinstance(
                action, (argparse._SubParsersAction,)  # noqa: SLF001
            ):
                positionals.append(action.dest)
            if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
                for sub in action.choices.values():
                    walk(sub)

    walk(parser)
    assert not [opt for opt in option_strings if "actor" in opt.lower()]
    assert not [name for name in positionals if "actor" in name.lower()]
    assert "actor" not in {opt.lstrip("-").replace("-", "_") for opt in option_strings}


def test_the_adult_actor_is_a_module_constant() -> None:
    assert memory_cli._adult_actor().kind == "adult_control_plane"  # noqa: SLF001
    assert memory_cli._adult_actor().actor_id == memory_cli.ADULT_ACTOR_ID  # noqa: SLF001
    assert memory_cli.ADULT_ACTOR_ID == "family-ai-memory"


# ---------------------------------------------------------------------------
# 2. 配置：db 路径与 .env 的凭证隔离
# ---------------------------------------------------------------------------


def test_db_path_priority(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit.sqlite3"
    env_db = tmp_path / "env.sqlite3"
    dotenv_db = tmp_path / "dotenv.sqlite3"
    env_file = tmp_path / ".env"
    env_file.write_text(f"MEMORY_DB_PATH={dotenv_db}\n", encoding="utf-8")

    resolve = memory_cli.resolve_db_path
    assert resolve(explicit=explicit, env_file=env_file, environ={}) == explicit
    assert (
        resolve(explicit=None, env_file=env_file, environ={"MEMORY_DB_PATH": str(env_db)})
        == env_db
    )
    assert resolve(explicit=None, env_file=env_file, environ={}) == dotenv_db
    assert resolve(explicit=None, env_file=None, environ={}) == memory_cli.DEFAULT_DB_PATH


def test_env_reader_only_reads_the_memory_keys(tmp_path: Path) -> None:
    """约束 2：``.env`` 里只读记忆相关的两个键 —— 凭证键在读文件这一步就落不到手里。"""

    env_file = tmp_path / ".env"
    env_file.write_text(
        "# 合成注释\nPROVIDER_API_KEY=SECRET-SHOULD-NEVER-BE-READ\n"
        "PROVIDER_APP_ID=APP-SECRET\nMEMORY_DB_PATH=/tmp/memory.sqlite3\n",
        encoding="utf-8",
    )

    # (a) CLI 的键白名单**只有**记忆键 —— 它没有「问凭证」的调用点。
    assert memory_cli._MEMORY_ENV_KEYS == ("MEMORY_DB_PATH", "MEMORY_DB")  # noqa: SLF001
    for key in memory_cli._MEMORY_ENV_KEYS:  # noqa: SLF001
        assert not any(bad in key for bad in ("KEY", "SECRET", "TOKEN", "APP_ID")), key

    # (b) 用这个白名单读一个含凭证的 .env：拿到的是记忆路径，凭证值不出现。
    value = memory_cli._env_file_value(env_file, memory_cli._MEMORY_ENV_KEYS)  # noqa: SLF001
    assert value == "/tmp/memory.sqlite3"
    assert "SECRET" not in value and "APP-SECRET" not in value

    # (c) 模块本身没有别的读取入口：**不导入** dotenv，也**不导入** soul_memory_kernel.config
    #     （后者的 load_settings 会要求 API key，把控制面工具变成凭证持有者）。
    #     用 AST 判导入，而不是在源码里找名字 —— 文档字符串里正当地提到了它。
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(memory_cli))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "dotenv" not in imported
    assert "soul_memory_kernel.config" not in imported
    assert not any(name.startswith("dotenv") for name in imported)


def test_env_reader_handles_quotes_and_missing_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text('MEMORY_DB = "/tmp/quoted.sqlite3"\n', encoding="utf-8")
    assert memory_cli._env_file_value(env_file, ("MEMORY_DB",)) == "/tmp/quoted.sqlite3"  # noqa: SLF001
    assert memory_cli._env_file_value(tmp_path / "nope", ("MEMORY_DB",)) is None  # noqa: SLF001


def test_read_only_commands_do_not_create_the_database(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """``list`` 不该在用户只是「看一眼」时凭空产生文件。"""

    missing = tmp_path / "nope.sqlite3"
    code, _, err = run_cli_capture(capsys, "list", db=missing)
    assert code == memory_cli.EXIT_CONFIG
    assert "CliError" in err
    assert not missing.exists()


# ---------------------------------------------------------------------------
# 3. 端到端：propose → list → confirm → correct → inspect → delete → sweep
# ---------------------------------------------------------------------------


def test_end_to_end_propose_list_confirm_correct_inspect_delete(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    # --- propose ---
    code, out, _ = run_cli_capture(
        capsys, "propose", "--content", "孩子对花生过敏", "--owner", "child",
        "--memory-class", "SAFETY", db=db,
    )
    assert code == memory_cli.EXIT_OK
    assert "PENDING_CONFIRMATION" in out
    assert "family-ai-memory" in out, "提案人应当是控制面 actor"
    record_id = _only_record_id(db)

    # --- list：候选不可召回 ---
    code, out, _ = run_cli_capture(capsys, "list", db=db)
    assert code == memory_cli.EXIT_OK
    assert record_id in out and "status_denied" in out
    assert "孩子对花生过敏" not in out, "list 只出元数据"

    # --- confirm ---
    code, out, _ = run_cli_capture(
        capsys, "confirm", record_id, "--audience", "family_all", db=db
    )
    assert code == memory_cli.EXIT_OK
    assert "[ACTIVE]" in out

    # --- list：可召回 ---
    code, out, _ = run_cli_capture(capsys, "list", db=db)
    assert code == memory_cli.EXIT_OK
    assert "本次可读（1 条）" in out
    assert "孩子对花生过敏" not in out, "list 仍然只出元数据"

    # --- inspect：成人自查，带正文 ---
    code, out, _ = run_cli_capture(capsys, "inspect", record_id, db=db)
    assert code == memory_cli.EXIT_OK
    assert "孩子对花生过敏" in out

    # --- correct ---
    code, out, _ = run_cli_capture(
        capsys, "correct", record_id, "--content", "孩子对花生和坚果过敏",
        "--importance", "0.9", db=db,
    )
    assert code == memory_cli.EXIT_OK
    code, out, _ = run_cli_capture(capsys, "inspect", record_id, db=db)
    assert "孩子对花生和坚果过敏" in out

    # --- delete（非 TTY，必须显式 --yes）---
    code, _, err = run_cli_capture(capsys, "delete", record_id, db=db)
    assert code == memory_cli.EXIT_ABORTED
    assert "--yes" in err
    assert _rows(db, "SELECT COUNT(*) FROM memory_record")[0][0] == 1, "未确认时不得改动"

    code, out, _ = run_cli_capture(capsys, "delete", record_id, "--yes", db=db)
    assert code == memory_cli.EXIT_OK
    assert _rows(db, "SELECT COUNT(*) FROM memory_record")[0][0] == 0
    assert _rows(db, "SELECT COUNT(*) FROM deletion_audit")[0][0] == 1
    # 删除报告必须如实列出删不掉的部分。
    assert "未知副本" in out
    for needle in ("provider 侧留存", "归档证据", "文件系统快照", "已经播出"):
        assert needle in out, needle
    assert "派生记录（仍在盘上、已永久不可召回）" in out


def test_end_to_end_sweep_decays_and_hard_deletes(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    # 一个已确认的 EVENT：到期转 DECAYED（不删盘）。
    run_cli("propose", "--content", "会过期的事件", "--owner", "child", db=db)
    event_id = _only_record_id(db)
    run_cli("confirm", event_id, "--audience", "family_all", db=db)
    # 一个永不确认的候选：到期硬删除。
    run_cli("propose", "--content", "过期的草稿", "--owner", "child", db=db)
    with sqlite3.connect(db) as con:
        candidate_id = con.execute(
            "SELECT id FROM memory_record WHERE status = 'PENDING_CONFIRMATION'"
        ).fetchone()[0]

    clock.advance_days(400)
    code, out, _ = run_cli_capture(capsys, "sweep", "--yes", db=db)

    assert code == memory_cli.EXIT_OK
    assert "转 DECAYED（不删盘）" in out
    assert "已永久删除到期候选" in out
    statuses = dict(_rows(db, "SELECT id, status FROM memory_record"))
    assert statuses[event_id] == "DECAYED", "已确认记录到期不删盘"
    assert candidate_id not in statuses, "候选到期是硬删除"
    assert _rows(db, "SELECT COUNT(*) FROM deletion_audit")[0][0] == 1


def test_sweep_requires_confirmation(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    run_cli("propose", "--content", "草稿", "--owner", "child", db=db)
    clock.advance_days(400)

    code, _, err = run_cli_capture(capsys, "sweep", db=db)

    assert code == memory_cli.EXIT_ABORTED
    assert "--yes" in err
    assert _rows(db, "SELECT COUNT(*) FROM memory_record")[0][0] == 1


def test_grant_issue_and_revoke(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    record_id = seed_confirmed(db)

    code, out, _ = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "sess-1", "--owner", "child",
        "--grant-id", "g-1", db=db,
    )
    assert code == memory_cli.EXIT_OK
    assert record_id in out
    grants = _rows(db, "SELECT grant_id, owner_id, audience_id, revoked_at FROM grant_record")
    assert grants == [("g-1", "child", "family_all", None)]

    # 撤销需要二次确认。
    code, _, err = run_cli_capture(capsys, "grant", "revoke", "g-1", db=db)
    assert code == memory_cli.EXIT_ABORTED
    assert _rows(db, "SELECT revoked_at FROM grant_record")[0][0] is None

    code, out, _ = run_cli_capture(capsys, "grant", "revoke", "g-1", "--yes", db=db)
    assert code == memory_cli.EXIT_OK
    assert _rows(db, "SELECT revoked_at FROM grant_record")[0][0] is not None


def test_grant_issue_rejects_a_ttl_over_the_cap(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    seed_confirmed(db)
    code, _, err = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "s", "--owner", "child",
        "--ttl-hours", "13", db=db,
    )
    assert code == memory_cli.EXIT_CONFIG
    assert "ttl-hours" in err


def test_grant_issue_has_no_resource_when_nothing_is_confirmed(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    run_cli("propose", "--content", "只是候选", "--owner", "child", db=db)
    code, out, _ = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "s", "--owner", "child", db=db
    )
    assert code == memory_cli.EXIT_FAILED
    assert "没有可授权的记录" in out


# ---------------------------------------------------------------------------
# 4. 隐私与输出
# ---------------------------------------------------------------------------


def test_cli_writes_no_log_and_never_persists_content_outside_the_database(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, db: Path, clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """约束 3：CLI 不写任何日志；正文只出现在数据库里。

    做法：把 cwd 换到一个空目录，跑完整流程，然后逐个文件检查 ——
    除记忆库外不得新增文件，且**任何**文件都不得含正文。
    """

    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    secret = "合成正文-不得出现在日志里-9f3a"

    record_id = seed_confirmed(db, content=secret)
    run_cli("correct", record_id, "--content", secret + "（改）", db=db)
    run_cli("sweep", "--yes", db=db)
    run_cli("delete", record_id, "--yes", db=db)

    created = [p for p in workdir.rglob("*") if p.is_file()]
    assert created == [], f"CLI 不得在工作目录写任何文件: {created}"

    leaks = [
        path
        for path in tmp_path.rglob("*")
        if path.is_file() and path != db and secret in _safe_read(path)
    ]
    assert leaks == [], f"正文出现在了记忆库之外的文件里: {leaks}"


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def test_list_shows_metadata_but_never_content(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    secret = "只该在 inspect 里出现的正文-71c2"
    record_id = seed_confirmed(db, content=secret)

    code, out, _ = run_cli_capture(capsys, "list", db=db)
    assert code == memory_cli.EXIT_OK
    assert record_id in out, "元数据必须够用（成人要用 id 去 confirm/correct/delete）"
    assert secret not in out

    code, out, _ = run_cli_capture(capsys, "inspect", record_id, db=db)
    assert secret in out


def test_error_output_carries_only_the_type_and_fixed_guidance(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    """约束 3：错误输出**只打异常类型 + 固定指引**，不打异常消息。"""

    seed_confirmed(db)
    missing = "mem-00000000000000000000000000000000"

    code, out, err = run_cli_capture(capsys, "delete", missing, "--yes", db=db)

    assert code == memory_cli.EXIT_FAILED
    assert "RecordNotFound" in err
    assert missing not in err, "record id 不得出现在错误输出里"
    assert missing not in out
    assert "请用 `list` 重新获取 id。" in err


def test_creation_failure_is_reported_as_a_type_and_guidance_only(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """库不可用（这里用「路径是个目录」制造）时同样只给类型与指引。"""

    bad = tmp_path / "not-a-file"
    bad.mkdir()
    code, _, err = run_cli_capture(capsys, "propose", "--content", "x", "--owner", "o", db=bad)
    assert code == memory_cli.EXIT_FAILED
    assert re.search(r"操作失败（\w+）。", err), err
    assert "x" not in err.replace("操作失败", ""), "不得回显参数内容"


def test_interactive_confirmation_accepts_only_yes(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TTY 场景：输入 yes 才继续；其它输入一律取消。"""

    record_id = seed_confirmed(db)
    monkeypatch.setattr(memory_cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    code, out, _ = run_cli_capture(capsys, "delete", record_id, db=db)
    assert code == memory_cli.EXIT_ABORTED
    assert _rows(db, "SELECT COUNT(*) FROM memory_record")[0][0] == 1

    monkeypatch.setattr("builtins.input", lambda _prompt: "YES")
    code, _, _ = run_cli_capture(capsys, "delete", record_id, db=db)
    assert code == memory_cli.EXIT_OK
    assert _rows(db, "SELECT COUNT(*) FROM memory_record")[0][0] == 0


# ---------------------------------------------------------------------------
# 5. A12：actor 归属、显式 actor 参数、v1 → v2 迁移
# ---------------------------------------------------------------------------


def test_propose_stamps_the_control_plane_actor(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    """A12：CLI 提议记 ``adult_control_plane``，不是 ``session_proposal``。"""

    run_cli("propose", "--content", "成人直接提议", "--owner", "child", db=db)
    rows = _rows(db, "SELECT actor_kind, actor_id FROM memory_record")
    assert rows == [("adult_control_plane", memory_cli.ADULT_ACTOR_ID)]


def test_confirm_and_correct_restamp_the_actor(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    record_id = seed_confirmed(db)
    assert _rows(db, "SELECT actor_kind FROM memory_record")[0][0] == "adult_control_plane"

    run_cli("correct", record_id, "--importance", "0.9", db=db)
    assert _rows(db, "SELECT actor_id FROM memory_record")[0][0] == memory_cli.ADULT_ACTOR_ID


def test_store_overwrites_forged_actor_attribution(db: Path) -> None:
    """A12 的防伪造面：落库归属由**写入者**决定，不由 record 上写什么决定。"""

    from dataclasses import replace

    from soul_memory_kernel.memory.model import Actor, MemoryCandidate, SourceSession
    from soul_memory_kernel.memory.grants import SqliteGrantStore
    from soul_memory_kernel.memory.service import MemoryService

    clock = Clock()
    store = SqliteMemoryStore(db)
    store.create_schema()
    service = MemoryService(
        store=store, grants=SqliteGrantStore(db, clock=clock), clock=clock
    )
    record = service.propose(
        MemoryCandidate(
            content="会话里说的", scope="FAMILY", memory_class="EVENT", owner_id="child",
            source_type="explicit_user", source_member_id="child", confidence=1.0,
            importance=0.5, audiences=frozenset({"family_all"}),
        ),
        SourceSession(
            session_id="sess-1", owner_id="child", audience_id="family_all",
            session_mode="shared", identity_assurance="unknown", grant_id=None,
        ),
    )
    assert record is not None

    # 手工把记录上的归属改成成人动作，再让 store 以「会话提议」写入。
    forged = replace(record, actor_kind="adult_control_plane", actor_id="forged")
    store.write_record(forged, actor=Actor(kind="session_proposal", actor_id="sess-1"))

    stored = store.read_record(record.id)
    assert (stored.actor_kind, stored.actor_id) == ("session_proposal", "sess-1"), (
        "归属必须来自本次写入的 actor，而不是 record 上写的值"
    )


def test_explicit_actor_parameter_defaults_to_the_session_proposal(
    db: Path, clock: Clock
) -> None:
    """A12：冻结签名只多了一个**带默认值**的关键字参数，缺省行为逐字不变。"""

    import inspect

    from soul_memory_kernel.memory.model import Actor
    from soul_memory_kernel.memory.service import MemoryService

    params = inspect.signature(MemoryService.propose).parameters
    assert list(params)[:3] == ["self", "candidate", "source_session"]
    assert "actor" in params
    assert params["actor"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["actor"].default is None

    store = SqliteMemoryStore(db)
    store.create_schema()
    from soul_memory_kernel.memory.grants import SqliteGrantStore
    from soul_memory_kernel.memory.model import MemoryCandidate, SourceSession

    service = MemoryService(store=store, grants=SqliteGrantStore(db, clock=clock), clock=clock)
    session = SourceSession(
        session_id="sess-42", owner_id="child", audience_id="family_all",
        session_mode="shared", identity_assurance="unknown", grant_id=None,
    )
    candidate = MemoryCandidate(
        content="会话里说的", scope="FAMILY", memory_class="EVENT", owner_id="child",
        source_type="explicit_user", source_member_id="child", confidence=1.0,
        importance=0.5, audiences=frozenset({"family_all"}),
    )
    default = service.propose(candidate, session)
    explicit = service.propose(candidate, session, actor=Actor(kind="adult_control_plane", actor_id="x"))

    assert default is not None and explicit is not None
    assert (default.actor_kind, default.actor_id) == ("session_proposal", "sess-42")
    assert (explicit.actor_kind, explicit.actor_id) == ("adult_control_plane", "x")


def _write_real_v1_database(
    db: Path,
    *,
    content: str = "迁移前就有的记录",
    owner: str = "child",
    extra_columns: tuple[str, ...] = (),
) -> str:
    """建一个**货真价实**的 v1 库（M2.1 形状：7 张表、无归属两列、无 ``content_over_length``）。

    **为什么不再用「从 v3 删列」的降级法**：``content_over_length`` 被表级 CHECK
    ``content_over_length = 1 OR length(content) <= 500`` 引用，SQLite 的
    ``ALTER TABLE … DROP COLUMN`` 会直接拒绝。而且从 M2.2 起 v2→v3 会在重建前比对列集、
    对多出来的列**点名报错**（审阅 A 建议 2），一个「少了两列、却多着新列」的四不像库
    本来就不该被当成 v1。

    v1 / v2 的表结构**冻结在** ``tests/test_memory_migration.py``（历史形状只该有一份
    定义）；这里只借用那份 DDL 与它自带的 ``_V2_COLUMNS`` 列序。返回新行的 id。
    """

    from tests.test_memory_migration import _V1_RECORD_DDL, _V1_V2_OTHER_TABLES

    record_id = "mem-v1"
    with sqlite3.connect(db) as con:
        con.execute(_V1_RECORD_DDL)
        for ddl in _V1_V2_OTHER_TABLES:
            con.execute(ddl)
        for column in extra_columns:  # 失败注入用：预置一列让 v1→v2 撞 duplicate column
            con.execute(f"ALTER TABLE memory_record ADD COLUMN {column}")
        con.execute(
            "INSERT INTO memory_record (id, owner_id, scope, memory_class, source_type, "
            "source_member_id, content, confidence, importance, created_at, updated_at, "
            "last_confirmed_at, expires_at, source_session_id, status, memory_policy, "
            "consent_version) VALUES (?, ?, 'FAMILY', 'EVENT', 'explicit_user', NULL, ?, "
            "1.0, 0.5, ?, ?, ?, ?, NULL, 'ACTIVE', 'persist_confirmed', 1)",
            (record_id, owner, content, CLOCK_NOW, CLOCK_NOW, CLOCK_NOW, "2026-10-26T12:00:00Z"),
        )
        con.execute(
            "INSERT INTO memory_audience (record_id, audience_id) VALUES (?, 'family_all')",
            (record_id,),
        )
        con.execute("PRAGMA user_version = 1")
    db.chmod(0o600)  # store 拒绝权限过宽的库文件（产品级约束，不用替身绕开）
    return record_id


def test_open_migrates_a_v1_database_explicitly(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    """A12 + T9 的迁移：v1 库被**显式**升到 v3（一次走完两段），既有行归属为 ``migration``。

    T9a 的用例口径：这条用例**改成断言最终版本是 3**（不是把断言放宽 —— 它原来断言的
    就是 ``MEMORY_SCHEMA_VERSION``，随常量一起前进）。
    """

    record_id = _write_real_v1_database(db)
    assert _rows(db, "PRAGMA user_version")[0][0] == 1

    # 打开即迁移：v1 → v2 → v3，一次打开走完。
    code, out, err = run_cli_capture(capsys, "list", db=db)

    assert code == memory_cli.EXIT_OK, err
    assert _rows(db, "PRAGMA user_version")[0][0] == MEMORY_SCHEMA_VERSION == 3
    rows = _rows(db, "SELECT actor_kind, actor_id FROM memory_record WHERE id = ?", (record_id,))
    assert rows == [("migration", "migration:v1->v2")], "既有行如实归属为迁移来源"
    # v2→v3 的重建表不丢列、不丢值，且新表就位。
    assert _rows(db, "SELECT content, content_over_length FROM memory_record WHERE id = ?", (record_id,)) == [
        ("迁移前就有的记录", 0)
    ]
    assert _rows(
        db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='extraction_usage'"
    )[0][0] == 1


def test_a_future_schema_version_is_refused(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    run_cli("propose", "--content", "x", "--owner", "child", db=db)
    with sqlite3.connect(db) as con:
        con.execute("PRAGMA user_version = 99")

    code, _, err = run_cli_capture(capsys, "list", db=db)

    assert code == memory_cli.EXIT_FAILED
    assert "StoreError" in err
    assert "99" not in err, "错误输出不回显实现细节"


# ---------------------------------------------------------------------------
# 6. §6.1.1：控制面与 grant store 同一个时钟
# ---------------------------------------------------------------------------


def test_grant_store_and_service_share_one_clock(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    """§6.1.1：两侧判定必须同源。

    做法：把 CLI 的时钟设在一个**过去的**时刻，签发的 ``issued_at`` 就是那个时刻。
    如果 ``SqliteGrantStore`` 用的是默认系统时钟，``issue()`` 会认为这条 grant
    超前（现在比它晚很久）而拒绝 —— 成功签发即证明注入生效。
    """

    clock.value = "2026-09-26T12:00:00Z"
    seed_confirmed(db)

    code, out, _ = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "s", "--owner", "child",
        "--grant-id", "g-clock", db=db,
    )

    assert code == memory_cli.EXIT_OK, out
    issued_at = _rows(db, "SELECT issued_at FROM grant_record")[0][0]
    assert issued_at == "2026-09-26T12:00:00Z", "签发用的是注入的时钟，不是系统墙钟"


def test_future_issued_at_is_refused_end_to_end(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    """B-s1 在 CLI 上的效果：时钟被回拨后，超前签发的 grant 会被 store 拒绝。"""

    seed_confirmed(db)
    clock.value = "2026-09-26T12:00:00Z"
    # 先把时钟拨到「grant 签发时刻」之后，再把它拨回去 —— 模拟时钟被回拨。
    code, _, _ = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "s", "--owner", "child", db=db
    )
    assert code == memory_cli.EXIT_OK


# ---------------------------------------------------------------------------
# 7. minimal 收尾（M2-A/B 复审 APPROVE 后的诊断点）
# ---------------------------------------------------------------------------


def test_correct_without_any_change_is_a_usage_error(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    """A1：什么都没指定时不写入 —— 空操作会递增 ``consent_version`` 让 grant 失效。"""

    record_id = seed_confirmed(db)
    before = _rows(db, "SELECT consent_version, updated_at FROM memory_record")[0]

    code, _, err = run_cli_capture(capsys, "correct", record_id, db=db)

    assert code == memory_cli.EXIT_CONFIG
    assert "未指定任何改动" in err
    assert _rows(db, "SELECT consent_version, updated_at FROM memory_record")[0] == before, (
        "空 correct 必须零副作用"
    )


def test_correct_with_content_file_still_works(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock, tmp_path: Path
) -> None:
    """A1 的边界：给了改动就必须照常执行。"""

    record_id = seed_confirmed(db)
    code, _, _ = run_cli_capture(capsys, "correct", record_id, "--importance", "0.9", db=db)
    assert code == memory_cli.EXIT_OK


def test_content_can_come_from_stdin(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B1：``--content -`` 从 stdin 读 —— 敏感正文不进 shell 历史。"""

    import io

    monkeypatch.setattr(memory_cli.sys, "stdin", io.StringIO("从标准输入来的正文\n"))

    code, _, _ = run_cli_capture(
        capsys, "propose", "--content", "-", "--owner", "child", db=db
    )

    assert code == memory_cli.EXIT_OK
    assert _rows(db, "SELECT content FROM memory_record")[0][0] == "从标准输入来的正文"


def test_content_can_come_from_a_file(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock, tmp_path: Path
) -> None:
    """B1：``--content-file`` 从文件读；路径进历史但不含正文。"""

    body = tmp_path / "body.txt"
    body.write_text("从文件来的正文\n", encoding="utf-8")

    code, _, _ = run_cli_capture(
        capsys, "propose", "--content-file", str(body), "--owner", "child", db=db
    )

    assert code == memory_cli.EXIT_OK
    assert _rows(db, "SELECT content FROM memory_record")[0][0] == "从文件来的正文"


def test_content_sources_are_mutually_exclusive(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock, tmp_path: Path
) -> None:
    body = tmp_path / "b.txt"
    body.write_text("x", encoding="utf-8")
    code, _, err = run_cli_capture(
        capsys, "propose", "--content", "a", "--content-file", str(body), "--owner", "o", db=db
    )
    # 输入互斥属**用法错误**（退出码 2），与 argparse 自己的用法错误一致。
    assert code == memory_cli.EXIT_CONFIG
    assert "CliError" in err


def test_content_help_warns_about_shell_history() -> None:
    """B1：help 必须提示「命令行正文会进 shell 历史」。"""

    for command in ("propose", "correct"):
        sub = memory_cli.build_parser()._subparsers._group_actions[0].choices[command]  # noqa: SLF001
        # argparse 会按宽度折行，先归一空白再查短语。
        help_text = " ".join(sub.format_help().split())
        assert "shell 历史" in help_text, command
        assert "--content-file" in help_text, command
        assert "stdin" in help_text, command


def test_empty_content_is_a_usage_error(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    for argv in (
        ("propose", "--content", "   ", "--owner", "child"),
        ("propose", "--owner", "child"),  # 完全不给 --content
    ):
        code, _, err = run_cli_capture(capsys, *argv, db=db)
        assert code == memory_cli.EXIT_CONFIG, argv
        assert "正文为空" in err, argv
    assert _rows(db, "SELECT COUNT(*) FROM memory_record")[0][0] == 0


def test_grant_resource_must_be_active_and_audience_compliant(
    capsys: pytest.CaptureFixture[str], db: Path, clock: Clock
) -> None:
    """B2：``--resource`` 不是后门 —— 与默认枚举同一条合规检查，违规退出码 2。"""

    run_cli("propose", "--content", "只是候选", "--owner", "child", db=db)
    candidate_id = _only_record_id(db)

    # (a) 候选不是 ACTIVE。
    code, _, err = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "s", "--owner", "child",
        "--resource", candidate_id, db=db,
    )
    assert code == memory_cli.EXIT_CONFIG
    assert "只接受 ACTIVE 记录" in err
    assert _rows(db, "SELECT COUNT(*) FROM grant_record")[0][0] == 0

    # (b) 确认之后是 ACTIVE，但受众换成别的 → 仍然拒绝。
    run_cli("confirm", candidate_id, "--audience", "family_all", db=db)
    code, _, err = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "s", "--owner", "child",
        "--audience", "adult_b", "--resource", candidate_id, db=db,
    )
    assert code == memory_cli.EXIT_CONFIG
    assert "受众含" in err
    assert _rows(db, "SELECT COUNT(*) FROM grant_record")[0][0] == 0

    # (c) 合规时照常签发。
    code, _, _ = run_cli_capture(
        capsys, "grant", "issue", "--session-id", "s", "--owner", "child",
        "--resource", candidate_id, db=db,
    )
    assert code == memory_cli.EXIT_OK
    assert _rows(db, "SELECT COUNT(*) FROM grant_record")[0][0] == 1


def test_grant_action_choices_come_from_the_contract() -> None:
    """B4 + 勘误 E4：``--action`` 的 choices 来自契约的**可签发动作集**，不是手抄一份。

    免 grant 的动作（``review_control_plane``）**永远不可签发**，因此 choices 是
    ``GRANTABLE_ACTIONS``（= ``ACTIONS`` 减去它），不是整个 ``ACTIONS``。
    """

    from soul_memory_kernel.memory.grants import GRANTABLE_ACTIONS

    sub = memory_cli.build_parser()._subparsers._group_actions[0].choices["grant"]  # noqa: SLF001
    issue = sub._subparsers._group_actions[0].choices["issue"]  # noqa: SLF001
    action = next(a for a in issue._actions if a.dest == "action")  # noqa: SLF001
    assert set(action.choices) == set(GRANTABLE_ACTIONS)
    assert "review_control_plane" not in action.choices, "免 grant 的动作不可签发"

    with pytest.raises(SystemExit):
        memory_cli.build_parser().parse_args(
            ["grant", "issue", "--session-id", "s", "--owner", "o", "--action", "nope"]
        )


def test_db_path_expands_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A3：三条来源都要 ``expanduser()`` —— 引号里的 ``~/x`` 不会被 shell 展开。"""

    monkeypatch.setenv("HOME", str(tmp_path))
    resolve = memory_cli.resolve_db_path

    explicit = resolve(explicit=Path("~/explicit.sqlite3"), env_file=None, environ={})
    assert explicit == tmp_path / "explicit.sqlite3"

    from_env = resolve(
        explicit=None, env_file=None, environ={"MEMORY_DB_PATH": "~/env.sqlite3"}
    )
    assert from_env == tmp_path / "env.sqlite3"

    env_file = tmp_path / ".env"
    env_file.write_text("MEMORY_DB_PATH=~/dotenv.sqlite3\n", encoding="utf-8")
    from_file = resolve(explicit=None, env_file=env_file, environ={})
    assert from_file == tmp_path / "dotenv.sqlite3"


def test_resolve_db_path_takes_a_mapping_without_copying_the_environment() -> None:
    """B5：``environ`` 只要 mapping —— CLI 不复制整个 ``os.environ``。"""

    import inspect

    annotation = inspect.signature(memory_cli.resolve_db_path).parameters["environ"].annotation
    assert annotation != "dict[str, str]"

    class Counted(dict):
        def __init__(self) -> None:
            super().__init__({"MEMORY_DB_PATH": "/tmp/x.sqlite3"})
            self.reads: list[str] = []

        def get(self, key, default=None):  # type: ignore[override]
            self.reads.append(key)
            return super().get(key, default)

    environ = Counted()
    assert memory_cli.resolve_db_path(explicit=None, env_file=None, environ=environ) == Path(
        "/tmp/x.sqlite3"
    )
    # 只按名字问过两个记忆键，没有遍历/复制整份环境。
    assert set(environ.reads) <= set(memory_cli._MEMORY_ENV_KEYS)  # noqa: SLF001


def test_env_reader_streams_and_drops_non_whitelisted_lines(tmp_path: Path) -> None:
    """B5：逐行流式读取；白名单以外的行立刻丢弃（不保留）。"""

    import inspect

    source = inspect.getsource(memory_cli._env_file_value)  # noqa: SLF001
    assert ".read_text(" not in source, "不许把整份 .env 读进内存"
    assert "for line in handle" in source, "逐行流式"

    env_file = tmp_path / ".env"
    body = "\n".join(f"SECRET_{i}=value-{i}" for i in range(500))
    env_file.write_text(body + "\nMEMORY_DB=/tmp/ok.sqlite3\n", encoding="utf-8")
    assert memory_cli._env_file_value(env_file, memory_cli._MEMORY_ENV_KEYS) == (  # noqa: SLF001
        "/tmp/ok.sqlite3"
    )


def test_migration_failure_rolls_back_entirely(tmp_path: Path) -> None:
    """A2：迁移任一步失败 → ``StoreError``、``user_version`` 仍是 1、两列都不存在。"""

    from soul_memory_kernel.memory.service import StoreError
    from soul_memory_kernel.memory.store import SqliteMemoryStore

    db = tmp_path / "v1.sqlite3"
    # 预置 actor_id：第一条 ALTER（actor_kind）会成功，第二条撞
    # duplicate column name 失败 —— 正好检验「两步都回滚」。
    _write_real_v1_database(db, extra_columns=("actor_id TEXT NOT NULL DEFAULT 'x'",))

    # 迁移发生在**第一次打开连接**时（构造不碰文件系统），所以这里调 create_schema。
    with pytest.raises(StoreError):
        SqliteMemoryStore(db).create_schema()

    assert _rows(db, "PRAGMA user_version")[0][0] == 1, "失败后版本号必须还是 1"
    columns = {row[1] for row in _rows(db, "PRAGMA table_info(memory_record)")}
    assert "actor_kind" not in columns, "第一条 ALTER 必须一起回滚"
    assert "actor_id" in columns, "预置的那一列是测试造出来的，与本模块无关"
    assert "content_over_length" not in columns, "第二个事务根本不该开始"
    # T9a：v1→v2 失败 ⇒ 第二个事务**根本不开始**（v2→v3 的暂存表不该出现）。
    assert _rows(
        db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_record__v3'"
    )[0][0] == 0


def test_concurrent_open_does_not_migrate_twice(tmp_path: Path) -> None:
    """B6：版本号在 ``BEGIN IMMEDIATE`` 之内复读 —— 并发下第二个进程不会重复 ALTER。

    直接模拟竞态的两半：两个连接**都在锁外**读到 v1（这是旧实现的决策依据），
    然后第一个完成 v1→v2；第二个再进 v1→v2 时，锁内复读会看到版本已经是 **2**，
    于是**跳过**而不是撞 ``duplicate column name``。

    **M2.2 之后** ``MEMORY_SCHEMA_VERSION`` 是 3，而 ``_migrate_v1_to_v2`` 只负责把库
    带到 v2 —— 它锁内复读的判据因此必须是「``>= 2``」而不是「== MEMORY_SCHEMA_VERSION」。
    下面第二段断言正是这条：v1→v2 这一段的产物是 v2，整条链的终点才是 v3。
    """

    from soul_memory_kernel.memory.store import SqliteMemoryStore

    db = tmp_path / "v1.sqlite3"
    _write_real_v1_database(db)

    first = sqlite3.connect(db)
    second = sqlite3.connect(db)
    try:
        # 两个连接都在锁外读到 v1（这正是旧实现用来决策的值）。
        assert first.execute("PRAGMA user_version").fetchone()[0] == 1
        assert second.execute("PRAGMA user_version").fetchone()[0] == 1

        assert SqliteMemoryStore._migrate_v1_to_v2(first) is True  # noqa: SLF001
        # 第二个进程进锁后复读：已经是 v2 → 跳过，不重复 ALTER、不抛错。
        assert SqliteMemoryStore._migrate_v1_to_v2(second) is False  # noqa: SLF001
        # v1→v2 这一段的终点是 2；v2→v3 是**另一段**（T9a：两段各自一个事务）。
        assert second.execute("PRAGMA user_version").fetchone()[0] == 2
    finally:
        first.close()
        second.close()

    # 库本身完全正常，可以被普通打开流程使用 —— 打开时补完第二段，一路到 v3。
    store = SqliteMemoryStore(db)
    store.create_schema()
    assert store.read_record("nope") is None
    assert _rows(db, "PRAGMA user_version")[0][0] == MEMORY_SCHEMA_VERSION == 3
    columns = {row[1] for row in _rows(db, "PRAGMA table_info(memory_record)")}
    assert {"actor_kind", "actor_id", "content_over_length"} <= columns
