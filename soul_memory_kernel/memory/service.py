"""M2 记忆服务：五个接口 + TTL 扫描（W0 冻结签名与错误语义；实现归 W3）。

接口名与位置参数沿用 ``docs/M2-PREPARATION.md`` 第 9 行的冻结形式：
``propose(candidate, source_session)`` / ``confirm_shared(candidate_id, audience)`` /
``query(session_access, purpose)`` / ``correct(id, replacement, actor)`` /
``delete(id, actor)``。相对该形式的**两处留痕的形状扩展**：

1. ``confirm_shared(candidate_id, audience)`` 增加**必填**位置参数 ``actor``
   （D3 要求每次成人动作可归属）。不扩展就无法满足 D3。
2. ``correct(id, replacement, actor)`` 的第一个参数命名为 ``record_id``
   （``id`` 会遮蔽内置名）。**位置与语义不变。**

其余参数是 keyword-only 的实现必需输入，不算改接口。

四条贯穿全部接口的纪律：

1. **读路径走 ``policy.authorize()``** 并按结论过滤。**M2.1 的写路径不走
   ``policy.require()``**（A7）：写门禁是「相位门 + actor 门 + 迁移表」三重检查
   （契约页 §3.7），由本服务直接执行。``require()`` 保留为 **M2.2 起**的写路径统一
   入口，签名已冻结、M2.1 不调用。
2. **读路径不抛授权异常**：没有授权是正常状态，退化为「没有记忆」，不是崩溃。
   写路径拒绝时抛 :class:`AuthorizationError`（携带 ``AuthorizationDecision``）。
3. **``do_not_persist`` 在 ``propose()`` 入口拦下**，绝不进入存储层。
4. **M2.1 相位限制**：产品路径只接受 ``scope="FAMILY"`` 与
   ``origin="explicit_user"``；``PERSONAL`` / ``SAFETY`` **scope** 由
   ``propose()`` / ``confirm_shared()`` 直接拒绝（``scope_not_enabled``），
   非显式 origin 抛 :class:`MemoryValidationError`。
   **``memory_class="SAFETY"``（内容类型，如过敏）在 ``FAMILY`` scope 下照常支持。**

实现说明（W3）
--------------

**判权调用的落点。** ``policy.authorize()`` 只通过 ``policy`` 模块属性调用，
不把函数名绑进本模块 —— 这样测试可以在不依赖 W2 实现的前提下替换判权函数，
而生产路径上调用的就是契约里的那个 ``authorize()``。判权输入只在本文件的
``_authorize()`` 里构造，``now`` 一律来自注入时钟。

**写路径的 ``require()`` 缺口（契约缺口，交付报告已登记）。** ``correct`` /
``confirm_shared`` / ``delete`` 的冻结签名里没有 ``access`` / ``grant`` /
``session_id`` / ``audience_id``，``propose`` 也没有 ``grant`` 参数（只有
``SourceSession.grant_id``），而 M2.1 无法构造带 ``session_owner`` 的
``SessionAccess``（W4 才加 ``authorization_ref``）。因此 M2.1 的写路径门是
**相位门**（``AuthorizationError(scope_not_enabled)``）+ **actor 门**
（§2.4 权限表，违规抛 :class:`IllegalTransition`）+ **迁移表校验**；
``policy.require()`` 在本相位没有可表达的调用点。不自行编造一份「合成 grant」——
那正是「不得在实现里顺手发明授权语义」禁止的事。

**``propose`` 的写入归属（主控仲裁 2026-09-26）。** 候选写入的 actor 是
``Actor(kind="session_proposal", actor_id=source_session.session_id)`` ——
**不是** ``adult_control_plane``：会话里产生的候选不是一次成人动作（D3 的确认/纠正/
删除才需要成人控制面），把它记成成人动作会伪造审计归属。归属到**会话**而不是某个
家人：M2.1 的会话里没有经认证的成人身份（grant 不是身份认证）。

``session_proposal`` 是契约补丁新增的**非成人** actor 类型；在本分支里
``model.ACTOR_KINDS`` / ``ActorKind`` 还没有这个取值，因此这里**按名字编码**
（集成时不需要改本行）。它是「只能写候选」的 actor：``confirm_shared`` / ``correct``
/ ``delete`` / ``sweep_expired`` 收到它一律 :class:`IllegalTransition`
（``_validate_actor`` 在补丁合入前会先按未知 kind 以 :class:`MemoryValidationError`
拒绝 —— 同样是 fail-closed，只是错误类型等契约常量到位后自动对齐）。

**存储接口的三个必要原语（主控仲裁 2026-09-26 已裁决）。**
契约 §7.1 要求 ``delete()`` 与候选到期写 ``deletion_audit`` 行，但 ``MemoryStore``
Protocol 原本没有写审计行的方法（``hard_delete`` 的 docstring 把这件事交给「调用方」）；
``sweep_expired()`` 也没有任何可枚举到期记录的接口（``list_eligible`` 是 ``query()``
的入口查询，强制受众过滤）。**主控仲裁后归 W1 的 store**，W3 直接调用：

```python
def list_expired(self, *, now: str) -> tuple[MemoryRecord, ...]: ...
def hard_delete_with_audit(          # A11：删除与审计同一事务，产品路径只走这一个
    self,
    *,
    record_id: str,
    actor: Actor,
    deleted_at: str,
    derived_removed: int = 0,
    unknown_copies: tuple[str, ...] = (),
) -> DeletionOutcome: ...
def write_deletion_audit(            # A11 的构件，产品路径不直接调用
    self,
    *,
    record_id: str,
    actor: Actor,
    deleted_at: str,
    tables_touched: tuple[str, ...],
    derived_removed: int = 0,
    unknown_copies: tuple[str, ...] = (),
) -> str:  # 返回 audit_id，由 store 生成
    ...
```

它们是**必需方法**：store 没实现就当场 ``AttributeError``（响亮失败），
不存在「跳过审计 / 扫一半」的降级路径。理由：``list_eligible`` 强制按受众过滤
（``audience_id`` 是必填），枚举不出「全部到期记录」；best-effort 探测会让非
``family_all`` 受众的到期候选永远留在磁盘上，恰好是 §6.2 硬删除要消除的驻留。

**读路径的 fail-closed。**
- 到期记录**实时排除**（§4.5/§6.3）：即使 ``status`` 还是 ``ACTIVE``，只要
  ``expires_at <= now`` 就不进快照；正确性不依赖 ``sweep_expired()``。
- 时钟不可解析时整个读路径退化为空快照：每条列出的记录都是 ``clock_invalid``
  （对齐 ``DENY_ORDER`` 第 1 条，且不依赖 ``authorize()`` 的实现）。
- 血缘无法证实（祖先缺失 / 解析抛错）一律按 ``missing_provenance`` 拒绝该记录，
  绝不「只授权可见的那部分」（§7.4）。
- ``resolve_provenance`` 抛 :class:`StoreError` 时向上传播（真实存储故障不该伪装成
  「没有记忆」）；**缺源请用返回值表达**（返回被截断的闭包），W3 会据此拒绝。
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from soul_memory_kernel.memory import policy
from soul_memory_kernel.memory.model import (
    ACTOR_KINDS,
    LEGAL_TRANSITIONS,
    M2_1_ALLOWED_ORIGINS,
    M2_1_ALLOWED_SCOPES,
    MAX_CONTENT_CHARS,
    MEMORY_CLASSES,
    MEMORY_STATUSES,
    QUERY_PURPOSES,
    REQUESTED_POLICIES,
    RESERVED_OWNER_IDS,
    SCOPES,
    SOURCE_TYPES,
    TTL_TRANSITIONS,
    Actor,
    DeletionReport,
    Grant,
    MemoryCandidate,
    MemoryCorrection,
    MemoryRecord,
    MemorySnapshot,
    QueryPurpose,
    RetentionPolicy,
    SnapshotEntry,
    SourceSession,
)
from soul_memory_kernel.memory.policy import M2_1_WRITE_GATE, Action, AuthorizationDecision
from soul_memory_kernel.memory.store import GrantStore, MemoryStore
from soul_memory_kernel.soul.policy import SessionAccess

# ``MAX_CONTENT_CHARS`` 由上面的 ``model`` 导入**再导出**（M2.2 T9f 搬家）：常量现在住在
# ``model.py``，而 ``apps/memory_cli.py`` 与 ``tests/test_memory_integration.py`` 都从
# ``service`` 导入它 —— 删掉这条再导出会打断 W8 的文件（契约 §6 T9f 明令保留）。
#
# 它同时被**下沉**到 store 的 ``write_record()`` 与 DDL CHECK（T9c 的写入边界表）：
# 本模块的 ``_validate_content()`` 是第一道，不是唯一一道。


class MemoryServiceError(ValueError):
    """记忆服务错误基类。沿用 ``SoulError`` / ``ProfileError`` 的 ``ValueError`` 惯例。"""


class MemoryValidationError(MemoryServiceError):
    """入参形状非法：字段缺失、超长、枚举越界、数值超出 [0,1]、时间戳不可解析，
    或 ``propose()`` 收到 M2.1 不支持的 ``origin``（非 ``explicit_user``）。"""


class AuthorizationError(MemoryServiceError):
    """写路径被拒绝。携带结构化的 :class:`AuthorizationDecision` 供上层记录。

    M2.1 的拒绝原因包括：``scope_not_enabled``（`PERSONAL` / `SAFETY` scope）、
    ``clock_invalid``（注入时钟不可解析时先于一切拒绝）、``no_grant`` 等 ——
    全部来自 :data:`soul_memory_kernel.memory.policy.DENY_ORDER`。
    """

    def __init__(self, decision: AuthorizationDecision) -> None:
        super().__init__(f"memory action denied: {decision.reason}")
        self.decision = decision


class RecordNotFound(MemoryServiceError):
    """目标记录不存在（或已被硬删除）。"""


class IllegalTransition(MemoryServiceError):
    """状态迁移不在 :data:`soul_memory_kernel.memory.model.LEGAL_TRANSITIONS` 内，
    或 ``actor.kind`` 无权执行该迁移（见 :class:`soul_memory_kernel.memory.model.Actor`）。

    **不允许静默 no-op**：非法迁移必须是可观测的错误，否则「删除后又被改回 ACTIVE」
    这类事故会无声发生。
    """

    def __init__(self, from_status: str, to_status: str, actor_kind: str) -> None:
        super().__init__(f"illegal memory transition: {from_status} -> {to_status} by {actor_kind}")
        self.from_status = from_status
        self.to_status = to_status
        self.actor_kind = actor_kind


class StoreError(MemoryServiceError):
    """SQLite / 文件系统层故障：权限过宽、symlink、schema 版本不符、完整性检查失败。"""


#: 内容副本无法枚举/无法承诺的位置（契约 §7.2）。**必须显式列出，禁止填空冒充完整。**
#: 最后一条是诚实登记：W3 的服务层没有文件系统视野，可安全重写的评测中间产物
#: （§7.1 第 9 项）在 M2.1 既未枚举也未删除。
_UNKNOWN_COPY_LOCATIONS: tuple[str, ...] = (
    "provider 侧留存（未验证，不得承诺已删除）",
    "带登记 sha256 的归档证据（评测 manifest / evidence JSON，不重写以免哈希失效）",
    "既有旧 JSONL 全文日志中的历史副本（需按「可控历史内容副本清单」另行盘点）",
    "文件系统快照与备份（Time Machine 等）",
    "已经播出或显示过的内容（物理上无法撤回）",
    "可安全重写的评测中间产物（W3 服务层无文件系统视野，M2.1 未枚举、未删除）",
)

#: 已确认记录的到期动作：状态迁移，不删盘（D5）。
_DECAYED = "DECAYED"
_CANDIDATE = "PENDING_CONFIRMATION"
_ACTIVE = "ACTIVE"

#: ``purpose`` → 授权动作（M2.2 §4.3，T15 第 2 处的落地）。
#:
#: M2.1 的四个 purpose 全是 ``read_model``（本地查询）；M2.2 新增的
#: ``control_plane_review`` 走 ``review_control_plane``（成人复审候选正文）。
#: **动作由 purpose 决定**，不是调用方传进来的 —— 否则调用方就能挑一个更宽的动作。
#: ``tests/test_memory_service.py`` 断言这张表与 ``QUERY_PURPOSES`` 相等。
_ACTION_FOR_PURPOSE: dict[str, Action] = {
    "session_projection": "read_model",
    "adult_list": "read_model",
    "adult_inspect": "read_model",
    "deletion_audit": "read_model",
    "control_plane_review": "review_control_plane",
}

#: 快照**携带正文**的 purpose 白名单（§4.3）。其余 purpose 只带元数据。
_CONTENT_CARRYING_PURPOSES: frozenset[str] = frozenset(
    {"session_projection", "adult_inspect", "control_plane_review"}
)


def _denied(reason: str) -> AuthorizationDecision:
    return AuthorizationDecision(allowed=False, reason=reason)  # type: ignore[arg-type]


def _is_non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


class MemoryService:
    """记忆读写服务。构造依赖注入，便于测试替换时钟与存储。

    冻结的构造签名（W4 的接缝与 W5 的 CLI 都按此实例化）::

        MemoryService(store=SqliteMemoryStore(db_path),
                      grants=SqliteGrantStore(db_path),
                      clock=<注入的 ISO-8601 UTC 时钟>,
                      retention=RetentionPolicy(...) | None)
    """

    def __init__(
        self,
        *,
        store: MemoryStore,
        grants: GrantStore,
        clock: Callable[[], str],
        retention: RetentionPolicy | None = None,
    ) -> None:
        """``clock`` 返回 ISO-8601 UTC 字符串，必须是注入的，不允许在方法里取墙钟。"""

        if not callable(clock):
            raise MemoryValidationError("clock must be a callable returning an ISO-8601 UTC string")
        self._store = store
        self._grants = grants
        self._clock = clock
        self._retention = RetentionPolicy() if retention is None else retention

    # ---------------------------------------------------------------- 写入

    def propose(
        self,
        candidate: MemoryCandidate,
        source_session: SourceSession,
        *,
        actor: Actor | None = None,
    ) -> MemoryRecord | None:
        """提交一条候选，落库为 ``PENDING_CONFIRMATION``。

        返回
        ----
        - 正常：新记录，``status="PENDING_CONFIRMATION"``、``memory_policy="candidate_only"``。
          即使 ``requested_policy="persist_confirmed"`` 也不会直接写成 ``ACTIVE`` ——
          变成可召回只有 ``confirm_shared()`` 一条路径。
        - ``requested_policy == "do_not_persist"``：返回 ``None``，**不落库**。
          这是 ``do_not_persist`` 的第一落点，在任何写入之前生效。

        ``actor``（**A12**，可选 keyword-only）
        ------------------------------------
        本次提议的**发起主体**。缺省 ``None`` = 会话内提议，实现自造
        ``Actor(kind="session_proposal", actor_id=source_session.session_id)``
        （与 A12 之前的行为逐字一致，冻结签名只多了一个带默认值的可选参数）。

        成人经 CLI 提议必须显式传 ``Actor(kind="adult_control_plane", ...)`` ——
        否则成人提议会被记成会话提议（§3.7 A-s2 登记的反向错误），
        既过不了 actor 门的语义，也让 ``memory_record.actor_*`` 的归属失真。

        ``actor.kind`` 必须落在 :data:`soul_memory_kernel.memory.policy.M2_1_WRITE_GATE`
        的 ``propose`` 允许集里（``adult_control_plane`` / ``session_proposal``）。

        抛错
        ----
        :class:`AuthorizationError`，``reason="scope_not_enabled"``
            ``candidate.scope`` 不是 ``FAMILY``。**这是 M2.1 相位限制，不是权限问题**：
            `PERSONAL` / `SAFETY` scope 的产品路径尚未裁决（受控私人会话、安全记忆给谁看）。
            注意 ``memory_class="SAFETY"`` 的内容类型在 ``FAMILY`` scope 下不受此限。
        :class:`AuthorizationError`（actor 门）
            调用方传入的 ``actor.kind`` 不是 ``session_proposal`` 或
            ``adult_control_plane``（§3.7 的 actor 门）。
            **``actor`` 必须是实际发起者**：会话里家人说「记住这个」要用
            ``Actor(kind="session_proposal", ...)``，**严禁记成 ``adult_control_plane``**
            —— 那会把家人的随口一说伪装成成人已确认（A8）。
        :class:`MemoryValidationError`
            字段非法；``scope="FAMILY"`` 但 ``audiences`` 为空（家庭共享必须有显式受众，
            不能靠默认值）；或 ``origin`` 不在
            :data:`soul_memory_kernel.memory.model.M2_1_ALLOWED_ORIGINS` 内
            （M2.1 只接受 ``explicit_user``，自动提取候选归 M2.2）。

        实现顺序（W3）
        --------------
        1. ``do_not_persist`` 拦截 —— **第一道判断**，在任何校验/写入之前，因此
           「这句话不落库」的承诺不依赖候选其余字段是否合法；
        2. 相位门 ``scope ∉ M2_1_ALLOWED_SCOPES`` → ``scope_not_enabled``；
        3. 形状校验（含 ``origin`` 白名单）→ :class:`MemoryValidationError`；
        4. 落库为候选：``consent_version=1``、``last_confirmed_at=None``、
           ``source_ids=()``、``expires_at = now + candidate_days``（SAFETY 类候选同样
           受候选期约束）。
        """

        if not isinstance(candidate, MemoryCandidate):
            raise MemoryValidationError("candidate must be a MemoryCandidate")
        if candidate.requested_policy == "do_not_persist":
            # 落点一：不写 DB、不建记录。DDL 的 CHECK 排除该取值，构成第二道防线。
            return None
        if candidate.scope not in M2_1_ALLOWED_SCOPES:
            raise AuthorizationError(_denied("scope_not_enabled"))

        self._validate_candidate(candidate, source_session)
        now = self._require_clock()
        # 契约补丁（主控仲裁 2）：会话内候选的 actor 是**非成人**的 session_proposal，
        # actor_id 用 session_id。按名字编码；model.ACTOR_KINDS 合入该取值后本行不变。
        if actor is None:
            actor = Actor(kind="session_proposal", actor_id=source_session.session_id)
        self._validate_actor(actor)
        self._require_write_gate("propose", actor)

        record = MemoryRecord(
            id=f"mem-{uuid4().hex}",
            owner_id=candidate.owner_id,
            scope=candidate.scope,
            memory_class=candidate.memory_class,
            source_type=candidate.source_type,
            source_member_id=candidate.source_member_id,
            content=candidate.content,
            confidence=float(candidate.confidence),
            importance=float(candidate.importance),
            created_at=now,
            updated_at=now,
            last_confirmed_at=None,
            expires_at=self._expiry_for(candidate.memory_class, is_candidate=True, now=now),
            source_session_id=source_session.session_id,
            status=_CANDIDATE,
            memory_policy="candidate_only",
            audiences=frozenset(candidate.audiences),
            consent_version=1,
            source_ids=(),
            # A12：归属在**构造时**就写进去，这样返回的对象与落库的行一致。
            # store.write_record 仍会用它的 actor 参数覆盖一次（防伪造的兜底），
            # 两边同源，因此那次覆盖是 no-op。
            actor_kind=actor.kind,
            actor_id=actor.actor_id,
        )
        self._store_call("write_record", self._store.write_record, record, actor=actor)
        return record

    def confirm_shared(
        self,
        candidate_id: str,
        audience: frozenset[str],
        actor: Actor,
    ) -> MemoryRecord:
        """把候选提升为可共享记忆。**唯一能把记录变成可召回的路径。**

        形状留痕：相对 ``M2-PREPARATION.md:9`` 的 ``confirm_shared(candidate_id, audience)``
        增加了**必填**位置参数 ``actor``（D3：每次成人动作必须可归属）。

        副作用：``status -> ACTIVE``、``memory_policy -> persist_confirmed``、
        ``last_confirmed_at = now``、``consent_version += 1``、``audiences`` 替换为
        ``audience``、``expires_at`` 按新配置重算（`FAMILY` + ``memory_class="SAFETY"``
        的已确认记录 ``expires_at`` 为 ``NULL``，即不过期）。

        ``consent_version`` 递增是关键：它让所有既有 grant 对该记录立刻
        ``stale_consent``，因此确认动作本身就是一次全量撤权重授权。

        抛错
        ----
        :class:`AuthorizationError`（``reason="scope_not_enabled"`` 表示目标记录的 scope
        在 M2.1 未启用）/ :class:`MemoryValidationError`（§3.7 的 actor 门：
        ``actor.kind`` 不是 ``adult_control_plane``。确认是成人动作，
        ``session_proposal`` 与 ``ttl_expiry`` 都不许确认）/ :class:`RecordNotFound` /
        :class:`IllegalTransition` / :class:`MemoryValidationError`（``audience`` 为空）。

        实现顺序（W3）
        --------------
        先做入参形状校验，再读记录（读不到 → :class:`RecordNotFound`），然后
        **相位门** → **actor 门** → **迁移表校验**（``（PENDING_CONFIRMATION|ACTIVE|
        DECAYED) -> ACTIVE`` 合法，``DELETED`` 是终态 → :class:`IllegalTransition`），
        最后一次性写回整条记录：``write_record`` 是「插入或整体替换」，只有它能同时
        落地 ``audiences`` / ``expires_at`` / ``memory_policy`` 这三项契约要求的副作用
        （``transition()`` 的冻结签名表达不了它们）。
        """

        self._validate_record_id(candidate_id)
        new_audience = self._validate_audience(audience, field="audience")
        self._validate_actor(actor)
        self._require_write_gate("confirm_shared", actor)
        now = self._require_clock()

        record = self._load_record(candidate_id)
        self._require_family_scope(record)
        self._require_confirmable_length(record)
        self._require_transition(record, _ACTIVE, actor)

        updated = replace(
            record,
            status=_ACTIVE,
            memory_policy="persist_confirmed",
            audiences=new_audience,
            last_confirmed_at=now,
            updated_at=now,
            consent_version=record.consent_version + 1,
            expires_at=self._expiry_for(record.memory_class, is_candidate=False, now=now),
            actor_kind=actor.kind,  # A12：最后一次写入的主体
            actor_id=actor.actor_id,
        )
        self._store_call("write_record", self._store.write_record, updated, actor=actor)
        return updated

    def correct(
        self,
        record_id: str,
        replacement: MemoryCorrection,
        actor: Actor,
    ) -> MemoryRecord:
        """修正内容 / 重要度 / 受众。

        **归属与来源不可改**：``owner_id`` / ``scope`` / ``memory_class`` /
        ``source_type`` / ``source_member_id`` / ``created_at`` 在
        :class:`MemoryCorrection` 上就没有对应字段，因此实现方无法改掉它们。
        这直接落实 M2-PREPARATION 第 9 行的「不允许模型直接写入或修改 owner/scope」。

        副作用：``updated_at = now``、``consent_version += 1``（受众或内容变化后
        旧 grant 必须失效）、``expires_at`` 按新配置重算。状态保持 ``ACTIVE``（自环）。

        抛错：:class:`RecordNotFound` / :class:`AuthorizationError` /
        :class:`MemoryValidationError`（§3.7 的 actor 门：
        ``actor.kind != "adult_control_plane"`）/ :class:`IllegalTransition`
        （``DELETED`` 记录不可修正）。

        实现补充（W3）
        --------------
        - ``replacement`` 只覆盖显式给出的字段（``None`` 表示不改），
          ``content`` / ``importance`` / ``audiences`` 的取值形状逐一校验。
        - 迁移合法性按**自环**判定：``ACTIVE`` / ``DECAYED`` 的自环合法；
          ``PENDING_CONFIRMATION`` 没有自环边（候选要先确认）、``DELETED`` 是终态，
          两者都抛 :class:`IllegalTransition`。
        - ``last_confirmed_at`` 不变：修正是改正内容，不是重新确认。
        """

        self._validate_record_id(record_id)
        if not isinstance(replacement, MemoryCorrection):
            raise MemoryValidationError("replacement must be a MemoryCorrection")
        self._validate_actor(actor)
        self._require_write_gate("correct", actor)
        now = self._require_clock()

        record = self._load_record(record_id)
        self._require_family_scope(record)
        self._require_transition(record, record.status, actor)

        content = record.content
        if replacement.content is not None:
            content = self._validate_content(replacement.content)
        importance = record.importance
        if replacement.importance is not None:
            importance = self._validate_unit_interval(replacement.importance, field="importance")
        audiences = record.audiences
        if replacement.audiences is not None:
            audiences = self._validate_audience(replacement.audiences, field="audiences")

        updated = replace(
            record,
            content=content,
            importance=importance,
            audiences=audiences,
            updated_at=now,
            consent_version=record.consent_version + 1,
            expires_at=self._expiry_for(
                record.memory_class,
                is_candidate=record.status == _CANDIDATE,
                now=now,
            ),
            # T9c：标记是**派生值** —— 正文变了就归零（这正是 flagged 行的修复路径：
            # 改到 ≤500 之后标记自动清零），正文没变就原样保留（改 importance /
            # audiences 不该把一条历史超长行「洗白」）。store 侧对**正文变更**的分支
            # 本来就忽略调用方的声明（审阅 A 建议 1(b)），这里显式写出是为了让
            # **返回的对象**与落库的行一致 —— 调用方拿到的 `updated` 不该带着过期的标记。
            content_over_length=0 if content != record.content else record.content_over_length,
            actor_kind=actor.kind,  # A12：最后一次写入的主体
            actor_id=actor.actor_id,
        )
        self._store_call("write_record", self._store.write_record, updated, actor=actor)
        return updated

    def reassign_owner(self, record_id: str, owner_id: str, *, actor: Actor) -> MemoryRecord:
        """把**候选**的归属定到某个成员（D13 / §2.4 的 **T26'**，M2.2 新增）。

        **为什么是独立方法而不是 ``confirm_shared`` 的新 kwarg**：后者会改 M2.1 冻结的
        位置参数表（``confirm_shared(candidate_id, audience, actor)``），而归
        「归属变更」与「确认共享」是两件事 —— ``correct`` 改内容，归属不是内容。
        合并会让「改了正文顺手改了归属」重新变得可能。

        它解决的是 D13 的问题：共享会话里提议出来的候选只能记 ``owner_id="family_shared"``
        （M1 不做说话人识别），而 ``correct`` 在类型上就改不了归属，于是保留归属会
        **永久粘住**。这个窄口子只对成人开放、只作用于候选阶段、只改归属。

        约束（契约 §2.4 T26' 的表，逐条落地）：

        - **只对候选**：``status != PENDING_CONFIRMATION`` 一律 :class:`IllegalTransition`
          （归属定型后不可改，这是 M2.1 的不变量）；用
          ``(当前状态 → PENDING_CONFIRMATION)`` 表达 —— 那本来就是一条不存在的迁移边；
        - **只由成人**：``M2_1_WRITE_GATE["reassign_owner"] = {"adult_control_plane"}``
          （§2.4 新增行），``session_proposal`` / ``ttl_expiry`` 一律拒绝；
        - **目标必须是非空字符串且不是保留 id**：把归属从 ``family_shared`` 定到具体成员
          才是它的用途；写回保留 id 是无意义操作，直接拒绝。**记忆侧不校验成员存在性**
          （沿用 M2.1 口径；那需要跨库读档案，登记为 M2.3 项）；
        - **递增同意版本**：``consent_version + 1``，``updated_at`` 与
          ``actor_kind`` / ``actor_id`` 同步（A12：归属不可伪造）；
        - **不改别的**：不碰 ``content`` / ``importance`` / ``audiences`` / ``scope`` /
          ``source_*`` / ``memory_class`` / ``expires_at`` / ``last_confirmed_at``。

        CLI 用法（W8）：``confirm --reassign-owner <member_id>``。**M2.3 起 CLI 走的是
        :meth:`confirm_shared_with_owner_reassign`（一次事务）**，本方法仍是它单独可用的
        公开形状（T26'），只是不再由 CLI 组合成两步 —— 两步组合会留下「归属已改、确认未
        完成」的中间态（契约 §7.5 第 6 项）。

        抛错：:class:`RecordNotFound` / :class:`AuthorizationError`
        （``scope_not_enabled``）/ :class:`MemoryValidationError`
        （actor 门、空 owner、保留 id）/ :class:`IllegalTransition`（非候选）。
        """

        self._validate_record_id(record_id)
        self._validate_owner_id(owner_id)
        self._validate_actor(actor)
        self._require_write_gate("reassign_owner", actor)
        now = self._require_clock()

        record = self._load_record(record_id)
        self._require_family_scope(record)
        if record.status != _CANDIDATE:
            # 归属定型后不可改（M2.1 不变量）。用「回到候选」这条不存在的迁移边表达 ——
            # ACTIVE / DECAYED / DELETED 都不该被改归属。
            raise IllegalTransition(record.status, _CANDIDATE, actor.kind)

        updated = replace(
            record,
            owner_id=owner_id,
            updated_at=now,
            consent_version=record.consent_version + 1,
            actor_kind=actor.kind,  # A12：最后一次写入的主体
            actor_id=actor.actor_id,
            # 正文不变 ⇒ content_over_length 原样保留（T9c：只在正文变更时清零）。
            content_over_length=record.content_over_length,
        )
        self._store_call("write_record", self._store.write_record, updated, actor=actor)
        return updated

    def confirm_shared_with_owner_reassign(
        self,
        candidate_id: str,
        audience: frozenset[str],
        owner_id: str,
        *,
        actor: Actor,
    ) -> MemoryRecord:
        """``confirm --reassign-owner`` 的**单事务**形状：改归属 + 确认共享，要么都成、要么都不成。

        契约依据：§2.4 **T26'**（``reassign_owner`` 的约束逐条照搬）+ §7.5 **第 6 项**
        （M2.3 欠账：CLI 的两步是两个事务，中间发生存储故障会留下「归属已改、确认未完成」）。

        **为什么是一个方法而不是 CLI 里连调两次**：``MemoryStore.write_record`` 是
        「插入或整体替换**整条**记录（含受众/血缘）」，每次调用自带一个
        ``BEGIN IMMEDIATE`` 事务。「改归属」与「确认共享」都要落到同一条记录上，
        因此**一次** ``write_record`` 就能同时表达两者的全部副作用
        （``owner_id`` / ``status`` / ``memory_policy`` / ``audiences`` /
        ``last_confirmed_at`` / ``expires_at`` / ``consent_version``）——
        两次调用反而会人为制造一个可失败的中间态。这与 **A11**
        （``hard_delete_with_audit``：删除与审计同一事务）是同一类裁决：
        同一件产品动作拆成两次写，就会有一个「写一半」的窗口，而这里连拆的必要都没有。

        **``consent_version`` 递增两次的量**（``+2``）：两步写法里改归属与确认各递增一次，
        合并后仍递增同样的量 —— 于是「确认即全量撤权重授权」的结论、以及任何既有 grant 的
        ``stale_consent`` 判定，与两步写法**逐字相同**（``1 → 3``，不是 ``1 → 2``）。
        这不是「少写了一次就少递增一次」：递增的语义是「同意内容变了一次」，
        而这次写入确实同时包含两次同意变更。

        约束（与 :meth:`reassign_owner` 逐条一致，只是不再单独落盘）：

        - **只对候选**：``status != PENDING_CONFIRMATION`` 一律 :class:`IllegalTransition`；
        - **只由成人**：两道 actor 门都过（``reassign_owner`` 与 ``confirm_shared``
          在 :data:`~soul_memory_kernel.memory.policy.M2_1_WRITE_GATE` 里都是 ``adult_control_plane``）；
        - **目标必须是非空字符串且不是保留 id**（校验**先于**任何读/写，一行都不写）；
        - **flagged 候选不能确认**（T9c，先于任何写入拒绝）；
        - **不改别的**：不碰 ``content`` / ``importance`` / ``scope`` / ``source_*`` /
          ``memory_class`` / ``created_at``。

        **失败面**：任何一步的校验或那次唯一的写入失败 ⇒ **整条记录保持原值**
        （``owner_id`` / ``status`` / ``consent_version`` 一起不变），不存在
        「归属已改、确认未完成」的中间态；重跑是安全的（幂等的前提是第一次真的没写进去）。

        抛错：与两步写法同类型 —— :class:`RecordNotFound` / :class:`AuthorizationError`
        （``scope_not_enabled``）/ :class:`MemoryValidationError`（actor 门、空 owner、
        保留 id、空受众、flagged 行）/ :class:`IllegalTransition`（非候选）/
        :class:`StoreError`（那次写入失败）。
        """

        self._validate_record_id(candidate_id)
        # 第一步（改归属）的入参校验：与 `reassign_owner` 同序、同错。
        self._validate_owner_id(owner_id)
        self._validate_actor(actor)
        self._require_write_gate("reassign_owner", actor)
        # 第二步（确认共享）的入参校验：与 `confirm_shared` 同序、同错。
        new_audience = self._validate_audience(audience, field="audience")
        self._require_write_gate("confirm_shared", actor)
        now = self._require_clock()

        record = self._load_record(candidate_id)
        self._require_family_scope(record)
        if record.status != _CANDIDATE:
            # T26'：归属定型后不可改。错误类型与两步写法一致（`reassign_owner` 先跑）。
            raise IllegalTransition(record.status, _CANDIDATE, actor.kind)
        self._require_confirmable_length(record)
        self._require_transition(record, _ACTIVE, actor)

        updated = replace(
            record,
            owner_id=owner_id,
            status=_ACTIVE,
            memory_policy="persist_confirmed",
            audiences=new_audience,
            last_confirmed_at=now,
            updated_at=now,
            # 两次同意变更（改归属 + 确认）合并成一次写入：递增量与两步写法相同。
            consent_version=record.consent_version + 2,
            expires_at=self._expiry_for(record.memory_class, is_candidate=False, now=now),
            actor_kind=actor.kind,  # A12：最后一次写入的主体
            actor_id=actor.actor_id,
            # 正文不变 ⇒ content_over_length 原样保留（T9c：只在正文变更时清零）。
            content_over_length=record.content_over_length,
        )
        self._store_call(
            "write_record (confirm + reassign, one transaction)",
            self._store.write_record,
            updated,
            actor=actor,
        )
        return updated

    def delete(self, record_id: str, actor: Actor) -> DeletionReport:
        """**磁盘删除**，不是「不再召回」。

        删除清单（必须全部枚举，缺一不可）：

        - ``memory_record`` 行
        - ``memory_audience`` 行
        - ``memory_source`` 中它**作为子节点**的血缘行（``record_id = ?``）
        - **``grant_resource`` 中指向它的行**（无外键、无级联，必须显式删；
          否则被删 id 会留在授权表里）
        - 应用侧派生摘要与内存缓存、派生任务引用
        - ``pending_item`` 中引用它的行（M2.2 起）
        - **可安全重写的产物**：能重新生成、且没有被登记 sha256 的评测中间产物
        - 一条 ``deletion_audit`` 行 —— 经 ``store.hard_delete_with_audit``（**A11**）
          在**同一事务**内写入（``actor`` / 时间 / 触及的表 / 计数 / unknown）

        **血缘口径（A2，与 §7.4 统一）**：**不删除派生记录**，也**不删除指向它的血缘行**
        （``source_id = ?`` 保留）。派生记录因此在 ``resolve_provenance`` 命中缺源，
        按 ``missing_provenance`` **永久 fail-closed**。
        它们**仍留在盘上**，必须如实列进 ``DeletionReport.derived_unreachable``
        （属于「删不掉的部分」）；``derived_removed`` 在 M2.1 恒为 ``()``。
        这样选的理由：级联删除是一次递归的、可能部分失败的图操作，而 fail-closed 解析
        是一次可证明的检查 —— 前者一旦失败就会留下「看起来没有祖先」的干净记录，
        那正是最危险的越权路径。

        **不重写、只登记为 ``unknown_copies``**：带 sha256 的归档证据
        （manifest / evidence JSON）—— 重写会让已登记的哈希失效，破坏历史可比性。

        **不能承诺**（必须写进 :class:`DeletionReport`，不得省略）：
        provider 侧留存（未验证）、既有旧 JSONL 全文日志中的历史副本
        （见 M2-PREPARATION「可控历史内容副本清单」）、文件系统快照与备份、
        已经播出或显示过的内容。

        ``unknown_copies`` 必须**显式列出枚举不到的位置**；**禁止填 0 冒充完整**。
        把「不再召回」当成「已删除」是本项目明令禁止的表述。

        抛错：:class:`RecordNotFound` / :class:`AuthorizationError` /
        :class:`MemoryValidationError`（``actor.kind != "adult_control_plane"``，
        §3.7 的 actor 门）/ :class:`StoreError`
        （删除中途失败必须让调用方知道删到哪一步，不能报成功）。

        实现补充（W3）
        --------------
        - **没有相位门**：删除不受 ``M2_1_ALLOWED_SCOPES`` 限制。M2.1 只是不**创建**
          也不**召回** `PERSONAL` / `SAFETY` 记忆；若库里存在（历史/导入），成人必须
          仍能把它删掉 —— 删不掉才是隐私事故。删除不是状态迁移（§2.3），因此也不查
          ``LEGAL_TRANSITIONS``：候选、`DECAYED`、甚至历史墓碑都删得掉。
        - **只有 ``adult_control_plane`` 能调用**（§2.4）：``ttl_expiry`` 的硬删除
          走 ``sweep_expired()``（只对到期候选），``migration`` 不得删任何记录。
        - **血缘按 A2**：派生记录**不连带删除**。它们在枚举后写进
          ``derived_unreachable``（仍在盘上、已永久不可召回），``derived_removed`` 恒为
          ``()``。``enumerate_dependents()`` 仍递归调用（去重、防环），但结果只用于
          **报告**，不用于删除。
        - §7.1 第 6/7 项的「应用侧派生摘要 / 内存缓存 / 派生任务引用」在 M2.1
          **不存在这些子系统**（M2.1 没有派生写入路径），因此没有可枚举的对象。
        - 审计行由 W1 的 ``store.hard_delete_with_audit(...)``（**A11**：删除与审计同一
          事务）写入并**返回 ``audit_id``**；:class:`DeletionReport.audit_id` 用的就是它。
        """

        self._validate_record_id(record_id)
        self._validate_actor(actor)
        self._require_write_gate("delete", actor)
        now = self._require_clock()

        # 不存在 → RecordNotFound；删除不是状态迁移（§2.3），因此不看 status。
        self._load_record(record_id)

        # A2：先枚举派生记录（只用于报告），再**只**硬删这一条。
        # 指向它的血缘行保留，因此这些派生记录会 miss provenance、永久不可召回。
        unreachable = self._collect_dependents(record_id)
        # A11（主控 2026-09-26）：删除与审计**同一事务**（hard_delete_with_audit）。
        # 分开调用会让「行已删掉、审计没写成」成为可能 —— 那正是 §7.1 第 9 项与 §4.4
        # 明令禁止的状态。原子方法失败时整体回滚：记录仍在、审计 0 行。
        # A-s5：标签不带 record_id —— 它会经 _store_call 进 StoreError 文本，
        # 而记录 id 不进日志是本项目的纪律（§5.1）。
        outcome = self._store_call(
            "hard_delete_with_audit (deletion and audit are one transaction)",
            self._store.hard_delete_with_audit,
            record_id=record_id,
            actor=actor,
            deleted_at=now,
            derived_removed=0,
            unknown_copies=_UNKNOWN_COPY_LOCATIONS,
        )
        return DeletionReport(
            record_ids=(record_id,),
            tables_touched=outcome.tables_touched,
            derived_removed=(),
            derived_unreachable=unreachable,
            fulltext_eval_copies_removed=(),
            unknown_copies=_UNKNOWN_COPY_LOCATIONS,
            audit_id=outcome.audit_id,
            deleted_at=now,
        )

    # ---------------------------------------------------------------- 读取

    def query(
        self,
        session_access: SessionAccess,
        purpose: QueryPurpose,
        *,
        session_id: str,
        audience_id: str,
        grant: Grant | None,
    ) -> MemorySnapshot:
        """返回不可变快照。**这是唯一的读取路径。**

        行为
        ----
        - 逐条调用 ``policy.authorize()``；被拒的记录进入 ``snapshot.denied``
          （只含 id 与固定枚举 reason，**不含正文**），不进入 ``entries``。
        - **无授权不是错误**：``grant=None`` 且没有家庭共享记录时返回空快照，
          不抛异常。这样「没有记忆」与「没有权限」在调用方看来是同一种退化。
        - **到期记录实时排除并记入 ``denied``**（主控 2026-09-26）：即使 ``status``
          还是 ``ACTIVE``，只要 ``expires_at <= now`` 就不进入快照，**并且**在
          ``denied`` 里留一条 ``(record_id, "record_expired")`` —— 排除不等于「这条
          记录不存在」，审计要能看出它是因为到期被排除的（与 B2 的判权 reason 同名）。
          正确性不依赖 ``sweep_expired()`` 是否跑过 —— 扫描只负责落状态 / 硬删候选。
        - **M2.1 只返回 `FAMILY`**：`PERSONAL` / `SAFETY` 记录（若库中存在）一律进
          ``denied``，reason ``scope_not_enabled``。
        - 携带内容与否由 ``purpose`` 决定：``session_projection`` / ``adult_inspect`` /
          ``control_plane_review`` 带正文；``adult_list`` / ``deletion_audit`` 只带元数据。
        - **不自行查 grant**：``grant`` 由调用方解析后传入，其会话绑定由
          ``authorize()`` 的 ``wrong_session`` 兜底。任何自行按 session_id 去查
          grant 的实现都是在造第二条授权路径，属于契约违规。
        - **``query()`` 的授权只到 ``read_model``**：它证明「应用可以本地读出这条记录」，
          **不证明「可以交给模型」**。接缝（§10.1）必须在渲染 instructions 前对
          **每一条**注入记录再调一次 ``authorize(action="send_provider")``（A9）——
          两个动作分离是本项目从隐私内核继承的语义，`read_model` 不自动升级为
          `send_provider`。

        抛错：只有 :class:`MemoryValidationError`（入参形状）与 :class:`StoreError`
        （存储故障）。**授权拒绝不抛错。**

        实现补充（W3）
        --------------
        - 候选集来自 ``list_eligible()``，**故意放宽**（全部 scope、全部状态）：
          多返回的记录由 ``authorize()`` 拒绝，但漏掉一条授权范围内的记录就是越权
          的反面 —— 「读不到本该读到的」。`PERSONAL` / `SAFETY` 记录能被列出来，
          才可能按 §4.5 进 ``denied``。
        - 判权 action **由 ``purpose`` 决定**（M2.2 §4.3）：前四个 purpose 是
          ``read_model``（本地查询），只有 ``control_plane_review`` 是
          ``review_control_plane``（成人复审候选）。调用方**不能**自选动作。
          ``session_projection`` 的快照随后由调用方决定是否交给模型。
        - 每条记录的 ``records=`` 是**该记录 + 它的祖先闭包**（``resolve_provenance``），
          祖先缺失即 ``missing_provenance`` 拒绝 —— 绝不「只授权可见的那部分」。
        - 到期过滤先于判权：到期记录在快照里**完全不存在**（既不进 ``entries`` 也不进
          ``denied``）；``expires_at`` 不可解析同样按到期处理（fail-closed）。
        - 时钟不可解析 → 空快照 + 每条 ``clock_invalid``（``DENY_ORDER`` 第 1 条）。
        """

        if not isinstance(session_access, SessionAccess):
            raise MemoryValidationError("session_access must be a SessionAccess")
        if purpose not in QUERY_PURPOSES:
            raise MemoryValidationError(f"unsupported query purpose: {purpose!r}")
        if not _is_non_empty_str(session_id):
            raise MemoryValidationError("session_id must be a non-empty string")
        if not _is_non_empty_str(audience_id):
            raise MemoryValidationError("audience_id must be a non-empty string")
        if grant is not None and not isinstance(grant, Grant):
            raise MemoryValidationError("grant must be a Grant or None")

        now = self._clock()
        now_dt = self._parse_instant(now)

        listed = tuple(
            dict.fromkeys(
                self._store_call(
                    "list_eligible",
                    self._store.list_eligible,
                    owner_id=None,  # FAMILY 的可读性由受众决定，不由 owner 决定
                    audience_id=audience_id,
                    scopes=tuple(sorted(SCOPES)),
                    statuses=tuple(sorted(MEMORY_STATUSES)),
                )
            )
        )
        fetched = self._store_call(
            "read_records", self._store.read_records, tuple(listed)
        )
        by_id = {record.id: record for record in fetched}

        entries: list[SnapshotEntry] = []
        denied: list[tuple[str, str]] = []

        for record_id in listed:
            record = by_id.get(record_id)
            if record is None:
                # list_eligible 之后消失：按缺源 fail-closed，绝不当作「没有这条」。
                denied.append((record_id, "missing_provenance"))
                continue
            if now_dt is None:
                denied.append((record_id, "clock_invalid"))
                continue
            if self._is_expired(record, now_dt):
                # 主控 2026-09-26：到期排除也记进 denied —— 「排除」不等于「没这条记录」，
                # 审计要能区分「本次会话看不到它」与「它根本不在候选集里」。
                # reason 与 B2 的判权 reason 同名，两条防线报同一个词。
                denied.append((record_id, "record_expired"))
                continue
            auth_records = self._authorized_records(record)
            if auth_records is None:
                denied.append((record_id, "missing_provenance"))
                continue
            decision = self._authorize(
                action=_ACTION_FOR_PURPOSE[purpose],
                access=session_access,
                grant=grant,
                session_id=session_id,
                audience_id=audience_id,
                records=auth_records,
            )
            if not decision.allowed:
                denied.append((record_id, decision.reason))
                continue
            entries.append(self._snapshot_entry(record, purpose))

        entries.sort(key=lambda entry: entry.record_id)
        record_ids = tuple(entry.record_id for entry in entries)
        return MemorySnapshot(
            snapshot_id=self._snapshot_id(
                session_id=session_id,
                audience_id=audience_id,
                purpose=purpose,
                created_at=now,
                record_ids=record_ids,
                denied=tuple(denied),
            ),
            session_id=session_id,
            audience_id=audience_id,
            purpose=purpose,
            record_ids=record_ids,
            source_ids=tuple(
                dict.fromkeys(
                    source_id
                    for entry in entries
                    for source_id in by_id[entry.record_id].source_ids
                )
            ),
            entries=tuple(entries),
            denied=tuple(denied),
            created_at=now,
        )

    # ---------------------------------------------------------------- 保留期

    def sweep_expired(self, actor: Actor) -> tuple[MemoryRecord | DeletionReport, ...]:
        """执行到期动作，返回被改动或删除的对象。

        枚举用 :meth:`soul_memory_kernel.memory.store.MemoryStore.list_expired`，
        **两条性质完全不同**的路径：

        1. ``ACTIVE`` 且 ``expires_at <= now`` → ``DECAYED``（状态迁移）。
           停止召回但**不删盘**，删不删由成人决定（D5）。
        2. ``PENDING_CONFIRMATION`` 且 ``expires_at <= now`` → **硬删除**
           （``hard_delete_with_audit``，**A11**：删除与审计同一事务，
           返回 :class:`DeletionReport`）。
           **不是状态翻转。** 翻转并不消除磁盘驻留，而候选从未进入召回路径，
           没有任何保留价值（见 :data:`soul_memory_kernel.memory.model.CANDIDATE_EXPIRY_IS_HARD_DELETE`）。

        **``memory_class="SAFETY"`` 的候选同样受 7 天候选期约束**；只有已确认的
        SAFETY 类记录才 ``expires_at IS NULL`` 且永不到期。

        只有 ``actor.kind == "ttl_expiry"`` 允许触发上述两条路径（§3.7 的 actor 门）；
        ``migration`` / ``adult_control_plane`` / ``session_proposal`` 走这条一律抛
        :class:`MemoryValidationError`（门 2 的失败类型，不是 :class:`IllegalTransition`
        —— 后者只表达状态迁移非法）。

        **这个方法不是正确性依赖**：即使从不调用，``query()`` 也不会召回到期记录。

        实现补充（W3）
        --------------
        - actor 门在前（``kind != "ttl_expiry"`` → :class:`IllegalTransition`，
          用 ``ACTIVE → DECAYED`` 这对状态表示「TTL 扫描」；违规的实质是
          ``actor_kind``），不做任何写入；两条路径的迁移合法性再逐条复核。
        - 到期判定是**记录级**的（``expires_at <= now``，``None`` 不算到期——
          DDL 保证只有已确认的 SAFETY 类可以没有期限；不可解析按到期处理）。
        - 枚举到期记录直接用 W1 的 ``store.list_expired(now=...)``（主控仲裁
          2026-09-26）；候选的硬删除用 W1 的 ``store.hard_delete_with_audit(...)``（A11），
          ``audit_id`` 由 store 生成并返回。两者都是**必需方法**，没有降级路径。
        """

        self._validate_actor(actor)
        # §3.7 第二道门（actor 门）已经保证 actor.kind == "ttl_expiry"，
        # 因此这里不再重复判定 —— 原先的兜底分支是死代码（A-s3）。
        self._require_write_gate("sweep_expired", actor)
        now = self._require_clock()
        now_dt = self._parse_instant(now)
        if now_dt is None:  # pragma: no cover —— _require_clock() 已保证可解析
            raise AuthorizationError(_denied("clock_invalid"))

        # A1（集成时由主控对齐）：``list_expired`` 返回的是**完整记录**，
        # 不是 id 元组 —— 调用方要靠 ``status`` 分派两条路径，只给 id 会逼出第二次查询。
        # W3 原稿按 id 处理，会在真实存储上把 MemoryRecord 当 record_id 传回去
        # （sqlite3.ProgrammingError）。这里直接消费记录本身。
        listed = self._store_call("list_expired", self._store.list_expired, now=now)
        expired: list[MemoryRecord] = []
        seen: set[str] = set()
        for record in listed:
            if record.id in seen:
                continue
            seen.add(record.id)
            if record.status not in (_ACTIVE, _CANDIDATE):
                continue
            if not self._is_expired(record, now_dt):
                continue
            expired.append(record)

        results: dict[str, MemoryRecord | DeletionReport] = {}
        for record in expired:
            if record.status == _CANDIDATE:
                results[record.id] = self._hard_delete_expired_candidate(
                    record, actor=actor, now=now
                )
                continue
            self._require_transition(record, _DECAYED, actor)
            results[record.id] = self._store_call(
                "transition",
                self._store.transition,
                record.id,
                _DECAYED,
                actor=actor,
                updated_at=now,
                # 到期不是一次新的同意：版本与「上次确认时间」都保持不变。
                consent_version=record.consent_version,
                last_confirmed_at=record.last_confirmed_at,
            )
        return tuple(results[record.id] for record in expired)

    # ---------------------------------------------------------------- 内部

    def _authorize(
        self,
        *,
        action: Action,
        access: SessionAccess,
        grant: Grant | None,
        session_id: str,
        audience_id: str,
        records: tuple[MemoryRecord, ...],
    ) -> AuthorizationDecision:
        """内部统一判权。**唯一允许构造判权输入的地方**，确保 ``now`` 来自注入时钟。"""

        return policy.authorize(
            action=action,
            access=access,
            grant=grant,
            session_id=session_id,
            audience_id=audience_id,
            records=records,
            now=self._clock(),
        )

    # -- 入参校验 ---------------------------------------------------------

    def _validate_record_id(self, record_id: object) -> None:
        if not _is_non_empty_str(record_id):
            raise MemoryValidationError("record_id must be a non-empty string")

    @staticmethod
    def _validate_owner_id(owner_id: object) -> None:
        """T26' 的目标归属校验：非空字符串且**不是保留 id**（两个写路径共用）。

        ``reassign_owner`` 与 :meth:`confirm_shared_with_owner_reassign` 的目标语义完全
        相同，校验因此只有一份：写回保留 id 是无意义操作（它的用途是把归属**移出**保留
        id），必须在校验阶段就拒绝 —— 且**先于**任何读/写，失败时一行都不写。
        """

        if not _is_non_empty_str(owner_id):
            raise MemoryValidationError("owner_id must be a non-empty string")
        if owner_id in RESERVED_OWNER_IDS:
            raise MemoryValidationError(
                f"owner_id {owner_id!r} is a reserved owner id: "
                "reassign_owner exists to move a candidate OFF the reserved id, not onto it"
            )

    def _validate_actor(self, actor: object) -> None:
        if not isinstance(actor, Actor):
            raise MemoryValidationError("actor must be an Actor")
        if actor.kind not in ACTOR_KINDS:
            raise MemoryValidationError(f"unsupported actor kind: {actor.kind!r}")
        if not _is_non_empty_str(actor.actor_id):
            raise MemoryValidationError("actor.actor_id must be a non-empty string")

    def _validate_content(self, content: object) -> str:
        """内容校验：非空 + **硬上限** :data:`MAX_CONTENT_CHARS`（B-s5）。

        条数上限（``MAX_PROJECTED_MEMORIES``）解决的是「注入太多条稀释固定行为边界」，
        长度上限解决的是同一件事的另一半：单条记忆可以长到把 instructions 撑满。
        两个上限都在**写入时**执行，因此库里的每一行都已经合规。
        """

        if not isinstance(content, str) or not content.strip():
            raise MemoryValidationError("content must be a non-empty string")
        if len(content) > MAX_CONTENT_CHARS:
            raise MemoryValidationError(
                f"content must be at most {MAX_CONTENT_CHARS} characters, got {len(content)}"
            )
        return content

    def _validate_unit_interval(self, value: object, *, field: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise MemoryValidationError(f"{field} must be a number in [0.0, 1.0]")
        number = float(value)
        if not math.isfinite(number) or not 0.0 <= number <= 1.0:
            raise MemoryValidationError(f"{field} must be a number in [0.0, 1.0]")
        return number

    def _validate_audience(self, value: object, *, field: str) -> frozenset[str]:
        if isinstance(value, str) or not isinstance(value, (frozenset, set, tuple, list)):
            raise MemoryValidationError(f"{field} must be a non-empty collection of audience ids")
        try:
            audiences = frozenset(value)
        except TypeError as exc:
            raise MemoryValidationError(f"{field} contains an unhashable audience id") from exc
        if not audiences:
            raise MemoryValidationError(
                f"{field} must not be empty: family-shared memories need an explicit audience"
            )
        for audience in audiences:
            if not _is_non_empty_str(audience):
                raise MemoryValidationError(f"{field} contains an invalid audience id: {audience!r}")
        return audiences

    def _validate_candidate(self, candidate: MemoryCandidate, source_session: object) -> None:
        if not isinstance(source_session, SourceSession):
            raise MemoryValidationError("source_session must be a SourceSession")
        self._validate_content(candidate.content)
        if not _is_non_empty_str(candidate.owner_id):
            raise MemoryValidationError("owner_id must be a non-empty string")
        if candidate.memory_class not in MEMORY_CLASSES:
            raise MemoryValidationError(f"unsupported memory_class: {candidate.memory_class!r}")
        if candidate.source_type not in SOURCE_TYPES:
            raise MemoryValidationError(f"unsupported source_type: {candidate.source_type!r}")
        if candidate.requested_policy not in REQUESTED_POLICIES:
            raise MemoryValidationError(
                f"unsupported requested_policy: {candidate.requested_policy!r}"
            )
        if candidate.source_member_id is not None and not _is_non_empty_str(
            candidate.source_member_id
        ):
            raise MemoryValidationError("source_member_id must be a non-empty string or None")
        if candidate.origin not in M2_1_ALLOWED_ORIGINS:
            # D2：自动提取候选归 M2.2。形状已就绪，但 M2.1 只接受显式候选。
            raise MemoryValidationError(
                f"unsupported candidate origin in M2.1: {candidate.origin!r} "
                f"(allowed: {sorted(M2_1_ALLOWED_ORIGINS)})"
            )
        self._validate_unit_interval(candidate.confidence, field="confidence")
        self._validate_unit_interval(candidate.importance, field="importance")
        self._validate_audience(candidate.audiences, field="audiences")
        if not _is_non_empty_str(source_session.session_id):
            raise MemoryValidationError("source_session.session_id must be a non-empty string")
        if not _is_non_empty_str(source_session.audience_id):
            raise MemoryValidationError("source_session.audience_id must be a non-empty string")

    # -- 相位 / 迁移 / 时钟 -----------------------------------------------

    def _require_family_scope(self, record: MemoryRecord) -> None:
        if record.scope not in M2_1_ALLOWED_SCOPES:
            raise AuthorizationError(_denied("scope_not_enabled"))

    @staticmethod
    def _require_confirmable_length(record: MemoryRecord) -> None:
        """**flagged 行不能确认**（M2.2 T9c，契约 §6 T9c 的写入边界表末两行）。

        确认是「变成可召回」的动作，而 500 字上限的存在理由就是「一条超长正文会撑满
        instructions 预算」（B-s5）。一条**没有达标**的行不该进入可召回集合 ——
        因此这里是一条硬前置校验，而不是「确认后再修」。

        它同时说明了**修复顺序**：

        - 非候选的 flagged 行：先 ``correct()`` 把正文改到 ≤500（标记自动清零），
          再走正常流程；
        - **flagged 候选没有这条路** —— ``correct()`` 对候选本来就是
          :class:`IllegalTransition`（``(PENDING_CONFIRMATION, PENDING_CONFIRMATION)``
          不在 :data:`~soul_memory_kernel.memory.model.LEGAL_TRANSITIONS` 里，M2.1 冻结），
          因此它**只能 ``delete()`` 或等 7 天候选期硬删**（契约 r4 修订摘要 B 建议 2）。
        """

        if record.content_over_length == 1:
            raise MemoryValidationError(
                "this record carries a historical over-length content "
                f"(content_over_length=1, over {MAX_CONTENT_CHARS} characters) and cannot be "
                "confirmed; shorten it with correct() first (candidates can only be deleted "
                "or left to expire)"
            )

    @staticmethod
    def _require_write_gate(operation: str, actor: Actor) -> None:
        """**§3.7 的第二道门：actor 门**，逐操作查 :data:`M2_1_WRITE_GATE`。

        失败抛 :class:`MemoryValidationError` —— 这是对**本次调用**的入参校验
        （调用方传了一个无权做这件事的 actor），不是记录状态机的问题。
        状态机的问题由 :meth:`_require_transition` 用 :class:`IllegalTransition` 表达。

        集成时由主控把 W3 原先散在各方法里的 ``actor.kind != ...`` 硬编码收敛到这里 ——
        让 :data:`M2_1_WRITE_GATE` 成为唯一事实来源，契约测试冻结的那张表才真正约束行为。
        """

        allowed = M2_1_WRITE_GATE.get(operation)
        if allowed is None:  # pragma: no cover —— 冻死的表，写错方法名属契约违规
            raise MemoryValidationError(f"unknown write operation in M2_1_WRITE_GATE: {operation!r}")
        if actor.kind not in allowed:
            raise MemoryValidationError(
                f"{operation} requires actor.kind in {sorted(allowed)}, got {actor.kind!r}"
            )

    def _require_transition(self, record: MemoryRecord, to_status: str, actor: Actor) -> None:
        """**§3.7 的第三道门：迁移表**（§2.3）。非法一律 :class:`IllegalTransition`。

        actor 权限已由 :meth:`_require_write_gate` 单独判定，这里只查状态机本身。
        """

        if (record.status, to_status) not in LEGAL_TRANSITIONS:
            raise IllegalTransition(record.status, to_status, actor.kind)

    def _require_clock(self) -> str:
        """时钟不可信时**先于一切**拒绝（写路径用）。

        ``clock_invalid`` 是 ``DENY_ORDER`` 的第 1 条：时钟不可解析时，期限算术与
        「什么时候确认的」都不可信，因此写路径直接拒绝，而不是写一条时间戳不可信的记录。
        """

        now = self._clock()
        if self._parse_instant(now) is None:
            raise AuthorizationError(_denied("clock_invalid"))
        return now

    @staticmethod
    def _parse_instant(value: object) -> datetime | None:
        """ISO-8601 UTC → ``datetime``；缺失 / 不可解析 / 无时区一律 ``None``。"""

        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        normalized = text[:-1] + "+00:00" if text[-1] in ("Z", "z") else text
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _format_instant(moment: datetime) -> str:
        """统一输出成 ISO-8601 UTC（``...Z``）。同一列里的文本比较要能对得上。"""

        utc = moment.astimezone(timezone.utc)
        if utc.microsecond:
            return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _expiry_for(self, memory_class: str, *, is_candidate: bool, now: str) -> str | None:
        """按分型 TTL 算 ``expires_at`` 并落库（D5：写入时算好，之后不重算）。

        ``None`` 只可能来自 ``days_for()`` 的 ``None``（已确认的 SAFETY 类）。
        """

        days = self._retention.days_for(memory_class, is_candidate=is_candidate)  # type: ignore[arg-type]
        if days is None:
            return None
        if isinstance(days, bool) or not isinstance(days, int) or days <= 0:
            raise MemoryValidationError(
                f"retention policy returned an unusable day count for {memory_class!r}: {days!r}"
            )
        moment = self._parse_instant(now)
        if moment is None:
            raise AuthorizationError(_denied("clock_invalid"))
        return self._format_instant(moment + timedelta(days=days))

    def _is_expired(self, record: MemoryRecord, now: datetime) -> bool:
        """``expires_at <= now``（边界取 ``>=``，fail-closed）。

        ``expires_at is None`` 不算到期：DDL 的 CHECK 保证只有**已确认的 SAFETY 类**
        可以没有期限。不可解析的 ``expires_at`` 按到期处理 —— 期限无法证实就不能召回。
        """

        if record.expires_at is None:
            return False
        expires = self._parse_instant(record.expires_at)
        if expires is None:
            return True
        return expires <= now

    # -- 存储访问 ---------------------------------------------------------

    def _store_call(
        self,
        description: str,
        func: Callable[..., Any],
        /,
        *args: object,
        **kwargs: object,
    ) -> Any:
        """统一的存储调用边界：契约错误原样传递，其余故障包成 :class:`StoreError`。

        这样「读路径只抛 ``MemoryValidationError`` / ``StoreError``」与
        「删除中途失败必须让调用方知道」都不依赖 W1 的异常类型选择。
        """

        try:
            return func(*args, **kwargs)
        except MemoryServiceError:
            raise
        except Exception as exc:  # noqa: BLE001 —— 存储层故障一律转成契约错误
            raise StoreError(f"{description} failed: {type(exc).__name__}: {exc}") from exc

    def _load_record(self, record_id: str) -> MemoryRecord:
        record = self._store_call("read_record", self._store.read_record, record_id)
        if record is None:
            raise RecordNotFound(f"memory record not found: {record_id!r}")
        return record

    def _authorized_records(self, record: MemoryRecord) -> tuple[MemoryRecord, ...] | None:
        """目标记录 + 祖先闭包；血缘无法证实返回 ``None``（调用方按缺源拒绝）。

        ``resolve_provenance`` 抛 :class:`StoreError` 时向上传播（真实存储故障不该
        伪装成「没有记忆」）；其余异常按「无法证实血缘」fail-closed 处理（§7.4）。
        """

        try:
            closure = self._store.resolve_provenance((record.id,))
        except StoreError:
            raise
        except MemoryServiceError:
            return None
        except Exception:  # noqa: BLE001 —— 血缘不可证实：fail-closed
            return None

        records: list[MemoryRecord] = [record]
        seen = {record.id}
        for ancestor in closure:
            if ancestor.id not in seen:
                seen.add(ancestor.id)
                records.append(ancestor)
        if not set(record.source_ids) <= seen:
            # 祖先缺源：绝不「只授权可见的那部分」。
            return None
        return tuple(records)

    def _collect_dependents(self, record_id: str) -> tuple[str, ...]:
        """递归枚举血缘上依赖该记录的派生记录（去重、防环）。"""

        removed: list[str] = []
        seen: set[str] = {record_id}
        queue = [record_id]
        while queue:
            current = queue.pop()
            dependents = self._store_call(
                "enumerate_dependents", self._store.enumerate_dependents, current
            )
            for dependent in dependents:
                if dependent in seen:
                    continue
                seen.add(dependent)
                removed.append(dependent)
                queue.append(dependent)
        return tuple(removed)

    def _hard_delete_expired_candidate(
        self,
        record: MemoryRecord,
        *,
        actor: Actor,
        now: str,
    ) -> DeletionReport:
        """候选到期：``hard_delete_with_audit``（A11 同一事务，``actor_kind="ttl_expiry"``）。

        ``audit_id`` 由 W1 的 ``store.hard_delete_with_audit(...)``（A11：删除与审计同一
        事务）生成并返回，服务层不再自造 id。
        """

        # A2：与 delete() 同口径 —— 派生记录只报告、不连带删除。
        unreachable = self._collect_dependents(record.id)
        # A11：与 delete() 同口径 —— 候选到期硬删也走 hard_delete_with_audit。
        outcome = self._store_call(
            "hard_delete_with_audit (candidate expiry, deletion and audit are one transaction)",
            self._store.hard_delete_with_audit,
            record_id=record.id,
            actor=actor,
            deleted_at=now,
            derived_removed=0,
            unknown_copies=_UNKNOWN_COPY_LOCATIONS,
        )
        return DeletionReport(
            record_ids=(record.id,),
            tables_touched=outcome.tables_touched,
            derived_removed=(),
            derived_unreachable=unreachable,
            fulltext_eval_copies_removed=(),
            unknown_copies=_UNKNOWN_COPY_LOCATIONS,
            audit_id=outcome.audit_id,
            deleted_at=now,
        )

    # -- 快照 -------------------------------------------------------------

    @staticmethod
    def _snapshot_entry(record: MemoryRecord, purpose: QueryPurpose) -> SnapshotEntry:
        """按 ``purpose`` 决定是否携带正文（§4.5 / §4.3）。"""

        carries_content = purpose in _CONTENT_CARRYING_PURPOSES
        return SnapshotEntry(
            record_id=record.id,
            owner_id=record.owner_id,
            scope=record.scope,
            memory_class=record.memory_class,
            content=record.content if carries_content else None,
            importance=record.importance,
            last_confirmed_at=record.last_confirmed_at,
        )

    @staticmethod
    def _snapshot_id(
        *,
        session_id: str,
        audience_id: str,
        purpose: str,
        created_at: str,
        record_ids: tuple[str, ...],
        denied: tuple[tuple[str, str], ...],
    ) -> str:
        """确定性快照 id：同一会话 + 同一授权范围 + 同一时刻 → 同一个 id。

        不引入随机数：快照是不可变值对象，id 相同意味着内容相同，回归比对才不会
        因为随机 id 变成假阳性。
        """

        material = "\x1f".join(
            (session_id, audience_id, purpose, created_at, *record_ids, "|denied|")
            + tuple(f"{record_id}:{reason}" for record_id, reason in denied)
        )
        return f"snap-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"
