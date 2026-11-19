"""W3 服务测试：``MemoryService`` 五接口 + TTL 扫描（契约页 §4/§5/§6/§7/§10）。

**这里的替身只按契约形状写**：``MemoryStore`` / ``GrantStore`` 是 W1/W2 尚未交付的
Protocol，本文件用内存假实现（``FakeMemoryStore`` / ``FakeGrantStore``）驱动；
``RetentionPolicy.days_for``（W1）与 ``policy.authorize``（W2）同样用形状替身。
**不 import 任何尚未写好的实现类**。真实判权的端到端用例在文件末尾
（``_require_real_policy()``：W2 落地后自动生效，落地前 skip）。

覆盖的正例与反例：

- ``propose``：候选写入、``do_not_persist`` 第一落点（返 ``None`` 且零写入）、
  相位门 ``scope_not_enabled``（PERSONAL / SAFETY）、``origin`` 白名单（D2）、
  形状校验、FAMILY + ``memory_class="SAFETY"`` 的正例；
- ``confirm_shared``：唯一的可召回路径、``consent_version += 1``、SAFETY 类不过期、
  重新确认 / 重新激活、actor 门、终态拒绝、相位门；
- ``correct``：只改 content / importance / audiences，状态与归属不变、版本递增、
  候选与墓碑拒绝；
- ``delete``：硬删除 + 派生记录 + ``grant_resource`` + ``deletion_audit``、
  ``unknown_copies`` 非空、无相位门（私人记忆也删得掉）、审计行走 store 并沿用其
  ``audit_id``；
- ``query``：授权过滤、``denied`` 不带正文、到期实时排除（不依赖 sweep）、
  祖先闭包、无 grant 不抛错、时钟不可信 → 空快照、§10.1 第四条（空 → instructions 无变化）；
- ``sweep_expired``：``ACTIVE → DECAYED``（不删盘）与候选硬删除（含 SAFETY 类）、
  只有 ``ttl_expiry`` 能触发、枚举走 ``store.list_expired``。

fixture 映射表里归 W3 的用例见 ``test_contract_supplementary_write_cases_match_the_frozen_mapping``
（``m2_1_personal_scope_write_denied`` / ``m2_1_safety_scope_write_denied`` /
``m2_1_auto_extracted_origin_rejected``）。
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soul_memory_kernel.memory import policy
from soul_memory_kernel.memory.model import (
    ACTOR_KINDS,
    DeletionOutcome,
    Actor,
    DeletionReport,
    Grant,
    MemoryCandidate,
    MemoryCorrection,
    MemoryRecord,
    RetentionPolicy,
    SourceSession,
)
from soul_memory_kernel.memory.policy import M2_1_WRITE_GATE, AuthorizationDecision
from soul_memory_kernel.memory.projection import MEMORY_BLOCK_HEADER, render_memory_block
from soul_memory_kernel.memory.service import (
    AuthorizationError,
    IllegalTransition,
    MemoryService,
    MemoryValidationError,
    RecordNotFound,
    StoreError,
)
from soul_memory_kernel.soul.policy import SessionAccess
from tests.test_memory_contract import CONTRACT_SUPPLEMENTARY_CASES

#: 契约补丁（主控仲裁 2）新增的**非成人** actor 类型：会话内产生的候选归它，
#: 不得记为 ``adult_control_plane``。补丁合入 ``model.py`` 之前，
#: ``model.ACTOR_KINDS`` 里还没有这个取值 —— 依赖它的断言在补丁到位前 skip，
#: 到位后自动生效（对齐点只有一个：model.py 的契约常量）。
SESSION_PROPOSAL_KIND = "session_proposal"
#: A8 的对齐点（集成时由主控去掉 skipif）：契约常量必须在 ``ACTOR_KINDS`` 里。
SESSION_PROPOSAL_IN_CONTRACT = SESSION_PROPOSAL_KIND in ACTOR_KINDS

NOW = "2026-09-26T12:00:00Z"
CANDIDATE_EXPIRY = "2026-10-03T12:00:00Z"  # NOW + 7 天（候选期）
EVENT_EXPIRY = "2026-10-26T12:00:00Z"  # NOW + 30 天（D5）
PREFERENCE_EXPIRY = "2027-03-25T12:00:00Z"  # NOW + 180 天（D5）
FAR_FUTURE = "2100-01-01T00:00:00Z"

ADULT = Actor(kind="adult_control_plane", actor_id="adult_a")
TTL = Actor(kind="ttl_expiry", actor_id="sweeper")
MIGRATION = Actor(kind="migration", actor_id="migrator")

# ---------------------------------------------------------------------------
# 契约形状的替身（不是 W1/W2 的实现）
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self, value: str = NOW) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        return self.value


class FakeRetention:
    """``RetentionPolicy.days_for`` 的形状替身（W1 尚未实现）。

    语义按契约 §6/§8.1：候选一律 ``candidate_days``（**含 SAFETY 类**）；
    已确认的 ``SAFETY`` 类不过期（``None``）；其余按分型天数。
    """

    def __init__(
        self,
        *,
        event_days: int = 30,
        preference_days: int = 180,
        candidate_days: int = 7,
    ) -> None:
        self.event_days = event_days
        self.preference_days = preference_days
        self.candidate_days = candidate_days
        self.calls: list[tuple[str, bool]] = []

    def days_for(self, memory_class: str, *, is_candidate: bool) -> int | None:
        self.calls.append((memory_class, is_candidate))
        if is_candidate:
            return self.candidate_days
        if memory_class == "SAFETY":
            return None
        return {"EVENT": self.event_days, "PREFERENCE": self.preference_days}[memory_class]


class FakeMemoryStore:
    """``MemoryStore`` Protocol 的内存替身。

    另外实现 W1 的 ``list_expired(now=...)`` 与 ``write_deletion_audit(...)``
    （主控仲裁 2026-09-26：这两个是 store 的**必需方法**，不是可选钩子；
    ``audit_id`` 由 store 生成并返回）。

    ``list_eligible`` / ``list_expired`` **故意可以多返回**（``eligible_extra`` /
    ``expired_extra`` / ``listing_mode="all"``）：契约要求服务层不信任列表，
    由 ``authorize()`` 与到期判定决定去留。
    """

    path = Path("/nonexistent/fake-memory.sqlite")

    def __init__(
        self,
        records: tuple[MemoryRecord, ...] = (),
        *,
        ancestor_of: dict[str, tuple[str, ...]] | None = None,
        dependents: dict[str, tuple[str, ...]] | None = None,
        eligible_extra: tuple[str, ...] = (),
        expired_extra: tuple[str, ...] = (),
        listing_mode: str = "filter",
        failures: dict[str, BaseException] | None = None,
    ) -> None:
        self.records: dict[str, MemoryRecord] = {record.id: record for record in records}
        self.ancestor_of = dict(ancestor_of or {})
        self.dependents = {key: tuple(value) for key, value in (dependents or {}).items()}
        self.eligible_extra = tuple(eligible_extra)
        self.expired_extra = tuple(expired_extra)
        self.listing_mode = listing_mode
        self.failures = dict(failures or {})
        self.calls: list[tuple[object, ...]] = []
        self.writes: list[tuple[MemoryRecord, Actor]] = []
        self.transitions: list[tuple[object, ...]] = []
        self.hard_deletes: list[str] = []
        self.audit_rows: list[dict[str, object]] = []
        self.listing_filters: list[tuple[object, ...]] = []

    # -- 内部 -------------------------------------------------------------

    def _maybe_fail(self, name: str) -> None:
        failure = self.failures.get(name)
        if failure is not None:
            raise failure

    # -- MemoryStore Protocol --------------------------------------------

    def create_schema(self) -> None:
        self.calls.append(("create_schema",))

    def read_record(self, record_id: str) -> MemoryRecord | None:
        self.calls.append(("read_record", record_id))
        self._maybe_fail("read_record")
        return self.records.get(record_id)

    def read_records(self, record_ids: tuple[str, ...]) -> tuple[MemoryRecord, ...]:
        self.calls.append(("read_records", record_ids))
        self._maybe_fail("read_records")
        return tuple(self.records[rid] for rid in record_ids if rid in self.records)

    def list_eligible(
        self,
        *,
        owner_id: str | None,
        audience_id: str,
        scopes: tuple[str, ...],
        statuses: tuple[str, ...],
    ) -> tuple[str, ...]:
        self.calls.append(("list_eligible", owner_id, audience_id, scopes, statuses))
        self._maybe_fail("list_eligible")
        self.listing_filters.append((owner_id, audience_id, scopes, statuses))
        matches = [
            record.id
            for record in self.records.values()
            if (owner_id is None or record.owner_id == owner_id)
            and (self.listing_mode == "all" or audience_id in record.audiences)
            and record.scope in scopes
            and record.status in statuses
        ]
        return tuple([*matches, *self.eligible_extra])

    def resolve_provenance(self, record_ids: tuple[str, ...]) -> tuple[MemoryRecord, ...]:
        self.calls.append(("resolve_provenance", record_ids))
        self._maybe_fail("resolve_provenance")
        resolved: list[MemoryRecord] = []
        seen: set[str] = set()
        queue = list(record_ids)
        while queue:
            record_id = queue.pop(0)
            if record_id in seen:
                continue
            seen.add(record_id)
            record = self.records.get(record_id)
            if record is None:
                continue  # 缺源：不返回它 —— 调用方按 missing_provenance 处理
            resolved.append(record)
            queue.extend(self.ancestor_of.get(record_id, ()))
        return tuple(resolved)

    def write_record(self, record: MemoryRecord, *, actor: Actor) -> None:
        self.calls.append(("write_record", record.id))
        self._maybe_fail("write_record")
        self.writes.append((record, actor))
        self.records[record.id] = record

    def transition(
        self,
        record_id: str,
        to_status: str,
        *,
        actor: Actor,
        updated_at: str,
        consent_version: int,
        last_confirmed_at: str | None,
    ) -> MemoryRecord:
        self.calls.append(("transition", record_id, to_status))
        self._maybe_fail("transition")
        self.transitions.append(
            (record_id, to_status, actor, updated_at, consent_version, last_confirmed_at)
        )
        updated = replace(
            self.records[record_id],
            status=to_status,  # type: ignore[arg-type]
            updated_at=updated_at,
            consent_version=consent_version,
            last_confirmed_at=last_confirmed_at,
        )
        self.records[record_id] = updated
        return updated

    def hard_delete(self, record_id: str) -> tuple[str, ...]:
        self.calls.append(("hard_delete", record_id))
        self._maybe_fail("hard_delete")
        self.hard_deletes.append(record_id)
        self.records.pop(record_id, None)
        return ("memory_record", "memory_audience", "memory_source", "grant_resource")

    def enumerate_dependents(self, record_id: str) -> tuple[str, ...]:
        self.calls.append(("enumerate_dependents", record_id))
        self._maybe_fail("enumerate_dependents")
        return self.dependents.get(record_id, ())

    # -- W1 的到期枚举与审计写入（主控仲裁：必需方法，不是可选钩子） ----------

    def list_expired(self, *, now: str) -> tuple[MemoryRecord, ...]:
        """故意宽返回：凡是带 ``expires_at`` 的都列出来，精确判定留给服务层。

        集成时由主控对齐 A1：契约冻结的签名返回**完整记录**（与 W1 的真实实现一致），
        不是 id 元组。W3 原稿返回 id，会让服务层在真实存储上把 ``MemoryRecord``
        当 ``record_id`` 传回去。
        """

        self.calls.append(("list_expired", now))
        self._maybe_fail("list_expired")
        return tuple(
            [record for record in self.records.values() if record.expires_at is not None]
            + list(self.expired_extra)
        )

    def hard_delete_with_audit(
        self,
        *,
        record_id: str,
        actor: Actor,
        deleted_at: str,
        derived_removed: int = 0,
        unknown_copies: tuple[str, ...] = (),
    ) -> DeletionOutcome:
        """A11 的原子删除：**任一步失败整体回滚**（记录恢复、审计 0 行）。

        替身用「先快照、失败则还原」模拟事务语义 —— 与真实 ``SqliteMemoryStore`` 的
        ``BEGIN IMMEDIATE`` / ``rollback`` 对应，好让服务层的原子性用例在替身上也成立。
        """

        self.calls.append(("hard_delete_with_audit", record_id))
        snapshot_records = dict(self.records)
        snapshot_deletes = list(self.hard_deletes)
        snapshot_audits = list(self.audit_rows)
        try:
            tables = self.hard_delete(record_id)
            tables_touched = tuple(dict.fromkeys((*tables, "deletion_audit")))
            audit_id = self.write_deletion_audit(
                record_id=record_id,
                actor=actor,
                deleted_at=deleted_at,
                tables_touched=tables_touched,
                derived_removed=derived_removed,
                unknown_copies=unknown_copies,
            )
        except BaseException:
            self.records = snapshot_records
            self.hard_deletes = snapshot_deletes
            self.audit_rows = snapshot_audits
            raise
        return DeletionOutcome(
            record_id=record_id, tables_touched=tables_touched, audit_id=audit_id
        )

    def write_deletion_audit(
        self,
        *,
        record_id: str,
        actor: Actor,
        deleted_at: str,
        tables_touched: tuple[str, ...],
        derived_removed: int = 0,
        unknown_copies: tuple[str, ...] = (),
    ) -> str:
        """写入审计行并**返回 audit_id**（由 store 生成，服务层不得自造）。"""

        self.calls.append(("write_deletion_audit", record_id))
        self._maybe_fail("write_deletion_audit")
        audit_id = f"audit-{len(self.audit_rows) + 1}"
        self.audit_rows.append(
            {
                "audit_id": audit_id,
                "record_id": record_id,
                "actor": actor,
                "deleted_at": deleted_at,
                "tables_touched": tables_touched,
                "derived_removed": derived_removed,
                "unknown_copies": unknown_copies,
            }
        )
        return audit_id


class FakeGrantStore:
    """``GrantStore`` Protocol 的内存替身。

    W3 的服务**不应**碰它（§4.5「不自行查 grant」）：``calls`` 用来断言这一点。
    """

    def __init__(self, grants: tuple[Grant, ...] = ()) -> None:
        self.grants = {grant.grant_id: grant for grant in grants}
        self.revoked: set[str] = set()
        self.calls: list[str] = []

    def issue(self, grant: Grant) -> None:
        self.calls.append("issue")
        self.grants[grant.grant_id] = grant

    def revoke(self, grant_id: str, *, revoked_at: str, actor: Actor) -> None:
        self.calls.append("revoke")
        self.revoked.add(grant_id)

    def load_current(self, grant_id: str) -> Grant | None:
        self.calls.append("load_current")
        if grant_id in self.revoked:
            return None
        return self.grants.get(grant_id)

    def load_for_session(self, session_id: str) -> Grant | None:
        self.calls.append("load_for_session")
        for grant in self.grants.values():
            if grant.session_id == session_id and grant.grant_id not in self.revoked:
                return grant
        return None


class FakeAuthorize:
    """``policy.authorize()`` 的形状替身：按记录 id 脚本化拒绝，并记录全部入参。

    语义故意保持极简（**不重实现 DENY_ORDER** —— 那是 W2 的验收范围）：
    闭包里有任何一条命中 ``denied`` 就整体拒绝（与「派生记录必须连同每个祖先都获授权」
    一致），否则按 ``default_reason`` 返回。
    """

    def __init__(
        self,
        *,
        denied: dict[str, str] | None = None,
        default_reason: str = "ok",
    ) -> None:
        self.denied = dict(denied or {})
        self.default_reason = default_reason
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        *,
        action: str,
        access: SessionAccess,
        grant: Grant | None,
        session_id: str,
        audience_id: str,
        records: tuple[MemoryRecord, ...],
        now: str | None,
    ) -> AuthorizationDecision:
        self.calls.append(
            {
                "action": action,
                "access": access,
                "grant": grant,
                "session_id": session_id,
                "audience_id": audience_id,
                "records": records,
                "now": now,
            }
        )
        for record in records:
            reason = self.denied.get(record.id)
            if reason is not None:
                return AuthorizationDecision(allowed=False, reason=reason)  # type: ignore[arg-type]
        return AuthorizationDecision(allowed=True, reason=self.default_reason)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 构造器与假件
# ---------------------------------------------------------------------------


def _record(record_id: str = "rec-1", **overrides: object) -> MemoryRecord:
    values: dict[str, object] = {
        "id": record_id,
        "owner_id": "adult_a",
        "scope": "FAMILY",
        "memory_class": "EVENT",
        "source_type": "explicit_user",
        "source_member_id": "adult_a",
        "content": "喜欢恐龙",
        "confidence": 1.0,
        "importance": 0.5,
        "created_at": NOW,
        "updated_at": NOW,
        "last_confirmed_at": NOW,
        "expires_at": FAR_FUTURE,
        "source_session_id": "session-1",
        "status": "ACTIVE",
        "memory_policy": "persist_confirmed",
        "audiences": frozenset({"family_all"}),
        "consent_version": 1,
        "source_ids": (),
    }
    values.update(overrides)
    if values["status"] == "PENDING_CONFIRMATION":
        values["memory_policy"] = "candidate_only"
        values["last_confirmed_at"] = None
        if "expires_at" not in overrides:
            values["expires_at"] = CANDIDATE_EXPIRY
    elif values["memory_class"] == "SAFETY" and "expires_at" not in overrides:
        values["expires_at"] = None
    return MemoryRecord(**values)  # type: ignore[arg-type]


def _candidate(**overrides: object) -> MemoryCandidate:
    values: dict[str, object] = {
        "content": "对花生过敏",
        "scope": "FAMILY",
        "memory_class": "EVENT",
        "owner_id": "adult_a",
        "source_type": "explicit_user",
        "source_member_id": "adult_a",
        "confidence": 1.0,
        "importance": 0.8,
        "requested_policy": "candidate_only",
        "audiences": frozenset({"family_all"}),
        "origin": "explicit_user",
    }
    values.update(overrides)
    return MemoryCandidate(**values)  # type: ignore[arg-type]


def _source_session(**overrides: object) -> SourceSession:
    values: dict[str, object] = {
        "session_id": "session-1",
        "owner_id": None,
        "audience_id": "family_all",
        "session_mode": "shared",
        "identity_assurance": "unknown",
        "grant_id": None,
    }
    values.update(overrides)
    return SourceSession(**values)  # type: ignore[arg-type]


def _grant() -> Grant:
    return Grant(
        grant_id="grant-1",
        version=1,
        session_id="session-1",
        subject_id="adult_a",
        owner_id="adult_a",
        audience_id="family_all",
        actions=frozenset({"read_model"}),
        resource_ids=frozenset({"rec-1"}),
        consent_versions=(("rec-1", 1),),
        expires_at=FAR_FUTURE,
        issuer="local_control_plane",
        issued_at=NOW,
    )


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


@pytest.fixture(name="store")
def store_fixture() -> FakeMemoryStore:
    return FakeMemoryStore()


@pytest.fixture(name="grants")
def grants_fixture() -> FakeGrantStore:
    return FakeGrantStore()


@pytest.fixture(name="clock")
def clock_fixture() -> FakeClock:
    return FakeClock()


@pytest.fixture(name="retention")
def retention_fixture() -> FakeRetention:
    return FakeRetention()


@pytest.fixture(name="authorize_double")
def authorize_double_fixture(monkeypatch: pytest.MonkeyPatch) -> FakeAuthorize:
    """把契约的 ``authorize()`` 换成形状替身（W2 落地前的离线测试边界）。"""

    double = FakeAuthorize()
    monkeypatch.setattr(policy, "authorize", double)
    return double


@pytest.fixture(name="service")
def service_fixture(
    store: FakeMemoryStore,
    grants: FakeGrantStore,
    clock: FakeClock,
    retention: FakeRetention,
    authorize_double: FakeAuthorize,
) -> MemoryService:
    return MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=grants,  # type: ignore[arg-type]
        clock=clock,
        retention=retention,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# 0. 替身与契约形状
# ---------------------------------------------------------------------------


def test_fakes_follow_the_frozen_store_protocols() -> None:
    """假件必须与冻结的 Protocol 同形状，否则测的是假件的私有约定。"""

    store = FakeMemoryStore()
    for name in (
        "create_schema",
        "read_record",
        "read_records",
        "list_eligible",
        "resolve_provenance",
        "write_record",
        "transition",
        "hard_delete",
        "enumerate_dependents",
        "list_expired",
        "write_deletion_audit",
    ):
        assert callable(getattr(store, name)), name
    assert isinstance(store.path, Path)

    grants = FakeGrantStore()
    for name in ("issue", "revoke", "load_current", "load_for_session"):
        assert callable(getattr(grants, name)), name


def test_constructor_requires_an_injected_clock(
    store: FakeMemoryStore, grants: FakeGrantStore
) -> None:
    with pytest.raises(MemoryValidationError):
        MemoryService(store=store, grants=grants, clock="2026-09-26T12:00:00Z")  # type: ignore[arg-type]


def test_constructor_defaults_to_the_frozen_retention_policy(
    store: FakeMemoryStore,
    grants: FakeGrantStore,
    clock: FakeClock,
    authorize_double: FakeAuthorize,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``retention=None`` 时必须落到契约的 ``RetentionPolicy``（而不是自造默认值）。"""

    seen: list[tuple[str, bool]] = []

    def fake_days_for(self: RetentionPolicy, memory_class: str, *, is_candidate: bool) -> int:
        seen.append((memory_class, is_candidate))
        return 30

    monkeypatch.setattr(RetentionPolicy, "days_for", fake_days_for)
    service = MemoryService(store=store, grants=grants, clock=clock)  # type: ignore[arg-type]

    record = service.propose(_candidate(), _source_session())

    assert record is not None
    assert seen == [("EVENT", True)]
    assert record.expires_at == EVENT_EXPIRY


def test_retention_arithmetic_follows_the_record_phase(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """``expires_at`` 是 ``now + days_for(...)`` 且**写死在记录上**（读取时不重算）。

    - 候选（任何 ``memory_class``，含 SAFETY）→ 候选期天数；
    - 确认后按分型天数，已确认的 SAFETY 类不过期。
    """

    pending = service.propose(_candidate(memory_class="PREFERENCE"), _source_session())
    assert pending is not None
    assert pending.expires_at == CANDIDATE_EXPIRY
    assert store.records[pending.id].expires_at == CANDIDATE_EXPIRY

    confirmed = service.confirm_shared(pending.id, frozenset({"family_all"}), ADULT)
    assert confirmed.expires_at == PREFERENCE_EXPIRY
    assert store.records[confirmed.id].expires_at == PREFERENCE_EXPIRY
    # 常量不是手抄的：逐条核对它真的等于 now + 配置天数。
    assert _instant(CANDIDATE_EXPIRY) - _instant(NOW) == timedelta(days=7)
    assert _instant(EVENT_EXPIRY) - _instant(NOW) == timedelta(days=30)
    assert _instant(PREFERENCE_EXPIRY) - _instant(NOW) == timedelta(days=180)


def test_propose_rejects_an_unusable_retention_day_count(
    store: FakeMemoryStore, grants: FakeGrantStore, clock: FakeClock, authorize_double: FakeAuthorize
) -> None:
    """保留期返回不可用的天数时 fail-closed，绝不写一条期限可疑的记录。"""

    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=grants,  # type: ignore[arg-type]
        clock=clock,
        retention=FakeRetention(candidate_days=0),  # type: ignore[arg-type]
    )

    with pytest.raises(MemoryValidationError):
        service.propose(_candidate(), _source_session())
    assert store.writes == []


# ---------------------------------------------------------------------------
# 1. propose
# ---------------------------------------------------------------------------


def test_propose_writes_a_candidate_never_an_active_record(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """即使 ``requested_policy="persist_confirmed"`` 也不会直接写成 ``ACTIVE``。"""

    for requested in ("candidate_only", "persist_confirmed"):
        store.writes.clear()
        store.records.clear()
        record = service.propose(_candidate(requested_policy=requested), _source_session())

        assert record is not None, requested
        assert record.status == "PENDING_CONFIRMATION", requested
        assert record.memory_policy == "candidate_only", requested
        assert record.last_confirmed_at is None, requested
        assert record.consent_version == 1, requested
        assert record.source_ids == (), requested
        assert record.source_session_id == "session-1", requested
        assert record.created_at == NOW and record.updated_at == NOW, requested
        assert record.expires_at == CANDIDATE_EXPIRY, requested
        assert record.owner_id == "adult_a" and record.scope == "FAMILY", requested
        assert record.memory_class == "EVENT" and record.content == "对花生过敏", requested
        assert record.audiences == frozenset({"family_all"}), requested
        assert store.writes[-1][0] == record, "返回的记录必须就是落库的那条"


def test_propose_attributes_the_write_to_the_source_session(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """候选的写归属是**来源会话**，且**不得**记成成人动作（主控仲裁 2）。

    会话里产生候选不是一次成人动作（D3 的确认/纠正/删除才需要成人控制面），
    记成 ``adult_control_plane`` 会伪造审计归属；actor_id 用 session_id。
    精确的 kind 断言（``session_proposal``）见下面那条契约对齐用例。
    """

    service.propose(_candidate(), _source_session(session_id="session-42"))

    written, actor = store.writes[0]
    assert actor.kind != "adult_control_plane"
    assert actor.kind not in {"ttl_expiry", "migration"}, "候选不是 TTL / 迁移动作"
    assert actor.actor_id == "session-42"
    assert written.source_session_id == "session-42"


def test_session_proposal_is_the_non_adult_candidate_actor(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """候选 actor 恰好是 ``session_proposal``，且它**只能**写候选。

    集成时由主控去掉原 ``skipif``：``model.ACTOR_KINDS`` 已含 ``session_proposal``
    （W0 r3 的 A8），契约对齐用例真实运行。
    """

    service.propose(_candidate(), _source_session(session_id="session-9"))

    _, actor = store.writes[0]
    assert actor.kind == SESSION_PROPOSAL_KIND
    assert actor.actor_id == "session-9"

    probe = Actor(kind=SESSION_PROPOSAL_KIND, actor_id="session-9")
    store.records["rec-pending"] = _record("rec-pending", status="PENDING_CONFIRMATION")
    store.records["rec-active"] = _record("rec-active")
    # §3.7 actor 门：session_proposal 只出现在 M2_1_WRITE_GATE["propose"] 里，
    # 其余四个写操作都必须拒绝它（失败类型 = MemoryValidationError）。
    with pytest.raises(MemoryValidationError):
        service.confirm_shared("rec-pending", frozenset({"family_all"}), probe)
    with pytest.raises(MemoryValidationError):
        service.correct("rec-active", MemoryCorrection(content="改一下"), probe)
    with pytest.raises(MemoryValidationError):
        service.delete("rec-active", probe)
    with pytest.raises(MemoryValidationError):
        service.sweep_expired(probe)
    # 反向：它对 propose 是合法的（这是它唯一的写权限）。
    assert M2_1_WRITE_GATE["propose"] == {"adult_control_plane", SESSION_PROPOSAL_KIND}


def test_do_not_persist_never_reaches_the_store(service: MemoryService, store: FakeMemoryStore) -> None:
    """落点一：返回 ``None``、库中零行、存储层零写入（契约 §5.4）。"""

    result = service.propose(_candidate(requested_policy="do_not_persist"), _source_session())

    assert result is None
    assert store.records == {}
    assert store.writes == []
    assert ("write_record",) not in [(call[0],) for call in store.calls]


@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": "PERSONAL"},
        {"scope": "SAFETY"},
        {"origin": "auto_extracted"},
        {"content": ""},
        {"audiences": frozenset()},
    ],
    ids=["personal", "safety-scope", "auto-extracted", "empty-content", "no-audience"],
)
def test_do_not_persist_is_the_first_gate(
    service: MemoryService, store: FakeMemoryStore, overrides: dict[str, object]
) -> None:
    """``do_not_persist`` 是**第一道判断**：其余字段非法也不落库、不抛错（§5 落点一）。"""

    candidate = _candidate(requested_policy="do_not_persist", **overrides)

    assert service.propose(candidate, _source_session()) is None
    assert store.records == {}
    assert store.writes == []


@pytest.mark.parametrize("scope", ["PERSONAL", "SAFETY"])
def test_propose_rejects_non_family_scope_with_scope_not_enabled(
    service: MemoryService, store: FakeMemoryStore, scope: str
) -> None:
    """M2.1 相位限制：``PERSONAL`` / ``SAFETY`` **scope** 的创建路径尚未裁决。"""

    with pytest.raises(AuthorizationError) as excinfo:
        service.propose(_candidate(scope=scope), _source_session())

    assert excinfo.value.decision.allowed is False
    assert excinfo.value.decision.reason == "scope_not_enabled"
    assert store.writes == []


def test_propose_keeps_safety_memory_class_in_family_scope(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """``memory_class="SAFETY"``（过敏这类内容）在 ``FAMILY`` scope 下照常支持。

    相位限制管的是 ``scope``（谁能读），不是 ``memory_class``（留多久）。
    候选期仍按 7 天算（§6.2）—— 「安全记忆不过期」说的是**已确认**的那条。
    """

    record = service.propose(_candidate(memory_class="SAFETY"), _source_session())

    assert record is not None
    assert record.memory_class == "SAFETY"
    assert record.scope == "FAMILY"
    assert record.expires_at == CANDIDATE_EXPIRY


def test_propose_accepts_auto_extracted_origin(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """M2.2 §3：``M2_1_ALLOWED_ORIGINS`` 放行 ``auto_extracted``，``propose()`` 接受它。

    **放行不等于放松**：它仍然只落 ``PENDING_CONFIRMATION`` + ``candidate_only``
    （约束 1：模型只能产出候选，成人确认是唯一生效路径），因此这里同时断言状态与策略。
    本用例是 T15 第 6 处（``m2_1_auto_extracted_origin_rejected`` 改为接受）的服务侧落地。
    """

    record = service.propose(_candidate(origin="auto_extracted"), _source_session())

    assert record is not None
    assert record.status == "PENDING_CONFIRMATION"
    assert record.memory_policy == "candidate_only"
    assert record.source_type == "explicit_user", "source_type 由候选自带，propose 不改写它"
    assert store.records[record.id].status == "PENDING_CONFIRMATION"


@pytest.mark.parametrize(
    "overrides",
    [
        {"content": ""},
        {"content": "   "},
        {"importance": 1.5},
        {"importance": -0.1},
        {"importance": float("nan")},
        {"confidence": 2.0},
        {"confidence": True},
        {"memory_class": "UNKNOWN"},
        {"source_type": "unknown_source"},
        {"requested_policy": "unknown_policy"},
        {"owner_id": ""},
        {"source_member_id": ""},
        {"audiences": frozenset({"  "})},
    ],
    ids=[
        "empty-content",
        "blank-content",
        "importance-high",
        "importance-low",
        "importance-nan",
        "confidence-high",
        "confidence-bool",
        "memory-class",
        "source-type",
        "requested-policy",
        "owner-id",
        "source-member-id",
        "blank-audience",
    ],
)
def test_propose_validates_candidate_shape(
    service: MemoryService, store: FakeMemoryStore, overrides: dict[str, object]
) -> None:
    with pytest.raises(MemoryValidationError):
        service.propose(_candidate(**overrides), _source_session())
    assert store.writes == []


def test_propose_requires_an_explicit_audience_for_family(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """家庭共享必须有显式受众，不能靠默认值。"""

    with pytest.raises(MemoryValidationError):
        service.propose(_candidate(audiences=frozenset()), _source_session())
    assert store.writes == []


def test_propose_validates_the_source_session(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    with pytest.raises(MemoryValidationError):
        service.propose(_candidate(), _source_session(session_id="  "))
    with pytest.raises(MemoryValidationError):
        service.propose(_candidate(), "session-1")  # type: ignore[arg-type]
    assert store.writes == []


def test_propose_with_an_unparsable_clock_is_denied_before_writing(
    store: FakeMemoryStore,
    grants: FakeGrantStore,
    authorize_double: FakeAuthorize,
) -> None:
    """时钟不可信时先于一切拒绝（§3.2）；不写一条时间戳可疑的记录。"""

    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=grants,  # type: ignore[arg-type]
        clock=FakeClock("not-a-timestamp"),
        retention=FakeRetention(),  # type: ignore[arg-type]
    )

    with pytest.raises(AuthorizationError) as excinfo:
        service.propose(_candidate(), _source_session())

    assert excinfo.value.decision.reason == "clock_invalid"
    assert store.writes == []


# ---------------------------------------------------------------------------
# 2. confirm_shared
# ---------------------------------------------------------------------------


def test_confirm_shared_promotes_the_candidate(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """唯一能把记录变成可召回的路径：状态、策略、受众、版本、期限一次落地。"""

    candidate = _record("rec-candidate", status="PENDING_CONFIRMATION", content="对花生过敏")
    store.records[candidate.id] = candidate

    confirmed = service.confirm_shared("rec-candidate", frozenset({"family_all"}), ADULT)

    assert confirmed.status == "ACTIVE"
    assert confirmed.memory_policy == "persist_confirmed"
    assert confirmed.last_confirmed_at == NOW
    assert confirmed.updated_at == NOW
    assert confirmed.consent_version == candidate.consent_version + 1
    assert confirmed.audiences == frozenset({"family_all"})
    assert confirmed.expires_at == EVENT_EXPIRY
    assert confirmed.created_at == candidate.created_at
    assert confirmed.content == candidate.content
    assert store.records["rec-candidate"] == confirmed


def test_confirm_shared_lets_confirmed_safety_memories_never_expire(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """D5：``FAMILY`` + ``memory_class="SAFETY"`` 的**已确认**记录 ``expires_at`` 为 NULL。"""

    store.records["rec-allergy"] = _record(
        "rec-allergy", memory_class="SAFETY", status="PENDING_CONFIRMATION", expires_at=CANDIDATE_EXPIRY
    )

    confirmed = service.confirm_shared("rec-allergy", frozenset({"family_all"}), ADULT)

    assert confirmed.expires_at is None
    assert confirmed.memory_class == "SAFETY"


def test_confirm_shared_replaces_the_audience(service: MemoryService, store: FakeMemoryStore) -> None:
    store.records["rec-candidate"] = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", audiences=frozenset({"family_all"})
    )

    confirmed = service.confirm_shared("rec-candidate", frozenset({"adult_b"}), ADULT)

    assert confirmed.audiences == frozenset({"adult_b"})


def test_confirm_shared_reconfirms_and_reactivates(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """``ACTIVE`` 自环（再次确认）与 ``DECAYED → ACTIVE``（重新激活）都合法，且版本递增。"""

    store.records["rec-active"] = _record("rec-active")
    store.records["rec-decayed"] = _record("rec-decayed", status="DECAYED")

    reconfirmed = service.confirm_shared("rec-active", frozenset({"family_all"}), ADULT)
    reactivated = service.confirm_shared("rec-decayed", frozenset({"family_all"}), ADULT)

    assert reconfirmed.status == "ACTIVE"
    assert reconfirmed.consent_version == 2
    assert reactivated.status == "ACTIVE"
    assert reactivated.consent_version == 2


@pytest.mark.parametrize("actor", [TTL, MIGRATION], ids=["ttl-expiry", "migration"])
def test_confirm_shared_requires_the_adult_control_plane(
    service: MemoryService, store: FakeMemoryStore, actor: Actor
) -> None:
    store.records["rec-candidate"] = _record("rec-candidate", status="PENDING_CONFIRMATION")

    # §3.7 第二道门（actor 门）→ MemoryValidationError：这是**本次调用**的入参问题，
    # 不是记录状态机的问题。第三道门（迁移表）才用 IllegalTransition。
    with pytest.raises(MemoryValidationError):
        service.confirm_shared("rec-candidate", frozenset({"family_all"}), actor)

    assert store.writes == []


def test_confirm_shared_rejects_deleted_records_and_unknown_ids(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    store.records["rec-deleted"] = _record(
        "rec-deleted", status="DELETED", memory_policy="persist_confirmed", content=""
    )

    with pytest.raises(IllegalTransition):
        service.confirm_shared("rec-deleted", frozenset({"family_all"}), ADULT)
    with pytest.raises(RecordNotFound):
        service.confirm_shared("rec-missing", frozenset({"family_all"}), ADULT)


def test_confirm_shared_enforces_the_m2_1_phase_scope(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    store.records["rec-personal"] = _record(
        "rec-personal", scope="PERSONAL", status="PENDING_CONFIRMATION"
    )

    with pytest.raises(AuthorizationError) as excinfo:
        service.confirm_shared("rec-personal", frozenset({"family_all"}), ADULT)

    assert excinfo.value.decision.reason == "scope_not_enabled"
    assert store.writes == []


@pytest.mark.parametrize("audience", [frozenset(), frozenset({"  "}), "family_all"])
def test_confirm_shared_rejects_an_empty_or_malformed_audience(
    service: MemoryService, store: FakeMemoryStore, audience: object
) -> None:
    store.records["rec-candidate"] = _record("rec-candidate", status="PENDING_CONFIRMATION")

    with pytest.raises(MemoryValidationError):
        service.confirm_shared("rec-candidate", audience, ADULT)  # type: ignore[arg-type]
    assert store.writes == []


# ---------------------------------------------------------------------------
# 3. correct
# ---------------------------------------------------------------------------


def test_correct_replaces_only_the_given_fields(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    original = _record("rec-1", content="喜欢恐龙", importance=0.5, audiences=frozenset({"family_all"}))
    store.records["rec-1"] = original

    corrected = service.correct(
        "rec-1",
        MemoryCorrection(content="喜欢三角龙", importance=0.9, audiences=frozenset({"adult_b"})),
        ADULT,
    )

    assert corrected.content == "喜欢三角龙"
    assert corrected.importance == 0.9
    assert corrected.audiences == frozenset({"adult_b"})
    assert corrected.updated_at == NOW
    assert corrected.consent_version == original.consent_version + 1
    assert corrected.expires_at == EVENT_EXPIRY
    # 归属、来源、状态、创建时间都不可改。
    assert corrected.owner_id == original.owner_id
    assert corrected.scope == original.scope
    assert corrected.memory_class == original.memory_class
    assert corrected.source_type == original.source_type
    assert corrected.source_member_id == original.source_member_id
    assert corrected.created_at == original.created_at
    assert corrected.status == original.status
    assert corrected.last_confirmed_at == original.last_confirmed_at


def test_correct_keeps_unspecified_fields(service: MemoryService, store: FakeMemoryStore) -> None:
    original = _record("rec-1", content="喜欢恐龙", importance=0.5)
    store.records["rec-1"] = original

    corrected = service.correct("rec-1", MemoryCorrection(content="喜欢翼龙"), ADULT)

    assert corrected.content == "喜欢翼龙"
    assert corrected.importance == original.importance
    assert corrected.audiences == original.audiences


@pytest.mark.parametrize(
    "status", ["PENDING_CONFIRMATION", "DELETED"], ids=["candidate", "tombstone"]
)
def test_correct_rejects_illegal_self_transitions(
    service: MemoryService, store: FakeMemoryStore, status: str
) -> None:
    """候选没有自环边（要先确认），墓碑是终态 —— 都不得被静默修正。"""

    store.records["rec-1"] = _record("rec-1", status=status)

    with pytest.raises(IllegalTransition):
        service.correct("rec-1", MemoryCorrection(content="改一下"), ADULT)
    assert store.writes == []


def test_correct_requires_the_adult_control_plane(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    store.records["rec-1"] = _record("rec-1")

    with pytest.raises(MemoryValidationError):  # §3.7 actor 门
        service.correct("rec-1", MemoryCorrection(content="改一下"), TTL)
    assert store.writes == []


@pytest.mark.parametrize(
    "replacement",
    [
        MemoryCorrection(content=""),
        MemoryCorrection(content="   "),
        MemoryCorrection(importance=1.5),
        MemoryCorrection(importance=-1.0),
        MemoryCorrection(audiences=frozenset()),
        MemoryCorrection(audiences=frozenset({" "})),
    ],
    ids=["empty-content", "blank-content", "importance", "importance-low", "no-audience", "blank-audience"],
)
def test_correct_rejects_malformed_replacements(
    service: MemoryService, store: FakeMemoryStore, replacement: MemoryCorrection
) -> None:
    store.records["rec-1"] = _record("rec-1")

    with pytest.raises(MemoryValidationError):
        service.correct("rec-1", replacement, ADULT)
    assert store.writes == []


def test_correct_requires_an_existing_record(service: MemoryService, store: FakeMemoryStore) -> None:
    with pytest.raises(RecordNotFound):
        service.correct("rec-missing", MemoryCorrection(content="改一下"), ADULT)


def test_correct_enforces_the_m2_1_phase_scope(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    store.records["rec-personal"] = _record("rec-personal", scope="PERSONAL")

    with pytest.raises(AuthorizationError) as excinfo:
        service.correct("rec-personal", MemoryCorrection(content="改一下"), ADULT)

    assert excinfo.value.decision.reason == "scope_not_enabled"
    assert store.writes == []


# ---------------------------------------------------------------------------
# 4. delete
# ---------------------------------------------------------------------------


def test_delete_removes_the_record_its_dependents_and_grant_rows(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """硬删除：只删这一条 + ``grant_resource`` 行 + 一条 ``deletion_audit``。

    **血缘按 A2**（集成时由主控对齐）：派生记录**不**连带删除，只写进
    ``derived_unreachable``；``derived_removed`` 恒为 ``()``。
    派生记录仍留在盘上，靠 ``missing_provenance`` 永久 fail-closed。
    """

    store.records["rec-1"] = _record("rec-1")
    store.records["rec-derived"] = _record("rec-derived")
    store.dependents = {"rec-1": ("rec-derived",), "rec-derived": ()}

    report = service.delete("rec-1", ADULT)

    assert store.hard_deletes == ["rec-1"], "A2：不级联删除派生记录"
    assert set(store.records) == {"rec-derived"}, "派生记录仍在盘上，但已不可召回"
    assert report.record_ids == ("rec-1",)
    assert report.derived_removed == (), "A2：没有删除任何派生记录"
    assert report.derived_unreachable == ("rec-derived",), (
        "A2：仍留在盘上、已永久不可召回的派生记录必须如实列出"
    )
    for table in ("memory_record", "memory_audience", "memory_source", "grant_resource"):
        assert table in report.tables_touched, table
    assert "deletion_audit" in report.tables_touched
    assert report.deleted_at == NOW
    assert len(store.audit_rows) == 1
    audit = store.audit_rows[0]
    assert audit["record_id"] == "rec-1"
    assert audit["actor"] == ADULT
    assert audit["derived_removed"] == 0, "A2：审计行同样不得谎报删除了派生记录"
    assert audit["unknown_copies"] == report.unknown_copies
    assert audit["tables_touched"] == report.tables_touched
    # audit_id 由 store 生成并返回（主控仲裁），服务层不自造 id。
    assert report.audit_id == audit["audit_id"] == "audit-1"


def test_delete_walks_dependents_transitively(service: MemoryService, store: FakeMemoryStore) -> None:
    """血缘由 ``enumerate_dependents()`` **递归**枚举（去重、防环），但只用于**报告**。

    A2（集成时由主控对齐）：枚举结果进 ``derived_unreachable``，不进 ``derived_removed``。
    ``rec-leaf`` 的反向边制造环，用来证明枚举不会死循环。
    """

    store.records["rec-1"] = _record("rec-1")
    store.records["rec-mid"] = _record("rec-mid")
    store.records["rec-leaf"] = _record("rec-leaf")
    store.dependents = {"rec-1": ("rec-mid",), "rec-mid": ("rec-leaf",), "rec-leaf": ("rec-1",)}

    report = service.delete("rec-1", ADULT)

    assert set(report.derived_unreachable) == {"rec-mid", "rec-leaf"}
    assert len(report.derived_unreachable) == len(set(report.derived_unreachable)), "不得重复"
    assert report.derived_removed == (), "A2：枚举不等于删除"
    assert store.hard_deletes == ["rec-1"]


def test_delete_report_never_claims_complete_deletion(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """``unknown_copies`` 必须显式列出枚举不到的位置，禁止填空冒充完整（§7.2/§7.3）。"""

    store.records["rec-1"] = _record("rec-1")

    report = service.delete("rec-1", ADULT)

    assert report.unknown_copies, "unknown_copies 不能为空"
    joined = " ".join(report.unknown_copies)
    for keyword in ("provider", "sha256", "JSONL", "快照", "播出"):
        assert keyword in joined, keyword


def test_delete_has_no_phase_gate(service: MemoryService, store: FakeMemoryStore) -> None:
    """M2.1 不创建也不召回私人记忆，但**成人必须仍能删掉**库里的私人记忆。"""

    store.records["rec-personal"] = _record("rec-personal", scope="PERSONAL")
    store.records["rec-safety"] = _record("rec-safety", scope="SAFETY", memory_class="SAFETY")

    service.delete("rec-personal", ADULT)
    service.delete("rec-safety", ADULT)

    assert store.records == {}


def test_delete_also_removes_candidates_and_decayed_records(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """删除不是状态迁移（§2.3）：候选、``DECAYED``、历史墓碑都删得掉。"""

    store.records["rec-candidate"] = _record("rec-candidate", status="PENDING_CONFIRMATION")
    store.records["rec-decayed"] = _record("rec-decayed", status="DECAYED")

    service.delete("rec-candidate", ADULT)
    service.delete("rec-decayed", ADULT)

    assert store.records == {}


@pytest.mark.parametrize("actor", [TTL, MIGRATION], ids=["ttl-expiry", "migration"])
def test_delete_requires_the_adult_control_plane(
    service: MemoryService, store: FakeMemoryStore, actor: Actor
) -> None:
    store.records["rec-1"] = _record("rec-1")

    with pytest.raises(MemoryValidationError):  # §3.7 actor 门
        service.delete("rec-1", actor)

    assert store.hard_deletes == []
    assert store.records != {}


def test_delete_writes_the_audit_row_through_the_store_method(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """审计行经 ``store.write_deletion_audit(...)`` 写入，``audit_id`` 用它的返回值。"""

    store.records["rec-1"] = _record("rec-1")

    report = service.delete("rec-1", ADULT)

    assert ("write_deletion_audit", "rec-1") in store.calls
    assert report.audit_id == store.audit_rows[0]["audit_id"] == "audit-1"


def test_delete_requires_an_existing_record(service: MemoryService, store: FakeMemoryStore) -> None:
    with pytest.raises(RecordNotFound):
        service.delete("rec-missing", ADULT)


def test_delete_wraps_store_failures_into_store_error(
    grants: FakeGrantStore,
    clock: FakeClock,
    retention: FakeRetention,
    authorize_double: FakeAuthorize,
) -> None:
    """删除中途失败必须让调用方知道，不能报成功（§4.7）。"""

    store = FakeMemoryStore(
        (_record("rec-1"),), failures={"hard_delete": RuntimeError("disk on fire")}
    )
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=grants,  # type: ignore[arg-type]
        clock=clock,
        retention=retention,  # type: ignore[arg-type]
    )

    with pytest.raises(StoreError):
        service.delete("rec-1", ADULT)


# ---------------------------------------------------------------------------
# 5. query
# ---------------------------------------------------------------------------


def test_query_returns_authorized_family_entries(
    service: MemoryService, store: FakeMemoryStore, authorize_double: FakeAuthorize
) -> None:
    store.records["rec-b"] = _record("rec-b", content="喜欢恐龙")
    store.records["rec-a"] = _record("rec-a", content="对花生过敏")

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.record_ids == ("rec-a", "rec-b")
    assert [entry.content for entry in snapshot.entries] == ["对花生过敏", "喜欢恐龙"]
    assert snapshot.denied == ()
    assert snapshot.session_id == "session-1"
    assert snapshot.audience_id == "family_all"
    assert snapshot.purpose == "session_projection"
    assert snapshot.created_at == NOW
    assert snapshot.snapshot_id.startswith("snap-")


def test_query_is_deterministic(service: MemoryService, store: FakeMemoryStore) -> None:
    """同一时刻、同一授权范围 → 同一快照 id（回归比对不因随机 id 变成假阳性）。"""

    store.records["rec-a"] = _record("rec-a")

    first = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )
    second = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert first.snapshot_id == second.snapshot_id
    assert first == second


@pytest.mark.parametrize(
    ("purpose", "carries_content"),
    [
        ("session_projection", True),
        ("adult_inspect", True),
        ("adult_list", False),
        ("deletion_audit", False),
    ],
)
def test_query_content_follows_the_purpose(
    service: MemoryService, store: FakeMemoryStore, purpose: str, carries_content: bool
) -> None:
    """带正文与否由 ``purpose`` 决定（§4.5）。"""

    store.records["rec-a"] = _record("rec-a", content="喜欢恐龙")

    snapshot = service.query(
        SessionAccess(), purpose, session_id="session-1", audience_id="family_all", grant=None  # type: ignore[arg-type]
    )

    assert snapshot.entries[0].content == ("喜欢恐龙" if carries_content else None)


def test_query_reports_denied_records_without_content(
    service: MemoryService, store: FakeMemoryStore, authorize_double: FakeAuthorize
) -> None:
    """``denied`` 只有 id 与固定枚举 reason，**绝不含正文**。"""

    store.records["rec-ok"] = _record("rec-ok", content="可以读")
    store.records["rec-no"] = _record("rec-no", content="读不到", scope="PERSONAL")
    authorize_double.denied["rec-no"] = "scope_not_enabled"

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.record_ids == ("rec-ok",)
    assert snapshot.denied == (("rec-no", "scope_not_enabled"),)
    assert "读不到" not in repr(snapshot.denied)


def test_query_does_not_trust_the_listing(authorize_double: FakeAuthorize) -> None:
    """``list_eligible`` 多返回的记录仍要过判权 —— 列表不是授权。"""

    store = FakeMemoryStore(
        (_record("rec-ok"), _record("rec-no")),
        listing_mode="all",
    )
    authorize_double.denied["rec-no"] = "scope_denied"
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=FakeGrantStore(),  # type: ignore[arg-type]
        clock=FakeClock(),
        retention=FakeRetention(),  # type: ignore[arg-type]
    )

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.record_ids == ("rec-ok",)
    assert snapshot.denied == (("rec-no", "scope_denied"),)


def test_query_excludes_expired_records_without_sweeping(
    service: MemoryService, store: FakeMemoryStore, authorize_double: FakeAuthorize
) -> None:
    """到期记录实时排除：``status`` 还是 ``ACTIVE`` 也不进快照，**不判权**，但记入 ``denied``。

    主控 2026-09-26：排除也要留痕 —— 「本次会话看不到它」与「它根本不在候选集里」
    是两件事，审计必须能区分。reason 与判权的 ``record_expired`` 同名。
    """

    store.records["rec-live"] = _record("rec-live", content="还在")
    store.records["rec-expired"] = _record(
        "rec-expired", content="过期了", expires_at="2026-09-26T11:59:59Z"
    )

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.record_ids == ("rec-live",)
    assert snapshot.denied == (("rec-expired", "record_expired"),), "排除也留痕"
    assert store.transitions == [], "query 不改状态（正确性不依赖 sweep）"
    decided = {record.id for call in authorize_double.calls for record in call["records"]}  # type: ignore[union-attr]
    assert decided == {"rec-live"}


def test_query_excludes_records_with_an_unparsable_expiry(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """期限无法证实就不能召回（fail-closed）。"""

    store.records["rec-bad"] = _record("rec-bad", expires_at="whenever")

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert snapshot.denied == (("rec-bad", "record_expired"),), "期限不可证实 = 按到期排除并留痕"


def test_query_passes_every_frozen_input_to_authorize(
    service: MemoryService, store: FakeMemoryStore, authorize_double: FakeAuthorize, clock: FakeClock
) -> None:
    """判权输入逐项核对：action / access / grant / session_id / audience_id / now / records。"""

    record = _record("rec-a")
    store.records["rec-a"] = record
    access = SessionAccess.for_manual_selection("adult_a")
    grant = _grant()

    service.query(
        access, "session_projection", session_id="session-1", audience_id="family_all", grant=grant
    )

    assert len(authorize_double.calls) == 1
    call = authorize_double.calls[0]
    assert call["action"] == "read_model"
    assert call["access"] is access
    assert call["grant"] is grant
    assert call["session_id"] == "session-1"
    assert call["audience_id"] == "family_all"
    assert call["now"] == NOW
    assert call["records"] == (record,)


def test_query_never_looks_up_grants_by_itself(
    service: MemoryService, store: FakeMemoryStore, grants: FakeGrantStore
) -> None:
    """§4.5：grant 由调用方传入，服务不得按 session_id 自建第二条授权路径。"""

    store.records["rec-a"] = _record("rec-a")

    service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert grants.calls == []


def test_query_passes_the_ancestor_closure_and_inherits_its_denials(
    service: MemoryService, authorize_double: FakeAuthorize
) -> None:
    """派生记录必须连同每个祖先一起判权；祖先被拒 → 派生物也不可读（§7.4）。"""

    root = _record("rec-root")
    derived = _record("rec-derived", source_ids=("rec-root",))
    store = FakeMemoryStore((root, derived), ancestor_of={"rec-derived": ("rec-root",)})
    authorize_double.denied["rec-root"] = "stale_consent"
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=FakeGrantStore(),  # type: ignore[arg-type]
        clock=FakeClock(),
        retention=FakeRetention(),  # type: ignore[arg-type]
    )

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert ("rec-derived", "stale_consent") in snapshot.denied
    closures = {
        tuple(record.id for record in call["records"])  # type: ignore[union-attr]
        for call in authorize_double.calls
    }
    assert ("rec-derived", "rec-root") in closures


def test_query_denies_records_with_a_missing_ancestor(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """祖先缺源 → ``missing_provenance``，绝不「只授权可见的那部分」。"""

    store.records["rec-derived"] = _record("rec-derived", source_ids=("rec-gone",))

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert snapshot.denied == (("rec-derived", "missing_provenance"),)


def test_query_denies_records_that_vanish_between_listing_and_reading(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    store.records["rec-a"] = _record("rec-a")
    store.eligible_extra = ("rec-ghost",)

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.record_ids == ("rec-a",)
    assert snapshot.denied == (("rec-ghost", "missing_provenance"),)


def test_query_denies_everything_when_provenance_cannot_be_attested(
    authorize_double: FakeAuthorize,
) -> None:
    """血缘解析异常 → 全部按缺源 fail-closed（不把「证不了」当成「可以读」）。"""

    store = FakeMemoryStore((_record("rec-a"),), failures={"resolve_provenance": RuntimeError("cycle")})
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=FakeGrantStore(),  # type: ignore[arg-type]
        clock=FakeClock(),
        retention=FakeRetention(),  # type: ignore[arg-type]
    )

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert snapshot.denied == (("rec-a", "missing_provenance"),)


def test_query_does_not_mask_store_errors_as_missing_provenance(
    authorize_double: FakeAuthorize,
) -> None:
    """真实存储故障必须报出来，不能伪装成「没有记忆」。"""

    store = FakeMemoryStore((_record("rec-a"),), failures={"resolve_provenance": StoreError("boom")})
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=FakeGrantStore(),  # type: ignore[arg-type]
        clock=FakeClock(),
        retention=FakeRetention(),  # type: ignore[arg-type]
    )

    with pytest.raises(StoreError):
        service.query(
            SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
        )


def test_query_with_an_unparsable_clock_returns_an_empty_denied_snapshot(
    store: FakeMemoryStore,
    grants: FakeGrantStore,
    retention: FakeRetention,
    authorize_double: FakeAuthorize,
) -> None:
    """时钟不可解析 → 空快照 + 每条 ``clock_invalid``（``DENY_ORDER`` 第 1 条），不抛错。"""

    store.records["rec-a"] = _record("rec-a")
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=grants,  # type: ignore[arg-type]
        clock=FakeClock("not-a-timestamp"),
        retention=retention,  # type: ignore[arg-type]
    )

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert snapshot.denied == (("rec-a", "clock_invalid"),)
    assert snapshot.created_at == "not-a-timestamp"
    assert authorize_double.calls == [], "时钟不可信时不进入判权（先于一切拒绝）"


def test_query_never_raises_on_a_missing_grant(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """无授权不是错误：没有记录时返回空快照，不抛异常。"""

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert snapshot.denied == ()


def test_empty_snapshot_appends_no_instructions(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """§10.1 第四条不变量（W3 侧断言）：无 grant 时 instructions 逐字节不变。"""

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert render_memory_block(snapshot) == ""


@pytest.mark.parametrize(
    "overrides",
    [
        {"purpose": "unknown_purpose"},
        {"session_id": ""},
        {"session_id": None},
        {"audience_id": "  "},
        {"grant": "grant-1"},
        {"session_access": "shared"},
    ],
    ids=["purpose", "session-id", "session-id-none", "audience-id", "grant-type", "access-type"],
)
def test_query_validates_its_shape(
    service: MemoryService, store: FakeMemoryStore, overrides: dict[str, object]
) -> None:
    """读路径只抛 ``MemoryValidationError`` / ``StoreError``（§4.7）。"""

    kwargs: dict[str, object] = {
        "session_access": SessionAccess(),
        "purpose": "session_projection",
        "session_id": "session-1",
        "audience_id": "family_all",
        "grant": None,
    }
    kwargs.update(overrides)
    session_access = kwargs.pop("session_access")
    purpose = kwargs.pop("purpose")

    with pytest.raises(MemoryValidationError):
        service.query(session_access, purpose, **kwargs)  # type: ignore[arg-type]


def test_query_wraps_store_failures_into_store_error(
    grants: FakeGrantStore,
    clock: FakeClock,
    retention: FakeRetention,
    authorize_double: FakeAuthorize,
) -> None:
    store = FakeMemoryStore(failures={"list_eligible": RuntimeError("db gone")})
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=grants,  # type: ignore[arg-type]
        clock=clock,
        retention=retention,  # type: ignore[arg-type]
    )

    with pytest.raises(StoreError):
        service.query(
            SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
        )


# ---------------------------------------------------------------------------
# 6. sweep_expired
# ---------------------------------------------------------------------------


def test_sweep_decays_expired_active_records_and_keeps_them_on_disk(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """``ACTIVE`` 到期 → ``DECAYED``：停止召回但**不删盘**（D5）。"""

    expired = _record("rec-expired", expires_at="2026-09-26T11:00:00Z")
    store.records["rec-expired"] = expired
    store.records["rec-live"] = _record("rec-live")

    results = service.sweep_expired(TTL)

    assert len(results) == 1
    decayed = results[0]
    assert isinstance(decayed, MemoryRecord)
    assert decayed.status == "DECAYED"
    assert "rec-expired" in store.records, "到期只停召回，不删盘"
    assert store.hard_deletes == []
    assert store.transitions == [
        ("rec-expired", "DECAYED", TTL, NOW, expired.consent_version, expired.last_confirmed_at)
    ]


def test_sweep_hard_deletes_expired_candidates_and_audits(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """候选到期是**硬删除**（删行 + 写 ``deletion_audit``），不是状态翻转（§6.2）。"""

    store.records["rec-candidate"] = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", expires_at="2026-09-26T11:00:00Z"
    )

    results = service.sweep_expired(TTL)

    assert len(results) == 1
    report = results[0]
    assert isinstance(report, DeletionReport)
    assert report.record_ids == ("rec-candidate",)
    assert report.deleted_at == NOW
    assert "rec-candidate" not in store.records
    assert store.hard_deletes == ["rec-candidate"]
    assert store.transitions == [], "候选到期不是状态迁移"
    assert len(store.audit_rows) == 1
    assert store.audit_rows[0]["actor"] == TTL
    assert store.audit_rows[0]["audit_id"] == report.audit_id


def test_sweep_applies_the_candidate_period_to_safety_class_candidates(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """``memory_class="SAFETY"`` 的**候选**同样受 7 天候选期约束（§6.2）。"""

    store.records["rec-allergy"] = _record(
        "rec-allergy",
        memory_class="SAFETY",
        status="PENDING_CONFIRMATION",
        expires_at="2026-09-26T11:00:00Z",
    )

    results = service.sweep_expired(TTL)

    assert isinstance(results[0], DeletionReport)
    assert "rec-allergy" not in store.records


def test_sweep_leaves_unexpired_and_non_recallable_records_alone(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    store.records["rec-live"] = _record("rec-live")
    store.records["rec-decayed"] = _record("rec-decayed", status="DECAYED", expires_at="2020-01-01T00:00:00Z")
    store.records["rec-tombstone"] = _record(
        "rec-tombstone", status="DELETED", content="", expires_at="2020-01-01T00:00:00Z"
    )
    store.records["rec-safety"] = _record("rec-safety", memory_class="SAFETY", expires_at=None)

    assert service.sweep_expired(TTL) == ()
    assert store.hard_deletes == []
    assert store.transitions == []


@pytest.mark.parametrize("actor", [ADULT, MIGRATION], ids=["adult-control-plane", "migration"])
def test_sweep_requires_the_ttl_expiry_actor(
    service: MemoryService, store: FakeMemoryStore, actor: Actor
) -> None:
    store.records["rec-expired"] = _record("rec-expired", expires_at="2026-09-26T11:00:00Z")

    with pytest.raises(MemoryValidationError):  # §3.7 actor 门
        service.sweep_expired(actor)

    assert store.transitions == []
    assert store.hard_deletes == []


def test_sweep_enumerates_expired_records_through_the_store_method(
    service: MemoryService, store: FakeMemoryStore, authorize_double: FakeAuthorize
) -> None:
    """枚举走 W1 的 ``store.list_expired(now=...)``，不用按受众过滤的 ``list_eligible``。"""

    store.records["rec-expired"] = _record("rec-expired", expires_at="2026-09-26T11:00:00Z")

    service.sweep_expired(TTL)

    assert ("list_expired", NOW) in store.calls
    assert store.listing_filters == [], "扫描不得退化成按受众的宽列表"


def test_sweep_audits_candidate_deletions_through_the_store_method(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """候选硬删除的审计行同样经 store 写入；报告里的 ``audit_id`` 是 store 的返回值。"""

    store.records["rec-candidate"] = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", expires_at="2026-09-26T11:00:00Z"
    )

    report = service.sweep_expired(TTL)[0]

    assert isinstance(report, DeletionReport)
    assert ("write_deletion_audit", "rec-candidate") in store.calls
    assert report.audit_id == store.audit_rows[0]["audit_id"] == "audit-1"
    assert report.unknown_copies, "候选删除同样不得声称完整删除"
    assert store.audit_rows[0]["derived_removed"] == 0


def test_sweep_wraps_store_failures_into_store_error(
    grants: FakeGrantStore,
    clock: FakeClock,
    retention: FakeRetention,
    authorize_double: FakeAuthorize,
) -> None:
    store = FakeMemoryStore(
        (_record("rec-expired", expires_at="2026-09-26T11:00:00Z"),),
        failures={"transition": RuntimeError("db gone")},
    )
    service = MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=grants,  # type: ignore[arg-type]
        clock=clock,
        retention=retention,  # type: ignore[arg-type]
    )

    with pytest.raises(StoreError):
        service.sweep_expired(TTL)


def test_sweep_expiry_comparison_is_fail_closed_at_the_boundary(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """``expires_at == now`` 已算到期（``>=``，fail-closed）。"""

    store.records["rec-boundary"] = _record("rec-boundary", expires_at=NOW)
    store.records["rec-unparsable"] = _record("rec-unparsable", expires_at="whenever")

    results = service.sweep_expired(TTL)

    assert {record.id for record in results if isinstance(record, MemoryRecord)} == {
        "rec-boundary",
        "rec-unparsable",
    }


# ---------------------------------------------------------------------------
# 7. 契约补充用例（fixture 映射表里归 W3 的写入路径用例）
# ---------------------------------------------------------------------------


def test_contract_supplementary_write_cases_match_the_frozen_mapping(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """逐条跑 ``CONTRACT_SUPPLEMENTARY_CASES`` 里的写入路径用例（契约页 §8.4）。

    用例 id 直接取自 ``tests/test_memory_contract.py`` 的冻结映射，改名/删条目会
    在这里红 —— 映射表与服务行为不允许各说各话。

    **M2.2（T15 第 6 处）**：``m2_1_auto_extracted_origin_rejected`` 的冻结结论从
    ``validation_error`` 改为**接受**，因此它从「拒绝」那一组挪到下面的正例段；
    它仍是同一条 id（契约 §6 T15 与 W7b/W7c 都按 id 引用）。
    """

    denied_cases = {
        "m2_1_personal_scope_write_denied": (_candidate(scope="PERSONAL"), AuthorizationError, "scope_not_enabled"),
        "m2_1_safety_scope_write_denied": (_candidate(scope="SAFETY"), AuthorizationError, "scope_not_enabled"),
    }

    for case_id, (candidate, error, reason) in denied_cases.items():
        frozen = CONTRACT_SUPPLEMENTARY_CASES[case_id]
        assert frozen["phase"] == "M2.1", case_id
        assert frozen["outcome"] == reason, case_id

        store.records.clear()
        store.writes.clear()
        with pytest.raises(error) as excinfo:  # type: ignore[misc]
            service.propose(candidate, _source_session())
        assert excinfo.value.decision.reason == reason, case_id
        assert store.writes == [], case_id
        assert store.records == {}, case_id

    accepted_case = "m2_1_auto_extracted_origin_rejected"
    assert CONTRACT_SUPPLEMENTARY_CASES[accepted_case]["outcome"] == "ok", accepted_case
    assert CONTRACT_SUPPLEMENTARY_CASES[accepted_case]["phase"] == "M2.2", accepted_case
    store.records.clear()
    store.writes.clear()
    accepted = service.propose(_candidate(origin="auto_extracted"), _source_session())
    assert accepted is not None, accepted_case
    assert accepted.status == "PENDING_CONFIRMATION", accepted_case


def test_contract_supplementary_read_positives_are_reachable(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """M2.1 可达的 FAMILY 正例（含 ``memory_class="SAFETY"``）必须真的读得到。"""

    for case_id in ("m2_1_family_event_positive", "m2_1_family_safety_class_positive"):
        assert CONTRACT_SUPPLEMENTARY_CASES[case_id]["outcome"] == "ok", case_id

    store.records["sup-family-event"] = _record("sup-family-event", content="周五去露营")
    store.records["sup-family-allergy"] = _record(
        "sup-family-allergy", memory_class="SAFETY", content="对花生过敏"
    )

    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert set(snapshot.record_ids) == {"sup-family-event", "sup-family-allergy"}
    assert snapshot.denied == ()


# ---------------------------------------------------------------------------
# 8. 与真实判权实现的集成（W2 落地前 skip；落地后自动生效）
# ---------------------------------------------------------------------------


def _require_real_policy() -> None:
    """W2 的 ``authorize()`` 未实现时跳过；实现后本组用例自动生效。"""

    try:
        policy.authorize(
            action="read_model",
            access=SessionAccess(),
            grant=None,
            session_id="probe",
            audience_id="family_all",
            records=(),
            now=NOW,
        )
    except NotImplementedError:  # pragma: no cover —— W2 落地后不再走到这里
        pytest.skip("W2 的 policy.authorize 尚未实现：本用例在 W2 落地后自动生效")


def _real_service(store: FakeMemoryStore) -> MemoryService:
    return MemoryService(
        store=store,  # type: ignore[arg-type]
        grants=FakeGrantStore(),  # type: ignore[arg-type]
        clock=FakeClock(),
        retention=FakeRetention(),  # type: ignore[arg-type]
    )


def test_query_integrates_with_the_real_policy_for_the_family_positive() -> None:
    """§8.3 ``approved_family_visible``：``FAMILY`` + 受众命中 + **无 grant** 也能读。"""

    _require_real_policy()
    store = FakeMemoryStore((_record("mem-family-approved", content="合成共享事项"),))

    snapshot = _real_service(store).query(
        SessionAccess(), "session_projection", session_id="session-2", audience_id="family_all", grant=None
    )

    assert snapshot.record_ids == ("mem-family-approved",)
    assert snapshot.denied == ()
    assert "合成共享事项" in render_memory_block(snapshot)


def test_query_denies_personal_scope_with_the_real_policy() -> None:
    """``PERSONAL`` 记录在 M2.1 不可读 —— **无 grant 时报 ``no_grant``**。

    集成裁决（主控）：``DENY_ORDER`` 里 ``no_grant`` 是第 2 位、``scope_not_enabled``
    是第 10 位，而 A5 的无 grant 例外是一张**白名单**（只覆盖 ``read_model`` /
    ``send_provider`` **且**落在家庭共享路径上）。``PERSONAL`` 不在白名单的适用范围内，
    因此在「没有 grant」这一步就被拒 —— 这也是 fixture 的 ``unknown_denied``
    （``scope=PERSONAL`` + ``grant_id=null`` → ``no_grant``，见
    ``FIXTURE_CASE_MAPPING``）冻结的结论。带有效 grant 的 ``scope_not_enabled``
    由写路径（``propose`` / ``confirm_shared``）与 fixture 的 M2.2 正例覆盖。
    """

    _require_real_policy()
    personal = _record("mem-private-a", scope="PERSONAL", audiences=frozenset({"family_all"}))
    store = FakeMemoryStore((personal,), listing_mode="all")

    snapshot = _real_service(store).query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert snapshot.denied == (("mem-private-a", "no_grant"),)


def test_query_denies_an_audience_mismatch_with_the_real_policy() -> None:
    """``FAMILY`` 记录但受众不匹配 → **无 grant 时报 ``no_grant``**。

    集成裁决（主控 / A5）：无 grant 例外是一张白名单，条件之一是
    ``audience_id in record.audiences``。受众不匹配时例外不成立 → 这次调用**需要** grant，
    而没有 grant → ``no_grant``。这是 fail-closed 的读法：无 grant 时把「需要授权」
    如实报成 ``no_grant``，而不是假装成「有 grant 但受众不对」（``scope_denied``）。
    ``scope_denied`` 需要 grant 在场才可达：W4 之后会话可以合法携带
    ``session_owner``（契约 §3.5），那条路径由
    ``tests/test_memory_projection_seam.py::test_an_owner_bound_session_with_a_grant_reaches_scope_denied``
    覆盖（M2.1 的产品路径仍不产出 ``controlled_private`` 会话）。
    """

    _require_real_policy()
    store = FakeMemoryStore((_record("rec-member", audiences=frozenset({"adult_b"})),), listing_mode="all")

    snapshot = _real_service(store).query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.entries == ()
    assert snapshot.denied == (("rec-member", "no_grant"),)


def test_propose_confirm_query_round_trip_with_the_real_policy() -> None:
    """端到端：候选 → 成人确认 → 无 grant 的 FAMILY 投影读得到。"""

    _require_real_policy()
    store = FakeMemoryStore()
    service = _real_service(store)

    candidate = service.propose(_candidate(content="对花生过敏"), _source_session())
    assert candidate is not None
    assert service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    ).entries == (), "候选不可召回"

    confirmed = service.confirm_shared(candidate.id, frozenset({"family_all"}), ADULT)
    snapshot = service.query(
        SessionAccess(), "session_projection", session_id="session-1", audience_id="family_all", grant=None
    )

    assert snapshot.record_ids == (confirmed.id,)
    assert render_memory_block(snapshot) == (
        f"{MEMORY_BLOCK_HEADER}\n- 对花生过敏"
    )


# ---------------------------------------------------------------------------
# 9. M2.2 §4.3：query 的 purpose 决定授权动作；§2.4 T26'：reassign_owner
# ---------------------------------------------------------------------------


def test_query_purpose_decides_the_authorization_action(
    service: MemoryService, store: FakeMemoryStore, authorize_double: FakeAuthorize
) -> None:
    """§4.3：``action`` **由 purpose 决定** —— 前四个是 ``read_model``，
    只有 ``control_plane_review`` 走 ``review_control_plane``。

    调用方只能挑 purpose，不能挑动作；这条用替身记录的真实入参钉死。
    """

    store.records["rec-1"] = _record("rec-1")

    for purpose in ("session_projection", "adult_list", "adult_inspect", "deletion_audit"):
        authorize_double.calls.clear()
        service.query(
            SessionAccess(),
            purpose,  # type: ignore[arg-type]
            session_id="session-1",
            audience_id="family_all",
            grant=None,
        )
        assert [call["action"] for call in authorize_double.calls] == ["read_model"], purpose

    authorize_double.calls.clear()
    snapshot = service.query(
        SessionAccess(),
        "control_plane_review",
        session_id="cli-session",
        audience_id="family_all",
        grant=None,
    )
    assert [call["action"] for call in authorize_double.calls] == ["review_control_plane"]
    assert snapshot.purpose == "control_plane_review"


def test_control_plane_review_carries_content_while_other_purposes_do_not() -> None:
    """§4.3 的「携带正文」白名单与「只有复审 purpose 读得到候选」。

    用**真判权**（不是替身）：候选在其余 purpose 下仍是 ``status_denied`` ——
    这正是 M2.1 的现状，也是 D11 要解的那个问题。控制面访问用**真实构造器**
    ``SessionAccess.for_control_plane()``（W8 落地；W9 当年的 ``ControlPlaneAccess``
    替身与它的工厂已退役，勘误 E7）。
    """

    _require_real_policy()
    store = FakeMemoryStore()
    service = _real_service(store)
    candidate = service.propose(_candidate(content="对花生过敏"), _source_session())
    assert candidate is not None

    review = service.query(
        SessionAccess.for_control_plane(),
        "control_plane_review",
        session_id="cli-session",
        audience_id="family_all",
        grant=None,
    )
    assert review.record_ids == (candidate.id,)
    assert review.entries[0].content == "对花生过敏", "复审必须看到候选正文（否则是盲确认）"
    assert review.denied == ()

    # CLI 的第一步（adult_inspect）看不到候选 —— W8 因此在 status_denied 时追加第二次查询。
    inspect = service.query(
        SessionAccess.for_control_plane(),
        "adult_inspect",
        session_id="cli-session",
        audience_id="family_all",
        grant=None,
    )
    assert inspect.entries == ()
    assert inspect.denied == ((candidate.id, "status_denied"),)

    # 会话路径（shared）**永远**读不到候选 —— 复审动作进不了投影。
    projection = service.query(
        SessionAccess(),
        "session_projection",
        session_id="session-1",
        audience_id="family_all",
        grant=None,
    )
    assert projection.entries == ()
    assert projection.denied == ((candidate.id, "status_denied"),)

    listing = service.query(
        SessionAccess(),
        "adult_list",
        session_id="session-1",
        audience_id="family_all",
        grant=None,
    )
    assert listing.entries == ()
    assert listing.denied == ((candidate.id, "status_denied"),)


def test_reassign_owner_moves_a_candidate_and_bumps_consent(
    service: MemoryService, store: FakeMemoryStore, clock: FakeClock
) -> None:
    """T26'：只对候选、只由成人、``consent_version + 1``、其余字段一律不动。"""

    candidate = _record(
        "rec-candidate",
        status="PENDING_CONFIRMATION",
        memory_policy="candidate_only",
        last_confirmed_at=None,
        owner_id="family_shared",
        content="周五去露营",
        audiences=frozenset({"family_all"}),
        expires_at=CANDIDATE_EXPIRY,
    )
    store.records[candidate.id] = candidate

    updated = service.reassign_owner(candidate.id, "adult_b", actor=ADULT)

    assert updated.owner_id == "adult_b"
    assert updated.consent_version == candidate.consent_version + 1
    assert updated.updated_at == clock.value
    assert (updated.actor_kind, updated.actor_id) == ("adult_control_plane", ADULT.actor_id)
    # **不碰别的**：内容 / 重要度 / 受众 / scope / 来源 / 类别 / 期限 / 状态。
    for field in (
        "content",
        "importance",
        "audiences",
        "scope",
        "source_type",
        "source_member_id",
        "memory_class",
        "expires_at",
        "last_confirmed_at",
        "status",
        "memory_policy",
    ):
        assert getattr(updated, field) == getattr(candidate, field), field
    assert store.writes[-1][0].owner_id == "adult_b"
    assert store.writes[-1][1] == ADULT


@pytest.mark.parametrize(
    "status",
    ["ACTIVE", "DECAYED", "DELETED"],
)
def test_reassign_owner_rejects_every_non_candidate(
    service: MemoryService, store: FakeMemoryStore, status: str
) -> None:
    """归属**定型后不可改**（M2.1 不变量）：非候选一律 ``IllegalTransition``，零写入。"""

    overrides: dict[str, object] = {"status": status}
    if status == "DELETED":
        overrides["content"] = ""
        overrides["memory_policy"] = "persist_confirmed"
    record = _record("rec-1", **overrides)
    store.records[record.id] = record
    writes_before = list(store.writes)

    with pytest.raises(IllegalTransition) as excinfo:
        service.reassign_owner(record.id, "adult_b", actor=ADULT)

    assert excinfo.value.from_status == status
    assert excinfo.value.to_status == "PENDING_CONFIRMATION"
    assert store.writes == writes_before, "被拒的归属变更不得写任何行"


def test_reassign_owner_is_adult_only(service: MemoryService, store: FakeMemoryStore) -> None:
    """§2.4：``M2_1_WRITE_GATE["reassign_owner"] = {"adult_control_plane"}``。"""

    record = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", memory_policy="candidate_only",
        last_confirmed_at=None,
    )
    store.records[record.id] = record

    for actor in (TTL, MIGRATION, Actor(kind="session_proposal", actor_id="session-1")):
        before = record.owner_id
        with pytest.raises(MemoryValidationError):
            service.reassign_owner(record.id, "adult_b", actor=actor)
        assert store.records[record.id].owner_id == before, actor.kind


@pytest.mark.parametrize("owner", ["family_shared", "", "   "])
def test_reassign_owner_rejects_reserved_and_empty_owner_ids(
    service: MemoryService, store: FakeMemoryStore, owner: str
) -> None:
    """保留 id 与非空校验：写回 ``family_shared`` 是无意义操作（且会让归属重新不可知）。"""

    record = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", memory_policy="candidate_only",
        last_confirmed_at=None, owner_id="family_shared",
    )
    store.records[record.id] = record
    writes_before = list(store.writes)

    with pytest.raises(MemoryValidationError):
        service.reassign_owner(record.id, owner, actor=ADULT)
    assert store.writes == writes_before


def test_reassign_owner_requires_an_existing_record(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    with pytest.raises(RecordNotFound):
        service.reassign_owner("rec-missing", "adult_b", actor=ADULT)


def test_reassign_owner_then_confirm_is_the_cli_two_step(service: MemoryService, store: FakeMemoryStore) -> None:
    """§2.4 的 CLI 用法：**先** ``reassign_owner``（候选态）**再** ``confirm_shared``。

    两步各自写一次、各自受 actor 门约束；前一步失败就不执行后一步（不做「半个确认」）。
    """

    record = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", memory_policy="candidate_only",
        last_confirmed_at=None, owner_id="family_shared",
    )
    store.records[record.id] = record

    moved = service.reassign_owner(record.id, "child", actor=ADULT)
    confirmed = service.confirm_shared(moved.id, frozenset({"family_all"}), ADULT)

    assert confirmed.owner_id == "child"
    assert confirmed.status == "ACTIVE"
    assert confirmed.consent_version == record.consent_version + 2, "两次写各自递增一次"
    assert confirmed.content == record.content, "归属变更不影响正文"


def test_confirm_shared_with_owner_reassign_is_one_write(
    service: MemoryService, store: FakeMemoryStore, clock: FakeClock
) -> None:
    """M2.3 §7.5 第 6 项：CLI 的改归属 + 确认共享合并成**一次** ``write_record``。

    产物与两步写法完全一致（``owner`` / ``status`` / ``consent_version``），但落库只有
    一次写入 —— 因此不存在「归属已改、确认未完成」的可失败中间点。
    """

    record = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", memory_policy="candidate_only",
        last_confirmed_at=None, owner_id="family_shared",
    )
    store.records[record.id] = record

    updated = service.confirm_shared_with_owner_reassign(
        record.id, frozenset({"family_all"}), "child", actor=ADULT
    )

    assert [call[0] for call in store.calls].count("write_record") == 1, "一个事务，一次写"
    assert len(store.writes) == 1
    assert store.writes[0][0] is updated
    assert store.writes[0][1] == ADULT
    assert updated.owner_id == "child"
    assert updated.status == "ACTIVE"
    assert updated.memory_policy == "persist_confirmed"
    assert updated.last_confirmed_at == clock.value
    assert updated.updated_at == clock.value
    assert updated.consent_version == record.consent_version + 2, "改归属 +1 与确认 +1 合并递增"
    assert updated.content == record.content, "归属变更不影响正文"
    assert updated.audiences == frozenset({"family_all"})


def test_confirm_shared_with_owner_reassign_writes_nothing_when_the_store_fails(
    service: MemoryService, store: FakeMemoryStore
) -> None:
    """那次唯一的写入失败 ⇒ **一行不留**（服务层不做补偿写，也不吞异常）。"""

    record = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", memory_policy="candidate_only",
        last_confirmed_at=None, owner_id="family_shared",
    )
    store.records[record.id] = record
    store.failures["write_record"] = StoreError("injected: disk I/O error")

    with pytest.raises(StoreError):
        service.confirm_shared_with_owner_reassign(
            record.id, frozenset({"family_all"}), "child", actor=ADULT
        )

    assert store.writes == [], "失败后不得留下任何写入"
    assert store.records[record.id] == record, "归属 / 状态 / 同意版本全部保持原值"


@pytest.mark.parametrize("kind", ["session_proposal", "ttl_expiry", "migration"])
def test_confirm_shared_with_owner_reassign_is_adult_only(
    service: MemoryService, store: FakeMemoryStore, kind: str
) -> None:
    """两道 actor 门（``reassign_owner`` / ``confirm_shared``）都只放成人。"""

    record = _record(
        "rec-candidate", status="PENDING_CONFIRMATION", memory_policy="candidate_only",
        last_confirmed_at=None,
    )
    store.records[record.id] = record

    with pytest.raises(MemoryValidationError):
        service.confirm_shared_with_owner_reassign(
            record.id,
            frozenset({"family_all"}),
            "child",
            actor=Actor(kind=kind, actor_id="someone"),  # type: ignore[arg-type]
        )
    assert store.writes == [], "被拒的合并写不得写任何行"
