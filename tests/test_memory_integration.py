"""M2.1 端到端集成测试（集成者）。

**这个文件是三方接口对齐的证据**：它不替换任何替身，用真实的

- ``SqliteMemoryStore(db_path)``（W1，真实 sqlite 文件 + 真实 schema + 真实血缘）
- ``SqliteGrantStore(db_path)``（W2，真实 grant 表）
- ``MemoryService(store, grants, clock, retention)``（W3，真实五接口）
- ``policy.authorize()``（W2，真实判权）
- ``render_memory_block()``（W3，真实渲染）

在 ``tmp_path`` 上的临时数据库里跑完整链路。**全程离线**（仓库级 ``tests/conftest.py``
的守门生效：清代理 + 拦截非 loopback 连接），无 live 调用、不读写仓库内 ``data/``。

覆盖四块：

1. **fixture 七个 case 端到端**（``test_fixture_case_*``）—— 用契约 §8.1 的
   **记录补齐规则**与 §8.2 的**归一化登记**把 ``docs/fixtures/m2-memory-policy.synthetic.json``
   落进真实库，逐条跑 ``service.query()``，与 ``FIXTURE_CASE_MAPPING`` 的
   ``m2_1_reason`` / 预期 ids 对照。
2. **D5 TTL**（``test_ttl_*``）—— EVENT 到期转 ``DECAYED``（不删盘）、候选 7 天到期
   **硬删除 + 写 ``deletion_audit``**、``memory_class="SAFETY"`` 确认后不过期、
   ``SAFETY`` 类**候选**仍受 7 天约束。
3. **删除与审计**（``test_delete_*``）—— 磁盘删除、审计行、A2 血缘口径
   （派生记录不连带删、靠 ``missing_provenance`` 永久 fail-closed）。
4. **投影接缝**（``test_projection_seam_*``）—— §10.1 的 ``read_model`` +
   ``send_provider`` 两次授权与真实渲染，含「空快照 → 空字符串」的 G1 回归护栏。

**W4 已落地**（§3.5 + §10.1 已合入本分支）：``SessionAccess`` 现在允许带
``authorization_ref`` 的 ``session_owner`` 绑定，因此 fixture 的
``authorized_owner_positive`` / ``wrong_owner_denied`` 两条依赖 owner 比较的 case
走得到契约预期的分支 —— 前者停在相位门 ``scope_not_enabled``（M2.1 不召回
PERSONAL），后者停在 ``wrong_owner``。判权输入仍全部来自真实存储。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soul_memory_kernel.memory.grants import SqliteGrantStore, load_grant_for_session
from soul_memory_kernel.memory.model import (
    Actor,
    Grant,
    MemoryCandidate,
    MemoryCorrection,
    MemoryRecord,
    RetentionPolicy,
    SourceSession,
)
from soul_memory_kernel.memory.policy import authorize
from soul_memory_kernel.memory.projection import render_memory_block
from soul_memory_kernel.memory.service import MemoryService
from soul_memory_kernel.memory.store import MAX_GRANT_TTL_SECONDS, SqliteMemoryStore
from soul_memory_kernel.soul.core import project_session_memory
from soul_memory_kernel.soul.policy import SessionAccess
from tests.test_memory_contract import (
    FIXTURE_CASE_MAPPING,
    FIXTURE_NORMALIZATIONS,
    FIXTURE_RECORD_COMPLETION,
    FIXTURE_RECORD_FIELD_MAP,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "m2-memory-policy.synthetic.json"

EVALUATE_AT = "2026-09-24T12:00:00Z"
ADULT = Actor(kind="adult_control_plane", actor_id="cli:adult")
TTL_ACTOR = Actor(kind="ttl_expiry", actor_id="ttl:sweeper")


class MutableClock:
    """可控 ISO-8601 UTC 时钟 —— D5 的 TTL 以「天」为单位，必须能时间旅行。"""

    def __init__(self, value: str = "2026-09-26T12:00:00Z") -> None:
        self.value = value

    def __call__(self) -> str:
        return self.value

    def advance_days(self, days: int) -> None:
        current = datetime.fromisoformat(self.value.replace("Z", "+00:00"))
        self.value = (current + timedelta(days=days)).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")


class Env:
    """一个临时库上的完整真实栈。"""

    def __init__(self, db_path: Path, clock: MutableClock) -> None:
        self.db_path = db_path
        self.clock = clock
        self.store = SqliteMemoryStore(db_path)
        # B-s1：issue() 会拒绝「还没到签发时刻」的 grant，因此把可控时钟也注入 grant
        # store —— 否则测试里那些 2026-09 的 grant 相对真实系统时刻永远是未来。
        self.grants = SqliteGrantStore(db_path, clock=clock)
        self.store.create_schema()
        self.service = MemoryService(
            store=self.store,
            grants=self.grants,
            clock=clock,
            retention=RetentionPolicy(),
        )

    def raw(self, sql: str, params: tuple = ()) -> list[tuple]:
        with sqlite3.connect(self.db_path) as db:
            return db.execute(sql, params).fetchall()

    def count(self, table: str) -> int:
        return self.raw(f"SELECT COUNT(*) FROM {table}")[0][0]

    def propose_family(self, content: str, memory_class: str, *, session_id: str = "sess-1"):
        return self.service.propose(
            MemoryCandidate(
                content=content,
                scope="FAMILY",
                memory_class=memory_class,
                owner_id="adult_a",
                source_type="explicit_user",
                source_member_id="child",
                confidence=1.0,
                importance=0.6,
                audiences=frozenset({"family_all"}),
            ),
            SourceSession(
                session_id=session_id,
                owner_id="adult_a",
                audience_id="family_all",
                session_mode="shared",
                identity_assurance="unknown",
                grant_id=None,
            ),
        )


@pytest.fixture(name="env")
def env_fixture(tmp_path: Path) -> Env:
    return Env(tmp_path / "memory.sqlite3", MutableClock())


# ---------------------------------------------------------------------------
# fixture → 真实库（§8.1 补齐规则 + §8.2 归一化登记）
# ---------------------------------------------------------------------------


def _fixture_doc() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _completed_records(doc: dict) -> tuple[MemoryRecord, ...]:
    """按契约 §8.1 / §8.2 把 fixture 记录补成完整 ``MemoryRecord``。

    这是**纯数据变换**，规则逐条来自契约：
    ``FIXTURE_RECORD_COMPLETION``（常量字段）、``FIXTURE_COMPLETION_RULES``（时间戳与
    期限）、``FIXTURE_NORMALIZATIONS``（两条登记过的归一化）。W2/W3 不需要另发明取值。
    """

    days = {
        "EVENT": RetentionPolicy().days_for("EVENT", is_candidate=False),
        "PREFERENCE": RetentionPolicy().days_for("PREFERENCE", is_candidate=False),
    }
    records: list[MemoryRecord] = []
    for raw in doc["records"]:
        policy = raw["memory_policy"]
        # 归一化 1：mem-family-unapproved 的 ACTIVE + candidate_only → 候选。
        status = "PENDING_CONFIRMATION" if policy == "candidate_only" else raw["status"]
        # 归一化 2：墓碑行不带正文。
        content = "" if status == "DELETED" else raw["content"]
        audiences = (
            frozenset({"family_all"}) if raw.get("shared_approved", False) else frozenset()
        )
        memory_class = "EVENT"
        if memory_class == "SAFETY" and status in {"ACTIVE", "DECAYED"}:
            expires_at = None
        elif status == "PENDING_CONFIRMATION":
            expires_at = "2026-10-01T12:00:00Z"  # evaluate_at + candidate_days
        else:
            expires_at = "2026-10-24T12:00:00Z"  # evaluate_at + event_days
        records.append(
            MemoryRecord(
                id=raw["id"],
                owner_id=raw["owner_id"],
                scope=raw["scope"],
                memory_class=memory_class,
                source_type="explicit_user",
                source_member_id=raw["owner_id"],
                content=content,
                confidence=1.0,
                importance=0.5,
                created_at=EVALUATE_AT,
                updated_at=EVALUATE_AT,
                last_confirmed_at=EVALUATE_AT if status == "ACTIVE" else None,
                expires_at=expires_at,
                source_session_id=None,
                status=status,
                memory_policy=policy,
                audiences=audiences,
                consent_version=1,
                source_ids=(),
            )
        )
    assert {r.id for r in records} == {r["id"] for r in doc["records"]}
    return tuple(records)


def _minus_seconds(timestamp: str, seconds: int) -> str:
    moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) - timedelta(seconds=seconds)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def _fixture_grant(doc: dict, grant_id: str) -> Grant:
    """按契约 §8.1 的「最小授权补齐」把 fixture 的 grant 补成完整 ``Grant``。"""

    raw = next(g for g in doc["fixture_grants"] if g["id"] == grant_id)
    active_of_owner = tuple(
        r["id"]
        for r in doc["records"]
        if r["owner_id"] == raw["owner_id"] and r["status"] == "ACTIVE"
    )
    return Grant(
        grant_id=raw["id"],
        version=1,
        session_id=raw["session_id"],
        subject_id=raw["owner_id"],
        owner_id=raw["owner_id"],
        audience_id="family_all",
        actions=frozenset({"read_model"}),
        resource_ids=frozenset(active_of_owner),
        consent_versions=tuple((record_id, 1) for record_id in active_of_owner),
        expires_at=raw["expires_at"],
        issuer=raw["issuer"],
        # §8.1（r3.1）：从到期时刻往回推一个上限窗口 —— ``issued_at = evaluate_at``
        # 会让已经过期的 grant 得到负 TTL，真实 store 必然拒绝。
        issued_at=_minus_seconds(raw["expires_at"], MAX_GRANT_TTL_SECONDS),
    )


@pytest.fixture(name="seeded")
def seeded_fixture(tmp_path: Path) -> tuple[Env, dict]:
    """把 fixture 的 5 条记录与 2 个 grant 落进真实库。"""

    doc = _fixture_doc()
    clock = MutableClock(EVALUATE_AT)
    env = Env(tmp_path / "fixture.sqlite3", clock)
    for record in _completed_records(doc):
        env.store.write_record(record, actor=ADULT)
    for raw_grant in doc["fixture_grants"]:
        env.grants.issue(_fixture_grant(doc, raw_grant["id"]))
    return env, doc


#: 每个 fixture case **作用在哪些记录上**。
#:
#: 由 case 的 ``query_scope`` 与 fixture 记录表推出（见
#: ``test_fixture_case_record_targets_match_their_query_scope`` 的交叉核对）：
#: ``PERSONAL`` 取 ``adult_a`` 的私人记录 ``mem-private-a``，``FAMILY`` 取已确认
#: 共享的 ``mem-family-approved``。fixture 没有直接给出这层映射，所以在这里显式写死
#: 并用一致性用例锁住，而不是让每条 case 自己发明。
FIXTURE_CASE_RECORDS: dict[str, tuple[str, ...]] = {
    "authorized_owner_positive": ("mem-private-a",),
    "unknown_denied": ("mem-private-a",),
    "self_claim_denied": ("mem-private-a",),
    "wrong_owner_denied": ("mem-private-a",),
    "expired_grant_denied": ("mem-private-a",),
    "new_session_without_grant_denied": ("mem-private-a",),
    "approved_family_visible": ("mem-family-approved",),
}


def _run_fixture_case(
    env: Env, doc: dict, case: dict
) -> tuple[str, tuple[str, ...]]:
    """把一个 fixture case 跑成一次真实的 ``authorize()`` 判定。

    返回 ``(reason, allowed_ids)``。**判权输入全部来自真实存储**：记录经
    ``store.read_record()`` 读出（含受众与血缘），grant 经
    ``grants.load_current()`` 读出。只有 ``access`` 是构造的 —— **W4 之后它按 fixture
    声明的 ``session_owner`` 构造**：owner 绑定必须带控制面 ``authorization_ref``
    （契约 §3.5），因此带 owner 的 case 现在走得到它们冻结的那一步
    （``authorized_owner_positive`` 走得到 ``scope_not_enabled``；
    ``wrong_owner_denied`` 照旧停在 ``wrong_owner``）。
    """

    grant = (
        env.grants.load_current(case["grant_id"]) if case["grant_id"] is not None else None
    )
    records = tuple(env.store.read_record(rid) for rid in FIXTURE_CASE_RECORDS[case["id"]])
    assert all(record is not None for record in records)
    if case["session_owner"] is None:
        access = SessionAccess(speaker_claim=case["speaker_claim"])
    else:
        # ``controlled_private`` 是 fixture 为 owner 绑定声明的会话模式；M2.1 的产品
        # 路径不产出它（§3.6），这里表达的是「该 case 声明的控制面状态」。
        access = SessionAccess(
            session_mode="controlled_private",
            session_owner=case["session_owner"],
            authorization_ref=f"ctl:fixture:{case['id']}",
            speaker_claim=case["speaker_claim"],
        )
    decision = authorize(
        action="read_model",
        access=access,
        grant=grant,
        session_id=case["session_id"],
        audience_id="family_all",
        records=records,
        now=env.clock(),
    )
    return decision.reason, tuple(r.id for r in records) if decision.allowed else ()


# ---------------------------------------------------------------------------
# 1. fixture 七个 case
# ---------------------------------------------------------------------------


def test_fixture_is_seeded_into_a_real_database(seeded: tuple[Env, dict]) -> None:
    """五条记录 + 两个 grant 真的落到了 sqlite 里（不是内存替身）。"""

    env, doc = seeded
    assert env.count("memory_record") == len(doc["records"]) == 5
    assert env.count("grant_record") == len(doc["fixture_grants"]) == 2
    # 归一化 1：mem-family-unapproved 落库时已是候选。
    status, = env.raw("SELECT status FROM memory_record WHERE id = 'mem-family-unapproved'")[0]
    assert status == "PENDING_CONFIRMATION"
    # 归一化 2：墓碑行不带正文（否则 DDL 的 CHECK 会拒绝写入）。
    content, = env.raw("SELECT content FROM memory_record WHERE id = 'mem-deleted'")[0]
    assert content == ""


def test_fixture_normalizations_are_actually_applied(seeded: tuple[Env, dict]) -> None:
    """两条归一化登记都必须真的生效（fixture 原文与契约不变量冲突之处）。"""

    env, doc = seeded
    raw = {r["id"]: r for r in doc["records"]}
    assert raw["mem-family-unapproved"]["status"] == "ACTIVE", "fixture 原文如此"
    assert raw["mem-deleted"]["content"] != "", "fixture 原文带正文"
    assert set(FIXTURE_NORMALIZATIONS) >= {
        "mem-family-unapproved_status",
        "mem-deleted_content",
    }
    assert env.store.read_record("mem-family-unapproved").status == "PENDING_CONFIRMATION"
    assert env.store.read_record("mem-deleted").content == ""


@pytest.mark.parametrize(
    "case_id",
    [
        # 注意：authorized_owner_positive 不在这里 —— 它的 ``expected_ids`` 是 fixture
        # 自己声明的 **M2.2** 结论（``("mem-private-a",)``），与 M2.1 的 ``[]`` 不同，
        # 无法用同一行断言表达。W4 之后它由
        # ``test_fixture_authorized_owner_positive_now_reaches_the_phase_gate`` 专测：
        # reason 收紧为冻结的 ``m2_1_reason``。
        "unknown_denied",
        "self_claim_denied",
        "wrong_owner_denied",
        "expired_grant_denied",
        "new_session_without_grant_denied",
        "approved_family_visible",
    ],
)
def test_fixture_case_matches_the_frozen_m2_1_mapping(
    seeded: tuple[Env, dict], case_id: str
) -> None:
    """七条 fixture case 逐条跑**真实判权**，与契约 §8.3 的 ``m2_1_reason`` 对照。"""

    env, doc = seeded
    case = next(c for c in doc["cases"] if c["id"] == case_id)
    row = FIXTURE_CASE_MAPPING[case_id]

    reason, allowed_ids = _run_fixture_case(env, doc, case)

    assert reason == row["m2_1_reason"]
    assert allowed_ids == tuple(row["expected_ids"])


def test_fixture_case_record_targets_match_their_query_scope(seeded: tuple[Env, dict]) -> None:
    """``FIXTURE_CASE_RECORDS`` 不是手写的：逐条核对它确实符合 fixture 的 ``query_scope``。"""

    env, doc = seeded
    scope_of = {r["id"]: r["scope"] for r in doc["records"]}
    owner_of = {r["id"]: r["owner_id"] for r in doc["records"]}
    assert set(FIXTURE_CASE_RECORDS) == {c["id"] for c in doc["cases"]}, "每个 case 都要有目标"

    grants = {g["id"]: g for g in doc["fixture_grants"]}
    for case in doc["cases"]:
        for record_id in FIXTURE_CASE_RECORDS[case["id"]]:
            assert scope_of[record_id] == case["query_scope"], case["id"]
            # owner 只在**没有** grant 时才必须与声明的 session_owner 一致：
            # wrong_owner_denied 的目标记录刻意属于别人（这正是它要测的东西），
            # authorized_owner_positive 则带着 owner 匹配的 grant。
            if case["grant_id"] is None and case["session_owner"] is not None:
                assert owner_of[record_id] == case["session_owner"], case["id"]
            if case["grant_id"] is not None:
                assert owner_of[record_id] == grants[case["grant_id"]]["owner_id"], case["id"]


def test_fixture_approved_family_visible_needs_no_grant(seeded: tuple[Env, dict]) -> None:
    """§8.3：``FAMILY`` + 受众命中 + **无 grant** 也能读 —— A5 例外的正例。"""

    env, doc = seeded
    case = next(c for c in doc["cases"] if c["id"] == "approved_family_visible")
    assert case["grant_id"] is None

    reason, allowed_ids = _run_fixture_case(env, doc, case)

    assert (reason, allowed_ids) == ("ok", ("mem-family-approved",))


def test_fixture_self_claim_is_not_an_authorization_input(seeded: tuple[Env, dict]) -> None:
    """``speaker_claim`` 不是判权输入：换成别的名字，结论逐字节不变。"""

    env, doc = seeded
    case = next(c for c in doc["cases"] if c["id"] == "self_claim_denied")

    baseline = _run_fixture_case(env, doc, case)
    for claim in ("adult_b", "孩子", "", None):
        assert _run_fixture_case(env, doc, dict(case, speaker_claim=claim)) == baseline, claim


def test_fixture_authorized_owner_positive_now_reaches_the_phase_gate(
    seeded: tuple[Env, dict],
) -> None:
    """fixture 唯一的 PERSONAL 正例：**grant 段整段通过**，被 M2.1 相位门拦下。

    W4 之后会话可以合法携带 ``session_owner``（契约 §3.5：owner 必须配控制面
    ``authorization_ref``），因此该 case 带着 ``grant-a-s1``（``owner_id="adult_a"``）
    不再停在 ``wrong_owner`` —— 它走完 grant 段（会话 / owner / 受众 / 动作 / 资源 /
    同意版本全部匹配），最后被 ``scope_not_enabled``（DENY_ORDER 第 11 位）拒绝。

    这条同时是 W4 的**收紧证据**：reason 从「应用没有 owner 绑定」变成
    「M2.1 相位不允许 PERSONAL」，与合同 §8.3 冻结的 ``m2_1_reason`` 一致。
    """

    env, doc = seeded
    case = next(c for c in doc["cases"] if c["id"] == "authorized_owner_positive")
    row = FIXTURE_CASE_MAPPING["authorized_owner_positive"]
    assert row["phase"] == "M2.2", "该正例冻结为 M2.2 用例"
    assert row["m2_1_reason"] == "scope_not_enabled"

    reason, allowed_ids = _run_fixture_case(env, doc, case)

    assert reason != "ok", "不变量：PERSONAL 在 M2.1 不可召回"
    assert allowed_ids == ()
    assert reason == "scope_not_enabled", "owner 绑定成立后，拦下它的是相位门而不是 wrong_owner"


def test_fixture_query_path_never_recalls_personal_or_candidates(seeded: tuple[Env, dict]) -> None:
    """整栈 ``query()`` 层面的不变量：PERSONAL / 候选 / 墓碑一律不出现。"""

    env, doc = seeded
    for case in doc["cases"]:
        grant = (
            env.grants.load_current(case["grant_id"]) if case["grant_id"] is not None else None
        )
        snapshot = env.service.query(
            SessionAccess(speaker_claim=case["speaker_claim"]),
            "session_projection",
            session_id=case["session_id"],
            audience_id="family_all",
            grant=grant,
        )
        recalled = {entry.record_id for entry in snapshot.entries}
        assert "mem-private-a" not in recalled, case["id"]
        assert "mem-private-b" not in recalled, case["id"]
        assert "mem-family-unapproved" not in recalled, case["id"]
        assert "mem-deleted" not in recalled, case["id"]


def test_m2_1_reachable_positive_is_non_empty_end_to_end(seeded: tuple[Env, dict]) -> None:
    """防作弊：真实栈上至少有一条 fixture case **确实被放行**（不是全拒绝）。"""

    env, doc = seeded
    positives = [
        case["id"]
        for case in doc["cases"]
        if _run_fixture_case(env, doc, case)[0] == "ok"
    ]
    assert positives == ["approved_family_visible"]


def test_fixture_record_field_map_still_covers_the_fixture() -> None:
    """补齐规则的输入契约没漂：fixture 的每个记录字段都还在映射表里。"""

    doc = _fixture_doc()
    for record in doc["records"]:
        assert set(record) <= set(FIXTURE_RECORD_FIELD_MAP)
    assert set(FIXTURE_RECORD_COMPLETION) >= {"memory_class", "source_type", "confidence"}


# ---------------------------------------------------------------------------
# 2. D5 TTL
# ---------------------------------------------------------------------------


def test_ttl_confirmed_event_decays_without_deleting_content(env: Env) -> None:
    """D5 第 1 条：``ACTIVE`` 到期 → ``DECAYED``，**停止召回但不删盘**。"""

    record = env.propose_family("孩子明天要竞选班长", "EVENT")
    confirmed = env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    assert confirmed.status == "ACTIVE"
    assert confirmed.expires_at is not None, "非 SAFETY 类确认后仍有期限"

    env.clock.advance_days(400)
    results = env.service.sweep_expired(TTL_ACTOR)

    assert [type(r).__name__ for r in results] == ["MemoryRecord"]
    after = env.store.read_record(record.id)
    assert after is not None, "DECAYED 不删盘"
    assert after.status == "DECAYED"
    assert after.content == "孩子明天要竞选班长", "正文仍在盘上，删不删由成人决定"
    assert env.count("deletion_audit") == 0, "DECAYED 不是删除，不写审计"


def test_ttl_decayed_record_is_no_longer_recallable(env: Env) -> None:
    """``DECAYED`` 不可召回 —— 而且**不依赖 sweep 是否跑过**（到期实时排除）。"""

    record = env.propose_family("到期前可读", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    env.clock.advance_days(400)

    # 先不 sweep：query 自己按 expires_at <= now 排除。
    before_sweep = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert before_sweep.entries == ()
    assert before_sweep.denied == ((record.id, "record_expired"),), "排除留痕（主控 2026-09-26）"

    env.service.sweep_expired(TTL_ACTOR)
    after_sweep = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert after_sweep.entries == ()


def test_ttl_candidate_expires_to_hard_delete_with_audit(env: Env) -> None:
    """D5 第 2 条：候选到期 **硬删除 + 写 ``deletion_audit``**，不是状态翻转。"""

    candidate = env.propose_family("没被确认的草稿", "EVENT")
    assert candidate.status == "PENDING_CONFIRMATION"
    assert env.count("memory_record") == 1

    env.clock.advance_days(8)  # 候选期 7 天
    results = env.service.sweep_expired(TTL_ACTOR)

    assert [type(r).__name__ for r in results] == ["DeletionReport"]
    report = results[0]
    assert report.record_ids == (candidate.id,)
    assert env.store.read_record(candidate.id) is None, "硬删除：行消失，不是标记"
    assert env.count("memory_record") == 0
    assert report.derived_removed == ()
    assert report.unknown_copies, "禁止填 0 冒充完整"

    audits = env.raw(
        "SELECT record_id, actor_kind, derived_removed FROM deletion_audit WHERE record_id = ?",
        (candidate.id,),
    )
    assert len(audits) == 1, "候选硬删除必须留审计行"
    assert audits[0][0] == candidate.id
    assert audits[0][1] == "ttl_expiry"
    # 审计表只存 id 与计数，绝不存正文。
    assert candidate.content not in str(audits)


def test_ttl_candidate_period_applies_to_safety_class_too(env: Env) -> None:
    """**SAFETY 类的候选同样受 7 天候选期约束**（只有已确认的才不过期）。"""

    candidate = env.propose_family("孩子对花生过敏（未确认）", "SAFETY")
    assert candidate.expires_at is not None, "候选一律有期限，SAFETY 类也不例外"
    assert candidate.memory_class == "SAFETY"

    env.clock.advance_days(8)
    env.service.sweep_expired(TTL_ACTOR)

    assert env.store.read_record(candidate.id) is None, "SAFETY 类候选照样硬删"
    assert env.count("deletion_audit") == 1


def test_ttl_confirmed_safety_class_never_expires(env: Env) -> None:
    """D5：``memory_class="SAFETY"`` **确认后** ``expires_at IS NULL``，永不到期。"""

    record = env.propose_family("孩子对花生过敏", "SAFETY")
    confirmed = env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)

    assert confirmed.status == "ACTIVE"
    assert confirmed.expires_at is None, "确认后的 SAFETY 类不过期（D5 硬不变量）"

    env.clock.advance_days(3650)
    assert env.service.sweep_expired(TTL_ACTOR) == ()
    after = env.store.read_record(record.id)
    assert after.status == "ACTIVE"
    assert after.expires_at is None

    snapshot = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert [e.record_id for e in snapshot.entries] == [record.id], "十年后仍可召回"


def test_ttl_confirmed_safety_class_never_decays_even_at_year_ten(env: Env) -> None:
    """上限不只是「不过期」：它压根不在 ``list_expired`` 的结果里。"""

    record = env.propose_family("过敏原：花生", "SAFETY")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)

    env.clock.advance_days(3650)
    assert env.store.list_expired(now=env.clock()) == ()


def test_ttl_sweep_is_not_a_correctness_dependency(env: Env) -> None:
    """``sweep_expired()`` 从不调用也不会让到期记录被召回。"""

    record = env.propose_family("会过期的普通事件", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    env.clock.advance_days(400)

    snapshot = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert snapshot.entries == ()
    assert env.store.read_record(record.id).status == "ACTIVE", "没 sweep 就还是 ACTIVE"


def test_ttl_sweep_requires_the_ttl_actor(env: Env) -> None:
    """§3.7 actor 门：只有 ``ttl_expiry`` 能触发到期动作。"""

    from soul_memory_kernel.memory.service import MemoryValidationError

    env.propose_family("草稿", "EVENT")
    env.clock.advance_days(8)

    for actor in (ADULT, Actor(kind="migration", actor_id="mig")):
        with pytest.raises(MemoryValidationError):
            env.service.sweep_expired(actor)
    assert env.count("memory_record") == 1, "被拒的 sweep 不得改动任何行"


# ---------------------------------------------------------------------------
# 3. 删除与审计
# ---------------------------------------------------------------------------


def test_delete_removes_rows_from_disk_and_writes_audit(env: Env) -> None:
    """``delete()`` 是**磁盘删除**：行消失 + 审计行 + 报告不含正文。"""

    record = env.propose_family("要删掉的共享记忆", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)

    report = env.service.delete(record.id, ADULT)

    assert report.record_ids == (record.id,)
    assert env.store.read_record(record.id) is None
    assert env.count("memory_record") == 0
    assert env.count("memory_audience") == 0, "受众行随记录一起清掉"
    # tables_touched 只列**实际触及**的表；本条没有 grant，所以不含 grant_resource
    # （有 grant 的情形见 test_delete_clears_grant_resource_rows）。
    assert "memory_record" in report.tables_touched
    assert "memory_audience" in report.tables_touched
    assert report.audit_id, "audit_id 来自 store.write_deletion_audit"
    assert report.unknown_copies, "禁止填 0 冒充完整"
    assert "provider" in " ".join(report.unknown_copies)

    audits = env.raw("SELECT audit_id, actor_kind, actor_id FROM deletion_audit")
    assert audits == [(report.audit_id, "adult_control_plane", "cli:adult")]
    # 审计表不得携带正文。
    assert record.content not in str(env.raw("SELECT * FROM deletion_audit"))


def test_delete_clears_grant_resource_rows(env: Env) -> None:
    """§7.1 第 4 项：``grant_resource`` 无外键、无级联，必须显式删。"""

    record = env.service.propose(
        MemoryCandidate(
            content="被授权覆盖的记忆",
            scope="FAMILY",
            memory_class="EVENT",
            owner_id="adult_a",
            source_type="explicit_user",
            source_member_id="child",
            confidence=1.0,
            importance=0.5,
            audiences=frozenset({"family_all"}),
        ),
        SourceSession(
            session_id="sess-1",
            owner_id="adult_a",
            audience_id="family_all",
            session_mode="shared",
            identity_assurance="unknown",
            grant_id=None,
        ),
    )
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    env.grants.issue(
        Grant(
            grant_id="g-1",
            version=1,
            session_id="sess-9",
            subject_id="adult_a",
            owner_id="adult_a",
            audience_id="family_all",
            actions=frozenset({"read_model"}),
            resource_ids=frozenset({record.id}),
            consent_versions=((record.id, 2),),
            expires_at="2026-09-26T13:00:00Z",
            issuer="local_control_plane",
            issued_at="2026-09-26T12:00:00Z",
        )
    )
    assert env.count("grant_resource") == 1

    env.service.delete(record.id, ADULT)

    assert env.count("grant_resource") == 0, "被删 id 不得留在授权表里"


def test_delete_keeps_inbound_provenance_and_fails_closed(env: Env) -> None:
    """A2 血缘口径：删来源 → 派生记录**仍在盘上**，但永久不可召回。"""

    source = env.propose_family("源记忆", "EVENT")
    env.service.confirm_shared(source.id, frozenset({"family_all"}), ADULT)
    derived = replace(
        env.store.read_record(source.id),
        id="mem-derived-0001",
        content="派生摘要",
        source_ids=(source.id,),
    )
    env.store.write_record(derived, actor=ADULT)

    before = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert set(e.record_id for e in before.entries) == {source.id, derived.id}

    report = env.service.delete(source.id, ADULT)

    # A2：派生记录不连带删除，只报告。
    assert report.derived_removed == ()
    assert report.derived_unreachable == (derived.id,)
    assert env.store.read_record(derived.id) is not None, "派生记录仍在盘上"

    after = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert after.entries == (), "派生记录永久不可召回"
    assert after.denied == ((derived.id, "missing_provenance"),)
    # 血缘行保留 —— 这是「曾经有祖先」的证据，也是 fail-closed 判定的依据。
    assert env.count("memory_source") == 1


def test_delete_requires_the_adult_control_plane(env: Env) -> None:
    """§3.7 actor 门：``session_proposal`` / ``ttl_expiry`` 都不得删除。"""

    from soul_memory_kernel.memory.service import MemoryValidationError

    record = env.propose_family("不许被非成人删掉", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)

    for actor in (Actor(kind="session_proposal", actor_id="s"), TTL_ACTOR):
        with pytest.raises(MemoryValidationError):
            env.service.delete(record.id, actor)

    assert env.store.read_record(record.id) is not None
    assert env.count("deletion_audit") == 0


# ---------------------------------------------------------------------------
# 4. 投影接缝（§10.1：read_model + send_provider 两次授权）
# ---------------------------------------------------------------------------


def _project(env: Env, access: SessionAccess, *, session_id: str, audience_id: str):
    """§10.1 的接缝 —— **直接调用生产实现**（``soul.core.project_session_memory``）。

    W4 之前这里是一份手写的等价实现（测试替身）；生产实现落地后改为调用它，
    免得测试与产品各留一份、各自漂移。grant 不再是参数：生产接缝按 ``session_id``
    用 ``load_grant_for_session`` 解析（契约 §4.5 禁止调用方别造第二条授权路径），
    因此这里测到的就是产品真实走的那条路。

    返回过滤后的 ``MemorySnapshot``（快照字段与 ``query()`` 同形状，只保留通过了
    ``send_provider`` 复判的条目）。
    """

    return project_session_memory(
        access=access,
        session_id=session_id,
        audience_id=audience_id,
        db_path=env.db_path,
        clock=env.clock,
    ).snapshot


def test_projection_seam_injects_confirmed_family_memories(env: Env) -> None:
    """真实栈上跑通 §10.1：确认过的 FAMILY 记忆进入 instructions。"""

    record = env.propose_family("孩子明天要竞选班长", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)

    snapshot = _project(env, SessionAccess(), session_id="s", audience_id="family_all")
    block = render_memory_block(snapshot, member_names={"adult_a": "爸爸"})

    assert record.content in block
    assert "爸爸" in block
    assert record.id not in block, "绝不把 owner_id / record_id 原样写进投影"


def test_projection_seam_empty_snapshot_renders_empty_string(env: Env) -> None:
    """G1 回归护栏：空快照 → ``""``，``_render_projection`` 不追加任何字符。"""

    snapshot = _project(env, SessionAccess(), session_id="s", audience_id="family_all")

    assert snapshot.entries == ()
    assert render_memory_block(snapshot) == ""


def test_projection_seam_candidate_never_reaches_instructions(env: Env) -> None:
    """未确认的候选到不了投影 —— 也到不了 ``send_provider``。"""

    candidate = env.propose_family("还没确认的草稿", "EVENT")

    snapshot = _project(env, SessionAccess(), session_id="s", audience_id="family_all")

    assert snapshot.entries == ()
    assert render_memory_block(snapshot) == ""
    assert candidate.id in dict(snapshot.denied), "被拒原因必须可见"


def test_projection_seam_send_provider_is_rechecked_per_record(env: Env) -> None:
    """A9：``send_provider`` 是**每一条**单独复判，任一条被拒就逐条剔除。"""

    keep = env.propose_family("保留的共享记忆", "EVENT")
    env.service.confirm_shared(keep.id, frozenset({"family_all"}), ADULT)
    other = env.propose_family("另一个受众的记忆", "EVENT")
    env.service.confirm_shared(other.id, frozenset({"adult_b"}), ADULT)

    snapshot = _project(env, SessionAccess(), session_id="s", audience_id="family_all")

    assert [e.record_id for e in snapshot.entries] == [keep.id]
    assert render_memory_block(snapshot).count("\n") >= 1
    assert other.content not in render_memory_block(snapshot)


def test_projection_seam_grant_path_with_a_shared_record(env: Env) -> None:
    """A10 接缝函数可用；A5' 之后，FAMILY 共享记录在 grant 在场时**照样可读**。

    ``wrong_owner`` 比较 ``grant.owner_id`` 与 ``access.session_owner``。若沿用旧口径
    （有 grant 就必须对得上），一个为**私人**会话签发的 grant 会把全家的共享记忆
    一并关掉 —— 私人授权不该有这种能力。A5' 裁决正是要消除这个副作用：
    豁免的记录**逐条跳过整段 grant 检查**。W4 之后这条口径仍然成立（现在 owner
    绑定可表达，本会话确实带着 ``grant.owner_id == access.session_owner``）。
    """

    record = env.propose_family("有会话授权的记忆", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    env.grants.issue(
        Grant(
            grant_id="g-seam",
            version=1,
            session_id="sess-authorized",
            subject_id="adult_a",
            owner_id="adult_a",
            audience_id="family_all",
            actions=frozenset({"read_model", "send_provider"}),
            resource_ids=frozenset({record.id}),
            consent_versions=((record.id, 2),),
            expires_at="2026-09-26T13:00:00Z",
            issuer="local_control_plane",
            issued_at="2026-09-26T12:00:00Z",
        )
    )

    grant = load_grant_for_session(env.db_path, "sess-authorized")
    assert grant is not None and grant.grant_id == "g-seam", "A10 接缝函数可用"

    snapshot = _project(
        env, SessionAccess(), session_id="sess-authorized", audience_id="family_all"
    )
    assert [e.record_id for e in snapshot.entries] == [record.id]
    assert record.content in render_memory_block(snapshot)


def test_grant_path_for_a_non_exempt_record_is_w4_tightened(env: Env) -> None:
    """**W4 收紧**：owner 绑定成立后，非豁免记录走得到它真正的那道门。

    §3.5 之前 ``access.session_owner`` 恒为 ``None``，而任何 grant 都带非空
    ``owner_id``，于是非豁免记录一律停在 ``wrong_owner``（DENY_ORDER 第 6 位）——
    那不是它真正的拒绝理由，只是「应用还没有 owner 绑定」的副作用。

    现在会话可以合法携带 owner（必须配控制面 ``authorization_ref``），因此：

    - **grant 覆盖 ∧ owner 匹配 → grant 段整段通过**（正例用 ``publish_text``：
      它不在 A5' 豁免白名单里，必须真刀真枪走完 grant 段）；
    - PERSONAL 记录仍被拒，但理由是 **``scope_not_enabled``**（M2.1 相位门，
      §3.6），不再是 ``wrong_owner``；
    - 其余情况照旧拒绝：owner 不匹配 → ``wrong_owner``；没有 owner 声明 → ``wrong_owner``。
    """

    family = env.service.confirm_shared(
        env.propose_family("共享的家庭记录", "EVENT").id, frozenset({"family_all"}), ADULT
    )
    personal = replace(
        env.store.read_record(env.propose_family("私人记录", "EVENT").id),
        id="mem-personal-w4-0001",
        scope="PERSONAL",
        audiences=frozenset(),
        status="ACTIVE",
        memory_policy="persist_confirmed",
        last_confirmed_at=env.clock(),
        expires_at="2026-10-26T12:00:00Z",  # DDL：非 SAFETY 类的 ACTIVE 记录必须有期限
    )
    env.store.write_record(personal, actor=ADULT)

    access = SessionAccess(
        session_mode="controlled_private",
        session_owner="adult_a",
        authorization_ref="ctl:grant-2026-09-26",
    )
    grant = Grant(
        grant_id="g-personal",
        version=1,
        session_id="sess-w4",
        subject_id="adult_a",
        owner_id="adult_a",
        audience_id="family_all",
        actions=frozenset({"read_model", "publish_text"}),
        resource_ids=frozenset({personal.id, family.id}),
        consent_versions=(
            (personal.id, personal.consent_version),
            (family.id, family.consent_version),
        ),
        expires_at="2026-09-26T13:00:00Z",
        issuer="local_control_plane",
        issued_at="2026-09-26T12:00:00Z",
    )

    allowed = authorize(
        action="publish_text",
        access=access,
        grant=grant,
        session_id="sess-w4",
        audience_id="family_all",
        records=(family,),
        now=env.clock(),
    )
    assert (allowed.allowed, allowed.reason) == (True, "ok"), "grant 覆盖 ∧ owner 匹配 → 放行"

    denied = authorize(
        action="read_model",
        access=access,
        grant=grant,
        session_id="sess-w4",
        audience_id="family_all",
        records=(personal,),
        now=env.clock(),
    )
    assert (denied.allowed, denied.reason) == (
        False,
        "scope_not_enabled",
    ), "非豁免的 PERSONAL 记录在 M2.1 由相位门拦下，不再报 wrong_owner"

    wrong_owner = authorize(
        action="publish_text",
        access=SessionAccess(
            session_mode="controlled_private",
            session_owner="adult_b",
            authorization_ref="ctl:grant-2026-09-26",
        ),
        grant=grant,
        session_id="sess-w4",
        audience_id="family_all",
        records=(family,),
        now=env.clock(),
    )
    assert (wrong_owner.allowed, wrong_owner.reason) == (False, "wrong_owner"), "owner 不匹配照旧拒绝"

    unbound = authorize(
        action="publish_text",
        access=SessionAccess(),
        grant=grant,
        session_id="sess-w4",
        audience_id="family_all",
        records=(family,),
        now=env.clock(),
    )
    assert (unbound.allowed, unbound.reason) == (False, "wrong_owner"), "没有 owner 声明照旧拒绝"


def test_projection_seam_revoked_grant_degrades_to_no_grant(env: Env) -> None:
    """A4：撤销是存储层语义 —— ``load_for_session`` 返回 ``None``，判权落成 ``no_grant``。"""

    record = env.propose_family("授权覆盖的记忆", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    env.grants.issue(
        Grant(
            grant_id="g-revoke",
            version=1,
            session_id="sess-x",
            subject_id="adult_a",
            owner_id="adult_a",
            audience_id="family_all",
            actions=frozenset({"read_model", "send_provider"}),
            resource_ids=frozenset({record.id}),
            consent_versions=((record.id, 2),),
            expires_at="2026-09-26T13:00:00Z",
            issuer="local_control_plane",
            issued_at="2026-09-26T12:00:00Z",
        )
    )
    assert env.grants.load_for_session("sess-x") is not None

    env.grants.revoke("g-revoke", revoked_at=env.clock(), actor=ADULT)

    assert env.grants.load_for_session("sess-x") is None, "撤销后 store 返回 None"
    assert load_grant_for_session(env.db_path, "sess-x") is None
    # 记录本身仍是 FAMILY 共享，所以无 grant 的例外路径照样放行 —— 撤销撤的是
    # 「那次会话的授权」，不是记录的可共享性。
    snapshot = _project(env, SessionAccess(), session_id="sess-x", audience_id="family_all")
    assert [e.record_id for e in snapshot.entries] == [record.id]


# ---------------------------------------------------------------------------
# 5. 三方接口对齐的形状检查
# ---------------------------------------------------------------------------


def test_real_stack_classes_are_the_frozen_ones(env: Env) -> None:
    """三个真实实现类的身份与构造签名就是契约冻结的那三个。"""

    assert type(env.store) is SqliteMemoryStore
    assert type(env.grants) is SqliteGrantStore
    assert type(env.service) is MemoryService
    assert SqliteMemoryStore.__module__ == "soul_memory_kernel.memory.store"
    assert SqliteGrantStore.__module__ == "soul_memory_kernel.memory.grants"


def test_schema_has_every_frozen_table(env: Env) -> None:
    """真实库里建出的表与契约 §2 的 7 张表逐一对应。"""

    tables = {
        row[0]
        for row in env.raw("SELECT name FROM sqlite_master WHERE type='table'")
        if not row[0].startswith("sqlite_")
    }
    assert tables == {
        "memory_record",
        "memory_audience",
        "memory_source",
        "grant_record",
        "grant_action",
        "grant_resource",
        "deletion_audit",
        # M2.2（W9）schema v3 的第 8 张表：§3.9 的每日提取熔断计数（契约 §6 T9b 步骤 8
        # 与 T9 承载的变更第 2 项）。这条断言是 M2.1 时期的「7 张表」快照，
        # 因 M2.2 变红；按契约 §6 T15「凡因 M2.2 变红的断言都由 W9 在同一提交里更新」
        # 在此同步（**同步断言，未放宽**：仍然是精确集合相等）。
        "extraction_usage",
    }


def test_status_policy_invariant_holds_for_every_row(env: Env) -> None:
    """落库的数据满足 ``STATUS_POLICY_INVARIANT``（DDL CHECK 在真实库上生效）。"""

    confirmed = env.propose_family("确认过的", "EVENT")
    env.service.confirm_shared(confirmed.id, frozenset({"family_all"}), ADULT)
    env.propose_family("没确认的", "EVENT")

    rows = env.raw("SELECT status, memory_policy FROM memory_record")
    assert rows
    for status, policy in rows:
        if status == "DELETED":
            continue
        assert (status, policy) in {
            ("PENDING_CONFIRMATION", "candidate_only"),
            ("ACTIVE", "persist_confirmed"),
            ("DECAYED", "persist_confirmed"),
        }, (status, policy)


def test_do_not_persist_never_reaches_the_real_database(env: Env) -> None:
    """落点一在真实库上也成立：``do_not_persist`` 返回 ``None`` 且库中零行。"""

    result = env.service.propose(
        MemoryCandidate(
            content="别记这个",
            scope="FAMILY",
            memory_class="EVENT",
            owner_id="adult_a",
            source_type="explicit_user",
            source_member_id="child",
            confidence=1.0,
            importance=0.5,
            requested_policy="do_not_persist",
            audiences=frozenset({"family_all"}),
        ),
        SourceSession(
            session_id="sess-1",
            owner_id="adult_a",
            audience_id="family_all",
            session_mode="shared",
            identity_assurance="unknown",
            grant_id=None,
        ),
    )

    assert result is None
    assert env.count("memory_record") == 0


def test_propose_actor_is_session_proposal_not_adult(env: Env) -> None:
    """A8：会话内候选的 actor 是 ``session_proposal``，且它只建得出候选。"""

    from soul_memory_kernel.memory.service import IllegalTransition

    candidate = env.propose_family("会话里说的", "EVENT")
    assert candidate.status == "PENDING_CONFIRMATION"

    # session_proposal 不得直接写一条可召回的记录（绕过确认）。
    with pytest.raises(IllegalTransition):
        env.store.write_record(
            replace(candidate, id="mem-sneaky-0001", status="ACTIVE",
                    memory_policy="persist_confirmed", last_confirmed_at=env.clock()),
            actor=Actor(kind="session_proposal", actor_id="sess-1"),
        )
    assert env.store.read_record("mem-sneaky-0001") is None


# ---------------------------------------------------------------------------
# 6. A11：删除与审计的原子性（注入真实的 DB 级失败）
# ---------------------------------------------------------------------------


def _install_audit_failure_trigger(env: Env) -> None:
    """在真实 sqlite 里装一个触发器，让 ``deletion_audit`` 的 INSERT 必然失败。

    比 monkeypatch 更接近真实故障：失败发生在**同一个事务内部**（删除语句已经执行
    过之后），因此它检验的正是 ``hard_delete_with_audit`` 的事务边界。
    """

    env.raw(
        "CREATE TRIGGER injected_audit_failure BEFORE INSERT ON deletion_audit "
        "BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END"
    )


def test_delete_is_atomic_record_survives_and_no_audit_row(env: Env) -> None:
    """A11：审计写失败时**整体回滚** —— 记录仍在、受众行仍在、审计 0 行。"""

    from soul_memory_kernel.memory.service import StoreError

    record = env.propose_family("要删掉的共享记忆", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    assert env.count("memory_audience") == 1
    _install_audit_failure_trigger(env)

    with pytest.raises(StoreError):
        env.service.delete(record.id, ADULT)

    assert env.store.read_record(record.id) is not None, "失败必须整体回滚，记录仍在"
    assert env.count("memory_record") == 1
    assert env.count("memory_audience") == 1, "受众行也要回滚"
    assert env.count("deletion_audit") == 0, "审计 0 行"
    # 重试仍然可用（不是 RecordNotFound）：拆除触发器后删除应当成功且留审计。
    env.raw("DROP TRIGGER injected_audit_failure")
    report = env.service.delete(record.id, ADULT)
    assert env.store.read_record(record.id) is None
    assert env.count("deletion_audit") == 1
    assert report.audit_id


def test_sweep_candidate_expiry_is_atomic(env: Env) -> None:
    """A11：候选到期硬删同样原子 —— 审计失败时候选仍在、审计 0 行。"""

    from soul_memory_kernel.memory.service import StoreError

    candidate = env.propose_family("没被确认的草稿", "EVENT")
    env.clock.advance_days(8)
    _install_audit_failure_trigger(env)

    with pytest.raises(StoreError):
        env.service.sweep_expired(TTL_ACTOR)

    assert env.store.read_record(candidate.id) is not None, "失败必须整体回滚"
    assert env.count("memory_record") == 1
    assert env.count("deletion_audit") == 0

    env.raw("DROP TRIGGER injected_audit_failure")
    results = env.service.sweep_expired(TTL_ACTOR)
    assert [type(r).__name__ for r in results] == ["DeletionReport"]
    assert env.store.read_record(candidate.id) is None
    assert env.count("deletion_audit") == 1


def test_hard_delete_with_audit_rejects_unauthorized_actors(env: Env) -> None:
    """B-s3：actor 策略显式校验 —— 越权 actor 得到校验错误，不是 DDL 的 CHECK 失败。"""

    from soul_memory_kernel.memory.service import MemoryValidationError

    record = env.propose_family("不该被删的记录", "EVENT")
    for actor in (
        Actor(kind="session_proposal", actor_id="s"),
        Actor(kind="migration", actor_id="m"),
    ):
        with pytest.raises(MemoryValidationError):
            env.store.hard_delete_with_audit(
                record_id=record.id, actor=actor, deleted_at=env.clock(), unknown_copies=()
            )
    assert env.store.read_record(record.id) is not None
    assert env.count("deletion_audit") == 0


# ---------------------------------------------------------------------------
# 7. B2：记录到期是判权的一部分（豁免路径同样执行）
# ---------------------------------------------------------------------------


def test_record_expiry_is_denied_even_on_the_grant_exempt_path(env: Env) -> None:
    """B2：FAMILY + 受众命中的**豁免**读取，遇到过期记录仍必须拒绝。

    这是 B2 的核心：豁免只跳过 **grant** 检查，**记录级**检查照常 ——
    一条过了期的共享记忆不该因为「家庭共享不需要 grant」而被读出来。
    """

    record = env.propose_family("会过期的共享记忆", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    stored = env.store.read_record(record.id)
    assert stored.expires_at is not None

    env.clock.advance_days(400)  # 过期，但**不跑 sweep**：状态仍是 ACTIVE

    decision = authorize(
        action="read_model",
        access=SessionAccess(),
        grant=None,  # 豁免路径
        session_id="s",
        audience_id="family_all",
        records=(stored,),
        now=env.clock(),
    )
    assert (decision.allowed, decision.reason) == (False, "record_expired")


def test_record_expiry_does_not_touch_unexpired_or_never_expiring_records(env: Env) -> None:
    """反向：未过期记录放行；``expires_at is None``（已确认 SAFETY 类）永不到期。"""

    event = env.propose_family("正常事件", "EVENT")
    env.service.confirm_shared(event.id, frozenset({"family_all"}), ADULT)
    allergy = env.propose_family("对花生过敏", "SAFETY")
    env.service.confirm_shared(allergy.id, frozenset({"family_all"}), ADULT)

    env.clock.advance_days(3650)  # 十年后
    snapshot = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert [e.record_id for e in snapshot.entries] == [allergy.id], "只剩不过期的 SAFETY 类"
    # ``query()`` 的兜底（先按 expires_at 排除）在 B2 之后**保留**，并且按主控
    # 2026-09-26 的裁决**在 denied 里留痕**（reason 与判权同名 record_expired）——
    # 两条防线各司其职：query() 不把它交出来且说明原因，authorize() 即使被直接调用
    # 也会报 record_expired。
    assert snapshot.denied == ((event.id, "record_expired"),)
    assert env.store.read_record(event.id).status == "ACTIVE", "没跑 sweep，状态没变"


# ---------------------------------------------------------------------------
# 8. B-s1：grant 不能倒填签发现刻
# ---------------------------------------------------------------------------


def test_issue_rejects_a_grant_issued_in_the_future(env: Env, tmp_path: Path) -> None:
    """B-s1：``issued_at`` 超前 > 60s 的 grant 必须被拒绝（否则 12h 窗口不锚定现刻）。"""

    from soul_memory_kernel.memory.service import MemoryValidationError

    future = Grant(
        grant_id="g-future",
        version=1,
        session_id="sess-f",
        subject_id="adult_a",
        owner_id="adult_a",
        audience_id="family_all",
        actions=frozenset({"read_model"}),
        resource_ids=frozenset({"rec-x"}),
        consent_versions=(("rec-x", 1),),
        expires_at="2026-09-26T12:30:00Z",
        issuer="local_control_plane",
        issued_at="2026-09-26T12:00:00Z",  # env 时钟是 2026-09-26T12:00:00Z 之前
    )
    # 先把可控时钟拨到签发时刻之前，制造「未来签发」。
    env.clock.value = "2026-09-26T06:00:00Z"
    with pytest.raises(MemoryValidationError, match="future"):
        env.grants.issue(future)
    assert env.count("grant_record") == 0, "拒绝必须零行落库"


def test_issue_tolerates_small_clock_skew(env: Env) -> None:
    """B-s1 的边界：≤60s 的偏移放行（同机控制面与 store 的时钟漂移）。"""

    env.clock.value = "2026-09-26T12:00:00Z"
    skewed = Grant(
        grant_id="g-skew",
        version=1,
        session_id="sess-s",
        subject_id="adult_a",
        owner_id="adult_a",
        audience_id="family_all",
        actions=frozenset({"read_model"}),
        resource_ids=frozenset({"rec-x"}),
        consent_versions=(("rec-x", 1),),
        expires_at="2026-09-26T13:00:00Z",
        issuer="local_control_plane",
        issued_at="2026-09-26T12:00:59Z",  # +59s
    )
    env.grants.issue(skewed)
    assert env.count("grant_record") == 1


def test_authorize_denies_a_not_yet_valid_grant(env: Env) -> None:
    """B-s1：窗口左端的判权检查 —— ``now < issued_at`` 报 ``not_yet_valid``。"""

    record = env.propose_family("普通共享记忆", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    stored = env.store.read_record(record.id)
    # 非豁免记录（受众不命中），强制 grant 段参与判定。
    non_exempt = replace(stored, audiences=frozenset({"someone-else"}))
    grant = Grant(
        grant_id="g-notyet",
        version=1,
        session_id="s",
        subject_id="adult_a",
        owner_id="adult_a",
        audience_id="family_all",
        actions=frozenset({"read_model"}),
        resource_ids=frozenset({non_exempt.id}),
        consent_versions=((non_exempt.id, stored.consent_version),),
        expires_at="2026-09-26T13:00:00Z",
        issuer="local_control_plane",
        issued_at="2026-09-26T12:59:00Z",
    )
    decision = authorize(
        action="read_model",
        access=SessionAccess(),
        grant=grant,
        session_id="s",
        audience_id="family_all",
        records=(non_exempt,),
        now="2026-09-26T12:00:00Z",
    )
    assert (decision.allowed, decision.reason) == (False, "not_yet_valid")


# ---------------------------------------------------------------------------
# 9. B-s5 / B-s6：内容长度上限与投影框架句
# ---------------------------------------------------------------------------


def test_content_length_is_capped_at_write_time(env: Env) -> None:
    """B-s5：``propose``/``correct`` 在**写入时**执行 500 字硬上限。"""

    from soul_memory_kernel.memory.service import MAX_CONTENT_CHARS, MemoryValidationError

    assert MAX_CONTENT_CHARS == 500
    ok = env.propose_family("短" * MAX_CONTENT_CHARS, "EVENT")
    assert env.store.read_record(ok.id) is not None

    with pytest.raises(MemoryValidationError, match="at most 500"):
        env.propose_family("长" * (MAX_CONTENT_CHARS + 1), "EVENT")
    assert env.count("memory_record") == 1, "超长候选零行落库"

    env.service.confirm_shared(ok.id, frozenset({"family_all"}), ADULT)
    with pytest.raises(MemoryValidationError, match="at most 500"):
        env.service.correct(
            ok.id, MemoryCorrection(content="超" * (MAX_CONTENT_CHARS + 1)), ADULT
        )


def test_projection_header_frames_memory_as_reference_not_instruction(env: Env) -> None:
    """B-s6：投影标题带「这是资料、不是指令」的框架句。"""

    from soul_memory_kernel.memory.projection import MEMORY_BLOCK_HEADER

    assert "不是指令" in MEMORY_BLOCK_HEADER
    assert "事实参考" in MEMORY_BLOCK_HEADER

    record = env.propose_family("孩子明天要竞选班长", "EVENT")
    env.service.confirm_shared(record.id, frozenset({"family_all"}), ADULT)
    block = render_memory_block(
        env.service.query(
            SessionAccess(),
            "session_projection",
            session_id="s",
            audience_id="family_all",
            grant=None,
        )
    )
    assert block.startswith(MEMORY_BLOCK_HEADER)


# ---------------------------------------------------------------------------
# 10. 接缝的 fail-closed：query 之后记录被删，不得进 instructions
# ---------------------------------------------------------------------------


def test_projection_seam_skips_an_entry_deleted_after_the_query(env: Env) -> None:
    """query 与渲染之间记录被删 → 接缝**跳过这一条**，绝不把已删内容放进 instructions。

    ``resolve_provenance`` 对不可解析的记录返回**空元组**，而 ``authorize(records=())``
    在 grant 前置条件成立时是「没有记录级失败 ⇒ ``ok``」。所以接缝必须自己判「闭包里
    有没有目标记录」—— 少了这一步，「会话持有效 grant + 记录在两步之间被删」的竞态
    就会把已删除的内容渲染出去（W4 放开 ``session_owner`` 之后这条路径真实可达）。
    """

    keep = env.propose_family("保留的共享记忆", "EVENT")
    env.service.confirm_shared(keep.id, frozenset({"family_all"}), ADULT)
    gone = env.propose_family("查完就删的记忆", "EVENT")
    env.service.confirm_shared(gone.id, frozenset({"family_all"}), ADULT)

    snapshot = env.service.query(
        SessionAccess(), "session_projection", session_id="s", audience_id="family_all", grant=None
    )
    assert {e.record_id for e in snapshot.entries} == {keep.id, gone.id}

    # 模拟两步之间被删（例如另一个进程/成人删除）。
    env.service.delete(gone.id, ADULT)

    # 接缝是**逐条**判的：不能复用上面的 snapshot，必须按它自己的读取顺序复判。
    seam_snapshot = _project(env, SessionAccess(), session_id="s", audience_id="family_all")
    rendered = render_memory_block(seam_snapshot)
    assert [e.record_id for e in seam_snapshot.entries] == [keep.id]
    assert gone.content not in rendered, "已删除记录的内容绝不进 instructions"
    assert keep.content in rendered


def test_projection_seam_closure_carries_ancestors(env: Env) -> None:
    """B-s2：接缝传的是祖先闭包 —— 有血缘的记录不会被 ``missing_provenance`` 误剔。"""

    ancestor = env.propose_family("祖先记忆", "EVENT")
    env.service.confirm_shared(ancestor.id, frozenset({"family_all"}), ADULT)
    derived = replace(
        env.store.read_record(ancestor.id),
        id="mem-derived-seam-01",
        content="派生摘要",
        source_ids=(ancestor.id,),
    )
    env.store.write_record(derived, actor=ADULT)

    # 裸记录会缺源（source_ids 不在 records 里）→ missing_provenance；
    # 闭包则可解析 → 放行。
    bare = authorize(
        action="send_provider",
        access=SessionAccess(),
        grant=None,
        session_id="s",
        audience_id="family_all",
        records=(env.store.read_record(derived.id),),
        now=env.clock(),
    )
    assert (bare.allowed, bare.reason) == (False, "missing_provenance")

    snapshot = _project(env, SessionAccess(), session_id="s", audience_id="family_all")
    assert {e.record_id for e in snapshot.entries} == {ancestor.id, derived.id}
    assert derived.content in render_memory_block(snapshot)


# ---------------------------------------------------------------------------
# 11. A11 的第三条：目标不存在 -> RecordNotFound，不写审计
# ---------------------------------------------------------------------------


def test_hard_delete_with_audit_refuses_a_missing_record(env: Env) -> None:
    """A11：目标不存在时抛 ``RecordNotFound`` 且**不写审计**。

    审计表是「删除事实」的凭据。写入一条没删过任何行的条目会让审计失真 ——
    与 §7.3「不得把『不再召回』写成『已删除』」是同一条纪律：
    不得把「没发生」写成「已发生」。
    """

    from soul_memory_kernel.memory.service import RecordNotFound

    with pytest.raises(RecordNotFound):
        env.store.hard_delete_with_audit(
            record_id="mem-never-existed",
            actor=ADULT,
            deleted_at=env.clock(),
            unknown_copies=(),
        )

    assert env.count("deletion_audit") == 0, "没删过任何行就不该有审计行"
    assert env.count("memory_record") == 0
