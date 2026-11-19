"""M2 数据模型层测试（W1）：保留期算术、grant 同意版本查询、写入前校验的边界。

分工（契约页 §9）：

- ``tests/test_memory_contract.py`` —— 永久冻结的**形状**不变量（W0 写，W1 不改）。
- 本文件 —— W1 实现的**行为**：``RetentionPolicy.days_for`` 的分型算术、
  ``RetentionPolicy`` 的配置形状校验、``Grant.consent_version_for``。
- ``tests/test_memory_store.py`` —— 持久化边界（DDL 落库 + CRUD + 删除/迁移）。

判权（``authorize`` / ``require``）归 W2，服务层五接口归 W3，本文件都不涉及。
"""

from __future__ import annotations

import inspect

import pytest

from soul_memory_kernel.memory.model import (
    DEFAULT_TTL_CANDIDATE_DAYS,
    DEFAULT_TTL_EVENT_DAYS,
    DEFAULT_TTL_PREFERENCE_DAYS,
    Grant,
    MemoryCandidate,
    MemoryCorrection,
    MemoryRecord,
    RetentionPolicy,
)
from soul_memory_kernel.memory.service import MemoryServiceError, MemoryValidationError

# ---------------------------------------------------------------------------
# RetentionPolicy.days_for —— D5 的分型 TTL
# ---------------------------------------------------------------------------


def test_default_retention_days_match_the_frozen_contract() -> None:
    """D5：EVENT 30 天、PREFERENCE 180 天、候选 7 天；SAFETY 已确认不过期。"""

    policy = RetentionPolicy()
    assert policy.event_days == DEFAULT_TTL_EVENT_DAYS == 30
    assert policy.preference_days == DEFAULT_TTL_PREFERENCE_DAYS == 180
    assert policy.candidate_days == DEFAULT_TTL_CANDIDATE_DAYS == 7


@pytest.mark.parametrize(
    ("memory_class", "expected_days"),
    [("EVENT", 30), ("PREFERENCE", 180), ("SAFETY", None)],
)
def test_days_for_confirmed_records(memory_class: str, expected_days: int | None) -> None:
    """已确认记录：EVENT / PREFERENCE 各按天数；**SAFETY 为 ``None``（不过期）**。"""

    assert RetentionPolicy().days_for(memory_class, is_candidate=False) == expected_days


@pytest.mark.parametrize("memory_class", ["EVENT", "PREFERENCE", "SAFETY"])
def test_days_for_candidates_of_every_class_use_the_candidate_window(memory_class: str) -> None:
    """阻塞 2 的关键一条：**SAFETY 类候选同样受候选期约束**。

    D5 的「安全记忆不过期」说的是**被确认下来的**安全事实，不是没人确认过的草稿。
    """

    assert RetentionPolicy().days_for(memory_class, is_candidate=True) == (
        DEFAULT_TTL_CANDIDATE_DAYS
    )


def test_days_for_uses_the_configured_values_not_the_defaults() -> None:
    """配置只影响新写入的记录，但算术必须真的用配置值。"""

    policy = RetentionPolicy(event_days=3, preference_days=5, candidate_days=2)
    assert policy.days_for("EVENT", is_candidate=False) == 3
    assert policy.days_for("PREFERENCE", is_candidate=False) == 5
    assert policy.days_for("SAFETY", is_candidate=False) is None
    assert policy.days_for("EVENT", is_candidate=True) == 2
    assert policy.days_for("SAFETY", is_candidate=True) == 2


def test_days_for_is_keyword_only_for_the_candidate_flag() -> None:
    """``is_candidate`` 是 keyword-only：位置传参太容易把「候选」与「已确认」写反。"""

    parameter = inspect.signature(RetentionPolicy.days_for).parameters["is_candidate"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


def test_days_for_rejects_an_unknown_memory_class() -> None:
    """未知留存类型不得静默按 30 天处理 —— 那是把「来自未来的 schema」当普通记录。"""

    with pytest.raises(MemoryValidationError) as excinfo:
        RetentionPolicy().days_for("EXPIRING", is_candidate=False)  # type: ignore[arg-type]
    assert "EXPIRING" in str(excinfo.value)
    assert isinstance(excinfo.value, MemoryServiceError)


@pytest.mark.parametrize("field", ["event_days", "preference_days", "candidate_days"])
@pytest.mark.parametrize("value", [0, -1, 1.5, "30", None])
def test_retention_policy_rejects_a_non_positive_or_non_integer_day_count(
    field: str, value: object
) -> None:
    """§6.1 的配置校验：非整数或 ``<= 0`` 一律拒绝（env 层抛 ``ConfigError``，类型层也拒绝）。"""

    with pytest.raises(MemoryValidationError):
        RetentionPolicy(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["event_days", "preference_days", "candidate_days"])
def test_retention_policy_rejects_bool_day_counts(field: str) -> None:
    """``bool`` 是 ``int`` 的子类：不显式排除的话 ``True`` 会静默变成「保留 1 天」。"""

    with pytest.raises(MemoryValidationError):
        RetentionPolicy(**{field: True})  # type: ignore[arg-type]


def test_retention_policy_accepts_every_positive_integer() -> None:
    policy = RetentionPolicy(event_days=1, preference_days=3650, candidate_days=1)
    assert policy.days_for("EVENT", is_candidate=False) == 1
    assert policy.days_for("PREFERENCE", is_candidate=False) == 3650


# ---------------------------------------------------------------------------
# Grant.consent_version_for —— 逐资源同意版本绑定
# ---------------------------------------------------------------------------


def _grant(consent_versions: tuple[tuple[str, int], ...]) -> Grant:
    return Grant(
        grant_id="grant-a",
        version=1,
        session_id="session-1",
        subject_id="adult_a",
        owner_id="adult_a",
        audience_id="family_all",
        actions=frozenset({"read_model"}),
        resource_ids=frozenset({"mem-1"}),
        consent_versions=consent_versions,
        expires_at="2026-09-27T00:00:00Z",
        issuer="local-control-plane",
        issued_at="2026-09-26T00:00:00Z",
    )


def test_consent_version_for_returns_the_bound_version() -> None:
    grant = _grant((("mem-1", 3), ("mem-2", 4)))
    assert grant.consent_version_for("mem-1") == 3
    assert grant.consent_version_for("mem-2") == 4


def test_consent_version_for_returns_none_when_the_record_is_not_covered() -> None:
    """``None`` = 该 grant 未覆盖这条记录，判权要按缺绑定处理（不是「版本 0」）。"""

    assert _grant(()).consent_version_for("mem-1") is None
    assert _grant((("mem-2", 4),)).consent_version_for("mem-1") is None


def test_consent_version_for_is_deterministic_on_duplicates() -> None:
    """``grant_resource`` 的主键排除了重复；若调用方硬塞重复项，取首个匹配。"""

    grant = _grant((("mem-1", 3), ("mem-1", 4)))
    assert grant.consent_version_for("mem-1") == 3


# ---------------------------------------------------------------------------
# 构造点**不**校验：policy_denied 的反例必须能在内存里构造
# ---------------------------------------------------------------------------


def test_memory_record_construction_does_not_validate_contract_invariants() -> None:
    """关键回归护栏（W1 的刻意决定，见 ``model.py`` 与 ``store.py`` 的 docstring）。

    契约 §3.3 的 ``policy_denied`` 要求判权能对**违反不变量的记录**报拒绝：

    1. ``memory_policy="do_not_persist"`` 的行（DDL 排除它，库里出现即违约）；
    2. ``status="ACTIVE"`` + ``memory_policy="candidate_only"``（违反
       ``STATUS_POLICY_INVARIANT``）。

    这两条只有在构造点**不**校验时才表达得出来。校验落在写入边界
    （``SqliteMemoryStore.write_record``），不落在 dataclass 上。
    """

    broken = MemoryRecord(
        id="mem-broken",
        owner_id="adult_a",
        scope="FAMILY",
        memory_class="EVENT",
        source_type="explicit_user",
        source_member_id="adult_a",
        content="违反不变量的行",
        confidence=1.0,
        importance=0.5,
        created_at="2026-09-26T00:00:00Z",
        updated_at="2026-09-26T00:00:00Z",
        last_confirmed_at="2026-09-26T00:00:00Z",
        expires_at="2026-10-26T00:00:00Z",
        source_session_id=None,
        status="ACTIVE",
        memory_policy="candidate_only",  # 与 status 不符：契约违规
        audiences=frozenset({"family_all"}),
        consent_version=1,
    )
    assert broken.status == "ACTIVE" and broken.memory_policy == "candidate_only"

    do_not_persist = MemoryRecord(**{**vars(broken), "memory_policy": "do_not_persist"})  # type: ignore[arg-type]
    assert do_not_persist.memory_policy == "do_not_persist"


def test_memory_candidate_and_correction_shapes_stay_open_at_construction() -> None:
    """候选与修正对象同理：形状校验在服务层（W3）做，不在 dataclass 构造点做。"""

    candidate = MemoryCandidate(
        content="",
        scope="PERSONAL",
        memory_class="EVENT",
        owner_id="child_a",
        source_type="auto_extracted",
        source_member_id=None,
        confidence=2.0,
        importance=-1.0,
        origin="auto_extracted",
    )
    assert candidate.origin == "auto_extracted"
    assert MemoryCorrection() == MemoryCorrection(None, None, None)
