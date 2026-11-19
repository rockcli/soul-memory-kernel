"""M2 授权与 grant 存储测试（W2）。

覆盖契约页 ``docs/M2-CONTRACT.md`` 分配给 W2 的两块：

1. ``family_ai/memory/policy.py`` —— ``authorize()`` / ``require()`` 的拒权优先判定、
   §8.3 fixture 映射的逐条真实断言、§8.4 补充正例、§8.6 要求 W2 自补的全部拒绝路径。
2. ``family_ai/memory/grants.py`` —— ``SqliteGrantStore`` 的 issue / revoke /
   load_current / load_for_session 与 ``load_grant_for_session``（见文件后半段）。

设计纪律：

- **正例非空**（防「全拒绝算通过」）：fixture 的 ``approved_family_visible`` 与 §8.4 的
  ``m2_1_family_event_positive`` / ``m2_1_family_safety_class_positive`` 三条都必须真的
  拿到 ``ok``。
- **反例逐条可达**：``DENY_ORDER`` 的每一项都必须有一个「只违反它」的输入，
  另有一个「后缀累积违反」的输入证明它按序报第一个。
- fixture 记录按 §8.1 的补齐规则确定性构造、按 §8.2 登记的两条归一化处理，
  **测试不自行发明 fixture 取值**。
- 本文件不 import ``soul_memory_kernel.privacy``（合成原型），与契约 §12.1 第 9 条一致。
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import soul_memory_kernel.memory as mem
from soul_memory_kernel.memory import policy as policy_module
from soul_memory_kernel.memory.grants import SqliteGrantStore, load_grant_for_session
from soul_memory_kernel.memory.model import Actor, Grant, MemoryRecord
from soul_memory_kernel.memory.policy import DENY_ORDER, authorize, require
from soul_memory_kernel.memory.service import AuthorizationError
from soul_memory_kernel.soul.policy import CONTROL_PLANE_AUTHORIZATION_REF, SessionAccess
from tests.test_memory_contract import (
    CONTRACT_SUPPLEMENTARY_CASES,
    FIXTURE_CASE_MAPPING,
    FIXTURE_RECORD_COMPLETION,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "m2-memory-policy.synthetic.json"

NOW = "2026-09-24T12:00:00Z"
SESSION_ID = "session-w2"
GRANT_ID = "grant-w2"
RECORD_ID = "rec-1"
AUDIENCE = "family_all"
OWNER = "adult_a"


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _epoch() -> datetime:
    return datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# 测试用访问状态：W4 之后 owner 绑定是**冻结形状的一部分**
# ---------------------------------------------------------------------------


def _owner_bound_access(
    owner: str | None, *, session_mode: str = "shared", speaker_claim: str | None = None
) -> SessionAccess:
    """带 ``session_owner`` 的访问状态 —— 用**真实的** :class:`SessionAccess`。

    W4（契约 §3.5）之前这里是 ``OwnerBoundAccess`` 子类：它吞掉父类那条
    「session owner 一律拒绝」的断言，伪造一个产品里不可表达的状态。W4 之后
    owner 绑定本身合法（必须配控制面 ``authorization_ref``），替身因此退役 ——
    测试与产品用同一个类，替身不可能比产品宽松、从而掩盖构造层的回归。
    """

    if owner is None:
        return SessionAccess(
            session_mode=session_mode,  # type: ignore[arg-type]
            speaker_claim=speaker_claim,
        )
    return SessionAccess(
        session_mode=session_mode,  # type: ignore[arg-type]
        session_owner=owner,
        authorization_ref=f"ctl:test:{session_mode}",
        speaker_claim=speaker_claim,
    )


# ---------------------------------------------------------------------------
# fixture 适配器：按 §8.1 补齐、按 §8.2 归一化与最小授权
# ---------------------------------------------------------------------------


def _fixture_doc() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _complete_fixture_record(raw: dict[str, Any], evaluate_at: str) -> MemoryRecord:
    """§8.1 的补齐规则：fixture 只给 7 个字段，其余由契约确定性地补齐。"""

    owner_id = raw["owner_id"]
    # §8.2 登记的归一化：mem-family-unapproved 原文 ACTIVE + candidate_only 违反
    # status↔policy CHECK，归一为候选（不影响该 case 的结论）。
    status = "PENDING_CONFIRMATION" if raw["memory_policy"] == "candidate_only" else raw["status"]
    memory_class = str(FIXTURE_RECORD_COMPLETION["memory_class"])
    created = datetime.fromisoformat(evaluate_at.replace("Z", "+00:00"))

    if memory_class == "SAFETY" and status in {"ACTIVE", "DECAYED"}:
        expires_at: str | None = None
    elif status == "PENDING_CONFIRMATION":
        expires_at = _iso(created + timedelta(days=mem.DEFAULT_TTL_CANDIDATE_DAYS))
    else:
        expires_at = _iso(created + timedelta(days=mem.DEFAULT_TTL_EVENT_DAYS))

    return MemoryRecord(
        id=raw["id"],
        owner_id=owner_id,
        scope=raw["scope"],
        memory_class=memory_class,  # type: ignore[arg-type]
        source_type="explicit_user",
        source_member_id=owner_id,
        content=raw["content"],
        confidence=1.0,
        importance=0.5,
        created_at=evaluate_at,
        updated_at=evaluate_at,
        last_confirmed_at=evaluate_at if status == "ACTIVE" else None,
        expires_at=expires_at,
        source_session_id=None,
        status=status,  # type: ignore[arg-type]
        memory_policy=raw["memory_policy"],
        audiences=frozenset({"family_all"}) if raw.get("shared_approved", False) else frozenset(),
        consent_version=1,
        source_ids=(),
    )


def _fixture_records() -> dict[str, MemoryRecord]:
    doc = _fixture_doc()
    return {
        record["id"]: _complete_fixture_record(record, doc["evaluate_at"])
        for record in doc["records"]
    }


def _fixture_grants(records: dict[str, MemoryRecord]) -> dict[str, Grant]:
    """§8.2：fixture 未给的 grant 字段按**最小授权**补齐（由 W2 的测试适配器做）。"""

    doc = _fixture_doc()
    grants: dict[str, Grant] = {}
    for raw in doc["fixture_grants"]:
        owned = sorted(
            record.id
            for record in records.values()
            if record.owner_id == raw["owner_id"] and record.status == "ACTIVE"
        )
        grants[raw["id"]] = Grant(
            grant_id=raw["id"],
            version=1,
            session_id=raw["session_id"],
            subject_id=raw["owner_id"],
            owner_id=raw["owner_id"],
            audience_id="family_all",
            actions=frozenset({"read_model"}),
            resource_ids=frozenset(owned),
            consent_versions=tuple((record_id, records[record_id].consent_version) for record_id in owned),
            expires_at=raw["expires_at"],
            issuer=raw["issuer"],
            issued_at=doc["evaluate_at"],
        )
    return grants


#: §8.3 的 fixture case → 构造输入。``authorize()`` 的全部输入都在这里显式写出，
#: 与契约页「契约表达」列逐项对应。
FIXTURE_CASE_INPUTS: dict[str, dict[str, Any]] = {
    "authorized_owner_positive": {
        "access": lambda: _owner_bound_access("adult_a", session_mode="controlled_private"),
        "grant_id": "grant-a-s1",
        "session_id": "session-1",
        "audience_id": "family_all",
        "action": "read_model",
        "record_ids": ("mem-private-a",),
    },
    "unknown_denied": {
        "access": lambda: SessionAccess(),
        "grant_id": None,
        "session_id": "session-1",
        "audience_id": "family_all",
        "action": "read_model",
        "record_ids": ("mem-private-a",),
    },
    "self_claim_denied": {
        "access": lambda: SessionAccess(speaker_claim="adult_a"),
        "grant_id": None,
        "session_id": "session-1",
        "audience_id": "family_all",
        "action": "read_model",
        "record_ids": ("mem-private-a",),
    },
    "wrong_owner_denied": {
        "access": lambda: _owner_bound_access("adult_b"),
        "grant_id": "grant-a-s1",
        "session_id": "session-1",
        "audience_id": "family_all",
        "action": "read_model",
        "record_ids": ("mem-private-a",),
    },
    "expired_grant_denied": {
        "access": lambda: _owner_bound_access("adult_a"),
        "grant_id": "grant-a-expired",
        "session_id": "session-1",
        "audience_id": "family_all",
        "action": "read_model",
        "record_ids": ("mem-private-a",),
    },
    "new_session_without_grant_denied": {
        "access": lambda: _owner_bound_access("adult_a"),
        "grant_id": None,
        "session_id": "session-2",
        "audience_id": "family_all",
        "action": "read_model",
        "record_ids": ("mem-private-a",),
    },
    "approved_family_visible": {
        "access": lambda: SessionAccess(),
        "grant_id": None,
        "session_id": "session-2",
        "audience_id": "family_all",
        "action": "read_model",
        "record_ids": ("mem-family-approved",),
    },
}


def _authorize_fixture_case(case_id: str) -> tuple[mem.AuthorizationDecision, tuple[MemoryRecord, ...]]:
    doc = _fixture_doc()
    records = _fixture_records()
    grants = _fixture_grants(records)
    spec = FIXTURE_CASE_INPUTS[case_id]
    selected = tuple(records[record_id] for record_id in spec["record_ids"])
    decision = authorize(
        action=spec["action"],
        access=spec["access"](),
        grant=grants.get(spec["grant_id"]) if spec["grant_id"] else None,
        session_id=spec["session_id"],
        audience_id=spec["audience_id"],
        records=selected,
        now=doc["evaluate_at"],
    )
    return decision, selected


# ---------------------------------------------------------------------------
# 1. fixture 映射（§8.3）：每一个正例与反例都转成真实断言
# ---------------------------------------------------------------------------


def test_fixture_case_inputs_cover_every_registered_mapping() -> None:
    """§8.3 的映射表里每一个 case 都必须有构造输入 —— 少一个就是漏测。"""

    assert set(FIXTURE_CASE_INPUTS) == set(FIXTURE_CASE_MAPPING)


@pytest.mark.parametrize("case_id", list(FIXTURE_CASE_INPUTS))
def test_fixture_case_mapping_holds_in_m2_1(case_id: str) -> None:
    """逐条核对：M2.1 相位下的 reason 必须等于映射表登记的 ``m2_1_reason``。"""

    expected = FIXTURE_CASE_MAPPING[case_id]["m2_1_reason"]
    decision, _ = _authorize_fixture_case(case_id)
    assert decision.reason == expected, case_id
    assert decision.allowed is (expected == "ok"), case_id


@pytest.mark.parametrize(
    "case_id",
    [cid for cid, row in FIXTURE_CASE_MAPPING.items() if row["m2_1_reason"] != "ok"],
)
def test_denied_fixture_cases_recall_nothing(case_id: str) -> None:
    """反例在 M2.1 不能召回任何记录。

    映射表里的 ``expected_ids`` 是该 case **所属相位**的预期；M2.1 相位下正例只有
    ``approved_family_visible``，因此这里只对 M2.1 相位的反例核对 ``expected_ids`` 为空，
    M2.2 登记的 PERSONAL 正例则单独断言「M2.1 召回为空、M2.2 预期非空」。
    """

    decision, records = _authorize_fixture_case(case_id)
    recalled = tuple(record.id for record in records if decision.allowed)
    assert recalled == ()
    if FIXTURE_CASE_MAPPING[case_id]["phase"] == "M2.1":
        assert FIXTURE_CASE_MAPPING[case_id]["expected_ids"] == ()


def test_approved_family_visible_is_recalled_without_any_grant() -> None:
    """§8.5 第 2 条：无 grant 却放行是 §3.3 ``no_grant`` 例外的直接体现。

    这同时是一条防线：把所有无 grant 请求一律拒绝的实现会在这里变红。
    """

    decision, records = _authorize_fixture_case("approved_family_visible")
    assert decision == mem.ALLOWED
    assert tuple(record.id for record in records if decision.allowed) == ("mem-family-approved",)
    assert FIXTURE_CASE_MAPPING["approved_family_visible"]["m2_1_reason"] == "ok"


def test_personal_positive_is_unreachable_in_m2_1() -> None:
    """§8.3 登记的 M2.2 正例：**即使 owner/grant/受众全部匹配**，M2.1 也拒绝。"""

    decision, records = _authorize_fixture_case("authorized_owner_positive")
    assert records[0].scope == "PERSONAL"
    assert decision.reason == "scope_not_enabled"
    assert decision.allowed is False
    assert tuple(record.id for record in records if decision.allowed) == (), "M2.1 召回为空"
    assert FIXTURE_CASE_MAPPING["authorized_owner_positive"]["expected_ids"] == ("mem-private-a",)
    assert FIXTURE_CASE_MAPPING["authorized_owner_positive"]["reason"] == "ok", (
        "fixture 自身的预期（M2.2 目标）必须保持不变"
    )


def test_speaker_claim_is_not_an_authorization_input() -> None:
    """§8.5 第 1 条：``speaker_claim`` 换值后判定**逐字节不变**。

    ``self_claim_denied`` 证明的是「自报姓名根本不是判权输入」，不是「自报被拒了」。
    """

    doc = _fixture_doc()
    records = _fixture_records()
    decisions = []
    for claim in ("adult_a", "adult_b", None, "未知的人"):
        decisions.append(
            authorize(
                action="read_model",
                access=SessionAccess(speaker_claim=claim),
                grant=None,
                session_id="session-1",
                audience_id="family_all",
                records=(records["mem-private-a"],),
                now=doc["evaluate_at"],
            )
        )
    assert len(set(decisions)) == 1
    assert decisions[0].reason == FIXTURE_CASE_MAPPING["self_claim_denied"]["m2_1_reason"]


def test_unapproved_candidate_and_deleted_tombstone_are_never_recalled() -> None:
    """§8.2 归一化后的候选与墓碑：在任何构造下都进不了正例。"""

    doc = _fixture_doc()
    records = _fixture_records()
    grants = _fixture_grants(records)
    for record_id in ("mem-family-unapproved", "mem-deleted"):
        decision = authorize(
            action="read_model",
            access=SessionAccess(),
            grant=grants["grant-a-s1"],
            session_id="session-1",
            audience_id="family_all",
            records=(records[record_id],),
            now=doc["evaluate_at"],
        )
        assert decision.allowed is False, record_id
        assert decision.reason in mem.DENY_ORDER, record_id

    normalized = records["mem-family-unapproved"]
    assert normalized.status == "PENDING_CONFIRMATION"
    assert normalized.memory_policy == "candidate_only"
    assert records["mem-deleted"].status == "DELETED"


# ---------------------------------------------------------------------------
# 2. §8.4 契约补充用例：M2.1 真实可达的正例必须非空
# ---------------------------------------------------------------------------


def _family_record(**overrides: Any) -> MemoryRecord:
    base: dict[str, Any] = {
        "id": RECORD_ID,
        "owner_id": OWNER,
        "scope": "FAMILY",
        "memory_class": "EVENT",
        "source_type": "explicit_user",
        "source_member_id": OWNER,
        "content": "合成共享事项",
        "confidence": 1.0,
        "importance": 0.5,
        "created_at": NOW,
        "updated_at": NOW,
        "last_confirmed_at": NOW,
        "expires_at": _iso(_epoch() + timedelta(days=mem.DEFAULT_TTL_EVENT_DAYS)),
        "source_session_id": None,
        "status": "ACTIVE",
        "memory_policy": "persist_confirmed",
        "audiences": frozenset({AUDIENCE}),
        "consent_version": 1,
        "source_ids": (),
    }
    base.update(overrides)
    return MemoryRecord(**base)


def _record_needing_grant(**overrides: Any) -> MemoryRecord:
    """一个**需要 grant** 的记录：``FAMILY`` 但受众不命中本次 ``AUDIENCE``。

    A5'（主控 2026-09-26 裁决）之后，``FAMILY`` + 受众命中 + **读取动作**的记录完全
    豁免 grant；要构造 grant 级拒绝（``expired`` / ``wrong_*`` / ``resource_not_granted`` /
    ``stale_consent``）就必须先把记录挪出豁免范围。受众不命中是最自然的做法 ——
    它同时说明「这条记录本来就不该被这次会话读到」。
    """
    overrides.setdefault("audiences", frozenset({"not-this-audience"}))
    return _family_record(**overrides)


def test_supplementary_case_family_event_positive() -> None:
    """``m2_1_family_event_positive``：FAMILY + EVENT 的普通共享记忆。"""

    decision = authorize(
        action="read_model",
        access=SessionAccess(),
        grant=None,
        session_id="session-2",
        audience_id=AUDIENCE,
        records=(_family_record(),),
        now=NOW,
    )
    assert decision == mem.ALLOWED
    assert CONTRACT_SUPPLEMENTARY_CASES["m2_1_family_event_positive"]["outcome"] == "ok"


def test_supplementary_case_family_safety_class_positive() -> None:
    """``m2_1_family_safety_class_positive``：FAMILY scope 下 SAFETY **类**不受相位限制。

    过敏这类内容类型在 FAMILY scope 下照常支持，且按 D5 确认后不过期
    （``expires_at is None``）。相位限制管的是 scope，不是 memory_class。
    """

    record = _family_record(
        id="sup-family-allergy",
        memory_class="SAFETY",
        expires_at=None,
        content="合成过敏事项",
    )
    decision = authorize(
        action="read_model",
        access=SessionAccess(),
        grant=None,
        session_id="session-2",
        audience_id=AUDIENCE,
        records=(record,),
        now=NOW,
    )
    assert decision == mem.ALLOWED
    assert "SAFETY" not in mem.M2_1_ALLOWED_SCOPES, "相位限制针对 scope，不是 memory_class"


@pytest.mark.parametrize(
    ("case_id", "scope", "memory_class"),
    [
        ("m2_1_personal_scope_write_denied", "PERSONAL", "EVENT"),
        ("m2_1_safety_scope_write_denied", "SAFETY", "SAFETY"),
    ],
)
def test_supplementary_scope_write_denials(case_id: str, scope: str, memory_class: str) -> None:
    """PERSONAL / SAFETY **scope** 的写路径在 M2.1 一律 ``scope_not_enabled``。

    ``m2_1_auto_extracted_origin_rejected`` 不在本文件：那是 ``propose()``（W3）
    对 ``origin`` 的校验，不属于判权函数。
    """

    record = _family_record(id="sup-scope-denied", scope=scope, memory_class=memory_class)
    grant = _grant(actions=frozenset({"write"}), resource_ids=frozenset({record.id}))
    decision = authorize(
        action="write",
        access=_owner_bound_access(OWNER),
        grant=grant,
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        records=(record,),
        now=NOW,
    )
    assert decision.reason == CONTRACT_SUPPLEMENTARY_CASES[case_id]["outcome"]
    assert decision.allowed is False


def test_m2_1_reachable_positives_are_not_empty() -> None:
    """防作弊断言在 W2 这一侧同样成立：可达正例非空且包含三条登记的 case。"""

    positives = {"approved_family_visible", "m2_1_family_event_positive", "m2_1_family_safety_class_positive"}
    for name in positives:
        assert name in FIXTURE_CASE_MAPPING or name in CONTRACT_SUPPLEMENTARY_CASES
    assert FIXTURE_CASE_MAPPING["approved_family_visible"]["m2_1_reason"] == "ok"
    assert CONTRACT_SUPPLEMENTARY_CASES["m2_1_family_event_positive"]["outcome"] == "ok"
    assert CONTRACT_SUPPLEMENTARY_CASES["m2_1_family_safety_class_positive"]["outcome"] == "ok"


# ---------------------------------------------------------------------------
# 3. 判权基线与 DENY_ORDER 的逐条 / 按序断言（§8.6）
# ---------------------------------------------------------------------------


def _grant(**overrides: Any) -> Grant:
    base: dict[str, Any] = {
        "grant_id": GRANT_ID,
        "version": 1,
        "session_id": SESSION_ID,
        "subject_id": OWNER,
        "owner_id": OWNER,
        "audience_id": AUDIENCE,
        "actions": frozenset({"read_model"}),
        "resource_ids": frozenset({RECORD_ID}),
        "consent_versions": ((RECORD_ID, 1),),
        "expires_at": _iso(_epoch() + timedelta(hours=1)),
        "issuer": "local_control_plane",
        "issued_at": NOW,
    }
    base.update(overrides)
    return Grant(**base)


def _corrupt(record: MemoryRecord, **overrides: Any) -> MemoryRecord:
    """模拟「从损坏 / 未来 schema 的库里读出来的记录」：绕过 dataclass 校验改字段。"""

    clone = dataclasses.replace(record)
    for name, value in overrides.items():
        object.__setattr__(clone, name, value)
    return clone


#: ``authorize()`` **真的会产出**的拒绝原因 = ``DENY_ORDER`` 去掉 ``revoked``。
#:
#: 主控 2026-09-26 仲裁：``revoked`` 属**存储层语义** —— ``GrantStore.revoke`` 把
#: ``revoked_at`` 写到全部版本上，``load_current`` / ``load_for_session`` 对已撤销的
#: grant 返回 ``None``，因此判权看到的是 ``no_grant``；``authorize()`` 不读
#: ``revoked_at``，也就没有产出 ``revoked`` 的分支。``revoked`` 仍留在
#: ``DENY_ORDER`` / ``REASONS`` 里（契约测试锁定，供审计与 M2.2 复用），
#: 因此涉及判权产出集合的用例用这个元组，而不是直接遍历 ``DENY_ORDER``。
AUTHORIZE_DENY_ORDER: tuple[str, ...] = tuple(r for r in DENY_ORDER if r != "revoked")


def _baseline() -> dict[str, Any]:
    """一个**全部检查都通过**的判权输入，作为逐条反例的对照基线。"""

    return {
        "action": "read_model",
        "access": _owner_bound_access(OWNER),
        "grant": _grant(),
        "session_id": SESSION_ID,
        "audience_id": AUDIENCE,
        "records": (_family_record(),),
        "now": NOW,
    }


def _violating_inputs(*reasons: str) -> dict[str, Any]:
    """构造**同时违反** ``reasons`` 全部检查的输入（各扰动可组合，用于按序断言）。"""

    kwargs = _baseline()
    record_overrides: dict[str, Any] = {}
    grant_overrides: dict[str, Any] = {}
    grant_is_none = False

    for reason in reasons:
        if reason == "clock_invalid":
            kwargs["now"] = None
        elif reason == "no_grant":
            grant_is_none = True
            record_overrides["audiences"] = frozenset()  # 家庭共享例外不再成立
        elif reason == "expired":
            grant_overrides["expires_at"] = NOW  # 边界：now >= expires_at
            record_overrides["audiences"] = frozenset({"not-this-audience"})  # A5' 解豁免
        elif reason == "not_yet_valid":
            # B-s1：grant 时间窗的左端。issued_at 在 now 之后即「还没生效」。
            # 记录同样要解除 A5' 豁免，否则 grant 段整段被跳过。
            grant_overrides["issued_at"] = _iso(_epoch() + timedelta(minutes=30))
            record_overrides["audiences"] = frozenset({"not-this-audience"})
        elif reason == "record_expired":
            # B2：记录自身到期。**记录级检查**，豁免记录同样执行 —— 不需要解豁免。
            record_overrides["expires_at"] = _iso(_epoch() - timedelta(seconds=1))
        elif reason == "wrong_session":
            kwargs["session_id"] = "session-other"
            record_overrides["audiences"] = frozenset({"not-this-audience"})
        elif reason == "wrong_owner":
            kwargs["access"] = _owner_bound_access("adult_b")
            record_overrides["audiences"] = frozenset({"not-this-audience"})
        elif reason == "wrong_audience":
            kwargs["audience_id"] = "adult_b"  # 受众不命中本身就解除了豁免
        elif reason == "action_not_granted":
            kwargs["action"] = "delete"
        elif reason == "resource_not_granted":
            grant_overrides["resource_ids"] = frozenset({"rec-other"})
            record_overrides["audiences"] = frozenset({"not-this-audience"})  # A5' 解豁免
        elif reason == "missing_provenance":
            record_overrides["source_ids"] = ("rec-ghost",)
        elif reason == "scope_not_enabled":
            record_overrides["scope"] = "PERSONAL"
        elif reason == "scope_denied":
            record_overrides["audiences"] = frozenset()
        elif reason == "policy_denied":
            record_overrides["memory_policy"] = "do_not_persist"
        elif reason == "status_denied":
            record_overrides["status"] = "DECAYED"
        elif reason == "stale_consent":
            record_overrides["consent_version"] = 2
        else:  # pragma: no cover - 表驱动，写错名字当场失败
            raise AssertionError(f"unknown reason: {reason}")

    if record_overrides:
        kwargs["records"] = (_corrupt(_family_record(), **record_overrides),)
    if grant_is_none:
        kwargs["grant"] = None
    elif grant_overrides:
        kwargs["grant"] = _grant(**grant_overrides)
    return kwargs


#: A5' 之后，**读取路径**上不可达的原因。
#:
#: ``FAMILY`` + 受众命中 + 读取动作的记录完全豁免 grant，因此同意版本不参与读取判权。
#: 让它可达必须同时满足「受众命中」（否则 ``scope_denied`` 先命中）与「需要 grant」
#: （即换一个非读取动作）—— 这没法在「基线 = 读取」的逐条反例里构造，
#: 因此单列 ``test_stale_consent_binds_grant_requiring_actions``。
READ_PATH_UNREACHABLE_REASONS: frozenset[str] = frozenset({"stale_consent"})


@pytest.mark.parametrize(
    "reason", [r for r in AUTHORIZE_DENY_ORDER if r not in READ_PATH_UNREACHABLE_REASONS]
)
def test_each_denial_reason_is_reachable_on_its_own(reason: str) -> None:
    """每条判权拒绝路径都必须有一个「只违反它」的输入 —— 否则它就是不可达的摆设。"""

    decision = authorize(**_violating_inputs(reason))
    assert decision.allowed is False
    assert decision.reason == reason


def test_revoked_is_store_layer_semantics_not_a_policy_branch() -> None:
    """主控仲裁：``revoked`` 由存储层落成 ``no_grant``，判权没有产出它的分支。"""

    # 集成时由主控（W0 契约 owner）按 A4 改成反向断言：撤销归存储层，判权层连枚举值
    # 都不保留 —— `revoked` 不是一个**可达**的判权结论，留在 REASONS 里会让
    # 「撤销状态没读到」看起来像正常的拒绝理由。
    assert "revoked" not in DENY_ORDER, "A4：revoked 不是判权结论"
    assert "revoked" not in mem.REASONS
    assert "revoked" not in AUTHORIZE_DENY_ORDER
    assert not hasattr(policy_module, "_is_revoked"), "判权不读 grant 上的 revoked_at"


def test_deny_order_perturbations_do_not_disturb_the_baseline() -> None:
    """基线本身必须 ``ok``：否则逐条反例断言会因为别的原因变红而失去意义。"""

    assert authorize(**_baseline()) == mem.ALLOWED


@pytest.mark.parametrize(
    ("index", "expected"),
    [
        (index, reason)
        for index, reason in enumerate(DENY_ORDER)
        if reason in AUTHORIZE_DENY_ORDER and reason not in READ_PATH_UNREACHABLE_REASONS
    ],
    ids=[
        reason
        for reason in DENY_ORDER
        if reason in AUTHORIZE_DENY_ORDER and reason not in READ_PATH_UNREACHABLE_REASONS
    ],
)
def test_deny_order_reports_the_first_failure_of_the_suffix(index: int, expected: str) -> None:
    """**按序报第一个**：累积违反 ``DENY_ORDER[index:]`` 时，报的必须是 ``DENY_ORDER[index]``。

    这比「两两相邻」更强：它一次性锁定了整条链的顺序 —— 任何重排、合并分支、
    或「先收集全部失败再挑一个报」都会在某个 index 上变红。

    后缀里的 ``revoked`` 没有对应扰动（存储层语义，递不到判权），不影响顺序断言：
    它前面的 ``no_grant`` 与后面的 ``expired`` 各自由相邻的 index 锁定。
    """

    decision = authorize(
        **_violating_inputs(*(r for r in DENY_ORDER[index:] if r in AUTHORIZE_DENY_ORDER))
    )
    assert decision.reason == expected


def test_clock_invalid_precedes_everything_even_an_expired_grant() -> None:
    decision = authorize(**_violating_inputs("clock_invalid", "expired", "stale_consent"))
    assert decision.reason == "clock_invalid"


@pytest.mark.parametrize(
    "now",
    [None, "", "   ", "not-a-timestamp", "2026-13-45T99:00:00Z", 12345, _epoch(), "2026-09-24T12:00:00"],
)
def test_clock_invalid_covers_every_unusable_clock(now: object) -> None:
    """时钟缺失、不可解析、非字符串、**无时区的 naive 时间戳**一律 ``clock_invalid``。"""

    kwargs = _baseline()
    kwargs["now"] = now
    assert authorize(**kwargs).reason == "clock_invalid"


def test_expiry_boundary_is_fail_closed() -> None:
    """``now >= expires_at`` 取 ``>=``：正好到期即拒绝，早一秒才放行。"""

    boundary = _violating_inputs("expired")
    assert authorize(**boundary).reason == "expired"

    just_before = _baseline()
    just_before["grant"] = _grant(expires_at=_iso(_epoch() + timedelta(seconds=1)))
    assert authorize(**just_before) == mem.ALLOWED

    # A5'：同一条过期 grant 在**豁免**的家庭共享读取上不再构成拒绝。
    exempt = _baseline()
    exempt["grant"] = _grant(expires_at=NOW)
    assert authorize(**exempt) == mem.ALLOWED


@pytest.mark.parametrize("action", ["write", "share", "delete"])
def test_write_actions_never_have_a_grant_free_path(action: str) -> None:
    """契约 §3.3：写动作永远需要成人控制面授权，不存在无 grant 的写路径。"""

    kwargs = _baseline()
    kwargs["action"] = action
    kwargs["grant"] = None
    assert authorize(**kwargs).reason == "no_grant"


@pytest.mark.parametrize("action", ["publish_text", "play_audio"])
def test_output_actions_need_a_grant_even_for_family_records(action: str) -> None:
    """出口动作（外放）不在无 grant 例外里：授权给家人绝不等于可以外放（§2.1）。

    即使受众命中 FAMILY 记录、即使该记录的 ``audiences`` 含 ``public_room``，
    出口动作仍必须有 grant。这是本实现把例外读成「受众命中**读取**」的 fail-closed
    读法（契约口径需 r3 明确，见 W2 交付报告）。
    """

    kwargs = _baseline()
    kwargs["action"] = action
    kwargs["grant"] = None
    assert authorize(**kwargs).reason == "no_grant"

    public = _family_record(audiences=frozenset({AUDIENCE, "public_room"}))
    kwargs["records"] = (public,)
    kwargs["audience_id"] = "public_room"
    assert authorize(**kwargs).reason == "no_grant"

    with_grant = _baseline() | {
        "action": action,
        "audience_id": "public_room",
        "records": (public,),
        "grant": _grant(actions=frozenset({action}), audience_id="public_room"),
    }
    assert authorize(**with_grant) == mem.ALLOWED


def test_family_audience_hit_without_grant_is_allowed_for_reads() -> None:
    """``no_grant`` 例外的正向面：FAMILY + 受众命中的读取不需要 grant。"""

    for action in ("read_model", "send_provider"):
        kwargs = _baseline()
        kwargs["action"] = action
        kwargs["grant"] = None
        assert authorize(**kwargs) == mem.ALLOWED, action


def test_a_present_grant_does_not_close_the_shared_path() -> None:
    """**A5'（主控 2026-09-26 裁决）**：FAMILY + 受众命中的读取**完全无视 grant**。

    本轮集成改写了 W2 原先的冻结口径。原稿锁的是「例外只豁免『没有 grant』——
    有 grant 时 grant 检查照常执行（fail-closed）」；裁决改成逐条豁免，理由是：
    §3.3 的受众表写明「``FAMILY`` | ``audience_id ∈ record.audiences``。
    **不需要 grant**」，而且**一个为私人会话签发的 grant 不能把全家的共享记忆关掉**。

    因此这里断言的是原稿的**反面**：同一批「本来会拒绝」的 grant 缺陷
    （过期 / 错 owner / 错 session / 同意版本不符），在 FAMILY + 受众命中的读取上
    一律不再构成拒绝。
    """

    for reason in ("expired", "wrong_owner", "wrong_session", "stale_consent"):
        kwargs = _baseline()
        if reason == "expired":
            kwargs["grant"] = _grant(expires_at=NOW)
        elif reason == "wrong_owner":
            kwargs["access"] = _owner_bound_access("adult_b")
        elif reason == "wrong_session":
            kwargs["session_id"] = "session-other"
        else:
            kwargs["records"] = (_corrupt(_family_record(), consent_version=2),)
        assert kwargs["records"][0].scope == "FAMILY", "豁免条件本身成立（FAMILY + 受众命中）"
        assert authorize(**kwargs) == mem.ALLOWED, reason


def test_family_record_with_uncovered_grant_is_ok() -> None:
    """裁决点名的正例：**有 grant、grant 未覆盖该 FAMILY 记录、受众命中 → ``ok``**。"""

    kwargs = _baseline()
    kwargs["grant"] = _grant(resource_ids=frozenset({"rec-other"}))
    assert authorize(**kwargs) == mem.ALLOWED


def test_family_record_with_mismatched_audience_is_denied() -> None:
    """裁决点名的反例一：**有 grant、FAMILY 但受众不命中 → 拒**。"""

    kwargs = _baseline()
    kwargs["audience_id"] = "public_room"  # 记录只对 family_all 共享
    decision = authorize(**kwargs)
    assert decision.allowed is False, "受众不命中不得因为 grant 在场被放过"


def test_personal_record_with_uncovered_grant_is_denied() -> None:
    """裁决点名的反例二：**有 grant 且 PERSONAL 未覆盖 → 仍拒**。"""

    kwargs = _baseline()
    kwargs["records"] = (_corrupt(_family_record(), scope="PERSONAL"),)
    kwargs["grant"] = _grant(resource_ids=frozenset({"rec-other"}))
    decision = authorize(**kwargs)
    assert decision.allowed is False
    assert decision.reason == "resource_not_granted"


def test_grant_is_still_required_off_the_shared_path() -> None:
    """A5' 的边界：豁免只对 FAMILY + 受众命中 + 读取动作成立，其余照旧需要 grant。"""

    # FAMILY 但受众不命中 → 不在豁免范围 → grant 缺陷照常拒绝。
    mismatched = _baseline()
    mismatched["audience_id"] = "adult_b"
    mismatched["grant"] = _grant(expires_at=NOW, audience_id="adult_b")
    assert authorize(**mismatched).reason == "expired"

    # 动作不是读取（出口 / 写）→ 不在豁免范围。
    for action in ("write", "publish_text", "play_audio"):
        kwargs = _baseline()
        kwargs["action"] = action
        kwargs["grant"] = _grant(
            expires_at=NOW, actions=frozenset({"read_model", action})
        )
        assert authorize(**kwargs).reason == "expired", action

    # 不带 grant 的家庭共享读取照旧放行（A5 的动作白名单仍然成立）。
    plain = _baseline()
    plain["grant"] = None
    assert authorize(**plain) == mem.ALLOWED


def test_empty_records_need_a_grant() -> None:
    """没有记录就没有受众命中 —— 无 grant 时不做例外（fail-closed）。"""

    kwargs = _baseline()
    kwargs["grant"] = None
    kwargs["records"] = ()
    assert authorize(**kwargs).reason == "no_grant"

    with_grant = _baseline()
    with_grant["records"] = ()
    assert authorize(**with_grant) == mem.ALLOWED


def test_one_record_off_the_shared_path_requires_a_grant_for_the_whole_call() -> None:
    """例外必须对每条记录成立：混入一条非家庭共享记录时，整次调用都需要 grant。"""

    kwargs = _baseline()
    kwargs["grant"] = None
    kwargs["records"] = (_family_record(), _family_record(id="rec-2", audiences=frozenset()))
    assert authorize(**kwargs).reason == "no_grant"


def test_missing_provenance_covers_both_gap_and_cycle() -> None:
    """血缘缺源与成环都是 ``missing_provenance``（契约 §7.4 的 fail-closed 语义）。"""

    gap = _violating_inputs("missing_provenance")
    assert authorize(**gap).reason == "missing_provenance"

    cycle_a = _family_record(id="rec-a", source_ids=("rec-b",))
    cycle_b = _family_record(id="rec-b", source_ids=("rec-a",))
    kwargs = _baseline()
    kwargs["grant"] = _grant(
        resource_ids=frozenset({"rec-a", "rec-b"}),
        consent_versions=(("rec-a", 1), ("rec-b", 1)),
    )
    kwargs["records"] = (cycle_a, cycle_b)
    assert authorize(**kwargs).reason == "missing_provenance"

    derived = _family_record(id="rec-derived", source_ids=(RECORD_ID,))
    kwargs = _baseline()
    kwargs["grant"] = _grant(
        resource_ids=frozenset({RECORD_ID, "rec-derived"}),
        consent_versions=((RECORD_ID, 1), ("rec-derived", 1)),
    )
    kwargs["records"] = (_family_record(), derived)
    assert authorize(**kwargs) == mem.ALLOWED, "闭包完整时派生记录必须放行"

    # 自环与三节点环同样是成环。
    self_loop = _family_record(id="rec-self", source_ids=("rec-self",))
    kwargs = _baseline()
    kwargs["grant"] = _grant(
        resource_ids=frozenset({"rec-self"}), consent_versions=(("rec-self", 1),)
    )
    kwargs["records"] = (self_loop,)
    assert authorize(**kwargs).reason == "missing_provenance"

    ring = (
        _family_record(id="rec-a", source_ids=("rec-b",)),
        _family_record(id="rec-b", source_ids=("rec-c",)),
        _family_record(id="rec-c", source_ids=("rec-a",)),
    )
    ring_ids = frozenset({"rec-a", "rec-b", "rec-c"})
    kwargs = _baseline()
    kwargs["grant"] = _grant(
        resource_ids=ring_ids,
        consent_versions=tuple((record_id, 1) for record_id in sorted(ring_ids)),
    )
    kwargs["records"] = ring
    assert authorize(**kwargs).reason == "missing_provenance"

    # 菱形血缘（共享祖先）**不是**成环：不得误报。
    diamond = (
        _family_record(id="rec-root"),
        _family_record(id="rec-left", source_ids=("rec-root",)),
        _family_record(id="rec-right", source_ids=("rec-root",)),
        _family_record(id="rec-join", source_ids=("rec-left", "rec-right")),
    )
    diamond_ids = frozenset({"rec-root", "rec-left", "rec-right", "rec-join"})
    kwargs = _baseline()
    kwargs["grant"] = _grant(
        resource_ids=diamond_ids,
        consent_versions=tuple((record_id, 1) for record_id in sorted(diamond_ids)),
    )
    kwargs["records"] = diamond
    assert authorize(**kwargs) == mem.ALLOWED, "共享祖先的 DAG 不是环"


@pytest.mark.parametrize(
    ("scope", "reason"),
    [("PERSONAL", "scope_not_enabled"), ("SAFETY", "scope_not_enabled")],
)
def test_phase_disabled_scopes_are_denied_for_reads_and_writes(scope: str, reason: str) -> None:
    """M2.1 主路径：``PERSONAL`` / ``SAFETY`` **scope** 读写皆拒，reason ``scope_not_enabled``。"""

    record = _family_record(id="rec-phase", scope=scope, memory_class="SAFETY" if scope == "SAFETY" else "EVENT")
    for action in ("read_model", "write"):
        kwargs = _baseline()
        kwargs["action"] = action
        kwargs["records"] = (record,)
        kwargs["grant"] = _grant(
            actions=frozenset({action}),
            resource_ids=frozenset({record.id}),
            consent_versions=((record.id, 1),),
        )
        assert authorize(**kwargs).reason == reason, action


def test_scope_not_enabled_precedes_scope_denied() -> None:
    """刻意的相邻关系 1：整个 scope 没启用，比「受众读不到这条记录」更基本。"""

    record = _family_record(id="rec-phase", scope="PERSONAL", audiences=frozenset())
    kwargs = _baseline()
    kwargs["records"] = (record,)
    kwargs["grant"] = _grant(
        resource_ids=frozenset({record.id}),
        consent_versions=((record.id, 1),),
    )
    assert authorize(**kwargs).reason == "scope_not_enabled"


def test_family_audience_mismatch_is_scope_denied() -> None:
    """``scope_denied`` 的 M2.1 分支：FAMILY 记录但受众不匹配。"""

    kwargs = _baseline()
    kwargs["grant"] = _grant(audience_id="adult_b")
    kwargs["audience_id"] = "adult_b"
    assert authorize(**kwargs).reason == "scope_denied"


def test_policy_denied_precedes_status_denied() -> None:
    """刻意的相邻关系 2：策略与状态不符是契约违规，不该被「状态不是 ACTIVE」掩盖。"""

    record = _corrupt(_family_record(), status="PENDING_CONFIRMATION", memory_policy="persist_confirmed")
    kwargs = _baseline()
    kwargs["records"] = (record,)
    assert authorize(**kwargs).reason == "policy_denied"


@pytest.mark.parametrize(
    ("overrides", "expect_policy_reason"),
    [
        ({"memory_policy": "do_not_persist"}, True),  # 情形 1
        ({"memory_policy": "future_schema_policy"}, True),  # 情形 2
        ({"status": "PENDING_CONFIRMATION", "memory_policy": "persist_confirmed"}, True),  # 情形 3
        ({"status": "ACTIVE", "memory_policy": "candidate_only"}, True),  # 情形 3（反向）
    ],
)
def test_policy_denied_covers_the_four_enumerated_situations(
    overrides: dict[str, Any], expect_policy_reason: bool
) -> None:
    """契约 §3.3 枚举的 ``policy_denied`` 情形（1–3）逐条可达；实现不得再发明别的。"""

    record = _corrupt(_family_record(), **overrides)
    kwargs = _baseline()
    kwargs["records"] = (record,)
    decision = authorize(**kwargs)
    assert decision.reason == ("policy_denied" if expect_policy_reason else "ok")


def test_policy_denied_situation_four_blocks_sharing_a_candidate() -> None:
    """情形 4：``action == "share"`` 而记录是候选 —— 共享必须走 ``confirm_shared()``。"""

    candidate = _family_record(
        id="rec-candidate",
        status="PENDING_CONFIRMATION",
        memory_policy="candidate_only",
        last_confirmed_at=None,
        expires_at=_iso(_epoch() + timedelta(days=mem.DEFAULT_TTL_CANDIDATE_DAYS)),
    )
    kwargs = _baseline()
    kwargs["action"] = "share"
    kwargs["grant"] = _grant(
        actions=frozenset({"share"}),
        resource_ids=frozenset({candidate.id}),
        consent_versions=((candidate.id, 1),),
    )
    kwargs["records"] = (candidate,)
    assert authorize(**kwargs).reason == "policy_denied"

    # 同一份候选走 read_model 不触发情形 4，落到 status_denied —— 说明区分是真的。
    kwargs["action"] = "read_model"
    kwargs["grant"] = _grant(
        resource_ids=frozenset({candidate.id}),
        consent_versions=((candidate.id, 1),),
    )
    assert authorize(**kwargs).reason == "status_denied"


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"status": "PENDING_CONFIRMATION", "memory_policy": "candidate_only", "last_confirmed_at": None}, "status_denied"),
        ({"status": "DECAYED"}, "status_denied"),
        ({"status": "DELETED", "content": ""}, "status_denied"),
        ({"status": "FUTURE_STATUS"}, "status_denied"),
    ],
)
def test_status_denied_covers_candidate_decayed_and_tombstone(
    overrides: dict[str, Any], expected: str
) -> None:
    """只有 ``ACTIVE`` 可召回：候选、``DECAYED``、墓碑都不可。"""

    record = _corrupt(_family_record(), **overrides)
    kwargs = _baseline()
    kwargs["records"] = (record,)
    assert authorize(**kwargs).reason == expected


def test_stale_consent_binds_grant_requiring_actions() -> None:
    """重新确认会递增 ``consent_version``，旧 grant 对**需要 grant 的动作**立刻失效。"""

    kwargs = _baseline()
    kwargs["action"] = "write"
    kwargs["grant"] = _grant(actions=frozenset({"read_model", "write"}))
    kwargs["records"] = (_corrupt(_family_record(), consent_version=2),)
    assert authorize(**kwargs).reason == "stale_consent"
    assert DENY_ORDER[-1] == "stale_consent"

    refreshed = _baseline()
    refreshed["action"] = "write"
    refreshed["grant"] = _grant(
        actions=frozenset({"read_model", "write"}), consent_versions=((RECORD_ID, 2),)
    )
    refreshed["records"] = (_corrupt(_family_record(), consent_version=2),)
    assert authorize(**refreshed) == mem.ALLOWED


def test_stale_consent_does_not_bind_grant_exempt_reads() -> None:
    """A5' 的后果，显式钉住：FAMILY + 受众命中的**读取**不看 consent 版本。

    这不削弱重新确认的效果 —— 读取路径本来就不需要 grant，也就没有同意绑定可比。
    """

    kwargs = _baseline()
    kwargs["records"] = (_corrupt(_family_record(), consent_version=2),)
    assert authorize(**kwargs) == mem.ALLOWED


def test_multi_record_denial_follows_deny_order_not_record_order() -> None:
    """多记录调用：外层是 ``DENY_ORDER``、内层才是记录顺序。"""

    shared_ok = _family_record(id=RECORD_ID)
    audience_miss = _family_record(id="rec-2", audiences=frozenset())
    status_bad = _family_record(id="rec-3", status="DECAYED")
    grant = _grant(
        resource_ids=frozenset({RECORD_ID, "rec-2", "rec-3"}),
        consent_versions=((RECORD_ID, 1), ("rec-2", 1), ("rec-3", 1)),
    )
    for records in ((shared_ok, audience_miss, status_bad), (status_bad, audience_miss, shared_ok)):
        decision = authorize(**_baseline() | {"records": records, "grant": grant})
        assert decision.reason == "scope_denied", "更靠前的步骤优先，与记录顺序无关"

    all_ok = _baseline() | {
        "records": (shared_ok, _family_record(id="rec-2")),
        "grant": _grant(
            resource_ids=frozenset({RECORD_ID, "rec-2"}),
            consent_versions=((RECORD_ID, 1), ("rec-2", 1)),
        ),
    }
    assert authorize(**all_ok) == mem.ALLOWED


def test_authorize_is_pure_and_deterministic() -> None:
    """纯函数：同样的输入永远同样的结论，且不改动入参对象。"""

    kwargs = _baseline()
    records_before = tuple(kwargs["records"])
    grant_before = kwargs["grant"]
    first = authorize(**kwargs)
    second = authorize(**kwargs)
    assert first == second == mem.ALLOWED
    assert tuple(kwargs["records"]) == records_before
    assert kwargs["grant"] == grant_before
    assert kwargs["grant"] is grant_before


def test_authorize_never_raises_on_unusable_inputs() -> None:
    """契约 §3.1：**任何异常路径都返回拒绝**，不抛异常。"""

    for access in (None, "not-an-access", object()):
        kwargs = _baseline()
        kwargs["access"] = access
        assert authorize(**kwargs).reason == "no_grant"

    kwargs = _baseline()
    kwargs["grant"] = {"grant_id": GRANT_ID}
    assert authorize(**kwargs).reason == "no_grant"


def test_scope_denied_m2_2_branches_are_implemented() -> None:
    """M2.2 的两行必须现在就写好（否则 M2.2 要改契约）。

    ``authorize()`` 在 M2.1 恒被 ``scope_not_enabled`` 先拦下，走不到这两行，
    因此这里直接核对判定片段本身：``controlled_private`` 会话 + owner 一致才放行。
    """

    private = _family_record(id="rec-private", scope="PERSONAL")
    for scope in ("PERSONAL", "SAFETY"):
        record = private if scope == "PERSONAL" else _family_record(
            id="rec-safety", scope="SAFETY", memory_class="SAFETY"
        )
        assert policy_module._scope_denied(
            record=record,
            access=_owner_bound_access(OWNER, session_mode="controlled_private"),
            audience_id=AUDIENCE,
        ) is False, scope
        assert policy_module._scope_denied(
            record=record, access=_owner_bound_access(OWNER), audience_id=AUDIENCE
        ) is True, f"{scope} in a shared session"
        assert policy_module._scope_denied(
            record=record,
            access=_owner_bound_access("adult_b", session_mode="controlled_private"),
            audience_id=AUDIENCE,
        ) is True, f"{scope} cross-owner"
        assert policy_module._scope_denied(
            record=record, access=SessionAccess(), audience_id=AUDIENCE
        ) is True, f"{scope} without owner"

    assert policy_module._scope_denied(
        record=_family_record(), access=SessionAccess(), audience_id=AUDIENCE
    ) is False
    assert policy_module._scope_denied(
        record=_corrupt(_family_record(), scope="FUTURE_SCOPE"),
        access=SessionAccess(),
        audience_id=AUDIENCE,
    ) is True, "未知 scope（DDL 已排除）必须 fail-closed"


def test_require_returns_the_decision_and_raises_with_it() -> None:
    """``require()`` 是写路径：放行返回同一个结论，拒绝时抛携带结论的异常。"""

    allowed = require(**_baseline())
    assert allowed == mem.ALLOWED

    denied_kwargs = _baseline()
    denied_kwargs["action"] = "write"
    denied_kwargs["grant"] = None
    with pytest.raises(AuthorizationError) as excinfo:
        require(**denied_kwargs)
    assert excinfo.value.decision.reason == "no_grant"
    assert excinfo.value.decision.allowed is False

    caught = _violating_inputs("scope_not_enabled")
    caught["action"] = "write"
    caught["grant"] = _grant(actions=frozenset({"write"}))
    with pytest.raises(AuthorizationError) as excinfo:
        require(**caught)
    assert excinfo.value.decision.reason == "scope_not_enabled"


# ===========================================================================
# 4. grant 存储（``grants.py``，W2）：issue / revoke / load_current /
#    load_for_session 与 ``load_grant_for_session``
# ===========================================================================


def _create_memory_schema(db_path: Path) -> Path:
    """测试适配器：按冻结的 DDL 建库（0600）。

    ``SqliteMemoryStore.create_schema()`` 归 W1，尚未落地；这里只执行
    :data:`soul_memory_kernel.memory.MEMORY_SCHEMA_DDL` 并写 ``PRAGMA user_version``，
    **不实现任何 W1 逻辑**。``SqliteGrantStore`` 自己不建库、不建表。
    """

    db_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    db = sqlite3.connect(db_path, isolation_level=None)
    with closing(db):
        db.execute("BEGIN IMMEDIATE")
        for ddl in mem.MEMORY_SCHEMA_DDL:
            db.execute(ddl)
        db.execute(f"PRAGMA user_version = {mem.MEMORY_SCHEMA_VERSION}")
        db.execute("COMMIT")
    return db_path


def _raw(db_path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as db:
        return db.execute(sql, params).fetchall()


@pytest.fixture(name="grant_db")
def grant_db_fixture(tmp_path: Path) -> Path:
    return _create_memory_schema(tmp_path / "memory.sqlite3")


def _issued_grant(**overrides: Any) -> Grant:
    return _grant(**overrides)


def test_schema_adapter_creates_every_frozen_table(grant_db: Path) -> None:
    tables = {row[0] for row in _raw(grant_db, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert mem.MEMORY_TABLES <= tables
    assert stat.S_IMODE(grant_db.stat().st_mode) == 0o600


def test_grant_store_matches_the_frozen_class_and_protocol_shape() -> None:
    """§9.1 冻结 ``SqliteGrantStore(db_path)``；方法集 = ``GrantStore`` Protocol。"""

    params = inspect.signature(SqliteGrantStore.__init__).parameters
    # 契约 §9.1：db_path 必需；**可选参数可以加，但必须带默认值**。
    assert list(params)[:2] == ["self", "db_path"]
    for name, param in list(params.items())[2:]:
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, name
        assert param.default is not inspect.Parameter.empty, name
    assert params["db_path"].default is inspect.Parameter.empty

    for name in ("issue", "revoke", "load_current", "load_for_session"):
        assert hasattr(SqliteGrantStore, name), name
    assert list(inspect.signature(SqliteGrantStore.revoke).parameters) == [
        "self",
        "grant_id",
        "revoked_at",
        "actor",
    ]
    assert list(inspect.signature(SqliteGrantStore.load_current).parameters) == ["self", "grant_id"]
    assert list(inspect.signature(SqliteGrantStore.load_for_session).parameters) == [
        "self",
        "session_id",
    ]
    assert list(inspect.signature(load_grant_for_session).parameters) == ["db_path", "session_id"]


def test_issue_then_load_current_round_trips_every_field(grant_db: Path) -> None:
    store = SqliteGrantStore(grant_db)
    grant = _grant(
        actions=frozenset({"read_model", "send_provider"}),
        resource_ids=frozenset({RECORD_ID, "rec-2"}),
        consent_versions=((RECORD_ID, 1), ("rec-2", 3)),
    )
    store.issue(grant)
    loaded = store.load_current(GRANT_ID)
    assert loaded == grant, "load_current 必须逐字段还原签发的 grant"


def test_issue_appends_versions_and_keeps_history(grant_db: Path) -> None:
    """续签是新行：旧版本保留供审计，``load_current`` 取最新版本。"""

    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1, actions=frozenset({"read_model"})))
    store.issue(
        _grant(
            version=2,
            actions=frozenset({"read_model", "write"}),
            resource_ids=frozenset({RECORD_ID, "rec-2"}),
            consent_versions=((RECORD_ID, 1), ("rec-2", 1)),
        )
    )
    loaded = store.load_current(GRANT_ID)
    assert loaded is not None and loaded.version == 2
    assert loaded.actions == frozenset({"read_model", "write"})
    assert loaded.resource_ids == frozenset({RECORD_ID, "rec-2"})

    rows = _raw(grant_db, "SELECT version FROM grant_record WHERE grant_id = ? ORDER BY version", (GRANT_ID,))
    assert [row[0] for row in rows] == [1, 2], "旧版本必须保留供审计"
    actions = _raw(
        grant_db,
        "SELECT action FROM grant_action WHERE grant_id = ? AND grant_version = 1 ORDER BY action",
        (GRANT_ID,),
    )
    assert [row[0] for row in actions] == ["read_model"]


@pytest.mark.parametrize("version", [1, 0, -3, True, "2", None])
def test_issue_rejects_non_increasing_or_non_integer_versions(grant_db: Path, version: object) -> None:
    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    with pytest.raises(mem.MemoryValidationError):
        store.issue(_grant(version=version))
    assert _raw(grant_db, "SELECT COUNT(*) FROM grant_record")[0][0] == 1


@pytest.mark.parametrize("field", ["grant_id", "session_id", "subject_id", "owner_id", "audience_id", "issuer"])
def test_issue_requires_every_identity_field(grant_db: Path, field: str) -> None:
    """``issuer`` 必填（Protocol 冻结），其余标识字段同样不允许空值。"""

    store = SqliteGrantStore(grant_db)
    with pytest.raises(mem.MemoryValidationError):
        store.issue(_grant(**{field: ""}))
    assert _raw(grant_db, "SELECT COUNT(*) FROM grant_record")[0][0] == 0


def test_issue_enforces_the_hard_ttl_bound(grant_db: Path) -> None:
    """``MAX_GRANT_TTL_SECONDS`` 是硬上界：正好 12h 放行，多一秒拒绝。

    主控 2026-09-26 裁决：**不为迁就 fixture 放宽隐私参数**，上限维持 12h；
    设计 fixture 的 ``grant-a-s1`` 窗口已同步缩到 12h（见契约 §8.1）。
    """

    store = SqliteGrantStore(grant_db)
    assert mem.MAX_GRANT_TTL_SECONDS == 12 * 60 * 60

    store.issue(_grant(expires_at=_iso(_epoch() + timedelta(seconds=mem.MAX_GRANT_TTL_SECONDS))))
    assert store.load_current(GRANT_ID) is not None

    with pytest.raises(mem.MemoryValidationError):
        store.issue(
            _grant(
                grant_id="grant-too-long",
                expires_at=_iso(_epoch() + timedelta(seconds=mem.MAX_GRANT_TTL_SECONDS + 1)),
            )
        )
    assert store.load_current("grant-too-long") is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"issued_at": NOW, "expires_at": NOW},  # TTL = 0
        {"expires_at": _iso(_epoch() - timedelta(hours=1))},  # 先过期再签发
        {"expires_at": "not-a-timestamp"},
        {"expires_at": "2026-09-24T13:00:00"},  # naive，无法证明是 UTC
        {"issued_at": "2026-09-24T12:00:00"},
        {"actions": frozenset({"future_action"})},
        {"actions": ["read_model"]},  # 类型不对（不是 frozenset）
        {"resource_ids": frozenset({"rec-2"})},  # 缺 consent 绑定
        {"consent_versions": ((RECORD_ID, 1), ("rec-2", 1))},  # 多出未授权的同意版本
        {"consent_versions": ((RECORD_ID, 0),)},
        {"consent_versions": ((RECORD_ID, 1), (RECORD_ID, 2))},  # 重复条目
        {"consent_versions": ((RECORD_ID, 1, "extra"),)},
    ],
)
def test_issue_rejects_malformed_grants_without_writing_anything(
    grant_db: Path, overrides: dict[str, Any]
) -> None:
    store = SqliteGrantStore(grant_db)
    with pytest.raises(mem.MemoryValidationError):
        store.issue(_grant(**overrides))
    for table in ("grant_record", "grant_action", "grant_resource"):
        assert _raw(grant_db, f"SELECT COUNT(*) FROM {table}")[0][0] == 0, table


def test_issue_rejects_a_revoked_grant_id_so_revocation_sticks(grant_db: Path) -> None:
    """撤销不可被新版本复活：重新授权必须换 ``grant_id``。"""

    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="adult_a"))
    with pytest.raises(mem.MemoryValidationError):
        store.issue(_grant(version=2))

    store.issue(_grant(grant_id="grant-w2-fresh", version=1))
    assert store.load_current("grant-w2-fresh") is not None


def test_revoke_invalidates_every_version(grant_db: Path) -> None:
    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    store.issue(_grant(version=2))
    store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="adult_a"))

    assert store.load_current(GRANT_ID) is None
    assert store.load_for_session(SESSION_ID) is None
    marked = _raw(
        grant_db,
        "SELECT version, revoked_at FROM grant_record WHERE grant_id = ? ORDER BY version",
        (GRANT_ID,),
    )
    assert [row[1] for row in marked] == [NOW, NOW], "撤销必须覆盖全部版本"


def test_revoke_is_idempotent_and_keeps_the_first_timestamp(grant_db: Path) -> None:
    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    actor = Actor(kind="adult_control_plane", actor_id="adult_a")
    store.revoke(GRANT_ID, revoked_at=NOW, actor=actor)
    later = _iso(_epoch() + timedelta(hours=2))
    store.revoke(GRANT_ID, revoked_at=later, actor=actor)
    store.revoke("grant-never-existed", revoked_at=later, actor=actor)  # 未知 id：no-op

    rows = _raw(grant_db, "SELECT revoked_at FROM grant_record WHERE grant_id = ?", (GRANT_ID,))
    assert rows == [(NOW,)]


@pytest.mark.parametrize("actor_kind", ["ttl_expiry", "migration"])
def test_revoke_requires_the_adult_control_plane(grant_db: Path, actor_kind: str) -> None:
    """撤销改变召回语义，只有 ``adult_control_plane`` 能做（契约 §2.4）。"""

    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    with pytest.raises(mem.MemoryValidationError):
        store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind=actor_kind, actor_id="x"))
    assert store.load_current(GRANT_ID) is not None, "被拒的撤销不得改动任何行"


@pytest.mark.parametrize("revoked_at", ["", "not-a-timestamp", "2026-09-24T12:00:00", None, 7])
def test_revoke_requires_a_valid_timestamp(grant_db: Path, revoked_at: object) -> None:
    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    with pytest.raises(mem.MemoryValidationError):
        store.revoke(
            GRANT_ID, revoked_at=revoked_at, actor=Actor(kind="adult_control_plane", actor_id="a")
        )
    assert store.load_current(GRANT_ID) is not None


def test_load_for_session_finds_the_newest_grant_of_that_session(grant_db: Path) -> None:
    store = SqliteGrantStore(grant_db)
    store.issue(_grant(grant_id="grant-old", issued_at=NOW, expires_at=_iso(_epoch() + timedelta(hours=1))))
    store.issue(
        _grant(
            grant_id="grant-new",
            issued_at=_iso(_epoch() + timedelta(minutes=1)),
            expires_at=_iso(_epoch() + timedelta(hours=2)),
        )
    )
    store.issue(_grant(grant_id="grant-other-session", session_id="session-other"))

    loaded = store.load_for_session(SESSION_ID)
    assert loaded is not None and loaded.grant_id == "grant-new"
    assert store.load_for_session("session-unknown") is None
    assert store.load_current("grant-unknown") is None


def test_load_for_session_does_not_filter_expired_grants(grant_db: Path) -> None:
    """契约明令：过期与否由 ``authorize()`` 判，store **不得**替它过滤。

    否则拒绝原因会从 ``expired`` 退化成 ``no_grant``，审计就查不出来了。
    """

    store = SqliteGrantStore(grant_db)
    expired = _grant(
        issued_at=_iso(_epoch() - timedelta(hours=2)),
        expires_at=_iso(_epoch() - timedelta(hours=1)),
    )
    store.issue(expired)
    loaded = store.load_for_session(SESSION_ID)
    assert loaded == expired, "过期的 grant 仍必须返回"

    decision = authorize(
        action="read_model",
        access=_owner_bound_access(OWNER),
        grant=loaded,
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        # A5'：家庭共享读取完全豁免 grant，因此过期必须用**需要 grant 的**记录来验。
        records=(_record_needing_grant(),),
        now=NOW,
    )
    assert decision.reason == "expired", "过期必须报 expired，而不是 no_grant"


def test_load_grant_for_session_wrapper_handles_every_degradation(grant_db: Path, tmp_path: Path) -> None:
    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    assert load_grant_for_session(grant_db, SESSION_ID) == _grant(version=1)
    assert load_grant_for_session(grant_db, "session-unknown") is None

    store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="adult_a"))
    assert load_grant_for_session(grant_db, SESSION_ID) is None

    missing = tmp_path / "not-created" / "memory.sqlite3"
    assert load_grant_for_session(missing, SESSION_ID) is None, "库不存在 = 没有 grant，不抛错"


def test_missing_database_degrades_reads_and_fails_writes(tmp_path: Path) -> None:
    """「文件不存在」与「文件坏了」必须区分：前者是正常的「没有 grant」。"""

    missing = tmp_path / "absent.sqlite3"
    store = SqliteGrantStore(missing)
    assert store.load_current(GRANT_ID) is None
    assert store.load_for_session(SESSION_ID) is None
    with pytest.raises(mem.StoreError):
        store.issue(_grant())
    assert not missing.exists(), "只读/失败路径都不得顺手创建库文件"
    with pytest.raises(mem.StoreError):
        store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="a"))


def test_wrong_schema_version_is_a_store_error_not_an_empty_result(tmp_path: Path) -> None:
    db_path = _create_memory_schema(tmp_path / "memory.sqlite3")
    with closing(sqlite3.connect(db_path)) as db:
        db.execute(f"PRAGMA user_version = {mem.MEMORY_SCHEMA_VERSION + 1}")
        db.commit()
    store = SqliteGrantStore(db_path)
    with pytest.raises(mem.StoreError):
        store.load_current(GRANT_ID)
    with pytest.raises(mem.StoreError):
        store.load_for_session(SESSION_ID)
    with pytest.raises(mem.StoreError):
        store.issue(_grant())


def test_database_without_the_grant_tables_is_a_store_error(tmp_path: Path) -> None:
    db_path = tmp_path / "memory.sqlite3"
    descriptor = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    with closing(sqlite3.connect(db_path)) as db:
        db.execute(f"PRAGMA user_version = {mem.MEMORY_SCHEMA_VERSION}")
        db.commit()
    store = SqliteGrantStore(db_path)
    with pytest.raises(mem.StoreError):
        store.load_current(GRANT_ID)
    with pytest.raises(mem.StoreError):
        store.issue(_grant())


def test_over_permissive_file_is_refused(tmp_path: Path) -> None:
    """权限过宽（组/其他可读）必须拒绝，而不是「读得到就先用着」。"""

    db_path = _create_memory_schema(tmp_path / "memory.sqlite3")
    os.chmod(db_path, 0o644)
    store = SqliteGrantStore(db_path)
    with pytest.raises(mem.StoreError):
        store.load_current(GRANT_ID)
    with pytest.raises(mem.StoreError):
        store.issue(_grant())


def test_symlinked_database_is_refused(tmp_path: Path) -> None:
    real = _create_memory_schema(tmp_path / "real.sqlite3")
    link = tmp_path / "link.sqlite3"
    link.symlink_to(real)
    store = SqliteGrantStore(link)
    with pytest.raises(mem.StoreError):
        store.load_current(GRANT_ID)
    with pytest.raises(mem.StoreError):
        store.issue(_grant())


def test_grant_store_rejects_blank_lookup_keys(grant_db: Path) -> None:
    store = SqliteGrantStore(grant_db)
    for call in (
        lambda: store.load_current(""),
        lambda: store.load_current("   "),
        lambda: store.load_for_session(""),
        lambda: store.revoke("", revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="a")),
    ):
        with pytest.raises(mem.MemoryValidationError):
            call()


def test_issued_grant_drives_authorize_end_to_end(grant_db: Path) -> None:
    """存储与判权的接缝：签发的 grant 真的能放行它覆盖的记录，撤销后不再可用。"""

    store = SqliteGrantStore(grant_db)
    record = _family_record()
    store.issue(
        _grant(
            issued_at=NOW,
            expires_at=_iso(_epoch() + timedelta(hours=1)),
            actions=frozenset({"read_model", "write"}),
            resource_ids=frozenset({record.id}),
            consent_versions=((record.id, record.consent_version),),
        )
    )
    loaded = load_grant_for_session(grant_db, SESSION_ID)
    allowed = authorize(
        action="read_model",
        access=_owner_bound_access(OWNER),
        grant=loaded,
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        records=(record,),
        now=NOW,
    )
    assert allowed == mem.ALLOWED

    refreshed = _corrupt(record, consent_version=2)  # confirm_shared() 之后
    # A5'：读取路径对 FAMILY + 受众命中的记录完全豁免 grant，因此旧版本失效要在
    # **需要 grant 的动作**上验证。
    stale = authorize(
        action="write",
        access=_owner_bound_access(OWNER),
        grant=loaded,
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        records=(refreshed,),
        now=NOW,
    )
    assert stale.reason == "stale_consent"

    # 写动作必须走 grant：撤销前放行。
    write_kwargs = {
        "action": "write",
        "access": _owner_bound_access(OWNER),
        "session_id": SESSION_ID,
        "audience_id": AUDIENCE,
        "records": (),
        "now": NOW,
    }
    assert authorize(grant=loaded, **write_kwargs) == mem.ALLOWED

    store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="adult_a"))
    assert load_grant_for_session(grant_db, SESSION_ID) is None
    assert authorize(grant=load_grant_for_session(grant_db, SESSION_ID), **write_kwargs).reason == "no_grant"

    # 家庭共享的读取不依赖 grant，因此撤销后仍走无 grant 例外 —— 这是契约语义，
    # 不是漏判：grant 管的是「应用这次能读什么」的授权凭据，FAMILY + 受众命中本身
    # 就是共享路径（§3.3）。
    after_revoke = authorize(
        action="read_model",
        access=_owner_bound_access(OWNER),
        grant=load_grant_for_session(grant_db, SESSION_ID),
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        records=(record,),
        now=NOW,
    )
    assert after_revoke == mem.ALLOWED


def test_revocation_reaches_authorize_as_no_grant(grant_db: Path) -> None:
    """主控 2026-09-26 仲裁：``revoked`` 属**存储层语义**。

    撤销后的 grant 不会被 ``load_current`` / ``load_for_session`` 交出来，因此判权
    看到的是 ``no_grant``（这里是写路径；家庭共享读取本来就依赖 grant 有无的例外，
    见 §3.3），``authorize()`` 不会有 ``revoked`` 这个产出。
    """

    store = SqliteGrantStore(grant_db)
    store.issue(_grant(actions=frozenset({"write"}), resource_ids=frozenset(), consent_versions=()))
    assert store.load_for_session(SESSION_ID) is not None

    store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="adult_a"))
    assert load_grant_for_session(grant_db, SESSION_ID) is None
    decision = authorize(
        action="write",
        access=_owner_bound_access(OWNER),
        grant=load_grant_for_session(grant_db, SESSION_ID),
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        records=(),
        now=NOW,
    )
    assert decision.reason == "no_grant"
    assert decision.reason != "revoked"


def test_issue_and_revoke_are_atomic_on_failure(grant_db: Path) -> None:
    """KV 约束失败时不得留下半条 grant（单事务）。"""

    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1, resource_ids=frozenset({RECORD_ID}), consent_versions=((RECORD_ID, 1),)))
    # 动作取值在写库前就被校验掉；这里再确认一次「拒绝 = 库内行数不变」。
    with pytest.raises(mem.MemoryValidationError):
        store.issue(_grant(version=2, actions=frozenset({"nope"})))
    assert _raw(grant_db, "SELECT COUNT(*) FROM grant_record")[0][0] == 1
    assert _raw(grant_db, "SELECT COUNT(*) FROM grant_action")[0][0] == 1
    assert _raw(grant_db, "SELECT COUNT(*) FROM grant_resource")[0][0] == 1


def test_sqlite_failures_surface_as_store_error(grant_db: Path) -> None:
    """SQLite / 文件系统故障必须是 ``StoreError``，不得把裸 ``sqlite3.Error`` 漏出去。"""

    store = SqliteGrantStore(grant_db)
    store.issue(_grant(version=1))
    os.chmod(grant_db, 0o400)  # 只读：写路径必须失败
    try:
        with pytest.raises(mem.StoreError):
            store.issue(_grant(grant_id="grant-readonly", version=1))
        with pytest.raises(mem.StoreError):
            store.revoke(
                GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="a")
            )
        assert store.load_current(GRANT_ID) is not None, "只读库的读路径仍然可用"
    finally:
        os.chmod(grant_db, 0o600)


def test_load_for_session_tie_breaks_are_deterministic(grant_db: Path) -> None:
    """同一 ``issued_at`` 时按插入顺序取最新 —— 排序口径必须确定性。"""

    store = SqliteGrantStore(grant_db)
    same_instant = _iso(_epoch() + timedelta(hours=1))
    store.issue(_grant(grant_id="grant-first", issued_at=NOW, expires_at=same_instant))
    store.issue(_grant(grant_id="grant-second", issued_at=NOW, expires_at=same_instant))
    loaded = store.load_for_session(SESSION_ID)
    assert loaded is not None and loaded.grant_id == "grant-second"


# ===========================================================================
# 5. M2.2 增量：控制面复审判权（§4.1 / §4.3）与 §5.2a 的 grant 生命周期表
# ===========================================================================

#: 契约 §4.2 冻结的控制面 ``authorization_ref`` 常量。**W8 已落地**，这里直接引用
#: ``soul/policy.py`` 的定义 —— 测试不再自带一份可能漂移的字面量。
CONTROL_PLANE_REF = CONTROL_PLANE_AUTHORIZATION_REF


# --- 替身退役（勘误 E7，W8）--------------------------------------------------
#
# W8 之前这里有一个 ``ControlPlaneAccess(SessionAccess)`` 子类 + 一个能构造**非法变体**
# 的 ``control_plane_access()`` 工厂：它吞掉父类那条「还不认识 control_plane 模式」的
# 断言，让 W9 的判权增量能在不依赖 W8 文件的前提下验收。W8 落地 ``SessionMode`` 的第三个
# 取值与 ``SessionAccess.for_control_plane()`` 之后，那个替身与它的工厂**整体删除**：
#
# - 测试里的控制面访问一律用**真实构造器** ``SessionAccess.for_control_plane()``；
# - 原本靠替身构造的非法变体（模式不对 / owner 非空 / ref 为空）改成断言**构造期
#   ``ValueError``**（见 ``test_control_plane_construction_rejects_illegal_shapes``），
#   ``__post_init__`` 一个字都没有放宽；
# - 全仓已 grep 确认 ``control_plane_access`` 只剩 ``tests/test_memory_service.py`` 的三处
#   引用，主控授权后那三处已改用真构造器（W8 收尾，2026-09-26）。


def _candidate(**overrides: Any) -> MemoryRecord:
    """一条**候选**（``PENDING_CONFIRMATION`` + ``candidate_only``）。"""

    base: dict[str, Any] = {
        "status": "PENDING_CONFIRMATION",
        "memory_policy": "candidate_only",
        "last_confirmed_at": None,
        "expires_at": _iso(_epoch() + timedelta(days=mem.DEFAULT_TTL_CANDIDATE_DAYS)),
    }
    base.update(overrides)
    return _family_record(**base)


def _review(**overrides: Any) -> mem.AuthorizationDecision:
    """``review_control_plane`` 的判权调用（默认：控制面 + 一条 FAMILY 候选 + 无 grant）。"""

    kwargs: dict[str, Any] = {
        "action": "review_control_plane",
        "access": SessionAccess.for_control_plane(),
        "grant": None,
        "session_id": "cli-session",
        "audience_id": AUDIENCE,
        "records": (_candidate(),),
        "now": NOW,
    }
    kwargs.update(overrides)
    return authorize(**kwargs)


# -- 4.1 模式校验（在类型兜底之后、grant 段之前）------------------------------


@pytest.mark.parametrize(
    "access",
    [
        SessionAccess(),  # shared
        SessionAccess(session_mode="controlled_private"),  # controlled_private
        _owner_bound_access(OWNER, session_mode="controlled_private"),
    ],
    ids=["shared", "controlled-private", "controlled-private-with-owner"],
)
def test_review_control_plane_is_action_not_granted_outside_the_control_plane(
    access: SessionAccess,
) -> None:
    """§4.1 硬边界 1：会话路径（``shared`` / ``controlled_private``）拿不到这个动作。"""

    decision = _review(access=access)
    assert decision.allowed is False
    assert decision.reason == "action_not_granted"


def test_review_control_plane_reads_a_family_candidate_without_any_grant() -> None:
    """正例：控制面 + FAMILY 候选 + **无 grant** ⇒ ``ok``（这就是 D11 要的能力）。

    M2.1 的判权只让 ``ACTIVE`` 可读，因此成人读不到候选正文 —— 这条正例证明
    「成人复审」在 M2.2 真的可达（防「全拒绝算通过」）。
    """

    assert _review().allowed is True
    # 已经确认的记录同样读得到（跳过的是 status 检查，不是「只读候选」）。
    assert _review(records=(_family_record(),)).allowed is True
    # A5' 的家庭共享读取路径没有被它影响。
    assert authorize(
        action="read_model",
        access=SessionAccess(),
        grant=None,
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        records=(_family_record(),),
        now=NOW,
    ).allowed is True


@pytest.mark.parametrize(
    "access",
    [
        SessionAccess(),  # shared
        SessionAccess(session_mode="controlled_private"),  # controlled_private
        _owner_bound_access(OWNER, session_mode="controlled_private"),  # owner 非空
        _owner_bound_access(OWNER),  # shared + owner
        None,
        "not-an-access",
        object(),
    ],
    ids=[
        "shared",
        "controlled-private",
        "controlled-private-owner",
        "shared-with-owner",
        "none",
        "not-an-access",
        "plain-object",
    ],
)
def test_is_control_plane_is_a_total_function(access: object) -> None:
    """A 的 N7：:func:`_is_control_plane` **绝不抛异常**，判定不通过就是 ``False``。

    对非 :class:`SessionAccess` 入参，类型兜底先给出 ``no_grant`` —— 模式校验
    不能反而制造一个新的抛错点。

    「模式是 control_plane 但 owner 非空 / ref 为空」那几组**非法形态**自 W8 起
    **构造不出来**（``__post_init__`` 直接 ``ValueError``），因此它们在
    ``test_control_plane_construction_rejects_illegal_shapes`` 里断言，不再走本用例。
    """

    assert policy_module._is_control_plane(access) is False
    if isinstance(access, SessionAccess):
        assert _review(access=access).reason == "action_not_granted"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"session_mode": "control_plane"},  # 无 ref
        {"session_mode": "control_plane", "authorization_ref": None},
        {"session_mode": "control_plane", "authorization_ref": "   "},
        {"session_mode": "control_plane", "authorization_ref": 123},  # type: ignore[arg-type]
        {"session_mode": "control_plane", "session_owner": OWNER,
         "authorization_ref": CONTROL_PLANE_REF},  # 控制面不是某个人
        {"session_mode": "control_plane", "session_owner": OWNER},  # 两样都错
    ],
    ids=["no-ref", "none-ref", "blank-ref", "non-str-ref", "owner-bound", "owner-without-ref"],
)
def test_control_plane_construction_rejects_illegal_shapes(kwargs: dict[str, Any]) -> None:
    """W8（勘误 E7）：控制面访问的非法形态在**构造期**就 ``ValueError``。

    替身退役后这些形态没有「更宽松的构造路径」可以走 —— 契约 §4.2 要求
    ``session_mode == "control_plane"`` 同时满足 ``session_owner is None`` **且**
    ``authorization_ref`` 非空，违反哪一条都不可表达。
    """

    with pytest.raises(ValueError):
        SessionAccess(**kwargs)  # type: ignore[arg-type]


def test_for_control_plane_uses_the_frozen_ref_and_is_the_real_class() -> None:
    """W8：``for_control_plane()`` 构造的是**真实**的 :class:`SessionAccess`。

    没有子类、没有替身：类型精确相等（而不是 ``isinstance``），字段与契约 §4.2 一致，
    默认 ref 就是冻结常量。
    """

    access = SessionAccess.for_control_plane()
    assert type(access) is SessionAccess
    assert access.session_mode == "control_plane"
    assert access.session_owner is None
    assert access.authorization_ref == CONTROL_PLANE_AUTHORIZATION_REF == CONTROL_PLANE_REF
    # 显式 ref 也允许（常量是默认值，不是唯一取值）。
    assert SessionAccess.for_control_plane(authorization_ref="cli:other").authorization_ref == (
        "cli:other"
    )
    # 空白 ref 仍然构造不出来。
    for bad in ("", "   "):
        with pytest.raises(ValueError):
            SessionAccess.for_control_plane(authorization_ref=bad)


def test_review_control_plane_keeps_the_type_fallback_before_the_mode_check() -> None:
    """§4.1：模式校验在**类型兜底之后** —— 非 ``SessionAccess`` 仍是 ``no_grant``。"""

    for access in (None, "nope", object()):
        decision = _review(access=access)
        assert decision.allowed is False
        assert decision.reason == "no_grant", "类型兜底先于模式校验"

    bad_grant = _review(grant={"grant_id": "forged"})
    assert bad_grant.reason == "no_grant", "非 Grant 的 grant 同样走类型兜底"

    # 空记录集仍是 no_grant（既有 fail-closed 口径不变）。
    assert _review(records=()).reason == "no_grant"


# -- 4.1 记录级检查：**只**跳过 status_denied ---------------------------------


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (
            _candidate(expires_at=_iso(_epoch() - timedelta(days=1))),
            "record_expired",
        ),
        (
            _candidate(
                source_ids=("ghost-ancestor",),
            ),
            "missing_provenance",
        ),
        (_candidate(scope="PERSONAL"), "scope_not_enabled"),
        (_family_record(scope="SAFETY", memory_class="SAFETY", status="PENDING_CONFIRMATION",
                        memory_policy="candidate_only", last_confirmed_at=None), "scope_not_enabled"),
        (_candidate(audiences=frozenset({"someone-else"})), "scope_denied"),
        (
            _corrupt(_candidate(), memory_policy="do_not_persist"),
            "policy_denied",
        ),
    ],
    ids=[
        "expired-candidate",
        "missing-provenance",
        "personal-candidate",
        "safety-candidate",
        "audience-mismatch",
        "corrupted-policy",
    ],
)
def test_review_control_plane_skips_only_status_denied(
    record: MemoryRecord, expected: str
) -> None:
    """§4.1 的表逐行：``missing_provenance`` / ``scope_not_enabled`` / ``scope_denied`` /
    ``policy_denied`` / ``record_expired`` **一律照常执行**，绝不写成 early-return。

    只有 ``status_denied`` 被跳过（候选正是 ``PENDING_CONFIRMATION``）。
    """

    decision = _review(records=(record,))
    assert decision.allowed is False
    assert decision.reason == expected


def test_review_control_plane_skips_status_denied_where_read_model_would_not() -> None:
    """对照：同一条候选，``read_model`` 报 ``status_denied``，复审动作报 ``ok``。"""

    candidate = _candidate()
    assert authorize(
        action="read_model",
        access=SessionAccess(),
        grant=None,
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        records=(candidate,),
        now=NOW,
    ).reason == "status_denied"
    assert _review(records=(candidate,)).allowed is True


def test_review_control_plane_does_not_enter_any_projection_path() -> None:
    """§4.2 硬边界 3：它**永不**出现在投影 / 发 provider 的判定里。"""

    assert mem.PROJECTION_SEAM_ACTIONS == ("read_model", "send_provider")
    assert "review_control_plane" not in mem.PROJECTION_SEAM_ACTIONS
    assert mem.NO_GRANT_EXEMPT_ACTIONS - {"read_model", "send_provider"} == {
        "review_control_plane"
    }, "免 grant 的例外只多这一个复审动作"


# -- §4.3：purpose → 动作 ------------------------------------------------------


def test_every_query_purpose_maps_to_exactly_one_action() -> None:
    """§4.3：动作**由 purpose 决定**；只有 ``control_plane_review`` 走复审动作。"""

    from soul_memory_kernel.memory.service import _ACTION_FOR_PURPOSE, _CONTENT_CARRYING_PURPOSES

    assert set(_ACTION_FOR_PURPOSE) == mem.QUERY_PURPOSES
    assert {
        purpose
        for purpose, action in _ACTION_FOR_PURPOSE.items()
        if action == "review_control_plane"
    } == {"control_plane_review"}
    for purpose, action in _ACTION_FOR_PURPOSE.items():
        assert action in mem.ACTIONS, purpose
    # 携带正文的白名单：session_projection / adult_inspect + 新增的 control_plane_review。
    assert _CONTENT_CARRYING_PURPOSES == {
        "session_projection",
        "adult_inspect",
        "control_plane_review",
    }


# -- §5.2a：grant 生命周期表逐行 ----------------------------------------------


def test_grant_lifecycle_table_row_by_row(grant_db: Path) -> None:
    """§5.2a 的表逐行（W9 的落点；语义沿用 M2.1，M2.2 只把它写成可裁的表）。

    判权输入固定为「**写动作** + 一条 FAMILY 记录」：写动作不在 A5' 的免 grant 白名单里，
    因此 grant 段**真的会执行**（读取路径上一条受众命中的 FAMILY 记录会整段豁免，
    什么也验证不到）；而 FAMILY + 受众命中又让记录级检查全部通过，于是
    「已签发（有效）」这一行能拿到 ``ok``。

    **本相位的边界（§5.2a 末注）**：``PERSONAL`` / ``SAFETY`` 记录仍被
    ``scope_not_enabled`` 先拦，因此「有效」一行的正例只能在 ``FAMILY`` 记录上验证；
    其余各行与 scope 无关。每行用**各自的会话** —— ``load_for_session`` 是按会话取
    「最新未撤销版本」，混在一起会让版本排序干扰逐行断言。
    """

    store = SqliteGrantStore(grant_db)
    record = _family_record()
    write_actions = frozenset({"read_model", "write"})

    def decision(**overrides: Any) -> mem.AuthorizationDecision:
        kwargs: dict[str, Any] = {
            "action": "write",
            "access": _owner_bound_access(OWNER, session_mode="controlled_private"),
            "grant": None,
            "session_id": SESSION_ID,
            "audience_id": AUDIENCE,
            "records": (record,),
            "now": NOW,
        }
        kwargs.update(overrides)
        return authorize(**kwargs)

    # 行 1「未签发」：load_for_session 是 None（库不存在也是 None），判权 no_grant。
    assert store.load_for_session(SESSION_ID) is None
    assert decision().reason == "no_grant"

    # 行 2「已签发（有效）」：会话绑定 / owner / 受众 / 动作 / 资源 / 同意版本逐项过 ⇒ ok。
    store.issue(_grant(actions=write_actions))
    live = store.load_for_session(SESSION_ID)
    assert live is not None and live.grant_id == GRANT_ID
    assert decision(grant=live).allowed is True

    # 行 3「已到期」：``now >= expires_at``。存储层**不按时间过滤**，仍 load 得到 ——
    # 否则拒绝原因会从 expired 退化成 no_grant，审计就查不出「授权到期」这件事。
    store.issue(
        _grant(
            grant_id="grant-expired",
            version=1,
            session_id="session-expired",
            actions=write_actions,
            issued_at=_iso(_epoch() - timedelta(hours=2)),
            expires_at=_iso(_epoch()),
        )
    )
    expired = store.load_for_session("session-expired")
    assert expired is not None and expired.grant_id == "grant-expired"
    assert decision(grant=expired, session_id="session-expired").reason == "expired"

    # 行 4「尚未生效」：``now < issued_at``（时钟回拨 / 未来签发，B-s1）⇒ not_yet_valid。
    store.issue(
        _grant(
            grant_id="grant-future",
            version=1,
            session_id="session-future",
            actions=write_actions,
            issued_at=_iso(_epoch() + timedelta(minutes=30)),
            expires_at=_iso(_epoch() + timedelta(hours=2)),
        )
    )
    not_yet = store.load_for_session("session-future")
    assert not_yet is not None and not_yet.grant_id == "grant-future"
    assert decision(grant=not_yet, session_id="session-future").reason == "not_yet_valid"

    # 行 5「已撤销」：load_for_session 变回 None ⇒ 判权 no_grant ——
    # **与「从未签发」刻意不可区分**（A4：不引入 revoked reason）。
    store.revoke(GRANT_ID, revoked_at=NOW, actor=Actor(kind="adult_control_plane", actor_id="adult_a"))
    assert store.load_for_session(SESSION_ID) is None
    assert decision().reason == "no_grant"

    # 行 6「重新签发」：换一个 grant_id 再 issue，按新窗口判定；旧 id 不可复活（另有用例）。
    store.issue(_grant(grant_id="grant-fresh", version=1, actions=write_actions))
    fresh = store.load_for_session(SESSION_ID)
    assert fresh is not None and fresh.grant_id == "grant-fresh"
    assert decision(grant=fresh).allowed is True


def test_grant_lifecycle_binding_rows_are_unchanged_in_m2_2() -> None:
    """§5.2a 的其余四行（绑定类）：``wrong_owner`` / ``wrong_session`` /
    ``resource_not_granted`` / ``stale_consent`` —— M2.2 不改任何一行。"""

    record = _family_record()
    write_actions = frozenset({"read_model", "write"})
    live = _grant(actions=write_actions, resource_ids=frozenset({RECORD_ID}),
                  consent_versions=((RECORD_ID, 1),))

    def decision(**overrides: Any) -> mem.AuthorizationDecision:
        kwargs: dict[str, Any] = {
            "action": "write",
            "access": _owner_bound_access(OWNER, session_mode="controlled_private"),
            "grant": live,
            "session_id": SESSION_ID,
            "audience_id": AUDIENCE,
            "records": (record,),
            "now": NOW,
        }
        kwargs.update(overrides)
        return authorize(**kwargs)

    assert decision().allowed is True
    assert decision(
        access=_owner_bound_access("adult_b", session_mode="controlled_private")
    ).reason == "wrong_owner"
    assert decision(session_id="another-session").reason == "wrong_session"
    assert decision(grant=_grant(actions=write_actions, resource_ids=frozenset({"other-record"}))).reason == (
        "resource_not_granted"
    )
    assert decision(
        grant=_grant(actions=write_actions, consent_versions=((RECORD_ID, 2),))
    ).reason == "stale_consent"
