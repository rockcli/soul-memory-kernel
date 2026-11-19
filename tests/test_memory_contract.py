"""M2 契约测试 —— **永久冻结的不变量**（W0）。

本文件只测契约本身，不测实现。**任何 writer 都不得删除本文件的测试**：
它们是跨切片长期成立的不变量。需要在实现期豁免的「桩形状」检查单独放在
``tests/test_memory_contract_w0.py``（那份可以按 writer 逐条退役）。

覆盖范围：

1. 类型可导入、公开名字齐全、枚举取值与冻结集合一致；
2. **M2.1 相位限制**：产品路径只允许 ``scope="FAMILY"`` 与 ``origin="explicit_user"``；
   ``memory_class="SAFETY"``（内容类型）不受限，且按 D5 不过期；
3. 状态机良构：终态无出边、候选不 decay（走硬删除）、TTL 迁移只有一条、
   策略绑定不变量完整；
4. 授权的拒绝优先顺序（含 ``scope_not_enabled`` 与 ``policy_denied`` 的位置）；
5. 五个 service 接口与冻结构造签名（含 ``SqliteMemoryStore`` / ``SqliteGrantStore``）；
6. DDL 的六条不变量（含候选一律有期限、status↔policy 绑定、墓碑无正文）；
7. `family_ai/memory/` 的架构边界（AST 静态扫描）；
8. ``docs/fixtures/m2-memory-policy.synthetic.json`` 的**每一个**正例与反例都能被契约
   表达，且 M2.1 可达的正例非空（防「全拒绝算通过」）。
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest

import soul_memory_kernel.memory as mem

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "m2-memory-policy.synthetic.json"
MEMORY_PACKAGE_DIR = REPO_ROOT / "soul_memory_kernel" / "memory"

#: W0 冻结建立的文件集。以后只增不减；``grants.py`` 由 W2 新增。
W0_FILE_SET: frozenset[str] = frozenset(
    {
        "__init__.py",
        "grants.py",
        "model.py",
        "policy.py",
        "projection.py",
        "service.py",
        "store.py",
    }
)


# ---------------------------------------------------------------------------
# 1. 可导入性与枚举
# ---------------------------------------------------------------------------


def test_public_names_are_exported() -> None:
    """``__all__`` 里的每个名字都必须真的存在（防止改名后留下悬空导出）。"""

    missing = [name for name in mem.__all__ if not hasattr(mem, name)]
    assert missing == []
    assert len(mem.__all__) == len(set(mem.__all__)), "duplicate names in __all__"


def test_frozen_enum_sets_match_contract() -> None:
    assert mem.SCOPES == {"FAMILY", "PERSONAL", "SAFETY"}
    assert mem.MEMORY_CLASSES == {"EVENT", "PREFERENCE", "SAFETY"}
    assert mem.MEMORY_STATUSES == {"PENDING_CONFIRMATION", "ACTIVE", "DECAYED", "DELETED"}
    # T15 第 2 处（M2.2 §4.3）：新增第 5 个 purpose —— 成人复审候选正文的读取通路。
    assert mem.QUERY_PURPOSES == {
        "session_projection",
        "adult_list",
        "adult_inspect",
        "deletion_audit",
        "control_plane_review",
    }
    assert mem.ACTOR_KINDS == {
        "adult_control_plane",
        "session_proposal",
        "ttl_expiry",
        "migration",
    }
    assert mem.CANDIDATE_ORIGINS == {"explicit_user", "auto_extracted"}
    # T15 第 1 处（M2.2 §4.1 / D11）：新增 review_control_plane —— 只读、只 FAMILY、
    # 只控制面，且**不进任何投影**。
    assert mem.ACTIONS == {
        "read_model",
        "send_provider",
        "publish_text",
        "play_audio",
        "write",
        "share",
        "delete",
        "review_control_plane",
    }


def test_do_not_persist_is_never_a_persistable_policy() -> None:
    """``do_not_persist`` 是可请求的策略，但**永远不是可落库的取值**（D2/D5 落点一）。"""

    assert "do_not_persist" in mem.REQUESTED_POLICIES
    assert "do_not_persist" not in mem.MEMORY_POLICIES
    assert mem.MEMORY_POLICIES == {"persist_confirmed", "candidate_only"}


def test_safety_ttl_defaults_are_not_configurable() -> None:
    """D5：``SAFETY`` 不过期是硬不变量，不是旋钮 —— 配置里没有它的天数。"""

    policy = mem.RetentionPolicy()
    fields = set(policy.__dataclass_fields__)
    assert fields == {"event_days", "preference_days", "candidate_days"}
    assert not any(
        "safety" in field for field in fields
    ), "SAFETY retention must not be a configurable field"
    assert policy.event_days == 30
    assert policy.preference_days == 180
    assert policy.candidate_days == 7


# ---------------------------------------------------------------------------
# 2. M2.1 相位限制（阻塞 1）
# ---------------------------------------------------------------------------


def test_m2_1_restricts_scope_to_family() -> None:
    """M2.1 产品路径只允许 ``FAMILY``；``PERSONAL`` / ``SAFETY`` scope 由服务层拒绝。"""

    assert mem.M2_1_ALLOWED_SCOPES == {"FAMILY"}
    assert mem.M2_1_ALLOWED_SCOPES < mem.SCOPES, "M2.1 must be a strict subset of scopes"


def test_m2_1_restricts_candidate_origin_to_explicit() -> None:
    """候选来源白名单 **== 候选来源全集**（M2.2 §3 自动提取落地后，T15 第 8/9 处）。

    M2.1 的读法是「只放行 ``explicit_user``，且它**严格小于** ``CANDIDATE_ORIGINS``」；
    M2.2 放行 ``auto_extracted``（§6 收口表第 12 项）之后，白名单与候选来源全集
    **对齐**，因此那两条断言改写成**集合相等**并写在这里 —— 严格子集断言不再成立，
    继续留着会变成一句空话。

    放行不等于放松：提取路径**只能**产出候选（``PENDING_CONFIRMATION`` +
    ``candidate_only``），成人确认仍是唯一生效路径（契约约束 1）。
    """

    assert mem.M2_1_ALLOWED_ORIGINS == {"explicit_user", "auto_extracted"}
    assert mem.M2_1_ALLOWED_ORIGINS == mem.CANDIDATE_ORIGINS, (
        "白名单已与候选来源全集对齐（M2.2 放行 auto_extracted）"
    )


def test_safety_memory_class_is_not_restricted_by_phase() -> None:
    """**关键区分**：相位限制管的是 ``scope``（谁能读），不是 ``memory_class``（留多久）。

    ``memory_class="SAFETY"``（过敏这类内容类型）在 ``FAMILY`` scope 下照常支持。
    """

    assert "SAFETY" in mem.MEMORY_CLASSES
    assert "SAFETY" not in mem.M2_1_ALLOWED_SCOPES, "SAFETY scope is M2.2+, by design"
    assert "SAFETY" in mem.MEMORY_CLASSES - mem.M2_1_ALLOWED_SCOPES


# ---------------------------------------------------------------------------
# 3. 状态机与 TTL（阻塞 2）
# ---------------------------------------------------------------------------


def test_legal_transitions_are_wellformed() -> None:
    for source, target in mem.LEGAL_TRANSITIONS:
        assert source in mem.MEMORY_STATUSES, source
        assert target in mem.MEMORY_STATUSES, target


def test_deleted_is_terminal() -> None:
    outgoing = {source for source, _ in mem.LEGAL_TRANSITIONS if source == "DELETED"}
    assert outgoing == set(), "DELETED must have no outgoing transition"


def test_candidate_never_decays() -> None:
    """候选从未可召回，``DECAYED`` 对它无意义；候选到期走**硬删除**。"""

    assert ("PENDING_CONFIRMATION", "DECAYED") not in mem.LEGAL_TRANSITIONS
    assert mem.CANDIDATE_EXPIRY_IS_HARD_DELETE is True


def test_ttl_transition_is_only_confirmed_decay() -> None:
    """TTL 只负责一条**状态迁移**：已确认记录到期转 ``DECAYED``（不删盘，D5）。

    候选到期不是状态迁移 —— 那是硬删除，不走 ``LEGAL_TRANSITIONS``。
    """

    assert mem.TTL_TRANSITIONS == {("ACTIVE", "DECAYED")}
    assert mem.TTL_TRANSITIONS < mem.LEGAL_TRANSITIONS


def test_active_never_falls_back_to_candidate() -> None:
    for source in ("ACTIVE", "DECAYED"):
        assert (source, "PENDING_CONFIRMATION") not in mem.LEGAL_TRANSITIONS


def test_every_non_terminal_status_has_a_path_to_deleted() -> None:
    """任何非终态都必须能到达 ``DELETED`` —— 否则历史墓碑数据无法表达。"""

    reachable: set[str] = set()
    frontier = {"DELETED"}
    while frontier:
        node = frontier.pop()
        for source, target in mem.LEGAL_TRANSITIONS:
            if target == node and source not in reachable:
                reachable.add(source)
                frontier.add(source)
    assert reachable >= {"PENDING_CONFIRMATION", "ACTIVE", "DECAYED"}


def test_status_policy_invariant_covers_every_status() -> None:
    assert set(mem.STATUS_POLICY_INVARIANT) | {"DELETED"} == mem.MEMORY_STATUSES
    assert set(mem.STATUS_POLICY_INVARIANT.values()) <= mem.MEMORY_POLICIES


# ---------------------------------------------------------------------------
# 4. 授权函数
# ---------------------------------------------------------------------------


def test_deny_order_is_complete_and_unique() -> None:
    assert len(mem.DENY_ORDER) == len(set(mem.DENY_ORDER)), "DENY_ORDER has duplicates"
    assert set(mem.DENY_ORDER) <= mem.REASONS
    assert "ok" not in mem.DENY_ORDER, "success is not a denial"
    assert mem.REASONS == set(mem.DENY_ORDER) | {"ok"}


def test_deny_order_starts_with_the_authorization_preconditions() -> None:
    """拒绝优先：先判授权本身是否可信，再判记录能不能做这个动作。"""

    assert mem.DENY_ORDER[:2] == ("clock_invalid", "no_grant")
    assert mem.DENY_ORDER.index("expired") < mem.DENY_ORDER.index("wrong_session")
    assert mem.DENY_ORDER.index("missing_provenance") < mem.DENY_ORDER.index("scope_not_enabled")
    assert mem.DENY_ORDER[-1] == "stale_consent"


def test_deny_order_adjacency_is_frozen() -> None:
    """四处刻意的相邻关系。"""

    order = mem.DENY_ORDER
    assert order.index("scope_not_enabled") < order.index("scope_denied")
    assert order.index("policy_denied") < order.index("status_denied")
    # B-s1：not_yet_valid 紧跟 expired —— 同属「grant 时间窗」这一段。
    assert order.index("not_yet_valid") == order.index("expired") + 1
    # B2：record_expired 在 status_denied 之后（状态是主门、到期是补充门），
    #     且在 stale_consent 之前（冻结的尾巴）。
    assert order.index("status_denied") < order.index("record_expired")
    assert order.index("record_expired") < order.index("stale_consent")


def test_scope_not_enabled_is_a_first_class_reason() -> None:
    """阻塞 1 的修法：相位拒绝是一个**独立 reason**，不是复用 scope_denied。"""

    assert "scope_not_enabled" in mem.REASONS
    assert "scope_not_enabled" in mem.DENY_ORDER


def test_authorize_takes_every_input_keyword_only() -> None:
    """``authorize()`` 全部 keyword-only：位置传参太容易把 session 和 audience 写反。"""

    params = inspect.signature(mem.authorize).parameters
    assert list(params) == [
        "action",
        "access",
        "grant",
        "session_id",
        "audience_id",
        "records",
        "now",
    ]
    for name, param in params.items():
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, name


def test_require_mirrors_authorize_signature() -> None:
    """``require()`` 是写入版，参数必须与 ``authorize()`` 完全一致，否则会出现两条判权入口。"""

    assert inspect.signature(mem.require).parameters.keys() == (
        inspect.signature(mem.authorize).parameters.keys()
    )


def test_decision_shortcuts_are_consistent() -> None:
    assert mem.ALLOWED.allowed is True and mem.ALLOWED.reason == "ok"
    assert mem.DENIED_NO_GRANT.allowed is False and mem.DENIED_NO_GRANT.reason == "no_grant"


# ---------------------------------------------------------------------------
# 5. 五个 service 接口的签名与冻结构造签名
# ---------------------------------------------------------------------------


def _positional_names(func: object) -> list[str]:
    return [
        name
        for name, param in inspect.signature(func).parameters.items()
        if param.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and name != "self"
    ]


def _keyword_only_names(func: object) -> list[str]:
    return [
        name
        for name, param in inspect.signature(func).parameters.items()
        if param.kind is inspect.Parameter.KEYWORD_ONLY
    ]


@pytest.mark.parametrize(
    ("method_name", "positional"),
    [
        ("propose", ["candidate", "source_session"]),
        # M2-PREPARATION 写的是 confirm_shared(candidate_id, audience)；actor 是
        # D3 要求的必填扩展（已在契约页与 docstring 留痕）。
        ("confirm_shared", ["candidate_id", "audience", "actor"]),
        ("query", ["session_access", "purpose"]),
        # M2-PREPARATION 写的是 correct(id, replacement, actor)；这里第一个参数
        # 命名为 record_id 以免遮蔽内置 id，位置与语义不变。
        ("correct", ["record_id", "replacement", "actor"]),
        ("delete", ["record_id", "actor"]),
    ],
)
def test_service_interface_positional_shape(method_name: str, positional: list[str]) -> None:
    method = getattr(mem.MemoryService, method_name)
    assert _positional_names(method) == positional


def test_query_requires_explicit_grant_and_session_binding() -> None:
    """grant 与会话绑定必须由调用方显式传入，服务不得自行按 session_id 查 grant。"""

    assert _keyword_only_names(mem.MemoryService.query) == [
        "session_id",
        "audience_id",
        "grant",
    ]


def test_service_constructor_injects_store_grants_clock() -> None:
    params = inspect.signature(mem.MemoryService.__init__).parameters
    assert [name for name in params if name != "self"] == [
        "store",
        "grants",
        "clock",
        "retention",
    ]
    assert params["retention"].default is None, "retention must default to the frozen policy"
    assert params["clock"].default is inspect.Parameter.empty, "clock must be injected"


def test_frozen_sqlite_implementation_class_names_and_signatures() -> None:
    """阻塞 4.5：具体实现类的**名字与构造签名**必须冻结，否则 W4/W5 无法实例化。"""

    for cls in (mem.SqliteMemoryStore, mem.SqliteGrantStore):
        params = inspect.signature(cls.__init__).parameters
        # 契约 §9.1：db_path 必需；**可选参数可以加，但必须带默认值**（B-s1 给
        # SqliteGrantStore 加了可选 clock）。
        assert list(params)[:2] == ["self", "db_path"], cls.__name__
        assert params["db_path"].default is inspect.Parameter.empty, cls.__name__
        for name, param in list(params.items())[2:]:
            assert param.kind is inspect.Parameter.KEYWORD_ONLY, f"{cls.__name__}.{name}"
            assert param.default is not inspect.Parameter.empty, f"{cls.__name__}.{name}"


def test_truthy_deletion_is_atomic_in_the_frozen_protocol() -> None:
    """A11：删除 + 审计必须是**一个** store 方法（同一事务），签名冻结。"""

    params = inspect.signature(mem.MemoryStore.hard_delete_with_audit).parameters
    assert list(params) == [
        "self",
        "record_id",
        "actor",
        "deleted_at",
        "derived_removed",
        "unknown_copies",
    ]
    for name in ("record_id", "actor", "deleted_at"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name
    assert params["derived_removed"].default == 0
    assert params["unknown_copies"].default == ()

    fields = set(mem.DeletionOutcome.__dataclass_fields__)
    assert fields == {"record_id", "tables_touched", "audit_id"}


def test_grant_store_has_a_by_session_lookup() -> None:
    """阻塞 4.1：接缝只有 ``session_id``，没有 ``grant_id``，所以必须有按会话查的方法。"""

    params = inspect.signature(mem.GrantStore.load_for_session).parameters
    assert list(params) == ["self", "session_id"]


def test_correction_cannot_express_ownership_or_source_changes() -> None:
    """不可改字段在**类型上就不可表达** —— 实现方无法顺手改掉归属或来源。"""

    fields = set(mem.MemoryCorrection.__dataclass_fields__)
    assert fields == {"content", "importance", "audiences"}
    forbidden = {
        "id",
        "record_id",
        "owner_id",
        "scope",
        "memory_class",
        "source_type",
        "source_member_id",
        "created_at",
        "status",
        "memory_policy",
        "consent_version",
    }
    assert fields.isdisjoint(forbidden)


def test_memory_record_carries_every_frozen_field() -> None:
    """``MemoryRecord`` 必须覆盖 M2-PREPARATION 第 7 行冻结的全部字段（只增不减）。"""

    frozen = {
        "id",
        "owner_id",
        "scope",
        "source_type",
        "source_member_id",
        "content",
        "confidence",
        "importance",
        "created_at",
        "updated_at",
        "last_confirmed_at",
        "source_session_id",
        "status",
        "memory_policy",
    }
    assert frozen <= set(mem.MemoryRecord.__dataclass_fields__)


def test_snapshot_denied_channel_carries_no_content() -> None:
    """``denied`` 只允许 id + 固定枚举 reason，不能有正文落点。"""

    fields = set(mem.MemorySnapshot.__dataclass_fields__)
    assert "denied" in fields
    entry_fields = set(mem.SnapshotEntry.__dataclass_fields__)
    assert "content" in entry_fields
    assert "content" not in set(mem.DeletionReport.__dataclass_fields__)


def test_deletion_report_has_an_honest_unknown_channel() -> None:
    """删除报告必须能表达「枚举不到的位置」，否则会被填 0 冒充完整删除。"""

    fields = set(mem.DeletionReport.__dataclass_fields__)
    assert {
        "record_ids",
        "tables_touched",
        "derived_removed",
        "fulltext_eval_copies_removed",
        "unknown_copies",
    } <= fields


def test_actor_kind_permissions_are_documented() -> None:
    """建议 5：``migration`` 的权限必须写明，否则它是个悬空枚举。"""

    doc = mem.Actor.__doc__ or ""
    for kind in mem.ACTOR_KINDS:
        assert kind in doc, f"Actor.{kind} has no documented permission boundary"
    assert "M2.1 没有任何迁移" in doc


# ---------------------------------------------------------------------------
# 6. DDL 不变量
# ---------------------------------------------------------------------------


def _normalized(ddl: str) -> str:
    return " ".join(ddl.split())


def _record_ddl() -> str:
    return _normalized(
        next(d for d in mem.MEMORY_SCHEMA_DDL if "CREATE TABLE memory_record " in d)
    )


def test_ddl_covers_every_declared_table() -> None:
    ddl = "\n".join(mem.MEMORY_SCHEMA_DDL)
    for table in mem.MEMORY_TABLES:
        assert f"CREATE TABLE {table} " in ddl, table
    assert ddl.count("CREATE TABLE ") == len(mem.MEMORY_TABLES)


def test_ddl_forbids_do_not_persist_rows() -> None:
    """落点一的第二道防线：即使服务层漏拦，库层也不接受 ``do_not_persist``。"""

    record_ddl = _record_ddl()
    assert "do_not_persist" not in record_ddl
    assert "memory_policy IN ('persist_confirmed','candidate_only')" in record_ddl


def test_ddl_enforces_retention_invariants() -> None:
    record_ddl = _record_ddl()
    # 1. SAFETY scope => SAFETY class
    assert "CHECK (scope <> 'SAFETY' OR memory_class = 'SAFETY')" in record_ddl
    # 2. expires_at 只在「已确认的 SAFETY 类」上可为空
    assert (
        "CHECK (expires_at IS NOT NULL OR (memory_class = 'SAFETY' AND "
        "status IN ('ACTIVE','DECAYED')))"
    ) in record_ddl
    # 3. FAMILY 且 ACTIVE => 必须已确认
    assert (
        "CHECK (scope <> 'FAMILY' OR status <> 'ACTIVE' OR last_confirmed_at IS NOT NULL)"
        in record_ddl
    )


def test_ddl_requires_expiry_for_candidates_of_every_class() -> None:
    """阻塞 2：**SAFETY 类候选同样受候选期约束**，只有已确认的 SAFETY 类才不过期。

    CHECK 的等价读法：``expires_at`` 为空 <=> 「``memory_class='SAFETY'`` 且状态是
    ``ACTIVE``/``DECAYED``」。候选（任何 class）与已确认的非 SAFETY 类都必须有期限。
    """

    record_ddl = _record_ddl()
    assert "memory_class = 'SAFETY' AND status IN ('ACTIVE','DECAYED')" in record_ddl
    # 反向核对：不能再出现「只要是 SAFETY 类就可以没有 expires_at」的旧写法。
    assert "CHECK (memory_class = 'SAFETY' OR expires_at IS NOT NULL)" not in record_ddl


def test_ddl_enforces_status_policy_invariant() -> None:
    """阻塞 3：状态↔策略的绑定必须真的写进 DDL，而不只是写在文档里。"""

    record_ddl = _record_ddl()
    assert (
        "CHECK (status = 'DELETED' OR (status = 'PENDING_CONFIRMATION' AND "
        "memory_policy = 'candidate_only') OR (status IN ('ACTIVE','DECAYED') AND "
        "memory_policy = 'persist_confirmed'))"
    ) in record_ddl


def test_ddl_audit_actor_enumeration_covers_every_actor_kind() -> None:
    """B-s3：``deletion_audit.actor_kind`` 的 CHECK 是**取值枚举守卫**。

    它必须覆盖全部 ``ACTOR_KINDS`` —— 否则越权 actor（例如 ``session_proposal``）会撞上
    原始的 ``CHECK constraint failed`` 并被包成 ``StoreError``，而不是一个明确的校验错误。
    「谁有权写审计」是**策略**，住在 ``write_deletion_audit`` 的显式校验里（只允许
    ``adult_control_plane`` 与 ``ttl_expiry``），不在 DDL 里。
    """

    audit_ddl = next(d for d in mem.MEMORY_SCHEMA_DDL if "CREATE TABLE deletion_audit " in d)
    for kind in mem.ACTOR_KINDS:
        assert f"'{kind}'" in audit_ddl, kind


def test_ddl_forbids_content_on_deleted_tombstones() -> None:
    """墓碑行不得携带正文 —— 即使墓碑真的出现，也不可能残留内容。"""

    assert "CHECK (status <> 'DELETED' OR content = '')" in _record_ddl()


def test_ddl_enforces_the_content_cap_with_a_historical_escape_hatch() -> None:
    """T9c / T9d：新列 + 表级 CHECK 描述「历史超长行放行、新行受限」。

    **落位也是契约的一部分**：SQLite 的**表级** CHECK 必须排在所有列定义之后
    （``MEMORY_RECORD_DDL`` 是「列 + 末尾表级 CHECK」结构），插在列中间会得到
    ``near "actor_kind": syntax error`` —— 所以这条同时断言它的位置。
    """

    record_ddl = _record_ddl()
    assert (
        "content_over_length INTEGER NOT NULL DEFAULT 0 "
        "CHECK (content_over_length IN (0,1))"
    ) in record_ddl
    assert "CHECK (content_over_length = 1 OR length(content) <= 500)" in record_ddl
    assert record_ddl.index("CHECK (content_over_length = 1") > record_ddl.index("actor_id"), (
        "表级 CHECK 必须排在列定义之后（T9d 点名的实现陷阱）"
    )
    assert "content_over_length" in set(mem.MemoryRecord.__dataclass_fields__)


def test_provenance_link_survives_source_deletion() -> None:
    """血缘行的 ``source_id`` 不能有外键 —— 否则来源被删后派生记录会「看起来没有祖先」。"""

    source_ddl = next(d for d in mem.MEMORY_SCHEMA_DDL if "CREATE TABLE memory_source " in d)
    source_id_line = next(
        line for line in source_ddl.splitlines() if line.strip().startswith("source_id")
    )
    assert "REFERENCES" not in source_id_line
    assert "record_id" in source_ddl and "REFERENCES memory_record(id) ON DELETE CASCADE" in source_ddl


def test_grant_ttl_has_a_hard_upper_bound() -> None:
    """「短期 grant」需要一个可核查的上界，否则「短期」只是形容词。"""

    assert isinstance(mem.MAX_GRANT_TTL_SECONDS, int)
    assert 0 < mem.MAX_GRANT_TTL_SECONDS <= 24 * 60 * 60


def test_projection_constants_are_usable() -> None:
    assert isinstance(mem.MEMORY_BLOCK_HEADER, str) and mem.MEMORY_BLOCK_HEADER.strip()
    assert isinstance(mem.MAX_PROJECTED_MEMORIES, int) and mem.MAX_PROJECTED_MEMORIES > 0
    # B-s6：框架句必须在 —— 内容逐字进 system instructions，要说清它是资料不是命令。
    assert "不是指令" in mem.MEMORY_BLOCK_HEADER


def test_a12_actor_attribution_is_frozen() -> None:
    """A12：``propose`` 的显式 actor、归属两列、schema 版本。"""

    import inspect

    params = inspect.signature(mem.MemoryService.propose).parameters
    assert list(params)[:3] == ["self", "candidate", "source_session"]
    assert params["actor"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["actor"].default is None, "缺省行为必须与 A12 之前逐字一致"

    fields = set(mem.MemoryRecord.__dataclass_fields__)
    assert {"actor_kind", "actor_id"} <= fields
    assert mem.ACTOR_COLUMNS == {"actor_kind", "actor_id"}
    # T15 第 5 处：M2.2 T9 把 schema 推到 v3（content_over_length + extraction_usage）。
    assert mem.MEMORY_SCHEMA_VERSION == 3

    record_ddl = next(d for d in mem.MEMORY_SCHEMA_DDL if "CREATE TABLE memory_record " in d)
    assert "actor_kind" in record_ddl and "actor_id" in record_ddl


def test_content_length_cap_is_frozen() -> None:
    """B-s5：单条 content 的硬上限。条数上限解决不了「一条超长撑满 instructions」。"""

    assert mem.MAX_CONTENT_CHARS == 500


# ---------------------------------------------------------------------------
# 7. 架构边界（静态扫描，不导入）
# ---------------------------------------------------------------------------


def _module_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _memory_package_modules() -> list[Path]:
    return sorted(MEMORY_PACKAGE_DIR.glob("*.py"))


def test_w0_file_set_is_present() -> None:
    """W0 建立的文件只增不减。**子集断言**，所以 W2 新增 ``grants.py`` 不会打红。"""

    present = {path.name for path in _memory_package_modules()}
    assert W0_FILE_SET <= present, f"W0 files disappeared: {sorted(W0_FILE_SET - present)}"


@pytest.mark.parametrize("path", _memory_package_modules(), ids=lambda p: p.name)
def test_memory_package_does_not_import_the_synthetic_prototype(path: Path) -> None:
    """M2 不把 ``soul_memory_kernel.privacy`` 的合成原型搬进产品路径。"""

    offenders = {m for m in _module_imports(path) if m.startswith("soul_memory_kernel.privacy")}
    assert offenders == set(), f"{path.name} imports the synthetic prototype: {offenders}"


@pytest.mark.parametrize("path", _memory_package_modules(), ids=lambda p: p.name)
def test_memory_package_does_not_depend_on_provider_or_audio_layers(path: Path) -> None:
    """记忆层不得反向依赖 adapters / voice / apps / benchmark / obs。"""

    forbidden_prefixes = (
        "soul_memory_kernel.adapters",
        "soul_memory_kernel.voice",
        "soul_memory_kernel.apps",
        "soul_memory_kernel.benchmark",
        "soul_memory_kernel.obs",
    )
    offenders = {
        module for module in _module_imports(path) if module.startswith(forbidden_prefixes)
    }
    assert offenders == set(), f"{path.name} depends on an outer layer: {offenders}"


# ---------------------------------------------------------------------------
# 8. fixture 映射
# ---------------------------------------------------------------------------

#: fixture 记录字段 → 契约中的落点。``shared_approved`` 是 fixture 的简写，
#: 在契约里展开为 ``audiences``（``true`` → ``{"family_all"}``，``false`` → 空集）。
FIXTURE_RECORD_FIELD_MAP: dict[str, str] = {
    "id": "MemoryRecord.id",
    "owner_id": "MemoryRecord.owner_id",
    "scope": "MemoryRecord.scope",
    "content": "MemoryRecord.content",
    "status": "MemoryRecord.status",
    "memory_policy": "MemoryRecord.memory_policy",
    "shared_approved": "MemoryRecord.audiences",
}

#: fixture 授权字段 → 契约中的落点。fixture 未给的字段按「最小授权」补齐。
FIXTURE_GRANT_FIELD_MAP: dict[str, str] = {
    "id": "Grant.grant_id",
    "owner_id": "Grant.owner_id",
    "session_id": "Grant.session_id",
    "expires_at": "Grant.expires_at",
    "issuer": "Grant.issuer",
}

#: **记录补齐规则（阻塞 3）。** fixture 记录只给 7 个字段，其余由这张表确定性补齐；
#: W2 不得自行发明取值。补齐后的记录必须满足 DDL 的全部 CHECK。
FIXTURE_RECORD_COMPLETION: dict[str, object] = {
    "memory_class": "EVENT",
    "source_type": "explicit_user",
    "confidence": 1.0,
    "importance": 0.5,
    "consent_version": 1,
    "source_ids": (),
    # A12（W5）：归属两列。fixture 记录没有 actor 可言，补齐值取「执行这次导入的主体」。
    "actor_kind": "adult_control_plane",
    "actor_id": "fixture-import",
    # T15 第 10 处（M2.2 T9c）：fixture 是 2026-09 之前的历史数据，正文都 ≤500，
    # 因此补齐值是正常的 0。缺了这一条，``test_record_completion_rules_cover_every_unset_field``
    # 会报 ``no completion rule for: ['content_over_length']``。
    "content_over_length": 0,
}
FIXTURE_COMPLETION_RULES: tuple[str, ...] = (
    "source_member_id := owner_id",
    "created_at := updated_at := evaluate_at",
    "last_confirmed_at := evaluate_at when status == 'ACTIVE' else None",
    "expires_at := None when (memory_class == 'SAFETY' and status in ACTIVE/DECAYED)",
    "expires_at := evaluate_at + candidate_days when status == 'PENDING_CONFIRMATION'",
    "expires_at := evaluate_at + event_days otherwise",
    "audiences := {'family_all'} when shared_approved is True else frozenset()"
    "（shared_approved 缺省视为 false）",
    "source_session_id := None (fixture carries no session link on records)",
    "content := '' when status == 'DELETED' (墓碑不带正文；见 FIXTURE_NORMALIZATIONS)",
    "content_over_length := 0 (fixture 的正文都 ≤500；历史超长行只可能来自真实库)",
)

#: **fixture 归一化登记。** 与 fixture 原文的字段级差异必须登记在这里，逐条可追溯。
#: fixture 文件本身**保持不动**（已 git 跟踪，改了会破坏历史可比性）。
FIXTURE_NORMALIZATIONS: dict[str, dict[str, str]] = {
    "shared_approved_to_audiences": {
        "field": "audiences",
        "rule": "shared_approved=true -> {'family_all'}；false -> 空集",
        "applies_to": "全部记录",
    },
    "mem-family-unapproved_status": {
        "field": "status",
        "rule": "ACTIVE -> PENDING_CONFIRMATION",
        "applies_to": "mem-family-unapproved",
        "why": (
            "fixture 原文是 ACTIVE + candidate_only + 未确认共享，违反 STATUS_POLICY_INVARIANT "
            "与 DDL 的 status<->policy CHECK；归一为候选后与 memory_policy=candidate_only 自洽，"
            "且不影响该 case 的结论（它本就不该被召回）"
        ),
    },
    "mem-deleted_content": {
        "field": "content",
        "rule": "DELETED -> content=''",
        "applies_to": "mem-deleted",
        "why": (
            "DDL 的 CHECK 要求墓碑行不带正文（status<>'DELETED' OR content=''）；"
            "fixture 原文给这条 DELETED 记录留了正文，归一为空串。"
            "清空只在 status 已是 DELETED 时发生，不影响任何 ACTIVE 记录"
        ),
    },
}

#: fixture case → 契约表达与预期结论。
#:
#: ``phase``   该 case 的结论在哪个相位成立。
#: ``reason``  该相位下的预期 reason。
#: ``m2_1_reason`` 在 **M2.1 产品路径**上的预期 reason（阻塞 1：PERSONAL 不可达）。
FIXTURE_CASE_MAPPING: dict[str, dict[str, object]] = {
    "authorized_owner_positive": {
        "phase": "M2.2",
        "construct": "authorize(action=read_model, access=controlled_private(adult_a), "
        "grant=grant-a-s1, session_id='session-1', audience_id='family_all', "
        "records=(mem-private-a,), now=evaluate_at)",
        "reason": "ok",
        "expected_ids": ("mem-private-a",),
        "m2_1_reason": "scope_not_enabled",
    },
    "unknown_denied": {
        "phase": "M2.1",
        "construct": "authorize(... grant=None, session_owner=None ...)",
        "reason": "no_grant",
        "expected_ids": (),
        "m2_1_reason": "no_grant",
    },
    "self_claim_denied": {
        "phase": "M2.1",
        "construct": "authorize(... grant=None ..., access.speaker_claim='adult_a')",
        "reason": "no_grant",
        "expected_ids": (),
        "m2_1_reason": "no_grant",
    },
    "wrong_owner_denied": {
        "phase": "M2.1",
        "construct": "authorize(... grant=grant-a-s1, access.session_owner='adult_b' ...)",
        "reason": "wrong_owner",
        "expected_ids": (),
        "m2_1_reason": "wrong_owner",
    },
    "expired_grant_denied": {
        "phase": "M2.1",
        "construct": "authorize(... grant=grant-a-expired, now=evaluate_at ...)",
        "reason": "expired",
        "expected_ids": (),
        "m2_1_reason": "expired",
    },
    "new_session_without_grant_denied": {
        "phase": "M2.1",
        "construct": "authorize(... session_id='session-2', grant=None ...)",
        "reason": "no_grant",
        "expected_ids": (),
        "m2_1_reason": "no_grant",
    },
    "approved_family_visible": {
        "phase": "M2.1",
        "construct": "authorize(action=read_model, access=shared, session_id='session-2', "
        "audience_id='family_all', grant=None, records=(mem-family-approved,), "
        "now=evaluate_at)",
        "reason": "ok",
        "expected_ids": ("mem-family-approved",),
        "m2_1_reason": "ok",
    },
}

#: **契约补充用例**（不在 fixture 里）。fixture 只有 1 个 FAMILY 正例，且它的唯一
#: PERSONAL 正例在 M2.1 不可达；这里补上 M2.1 产品路径上真实可达的正例，
#: 让「正例非空」的防作弊断言仍然成立。
CONTRACT_SUPPLEMENTARY_CASES: dict[str, dict[str, object]] = {
    "m2_1_family_event_positive": {
        "phase": "M2.1",
        "outcome": "ok",
        "records": (
            {"id": "sup-family-event", "scope": "FAMILY", "memory_class": "EVENT"},
        ),
        "expected_ids": ("sup-family-event",),
        "why": "M2.1 产品路径可达的 FAMILY 普通共享记忆正例",
    },
    "m2_1_family_safety_class_positive": {
        "phase": "M2.1",
        "outcome": "ok",
        "records": (
            {"id": "sup-family-allergy", "scope": "FAMILY", "memory_class": "SAFETY"},
        ),
        "expected_ids": ("sup-family-allergy",),
        "why": "FAMILY scope 下的 memory_class=SAFETY（如过敏）不受相位限制，且按 D5 不过期",
    },
    "m2_1_personal_scope_write_denied": {
        "phase": "M2.1",
        "outcome": "scope_not_enabled",
        "records": (),
        "expected_ids": (),
        "why": "PERSONAL scope 的产品路径尚未裁决（受控私人会话）",
    },
    "m2_1_safety_scope_write_denied": {
        "phase": "M2.1",
        "outcome": "scope_not_enabled",
        "records": (),
        "expected_ids": (),
        "why": "SAFETY scope 的『安全记忆给谁看』尚未裁决",
    },
    # T15 第 6 处：M2.2 放行 ``auto_extracted``（§6 收口表第 12 项）之后，
    # 这条从 ``validation_error`` 改为**接受**。**case id 保持不动** —— 契约 §6 T15
    # 与 W7b/W7c 都按这个 id 引用它，改名只会让映射漂移。
    "m2_1_auto_extracted_origin_rejected": {
        "phase": "M2.2",
        "outcome": "ok",
        "records": (),
        "expected_ids": (),
        "why": (
            "M2.2 §3 落地自动提取后 M2_1_ALLOWED_ORIGINS 放行 auto_extracted，"
            "propose() 接受这条候选（仍只落 PENDING_CONFIRMATION + candidate_only，"
            "成人确认是唯一生效路径）"
        ),
    },
}

_VALIDATION_ERROR = "validation_error"


@pytest.fixture(name="fixture_doc")
def fixture_doc_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_is_still_marked_synthetic_only(fixture_doc: dict) -> None:
    assert fixture_doc["data_class"] == "synthetic_only"
    assert fixture_doc["schema_version"] == 1


def test_every_fixture_case_is_mapped_exactly_once(fixture_doc: dict) -> None:
    """没有遗漏、也没有多余 —— W2 实现时不可能漏掉任一正反例。"""

    fixture_ids = [case["id"] for case in fixture_doc["cases"]]
    assert len(fixture_ids) == len(set(fixture_ids)), "duplicate case ids in fixture"
    assert set(fixture_ids) == set(FIXTURE_CASE_MAPPING)
    assert fixture_ids == list(FIXTURE_CASE_MAPPING), "mapping must keep fixture order"


def test_fixture_mapping_reasons_are_known() -> None:
    for case_id, row in FIXTURE_CASE_MAPPING.items():
        assert row["reason"] in mem.REASONS, case_id
        assert row["m2_1_reason"] in mem.REASONS, case_id
        assert row["phase"] in {"M2.1", "M2.2"}, case_id


def test_denied_cases_use_reasons_from_the_frozen_deny_order() -> None:
    for case_id, row in FIXTURE_CASE_MAPPING.items():
        for key in ("reason", "m2_1_reason"):
            reason = row[key]
            if reason != "ok":
                assert reason in mem.DENY_ORDER, f"{case_id}.{key} uses a non-denial reason"

    denied = {
        row["m2_1_reason"] for row in FIXTURE_CASE_MAPPING.values() if row["m2_1_reason"] != "ok"
    }
    assert denied == {"no_grant", "wrong_owner", "expired", "scope_not_enabled"}


def test_m2_1_reachable_positives_are_non_empty() -> None:
    """防作弊：独立验收不得把所有请求都拒绝算通过（沿用隐私内核验收的同一条纪律）。

    阻塞 1 之后 fixture 里唯一在 M2.1 可达的正例是 ``approved_family_visible``；
    补充用例再补上 FAMILY + SAFETY 类（过敏）这一条。两者都必须存在。
    """

    fixture_positives = {
        cid for cid, row in FIXTURE_CASE_MAPPING.items() if row["m2_1_reason"] == "ok"
    }
    supplementary_positives = {
        cid for cid, row in CONTRACT_SUPPLEMENTARY_CASES.items() if row["outcome"] == "ok"
    }
    assert fixture_positives == {"approved_family_visible"}
    assert fixture_positives | supplementary_positives >= {
        "approved_family_visible",
        "m2_1_family_event_positive",
        "m2_1_family_safety_class_positive",
    }


def test_personal_positive_is_marked_as_m2_2() -> None:
    """阻塞 1：fixture 的 PERSONAL 正例在 M2.1 不可达，必须显式登记相位。"""

    row = FIXTURE_CASE_MAPPING["authorized_owner_positive"]
    assert row["phase"] == "M2.2"
    assert row["reason"] == "ok", "fixture 自身的预期（M2.2 目标）保持不变"
    assert row["m2_1_reason"] == "scope_not_enabled"


def test_supplementary_cases_are_wellformed() -> None:
    valid_outcomes = mem.REASONS | {_VALIDATION_ERROR}
    for case_id, row in CONTRACT_SUPPLEMENTARY_CASES.items():
        assert row["outcome"] in valid_outcomes, case_id
        assert row["phase"] in {"M2.1", "M2.2"}, case_id
        assert row["why"], case_id
        if row["outcome"] == _VALIDATION_ERROR:
            assert row["expected_ids"] == ()
        if row["outcome"] == "scope_not_enabled":
            assert row["expected_ids"] == (), case_id


def test_phase_denied_scopes_are_exactly_personal_and_safety() -> None:
    """相位拒绝只针对 scope；``memory_class`` 不受限（关键区分，见阻塞 1）。"""

    denied_scopes = mem.SCOPES - mem.M2_1_ALLOWED_SCOPES
    assert denied_scopes == {"PERSONAL", "SAFETY"}
    # memory_class 与 scope 正交：SAFETY 类不被相位拒绝。
    assert mem.MEMORY_CLASSES - mem.M2_1_ALLOWED_SCOPES == mem.MEMORY_CLASSES


def test_every_fixture_record_field_has_a_contract_home(fixture_doc: dict) -> None:
    record_fields = set(mem.MemoryRecord.__dataclass_fields__)
    for record in fixture_doc["records"]:
        for key in record:
            assert key in FIXTURE_RECORD_FIELD_MAP, f"unmapped fixture record field: {key}"
            target = FIXTURE_RECORD_FIELD_MAP[key]
            if target.startswith("MemoryRecord."):
                assert target.split(".", 1)[1] in record_fields, target


def test_record_completion_rules_cover_every_unset_field(fixture_doc: dict) -> None:
    """阻塞 3：补齐后的记录必须**每个字段都有值**，W2 不需要自行发明任何取值。"""

    record_fields = set(mem.MemoryRecord.__dataclass_fields__)
    provided = set(FIXTURE_RECORD_FIELD_MAP.values())
    provided = {target.split(".", 1)[1] for target in provided}
    unset = record_fields - provided
    completed = set(FIXTURE_RECORD_COMPLETION) | {
        "source_member_id",
        "created_at",
        "updated_at",
        "last_confirmed_at",
        "expires_at",
        "source_session_id",
    }
    assert unset <= completed, f"no completion rule for: {sorted(unset - completed)}"
    assert len(FIXTURE_COMPLETION_RULES) >= 8


def test_completed_fixture_records_satisfy_every_ddl_invariant(fixture_doc: dict) -> None:
    """把补齐规则真的跑一遍，逐条核对 DDL 的六条 CHECK。

    这条把「补齐规则」从散文变成可执行断言：如果 fixture 改了，或补齐规则漏了某条
    不变量，测试当场红。
    """

    days = {"EVENT": mem.DEFAULT_TTL_EVENT_DAYS, "PREFERENCE": mem.DEFAULT_TTL_PREFERENCE_DAYS}
    for record in fixture_doc["records"]:
        scope = record["scope"]
        memory_class = str(FIXTURE_RECORD_COMPLETION["memory_class"])
        policy = record["memory_policy"]
        # 归一化登记：mem-family-unapproved 的 status 被归一为候选。
        status = "PENDING_CONFIRMATION" if policy == "candidate_only" else record["status"]
        audiences = (
            frozenset({"family_all"}) if record.get("shared_approved", False) else frozenset()
        )

        if memory_class == "SAFETY" and status in {"ACTIVE", "DECAYED"}:
            expires_at = None
        elif status == "PENDING_CONFIRMATION":
            expires_at = mem.DEFAULT_TTL_CANDIDATE_DAYS
        else:
            expires_at = days[memory_class]
        last_confirmed_at = "evaluate_at" if status == "ACTIVE" else None
        # 归一化登记：墓碑行不带正文（mem-deleted_content）。
        content = "" if status == "DELETED" else record["content"]

        label = f"{record['id']}: "
        # CHECK 1
        assert scope != "SAFETY" or memory_class == "SAFETY", label + "scope/class"
        # CHECK 2（候选一律有期限）
        assert expires_at is not None or (
            memory_class == "SAFETY" and status in {"ACTIVE", "DECAYED"}
        ), label + "expiry"
        # CHECK 3
        assert scope != "FAMILY" or status != "ACTIVE" or last_confirmed_at is not None, (
            label + "family-confirmed"
        )
        # CHECK 4（status ↔ policy）
        assert (
            status == "DELETED"
            or (status == "PENDING_CONFIRMATION" and policy == "candidate_only")
            or (status in {"ACTIVE", "DECAYED"} and policy == "persist_confirmed")
        ), label + "status-policy"
        # CHECK 5（策略取值）与 CHECK 6（墓碑无正文）
        assert policy in mem.MEMORY_POLICIES, label + "policy"
        assert status != "DELETED" or content == "", label + "tombstone-content"
        assert audiences <= mem.RESERVED_AUDIENCES | {"family_all"}, label + "audiences"


def test_fixture_normalizations_are_registered(fixture_doc: dict) -> None:
    """与 fixture 原文的字段级差异必须登记在案，逐条可追溯。"""

    records = {record["id"]: record for record in fixture_doc["records"]}
    unapproved = records["mem-family-unapproved"]
    # fixture 原文的不自洽组合是归一化的**触发条件**；若 fixture 改了，这条会红。
    assert unapproved["status"] == "ACTIVE"
    assert unapproved["memory_policy"] == "candidate_only"
    assert "mem-family-unapproved_status" in FIXTURE_NORMALIZATIONS
    assert FIXTURE_NORMALIZATIONS["mem-family-unapproved_status"]["applies_to"] == (
        "mem-family-unapproved"
    )
    # A3：墓碑正文归一化必须登记，且触发条件在 fixture 原文里确实成立。
    assert records["mem-deleted"]["content"] != "", "fixture 原文应当带正文，否则归一化无意义"
    assert "mem-deleted_content" in FIXTURE_NORMALIZATIONS
    assert FIXTURE_NORMALIZATIONS["mem-deleted_content"]["applies_to"] == "mem-deleted"
    for name, entry in FIXTURE_NORMALIZATIONS.items():
        assert entry["field"] and entry["rule"], name


def test_every_fixture_grant_field_has_a_contract_home(fixture_doc: dict) -> None:
    grant_fields = set(mem.Grant.__dataclass_fields__)
    for grant in fixture_doc["fixture_grants"]:
        for key in grant:
            assert key in FIXTURE_GRANT_FIELD_MAP, f"unmapped fixture grant field: {key}"
            assert FIXTURE_GRANT_FIELD_MAP[key].split(".", 1)[1] in grant_fields


def test_fixture_status_and_policy_values_are_contract_values(fixture_doc: dict) -> None:
    for record in fixture_doc["records"]:
        assert record["status"] in mem.MEMORY_STATUSES, record["id"]
        assert record["memory_policy"] in mem.MEMORY_POLICIES, record["id"]
        assert record["scope"] in mem.SCOPES, record["id"]


def test_fixture_expiry_expectations_match_the_frozen_rule(fixture_doc: dict) -> None:
    """按契约的 ``now >= expires_at`` 规则，逐条核对 fixture 自己声明的预期。

    这条把「映射表里写 expired」从断言变成了**算术核对**：如果 fixture 改了时间戳
    而没有同步映射表，测试会失败。
    """

    from datetime import datetime

    now = datetime.fromisoformat(fixture_doc["evaluate_at"].replace("Z", "+00:00"))
    grants = {grant["id"]: grant for grant in fixture_doc["fixture_grants"]}
    for case in fixture_doc["cases"]:
        grant_id = case.get("grant_id")
        if grant_id is None:
            continue
        expires_at = datetime.fromisoformat(grants[grant_id]["expires_at"].replace("Z", "+00:00"))
        expected_reason = FIXTURE_CASE_MAPPING[case["id"]]["reason"]
        if expected_reason == "expired":
            assert now >= expires_at, f"{case['id']} is mapped expired but the grant is still live"
        else:
            assert now < expires_at, f"{case['id']} is mapped live but the grant already expired"


def test_fixture_unapproved_candidate_is_not_recallable(fixture_doc: dict) -> None:
    """``mem-family-unapproved`` 归一为候选 —— 契约里它到不了任何正例。"""

    records = {record["id"]: record for record in fixture_doc["records"]}
    unapproved = records["mem-family-unapproved"]
    assert unapproved["shared_approved"] is False
    assert unapproved["memory_policy"] == "candidate_only"
    recalled = _all_recalled_ids()
    assert "mem-family-unapproved" not in recalled


def test_fixture_deleted_record_is_not_recallable(fixture_doc: dict) -> None:
    records = {record["id"]: record for record in fixture_doc["records"]}
    assert records["mem-deleted"]["status"] == "DELETED"
    assert "mem-deleted" not in _all_recalled_ids()


def _all_recalled_ids() -> set[str]:
    ids: set[str] = set()
    for row in FIXTURE_CASE_MAPPING.values():
        ids.update(row["expected_ids"])  # type: ignore[arg-type]
    for row in CONTRACT_SUPPLEMENTARY_CASES.values():
        ids.update(row["expected_ids"])  # type: ignore[arg-type]
    return ids


# ---------------------------------------------------------------------------
# 9. r3 契约增补（A1–A10）
# ---------------------------------------------------------------------------


def test_memory_store_declares_expiry_and_audit_primitives() -> None:
    """A1：``sweep_expired`` 的两条路径需要两个原语，签名以 W1 的实现为准。"""

    expired = inspect.signature(mem.MemoryStore.list_expired)
    assert list(expired.parameters) == ["self", "now"]
    assert expired.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
    # W1 返回完整记录而非 id 元组：调用方要靠 status 分派两条路径。
    assert expired.return_annotation in ("tuple[MemoryRecord, ...]",)

    audit = inspect.signature(mem.MemoryStore.write_deletion_audit)
    assert list(audit.parameters) == [
        "self",
        "record_id",
        "actor",
        "deleted_at",
        "tables_touched",
        "derived_removed",
        "unknown_copies",
    ]
    for name in ("record_id", "actor", "deleted_at", "tables_touched"):
        assert audit.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY, name
    assert audit.parameters["derived_removed"].default == 0
    assert audit.parameters["unknown_copies"].default == ()
    assert audit.return_annotation in ("str",)


def test_lineage_rule_is_uniform_and_fail_closed() -> None:
    """A2：§7.1 第 3 项与 §7.4 统一为同一口径 —— 不级联删派生记录。"""

    assert mem.DELETE_KEEPS_INBOUND_PROVENANCE is True
    # 血缘行的 source_id 仍然没有外键（级联会抹掉「曾经有祖先」这个事实）。
    source_ddl = next(d for d in mem.MEMORY_SCHEMA_DDL if "CREATE TABLE memory_source " in d)
    source_id_line = next(
        line for line in source_ddl.splitlines() if line.strip().startswith("source_id")
    )
    assert "REFERENCES" not in source_id_line


def test_deletion_report_separates_removed_from_unreachable() -> None:
    """A2 的诚实报告通道：删不掉的派生记录必须有地方如实列出。"""

    fields = set(mem.DeletionReport.__dataclass_fields__)
    assert "derived_removed" in fields
    assert "derived_unreachable" in fields
    doc = mem.DeletionReport.__doc__ or ""
    assert "derived_unreachable" in doc
    assert "仍留在盘上" in doc


def test_revoked_is_not_a_judgment_reason() -> None:
    """A4：撤销是存储层语义（store 返回 None → ``no_grant``），判权层不读撤销标记。"""

    assert "revoked" not in mem.REASONS
    assert "revoked" not in mem.DENY_ORDER
    # Grant 数据类不携带撤销状态 —— 撤销后的 grant 根本不会到达判权函数。
    assert "revoked_at" not in set(mem.Grant.__dataclass_fields__)


def test_no_grant_exemption_covers_only_read_actions() -> None:
    """A5 + T15 第 3 处：例外只覆盖三个**读取**动作，出口与写动作永远需要 grant。

    M2.2 加进 ``review_control_plane``（§4.1）—— 它是只读复审动作，
    **只在控制面访问形态下**可用，且 `PERSONAL` / `SAFETY` 仍被 ``scope_not_enabled``
    先拦（见 ``test_personal_candidate_is_scope_not_enabled_not_no_grant``）。
    """

    assert mem.NO_GRANT_EXEMPT_ACTIONS == {
        "read_model",
        "send_provider",
        "review_control_plane",
    }
    assert mem.NO_GRANT_EXEMPT_ACTIONS < mem.ACTIONS
    # 出口动作不在例外里：外放到公共空间 != 家人可读。
    assert {"publish_text", "play_audio"}.isdisjoint(mem.NO_GRANT_EXEMPT_ACTIONS)
    assert {"write", "share", "delete"}.isdisjoint(mem.NO_GRANT_EXEMPT_ACTIONS)


def test_m2_1_write_gate_table_is_frozen() -> None:
    """A7 + A8 + T15 第 4 处：写门禁的 actor 门逐操作冻结。

    M2.2 新增 ``reassign_owner``（D13 / §2.4 T26'）—— 只允许 ``adult_control_plane``。
    """

    assert mem.M2_1_WRITE_GATE == {
        "propose": {"adult_control_plane", "session_proposal"},
        "confirm_shared": {"adult_control_plane"},
        "correct": {"adult_control_plane"},
        "delete": {"adult_control_plane"},
        "sweep_expired": {"ttl_expiry"},
        "reassign_owner": {"adult_control_plane"},
    }
    for operation, allowed in mem.M2_1_WRITE_GATE.items():
        assert allowed <= mem.ACTOR_KINDS, operation
        assert allowed, operation


def test_session_proposal_can_only_propose() -> None:
    """A8：``session_proposal`` 只能 propose；**严禁**被记成成人确认。"""

    assert "session_proposal" in mem.ACTOR_KINDS
    proposing = {op for op, kinds in mem.M2_1_WRITE_GATE.items() if "session_proposal" in kinds}
    assert proposing == {"propose"}, "session_proposal must not reach any other write path"
    # 只有 propose 同时接受两个 kind；其余写操作的 actor 集合都不含它。
    for operation, allowed in mem.M2_1_WRITE_GATE.items():
        if operation != "propose":
            assert "session_proposal" not in allowed, operation


def test_m2_1_write_paths_do_not_use_require() -> None:
    """A7：M2.1 写门禁是三重检查（相位门 + actor 门 + 迁移表），``require()`` 归 M2.2。"""

    assert mem.M2_1_WRITE_PATHS_USE_REQUIRE is False
    # require() 仍然冻结着签名（M2.2 要用），只是 M2.1 不调用。
    assert inspect.signature(mem.require).parameters.keys() == (
        inspect.signature(mem.authorize).parameters.keys()
    )
    assert "M2.2" in (mem.require.__doc__ or "")


def test_every_write_path_has_a_phase_actor_gate() -> None:
    """三重门禁的第三道是迁移表：写门禁表里的每个操作都必须有对应约束。

    M2.2 的 ``reassign_owner`` 是**只对候选**的动作：它没有自己的迁移边，
    而是用「回到候选」这条**不存在**的边拒绝非候选记录（见
    ``MemoryService.reassign_owner`` 与 ``test_active_never_falls_back_to_candidate``）。
    """

    assert set(mem.M2_1_WRITE_GATE) <= {
        "propose",
        "confirm_shared",
        "correct",
        "delete",
        "sweep_expired",
        "reassign_owner",
    }
    # confirm / correct 落进迁移表；sweep 由 TTL_TRANSITIONS 约束。
    assert ("PENDING_CONFIRMATION", "ACTIVE") in mem.LEGAL_TRANSITIONS
    assert mem.TTL_TRANSITIONS <= mem.LEGAL_TRANSITIONS
    # reassign_owner 只对候选：ACTIVE / DECAYED 都没有回到候选的迁移边。
    for source in ("ACTIVE", "DECAYED", "DELETED"):
        assert (source, "PENDING_CONFIRMATION") not in mem.LEGAL_TRANSITIONS, source


def test_sqlite_grant_store_lives_in_the_grants_module() -> None:
    """A10：``SqliteGrantStore`` 归 ``grants.py``，``store.py`` 不再声明它。"""

    assert mem.SqliteGrantStore.__module__ == "soul_memory_kernel.memory.grants"
    assert mem.load_grant_for_session.__module__ == "soul_memory_kernel.memory.grants"
    store_module = __import__("soul_memory_kernel.memory.store", fromlist=["_"])
    assert not hasattr(store_module, "SqliteGrantStore"), (
        "SqliteGrantStore must live in grants.py, not store.py"
    )
    assert mem.SqliteMemoryStore.__module__ == "soul_memory_kernel.memory.store"


def test_grant_failures_are_validation_errors() -> None:
    """A6：签发/撤销的 actor 与 issuer 问题抛 ``MemoryValidationError``。"""

    issue_doc = mem.GrantStore.issue.__doc__ or ""
    revoke_doc = mem.GrantStore.revoke.__doc__ or ""
    assert "MemoryValidationError" in issue_doc
    assert "issuer" in issue_doc
    assert "MemoryValidationError" in revoke_doc
    assert "adult_control_plane" in revoke_doc


def test_projection_seam_requires_both_authorizations() -> None:
    """A9：接缝必须按序做 ``read_model`` 与 ``send_provider`` 两次授权。"""

    assert mem.PROJECTION_SEAM_ACTIONS == ("read_model", "send_provider")
    assert set(mem.PROJECTION_SEAM_ACTIONS) <= mem.ACTIONS
    projection_module = __import__("soul_memory_kernel.memory.projection", fromlist=["_"])
    source = Path(projection_module.__file__).read_text(encoding="utf-8")
    assert "send_provider" in source
    assert "不自动升级为" in source


# ---------------------------------------------------------------------------
# 10. M2.2 判权增量（§4.1 / §4.3 / §2.4）
# ---------------------------------------------------------------------------


def _personal_candidate_record() -> mem.MemoryRecord:
    """一条 ``PERSONAL`` 候选（判权输入的最小形状）。"""

    return mem.MemoryRecord(
        id="rec-personal-candidate",
        owner_id="adult_a",
        scope="PERSONAL",
        memory_class="EVENT",
        source_type="explicit_user",
        source_member_id="adult_a",
        content="合成私人候选",
        confidence=1.0,
        importance=0.5,
        created_at="2026-09-26T12:00:00Z",
        updated_at="2026-09-26T12:00:00Z",
        last_confirmed_at=None,
        expires_at="2026-10-03T12:00:00Z",
        source_session_id=None,
        status="PENDING_CONFIRMATION",
        memory_policy="candidate_only",
        audiences=frozenset({"family_all"}),
        consent_version=1,
    )


def test_personal_candidate_with_control_plane_access_is_scope_not_enabled() -> None:
    """T15 第 7 处（§4.1 末段）：免 grant 判定对 control-plane 复审**无条件**成立。

    若把 ``review_control_plane`` 直接塞进 ``_is_grant_exempt``（它要求
    ``scope ∈ M2_1_ALLOWED_SCOPES`` 且受众命中），一条 ``PERSONAL`` 候选会变成
    「需要 grant」，于是在 ``grant=None`` 时先撞 ``no_grant`` —— 而**不是** D11
    硬边界 2 要求的 ``scope_not_enabled``。这条把那个错误钉死。

    判权输入用**真实**的 ``SessionAccess.for_control_plane()``：W8 已把 ``SessionMode``
    的第三个取值与那个构造器落地，W9 当年的 ``ControlPlaneAccess`` 替身随之退役
    （勘误 E7）。
    """

    from soul_memory_kernel.soul.policy import SessionAccess

    decision = mem.authorize(
        action="review_control_plane",
        access=SessionAccess.for_control_plane(),
        grant=None,
        session_id="cli-session",
        audience_id="family_all",
        records=(_personal_candidate_record(),),
        now="2026-09-26T12:00:00Z",
    )

    assert decision.allowed is False
    assert decision.reason == "scope_not_enabled"
    assert decision.reason != "no_grant"


def test_control_plane_review_action_is_never_used_by_the_projection_paths() -> None:
    """§4.2 硬边界 3：``review_control_plane`` **不进任何投影**（T15 第 1/2 处的连带）。"""

    assert mem.PROJECTION_SEAM_ACTIONS == ("read_model", "send_provider")
    assert mem.PROJECTION_SEAM_ACTIONS[0] == "read_model"
    assert "review_control_plane" not in mem.PROJECTION_SEAM_ACTIONS


def test_grant_action_choices_exclude_the_review_action() -> None:
    """T15 第 11 处（A 的 N9）：``grant_action`` 的取值集 **== ACTIONS − {review_control_plane}**。

    复审动作**永不进 grant DDL** —— 它是免 grant 的（§4.1）。这条把「以后有人顺手
    把它加进 grant 表」钉死：那会让一个免 grant 的动作重新获得一条 grant 路径。
    """

    grant_action_ddl = next(
        d for d in mem.MEMORY_SCHEMA_DDL if "CREATE TABLE grant_action " in d
    )
    inside = grant_action_ddl.split("action IN (", 1)[1].split(")", 1)[0]
    declared = frozenset(part.strip().strip("'") for part in inside.split(","))

    assert declared == mem.ACTIONS - {"review_control_plane"}
    assert "review_control_plane" not in declared
    assert declared == {
        "read_model",
        "send_provider",
        "publish_text",
        "play_audio",
        "write",
        "share",
        "delete",
    }
