"""W8 契约测试：控制面复审（③）—— 判权矩阵、AST 护栏、可签发动作集、CLI 复审路径。

契约依据：``docs/M2-2-CONTRACT.md`` §4.1（判权表 + 免 grant 的**无条件性** + 勘误 E4 的
``GRANTABLE_ACTIONS`` + 勘误 E8 的墓碑口径）、§4.2（三条硬边界 + ``for_control_plane()`` +
AST 锁）、§4.3（新 ``QueryPurpose`` 与 ``inspect`` 流程）、§4.4（对召回面的影响：无）、
§10.2 的 ⑨–⑫b、§3.9（`count_over_length()`，勘误 E3）、§6 T9c（flagged 行的写入边界）。

四条硬边界各有一个**结构性**用例（不靠纪律）：

1. 只有 ``control_plane`` 模式可用 —— 判权矩阵 + AST 锁死唯一构造点；
2. 只覆盖 ``FAMILY`` —— `PERSONAL` / `SAFETY` 仍是 `scope_not_enabled`；
3. 永不进入投影 —— ``review_control_plane`` 不在 `session_projection` / `send_provider`
   的判定里；
4. 免 grant 的动作**不可签发** —— ``GRANTABLE_ACTIONS`` 在解析层与 ``issue()`` 两处收口。

全程离线：只操作 ``tmp_path`` 下的临时库与合成记录（``tests/conftest.py`` 的守门生效）。
"""

from __future__ import annotations

import ast
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import soul_memory_kernel.memory as mem
from soul_memory_kernel.memory import cli as memory_cli
from soul_memory_kernel.memory.grants import GRANTABLE_ACTIONS, SqliteGrantStore
from soul_memory_kernel.memory.model import Actor, Grant, MemoryRecord
from soul_memory_kernel.memory.policy import ACTIONS
from soul_memory_kernel.memory.projection import PROJECTION_SEAM_ACTIONS
from soul_memory_kernel.memory.service import MemoryService, MemoryValidationError, RetentionPolicy, StoreError
from soul_memory_kernel.memory.store import SqliteMemoryStore
from soul_memory_kernel.soul.policy import CONTROL_PLANE_AUTHORIZATION_REF, SessionAccess
from tests.test_memory_migration import OVER_LONG, _build_v2  # noqa: PLC2701 —— 复用 W9 的 v2 建库器

REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_DIR = REPO_ROOT / "soul_memory_kernel"

NOW = "2026-09-26T12:00:00Z"
LATER = "2026-10-03T12:00:00Z"
EXPIRED = "2026-09-25T12:00:00Z"
SESSION_ID = "cli-session"
AUDIENCE = "family_all"
OWNER = "adult_a"
ADULT = Actor(kind="adult_control_plane", actor_id="family-ai-memory")


@pytest.fixture(autouse=True)
def _frozen_cli_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI 的时钟钉在 ``NOW``：候选期是「天」为单位，跑在真实墙钟上迟早会过期。"""

    monkeypatch.setattr(memory_cli, "_system_clock", lambda: NOW)


# ---------------------------------------------------------------------------
# 合成记录与判权调用
# ---------------------------------------------------------------------------


def _record(**overrides: Any) -> MemoryRecord:
    """一条 FAMILY **候选**（``PENDING_CONFIRMATION`` + ``candidate_only``）。"""

    base: dict[str, Any] = {
        "id": "mem-candidate",
        "owner_id": OWNER,
        "scope": "FAMILY",
        "memory_class": "EVENT",
        "source_type": "explicit_user",
        "source_member_id": OWNER,
        "content": "周五去露营",
        "confidence": 1.0,
        "importance": 0.5,
        "created_at": NOW,
        "updated_at": NOW,
        "last_confirmed_at": None,
        "expires_at": LATER,
        "source_session_id": None,
        "status": "PENDING_CONFIRMATION",
        "memory_policy": "candidate_only",
        "audiences": frozenset({AUDIENCE}),
        "consent_version": 1,
        "source_ids": (),
    }
    base.update(overrides)
    return MemoryRecord(**base)


def _active(**overrides: Any) -> MemoryRecord:
    base: dict[str, Any] = {
        "status": "ACTIVE",
        "memory_policy": "persist_confirmed",
        "last_confirmed_at": NOW,
    }
    base.update(overrides)
    return _record(**base)


_UNSET = object()


def _review(*, access: Any = _UNSET, **overrides: Any) -> mem.AuthorizationDecision:
    """``review_control_plane`` 的判权调用（默认：控制面 + 一条候选 + 无 grant）。

    ``access`` 用哨兵区分「没给」（默认控制面）与「显式给 ``None``」（类型兜底用例）。
    """

    kwargs: dict[str, Any] = {
        "action": "review_control_plane",
        "access": SessionAccess.for_control_plane(),
        "grant": None,
        "session_id": SESSION_ID,
        "audience_id": AUDIENCE,
        "records": (_record(),),
        "now": NOW,
    }
    if access is not _UNSET:
        kwargs["access"] = access
    kwargs.update(overrides)
    return mem.authorize(**kwargs)


# ---------------------------------------------------------------------------
# ⑨ 判权矩阵（§4.1 的表逐行）
# ---------------------------------------------------------------------------

#: ``(access, records, expected_reason)`` 的**逐行**矩阵。
#: ``expected_reason is None`` = 放行（这条矩阵必须**非空正例**，否则「全拒绝」也会通过）。
MATRIX: tuple[tuple[Any, Any, str | None], ...] = (
    # -- 硬边界 1：会话路径拿不到这个动作（模式校验 → action_not_granted）--
    (SessionAccess(), (_record(),), "action_not_granted"),
    (SessionAccess(session_mode="controlled_private"), (_record(),), "action_not_granted"),
    (
        SessionAccess(
            session_mode="controlled_private",
            session_owner=OWNER,
            authorization_ref="ctl:test",
        ),
        (_record(),),
        "action_not_granted",
    ),
    # -- 控制面：候选就是它存在的理由（唯一被跳过的记录级检查是 status_denied）--
    (SessionAccess.for_control_plane(), (_record(),), None),
    (SessionAccess.for_control_plane(), (_active(),), None),
    (
        SessionAccess.for_control_plane(),
        (_record(status="DECAYED", memory_policy="persist_confirmed", last_confirmed_at=NOW),),
        None,
    ),
    # -- 其余记录级检查一律照常（绝不写成 early-return）--
    (
        SessionAccess.for_control_plane(),
        (_record(expires_at=EXPIRED),),
        "record_expired",
    ),
    (
        SessionAccess.for_control_plane(),
        (_record(source_ids=("ghost-ancestor",)),),
        "missing_provenance",
    ),
    (SessionAccess.for_control_plane(), (_record(scope="PERSONAL"),), "scope_not_enabled"),
    (
        SessionAccess.for_control_plane(),
        (
            _record(
                scope="SAFETY",
                memory_class="SAFETY",
                expires_at=None,
            ),
        ),
        "scope_not_enabled",
    ),
    (
        SessionAccess.for_control_plane(),
        (_record(audiences=frozenset({"someone-else"})),),
        "scope_denied",
    ),
    (
        SessionAccess.for_control_plane(),
        (_record(memory_policy="do_not_persist"),),
        "policy_denied",
    ),
    (
        SessionAccess.for_control_plane(),
        (_active(memory_policy="candidate_only"),),
        "policy_denied",
    ),
    # -- 类型兜底先于模式校验（非 SessionAccess / 非 Grant）--
    (None, (_record(),), "no_grant"),
    ("not-an-access", (_record(),), "no_grant"),
    (SessionAccess.for_control_plane(), (_record(),), "no_grant"),  # 见下面的 grant 覆盖
)

MATRIX_IDS = (
    "shared-candidate",
    "controlled-private-candidate",
    "controlled-private-owner-candidate",
    "control-plane-candidate-ok",
    "control-plane-active-ok",
    "control-plane-decayed-ok",
    "control-plane-expired",
    "control-plane-missing-provenance",
    "control-plane-personal",
    "control-plane-safety-class",
    "control-plane-audience-mismatch",
    "control-plane-corrupt-policy",
    "control-plane-status-policy-mismatch",
    "access-none",
    "access-not-a-session-access",
    "grant-is-not-a-grant",
)


@pytest.mark.parametrize(("access", "records", "expected"), MATRIX, ids=MATRIX_IDS)
def test_review_control_plane_authorization_matrix(
    access: object, records: tuple[MemoryRecord, ...], expected: str | None
) -> None:
    """§4.1 的判定表**逐行**：模式校验、类型兜底、以及「只跳过 ``status_denied``」。

    最后一行（`grant-is-not-a-grant`）用伪造的 grant 走类型兜底：``review_control_plane``
    **整段不需要 grant**，但一个「不是 ``Grant`` 的 grant 入参」仍然 fail-closed 成
    ``no_grant``（类型兜底在模式校验之前，模式校验不能反过来制造新的抛错点）。
    """

    if expected == "no_grant" and isinstance(access, SessionAccess):
        # 只有最后一行走这条路：伪造的 grant。
        decision = _review(access=access, records=records, grant={"grant_id": "forged"})
    else:
        decision = _review(access=access, records=records)

    assert decision.reason == (expected or "ok"), decision
    assert decision.allowed is (expected is None)


def test_review_control_plane_needs_no_grant_and_ignores_grants_it_might_see() -> None:
    """免 grant 是**无条件**的：空 grant 放行，一个无关 grant 也一样放行。

    若把本动作塞进 ``_is_grant_exempt``（要求 ``FAMILY`` + 受众命中），一条 ``PERSONAL``
    候选会变成「需要 grant」并先撞 ``no_grant`` —— 矩阵里的 `control-plane-personal`
    行把那个错误钉死（它必须报 ``scope_not_enabled``）。
    """

    assert _review().allowed is True
    stranger = Grant(
        grant_id="grant-other",
        version=1,
        session_id="another-session",
        subject_id="adult_b",
        owner_id="adult_b",
        audience_id="someone-else",
        actions=frozenset({"read_model"}),
        resource_ids=frozenset({"mem-other"}),
        consent_versions=(("mem-other", 3),),
        expires_at=LATER,
        issuer="cli",
        issued_at=NOW,
    )
    # 复审动作整段不看 grant：换会话 / 换 owner / 换受众都不影响它的结论。
    assert _review(grant=stranger).allowed is True
    # 对照：同一条候选走 `read_model` 仍然是 status_denied（M2.1 现状）。
    assert (
        mem.authorize(
            action="read_model",
            access=SessionAccess(),
            grant=None,
            session_id=SESSION_ID,
            audience_id=AUDIENCE,
            records=(_record(),),
            now=NOW,
        ).reason
        == "status_denied"
    )


def test_deleted_tombstone_is_readable_by_review_and_carries_no_content(tmp_path: Path) -> None:
    """勘误 E8：``review_control_plane`` **不拦墓碑** —— 这是刻意的，且无正文可泄露。

    两半都要断言：

    1. 判权面：一条 ``DELETED`` 墓碑（``content=""``）在复审下 ``allowed is True``
       —— CLI 文案因此**不能**写成「墓碑不可复审」；
    2. 数据面：墓碑**不可能**带正文 —— 真库的 DDL CHECK
       （``CHECK (status <> 'DELETED' OR content = '')``）当场拒绝。
    """

    tombstone = _record(
        id="mem-tombstone",
        status="DELETED",
        memory_policy="persist_confirmed",
        content="",
        last_confirmed_at=NOW,
    )
    assert tombstone.content == ""
    assert _review(records=(tombstone,)).allowed is True

    db_path = tmp_path / "memory.sqlite3"
    SqliteMemoryStore(db_path).create_schema()
    with sqlite3.connect(db_path) as db:
        # 同一行、只有 content 不同：空正文通过，非空被墓碑 CHECK 拒绝 ——
        # 证明拒绝来自 `CHECK (status <> 'DELETED' OR content = '')`，不是别的约束。
        _insert_tombstone(db, "mem-tombstone-ok", content="")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_tombstone(db, "mem-tombstone-bad", content="墓碑不该有正文")


# ---------------------------------------------------------------------------
# ⑩ AST 锁：control_plane 访问的唯一构造点（§4.2）
# ---------------------------------------------------------------------------


def _production_files() -> list[Path]:
    return sorted(PRODUCTION_DIR.rglob("*.py"))


def _for_control_plane_call_sites() -> list[tuple[str, int]]:
    sites: list[tuple[str, int]] = []
    for path in _production_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "for_control_plane"
            ):
                sites.append((path.relative_to(REPO_ROOT).as_posix(), node.lineno))
    return sites


def _session_mode_literal_call_sites() -> list[tuple[str, int]]:
    """生产代码里 ``f(..., session_mode="control_plane", ...)`` 的字面量构造点。"""

    sites: list[tuple[str, int]] = []
    for path in _production_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "session_mode"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == "control_plane"
                ):
                    sites.append((path.relative_to(REPO_ROOT).as_posix(), node.lineno))
    return sites


def test_for_control_plane_has_exactly_one_production_caller_file() -> None:
    """§4.2 / §10.2 ⑩：``SessionAccess.for_control_plane(`` 的调用点**恰好**是本机 CLI。

    「只能由 CLI 构造」不靠纪律：多一个调用点（比如某个 adapter 或 console 顺手构造
    control-plane 访问）就当场红灯。
    """

    sites = _for_control_plane_call_sites()
    files = sorted({path for path, _ in sites})
    assert files == ["soul_memory_kernel/memory/cli.py"], sites
    # CLI 必须**真的**用它：list 与 inspect 两条读路径都在里面（§4.2 末条）。
    assert len(sites) >= 2, sites
    # 冻结的 ref 常量与 `for_control_plane()` 的默认值同源。
    assert SessionAccess.for_control_plane().authorization_ref == CONTROL_PLANE_AUTHORIZATION_REF


def test_no_production_literal_builds_a_control_plane_access() -> None:
    """§4.2：生产代码里不允许 ``session_mode="control_plane"`` 的字面量构造。

    唯一例外是定义处 ``family_ai/soul/policy.py``（``for_control_plane()`` 里那一行）——
    这条规则正是「绕开专用构造器直接拼一个控制面访问」的拦网点。
    """

    sites = _session_mode_literal_call_sites()
    # 唯一允许的字面量构造点：定义处（`for_control_plane()` 里的 `cls(...)`）。
    assert sorted({path for path, _ in sites}) == ["soul_memory_kernel/soul/policy.py"], sites
    assert len(sites) == 1, sites


# ---------------------------------------------------------------------------
# ⑩b §7.5 第 8 项（M2.3）：control_plane 形态**不带说话人**（冗余加固）
# ---------------------------------------------------------------------------


def test_control_plane_access_rejects_a_selected_speaker() -> None:
    """§7.5 第 8 项：``control_plane`` + 非空 ``selected_speaker_id`` ⇒ 构造期 ``ValueError``。

    与既有的两条同类约束（``session_owner is None`` / ``authorization_ref`` 非空）同处一个
    分支、同一种抛错。它**不是**缺陷修复：判定侧（§4.1）本来就不消费 ``selected_speaker_id``
    与 ``identity_assurance``，这里只是把「控制面不是人，却带着一个说话人」这种没有意义的
    形态变得**不可表达**（``is not None`` 与 ``authorization_ref`` 的判据一致：空串也算带了）。
    """

    with pytest.raises(ValueError):
        SessionAccess(
            session_mode="control_plane",
            authorization_ref=CONTROL_PLANE_AUTHORIZATION_REF,
            selected_speaker_id=OWNER,
        )
    # 手动的身份保证同样要带选择 ⇒ 一并被这条新约束挡住。
    with pytest.raises(ValueError):
        SessionAccess(
            session_mode="control_plane",
            authorization_ref=CONTROL_PLANE_AUTHORIZATION_REF,
            selected_speaker_id=OWNER,
            identity_assurance="manually_selected_unverified",
        )
    with pytest.raises(ValueError):
        SessionAccess(
            session_mode="control_plane",
            authorization_ref=CONTROL_PLANE_AUTHORIZATION_REF,
            selected_speaker_id="",
        )
    # 对照：另外两种会话形态**照旧**允许带手动选择（不在本次加固范围内）。
    assert SessionAccess.for_manual_selection(OWNER).selected_speaker_id == OWNER
    assert (
        SessionAccess(
            session_mode="controlled_private",
            session_owner=OWNER,
            authorization_ref="ctl:test",
            selected_speaker_id=OWNER,
            identity_assurance="manually_selected_unverified",
        ).selected_speaker_id
        == OWNER
    )


def test_for_control_plane_still_constructs_and_the_matrix_is_unchanged() -> None:
    """验收②③④：``for_control_plane()`` 的产出仍能构造，判权矩阵与 CLI 调用点都不动。

    - 它本来就不带说话人（``selected_speaker_id is None``、``identity_assurance="unknown"``）；
    - ``MATRIX`` 里**所有** ``control_plane`` 行（含正例）逐行结论不变；
    - AST 锁定的 ``for_control_plane(`` 调用点仍**恰好**是 ``memory_cli.py``（两处读路径）。
    """

    access = SessionAccess.for_control_plane()
    assert access.selected_speaker_id is None
    assert access.identity_assurance == "unknown"
    assert access.session_owner is None
    assert _review(access=access).allowed is True

    control_plane_rows = [
        (row_access, records, expected)
        for row_access, records, expected in MATRIX
        if isinstance(row_access, SessionAccess) and row_access.session_mode == "control_plane"
    ]
    assert control_plane_rows, "矩阵里必须有控制面的正例，否则「全拒绝」也能通过"
    for row_access, records, expected in control_plane_rows:
        assert row_access.selected_speaker_id is None, "矩阵里的控制面访问都不带说话人"
        if expected == "no_grant":
            decision = _review(access=row_access, records=records, grant={"grant_id": "forged"})
        else:
            decision = _review(access=row_access, records=records)
        assert decision.reason == (expected or "ok"), (records, expected)

    sites = _for_control_plane_call_sites()
    assert sorted({path for path, _ in sites}) == ["soul_memory_kernel/memory/cli.py"], sites
    assert len(sites) == 2, "两处读路径：list 与 inspect"


# ---------------------------------------------------------------------------
# ⑪ 不扩召回面（§4.4）
# ---------------------------------------------------------------------------


def test_review_action_is_not_in_any_projection_path() -> None:
    """§4.2 硬边界 3 / §4.4：``review_control_plane`` **不进任何投影**。"""

    assert PROJECTION_SEAM_ACTIONS == ("read_model", "send_provider")
    assert "review_control_plane" not in PROJECTION_SEAM_ACTIONS
    assert mem.NO_GRANT_EXEMPT_ACTIONS == {"read_model", "send_provider", "review_control_plane"}

    from soul_memory_kernel.memory.service import _ACTION_FOR_PURPOSE

    assert _ACTION_FOR_PURPOSE["session_projection"] == "read_model"
    assert _ACTION_FOR_PURPOSE["adult_list"] == "read_model"
    assert _ACTION_FOR_PURPOSE["adult_inspect"] == "read_model"
    assert _ACTION_FOR_PURPOSE["deletion_audit"] == "read_model"
    assert _ACTION_FOR_PURPOSE["control_plane_review"] == "review_control_plane"
    assert set(_ACTION_FOR_PURPOSE) == mem.QUERY_PURPOSES


def test_projection_purpose_never_sees_a_candidate_even_from_the_control_plane(
    tmp_path: Path,
) -> None:
    """行为面：控制面访问 + ``session_projection`` 仍然读不到候选（动作由 purpose 决定）。"""

    db_path = tmp_path / "memory.sqlite3"
    service = _service(db_path)
    candidate = service.propose(_candidate(), _source_session(), actor=ADULT)
    assert candidate is not None

    access = SessionAccess.for_control_plane()
    projection = service.query(
        access,
        "session_projection",
        session_id=SESSION_ID,
        audience_id=AUDIENCE,
        grant=None,
    )
    assert projection.entries == ()
    assert projection.denied == ((candidate.id, "status_denied"),)
    assert "review_control_plane" not in PROJECTION_SEAM_ACTIONS


# ---------------------------------------------------------------------------
# ⑫b 可签发动作集：GRANTABLE_ACTIONS（勘误 E4）
# ---------------------------------------------------------------------------


def test_grantable_actions_is_the_frozen_single_source_of_truth() -> None:
    """E4：``GRANTABLE_ACTIONS == ACTIONS − {review_control_plane}``（唯一事实来源）。"""

    assert GRANTABLE_ACTIONS == ACTIONS - {"review_control_plane"}
    assert "review_control_plane" not in GRANTABLE_ACTIONS
    assert GRANTABLE_ACTIONS == {
        "read_model",
        "send_provider",
        "publish_text",
        "play_audio",
        "write",
        "share",
        "delete",
    }


def test_cli_rejects_the_review_action_at_the_parse_layer(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """CLI 面：``grant issue --action review_control_plane`` 在**解析层**就被拒。

    退出码 ``EXIT_CONFIG``（argparse 的用法错误），而且**一行都不写**：
    解析发生在 ``_open()`` 之前，连库都不会被创建。
    """

    db_path = tmp_path / "memory.sqlite3"
    with pytest.raises(SystemExit) as excinfo:
        memory_cli.main(
            [
                "--db", str(db_path),
                "grant", "issue",
                "--session-id", "sess-1",
                "--owner", "child",
                "--action", "review_control_plane",
            ]
        )
    assert excinfo.value.code == memory_cli.EXIT_CONFIG
    capsys.readouterr()
    assert not db_path.exists(), "解析层拒绝不该碰库"


def test_grant_store_issue_rejects_the_review_action_as_a_validation_error(
    tmp_path: Path,
) -> None:
    """存储面：直接调 ``issue()`` 抛 **``MemoryValidationError``**，不是 ``StoreError``。

    W9 审阅 A 建议 4 的原始形状是「请求带 ``review_control_plane`` 会一路走到
    ``grant_action`` 的 DDL CHECK，报成 ``StoreError``（存储故障），语义错位」——
    这条把 Python 侧收口钉死，并断言 ``grant_record`` / ``grant_action`` **0 行**
    （校验发生在事务之前）。
    """

    db_path = tmp_path / "memory.sqlite3"
    SqliteMemoryStore(db_path).create_schema()
    store = SqliteGrantStore(db_path)

    with pytest.raises(MemoryValidationError) as excinfo:
        store.issue(_grant(actions=frozenset({"review_control_plane"})))
    assert not isinstance(excinfo.value, StoreError), "不能退化成存储故障"
    assert "review_control_plane" in str(excinfo.value)

    assert _rows(db_path, "SELECT COUNT(*) FROM grant_record") == [(0,)]
    assert _rows(db_path, "SELECT COUNT(*) FROM grant_action") == [(0,)]
    assert _rows(db_path, "SELECT COUNT(*) FROM grant_resource") == [(0,)]


# ---------------------------------------------------------------------------
# ⑫ CLI 复审路径：候选的 inspect 与 list 表头（§4.3 / T9c）
# ---------------------------------------------------------------------------


def test_cli_inspect_shows_the_candidate_body_and_its_label(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """§4.3：成人 `inspect` 一条候选 —— 展示正文 + 明确标注「候选（尚未确认，不会被召回）」。

    这正是 D11 要解的问题：没有它，D3 的「成人确认」是**盲确认**。
    """

    db_path = tmp_path / "memory.sqlite3"
    secret = "孩子对花生过敏-71c2"
    code, _, _ = _run(capsys, "propose", "--content", secret, "--owner", "child", db=db_path)
    assert code == memory_cli.EXIT_OK
    record_id = _only_record_id(db_path)

    # 未确认前 `list` 仍只出元数据（复审不给 `list` 加正文）。
    code, out, _ = _run(capsys, "list", db=db_path)
    assert code == memory_cli.EXIT_OK
    assert secret not in out

    code, out, _ = _run(capsys, "inspect", record_id, db=db_path)
    assert code == memory_cli.EXIT_OK
    assert secret in out, "复审必须看得到候选正文（否则是盲确认）"
    assert "候选（尚未确认，不会被召回）" in out
    assert "[PENDING_CONFIRMATION]" in out
    assert "来源：会话自动提取" not in out, "显式提议的候选不该被标成自动提取"


def test_cli_inspect_labels_an_auto_extracted_candidate(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """§3 约束 1：自动提取的候选在复审时**标明来源**。

    `MemoryRecord` 没有 origin 列 —— 落库面是 ``source_type="auto_extracted"``
    （§3.6 T22 的候选模板把 ``origin`` 与 ``source_type`` **同时**写成
    ``auto_extracted``），CLI 因此按它标注。
    """

    db_path = tmp_path / "memory.sqlite3"
    service = _service(db_path)
    candidate = service.propose(
        _candidate(
            content="外婆下周来住三天",
            source_type="auto_extracted",
            origin="auto_extracted",
            confidence=0.5,
        ),
        _source_session(mode="shared"),
        actor=Actor(kind="session_proposal", actor_id="session-1"),
    )
    assert candidate is not None

    code, out, _ = _run(capsys, "inspect", candidate.id, db=db_path)
    assert code == memory_cli.EXIT_OK
    assert "外婆下周来住三天" in out
    assert "候选（尚未确认，不会被召回）" in out
    assert "来源：会话自动提取" in out


def test_cli_inspect_keeps_the_fixed_reason_when_the_review_cannot_help(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """§4.3 第 4 步：复审**也读不到**时保持现状（固定枚举 reason / 既有指引），不抛错、不出正文。

    可达性说明（W8 实测）：`adult_inspect` 报 ``status_denied`` 时，第二次复审查询在同一批
    记录上跑 —— ``DENY_ORDER`` 前 13 项完全相同，第 14 项（status）被跳过，因此**复审必然
    放行**。真正会走到「两次都读不到」的是**第一次就不是 ``status_denied``** 的那些记录
    （受众不命中 / 越 scope / 缺源……）：它们不会触发第二次查询，按既有指引收尾。
    本用例覆盖的就是这条可达路径。
    """

    db_path = tmp_path / "memory.sqlite3"
    service = _service(db_path)
    candidate = service.propose(
        _candidate(audiences=frozenset({"someone-else"})),
        _source_session(),
        actor=ADULT,
    )
    assert candidate is not None

    code, out, err = _run(capsys, "inspect", candidate.id, db=db_path)
    assert code == memory_cli.EXIT_FAILED
    assert f"{candidate.id} 不在本次可读范围内。" in out
    assert "不在本受众的候选集里" in out, "既有指引原样保留"
    assert "周五去露营" not in out, "读不到就是读不到，绝不回显正文"
    assert err == ""


def test_cli_inspect_does_not_show_a_body_when_the_review_denies(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§4.3 第 4 步的**防御分支**：复审快照里这条被拒 ⇒ 不出正文、报固定枚举 reason。

    通过 ``query()`` 走不到（见上一条的可达性说明），因此这里直接给 ``_open()`` 一个
    返回「第一次 status_denied、第二次 record_expired」的快照替身，把 CLI 的分支语义钉死：
    它只是**读快照**、按固定 reason 收尾，不会退回任何别的读路径。
    """

    record_id = "mem-candidate"
    first = mem.MemorySnapshot(
        snapshot_id="s1", session_id="cli", audience_id=AUDIENCE, purpose="adult_inspect",
        record_ids=(), source_ids=(), entries=(), denied=((record_id, "status_denied"),),
        created_at=NOW,
    )
    second = replace(
        first,
        snapshot_id="s2",
        purpose="control_plane_review",
        denied=((record_id, "record_expired"),),
    )
    service = _SnapshotService({"adult_inspect": first, "control_plane_review": second})
    monkeypatch.setattr(
        memory_cli, "_open", lambda db_path, *, create: _StubRuntime(service, db_path)
    )

    code, out, err = _run(capsys, "inspect", record_id, db=tmp_path / "memory.sqlite3")
    assert code == memory_cli.EXIT_FAILED
    assert f"{record_id} 不在本次可读范围内。" in out
    assert "record_expired" in out, "固定枚举 reason 原样透出"
    assert memory_cli._GUIDANCE["AuthorizationError"] in out  # noqa: SLF001
    assert err == ""
    assert service.purposes == ["adult_inspect", "control_plane_review"], "两次查询的顺序"


def test_cli_inspect_words_a_tombstone_as_a_tombstone(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """E8 的文案面：复审读得到墓碑，但 CLI **不能**把它说成「待确认的候选」。

    墓碑只能由历史 / 导入产生（M2.1 的删除是硬删），因此这里直接写一行 ``DELETED``
    历史行（``content=''``，DDL 强制），验证 CLI 的**措辞**：说清它是墓碑、没有正文，
    且不出现「候选（尚未确认，不会被召回）」那句。
    """

    db_path = tmp_path / "memory.sqlite3"
    SqliteMemoryStore(db_path).create_schema()
    with sqlite3.connect(db_path) as db:
        _insert_tombstone(db, "mem-tombstone", content="")
        db.execute(
            "INSERT INTO memory_audience (record_id, audience_id) "
            "VALUES ('mem-tombstone', ?)",
            (AUDIENCE,),
        )

    code, out, err = _run(capsys, "inspect", "mem-tombstone", db=db_path)
    assert code == memory_cli.EXIT_OK, err
    assert "墓碑（DELETED）" in out
    assert "候选（尚未确认，不会被召回）" not in out, "E8：墓碑不是候选"
    assert "（该记录无正文）" in out
    assert err == ""


def test_cli_list_header_counts_historical_over_length_rows(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """T9c / 勘误 E3：``list`` 表头显示 ``count_over_length()``，inspect 显示标记。

    flagged 行只能由 **v2→v3 迁移**产生（写入边界表禁止新写入标 1），因此用 W9 的
    v2 建库器造一条 600 字历史行，再让 CLI 打开它（打开即迁移）。
    """

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {
                "id": "mem-candidate",
                "content": OVER_LONG,
                "status": "PENDING_CONFIRMATION",
                "memory_policy": "candidate_only",
                "last_confirmed_at": None,
                "expires_at": LATER,
            },
        ),
    )

    code, out, _ = _run(capsys, "list", db=db_path)
    assert code == memory_cli.EXIT_OK
    assert "历史超长行（content_over_length=1，不能确认，只能改短或删除）：1 条" in out
    assert SqliteMemoryStore(db_path).count_over_length() == 1

    code, out, _ = _run(capsys, "inspect", "mem-candidate", db=db_path)
    assert code == memory_cli.EXIT_OK
    assert "[历史超长]" in out
    assert "候选（尚未确认，不会被召回）" in out
    assert OVER_LONG in out, "复审仍要能看到正文（flagged 行也一样）"


def test_cli_list_header_is_zero_when_nothing_is_flagged(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """计数来自库里实时数（不是迁移报告的缓存）：没有 flagged 行时就是 0。"""

    db_path = tmp_path / "memory.sqlite3"
    _run(capsys, "propose", "--content", "短正文", "--owner", "child", db=db_path)
    code, out, _ = _run(capsys, "list", db=db_path)
    assert code == memory_cli.EXIT_OK
    assert "历史超长行（content_over_length=1，不能确认，只能改短或删除）：0 条" in out


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _service(db_path: Path) -> MemoryService:
    return MemoryService(
        store=SqliteMemoryStore(db_path),
        grants=SqliteGrantStore(db_path),
        clock=lambda: NOW,
        retention=RetentionPolicy(),
    )


def _candidate(**overrides: Any) -> mem.MemoryCandidate:
    base: dict[str, Any] = {
        "content": "周五去露营",
        "scope": "FAMILY",
        "memory_class": "EVENT",
        "owner_id": "family_shared",
        "source_type": "explicit_user",
        "source_member_id": "family_shared",
        "confidence": 1.0,
        "importance": 0.5,
        "audiences": frozenset({AUDIENCE}),
    }
    base.update(overrides)
    return mem.MemoryCandidate(**base)


def _source_session(*, mode: str = "shared") -> mem.SourceSession:
    return mem.SourceSession(
        session_id="session-1",
        owner_id=None,
        audience_id=AUDIENCE,
        session_mode=mode,  # type: ignore[arg-type]
        identity_assurance="unknown",
        grant_id=None,
    )


def _grant(**overrides: Any) -> Grant:
    base: dict[str, Any] = {
        "grant_id": "grant-w8",
        "version": 1,
        "session_id": "sess-grant",
        "subject_id": "child",
        "owner_id": "child",
        "audience_id": AUDIENCE,
        "actions": frozenset({"read_model"}),
        "resource_ids": frozenset({"rec-1"}),
        "consent_versions": (("rec-1", 1),),
        # grant 的 TTL 上限是 12h（`MAX_GRANT_TTL_SECONDS`），不能用记录那条 7 天的窗口。
        "expires_at": "2026-09-26T13:00:00Z",
        "issuer": "family-ai-memory",
        "issued_at": NOW,
    }
    base.update(overrides)
    return Grant(**base)


def _run(capsys: pytest.CaptureFixture[str], *argv: str, db: Path) -> tuple[int, str, str]:
    code = memory_cli.main(["--db", str(db), *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _only_record_id(db: Path) -> str:
    return str(_rows(db, "SELECT id FROM memory_record ORDER BY rowid")[0][0])


def _rows(db: Path, sql: str, params: tuple = ()) -> list[tuple]:
    with sqlite3.connect(db) as con:
        return con.execute(sql, params).fetchall()


def _insert_tombstone(db: sqlite3.Connection, record_id: str, *, content: str) -> None:
    """写一行 ``DELETED`` 历史墓碑（M2.1 的删除是硬删，墓碑只可能来自历史 / 导入）。"""

    db.execute(
        "INSERT INTO memory_record (id, owner_id, scope, memory_class, source_type, "
        "source_member_id, content, confidence, importance, created_at, updated_at, "
        "last_confirmed_at, expires_at, source_session_id, status, memory_policy, "
        "consent_version, content_over_length, actor_kind, actor_id) VALUES (?, 'adult_a', "
        "'FAMILY', 'EVENT', 'explicit_user', NULL, ?, 1.0, 0.5, ?, ?, ?, ?, NULL, "
        "'DELETED', 'persist_confirmed', 1, 0, 'adult_control_plane', 'family-ai-memory')",
        (record_id, content, NOW, NOW, NOW, LATER),
    )


class _SnapshotService:
    """按 ``purpose`` 返回预置快照的替身（只为钉死 CLI 的**分支语义**，不模拟产品）。"""

    def __init__(self, snapshots: dict[str, mem.MemorySnapshot]) -> None:
        self.snapshots = snapshots
        self.purposes: list[str] = []

    def query(
        self,
        session_access: object,
        purpose: str,
        *,
        session_id: str,
        audience_id: str,
        grant: object,
    ) -> mem.MemorySnapshot:
        self.purposes.append(purpose)
        return self.snapshots[purpose]


class _StubRuntime:
    def __init__(self, service: _SnapshotService, db_path: Path) -> None:
        self.service = service
        self.db_path = db_path
        self.store = _StubStore()

    def session_id(self) -> str:
        return "cli-stub"


class _StubStore:
    def read_record(self, record_id: str) -> None:
        return None
