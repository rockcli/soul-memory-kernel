"""W8 契约测试：D13 的归属纠正（``reassign_owner``）与 ``confirm --reassign-owner``。

契约依据：``docs/M2-2-CONTRACT.md`` §2.4 **T26'**（``reassign_owner`` 的形状：只对候选 /
只由成人 / ``consent_version + 1`` / 不改别的 / CLI 两步顺序）、§6 T9c 的写入边界表
（flagged 候选**只能删或等 TTL**，W9 审阅 B 建议 1 要求 CLI 给**可执行**提示）与 §7.5
**第 6 项**（M2.3 收口：CLI 的两步必须合并成一个事务）。

覆盖四块：

1. **服务方法**：候选可改、非候选一律 ``IllegalTransition``、actor 门、保留 id / 空 owner、
   以及「只改归属，不碰别的字段」；
2. **CLI 一步**（M2.3 §7.5 第 6 项）：``confirm --reassign-owner`` 的改归属与确认共享是
   **同一次写入**（一个事务）—— 要么都成、要么都不成；产物与两步写法逐字段相同
   （``consent_version`` 仍是 ``1 → 3``）；
3. **flagged 候选**：确认被拒时的文案必须可执行（删除 / 等过期），并且**一行都不改**
   （连归属也不改 —— 否则就是半个操作）；
4. **注入失败零残留**：让「确认那一步的写入」失败 ⇒ 库里 ``owner`` / ``status`` /
   ``consent_version`` 全部保持原值（不再有「归属已改、确认未完成」的中间态）。

全程离线：只操作 ``tmp_path`` 下的临时库与合成记录。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

import soul_memory_kernel.memory as mem
from soul_memory_kernel.memory import cli as memory_cli
from soul_memory_kernel.memory.grants import SqliteGrantStore
from soul_memory_kernel.memory.model import Actor
from soul_memory_kernel.memory.service import (
    IllegalTransition,
    MemoryService,
    MemoryValidationError,
    RetentionPolicy,
)
from soul_memory_kernel.memory.store import SqliteMemoryStore
from tests.test_memory_migration import OVER_LONG, _build_v2  # noqa: PLC2701 —— 复用 W9 的 v2 建库器

NOW = "2026-09-26T12:00:00Z"
LATER = "2026-10-03T12:00:00Z"
AUDIENCE = "family_all"
ADULT = Actor(kind="adult_control_plane", actor_id="family-ai-memory")


@pytest.fixture(autouse=True)
def _frozen_cli_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI 的时钟钉在 ``NOW``：候选期是「天」为单位，跑在真实墙钟上迟早会过期。"""

    monkeypatch.setattr(memory_cli, "_system_clock", lambda: NOW)


# ---------------------------------------------------------------------------
# 1. 服务方法：只对候选、只由成人、consent_version + 1、保留 id 拒绝
# ---------------------------------------------------------------------------


def _service(db_path: Path) -> MemoryService:
    return MemoryService(
        store=SqliteMemoryStore(db_path),
        grants=SqliteGrantStore(db_path, clock=lambda: NOW),
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


def _source_session() -> mem.SourceSession:
    return mem.SourceSession(
        session_id="session-1",
        owner_id=None,
        audience_id=AUDIENCE,
        session_mode="shared",
        identity_assurance="unknown",
        grant_id=None,
    )


def _propose(service: MemoryService, **overrides: Any) -> mem.MemoryRecord:
    record = service.propose(
        _candidate(**overrides),
        _source_session(),
        actor=Actor(kind="session_proposal", actor_id="session-1"),
    )
    assert record is not None
    return record


def test_reassign_owner_moves_a_candidate_and_bumps_the_consent_version(
    tmp_path: Path,
) -> None:
    """T26' 的正例：候选的归属从保留 id 定到具体成员，且**只**动归属相关的字段。"""

    service = _service(tmp_path / "memory.sqlite3")
    candidate = _propose(service)
    assert candidate.owner_id == "family_shared"
    assert candidate.consent_version == 1

    updated = service.reassign_owner(candidate.id, "child", actor=ADULT)

    assert updated.owner_id == "child"
    assert updated.consent_version == candidate.consent_version + 1, "归属变更是一次写入"
    assert updated.updated_at == NOW
    assert updated.actor_kind == "adult_control_plane"
    assert updated.actor_id == ADULT.actor_id
    # 「不改别的」：内容 / 重要度 / 受众 / scope / 来源 / 类型 / 状态 / 候选期都不动。
    for field in (
        "content",
        "importance",
        "audiences",
        "scope",
        "source_type",
        "source_member_id",
        "memory_class",
        "status",
        "memory_policy",
        "expires_at",
        "last_confirmed_at",
        "created_at",
    ):
        assert getattr(updated, field) == getattr(candidate, field), field

    # 落库面与返回值一致（不是只改了内存对象）。
    stored = SqliteMemoryStore(tmp_path / "memory.sqlite3").read_record(candidate.id)
    assert stored is not None
    assert (stored.owner_id, stored.consent_version, stored.actor_id) == (
        "child",
        candidate.consent_version + 1,
        ADULT.actor_id,
    )


@pytest.mark.parametrize("status", ["ACTIVE", "DECAYED"])
def test_reassign_owner_refuses_anything_that_is_not_a_candidate(
    tmp_path: Path, status: str
) -> None:
    """T26'：归属**定型后不可改** —— 非候选一律 ``IllegalTransition``，且不改任何行。

    两个状态都用**产品自己的路径**造出来：``ACTIVE`` 走 ``confirm_shared``，
    ``DECAYED`` 再走 ``ttl_expiry`` 的那条 TTL 迁移（``("ACTIVE","DECAYED")``）。
    """

    db_path = tmp_path / "memory.sqlite3"
    service = _service(db_path)
    candidate = _propose(service)
    confirmed = service.confirm_shared(candidate.id, frozenset({AUDIENCE}), ADULT)
    if status == "DECAYED":
        _decay(service, confirmed)

    before = _row(db_path, candidate.id)
    with pytest.raises(IllegalTransition):
        service.reassign_owner(candidate.id, "child", actor=ADULT)
    assert _row(db_path, candidate.id) == before, "拒绝时不得留下任何改动"


@pytest.mark.parametrize("kind", ["session_proposal", "ttl_expiry"])
def test_reassign_owner_is_adult_only(tmp_path: Path, kind: str) -> None:
    """T26'：``M2_1_WRITE_GATE["reassign_owner"] = {"adult_control_plane"}``（只由成人）。"""

    db_path = tmp_path / "memory.sqlite3"
    service = _service(db_path)
    candidate = _propose(service)
    before = _row(db_path, candidate.id)

    with pytest.raises(MemoryValidationError):
        service.reassign_owner(
            candidate.id, "child", actor=Actor(kind=kind, actor_id="someone")  # type: ignore[arg-type]
        )
    assert _row(db_path, candidate.id) == before


@pytest.mark.parametrize(
    "owner_id",
    ["family_shared", "", "   "],
    ids=["reserved-owner-id", "empty", "blank"],
)
def test_reassign_owner_refuses_reserved_and_empty_owner_ids(
    tmp_path: Path, owner_id: str
) -> None:
    """T26'：目标必须是非空字符串且**不是保留 id**（它的用途是把归属**移出**保留 id）。"""

    db_path = tmp_path / "memory.sqlite3"
    service = _service(db_path)
    candidate = _propose(service)
    before = _row(db_path, candidate.id)

    with pytest.raises(MemoryValidationError):
        service.reassign_owner(candidate.id, owner_id, actor=ADULT)
    assert _row(db_path, candidate.id) == before


def test_cli_confirm_with_reassign_owner_writes_twice_in_order(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """CLI 两步：``--reassign-owner`` **先**写归属、**再**确认共享（``consent_version`` 两次递增）。

    M2.3（§7.5 第 6 项）把这两次递增合并进**同一次写入**，因此本用例断言的是**效果**
    （``consent_version`` 由 1 到 3、归属定到 ``child``、状态 ``ACTIVE``）—— 它对两种写法
    都成立；「只写一次」的结构性断言在同文件的
    ``test_cli_confirm_reassign_owner_writes_once_in_one_transaction``。
    """

    db_path = tmp_path / "memory.sqlite3"
    code, _, _ = _run(capsys, "propose", "--content", "周五去露营", "--owner", "family_shared", db=db_path)
    assert code == memory_cli.EXIT_OK
    record_id = _only_record_id(db_path)

    code, out, err = _run(
        capsys, "confirm", record_id, "--audience", AUDIENCE, "--reassign-owner", "child", db=db_path
    )
    assert code == memory_cli.EXIT_OK, err
    assert "已确认共享：" in out
    assert "owner=child" in out, "确认后的归属必须是定到的那个人"

    owner_id, status, consent_version = _row(db_path, record_id)
    assert (owner_id, status) == ("child", "ACTIVE")
    assert consent_version == 3, "候选建库 1 → 改归属 2 → 确认 3（两次写）"


def test_cli_confirm_without_reassign_owner_still_works(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """不带 ``--reassign-owner`` 时**一步都不多写**（保留归属原样确认）。"""

    db_path = tmp_path / "memory.sqlite3"
    _run(capsys, "propose", "--content", "周五去露营", "--owner", "family_shared", db=db_path)
    record_id = _only_record_id(db_path)

    code, _, _ = _run(capsys, "confirm", record_id, "--audience", AUDIENCE, db=db_path)
    assert code == memory_cli.EXIT_OK
    assert _row(db_path, record_id) == ("family_shared", "ACTIVE", 2), "只写一次"


def test_cli_confirm_does_not_confirm_when_the_reassign_step_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """T26'：「前一步失败就不执行后一步」—— 归属改不动时，确认**不发生**（不做半个确认）。"""

    db_path = tmp_path / "memory.sqlite3"
    _run(capsys, "propose", "--content", "周五去露营", "--owner", "family_shared", db=db_path)
    record_id = _only_record_id(db_path)

    # 保留 id 是非法目标 ⇒ reassign_owner 抛 MemoryValidationError。
    code, out, err = _run(
        capsys,
        "confirm", record_id, "--audience", AUDIENCE, "--reassign-owner", "family_shared",
        db=db_path,
    )
    assert code == memory_cli.EXIT_FAILED
    assert "已确认共享" not in out
    assert "MemoryValidationError" in err
    assert _row(db_path, record_id) == ("family_shared", "PENDING_CONFIRMATION", 1), "一行都没改"


def test_cli_confirm_reassign_owner_refuses_a_record_that_is_already_active(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """归属定型后不可改：对一条 ``ACTIVE`` 记录再改归属 ⇒ ``IllegalTransition``，不重复确认。"""

    db_path = tmp_path / "memory.sqlite3"
    _run(capsys, "propose", "--content", "周五去露营", "--owner", "family_shared", db=db_path)
    record_id = _only_record_id(db_path)
    assert _run(capsys, "confirm", record_id, "--audience", AUDIENCE, db=db_path)[0] == 0
    confirmed = _row(db_path, record_id)

    code, out, err = _run(
        capsys, "confirm", record_id, "--audience", AUDIENCE, "--reassign-owner", "child", db=db_path
    )
    assert code == memory_cli.EXIT_FAILED
    assert "IllegalTransition" in err
    assert "已确认共享" not in out
    assert _row(db_path, record_id) == confirmed


def test_cli_confirm_validates_the_audience_before_the_first_write(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """「不做半个确认」的另一面：第二步的**输入**也要在第一步写入之前校验掉。

    ``--audience ""`` 会在 ``confirm_shared`` 里才报错，那时归属已经改完 —— 因此 CLI
    把它当**用法错误**在写之前退掉（退出码 2），一行都不写。
    """

    db_path = tmp_path / "memory.sqlite3"
    _run(capsys, "propose", "--content", "周五去露营", "--owner", "family_shared", db=db_path)
    record_id = _only_record_id(db_path)

    code, out, err = _run(
        capsys, "confirm", record_id, "--audience", "", "--reassign-owner", "child", db=db_path
    )
    assert code == memory_cli.EXIT_CONFIG
    assert "audience" in err
    assert "已确认共享" not in out
    assert _row(db_path, record_id) == ("family_shared", "PENDING_CONFIRMATION", 1), "一行都没改"


def test_cli_parser_has_no_actor_input_for_the_reassign_path() -> None:
    """约束 1 的延续：归属变更只用**固定的**控制面 actor，解析器里没有 actor 输入。"""

    import argparse

    sub = memory_cli.build_parser()._subparsers._group_actions[0].choices["confirm"]  # noqa: SLF001
    option_strings = [
        option for action in sub._actions for option in action.option_strings  # noqa: SLF001
    ]
    assert "--reassign-owner" in option_strings
    assert not [option for option in option_strings if "actor" in option.lower()]
    assert not isinstance(sub._actions[0], argparse._SubParsersAction)  # noqa: SLF001


# ---------------------------------------------------------------------------
# 1b. M2.3 §7.5 第 6 项：改归属 + 确认共享 = **同一次写入**（一个事务）
# ---------------------------------------------------------------------------


def test_confirm_shared_with_owner_reassign_matches_the_two_step_result(tmp_path: Path) -> None:
    """「行为不变」的最强形式：合并写法的产物与两步写法**逐字段**相同。

    两个库各自从同样的候选出发：一边走 ``reassign_owner`` + ``confirm_shared``（老的两次写），
    一边走 ``confirm_shared_with_owner_reassign``（一次写）。只允许 ``id`` 不同（``propose``
    生成的 uuid），其余列必须一字不差 —— 包括 ``consent_version``（两次递增的量）。
    """

    from dataclasses import replace

    two_step_path = tmp_path / "two-step.sqlite3"
    two_step = _service(two_step_path)
    two_step_candidate = _propose(two_step)
    moved = two_step.reassign_owner(two_step_candidate.id, "child", actor=ADULT)
    two_step_result = two_step.confirm_shared(moved.id, frozenset({AUDIENCE}), ADULT)

    merged_path = tmp_path / "merged.sqlite3"
    merged = _service(merged_path)
    merged_candidate = _propose(merged)
    merged_result = merged.confirm_shared_with_owner_reassign(
        merged_candidate.id, frozenset({AUDIENCE}), "child", actor=ADULT
    )

    # 返回值面
    assert replace(merged_result, id=two_step_result.id) == two_step_result
    # 落库面（不是只改了内存对象）
    stored_two_step = SqliteMemoryStore(two_step_path).read_record(two_step_candidate.id)
    stored_merged = SqliteMemoryStore(merged_path).read_record(merged_candidate.id)
    assert stored_two_step is not None and stored_merged is not None
    assert stored_merged.id != stored_two_step.id, "两个库各自 propose，id 必然不同"
    assert replace(stored_merged, id=stored_two_step.id) == stored_two_step
    assert stored_merged.consent_version == 3, "候选建库 1 → 改归属 +1 → 确认 +1"


def test_cli_confirm_reassign_owner_writes_once_in_one_transaction(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI 面：``confirm --reassign-owner`` 只做**一次** ``write_record``（一个事务）。

    结构性断言（不靠读产物）：写次数为 1 意味着「改完归属、确认没写成」这件事在结构上
    不可能发生 —— 两次写才有那个中间态。
    """

    db_path = tmp_path / "memory.sqlite3"
    _run(capsys, "propose", "--content", "周五去露营", "--owner", "family_shared", db=db_path)
    record_id = _only_record_id(db_path)

    written: list[str] = []
    real_write_record = SqliteMemoryStore.write_record

    def _spy(self: SqliteMemoryStore, record: mem.MemoryRecord, *, actor: mem.Actor) -> None:
        written.append(record.status)
        real_write_record(self, record, actor=actor)

    monkeypatch.setattr(SqliteMemoryStore, "write_record", _spy)

    code, out, err = _run(
        capsys, "confirm", record_id, "--audience", AUDIENCE, "--reassign-owner", "child", db=db_path
    )
    assert code == memory_cli.EXIT_OK, err
    assert "已确认共享：" in out and "owner=child" in out
    assert written == ["ACTIVE"], "改归属与确认共享必须在同一次写入里完成（没有中间态写）"
    assert _row(db_path, record_id) == ("child", "ACTIVE", 3)


def test_cli_confirm_reassign_owner_leaves_zero_residue_when_the_confirm_write_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§7.5 第 6 项的验收①：注入「确认那一步写失败」⇒ 库里**两步都没生效**（零残留）。

    注入方式与审阅 B 实测的故障同构：让**承载确认结果**的那次写入抛错
    （``status="ACTIVE"`` 的记录写不进去），别的写照常。

    旧的两步写法下，第一步的归属变更已经落库，库里会留下
    ``owner=child / status=PENDING_CONFIRMATION / consent_version+1`` —— 正是
    「归属已改、确认未完成」的半个操作。合并成一次写入后，这次失败让**整条记录**
    保持原值（本用例对旧实现必然红灯，因此它钉住的是修复本身）。
    """

    db_path = tmp_path / "memory.sqlite3"
    _run(capsys, "propose", "--content", "周五去露营", "--owner", "family_shared", db=db_path)
    record_id = _only_record_id(db_path)
    before = _row(db_path, record_id)
    assert before == ("family_shared", "PENDING_CONFIRMATION", 1)

    real_write_record = SqliteMemoryStore.write_record

    def _fail_on_confirm(self: SqliteMemoryStore, record: mem.MemoryRecord, *, actor: mem.Actor) -> None:
        if record.status == "ACTIVE":
            raise sqlite3.OperationalError("injected: disk I/O error")
        real_write_record(self, record, actor=actor)

    monkeypatch.setattr(SqliteMemoryStore, "write_record", _fail_on_confirm)

    code, out, err = _run(
        capsys, "confirm", record_id, "--audience", AUDIENCE, "--reassign-owner", "child", db=db_path
    )

    assert code == memory_cli.EXIT_FAILED
    assert "已确认共享" not in out
    assert "StoreError" in err, "存储故障必须是 StoreError，不能伪装成别的失败"
    assert "同一次写入" in err, "提示必须说清没有中间态（§7.5 第 6 项）"
    assert _row(db_path, record_id) == before, (
        "注入失败后零残留：owner / status / consent_version 全部保持原值"
    )
    assert _row(db_path, record_id)[0] != "child", "绝不能留下「归属已改、确认未完成」"


def test_confirm_shared_with_owner_reassign_rejects_without_writing_anything(
    tmp_path: Path,
) -> None:
    """四类前置拒绝（非候选 / flagged / 保留 id / 空受众）语义不变，且**一行未写**。

    服务层直接调用（CLI 还会在更前面拦掉 ``--audience ""`` 与 flagged 行）：
    错误类型与两步写法逐个对齐 —— ``IllegalTransition`` / ``MemoryValidationError``。
    """

    # 1. 非候选：归属定型后不可改（T26'）
    non_candidate = tmp_path / "non-candidate.sqlite3"
    service = _service(non_candidate)
    confirmed = service.confirm_shared(_propose(service).id, frozenset({AUDIENCE}), ADULT)
    before = _row(non_candidate, confirmed.id)
    with pytest.raises(IllegalTransition):
        service.confirm_shared_with_owner_reassign(
            confirmed.id, frozenset({AUDIENCE}), "child", actor=ADULT
        )
    assert _row(non_candidate, confirmed.id) == before

    # 2. flagged 候选：T9c 的写入边界 —— 连归属都不改
    flagged = tmp_path / "flagged.sqlite3"
    _build_v2(
        flagged,
        (
            {
                "id": "mem-flagged",
                "content": OVER_LONG,
                "status": "PENDING_CONFIRMATION",
                "memory_policy": "candidate_only",
                "last_confirmed_at": None,
                "expires_at": LATER,
            },
        ),
    )
    # v2 库先迁移到 v3（`create_schema()` 走 12 步迁移法；CLI 的 `_open()` 也是这样打开的）。
    SqliteMemoryStore(flagged).create_schema()
    flagged_service = _service(flagged)
    before_flagged = _row(flagged, "mem-flagged")
    with pytest.raises(MemoryValidationError):
        flagged_service.confirm_shared_with_owner_reassign(
            "mem-flagged", frozenset({AUDIENCE}), "child", actor=ADULT
        )
    assert _row(flagged, "mem-flagged") == before_flagged

    # 3. 保留 id / 空受众：校验先于读写
    plain = tmp_path / "plain.sqlite3"
    plain_service = _service(plain)
    candidate = _propose(plain_service)
    before_plain = _row(plain, candidate.id)
    for owner_id, audience in (
        ("family_shared", frozenset({AUDIENCE})),  # 保留 id
        ("", frozenset({AUDIENCE})),  # 空 owner
        ("child", frozenset()),  # 空受众
    ):
        with pytest.raises(MemoryValidationError):
            plain_service.confirm_shared_with_owner_reassign(
                candidate.id, audience, owner_id, actor=ADULT
            )
        assert _row(plain, candidate.id) == before_plain, (owner_id, audience)

    # 4. actor 门：只有成人能合并做这两件事（两道门都是 adult_control_plane）
    for kind in ("session_proposal", "ttl_expiry"):
        with pytest.raises(MemoryValidationError):
            plain_service.confirm_shared_with_owner_reassign(
                candidate.id,
                frozenset({AUDIENCE}),
                "child",
                actor=Actor(kind=kind, actor_id="someone"),  # type: ignore[arg-type]
            )
        assert _row(plain, candidate.id) == before_plain, kind


# ---------------------------------------------------------------------------
# 2. flagged 候选：确认被拒时的文案可执行（W9 审阅 B 建议 1 / T9c）
# ---------------------------------------------------------------------------


def test_cli_confirm_explains_a_flagged_candidate_in_actionable_terms(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """flagged 候选**不能**确认：CLI 必须说清「怎么办」，不是泛泛的「操作失败」。

    flagged 行只能由 v2→v3 迁移产生（写入边界表禁止新写入标 1），候选又走不了
    ``correct``（``(PENDING, PENDING)`` 不在 ``LEGAL_TRANSITIONS`` 里）⇒ 出路只有
    **删除**或**等候选期结束**，文案必须给出这两条。
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

    code, out, err = _run(capsys, "confirm", "mem-candidate", "--audience", AUDIENCE, db=db_path)
    assert code == memory_cli.EXIT_FAILED
    assert "已确认共享" not in out
    assert "历史超长" in err, "说清是哪一类拒绝"
    assert "delete" in err and "过期" in err, "必须给可执行的出路"
    assert _row(db_path, "mem-candidate") == ("adult_a", "PENDING_CONFIRMATION", 1), "一行都没改"


def test_cli_confirm_reassign_owner_does_not_half_apply_on_a_flagged_candidate(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """flagged 候选 + ``--reassign-owner``：**连归属都不改**（否则就是半个操作）。"""

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {
                "id": "mem-flagged",
                "content": OVER_LONG,
                "status": "PENDING_CONFIRMATION",
                "memory_policy": "candidate_only",
                "last_confirmed_at": None,
                "expires_at": LATER,
            },
        ),
    )

    code, _, err = _run(
        capsys,
        "confirm", "mem-flagged", "--audience", AUDIENCE, "--reassign-owner", "child",
        db=db_path,
    )
    assert code == memory_cli.EXIT_FAILED
    assert "历史超长" in err
    assert _row(db_path, "mem-flagged") == ("adult_a", "PENDING_CONFIRMATION", 1)


def test_flagged_candidate_can_still_be_deleted(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """出路的另一半：``delete --yes`` 真的能把 flagged 候选删掉（文案不是空头支票）。"""

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {
                "id": "mem-flagged",
                "content": OVER_LONG,
                "status": "PENDING_CONFIRMATION",
                "memory_policy": "candidate_only",
                "last_confirmed_at": None,
                "expires_at": LATER,
            },
        ),
    )

    code, out, err = _run(capsys, "delete", "mem-flagged", "--yes", db=db_path)
    assert code == memory_cli.EXIT_OK, err
    assert "已删除" in out
    assert _rows(db_path, "SELECT id FROM memory_record") == []


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _decay(service: MemoryService, record: mem.MemoryRecord) -> None:
    """把一条 ``ACTIVE`` 记录落成 ``DECAYED``：走 ``ttl_expiry`` 的那条 TTL 迁移。

    ``("ACTIVE","DECAYED")`` 是 :data:`~soul_memory_kernel.memory.model.TTL_TRANSITIONS` 里唯一的
    一条，只有 ``ttl_expiry`` 能做 —— 因此这是**产品自己的路径**，不是构造出来的状态。
    """

    from dataclasses import replace

    service._store.write_record(  # noqa: SLF001 —— 只为构造「非候选」前置状态
        replace(record, status="DECAYED"),
        actor=Actor(kind="ttl_expiry", actor_id="family-ai-memory"),
    )


def _run(capsys: pytest.CaptureFixture[str], *argv: str, db: Path) -> tuple[int, str, str]:
    code = memory_cli.main(["--db", str(db), *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _only_record_id(db: Path) -> str:
    return str(_rows(db, "SELECT id FROM memory_record ORDER BY rowid")[0][0])


def _row(db: Path, record_id: str) -> tuple:
    rows = _rows(db, "SELECT owner_id, status, consent_version FROM memory_record WHERE id = ?", (record_id,))
    assert len(rows) == 1, rows
    return rows[0]


def _rows(db: Path, sql: str, params: tuple = ()) -> list[tuple]:
    with sqlite3.connect(db) as con:
        return con.execute(sql, params).fetchall()
