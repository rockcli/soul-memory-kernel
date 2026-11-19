"""M2 SQLite 存储层测试（W1）：DDL 落库、文件纪律、CRUD、状态迁移、删除与血缘。

契约页 §9 把 ``store.py`` 的 ``SqliteMemoryStore`` 与 ``tests/test_memory_store.py``
一起归 W1。本文件按两组覆盖：

1. **文件与 schema 组** —— 0600 独占创建、symlink 拒绝、``PRAGMA user_version`` /
   ``quick_check`` 校验、并发建表后的幂等、投影路径只读；
2. **CRUD 组** —— 记录往返、受众与血缘行、``do_not_persist`` 与 DDL 六条 CHECK 的
   写入前拒绝、状态机（合法迁移 / 非法迁移 / actor 权限）、到期扫描、候选硬删除、
   删除清单（含无外键的 ``grant_resource``）与 ``deletion_audit``。

**负例与正例成对**：每条拒绝路径都配一条「合法输入通过」的断言，避免「把所有输入都
拒绝」也算通过。
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from dataclasses import fields, replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soul_memory_kernel.memory.model import Actor, MemoryRecord, RetentionPolicy
from soul_memory_kernel.memory.service import (
    IllegalTransition,
    MemoryServiceError,
    MemoryValidationError,
    RecordNotFound,
    StoreError,
)
from soul_memory_kernel.memory.store import (
    MEMORY_SCHEMA_DDL,
    MEMORY_SCHEMA_VERSION,
    MEMORY_TABLES,
    SqliteMemoryStore,
)

#: 三个 actor：成人控制面（唯一能改召回语义的）、TTL 扫描、schema 迁移。
ADULT = Actor(kind="adult_control_plane", actor_id="family-ai-memory-cli")
TTL = Actor(kind="ttl_expiry", actor_id="family-ai-memory-sweep")
MIGRATION = Actor(kind="migration", actor_id="schema-migration")

_WHEN = "2026-09-26T00:00:00Z"
_LATER = "2026-10-27T00:00:00Z"
#: 候选的到期时间（7 天候选期）。
_LATER_CANDIDATE = "2026-10-03T00:00:00Z"


def _record(record_id: str, **overrides: object) -> MemoryRecord:
    """一条合法的 ``PENDING_CONFIRMATION`` 候选；用 overrides 造各种边界记录。"""

    values: dict[str, object] = {
        "id": record_id,
        "owner_id": "adult_a",
        "scope": "FAMILY",
        "memory_class": "EVENT",
        "source_type": "explicit_user",
        "source_member_id": "adult_a",
        "content": f"content of {record_id}",
        "confidence": 1.0,
        "importance": 0.5,
        "created_at": _WHEN,
        "updated_at": _WHEN,
        "last_confirmed_at": None,
        "expires_at": _LATER_CANDIDATE,
        "source_session_id": "session-1",
        "status": "PENDING_CONFIRMATION",
        "memory_policy": "candidate_only",
        "audiences": frozenset(),
        "consent_version": 1,
        "source_ids": (),
        # A12：归属两列在构造上就与测试用的 ADULT 对齐 —— ``write_record`` 会用本次
        # 写入的 actor 覆盖它们，默认写成别的值会让「逐字段往返」断言变成假失败。
        # 归属要单独验的场合由 test_memory_store 的 A12 专测负责。
        "actor_kind": ADULT.kind,
        "actor_id": ADULT.actor_id,
    }
    values.update(overrides)
    return MemoryRecord(**values)  # type: ignore[arg-type]


def _confirmed(record_id: str, **overrides: object) -> MemoryRecord:
    """一条合法的 ``ACTIVE`` 家庭共享记忆（已确认、有受众、30 天保留期）。"""

    values: dict[str, object] = {
        "last_confirmed_at": _WHEN,
        "expires_at": "2026-10-26T00:00:00Z",
        "status": "ACTIVE",
        "memory_policy": "persist_confirmed",
        "audiences": frozenset({"family_all"}),
        "consent_version": 2,
    }
    values.update(overrides)
    return _record(record_id, **values)


def _stored(tmp_path: Path, name: str = "memory/memory.db") -> SqliteMemoryStore:
    store = SqliteMemoryStore(tmp_path / name)
    store.create_schema()
    return store


def _raw(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    return db


def _count(path: Path, table: str, where: str = "", params: tuple[object, ...] = ()) -> int:
    db = _raw(path)
    try:
        clause = f" WHERE {where}" if where else ""
        return int(db.execute(f"SELECT COUNT(*) FROM {table}{clause}", params).fetchone()[0])
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 文件与 schema 组
# ---------------------------------------------------------------------------


def _store(tmp_path: Path, name: str = "memory/memory.db") -> SqliteMemoryStore:
    """构造 store（**不建库**）：路径带一级子目录，顺便覆盖「自动建父目录」。"""

    return SqliteMemoryStore(tmp_path / name)


def _open_raw(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def test_constructing_the_store_does_not_touch_the_filesystem(tmp_path: Path) -> None:
    """构造是纯的：投影接缝会在会话前 new 一个 store，不能因此落下文件或 schema。"""

    target = tmp_path / "memory" / "memory.db"
    store = SqliteMemoryStore(target)
    assert store.path == target
    assert isinstance(store.path, Path)
    assert not target.exists()
    assert not target.parent.exists()


def test_create_schema_creates_the_seven_tables_and_the_frozen_version(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_schema()

    db = _open_raw(store.path)
    try:
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        version = db.execute("PRAGMA user_version").fetchone()[0]
    finally:
        db.close()
    assert MEMORY_TABLES <= tables
    assert version == MEMORY_SCHEMA_VERSION


def test_create_schema_creates_an_owner_only_file(tmp_path: Path) -> None:
    """0600 独占创建：记忆库是家庭隐私数据，不能落到组 / 其他人可读的权限上。"""

    store = _store(tmp_path)
    store.create_schema()
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_create_schema_is_idempotent(tmp_path: Path) -> None:
    """重复调用是 no-op，不报错、也不清空既有表。"""

    store = _store(tmp_path)
    store.create_schema()
    store.create_schema()
    db = _open_raw(store.path)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == MEMORY_SCHEMA_VERSION
    finally:
        db.close()


def test_create_schema_adopts_an_empty_existing_file(tmp_path: Path) -> None:
    """长度为 0 的文件（``touch`` 或中断的创建）视为新库，直接建表。"""

    target = tmp_path / "memory" / "memory.db"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(mode=0o600)
    assert target.stat().st_size == 0

    SqliteMemoryStore(target).create_schema()
    db = _open_raw(target)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == MEMORY_SCHEMA_VERSION
    finally:
        db.close()


def test_foreign_database_is_refused(tmp_path: Path) -> None:
    """别的库（例如 M1 的家人档案库）不得被当成记忆库打开。"""

    target = tmp_path / "foreign.db"
    db = sqlite3.connect(target)
    db.execute("CREATE TABLE family_member (id TEXT PRIMARY KEY, name TEXT NOT NULL)")
    db.commit()
    db.close()
    os.chmod(target, 0o600)

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(target).create_schema()
    assert "schema version" in str(excinfo.value)


def test_wrong_schema_version_is_refused(tmp_path: Path) -> None:
    """版本不符一律拒绝读取，不做静默迁移。"""

    store = _store(tmp_path)
    store.create_schema()
    db = _open_raw(store.path)
    try:
        db.execute(f"PRAGMA user_version = {MEMORY_SCHEMA_VERSION + 1}")
        db.commit()
    finally:
        db.close()

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(store.path).create_schema()
    assert "refusing to read or migrate" in str(excinfo.value)


def test_missing_table_is_refused(tmp_path: Path) -> None:
    """表缺失（半截 schema）不得被当成可用库。"""

    store = _store(tmp_path)
    store.create_schema()
    db = _open_raw(store.path)
    try:
        db.execute("DROP TABLE memory_audience")
        db.commit()
    finally:
        db.close()

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(store.path).create_schema()
    assert "missing tables" in str(excinfo.value)


def test_missing_column_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_schema()
    db = _open_raw(store.path)
    try:
        db.execute("ALTER TABLE memory_record DROP COLUMN source_session_id")
        db.commit()
    finally:
        db.close()

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(store.path).create_schema()
    assert "missing columns" in str(excinfo.value)


def test_corrupt_database_file_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_schema()
    store.path.write_bytes(b"this is not a sqlite database at all" * 4)

    with pytest.raises(StoreError):
        SqliteMemoryStore(store.path).create_schema()


def test_symlinked_database_is_refused(tmp_path: Path) -> None:
    """symlink 拒绝：否则 0600 的检查可以被绕到一个共享文件上。"""

    real = tmp_path / "real.db"
    SqliteMemoryStore(real).create_schema()
    link = tmp_path / "link.db"
    link.symlink_to(real)

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(link).create_schema()
    assert "symlink" in str(excinfo.value)


def test_broad_permissions_are_refused(tmp_path: Path) -> None:
    """权限过宽（组 / 其他人可读）拒绝，并在错误里给出 ``chmod 600`` 的指引。"""

    store = _store(tmp_path)
    store.create_schema()
    os.chmod(store.path, 0o644)

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(store.path).create_schema()
    assert "chmod 600" in str(excinfo.value)


# ---------------------------------------------------------------------------
# CRUD 组：写入 / 读取
# ---------------------------------------------------------------------------


def test_write_record_creates_the_database_on_first_write(tmp_path: Path) -> None:
    """首次写入自动建库建表（W5 的 CLI 不必先手动 ``create_schema``）。"""

    target = tmp_path / "fresh" / "memory.db"
    store = SqliteMemoryStore(target)
    assert not target.exists()
    store.write_record(_record("c1"), actor=ADULT)

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [record.id for record in store.read_records(("c1",))] == ["c1"]


def test_write_and_read_record_round_trips_every_field(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    record = _record(
        "c1",
        memory_class="PREFERENCE",
        importance=0.75,
        audiences=frozenset({"family_all", "adult_b"}),
        source_ids=(),
    )
    store.write_record(record, actor=ADULT)

    assert store.read_record("c1") == record
    for field in fields(MemoryRecord):
        assert getattr(store.read_record("c1"), field.name) == getattr(record, field.name), field.name


def test_read_record_returns_none_for_a_missing_or_absent_database(tmp_path: Path) -> None:
    """「没有记忆」是正常状态：库不存在、记录不存在都返回 ``None``，不抛异常。"""

    missing_db = SqliteMemoryStore(tmp_path / "nowhere" / "memory.db")
    assert missing_db.read_record("c1") is None
    assert missing_db.read_records(("c1",)) == ()
    assert missing_db.list_eligible(
        owner_id=None, audience_id="family_all", scopes=("FAMILY",), statuses=("ACTIVE",)
    ) == ()
    assert missing_db.resolve_provenance(("c1",)) == ()
    assert missing_db.enumerate_dependents("c1") == ()
    assert not (tmp_path / "nowhere").exists(), "读路径不得创建库"

    assert _stored(tmp_path).read_record("ghost") is None


def test_read_records_signals_a_missing_id_by_leaving_it_out(tmp_path: Path) -> None:
    """批量读的「缺源信号」= 结果短了：调用方据此报 ``missing_provenance``。"""

    store = _stored(tmp_path)
    store.write_record(_record("c1"), actor=ADULT)
    store.write_record(_record("c2"), actor=ADULT)

    assert [record.id for record in store.read_records(("c1", "ghost", "c2"))] == ["c1", "c2"]
    assert [record.id for record in store.read_records(("c2", "c1"))] == ["c2", "c1"]
    assert [record.id for record in store.read_records(("c1", "c1"))] == ["c1"]
    assert store.read_records(()) == ()


def test_write_record_replaces_audiences_and_lineage_wholesale(tmp_path: Path) -> None:
    """整体替换：旧的受众行与血缘行必须消失，ordinal 按传入顺序重建。"""

    store = _stored(tmp_path)
    store.write_record(_record("s1"), actor=ADULT)
    store.write_record(_record("s2"), actor=ADULT)
    store.write_record(
        _record("r1", audiences=frozenset({"family_all", "adult_b"}), source_ids=("s1",)),
        actor=ADULT,
    )
    assert store.read_record("r1").audiences == {"family_all", "adult_b"}

    store.write_record(
        _record("r1", audiences=frozenset({"family_all"}), source_ids=("s2", "s1")),
        actor=ADULT,
    )
    updated = store.read_record("r1")
    assert updated.audiences == frozenset({"family_all"})
    assert updated.source_ids == ("s2", "s1"), "血缘顺序必须稳定（ordinal）"
    assert _count(store.path, "memory_audience", "record_id = ?", ("r1",)) == 1
    assert _count(store.path, "memory_source", "record_id = ?", ("r1",)) == 2


def test_rewriting_a_source_keeps_lineage_rows_pointing_at_it(tmp_path: Path) -> None:
    """契约 §7.4：血缘行以 ``source_id`` 指向来源，**重写来源不得动这些行**。"""

    store = _stored(tmp_path)
    store.write_record(_record("s1"), actor=ADULT)
    store.write_record(_record("d1", source_ids=("s1",)), actor=ADULT)

    store.write_record(_confirmed("s1"), actor=ADULT)  # 确认来源：状态从候选变 ACTIVE

    assert store.read_record("d1").source_ids == ("s1",)
    assert store.enumerate_dependents("s1") == ("d1",)


def test_provenance_row_survives_a_raw_delete_of_the_source(tmp_path: Path) -> None:
    """``source_id`` **没有外键**：来源行被外部工具删掉后，血缘行必须还在。

    若加了 ``ON DELETE CASCADE``，派生记录会「看起来没有祖先」而被当成干净记录继续
    召回 —— 那正是最危险的越权路径（契约 §7.4）。这里用裸 SQL 删来源行来证明没有级联。
    """

    store = _stored(tmp_path)
    store.write_record(_record("s1"), actor=ADULT)
    store.write_record(_record("d1", source_ids=("s1",)), actor=ADULT)

    db = _raw(store.path)
    try:
        db.execute("DELETE FROM memory_record WHERE id = 's1'")
        db.commit()
    finally:
        db.close()

    assert _count(store.path, "memory_source", "record_id = ?", ("d1",)) == 1
    assert store.read_record("d1").source_ids == ("s1",)
    # 解析时缺源 ⇒ 派生记录被 fail-closed 剪掉（调用方据此报 missing_provenance）
    assert store.resolve_provenance(("d1",)) == ()


def test_write_record_failure_leaves_the_stored_record_untouched(tmp_path: Path) -> None:
    """写入是一个事务：校验失败时既不能落半条记录，也不能破坏既有记录。"""

    store = _stored(tmp_path)
    original = _record("c1", audiences=frozenset({"family_all"}), source_ids=())
    store.write_record(original, actor=ADULT)

    with pytest.raises(MemoryValidationError):
        store.write_record(
            _record("c1", audiences=frozenset({"family_all"}), source_ids=("c1",)), actor=ADULT
        )

    assert store.read_record("c1") == original


def test_reads_do_not_write_to_the_database_directory(tmp_path: Path) -> None:
    """投影路径只读：读过一轮之后目录里不得多出 journal / 临时文件。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("c1"), actor=ADULT)
    before = {path.name for path in store.path.parent.iterdir()}

    store.read_record("c1")
    store.read_records(("c1",))
    store.list_eligible(
        owner_id=None, audience_id="family_all", scopes=("FAMILY",), statuses=("ACTIVE",)
    )
    store.resolve_provenance(("c1",))
    store.enumerate_dependents("c1")
    store.list_expired(now=_LATER)

    assert {path.name for path in store.path.parent.iterdir()} == before


# ---------------------------------------------------------------------------
# CRUD 组：写入前校验（DDL 六条 CHECK + 契约不变量）
# ---------------------------------------------------------------------------


def test_write_record_rejects_do_not_persist_before_touching_the_database(tmp_path: Path) -> None:
    """落点一在库层的第二道防线：DDL 排除该取值，写入路径也在写之前拒绝。"""

    store = _stored(tmp_path)
    with pytest.raises(MemoryValidationError) as excinfo:
        store.write_record(_record("c1", memory_policy="do_not_persist"), actor=ADULT)
    assert "do_not_persist" in str(excinfo.value)
    assert _count(store.path, "memory_record") == 0


@pytest.mark.parametrize(
    ("overrides", "expected_fragment"),
    [
        ({"scope": "SAFETY"}, "scope='SAFETY' requires memory_class='SAFETY'"),
        ({"memory_class": "SAFETY", "expires_at": None}, "expires_at may be NULL only"),
        ({"scope": "PERSONAL", "expires_at": None}, "expires_at may be NULL only"),
        (
            {"status": "ACTIVE", "memory_policy": "persist_confirmed", "expires_at": None},
            "expires_at may be NULL only",
        ),
        (
            {"status": "ACTIVE", "memory_policy": "persist_confirmed"},
            "must have last_confirmed_at",
        ),
        ({"status": "ACTIVE"}, "requires memory_policy 'persist_confirmed'"),
        ({"memory_policy": "persist_confirmed"}, "requires memory_policy 'candidate_only'"),
        (
            {"status": "DELETED", "memory_policy": "candidate_only"},
            "must carry empty content",
        ),
        ({"content": ""}, "content must be non-empty"),
        ({"confidence": 1.5}, "confidence must be a number within [0, 1]"),
        ({"importance": -0.1}, "importance must be a number within [0, 1]"),
        ({"consent_version": 0}, "consent_version must be >= 1"),
        ({"scope": "SHARED"}, "scope must be one of"),
        ({"memory_class": "MOOD"}, "memory_class must be one of"),
        ({"source_type": "guessed"}, "source_type must be one of"),
        ({"status": "FROZEN"}, "status must be one of"),
        ({"id": "  "}, "id must be a non-empty string"),
        ({"owner_id": ""}, "owner_id must be a non-empty string"),
        ({"created_at": "yesterday"}, "created_at is not a parseable ISO-8601 timestamp"),
        ({"updated_at": "2026-09-26T00:00:00"}, "must carry a UTC offset"),
        ({"expires_at": "soon"}, "expires_at is not a parseable ISO-8601 timestamp"),
        ({"last_confirmed_at": "  "}, "last_confirmed_at is not a parseable ISO-8601 timestamp"),
        ({"source_ids": ("c1",)}, "must not contain the record's own id"),
        ({"source_ids": ("s1", "s1")}, "source_ids must not repeat an id"),
        ({"source_ids": ("s1", "")}, "source_ids must be a tuple of non-empty strings"),
        ({"audiences": frozenset({"family_all", " "})}, "audiences must be a frozenset"),
        ({"audiences": ("family_all",)}, "audiences must be a frozenset"),
        ({"source_member_id": ""}, "source_member_id must be None or a non-empty string"),
    ],
)
def test_write_record_refuses_contract_violating_records(
    tmp_path: Path, overrides: dict[str, object], expected_fragment: str
) -> None:
    """每条不变量都配一个反例；错误信息要指出**是哪条**不变量，不是笼统的失败。"""

    store = _stored(tmp_path)
    with pytest.raises(MemoryValidationError) as excinfo:
        store.write_record(_record("c1", **overrides), actor=ADULT)
    assert expected_fragment in str(excinfo.value)
    assert _count(store.path, "memory_record") == 0


@pytest.mark.parametrize(
    "record",
    [
        _confirmed("ok-family-event"),
        _record("ok-candidate"),
        _record("ok-preference", memory_class="PREFERENCE"),
        # FAMILY + memory_class=SAFETY：不受相位限制，且确认后不过期（D5）。
        _confirmed(
            "ok-family-safety",
            memory_class="SAFETY",
            expires_at=None,
        ),
        # 历史墓碑（M2.1 不产出，但导入要能落库）：无正文、无期限要求。
        _record(
            "ok-tombstone",
            status="DELETED",
            memory_policy="candidate_only",
            content="",
            expires_at=_LATER,
        ),
    ],
)
def test_write_record_accepts_every_legal_shape(tmp_path: Path, record: MemoryRecord) -> None:
    """正例成对出现：上面的反例不能靠「把所有写入都拒绝」通过。"""

    store = _stored(tmp_path)
    store.write_record(record, actor=ADULT)
    assert store.read_record(record.id) == record


def test_write_record_accepts_non_family_scopes_for_import_and_deny_tests(
    tmp_path: Path,
) -> None:
    """**库层不执行 M2.1 相位限制** —— 相位是服务层的规则，不是 schema 的规则。

    两个理由：(1) 契约 §4.5 要求「`PERSONAL` / `SAFETY` 记录（**若库中存在**）一律进
    ``denied``」，W2/W3 要能造出这类行来验证 ``scope_not_enabled``；(2) 历史 / 导入数据
    可能带非 FAMILY scope。拒绝它们发生在 ``propose()`` / ``confirm_shared()`` / 读判权，
    不在这里 —— 若库层也拦，W2 的反例就构造不出来。
    """

    store = _stored(tmp_path)
    personal = _confirmed("p1", scope="PERSONAL", audiences=frozenset({"adult_a"}))
    safety_scope = _confirmed(
        "s1", scope="SAFETY", memory_class="SAFETY", expires_at=None
    )
    store.write_record(personal, actor=ADULT)
    store.write_record(safety_scope, actor=ADULT)

    assert store.read_record("p1").scope == "PERSONAL"
    assert store.read_record("s1").scope == "SAFETY"
    assert store.read_record("s1").expires_at is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": ["FAMILY"]},
        {"status": {"ACTIVE": 1}},
        {"memory_class": {"SAFETY": 1}},
        {"memory_policy": ["candidate_only"]},
        {"source_type": 7},
    ],
)
def test_write_record_reports_shape_errors_not_type_errors(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    """非字符串 / 不可哈希的取值是形状错误（``MemoryValidationError``），不是 ``TypeError``。

    否则调用方拿到的是 Python 内部错误（``unhashable type``），既不是契约错误也没法审计。
    """

    store = _stored(tmp_path)
    with pytest.raises(MemoryValidationError):
        store.write_record(_record("c1", **overrides), actor=ADULT)
    assert _count(store.path, "memory_record") == 0


def test_transition_rejects_a_non_string_target_status(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_record("c1"), actor=ADULT)
    with pytest.raises(IllegalTransition):
        store.transition(
            "c1",
            {"ACTIVE": 1},  # type: ignore[arg-type]
            actor=ADULT,
            updated_at=_LATER,
            consent_version=2,
            last_confirmed_at=_LATER,
        )


def test_list_eligible_rejects_non_string_filters(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    with pytest.raises(MemoryValidationError):
        store.list_eligible(
            owner_id=None, audience_id="family_all", scopes=(1,), statuses=("ACTIVE",)  # type: ignore[arg-type]
        )
    with pytest.raises(MemoryValidationError):
        store.list_eligible(
            owner_id=7, audience_id="family_all", scopes=("FAMILY",), statuses=("ACTIVE",)  # type: ignore[arg-type]
        )


def test_write_record_rejects_an_unknown_actor_kind(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    with pytest.raises(IllegalTransition):
        store.write_record(_record("c1"), actor=Actor(kind="robot", actor_id="x"))  # type: ignore[arg-type]


def test_only_the_adult_control_plane_may_insert_records(tmp_path: Path) -> None:
    """§2.4：``ttl_expiry`` 只能做两条 TTL 路径，``migration`` 在 M2.1 无可用动作。"""

    store = _stored(tmp_path)
    for actor in (TTL, MIGRATION):
        with pytest.raises(IllegalTransition) as excinfo:
            store.write_record(_record("c1"), actor=actor)
        assert "ABSENT" in str(excinfo.value)
    assert _count(store.path, "memory_record") == 0
    store.write_record(_record("c1"), actor=ADULT)
    assert store.read_record("c1") is not None


def test_ttl_expiry_cannot_edit_recall_semantics(tmp_path: Path) -> None:
    """``ttl_expiry`` 的写权限只覆盖「停止召回」：正文 / 受众 / 血缘 / consent 都不许改。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("c1"), actor=ADULT)

    with pytest.raises(IllegalTransition):
        store.write_record(_confirmed("c1", content="被改写的正文"), actor=TTL)
    with pytest.raises(IllegalTransition):
        store.write_record(_confirmed("c1", audiences=frozenset({"family_all", "adult_b"})), actor=TTL)
    with pytest.raises(IllegalTransition):
        store.write_record(_confirmed("c1", consent_version=3), actor=TTL)

    # 正例：TTL 的合法写就是 ACTIVE → DECAYED，其余字段原样。
    store.write_record(
        _confirmed("c1", status="DECAYED", updated_at=_LATER),
        actor=TTL,
    )
    assert store.read_record("c1").status == "DECAYED"
    assert store.read_record("c1").content == "content of c1"


def test_migration_cannot_change_recall_semantics_or_status(tmp_path: Path) -> None:
    """``migration`` 允许改非召回字段（时间戳格式），禁止改正文 / consent / 状态。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("c1"), actor=ADULT)

    with pytest.raises(IllegalTransition):
        store.write_record(_confirmed("c1", content="migration rewrite"), actor=MIGRATION)
    with pytest.raises(IllegalTransition):
        store.write_record(_confirmed("c1", consent_version=3), actor=MIGRATION)
    with pytest.raises(IllegalTransition):
        store.write_record(_confirmed("c1", status="DECAYED"), actor=MIGRATION)

    # 正例：只改时间戳格式（非召回字段）是允许的。
    store.write_record(
        _confirmed("c1", created_at="2026-09-26T00:00:00+00:00", updated_at=_LATER),
        actor=MIGRATION,
    )
    assert store.read_record("c1").updated_at == _LATER


def test_write_record_cannot_decrease_consent_version(tmp_path: Path) -> None:
    """``consent_version`` 递减会让旧 grant 复活 —— 任何 actor 都不许。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("c1", consent_version=3), actor=ADULT)
    with pytest.raises(MemoryValidationError):
        store.write_record(_confirmed("c1", consent_version=2), actor=ADULT)
    assert store.read_record("c1").consent_version == 3


def test_write_record_enforces_the_state_machine_on_status_changes(tmp_path: Path) -> None:
    """**换入口不等于绕开状态机**：整体替换里的状态变化同样要过 ``LEGAL_TRANSITIONS``。

    这条对 W3 很关键：``confirm_shared()`` 需要改 ``audiences`` / ``expires_at``，只能走
    ``write_record``，因此 ``write_record`` 必须自己守住迁移合法性。
    """

    store = _stored(tmp_path)
    store.write_record(_record("c1"), actor=ADULT)

    # 候选直接变 DECAYED：不在 LEGAL_TRANSITIONS 里（候选从未可召回）。
    with pytest.raises(IllegalTransition):
        store.write_record(
            _record("c1", status="DECAYED", memory_policy="persist_confirmed"), actor=ADULT
        )
    # 指向 DELETED 的三条边在 M2.1 没有产出路径（删除即硬删）。
    with pytest.raises(IllegalTransition):
        store.write_record(
            _record("c1", status="DELETED", memory_policy="candidate_only", content=""),
            actor=ADULT,
        )
    # 自环 PENDING → PENDING 不是合法迁移，但「不改状态的整体替换」是允许的。
    store.write_record(_record("c1", content="候选正文修正"), actor=ADULT)
    assert store.read_record("c1").content == "候选正文修正"
    # 正例：候选 → ACTIVE（确认路径）。
    store.write_record(_confirmed("c1"), actor=ADULT)
    assert store.read_record("c1").status == "ACTIVE"


# ---------------------------------------------------------------------------
# CRUD 组：状态迁移
# ---------------------------------------------------------------------------


def test_transition_confirming_a_candidate_writes_the_bound_policy(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_record("c1"), actor=ADULT)

    updated = store.transition(
        "c1",
        "ACTIVE",
        actor=ADULT,
        updated_at=_LATER,
        consent_version=2,
        last_confirmed_at=_LATER,
    )
    assert (updated.status, updated.memory_policy, updated.consent_version) == (
        "ACTIVE",
        "persist_confirmed",
        2,
    )
    assert store.read_record("c1") == updated, "返回的记录必须与库内一致"


def test_transition_decay_and_reactivation(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_confirmed("c1"), actor=ADULT)

    decayed = store.transition(
        "c1",
        "DECAYED",
        actor=TTL,
        updated_at=_LATER,
        consent_version=2,
        last_confirmed_at=_WHEN,
    )
    assert (decayed.status, decayed.memory_policy) == ("DECAYED", "persist_confirmed")

    revived = store.transition(
        "c1",
        "ACTIVE",
        actor=ADULT,
        updated_at=_LATER,
        consent_version=3,
        last_confirmed_at=_LATER,
    )
    assert (revived.status, revived.memory_policy) == ("ACTIVE", "persist_confirmed")
    assert store.read_record("c1").consent_version == 3


def test_transition_self_loops(tmp_path: Path) -> None:
    """``ACTIVE → ACTIVE``（修正 / 再次确认）与 ``DECAYED → DECAYED``（幂等 no-op）。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("c1"), actor=ADULT)
    store.write_record(_confirmed("c2"), actor=ADULT)
    store.transition(
        "c2", "DECAYED", actor=TTL, updated_at=_LATER, consent_version=2, last_confirmed_at=_WHEN
    )

    same = store.transition(
        "c1", "ACTIVE", actor=ADULT, updated_at=_LATER, consent_version=3, last_confirmed_at=_LATER
    )
    assert same.status == "ACTIVE" and same.consent_version == 3
    # §2.3 第 7 行：DECAYED → DECAYED 是幂等 no-op，actor 任意。
    noop = store.transition(
        "c2",
        "DECAYED",
        actor=MIGRATION,
        updated_at=_LATER,
        consent_version=2,
        last_confirmed_at=_WHEN,
    )
    assert noop.status == "DECAYED"


@pytest.mark.parametrize(
    ("from_status", "to_status"),
    [
        ("PENDING_CONFIRMATION", "DECAYED"),
        ("PENDING_CONFIRMATION", "DELETED"),
        ("ACTIVE", "DELETED"),
        ("DECAYED", "DELETED"),
    ],
)
def test_transition_refuses_illegal_edges(
    tmp_path: Path, from_status: str, to_status: str
) -> None:
    """不可迁移的边必须抛 ``IllegalTransition``，**不得静默 no-op**。"""

    store = _stored(tmp_path)
    if from_status == "PENDING_CONFIRMATION":
        store.write_record(_record("c1"), actor=ADULT)
    else:
        store.write_record(_confirmed("c1", status=from_status), actor=ADULT)

    with pytest.raises(IllegalTransition) as excinfo:
        store.transition(
            "c1",
            to_status,
            actor=ADULT,
            updated_at=_LATER,
            consent_version=2,
            last_confirmed_at=_WHEN,
        )
    assert excinfo.value.from_status == from_status
    assert excinfo.value.to_status == to_status
    assert store.read_record("c1").status == from_status, "非法迁移不得改动记录"


def test_transition_from_deleted_is_terminal(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(
        _record(
            "tomb",
            status="DELETED",
            memory_policy="candidate_only",
            content="",
            expires_at=_LATER,
        ),
        actor=ADULT,
    )
    with pytest.raises(IllegalTransition):
        store.transition(
            "tomb",
            "ACTIVE",
            actor=ADULT,
            updated_at=_LATER,
            consent_version=2,
            last_confirmed_at=_LATER,
        )


@pytest.mark.parametrize(
    ("actor", "from_status", "to_status"),
    [
        (ADULT, "ACTIVE", "DECAYED"),  # TTL 迁移只有 ttl_expiry 能做
        (MIGRATION, "ACTIVE", "DECAYED"),
        (TTL, "DECAYED", "ACTIVE"),  # ttl_expiry 不得重新激活
        (TTL, "PENDING_CONFIRMATION", "ACTIVE"),  # 也不得确认
        (MIGRATION, "PENDING_CONFIRMATION", "ACTIVE"),
    ],
)
def test_transition_refuses_actors_without_permission(
    tmp_path: Path, actor: Actor, from_status: str, to_status: str
) -> None:
    store = _stored(tmp_path)
    if from_status == "PENDING_CONFIRMATION":
        store.write_record(_record("c1"), actor=ADULT)
    else:
        store.write_record(_confirmed("c1", status=from_status), actor=ADULT)

    with pytest.raises(IllegalTransition) as excinfo:
        store.transition(
            "c1",
            to_status,
            actor=actor,
            updated_at=_LATER,
            consent_version=2,
            last_confirmed_at=_WHEN,
        )
    assert excinfo.value.actor_kind == actor.kind


def test_transition_requires_the_record_and_valid_timestamps(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    with pytest.raises(RecordNotFound):
        store.transition(
            "ghost",
            "ACTIVE",
            actor=ADULT,
            updated_at=_LATER,
            consent_version=2,
            last_confirmed_at=_LATER,
        )

    store.write_record(_record("c1"), actor=ADULT)
    with pytest.raises(MemoryValidationError) as excinfo:
        store.transition(
            "c1",
            "ACTIVE",
            actor=ADULT,
            updated_at=_LATER,
            consent_version=2,
            last_confirmed_at=None,  # FAMILY + ACTIVE 必须带确认时间
        )
    assert "last_confirmed_at" in str(excinfo.value)
    assert store.read_record("c1").status == "PENDING_CONFIRMATION"

    with pytest.raises(MemoryValidationError):
        store.transition(
            "c1",
            "ACTIVE",
            actor=ADULT,
            updated_at=_LATER,
            consent_version=2,
            last_confirmed_at="not-a-time",
        )
    with pytest.raises(MemoryValidationError):
        store.transition(
            "c1",
            "ACTIVE",
            actor=ADULT,
            updated_at=_LATER,
            consent_version=0,
            last_confirmed_at=_LATER,
        )


# ---------------------------------------------------------------------------
# CRUD 组：查询入口与血缘解析
# ---------------------------------------------------------------------------


def test_list_eligible_narrows_by_audience_owner_scope_and_status(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_confirmed("a-family"), actor=ADULT)
    store.write_record(_confirmed("b-other-owner", owner_id="adult_b"), actor=ADULT)
    store.write_record(_record("c-candidate"), actor=ADULT)  # 无受众（刚 propose 出来）
    store.write_record(
        _record("f-candidate-audience", audiences=frozenset({"family_all"})), actor=ADULT
    )
    store.write_record(
        _confirmed("d-member-audience", audiences=frozenset({"adult_b"})), actor=ADULT
    )
    db = _raw(store.path)
    try:
        # 库里可能存在的非 FAMILY 记录（M2.1 读路径会 deny，但缩范围时要能查出来）
        db.execute(
            "INSERT INTO memory_record (id, owner_id, scope, memory_class, source_type, "
            "source_member_id, content, confidence, importance, created_at, updated_at, "
            "last_confirmed_at, expires_at, source_session_id, status, memory_policy, "
            "consent_version, actor_kind, actor_id) "
            "VALUES ('e-personal', 'adult_a', 'PERSONAL', 'EVENT', "
            "'explicit_user', 'adult_a', 'x', 1.0, 0.5, ?, ?, ?, ?, NULL, 'ACTIVE', "
            "'persist_confirmed', 1, 'adult_control_plane', 'test:raw-insert')",
            (_WHEN, _WHEN, _WHEN, _LATER),
        )
        db.execute(
            "INSERT INTO memory_audience (record_id, audience_id) VALUES ('e-personal', 'family_all')"
        )
        db.commit()
    finally:
        db.close()

    # 缩范围按 scope 过滤：非 FAMILY 记录只有把它的 scope 放进 scopes 才会出现
    # （M2.1 读路径随后会以 scope_not_enabled 拒绝它 —— 那是判权的事，不是缩范围的事）。
    assert store.list_eligible(
        owner_id=None, audience_id="family_all", scopes=("FAMILY",), statuses=("ACTIVE",)
    ) == ("a-family", "b-other-owner")
    assert store.list_eligible(
        owner_id=None,
        audience_id="family_all",
        scopes=("FAMILY", "PERSONAL"),
        statuses=("ACTIVE",),
    ) == ("a-family", "b-other-owner", "e-personal")
    assert store.list_eligible(
        owner_id="adult_a", audience_id="family_all", scopes=("FAMILY",), statuses=("ACTIVE",)
    ) == ("a-family",)
    assert store.list_eligible(
        owner_id=None,
        audience_id="family_all",
        scopes=("FAMILY",),
        statuses=("PENDING_CONFIRMATION",),
    ) == ("f-candidate-audience",)
    assert store.list_eligible(
        owner_id=None, audience_id="adult_b", scopes=("FAMILY",), statuses=("ACTIVE",)
    ) == ("d-member-audience",)


def test_list_eligible_is_deny_by_default(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_confirmed("c1"), actor=ADULT)

    assert store.list_eligible(
        owner_id=None, audience_id="family_all", scopes=(), statuses=("ACTIVE",)
    ) == ()
    assert store.list_eligible(
        owner_id=None, audience_id="family_all", scopes=("FAMILY",), statuses=()
    ) == ()
    assert store.list_eligible(
        owner_id=None, audience_id="", scopes=("FAMILY",), statuses=("ACTIVE",)
    ) == ()
    # public_room 与「家人可读」是不同受众。
    assert store.list_eligible(
        owner_id=None, audience_id="public_room", scopes=("FAMILY",), statuses=("ACTIVE",)
    ) == ()
    # 未知 scope / status 不匹配，而不是「当成全部」。
    assert store.list_eligible(
        owner_id=None, audience_id="family_all", scopes=("SHARED",), statuses=("ACTIVE",)
    ) == ()
    assert store.list_eligible(
        owner_id=None, audience_id="family_all", scopes=("FAMILY",), statuses=("FROZEN",)
    ) == ()


def test_resolve_provenance_returns_a_closed_ancestor_closure(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_record("root"), actor=ADULT)
    store.write_record(_record("mid", source_ids=("root",)), actor=ADULT)
    store.write_record(_record("leaf", source_ids=("mid", "root")), actor=ADULT)

    closure = store.resolve_provenance(("leaf",))
    assert [record.id for record in closure] == ["leaf", "mid", "root"]
    returned = {record.id for record in closure}
    for record in closure:
        assert set(record.source_ids) <= returned, "闭包必须对 source_ids 闭合"
    assert store.resolve_provenance(()) == ()


def test_resolve_provenance_fails_closed_on_missing_ancestors(tmp_path: Path) -> None:
    """缺源 → 该记录**及依赖它的一切**都不返回（缺源信号就是缺失本身）。"""

    store = _stored(tmp_path)
    store.write_record(_record("clean"), actor=ADULT)
    store.write_record(_record("broken", source_ids=("ghost",)), actor=ADULT)
    store.write_record(_record("on-broken", source_ids=("broken",)), actor=ADULT)

    assert [record.id for record in store.resolve_provenance(("broken",))] == []
    assert [record.id for record in store.resolve_provenance(("on-broken",))] == []
    assert [record.id for record in store.resolve_provenance(("clean", "broken"))] == ["clean"]
    # 无关的干净记录不受牵连
    assert [record.id for record in store.resolve_provenance(("clean",))] == ["clean"]


def test_resolve_provenance_fails_closed_on_cycles(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_record("a", source_ids=("b",)), actor=ADULT)
    store.write_record(_record("b", source_ids=("a",)), actor=ADULT)
    store.write_record(_record("outsider"), actor=ADULT)

    assert store.resolve_provenance(("a",)) == ()
    assert store.resolve_provenance(("b",)) == ()
    assert [record.id for record in store.resolve_provenance(("outsider", "a"))] == ["outsider"]


def test_enumerate_dependents_is_transitive(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_record("root"), actor=ADULT)
    store.write_record(_record("child", source_ids=("root",)), actor=ADULT)
    store.write_record(_record("grandchild", source_ids=("child",)), actor=ADULT)
    store.write_record(_record("unrelated"), actor=ADULT)

    assert store.enumerate_dependents("root") == ("child", "grandchild")
    assert store.enumerate_dependents("child") == ("grandchild",)
    assert store.enumerate_dependents("unrelated") == ()
    assert store.enumerate_dependents("nobody") == ()


# ---------------------------------------------------------------------------
# CRUD 组：删除清单与 deletion_audit
# ---------------------------------------------------------------------------


def test_hard_delete_removes_every_row_in_the_contract_checklist(tmp_path: Path) -> None:
    """§7.1：记录行、受众行、**它自己作为子节点的**血缘行、``grant_resource`` 行消失；
    **指向它的血缘行保留**（主控仲裁 2026-09-26 的血缘口径）。

    ``grant_resource`` 无外键无级联，最容易漏；这里显式放一行再验证它被删掉。
    """

    store = _stored(tmp_path)
    store.write_record(_record("base"), actor=ADULT)
    store.write_record(
        _record("root", audiences=frozenset({"family_all"}), source_ids=("base",)), actor=ADULT
    )
    store.write_record(_record("dependent", source_ids=("root",)), actor=ADULT)

    db = _raw(store.path)
    try:
        db.execute("INSERT INTO grant_resource VALUES ('grant-a', 1, 'root', 1)")
        db.execute("INSERT INTO grant_resource VALUES ('grant-a', 1, 'dependent', 1)")
        db.commit()
    finally:
        db.close()

    touched = store.hard_delete("root")
    assert touched == ("memory_source", "memory_audience", "grant_resource", "memory_record")

    assert store.read_record("root") is None
    assert _count(store.path, "memory_audience", "record_id = ?", ("root",)) == 0
    assert _count(store.path, "grant_resource", "record_id = ?", ("root",)) == 0
    # 它自己作为子节点的血缘行（root → base）随记录一起消失。
    assert _count(store.path, "memory_source", "record_id = ?", ("root",)) == 0
    # **指向它的**血缘行保留：派生记录不会「看起来没有祖先」（契约 §7.4 的最危险路径）。
    assert _count(store.path, "memory_source", "source_id = ?", ("root",)) == 1
    dependent = store.read_record("dependent")
    assert dependent is not None and dependent.source_ids == ("root",)
    # 派生记录自己的 grant_resource 行不属于本次删除范围。
    assert _count(store.path, "grant_resource", "record_id = ?", ("dependent",)) == 1


def test_ancestor_deletion_leaves_dependents_fail_closed_but_enumerable(tmp_path: Path) -> None:
    """删除顺序**不受约束**（仲裁修订）：先删祖先也不会让派生记录变成「干净记录」。

    - 指向它的血缘行保留 ⇒ :meth:`enumerate_dependents` 在祖先删除之后照样反查得出；
    - 但在派生记录被删掉之前，它解析不出祖先 ⇒ :meth:`resolve_provenance` fail-closed，
      调用方按 ``missing_provenance`` 拒绝它 —— 这正是 §7.4 要防的越权路径；
    - 派生记录按 §7.1 第 5 项连带删除后，血缘行随它们自己的删除一起消失。
    """

    store = _stored(tmp_path)
    store.write_record(_record("root", audiences=frozenset({"family_all"})), actor=ADULT)
    store.write_record(_record("child", source_ids=("root",)), actor=ADULT)
    store.write_record(_record("grandchild", source_ids=("child",)), actor=ADULT)

    touched = store.hard_delete("root")  # 先删祖先：允许，不是接口顺序错误
    assert "memory_record" in touched
    assert store.read_record("root") is None

    assert store.enumerate_dependents("root") == ("child", "grandchild"), "血缘行仍在"
    assert store.resolve_provenance(("child",)) == (), "缺源 ⇒ fail-closed"
    assert store.resolve_provenance(("grandchild",)) == ()
    assert store.read_record("child") is not None, "派生记录本身还在，由调用方连带删除"

    for dependent in ("grandchild", "child"):  # 反向顺序也可以
        store.hard_delete(dependent)
    assert store.read_record("child") is None
    assert store.read_record("grandchild") is None
    assert _count(store.path, "memory_source") == 0


def test_hard_delete_is_idempotent_and_reports_nothing_when_absent(tmp_path: Path) -> None:
    store = _stored(tmp_path)
    store.write_record(_record("c1", audiences=frozenset({"family_all"})), actor=ADULT)

    assert "memory_record" in store.hard_delete("c1")
    assert store.hard_delete("c1") == ()
    assert store.hard_delete("never-existed") == ()


def test_hard_delete_only_touches_tables_that_had_rows(tmp_path: Path) -> None:
    """``tables_touched`` 报的是事实：没有受众行 / 授权行时不得把它们列进去。"""

    store = _stored(tmp_path)
    store.write_record(_record("bare"), actor=ADULT)  # 无受众、无血缘、无 grant_resource
    assert store.hard_delete("bare") == ("memory_record",)


def test_write_deletion_audit_records_the_deletion_without_content(tmp_path: Path) -> None:
    """审计行只存 record_id 与计数；**正文绝不进审计表**（§7.3）。"""

    store = _stored(tmp_path)
    secret = "SECRET-ALLERGY-NOTE"
    store.write_record(_record("c1", content=secret), actor=ADULT)
    store.hard_delete("c1")

    audit_id = store.write_deletion_audit(
        record_id="c1",
        actor=ADULT,
        deleted_at=_LATER,
        tables_touched=("memory_source", "memory_record"),
        derived_removed=2,
        unknown_copies=("provider-side", "time-machine"),
    )
    assert re.fullmatch(r"[0-9a-f]{32}", audit_id)

    db = _raw(store.path)
    try:
        rows = db.execute(
            "SELECT audit_id, record_id, actor_kind, actor_id, deleted_at, tables_touched, "
            "derived_removed, unknown_copies FROM deletion_audit"
        ).fetchall()
    finally:
        db.close()
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == audit_id
    assert row[1] == "c1"
    assert (row[2], row[3], row[4]) == ("adult_control_plane", ADULT.actor_id, _LATER)
    assert row[5] == '["memory_source", "memory_record"]'
    assert row[6] == 2
    assert row[7] == '["provider-side", "time-machine"]'
    assert secret not in " ".join(str(value) for value in row)


def test_write_deletion_audit_refuses_bad_input(tmp_path: Path) -> None:
    store = _stored(tmp_path)

    # B-s3（主控 2026-09-26）：actor 策略**显式**校验，不靠 DDL CHECK 兜底 ——
    # 越权 actor 得到明确的校验错误，而不是被包成 StoreError 的 CHECK constraint failed。
    # 允许写审计的只有 adult_control_plane 与 ttl_expiry。
    for denied in (MIGRATION, Actor(kind="session_proposal", actor_id="s")):
        with pytest.raises(MemoryValidationError) as excinfo:
            store.write_deletion_audit(
                record_id="c1", actor=denied, deleted_at=_LATER, tables_touched=()
            )
        assert denied.kind in str(excinfo.value)
    with pytest.raises(MemoryValidationError):
        store.write_deletion_audit(
            record_id="c1", actor=Actor(kind="robot", actor_id="x"), deleted_at=_LATER, tables_touched=()  # type: ignore[arg-type]
        )

    for kwargs in (
        {"record_id": "  ", "deleted_at": _LATER, "tables_touched": ()},
        {"record_id": "c1", "deleted_at": "yesterday", "tables_touched": ()},
        {"record_id": "c1", "deleted_at": _LATER, "tables_touched": (), "derived_removed": -1},
        {"record_id": "c1", "deleted_at": _LATER, "tables_touched": ["memory_record"]},
    ):
        with pytest.raises(MemoryValidationError):
            store.write_deletion_audit(actor=ADULT, **kwargs)  # type: ignore[arg-type]
    assert _count(store.path, "deletion_audit") == 0


# ---------------------------------------------------------------------------
# CRUD 组：到期扫描（TTL sweep 的枚举入口）
# ---------------------------------------------------------------------------


def test_list_expired_returns_only_records_with_a_due_action(tmp_path: Path) -> None:
    """两条路径各自的对象都要在，且**已确认的 SAFETY 类（``expires_at IS NULL``）不在**。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("active-due", expires_at="2026-09-25T00:00:00Z"), actor=ADULT)
    store.write_record(_confirmed("active-live", expires_at="2026-10-26T00:00:00Z"), actor=ADULT)
    store.write_record(_record("candidate-due", expires_at="2026-09-25T00:00:00Z"), actor=ADULT)
    store.write_record(_record("candidate-live"), actor=ADULT)
    store.write_record(
        _confirmed("safety-forever", memory_class="SAFETY", expires_at=None), actor=ADULT
    )
    # 已经 DECAYED 的记录没有到期动作可做（TTL 只管 ACTIVE → DECAYED 与候选硬删）。
    store.write_record(_confirmed("decayed", expires_at="2026-09-25T00:00:00Z"), actor=ADULT)
    store.transition(
        "decayed", "DECAYED", actor=TTL, updated_at=_WHEN, consent_version=2, last_confirmed_at=_WHEN
    )

    due = {record.id for record in store.list_expired(now=_WHEN)}
    assert due == {"active-due", "candidate-due"}


def test_list_expired_boundary_is_fail_closed(tmp_path: Path) -> None:
    """``expires_at <= now``（边界取 ``>=``）：正好到点也算到期。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("c1", expires_at=_WHEN), actor=ADULT)

    assert [record.id for record in store.list_expired(now=_WHEN)] == ["c1"]
    assert store.list_expired(now="2026-09-25T23:59:59Z") == ()


def test_list_expired_compares_instants_not_strings(tmp_path: Path) -> None:
    """``Z`` 与 ``+00:00`` / 带小数秒的写法字典序会给出错误答案，必须按时间点比较。"""

    store = _stored(tmp_path)
    store.write_record(
        _confirmed("c1", expires_at="2026-09-25T23:00:00+00:00"), actor=ADULT
    )
    store.write_record(_confirmed("c2", expires_at="2026-09-25T23:00:00.500Z"), actor=ADULT)

    assert [record.id for record in store.list_expired(now="2026-09-25T23:00:00Z")] == ["c1"]
    assert [record.id for record in store.list_expired(now="2026-09-25T23:00:01Z")] == ["c1", "c2"]


def test_list_expired_requires_a_trustworthy_clock(tmp_path: Path) -> None:
    """时钟不可解析 / 无时区一律拒绝 —— 时钟不可信时到期判定也不可信（§3.2）。"""

    store = _stored(tmp_path)
    store.write_record(_confirmed("c1"), actor=ADULT)

    with pytest.raises(MemoryValidationError):
        store.list_expired(now="")
    with pytest.raises(MemoryValidationError):
        store.list_expired(now="yesterday")
    with pytest.raises(MemoryValidationError):
        store.list_expired(now="2026-09-26T00:00:00")  # naive：不知道是不是 UTC


def test_list_expired_refuses_to_guess_on_corrupt_expiry(tmp_path: Path) -> None:
    """库内 ``expires_at`` 不可解析属数据损坏：报错，**不得**当成「已到期」删数据。"""

    store = _stored(tmp_path)
    store.write_record(_record("c1"), actor=ADULT)
    db = _raw(store.path)
    try:
        db.execute("UPDATE memory_record SET expires_at = 'not-a-timestamp' WHERE id = 'c1'")
        db.commit()
    finally:
        db.close()

    with pytest.raises(StoreError) as excinfo:
        store.list_expired(now=_WHEN)
    assert "expires_at" in str(excinfo.value)
    assert store.read_record("c1") is not None, "报错路径不得删除任何东西"


# ---------------------------------------------------------------------------
# CRUD 组：读路径不得校验（policy_denied 的反例必须读得出来）
# ---------------------------------------------------------------------------

def _without_check_expressions(ddl: str) -> str:
    """剥掉 DDL 里的 ``CHECK (...)``（括号配对扫描，能处理多层嵌套括号）。"""

    pieces: list[str] = []
    cursor = 0
    while True:
        found = ddl.find("CHECK", cursor)
        if found == -1:
            pieces.append(ddl[cursor:])
            break
        pieces.append(ddl[cursor:found])
        index = ddl.index("(", found)
        depth = 0
        while True:
            character = ddl[index]
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    index += 1
                    break
            index += 1
        cursor = index
    text = "".join(pieces)
    # 表级 CHECK 各自独占一行（前面带逗号）；整行被剥掉后会留下空的「只有逗号」的行。
    text = "\n".join(
        line for line in text.splitlines() if line.strip() not in {"", ","}
    )
    text = re.sub(r",(\s*)\)", r"\1)", text)  # 去掉最后一列后面的悬空逗号
    assert "CHECK" not in text
    return text


def _permissive_store(tmp_path: Path) -> SqliteMemoryStore:
    """建一个**剥掉 CHECK** 的库：版本 / 表 / 列都合格，但允许落违约行。

    真库有 CHECK 兜底，违约行进不来；而契约 §3.3 的 ``policy_denied`` 四种情形要求
    ``authorize()`` 能对**已经存在**的违约行报拒绝。这个库用来验证：读路径必须把违约行
    原样读出来交给判权，而不是在读的时候抛错。
    """

    target = tmp_path / "permissive" / "memory.db"
    target.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(target)
    try:
        for ddl in MEMORY_SCHEMA_DDL:
            statement = ddl
            if ddl.startswith("CREATE TABLE memory_record "):
                statement = _without_check_expressions(ddl)
            db.execute(statement)
        db.execute(f"PRAGMA user_version = {MEMORY_SCHEMA_VERSION}")
        db.commit()
    finally:
        db.close()
    os.chmod(target, 0o600)
    return SqliteMemoryStore(target)


@pytest.mark.parametrize(
    "record",
    [
        # policy_denied 情形 1：do_not_persist 行（DDL 排除该取值，库里出现即契约违规）
        _record("bad-policy", memory_policy="do_not_persist"),
        # 情形 2：未知策略
        _record("bad-unknown-policy", memory_policy="persist_maybe"),
        # 情形 3：status 与 memory_policy 不符
        _confirmed("bad-binding", memory_policy="candidate_only"),
    ],
)
def test_read_path_returns_contract_violating_rows_for_authorize_to_deny(
    tmp_path: Path, record: MemoryRecord
) -> None:
    store = _permissive_store(tmp_path)
    columns = [
        field.name
        for field in fields(MemoryRecord)
        if field.name not in {"audiences", "source_ids"}
    ]
    db = _raw(store.path)
    try:
        db.execute(
            f"INSERT INTO memory_record ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            tuple(getattr(record, column) for column in columns),
        )
        db.commit()
    finally:
        db.close()

    read_back = store.read_record(record.id)
    assert read_back is not None, "读路径不得因为契约违规而抛错或丢记录"
    assert read_back.memory_policy == record.memory_policy
    assert read_back.status == record.status
    # A12：裸插入的归属来自 SQL 里显式写的那两列（fresh DDL 无 DEFAULT）。
    assert (read_back.actor_kind, read_back.actor_id) == (
        record.actor_kind,
        record.actor_id,
    )
    assert [found.id for found in store.read_records((record.id,))] == [record.id]
    assert [found.id for found in store.resolve_provenance((record.id,))] == [record.id]


def test_queries_still_enforce_schema_version_on_a_permissive_library(tmp_path: Path) -> None:
    """放宽的只是 CHECK；版本 / 表 / 列的校验一条都不放松。"""

    store = _permissive_store(tmp_path)
    db = _raw(store.path)
    try:
        db.execute(f"PRAGMA user_version = {MEMORY_SCHEMA_VERSION + 1}")
        db.commit()
    finally:
        db.close()

    with pytest.raises(StoreError):
        store.read_record("anything")


# ---------------------------------------------------------------------------
# fixture 映射（契约 §8.1/§8.2）—— W1 负责的「补齐后的记录真的写得进库」
# ---------------------------------------------------------------------------

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "m2-memory-policy.synthetic.json"


def _completed_fixture_records() -> list[tuple[dict, MemoryRecord]]:
    """按契约 §8.1/§8.2 的补齐规则与归一化，把 fixture 记录补成 ``MemoryRecord``。

    **不发明取值**：``memory_class`` / ``source_type`` / ``confidence`` / ``importance`` /
    ``consent_version`` / ``source_ids`` / 时间戳 / ``audiences`` 全部照契约页的表补齐；
    ``expires_at`` 用 :meth:`RetentionPolicy.days_for` 算（这正是 W1 交付的保留期算术），
    未知 ``memory_class`` 会抛错而不是猜。
    """

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    evaluate_at = fixture["evaluate_at"]
    created = datetime.fromisoformat(evaluate_at.replace("Z", "+00:00"))
    retention = RetentionPolicy()

    completed: list[tuple[dict, MemoryRecord]] = []
    for raw in fixture["records"]:
        # 归一化登记 §8.2（三条）：
        # 1. mem-family-unapproved 的 status：ACTIVE → PENDING_CONFIRMATION；
        # 2. shared_approved → audiences（下面按布尔值展开）；
        # 3. mem-deleted 的 content := ''（墓碑不得携带正文，DDL 的 CHECK 要求）。
        status = "PENDING_CONFIRMATION" if raw["memory_policy"] == "candidate_only" else raw["status"]
        content = "" if status == "DELETED" else raw["content"]
        memory_class = "EVENT"  # §8.1 补齐值
        days = retention.days_for(memory_class, is_candidate=status == "PENDING_CONFIRMATION")
        expires_at = (
            None
            if days is None
            else (created + timedelta(days=days)).isoformat().replace("+00:00", "Z")
        )
        completed.append(
            (
                raw,
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
                    created_at=evaluate_at,
                    updated_at=evaluate_at,
                    last_confirmed_at=evaluate_at if status == "ACTIVE" else None,
                    expires_at=expires_at,
                    source_session_id=None,
                    status=status,
                    memory_policy=raw["memory_policy"],
                    audiences=(
                        frozenset({"family_all"}) if raw.get("shared_approved", False) else frozenset()
                    ),
                    consent_version=1,
                    source_ids=(),
                    # A12：§8.1 的补齐规则新增两条 —— fixture 记录没有 actor 可言，
                    # 补齐值取「执行这次导入的主体」（测试里就是 ADULT）。
                    actor_kind=ADULT.kind,
                    actor_id=ADULT.actor_id,
                ),
            )
        )
    return completed


def test_fixture_expiry_arithmetic_uses_the_frozen_retention_days() -> None:
    """§8.1 的 ``expires_at`` 三条规则必须由 ``RetentionPolicy.days_for`` 复现。"""

    records = {raw["id"]: record for raw, record in _completed_fixture_records()}
    assert records["mem-family-approved"].expires_at == "2026-10-24T12:00:00Z"  # evaluate_at + 30
    assert records["mem-private-a"].expires_at == "2026-10-24T12:00:00Z"
    assert (
        records["mem-family-unapproved"].expires_at == "2026-10-01T12:00:00Z"
    )  # evaluate_at + 7（候选期）
    assert records["mem-family-unapproved"].status == "PENDING_CONFIRMATION"  # 归一化登记
    assert records["mem-family-approved"].last_confirmed_at == "2026-09-24T12:00:00Z"
    assert records["mem-family-unapproved"].last_confirmed_at is None


def test_fixture_records_completed_by_the_contract_rules_are_writable(tmp_path: Path) -> None:
    """补齐后的记录必须**真的**过得了写入路径的 DDL 不变量（不只是纸上核对）。

    契约 §8.1 要求「补齐后的记录必须满足 DDL 的全部 CHECK」；契约测试只在算式上核对了
    六条不变量，这里把它落到真实库上：逐条 ``write_record`` + 读回比对。
    """

    store = _stored(tmp_path)
    for _raw, record in _completed_fixture_records():
        store.write_record(record, actor=ADULT)
        assert store.read_record(record.id) == record
    assert _count(store.path, "memory_record") == 5


def test_fixture_tombstone_uses_the_registered_content_normalization(tmp_path: Path) -> None:
    """§8.2 登记的第三条归一化：``mem-deleted`` 的 ``content := ''``。

    fixture 原文的 ``mem-deleted`` 带正文，而 DDL（阻塞 2）要求墓碑行的内容为空 ——
    归一化把正文清空之后，补齐记录才满足全部 CHECK。测试同时确认归一化**只清正文**，
    其余字段（含按补齐规则算出的 ``expires_at``）保持原样，并真的能落库。
    """

    raw, record = next(
        (raw, record)
        for raw, record in _completed_fixture_records()
        if raw["id"] == "mem-deleted"
    )
    assert raw["content"] != "", "fixture 原文确实带正文 —— 这就是归一化的触发条件"
    assert record.content == ""
    assert record.status == "DELETED"
    assert record.expires_at == "2026-10-24T12:00:00Z", "DELETED 行同样有期限（DDL CHECK 2）"

    store = _stored(tmp_path)
    store.write_record(record, actor=ADULT)
    stored = store.read_record("mem-deleted")
    assert stored == record
    assert stored.content == "" and stored.status == "DELETED"
