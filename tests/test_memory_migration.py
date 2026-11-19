"""M2.2 schema v3 迁移契约测试（W9 · 9-1）。

覆盖契约 §6 T9(a)–(f) 与 §10.2 的 ⑬⑭⑮（迁移与超长行那一格）：

- v1 库**一次走完** v1→v2→v3，``user_version == 3``（T9a）；
- 分段失败语义：v1→v2 失败 ⇒ 库仍是 **v1**；v2→v3 失败 ⇒ 库仍是 **v2**；
- v2→v3 的 **12 步法**：重建表**不静默删** ``memory_audience`` / ``memory_source`` 行
  （r3 的 [致命] 修正）；逐表行数相等 + 逐行 value 抽样相等（``content`` / ``actor_*``）；
  ``PRAGMA foreign_key_check`` 为空；迁移后一条共享记录的 ``audiences`` **端到端仍可读**；
- 既有超长行：不截断、不删除、标记为 1；``MigrationReport.over_length_count``；
- **写入边界表**（T9c）逐行：新记录、正文变更 / 不变、flag=1 的两个方向、
  双向伪造防护、``confirm_shared`` 对 flagged 行的拒绝。

**全部真跑 SQLite 临时库**（契约 §8.4：W9 不触发 adapter live gate，但迁移用例
「必须真跑 SQLite，不得用替身」）。

**为什么 v1 / v2 的表结构在这里逐字冻结**：它们是**历史形状**，不是生产 DDL 的投影。
若从 ``MEMORY_RECORD_DDL`` 反推 v2，生产 DDL 一改，「v2 库」就会跟着变 —— 那样这个文件
就再也测不出「老库能不能升上来」。
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soul_memory_kernel.memory.grants import SqliteGrantStore
from soul_memory_kernel.memory.model import (
    Actor,
    MemoryCorrection,
    MigrationReport,
    RetentionPolicy,
)
from soul_memory_kernel.memory.service import (
    IllegalTransition,
    MemoryService,
    MemoryValidationError,
)
from soul_memory_kernel.memory.store import (
    MEMORY_AUDIENCE_DDL,
    MEMORY_DELETION_AUDIT_DDL,
    MEMORY_GRANT_ACTION_DDL,
    MEMORY_GRANT_DDL,
    MEMORY_GRANT_RESOURCE_DDL,
    MEMORY_SCHEMA_VERSION,
    MEMORY_SOURCE_DDL,
    SqliteMemoryStore,
)
from soul_memory_kernel.soul.policy import SessionAccess

NOW = "2026-09-26T12:00:00Z"
ADULT = Actor(kind="adult_control_plane", actor_id="cli:adult")
TTL_ACTOR = Actor(kind="ttl_expiry", actor_id="ttl:sweeper")

#: v1 的 ``memory_record``（M2.1 原样：没有写入归属两列，也没有 ``content_over_length``）。
_V1_RECORD_DDL = """
CREATE TABLE memory_record (
    id                TEXT    PRIMARY KEY,
    owner_id          TEXT    NOT NULL,
    scope             TEXT    NOT NULL CHECK (scope IN ('FAMILY','PERSONAL','SAFETY')),
    memory_class      TEXT    NOT NULL CHECK (memory_class IN ('EVENT','PREFERENCE','SAFETY')),
    source_type       TEXT    NOT NULL CHECK (
                          source_type IN ('explicit_user','explicit_adult',
                                          'confirmed_candidate','auto_extracted')),
    source_member_id  TEXT    NULL,
    content           TEXT    NOT NULL,
    confidence        REAL    NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    importance        REAL    NOT NULL CHECK (importance >= 0.0 AND importance <= 1.0),
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL,
    last_confirmed_at TEXT    NULL,
    expires_at        TEXT    NULL,
    source_session_id TEXT    NULL,
    status            TEXT    NOT NULL CHECK (
                          status IN ('PENDING_CONFIRMATION','ACTIVE','DECAYED','DELETED')),
    memory_policy     TEXT    NOT NULL CHECK (memory_policy IN ('persist_confirmed','candidate_only')),
    consent_version   INTEGER NOT NULL CHECK (consent_version >= 1),
    CHECK (scope <> 'SAFETY' OR memory_class = 'SAFETY'),
    CHECK (expires_at IS NOT NULL
           OR (memory_class = 'SAFETY' AND status IN ('ACTIVE','DECAYED'))),
    CHECK (scope <> 'FAMILY' OR status <> 'ACTIVE' OR last_confirmed_at IS NOT NULL),
    CHECK (status = 'DELETED'
           OR (status = 'PENDING_CONFIRMATION' AND memory_policy = 'candidate_only')
           OR (status IN ('ACTIVE','DECAYED') AND memory_policy = 'persist_confirmed')),
    CHECK (status <> 'DELETED' OR content = '')
)
""".strip()

#: v2 的 ``memory_record``（A12 加了写入归属两列；仍没有 ``content_over_length``）。
_V2_RECORD_DDL = """
CREATE TABLE memory_record (
    id                TEXT    PRIMARY KEY,
    owner_id          TEXT    NOT NULL,
    scope             TEXT    NOT NULL CHECK (scope IN ('FAMILY','PERSONAL','SAFETY')),
    memory_class      TEXT    NOT NULL CHECK (memory_class IN ('EVENT','PREFERENCE','SAFETY')),
    source_type       TEXT    NOT NULL CHECK (
                          source_type IN ('explicit_user','explicit_adult',
                                          'confirmed_candidate','auto_extracted')),
    source_member_id  TEXT    NULL,
    content           TEXT    NOT NULL,
    confidence        REAL    NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    importance        REAL    NOT NULL CHECK (importance >= 0.0 AND importance <= 1.0),
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL,
    last_confirmed_at TEXT    NULL,
    expires_at        TEXT    NULL,
    source_session_id TEXT    NULL,
    status            TEXT    NOT NULL CHECK (
                          status IN ('PENDING_CONFIRMATION','ACTIVE','DECAYED','DELETED')),
    memory_policy     TEXT    NOT NULL CHECK (memory_policy IN ('persist_confirmed','candidate_only')),
    consent_version   INTEGER NOT NULL CHECK (consent_version >= 1),
    actor_kind        TEXT    NOT NULL DEFAULT 'migration' CHECK (
                          actor_kind IN ('adult_control_plane','session_proposal',
                                         'ttl_expiry','migration')),
    actor_id          TEXT    NOT NULL DEFAULT 'migration:v1->v2',
    CHECK (scope <> 'SAFETY' OR memory_class = 'SAFETY'),
    CHECK (expires_at IS NOT NULL
           OR (memory_class = 'SAFETY' AND status IN ('ACTIVE','DECAYED'))),
    CHECK (scope <> 'FAMILY' OR status <> 'ACTIVE' OR last_confirmed_at IS NOT NULL),
    CHECK (status = 'DELETED'
           OR (status = 'PENDING_CONFIRMATION' AND memory_policy = 'candidate_only')
           OR (status IN ('ACTIVE','DECAYED') AND memory_policy = 'persist_confirmed')),
    CHECK (status <> 'DELETED' OR content = '')
)
""".strip()

#: v1 / v2 共有的列（v3 比它多一个 ``content_over_length``）。
_V2_COLUMNS: tuple[str, ...] = (
    "id",
    "owner_id",
    "scope",
    "memory_class",
    "source_type",
    "source_member_id",
    "content",
    "confidence",
    "importance",
    "created_at",
    "updated_at",
    "last_confirmed_at",
    "expires_at",
    "source_session_id",
    "status",
    "memory_policy",
    "consent_version",
    "actor_kind",
    "actor_id",
)

#: v1 / v2 期就存在的六张表（v3 只新增 ``extraction_usage``）。
_V1_V2_OTHER_TABLES: tuple[str, ...] = (
    MEMORY_AUDIENCE_DDL,
    MEMORY_SOURCE_DDL,
    MEMORY_GRANT_DDL,
    MEMORY_GRANT_ACTION_DDL,
    MEMORY_GRANT_RESOURCE_DDL,
    MEMORY_DELETION_AUDIT_DDL,
)

OVER_LONG = "长" * 600
SHORT = "周五去露营"


# ---------------------------------------------------------------------------
# 临时库构造器：真的建出 v1 / v2 形状的库
# ---------------------------------------------------------------------------


def _new_db(path: Path) -> sqlite3.Connection:
    """建库连接。**0600**：store 会拒绝权限过宽的库文件（产品级约束，不用替身绕开）。"""

    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    path.chmod(0o600)
    return db


def _build_v1(path: Path) -> None:
    """建一个货真价实的 v1 库（7 张表、``user_version = 1``、一行记录）。"""

    with _new_db(path) as db:
        db.execute(_V1_RECORD_DDL)
        for ddl in _V1_V2_OTHER_TABLES:
            db.execute(ddl)
        db.execute(
            "INSERT INTO memory_record (id, owner_id, scope, memory_class, source_type, "
            "source_member_id, content, confidence, importance, created_at, updated_at, "
            "last_confirmed_at, expires_at, source_session_id, status, memory_policy, "
            "consent_version) VALUES ('mem-v1', 'adult_a', 'FAMILY', 'EVENT', "
            "'explicit_user', NULL, '迁移前就有的记录', 1.0, 0.5, ?, ?, ?, ?, NULL, "
            "'ACTIVE', 'persist_confirmed', 1)",
            (NOW, NOW, NOW, "2026-10-26T12:00:00Z"),
        )
        db.execute(
            "INSERT INTO memory_audience (record_id, audience_id) VALUES ('mem-v1', 'family_all')"
        )
        db.execute("PRAGMA user_version = 1")


def _record_values(**overrides: object) -> tuple:
    """v2 行的一整套值（未给的字段用确定性的默认值补齐）。"""

    values: dict[str, object] = {
        "id": "mem-x",
        "owner_id": "adult_a",
        "scope": "FAMILY",
        "memory_class": "EVENT",
        "source_type": "explicit_user",
        "source_member_id": None,
        "content": SHORT,
        "confidence": 1.0,
        "importance": 0.5,
        "created_at": NOW,
        "updated_at": NOW,
        "last_confirmed_at": NOW,
        "expires_at": "2026-10-26T12:00:00Z",
        "source_session_id": None,
        "status": "ACTIVE",
        "memory_policy": "persist_confirmed",
        "consent_version": 1,
        "actor_kind": "adult_control_plane",
        "actor_id": "cli:adult",
    }
    values.update(overrides)
    return tuple(values[column] for column in _V2_COLUMNS)


def _build_v2(path: Path, rows: tuple[dict, ...]) -> None:
    """建一个 v2 库并写入给定的行（``rows`` 是 ``_record_values`` 的 overrides 元组）。

    行按给定顺序写入；``audiences`` / ``source_ids`` 由各自的键单独补。
    """

    with _new_db(path) as db:
        db.execute(_V2_RECORD_DDL)
        for ddl in _V1_V2_OTHER_TABLES:
            db.execute(ddl)
        placeholders = ", ".join("?" for _ in _V2_COLUMNS)
        for overrides in rows:
            row = dict(overrides)
            db.execute(
                f"INSERT INTO memory_record ({', '.join(_V2_COLUMNS)}) VALUES ({placeholders})",
                _record_values(**row),
            )
            for audience in row.get("audiences", ("family_all",)):
                db.execute(
                    "INSERT INTO memory_audience (record_id, audience_id) VALUES (?, ?)",
                    (row["id"], audience),
                )
            for ordinal, source_id in enumerate(row.get("source_ids", ())):
                db.execute(
                    "INSERT INTO memory_source (record_id, source_id, ordinal) VALUES (?, ?, ?)",
                    (row["id"], source_id, ordinal),
                )
        db.execute("PRAGMA user_version = 2")


def _scalar(path: Path, sql: str, params: tuple = ()) -> object:
    with sqlite3.connect(path) as db:
        row = db.execute(sql, params).fetchone()
    return None if row is None else row[0]


def _counts(path: Path, tables: tuple[str, ...]) -> dict[str, int]:
    return {table: int(_scalar(path, f"SELECT COUNT(*) FROM {table}")) for table in tables}


def _rows(path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    with sqlite3.connect(path) as db:
        return db.execute(sql, params).fetchall()


def _service(path: Path) -> MemoryService:
    return MemoryService(
        store=SqliteMemoryStore(path),
        grants=SqliteGrantStore(path, clock=lambda: NOW),
        clock=lambda: NOW,
        retention=RetentionPolicy(),
    )


# ---------------------------------------------------------------------------
# ① v1 → v2 → v3 一次走完
# ---------------------------------------------------------------------------


def test_v1_database_migrates_all_the_way_to_v3_in_one_open(tmp_path: Path) -> None:
    """T9a：v1 库在打开时**一次走完** v1→v2→v3（两段各自一个事务）。"""

    db_path = tmp_path / "memory.sqlite3"
    _build_v1(db_path)
    assert _scalar(db_path, "PRAGMA user_version") == 1

    store = SqliteMemoryStore(db_path)
    report = store.create_schema()

    assert _scalar(db_path, "PRAGMA user_version") == MEMORY_SCHEMA_VERSION == 3
    assert isinstance(report, MigrationReport)
    # 报告如实描述「打开时这个库处在什么版本」，而不是「产生报告的那一段」。
    assert (report.from_version, report.to_version) == (1, 3)
    assert report.over_length_count == 0

    # v1 → v2 的加法仍然生效：既有行如实归属为迁移来源。
    assert _rows(db_path, "SELECT actor_kind, actor_id, content_over_length FROM memory_record") == [
        ("migration", "migration:v1->v2", 0)
    ]
    # v3 的两件事都到位：新列 + extraction_usage 表。
    columns = {row[1] for row in _rows(db_path, "PRAGMA table_info(memory_record)")}
    assert "content_over_length" in columns
    assert _scalar(
        db_path, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='extraction_usage'"
    ) == 1
    # 第二次打开是 no-op（幂等），不再产生报告。
    assert SqliteMemoryStore(db_path).create_schema() is None


def test_v1_to_v2_failure_leaves_the_database_at_v1(tmp_path: Path) -> None:
    """T9a：``v1 → v2`` 失败 ⇒ 库**仍是 v1**（该段整体回滚，第二个事务根本不开始）。

    注入方式与既有 A2 用例同源：预置一列 ``actor_id``，让第二条 ``ALTER`` 撞
    ``duplicate column name``。第一次 ``ALTER``（``actor_kind``）必须跟着回滚。
    """

    from soul_memory_kernel.memory.service import StoreError

    db_path = tmp_path / "memory.sqlite3"
    _build_v1(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE memory_record ADD COLUMN actor_id TEXT NOT NULL DEFAULT 'x'")

    with pytest.raises(StoreError):
        SqliteMemoryStore(db_path).create_schema()

    assert _scalar(db_path, "PRAGMA user_version") == 1, "失败后版本号必须还是 1"
    columns = {row[1] for row in _rows(db_path, "PRAGMA table_info(memory_record)")}
    assert "actor_kind" not in columns, "第一条 ALTER 必须一起回滚"
    assert "content_over_length" not in columns, "第二个事务根本不该开始"
    assert _scalar(
        db_path, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='extraction_usage'"
    ) == 0, "v2→v3 的表不该出现"


def test_v2_to_v3_failure_leaves_the_database_at_v2_and_rows_intact(tmp_path: Path) -> None:
    """T9a：``v2 → v3`` 失败 ⇒ 库**仍是 v2**，且行数与迁移前相等。

    注入方式：预置一张同名暂存表 ``memory_record__v3``，让步骤 3 的
    ``CREATE TABLE memory_record__v3`` 撞 ``already exists``。
    """

    from soul_memory_kernel.memory.service import StoreError

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {"id": "mem-a"},
            {"id": "mem-b", "content": OVER_LONG, "expires_at": "2026-10-26T12:00:00Z"},
        ),
    )
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE memory_record__v3 (bogus TEXT)")
    before = _counts(db_path, ("memory_record", "memory_audience", "memory_source", "grant_resource"))

    with pytest.raises(StoreError):
        SqliteMemoryStore(db_path).create_schema()

    assert _scalar(db_path, "PRAGMA user_version") == 2, "失败后版本号必须还是 2"
    assert _counts(
        db_path, ("memory_record", "memory_audience", "memory_source", "grant_resource")
    ) == before
    # 依然是 v2 形状：新列不该出现，重建也没发生。
    columns = {row[1] for row in _rows(db_path, "PRAGMA table_info(memory_record)")}
    assert "content_over_length" not in columns
    assert sorted(
        row[0]
        for row in _rows(db_path, "SELECT content FROM memory_record ORDER BY id")
    ) == sorted([SHORT, OVER_LONG])


def test_v2_to_v3_aborts_loudly_on_pre_existing_orphan_rows(tmp_path: Path) -> None:
    """T9b 步骤 9 / R13：库里本来就有孤儿行 ⇒ 迁移**响亮地**失败，库停在 v2。

    错误里给**违规表名 + 行数**，不含正文；**不静默清理孤儿行**
    （在人家的记忆库上顺手删几行比拒绝打开更糟）。
    """

    from soul_memory_kernel.memory.service import StoreError

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(db_path, ({"id": "mem-a"},))
    # 历史遗留：有进程在 FK 关闭时写过一行指向不存在记录的受众行。
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA foreign_keys = OFF")
        db.execute(
            "INSERT INTO memory_audience (record_id, audience_id) VALUES ('mem-ghost', 'family_all')"
        )

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(db_path).create_schema()

    message = str(excinfo.value)
    assert "memory_audience" in message, "错误必须点名违规表"
    assert "1 orphan row" in message, "错误必须给出违规行数"
    assert SHORT not in message, "错误不得回显任何正文"
    assert _scalar(db_path, "PRAGMA user_version") == 2
    # 孤儿行原样留着 —— 迁移不替用户删数据。
    assert _scalar(
        db_path, "SELECT COUNT(*) FROM memory_audience WHERE record_id = 'mem-ghost'"
    ) == 1


# ---------------------------------------------------------------------------
# ② 行数与取值保真（N1：错列会静默写坏 actor_*）
# ---------------------------------------------------------------------------


def test_migration_preserves_every_row_and_the_actor_columns(tmp_path: Path) -> None:
    """T9b 的测试口径：四张表行数逐表相等 + **逐行 value 抽样相等**。

    行数相等抓不到错列映射，所以逐行比对 ``content`` 与 ``actor_kind`` / ``actor_id``
    （r4 按 A 的 N1 补）。夹具里刻意让 ``actor_id`` 取到与 ``content_over_length``
    同域的值（``'1'`` / ``'0'``）—— ``SELECT *, CASE …`` 的错列写法正是把它们写成 1/0。
    """

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {"id": "mem-1", "actor_kind": "adult_control_plane", "actor_id": "cli:adult"},
            {"id": "mem-2", "actor_kind": "migration", "actor_id": "migration:v1->v2"},
            {"id": "mem-3", "actor_kind": "ttl_expiry", "actor_id": "ttl:sweeper"},
            {"id": "mem-4", "content": OVER_LONG, "actor_id": "0"},
        ),
    )
    tables = ("memory_record", "memory_audience", "memory_source", "grant_resource")
    before_counts = _counts(db_path, tables)
    before_values = _rows(
        db_path,
        "SELECT id, content, actor_kind, actor_id, owner_id, status, consent_version "
        "FROM memory_record ORDER BY id",
    )

    SqliteMemoryStore(db_path).create_schema()

    assert _counts(db_path, tables) == before_counts, "逐表行数必须相等（级联删会在这里现形）"
    after_values = _rows(
        db_path,
        "SELECT id, content, actor_kind, actor_id, owner_id, status, consent_version "
        "FROM memory_record ORDER BY id",
    )
    assert after_values == before_values, "逐行 value 抽样必须相等（错列会在这里现形）"
    assert _rows(db_path, "PRAGMA foreign_key_check") == []


def test_audiences_of_a_shared_record_still_read_end_to_end_after_migration(
    tmp_path: Path,
) -> None:
    """迁移后一条共享记录的 ``audiences`` **端到端仍可读**（不只比行数）。

    若 ``DROP TABLE`` 在 FK 打开时级联删掉了受众行，这一条会以 ``scope_denied`` 现形 ——
    那正是 R12 说的「家人所有已确认记忆静默不可召回」。
    """

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(db_path, ({"id": "mem-shared", "content": "对花生过敏"},))

    SqliteMemoryStore(db_path).create_schema()

    record = SqliteMemoryStore(db_path).read_record("mem-shared")
    assert record is not None and record.audiences == frozenset({"family_all"})

    snapshot = _service(db_path).query(
        SessionAccess(),
        "session_projection",
        session_id="sess-1",
        audience_id="family_all",
        grant=None,
    )
    assert snapshot.record_ids == ("mem-shared",)
    assert snapshot.entries[0].content == "对花生过敏"
    assert snapshot.denied == ()


# ---------------------------------------------------------------------------
# ③ 既有超长行：不截断、不删除、标记为 1
# ---------------------------------------------------------------------------


def _migrated_over_length_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {"id": "mem-short"},
            {"id": "mem-long", "content": OVER_LONG, "audiences": ("family_all",)},
        ),
    )
    store = SqliteMemoryStore(db_path)
    report = store.create_schema()
    assert report is not None
    assert report.over_length_count == 1
    return db_path


def test_historical_over_length_rows_are_kept_and_flagged(tmp_path: Path) -> None:
    """T9c：600 字历史行**原样保留**、``content_over_length = 1``，计数两个面都可读。"""

    db_path = _migrated_over_length_db(tmp_path)

    assert _rows(db_path, "SELECT id, length(content), content_over_length FROM memory_record ORDER BY id") == [
        ("mem-long", 600, 1),
        ("mem-short", len(SHORT), 0),
    ]
    assert SqliteMemoryStore(db_path).count_over_length() == 1


def test_over_length_count_is_reported_and_visible_without_content(tmp_path: Path) -> None:
    """R10a：``MigrationReport`` 是**纯返回值** —— 只有计数，没有正文、没有 id。"""

    db_path = _migrated_over_length_db(tmp_path)
    report = SqliteMemoryStore(db_path).create_schema()
    # 已经迁完：不再产生报告；权威的实时可见面是 count_over_length()。
    assert report is None
    store = SqliteMemoryStore(db_path)
    store.create_schema()
    assert store.migration_report is None
    assert store.count_over_length() == 1


# ---------------------------------------------------------------------------
# ④ 写入边界表（T9c）
# ---------------------------------------------------------------------------


def test_new_writes_cannot_exceed_the_content_cap(tmp_path: Path) -> None:
    """新记录：正文必须 ≤500（store 层硬拒，不再只是 service 层的事）。"""

    from soul_memory_kernel.memory.model import MemoryRecord

    db_path = tmp_path / "memory.sqlite3"
    store = SqliteMemoryStore(db_path)
    store.create_schema()
    assert store.read_record("mem-new") is None  # 库是空的

    fresh = MemoryRecord(
        id="mem-new",
        owner_id="adult_a",
        scope="FAMILY",
        memory_class="EVENT",
        source_type="explicit_user",
        source_member_id=None,
        content="超" * 501,
        confidence=1.0,
        importance=0.5,
        created_at=NOW,
        updated_at=NOW,
        last_confirmed_at=None,
        expires_at="2026-10-26T12:00:00Z",
        source_session_id=None,
        status="PENDING_CONFIRMATION",
        memory_policy="candidate_only",
        audiences=frozenset({"family_all"}),
        consent_version=1,
    )
    with pytest.raises(MemoryValidationError):
        store.write_record(fresh, actor=ADULT)
    assert _scalar(db_path, "SELECT COUNT(*) FROM memory_record") == 0


def test_write_record_rejects_a_501_character_record_and_a_forged_flag(tmp_path: Path) -> None:
    """store 层：501 字被拒；**凭空标 1** 也被拒（双向伪造防护的第一向）。"""

    from dataclasses import replace as _replace

    db_path = tmp_path / "memory.sqlite3"
    record = _propose_via_service(_service(db_path), "短" * 500)
    assert record.content_over_length == 0

    store = SqliteMemoryStore(db_path)
    with pytest.raises(MemoryValidationError):
        store.write_record(
            _replace(record, content="长" * 501, content_over_length=0), actor=ADULT
        )
    with pytest.raises(MemoryValidationError):
        # 正文变更到 600 字：派生值获胜（声明被忽略）**不等于**放宽长度 —— 超长正文照样拒。
        store.write_record(
            _replace(record, content="长" * 600, content_over_length=1), actor=ADULT
        )
    with pytest.raises(MemoryValidationError):
        # 正文没超长却自称 flag=1：正文不变时的伪造方向，直接拒（无中生有）。
        store.write_record(
            _replace(record, content="短" * 500, content_over_length=1), actor=ADULT
        )
    assert (
        _scalar(db_path, "SELECT content_over_length FROM memory_record WHERE id = ?", (record.id,))
        == 0
    )


def _propose_via_service(service: MemoryService, content: str):
    """通过服务写一条普通候选并返回它（测试辅助；状态是候选，未确认）。"""

    from soul_memory_kernel.memory.model import MemoryCandidate, SourceSession

    return service.propose(
        MemoryCandidate(
            content=content,
            scope="FAMILY",
            memory_class="EVENT",
            owner_id="adult_a",
            source_type="explicit_user",
            source_member_id=None,
            confidence=1.0,
            importance=0.5,
            audiences=frozenset({"family_all"}),
        ),
        SourceSession(
            session_id="sess-1",
            owner_id=None,
            audience_id="family_all",
            session_mode="shared",
            identity_assurance="unknown",
            grant_id=None,
        ),
    )


def test_content_unchanged_writes_keep_the_flag_and_content_changes_clear_it(
    tmp_path: Path,
) -> None:
    """T9c 的核心两行：**正文不变的写放行且保持 1**；**正文变更必须 ≤500 并把标记清零**。"""

    db_path = _migrated_over_length_db(tmp_path)
    service = _service(db_path)

    # 正文不变（只改 importance）：成功，标记保持 1。
    kept = service.correct("mem-long", MemoryCorrection(importance=0.9), ADULT)
    assert kept.content_over_length == 1
    assert kept.importance == 0.9
    assert kept.content == OVER_LONG, "历史超长正文不得被截断"

    # 正文变更到 ≤500：这就是**修复路径**，标记自动清零（不需要回退旧二进制）。
    fixed = service.correct("mem-long", MemoryCorrection(content="孩子对花生过敏"), ADULT)
    assert fixed.content_over_length == 0
    assert _scalar(db_path, "SELECT content_over_length FROM memory_record WHERE id = 'mem-long'") == 0

    # 再改长到 501：现在没有豁免了，拒绝。
    with pytest.raises(MemoryValidationError):
        service.correct("mem-long", MemoryCorrection(content="长" * 501), ADULT)


def test_clearing_the_flag_without_changing_the_content_is_rejected(tmp_path: Path) -> None:
    """双向伪造防护的第二向：**正文不变时清掉 1** 必须被拒（否则是掩盖历史超长行）。"""

    from dataclasses import replace as _replace

    db_path = _migrated_over_length_db(tmp_path)
    store = SqliteMemoryStore(db_path)
    record = store.read_record("mem-long")
    assert record is not None and record.content_over_length == 1

    with pytest.raises(MemoryValidationError):
        store.write_record(_replace(record, content_over_length=0), actor=ADULT)
    assert _scalar(
        db_path, "SELECT content_over_length FROM memory_record WHERE id = 'mem-long'"
    ) == 1, "被拒的写不得改动任何行"


def test_flagged_candidate_can_only_be_deleted_or_left_to_expire(tmp_path: Path) -> None:
    """T9c：**flagged 候选** confirm 被拒、correct 是 ``IllegalTransition``、delete 成功。"""

    db_path = tmp_path / "memory.sqlite3"
    candidate_expiry = (datetime(2026, 9, 26, 12, tzinfo=UTC) + timedelta(days=7)).isoformat().replace(
        "+00:00", "Z"
    )
    _build_v2(
        db_path,
        (
            {
                "id": "mem-flagged-candidate",
                "content": OVER_LONG,
                "status": "PENDING_CONFIRMATION",
                "memory_policy": "candidate_only",
                "last_confirmed_at": None,
                "expires_at": candidate_expiry,
                "audiences": ("family_all",),
            },
        ),
    )
    assert SqliteMemoryStore(db_path).create_schema().over_length_count == 1
    service = _service(db_path)

    with pytest.raises(MemoryValidationError):
        service.confirm_shared("mem-flagged-candidate", frozenset({"family_all"}), ADULT)
    with pytest.raises(IllegalTransition):
        service.correct(
            "mem-flagged-candidate", MemoryCorrection(content="改短"), actor=ADULT
        )
    assert _scalar(
        db_path, "SELECT status FROM memory_record WHERE id = 'mem-flagged-candidate'"
    ) == "PENDING_CONFIRMATION"

    report = service.delete("mem-flagged-candidate", ADULT)
    assert report.record_ids == ("mem-flagged-candidate",)
    assert _scalar(
        db_path, "SELECT COUNT(*) FROM memory_record WHERE id = 'mem-flagged-candidate'"
    ) == 0
    assert SqliteMemoryStore(db_path).count_over_length() == 0


def test_flagged_active_record_cannot_be_confirmed_either(tmp_path: Path) -> None:
    """契约 T9c 末段没有为 actives 开例外：flagged 行**一律**不得确认。"""

    db_path = _migrated_over_length_db(tmp_path)
    service = _service(db_path)
    with pytest.raises(MemoryValidationError):
        service.confirm_shared("mem-long", frozenset({"family_all"}), ADULT)


def test_flagged_row_can_still_be_swept_by_the_ttl_actor(tmp_path: Path) -> None:
    """迁移不改变 TTL 语义：flagged 的 ACTIVE 记录到期照常转 ``DECAYED``。"""

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {
                "id": "mem-expired-long",
                "content": OVER_LONG,
                "expires_at": "2026-09-25T00:00:00Z",
            },
        ),
    )
    SqliteMemoryStore(db_path).create_schema()
    service = _service(db_path)

    results = service.sweep_expired(TTL_ACTOR)

    assert [record.status for record in results] == ["DECAYED"]  # type: ignore[union-attr]
    assert _scalar(
        db_path, "SELECT content_over_length FROM memory_record WHERE id = 'mem-expired-long'"
    ) == 1, "TTL 迁移不是正文变更，标记必须保持"


def test_ttl_sweep_hard_deletes_an_expired_flagged_candidate(tmp_path: Path) -> None:
    """flagged 候选的另一条出路：7 天候选期到 ⇒ TTL 硬删（契约 T9c 明列）。"""

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {
                "id": "mem-stale-candidate",
                "content": OVER_LONG,
                "status": "PENDING_CONFIRMATION",
                "memory_policy": "candidate_only",
                "last_confirmed_at": None,
                "expires_at": "2026-09-25T00:00:00Z",
            },
        ),
    )
    SqliteMemoryStore(db_path).create_schema()
    service = _service(db_path)

    results = service.sweep_expired(TTL_ACTOR)

    assert len(results) == 1
    assert _scalar(db_path, "SELECT COUNT(*) FROM memory_record") == 0
    assert _scalar(db_path, "SELECT COUNT(*) FROM deletion_audit") == 1


def test_write_boundary_table_is_enforced_on_the_store_not_only_the_service(
    tmp_path: Path,
) -> None:
    """DDL 与 Python 校验同口径：绕过 ``write_record`` 直接写，SQLite 也不放行超长正文。

    这一条用一个**绕过 ``write_record``** 的裸 UPDATE 证明表级 CHECK 真的落在库里 ——
    否则「500 字上限下沉到 store」只是服务层的一句承诺。

    **边界说明**：DDL 能表达的是「``flag = 1`` 或 ``length ≤ 500``」。它**表达不了**
    「这一行**历史上**就超长」—— 凭空把 ``flag`` 标成 1 这件事只有 Python 侧的
    ``write_record`` 能判（它看得见迁移前的正文），见上面两条伪造防护用例。
    两者的分工就是 T9c 的「DDL 同口径 + 双向伪造防护」两句话。
    """

    db_path = _migrated_over_length_db(tmp_path)
    with sqlite3.connect(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "UPDATE memory_record SET content = ? WHERE id = 'mem-short'", ("长" * 501,)
            )
    assert _scalar(db_path, "SELECT length(content) FROM memory_record WHERE id = 'mem-short'") == len(
        SHORT
    ), "被 CHECK 拒绝的写不得改动任何行"


def test_reassign_owner_on_a_flagged_candidate_keeps_the_flag(tmp_path: Path) -> None:
    """T9c × T26'：``reassign_owner`` 是**正文不变的写** ⇒ flagged 行上成功且标记保持 1。

    它同时说明 T9c 的「只在 content 变更时才强制清零」不是一句口号：
    归属变更（``confirm`` 前的那一步）不会被历史超长标记挡住，而 ``confirm`` 本身仍被拒 ——
    这正是契约要的修复顺序（flagged 候选只能 delete / 等 TTL，与归属变更无关）。
    """

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(
        db_path,
        (
            {
                "id": "mem-flagged-shared",
                "content": OVER_LONG,
                "status": "PENDING_CONFIRMATION",
                "memory_policy": "candidate_only",
                "last_confirmed_at": None,
                "expires_at": "2026-10-03T12:00:00Z",
                "owner_id": "family_shared",
                "audiences": ("family_all",),
            },
        ),
    )
    assert SqliteMemoryStore(db_path).create_schema().over_length_count == 1
    service = _service(db_path)

    moved = service.reassign_owner("mem-flagged-shared", "adult_b", actor=ADULT)

    assert moved.owner_id == "adult_b"
    assert moved.content_over_length == 1, "正文不变 ⇒ 标记必须保持"
    assert moved.content == OVER_LONG, "历史超长正文不得被截断"
    assert moved.consent_version == 2
    assert _rows(
        db_path,
        "SELECT owner_id, content_over_length, length(content) FROM memory_record",
    ) == [("adult_b", 1, 600)]

    # 归属定好了，但它仍然不能被确认（T9c 的前置校验）。
    with pytest.raises(MemoryValidationError):
        service.confirm_shared("mem-flagged-shared", frozenset({"family_all"}), ADULT)


# ---------------------------------------------------------------------------
# ⑤ 收尾轮：审阅 A 建议 1(b) 与建议 2
# ---------------------------------------------------------------------------


def test_a_rewritten_content_lets_the_derived_flag_win(tmp_path: Path) -> None:
    """审阅 A 建议 1 取 (b)：**正文变更时派生值获胜，调用方声明的值被忽略**。

    这一列是派生列：正文改了，旧标记就自动作废，没有被「沿用」的语义。因此
    「拿一条 flagged 记录、只替换正文、忘了改声明值」这条厂外 API 捷径**不再报错** ——
    它落库的结果与显式清零完全一致。两个伪造方向（下文两条用例）不受影响。
    """

    from dataclasses import replace as _replace

    db_path = _migrated_over_length_db(tmp_path)
    store = SqliteMemoryStore(db_path)
    flagged = store.read_record("mem-long")
    assert flagged is not None and flagged.content_over_length == 1

    # 正文改短但**沿用**旧记录里的 flag=1：派生值（0）获胜。
    store.write_record(_replace(flagged, content="孩子对花生过敏"), actor=ADULT)

    assert _rows(
        db_path, "SELECT content, content_over_length FROM memory_record WHERE id = 'mem-long'"
    ) == [("孩子对花生过敏", 0)]
    assert SqliteMemoryStore(db_path).count_over_length() == 0


def test_a_fresh_record_may_not_claim_the_over_length_flag(tmp_path: Path) -> None:
    """审阅 A 建议 1 的边界：**新记录**仍然不能凭空声明 ``flag=1``（伪造方向之一）。"""

    from dataclasses import replace as _replace

    db_path = tmp_path / "memory.sqlite3"
    record = _propose_via_service(_service(db_path), SHORT)
    store = SqliteMemoryStore(db_path)

    # 同一条记录、同样的正文，但库里还没有它 —— 这就是「新记录」：声明 1 必须被拒。
    with pytest.raises(MemoryValidationError):
        store.write_record(
            _replace(record, id="mem-brand-new", content_over_length=1), actor=ADULT
        )
    assert _scalar(db_path, "SELECT COUNT(*) FROM memory_record WHERE id = 'mem-brand-new'") == 0


def test_a_rewritten_content_still_may_not_exceed_the_cap(tmp_path: Path) -> None:
    """派生值获胜**不等于**放宽长度：正文变更后的新正文仍必须 ≤500（T9c 第 4 行）。"""

    from dataclasses import replace as _replace

    db_path = _migrated_over_length_db(tmp_path)
    store = SqliteMemoryStore(db_path)
    flagged = store.read_record("mem-long")
    assert flagged is not None

    for declared in (0, 1, flagged.content_over_length):
        with pytest.raises(MemoryValidationError):
            store.write_record(
                _replace(flagged, content="长" * 501, content_over_length=declared), actor=ADULT
            )
    assert _scalar(
        db_path, "SELECT length(content) FROM memory_record WHERE id = 'mem-long'"
    ) == 600, "被拒的写不得改动任何行"


def test_migration_refuses_to_drop_an_unexpected_column(tmp_path: Path) -> None:
    """审阅 A 建议 2：v2 库多出一列 ⇒ **点名报错 + 回滚**，不静默丢列。

    重建表只按 ``_RECORD_COLUMNS`` 拷贝，因此「多出来的列」在旧实现下会连同数据
    一起消失（迁移报成功）。这与整条迁移纪律相悖 —— 宁可响亮失败，不静默丢数据。
    """

    from soul_memory_kernel.memory.service import StoreError

    db_path = tmp_path / "memory.sqlite3"
    _build_v2(db_path, ({"id": "mem-a"}, {"id": "mem-b"}))
    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE memory_record ADD COLUMN vendor_tag TEXT NOT NULL DEFAULT 'kept'")
    before = _counts(db_path, ("memory_record", "memory_audience"))

    with pytest.raises(StoreError) as excinfo:
        SqliteMemoryStore(db_path).create_schema()

    message = str(excinfo.value)
    assert "vendor_tag" in message, "错误必须点名多出来的列"
    assert "still at v2" in message
    assert SHORT not in message, "错误不得回显任何正文"
    assert _scalar(db_path, "PRAGMA user_version") == 2, "库里仍是 v2"
    assert _counts(db_path, ("memory_record", "memory_audience")) == before
    # 那一列**连同它的值**原样留着 —— 迁移不替用户丢数据，也不替用户删列。
    assert _rows(db_path, "SELECT DISTINCT vendor_tag FROM memory_record") == [("kept",)]
    assert "content_over_length" not in {
        row[1] for row in _rows(db_path, "PRAGMA table_info(memory_record)")
    }

    # 用户手工把那一列去掉之后，迁移照常成功（失败不是永久性的）。
    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE memory_record DROP COLUMN vendor_tag")
    report = SqliteMemoryStore(db_path).create_schema()
    assert report is not None and report.to_version == 3
    assert _rows(db_path, "SELECT COUNT(*) FROM memory_record") == [(2,)]
