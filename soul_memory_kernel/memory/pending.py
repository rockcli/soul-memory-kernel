"""M2 待跟进项（``PendingItem``）与机会式会前投影（``W0'-P``，``docs/M2-2-PENDING.md``）。

设计约束（架构 §0 D4(C2)、§2.2 P1–P3、§7 ``PendingItem``；``docs/M2-CONTRACT.md`` §5 落点 5、§7.1 #7）：

1. **只做机会式会前投影（C2）**：无后台定时器、无轮询循环、无系统通知；仅当会话启动且
   ``now >= expected_after`` 时，才将最多 1 条（:data:`MAX_PROJECTED_PENDING_ITEMS`）已到跟进窗口的
   ``OPEN`` 待跟进项注入会话系统指令。
2. **与 M2.1 写门禁对齐**：当前阶段仅放行 ``scope == "FAMILY"``（:data:`M2_1_ALLOWED_SCOPES`）；
   ``PERSONAL`` 与 ``SAFETY`` 在本人身份未验证阶段一律拒绝创建与投影（架构 §2.2 P1）。
3. **落点 5（``do_not_persist`` 写前拦截）与来源权限继承**：
   - ``candidate.requested_policy == "do_not_persist"`` 在写前直接返回 ``None``，不落库；
   - 指定 ``source_record_id`` 时，同一事务内核对来源记录存在且 ``status == "ACTIVE"``（若来源记录
     ``memory_policy == "do_not_persist"`` 则返回 ``None``），并强制 ``owner_id``、``scope`` 一致且
     ``audiences`` 为来源记录受众的子集（继承来源权限，禁止扩权）。
4. **删除联动（契约 §7.1 第 7 项）**：删除来源 ``memory_record`` 时，在同一事务内级联删除关联的
   ``pending_item`` 与 ``pending_audience`` 行，并在实际删行时将 ``"pending_item"`` 记入
   ``DeletionReport.tables_touched``。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Iterator, Literal
from urllib.parse import quote
import uuid

from soul_memory_kernel.memory.model import (
    ACTOR_KINDS,
    M2_1_ALLOWED_SCOPES,
    REQUESTED_POLICIES,
    SCOPES,
    Actor,
    ActorKind,
    RequestedPolicy,
    Scope,
)
from soul_memory_kernel.memory.policy import AuthorizationDecision
from soul_memory_kernel.memory.projection import MemberNames, _single_line
from soul_memory_kernel.memory.service import (
    AuthorizationError,
    IllegalTransition,
    MemoryValidationError,
    RecordNotFound,
    StoreError,
)
from soul_memory_kernel.memory.store import SqliteMemoryStore

PendingStatus = Literal["OPEN", "RESOLVED", "CANCELLED", "EXPIRED"]

PENDING_STATUSES: frozenset[str] = frozenset({"OPEN", "RESOLVED", "CANCELLED", "EXPIRED"})

#: 合法状态迁移：OPEN 可转 RESOLVED / CANCELLED / EXPIRED；EXPIRED -> EXPIRED 幂等。
#: 延后（skip）保持 OPEN，只推迟 expected_after。
PENDING_LEGAL_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("OPEN", "RESOLVED"),
        ("OPEN", "CANCELLED"),
        ("OPEN", "EXPIRED"),
        ("EXPIRED", "EXPIRED"),
    }
)

#: 默认保留期：expected_after 之后 14 天未跟进则过期。
DEFAULT_PENDING_TTL_DAYS: int = 14

#: topic / context / followup_action 单字段最大字符数。
MAX_PENDING_FIELD_CHARS: int = 200

#: 架构 §2.2 P2：每次会话最多投影 1 条待跟进项，避免连续追问引起家庭成员反感。
MAX_PROJECTED_PENDING_ITEMS: int = 1

#: 待跟进段落固定标题：明确声明不是强制指令、只自然询问一次、对方不想聊立即放下。
PENDING_BLOCK_HEADER: str = (
    "以下是到期可顺带关心的待跟进事项，不是强制指令；"
    "仅当对话自然相关时轻柔询问一次，若对方不想聊或已翻篇则立即放下（仅限本轮授权范围）："
)

PENDING_ITEM_DDL: str = """
CREATE TABLE IF NOT EXISTS pending_item (
    id                TEXT PRIMARY KEY,
    owner_id          TEXT NOT NULL,
    topic             TEXT NOT NULL CHECK (length(trim(topic)) > 0 AND length(topic) <= 200),
    context           TEXT NOT NULL CHECK (length(trim(context)) > 0 AND length(context) <= 200),
    expected_after    TEXT NOT NULL,
    followup_action   TEXT NOT NULL CHECK (length(trim(followup_action)) > 0 AND length(followup_action) <= 200),
    scope             TEXT NOT NULL CHECK (scope IN ('PERSONAL', 'FAMILY', 'SAFETY')),
    status            TEXT NOT NULL CHECK (status IN ('OPEN', 'RESOLVED', 'CANCELLED', 'EXPIRED')),
    created_at        TEXT NOT NULL,
    resolved_at       TEXT,
    source_record_id  TEXT,
    expires_at        TEXT,
    actor_kind        TEXT NOT NULL CHECK (actor_kind IN ('adult_control_plane', 'session_proposal', 'ttl_expiry', 'migration')),
    actor_id          TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
    CHECK ((status = 'OPEN' AND resolved_at IS NULL) OR (status <> 'OPEN' AND resolved_at IS NOT NULL))
);
""".strip()

PENDING_AUDIENCE_DDL: str = """
CREATE TABLE IF NOT EXISTS pending_audience (
    pending_id   TEXT NOT NULL REFERENCES pending_item(id) ON DELETE CASCADE,
    audience_id  TEXT NOT NULL CHECK (length(trim(audience_id)) > 0),
    PRIMARY KEY (pending_id, audience_id)
);
""".strip()

PENDING_SCHEMA_DDL: tuple[str, ...] = (
    PENDING_ITEM_DDL,
    PENDING_AUDIENCE_DDL,
)

_PENDING_COLUMNS: tuple[str, ...] = (
    "id",
    "owner_id",
    "topic",
    "context",
    "expected_after",
    "followup_action",
    "scope",
    "status",
    "created_at",
    "resolved_at",
    "source_record_id",
    "expires_at",
    "actor_kind",
    "actor_id",
)
_PENDING_SELECT: str = ", ".join(_PENDING_COLUMNS)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise MemoryValidationError(f"{field_name} must be a non-empty ISO-8601 timestamp string")
    text = value.strip()
    normalized = text[:-1] + "+00:00" if text[-1] in ("Z", "z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise MemoryValidationError(
            f"{field_name} must be a valid ISO-8601 timestamp: {value!r}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MemoryValidationError(f"{field_name} must include a timezone offset: {value!r}")
    return parsed.astimezone(timezone.utc)


def _validate_non_empty_text(value: object, field_name: str, *, max_chars: int) -> str:
    if not isinstance(value, str):
        raise MemoryValidationError(f"{field_name} must be a string")
    if not _single_line(value).strip():
        raise MemoryValidationError(f"{field_name} must not be empty or whitespace")
    if len(value) > max_chars:
        raise MemoryValidationError(
            f"{field_name} must be at most {max_chars} characters, got {len(value)}"
        )
    return value


def _validate_identifier(value: object, field_name: str, *, max_chars: int = 120) -> str:
    text = _validate_non_empty_text(value, field_name, max_chars=max_chars)
    if text != text.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise MemoryValidationError(
            f"{field_name} must not have leading/trailing whitespace or control characters"
        )
    return text


def _validate_actor(actor: object, *, allowed_kinds: frozenset[str]) -> Actor:
    if not isinstance(actor, Actor):
        raise MemoryValidationError("actor must be an Actor instance")
    if actor.kind not in ACTOR_KINDS:
        raise IllegalTransition("<none>", "<none>", str(actor.kind))
    if not isinstance(actor.actor_id, str) or not actor.actor_id.strip():
        raise MemoryValidationError("actor.actor_id must be a non-empty string")
    if actor.kind not in allowed_kinds:
        raise IllegalTransition("<none>", "<none>", actor.kind)
    return actor


@dataclass(frozen=True)
class PendingCandidate:
    """创建待跟进项的候选输入（经落点 5 与来源权限校验后才落库）。"""

    owner_id: str
    topic: str
    context: str
    expected_after: str
    followup_action: str
    scope: Scope = "FAMILY"
    audiences: frozenset[str] = frozenset({"family_all"})
    source_record_id: str | None = None
    expires_at: str | None = None
    requested_policy: RequestedPolicy = "persist_confirmed"


@dataclass(frozen=True)
class PendingItem:
    """已落库的待跟进项（架构 §7 ``PendingItem``）。"""

    id: str
    owner_id: str
    topic: str
    context: str
    expected_after: str
    followup_action: str
    scope: Scope
    status: PendingStatus
    created_at: str
    resolved_at: str | None = None
    audiences: frozenset[str] = frozenset()
    source_record_id: str | None = None
    expires_at: str | None = None
    actor_kind: ActorKind = "adult_control_plane"
    actor_id: str = "local_control_plane"


class SqlitePendingStore:
    """与 ``SqliteMemoryStore`` 共用同一个 ``memory.sqlite3`` 文件的待跟进项存储。"""

    def __init__(
        self,
        db_path: Path,
        *,
        clock: Callable[[], str] | None = None,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        self._memory_store = SqliteMemoryStore(
            db_path, busy_timeout_seconds=busy_timeout_seconds
        )
        self.path = self._memory_store.path
        self._clock = clock or _utc_now_iso
        self._busy_timeout_seconds = float(busy_timeout_seconds)

    def create_schema(self) -> None:
        db = self._connect_write()
        db.close()

    def _connect_write(self) -> sqlite3.Connection:
        db = self._memory_store._connect_write()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                for ddl in PENDING_SCHEMA_DDL:
                    db.execute(ddl)
            except BaseException:
                db.rollback()
                raise
            db.commit()
        except sqlite3.Error as exc:
            db.close()
            raise StoreError(f"cannot initialize pending schema in {self.path}: {exc}") from exc
        except BaseException:
            db.close()
            raise
        return db

    def _connect_readonly(self) -> sqlite3.Connection:
        uri = f"file:{quote(self.path.resolve().as_posix())}?mode=ro"
        db: sqlite3.Connection | None = None
        try:
            self._memory_store._check_private_permissions()
            db = sqlite3.connect(uri, uri=True, timeout=self._busy_timeout_seconds)
            self._memory_store._check_schema(db)
            self._check_pending_schema(db)
            return db
        except StoreError:
            if db is not None:
                db.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            if db is not None:
                db.close()
            raise StoreError(f"cannot read pending database {self.path}: {exc}") from exc
        except BaseException:
            if db is not None:
                db.close()
            raise

    @staticmethod
    def _check_pending_schema(db: sqlite3.Connection) -> None:
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name IN ('pending_item', 'pending_audience')"
            )
        }
        if not tables:
            return
        if "pending_item" not in tables or "pending_audience" not in tables:
            raise StoreError(
                f"pending schema is incomplete: found {sorted(tables)}, "
                "expected both pending_item and pending_audience"
            )
        item_cols = {row[1] for row in db.execute("PRAGMA table_info(pending_item)")}
        missing_item = set(_PENDING_COLUMNS) - item_cols
        if missing_item:
            raise StoreError(f"pending_item is missing columns: {sorted(missing_item)}")
        aud_cols = {row[1] for row in db.execute("PRAGMA table_info(pending_audience)")}
        missing_aud = {"pending_id", "audience_id"} - aud_cols
        if missing_aud:
            raise StoreError(f"pending_audience is missing columns: {sorted(missing_aud)}")

    @contextmanager
    def _transaction(self, db: sqlite3.Connection) -> Iterator[None]:
        db.execute("BEGIN IMMEDIATE")
        try:
            yield
            db.commit()
        except sqlite3.Error as exc:
            db.rollback()
            raise StoreError(f"cannot write pending database {self.path}: {exc}") from exc
        except BaseException:
            db.rollback()
            raise

    @staticmethod
    def _has_pending_table(db: sqlite3.Connection) -> bool:
        row = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_item'"
        ).fetchone()
        return row is not None

    @staticmethod
    def _row_to_item(db: sqlite3.Connection, row: tuple) -> PendingItem:
        values = dict(zip(_PENDING_COLUMNS, row))
        audiences = frozenset(
            aud
            for (aud,) in db.execute(
                "SELECT audience_id FROM pending_audience WHERE pending_id = ?",
                (values["id"],),
            )
        )
        return PendingItem(**values, audiences=audiences)

    def _load_item(self, db: sqlite3.Connection, item_id: str) -> PendingItem | None:
        if not self._has_pending_table(db):
            return None
        row = db.execute(
            f"SELECT {_PENDING_SELECT} FROM pending_item WHERE id = ?",
            (item_id,),
        ).fetchone()
        return None if row is None else self._row_to_item(db, row)

    def create(
        self,
        candidate: PendingCandidate,
        *,
        actor: Actor = Actor(kind="adult_control_plane", actor_id="local_control_plane"),
        item_id: str | None = None,
    ) -> PendingItem | None:
        """创建一条 ``OPEN`` 待跟进项；命中落点 5 ``do_not_persist`` 时返回 ``None``。"""

        checked_actor = _validate_actor(
            actor, allowed_kinds=frozenset({"adult_control_plane"})
        )
        if not isinstance(candidate, PendingCandidate):
            raise MemoryValidationError("candidate must be a PendingCandidate")

        # 契约 §5 落点 5：do_not_persist 写前拦截（候选自身声明）。
        if candidate.requested_policy == "do_not_persist":
            return None
        if candidate.requested_policy not in REQUESTED_POLICIES:
            raise MemoryValidationError(
                f"unsupported requested_policy: {candidate.requested_policy!r}"
            )

        if candidate.scope not in SCOPES:
            raise MemoryValidationError(f"unsupported scope: {candidate.scope!r}")
        if candidate.scope not in M2_1_ALLOWED_SCOPES:
            raise AuthorizationError(
                AuthorizationDecision(allowed=False, reason="scope_not_enabled")
            )

        owner_id = _validate_identifier(candidate.owner_id, "owner_id")
        topic = _validate_non_empty_text(
            candidate.topic, "topic", max_chars=MAX_PENDING_FIELD_CHARS
        )
        context = _validate_non_empty_text(
            candidate.context, "context", max_chars=MAX_PENDING_FIELD_CHARS
        )
        followup_action = _validate_non_empty_text(
            candidate.followup_action,
            "followup_action",
            max_chars=MAX_PENDING_FIELD_CHARS,
        )

        if not isinstance(candidate.audiences, frozenset) or not candidate.audiences:
            raise MemoryValidationError("audiences must be a non-empty frozenset of strings")
        audiences = frozenset(
            _validate_identifier(aud, "audience_id") for aud in candidate.audiences
        )

        expected_after_dt = _parse_iso_timestamp(candidate.expected_after, "expected_after")
        now_str = self._clock()
        now_dt = _parse_iso_timestamp(now_str, "clock()")

        if candidate.expires_at is not None:
            expires_at_dt = _parse_iso_timestamp(candidate.expires_at, "expires_at")
            expires_at_str = candidate.expires_at.strip()
        else:
            expires_at_dt = expected_after_dt + timedelta(days=DEFAULT_PENDING_TTL_DAYS)
            expires_at_str = expires_at_dt.isoformat(timespec="seconds").replace("+00:00", "Z")

        if expires_at_dt <= expected_after_dt:
            raise MemoryValidationError("expires_at must be strictly after expected_after")

        source_record_id: str | None = None
        if candidate.source_record_id is not None:
            source_record_id = _validate_identifier(
                candidate.source_record_id, "source_record_id"
            )

        resolved_id = (
            _validate_identifier(item_id, "item_id")
            if item_id is not None
            else f"pend-{uuid.uuid4().hex[:12]}"
        )

        with closing(self._connect_write()) as db, self._transaction(db):
            if source_record_id is not None:
                source_row = db.execute(
                    "SELECT owner_id, scope, status, memory_policy, expires_at "
                    "FROM memory_record WHERE id = ?",
                    (source_record_id,),
                ).fetchone()
                if source_row is None:
                    raise RecordNotFound(f"source memory record not found: {source_record_id}")
                src_owner, src_scope, src_status, src_policy, src_expires_at = source_row
                # 契约 §5 落点 5：来源记录或其祖先为 do_not_persist 时写前拦截，不生成 PendingItem。
                if src_policy == "do_not_persist":
                    return None
                if src_status != "ACTIVE":
                    raise MemoryValidationError(
                        f"source memory record must be ACTIVE to derive a pending item, "
                        f"got status={src_status!r}"
                    )
                if src_expires_at is not None:
                    if _parse_iso_timestamp(src_expires_at, "source.expires_at") <= now_dt:
                        raise MemoryValidationError(
                            "source memory record has already expired"
                        )
                # 递归校验来源记录的祖先闭包（缺源/非 ACTIVE/过期/do_not_persist）
                frontier = [
                    parent_id
                    for (parent_id,) in db.execute(
                        "SELECT source_id FROM memory_source WHERE record_id = ? ORDER BY ordinal",
                        (source_record_id,),
                    )
                ]
                visited = {source_record_id}
                while frontier:
                    anc_id = frontier.pop(0)
                    if anc_id in visited:
                        continue
                    visited.add(anc_id)
                    anc_row = db.execute(
                        "SELECT status, memory_policy, expires_at FROM memory_record WHERE id = ?",
                        (anc_id,),
                    ).fetchone()
                    if anc_row is None:
                        raise MemoryValidationError(
                            f"source memory record {source_record_id} has missing ancestor {anc_id}"
                        )
                    anc_status, anc_policy, anc_expires_at = anc_row
                    if anc_policy == "do_not_persist":
                        return None
                    if anc_status != "ACTIVE":
                        raise MemoryValidationError(
                            f"source memory record ancestor {anc_id} is not ACTIVE ({anc_status!r})"
                        )
                    if anc_expires_at is not None:
                        if _parse_iso_timestamp(anc_expires_at, "ancestor.expires_at") <= now_dt:
                            raise MemoryValidationError(
                                f"source memory record ancestor {anc_id} has already expired"
                            )
                    frontier.extend(
                        parent_id
                        for (parent_id,) in db.execute(
                            "SELECT source_id FROM memory_source WHERE record_id = ? ORDER BY ordinal",
                            (anc_id,),
                        )
                        if parent_id not in visited
                    )
                if owner_id != src_owner:
                    raise MemoryValidationError(
                        "pending item owner_id must match source record owner_id"
                    )
                if candidate.scope != src_scope:
                    raise MemoryValidationError(
                        "pending item scope must match source record scope"
                    )
                src_audiences = frozenset(
                    aud
                    for (aud,) in db.execute(
                        "SELECT audience_id FROM memory_audience WHERE record_id = ?",
                        (source_record_id,),
                    )
                )
                if not audiences <= src_audiences:
                    raise MemoryValidationError(
                        "pending item audiences must be a subset of source record audiences"
                    )

            if self._load_item(db, resolved_id) is not None:
                raise MemoryValidationError(f"pending item id already exists: {resolved_id}")

            item = PendingItem(
                id=resolved_id,
                owner_id=owner_id,
                topic=topic,
                context=context,
                expected_after=candidate.expected_after.strip(),
                followup_action=followup_action,
                scope=candidate.scope,
                status="OPEN",
                created_at=now_str,
                resolved_at=None,
                audiences=audiences,
                source_record_id=source_record_id,
                expires_at=expires_at_str,
                actor_kind=checked_actor.kind,
                actor_id=checked_actor.actor_id,
            )
            db.execute(
                f"INSERT INTO pending_item ({_PENDING_SELECT}) "
                f"VALUES ({', '.join('?' for _ in _PENDING_COLUMNS)})",
                tuple(getattr(item, col) for col in _PENDING_COLUMNS),
            )
            db.executemany(
                "INSERT INTO pending_audience (pending_id, audience_id) VALUES (?, ?)",
                sorted((item.id, aud) for aud in item.audiences),
            )
            return item

    def resolve(
        self,
        item_id: str,
        *,
        actor: Actor = Actor(kind="adult_control_plane", actor_id="local_control_plane"),
    ) -> PendingItem:
        """将 ``OPEN`` 待跟进项结项为 ``RESOLVED``。"""

        return self._transition_status(
            item_id,
            to_status="RESOLVED",
            actor=actor,
            allowed_actors=frozenset({"adult_control_plane"}),
        )

    def cancel(
        self,
        item_id: str,
        *,
        actor: Actor = Actor(kind="adult_control_plane", actor_id="local_control_plane"),
    ) -> PendingItem:
        """将 ``OPEN`` 待跟进项取消为 ``CANCELLED``。"""

        return self._transition_status(
            item_id,
            to_status="CANCELLED",
            actor=actor,
            allowed_actors=frozenset({"adult_control_plane"}),
        )

    def expire(
        self,
        item_id: str,
        *,
        actor: Actor = Actor(kind="ttl_expiry", actor_id="pending_sweep"),
    ) -> PendingItem:
        """将 ``OPEN`` 待跟进项置为 ``EXPIRED``（``EXPIRED -> EXPIRED`` 幂等）。"""

        return self._transition_status(
            item_id,
            to_status="EXPIRED",
            actor=actor,
            allowed_actors=frozenset({"ttl_expiry", "adult_control_plane"}),
        )

    def _transition_status(
        self,
        item_id: str,
        *,
        to_status: PendingStatus,
        actor: Actor,
        allowed_actors: frozenset[str],
    ) -> PendingItem:
        checked_actor = _validate_actor(actor, allowed_kinds=allowed_actors)
        clean_id = _validate_identifier(item_id, "item_id")
        now_str = self._clock()
        _parse_iso_timestamp(now_str, "clock()")

        with closing(self._connect_write()) as db, self._transaction(db):
            current = self._load_item(db, clean_id)
            if current is None:
                raise RecordNotFound(f"pending item not found: {clean_id}")
            if (current.status, to_status) not in PENDING_LEGAL_TRANSITIONS:
                raise IllegalTransition(current.status, to_status, checked_actor.kind)
            if current.status == "EXPIRED" and to_status == "EXPIRED":
                return current
            db.execute(
                "UPDATE pending_item SET status = ?, resolved_at = ?, "
                "actor_kind = ?, actor_id = ? WHERE id = ?",
                (to_status, now_str, checked_actor.kind, checked_actor.actor_id, clean_id),
            )
            return replace(
                current,
                status=to_status,
                resolved_at=now_str,
                actor_kind=checked_actor.kind,
                actor_id=checked_actor.actor_id,
            )

    def skip(
        self,
        item_id: str,
        *,
        until: str,
        actor: Actor = Actor(kind="adult_control_plane", actor_id="local_control_plane"),
    ) -> PendingItem:
        """延后跟进时间（保持 ``status='OPEN'``，推迟 ``expected_after``）。"""

        checked_actor = _validate_actor(
            actor, allowed_kinds=frozenset({"adult_control_plane"})
        )
        clean_id = _validate_identifier(item_id, "item_id")
        until_dt = _parse_iso_timestamp(until, "until")
        now_str = self._clock()
        now_dt = _parse_iso_timestamp(now_str, "clock()")
        if until_dt <= now_dt:
            raise MemoryValidationError("skip until timestamp must be in the future")

        with closing(self._connect_write()) as db, self._transaction(db):
            current = self._load_item(db, clean_id)
            if current is None:
                raise RecordNotFound(f"pending item not found: {clean_id}")
            if current.status != "OPEN":
                raise IllegalTransition(current.status, "OPEN", checked_actor.kind)
            current_expected_dt = _parse_iso_timestamp(
                current.expected_after, "expected_after"
            )
            if until_dt <= current_expected_dt:
                raise MemoryValidationError(
                    "skip until timestamp must be strictly after current expected_after"
                )
            if current.expires_at is not None:
                expires_dt = _parse_iso_timestamp(current.expires_at, "expires_at")
                if until_dt >= expires_dt:
                    raise MemoryValidationError(
                        "skip until timestamp must be strictly before expires_at"
                    )
            clean_until = until.strip()
            db.execute(
                "UPDATE pending_item SET expected_after = ?, actor_kind = ?, actor_id = ? "
                "WHERE id = ?",
                (clean_until, checked_actor.kind, checked_actor.actor_id, clean_id),
            )
            return replace(
                current,
                expected_after=clean_until,
                actor_kind=checked_actor.kind,
                actor_id=checked_actor.actor_id,
            )

    def sweep_expired(
        self,
        *,
        actor: Actor = Actor(kind="ttl_expiry", actor_id="pending_sweep"),
    ) -> tuple[PendingItem, ...]:
        """扫描并将所有 ``status='OPEN'`` 且 ``expires_at <= now`` 的待跟进项置为 ``EXPIRED``。"""

        checked_actor = _validate_actor(
            actor, allowed_kinds=frozenset({"ttl_expiry", "adult_control_plane"})
        )
        now_str = self._clock()
        now_dt = _parse_iso_timestamp(now_str, "clock()")
        if not self.path.exists():
            return ()

        with closing(self._connect_write()) as db, self._transaction(db):
            rows = db.execute(
                f"SELECT {_PENDING_SELECT} FROM pending_item "
                "WHERE status = 'OPEN' AND expires_at IS NOT NULL ORDER BY id"
            ).fetchall()
            items = [self._row_to_item(db, row) for row in rows]
            expired: list[PendingItem] = []
            for item in items:
                if item.expires_at is None:
                    continue
                try:
                    exp_dt = _parse_iso_timestamp(item.expires_at, "expires_at")
                except MemoryValidationError as exc:
                    raise StoreError(
                        f"pending item {item.id} has unparseable expires_at: {item.expires_at!r}"
                    ) from exc
                if exp_dt <= now_dt:
                    db.execute(
                        "UPDATE pending_item SET status = 'EXPIRED', resolved_at = ?, "
                        "actor_kind = ?, actor_id = ? WHERE id = ?",
                        (now_str, checked_actor.kind, checked_actor.actor_id, item.id),
                    )
                    expired.append(
                        replace(
                            item,
                            status="EXPIRED",
                            resolved_at=now_str,
                            actor_kind=checked_actor.kind,
                            actor_id=checked_actor.actor_id,
                        )
                    )
            return tuple(expired)

    def read_item(self, item_id: str) -> PendingItem | None:
        """只读获取单条待跟进项；库文件或表不存在时返回 ``None``（不创建文件）。"""

        if not isinstance(item_id, str) or not item_id.strip() or not self.path.exists():
            return None
        try:
            with closing(self._connect_readonly()) as db:
                return self._load_item(db, item_id)
        except sqlite3.Error as exc:
            raise StoreError(f"cannot read pending database {self.path}: {exc}") from exc

    def list_items(
        self,
        *,
        audience_id: str | None = None,
        statuses: tuple[str, ...] = (),
    ) -> tuple[PendingItem, ...]:
        """只读列出待跟进项（供控制面 CLI 查看）；库或表不存在时返回空元组。"""

        if not self.path.exists():
            return ()
        try:
            with closing(self._connect_readonly()) as db:
                if not self._has_pending_table(db):
                    return ()
                sql = [f"SELECT DISTINCT p.{', p.'.join(_PENDING_COLUMNS)} FROM pending_item AS p"]
                params: list[object] = []
                where: list[str] = []
                if audience_id is not None:
                    sql.append("JOIN pending_audience AS a ON a.pending_id = p.id")
                    where.append("a.audience_id = ?")
                    params.append(audience_id)
                if statuses:
                    placeholders = ", ".join("?" for _ in statuses)
                    where.append(f"p.status IN ({placeholders})")
                    params.extend(statuses)
                if where:
                    sql.append("WHERE " + " AND ".join(where))
                sql.append("ORDER BY p.expected_after ASC, p.created_at ASC, p.id ASC")
                rows = db.execute(" ".join(sql), params).fetchall()
                return tuple(self._row_to_item(db, row) for row in rows)
        except sqlite3.Error as exc:
            raise StoreError(f"cannot read pending database {self.path}: {exc}") from exc

    def list_open_for_session(
        self,
        *,
        audience_id: str,
        now: str,
    ) -> tuple[PendingItem, ...]:
        """会前机会式跟进的只读候选枚举（``mode=ro``，不建库、无副作用）。

        过滤条件：
        1. ``status == 'OPEN'`` 且 ``scope == 'FAMILY'``（M2.1 仅开放 FAMILY；PERSONAL / SAFETY
           在本人身份未验证阶段一律排除，架构 §2.2 P1）；
        2. ``audience_id`` 命中 ``pending_audience``；
        3. ``now >= expected_after``（到达跟进时间窗口，架构 §2.2 P3）；
        4. 未过期（``expires_at is None`` 或 ``expires_at > now``）。
        """

        now_dt = _parse_iso_timestamp(now, "now")
        if not isinstance(audience_id, str) or not audience_id.strip():
            return ()
        if not self.path.exists():
            return ()

        try:
            with closing(self._connect_readonly()) as db:
                if not self._has_pending_table(db):
                    return ()
                rows = db.execute(
                    f"SELECT DISTINCT p.{', p.'.join(_PENDING_COLUMNS)} "
                    "FROM pending_item AS p "
                    "JOIN pending_audience AS a ON a.pending_id = p.id "
                    "WHERE a.audience_id = ? AND p.status = 'OPEN' AND p.scope = 'FAMILY' "
                    "ORDER BY p.id ASC",
                    (audience_id,),
                ).fetchall()
                candidates = [self._row_to_item(db, row) for row in rows]
        except sqlite3.Error as exc:
            raise StoreError(f"cannot read pending database {self.path}: {exc}") from exc

        eligible: list[tuple[datetime, datetime, str, PendingItem]] = []
        for item in candidates:
            try:
                expected_dt = _parse_iso_timestamp(item.expected_after, "expected_after")
                created_dt = _parse_iso_timestamp(item.created_at, "created_at")
                if item.expires_at is not None:
                    expires_dt = _parse_iso_timestamp(item.expires_at, "expires_at")
                    if expires_dt <= now_dt:
                        continue
            except MemoryValidationError:
                # 时间戳损坏行按 fail-closed 跳过，不注入给 provider。
                continue
            if now_dt < expected_dt:
                continue
            eligible.append((expected_dt, created_dt, item.id, item))

        eligible.sort(key=lambda entry: (entry[0], entry[1], entry[2]))
        return tuple(entry[3] for entry in eligible)


def render_pending_block(
    items: Sequence[PendingItem],
    *,
    member_names: MemberNames | None = None,
) -> str:
    """将已通过会前复核的待跟进项渲染为 ``SessionConfig.instructions`` 段落。

    不变量：
    - ``items`` 为空时返回 ``""``（不追加任何字符，保持 G1 r5 基准指纹不变）；
    - 每次会话最多渲染 :data:`MAX_PROJECTED_PENDING_ITEMS`（1）条；
    - 所有文本经 :func:`~soul_memory_kernel.memory.projection._single_line` 折叠控制字符与换行，
      防止在 system instructions 中伪造独立规则行；
    - 绝不输出 ``item.id``、``item.owner_id`` 或 ``item.source_record_id``。
    """

    if not items:
        return ""
    names = member_names or {}

    renderable: list[tuple[tuple[int, float], tuple[int, float], str, PendingItem]] = []
    for item in items:
        if item.status != "OPEN" or item.scope not in M2_1_ALLOWED_SCOPES:
            continue
        topic = _single_line(item.topic).strip()
        context = _single_line(item.context).strip()
        followup = _single_line(item.followup_action).strip()
        if not (topic and context and followup):
            continue
        try:
            exp_key = (0, _parse_iso_timestamp(item.expected_after, "expected_after").timestamp())
        except MemoryValidationError:
            exp_key = (1, 0.0)
        try:
            crt_key = (0, _parse_iso_timestamp(item.created_at, "created_at").timestamp())
        except MemoryValidationError:
            crt_key = (1, 0.0)
        renderable.append((exp_key, crt_key, item.id, item))

    if not renderable:
        return ""

    renderable.sort(key=lambda entry: (entry[0], entry[1], entry[2]))
    selected = [entry[3] for entry in renderable[:MAX_PROJECTED_PENDING_ITEMS]]

    lines = [PENDING_BLOCK_HEADER]
    for item in selected:
        raw_name = names.get(item.owner_id)
        clean_name = _single_line(raw_name).strip() if isinstance(raw_name, str) else ""
        attribution = f"{clean_name}：" if clean_name else ""
        topic = _single_line(item.topic).strip()
        context = _single_line(item.context).strip()
        followup = _single_line(item.followup_action).strip()
        lines.append(
            f"- {attribution}{topic}（背景：{context}；跟进建议：{followup}）"
        )
    return "\n".join(lines)
