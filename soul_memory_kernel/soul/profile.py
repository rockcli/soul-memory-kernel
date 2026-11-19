"""Explicitly maintained static family profile stored in a local SQLite file."""

from __future__ import annotations

import re
import math
import os
import sqlite3
import stat
import unicodedata
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

PROFILE_SCHEMA_VERSION = 1
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ProfileError(ValueError):
    """Invalid or unavailable local family profile store."""


@dataclass(frozen=True)
class FamilyMember:
    id: str
    name: str
    role: str
    age: int | None
    created_at: str | None = None
    relationship: str = ""


def _text(value: str, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ProfileError(f"{field} must be non-empty and at most {limit} characters")
    if any(unicodedata.category(char) == "Cc" or char in "\u2028\u2029" for char in value):
        raise ProfileError(f"{field} must not contain line breaks or control characters")
    return value.strip()


def validate_member(member: FamilyMember) -> FamilyMember:
    if not isinstance(member.id, str) or not _ID_RE.fullmatch(member.id):
        raise ProfileError("member id must use lowercase ASCII letters, digits, '_' or '-' (1-64 chars)")
    if member.age is not None and (
        not isinstance(member.age, int)
        or isinstance(member.age, bool)
        or not 0 <= member.age <= 130
    ):
        raise ProfileError("age must be an integer between 0 and 130")
    created_at = member.created_at or datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ProfileError("created_at must be an ISO-8601 timestamp") from exc
    return FamilyMember(
        id=member.id,
        name=_text(member.name, "name", 80),
        role=_text(member.role, "role", 80),
        age=member.age,
        created_at=created_at,
        relationship=_text(member.relationship, "relationship", 100),
    )


class FamilyProfileStore:
    """Profile reads are read-only; schema creation is only used by explicit add."""

    def __init__(self, path: Path, *, busy_timeout_seconds: float = 5.0):
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds < 0
        ):
            raise ValueError("busy_timeout_seconds must be a finite number >= 0")
        self.path = path
        self._busy_timeout_seconds = float(busy_timeout_seconds)

    def list_members(self) -> tuple[FamilyMember, ...]:
        if not self.path.exists():
            return ()
        with closing(self._connect_readonly()) as db:
            # 连接与 schema 检查之后的 SELECT 也要包进来：否则这一小段窗口里的
            # SQLITE_BUSY / 读故障会以裸 sqlite3.Error 穿出调用方（审阅 A-s2），
            # 让「档案库不可读 → 按解析不出处理」的承诺出现缝隙。
            try:
                rows = db.execute(
                    "SELECT id, name, role, age, created_at, relationship "
                    "FROM family_member ORDER BY id"
                ).fetchall()
            except (OSError, sqlite3.Error) as exc:
                raise ProfileError(
                    f"cannot read family profile database {self.path}: {exc}"
                ) from exc
        return tuple(self._row_to_member(row) for row in rows)

    def get(self, member_id: str) -> FamilyMember | None:
        if not self.path.exists():
            return None
        with closing(self._connect_readonly()) as db:
            try:
                row = db.execute(
                    "SELECT id, name, role, age, created_at, relationship "
                    "FROM family_member WHERE id = ?",
                    (member_id,),
                ).fetchone()
            except (OSError, sqlite3.Error) as exc:
                raise ProfileError(
                    f"cannot read family profile database {self.path}: {exc}"
                ) from exc
        return self._row_to_member(row) if row is not None else None

    def upsert(self, member: FamilyMember) -> None:
        item = validate_member(member)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            created = self._create_private_file_if_missing()
            with sqlite3.connect(self.path, timeout=self._busy_timeout_seconds) as db:
                if created:
                    self._create_schema(db)
                else:
                    self._check_schema(db)
                db.execute(
                    "INSERT INTO family_member "
                    "(id, name, role, age, created_at, relationship) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET name=excluded.name, role=excluded.role, "
                    "age=excluded.age, relationship=excluded.relationship",
                    (
                        item.id,
                        item.name,
                        item.role,
                        item.age,
                        item.created_at,
                        item.relationship,
                    ),
                )
        except (OSError, sqlite3.Error) as exc:
            raise ProfileError(f"cannot update family profile database {self.path}: {exc}") from exc

    def remove(self, member_id: str) -> bool:
        if not self.path.exists():
            return False
        try:
            self._check_private_permissions()
            with sqlite3.connect(self.path, timeout=self._busy_timeout_seconds) as db:
                self._check_schema(db)
                cursor = db.execute("DELETE FROM family_member WHERE id = ?", (member_id,))
                return cursor.rowcount > 0
        except (OSError, sqlite3.Error) as exc:
            raise ProfileError(f"cannot update family profile database {self.path}: {exc}") from exc

    def _connect_readonly(self) -> sqlite3.Connection:
        uri = f"file:{quote(self.path.resolve().as_posix())}?mode=ro"
        db: sqlite3.Connection | None = None
        try:
            self._check_private_permissions()
            db = sqlite3.connect(uri, uri=True, timeout=self._busy_timeout_seconds)
            self._check_schema(db)
            return db
        except (OSError, sqlite3.Error, ProfileError) as exc:
            if db is not None:
                db.close()
            raise ProfileError(f"cannot read family profile database {self.path}: {exc}") from exc

    def _create_private_file_if_missing(self) -> bool:
        """Create a new database with owner-only permissions, without a race."""

        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            self._check_private_permissions()
            return False
        except OSError as exc:
            raise ProfileError(f"cannot create family profile database {self.path}: {exc}") from exc
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self._check_private_permissions()
        return True

    def _check_private_permissions(self) -> None:
        try:
            if self.path.is_symlink():
                raise ProfileError("family profile database must not be a symlink")
            mode = stat.S_IMODE(self.path.stat().st_mode)
        except OSError as exc:
            raise ProfileError(f"cannot inspect family profile permissions {self.path}: {exc}") from exc
        if mode & 0o077:
            raise ProfileError(
                f"family profile database permissions are too broad ({mode:o}); "
                "restrict it to owner access with chmod 600"
            )

    @staticmethod
    def _create_schema(db: sqlite3.Connection) -> None:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "CREATE TABLE family_member ("
            "id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, age INTEGER NULL, "
            "created_at TEXT NOT NULL, relationship TEXT NOT NULL, "
            "CHECK(age IS NULL OR (age >= 0 AND age <= 130)))"
        )
        db.execute(f"PRAGMA user_version = {PROFILE_SCHEMA_VERSION}")
        db.commit()

    @staticmethod
    def _check_schema(db: sqlite3.Connection) -> None:
        try:
            check = db.execute("PRAGMA quick_check").fetchone()
            version = db.execute("PRAGMA user_version").fetchone()
            columns = {row[1] for row in db.execute("PRAGMA table_info(family_member)")}
        except sqlite3.Error as exc:
            raise ProfileError(f"invalid family profile database: {exc}") from exc
        required = {
            "id", "name", "role", "age", "created_at", "relationship"
        }
        if check is None or check[0] != "ok" or version is None or version[0] != PROFILE_SCHEMA_VERSION:
            raise ProfileError("family profile database failed integrity or schema-version check")
        if columns != required:
            raise ProfileError("family profile database schema does not match the supported version")

    @staticmethod
    def _row_to_member(row: tuple) -> FamilyMember:
        try:
            return validate_member(FamilyMember(row[0], row[1], row[2], row[3], row[4], row[5]))
        except (TypeError, ValueError) as exc:
            raise ProfileError(f"family profile row is invalid: {exc}") from exc
