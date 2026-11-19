"""M2 grant 存储（W2）：``SqliteGrantStore`` 与 ``load_grant_for_session``。

契约依据：``docs/M2-CONTRACT.md`` §3.3（判权输入）、§9（**``grants.py`` 归 W2**）、
§9.1（``SqliteGrantStore(db_path)`` 构造签名冻结）、§10.1（投影接缝只有 ``session_id``）。

两块内容：

- :class:`SqliteGrantStore` —— 方法集 = :class:`soul_memory_kernel.memory.store.GrantStore`
  Protocol：``issue`` / ``revoke`` / ``load_current`` / ``load_for_session``。
- :func:`load_grant_for_session` —— W4 接缝用的薄封装（打开 store 再按会话查）。

三条不可让步的语义：

1. **追加写**：``grant_record`` 的主键是 ``(grant_id, version)``，续签是新行，旧版本
   保留供审计；``version`` 必须**严格递增**。
2. **撤销不可被复活**：``revoke`` 把该 ``grant_id`` 的**全部版本**写 ``revoked_at``，
   之后**不允许**再为同一 ``grant_id`` 签发新版本（要重新授权必须换 ``grant_id``）。
3. **不替 ``authorize()`` 过滤过期**：``load_for_session`` 只排除**已撤销**的版本，
   到期与否由 ``authorize()`` 判 ``expired``。过滤过期会让拒绝原因从 ``expired``
   退化成 ``no_grant``，审计就查不出来了（契约 §GrantStore.load_for_session）。

存储层的产品级约束沿用 M1 ``FamilyProfileStore``：库文件必须已存在（schema 由
``SqliteMemoryStore.create_schema()`` 建立，本模块**不建表也不建文件**）、拒绝 symlink、
拒绝组/其他可读权限（0600）、``PRAGMA user_version`` 必须相符、``PRAGMA quick_check``
必须 ok、读路径只用 ``mode=ro`` 连接。

**读路径的降级**：库文件不存在时 ``load_current`` / ``load_for_session`` 返回 ``None``
（= 没有 grant，是正常状态），但库存在而结构/权限/版本不对时抛 ``StoreError`` ——
「文件不存在」与「文件坏了」必须区分，后者静默降级会把损坏说成「没有授权」。
"""

from __future__ import annotations

import os
import math
import sqlite3
import stat
from contextlib import closing
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from soul_memory_kernel.memory.model import Actor, Grant
from soul_memory_kernel.memory.policy import ACTIONS
from soul_memory_kernel.memory.service import MemoryValidationError, StoreError
from soul_memory_kernel.memory.store import MAX_GRANT_TTL_SECONDS, MEMORY_SCHEMA_VERSION

#: 本模块用到的三张 grant 表（DDL 在 W0 冻结的 ``store.py`` 里）。
GRANT_TABLES: frozenset[str] = frozenset({"grant_record", "grant_action", "grant_resource"})

#: **可签发动作集**（契约 §4.1 勘误 E4，冻结；W8 落地）。
#:
#: 免 grant 的动作**永远不可签发**：``review_control_plane`` 是「成人复审候选」的控制面
#: 动作，它按契约**无条件免 grant**（``NO_GRANT_EXEMPT_ACTIONS``），签发它没有任何意义，
#: 却会造出一条「本该免 grant 的动作也有一条 grant 路径」的假象。
#:
#: 它是**契约可见的唯一事实来源**：``SqliteGrantStore.issue()`` 的 Python 侧校验与
#: ``memory_cli.py`` 的 ``grant issue --action`` 的 ``choices`` 都从这里取，各处不得内联
#: ``ACTIONS`` 再自己减一遍（W9 审阅 A 建议 4：内联 ``ACTIONS`` 会让带
#: ``review_control_plane`` 的请求一路走到 ``grant_action`` 的 DDL CHECK，
#: 报成 :class:`~soul_memory_kernel.memory.service.StoreError`（存储故障）—— 语义错位）。
GRANTABLE_ACTIONS: frozenset[str] = ACTIONS - {"review_control_plane"}

#: ``grant_record`` 的列顺序（``_row_to_grant`` 与所有 SELECT 共用，避免列序漂移）。
_GRANT_COLUMNS = (
    "grant_id",
    "version",
    "session_id",
    "subject_id",
    "owner_id",
    "audience_id",
    "issuer",
    "issued_at",
    "expires_at",
)


def _parse_instant(value: object) -> datetime | None:
    """解析 ISO-8601 UTC 时间戳；不可解析、缺时区、非字符串一律 ``None``。

    与 ``policy._parse_utc`` 同一套 fail-closed 口径：没有时区偏移的时间戳无法证明
    自己是 UTC，与 ``expires_at`` 做 TTL 算术也没有定义，因此按不可信处理。
    """

    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MemoryValidationError(f"grant {field} must be a non-empty string")
    return value


def _validate_grant_for_issue(grant: Grant) -> None:
    """签发前的入参校验。**形状非法抛 ``MemoryValidationError``，不落任何行。**

    逐条对应 :meth:`GrantStore.issue` 的冻结要求（``version`` 递增、``issuer`` 必填、
    TTL 不超过 :data:`MAX_GRANT_TTL_SECONDS`）以及 DDL 约束（动作取值、同意版本 >= 1）。
    动作取值对着 :data:`GRANTABLE_ACTIONS` 判（免 grant 的动作不可签发，
    契约 §4.1 勘误 E4），违反抛 :class:`~soul_memory_kernel.memory.service.MemoryValidationError`。
    ``version`` 的**递增性**要对着库里已有版本判断，因此放在事务里做，不在这里。
    """

    if not isinstance(grant, Grant):
        raise MemoryValidationError("grant must be a Grant")

    for field in ("grant_id", "session_id", "subject_id", "owner_id", "audience_id", "issuer"):
        _require_text(getattr(grant, field), field)

    if not isinstance(grant.version, int) or isinstance(grant.version, bool) or grant.version < 1:
        raise MemoryValidationError("grant version must be an integer >= 1")

    issued_at = _parse_instant(grant.issued_at)
    if issued_at is None:
        raise MemoryValidationError("grant issued_at must be an ISO-8601 UTC timestamp")
    expires_at = _parse_instant(grant.expires_at)
    if expires_at is None:
        raise MemoryValidationError("grant expires_at must be an ISO-8601 UTC timestamp")

    ttl_seconds = (expires_at - issued_at).total_seconds()
    if ttl_seconds <= 0:
        raise MemoryValidationError("grant expires_at must be after issued_at")
    if ttl_seconds > MAX_GRANT_TTL_SECONDS:
        raise MemoryValidationError(
            f"grant TTL {ttl_seconds:g}s exceeds MAX_GRANT_TTL_SECONDS={MAX_GRANT_TTL_SECONDS}"
        )

    if not isinstance(grant.actions, frozenset):
        raise MemoryValidationError("grant actions must be a frozenset")
    # 契约 §4.1（勘误 E4）：Python 侧校验用契约可见的 ``GRANTABLE_ACTIONS``，
    # **不内联 ``ACTIONS``** —— 免 grant 的 ``review_control_plane`` 必须在这里被拒
    # （``MemoryValidationError``，「入参形状非法」），而不是一路走到 ``grant_action``
    # 的 DDL CHECK 再变成 ``StoreError``（「存储故障」）。
    unknown_actions = set(grant.actions) - GRANTABLE_ACTIONS
    if unknown_actions:
        raise MemoryValidationError(
            "grant actions contain unknown or non-grantable actions "
            f"(grantable: {sorted(GRANTABLE_ACTIONS)}): {sorted(unknown_actions)}"
        )

    if not isinstance(grant.resource_ids, frozenset):
        raise MemoryValidationError("grant resource_ids must be a frozenset")
    for record_id in grant.resource_ids:
        _require_text(record_id, "resource_ids[]")

    if not isinstance(grant.consent_versions, tuple):
        raise MemoryValidationError("grant consent_versions must be a tuple of (record_id, version)")
    consents: dict[str, int] = {}
    for entry in grant.consent_versions:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise MemoryValidationError("grant consent_versions entries must be (record_id, version)")
        record_id, consent_version = entry
        _require_text(record_id, "consent_versions[].record_id")
        if record_id in consents:
            raise MemoryValidationError(f"grant consent_versions has a duplicate entry: {record_id}")
        if (
            not isinstance(consent_version, int)
            or isinstance(consent_version, bool)
            or consent_version < 1
        ):
            raise MemoryValidationError("grant consent versions must be integers >= 1")
        consents[record_id] = consent_version

    # ``grant_resource`` 每行只存一个 ``record_id`` + 一个同意版本，因此两张视图必须
    # 描述同一批记录：只授权不给同意版本无处可存，只给同意版本不授权则会静默丢失。
    if set(consents) != set(grant.resource_ids):
        missing = sorted(set(grant.resource_ids) - set(consents))
        extra = sorted(set(consents) - set(grant.resource_ids))
        raise MemoryValidationError(
            "grant resource_ids and consent_versions must cover the same records "
            f"(missing consent versions: {missing}; consents without resource: {extra})"
        )


#: 允许的时钟偏移（秒）：``issued_at`` 最多可以比「现在」晚这么多。
#:
#: B-s1（主控 2026-09-26）：12h 的窗口上限只约束**长度**，不锚定**签发现刻** —— 一个
#: ``issued_at=2026-12-01`` 的 grant 会被接受，然后从今天起一直可用。加这一道之后，
#: 「短期」才在时限上真正成立。60s 是给同一台机器上控制面与 store 的时钟漂移留的余量。
GRANT_ISSUED_AT_SKEW_SECONDS = 60


def _system_clock() -> str:
    """``SqliteGrantStore`` 的默认时钟：当前 UTC 时刻，ISO-8601。"""

    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class SqliteGrantStore:
    """grant 持久化（W2）。构造签名冻结为 ``SqliteGrantStore(db_path)``。

    方法集 = :class:`soul_memory_kernel.memory.store.GrantStore` Protocol。
    **本类不创建 schema、不创建库文件**：schema 归 ``SqliteMemoryStore.create_schema()``
    （W1），本类只读写既有库。库文件不存在时读返回 ``None``、写抛 ``StoreError``。
    """

    def __init__(
        self,
        db_path: Path,
        *,
        clock: Callable[[], str] | None = None,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        """``clock`` 可选（冻结签名只要求 ``db_path`` 必需）：注入 ISO-8601 UTC 时钟，
        默认取系统时刻。测试用它做时间旅行。

        ``busy_timeout_seconds`` 默认保持 SQLite 原有的 5 秒设置；实时会话可将它设为
        ``0``，让授权存储的锁冲突立即失败。"""

        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds < 0
        ):
            raise ValueError("busy_timeout_seconds must be a finite number >= 0")

        self.path = Path(db_path)
        self._clock = clock or _system_clock
        self._busy_timeout_seconds = float(busy_timeout_seconds)

    # ---------------------------------------------------------------- 写入

    def issue(self, grant: Grant) -> None:
        """签发一个 grant 版本。``version`` 必须严格递增；``issuer`` 必填。

        - 同一 ``(grant_id, version)`` 重复签发、或版本号不大于库中最大版本 → 拒绝
          （追加写，旧版本保留供审计，绝不覆盖）。
        - 该 ``grant_id`` 只要被撤销过，就**不允许**再签发新版本：撤销不可被新版本
          复活，要重新授权必须换 ``grant_id``。
        - TTL 超过 :data:`MAX_GRANT_TTL_SECONDS`、时间戳不可解析、动作越界、
          ``resource_ids`` 与 ``consent_versions`` 不一致 → ``MemoryValidationError``，
          且**不落任何行**（单事务）。
        - 库文件缺失 / 权限过宽 / symlink / schema 版本不符 → ``StoreError``。
        """

        _validate_grant_for_issue(grant)
        self._require_not_from_the_future(grant)
        db = self._write_connection()
        with closing(db):
            try:
                db.execute("BEGIN IMMEDIATE")
                rows = db.execute(
                    "SELECT version, revoked_at FROM grant_record WHERE grant_id = ?",
                    (grant.grant_id,),
                ).fetchall()
                if any(row[1] for row in rows):
                    raise MemoryValidationError(
                        f"grant {grant.grant_id} was revoked; a new version cannot revive it "
                        "(issue a new grant_id instead)"
                    )
                max_version = max((row[0] for row in rows), default=0)
                if grant.version <= max_version:
                    raise MemoryValidationError(
                        f"grant {grant.grant_id} version must increase: "
                        f"{grant.version} <= {max_version}"
                    )
                db.execute(
                    f"INSERT INTO grant_record ({', '.join(_GRANT_COLUMNS)}) "
                    f"VALUES ({', '.join('?' for _ in _GRANT_COLUMNS)})",
                    (
                        grant.grant_id,
                        grant.version,
                        grant.session_id,
                        grant.subject_id,
                        grant.owner_id,
                        grant.audience_id,
                        grant.issuer,
                        grant.issued_at,
                        grant.expires_at,
                    ),
                )
                db.executemany(
                    "INSERT INTO grant_action (grant_id, grant_version, action) VALUES (?, ?, ?)",
                    [(grant.grant_id, grant.version, action) for action in sorted(grant.actions)],
                )
                db.executemany(
                    "INSERT INTO grant_resource "
                    "(grant_id, grant_version, record_id, consent_version) VALUES (?, ?, ?, ?)",
                    [
                        (grant.grant_id, grant.version, record_id, consent_version)
                        for record_id, consent_version in sorted(grant.consent_versions)
                    ],
                )
                db.execute("COMMIT")
            except BaseException as exc:
                self._rollback(db)
                if isinstance(exc, sqlite3.Error):
                    raise StoreError(f"cannot issue memory grant: {exc}") from exc
                raise

    def _require_not_from_the_future(self, grant: Grant) -> None:
        """B-s1：拒绝 ``issued_at`` 超前的 grant（允许 ≤ :data:`GRANT_ISSUED_AT_SKEW_SECONDS`）。

        ``issued_at`` 超前意味着这个窗口还没开始 —— 签下去等于给未来预支一段授权，
        而 12h 的长度上限对此毫无约束。时钟不可解析时 fail-closed 同样拒绝。
        """

        issued_at = _parse_instant(grant.issued_at)
        now = _parse_instant(self._clock())
        if issued_at is None or now is None:
            raise MemoryValidationError("grant issued_at must be an ISO-8601 UTC timestamp")
        if (issued_at - now).total_seconds() > GRANT_ISSUED_AT_SKEW_SECONDS:
            raise MemoryValidationError(
                f"grant issued_at {grant.issued_at} is in the future "
                f"(now={now.isoformat()}, allowed skew={GRANT_ISSUED_AT_SKEW_SECONDS}s)"
            )

    def revoke(self, grant_id: str, *, revoked_at: str, actor: Actor) -> None:
        """撤销该 ``grant_id`` 的**全部版本**，撤销后任何版本都不再有效。

        - 只有 ``actor.kind == "adult_control_plane"`` 可以撤销：撤销改变「应用这次能
          读什么」，属召回语义（契约 §2.4）。其它 kind 抛 ``MemoryValidationError``
          —— 契约没有为这条路径指定异常类型（W2 已上报），这里按「入参形状非法」处理。
        - 重复撤销是幂等 no-op，且**保留首次撤销时间戳**（``WHERE revoked_at IS NULL``）；
          未知 ``grant_id`` 同样 no-op（无行可改，不报错）。
        """

        _require_text(grant_id, "grant_id")
        if not isinstance(actor, Actor) or actor.kind != "adult_control_plane":
            raise MemoryValidationError(
                "only adult_control_plane may revoke memory grants"
            )
        _require_text(actor.actor_id, "actor_id")
        if _parse_instant(revoked_at) is None:
            raise MemoryValidationError("revoked_at must be an ISO-8601 UTC timestamp")

        db = self._write_connection()
        with closing(db):
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "UPDATE grant_record SET revoked_at = ? "
                    "WHERE grant_id = ? AND revoked_at IS NULL",
                    (revoked_at, grant_id),
                )
                db.execute("COMMIT")
            except BaseException as exc:
                self._rollback(db)
                if isinstance(exc, sqlite3.Error):
                    raise StoreError(f"cannot revoke memory grant: {exc}") from exc
                raise

    # ---------------------------------------------------------------- 读取

    def load_current(self, grant_id: str) -> Grant | None:
        """取该 ``grant_id`` 的最新未撤销版本；已撤销或无行返回 ``None``。"""

        _require_text(grant_id, "grant_id")
        return self._load_one(
            "SELECT " + ", ".join(_GRANT_COLUMNS) + " FROM grant_record "
            "WHERE grant_id = ? AND revoked_at IS NULL "
            "ORDER BY version DESC LIMIT 1",
            (grant_id,),
        )

    def load_for_session(self, session_id: str) -> Grant | None:
        """取该会话当前有效的 grant（= 该 session 的最新未撤销版本）；无则 ``None``。

        **不得替 ``authorize()`` 过滤过期**：过期的 grant 仍要返回，让判权给出
        ``expired`` 而不是 ``no_grant``（契约在方法 docstring 里明确要求）。

        「最新」的排序口径（契约未再细化，这里定死并测试）：先比 ``issued_at``（ISO-8601
        字符串比较），再比 ``version``，最后比插入顺序 ``rowid``。行是追加写且从不删除，
        因此 ``rowid`` 就是签发顺序，能给所有并列情况一个确定性结果。
        """

        _require_text(session_id, "session_id")
        return self._load_one(
            "SELECT " + ", ".join(_GRANT_COLUMNS) + " FROM grant_record "
            "WHERE session_id = ? AND revoked_at IS NULL "
            "ORDER BY issued_at DESC, version DESC, rowid DESC LIMIT 1",
            (session_id,),
        )

    # ---------------------------------------------------------------- 内部

    @staticmethod
    def _rollback(db: sqlite3.Connection) -> None:
        """尽力回滚；``BEGIN`` 本身失败时没有活动事务，回滚报错不是新故障。"""

        try:
            db.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _load_one(self, sql: str, params: tuple[str, ...]) -> Grant | None:
        db = self._read_connection()
        if db is None:
            return None  # 库还不存在 = 这个家庭还没有任何 grant，不是错误
        with closing(db):
            try:
                row = db.execute(sql, params).fetchone()
                if row is None:
                    return None
                return self._row_to_grant(db, row)
            except sqlite3.Error as exc:
                raise StoreError(f"cannot read memory grants: {exc}") from exc

    def _check_private_file(self, *, must_exist: bool) -> bool:
        """symlink / 权限位检查。返回文件是否存在；``must_exist`` 时缺失即 ``StoreError``。"""

        try:
            if self.path.is_symlink():
                raise StoreError(f"memory database must not be a symlink: {self.path}")
            if not self.path.exists():
                if must_exist:
                    raise StoreError(
                        f"memory database does not exist: {self.path} "
                        "(create the schema with SqliteMemoryStore.create_schema() first)"
                    )
                return False
            if not self.path.is_file():
                raise StoreError(f"memory database path is not a regular file: {self.path}")
            mode = stat.S_IMODE(self.path.stat().st_mode)
        except OSError as exc:
            raise StoreError(f"cannot inspect memory database {self.path}: {exc}") from exc
        if mode & 0o077:
            raise StoreError(
                f"memory database permissions are too broad ({mode:o}); "
                "restrict it to owner access with chmod 600"
            )
        return True

    @staticmethod
    def _check_schema(db: sqlite3.Connection) -> None:
        try:
            check = db.execute("PRAGMA quick_check").fetchone()
            version = db.execute("PRAGMA user_version").fetchone()
            tables = {
                row[0]
                for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
        except sqlite3.Error as exc:
            raise StoreError(f"invalid memory database: {exc}") from exc
        if check is None or check[0] != "ok":
            raise StoreError("memory database failed the integrity check (PRAGMA quick_check)")
        if version is None or version[0] != MEMORY_SCHEMA_VERSION:
            raise StoreError(
                "memory database schema version mismatch: "
                f"expected {MEMORY_SCHEMA_VERSION}, found {version[0] if version else None}"
            )
        missing = GRANT_TABLES - tables
        if missing:
            raise StoreError(f"memory database is missing grant tables: {sorted(missing)}")

    def _write_connection(self) -> sqlite3.Connection:
        self._check_private_file(must_exist=True)
        return self._open(readonly=False)

    def _read_connection(self) -> sqlite3.Connection | None:
        if not self._check_private_file(must_exist=False):
            return None
        return self._open(readonly=True)

    def _open(self, *, readonly: bool) -> sqlite3.Connection:
        try:
            if readonly:
                uri = f"file:{quote(self.path.resolve().as_posix())}?mode=ro"
                db = sqlite3.connect(
                    uri, uri=True, timeout=self._busy_timeout_seconds
                )
            else:
                # ``isolation_level=None`` = 自己管事务：issue/revoke 都显式
                # ``BEGIN IMMEDIATE``，否则「先读最大版本再写」会有竞态窗口。
                db = sqlite3.connect(
                    self.path,
                    isolation_level=None,
                    timeout=self._busy_timeout_seconds,
                )
        except (OSError, sqlite3.Error) as exc:
            raise StoreError(f"cannot open memory database {self.path}: {exc}") from exc
        try:
            self._check_schema(db)
        except BaseException:
            db.close()
            raise
        return db

    @staticmethod
    def _row_to_grant(db: sqlite3.Connection, row: tuple) -> Grant:
        (
            grant_id,
            version,
            session_id,
            subject_id,
            owner_id,
            audience_id,
            issuer,
            issued_at,
            expires_at,
        ) = row
        actions = frozenset(
            item[0]
            for item in db.execute(
                "SELECT action FROM grant_action WHERE grant_id = ? AND grant_version = ?",
                (grant_id, version),
            )
        )
        consents = tuple(
            (item[0], item[1])
            for item in db.execute(
                "SELECT record_id, consent_version FROM grant_resource "
                "WHERE grant_id = ? AND grant_version = ? ORDER BY record_id",
                (grant_id, version),
            )
        )
        return Grant(
            grant_id=grant_id,
            version=version,
            session_id=session_id,
            subject_id=subject_id,
            owner_id=owner_id,
            audience_id=audience_id,
            actions=actions,
            resource_ids=frozenset(record_id for record_id, _ in consents),
            consent_versions=consents,
            expires_at=expires_at,
            issuer=issuer,
            issued_at=issued_at,
        )


def load_grant_for_session(db_path: Path, session_id: str) -> Grant | None:
    """投影接缝（契约 §10.1）用的薄封装：打开 store 再按会话取 grant。

    只有 ``session_id`` 可用（没有 ``grant_id``），这正是 ``GrantStore`` 需要
    ``load_for_session`` 的原因。库不存在时返回 ``None`` —— 调用方（W4）据此拿到
    ``grant=None``，投影自然退化为空，不影响 instructions。
    """

    return SqliteGrantStore(db_path).load_for_session(session_id)
