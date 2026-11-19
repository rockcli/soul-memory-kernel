"""M2 SQLite schema 与持久化接口（W0 冻结 DDL + Protocol；W1 实现 ``SqliteMemoryStore``）。

本模块有两部分：

1. **DDL 字符串常量与 Protocol 签名（W0 冻结，W1 只读不改）** —— schema 是所有 writer
   的共同边界：W1 实现存储、W2 实现授权、W3 实现服务、W4 接投影、W5 写 CLI，五者必须
   对表名、列名、约束有完全一致的认知。把它冻在一处，比让 W1 边写边定更安全。
2. **``SqliteMemoryStore``（W1 实现）** —— DDL 落库、CRUD、状态迁移、血缘解析、
   到期扫描与候选硬删除、``deletion_audit`` 行。

**``SqliteGrantStore`` 不在这里**（A10）：它归 ``family_ai/memory/grants.py``（W2）。
本模块只冻结 :class:`GrantStore` Protocol；``__init__.py`` 从 ``grants`` 导入实现类。

沿用 M1 ``FamilyProfileStore`` 的产品级约束（逐条照抄，不重新发明）：
0600 独占创建、symlink 拒绝、``PRAGMA user_version`` 校验、``PRAGMA quick_check``、
投影路径只用 ``mode=ro`` URI 只读连接、``BEGIN IMMEDIATE`` 建表。

W1 的两条实现纪律：

- **写入前校验，读取时不校验。** 违约数据（``policy_denied`` 的四种情形）必须能被读
  出来交给 ``authorize()`` 判拒绝，所以读取路径只做列映射；反过来，任何**写入**都要先
  过 :func:`_record_violations`，不允许把违反契约的记录塞进库。
- **错误类型按契约页 §4.7**：存储 / 文件系统故障抛 ``StoreError``，形状非法抛
  ``MemoryValidationError``，非法迁移或越权 actor 抛 ``IllegalTransition``。这三个类
  定义在 ``service.py``，而 ``service.py`` 在模块级导入本模块，所以这里**在调用点
  延迟导入**，避免 ``store → service → store`` 的循环导入。
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

from soul_memory_kernel.memory.model import (
    ACTOR_KINDS,
    MAX_CONTENT_CHARS,
    DeletionOutcome,
    LEGAL_TRANSITIONS,
    MEMORY_CLASSES,
    MEMORY_POLICIES,
    MEMORY_STATUSES,
    SCOPES,
    SOURCE_TYPES,
    STATUS_POLICY_INVARIANT,
    TTL_TRANSITIONS,
    Actor,
    Grant,
    MemoryRecord,
    MigrationReport,
)

#: schema 版本。与 ``FamilyProfileStore.PROFILE_SCHEMA_VERSION`` 同风格：
#: 版本不符一律拒绝读取，不做静默迁移。
#:
#: - **v2（A12）**给 ``memory_record`` 加了写入归属 ``actor_kind`` / ``actor_id``；
#: - **v3（M2.2 T9）**加两件事：① ``content_over_length``（500 字上限下沉 + 历史超长行
#:   的标记处置）；② ``extraction_usage`` 表（§3.9 的每日提取熔断计数）。
#:
#: v1 的库会在打开时**一次走完 v1→v2→v3**（见 :meth:`SqliteMemoryStore._open_or_migrate`），
#: **两段各自一个事务**（SQLite 不允许嵌套事务，``foreign_keys`` 也不能在事务内切换）。
MEMORY_SCHEMA_VERSION = 3

#: **打开即迁移**：任何连接打开本模块的库时，v1 会被就地升到 v2（见
#: :meth:`SqliteMemoryStore._migrate_v1_to_v2`）。迁移是加法且幂等；不迁移就没法读
#: —— 列不齐会被 schema 校验拒绝。因此「先跑一次 family-ai-memory list」即可完成迁移。

#: 授权的有效期上限（秒）。D1 的「短期 grant」需要一个可核查的上界，
#: 否则「短期」只是形容词。W2 签发时超过此值必须拒绝。
#:
#: **主控 2026-09-26 裁决：维持 12h，不为迁就 fixture 放宽隐私参数。**
#: 集成中途曾短暂调到 24h 以适配设计 fixture 的 24h 窗口，该改动已回滚；
#: 反过来把 fixture 的 ``grant-a-s1`` 窗口缩到 12h（见契约 §8.1）。
MAX_GRANT_TTL_SECONDS = 12 * 60 * 60

#: ``memory_record`` 表。
#:
#: 五条 CHECK 是硬不变量，不是注释：
#:  1. ``scope='SAFETY'`` ⇒ ``memory_class='SAFETY'``：安全 scope 的内容类型必须是安全类。
#:     （M2.1 不写 ``scope='SAFETY'``，这条为 M2.2+ 保留，不因相位而删。）
#:  2. ``expires_at`` 只有在「**已确认的 SAFETY 类**」记录上才允许为空。等价表述：
#:     **候选一律有期限，包括 SAFETY 类候选**；只有确认后的 SAFETY 类才不过期（D5）。
#:     这条修正了旧版「SAFETY 类候选可以永不过期」的漏洞。
#:  3. ``FAMILY`` 且 ``ACTIVE`` ⇒ 必须有 ``last_confirmed_at``：未经确认的家庭共享
#:     记忆不允许处于可召回状态。
#:  4. ``status`` 与 ``memory_policy`` 必须符合 :data:`STATUS_POLICY_INVARIANT`
#:     （``DELETED`` 墓碑保留删除时的策略值，不参与该约束）。
#:  5. **v3 新增（T9c）**：``content_over_length = 1 OR length(content) <= 500`` ——
#:     历史超长行放行、新行受限。**表级 CHECK 必须排在所有列定义之后**，而本字符串是
#:     「列 + 末尾表级 CHECK」结构：把新 CHECK 插在列中间会得到
#:     ``near "actor_kind": syntax error``（契约 §6 T9d 点名的实现陷阱）。
#:
#: 另有两条安全兜底：
#:
#:  - ``memory_policy`` 的 CHECK **刻意排除 ``do_not_persist``** —— 该策略的正确落点是
#:    「写入前拦截」，不是「写进去再标记」。库内出现该值即为契约违规（读路径报
#:    ``policy_denied``）。
#:  - ``DELETED`` 墓碑行的 ``content`` 必须为空字符串 —— 即使墓碑真的出现，
#:    也不可能带着正文。
MEMORY_RECORD_DDL = """
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
    actor_kind        TEXT    NOT NULL CHECK (
                          actor_kind IN ('adult_control_plane','session_proposal',
                                         'ttl_expiry','migration')),
    actor_id          TEXT    NOT NULL,
    content_over_length INTEGER NOT NULL DEFAULT 0
                        CHECK (content_over_length IN (0,1)),
    CHECK (scope <> 'SAFETY' OR memory_class = 'SAFETY'),
    CHECK (expires_at IS NOT NULL
           OR (memory_class = 'SAFETY' AND status IN ('ACTIVE','DECAYED'))),
    CHECK (scope <> 'FAMILY' OR status <> 'ACTIVE' OR last_confirmed_at IS NOT NULL),
    CHECK (status = 'DELETED'
           OR (status = 'PENDING_CONFIRMATION' AND memory_policy = 'candidate_only')
           OR (status IN ('ACTIVE','DECAYED') AND memory_policy = 'persist_confirmed')),
    CHECK (status <> 'DELETED' OR content = ''),
    CHECK (content_over_length = 1 OR length(content) <= 500)
)
""".strip()

#: 受众表。``audiences`` 是集合，不塞进单列做逗号拼接 —— 拼接会让
#: 「audience_id IN (...)」这类判权查询退化成全表扫描加字符串解析。
#:
#: ``ON DELETE CASCADE`` 是安全的：记录没了，它的受众行没有独立意义。
MEMORY_AUDIENCE_DDL = """
CREATE TABLE memory_audience (
    record_id   TEXT NOT NULL REFERENCES memory_record(id) ON DELETE CASCADE,
    audience_id TEXT NOT NULL,
    PRIMARY KEY (record_id, audience_id)
)
""".strip()

#: 派生来源表（血缘）。
#:
#: **``source_id`` 刻意不加外键。** 若加 ``ON DELETE CASCADE``，删除来源记录会
#: 把血缘行一起抹掉，派生记录就会「看起来没有祖先」而被当成干净记录继续召回 ——
#: 这正是最危险的越权路径。加了引用完整性则删除来源会被 FK 挡住，删除无法完成。
#: 因此选择：**血缘行在来源被删后保留**，解析时发现 ``source_id`` 指向不存在的
#: 记录即按 ``missing_provenance`` 拒绝（对齐原型 ``PrivacyKernel._resolve``）。
#: **A2：删除动作不连带删除派生记录**，只在 ``DeletionReport.derived_unreachable``
#: 里如实列出它们（仍在盘上、已永久不可召回）。
MEMORY_SOURCE_DDL = """
CREATE TABLE memory_source (
    record_id TEXT    NOT NULL REFERENCES memory_record(id) ON DELETE CASCADE,
    source_id TEXT    NOT NULL,
    ordinal   INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (record_id, source_id)
)
""".strip()

#: grant 表。``PRIMARY KEY (grant_id, version)`` = 追加写：每次续签是新行，
#: 旧版本保留供审计。撤销写 ``revoked_at`` 到该 ``grant_id`` 的**全部**行，
#: 因此撤销不可被新版本"复活"；要重新授权必须新建 ``grant_id``。
MEMORY_GRANT_DDL = """
CREATE TABLE grant_record (
    grant_id    TEXT    NOT NULL,
    version     INTEGER NOT NULL CHECK (version >= 1),
    session_id  TEXT    NOT NULL,
    subject_id  TEXT    NOT NULL,
    owner_id    TEXT    NOT NULL,
    audience_id TEXT    NOT NULL,
    issuer      TEXT    NOT NULL,
    issued_at   TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    revoked_at  TEXT    NULL,
    PRIMARY KEY (grant_id, version)
)
""".strip()

MEMORY_GRANT_ACTION_DDL = """
CREATE TABLE grant_action (
    grant_id      TEXT    NOT NULL,
    grant_version INTEGER NOT NULL,
    action        TEXT    NOT NULL CHECK (
                      action IN ('read_model','send_provider','publish_text',
                                 'play_audio','write','share','delete')),
    PRIMARY KEY (grant_id, grant_version, action)
)
""".strip()

#: 逐资源同意版本绑定。派生记录必须连同每个祖先都在这里有行且版本相符，
#: 否则 ``stale_consent`` 拒绝（对齐原型 ``_allows`` 的 consent 检查）。
MEMORY_GRANT_RESOURCE_DDL = """
CREATE TABLE grant_resource (
    grant_id        TEXT    NOT NULL,
    grant_version   INTEGER NOT NULL,
    record_id       TEXT    NOT NULL,
    consent_version INTEGER NOT NULL CHECK (consent_version >= 1),
    PRIMARY KEY (grant_id, grant_version, record_id)
)
""".strip()

#: 删除审计。**只存 record_id 与计数，绝不存正文** —— 审计表本身不能变成
#: 新的留存泄漏点。
MEMORY_DELETION_AUDIT_DDL = """
CREATE TABLE deletion_audit (
    audit_id      TEXT    PRIMARY KEY,
    record_id     TEXT    NOT NULL,
    actor_kind    TEXT    NOT NULL CHECK (
                      actor_kind IN ('adult_control_plane','session_proposal',
                                     'ttl_expiry','migration')),
    actor_id      TEXT    NOT NULL,
    deleted_at    TEXT    NOT NULL,
    tables_touched TEXT   NOT NULL,
    derived_removed INTEGER NOT NULL CHECK (derived_removed >= 0),
    unknown_copies TEXT   NOT NULL
)
""".strip()

#: 提取预算计数表（**v3 新增，§3.9 T27**）。**只存计数，不存正文、不存 id。**
#:
#: 每天一行（``day`` 是注入时钟的 ``YYYY-MM-DD``，UTC）。判定用**一条** upsert 完成
#: 「递增并判定」（见 :meth:`SqliteMemoryStore.consume_extraction_budget`）：
#: 「先查后写」在两个 console 进程同时跑时会同时越界。
#:
#: **上限是「每记忆库」的，不是「每用户 / 每设备」的** —— 换 ``--db`` / 删库即归零。
#: 它是**成本熔断，不是安全边界**；真正的安全边界是提取的本地门 0–3 与
#: 「模型只产出候选」。**策略（会话计数、限额、fail-closed）不在这里**：
#: 闸住 ``family_ai/extraction/budget.py``（W7b），本模块只提供无策略的 DB 原语。
MEMORY_EXTRACTION_USAGE_DDL = """
CREATE TABLE extraction_usage (
    day        TEXT    PRIMARY KEY,
    call_count INTEGER NOT NULL CHECK (call_count >= 0)
)
""".strip()

#: 迁移用的幂等形态（契约 §6 T9b 步骤 8 逐字要求 ``CREATE TABLE IF NOT EXISTS``）。
#: 由上面那份定义派生，避免两处表定义漂移。
MEMORY_EXTRACTION_USAGE_MIGRATION_DDL = MEMORY_EXTRACTION_USAGE_DDL.replace(
    "CREATE TABLE extraction_usage", "CREATE TABLE IF NOT EXISTS extraction_usage", 1
)

#: 建表顺序即依赖顺序（W1 的 ``_create_schema`` 必须按此顺序执行）。
MEMORY_SCHEMA_DDL: tuple[str, ...] = (
    MEMORY_RECORD_DDL,
    MEMORY_AUDIENCE_DDL,
    MEMORY_SOURCE_DDL,
    MEMORY_GRANT_DDL,
    MEMORY_GRANT_ACTION_DDL,
    MEMORY_GRANT_RESOURCE_DDL,
    MEMORY_DELETION_AUDIT_DDL,
    MEMORY_EXTRACTION_USAGE_DDL,
)

#: 上述 DDL 建立的全部表名。测试与删除清单用它核对「枚举到的表」是否完整。
MEMORY_TABLES: frozenset[str] = frozenset(
    {
        "memory_record",
        "memory_audience",
        "memory_source",
        "grant_record",
        "grant_action",
        "grant_resource",
        "deletion_audit",
        "extraction_usage",
    }
)

# --------------------------------------------------------------------------
# 持久化接口（Protocol；实现在 W1）
# --------------------------------------------------------------------------


class MemoryStore(Protocol):
    """记忆持久化。**投影路径只允许调用 ``read_*``**，且必须是 ``mode=ro`` 连接。"""

    path: Path

    def create_schema(self) -> MigrationReport | None:
        """首次创建 schema。必须用 ``BEGIN IMMEDIATE`` + ``PRAGMA user_version``。

        **M2.2 T9b**：打开时就地迁移（v1 → v2 → v3，两段各自一个事务）时返回
        :class:`~soul_memory_kernel.memory.model.MigrationReport`，否则返回 ``None``。
        """

        raise NotImplementedError

    def read_record(self, record_id: str) -> MemoryRecord | None:
        """读单条记录（含受众与血缘）。读不到返回 ``None``，不抛异常。"""

        raise NotImplementedError

    def read_records(self, record_ids: tuple[str, ...]) -> tuple[MemoryRecord, ...]:
        """批量读。**缺任何一条都返回缺源信号**，由调用方按 ``missing_provenance`` 处理。"""

        raise NotImplementedError

    def list_eligible(
        self,
        *,
        owner_id: str | None,
        audience_id: str,
        scopes: tuple[str, ...],
        statuses: tuple[str, ...],
    ) -> tuple[str, ...]:
        """列出本次会话**可能**可读的记录 id（仍未判权）。

        这是 ``query()`` 的入口查询：先按 owner / 受众 / scope / 状态缩范围，
        再逐条交给 ``authorize()``。**本方法不做授权判定**，它只保证「不会漏掉
        授权范围内的记录」；多返回的记录由 ``authorize()`` 拒绝。
        """

        raise NotImplementedError

    def resolve_provenance(self, record_ids: tuple[str, ...]) -> tuple[MemoryRecord, ...]:
        """递归解析祖先闭包。缺源、成环、未登记来源一律拒绝（fail-closed）。"""

        raise NotImplementedError

    def write_record(self, record: MemoryRecord, *, actor: Actor) -> None:
        """插入或整体替换一条记录及其受众、血缘。``do_not_persist`` 不得到达这里。"""

        raise NotImplementedError

    def transition(
        self,
        record_id: str,
        to_status: str,
        *,
        actor: Actor,
        updated_at: str,
        consent_version: int,
        last_confirmed_at: str | None,
    ) -> MemoryRecord:
        """状态迁移。非法迁移必须抛 ``IllegalTransition``，不得静默 no-op。"""

        raise NotImplementedError

    def hard_delete(self, record_id: str) -> tuple[str, ...]:
        """**磁盘删除**：``DELETE`` 行，不是标记。返回实际触及的表名。

        血缘口径（A2 统一，契约页 §7.1 / §7.4）：

        - **删除** ``memory_source`` 中该记录**作为子节点**的行
          （``WHERE record_id = ?``）—— 它自己的来源关系随它一起消失；
        - **保留** ``memory_source`` 中**指向它**的行（``WHERE source_id = ?``）——
          绝不连带删除，也绝不连带删除派生记录。派生记录因此会在
          :meth:`resolve_provenance` 命中缺源，按 ``missing_provenance`` 永久 fail-closed。

        另需清理 ``memory_audience``（级联）与 ``grant_resource`` 中指向该 id 的行。

        **产品路径不要直接调用本方法**（A11）：删除与审计必须原子，走
        :meth:`hard_delete_with_audit`。本方法与 :meth:`write_deletion_audit` 是它的
        两个构件，各自开事务，分开调用会让「删成功但审计缺失」成为可能。
        """

        raise NotImplementedError

    def enumerate_dependents(self, record_id: str) -> tuple[str, ...]:
        """枚举血缘上**指向**该记录的派生记录。

        用于**报告**（写进 ``DeletionReport.derived_unreachable``），**不用于删除** ——
        删除动作不碰派生记录（A2：只删它自己作为子节点的血缘行，指向它的血缘行保留，
        派生记录靠 ``missing_provenance`` 永久 fail-closed）。
        """

        raise NotImplementedError

    def hard_delete_with_audit(
        self,
        *,
        record_id: str,
        actor: Actor,
        deleted_at: str,
        derived_removed: int = 0,
        unknown_copies: tuple[str, ...] = (),
    ) -> DeletionOutcome:
        """**A11：删除与审计在同一事务内完成**（主控 2026-09-26 裁决）。

        等价于 :meth:`hard_delete` + :meth:`write_deletion_audit`，但**共用一次
        ``BEGIN IMMEDIATE`` / 一次 ``COMMIT``**。分开调用会让「行已删掉、审计没写成」
        成为可能 —— 那正是 §7.1 第 9 项与 §4.4「不能报成功」明令禁止的状态。

        语义：

        - 成功：返回 :class:`~soul_memory_kernel.memory.model.DeletionOutcome`，
          ``tables_touched`` 是**真的删掉了行**的表（``rowcount > 0``）并**已含**
          ``deletion_audit``；
        - 任何一步失败：**整体回滚** —— 记录仍在、受众行仍在、``grant_resource`` 行仍在、
          ``deletion_audit`` **0 行**，并抛 ``StoreError``；
        - **目标行不存在：抛 ``RecordNotFound`` 且不写审计**（主控 2026-09-26）。
          审计表是「删除事实」的凭据，写入一条没删过任何行的条目会让审计失真
          （§7.3 的同一纪律：不得把「没发生」写成「已发生」）。检查与删除在同一事务内，
          因此抛错时不会有任何半成品状态；
        - actor 校验与 :meth:`write_deletion_audit` 完全一致：只允许
          ``adult_control_plane``（成人显式删除）与 ``ttl_expiry``（候选到期硬删）。
        """

        raise NotImplementedError

    def list_expired(self, *, now: str) -> tuple[MemoryRecord, ...]:
        """列出 ``expires_at <= now`` 且**仍有到期动作要做**的记录（A1 增补）。

        ``sweep_expired()`` 的两条路径都需要先枚举到期对象，而 :meth:`list_eligible`
        是按受众查「可能可读」的记录，枚举不到尚无受众的候选。返回的记录带完整字段
        （受众 + 血缘），调用方按 ``status`` 分派：

        - ``ACTIVE`` → 状态迁移 ``ACTIVE → DECAYED``（不删盘，D5）；
        - ``PENDING_CONFIRMATION`` → :meth:`hard_delete` + :meth:`write_deletion_audit`
          （候选到期是硬删除，不是状态翻转）。

        ``expires_at`` 为空（已确认的 ``SAFETY`` 类）永不到期，不出现在结果里。
        库内 ``expires_at`` 不可解析属数据损坏：**抛 ``StoreError`` 而不是当成已到期**
        —— 在无法判断是否到期时删数据是最危险的选择。
        ``now`` 必须是带时区的 ISO-8601；不可解析即 fail-closed，
        抛 ``MemoryValidationError``。

        **签名以 W1 的实现为准**：返回 ``tuple[MemoryRecord, ...]`` 而非 id 元组 ——
        调用方需要 ``status`` 来分派两条路径，只给 id 会逼出第二次查询。
        """

        raise NotImplementedError

    def write_deletion_audit(
        self,
        *,
        record_id: str,
        actor: Actor,
        deleted_at: str,
        tables_touched: tuple[str, ...],
        derived_removed: int = 0,
        unknown_copies: tuple[str, ...] = (),
    ) -> str:
        """写一条 ``deletion_audit`` 行并返回 ``audit_id``（A1 增补）。

        ``hard_delete()`` 的冻结签名里没有 actor 与时间（它只做行删除），而 Protocol
        原本没有提供写审计的方法，因此补上这一个原语，让 ``DeletionReport.audit_id``
        有确定的来源。

        **审计表只存 record_id 与计数，绝不存正文**（§7.3）—— 参数里没有正文通道。
        ``tables_touched`` / ``unknown_copies`` 以 JSON 数组落库。

        ``migration`` actor 可能删掉审计痕迹，因此**不得写审计行**：抛
        ``MemoryValidationError``。入参形状非法（空 ``record_id`` / 空 ``actor_id``、
        ``deleted_at`` 不可解析、``derived_removed`` 为负）同样抛
        ``MemoryValidationError``。
        """

        raise NotImplementedError

    def consume_extraction_budget(self, day: str, limit: int) -> bool:
        """**M2.2（W9）新增**：当日提取预算的 DB 原子递增原语（§3.9 T27）。

        ``True`` = 获准且已计数（调用方随后**才**可以出网）；``False`` = 已到上限且
        **没有递增**。它**不含任何策略** —— 会话计数、限额来源与「读失败 ⇒ 不调用」
        的 fail-closed 判定住 ``family_ai/extraction/budget.py``（W7b），那里只调本原语。
        """

        raise NotImplementedError


class GrantStore(Protocol):
    """grant 持久化（实现在 W2 的 ``grants.py``）。"""

    def issue(self, grant: Grant) -> None:
        """签发。``version`` 必须递增；``issuer`` 必填；TTL 不得超过 ``MAX_GRANT_TTL_SECONDS``。

        **失败一律抛 ``MemoryValidationError``**（A6）：形状非法（含 ``issuer`` 为空、
        TTL 越界、动作取值未知、``resource_ids`` 与 ``consent_versions`` 覆盖不一致）
        都不落任何行。签发路径没有「授权不成立」这个中间态 —— 要么入参合法可签发，
        要么是非法入参。
        """

        raise NotImplementedError

    def revoke(self, grant_id: str, *, revoked_at: str, actor: Actor) -> None:
        """撤销该 ``grant_id`` 的**全部版本**。撤销后任何版本都不再有效。

        **``revoked_at`` 是存储层字段，判权函数永不读它**（A4）：撤销的效果是
        :meth:`load_current` / :meth:`load_for_session` 开始返回 ``None``，
        ``authorize()`` 于是给出 ``no_grant``。这样「已撤销」与「从未签发」在判权层
        不可区分，也就不存在「撤销状态没被读到」这个失败模式。

        actor 必须满足 ``kind == "adult_control_plane"``（撤销改变召回语义，§2.4）；
        否则抛 ``MemoryValidationError``（A6）。重复撤销幂等且保留首次时间戳。
        """

        raise NotImplementedError

    def load_current(self, grant_id: str) -> Grant | None:
        """取该 ``grant_id`` 的最新未撤销版本。已撤销或无行返回 ``None``。"""

        raise NotImplementedError

    def load_for_session(self, session_id: str) -> Grant | None:
        """取该**会话**当前有效的 grant。无有效 grant 返回 ``None``。

        这是会话投影接缝（契约页 §10.1）要用的查询：调用方只有 ``session_id``，
        没有 ``grant_id``。语义上等价于「该 session 的最新未撤销版本」；
        过期与否仍由 ``authorize()`` 的 ``expired`` 判定，本方法**不得**替它过滤，
        否则拒绝原因会从 ``expired`` 退化成 ``no_grant``，审计就查不出来了。

        **归属 W2**：实现在 ``family_ai/memory/grants.py``（连同薄封装
        ``load_grant_for_session(db_path, session_id)``）。
        """

        raise NotImplementedError


# --------------------------------------------------------------------------
# 具体实现类（W0 冻结**类名与构造签名**；方法集由上面的 Protocol 冻结）
#
# ``SqliteGrantStore`` 的桩已按**主控仲裁（2026-09-26）**从这里删除：它归 W2 的
# ``grants.py``（契约页 §9 的 W2 行）。``family_ai/memory/__init__.py`` 里对它的导入
# 由集成者在 W2 落地时改指 ``grants.py`` —— W1 不动 ``__init__.py``。
# --------------------------------------------------------------------------

#: ``memory_record`` 的完整列集（顺序即 SELECT / INSERT 的列顺序）。schema 校验也用它
#: 核对「这个文件真的是本版本的记忆库」，防止把 M1 家人档案库或别的东西当记忆库打开。
#:
#: 顺序与 ``MEMORY_RECORD_DDL`` 的列顺序一致 —— 迁移里的「两侧都写显式列名」正是靠它
#: 保证不会错列（契约 §6 T9b 步骤 4 的修正：**禁止** ``SELECT *, CASE …``）。
_RECORD_COLUMNS: tuple[str, ...] = (
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
    "content_over_length",
)

_MEMORY_RECORD_COLUMNS: frozenset[str] = frozenset(_RECORD_COLUMNS)

#: A12 的写入归属两列。它们由 ``write_record`` 从 ``actor`` 参数覆盖，不由调用方提供，
#: 因此**不在** :data:`_RECALL_SEMANTIC_FIELDS` 里（没有任何调用方能改到它们）。
ACTOR_COLUMNS: frozenset[str] = frozenset({"actor_kind", "actor_id"})

#: 「已确认」的两个状态。DDL 的 ``expires_at`` CHECK 与 STATUS_POLICY_INVARIANT 都用它。
_CONFIRMED_STATUSES: frozenset[str] = frozenset({"ACTIVE", "DECAYED"})

_RECORD_SELECT = ", ".join(_RECORD_COLUMNS)
_RECORD_PLACEHOLDERS = ", ".join("?" for _ in _RECORD_COLUMNS)
#: 整体替换语义：除主键外每一列都跟着新记录走。
_RECORD_UPSERT_SET = ", ".join(
    f"{column} = excluded.{column}" for column in _RECORD_COLUMNS if column != "id"
)

#: 「记录还不存在」的伪状态：只用于 ``IllegalTransition.from_status``，让「这个 actor
#: 不许新增记录」这件事也能带结构化字段抛错（不是合法 ``MemoryStatus`` 取值）。
_ABSENT_STATUS = "ABSENT"

#: **谁可以写 ``deletion_audit`` 行（B-s3 的策略面）。**
#:
#: ``adult_control_plane`` = 成人显式删除；``ttl_expiry`` = 候选到期硬删。
#: ``session_proposal`` 与 ``migration`` 不在其中：前者只能落候选，后者不得制造审计痕迹。
#:
#: 这与 DDL 的 ``deletion_audit.actor_kind`` CHECK **不是一回事**：CHECK 是取值枚举守卫
#: （四个 ``ACTOR_KINDS`` 都在里面，任何越权 actor 因此不会被糊成 ``CHECK constraint
#: failed``），而「谁有权写」是策略，住在这里。
_DELETION_AUDIT_ACTOR_KINDS: frozenset[str] = frozenset({"adult_control_plane", "ttl_expiry"})

#: **召回语义字段**：改变它们就等于改变「谁能召回什么」。``ttl_expiry`` 与 ``migration``
#: 一律不得改动（§2.4 的允许 / 禁止清单），``adult_control_plane`` 可以改。
#: ``expires_at`` 也在里面：改写期限等于偷偷延长或提前终止召回。
_RECALL_SEMANTIC_FIELDS: tuple[str, ...] = (
    "owner_id",
    "scope",
    "memory_class",
    "source_type",
    "source_member_id",
    "content",
    "audiences",
    "source_ids",
    "memory_policy",
    "consent_version",
    "expires_at",
)

#: ``ttl_expiry`` **额外**不得碰的字段：它只做「停止召回」这一件事，不整理历史时间戳，
#: 也不改来源会话链接（``updated_at`` 允许改 —— 扫描要留痕）。
_TTL_IMMUTABLE_FIELDS: tuple[str, ...] = (
    "created_at",
    "last_confirmed_at",
    "source_session_id",
)

#: M2.1 **有产出路径**的状态迁移 = 全表减去三条「历史墓碑 / M2.2+ 延迟删除」边。
#:
#: 契约页 §2.3 给这三条边标注了「M2.1 产出 ✘」且 actor 为「—」：M2.1 的删除一律是
#: **硬删除**，不产出墓碑。它们保留在 :data:`LEGAL_TRANSITIONS` 里是为了**读取/导入**
#: 历史墓碑数据（那走插入，不是迁移），所以这里把它们从「可执行迁移」里剔除。
_M2_1_PRODUCIBLE_TRANSITIONS: frozenset[tuple[str, str]] = LEGAL_TRANSITIONS - {
    ("PENDING_CONFIRMATION", "DELETED"),
    ("ACTIVE", "DELETED"),
    ("DECAYED", "DELETED"),
}

#: v2→v3 的**暂存表**定义（步骤 3）。从 :data:`MEMORY_RECORD_DDL` **派生**：
#: 两处各写一份表定义迟早会漂移，而漂移过的重建表正是最难查的一类迁移缺陷。
_MEMORY_RECORD_V3_DDL: str = MEMORY_RECORD_DDL.replace(
    "CREATE TABLE memory_record ", "CREATE TABLE memory_record__v3 ", 1
)

#: **v2 的** ``memory_record`` 列集 = v3 列集减去 v3 新增的那一列。
#:
#: 重建前用它比对 ``PRAGMA table_info(memory_record)``：**多出来的列一律报错回滚**
#: （审阅 A 建议 2）。重建表只按 :data:`_RECORD_COLUMNS` 拷贝，因此库里若有一列
#: 不在这个集合里（手工改库、并行分支、厂商列），它会**静默消失** —— 那与
#: 「宁可响亮失败，不静默丢数据」的整条迁移纪律相悖（R13 的孤儿行就是这么处理的）。
_V2_RECORD_COLUMNS: tuple[str, ...] = tuple(
    column for column in _RECORD_COLUMNS if column != "content_over_length"
)

#: v2→v3 的拷贝语句（步骤 4）。**两侧都写显式列名**（A 的 N1）：
#: ``SELECT *, CASE …`` 依赖列排列，新列若插在中间就会静默错列 —— 实测错列会撞
#: ``content_over_length IN (0,1)`` 而回滚，但若没有那条 CHECK 就会把 ``actor_id``
#: 写成 ``1/0``，属于最难查的一类数据损坏。
#: 目标列与来源列都由 :data:`_RECORD_COLUMNS` 生成，只有 ``content_over_length``
#: 一列在来源侧换成按正文长度算出来的 CASE。
_V3_COPY_SELECT: str = ", ".join(
    "CASE WHEN length(content) > 500 THEN 1 ELSE 0 END"
    if column == "content_over_length"
    else column
    for column in _RECORD_COLUMNS
)
_COPY_INTO_V3_SQL: str = (
    f"INSERT INTO memory_record__v3 ({_RECORD_SELECT}) "
    f"SELECT {_V3_COPY_SELECT} FROM memory_record"
)


def _placeholders(values: tuple[str, ...]) -> str:
    """生成 ``?, ?, ?``（SQLite 不接受把 ``IN`` 的列表当单个参数绑定）。"""

    return ", ".join("?" for _ in values)


def _in(value: object, allowed: frozenset[str]) -> bool:
    """``value in allowed``，但把非字符串 / 不可哈希的输入当成「不在集合里」。

    形状校验要报 ``MemoryValidationError``，不能因为调用方传了个 list 就漏出
    ``TypeError: unhashable type``。非字符串本来也不可能等于任何枚举取值。
    """

    return isinstance(value, str) and value in allowed


def _store_error(message: str) -> ValueError:
    """构造 ``StoreError``（延迟导入，见模块 docstring）。"""

    from soul_memory_kernel.memory.service import StoreError

    return StoreError(message)


def _validation_error(message: str) -> ValueError:
    """构造 ``MemoryValidationError``（延迟导入，见模块 docstring）。"""

    from soul_memory_kernel.memory.service import MemoryValidationError

    return MemoryValidationError(message)


def _record_not_found(record_id: str) -> ValueError:
    """构造 ``RecordNotFound``（延迟导入，见模块 docstring；避免 store↔service 成环）。"""

    from soul_memory_kernel.memory.service import RecordNotFound

    return RecordNotFound(f"memory record not found: {record_id!r}")


def _illegal_transition(from_status: str, to_status: str, actor_kind: str) -> ValueError:
    """构造 ``IllegalTransition``（延迟导入，见模块 docstring）。"""

    from soul_memory_kernel.memory.service import IllegalTransition

    return IllegalTransition(from_status, to_status, actor_kind)


def _record_not_found(record_id: str) -> ValueError:
    """构造 ``RecordNotFound``（延迟导入，见模块 docstring）。"""

    from soul_memory_kernel.memory.service import RecordNotFound

    return RecordNotFound(f"memory record not found: {record_id}")


def _parse_timestamp(value: object, field: str) -> datetime:
    """把 ISO-8601 时间戳解析成**带时区**的 ``datetime``，失败抛校验错误。

    契约的 TTL 语义建立在「ISO-8601 UTC」上。这里统一要求**带时区**：``naive`` 时间戳
    无法判断是不是 UTC，按 fail-closed 拒绝（``StoreError`` 只用于存储故障，所以形状
    问题走 ``MemoryValidationError``）。
    """

    if not isinstance(value, str) or not value:
        raise _validation_error(f"{field} must be a non-empty ISO-8601 string, got {value!r}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _validation_error(f"{field} is not a parseable ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise _validation_error(f"{field} must carry a UTC offset (Z or +00:00): {value!r}")
    return parsed.astimezone(UTC)


def _is_expired(expires_at: str | None, now: datetime) -> bool:
    """``expires_at <= now`` 即到期（边界取 ``>=``，fail-closed）。

    ``None`` 表示不过期（只有已确认的 ``SAFETY`` 类会是 ``None``，DDL 的 CHECK 保证）。
    比较用**解析后的时间点**而不是字符串字典序：``Z`` 与 ``+00:00`` 两种写法、以及
    带小数的秒，字典序都会给出错误答案。
    """

    if expires_at is None:
        return False
    return _parse_timestamp(expires_at, "expires_at") <= now


def _record_violations(record: MemoryRecord) -> tuple[str, ...]:
    """返回该记录违反契约 / DDL 不变量的全部原因（空元组表示合法）。

    逐条对应 ``MEMORY_RECORD_DDL`` 的六条 CHECK 与字段类型约束。**写入前**必须调用：
    违反走 ``MemoryValidationError``（形状非法），而不是等 SQLite 抛
    ``IntegrityError`` 再笼统地报存储故障 —— 前者能告诉调用方到底哪条不变量破了。
    """

    problems: list[str] = []

    for field in ("id", "owner_id"):
        value = getattr(record, field)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{field} must be a non-empty string")
    if not _in(record.scope, SCOPES):
        problems.append(f"scope must be one of {sorted(SCOPES)}, got {record.scope!r}")
    if not _in(record.memory_class, MEMORY_CLASSES):
        problems.append(
            f"memory_class must be one of {sorted(MEMORY_CLASSES)}, got {record.memory_class!r}"
        )
    if not _in(record.source_type, SOURCE_TYPES):
        problems.append(
            f"source_type must be one of {sorted(SOURCE_TYPES)}, got {record.source_type!r}"
        )
    if not _in(record.status, MEMORY_STATUSES):
        problems.append(f"status must be one of {sorted(MEMORY_STATUSES)}, got {record.status!r}")
    # CHECK（do_not_persist 的第二道防线）：该取值不可落库，库层直接排除。
    if not _in(record.memory_policy, MEMORY_POLICIES):
        problems.append(
            "memory_policy must be one of "
            f"{sorted(MEMORY_POLICIES)} (do_not_persist is never persistable), "
            f"got {record.memory_policy!r}"
        )
    if record.source_member_id is not None and (
        not isinstance(record.source_member_id, str) or not record.source_member_id.strip()
    ):
        problems.append("source_member_id must be None or a non-empty string")

    for field in ("confidence", "importance"):
        value = getattr(record, field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
            problems.append(f"{field} must be a number within [0, 1], got {value!r}")
    if isinstance(record.consent_version, bool) or not isinstance(record.consent_version, int):
        problems.append(f"consent_version must be an integer, got {record.consent_version!r}")
    elif record.consent_version < 1:
        problems.append("consent_version must be >= 1 (DDL CHECK)")

    for field in ("created_at", "updated_at"):
        try:
            _parse_timestamp(getattr(record, field), field)
        except ValueError as exc:
            problems.append(str(exc))
    for field in ("last_confirmed_at", "expires_at"):
        value = getattr(record, field)
        if value is not None:
            try:
                _parse_timestamp(value, field)
            except ValueError as exc:
                problems.append(str(exc))

    if not isinstance(record.content, str):
        problems.append("content must be a string")
    elif record.status == "DELETED":
        # 墓碑行不得携带正文（DDL CHECK）。
        if record.content != "":
            problems.append("DELETED tombstone must carry empty content (DDL CHECK)")
    elif not record.content.strip():
        problems.append("content must be non-empty unless the row is a DELETED tombstone")

    # T9c 的**列级** CHECK，与 DDL 的 ``content_over_length IN (0,1)`` 同口径。
    flag = record.content_over_length
    if isinstance(flag, bool) or not isinstance(flag, int) or flag not in (0, 1):
        problems.append(f"content_over_length must be 0 or 1 (DDL CHECK), got {flag!r}")
    elif flag == 0 and isinstance(record.content, str) and len(record.content) > MAX_CONTENT_CHARS:
        # T9c 的**表级** CHECK：``content_over_length = 1 OR length(content) <= 500``。
        # 在这里先判一次，是为了让违规得到 ``MemoryValidationError``（形状问题），
        # 而不是等 SQLite 抛 ``IntegrityError`` 再被糊成 ``StoreError``（存储故障）。
        problems.append(
            f"content must be at most {MAX_CONTENT_CHARS} characters unless the row is "
            f"flagged as a historical over-length record "
            f"(content_over_length=1), got {len(record.content)}"
        )

    if not isinstance(record.audiences, frozenset) or any(
        not isinstance(audience, str) or not audience.strip() for audience in record.audiences
    ):
        problems.append("audiences must be a frozenset of non-empty strings")

    if not isinstance(record.source_ids, tuple) or any(
        not isinstance(source_id, str) or not source_id.strip() for source_id in record.source_ids
    ):
        problems.append("source_ids must be a tuple of non-empty strings")
    else:
        if len(set(record.source_ids)) != len(record.source_ids):
            problems.append("source_ids must not repeat an id (memory_source primary key)")
        if record.id in record.source_ids:
            # 自指血缘必然成环：resolve_provenance 会把它整个拒掉，写入时就直接拒绝，
            # 免得库里存下一段永远解析不出来的血缘。
            problems.append("source_ids must not contain the record's own id (cycle)")

    # CHECK 1：SAFETY scope 的内容类型必须是 SAFETY 类。
    if record.scope == "SAFETY" and record.memory_class != "SAFETY":
        problems.append("scope='SAFETY' requires memory_class='SAFETY' (DDL CHECK)")
    # CHECK 2：expires_at 为空 <=> 「memory_class='SAFETY' 且已确认」。
    # 候选（任何 class）与已确认的非 SAFETY 类都必须有期限。
    if record.expires_at is None and not (
        record.memory_class == "SAFETY" and _in(record.status, _CONFIRMED_STATUSES)
    ):
        problems.append(
            "expires_at may be NULL only for a confirmed (ACTIVE/DECAYED) SAFETY-class "
            "record — candidates of every class must expire (DDL CHECK)"
        )
    # CHECK 3：FAMILY 且 ACTIVE ⇒ 必须已确认。
    if record.scope == "FAMILY" and record.status == "ACTIVE" and record.last_confirmed_at is None:
        problems.append(
            "a FAMILY record in status ACTIVE must have last_confirmed_at (DDL CHECK)"
        )
    # CHECK 4：status ↔ memory_policy 绑定不变量。
    expected_policy = (
        STATUS_POLICY_INVARIANT.get(record.status)
        if _in(record.status, MEMORY_STATUSES)
        else None
    )
    if expected_policy is not None and record.memory_policy != expected_policy:
        problems.append(
            f"status {record.status!r} requires memory_policy {expected_policy!r} "
            f"(STATUS_POLICY_INVARIANT, DDL CHECK)"
        )

    return tuple(problems)


def _effective_content_over_length(
    *, existing: MemoryRecord | None, record: MemoryRecord
) -> int:
    """**T9c 的写入边界**：这条记录落库时 ``content_over_length`` 必须是什么。

    契约 §6 T9c 的表逐行落地在这里（顺序即判定顺序）：

    ==========================================  ==================  ================
    写入形态                                     落库值              调用方声明的值
    ==========================================  ==================  ================
    新记录（库里没有该 id）                        ``0``               必须为 0
    既有行，**正文变更**                          ``0``（派生值获胜）  **忽略**
    既有 ``flag=0``，正文不变                     ``0``               必须为 0
    既有 ``flag=1``，正文不变                     ``1``（CHECK 放行）  必须为 1
    ==========================================  ==================  ================

    一句话：**只在 ``content`` 变更时才强制清零**。r3 的「一律强制清零」会让
    「正文不变的写」（``correct(importance=…)`` / ``reassign_owner`` /
    ``confirm_shared``）撞上表级 CHECK 而写不进去（契约 r4 修订摘要 B 建议 2）。

    **正文变更时派生值获胜，调用方声明的值被忽略**（审阅 A 建议 1 取 (b)）：
    这一列是**派生列** —— 正文变了，旧值就自动作废，没有被「沿用」的语义，让调用方
    去猜一个必然被覆盖的值只会制造一类 API 陷阱。**新写入的正文仍然硬性 ≤500**：
    派生值 0 与超长正文不能共存，那一条在下面单独判。

    **两个伪造方向仍然拒绝，一个都不放松**（契约 T9c 末行）：

    - **凭空标成 1**：新记录声称 1（无中生有）⇒ 拒绝；
    - **正文不变却清成 0**：那条历史超长行的标记被掩盖掉 ⇒ 拒绝。
    """

    if existing is None:
        # 新记录：该列**必须为 0**（T9c 第一行）。无中生有的标记没有来源。
        if record.content_over_length != 0:
            raise _validation_error(
                "content_over_length must be 0 for a new record: the over-length flag only "
                f"ever comes from the v2->v3 migration, got {record.content_over_length!r} "
                "(T9c forgery protection)"
            )
        return 0

    if existing.content != record.content:
        # 正文变更：派生值获胜 —— 正文变了，标记必然归零（这同时是 flagged 行的修复路径）。
        # 调用方的声明在这里**被忽略**而不是被比对（审阅 A 建议 1(b)）。
        if isinstance(record.content, str) and len(record.content) > MAX_CONTENT_CHARS:
            raise _validation_error(
                f"content must be at most {MAX_CONTENT_CHARS} characters "
                f"(a rewritten content is never allowed to stay over the cap), "
                f"got {len(record.content)}"
            )
        return 0

    # 正文不变：标记是**既成事实**，只能原样保留 —— 双向伪造防护都在这里。
    if record.content_over_length != existing.content_over_length:
        raise _validation_error(
            "content_over_length is derived from the previous content and cannot be changed "
            f"when the content is unchanged: expected {existing.content_over_length}, got "
            f"{record.content_over_length!r} (T9c forgery protection: a flag may be neither "
            "invented nor cleared without rewriting the content)"
        )
    return existing.content_over_length


def _actor_kind(actor: Actor) -> str:
    """取 ``actor.kind`` 并核对它是冻结枚举之一。

    未知 kind 不在 §2.4 的权限表里 ⇒ 任何组合都不被允许 ⇒ 按「无权执行」抛
    ``IllegalTransition``（契约 §4.7 的措辞）。
    """

    kind = getattr(actor, "kind", None)
    if not _in(kind, ACTOR_KINDS):
        raise _illegal_transition(_ABSENT_STATUS, _ABSENT_STATUS, str(kind))
    return kind


def _may_create(record: MemoryRecord, actor_kind: str) -> bool:
    """**新建**一条记录是否被该 actor 允许（§2.4 的权限表在「无既有行」时的读法）。

    集成时由主控补上（A8）：W1 原先只允许 ``adult_control_plane`` 新建记录，
    这会让 ``MemoryService.propose()`` 在真实存储上必然失败 —— A8 给
    ``session_proposal`` 开的**唯一**写权限就是「落一条候选」。

    - ``adult_control_plane``：可建任何已通过校验的合法记录；
    - ``session_proposal``：**只能**建候选（``PENDING_CONFIRMATION`` +
      ``candidate_only``）。想直接落一条可召回的记录即越界；
    - ``ttl_expiry`` / ``migration``：**不得新建记录**（§2.4 的禁止清单）。
    """

    if actor_kind == "adult_control_plane":
        return True
    if actor_kind == "session_proposal":
        return record.status == "PENDING_CONFIRMATION" and record.memory_policy == "candidate_only"
    return False


def _check_transition(from_status: str, to_status: str, actor_kind: str) -> None:
    """核对一次状态变化：边必须在表内、在 M2.1 有产出路径、且 actor 有权。

    §2.4 的 actor 权限边界落在这里：

    - ``("ACTIVE", "DECAYED")`` 属 :data:`TTL_TRANSITIONS`，**只有 ``ttl_expiry``** 能做；
    - 其余可产出的边（确认 / 修正自环 / 重新确认）只有 ``adult_control_plane`` 能做；
    - ``("DECAYED", "DECAYED")`` 是契约 §2.3 第 7 行的**幂等 no-op，actor 任意**；
    - 指向 ``DELETED`` 的边在 M2.1 没有产出路径，任何 actor 都不行（``migration`` 也不
      例外：删除即硬删，墓碑只用于导入）。
    """

    if not (_in(from_status, MEMORY_STATUSES) and _in(to_status, MEMORY_STATUSES)):
        raise _illegal_transition(str(from_status), str(to_status), actor_kind)
    if (from_status, to_status) not in LEGAL_TRANSITIONS:
        raise _illegal_transition(from_status, to_status, actor_kind)
    if (from_status, to_status) not in _M2_1_PRODUCIBLE_TRANSITIONS:
        raise _illegal_transition(from_status, to_status, actor_kind)
    if (from_status, to_status) in TTL_TRANSITIONS:
        if actor_kind != "ttl_expiry":
            raise _illegal_transition(from_status, to_status, actor_kind)
        return
    if (from_status, to_status) == ("DECAYED", "DECAYED"):
        return  # 幂等 no-op：什么都没变，§2.3 表里 actor 为「任意」
    if actor_kind != "adult_control_plane":
        raise _illegal_transition(from_status, to_status, actor_kind)


def _check_actor_edit(actor_kind: str, old: MemoryRecord, new: MemoryRecord) -> None:
    """核对**已存在记录**被改写时，该 actor 有没有越界（§2.4）。

    A12 的归属两列（``actor_kind`` / ``actor_id``）**不在这里管**：它们由
    ``write_record`` 从本次写入的 ``actor`` 覆盖，调用方提供的值不参与落库，
    因此既不需要列为「召回语义字段」，也不存在被伪造的路径。

    - ``ttl_expiry``：只能做 TTL 的两条路径 —— 除了 :data:`TTL_TRANSITIONS` 那一条状态
      迁移，不得改任何召回语义字段（含 ``consent_version`` 与 ``expires_at``），
      ``created_at`` / ``last_confirmed_at`` / ``source_session_id`` 也不许碰；
    - ``migration``：不得改召回语义字段、不得改 ``consent_version``、不得改状态；允许改写
      时间戳格式 / 索引重建这类非召回字段（M2.1 本就没有迁移，这条为将来预留）；
    - ``adult_control_plane``：唯一能改变召回语义的 actor，只额外禁止
      ``consent_version`` 递减（递减会让旧 grant 复活）。
    """

    if new.consent_version < old.consent_version:
        raise _validation_error(
            "consent_version must never decrease: a decrease would revalidate stale grants"
        )
    if actor_kind == "adult_control_plane":
        return
    if old.status != new.status:
        allowed = actor_kind == "ttl_expiry" and (old.status, new.status) in TTL_TRANSITIONS
        if not allowed:
            raise _illegal_transition(old.status, new.status, actor_kind)
    forbidden = _RECALL_SEMANTIC_FIELDS
    if actor_kind == "ttl_expiry":
        forbidden = forbidden + _TTL_IMMUTABLE_FIELDS
    for field in forbidden:
        if getattr(old, field) != getattr(new, field):
            raise _illegal_transition(old.status, new.status, actor_kind)


def _resolvable(found: dict[str, MemoryRecord]) -> frozenset[str]:
    """闭包剪枝：只剩「所有祖先都解析成功」的记录。

    Kahn 式迭代：把「依赖数 = 祖先数」的记录入队，依赖全部变绿才变绿。**缺源的记录永远
    等不到那一次递减，成环的记录也一样**，两者都不会出现在结果里（fail-closed）。
    """

    remaining = {record_id: len(record.source_ids) for record_id, record in found.items()}
    dependents: dict[str, list[str]] = {}
    for record_id, record in found.items():
        for source_id in record.source_ids:
            dependents.setdefault(source_id, []).append(record_id)
    green = {record_id for record_id, count in remaining.items() if count == 0}
    frontier = list(green)
    while frontier:
        current = frontier.pop()
        for dependent in dependents.get(current, ()):
            remaining[dependent] -= 1
            if remaining[dependent] == 0 and dependent not in green:
                green.add(dependent)
                frontier.append(dependent)
    return frozenset(green)


class SqliteMemoryStore:
    """W1 的实现类。构造签名冻结为 ``SqliteMemoryStore(db_path)``。

    方法集 = :class:`MemoryStore` Protocol 的全部方法。W1 不得加必需构造参数
    （可选参数可以加，但必须带默认值），否则 W4 的接缝与 W5 的 CLI 要跟着改。

    除 Protocol 的方法外，还有几个由 W1 / W9 上报、**主控仲裁后并入 Protocol** 的原语
    （名字与签名保持仲裁时的形态）：

    - :meth:`list_expired` —— 到期扫描的枚举入口（``sweep_expired()`` 的两条路径
      需要先找到「``ACTIVE``/候选 且 ``expires_at <= now``」的记录，而
      ``list_eligible`` 是按受众查可读记录的，枚举不到**还没有受众的候选**）；
    - :meth:`write_deletion_audit` —— 写 ``deletion_audit`` 行。``hard_delete()`` 的
      签名里没有 actor / 时间，按契约它的 docstring 把审计留给调用方，但 Protocol 原本
      没有提供任何写审计的方法；
    - :meth:`consume_extraction_budget`（**M2.2 W9**）—— §3.9 的每日提取预算原子递增
      原语（无策略，闸住 W7b）；
    - :meth:`count_over_length`（**M2.2 W9，仅实现类**）—— 被标记的历史超长行计数，
      W8 的 ``family-ai-memory list`` 表头用；
    - :attr:`migration_report`（**M2.2 W9，仅实现类**）—— 最近一次打开时的迁移报告；
    - 读路径**不做授权判定**：``read_*`` / ``list_eligible`` 只缩范围，判定归
      ``policy.authorize()``（契约页 §3.1 的「没有第三条路径」）。

    W3 用这套原语拼服务层时的三条接缝（都是冻结签名逼出来的，不是自由发挥）：

    1. **「确认」走 :meth:`write_record`，不是 :meth:`transition`** —— 确认要同时改
       ``audiences`` / ``expires_at`` / ``consent_version``，而 ``transition()`` 的签名里
       没有这些参数。换入口不会绕开状态机：``write_record`` 对已存在记录的状态变化同样
       走 :func:`_check_transition`。
    2. **删除的调用顺序不受约束**（A2）：:meth:`hard_delete` 只删记录自己作为子节点的
       血缘行，指向它的血缘行保留，所以 ``enumerate_dependents`` 在删祖先之后照样可用；
       **派生记录不连带删除**，只进 ``DeletionReport.derived_unreachable``。
       产品路径走 :meth:`hard_delete_with_audit`（A11：删除与审计同一事务）。
    3. **到期实时排除**由调用方完成：:meth:`list_eligible` 不按 ``expires_at`` 过滤
       （契约 §4.5 要求 ``query()`` 自己排除），判定依据用 :meth:`list_expired` 或自己
       的时钟比较。
    """

    def __init__(self, db_path: Path, *, busy_timeout_seconds: float = 5.0) -> None:
        """只记住路径，**不碰文件系统**。

        ``__init__`` 不做任何 I/O：投影接缝（契约页 §10.1）会在会话前构造本对象，
        而读路径必须是 ``mode=ro``。文件与 schema 的创建只在写路径发生
        （:meth:`create_schema` / 首次写入），所以「库不存在」对读取是正常状态。

        ``busy_timeout_seconds`` 保持 SQLite 原有的 5 秒默认值；实时会话可以显式设为
        ``0``，让锁冲突立即变成 ``StoreError``，由上层按 fail-closed 处理。
        """

        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds < 0
        ):
            raise ValueError("busy_timeout_seconds must be a finite number >= 0")

        self.path = Path(db_path)
        self._busy_timeout_seconds = float(busy_timeout_seconds)
        #: 本实例**最近一次**在打开连接时执行的迁移报告（无迁移则为 ``None``）。
        #: 迁移可能发生在 ``create_schema()``，也可能发生在任意一次写连接里
        #: （第一次 ``propose`` 打开一个 v1 库）。只读属性见 :attr:`migration_report`。
        self._last_migration_report: MigrationReport | None = None

    @property
    def migration_report(self) -> MigrationReport | None:
        """本实例最近一次打开连接时执行的迁移报告（没有就返回 ``None``）。

        构造器**不碰文件系统**，所以 `SqliteMemoryStore(path)` 之后这个属性是
        ``None``；要么调 :meth:`create_schema`，要么等第一次写操作打开连接。
        报告的语义见 :class:`~soul_memory_kernel.memory.model.MigrationReport`。
        """

        return self._last_migration_report

    # ------------------------------------------------------------ 文件与 schema

    def create_schema(self) -> MigrationReport | None:
        """首次创建 schema。必须用 ``BEGIN IMMEDIATE`` + ``PRAGMA user_version``。

        幂等：文件已是本版本的记忆库时是 no-op；文件存在但 schema 版本不符 / 表缺失
        时抛 ``StoreError``（**不静默迁移**，也不覆盖既有数据）。文件不存在时按 0600
        独占创建。

        **返回值（M2.2 T9b）**：本次打开**真的执行了迁移**时返回
        :class:`~soul_memory_kernel.memory.model.MigrationReport`（打开时是 v1 或 v2），否则
        ``None``。报告是纯返回值：只有版本号与被标记的超长行**计数**，绝不含正文，
        也不经过任何日志。
        """

        with closing(self._connect_write()):
            pass
        return self._last_migration_report

    def _connect_write(self) -> sqlite3.Connection:
        """打开可写连接，并保证 schema 已就绪。

        新文件（本次创建，或长度为 0 的空文件）直接建表；已有文件先过schema 校验。
        开 ``PRAGMA foreign_keys = ON``，让 ``ON DELETE CASCADE`` 的受众行清理真实生效
        （W1 的 ``hard_delete`` 仍会显式删，见那里的说明）。
        """

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            created = self._create_private_file_if_missing()
            db = sqlite3.connect(self.path, timeout=self._busy_timeout_seconds)
        except (OSError, sqlite3.Error) as exc:
            raise _store_error(f"cannot open memory database {self.path}: {exc}") from exc
        try:
            db.execute("PRAGMA foreign_keys = ON")
            if created or self.path.stat().st_size == 0:
                try:
                    self._create_schema(db)
                except sqlite3.OperationalError as exc:
                    # 并发建表：另一个进程在 BEGIN IMMEDIATE 之后先建好了。只要 schema
                    # 正确就接受 —— 结果是同一个 schema，不是冲突。
                    if "already exists" not in str(exc):
                        raise
                    self._check_schema(db)
            else:
                report = self._open_or_migrate(db)
                if report is not None:
                    self._last_migration_report = report
        except sqlite3.Error as exc:
            db.close()
            raise _store_error(f"invalid memory database {self.path}: {exc}") from exc
        except Exception:
            db.close()
            raise
        return db

    def _connect_readonly(self) -> sqlite3.Connection:
        """打开 ``mode=ro`` 只读连接。投影接缝只允许这条路径。

        库不存在时**不创建**：由调用方在打开前判断（``read_*`` 返回「没有记忆」）。
        """

        uri = f"file:{quote(self.path.resolve().as_posix())}?mode=ro"
        db: sqlite3.Connection | None = None
        try:
            self._check_private_permissions()
            db = sqlite3.connect(uri, uri=True, timeout=self._busy_timeout_seconds)
            self._check_schema(db)
            return db
        except (OSError, sqlite3.Error) as exc:
            if db is not None:
                db.close()
            raise _store_error(f"cannot read memory database {self.path}: {exc}") from exc
        except Exception:
            if db is not None:
                db.close()
            raise

    @staticmethod
    def _create_schema(db: sqlite3.Connection) -> None:
        """按 ``MEMORY_SCHEMA_DDL`` 的顺序建表，事务内一次完成。"""

        db.execute("BEGIN IMMEDIATE")
        try:
            for ddl in MEMORY_SCHEMA_DDL:
                db.execute(ddl)
            # PRAGMA 不接受参数占位符；这里是本模块的 int 常量，不是外部输入。
            db.execute(f"PRAGMA user_version = {MEMORY_SCHEMA_VERSION}")
        except sqlite3.Error:
            db.rollback()
            raise
        db.commit()

    @staticmethod
    def _migrate_v1_to_v2(db: sqlite3.Connection) -> bool:
        """**A12 的显式迁移**：v1 → v2，给 ``memory_record`` 补写入归属两列。

        只做这一件事，且是**加法**：不动任何既有列、不删任何行、不改任何内容。
        既有行的归属填 ``migration`` —— 它们产生于「记录 actor」这个能力之前，
        如实记成迁移来源比编一个假的成人动作诚实。

        SQLite 的 ``ALTER TABLE ADD COLUMN`` 带 ``NOT NULL`` 时必须给默认值；
        CHECK 一并带上，让迁移后的表与全新建的表约束一致。

        迁移在**一个事务内**完成，失败整体回滚（库仍是 v1，调用方拿到 ``StoreError``）。
        **绝不静默**：迁移前后版本号都写进 ``PRAGMA user_version``。

        **版本号在 ``BEGIN IMMEDIATE`` 之内复读（B6）**：两个进程同时打开同一个 v1 库时，
        先拿到写锁的那个完成迁移，后一个在锁内会看到 ``user_version`` 已经是 2，
        于是**直接返回**而不是再执行一遍 ``ALTER TABLE``（那会撞
        ``duplicate column name``，让用户看到一个毫无意义的失败）。
        锁外的预读只用于分流，不作为决策依据。

        返回 ``True`` 表示本次真的执行了迁移，``False`` 表示并发下已被别人迁完。
        """

        db.execute("BEGIN IMMEDIATE")
        try:
            current = db.execute("PRAGMA user_version").fetchone()
            # 锁内复读（B6）：**v2 或更高**都说明这一段已经被做过（可能是并发下的另一个
            # 进程，也可能是本次打开的前一段）。用 ``>= 2`` 而不是 ``== MEMORY_SCHEMA_VERSION``：
            # v3 起 ``MEMORY_SCHEMA_VERSION`` 是 3，而本函数只负责把库带到 2 ——
            # 拿 3 去比会让「已经是 v2 的库」再 ALTER 一次并撞 ``duplicate column name``。
            if current is not None and current[0] >= 2:
                db.commit()  # 另一个进程已经迁完：什么都不做
                return False
            db.execute(
                "ALTER TABLE memory_record ADD COLUMN actor_kind TEXT NOT NULL "
                "DEFAULT 'migration' CHECK (actor_kind IN "
                "('adult_control_plane','session_proposal','ttl_expiry','migration'))"
            )
            db.execute(
                "ALTER TABLE memory_record ADD COLUMN actor_id TEXT NOT NULL "
                "DEFAULT 'migration:v1->v2'"
            )
            db.execute("PRAGMA user_version = 2")
        except sqlite3.Error:
            db.rollback()
            raise
        db.commit()
        return True

    @staticmethod
    def _migrate_v2_to_v3(db: sqlite3.Connection) -> MigrationReport | None:
        """**T9b 的 v2 → v3 迁移**：重建 ``memory_record`` + 建 ``extraction_usage``。

        承载两件事（契约 §6 T9）：

        1. ``content_over_length``（500 字上限下沉 + 既有超长行的标记处置，T9c）；
        2. ``extraction_usage`` 表（§3.9 的每日提取熔断计数）。

        **严格执行 SQLite 官方 12 步法，顺序不可换**（契约 §6 T9b；r3 的 [致命] 修正）：

        1. ``PRAGMA foreign_keys = OFF`` —— **必须在事务之外**（事务内该 PRAGMA 被忽略）；
        2. ``BEGIN IMMEDIATE``；
        2b. **列集自检**（审阅 A 建议 2）：比对 ``PRAGMA table_info(memory_record)`` 与 v2 的
           期望列集，多出任何一列即点名报错并回滚 —— 重建表只按 :data:`_RECORD_COLUMNS`
           拷贝，多出的列会**静默消失**，而「不静默丢数据」是整条迁移纪律；
        3. ``CREATE TABLE memory_record__v3``（新列 + 新 CHECK）；
        4. **两侧都写显式列名**的拷贝（``SELECT *, CASE …`` 会依赖列排列，错列会静默写坏
           ``actor_*`` —— A 的 N1）；
        5. ``DROP TABLE memory_record``；
        6. ``ALTER TABLE memory_record__v3 RENAME TO memory_record``；
        7. 重建索引 / 触发器（本 schema 一个都没有，故为空步）；
        8. ``CREATE TABLE IF NOT EXISTS extraction_usage``；
        9. ``PRAGMA foreign_key_check``（**COMMIT 之前**；有任何一行即 ``ROLLBACK`` +
           ``StoreError``，错误里只有**违规表名 + 行数**，不含正文）；
        10. ``PRAGMA user_version = 3``；
        11. ``COMMIT``；
        12. ``PRAGMA foreign_keys = ON``（``try/finally``，异常路径也恢复）。

        **为什么不能只写「一个事务 + 建新表换名」**：``memory_audience`` 与
        ``memory_source`` 都是 ``REFERENCES memory_record(id) ON DELETE CASCADE``，
        而写连接打开时就 ``PRAGMA foreign_keys = ON``。FK 打开时 ``DROP TABLE`` 会先做
        一次隐式 ``DELETE FROM``，**级联删掉子表行** —— 提交成功、无任何报错，而迁移后
        每条共享记忆都丢了受众行 ⇒ 全库 ``scope_denied``，家人所有已确认记忆静默不可召回。

        **失败语义（T9a）**：任何一步失败 ⇒ ``ROLLBACK`` ⇒ 库**仍是 v2**（v1→v2 已提交且
        其结果是完整的 v2 库），抛 ``StoreError`` 并带可诊断信息（版本 / 失败步骤 / 计数，
        绝不含正文）。**绝不出现「``user_version`` 已前进但数据未迁移」的半成品** ——
        版本号与数据结构在**同一个事务**里变更。

        返回 ``None`` 表示并发下已被别人迁完；否则返回这一段的
        :class:`~soul_memory_kernel.memory.model.MigrationReport`（``from_version=2``，
        调用方 ``_open_or_migrate`` 会把 v1 库的报告改写成 ``from_version=1``）。
        """

        # 步骤 1：必须在 BEGIN 之外 —— 事务内设置 foreign_keys 是静默 no-op。
        db.execute("PRAGMA foreign_keys = OFF")
        try:
            # 步骤 2
            db.execute("BEGIN IMMEDIATE")
            try:
                current = db.execute("PRAGMA user_version").fetchone()
                version = current[0] if current else None
                if version is not None and version >= MEMORY_SCHEMA_VERSION:
                    db.commit()  # 并发下已被别人迁完
                    return None
                if version != 2:
                    raise _store_error(
                        f"memory database schema migration expected v2, found {version}; "
                        "refusing to migrate it"
                    )
                # 步骤 3 之前：**列集自检**（审阅 A 建议 2）。重建表只按 _RECORD_COLUMNS
                # 拷贝，因此多出来的列会静默消失 —— 那是数据损失，不是迁移。
                # 点名报错并回滚（库仍是 v2），错误里只有列名。
                found_columns = tuple(
                    row[1] for row in db.execute("PRAGMA table_info(memory_record)")
                )
                unexpected = tuple(
                    name for name in found_columns if name not in _V2_RECORD_COLUMNS
                )
                if unexpected:
                    raise _store_error(
                        "memory database migration expected a stock v2 memory_record but found "
                        f"unexpected column(s) {sorted(unexpected)}; refusing to rebuild the "
                        "table because the rebuild would silently drop them "
                        "(the database is still at v2)"
                    )
                # 步骤 3
                db.execute(_MEMORY_RECORD_V3_DDL)
                # 步骤 4：两侧都写显式列名（顺序无关，错列不可能发生）
                db.execute(_COPY_INTO_V3_SQL)
                # 步骤 5 + 6
                db.execute("DROP TABLE memory_record")
                db.execute("ALTER TABLE memory_record__v3 RENAME TO memory_record")
                # 步骤 7：索引 / 触发器 —— 本 schema 没有，重建清单为空。
                # 步骤 8
                db.execute(MEMORY_EXTRACTION_USAGE_MIGRATION_DDL)
                # 步骤 9：COMMIT **之前**的外键自检。库里本来就有孤儿行时（R13）
                # 迁移会**响亮地**失败：给出违规表名 + 行数，不回显任何正文，
                # 也绝不「顺手清掉几行」（在人家的记忆库上这么干比拒绝打开更糟）。
                violations = db.execute("PRAGMA foreign_key_check").fetchall()
                if violations:
                    offending = sorted({str(row[0]) for row in violations})
                    raise _store_error(
                        "memory database migration aborted: foreign key check reported "
                        f"{len(violations)} orphan row(s) in {offending}; "
                        "the database is still at v2 (see R13 for the recovery steps)"
                    )
                over_length = db.execute(
                    "SELECT COUNT(*) FROM memory_record WHERE content_over_length = 1"
                ).fetchone()
                # 步骤 10
                db.execute(f"PRAGMA user_version = {MEMORY_SCHEMA_VERSION}")
            except BaseException:
                db.rollback()
                raise
            # 步骤 11
            db.commit()
        finally:
            # 步骤 12：异常路径也必须恢复（本连接随后还要被正常使用）。
            db.execute("PRAGMA foreign_keys = ON")
        return MigrationReport(
            from_version=2,
            to_version=MEMORY_SCHEMA_VERSION,
            over_length_count=int(over_length[0]) if over_length else 0,
        )

    @classmethod
    def _open_or_migrate(cls, db: sqlite3.Connection) -> MigrationReport | None:
        """已有文件：版本相符就校验，v1/v2 就地迁移，其余一律拒绝。

        **一次走完的迁移链（T9a）**：v1 库按 ``v1→v2`` → ``v2→v3`` 两段执行，
        **两段各自一个事务**（SQLite 不允许嵌套事务，``foreign_keys`` 也不能在事务内切换），
        因此失败语义按段说清楚：

        - ``v1 → v2`` 失败 ⇒ 库**仍是 v1**（该段整体回滚；第二个事务根本不开始）；
        - ``v2 → v3`` 失败 ⇒ 库**仍是 v2**（v1→v2 已提交且其结果是完整的 v2 库）。

        返回本次打开真的执行了迁移时的报告（``None`` = 没有迁移）。v1 库的报告
        ``from_version`` 是 **1** —— 它如实描述「打开时这个库处在什么版本」，
        而 :meth:`_migrate_v2_to_v3` 单独看只知道自己在做第二段。
        """

        version = db.execute("PRAGMA user_version").fetchone()
        current = version[0] if version else None
        if current == MEMORY_SCHEMA_VERSION:
            cls._check_schema(db)
            return None
        if current == 1:
            # 锁外预读只用来分流；真正的决策在每段的 BEGIN IMMEDIATE 之内复读一次
            # （B6：并发打开同一个 v1 库时，后到的进程不会重复 ALTER / 重复重建）。
            cls._migrate_v1_to_v2(db)
            report = cls._migrate_v2_to_v3(db)
            cls._check_schema(db)
            if report is None:
                return None  # 并发下另一个进程把两段都做完了
            return replace(report, from_version=1)
        if current == 2:
            report = cls._migrate_v2_to_v3(db)
            cls._check_schema(db)
            return report
        raise _store_error(
            f"memory database schema version is {current}, expected {MEMORY_SCHEMA_VERSION}; "
            "refusing to read or migrate it"
        )

    @staticmethod
    def _check_schema(db: sqlite3.Connection) -> None:
        """完整性 + 版本 + 表/列齐备。版本不符由 :meth:`_open_or_migrate` 先处理。"""

        try:
            check = db.execute("PRAGMA quick_check").fetchone()
            version = db.execute("PRAGMA user_version").fetchone()
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            columns = {row[1] for row in db.execute("PRAGMA table_info(memory_record)")}
        except sqlite3.Error as exc:
            raise _store_error(f"invalid memory database: {exc}") from exc
        if check is None or check[0] != "ok":
            raise _store_error("memory database failed the integrity check (PRAGMA quick_check)")
        if version is None or version[0] != MEMORY_SCHEMA_VERSION:
            raise _store_error(
                f"memory database schema version is {version[0] if version else None}, "
                f"expected {MEMORY_SCHEMA_VERSION}; refusing to read or migrate it"
            )
        missing_tables = MEMORY_TABLES - tables
        if missing_tables:
            raise _store_error(f"memory database is missing tables: {sorted(missing_tables)}")
        missing_columns = _MEMORY_RECORD_COLUMNS - columns
        if missing_columns:
            raise _store_error(
                f"memory_record is missing columns: {sorted(missing_columns)}"
            )

    def _create_private_file_if_missing(self) -> bool:
        """独占创建一个 0600 的库文件；已存在则校验权限后返回 ``False``。"""

        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            self._check_private_permissions()
            return False
        except OSError as exc:
            raise _store_error(f"cannot create memory database {self.path}: {exc}") from exc
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self._check_private_permissions()
        return True

    def _check_private_permissions(self) -> None:
        """拒绝 symlink 与过宽权限（``mode & 0o077``）。"""

        try:
            if self.path.is_symlink():
                raise _store_error("memory database must not be a symlink")
            mode = stat.S_IMODE(self.path.stat().st_mode)
        except OSError as exc:
            raise _store_error(f"cannot inspect memory database permissions {self.path}: {exc}") from exc
        if mode & 0o077:
            raise _store_error(
                f"memory database permissions are too broad ({mode:o}); "
                "restrict it to owner access with chmod 600"
            )

    # ------------------------------------------------------------ 读取

    def read_record(self, record_id: str) -> MemoryRecord | None:
        """读单条记录（含受众与血缘）。读不到 —— 包括库还不存在 —— 返回 ``None``。

        **不校验形状**：库里已有的违约数据（``policy_denied`` 的四种情形）必须能被读出
        来交给 ``authorize()`` 判拒绝，而不是在读的时候炸。
        """

        if not self.path.exists():
            return None
        with closing(self._connect_readonly()) as db:
            return self._load_record(db, record_id)

    def read_records(self, record_ids: tuple[str, ...]) -> tuple[MemoryRecord, ...]:
        """批量读。**缺任何一条都返回缺源信号**，由调用方按 ``missing_provenance`` 处理。

        实现语义（协议只说了「返回缺源信号」，没说信号长什么样）：

        - 返回顺序 = 请求顺序；重复 id 只出现一次（否则调用方的集合比对会失去意义）；
        - **读不到的 id 直接不出现在结果里**，这个「短了」就是缺源信号。调用方把请求的
          id 集合与返回记录的 id 集合一比，就知道哪条记录的血缘不可解析，按
          ``missing_provenance`` 处理。:meth:`resolve_provenance` 是同一件事的闭包版本。
        """

        ordered = list(dict.fromkeys(record_ids))
        if not ordered or not self.path.exists():
            return ()
        with closing(self._connect_readonly()) as db:
            found = [self._load_record(db, record_id) for record_id in ordered]
        return tuple(record for record in found if record is not None)

    def list_eligible(
        self,
        *,
        owner_id: str | None,
        audience_id: str,
        scopes: tuple[str, ...],
        statuses: tuple[str, ...],
    ) -> tuple[str, ...]:
        """列出本次会话**可能**可读的记录 id（仍未判权）。

        这是 ``query()`` 的入口查询：先按 owner / 受众 / scope / 状态缩范围，
        再逐条交给 ``authorize()``。**本方法不做授权判定**，它只保证「不会漏掉
        授权范围内的记录」；多返回的记录由 ``authorize()`` 拒绝。

        实现语义：

        - ``owner_id=None`` = 不限 owner（家庭共享读取的正常形态）；给定 owner 时精确匹配；
        - ``audience_id`` 必须命中 ``memory_audience`` 里的一行 —— ``public_room`` 与
          ``family_all`` 是不同受众，前者永远匹配不到家庭共享记录（契约页 §2.1）；
        - **空 ``scopes`` / ``statuses`` 返回空元组**，不是「全部」；未知取值在 SQL 的
          ``IN`` 里自然不匹配。两者都是 deny-by-default；
        - 到期记录**不在这里排除**：契约 §4.5 要求 ``query()`` 按 ``expires_at <= now``
          实时排除，由调用方完成（这样正确性不依赖 ``sweep_expired()`` 是否跑过）。
        """

        if not scopes or not statuses:
            return ()
        if not isinstance(audience_id, str) or not audience_id:
            return ()
        if any(not isinstance(value, str) for value in (*scopes, *statuses)):
            raise _validation_error("scopes and statuses must be tuples of strings")
        if owner_id is not None and not isinstance(owner_id, str):
            raise _validation_error("owner_id must be None or a string")
        if not self.path.exists():
            return ()

        sql = [
            "SELECT DISTINCT r.id FROM memory_record AS r",
            "JOIN memory_audience AS a ON a.record_id = r.id",
            f"WHERE a.audience_id = ? AND r.scope IN ({_placeholders(scopes)})",
            f"AND r.status IN ({_placeholders(statuses)})",
        ]
        params: list[object] = [audience_id, *scopes, *statuses]
        if owner_id is not None:
            sql.append("AND r.owner_id = ?")
            params.append(owner_id)
        sql.append("ORDER BY r.id")

        with closing(self._connect_readonly()) as db:
            return tuple(row[0] for row in db.execute(" ".join(sql), params))

    def resolve_provenance(self, record_ids: tuple[str, ...]) -> tuple[MemoryRecord, ...]:
        """递归解析祖先闭包。缺源、成环、未登记来源一律拒绝（fail-closed）。

        实现语义（协议只说了「一律拒绝」，没说怎么表达）：

        - 返回的集合对 ``source_ids`` **闭合**：结果里每条记录的每个祖先也在结果里；
        - **解析不出来的记录（含它的全部依赖者）一律不出现在结果里**。缺源信号就是缺失
          本身：调用方看到请求的 id 不在返回集合里，即按 ``missing_provenance`` 处理；
        - 顺序：请求的根在前，其余按发现顺序（BFS）补齐，确定性可复现；
        - 空输入、库不存在都返回空元组（没有记忆是正常状态，不是错误）。

        剪枝用 Kahn 式迭代（依赖全部解析成功才算解析成功），不用递归 —— 血缘链再深也
        不会撞 Python 的递归上限，成环时也不会死循环。
        """

        roots = list(dict.fromkeys(record_ids))
        if not roots or not self.path.exists():
            return ()

        found: dict[str, MemoryRecord] = {}
        order: list[str] = []
        frontier = list(roots)
        with closing(self._connect_readonly()) as db:
            while frontier:
                record_id = frontier.pop(0)
                if record_id in found:
                    continue
                record = self._load_record(db, record_id)
                if record is None:
                    continue  # 缺源 / 未登记来源：不进入 found，依赖它的记录会被剪掉
                found[record_id] = record
                order.append(record_id)
                frontier.extend(
                    source_id for source_id in record.source_ids if source_id not in found
                )
        resolvable = _resolvable(found)
        return tuple(found[record_id] for record_id in order if record_id in resolvable)

    # ------------------------------------------------------------ 写入

    def write_record(self, record: MemoryRecord, *, actor: Actor) -> None:
        """插入或整体替换一条记录及其受众、血缘。``do_not_persist`` 不得到达这里。

        实现语义：

        - **写入前**逐条核对契约 / DDL 不变量（:func:`_record_violations`），违规抛
          ``MemoryValidationError``，不让 SQLite 的 ``IntegrityError`` 把它糊成存储故障；
        - 记录行、``memory_audience`` 行、本条记录**自己的** ``memory_source`` 行在同一个
          事务里整体替换（「指向它的」血缘行不动 —— 契约 §7.4 要求血缘行在来源被删后
          仍然保留）；
        - 新记录只允许 ``adult_control_plane`` 插入（§2.4：``ttl_expiry`` 只能做两条 TTL
          路径，``migration`` 在 M2.1 无可用动作且禁止新增记录）；
        - **已存在记录的状态变化同样受状态机约束**（走 :func:`_check_transition`）。这一点
          对 W3 很重要：``confirm_shared()`` 要同时改 ``audiences`` / ``expires_at`` /
          ``consent_version``，而 :meth:`transition` 的冻结签名表达不了这些字段，因此
          「确认」类写入走本方法 —— 状态机不会因为换了入口就被绕开。
        """

        problems = _record_violations(record)
        if problems:
            raise _validation_error("invalid memory record: " + "; ".join(problems))
        actor_kind = _actor_kind(actor)

        with closing(self._connect_write()) as db, self._transaction(db):
            existing = self._load_record(db, record.id)
            if existing is None:
                if not _may_create(record, actor_kind):
                    raise _illegal_transition(_ABSENT_STATUS, record.status, actor_kind)
            else:
                if record.status != existing.status:
                    _check_transition(existing.status, record.status, actor_kind)
                _check_actor_edit(actor_kind, existing, record)
            # T9c：``content_over_length`` 是**派生值**，由这里定稿 —— 正文变更时派生值
            # 获胜（忽略调用方声明），正文不变时只接受与既有值一致的声明（伪造防护）。
            # 放在状态机与 actor 门**之后**：越权的写不该先拿到一条形状错误的报告。
            content_over_length = _effective_content_over_length(
                existing=existing, record=record
            )
            # A12：**归属由本次写入的 actor 决定**，不从 record 上取。
            # 这样「构造一条 actor_kind=adult_control_plane 的记录再递给 store」
            # 无法伪造归属 —— 落库的永远是真正执行这次写入的主体。
            record = replace(
                record,
                actor_kind=actor_kind,
                actor_id=actor.actor_id,
                content_over_length=content_over_length,
            )
            db.execute(
                f"INSERT INTO memory_record ({_RECORD_SELECT}) "
                f"VALUES ({_RECORD_PLACEHOLDERS}) "
                f"ON CONFLICT(id) DO UPDATE SET {_RECORD_UPSERT_SET}",
                tuple(getattr(record, column) for column in _RECORD_COLUMNS),
            )
            db.execute("DELETE FROM memory_audience WHERE record_id = ?", (record.id,))
            db.executemany(
                "INSERT INTO memory_audience (record_id, audience_id) VALUES (?, ?)",
                sorted((record.id, audience) for audience in record.audiences),
            )
            db.execute("DELETE FROM memory_source WHERE record_id = ?", (record.id,))
            db.executemany(
                "INSERT INTO memory_source (record_id, source_id, ordinal) VALUES (?, ?, ?)",
                [
                    (record.id, source_id, ordinal)
                    for ordinal, source_id in enumerate(record.source_ids)
                ],
            )

    def transition(
        self,
        record_id: str,
        to_status: str,
        *,
        actor: Actor,
        updated_at: str,
        consent_version: int,
        last_confirmed_at: str | None,
    ) -> MemoryRecord:
        """状态迁移。非法迁移必须抛 ``IllegalTransition``，不得静默 no-op。

        实现语义：

        - 目标记录不存在（或已被硬删）抛 ``RecordNotFound``；
        - ``(from, to)`` 必须在 :data:`LEGAL_TRANSITIONS` 内，且必须落在
          ``_M2_1_PRODUCIBLE_TRANSITIONS`` 里（指向 ``DELETED`` 的三条边在 M2.1 没有产出
          路径 —— 删除即硬删；那三条只用于**导入**历史墓碑数据，导入走
          :meth:`write_record` 的插入分支）；
        - ``memory_policy`` 按 :data:`STATUS_POLICY_INVARIANT` **从目标状态推导**（签名里
          没有这个参数，也不该有：状态与策略是绑定的，不由调用方分别指定）；
        - ``expires_at`` / ``audiences`` / ``content`` **不在本方法的签名里**，所以「确认」
          （要重算保留期与受众）必须走 :meth:`write_record`；本方法覆盖纯状态迁移 ——
          主要是 TTL 的 ``ACTIVE → DECAYED`` 与重新确认 ``DECAYED → ACTIVE``；
        - 迁移结果整体过一次 :func:`_record_violations`，保证落库状态仍然自洽（例如
          ``FAMILY`` + ``ACTIVE`` 必须带 ``last_confirmed_at``）。
        """

        actor_kind = _actor_kind(actor)
        with closing(self._connect_write()) as db, self._transaction(db):
            current = self._load_record(db, record_id)
            if current is None:
                raise _record_not_found(record_id)
            _check_transition(current.status, to_status, actor_kind)
            updated = replace(
                current,
                status=to_status,
                memory_policy=STATUS_POLICY_INVARIANT.get(to_status, current.memory_policy),
                updated_at=updated_at,
                consent_version=consent_version,
                last_confirmed_at=last_confirmed_at,
            )
            problems = _record_violations(updated)
            if problems:
                raise _validation_error(
                    f"transition to {to_status} would violate the contract: " + "; ".join(problems)
                )
            _check_actor_edit(actor_kind, current, updated)
            cursor = db.execute(
                "UPDATE memory_record SET status = ?, memory_policy = ?, updated_at = ?, "
                "consent_version = ?, last_confirmed_at = ? WHERE id = ? AND status = ?",
                (
                    updated.status,
                    updated.memory_policy,
                    updated.updated_at,
                    updated.consent_version,
                    updated.last_confirmed_at,
                    record_id,
                    current.status,
                ),
            )
            if cursor.rowcount != 1:
                # 同进程内的写由 sqlite 串行化，正常到不了这里；真到了说明库被外部进程
                # 改过，必须报错而不是假装迁移成功。
                raise _store_error(f"memory record {record_id} changed during the transition")
        return updated

    @staticmethod
    def _delete_record_rows(db: sqlite3.Connection, record_id: str) -> tuple[str, ...]:
        """**事务内**的行删除：``memory_source`` → ``memory_audience`` →
        ``grant_resource`` → ``pending_item``（若存在）→ ``memory_record``，返回真的删掉行的表。

        由 :meth:`hard_delete` 与 :meth:`hard_delete_with_audit` 共用 —— A11 要求删除与
        审计同事务，共用一个不自己开事务的实现是最直接的保证。
        契约 §7.1 第 7 项（``W0'-P``）：若同库存在 ``pending_item`` 表，一并清理
        ``source_record_id = ?`` 的待跟进项（及其受众子表），删到行时记入 ``tables_touched``。
        """

        plan: list[tuple[str, str, tuple[str, ...]]] = [
            ("memory_source", "DELETE FROM memory_source WHERE record_id = ?", (record_id,)),
            ("memory_audience", "DELETE FROM memory_audience WHERE record_id = ?", (record_id,)),
            ("grant_resource", "DELETE FROM grant_resource WHERE record_id = ?", (record_id,)),
        ]
        has_pending_item = (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_item'"
            ).fetchone()
            is not None
        )
        if has_pending_item:
            has_pending_audience = (
                db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pending_audience'"
                ).fetchone()
                is not None
            )
            if has_pending_audience:
                db.execute(
                    "DELETE FROM pending_audience WHERE pending_id IN "
                    "(SELECT id FROM pending_item WHERE source_record_id = ?)",
                    (record_id,),
                )
            plan.append(
                (
                    "pending_item",
                    "DELETE FROM pending_item WHERE source_record_id = ?",
                    (record_id,),
                )
            )
        plan.append(("memory_record", "DELETE FROM memory_record WHERE id = ?", (record_id,)))
        touched: list[str] = []
        for table, statement, params in plan:
            if db.execute(statement, params).rowcount > 0:
                touched.append(table)
        return tuple(touched)

    @staticmethod
    def _validate_deletion_audit(
        *,
        record_id: str,
        actor: Actor,
        deleted_at: str,
        derived_removed: int,
        unknown_copies: tuple[str, ...],
    ) -> str:
        """审计入参校验 + actor 策略（B-s3）。返回 ``actor_kind``，非法一律抛校验错误。

        策略：只有 ``adult_control_plane`` 与 ``ttl_expiry`` 可以写审计行。
        ``session_proposal`` / ``migration`` 显式拒绝，不靠 DDL CHECK 兜底。
        """

        if not isinstance(actor, Actor):
            raise _validation_error("deletion audit actor must be an Actor")
        # 未知 kind 也走校验错误：审计路径没有「状态迁移」可言，入参不认识就是入参问题。
        if actor.kind not in ACTOR_KINDS:
            raise _validation_error(f"unsupported actor kind: {actor.kind!r}")
        actor_kind = actor.kind
        if actor_kind not in _DELETION_AUDIT_ACTOR_KINDS:
            raise _validation_error(
                "deletion audit may only be written by "
                f"{sorted(_DELETION_AUDIT_ACTOR_KINDS)}, got {actor_kind!r}"
            )
        if not isinstance(record_id, str) or not record_id.strip():
            raise _validation_error("deletion audit record_id must be a non-empty string")
        if not isinstance(actor.actor_id, str) or not actor.actor_id.strip():
            raise _validation_error("deletion audit actor_id must be a non-empty string")
        _parse_timestamp(deleted_at, "deleted_at")
        if (
            isinstance(derived_removed, bool)
            or not isinstance(derived_removed, int)
            or derived_removed < 0
        ):
            raise _validation_error(
                f"derived_removed must be a non-negative integer, got {derived_removed!r}"
            )
        if not isinstance(unknown_copies, tuple) or any(
            not isinstance(value, str) or not value.strip() for value in unknown_copies
        ):
            raise _validation_error("unknown_copies must be a tuple of non-empty strings")
        return actor_kind

    @staticmethod
    def _insert_deletion_audit(
        db: sqlite3.Connection,
        *,
        record_id: str,
        actor: Actor,
        actor_kind: str,
        deleted_at: str,
        tables_touched: tuple[str, ...],
        derived_removed: int,
        unknown_copies: tuple[str, ...],
    ) -> str:
        """**事务内**写审计行（调用方已校验）。返回 ``audit_id``。"""

        audit_id = uuid.uuid4().hex
        db.execute(
            "INSERT INTO deletion_audit (audit_id, record_id, actor_kind, actor_id, "
            "deleted_at, tables_touched, derived_removed, unknown_copies) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                audit_id,
                record_id,
                actor_kind,
                actor.actor_id,
                deleted_at,
                json.dumps(list(tables_touched), ensure_ascii=False),
                derived_removed,
                json.dumps(list(unknown_copies), ensure_ascii=False),
            ),
        )
        return audit_id

    def hard_delete_with_audit(
        self,
        *,
        record_id: str,
        actor: Actor,
        deleted_at: str,
        derived_removed: int = 0,
        unknown_copies: tuple[str, ...] = (),
    ) -> DeletionOutcome:
        """A11：删除与审计在**同一事务**内完成，失败整体回滚。"""

        actor_kind = self._validate_deletion_audit(
            record_id=record_id,
            actor=actor,
            deleted_at=deleted_at,
            derived_removed=derived_removed,
            unknown_copies=unknown_copies,
        )
        with closing(self._connect_write()) as db, self._transaction(db):
            if db.execute(
                "SELECT 1 FROM memory_record WHERE id = ?", (record_id,)
            ).fetchone() is None:
                # 先判存在再删：同一事务内，抛错时没有半成品状态，也不留审计行。
                raise _record_not_found(record_id)
            touched = self._delete_record_rows(db, record_id)
            tables_touched = tuple(dict.fromkeys((*touched, "deletion_audit")))
            audit_id = self._insert_deletion_audit(
                db,
                record_id=record_id,
                actor=actor,
                actor_kind=actor_kind,
                deleted_at=deleted_at,
                tables_touched=tables_touched,
                derived_removed=derived_removed,
                unknown_copies=unknown_copies,
            )
        return DeletionOutcome(
            record_id=record_id, tables_touched=tables_touched, audit_id=audit_id
        )

    def hard_delete(self, record_id: str) -> tuple[str, ...]:
        """**磁盘删除**：``DELETE`` 行，不是标记。返回实际触及的表名。

        必须一并清理 ``memory_audience`` / ``memory_source`` / ``grant_resource``
        中指向该 id 的行（见契约页 §7.1）。

        实现语义（血缘口径按主控仲裁 2026-09-26 修订）：

        - 删除顺序：``memory_source`` → ``memory_audience`` → ``grant_resource`` →
          ``memory_record``，同一事务。``grant_resource`` **没有外键、没有级联**
          （契约 §7.1 第 4 项），不显式删就会把被删记录的 id 留在授权表里；
        - ``memory_source`` **只删它自己作为子节点的行**（``record_id = ?``）；**指向它
          的血缘行（``source_id = ?``）保留** —— 否则派生记录会「看起来没有祖先」而被
          当成干净记录继续召回，正是契约 §7.4 点名的最危险路径。保留之后，派生记录在
          解析时按 ``missing_provenance`` fail-closed；
        - 因此**调用顺序不受约束**：先删祖先还是先删派生记录都行，
          :meth:`enumerate_dependents` 在祖先删除后照样反查得出（血缘行还在）；
        - ``tables_touched`` 只列**真的删掉了行**的表（``rowcount > 0``）—— 报告要的是
          事实，不是「我们执行过语句」；
        - 记录行本来就没了 → 返回空元组（幂等 no-op）；「目标不存在」的报错归服务层的
          ``RecordNotFound``；
        - **不递归删派生记录，也不删派生记录**（A2）：调用方用
          :meth:`enumerate_dependents` 枚举后只写进 ``DeletionReport.derived_unreachable``
          （仍在盘上、已永久不可召回），``derived_removed`` 恒为 ``()``。
        """

        with closing(self._connect_write()) as db, self._transaction(db):
            exists = db.execute(
                "SELECT 1 FROM memory_record WHERE id = ?", (record_id,)
            ).fetchone()
            if exists is None:
                return ()
            touched = self._delete_record_rows(db, record_id)
        return touched

    def enumerate_dependents(self, record_id: str) -> tuple[str, ...]:
        """枚举血缘上依赖该记录的派生记录（**只用于报告，不用于删除**，A2）。

        结果进 ``DeletionReport.derived_unreachable``：这些记录**仍在盘上**、
        已因祖先消失而永久不可召回（``missing_provenance`` fail-closed），
        必须如实列出，否则报告会让人误以为派生内容已经消失。

        递归（BFS）覆盖多级派生：「以它为祖先」是**传递**关系，只报一级会漏掉解析不出
        祖先的孙辈。结果不含 ``record_id`` 自己；成环时既不重复也不死循环。

        血缘行在来源被删后仍然保留（契约 §7.4），所以本方法**在祖先删除之后依然可用**
        —— 删除顺序不受约束。
        """

        if not self.path.exists():
            return ()
        found: list[str] = []
        seen = {record_id}
        frontier = [record_id]
        with closing(self._connect_readonly()) as db:
            while frontier:
                current = frontier.pop(0)
                rows = db.execute(
                    "SELECT record_id FROM memory_source WHERE source_id = ? ORDER BY record_id",
                    (current,),
                ).fetchall()
                for (dependent,) in rows:
                    if dependent in seen:
                        continue
                    seen.add(dependent)
                    found.append(dependent)
                    frontier.append(dependent)
        return tuple(found)

    # ------------------------------------------------------------ 到期扫描与审计

    def list_expired(self, *, now: str) -> tuple[MemoryRecord, ...]:
        """列出 ``expires_at <= now`` 且**仍有到期动作要做**的记录（仲裁并入 Protocol 的原语）。

        ``sweep_expired()`` 的两条路径都需要先枚举到期对象，而 Protocol 里的
        ``list_eligible`` 是按受众查「可能可读」的记录，枚举不到尚无受众的候选 ——
        这正是本原语被仲裁并入 Protocol 的原因。返回
        的记录带完整字段（受众 + 血缘），调用方按 ``status`` 分派：

        - ``ACTIVE`` → 状态迁移 ``ACTIVE → DECAYED``（不删盘，D5）；
        - ``PENDING_CONFIRMATION`` → :meth:`hard_delete` + :meth:`write_deletion_audit`
          （候选到期是硬删除，不是状态翻转）。

        ``expires_at`` 为空（已确认的 ``SAFETY`` 类）永不到期，不出现在结果里。库内
        ``expires_at`` 不可解析属数据损坏：**抛 ``StoreError`` 而不是当成已到期** ——
        在无法判断是否到期时删数据是最危险的选择。``now`` 必须是带时区的 ISO-8601
        （不可解析即 fail-closed，抛 ``MemoryValidationError``）。
        """

        now_dt = _parse_timestamp(now, "now")
        if not self.path.exists():
            return ()
        with closing(self._connect_readonly()) as db:
            rows = db.execute(
                f"SELECT {_RECORD_SELECT} FROM memory_record "
                "WHERE status IN ('ACTIVE', 'PENDING_CONFIRMATION') ORDER BY id"
            ).fetchall()
            records = [self._row_to_record(db, row) for row in rows]
        expired: list[MemoryRecord] = []
        for record in records:
            try:
                is_expired = _is_expired(record.expires_at, now_dt)
            except ValueError as exc:
                raise _store_error(
                    f"memory record {record.id} has an unparseable expires_at "
                    f"({record.expires_at!r}); refusing to sweep"
                ) from exc
            if is_expired:
                expired.append(record)
        return tuple(expired)

    def write_deletion_audit(
        self,
        *,
        record_id: str,
        actor: Actor,
        deleted_at: str,
        tables_touched: tuple[str, ...],
        derived_removed: int = 0,
        unknown_copies: tuple[str, ...] = (),
    ) -> str:
        """写一条 ``deletion_audit`` 行并返回 ``audit_id``（仲裁并入 Protocol 的原语）。

        ``hard_delete()`` 的冻结签名里没有 actor 与时间，它的 docstring 把审计留给调用
        方；Protocol 原本没有提供写审计的方法，因此由本原语承担（主控仲裁 2026-09-26：
        保留此名字与签名，契约页随后把 ``list_expired`` / ``write_deletion_audit`` 补进
        ``MemoryStore`` Protocol）。

        **审计表只存 record_id 与计数，绝不存正文**（契约页 §7.3）—— 参数里没有正文
        通道，``tables_touched`` / ``unknown_copies`` 以 JSON 数组落库。

        **actor 显式校验（B-s3）**：只有 ``adult_control_plane``（成人显式删除）与
        ``ttl_expiry``（候选到期硬删）可以写审计行。``session_proposal`` 与 ``migration``
        一律抛 ``MemoryValidationError`` —— **不靠 DDL CHECK 兜底**：
        ``deletion_audit.actor_kind`` 的 CHECK 是**取值枚举**守卫（现已与
        :data:`~soul_memory_kernel.memory.model.ACTOR_KINDS` 对齐，四个值都在），
        「谁有权写审计」是**策略**，住在这一层。这样越权 actor 得到的是明确的校验错误，
        而不是被包成 ``StoreError`` 的 ``CHECK constraint failed``。
        """

        actor_kind = self._validate_deletion_audit(
            record_id=record_id,
            actor=actor,
            deleted_at=deleted_at,
            derived_removed=derived_removed,
            unknown_copies=unknown_copies,
        )
        if not isinstance(tables_touched, tuple) or any(
            not isinstance(value, str) or not value.strip() for value in tables_touched
        ):
            raise _validation_error("tables_touched must be a tuple of non-empty strings")

        with closing(self._connect_write()) as db, self._transaction(db):
            return self._insert_deletion_audit(
                db,
                record_id=record_id,
                actor=actor,
                actor_kind=actor_kind,
                deleted_at=deleted_at,
                tables_touched=tables_touched,
                derived_removed=derived_removed,
                unknown_copies=unknown_copies,
            )

    # ------------------------------------------------------------ 提取预算与超长行
    # M2.2（W9）新增的两条原语：
    #
    # - ``consume_extraction_budget`` —— §3.9 的**DB 原子递增原语**（**不含任何策略**：
    #   会话计数、限额来源、fail-closed 判定全在 W7b 的 ``extraction/budget.py``）；
    # - ``count_over_length`` —— 被标记的历史超长行计数（W8 的 ``list`` 表头用）。

    def consume_extraction_budget(self, day: str, limit: int) -> bool:
        """**原子地**「递增并判定」当日的提取调用计数（§3.9 T27 要求 1）。

        一条语句完成两件事，因此两个 ``console`` 进程同时跑也**不会同时越界**
        （「先查后写」会）::

            INSERT INTO extraction_usage(day, call_count) VALUES (?, 1)
              ON CONFLICT(day) DO UPDATE SET call_count = call_count + 1
              WHERE call_count < ?;

        判定用 ``cursor.rowcount``：``1`` = 获准且已计数；``0`` = 已到上限、
        **没有递增**（``WHERE`` 不成立时 upsert 什么也不做）。

        **调用时机是「每次实际出网之前」**（契约 T27 第 3 条）：超时 / 非 2xx /
        schema 失败都算一次，重试算第二次，先计数后调用（调用后进程崩溃也已计数）。

        **本方法不含任何策略**：它不读配置、不知道会话、不决定「拿不准就不出境」
        （那是 W7b 的闸）。它只保证「计数不会因为并发而越界」。
        入参形状非法（空 ``day``、``limit < 1``）抛 ``MemoryValidationError``；
        存储故障抛 ``StoreError``。
        """

        if not isinstance(day, str) or not day.strip():
            raise _validation_error("extraction budget day must be a non-empty string")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise _validation_error(
                f"extraction budget limit must be an integer >= 1, got {limit!r}"
            )
        with closing(self._connect_write()) as db, self._transaction(db):
            cursor = db.execute(
                "INSERT INTO extraction_usage (day, call_count) VALUES (?, 1) "
                "ON CONFLICT(day) DO UPDATE SET call_count = call_count + 1 "
                "WHERE call_count < ?",
                (day, limit),
            )
            return cursor.rowcount == 1

    def count_over_length(self) -> int:
        """当前库里被标记为「历史超长」的行数（``content_over_length = 1``）。

        契约 §3.9 的两条可见面之一：``family-ai-memory list`` 的表头显示这个数字
        （**W8**，从库里实时数，权威且总是最新）。另一个是 v2→v3 迁移返回的
        :class:`~soul_memory_kernel.memory.model.MigrationReport`。**不新增日志事件。**

        库不存在时返回 ``0``（没有记忆 = 没有被标记的行，不是错误）。
        """

        if not self.path.exists():
            return 0
        with closing(self._connect_readonly()) as db:
            row = db.execute(
                "SELECT COUNT(*) FROM memory_record WHERE content_over_length = 1"
            ).fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------ 内部

    @staticmethod
    def _row_to_record(db: sqlite3.Connection, row: tuple) -> MemoryRecord:
        """行 → 记录（含受众集合与按 ``ordinal`` 排好序的血缘元组）。"""

        values = dict(zip(_RECORD_COLUMNS, row))
        audiences = frozenset(
            audience
            for (audience,) in db.execute(
                "SELECT audience_id FROM memory_audience WHERE record_id = ?", (values["id"],)
            )
        )
        source_ids = tuple(
            source_id
            for (source_id,) in db.execute(
                "SELECT source_id FROM memory_source WHERE record_id = ? ORDER BY ordinal",
                (values["id"],),
            )
        )
        return MemoryRecord(**values, audiences=audiences, source_ids=source_ids)

    def _load_record(self, db: sqlite3.Connection, record_id: str) -> MemoryRecord | None:
        row = db.execute(
            f"SELECT {_RECORD_SELECT} FROM memory_record WHERE id = ?", (record_id,)
        ).fetchone()
        return None if row is None else self._row_to_record(db, row)

    @contextmanager
    def _transaction(self, db: sqlite3.Connection) -> Iterator[None]:
        """一组 DML 的原子边界：成功 commit；任何异常先 rollback 再抛。

        ``sqlite3.Error`` 统一转成 ``StoreError``（契约 §4.7：删除中途失败必须让调用方
        知道，不能报成功）；本模块自己抛的校验 / 迁移错误原样传播。
        """

        try:
            yield
            db.commit()
        except sqlite3.Error as exc:
            db.rollback()
            raise _store_error(f"cannot write memory database {self.path}: {exc}") from exc
        except BaseException:
            db.rollback()
            raise
