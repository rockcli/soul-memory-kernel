"""soul_memory_kernel.memory —— 显式共享记忆、应用侧授权与保留期（M2）。

状态：**W0 契约冻结**。本包当前只含类型、DDL 常量、Protocol 与函数签名，
所有函数体为 ``raise NotImplementedError``。**没有任何可运行的业务逻辑。**

契约全文见 ``docs/M2-CONTRACT.md``；契约测试见 ``tests/test_memory_contract.py``。

分工（一个文件只有一个 writer，详见契约页 §文件所有权）：

===========  ==========================================  ====================
writer       文件                                        本轮状态
===========  ==========================================  ====================
W0（本包）   ``__init__`` / ``model`` / ``store``(DDL)   **已冻结**
             ``policy`` / ``service`` / ``projection``
W1           ``store.py`` 的 MemoryStore 实现（CRUD）    待派
W2           ``policy.py`` 实现 + ``grants.py``          待派
W3           ``service.py`` / ``projection.py`` 实现     待派
W4           ``soul/core.py``、``soul/policy.py`` 接缝    待派
W5           ``apps/memory_cli.py``                      待派
===========  ==========================================  ====================

与 :mod:`soul_memory_kernel.privacy` 的关系：那个包是**默认关闭的合成原型**，只有测试与
``experiments/`` 引用它，零生产导入。M2 **不搬它的代码进产品路径**，只沿用两条
已经过独立验收的语义：逐动作判权（``read_model`` / ``send_provider`` / 两个出口
分离）与递归血缘授权（派生记录必须连同每个祖先都获授权）。原型的
``PrivacySessionCoordinator`` 不进入产品 —— 它与实时传输层的外部会话
生命周期同构，直接接入会变成两套会话生命周期。
"""

from soul_memory_kernel.memory.grants import SqliteGrantStore, load_grant_for_session
from soul_memory_kernel.memory.model import (
    ACTOR_KINDS,
    CANDIDATE_EXPIRY_IS_HARD_DELETE,
    DELETE_KEEPS_INBOUND_PROVENANCE,
    CANDIDATE_ORIGINS,
    DEFAULT_TTL_CANDIDATE_DAYS,
    DEFAULT_TTL_EVENT_DAYS,
    DEFAULT_TTL_PREFERENCE_DAYS,
    LEGAL_TRANSITIONS,
    M2_1_ALLOWED_ORIGINS,
    M2_1_ALLOWED_SCOPES,
    MAX_CONTENT_CHARS,
    MEMORY_CLASSES,
    MEMORY_POLICIES,
    MEMORY_STATUSES,
    QUERY_PURPOSES,
    REQUESTED_POLICIES,
    RESERVED_AUDIENCES,
    RESERVED_OWNER_IDS,
    SCOPES,
    SOURCE_TYPES,
    STATUS_POLICY_INVARIANT,
    TTL_TRANSITIONS,
    Actor,
    DeletionOutcome,
    DeletionReport,
    Grant,
    MemoryCandidate,
    MemoryCorrection,
    MemoryRecord,
    MemorySnapshot,
    MigrationReport,
    RetentionPolicy,
    SnapshotEntry,
    SourceSession,
)
from soul_memory_kernel.memory.pending import (
    DEFAULT_PENDING_TTL_DAYS,
    MAX_PENDING_FIELD_CHARS,
    MAX_PROJECTED_PENDING_ITEMS,
    PENDING_AUDIENCE_DDL,
    PENDING_BLOCK_HEADER,
    PENDING_ITEM_DDL,
    PENDING_LEGAL_TRANSITIONS,
    PENDING_SCHEMA_DDL,
    PENDING_STATUSES,
    PendingCandidate,
    PendingItem,
    PendingStatus,
    SqlitePendingStore,
    render_pending_block,
)
from soul_memory_kernel.memory.policy import (
    ACTIONS,
    ALLOWED,
    DENIED_NO_GRANT,
    DENY_ORDER,
    M2_1_WRITE_GATE,
    M2_1_WRITE_PATHS_USE_REQUIRE,
    NO_GRANT_EXEMPT_ACTIONS,
    REASONS,
    AuthorizationDecision,
    authorize,
    require,
)
from soul_memory_kernel.memory.projection import (
    MAX_PROJECTED_MEMORIES,
    MEMORY_BLOCK_HEADER,
    PROJECTION_SEAM_ACTIONS,
    render_memory_block,
)
from soul_memory_kernel.memory.service import (
    AuthorizationError,
    IllegalTransition,
    MemoryService,
    MemoryServiceError,
    MemoryValidationError,
    RecordNotFound,
    StoreError,
)
from soul_memory_kernel.memory.store import (
    ACTOR_COLUMNS,
    MAX_GRANT_TTL_SECONDS,
    MEMORY_EXTRACTION_USAGE_DDL,
    MEMORY_SCHEMA_DDL,
    MEMORY_SCHEMA_VERSION,
    MEMORY_TABLES,
    GrantStore,
    MemoryStore,
    SqliteMemoryStore,
)

__all__ = [
    # model
    "ACTOR_KINDS",
    "CANDIDATE_EXPIRY_IS_HARD_DELETE",
    "CANDIDATE_ORIGINS",
    "DELETE_KEEPS_INBOUND_PROVENANCE",
    "DEFAULT_TTL_CANDIDATE_DAYS",
    "DEFAULT_TTL_EVENT_DAYS",
    "DEFAULT_TTL_PREFERENCE_DAYS",
    "LEGAL_TRANSITIONS",
    "M2_1_ALLOWED_ORIGINS",
    "M2_1_ALLOWED_SCOPES",
    "MAX_CONTENT_CHARS",
    "MEMORY_CLASSES",
    "MEMORY_POLICIES",
    "MEMORY_STATUSES",
    "QUERY_PURPOSES",
    "REQUESTED_POLICIES",
    "RESERVED_AUDIENCES",
    "RESERVED_OWNER_IDS",
    "SCOPES",
    "SOURCE_TYPES",
    "STATUS_POLICY_INVARIANT",
    "TTL_TRANSITIONS",
    "Actor",
    "DeletionOutcome",
    "DeletionReport",
    "Grant",
    "MemoryCandidate",
    "MemoryCorrection",
    "MemoryRecord",
    "MemorySnapshot",
    "MigrationReport",
    "RetentionPolicy",
    "SnapshotEntry",
    "SourceSession",
    # policy
    "ACTIONS",
    "ALLOWED",
    "DENIED_NO_GRANT",
    "DENY_ORDER",
    "M2_1_WRITE_GATE",
    "M2_1_WRITE_PATHS_USE_REQUIRE",
    "NO_GRANT_EXEMPT_ACTIONS",
    "REASONS",
    "AuthorizationDecision",
    "authorize",
    "require",
    # projection
    "MAX_PROJECTED_MEMORIES",
    "MEMORY_BLOCK_HEADER",
    "PROJECTION_SEAM_ACTIONS",
    "render_memory_block",
    # service
    # ``MAX_CONTENT_CHARS`` 见上面的 model 段：常量住在 ``model.py``（M2.2 T9f 搬家），
    # ``service.py`` 仍然再导出它（``apps/memory_cli.py`` / 集成测试从那里导入）。
    "AuthorizationError",
    "IllegalTransition",
    "MemoryService",
    "MemoryServiceError",
    "MemoryValidationError",
    "RecordNotFound",
    "StoreError",
    # store
    "ACTOR_COLUMNS",
    "MAX_GRANT_TTL_SECONDS",
    "MEMORY_EXTRACTION_USAGE_DDL",
    "MEMORY_SCHEMA_DDL",
    "MEMORY_SCHEMA_VERSION",
    "MEMORY_TABLES",
    "GrantStore",
    "MemoryStore",
    "SqliteGrantStore",
    "SqliteMemoryStore",
    # grants（W2；W0 只建立桩以固定导入点）
    "load_grant_for_session",
    # pending（W0'-P）
    "DEFAULT_PENDING_TTL_DAYS",
    "MAX_PENDING_FIELD_CHARS",
    "MAX_PROJECTED_PENDING_ITEMS",
    "PENDING_AUDIENCE_DDL",
    "PENDING_BLOCK_HEADER",
    "PENDING_ITEM_DDL",
    "PENDING_LEGAL_TRANSITIONS",
    "PENDING_SCHEMA_DDL",
    "PENDING_STATUSES",
    "PendingCandidate",
    "PendingItem",
    "PendingStatus",
    "SqlitePendingStore",
    "render_pending_block",
]
