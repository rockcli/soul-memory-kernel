"""M2 记忆数据模型（W0 冻结形状；W1 实现保留期算术与校验）。

本模块是**类型 + 声明式规格数据**：dataclass、Literal 枚举、供测试枚举的冻结集合
常量与迁移表。W1 在这里实现的只有保留期算术与输入校验，没有业务逻辑：

- :meth:`RetentionPolicy.days_for` —— D5 的分型保留天数；
- :meth:`RetentionPolicy.__post_init__` —— 天数形状校验（非 ``bool`` 的正整数）；
- :meth:`Grant.consent_version_for` —— grant 对某条记录的同意版本查询。

**为什么 ``MemoryRecord`` / ``MemoryCandidate`` 没有 ``__post_init__`` 校验**：契约的
``policy_denied`` 四种情形要求**能在内存里构造**违反不变量的记录（``do_not_persist``
行、未知策略、``status`` 与 ``memory_policy`` 不符）来验证判权拒绝路径；若在构造点
就拒绝，W2 无法表达这些反例。记录形状的校验因此落在**持久化边界**
（``store.SqliteMemoryStore.write_record``）。读取路径一律不校验 —— 库里已有的违约
数据必须能被读出来交给 ``authorize()`` 判 ``policy_denied``，而不是在读取时抛错。

冻结依据：``docs/M2-CONTRACT.md``。任何字段增删都是契约变更，必须改契约页并
同步 ``tests/test_memory_contract.py``，不得由实现方自行调整。

与 M1 的关系：
- ``scope`` 直接复用 :mod:`soul_memory_kernel.soul.policy` 里冻结的 ``Scope`` Literal，
  不复制第二份定义 —— M2 不新造 scope 语义。
- ``SessionMode`` / ``IdentityAssurance`` 同样复用，保证 ``SessionAccess`` 与
  记忆判权看到的是同一套枚举。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from soul_memory_kernel.soul.policy import IdentityAssurance, Scope, SessionMode

# --------------------------------------------------------------------------
# 枚举（Literal + 冻结集合；集合供契约测试枚举，不要在各 writer 里另抄一份）
# --------------------------------------------------------------------------

#: 记忆的保留类型（D5）。与 ``scope`` 正交：
#: ``scope`` 管「谁能读」，``memory_class`` 管「留多久」。
MemoryClass = Literal["EVENT", "PREFERENCE", "SAFETY"]

#: 写入策略。注意 ``do_not_persist`` **不出现在这个 Literal 里** —— 它不是一个
#: 可以落库的取值，而是「不写入」这一动作。见 ``MEMORY_POLICIES`` 的说明。
MemoryPolicy = Literal["persist_confirmed", "candidate_only"]

#: 请求侧声明的策略：比 ``MemoryPolicy`` 多一个 ``do_not_persist``。
RequestedPolicy = Literal["persist_confirmed", "candidate_only", "do_not_persist"]

#: 生命周期状态。``PENDING_CONFIRMATION`` 即 D2 里的「候选」。
#:
#: ``DELETED`` 是**墓碑状态**：它表示「这个 id 曾经存在且已被删除」。
#: **M2.1 的删除动作一律是硬删除（行消失 + `deletion_audit`），不产出墓碑行。**
#: 保留该状态是为了 (a) 读取迁移/导入的历史数据，(b) 将来引入「延迟删除/宽限期」
#: 时不必改枚举。DDL 对它有额外约束：墓碑行的 ``content`` 必须为空字符串 ——
#: 即使墓碑真的出现，也不可能带着正文。
MemoryStatus = Literal["PENDING_CONFIRMATION", "ACTIVE", "DECAYED", "DELETED"]

#: 来源类型（M2-PREPARATION 第 7 行冻结字段 ``source_type``）。
SourceType = Literal["explicit_user", "explicit_adult", "confirmed_candidate", "auto_extracted"]

#: 候选的产生路径。D2：M2.1 只允许 ``explicit_user``；``auto_extracted`` 的形状
#: 先建好，提取器本身放 M2.2。
CandidateOrigin = Literal["explicit_user", "auto_extracted"]

#: 查询目的。决定快照**携带什么**，是 deny-by-default 的一部分：
#: ``session_projection`` 带正文（要进模型投影）；``adult_list`` / ``deletion_audit``
#: 只带元数据；``adult_inspect`` 带正文但必须由成人显式 ``--show-content`` 触发。
#:
#: **M2.2 的第 5 个取值 ``control_plane_review``（§4.3 / D11）**：成人复审候选正文。
#: 它同时决定 ``query()`` 用哪个授权动作 —— 前四个 purpose 都是 ``read_model``，
#: 只有它走 ``review_control_plane``（见 ``service._ACTION_FOR_PURPOSE``）。
#: **读路径不新增第二条**：正文仍然只从 ``MemoryService.query()`` 出。
QueryPurpose = Literal[
    "session_projection",
    "adult_list",
    "adult_inspect",
    "deletion_audit",
    "control_plane_review",
]

#: 写入者类别。除 ``ttl_expiry`` / ``session_proposal`` 外都必须是成人控制面动作。
#:
#: ``session_proposal`` 是 **r3 增补**（A8）：会话里家人说「记住这个」时产生的
#: ``propose()`` 由**会话**发起，不是成人控制面动作。**严禁把它记成
#: ``adult_control_plane``** —— 那会把「家人随口一说」伪装成「成人已确认」，
#: 直接架空 D3。
ActorKind = Literal["adult_control_plane", "session_proposal", "ttl_expiry", "migration"]

#: 受众词汇：`family_all`（全体家人）、成员 id（指定家人）、`public_room`（公开空间）。
#: `public_room` 与「家人可读」是**不同**的受众；授权给家人绝不等于可以外放。
Audience = str
RESERVED_AUDIENCES: frozenset[str] = frozenset({"family_all", "public_room"})

#: **保留归属 id（D13 / §2.4）。** 共享会话里提议出来的候选记不出「这是谁的」
#: （M1 明确不做说话人识别），因此用保留归属 ``"family_shared"``，
#: 由成人在 ``confirm`` 时用 ``reassign_owner`` 定到具体成员。
#:
#: 保留 id 只保证**不与档案录入路径冲突** —— 记忆侧**不校验成员存在性**
#: （``MemoryService`` 只要求非空字符串），因此这里只钉住「哪些 id 是保留语义」。
#: ``reassign_owner`` 拒绝把归属改**回**保留 id：那是一次无意义操作，且会让
#: 「已定归属」重新变得不可知。
RESERVED_OWNER_IDS: frozenset[str] = frozenset({"family_shared"})

#: **M2.1 相位限制（用户裁决，2026-09-26）。**
#:
#: M2.1 的产品路径**只允许创建和召回 `scope=FAMILY` 的记忆**。
#: `PERSONAL` / `SAFETY` 两种 scope 由 ``propose()`` / ``confirm_shared()`` 直接拒绝，
#: 读路径也一律拒绝，reason 为 ``scope_not_enabled``。
#:
#: 注意区分两件不同的事：
#:
#: - ``scope``   —— **谁能读**。M2.1 只有 `FAMILY`。
#: - ``memory_class`` —— **留多久**（D5）。`memory_class="SAFETY"`（过敏、禁忌这类
#:   **内容类型**）在 `FAMILY` scope 下**照常支持**，并且按 D5 不过期。
#:
#: 受控私人会话（`PERSONAL`）与「安全记忆给谁看」（`SAFETY` scope）需要**另行裁决**，
#: 属 M2.2+。见契约页 §3.6。
M2_1_ALLOWED_SCOPES: frozenset[str] = frozenset({"FAMILY"})

#: ``propose()`` 接受的候选产生路径白名单。
#:
#: M2.1 只放行 ``explicit_user``；**M2.2 放行 ``auto_extracted``**（§3 自动提取，
#: 契约 §6 收口表第 12 项 / §8.1 的 W9 行）。放行不等于放松：提取路径**只能**产出
#: 候选（``PENDING_CONFIRMATION`` + ``candidate_only``），成人确认仍是唯一生效路径
#: （约束 1），因此这个集合现在与 :data:`CANDIDATE_ORIGINS` **相等**。
M2_1_ALLOWED_ORIGINS: frozenset[str] = frozenset({"explicit_user", "auto_extracted"})

#: 单条记忆内容的硬上限（字符数，Unicode 字符而非字节）。B-s5（主控 2026-09-26）：
#: 投影只限条数不限长度，一条超长记忆照样能把 instructions 撑满 —— 正是
#: ``MAX_PROJECTED_MEMORIES`` 想避免的事。500 字足够容纳一条家庭事实
#: （「孩子对花生过敏」「明天要竞选班长」），又远小于任何会挤占固定行为边界的规模。
#:
#: **M2.2 搬家（T9f，契约 §6 收口表第 20 项）**：常量从 ``service.py`` 移到本模块，
#: 并**下沉到 ``MemoryStore.write_record()`` 与 DDL CHECK**（T9c 的写入边界表）。
#: ``service.py`` 保留再导出（``apps/memory_cli.py`` 与 ``tests/test_memory_integration.py``
#: 都从 ``service`` 导入它），删掉再导出会打断 W8 的文件。
MAX_CONTENT_CHARS = 500

#: 冻结集合，供契约测试逐值核对。
SCOPES: frozenset[str] = frozenset({"FAMILY", "PERSONAL", "SAFETY"})
MEMORY_CLASSES: frozenset[str] = frozenset({"EVENT", "PREFERENCE", "SAFETY"})
MEMORY_POLICIES: frozenset[str] = frozenset({"persist_confirmed", "candidate_only"})
REQUESTED_POLICIES: frozenset[str] = MEMORY_POLICIES | {"do_not_persist"}
MEMORY_STATUSES: frozenset[str] = frozenset(
    {"PENDING_CONFIRMATION", "ACTIVE", "DECAYED", "DELETED"}
)
SOURCE_TYPES: frozenset[str] = frozenset(
    {"explicit_user", "explicit_adult", "confirmed_candidate", "auto_extracted"}
)
CANDIDATE_ORIGINS: frozenset[str] = frozenset({"explicit_user", "auto_extracted"})
QUERY_PURPOSES: frozenset[str] = frozenset(
    {
        "session_projection",
        "adult_list",
        "adult_inspect",
        "deletion_audit",
        "control_plane_review",
    }
)
ACTOR_KINDS: frozenset[str] = frozenset(
    {"adult_control_plane", "session_proposal", "ttl_expiry", "migration"}
)

#: 状态机合法迁移表（W0 冻结规格数据，非实现）。
#:
#: 规则：
#: - ``DELETED`` 是终态，无出边。
#: - 候选（``PENDING_CONFIRMATION``）**不 decay**：它从未进入召回路径，
#:   「停止召回」对它无意义。候选到期走 :data:`CANDIDATE_EXPIRY_IS_HARD_DELETE`
#:   描述的**硬删除**路径，不是状态迁移。
#: - ``ACTIVE`` 的自环是 ``correct`` / 再次确认：状态不变，刷新
#:   ``updated_at`` / ``last_confirmed_at`` / ``expires_at``。
#: - ``DECAYED`` 可被成人重新确认回到 ``ACTIVE``（需要新 ``consent_version``）。
#: - 不存在 ``ACTIVE -> PENDING_CONFIRMATION`` 的回退：已确认的记录不重新变候选。
#:
#: **指向 ``DELETED`` 的三条边在 M2.1 没有产出路径**（删除即硬删）。保留它们是为了
#: 读取迁移/导入的历史墓碑数据，以及 M2.2+ 可能的延迟删除。契约页 §2.3 的迁移表
#: 逐行标注了「M2.1 是否产出」。
LEGAL_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("PENDING_CONFIRMATION", "ACTIVE"),  # confirm_shared（成人）
        ("PENDING_CONFIRMATION", "DELETED"),  # M2.1 不产出：仅历史墓碑
        ("ACTIVE", "ACTIVE"),  # correct / 再次确认（自环）
        ("ACTIVE", "DECAYED"),  # TTL 到期
        ("ACTIVE", "DELETED"),  # M2.1 不产出：仅历史墓碑
        ("DECAYED", "ACTIVE"),  # 成人重新确认
        ("DECAYED", "DECAYED"),  # 幂等 no-op
        ("DECAYED", "DELETED"),  # M2.1 不产出：仅历史墓碑
    }
)

#: 允许由 ``ttl_expiry`` 触发（即非成人动作）的状态迁移。
#:
#: **只有一条**：已确认记录到期转 ``DECAYED``（停止召回但不删盘 —— D5）。
#: 候选到期不是状态迁移，见 :data:`CANDIDATE_EXPIRY_IS_HARD_DELETE`。
TTL_TRANSITIONS: frozenset[tuple[str, str]] = frozenset({("ACTIVE", "DECAYED")})

#: 候选到期 —— **见证值，不是迁移**。
#:
#: 到期候选执行**硬删除**（删行 + 写 ``deletion_audit``），不做状态翻转。
#: 理由：状态翻转并不消除磁盘驻留，而把「不再召回」当成「已删除」是本项目明令禁止的
#: 表述（契约页 §7.3）。候选从未进入召回路径，没有任何保留价值。
#:
#: **``memory_class="SAFETY"` 的候选同样受 7 天候选期约束** —— 只有**已确认的**
#: SAFETY 类记录才不过期（D5）。见契约页 §6.2。
CANDIDATE_EXPIRY_IS_HARD_DELETE = True

#: **血缘删除口径（A2）。** ``True`` = 删除一条记录时**只删掉它自己作为子节点的血缘行**
#: （``memory_source.record_id = ?``），**指向它的血缘行保留**（``source_id = ?``），
#: 派生记录不连带删除、而是靠 ``missing_provenance`` 永久 fail-closed。
#:
#: 为什么不做级联删除：级联删除是一次递归的、可能部分失败的图操作；一旦失败就会留下
#: 「看起来没有祖先」的干净记录 —— 那正是最危险的越权路径。fail-closed 解析则是一次
#: 可证明的检查，失败方向永远偏向「读不到」。
#:
#: 代价是派生记录**仍留在盘上**，因此必须如实列进
#: :attr:`DeletionReport.derived_unreachable`。
DELETE_KEEPS_INBOUND_PROVENANCE = True

#: 状态与写入策略的绑定不变量。DDL 的 ``memory_record_status_policy_check``
#: 逐条强制它；库内出现不符即为契约违规，读路径报 ``policy_denied``。
#: ``DELETED`` 保留删除时的策略值（审计用），因此不在表内。
STATUS_POLICY_INVARIANT: dict[str, str] = {
    "PENDING_CONFIRMATION": "candidate_only",
    "ACTIVE": "persist_confirmed",
    "DECAYED": "persist_confirmed",
}


# --------------------------------------------------------------------------
# 数据类
# --------------------------------------------------------------------------


def _validation_error(message: str) -> ValueError:
    """构造 :class:`soul_memory_kernel.memory.service.MemoryValidationError`。

    **为什么延迟导入**：错误层级按契约页 §4.7 定义在 ``service.py``，而 ``service.py``
    在模块级导入 ``model`` / ``store``。在本模块（以及 ``store``）顶层导入它会让
    ``model → service → model`` 变成循环导入。延迟到调用点导入即可，异常类型与
    捕获行为都不变（``MemoryValidationError`` 是 ``ValueError`` 的子类）。
    """

    from soul_memory_kernel.memory.service import MemoryValidationError

    return MemoryValidationError(message)


@dataclass(frozen=True)
class Actor:
    """一次写入动作的归属者。每个写路径都必须带 ``actor``，便于审计。

    四种 ``kind`` 的权限边界（**收紧定义，不留含糊**）：

    ``adult_control_plane``
        唯一可以改变**召回语义**的 actor：确认候选、修正、删除、重新确认。
        全部经由 `family-ai-memory` CLI（D3）。
    ``session_proposal``
        **只能通过 ``propose()`` 落一条候选**（``PENDING_CONFIRMATION`` +
        ``candidate_only``）。**禁止** confirm / correct / delete / share / 重新确认，
        也**禁止**修改任何既有记录。会话里家人说「记住这个」用的是这个 kind；
        **严禁记成 ``adult_control_plane``** —— 那会把家人的随口一说伪装成成人已确认。
    ``ttl_expiry``
        只能做两件事：(1) 已确认记录 ``ACTIVE -> DECAYED``；(2) **硬删除**到期候选
        （含写 ``deletion_audit``）。不能确认、不能修正、不能重新激活。
    ``migration``
        schema 版本迁移专用。**M2.1 没有任何迁移，因此该 actor 在 M2.1 无可用动作**；
        它存在只是为将来的 schema 升级预留归属。允许：改写非召回字段
        （时间戳格式、索引重建）。**禁止**：新增或恢复可召回记录、把 ``DECAYED``
        改回 ``ACTIVE``、修改 ``consent_version``、删除或新增 ``deletion_audit`` 行、
        修改任何 ``content``。

    任何不被上述清单允许的组合都必须抛 ``IllegalTransition``（grant 路径抛
    ``MemoryValidationError``），不得静默执行。
    """

    kind: ActorKind
    actor_id: str


#: D5 保留天数默认值。``EVENT`` / ``PREFERENCE`` 可配置；``SAFETY`` **不是配置项** ——
#: 「安全类不过期」是硬不变量，不是旋钮（见 ``MEMORY_RECORD_DDL`` 的第一条 CHECK）。
DEFAULT_TTL_EVENT_DAYS = 30
DEFAULT_TTL_PREFERENCE_DAYS = 180
#: 未确认候选的保留天数。取 7 天：候选从未进入召回路径，留得越久越是纯粹的
#: 儿童数据磁盘驻留。**这是 W0 在 D5 范围内的补充冻结**（D5 只裁到已确认记录），
#: 审阅时若要改，只需改这个常量与契约页。
DEFAULT_TTL_CANDIDATE_DAYS = 7


@dataclass(frozen=True)
class RetentionPolicy:
    """分型 TTL（D5）。

    ``expires_at`` 在**写入时**按当时的配置算好并落库，之后不随配置变化重算。
    理由：追溯性重算会静默地让一批已有家庭数据提前过期或复活，而每条记录对家人
    的保留承诺应当是稳定的。配置改动只影响新写入的记录。
    """

    event_days: int = DEFAULT_TTL_EVENT_DAYS
    preference_days: int = DEFAULT_TTL_PREFERENCE_DAYS
    candidate_days: int = DEFAULT_TTL_CANDIDATE_DAYS

    def __post_init__(self) -> None:
        """校验三个天数都是正整数。

        契约页 §6.1 把「非整数或 ``<= 0``」判为**配置错误**（env 侧的抛
        ``ConfigError``，归 W4 的 ``config.py``）。这里再加一道类型内的防线：即使
        有人绕过配置层直接构造本 dataclass，也不允许出现「0 天保留」这种会把新记录
        写成**一落库就过期**的取值。``bool`` 是 ``int`` 的子类，必须显式排除，否则
        ``RetentionPolicy(event_days=True)`` 会静默变成 1 天。
        """

        for name in ("event_days", "preference_days", "candidate_days"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise _validation_error(
                    f"retention policy {name} must be a positive integer, got {value!r}"
                )

    def days_for(self, memory_class: MemoryClass, *, is_candidate: bool) -> int | None:
        """返回该类型的保留天数；``None`` 表示不过期（仅 ``SAFETY``）。

        契约页 §6.2 的两条口径都收敛在这里：

        - **候选（任何 ``memory_class``，含 ``SAFETY`` 类）一律走候选期** ——
          D5 的「安全记忆不过期」只适用于被确认下来的安全事实。
        - **已确认的 ``SAFETY`` 类不过期**（``None``）；``EVENT`` / ``PREFERENCE``
          各按自己的天数。

        未知 ``memory_class`` 是入参形状非法（不是「默认 30 天」），必须 fail-closed。
        """

        if memory_class not in MEMORY_CLASSES:
            raise _validation_error(f"unknown memory_class: {memory_class!r}")
        if is_candidate:
            return self.candidate_days
        if memory_class == "SAFETY":
            return None
        return self.event_days if memory_class == "EVENT" else self.preference_days


@dataclass(frozen=True)
class Grant:
    """应用侧签发的短期会话授权（D1）。

    **Grant 不是身份认证。** 它只约束「应用这次能读什么」。它不证明说话的是谁，
    不排除旁听者，也不能从「家人可读」推出「可外放」。签名/存储都不是密码学凭证。
    """

    grant_id: str
    version: int
    session_id: str
    subject_id: str
    owner_id: str
    audience_id: str
    actions: frozenset[str]
    resource_ids: frozenset[str]
    consent_versions: tuple[tuple[str, int], ...]
    expires_at: str
    #: D1：预留 OS 本机绑定。M2.1 固定为本机控制面标识，取值留空表示未绑定。
    issuer: str
    issued_at: str

    def consent_version_for(self, record_id: str) -> int | None:
        """返回该记录在授权时的同意版本；缺省表示未覆盖该记录。

        ``consent_versions`` 是 ``(record_id, version)`` 的元组（来自 ``grant_resource``
        表，主键 ``(grant_id, grant_version, record_id)`` 保证同一个 ``grant_id`` 下
        不会有重复记录）。若调用方硬塞进重复项，取**首个**匹配 —— 判权要的是确定性，
        不是在这一层抛错。
        """

        for candidate_id, version in self.consent_versions:
            if candidate_id == record_id:
                return version
        return None


@dataclass(frozen=True)
class MemoryRecord:
    """一条已落库的记忆。字段对齐 M2-PREPARATION 第 7 行，只增四项授权必需项。

    相对该字段表的增补（都是授权判定必需，理由见契约页 §数据模型）：
    ``memory_class``（D5 保留类型）、``audiences``（FAMILY 的显式受众）、
    ``consent_version``（同意版本，供 grant 绑定）、``source_ids``（派生来源）、
    ``actor_kind`` / ``actor_id``（A12 写入归属）。

    **M2.1 相位限制**：产品路径只会落库 ``scope="FAMILY"`` 的记录
    （见 :data:`M2_1_ALLOWED_SCOPES`）。``scope`` 字段本身保留三值形状，
    是为了 M2.2 接私人会话时不必改类型。
    """

    id: str
    owner_id: str
    scope: Scope
    memory_class: MemoryClass
    source_type: SourceType
    source_member_id: str | None
    content: str
    confidence: float
    importance: float
    created_at: str
    updated_at: str
    last_confirmed_at: str | None
    expires_at: str | None
    source_session_id: str | None
    status: MemoryStatus
    memory_policy: MemoryPolicy
    audiences: frozenset[str]
    consent_version: int
    source_ids: tuple[str, ...] = ()
    #: **T9c：这条记录的正文是否超过 :data:`MAX_CONTENT_CHARS`（历史超长标记）。**
    #:
    #: ``0`` = 正常（新写入一律是 0）；``1`` = **历史遗留的超长行**（v2→v3 迁移时
    #: ``length(content) > 500`` 的既有行）。M2.1 的上限只在 service 层卡，store 层不卡，
    #: 因此库里存在超长行是**可达状态**；v3 的处置是**不截断、不删除**，标记 + 新写入硬拒
    #: （``CHECK (content_over_length = 1 OR length(content) <= 500)``）。
    #:
    #: 写入边界（契约 §6 T9c 的表，由 ``SqliteMemoryStore.write_record`` 执行）：
    #: 该列是**派生值** —— 只在 ``content`` 变更时才允许（且必须）清零；正文不变时
    #: 必须原样保留。调用方凭空写 1、或在正文不变时清掉 1，都会被拒绝。
    #: 修复路径是复用的 ``correct()``（把正文改到 ≤500 ⇒ 标记自动清零）。
    content_over_length: int = 0
    #: **A12：最后一次写入该记录的应用主体**（谁创建的、谁改的）。
    #:
    #: 与 ``deletion_audit.actor_*`` 分工：那里记「谁删的」（行没了，事实留在审计表），
    #: 这里记「谁写的」（行还在，归属跟着行）。**归属不可由记录伪造** ——
    #: ``write_record(record, actor=...)`` 用它的 ``actor`` 参数覆盖这两个字段。
    #:
    #: 默认值是 **v1→v2 迁移**的归属：M2.1 之前的行没有 actor 可言，
    #: 如实记成 ``migration`` 比编一个假的成人动作诚实。
    actor_kind: ActorKind = "migration"
    actor_id: str = "migration:v1->v2"


@dataclass(frozen=True)
class MemoryCandidate:
    """写入请求。``propose()`` 的唯一入参形状（D2）。

    ``origin`` 区分「家人显式要求记住」与「M2.2 自动提取」：M2.1 只接受
    ``explicit_user``，但形状现在就是自动候选要用的形状，M2.2 不需要改签名。
    """

    content: str
    scope: Scope
    memory_class: MemoryClass
    owner_id: str
    source_type: SourceType
    source_member_id: str | None
    confidence: float
    importance: float
    requested_policy: RequestedPolicy = "candidate_only"
    audiences: frozenset[str] = field(default_factory=frozenset)
    origin: CandidateOrigin = "explicit_user"


@dataclass(frozen=True)
class SourceSession:
    """候选的来源会话。用于写 ``source_session_id`` 与判定「谁在写」。"""

    session_id: str
    owner_id: str | None
    audience_id: str
    session_mode: SessionMode
    identity_assurance: IdentityAssurance
    grant_id: str | None


@dataclass(frozen=True)
class MemoryCorrection:
    """``correct()`` 的替换内容。

    **不可改字段在类型上就不可表达**：``id`` / ``owner_id`` / ``scope`` /
    ``memory_class`` / ``source_type`` / ``source_member_id`` / ``created_at``
    没有对应参数，因此实现方无法「顺手」改掉归属或来源。
    """

    content: str | None = None
    importance: float | None = None
    audiences: frozenset[str] | None = None


@dataclass(frozen=True)
class DeletionOutcome:
    """``MemoryStore.hard_delete_with_audit()`` 的返回（**A11**，主控 2026-09-26 裁决）。

    删除与审计必须**同一事务**：一次成功的家庭数据删除不可能不留审计，
    失败时记录仍在、审计 0 行。这个类型把「删了什么」与「审计 id」一起交回来，
    避免调用方自己去拼两个可能来自不同事务的事实。
    """

    record_id: str
    #: 真的删掉了行的表（``rowcount > 0``），**已含** ``deletion_audit``。
    tables_touched: tuple[str, ...]
    #: 同事务写入的审计行 id。
    audit_id: str


@dataclass(frozen=True)
class MigrationReport:
    """一次 schema 迁移的结果（**T9b，纯返回值，不含正文**）。

    M2.2 §3.9 冻结的唯一「被标记的超长历史行」可观测面之一（另一个是
    ``family-ai-memory list`` 的表头计数，归 W8）。**不新增日志事件**：计数走返回值，
    不经过 JSONL。

    字段：

    - ``from_version`` —— 打开这个库时它**实际处在**的 schema 版本（v1 库走完
      v1→v2→v3 一条链，报告里就是 ``1``；v2 库就是 ``2``）。它是「这次打开做了什么」
      的如实记录，不是「产生报告的那一段」的编号 —— 两段迁移各自是独立事务
      （T9a），而报告描述的是**整次打开**。
    - ``to_version`` —— 迁移完成后的版本（M2.2 恒为 ``3``）。
    - ``over_length_count`` —— 迁移后 ``content_over_length = 1`` 的行数（历史超长行，
      原样保留、标记、新写入硬拒）。**只有计数，没有正文、没有 id。**
    """

    from_version: int
    to_version: int
    over_length_count: int


@dataclass(frozen=True)
class SnapshotEntry:
    """投影快照里的一条。``content`` 仅在携带正文的 purpose 下非空。"""

    record_id: str
    owner_id: str
    scope: Scope
    memory_class: MemoryClass
    content: str | None
    importance: float
    last_confirmed_at: str | None


@dataclass(frozen=True)
class MemorySnapshot:
    """``query()`` 的返回：不可变、已按授权过滤、会话期间不再重查。"""

    snapshot_id: str
    session_id: str
    audience_id: str
    purpose: QueryPurpose
    record_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    entries: tuple[SnapshotEntry, ...]
    #: 被拒绝的记录与原因。**只含 id 与固定枚举 reason，绝不含正文。**
    #:
    #: **可以写进应用内的审计表（如 ``deletion_audit``），但不进 JSONL 事件日志。**
    #: M1 的日志纪律是「默认只存白名单元数据」：事件日志只接受数值与固定枚举，
    #: 记录 id 不属于白名单。需要逐条追溯拒绝原因的场合用审计表，不要用事件日志。
    denied: tuple[tuple[str, str], ...]
    created_at: str


@dataclass(frozen=True)
class DeletionReport:
    """``delete()`` 的结果。**必须诚实报告删不掉的部分。**

    ``unknown_copies`` 显式列出枚举不到的位置；**禁止填 0 冒充完整**。
    "不再召回" 不等于 "磁盘已删除"；本报告只描述应用可控范围。

    血缘口径（A2 统一后）：删除一条记录**不连带删除**它的派生记录，只删掉它
    **自己作为子节点**的血缘行；指向它的血缘行**保留**，于是派生记录在解析时
    命中 ``missing_provenance`` 而永久不可召回（fail-closed）。因此：

    - ``derived_removed`` —— **实际被删除**的派生记录。M2.1 没有派生路径，恒为 ``()``。
    - ``derived_unreachable`` —— 因祖先被删而永久不可召回、但**仍留在盘上**的派生
      记录。它们是「删不掉的部分」的一种，必须如实列出，否则报告会让人误以为
      派生内容已经消失。
    """

    record_ids: tuple[str, ...]
    tables_touched: tuple[str, ...]
    derived_removed: tuple[str, ...]
    derived_unreachable: tuple[str, ...]
    fulltext_eval_copies_removed: tuple[str, ...]
    unknown_copies: tuple[str, ...]
    audit_id: str
    deleted_at: str
