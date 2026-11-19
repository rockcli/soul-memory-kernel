"""M2 授权函数（W0 冻结签名与语义；实现归 W2）。

``authorize()`` 是 **M2 记忆读写的唯一授权入口**。任何绕过它的读取都是契约违规：
没有第二条路径，也没有「先读出来再过滤」的写法（那等于把越权数据放进了进程）。

与 M1 :meth:`soul_memory_kernel.soul.policy.SessionAccess.may_inject` 的关系（刻意的分工，
不是重复）：

- ``may_inject()`` 服务 **M1 静态家人档案**路径，语义冻结在 M1 契约里，M2.1 不改它。
  W4 只给 ``SessionAccess`` 增加授权凭据引用字段，不碰 ``may_inject`` 的分支。
- ``authorize()`` 服务 **M2 记忆**路径。

因此会出现一个**有意的非对称**：持有效 grant 时，``may_inject()`` 对 ``PERSONAL``
仍返回 ``False``，而 ``authorize()`` 可以放行 ``PERSONAL`` 记忆。这不是矛盾 ——
前者管「静态档案能不能进投影」，后者管「记忆记录能不能读」。M2.2+ 若要把两者统一，
必须走契约变更，不得在实现里顺手合并。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from soul_memory_kernel.memory.model import (
    M2_1_ALLOWED_SCOPES,
    MEMORY_POLICIES,
    STATUS_POLICY_INVARIANT,
    Grant,
    MemoryRecord,
)
from soul_memory_kernel.soul.policy import SessionAccess

#: 逐动作授权。沿用原型 ``PrivacyKernel`` 的动作集合（读模型 / 发 provider /
#: 两个出口 / 三个写动作），不新增也不删减 —— M2.1 的产品路径只用到
#: ``read_model``（本地查询）与 ``send_provider``（把快照交给模型），其余动作
#: 先冻结语义，留给 M2.2 的 Pending 与后续出口门禁。
#:
#: **M2.2 的加法（D11 / §4.1）**：新增 ``review_control_plane`` —— 成人复审候选
#: 正文的**只读**动作。它是**免 grant** 动作（见 :data:`NO_GRANT_EXEMPT_ACTIONS`），
#: 只在 ``session_mode == "control_plane"`` 的访问形态下可用（见 :func:`_is_control_plane`），
#: 并且**只**跳过记录级的 ``status_denied``。
Action = Literal[
    "read_model",
    "send_provider",
    "publish_text",
    "play_audio",
    "write",
    "share",
    "delete",
    "review_control_plane",
]

#: 拒绝原因。**固定枚举，不是自由文本** —— 因此可以安全写进日志与审计
#: （白名单只接受已知取值，不携带任何被拒记录的正文或 id 之外的上下文）。
#:
#: **没有 ``revoked``**（A4）：撤销是**存储层语义** —— ``revoke()`` 之后
#: ``load_current`` / ``load_for_session`` 返回 ``None``，``authorize()`` 看到的是
#: ``grant=None``，落成 ``no_grant``。判权函数不读任何撤销标记，也不该读：
#: 让「已撤销」与「从未签发」在判权层不可区分，就没有「撤销状态没读到」这个失败模式。
Reason = Literal[
    "ok",
    "clock_invalid",
    "no_grant",
    "expired",
    "not_yet_valid",
    "wrong_session",
    "wrong_owner",
    "wrong_audience",
    "action_not_granted",
    "resource_not_granted",
    "missing_provenance",
    "scope_not_enabled",
    "scope_denied",
    "policy_denied",
    "status_denied",
    "record_expired",
    "stale_consent",
]

ACTIONS: frozenset[str] = frozenset(
    {
        "read_model",
        "send_provider",
        "publish_text",
        "play_audio",
        "write",
        "share",
        "delete",
        "review_control_plane",
    }
)

#: 无 grant 也能走的动作白名单（A5 + M2.2 §4.1）。
#:
#: 覆盖**读取**的三个动作：``read_model``（本地查询）、``send_provider``
#: （把已投影快照交给模型，§10.1 的接缝）与 ``review_control_plane``（成人复审候选，
#: D11；**只在控制面访问形态下可用**，前置模式校验在 grant 段之前）。
#:
#: **出口动作** ``publish_text`` / ``play_audio`` 不在其中 —— 「外放到公共空间」与
#: 「家人可读」是两件事（§2.1），授权给家人绝不等于可以外放。
#: **写动作** ``write`` / ``share`` / ``delete`` 同样永远需要成人控制面授权。
#:
#: ``review_control_plane`` 进这个集合**不是漏洞**：四条边界同时成立 ——
#: ① 只在 ``control_plane`` 模式可用（会话路径拿不到）；② 只覆盖 ``FAMILY``
#: （``PERSONAL`` / ``SAFETY`` 仍 ``scope_not_enabled``）；③ 永不进入投影；
#: ④ 唯一构造点被 AST 锁死在 ``memory_cli.py``（§4.2）。
#: **实现判定用的是 authorize() 里那条无条件规则**，不是本集合里其余两项的
#: 「FAMILY + 受众命中」条件 —— 否则一条 ``PERSONAL`` 候选会先撞 ``no_grant``，
#: 而不是 D11 硬边界 2 要求的 ``scope_not_enabled``（§4.1 末段）。
NO_GRANT_EXEMPT_ACTIONS: frozenset[str] = frozenset(
    {"read_model", "send_provider", "review_control_plane"}
)

#: **M2.1 写路径的 actor 门（A7 + A8）。** 键是 ``MemoryService`` 的写方法名，
#: 值是该操作允许的 ``Actor.kind`` 集合。不在集合里的一律拒绝。
#:
#: - ``propose`` 允许 ``session_proposal``：会话里家人说「记住这个」由**会话**发起。
#:   成人经 CLI 直接提议也算（``adult_control_plane``）。
#: - 其余写操作**只允许** ``adult_control_plane``：确认、修正、删除都改变召回语义，
#:   是成人动作（D3）。
#: - ``sweep_expired`` 只允许 ``ttl_expiry``：它是时间驱动的收尾，不是人发起的决定。
#: - **M2.2 新增 ``reassign_owner``（D13 / §2.4 T26'）**：只允许 ``adult_control_plane``。
#:   它只对**候选**生效，且只改归属（``consent_version + 1``），不碰内容与来源 ——
#:   与 ``correct`` 分开，因为二者要守的边界不同。
#:
#: **这份表是 M2.1 写门禁的第二道**（第一道是相位门，第三道是迁移表）。
M2_1_WRITE_GATE: dict[str, frozenset[str]] = {
    "propose": frozenset({"adult_control_plane", "session_proposal"}),
    "confirm_shared": frozenset({"adult_control_plane"}),
    "correct": frozenset({"adult_control_plane"}),
    "delete": frozenset({"adult_control_plane"}),
    "sweep_expired": frozenset({"ttl_expiry"}),
    "reassign_owner": frozenset({"adult_control_plane"}),
}

#: **M2.1 的写路径不使用 :func:`require`**（A7）。
#:
#: M2.1 的写门禁是「相位门 + actor 门（:data:`M2_1_WRITE_GATE`）+ 迁移表」三重检查，
#: 由 ``MemoryService`` 直接执行 —— 这个组合比单次 ``authorize()`` 调用更严格，
#: 也更容易逐条验收。``require()`` 从 **M2.2 起**才是写路径的统一入口，签名现已冻结。
M2_1_WRITE_PATHS_USE_REQUIRE = False

REASONS: frozenset[str] = frozenset(
    {
        "ok",
        "clock_invalid",
        "no_grant",
        "expired",
        "not_yet_valid",
        "wrong_session",
        "wrong_owner",
        "wrong_audience",
        "action_not_granted",
        "resource_not_granted",
        "missing_provenance",
        "scope_not_enabled",
        "scope_denied",
        "policy_denied",
        "status_denied",
        "record_expired",
        "stale_consent",
    }
)

#: 拒绝检查的**固定顺序**（拒绝优先，第一个命中的原因就是返回值）。
#:
#: 顺序原则：先判「这次授权本身是否可信」，再判「这条记录能不能做这个动作」。
#: 越基本的原因越靠前 —— 这样审计看到的拒绝理由不会因为记录级细节而掩盖
#: 「压根没有有效授权」这一事实。
#:
#: 两处**刻意**的相邻关系：
#:
#: - ``scope_not_enabled`` 在 ``scope_denied`` **之前**：整个 scope 在本相位没启用，
#:   比「这个受众读不到这条记录」更基本。
#: - ``policy_denied`` 在 ``status_denied`` **之前**：策略与状态不符（或被禁止的策略
#:   出现在库里）是**契约违规/数据损坏**，比「状态不是 ACTIVE」更严重，不该被后者掩盖。
#:
#: 实现必须按这个元组逐个检查并在首个失败处返回；不得重排、不得合并分支、
#: 不得「先收集所有失败再挑一个报」。测试会按此顺序构造多重违规输入。
DENY_ORDER: tuple[str, ...] = (
    "clock_invalid",
    "no_grant",
    "expired",
    "not_yet_valid",
    "wrong_session",
    "wrong_owner",
    "wrong_audience",
    "action_not_granted",
    "resource_not_granted",
    "missing_provenance",
    "scope_not_enabled",
    "scope_denied",
    "policy_denied",
    "status_denied",
    "record_expired",
    "stale_consent",
)

# ``not_yet_valid`` 的位置（B-s1，主控 2026-09-26）：紧跟在 ``expired`` 之后。
#
# 两者是同一类检查 —— **grant 的时间窗**（``expired`` 管右端 ``now >= expires_at``，
# ``not_yet_valid`` 管左端 ``now < issued_at``）。放在一起让「授权在时间上不成立」
# 这一段在审计里连成一块；``issue()`` 已经保证 ``issued_at < expires_at``，
# 因此两者的先后对结论没有影响，纯粹是可读性。

# ``record_expired`` 的位置（B2，主控 2026-09-26）：在 ``status_denied`` 之后、
# ``stale_consent`` 之前。
#
# 理由：``status_denied`` 是**主门** —— 候选 / ``DECAYED`` / 墓碑与时间无关地拒绝；
# ``record_expired`` 是**补充门** —— 它的典型场景是「记录已过期、但 ``sweep`` 还没把
# 状态落成 ``DECAYED``」（状态仍是 ``ACTIVE``）。先报状态更根本，也更有信息量：
# 一条候选即使同时过期，正确的解释是「候选不可召回」，而不是「它过期了」
# （候选到期走的是**硬删除**，不是读取拒绝）。
#
# 它是**记录级**检查，因此 **A5' 豁免的记录同样执行** —— 家庭共享读取可以不带 grant，
# 但一条过了期的共享记忆不该被读出来。


@dataclass(frozen=True)
class AuthorizationDecision:
    """授权结论。

    返回 ``reason`` 而不是 ``bool``：生产排障需要区分「没有 grant」与
    「有 grant 但这条记录的同意版本变了」。``reason`` 是固定枚举，因此可以
    进日志白名单，不违反 M1 的日志隐私纪律。
    """

    allowed: bool
    reason: Reason


#: 全放行 / 全拒绝两个构造快捷方式（只构造结论，不做判定）。
ALLOWED = AuthorizationDecision(allowed=True, reason="ok")
DENIED_NO_GRANT = AuthorizationDecision(allowed=False, reason="no_grant")


# --------------------------------------------------------------------------
# 实现辅助（W2）。以下都是**私有判定片段**，不是第二条授权入口：
# ``authorize()`` 仍是唯一入口，这些函数只被它调用。
# --------------------------------------------------------------------------

#: 无 grant 也能走的**读取**动作（契约 §3.3「``no_grant`` 的例外」）。
#:
#: 例外只覆盖读取：``read_model``（本地查询）与 ``send_provider``（把快照交给模型，
#: §10.1 的投影路径）。**出口动作** ``publish_text`` / ``play_audio`` 不在其中 ——
#: 「外放到公共空间」与「家人可读」是两件事（§2.1），
#: 授权给家人绝不等于可以外放，因此出口动作与写动作一样必须有 grant。
#:
#: 契约把例外写成「``FAMILY`` 且受众命中的**读取**」，并把 ``write`` / ``share`` /
#: ``delete`` 点名为「永远需要授权」；本集合是读侧的白名单读法（fail-closed）。
#: 这是一处契约口径需要 r3 明确的点，已随 W2 交付报告上报。
_GRANT_FREE_READ_ACTIONS: frozenset[str] = frozenset({"read_model", "send_provider"})


def _deny(reason: Reason) -> AuthorizationDecision:
    return AuthorizationDecision(allowed=False, reason=reason)


def _parse_utc(value: object) -> datetime | None:
    """解析 ISO-8601 UTC 时间戳；不可解析、缺时区、或非字符串一律返回 ``None``。

    **无时区偏移的时间戳判为不可信**：``now`` 的契约类型是「ISO-8601 UTC」，
    naive 时间戳无法证明自己是 UTC，与带时区的 ``expires_at`` 比较也没有定义，
    因此 fail-closed 处理（``now`` 走 ``clock_invalid``，``expires_at`` 走 ``expired``）。
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


def _is_control_plane(access: object) -> bool:
    """这次访问是不是**控制面复审**形态（§4.1 的前置模式校验）。

    ``True`` 必须同时满足三条（契约 §4.2 第 1 条与 §4.1 的表）：

    1. ``access.session_mode == "control_plane"``；
    2. ``access.session_owner is None`` —— **控制面不是某个人**；
    3. ``access.authorization_ref`` 是非空字符串。

    **它必须是全函数**（A 的 N7）：对非 :class:`SessionAccess`、模式不对、owner 非空、
    ref 为空的输入一律返回 ``False``，**绝不抛异常**。理由：``authorize()`` 是纯函数，
    契约要求它对任何入参都返回结论；类型兜底已经把「不可用的输入」变成了 ``no_grant``，
    模式校验不能反而制造一个新的抛错点。

    **它不是身份校验**：``authorization_ref`` 可伪造，真正的护栏是「``control_plane``
    访问的唯一构造点是本机 CLI」那条 AST 扫描（§4.2，归 W8 的
    ``SessionAccess.for_control_plane()``）。本函数只负责把「访问形态不对」这件事
    变成 ``action_not_granted``。
    """

    if not isinstance(access, SessionAccess):
        return False
    if getattr(access, "session_mode", None) != "control_plane":
        return False
    if getattr(access, "session_owner", None) is not None:
        return False
    ref = getattr(access, "authorization_ref", None)
    return isinstance(ref, str) and bool(ref.strip())


def _is_grant_exempt(*, record: MemoryRecord, action: Action, audience_id: str) -> bool:
    """**A5'（主控 2026-09-26 裁决）：这条记录是否完全不需要 grant。**

    ``scope`` 在 M2.1 白名单内 + 受众命中 + 读取动作 ⇒ **逐条**跳过整段 grant 检查
    （会话绑定、owner、受众、动作集合、资源覆盖、同意版本全部跳过），
    只留记录级检查（血缘、相位、受众、策略、状态）。

    为什么是「整段跳过」而不是「只跳过资源覆盖」：§3.3 的受众表写明
    「``FAMILY`` | ``audience_id ∈ record.audiences``。**不需要 grant**」。
    若只跳过资源覆盖而保留 owner/受众/会话绑定检查，一个为**私人**会话签发的 grant
    会把全家的共享记忆一并关掉 —— 私人授权不该有这种副作用。

    **不豁免**：写动作与出口动作（``publish_text`` / ``play_audio``）仍然需要 grant
    （A5 的动作白名单）；删除 / 过期 / `DECAYED` / 受众不命中 / 相位 / 策略违规
    等记录级拒绝照常，顺序不变。

    原实现是批量的 ``_family_read_without_grant()``（要求**全部**记录都命中），
    集成时按 A5' 改成逐记录判定，grant 段只对非豁免记录生效。
    """

    return (
        action in _GRANT_FREE_READ_ACTIONS
        and record.scope in M2_1_ALLOWED_SCOPES
        and audience_id in record.audiences
    )


def _record_expired(record: MemoryRecord, now_at: datetime) -> bool:
    """记录自身是否已到期（B2）。

    ``expires_at is None`` = 永不到期（已确认的 ``memory_class="SAFETY"`` 类，D5）。
    ``expires_at`` 不可解析属数据损坏：**按到期处理**（fail-closed，与 ``query()``
    的兜底同口径）—— 无法证明它没过期时，读出来才是最危险的选择。
    """

    if record.expires_at is None:
        return False
    parsed = _parse_utc(record.expires_at)
    return parsed is None or now_at >= parsed


def _scope_denied(*, record: MemoryRecord, access: SessionAccess, audience_id: str) -> bool:
    """契约 §3.3 的 ``scope_denied`` **全表**（两段都写；M2.1 只走 FAMILY 段）。

    - ``FAMILY``：``audience_id ∈ record.audiences``。
    - ``PERSONAL`` / ``SAFETY``：**M2.2+ 定义**，要求 ``controlled_private`` 会话且
      ``access.session_owner == record.owner_id``。M2.1 里这两行恒被
      ``scope_not_enabled`` 先拦下、永远走不到；保留实现是为了 M2.2 不必改契约。
    - 未知 scope：DDL 的 CHECK 已排除；真出现即数据损坏，fail-closed 拒绝。
    """

    if record.scope == "FAMILY":
        return audience_id not in record.audiences
    if record.scope in ("PERSONAL", "SAFETY"):
        return not (
            access.session_mode == "controlled_private"
            and access.session_owner is not None
            and access.session_owner == record.owner_id
        )
    return True


def _policy_denied(*, record: MemoryRecord, action: Action) -> bool:
    """契约 §3.3 的 ``policy_denied`` **四种情形，不多不少**。"""

    policy = record.memory_policy
    if policy == "do_not_persist":  # 1. 被 DDL CHECK 排除的取值 = 契约违规
        return True
    if policy not in MEMORY_POLICIES:  # 2. 未知取值 = 数据损坏 / 未来 schema
        return True
    expected = STATUS_POLICY_INVARIANT.get(record.status)
    if expected is not None and expected != policy:  # 3. status↔policy 不符
        return True
    if action == "share" and policy == "candidate_only":  # 4. 绕过 confirm_shared()
        return True
    return False


def _has_missing_or_cyclic_provenance(records: tuple[MemoryRecord, ...]) -> bool:
    """血缘缺源或成环（契约 ``missing_provenance``）。

    ``records`` 按契约是**已解析的祖先闭包**，所以缺源表现为「某条记录的
    ``source_id`` 不在本次传入的集合里」，成环表现为祖先图里有回路。两者都必须拒绝：
    派生记录要连同每个祖先一起得到授权，绝不「只授权可见的那部分」。
    这里只做集合内一致性检查，**不读数据库**（``authorize()`` 是纯函数）。
    """

    known = {record.id for record in records}
    for record in records:
        if any(source_id not in known for source_id in record.source_ids):
            return True

    edges = {record.id: tuple(record.source_ids) for record in records}
    visiting: set[str] = set()
    done: set[str] = set()
    for start in edges:
        if start in done:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        visiting.add(start)
        while stack:
            node, index = stack[-1]
            children = edges[node]
            if index >= len(children):
                stack.pop()
                visiting.discard(node)
                done.add(node)
                continue
            stack[-1] = (node, index + 1)
            child = children[index]
            if child in visiting:
                return True
            if child not in done:
                visiting.add(child)
                stack.append((child, 0))
    return False


def authorize(
    *,
    action: Action,
    access: SessionAccess,
    grant: Grant | None,
    session_id: str,
    audience_id: str,
    records: tuple[MemoryRecord, ...],
    now: str | None,
) -> AuthorizationDecision:
    """判定一次动作是否被授权。**纯函数，无副作用，不读数据库。**

    参数
    ----
    action:
        见 :data:`Action`。
    access:
        控制面策略状态（会话模式、身份保证级别、声明的 owner）。**不接受任何来自
        模型或 ASR 的输入**：``speaker_claim`` 不是判权输入。
    grant:
        本次会话持有的授权；``None`` 表示没有授权（这是正常状态，不是错误）。
    session_id:
        本次会话的传输标识。**必须由调用方显式传入**，不从 ``access`` 里取 ——
        grant 的会话绑定必须是显式比较，而不是藏在 dataclass 字段里。
    audience_id:
        本次动作的受众。``public_room`` 与「指定家人成员」是**不同**的受众；
        授权给家人绝不等于可以外放。
    records:
        **实际记录**（含解析后的祖先闭包），不是调用方声明的 id 列表。
        传 id 而不传记录会让「先伪造 id 再判权」成为可能。
    now:
        ISO-8601 UTC 时间字符串。``None`` 或不可解析一律 ``clock_invalid`` 拒绝。
        用墙钟而不是单调钟是刻意的：TTL 以「天」为单位，单调钟表达不了留存期。

    返回
    ----
    :class:`AuthorizationDecision`。**任何异常路径都返回拒绝**，不抛异常 ——
    读取路径的「没有授权」是正常结果（退化为「没有记忆」），不是错误。

    检查顺序
    --------
    严格按 :data:`DENY_ORDER` 执行，首个失败即返回。各步语义：

    ``clock_invalid``
        时钟缺失 / 不可解析 / 非有限。**先于一切** —— 时钟不可信时，
        过期与撤销判定都不可信。
    类型兜底（1.4，fail-closed）
        ``access`` 不是 :class:`SessionAccess`、或 ``grant`` 不是 :class:`Grant`
        （且非 ``None``）⇒ ``no_grant``，**不抛异常**。
    ``action_not_granted``（1.5，前置模式校验，M2.2 §4.1）
        仅对 ``review_control_plane``：访问形态不是控制面（:func:`_is_control_plane`
        为假）⇒ ``action_not_granted``。位置在**类型兜底之后**、grant 段之前，
        且不读 ``grant``。它**不是**一条新的 ``DENY_ORDER`` 条目 —— 用的是既有 reason。
    ``no_grant`` / ``expired``
        grant 缺失、``now >= expires_at``（边界取 ``>=``，fail-closed）。
        **撤销不在这里（A4）**：撤销是存储层语义 —— ``revoke()`` 之后 store 返回
        ``None``，本函数看到的就是 ``no_grant``。``revoked`` **不是** ``Reason`` 的
        取值（见 :data:`REASONS`）。
    ``wrong_session`` / ``wrong_owner`` / ``wrong_audience``
        grant 与本次会话的绑定不符。``wrong_owner`` 比较 ``grant.owner_id`` 与
        ``access.session_owner`` —— 这是「拿错 grant」与「用别人的 grant 冒充」的
        拦截点，即使两者都由控制面构造也必须有此检查。
    ``action_not_granted`` / ``resource_not_granted``
        动作或记录不在 grant 范围内。
    ``missing_provenance``
        血缘解析发现缺源或成环。**派生记录必须连同每个祖先都得到授权**，
        因此缺源一律拒绝，绝不「只授权可见的那部分」。
    ``scope_not_enabled``
        **M2.1 相位限制**：产品路径只允许 `FAMILY`（:data:`M2_1_ALLOWED_SCOPES`）。
        任何 `PERSONAL` / `SAFETY` **scope** 的记录一律拒绝，读写皆然。
        受控私人会话与「安全记忆给谁看」需要另行裁决，属 M2.2+。
        **注意**：这管的是 `scope`（谁能读）。`memory_class="SAFETY"`（内容类型，
        如过敏）在 `FAMILY` scope 下照常支持，不受本条影响。
    ``scope_denied``
        **M2.1 只有一种情形**：`FAMILY` 记录但 `audience_id ∉ record.audiences`
        （家庭共享记忆的受众不匹配）。
        `PERSONAL` / `SAFETY` 的分支（要求 `controlled_private` 会话与 owner 一致）
        是 **M2.2+ 定义**：M2.1 里它们恒被 `scope_not_enabled` 先拦下，永远走不到这里。
        `SAFETY` **不是**家人通读许可。
    ``policy_denied``
        记录级写入策略不允许该动作。**四种情形，全部在此枚举，B2 实现不得再发明别的**：

        1. 记录 `memory_policy == "do_not_persist"` —— 该取值被 DDL CHECK 排除，
           库里出现即为契约违规，**拒绝一切动作**（fail-closed），不是「当普通记录处理」。
        2. 记录 `memory_policy` 不是 `persist_confirmed` / `candidate_only` 之一
           —— 数据损坏或来自未来的 schema 版本，同样拒绝一切动作。
        3. `status` 与 `memory_policy` 不符（违反 :data:`STATUS_POLICY_INVARIANT`，
           例如 `status="ACTIVE"` + `memory_policy="candidate_only"`）—— 契约违规。
        4. `action == "share"` 而 `memory_policy == "candidate_only"` —— 试图绕过
           `confirm_shared()` 直接共享候选。共享必须走确认路径，不得跳过。
    ``status_denied``
        只有 `ACTIVE` 可读。`PENDING_CONFIRMATION`（候选）、`DECAYED`
        （已过期）、`DELETED`（墓碑）都不可召回。
        **唯一例外**：``review_control_plane``（成人复审候选）**只**跳过这一条，
        其余记录级检查照常执行（§4.1 的判定表）。
    ``stale_consent``
        ``grant`` 对该记录的同意版本与记录当前 ``consent_version`` 不符。
        重新确认会递增版本，因此旧 grant 自动失效。

    控制面复审（``review_control_plane``，M2.2 §4.1 / D11）
    ------------------------------------------------------
    成人要在 CLI 上读**候选正文**（否则 D3 的「成人确认」是盲确认）。M2.1 的判权
    只让 `ACTIVE` 可读，因此新增这一个动作。三条硬边界（§4.2，不由实现方放宽）：

    1. **只在 ``control_plane`` 访问形态下可用** —— ``session_mode == "control_plane"``
       且 ``session_owner is None`` 且 ``authorization_ref`` 非空；
    2. **只覆盖 ``FAMILY``** —— ``PERSONAL`` / ``SAFETY`` 仍 ``scope_not_enabled``；
    3. **永不进入投影** —— 它不出现在 ``session_projection`` / ``send_provider`` 的
       判定里（``query(purpose="session_projection")`` 的动作仍是 ``read_model``）。

    实现口径（逐项冻结在 §4.1 的表里）：

    - **模式校验**在类型兜底之后、grant 段之前，失败给 ``action_not_granted``；
    - **免 grant 是无条件的**（``needs_grant`` 直接跳过本动作的全部记录），
      **不经过** :func:`_is_grant_exempt` 的「FAMILY + 受众命中」条件 ——
      否则一条 ``PERSONAL`` 候选会先撞 ``no_grant``，而不是硬边界 2 要求的
      ``scope_not_enabled``；
    - **只跳过 ``status_denied``**：``missing_provenance`` / ``scope_not_enabled`` /
      ``scope_denied`` / ``policy_denied`` / ``record_expired`` 一律照常执行；
      ``stale_consent`` 属 grant 段，随该段一起跳过（免 grant 动作本就没有同意绑定）；
    - **空记录集仍是 ``no_grant``**（既有 fail-closed 口径不变）——本动作的实际调用
      永远带 ≥1 条记录（``query()`` 逐条判定）。

    一个连带的、**刻意的**后果（审阅 B 建议 2 登记）：一条 ``DELETED`` 墓碑不被
    ``status_denied`` 拦下 —— 只要它没到期、受众命中、策略自洽，复审动作就能读到它。
    **没有正文可泄露**：DDL 的 ``CHECK (status <> 'DELETED' OR content = '')`` 是 M2.1
    冻结的不变量，而 M2.1 的删除是硬删、不产墓碑。W8 的 CLI 若要把墓碑显示成候选，
    文案上别把它说成「待确认的候选」即可。

    家庭共享路径的豁免（A5 + A5'）
    ------------------------------
    动作白名单（A5）：例外**只覆盖三个动作** —— ``read_model`` / ``send_provider`` /
    ``review_control_plane``（:data:`NO_GRANT_EXEMPT_ACTIONS`）。出口动作与写动作
    一律需要 grant ——「外放到公共空间」和「授权给家人」是两件事。

    豁免范围（**A5'，主控 2026-09-26 裁决，取代 A5 的原始读法**）：
    ``scope`` 在 M2.1 白名单内 + 受众命中 + 读取动作的记录，**逐条跳过整段 grant 检查**
    （会话绑定 / owner / 受众 / 动作集合 / 资源覆盖 / 同意版本全部跳过），
    见 :func:`_is_grant_exempt`。

    - 原 A5 读法（「只豁免『没有 grant』，有 grant 时 grant 检查照常执行」）会让一个为
      **私人**会话签发的 grant 把全家的共享记忆一并关掉 —— 私人授权不该有这种能力。
    - 无论豁免与否，``scope_not_enabled`` / ``scope_denied`` / ``policy_denied`` /
      ``status_denied`` / ``missing_provenance`` / 记录到期等**记录级**检查一律照常，
      :data:`DENY_ORDER` 顺序不变。
    - **豁免不扩大**：受众不命中的 ``FAMILY`` 记录、``PERSONAL`` / ``SAFETY`` 记录、
      以及写 / 出口动作都不在豁免范围。

    M2.1 与 M2.2 的相位
    -------------------
    M2.1 的产品路径只召回 ``FAMILY``。上表里所有 `PERSONAL` / `SAFETY` 分支都是
    **M2.2+ 定义**，M2.1 里被 ``scope_not_enabled`` 提前拦下。实现必须两段都写
    （否则 M2.2 要改契约），但 M2.1 的验收只覆盖 `FAMILY` 路径。

    ``require()`` 的适用相位
    -----------------------
    **M2.1 的写路径不走 ``require()``**（A7）：M2.1 的写门禁是
    「相位门 + actor 门 + 迁移表」三重检查（§3.7），由 ``MemoryService`` 直接执行。
    ``require()`` 保留为 M2.2 起写路径的统一入口，签名现在冻结、M2.1 不调用。

    实现口径（W2 补充，不改上表语义）
    -------------------------------
    - **检查顺序的外层是** :data:`DENY_ORDER` **，内层是** ``records`` **的顺序**：
      每一步都先检查全部记录再进入下一步，因此「记录 A 在后面的步骤失败、记录 B 在
      前面的步骤失败」报的是**前面**那个原因，与记录的传入顺序无关。
      ``authorize()`` 是对整批记录的单一结论（全通过才 ``ok``）。
    - **``records`` 为空**：没有记录级失败，grant 前置条件全过即 ``ok``；
      无 grant 且不是家庭共享读取时仍是 ``no_grant``。
    - **``grant.expires_at`` 不可解析**时按 ``expired`` 拒绝 —— 无法证明它没过期，
      fail-closed，且不新增 reason。
    - **``revoked`` 属存储层语义（主控 2026-09-26 仲裁 / A4）**：撤销由
      ``GrantStore.revoke`` 写 ``revoked_at``、并在 ``load_current`` /
      ``load_for_session`` 返回 ``None`` 体现，因此判权看到的是 ``no_grant`` ——
      「已撤销的 grant」不可能作为非 ``None`` 的 :class:`Grant` 递到本函数。
      因此 ``revoked`` **不在** :data:`REASONS` / :data:`DENY_ORDER` 里：它不是一个
      可达的判权结论，把它留在枚举里会让「撤销状态没读到」看起来像一种正常的拒绝理由。
      审计需要区分「已撤销」与「从未签发」时，查 ``grant_record.revoked_at``。
    - **无 grant 的 FAMILY 例外跳过整段 grant 检查**：没有 grant 就没有会话绑定、
      动作集合与同意版本可比，因此 ``wrong_*`` / ``action_not_granted`` /
      ``resource_not_granted`` / ``stale_consent`` 都只对「有 grant」的调用生效。
      例外本身只覆盖 :data:`NO_GRANT_EXEMPT_ACTIONS`（A5），且只豁免 ``no_grant``
      这一项检查。
    - ``access`` / ``grant`` 的类型不可用时（``None``、非 :class:`SessionAccess` /
      :class:`Grant`）一律 fail-closed 按 ``no_grant`` 拒绝，不抛异常。
    """

    # 1. clock_invalid —— 先于一切：时钟不可信时过期与撤销判定都不可信。
    now_at = _parse_utc(now)
    if now_at is None:
        return _deny("clock_invalid")

    # 类型兜底（fail-closed，不新增 reason）：判权输入不可用 = 没有可用授权。
    if not isinstance(access, SessionAccess):
        return _deny("no_grant")
    if grant is not None and not isinstance(grant, Grant):
        return _deny("no_grant")

    # 1.5 **前置模式校验**（M2.2 §4.1，A 的 N7 定的位置）：
    #     在**类型兜底之后**、grant 段之前，且**不读 grant**。
    #     非控制面访问形态下 `review_control_plane` 没有授权可言 —— 用既有的
    #     `action_not_granted`（「这个动作在这次访问形态下没有授权」），
    #     不新造 reason、不动 DENY_ORDER。
    if action == "review_control_plane" and not _is_control_plane(access):
        return _deny("action_not_granted")

    # A5'：把记录分成「不需要 grant」与「需要 grant」两组。
    # 空记录集没有可豁免的对象：无 grant 时一律 fail-closed（保持既有口径）。
    if not records:
        if grant is None:
            return _deny("no_grant")
        # 空记录集没有可豁免的对象；保持既有口径：grant 前置条件照常核对。
        needs_grant: tuple[MemoryRecord, ...] = ()
        apply_grant_checks = True
    else:
        # M2.2 §4.1：模式校验已过的 control-plane 复审**整段不需要 grant**（无条件）。
        # 不能把它塞进 `_is_grant_exempt`：那个判定要求 `scope ∈ M2_1_ALLOWED_SCOPES`
        # 且受众命中，一条 PERSONAL 候选会因此变成「需要 grant」并在 grant=None 时
        # 先撞 `no_grant` —— 而不是 D11 硬边界 2 要求的 `scope_not_enabled`。
        needs_grant = tuple(
            record
            for record in records
            if not (
                action == "review_control_plane"
                or _is_grant_exempt(record=record, action=action, audience_id=audience_id)
            )
        )
        # 2. no_grant —— 只有**需要** grant 的记录才会触发这一条（A5'）。
        if grant is None and needs_grant:
            return _deny("no_grant")
        # A5' 的关键一步：**全部**记录都豁免时，整段 grant 检查都不执行。
        # 这正是「一个私人 grant 不能把全家的共享记忆关掉」的落地。
        apply_grant_checks = bool(needs_grant)

    if grant is not None and apply_grant_checks:
        # 3. revoked —— **存储层语义，本函数无分支**：撤销的 grant 由
        #    GrantStore 的 load_* 过滤成 None，到这里就是上面的 no_grant。
        # 4. expired —— 边界取 >=（fail-closed）；expires_at 不可解析同样拒绝。
        expires_at = _parse_utc(grant.expires_at)
        if expires_at is None or now_at >= expires_at:
            return _deny("expired")
        # 4b. not_yet_valid（B-s1）—— grant 时间窗的**左端**：还没生效的授权不算授权。
        #     ``issued_at`` 不可解析同样拒绝（无法证明它已生效）。
        issued_at = _parse_utc(grant.issued_at)
        if issued_at is None or now_at < issued_at:
            return _deny("not_yet_valid")
        # 5. wrong_session —— grant 的会话绑定必须是显式比较。
        if grant.session_id != session_id:
            return _deny("wrong_session")
        # 6. wrong_owner —— 拿错 grant 与用别人的 grant 冒充的拦截点。
        if grant.owner_id != access.session_owner:
            return _deny("wrong_owner")
        # 7. wrong_audience
        if audience_id != grant.audience_id:
            return _deny("wrong_audience")
        # 8. action_not_granted
        if action not in grant.actions:
            return _deny("action_not_granted")

    # 9. resource_not_granted —— grant 必须逐条覆盖**需要 grant 的**那些记录。
    #    A5'：FAMILY 且受众命中的记录不在此列（私人 grant 不该关掉家庭共享记忆）。
    if grant is not None:
        for record in needs_grant:
            if record.id not in grant.resource_ids:
                return _deny("resource_not_granted")

    # 10. missing_provenance —— 缺源或成环，绝不「只授权可见的那部分」。
    if _has_missing_or_cyclic_provenance(records):
        return _deny("missing_provenance")

    # 11. scope_not_enabled —— M2.1 相位限制（管 scope，不管 memory_class）。
    for record in records:
        if record.scope not in M2_1_ALLOWED_SCOPES:
            return _deny("scope_not_enabled")

    # 12. scope_denied —— 受众不匹配（M2.1 只有 FAMILY 分支可达）。
    for record in records:
        if _scope_denied(record=record, access=access, audience_id=audience_id):
            return _deny("scope_denied")

    # 13. policy_denied —— 契约违规 / 数据损坏，先于 status_denied。
    for record in records:
        if _policy_denied(record=record, action=action):
            return _deny("policy_denied")

    # 14. status_denied —— 只有 ACTIVE 可召回。
    #     **M2.2 §4.1：`review_control_plane` 是唯一跳过本条的动作** —— 候选正是
    #     `PENDING_CONFIRMATION`，这就是该动作存在的理由。其余记录级检查
    #     （missing_provenance / scope_not_enabled / scope_denied / policy_denied /
    #     record_expired）**一律照常执行**，绝不写成 early-return。
    if action != "review_control_plane":
        for record in records:
            if record.status != "ACTIVE":
                return _deny("status_denied")

    # 15. record_expired（B2）—— 记录自身的到期。
    #     **记录级检查：A5' 豁免的记录同样执行**（家庭共享读取可以不带 grant，
    #     但过了期的共享记忆不该被读出来）。``status`` 是主门、到期是补充门，
    #     因此它排在 status_denied 之后（位置理由见 DENY_ORDER 上方的注释）。
    for record in records:
        if _record_expired(record, now_at):
            return _deny("record_expired")

    # 16. stale_consent —— 只对需要 grant 的记录比对同意版本；
    #     无 grant 的家庭共享读取（含 A5' 豁免的记录）没有同意绑定，跳过。
    if grant is not None:
        consents = dict(grant.consent_versions)
        for record in needs_grant:
            if consents.get(record.id) != record.consent_version:
                return _deny("stale_consent")

    return ALLOWED


def require(
    *,
    action: Action,
    access: SessionAccess,
    grant: Grant | None,
    session_id: str,
    audience_id: str,
    records: tuple[MemoryRecord, ...],
    now: str | None,
) -> AuthorizationDecision:
    """``authorize()`` 的写入版：拒绝时抛 :class:`AuthorizationError`。

    存在的理由：写路径不能「忘记检查返回值」。参数与 :func:`authorize` 完全一致。
    放行时返回 ``AuthorizationDecision``，拒绝时抛错（异常携带同一个 decision，
    便于上层记录固定枚举原因）。

    **相位（A7）：M2.1 的写路径不使用本函数。** M2.1 的写门禁是
    「相位门 + actor 门 + 迁移表」三重检查（契约页 §3.7），由 ``MemoryService``
    直接执行 —— 那个组合比单次 ``authorize()`` 调用更严格，也更容易逐条验收。
    本函数保留为 **M2.2 起**写路径的统一入口：签名现在冻结，M2.1 不调用。
    """

    decision = authorize(
        action=action,
        access=access,
        grant=grant,
        session_id=session_id,
        audience_id=audience_id,
        records=records,
        now=now,
    )
    if not decision.allowed:
        # 延迟导入：``service`` 在模块层导入本模块，模块层反向导入会成环。
        # ``AuthorizationError`` 的形状冻结在 ``service.py``（W3 的文件），
        # 不由本模块另造一个异常类型。
        from soul_memory_kernel.memory.service import AuthorizationError

        raise AuthorizationError(decision)
    return decision
