"""JSONL 事件日志(规格 §9)。

- 每行一个事件,公共字段 ts(ISO8601)/ session_id / event / payload。
- 事件集与延迟埋点定义见规格 §9.1/§9.3;append-only,原始音频不落盘(§9.2)。
- 一条 session 一个文件,写入 data/logs/(或 LOG_DIR);目录必须进 .gitignore。
"""

import json
import math
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


def now_iso() -> str:
    """ISO8601 事件时间戳(UTC,毫秒精度)。"""

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


_DROP = object()
_SESSION_STATES = frozenset({"listening", "thinking", "speaking"})
_EVENT_CODES = frozenset(
    {"50", "51", "52", "150", "151", "152", "154", "350", "351", "359", "450", "451", "459"}
)
_PHASES = _SESSION_STATES | frozenset({"audio-device", "connect", "pipeline"})
_EVENT_NAMES = frozenset(
    {
        "session_started",
        "session_ended",
        "user_speech_started",
        "user_transcript",
        "agent_transcript",
        "provider_audio_first_event",
        "agent_audio_discarded",
        "user_turn_completed",
        "agent_tts_sentence_completed",
        "agent_turn_started",
        "agent_turn_completed",
        "agent_output_stopped",
        "agent_output_queue_drained",
        "usage",
        "error",
        "interruption_requested",
        "provider_interrupt_call",
        "interruption_queue_processing",
        "native_output_stop_ack",
        # M2.2 契约 §8.2.1 的交接表:5 个新事件名。**注册表必须先于生产者落地** ——
        # 未登记的事件名会被 ``_safe_event_name`` 换成 ``unknown_event``,未登记的
        # payload 键会被 ``_sanitize_payload`` 静默丢弃,生产者的计数会凭空消失。
        "memory_proposal_failed",
        "memory_proposal_declined",
        "extraction_failed",
        "extraction_unavailable",
        "extraction_budget_exhausted",
        # M2.3 §7.5 第 3 项（W7b 的 ``propose`` 失败没有计数）：提取路径的**写库失败**。
        # 与上面 5 个同理，**注册表先于生产者落地** —— 名字没登记就会被 ``_safe_event_name``
        # 换成 ``unknown_event``，「模型提了但没落库」在 live 批次里会再次变得不可观测。
        "extraction_propose_failed",
        # M2.2 契约 §6 T28（M5 前落地）：启动读路径记忆库故障（损坏 / 被锁 / I/O 故障）
        # 时降级为「本会话无记忆」，并记一条闭集事件；旧 schema 需迁移仍维持 fail-loud。
        "memory_unavailable",
    }
)

#: M2.2 契约 §2.5 的固定枚举 ``proposal_failure_reason``:会话内提议失败的**全部**
#: 合法取值。说给家人的话术不区分原因(§2.5 硬约束 1),原因只出现在计数里。
PROPOSAL_FAILURE_REASONS = frozenset({"scope_not_enabled", "validation_error", "store_error"})

#: M2.2 契约 §3.3 T17 的固定枚举 ``extraction_failure_reason``:提取调用失败的分类。
EXTRACTION_FAILURE_REASONS = frozenset({"timeout", "network_error", "http_error", "schema_invalid"})

#: M2.2 契约 §3.8 T25 / §3.9 T27:``extraction_unavailable`` 的 ``reason``。
#: **门 0 命中(开关关闭)不在这里** —— 那是配置事实,由启动横幅与
#: ``session_started.memory_enabled`` 表达,不是故障。
#:
#: M2.3 §7.5 第 9 项(收口 W7a 裁决 (a) 的已知缺口)起,「端点未配置」不再借
#: ``credentials_missing`` 表达:base URL 缺失 / 空白 / 非 https / 带 userinfo 走
#: ``endpoint_missing``,``credentials_missing`` **只**留给凭据缺失(外部 adapter 分流)。
#: 两个取值**都仍是闭集成员**,闭集之外仍是一律丢弃(自由文本没有入口)。
EXTRACTION_UNAVAILABLE_REASONS = frozenset(
    {"credentials_missing", "endpoint_missing", "budget_store_error"}
)

#: M2.3 契约 §7.5 第 3 项(W7b 的 ``propose`` 失败没有计数):``extraction_propose_failed``
#: 的 ``reason`` —— 「模型提了但没落库」的**失败分类**。
#:
#: 三个取值对应 ``MemoryService.propose()`` 抛出的三类 ``MemoryServiceError``:
#: ``MemoryValidationError``(候选/入参形状非法)/ ``AuthorizationError``(写路径被拒)/
#: 其余(``StoreError`` 等存储层故障)。刻意**不**复用 ``PROPOSAL_FAILURE_REASONS``:
#: 那张表描述的是 W6 会话内提议的失败面(含 ``scope_not_enabled``),语义不同。
#: **候选正文、记录 id、异常消息都不在这里** —— 这个事件的 payload 只有一个词。
EXTRACTION_PROPOSE_FAILURE_REASONS = frozenset(
    {"validation_error", "authorization_denied", "store_error"}
)

#: M2.2 契约 §3.9 T27:``extraction_budget_exhausted`` 的 ``level``(两级预算)。
EXTRACTION_BUDGET_LEVELS = frozenset({"session", "day"})

#: M2.2 契约 §6 T28(M5 前落地):``memory_unavailable`` 的 ``reason`` ——
#: 启动读路径遇记忆库损坏 / 被锁 / I/O 故障时降级为「本会话无记忆」的闭集原因。
#: 旧版 schema 需要迁移仍维持 fail-loud(退出码 2),不走本事件。
MEMORY_UNAVAILABLE_REASONS = frozenset({"store_error"})

#: ``count`` 取值规则的上界。与 ``_clean_value`` 的 ``count`` 分支**共用同一个常量**:
#: 类型化 helper 接受的输入必须保证能通过 JSONL 层的同一道检查,否则 helper 就是
#: 「假 fail-loud」—— 它放行了一个会被静默丢弃的值。
_COUNT_MAXIMUM = 1_000_000_000

#: T17:最多重试 1 次 ⇒ ``attempts`` 只可能是 1(首次)或 2(重试后)。
_EXTRACTION_ATTEMPTS = frozenset({1, 2})

# Each entry maps an accepted call-site key to its stored key and a narrowly
# defined value rule. Free text is represented only by a presence bit. Fields
# from provider dictionaries, exception messages, raw events, and nested maps
# are intentionally absent from these schemas.
_EVENT_PAYLOAD_RULES: dict[str, dict[str, tuple[str, str]]] = {
    "session_started": {
        "provider": ("provider", "provider"),
        "route": ("route", "route"),
        "model_parameter_sent": ("model_parameter_sent", "bool"),
        "voice_parameter_sent": ("voice_parameter_sent", "bool"),
        "identity_scope": ("identity_scope", "identity_scope"),
        "identity_assurance": ("identity_assurance", "identity_assurance"),
        "session_mode": ("session_mode", "session_mode"),
        # M2.1 落点 2(契约 §5):记忆只以**计数**进事件日志。正文、记录 id、
        # 拒绝原因列表都不在这里 —— 它们不在白名单内,调用方写了也会被丢弃。
        "memory_record_count": ("memory_record_count", "count"),
        "memory_projected_count": ("memory_projected_count", "count"),
        "memory_truncated_count": ("memory_truncated_count", "count"),
        # M2.2 §8.2.1 交接表:D15 的记忆总开关事实 + D14 的接缝剔除计数。
        # **W10 只登记规则,不负责发射**(发射归 W6)。键名与契约逐字一致 ——
        # ``seam_filtered_count`` 刻意**不带** ``memory_`` 前缀。
        "memory_enabled": ("memory_enabled", "bool"),
        "seam_filtered_count": ("seam_filtered_count", "count"),
        # M2.3 T31: N4 reports only opt-in facts, never the selected owner id.
        "extraction_enabled": ("extraction_enabled", "bool"),
        "extraction_owner_declared": ("extraction_owner_declared", "bool"),
    },
    "session_ended": {
        "duration_s": ("duration_s", "seconds"),
        "reason": ("reason", "end_reason"),
        "interruptions": ("interruptions", "count"),
    },
    "user_speech_started": {
        "offset_ms": ("offset_ms", "milliseconds"),
        "was_speaking": ("was_speaking", "bool"),
        "state": ("state", "state"),
    },
    "user_transcript": {
        "text": ("text_present", "presence"),
        "is_final": ("is_final", "bool"),
        "source_event": ("source_event", "event_code"),
        "finalized_by_event": ("finalized_by_event", "event_code"),
    },
    "agent_transcript": {
        "text": ("text_present", "presence"),
        "is_final": ("is_final", "bool"),
    },
    "provider_audio_first_event": {"bytes": ("bytes", "byte_count")},
    "agent_audio_discarded": {"bytes": ("bytes", "byte_count")},
    "user_turn_completed": {"source_event": ("source_event", "event_code")},
    "agent_tts_sentence_completed": {"source_event": ("source_event", "event_code")},
    "agent_turn_started": {"source_event": ("source_event", "event_code")},
    "agent_turn_completed": {"source_event": ("source_event", "event_code")},
    "agent_output_stopped": {
        "source": ("source", "output_source"),
        "physical_silence_observed": ("physical_silence_observed", "bool"),
    },
    "agent_output_queue_drained": {
        "source": ("source", "output_source"),
        "physical_silence_observed": ("physical_silence_observed", "bool"),
    },
    "usage": {
        "amount": ("amount", "usage_number"),
        "input_tokens": ("input_tokens", "usage_count"),
        "output_tokens": ("output_tokens", "usage_count"),
        "total_tokens": ("total_tokens", "usage_count"),
        "input_token_count": ("input_token_count", "usage_count"),
        "output_token_count": ("output_token_count", "usage_count"),
    },
    "error": {
        "phase": ("phase", "phase"),
        "fatal": ("fatal", "bool"),
        "message": ("message_present", "presence"),
    },
    "interruption_requested": {
        "trigger": ("trigger", "interrupt_trigger"),
        "from_state": ("from_state", "state"),
    },
    "provider_interrupt_call": {
        "call_returned": ("call_returned", "nullable_bool"),
        "elapsed_ms": ("elapsed_ms", "milliseconds"),
        "error": ("error_present", "presence"),
    },
    "interruption_queue_processing": {
        "processed": ("processed", "nullable_bool"),
        "elapsed_ms": ("elapsed_ms", "milliseconds"),
        "error": ("error_present", "presence"),
    },
    "native_output_stop_ack": {
        "acknowledged": ("acknowledged", "nullable_bool"),
        "elapsed_ms": ("elapsed_ms", "milliseconds"),
        "physical_silence_observed": ("physical_silence_observed", "bool"),
        "error": ("error_present", "presence"),
    },
    # ---- M2.2 §8.2.1 交接表:5 个新事件(生产者 W6 / W7b) ----
    # 全部**只**接受固定枚举与计数:对家人的失败语义是 fail-quiet(§2.5 / T17),
    # 对日志是 fail-loud,而「loud」的内容也只是闭集里的一个词加一个数。
    "memory_proposal_failed": {
        "reason": ("reason", "proposal_failure_reason"),
    },
    "memory_proposal_declined": {
        "declined_count": ("declined_count", "count"),
    },
    "extraction_failed": {
        "reason": ("reason", "extraction_failure_reason"),
        "attempts": ("attempts", "count"),
    },
    "extraction_unavailable": {
        "reason": ("reason", "extraction_unavailable_reason"),
    },
    "extraction_budget_exhausted": {
        "level": ("level", "extraction_budget_level"),
    },
    # ---- M2.3 §7.5 第 3 项:提取路径的写库失败(W7b 生产者) ----
    # 与 ``memory_proposal_failed`` 同形:只接受固定枚举,一个计数一个词。
    # 候选正文、``MemoryCandidate`` 的任何字段、异常消息都**不在**这张表里 ——
    # 调用方就算写了 ``content=...`` 也会被 ``_sanitize_payload`` 静默丢弃。
    "extraction_propose_failed": {
        "reason": ("reason", "extraction_propose_failure_reason"),
    },
    # ---- M2.2 §6 T28:启动读路径记忆库不可用,本会话有观测降级(console 生产者) ----
    # 只接受固定枚举,不含异常消息、库路径或任何记录信息。
    "memory_unavailable": {
        "reason": ("reason", "memory_unavailable_reason"),
    },
}


def _safe_event_name(event: object) -> str:
    """Return a fixed event name without stringifying untrusted input."""

    if type(event) is str and len(event) <= 64 and event in _EVENT_NAMES:
        return event
    return "unknown_event"


def _safe_event_code(value: object) -> object:
    if type(value) is int and str(value) in _EVENT_CODES:
        return value
    if type(value) is str and len(value) <= 5 and value.isascii() and value.isdigit():
        if value in _EVENT_CODES:
            return value
    return _DROP


def _bounded_number(value: object, maximum: int | float) -> object:
    if type(value) is int:
        return value if 0 <= value <= maximum else _DROP
    if type(value) is float and math.isfinite(value):
        return value if 0 <= value <= maximum else _DROP
    return _DROP


def _clean_value(rule: str, value: object) -> object:
    if rule == "presence":
        if value is None:
            return False
        return value != "" if type(value) is str else True
    if rule == "bool":
        return value if type(value) is bool else _DROP
    if rule == "nullable_bool":
        return value if value is None or type(value) is bool else _DROP
    if rule == "event_code":
        return _safe_event_code(value)
    if rule == "milliseconds":
        return _bounded_number(value, 604_800_000)
    if rule == "seconds":
        return _bounded_number(value, 604_800)
    if rule == "count":
        return _bounded_number(value, _COUNT_MAXIMUM)
    if rule == "byte_count":
        return _bounded_number(value, 67_108_864)
    if rule == "usage_count":
        if type(value) is int:
            return value if 0 <= value <= 1_000_000_000_000 else _DROP
        return _DROP
    if rule == "usage_number":
        return _bounded_number(value, 1_000_000_000_000)
    if rule == "provider":
        return (
            value
            if type(value) is str
            and 1 <= len(value) <= 32
            and value.isascii()
            and value[0].isalnum()
            and all(ch.isalnum() or ch in "_-" for ch in value)
            else _DROP
        )
    if rule == "route":
        return value if type(value) is str and value in {"A", "B", "C"} else _DROP
    if rule == "identity_scope":
        return (
            value
            if type(value) is str and value in {"unknown", "manually_selected_unverified"}
            else _DROP
        )
    if rule == "identity_assurance":
        return (
            value
            if type(value) is str and value in {"unknown", "manually_selected_unverified"}
            else _DROP
        )
    if rule == "session_mode":
        return value if type(value) is str and value in {"shared", "controlled_private"} else _DROP
    if rule == "state":
        return value if type(value) is str and value in _SESSION_STATES else _DROP
    if rule == "phase":
        return value if type(value) is str and value in _PHASES else _DROP
    if rule == "end_reason":
        return value if type(value) is str and value in {"manual", "remote", "error"} else _DROP
    if rule == "output_source":
        return (
            value
            if type(value) is str
            and value in {"local_output_transport", "output_transport", "unknown"}
            else _DROP
        )
    if rule == "interrupt_trigger":
        return value if type(value) is str and value in {"user_speech_started", "user_transcript"} else _DROP
    # ---- M2.2 §8.2.1:固定枚举是**闭集**,枚举外的取值一律丢弃(fail-closed)。
    # 不做大小写折叠、不做去空白、不做前缀匹配:注册表只接受闭集里的**原样**取值,
    # 绝不把调用方给的原文透传进 JSONL。
    if rule == "proposal_failure_reason":
        return value if type(value) is str and value in PROPOSAL_FAILURE_REASONS else _DROP
    if rule == "extraction_failure_reason":
        return value if type(value) is str and value in EXTRACTION_FAILURE_REASONS else _DROP
    if rule == "extraction_unavailable_reason":
        return value if type(value) is str and value in EXTRACTION_UNAVAILABLE_REASONS else _DROP
    if rule == "extraction_budget_level":
        return value if type(value) is str and value in EXTRACTION_BUDGET_LEVELS else _DROP
    if rule == "extraction_propose_failure_reason":
        return (
            value
            if type(value) is str and value in EXTRACTION_PROPOSE_FAILURE_REASONS
            else _DROP
        )
    if rule == "memory_unavailable_reason":
        return value if type(value) is str and value in MEMORY_UNAVAILABLE_REASONS else _DROP
    return _DROP


def _sanitize_payload(event: str, payload: dict) -> dict:
    """Select only typed, event-specific metadata before JSON serialization."""

    rules = _EVENT_PAYLOAD_RULES.get(event, {})
    sanitized: dict[str, object] = {}
    for key, value in payload.items():
        # Do not stringify, normalize, or hash caller-controlled keys. Exact str
        # keys and explicit schema entries are the only inputs we inspect.
        if type(key) is not str or len(key) > 64:
            continue
        field_rule = rules.get(key)
        if field_rule is None:
            continue
        stored_key, value_rule = field_rule
        cleaned = _clean_value(value_rule, value)
        if cleaned is not _DROP:
            sanitized[stored_key] = cleaned
    return sanitized


@dataclass
class EventRecord:
    ts: str
    session_id: str
    event: str
    payload: dict

    def to_dict(self) -> dict:
        return {"ts": self.ts, "session_id": self.session_id, "event": self.event, "payload": self.payload}


class JsonlEventLog:
    """Append-only JSONL writer with an event-specific metadata privacy boundary."""

    def __init__(self, log_dir: Path, session_id: str):
        self.session_id = session_id
        log_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.path = log_dir / f"{stamp}-{session_id}.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")

    def append(self, event: str, **payload) -> EventRecord:
        safe_event = _safe_event_name(event)
        safe_payload = _sanitize_payload(safe_event, payload)
        record = EventRecord(
            ts=now_iso(),
            session_id=self.session_id,
            event=safe_event,
            payload=safe_payload,
        )
        self._fh.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
        self._fh.flush()
        return record

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "JsonlEventLog":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


# ---------------------------------------------------------------------------
# M2.2 登记项的类型化 helper(契约 §8.2.1:「取值枚举的类型化 helper」)
#
# 生产者(W6 的提议路径、W7b 的提取编排)**只应该**通过这些函数写 M2.2 的计数,
# 而不是自己拼 ``log.append("extraction_failed", ...)``:事件名与字段名写错在
# JSONL 层是**静默**丢弃,只有 helper 能在开发期把它变成一声响。
#
# 两层防线各司其职,两层都必须保留:
#   - helper(这一层,``ValueError``):**fail-loud**。枚举外的取值、非 int 的计数
#     在调用点就抛错,不写任何日志。这是给程序员看的。
#   - ``_clean_value`` / ``_sanitize_payload``(那一层,``_DROP``):**fail-closed**。
#     任何来源(包括绕过 helper 的直接 ``append``)的脏值一律不进 JSONL。
#     这是给运行时兜底的 —— 少了它,一条绕过 helper 的路径就能把原文写进日志。
# ---------------------------------------------------------------------------


class EventLogLike(Protocol):
    """helper 需要的最小日志形状:一个 ``append(event, **payload)``。

    真实的 :class:`JsonlEventLog` 满足它;测试替身也满足它,不必继承。
    """

    def append(self, event: str, **payload: object) -> EventRecord: ...


def _require_enum(field: str, allowed: frozenset[str], value: object) -> str:
    """闭集校验:**枚举外的取值抛 ``ValueError``**,绝不透传原文。

    失败发生在 ``log.append`` **之前**,所以脏值没有任何机会进 JSONL;异常消息是
    给开发期看的,不是日志内容。
    """

    if type(value) is str and value in allowed:
        return value
    raise ValueError(f"{field} must be one of {sorted(allowed)}; got {value!r}")


def _require_count(field: str, value: object) -> int:
    """计数校验:只接受 ``int``(``bool`` 不算),范围与 ``count`` 取值规则一致。"""

    if type(value) is int and 0 <= value <= _COUNT_MAXIMUM:
        return value
    raise ValueError(f"{field} must be an int in [0, {_COUNT_MAXIMUM}]; got {value!r}")


def _require_attempts(value: object) -> int:
    """T17:最多重试 1 次 ⇒ ``attempts`` 只可能是 1 或 2(``bool`` 不算)。"""

    if type(value) is int and value in _EXTRACTION_ATTEMPTS:
        return value
    raise ValueError(f"attempts must be one of {sorted(_EXTRACTION_ATTEMPTS)}; got {value!r}")


def log_proposal_failed(log: EventLogLike, *, reason: str) -> EventRecord:
    """``memory_proposal_failed``(契约 §2.5):提议失败,只记固定枚举 ``reason``。

    对家人 fail-quiet、对日志 fail-loud;说给家人的话术**不**区分原因(§2.5 硬约束 1)。
    """

    return log.append(
        "memory_proposal_failed",
        reason=_require_enum("proposal_failure_reason", PROPOSAL_FAILURE_REASONS, reason),
    )


def log_proposal_declined(log: EventLogLike, *, declined_count: int) -> EventRecord:
    """``memory_proposal_declined``(契约 §2.5):说话人明确要求不记,记一个计数。"""

    return log.append(
        "memory_proposal_declined",
        declined_count=_require_count("declined_count", declined_count),
    )


def log_extraction_failed(log: EventLogLike, *, reason: str, attempts: int) -> EventRecord:
    """``extraction_failed``(契约 §3.3 T17):失败分类 + 已发生的出境次数。

    ``attempts=2`` 意味着 **2 次出境、2 次预算扣减**(T17):重试不是免费的。
    """

    return log.append(
        "extraction_failed",
        reason=_require_enum("extraction_failure_reason", EXTRACTION_FAILURE_REASONS, reason),
        attempts=_require_attempts(attempts),
    )


def log_extraction_unavailable(log: EventLogLike, *, reason: str) -> EventRecord:
    """``extraction_unavailable``(契约 §3.8 T25 / §3.9 T27):提取不可用,没有出境。

    门 0(开关关闭)命中时**不记**这个计数 —— 那是配置事实,不是故障。
    """

    return log.append(
        "extraction_unavailable",
        reason=_require_enum(
            "extraction_unavailable_reason", EXTRACTION_UNAVAILABLE_REASONS, reason
        ),
    )


def log_extraction_budget_exhausted(log: EventLogLike, *, level: str) -> EventRecord:
    """``extraction_budget_exhausted``(契约 §3.9 T27):两级预算的哪一级到顶了。"""

    return log.append(
        "extraction_budget_exhausted",
        level=_require_enum("extraction_budget_level", EXTRACTION_BUDGET_LEVELS, level),
    )


def log_extraction_propose_failed(log: EventLogLike, *, reason: str) -> EventRecord:
    """``extraction_propose_failed``(契约 §7.5 第 3 项):**模型提了,但没落库**。

    与 ``extraction_failed`` 的分工是刻意的:后者数的是「调用失败」(已经出境的失败),
    这个数的是「调用成功、schema 也过了、``propose()`` 却没写成」—— 前者在 live 批次里
    可见,后者在 M2.3 之前**不可见**。它**不含**候选正文、不含记录 id、不含异常消息:
    payload 里只有一个闭集取值。
    """

    return log.append(
        "extraction_propose_failed",
        reason=_require_enum(
            "extraction_propose_failure_reason", EXTRACTION_PROPOSE_FAILURE_REASONS, reason
        ),
    )


def log_memory_unavailable(log: EventLogLike, *, reason: str) -> EventRecord:
    """``memory_unavailable``(契约 §6 T28):启动读路径记忆库故障,本会话降级为无记忆。

    旧 schema 需要迁移仍维持 fail-loud(退出码 2),不调用本函数;库损坏 / 被锁 / I/O
    故障时会话继续、instructions 走已验证的无记忆路径,并记这一条闭集事件。
    """

    return log.append(
        "memory_unavailable",
        reason=_require_enum("memory_unavailable_reason", MEMORY_UNAVAILABLE_REASONS, reason),
    )


def load_events(path: Path) -> Iterator[dict]:
    """逐行读取 JSONL;损坏行跳过不抛(T2:日志损坏不致丢整场)。"""

    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _delta_ms(start: str, end: str) -> float:
    fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
    try:
        a = datetime.strptime(start, fmt)
        b = datetime.strptime(end, fmt)
    except (ValueError, TypeError):
        return float("nan")
    return (b - a).total_seconds() * 1000.0


def provider_audio_event_arrival_latencies_ms(path: Path) -> list[float]:
    """Pair a completed user turn/final transcript with the first provider audio event.

    This is event arrival at the app consumer, before the local output transport
    writes audio. Route C uses event 459 as the turn boundary; event 351 is an
    assistant TTS sentence marker. Legacy logs that misclassified 351 as a user
    transcript remain excluded from this measurement.
    """

    latencies: list[float] = []
    start_ts: str | None = None
    start_is_turn_boundary = False
    for item in load_events(path):
        name = item.get("event")
        payload = item.get("payload", {})
        if name == "user_turn_completed":
            start_ts = item.get("ts")
            start_is_turn_boundary = True
        elif name == "user_transcript" and payload.get("is_final", False):
            # Synthetic Route C finals are flushed after 459; the control event
            # is the authoritative start. Ignore the duplicate timestamp here.
            if payload.get("finalized_by_event") in (459, "459"):
                continue
            # Keep old logs from treating the misclassified 351 as user ASR.
            if payload.get("source_event") in (351, "351"):
                continue
            if not start_is_turn_boundary:
                start_ts = item.get("ts")
        elif name == "provider_audio_first_event" and start_ts is not None:
            latencies.append(_delta_ms(start_ts, item.get("ts")))
            start_ts = None
            start_is_turn_boundary = False
    return latencies


def first_response_latencies_ms(path: Path) -> list[float]:
    """Compatibility alias; samples are provider audio event arrival, not playback."""

    return provider_audio_event_arrival_latencies_ms(path)


def interruption_queue_processing_latencies_ms(path: Path) -> list[float]:
    """Successful software queue handling: user_speech_started to processed=true.

    This is not a physical speaker-silence measurement. Failed or timed-out queue
    handling attempts are intentionally excluded from this latency sample.
    """

    latencies: list[float] = []
    start_ts: str | None = None
    for item in load_events(path):
        name = item.get("event")
        if name == "user_speech_started":
            start_ts = item.get("ts")
        elif name == "interruption_queue_processing" and start_ts is not None:
            if item.get("payload", {}).get("processed") is True:
                latencies.append(_delta_ms(start_ts, item.get("ts")))
            start_ts = None
    return latencies


def interruption_latencies_ms(path: Path) -> list[float]:
    """Compatibility alias for successful local software queue processing latency."""

    return interruption_queue_processing_latencies_ms(path)


def session_summary(path: Path) -> dict:
    """§6.5 记录清单中可自动计算的汇总(时长/打断次数/错误数/延迟采样)。"""

    events = list(load_events(path))

    def count(name: str) -> int:
        return sum(1 for e in events if e.get("event") == name)

    started = next((e for e in events if e.get("event") == "session_started"), None)
    ended = next((e for e in events if e.get("event") == "session_ended"), None)
    duration_s = None
    if started and ended:
        duration_s = _delta_ms(started["ts"], ended["ts"]) / 1000.0

    return {
        "path": str(path),
        "duration_s": duration_s,
        "interruptions": count("interruption_requested"),
        "interruption_queue_processed": sum(
            1
            for event in events
            if event.get("event") == "interruption_queue_processing"
            and event.get("payload", {}).get("processed") is True
        ),
        "output_stops_observed": count("agent_output_stopped"),
        "errors": count("error"),
        "provider_audio_event_arrival_ms": provider_audio_event_arrival_latencies_ms(path),
        "interruption_queue_processing_ms": interruption_queue_processing_latencies_ms(path),
        "ended_reason": (ended or {}).get("payload", {}).get("reason"),
    }
