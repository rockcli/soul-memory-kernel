"""W10 专项：M2.2 日志计数注册表（契约 §8.2.1 交接表 / §10.2 ⑰）。

本片先落地注册表，W6（会话内提议）与 W7b（提取编排）才有地方写计数 ——
``obs/events.py`` 对**未登记**的事件名落 ``unknown_event``、对**未登记**的 payload
键直接丢弃，所以「注册表必须先落地」不是顺序偏好，是那两片的计数能不能存在的前提。

四块覆盖：

1. **注册表逐行断言**：§8.2.1 交接表的 7 个登记项（5 个新事件名 + 2 个
   ``session_started`` 新字段）的事件名 / 字段名 / 取值规则都在注册表里，
   且键名与契约逐字一致；
2. **防线自证**：未登记事件名落 ``unknown_event``、未登记 payload 键被丢弃 ——
   证明「注册表必须先落地」这条前提本身是真的，而不是一句注解；
3. **固定枚举是闭集**：枚举内全部接受；枚举外（大小写 / 空白 / 拼接变体、
   别的枚举里的合法值、``str`` 子类、非字符串）一律丢弃，绝不透传原文；
4. **类型化 helper**：合法调用产出预期 payload；枚举外 / 非 ``int`` 抛
   ``ValueError`` 且**在写之前**抛出（脏值没有机会进 JSONL）；helper 放行的输入
   必须能通过 JSONL 层（两层同口径，否则 helper 是「假 fail-loud」）。

全程离线：只写 ``tmp_path`` 下的 JSONL，没有网络（仓库级 ``tests/conftest.py`` 守门）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from soul_memory_kernel.obs.events import (
    EXTRACTION_BUDGET_LEVELS,
    EXTRACTION_FAILURE_REASONS,
    EXTRACTION_PROPOSE_FAILURE_REASONS,
    EXTRACTION_UNAVAILABLE_REASONS,
    MEMORY_UNAVAILABLE_REASONS,
    PROPOSAL_FAILURE_REASONS,
    EventRecord,
    JsonlEventLog,
    _EVENT_NAMES,
    _EVENT_PAYLOAD_RULES,
    _sanitize_payload,
    load_events,
    log_extraction_budget_exhausted,
    log_extraction_failed,
    log_extraction_propose_failed,
    log_extraction_unavailable,
    log_memory_unavailable,
    log_proposal_declined,
    log_proposal_failed,
)

#: 合成样本（``data_class = synthetic_only``）：不是任何真实家庭的记忆内容或 id。
SECRET_CONTENT = "合成样本：某个孩子对某种坚果过敏"
SECRET_RECORD_ID = "mem-synthetic-0001"
SECRET_SESSION_ID = "sess-synthetic-0001"

#: 契约 §8.2.1 交接表的**全部**登记项 —— ``(事件名, 字段名, 取值规则)``。
#: 7 个计数登记项 = 5 个新事件名 + 2 个 ``session_started`` 新字段；
#: ``extraction_failed`` 有 ``reason`` / ``attempts`` 两个字段，所以表里是 8 行。
M2_2_REGISTRY_ROWS: tuple[tuple[str, str, str], ...] = (
    ("memory_proposal_failed", "reason", "proposal_failure_reason"),
    ("memory_proposal_declined", "declined_count", "count"),
    ("session_started", "memory_enabled", "bool"),
    ("session_started", "seam_filtered_count", "count"),
    ("extraction_failed", "reason", "extraction_failure_reason"),
    ("extraction_failed", "attempts", "count"),
    ("extraction_unavailable", "reason", "extraction_unavailable_reason"),
    ("extraction_budget_exhausted", "level", "extraction_budget_level"),
)

#: §8.2.1 新增的 5 个事件名（``session_started`` 是既有事件，不在此列）。
M2_2_EVENT_NAMES = frozenset(
    {
        "memory_proposal_failed",
        "memory_proposal_declined",
        "extraction_failed",
        "extraction_unavailable",
        "extraction_budget_exhausted",
    }
)

#: M2.3 §7.5 第 3 项新登记的第 6 个新事件名：提取路径的**写库失败**计数
#: （``propose`` 抛 ``MemoryServiceError`` ⇒「模型提了但没落库」）。
#: 与 M2_2 分开列：它是 M2.3 的加法，不是 W10 那一批的一部分。
M2_3_EVENT_NAMES = frozenset({"extraction_propose_failed"})

#: M2.3 登记项的**契约取值表**（§8.2.1 的 ``extraction_propose_failure_reason``）。
#:
#: **为什么单列一张表，而不是并进上面的 ``CONTRACT_ENUM_VALUES``**：那张表不只是
#: 「契约取值表」，它还承载 W10 的一条更强的不变量 —— **跨枚举取值互不接受**
#: （``test_a_value_from_another_enum_is_not_accepted`` 遍历它的**全部**取值，对每个枚举
#: 逐值断言「别的枚举里的合法值在这里照样被丢」）。而 ``extraction_propose_failure_reason``
#: 与 ``proposal_failure_reason`` **刻意共用** ``validation_error`` / ``store_error``
#: 两个词（同一个失败形态在两个事件里同名，便于对账，契约 §8.2.1 逐字如此）——
#: 并进去会让那条**既有**断言变红，而放开它属于「放宽既有断言」，本片没有这个授权。
#: 因此这里用**同构的参数化**把同样两条性质（逐值与契约对齐、枚举外一律丢弃）单独钉死，
#: 并把「共用的恰好是那两个词」显式记下来（多一个共用词就会变红）。
M2_3_CONTRACT_ENUM_VALUES: dict[str, tuple[str, ...]] = {
    "extraction_propose_failure_reason": (
        "validation_error",
        "authorization_denied",
        "store_error",
    ),
}

#: ``(事件名, 字段名, 取值规则, 模块里的闭集常量)`` —— 与 ``ENUM_RULES`` **同构**。
M2_3_ENUM_RULES = (
    (
        "extraction_propose_failed",
        "reason",
        "extraction_propose_failure_reason",
        EXTRACTION_PROPOSE_FAILURE_REASONS,
    ),
)

# M2.3 T31 N4: startup reports opt-in facts, never the chosen owner identifier.
N4_T31_REGISTRY_ROWS: tuple[tuple[str, str, str], ...] = (
    ("session_started", "extraction_enabled", "bool"),
    ("session_started", "extraction_owner_declared", "bool"),
)

#: 与 ``proposal_failure_reason`` **刻意共用**的两个词（见上面的说明）。
M2_3_SHARED_WORDS = frozenset({"validation_error", "store_error"})

#: M2.2 契约 §6 T28（M5 前落地）：启动读路径记忆库故障的有观测降级事件。
T28_EVENT_NAMES = frozenset({"memory_unavailable"})
T28_CONTRACT_ENUM_VALUES: dict[str, tuple[str, ...]] = {
    "memory_unavailable_reason": ("store_error",),
}
T28_ENUM_RULES = (
    (
        "memory_unavailable",
        "reason",
        "memory_unavailable_reason",
        MEMORY_UNAVAILABLE_REASONS,
    ),
)

#: W10 之前（M2.1）的 19 个事件名。注册表**只增不减**：这些名字一个都不许消失，
#: 否则既有生产者的输出会整条退化成 ``unknown_event``。
M2_1_EVENT_NAMES = frozenset(
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
    }
)

#: 契约里**逐字冻结**的枚举取值。刻意不引用模块常量：引用常量会让
#: 「常量本身被改坏」这条最该被抓的漂移悄悄通过。
#: ``extraction_unavailable_reason`` 的第三个取值 ``endpoint_missing`` 是 **M2.3**
#: 按 §7.5 第 9 项新登记进契约 §8.2.1 的（主控登记；本表与它逐字对齐）。
CONTRACT_ENUM_VALUES: dict[str, tuple[str, ...]] = {
    "proposal_failure_reason": ("scope_not_enabled", "validation_error", "store_error"),
    "extraction_failure_reason": ("timeout", "network_error", "http_error", "schema_invalid"),
    "extraction_unavailable_reason": (
        "credentials_missing",
        "endpoint_missing",
        "budget_store_error",
    ),
    "extraction_budget_level": ("session", "day"),
}

#: ``(事件名, 字段名, 取值规则, 模块里的闭集常量)`` —— 四个固定枚举逐个登记。
ENUM_RULES = (
    ("memory_proposal_failed", "reason", "proposal_failure_reason", PROPOSAL_FAILURE_REASONS),
    ("extraction_failed", "reason", "extraction_failure_reason", EXTRACTION_FAILURE_REASONS),
    (
        "extraction_unavailable",
        "reason",
        "extraction_unavailable_reason",
        EXTRACTION_UNAVAILABLE_REASONS,
    ),
    ("extraction_budget_exhausted", "level", "extraction_budget_level", EXTRACTION_BUDGET_LEVELS),
)


class _SmuggledEnum(str):
    """``str`` 子类：值相等也不算数 —— 注册表只接受**原样**的 ``str``。"""


class _RecordingLog:
    """``EventLogLike`` 的最小替身：记录调用、不写盘。

    它同时也证明 helper 只依赖 ``append(event, **payload)`` 这一个形状，
    没有偷偷依赖 ``JsonlEventLog`` 的实现细节。
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def append(self, event: str, **payload: object) -> EventRecord:
        self.calls.append((event, dict(payload)))
        return EventRecord(
            ts="2026-09-26T12:00:00.000+00:00",
            session_id="synthetic",
            event=event,
            payload=dict(payload),
        )


# ---------------------------------------------------------------------------
# 1. 注册表逐行断言（契约 §8.2.1）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("event", "field", "value_rule"), M2_2_REGISTRY_ROWS)
def test_every_registry_row_is_registered(event: str, field: str, value_rule: str) -> None:
    assert event in _EVENT_NAMES, f"{event} 必须进 _EVENT_NAMES（否则落 unknown_event）"
    rules = _EVENT_PAYLOAD_RULES.get(event)
    assert rules is not None, f"{event} 必须有自己的 payload 规则表"
    assert field in rules, f"{event}.{field} 必须进 _EVENT_PAYLOAD_RULES（否则被静默丢弃）"
    stored_key, registered_rule = rules[field]
    assert stored_key == field, "存储键名必须与契约逐字一致"
    assert registered_rule == value_rule


@pytest.mark.parametrize("event", sorted(M2_2_EVENT_NAMES))
def test_the_five_new_event_names_are_registered(event: str) -> None:
    assert event in _EVENT_NAMES


@pytest.mark.parametrize(
    ("event", "field", "value_rule"),
    [
        ("session_started", "memory_record_count", "count"),
        ("session_started", "memory_projected_count", "count"),
        ("session_started", "memory_truncated_count", "count"),
        ("session_started", "memory_enabled", "bool"),
        ("session_started", "seam_filtered_count", "count"),
        ("session_started", "extraction_enabled", "bool"),
        ("session_started", "extraction_owner_declared", "bool"),
    ],
)
def test_session_started_registers_the_m2_1_counts_plus_the_two_new_fields(
    event: str, field: str, value_rule: str
) -> None:
    """D14 / D15 的两个新字段是**加法**：M2.1 的三个计数一个不动。"""

    assert _EVENT_PAYLOAD_RULES[event][field] == (field, value_rule)


@pytest.mark.parametrize(("event", "field", "value_rule"), N4_T31_REGISTRY_ROWS)
def test_n4_t31_session_flags_are_registered_as_booleans(
    event: str, field: str, value_rule: str
) -> None:
    assert _EVENT_PAYLOAD_RULES[event][field] == (field, value_rule)


def test_the_event_registry_is_append_only() -> None:
    """注册表只增不减：M2.1 的 19 个事件名一个不丢，新增的恰好是 M2.2 (5) + M2.3 (1) + T28 (1)。"""

    assert M2_1_EVENT_NAMES <= _EVENT_NAMES, "既有事件名不许消失"
    assert M2_2_EVENT_NAMES <= _EVENT_NAMES
    assert M2_3_EVENT_NAMES <= _EVENT_NAMES
    assert T28_EVENT_NAMES <= _EVENT_NAMES
    assert _EVENT_NAMES - M2_1_EVENT_NAMES == (
        M2_2_EVENT_NAMES | M2_3_EVENT_NAMES | T28_EVENT_NAMES
    ), "新增的事件名恰好是 5 个（M2.2）+ 1 个（M2.3 §7.5 第 3 项）+ 1 个（T28 memory_unavailable）"


def test_every_registered_event_name_has_exactly_one_payload_rule_table() -> None:
    """登记事件名与规则表一一对应：没有「登记了却没规则」或「有规则却没登记」的名字。"""

    assert set(_EVENT_NAMES) == set(_EVENT_PAYLOAD_RULES)


def test_the_two_session_started_keys_are_verbatim() -> None:
    """键名逐字：``seam_filtered_count`` 契约里就**没有** ``memory_`` 前缀。"""

    assert _sanitize_payload("session_started", {"seam_filtered_count": 3}) == {
        "seam_filtered_count": 3
    }
    assert _sanitize_payload("session_started", {"memory_seam_filtered_count": 3}) == {}
    assert _sanitize_payload("session_started", {"seam_filtered": 3}) == {}


def test_n4_session_flags_are_strict_booleans_and_owner_ids_are_never_registered() -> None:
    assert _sanitize_payload(
        "session_started",
        {
            "extraction_enabled": True,
            "extraction_owner_declared": False,
            "extraction_owner": "adult-secret-id",
        },
    ) == {"extraction_enabled": True, "extraction_owner_declared": False}
    for invalid in (1, 0, "true", None):
        assert _sanitize_payload("session_started", {"extraction_enabled": invalid}) == {}


# ---------------------------------------------------------------------------
# 2. 防线自证：未登记 = 静默丢弃（这才是「注册表必须先落地」的理由）
# ---------------------------------------------------------------------------


def test_an_unregistered_event_name_falls_back_to_unknown_event(tmp_path: Path) -> None:
    """§8.2.1 的前提本身：未登记的事件名连 payload 一起消失。

    下面两个名字**看起来很像真的**，但它们没有登记 —— 这就是生产者先于注册表
    落地时会发生的事：计数不会报错，只会凭空不见。
    """

    plausible_but_unregistered = ("memory_proposal_recorded", "extraction_succeeded")
    assert not (set(plausible_but_unregistered) & _EVENT_NAMES)

    with JsonlEventLog(tmp_path, "unregistered-name") as log:
        for name in plausible_but_unregistered:
            record = log.append(name, reason="store_error", declined_count=1)
            assert record.event == "unknown_event"
            assert record.payload == {}

    contents = log.path.read_text(encoding="utf-8")
    for name in plausible_but_unregistered:
        assert name not in contents


def test_an_unregistered_payload_key_is_dropped(tmp_path: Path) -> None:
    """§8.2.1 的前提本身：已登记事件上的未登记键被丢弃，且内容不留痕。"""

    with JsonlEventLog(tmp_path, "unregistered-key") as log:
        record = log.append(
            "memory_proposal_failed",
            reason="store_error",
            reason_text=SECRET_CONTENT,  # 想偷偷带上原文的字段
            message=SECRET_CONTENT,
            error="TimeoutError('...')",
            content=SECRET_CONTENT,
            record_id=SECRET_RECORD_ID,
            session_id=SECRET_SESSION_ID,
            persona="合成 persona 片段",
        )

    assert record.payload == {"reason": "store_error"}
    contents = log.path.read_text(encoding="utf-8")
    for secret in (SECRET_CONTENT, SECRET_RECORD_ID, SECRET_SESSION_ID, "合成 persona 片段"):
        assert secret not in contents
    for dropped_key in ("reason_text", "content", "record_id", "persona"):
        assert dropped_key not in contents


def test_a_registered_event_with_no_payload_still_lands(tmp_path: Path) -> None:
    """登记项之外的字段全是可选的：生产者只写它算得出来的那一部分。"""

    with JsonlEventLog(tmp_path, "partial") as log:
        record = log.append("extraction_budget_exhausted")

    assert record.event == "extraction_budget_exhausted"
    assert record.payload == {}


# ---------------------------------------------------------------------------
# 3. 固定枚举是闭集
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), ENUM_RULES)
def test_each_closed_set_matches_the_contract_verbatim(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    assert _EVENT_PAYLOAD_RULES[event][field] == (field, value_rule)
    assert set(allowed) == set(CONTRACT_ENUM_VALUES[value_rule]), (
        f"{value_rule} 的闭集必须与契约 §8.2.1 逐字一致"
    )


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), ENUM_RULES)
def test_every_value_inside_the_closed_set_is_accepted(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    for value in sorted(allowed):
        assert _sanitize_payload(event, {field: value}) == {field: value}


def _near_misses(allowed: frozenset[str]) -> list[object]:
    """每个枚举都要拒绝的**近似值**：看着像、但不等于闭集里的任何一个。"""

    sample = sorted(allowed)[0]
    candidates: list[object] = [
        sample.upper(),
        f" {sample}",
        f"{sample} ",
        f"{sample}_",
        f"_{sample}",
        f"{sample}2",
        sample.replace("_", "-"),
        sample.replace("_", " "),
        "unknown",
        "",
        None,
        0,
        1,
        True,
        b"timeout",
        ["timeout"],
        {"reason": sample},
    ]
    # 折叠出的变体有可能恰好撞回闭集（例如 "day" 没有下划线），撞回的去掉。
    return [item for item in candidates if not (type(item) is str and item in allowed)]


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), ENUM_RULES)
def test_values_outside_the_closed_set_are_dropped_not_passed_through(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    """**fail-closed**：枚举外的取值一律丢弃；不做折叠、不做规范化、不透传原文。"""

    for value in _near_misses(allowed):
        assert _sanitize_payload(event, {field: value}) == {}, (value_rule, value)


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), ENUM_RULES)
def test_a_value_from_another_enum_is_not_accepted(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    """跨枚举不算数：``store_error`` 在提议里合法，在提取里照样被丢。"""

    for other_rule, values in CONTRACT_ENUM_VALUES.items():
        if other_rule == value_rule:
            continue
        for value in values:
            assert _sanitize_payload(event, {field: value}) == {}, (value_rule, value)


# ---------------------------------------------------------------------------
# 3b. M2.3 的第五个固定枚举（§7.5 第 3 项）—— 与上面四条**同构**的参数化钉子
#
# ``extraction_propose_failure_reason`` 走的是同一套注册表口径：逐值与契约逐字对齐、
# 枚举外（含别的枚举里的合法值）一律丢弃。它单列一张表的原因见
# ``M2_3_CONTRACT_ENUM_VALUES`` 上的说明（跨枚举共用了两个词）。
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), M2_3_ENUM_RULES)
def test_m2_3_registry_row_is_registered(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    """登记项三件套：事件名在 ``_EVENT_NAMES``、字段在规则表、规则名逐字一致。"""

    assert event in _EVENT_NAMES, f"{event} 必须进 _EVENT_NAMES（否则落 unknown_event）"
    rules = _EVENT_PAYLOAD_RULES.get(event)
    assert rules is not None, f"{event} 必须有自己的 payload 规则表"
    assert rules[field] == (field, value_rule)
    assert allowed, f"{value_rule} 不能是空闭集"


def test_m2_3_enum_events_are_exactly_the_m2_3_event_names() -> None:
    """取值表的观察对象与「M2.3 新增事件名」这张表对齐：不多一个、不少一个。"""

    assert {event for event, _, _, _ in M2_3_ENUM_RULES} == set(M2_3_EVENT_NAMES)


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), M2_3_ENUM_RULES)
def test_m2_3_closed_set_matches_the_contract_verbatim(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    assert set(allowed) == set(M2_3_CONTRACT_ENUM_VALUES[value_rule]), (
        f"{value_rule} 的闭集必须与契约 §8.2.1 逐字一致"
    )


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), M2_3_ENUM_RULES)
def test_m2_3_every_value_inside_the_closed_set_is_accepted(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    for value in sorted(allowed):
        assert _sanitize_payload(event, {field: value}) == {field: value}


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), M2_3_ENUM_RULES)
def test_m2_3_values_outside_the_closed_set_are_dropped_not_passed_through(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    """**fail-closed**：枚举外的取值一律丢弃（复用 W10 的近似值语料，同一条纪律）。"""

    for value in _near_misses(allowed):
        assert _sanitize_payload(event, {field: value}) == {}, (value_rule, value)


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), M2_3_ENUM_RULES)
def test_m2_3_rejects_other_enum_values_except_the_shared_words(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    """跨枚举取值仍然不算数 —— **除了**契约明说要共用的那两个词，且**只有**那两个。"""

    overlap: set[str] = set()
    combined = {**CONTRACT_ENUM_VALUES, **M2_3_CONTRACT_ENUM_VALUES}
    for other_rule, values in combined.items():
        if other_rule == value_rule:
            continue
        for value in values:
            if value in allowed:
                overlap.add(value)
                continue
            assert _sanitize_payload(event, {field: value}) == {}, (value_rule, value)
    assert overlap == set(M2_3_SHARED_WORDS), (
        "与其它枚举共用的词必须恰好是契约里同名的那两个；多一个就说明闭集漂移了"
    )


def test_m2_3_helper_is_fail_loud_and_lands_on_the_registry() -> None:
    """类型化 helper：闭集内的取值落成登记过的事件；闭集外的取值**写之前**就抛。"""

    class _RecordingLog:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def append(self, event: str, **payload: object) -> EventRecord:
            self.calls.append((event, dict(payload)))
            return EventRecord(
                ts="2026-09-27T00:00:00.000+00:00",
                session_id="synthetic",
                event=event,
                payload=dict(payload),
            )

    log = _RecordingLog()
    for value in sorted(EXTRACTION_PROPOSE_FAILURE_REASONS):
        record = log_extraction_propose_failed(log, reason=value)
        assert record.event == "extraction_propose_failed"
        assert record.payload == {"reason": value}

    for rejected in ("scope_not_enabled", "unknown", "STORE_ERROR", "store_error ", ""):
        with pytest.raises(ValueError):
            log_extraction_propose_failed(log, reason=rejected)

    assert log.calls == [
        ("extraction_propose_failed", {"reason": value})
        for value in sorted(EXTRACTION_PROPOSE_FAILURE_REASONS)
    ], "闭集外的取值一次都没有写进去"


@pytest.mark.parametrize(("event", "field", "value_rule", "allowed"), T28_ENUM_RULES)
def test_t28_memory_unavailable_registry_and_closed_set(
    event: str, field: str, value_rule: str, allowed: frozenset[str]
) -> None:
    """M2.2 §6 T28：``memory_unavailable`` 注册在闭集内，只接受 ``store_error``。"""

    assert event in _EVENT_NAMES
    rules = _EVENT_PAYLOAD_RULES.get(event)
    assert rules == {field: (field, value_rule)}
    assert set(allowed) == set(T28_CONTRACT_ENUM_VALUES[value_rule])
    for value in sorted(allowed):
        assert _sanitize_payload(event, {field: value, "message": SECRET_CONTENT}) == {
            field: value
        }
    for value in _near_misses(allowed):
        assert _sanitize_payload(event, {field: value}) == {}

    log = _RecordingLog()
    record = log_memory_unavailable(log, reason="store_error")
    assert record.event == "memory_unavailable"
    assert record.payload == {"reason": "store_error"}
    for rejected in ("validation_error", "unknown", "STORE_ERROR", "store_error ", ""):
        with pytest.raises(ValueError, match="memory_unavailable_reason"):
            log_memory_unavailable(log, reason=rejected)
    assert log.calls == [("memory_unavailable", {"reason": "store_error"})]


def test_a_str_subclass_that_compares_equal_is_still_dropped() -> None:
    """``str`` 子类不算数：注册表只接受原样的 ``str``（与 ``DynamicKey`` 同一条纪律）。"""

    smuggled = _SmuggledEnum("day")
    assert smuggled == "day"
    assert _sanitize_payload("extraction_budget_exhausted", {"level": smuggled}) == {}


def test_the_new_bool_and_count_fields_are_type_strict() -> None:
    """``memory_enabled`` 只接受 ``bool``；``seam_filtered_count`` 走既有的 ``count`` 规则。"""

    assert _sanitize_payload("session_started", {"memory_enabled": True}) == {"memory_enabled": True}
    assert _sanitize_payload("session_started", {"memory_enabled": False}) == {
        "memory_enabled": False
    }
    for bad_bool in (1, 0, "true", "false", None, [], b"true"):
        assert _sanitize_payload("session_started", {"memory_enabled": bad_bool}) == {}

    assert _sanitize_payload("session_started", {"seam_filtered_count": 0}) == {
        "seam_filtered_count": 0
    }
    for bad_count in (-1, "3", True, None, 1_000_000_001):
        assert _sanitize_payload("session_started", {"seam_filtered_count": bad_count}) == {}


def test_the_count_rule_keeps_its_m2_1_semantics() -> None:
    """**既有规则语义不变**（本片要求 8）：``count`` 一直接受有界的有限 ``float``。

    这里刻意**不收紧** ``count``：契约把新计数的取值规则逐字写成 ``count``，而
    ``count`` 在 M2.1 就走 ``_bounded_number``（接受 ``3.0``）。收紧它会改变既有事件
    （``memory_record_count=3.0``）的行为 —— 那是本片明令不许做的事。

    两层因此有意不同口径：JSONL 层更宽是**兼容性**，helper 层更严（``type is int``）
    是**开发期防线**。生产者的每一笔计数都走 helper，所以落盘的计数是 int。
    """

    assert _sanitize_payload("session_started", {"memory_record_count": 3.0}) == {
        "memory_record_count": 3.0
    }
    assert _sanitize_payload("session_started", {"seam_filtered_count": 3.0}) == {
        "seam_filtered_count": 3.0
    }
    assert _sanitize_payload("memory_proposal_declined", {"declined_count": 1.5}) == {
        "declined_count": 1.5
    }
    # 非有限 float 与越界值照旧丢弃（``_bounded_number`` 的原语义）。
    for bad in (float("inf"), float("nan"), -3.0, 1_000_000_001.0):
        assert _sanitize_payload("session_started", {"seam_filtered_count": bad}) == {}

    log = _RecordingLog()
    with pytest.raises(ValueError, match="declined_count"):
        log_proposal_declined(log, declined_count=1.5)
    with pytest.raises(ValueError, match="attempts"):
        log_extraction_failed(log, reason="timeout", attempts=2.0)
    assert log.calls == []


def test_declined_count_and_attempts_are_bounded_counts() -> None:
    assert _sanitize_payload("memory_proposal_declined", {"declined_count": 1}) == {
        "declined_count": 1
    }
    for bad in (-1, "1", True, None):
        assert _sanitize_payload("memory_proposal_declined", {"declined_count": bad}) == {}

    assert _sanitize_payload("extraction_failed", {"attempts": 1}) == {"attempts": 1}
    assert _sanitize_payload("extraction_failed", {"attempts": 2}) == {"attempts": 2}
    for bad in (-1, "2", True, None):
        assert _sanitize_payload("extraction_failed", {"attempts": bad}) == {}


# ---------------------------------------------------------------------------
# 4. 类型化 helper（契约 §8.2.1 的「取值枚举的类型化 helper」）
# ---------------------------------------------------------------------------


def test_helpers_write_exactly_the_registered_payload() -> None:
    log = _RecordingLog()

    assert log_proposal_failed(log, reason="scope_not_enabled").payload == {
        "reason": "scope_not_enabled"
    }
    assert log_proposal_declined(log, declined_count=1).payload == {"declined_count": 1}
    assert log_extraction_failed(log, reason="timeout", attempts=2).payload == {
        "reason": "timeout",
        "attempts": 2,
    }
    assert log_extraction_unavailable(log, reason="credentials_missing").payload == {
        "reason": "credentials_missing"
    }
    assert log_extraction_budget_exhausted(log, level="day").payload == {"level": "day"}

    assert log.calls == [
        ("memory_proposal_failed", {"reason": "scope_not_enabled"}),
        ("memory_proposal_declined", {"declined_count": 1}),
        ("extraction_failed", {"reason": "timeout", "attempts": 2}),
        ("extraction_unavailable", {"reason": "credentials_missing"}),
        ("extraction_budget_exhausted", {"level": "day"}),
    ]


@pytest.mark.parametrize("reason", sorted(PROPOSAL_FAILURE_REASONS))
def test_proposal_failed_helper_accepts_the_whole_closed_set(reason: str) -> None:
    log = _RecordingLog()
    assert log_proposal_failed(log, reason=reason).payload == {"reason": reason}


@pytest.mark.parametrize("reason", sorted(EXTRACTION_FAILURE_REASONS))
def test_extraction_failed_helper_accepts_the_whole_closed_set(reason: str) -> None:
    log = _RecordingLog()
    assert log_extraction_failed(log, reason=reason, attempts=1).payload == {
        "reason": reason,
        "attempts": 1,
    }


@pytest.mark.parametrize("reason", sorted(EXTRACTION_UNAVAILABLE_REASONS))
def test_extraction_unavailable_helper_accepts_the_whole_closed_set(reason: str) -> None:
    log = _RecordingLog()
    assert log_extraction_unavailable(log, reason=reason).payload == {"reason": reason}


@pytest.mark.parametrize("level", sorted(EXTRACTION_BUDGET_LEVELS))
def test_budget_helper_accepts_the_whole_closed_set(level: str) -> None:
    log = _RecordingLog()
    assert log_extraction_budget_exhausted(log, level=level).payload == {"level": level}


def test_helpers_raise_value_error_before_writing_anything() -> None:
    """**fail-loud 在开发期**：脏值抛 ``ValueError``，且一次都没写出去。"""

    log = _RecordingLog()

    with pytest.raises(ValueError, match="proposal_failure_reason"):
        log_proposal_failed(log, reason="scope-disabled")
    with pytest.raises(ValueError, match="declined_count"):
        log_proposal_declined(log, declined_count=-1)
    with pytest.raises(ValueError, match="declined_count"):
        log_proposal_declined(log, declined_count="1")
    with pytest.raises(ValueError, match="extraction_failure_reason"):
        log_extraction_failed(log, reason="Timeout", attempts=1)
    with pytest.raises(ValueError, match="attempts"):
        log_extraction_failed(log, reason="timeout", attempts=3)
    with pytest.raises(ValueError, match="extraction_unavailable_reason"):
        log_extraction_unavailable(log, reason="extraction_disabled")
    with pytest.raises(ValueError, match="extraction_budget_level"):
        log_extraction_budget_exhausted(log, level="daily")

    assert log.calls == [], "helper 必须在 log.append 之前抛出：脏值没有任何机会进 JSONL"


@pytest.mark.parametrize(
    "bad",
    ["timeout ", " timeout", "Timeout", "timeout_", "timeout2", "unknown", "", None, 1, True,
     b"timeout", ["timeout"]],
)
def test_out_of_enum_extraction_reason_raises(bad: object) -> None:
    log = _RecordingLog()
    with pytest.raises(ValueError, match="extraction_failure_reason"):
        log_extraction_failed(log, reason=bad, attempts=1)  # type: ignore[arg-type]
    assert log.calls == []


@pytest.mark.parametrize("bad", [0, 3, -1, 1_000_000_001, True, False, "1", 1.0, None])
def test_attempts_outside_one_or_two_raises(bad: object) -> None:
    """T17：最多重试 1 次 ⇒ ``attempts`` 只能是 1 或 2（``True == 1`` 也不许混进来）。"""

    log = _RecordingLog()
    with pytest.raises(ValueError, match="attempts"):
        log_extraction_failed(log, reason="timeout", attempts=bad)  # type: ignore[arg-type]
    assert log.calls == []


@pytest.mark.parametrize("bad", [None, "", "Session", "DAY", "daily", "session ", 0, 1, True])
def test_budget_level_outside_the_closed_set_raises(bad: object) -> None:
    log = _RecordingLog()
    with pytest.raises(ValueError, match="extraction_budget_level"):
        log_extraction_budget_exhausted(log, level=bad)  # type: ignore[arg-type]
    assert log.calls == []


def test_helpers_take_keyword_only_arguments() -> None:
    """关键字限定：位置参数传不进去，字段名就不可能接错位置。"""

    log = _RecordingLog()
    with pytest.raises(TypeError):
        log_proposal_failed(log, "scope_not_enabled")  # type: ignore[misc]
    with pytest.raises(TypeError):
        log_extraction_failed(log, "timeout", 1)  # type: ignore[misc]
    assert log.calls == []


def test_every_helper_output_survives_the_jsonl_layer() -> None:
    """两层必须**同口径**：helper 放行的值一个都不许被 JSONL 层丢掉。

    若两层漂移（例如 ``count`` 的上界只在一边收紧），helper 就成了「假 fail-loud」：
    调用点放行，值却在落盘时静默消失 —— 比一开始就报错更难查。
    """

    log = _RecordingLog()
    log_proposal_failed(log, reason="validation_error")
    log_proposal_declined(log, declined_count=0)
    log_proposal_declined(log, declined_count=1_000_000_000)  # count 的上界本身
    log_extraction_failed(log, reason="network_error", attempts=1)
    log_extraction_failed(log, reason="http_error", attempts=2)
    log_extraction_failed(log, reason="schema_invalid", attempts=2)
    log_extraction_unavailable(log, reason="budget_store_error")
    log_extraction_budget_exhausted(log, level="session")

    for event, payload in log.calls:
        assert event in _EVENT_NAMES
        assert _sanitize_payload(event, payload) == payload, (event, payload)


def test_helpers_round_trip_through_a_real_jsonl_file(tmp_path: Path) -> None:
    """真写一次盘再读回来：payload 逐字节等于 helper 给的那个 dict。"""

    with JsonlEventLog(tmp_path, "round-trip") as log:
        log_proposal_failed(log, reason="store_error")
        log_proposal_declined(log, declined_count=2)
        log_extraction_failed(log, reason="schema_invalid", attempts=2)
        log_extraction_unavailable(log, reason="credentials_missing")
        log_extraction_budget_exhausted(log, level="session")

    events = list(load_events(log.path))
    assert [(item["event"], item["payload"]) for item in events] == [
        ("memory_proposal_failed", {"reason": "store_error"}),
        ("memory_proposal_declined", {"declined_count": 2}),
        ("extraction_failed", {"reason": "schema_invalid", "attempts": 2}),
        ("extraction_unavailable", {"reason": "credentials_missing"}),
        ("extraction_budget_exhausted", {"level": "session"}),
    ]


# ---------------------------------------------------------------------------
# 5. 隐私：新登记项只带计数 / 布尔 / 固定枚举
# ---------------------------------------------------------------------------


def test_new_registry_entries_never_carry_content_ids_or_persona(tmp_path: Path) -> None:
    """§2.5 硬约束 2 / §5 落点 2：新增的 7 个登记项一个都不许带正文或 id。"""

    with JsonlEventLog(tmp_path, "privacy") as log:
        # helper 路径：只能给出枚举与计数，正文/ id 连参数位都没有。
        log_proposal_failed(log, reason="scope_not_enabled")
        log_proposal_declined(log, declined_count=1)
        log_extraction_failed(log, reason="timeout", attempts=1)
        log_extraction_unavailable(log, reason="budget_store_error")
        log_extraction_budget_exhausted(log, level="day")
        # 直连路径：调用方硬塞未登记键，照样被丢弃。
        log.append(
            "extraction_failed",
            reason="http_error",
            attempts=2,
            content=SECRET_CONTENT,
            record_id=SECRET_RECORD_ID,
            session_id=SECRET_SESSION_ID,
            persona="合成 persona 片段",
            message=SECRET_CONTENT,
        )
        log.append(
            "session_started",
            memory_enabled=True,
            seam_filtered_count=3,
            memory_content=SECRET_CONTENT,
            memory_record_ids=[SECRET_RECORD_ID],
            record_id=SECRET_RECORD_ID,
            session_id=SECRET_SESSION_ID,
            persona="合成 persona 片段",
        )

    contents = log.path.read_text(encoding="utf-8")
    for secret in (SECRET_CONTENT, SECRET_RECORD_ID, SECRET_SESSION_ID, "合成 persona 片段"):
        assert secret not in contents

    events = list(load_events(log.path))
    assert [item["event"] for item in events] == [
        "memory_proposal_failed",
        "memory_proposal_declined",
        "extraction_failed",
        "extraction_unavailable",
        "extraction_budget_exhausted",
        "extraction_failed",
        "session_started",
    ]
    forbidden_keys = {"content", "record_id", "record_ids", "session_id", "persona", "message"}
    for item in events:
        payload = item["payload"]
        assert not (forbidden_keys & set(payload)), item
        for value in payload.values():
            # 只允许计数(bool 是 int 的子类,单列)、布尔与固定枚举字符串。
            assert type(value) in (int, bool, str), item
            if type(value) is str:
                assert value in set().union(*CONTRACT_ENUM_VALUES.values()), item

    assert events[6]["payload"] == {"memory_enabled": True, "seam_filtered_count": 3}
