"""The default JSONL event log retains bounded metadata and drops content."""

from datetime import datetime, timedelta, timezone
import json

from soul_memory_kernel.obs import events as event_module
from soul_memory_kernel.obs.events import (
    JsonlEventLog,
    interruption_queue_processing_latencies_ms,
    log_extraction_budget_exhausted,
    log_extraction_failed,
    log_extraction_unavailable,
    log_proposal_declined,
    log_proposal_failed,
    provider_audio_event_arrival_latencies_ms,
    session_summary,
)


class SecretValue:
    def __repr__(self):
        raise AssertionError("logger must not repr untrusted values")

    def __str__(self):
        raise AssertionError("logger must not stringify untrusted values")


class DynamicKey(str):
    pass


def test_transcripts_store_only_presence_metadata(tmp_path):
    with JsonlEventLog(tmp_path, "transcript") as log:
        user = log.append(
            "user_transcript",
            text="真实家庭对话原文",
            is_final=True,
            source_event=451,
            finalized_by_event=459,
        )
        agent = log.append("agent_transcript", text="AI 回复全文", is_final=True)

    assert user.payload == {
        "text_present": True,
        "is_final": True,
        "source_event": 451,
        "finalized_by_event": 459,
    }
    assert agent.payload == {"text_present": True, "is_final": True}
    contents = log.path.read_text(encoding="utf-8")
    assert "真实家庭对话原文" not in contents
    assert "AI 回复全文" not in contents
    assert "hash" not in contents.lower()


def test_message_raw_event_dynamic_keys_nested_values_and_hashes_are_dropped(tmp_path):
    payload = {
        "phase": "pipeline",
        "fatal": True,
        "message": SecretValue(),
        "raw_event": {
            "text": "nested private transcript",
            "audio": b"private pcm bytes",
            "nested": {"message": SecretValue()},
        },
        "text_hash": "low-entropy-hash-of-yes",
        "reply_hash": "hash-of-private-reply",
        DynamicKey("dynamic_private_field"): "dynamic private value",
    }

    with JsonlEventLog(tmp_path, "filtered") as log:
        record = log.append("error", **payload)

    assert record.payload == {"phase": "pipeline", "fatal": True, "message_present": True}
    contents = log.path.read_text(encoding="utf-8")
    for secret in (
        "nested private transcript",
        "private pcm bytes",
        "low-entropy-hash-of-yes",
        "hash-of-private-reply",
        "dynamic_private_field",
        "dynamic private value",
    ):
        assert secret not in contents
    assert "message_present" in contents


def test_unknown_event_name_and_payload_are_normalized_away(tmp_path):
    with JsonlEventLog(tmp_path, "unknown") as log:
        record = log.append("private.dynamic.event", text="should not survive")

    assert record.event == "unknown_event"
    assert record.payload == {}
    contents = log.path.read_text(encoding="utf-8")
    assert "private.dynamic.event" not in contents
    assert "should not survive" not in contents


def test_usage_retains_only_known_top_level_numeric_counters(tmp_path):
    with JsonlEventLog(tmp_path, "usage") as log:
        record = log.append(
            "usage",
            amount=0.25,
            input_tokens=120,
            output_tokens=30,
            input_token_details={"cached_tokens": 99, "private": "nested"},
            arbitrary_counter=777,
            low_entropy_hash="1234",
        )

    assert record.payload == {"amount": 0.25, "input_tokens": 120, "output_tokens": 30}
    contents = log.path.read_text(encoding="utf-8")
    assert "cached_tokens" not in contents
    assert "nested" not in contents
    assert "arbitrary_counter" not in contents
    assert "low_entropy_hash" not in contents


def test_session_started_retains_mode_but_drops_config_and_identity_values(tmp_path):
    with JsonlEventLog(tmp_path, "session-start") as log:
        record = log.append(
            "session_started",
            provider="realtime_ws",
            route="C",
            model_parameter_sent=False,
            voice_parameter_sent=False,
            identity_scope="manually_selected_unverified",
            identity_assurance="manually_selected_unverified",
            session_mode="shared",
            speaker_id="private-person-id",
            model="private custom model name",
            base_url="https://secret.example.invalid",
        )

    assert record.payload == {
        "provider": "realtime_ws",
        "route": "C",
        "model_parameter_sent": False,
        "voice_parameter_sent": False,
        "identity_scope": "manually_selected_unverified",
        "identity_assurance": "manually_selected_unverified",
        "session_mode": "shared",
    }
    contents = log.path.read_text(encoding="utf-8")
    assert "private-person-id" not in contents
    assert "private custom model name" not in contents
    assert "secret.example.invalid" not in contents


def test_metadata_needed_by_latency_and_summary_helpers_is_retained(tmp_path, monkeypatch):
    current = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)

    def ticking_now_iso():
        nonlocal current
        result = current.isoformat(timespec="milliseconds")
        current += timedelta(milliseconds=100)
        return result

    monkeypatch.setattr(event_module, "now_iso", ticking_now_iso)
    with JsonlEventLog(tmp_path, "metrics") as log:
        log.append("session_started", provider="realtime_ws", route="C")
        log.append("user_turn_completed", source_event=459)
        log.append("provider_audio_first_event", bytes=480)
        log.append("user_speech_started", offset_ms=100, was_speaking=False, state="listening")
        log.append("interruption_requested", trigger="user_speech_started", from_state="speaking")
        log.append("interruption_queue_processing", processed=True, elapsed_ms=50.0, error="private error")
        log.append("agent_output_stopped", source="local_output_transport", physical_silence_observed=False)
        log.append("error", phase="pipeline", fatal=True, message="private provider error")
        log.append("session_ended", duration_s=0.8, reason="manual", interruptions=1)

    assert provider_audio_event_arrival_latencies_ms(log.path) == [100.0]
    assert interruption_queue_processing_latencies_ms(log.path) == [200.0]
    summary = session_summary(log.path)
    assert summary["duration_s"] == 0.8
    assert summary["interruptions"] == 1
    assert summary["interruption_queue_processed"] == 1
    assert summary["output_stops_observed"] == 1
    assert summary["errors"] == 1
    assert summary["ended_reason"] == "manual"
    contents = log.path.read_text(encoding="utf-8")
    assert "private error" not in contents
    assert "private provider error" not in contents


def test_audio_and_invalid_or_nested_fields_never_reach_json(tmp_path):
    with JsonlEventLog(tmp_path, "audio") as log:
        record = log.append(
            "provider_audio_first_event",
            bytes=480,
            raw_event={"audio": b"raw pcm", "text": "secret"},
            text_hash="hashed transcript",
            bytes_extra={"count": 480},
        )

    assert record.payload == {"bytes": 480}
    contents = log.path.read_text(encoding="utf-8")
    assert "raw pcm" not in contents
    assert "secret" not in contents
    assert "hashed transcript" not in contents
    assert "bytes_extra" not in contents


def test_event_file_is_valid_json_even_when_untrusted_repr_would_raise(tmp_path):
    with JsonlEventLog(tmp_path, "repr") as log:
        log.append("error", phase="connect", message=SecretValue())

    decoded = [json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines()]
    assert decoded[0]["payload"] == {"phase": "connect", "message_present": True}


# ---------------------------------------------------------------------------
# M2.2(W10):新增的 5 个计数事件 + session_started 的两个新字段
#
# 这一组是 M2.1 纪律在**新登记项**上的延伸,不是新纪律:新事件只能携带计数、
# 布尔与固定枚举,未登记键(正文、记录 id、会话 id、persona 片段)照旧被丢弃。
# 既有的每一条断言都保持不变 —— 新增项在旧的断言之外另立一条。
# ---------------------------------------------------------------------------

#: 合成样本(data_class = synthetic_only),不是任何真实家庭的记忆内容或 id。
M2_2_SECRET_CONTENT = "合成样本:某个孩子对某种坚果过敏"
M2_2_SECRET_RECORD_ID = "mem-synthetic-0001"
M2_2_SECRET_SESSION_ID = "sess-synthetic-0001"
M2_2_SECRET_PERSONA = "合成 persona 片段"


def test_m2_2_counter_events_retain_only_counts_and_closed_set_values(tmp_path):
    """五个新事件经 JSONL 往返后**只有**计数与固定枚举:正文/id/会话 id 一个不留。"""

    with JsonlEventLog(tmp_path, "m22-counters") as log:
        log_proposal_failed(log, reason="scope_not_enabled")
        log_proposal_declined(log, declined_count=1)
        log_extraction_failed(log, reason="timeout", attempts=2)
        log_extraction_unavailable(log, reason="credentials_missing")
        log_extraction_budget_exhausted(log, level="day")
        # 直连路径:调用方硬塞未登记键,照样被丢弃(防线不只在 helper 里)。
        log.append(
            "memory_proposal_failed",
            reason="store_error",
            content=M2_2_SECRET_CONTENT,
            record_id=M2_2_SECRET_RECORD_ID,
            session_id=M2_2_SECRET_SESSION_ID,
            persona=M2_2_SECRET_PERSONA,
            error="TimeoutError('synthetic')",
        )

    decoded = [json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines()]
    assert [item["event"] for item in decoded] == [
        "memory_proposal_failed",
        "memory_proposal_declined",
        "extraction_failed",
        "extraction_unavailable",
        "extraction_budget_exhausted",
        "memory_proposal_failed",
    ]
    assert [item["payload"] for item in decoded] == [
        {"reason": "scope_not_enabled"},
        {"declined_count": 1},
        {"reason": "timeout", "attempts": 2},
        {"reason": "credentials_missing"},
        {"level": "day"},
        {"reason": "store_error"},
    ]

    contents = log.path.read_text(encoding="utf-8")
    for secret in (
        M2_2_SECRET_CONTENT,
        M2_2_SECRET_RECORD_ID,
        M2_2_SECRET_SESSION_ID,
        M2_2_SECRET_PERSONA,
        "TimeoutError",
        "persona",
        "content",
        "record_id",
    ):
        assert secret not in contents


def test_m2_2_session_started_new_fields_are_count_and_bool_only(tmp_path):
    """D14/D15 的两个新字段:只接受布尔与计数;正文、id、persona 片段照旧进不去。"""

    with JsonlEventLog(tmp_path, "m22-session") as log:
        record = log.append(
            "session_started",
            provider="realtime_ws",
            route="C",
            memory_enabled=True,
            seam_filtered_count=2,
            memory_record_count=3,
            memory_projected_count=3,
            memory_truncated_count=0,
            # 以下都不在白名单里:正文 / 记录 id / 会话 id / persona 片段 /
            # 投影文本本身。它们必须与 M2.1 一样被丢弃。
            memory_content=M2_2_SECRET_CONTENT,
            memory_record_id=M2_2_SECRET_RECORD_ID,
            memory_records=[M2_2_SECRET_RECORD_ID],
            session_id=M2_2_SECRET_SESSION_ID,
            persona=M2_2_SECRET_PERSONA,
            memory_block=M2_2_SECRET_CONTENT,
            seam_filtered_ids=[M2_2_SECRET_RECORD_ID],
        )

    assert record.payload == {
        "provider": "realtime_ws",
        "route": "C",
        "memory_enabled": True,
        "seam_filtered_count": 2,
        "memory_record_count": 3,
        "memory_projected_count": 3,
        "memory_truncated_count": 0,
    }
    contents = log.path.read_text(encoding="utf-8")
    for secret in (
        M2_2_SECRET_CONTENT,
        M2_2_SECRET_RECORD_ID,
        M2_2_SECRET_SESSION_ID,
        M2_2_SECRET_PERSONA,
        "seam_filtered_ids",
        "memory_content",
        "persona",
    ):
        assert secret not in contents


def test_m2_2_new_event_names_do_not_open_a_free_text_channel(tmp_path):
    """新事件名不是「随便写点什么」的后门:只登记的键进得去,别的键一律丢弃。"""

    with JsonlEventLog(tmp_path, "m22-backdoor") as log:
        for event in (
            "memory_proposal_failed",
            "memory_proposal_declined",
            "extraction_failed",
            "extraction_unavailable",
            "extraction_budget_exhausted",
        ):
            record = log.append(
                event,
                text=M2_2_SECRET_CONTENT,
                transcript=M2_2_SECRET_CONTENT,
                exception=str(SecretValue.__name__),
                raw={"content": M2_2_SECRET_CONTENT},
                nested={"reason": "store_error"},
            )
            assert record.payload == {}, event

    contents = log.path.read_text(encoding="utf-8")
    assert M2_2_SECRET_CONTENT not in contents
    assert "transcript" not in contents
    assert "exception" not in contents
