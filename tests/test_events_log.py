"""JSONL 事件日志测试(规格 §9):追加、延迟埋点、损坏行不崩、§6.5 汇总。"""

import json
from datetime import datetime, timezone
from pathlib import Path

from soul_memory_kernel.obs.events import (
    JsonlEventLog,
    first_response_latencies_ms,
    interruption_latencies_ms,
    interruption_queue_processing_latencies_ms,
    load_events,
    now_iso,
    provider_audio_event_arrival_latencies_ms,
    session_summary,
)

TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"


def _ts(base: datetime, offset_ms: int) -> str:
    from datetime import timedelta

    return (base + timedelta(milliseconds=offset_ms)).isoformat(timespec="milliseconds")


def _write_events(path: Path, events: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")


# ---- 写入器 ----


def test_append_record_fields(tmp_path: Path):
    with JsonlEventLog(tmp_path, "sess1") as log:
        rec = log.append("user_transcript", text="敏感转写", is_final=True, source_event=451)
    assert rec.session_id == "sess1"
    assert rec.event == "user_transcript"
    assert rec.payload == {"text_present": True, "is_final": True, "source_event": 451}
    # ts 为 ISO8601 且可解析(延迟计算依赖该格式)
    datetime.strptime(rec.ts, TS_FMT)
    # 每行一个事件,公共字段齐全
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert set(obj) == {"ts", "session_id", "event", "payload"}
    assert "敏感转写" not in lines[0]


def test_append_multiple_events_no_truncation(tmp_path: Path):
    with JsonlEventLog(tmp_path, "sess2") as log:
        for i in range(5):
            log.append("user_transcript", text=f"第{i}句", is_final=True)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5  # append-only,追加不截断
    assert json.loads(lines[-1])["payload"]["text_present"] is True
    assert all("第" not in line for line in lines)


def test_log_file_lives_in_log_dir_named_by_session(tmp_path: Path):
    with JsonlEventLog(tmp_path, "abc123") as log:
        pass
    assert log.path.parent == tmp_path
    assert log.path.name.endswith("-abc123.jsonl")
    assert log.path.exists()


def test_writer_creates_missing_dir(tmp_path: Path):
    nested = tmp_path / "a" / "b"
    with JsonlEventLog(nested, "s") as log:
        log.append("session_started")
    assert log.path.exists()


def test_transcript_text_is_not_persisted(tmp_path: Path):
    with JsonlEventLog(tmp_path, "s") as log:
        log.append("user_transcript", text="不要落盘的中文内容", is_final=True)
    contents = log.path.read_text(encoding="utf-8")
    assert "不要落盘的中文内容" not in contents
    assert '"text_present": true' in contents


# ---- 读取与损坏行 ----


def test_load_events_roundtrip(tmp_path: Path):
    path = tmp_path / "x.jsonl"
    _write_events(path, [
        {"ts": now_iso(), "session_id": "s", "event": "session_started", "payload": {}},
        {"ts": now_iso(), "session_id": "s", "event": "session_ended", "payload": {"reason": "manual"}},
    ])
    events = list(load_events(path))
    assert [e["event"] for e in events] == ["session_started", "session_ended"]


def test_load_events_skips_corrupted_lines(tmp_path: Path):
    path = tmp_path / "x.jsonl"
    good = {"ts": now_iso(), "session_id": "s", "event": "error", "payload": {"message": "m"}}
    path.write_text(
        "{broken json\n"
        "\n"
        + json.dumps(good, ensure_ascii=False)
        + "\n[1,2,3]\n"  # 合法 JSON 但不是对象
        + '{"ts": "incomplete\n',
        encoding="utf-8",
    )
    events = list(load_events(path))  # 不抛,坏行跳过
    assert events == [good]


# ---- 延迟埋点计算(规格 §9.3) ----


def _base() -> datetime:
    # 与 now_iso() 同为带时区的 UTC 时间戳(isoformat 输出含偏移,%z 可解析)
    return datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


def test_provider_audio_arrival_pairs_route_c_459_not_delayed_351(tmp_path: Path):
    path = tmp_path / "lat.jsonl"
    t0 = _base()
    _write_events(path, [
        {"ts": _ts(t0, 0), "session_id": "s", "event": "user_transcript", "payload": {"text": "你", "is_final": False}},
        {"ts": _ts(t0, 100), "session_id": "s", "event": "user_turn_completed", "payload": {"source_event": 459}},
        {"ts": _ts(t0, 150), "session_id": "s", "event": "agent_turn_started", "payload": {"source_event": 350}},
        {"ts": _ts(t0, 200), "session_id": "s", "event": "agent_transcript", "payload": {"text": "你好", "is_final": False}},
        {"ts": _ts(t0, 250), "session_id": "s", "event": "agent_transcript", "payload": {"is_final": True}},
        {"ts": _ts(t0, 300), "session_id": "s", "event": "usage", "payload": {"usage": {}}},
        {"ts": _ts(t0, 900), "session_id": "s", "event": "provider_audio_first_event", "payload": {"bytes": 480}},
        {"ts": _ts(t0, 950), "session_id": "s", "event": "provider_audio_first_event", "payload": {"bytes": 480}},  # 只配对一次
        {"ts": _ts(t0, 1000), "session_id": "s", "event": "user_transcript", "payload": {"text": "历史误映射", "is_final": True, "source_event": 351}},
        {"ts": _ts(t0, 1050), "session_id": "s", "event": "agent_tts_sentence_completed", "payload": {"source_event": 351}},
        {"ts": _ts(t0, 1100), "session_id": "s", "event": "user_transcript", "payload": {"text": "收束后的转写", "is_final": True, "source_event": 451, "finalized_by_event": 459}},
        {"ts": _ts(t0, 1300), "session_id": "s", "event": "provider_audio_first_event", "payload": {"bytes": 480}},  # 迟到 351/合成 final 均不重开起点
        {"ts": _ts(t0, 2500), "session_id": "s", "event": "user_transcript", "payload": {"text": "再见", "is_final": True}},
        {"ts": _ts(t0, 3000), "session_id": "s", "event": "provider_audio_first_event", "payload": {"bytes": 480}},
    ])
    latencies = first_response_latencies_ms(path)
    assert latencies == [800.0, 500.0]  # 459 → 音频事件；351 不重开
    assert provider_audio_event_arrival_latencies_ms(path) == latencies


def test_interruption_latency_pairs_only_successful_queue_processing(tmp_path: Path):
    path = tmp_path / "int.jsonl"
    t0 = _base()
    _write_events(path, [
        {"ts": _ts(t0, 0), "session_id": "s", "event": "user_speech_started", "payload": {"offset_ms": 0}},
        {"ts": _ts(t0, 1), "session_id": "s", "event": "interruption_requested", "payload": {"trigger": "user_speech_started"}},
        {"ts": _ts(t0, 2), "session_id": "s", "event": "provider_interrupt_call", "payload": {"call_returned": True}},
        {"ts": _ts(t0, 3), "session_id": "s", "event": "interruption_applied", "payload": {"elapsed_ms": 0.7}},  # legacy metric is ignored
        {"ts": _ts(t0, 180), "session_id": "s", "event": "interruption_queue_processing", "payload": {"processed": False}},
        {"ts": _ts(t0, 3000), "session_id": "s", "event": "user_speech_started", "payload": {"offset_ms": 1}},
        {"ts": _ts(t0, 3010), "session_id": "s", "event": "provider_interrupt_call", "payload": {"call_returned": True}},
        {"ts": _ts(t0, 3220), "session_id": "s", "event": "interruption_queue_processing", "payload": {"processed": True}},
    ])
    assert interruption_queue_processing_latencies_ms(path) == [220.0]
    assert interruption_latencies_ms(path) == [220.0]  # compatibility alias


def test_latency_helpers_on_missing_files_do_not_crash(tmp_path: Path):
    missing = tmp_path / "nope.jsonl"
    missing.write_text("", encoding="utf-8")
    assert first_response_latencies_ms(missing) == []
    assert interruption_latencies_ms(missing) == []
    assert interruption_queue_processing_latencies_ms(missing) == []


# ---- session 汇总(§6.5 可自动计算项) ----


def test_session_summary_computes_expected_metrics(tmp_path: Path):
    path = tmp_path / "sum.jsonl"
    t0 = _base()
    _write_events(path, [
        {"ts": _ts(t0, 0), "session_id": "s", "event": "session_started", "payload": {"provider": "realtime_ws"}},
        {"ts": _ts(t0, 100), "session_id": "s", "event": "user_turn_completed", "payload": {"source_event": 459}},
        {"ts": _ts(t0, 800), "session_id": "s", "event": "provider_audio_first_event", "payload": {"bytes": 1}},
        {"ts": _ts(t0, 2000), "session_id": "s", "event": "user_speech_started", "payload": {}},
        {"ts": _ts(t0, 2010), "session_id": "s", "event": "interruption_requested", "payload": {}},
        {"ts": _ts(t0, 2020), "session_id": "s", "event": "provider_interrupt_call", "payload": {"call_returned": True}},
        {"ts": _ts(t0, 2100), "session_id": "s", "event": "interruption_queue_processing", "payload": {"processed": True}},
        {"ts": _ts(t0, 2150), "session_id": "s", "event": "agent_output_stopped", "payload": {"physical_silence_observed": False}},
        {"ts": _ts(t0, 2200), "session_id": "s", "event": "interruption_applied", "payload": {"elapsed_ms": 0.7}},  # legacy event is not evidence
        {"ts": _ts(t0, 3000), "session_id": "s", "event": "error", "payload": {"message": "x"}},
        {"ts": _ts(t0, 65000), "session_id": "s", "event": "session_ended", "payload": {"reason": "manual", "duration_s": 65.0, "interruptions": 1}},
    ])
    summary = session_summary(path)
    assert summary["duration_s"] == 65.0
    assert summary["interruptions"] == 1
    assert summary["errors"] == 1
    assert summary["provider_audio_event_arrival_ms"] == [700.0]
    assert "first_response_ms" not in summary
    assert summary["interruptions"] == 1
    assert summary["interruption_queue_processed"] == 1
    assert summary["output_stops_observed"] == 1
    assert summary["interruption_queue_processing_ms"] == [100.0]
    assert "interruption_applied_ms" not in summary
    assert summary["ended_reason"] == "manual"
