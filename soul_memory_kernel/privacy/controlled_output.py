"""Isolated application-side experimental output gate.

This module is not wired into the M0 voice pipeline. Synthetic tests and the
explicit one-turn Route C experiment supply identities and a synchronous,
non-blocking sink. Its ordering proof ends at sink.enqueue/stop; it makes no
claim about physical speaker silence or semantic content safety.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from time import monotonic
from typing import Literal, Protocol

from soul_memory_kernel.privacy.provider_types import ProviderEvent


@dataclass(frozen=True)
class TurnKey:
    session_id: str
    turn_id: str
    content_version: str
    output_generation: str

    def __post_init__(self) -> None:
        if not all((self.session_id, self.turn_id, self.content_version, self.output_generation)):
            raise ValueError("all turn identity fields are required")
        if any(
            len(value.encode("utf-8")) > 128
            for value in (self.session_id, self.turn_id, self.content_version, self.output_generation)
        ):
            raise ValueError("turn identity field exceeds 128 bytes")


@dataclass(frozen=True)
class SealedOutput:
    key: TurnKey
    digest: str
    text: str
    audio_chunks: tuple[bytes, ...]


@dataclass(frozen=True)
class Decision:
    key: TurnKey
    digest: str
    action: Literal["allow", "deny"]


class Decider(Protocol):
    """Implementations must promptly cooperate with task cancellation."""

    async def decide(self, output: SealedOutput) -> Decision: ...


class PlaybackSink(Protocol):
    """Non-blocking enqueue and stop; neither method may await or call the gate."""

    def publish_text(self, key: TurnKey, text: str) -> None: ...

    def enqueue(self, key: TurnKey, pcm16: bytes) -> None: ...

    def stop(self, key: TurnKey) -> None: ...


@dataclass(frozen=True)
class Limits:
    max_text_bytes: int = 16_384
    max_text_chunks: int = 256
    max_audio_bytes: int = 2_000_000
    max_audio_chunks: int = 256
    max_turns: int = 1_024
    max_wait_s: float = 5.0

    def __post_init__(self) -> None:
        if min(
            self.max_text_bytes,
            self.max_text_chunks,
            self.max_audio_bytes,
            self.max_audio_chunks,
            self.max_turns,
        ) <= 0:
            raise ValueError("buffer limits must be positive")
        if self.max_wait_s <= 0:
            raise ValueError("max_wait_s must be positive")


@dataclass
class TurnResult:
    key: TurnKey
    status: str = "pending"
    text_bytes: int = 0
    audio_bytes: int = 0
    audio_chunks: int = 0
    peak_gate_list_payload_bytes: int = 0
    started_at: float = field(default_factory=monotonic)
    provider_complete_at: float | None = None
    text_published_at: float | None = None
    first_enqueue_at: float | None = None
    finished_at: float | None = None
    gate_list_payload_bytes_after: int = 0
    _done: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    async def wait(self) -> TurnResult:
        await self._done.wait()
        return self


@dataclass
class _Turn:
    result: TurnResult
    deadline: float
    text_parts: list[str] = field(default_factory=list)
    audio_chunks: list[bytes] = field(default_factory=list)
    text_final: bool = False
    provider_complete: bool = False
    state: Literal["collecting", "deciding", "releasing", "finished"] = "collecting"
    decision_task: asyncio.Task[None] | None = None
    watchdog: asyncio.Task[None] | None = None
    write_started: bool = False

    @property
    def key(self) -> TurnKey:
        return self.result.key


class ControlledOutputGate:
    """One bounded synthetic turn at a time; all sink calls linearize on one lock."""

    def __init__(self, decider: Decider, sink: PlaybackSink, limits: Limits = Limits()):
        self._decider = decider
        self._sink = sink
        self._limits = limits
        self._lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()
        self._turn: _Turn | None = None
        self._last_played_key: TurnKey | None = None
        self._closed = False
        self._tasks: set[asyncio.Task[None]] = set()
        self._used_keys: set[TurnKey] = set()

    @property
    def pending_tasks(self) -> int:
        return sum(not task.done() for task in self._tasks)

    def _track(self, task: asyncio.Task[None]) -> asyncio.Task[None]:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    @staticmethod
    async def _join(turn: _Turn | None) -> None:
        if turn is None:
            return
        tasks = [task for task in (turn.decision_task, turn.watchdog) if task is not None]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def begin(self, key: TurnKey) -> TurnResult:
        async with self._lifecycle_lock:
            async with self._lock:
                if self._closed:
                    raise RuntimeError("gate closed")
                previous = self._turn
                if previous is not None and previous.state != "finished":
                    raise RuntimeError("cancel or finish the active turn first")
            await self._join(previous)
            async with self._lock:
                if key in self._used_keys or len(self._used_keys) >= self._limits.max_turns:
                    raise RuntimeError("turn identity reused or gate turn limit reached")
                if self._last_played_key is not None:
                    self._sink.stop(self._last_played_key)
                    self._last_played_key = None
                self._used_keys.add(key)
                result = TurnResult(key=key)
                turn = _Turn(result=result, deadline=result.started_at + self._limits.max_wait_s)
                self._turn = turn
                turn.watchdog = self._track(asyncio.create_task(self._expire(turn)))
                return result

    async def ingest(self, key: TurnKey, event: ProviderEvent) -> bool:
        """Return False for stale or rejected events; never route those to sink."""

        async with self._lock:
            turn = self._turn
            if self._closed or turn is None or turn.key != key or turn.state == "finished":
                return False
            if event.output_generation != key.output_generation:
                self._finish_locked(turn, "invalid_output")
                return False
            if monotonic() >= turn.deadline:
                self._finish_locked(turn, "timeout")
                return False
            if event.kind == "error":
                self._finish_locked(turn, "error")
                return True
            if turn.state != "collecting":
                # A late delta after 359 invalidates an undecided seal. Once
                # release starts it is simply stale and can never join approval.
                if turn.state == "deciding" and event.kind in {"agent_transcript", "agent_audio_delta"}:
                    self._finish_locked(turn, "invalid_output")
                return False
            if event.kind == "agent_transcript":
                if turn.text_final or not isinstance(event.text, str):
                    self._finish_locked(turn, "invalid_output")
                    return False
                if not event.text and not event.is_final:
                    return True
                added = len(event.text.encode("utf-8"))
                if (
                    turn.result.text_bytes + added > self._limits.max_text_bytes
                    or len(turn.text_parts) + 1 > self._limits.max_text_chunks
                ):
                    self._finish_locked(turn, "over_limit")
                    return False
                turn.text_parts.append(event.text)
                turn.result.text_bytes += added
                if event.is_final:
                    turn.text_final = True
            elif event.kind == "agent_audio_delta":
                audio = event.audio
                if not isinstance(audio, bytes) or not audio or len(audio) % 2:
                    self._finish_locked(turn, "invalid_output")
                    return False
                if (
                    turn.result.audio_bytes + len(audio) > self._limits.max_audio_bytes
                    or turn.result.audio_chunks + 1 > self._limits.max_audio_chunks
                ):
                    self._finish_locked(turn, "over_limit")
                    return False
                turn.audio_chunks.append(audio)
                turn.result.audio_bytes += len(audio)
                turn.result.audio_chunks += 1
            elif event.kind == "agent_turn_completed":
                if turn.provider_complete:
                    self._finish_locked(turn, "invalid_output")
                    return False
                turn.provider_complete = True
                turn.result.provider_complete_at = monotonic()
                if not turn.text_final or turn.result.text_bytes == 0 or turn.result.audio_bytes == 0:
                    self._finish_locked(turn, "invalid_output")
                    return False
                self._seal_locked(turn)
            else:
                return False
            turn.result.peak_gate_list_payload_bytes = max(
                turn.result.peak_gate_list_payload_bytes,
                turn.result.text_bytes + turn.result.audio_bytes,
            )
            return True

    def _seal_locked(self, turn: _Turn) -> None:
        text = "".join(turn.text_parts)
        audio = tuple(turn.audio_chunks)
        digest = hashlib.sha256()
        for field_value in (
            turn.key.session_id,
            turn.key.turn_id,
            turn.key.content_version,
            turn.key.output_generation,
            text,
        ):
            encoded = field_value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        for chunk in audio:
            digest.update(len(chunk).to_bytes(8, "big"))
            digest.update(chunk)
        sealed = SealedOutput(turn.key, digest.hexdigest(), text, audio)
        turn.state = "deciding"
        turn.decision_task = self._track(asyncio.create_task(self._decide_and_release(turn, sealed)))

    async def _decide_and_release(self, turn: _Turn, sealed: SealedOutput) -> None:
        try:
            remaining = max(0.0, turn.deadline - monotonic())
            decision = await asyncio.wait_for(self._decider.decide(sealed), timeout=remaining)
            async with self._lock:
                if self._turn is not turn or turn.state != "deciding":
                    return
                if not isinstance(decision, Decision) or (
                    decision.key != sealed.key
                    or decision.digest != sealed.digest
                    or decision.action not in ("allow", "deny")
                ):
                    self._finish_locked(turn, "invalid_decision")
                    return
                if decision.action == "deny":
                    self._finish_locked(turn, "denied")
                    return
                if monotonic() >= turn.deadline:
                    self._finish_locked(turn, "timeout")
                    return
                turn.state = "releasing"
                turn.write_started = True  # sink may mutate then raise
                self._sink.publish_text(turn.key, sealed.text)
                turn.result.text_published_at = monotonic()
            await asyncio.sleep(0)
            for chunk in sealed.audio_chunks:
                async with self._lock:
                    if self._turn is not turn or turn.state != "releasing":
                        return
                    if monotonic() >= turn.deadline:
                        self._finish_locked(turn, "timeout")
                        return
                    turn.write_started = True
                    self._sink.enqueue(turn.key, chunk)
                    if turn.result.first_enqueue_at is None:
                        turn.result.first_enqueue_at = monotonic()
                await asyncio.sleep(0)  # let cancellation acquire the same lock
            async with self._lock:
                if self._turn is turn and turn.state == "releasing":
                    self._last_played_key = turn.key
                    self._finish_locked(turn, "allowed")
        except asyncio.CancelledError:
            return
        except TimeoutError:
            async with self._lock:
                if self._turn is turn and turn.state != "finished":
                    self._finish_locked(turn, "timeout")
        except Exception:
            async with self._lock:
                if self._turn is turn and turn.state != "finished":
                    self._finish_locked(
                        turn, "sink_error" if turn.state == "releasing" else "decider_error"
                    )

    async def _expire(self, turn: _Turn) -> None:
        try:
            await asyncio.sleep(max(0.0, turn.deadline - monotonic()))
            async with self._lock:
                if self._turn is turn and turn.state != "finished":
                    self._finish_locked(turn, "timeout")
        except asyncio.CancelledError:
            return

    def _finish_locked(self, turn: _Turn, status: str) -> None:
        if turn.state == "finished":
            return
        turn.state = "finished"
        turn.text_parts.clear()
        turn.audio_chunks.clear()
        if turn.write_started and status != "allowed":
            try:
                self._sink.stop(turn.key)
            except Exception:
                status = "sink_error"
        turn.result.status = status
        turn.result.finished_at = monotonic()
        turn.result.gate_list_payload_bytes_after = sum(
            len(part.encode("utf-8")) for part in turn.text_parts
        ) + sum(map(len, turn.audio_chunks))
        for task in (turn.decision_task, turn.watchdog):
            if task is not None and task is not asyncio.current_task():
                task.cancel()
        turn.result._done.set()

    async def cancel(self) -> None:
        async with self._lifecycle_lock:
            await self._cancel_inside_lifecycle("cancelled")

    async def _cancel_inside_lifecycle(
        self, status: str, *, detach: bool = False, close: bool = False
    ) -> None:
        async with self._lock:
            if close:
                self._closed = True
            turn = self._turn
            if turn is not None:
                self._finish_locked(turn, status)
            if self._last_played_key is not None:
                try:
                    self._sink.stop(self._last_played_key)
                except Exception:
                    if turn is not None:
                        turn.result.status = "sink_error"
                self._last_played_key = None
        await self._join(turn)
        if detach:
            async with self._lock:
                self._turn = None
                if close:
                    self._used_keys.clear()

    async def reset_session(self) -> None:
        async with self._lifecycle_lock:
            await self._cancel_inside_lifecycle("session_changed", detach=True)

    async def close(self) -> None:
        async with self._lifecycle_lock:
            await self._cancel_inside_lifecycle("closed", detach=True, close=True)
