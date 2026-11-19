"""A synthetic provider lifecycle around each projected context snapshot."""

from __future__ import annotations

import asyncio
import math
from dataclasses import replace
from collections.abc import Callable
from collections.abc import AsyncIterator
from time import monotonic
from typing import Protocol

from soul_memory_kernel.privacy.provider_types import ProviderEvent, SessionConfig
from soul_memory_kernel.privacy.controlled_output import TurnKey, TurnResult

from .kernel import ContextSnapshot, PrivacyKernel
from .output import PrivacyOutput


class SyntheticProvider(Protocol):
    async def start_session(self, config: SessionConfig) -> None: ...
    async def send_text(self, text: str) -> None: ...
    def events(self) -> AsyncIterator[ProviderEvent]: ...
    async def end_session(self) -> None: ...


class PrivacySessionError(RuntimeError):
    pass


class PrivacySessionCoordinator:
    """A new provider instance per snapshot, even if the subject stays the same.

    The coordinator never reuses a model context after private material entered
    it. Failed start/end locks the instance; callers must not silently reopen.
    """

    def __init__(
        self,
        kernel: PrivacyKernel,
        output: PrivacyOutput,
        provider_factory: Callable[[], SyntheticProvider],
        *,
        close_timeout_s: float = 2.0,
    ):
        if not isinstance(close_timeout_s, (int, float)) or not math.isfinite(close_timeout_s) or close_timeout_s <= 0:
            raise ValueError("close timeout must be positive")
        self.kernel = kernel
        self.output = output
        self.output._require_coordinator_binding()
        self.provider_factory = provider_factory
        self._provider: SyntheticProvider | None = None
        self._snapshot: ContextSnapshot | None = None
        self._turn_key: TurnKey | None = None
        self._used_providers: list[SyntheticProvider] = []
        self._unclosed_providers: list[SyntheticProvider] = []
        self._pending_tasks: set[asyncio.Task[None]] = set()
        self._faulted = False
        self._closed = False
        self._closing = False
        self._transition_requested = False
        self._run_task: asyncio.Task[TurnResult] | None = None
        self._close_timeout_s = close_timeout_s
        self._lock = asyncio.Lock()

    @property
    def faulted(self) -> bool:
        return self._faulted

    @property
    def active_provider(self) -> SyntheticProvider | None:
        """Only for isolated fake-provider observations and tests."""

        return self._provider

    @property
    def pending_cleanup_tasks(self) -> int:
        return sum(not task.done() for task in self._pending_tasks)

    async def _bounded(self, operation, timeout_s: float | None = None) -> None:
        task = asyncio.create_task(operation)
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout_s or self._close_timeout_s)
        except BaseException:
            task.cancel()
            await asyncio.wait({task}, timeout=self._close_timeout_s)
            if not task.done():
                self._pending_tasks.add(task)
                task.add_done_callback(self._pending_tasks.discard)
            elif not task.cancelled():
                task.exception()  # mark cleanup faults retrieved
            raise

    async def open(self, snapshot: ContextSnapshot) -> None:
        # A prior finished turn may still have a decision pending. Revoke its
        # output before waiting for the lifecycle lock.
        if self._snapshot is not None:
            await self._preempt_active_run()
        async with self._lock:
            if self._closed or self._closing or self._faulted or self._provider is not None:
                raise PrivacySessionError("coordinator unavailable")
            if self._snapshot is not None:
                await self.output.invalidate(self._snapshot.session_id)
                self._snapshot = None
                self.output._bind(None)
            self._transition_requested = False
            await self._start(snapshot)

    async def _preempt_active_run(self) -> None:
        """Immediately seal old authority, then cancel/join its provider pump."""

        snapshot = self._snapshot
        if snapshot is not None:
            self.kernel.rotate_session(snapshot.session_id)
            self.output._bind(None)
        task = self._run_task
        if task is not None and task is not asyncio.current_task() and not task.done():
            self._transition_requested = True
            task.cancel()
            await asyncio.wait({task}, timeout=self._close_timeout_s)
            if not task.done():
                self._faulted = True
                raise PrivacySessionError("old provider turn did not stop")

    async def _start(self, snapshot: ContextSnapshot) -> None:
        if not self.kernel.can_send_provider(snapshot):
            raise PermissionError("provider transmission denied")
        texts = self.kernel.snapshot_text(snapshot)
        try:
            provider = self.provider_factory()
        except BaseException as error:
            self._faulted = True
            self.kernel.rotate_session(snapshot.session_id)
            raise PrivacySessionError("synthetic provider factory failed") from error
        if any(provider is used for used in self._used_providers):
            self._faulted = True
            raise PrivacySessionError("provider instance reused")
        self._used_providers.append(provider)
        try:
            await self._bounded(provider.start_session(SessionConfig(instructions="\n".join(texts))))
        except BaseException as error:
            self._faulted = True
            self.kernel.rotate_session(snapshot.session_id)
            try:
                await self._bounded(provider.end_session())
            except BaseException:
                self._unclosed_providers.append(provider)
            raise PrivacySessionError("synthetic provider start failed") from error
        self._provider = provider
        self._snapshot = snapshot
        self.output._bind(snapshot)

    async def begin_turn(self, turn_id: str, output_generation: str) -> tuple[TurnKey, TurnResult]:
        async with self._lock:
            if self._closed or self._closing or self._faulted or self._provider is None or self._snapshot is None:
                raise PrivacySessionError("no active synthetic provider")
            if self._turn_key is not None:
                raise PrivacySessionError("finish or change the active turn first")
            snapshot = self._snapshot
            key = TurnKey(snapshot.session_id, turn_id, snapshot.snapshot_id, output_generation)
            result = await self.output.begin(snapshot, key)
            self._turn_key = key
            return key, result

    async def ingest_from_provider(
        self, provider: SyntheticProvider, key: TurnKey, event: ProviderEvent
    ) -> bool:
        if (
            self._closed
            or self._closing
            or self._faulted
            or provider is not self._provider
            or key != self._turn_key
        ):
            return False
        accepted = await self.output.ingest(key, event)
        if event.kind in ("agent_turn_completed", "error"):
            self._turn_key = None
        return accepted

    async def change(self, snapshot: ContextSnapshot) -> None:
        """Stop old output, end old provider, then start a fresh one."""

        await self._preempt_active_run()
        async with self._lock:
            if self._closed or self._closing or self._faulted:
                raise PrivacySessionError("no active synthetic provider")
            if self._provider is None and self._transition_requested:
                self._transition_requested = False
                await self._start(snapshot)
                return
            if self._provider is None or self._snapshot is None:
                raise PrivacySessionError("no active synthetic provider")
            old_provider, old_snapshot = self._provider, self._snapshot
            self._provider = None
            self._snapshot = None
            self._turn_key = None
            self.output._bind(None)
            invalidate_error: BaseException | None = None
            try:
                await self.output.invalidate(old_snapshot.session_id)
            except BaseException as error:
                invalidate_error = error
            try:
                await self._bounded(old_provider.end_session())
            except BaseException as error:
                self._faulted = True
                self._unclosed_providers.append(old_provider)
                raise PrivacySessionError("old synthetic provider did not close") from error
            if invalidate_error is not None:
                self._faulted = True
                raise PrivacySessionError("old output did not stop") from invalidate_error
            await self._start(snapshot)

    async def run_turn(
        self,
        prompt: str,
        turn_id: str,
        output_generation: str,
        *,
        event_timeout_s: float = 30.0,
    ) -> TurnResult:
        """Bind one provider stream to one snapshot; close before releasing 359.

        Only this combined path can substantiate provider-originated output.
        Older caller-supplied ingest methods remain for isolated fake tests.
        """

        if (
            not isinstance(prompt, str)
            or not prompt
            or not isinstance(event_timeout_s, (int, float))
            or not math.isfinite(event_timeout_s)
            or event_timeout_s <= 0
        ):
            raise ValueError("synthetic prompt and positive timeout required")
        async with self._lock:
            if self._closed or self._closing or self._faulted or self._provider is None or self._snapshot is None:
                raise PrivacySessionError("no active synthetic provider")
            provider, snapshot = self._provider, self._snapshot
            key = TurnKey(snapshot.session_id, turn_id, snapshot.snapshot_id, output_generation)
            if self._turn_key is not None:
                raise PrivacySessionError("active turn already exists")
            result = await self.output.begin(snapshot, key)
            self._turn_key = key
            self._run_task = asyncio.current_task()
            stream = None
            try:
                if not self.kernel.can_send_provider(snapshot):
                    raise PermissionError("provider transmission denied")
                await self._bounded(provider.send_text(prompt), event_timeout_s)
                stream = provider.events()
                deadline = monotonic() + event_timeout_s
                complete_event: ProviderEvent | None = None
                for _ in range(1024):
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise TimeoutError("provider response timed out")
                    event = await asyncio.wait_for(anext(stream), timeout=remaining)
                    if event.kind == "agent_turn_completed":
                        complete_event = replace(event, output_generation=key.output_generation)
                        break
                    if event.kind == "error":
                        raise PrivacySessionError("provider error event")
                    if event.kind in ("agent_transcript", "agent_audio_delta"):
                        if not await self.output.ingest(
                            key, replace(event, output_generation=key.output_generation)
                        ):
                            raise PrivacySessionError("invalid or over-limit provider output")
                if complete_event is None:
                    raise PrivacySessionError("provider event limit reached")
                if hasattr(stream, "aclose"):
                    await self._bounded(stream.aclose())
                    stream = None
                await self._bounded(provider.end_session())
                self._provider = None
                self._turn_key = None
                if not await self.output.ingest(key, complete_event):
                    raise PrivacySessionError("incomplete provider output")
                return result
            except BaseException as error:
                self._turn_key = None
                self._provider = None
                self.output._bind(None)
                cleanup_failed = False
                try:
                    await self.output.invalidate(snapshot.session_id)
                except BaseException:
                    cleanup_failed = True
                if stream is not None and hasattr(stream, "aclose"):
                    try:
                        await self._bounded(stream.aclose())
                    except BaseException:
                        cleanup_failed = True
                try:
                    await self._bounded(provider.end_session())
                except BaseException:
                    self._unclosed_providers.append(provider)
                    cleanup_failed = True
                if isinstance(error, asyncio.CancelledError) and self._transition_requested and not cleanup_failed:
                    self._snapshot = None
                    raise PrivacySessionError("synthetic turn cancelled for transition") from error
                self._faulted = True
                raise PrivacySessionError("synthetic provider turn failed") from error
            finally:
                self._run_task = None

    async def close(self) -> None:
        await self._preempt_active_run()
        async with self._lock:
            if self._closed:
                return
            self._closing = True
            provider, snapshot = self._provider, self._snapshot
            self._provider = None
            self._snapshot = None
            self._turn_key = None
            self.output._bind(None)
            errors: list[BaseException] = []
            if snapshot is not None:
                try:
                    await self.output.invalidate(snapshot.session_id)
                except BaseException as error:
                    errors.append(error)
            for task in tuple(self._pending_tasks):
                task.cancel()
            if self._pending_tasks:
                await asyncio.wait(self._pending_tasks, timeout=self._close_timeout_s)
            if self.pending_cleanup_tasks:
                errors.append(TimeoutError("provider cleanup task did not stop"))
            providers = list(self._unclosed_providers)
            if provider is not None:
                self._unclosed_providers.append(provider)
                providers.append(provider)
            for pending_provider in providers:
                try:
                    if self.pending_cleanup_tasks:
                        raise TimeoutError("prior provider close still active")
                    await self._bounded(pending_provider.end_session())
                except BaseException as error:
                    errors.append(error)
                else:
                    self._unclosed_providers = [
                        item for item in self._unclosed_providers if item is not pending_provider
                    ]
            try:
                await self.output.close()
            except BaseException as error:
                errors.append(error)
            if errors:
                self._faulted = True
                raise PrivacySessionError("synthetic provider close failed") from errors[0]
            self._closed = True
