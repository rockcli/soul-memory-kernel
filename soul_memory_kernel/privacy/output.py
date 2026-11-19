"""Synthetic output experiment: one policy for text and PCM at the final sink."""

from __future__ import annotations

from soul_memory_kernel.privacy.provider_types import ProviderEvent
from soul_memory_kernel.privacy.controlled_output import (
    ControlledOutputGate,
    Decider,
    Decision,
    Limits,
    PlaybackSink,
    SealedOutput,
    TurnKey,
    TurnResult,
)

from .kernel import ContextSnapshot, PrivacyKernel


class _PolicyDecider:
    def __init__(self, owner: PrivacyOutput, delegate: Decider):
        self.owner = owner
        self.delegate = delegate

    async def decide(self, output: SealedOutput) -> Decision:
        snapshot = self.owner._snapshots.get(output.key)
        if snapshot is None or not self.owner._can_release(snapshot):
            return Decision(output.key, output.digest, "deny")
        decision = await self.delegate.decide(output)
        if not self.owner._can_release(snapshot):
            return Decision(output.key, output.digest, "deny")
        return decision


class _PolicySink:
    def __init__(self, owner: PrivacyOutput, delegate: PlaybackSink):
        self.owner = owner
        self.delegate = delegate

    def _check(self, key: TurnKey) -> None:
        snapshot = self.owner._snapshots.get(key)
        if snapshot is None or not self.owner._can_release(snapshot):
            raise PermissionError("output authority expired")

    def publish_text(self, key: TurnKey, text: str) -> None:
        self._check(key)
        self.delegate.publish_text(key, text)

    def enqueue(self, key: TurnKey, pcm16: bytes) -> None:
        self._check(key)
        self.delegate.enqueue(key, pcm16)

    def stop(self, key: TurnKey) -> None:
        self.delegate.stop(key)


class PrivacyOutput:
    """Default-off gate wrapper. No model semantics or real speaker control."""

    def __init__(
        self,
        kernel: PrivacyKernel,
        sink: PlaybackSink,
        decider: Decider,
        limits: Limits = Limits(),
    ):
        self.kernel = kernel
        self._snapshots: dict[TurnKey, ContextSnapshot] = {}
        self._requires_binding = False
        self._bound_snapshot: ContextSnapshot | None = None
        self._gate = ControlledOutputGate(_PolicyDecider(self, decider), _PolicySink(self, sink), limits)

    def _require_coordinator_binding(self) -> None:
        self._requires_binding = True

    def _bind(self, snapshot: ContextSnapshot | None) -> None:
        self._bound_snapshot = snapshot

    @property
    def pending_tasks(self) -> int:
        return self._gate.pending_tasks

    def _can_release(self, snapshot: ContextSnapshot) -> bool:
        return (not self._requires_binding or self._bound_snapshot is snapshot) and self.kernel.speak_to_audience(snapshot, snapshot.audience_id, "publish_text") and self.kernel.speak_to_audience(
            snapshot, snapshot.audience_id, "play_audio"
        )

    async def begin(self, snapshot: ContextSnapshot, key: TurnKey) -> TurnResult:
        if (
            key.session_id != snapshot.session_id
            or key.content_version != snapshot.snapshot_id
            or not self._can_release(snapshot)
        ):
            raise PermissionError("output snapshot is not authorized")
        self._snapshots[key] = snapshot
        try:
            return await self._gate.begin(key)
        except BaseException:
            self._snapshots.pop(key, None)
            raise

    async def ingest(self, key: TurnKey, event: ProviderEvent) -> bool:
        return await self._gate.ingest(key, event)

    async def invalidate(self, session_id: str) -> None:
        """Revoke the old epoch first, then stop and join gate tasks."""

        self.kernel.rotate_session(session_id)
        await self._gate.reset_session()
        self._snapshots = {
            key: snapshot for key, snapshot in self._snapshots.items() if key.session_id != session_id
        }

    async def close(self) -> None:
        self._bound_snapshot = None
        for session_id in {key.session_id for key in self._snapshots}:
            self.kernel.rotate_session(session_id)
        await self._gate.close()
        self._snapshots.clear()
