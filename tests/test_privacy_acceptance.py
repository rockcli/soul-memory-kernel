"""Independent acceptance counterexamples for the default-off privacy prototype.

All people, records, and provider events here are synthetic. These tests exercise
the public kernel, coordinator and output interfaces, not their private stores.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from soul_memory_kernel.privacy.provider_types import ProviderEvent
from soul_memory_kernel.privacy.kernel import FixtureGrant, PrivacyKernel, Record, SpeakerObservation
from soul_memory_kernel.privacy.output import PrivacyOutput
from soul_memory_kernel.privacy.session import PrivacySessionCoordinator, PrivacySessionError
from soul_memory_kernel.privacy.controlled_output import Decision, Limits, TurnKey


ALL_ACTIONS = frozenset({"read_model", "send_provider", "publish_text", "play_audio"})
CHILD_AUDIENCE = "member:child"


def make_kernel(now: list[float] | None = None) -> PrivacyKernel:
    now = now if now is not None else [100.0]
    return PrivacyKernel(enabled=True, clock=lambda: now[0])


def add_record(
    kernel: PrivacyKernel,
    record_id: str = "child-note",
    *,
    owner: str = "child",
    audience: str = CHILD_AUDIENCE,
    scope: str = "PERSONAL",
    content: str = "SYNTHETIC_CHILD_PRIVATE_NOTE",
    actions: frozenset[str] = ALL_ACTIONS,
    sources: tuple[str, ...] = (),
    version: int = 1,
) -> Record:
    record = Record(record_id, owner, scope, content, frozenset({audience}), actions, sources, version)
    kernel.add_record(record)
    return record


def issue(
    kernel: PrivacyKernel,
    *,
    grant_id: str = "fixture-child",
    session: str = "child-session",
    subject: str = "child",
    owner: str = "child",
    audience: str = CHILD_AUDIENCE,
    actions: frozenset[str] = ALL_ACTIONS,
    resources: frozenset[str] = frozenset({"child-note"}),
    versions: tuple[tuple[str, int], ...] = (("child-note", 1),),
    expiry: float = 200.0,
    version: int = 1,
) -> FixtureGrant:
    grant = FixtureGrant(
        grant_id, session, subject, owner, audience, actions, resources,
        expiry, version, consent_versions=versions,
    )
    kernel.issue_fixture_grant(grant)
    return grant


def authorized_snapshot(
    *,
    now: list[float] | None = None,
    actions: frozenset[str] = ALL_ACTIONS,
):
    kernel = make_kernel(now)
    add_record(kernel, actions=actions)
    issue(kernel, actions=actions)
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    return kernel, kernel.read_for_model(lease, ("child-note",))


class Sink:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.pcm: list[bytes] = []
        self.stops: list[TurnKey] = []
        self.on_text = None

    def publish_text(self, key: TurnKey, text: str) -> None:
        self.texts.append(text)
        if self.on_text is not None:
            self.on_text()

    def enqueue(self, key: TurnKey, pcm16: bytes) -> None:
        self.pcm.append(pcm16)

    def stop(self, key: TurnKey) -> None:
        self.stops.append(key)


class HeldDecider:
    def __init__(self) -> None:
        self.called = asyncio.Event()
        self.release = asyncio.Event()

    async def decide(self, output):
        self.called.set()
        await self.release.wait()
        return Decision(output.key, output.digest, "allow")


class FakeProvider:
    def __init__(self, name: str, timeline: list[str], *, fail_end: bool = False):
        self.name = name
        self.timeline = timeline
        self.config = None
        self.end_started = asyncio.Event()
        self.end_release = asyncio.Event()
        self.end_release.set()
        self.fail_end = fail_end

    async def start_session(self, config):
        self.config = config
        self.timeline.append(f"start:{self.name}")

    async def end_session(self):
        self.timeline.append(f"end-start:{self.name}")
        self.end_started.set()
        await self.end_release.wait()
        if self.fail_end:
            raise RuntimeError("synthetic close failure")
        self.timeline.append(f"end-done:{self.name}")


class StreamProvider(FakeProvider):
    def __init__(self, name: str, timeline: list[str], *, fail_end: bool = False):
        super().__init__(name, timeline, fail_end=fail_end)
        self.queue: asyncio.Queue[ProviderEvent] = asyncio.Queue()
        self.sent: list[str] = []

    async def send_text(self, text: str) -> None:
        self.sent.append(text)
        self.timeline.append(f"send:{self.name}")

    async def events(self):
        while True:
            yield await self.queue.get()


def put_complete_stream(provider: StreamProvider, *, text: str = "SYNTHETIC_STREAM_REPLY"):
    provider.queue.put_nowait(ProviderEvent(kind="agent_transcript", text=text))
    provider.queue.put_nowait(ProviderEvent(kind="agent_audio_delta", audio=b"\x01\x00"))
    provider.queue.put_nowait(ProviderEvent(kind="agent_transcript", text="", is_final=True))
    provider.queue.put_nowait(ProviderEvent(kind="agent_turn_completed"))


def event(kind: str, key: TurnKey, *, text=None, audio=None, final=False):
    return ProviderEvent(
        kind=kind, text=text, audio=audio, is_final=final,
        output_generation=key.output_generation,
    )


async def seal(output: PrivacyOutput, key: TurnKey):
    assert await output.ingest(key, event("agent_transcript", key, text="SYNTHETIC_REPLY"))
    assert await output.ingest(key, event("agent_audio_delta", key, audio=b"\x01\x00"))
    assert await output.ingest(key, event("agent_transcript", key, text="", final=True))
    assert await output.ingest(key, event("agent_turn_completed", key))


def test_owner_positive_and_unknown_voice_cannot_supply_authority():
    kernel, snapshot = authorized_snapshot()
    assert kernel.snapshot_text(snapshot) == ("SYNTHETIC_CHILD_PRIVATE_NOTE",)
    assert kernel.can_send_provider(snapshot)
    assert kernel.speak_to_audience(snapshot, CHILD_AUDIENCE, "publish_text")
    assert kernel.speak_to_audience(snapshot, CHILD_AUDIENCE, "play_audio")
    assert not kernel.speak_to_audience(snapshot, "public_room", "play_audio")

    for observation in (
        SpeakerObservation(),
        SpeakerObservation(candidate_id="child", score=0.99, state="candidate"),
    ):
        with pytest.raises(PermissionError):
            kernel.open_session("guest-session", "guest", CHILD_AUDIENCE, "fixture-child", observation)
    with pytest.raises(PermissionError):
        kernel.open_session("child-session", "other-owner", CHILD_AUDIENCE, "fixture-child")


def test_empty_wrong_session_expired_revoked_and_bad_clock_deny():
    with pytest.raises(ValueError):
        Record("empty", "child", "PERSONAL", "SYNTHETIC", frozenset({CHILD_AUDIENCE}), frozenset())
    with pytest.raises(ValueError):
        FixtureGrant("empty", "s", "child", "child", CHILD_AUDIENCE,
                     frozenset(), frozenset({"child-note"}), 200.0)
    disabled = PrivacyKernel()
    with pytest.raises(PermissionError):
        disabled.open_session("s", "child", CHILD_AUDIENCE, "missing")
    kernel = make_kernel()
    add_record(kernel)
    with pytest.raises(PermissionError):
        kernel.open_session("child-session", "child", CHILD_AUDIENCE, "missing")
    issue(kernel)
    with pytest.raises(PermissionError):
        kernel.open_session("wrong-session", "child", CHILD_AUDIENCE, "fixture-child")
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    snapshot = kernel.read_for_model(lease, ("child-note",))
    kernel.revoke_grant("fixture-child")
    assert not kernel.can_send_provider(snapshot)
    assert not kernel.speak_to_audience(snapshot, CHILD_AUDIENCE, "publish_text")
    with pytest.raises(PermissionError):
        kernel.snapshot_text(snapshot)

    for bad_clock in (
        lambda: float("nan"), lambda: float("inf"),
        lambda: (_ for _ in ()).throw(RuntimeError("clock")),
    ):
        broken = PrivacyKernel(enabled=True, clock=bad_clock)
        add_record(broken)
        issue(broken)
        with pytest.raises(PermissionError):
            broken.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")


def test_exact_consent_version_and_independent_provider_and_speaker_actions():
    kernel = make_kernel()
    add_record(kernel, version=2)
    issue(kernel, version=99, versions=(("child-note", 1),))
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    with pytest.raises(PermissionError):
        kernel.read_for_model(lease, ("child-note",))

    kernel = make_kernel()
    add_record(kernel)
    issue(kernel, versions=())
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    with pytest.raises(PermissionError):
        kernel.read_for_model(lease, ("child-note",))

    kernel = make_kernel()
    add_record(kernel)
    issue(kernel, actions=frozenset({"read_model"}))
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    snapshot = kernel.read_for_model(lease, ("child-note",))
    assert not kernel.can_send_provider(snapshot)
    assert not kernel.speak_to_audience(snapshot, CHILD_AUDIENCE, "publish_text")
    assert not kernel.speak_to_audience(snapshot, CHILD_AUDIENCE, "play_audio")


@pytest.mark.asyncio
async def test_read_permission_alone_never_starts_provider():
    kernel = make_kernel()
    add_record(kernel)
    issue(kernel, actions=frozenset({"read_model"}))
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    snapshot = kernel.read_for_model(lease, ("child-note",))
    created: list[FakeProvider] = []

    def factory():
        provider = FakeProvider("unexpected", [])
        created.append(provider)
        return provider

    coordinator = PrivacySessionCoordinator(kernel, PrivacyOutput(kernel, Sink(), HeldDecider()), factory)
    with pytest.raises(PermissionError):
        await coordinator.open(snapshot)
    assert created == []
    await coordinator.close()


def test_named_family_member_positive_but_public_room_and_guest_denied():
    kernel = make_kernel()
    add_record(kernel, "family-note", scope="FAMILY", audience="member:dad", content="SYNTHETIC_FAMILY")
    issue(kernel, grant_id="dad-grant", session="dad-session", subject="dad", audience="member:dad",
          resources=frozenset({"family-note"}), versions=(("family-note", 1),))
    lease = kernel.open_session("dad-session", "dad", "member:dad", "dad-grant")
    snapshot = kernel.read_for_model(lease, ("family-note",))
    assert kernel.snapshot_text(snapshot) == ("SYNTHETIC_FAMILY",)
    assert kernel.speak_to_audience(snapshot, "member:dad", "play_audio")
    assert not kernel.speak_to_audience(snapshot, "public_room", "publish_text")
    for who, audience in (("guest", "member:dad"), ("dad", "public_room")):
        with pytest.raises(PermissionError):
            kernel.open_session("dad-session", who, audience, "dad-grant")


def test_derived_record_requires_every_actual_source_and_rejects_forgery():
    kernel = make_kernel()
    add_record(kernel, "base", content="SYNTHETIC_BASE")
    add_record(kernel, "summary", content="SYNTHETIC_SUMMARY", sources=("base",))
    issue(kernel, resources=frozenset({"summary"}), versions=(("summary", 1),))
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    with pytest.raises(PermissionError):
        kernel.read_for_model(lease, ("summary",))

    kernel = make_kernel()
    add_record(kernel, "base", content="SYNTHETIC_BASE")
    add_record(kernel, "summary", content="SYNTHETIC_SUMMARY", sources=("base",))
    issue(kernel, resources=frozenset({"summary", "base"}),
          versions=(("base", 1), ("summary", 1)))
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    snapshot = kernel.read_for_model(lease, ("summary",))
    assert set(snapshot.source_ids) == {"base", "summary"}
    assert kernel.can_send_provider(snapshot)
    forged = replace(snapshot, source_ids=("summary",))
    assert not kernel.can_send_provider(forged)
    assert not kernel.speak_to_audience(forged, CHILD_AUDIENCE, "publish_text")
    with pytest.raises(PermissionError):
        kernel.snapshot_text(forged)
    forged_content = replace(snapshot, texts=("FORGED_PRIVATE_CONTENT",))
    assert not kernel.can_send_provider(forged_content)
    with pytest.raises(PermissionError):
        kernel.snapshot_text(forged_content)

    missing = make_kernel()
    add_record(missing, "summary", sources=("absent",))
    issue(missing, resources=frozenset({"summary", "absent"}),
          versions=(("absent", 1), ("summary", 1)))
    lease = missing.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    with pytest.raises(PermissionError):
        missing.read_for_model(lease, ("summary",))

    cyclic = make_kernel()
    add_record(cyclic, "a", sources=("b",))
    add_record(cyclic, "b", sources=("a",))
    issue(cyclic, resources=frozenset({"a", "b"}), versions=(("a", 1), ("b", 1)))
    lease = cyclic.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    with pytest.raises(PermissionError):
        cyclic.read_for_model(lease, ("a",))


def test_guessed_record_id_and_cross_owner_source_do_not_inherit_child_grant():
    kernel = make_kernel()
    add_record(kernel, "child-note")
    add_record(kernel, "other-note", owner="other", content="SYNTHETIC_OTHER_PRIVATE")
    add_record(kernel, "summary", content="SYNTHETIC_MIXED_SUMMARY", sources=("child-note", "other-note"))
    issue(kernel, resources=frozenset({"child-note", "other-note", "summary"}),
          versions=(("child-note", 1), ("other-note", 1), ("summary", 1)))
    lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    assert kernel.snapshot_text(kernel.read_for_model(lease, ("child-note",))) == (
        "SYNTHETIC_CHILD_PRIVATE_NOTE",
    )
    for requested in (("other-note",), ("summary",), ("guessed-missing-id",)):
        with pytest.raises(PermissionError):
            kernel.read_for_model(lease, requested)


@pytest.mark.asyncio
async def test_provider_start_receives_only_new_authorized_snapshot_after_change():
    kernel = make_kernel()
    add_record(kernel, "old-private", content="SYNTHETIC_OLD_PRIVATE")
    issue(kernel, resources=frozenset({"old-private"}), versions=(("old-private", 1),))
    old_lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    old_snapshot = kernel.read_for_model(old_lease, ("old-private",))

    add_record(kernel, "guest-public", owner="guest", audience="public_room", scope="FAMILY",
               content="SYNTHETIC_PUBLIC")
    issue(kernel, grant_id="guest-grant", session="guest-session", subject="guest", owner="guest",
          audience="public_room", resources=frozenset({"guest-public"}),
          versions=(("guest-public", 1),))
    guest_lease = kernel.open_session("guest-session", "guest", "public_room", "guest-grant")
    guest_snapshot = kernel.read_for_model(guest_lease, ("guest-public",))

    timeline: list[str] = []
    providers: list[FakeProvider] = []

    def factory():
        provider = FakeProvider(str(len(providers)), timeline)
        providers.append(provider)
        return provider

    output = PrivacyOutput(kernel, Sink(), HeldDecider())
    coordinator = PrivacySessionCoordinator(kernel, output, factory)
    await coordinator.open(old_snapshot)
    assert providers[0].config.instructions == "SYNTHETIC_OLD_PRIVATE"
    await coordinator.change(guest_snapshot)
    assert timeline == ["start:0", "end-start:0", "end-done:0", "start:1"]
    assert providers[1].config.instructions == "SYNTHETIC_PUBLIC"
    assert "SYNTHETIC_OLD_PRIVATE" not in providers[1].config.instructions
    assert not kernel.can_send_provider(old_snapshot)
    await coordinator.close()


@pytest.mark.asyncio
async def test_provider_close_pending_or_failed_never_starts_new_provider():
    kernel, old_snapshot = authorized_snapshot()
    add_record(kernel, "new-note", content="SYNTHETIC_NEW")
    issue(kernel, grant_id="new-grant", session="new-session", resources=frozenset({"new-note"}),
          versions=(("new-note", 1),))
    new_lease = kernel.open_session("new-session", "child", CHILD_AUDIENCE, "new-grant")
    new_snapshot = kernel.read_for_model(new_lease, ("new-note",))
    timeline: list[str] = []
    providers: list[FakeProvider] = []

    def factory():
        provider = FakeProvider(str(len(providers)), timeline)
        providers.append(provider)
        return provider

    coordinator = PrivacySessionCoordinator(kernel, PrivacyOutput(kernel, Sink(), HeldDecider()), factory)
    await coordinator.open(old_snapshot)
    providers[0].end_release.clear()
    change = asyncio.create_task(coordinator.change(new_snapshot))
    await asyncio.wait_for(providers[0].end_started.wait(), 1)
    assert timeline == ["start:0", "end-start:0"]
    assert len(providers) == 1
    providers[0].fail_end = True
    providers[0].end_release.set()
    with pytest.raises(PrivacySessionError):
        await asyncio.wait_for(change, 1)
    assert coordinator.faulted and len(providers) == 1
    with pytest.raises(PrivacySessionError):
        await coordinator.open(new_snapshot)
    with pytest.raises(PrivacySessionError):
        await coordinator.close()


@pytest.mark.asyncio
async def test_provider_identity_binds_output_snapshot_and_rejects_old_provider_laundering():
    kernel = make_kernel()
    add_record(kernel, "private-a", content="SYNTHETIC_PRIVATE_A")
    issue(kernel, resources=frozenset({"private-a"}), versions=(("private-a", 1),))
    a_lease = kernel.open_session("child-session", "child", CHILD_AUDIENCE, "fixture-child")
    a_snapshot = kernel.read_for_model(a_lease, ("private-a",))

    add_record(kernel, "public-b", owner="guest", audience="public_room", scope="FAMILY",
               content="SYNTHETIC_PUBLIC_B")
    issue(kernel, grant_id="guest-grant", session="guest-session", subject="guest", owner="guest",
          audience="public_room", resources=frozenset({"public-b"}),
          versions=(("public-b", 1),))
    b_lease = kernel.open_session("guest-session", "guest", "public_room", "guest-grant")
    b_snapshot = kernel.read_for_model(b_lease, ("public-b",))

    providers: list[FakeProvider] = []

    def factory():
        provider = FakeProvider(str(len(providers)), [])
        providers.append(provider)
        return provider

    sink, decider = Sink(), HeldDecider()
    output = PrivacyOutput(kernel, sink, decider)
    coordinator = PrivacySessionCoordinator(kernel, output, factory)
    await coordinator.open(a_snapshot)
    a_key, _ = await coordinator.begin_turn("a-turn", "a-generation")
    assert a_key.content_version == a_snapshot.snapshot_id
    old_provider = providers[0]
    assert await coordinator.ingest_from_provider(
        old_provider, a_key, event("agent_transcript", a_key, text="SYNTHETIC_PRIVATE_A_RESPONSE")
    )
    await coordinator.change(b_snapshot)
    b_key, b_result = await coordinator.begin_turn("b-turn", "b-generation")
    assert b_key.content_version == b_snapshot.snapshot_id
    assert not await coordinator.ingest_from_provider(
        old_provider, b_key, event("agent_transcript", b_key, text="LAUNDERED_A")
    )
    assert not await coordinator.ingest_from_provider(
        old_provider, a_key, event("agent_audio_delta", a_key, audio=b"\x01\x00")
    )
    assert sink.texts == [] and sink.pcm == []
    current_provider = providers[1]
    assert await coordinator.ingest_from_provider(
        current_provider, b_key, event("agent_transcript", b_key, text="SYNTHETIC_PUBLIC_B_RESPONSE")
    )
    assert await coordinator.ingest_from_provider(
        current_provider, b_key, event("agent_audio_delta", b_key, audio=b"\x02\x00")
    )
    assert await coordinator.ingest_from_provider(
        current_provider, b_key, event("agent_transcript", b_key, text="", final=True)
    )
    assert await coordinator.ingest_from_provider(
        current_provider, b_key, event("agent_turn_completed", b_key)
    )
    decider.release.set()
    await asyncio.wait_for(b_result.wait(), 1)
    assert b_result.status == "allowed"
    assert sink.texts == ["SYNTHETIC_PUBLIC_B_RESPONSE"] and sink.pcm == [b"\x02\x00"]
    await coordinator.close()


@pytest.mark.asyncio
async def test_unfinished_provider_close_times_out_and_fails_closed():
    kernel, old_snapshot = authorized_snapshot()
    add_record(kernel, "new-note", content="SYNTHETIC_NEW")
    issue(kernel, grant_id="new-grant", session="new-session", resources=frozenset({"new-note"}),
          versions=(("new-note", 1),))
    new_lease = kernel.open_session("new-session", "child", CHILD_AUDIENCE, "new-grant")
    new_snapshot = kernel.read_for_model(new_lease, ("new-note",))
    providers: list[FakeProvider] = []

    def factory():
        provider = FakeProvider(str(len(providers)), [])
        providers.append(provider)
        return provider

    coordinator = PrivacySessionCoordinator(
        kernel, PrivacyOutput(kernel, Sink(), HeldDecider()), factory, close_timeout_s=0.02
    )
    await coordinator.open(old_snapshot)
    providers[0].end_release.clear()
    with pytest.raises(PrivacySessionError):
        await asyncio.wait_for(coordinator.change(new_snapshot), 1)
    assert coordinator.faulted and len(providers) == 1
    with pytest.raises(PrivacySessionError):
        await coordinator.open(new_snapshot)
    with pytest.raises(PrivacySessionError):
        await asyncio.wait_for(coordinator.close(), 1)


@pytest.mark.asyncio
async def test_provider_factory_cannot_reuse_previously_closed_session_instance():
    kernel, old_snapshot = authorized_snapshot()
    add_record(kernel, "new-note", content="SYNTHETIC_NEW")
    issue(kernel, grant_id="new-grant", session="new-session", resources=frozenset({"new-note"}),
          versions=(("new-note", 1),))
    new_lease = kernel.open_session("new-session", "child", CHILD_AUDIENCE, "new-grant")
    new_snapshot = kernel.read_for_model(new_lease, ("new-note",))
    provider = FakeProvider("same-instance", [])
    coordinator = PrivacySessionCoordinator(
        kernel, PrivacyOutput(kernel, Sink(), HeldDecider()), lambda: provider
    )
    await coordinator.open(old_snapshot)
    with pytest.raises(PrivacySessionError):
        await coordinator.change(new_snapshot)
    assert coordinator.faulted
    assert provider.config.instructions != "SYNTHETIC_NEW"
    await coordinator.close()


@pytest.mark.asyncio
async def test_combined_provider_stream_releases_only_after_successful_close():
    kernel, snapshot = authorized_snapshot()
    timeline: list[str] = []
    provider = StreamProvider("stream", timeline)
    sink, decider = Sink(), HeldDecider()
    sink.on_text = lambda: timeline.append("publish-text")
    decider.release.set()
    coordinator = PrivacySessionCoordinator(
        kernel, PrivacyOutput(kernel, sink, decider, Limits(max_wait_s=2)),
        lambda: provider,
    )
    await coordinator.open(snapshot)
    put_complete_stream(provider)
    result = await coordinator.run_turn("SYNTHETIC_PROMPT", "turn-1", "generation-1")
    await asyncio.wait_for(result.wait(), 1)
    assert result.status == "allowed"
    assert provider.sent == ["SYNTHETIC_PROMPT"]
    assert timeline.index("end-done:stream") < timeline.index("publish-text")
    assert sink.texts == ["SYNTHETIC_STREAM_REPLY"] and sink.pcm == [b"\x01\x00"]
    await coordinator.close()


@pytest.mark.asyncio
async def test_combined_stream_close_failure_never_releases_text_or_pcm():
    kernel, snapshot = authorized_snapshot()
    provider = StreamProvider("stream", [], fail_end=True)
    sink, decider = Sink(), HeldDecider()
    decider.release.set()
    coordinator = PrivacySessionCoordinator(kernel, PrivacyOutput(kernel, sink, decider), lambda: provider)
    await coordinator.open(snapshot)
    put_complete_stream(provider)
    with pytest.raises(PrivacySessionError):
        await coordinator.run_turn("SYNTHETIC_PROMPT", "turn-1", "generation-1")
    assert coordinator.faulted and sink.texts == [] and sink.pcm == []
    with pytest.raises(PrivacySessionError):
        await coordinator.close()


@pytest.mark.asyncio
async def test_close_requested_during_stream_invalidates_old_reply_before_release():
    kernel, snapshot = authorized_snapshot()
    provider = StreamProvider("stream", [])
    sink, decider = Sink(), HeldDecider()
    decider.release.set()
    coordinator = PrivacySessionCoordinator(
        kernel, PrivacyOutput(kernel, sink, decider, Limits(max_wait_s=2)),
        lambda: provider,
    )
    await coordinator.open(snapshot)
    turn = asyncio.create_task(coordinator.run_turn("SYNTHETIC_PROMPT", "turn-1", "generation-1"))
    for _ in range(10):
        if provider.sent:
            break
        await asyncio.sleep(0)
    assert provider.sent
    closing = asyncio.create_task(coordinator.close())
    await asyncio.sleep(0)
    put_complete_stream(provider)
    try:
        await asyncio.wait_for(turn, 1)
    except PrivacySessionError:
        pass
    await asyncio.wait_for(closing, 1)
    assert sink.texts == [] and sink.pcm == []


@pytest.mark.asyncio
@pytest.mark.parametrize("expire", [False, True])
async def test_expiry_or_revocation_while_decider_waits_releases_neither_text_nor_pcm(expire):
    now = [100.0]
    kernel, snapshot = authorized_snapshot(now=now)
    sink, decider = Sink(), HeldDecider()
    output = PrivacyOutput(kernel, sink, decider)
    key = TurnKey(snapshot.session_id, "turn-1", snapshot.snapshot_id, "generation-1")
    result = await output.begin(snapshot, key)
    await seal(output, key)
    await asyncio.wait_for(decider.called.wait(), 1)
    assert sink.texts == [] and sink.pcm == []
    if expire:
        now[0] = 201.0
    else:
        kernel.revoke_grant("fixture-child")
    decider.release.set()
    await asyncio.wait_for(result.wait(), 1)
    assert result.status != "allowed" and sink.texts == [] and sink.pcm == []
    await output.close()
    assert output.pending_tasks == 0


@pytest.mark.asyncio
async def test_positive_complete_output_and_recheck_between_text_and_pcm():
    kernel, snapshot = authorized_snapshot()
    sink, decider = Sink(), HeldDecider()
    output = PrivacyOutput(kernel, sink, decider)
    key = TurnKey(snapshot.session_id, "turn-1", snapshot.snapshot_id, "generation-1")
    result = await output.begin(snapshot, key)
    await seal(output, key)
    decider.release.set()
    await asyncio.wait_for(result.wait(), 1)
    assert result.status == "allowed"
    assert sink.texts == ["SYNTHETIC_REPLY"] and sink.pcm == [b"\x01\x00"]
    await output.close()

    kernel, snapshot = authorized_snapshot()
    sink, decider = Sink(), HeldDecider()
    sink.on_text = lambda: kernel.revoke_grant("fixture-child")
    output = PrivacyOutput(kernel, sink, decider)
    key = TurnKey(snapshot.session_id, "turn-2", snapshot.snapshot_id, "generation-1")
    result = await output.begin(snapshot, key)
    await seal(output, key)
    decider.release.set()
    await asyncio.wait_for(result.wait(), 1)
    assert sink.texts == ["SYNTHETIC_REPLY"] and sink.pcm == []
    assert result.status != "allowed"
    await output.close()


@pytest.mark.asyncio
async def test_stale_epoch_and_missing_final_never_release_old_output():
    kernel, snapshot = authorized_snapshot()
    sink, decider = Sink(), HeldDecider()
    output = PrivacyOutput(kernel, sink, decider, Limits(max_wait_s=0.02))
    key = TurnKey(snapshot.session_id, "turn-1", snapshot.snapshot_id, "generation-1")
    result = await output.begin(snapshot, key)
    await output.ingest(key, event("agent_transcript", key, text="SYNTHETIC_REPLY"))
    await output.ingest(key, event("agent_audio_delta", key, audio=b"\x01\x00"))
    await output.ingest(key, event("agent_turn_completed", key))
    await asyncio.wait_for(result.wait(), 1)
    assert result.status != "allowed" and sink.texts == [] and sink.pcm == []
    await output.invalidate(snapshot.session_id)
    assert not await output.ingest(key, event("agent_transcript", key, text="LATE", final=True))
    with pytest.raises(PermissionError):
        await output.begin(snapshot, TurnKey(snapshot.session_id, "turn-2", snapshot.snapshot_id, "generation-2"))
    await output.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("omission", ["text_final", "turn_completed"])
async def test_combined_output_missing_end_marker_times_out_without_release(omission):
    kernel, snapshot = authorized_snapshot()
    sink, decider = Sink(), HeldDecider()
    output = PrivacyOutput(kernel, sink, decider, Limits(max_wait_s=0.02))
    key = TurnKey(snapshot.session_id, "turn-missing", snapshot.snapshot_id, "generation-1")
    result = await output.begin(snapshot, key)
    await output.ingest(key, event("agent_transcript", key, text="SYNTHETIC_REPLY"))
    await output.ingest(key, event("agent_audio_delta", key, audio=b"\x01\x00"))
    if omission != "text_final":
        await output.ingest(key, event("agent_transcript", key, text="", final=True))
    if omission != "turn_completed":
        await output.ingest(key, event("agent_turn_completed", key))
    await asyncio.wait_for(result.wait(), 1)
    assert result.status in {"invalid_output", "timeout"}
    assert sink.texts == [] and sink.pcm == [] and not decider.called.is_set()
    await output.close()


@pytest.mark.asyncio
async def test_late_chunk_and_buffer_limit_reject_before_release():
    kernel, snapshot = authorized_snapshot()
    sink, decider = Sink(), HeldDecider()
    output = PrivacyOutput(kernel, sink, decider)
    key = TurnKey(snapshot.session_id, "turn-late", snapshot.snapshot_id, "generation-1")
    result = await output.begin(snapshot, key)
    await seal(output, key)
    await asyncio.wait_for(decider.called.wait(), 1)
    assert not await output.ingest(key, event("agent_audio_delta", key, audio=b"\x02\x00"))
    decider.release.set()
    await asyncio.wait_for(result.wait(), 1)
    assert result.status == "invalid_output" and sink.texts == [] and sink.pcm == []
    await output.close()

    kernel, snapshot = authorized_snapshot()
    sink = Sink()
    output = PrivacyOutput(kernel, sink, HeldDecider(), Limits(max_audio_bytes=2))
    key = TurnKey(snapshot.session_id, "turn-over", snapshot.snapshot_id, "generation-1")
    result = await output.begin(snapshot, key)
    assert not await output.ingest(key, event("agent_audio_delta", key, audio=b"\x01\x00\x02\x00"))
    await asyncio.wait_for(result.wait(), 1)
    assert result.status == "over_limit" and sink.texts == [] and sink.pcm == []
    await output.close()
