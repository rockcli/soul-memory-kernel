"""Focused implementation tests for the synthetic-only Privacy Kernel."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from dataclasses import replace

import pytest

from soul_memory_kernel.privacy.provider_types import ProviderEvent
from soul_memory_kernel.privacy.kernel import FixtureGrant, PrivacyKernel, Record
from soul_memory_kernel.privacy.output import PrivacyOutput
from soul_memory_kernel.privacy.session import PrivacySessionCoordinator, PrivacySessionError
from soul_memory_kernel.privacy.controlled_output import Decision, TurnKey


ACTIONS = frozenset(("read_model", "send_provider", "publish_text", "play_audio"))


def fixture(now: list[float] | None = None):
    now = now or [100.0]
    kernel = PrivacyKernel(enabled=True, clock=lambda: now[0])
    kernel.add_record(Record(
        "synthetic-private", "child", "PERSONAL", "SECRET_SENTINEL_SYNTHETIC",
        frozenset(("member:child",)), ACTIONS,
    ))
    kernel.issue_fixture_grant(FixtureGrant(
        "fixture-grant", "synthetic-session", "child", "child", "member:child",
        ACTIONS, frozenset(("synthetic-private",)), 200.0,
        consent_versions=(("synthetic-private", 1),),
    ))
    lease = kernel.open_session("synthetic-session", "child", "member:child", "fixture-grant")
    return kernel, kernel.read_for_model(lease, ("synthetic-private",)), now


class Sink:
    def __init__(self):
        self.texts = []
        self.audio = []
        self.stops = []
        self.on_text = None

    def publish_text(self, key, text):
        self.texts.append(text)
        if self.on_text:
            self.on_text()

    def enqueue(self, key, pcm16):
        self.audio.append(pcm16)

    def stop(self, key):
        self.stops.append(key)


class HeldDecider:
    def __init__(self):
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def decide(self, sealed):
        self.entered.set()
        await self.release.wait()
        return Decision(sealed.key, sealed.digest, "allow")


async def seal(output, key):
    for event in (
        ProviderEvent("agent_transcript", text="SECRET_SENTINEL_SYNTHETIC", output_generation=key.output_generation),
        ProviderEvent("agent_audio_delta", audio=b"\x01\x00", output_generation=key.output_generation),
        ProviderEvent("agent_transcript", text="", is_final=True, output_generation=key.output_generation),
        ProviderEvent("agent_turn_completed", output_generation=key.output_generation),
    ):
        await output.ingest(key, event)


@pytest.mark.asyncio
async def test_grant_replacement_during_decision_rejects_both_sinks():
    kernel, snapshot, _ = fixture()
    sink, decider = Sink(), HeldDecider()
    output = PrivacyOutput(kernel, sink, decider)
    key = TurnKey(snapshot.session_id, "turn", snapshot.snapshot_id, "gen")
    result = await output.begin(snapshot, key)
    await seal(output, key)
    await asyncio.wait_for(decider.entered.wait(), 1)
    kernel.issue_fixture_grant(FixtureGrant(
        "fixture-grant", "synthetic-session", "child", "child", "member:child",
        ACTIONS, frozenset(("synthetic-private",)), 200.0, version=2,
        consent_versions=(("synthetic-private", 1),),
    ))
    decider.release.set()
    assert (await asyncio.wait_for(result.wait(), 1)).status == "denied"
    assert sink.texts == [] and sink.audio == []
    await output.close()


@pytest.mark.asyncio
async def test_revocation_between_text_and_pcm_stops_any_further_output():
    kernel, snapshot, _ = fixture()
    sink, decider = Sink(), HeldDecider()
    sink.on_text = lambda: kernel.revoke_grant("fixture-grant")
    output = PrivacyOutput(kernel, sink, decider)
    key = TurnKey(snapshot.session_id, "turn", snapshot.snapshot_id, "gen")
    result = await output.begin(snapshot, key)
    await seal(output, key)
    await asyncio.wait_for(decider.entered.wait(), 1)
    decider.release.set()
    assert (await asyncio.wait_for(result.wait(), 1)).status == "sink_error"
    assert len(sink.texts) == 1 and sink.audio == [] and sink.stops == [key]
    await output.close()


@pytest.mark.asyncio
async def test_coordinator_rejects_valid_but_unbound_snapshot():
    kernel, snapshot, _ = fixture()
    kernel.add_record(Record(
        "synthetic-other", "child", "FAMILY", "OTHER_SYNTHETIC",
        frozenset(("member:child",)), ACTIONS,
    ))
    kernel.issue_fixture_grant(FixtureGrant(
        "other-grant", "other-session", "child", "child", "member:child",
        ACTIONS, frozenset(("synthetic-other",)), 200.0,
        consent_versions=(("synthetic-other", 1),),
    ))
    other = kernel.read_for_model(
        kernel.open_session("other-session", "child", "member:child", "other-grant"),
        ("synthetic-other",),
    )

    class Provider:
        async def start_session(self, config):
            pass

        async def end_session(self):
            pass

    output = PrivacyOutput(kernel, Sink(), HeldDecider())
    coordinator = PrivacySessionCoordinator(kernel, output, Provider)
    await coordinator.open(snapshot)
    with pytest.raises(PermissionError):
        await output.begin(other, TurnKey(other.session_id, "turn", other.snapshot_id, "gen"))
    await coordinator.close()


@pytest.mark.asyncio
async def test_failed_start_locks_coordinator_and_attempts_cleanup():
    kernel, snapshot, _ = fixture()
    made = []

    class Provider:
        async def start_session(self, config):
            raise RuntimeError("synthetic start fault")

        async def end_session(self):
            made.append("end")

    coordinator = PrivacySessionCoordinator(kernel, PrivacyOutput(kernel, Sink(), HeldDecider()), Provider)
    with pytest.raises(PrivacySessionError):
        await coordinator.open(snapshot)
    assert made == ["end"] and coordinator.faulted
    with pytest.raises(PrivacySessionError):
        await coordinator.open(snapshot)
    await coordinator.close()
