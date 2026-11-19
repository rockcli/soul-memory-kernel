"""Default-off authorization experiment using synthetic records and fixture grants.

No production identity source issues grants. The existing SessionAccess remains
closed for PERSONAL/SAFETY; this module is not imported by the voice pipeline.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from time import monotonic
from typing import Callable, Literal

from soul_memory_kernel.soul.policy import Scope

Action = Literal["read_model", "send_provider", "publish_text", "play_audio", "write", "share", "delete"]
_ACTIONS = frozenset(("read_model", "send_provider", "publish_text", "play_audio", "write", "share", "delete"))
_SCOPES = frozenset(("FAMILY", "PERSONAL", "SAFETY"))


def _id(value: str) -> bool:
    return isinstance(value, str) and bool(value) and len(value.encode("utf-8")) <= 128


def _ids(values: frozenset[str]) -> bool:
    return isinstance(values, frozenset) and bool(values) and all(_id(value) for value in values)


@dataclass(frozen=True)
class SpeakerObservation:
    candidate_id: str | None = None
    score: float | None = None
    state: Literal["unknown", "candidate", "multiple"] = "unknown"

    def __post_init__(self) -> None:
        if self.state not in ("unknown", "candidate", "multiple"):
            raise ValueError("invalid speaker state")
        if self.candidate_id is not None and not _id(self.candidate_id):
            raise ValueError("invalid candidate ID")
        if self.score is not None and (
            not isinstance(self.score, (int, float))
            or not math.isfinite(self.score)
            or not 0 <= self.score <= 1
        ):
            raise ValueError("invalid similarity score")


@dataclass(frozen=True)
class Record:
    record_id: str
    owner_id: str
    scope: Scope
    content: str
    audiences: frozenset[str]
    actions: frozenset[Action]
    source_ids: tuple[str, ...] = ()
    consent_version: int = 1

    def __post_init__(self) -> None:
        if not _id(self.record_id) or not _id(self.owner_id):
            raise ValueError("record and owner IDs are required")
        if self.scope not in _SCOPES or not isinstance(self.content, str):
            raise ValueError("invalid record scope or content")
        if not _ids(self.audiences) or not _ids(self.actions) or not self.actions <= _ACTIONS:
            raise ValueError("explicit audience and known actions are required")
        if not isinstance(self.source_ids, tuple) or not all(_id(s) for s in self.source_ids):
            raise ValueError("invalid source IDs")
        if type(self.consent_version) is not int or self.consent_version < 1:
            raise ValueError("invalid consent version")


@dataclass(frozen=True)
class FixtureGrant:
    grant_id: str
    session_id: str
    subject_id: str
    owner_id: str
    audience_id: str
    actions: frozenset[Action]
    resource_ids: frozenset[str]
    expires_at: float
    version: int = 1
    consent_versions: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if not all(_id(value) for value in (
            self.grant_id, self.session_id, self.subject_id, self.owner_id, self.audience_id
        )):
            raise ValueError("grant identities are required")
        if not _ids(self.actions) or not self.actions <= _ACTIONS or not _ids(self.resource_ids):
            raise ValueError("grant actions and resources must be explicit")
        if not isinstance(self.expires_at, (int, float)) or not math.isfinite(self.expires_at):
            raise ValueError("invalid expiry")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("invalid grant version")
        if not isinstance(self.consent_versions, tuple) or any(
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not _id(entry[0])
            or type(entry[1]) is not int
            or entry[1] < 1
            for entry in self.consent_versions
        ):
            raise ValueError("invalid consent versions")
        if len({record_id for record_id, _ in self.consent_versions}) != len(self.consent_versions):
            raise ValueError("duplicate consent version")


@dataclass(frozen=True)
class SessionLease:
    session_id: str
    subject_id: str
    audience_id: str
    grant_id: str
    grant_version: int
    epoch: int
    nonce: str


@dataclass(frozen=True)
class ContextSnapshot:
    snapshot_id: str
    session_id: str
    epoch: int
    audience_id: str
    record_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    texts: tuple[str, ...]


class PrivacyKernel:
    """An isolated in-memory fixture authority with no production grant issuer."""

    def __init__(self, *, enabled: bool = False, clock: Callable[[], float] = monotonic):
        self.enabled = enabled
        self._clock = clock
        self._records: dict[str, Record] = {}
        self._grants: dict[str, FixtureGrant] = {}
        self._revoked: set[str] = set()
        self._leases: dict[str, SessionLease] = {}
        self._epochs: dict[str, int] = {}
        self._snapshots: dict[str, ContextSnapshot] = {}

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise PermissionError("synthetic privacy kernel is disabled")

    def _now(self) -> float | None:
        try:
            now = self._clock()
            if isinstance(now, (int, float)) and math.isfinite(now):
                return float(now)
        except Exception:
            pass
        return None

    def add_record(self, record: Record) -> None:
        self._require_enabled()
        if record.record_id in self._records:
            raise ValueError("record ID already exists")
        self._records[record.record_id] = record

    def issue_fixture_grant(self, grant: FixtureGrant) -> None:
        """Only tests/CLI call this; never a product authentication API."""

        self._require_enabled()
        old = self._grants.get(grant.grant_id)
        if old is not None and grant.version <= old.version:
            raise ValueError("grant version must increase")
        self._grants[grant.grant_id] = grant
        self._revoked.discard(grant.grant_id)

    def revoke_grant(self, grant_id: str) -> None:
        self._revoked.add(grant_id)

    def open_session(
        self,
        session_id: str,
        subject_id: str,
        audience_id: str,
        grant_id: str,
        observation: SpeakerObservation | None = None,
    ) -> SessionLease:
        self._require_enabled()
        # observation is deliberately never consulted in the grant decision.
        if observation is not None and not isinstance(observation, SpeakerObservation):
            raise ValueError("invalid observation")
        grant = self._grants.get(grant_id)
        now = self._now()
        if (
            grant is None
            or grant_id in self._revoked
            or now is None
            or now >= grant.expires_at
            or (grant.session_id, grant.subject_id, grant.audience_id)
            != (session_id, subject_id, audience_id)
            or session_id in self._leases
        ):
            raise PermissionError("no current fixture grant for session")
        epoch = self._epochs.get(session_id, 0) + 1
        self._epochs[session_id] = epoch
        lease = SessionLease(
            session_id, subject_id, audience_id, grant_id, grant.version, epoch, secrets.token_hex(16)
        )
        self._leases[session_id] = lease
        return lease

    def rotate_session(self, session_id: str) -> int:
        """Invalidate all old leases/snapshots before any provider restart."""

        self._leases.pop(session_id, None)
        epoch = self._epochs.get(session_id, 0) + 1
        self._epochs[session_id] = epoch
        return epoch

    def _grant_for(self, lease: SessionLease) -> FixtureGrant | None:
        grant = self._grants.get(lease.grant_id)
        now = self._now()
        if (
            not self.enabled
            or self._leases.get(lease.session_id) is not lease
            or grant is None
            or lease.grant_id in self._revoked
            or now is None
            or now >= grant.expires_at
            or grant.version != lease.grant_version
            or self._epochs.get(lease.session_id) != lease.epoch
        ):
            return None
        return grant

    def _resolve(self, record_ids: tuple[str, ...]) -> tuple[Record, ...]:
        resolved: list[Record] = []
        visited: set[str] = set()
        visiting: set[str] = set()

        def visit(record_id: str) -> None:
            if record_id in visiting:
                raise PermissionError("cyclic provenance")
            if record_id in visited:
                return
            record = self._records.get(record_id)
            if record is None:
                raise PermissionError("missing provenance")
            visiting.add(record_id)
            for source_id in record.source_ids:
                visit(source_id)
            visiting.remove(record_id)
            visited.add(record_id)
            resolved.append(record)

        for record_id in record_ids:
            visit(record_id)
        return tuple(resolved)

    @staticmethod
    def _allows(grant: FixtureGrant, records: tuple[Record, ...], audience_id: str, action: Action) -> bool:
        consents = dict(grant.consent_versions)
        return (
            action in grant.actions
            and audience_id == grant.audience_id
            and all(
                record.record_id in grant.resource_ids
                and record.owner_id == grant.owner_id
                and audience_id in record.audiences
                and action in record.actions
                and consents.get(record.record_id) == record.consent_version
                for record in records
            )
        )

    def read_for_model(self, lease: SessionLease, record_ids: tuple[str, ...]) -> ContextSnapshot:
        """Query actual records, authorize all ancestors, then register the projection."""

        self._require_enabled()
        grant = self._grant_for(lease)
        if grant is None or not isinstance(record_ids, tuple) or not record_ids:
            raise PermissionError("no active lease or records")
        records = self._resolve(record_ids)
        if not self._allows(grant, records, lease.audience_id, "read_model"):
            raise PermissionError("record projection denied")
        snapshot = ContextSnapshot(
            secrets.token_hex(16), lease.session_id, lease.epoch, lease.audience_id,
            record_ids, tuple(record.record_id for record in records),
            tuple(self._records[record_id].content for record_id in record_ids),
        )
        self._snapshots[snapshot.snapshot_id] = snapshot
        return snapshot

    def _snapshot_state(self, snapshot: ContextSnapshot) -> tuple[FixtureGrant, tuple[Record, ...]] | None:
        if self._snapshots.get(snapshot.snapshot_id) is not snapshot:
            return None
        lease = self._leases.get(snapshot.session_id)
        if lease is None or lease.epoch != snapshot.epoch:
            return None
        grant = self._grant_for(lease)
        if grant is None:
            return None
        try:
            records = self._resolve(snapshot.record_ids)
        except PermissionError:
            return None
        if tuple(record.record_id for record in records) != snapshot.source_ids:
            return None
        return grant, records

    def snapshot_text(self, snapshot: ContextSnapshot) -> tuple[str, ...]:
        state = self._snapshot_state(snapshot)
        if state is None or not self._allows(state[0], state[1], snapshot.audience_id, "read_model"):
            raise PermissionError("stale context snapshot")
        return snapshot.texts

    def speak_to_audience(
        self, snapshot: ContextSnapshot, audience_id: str, action: Literal["publish_text", "play_audio"]
    ) -> bool:
        if action not in ("publish_text", "play_audio"):
            raise ValueError("unsupported output action")
        state = self._snapshot_state(snapshot)
        return state is not None and self._allows(state[0], state[1], audience_id, action)

    def can_send_provider(self, snapshot: ContextSnapshot) -> bool:
        state = self._snapshot_state(snapshot)
        return state is not None and self._allows(
            state[0], state[1], snapshot.audience_id, "send_provider"
        )

    def authorize_record_action(self, lease: SessionLease, record_id: str, action: Action) -> bool:
        """Check an action, without performing a write/share/delete operation."""

        if action not in _ACTIONS:
            raise ValueError("unsupported record action")
        grant = self._grant_for(lease)
        if grant is None:
            return False
        try:
            records = self._resolve((record_id,))
        except PermissionError:
            return False
        return self._allows(grant, records, lease.audience_id, action)
