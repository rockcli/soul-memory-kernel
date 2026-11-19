"""Opt-in, synthetic-only privacy experiments; no product authentication."""

from .kernel import (
    ContextSnapshot,
    FixtureGrant,
    PrivacyKernel,
    Record,
    SessionLease,
    SpeakerObservation,
)

__all__ = [
    "ContextSnapshot",
    "FixtureGrant",
    "PrivacyKernel",
    "Record",
    "SessionLease",
    "SpeakerObservation",
]
