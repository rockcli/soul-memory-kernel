"""Application-side M1 injection authority, using only synthetic identifiers."""

import pytest

from soul_memory_kernel.soul.policy import SessionAccess


@pytest.mark.parametrize(
    "access",
    [
        SessionAccess(),
        SessionAccess(speaker_claim="owner"),
        SessionAccess.for_manual_selection("owner"),
        SessionAccess(session_mode="controlled_private", speaker_claim="owner"),
    ],
)
def test_claim_selection_and_private_label_do_not_grant_personal_data(access):
    assert not access.may_inject(scope="PERSONAL", owner_id="owner")
    assert not access.may_inject(scope="PERSONAL", owner_id="other")
    assert not access.may_inject(scope="SAFETY", owner_id="owner")


def test_family_projection_requires_explicit_share_approval():
    access = SessionAccess.for_manual_selection("owner")
    assert not access.may_inject(scope="FAMILY", owner_id="owner")
    assert access.may_inject(scope="FAMILY", owner_id="owner", shared_approved=True)
    assert not access.may_inject(scope="FAMILY", owner_id="owner", shared_approved="false")


def test_product_cannot_create_owner_binding_without_trusted_authorizer():
    # W4 (M2 contract §3.5): an owner binding is expressible, but only next to a
    # non-empty control-plane authorization_ref. A bare "this session has an
    # owner" declaration stays unrepresentable.
    for ref in (None, "", "   "):
        with pytest.raises(ValueError, match="trusted local authorization"):
            SessionAccess(session_owner="owner", authorization_ref=ref)
    bound = SessionAccess(session_owner="owner", authorization_ref="ctl:session-grant")
    assert bound.session_owner == "owner"
    # the owner binding itself is not a data grant: may_inject stays closed
    assert not bound.may_inject(scope="PERSONAL", owner_id="owner")
    assert not bound.may_inject(scope="SAFETY", owner_id="owner")

    with pytest.raises(ValueError, match="manual identity assurance"):
        SessionAccess(identity_assurance="manually_selected_unverified")
    with pytest.raises(ValueError, match="unverified manual selection"):
        SessionAccess(selected_speaker_id="owner")


def test_unknown_scope_fails_closed():
    with pytest.raises(ValueError, match="unsupported data scope"):
        SessionAccess().may_inject(scope="PUBLIC", owner_id=None, shared_approved=True)
