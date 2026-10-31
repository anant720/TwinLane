"""Unit tests for capability delegation and monotonic attenuation invariants."""

import pytest

from twinlane.capabilities.delegation import verify_attenuation
from twinlane.capabilities.token import CapabilityToken
from twinlane.protocol.errors import AttenuationViolationError


def test_valid_delegation_narrowing() -> None:
    """Delegated child token with strictly narrower permissions succeeds."""
    parent = CapabilityToken(
        token_id="parent-1",
        issuer="ed25519:root",
        subject="ed25519:agent-a",
        intents=["report_result", "send_email", "fetch_url"],
        constraints={
            "send_email": {
                "recipient_allowlist": ["a@example.com", "b@example.com"],
                "subject_max": 100,
            }
        },
        not_before=1000,
        expires_at=2000,
        max_uses=10,
    )

    child = CapabilityToken(
        token_id="child-1",
        parent_token_id="parent-1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["send_email"],  # Narrower subset
        constraints={
            "send_email": {
                "recipient_allowlist": ["a@example.com"],  # Narrower subset
                "subject_max": 50,  # Narrower bound
            }
        },
        not_before=1100,
        expires_at=1900,
        max_uses=5,
    )

    # Verification must succeed
    verify_attenuation(parent, child)


def test_child_widening_intents_rejected() -> None:
    """Child attempting to add an intent absent from parent is rejected."""
    parent = CapabilityToken(
        token_id="parent-1",
        issuer="ed25519:root",
        subject="ed25519:agent-a",
        intents=["report_result"],
    )
    child = CapabilityToken(
        token_id="child-1",
        parent_token_id="parent-1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["report_result", "delete_database"],  # Escalation!
    )

    with pytest.raises(AttenuationViolationError, match="unauthorized intents"):
        verify_attenuation(parent, child)


def test_child_widening_allowlist_rejected() -> None:
    """Child attempting to add new recipients to allowlist is rejected."""
    parent = CapabilityToken(
        token_id="parent-1",
        issuer="ed25519:root",
        subject="ed25519:agent-a",
        intents=["send_email"],
        constraints={"send_email": {"recipient_allowlist": ["safe@corp.local"]}},
    )
    child = CapabilityToken(
        token_id="child-1",
        parent_token_id="parent-1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["send_email"],
        constraints={
            "send_email": {"recipient_allowlist": ["safe@corp.local", "evil@attacker.test"]}
        },
    )

    with pytest.raises(AttenuationViolationError, match="widens allowed items"):
        verify_attenuation(parent, child)


def test_child_extending_lifetime_rejected() -> None:
    """Child cannot live longer than parent."""
    parent = CapabilityToken(
        token_id="parent-1",
        issuer="ed25519:root",
        subject="ed25519:agent-a",
        intents=["ping"],
        expires_at=1000,
    )
    child = CapabilityToken(
        token_id="child-1",
        parent_token_id="parent-1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["ping"],
        expires_at=2000,  # Longer than parent!
    )

    with pytest.raises(AttenuationViolationError, match="exceeds parent expires_at"):
        verify_attenuation(parent, child)


def test_delegation_mismatched_parent_id_and_issuer() -> None:
    """Parent ID must match and child issuer must match parent subject."""
    parent = CapabilityToken(
        token_id="p1",
        issuer="ed25519:root",
        subject="ed25519:agent-a",
        intents=["read_file"],
    )

    # 1. Wrong parent ID
    c1 = CapabilityToken(
        token_id="c1",
        parent_token_id="wrong-parent",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["read_file"],
    )
    with pytest.raises(AttenuationViolationError, match="does not match parent ID"):
        verify_attenuation(parent, c1)

    # 2. Wrong issuer
    c2 = CapabilityToken(
        token_id="c2",
        parent_token_id="p1",
        issuer="ed25519:imposter",
        subject="ed25519:agent-b",
        intents=["read_file"],
    )
    with pytest.raises(AttenuationViolationError, match="must be parent subject"):
        verify_attenuation(parent, c2)


def test_delegation_temporal_and_quota_narrowing() -> None:
    """not_before cannot precede parent and max_uses cannot exceed remaining uses."""
    parent = CapabilityToken(
        token_id="p1",
        issuer="ed25519:root",
        subject="ed25519:agent-a",
        intents=["read_file"],
        not_before=1000,
        expires_at=2000,
        max_uses=10,
        uses_count=4,  # 6 remaining
    )

    # 1. Preceding not_before
    c1 = CapabilityToken(
        token_id="c1",
        parent_token_id="p1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["read_file"],
        not_before=900,  # Precedes parent 1000
        expires_at=1500,
        max_uses=5,
    )
    with pytest.raises(AttenuationViolationError, match="cannot precede parent not_before"):
        verify_attenuation(parent, c1)

    # 2. Exceeding max_uses
    c2 = CapabilityToken(
        token_id="c2",
        parent_token_id="p1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["read_file"],
        not_before=1000,
        expires_at=1500,
        max_uses=7,  # Exceeds 6 remaining
    )
    with pytest.raises(AttenuationViolationError, match="exceeds remaining parent uses"):
        verify_attenuation(parent, c2)


def test_delegation_constraint_narrowing_max_and_prefix() -> None:
    """Child max constraint cannot exceed parent; child prefix must start with parent prefix."""
    parent = CapabilityToken(
        token_id="p1",
        issuer="ed25519:root",
        subject="ed25519:agent-a",
        intents=["read_file"],
        constraints={"read_file": {"bytes_max": 500, "path_prefix": "/var/data"}},
    )

    # 1. Widening bytes_max
    c1 = CapabilityToken(
        token_id="c1",
        parent_token_id="p1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["read_file"],
        constraints={"read_file": {"bytes_max": 1000}},
    )
    with pytest.raises(AttenuationViolationError, match="exceeds parent limit"):
        verify_attenuation(parent, c1)

    # 2. Widening path_prefix
    c2 = CapabilityToken(
        token_id="c2",
        parent_token_id="p1",
        issuer="ed25519:agent-a",
        subject="ed25519:agent-b",
        intents=["read_file"],
        constraints={"read_file": {"path_prefix": "/etc/shadow"}},
    )
    with pytest.raises(AttenuationViolationError, match="does not narrow parent prefix"):
        verify_attenuation(parent, c2)
