"""Unit tests for TrustStore."""

import pytest

from twinlane.crypto.keys import generate_keypair
from twinlane.identity.trust_store import TrustStore
from twinlane.protocol.errors import SenderNotTrustedError


def test_trust_store_registration_and_lookup() -> None:
    """Registered public keys are retrievable by fingerprint and name."""
    store = TrustStore()
    kp = generate_keypair()

    fingerprint = store.register(kp.public_key, name="agent-alice")
    assert store.is_trusted(fingerprint)
    assert store.is_trusted("agent-alice")

    key_by_fp = store.get_public_key(fingerprint)
    key_by_name = store.get_public_key("agent-alice")

    assert key_by_fp is not None
    assert key_by_name is not None
    assert key_by_fp == key_by_name


def test_trust_store_unknown_sender() -> None:
    """Unregistered sender raises SenderNotTrustedError when required."""
    store = TrustStore()
    assert not store.is_trusted("ed25519:unknown")

    with pytest.raises(SenderNotTrustedError):
        store.require_public_key("ed25519:unknown")
