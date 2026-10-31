"""Unit tests for CapabilityStore and delegation chain verification."""

import time

import pytest

from twinlane.capabilities.manifest import CapabilityStore
from twinlane.capabilities.token import CapabilityToken
from twinlane.crypto.keys import generate_keypair
from twinlane.identity.trust_store import TrustStore
from twinlane.protocol.errors import AttenuationViolationError, CapabilityError, TokenExpiredError


def test_capability_store_valid_chain() -> None:
    """A valid delegation chain from root to child validates cleanly."""
    root_keys = generate_keypair()
    agent_a_keys = generate_keypair()
    agent_b_keys = generate_keypair()

    trust_store = TrustStore()
    trust_store.register(root_keys.public_key, name="root")
    trust_store.register(agent_a_keys.public_key, name="agent-a")
    trust_store.register(agent_b_keys.public_key, name="agent-b")

    store = CapabilityStore(trust_store)
    now = int(time.time())

    # Root token issued by root to agent-a
    root_token = CapabilityToken(
        token_id="root-tok",
        issuer=root_keys.fingerprint,
        subject=agent_a_keys.fingerprint,
        intents=["read_file", "send_email"],
        not_before=now - 10,
        expires_at=now + 1000,
        max_uses=10,
    ).sign(root_keys.private_key)
    store.store(root_token)

    # Delegated child token issued by agent-a to agent-b
    child_token = CapabilityToken(
        token_id="child-tok",
        parent_token_id="root-tok",
        issuer=agent_a_keys.fingerprint,
        subject=agent_b_keys.fingerprint,
        intents=["read_file"],
        not_before=now,
        expires_at=now + 500,
        max_uses=5,
    ).sign(agent_a_keys.private_key)
    store.store(child_token)

    assert store.get("child-tok") == child_token
    # Validates without error
    store.verify_token_chain(child_token)


def test_capability_store_untrusted_issuer() -> None:
    """A token whose issuer is not in the trust store fails verification."""
    untrusted_keys = generate_keypair()
    trust_store = TrustStore()
    store = CapabilityStore(trust_store)

    token = CapabilityToken(
        token_id="tok-1",
        issuer=untrusted_keys.fingerprint,
        subject="ed25519:someone",
        intents=["read_file"],
    ).sign(untrusted_keys.private_key)
    store.store(token)

    with pytest.raises(CapabilityError, match="is not trusted"):
        store.verify_token_chain(token)


def test_capability_store_expired_token() -> None:
    """An expired token in the chain fails verification."""
    root_keys = generate_keypair()
    trust_store = TrustStore()
    trust_store.register(root_keys.public_key, name="root")
    store = CapabilityStore(trust_store)

    token = CapabilityToken(
        token_id="tok-expired",
        issuer=root_keys.fingerprint,
        subject="ed25519:someone",
        intents=["read_file"],
        not_before=100,
        expires_at=200,  # Far in the past
    ).sign(root_keys.private_key)
    store.store(token)

    with pytest.raises(TokenExpiredError, match="has expired"):
        store.verify_token_chain(token)


def test_capability_store_missing_parent() -> None:
    """A child token referencing a non-existent parent token fails verification."""
    root_keys = generate_keypair()
    trust_store = TrustStore()
    trust_store.register(root_keys.public_key, name="root")
    store = CapabilityStore(trust_store)

    now = int(time.time())
    child_token = CapabilityToken(
        token_id="child-orphaned",
        parent_token_id="missing-parent-id",
        issuer=root_keys.fingerprint,
        subject="ed25519:someone",
        intents=["read_file"],
        not_before=now - 10,
        expires_at=now + 1000,
    ).sign(root_keys.private_key)
    store.store(child_token)

    with pytest.raises(CapabilityError, match="Parent token 'missing-parent-id' not found"):
        store.verify_token_chain(child_token)


def test_capability_store_circular_delegation() -> None:
    """A circular delegation chain is caught and rejected."""
    key_a = generate_keypair()
    trust_store = TrustStore()
    trust_store.register(key_a.public_key, name="a")
    store = CapabilityStore(trust_store)

    now = int(time.time())
    tok1 = CapabilityToken(
        token_id="tok-a",
        parent_token_id="tok-b",
        issuer=key_a.fingerprint,
        subject=key_a.fingerprint,
        intents=["read_file"],
        not_before=now - 10,
        expires_at=now + 1000,
    ).sign(key_a.private_key)

    tok2 = CapabilityToken(
        token_id="tok-b",
        parent_token_id="tok-a",
        issuer=key_a.fingerprint,
        subject=key_a.fingerprint,
        intents=["read_file"],
        not_before=now - 10,
        expires_at=now + 1000,
    ).sign(key_a.private_key)

    store.store(tok1)
    store.store(tok2)

    with pytest.raises(AttenuationViolationError, match="Circular delegation loop detected"):
        store.verify_token_chain(tok1)
