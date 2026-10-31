"""Unit tests for AgentRegistry."""

from twinlane.crypto.keys import generate_keypair
from twinlane.identity.registry import AgentRegistry
from twinlane.identity.trust_store import TrustStore


def test_agent_registry_initialization() -> None:
    """AgentRegistry registers local keypair in trust store."""
    kp = generate_keypair()
    trust_store = TrustStore()
    registry = AgentRegistry(local_keypair=kp, trust_store=trust_store)

    assert registry.local_fingerprint == kp.fingerprint
    assert registry.trust_store.is_trusted("self")
    assert registry.trust_store.is_trusted(kp.fingerprint)
