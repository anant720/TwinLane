"""Agent identity registry and configuration loader."""

from twinlane.crypto.keys import KeyPair
from twinlane.identity.trust_store import TrustStore


class AgentRegistry:
    """Manages local agent identity alongside peer trust stores."""

    def __init__(self, local_keypair: KeyPair, trust_store: TrustStore | None = None) -> None:
        self.local_keypair = local_keypair
        self.trust_store = trust_store or TrustStore()

        # Register self in trust store
        self.trust_store.register(
            public_key=local_keypair.public_key,
            name="self",
            metadata={"role": "local"},
        )

    @property
    def local_fingerprint(self) -> str:
        """Return the fingerprint of the local agent."""
        return self.local_keypair.fingerprint
