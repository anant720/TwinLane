"""Public Key Trust Store for validating authenticated peer identities."""

from typing import Any, NamedTuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from twinlane.crypto.keys import compute_key_fingerprint
from twinlane.protocol.errors import SenderNotTrustedError


class TrustedAgent(NamedTuple):
    """Metadata container for a trusted peer agent."""

    name: str
    fingerprint: str
    public_key: ed25519.Ed25519PublicKey
    metadata: dict[str, Any]


class TrustStore:
    """In-memory repository of trusted peer public keys and identities."""

    def __init__(self) -> None:
        self._by_fingerprint: dict[str, TrustedAgent] = {}
        self._by_name: dict[str, str] = {}  # name -> fingerprint

    def register(
        self,
        public_key: ed25519.Ed25519PublicKey,
        name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Register a public key in the trust store.

        Returns:
            The computed public key fingerprint (ed25519:<hex>).
        """
        fingerprint = compute_key_fingerprint(public_key)
        agent_record = TrustedAgent(
            name=name,
            fingerprint=fingerprint,
            public_key=public_key,
            metadata=metadata or {},
        )
        self._by_fingerprint[fingerprint] = agent_record
        if name:
            self._by_name[name] = fingerprint
        return fingerprint

    def get_public_key(self, identifier: str) -> ed25519.Ed25519PublicKey | None:
        """Look up public key by fingerprint or name."""
        if identifier in self._by_fingerprint:
            return self._by_fingerprint[identifier].public_key

        if identifier in self._by_name:
            fingerprint = self._by_name[identifier]
            return self._by_fingerprint[fingerprint].public_key

        return None

    def get_agent(self, identifier: str) -> TrustedAgent | None:
        """Retrieve full agent record by identifier."""
        if identifier in self._by_fingerprint:
            return self._by_fingerprint[identifier]
        if identifier in self._by_name:
            fingerprint = self._by_name[identifier]
            return self._by_fingerprint[fingerprint]
        return None

    def require_public_key(self, identifier: str) -> ed25519.Ed25519PublicKey:
        """Look up public key or raise SenderNotTrustedError if absent."""
        key = self.get_public_key(identifier)
        if key is None:
            raise SenderNotTrustedError(identifier)
        return key

    def is_trusted(self, identifier: str) -> bool:
        """Return True if identifier is registered in this trust store."""
        return self.get_public_key(identifier) is not None

    def all_fingerprints(self) -> list[str]:
        """Return all registered fingerprints."""
        return list(self._by_fingerprint.keys())
