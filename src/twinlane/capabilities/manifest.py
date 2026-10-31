"""Capability Store and delegation chain resolver."""

from cryptography.hazmat.primitives.asymmetric import ed25519

from twinlane.capabilities.delegation import verify_attenuation
from twinlane.capabilities.token import CapabilityToken
from twinlane.identity.trust_store import TrustStore
from twinlane.protocol.errors import AttenuationViolationError, CapabilityError, TokenExpiredError


class CapabilityStore:
    """Manages active capability tokens and validates delegation chains."""

    def __init__(self, trust_store: TrustStore) -> None:
        self.trust_store = trust_store
        self._tokens: dict[str, CapabilityToken] = {}

    def store(self, token: CapabilityToken) -> None:
        """Store an active capability token."""
        self._tokens[token.token_id] = token

    def get(self, token_id: str) -> CapabilityToken | None:
        """Look up a token by ID."""
        return self._tokens.get(token_id)

    def verify_token_chain(self, token: CapabilityToken) -> None:
        """Validate a capability token and its full delegation chain to a trusted root anchor.

        Raises:
            CapabilityError: If token signature fails, expiration occurs,
                             or delegation chain violates monotonic attenuation.
        """
        current = token
        visited: set[str] = set()

        while True:
            if current.token_id in visited:
                raise AttenuationViolationError(
                    f"Circular delegation loop detected at token '{current.token_id}'"
                )
            visited.add(current.token_id)

            # 1. Look up issuer public key in trust store
            issuer_key: ed25519.Ed25519PublicKey | None = self.trust_store.get_public_key(
                current.issuer
            )
            if issuer_key is None:
                raise CapabilityError(f"Token issuer '{current.issuer}' is not trusted")

            # 2. Verify signature on token
            current.verify_signature(issuer_key)

            # 3. Check expiration
            if not current.is_valid_now():
                raise TokenExpiredError(f"Token '{current.token_id}' has expired")

            # 4. If root token (no parent), chain is valid
            if current.parent_token_id is None:
                break

            # 5. Lookup parent and verify attenuation
            parent = self._tokens.get(current.parent_token_id)
            if parent is None:
                raise CapabilityError(
                    f"Parent token '{current.parent_token_id}' not found in store"
                )

            verify_attenuation(parent, current)
            current = parent
