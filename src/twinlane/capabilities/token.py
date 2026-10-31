"""Capability tokens with parameter constraints, TTLs, usage counters, and Ed25519 signatures."""

import time
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, Field

from twinlane.crypto.keys import compute_key_fingerprint
from twinlane.protocol.canonical import canonicalize_json
from twinlane.protocol.errors import (
    ConstraintViolationError,
    IntentNotAuthorizedError,
    SignatureVerificationError,
    TokenExpiredError,
    TokenUsesExhaustedError,
)


class CapabilityToken(BaseModel):
    """Cryptographically signed capability token authorizing specific intents with constraints."""

    token_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique token UUID")
    issuer: str = Field(..., description="Issuer public key fingerprint")
    subject: str = Field(..., description="Subject / grantee public key fingerprint")
    intents: list[str] = Field(..., description="List of authorized intent identifiers")
    constraints: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Per-intent parameter constraints (e.g. allowlists, numeric ranges, prefixes)",
    )
    not_before: int = Field(
        default_factory=lambda: int(time.time()), description="Valid from timestamp"
    )
    expires_at: int = Field(
        default_factory=lambda: int(time.time()) + 3600,
        description="Valid until timestamp",
    )
    max_uses: int = Field(
        default=1000, ge=1, description="Maximum number of times token can be used"
    )
    uses_count: int = Field(default=0, ge=0, description="Current execution count")
    parent_token_id: str | None = Field(default=None, description="Parent token ID if delegated")
    signature: str | None = Field(default=None, description="Ed25519 signature hex string")

    model_config = {"extra": "forbid"}

    def get_signable_payload(self) -> dict[str, Any]:
        """Construct the canonical signable dictionary for the capability token."""
        return {
            "token_id": self.token_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "intents": sorted(self.intents),
            "constraints": self.constraints,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "max_uses": self.max_uses,
            "parent_token_id": self.parent_token_id,
        }

    def sign(self, private_key: ed25519.Ed25519PrivateKey) -> "CapabilityToken":
        """Sign this capability token with the issuer's private key and return a copy."""
        public_key = private_key.public_key()
        fp = compute_key_fingerprint(public_key)
        if fp.lower() != self.issuer.lower():
            raise ValueError(
                f"Signing key fingerprint '{fp}' does not match token issuer '{self.issuer}'"
            )

        canonical_bytes = canonicalize_json(self.get_signable_payload())
        raw_sig = private_key.sign(canonical_bytes)

        token_dict = self.model_dump(mode="python")
        token_dict["signature"] = raw_sig.hex()
        return CapabilityToken.model_validate(token_dict)

    def verify_signature(self, issuer_public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify the Ed25519 signature of this capability token."""
        if self.signature is None:
            raise SignatureVerificationError(f"Token '{self.token_id}' has no signature")

        try:
            raw_sig = bytes.fromhex(self.signature)
            canonical_bytes = canonicalize_json(self.get_signable_payload())
            issuer_public_key.verify(raw_sig, canonical_bytes)
            return True
        except (ValueError, InvalidSignature) as e:
            raise SignatureVerificationError(f"Token signature verification failed: {e}") from e

    def is_valid_now(self, now: int | None = None) -> bool:
        """Check whether the token is currently active within its time window."""
        t = now if now is not None else int(time.time())
        return self.not_before <= t <= self.expires_at

    def check_authorization(
        self, intent: str, params: dict[str, Any], now: int | None = None
    ) -> None:
        """Verify intent, constraints, usage count, and expiration.

        Raises:
            TokenExpiredError: If token is expired or not yet valid.
            TokenUsesExhaustedError: If uses_count >= max_uses.
            IntentNotAuthorizedError: If intent is not in allowed list.
            ConstraintViolationError: If a parameter violates constraint rules.
        """
        # 1. Temporal validity
        if not self.is_valid_now(now):
            raise TokenExpiredError(f"Token '{self.token_id}' is expired or not yet active")

        # 2. Usage quota
        if self.uses_count >= self.max_uses:
            raise TokenUsesExhaustedError(self.max_uses)

        # 3. Intent permission
        if intent not in self.intents:
            raise IntentNotAuthorizedError(intent)

        # 4. Parameter constraints
        if intent in self.constraints:
            intent_rules = self.constraints[intent]
            for param_key, rule_val in intent_rules.items():
                if param_key.endswith("_allowlist"):
                    actual_param = param_key[:-10]
                    if actual_param in params:
                        val = params[actual_param]
                        if isinstance(rule_val, list) and val not in rule_val:
                            raise ConstraintViolationError(
                                actual_param,
                                f"value '{val}' not in allowed list: {rule_val}",
                            )
                elif param_key.endswith("_max"):
                    actual_param = param_key[:-4]
                    if actual_param in params:
                        val = params[actual_param]
                        if isinstance(val, (int, float)) and val > rule_val:
                            raise ConstraintViolationError(
                                actual_param,
                                f"value {val} exceeds maximum limit of {rule_val}",
                            )
                elif param_key.endswith("_prefix"):
                    actual_param = param_key[:-7]
                    if actual_param in params:
                        val = str(params[actual_param])
                        if not val.startswith(rule_val):
                            raise ConstraintViolationError(
                                actual_param,
                                f"value '{val}' must start with prefix '{rule_val}'",
                            )

    def record_usage(self) -> None:
        """Increment usage counter."""
        self.uses_count += 1
