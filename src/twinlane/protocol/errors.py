"""Comprehensive exception hierarchy for TwinLane protocol and Gate verification."""


class TwinLaneError(Exception):
    """Base exception for all TwinLane runtime and protocol errors."""

    def __init__(self, message: str, code: str = "ERR_INTERNAL") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


# --- Protocol & Serialization Errors ---


class ProtocolError(TwinLaneError):
    """Base exception for protocol formatting and serialization errors."""

    def __init__(self, message: str, code: str = "ERR_PROTOCOL") -> None:
        super().__init__(message, code=code)


class CanonicalizationError(ProtocolError):
    """Raised when JSON canonicalization (RFC 8785) fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="ERR_CANONICALIZATION_FAILED")


class OversizeMessageError(ProtocolError):
    """Raised when an incoming envelope exceeds maximum allowed byte size."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="ERR_OVERSIZE_MESSAGE")


class InvalidSchemaError(ProtocolError):
    """Raised when envelope fields fail JSON Schema or Pydantic validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="ERR_INVALID_SCHEMA")


# --- Authentication & Crypto Gate Errors ---


class AuthenticationError(TwinLaneError):
    """Base exception for authentication, signature, and replay check failures."""

    def __init__(self, message: str, code: str = "ERR_AUTH_FAILED") -> None:
        super().__init__(message, code=code)


class SignatureVerificationError(AuthenticationError):
    """Raised when Ed25519 signature verification fails."""

    def __init__(self, message: str = "Cryptographic signature verification failed") -> None:
        super().__init__(message, code="ERR_SIGNATURE_INVALID")


class SenderNotTrustedError(AuthenticationError):
    """Raised when the message sender is not found in the local Trust Store."""

    def __init__(self, sender_id: str) -> None:
        super().__init__(
            f"Sender '{sender_id}' is not trusted in local TrustStore",
            code="ERR_SENDER_NOT_TRUSTED",
        )


class RecipientMismatchError(AuthenticationError):
    """Raised when the message recipient does not match the local agent identity."""

    def __init__(self, recipient: str, expected: str) -> None:
        super().__init__(
            f"Recipient '{recipient}' does not match expected agent '{expected}'",
            code="ERR_RECIPIENT_MISMATCH",
        )


class MessageExpiredError(AuthenticationError):
    """Raised when message expiration timestamp is in the past."""

    def __init__(self, message: str = "Message has expired") -> None:
        super().__init__(message, code="ERR_MESSAGE_EXPIRED")


class ClockSkewError(AuthenticationError):
    """Raised when message issued_at timestamp exceeds maximum allowed clock skew."""

    def __init__(self, message: str = "Message timestamp exceeds allowed clock skew") -> None:
        super().__init__(message, code="ERR_CLOCK_SKEW")


class NonceReplayError(AuthenticationError):
    """Raised when a nonce has already been seen in the active cache."""

    def __init__(self, nonce: str) -> None:
        super().__init__(
            f"Duplicate nonce '{nonce}' detected; potential replay attack",
            code="ERR_REPLAY_DETECTED",
        )


class SequenceRegressionError(AuthenticationError):
    """Raised when sequence number is not strictly greater than previous sequence."""

    def __init__(self, seq: int, expected_min: int) -> None:
        super().__init__(
            f"Sequence counter regression or replay: got {seq}, expected > {expected_min}",
            code="ERR_SEQUENCE_REGRESSION",
        )


# --- Capability & Policy Errors ---


class CapabilityError(TwinLaneError):
    """Base exception for capability token authorization errors."""

    def __init__(self, message: str, code: str = "ERR_CAPABILITY_VIOLATION") -> None:
        super().__init__(message, code=code)


class IntentNotAuthorizedError(CapabilityError):
    """Raised when requested intent is not granted by the capability token."""

    def __init__(self, intent: str) -> None:
        super().__init__(
            f"Intent '{intent}' is not authorized by capability token",
            code="ERR_INTENT_NOT_AUTHORIZED",
        )


class ConstraintViolationError(CapabilityError):
    """Raised when intent parameters violate capability token constraints."""

    def __init__(self, param: str, details: str) -> None:
        super().__init__(
            f"Parameter '{param}' violates capability constraints: {details}",
            code="ERR_CONSTRAINT_VIOLATION",
        )


class TokenExpiredError(CapabilityError):
    """Raised when capability token has expired or is not yet valid."""

    def __init__(self, message: str = "Capability token has expired") -> None:
        super().__init__(message, code="ERR_TOKEN_EXPIRED")


class TokenUsesExhaustedError(CapabilityError):
    """Raised when capability token maximum uses counter is exceeded."""

    def __init__(self, max_uses: int) -> None:
        super().__init__(
            f"Capability token has exceeded maximum usage limit of {max_uses}",
            code="ERR_TOKEN_USES_EXHAUSTED",
        )


class AttenuationViolationError(CapabilityError):
    """Raised when delegated child capability token attempts to widen scope."""

    def __init__(self, message: str) -> None:
        super().__init__(
            f"Child capability violates monotonic attenuation: {message}",
            code="ERR_ATTENUATION_VIOLATION",
        )


# --- Provenance Errors ---


class ProvenanceError(TwinLaneError):
    """Base exception for data provenance and label propagation errors."""

    def __init__(self, message: str, code: str = "ERR_PROVENANCE_CHECK_FAILED") -> None:
        super().__init__(message, code=code)


class UntrustedParameterError(ProvenanceError):
    """Raised when a sensitive parameter is derived from untrusted data in Strict mode."""

    def __init__(self, param: str) -> None:
        super().__init__(
            f"Parameter '{param}' is derived from UNTRUSTED data and rejected by policy",
            code="ERR_UNTRUSTED_PARAMETER",
        )


# --- Audit Errors ---


class AuditChainError(TwinLaneError):
    """Base exception for audit trail integrity and hash-chaining verification."""

    def __init__(self, message: str, code: str = "ERR_AUDIT_CORRUPTED") -> None:
        super().__init__(message, code=code)


class AuditChainTamperError(AuditChainError):
    """Raised when an audit record hash does not match previous hash pointer."""

    def __init__(self, index: int, message: str) -> None:
        super().__init__(
            f"Audit chain verification failed at record index {index}: {message}",
            code="ERR_AUDIT_TAMPER_DETECTED",
        )
