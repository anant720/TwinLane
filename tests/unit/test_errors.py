"""Unit tests for TwinLane exception hierarchy."""

from twinlane.protocol.errors import (
    AttenuationViolationError,
    AuditChainTamperError,
    CanonicalizationError,
    ClockSkewError,
    ConstraintViolationError,
    IntentNotAuthorizedError,
    InvalidSchemaError,
    MessageExpiredError,
    NonceReplayError,
    OversizeMessageError,
    RecipientMismatchError,
    SenderNotTrustedError,
    SequenceRegressionError,
    SignatureVerificationError,
    TokenExpiredError,
    TokenUsesExhaustedError,
    TwinLaneError,
    UntrustedParameterError,
)


def test_exception_codes() -> None:
    """Verify standard error codes across exception types."""
    err = TwinLaneError("test", code="ERR_CUSTOM")
    assert err.code == "ERR_CUSTOM"

    assert CanonicalizationError("msg").code == "ERR_CANONICALIZATION_FAILED"
    assert OversizeMessageError("msg").code == "ERR_OVERSIZE_MESSAGE"
    assert InvalidSchemaError("msg").code == "ERR_INVALID_SCHEMA"
    assert SignatureVerificationError().code == "ERR_SIGNATURE_INVALID"
    assert SenderNotTrustedError("s1").code == "ERR_SENDER_NOT_TRUSTED"
    assert RecipientMismatchError("r1", "r2").code == "ERR_RECIPIENT_MISMATCH"
    assert MessageExpiredError().code == "ERR_MESSAGE_EXPIRED"
    assert ClockSkewError().code == "ERR_CLOCK_SKEW"
    assert NonceReplayError("n1").code == "ERR_REPLAY_DETECTED"
    assert SequenceRegressionError(1, 2).code == "ERR_SEQUENCE_REGRESSION"
    assert IntentNotAuthorizedError("i1").code == "ERR_INTENT_NOT_AUTHORIZED"
    assert ConstraintViolationError("p1", "d1").code == "ERR_CONSTRAINT_VIOLATION"
    assert TokenExpiredError().code == "ERR_TOKEN_EXPIRED"
    assert TokenUsesExhaustedError(10).code == "ERR_TOKEN_USES_EXHAUSTED"
    assert AttenuationViolationError("v1").code == "ERR_ATTENUATION_VIOLATION"
    assert UntrustedParameterError("p1").code == "ERR_UNTRUSTED_PARAMETER"
    assert AuditChainTamperError(0, "tamper").code == "ERR_AUDIT_TAMPER_DETECTED"
