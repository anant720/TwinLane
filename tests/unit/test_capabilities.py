"""Unit tests for capability tokens, intent catalog, and constraint enforcement."""

import pytest

from twinlane.capabilities.intents import IntentCatalog, IntentDefinition
from twinlane.capabilities.token import CapabilityToken
from twinlane.crypto.keys import generate_keypair
from twinlane.protocol.errors import (
    ConstraintViolationError,
    IntentNotAuthorizedError,
    TokenExpiredError,
    TokenUsesExhaustedError,
)


def test_intent_catalog_validation() -> None:
    """Intent catalog validates required and forbidden parameter keys."""
    catalog = IntentCatalog()
    catalog.register(
        IntentDefinition(
            name="custom_task",
            description="test",
            required_params=["task_id"],
            allowed_params=["task_id", "priority"],
        )
    )

    intent = catalog.get("custom_task")
    assert intent is not None

    # Valid
    intent.validate_params({"task_id": "1", "priority": "high"})

    # Missing required
    with pytest.raises(ValueError, match="Missing required parameter"):
        intent.validate_params({"priority": "high"})

    # Unknown parameter
    with pytest.raises(ValueError, match="Unknown parameter 'evil'"):
        intent.validate_params({"task_id": "1", "evil": "rm -rf"})


def test_capability_token_signing_and_verification() -> None:
    """Capability token signing and cryptographic verification."""
    kp_root = generate_keypair()
    kp_worker = generate_keypair()

    token = CapabilityToken(
        issuer=kp_root.fingerprint,
        subject=kp_worker.fingerprint,
        intents=["report_result", "fetch_url"],
    )
    signed_token = token.sign(kp_root.private_key)
    assert signed_token.signature is not None
    assert signed_token.verify_signature(kp_root.public_key) is True


def test_capability_token_intent_check() -> None:
    """Unauthorized intent raises IntentNotAuthorizedError."""
    kp_root = generate_keypair()
    kp_worker = generate_keypair()

    token = CapabilityToken(
        issuer=kp_root.fingerprint,
        subject=kp_worker.fingerprint,
        intents=["report_result"],
    )

    # Allowed
    token.check_authorization("report_result", {})

    # Denied
    with pytest.raises(IntentNotAuthorizedError):
        token.check_authorization("delete_database", {})


def test_capability_token_constraint_violations() -> None:
    """Parameters violating constraints raise ConstraintViolationError."""
    kp_root = generate_keypair()
    kp_worker = generate_keypair()

    token = CapabilityToken(
        issuer=kp_root.fingerprint,
        subject=kp_worker.fingerprint,
        intents=["send_email", "transfer_funds"],
        constraints={
            "send_email": {
                "recipient_allowlist": ["allowed@example.test"],
            },
            "transfer_funds": {
                "amount_max": 500,
                "memo_prefix": "PAY-",
            },
        },
    )

    # Allowlist pass and fail
    token.check_authorization("send_email", {"recipient": "allowed@example.test"})
    with pytest.raises(ConstraintViolationError, match="not in allowed list"):
        token.check_authorization("send_email", {"recipient": "evil@attacker.test"})

    # Max limit pass and fail
    token.check_authorization("transfer_funds", {"amount": 250, "memo": "PAY-12"})
    with pytest.raises(ConstraintViolationError, match="exceeds maximum limit"):
        token.check_authorization("transfer_funds", {"amount": 1000, "memo": "PAY-12"})

    # Prefix pass and fail
    with pytest.raises(ConstraintViolationError, match="must start with prefix"):
        token.check_authorization("transfer_funds", {"amount": 100, "memo": "HACK-12"})


def test_capability_token_usage_and_expiry() -> None:
    """Usage limits and temporal windows are strictly checked."""
    kp_root = generate_keypair()
    kp_worker = generate_keypair()

    # Expired token
    expired_token = CapabilityToken(
        issuer=kp_root.fingerprint,
        subject=kp_worker.fingerprint,
        intents=["ping"],
        not_before=100,
        expires_at=200,
    )
    with pytest.raises(TokenExpiredError):
        expired_token.check_authorization("ping", {}, now=300)

    # Exhausted quota
    quota_token = CapabilityToken(
        issuer=kp_root.fingerprint,
        subject=kp_worker.fingerprint,
        intents=["ping"],
        max_uses=1,
    )
    quota_token.check_authorization("ping", {})
    quota_token.record_usage()
    with pytest.raises(TokenUsesExhaustedError):
        quota_token.check_authorization("ping", {})
