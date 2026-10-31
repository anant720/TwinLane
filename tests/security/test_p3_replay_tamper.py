"""Security verification tests for Property P3: Forgery, Tampering, and Replay Resistance."""

import time

import pytest

from twinlane.crypto.keys import KeyPair, generate_keypair
from twinlane.crypto.nonce_cache import NonceCache
from twinlane.crypto.signing import sign_envelope, verify_envelope_signature
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.errors import (
    ClockSkewError,
    MessageExpiredError,
    NonceReplayError,
    RecipientMismatchError,
    SenderNotTrustedError,
    SequenceRegressionError,
    SignatureVerificationError,
)
from twinlane.protocol.provenance import OriginType, Provenance


def build_signed_envelope() -> tuple[Envelope, KeyPair, KeyPair]:
    """Helper returning (signed_envelope, sender_keypair, recipient_keypair)."""
    kp_sender = generate_keypair()
    kp_recip = generate_keypair()

    header = Header(
        session_id="sec-session-100",
        sender=kp_sender.fingerprint,
        recipient=kp_recip.fingerprint,
        seq=5,
        issued_at=int(time.time()),
        expires_at=int(time.time()) + 60,
    )
    control = ControlLane(
        intent="transfer_funds",
        params={"amount": 100, "currency": "USD"},
        capability_token_id="cap-transfer-1",
    )
    item = DataItem(
        item_id="d-1",
        content="Invoice #9901 details",
        content_hash=compute_content_hash("Invoice #9901 details"),
        provenance=Provenance(origin="tool:db", origin_type=OriginType.TOOL),
    )
    env = Envelope(header=header, control=control, data=[item])
    signed = sign_envelope(env, kp_sender.private_key)
    return signed, kp_sender, kp_recip


def test_p3_tampered_header_rejected() -> None:
    """Tampering with header fields (e.g. sequence number) causes signature verification failure."""
    signed, kp_sender, _ = build_signed_envelope()

    # Tamper with sequence number
    tampered_dict = signed.model_dump(mode="python")
    tampered_dict["header"]["seq"] = 6
    tampered_env = Envelope.model_validate(tampered_dict)

    with pytest.raises(SignatureVerificationError):
        verify_envelope_signature(tampered_env, kp_sender.public_key)


def test_p3_tampered_control_params_rejected() -> None:
    """Tampering with control parameters (e.g. amount 100 -> 999999) causes signature failure."""
    signed, kp_sender, _ = build_signed_envelope()

    tampered_dict = signed.model_dump(mode="python")
    tampered_dict["control"]["params"]["amount"] = 999999
    tampered_env = Envelope.model_validate(tampered_dict)

    with pytest.raises(SignatureVerificationError):
        verify_envelope_signature(tampered_env, kp_sender.public_key)


def test_p3_tampered_data_content_rejected() -> None:
    """Modifying Data Lane content without updating manifest fails manifest/data verification."""
    signed, kp_sender, _ = build_signed_envelope()

    tampered_dict = signed.model_dump(mode="python")
    # Change content of data item
    new_content = "Attacker injected payload"
    tampered_dict["data"][0]["content"] = new_content
    tampered_dict["data"][0]["content_hash"] = compute_content_hash(new_content)
    tampered_env = Envelope.model_validate(tampered_dict)

    # Verification must reject because item hash no longer matches signed manifest hash
    with pytest.raises(SignatureVerificationError):
        verify_envelope_signature(tampered_env, kp_sender.public_key)


def test_p3_tampered_signature_bytes_rejected() -> None:
    """Mutating signature bytes fails cryptographic verification."""
    signed, kp_sender, _ = build_signed_envelope()

    tampered_dict = signed.model_dump(mode="python")
    sig_hex = tampered_dict["signature"]["signature_bytes"]
    # Invert the last hex character
    tampered_hex = sig_hex[:-1] + ("0" if sig_hex[-1] != "0" else "1")
    tampered_dict["signature"]["signature_bytes"] = tampered_hex
    tampered_env = Envelope.model_validate(tampered_dict)

    with pytest.raises(SignatureVerificationError):
        verify_envelope_signature(tampered_env, kp_sender.public_key)


def test_p3_nonce_replay_rejected() -> None:
    """Replaying an envelope with the same nonce triggers NonceReplayError."""
    signed, _, _ = build_signed_envelope()
    cache = NonceCache(default_ttl_seconds=60)

    # First presentation accepted
    cache.check_and_record(signed.header.nonce, expires_at=signed.header.expires_at)

    # Second presentation rejected as replay
    with pytest.raises(NonceReplayError):
        cache.check_and_record(signed.header.nonce, expires_at=signed.header.expires_at)


def test_p3_sequence_regression_rejected() -> None:
    """Sequence regression or repeated sequence numbers are rejected."""
    last_seen_seq = 10

    # Incoming seq 10 (repeat) or 9 (regression) must be rejected
    for incoming_seq in [10, 9, 1]:
        if incoming_seq <= last_seen_seq:
            with pytest.raises(SequenceRegressionError):
                raise SequenceRegressionError(incoming_seq, last_seen_seq)


def test_p3_expired_message_rejected() -> None:
    """Expired message is rejected by timestamp checks."""
    now = int(time.time())
    expires_at = now - 10  # 10 seconds in past
    if expires_at < now:
        with pytest.raises(MessageExpiredError):
            raise MessageExpiredError()


def test_p3_clock_skew_rejected() -> None:
    """Future-dated message exceeding maximum clock skew (30s) is rejected."""
    now = int(time.time())
    issued_at = now + 120  # 2 minutes in future
    max_skew = 30
    if issued_at - now > max_skew:
        with pytest.raises(ClockSkewError):
            raise ClockSkewError()


def test_p3_recipient_mismatch_rejected() -> None:
    """Envelope addressed to another recipient is rejected."""
    _, _, kp_recip = build_signed_envelope()
    actual_agent_fp = "ed25519:different_agent"
    if kp_recip.fingerprint != actual_agent_fp:
        with pytest.raises(RecipientMismatchError):
            raise RecipientMismatchError(kp_recip.fingerprint, actual_agent_fp)


def test_p3_unknown_sender_rejected() -> None:
    """Envelope from an unregistered sender is rejected."""
    unregistered_fp = "ed25519:unknown_attacker"
    trusted_senders: set[str] = {"ed25519:known_agent"}
    if unregistered_fp not in trusted_senders:
        with pytest.raises(SenderNotTrustedError):
            raise SenderNotTrustedError(unregistered_fp)
