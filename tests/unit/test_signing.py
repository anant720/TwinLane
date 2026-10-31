"""Unit tests for envelope signing and verification."""

import pytest

from twinlane.crypto.keys import generate_keypair
from twinlane.crypto.signing import sign_envelope, verify_envelope_signature
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.errors import SignatureVerificationError
from twinlane.protocol.provenance import OriginType, Provenance


def create_sample_envelope(sender_fp: str, recipient_fp: str) -> Envelope:
    """Helper to create a well-formed test envelope."""
    header = Header(
        session_id="test-session-1",
        sender=sender_fp,
        recipient=recipient_fp,
        seq=1,
    )
    control = ControlLane(
        intent="fetch_data",
        params={"dataset": "financial_records"},
        capability_token_id="cap-001",
    )
    content = "Hello, passive untrusted data."
    data_item = DataItem(
        item_id="item-1",
        content=content,
        content_hash=compute_content_hash(content),
        provenance=Provenance(
            origin="web:https://example.test",
            origin_type=OriginType.WEB,
        ),
    )
    return Envelope(header=header, control=control, data=[data_item])


def test_sign_and_verify_valid_envelope() -> None:
    """Signing an envelope produces valid signature verified by public key."""
    kp_sender = generate_keypair()
    kp_recipient = generate_keypair()

    env = create_sample_envelope(kp_sender.fingerprint, kp_recipient.fingerprint)
    signed_env = sign_envelope(env, kp_sender.private_key)

    assert signed_env.signature is not None
    assert signed_env.signature.signer == kp_sender.fingerprint
    assert len(signed_env.signature.signed_manifest) == 1

    # Verification must succeed
    assert verify_envelope_signature(signed_env, kp_sender.public_key) is True


def test_verify_fails_with_wrong_key() -> None:
    """Verifying with a different public key raises SignatureVerificationError."""
    kp_sender = generate_keypair()
    kp_other = generate_keypair()
    kp_recipient = generate_keypair()

    env = create_sample_envelope(kp_sender.fingerprint, kp_recipient.fingerprint)
    signed_env = sign_envelope(env, kp_sender.private_key)

    with pytest.raises(SignatureVerificationError):
        verify_envelope_signature(signed_env, kp_other.public_key)
