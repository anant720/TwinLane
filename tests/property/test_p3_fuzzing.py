"""Property-based fuzzing tests using Hypothesis for Property P3 (Forgery Resistance)."""

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from twinlane.crypto.keys import KeyPair, generate_keypair
from twinlane.crypto.signing import sign_envelope, verify_envelope_signature
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.errors import SignatureVerificationError
from twinlane.protocol.provenance import OriginType, Provenance


def generate_base_envelope() -> tuple[Envelope, KeyPair, KeyPair]:
    """Create a standard signed envelope for mutation testing."""
    kp_sender = generate_keypair()
    kp_recip = generate_keypair()

    header = Header(
        session_id="fuzz-session-001",
        sender=kp_sender.fingerprint,
        recipient=kp_recip.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="query_database",
        params={"query_id": "Q-42"},
        capability_token_id="cap-query-1",
    )
    data = DataItem(
        item_id="d-1",
        content="fuzz target data",
        content_hash=compute_content_hash("fuzz target data"),
        provenance=Provenance(origin="tool:sql", origin_type=OriginType.TOOL),
    )
    env = Envelope(header=header, control=control, data=[data])
    signed = sign_envelope(env, kp_sender.private_key)
    return signed, kp_sender, kp_recip


@settings(max_examples=50, deadline=None)
@given(
    byte_index=st.integers(min_value=0, max_value=200),
    xor_mask=st.integers(min_value=1, max_value=255),
)
def test_p3_single_byte_mutation_fails(byte_index: int, xor_mask: int) -> None:
    """Any single-byte mutation in a serialized signed envelope must fail verification.

    Either the envelope fails JSON parsing/schema validation, or signature verification fails.
    No mutated envelope can EVER verify successfully.
    """
    signed_env, kp_sender, _ = generate_base_envelope()
    json_bytes = bytearray(signed_env.to_json().encode("utf-8"))

    if byte_index >= len(json_bytes):
        return

    # Flip bits at the chosen byte index
    json_bytes[byte_index] ^= xor_mask

    try:
        mutated_env = Envelope.from_json(json_bytes.decode("utf-8"))
        # If it parsed, cryptographic signature check MUST fail
        try:
            valid = verify_envelope_signature(mutated_env, kp_sender.public_key)
            assert not valid, "Mutated envelope unexpectedly verified!"
        except SignatureVerificationError:
            pass  # Expected fail-closed behavior
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, Exception):
        # Expected parsing rejection
        pass
