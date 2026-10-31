"""Property-based fuzzing tests for TwinLane Gate and RFC 8785 Canonical JSON."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from twinlane.capabilities.token import CapabilityToken
from twinlane.crypto.keys import generate_keypair
from twinlane.crypto.signing import sign_envelope
from twinlane.gate.gateway import Gate
from twinlane.identity.trust_store import TrustStore
from twinlane.policy.decisions import Decision
from twinlane.policy.loader import load_policy_from_str
from twinlane.protocol.canonical import canonicalize_json
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.provenance import OriginType, Provenance


@settings(max_examples=50, deadline=None)
@given(
    data=st.dictionaries(
        keys=st.text(min_size=1, max_size=10),
        values=st.one_of(
            st.integers(),
            st.text(max_size=20),
            st.booleans(),
            st.lists(st.integers(), max_size=5),
        ),
        max_size=6,
    )
)
def test_canonical_json_permutation_invariance(data: dict[str, object]) -> None:
    """Canonical JSON output must be identical regardless of key insertion order."""
    keys = list(data.keys())
    reversed_keys = list(reversed(keys))

    dict_a = {k: data[k] for k in keys}
    dict_b = {k: data[k] for k in reversed_keys}

    bytes_a = canonicalize_json(dict_a)
    bytes_b = canonicalize_json(dict_b)

    assert bytes_a == bytes_b


@settings(max_examples=25, deadline=None)
@given(
    expires_at_offset=st.integers(min_value=-10000, max_value=-1),  # In the past
)
def test_gate_rejects_expired_tokens(expires_at_offset: int) -> None:
    """Gate must deterministically reject expired capability tokens."""
    policy_str = """
version: "1.0"
mode: "strict"
intents:
  query_database:
    required_capability: "query_database"
    allowed_senders: ["*"]
"""
    policy = load_policy_from_str(policy_str)
    trust_store = TrustStore()
    kp_sender = generate_keypair()
    kp_gate = generate_keypair()
    trust_store.register(kp_sender.public_key, name="sender")
    trust_store.register(kp_gate.public_key, name="gatekeeper")

    gate = Gate(
        local_fingerprint=kp_gate.fingerprint,
        trust_store=trust_store,
        policy_config=policy,
    )

    token = CapabilityToken(
        token_id="tok-invalid",
        issuer=kp_gate.fingerprint,
        subject=kp_sender.fingerprint,
        intents=["query_database"],
        not_before=1000,
        expires_at=1000 + expires_at_offset,
        max_uses=10,
    )
    token.sign(kp_gate.private_key)
    gate.capability_store.store(token)

    header = Header(
        session_id="sess-fuzz-token",
        sender=kp_sender.fingerprint,
        recipient=kp_gate.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="query_database",
        params={},
        capability_token_id=token.token_id,
    )
    env = Envelope(header=header, control=control)
    signed = sign_envelope(env, kp_sender.private_key)

    decision = gate.process_envelope(signed)
    assert decision.decision == Decision.DENY


@settings(max_examples=25, deadline=None)
@given(
    fuzzed_hash=st.text(min_size=1, max_size=64),
    payload=st.text(min_size=1, max_size=100),
)
def test_gate_rejects_corrupted_data_provenance(fuzzed_hash: str, payload: str) -> None:
    """Gate must reject envelopes where content hash doesn't match data manifest."""
    policy_str = """
version: "1.0"
mode: "strict"
intents:
  store_data:
    required_capability: "store_data"
    allowed_senders: ["*"]
"""
    policy = load_policy_from_str(policy_str)
    trust_store = TrustStore()
    kp_sender = generate_keypair()
    kp_gate = generate_keypair()
    trust_store.register(kp_sender.public_key, name="sender")
    trust_store.register(kp_gate.public_key, name="gatekeeper")

    gate = Gate(
        local_fingerprint=kp_gate.fingerprint,
        trust_store=trust_store,
        policy_config=policy,
    )

    token = CapabilityToken(
        token_id="tok-store",
        issuer=kp_gate.fingerprint,
        subject=kp_sender.fingerprint,
        intents=["store_data"],
        not_before=1000,
        expires_at=2000000000,
        max_uses=10,
    )
    token.sign(kp_gate.private_key)
    gate.capability_store.store(token)

    header = Header(
        session_id="sess-fuzz-data",
        sender=kp_sender.fingerprint,
        recipient=kp_gate.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="store_data",
        params={},
        capability_token_id=token.token_id,
    )
    real_hash = compute_content_hash(payload)
    bad_hash = fuzzed_hash if fuzzed_hash != real_hash else "bad_hash_digest_123"

    # 1. Pydantic model validator rejects mismatched hash upon DataItem instantiation
    with pytest.raises(ValidationError, match="Content hash mismatch"):
        DataItem(
            item_id="item-fuzz",
            content=payload,
            content_hash=bad_hash,
            provenance=Provenance(origin="client", origin_type=OriginType.WEB),
        )

    # 2. Envelope model validator also rejects mismatched hash upon Envelope construction
    valid_item = DataItem(
        item_id="item-fuzz-valid",
        content=payload,
        content_hash=real_hash,
        provenance=Provenance(origin="client", origin_type=OriginType.WEB),
    )
    tampered_item = valid_item.model_copy(update={"content": payload + "_tampered"})
    with pytest.raises(ValidationError, match="Content hash mismatch"):
        Envelope(header=header, control=control, data=[tampered_item])
