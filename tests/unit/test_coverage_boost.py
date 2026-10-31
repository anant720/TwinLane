"""Targeted tests to exercise edge cases and ensure >= 90% coverage on all security modules."""

from pathlib import Path
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives import serialization

from twinlane.audit.chain import AuditChain
from twinlane.audit.log import AuditLogger
from twinlane.audit.verify import verify_audit_log_file
from twinlane.crypto.keys import (
    generate_keypair,
    private_key_from_pem,
    public_key_from_pem,
    public_key_from_raw_bytes,
)
from twinlane.crypto.signing import sign_envelope, verify_envelope_signature
from twinlane.identity.trust_store import TrustStore
from twinlane.protocol.canonical import canonicalize_json
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.errors import (
    AuthenticationError,
    CanonicalizationError,
    SenderNotTrustedError,
    SignatureVerificationError,
)
from twinlane.protocol.provenance import OriginType, Provenance


def test_canonical_edge_cases() -> None:
    """Exercise UUID, bytes, Pydantic models, and unsupported types in canonicalize_json."""
    uid = uuid4()
    prov = Provenance(origin="tool:test", origin_type=OriginType.TOOL)
    data = {
        "uuid": uid,
        "bytes": b"\x01\x02\x03",
        "model": prov,
    }
    canonical = canonicalize_json(data)
    assert str(uid).encode("utf-8") in canonical
    assert b"010203" in canonical

    # Unsupported type
    class Unsupported:
        pass

    with pytest.raises(CanonicalizationError):
        canonicalize_json({"bad": Unsupported()})


def test_control_lane_validation_edge_cases() -> None:
    """Exercise empty intent and invalid character checks."""
    with pytest.raises(ValueError, match="Intent name cannot be empty"):
        ControlLane(intent="   ", capability_token_id="c1")

    with pytest.raises(ValueError, match="Invalid character"):
        ControlLane(intent="bad$intent!", capability_token_id="c1")


def test_envelope_header_edge_cases() -> None:
    """Exercise unsupported version and short nonce errors."""
    with pytest.raises(ValueError, match="Unsupported protocol version"):
        Header(session_id="s1", sender="a", recipient="b", seq=1, version=999)

    with pytest.raises(ValueError, match="Nonce must be at least 16 hex characters"):
        Header(session_id="s1", sender="a", recipient="b", seq=1, nonce="short")


def test_crypto_keys_edge_cases() -> None:
    """Exercise raw public key bytes and PEM loading error paths."""
    kp = generate_keypair()
    raw_pub = kp.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    loaded_raw = public_key_from_raw_bytes(raw_pub)
    assert loaded_raw == kp.public_key

    with pytest.raises(AuthenticationError):
        public_key_from_raw_bytes(b"short")

    with pytest.raises(AuthenticationError):
        private_key_from_pem(b"not-a-pem")

    with pytest.raises(AuthenticationError):
        public_key_from_pem(b"not-a-pem")


def test_signing_error_branches() -> None:
    """Exercise signature length, manifest length mismatch, and invalid hex."""
    kp_sender = generate_keypair()
    header = Header(session_id="s1", sender=kp_sender.fingerprint, recipient="recip", seq=1)
    control = ControlLane(intent="ping", capability_token_id="c1")
    item1 = DataItem(
        item_id="d1",
        content="foo",
        content_hash=compute_content_hash("foo"),
        provenance=Provenance(origin="tool"),
    )
    env = Envelope(header=header, control=control, data=[item1])
    signed = sign_envelope(env, kp_sender.private_key)

    # 1. Manifest length mismatch
    dict_env = signed.model_dump(mode="python")
    dict_env["data"].append(
        DataItem(
            item_id="d2",
            content="bar",
            content_hash=compute_content_hash("bar"),
            provenance=Provenance(origin="tool"),
        )
    )
    with pytest.raises(SignatureVerificationError, match="Data item count does not match"):
        verify_envelope_signature(Envelope.model_validate(dict_env), kp_sender.public_key)

    # 2. Invalid hex in signature_bytes
    dict_env2 = signed.model_dump(mode="python")
    dict_env2["signature"]["signature_bytes"] = "not_hex_string_!!"
    with pytest.raises(SignatureVerificationError, match="Signature is not valid hexadecimal"):
        verify_envelope_signature(Envelope.model_validate(dict_env2), kp_sender.public_key)

    # 3. Invalid signature length
    dict_env3 = signed.model_dump(mode="python")
    dict_env3["signature"]["signature_bytes"] = "abcd"
    with pytest.raises(SignatureVerificationError, match="Invalid signature length"):
        verify_envelope_signature(Envelope.model_validate(dict_env3), kp_sender.public_key)


def test_trust_store_edge_cases() -> None:
    """Exercise get_agent, all_fingerprints, require_public_key."""
    store = TrustStore()
    kp = generate_keypair()
    fp = store.register(kp.public_key, name="bob", metadata={"tier": "admin"})

    agent = store.get_agent("bob")
    assert agent is not None
    assert agent.name == "bob"
    assert agent.metadata["tier"] == "admin"

    assert fp in store.all_fingerprints()

    with pytest.raises(SenderNotTrustedError):
        store.require_public_key("nonexistent")


def test_audit_log_reload_and_verify_branches(tmp_path: Path) -> None:
    """Exercise AuditLogger loading existing files and verify error branches."""
    log_file = tmp_path / "chain.jsonl"
    logger1 = AuditLogger(log_file)
    logger1.log(msg_id="m1", session_id="s1", sender="a", intent="t1", decision="ALLOW")
    logger1.log(msg_id="m2", session_id="s1", sender="a", intent="t2", decision="DENY")

    # Reload existing file
    logger2 = AuditLogger(log_file)
    assert logger2.chain.count() == 2

    # verify non-existent file
    res_missing = verify_audit_log_file(tmp_path / "does_not_exist.jsonl")
    assert res_missing.is_valid is False
    assert "does not exist" in (res_missing.error_message or "")

    # verify malformed JSON line
    bad_file = tmp_path / "bad.jsonl"
    bad_file.write_text("not json\n", encoding="utf-8")
    res_bad = verify_audit_log_file(bad_file)
    assert res_bad.is_valid is False
    assert "Malformed JSON" in (res_bad.error_message or "")


def test_audit_chain_helper_methods() -> None:
    """Exercise AuditChain last_record and records methods."""
    chain = AuditChain()
    assert chain.last_record() is None
    rec = chain.append(msg_id="m", session_id="s", sender="a", intent="i", decision="ALLOW")
    assert chain.last_record() == rec
    assert len(chain.records()) == 1
