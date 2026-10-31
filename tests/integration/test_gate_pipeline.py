"""End-to-end integration tests for the full 7-step Gate verification pipeline."""

from typing import Any

import pytest

from twinlane.capabilities.token import CapabilityToken
from twinlane.crypto.keys import KeyPair, generate_keypair
from twinlane.crypto.signing import sign_envelope
from twinlane.gate.gateway import Gate
from twinlane.identity.trust_store import TrustStore
from twinlane.policy.decisions import Decision
from twinlane.policy.loader import load_policy_from_str
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.provenance import IntegrityLabel, OriginType, Provenance

INTEGRATION_POLICY: str = """
version: "1.0"
mode: "balanced"
intents:
  report_result:
    required_capability: "report_result"
    allowed_senders: ["*"]
    parameters:
      task_id:
        type: "string"
        provenance_required: "TRUSTED_OR_SANCTIONED"
      status:
        type: "string"
        enum: ["SUCCESS", "FAILED"]
  send_email:
    required_capability: "send_email"
    allowed_senders: ["*"]
    parameters:
      recipient:
        type: "string"
        allowlist: ["admin@corp.local"]
        provenance_required: "TRUSTED_OR_SANCTIONED"
      subject:
        type: "string"
        provenance_required: "TRUSTED"
"""


@pytest.fixture
def test_setup() -> tuple[Gate, KeyPair, KeyPair, CapabilityToken]:
    """Fixture providing initialized Gate, keys, and valid capability token."""
    kp_gate = generate_keypair()
    kp_sender = generate_keypair()

    trust_store = TrustStore()
    trust_store.register(kp_gate.public_key, name="gate-agent")
    trust_store.register(kp_sender.public_key, name="worker-agent")

    policy_cfg = load_policy_from_str(INTEGRATION_POLICY)
    gate = Gate(
        local_fingerprint=kp_gate.fingerprint,
        trust_store=trust_store,
        policy_config=policy_cfg,
    )

    # Issue root token to worker
    token = CapabilityToken(
        token_id="cap-worker-001",
        issuer=kp_gate.fingerprint,
        subject=kp_sender.fingerprint,
        intents=["report_result", "send_email"],
        constraints={"send_email": {"recipient_allowlist": ["admin@corp.local"]}},
    ).sign(kp_gate.private_key)

    gate.capability_store.store(token)
    return gate, kp_gate, kp_sender, token


def test_gate_valid_envelope_allowed(test_setup: Any) -> None:
    """A valid, signed envelope covered by a capability token is ALLOWED."""
    gate, kp_gate, kp_sender, token = test_setup

    header = Header(
        session_id="session-e2e-1",
        sender=kp_sender.fingerprint,
        recipient=kp_gate.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="report_result",
        params={"task_id": "task-42", "status": "SUCCESS"},
        capability_token_id=token.token_id,
    )
    content = "Some raw worker logs"
    data = [
        DataItem(
            item_id="d1",
            content=content,
            content_hash=compute_content_hash(content),
            provenance=Provenance(origin="tool:worker", origin_type=OriginType.TOOL),
        )
    ]
    env = Envelope(header=header, control=control, data=data)
    signed_env = sign_envelope(env, kp_sender.private_key)

    decision = gate.process_envelope(signed_env)
    assert decision.decision == Decision.ALLOW

    # Verify audit record was created and hash-chained
    last_rec = gate.last_audit_record()
    assert last_rec is not None
    assert last_rec.decision == "ALLOW"
    assert last_rec.intent == "report_result"


def test_gate_step1_unknown_sender_denied(test_setup: Any) -> None:
    """An envelope from an unknown sender is rejected at Step 1."""
    gate, kp_gate, _, token = test_setup
    kp_unknown = generate_keypair()

    header = Header(
        session_id="session-e2e-2",
        sender=kp_unknown.fingerprint,
        recipient=kp_gate.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="report_result",
        params={"task_id": "task-42", "status": "SUCCESS"},
        capability_token_id=token.token_id,
    )
    env = Envelope(header=header, control=control, data=[])
    signed_env = sign_envelope(env, kp_unknown.private_key)

    decision = gate.process_envelope(signed_env)
    assert decision.decision == Decision.DENY
    assert decision.step_failed == 1

    last_rec = gate.last_audit_record()
    assert last_rec is not None
    assert last_rec.decision == "DENY"


def test_gate_step3_intent_not_in_token_denied(test_setup: Any) -> None:
    """An intent not in the sender's capability token is rejected at Step 3."""
    gate, kp_gate, kp_sender, token = test_setup

    # Token only grants report_result and send_email; request fetch_url
    header = Header(
        session_id="session-e2e-3",
        sender=kp_sender.fingerprint,
        recipient=kp_gate.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="fetch_url",
        params={"url": "https://example.test"},
        capability_token_id=token.token_id,
    )
    env = Envelope(header=header, control=control, data=[])
    signed_env = sign_envelope(env, kp_sender.private_key)

    decision = gate.process_envelope(signed_env)
    assert decision.decision == Decision.DENY
    assert decision.step_failed == 3

    last_rec = gate.last_audit_record()
    assert last_rec is not None
    assert last_rec.decision == "DENY"


def test_gate_step3_constraint_violation_denied(test_setup: Any) -> None:
    """Parameters violating capability constraints are rejected at Step 3."""
    gate, kp_gate, kp_sender, token = test_setup

    # Token constraints: recipient must be admin@corp.local
    header = Header(
        session_id="session-e2e-4",
        sender=kp_sender.fingerprint,
        recipient=kp_gate.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="send_email",
        params={"recipient": "attacker@evil.test", "subject": "Secret Exfil"},
        capability_token_id=token.token_id,
    )
    env = Envelope(header=header, control=control, data=[])
    signed_env = sign_envelope(env, kp_sender.private_key)

    decision = gate.process_envelope(signed_env)
    assert decision.decision == Decision.DENY
    assert decision.step_failed == 3


def test_gate_step4_strict_mode_untrusted_param_denied(test_setup: Any) -> None:
    """Strict mode immediately denies any parameter with UNTRUSTED taint at Step 4."""
    gate, kp_gate, kp_sender, token = test_setup
    gate.policy_engine.mode = "strict"

    header = Header(
        session_id="session-e2e-5",
        sender=kp_sender.fingerprint,
        recipient=kp_gate.fingerprint,
        seq=1,
    )
    control = ControlLane(
        intent="report_result",
        params={"task_id": "task-untrusted-derived", "status": "SUCCESS"},
        capability_token_id=token.token_id,
    )
    env = Envelope(header=header, control=control, data=[])
    signed_env = sign_envelope(env, kp_sender.private_key)

    # Simulate parameter tainted by untrusted data
    decision = gate.process_envelope(
        signed_env,
        param_labels={"task_id": IntegrityLabel.UNTRUSTED},
    )
    assert decision.decision == Decision.DENY
    assert decision.step_failed == 4
