"""Unit tests for PolicyEngine and YAML policy loading."""

import pytest

from twinlane.policy.decisions import Decision
from twinlane.policy.engine import PolicyEngine
from twinlane.policy.loader import load_policy_from_str, load_policy_from_yaml
from twinlane.protocol.control import ControlLane
from twinlane.protocol.envelope import Header
from twinlane.protocol.errors import InvalidSchemaError
from twinlane.protocol.provenance import IntegrityLabel

SAMPLE_POLICY: str = """
version: "1.0"
mode: "strict"
intents:
  send_email:
    required_capability: "send_email"
    allowed_senders: ["ed25519:alice"]
    parameters:
      recipient:
        type: "string"
        allowlist: ["allowed@corp.local"]
        provenance_required: "TRUSTED"
      amount:
        type: "number"
        min_value: 10
        max_value: 1000
      code:
        type: "string"
        pattern: "^[A-Z]{3}$"
        max_length: 3
      category:
        type: "string"
        enum: ["finance", "ops"]
"""


def test_policy_strict_mode_blocks_untrusted_parameters() -> None:
    """Strict mode blocks any parameter derived from untrusted sources."""
    config = load_policy_from_str(SAMPLE_POLICY)
    engine = PolicyEngine(config)

    header = Header(session_id="s1", sender="ed25519:alice", recipient="b", seq=1)
    control = ControlLane(
        intent="send_email",
        params={"recipient": "allowed@corp.local", "amount": 100},
        capability_token_id="c1",
    )

    # 1. Trusted param -> ALLOW
    res_trusted = engine.evaluate(
        header,
        control,
        param_labels={"recipient": IntegrityLabel.TRUSTED},
    )
    assert res_trusted.decision == Decision.ALLOW

    # 2. Untrusted param -> DENY in strict mode
    res_untrusted = engine.evaluate(
        header,
        control,
        param_labels={"recipient": IntegrityLabel.UNTRUSTED},
    )
    assert res_untrusted.decision == Decision.DENY
    assert "strict mode" in res_untrusted.violations[0]


def test_policy_balanced_mode() -> None:
    """Balanced mode allows EXTRACTED_UNTRUSTED parameters."""
    cfg_balanced = load_policy_from_str(SAMPLE_POLICY.replace('mode: "strict"', 'mode: "balanced"'))
    engine = PolicyEngine(cfg_balanced)

    header = Header(session_id="s1", sender="ed25519:alice", recipient="b", seq=1)
    control = ControlLane(
        intent="send_email",
        params={"recipient": "allowed@corp.local", "amount": 50},
        capability_token_id="c1",
    )

    res = engine.evaluate(
        header,
        control,
        param_labels={"recipient": IntegrityLabel.EXTRACTED_UNTRUSTED},
    )
    assert res.decision == Decision.ALLOW

    # Raw untrusted in balanced mode must fail
    res_raw = engine.evaluate(
        header,
        control,
        param_labels={"recipient": IntegrityLabel.UNTRUSTED},
    )
    assert res_raw.decision == Decision.DENY
    assert "without sanctioned extraction" in res_raw.violations[0]


def test_policy_observe_mode() -> None:
    """Observe mode logs violations but returns ALLOW for benchmark tracking."""
    cfg_observe = load_policy_from_str(SAMPLE_POLICY.replace('mode: "strict"', 'mode: "observe"'))
    engine = PolicyEngine(cfg_observe)

    header = Header(session_id="s1", sender="ed25519:alice", recipient="b", seq=1)
    # Violate max amount (9999 > 1000)
    control = ControlLane(
        intent="send_email",
        params={"recipient": "allowed@corp.local", "amount": 9999},
        capability_token_id="c1",
    )

    res = engine.evaluate(header, control)
    assert res.decision == Decision.ALLOW
    assert res.reason == "OBSERVE_MODE_ALLOWED"
    assert len(res.violations) >= 1


def test_policy_parameter_validations() -> None:
    """Test pattern, enum, min_value, and max_length validations."""
    config = load_policy_from_str(SAMPLE_POLICY)
    engine = PolicyEngine(config)
    header = Header(session_id="s1", sender="ed25519:alice", recipient="b", seq=1)

    # Invalid pattern and length
    control = ControlLane(
        intent="send_email",
        params={
            "recipient": "allowed@corp.local",
            "amount": 5,  # below min 10
            "code": "TOOLONG",  # exceeds max_length 3 and fails regex
            "category": "marketing",  # not in enum
        },
        capability_token_id="c1",
    )

    res = engine.evaluate(header, control, param_labels={"recipient": IntegrityLabel.TRUSTED})
    assert res.decision == Decision.DENY
    assert any("does not match regex" in v for v in res.violations)
    assert any("exceeds maximum 3" in v for v in res.violations)
    assert any("not in enum" in v for v in res.violations)
    assert any("below minimum 10" in v for v in res.violations)


def test_policy_disallowed_intent_and_sender() -> None:
    """Test policy rejecting unconfigured intents or unauthorized senders."""
    config = load_policy_from_str(SAMPLE_POLICY)
    engine = PolicyEngine(config)

    # 1. Unknown intent
    header1 = Header(session_id="s1", sender="ed25519:alice", recipient="b", seq=1)
    control1 = ControlLane(intent="drop_table", params={}, capability_token_id="c1")
    res1 = engine.evaluate(header1, control1)
    assert res1.decision == Decision.DENY
    assert "not in policy catalog" in res1.violations[0]

    # 2. Unauthorized sender
    header2 = Header(session_id="s1", sender="ed25519:mallory", recipient="b", seq=1)
    control2 = ControlLane(
        intent="send_email",
        params={"recipient": "allowed@corp.local"},
        capability_token_id="c1",
    )
    res2 = engine.evaluate(header2, control2)
    assert res2.decision == Decision.DENY
    assert "not in allowed senders" in res2.violations[0]


def test_load_policy_from_yaml_file() -> None:
    """Test loading valid and invalid YAML files."""
    # 1. Load default YAML from repo
    default_cfg = load_policy_from_yaml("src/twinlane/policy/rules/default.yaml")
    assert default_cfg.version == "1.0"
    assert "report_result" in default_cfg.intents

    # 2. Non-existent file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        load_policy_from_yaml("nonexistent_policy_file.yaml")

    # 3. Non-mapping yaml content raises InvalidSchemaError
    with pytest.raises(InvalidSchemaError, match="must define a root mapping"):
        load_policy_from_str("just a string")

    # 4. Invalid schema yaml content raises InvalidSchemaError
    with pytest.raises(InvalidSchemaError):
        load_policy_from_str("version: 123\nmode: 456\nextra_forbidden_field: true")
