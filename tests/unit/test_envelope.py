"""Unit tests for Envelope serialization and size bounds."""

import pytest

from twinlane.protocol.control import ControlLane
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.errors import OversizeMessageError


def test_envelope_json_roundtrip() -> None:
    """Envelope serializes to JSON and parses back identically."""
    header = Header(
        session_id="session-42",
        sender="ed25519:sender",
        recipient="ed25519:recip",
        seq=10,
    )
    control = ControlLane(
        intent="ping",
        params={"code": 200},
        capability_token_id="cap-ping",
    )
    env = Envelope(header=header, control=control, data=[])

    json_str = env.to_json()
    parsed = Envelope.from_json(json_str)

    assert parsed.header.session_id == env.header.session_id
    assert parsed.header.seq == env.header.seq
    assert parsed.control.intent == env.control.intent


def test_envelope_oversize_rejected() -> None:
    """Oversize envelope payload is rejected before parsing."""
    large_json = "{" + "a" * 2000 + "}"
    with pytest.raises(OversizeMessageError):
        Envelope.from_json(large_json, max_bytes=1000)
