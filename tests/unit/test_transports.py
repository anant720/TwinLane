"""Unit tests for InProcTransport and HttpTransport."""

from typing import Any

import pytest

from twinlane.crypto.keys import generate_keypair
from twinlane.crypto.signing import sign_envelope
from twinlane.protocol.control import ControlLane
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.errors import RecipientMismatchError, TwinLaneError
from twinlane.transport.http import HttpTransport, create_agent_app
from twinlane.transport.inproc import InProcTransport


def test_inproc_transport() -> None:
    """Test in-memory message routing between agents."""
    kp_a = generate_keypair()
    kp_b = generate_keypair()

    transport = InProcTransport()
    received: list[Envelope] = []

    def b_handler(env: Envelope) -> Envelope | None:
        received.append(env)
        return None

    transport.register_handler(kp_b.fingerprint, b_handler)

    header = Header(
        session_id="s1",
        sender=kp_a.fingerprint,
        recipient=kp_b.fingerprint,
        seq=1,
    )
    control = ControlLane(intent="ping", params={}, capability_token_id="c1")
    env = sign_envelope(
        Envelope(header=header, control=control),
        kp_a.private_key,
    )

    # Delivery succeeds
    transport.send(env)
    assert len(received) == 1
    assert received[0].header.sender == kp_a.fingerprint

    # Unknown recipient raises RecipientMismatchError
    header_unknown = Header(
        session_id="s1",
        sender=kp_a.fingerprint,
        recipient="ed25519:unknown",
        seq=2,
    )
    env_unknown = sign_envelope(
        Envelope(header=header_unknown, control=control),
        kp_a.private_key,
    )
    with pytest.raises(RecipientMismatchError, match="Recipient 'ed25519:unknown' does not match"):
        transport.send(env_unknown)


def test_http_transport_fastapi_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test FastAPI agent endpoint and HTTP transport routing."""
    kp_a = generate_keypair()
    kp_b = generate_keypair()

    def mock_server_handler(env: Envelope) -> Envelope | None:
        # Echo back a response envelope
        resp_header = Header(
            session_id=env.header.session_id,
            sender=kp_b.fingerprint,
            recipient=kp_a.fingerprint,
            seq=1,
        )
        resp_control = ControlLane(intent="pong", params={"ack": True}, capability_token_id="c1")
        return sign_envelope(
            Envelope(header=resp_header, control=resp_control),
            kp_b.private_key,
        )

    app = create_agent_app(mock_server_handler)

    # 1. Test endpoint handler with valid envelope data
    header = Header(
        session_id="s-http-1",
        sender=kp_a.fingerprint,
        recipient=kp_b.fingerprint,
        seq=1,
    )
    control = ControlLane(intent="ping", params={}, capability_token_id="c1")
    env = sign_envelope(
        Envelope(header=header, control=control),
        kp_a.private_key,
    )

    # Find registered endpoint route
    endpoint_func = None
    for route in app.routes:
        if getattr(route, "path", None) == "/twinlane/v1/envelope":
            endpoint_func = getattr(route, "endpoint", None)
            break
    assert endpoint_func is not None

    res_data = endpoint_func(env.model_dump())
    assert res_data is not None
    assert res_data["control"]["intent"] == "pong"

    # 2. Test HttpTransport error when route is missing
    transport = HttpTransport()
    with pytest.raises(TwinLaneError, match="No HTTP endpoint route known"):
        transport.send(env)

    # 3. Test HttpTransport local handler fallback
    transport.register_handler(kp_b.fingerprint, mock_server_handler)
    res_local = transport.send(env)
    assert res_local is not None
    assert res_local.control.intent == "pong"

    # 4. Test HttpTransport sending to remote URL with mock
    transport_remote = HttpTransport()
    transport_remote.register_endpoint(
        kp_b.fingerprint, "http://remote-agent.local/twinlane/v1/envelope"
    )

    class MockRemoteResponse:
        status_code = 200
        text = '{"dummy": "data"}'

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return dict(res_data)

    class MockRemoteHttpClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "MockRemoteHttpClient":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def post(self, _url: str, **_kwargs: object) -> MockRemoteResponse:
            return MockRemoteResponse()

    monkeypatch.setattr("twinlane.transport.http.httpx.Client", MockRemoteHttpClient)
    res_remote = transport_remote.send(env)
    assert res_remote is not None
    assert res_remote.control.intent == "pong"
