"""HTTP transport and FastAPI endpoint for distributed TwinLane agents."""

from collections.abc import Callable
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException

from twinlane.protocol.envelope import Envelope
from twinlane.protocol.errors import TwinLaneError
from twinlane.transport.base import Transport


class HttpTransport(Transport):
    """HTTP client transport sending envelopes to agent endpoints."""

    def __init__(self, routing_table: dict[str, str] | None = None, timeout: float = 10.0) -> None:
        self.routing_table = routing_table or {}  # recipient_fingerprint -> http URL
        self.timeout = timeout
        self._handlers: dict[str, Callable[[Envelope], Envelope | None]] = {}

    def register_endpoint(self, recipient_fingerprint: str, url: str) -> None:
        """Associate an agent fingerprint with its HTTP URL."""
        self.routing_table[recipient_fingerprint.lower()] = url

    def register_handler(
        self,
        recipient_fingerprint: str,
        handler: Callable[[Envelope], Envelope | None],
    ) -> None:
        """Register local in-memory handler if serving locally."""
        self._handlers[recipient_fingerprint.lower()] = handler

    def send(self, envelope: Envelope) -> Envelope | None:
        """POST envelope to recipient's HTTP URL."""
        recipient = envelope.header.recipient.lower()
        url = self.routing_table.get(recipient)

        if not url:
            # Fallback to local handler if registered
            if recipient in self._handlers:
                return self._handlers[recipient](envelope)
            raise TwinLaneError(f"No HTTP endpoint route known for recipient '{recipient}'")

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, json=envelope.model_dump())
                res.raise_for_status()
                if res.status_code == 204 or not res.text:
                    return None
                return Envelope.model_validate(res.json())
        except Exception as e:
            raise TwinLaneError(f"HTTP transport failed sending to '{url}': {e}") from e


def create_agent_app(handler: Callable[[Envelope], Envelope | None]) -> FastAPI:
    """Create a FastAPI application serving the standard TwinLane endpoint."""
    app = FastAPI(title="TwinLane Agent Gateway")

    @app.post("/twinlane/v1/envelope", response_model=dict[str, Any] | None)
    def receive_envelope(envelope_data: dict[str, Any]) -> dict[str, Any] | None:
        try:
            env = Envelope.model_validate(envelope_data)
            reply = handler(env)
            if reply is not None:
                return reply.model_dump()
            return None
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    return app
