"""In-process message transport for tests, benchmarks, and local execution."""

from collections.abc import Callable

from twinlane.protocol.envelope import Envelope
from twinlane.protocol.errors import RecipientMismatchError
from twinlane.transport.base import Transport


class InProcTransport(Transport):
    """Direct in-memory message transport."""

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[[Envelope], Envelope | None]] = {}
        self.history: list[Envelope] = []

    def register_handler(
        self,
        recipient_fingerprint: str,
        handler: Callable[[Envelope], Envelope | None],
    ) -> None:
        """Register a handler callback for a recipient agent."""
        self._handlers[recipient_fingerprint.lower()] = handler

    def send(self, envelope: Envelope) -> Envelope | None:
        """Deliver envelope synchronously to registered recipient handler."""
        self.history.append(envelope)
        recipient = envelope.header.recipient.lower()

        handler = self._handlers.get(recipient)
        if not handler:
            raise RecipientMismatchError(recipient=recipient, expected="registered handler")

        return handler(envelope)
