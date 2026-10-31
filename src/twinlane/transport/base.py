"""Abstract transport interface for TwinLane envelope exchange."""

from abc import ABC, abstractmethod
from collections.abc import Callable

from twinlane.protocol.envelope import Envelope


class Transport(ABC):
    """Abstract communication channel between agents."""

    @abstractmethod
    def send(self, envelope: Envelope) -> Envelope | None:
        """Transmit an envelope to its designated recipient."""
        pass

    @abstractmethod
    def register_handler(
        self,
        recipient_fingerprint: str,
        handler: Callable[[Envelope], Envelope | None],
    ) -> None:
        """Register a message receiver handler for an agent fingerprint."""
        pass
