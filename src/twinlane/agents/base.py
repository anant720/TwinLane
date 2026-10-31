"""Base agent implementation with cryptographic identity and envelope dispatch."""

import time
from abc import ABC, abstractmethod

from twinlane.agents.tools.base import ToolRegistry
from twinlane.crypto.keys import KeyPair, generate_keypair
from twinlane.crypto.signing import sign_envelope
from twinlane.identity.trust_store import TrustStore
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem
from twinlane.protocol.envelope import Envelope, Header
from twinlane.protocol.version import PROTOCOL_VERSION
from twinlane.transport.base import Transport


class BaseAgent(ABC):
    """Abstract agent with an Ed25519 identity, tools, and message exchange capabilities."""

    def __init__(
        self,
        name: str,
        keypair: KeyPair | None = None,
        trust_store: TrustStore | None = None,
        tool_registry: ToolRegistry | None = None,
        transport: Transport | None = None,
    ) -> None:
        self.name = name
        self.keypair = keypair or generate_keypair()
        self.trust_store = trust_store or TrustStore()
        self.trust_store.register(self.keypair.public_key, name=self.name)
        self.tools = tool_registry or ToolRegistry()
        self.transport = transport
        self.seq_out = 0

    @property
    def fingerprint(self) -> str:
        """Agent's public key fingerprint (RFC 8785 Ed25519)."""
        return self.keypair.fingerprint

    def create_envelope(
        self,
        recipient: str,
        session_id: str,
        control: ControlLane,
        data: list[DataItem] | None = None,
        ttl_seconds: int = 60,
    ) -> Envelope:
        """Create and cryptographically sign a TwinLane envelope."""
        self.seq_out += 1
        now = int(time.time())

        header = Header(
            version=PROTOCOL_VERSION,
            session_id=session_id,
            sender=self.fingerprint,
            recipient=recipient,
            seq=self.seq_out,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )

        unsigned_env = Envelope(
            header=header,
            control=control,
            data=data or [],
        )

        return sign_envelope(
            envelope=unsigned_env,
            private_key=self.keypair.private_key,
        )

    def send_envelope(self, envelope: Envelope) -> Envelope | None:
        """Transmit envelope via the configured transport."""
        if not self.transport:
            raise RuntimeError(f"No transport configured on agent '{self.name}'")
        return self.transport.send(envelope)

    @abstractmethod
    def handle_envelope(self, envelope: Envelope) -> Envelope | None:
        """Handle incoming envelope received from a peer agent."""
        pass
