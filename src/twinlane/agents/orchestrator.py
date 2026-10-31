"""Orchestrator agent coordinating tasks, issuing capabilities, and enforcing the Gate."""

import time
from typing import Any

import structlog

from twinlane.agents.base import BaseAgent
from twinlane.agents.tools.base import ToolRegistry
from twinlane.capabilities.token import CapabilityToken
from twinlane.crypto.keys import KeyPair
from twinlane.gate.gateway import Gate
from twinlane.identity.trust_store import TrustStore
from twinlane.policy.decisions import Decision, GateDecision
from twinlane.policy.loader import PolicyConfig
from twinlane.protocol.control import ControlLane
from twinlane.protocol.envelope import Envelope
from twinlane.transport.base import Transport

logger = structlog.get_logger(__name__)


class OrchestratorAgent(BaseAgent):
    """Primary orchestrating agent with an integrated deterministic TwinLane Gate."""

    def __init__(
        self,
        name: str = "orchestrator-agent",
        keypair: KeyPair | None = None,
        trust_store: TrustStore | None = None,
        tool_registry: ToolRegistry | None = None,
        transport: Transport | None = None,
        gate: Gate | None = None,
        policy_config: PolicyConfig | None = None,
    ) -> None:
        super().__init__(
            name=name,
            keypair=keypair,
            trust_store=trust_store,
            tool_registry=tool_registry,
            transport=transport,
        )
        self.gate = gate or Gate(
            local_fingerprint=self.fingerprint,
            trust_store=self.trust_store,
            policy_config=policy_config,
        )
        self.processed_decisions: list[GateDecision] = []

    def issue_worker_capability(
        self,
        worker_fingerprint: str,
        intents: list[str],
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int = 300,
        max_uses: int = 10,
    ) -> CapabilityToken:
        """Issue and sign a capability token authorizing worker for specific intents."""
        now = int(time.time())
        token_id = f"cap-{self.name}-{int(time.time() * 1000)}"

        token = CapabilityToken(
            token_id=token_id,
            issuer=self.fingerprint,
            subject=worker_fingerprint,
            intents=intents,
            constraints=constraints or {},
            not_before=now - 5,
            expires_at=now + ttl_seconds,
            max_uses=max_uses,
        )
        token = token.sign(self.keypair.private_key)

        # Store in Gate's capability store so Gate can verify it upon return
        self.gate.capability_store.store(token)
        return token

    def assign_task(
        self,
        worker_fingerprint: str,
        session_id: str,
        task_id: str,
        action: str,
        target: str,
        allowed_return_intents: list[str] | None = None,
    ) -> Envelope | None:
        """Issue capability and send task assignment to worker."""
        # 1. Issue capability token to worker for response
        intents = allowed_return_intents or ["report_result"]
        cap_token = self.issue_worker_capability(worker_fingerprint, intents=intents)

        # 2. Issue capability token for assign_task intent itself
        self_cap = CapabilityToken(
            token_id=f"cap-self-{task_id}",
            issuer=self.fingerprint,
            subject=self.fingerprint,
            intents=["assign_task"],
        ).sign(self.keypair.private_key)
        self.gate.capability_store.store(self_cap)

        control = ControlLane(
            intent="assign_task",
            params={"task_id": task_id, "action": action, "target": target},
            capability_token_id=cap_token.token_id,
        )

        env = self.create_envelope(
            recipient=worker_fingerprint,
            session_id=session_id,
            control=control,
        )

        return self.send_envelope(env)

    def handle_envelope(self, envelope: Envelope) -> Envelope | None:
        """Receive incoming envelope from peer, evaluate through Gate, and take action."""
        logger.info(
            "Orchestrator received incoming envelope",
            sender=envelope.header.sender,
            intent=envelope.control.intent,
        )

        decision = self.gate.process_envelope(envelope)
        self.processed_decisions.append(decision)

        if decision.decision != Decision.ALLOW:
            logger.warn(
                "Gate rejected incoming envelope",
                decision=decision.decision,
                reason=decision.reason,
                violations=decision.violations,
            )
            return None

        # Execute post-gate action if needed (e.g. log or trigger next step)
        logger.info("Gate ALLOWED envelope", intent=envelope.control.intent)
        return None
