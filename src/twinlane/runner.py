"""Task runner coordinating Orchestrator, Worker, and Gate under TwinLane protocol."""

from dataclasses import dataclass, field
from typing import Any

from twinlane.agents.orchestrator import OrchestratorAgent
from twinlane.agents.tools.base import ToolRegistry
from twinlane.agents.worker import WorkerAgent
from twinlane.gate.gateway import Gate
from twinlane.identity.trust_store import TrustStore
from twinlane.llm.base import LLMClient
from twinlane.llm.mock import MockLLMClient
from twinlane.policy.decisions import Decision, GateDecision
from twinlane.policy.loader import PolicyConfig
from twinlane.transport.inproc import InProcTransport


@dataclass
class TwinLaneExecutionResult:
    """Outcome of a TwinLane task execution."""

    allowed: bool
    decision: GateDecision | None = None
    worker_output: Any = None
    violations: list[str] = field(default_factory=list)
    action_taken: str = ""


class TwinLaneRunner:
    """Coordinating runner for TwinLane-protected agent interactions."""

    def __init__(
        self,
        tools: ToolRegistry,
        policy_config: PolicyConfig | None = None,
        llm: LLMClient | None = None,
        # Ablation flags
        verify_signatures: bool = True,
        require_capabilities: bool = True,
        track_provenance: bool = True,
        use_quarantine: bool = True,
    ) -> None:
        self.tools = tools
        self.policy_config = policy_config
        self.llm = llm or MockLLMClient()
        self.verify_signatures = verify_signatures
        self.require_capabilities = require_capabilities
        self.track_provenance = track_provenance
        self.use_quarantine = use_quarantine

        # Setup shared trust store and transport
        self.trust_store = TrustStore()
        self.transport = InProcTransport()

        # Orchestrator
        self.orchestrator = OrchestratorAgent(
            name="orchestrator",
            trust_store=self.trust_store,
            tool_registry=self.tools,
            transport=self.transport,
            policy_config=self.policy_config,
        )

        # Worker
        self.worker = WorkerAgent(
            name="worker",
            trust_store=self.trust_store,
            tool_registry=self.tools,
            transport=self.transport,
            llm_client=self.llm,
        )

        # Register mutual identities in trust store
        self.trust_store.register(self.orchestrator.keypair.public_key, name="orchestrator")
        self.trust_store.register(self.worker.keypair.public_key, name="worker")

        # Register message handlers on transport
        self.transport.register_handler(
            self.orchestrator.fingerprint,
            self.orchestrator.handle_envelope,
        )
        self.transport.register_handler(
            self.worker.fingerprint,
            self.worker.handle_envelope,
        )

    def run_task(
        self,
        session_id: str,
        task_id: str,
        action: str,
        target: str,
        allowed_intents: list[str] | None = None,
    ) -> TwinLaneExecutionResult:
        """Run an end-to-end task under TwinLane protection."""
        # Orchestrator sends assign_task to worker
        response_env = self.orchestrator.assign_task(
            worker_fingerprint=self.worker.fingerprint,
            session_id=session_id,
            task_id=task_id,
            action=action,
            target=target,
            allowed_return_intents=allowed_intents or ["report_result"],
        )

        if not response_env:
            return TwinLaneExecutionResult(
                allowed=False,
                violations=["Worker did not return an envelope"],
            )

        # Evaluate response envelope at Orchestrator Gate
        # Support ablation flags if configured
        gate: Gate = self.orchestrator.gate
        decision = gate.process_envelope(response_env)

        is_allowed = decision.decision == Decision.ALLOW
        action_taken = response_env.control.intent if is_allowed else "BLOCKED_BY_GATE"

        return TwinLaneExecutionResult(
            allowed=is_allowed,
            decision=decision,
            worker_output=response_env.control.params,
            violations=decision.violations,
            action_taken=action_taken,
        )
