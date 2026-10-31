"""Worker agent executing sandboxed tool operations and constructing TwinLane envelopes."""

from typing import Any

import structlog

from twinlane.agents.base import BaseAgent
from twinlane.agents.tools.base import ToolRegistry
from twinlane.crypto.keys import KeyPair
from twinlane.identity.trust_store import TrustStore
from twinlane.llm.base import ChatMessage, LLMClient
from twinlane.llm.mock import MockLLMClient
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.envelope import Envelope
from twinlane.protocol.provenance import IntegrityLabel, OriginType, Provenance
from twinlane.transport.base import Transport

logger = structlog.get_logger(__name__)


class WorkerAgent(BaseAgent):
    """Worker agent that interacts with tools and packages outputs into TwinLane envelopes."""

    def __init__(
        self,
        name: str = "worker-agent",
        keypair: KeyPair | None = None,
        trust_store: TrustStore | None = None,
        tool_registry: ToolRegistry | None = None,
        transport: Transport | None = None,
        llm_client: LLMClient | None = None,
    ) -> None:
        super().__init__(
            name=name,
            keypair=keypair,
            trust_store=trust_store,
            tool_registry=tool_registry,
            transport=transport,
        )
        self.llm = llm_client or MockLLMClient()
        self.received_envelopes: list[Envelope] = []

    def handle_envelope(self, envelope: Envelope) -> Envelope | None:
        """Process an incoming task envelope from the orchestrator."""
        self.received_envelopes.append(envelope)
        intent = envelope.control.intent
        params = envelope.control.params
        session_id = envelope.header.session_id
        cap_id = envelope.control.capability_token_id

        logger.info(
            "Worker received envelope",
            sender=envelope.header.sender,
            intent=intent,
            session_id=session_id,
        )

        if intent == "assign_task":
            return self._execute_task(session_id, params, cap_id, envelope.header.sender)

        # Default ack
        return None

    def _execute_task(
        self,
        session_id: str,
        params: dict[str, Any],
        capability_token_id: str,
        orchestrator_fingerprint: str,
    ) -> Envelope:
        """Execute task tool call and return response envelope with Data and Control lanes."""
        action = str(params.get("action", "read_file"))
        target = str(params.get("target", ""))

        # 1. Execute tool
        tool_res = self.tools.execute(action, path=target, url=target)
        raw_content = str(tool_res.data) if tool_res.success else (tool_res.error or "Error")

        # 2. Package tool output into Data Lane with UNTRUSTED provenance
        data_item = DataItem(
            item_id="data-tool-output-01",
            content=raw_content,
            content_hash=compute_content_hash(raw_content),
            provenance=Provenance(
                origin=f"tool:{action}:{target}",
                origin_type=OriginType.TOOL,
                integrity=IntegrityLabel.UNTRUSTED,
            ),
        )

        # 3. Optional LLM analysis for worker summary
        prompt = (
            f"You received content from tool '{action}':\n"
            f"{raw_content}\n"
            "Summarize the key facts concisely for the orchestrator."
        )
        llm_res = self.llm.generate([ChatMessage(role="user", content=prompt)])
        logger.debug("Worker LLM generated analysis", length=len(llm_res.content))

        # 4. Construct response Control Lane (typed schema, no free-text instructions)
        control = ControlLane(
            intent="report_result",
            params={
                "task_id": params.get("task_id", "task-default"),
                "status": "SUCCESS" if tool_res.success else "FAILED",
                "data_ref": data_item.item_id,
            },
            capability_token_id=capability_token_id,
        )

        # 5. Sign and return envelope
        return self.create_envelope(
            recipient=orchestrator_fingerprint,
            session_id=session_id,
            control=control,
            data=[data_item],
        )
