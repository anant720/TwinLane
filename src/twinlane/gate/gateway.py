"""TwinLane Gate interface coordinating verification, policies, and audit trails."""

from pathlib import Path

from twinlane.audit.chain import AuditChain, AuditRecord
from twinlane.audit.log import AuditLogger
from twinlane.capabilities.intents import IntentCatalog, default_intent_catalog
from twinlane.capabilities.manifest import CapabilityStore
from twinlane.crypto.nonce_cache import NonceCache
from twinlane.gate.extractors import ExtractorRegistry
from twinlane.gate.pipeline import PipelineContext, execute_gate_pipeline
from twinlane.gate.quarantine import QuarantineReader
from twinlane.identity.trust_store import TrustStore
from twinlane.policy.decisions import GateDecision
from twinlane.policy.engine import PolicyEngine
from twinlane.policy.loader import PolicyConfig, load_policy_from_str
from twinlane.protocol.envelope import Envelope
from twinlane.protocol.provenance import IntegrityLabel

DEFAULT_MINIMAL_POLICY: str = """
version: "1.0"
mode: "balanced"
intents:
  report_result:
    required_capability: "report_result"
    allowed_senders: ["*"]
  fetch_url:
    required_capability: "fetch_url"
    allowed_senders: ["*"]
  read_file:
    required_capability: "read_file"
    allowed_senders: ["*"]
  send_email:
    required_capability: "send_email"
    allowed_senders: ["*"]
  http_post:
    required_capability: "http_post"
    allowed_senders: ["*"]
"""


class Gate:
    """The central TwinLane security gate evaluating all incoming envelopes."""

    def __init__(
        self,
        local_fingerprint: str,
        trust_store: TrustStore,
        capability_store: CapabilityStore | None = None,
        policy_config: PolicyConfig | None = None,
        policy_str: str | None = None,
        intent_catalog: IntentCatalog | None = None,
        audit_log_path: str | Path | None = None,
        nonce_cache: NonceCache | None = None,
        extractor_registry: ExtractorRegistry | None = None,
    ) -> None:
        self.local_fingerprint = local_fingerprint
        self.trust_store = trust_store
        self.capability_store = capability_store or CapabilityStore(trust_store)
        self.intent_catalog = intent_catalog or default_intent_catalog
        self.nonce_cache = nonce_cache or NonceCache()
        self.extractor_registry = extractor_registry or ExtractorRegistry()
        self.quarantine_reader = QuarantineReader()
        self.seq_tracker: dict[tuple[str, str], int] = {}

        if policy_config is not None:
            self.policy_config = policy_config
        elif policy_str is not None:
            self.policy_config = load_policy_from_str(policy_str)
        else:
            self.policy_config = load_policy_from_str(DEFAULT_MINIMAL_POLICY)

        self.policy_engine = PolicyEngine(
            config=self.policy_config,
            extractor_registry=self.extractor_registry,
        )

        if audit_log_path is not None:
            self.audit_logger: AuditLogger | None = AuditLogger(audit_log_path)
            self.audit_chain = self.audit_logger.chain
        else:
            self.audit_logger = None
            self.audit_chain = AuditChain()

    def process_envelope(
        self,
        envelope: Envelope,
        param_labels: dict[str, IntegrityLabel] | None = None,
    ) -> GateDecision:
        """Process an incoming envelope through the 7-step Gate pipeline."""
        ctx = PipelineContext(
            envelope=envelope,
            local_fingerprint=self.local_fingerprint,
            trust_store=self.trust_store,
            nonce_cache=self.nonce_cache,
            capability_store=self.capability_store,
            intent_catalog=self.intent_catalog,
            policy_engine=self.policy_engine,
            audit_chain=self.audit_chain,
            quarantine_reader=self.quarantine_reader,
            seq_tracker=self.seq_tracker,
            param_labels=param_labels,
            max_clock_skew_seconds=self.policy_config.defaults.max_clock_skew_seconds,
        )

        decision = execute_gate_pipeline(ctx)

        # Flush to persistent log if logger is configured
        if self.audit_logger is not None and ctx.audit_record is not None:
            # AuditLogger handles writing on append; ensure parent dir flushed
            pass

        return decision

    def last_audit_record(self) -> AuditRecord | None:
        """Return the most recent audit record."""
        return self.audit_chain.last_record()
