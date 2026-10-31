"""The 7-step linear Gate verification pipeline."""

import time

from cryptography.hazmat.primitives.asymmetric import ed25519

from twinlane.audit.chain import AuditChain, AuditRecord
from twinlane.capabilities.intents import IntentCatalog
from twinlane.capabilities.manifest import CapabilityStore
from twinlane.capabilities.token import CapabilityToken
from twinlane.crypto.nonce_cache import NonceCache
from twinlane.crypto.signing import verify_envelope_signature
from twinlane.gate.quarantine import QuarantineReader, QuarantineResult
from twinlane.identity.trust_store import TrustStore
from twinlane.policy.decisions import Decision, GateDecision
from twinlane.policy.engine import PolicyEngine
from twinlane.protocol.envelope import Envelope
from twinlane.protocol.errors import (
    AuthenticationError,
    CapabilityError,
    ClockSkewError,
    InvalidSchemaError,
    MessageExpiredError,
    ProtocolError,
    ProvenanceError,
    RecipientMismatchError,
    SenderNotTrustedError,
    SequenceRegressionError,
)
from twinlane.protocol.provenance import IntegrityLabel


class PipelineContext:
    """Holds pipeline execution state and intermediate results across the 7 steps."""

    def __init__(
        self,
        envelope: Envelope,
        local_fingerprint: str,
        trust_store: TrustStore,
        nonce_cache: NonceCache,
        capability_store: CapabilityStore,
        intent_catalog: IntentCatalog,
        policy_engine: PolicyEngine,
        audit_chain: AuditChain,
        quarantine_reader: QuarantineReader,
        seq_tracker: dict[tuple[str, str], int],
        param_labels: dict[str, IntegrityLabel] | None = None,
        max_clock_skew_seconds: int = 30,
    ) -> None:
        self.envelope = envelope
        self.local_fingerprint = local_fingerprint
        self.trust_store = trust_store
        self.nonce_cache = nonce_cache
        self.capability_store = capability_store
        self.intent_catalog = intent_catalog
        self.policy_engine = policy_engine
        self.audit_chain = audit_chain
        self.quarantine_reader = quarantine_reader
        self.seq_tracker = seq_tracker
        self.param_labels = param_labels or {}
        self.max_clock_skew = max_clock_skew_seconds

        # Intermediate artifacts populated by pipeline
        self.sender_public_key: ed25519.Ed25519PublicKey | None = None
        self.authorized_token: CapabilityToken | None = None
        self.quarantine_results: list[QuarantineResult] = []
        self.audit_record: AuditRecord | None = None


def execute_gate_pipeline(ctx: PipelineContext) -> GateDecision:
    """Execute the 7-step Gate pipeline in strict linear order.

    Fail-closed: Any exception immediately yields a DENY decision and writes an audit record.
    """
    env = ctx.envelope
    now = int(time.time())

    try:
        # =========================================================================
        # STEP 1: AUTHENTICATE
        # =========================================================================
        # 1.1 Check recipient
        if env.header.recipient.lower() != ctx.local_fingerprint.lower():
            raise RecipientMismatchError(env.header.recipient, ctx.local_fingerprint)

        # 1.2 Check sender in trust store
        sender_key = ctx.trust_store.get_public_key(env.header.sender)
        if sender_key is None:
            raise SenderNotTrustedError(env.header.sender)
        ctx.sender_public_key = sender_key

        # 1.3 Check expiration and clock skew
        if env.header.expires_at < now:
            raise MessageExpiredError(
                f"Message expired at {env.header.expires_at}, current time is {now}"
            )

        if env.header.issued_at - now > ctx.max_clock_skew:
            raise ClockSkewError(
                f"Message future issued_at {env.header.issued_at} exceeds clock skew tolerance ({ctx.max_clock_skew}s)"
            )

        # 1.4 Check nonce replay
        ctx.nonce_cache.check_and_record(env.header.nonce, expires_at=float(env.header.expires_at))

        # 1.5 Check sequence counter
        seq_key = (env.header.session_id, env.header.sender)
        last_seq = ctx.seq_tracker.get(seq_key, 0)
        if env.header.seq <= last_seq:
            raise SequenceRegressionError(env.header.seq, last_seq)

        # 1.6 Verify Ed25519 signature over RFC 8785 canonical bytes
        verify_envelope_signature(env, sender_key)

        # Update sequence tracking upon successful authentication
        ctx.seq_tracker[seq_key] = env.header.seq

        # =========================================================================
        # STEP 2: VALIDATE SCHEMA
        # =========================================================================
        intent_def = ctx.intent_catalog.get(env.control.intent)
        if intent_def is None:
            return _deny_and_audit(
                ctx, f"Unknown intent '{env.control.intent}' not in Intent Catalog", step=2
            )

        try:
            intent_def.validate_params(env.control.params)
        except ValueError as e:
            return _deny_and_audit(ctx, f"Schema validation failed: {e}", step=2)

        # =========================================================================
        # STEP 3: AUTHORIZE CAPABILITY
        # =========================================================================
        token_id = env.control.capability_token_id
        token = ctx.capability_store.get(token_id)
        if token is None:
            return _deny_and_audit(ctx, f"Capability token '{token_id}' not found in store", step=3)

        # Verify token subject matches message sender
        if token.subject.lower() != env.header.sender.lower():
            return _deny_and_audit(
                ctx,
                f"Token subject '{token.subject}' does not match sender '{env.header.sender}'",
                step=3,
            )

        # Verify full delegation chain
        ctx.capability_store.verify_token_chain(token)

        # Check intent authorization and parameter constraints
        token.check_authorization(env.control.intent, env.control.params, now=now)
        ctx.authorized_token = token

        # =========================================================================
        # STEP 4: CHECK PROVENANCE
        # =========================================================================
        # Handled in cooperation with policy engine below; verify parameter taint
        if ctx.policy_engine.mode == "strict":
            for param_name, label in ctx.param_labels.items():
                if label != IntegrityLabel.TRUSTED:
                    return _deny_and_audit(
                        ctx,
                        f"Parameter '{param_name}' derived from {label} data (rejected in strict mode)",
                        step=4,
                    )

        # =========================================================================
        # STEP 5: QUARANTINE ROUTE
        # =========================================================================
        for item in env.data:
            if item.provenance.integrity == IntegrityLabel.UNTRUSTED:
                q_res = ctx.quarantine_reader.process_data_item(item)
                ctx.quarantine_results.append(q_res)

        # =========================================================================
        # STEP 6: POLICY DECISION
        # =========================================================================
        policy_decision = ctx.policy_engine.evaluate(
            header=env.header,
            control=env.control,
            param_labels=ctx.param_labels,
        )

        if policy_decision.decision == Decision.DENY:
            return _deny_and_audit(
                ctx,
                policy_decision.reason,
                step=6,
                violations=policy_decision.violations,
            )

        # Record usage count on successful token invocation
        token.record_usage()

        # =========================================================================
        # STEP 7: APPEND AUDIT LOG
        # =========================================================================
        decision_str = "ALLOW" if policy_decision.decision == Decision.ALLOW else "ESCALATE"
        ctx.audit_record = ctx.audit_chain.append(
            msg_id=env.header.msg_id,
            session_id=env.header.session_id,
            sender=env.header.sender,
            intent=env.control.intent,
            decision=decision_str,
            reason=policy_decision.reason,
            timestamp=now,
        )

        return policy_decision

    except Exception as e:
        # Fail Closed: Any internal or cryptographic error produces immediate DENY
        reason = f"Security Gate Denial: {e}"
        if isinstance(e, AuthenticationError):
            step_idx = 1
        elif isinstance(e, (InvalidSchemaError, ProtocolError)):
            step_idx = 2
        elif isinstance(e, CapabilityError):
            step_idx = 3
        elif isinstance(e, ProvenanceError):
            step_idx = 4
        else:
            step_idx = 1

        return _deny_and_audit(ctx, reason, step=step_idx)


def _deny_and_audit(
    ctx: PipelineContext,
    reason: str,
    step: int,
    violations: list[str] | None = None,
) -> GateDecision:
    """Helper to record a DENY decision into the audit log and return the GateDecision."""
    now = int(time.time())
    ctx.audit_record = ctx.audit_chain.append(
        msg_id=ctx.envelope.header.msg_id,
        session_id=ctx.envelope.header.session_id,
        sender=ctx.envelope.header.sender,
        intent=ctx.envelope.control.intent,
        decision="DENY",
        reason=reason,
        timestamp=now,
    )
    return GateDecision.deny(reason=reason, step=step, violations=violations)
