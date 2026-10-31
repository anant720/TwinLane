"""SHA-256 hash-chained immutable audit records and chain verification."""

import hashlib
import time

from pydantic import BaseModel, Field

from twinlane.protocol.canonical import canonicalize_json
from twinlane.protocol.errors import AuditChainTamperError

# Genesis block sentinel hash
GENESIS_PREV_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"


class AuditRecord(BaseModel):
    """An immutable audit record bound into a cryptographic hash chain."""

    index: int = Field(
        ..., ge=0, description="Monotonically increasing zero-indexed record counter"
    )
    timestamp: int = Field(
        default_factory=lambda: int(time.time()), description="Unix timestamp of decision"
    )
    msg_id: str = Field(..., description="Message UUID evaluated by Gate")
    session_id: str = Field(..., description="Session UUID")
    sender: str = Field(..., description="Sender public key fingerprint")
    intent: str = Field(..., description="Requested intent identifier")
    decision: str = Field(..., description="Authorization outcome: ALLOW, DENY, or ESCALATE")
    reason: str = Field(default="", description="Diagnostic or error code explaining decision")
    prev_hash: str = Field(..., description="SHA-256 hex hash of preceding record (or GENESIS)")
    record_hash: str = Field(
        ..., description="SHA-256 hex hash of canonical content of this record"
    )

    model_config = {"extra": "forbid"}

    def get_hashable_payload(self) -> dict[str, object]:
        """Return the dictionary of fields covered by the record_hash (excluding record_hash)."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "msg_id": self.msg_id,
            "session_id": self.session_id,
            "sender": self.sender,
            "intent": self.intent,
            "decision": self.decision,
            "reason": self.reason,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        """Compute the canonical SHA-256 digest over hashable fields."""
        canonical_bytes = canonicalize_json(self.get_hashable_payload())
        return hashlib.sha256(canonical_bytes).hexdigest()

    def verify_integrity(self, expected_prev_hash: str | None = None) -> None:
        """Verify internal hash and link to previous record.

        Raises:
            AuditChainTamperError: If hash mismatch or prev_hash link is broken.
        """
        computed = self.compute_hash()
        if computed.lower() != self.record_hash.lower():
            raise AuditChainTamperError(
                self.index,
                f"Record hash mismatch: declared '{self.record_hash}', computed '{computed}'",
            )

        if expected_prev_hash is not None and self.prev_hash.lower() != expected_prev_hash.lower():
            raise AuditChainTamperError(
                self.index,
                f"Previous hash link broken: points to '{self.prev_hash}', expected '{expected_prev_hash}'",
            )


class AuditChain:
    """In-memory append-only hash chain manager."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(
        self,
        msg_id: str,
        session_id: str,
        sender: str,
        intent: str,
        decision: str,
        reason: str = "",
        timestamp: int | None = None,
    ) -> AuditRecord:
        """Create and append a new verified record to the chain."""
        index = len(self._records)
        prev_hash = self._records[-1].record_hash if self._records else GENESIS_PREV_HASH
        ts = timestamp if timestamp is not None else int(time.time())

        # Construct unsigned draft
        draft = {
            "index": index,
            "timestamp": ts,
            "msg_id": msg_id,
            "session_id": session_id,
            "sender": sender,
            "intent": intent,
            "decision": decision,
            "reason": reason,
            "prev_hash": prev_hash,
        }
        canonical_bytes = canonicalize_json(draft)
        record_hash = hashlib.sha256(canonical_bytes).hexdigest()

        record = AuditRecord(
            index=index,
            timestamp=ts,
            msg_id=msg_id,
            session_id=session_id,
            sender=sender,
            intent=intent,
            decision=decision,
            reason=reason,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )

        self._records.append(record)
        return record

    def verify_all(self) -> None:
        """Verify the entire chain from genesis to head.

        Raises:
            AuditChainTamperError: If any record or link is invalid.
        """
        prev_hash = GENESIS_PREV_HASH
        for i, rec in enumerate(self._records):
            if rec.index != i:
                raise AuditChainTamperError(
                    i, f"Index sequence jump: expected {i}, got {rec.index}"
                )
            rec.verify_integrity(expected_prev_hash=prev_hash)
            prev_hash = rec.record_hash

    def count(self) -> int:
        """Return total record count."""
        return len(self._records)

    def last_record(self) -> AuditRecord | None:
        """Return the most recently appended record or None."""
        return self._records[-1] if self._records else None

    def records(self) -> list[AuditRecord]:
        """Return a copy of the record list."""
        return list(self._records)
