"""Append-only JSONL persistent audit logger."""

import json
from pathlib import Path

from twinlane.audit.chain import AuditChain, AuditRecord


class AuditLogger:
    """Manages appending and loading hash-chained audit records to a JSONL file."""

    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)
        self.chain = AuditChain()
        self._load_existing()

    def _load_existing(self) -> None:
        """Load and verify existing records from disk if the file exists."""
        if not self.log_path.exists():
            return

        with self.log_path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    data = json.loads(clean_line)
                    record = AuditRecord.model_validate(data)
                    self.chain._records.append(record)
                except Exception as e:
                    raise ValueError(
                        f"Corrupt audit record at {self.log_path}:{line_no}: {e}"
                    ) from e

        # Verify integrity of loaded history
        self.chain.verify_all()

    def log(
        self,
        msg_id: str,
        session_id: str,
        sender: str,
        intent: str,
        decision: str,
        reason: str = "",
        timestamp: int | None = None,
    ) -> AuditRecord:
        """Append a new record to the chain and flush it to disk."""
        record = self.chain.append(
            msg_id=msg_id,
            session_id=session_id,
            sender=sender,
            intent=intent,
            decision=decision,
            reason=reason,
            timestamp=timestamp,
        )

        # Ensure parent directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Append to JSONL file
        record_json = json.dumps(
            record.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
        )
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(record_json + "\n")

        return record
