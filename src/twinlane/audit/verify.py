"""Verification utility for persistent JSONL audit logs."""

import json
from pathlib import Path
from typing import NamedTuple

from twinlane.audit.chain import GENESIS_PREV_HASH, AuditRecord
from twinlane.protocol.errors import AuditChainTamperError


class VerificationResult(NamedTuple):
    """Result of verifying an audit log file."""

    is_valid: bool
    record_count: int
    error_message: str | None = None
    failed_record_index: int | None = None


def verify_audit_log_file(file_path: str | Path) -> VerificationResult:
    """Verify the hash chain integrity of a JSONL audit log file from start to finish.

    Args:
        file_path: Path to audit.jsonl file.

    Returns:
        VerificationResult with validity status and details.
    """
    path = Path(file_path)
    if not path.exists():
        return VerificationResult(
            is_valid=False,
            record_count=0,
            error_message=f"Audit log file does not exist: {path}",
        )

    expected_prev_hash = GENESIS_PREV_HASH
    count = 0

    try:
        with path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                clean = line.strip()
                if not clean:
                    continue

                try:
                    data = json.loads(clean)
                    record = AuditRecord.model_validate(data)
                except Exception as e:
                    return VerificationResult(
                        is_valid=False,
                        record_count=count,
                        error_message=f"Malformed JSON at line {line_no}: {e}",
                        failed_record_index=count,
                    )

                if record.index != count:
                    return VerificationResult(
                        is_valid=False,
                        record_count=count,
                        error_message=f"Sequence index jump: line {line_no} has index {record.index}, expected {count}",
                        failed_record_index=count,
                    )

                try:
                    record.verify_integrity(expected_prev_hash=expected_prev_hash)
                except AuditChainTamperError as e:
                    return VerificationResult(
                        is_valid=False,
                        record_count=count,
                        error_message=str(e),
                        failed_record_index=record.index,
                    )

                expected_prev_hash = record.record_hash
                count += 1

        return VerificationResult(is_valid=True, record_count=count)
    except Exception as e:
        return VerificationResult(
            is_valid=False,
            record_count=count,
            error_message=f"Unexpected error reading audit log: {e}",
        )
