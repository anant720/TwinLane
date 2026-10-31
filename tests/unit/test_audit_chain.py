"""Unit tests for SHA-256 hash-chained audit ledger."""

from pathlib import Path

import pytest

from twinlane.audit.chain import GENESIS_PREV_HASH, AuditChain
from twinlane.audit.log import AuditLogger
from twinlane.audit.verify import verify_audit_log_file
from twinlane.protocol.errors import AuditChainTamperError


def test_audit_chain_append_and_verify() -> None:
    """Appending records maintains unbroken hash chain."""
    chain = AuditChain()
    r0 = chain.append(
        msg_id="m-0",
        session_id="s-1",
        sender="ed25519:alice",
        intent="fetch_data",
        decision="ALLOW",
    )
    assert r0.index == 0
    assert r0.prev_hash == GENESIS_PREV_HASH

    r1 = chain.append(
        msg_id="m-1",
        session_id="s-1",
        sender="ed25519:alice",
        intent="send_email",
        decision="DENY",
        reason="UNTRUSTED_PARAM",
    )
    assert r1.index == 1
    assert r1.prev_hash == r0.record_hash

    # Full chain verification passes
    chain.verify_all()


def test_audit_chain_tamper_detection() -> None:
    """Modifying any field in a historical record is detected."""
    chain = AuditChain()
    chain.append(msg_id="m-0", session_id="s-1", sender="a", intent="ping", decision="ALLOW")
    chain.append(msg_id="m-1", session_id="s-1", sender="a", intent="pong", decision="ALLOW")

    # Tamper with record 0's decision
    chain._records[0].decision = "DENY"

    with pytest.raises(AuditChainTamperError):
        chain.verify_all()


def test_persistent_audit_logger_and_verifier(tmp_path: Path) -> None:
    """AuditLogger persists records to JSONL verified by verify_audit_log_file."""
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_file)

    logger.log(msg_id="m-1", session_id="s-1", sender="sender-1", intent="task_a", decision="ALLOW")
    logger.log(msg_id="m-2", session_id="s-1", sender="sender-1", intent="task_b", decision="DENY")

    res = verify_audit_log_file(log_file)
    assert res.is_valid is True
    assert res.record_count == 2
