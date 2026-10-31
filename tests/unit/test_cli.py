"""Unit tests for TwinLane CLI commands."""

from pathlib import Path

from click.testing import CliRunner

from twinlane.cli import main


def test_cli_version() -> None:
    """Verify cli --version reports version."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_help() -> None:
    """Verify cli --help displays commands."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "keygen" in result.output
    assert "bench" in result.output
    assert "run-demo" in result.output
    assert "verify-audit" in result.output


def test_cli_keygen_command(tmp_path: Path) -> None:
    """Verify keygen command invocation."""
    runner = CliRunner()
    key_dir = str(tmp_path / "keys")
    result = runner.invoke(main, ["keygen", "--name", "agent-test", "--out-dir", key_dir])
    assert result.exit_code == 0
    assert "Generated Ed25519 keypair for 'agent-test'" in result.output


def test_cli_bench_command() -> None:
    """Verify bench command invocation."""
    runner = CliRunner()
    result = runner.invoke(main, ["bench", "--attacks", "bench/attacks"])
    assert result.exit_code == 0
    assert "Running benchmark" in result.output


def test_cli_run_demo_command() -> None:
    """Verify run-demo command invocation."""
    runner = CliRunner()
    result = runner.invoke(main, ["run-demo", "--port", "9000"])
    assert result.exit_code == 0
    assert "Starting TwinLane demo server on http://localhost:9000" in result.output


def test_cli_verify_audit_command(tmp_path: Path) -> None:
    """Verify verify-audit command invocation."""
    from twinlane.audit.log import AuditLogger

    log_file = tmp_path / "valid_audit.jsonl"
    logger = AuditLogger(log_file)
    logger.log(msg_id="m1", session_id="s1", sender="a", intent="ping", decision="ALLOW")

    runner = CliRunner()
    result = runner.invoke(main, ["verify-audit", "--log", str(log_file)])
    assert result.exit_code == 0
    assert "PASS: Audit log verified" in result.output
