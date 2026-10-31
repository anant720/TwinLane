"""Unit tests for TwinLane CLI commands."""

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


def test_cli_keygen_command() -> None:
    """Verify keygen command invocation."""
    runner = CliRunner()
    result = runner.invoke(main, ["keygen", "--name", "agent-test"])
    assert result.exit_code == 0
    assert "Generating Ed25519 keypair for 'agent-test'" in result.output


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


def test_cli_verify_audit_command() -> None:
    """Verify verify-audit command invocation."""
    runner = CliRunner()
    result = runner.invoke(main, ["verify-audit", "--log", "audit.jsonl"])
    assert result.exit_code == 0
    assert "Verifying audit log integrity: 'audit.jsonl'" in result.output
