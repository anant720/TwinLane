"""TwinLane Command Line Interface."""

import click


@click.group()
@click.version_option(version="0.1.0", prog_name="twinlane")
def main() -> None:
    """TwinLane: Zero-Trust Agent-to-Agent Security Protocol CLI."""
    pass


@main.command()
@click.option("--name", required=True, help="Agent identity name (e.g. agent-a)")
@click.option("--out-dir", default=".twinlane_keys", help="Output directory for generated keys")
def keygen(name: str, out_dir: str) -> None:
    """Generate a new Ed25519 signing keypair for an agent."""
    click.echo(f"Generating Ed25519 keypair for '{name}' into '{out_dir}'...")


@main.command()
@click.option("--attacks", default="bench/attacks", help="Path to attack corpus YAML files")
@click.option("--output", default="bench/results/latest.json", help="Output JSON path")
def bench(attacks: str, output: str) -> None:
    """Execute evaluation benchmark suite against baselines and TwinLane."""
    click.echo(f"Running benchmark with attacks from '{attacks}' -> '{output}'...")


@main.command()
@click.option("--port", default=8000, help="Port to run demo web app")
def run_demo(port: int) -> None:
    """Launch interactive side-by-side demo server."""
    click.echo(f"Starting TwinLane demo server on http://localhost:{port}...")


@main.command()
@click.option("--log", required=True, help="Path to audit.jsonl log file")
def verify_audit(log: str) -> None:
    """Verify cryptographic hash chain integrity of an audit log."""
    click.echo(f"Verifying audit log integrity: '{log}'...")


if __name__ == "__main__":
    main()
