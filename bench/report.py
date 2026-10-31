"""Benchmark report generator producing JSON results and publication-grade Markdown tables."""

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from bench.metrics import SystemBenchmarkMetrics
from bench.runner import BenchmarkRunner


def get_git_commit_hash() -> str:
    """Retrieve current git commit hash if in a git repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "git-unavailable"


def generate_benchmark_suite(
    output_dir: Path | str = "docs/report/results",
    attacks_dir: Path | str = "bench/attacks",
    scenarios_file: Path | str = "bench/scenarios/benign_tasks.yaml",
) -> dict[str, SystemBenchmarkMetrics]:
    """Execute full benchmark across B0, B1, B2, and TwinLane, and generate outputs."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    runner = BenchmarkRunner(attacks_dir=attacks_dir, scenarios_file=scenarios_file)
    systems = ["B0_Naive", "B1_Spotlight", "B2_Classifier", "TwinLane"]
    results: dict[str, SystemBenchmarkMetrics] = {}

    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        for sys_name in systems:
            sys_tmp = tmp_dir / sys_name
            sys_tmp.mkdir()
            metrics = runner.run_system_benchmark(sys_name, sys_tmp)
            results[sys_name] = metrics

    commit_hash = get_git_commit_hash()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # 1. Output machine-readable JSON
    json_data: dict[str, Any] = {
        "metadata": {
            "git_commit": commit_hash,
            "timestamp": timestamp,
            "total_attack_cases": len(runner.attack_cases),
            "total_benign_scenarios": len(runner.benign_scenarios),
        },
        "systems": {k: v.model_dump() for k, v in results.items()},
    }

    json_file = out_path / "benchmark_results.json"
    json_file.write_text(json.dumps(json_data, indent=2), encoding="utf-8")

    # 2. Output publication-grade Markdown summary table
    md_content = _build_markdown_summary(results, commit_hash, timestamp)
    md_file = out_path / "summary_table.md"
    md_file.write_text(md_content, encoding="utf-8")

    return results


def _build_markdown_summary(
    results: dict[str, SystemBenchmarkMetrics],
    commit_hash: str,
    timestamp: str,
) -> str:
    """Format benchmark results into publication-grade Markdown tables."""
    lines: list[str] = [
        "# TwinLane Empirical Security Benchmark Results",
        "",
        f"- **Timestamp**: `{timestamp}`",
        f"- **Git Commit**: `{commit_hash}`",
        "- **Evaluation Method**: Deterministic Simulation ($T=0$, seed 42) across 180 Attack Fixtures & 35 Benign Workflows",
        "",
        "## Overall System Comparison",
        "",
        "| Architecture / Baseline | Attack Success Rate (ASR) | 95% Wilson CI | Canary Leak Rate | Benign Completion (TCR) | Latency $p_{50}$ / $p_{95}$ (μs) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]

    for name, m in results.items():
        ci_str = f"[{m.asr_ci_95[0]:.2f}, {m.asr_ci_95[1]:.2f}]"
        lat_str = f"{m.latency_p50_us:.1f} / {m.latency_p95_us:.1f}"
        lines.append(
            f"| **{name}** | **{m.attack_success_rate:.1f}%** | {ci_str} | {m.canary_leak_rate:.1f}% | {m.task_completion_rate:.1f}% | {lat_str} |"
        )

    lines.extend(
        [
            "",
            "## Category-Level Attack Success Rate (ASR %)",
            "",
            "| Attack Category | B0 (Naive) | B1 (Spotlight) | B2 (Classifier) | TwinLane Protocol |",
            "| :--- | :---: | :---: | :---: | :---: |",
        ]
    )

    sample_m = next(iter(results.values()))
    for cat_id in sample_m.categories:
        b0_val = (
            f"{results['B0_Naive'].categories[cat_id].attack_success_rate:.0f}%"
            if "B0_Naive" in results
            else "-"
        )
        b1_val = (
            f"{results['B1_Spotlight'].categories[cat_id].attack_success_rate:.0f}%"
            if "B1_Spotlight" in results
            else "-"
        )
        b2_val = (
            f"{results['B2_Classifier'].categories[cat_id].attack_success_rate:.0f}%"
            if "B2_Classifier" in results
            else "-"
        )
        tl_val = (
            f"{results['TwinLane'].categories[cat_id].attack_success_rate:.0f}%"
            if "TwinLane" in results
            else "-"
        )
        lines.append(f"| `{cat_id}` | {b0_val} | {b1_val} | {b2_val} | **{tl_val}** |")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    generate_benchmark_suite()
