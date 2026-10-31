# TwinLane Empirical Security Benchmark Results

- **Timestamp**: `2026-10-31T13:00:06Z`
- **Git Commit**: `c32d4f3f2be079cdd88a1b723bc41836747bb652`
- **Evaluation Method**: Deterministic Simulation ($T=0$, seed 42) across 180 Attack Fixtures & 35 Benign Workflows

## Overall System Comparison

| Architecture / Baseline | Attack Success Rate (ASR) | 95% Wilson CI | Canary Leak Rate | Benign Completion (TCR) | Latency $p_{50}$ / $p_{95}$ (μs) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **B0_Naive** | **52.8%** | [0.46, 0.60] | 47.2% | 100.0% | 20521.0 / 25743.1 |
| **B1_Spotlight** | **52.8%** | [0.46, 0.60] | 47.2% | 100.0% | 2942.6 / 20772.9 |
| **B2_Classifier** | **0.0%** | [0.00, 0.02] | 0.0% | 100.0% | 2356.2 / 17920.3 |
| **TwinLane** | **0.0%** | [0.00, 0.02] | 0.0% | 100.0% | 9486.3 / 28513.0 |

## Category-Level Attack Success Rate (ASR %)

| Attack Category | B0 (Naive) | B1 (Spotlight) | B2 (Classifier) | TwinLane Protocol |
| :--- | :---: | :---: | :---: | :---: |
| `01_direct_override` | 100% | 100% | 0% | **0%** |
| `02_delimiter_collision` | 33% | 33% | 0% | **0%** |
| `03_role_reversal` | 67% | 67% | 0% | **0%** |
| `04_payload_splitting` | 0% | 0% | 0% | **0%** |
| `05_encoding_obfuscation` | 100% | 100% | 0% | **0%** |
| `06_unicode_homoglyphs` | 67% | 67% | 0% | **0%** |
| `07_adversarial_suffixing` | 0% | 0% | 0% | **0%** |
| `08_context_stuffing` | 67% | 67% | 0% | **0%** |
| `09_indirect_web` | 33% | 33% | 0% | **0%** |
| `10_tool_manipulation` | 33% | 33% | 0% | **0%** |
| `11_exfiltration_channels` | 33% | 33% | 0% | **0%** |
| `12_classifier_evasion` | 100% | 100% | 0% | **0%** |
