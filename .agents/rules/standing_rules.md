# Standing Rules for TwinLane Agents

(This file mirrors AGENTS.md at the repository root)

## 1. Mission and Honest Positioning

Build TwinLane from scratch: a lightweight, framework-agnostic, zero-trust protocol and reference implementation that lets two LLM agents (possibly owned by different parties across distinct trust domains) communicate such that prompt injection cannot cause an unauthorized action.

TwinLane structures every message into a single cryptographically signed envelope containing two distinct lanes:
- **Control Lane**: Typed, schema-validated intents from an agreed Intent Catalog. No free-text instructions. Signed. Covered by a capability token.
- **Data Lane**: Content items with explicit provenance and trust labels. Untrusted by default. Never directly interpreted as instructions.

A deterministic **Gate** on the receiving side authenticates, validates, authorizes, checks provenance, routes data to quarantine when needed, decides (`ALLOW`, `DENY`, `ESCALATE`), and writes a tamper-evident audit record. **No LLM ever makes the final authorization decision.**

### Honest Claim and Non-Goals
- **The principle of separating control from data is NOT new**: Prior work includes CaMeL (Google DeepMind), Multi-CaMeL (multi-agent extension, Oct 2026), and FIDES (Microsoft).
- **Our contribution**: A lightweight, wire-level, zero-trust protocol for agents across trust boundaries featuring cryptographic identity (Ed25519), signed typed intents, capability tokens with attenuating delegation, provenance-labelled data manifests, and a deterministic gate—requiring no custom interpreter and no mandatory second LLM.
- **Threat Model Boundary**: We claim resistance to unauthorized actions inside our stated threat model, measured empirically. We do **NOT** claim prompt injection is mathematically impossible, and we do **NOT** claim an LLM can never be misled by text-only summaries.

## 2. Safety Guidelines for Defensive Research

1. **Defensive Research Only**: All attack payloads are test fixtures stored in a local sandbox (`bench/attacks/` and `demo/fixtures/`).
2. **Mock Tools by Default**: All tools used in testing and evaluation (`read_file`, `send_email`, `http_post`, `fetch_url`) are safe mocks. 
   - No real network egress from tools.
   - `send_email` writes to a local sandbox outbox directory.
   - Secrets are fake canary strings (e.g., `CANARY-7f3a9b1c`).
3. **Zero Secrets in Repository**: Never commit API keys or real credentials. All optional external LLM keys must be loaded from environment variables (`.env`, with `.env.example` committed).

## 3. Standing Engineering Rules

1. Python 3.12+ (compatible with Python 3.13), Pydantic v2, cryptography (Ed25519), httpx, fastapi, pytest, pytest-asyncio, hypothesis, ruff, mypy strict, structlog.
2. Every file fully typed. `mypy --strict` passes with 0 errors. `ruff` check and format clean. No bare except. No print in library code.
3. Security-critical code pure where feasible, thoroughly tested. Fail closed on any error.
4. Never allow an LLM output to decide an authorization outcome.
5. Redact secrets/canaries in logs and test outputs.
6. Commit messages follow conventional commits; one logical change per commit.
7. Public modules and functions documented with docstrings; ADRs written for architectural decisions.
8. Cite primary sources in `docs/research/references.md`; label unverified claims `[UNVERIFIED]`.
9. Minimize external dependencies; standard library preferred.
10. Deterministic benchmarks: fixed seeds, temperature 0, recorded model metadata, JSON outputs with commit hash.
11. Pass quality gates at every phase before proceeding.

