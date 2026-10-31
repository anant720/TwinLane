# TwinLane: Zero-Trust Protocol for Prompt-Injection-Resistant Agent Communication

[![CI](https://github.com/twinlane/twinlane/actions/workflows/ci.yml/badge.svg)](https://github.com/twinlane/twinlane/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checked-mypy%20strict-brightgreen.svg)](https://mypy-lang.org/)

TwinLane is a lightweight, framework-agnostic, zero-trust protocol and reference implementation designed to secure communication between autonomous Large Language Model (LLM) agents operating across distinct trust boundaries.

---

## 1. Honest Positioning & Threat Model Boundary

The principle of separating control instructions from passive data to resist prompt injection is **not new**:
- **CaMeL** (Google DeepMind / ETH Zurich, 2025) proved this inside a single agent using a custom runtime and dual-LLM planner.
- **Multi-CaMeL** (October 2026) extended channel segregation to multi-agent tool hierarchies.
- **FIDES** (Microsoft Research, 2025) implemented dynamic information-flow control labels inside Microsoft Agent Framework.

### Our Contribution
TwinLane operationalizes these principles into a **lightweight, wire-level, zero-trust protocol for agents across independent administrative boundaries**:
1. **Two-Lane Wire Envelopes**: Typed, schema-validated command intents in the **Control Lane**; provenance-tagged content in the **Data Lane**.
2. **Cryptographic Identity & Anti-Replay**: Ed25519 digital signatures over [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) canonical JSON, monotonic sequence counters, 128-bit nonces, and bounded TTLs.
3. **Attenuating Capability Tokens**: Mathematical guarantees that a peer agent (even if completely compromised) can never escalate its permissions or invoke out-of-scope actions.
4. **Deterministic Gate**: Evaluates authorization, parameter constraints, and provenance rules *before* any action can execute. **No LLM ever makes an authorization decision.**
5. **No Mandatory Dual-LLM & No Custom Interpreter**: Runs on standard JSON over HTTP or in-process queues without duplicating model calls for benign control messages.

### Honest Claim
Inside our stated threat model (untrusted content injection, compromised peer agents, and wire tampering), TwinLane guarantees that prompt injection **cannot trigger an unauthorized action**. We do **NOT** claim prompt injection is mathematically impossible, and we do **NOT** claim an LLM can never be misled by text-only summaries that trigger no actions.

---

## 2. Architecture Overview

```
User / Root Authority
       │  (Root Capability Token, Ed25519 Signed)
       ▼
┌──────────────────┐           Wire Envelope {Header, Control, Data, Signature}          ┌──────────────────┐
│     Agent A      │ ───────────────────────────────────────────────────────────────────► │     Agent B      │
│  (Orchestrator)  │ ◄─────────────────────────────────────────────────────────────────── │     (Worker)     │
└────────┬─────────┘                                                                      └────────┬─────────┘
         │                                                                                         │
   [ TwinLane Gate ]                                                                         [ TwinLane Gate ]
   1. Authenticate (Ed25519, TrustStore, NonceCache, Seq, Expiry)                            1. Authenticate
   2. Validate Control (IntentCatalog JSON Schema, no free-text)                              2. Validate Control
   3. Authorize Capability (Token signature, expiry, max uses, constraints)                  3. Authorize Capability
   4. Provenance Check (Untrusted data blocked from control parameters)                       4. Provenance Check
   5. Quarantine Route (Untrusted data routed to zero-tool reader)                           5. Quarantine Route
   6. Policy Decision (ALLOW / DENY / ESCALATE, fail-closed)                                 6. Policy Decision
   7. Append Audit Record (SHA-256 hash-chained immutable log)                               7. Append Audit Record
```

---

## 3. Quickstart (Under 5 Commands)

```bash
# 1. Clone repository and install dependencies
git clone https://github.com/twinlane/twinlane.git
cd twinlane
pip install -e ".[dev]"

# 2. Run test suite and strict type checking
pytest
mypy --strict src/

# 3. Generate Ed25519 keypair for local agent
twinlane keygen --name agent-a

# 4. Verify cryptographic audit chain
twinlane verify-audit --log audit/audit.jsonl

# 5. Launch interactive side-by-side demo (Baseline vs. TwinLane)
twinlane run-demo
```

---

## 4. Key Protocol Specifications

- [Threat Model & Vulnerability Analysis](docs/spec/threat-model.md)
- [TwinLane Protocol Specification v1.0](docs/spec/protocol-spec.md)
- [Formal Security Properties (P1–P5)](docs/spec/security-properties.md)
- [Declarative YAML Policy Language](docs/spec/policy-language.md)

### Architectural Decision Records (ADRs)
- [ADR 0001: JSON and RFC 8785 Canonicalization](docs/adr/0001-canonical-json-over-cbor.md)
- [ADR 0002: Ed25519 for Asymmetric Envelope Signatures](docs/adr/0002-ed25519-for-envelope-signatures.md)
- [ADR 0003: Pure Declarative YAML Policy Engine](docs/adr/0003-declarative-yaml-policy-engine.md)
- [ADR 0004: Quarantine Reader Architecture](docs/adr/0004-quarantine-reader-architecture.md)
- [ADR 0005: Transport Abstraction](docs/adr/0005-in-process-and-http-transport-abstraction.md)

---

## 5. Security Properties (P1–P5)

| Property | Description | Verification Harness |
| :--- | :--- | :--- |
| **P1 Control Integrity** | No action runs without a signed intent covered by a capability token. | `tests/security/test_p1_control_integrity.py` |
| **P2 Data Non-Interference** | Data lane content cannot modify authorized actions or parameters. | `tests/security/test_p2_non_interference.py` |
| **P3 Forgery/Replay Resistance**| Replayed, altered, or unsigned envelopes are deterministically rejected. | `tests/property/test_p3_fuzzing.py` (Hypothesis) |
| **P4 Confinement** | A compromised peer is strictly constrained to its provisioned scope. | `tests/security/test_p4_confinement.py` |
| **P5 Auditability** | Every gate decision is cryptographically chained in a tamper-evident log. | `tests/unit/test_p5_audit_chain.py` |

---

## 6. License

TwinLane is released under the [Apache License, Version 2.0](LICENSE).
