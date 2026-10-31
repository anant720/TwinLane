# PBA 2 Slide Outline: TwinLane Protocol

**Title**: TwinLane: A Zero-Trust Protocol for Prompt-Injection-Resistant Agent-to-Agent Communication  
**Presenters**: Anant, Shweta, Aditya  
**Target Duration**: 8–10 Minutes  

---

## Slide 1: The Multi-Agent Trust Boundary Problem
- **The Core Vulnerability**: LLMs process control commands and passive data as a single continuous token stream (in-band architecture).
- **The Multi-Agent Danger**:
  - Boundary laundering (Worker reads web page -> summarizes -> Orchestrator promotes summary to command).
  - Confused deputy attacks across organizational boundaries.
  - Wire tampering and message replays.
- **Visual**: Diagram showing an untrusted web page injecting an email exfiltration command that crosses from Worker to Orchestrator.

---

## Slide 2: Honest Academic Positioning & Gap Analysis
- **Concession**: The principle of separating control from data is **NOT new**:
  - CaMeL (Google DeepMind, 2025): Single-agent, dual-LLM with custom Python interpreter.
  - Multi-CaMeL (Oct 2026): Hierarchical agent channels tied to CaMeL runtime.
  - FIDES (Microsoft, 2025): Information-flow control labels inside Microsoft Agent Framework.
- **The Open Gap**:
  - Existing defenses require heavy custom interpreters or dual LLMs (~2x cost/latency).
  - Inter-agent protocols (A2A, MCP) lack cryptographic message integrity, nonces, and capability bounding.
- **TwinLane's Contribution**: A lightweight, wire-level zero-trust protocol with Ed25519 identity, attenuating capability tokens, and a deterministic gate—no custom interpreter and no mandatory second LLM.

---

## Slide 3: The TwinLane Architecture: Two Lanes, One Gate
- **Control Lane**: Strictly typed, schema-validated intents from an agreed Intent Catalog. Zero free-text commands.
- **Data Lane**: Content items with explicit provenance and security labels (`TRUSTED` / `UNTRUSTED`).
- **Cryptographic Wire Envelope**: Header + Control + Data Manifest signed with Ed25519 over RFC 8785 canonical JSON.
- **Deterministic Gate**: Evaluates authorization, parameter bounds, and provenance before tool execution. **No LLM decides security outcomes.**

---

## Slide 4: Capability Tokens & Monotonic Attenuation
- **Saltzer & Schroeder Principle of Least Privilege**:
  - An orchestrator delegates a sub-token to a worker.
  - Monotonic narrowing invariant: $\text{Scope}(\mathcal{C}_{child}) \subseteq \text{Scope}(\mathcal{C}_{parent})$.
- **Blast-Radius Confinement**: Even if Worker B is 100% compromised or malicious, it cannot invoke ungranted tools or exceed numeric/allowlist bounds.

---

## 5. Slide 5: The 7-Step Gate Pipeline
- Walkthrough of the linear, fail-closed verification pipeline:
  1. Authenticate (Ed25519 signature, Trust Store, 128-bit Nonce, Seq counter, Expiry).
  2. Validate (Intent Catalog schema, reject unknown fields).
  3. Authorize (Capability Token check, constraint validation).
  4. Provenance Check (Untrusted data blocked from sensitive parameters).
  5. Quarantine Route (Passive data routed to zero-tool reader).
  6. Policy Decision (`ALLOW`, `DENY`, `ESCALATE`).
  7. Append Audit Record (SHA-256 hash-chained log).

---

## Slide 6: Benchmark & Empirical Evaluation
- **Methodology**: 12 attack categories (direct override, boundary laundering, encoding tricks, tool spoofing, split payloads, parameter exfiltration).
- **Comparative Baselines**:
  - B0: Naive (Unprotected free-text).
  - B1: Spotlighting / System Prompts (Delimiters).
  - B2: Input Classifiers (Prompt-Guard).
  - TL: TwinLane Protected.
- **Key Metrics**: Attack Success Rate (ASR) with Wilson 95% confidence intervals, benign task success, latency overhead, Gate CPU time.

---

## Slide 7: Live 5-Minute Demonstration Walkthrough
- Side-by-side terminal / web UI execution:
  - Injection attack launched against Naive Baseline -> Canary token exfiltrated to mock outbox (Breach!).
  - Identical attack launched against TwinLane -> Gate blocks parameter at Step 4; Decision: `DENY` with audit hash chain generated.
  - Zero false positives on benign multi-agent workflows.

---

## Slide 8: Limitations, Roadmap & Summary
- **Limitations Stated Plainly**:
  - Does not prevent pure text deception that triggers no tool action.
  - Security depends on well-formed declarative policies.
- **Roadmap**:
  - A2A compatibility adapter.
  - Multi-hop distributed federation.
- **Takeaway**: TwinLane turns theoretical control/data separation into an auditable, lightweight wire reality for production AI agents.
