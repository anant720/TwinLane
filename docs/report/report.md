# TwinLane: A Zero-Trust Protocol for Prompt-Injection-Resistant Agent-to-Agent Communication

**Technical Research & Engineering Report**  
**Authors**: Anant, Shweta, Aditya  
**Date**: October 2026  
**Status**: Reference Architecture & Prototype  

---

## 1. Executive Summary

Autonomous Large Language Model (LLM) agents are increasingly organized into multi-agent systems (MAS) to solve complex workflows spanning distinct organizations, microservices, and tool ecosystems. However, the fundamental in-band nature of LLMs—wherein system instructions and external data are parsed as a continuous token sequence—renders multi-agent systems acutely vulnerable to **indirect prompt injection (IPI)**. In multi-agent interactions, this vulnerability manifests as **boundary laundering**, **confused deputy attacks**, **wire message tampering**, and **cascading peer compromises**.

Existing state-of-the-art defenses (such as CaMeL and Multi-CaMeL) demonstrate that separating control instructions from untrusted data can successfully prevent unauthorized actions. However, these systems rely on heavyweight custom Python interpreters, require mandatory dual-LLM execution for all operations, and do not provide an interoperable, wire-level zero-trust transport for mutually untrusted agents across organizational boundaries.

**TwinLane** addresses this gap by defining a lightweight, framework-agnostic wire protocol and deterministic Gate pipeline featuring:
1. **Two-Lane Cryptographic Envelopes**: Typed, schema-validated command intents in the Control Lane, separated from provenance-labelled items in the Data Lane.
2. **Asymmetric Wire Identity & Replay Protection**: Ed25519 digital signatures over RFC 8785 canonical JSON with monotonic sequence tracking, 128-bit nonces, and bounded TTLs.
3. **Attenuating Capability Tokens**: Mathematically provable monotonic narrowing of delegated permissions, confining even compromised peers to their pre-allocated blast radius.
4. **Deterministic Gate**: A 7-step fail-closed verification pipeline evaluated outside the model. No LLM ever makes an authorization decision.
5. **Tamper-Evident Audit Chains**: Every gate evaluation appends an entry to a SHA-256 hash-chained log.

---

## 2. Research Landscape & Honest Positioning

### 2.1 Concession of Prior Art
TwinLane does not claim that the principle of separating control from data is new. We acknowledge foundational prior work:
- **Dual-LLM Isolation**: Simon Willison (2023).
- **Structured Instruction Channels**: StruQ (Chen et al., USENIX Security 2024).
- **Capability Sandboxing in Single Agents**: CaMeL (Tramer et al., Google DeepMind / ETH Zurich, arXiv:2503.18813).
- **Multi-Agent Channel Separation**: Multi-CaMeL (*Can CaMeLs Talk?*, October 2026, arXiv:2610.05640).
- **Information-Flow Control Labels**: FIDES (Microsoft Research, arXiv:2505.23643).
- **Pre-Action Deterministic Authorization**: Progent (Shi et al., arXiv:2504.11703) and OAP (Uchibeke, arXiv:2603.20953).

### 2.2 TwinLane's Differentiating Contribution
Where prior work is embedded within single-agent runtimes or requires custom language interpreters and dual LLMs for every task, TwinLane provides:
- An **interoperable wire protocol** that works across languages and frameworks.
- Wire-level cryptographic signatures and sequence freshness.
- Portable, attenuating capability tokens for cross-organization delegation.
- Sub-millisecond gate execution with zero LLM overhead for benign control messages.

---

## 3. Protocol Architecture & Invariants

*(Detailed in `docs/spec/protocol-spec.md` and `docs/spec/threat-model.md`)*

### Invariants:
1. **Fail-Closed Gate**: Any validation, cryptographic, or schema error immediately yields `DENY`.
2. **Channel Isolation**: Data Lane content cannot bind to control parameters without registered Sanctioned Extractors.
3. **Monotonic Confinement**: Capability delegation can only narrow privileges, never expand them.

---

## 4. Empirical Evaluation Plan

TwinLane is evaluated against three baselines across 12 distinct attack categories:
- **B0: Naive Baseline**: Unprotected natural-language agent communication.
- **B1: Spotlighting Baseline**: Delimiters and defensive prompt framing.
- **B2: Classifier Baseline**: Input injection filter (Prompt-Guard style).
- **TL: TwinLane Protocol**: Full 7-step Gate verification.

### Target Metrics:
- Attack Success Rate (ASR) with Wilson 95% confidence intervals.
- Benign Task Success Rate and False Block Rate.
- P50 and P95 latency overhead.
- Gate CPU evaluation time.

*(Empirical results will be populated upon completion of Phase 6 benchmarks).*

