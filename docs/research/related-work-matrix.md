# Related Work Matrix: Comprehensive Comparison of Defenses

This matrix systematically evaluates defense mechanisms across nine architectural and operational dimensions.

---

## 1. Feature Comparison Table

| Approach / System | Boundary Focus | Cryptographic Wire Identity | Needs Dual LLM or Custom Interpreter? | Guarantee Type | Data Provenance Tracking | Capability Attenuation Support | Utility Cost / Latency Overhead | Known Failure Modes / Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Heuristic Prompts / Delimiters** (e.g., Sandwich, XML tags) | Single Agent | No | No | Heuristic | None | None | Negligible (~0 ms) | Easily bypassed via delimiter closing tags, escaping, roleplay, cognitive overload. |
| **Spotlighting** (Hines et al., 2024) | Single Agent | No | No | Heuristic / Statistical | Minimal (token marking) | None | Low (minor token expansion) | Complex instruction-carrying payloads can still guide attention; cannot guarantee tool safety. |
| **Model Alignment** (StruQ, SecAlign, Instruction Hierarchy) | Single Agent | No | No (requires fine-tuning weights) | Statistical | Channel-based in prompt | None | Zero runtime overhead | Statistical only; out-of-distribution adversarial prompts jailbreak alignment; cannot verify wire messages. |
| **Input/Output Classifiers** (Prompt-Guard, Llama-Guard) | Proxy / Perimeter | No | No | Statistical | None | None | Low-to-Medium (~50–200 ms) | Evaded by encoding (base64, homoglyphs), multi-step splitting, paraphrasing; high false-positive rate. |
| **Dual-LLM Pattern** (Simon Willison, 2023) | Single Agent | No | Yes (Two LLM calls) | Structural Isolation | Implicit (tool separation) | None | High (2x model calls and token cost) | Unspecified wire format; vulnerable when untrusted data is passed back to controller as free text. |
| **CaMeL** (Tramer et al., 2025, arXiv:2503.18813) | Single Agent | No | Yes (Custom Python interpreter + Dual LLM) | Strong (by construction) | Object-level in runtime | Yes (runtime capabilities) | High (~2x model calls + custom interpreter overhead) | Single-agent scope; tied to custom runtime; cross-agent compositions fail (*Can CaMeLs Talk?*). |
| **Multi-CaMeL** (arXiv:2610.05640, Oct 2026) | Multi-Agent (hierarchical) | No | Yes (Tied to CaMeL custom runtime) | Deterministic in benchmark (0.0% ASR) | Channel-based across agents | Implicit in CaMeL | High (~2x model calls per agent step) | Tied to CaMeL execution engine; lacks cryptographic wire nonces, signatures, and cross-domain zero-trust. |
| **FIDES** (Microsoft, 2025, arXiv:2505.23643) | Single-Agent / Intra-Framework | No | No (Single LLM + selective quarantine) | Deterministic Policy (IFC) | Explicit (Integrity & Confidentiality) | Policy-based | Medium (policy checks + selective extractions) | Framework-internal middleware (Microsoft Agent Framework); not a cross-organization wire standard. |
| **Progent** (Shi et al., 2025, arXiv:2504.11703) | Single Agent | No | No (SMT solver for policy updates) | Deterministic Pre-Action | None | Monotonic confinement (SMT) | Low (SMT check before tool call) | Restricts tool execution, but does not track data provenance or segregate wire communications. |
| **Open Agent Passport / OAP** (Uchibeke, 2026, arXiv:2603.20953) | Tool Boundary / A2A extension | Proposed | No | Deterministic Authorization | None | Scoped passports | Low (~1–5 ms crypto validation) | Authorizes pre-action tool invocations; lacks end-to-end data provenance tracking on the wire. |
| **Google A2A Protocol** (Linux Foundation / Google) | Multi-Agent (Inter-organization) | Partial (OAuth/OIDC, optional JWS) | No | Transport-only (None for injection) | None | AgentCard scopes | Low (JSON-RPC) | Context injection, credential harvesting in multi-hop, lacks input canonicalization (*A2ABreak*). |
| **Anthropic MCP** (Model Context Protocol) | Agent-to-Tool / Agent-to-Server | No (Transport layer only) | No | Transport-only (None for injection) | None | Server permissions | Low (JSON-RPC) | Susceptible to Tool Poisoning attacks via descriptions/schemas (*MCPTox*, *MCP-DPT*). |
| **TwinLane (Our System)** | **Multi-Agent Wire Protocol** | **Yes (Ed25519, RFC 8785 Canonical JSON, nonces, seq)** | **No (Deterministic Gate; optional quarantine reader)** | **Deterministic within Threat Model** | **Yes (Explicit provenance chain & SHA-256 manifests)** | **Yes (Attenuating signed capability tokens)** | **Minimal (~0.5–2 ms gate latency; 0 extra LLM calls for control)** | Text-only deception (without tool action) requires user provenance inspection; policy quality dependent. |

---

## 2. In-Depth Comparison with Closest Competitors

### 2.1 TwinLane vs. Multi-CaMeL
- **Similarity**: Both recognize that multi-agent systems must maintain strict separation between control instructions and untrusted data across agent interactions.
- **Differences**:
  1. *Runtime Independence*: Multi-CaMeL requires all participating agents to run inside the CaMeL execution framework with its custom Python sandbox interpreter and mandatory dual-LLM structure. TwinLane is an interoperable **wire protocol**: Agent A (written in Python/FastAPI) can communicate with Agent B (written in Go, Rust, or TypeScript) using standard JSON over HTTP or message queues.
  2. *Cryptographic Identity & Anti-Replay*: TwinLane introduces Ed25519 asymmetric signatures, RFC 8785 canonicalization, session sequence numbers, and cryptographic nonces. Multi-CaMeL does not focus on wire-level transport security or message replay.
  3. *Attenuating Capability Tokens*: TwinLane includes cryptographically signed, parent-chained capability tokens that allow an orchestrator to strictly bound what a downstream worker or third-party agent can request.

### 2.2 TwinLane vs. FIDES (Microsoft)
- **Similarity**: Both employ a two-dimensional label system (`Integrity` $\in \{\text{TRUSTED}, \text{UNTRUSTED}\}$ and `Confidentiality` $\in \{\text{PUBLIC}, \text{INTERNAL}, \text{SECRET}\}$), with deterministic pre-action policy evaluation and sanctioned data extraction.
- **Differences**:
  1. *Wire Envelope vs. Internal Middleware*: FIDES operates as internal planner middleware inside an agent framework. TwinLane packages these labels into a portable wire envelope where data items are hash-bound to a signed manifest.
  2. *Cross-Domain Federation*: FIDES assumes a single trust perimeter. TwinLane explicitly targets mutually untrusted agents operating across different organizational boundaries.

### 2.3 TwinLane vs. OAP (Open Agent Passport)
- **Similarity**: Both advocate for deterministic pre-action authorization rather than relying on probabilistic LLM alignment.
- **Differences**:
  1. *Provenance Integration*: OAP evaluates permissions based on the agent's identity and passport. TwinLane combines capability checks with **data provenance tracking**: an action is denied if any sensitive parameter is tainted by untrusted data without having passed a sanctioned extractor.
  2. *Two-Lane Protocol*: TwinLane strictly isolates typed control intents from untrusted data items within the wire envelope itself, preventing prompt injection from masquerading as a command.

