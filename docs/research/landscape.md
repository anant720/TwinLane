# Landscape: Defenses Against Prompt Injection and Agent Vulnerabilities

## 1. Introduction

Large Language Models (LLMs) fundamentally operate on an **in-band architecture**: instructions (system prompts, developer guidelines) and external data (user queries, retrieved web pages, email messages, tool outputs) are concatenated into a single linear sequence of tokens. Because transformers lack hardware-level separation between executable code and passive data, an attacker can embed natural-language directives inside untrusted content. When the model processes this untrusted content, it can be induced to treat the embedded data as privileged instructions—a vulnerability known as **Indirect Prompt Injection (IPI)**.

In multi-agent systems (MAS), this vulnerability compounds across agent boundaries:
- **Boundary Laundering**: A worker agent reads an untrusted document containing an injection payload, produces a seemingly benign summary, and forwards it to an orchestrator agent. The orchestrator consumes the summary as trusted guidance, promoting the attacker's payload across trust perimeters.
- **Confused Deputy Attacks**: An unprivileged agent tricks a privileged peer into executing tools or accessing resources on its behalf.
- **Rogue or Compromised Peers**: An agent operated by a third party or compromised by an earlier exploit issues malicious commands to peer agents.
- **Wire-Level Tampering**: Traditional multi-agent transports lack cryptographic nonces, message sequence tracking, and payload binding, leaving agents vulnerable to replay, forgery, and parameter swapping.

Below, we survey the eight primary families of defenses developed to address prompt injection and multi-agent security vulnerabilities.

---

## 2. Taxonomy of Defense Families

```
+---------------------------------------------------------------------------------------------------+
|                                  Prompt Injection Defenses                                        |
+---------------------------------------------------------------------------------------------------+
           |                                     |                                    |
+----------------------+              +----------------------+             +----------------------+
|  Heuristic / Prompt  |              |  Model / Fine-Tuning |             | System / Dynamic IFC |
+----------------------+              +----------------------+             +----------------------+
| - System Prompts     |              | - StruQ (USENIX '24) |             | - Dual-LLM (Willison)|
| - Delimiters         |              | - SecAlign (2024)    |             | - CaMeL (DeepMind)   |
| - Spotlighting (MSFT)|              | - Instruction        |             | - Multi-CaMeL (2026) |
| - Sandwich Defense   |              |   Hierarchy (OpenAI) |             | - FIDES (MSFT, 2025) |
+----------------------+              +----------------------+             +----------------------+
           |                                     |                                    |
           v                                     v                                    v
  Heuristic/Bypassable                   Statistical, Internal             Deterministic Runtime
                                                                           Policy & Provenance
```

---

### 2.1 Heuristic Prompt Defenses (Delimiters, Spotlighting, System Prompts)

- **Mechanism**: The system prompt instructs the LLM to ignore commands found within data sections, wraps untrusted content in special XML/Markdown delimiters (e.g., `<user_data>...</user_data>`), repeats the system prompt after untrusted content (sandwich defense), or applies data-marking transformations (Spotlighting; Hines et al., Microsoft Research, 2024).
- **Security Guarantee**: **None (Heuristic)**.
- **Strengths**: Zero code changes to agent runtimes; zero training cost; easy to implement across existing APIs.
- **Weaknesses**: Vulnerable to adaptive attacks. Attackers routinely escape delimiters via closing tags, payload obfuscation, role-playing, cognitive overload, and multi-step reasoning tricks. Because the LLM remains the judge of its own compliance, heuristic defenses fail under adversarial pressure.

---

### 2.2 Fine-Tuning and Model-Internal Alignment (StruQ, SecAlign, Instruction Hierarchy)

- **StruQ (Chen et al., USENIX Security 2024)**: Inspired by SQL prepared statements, StruQ formats prompts and data into structured channels demarcated by special control tokens. Models undergo *Structured Instruction Tuning* on synthetic corpora containing adversarial data to train the model to ignore instructions in data channels.
- **SecAlign (Zhang et al., 2024)**: Leverages Direct Preference Optimization (DPO) to steer model weights toward safe completions when confronted with prompt injections, maximizing the probability gap between adhering to system instructions versus following injected directives.
- **OpenAI Instruction Hierarchy (Wallace et al., 2024)**: Explicitly trains models to prioritize system instructions over user messages, and user messages over tool/data inputs.
- **Security Guarantee**: **Statistical**.
- **Strengths**: Built directly into model weights; introduces negligible inference latency overhead; preserves general downstream utility.
- **Weaknesses**: Requires access to model training or fine-tuning weights (unavailable for proprietary closed models). Crucially, statistical robustness does not offer deterministic guarantees; out-of-distribution adversarial prompts or sophisticated jailbreaks can still override learned priorities. Furthermore, model-internal training cannot verify cross-agent wire integrity or enforce capability constraints between independent organizations.

---

### 2.3 Input/Output Classifiers and Detectors

- **Mechanism**: Dedicated binary or multi-class models (e.g., Prompt Guard, Llama-Guard, Lakera Gandalf, fine-tuned DeBERTa classifiers) inspect incoming text before it reaches the target LLM or evaluate generated responses before execution.
- **Security Guarantee**: **Statistical**.
- **Strengths**: Can be deployed as a bump-in-the-wire proxy without modifying agent architectures.
- **Weaknesses**: Inherently subject to the classifier arms race. Vulnerable to evasion via base64, Unicode homoglyphs, zero-width spaces, leetspeak, multilingual phrasing, and multi-turn splitting. High false-positive rates on complex, technical, or benign security queries degrade agent utility.

---

### 2.4 Dual-LLM Architecture and CaMeL (Google DeepMind / ETH Zurich)

- **Dual-LLM Pattern (Simon Willison, 2023)**: Proposes partitioning the system into two distinct models: a **Privileged Controller LLM** that plans actions and holds tool access, and an **Unprivileged / Quarantined LLM** that parses untrusted input and returns plain text data without tool invocation capabilities.
- **CaMeL (Capabilities for Machine Learning; Tramer et al., Google / ETH Zurich, 2025, arXiv:2503.18813)**: Formalizes the dual-LLM pattern into a rigorous capability-based architecture for single-agent systems.
  - Generates an execution plan from trusted user instructions.
  - When untrusted data must be parsed, it executes within a quarantined sandbox environment.
  - A custom Python-based runtime interpreter tracks data provenance and evaluates capability policies before any tool execution occurs.
- **Security Guarantee**: **Strong (By Construction / Deterministic for targeted threat model)**.
- **Strengths**: Successfully prevents indirect prompt injection from triggering unauthorized tool execution within a single agent workflow.
- **Weaknesses**:
  - Heavy infrastructure footprint: requires a specialized runtime interpreter and at least two distinct LLM calls per step (~2x inference cost and latency).
  - Designed for a single-agent sandbox; does not address distributed multi-agent wire protocols, cryptographic identity, replay attacks, or cross-domain delegation.

---

### 2.5 Multi-CaMeL (October 2026, arXiv:2610.05640)

- **Title**: *"Can CaMeLs Talk? Securing Multi-Agent Systems Against Indirect Prompt Injection Attacks"*.
- **The Problem**: Demonstrates that single-agent CaMeL guarantees do **not** automatically compose in hierarchical multi-agent systems. When Agent A invokes Agent B as a tool, untrusted data processed by B can be laundered and re-interpreted as trusted instructions by A.
- **The Solution**: Introduces an agent-to-agent protocol that maintains separate channels for natural-language instructions and untrusted data across agent boundaries, ensuring that data provenance is preserved throughout the invocation tree.
- **Security Guarantee**: **Deterministic (Zero successful attacks in tested multi-agent benchmarks)**.
- **Strengths**: Solves boundary laundering in hierarchical agent tool invocation; achieves 0.0% ASR on its evaluation suite.
- **Weaknesses**:
  - Tightly coupled to the CaMeL runtime, custom Python interpreter, and dual-LLM architecture.
  - Focuses on intra-system agent tool invocation rather than an open, zero-trust wire protocol for mutually untrusted peers across distinct organizations.
  - Does not establish cryptographic wire envelopes, Ed25519 signatures, sequence anti-replay counters, or portable capability tokens.

---

### 2.6 Information-Flow Control (IFC) and FIDES (Microsoft Research, 2025)

- **Title**: *"Securing AI Agents with Information-Flow Control"* (arXiv:2505.23643; integrated into Microsoft Agent Framework).
- **Mechanism**: FIDES (Flow Integrity Deterministic Enforcement System) implements dynamic taint tracking and information-flow control directly within the agent planner.
  - Every data item is tagged with a two-dimensional security label: **Confidentiality** (e.g., Public, Internal, Secret) and **Integrity** (Trusted, Untrusted).
  - Taint propagates monotonically through all agent transformations: any output derived from untrusted input inherits the untrusted taint label.
  - Before a sensitive action or tool executes, a deterministic policy engine checks whether the parameters and execution context satisfy integrity and confidentiality constraints.
  - Employs *selective hiding* and *quarantined extractions* to safely extract necessary fields from untrusted documents.
- **Security Guarantee**: **Deterministic Policy Enforcement**.
- **Strengths**: Provides a formal security model for agent planners; effectively blocks both indirect prompt injection and private data exfiltration without requiring full dual-LLM replication for every task.
- **Weaknesses**:
  - Formulated as internal framework middleware for a single agent runtime (e.g., Microsoft Agent Framework), not as an interoperable network wire protocol.
  - Lacks cryptographic authentication, wire serialization rules, message signing, and multi-party capability delegation.

---

### 2.7 Privilege Control and Deterministic Pre-Action Authorization (Progent, OAP)

- **Progent (Shi et al., 2025, arXiv:2504.11703)**:
  - Formulates agent privileges as symbolic security policies over tool names and arguments using a domain-specific language (DSL).
  - Enforces *monotonic confinement* via an SMT solver: policies can only be narrowed dynamically, never expanded without explicit user authorization.
  - Synchronously blocks unauthorized tool executions deterministically at runtime.
- **Open Agent Passport / OAP (Uche Uchibeke, 2026, arXiv:2603.20953)**:
  - Addresses the *pre-action authorization problem*: agents possess credentials but lack cryptographically verifiable permission slips for individual tool calls.
  - Intercepts tool calls prior to execution and evaluates them against declarative policies, issuing signed authorization audit trails.
- **Security Guarantee**: **Deterministic Authorization**.
- **Strengths**: Enforces principle of least privilege outside the model; prevents over-privileged agents from executing out-of-scope actions.
- **Weaknesses**: Focuses exclusively on authorizing actions at the tool boundary. Does not track cross-agent data provenance on the wire, nor does it isolate control flows from data flows during agent-to-agent message exchange.

---

### 2.8 Protocol-Level Security Analysis (A2A, ACP, CORAL, MCP)

Recent research has begun analyzing communication protocols designed for agent interoperability:
- **Google / Linux Foundation Agent-to-Agent (A2A) Protocol**:
  - Enables agent discovery via `AgentCard` and task delegation via JSON-RPC.
  - **Vulnerabilities**: *A2ABreak* (Lotfi et al., 2026, arXiv:2609.10871) demonstrated cross-client context injection, credential harvesting in multi-hop delegation, and exfiltration via rogue capability advertisements. Louck et al. (2025, arXiv:2505.12490) demonstrated that A2A lacks ephemeral token scoping and strong customer authentication.
- **Agent Communication Protocol (ACP) & CORAL**:
  - Louck et al. (2025, arXiv:2511.03841) conducted a comparative security audit. ACP makes JSON Web Signatures (JWS) optional, leaving message integrity vulnerable, while CORAL suffers from authorization breakdowns at its Server-Sent Events (SSE) gateway.
- **Model Context Protocol (MCP)**:
  - Anthropic's open standard for connecting LLMs to tools and data servers.
  - **Vulnerabilities**: *MCPTox* (2025, arXiv:2508.14925) and *MCP-DPT* (Rostamzadeh et al., 2026, arXiv:2604.07551) proved that MCP servers can poison agents simply by injecting instructions into tool descriptions and schemas, achieving up to 72.8% ASR against frontier models without executing any tools.

---

## 3. Summary of the State of the Art

Across the surveyed landscape, an important pattern emerges:
1. **The separation of control from data** has been proven effective inside single agents (CaMeL) and inside proprietary agent invocation hierarchies (Multi-CaMeL).
2. **Information-Flow Control (IFC)** has been proven effective for policy enforcement within monolithic agent frameworks (FIDES).
3. **Pre-action deterministic gating** has been proven effective for restricting tool privileges (Progent, OAP).
4. **However**, inter-agent protocols (A2A, MCP, ACP) still transport unstructured text or loosely typed JSON over the wire without cryptographic provenance tracking, strict control/data lane separation, or attenuating capability tokens.

This gap is where **TwinLane** is situated.

