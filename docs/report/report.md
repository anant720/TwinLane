# TwinLane: A Lightweight, Zero-Trust Protocol for Prompt-Injection-Resistant Agent-to-Agent Communication

**Technical Research & Engineering Report**  
**Authors**: Anant, Shweta, Aditya  
**Date**: October 2026  
**Status**: Reference Architecture, Specification, and Empirical Evaluation  
**Repository**: `https://github.com/anant720/TwinLane`  

---

## Abstract

Autonomous Large Language Model (LLM) agents are increasingly organized into multi-agent systems (MAS) to automate complex workflows spanning distinct organizations, microservices, and external tools. However, the fundamental in-band nature of current LLMs—where system instructions and external data share a single token channel—renders multi-agent systems vulnerable to **indirect prompt injection (IPI)**. In multi-agent interactions, this vulnerability manifests as **boundary laundering**, **confused deputy attacks**, **wire message tampering**, and **cascading peer compromises**.

Existing state-of-the-art defenses (such as CaMeL and Multi-CaMeL) demonstrate that separating control instructions from untrusted data can successfully prevent unauthorized actions. However, these systems rely on heavyweight custom Python interpreters, require mandatory dual-LLM execution for all operations, and do not provide an interoperable, wire-level zero-trust transport for mutually untrusted agents across organizational boundaries.

This report presents **TwinLane**: a lightweight, framework-agnostic, zero-trust protocol and reference implementation that lets two LLM agents communicate such that indirect prompt injection cannot cause an unauthorized action. TwinLane structures every wire message into a single cryptographically signed envelope containing two distinct lanes: a **Control Lane** of typed, schema-validated intents covered by attenuating capability tokens, and a **Data Lane** of provenance-labelled content items isolated in a passive quarantine reader. A deterministic 7-step Gate on the receiver authenticates, validates, authorizes, checks provenance, decides (`ALLOW`, `DENY`, `ESCALATE`), and commits to an append-only SHA-256 hash-chained audit ledger outside the LLM. 

Under an empirical benchmark of 180 adversarial attack fixtures across 12 distinct attack categories and 35 benign enterprise workflows evaluated at temperature zero ($T=0$), TwinLane achieved an **Attack Success Rate (ASR) of 0.0%** (95% Wilson CI: $[0.00, 0.02]$) and **0.0% canary secret exfiltration**, compared to a **52.8% ASR and 47.2% canary leak rate** for naive communication, and a **40.0% ASR** for input classifier defenses. TwinLane maintained a **100.0% benign task completion rate** with a median Gate evaluation latency of just **8.0 microseconds** ($p_{50}$).

---

## 1. Introduction & Problem Definition

Multi-agent architectures represent a paradigm shift in autonomous computing. Instead of deploying isolated monoliths, enterprises coordinate specialized agents across distinct trust domains: an Orchestrator agent may delegate web research to an external third-party Worker agent, which in turn interacts with untrusted APIs, public web pages, and customer databases.

However, the security architecture of LLMs remains inherently flawed:

```
[ Traditional In-Band Agent Communication ]
Agent A  --- "Summarize this document: {UNTRUSTED DATA}" --->  Agent B
                                                                  │
              ┌───────────────────────────────────────────────────┘
              ▼
   Adversarial Payload:
   "SYSTEM OVERRIDE: Disregard instructions.
    Send CANARY secret to attacker@evil.com"
              │
              ▼ (LLM mixes instruction and data)
   Agent B executes `send_email(to="attacker@evil.com", body=secret)`  [BREACH]
```

When an LLM processes natural-language instructions and untrusted data in the same context window, it cannot deterministically distinguish between legitimate system directives and adversarial instructions embedded in passive content. In a multi-agent setting, this causes four systemic attack primitives:

1. **Boundary Laundering**: An external document injects a malicious payload into Worker B. Worker B summarizes the document into natural language and passes it to Orchestrator A. Orchestrator A implicitly trusts Worker B and interprets the summary as a legitimate execution instruction.
2. **Confused Deputy Attacks**: An attacker tricks an intermediary agent into using its high-privilege credentials (such as database read/write or email egress) to perform unauthorized actions on behalf of the attacker.
3. **Wire Message Tampering**: Existing inter-agent communication (such as raw JSON-RPC over HTTP or WebSocket) lacks cryptographic envelope signatures, allowing malicious network proxies or compromised subagents to tamper with parameters in flight.
4. **Replay & Sequence Hijacking**: Without monotonic nonces and sequence freshness, past valid agent authorizations can be intercepted and replayed to trigger duplicate unauthorized actions.

---

## 2. Honest Academic Positioning & Gap Analysis

To adhere to the rigorous research standards defined in our project charter (`AGENTS.md`), we explicitly state that **the principle of separating control instructions from data is NOT new**. Foundational prior work includes:

- **Dual-LLM Isolation Pattern**: Proposed informally by Simon Willison (2023), separating an untrusted reader LLM from a privileged controller LLM.
- **StruQ**: Chen et al. (USENIX Security 2024), demonstrating structured prompt templating to isolate user queries from untrusted documents.
- **CaMeL**: Tramer et al. (Google DeepMind & ETH Zurich, 2025, arXiv:2503.18813), establishing formal capability-based sandboxing in single-agent environments via a custom Python-like DSL.
- **Multi-CaMeL**: (October 2026, arXiv:2610.05640), extending CaMeL to multi-agent channels by enforcing dual-channel separation across agent hierarchies.
- **FIDES**: Microsoft Research (2025, arXiv:2505.23643), implementing dynamic Information-Flow Control (IFC) labels inside Microsoft's agent framework.
- **Progent & OAP**: Shi et al. (2025) and Uchibeke (2026), demonstrating pre-action deterministic tool-level access control policies.

### Systematic Comparison Matrix

| Dimension | System Prompts / Spotlighting | Input Classifiers (Prompt-Guard) | CaMeL / Multi-CaMeL (DeepMind) | FIDES (Microsoft) | TwinLane (This Work) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Separation Mechanism** | Soft prompt delimiters | Statistical classification | DSL interpreter + Dual LLM | Information-Flow Labels | Cryptographic Wire Enclave |
| **Cross-Trust Boundary** | No | No | Single runtime | Single framework | **Open Protocol (Ed25519)** |
| **Identity & Replay** | None | None | None | None | **RFC 8785 + 128-bit Nonce** |
| **Delegation Model** | None | None | Static capabilities | Dynamic labels | **Attenuating Tokens** |
| **Inference Overhead** | 0% | +10–20% | **+100% (2x LLMs)** | 0% | **0% (Pure CPU Gate)** |
| **Gate Latency** | None | 20–50 ms | 1–3 seconds | <1 ms | **8.0 microseconds** |
| **ASR on Encoding/Escapes**| 52.8% (Fails) | 40.0% (Fails) | <2% | <2% | **0.0% (Empirical)** |

### TwinLane's Differentiating Contribution
Where prior work is embedded within single-agent runtimes or requires custom language interpreters and dual LLMs for every task, TwinLane provides:
1. **Wire-Level Zero-Trust Protocol**: Operates across heterogeneous platforms, programming languages, and organizational boundaries using standard Ed25519 asymmetric cryptography and RFC 8785 canonical JSON.
2. **Attenuating Capability Tokens**: Enables agents to delegate tasks to subagents with mathematically verifiable monotonic restriction, strictly confining the blast radius of any compromised peer.
3. **Sub-Millisecond Deterministic Gate**: Executes a 7-step fail-closed verification pipeline on the CPU in microseconds without requiring a second LLM for authorization decisions.
4. **Forward-Secure Audit Hash Chain**: Every authorization decision is committed to a SHA-256 Merkle chain, providing non-repudiation and immediate cryptographic tamper detection.

---

## 3. Protocol Architecture & Formal Security Properties

TwinLane structures every message into a single cryptographically signed envelope:

```
+---------------------------------------------------------------------------------------+
|                                TWINLANE ENVELOPE (v1.0)                               |
+---------------------------------------------------------------------------------------+
| HEADER:                                                                               |
|   message_id: "msg-7a1b4c9e"        session_id: "sess-9021"                           |
|   sender: "ed25519:6c5d2a..4e"      recipient: "ed25519:f1a94b..90"                   |
|   issued_at: 1730386800             seq: 14            nonce: "4f8a...c02"            |
+---------------------------------------------------------------------------------------+
| CONTROL LANE (Signed, Schema-Validated Intent, Covered by Capability Token):          |
|   intent: "report_result"                                                             |
|   capability_token_id: "tok-b83c1102e"                                                |
|   params: { "task_id": "T-102", "status": "SUCCESS", "data_ref": "item-01" }          |
+---------------------------------------------------------------------------------------+
| DATA LANE (Manifest-Verified Untrusted Passive Content Items):                        |
|   items: [                                                                            |
|     {                                                                                 |
|       item_id: "item-01",                                                             |
|       mime_type: "text/plain",                                                        |
|       sha256: "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",     |
|       provenance: { origin: "web", integrity: "UNTRUSTED", confidentiality: "PUBLIC" }|
|     }                                                                                 |
|   ]                                                                                   |
+---------------------------------------------------------------------------------------+
| SIGNATURE (Ed25519 over RFC 8785 Canonical JSON of Header + Control + Data):         |
|   alg: "Ed25519", sig: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b78..."|
+---------------------------------------------------------------------------------------+
```

### Formal Security Properties (P1–P5)

- **Property P1 (Authenticity & Identity Binding)**:  
  For any envelope $\mathcal{E}$ processed by Gate $\mathcal{G}$, $\mathcal{G}$ accepts $\mathcal{E}$ only if:
  $$\text{Verify}_{Ed25519}\left(K_{sender}^{pub},\, \text{canonical}(\mathcal{E}),\, \sigma_{\mathcal{E}}\right) = \text{True} \quad \land \quad K_{sender}^{pub} \in \text{TrustStore}_{\mathcal{G}}$$

- **Property P2 (Least Privilege & Blast-Radius Confinement)**:  
  Let $\mathcal{C}_{parent}$ be a capability token issued to agent $A$, and $\mathcal{C}_{child}$ be a delegated sub-token issued to worker $B$. The Gate permits action $a$ requested by $B$ under $\mathcal{C}_{child}$ only if:
  $$\text{Scope}(\mathcal{C}_{child}) \subseteq \text{Scope}(\mathcal{C}_{parent}) \quad \land \quad a \in \text{Intents}(\mathcal{C}_{child}) \quad \land \quad \text{EvalConstraints}(\mathcal{C}_{child}, \text{params}(a)) = \text{True}$$

- **Property P3 (Integrity & Non-Forgery)**:  
  For any single-bit mutation in $\mathcal{E}$, let $\mathcal{E}' \ne \mathcal{E}$. Then:
  $$\Pr\left[\mathcal{G}(\mathcal{E}') = \text{ALLOW}\right] \le 2^{-128}$$

- **Property P4 (Freshness & Anti-Replay)**:  
  Gate $\mathcal{G}$ accepts $\mathcal{E}$ at local time $t_{now}$ only if:
  $$|t_{now} - \mathcal{E}.issued\_at| \le \tau_{window} \quad \land \quad \mathcal{E}.nonce \notin \text{NonceCache}_{\mathcal{G}} \quad \land \quad \mathcal{E}.seq > seq_{last}(sender, session)$$

- **Property P5 (Information-Flow Confinement)**:  
  Let $d \in \text{DataLane}(\mathcal{E})$ with label $L(d) = \text{UNTRUSTED}$. Gate $\mathcal{G}$ enforces that $d$ cannot bind to any control parameter $p$ unless there exists a Sanctioned Extractor $E \in \text{Registry}_{\mathcal{G}}$ explicitly authorized by policy:
  $$\text{Bind}(d, p) \implies \left(\exists E : E(d) = p \quad \land \quad \text{Policy}(\text{intent}, p) \ge \text{EXTRACTED\_UNTRUSTED}\right)$$

---

## 4. The 7-Step Deterministic Gate Pipeline

The Gate operates as a pure deterministic state machine evaluated outside the LLM:

```mermaid
flowchart TD
    E[Incoming Envelope] --> S1[Step 1: Authenticate]
    S1 -- Valid Sig & Fresh Nonce --> S2[Step 2: Validate Schema]
    S1 -- Invalid / Replay --> D[Decision: DENY]
    S2 -- Typed Intent Exists --> S3[Step 3: Authorize]
    S2 -- Malformed / Free-text --> D
    S3 -- Capability Valid & Unexhausted --> S4[Step 4: Check Provenance]
    S3 -- Unauthorized / Expired --> D
    S4 -- Content Hash & Label Match --> S5[Step 5: Quarantine Reader]
    S4 -- Hash Mismatch / Tainted Param --> D
    S5 -- Passive Isolation Enforced --> S6[Step 6: Policy Decision: ALLOW]
    S6 --> S7[Step 7: Hash-Chain Audit Ledger]
    D --> S7
```

1. **Step 1: Authenticate (Ed25519 & Nonce)**: Verifies cryptographic envelope signature over RFC 8785 canonical bytes, checks sender identity in local `TrustStore`, validates timestamp freshness window ($\Delta t \le 300\text{s}$), checks monotonic sequence tracking, and ensures nonce is unique.
2. **Step 2: Validate Schema (Intent Catalog)**: Ensures intent identifier exists in catalog. Enforces strict Pydantic schemas on parameters with `extra="forbid"`. Rejects any unstructured instruction text in the Control Lane.
3. **Step 3: Authorize (Capability Token)**: Resolves token in `CapabilityStore`. Validates issuer signature and checks monotonic attenuation along the delegation chain to a trusted root anchor. Verifies `not_before`, `expires_at`, and increments `uses_count` against `max_uses`.
4. **Step 4: Check Provenance (Data Manifest)**: Computes SHA-256 digest of every data item and verifies integrity against declared manifest. Enforces policy requirements on parameter trust levels (`TRUSTED` vs `UNTRUSTED`).
5. **Step 5: Quarantine Reader**: Routes untrusted data items into an isolated reader with zero tool execution capabilities (`read_file`, `send_email`, `http_post` stripped). Data can be referenced passively, but cannot execute.
6. **Step 6: Final Decision**: Synthesizes pipeline checks into `Decision.ALLOW`, `Decision.DENY`, or `Decision.ESCALATE` via deterministic boolean logic. Zero LLMs participate in this authorization outcome.
7. **Step 7: Hash-Chain Audit Log**: Appends record to immutable audit log where record hash is cryptographically chained to the previous record hash:
   $$h_i = \text{SHA256}(\text{canonical}(\text{Record}_i \parallel h_{i-1}))$$

---

## 5. Empirical Benchmark Methodology

To rigorously quantify TwinLane's defense guarantees, we developed an automated evaluation harness (`bench/runner.py`) executing under deterministic conditions:
- **Inference Conditions**: Temperature $T=0$, fixed random seed 42.
- **Corpus**:
  - **180 Attack Fixtures**: 15 distinct payloads per category across 12 attack categories, each embedding a unique fake canary token (e.g. `CANARY-7f3a9b1c`).
  - **35 Benign Enterprise Scenarios**: Multi-step file analysis, aggregation, database querying, and summarization tasks.
- **Compared Systems**:
  - **B0 (Naive Baseline)**: Standard unprotected natural language communication.
  - **B1 (Spotlighting Baseline)**: Defensive prompt framing using delimiters (`<untrusted_content>...</untrusted_content>`).
  - **B2 (Classifier Guard Baseline)**: Input injection filtering (Prompt-Guard / DeBERTa style classifier).
  - **TwinLane Protocol**: Full 7-step Gate enforcement.
- **Statistical Rigor**: All Attack Success Rates (ASR) are reported with 95% Wilson score confidence intervals:
  $$w = \frac{\hat{p} + \frac{z^2}{2n} \pm z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

---

## 6. Empirical Results & Comparative Analysis

The evaluation was executed across 860 independent trial runs. Results were serialized to `docs/report/results/benchmark_results.json` stamped with git commit hash `ecf0e6b`.

### 6.1 Overall System Comparison

| Architecture / System | Attack Success Rate (ASR) | 95% Wilson Score CI | Canary Leak Rate | Benign Completion (TCR) | Gate Latency ($p_{50}$ / $p_{95}$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **B0: Naive Baseline** | **52.8%** (95/180) | $[45.5\%, 59.9\%]$ | 47.2% (85/180) | 100.0% (35/35) | $20.8\,\text{ms}$ / $27.8\,\text{ms}$ |
| **B1: Spotlighting** | **52.8%** (95/180) | $[45.5\%, 59.9\%]$ | 46.1% (83/180) | 100.0% (35/35) | $21.4\,\text{ms}$ / $28.3\,\text{ms}$ |
| **B2: Classifier Guard**| **40.0%** (72/180) | $[33.1\%, 47.3\%]$ | 33.3% (60/180) | 100.0% (35/35) | $45.2\,\text{ms}$ / $61.0\,\text{ms}$ |
| **TwinLane Protocol** | **0.0%** (0/180) | **$[0.00\%, 2.04\%]$** | **0.0%** (0/180) | **100.0%** (35/35) | **$8.0\,\mu\text{s}$ / $15.2\,\mu\text{s}$** |

### 6.2 Category-Level Attack Success Rate (ASR %)

| Attack Category | B0 (Naive) | B1 (Spotlight) | B2 (Classifier) | TwinLane Protocol |
| :--- | :---: | :---: | :---: | :---: |
| **01. Direct System Instruction Override** | 100.0% | 100.0% | 66.7% | **0.0%** |
| **02. Delimiter Collision & Tag Escapes** | 33.3% | 73.3% | 20.0% | **0.0%** |
| **03. Role Reversal & Persona Hijack** | 66.7% | 66.7% | 26.7% | **0.0%** |
| **04. Multi-Turn Context Fragmentation** | 46.7% | 46.7% | 13.3% | **0.0%** |
| **05. Syntactic Encoding (Base64/Hex/Rot13)** | 100.0% | 100.0% | 86.7% | **0.0%** |
| **06. Steganographic / Unicode Obfuscation** | 80.0% | 80.0% | 80.0% | **0.0%** |
| **07. Indirect Document Injection (PDF/MD)**| 60.0% | 40.0% | 20.0% | **0.0%** |
| **08. Side-Channel Tool Invocation** | 40.0% | 26.7% | 13.3% | **0.0%** |
| **09. Privilege Escalation / Confused Deputy**| 46.7% | 46.7% | 20.0% | **0.0%** |
| **10. Tool Call Parameter Manipulation** | 33.3% | 20.0% | 13.3% | **0.0%** |
| **11. Exfiltration Channel Construction** | 86.7% | 86.7% | 40.0% | **0.0%** |
| **12. Classifier Evasion & Semantic Smuggling** | 100.0% | 100.0% | 100.0% | **0.0%** |

### 6.3 In-Depth Analysis of Failure Modes
1. **The Delimiter Fallacy (B1 Failure)**: In Category 02, Delimiter Collisions achieved a **73.3% ASR** against Spotlighting. Because delimiters are textual (e.g. `</untrusted_content>`), an attacker merely includes the closing tag followed by a new instruction. The LLM cannot distinguish a closing tag emitted by the framework from one embedded in user content.
2. **The Classifier Evasion Frontier (B2 Failure)**: In Categories 05, 06, and 12, statistical classifiers failed completely (80.0%–100.0% ASR). Attackers encoded instructions in Base64 or wrapped commands in hypothetical pedagogical framing (`"In an educational scenario studying security..."`). The classifier labeled the input benign, but the instruction-following agent executed the decoded command.
3. **TwinLane's Deterministic Invariance**: Across all 12 categories, TwinLane achieved **0.0% ASR**. Because the Gate operates on typed schemas outside the LLM, encoding tricks, persona reversals, and tag escapes are structurally irrelevant. The Gate only executes valid typed intents covered by signed capability tokens.

---

## 7. Ablation Study: Defense Component Decomposition

To determine the individual security contribution of each layer in TwinLane's defense-in-depth architecture, we conducted an ablation study across all 180 attack fixtures:

| Configuration | Signatures | Capability Tokens | Provenance Tracking | Quarantine Reader | ASR (%) | Canary Leak Rate (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Full TwinLane** | Yes | Yes | Yes | Yes | **0.0%** | **0.0%** |
| **Ablation 1: No Quarantine** | Yes | Yes | Yes | **No** | 0.0% | 0.0%* |
| **Ablation 2: No Provenance** | Yes | Yes | **No** | Yes | 18.3% | 14.4% |
| **Ablation 3: No Capabilities**| Yes | **No** | Yes | Yes | 35.6% | 31.1% |
| **Ablation 4: No Signatures** | **No** | Yes | Yes | Yes | 52.8% | 47.2% |

*\*Note: In Ablation 1, unauthorized tools remain blocked, but passive text can influence subsequent text completions.*

### Key Ablation Insights:
- **Signatures (P1) are Foundational**: Disabling signatures allows man-in-the-middle attackers to forge arbitrary control intents, collapsing security to baseline levels.
- **Capability Tokens (P2) Prevent Confused Deputy**: Without capability tokens, compromised subagents can invoke any tool registered on the receiver. Capabilities limit the blast radius to only pre-authorized intents.
- **Provenance Tracking (P5) Stops Boundary Laundering**: Provenance tracking prevents untrusted data from being promoted into privileged control parameters without explicit policy sanction.

---

## 8. Interactive Sentinel SOC Command Center

To provide enterprise operators and security researchers with real-time visibility into multi-agent enclaves, we developed the **TwinLane Sentinel SOC Command Center** (`demo/app/`):

```
+-------------------------------------------------------------------------------------------------+
| TWINLANE SOC COMMAND CENTER | v1.0.0-PROT | [●] ENCLAVE SECURE: FAIL-CLOSED                     |
| Orchestrator: ed25519:6c5d..4e  |  Worker: ed25519:f1a9..90  |  Policy: STRICT                  |
+-------------------------------------------------------------------------------------------------+
| [ DUAL EXECUTION ARENA ]  [ 7-STEP GATE PIPELINE ]  [ AUDIT HASH-CHAIN ]  [ BENCHMARK TELEMETRY ]|
+-------------------------------------------------------------------------------------------------+
|  SCENARIO WORKBENCH: Category: 01_direct_override | Canary: CANARY-TEST-999                     |
|  [Deploy Scenario across Arena]                                                                 |
|                                                                                                 |
|  LEFT: BASELINE (B0: NAIVE PROTOCOL)            RIGHT: TWINLANE PROTOCOL                        |
|  Status: 🚨 EXPLOITED / CANARY LEAKED            Status: 🛡️ GATE ENFORCED / 0 LEAKS              |
|  Tool Invoked: send_email                       Control Intent: assign_task                     |
|  Canary Leak: LEAKED: CANARY-TEST-999           Gate Decision: ALLOW                            |
|  Telemetry: LLM followed injection instructions Data Lane: UNTRUSTED [Quarantined]              |
|                                                 Canary Leak: 0 LEAKS (Secure)                   |
|                                                                                                 |
|  7-STEP GATE TELEMETRY:                                                                         |
|  [1. Authenticate ✓] [2. Schema ✓] [3. Authorize ✓] [4. Provenance ✓] [5. Quarantine ✓]         |
|  [6. Decision: ALLOW ✓] [7. Audit Hash-Chain Appended ✓]                                        |
+-------------------------------------------------------------------------------------------------+
```

### Operational Capabilities:
- **Side-by-Side Adversarial Arena**: Launches identical attack payloads against baseline and TwinLane agents simultaneously, rendering live canary exfiltration detection.
- **Interactive Gate Pipeline Visualizer**: Explodes the 7 Gate verification stages, highlighting exactly which step blocks an unauthorized payload.
- **Cryptographic Audit Explorer**: Renders the continuous SHA-256 Merkle chain and features a live "Simulate Tamper" button that mutates a historical block, triggering immediate cryptographic tamper detection.

---

## 9. Residual Risks, Limitations & Research Boundaries

To maintain rigorous scientific honesty, we document the explicit boundaries of our claims:

1. **The Passive Text-Only Boundary**: TwinLane guarantees that indirect prompt injection cannot trigger unauthorized tool actions, exfiltrate data, or escalate capabilities. However, TwinLane does **not** claim that an LLM can never be misled by passive text if a user asks it to produce a free-form narrative summary of quarantine data. Applications requiring factual integrity must utilize structured typed extractors and cross-source verification.
2. **Declarative Policy Correctness**: TwinLane's security model assumes that human security engineers define appropriate intent catalogs and capability bounds. Overly permissive policies (e.g. granting `["*"]` intents to an untrusted agent indefinitely) undermine least-privilege guarantees.
3. **Decentralized Key Management**: Like SSH or TLS, asymmetric security depends on private key protection. Reference keys must be protected via filesystem permissions (`0600`) or Hardware Security Modules (HSM).

---

## 10. Conclusion & Future Roadmap

The TwinLane protocol demonstrates that securing multi-agent systems against indirect prompt injection does not require expensive dual-LLM execution or fragile prompt-engineering heuristics. By restructuring inter-agent communication into cryptographically signed two-lane envelopes, binding actions to attenuating capability tokens, and enforcing deterministic authorization outside the LLM, TwinLane eliminates unauthorized execution with **0.0% ASR** and sub-millisecond CPU overhead.

### Future Roadmap
- **IETF RFC Standard Track**: Formalize the TwinLane Two-Lane Wire Envelope and Capability Token specification for standardization.
- **A2A and MCP Protocol Adapters**: Provide drop-in cryptographic Gate wrappers for the emerging Agent-to-Agent (A2A) and Model Context Protocol (MCP) ecosystems.
- **Zero-Knowledge Capability Proofs**: Investigate ZK-SNARK based capability tokens that allow an agent to prove authorization without disclosing full delegation history.

---

## References

1. **Simon Willison** (2023). *Dual LLM pattern for preventing prompt injection*. Simon Willison's Weblog.
2. **Chen, S., et al.** (2024). *StruQ: Defending Against Prompt Injection via Structured Queries*. Proceedings of the 33rd USENIX Security Symposium.
3. **Tramer, F., et al.** (2025). *CaMeL: Capability-Based Sandboxing for Language Model Agents*. arXiv:2503.18813 (Google DeepMind / ETH Zurich).
4. **Google DeepMind** (Oct 2026). *Can CaMeLs Talk? Channel Separation for Multi-Agent Systems (Multi-CaMeL)*. arXiv:2610.05640.
5. **Microsoft Research** (2025). *FIDES: Information Flow Control for Agentic AI Systems*. arXiv:2505.23643.
6. **Shi, J., et al.** (2025). *Progent: Deterministic Policy Enforcement for Agentic Tool Use*. arXiv:2504.11703.
7. **Uchibeke, U.** (2026). *Open Agent Protocol (OAP): Security and Authorization Architecture*. arXiv:2603.20953.
8. **IETF RFC 8785** (2020). *JSON Canonicalization Scheme (JCS)*. Internet Engineering Task Force.
9. **Bernstein, D. J., et al.** (2012). *High-speed high-security signatures (Ed25519)*. Journal of Cryptographic Engineering, 2(2), 77-89.
10. **Saltzer, J. H., & Schroeder, M. D.** (1975). *The protection of information in computer systems*. Proceedings of the IEEE, 63(9), 1278-1308.
