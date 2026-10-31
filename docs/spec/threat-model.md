# Threat Model & Vulnerability Analysis for TwinLane

**Protocol Version**: 1.0.0  
**Target Systems**: Multi-Agent Systems (MAS), Inter-Agent Communication (A2A), Tool-Executing Autonomous Agents  
**Methodology**: STRIDE + Attack Trees + Cryptographic Invariants

---

## 1. System Overview & Trust Boundaries

TwinLane secures communication between two autonomous LLM agents—**Agent A (Orchestrator)** and **Agent B (Worker)**—operating across distinct administrative domains, organizational perimeters, or privilege levels.

```
+----------------------------------------------------------------------------------------------------+
|                                    TRUST BOUNDARY (NETWORK / WIRE)                                 |
+----------------------------------------------------------------------------------------------------+
              |                                                                   ^
              | Wire Envelope: {Header, Control Lane, Data Lane, Ed25519 Sig}      |
              v                                                                   |
+----------------------------+                                      +----------------------------+
| Agent A Domain             |                                      | Agent B Domain             |
|                            |                                      |                            |
| +------------------------+ |                                      | +------------------------+ |
| | Orchestrator LLM       | |                                      | | Worker LLM             | |
| +-----------+------------+ |                                      | +-----------+------------+ |
|             |              |                                      |             |              |
|             v              |                                      |             v              |
|    [ TwinLane Gate ]       |                                      |    [ TwinLane Gate ]       |
|    - Authenticate          |                                      |    - Authenticate          |
|    - Validate Intent       |                                      |    - Validate Intent       |
|    - Authorize Capability  |                                      |    - Authorize Capability  |
|    - Check Provenance      |                                      |    - Check Provenance      |
|    - Quarantine Reader     |                                      |    - Quarantine Reader     |
|    - Decide (ALLOW/DENY)   |                                      |    - Decide (ALLOW/DENY)   |
|    - Hash-Chained Audit    |                                      |    - Hash-Chained Audit    |
|             |              |                                      |             |              |
|             v              |                                      |             v              |
|    +------------------+    |                                      |    +------------------+    |
|    | Sensitive Tools  |    |                                      |    | Local Tools      |    |
|    | (send_email,     |    |                                      |    | (fetch_url,      |    |
|    |  read_file, etc) |    |                                      |    |  parse_doc, etc) |    |
|    +------------------+    |                                      |    +------------------+    |
+----------------------------+                                      +----------------------------+
```

### Trust Zones
1. **Zone 1: Local Trusted Execution**: The local agent runtime, host OS, private keys, local memory, and Gate logic.
2. **Zone 2: Peer Agent Domain**: May be operated by a third party, partner, or sub-contractor. Considered **untrusted by default** until authenticated, and strictly confined to granted capabilities even when authenticated.
3. **Zone 3: Untrusted External Environment**: The open Internet, external document repositories, web scrapers, email bodies, third-party tool responses, and network transit.

---

## 2. Attacker Profile & Capabilities

The adversary $\mathcal{A}$ may operate from multiple positions in the system:

### 2.1 In-Scope Attacker Capabilities
1. **Adversarial Content Injection (Indirect Prompt Injection)**:
   - $\mathcal{A}$ can write arbitrary text, code, or formatting into resources that agents consume (web pages, PDFs, emails, databases, API outputs).
   - $\mathcal{A}$ can utilize arbitrary evasion techniques: delimiter escaping, payload splitting, base64 encoding, Unicode homoglyphs, zero-width characters, multilingual translations, or instructions disguised as tool definitions/schemas.
2. **Boundary Laundering**:
   - $\mathcal{A}$ can inject payloads into data read by Agent B such that Agent B summarizes, reformulates, or paraphrases the payload and passes it to Agent A in an attempt to launder untrusted text into a trusted command.
3. **Full Peer Agent Compromise (Malicious Peer)**:
   - $\mathcal{A}$ can have complete control over Agent B's LLM, prompts, and memory (either because Agent B is malicious or because Agent B was hijacked by an earlier direct injection).
   - $\mathcal{A}$ possesses Agent B's valid cryptographic keys and can sign well-formed TwinLane envelopes.
4. **Network Adversary (Man-in-the-Middle / Wire Attacks)**:
   - $\mathcal{A}$ can intercept, drop, delay, replay, duplicate, or tamper with wire messages exchanged between agents.
   - $\mathcal{A}$ can forge arbitrary header, control, and data fields in network packets.
5. **Confused Deputy Exploitation**:
   - $\mathcal{A}$ uses a low-privilege agent to invoke high-privilege operations on a peer agent without possessing the required capability token.

---

## 3. Out-of-Scope Non-Goals (Explicit Exclusions)

To maintain rigorous, falsifiable security boundaries, the following threats are explicitly outside the scope of TwinLane:

1. **Host OS and Key Compromise**:
   - If $\mathcal{A}$ compromises the underlying operating system kernel, gains read access to the local key store, or steals the private Ed25519 signing key of Agent A, the security of Agent A's gate is completely broken.
2. **Pre-Deployment Model Poisoning & Backdoors**:
   - We assume base LLM weights and provider APIs are not backdoored during pre-training or fine-tuning to deliberately ignore gate directives.
3. **Hardware & Side-Channel Attacks**:
   - Microarchitectural timing attacks, power analysis, and memory bus probing are out of scope.
4. **Pure Text-Only Semantic Manipulation (Without Action)**:
   - If $\mathcal{A}$ convinces an LLM to generate a factually incorrect summary or hallucinated text, and that text **triggers no tool execution or state modification**, TwinLane does not prevent the generation. This is mitigated through transparent provenance tagging and user display, not by Gate rejection.

---

## 4. STRIDE Threat Analysis

| Threat (STRIDE) | Attack Vector | Target Component | Protocol Mitigation in TwinLane |
| :--- | :--- | :--- | :--- |
| **S**poofing | Attacker sends messages claiming to be Agent B | Header (`sender`), Signature | Asymmetric Ed25519 signature over canonical JSON; verified against Trust Store public key. |
| **T**ampering | Attacker modifies control parameters or replaces data items in flight | Wire Envelope (`control`, `data`) | RFC 8785 canonical hash binding. Signature covers `{header, control, data_manifest}`. Manifest binds SHA-256 hashes of all data items. |
| **R**epudiation | Sender denies issuing an unauthorized instruction or receiver denies denying it | Audit Trail, Message History | Non-repudiable Ed25519 signatures; append-only SHA-256 hash-chained audit log with verifiable checkpoints. |
| **I**nformation Disclosure | Attacker attempts to leak secrets via unauthorized tool parameters | Data Lane, Gate Parameters | Provenance tracking (`confidentiality` labels `SECRET`); gate denies routing secret data to public channels without explicit declassification policy. |
| **D**enial of Service | Oversize messages, deep JSON nesting, nonce flooding, clock skew skewing | Gate Parser, Nonce Cache | Strict envelope size limits (default max 1 MB), depth limits (max 10), bounded TTLs (60s), clock skew limits (30s), in-memory TTL-bounded nonce cache. |
| **E**levation of Privilege | Compromised peer requests actions outside its granted scope, or injection alters parameters | Control Lane, Policy Engine | Capability tokens with attenuating delegation; strict Intent Catalog; parameter constraints; untrusted data cannot alter control lane parameters. |

---

## 5. Attack Trees

### Attack Tree 1: Indirect Injection Leading to Unauthorized Action Execution

```
[Goal: Execute Unauthorized Sensitive Action on Orchestrator (e.g., send_email with secret)]
├── 1. Exploit Wire Transport
│   ├── 1.1 Forge signature -> Blocked by Ed25519 signature verification (Step 1)
│   ├── 1.2 Replay old approved envelope -> Blocked by Nonce Cache & Seq counter (Step 1)
│   └── 1.3 Modify recipient in flight -> Blocked by RFC 8785 Canonical Digest mismatch (Step 1)
├── 2. Smuggle Command in Control Lane
│   ├── 2.1 Pass arbitrary free-text command -> Blocked by Intent Catalog schema validation (Step 2)
│   └── 2.2 Inject unknown parameters -> Blocked by strict schema (reject unknown fields) (Step 2)
├── 3. Bypass Capability Authorization
│   ├── 3.1 Request intent outside token -> Blocked by Token Intent Check (Step 3)
│   ├── 3.2 Escalate parameter scope (e.g. out-of-allowlist recipient) -> Blocked by Token Constraint Check (Step 3)
│   └── 3.3 Forge delegation chain -> Blocked by Parent Token Signature & Attenuation validation (Step 3)
└── 4. Boundary Laundering via Data Lane
    ├── 4.1 Injected text in document read by Worker
    │   └── 4.2 Worker summarizer preserves attacker command
    │       └── 4.3 Data item tagged UNTRUSTED
    │           ├── 4.4 Data passed directly to tool parameter -> Blocked by Provenance Check (Step 4)
    │           ├── 4.5 Data parsed by Quarantine Reader -> Output stays UNTRUSTED; cannot promote to Control
    │           └── 4.6 Sanctioned Extractor used -> Parameter marked EXTRACTED_UNTRUSTED; Policy denies sensitive action
```

### Attack Tree 2: Compromised Peer Confused Deputy Escalation

```
[Goal: Hijacked Worker B forces Orchestrator A to delete files]
├── 1. Worker B sends signed envelope requesting delete_file intent
│   ├── 1.1 Envelope is cryptographically valid and fresh
│   ├── 1.2 Gate checks Worker B's Capability Token
│   └── 1.3 Result: delete_file NOT in Worker B's allowed intents
│       └── Decision: DENY (logged to tamper-evident audit chain)
└── 2. Worker B attempts to delegate higher capability to itself
    ├── 2.1 Worker B crafts sub-token with delete_file
    └── 2.2 Gate evaluates parent delegation chain
        └── Result: Child scope exceeds parent scope (violation of monotonic attenuation)
            └── Decision: DENY (Immediate termination of session)
```

---

## 6. Security Invariants (Guaranteed Properties)

The TwinLane Gate enforces three non-negotiable operational invariants:

1. **Invariant 1 (Fail-Closed Execution)**:  
   Any syntactic parse failure, cryptographic signature mismatch, expired timestamp, sequence regression, unknown schema field, or unhandled internal exception **MUST immediately result in a `DENY` decision**.

2. **Invariant 2 (Strict Channel Separation)**:  
   No string originating from the Data Lane or derived from an `UNTRUSTED` source may be bound to an authorization-critical control parameter without passing through a registered, deterministic **Sanctioned Extractor**.

3. **Invariant 3 (Monotonic Capability Attenuation)**:  
   Let $\mathcal{C}_{parent}$ and $\mathcal{C}_{child}$ be capability tokens where $\mathcal{C}_{child}$ is delegated from $\mathcal{C}_{parent}$. Then:
   $$\text{Intents}(\mathcal{C}_{child}) \subseteq \text{Intents}(\mathcal{C}_{parent})$$
   $$\forall p \in \text{Params}, \quad \text{Constraint}(\mathcal{C}_{child}, p) \subseteq \text{Constraint}(\mathcal{C}_{parent}, p)$$
   $$\text{TTL}(\mathcal{C}_{child}) \le \text{TTL}(\mathcal{C}_{parent})$$
   No delegation can ever expand privilege.
