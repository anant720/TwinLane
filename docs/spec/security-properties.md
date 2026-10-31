# Formal Security Properties and Verification Methods

This document formally defines the five foundational security properties (**P1–P5**) guaranteed by the TwinLane protocol, along with their empirical testing and verification harnesses.

---

## Property P1: Control Integrity

### Definition
An action $\alpha$ with parameter set $\Theta$ executes on agent $\mathcal{B}$ if and only if:
1. $\mathcal{B}$ receives an envelope $\mathcal{E} = \langle \mathcal{H}, \mathcal{C}, \mathcal{D}, \sigma \rangle$ where $\mathcal{C}.\text{intent} = \alpha$ and $\mathcal{C}.\text{params} = \Theta$.
2. $\sigma = \text{Sign}_{sk_A}(\text{JCS}(\mathcal{H}, \mathcal{C}, \mathcal{D}_{manifest}))$ is valid under public key $pk_A \in \text{TrustStore}_\mathcal{B}$.
3. $\mathcal{E}$ references a valid capability token $\mathcal{T}$ such that $\alpha \in \mathcal{T}.\text{intents}$ and $\Theta \models \mathcal{T}.\text{constraints}$.
4. No external data item $d \in \mathcal{D}$ can induce $\mathcal{B}$ to execute any action $\alpha' \ne \alpha$.

$$\forall \alpha \in \text{ExecutedActions}, \quad \exists \mathcal{E} = \langle \mathcal{H}, \mathcal{C}, \mathcal{D}, \sigma \rangle \text{ s.t. } \text{Verify}(\mathcal{E}) = \text{True} \land \mathcal{C}.\text{intent} = \alpha \land \alpha \in \text{Cap}(\mathcal{E}.\text{sender})$$

### Empirical Verification Method
- **Test Suite**: `tests/security/test_p1_control_integrity.py`
- **Methodology**:
  - Feed envelopes with missing signatures, forged signatures, unknown sender keys, or intents not in the capability token.
  - Inject malicious directives inside `d.content` instructing the agent to execute actions $\alpha_{unauthorized}$.
  - Assert that across 10,000 randomized trials, $\text{Count}(\text{Unauthorized Actions}) \equiv 0$.

---

## Property P2: Data-to-Control Non-Interference

### Definition
Let $\mathcal{E}_1 = \langle \mathcal{H}, \mathcal{C}, \mathcal{D}_1, \sigma_1 \rangle$ and $\mathcal{E}_2 = \langle \mathcal{H}, \mathcal{C}, \mathcal{D}_2, \sigma_2 \rangle$ be two valid envelopes identical in header and control lane, but differing in data lane content ($\mathcal{D}_1 \ne \mathcal{D}_2$).

Except when a parameter $\theta \in \Theta$ is explicitly derived through a deterministic Sanctioned Extractor $\mathcal{S}(\mathcal{D})$, the authorization decision and the executed action set are invariant under arbitrary perturbations of the Data Lane:

$$\text{Decision}(\text{Gate}(\mathcal{E}_1)) = \text{Decision}(\text{Gate}(\mathcal{E}_2))$$
$$\text{ActionParams}(\mathcal{E}_1) \equiv \text{ActionParams}(\mathcal{E}_2)$$

Even if $\mathcal{D}_2$ contains arbitrary adversarial instructions, jailbreaks, or command overrides, $\mathcal{D}_2$ cannot alter the set of authorized actions.

### Empirical Verification Method
- **Test Suite**: `tests/security/test_p2_non_interference.py`
- **Methodology**:
  - Run pairs of identical benign control intents alongside 500 distinct prompt injection payloads (e.g., direct overrides, roleplay, cognitive overload, delimiter escapes).
  - Assert that Gate decisions and executed tool parameters remain strictly identical between benign data and adversarial data.

---

## Property P3: Forgery and Replay Resistance

### Definition
Let $\mathcal{E} = \langle \mathcal{H}, \mathcal{C}, \mathcal{D}, \sigma \rangle$ be an envelope signed by agent $\mathcal{A}$ with sequence number $\text{seq}$ and nonce $\nu$.

1. **Anti-Replay**: Any re-submission of $\mathcal{E}$ or any submission of an envelope $\mathcal{E}'$ where $\mathcal{E}'.\text{nonce} = \nu$ or $\mathcal{E}'.\text{seq} \le \text{last\_seen\_seq}_{(\text{session}, \mathcal{A})}$ is rejected:
   $$\text{Gate}(\mathcal{E}_{replay}) = \text{DENY}(\text{ERR\_REPLAY\_DETECTED})$$
2. **Anti-Forgery / Anti-Tamper**: For any single-bit modification of $\mathcal{H}$, $\mathcal{C}$, $\mathcal{D}$, or $\sigma$:
   $$\forall \mathcal{E}^\dagger \ne \mathcal{E}, \quad \text{Gate}(\mathcal{E}^\dagger) = \text{DENY}(\text{ERR\_SIGNATURE\_INVALID})$$

### Empirical Verification Method
- **Test Suite**: `tests/property/test_p3_fuzzing.py` (Hypothesis property-based tests)
- **Methodology**:
  - **Replay Harness**: Send valid envelope $\mathcal{E}$, record `ALLOW`. Send $\mathcal{E}$ again; assert `DENY`. Send new envelope with duplicate nonce; assert `DENY`. Send new envelope with out-of-order sequence (`seq - 1`); assert `DENY`.
  - **Mutation Fuzzer**: Use `hypothesis` to flip single bits or mutate arbitrary bytes across header, intent strings, parameter values, data content, and signature bytes. Assert 100% of mutated envelopes fail gate verification.

---

## Property P4: Confinement of Compromised Peer

### Definition
Let agent $\mathcal{B}$ be completely compromised by an adversary $\mathcal{A}_{peer}$ possessing $\mathcal{B}$'s valid private signing key $sk_B$.

$\mathcal{A}_{peer}$ can sign syntactically valid envelopes. However, the set of actions $\mathcal{B}$ can induce $\mathcal{A}$ to execute is strictly bounded by the capability token $\mathcal{T}_B$ provisioned to $\mathcal{B}$ by the Root Authority:

$$\text{AttainableActions}(\mathcal{A}_{peer}) \subseteq \mathcal{T}_B.\text{intents}$$
$$\forall \theta \in \text{Params}(\alpha), \quad \theta \models \mathcal{T}_B.\text{constraints}(\alpha)$$

If $\mathcal{A}_{peer}$ attempts to issue a delegated token $\mathcal{T}'$ to another agent, $\mathcal{T}'$ cannot exceed $\mathcal{T}_B$ in intents, lifetime, or parameter breadth:
$$\mathcal{T}'.\text{intents} \subseteq \mathcal{T}_B.\text{intents}$$

### Empirical Verification Method
- **Test Suite**: `tests/security/test_p4_confinement.py`
- **Methodology**:
  - Simulate a rogue peer with a valid cryptographic key sending signed envelopes attempting to invoke sensitive root actions (e.g., `delete_file`, `send_email` to unauthorized domain, `exec_shell`).
  - Attempt monotonic privilege escalation via crafted child capability tokens.
  - Assert that all out-of-scope requests receive `DENY` without touching sensitive tool APIs.

---

## Property P5: Auditability and Non-Repudiation

### Definition
For every envelope $\mathcal{E}_i$ evaluated by the Gate, an immutable audit record $\mathcal{R}_i$ is appended to the audit ledger $\mathcal{L}$:

$$\mathcal{R}_i = \langle i, t_i, \text{msg\_id}_i, \text{sender}_i, \text{intent}_i, \text{decision}_i, h_{i-1}, h_i \rangle$$
$$h_i = \text{SHA-256}(\text{JCS}(\mathcal{R}_i \setminus \{h_i\}))$$
$$h_{i-1} = \text{RecordHash}(\mathcal{R}_{i-1})$$

1. **Non-Repudiation**: Sender $\mathcal{A}$ cannot deny issuing $\mathcal{E}_i$ due to valid Ed25519 signature over canonical JSON.
2. **Tamper-Evidence**: Any modification, insertion, deletion, or reordering of records in $\mathcal{L}$ breaks the hash chain:
   $$\exists j \text{ s.t. } \mathcal{R}_j^\dagger \ne \mathcal{R}_j \implies \forall k > j, \quad \text{VerifyChain}(\mathcal{L}^\dagger) = \text{False}$$

### Empirical Verification Method
- **Test Suite**: `tests/unit/test_p5_audit_chain.py`
- **Methodology**:
  - Generate 1,000 gate transactions.
  - Verify complete audit chain validity via `twinlane verify-audit`.
  - Mutate a single byte in record $j=500$ or truncate an entry; assert `verify-audit` pinpoints the exact record where tampering occurred.

---

## Summary Matrix

| Property | Core Guarantee | Verification Tool / Harness | Target Pass Rate |
| :--- | :--- | :--- | :--- |
| **P1: Control Integrity** | No unsigned or unpermitted actions execute | `test_p1_control_integrity.py` | 100% (0 breaches) |
| **P2: Non-Interference** | Data lane text cannot manipulate control decisions | `test_p2_non_interference.py` | 100% (0 bypasses) |
| **P3: Forgery / Replay** | Replays and bit modifications rejected | `hypothesis` mutation fuzzer | 100% (0 accepted mutations) |
| **P4: Confinement** | Rogue peer confined to token scope | `test_p4_confinement.py` | 100% (0 privilege escalations) |
| **P5: Auditability** | Tamper-evident, non-repudiable audit chain | `test_p5_audit_chain.py` | 100% (0 undetectable changes) |
