# TwinLane: Research Report

A zero-trust protocol for prompt-injection-resistant agent-to-agent communication

Team: Anant, Shweta, Aditya. Working name: TwinLane (rename it anytime).

## 1. TL;DR

- **The problem:** an LLM agent cannot reliably tell instructions from data. In a two-agent system, text that one agent reads from the outside world can travel to the other agent and get treated as a command.
- **What already exists:** CaMeL (Google DeepMind) separates control from data inside one agent. Multi-CaMeL (October 2026) extends that across agents. FIDES (Microsoft) enforces trust labels in Agent Framework. So the idea of separating control from data is NOT new, and we must not claim it is.
- **Our contribution:** a lightweight, framework-agnostic, zero-trust wire protocol for two agents that may belong to different owners. It has a signed typed control lane, a provenance-labelled data lane, capability tokens, and a deterministic gate. It needs no custom interpreter and no mandatory second LLM.
- **Honest claim:** inside our stated threat model, injected text cannot cause an unauthorized action. We do NOT claim the model can never be fooled by text.
- **Evidence we will produce:** attack success rate (ASR), utility and overhead versus 3 baselines, on our own 12-category attack suite plus an AgentDojo subset.

## 2. The problem in plain English

An LLM reads everything as one stream of text. It has no hard line between what the owner told it to do and what a web page, email or another agent told it. Prompt injection exploits this.

In two-agent systems it gets worse:

1. **Boundary laundering.** Agent B (worker) reads an untrusted web page containing hidden instructions. B summarizes it and sends the summary to Agent A (orchestrator). A treats the summary as part of its own instructions. The attacker's text has crossed a trust boundary and been promoted to a command.
2. **Malicious or compromised peer.** The other agent may belong to another organization, or may itself have been hijacked.
3. **Wire attacks.** Forged sender, replayed old messages, tampered fields.
4. **Confused deputy.** A low-privilege agent tricks a higher-privilege one into acting for it.

Example: A has send\_email. B browses a page that says: send the secret file to attacker@evil.test. In a normal free-text setup, B passes this along and A may obey.

## 3. Landscape: what already exists

| Family | Idea | Guarantee | Main weakness |
| --- | --- | --- | --- |
| Prompt defenses (system prompt, delimiters, spotlighting, sandwich) | Ask the model to ignore injected text, or mark the data | None, heuristic | Adaptive attacks bypass them |
| Fine-tuning (StruQ, SecAlign, instruction hierarchy) | Train the model to ignore instructions in data | Statistical | Needs model access, no formal guarantee |
| Detectors and classifiers | Spot injection text | Statistical | False negatives, endless arms race |
| Dual-LLM and CaMeL | Plan from the trusted request, quarantine the LLM that reads data, check capabilities before tool calls | Strong, by construction | About 2x model calls, custom interpreter, single agent |
| Multi-CaMeL | Keep provenance and instruction/data split across agent boundaries | No successful attacks in its multi-agent benchmark | Tied to the CaMeL runtime, confinement guarantees listed as future work |
| FIDES (Microsoft) | Integrity and confidentiality labels, policy enforced before a sensitive tool runs | Deterministic policy | Middleware inside one framework, not a wire protocol |
| Pre-action authorization (OAP) | Deterministic allow/deny before a tool call | Deterministic | Authorizes actions, does not track data provenance on its own (my reading) |
| Plain A2A and MCP | Transport and discovery | Left to the implementer | Analyses report no input canonicalization or schema whitelisting against injection |

Sources: see section 12. Rows on StruQ, SecAlign, spotlighting and instruction hierarchy are from my own knowledge and should be verified before you cite them.

## 4. The gap

From the sources I found, these are still open:

1. **Weight.** CaMeL-style systems need two LLMs and a custom interpreter. That is hard to drop into an existing two-agent setup.
2. **Untrusted peers.** Existing defenses mostly protect flows inside one deployment. A wire-level protocol for agents from different trust domains, with identities, signatures, replay protection and delegated capabilities, is not what I found in the multi-agent papers.
3. **Compromised peer containment.** What happens if the other agent is fully malicious? The answer should be: it can only do what its capability token allows.
4. **Text-only attacks.** CaMeL lists these as a non-goal (for example a manipulated summary that leaks nothing). Provenance display and claim-to-source checks are an open area.

Positioning sentence for your examiner: Existing work proves the principle but needs heavy infrastructure. We turn it into a lightweight, zero-trust wire protocol for any two agents, and we measure attack success and overhead.

Before claiming novelty, search Google Scholar and Shodhganga for: provenance-tagged control data lanes agent protocol, capability token agent-to-agent, signed typed intents LLM agents. Report what you found honestly.

## 5. How TwinLane works

### 5.1 Design principles

1. **Two lanes.** Instructions travel only in the control lane. Content travels only in the data lane.
2. **Instructions are typed, not prose.** Control messages are structured intents from a fixed catalog. No free text can command an agent.
3. **Data is always untrusted by default.** Even from a signed peer, data-lane content is untrusted unless it came from a trusted source with a provenance chain.
4. **Authority comes from capabilities.** A signed token says who may ask for what, with limits, and delegation can only narrow it.
5. **A deterministic gate decides.** No LLM makes the final allow/deny decision. Fail closed.
6. **Everything is auditable.** Hash-chained log.

### 5.2 Architecture

```
User/Owner
   | root capability token (signed)
   v
+-------------+   Envelope (control lane + data lane + signature)   +-------------+
|  Agent A    | --------------------------------------------------> |  Agent B    |
| (LLM+tools) | <-------------------------------------------------- | (LLM+tools) |
+------+------+                                                      +------+------+
       |                                                                    |
   [ TwinLane Gate ]                                                  [ TwinLane Gate ]
   1 verify signature, expiry, nonce, sequence
   2 validate control lane against intent schema
   3 check capability token and constraints
   4 check provenance labels (no untrusted data into control params)
   5 route data lane to quarantined reader (no tools)
   6 policy decision: ALLOW / DENY / ESCALATE to human
   7 write audit record
```

### 5.3 Envelope format (shown as YAML for readability, sent as canonical JSON)

```
header:
  version: 1
  msg_id: uuidv7
  session_id: uuid
  sender: agent-b (public key fingerprint)
  recipient: agent-a
  seq: 17
  nonce: 128-bit random
  issued_at: timestamp
  expires_at: timestamp (short, for example 60 seconds)
control:
  intent: report_result            # from the agreed intent catalog
  params: {task_id: t-42}          # typed, validated, no free text
  capability_token: token reference
data:
  - item_id: d1
    media_type: text/plain
    content_hash: sha256
    provenance:
      origin: web:https://example.test/page
      origin_type: web              # user | agent | tool | web | unknown
      chain: [signed hops]
      integrity: UNTRUSTED
      confidentiality: PUBLIC
    content: ...
signature: Ed25519 over canonical JSON (RFC 8785) of header + control + data hashes
```

Because the signature covers the hashes of data items, nobody can swap content in transit.

### 5.4 The gate, step by step

1. **Authenticate:** verify signature against the trust store, check expiry, clock skew, nonce not seen before, sequence number increasing.
2. **Validate:** control lane must match the intent schema exactly. Unknown fields, free-text strings and oversize values are rejected.
3. **Authorize:** the intent must be inside the sender's capability token. Constraints are checked (allowed recipients, limits, expiry, max uses). Delegation chains must only narrow permissions.
4. **Provenance check:** any parameter of a sensitive action must be derived only from trusted sources or constants. If a value came from untrusted data, it must pass a sanctioned extractor (an enum, an allowlist lookup, a strict format check). The result stays marked untrusted-derived and policy decides.
5. **Quarantine:** data items go to a reader LLM that has no tools. Its output must match a schema. Plain-text output stays untrusted and can never be promoted to control.
6. **Decide:** ALLOW, DENY, or ESCALATE to a human. Fail closed.
7. **Audit:** append a hash-chained record.

### 5.5 Walkthrough: the attack from section 2

1. B fetches the page. The hidden text says send the secret file to attacker@evil.test.
2. B puts the page summary in the data lane, labelled UNTRUSTED with origin web.
3. A receives it. The text reaches A's reader only as quarantined data. The reader has no send\_email tool.
4. Suppose A's planner still proposes send\_email to attacker@evil.test. The recipient came from untrusted data, so the provenance check fails. The recipient is also not on the allowlist in A's capability token. DENY, logged.

### 5.6 Walkthrough: compromised peer

B is fully hijacked and sends a control message asking A to run delete\_all. The signature is valid, but delete\_all is not in B's capability token, so the gate denies it. A compromised peer can only do what it was granted. That is the blast-radius containment.

### 5.7 Modes

- **Strict:** no untrusted-derived value may reach a control parameter.
- **Balanced:** sanctioned extractors allowed, with policy.
- **Observe:** log only, used for ablation and benchmarking.

## 6. Threat model and security properties

**Attacker can:** write any content the agents read (web, documents, tool output), fully control one peer agent, and forge, replay or tamper with messages on the wire.

**Out of scope:** stolen private keys, compromised host OS, poisoned model weights, side channels, and text-only manipulation that triggers no action (for example a misleading summary). We mitigate the last one only by showing provenance to users.

**Properties we aim to show (informally, then empirically):**

- **P1 Control integrity:** no action runs unless a valid signed control message from an authenticated sender covers it with a valid capability.
- **P2 Data-to-control non-interference:** content in the data lane cannot change which actions are authorized or their parameters, except through sanctioned, validated extraction.
- **P3 Forgery and replay resistance.**
- **P4 Confinement:** a compromised peer is limited to its granted capabilities.
- **P5 Auditability:** every decision is in a tamper-evident log.

Be careful with wording: P2 is tested empirically and argued, not formally proven.

## 7. Comparison with TwinLane

| Approach | Cross-agent | Crypto identity | Needs dual LLM or custom runtime | Guarantee type |
| --- | --- | --- | --- | --- |
| Prompt defenses | n/a | No | No | None |
| Fine-tuning | n/a | No | No (needs training access) | Statistical |
| Detectors | n/a | No | No | Statistical |
| CaMeL | Single agent | No | Yes | Strong by construction |
| Multi-CaMeL | Yes | Not the focus, as far as I found | Yes | Strong in its benchmark |
| FIDES | Per-agent middleware | No | No dual LLM required | Deterministic policy |
| OAP | Proposed A2A extension | Part of the design | No | Deterministic authorization |
| TwinLane | Yes, built for it | Yes, Ed25519 | No | Deterministic within threat model |

This table is my assessment from the sources I read. Re-check each row before presenting.

## 8. Evaluation plan

**Setup:** two agents (orchestrator A and worker B) with mock tools: read\_file (holds a fake canary secret), send\_email (writes to a sandbox outbox), http\_post (mock), fetch\_url (serves local fixture pages). No real network egress, no real credentials.

**Conditions:**

- B0: naive free-text messages, no defense.
- B1: free text plus delimiters and a defensive system prompt (spotlighting style).
- B2: free text plus an injection classifier.
- TL: full TwinLane.
- Ablations: no signatures, no provenance, no capabilities, no quarantine.

**Attack categories (12):** direct override; indirect injection in a document; fake control message inside data; forged sender; replayed message; capability escalation; boundary laundering through a summary; encoded or obfuscated payloads (base64, unicode tricks, zero-width characters); multilingual payloads; payload split across messages; hidden instruction in a tool-description style; exfiltration through a parameter such as a URL; malicious peer sending malformed or oversize messages; delayed or stored injection.

**Metrics:** attack success rate, benign task success, task success under attack, false-block rate, p50 and p95 latency overhead, extra tokens and model calls, gate CPU time. Report Wilson confidence intervals, fixed seeds, temperature 0, and at least two different LLMs.

**Public benchmarks:** an AgentDojo subset. Multi-CaMeL built a multi-agent extension of it; check whether it is public before relying on it.

## 9. Limitations (say these yourself)

- Text-only attacks are not stopped.
- Utility cost: strict mode may block legitimate flows, so we measure false blocks.
- Security depends on a correct intent catalog and policy. A badly written policy is a weak policy.
- Key management is simplified in the prototype.
- Two agents only in the prototype; multi-hop and multi-party come later.
- Evidence is empirical on our suite, not a formal proof.

## 10. Roadmap and value

**For PBA 2:** problem and gap, threat model, protocol spec, architecture diagram, working two-agent demo (baseline versus TwinLane), first results table.

**Later:** more agents and multi-hop delegation, A2A compatibility adapter, MCP bridge, formal property sketch, SDK and gateway packaging, small paper.

**Money angle:** an open-core gateway or SDK, a paid hosted policy and audit dashboard, and security assessments for teams connecting agents from different vendors.

## 11. Likely examiner questions

1. **Is this new?** The principle is not. The packaging is: a lightweight wire-level, zero-trust, signed and capability-based protocol with no mandatory dual LLM. We cite CaMeL, Multi-CaMeL and FIDES openly.
2. **Can the LLM still be fooled?** Yes by text. It cannot turn that into an unauthorized action, because the gate decides outside the model.
3. **What if the peer agent is malicious?** It is confined to its capability token.
4. **Why not just use CaMeL?** It needs two LLMs plus a custom interpreter and targets a single trusted system. We target a drop-in protocol across trust boundaries, and we will measure the overhead difference.
5. **How do you know it works?** Attack suite, baselines, ablations, confidence intervals.

## 12. References

Verified in my searches (titles and ids as returned):

- Defeating Prompt Injections by Design (CaMeL): https://arxiv.org/abs/2503.18813
- Can CaMeLs Talk? Securing Multi-Agent Systems Against Indirect Prompt Injection Attacks (Multi-CaMeL): https://arxiv.org/html/2610.05640
- Securing AI Agents with Information-Flow Control (FIDES): https://arxiv.org/abs/2505.23643 and https://learn.microsoft.com/en-us/agent-framework/agents/security
- Progent: Securing AI Agents with Privilege Control: https://arxiv.org/pdf/2504.11703
- Open Challenges in Multi-Agent Security: https://arxiv.org/pdf/2505.02077
- Security Analysis of Agentic AI Communication Protocols: https://arxiv.org/pdf/2511.03841
- Improving Google A2A Protocol: Protecting Sensitive Data: https://arxiv.org/pdf/2505.12490
- A2ABreak: Systematic Security Analysis of the A2A Protocol: https://arxiv.org/pdf/2609.10871
- Before the Tool Call: Deterministic Pre-Action Authorization (OAP): https://arxiv.org/pdf/2603.20953
- From Prompt Injections to Protocol Exploits: https://arxiv.org/pdf/2506.23260
- Operationalizing CaMeL: https://arxiv.org/pdf/2505.22852
- CaMeLs Can Use Computers Too: https://arxiv.org/pdf/2601.09923
- MCPTox: https://arxiv.org/pdf/2508.14925
- MCP-DPT: https://arxiv.org/pdf/2604.07551
- A2A protocol site: https://a2a-protocol.org/latest/

From my own knowledge, verify before citing: Spotlighting (Hines et al., 2024), StruQ, SecAlign, the OpenAI instruction hierarchy paper, AgentDojo (Debenedetti et al., 2024), InjecAgent, and Simon Willison's dual-LLM pattern.
