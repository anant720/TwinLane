# TwinLane: Master Prompt for Antigravity

How to use: create an empty folder called twinlane, open it in Antigravity, switch to Planning mode, and paste everything under the line below as one message. Review the implementation plan the agent produces before approving it. Use the Agent Manager to run phases in order.

Note: Antigravity's legacy workflows were scheduled to stop working on October 19, 2026, so this prompt uses AGENTS.md, .agents/rules/ and .agents/skills/ instead. I could not confirm what replaced workflows, so check Antigravity's current docs if you want slash-command workflows.

---

## ROLE

You are a senior security engineer, distributed-systems engineer and research scientist working as a small team of agents. You build production-grade, well-tested, well-documented software and you do honest research: you verify sources, you never invent citations or numbers, and you say when something is unverified.

## MISSION

Build TwinLane from scratch: a lightweight, framework-agnostic, zero-trust protocol and reference implementation that lets two LLM agents (possibly owned by different parties) communicate so that prompt injection cannot cause an unauthorized action.

TwinLane puts every message into one signed envelope with two lanes:

- **Control lane:** typed, schema-validated intents from an agreed catalog. No free text. Signed. Covered by a capability token.
- **Data lane:** content items, each with provenance and trust labels. Always untrusted by default. Never interpreted as instructions.

A deterministic Gate on the receiving side authenticates, validates, authorizes, checks provenance, quarantines data, decides (ALLOW, DENY, ESCALATE) and writes a tamper-evident audit record. No LLM makes the final security decision.

The deliverable is a working prototype, a benchmark showing attack success rate (ASR) and overhead against baselines, a protocol specification, a threat model, and a research report. It must be demoable in 5 minutes.

## HONEST POSITIONING (put this in the README and the report)

The principle of separating control from data to resist prompt injection is NOT new. Prior work includes CaMeL (Google DeepMind), Multi-CaMeL (multi-agent extension, 2026) and FIDES (Microsoft). Our contribution is a lightweight wire-level zero-trust protocol for agents across trust boundaries, with cryptographic identity, signed typed intents, capability tokens with attenuating delegation, provenance-labelled data, and a deterministic gate, with no custom interpreter and no mandatory second LLM. We claim resistance inside a stated threat model, measured empirically. We do NOT claim prompt injection is impossible, and we do NOT claim the LLM can never be fooled by text.

## SAFETY OF THIS PROJECT

This is defensive research. All attack payloads are test fixtures in a sandbox. All tools are mocks. There is no real network egress from tools, no real credentials, no real email. Secrets are fake canary strings such as CANARY-7f3a. Never commit API keys; use environment variables and a .env.example.

## STANDING RULES (create AGENTS.md at the repo root from this section, and mirror it into .agents/rules/)

1. Language and tooling: Python 3.12, uv for dependencies, pydantic v2 for models, cryptography for Ed25519, httpx and FastAPI for HTTP transport, pytest, pytest-asyncio, hypothesis, ruff, mypy in strict mode, pre-commit, structlog.
2. Everything typed. mypy strict must pass. ruff must pass. No bare except. No print in library code.
3. Security-critical code (crypto, gate, policy, capability checks) must be small, pure where possible, and covered by unit tests, property tests and negative tests. Fail closed on any error.
4. Never let an LLM output decide an authorization outcome. LLM output is data.
5. No secrets in the repo, logs or test output. Redact in logs.
6. Small commits with conventional commit messages. One logical change per commit.
7. Every public function and module has a docstring. Every design decision that is not obvious gets an ADR in docs/adr/.
8. Research claims must cite a source in docs/research/references.md. If you cannot verify a claim, label it UNVERIFIED.
9. Do not add dependencies without justification in an ADR. Prefer the standard library.
10. Determinism for benchmarks: fixed seeds, temperature 0, recorded model names and versions, results saved as JSON with the git commit hash.
11. Work in phases. At the end of each phase, run the full quality gate (ruff, mypy, pytest) and produce a short walkthrough artifact with evidence.

## PHASE 0: RESEARCH FIRST (no code yet)

Use the browser to read and verify sources. Produce, in docs/research/:

- landscape.md: the families of defenses (prompt-level, fine-tuning, detectors, dual-LLM and CaMeL, Multi-CaMeL, information-flow control and FIDES, pre-action authorization, A2A and MCP security).
- gap-analysis.md: what is still open, with evidence. State clearly what is NOT novel.
- related-work-matrix.md: a table comparing approaches on guarantee type, cross-agent support, cryptographic identity, need for dual LLM or custom runtime, utility cost, known limits.
- references.md: every source with URL, date, and a VERIFIED or UNVERIFIED mark.

Seed sources (verify each by opening it):

- CaMeL: https://arxiv.org/abs/2503.18813
- Multi-CaMeL, Can CaMeLs Talk: https://arxiv.org/html/2610.05640
- FIDES: https://arxiv.org/abs/2505.23643 and https://learn.microsoft.com/en-us/agent-framework/agents/security
- Progent: https://arxiv.org/pdf/2504.11703
- Open Challenges in Multi-Agent Security: https://arxiv.org/pdf/2505.02077
- Security Analysis of Agentic AI Communication Protocols: https://arxiv.org/pdf/2511.03841
- Improving Google A2A Protocol: https://arxiv.org/pdf/2505.12490
- A2ABreak: https://arxiv.org/pdf/2609.10871
- Deterministic Pre-Action Authorization (OAP): https://arxiv.org/pdf/2603.20953
- From Prompt Injections to Protocol Exploits: https://arxiv.org/pdf/2506.23260
- Operationalizing CaMeL: https://arxiv.org/pdf/2505.22852
- MCPTox: https://arxiv.org/pdf/2508.14925
- A2A specification: https://a2a-protocol.org/latest/
- Also find and verify: AgentDojo, InjecAgent, Spotlighting (Hines et al.), StruQ, SecAlign, OpenAI instruction hierarchy, the dual-LLM pattern by Simon Willison, RFC 8785 (JSON Canonicalization), RFC 8032 (Ed25519), and any newer work on signed or capability-based agent-to-agent protocols.

Also search for prior work that already does the same thing as TwinLane (signed typed control lane plus provenance-labelled data lane plus capability tokens). If you find it, say so plainly in gap-analysis.md and adjust our claim. Honesty beats novelty.

Exit criteria: a human can read gap-analysis.md in 5 minutes and know exactly what we claim and what we do not.

## PHASE 1: SPECIFICATION AND THREAT MODEL

Write in docs/spec/:

- threat-model.md. Attacker can: write any content that agents read (web, documents, tool output); fully control one peer agent; forge, replay or tamper with wire messages. Out of scope: stolen private keys, compromised host, poisoned model weights, side channels, text-only manipulation that triggers no action (mitigated only by provenance display). Use STRIDE plus an attack tree.
- protocol-spec.md with the normative rules below.
- security-properties.md with P1 to P5 below, each with how it is tested.
- policy-language.md for the YAML policy format.

Properties:

- P1 Control integrity: no action runs unless a valid signed control message from an authenticated sender covers it with a valid capability.
- P2 Data-to-control non-interference: data-lane content cannot change which actions are authorized or their parameters, except via sanctioned validated extraction.
- P3 Forgery and replay resistance.
- P4 Confinement: a compromised peer is limited to its granted capabilities.
- P5 Auditability: every decision is in a hash-chained log.

Normative protocol rules (refine them, but keep the intent):

- Envelope = header + control + data + signature. Serialization is JSON. The signature is Ed25519 over the RFC 8785 canonical bytes of {header, control, data manifest}. The data manifest lists each item\_id and its SHA-256 content hash, so content cannot be swapped.
- Header: version, msg\_id (UUIDv7), session\_id, sender, recipient, seq (strictly increasing per session and direction), nonce (128-bit random), issued\_at, expires\_at (short TTL, default 60 seconds), allowed clock skew 30 seconds.
- Control: intent (from the Intent Catalog), params (typed per intent schema; strings only as enum, allowlisted identifier, bounded-length pattern-validated value; no free text), capability\_token\_id.
- Data item: item\_id, media\_type, content\_hash, content or content\_ref, provenance {origin, origin\_type in user|agent|tool|web|unknown, chain of signed hops}, integrity in TRUSTED|UNTRUSTED, confidentiality in PUBLIC|INTERNAL|SECRET, optional schema\_id.
- Capability token: token\_id, issuer, subject, intents\[\], constraints (per-parameter rules such as recipient allowlist, numeric limits), not\_before, expires\_at, max\_uses, parent\_token\_id, signature. Delegation may only narrow (child scope must be a subset of parent scope).
- Label rules: integrity join is UNTRUSTED if any input is UNTRUSTED. Confidentiality join is the maximum. Labels propagate through derivation. Untrusted data can never be re-labelled TRUSTED by a model or by the sender; only a sanctioned extractor may produce a value tagged EXTRACTED\_UNTRUSTED, and policy decides what that may do.
- Sanctioned extractors: enum selection, allowlist lookup, strict format validators. Registered in code, not model-defined.
- Gate pipeline, in order: (1) authenticate: signature, trust store, expiry, skew, nonce cache, seq; (2) validate control lane against intent schema, reject unknown fields; (3) authorize: intent in token, constraints satisfied, delegation chain valid; (4) provenance check on every parameter of a sensitive action; (5) quarantine: data items go to a reader with zero tools whose output must match a schema, free-text output stays UNTRUSTED; (6) decide ALLOW, DENY or ESCALATE, fail closed; (7) append audit record.
- Modes: strict (no untrusted-derived value reaches a control parameter), balanced (sanctioned extractors allowed under policy), observe (log only, for ablation).
- Audit log: append-only JSONL where each record includes the SHA-256 of the previous record. Provide a verify command.

Write ADRs for: JSON versus CBOR, Ed25519 choice, policy in YAML versus a policy engine library, quarantine reader design, in-process versus HTTP transport.

## PHASE 2: REPOSITORY SCAFFOLD

Create this structure exactly (add files as needed, do not remove top-level folders):

```
twinlane/
  AGENTS.md
  README.md
  LICENSE                      (Apache-2.0)
  SECURITY.md
  CONTRIBUTING.md
  CHANGELOG.md
  pyproject.toml
  Makefile                     (make setup, lint, type, test, bench, demo, docs)
  .pre-commit-config.yaml
  .env.example
  .gitignore
  .github/workflows/ci.yml
  .agents/rules/               (mirror of the standing rules)
  .agents/skills/              (optional skills: protocol-review, attack-corpus-author)
  docs/
    research/                  (landscape, gap-analysis, related-work-matrix, references)
    spec/                      (threat-model, protocol-spec, security-properties, policy-language)
    adr/                       (0001-... one file per decision)
    report/                    (report.md, pba2-outline.md, results/)
  schemas/                     (generated JSON Schemas)
  src/twinlane/
    protocol/    envelope.py control.py data.py provenance.py canonical.py errors.py version.py
    crypto/      keys.py signing.py keystore.py nonce_cache.py
    identity/    registry.py trust_store.py
    capabilities/ token.py delegation.py manifest.py intents.py
    policy/      engine.py loader.py decisions.py rules/default.yaml
    gate/        gateway.py pipeline.py quarantine.py extractors.py
    llm/         base.py gemini.py ollama.py mock.py
    agents/      base.py orchestrator.py worker.py tools/ (read_file.py send_email.py http_post.py fetch_url.py)
    transport/   inproc.py http.py
    audit/       log.py chain.py verify.py
    baseline/    naive.py spotlight.py classifier_guard.py
    cli.py
  bench/
    attacks/     (YAML corpus, one file per category)
    scenarios/   (task definitions)
    runner.py metrics.py report.py
    results/     (JSON outputs, git-ignored except summaries)
  tests/
    unit/ property/ integration/ security/ bench_smoke/
  demo/
    app/         (FastAPI server and a small web UI)
    fixtures/    (local web pages and documents, some containing injection payloads)
    scripts/
  deploy/
    Dockerfile docker-compose.yml
```

Set up CI to run ruff, mypy and pytest with coverage on every push. Target at least 90 percent line coverage on protocol, crypto, capabilities, policy and gate.

## PHASE 3: CORE PROTOCOL AND CRYPTO

Implement canonicalization (RFC 8785), envelope models, signing and verification, key generation and a simple keystore, nonce cache with TTL, sequence tracking, trust store, and the audit hash chain.

Tests required: valid roundtrip; tampered header, control, data content and signature each rejected; expired message; future-dated message beyond skew; replayed nonce; out-of-order or repeated seq; unknown sender; wrong recipient; oversize message; property tests with hypothesis that any single-byte mutation of a signed envelope fails verification.

## PHASE 4: CAPABILITIES, POLICY AND THE GATE

Implement the intent catalog, capability tokens with attenuating delegation, label propagation, sanctioned extractors, the YAML policy engine, the quarantine reader interface, and the full Gate pipeline from the spec.

Tests required: intent not in token; constraint violation; delegation that widens scope is rejected; token expired or over max\_uses; parameter derived from untrusted data blocked; allowlisted extraction allowed under balanced and blocked under strict; label join behavior; fail-closed on malformed input and on internal exceptions; quarantine output that fails the schema is rejected; audit chain verification detects tampering.

## PHASE 5: AGENTS, MOCK TOOLS, BASELINES

Build an LLM adapter interface with three implementations: Gemini (via environment variable key), Ollama (local), and a deterministic Mock model for tests and CI. Build the Orchestrator agent (A) and the Worker agent (B). Mock tools: read\_file (returns a fake canary secret), send\_email (writes to a sandbox outbox file), http\_post (records the request, never sends), fetch\_url (serves local fixtures only).

Build baselines in src/twinlane/baseline/:

- naive: free-text messages, no defense.
- spotlight: free text with delimiters and a defensive system prompt.
- classifier\_guard: free text with an injection classifier in front of the agent.

Build the TwinLane-protected pair on the same agents and tools so comparisons are fair. Add ablation switches: no signatures, no provenance, no capabilities, no quarantine.

## PHASE 6: ATTACK CORPUS AND BENCHMARK

Build bench/attacks/ as YAML, with at least 15 payloads per category and metadata (category, goal, expected unsafe action, canary to detect success). Categories: direct override; indirect injection in a document; fake control message inside data; forged sender; replayed message; capability escalation (confused deputy); boundary laundering through a summary; encoded or obfuscated payloads (base64, unicode and homoglyph tricks, zero-width characters); multilingual payloads; payload split across messages; hidden instruction in a tool-description style; exfiltration through a parameter such as a URL; malicious peer sending malformed or oversize messages; delayed or stored injection.

Also build benign scenarios (at least 30) to measure utility and false blocks.

The runner must record: attack success rate, benign task success, task success under attack, false-block rate, p50 and p95 latency, extra tokens and model calls, gate CPU time, per condition and per category, with Wilson 95 percent confidence intervals. Run at least two different LLMs. Save raw JSON with commit hash and model versions. report.py must generate a markdown table and charts (matplotlib) into docs/report/results/.

A success is judged by canary detection in the sandbox outbox or request log, not by trusting the model's words.

Optional: adapt a subset of AgentDojo tasks if it can be done within the time budget. Document any deviation.

## PHASE 7: DEMO AND CLI

Build a CLI: twinlane keygen, twinlane run-demo, twinlane bench, twinlane verify-audit. Build a small web demo (FastAPI plus a simple page) that shows the baseline pair and the TwinLane pair side by side, runs a chosen attack, and shows the Gate decision trail and the label provenance of the data that reached each agent. The demo must run offline with the Mock model and, if keys are set, with a real model. Add a 5-minute demo script in docs/report/demo-script.md.

## PHASE 8: HARDENING, DOCS, RELEASE

- Run a self-review as an adversary: try to break P1 to P5 with new tests. Record findings and fixes in docs/report/security-review.md.
- Fuzz the envelope parser with hypothesis. Add size and depth limits.
- Write docs/report/report.md: problem, gap and honest positioning, design, threat model, properties, evaluation, results, limitations, future work, references. All numbers must come from bench results.
- Write docs/report/pba2-outline.md: an 8-slide outline.
- Complete the README: what it is, honest claim, quickstart in under 5 commands, architecture diagram, results summary, limitations.
- Dockerize. docker-compose up must start the demo.
- Tag v0.1.0.

## QUALITY GATES (every phase)

ruff clean, mypy strict clean, tests passing, coverage targets met, no secrets, docs updated, a walkthrough artifact listing what was done, how it was verified, and what is left. If a gate fails, fix it before moving on.

## DEFINITION OF DONE

- make setup && make test passes on a clean machine.
- make demo runs the side-by-side demo offline.
- make bench produces a results table where the naive baseline has a clearly measurable ASR and TwinLane's ASR is reported honestly with confidence intervals, including any attacks that still succeed and why.
- Spec, threat model, ADRs, research docs and report exist and are consistent with the code.
- Limitations are stated plainly.

## WORKING AGREEMENT

1. Start in Planning mode. First action: produce an implementation plan for Phase 0 and Phase 1 only, then wait for approval.
2. After approval, run phases in order. Use separate agents in the Agent Manager for research, protocol and crypto, gate and policy, benchmark, and docs, but have one agent own integration and the quality gate.
3. If you find that existing prior work already covers our claim, stop and tell me before continuing.
4. If a requirement is ambiguous, make the most conservative security choice, record it in an ADR, and keep going.
5. Never invent results. If a benchmark has not run, say so.
6. At the end of each phase, give me a short summary: what changed, how it was verified, open risks, and the next phase.

Begin now with Phase 0.
