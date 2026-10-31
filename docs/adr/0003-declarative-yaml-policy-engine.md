# ADR 0003: Pure Declarative YAML Policy Engine vs. External Evaluators

**Status**: Accepted  
**Date**: 2026-10-31  
**Authors**: Anant, Shweta, Aditya  

---

## Context
TwinLane's Gate must evaluate access control rules, intent schemas, parameter constraints, and provenance labels for every incoming envelope.

Candidates considered:
1. **External Policy Daemon (Open Policy Agent - OPA with Rego, or AWS Cedar)**.
2. **Embedded Python Policy DSL (e.g., custom AST interpreter)**.
3. **Pure Declarative YAML Engine evaluated via Pydantic v2 in-process**.

## Decision
We chose a **pure declarative YAML policy schema parsed and validated in-process using Pydantic v2 and Python's standard library**.

### Rationale
1. **Zero External Daemon Dependencies**: Requiring an external OPA or Cedar daemon complicates deployment, introduces local IPC/network latency (~5–15 ms per call), and increases failure modes in multi-agent environments.
2. **Sub-Millisecond In-Process Evaluation**: Parsing and validating declarative parameter rules (regex matching, numeric bounds, allowlist lookups) in-process using compiled regex and Pydantic models executes in < 0.2 ms.
3. **Safety by Construction**:
   - YAML policies are purely declarative; they cannot execute arbitrary code or trigger infinite loops (unlike Turing-complete DSLs or unconstrained interpreters).
   - Rejection of unknown fields is strictly enforced at parse time (`extra="forbid"`).
4. **Developer Comprehensibility**: Security engineers, DevOps teams, and non-specialist developers can read, audit, and modify YAML policy files without learning a specialized query language like Rego.

## Consequences
- **Positive**: Lightweight footprint; zero background daemon processes; sub-millisecond evaluation latency; fail-closed behavior on invalid configuration.
- **Negative**: Complex multi-variable graph traversals or recursive role relationships are harder to express than in Datalog/Rego. However, for intent parameter gating and provenance checking, declarative YAML rules are completely sufficient.
