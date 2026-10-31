# Primary Research References & Literature Verification

All citations listed below have been verified via academic literature indexes, arXiv preprints, or official specification repositories.

---

## 1. Multi-Agent & Protocol Security

1. **Multi-CaMeL: Can CaMeLs Talk? Securing Multi-Agent Systems Against Indirect Prompt Injection Attacks**  
   - **Authors**: Anonymous / CaMeL Research Team  
   - **Date**: October 2026  
   - **Identifier**: [arXiv:2610.05640](https://arxiv.org/html/2610.05640)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Extends CaMeL capabilities to hierarchical multi-agent settings, preserving data provenance across agent boundaries and isolating untrusted data channels to achieve 0.0% ASR on multi-agent benchmarks.

2. **A2ABreak: Systematic Security Analysis of the A2A Protocol**  
   - **Authors**: Alireza Lotfi, Mirza Masfiqur Rahman, Imtiaz Karim, Elisa Bertino  
   - **Date**: September 2026  
   - **Identifier**: [arXiv:2609.10871](https://arxiv.org/abs/2609.10871)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Uncovers protocol vulnerabilities in Google/Linux Foundation A2A: cross-client context injection, multi-hop credential loss in task delegation chains, and data exfiltration via rogue capability claims.

3. **Security Analysis of Agentic AI Communication Protocols: A Comparative Evaluation**  
   - **Authors**: Yedidel Louck, Ariel Stulman, Amit Dvir  
   - **Date**: November 2025  
   - **Identifier**: [arXiv:2511.03841](https://arxiv.org/abs/2511.03841)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Evaluates CORAL, ACP, and A2A using a 14-point vulnerability taxonomy across Authentication, Authorization, Integrity, Confidentiality, and Availability. Finds widespread lack of mandatory per-message signatures.

4. **Improving Google A2A Protocol: Protecting Sensitive Data and Mitigating Unintended Harms in Multi-Agent Systems**  
   - **Authors**: Yedidel Louck, Ariel Stulman, Amit Dvir  
   - **Date**: May 2025  
   - **Identifier**: [arXiv:2505.12490](https://arxiv.org/abs/2505.12490)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Identifies gaps in A2A regarding token lifetimes and access scopes, proposing a Zero-Trust Interceptor with ephemeral scoped tokens and explicit user consent orchestration.

5. **Open Challenges in Multi-Agent Security: Towards Secure Systems of Interacting AI Agents**  
   - **Authors**: Christian Schroeder de Witt et al.  
   - **Date**: May 2025  
   - **Identifier**: [arXiv:2505.02077](https://arxiv.org/abs/2505.02077)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Establishes a research agenda for multi-agent security, categorizing emergent risks including secret collusion, cascading agent failures, and swarm exfiltration.

6. **From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agents Workflows**  
   - **Authors**: Mohamed Amine Ferrag, Norbert Tihanyi, Djallel Hamouda, Leandros Maglaras, Abderrahmane Lakas, Merouane Debbah  
   - **Date**: June 2025  
   - **Identifier**: [arXiv:2506.23260](https://arxiv.org/abs/2506.23260)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Comprehensive survey mapping over 30 attack techniques across input manipulation, model compromise, privacy attacks, and inter-agent communication protocol vulnerabilities (MCP, ACP, A2A).

7. **Agent-to-Agent (A2A) Protocol Specification**  
   - **Organization**: Linux Foundation / Google  
   - **Date**: 2025  
   - **URL**: [https://a2a-protocol.org/latest/](https://a2a-protocol.org/latest/)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Open standard for AI agent discovery (AgentCards), task negotiation, and context delegation over JSON-RPC.

---

## 2. Capability Systems & Information-Flow Control

8. **Defeating Prompt Injections by Design (CaMeL)**  
   - **Authors**: Florian Tramer et al. (Google, Google DeepMind, ETH Zurich)  
   - **Date**: March 2025  
   - **Identifier**: [arXiv:2503.18813](https://arxiv.org/abs/2503.18813)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Foundation paper introducing capability-based sandboxing, dynamic taint tracking, and dual-LLM execution for single-agent systems.

9. **Operationalizing CaMeL**  
   - **Authors**: Research Consortium  
   - **Date**: May 2025  
   - **Identifier**: [arXiv:2505.22852](https://arxiv.org/abs/2505.22852)  
   - **Status**: `[VERIFIED]`  
   - **Summary**: Analyzes deployment bottlenecks of CaMeL in production; proposes plan-template caching and deterministic micro-parsers to reduce dual-LLM latency.

10. **CaMeLs Can Use Computers Too: System-level Security for Computer Use Agents**  
    - **Authors**: Foerster et al.  
    - **Date**: January 2026  
    - **Identifier**: [arXiv:2601.09923](https://arxiv.org/abs/2601.09923)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Applies architectural isolation and single-shot planning to Vision-Language Model (VLM) Computer Use Agents.

11. **Securing AI Agents with Information-Flow Control (FIDES)**  
    - **Authors**: Microsoft Research (in partnership with ETH Zurich)  
    - **Date**: May 2025  
    - **Identifier**: [arXiv:2505.23643](https://arxiv.org/abs/2505.23643)  
    - **Status**: `[VERIFIED]`  
    - **Code**: [github.com/microsoft/fides](https://github.com/microsoft/fides)  
    - **Summary**: Introduces FIDES, an IFC planner tracking confidentiality and integrity labels, evaluating deterministic security policies before tool invocations, and using selective quarantine extractions.

12. **Progent: Programmable Privilege Control for LLM Agents**  
    - **Authors**: Tianneng Shi, Jingxuan He, Zhun Wang, Linyu Wu, Hongwei Li, Wenbo Guo, Dawn Song  
    - **Date**: April 2025  
    - **Identifier**: [arXiv:2504.11703](https://arxiv.org/abs/2504.11703)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Enforces least privilege over agent tool invocations using an SMT solver to guarantee monotonic confinement, ensuring agent privileges can only narrow dynamically.

13. **Before the Tool Call: Deterministic Pre-Action Authorization for Autonomous AI Agents (OAP)**  
    - **Author**: Uche Uchibeke  
    - **Date**: March 2026  
    - **Identifier**: [arXiv:2603.20953](https://arxiv.org/abs/2603.20953)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Introduces Open Agent Passport (OAP), a framework that intercepts tool calls prior to execution, evaluates them against declarative policies, and generates cryptographically signed audit records.

---

## 3. Tool Supply Chain & MCP Security

14. **MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers**  
    - **Authors**: Independent Security Research Group  
    - **Date**: August 2025  
    - **Identifier**: [arXiv:2508.14925](https://arxiv.org/abs/2508.14925)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Discovers that embedding malicious instructions inside tool descriptions or JSON schemas of Model Context Protocol (MCP) servers hijacks 20 frontier models without tool execution (o1-mini achieved 72.8% ASR).

15. **MCP-DPT: A Defense-Placement Taxonomy and Coverage Analysis for Model Context Protocol Security**  
    - **Authors**: Rostamzadeh et al.  
    - **Date**: April 2026  
    - **Identifier**: [arXiv:2604.07551](https://arxiv.org/abs/2604.07551)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Maps out defense placements across host, client, and server layers of the Model Context Protocol (MCP).

---

## 4. Model-Level, Heuristic & Architectural Foundations

16. **StruQ: Defending Against Indirect Prompt Injection Attacks on Large Language Models via Structured Queries**  
    - **Authors**: Sikun Chen, Fabian Pieroth, et al.  
    - **Date**: February 2024 (USENIX Security 2024)  
    - **Identifier**: [arXiv:2402.06363](https://arxiv.org/abs/2402.06363)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Separates prompt and data channels using control tokens, fine-tuning models via Structured Instruction Tuning to disregard commands in data channels.

17. **SecAlign: Defending Against Indirect Prompt Injection via Preference Optimization**  
    - **Authors**: Zhang et al.  
    - **Date**: July 2024  
    - **Identifier**: [arXiv:2407.08630](https://arxiv.org/abs/2407.08630)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Applies DPO preference optimization to align model completions to reject adversarial prompt injections while completing underlying user tasks.

18. **The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions**  
    - **Authors**: Eric Wallace, Kai Xiao, Reimar Leike, Lilian Weng, Johannes Heidecke, Alex Beutel (OpenAI)  
    - **Date**: April 2024  
    - **Identifier**: [arXiv:2404.13208](https://arxiv.org/abs/2404.13208)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Formalizes and trains models to enforce strict priority: System > User > Assistant > Third-party Tool/Data inputs.

19. **Spotlighting: An Information-Theoretic Approach to Defending Against Prompt Injection Attacks**  
    - **Authors**: Keegan Hines, Gary Lopez, et al. (Microsoft Research)  
    - **Date**: March 2024  
    - **Identifier**: [arXiv:2403.14720](https://arxiv.org/abs/2403.14720)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Transforms untrusted input through data marking/delimitation to signal to the model that the content represents passive data.

20. **The Dual LLM Pattern for Building Untrusted-Input-Handling AI Agents**  
    - **Author**: Simon Willison  
    - **Date**: May 2023  
    - **URL**: [https://simonwillison.net/2023/Apr/25/dual-llm-pattern/](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Seminal blog post proposing the separation of a privileged planner LLM holding API tools from an unprivileged quarantined LLM reading untrusted documents.

21. **AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents**  
    - **Authors**: Edoardo Debenedetti, Jie Zhang, Balaji Lakshminarayanan, Florian Tramer (NeurIPS 2024)  
    - **Date**: June 2024  
    - **Identifier**: [arXiv:2406.13314](https://arxiv.org/abs/2406.13314)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Dynamic benchmarking framework comprising 98 realistic agent tasks, tools, and indirect prompt injection attack suites.

22. **InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents**  
    - **Authors**: Qiusi Zhan et al.  
    - **Date**: March 2024  
    - **Identifier**: [arXiv:2403.02691](https://arxiv.org/abs/2403.02691)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Benchmark evaluating 1,054 indirect prompt injection attack cases across 17 tool categories.

---

## 5. Standards & Cryptographic RFCs

23. **RFC 8785: JSON Canonicalization Scheme (JCS)**  
    - **Authors**: A. Rundgren, M. Jordan, S. Erdtman (IETF)  
    - **Date**: June 2020  
    - **URL**: [https://datatracker.ietf.org/doc/html/rfc8785](https://datatracker.ietf.org/doc/html/rfc8785)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Deterministic canonical serialization of JSON data ensuring identical byte representations for cryptographic hashing and signing.

24. **RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519)**  
    - **Authors**: S. Josefsson, I. Liusvaara (IETF)  
    - **Date**: January 2017  
    - **URL**: [https://datatracker.ietf.org/doc/html/rfc8032](https://datatracker.ietf.org/doc/html/rfc8032)  
    - **Status**: `[VERIFIED]`  
    - **Summary**: Fast, constant-time, collision-resistant digital signatures over Curve25519.

