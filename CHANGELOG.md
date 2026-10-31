# Changelog

All notable changes to the TwinLane project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Phase 0 (Research & Literature Grounding)**:
  - Comprehensive landscape survey covering 8 defense families (`docs/research/landscape.md`).
  - Gap analysis establishing honest claim boundaries and concession of non-novel elements (`docs/research/gap-analysis.md`).
  - Comparative related work matrix evaluated across 9 dimensions (`docs/research/related-work-matrix.md`).
  - 24 verified academic literature citations (`docs/research/references.md`).
  - Standing engineering rules and safety guidelines (`AGENTS.md` and `.agents/rules/standing_rules.md`).
- **Phase 1 (Specification & Threat Model)**:
  - Formal STRIDE threat model and attack trees (`docs/spec/threat-model.md`).
  - TwinLane Protocol Specification v1.0 defining wire envelopes, canonicalization, and Gate pipeline (`docs/spec/protocol-spec.md`).
  - Mathematical definitions of security properties P1–P5 with verification test designs (`docs/spec/security-properties.md`).
  - Declarative YAML policy language schema (`docs/spec/policy-language.md`).
  - Architectural Decision Records: ADR 0001 through ADR 0005 (`docs/adr/`).
- **Phase 2 (Repository Scaffold & Tooling)**:
  - Root configuration (`pyproject.toml`, `Makefile`, `.gitignore`, `.pre-commit-config.yaml`, `.env.example`).
  - GitHub Actions CI workflow (`.github/workflows/ci.yml`).
