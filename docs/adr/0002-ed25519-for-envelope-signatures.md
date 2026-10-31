# ADR 0002: Ed25519 for Asymmetric Envelope Signatures

**Status**: Accepted  
**Date**: 2026-10-31  
**Authors**: Anant, Shweta, Aditya  

---

## Context
TwinLane requires an asymmetric cryptographic digital signature algorithm to authenticate agent identities, prevent message tampering, enforce non-repudiation, and bind capability tokens.

Candidates considered:
1. **Ed25519 (RFC 8032)**.
2. **ECDSA (NIST P-256 / secp256r1)**.
3. **RSA (2048-bit or 4096-bit)**.

## Decision
We chose **Ed25519 (Edwards-curve Digital Signature Algorithm over Curve25519)** as the mandatory cryptographic signature scheme for all TwinLane envelopes and capability tokens.

### Rationale
1. **High Performance**: Ed25519 signature generation and verification take under 0.1 ms on standard modern CPUs, minimizing gate latency overhead.
2. **Deterministic Signatures**: Unlike standard ECDSA, which requires a cryptographically secure random number ($k$) per signature (where any entropy failure completely leaks the private key), Ed25519 generates signatures deterministically using a cryptographic hash of the message and private key.
3. **Constant-Time Execution & Side-Channel Resistance**: Modern Ed25519 implementations (including the `cryptography` library backing TwinLane) are constant-time, eliminating timing attack vulnerabilities.
4. **Compact Footprint**:
   - Public keys are 32 bytes (64 hex characters).
   - Signatures are 64 bytes (128 hex characters).
   - Ideal for inclusion in HTTP headers and JSON envelopes without message bloating.
5. **Universal Adoption**: Ed25519 is the standard for modern secure protocols (SSH, Signal, TLS 1.3, WireGuard).

## Consequences
- **Positive**: Blazing fast gate evaluation; small key and signature footprints; immune to random number generator failures during signing.
- **Negative**: Agents must maintain an Ed25519 keypair and trust store. Legacy enterprise systems requiring NIST-approved curves (e.g., FIPS 140-2 environments requiring P-256) will require a future crypto-pluggable abstraction adapter.

