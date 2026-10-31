# Security Policy

## 1. Defensive Research Scope

TwinLane is a defensive security research project. All attack corpora (`bench/attacks/`) and benchmark scenarios (`demo/fixtures/`) are designed exclusively for controlled, local evaluation against mock tools.

- **No Real Network Egress**: Mock tools (`fetch_url`, `http_post`, `send_email`) are local sandboxes and do not perform unauthorized network calls.
- **Mock Secrets & Canaries**: Test secrets are synthetic canary tokens (e.g., `CANARY-7f3a9b1c`). Never commit real API keys or sensitive credentials to this repository.

## 2. Reporting a Vulnerability

If you discover a vulnerability or security bypass in the TwinLane protocol or reference Gate implementation:
1. **Do not open a public issue.**
2. Send a detailed report via encrypted email to the maintainers at `security@twinlane.local` or submit a private GitHub Security Advisory.
3. Include:
   - Steps to reproduce or adversarial test fixture.
   - Target LLM model and version (if applicable).
   - Expected behavior vs. actual Gate decision.
   - Proposed fix or mitigation if available.

We commit to acknowledging reports within 48 hours and providing a remediation timeline within 7 days.

