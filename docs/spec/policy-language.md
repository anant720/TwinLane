# TwinLane Policy Language Specification

**Version**: 1.0  
**Format**: Declarative YAML  
**Purpose**: Defines deterministic access control, parameter validation rules, provenance checks, and quarantine behaviors enforced by the TwinLane Gate.

---

## 1. Overview and Design Principles

The TwinLane policy engine is intentionally decoupled from model generation. The policy defines unambiguous, deterministic rules that govern:
1. Which intents can be processed under each operational mode.
2. What capability tokens and scopes are required for each intent.
3. Parameter type constraints, regex patterns, numeric bounds, and allowlists.
4. Provenance and taint restrictions (e.g., whether `UNTRUSTED` or `EXTRACTED_UNTRUSTED` parameters are permitted).
5. When an action must be escalated to a human operator (`ESCALATE`).

---

## 2. Top-Level Policy Schema

```yaml
version: "1.0"
mode: "strict" # strict | balanced | observe

# Global defaults
defaults:
  max_envelope_size_bytes: 1048576 # 1 MB
  max_json_depth: 10
  default_ttl_seconds: 60
  max_clock_skew_seconds: 30

# Registered Sanctioned Extractors
extractors:
  - id: "email_extractor"
    type: "regex"
    pattern: "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$"
  - id: "task_status_extractor"
    type: "enum"
    allowed_values: ["SUCCESS", "FAILED", "PENDING"]
  - id: "partner_domain_extractor"
    type: "allowlist"
    allowed_values: ["partner.example.com", "trusted.org"]

# Intent Rules
intents:
  report_result:
    description: "Worker reports completed task result"
    allowed_senders: ["*"]
    required_capability: "report_result"
    parameters:
      task_id:
        type: "string"
        pattern: "^task-[0-9a-f]{4,12}$"
        provenance_required: "TRUSTED"
      status:
        type: "string"
        enum: ["SUCCESS", "FAILED", "PARTIAL"]
        provenance_required: "TRUSTED"
    escalate_if: null

  send_email:
    description: "Send email notification or report"
    allowed_senders: ["ed25519:orchestrator_fingerprint"]
    required_capability: "send_email"
    parameters:
      recipient:
        type: "string"
        extractor: "email_extractor"
        allowlist: ["security-team@example.test", "admin@example.test"]
        provenance_required: "TRUSTED_OR_SANCTIONED"
      subject:
        type: "string"
        max_length: 120
        pattern: "^[a-zA-Z0-9 _\\-:\\[\\]]+$"
        provenance_required: "TRUSTED"
    escalate_if:
      - condition: "recipient_domain_not_in"
        values: ["example.test"]

  read_file:
    description: "Read local sandboxed file"
    allowed_senders: ["*"]
    required_capability: "read_file"
    parameters:
      path:
        type: "string"
        pattern: "^sandbox/[a-zA-Z0-9_-]+\\.[a-z]{2,4}$"
        provenance_required: "TRUSTED"
    escalate_if: null
```

---

## 3. Field Specifications

### 3.1 Mode Configuration
- `mode: strict`:
  - Default for high-security systems.
  - Parameters marked `UNTRUSTED` or `EXTRACTED_UNTRUSTED` are **strictly blocked** from all sensitive actions.
  - Any provenance violation triggers an immediate `DENY`.
- `mode: balanced`:
  - Designed for production workflows that must ingest real-world data (e.g. email addresses from incoming messages).
  - Permits parameters tagged `EXTRACTED_UNTRUSTED` if they successfully pass a registered Sanctioned Extractor and match allowlist rules.
- `mode: observe`:
  - Evaluation and benchmarking mode.
  - Gate records `ALLOW` or `DENY` decisions to the audit log but does not abort execution, enabling measurement of baseline attack outcomes.

### 3.2 Sanctioned Extractors Specification
Extractors isolate untrusted data parsing from instruction interpretation:
- `regex`: Compiles a regular expression with length bounds. String must fully match (`re.fullmatch`).
- `enum`: Verifies the extracted string exists in a fixed tuple of safe constants.
- `allowlist`: Verifies the extracted string exists in a pre-approved set of trusted entities or domain names.

### 3.3 Intent Rules Specification
Each intent in `intents` defines:
1. `required_capability`: The permission string that MUST appear in the sender's active capability token.
2. `allowed_senders`: List of public key fingerprints authorized to invoke this intent (`["*"]` allows any authenticated sender with capability).
3. `parameters`: Dictionary defining validation rules per parameter:
   - `type`: `string`, `integer`, `boolean`, `array`.
   - `pattern`: Regular expression for string validation.
   - `enum`: Explicit list of allowed literal values.
   - `min_value` / `max_value`: Bounds for numeric types.
   - `max_length`: Maximum character length.
   - `provenance_required`:
     - `TRUSTED`: Input must originate exclusively from trusted user directives, system config, or trusted constants.
     - `TRUSTED_OR_SANCTIONED`: Input may originate from untrusted content only if processed by the specified `extractor`.
4. `escalate_if`: Conditions that pause automated execution and produce an `ESCALATE` decision requiring human approval.

---

## 4. Example Default Policy (`policy/rules/default.yaml`)

```yaml
version: "1.0"
mode: "balanced"

defaults:
  max_envelope_size_bytes: 1048576
  max_json_depth: 8
  default_ttl_seconds: 60
  max_clock_skew_seconds: 30

extractors:
  - id: "safe_task_id"
    type: "regex"
    pattern: "^t-[0-9a-fA-F]{4,8}$"
  - id: "recipient_domain_allowlist"
    type: "allowlist"
    allowed_values: ["internal.corp", "trusted-partner.com"]

intents:
  fetch_url:
    required_capability: "fetch_url"
    allowed_senders: ["*"]
    parameters:
      url:
        type: "string"
        pattern: "^https://[a-zA-Z0-9.-]+\\.(internal\\.corp|trusted-partner\\.com)/.*$"
        provenance_required: "TRUSTED"

  report_result:
    required_capability: "report_result"
    allowed_senders: ["*"]
    parameters:
      task_id:
        type: "string"
        extractor: "safe_task_id"
        provenance_required: "TRUSTED_OR_SANCTIONED"
      status:
        type: "string"
        enum: ["SUCCESS", "FAILED", "RETRY"]
        provenance_required: "TRUSTED"

  send_email:
    required_capability: "send_email"
    allowed_senders: ["*"]
    parameters:
      recipient:
        type: "string"
        extractor: "recipient_domain_allowlist"
        provenance_required: "TRUSTED_OR_SANCTIONED"
      body_summary:
        type: "string"
        max_length: 500
        provenance_required: "TRUSTED"
```

