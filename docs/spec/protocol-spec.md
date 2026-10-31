# TwinLane Protocol Specification (Version 1.0)

**Status**: Normative Specification  
**Editors**: Anant, Shweta, Aditya  
**Classification**: Standards Track / Defensive Systems Architecture

---

## 1. Terminology and Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

---

## 2. High-Level Architecture & Envelopes

Every communication between two agents in TwinLane MUST be structured as a **TwinLane Wire Envelope** consisting of four distinct top-level objects:
1. `header`: Transport, session, identity, and replay-protection metadata.
2. `control`: Typed, schema-validated command intent covered by a capability token.
3. `data`: Array of content items, each bearing explicit provenance and security labels.
4. `signature`: Cryptographic signature binding the header, control lane, and data manifest.

```
+-------------------------------------------------------------------------+
|                         TWINLANE WIRE ENVELOPE                          |
+-------------------------------------------------------------------------+
| 1. HEADER                                                               |
|    - version: 1                                                         |
|    - msg_id: uuidv7                                                     |
|    - session_id: uuid                                                   |
|    - sender: "agent-b-fingerprint"                                      |
|    - recipient: "agent-a-fingerprint"                                   |
|    - seq: 104                                                           |
|    - nonce: "3f7a1b...128-bit-hex"                                      |
|    - issued_at: "2026-10-31T15:00:00Z"                                 |
|    - expires_at: "2026-10-31T15:01:00Z"                                |
+-------------------------------------------------------------------------+
| 2. CONTROL LANE                                                         |
|    - intent: "report_result" (from Intent Catalog)                      |
|    - params: { "task_id": "task-8842", "status": "COMPLETED" }          |
|    - capability_token_id: "cap-991b-412"                                |
+-------------------------------------------------------------------------+
| 3. DATA LANE                                                            |
|    - item_id: "d-1"                                                     |
|      media_type: "text/plain"                                           |
|      content_hash: "sha256-hex"                                         |
|      provenance:                                                        |
|        origin: "web:https://example.test/article"                       |
|        origin_type: "web" (user | agent | tool | web | unknown)         |
|        chain: ["agent-b-fingerprint"]                                   |
|        integrity: "UNTRUSTED" (TRUSTED | UNTRUSTED)                     |
|        confidentiality: "PUBLIC" (PUBLIC | INTERNAL | SECRET)           |
|      content: "Scraped text containing potential injections..."         |
+-------------------------------------------------------------------------+
| 4. SIGNATURE                                                            |
|    - alg: "Ed25519"                                                     |
|    - signer: "agent-b-fingerprint"                                      |
|    - signature_bytes: "hex / base64"                                    |
|    - signed_fields: ["header", "control", "data_manifest"]              |
+-------------------------------------------------------------------------+
```

---

## 3. Normative Envelope Definitions

### 3.1 Header Specification
The `header` object provides message-level authentication and replay prevention.

```json
{
  "version": 1,
  "msg_id": "01859b8a-936d-7422-b5e2-2e9e2b104c8f",
  "session_id": "9b1c7f3a-8b2d-4c3e-9f1a-5d6e7f8a9b0c",
  "sender": "ed25519:e5a8f4c2810a9b6c12...",
  "recipient": "ed25519:a1b2c3d4e5f60718...",
  "seq": 42,
  "nonce": "c4d3b2a19876543210abcdef01234567",
  "issued_at": 1793448000,
  "expires_at": 1793448060
}
```

- `version` (integer, REQUIRED): MUST be `1`.
- `msg_id` (string, REQUIRED): UUIDv7 string with embedded millisecond timestamp.
- `session_id` (string, REQUIRED): Persistent UUID representing the conversational session.
- `sender` (string, REQUIRED): Public key fingerprint of the sending agent in format `ed25519:<hex_key_hash>`.
- `recipient` (string, REQUIRED): Public key fingerprint of the intended receiving agent.
- `seq` (integer, REQUIRED): Monotonically increasing sequence integer. Per session and sender, each message MUST have `seq > last_seen_seq`.
- `nonce` (string, REQUIRED): Cryptographically random 128-bit hex string (32 characters).
- `issued_at` (integer, REQUIRED): Unix epoch timestamp in seconds.
- `expires_at` (integer, REQUIRED): Unix epoch timestamp in seconds. MUST NOT exceed `issued_at + 60` by default. Max clock skew tolerated by receiver is 30 seconds.

### 3.2 Control Lane Specification
The `control` object conveys structured intent. **Free-text instructions are strictly prohibited in the control lane.**

```json
{
  "intent": "fetch_record",
  "params": {
    "record_id": "REC-9402",
    "format": "JSON"
  },
  "capability_token_id": "cap-7f3a-8b1c-9902"
}
```

- `intent` (string, REQUIRED): An identifier registered in the agreed **Intent Catalog** (e.g., `execute_task`, `report_result`, `request_action`, `cancel_task`).
- `params` (object, REQUIRED): Key-value dictionary conforming to the intent's registered schema. Strings MUST be enums, allowlisted identifiers, or bounded regex-validated patterns. Free-text strings are rejected.
- `capability_token_id` (string, REQUIRED): Reference identifier of the capability token granting permission for this intent.

### 3.3 Data Lane Specification
The `data` object is an array of passive content items:

```json
[
  {
    "item_id": "data-item-1",
    "media_type": "text/plain",
    "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "content": "Raw retrieved document body...",
    "content_ref": null,
    "provenance": {
      "origin": "web:https://news.example.test/story",
      "origin_type": "web",
      "chain": ["ed25519:e5a8f4c2810a9b6c12..."],
      "integrity": "UNTRUSTED",
      "confidentiality": "PUBLIC"
    },
    "schema_id": null
  }
]
```

- `item_id` (string, REQUIRED): Unique string identifier within the envelope.
- `media_type` (string, REQUIRED): MIME type (e.g., `text/plain`, `application/json`).
- `content_hash` (string, REQUIRED): Lowercase hex-encoded SHA-256 hash of `content` bytes.
- `content` (string, OPTIONAL): Inline content string.
- `content_ref` (string, OPTIONAL): URI reference when content is transferred out-of-band.
- `provenance` (object, REQUIRED):
  - `origin` (string, REQUIRED): Source URI or descriptor (e.g., `user:alice`, `tool:read_file`, `web:https://...`).
  - `origin_type` (string, REQUIRED): One of `user`, `agent`, `tool`, `web`, `unknown`.
  - `chain` (array of strings, REQUIRED): Array of sender fingerprints that processed this item.
  - `integrity` (string, REQUIRED): `TRUSTED` or `UNTRUSTED`.
  - `confidentiality` (string, REQUIRED): `PUBLIC`, `INTERNAL`, or `SECRET`.
- `schema_id` (string, OPTIONAL): Schema URI if the data item is structured.

### 3.4 Data Manifest and Canonical Signing
To prevent tampering and content swapping while allowing efficient signing:
1. The sender creates a **Data Manifest** consisting of an array of `{item_id, content_hash}`.
2. The signable payload is constructed:
   $$\text{SignablePayload} = \{\text{"header"}: \text{header}, \text{"control"}: \text{control}, \text{"data\_manifest"}: [\{\text{"item\_id"}: d.\text{item\_id}, \text{"content\_hash"}: d.\text{content\_hash}\} \mid d \in \text{data}]\}$$
3. The payload is serialized to bytes using the **JSON Canonicalization Scheme (RFC 8785)**.
4. The Ed25519 signature is computed over these canonical bytes using the sender's private key.
5. The signature object is populated:
   ```json
   {
     "alg": "Ed25519",
     "signer": "ed25519:e5a8f4c2810a9b6c12...",
     "signature_bytes": "3a7b9c...",
     "signed_manifest": [
       {"item_id": "data-item-1", "content_hash": "e3b0c442..."}
     ]
   }
   ```

---

## 4. Capability Tokens & Monotonic Delegation

Every control intent MUST be authorized by a valid **Capability Token**.

### 4.1 Capability Token Schema
```json
{
  "token_id": "cap-7f3a-8b1c-9902",
  "issuer": "ed25519:root_admin_fingerprint",
  "subject": "ed25519:agent-b-fingerprint",
  "intents": ["fetch_record", "report_result"],
  "constraints": {
    "fetch_record": {
      "record_id_prefix": "REC-",
      "format": ["JSON", "TEXT"]
    }
  },
  "not_before": 1793440000,
  "expires_at": 1793450000,
  "max_uses": 100,
  "uses_count": 3,
  "parent_token_id": null,
  "signature": "ed25519:signature_bytes..."
}
```

### 4.2 Attenuation Invariant (Monotonic Narrowing)
A token $\mathcal{C}_{child}$ derived from $\mathcal{C}_{parent}$ is valid if and only if:
1. $\text{intents}(\mathcal{C}_{child}) \subseteq \text{intents}(\mathcal{C}_{parent})$.
2. For all parameter constraints in $\mathcal{C}_{parent}$, the constraint in $\mathcal{C}_{child}$ is a subset or narrower range.
3. $\text{not\_before}(\mathcal{C}_{child}) \ge \text{not\_before}(\mathcal{C}_{parent})$.
4. $\text{expires\_at}(\mathcal{C}_{child}) \le \text{expires\_at}(\mathcal{C}_{parent})$.
5. The delegation chain terminates at an authorized trust anchor (Root Issuer).

Any attempt to delegate a wider permission or extend validity MUST be rejected immediately.

---

## 5. Security Labels & Information Flow Rules

### 5.1 Label Lattice
- **Integrity Lattice**: $\text{TRUSTED} > \text{UNTRUSTED}$
- **Confidentiality Lattice**: $\text{SECRET} > \text{INTERNAL} > \text{PUBLIC}$

### 5.2 Join Operations
When multiple data items or inputs $x_1, x_2, \dots, x_k$ are combined or derived:
$$\text{Integrity}(x_1 \oplus \dots \oplus x_k) = \begin{cases} \text{UNTRUSTED} & \text{if } \exists i: \text{Integrity}(x_i) = \text{UNTRUSTED} \\ \text{TRUSTED} & \text{otherwise} \end{cases}$$
$$\text{Confidentiality}(x_1 \oplus \dots \oplus x_k) = \max_{1 \le i \le k} \text{Confidentiality}(x_i)$$

### 5.3 Promotion Restrictions
- No LLM, sender, or intermediary may ever change an `UNTRUSTED` label to `TRUSTED`.
- Untrusted data can only yield a value bound to an action parameter via a **Sanctioned Extractor**. The extracted value receives the label `EXTRACTED_UNTRUSTED`.
- Policy determines whether an action allows parameters labeled `EXTRACTED_UNTRUSTED`.

### 5.4 Sanctioned Extractors
Sanctioned extractors are deterministic, registered functions:
1. `EnumExtractor`: Matches against a hardcoded set of allowed string literals.
2. `AllowlistLookupExtractor`: Verifies that the string exists in a trusted key-value map or database.
3. `RegexFormatExtractor`: Verifies that the string conforms to a strict, bounded regex (e.g., `^[A-Z0-9]{3,8}$`).

---

## 6. The Gate Pipeline: 7-Step Verification

When an agent receives a TwinLane envelope, the **TwinLane Gate** executes the following 7 steps in strict linear order. If any step fails, the pipeline immediately halts and issues a `DENY`.

```
[ Incoming Envelope ]
        |
        v
+-----------------------+   Failure
| 1. Authenticate       | ---------> [ DENY: AUTH_FAILED ]
+-----------------------+
        | Success
        v
+-----------------------+   Failure
| 2. Validate Schema    | ---------> [ DENY: INVALID_SCHEMA ]
+-----------------------+
        | Success
        v
+-----------------------+   Failure
| 3. Authorize Cap      | ---------> [ DENY: CAPABILITY_VIOLATION ]
+-----------------------+
        | Success
        v
+-----------------------+   Failure
| 4. Check Provenance   | ---------> [ DENY: UNTRUSTED_PARAM ]
+-----------------------+
        | Success
        v
+-----------------------+
| 5. Quarantine Route   | (Passive data routed to tool-free reader)
+-----------------------+
        |
        v
+-----------------------+
| 6. Policy Decision    | ---------> [ ALLOW / DENY / ESCALATE ]
+-----------------------+
        |
        v
+-----------------------+
| 7. Append Audit Log   | (Hash-chained append-only log record)
+-----------------------+
```

### Detailed Pipeline Steps:
1. **Step 1: Authenticate**:
   - Verify `sender` is present in local `TrustStore`.
   - Verify `recipient` matches the local agent's identity.
   - Verify `issued_at` and `expires_at` against current time (reject if expired or clock skew > 30s).
   - Check `nonce` against in-memory `NonceCache` with TTL (reject if seen).
   - Verify `seq > last_seen_seq` for `(session_id, sender)`.
   - Recompute SHA-256 hash for every item in `data` and confirm it matches `data_manifest`.
   - Canonicalize `{header, control, data_manifest}` via RFC 8785 and verify Ed25519 signature.
2. **Step 2: Validate Schema**:
   - Check `intent` against registered `IntentCatalog`.
   - Validate `params` against the intent's JSON Schema. Reject unrecognized keys or unconstrained strings.
3. **Step 3: Authorize Capability**:
   - Retrieve `capability_token_id`.
   - Verify token signature, expiration, and remaining `max_uses`.
   - Confirm requested `intent` is permitted in `token.intents`.
   - Check all `params` against `token.constraints`.
   - If token has `parent_token_id`, verify unbroken delegation chain to root trust anchor.
4. **Step 4: Check Provenance**:
   - Inspect provenance labels for all parameter inputs.
   - In `Strict` mode, reject any parameter derived from `UNTRUSTED` data.
   - In `Balanced` mode, verify that any `UNTRUSTED` parameter passed through a registered Sanctioned Extractor and satisfies policy.
5. **Step 5: Quarantine Routing**:
   - Untrusted items in the Data Lane are forwarded exclusively to a **Quarantine Reader** instance.
   - The Quarantine Reader has **zero tool-calling capabilities**. Its output is schema-validated and retains an `UNTRUSTED` label.
6. **Step 6: Policy Decision**:
   - Evaluate intent and parameters against the declarative policy engine.
   - Decide: `ALLOW`, `DENY`, or `ESCALATE` (to human-in-the-loop).
7. **Step 7: Append Audit Log**:
   - Append an immutable JSONL record containing:
     $$\text{Record}_n = \{\text{index}, \text{timestamp}, \text{msg\_id}, \text{sender}, \text{intent}, \text{decision}, \text{prev\_hash}, \text{record\_hash}\}$$
   - Where $\text{prev\_hash} = \text{SHA-256}(\text{Record}_{n-1})$ and $\text{record\_hash} = \text{SHA-256}(\text{Record}_n \setminus \{\text{record\_hash}\})$.

---

## 7. Operational Modes

1. **Strict Mode**:
   - Default for high-security environments (financial, administrative, sensitive data access).
   - Zero tolerance: no parameter derived from an `UNTRUSTED` origin may be passed to any tool or action, even via extractors.
2. **Balanced Mode**:
   - Default for operational agent pairs.
   - Permits sanctioned extraction (enum matching, allowlist validation) under explicit policy rules.
3. **Observe Mode**:
   - Evaluation and benchmark mode.
   - Executes all Gate checks and logs decisions to the audit trail, but permits execution to continue for comparative ASR measurement.

