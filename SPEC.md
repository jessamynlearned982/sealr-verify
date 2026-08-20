# 03 — Evidence Format Specification

This document specifies the Sealr evidence format: records, chains, checkpoints, signatures, timestamps, keys, redaction, the `.seal` bundle, and the verification procedure. It is written to be published: auditors and third parties will rely on it. The reference implementation is `crates/evidence`, `crates/bundle`, `crates/verify` (verifier: Apache-2.0).

Honesty clause (normative for all marketing and docs): Sealr evidence is **tamper-evident, not tamper-proof**. It proves integrity, ordering, timing, and origin of the recorded stream; it cannot prove that unrecorded events did not happen. Coverage-gap records and reconciliation (01 FR-3.6) bound — but do not eliminate — that limit. State this limit wherever guarantees are described.

---

## 1. Terminology

- **Record** — one signed-into-chain unit describing an event (operation, verdict, approval, lifecycle, gap).
- **Stream** — totally ordered sequence of records from one recorder identity; identified by `stream_id`.
- **Segment** — contiguous portion of a stream between recorder starts (one boot = one segment).
- **Checkpoint** — signed statement binding a Merkle root over recent records + the chain head.
- **Anchor** — RFC 3161 timestamp token (TSA) or eIDAS qualified timestamp (QTS) over checkpoint data.
- **Bundle (`.seal`)** — portable, self-contained evidence export.
- **Commitment** — salted hash standing in for a payload.

## 2. Encoding and canonicalization

- V1 encoding: **JSON**, canonicalized per **RFC 8785 (JCS)** for all hashing and signing. Rationale: human inspectability for auditors outweighs compactness; CBOR/COSE migration is `ADR-001` (format carries `schema_version` to permit it).
- All hashes: **BLAKE3-256**, lowercase hex. (`ADR-003` records the BLAKE3 vs SHA-256 tradeoff; RFC 3161 interop uses SHA-256 digests of the checkpoint bytes where the TSA requires it — both digests are stored.)
- All signatures: **Ed25519** over the BLAKE3-256 digest of the JCS bytes of the signed structure.
- Timestamps: `ts_wall` RFC 3339 UTC with milliseconds; `ts_mono_ns` monotonic nanoseconds since segment start (u64).
- Ids: ULID (26-char Crockford base32).

## 3. Record schema (v1)

Top-level fields. `console: yes` marks fields included in the Console metadata projection (02 §5); everything else never leaves the customer boundary in Hybrid mode.

| Field | Type | Console | Description |
|---|---|---|---|
| `schema_version` | string `"1"` | yes | Format version |
| `record_id` | ULID | yes | Unique id |
| `stream_id` | ULID | yes | Recorder stream |
| `segment_id` | ULID | yes | Boot segment |
| `seq` | u64 | yes | Strictly monotonic per stream, no gaps within a segment |
| `ts_wall` / `ts_mono_ns` | see §2 | yes | Dual clocks |
| `record_type` | enum | yes | `operation` \| `outcome` \| `approval` \| `policy_event` \| `lifecycle` \| `coverage_gap` \| `guard_error` \| `spool_shed` \| `clock_anomaly` \| `generic_exec` |
| `recorder` | object | yes | `{recorder_id, version, host_fingerprint, platform}` |
| `subject` | object | yes | `{agent_kind, agent_session, human_principal?, attribution: attributed\|inferred\|unattributed, source}` |
| `action` | object | yes | `{integration, operation, verb_class, target_resource, resource_labels[]}` — structural only, no literals (01 FR-2.3) |
| `action_detail` | object | **no** | Structural detail that may be sensitive (normalized statement skeleton, resource addresses) — Ledger only |
| `payload_commitment` | object | yes | `{alg:"blake3-salted", commitment}` — see §6 |
| `payload_ref` | object | **no** | `{vault_url, enc:"aes-256-gcm", key_ref}` when vaulted |
| `verdict` | object | yes | `{decision, mode, risk_class, policy_version, rule_ids[], reason_codes[], guard:{name,version}, eval_ms}` |
| `approval_ref` | object | yes | `{approval_record_id}` when applicable |
| `links` | object | yes | `{request_record_id?}` for outcomes |
| `prev_hash` | hex | yes | Chain: hash of previous record in stream (`GENESIS` sentinel rules in §5) |
| `record_hash` | hex | yes | BLAKE3-256 of JCS(record without `record_hash`) |

Unknown fields MUST be rejected by writers and preserved-but-flagged by verifiers of higher minor versions.

## 4. Chaining

`record_hash_i = BLAKE3(JCS(record_i \ {record_hash}))` with `record_i.prev_hash = record_hash_{i-1}`.
Verification asserts: hash correctness, `prev_hash` linkage, `seq` strict monotonic +1 within a segment, `ts_mono_ns` non-decreasing, `ts_wall` non-decreasing within tolerance (±2 s skew allowed, larger deltas require a `clock_anomaly` record adjacent).

## 5. Segments

On start, the recorder writes a `lifecycle:segment_start` record containing: recorder certificate chain (§7), host fingerprint (machine-id hash, OS, arch), recorder version, config digest, policy bundle version + digest, previous segment's final `record_hash` if locally known (cross-segment continuity), and a 32-byte boot nonce. First record of the first segment of a stream uses `prev_hash = BLAKE3("SEALR-GENESIS" || stream_id)`. Clean shutdown appends `lifecycle:segment_end`; its absence in a later segment's predecessor is itself evidence (crash), and the verifier reports it.

## 6. Payload commitments and redaction

`commitment = BLAKE3(salt || payload_bytes)` with 32-byte random salt. The salt is stored **with the payload** (vault) or discarded in `commitment_only` mode — never in the record. Consequences (normative):
- A redacted/metadata-level bundle verifies fully (chain, signatures, anchors) without payloads.
- Holding the payload + salt allows anyone to prove that payload matches the record (selective disclosure, e.g., to a court).
- Without the salt, the commitment reveals nothing practical about low-entropy payloads (no dictionary confirmation) — this is why the salt MUST NOT travel with the record.
Vaulted payloads: AES-256-GCM, per-payload data key, wrapped by customer KMS key (envelope); `key_ref` names the wrapping key, never key material.

## 7. Keys and identity

Hierarchy:

```
Sealr Root (offline, 2-of-3 ceremony, Ed25519)            — signs →
  Tenant CA (Console KMS/HSM-held, per tenant)               — signs →
    Recorder identity cert (pub key from on-device keypair)  — signs → records? NO: signs checkpoints
Console signing key (per environment, KMS)                   — countersigns checkpoints, signs policy bundles, approvals
```

- Recorder keypair: generated on device at enrollment (single-use token, 01 FR-10.2); private key in TPM 2.0 / Secure Enclave / OS keychain; documented file fallback (0600, zeroized in memory). Rotation ≤ 90 days: new keypair + `lifecycle:key_rotation` record signed by both old (if available) and new keys.
- Individual records are **not** individually signed (cost); integrity flows from chaining up to **signed checkpoints** (§8). A record is considered attested when covered by ≥ 1 valid checkpoint.
- Revocation: Console publishes a signed revocation list (recorder cert serials + effective time); verifier treats checkpoints signed after revocation time as invalid and reports the boundary. `ADR-011` covers custody edge cases.

## 8. Checkpoints, countersignature, anchoring

**CheckpointNote** (signed by recorder key):
`{checkpoint_id, stream_id, segment_id, seq_from, seq_to, chain_head_hash, merkle_root, tree_size, ts_wall, recorder_cert_fingerprint}` — Merkle tree per RFC 6962 conventions (leaf = `record_hash`, leaf prefix `0x00`, node prefix `0x01`) over records `[seq_from, seq_to]`. Emitted every ≤ 1,000 records or ≤ 10 s of activity (01 FR-3.2).

**Countersignature:** Console verifies recorder signature, verifies `seq_from = last_seq_to + 1` against its stored head (anti-fork/rollback), then signs `{checkpoint_id, received_at, console_key_id}`. Divergence → `chain_conflict` alert + record; the verifier can detect forks when given both branches.

**Anchoring:** Console batches ≤ 5 min of new checkpoint hashes into a batch Merkle root → RFC 3161 request (SHA-256 digest) → token stored with inclusion proofs per checkpoint. Daily: consolidated root over the day's batch roots → **eIDAS qualified timestamp** from a QTSP (`ADR-007`) → token stored; same daily root published externally (`ADR-015`: public transparency mechanism; interim: signed publication at `https://anchors.sealr.example` + mirrored to a public git repo). Hybrid customers MAY add their own TSA; tokens accumulate — more anchors never invalidate a bundle.

## 9. Verification procedure (normative for `sealr-verify`)

Given a bundle, the verifier MUST:
1. Parse manifest; check schema versions.
2. Validate certificate chain(s) to a trusted root (embedded release roots, `--root` override, or bundle-pinned root with explicit warning).
3. Apply revocation list; compute validity windows.
4. Verify every record hash + chain linkage + seq/clock rules (§4–5) per stream.
5. Verify every CheckpointNote signature; verify Merkle roots by recomputation; verify Console countersignatures if present.
6. Verify RFC 3161 tokens (against bundled TSA certs) and QTS tokens; bind each covered checkpoint to its earliest proven time.
7. Cross-check coverage: report unanchored tails, segments lacking clean end, coverage_gap records, revocation boundaries.
8. Output: human-readable report + machine JSON: `{result: pass|pass_with_findings|fail, findings[], proven: {records, span, earliest_anchor, streams}, limits[]}`.

The verifier MUST print, in every report, the standing limits: (a) tamper-evident not tamper-proof; (b) proves the recorded stream only; (c) time proven = anchor time (records are "no later than" anchor; "no earlier than" bounded by previous anchor + monotonic deltas); (d) subject attribution quality is as recorded (`attribution` field), not independently proven.

## 10. Bundle format `.seal`

Zip container (deterministic ordering, stored or zstd):

```
manifest.json          # bundle id, created_at, scope (streams, seq/time ranges), tool versions, content hashes
records/<stream>.ndjson# records in seq order (metadata-level or full, per export scope)
checkpoints/*.json     # CheckpointNotes + countersignatures
anchors/rfc3161/*.tsr  anchors/qts/*.der  anchors/proofs.json
identity/certs.pem  identity/revocations.json  identity/roots.json
vault/                 # optional, customer-side exports only: encrypted payloads + salts
VERIFY.md              # how to verify offline, verifier version pins
```

`manifest.json` is JCS-hashed and its hash printed by the exporter; exports > 2 GB shard `records/` with a shard index. Extension `.seal`; media type `application/vnd.sealr.bundle+zip` (`ADR-014` finalizes registration details).

## 11. Test vectors and conformance

The repo MUST publish (Apache-2.0, with the verifier): golden bundles (valid; each single-fault class: bad hash, reordered, gap, forged checkpoint, revoked key, bad TSA token, fork), and a conformance checklist for third-party implementations. CI runs the verifier against all vectors; property test: any single-byte mutation of any golden bundle ⇒ `fail` with the correct finding class (02 §11).

## 12. Versioning and migration

`schema_version` per record and per bundle; verifiers MUST support all published minor versions of a major; writers MUST emit exactly one version per segment. Breaking changes require a new major, a migration note in this document, and dual-emit support in the recorder for ≥ 2 minor releases.
