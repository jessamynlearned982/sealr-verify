//! Record schema v1 (doc 03 §3) and record hashing (doc 03 §4).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use crate::error::{EvidenceError, Result};
use crate::hash::blake3_hex;
use crate::jcs;

/// Current record schema version.
pub const SCHEMA_VERSION: &str = "1";

/// Sentinel prefix for the first record of a stream (doc 03 §5).
pub const GENESIS_PREFIX: &str = "SEALR-GENESIS";

/// Sentinel prefix for a segment whose predecessor's chain head is unrecoverable
/// (total local-state loss). Its use is itself a finding the verifier reports.
pub const SEGMENT_BREAK_PREFIX: &str = "SEALR-SEGMENT-BREAK";

/// Compute the genesis `prev_hash` for a stream: `BLAKE3("SEALR-GENESIS" || stream_id)`.
pub fn genesis_prev_hash(stream_id: Ulid) -> String {
    let mut input = GENESIS_PREFIX.as_bytes().to_vec();
    input.extend_from_slice(stream_id.to_string().as_bytes());
    blake3_hex(&input)
}

/// Compute the segment-break sentinel `prev_hash` for an unrecoverable chain head.
pub fn segment_break_prev_hash(stream_id: Ulid, segment_id: Ulid) -> String {
    let mut input = SEGMENT_BREAK_PREFIX.as_bytes().to_vec();
    input.extend_from_slice(stream_id.to_string().as_bytes());
    input.extend_from_slice(segment_id.to_string().as_bytes());
    blake3_hex(&input)
}

/// Record type enumeration (doc 03 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecordType {
    Operation,
    Outcome,
    Approval,
    PolicyEvent,
    Lifecycle,
    CoverageGap,
    GuardError,
    SpoolShed,
    ClockAnomaly,
    GenericExec,
}

/// Recorder identity block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecorderInfo {
    pub recorder_id: String,
    pub version: String,
    pub host_fingerprint: String,
    pub platform: String,
}

/// Attribution quality (FR-1.7). Never claim more than is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    Attributed,
    Inferred,
    Unattributed,
}

/// Subject block: who/what performed the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub agent_kind: String,
    pub agent_session: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_principal: Option<String>,
    pub attribution: Attribution,
    pub source: String,
}

/// Structural action block — no literals ever (FR-2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub integration: String,
    pub operation: String,
    pub verb_class: String,
    pub target_resource: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_labels: Vec<String>,
}

/// Salted payload commitment (doc 03 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadCommitment {
    /// Always `"blake3-salted"` in v1.
    pub alg: String,
    /// Lowercase hex BLAKE3-256 of `salt || payload_bytes`.
    pub commitment: String,
}

/// Vault reference for vaulted payloads (Ledger only, never in the Console projection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadRef {
    pub vault_url: String,
    /// Always `"aes-256-gcm"` in v1.
    pub enc: String,
    /// Names the wrapping key; never key material.
    pub key_ref: String,
}

/// Guard identity within a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardRef {
    pub name: String,
    pub version: String,
}

/// Verdict decisions (FR-4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Warn,
    RequireApproval,
    Block,
}

/// Risk classes (FR-4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

/// Enforcement mode of the binding that produced a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
    Enforce,
}

/// Verdict block (doc 03 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub decision: Decision,
    pub mode: Mode,
    pub risk_class: RiskClass,
    pub policy_version: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    pub guard: GuardRef,
    pub eval_ms: u64,
}

/// Reference to the approval record that released a held operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRef {
    pub approval_record_id: String,
}

/// Links between records (outcome → request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Links {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_record_id: Option<String>,
}

/// One evidence record (doc 03 §3).
///
/// Optionality clarification (normative, reflected in the format spec):
/// `payload_commitment` and `verdict` are present on `operation`, `outcome`, and
/// `generic_exec` records; lifecycle/gap/policy records omit fields that do not
/// apply. `record_hash` is always the BLAKE3-256 of the JCS form of the record
/// with `record_hash` removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: String,
    pub record_id: String,
    pub stream_id: String,
    pub segment_id: String,
    pub seq: u64,
    /// RFC 3339 UTC with milliseconds, e.g. `2026-08-11T12:00:00.000Z`.
    pub ts_wall: String,
    pub ts_mono_ns: u64,
    pub record_type: RecordType,
    pub recorder: RecorderInfo,
    pub subject: Subject,
    pub action: Action,
    /// Structural detail that may be sensitive — Ledger only, never projected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_detail: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_commitment: Option<PayloadCommitment>,
    /// Ledger only, never projected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<PayloadRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<ApprovalRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
    pub prev_hash: String,
    pub record_hash: String,
}

impl Record {
    /// Compute the record hash: BLAKE3-256 of JCS(record without `record_hash`).
    pub fn compute_hash(&self) -> Result<String> {
        let mut v = serde_json::to_value(self)?;
        Self::compute_hash_of_value(&mut v)
    }

    /// Compute the record hash from a raw JSON value (schema-agnostic: works for
    /// records from future minor versions carrying unknown fields).
    pub fn compute_hash_of_value(v: &mut Value) -> Result<String> {
        let obj = v
            .as_object_mut()
            .ok_or_else(|| EvidenceError::Schema("record must be a JSON object".to_string()))?;
        obj.remove("record_hash");
        let bytes = jcs::to_jcs_bytes(v)?;
        Ok(blake3_hex(&bytes))
    }

    /// Finalize: compute and set `record_hash`. Returns the hash.
    pub fn finalize(&mut self) -> Result<String> {
        let h = self.compute_hash()?;
        self.record_hash.clone_from(&h);
        Ok(h)
    }

    /// Serialize to the canonical NDJSON line (JCS bytes + newline). This is the
    /// on-disk spool format (ADR-013) and the bundle record format.
    pub fn to_ndjson_line(&self) -> Result<Vec<u8>> {
        let v = serde_json::to_value(self)?;
        let mut bytes = jcs::to_jcs_bytes(&v)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Wall-clock formatting helper: RFC 3339 UTC with exactly millisecond precision.
pub fn format_wall(ts: chrono::DateTime<chrono::Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Parse a `ts_wall` value.
pub fn parse_wall(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| EvidenceError::Schema(format!("invalid ts_wall {s:?}: {e}")))
}

/// Test-support constructors shared across the workspace's test suites.
/// Enabled with the `test-support` feature (or `cfg(test)` within this crate).
#[cfg(any(test, feature = "test-support"))]
pub mod tests_support {
    use super::{
        Action, Attribution, Decision, GuardRef, Mode, PayloadCommitment, Record, RecordType,
        RecorderInfo, RiskClass, Subject, Verdict, SCHEMA_VERSION,
    };
    use ulid::Ulid;

    /// Build an unchained record (`seq/prev_hash/record_hash` left for `ChainHead::append`).
    pub fn sample_unchained(stream: Ulid, segment: Ulid, i: u64) -> Record {
        Record {
            schema_version: SCHEMA_VERSION.to_string(),
            record_id: Ulid::from_parts(i.wrapping_mul(1000).max(1), u128::from(i) + 1).to_string(),
            stream_id: stream.to_string(),
            segment_id: segment.to_string(),
            seq: 0,
            ts_wall: format!("2026-08-11T12:00:{:02}.000Z", i % 60),
            ts_mono_ns: i * 1_000_000,
            record_type: RecordType::Operation,
            recorder: RecorderInfo {
                recorder_id: Ulid::from_parts(1, 3).to_string(),
                version: "0.1.0".to_string(),
                host_fingerprint: "abc".to_string(),
                platform: "linux-x86_64".to_string(),
            },
            subject: Subject {
                agent_kind: "claude-code".to_string(),
                agent_session: "sess-1".to_string(),
                human_principal: Some("dev@example.com".to_string()),
                attribution: Attribution::Attributed,
                source: "oidc-hook".to_string(),
            },
            action: Action {
                integration: "sql".to_string(),
                operation: "query".to_string(),
                verb_class: "bounded_write".to_string(),
                target_resource: "db:prod-main".to_string(),
                resource_labels: vec!["env:prod".to_string()],
            },
            action_detail: None,
            payload_commitment: Some(PayloadCommitment {
                alg: "blake3-salted".to_string(),
                commitment: "00".repeat(32),
            }),
            payload_ref: None,
            verdict: Some(Verdict {
                decision: Decision::Allow,
                mode: Mode::Observe,
                risk_class: RiskClass::Medium,
                policy_version: 1,
                rule_ids: vec!["default".to_string()],
                reason_codes: vec![],
                guard: GuardRef {
                    name: "sql".to_string(),
                    version: "0.1.0".to_string(),
                },
                eval_ms: 2,
            }),
            approval_ref: None,
            links: None,
            prev_hash: String::new(),
            record_hash: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(seq: u64, prev_hash: String) -> Record {
        let mut r =
            tests_support::sample_unchained(Ulid::from_parts(1, 1), Ulid::from_parts(1, 2), seq);
        r.seq = seq;
        r.prev_hash = prev_hash;
        r.finalize().unwrap();
        r
    }

    #[test]
    fn hash_is_stable_and_excludes_itself() {
        let stream = Ulid::from_parts(1, 1);
        let r = sample_record(0, genesis_prev_hash(stream));
        let recomputed = r.compute_hash().unwrap();
        assert_eq!(r.record_hash, recomputed);
        // Mutating record_hash must not change the computed hash.
        let mut r2 = r.clone();
        r2.record_hash = "ff".repeat(32);
        assert_eq!(r2.compute_hash().unwrap(), recomputed);
    }

    #[test]
    fn any_field_mutation_changes_hash() {
        let stream = Ulid::from_parts(1, 1);
        let r = sample_record(0, genesis_prev_hash(stream));
        let baseline = r.compute_hash().unwrap();
        let mut m = r.clone();
        m.action.target_resource = "db:other".to_string();
        assert_ne!(m.compute_hash().unwrap(), baseline);
        let mut m = r.clone();
        m.seq = 1;
        assert_ne!(m.compute_hash().unwrap(), baseline);
        let mut m = r;
        m.subject.human_principal = None;
        assert_ne!(m.compute_hash().unwrap(), baseline);
    }

    #[test]
    fn decisions_and_risks_order() {
        assert!(Decision::Block > Decision::RequireApproval);
        assert!(Decision::RequireApproval > Decision::Warn);
        assert!(Decision::Warn > Decision::Allow);
        assert!(RiskClass::Critical > RiskClass::Low);
    }

    #[test]
    fn serde_round_trip_ndjson() {
        let stream = Ulid::from_parts(1, 1);
        let r = sample_record(3, genesis_prev_hash(stream));
        let line = r.to_ndjson_line().unwrap();
        let parsed: Record = serde_json::from_slice(&line).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn unknown_fields_rejected_by_typed_parse_but_hashable_raw() {
        let stream = Ulid::from_parts(1, 1);
        let r = sample_record(0, genesis_prev_hash(stream));
        let mut v = serde_json::to_value(&r).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("future_field".to_string(), serde_json::json!("x"));
        // Typed parse rejects (writers MUST reject unknown fields).
        assert!(serde_json::from_value::<Record>(v.clone()).is_err());
        // Raw hashing still works (verifiers of higher minors preserve-but-flag).
        let mut v2 = v.clone();
        let h = Record::compute_hash_of_value(&mut v2).unwrap();
        assert_eq!(h.len(), 64);
    }
}
