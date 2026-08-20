//! `ConsoleSafe` metadata projection (doc 02 §5 — normative allowlist).
//!
//! `ConsoleSafeRecord` is the ONLY record shape that may cross the customer
//! boundary toward the Console. It is a compile-time separated type: it has no
//! fields for `action_detail` or `payload_ref`, so literal-bearing data is
//! structurally impossible to project. All strings are sanitized (control
//! characters stripped, length-capped) against T8 (hostile recorded content).

use serde::{Deserialize, Serialize};

use crate::record::{
    Action, ApprovalRef, Links, PayloadCommitment, Record, RecordType, RecorderInfo, Subject,
    Verdict,
};

/// Maximum length of any projected string field.
pub const MAX_PROJECTED_STRING: usize = 512;
/// Maximum number of resource labels projected.
pub const MAX_PROJECTED_LABELS: usize = 32;

/// Sanitize a recorded string for projection: strip control characters
/// (including newlines — projected fields are single-line), cap length on a
/// char boundary, and append `…` when truncated.
pub fn sanitize(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_len));
    for c in s.chars() {
        if out.len() >= max_len {
            out.push('…');
            break;
        }
        if c.is_control() {
            continue;
        }
        out.push(c);
    }
    out
}

/// The `ConsoleSafe` projection of a record. Field-for-field mirror of the
/// `console: yes` rows of doc 03 §3 — nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleSafeRecord {
    pub schema_version: String,
    pub record_id: String,
    pub stream_id: String,
    pub segment_id: String,
    pub seq: u64,
    pub ts_wall: String,
    pub ts_mono_ns: u64,
    pub record_type: RecordType,
    pub recorder: RecorderInfo,
    pub subject: Subject,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_commitment: Option<PayloadCommitment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<ApprovalRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
    pub prev_hash: String,
    pub record_hash: String,
}

impl From<&Record> for ConsoleSafeRecord {
    fn from(r: &Record) -> Self {
        let s = |v: &str| sanitize(v, MAX_PROJECTED_STRING);
        Self {
            schema_version: r.schema_version.clone(),
            record_id: r.record_id.clone(),
            stream_id: r.stream_id.clone(),
            segment_id: r.segment_id.clone(),
            seq: r.seq,
            ts_wall: r.ts_wall.clone(),
            ts_mono_ns: r.ts_mono_ns,
            record_type: r.record_type,
            recorder: RecorderInfo {
                recorder_id: s(&r.recorder.recorder_id),
                version: s(&r.recorder.version),
                host_fingerprint: s(&r.recorder.host_fingerprint),
                platform: s(&r.recorder.platform),
            },
            subject: Subject {
                agent_kind: s(&r.subject.agent_kind),
                agent_session: s(&r.subject.agent_session),
                human_principal: r.subject.human_principal.as_deref().map(s),
                attribution: r.subject.attribution,
                source: s(&r.subject.source),
            },
            action: Action {
                integration: s(&r.action.integration),
                operation: s(&r.action.operation),
                verb_class: s(&r.action.verb_class),
                target_resource: s(&r.action.target_resource),
                resource_labels: r
                    .action
                    .resource_labels
                    .iter()
                    .take(MAX_PROJECTED_LABELS)
                    .map(|l| s(l))
                    .collect(),
            },
            payload_commitment: r.payload_commitment.clone(),
            verdict: r.verdict.clone(),
            approval_ref: r.approval_ref.clone(),
            links: r.links.clone(),
            prev_hash: r.prev_hash.clone(),
            record_hash: r.record_hash.clone(),
        }
    }
}

/// Compile-time guarantee exercised in tests: serializing a projection never
/// yields `action_detail` or `payload_ref` keys.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests_support::sample_unchained;
    use ulid::Ulid;

    #[test]
    fn projection_excludes_sensitive_fields_structurally() {
        let mut r = sample_unchained(Ulid::from_parts(1, 1), Ulid::from_parts(1, 2), 0);
        r.action_detail = Some(serde_json::json!({"where_skeleton": "email = <string>"}));
        r.payload_ref = Some(crate::record::PayloadRef {
            vault_url: "s3://bucket/key".to_string(),
            enc: "aes-256-gcm".to_string(),
            key_ref: "kms:key-1".to_string(),
        });
        r.finalize().unwrap();
        let proj = ConsoleSafeRecord::from(&r);
        let json = serde_json::to_string(&proj).unwrap();
        assert!(!json.contains("action_detail"));
        assert!(!json.contains("payload_ref"));
        assert!(!json.contains("vault_url"));
    }

    #[test]
    fn hostile_strings_sanitized() {
        let mut r = sample_unchained(Ulid::from_parts(1, 1), Ulid::from_parts(1, 2), 0);
        r.action.operation = "evil\r\nInject: header\u{0000}\u{001b}[31m".to_string();
        r.subject.agent_session = "x".repeat(2000);
        r.finalize().unwrap();
        let proj = ConsoleSafeRecord::from(&r);
        assert_eq!(proj.action.operation, "evilInject: header[31m");
        assert!(proj.subject.agent_session.chars().count() <= MAX_PROJECTED_STRING + 1);
        assert!(proj.subject.agent_session.ends_with('…'));
    }

    #[test]
    fn sanitize_respects_char_boundaries() {
        let s = "é".repeat(600);
        let out = sanitize(&s, MAX_PROJECTED_STRING);
        assert!(out.ends_with('…'));
        // Must not panic and must be valid UTF-8 (guaranteed by construction).
    }
}
