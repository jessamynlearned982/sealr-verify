//! Error taxonomy for the evidence crate.

use thiserror::Error;

/// Errors produced while building, canonicalizing, signing, or verifying evidence.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    /// JCS canonicalization rejects non-integer or out-of-safe-range numbers (ADR-001).
    #[error("non-integer or unsafe number in signed structure: {0}")]
    UnsafeNumber(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid hex in field {field}: {detail}")]
    InvalidHex { field: &'static str, detail: String },

    #[error("record hash mismatch at seq {seq}: expected {expected}, computed {computed}")]
    RecordHashMismatch {
        seq: u64,
        expected: String,
        computed: String,
    },

    #[error("chain linkage broken at seq {seq}: prev_hash {found} does not match previous record hash {expected}")]
    ChainLinkageBroken {
        seq: u64,
        expected: String,
        found: String,
    },

    #[error("sequence violation at record {record_id}: expected seq {expected}, found {found}")]
    SequenceViolation {
        record_id: String,
        expected: u64,
        found: u64,
    },

    #[error("monotonic clock regression at seq {seq}: {prev_ns} -> {found_ns}")]
    MonotonicRegression {
        seq: u64,
        prev_ns: u64,
        found_ns: u64,
    },

    #[error("wall clock regression beyond tolerance at seq {seq}: {detail}")]
    WallClockRegression { seq: u64, detail: String },

    #[error("genesis rule violated for stream {stream_id}: {detail}")]
    GenesisViolation { stream_id: String, detail: String },

    #[error("signature invalid: {context}")]
    SignatureInvalid { context: String },

    #[error("key error: {0}")]
    Key(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("checkpoint invalid: {0}")]
    Checkpoint(String),

    #[error("merkle proof invalid: {0}")]
    MerkleProof(String),

    #[error("schema violation: {0}")]
    Schema(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, EvidenceError>;
