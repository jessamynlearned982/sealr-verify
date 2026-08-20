//! Bundle error taxonomy.

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BundleError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("evidence error: {0}")]
    Evidence(#[from] sealr_evidence::EvidenceError),

    #[error("manifest error: {0}")]
    Manifest(String),

    #[error(
        "bundle entry {path}: content hash mismatch (expected {expected}, computed {computed})"
    )]
    ContentHashMismatch {
        path: String,
        expected: String,
        computed: String,
    },

    #[error("missing bundle entry: {0}")]
    MissingEntry(String),

    #[error("invalid bundle: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, BundleError>;
