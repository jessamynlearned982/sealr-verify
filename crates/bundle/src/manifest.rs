//! Bundle manifest (doc 03 §10 / ADR-014).

use serde::{Deserialize, Serialize};

/// Export level: metadata-only (Console-side export) or full (customer-side,
/// may include vault entries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportLevel {
    Metadata,
    Full,
}

/// Per-stream scope of the export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamScope {
    pub stream_id: String,
    pub seq_from: u64,
    pub seq_to: u64,
    pub record_count: u64,
}

/// Overall export scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleScope {
    pub level: ExportLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    pub streams: Vec<StreamScope>,
}

/// One content entry: every zip entry except `manifest.json` itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentEntry {
    pub path: String,
    /// BLAKE3-256 of the stored (possibly compressed) entry bytes.
    pub blake3: String,
    pub bytes: u64,
}

/// Tool identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

/// The bundle manifest. JCS-hashed; the exporter prints the hash (ADR-014).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: String,
    pub bundle_id: String,
    pub created_at: String,
    pub tool: ToolInfo,
    pub scope: BundleScope,
    pub contents: Vec<ContentEntry>,
}

impl Manifest {
    /// JCS hash of the manifest (lowercase hex).
    pub fn jcs_hash(&self) -> sealr_evidence::Result<String> {
        let bytes = sealr_evidence::jcs::struct_to_jcs_bytes(self)?;
        Ok(sealr_evidence::hash::blake3_hex(&bytes))
    }
}
