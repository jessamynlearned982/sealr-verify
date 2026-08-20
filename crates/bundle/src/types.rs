//! Shared bundle document types (checkpoints file, record index, identity).

use serde::{Deserialize, Serialize};

use sealr_evidence::checkpoint::{Countersignature, SignedCheckpoint};
use sealr_evidence::revocation::SignedRevocationList;

/// One checkpoint plus its (optional) console countersignature, as stored in
/// `checkpoints/<stream>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleCheckpoint {
    pub checkpoint: SignedCheckpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub countersignature: Option<Countersignature>,
}

/// The `checkpoints/<stream>.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamCheckpoints {
    pub stream_id: String,
    pub checkpoints: Vec<BundleCheckpoint>,
}

/// One stream's shard listing in `records/index.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordIndexStream {
    pub stream_id: String,
    /// Shard entry paths, in read order.
    pub shards: Vec<String>,
    pub seq_from: u64,
    pub seq_to: u64,
    pub record_count: u64,
}

/// The `records/index.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RecordIndex {
    pub streams: Vec<RecordIndexStream>,
}

/// One trusted root in `identity/roots.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRoot {
    pub name: String,
    pub cert_pem: String,
}

/// The console signing key statement, attested by the root key (ADR-011).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleKeyStatement {
    pub key_id: String,
    /// SPKI PEM of the Ed25519 console verifying key.
    pub public_key_pem: String,
    pub not_before: String,
    pub not_after: String,
}

/// A console key plus (optionally) the root's Ed25519 signature over the
/// JCS bytes of the statement. Unattested keys are reported by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedConsoleKey {
    pub statement: ConsoleKeyStatement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Name of the root (in `roots`) whose key signed the statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_name: Option<String>,
}

/// The `identity/roots.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RootsFile {
    pub roots: Vec<TrustedRoot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub console_keys: Vec<AttestedConsoleKey>,
}

/// Parsed identity directory.
#[derive(Debug, Clone)]
pub struct BundleIdentity {
    /// All certificate PEM blocks (tenant CAs + recorder certs), concatenated.
    pub certs_pem: String,
    pub revocations: Option<SignedRevocationList>,
    pub roots: RootsFile,
}
