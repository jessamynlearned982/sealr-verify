//! Anchor structures: RFC 3161 batches, daily consolidated roots, inclusion
//! proofs (doc 03 §8, ADR-003, ADR-015). Serialized as `anchors/proofs.json`.

use serde::{Deserialize, Serialize};

use sealr_evidence::hash::{hex_decode_digest, hex_encode};
use sealr_evidence::merkle;

/// One step of a stored Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProofStep {
    /// Sibling digest, lowercase hex.
    pub sibling: String,
    /// True when the sibling is the left child.
    pub left: bool,
}

impl StoredProofStep {
    pub fn to_step(&self) -> sealr_evidence::Result<merkle::ProofStep> {
        Ok(merkle::ProofStep {
            sibling: hex_decode_digest("proof.sibling", &self.sibling)?,
            sibling_on_left: self.left,
        })
    }

    pub fn from_step(step: &merkle::ProofStep) -> Self {
        Self {
            sibling: hex_encode(&step.sibling),
            left: step.sibling_on_left,
        }
    }
}

/// Inclusion of one checkpoint in a TSA batch tree.
///
/// Leaf definition (normative): leaf bytes = the 32-byte BLAKE3-256 digest of
/// the JCS bytes of the checkpoint's `note` (the same digest the recorder
/// signed). Batch root = RFC 6962-style BLAKE3 tree over those leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointInclusion {
    pub checkpoint_id: String,
    /// Lowercase hex of the leaf bytes (the checkpoint note digest).
    pub leaf: String,
    pub leaf_index: u64,
    pub tree_size: u64,
    pub proof: Vec<StoredProofStep>,
}

/// One anchoring batch: ≤ 5 minutes of checkpoint digests, one TSA token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorBatch {
    pub batch_id: String,
    pub created_at: String,
    /// BLAKE3 batch tree root, lowercase hex.
    pub root_blake3: String,
    /// SHA-256 of the raw 32-byte BLAKE3 root — the TSA messageImprint digest (ADR-003).
    pub root_sha256: String,
    /// Path within the bundle to the RFC 3161 token, e.g. `anchors/rfc3161/<batch_id>.tsr`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsr_file: Option<String>,
    /// Whether the TSA endpoint is an eIDAS qualified trust service (ADR-007).
    pub qualified: bool,
    pub checkpoints: Vec<CheckpointInclusion>,
}

/// Daily consolidated root over the day's batch roots (leaf = raw batch root),
/// published per ADR-015 and qualified-timestamped (doc 03 §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailyRoot {
    /// `YYYY-MM-DD` (UTC).
    pub day: String,
    pub root_blake3: String,
    pub root_sha256: String,
    /// Hash chain over the publication series (ADR-015).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_day_hash: Option<String>,
    /// Batch roots included, in order (lowercase hex).
    pub batch_roots: Vec<String>,
    /// Path to the qualified timestamp token when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qts_file: Option<String>,
    /// Console signature over the JCS of this structure minus `signature`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_key_id: Option<String>,
}

/// The `anchors/proofs.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AnchorProofs {
    #[serde(default)]
    pub batches: Vec<AnchorBatch>,
    #[serde(default)]
    pub daily: Vec<DailyRoot>,
}

/// Build a batch over checkpoint note digests (raw 32-byte leaves).
pub fn build_batch(
    batch_id: String,
    created_at: String,
    checkpoint_leaves: &[(String, [u8; 32])],
    qualified: bool,
) -> sealr_evidence::Result<AnchorBatch> {
    let leaves: Vec<[u8; 32]> = checkpoint_leaves.iter().map(|(_, d)| *d).collect();
    let root = merkle::merkle_root(&leaves);
    let root_sha256 = sealr_evidence::hash::sha256_hex(&root);
    let mut checkpoints = Vec::with_capacity(checkpoint_leaves.len());
    for (i, (id, digest)) in checkpoint_leaves.iter().enumerate() {
        let proof = merkle::inclusion_proof(&leaves, i)?;
        checkpoints.push(CheckpointInclusion {
            checkpoint_id: id.clone(),
            leaf: hex_encode(digest),
            leaf_index: i as u64,
            tree_size: leaves.len() as u64,
            proof: proof.iter().map(StoredProofStep::from_step).collect(),
        });
    }
    Ok(AnchorBatch {
        batch_id,
        created_at,
        root_blake3: hex_encode(&root),
        root_sha256,
        tsr_file: None,
        qualified,
        checkpoints,
    })
}

/// Verify a stored inclusion proof against a batch root.
pub fn verify_inclusion(
    inclusion: &CheckpointInclusion,
    root_blake3_hex: &str,
) -> sealr_evidence::Result<()> {
    let leaf = hex_decode_digest("inclusion.leaf", &inclusion.leaf)?;
    let root = hex_decode_digest("batch.root_blake3", root_blake3_hex)?;
    let proof: Vec<merkle::ProofStep> = inclusion
        .proof
        .iter()
        .map(StoredProofStep::to_step)
        .collect::<sealr_evidence::Result<_>>()?;
    merkle::verify_inclusion(
        &leaf,
        usize::try_from(inclusion.leaf_index).unwrap_or(usize::MAX),
        usize::try_from(inclusion.tree_size).unwrap_or(usize::MAX),
        &proof,
        &root,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealr_evidence::hash::blake3_raw;

    #[test]
    fn batch_inclusion_round_trip() {
        let leaves: Vec<(String, [u8; 32])> = (0..7)
            .map(|i| {
                (
                    format!("cp-{i}"),
                    blake3_raw(format!("note-{i}").as_bytes()),
                )
            })
            .collect();
        let batch = build_batch(
            "b1".into(),
            "2026-08-11T12:00:00.000Z".into(),
            &leaves,
            false,
        )
        .unwrap();
        for inc in &batch.checkpoints {
            verify_inclusion(inc, &batch.root_blake3).unwrap();
        }
        // Tampered leaf fails.
        let mut bad = batch.checkpoints[2].clone();
        bad.leaf = "00".repeat(32);
        assert!(verify_inclusion(&bad, &batch.root_blake3).is_err());
    }
}
