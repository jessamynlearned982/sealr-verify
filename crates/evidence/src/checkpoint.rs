//! Checkpoints, countersignatures (doc 03 §8).

use serde::{Deserialize, Serialize};

use crate::error::{EvidenceError, Result};
use crate::hash::{hex_decode_digest, hex_encode};
use crate::keys::{SigningKey, VerifyingKey};
use crate::merkle;
use crate::record::Record;

/// Emit thresholds (FR-3.2): every ≤ 1,000 records or ≤ 10 s of activity.
pub const CHECKPOINT_MAX_RECORDS: u64 = 1_000;
pub const CHECKPOINT_MAX_INTERVAL_SECS: u64 = 10;

/// The signed statement binding a Merkle root over `[seq_from, seq_to]` and the
/// running chain head (doc 03 §8).
///
/// Checkpoints of a stream form their own hash chain through
/// `prev_checkpoint_hash`. Without it, removing an interior checkpoint (and the
/// records it covers) leaves a self-consistent set; with it, only the *tail*
/// of the checkpoint chain can be dropped — and a dropped tail is reported by
/// the verifier as `tail_completeness_unproven` unless an external attestation
/// (Console countersignature or timestamp anchor) bounds the stream extent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointNote {
    pub checkpoint_id: String,
    pub stream_id: String,
    pub segment_id: String,
    pub seq_from: u64,
    pub seq_to: u64,
    /// `record_hash` of the record at `seq_to` (the chain head at emit time).
    pub chain_head_hash: String,
    /// BLAKE3 RFC 6962-style root over the records' hashes in `[seq_from, seq_to]`.
    pub merkle_root: String,
    pub tree_size: u64,
    pub ts_wall: String,
    pub recorder_cert_fingerprint: String,
    /// BLAKE3-256 of JCS(previous checkpoint note) for this stream; absent only
    /// on a stream's first checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_checkpoint_hash: Option<String>,
}

impl CheckpointNote {
    /// The identity of this note for checkpoint-chain linking: BLAKE3-256 over
    /// its canonical JCS encoding.
    pub fn note_hash(&self) -> Result<String> {
        Ok(crate::hash::blake3_hex(&crate::jcs::struct_to_jcs_bytes(
            self,
        )?))
    }
}

/// A checkpoint note plus its recorder signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub note: CheckpointNote,
    /// Ed25519 over BLAKE3-256(JCS(note)), lowercase hex.
    pub signature: String,
}

/// Console countersignature statement (doc 03 §8).
///
/// `stream_high_water_seq` is the Console's authoritative view of how far the
/// stream had advanced when it countersigned. It is what makes tail truncation
/// *provable* rather than merely unproven: a bundle whose records stop below a
/// countersigned high-water is demonstrably incomplete, and the recorder-side
/// attacker cannot forge a lower value without the Console signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountersignatureNote {
    pub checkpoint_id: String,
    /// RFC 3339 UTC when the console accepted the checkpoint.
    pub received_at: String,
    pub console_key_id: String,
    /// Highest record seq the Console had accepted for this stream at that time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_high_water_seq: Option<u64>,
}

/// Countersignature note plus console signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Countersignature {
    pub note: CountersignatureNote,
    pub signature: String,
}

/// Compute the Merkle root (hex) over an ordered slice of record hashes (hex).
pub fn merkle_root_of_record_hashes(record_hashes_hex: &[String]) -> Result<String> {
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(record_hashes_hex.len());
    for h in record_hashes_hex {
        leaves.push(hex_decode_digest("record_hash", h)?);
    }
    Ok(hex_encode(&merkle::merkle_root(&leaves)))
}

/// Build a checkpoint note over a contiguous run of records.
///
/// `records` must be in seq order, non-empty, from one stream/segment.
/// `prev_checkpoint_hash` links this checkpoint to the stream's previous one
/// (`None` only for a stream's very first checkpoint).
pub fn build_note_linked(
    checkpoint_id: String,
    records: &[Record],
    ts_wall: String,
    recorder_cert_fingerprint: String,
    prev_checkpoint_hash: Option<String>,
) -> Result<CheckpointNote> {
    let mut note = build_note(checkpoint_id, records, ts_wall, recorder_cert_fingerprint)?;
    note.prev_checkpoint_hash = prev_checkpoint_hash;
    Ok(note)
}

/// Build an unlinked checkpoint note (first checkpoint of a stream, or tests).
pub fn build_note(
    checkpoint_id: String,
    records: &[Record],
    ts_wall: String,
    recorder_cert_fingerprint: String,
) -> Result<CheckpointNote> {
    let first = records
        .first()
        .ok_or_else(|| EvidenceError::Checkpoint("cannot checkpoint zero records".into()))?;
    let last = records.last().expect("non-empty");
    if u64::try_from(records.len()).ok() != last.seq.checked_sub(first.seq).map(|d| d + 1) {
        return Err(EvidenceError::Checkpoint(format!(
            "records not contiguous: {} entries for seq range [{}, {}]",
            records.len(),
            first.seq,
            last.seq
        )));
    }
    let hashes: Vec<String> = records.iter().map(|r| r.record_hash.clone()).collect();
    Ok(CheckpointNote {
        checkpoint_id,
        stream_id: first.stream_id.clone(),
        segment_id: first.segment_id.clone(),
        seq_from: first.seq,
        seq_to: last.seq,
        chain_head_hash: last.record_hash.clone(),
        merkle_root: merkle_root_of_record_hashes(&hashes)?,
        tree_size: hashes.len() as u64,
        ts_wall,
        recorder_cert_fingerprint,
        prev_checkpoint_hash: None,
    })
}

/// Sign a checkpoint note with the recorder identity key.
pub fn sign_note(note: CheckpointNote, key: &SigningKey) -> Result<SignedCheckpoint> {
    let signature = key.sign_jcs(&note)?;
    Ok(SignedCheckpoint { note, signature })
}

impl SignedCheckpoint {
    /// Verify the recorder signature.
    pub fn verify(&self, recorder_key: &VerifyingKey) -> Result<()> {
        recorder_key.verify_jcs(
            &self.note,
            &self.signature,
            &format!("checkpoint {}", self.note.checkpoint_id),
        )
    }

    /// Recompute and check the Merkle root against the covered records' hashes.
    pub fn verify_root(&self, record_hashes_hex: &[String]) -> Result<()> {
        if record_hashes_hex.len() as u64 != self.note.tree_size {
            return Err(EvidenceError::Checkpoint(format!(
                "checkpoint {} tree_size {} but {} record hashes supplied",
                self.note.checkpoint_id,
                self.note.tree_size,
                record_hashes_hex.len()
            )));
        }
        let root = merkle_root_of_record_hashes(record_hashes_hex)?;
        if root != self.note.merkle_root {
            return Err(EvidenceError::Checkpoint(format!(
                "checkpoint {}: recomputed merkle root {} != stored {}",
                self.note.checkpoint_id, root, self.note.merkle_root
            )));
        }
        match record_hashes_hex.last() {
            Some(last) if *last == self.note.chain_head_hash => Ok(()),
            Some(last) => Err(EvidenceError::Checkpoint(format!(
                "checkpoint {}: chain_head_hash {} != last covered record hash {}",
                self.note.checkpoint_id, self.note.chain_head_hash, last
            ))),
            None => Err(EvidenceError::Checkpoint("empty record hash set".into())),
        }
    }
}

impl Countersignature {
    /// Build and sign a countersignature with the console key.
    pub fn create(
        checkpoint_id: String,
        received_at: String,
        console_key_id: String,
        stream_high_water_seq: Option<u64>,
        key: &SigningKey,
    ) -> Result<Self> {
        let note = CountersignatureNote {
            checkpoint_id,
            received_at,
            console_key_id,
            stream_high_water_seq,
        };
        let signature = key.sign_jcs(&note)?;
        Ok(Self { note, signature })
    }

    /// Verify against the console verifying key.
    pub fn verify(&self, console_key: &VerifyingKey) -> Result<()> {
        console_key.verify_jcs(
            &self.note,
            &self.signature,
            &format!("countersignature for {}", self.note.checkpoint_id),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainHead;
    use crate::record::tests_support::sample_unchained;
    use ulid::Ulid;

    fn chained(n: u64) -> Vec<Record> {
        let stream = Ulid::from_parts(9, 9);
        let mut head = ChainHead::genesis(stream);
        (0..n)
            .map(|i| {
                let mut r = sample_unchained(stream, Ulid::from_parts(9, 10), i);
                head.append(&mut r).unwrap();
                r
            })
            .collect()
    }

    #[test]
    fn checkpoint_sign_verify_round_trip() {
        let records = chained(25);
        let key = SigningKey::generate();
        let note = build_note(
            Ulid::from_parts(2, 2).to_string(),
            &records,
            "2026-08-11T12:01:00.000Z".to_string(),
            "fp".to_string(),
        )
        .unwrap();
        let signed = sign_note(note, &key).unwrap();
        signed.verify(&key.verifying_key()).unwrap();
        let hashes: Vec<String> = records.iter().map(|r| r.record_hash.clone()).collect();
        signed.verify_root(&hashes).unwrap();
    }

    #[test]
    fn forged_signature_rejected() {
        let records = chained(5);
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let note = build_note(
            Ulid::from_parts(2, 3).to_string(),
            &records,
            "2026-08-11T12:01:00.000Z".to_string(),
            "fp".to_string(),
        )
        .unwrap();
        let signed = sign_note(note, &other).unwrap();
        assert!(signed.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn tampered_record_set_fails_root() {
        let records = chained(10);
        let key = SigningKey::generate();
        let note = build_note(
            Ulid::from_parts(2, 4).to_string(),
            &records,
            "2026-08-11T12:01:00.000Z".to_string(),
            "fp".to_string(),
        )
        .unwrap();
        let signed = sign_note(note, &key).unwrap();
        let mut hashes: Vec<String> = records.iter().map(|r| r.record_hash.clone()).collect();
        hashes[3] = "ee".repeat(32);
        assert!(signed.verify_root(&hashes).is_err());
    }

    #[test]
    fn non_contiguous_rejected() {
        let mut records = chained(10);
        records.remove(4);
        let err = build_note(
            Ulid::from_parts(2, 5).to_string(),
            &records,
            "2026-08-11T12:01:00.000Z".to_string(),
            "fp".to_string(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn countersignature_round_trip() {
        let console = SigningKey::generate();
        let cs = Countersignature::create(
            "cp-1".to_string(),
            "2026-08-11T12:02:00.000Z".to_string(),
            "console-key-1".to_string(),
            Some(41),
            &console,
        )
        .unwrap();
        cs.verify(&console.verifying_key()).unwrap();
        assert!(cs.verify(&SigningKey::generate().verifying_key()).is_err());
    }
}
