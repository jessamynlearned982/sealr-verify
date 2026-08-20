//! Hash-chain construction (writer side) and verification (doc 03 §4–5).

use serde_json::Value;
use ulid::Ulid;

use crate::error::{EvidenceError, Result};
use crate::record::{genesis_prev_hash, Record};

/// Wall-clock regression tolerance without an adjacent `clock_anomaly` record (±2 s).
pub const WALL_TOLERANCE_MS: i64 = 2_000;

// ---------------------------------------------------------------------------
// Writer side
// ---------------------------------------------------------------------------

/// Mutable chain head used by a writer (the recorder) to append records.
#[derive(Debug, Clone)]
pub struct ChainHead {
    stream_id: Ulid,
    /// Hash of the last appended record (or the genesis sentinel).
    head_hash: String,
    /// Sequence of the last appended record; `None` before the first record.
    last_seq: Option<u64>,
}

impl ChainHead {
    /// Start a brand-new stream (genesis).
    pub fn genesis(stream_id: Ulid) -> Self {
        Self {
            stream_id,
            head_hash: genesis_prev_hash(stream_id),
            last_seq: None,
        }
    }

    /// Resume from a persisted head (crash/restart recovery).
    pub fn resume(stream_id: Ulid, head_hash: String, last_seq: u64) -> Self {
        Self {
            stream_id,
            head_hash,
            last_seq: Some(last_seq),
        }
    }

    /// The sequence number the next record must carry.
    pub fn next_seq(&self) -> u64 {
        self.last_seq.map_or(0, |s| s + 1)
    }

    /// Current head hash.
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }

    pub fn stream_id(&self) -> Ulid {
        self.stream_id
    }

    /// Chain a record: sets `seq` and `prev_hash`, finalizes `record_hash`,
    /// and advances the head. The record's `stream_id` must match.
    pub fn append(&mut self, record: &mut Record) -> Result<()> {
        if record.stream_id != self.stream_id.to_string() {
            return Err(EvidenceError::Schema(format!(
                "record stream_id {} does not match chain stream {}",
                record.stream_id, self.stream_id
            )));
        }
        record.seq = self.next_seq();
        record.prev_hash.clone_from(&self.head_hash);
        let hash = record.finalize()?;
        self.head_hash = hash;
        self.last_seq = Some(record.seq);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Verifier side
// ---------------------------------------------------------------------------

/// Minimal view of a record extracted from raw JSON — verification is
/// schema-agnostic so records from future minor versions still chain-verify.
#[derive(Debug, Clone)]
pub struct RecordView {
    pub record_id: String,
    pub stream_id: String,
    pub segment_id: String,
    pub seq: u64,
    pub ts_wall: String,
    pub ts_mono_ns: u64,
    pub record_type: String,
    pub prev_hash: String,
    pub record_hash: String,
}

impl RecordView {
    /// Extract the chain-relevant fields from a raw record value.
    pub fn from_value(v: &Value) -> Result<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| EvidenceError::Schema("record must be a JSON object".into()))?;
        let s = |k: &str| -> Result<String> {
            obj.get(k)
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .ok_or_else(|| EvidenceError::Schema(format!("record missing string field {k:?}")))
        };
        let u = |k: &str| -> Result<u64> {
            obj.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| EvidenceError::Schema(format!("record missing u64 field {k:?}")))
        };
        Ok(Self {
            record_id: s("record_id")?,
            stream_id: s("stream_id")?,
            segment_id: s("segment_id")?,
            seq: u("seq")?,
            ts_wall: s("ts_wall")?,
            ts_mono_ns: u("ts_mono_ns")?,
            record_type: s("record_type")?,
            prev_hash: s("prev_hash")?,
            record_hash: s("record_hash")?,
        })
    }
}

/// Classification of chain findings (doc 03 §4–5; verifier output classes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "class")]
#[non_exhaustive]
pub enum ChainFinding {
    /// Recomputed record hash differs from the stored `record_hash`.
    RecordHashMismatch {
        seq: u64,
        expected: String,
        computed: String,
    },
    /// `prev_hash` does not link to the previous record.
    LinkBroken {
        seq: u64,
        expected: String,
        found: String,
    },
    /// Sequence not strictly +1 within a segment.
    SeqGapInSegment {
        segment_id: String,
        expected: u64,
        found: u64,
    },
    /// Sequence not strictly increasing across the stream.
    SeqNotMonotonic { prev: u64, found: u64 },
    /// Monotonic clock regressed within a segment.
    MonoRegression {
        seq: u64,
        prev_ns: u64,
        found_ns: u64,
    },
    /// Wall clock regressed beyond tolerance without an adjacent `clock_anomaly` record.
    WallRegression { seq: u64, delta_ms: i64 },
    /// First record of the stream does not use the genesis sentinel.
    GenesisViolation { found: String, expected: String },
    /// A segment opened with the segment-break sentinel (unrecoverable local head).
    SegmentBreak { segment_id: String, seq: u64 },
    /// Record belongs to a different stream than the one under verification.
    StreamMismatch { seq: u64, found_stream: String },
    /// `ts_wall` could not be parsed.
    BadWallTimestamp { seq: u64, value: String },
}

/// Streaming chain verifier for one stream. Feed records in file order;
/// findings accumulate instead of aborting so a verifier can report everything.
#[derive(Debug)]
pub struct StreamVerifier {
    stream_id: String,
    genesis: String,
    prev: Option<RecordView>,
    prev_wall_ms: Option<i64>,
    pub records_verified: u64,
}

impl StreamVerifier {
    pub fn new(stream_id: &str) -> Result<Self> {
        let ulid: Ulid = stream_id
            .parse()
            .map_err(|e| EvidenceError::Schema(format!("invalid stream_id {stream_id:?}: {e}")))?;
        Ok(Self {
            stream_id: stream_id.to_string(),
            genesis: genesis_prev_hash(ulid),
            prev: None,
            prev_wall_ms: None,
            records_verified: 0,
        })
    }

    /// Verify the next record (raw JSON value). Returns findings for this record.
    pub fn verify_next(&mut self, raw: &Value) -> Result<Vec<ChainFinding>> {
        let mut findings = Vec::new();
        let view = RecordView::from_value(raw)?;

        if view.stream_id != self.stream_id {
            findings.push(ChainFinding::StreamMismatch {
                seq: view.seq,
                found_stream: view.stream_id.clone(),
            });
        }

        // Hash correctness (schema-agnostic).
        let mut clone = raw.clone();
        let computed = Record::compute_hash_of_value(&mut clone)?;
        if computed != view.record_hash {
            findings.push(ChainFinding::RecordHashMismatch {
                seq: view.seq,
                expected: view.record_hash.clone(),
                computed,
            });
        }

        match &self.prev {
            None => {
                // First record seen: genesis, or a segment-break sentinel (partial export
                // starting mid-stream links to a real prior hash — the bundle manifest
                // declares the export scope; the verifier reports continuity separately).
                if view.seq == 0 && view.prev_hash != self.genesis {
                    findings.push(ChainFinding::GenesisViolation {
                        found: view.prev_hash.clone(),
                        expected: self.genesis.clone(),
                    });
                }
            }
            Some(prev) => {
                let same_segment = prev.segment_id == view.segment_id;
                if view.seq <= prev.seq {
                    findings.push(ChainFinding::SeqNotMonotonic {
                        prev: prev.seq,
                        found: view.seq,
                    });
                } else if same_segment && view.seq != prev.seq + 1 {
                    findings.push(ChainFinding::SeqGapInSegment {
                        segment_id: view.segment_id.clone(),
                        expected: prev.seq + 1,
                        found: view.seq,
                    });
                }
                if view.prev_hash != prev.record_hash {
                    // A new segment may legitimately open with the break sentinel.
                    let is_break = !same_segment && Self::is_segment_break(&view);
                    if is_break {
                        findings.push(ChainFinding::SegmentBreak {
                            segment_id: view.segment_id.clone(),
                            seq: view.seq,
                        });
                    } else {
                        findings.push(ChainFinding::LinkBroken {
                            seq: view.seq,
                            expected: prev.record_hash.clone(),
                            found: view.prev_hash.clone(),
                        });
                    }
                }
                if same_segment && view.ts_mono_ns < prev.ts_mono_ns {
                    findings.push(ChainFinding::MonoRegression {
                        seq: view.seq,
                        prev_ns: prev.ts_mono_ns,
                        found_ns: view.ts_mono_ns,
                    });
                }
                // Wall-clock monotonicity within tolerance (doc 03 §4).
                match (crate::record::parse_wall(&view.ts_wall), self.prev_wall_ms) {
                    (Ok(wall), Some(prev_ms)) => {
                        let ms = wall.timestamp_millis();
                        let delta = ms - prev_ms;
                        if delta < -WALL_TOLERANCE_MS
                            && view.record_type != "clock_anomaly"
                            && prev.record_type != "clock_anomaly"
                        {
                            findings.push(ChainFinding::WallRegression {
                                seq: view.seq,
                                delta_ms: delta,
                            });
                        }
                    }
                    (Err(_), _) => findings.push(ChainFinding::BadWallTimestamp {
                        seq: view.seq,
                        value: view.ts_wall.clone(),
                    }),
                    _ => {}
                }
            }
        }

        if let Ok(w) = crate::record::parse_wall(&view.ts_wall) {
            self.prev_wall_ms = Some(w.timestamp_millis());
        }
        self.prev = Some(view);
        self.records_verified += 1;
        Ok(findings)
    }

    fn is_segment_break(view: &RecordView) -> bool {
        let (Ok(stream), Ok(segment)) = (view.stream_id.parse(), view.segment_id.parse()) else {
            return false;
        };
        view.prev_hash == crate::record::segment_break_prev_hash(stream, segment)
    }

    /// The last verified record's hash (the stream head as seen so far).
    pub fn head(&self) -> Option<&str> {
        self.prev.as_ref().map(|p| p.record_hash.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests_support::sample_unchained;

    fn chained(n: u64) -> (Ulid, Vec<Record>) {
        let stream = Ulid::from_parts(7, 7);
        let mut head = ChainHead::genesis(stream);
        let mut out = Vec::new();
        for i in 0..n {
            let mut r = sample_unchained(stream, Ulid::from_parts(7, 8), i);
            head.append(&mut r).unwrap();
            out.push(r);
        }
        (stream, out)
    }

    fn verify_all(stream: Ulid, records: &[Record]) -> Vec<ChainFinding> {
        let mut v = StreamVerifier::new(&stream.to_string()).unwrap();
        let mut all = Vec::new();
        for r in records {
            let raw = serde_json::to_value(r).unwrap();
            all.extend(v.verify_next(&raw).unwrap());
        }
        all
    }

    #[test]
    fn clean_chain_verifies() {
        let (stream, records) = chained(50);
        assert!(verify_all(stream, &records).is_empty());
    }

    #[test]
    fn tampered_field_detected() {
        let (stream, mut records) = chained(10);
        records[4].action.target_resource = "db:tampered".to_string();
        let findings = verify_all(stream, &records);
        assert!(findings
            .iter()
            .any(|f| matches!(f, ChainFinding::RecordHashMismatch { seq: 4, .. })));
    }

    #[test]
    fn deleted_record_detected() {
        let (stream, mut records) = chained(10);
        records.remove(5);
        let findings = verify_all(stream, &records);
        assert!(findings.iter().any(|f| matches!(
            f,
            ChainFinding::LinkBroken { seq: 6, .. }
                | ChainFinding::SeqGapInSegment { found: 6, .. }
        )));
    }

    #[test]
    fn reordered_records_detected() {
        let (stream, mut records) = chained(10);
        records.swap(3, 4);
        let findings = verify_all(stream, &records);
        assert!(!findings.is_empty());
    }

    #[test]
    fn forged_tail_detected() {
        let (stream, mut records) = chained(5);
        // Re-finalize a forged record with correct hash but wrong linkage.
        let mut forged = records[4].clone();
        forged.seq = 5;
        forged.prev_hash = "ab".repeat(32);
        forged.finalize().unwrap();
        records.push(forged);
        let findings = verify_all(stream, &records);
        assert!(findings
            .iter()
            .any(|f| matches!(f, ChainFinding::LinkBroken { seq: 5, .. })));
    }

    #[test]
    fn genesis_rule_enforced() {
        let stream = Ulid::from_parts(7, 7);
        // seq 0 with a non-genesis prev_hash must be flagged.
        let mut r = sample_unchained(stream, Ulid::from_parts(7, 8), 0);
        r.seq = 0;
        r.prev_hash = "aa".repeat(32);
        r.finalize().unwrap();
        let findings = verify_all(stream, &[r]);
        assert!(findings
            .iter()
            .any(|f| matches!(f, ChainFinding::GenesisViolation { .. })));
    }
}
