//! # Sealr evidence format — reference implementation
//!
//! Records, hash chains, checkpoints, signatures, commitments, identity
//! certificates, and the `ConsoleSafe` projection, per the published evidence
//! format specification (`docs/03-EVIDENCE-FORMAT-SPEC.md`).
//!
//! Honesty clause (normative): Sealr evidence is **tamper-evident, not
//! tamper-proof**. It proves integrity, ordering, timing, and origin of the
//! recorded stream; it cannot prove that unrecorded events did not happen.
//!
//! License: Apache-2.0 — third parties must be able to implement and verify
//! this format without Sealr.

pub mod certs;
pub mod chain;
pub mod checkpoint;
pub mod commitment;
pub mod error;
pub mod hash;
pub mod jcs;
pub mod keys;
pub mod merkle;
pub mod projection;
pub mod record;
pub mod revocation;

pub use error::{EvidenceError, Result};

#[cfg(test)]
mod proptests {
    //! Property tests over the chain/verifier invariants (doc 02 §11):
    //! any single-bit mutation of any record byte ⇒ verifier reports a finding.

    use proptest::prelude::*;
    use ulid::Ulid;

    use crate::chain::{ChainHead, StreamVerifier};
    use crate::record::tests_support::sample_unchained;
    use crate::record::Record;

    fn build_chain(n: u64) -> (Ulid, Vec<Record>) {
        let stream = Ulid::from_parts(42, 42);
        let mut head = ChainHead::genesis(stream);
        let records = (0..n)
            .map(|i| {
                let mut r = sample_unchained(stream, Ulid::from_parts(42, 43), i);
                head.append(&mut r).unwrap();
                r
            })
            .collect();
        (stream, records)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn any_single_bit_flip_is_detected(
            record_idx in 0usize..10,
            byte_pos in 0usize..200,
            bit in 0u8..8,
        ) {
            let (stream, records) = build_chain(10);
            // Serialize the chain to NDJSON, flip one bit inside one record line,
            // reparse, verify — a finding (or a parse failure) must result.
            let mut lines: Vec<Vec<u8>> = records
                .iter()
                .map(|r| r.to_ndjson_line().unwrap())
                .collect();
            let line = &mut lines[record_idx];
            let pos = byte_pos % (line.len() - 1); // avoid trailing newline
            line[pos] ^= 1 << bit;

            let mut verifier = StreamVerifier::new(&stream.to_string()).unwrap();
            let mut findings = 0usize;
            let mut parse_failures = 0usize;
            for line in &lines {
                match serde_json::from_slice::<serde_json::Value>(line) {
                    Ok(v) => {
                        match verifier.verify_next(&v) {
                            Ok(fs) => findings += fs.len(),
                            Err(_) => findings += 1, // structurally broken record = finding
                        }
                    }
                    Err(_) => parse_failures += 1,
                }
            }
            prop_assert!(
                findings > 0 || parse_failures > 0,
                "single-bit flip at record {record_idx} byte {pos} bit {bit} went undetected"
            );
        }

        #[test]
        fn round_trip_chain_always_verifies(n in 1u64..40) {
            let (stream, records) = build_chain(n);
            let mut verifier = StreamVerifier::new(&stream.to_string()).unwrap();
            for r in &records {
                let v = serde_json::to_value(r).unwrap();
                let findings = verifier.verify_next(&v).unwrap();
                prop_assert!(findings.is_empty(), "unexpected findings: {findings:?}");
            }
        }
    }
}
