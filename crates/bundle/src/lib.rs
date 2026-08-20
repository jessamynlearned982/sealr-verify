//! # `.seal` bundle — portable, self-contained evidence export
//!
//! Reference implementation of the Seal bundle container (doc 03 §10,
//! ADR-014): a deterministic zip holding records (NDJSON, zstd shards),
//! checkpoints with countersignatures, timestamp anchors with inclusion
//! proofs, the identity chain, and a JCS-hashed manifest.
//!
//! License: Apache-2.0.

pub mod anchors;
pub mod error;
pub mod manifest;
pub mod read;
pub mod types;
pub mod write;

pub use error::{BundleError, Result};
pub use manifest::{ExportLevel, Manifest};
pub use read::BundleReader;
pub use write::{BundleWriter, BUNDLE_SCHEMA_VERSION, MEDIA_TYPE};

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use sealr_evidence::chain::ChainHead;
    use sealr_evidence::checkpoint::{build_note, sign_note, Countersignature};
    use sealr_evidence::keys::SigningKey;
    use sealr_evidence::record::tests_support::sample_unchained;
    use ulid::Ulid;

    use super::manifest::{ExportLevel, ToolInfo};
    use super::types::{BundleCheckpoint, RootsFile, TrustedRoot};
    use super::*;

    fn tool() -> ToolInfo {
        ToolInfo {
            name: "sealr-export".into(),
            version: "0.1.0".into(),
        }
    }

    fn make_records(stream: Ulid, segment: Ulid, n: u64) -> Vec<sealr_evidence::record::Record> {
        let mut head = ChainHead::genesis(stream);
        (0..n)
            .map(|i| {
                let mut r = sample_unchained(stream, segment, i);
                head.append(&mut r).unwrap();
                r
            })
            .collect()
    }

    /// Build a complete bundle, returning (zip bytes, manifest hash).
    fn build_bundle(
        shard_threshold: u64,
        records: &[sealr_evidence::record::Record],
        sid: &str,
        with_checkpoint: bool,
    ) -> (Vec<u8>, String) {
        let mut writer = BundleWriter::new(
            Cursor::new(Vec::new()),
            Ulid::from_parts(11, 14).to_string(),
            "2026-08-11T13:00:00.000Z".into(),
            tool(),
        )
        .with_shard_threshold(shard_threshold);

        writer
            .add_stream_records(sid, records.iter().map(|r| Ok(r.to_ndjson_line().unwrap())))
            .unwrap();
        if with_checkpoint {
            let recorder_key = SigningKey::generate();
            let console_key = SigningKey::generate();
            let note = build_note(
                Ulid::from_parts(11, 13).to_string(),
                records,
                "2026-08-11T12:00:30.000Z".into(),
                "fp-test".into(),
            )
            .unwrap();
            let signed = sign_note(note, &recorder_key).unwrap();
            let cs = Countersignature::create(
                signed.note.checkpoint_id.clone(),
                "2026-08-11T12:00:31.000Z".into(),
                "console-1".into(),
                Some(signed.note.seq_to),
                &console_key,
            )
            .unwrap();
            writer
                .add_stream_checkpoints(
                    sid,
                    vec![BundleCheckpoint {
                        checkpoint: signed,
                        countersignature: Some(cs),
                    }],
                )
                .unwrap();
            writer
                .add_identity(
                    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                    None,
                    &RootsFile {
                        roots: vec![TrustedRoot {
                            name: "test-root".into(),
                            cert_pem: "PEM".into(),
                        }],
                        console_keys: vec![],
                    },
                )
                .unwrap();
        }
        let (manifest, hash, cursor) = writer
            .finish(ExportLevel::Metadata, None, None, vec![])
            .unwrap();
        assert_eq!(manifest.scope.streams.len(), 1);
        (cursor.into_inner(), hash)
    }

    #[test]
    fn reader_round_trip_with_shards() {
        let stream = Ulid::from_parts(21, 21);
        let records = make_records(stream, Ulid::from_parts(21, 22), 10);
        let sid = stream.to_string();
        // Tiny threshold forces multiple shards.
        let (bytes, hash) = build_bundle(200, &records, &sid, true);
        assert_eq!(hash.len(), 64);

        let mut reader = BundleReader::open(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.manifest().scope.streams[0].record_count, 10);
        assert_eq!(reader.manifest_hash().unwrap(), hash);
        let unlisted = reader.verify_content_hashes().unwrap();
        assert!(unlisted.is_empty());
        let index = reader.record_index().unwrap();
        assert!(
            index.streams[0].shards.len() > 1,
            "expected multiple shards"
        );

        let mut seen = Vec::new();
        let n = reader
            .read_stream_records(&sid, |line| {
                let v: serde_json::Value = serde_json::from_slice(line).unwrap();
                seen.push(v.get("seq").unwrap().as_u64().unwrap());
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 10);
        assert_eq!(seen, (0..10).collect::<Vec<u64>>());

        let cps = reader.stream_checkpoints(&sid).unwrap();
        assert_eq!(cps.checkpoints.len(), 1);
        let identity = reader.identity().unwrap();
        assert_eq!(identity.roots.roots[0].name, "test-root");
    }

    #[test]
    fn determinism_same_inputs_same_bytes() {
        let stream = Ulid::from_parts(31, 31);
        let records = make_records(stream, Ulid::from_parts(31, 32), 8);
        let sid = stream.to_string();
        // No checkpoints/identity: fresh signing keys would differ between builds.
        let (a, ha) = build_bundle(1_000_000, &records, &sid, false);
        let (b, hb) = build_bundle(1_000_000, &records, &sid, false);
        assert_eq!(
            a, b,
            "same scope + same tool version must be byte-identical"
        );
        assert_eq!(ha, hb);
    }

    #[test]
    fn tampered_entry_detected_by_content_hashes() {
        let stream = Ulid::from_parts(41, 41);
        let records = make_records(stream, Ulid::from_parts(41, 42), 5);
        let sid = stream.to_string();
        let (bytes, _) = build_bundle(1_000_000, &records, &sid, false);

        // Flip one byte inside the zip payload area (past the first local header).
        let mut tampered = bytes.clone();
        let pos = 200.min(tampered.len() - 1);
        tampered[pos] ^= 0x01;
        let Ok(mut reader) = BundleReader::open(Cursor::new(tampered)) else {
            return; // corrupted container structure = detected
        };
        assert!(reader.verify_content_hashes().is_err());
    }
}
