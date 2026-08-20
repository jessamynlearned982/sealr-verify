//! Deterministic `.seal` bundle writer (ADR-014).
//!
//! Canonical entry order: `records/` shards, `records/index.json`,
//! `checkpoints/`, `anchors/`, `identity/`, `vault/`, `VERIFY.md`,
//! `manifest.json` (last — it hashes every preceding entry). Entries are
//! `stored` (no zip compression) with fixed timestamps; record shards are
//! zstd-compressed payloads. Same scope + same tool version ⇒ byte-identical
//! bundle.

use std::io::{Cursor, Write};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use sealr_evidence::hash::blake3_hex;

use crate::anchors::AnchorProofs;
use crate::error::{BundleError, Result};
use crate::manifest::{BundleScope, ContentEntry, ExportLevel, Manifest, StreamScope, ToolInfo};
use crate::types::{
    BundleCheckpoint, RecordIndex, RecordIndexStream, RootsFile, StreamCheckpoints,
};

/// Reserved media type (ADR-014).
pub const MEDIA_TYPE: &str = "application/vnd.sealr.bundle+zip";

/// Bundle schema version.
pub const BUNDLE_SCHEMA_VERSION: &str = "1";

/// Uncompressed shard threshold (ADR-014: 512 MB).
pub const SHARD_SIZE_BYTES: u64 = 512 * 1024 * 1024;

/// zstd level for record shards — fixed for determinism.
const ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Records,
    Checkpoints,
    Anchors,
    Identity,
    Vault,
    Finished,
}

/// Streaming bundle writer over any `Write + Seek` target.
pub struct BundleWriter<W: Write + std::io::Seek> {
    zip: ZipWriter<W>,
    contents: Vec<ContentEntry>,
    index: RecordIndex,
    phase: Phase,
    tool: ToolInfo,
    bundle_id: String,
    created_at: String,
    shard_threshold: u64,
}

impl<W: Write + std::io::Seek> std::fmt::Debug for BundleWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleWriter")
            .field("bundle_id", &self.bundle_id)
            .field("entries", &self.contents.len())
            .finish_non_exhaustive()
    }
}

fn entry_options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644)
}

impl<W: Write + std::io::Seek> BundleWriter<W> {
    /// Create a writer. `bundle_id` and `created_at` come from the exporter so
    /// re-exports of the same scope can be made reproducible.
    pub fn new(target: W, bundle_id: String, created_at: String, tool: ToolInfo) -> Self {
        Self {
            zip: ZipWriter::new(target),
            contents: Vec::new(),
            index: RecordIndex::default(),
            phase: Phase::Records,
            tool,
            bundle_id,
            created_at,
            shard_threshold: SHARD_SIZE_BYTES,
        }
    }

    /// Override the shard threshold (tests).
    pub fn with_shard_threshold(mut self, bytes: u64) -> Self {
        self.shard_threshold = bytes;
        self
    }

    fn require_phase(&mut self, at_most: Phase, next: Phase) -> Result<()> {
        if self.phase > at_most {
            return Err(BundleError::Invalid(format!(
                "bundle writer phase error: cannot write {next:?} after {:?}",
                self.phase
            )));
        }
        self.phase = next;
        Ok(())
    }

    /// Write one raw entry, hashing stored bytes into the manifest.
    fn write_entry(&mut self, path: &str, bytes: &[u8]) -> Result<()> {
        self.zip.start_file(path, entry_options())?;
        self.zip.write_all(bytes)?;
        self.contents.push(ContentEntry {
            path: path.to_string(),
            blake3: blake3_hex(bytes),
            bytes: bytes.len() as u64,
        });
        Ok(())
    }

    /// Add one stream's records from an iterator of NDJSON lines (each line
    /// must include its trailing newline). Lines are the canonical JCS record
    /// bytes (ADR-013: the spool bytes are the bundle bytes).
    ///
    /// Returns the shard paths written.
    pub fn add_stream_records<I>(&mut self, stream_id: &str, lines: I) -> Result<RecordIndexStream>
    where
        I: IntoIterator<Item = Result<Vec<u8>>>,
    {
        self.require_phase(Phase::Records, Phase::Records)?;

        let mut shards: Vec<String> = Vec::new();
        let mut shard_buf: Vec<u8> = Vec::new();
        let mut shard_no: u32 = 1;
        let mut count: u64 = 0;
        let mut first_line: Option<Vec<u8>> = None;
        let mut last_line: Option<Vec<u8>> = None;

        let flush_shard = |writer: &mut Self,
                           buf: &mut Vec<u8>,
                           shard_no: u32,
                           shards: &mut Vec<String>|
         -> Result<()> {
            if buf.is_empty() {
                return Ok(());
            }
            let compressed = zstd::stream::encode_all(Cursor::new(&buf[..]), ZSTD_LEVEL)
                .map_err(BundleError::Io)?;
            let path = format!("records/{stream_id}.part-{shard_no:05}.ndjson.zst");
            writer.write_entry(&path, &compressed)?;
            shards.push(path);
            buf.clear();
            Ok(())
        };

        for line in lines {
            let line = line?;
            if first_line.is_none() {
                first_line = Some(line.clone());
            }
            last_line = Some(line.clone());
            shard_buf.extend_from_slice(&line);
            count += 1;
            if shard_buf.len() as u64 >= self.shard_threshold {
                flush_shard(self, &mut shard_buf, shard_no, &mut shards)?;
                shard_no += 1;
            }
        }
        flush_shard(self, &mut shard_buf, shard_no, &mut shards)?;

        if count == 0 {
            return Err(BundleError::Invalid(format!(
                "stream {stream_id}: cannot export zero records"
            )));
        }

        let seq_of = |line: &[u8]| -> Result<u64> {
            let v: serde_json::Value = serde_json::from_slice(line)?;
            v.get("seq")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    BundleError::Invalid(format!("stream {stream_id}: record line missing seq"))
                })
        };
        let entry = RecordIndexStream {
            stream_id: stream_id.to_string(),
            shards,
            seq_from: seq_of(first_line.as_deref().expect("count>0"))?,
            seq_to: seq_of(last_line.as_deref().expect("count>0"))?,
            record_count: count,
        };
        self.index.streams.push(entry.clone());
        Ok(entry)
    }

    /// Write `checkpoints/<stream>.json`. Closes the records phase on first call.
    pub fn add_stream_checkpoints(
        &mut self,
        stream_id: &str,
        checkpoints: Vec<BundleCheckpoint>,
    ) -> Result<()> {
        if self.phase == Phase::Records {
            self.finish_records()?;
        }
        self.require_phase(Phase::Checkpoints, Phase::Checkpoints)?;
        let doc = StreamCheckpoints {
            stream_id: stream_id.to_string(),
            checkpoints,
        };
        let bytes = serde_json::to_vec_pretty(&doc)?;
        self.write_entry(&format!("checkpoints/{stream_id}.json"), &bytes)
    }

    fn finish_records(&mut self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.index)?;
        self.write_entry("records/index.json", &bytes)?;
        self.phase = Phase::Checkpoints;
        Ok(())
    }

    /// Write an RFC 3161 token (`anchors/rfc3161/<batch_id>.tsr`).
    pub fn add_rfc3161_token(&mut self, batch_id: &str, token_der: &[u8]) -> Result<()> {
        if self.phase == Phase::Records {
            self.finish_records()?;
        }
        self.require_phase(Phase::Anchors, Phase::Anchors)?;
        self.write_entry(&format!("anchors/rfc3161/{batch_id}.tsr"), token_der)
    }

    /// Write a qualified timestamp token (`anchors/qts/<day>.der`).
    pub fn add_qts_token(&mut self, day: &str, token_der: &[u8]) -> Result<()> {
        if self.phase == Phase::Records {
            self.finish_records()?;
        }
        self.require_phase(Phase::Anchors, Phase::Anchors)?;
        self.write_entry(&format!("anchors/qts/{day}.der"), token_der)
    }

    /// Write `anchors/proofs.json` (once, after tokens).
    pub fn add_anchor_proofs(&mut self, proofs: &AnchorProofs) -> Result<()> {
        if self.phase == Phase::Records {
            self.finish_records()?;
        }
        self.require_phase(Phase::Anchors, Phase::Anchors)?;
        let bytes = serde_json::to_vec_pretty(proofs)?;
        self.write_entry("anchors/proofs.json", &bytes)
    }

    /// Write the identity directory.
    pub fn add_identity(
        &mut self,
        certs_pem: &str,
        revocations: Option<&sealr_evidence::revocation::SignedRevocationList>,
        roots: &RootsFile,
    ) -> Result<()> {
        if self.phase == Phase::Records {
            self.finish_records()?;
        }
        self.require_phase(Phase::Anchors, Phase::Identity)?;
        self.write_entry("identity/certs.pem", certs_pem.as_bytes())?;
        if let Some(rev) = revocations {
            let bytes = serde_json::to_vec_pretty(rev)?;
            self.write_entry("identity/revocations.json", &bytes)?;
        }
        let bytes = serde_json::to_vec_pretty(roots)?;
        self.write_entry("identity/roots.json", &bytes)
    }

    /// Write an opaque vault entry (customer-side full exports only).
    pub fn add_vault_entry(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.require_phase(Phase::Vault, Phase::Vault)?;
        if name.contains("..") || name.starts_with('/') {
            return Err(BundleError::Invalid(format!(
                "invalid vault entry name {name:?}"
            )));
        }
        self.write_entry(&format!("vault/{name}"), bytes)
    }

    /// Finish: writes `VERIFY.md` and `manifest.json`, returns the manifest,
    /// its JCS hash, and the underlying target.
    pub fn finish(
        mut self,
        level: ExportLevel,
        ts_from: Option<String>,
        ts_to: Option<String>,
        resources: Vec<String>,
    ) -> Result<(Manifest, String, W)> {
        if self.phase == Phase::Records {
            self.finish_records()?;
        }
        let verify_md = verify_md_template(&self.tool);
        self.write_entry("VERIFY.md", verify_md.as_bytes())?;

        let streams = self
            .index
            .streams
            .iter()
            .map(|s| StreamScope {
                stream_id: s.stream_id.clone(),
                seq_from: s.seq_from,
                seq_to: s.seq_to,
                record_count: s.record_count,
            })
            .collect();

        let manifest = Manifest {
            schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: self.bundle_id.clone(),
            created_at: self.created_at.clone(),
            tool: self.tool.clone(),
            scope: BundleScope {
                level,
                ts_from,
                ts_to,
                resources,
                streams,
            },
            contents: self.contents.clone(),
        };
        let hash = manifest.jcs_hash()?;
        let manifest_bytes = sealr_evidence::jcs::struct_to_jcs_bytes(&manifest)?;
        self.zip.start_file("manifest.json", entry_options())?;
        self.zip.write_all(&manifest_bytes)?;
        self.phase = Phase::Finished;
        let target = self.zip.finish()?;
        Ok((manifest, hash, target))
    }
}

fn verify_md_template(tool: &ToolInfo) -> String {
    format!(
        "# Verifying this Seal bundle\n\n\
This is an Sealr evidence bundle (`{MEDIA_TYPE}`).\n\n\
To verify it offline, without contacting Sealr:\n\n\
```\nsealr-verify <this-file>.seal\n```\n\n\
The verifier is open source (Apache-2.0): https://github.com/sealr/sealr \n\
Verifier releases embed the Sealr root public keys; you may also pass\n\
`--root <pem>` to pin your own trusted root, and `--json` for machine output.\n\n\
The bundle manifest (`manifest.json`) lists the BLAKE3-256 hash of every entry.\n\
The manifest's own canonical hash is `BLAKE3-256(JCS(manifest.json))`; the\n\
exporter prints it at export time — compare it with the value communicated to\n\
you out of band.\n\n\
Standing limits (also printed by the verifier): Sealr evidence is\n\
tamper-evident, not tamper-proof; it proves integrity, ordering, timing, and\n\
origin of the recorded stream only; proven time comes from timestamp anchors;\n\
subject attribution quality is as recorded, not independently proven.\n\n\
Exported by {} {}.\n",
        tool.name, tool.version
    )
}
