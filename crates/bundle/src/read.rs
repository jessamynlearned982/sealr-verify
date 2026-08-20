//! `.seal` bundle reader.

use std::io::{BufRead, BufReader, Read, Seek};

use zip::ZipArchive;

use sealr_evidence::hash::blake3_hex;

use crate::anchors::AnchorProofs;
use crate::error::{BundleError, Result};
use crate::manifest::Manifest;
use crate::types::{BundleIdentity, RecordIndex, RootsFile, StreamCheckpoints};

/// Reader over a bundle from any `Read + Seek` source.
pub struct BundleReader<R: Read + Seek> {
    zip: ZipArchive<R>,
    manifest: Manifest,
}

impl<R: Read + Seek> std::fmt::Debug for BundleReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleReader")
            .field("bundle_id", &self.manifest.bundle_id)
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> BundleReader<R> {
    /// Open and parse the manifest.
    pub fn open(source: R) -> Result<Self> {
        let mut zip = ZipArchive::new(source)?;
        let manifest_bytes = read_entry(&mut zip, "manifest.json")?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| BundleError::Manifest(format!("manifest.json parse: {e}")))?;
        Ok(Self { zip, manifest })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Recompute the manifest's canonical JCS hash.
    pub fn manifest_hash(&self) -> Result<String> {
        Ok(self.manifest.jcs_hash()?)
    }

    /// Verify every entry's stored bytes against the manifest content hashes.
    /// Returns the list of entry paths present in the zip but not the manifest
    /// (excluding `manifest.json`) — those are reported, not fatal here.
    pub fn verify_content_hashes(&mut self) -> Result<Vec<String>> {
        for entry in &self.manifest.contents.clone() {
            let bytes = read_entry(&mut self.zip, &entry.path)?;
            let computed = blake3_hex(&bytes);
            if computed != entry.blake3 {
                return Err(BundleError::ContentHashMismatch {
                    path: entry.path.clone(),
                    expected: entry.blake3.clone(),
                    computed,
                });
            }
            if bytes.len() as u64 != entry.bytes {
                return Err(BundleError::Manifest(format!(
                    "entry {} size {} != manifest {}",
                    entry.path,
                    bytes.len(),
                    entry.bytes
                )));
            }
        }
        // Unlisted entries (anything not in the manifest) are suspicious.
        let listed: std::collections::HashSet<&str> = self
            .manifest
            .contents
            .iter()
            .map(|c| c.path.as_str())
            .collect();
        let mut unlisted = Vec::new();
        for i in 0..self.zip.len() {
            let name = self.zip.by_index(i)?.name().to_string();
            if name != "manifest.json" && !listed.contains(name.as_str()) && !name.ends_with('/') {
                unlisted.push(name);
            }
        }
        Ok(unlisted)
    }

    /// Parse `records/index.json`.
    pub fn record_index(&mut self) -> Result<RecordIndex> {
        let bytes = read_entry(&mut self.zip, "records/index.json")?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Stream one stream's record lines (without trailing newline) to `f`,
    /// in order across shards. Returns the number of lines.
    pub fn read_stream_records(
        &mut self,
        stream_id: &str,
        mut f: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        let index = self.record_index()?;
        let entry = index
            .streams
            .iter()
            .find(|s| s.stream_id == stream_id)
            .ok_or_else(|| BundleError::MissingEntry(format!("stream {stream_id} in index")))?
            .clone();
        let mut count = 0u64;
        for shard in &entry.shards {
            let file = self.zip.by_name(shard)?;
            let decoder = zstd::stream::Decoder::new(file).map_err(BundleError::Io)?;
            let mut reader = BufReader::new(decoder);
            let mut line = Vec::new();
            loop {
                line.clear();
                let n = reader.read_until(b'\n', &mut line)?;
                if n == 0 {
                    break;
                }
                let trimmed = if line.last() == Some(&b'\n') {
                    &line[..line.len() - 1]
                } else {
                    &line[..]
                };
                if trimmed.is_empty() {
                    continue;
                }
                f(trimmed)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Parse `checkpoints/<stream>.json` (missing file → empty set is an error;
    /// the verifier decides how to report absent checkpoints).
    pub fn stream_checkpoints(&mut self, stream_id: &str) -> Result<StreamCheckpoints> {
        let bytes = read_entry(&mut self.zip, &format!("checkpoints/{stream_id}.json"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Parse `anchors/proofs.json` (absent → empty).
    pub fn anchor_proofs(&mut self) -> Result<AnchorProofs> {
        match read_entry(&mut self.zip, "anchors/proofs.json") {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(BundleError::MissingEntry(_)) => Ok(AnchorProofs::default()),
            Err(e) => Err(e),
        }
    }

    /// Read a raw entry (e.g. an anchor token referenced from proofs.json).
    pub fn entry_bytes(&mut self, path: &str) -> Result<Vec<u8>> {
        read_entry(&mut self.zip, path)
    }

    /// Parse the identity directory.
    pub fn identity(&mut self) -> Result<BundleIdentity> {
        let certs_pem = String::from_utf8(read_entry(&mut self.zip, "identity/certs.pem")?)
            .map_err(|e| BundleError::Invalid(format!("identity/certs.pem not UTF-8: {e}")))?;
        let revocations = match read_entry(&mut self.zip, "identity/revocations.json") {
            Ok(bytes) => Some(serde_json::from_slice(&bytes)?),
            Err(BundleError::MissingEntry(_)) => None,
            Err(e) => return Err(e),
        };
        let roots: RootsFile =
            serde_json::from_slice(&read_entry(&mut self.zip, "identity/roots.json")?)?;
        Ok(BundleIdentity {
            certs_pem,
            revocations,
            roots,
        })
    }
}

fn read_entry<R: Read + Seek>(zip: &mut ZipArchive<R>, path: &str) -> Result<Vec<u8>> {
    let mut file = match zip.by_name(path) {
        Ok(f) => f,
        Err(zip::result::ZipError::FileNotFound) => {
            return Err(BundleError::MissingEntry(path.to_string()))
        }
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::with_capacity(usize::try_from(file.size()).unwrap_or(0));
    file.read_to_end(&mut out)?;
    Ok(out)
}
