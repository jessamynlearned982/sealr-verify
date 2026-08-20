//! The offline verification engine (doc 03 §9, normative order).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek};

use sealr_bundle::anchors::AnchorProofs;
use sealr_bundle::types::{BundleCheckpoint, RootsFile};
use sealr_bundle::BundleReader;
use sealr_evidence::certs::{self, ValidatedCert};
use sealr_evidence::chain::{ChainFinding, StreamVerifier};
use sealr_evidence::hash::{blake3_raw, hex_decode_digest, sha256_hex};
use sealr_evidence::keys::VerifyingKey;
use sealr_evidence::revocation::SignedRevocationList;
use x509_parser::prelude::FromDer;

use crate::report::{Finding, Proven, Report, Severity, ToolVersions};
use crate::tsa;

/// Verifier version (embedded in reports).
pub const VERIFIER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Roots embedded at release time (empty in dev builds; a finding notes it).
pub const EMBEDDED_ROOTS_PEM: &str = include_str!("../roots/embedded-roots.pem");

/// Options for a verification run.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Trusted root certificate PEM override (`--root`).
    pub root_pem_override: Option<String>,
    /// Console verifying key override, SPKI PEM (`--console-key`).
    pub console_key_override: Option<String>,
    /// Verification wall time (unix seconds); defaults to now.
    pub now_unix: Option<i64>,
    /// Out-of-band stream extents (`--expect-high-water STREAM=SEQ`).
    ///
    /// Tail truncation cannot be ruled out from a bundle alone: cutting the end
    /// of a hash chain leaves a shorter, self-consistent chain. Pinning the
    /// Console's authoritative high-water mark (from
    /// `GET /v1/streams/{id}/integrity`) turns that into a decidable check —
    /// the same role `--root` plays for trust roots.
    pub expected_high_water: HashMap<String, u64>,
}

struct Ctx {
    findings: Vec<Finding>,
}

impl Ctx {
    fn add(&mut self, severity: Severity, class: &str, message: String) {
        self.findings.push(Finding {
            severity,
            class: class.to_string(),
            message,
            stream_id: None,
            seq: None,
        });
    }
    fn add_at(
        &mut self,
        severity: Severity,
        class: &str,
        message: String,
        stream: &str,
        seq: Option<u64>,
    ) {
        self.findings.push(Finding {
            severity,
            class: class.to_string(),
            message,
            stream_id: Some(stream.to_string()),
            seq,
        });
    }
}

/// Verify a bundle end to end. Never panics on malformed input; all problems
/// become findings (fatal structure problems yield an Error finding and stop
/// what cannot proceed).
pub fn verify_bundle<R: Read + Seek>(reader: &mut BundleReader<R>, opts: &VerifyOptions) -> Report {
    let mut ctx = Ctx {
        findings: Vec::new(),
    };
    let now_unix = opts
        .now_unix
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    let manifest = reader.manifest().clone();
    let manifest_hash = reader
        .manifest_hash()
        .unwrap_or_else(|_| "unavailable".to_string());

    // 1. Schema + container integrity.
    if manifest.schema_version != sealr_bundle::BUNDLE_SCHEMA_VERSION {
        ctx.add(
            Severity::Warning,
            "schema_version_unknown",
            format!(
                "bundle schema_version {:?} (verifier supports 1)",
                manifest.schema_version
            ),
        );
    }
    match reader.verify_content_hashes() {
        Ok(unlisted) => {
            for path in unlisted {
                ctx.add(
                    Severity::Error,
                    "unlisted_entry",
                    format!("entry {path:?} present in container but not in manifest"),
                );
            }
        }
        Err(e) => {
            ctx.add(Severity::Error, "content_hash_mismatch", e.to_string());
        }
    }

    // 2. Identity: roots, certificates, console keys, revocations.
    let identity = reader.identity().ok();
    let (root_pems, root_source) =
        select_roots(&mut ctx, opts, identity.as_ref().map(|i| &i.roots));
    let cert_map = build_cert_map(
        &mut ctx,
        identity.as_ref().map(|i| i.certs_pem.as_str()),
        &root_pems,
        now_unix,
    );
    let console_keys = resolve_console_keys(
        &mut ctx,
        opts,
        identity.as_ref().map(|i| &i.roots),
        &root_pems,
    );
    let revocations = identity.as_ref().and_then(|i| i.revocations.clone());
    if let Some(rev) = &revocations {
        let verified = console_keys.values().any(|k| rev.verify(k).is_ok());
        if !verified && !console_keys.is_empty() {
            ctx.add(
                Severity::Error,
                "revocation_list_signature_invalid",
                "revocation list signature does not verify with any known console key".into(),
            );
        } else if console_keys.is_empty() {
            ctx.add(
                Severity::Warning,
                "revocation_list_unverifiable",
                "revocation list present but no console key available to verify it".into(),
            );
        }
    }
    if !root_source.is_empty() {
        ctx.add(Severity::Info, "root_source", root_source);
    }

    // 3–4. Chain verification per stream; collect hashes and stats.
    let mut per_stream: BTreeMap<String, StreamData> = BTreeMap::new();
    for scope in &manifest.scope.streams {
        let data = verify_stream_chain(&mut ctx, reader, &scope.stream_id);
        per_stream.insert(scope.stream_id.clone(), data);
    }

    // 5. Checkpoints + countersignatures.
    for (stream_id, data) in &mut per_stream {
        let checkpoints = if let Ok(c) = reader.stream_checkpoints(stream_id) {
            c.checkpoints
        } else {
            ctx.add_at(
                Severity::Warning,
                "checkpoints_missing",
                "no checkpoints exported for stream".into(),
                stream_id,
                None,
            );
            continue;
        };
        verify_checkpoints(
            &mut ctx,
            stream_id,
            data,
            &checkpoints,
            &cert_map,
            revocations.as_ref(),
            &console_keys,
        );
        data.checkpoints = checkpoints;
    }

    // 6. Anchors.
    let proofs = reader.anchor_proofs().unwrap_or_default();
    let earliest_anchor = verify_anchors(&mut ctx, reader, &proofs, &mut per_stream, &console_keys);

    // 7. Coverage cross-checks.
    let mut proven = Proven::default();
    for (stream_id, data) in &per_stream {
        proven.records += data.hashes_by_seq.len() as u64;
        proven.streams += 1;
        proven.attested_records += data.attested_seqs.len() as u64;
        proven.anchored_records += data.anchored_seqs.len() as u64;
        if let (Some(min), Some(max)) = (data.ts_min.clone(), data.ts_max.clone()) {
            if proven.span_from.as_ref().is_none_or(|s| min < *s) {
                proven.span_from = Some(min);
            }
            if proven.span_to.as_ref().is_none_or(|s| max > *s) {
                proven.span_to = Some(max);
            }
        }
        let total = data.hashes_by_seq.len() as u64;
        let unattested = total.saturating_sub(data.attested_seqs.len() as u64);
        if unattested > 0 {
            ctx.add_at(
                Severity::Warning,
                "unattested_tail",
                format!("{unattested} record(s) not covered by any valid checkpoint"),
                stream_id,
                None,
            );
        }

        // --- Truncation defenses (doc 04 T1) -------------------------------
        // (a) A checkpoint pointing at an absent predecessor proves that an
        //     interior checkpoint (and the records it covered) was removed.
        for (cp_id, prev) in &data.checkpoint_links {
            if !data.checkpoint_note_hashes.contains(prev) {
                ctx.add_at(
                    Severity::Error,
                    "checkpoint_chain_broken",
                    format!(
                        "checkpoint {cp_id} references predecessor {prev} which is absent from the bundle: an earlier checkpoint and the records it attested were removed"
                    ),
                    stream_id,
                    None,
                );
            }
        }
        // (b) PROVEN truncation: either the operator pinned the Console's
        //     authoritative extent out of band, or a retained countersignature
        //     attests a high-water the bundle does not reach. The attacker
        //     cannot forge a lower value without the console signing key.
        let pinned = opts.expected_high_water.get(stream_id).copied();
        if let Some(hw) = pinned
            .into_iter()
            .chain(data.countersigned_high_water)
            .max()
        {
            let max_present = data.hashes_by_seq.keys().next_back().copied();
            if max_present.is_none_or(|m| m < hw) {
                ctx.add_at(
                    Severity::Error,
                    "truncation_detected",
                    format!(
                        "the Console countersigned that this stream had reached seq {hw}, but the bundle stops at seq {}: {} record(s) were removed from the end",
                        max_present.map_or_else(|| "nothing".to_string(), |m| m.to_string()),
                        hw - max_present.unwrap_or(0),
                    ),
                    stream_id,
                    None,
                );
            }
        }
        // (c) A hash chain can always be cut at the end and still verify as a
        //     shorter honest stream. Only an EXTERNAL attestation over the last
        //     checkpoint bounds the stream's extent. Say so explicitly rather
        //     than passing silently — the verifier must never imply that a
        //     tail-truncated bundle is complete.
        //     Completeness of the tail is never decidable from a bundle alone:
        //     cutting the end of a hash chain — records and their checkpoints
        //     together — leaves a shorter chain that is perfectly self-
        //     consistent. Only an out-of-band extent decides it. State the
        //     strongest floor the bundle does establish, and say plainly that
        //     nothing above it is proven.
        //     The universal caveat is a standing limit printed in every report.
        //     Warn only when the bundle establishes no external floor at all,
        //     i.e. nothing outside the recorder attests how far it ran.
        if pinned.is_none() && total > 0 && data.countersigned_high_water.is_none() {
            let detail = match &data.top_checkpoint {
                Some((cp_id, seq_to)) => format!(
                    "the last checkpoint ({cp_id}) covers up to seq {seq_to} but carries no console countersignature and no timestamp anchor"
                ),
                None => "the stream has no valid checkpoint at all".to_string(),
            };
            ctx.add_at(
                Severity::Warning,
                "tail_completeness_unproven",
                format!(
                    "no external attestation bounds this stream's extent: {detail}. Trailing records — together with the checkpoints attesting them — could have been removed leaving a self-consistent bundle. Re-run with --expect-high-water {stream_id}=<max_seq from GET /v1/streams/{stream_id}/integrity> to make the true extent decidable."
                ),
                stream_id,
                None,
            );
        }
        if data.coverage_gap_count > 0 {
            ctx.add_at(
                Severity::Warning,
                "coverage_gaps_recorded",
                format!(
                    "stream contains {} coverage_gap record(s)",
                    data.coverage_gap_count
                ),
                stream_id,
                None,
            );
        }
        for seg in &data.segments_without_end {
            ctx.add_at(
                Severity::Info,
                "segment_no_clean_end",
                format!(
                    "segment {seg} has no segment_end record (crash or still active at export)"
                ),
                stream_id,
                None,
            );
        }
    }
    proven.earliest_anchor = earliest_anchor;

    let findings = ctx.findings;
    let result = Report::compute_result(&findings);
    Report {
        result,
        bundle_id: manifest.bundle_id,
        manifest_hash,
        tool: ToolVersions {
            verifier: VERIFIER_VERSION.to_string(),
            bundle_schema: manifest.schema_version,
        },
        proven,
        findings,
        limits: crate::report::STANDING_LIMITS
            .iter()
            .map(ToString::to_string)
            .collect(),
    }
}

#[derive(Default)]
struct StreamData {
    hashes_by_seq: BTreeMap<u64, String>,
    ts_min: Option<String>,
    ts_max: Option<String>,
    coverage_gap_count: u64,
    segments_without_end: Vec<String>,
    checkpoints: Vec<BundleCheckpoint>,
    attested_seqs: HashSet<u64>,
    anchored_seqs: HashSet<u64>,
    /// `checkpoint_id` -> note digest (leaf bytes for anchor batches)
    checkpoint_digests: HashMap<String, [u8; 32]>,
    /// `checkpoint_id` -> (`seq_from`, `seq_to`) for valid checkpoints
    valid_checkpoint_ranges: HashMap<String, (u64, u64)>,
    /// Hex note hashes of every checkpoint present (targets of `prev_checkpoint_hash`).
    checkpoint_note_hashes: HashSet<String>,
    /// (`checkpoint_id`, `prev_checkpoint_hash`) links to resolve after the pass.
    checkpoint_links: Vec<(String, String)>,
    /// Checkpoints carrying a verified console countersignature.
    countersigned_checkpoints: HashSet<String>,
    /// Highest `stream_high_water_seq` asserted by a verified countersignature.
    countersigned_high_water: Option<u64>,
    /// The checkpoint with the highest `seq_to`, and that value.
    top_checkpoint: Option<(String, u64)>,
}

fn verify_stream_chain<R: Read + Seek>(
    ctx: &mut Ctx,
    reader: &mut BundleReader<R>,
    stream_id: &str,
) -> StreamData {
    let mut data = StreamData::default();
    let mut verifier = match StreamVerifier::new(stream_id) {
        Ok(v) => v,
        Err(e) => {
            ctx.add_at(
                Severity::Error,
                "stream_id_invalid",
                e.to_string(),
                stream_id,
                None,
            );
            return data;
        }
    };
    let mut segments_seen: Vec<String> = Vec::new();
    let mut segments_ended: HashSet<String> = HashSet::new();

    let result = reader.read_stream_records(stream_id, |line| {
        let value: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => {
                ctx.add_at(
                    Severity::Error,
                    "record_parse_error",
                    e.to_string(),
                    stream_id,
                    None,
                );
                return Ok(());
            }
        };
        let seq = value.get("seq").and_then(serde_json::Value::as_u64);
        match verifier.verify_next(&value) {
            Ok(findings) => {
                for f in findings {
                    let (class, msg) = classify_chain_finding(&f);
                    let sev = match f {
                        ChainFinding::SegmentBreak { .. } => Severity::Warning,
                        _ => Severity::Error,
                    };
                    ctx.add_at(sev, class, msg, stream_id, seq);
                }
            }
            Err(e) => {
                ctx.add_at(
                    Severity::Error,
                    "record_invalid",
                    e.to_string(),
                    stream_id,
                    seq,
                );
                return Ok(());
            }
        }
        // Stats + hash collection.
        if let (Some(seq), Some(hash)) = (
            seq,
            value.get("record_hash").and_then(serde_json::Value::as_str),
        ) {
            data.hashes_by_seq.insert(seq, hash.to_string());
        }
        if let Some(ts) = value.get("ts_wall").and_then(serde_json::Value::as_str) {
            if data.ts_min.as_deref().is_none_or(|m| ts < m) {
                data.ts_min = Some(ts.to_string());
            }
            if data.ts_max.as_deref().is_none_or(|m| ts > m) {
                data.ts_max = Some(ts.to_string());
            }
        }
        let rtype = value
            .get("record_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if rtype == "coverage_gap" {
            data.coverage_gap_count += 1;
        }
        if let Some(seg) = value.get("segment_id").and_then(serde_json::Value::as_str) {
            if segments_seen.last().map(String::as_str) != Some(seg) {
                segments_seen.push(seg.to_string());
            }
            if rtype == "lifecycle" {
                let op = value
                    .pointer("/action/operation")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if op == "segment_end" {
                    segments_ended.insert(seg.to_string());
                }
            }
        }
        Ok(())
    });
    if let Err(e) = result {
        ctx.add_at(
            Severity::Error,
            "stream_read_error",
            e.to_string(),
            stream_id,
            None,
        );
    }
    data.segments_without_end = segments_seen
        .into_iter()
        .filter(|s| !segments_ended.contains(s))
        .collect();
    data
}

fn classify_chain_finding(f: &ChainFinding) -> (&'static str, String) {
    match f {
        ChainFinding::RecordHashMismatch {
            seq,
            expected,
            computed,
        } => (
            "record_hash_mismatch",
            format!("record {seq}: stored hash {expected} but computed {computed}"),
        ),
        ChainFinding::LinkBroken {
            seq,
            expected,
            found,
        } => (
            "chain_link_broken",
            format!("record {seq}: prev_hash {found} does not match previous record {expected}"),
        ),
        ChainFinding::SeqGapInSegment {
            segment_id,
            expected,
            found,
        } => (
            "seq_gap",
            format!("segment {segment_id}: expected seq {expected}, found {found}"),
        ),
        ChainFinding::SeqNotMonotonic { prev, found } => {
            ("seq_not_monotonic", format!("seq {found} after {prev}"))
        }
        ChainFinding::MonoRegression {
            seq,
            prev_ns,
            found_ns,
        } => (
            "monotonic_regression",
            format!("record {seq}: monotonic clock went {prev_ns} -> {found_ns}"),
        ),
        ChainFinding::WallRegression { seq, delta_ms } => (
            "wall_clock_regression",
            format!("record {seq}: wall clock regressed {delta_ms} ms without clock_anomaly"),
        ),
        ChainFinding::GenesisViolation { found, expected } => (
            "genesis_violation",
            format!("first record prev_hash {found}, expected genesis {expected}"),
        ),
        ChainFinding::SegmentBreak { segment_id, seq } => (
            "segment_break",
            format!("segment {segment_id} opened at seq {seq} with an unrecoverable-head sentinel"),
        ),
        ChainFinding::StreamMismatch { seq, found_stream } => (
            "stream_mismatch",
            format!("record {seq} belongs to stream {found_stream}"),
        ),
        ChainFinding::BadWallTimestamp { seq, value } => (
            "bad_wall_timestamp",
            format!("record {seq}: unparseable ts_wall {value:?}"),
        ),
        other => ("chain_finding", format!("{other:?}")),
    }
}

fn select_roots(
    ctx: &mut Ctx,
    opts: &VerifyOptions,
    bundle_roots: Option<&RootsFile>,
) -> (Vec<String>, String) {
    if let Some(pem) = &opts.root_pem_override {
        return (
            vec![pem.clone()],
            "root source: --root override".to_string(),
        );
    }
    if !EMBEDDED_ROOTS_PEM.trim().is_empty() && EMBEDDED_ROOTS_PEM.contains("BEGIN CERTIFICATE") {
        return (
            vec![EMBEDDED_ROOTS_PEM.to_string()],
            "root source: embedded release roots".to_string(),
        );
    }
    if let Some(roots) = bundle_roots {
        if !roots.roots.is_empty() {
            ctx.add(
                Severity::Warning,
                "root_bundle_pinned",
                "no embedded or supplied root; trusting the bundle's own roots.json (a forged bundle could pin its own root — pass --root to pin an out-of-band root)"
                    .into(),
            );
            return (
                roots.roots.iter().map(|r| r.cert_pem.clone()).collect(),
                "root source: bundle-pinned (see root_bundle_pinned finding)".to_string(),
            );
        }
    }
    ctx.add(
        Severity::Error,
        "no_trust_root",
        "no trusted root available (bundle has none, none embedded, none supplied)".into(),
    );
    (Vec::new(), String::new())
}

/// fingerprint -> validated cert info.
type CertMap = HashMap<String, ValidatedCert>;

fn build_cert_map(
    ctx: &mut Ctx,
    certs_pem: Option<&str>,
    root_pems: &[String],
    now_unix: i64,
) -> CertMap {
    let mut map = CertMap::new();
    let Some(certs_pem) = certs_pem else {
        ctx.add(
            Severity::Warning,
            "identity_missing",
            "bundle has no identity/certs.pem".into(),
        );
        return map;
    };
    if root_pems.is_empty() {
        return map;
    }
    let root_pem = root_pems.join("\n");
    // Split the PEM into individual certificates; validate each against the pool.
    let Ok(ders) = certs::parse_pem_chain(certs_pem) else {
        ctx.add(
            Severity::Error,
            "identity_unparseable",
            "identity/certs.pem could not be parsed".into(),
        );
        return map;
    };
    let single_pems: Vec<String> = ders.iter().map(|der| der_to_pem(der)).collect();
    for pem in &single_pems {
        let intermediates: Vec<String> =
            single_pems.iter().filter(|p| *p != pem).cloned().collect();
        match certs::validate_chain(pem, &intermediates, &root_pem, now_unix) {
            Ok(validated) => {
                map.insert(validated.fingerprint.clone(), validated);
            }
            Err(e) => {
                // CA certs validate as their own leaf; failures here are reported once.
                ctx.add(
                    Severity::Warning,
                    "cert_unvalidated",
                    format!("a certificate in identity/certs.pem did not validate: {e}"),
                );
            }
        }
    }
    map
}

fn der_to_pem(der: &[u8]) -> String {
    use std::fmt::Write;
    let b64 = base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        let _ = writeln!(out, "{}", std::str::from_utf8(chunk).unwrap_or(""));
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn resolve_console_keys(
    ctx: &mut Ctx,
    opts: &VerifyOptions,
    bundle_roots: Option<&RootsFile>,
    root_pems: &[String],
) -> HashMap<String, VerifyingKey> {
    let mut keys = HashMap::new();
    if let Some(pem) = &opts.console_key_override {
        match VerifyingKey::from_spki_pem(pem) {
            Ok(k) => {
                keys.insert("override".to_string(), k);
            }
            Err(e) => ctx.add(
                Severity::Error,
                "console_key_invalid",
                format!("--console-key: {e}"),
            ),
        }
        return keys;
    }
    let Some(roots) = bundle_roots else {
        return keys;
    };

    // Root public keys (for statement attestation).
    let mut root_keys: Vec<VerifyingKey> = Vec::new();
    for pem in root_pems {
        if let Ok(ders) = certs::parse_pem_chain(pem) {
            for der in ders {
                if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&der) {
                    if let Ok(k) =
                        VerifyingKey::from_bytes(&cert.public_key().subject_public_key.data)
                    {
                        root_keys.push(k);
                    }
                }
            }
        }
    }

    for entry in &roots.console_keys {
        let key = match VerifyingKey::from_spki_pem(&entry.statement.public_key_pem) {
            Ok(k) => k,
            Err(e) => {
                ctx.add(
                    Severity::Warning,
                    "console_key_unparseable",
                    format!("console key {}: {e}", entry.statement.key_id),
                );
                continue;
            }
        };
        if let Some(sig) = &entry.signature {
            let attested = root_keys.iter().any(|rk| {
                rk.verify_jcs(&entry.statement, sig, "console key statement")
                    .is_ok()
            });
            if attested {
                keys.insert(entry.statement.key_id.clone(), key);
            } else {
                ctx.add(
                    Severity::Error,
                    "console_key_attestation_invalid",
                    format!(
                        "console key {} statement signature does not verify with any trusted root",
                        entry.statement.key_id
                    ),
                );
            }
        } else {
            ctx.add(
                Severity::Warning,
                "console_key_unattested",
                format!(
                    "console key {} is bundle-pinned without root attestation",
                    entry.statement.key_id
                ),
            );
            keys.insert(entry.statement.key_id.clone(), key);
        }
    }
    keys
}

fn verify_checkpoints(
    ctx: &mut Ctx,
    stream_id: &str,
    data: &mut StreamData,
    checkpoints: &[BundleCheckpoint],
    cert_map: &CertMap,
    revocations: Option<&SignedRevocationList>,
    console_keys: &HashMap<String, VerifyingKey>,
) {
    let mut ranges: Vec<(u64, u64, String, String)> = Vec::new(); // (from, to, root, id)
    for bc in checkpoints {
        let note = &bc.checkpoint.note;
        let cp_id = note.checkpoint_id.clone();
        if note.stream_id != stream_id {
            ctx.add_at(
                Severity::Error,
                "checkpoint_stream_mismatch",
                format!("checkpoint {cp_id} is for stream {}", note.stream_id),
                stream_id,
                None,
            );
            continue;
        }

        // Signature by the recorder certificate.
        let Some(cert) = cert_map.get(&note.recorder_cert_fingerprint) else {
            ctx.add_at(
                Severity::Error,
                "checkpoint_cert_unknown",
                format!(
                    "checkpoint {cp_id}: recorder certificate {} not in validated identity set",
                    note.recorder_cert_fingerprint
                ),
                stream_id,
                None,
            );
            continue;
        };
        if bc.checkpoint.verify(&cert.public_key).is_err() {
            ctx.add_at(
                Severity::Error,
                "checkpoint_signature_invalid",
                format!("checkpoint {cp_id}: recorder signature does not verify"),
                stream_id,
                None,
            );
            continue;
        }

        // Revocation boundary.
        if let (Some(rev), Ok(ts)) = (
            revocations,
            sealr_evidence::record::parse_wall(&note.ts_wall),
        ) {
            if rev.is_revoked_at(&note.recorder_cert_fingerprint, ts) {
                ctx.add_at(
                    Severity::Error,
                    "checkpoint_after_revocation",
                    format!(
                        "checkpoint {cp_id} signed at {} after certificate revocation",
                        note.ts_wall
                    ),
                    stream_id,
                    None,
                );
                continue;
            }
        }

        // Fork detection first: two validly signed checkpoints over the same
        // range with different roots is a fork regardless of record contents.
        for (from, to, root, other_id) in &ranges {
            let overlaps = note.seq_from <= *to && *from <= note.seq_to;
            if overlaps && (*from, *to) == (note.seq_from, note.seq_to) && *root != note.merkle_root
            {
                ctx.add_at(
                    Severity::Error,
                    "chain_fork_detected",
                    format!("checkpoints {other_id} and {cp_id} cover [{from}, {to}] with different roots"),
                    stream_id,
                    None,
                );
            }
        }
        ranges.push((
            note.seq_from,
            note.seq_to,
            note.merkle_root.clone(),
            cp_id.clone(),
        ));

        // Merkle root recomputation over covered records.
        let covered: Vec<String> = (note.seq_from..=note.seq_to)
            .map_while(|s| data.hashes_by_seq.get(&s).cloned())
            .collect();
        if covered.len() as u64 == note.seq_to - note.seq_from + 1 {
            if let Err(e) = bc.checkpoint.verify_root(&covered) {
                ctx.add_at(
                    Severity::Error,
                    "checkpoint_root_mismatch",
                    e.to_string(),
                    stream_id,
                    None,
                );
                continue;
            }
            for s in note.seq_from..=note.seq_to {
                data.attested_seqs.insert(s);
            }
        } else {
            ctx.add_at(
                Severity::Info,
                "checkpoint_range_not_fully_exported",
                format!(
                    "checkpoint {cp_id} covers [{}, {}] but the export does not contain the full range; root not recomputed",
                    note.seq_from, note.seq_to
                ),
                stream_id,
                None,
            );
        }

        // Countersignature.
        match &bc.countersignature {
            Some(cs) => {
                let ok = console_keys.values().any(|k| cs.verify(k).is_ok());
                if ok {
                    data.countersigned_checkpoints.insert(cp_id.clone());
                    // The Console's signed view of how far this stream had
                    // advanced. Keep the highest across all countersignatures.
                    if let Some(hw) = cs.note.stream_high_water_seq {
                        if data.countersigned_high_water.is_none_or(|c| hw > c) {
                            data.countersigned_high_water = Some(hw);
                        }
                    }
                } else if console_keys.is_empty() {
                    ctx.add_at(
                        Severity::Warning,
                        "countersignature_unverifiable",
                        format!(
                            "checkpoint {cp_id}: countersignature present but no console key available"
                        ),
                        stream_id,
                        None,
                    );
                } else {
                    ctx.add_at(
                        Severity::Error,
                        "countersignature_invalid",
                        format!("checkpoint {cp_id}: console countersignature does not verify"),
                        stream_id,
                        None,
                    );
                    continue;
                }
            }
            None => {
                ctx.add_at(
                    Severity::Info,
                    "not_countersigned",
                    format!("checkpoint {cp_id} has no console countersignature"),
                    stream_id,
                    None,
                );
            }
        }

        // Leaf digest for anchor batches.
        if let Ok(jcs) = sealr_evidence::jcs::struct_to_jcs_bytes(note) {
            data.checkpoint_digests
                .insert(cp_id.clone(), blake3_raw(&jcs));
        }
        // Checkpoint-chain bookkeeping (anti-truncation, doc 04 T1).
        if let Ok(h) = note.note_hash() {
            data.checkpoint_note_hashes.insert(h);
        }
        if let Some(prev) = &note.prev_checkpoint_hash {
            data.checkpoint_links.push((cp_id.clone(), prev.clone()));
        }
        if data
            .top_checkpoint
            .as_ref()
            .is_none_or(|(_, s)| note.seq_to > *s)
        {
            data.top_checkpoint = Some((cp_id.clone(), note.seq_to));
        }
        data.valid_checkpoint_ranges
            .insert(cp_id, (note.seq_from, note.seq_to));
    }
}

fn verify_anchors<R: Read + Seek>(
    ctx: &mut Ctx,
    reader: &mut BundleReader<R>,
    proofs: &AnchorProofs,
    per_stream: &mut BTreeMap<String, StreamData>,
    console_keys: &HashMap<String, VerifyingKey>,
) -> Option<String> {
    let mut earliest: Option<String> = None;

    for batch in &proofs.batches {
        // root_sha256 must bind to root_blake3 (ADR-003 dual digest).
        let Ok(root_raw) = hex_decode_digest("root_blake3", &batch.root_blake3) else {
            ctx.add(
                Severity::Error,
                "anchor_invalid",
                format!("batch {}: bad root_blake3", batch.batch_id),
            );
            continue;
        };
        if sha256_hex(&root_raw) != batch.root_sha256 {
            ctx.add(
                Severity::Error,
                "anchor_digest_binding_broken",
                format!(
                    "batch {}: root_sha256 does not equal SHA-256(root_blake3)",
                    batch.batch_id
                ),
            );
            continue;
        }

        // Inclusions: proof valid AND leaf equals the checkpoint's recomputed digest.
        let mut batch_checkpoints: Vec<(String, String)> = Vec::new(); // (stream, cp_id)
        for inc in &batch.checkpoints {
            if let Err(e) = sealr_bundle::anchors::verify_inclusion(inc, &batch.root_blake3) {
                ctx.add(
                    Severity::Error,
                    "anchor_inclusion_invalid",
                    format!(
                        "batch {}: checkpoint {}: {e}",
                        batch.batch_id, inc.checkpoint_id
                    ),
                );
                continue;
            }
            let mut found = false;
            for (stream_id, data) in per_stream.iter() {
                if let Some(digest) = data.checkpoint_digests.get(&inc.checkpoint_id) {
                    found = true;
                    let leaf = hex_decode_digest("inclusion.leaf", &inc.leaf).unwrap_or([0u8; 32]);
                    if &leaf == digest {
                        batch_checkpoints.push((stream_id.clone(), inc.checkpoint_id.clone()));
                    } else {
                        ctx.add(
                            Severity::Error,
                            "anchor_leaf_mismatch",
                            format!(
                                "batch {}: leaf for checkpoint {} does not match the checkpoint note digest",
                                batch.batch_id, inc.checkpoint_id
                            ),
                        );
                    }
                    break;
                }
            }
            if !found {
                ctx.add(
                    Severity::Info,
                    "anchor_checkpoint_not_in_export",
                    format!(
                        "batch {}: anchored checkpoint {} is not part of this export",
                        batch.batch_id, inc.checkpoint_id
                    ),
                );
            }
        }

        // TSA token.
        match &batch.tsr_file {
            Some(path) => {
                let sha: [u8; 32] = {
                    let Ok(v) = sealr_evidence::hash::hex_decode("root_sha256", &batch.root_sha256)
                    else {
                        continue;
                    };
                    match v.try_into() {
                        Ok(a) => a,
                        Err(_) => continue,
                    }
                };
                match reader.entry_bytes(path) {
                    Ok(bytes) => match tsa::verify_token(&bytes, &sha) {
                        Ok(token) => {
                            if earliest.as_ref().is_none_or(|e| token.gen_time < *e) {
                                earliest = Some(token.gen_time.clone());
                            }
                            for (stream_id, cp_id) in &batch_checkpoints {
                                if let Some(data) = per_stream.get_mut(stream_id) {
                                    if let Some((from, to)) =
                                        data.valid_checkpoint_ranges.get(cp_id).copied()
                                    {
                                        for s in from..=to {
                                            if data.attested_seqs.contains(&s) {
                                                data.anchored_seqs.insert(s);
                                            }
                                        }
                                    }
                                }
                            }
                            ctx.add(
                                Severity::Info,
                                "anchor_verified",
                                format!(
                                    "batch {} anchored at {} by {} ({})",
                                    batch.batch_id,
                                    token.gen_time,
                                    token.signer_subject,
                                    if batch.qualified {
                                        "recorded as qualified"
                                    } else {
                                        "not qualified"
                                    }
                                ),
                            );
                        }
                        Err(e) => {
                            ctx.add(
                                Severity::Error,
                                "anchor_invalid",
                                format!("batch {}: token verification failed: {e}", batch.batch_id),
                            );
                        }
                    },
                    Err(e) => {
                        ctx.add(
                            Severity::Error,
                            "anchor_token_missing",
                            format!("batch {}: {e}", batch.batch_id),
                        );
                    }
                }
            }
            None => {
                ctx.add(
                    Severity::Warning,
                    "anchor_pending",
                    format!("batch {} has no timestamp token yet", batch.batch_id),
                );
            }
        }
    }

    // Daily roots.
    for day in &proofs.daily {
        let Ok(leaves) = day
            .batch_roots
            .iter()
            .map(|h| hex_decode_digest("batch_root", h))
            .collect::<sealr_evidence::Result<Vec<[u8; 32]>>>()
        else {
            ctx.add(
                Severity::Error,
                "daily_root_invalid",
                format!("day {}: bad batch root hex", day.day),
            );
            continue;
        };
        let root = sealr_evidence::merkle::merkle_root(&leaves);
        if sealr_evidence::hash::hex_encode(&root) != day.root_blake3 {
            ctx.add(
                Severity::Error,
                "daily_root_mismatch",
                format!("day {}: recomputed daily root does not match", day.day),
            );
            continue;
        }
        if let (Some(sig), Some(_key_id)) = (&day.signature, &day.console_key_id) {
            let mut unsigned = day.clone();
            unsigned.signature = None;
            let ok = console_keys
                .values()
                .any(|k| k.verify_jcs(&unsigned, sig, "daily root").is_ok());
            if !ok && !console_keys.is_empty() {
                ctx.add(
                    Severity::Error,
                    "daily_root_signature_invalid",
                    format!("day {}: signature does not verify", day.day),
                );
            }
        }
        if let Some(qts) = &day.qts_file {
            let Ok(root_raw) = hex_decode_digest("daily.root_blake3", &day.root_blake3) else {
                continue;
            };
            let sha = sealr_evidence::hash::sha256_raw(&root_raw);
            match reader.entry_bytes(qts) {
                Ok(bytes) => match tsa::verify_token(&bytes, &sha) {
                    Ok(token) => {
                        if earliest.as_ref().is_none_or(|e| token.gen_time < *e) {
                            earliest = Some(token.gen_time.clone());
                        }
                        ctx.add(
                            Severity::Info,
                            "qts_verified",
                            format!(
                                "day {} qualified timestamp at {} by {}",
                                day.day, token.gen_time, token.signer_subject
                            ),
                        );
                    }
                    Err(e) => ctx.add(
                        Severity::Error,
                        "qts_invalid",
                        format!(
                            "day {}: qualified timestamp verification failed: {e}",
                            day.day
                        ),
                    ),
                },
                Err(e) => ctx.add(
                    Severity::Error,
                    "qts_token_missing",
                    format!("day {}: {e}", day.day),
                ),
            }
        }
    }

    earliest
}
