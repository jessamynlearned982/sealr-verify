//! Verifier report model (doc 03 §9).

use serde::Serialize;

/// Overall verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyResult {
    Pass,
    PassWithFindings,
    Fail,
}

/// Finding severity: `Error` ⇒ fail; `Warning` ⇒ `pass_with_findings`; `Info` is reported only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// One verification finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine class, e.g. `record_hash_mismatch`, `anchor_invalid`.
    pub class: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// What the bundle proves, when it passes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Proven {
    pub records: u64,
    pub streams: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_to: Option<String>,
    /// Earliest anchor time covering any checkpoint (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_anchor: Option<String>,
    /// Records covered by at least one valid checkpoint.
    pub attested_records: u64,
    /// Records covered by at least one valid, anchored checkpoint.
    pub anchored_records: u64,
}

/// Standing limits — printed in EVERY report (doc 03 §9, normative).
pub const STANDING_LIMITS: [&str; 5] = [
    "Tamper-evident, not tamper-proof: this report proves integrity, ordering, timing, and origin of the recorded stream; it cannot prove that unrecorded events did not happen.",
    "Coverage is a deployment property: only operations that passed through a recorder are in this stream.",
    "Proven time comes from timestamp anchors: records are proven to exist no later than their earliest anchor; 'no earlier than' is bounded by the previous anchor and monotonic clock deltas.",
    "Subject attribution quality is as recorded (see each record's attribution field); it is not independently proven.",
    "Tail completeness is bounded, not proven: removing trailing records together with the checkpoints attesting them leaves a shorter, self-consistent chain. This report proves the stream reached at least the highest externally attested point; pass --expect-high-water STREAM=SEQ (from the Console's stream integrity endpoint) to make the true extent decidable.",
];

/// The full report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub result: VerifyResult,
    pub bundle_id: String,
    pub manifest_hash: String,
    pub tool: ToolVersions,
    pub proven: Proven,
    pub findings: Vec<Finding>,
    pub limits: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolVersions {
    pub verifier: String,
    pub bundle_schema: String,
}

impl Report {
    pub fn compute_result(findings: &[Finding]) -> VerifyResult {
        if findings.iter().any(|f| f.severity == Severity::Error) {
            VerifyResult::Fail
        } else if findings.iter().any(|f| f.severity == Severity::Warning) {
            VerifyResult::PassWithFindings
        } else {
            VerifyResult::Pass
        }
    }

    /// Process exit code (doc 05 §5): 0 pass, 10 `pass_with_findings`, 11 fail.
    pub fn exit_code(&self) -> i32 {
        match self.result {
            VerifyResult::Pass => 0,
            VerifyResult::PassWithFindings => 10,
            VerifyResult::Fail => 11,
        }
    }

    /// Human-readable rendering.
    pub fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let verdict = match self.result {
            VerifyResult::Pass => "PASS",
            VerifyResult::PassWithFindings => "PASS WITH FINDINGS",
            VerifyResult::Fail => "FAIL",
        };
        let _ = writeln!(
            out,
            "sealr-verify {} — bundle {}",
            self.tool.verifier, self.bundle_id
        );
        let _ = writeln!(out, "manifest hash (BLAKE3/JCS): {}", self.manifest_hash);
        let _ = writeln!(out, "\nRESULT: {verdict}\n");
        let _ = writeln!(
            out,
            "Proven: {} records across {} stream(s); {} attested by checkpoints; {} anchored.",
            self.proven.records,
            self.proven.streams,
            self.proven.attested_records,
            self.proven.anchored_records
        );
        if let (Some(from), Some(to)) = (&self.proven.span_from, &self.proven.span_to) {
            let _ = writeln!(out, "Recorded span: {from} .. {to}");
        }
        if let Some(anchor) = &self.proven.earliest_anchor {
            let _ = writeln!(out, "Earliest timestamp anchor: {anchor}");
        }
        if self.findings.is_empty() {
            let _ = writeln!(out, "\nFindings: none.");
        } else {
            let _ = writeln!(out, "\nFindings ({}):", self.findings.len());
            for f in &self.findings {
                let sev = match f.severity {
                    Severity::Error => "ERROR",
                    Severity::Warning => "WARN ",
                    Severity::Info => "INFO ",
                };
                let loc = match (&f.stream_id, f.seq) {
                    (Some(s), Some(q)) => format!(" [stream {s} seq {q}]"),
                    (Some(s), None) => format!(" [stream {s}]"),
                    _ => String::new(),
                };
                let _ = writeln!(out, "  {sev} {}{loc}: {}", f.class, f.message);
            }
        }
        let _ = writeln!(out, "\nStanding limits:");
        for l in &self.limits {
            let _ = writeln!(out, "  - {l}");
        }
        out
    }
}
