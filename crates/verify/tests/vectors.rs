//! Conformance test (doc 03 §11): the verifier must produce the expected result
//! and finding classes for every golden vector.
//!
//! This reads the vectors COMMITTED under testdata/vectors rather than
//! generating them. Two reasons, and the second is the important one:
//!
//!   * It is the same artefact a third party downloads, so this test proves
//!     what they can reproduce — not what a generator happens to emit today.
//!   * Generation lives in `sealr-devtools`, which is source-available rather
//!     than open source. Depending on it here would mean the verifier could not
//!     be built and tested from its own public repository, which is the whole
//!     point of publishing it.
//!
//! The generator has its own round-trip test in `crates/devtools`.

use std::fs::File;
use std::path::{Path, PathBuf};

use sealr_bundle::BundleReader;
use sealr_verify::{verify_bundle, VerifyOptions, VerifyResult};

#[derive(serde::Deserialize)]
struct Expectation {
    file: String,
    result: String,
    #[serde(default)]
    must_contain: Vec<String>,
}

/// testdata/ sits at the workspace root in the monorepo and beside the crate in
/// the published repository; accept either so one test serves both layouts.
fn vectors_dir() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        crate_dir.join("../../testdata/vectors"),
        crate_dir.join("../testdata/vectors"),
        crate_dir.join("testdata/vectors"),
    ] {
        if candidate.join("expected.json").is_file() {
            return candidate;
        }
    }
    panic!(
        "could not locate testdata/vectors relative to {}",
        crate_dir.display()
    );
}

fn load(dir: &Path) -> (Vec<Expectation>, VerifyOptions) {
    let raw = std::fs::read_to_string(dir.join("expected.json")).expect("expected.json");
    let expectations: Vec<Expectation> = serde_json::from_str(&raw).expect("parse expected.json");
    let root_pem = std::fs::read_to_string(dir.join("root.pem")).expect("root.pem");
    (
        expectations,
        VerifyOptions {
            root_pem_override: Some(root_pem),
            ..Default::default()
        },
    )
}

#[test]
fn all_golden_vectors_verify_as_expected() {
    let dir = vectors_dir();
    let (expectations, opts) = load(&dir);
    assert!(expectations.len() >= 8, "expected at least 8 vectors");

    for expected in &expectations {
        let path = dir.join(&expected.file);
        let file = File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", expected.file));
        let mut reader =
            BundleReader::open(file).unwrap_or_else(|e| panic!("read {}: {e}", expected.file));
        let report = verify_bundle(&mut reader, &opts);

        let got = match report.result {
            VerifyResult::Pass => "pass",
            VerifyResult::PassWithFindings => "pass_with_findings",
            VerifyResult::Fail => "fail",
        };
        assert_eq!(
            got, expected.result,
            "vector {}: expected {} but verifier said {}\nfindings: {:#?}",
            expected.file, expected.result, got, report.findings
        );
        for class in &expected.must_contain {
            assert!(
                report.findings.iter().any(|f| f.class == *class),
                "vector {}: missing expected finding class {class}\nfindings: {:#?}",
                expected.file,
                report.findings
            );
        }
        // Standing limits must be printed in every report (doc 03 §9).
        assert_eq!(
            report.limits.len(),
            sealr_verify::report::STANDING_LIMITS.len(),
            "standing limits must always be present"
        );
    }
}

#[test]
fn valid_vector_proves_anchoring() {
    let dir = vectors_dir();
    let (_, opts) = load(&dir);
    let file = File::open(dir.join("valid.seal")).expect("open valid");
    let mut reader = BundleReader::open(file).expect("read valid");
    let report = verify_bundle(&mut reader, &opts);

    assert_eq!(report.proven.attested_records, report.proven.records);
    assert_eq!(
        report.proven.anchored_records, report.proven.records,
        "every record in the valid vector is under an anchored checkpoint"
    );
    assert!(
        report.proven.earliest_anchor.is_some(),
        "TSA genTime must be extracted"
    );
}
