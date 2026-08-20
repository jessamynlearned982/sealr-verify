//! `sealr-verify` CLI (doc 05 §5).
//!
//! Exit codes: 0 pass · 10 `pass_with_findings` · 11 fail · 30 usage/config error.

use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use sealr_bundle::BundleReader;
use sealr_verify::{verify_bundle, VerifyOptions};

#[derive(Parser, Debug)]
#[command(
    name = "sealr-verify",
    version,
    about = "Offline verifier for Sealr (.seal) evidence bundles",
    long_about = "Verifies an Seal evidence bundle fully offline: hash chain integrity, Merkle \
roots, checkpoint signatures, console countersignatures, certificate chains, revocations, and \
RFC 3161 / eIDAS qualified timestamp tokens. No network access, no trust in Sealr servers."
)]
struct Args {
    /// Path to the .seal bundle.
    bundle: PathBuf,

    /// Trusted root certificate PEM (overrides embedded and bundle-pinned roots).
    #[arg(long)]
    root: Option<PathBuf>,

    /// Console verifying key (SPKI PEM) for countersignature verification.
    #[arg(long)]
    console_key: Option<PathBuf>,

    /// Pin a stream's authoritative extent, as `STREAM_ID=SEQ` (repeatable).
    ///
    /// A bundle alone cannot rule out tail truncation. Obtain the value out of
    /// band from `GET /v1/streams/{id}/integrity` (`max_seq`) and pass it here
    /// to make missing trailing records a hard failure.
    #[arg(long = "expect-high-water", value_name = "STREAM_ID=SEQ")]
    expect_high_water: Vec<String>,

    /// Emit the machine-readable JSON report instead of text.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let read_opt_file = |path: &Option<PathBuf>, what: &str| -> Result<Option<String>, String> {
        match path {
            None => Ok(None),
            Some(p) => std::fs::read_to_string(p)
                .map(Some)
                .map_err(|e| format!("cannot read {what} {}: {e}", p.display())),
        }
    };

    let root_pem_override = match read_opt_file(&args.root, "--root") {
        Ok(v) => v,
        Err(e) => return usage_error(&e),
    };
    let console_key_override = match read_opt_file(&args.console_key, "--console-key") {
        Ok(v) => v,
        Err(e) => return usage_error(&e),
    };

    let file = match File::open(&args.bundle) {
        Ok(f) => f,
        Err(e) => {
            return usage_error(&format!(
                "cannot open bundle {}: {e}",
                args.bundle.display()
            ))
        }
    };
    let mut reader = match BundleReader::open(file) {
        Ok(r) => r,
        Err(e) => return usage_error(&format!("not a readable .seal bundle: {e}")),
    };

    let mut expected_high_water = std::collections::HashMap::new();
    for spec in &args.expect_high_water {
        let Some((stream, seq)) = spec.split_once('=') else {
            eprintln!("--expect-high-water expects STREAM_ID=SEQ, got {spec:?}");
            return ExitCode::from(2);
        };
        let Ok(seq) = seq.trim().parse::<u64>() else {
            eprintln!("--expect-high-water: {seq:?} is not a sequence number");
            return ExitCode::from(2);
        };
        expected_high_water.insert(stream.trim().to_string(), seq);
    }

    let opts = VerifyOptions {
        root_pem_override,
        console_key_override,
        now_unix: None,
        expected_high_water,
    };
    let report = verify_bundle(&mut reader, &opts);

    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => return usage_error(&format!("report serialization failed: {e}")),
        }
    } else {
        print!("{}", report.render_text());
    }

    #[allow(clippy::cast_sign_loss)]
    ExitCode::from(report.exit_code() as u8)
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("sealr-verify: {msg}");
    ExitCode::from(30)
}
