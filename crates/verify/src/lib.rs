//! # sealr-verify — offline verifier for Seal evidence bundles
//!
//! Verifies chain integrity, Merkle roots, checkpoint signatures, console
//! countersignatures, certificate chains, revocations, and RFC 3161 / qualified
//! timestamp tokens — fully offline, without trusting Sealr's servers.
//!
//! License: Apache-2.0.

pub mod engine;
pub mod report;
pub mod tsa;

pub use engine::{verify_bundle, VerifyOptions, VERIFIER_VERSION};
pub use report::{Finding, Report, Severity, VerifyResult};
