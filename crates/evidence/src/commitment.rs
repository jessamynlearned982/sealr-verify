//! Salted payload commitments (doc 03 §6).
//!
//! `commitment = BLAKE3(salt || payload_bytes)` with a 32-byte random salt.
//! The salt travels with the payload (vault) or is discarded in
//! `commitment_only` mode — never stored in the record. Without the salt the
//! commitment reveals nothing practical about low-entropy payloads; with the
//! payload + salt anyone can prove the payload matches the record.

use rand::RngCore;

use crate::hash::{blake3_hex, hex_decode, hex_encode};
use crate::record::PayloadCommitment;

/// Commitment algorithm identifier for v1.
pub const COMMITMENT_ALG: &str = "blake3-salted";

/// A 32-byte commitment salt.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt(pub [u8; 32]);

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print salt material.
        f.write_str("Salt(..)")
    }
}

impl Salt {
    /// Generate a random salt from the OS RNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Hex encoding (for vault storage alongside the payload).
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Decode from hex.
    pub fn from_hex(hex: &str) -> crate::error::Result<Self> {
        let v = hex_decode("salt", hex)?;
        let arr: [u8; 32] =
            v.try_into()
                .map_err(|v: Vec<u8>| crate::error::EvidenceError::InvalidHex {
                    field: "salt",
                    detail: format!("expected 32 bytes, got {}", v.len()),
                })?;
        Ok(Self(arr))
    }
}

/// Compute a commitment over payload bytes with the given salt.
pub fn commit(payload: &[u8], salt: &Salt) -> PayloadCommitment {
    let mut input = Vec::with_capacity(32 + payload.len());
    input.extend_from_slice(&salt.0);
    input.extend_from_slice(payload);
    PayloadCommitment {
        alg: COMMITMENT_ALG.to_string(),
        commitment: blake3_hex(&input),
    }
}

/// Selective disclosure check: does `payload` + `salt` match `commitment`?
pub fn verify_commitment(payload: &[u8], salt: &Salt, commitment: &PayloadCommitment) -> bool {
    commitment.alg == COMMITMENT_ALG && commit(payload, salt).commitment == commitment.commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_round_trip() {
        let salt = Salt::random();
        let c = commit(b"DELETE FROM users", &salt);
        assert!(verify_commitment(b"DELETE FROM users", &salt, &c));
        assert!(!verify_commitment(b"DELETE FROM other", &salt, &c));
        assert!(!verify_commitment(
            b"DELETE FROM users",
            &Salt::random(),
            &c
        ));
    }

    #[test]
    fn same_payload_different_salt_different_commitment() {
        // No dictionary confirmation without the salt.
        let c1 = commit(b"SELECT 1", &Salt::random());
        let c2 = commit(b"SELECT 1", &Salt::random());
        assert_ne!(c1.commitment, c2.commitment);
    }

    #[test]
    fn salt_hex_round_trip() {
        let s = Salt::random();
        let restored = Salt::from_hex(&s.to_hex()).unwrap();
        assert_eq!(s, restored);
    }
}
