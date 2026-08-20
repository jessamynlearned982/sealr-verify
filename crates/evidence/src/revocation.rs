//! Signed recorder-certificate revocation list (doc 03 §7, FR-3.5).

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::keys::{SigningKey, VerifyingKey};

/// One revocation entry. Checkpoints signed by this certificate after
/// `effective_at` are invalid; the verifier reports the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    /// BLAKE3-256 fingerprint of the certificate DER, lowercase hex.
    pub cert_fingerprint: String,
    /// RFC 3339 UTC.
    pub effective_at: String,
    /// Machine-readable reason, e.g. "`key_compromise`", "decommissioned", "rotation".
    pub reason: String,
}

/// The revocation list document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    pub updated_at: String,
    #[serde(default)]
    pub revocations: Vec<RevocationEntry>,
}

/// Signed revocation list as published by the Console and embedded in bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocationList {
    pub list: RevocationList,
    pub console_key_id: String,
    /// Ed25519 over BLAKE3-256(JCS(list)), lowercase hex.
    pub signature: String,
}

impl SignedRevocationList {
    pub fn create(list: RevocationList, console_key_id: String, key: &SigningKey) -> Result<Self> {
        let signature = key.sign_jcs(&list)?;
        Ok(Self {
            list,
            console_key_id,
            signature,
        })
    }

    pub fn verify(&self, console_key: &VerifyingKey) -> Result<()> {
        console_key.verify_jcs(&self.list, &self.signature, "revocation list")
    }

    /// Is `cert_fingerprint` revoked at `at` (RFC 3339 compare on parsed times)?
    pub fn is_revoked_at(&self, cert_fingerprint: &str, at: chrono::DateTime<chrono::Utc>) -> bool {
        self.list.revocations.iter().any(|r| {
            r.cert_fingerprint == cert_fingerprint
                && crate::record::parse_wall(&r.effective_at).is_ok_and(|eff| at >= eff)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_boundary() {
        let key = SigningKey::generate();
        let list = RevocationList {
            updated_at: "2026-08-11T00:00:00.000Z".to_string(),
            revocations: vec![RevocationEntry {
                cert_fingerprint: "ab".repeat(32),
                effective_at: "2026-08-10T00:00:00.000Z".to_string(),
                reason: "key_compromise".to_string(),
            }],
        };
        let signed = SignedRevocationList::create(list, "k1".to_string(), &key).unwrap();
        signed.verify(&key.verifying_key()).unwrap();

        let before = crate::record::parse_wall("2026-08-09T00:00:00.000Z").unwrap();
        let after = crate::record::parse_wall("2026-08-10T00:00:01.000Z").unwrap();
        let fp = "ab".repeat(32);
        assert!(!signed.is_revoked_at(&fp, before));
        assert!(signed.is_revoked_at(&fp, after));
        assert!(!signed.is_revoked_at(&"cd".repeat(32), after));
    }

    #[test]
    fn tampered_list_fails() {
        let key = SigningKey::generate();
        let list = RevocationList {
            updated_at: "2026-08-11T00:00:00.000Z".into(),
            revocations: vec![],
        };
        let mut signed = SignedRevocationList::create(list, "k1".into(), &key).unwrap();
        signed.list.revocations.push(RevocationEntry {
            cert_fingerprint: "00".repeat(32),
            effective_at: "2026-08-11T00:00:00.000Z".into(),
            reason: "x".into(),
        });
        assert!(signed.verify(&key.verifying_key()).is_err());
    }
}
