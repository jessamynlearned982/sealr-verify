//! Ed25519 signing/verification and JCS-bound signature helpers (doc 03 §2, §7).
//!
//! Convention (normative): every Sealr signature is Ed25519 over the
//! BLAKE3-256 digest of the JCS bytes of the signed structure.

use ed25519_dalek::{Signer, Verifier};
use rand::rngs::OsRng;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{EvidenceError, Result};
use crate::hash::{blake3_raw, hex_decode, hex_encode};
use crate::jcs;

/// An Ed25519 signing key. Key material is zeroized on drop.
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.verifying_key_hex())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generate a fresh keypair from the OS RNG.
    pub fn generate() -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Load from raw 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| EvidenceError::Key("seed must be 32 bytes".into()))?;
        Ok(Self {
            inner: ed25519_dalek::SigningKey::from_bytes(&seed),
        })
    }

    /// Export the seed (handle with care; wrap in `Zeroizing`).
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.inner.to_bytes())
    }

    /// PKCS#8 PEM export (for `KeyStore` backends and rcgen interop).
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        self.inner
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|e| EvidenceError::Key(format!("pkcs8 export: {e}")))
    }

    /// PKCS#8 PEM import.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map(|inner| Self { inner })
            .map_err(|e| EvidenceError::Key(format!("pkcs8 import: {e}")))
    }

    /// The verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Public key as lowercase hex (32 bytes).
    pub fn verifying_key_hex(&self) -> String {
        hex_encode(self.inner.verifying_key().as_bytes())
    }

    /// Sign a 32-byte digest; returns the signature as lowercase hex (64 bytes).
    pub fn sign_digest(&self, digest: &[u8; 32]) -> String {
        hex_encode(&self.inner.sign(digest).to_bytes())
    }

    /// Sign a serializable structure: signature over BLAKE3-256(JCS(value)).
    pub fn sign_jcs<T: Serialize>(&self, value: &T) -> Result<String> {
        let bytes = jcs::struct_to_jcs_bytes(value)?;
        Ok(self.sign_digest(&blake3_raw(&bytes)))
    }

    /// Sign raw bytes' digest.
    pub fn sign_bytes(&self, bytes: &[u8]) -> String {
        self.sign_digest(&blake3_raw(bytes))
    }
}

/// An Ed25519 verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    /// From raw 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EvidenceError::Key("public key must be 32 bytes".into()))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map(|inner| Self { inner })
            .map_err(|e| EvidenceError::Key(format!("invalid public key: {e}")))
    }

    /// From lowercase hex.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(&hex_decode("public_key", hex)?)
    }

    /// SPKI PEM import (`-----BEGIN PUBLIC KEY-----`).
    pub fn from_spki_pem(pem: &str) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
            .map(|inner| Self { inner })
            .map_err(|e| EvidenceError::Key(format!("spki import: {e}")))
    }

    /// SPKI PEM export.
    pub fn to_spki_pem(&self) -> Result<String> {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        self.inner
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|e| EvidenceError::Key(format!("spki export: {e}")))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex_encode(self.inner.as_bytes())
    }

    /// Verify a hex signature over a 32-byte digest.
    pub fn verify_digest(
        &self,
        digest: &[u8; 32],
        signature_hex: &str,
        context: &str,
    ) -> Result<()> {
        let sig_bytes = hex_decode("signature", signature_hex)?;
        let sig_arr: [u8; 64] =
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EvidenceError::SignatureInvalid {
                    context: format!("{context}: signature must be 64 bytes"),
                })?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        self.inner
            .verify(digest, &sig)
            .map_err(|_| EvidenceError::SignatureInvalid {
                context: context.to_string(),
            })
    }

    /// Verify a signature over BLAKE3-256(JCS(value)).
    pub fn verify_jcs<T: Serialize>(
        &self,
        value: &T,
        signature_hex: &str,
        context: &str,
    ) -> Result<()> {
        let bytes = jcs::struct_to_jcs_bytes(value)?;
        self.verify_digest(&blake3_raw(&bytes), signature_hex, context)
    }

    /// Verify a signature over the digest of raw bytes.
    pub fn verify_bytes(&self, bytes: &[u8], signature_hex: &str, context: &str) -> Result<()> {
        self.verify_digest(&blake3_raw(bytes), signature_hex, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::generate();
        let value = json!({"a": 1, "b": "x"});
        let sig = key.sign_jcs(&value).unwrap();
        key.verifying_key()
            .verify_jcs(&value, &sig, "test")
            .unwrap();
        // Tampered value fails.
        let tampered = json!({"a": 2, "b": "x"});
        assert!(key
            .verifying_key()
            .verify_jcs(&tampered, &sig, "test")
            .is_err());
    }

    #[test]
    fn pem_round_trips() {
        let key = SigningKey::generate();
        let pem = key.to_pkcs8_pem().unwrap();
        let restored = SigningKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(key.verifying_key_hex(), restored.verifying_key_hex());

        let vk_pem = key.verifying_key().to_spki_pem().unwrap();
        let vk = VerifyingKey::from_spki_pem(&vk_pem).unwrap();
        assert_eq!(vk.to_hex(), key.verifying_key_hex());
    }

    #[test]
    fn hex_round_trip() {
        let key = SigningKey::generate();
        let vk = VerifyingKey::from_hex(&key.verifying_key_hex()).unwrap();
        assert_eq!(vk.to_hex(), key.verifying_key_hex());
    }
}
