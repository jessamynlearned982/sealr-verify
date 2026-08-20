//! RFC 3161 timestamp token verification (offline).
//!
//! Scope (documented, V1): parses `TimeStampResp`/`ContentInfo` tokens,
//! validates the message imprint binding, extracts `genTime`, and verifies the
//! CMS `SignedData` signature (RSA PKCS#1 v1.5 with SHA-256/384/512) against
//! the signer certificate embedded in the token. EU-trust-list qualification is
//! reported as recorded by the exporter, not independently validated offline.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_tsp::TstInfo;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TsaError {
    #[error("token parse error: {0}")]
    Parse(String),
    #[error("timestamp not granted: PKIStatus {0}")]
    NotGranted(u32),
    #[error("message imprint mismatch: token binds a different digest")]
    ImprintMismatch,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("token signature invalid: {0}")]
    SignatureInvalid(String),
    #[error("signer certificate not found in token")]
    SignerCertMissing,
}

/// Result of verifying one token.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    /// `genTime` as RFC 3339 UTC.
    pub gen_time: String,
    /// Subject of the TSA signer certificate (best-effort display string).
    pub signer_subject: String,
    /// True when the CMS signature verified against the embedded signer cert.
    pub signature_verified: bool,
}

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
const OID_SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";

/// Verify a `.tsr` (`TimeStampResp`) or raw token (`ContentInfo`) against the
/// expected SHA-256 message imprint (the digest the batch root was hashed to).
pub fn verify_token(
    token_der: &[u8],
    expected_sha256_imprint: &[u8; 32],
) -> Result<VerifiedToken, TsaError> {
    // Accept both TimeStampResp and bare ContentInfo tokens.
    let content_info = parse_token(token_der)?;

    if content_info.content_type != OID_SIGNED_DATA {
        return Err(TsaError::Parse(format!(
            "token content type {} is not id-signedData",
            content_info.content_type
        )));
    }
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|e| TsaError::Parse(format!("SignedData: {e}")))?;

    // TSTInfo from the encapsulated content.
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| TsaError::Parse("missing eContent".into()))?;
    let tst_bytes: OctetString = econtent
        .decode_as()
        .map_err(|e| TsaError::Parse(format!("eContent octet string: {e}")))?;
    let tst_info = TstInfo::from_der(tst_bytes.as_bytes())
        .map_err(|e| TsaError::Parse(format!("TSTInfo: {e}")))?;

    // Message imprint binding.
    let imprint_alg = tst_info.message_imprint.hash_algorithm.oid.to_string();
    if imprint_alg != OID_SHA256 {
        return Err(TsaError::UnsupportedAlgorithm(format!(
            "imprint digest {imprint_alg}"
        )));
    }
    if tst_info.message_imprint.hashed_message.as_bytes() != expected_sha256_imprint {
        return Err(TsaError::ImprintMismatch);
    }

    // genTime.
    let unix = tst_info.gen_time.to_unix_duration();
    let secs =
        i64::try_from(unix.as_secs()).map_err(|_| TsaError::Parse("genTime overflow".into()))?;
    let gen_time = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, unix.subsec_nanos())
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .ok_or_else(|| TsaError::Parse("genTime out of range".into()))?;

    // CMS signature over signed attributes.
    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| TsaError::Parse("no SignerInfo".into()))?;
    let signer_cert = find_signer_cert(&signed_data, signer_info)?;
    let signer_subject = signer_cert.tbs_certificate.subject.to_string();

    verify_cms_signature(signer_info, &signer_cert, tst_bytes.as_bytes())?;

    Ok(VerifiedToken {
        gen_time,
        signer_subject,
        signature_verified: true,
    })
}

fn parse_token(token_der: &[u8]) -> Result<ContentInfo, TsaError> {
    // TimeStampResp = SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
    if let Ok(resp) = x509_tsp::TimeStampResp::from_der(token_der) {
        let status = resp.status.status as u32;
        if status != 0 && status != 1 {
            return Err(TsaError::NotGranted(status));
        }
        return resp
            .time_stamp_token
            .ok_or_else(|| TsaError::Parse("granted response without token".into()));
    }
    ContentInfo::from_der(token_der).map_err(|e| TsaError::Parse(format!("ContentInfo: {e}")))
}

fn find_signer_cert(
    signed_data: &SignedData,
    signer: &SignerInfo,
) -> Result<Certificate, TsaError> {
    let certs = signed_data
        .certificates
        .as_ref()
        .ok_or(TsaError::SignerCertMissing)?;
    for choice in certs.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            match &signer.sid {
                SignerIdentifier::IssuerAndSerialNumber(iasn) => {
                    if cert.tbs_certificate.serial_number == iasn.serial_number
                        && cert.tbs_certificate.issuer == iasn.issuer
                    {
                        return Ok(cert.clone());
                    }
                }
                SignerIdentifier::SubjectKeyIdentifier(_) => {
                    // Fall back to the first certificate for SKI-identified signers.
                    return Ok(cert.clone());
                }
            }
        }
    }
    Err(TsaError::SignerCertMissing)
}

fn verify_cms_signature(
    signer: &SignerInfo,
    cert: &Certificate,
    econtent_bytes: &[u8],
) -> Result<(), TsaError> {
    let digest_oid = signer.digest_alg.oid.to_string();

    // What was signed: DER of SignedAttributes re-tagged as SET OF (RFC 5652 §5.4),
    // whose messageDigest attribute must match digest(econtent).
    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TsaError::Parse("missing signedAttrs".into()))?;

    // Check messageDigest attribute.
    let econtent_digest = digest_bytes(&digest_oid, econtent_bytes)?;
    let mut md_ok = false;
    for attr in signed_attrs.iter() {
        if attr.oid == OID_MESSAGE_DIGEST {
            if let Some(v) = attr.values.iter().next() {
                let od: OctetString = v
                    .decode_as()
                    .map_err(|e| TsaError::Parse(format!("messageDigest: {e}")))?;
                md_ok = od.as_bytes() == econtent_digest.as_slice();
            }
        }
    }
    if !md_ok {
        return Err(TsaError::SignatureInvalid(
            "messageDigest attribute mismatch".into(),
        ));
    }

    // SignedAttributes encode as IMPLICIT [0] in the message; signature is over
    // the same encoding with the explicit SET OF tag (0x31).
    let mut attrs_der = signed_attrs
        .to_der()
        .map_err(|e| TsaError::Parse(format!("signedAttrs DER: {e}")))?;
    if attrs_der.first() == Some(&0xA0) {
        attrs_der[0] = 0x31;
    }
    let signed_digest = digest_bytes(&digest_oid, &attrs_der)?;

    let sig_alg = signer.signature_algorithm.oid.to_string();
    match sig_alg.as_str() {
        OID_RSA_ENCRYPTION | OID_SHA256_WITH_RSA | OID_SHA384_WITH_RSA | OID_SHA512_WITH_RSA => {
            let spki = &cert.tbs_certificate.subject_public_key_info;
            let spki_der = spki
                .to_der()
                .map_err(|e| TsaError::Parse(format!("SPKI DER: {e}")))?;
            let public_key = rsa_key_from_spki(&spki_der)?;
            let padding = match digest_oid.as_str() {
                OID_SHA256 => Pkcs1v15Sign::new::<Sha256>(),
                OID_SHA384 => Pkcs1v15Sign::new::<Sha384>(),
                OID_SHA512 => Pkcs1v15Sign::new::<Sha512>(),
                other => return Err(TsaError::UnsupportedAlgorithm(format!("digest {other}"))),
            };
            public_key
                .verify(padding, &signed_digest, signer.signature.as_bytes())
                .map_err(|e| TsaError::SignatureInvalid(format!("RSA verify: {e}")))
        }
        other => Err(TsaError::UnsupportedAlgorithm(format!("signature {other}"))),
    }
}

fn digest_bytes(oid: &str, bytes: &[u8]) -> Result<Vec<u8>, TsaError> {
    Ok(match oid {
        OID_SHA256 => Sha256::digest(bytes).to_vec(),
        OID_SHA384 => Sha384::digest(bytes).to_vec(),
        OID_SHA512 => Sha512::digest(bytes).to_vec(),
        other => return Err(TsaError::UnsupportedAlgorithm(format!("digest {other}"))),
    })
}

fn rsa_key_from_spki(spki_der: &[u8]) -> Result<RsaPublicKey, TsaError> {
    use rsa::pkcs8::DecodePublicKey;
    RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| TsaError::Parse(format!("RSA SPKI: {e}")))
}
