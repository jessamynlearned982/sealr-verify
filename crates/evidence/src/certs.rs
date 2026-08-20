//! X.509 identity certificates (Ed25519) — issuance helpers and offline chain
//! validation (doc 03 §7).
//!
//! Hierarchy: Sealr Root (offline) → Tenant CA (Console) → Recorder cert.
//! Rust-side issuance is used by the recorder (CSR), dev tooling, and tests;
//! the production tenant CA lives in the Console. Validation is used by the
//! verifier and must work fully offline.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use x509_parser::prelude::{FromDer, ParsedExtension, Pem, X509Certificate};

use crate::error::{EvidenceError, Result};
use crate::hash::blake3_hex;
use crate::keys::{SigningKey, VerifyingKey};

/// Validity periods (doc 03 §7 / ADR-011).
pub const ROOT_VALIDITY_DAYS: i64 = 3650;
pub const TENANT_CA_VALIDITY_DAYS: i64 = 730;
pub const RECORDER_CERT_VALIDITY_DAYS: i64 = 90;

/// A validated certificate's extracted identity.
#[derive(Debug, Clone)]
pub struct ValidatedCert {
    pub subject_common_name: String,
    pub public_key: VerifyingKey,
    /// BLAKE3-256 of the certificate DER, lowercase hex.
    pub fingerprint: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
}

fn rcgen_keypair(key: &SigningKey) -> Result<KeyPair> {
    let pem = key.to_pkcs8_pem()?;
    KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_ED25519)
        .map_err(|e| EvidenceError::Certificate(format!("rcgen keypair: {e}")))
}

fn validity(days: i64) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let now = time::OffsetDateTime::now_utc();
    (
        now - time::Duration::minutes(5),
        now + time::Duration::days(days),
    )
}

/// Generate a self-signed CA certificate (root, or a standalone dev CA).
pub fn generate_self_signed_ca(key: &SigningKey, common_name: &str, days: i64) -> Result<String> {
    let kp = rcgen_keypair(key)?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Sealr");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let (nb, na) = validity(days);
    params.not_before = nb;
    params.not_after = na;
    let cert = params
        .self_signed(&kp)
        .map_err(|e| EvidenceError::Certificate(format!("self-sign: {e}")))?;
    Ok(cert.pem())
}

/// Issue an intermediate CA (tenant CA) signed by a parent CA.
pub fn issue_intermediate_ca(
    subject_key: &SigningKey,
    common_name: &str,
    days: i64,
    parent_key: &SigningKey,
    parent_cert_pem: &str,
) -> Result<String> {
    let subject_kp = rcgen_keypair(subject_key)?;
    let parent_kp = rcgen_keypair(parent_key)?;
    let parent_params = CertificateParams::from_ca_cert_pem(parent_cert_pem)
        .map_err(|e| EvidenceError::Certificate(format!("parse parent CA: {e}")))?;
    let parent_cert = parent_params
        .self_signed(&parent_kp)
        .map_err(|e| EvidenceError::Certificate(format!("rebuild parent CA: {e}")))?;

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Sealr");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let (nb, na) = validity(days);
    params.not_before = nb;
    params.not_after = na;
    let cert = params
        .signed_by(&subject_kp, &parent_cert, &parent_kp)
        .map_err(|e| EvidenceError::Certificate(format!("issue intermediate: {e}")))?;
    Ok(cert.pem())
}

/// Recorder side: generate a certificate signing request for the identity key.
pub fn generate_csr(key: &SigningKey, common_name: &str) -> Result<String> {
    let kp = rcgen_keypair(key)?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let csr = params
        .serialize_request(&kp)
        .map_err(|e| EvidenceError::Certificate(format!("serialize CSR: {e}")))?;
    csr.pem()
        .map_err(|e| EvidenceError::Certificate(format!("CSR pem: {e}")))
}

/// CA side: sign a CSR into an end-entity (recorder) certificate.
pub fn sign_csr(
    csr_pem: &str,
    ca_key: &SigningKey,
    ca_cert_pem: &str,
    days: i64,
) -> Result<String> {
    let ca_kp = rcgen_keypair(ca_key)?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .map_err(|e| EvidenceError::Certificate(format!("parse CA cert: {e}")))?;
    let ca_cert = ca_params
        .self_signed(&ca_kp)
        .map_err(|e| EvidenceError::Certificate(format!("rebuild CA cert: {e}")))?;

    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| EvidenceError::Certificate(format!("parse CSR: {e}")))?;
    let (nb, na) = validity(days);
    csr.params.not_before = nb;
    csr.params.not_after = na;
    csr.params.is_ca = IsCa::ExplicitNoCa;
    csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cert = csr
        .signed_by(&ca_cert, &ca_kp)
        .map_err(|e| EvidenceError::Certificate(format!("sign CSR: {e}")))?;
    Ok(cert.pem())
}

/// Parse all certificates out of a PEM string (in order).
pub fn parse_pem_chain(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut ders = Vec::new();
    for item in Pem::iter_from_buffer(pem.as_bytes()) {
        let pem = item.map_err(|e| EvidenceError::Certificate(format!("PEM parse: {e}")))?;
        if pem.label == "CERTIFICATE" {
            ders.push(pem.contents);
        }
    }
    if ders.is_empty() {
        return Err(EvidenceError::Certificate(
            "no CERTIFICATE blocks in PEM".into(),
        ));
    }
    Ok(ders)
}

/// BLAKE3-256 fingerprint of the first certificate in a PEM string.
pub fn cert_fingerprint(cert_pem: &str) -> Result<String> {
    let ders = parse_pem_chain(cert_pem)?;
    Ok(blake3_hex(&ders[0]))
}

fn extract_ed25519_key(cert: &X509Certificate<'_>) -> Result<VerifyingKey> {
    let spki = cert.public_key();
    // Ed25519 OID 1.3.101.112; raw subjectPublicKey BIT STRING is the 32-byte key.
    VerifyingKey::from_bytes(&spki.subject_public_key.data)
}

fn common_name(cert: &X509Certificate<'_>) -> String {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Validate a chain: `leaf_pem` must chain through `intermediates_pem` (in any
/// order; matched by issuer) to `root_pem`, every certificate valid at `at_unix`
/// (seconds), signatures verified, CA constraints respected.
pub fn validate_chain(
    leaf_pem: &str,
    intermediates_pem: &[String],
    root_pem: &str,
    at_unix: i64,
) -> Result<ValidatedCert> {
    let leaf_der = parse_pem_chain(leaf_pem)?.remove(0);
    let root_der = parse_pem_chain(root_pem)?.remove(0);
    let mut pool: Vec<Vec<u8>> = Vec::new();
    for pem in intermediates_pem {
        pool.extend(parse_pem_chain(pem)?);
    }

    let (_, leaf) = X509Certificate::from_der(&leaf_der)
        .map_err(|e| EvidenceError::Certificate(format!("leaf DER: {e}")))?;
    let (_, root) = X509Certificate::from_der(&root_der)
        .map_err(|e| EvidenceError::Certificate(format!("root DER: {e}")))?;

    let at = x509_parser::time::ASN1Time::from_timestamp(at_unix)
        .map_err(|e| EvidenceError::Certificate(format!("timestamp: {e}")))?;

    check_validity(&leaf, at, "leaf")?;
    check_validity(&root, at, "root")?;

    // Walk up: find issuer for current cert among pool ∪ {root}.
    let mut current_der = leaf_der.clone();
    let mut hops = 0;
    loop {
        hops += 1;
        if hops > 8 {
            return Err(EvidenceError::Certificate("chain too deep".into()));
        }
        let (_, current) = X509Certificate::from_der(&current_der)
            .map_err(|e| EvidenceError::Certificate(format!("chain DER: {e}")))?;

        // Root reached?
        if current.issuer() == root.subject() {
            verify_signed_by(&current, &root, "root")?;
            if !is_ca(&root) {
                return Err(EvidenceError::Certificate("root is not a CA".into()));
            }
            break;
        }

        // Find issuer in pool.
        let mut found: Option<Vec<u8>> = None;
        for cand_der in &pool {
            let (_, cand) = X509Certificate::from_der(cand_der)
                .map_err(|e| EvidenceError::Certificate(format!("pool DER: {e}")))?;
            if cand.subject() == current.issuer() {
                check_validity(&cand, at, "intermediate")?;
                if !is_ca(&cand) {
                    return Err(EvidenceError::Certificate(format!(
                        "intermediate {} is not a CA",
                        common_name(&cand)
                    )));
                }
                verify_signed_by(&current, &cand, "intermediate")?;
                found = Some(cand_der.clone());
                break;
            }
        }
        match found {
            Some(der) => current_der = der,
            None => {
                return Err(EvidenceError::Certificate(format!(
                    "no issuer found for {:?}",
                    common_name(&current)
                )))
            }
        }
    }

    Ok(ValidatedCert {
        subject_common_name: common_name(&leaf),
        public_key: extract_ed25519_key(&leaf)?,
        fingerprint: blake3_hex(&leaf_der),
        not_before_unix: leaf.validity().not_before.timestamp(),
        not_after_unix: leaf.validity().not_after.timestamp(),
    })
}

fn check_validity(
    cert: &X509Certificate<'_>,
    at: x509_parser::time::ASN1Time,
    what: &str,
) -> Result<()> {
    if !cert.validity().is_valid_at(at) {
        return Err(EvidenceError::Certificate(format!(
            "{what} certificate {:?} not valid at requested time",
            common_name(cert)
        )));
    }
    Ok(())
}

fn is_ca(cert: &X509Certificate<'_>) -> bool {
    cert.extensions()
        .iter()
        .any(|ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca))
}

fn verify_signed_by(
    cert: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    what: &str,
) -> Result<()> {
    cert.verify_signature(Some(issuer.public_key()))
        .map_err(|e| {
            EvidenceError::Certificate(format!(
                "{what} signature verification failed for {:?}: {e}",
                common_name(cert)
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_unix() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn full_hierarchy_round_trip() {
        let root_key = SigningKey::generate();
        let root_pem =
            generate_self_signed_ca(&root_key, "Sealr Root (test)", ROOT_VALIDITY_DAYS).unwrap();

        let tenant_key = SigningKey::generate();
        let tenant_pem = issue_intermediate_ca(
            &tenant_key,
            "Sealr Tenant CA test-tenant",
            TENANT_CA_VALIDITY_DAYS,
            &root_key,
            &root_pem,
        )
        .unwrap();

        let recorder_key = SigningKey::generate();
        let csr = generate_csr(&recorder_key, "recorder-01ABC").unwrap();
        let recorder_pem =
            sign_csr(&csr, &tenant_key, &tenant_pem, RECORDER_CERT_VALIDITY_DAYS).unwrap();

        let validated = validate_chain(
            &recorder_pem,
            std::slice::from_ref(&tenant_pem),
            &root_pem,
            now_unix(),
        )
        .unwrap();
        assert_eq!(validated.subject_common_name, "recorder-01ABC");
        assert_eq!(
            validated.public_key.to_hex(),
            recorder_key.verifying_key_hex()
        );
    }

    #[test]
    fn wrong_root_rejected() {
        let root_key = SigningKey::generate();
        let root_pem = generate_self_signed_ca(&root_key, "Root A", ROOT_VALIDITY_DAYS).unwrap();
        let other_root_key = SigningKey::generate();
        let other_root_pem =
            generate_self_signed_ca(&other_root_key, "Root B", ROOT_VALIDITY_DAYS).unwrap();

        let tenant_key = SigningKey::generate();
        let tenant_pem = issue_intermediate_ca(
            &tenant_key,
            "CA",
            TENANT_CA_VALIDITY_DAYS,
            &root_key,
            &root_pem,
        )
        .unwrap();
        let rec_key = SigningKey::generate();
        let csr = generate_csr(&rec_key, "rec").unwrap();
        let rec_pem =
            sign_csr(&csr, &tenant_key, &tenant_pem, RECORDER_CERT_VALIDITY_DAYS).unwrap();

        assert!(validate_chain(&rec_pem, &[tenant_pem], &other_root_pem, now_unix()).is_err());
    }

    #[test]
    fn fingerprint_is_stable() {
        let key = SigningKey::generate();
        let pem = generate_self_signed_ca(&key, "X", 10).unwrap();
        assert_eq!(
            cert_fingerprint(&pem).unwrap(),
            cert_fingerprint(&pem).unwrap()
        );
    }
}
