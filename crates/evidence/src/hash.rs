//! BLAKE3-256 hashing helpers (ADR-003). All hashes are lowercase hex.

use crate::error::{EvidenceError, Result};

/// Byte length of a BLAKE3-256 digest.
pub const DIGEST_LEN: usize = 32;

/// Hash bytes with BLAKE3-256, returning lowercase hex.
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Hash bytes with BLAKE3-256, returning the raw 32-byte digest.
pub fn blake3_raw(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    *blake3::hash(bytes).as_bytes()
}

/// SHA-256 digest (TSA interop boundary, ADR-003), lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(&h.finalize())
}

/// SHA-256 digest, raw bytes.
pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Encode bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode lowercase/uppercase hex into bytes.
pub fn hex_decode(field: &'static str, s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(EvidenceError::InvalidHex {
            field,
            detail: format!("odd length {}", s.len()),
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(field, pair[0])?;
        let lo = hex_val(field, pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decode a 32-byte digest from hex.
pub fn hex_decode_digest(field: &'static str, s: &str) -> Result<[u8; DIGEST_LEN]> {
    let v = hex_decode(field, s)?;
    v.try_into()
        .map_err(|v: Vec<u8>| EvidenceError::InvalidHex {
            field,
            detail: format!("expected {DIGEST_LEN} bytes, got {}", v.len()),
        })
}

fn hex_val(field: &'static str, c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(EvidenceError::InvalidHex {
            field,
            detail: format!("invalid hex character {:?}", c as char),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 0xab, 0xff];
        let h = hex_encode(&bytes);
        assert_eq!(h, "0001abff");
        assert_eq!(hex_decode("t", &h).unwrap(), bytes);
        assert_eq!(hex_decode("t", "0001ABFF").unwrap(), bytes);
        assert!(hex_decode("t", "xyz").is_err());
        assert!(hex_decode("t", "abc").is_err());
    }

    #[test]
    fn blake3_known_shape() {
        let h = blake3_hex(b"sealr");
        assert_eq!(h.len(), 64);
        assert_eq!(h, h.to_lowercase());
    }
}
