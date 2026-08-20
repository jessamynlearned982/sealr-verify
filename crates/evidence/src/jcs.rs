//! RFC 8785 (JCS) canonicalization, restricted per ADR-001.
//!
//! All hashed and signed Sealr structures are canonicalized with this module.
//! Restriction (normative, doc 03 §2 / ADR-001): numbers in signed structures MUST
//! be integers with absolute value ≤ 2^53 − 1. This sidesteps ECMAScript
//! double-formatting entirely: an integer-valued IEEE 754 double in the safe range
//! serializes identically to its plain integer form, which is what we emit.
//! The canonicalizer rejects anything else rather than risk cross-implementation
//! divergence.

use serde_json::Value;

use crate::error::{EvidenceError, Result};

/// Maximum integer exactly representable in an IEEE 754 double (2^53 − 1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Canonicalize a JSON value to JCS bytes.
pub fn to_jcs_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    write_value(value, &mut out)?;
    Ok(out)
}

/// Canonicalize a serializable structure to JCS bytes.
pub fn struct_to_jcs_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value)?;
    to_jcs_bytes(&v)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785: sort property names by their UTF-16 code unit sequences.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a16: Vec<u16> = a.encode_utf16().collect();
                let b16: Vec<u16> = b.encode_utf16().collect();
                a16.cmp(&b16)
            });
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(&map[key.as_str()], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut Vec<u8>) -> Result<()> {
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(EvidenceError::UnsafeNumber(n.to_string()));
        }
        out.extend_from_slice(u.to_string().as_bytes());
        return Ok(());
    }
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(EvidenceError::UnsafeNumber(n.to_string()));
        }
        out.extend_from_slice(i.to_string().as_bytes());
        return Ok(());
    }
    // Tolerate integral doubles produced by lossy JSON pipelines; reject true fractions.
    if let Some(f) = n.as_f64() {
        #[allow(clippy::cast_possible_truncation)]
        if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64 {
            let i = f as i64;
            out.extend_from_slice(i.to_string().as_bytes());
            return Ok(());
        }
    }
    Err(EvidenceError::UnsafeNumber(n.to_string()))
}

/// RFC 8785 §3.2.2.2 string serialization.
fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{0009}' => out.extend_from_slice(b"\\t"),
            '\u{000A}' => out.extend_from_slice(b"\\n"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\u{000D}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                // Lowercase hex, four digits.
                let code = c as u32;
                out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jcs(v: &Value) -> String {
        String::from_utf8(to_jcs_bytes(v).unwrap()).unwrap()
    }

    #[test]
    fn sorts_keys_and_compacts() {
        let v = json!({"b": 2, "a": 1, "c": {"z": null, "y": [true, false]}});
        assert_eq!(jcs(&v), r#"{"a":1,"b":2,"c":{"y":[true,false],"z":null}}"#);
    }

    #[test]
    fn escapes_per_rfc8785() {
        let v = json!({"k": "a\"b\\c\u{0007}\n\t"});
        assert_eq!(jcs(&v), "{\"k\":\"a\\\"b\\\\c\\u0007\\n\\t\"}");
    }

    #[test]
    fn utf16_key_ordering() {
        // U+E000 (BMP private use) sorts AFTER U+10000 (surrogate pair D800 DC00)
        // in UTF-16 code-unit order, although its code point is smaller.
        let mut map = serde_json::Map::new();
        map.insert("\u{E000}".to_string(), json!(1));
        map.insert("\u{10000}".to_string(), json!(2));
        let v = Value::Object(map);
        let out = jcs(&v);
        let pos_supplementary = out.find("\u{10000}").unwrap();
        let pos_private = out.find('\u{E000}').unwrap();
        assert!(
            pos_supplementary < pos_private,
            "UTF-16 order must place surrogate pairs before U+E000..U+FFFF: {out}"
        );
    }

    #[test]
    fn rejects_fractions_and_unsafe_integers() {
        assert!(to_jcs_bytes(&json!({ "x": 1.5 })).is_err());
        assert!(to_jcs_bytes(&json!({ "x": 9_007_199_254_740_992_u64 })).is_err());
        assert_eq!(
            jcs(&json!({ "x": 9_007_199_254_740_991_u64 })),
            r#"{"x":9007199254740991}"#
        );
        assert_eq!(jcs(&json!({ "x": -42 })), r#"{"x":-42}"#);
    }

    #[test]
    fn integral_double_serializes_as_integer() {
        let v: Value = serde_json::from_str(r#"{"x": 10.0}"#).unwrap();
        assert_eq!(jcs(&v), r#"{"x":10}"#);
    }

    #[test]
    fn unicode_passthrough() {
        let v = json!({"€": "déjà vu ✓"});
        assert_eq!(jcs(&v), "{\"€\":\"déjà vu ✓\"}");
    }
}
