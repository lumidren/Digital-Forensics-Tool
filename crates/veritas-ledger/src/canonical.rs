//! Canonical JSON serialization used for signing and chaining.
//!
//! Rules (a strict subset of RFC 8785 JCS):
//! - object keys sorted by their UTF-16 code units (equivalently by Unicode scalar value for BMP);
//! - no whitespace;
//! - numbers must be integers (floats are rejected, they are never used in ledger entries);
//! - strings escaped with the minimal JSON escapes and lower-case `\u00xx` for other controls.
//!
//! The writer and the verifier both call [`canonical_bytes`]; this is the only code they share.
#![forbid(unsafe_code)]

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("floating point numbers are not permitted in canonical JSON: {0}")]
    Float(f64),
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Serialize any value to canonical JSON bytes. THREAT:T2.1
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let v = serde_json::to_value(value)?;
    let mut out = Vec::with_capacity(512);
    write_value(&v, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(CanonicalError::Float(n.as_f64().unwrap_or(f64::NAN)));
            }
        }
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
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&map[*k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
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

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({"b": 1, "a": {"z": [1, 2, {"y": "x"}], "c": null}});
        assert_eq!(
            String::from_utf8(canonical_bytes(&v).unwrap()).unwrap(),
            r#"{"a":{"c":null,"z":[1,2,{"y":"x"}]},"b":1}"#
        );
    }

    #[test]
    fn rejects_floats() {
        assert!(canonical_bytes(&json!({"x": 1.5})).is_err());
    }

    #[test]
    fn escapes_controls_lowercase() {
        let v = json!({"s": "a\"b\\c\n\u{1}"});
        assert_eq!(
            String::from_utf8(canonical_bytes(&v).unwrap()).unwrap(),
            r#"{"s":"a\"b\\c\n\u0001"}"#
        );
    }

    #[test]
    fn stable_across_calls() {
        let v = json!({"k": [3, 2, 1], "j": "é"});
        assert_eq!(canonical_bytes(&v).unwrap(), canonical_bytes(&v).unwrap());
    }
}
