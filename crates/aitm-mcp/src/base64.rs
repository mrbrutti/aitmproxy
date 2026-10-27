//! Standard base64 (RFC 4648 §4, padded) for carrying `Value::Bytes` inside JSON.
//! Hand-rolled because the workspace stack names no base64 crate.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as padded standard base64.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64; padding may be present or omitted.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    let body = bytes
        .strip_suffix(b"==")
        .or_else(|| bytes.strip_suffix(b"="))
        .unwrap_or(bytes);
    if body.len() != bytes.len() && !bytes.len().is_multiple_of(4) {
        return Err("invalid base64: padded length is not a multiple of 4".into());
    }
    if body.len() % 4 == 1 {
        return Err("invalid base64: length".into());
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in body {
        let v = sextet(c).ok_or_else(|| format!("invalid base64 character {:?}", c as char))?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 test vectors.
    const VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc_vectors_encode() {
        for (plain, enc) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), *enc, "{plain}");
        }
    }

    #[test]
    fn rfc_vectors_decode_padded_and_unpadded() {
        for (plain, enc) in VECTORS {
            assert_eq!(decode(enc).unwrap(), plain.as_bytes(), "{enc}");
            assert_eq!(
                decode(enc.trim_end_matches('=')).unwrap(),
                plain.as_bytes(),
                "{enc} unpadded"
            );
        }
    }

    #[test]
    fn binary_roundtrip() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("not base64!").is_err());
        assert!(decode("Zg=").is_err(), "bad padded length");
        assert!(decode("Z").is_err(), "length 1 mod 4");
    }
}
