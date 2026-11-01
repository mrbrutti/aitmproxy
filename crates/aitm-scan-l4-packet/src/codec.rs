//! Hex and base64 codecs for operator-authored seed payloads — owned by scanner
//! v2 track T5, plan task 2.
//!
//! A profile seeds a packet case with `seeds: [{ hex: "deadbeef0000" }]` or its
//! base64 equivalent, and the lane renders `sent_hex` for evidence. Both halves
//! are pure, allocation-bounded and reject malformed input with a located
//! error rather than panicking: the strings come from an operator file.

use std::fmt;

/// Why a hex or base64 string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// A hex string holds an odd number of digits.
    OddLength,
    /// A character outside the alphabet, at its byte offset in the input.
    BadChar {
        /// Byte offset of the offending character in the input string.
        offset: usize,
        /// The offending character.
        ch: char,
    },
    /// base64 padding is missing, misplaced or too long.
    BadPadding,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("hex string has an odd number of digits"),
            Self::BadChar { offset, ch } => {
                write!(f, "invalid character {ch:?} at offset {offset}")
            }
            Self::BadPadding => f.write_str("invalid base64 padding"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Lowercase hex for `bytes`.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

/// The lowercase hex digit for a nibble (values above 15 cannot occur).
const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0',
    }
}

/// Decode a hex string, ignoring ASCII whitespace.
///
/// # Errors
///
/// [`CodecError::BadChar`] for a non-hex, non-whitespace character and
/// [`CodecError::OddLength`] when an even number of digits does not remain.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, CodecError> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(s.len());
    for (offset, ch) in s.char_indices() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let value = ch
            .to_digit(16)
            .and_then(|digit| u8::try_from(digit).ok())
            .ok_or(CodecError::BadChar { offset, ch })?;
        nibbles.push(value);
    }
    if !nibbles.len().is_multiple_of(2) {
        return Err(CodecError::OddLength);
    }
    Ok(nibbles
        .chunks_exact(2)
        .filter_map(|pair| match pair {
            [high, low] => Some((high << 4) | low),
            _ => None,
        })
        .collect())
}

/// The 6-bit value of a standard base64 symbol.
const fn base64_value(ch: char) -> Option<u8> {
    match ch {
        'A'..='Z' => Some(ch as u8 - b'A'),
        'a'..='z' => Some(ch as u8 - b'a' + 26),
        '0'..='9' => Some(ch as u8 - b'0' + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    }
}

/// Decode a standard-alphabet base64 string, ignoring ASCII whitespace.
///
/// Trailing `=` padding is optional, so both `"cHJvYmU="` and `"cHJvYmU"`
/// decode to `b"probe"`.
///
/// # Errors
///
/// [`CodecError::BadChar`] for a symbol outside the alphabet and
/// [`CodecError::BadPadding`] for a truncated group, data after padding, or
/// more than two padding characters.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, CodecError> {
    let mut symbols: Vec<u8> = Vec::with_capacity(s.len());
    let mut padding = 0usize;
    for (offset, ch) in s.char_indices() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        if ch == '=' {
            padding += 1;
            if padding > 2 {
                return Err(CodecError::BadPadding);
            }
            continue;
        }
        if padding > 0 {
            return Err(CodecError::BadPadding);
        }
        symbols.push(base64_value(ch).ok_or(CodecError::BadChar { offset, ch })?);
    }
    if symbols.len() % 4 == 1 {
        return Err(CodecError::BadPadding);
    }
    if padding > 0 && !(symbols.len() + padding).is_multiple_of(4) {
        return Err(CodecError::BadPadding);
    }
    let mut out: Vec<u8> = Vec::with_capacity(symbols.len() / 4 * 3 + 2);
    for group in symbols.chunks(4) {
        let (bits, len) = match group {
            [a, b, c, d] => (
                (u32::from(*a) << 18)
                    | (u32::from(*b) << 12)
                    | (u32::from(*c) << 6)
                    | u32::from(*d),
                3,
            ),
            [a, b, c] => (
                (u32::from(*a) << 18) | (u32::from(*b) << 12) | (u32::from(*c) << 6),
                2,
            ),
            [a, b] => ((u32::from(*a) << 18) | (u32::from(*b) << 12), 1),
            _ => continue,
        };
        for shift in 0..len {
            out.push(((bits >> (16 - 8 * shift)) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{base64_decode, hex_decode, hex_encode, CodecError};

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_decode("DE ad\nbe ef"), Ok(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn hex_rejects() {
        assert_eq!(hex_decode("abc"), Err(CodecError::OddLength));
        assert_eq!(
            hex_decode("zz"),
            Err(CodecError::BadChar { offset: 0, ch: 'z' })
        );
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_decode("AAE="), Ok(vec![0, 1]));
        assert_eq!(base64_decode("cHJvYmU="), Ok(b"probe".to_vec()));
        assert_eq!(base64_decode("cHJvYmU"), Ok(b"probe".to_vec()));
        assert!(matches!(
            base64_decode("cHJv!mU="),
            Err(CodecError::BadChar { .. })
        ));
    }

    /// Tester (stage 5): empty and whitespace-only strings decode to nothing
    /// (an operator can write `hex: ""` for an empty seed payload), and the
    /// encoder of nothing is the empty string.
    #[test]
    fn empty_and_whitespace_only_inputs_decode_to_nothing() {
        assert_eq!(hex_decode(""), Ok(Vec::new()));
        assert_eq!(hex_decode(" \t\r\n"), Ok(Vec::new()));
        assert_eq!(base64_decode(""), Ok(Vec::new()));
        assert_eq!(base64_decode("\n \t"), Ok(Vec::new()));
        assert_eq!(hex_encode(&[]), "");
    }

    /// Tester (stage 5): a bad character is located by its **byte** offset in
    /// the original string, whitespace included, and a non-ASCII character is
    /// reported as the character, not as a byte.
    #[test]
    fn hex_locates_bad_characters_by_byte_offset() {
        assert_eq!(
            hex_decode("ab\u{e9}"),
            Err(CodecError::BadChar {
                offset: 2,
                ch: '\u{e9}'
            })
        );
        assert_eq!(
            hex_decode("ab cd 0g"),
            Err(CodecError::BadChar { offset: 7, ch: 'g' })
        );
        assert_eq!(
            hex_decode("\u{e9}\u{e9}ab"),
            Err(CodecError::BadChar {
                offset: 0,
                ch: '\u{e9}'
            })
        );
        // Whitespace is ignored even between the two nibbles of one byte, and
        // the odd-length check runs over the digits that remain.
        assert_eq!(hex_decode("d e a d"), Ok(vec![0xde, 0xad]));
        assert_eq!(hex_decode("abc "), Err(CodecError::OddLength));
        assert_eq!(hex_decode("0"), Err(CodecError::OddLength));
        // A bad character is reported before an odd length.
        assert_eq!(
            hex_decode("abz"),
            Err(CodecError::BadChar { offset: 2, ch: 'z' })
        );
        assert_eq!(
            hex_decode("0x00"),
            Err(CodecError::BadChar { offset: 1, ch: 'x' })
        );
    }

    /// Tester (stage 5): a megabyte of hex round-trips byte for byte.
    #[test]
    fn hex_megabyte_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(1 << 20).collect();
        let text = hex_encode(&bytes);
        assert_eq!(text.len(), 2 << 20);
        assert_eq!(hex_decode(&text), Ok(bytes));
    }

    /// Tester (stage 5): the padding rules, each as a literal.
    #[test]
    fn base64_padding_rules_are_literal() {
        assert_eq!(base64_decode("AA"), Ok(vec![0]));
        assert_eq!(base64_decode("AA=="), Ok(vec![0]));
        assert_eq!(base64_decode("AAA"), Ok(vec![0, 0]));
        assert_eq!(base64_decode("AAA="), Ok(vec![0, 0]));
        assert_eq!(base64_decode("AAAA"), Ok(vec![0, 0, 0]));
        assert_eq!(base64_decode("AAAA\nAAAA"), Ok(vec![0; 6]));
        assert_eq!(base64_decode("/+8="), Ok(vec![0xff, 0xef]));
        for bad in ["A", "AAAAA", "AA=", "A===", "AA=A", "=", "==", "AAA=="] {
            assert_eq!(base64_decode(bad), Err(CodecError::BadPadding), "{bad:?}");
        }
        // The URL-safe alphabet is not the standard one.
        assert_eq!(
            base64_decode("AA-A"),
            Err(CodecError::BadChar { offset: 2, ch: '-' })
        );
        assert_eq!(
            base64_decode("AA_A"),
            Err(CodecError::BadChar { offset: 2, ch: '_' })
        );
        assert_eq!(
            CodecError::BadChar { offset: 2, ch: '-' }.to_string(),
            "invalid character '-' at offset 2"
        );
        assert_eq!(
            CodecError::OddLength.to_string(),
            "hex string has an odd number of digits"
        );
        assert_eq!(CodecError::BadPadding.to_string(), "invalid base64 padding");
    }
}
