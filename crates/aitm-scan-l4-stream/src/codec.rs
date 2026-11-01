//! Hand-rolled hex, base64, FNV-1a, CRC-32 and internet checksum (spec
//! Constraints: no `hex`, `base64` or `crc` crate in this workspace).
//!
//! Everything here is a pure function of its bytes: no allocation the caller
//! cannot see, no I/O, no panic on any input, and no `unwrap`/`expect` on a
//! value that comes from an operator profile or the wire. The decoders back
//! the operator seed forms of spec S5.2 (b) (`hex:` and `base64:` seeds);
//! [`fnv1a64`] and [`hex16`] back the stable point ids and RNG seeds of
//! S5.3 (FNV-1a is the crate's only hash); [`crc32`] and
//! [`internet_checksum`] back the two `checksum` relation algorithms of S2
//! and are called from [`crate::tree::resatisfy`].

use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a hex or base64 seed could not be decoded.
///
/// `at` is a byte offset into the *original* text the caller passed, so a
/// discovery error can quote the operator's own seed string (S5.2 (b):
/// a bad seed fails discovery with `invalid_profile` naming the seed index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Hex with an odd number of digits: a byte is half written.
    OddLength,
    /// A character that is not a hex digit, at this offset in the input.
    BadDigit {
        /// Byte offset of the offending character in the input text.
        at: usize,
    },
    /// A character that is not in the standard base64 alphabet, at this
    /// offset in the input. Line breaks count: base64 seeds are one line.
    BadBase64 {
        /// Byte offset of the offending character in the input text.
        at: usize,
    },
    /// Base64 whose length is not a multiple of four, or whose `=` padding
    /// is not the one or two trailing characters of the last group.
    BadPadding,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::OddLength => {
                f.write_str("hex has an odd number of digits, so a byte is incomplete")
            }
            CodecError::BadDigit { at } => {
                write!(f, "character {at} is not a hex digit")
            }
            CodecError::BadBase64 { at } => {
                write!(f, "character {at} is not in the base64 alphabet")
            }
            CodecError::BadPadding => f.write_str(
                "base64 length is not a multiple of four or the '=' padding is misplaced",
            ),
        }
    }
}

impl std::error::Error for CodecError {}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Decode hex text to bytes.
///
/// An optional `0x` / `0X` prefix is stripped, ASCII whitespace anywhere is
/// ignored (so `"00 FF"` and `"00ff"` agree), and both digit cases are
/// accepted. An odd digit count is [`CodecError::OddLength`]; any other
/// character is [`CodecError::BadDigit`] naming its offset in `text`.
/// Empty text (or a bare `0x`) decodes to no bytes.
///
/// # Errors
///
/// [`CodecError::OddLength`] or [`CodecError::BadDigit`], as above.
pub fn decode_hex(text: &str) -> Result<Vec<u8>, CodecError> {
    // (offset in `text`, digit value) for every non-whitespace character.
    let mut digits: Vec<(usize, u8)> = Vec::with_capacity(text.len());
    let body = strip_hex_prefix(text);
    let base = text.len() - body.len();

    for (i, ch) in body.char_indices() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let at = base + i;
        match hex_digit(ch) {
            Some(value) => digits.push((at, value)),
            None => return Err(CodecError::BadDigit { at }),
        }
    }

    if !digits.len().is_multiple_of(2) {
        return Err(CodecError::OddLength);
    }

    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = pair.first().map_or(0, |(_, v)| *v);
        let lo = pair.get(1).map_or(0, |(_, v)| *v);
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Encode bytes as lowercase hex, with no `0x` prefix and no separators.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// `text` without a leading `0x` / `0X`, ignoring leading whitespace.
fn strip_hex_prefix(text: &str) -> &str {
    // When there is a prefix only its two characters are consumed; the
    // caller re-derives the offset into `text` from the length difference.
    let trimmed = text.trim_start();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(text)
}

/// The value of one hex digit, either case.
fn hex_digit(ch: char) -> Option<u8> {
    match ch {
        '0'..='9' => Some(ch as u8 - b'0'),
        'a'..='f' => Some(ch as u8 - b'a' + 10),
        'A'..='F' => Some(ch as u8 - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

/// Decode standard-alphabet base64 (`A-Z a-z 0-9 + /`) with required `=`
/// padding.
///
/// There is no line-break tolerance and no URL-safe alphabet: a seed is one
/// line of standard base64. A length that is not a multiple of four, or `=`
/// anywhere but as the last one or two characters, is
/// [`CodecError::BadPadding`]; any other character outside the alphabet is
/// [`CodecError::BadBase64`] naming its offset. Empty text decodes to no
/// bytes.
///
/// # Errors
///
/// [`CodecError::BadPadding`] or [`CodecError::BadBase64`], as above.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, CodecError> {
    let chars = text.as_bytes();
    if !chars.len().is_multiple_of(4) {
        return Err(CodecError::BadPadding);
    }
    if chars.is_empty() {
        return Ok(Vec::new());
    }

    // Padding: `=` may only be the last character, or the last two.
    let pad = chars.iter().filter(|c| **c == b'=').count();
    if pad > 2 {
        return Err(CodecError::BadPadding);
    }
    for (at, ch) in chars.iter().enumerate() {
        if *ch == b'=' && at + pad < chars.len() {
            return Err(CodecError::BadPadding);
        }
    }

    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    for (group, quad) in chars.chunks(4).enumerate() {
        let mut acc: u32 = 0;
        let mut bytes_in_group: usize = 3;
        for (i, ch) in quad.iter().enumerate() {
            let at = group * 4 + i;
            if *ch == b'=' {
                acc <<= 6;
                bytes_in_group = bytes_in_group.saturating_sub(1);
                continue;
            }
            match base64_value(*ch) {
                Some(value) => acc = (acc << 6) | u32::from(value),
                None => return Err(CodecError::BadBase64 { at }),
            }
        }
        let triple = acc.to_be_bytes();
        // `acc` holds 24 bits, so the three payload bytes are the low three.
        for byte in triple.iter().skip(1).take(bytes_in_group) {
            out.push(*byte);
        }
    }
    Ok(out)
}

/// The six-bit value of one standard-alphabet base64 character.
fn base64_value(ch: u8) -> Option<u8> {
    match ch {
        b'A'..=b'Z' => Some(ch - b'A'),
        b'a'..=b'z' => Some(ch - b'a' + 26),
        b'0'..=b'9' => Some(ch - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// The FNV-1a 64-bit offset basis.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// The FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a, 64-bit. The crate's only hash (spec S5.3): it backs the stable
/// point id `l4s-<hex16>` and every campaign's `rng_seed`, so its value must
/// never drift.
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// A `u64` as exactly 16 lowercase hex digits, zero padded.
#[must_use]
pub fn hex16(v: u64) -> String {
    format!("{v:016x}")
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// CRC-32 (IEEE, the zlib/PNG parameters), table-free so the crate carries no
/// generated table. One of the two `checksum` relation algorithms of S2.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// The RFC 1071 internet checksum: the one's-complement sum of the big-endian
/// 16-bit words, with a final odd byte padded on the right. The other
/// `checksum` relation algorithm of S2.
#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in bytes.chunks(2) {
        let hi = pair.first().copied().unwrap_or(0);
        let lo = pair.get(1).copied().unwrap_or(0);
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum & 0xffff).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_forms() {
        assert_eq!(decode_hex("00ff"), Ok(vec![0, 255]));
        assert_eq!(decode_hex("00 FF"), Ok(vec![0, 255]));
        assert_eq!(decode_hex("0x00ff"), Ok(vec![0, 255]));
        assert_eq!(decode_hex("0f0"), Err(CodecError::OddLength));
        assert_eq!(decode_hex("zz"), Err(CodecError::BadDigit { at: 0 }));
        assert_eq!(encode_hex(&[0xde, 0xad]), "dead");
    }

    #[test]
    fn base64_forms() {
        assert_eq!(decode_base64("AAE="), Ok(vec![0, 1]));
        assert_eq!(decode_base64("A"), Err(CodecError::BadPadding));
        assert_eq!(decode_base64("A*=="), Err(CodecError::BadBase64 { at: 1 }));
    }

    #[test]
    fn fnv1a64_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(hex16(1), "0000000000000001");
    }

    #[test]
    fn crc32_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn internet_checksum_vector() {
        assert_eq!(
            internet_checksum(&[
                0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
            ]),
            0xb861
        );
    }

    // --- beyond the plan's five vectors: the properties the callers rely on

    #[test]
    fn hex_round_trips_and_tolerates_the_prefixed_spaced_form() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode_hex(&encode_hex(&bytes)), Ok(bytes));
        assert_eq!(
            decode_hex("0X DE ad BE ef"),
            Ok(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(decode_hex(""), Ok(Vec::new()));
        assert_eq!(decode_hex("0x"), Ok(Vec::new()));
        // The offset a bad digit reports is into the text the operator wrote,
        // prefix and spaces included.
        assert_eq!(decode_hex("0x00 0g"), Err(CodecError::BadDigit { at: 6 }));
    }

    #[test]
    fn base64_lengths_padding_and_alphabet() {
        assert_eq!(decode_base64(""), Ok(Vec::new()));
        assert_eq!(decode_base64("AAAA"), Ok(vec![0, 0, 0]));
        assert_eq!(decode_base64("AA=="), Ok(vec![0]));
        assert_eq!(decode_base64("TWFu"), Ok(b"Man".to_vec()));
        assert_eq!(
            decode_base64("bGlnaHQgd29yaw=="),
            Ok(b"light work".to_vec())
        );
        assert_eq!(decode_base64("+/8="), Ok(vec![0xfb, 0xff]));
        // Padding that is not the trailing one or two characters.
        assert_eq!(decode_base64("=AAA"), Err(CodecError::BadPadding));
        assert_eq!(decode_base64("A=AA"), Err(CodecError::BadPadding));
        assert_eq!(decode_base64("A==="), Err(CodecError::BadPadding));
        assert_eq!(decode_base64("AAAAA"), Err(CodecError::BadPadding));
        // A line break is not in the alphabet: seeds are one line.
        assert_eq!(decode_base64("AA\nA"), Err(CodecError::BadBase64 { at: 2 }));
        // URL-safe characters are not the standard alphabet.
        assert_eq!(decode_base64("ab-d"), Err(CodecError::BadBase64 { at: 2 }));
    }

    #[test]
    fn errors_display_their_cause() {
        assert_eq!(
            CodecError::OddLength.to_string(),
            "hex has an odd number of digits, so a byte is incomplete"
        );
        assert_eq!(
            CodecError::BadDigit { at: 3 }.to_string(),
            "character 3 is not a hex digit"
        );
        assert_eq!(
            CodecError::BadBase64 { at: 1 }.to_string(),
            "character 1 is not in the base64 alphabet"
        );
        assert_eq!(
            CodecError::BadPadding.to_string(),
            "base64 length is not a multiple of four or the '=' padding is misplaced"
        );
    }

    #[test]
    fn fnv1a64_is_the_published_sequence_and_feeds_stable_ids() {
        // github.com/fnvhash vectors.
        assert_eq!(fnv1a64(b"foobar"), 0x85944171_f73967e8);
        // Distinct inputs, distinct ids: the point id depends on every part.
        assert_ne!(fnv1a64(b"node|seed|a"), fnv1a64(b"node|seed|b"));
        assert_eq!(hex16(fnv1a64(b"")).len(), 16);
        assert_eq!(hex16(u64::MAX), "ffffffffffffffff");
    }

    #[test]
    fn checksums_on_the_empty_and_odd_length_cases() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xe8b7_be43);
        assert_eq!(internet_checksum(&[]), 0xffff);
        // An odd trailing byte is padded on the right, not the left.
        assert_eq!(internet_checksum(&[0x01]), internet_checksum(&[0x01, 0x00]));
        assert_ne!(internet_checksum(&[0x01]), internet_checksum(&[0x00, 0x01]));
    }
}
