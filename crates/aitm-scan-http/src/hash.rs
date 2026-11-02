//! FNV-1a 64-bit hashing for page fingerprints and site-map node ids.
//!
//! The lane needs a fast, stable, non-cryptographic hash to fold a normalised
//! page or node key into a `u64`. It is never used for a security decision, so
//! the design deliberately takes FNV-1a over a cryptographic hash and adds no
//! dependency (plan call A1: `blake3` stays out of this crate).

/// FNV-1a offset basis, 64-bit.
const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a prime, 64-bit.
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// The FNV-1a 64-bit hash of `bytes`.
///
/// Empty input hashes to the offset basis, as the algorithm specifies.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::fnv1a64;

    #[test]
    fn fnv1a64_known_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
