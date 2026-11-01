//! A seedable, dependency-free PRNG — owned by scanner v2 track T5, plan task 2.
//!
//! The lane records an `rng_seed` in every `L4Evidence` so a case replays
//! (spec D8.4). `rand`/`rand_chacha` are declared in the workspace but are not
//! in this track's offline cache and the lane never inherits them, so the
//! generator is the public-domain **splitmix64** hand-rolled here: 64 bits of
//! state, one multiply-xor-shift round per draw, identical output on every
//! platform.

/// splitmix64's additive constant (the 64-bit golden ratio).
const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
/// FNV-1a 64-bit offset basis.
const FNV_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// splitmix64's mixing step: the avalanche applied to an advanced state.
const fn mix(state: u64) -> u64 {
    let z = state;
    let z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A deterministic, seedable splitmix64 generator.
///
/// Two generators built from the same seed produce the same sequence, which is
/// what lets a reported case be replayed from its `rng_seed`. It is not a
/// cryptographic generator and is never used for anything but mutation choice.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator seeded with `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64-bit draw.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GOLDEN_GAMMA);
        mix(self.0)
    }

    /// A draw in `0..n`, or `0` when `n` is zero.
    ///
    /// Plain modulo: the bias for the small `n` the lane uses (table lengths,
    /// payload offsets) is immaterial next to the mutation choice itself, and a
    /// rejection loop would make a case's draw count depend on the seed.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    /// A uniformly chosen element of `items`, or `None` when it is empty.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let len = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let index = usize::try_from(self.below(len)).unwrap_or(0);
        items.get(index)
    }
}

/// The per-point seed: FNV-1a 64 over `marker`, a `0` separator and `point_id`,
/// run through one splitmix64 mixing step.
///
/// Every point of every job therefore starts from its own reproducible seed,
/// derived from values that are already in the evidence (the job's marker and
/// the point id), so a reader can recompute it.
#[must_use]
pub fn derive_seed(marker: &str, point_id: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in marker
        .bytes()
        .chain(std::iter::once(0u8))
        .chain(point_id.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    mix(hash)
}

#[cfg(test)]
mod tests {
    use super::{derive_seed, Rng};

    #[test]
    fn splitmix64_reference_first_output() {
        assert_eq!(Rng::new(0).next_u64(), 0xe220_a839_7b1d_cdaf);
    }

    #[test]
    fn below_is_bounded_and_deterministic() {
        let mut rng = Rng::new(42);
        for _ in 0..1000 {
            assert!(rng.below(7) < 7);
        }
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        let first: Vec<u64> = (0..16).map(|_| a.next_u64()).collect();
        let second: Vec<u64> = (0..16).map(|_| b.next_u64()).collect();
        assert_eq!(first, second);
    }

    #[test]
    fn below_zero_is_zero() {
        let mut rng = Rng::new(3);
        assert_eq!(rng.below(0), 0);
    }

    #[test]
    fn derive_seed_deterministic_and_distinct() {
        let a = derive_seed("aitm7f3a", "l4:127.0.0.1:9/udp/raw");
        assert_eq!(a, derive_seed("aitm7f3a", "l4:127.0.0.1:9/udp/raw"));
        assert_ne!(a, derive_seed("aitm7f3a", "l4:127.0.0.1:9/udp/ipv4.ttl"));
        assert_ne!(a, derive_seed("aitm7f3b", "l4:127.0.0.1:9/udp/raw"));
    }
}
