//! The 25 byte-level mutators of spec S6.4, hand-rolled.
//!
//! The names are LibAFL's `mutators::mutations` set minus the two `Mapped*`
//! variants (research `18-protocol-fuzzing.md` §3.3); the bodies are ours, so
//! the crate takes no fuzzing-framework dependency. Every mutator is a pure
//! function of `(input, rng state, donors)`: the same `ChaCha8Rng` seed over
//! the same input and donor set always produces the same bytes and the same
//! parameter string (spec C5).
//!
//! [`apply`] returns the parameter string the schedule puts inside the chain
//! entry `"<mutator>(<path>,<params>)"` (spec S6.4 "Chain naming"), or `None`
//! when the mutator does not apply to this input: too short, no donor, or a
//! growth that would pass `max_len`. On `None` the input is left untouched.
//!
//! Parameter grammar: `@<offset>` is a byte offset (a *bit* offset for
//! `BitFlip`), `+<n>`/`-<n>` a signed arithmetic delta or a count of bytes
//! added or removed, `=<n>` a count of bytes overwritten, `^<n>` an xor mask,
//! `src=<offset>` the source of a copy, `donor=<i>` the index in the donor set
//! and `be`/`le` the endianness a multi-byte mutator read the field with.

use std::fmt;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

/// AFL's 8-bit interesting values.
pub const INTERESTING_8: [i8; 9] = [-128, -1, 0, 1, 16, 32, 64, 100, 127];

/// AFL's 16-bit interesting values: the 8-bit table (the first nine) plus the
/// ten wider ones.
pub const INTERESTING_16: [i16; 19] = [
    -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
];

/// AFL's 32-bit interesting values: the 16-bit table (the first nineteen,
/// which themselves open with the 8-bit table) plus the eight wider ones.
pub const INTERESTING_32: [i32; 27] = [
    -128,
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    -32768,
    -129,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    -2147483648,
    -100663046,
    -32769,
    32768,
    65535,
    65536,
    100663045,
    2147483647,
];

/// The largest message a byte-level mutation may grow to (spec S6.4).
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// AFL's arithmetic range: a byte/word/dword add moves a field by `1..=35`.
const ARITH_MAX: usize = 35;

/// The longest block a single mutator inserts, sets, copies or swaps.
const MAX_BLOCK: usize = 16;

/// The byte-level mutator set (spec S6.4), named after LibAFL's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByteMutator {
    BitFlip,
    ByteFlip,
    ByteInc,
    ByteDec,
    ByteNeg,
    ByteRand,
    ByteAdd,
    WordAdd,
    DwordAdd,
    QwordAdd,
    ByteInteresting,
    WordInteresting,
    DwordInteresting,
    BytesDelete,
    BytesExpand,
    BytesInsert,
    BytesRandInsert,
    BytesSet,
    BytesRandSet,
    BytesCopy,
    BytesInsertCopy,
    BytesSwap,
    CrossoverInsert,
    CrossoverReplace,
    Splice,
}

impl ByteMutator {
    /// Every mutator, in declaration order. The schedule stacks from this set.
    pub const ALL: [ByteMutator; 25] = [
        ByteMutator::BitFlip,
        ByteMutator::ByteFlip,
        ByteMutator::ByteInc,
        ByteMutator::ByteDec,
        ByteMutator::ByteNeg,
        ByteMutator::ByteRand,
        ByteMutator::ByteAdd,
        ByteMutator::WordAdd,
        ByteMutator::DwordAdd,
        ByteMutator::QwordAdd,
        ByteMutator::ByteInteresting,
        ByteMutator::WordInteresting,
        ByteMutator::DwordInteresting,
        ByteMutator::BytesDelete,
        ByteMutator::BytesExpand,
        ByteMutator::BytesInsert,
        ByteMutator::BytesRandInsert,
        ByteMutator::BytesSet,
        ByteMutator::BytesRandSet,
        ByteMutator::BytesCopy,
        ByteMutator::BytesInsertCopy,
        ByteMutator::BytesSwap,
        ByteMutator::CrossoverInsert,
        ByteMutator::CrossoverReplace,
        ByteMutator::Splice,
    ];

    /// The mutator's name, as it appears in a mutation chain entry.
    pub fn name(self) -> &'static str {
        match self {
            ByteMutator::BitFlip => "BitFlip",
            ByteMutator::ByteFlip => "ByteFlip",
            ByteMutator::ByteInc => "ByteInc",
            ByteMutator::ByteDec => "ByteDec",
            ByteMutator::ByteNeg => "ByteNeg",
            ByteMutator::ByteRand => "ByteRand",
            ByteMutator::ByteAdd => "ByteAdd",
            ByteMutator::WordAdd => "WordAdd",
            ByteMutator::DwordAdd => "DwordAdd",
            ByteMutator::QwordAdd => "QwordAdd",
            ByteMutator::ByteInteresting => "ByteInteresting",
            ByteMutator::WordInteresting => "WordInteresting",
            ByteMutator::DwordInteresting => "DwordInteresting",
            ByteMutator::BytesDelete => "BytesDelete",
            ByteMutator::BytesExpand => "BytesExpand",
            ByteMutator::BytesInsert => "BytesInsert",
            ByteMutator::BytesRandInsert => "BytesRandInsert",
            ByteMutator::BytesSet => "BytesSet",
            ByteMutator::BytesRandSet => "BytesRandSet",
            ByteMutator::BytesCopy => "BytesCopy",
            ByteMutator::BytesInsertCopy => "BytesInsertCopy",
            ByteMutator::BytesSwap => "BytesSwap",
            ByteMutator::CrossoverInsert => "CrossoverInsert",
            ByteMutator::CrossoverReplace => "CrossoverReplace",
            ByteMutator::Splice => "Splice",
        }
    }
}

impl fmt::Display for ByteMutator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The other seeds of the same endpoint, the donor set for `Crossover*` and
/// `Splice`. Holds message bytes, so its `Debug` prints sizes only.
#[derive(Clone, Copy)]
pub struct Donors<'a>(pub &'a [Vec<u8>]);

impl fmt::Debug for Donors<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total: usize = self.0.iter().map(Vec::len).sum();
        write!(f, "Donors({} donors, {total} bytes)", self.0.len())
    }
}

/// Endianness a multi-byte mutator reads and writes a field with.
#[derive(Clone, Copy)]
enum End {
    Be,
    Le,
}

impl End {
    fn tag(self) -> &'static str {
        match self {
            End::Be => "be",
            End::Le => "le",
        }
    }
}

/// A uniform index in `0..n`, and `0` when there is nothing to choose from.
fn below(rng: &mut ChaCha8Rng, n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        rng.random_range(0..n)
    }
}

fn pick_end(rng: &mut ChaCha8Rng) -> End {
    if rng.random_bool(0.5) {
        End::Be
    } else {
        End::Le
    }
}

/// `1..=max`, clamped so a zero-width choice never panics.
fn count_up_to(rng: &mut ChaCha8Rng, max: usize) -> usize {
    1 + below(rng, max.max(1))
}

fn read_uint(bytes: &[u8], end: End) -> u64 {
    let mut v = 0u64;
    match end {
        End::Be => {
            for &b in bytes {
                v = (v << 8) | u64::from(b);
            }
        }
        End::Le => {
            for &b in bytes.iter().rev() {
                v = (v << 8) | u64::from(b);
            }
        }
    }
    v
}

fn write_uint(bytes: &mut [u8], end: End, v: u64) {
    let width = bytes.len();
    for (k, slot) in bytes.iter_mut().enumerate() {
        let shift = 8 * match end {
            End::Be => width - 1 - k,
            End::Le => k,
        };
        *slot = (v >> shift) as u8;
    }
}

/// Add a signed delta to the `width`-byte field at a random offset.
fn arith_at(input: &mut [u8], rng: &mut ChaCha8Rng, width: usize) -> Option<String> {
    let len = input.len();
    if len < width {
        return None;
    }
    let off = below(rng, len - width + 1);
    let end = pick_end(rng);
    let magnitude = count_up_to(rng, ARITH_MAX) as i64;
    let delta = if rng.random_bool(0.5) {
        -magnitude
    } else {
        magnitude
    };
    let field = input.get_mut(off..off + width)?;
    let value = read_uint(field, end).wrapping_add(delta as u64);
    write_uint(field, end, value);
    if width == 1 {
        Some(format!("@{off},{delta:+}"))
    } else {
        Some(format!("@{off},{},{delta:+}", end.tag()))
    }
}

/// Overwrite the `width`-byte field at a random offset with an AFL
/// interesting value, two's complement, in a random endianness.
///
/// The table is borrowed as the `&[i8]`, `&[i16]` or `&[i32]` the const
/// declares, and the chosen entry is widened to `i64` where it is used, so a
/// call copies nothing.
fn interesting_at<T>(
    input: &mut [u8],
    rng: &mut ChaCha8Rng,
    width: usize,
    table: &[T],
) -> Option<String>
where
    T: Copy + Into<i64>,
{
    let len = input.len();
    if len < width || table.is_empty() {
        return None;
    }
    let off = below(rng, len - width + 1);
    let end = pick_end(rng);
    let value: i64 = (*table.get(below(rng, table.len()))?).into();
    let field = input.get_mut(off..off + width)?;
    write_uint(field, end, value as u64);
    if width == 1 {
        Some(format!("@{off},{value}"))
    } else {
        Some(format!("@{off},{},{value}", end.tag()))
    }
}

/// Apply one mutator to `input` in place.
///
/// Returns the parameter string for the chain entry, or `None` when the
/// mutator does not apply — in which case `input` is unchanged. `max_len`
/// bounds growth (spec S6.4: 64 KiB, [`MAX_MESSAGE_BYTES`]).
pub fn apply(
    m: ByteMutator,
    input: &mut Vec<u8>,
    rng: &mut ChaCha8Rng,
    donors: &Donors<'_>,
    max_len: usize,
) -> Option<String> {
    let len = input.len();
    match m {
        ByteMutator::BitFlip => {
            if len == 0 {
                return None;
            }
            let bit = below(rng, len * 8);
            *input.get_mut(bit / 8)? ^= 1u8 << (bit % 8);
            Some(format!("@{bit}"))
        }
        ByteMutator::ByteFlip => {
            if len == 0 {
                return None;
            }
            let at = below(rng, len);
            let byte = input.get_mut(at)?;
            *byte ^= 0xff;
            Some(format!("@{at}"))
        }
        ByteMutator::ByteInc => {
            if len == 0 {
                return None;
            }
            let at = below(rng, len);
            let byte = input.get_mut(at)?;
            *byte = byte.wrapping_add(1);
            Some(format!("@{at},+1"))
        }
        ByteMutator::ByteDec => {
            if len == 0 {
                return None;
            }
            let at = below(rng, len);
            let byte = input.get_mut(at)?;
            *byte = byte.wrapping_sub(1);
            Some(format!("@{at},-1"))
        }
        ByteMutator::ByteNeg => {
            if len == 0 {
                return None;
            }
            let at = below(rng, len);
            let byte = input.get_mut(at)?;
            *byte = byte.wrapping_neg();
            Some(format!("@{at}"))
        }
        ByteMutator::ByteRand => {
            if len == 0 {
                return None;
            }
            let at = below(rng, len);
            // `1..=254` so the byte always changes.
            let mask = count_up_to(rng, 254) as u8;
            let byte = input.get_mut(at)?;
            *byte ^= mask;
            Some(format!("@{at},^{mask}"))
        }
        ByteMutator::ByteAdd => arith_at(input, rng, 1),
        ByteMutator::WordAdd => arith_at(input, rng, 2),
        ByteMutator::DwordAdd => arith_at(input, rng, 4),
        ByteMutator::QwordAdd => arith_at(input, rng, 8),
        ByteMutator::ByteInteresting => interesting_at(input, rng, 1, &INTERESTING_8),
        ByteMutator::WordInteresting => interesting_at(input, rng, 2, &INTERESTING_16),
        ByteMutator::DwordInteresting => interesting_at(input, rng, 4, &INTERESTING_32),
        ByteMutator::BytesDelete => {
            if len < 2 {
                return None;
            }
            // Leave at least one byte behind.
            let count = count_up_to(rng, len - 1);
            let off = below(rng, len - count + 1);
            input.drain(off..off + count);
            Some(format!("@{off},-{count}"))
        }
        ByteMutator::BytesExpand => {
            if len == 0 {
                return None;
            }
            let count = count_up_to(rng, MAX_BLOCK.min(len));
            if len + count > max_len {
                return None;
            }
            let off = below(rng, len - count + 1);
            let block = input.get(off..off + count)?.to_vec();
            input.splice(off + count..off + count, block);
            Some(format!("@{off},+{count}"))
        }
        ByteMutator::BytesInsert => {
            if len == 0 {
                return None;
            }
            let count = count_up_to(rng, MAX_BLOCK);
            if len + count > max_len {
                return None;
            }
            let value = *input.get(below(rng, len))?;
            let off = below(rng, len + 1);
            input.splice(off..off, vec![value; count]);
            Some(format!("@{off},+{count}"))
        }
        ByteMutator::BytesRandInsert => {
            let count = count_up_to(rng, MAX_BLOCK);
            if len + count > max_len {
                return None;
            }
            let block: Vec<u8> = (0..count).map(|_| rng.random::<u8>()).collect();
            let off = below(rng, len + 1);
            input.splice(off..off, block);
            Some(format!("@{off},+{count}"))
        }
        ByteMutator::BytesSet => {
            if len == 0 {
                return None;
            }
            let count = count_up_to(rng, MAX_BLOCK.min(len));
            let off = below(rng, len - count + 1);
            let value = *input.get(below(rng, len))?;
            for slot in input.get_mut(off..off + count)? {
                *slot = value;
            }
            Some(format!("@{off},={count}"))
        }
        ByteMutator::BytesRandSet => {
            if len == 0 {
                return None;
            }
            let count = count_up_to(rng, MAX_BLOCK.min(len));
            let off = below(rng, len - count + 1);
            let value = rng.random::<u8>();
            for slot in input.get_mut(off..off + count)? {
                *slot = value;
            }
            Some(format!("@{off},={count}"))
        }
        ByteMutator::BytesCopy => {
            if len < 2 {
                return None;
            }
            let count = count_up_to(rng, MAX_BLOCK.min(len));
            let from = below(rng, len - count + 1);
            let to = below(rng, len - count + 1);
            let block = input.get(from..from + count)?.to_vec();
            input.get_mut(to..to + count)?.copy_from_slice(&block);
            Some(format!("@{to},={count},src={from}"))
        }
        ByteMutator::BytesInsertCopy => {
            if len == 0 {
                return None;
            }
            let count = count_up_to(rng, MAX_BLOCK.min(len));
            if len + count > max_len {
                return None;
            }
            let from = below(rng, len - count + 1);
            let to = below(rng, len + 1);
            let block = input.get(from..from + count)?.to_vec();
            input.splice(to..to, block);
            Some(format!("@{to},+{count},src={from}"))
        }
        ByteMutator::BytesSwap => {
            if len < 2 {
                return None;
            }
            let count = count_up_to(rng, (len / 2).min(MAX_BLOCK));
            let first = below(rng, len - 2 * count + 1);
            let lowest_second = first + count;
            let second = lowest_second + below(rng, len - count - lowest_second + 1);
            for k in 0..count {
                input.swap(first + k, second + k);
            }
            Some(format!("@{first}<->{second},={count}"))
        }
        ByteMutator::CrossoverInsert => {
            let (index, donor) = pick_donor(rng, donors)?;
            let count = count_up_to(rng, donor.len());
            if len + count > max_len {
                return None;
            }
            let from = below(rng, donor.len() - count + 1);
            let block = donor.get(from..from + count)?.to_vec();
            let to = below(rng, len + 1);
            input.splice(to..to, block);
            Some(format!("donor={index},@{to},+{count}"))
        }
        ByteMutator::CrossoverReplace => {
            if len == 0 {
                return None;
            }
            let (index, donor) = pick_donor(rng, donors)?;
            let count = count_up_to(rng, donor.len().min(len));
            let from = below(rng, donor.len() - count + 1);
            let to = below(rng, len - count + 1);
            let block = donor.get(from..from + count)?.to_vec();
            input.get_mut(to..to + count)?.copy_from_slice(&block);
            Some(format!("donor={index},@{to},={count}"))
        }
        ByteMutator::Splice => {
            let (index, donor) = pick_donor(rng, donors)?;
            let split = below(rng, len + 1);
            let donor_split = below(rng, donor.len() + 1);
            let tail = donor.get(donor_split..)?;
            if split + tail.len() > max_len {
                return None;
            }
            let tail = tail.to_vec();
            input.truncate(split);
            input.extend_from_slice(&tail);
            Some(format!("donor={index},@{split},+{}", tail.len()))
        }
    }
}

/// Choose a non-empty donor; `None` when the set is empty or all-empty.
fn pick_donor<'a>(rng: &mut ChaCha8Rng, donors: &Donors<'a>) -> Option<(usize, &'a [u8])> {
    if donors.0.is_empty() {
        return None;
    }
    let index = below(rng, donors.0.len());
    let donor = donors.0.get(index)?;
    if donor.is_empty() {
        return None;
    }
    Some((index, donor.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn donors() -> Vec<Vec<u8>> {
        vec![b"abc".to_vec()]
    }

    #[test]
    fn every_mutator_is_deterministic() {
        let pool = donors();
        for m in ByteMutator::ALL {
            let run = || {
                let mut rng = ChaCha8Rng::seed_from_u64(7);
                let mut buf = b"hello world".to_vec();
                let note = apply(m, &mut buf, &mut rng, &Donors(&pool), 65536);
                (note, buf)
            };
            let first = run();
            let second = run();
            assert_eq!(first, second, "{} is not deterministic", m.name());
        }
    }

    #[test]
    fn bitflip_changes_exactly_one_bit() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buf = vec![0u8; 8];
        let note = apply(
            ByteMutator::BitFlip,
            &mut buf,
            &mut rng,
            &Donors(&[]),
            65536,
        );
        assert!(note.is_some());
        let bits: u32 = buf.iter().map(|b| b.count_ones()).sum();
        assert_eq!(bits, 1);
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn delete_shrinks_insert_grows() {
        let pool = donors();
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        let mut buf = vec![0xabu8; 16];
        let note = apply(
            ByteMutator::BytesDelete,
            &mut buf,
            &mut rng,
            &Donors(&pool),
            65536,
        );
        assert!(note.is_some());
        assert!(buf.len() < 16, "delete did not shrink: {}", buf.len());
        assert!(!buf.is_empty());

        let mut buf = vec![0xabu8; 16];
        let note = apply(
            ByteMutator::BytesInsert,
            &mut buf,
            &mut rng,
            &Donors(&pool),
            65536,
        );
        assert!(note.is_some());
        assert!(buf.len() > 16, "insert did not grow: {}", buf.len());

        let mut buf = vec![0xabu8; 16];
        let note = apply(
            ByteMutator::BytesInsert,
            &mut buf,
            &mut rng,
            &Donors(&pool),
            16,
        );
        assert_eq!(note, None);
        assert_eq!(buf, vec![0xabu8; 16]);
    }

    #[test]
    fn crossover_without_donor_is_none() {
        for m in [
            ByteMutator::CrossoverInsert,
            ByteMutator::CrossoverReplace,
            ByteMutator::Splice,
        ] {
            let mut rng = ChaCha8Rng::seed_from_u64(7);
            let mut buf = b"hello world".to_vec();
            let note = apply(m, &mut buf, &mut rng, &Donors(&[]), 65536);
            assert_eq!(note, None, "{} with no donor", m.name());
            assert_eq!(buf, b"hello world".to_vec());
        }
    }

    /// `interesting_at` reads the `INTERESTING_*` consts where they are: the
    /// three tables are passed in as the `&[i8]`, `&[i16]` and `&[i32]` they
    /// are declared as, widened at use, so no per-call `Vec<i64>` is built.
    ///
    /// The three pinned notes are the mutators' output before the tables
    /// stopped being copied, so the draw order — offset, endianness, index —
    /// is the same one the schedule's determinism depends on (spec C5).
    #[test]
    fn interesting_at_reads_the_const_tables() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buf = b"hello world".to_vec();
        assert_eq!(
            interesting_at(&mut buf, &mut rng, 1, &INTERESTING_8),
            Some("@1,-1".to_string())
        );
        assert_eq!(
            buf,
            vec![104, 255, 108, 108, 111, 32, 119, 111, 114, 108, 100]
        );

        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buf = b"hello world".to_vec();
        assert_eq!(
            interesting_at(&mut buf, &mut rng, 2, &INTERESTING_16),
            Some("@1,be,1".to_string())
        );
        assert_eq!(buf, vec![104, 0, 1, 108, 111, 32, 119, 111, 114, 108, 100]);

        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buf = b"hello world".to_vec();
        assert_eq!(
            interesting_at(&mut buf, &mut rng, 4, &INTERESTING_32),
            Some("@1,be,16".to_string())
        );
        assert_eq!(buf, vec![104, 0, 0, 0, 16, 32, 119, 111, 114, 108, 100]);

        // Every draw writes one of the table's values, widened, in one of the
        // two byte orders — and touches nothing outside its own field.
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        for _ in 0..200 {
            let mut buf = vec![0x41u8; 8];
            let note = interesting_at(&mut buf, &mut rng, 2, &INTERESTING_16)
                .expect("an eight-byte buffer has room for a two-byte field");
            let mut parts = note.trim_start_matches('@').split(',');
            let off: usize = parts
                .next()
                .and_then(|text| text.parse().ok())
                .expect("the note opens with the offset");
            let end = match parts.next() {
                Some("be") => End::Be,
                Some("le") => End::Le,
                other => panic!("the note names a byte order, not {other:?}"),
            };
            let value: i64 = parts
                .next()
                .and_then(|text| text.parse().ok())
                .expect("the note ends with the value written");
            assert!(
                INTERESTING_16.iter().any(|&v| i64::from(v) == value),
                "{value} is not one of the 16-bit interesting values"
            );
            let field = buf.get(off..off + 2).expect("the field is in the buffer");
            assert_eq!(read_uint(field, end), value as u16 as u64);
            assert!(
                buf.iter()
                    .enumerate()
                    .all(|(i, &b)| (off..off + 2).contains(&i) || b == 0x41),
                "a byte outside the field changed: {buf:?}"
            );
        }

        // Nothing to write into, and nothing to choose from.
        let mut short = vec![0u8];
        assert_eq!(
            interesting_at(&mut short, &mut rng, 4, &INTERESTING_32),
            None
        );
        assert_eq!(interesting_at(&mut short, &mut rng, 1, &[] as &[i8]), None);
    }

    #[test]
    fn interesting_tables() {
        assert_eq!(INTERESTING_8, [-128, -1, 0, 1, 16, 32, 64, 100, 127]);
        assert_eq!(INTERESTING_16.len(), 19);
        assert_eq!(INTERESTING_32.len(), 27);
    }

    #[test]
    fn names_match_libafl() {
        assert_eq!(ByteMutator::QwordAdd.name(), "QwordAdd");
        assert_eq!(ByteMutator::ALL.len(), 25);
    }
}
