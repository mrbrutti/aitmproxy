//! Generic TLV length-relation inference over captured seeds (spec S4).
//!
//! A service nobody wrote a grammar for usually still frames its messages the
//! same way: a few fixed bytes, a length, then a body. [`infer`] recovers that
//! relation from captured seeds alone — where the length field sits, how wide
//! it is, its byte order, what it counts and by how much it is off — and
//! [`descriptor_to_spec`] renders the answer as an ordinary
//! [`MessageSpec`](crate::spec::MessageSpec) of `prefix`, `length` and
//! `payload`, so the inferred grammar is mutated and re-satisfied exactly like
//! a hand-written one.
//!
//! Inference guesses nothing: it needs at least two seeds of at least two
//! distinct lengths (otherwise a constant field fits every message), every
//! candidate must fit *every* seed, and a candidate space this small either
//! has one best answer or is refused. On refusal the lane falls back to
//! `raw` and names the reason.

use std::fmt;

use crate::spec::{Endian, FieldKind, FieldSpec, LenOf, MessageSpec, Relation, Transport};

/// The furthest into a message a length field may be looked for (spec S4).
pub const MAX_OFFSET: usize = 8;

/// The largest constant correction a candidate may carry, either way.
pub const MAX_ADJUST: i32 = 4;

/// The field widths a candidate may have, in bytes.
const WIDTHS: [u8; 3] = [1, 2, 4];

/// The prose `reply:` paragraph every inferred `tlv` grammar carries.
pub const TLV_REPLY: &str = "Opaque framing: any byte that comes back is a reply, and a TCP service that stays open without answering is alive too.";

/// A recovered length relation: where the length field sits, how wide it is,
/// how it is encoded, what it counts and by how much it is off.
///
/// For a message of `L` bytes whose field at `offset..offset + width` reads
/// `v` (spec S4): [`Counts::BodyOnly`] means `v + adjust == L - (offset +
/// width)`, [`Counts::Inclusive`] means `v + adjust == L - offset`, and
/// [`Counts::Whole`] means `v + adjust == L`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LenDescriptor {
    /// Where the length field starts.
    pub offset: usize,
    /// How wide the field is, in bytes: 1, 2 or 4.
    pub width: u8,
    /// The field's byte order.
    pub endian: Endian,
    /// What the field counts.
    pub counts: Counts,
    /// A constant correction, in `-4..=4`.
    pub adjust: i32,
}

/// What a length field counts (spec S4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Counts {
    /// The bytes after the length field.
    BodyOnly,
    /// The length field and everything after it (boofuzz's `inclusive`).
    Inclusive,
    /// The whole message, the bytes before the field included.
    Whole,
}

/// Why inference would not name a length relation.
///
/// [`fmt::Display`] gives the snake_case token the lane puts in a node's
/// `path_template` suffix and in every verdict `detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferRefusal {
    /// Fewer than two seeds: nothing to compare.
    TooFewSeeds,
    /// Every seed is the same length, so a constant field would fit.
    SameLength,
    /// No candidate of the space fits every seed.
    NoCandidateFits,
    /// Two candidates are equally good on every tie-break key. The space
    /// makes this unreachable; the variant exists so the refusal is explicit
    /// rather than an arbitrary pick.
    Ambiguous(Vec<LenDescriptor>),
}

impl fmt::Display for InferRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InferRefusal::TooFewSeeds => "too_few_seeds",
            InferRefusal::SameLength => "same_length",
            InferRefusal::NoCandidateFits => "no_candidate_fits",
            InferRefusal::Ambiguous(_) => "ambiguous",
        })
    }
}

impl std::error::Error for InferRefusal {}

// ---------------------------------------------------------------------------
// Inference
// ---------------------------------------------------------------------------

/// Recover the length relation the seeds agree on (spec S4).
///
/// The candidate space is `offset` in `0..=8`, `width` in `{1, 2, 4}`
/// (big-endian only at width 1), every [`Counts`], and `adjust` in `-4..=4`,
/// bounded by `offset + width <= ` the shortest seed. A candidate is kept
/// only when it fits every seed. Among those, the best is the one with the
/// smallest `|adjust|`, then `BodyOnly` before `Inclusive` before `Whole`,
/// then width 2 before 4 before 1, then big-endian before little, then the
/// smallest offset.
///
/// # Errors
///
/// [`InferRefusal`]: fewer than two seeds, seeds of one single length, no
/// fitting candidate, or (unreachably) a tie on every key.
pub fn infer(seeds: &[Vec<u8>]) -> Result<LenDescriptor, InferRefusal> {
    if seeds.len() < 2 {
        return Err(InferRefusal::TooFewSeeds);
    }
    let shortest = seeds.iter().map(Vec::len).min().unwrap_or(0);
    let first_len = seeds.first().map_or(0, Vec::len);
    if seeds.iter().all(|seed| seed.len() == first_len) {
        return Err(InferRefusal::SameLength);
    }

    let mut fitting = Vec::new();
    for offset in 0..=MAX_OFFSET {
        for width in WIDTHS {
            if offset + usize::from(width) > shortest {
                continue;
            }
            for endian in endians(width).iter().copied() {
                for counts in [Counts::BodyOnly, Counts::Inclusive, Counts::Whole] {
                    for adjust in -MAX_ADJUST..=MAX_ADJUST {
                        let candidate = LenDescriptor {
                            offset,
                            width,
                            endian,
                            counts: counts.clone(),
                            adjust,
                        };
                        if seeds.iter().all(|seed| fits(&candidate, seed)) {
                            fitting.push(candidate);
                        }
                    }
                }
            }
        }
    }

    best(fitting)
}

/// The byte orders a field of this width can have: one byte has no order.
fn endians(width: u8) -> &'static [Endian] {
    if width == 1 {
        &[Endian::Be]
    } else {
        &[Endian::Be, Endian::Le]
    }
}

/// Whether `candidate` explains this seed's length.
fn fits(candidate: &LenDescriptor, seed: &[u8]) -> bool {
    let (Some(declared), Some(target)) =
        (read_field(candidate, seed), target(candidate, seed.len()))
    else {
        return false;
    };
    declared + i64::from(candidate.adjust) == target
}

/// The value the candidate's field reads in `seed`, or `None` when the field
/// does not fit inside it.
fn read_field(candidate: &LenDescriptor, seed: &[u8]) -> Option<i64> {
    let end = candidate.offset.checked_add(usize::from(candidate.width))?;
    let bytes = seed.get(candidate.offset..end)?;
    let mut value: i64 = 0;
    match candidate.endian {
        Endian::Be => {
            for byte in bytes {
                value = (value << 8) | i64::from(*byte);
            }
        }
        Endian::Le => {
            for byte in bytes.iter().rev() {
                value = (value << 8) | i64::from(*byte);
            }
        }
    }
    Some(value)
}

/// What the candidate's field must add up to for a message of `len` bytes,
/// or `None` when the field does not fit in it.
fn target(candidate: &LenDescriptor, len: usize) -> Option<i64> {
    let after_field = candidate.offset.checked_add(usize::from(candidate.width))?;
    if after_field > len {
        return None;
    }
    let len = i64::try_from(len).ok()?;
    let offset = i64::try_from(candidate.offset).ok()?;
    let after_field = i64::try_from(after_field).ok()?;
    Some(match candidate.counts {
        Counts::BodyOnly => len - after_field,
        Counts::Inclusive => len - offset,
        Counts::Whole => len,
    })
}

/// The tie-break key of spec S4, smallest first.
fn rank(candidate: &LenDescriptor) -> (i32, u8, u8, u8, usize) {
    let counts = match candidate.counts {
        Counts::BodyOnly => 0,
        Counts::Inclusive => 1,
        Counts::Whole => 2,
    };
    let width = match candidate.width {
        2 => 0,
        4 => 1,
        _ => 2,
    };
    let endian = match candidate.endian {
        Endian::Be => 0,
        Endian::Le => 1,
    };
    (
        candidate.adjust.abs(),
        counts,
        width,
        endian,
        candidate.offset,
    )
}

/// The one best candidate, or the refusal that says why there is not one.
fn best(fitting: Vec<LenDescriptor>) -> Result<LenDescriptor, InferRefusal> {
    let Some(best) = fitting.iter().min_by_key(|candidate| rank(candidate)) else {
        return Err(InferRefusal::NoCandidateFits);
    };
    let tied: Vec<LenDescriptor> = fitting
        .iter()
        .filter(|candidate| rank(candidate) == rank(best))
        .cloned()
        .collect();
    match tied.as_slice() {
        [only] => Ok(only.clone()),
        _ => Err(InferRefusal::Ambiguous(tied)),
    }
}

// ---------------------------------------------------------------------------
// The generated grammar
// ---------------------------------------------------------------------------

/// Render a recovered relation as a grammar: `prefix` (only when the length
/// field is not first), `length`, `payload` (spec S4).
///
/// The `length` field measures `rest` — every byte after it — so the three
/// [`Counts`] become one `len` relation that
/// [`resatisfy`](crate::tree::resatisfy) reproduces exactly: `BodyOnly` is
/// `rest`, `Inclusive` adds the field's own width, and `Whole` adds the
/// prefix on top of that. The descriptor's `adjust` is what the wire value
/// is *missing*, so the relation's adjust is its negative.
#[must_use]
pub fn descriptor_to_spec(descriptor: &LenDescriptor) -> MessageSpec {
    let mut message = Vec::with_capacity(3);
    if descriptor.offset > 0 {
        message.push(FieldSpec {
            name: "prefix".to_string(),
            kind: FieldKind::Bytes {
                size: Some(descriptor.offset),
            },
            // Fixed bytes before the length are a magic/version header: a
            // mutator that rewrites them only makes the peer hang up.
            mutable: false,
            ..FieldSpec::default()
        });
    }
    message.push(FieldSpec {
        name: "length".to_string(),
        kind: length_kind(descriptor),
        relation: Some(Relation::Len {
            of: LenOf::Rest,
            inclusive: descriptor.counts != Counts::BodyOnly,
            adjust: relation_adjust(descriptor),
        }),
        ..FieldSpec::default()
    });
    message.push(FieldSpec {
        name: "payload".to_string(),
        kind: FieldKind::Bytes { size: None },
        ..FieldSpec::default()
    });

    MessageSpec {
        grammar: "tlv".to_string(),
        transport: Transport::Tcp,
        default_ports: Vec::new(),
        close_on_malformed_is_expected: false,
        reply: Some(TLV_REPLY.to_string()),
        message,
    }
}

/// The field type of a recovered width. The width is 1, 2 or 4 by
/// construction; anything else is read as one byte rather than panicking.
fn length_kind(descriptor: &LenDescriptor) -> FieldKind {
    match descriptor.width {
        2 => FieldKind::U16 {
            endian: descriptor.endian,
        },
        4 => FieldKind::U32 {
            endian: descriptor.endian,
        },
        _ => FieldKind::U8,
    }
}

/// The `len` relation's `adjust` for a descriptor.
///
/// `resatisfy` computes `rest + (inclusive ? width : 0) + adjust`, and the
/// wire value is `target - descriptor.adjust`, so `BodyOnly` and `Inclusive`
/// need `-adjust` and `Whole` needs the prefix added on top.
fn relation_adjust(descriptor: &LenDescriptor) -> i32 {
    let offset = i32::try_from(descriptor.offset).unwrap_or(i32::MAX);
    match descriptor.counts {
        Counts::BodyOnly | Counts::Inclusive => -descriptor.adjust,
        Counts::Whole => offset.saturating_sub(descriptor.adjust),
    }
}

#[cfg(test)]
mod tests {
    use super::{descriptor_to_spec, infer, Counts, InferRefusal, LenDescriptor};
    use crate::codec::decode_hex;
    use crate::spec::{Endian, FieldKind, LenOf, Relation};
    use crate::tree::{parse, render, resatisfy, FieldPath};

    fn hex(text: &str) -> Vec<u8> {
        decode_hex(text).expect("the test literal is hex")
    }

    /// Spec S4's worked set: a two-byte big-endian length counting the body.
    fn body_only_set() -> Vec<Vec<u8>> {
        vec![hex("0002aabb"), hex("00050102030405"), hex("0001ff")]
    }

    #[test]
    fn recovers_u16_be_body_only() {
        assert_eq!(
            infer(&body_only_set()),
            Ok(LenDescriptor {
                offset: 0,
                width: 2,
                endian: Endian::Be,
                counts: Counts::BodyOnly,
                adjust: 0,
            })
        );
    }

    #[test]
    fn refuses_non_fitting() {
        // The plan's literal for this case, `00 02 aa bb` and `00 09 01 02`,
        // is two seeds of the *same* length (4 bytes), which S4's "at least 2
        // distinct lengths" requirement refuses before any candidate is tried
        // — and a constant-field candidate does fit it ({offset 0, width 1,
        // be, body_only, adjust 3}), so `NoCandidateFits` is not reachable for
        // it. Pinned here, and reported to the architect.
        assert_eq!(
            infer(&[hex("0002aabb"), hex("00090102")]),
            Err(InferRefusal::SameLength)
        );

        // A second seed of a different length makes the contradiction real:
        // `00 09` declares nine body bytes and carries five.
        assert_eq!(
            infer(&[hex("0002aabb"), hex("00090102030405")]),
            Err(InferRefusal::NoCandidateFits)
        );
    }

    #[test]
    fn refuses_single_seed() {
        assert_eq!(infer(&[hex("0002aabb")]), Err(InferRefusal::TooFewSeeds));
        assert_eq!(infer(&[]), Err(InferRefusal::TooFewSeeds));
    }

    #[test]
    fn refuses_same_length() {
        assert_eq!(
            infer(&[hex("0002aabb"), hex("0002ccdd")]),
            Err(InferRefusal::SameLength)
        );
    }

    #[test]
    fn recovers_u16_le_inclusive() {
        assert_eq!(
            infer(&[hex("0300aa"), hex("0500aabbcc")]),
            Ok(LenDescriptor {
                offset: 0,
                width: 2,
                endian: Endian::Le,
                counts: Counts::Inclusive,
                adjust: 0,
            })
        );
    }

    #[test]
    fn refusals_display_as_snake_case_tokens() {
        assert_eq!(InferRefusal::TooFewSeeds.to_string(), "too_few_seeds");
        assert_eq!(InferRefusal::SameLength.to_string(), "same_length");
        assert_eq!(
            InferRefusal::NoCandidateFits.to_string(),
            "no_candidate_fits"
        );
        assert_eq!(InferRefusal::Ambiguous(Vec::new()).to_string(), "ambiguous");
    }

    #[test]
    fn descriptor_round_trips_through_tree() {
        let seeds = body_only_set();
        let descriptor = infer(&seeds).expect("the worked set fits one relation");
        let spec = descriptor_to_spec(&descriptor);
        spec.validate().expect("the generated spec is valid");
        assert_eq!(spec.grammar, "tlv");
        assert_eq!(spec.message.len(), 2, "no prefix field when offset is 0");

        for seed in &seeds {
            let mut tree = parse(&spec, seed).expect("the generated spec parses its own seed");
            let length = tree
                .get(&FieldPath::new("length"))
                .expect("the spec declares a length field");
            assert_eq!(length.kind, FieldKind::U16 { endian: Endian::Be });
            assert!(matches!(
                length.relation,
                Some(Relation::Len {
                    of: LenOf::Rest,
                    inclusive: false,
                    adjust: 0
                })
            ));
            assert!(!length.relation_broken, "the seed's own length fits");
            resatisfy(&mut tree, None);
            assert_eq!(&render(&tree), seed);
        }
    }

    #[test]
    fn prefixed_whole_and_adjusted_descriptors_round_trip() {
        // {offset 2, width 1, whole, adjust 0}: `aa bb` prefix, then a byte
        // counting the whole six-byte message.
        let whole = LenDescriptor {
            offset: 2,
            width: 1,
            endian: Endian::Be,
            counts: Counts::Whole,
            adjust: 0,
        };
        let spec = descriptor_to_spec(&whole);
        spec.validate().expect("the generated spec is valid");
        assert_eq!(spec.message.len(), 3, "a prefix field when offset is 2");
        let seed = hex("aabb06010203");
        let mut tree = parse(&spec, &seed).expect("the generated spec parses the message");
        assert_eq!(
            tree.get(&FieldPath::new("prefix"))
                .expect("prefix node")
                .bytes,
            hex("aabb")
        );
        assert!(
            !tree
                .get(&FieldPath::new("prefix"))
                .expect("prefix node")
                .mutable
        );
        assert_eq!(
            tree.get(&FieldPath::new("payload"))
                .expect("payload node")
                .bytes,
            hex("010203")
        );
        resatisfy(&mut tree, None);
        assert_eq!(render(&tree), seed);

        // {offset 0, width 2, be, inclusive, adjust 2}: the field reads
        // `L - offset - adjust` = 4 for a six-byte message.
        let adjusted = LenDescriptor {
            offset: 0,
            width: 2,
            endian: Endian::Be,
            counts: Counts::Inclusive,
            adjust: 2,
        };
        let seed = hex("000401020304");
        let spec = descriptor_to_spec(&adjusted);
        let mut tree = parse(&spec, &seed).expect("the generated spec parses the message");
        assert!(
            !tree
                .get(&FieldPath::new("length"))
                .expect("length node")
                .relation_broken
        );
        resatisfy(&mut tree, None);
        assert_eq!(render(&tree), seed);
    }
}
