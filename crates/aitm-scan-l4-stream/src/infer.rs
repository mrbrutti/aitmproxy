//! Generic TLV length-relation inference over captured seeds (spec S4).
//!
//! Task 7 declares [`LenDescriptor`] and [`Counts`] only, so
//! [`crate::grammar::SelectionReason::Inferred`] compiles; task 8 adds
//! `infer`, `InferRefusal` and `descriptor_to_spec` and keeps these two.

use crate::spec::Endian;

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
