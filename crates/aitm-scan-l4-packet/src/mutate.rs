//! Field boundary tables and seeded raw byte mutators — owned by scanner v2
//! track T5, plan task 4.
//!
//! A case is one [`Mutation`] applied to the seed [`PacketSpec`]: a header
//! field set verbatim, a fragment offset paired with its MF flag, a payload
//! length pass, or one of the fifteen byte mutators spec D8.5 names. Everything
//! here is pure — it builds a spec, it never sends one — and everything random
//! is drawn from [`Rng`], so a case replays from the `rng_seed` the evidence
//! records (spec D8.4).
//!
//! Two orderings matter and are therefore fixed:
//!
//! * [`boundary_cases`] returns each field's table in a declared order, so a
//!   point's first cases are the same on every run.
//! * the raw table is a **length pass first** (grow to each interesting length
//!   with zero fill, then the same lengths repeating the seed payload, then the
//!   truncations): an operator seed plus a length boundary reaches a
//!   length-triggered bug deterministically, where random bytes would not
//!   (plan call C26).

use std::fmt;

use aitm_proto_l4::craft::{Layer, PacketSpec};

use crate::fields::{FieldClass, FieldPath, Ipv4Field, Ipv6Field, TcpField, UdpField};
use crate::rng::Rng;

/// The payload lengths [`RawMutator::LongRun`] produces, before the case's
/// ceiling is applied: a kilobyte-ish run and the usual Ethernet MTU payload.
pub const LONG_RUN_SIZES: [usize; 3] = [256, 1024, 1472];

/// The default ceiling on a mutated payload: one Ethernet MTU of transport
/// payload, so a case stays a single unfragmented frame.
pub const DEFAULT_MAX_RAW_BYTES: usize = 1472;

/// The fixed eight-bit boundary values. A `U8` table is these six plus the two
/// values computed from the field's declared value (`^ 0x01`, `^ 0x80`).
pub const INTERESTING_8: [u8; 6] = [0, 1, 0x7f, 0x80, 0xfe, 0xff];

/// The fixed sixteen-bit boundary values.
pub const INTERESTING_16: [u16; 6] = [0, 1, 0x7fff, 0x8000, 0xfffe, 0xffff];

/// The fixed thirty-two-bit boundary values.
pub const INTERESTING_32: [u32; 5] = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];

/// The largest chunk a block mutator deletes, inserts, sets, copies or swaps.
const MAX_BLOCK: usize = 64;

/// A byte-level mutator over the seed's raw payload (spec D8.5's names, the
/// AFL/`LibAFL` havoc catalogue).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RawMutator {
    /// Flip one bit of one byte.
    BitFlip,
    /// Invert one byte.
    ByteFlip,
    /// Increment one byte, wrapping.
    ByteInc,
    /// Decrement one byte, wrapping.
    ByteDec,
    /// Negate one byte, wrapping.
    ByteNeg,
    /// Overwrite one byte with an [`INTERESTING_8`] value.
    ByteInteresting,
    /// Overwrite two big-endian bytes with an [`INTERESTING_16`] value.
    WordInteresting,
    /// Overwrite four big-endian bytes with an [`INTERESTING_32`] value.
    DwordInteresting,
    /// Delete a chunk.
    BytesDelete,
    /// Duplicate a chunk in place, growing the payload.
    BytesExpand,
    /// Insert a run of one repeated byte.
    BytesInsert,
    /// Overwrite a chunk with one repeated byte.
    BytesSet,
    /// Copy a chunk over another chunk of the same payload.
    BytesCopy,
    /// Swap two chunks of the same payload.
    BytesSwap,
    /// Replace the payload with a long run of one byte.
    LongRun,
}

impl RawMutator {
    /// Every mutator, in the order a random draw indexes.
    pub const ALL: [Self; 15] = [
        Self::BitFlip,
        Self::ByteFlip,
        Self::ByteInc,
        Self::ByteDec,
        Self::ByteNeg,
        Self::ByteInteresting,
        Self::WordInteresting,
        Self::DwordInteresting,
        Self::BytesDelete,
        Self::BytesExpand,
        Self::BytesInsert,
        Self::BytesSet,
        Self::BytesCopy,
        Self::BytesSwap,
        Self::LongRun,
    ];

    /// The mutator's D8.5 name, as it appears in a case label and in evidence.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::BitFlip => "bit_flip",
            Self::ByteFlip => "byte_flip",
            Self::ByteInc => "byte_inc",
            Self::ByteDec => "byte_dec",
            Self::ByteNeg => "byte_neg",
            Self::ByteInteresting => "byte_interesting",
            Self::WordInteresting => "word_interesting",
            Self::DwordInteresting => "dword_interesting",
            Self::BytesDelete => "bytes_delete",
            Self::BytesExpand => "bytes_expand",
            Self::BytesInsert => "bytes_insert",
            Self::BytesSet => "bytes_set",
            Self::BytesCopy => "bytes_copy",
            Self::BytesSwap => "bytes_swap",
            Self::LongRun => "long_run",
        }
    }

    /// Whether the mutator needs at least one payload byte to act on.
    ///
    /// The four that do not can grow an empty payload, which is why a random
    /// draw on an empty seed payload is restricted to them.
    #[must_use]
    pub const fn needs_bytes(&self) -> bool {
        !matches!(
            self,
            Self::BytesExpand | Self::BytesInsert | Self::BytesSet | Self::LongRun
        )
    }
}

/// What a [`Mutation::Grow`] appends: zero bytes, or the seed payload repeated
/// cyclically (an operator seed pushed past its own length boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrowFill {
    /// Append `0x00`.
    Zeros,
    /// Repeat the seed payload.
    Repeat,
}

/// One case: the single change applied to the seed [`PacketSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Set one header field verbatim.
    Field {
        /// The field to set.
        path: FieldPath,
        /// The value, truncated to the field's width.
        value: u32,
    },
    /// Set the IPv4 fragment offset and the MF flag together.
    Fragment {
        /// The fragment offset, in 8-byte units.
        offset: u16,
        /// Whether the MF (more fragments) flag is set.
        more_fragments: bool,
    },
    /// Grow the raw payload to `len` bytes.
    Grow {
        /// The target payload length, before the case's ceiling.
        len: usize,
        /// What the new bytes are.
        fill: GrowFill,
    },
    /// Keep the first `len` bytes of the raw payload.
    Truncate {
        /// The target payload length.
        len: usize,
    },
    /// Apply one byte mutator to the raw payload.
    Raw {
        /// The mutator.
        mutator: RawMutator,
        /// Where it acts, taken modulo the payload length.
        offset: usize,
        /// The mutator's argument: the value, length or source offset it needs.
        arg: u64,
    },
}

impl Mutation {
    /// The case's label, as it appears in evidence and in a point's case list.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Field { path, value } => format!("{path}={value}"),
            Self::Fragment {
                offset,
                more_fragments,
            } => format!(
                "ipv4.fragment_offset={offset},ipv4.flags={}",
                u8::from(*more_fragments)
            ),
            Self::Grow { len, fill } => match fill {
                GrowFill::Zeros => format!("grow:{len}"),
                GrowFill::Repeat => format!("grow:{len}:repeat"),
            },
            Self::Truncate { len } => format!("truncate:{len}"),
            Self::Raw {
                mutator, offset, ..
            } => format!("raw:{}@{offset}", mutator.name()),
        }
    }

    /// Apply the case to `seed`, returning the mutated spec.
    ///
    /// The seed is cloned, never modified. A header value is written verbatim —
    /// a deliberately wrong length or checksum is the point of the lane — and a
    /// payload never ends up longer than `max_raw_bytes`. The result is built
    /// once before it is returned, so a caller that builds it again cannot be
    /// surprised by a craft error mid-run.
    ///
    /// # Errors
    ///
    /// [`MutateError::LayerAbsent`] when the seed has no layer for the field (or
    /// no `Raw` layer for a payload case), [`MutateError::EmptyPayload`] when a
    /// byte mutator that needs bytes meets an empty payload, and
    /// [`MutateError::Craft`] when the mutated spec does not build.
    pub fn apply(
        &self,
        seed: &PacketSpec,
        max_raw_bytes: usize,
    ) -> Result<PacketSpec, MutateError> {
        let mut spec = seed.clone();
        match self {
            Self::Field { path, value } => set_field(&mut spec, *path, *value)?,
            Self::Fragment {
                offset,
                more_fragments,
            } => {
                set_field(
                    &mut spec,
                    FieldPath::Ipv4(Ipv4Field::FragmentOffset),
                    u32::from(*offset),
                )?;
                set_field(
                    &mut spec,
                    FieldPath::Ipv4(Ipv4Field::Flags),
                    u32::from(*more_fragments),
                )?;
            }
            Self::Grow { len, fill } => {
                let payload = raw_mut(&mut spec)?;
                // The ceiling is applied to the *requested* length, before a
                // byte is allocated: growing first and clamping after turns a
                // `len` of `usize::MAX` into an unbounded allocation for the
                // same clamped result (tester finding F3).
                grow(payload, (*len).min(max_raw_bytes), *fill);
                payload.truncate(max_raw_bytes);
            }
            Self::Truncate { len } => {
                let payload = raw_mut(&mut spec)?;
                payload.truncate(*len);
            }
            Self::Raw {
                mutator,
                offset,
                arg,
            } => {
                let payload = raw_mut(&mut spec)?;
                apply_raw(*mutator, payload, *offset, *arg, max_raw_bytes)?;
                payload.truncate(max_raw_bytes);
            }
        }
        spec.build()
            .map_err(|err| MutateError::Craft(err.to_string()))?;
        Ok(spec)
    }
}

/// Why a case could not be turned into a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutateError {
    /// The seed has no layer carrying this field.
    LayerAbsent(FieldPath),
    /// The mutator needs payload bytes and the seed payload is empty.
    EmptyPayload(RawMutator),
    /// The mutated spec did not build.
    Craft(String),
}

impl fmt::Display for MutateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayerAbsent(path) => {
                write!(f, "the seed has no layer for field path {path}")
            }
            Self::EmptyPayload(mutator) => {
                write!(f, "mutator {} needs a non-empty payload", mutator.name())
            }
            Self::Craft(message) => write!(f, "the mutated packet does not build: {message}"),
        }
    }
}

impl std::error::Error for MutateError {}

/// Set one header field of `spec` verbatim, on its first matching layer.
///
/// `u8` and `u16` fields truncate `value` to their width; `u32` fields take it
/// whole. The value is never validated: writing a wrong length, a wrong header
/// length or a wrong checksum is what a case is for.
///
/// # Errors
///
/// [`MutateError::LayerAbsent`] when `spec` carries no layer for `path`.
/// [`FieldPath::Raw`] is not a header field and is refused the same way.
pub fn set_field(spec: &mut PacketSpec, path: FieldPath, value: u32) -> Result<(), MutateError> {
    match path {
        FieldPath::Ipv4(field) => {
            let ip = spec
                .layers
                .iter_mut()
                .find_map(|layer| match layer {
                    Layer::Ipv4(ip) => Some(ip),
                    _ => None,
                })
                .ok_or(MutateError::LayerAbsent(path))?;
            match field {
                Ipv4Field::Ttl => ip.ttl = Some(as_u8(value)),
                Ipv4Field::Ihl => ip.ihl = Some(as_u8(value)),
                Ipv4Field::TotalLength => ip.total_length = Some(as_u16(value)),
                Ipv4Field::Flags => ip.flags = Some(as_u8(value)),
                Ipv4Field::FragmentOffset => ip.fragment_offset = Some(as_u16(value)),
                Ipv4Field::Checksum => ip.checksum = Some(as_u16(value)),
                Ipv4Field::Protocol => ip.protocol = Some(as_u8(value)),
                Ipv4Field::Identification => ip.identification = Some(as_u16(value)),
                Ipv4Field::Dscp => ip.dscp = Some(as_u8(value)),
                Ipv4Field::Ecn => ip.ecn = Some(as_u8(value)),
            }
        }
        FieldPath::Ipv6(field) => {
            let ip = spec
                .layers
                .iter_mut()
                .find_map(|layer| match layer {
                    Layer::Ipv6(ip) => Some(ip),
                    _ => None,
                })
                .ok_or(MutateError::LayerAbsent(path))?;
            match field {
                Ipv6Field::HopLimit => ip.hop_limit = Some(as_u8(value)),
                Ipv6Field::PayloadLength => ip.payload_length = Some(as_u16(value)),
                Ipv6Field::NextHeader => ip.next_header = Some(as_u8(value)),
                Ipv6Field::TrafficClass => ip.traffic_class = Some(as_u8(value)),
                Ipv6Field::FlowLabel => ip.flow_label = Some(value),
            }
        }
        FieldPath::Udp(field) => {
            let udp = spec
                .layers
                .iter_mut()
                .find_map(|layer| match layer {
                    Layer::Udp(udp) => Some(udp),
                    _ => None,
                })
                .ok_or(MutateError::LayerAbsent(path))?;
            match field {
                UdpField::SrcPort => udp.src_port = Some(as_u16(value)),
                UdpField::Length => udp.length = Some(as_u16(value)),
                UdpField::Checksum => udp.checksum = Some(as_u16(value)),
            }
        }
        FieldPath::Tcp(field) => {
            let tcp = spec
                .layers
                .iter_mut()
                .find_map(|layer| match layer {
                    Layer::Tcp(tcp) => Some(tcp),
                    _ => None,
                })
                .ok_or(MutateError::LayerAbsent(path))?;
            match field {
                TcpField::SrcPort => tcp.src_port = Some(as_u16(value)),
                TcpField::Seq => tcp.seq = Some(value),
                TcpField::Ack => tcp.ack = Some(value),
                TcpField::DataOffset => tcp.data_offset = Some(as_u8(value)),
                TcpField::Flags => tcp.flags = Some(as_u8(value)),
                TcpField::Window => tcp.window = Some(as_u16(value)),
                TcpField::Checksum => tcp.checksum = Some(as_u16(value)),
                TcpField::UrgentPtr => tcp.urgent_ptr = Some(as_u16(value)),
            }
        }
        FieldPath::Raw => return Err(MutateError::LayerAbsent(path)),
    }
    Ok(())
}

/// The value the seed actually puts on the wire for `path`.
///
/// Explicit `Some` fields and the craft layer's auto-completed `None` fields are
/// read the same way: from `seed.build()`, at the field's byte offset, so a
/// computed length or checksum is the real one. `link_len` is the length of the
/// link-layer header the seed carries (`0` for a layer-3 seed, `14` for
/// Ethernet). `None` when the layer is absent, the seed does not build, or the
/// built frame is shorter than the offset — our own bytes are trusted only after
/// `build()` succeeded, and only through checked slicing.
#[must_use]
pub fn declared_value(seed: &PacketSpec, path: FieldPath, link_len: usize) -> Option<u32> {
    if !has_layer(seed, path) {
        return None;
    }
    let bytes = seed.build().ok()?;
    match path {
        FieldPath::Ipv4(field) => ipv4_value(&bytes, link_len, field),
        FieldPath::Ipv6(field) => ipv6_value(&bytes, link_len, field),
        FieldPath::Udp(field) => {
            udp_value(&bytes, transport_offset(seed, &bytes, link_len)?, field)
        }
        FieldPath::Tcp(field) => {
            tcp_value(&bytes, transport_offset(seed, &bytes, link_len)?, field)
        }
        FieldPath::Raw => None,
    }
}

/// [`declared_value`] for the three checksum paths: the checksum the seed ships.
///
/// `None` for any other path, and for a seed whose layer is absent or that does
/// not build.
#[must_use]
pub fn computed_checksum(seed: &PacketSpec, path: FieldPath, link_len: usize) -> Option<u16> {
    if path.class() != FieldClass::Checksum {
        return None;
    }
    u16::try_from(declared_value(seed, path, link_len)?).ok()
}

/// The deterministic boundary table for `path`: every case the lane sends
/// before it starts drawing random ones.
///
/// Sizes are fixed per class and the tables are **not** de-duplicated, so a
/// field whose declared value happens to be a boundary value still contributes
/// its full table and a point's case count does not depend on the seed. The one
/// exception is [`FieldPath::Raw`]'s length pass, where duplicate lengths are
/// dropped: `max_raw_bytes` bounds it, so repeated lengths are the common case.
#[must_use]
pub fn boundary_cases(
    path: FieldPath,
    seed: &PacketSpec,
    link_len: usize,
    max_raw_bytes: usize,
) -> Vec<Mutation> {
    let field = |value: u32| Mutation::Field { path, value };
    match path.class() {
        FieldClass::U8 => {
            let declared = as_u8(declared_value(seed, path, link_len).unwrap_or(0));
            INTERESTING_8
                .into_iter()
                .chain([declared ^ 0x01, declared ^ 0x80])
                .map(|value| field(u32::from(value)))
                .collect()
        }
        FieldClass::U16 => {
            let declared = as_u16(declared_value(seed, path, link_len).unwrap_or(0));
            INTERESTING_16
                .into_iter()
                .chain([
                    declared.wrapping_sub(1),
                    declared.wrapping_add(1),
                    declared.swap_bytes(),
                ])
                .map(|value| field(u32::from(value)))
                .collect()
        }
        FieldClass::U32 => INTERESTING_32.into_iter().map(field).collect(),
        FieldClass::HeaderWords => [0, 1, 2, 3, 4, 6, 7, 15].into_iter().map(field).collect(),
        FieldClass::Checksum => {
            let computed = computed_checksum(seed, path, link_len).unwrap_or(0);
            [computed ^ 0xffff, 0x0000, 0xffff]
                .into_iter()
                .map(|value| field(u32::from(value)))
                .collect()
        }
        FieldClass::Ipv4Flags => (0..=7u32).map(field).collect(),
        FieldClass::FragmentOffset => {
            let mut out = Vec::with_capacity(6);
            for offset in [1u16, 8, 0x1fff] {
                for more_fragments in [true, false] {
                    out.push(Mutation::Fragment {
                        offset,
                        more_fragments,
                    });
                }
            }
            out
        }
        FieldClass::Ttl => [0, 1, 2, 255].into_iter().map(field).collect(),
        FieldClass::TcpFlags => [0x00, 0x03, 0x29, 0xff, 0x06, 0x10, 0xc2]
            .into_iter()
            .map(field)
            .collect(),
        FieldClass::Raw => length_pass(seed_payload(seed).len(), max_raw_bytes),
    }
}

/// The raw field's deterministic length pass (plan call C26).
fn length_pass(seed_len: usize, max_raw_bytes: usize) -> Vec<Mutation> {
    let mut lengths: Vec<usize> = [
        seed_len.saturating_add(1),
        seed_len.saturating_add(2),
        seed_len.saturating_mul(2),
        16,
        64,
        256,
        1024,
        1472,
    ]
    .into_iter()
    .filter(|len| *len > seed_len && *len <= max_raw_bytes)
    .collect();
    lengths.sort_unstable();
    lengths.dedup();

    let mut out: Vec<Mutation> = Vec::with_capacity(lengths.len() * 2 + 3);
    for fill in [GrowFill::Zeros, GrowFill::Repeat] {
        out.extend(lengths.iter().map(|len| Mutation::Grow { len: *len, fill }));
    }

    let mut cuts: Vec<usize> = [seed_len.saturating_sub(1), 1, 0]
        .into_iter()
        .filter(|len| *len < seed_len)
        .collect();
    cuts.sort_unstable_by(|a, b| b.cmp(a));
    cuts.dedup();
    out.extend(cuts.into_iter().map(|len| Mutation::Truncate { len }));
    out
}

/// One randomly drawn case for `path`, from the point's seeded generator.
///
/// Header fields draw a value within the field's width; `raw` draws a mutator
/// (restricted to the ones that do not need bytes when the seed payload is
/// empty), an offset inside the payload and the mutator's argument. Every draw
/// goes through [`Rng`] in a fixed order, so the same seed replays the same
/// sequence of cases.
#[must_use]
pub fn random_case(path: FieldPath, seed: &PacketSpec, rng: &mut Rng) -> Mutation {
    let mut field = |width: u64| Mutation::Field {
        path,
        value: as_u32(rng.below(width)),
    };
    // The IP protocol / next-header fields draw a byte that excludes the
    // tunnelling numbers, so a case never asks the kernel to decapsulate the
    // seed as an inner packet aimed off the pinned destination (SEC6).
    if matches!(
        path,
        FieldPath::Ipv4(Ipv4Field::Protocol) | FieldPath::Ipv6(Ipv6Field::NextHeader)
    ) {
        return Mutation::Field {
            path,
            value: draw_ip_protocol(rng),
        };
    }
    match path.class() {
        FieldClass::U8 | FieldClass::Ttl | FieldClass::TcpFlags => field(0x100),
        FieldClass::U16 | FieldClass::Checksum => field(0x1_0000),
        FieldClass::U32 => field(0x1_0000_0000),
        FieldClass::HeaderWords => field(0x10),
        FieldClass::Ipv4Flags => field(0x8),
        FieldClass::FragmentOffset => Mutation::Fragment {
            offset: as_u16(as_u32(rng.below(0x2000))),
            more_fragments: rng.below(2) == 1,
        },
        FieldClass::Raw => {
            let payload_len = seed_payload(seed).len();
            let candidates: Vec<RawMutator> = if payload_len == 0 {
                RawMutator::ALL
                    .into_iter()
                    .filter(|mutator| !mutator.needs_bytes())
                    .collect()
            } else {
                RawMutator::ALL.to_vec()
            };
            let mutator = rng
                .pick(&candidates)
                .copied()
                .unwrap_or(RawMutator::BytesInsert);
            let offset = as_usize(rng.below(as_u64(payload_len)));
            Mutation::Raw {
                mutator,
                offset,
                arg: rng.next_u64(),
            }
        }
    }
}

/// The IP protocol numbers never drawn for `ipv4.protocol`/`ipv6.next_header`:
/// 4 (IP-in-IP), 41 (IPv6-in-IPv4) and 47 (GRE) ask a stock host to
/// decapsulate the seed payload as an inner packet whose addresses are not the
/// pinned destination (review finding SEC6).
const TUNNELLING_PROTOS: [u8; 3] = [4, 41, 47];

/// A uniform protocol byte drawn from the 253 numbers that are not a
/// tunnelling protocol: the `index`-th value of `0..=255` with
/// [`TUNNELLING_PROTOS`] removed, so the draw stays single-pass and seed-stable.
fn draw_ip_protocol(rng: &mut Rng) -> u32 {
    let span = 256 - TUNNELLING_PROTOS.len() as u64;
    let mut value = rng.below(span);
    for excluded in TUNNELLING_PROTOS {
        if value >= u64::from(excluded) {
            value += 1;
        }
    }
    as_u32(value)
}

/// Apply one byte mutator in place. `payload` is the lane's own buffer, so the
/// only hostile input here is `arg`, which every branch reduces modulo a length
/// it has already checked.
fn apply_raw(
    mutator: RawMutator,
    payload: &mut Vec<u8>,
    offset: usize,
    arg: u64,
    max_raw_bytes: usize,
) -> Result<(), MutateError> {
    if payload.is_empty() && mutator.needs_bytes() {
        return Err(MutateError::EmptyPayload(mutator));
    }
    let len = payload.len();
    let at = if len == 0 { 0 } else { offset % len };
    let byte = as_u8(as_u32((arg >> 32) & 0xff));
    let source = if len == 0 {
        0
    } else {
        as_usize((arg >> 16) & 0xffff) % len
    };

    match mutator {
        RawMutator::BitFlip => {
            if let Some(slot) = payload.get_mut(at) {
                *slot ^= 1u8 << (arg % 8);
            }
        }
        RawMutator::ByteFlip => {
            if let Some(slot) = payload.get_mut(at) {
                *slot ^= 0xff;
            }
        }
        RawMutator::ByteInc => {
            if let Some(slot) = payload.get_mut(at) {
                *slot = slot.wrapping_add(1);
            }
        }
        RawMutator::ByteDec => {
            if let Some(slot) = payload.get_mut(at) {
                *slot = slot.wrapping_sub(1);
            }
        }
        RawMutator::ByteNeg => {
            if let Some(slot) = payload.get_mut(at) {
                *slot = slot.wrapping_neg();
            }
        }
        RawMutator::ByteInteresting => {
            let value = pick_const(&INTERESTING_8, arg);
            if let Some(slot) = payload.get_mut(at) {
                *slot = value;
            }
        }
        RawMutator::WordInteresting => {
            let value = pick_const(&INTERESTING_16, arg);
            write_be(payload, at, &value.to_be_bytes());
        }
        RawMutator::DwordInteresting => {
            let value = pick_const(&INTERESTING_32, arg);
            write_be(payload, at, &value.to_be_bytes());
        }
        RawMutator::BytesDelete => {
            let span = len.saturating_sub(at);
            let end = at.saturating_add(block_len(arg, span)).min(len);
            payload.drain(at..end);
        }
        RawMutator::BytesExpand => {
            let span = len.saturating_sub(at);
            let count = block_len(arg, span);
            let chunk: Vec<u8> = match payload.get(at..at.saturating_add(count).min(len)) {
                Some(slice) if !slice.is_empty() => slice.to_vec(),
                _ => vec![0u8; count],
            };
            splice_in(payload, at, chunk);
        }
        RawMutator::BytesInsert => {
            let count = block_len(arg, 0);
            splice_in(payload, at, vec![byte; count]);
        }
        RawMutator::BytesSet => {
            if len == 0 {
                payload.extend(std::iter::repeat_n(byte, block_len(arg, 0)));
            } else {
                let span = len.saturating_sub(at);
                let end = at.saturating_add(block_len(arg, span)).min(len);
                if let Some(slice) = payload.get_mut(at..end) {
                    slice.fill(byte);
                }
            }
        }
        RawMutator::BytesCopy => {
            let span = len.saturating_sub(at).min(len.saturating_sub(source));
            let count = block_len(arg, span);
            let chunk: Vec<u8> = match payload.get(source..source.saturating_add(count).min(len)) {
                Some(slice) => slice.to_vec(),
                None => Vec::new(),
            };
            let end = at.saturating_add(chunk.len()).min(len);
            if let Some(slot) = payload.get_mut(at..end) {
                slot.copy_from_slice(chunk.get(..slot.len()).unwrap_or_default());
            }
        }
        RawMutator::BytesSwap => {
            let low = at.min(source);
            let high = at.max(source);
            let gap = high.saturating_sub(low);
            if gap > 0 {
                let count = block_len(arg, gap.min(len.saturating_sub(high)));
                for step in 0..count {
                    let (a, b) = (low.saturating_add(step), high.saturating_add(step));
                    if a < len && b < len {
                        payload.swap(a, b);
                    }
                }
            }
        }
        RawMutator::LongRun => {
            let size = pick_const(&LONG_RUN_SIZES, arg).min(max_raw_bytes);
            *payload = vec![byte; size];
        }
    }
    Ok(())
}

/// Grow `payload` to `len` bytes; a `len` at or below the current length is a
/// no-op.
///
/// `len` is what the caller has already clamped to its ceiling, so this
/// allocates at most that much (tester finding F3).
fn grow(payload: &mut Vec<u8>, len: usize, fill: GrowFill) {
    if len <= payload.len() {
        return;
    }
    match fill {
        GrowFill::Zeros => payload.resize(len, 0),
        GrowFill::Repeat => {
            let base = payload.clone();
            if base.is_empty() {
                payload.resize(len, 0);
                return;
            }
            while payload.len() < len {
                let next = base.get(payload.len() % base.len()).copied().unwrap_or(0);
                payload.push(next);
            }
        }
    }
}

/// Insert `chunk` at `at`, clamped to the end of `payload`.
fn splice_in(payload: &mut Vec<u8>, at: usize, chunk: Vec<u8>) {
    let at = at.min(payload.len());
    let tail = payload.split_off(at);
    payload.extend(chunk);
    payload.extend(tail);
}

/// Write `raw` at `at`, sliding left so the write fits; a payload shorter than
/// `raw` is left unchanged.
fn write_be(payload: &mut [u8], at: usize, raw: &[u8]) {
    let Some(last) = payload.len().checked_sub(raw.len()) else {
        return;
    };
    let start = at.min(last);
    if let Some(slot) = payload.get_mut(start..start.saturating_add(raw.len())) {
        slot.copy_from_slice(raw);
    }
}

/// The chunk length a block mutator uses: `1..=MAX_BLOCK`, further bounded by
/// `span` when `span` is non-zero.
fn block_len(arg: u64, span: usize) -> usize {
    let cap = if span == 0 {
        MAX_BLOCK
    } else {
        span.min(MAX_BLOCK)
    };
    let modulus = as_u64(cap).max(1);
    as_usize(arg % modulus).saturating_add(1)
}

/// The element of a fixed table `arg` selects.
fn pick_const<T: Copy + Default>(table: &[T], arg: u64) -> T {
    if table.is_empty() {
        return T::default();
    }
    let index = as_usize(arg % as_u64(table.len()).max(1));
    table.get(index).copied().unwrap_or_default()
}

/// The seed's raw payload: the last `Raw` layer, or empty when it has none.
fn seed_payload(spec: &PacketSpec) -> &[u8] {
    spec.layers
        .iter()
        .rev()
        .find_map(|layer| match layer {
            Layer::Raw(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The last `Raw` layer's buffer, for a payload case.
fn raw_mut(spec: &mut PacketSpec) -> Result<&mut Vec<u8>, MutateError> {
    spec.layers
        .iter_mut()
        .rev()
        .find_map(|layer| match layer {
            Layer::Raw(bytes) => Some(bytes),
            _ => None,
        })
        .ok_or(MutateError::LayerAbsent(FieldPath::Raw))
}

/// Whether `spec` carries the layer `path` names.
fn has_layer(spec: &PacketSpec, path: FieldPath) -> bool {
    spec.layers.iter().any(|layer| match path {
        FieldPath::Ipv4(_) => matches!(layer, Layer::Ipv4(_)),
        FieldPath::Ipv6(_) => matches!(layer, Layer::Ipv6(_)),
        FieldPath::Udp(_) => matches!(layer, Layer::Udp(_)),
        FieldPath::Tcp(_) => matches!(layer, Layer::Tcp(_)),
        FieldPath::Raw => matches!(layer, Layer::Raw(_)),
    })
}

/// Where the transport header starts in the built frame: after the link header
/// and the network header the seed declares (IPv4's own `ihl`, 40 bytes for
/// IPv6).
fn transport_offset(spec: &PacketSpec, bytes: &[u8], link_len: usize) -> Option<usize> {
    for layer in &spec.layers {
        match layer {
            Layer::Ipv4(_) => {
                let ihl = usize::from(bytes.get(link_len)? & 0x0f);
                return link_len.checked_add(ihl.checked_mul(4)?);
            }
            Layer::Ipv6(_) => return link_len.checked_add(40),
            _ => {}
        }
    }
    Some(link_len)
}

/// An IPv4 header field, read from the built frame at `base`.
fn ipv4_value(bytes: &[u8], base: usize, field: Ipv4Field) -> Option<u32> {
    match field {
        Ipv4Field::Ttl => u8_at(bytes, base.checked_add(8)?),
        Ipv4Field::Ihl => u8_at(bytes, base).map(|value| value & 0x0f),
        Ipv4Field::TotalLength => u16_at(bytes, base.checked_add(2)?),
        Ipv4Field::Flags => u16_at(bytes, base.checked_add(6)?).map(|value| value >> 13),
        Ipv4Field::FragmentOffset => {
            u16_at(bytes, base.checked_add(6)?).map(|value| value & 0x1fff)
        }
        Ipv4Field::Checksum => u16_at(bytes, base.checked_add(10)?),
        Ipv4Field::Protocol => u8_at(bytes, base.checked_add(9)?),
        Ipv4Field::Identification => u16_at(bytes, base.checked_add(4)?),
        Ipv4Field::Dscp => u8_at(bytes, base.checked_add(1)?).map(|value| value >> 2),
        Ipv4Field::Ecn => u8_at(bytes, base.checked_add(1)?).map(|value| value & 0x03),
    }
}

/// An IPv6 header field, read from the built frame at `base`.
fn ipv6_value(bytes: &[u8], base: usize, field: Ipv6Field) -> Option<u32> {
    match field {
        Ipv6Field::HopLimit => u8_at(bytes, base.checked_add(7)?),
        Ipv6Field::PayloadLength => u16_at(bytes, base.checked_add(4)?),
        Ipv6Field::NextHeader => u8_at(bytes, base.checked_add(6)?),
        Ipv6Field::TrafficClass => {
            let high = u8_at(bytes, base)? & 0x0f;
            let low = u8_at(bytes, base.checked_add(1)?)? >> 4;
            Some((high << 4) | low)
        }
        Ipv6Field::FlowLabel => u32_at(bytes, base).map(|value| value & 0x000f_ffff),
    }
}

/// A UDP header field, read from the built frame at the transport offset.
fn udp_value(bytes: &[u8], base: usize, field: UdpField) -> Option<u32> {
    match field {
        UdpField::SrcPort => u16_at(bytes, base),
        UdpField::Length => u16_at(bytes, base.checked_add(4)?),
        UdpField::Checksum => u16_at(bytes, base.checked_add(6)?),
    }
}

/// A TCP header field, read from the built frame at the transport offset.
fn tcp_value(bytes: &[u8], base: usize, field: TcpField) -> Option<u32> {
    match field {
        TcpField::SrcPort => u16_at(bytes, base),
        TcpField::Seq => u32_at(bytes, base.checked_add(4)?),
        TcpField::Ack => u32_at(bytes, base.checked_add(8)?),
        TcpField::DataOffset => u8_at(bytes, base.checked_add(12)?).map(|value| value >> 4),
        TcpField::Flags => u8_at(bytes, base.checked_add(13)?),
        TcpField::Window => u16_at(bytes, base.checked_add(14)?),
        TcpField::Checksum => u16_at(bytes, base.checked_add(16)?),
        TcpField::UrgentPtr => u16_at(bytes, base.checked_add(18)?),
    }
}

/// One byte of `bytes`, widened.
fn u8_at(bytes: &[u8], index: usize) -> Option<u32> {
    bytes.get(index).map(|byte| u32::from(*byte))
}

/// Two big-endian bytes of `bytes`, widened.
fn u16_at(bytes: &[u8], index: usize) -> Option<u32> {
    let end = index.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(index..end)?.try_into().ok()?;
    Some(u32::from(u16::from_be_bytes(raw)))
}

/// Four big-endian bytes of `bytes`.
fn u32_at(bytes: &[u8], index: usize) -> Option<u32> {
    let end = index.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(index..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(raw))
}

/// `value` truncated to eight bits.
fn as_u8(value: u32) -> u8 {
    u8::try_from(value & 0xff).unwrap_or(0)
}

/// `value` truncated to sixteen bits.
fn as_u16(value: u32) -> u16 {
    u16::try_from(value & 0xffff).unwrap_or(0)
}

/// `value` truncated to thirty-two bits.
fn as_u32(value: u64) -> u32 {
    u32::try_from(value & 0xffff_ffff).unwrap_or(0)
}

/// `value` as a `u64`, saturating (a `usize` is never wider here).
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// `value` as a `usize`, saturating.
fn as_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    use aitm_proto_l4::craft::{Ipv4Spec, Layer, PacketSpec, TcpSpec, UdpSpec};

    use crate::fields::{FieldPath, Ipv4Field, TcpField, UdpField};
    use crate::rng::Rng;

    use super::{
        boundary_cases, computed_checksum, declared_value, random_case, GrowFill, MutateError,
        Mutation, RawMutator,
    };

    /// `craft.rs`'s known packet: `[Ipv4 { dst: 127.0.0.1 }, Udp { dst_port: 9 },
    /// Raw(payload)]`, no link layer, so `link_len` is `0`.
    fn udp_seed(payload: &[u8]) -> PacketSpec {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
    }

    /// The same seed over TCP.
    fn tcp_seed(payload: &[u8]) -> PacketSpec {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    dst_port: Some(9),
                    ..TcpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
    }

    fn payload_of(spec: &PacketSpec) -> Vec<u8> {
        spec.layers
            .iter()
            .rev()
            .find_map(|layer| match layer {
                Layer::Raw(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn ipv4_of(spec: &PacketSpec) -> Ipv4Spec {
        spec.layers
            .iter()
            .find_map(|layer| match layer {
                Layer::Ipv4(ip) => Some(ip.clone()),
                _ => None,
            })
            .expect("the seed has an IPv4 layer")
    }

    fn labels(cases: &[Mutation]) -> Vec<String> {
        cases.iter().map(Mutation::label).collect()
    }

    fn case_labelled(cases: &[Mutation], label: &str) -> Mutation {
        cases
            .iter()
            .find(|case| case.label() == label)
            .unwrap_or_else(|| panic!("no case labelled {label}"))
            .clone()
    }

    fn field_values(cases: &[Mutation]) -> Vec<u32> {
        cases
            .iter()
            .filter_map(|case| match case {
                Mutation::Field { value, .. } => Some(*value),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn table_sizes() {
        let seed = udp_seed(b"probe");
        for (path, len) in [
            (FieldPath::Ipv4(Ipv4Field::Ttl), 4),
            (FieldPath::Ipv4(Ipv4Field::Flags), 8),
            (FieldPath::Ipv4(Ipv4Field::FragmentOffset), 6),
            (FieldPath::Ipv4(Ipv4Field::Ihl), 8),
            (FieldPath::Ipv4(Ipv4Field::Dscp), 8),
            (FieldPath::Ipv4(Ipv4Field::Identification), 9),
            (FieldPath::Ipv4(Ipv4Field::Checksum), 3),
            (FieldPath::Udp(UdpField::Length), 9),
            (FieldPath::Udp(UdpField::Checksum), 3),
        ] {
            assert_eq!(boundary_cases(path, &seed, 0, 1472).len(), len, "{path}");
        }

        let tcp = tcp_seed(b"probe");
        for (path, len) in [
            (FieldPath::Tcp(TcpField::Seq), 5),
            (FieldPath::Tcp(TcpField::Flags), 7),
            (FieldPath::Tcp(TcpField::DataOffset), 8),
        ] {
            assert_eq!(boundary_cases(path, &tcp, 0, 1472).len(), len, "{path}");
        }

        // The raw length pass: grow lengths x two fills, then the truncations.
        assert_eq!(
            boundary_cases(FieldPath::Raw, &seed, 0, 1472).len(),
            19,
            "5-byte seed, max 1472: {{6,7,10,16,64,256,1024,1472}} x 2 + 3"
        );
        assert_eq!(
            boundary_cases(FieldPath::Raw, &udp_seed(&[0x41; 16]), 0, 1472).len(),
            17,
            "16-byte seed, max 1472: {{17,18,32,64,256,1024,1472}} x 2 + 3"
        );
        assert_eq!(
            boundary_cases(FieldPath::Raw, &udp_seed(&[0x41; 6]), 0, 64).len(),
            13,
            "6-byte seed, max 64: {{7,8,12,16,64}} x 2 + 3"
        );
    }

    #[test]
    fn length_pass_order_and_labels() {
        let seed = udp_seed(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        let cases = boundary_cases(FieldPath::Raw, &seed, 0, 1472);
        assert_eq!(
            labels(&cases)[..3],
            [
                "grow:7".to_string(),
                "grow:8".to_string(),
                "grow:12".to_string()
            ]
        );

        let grown = case_labelled(&cases, "grow:8")
            .apply(&seed, 1472)
            .expect("grow applies");
        assert_eq!(
            payload_of(&grown),
            vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00]
        );

        let repeated = case_labelled(&cases, "grow:8:repeat")
            .apply(&seed, 1472)
            .expect("repeat grow applies");
        assert_eq!(
            payload_of(&repeated),
            vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0xde, 0xad]
        );

        let cut = case_labelled(&cases, "truncate:1")
            .apply(&seed, 1472)
            .expect("truncate applies");
        assert_eq!(payload_of(&cut), vec![0xde]);

        let empty = case_labelled(&cases, "truncate:0")
            .apply(&seed, 1472)
            .expect("truncate to nothing applies");
        assert_eq!(payload_of(&empty), Vec::<u8>::new());
        assert!(empty.build().is_ok(), "an empty payload still builds");
    }

    #[test]
    fn checksum_table_inverts_the_computed_value() {
        let seed = udp_seed(b"probe");
        assert_eq!(
            computed_checksum(&seed, FieldPath::Ipv4(Ipv4Field::Checksum), 0),
            Some(0xFBCB),
            "the literal craft.rs pins"
        );
        assert_eq!(
            field_values(&boundary_cases(
                FieldPath::Ipv4(Ipv4Field::Checksum),
                &seed,
                0,
                1472
            )),
            vec![0x0434, 0x0000, 0xffff]
        );
    }

    #[test]
    fn u16_table_brackets_declared() {
        let seed = udp_seed(b"probe");
        assert_eq!(
            declared_value(&seed, FieldPath::Udp(UdpField::Length), 0),
            Some(13),
            "8 header bytes plus the 5-byte payload"
        );
        let values = field_values(&boundary_cases(
            FieldPath::Udp(UdpField::Length),
            &seed,
            0,
            1472,
        ));
        for expected in [12, 14, 0x0d00] {
            assert!(values.contains(&expected), "{expected:#x} in {values:?}");
        }
    }

    #[test]
    fn apply_writes_verbatim() {
        let seed = udp_seed(b"probe");
        let bytes = Mutation::Field {
            path: FieldPath::Ipv4(Ipv4Field::Ttl),
            value: 0,
        }
        .apply(&seed, 1472)
        .expect("ttl applies")
        .build()
        .expect("the mutated spec builds");
        assert_eq!(bytes.get(8), Some(&0u8), "ttl is IPv4 byte 8");

        let bytes = Mutation::Field {
            path: FieldPath::Udp(UdpField::Length),
            value: 0xffff,
        }
        .apply(&seed, 1472)
        .expect("length applies")
        .build()
        .expect("the mutated spec builds");
        assert_eq!(
            bytes.get(24..26),
            Some([0xff, 0xff].as_slice()),
            "a lying UDP length reaches the wire verbatim"
        );
    }

    #[test]
    fn fragment_sets_both_fields() {
        let seed = udp_seed(b"probe");
        let more = Mutation::Fragment {
            offset: 8,
            more_fragments: true,
        }
        .apply(&seed, 1472)
        .expect("fragment applies");
        let ip = ipv4_of(&more);
        assert_eq!(ip.fragment_offset, Some(8));
        assert_eq!(ip.flags, Some(1));

        let last = Mutation::Fragment {
            offset: 8,
            more_fragments: false,
        }
        .apply(&seed, 1472)
        .expect("fragment applies");
        assert_eq!(ipv4_of(&last).flags, Some(0));
    }

    #[test]
    fn labels_render_the_case() {
        assert_eq!(
            Mutation::Field {
                path: FieldPath::Ipv4(Ipv4Field::Ttl),
                value: 0,
            }
            .label(),
            "ipv4.ttl=0"
        );
        assert_eq!(
            Mutation::Fragment {
                offset: 8,
                more_fragments: true,
            }
            .label(),
            "ipv4.fragment_offset=8,ipv4.flags=1"
        );
        assert_eq!(
            Mutation::Raw {
                mutator: RawMutator::BitFlip,
                offset: 7,
                arg: 0,
            }
            .label(),
            "raw:bit_flip@7"
        );
        assert_eq!(
            Mutation::Grow {
                len: 8,
                fill: GrowFill::Zeros,
            }
            .label(),
            "grow:8"
        );
        assert_eq!(
            Mutation::Grow {
                len: 8,
                fill: GrowFill::Repeat,
            }
            .label(),
            "grow:8:repeat"
        );
        assert_eq!(Mutation::Truncate { len: 1 }.label(), "truncate:1");
    }

    #[test]
    fn raw_mutators_named_and_bounded() {
        let names: HashSet<&'static str> = RawMutator::ALL.iter().map(RawMutator::name).collect();
        assert_eq!(names.len(), 15, "the 15 D8.5 names are distinct");
        assert_eq!(RawMutator::LongRun.name(), "long_run");
        assert_eq!(RawMutator::BitFlip.name(), "bit_flip");

        let payload: Vec<u8> = (0..16u8).collect();
        let seed = udp_seed(&payload);
        let mut rng = Rng::new(1);
        for _ in 0..200 {
            let case = random_case(FieldPath::Raw, &seed, &mut rng);
            let mutated = case
                .apply(&seed, 1472)
                .unwrap_or_else(|err| panic!("{} must apply: {err}", case.label()));
            assert!(
                payload_of(&mutated).len() <= 1472,
                "{} grew past the ceiling",
                case.label()
            );
        }

        for (arg, len) in [(0u64, 256usize), (1, 1024), (2, 1472)] {
            let case = Mutation::Raw {
                mutator: RawMutator::LongRun,
                offset: 0,
                arg,
            };
            assert_eq!(
                payload_of(&case.apply(&seed, 1472).expect("long run applies")).len(),
                len,
                "arg {arg}"
            );
        }
        for (arg, len) in [(0u64, 256usize), (1, 300), (2, 300)] {
            let case = Mutation::Raw {
                mutator: RawMutator::LongRun,
                offset: 0,
                arg,
            };
            assert_eq!(
                payload_of(&case.apply(&seed, 300).expect("long run applies")).len(),
                len,
                "arg {arg} under a 300-byte ceiling"
            );
        }
    }

    #[test]
    fn empty_payload_never_errors_randomly() {
        let seed = udp_seed(&[]);
        let mut rng = Rng::new(5);
        for _ in 0..100 {
            let case = random_case(FieldPath::Raw, &seed, &mut rng);
            let mutated = case
                .apply(&seed, 1472)
                .unwrap_or_else(|err| panic!("{} must apply: {err}", case.label()));
            assert!(payload_of(&mutated).len() <= 1472);
        }
        assert_eq!(
            Mutation::Raw {
                mutator: RawMutator::BitFlip,
                offset: 0,
                arg: 0,
            }
            .apply(&seed, 1472),
            Err(MutateError::EmptyPayload(RawMutator::BitFlip))
        );
    }

    /// Review finding SEC6: the random draw for `ipv4.protocol` and
    /// `ipv6.next_header` never emits 4 (IP-in-IP), 41 (IPv6-in-IPv4) or 47
    /// (GRE), so the kernel is never asked to decapsulate the seed as an inner
    /// packet aimed somewhere other than the pinned destination.
    #[test]
    fn protocol_draw_never_tunnels() {
        use aitm_proto_l4::craft::Ipv6Spec;

        use crate::fields::Ipv6Field;

        let v4_seed = udp_seed(b"probe");
        let v6_seed = PacketSpec {
            layers: vec![
                Layer::Ipv6(Ipv6Spec {
                    dst: Some(std::net::Ipv6Addr::LOCALHOST),
                    ..Ipv6Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        };
        for (path, seed) in [
            (FieldPath::Ipv4(Ipv4Field::Protocol), &v4_seed),
            (FieldPath::Ipv6(Ipv6Field::NextHeader), &v6_seed),
        ] {
            let mut rng = Rng::new(0x5EC6);
            for _ in 0..500 {
                let Mutation::Field { value, .. } = random_case(path, seed, &mut rng) else {
                    panic!("{path} draws a field case");
                };
                assert!(
                    !matches!(value, 4 | 41 | 47),
                    "{path} drew a tunnelling protocol {value}"
                );
            }
        }
    }

    #[test]
    fn deterministic_under_seed() {
        let seed = udp_seed(&(0..16u8).collect::<Vec<u8>>());
        let draw = |rng_seed: u64| {
            let mut rng = Rng::new(rng_seed);
            (0..50)
                .map(|_| random_case(FieldPath::Raw, &seed, &mut rng).label())
                .collect::<Vec<String>>()
        };
        assert_eq!(draw(7), draw(7));
        assert_ne!(draw(7), draw(8));
    }

    #[test]
    fn layer_absent() {
        let seed = udp_seed(b"probe");
        assert_eq!(
            Mutation::Field {
                path: FieldPath::Tcp(TcpField::Seq),
                value: 1,
            }
            .apply(&seed, 1472),
            Err(MutateError::LayerAbsent(FieldPath::Tcp(TcpField::Seq)))
        );
    }

    /// Tester (stage 5): `Mutation::apply` is total over the lane's own
    /// inputs. Every boundary case of every default field, plus 50 seeded
    /// random cases per field, applies and builds on every seed shape the lane
    /// crafts — IPv4 and IPv6, UDP and TCP, BSD-loopback and Ethernet framing,
    /// an empty, a short and a full-MTU payload. This is the regression net
    /// over the `craft.rs` verbatim-length fix (dc07f736): before it, the
    /// `ipv4.ihl`, `ipv4.total_length` and `tcp.data_offset` tables aborted
    /// the build.
    #[test]
    fn every_default_case_applies_on_every_seed_shape() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        use aitm_scan_model::vocab::L4Transport;

        use crate::fields::{default_fields, IpVersion};
        use crate::plan::{seed_spec, LinkFraming};

        let full_mtu = vec![0x41u8; 1472];
        let payloads: [&[u8]; 3] = [b"", b"probe", full_mtu.as_slice()];
        let mut boundary_applied = 0usize;
        let mut random_applied = 0usize;

        for (ip, local) in [
            (IpVersion::V4, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            (IpVersion::V6, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            for transport in [L4Transport::Udp, L4Transport::Tcp] {
                for framing in [LinkFraming::Null, LinkFraming::Ethernet] {
                    for payload in payloads {
                        let shape = format!("{ip:?}/{transport:?}/{framing:?}/{}B", payload.len());
                        let seed = seed_spec(
                            framing,
                            local,
                            local,
                            9,
                            transport,
                            40000,
                            payload,
                            "seed".to_string(),
                        )
                        .unwrap_or_else(|err| panic!("{shape}: the seed builds: {err}"));
                        let link_len = framing.header_len();

                        for field in default_fields(ip, transport) {
                            if field != FieldPath::Raw {
                                assert!(
                                    declared_value(&seed.spec, field, link_len).is_some(),
                                    "{shape}: {field} has a declared value"
                                );
                            }
                            let table = boundary_cases(field, &seed.spec, link_len, 1472);
                            if field == FieldPath::Raw {
                                let expected = match payload.len() {
                                    // {1,2,16,64,256,1024,1472} x 2 fills; nothing to cut.
                                    0 => 14,
                                    // {6,7,10,16,64,256,1024,1472} x 2 + cuts {4,1,0}.
                                    5 => 19,
                                    // Nothing longer fits under 1472; cuts {1471,1,0}.
                                    _ => 3,
                                };
                                assert_eq!(table.len(), expected, "{shape}: raw table size");
                            }
                            for case in &table {
                                let mutated = case.apply(&seed.spec, 1472).unwrap_or_else(|err| {
                                    panic!("{shape}: {} must apply: {err}", case.label())
                                });
                                let bytes = mutated.build().unwrap_or_else(|err| {
                                    panic!("{shape}: {} must build: {err}", case.label())
                                });
                                assert!(
                                    bytes.len() <= link_len + 40 + 20 + 1472,
                                    "{shape}: {} is {} bytes",
                                    case.label(),
                                    bytes.len()
                                );
                                assert!(
                                    payload_of(&mutated).len() <= 1472,
                                    "{shape}: {} grew the payload past the ceiling",
                                    case.label()
                                );
                                boundary_applied += 1;
                            }

                            let mut rng = Rng::new(0x7e57_0005);
                            for _ in 0..50 {
                                let case = random_case(field, &seed.spec, &mut rng);
                                let mutated = case.apply(&seed.spec, 1472).unwrap_or_else(|err| {
                                    panic!("{shape}: random {} must apply: {err}", case.label())
                                });
                                assert!(
                                    mutated.build().is_ok(),
                                    "{shape}: random {} must build",
                                    case.label()
                                );
                                assert!(payload_of(&mutated).len() <= 1472);
                                random_applied += 1;
                            }
                        }
                    }
                }
            }
        }

        // Header tables: v4 71 + udp 21 = 92, v4 + tcp 55 = 126, v6 34 + udp = 55,
        // v6 + tcp = 89; 362 per framing, x 2 framings x 3 payloads = 2172.
        // Raw: (14 + 19 + 3) per (ip, transport, framing) = 36 x 8 = 288.
        assert_eq!(boundary_applied, 2172 + 288);
        // 50 random cases x (14 + 19 + 9 + 14 = 56 fields) x 2 framings x 3 payloads.
        assert_eq!(random_applied, 50 * 56 * 2 * 3);
    }

    /// Tester (stage 5): the declared values the tables bracket are the bytes
    /// the craft layer really writes, read back through the link header.
    #[test]
    fn declared_values_are_read_from_the_built_frame() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        use aitm_scan_model::vocab::L4Transport;

        use crate::fields::{Ipv6Field, TcpField};
        use crate::plan::{seed_spec, LinkFraming};

        let v4 = seed_spec(
            LinkFraming::Null,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
            L4Transport::Udp,
            40000,
            b"probe",
            "v4".to_string(),
        )
        .expect("the v4 seed builds");
        let at = |field| declared_value(&v4.spec, field, 4);
        assert_eq!(at(FieldPath::Ipv4(Ipv4Field::Ttl)), Some(64));
        assert_eq!(at(FieldPath::Ipv4(Ipv4Field::Ihl)), Some(5));
        assert_eq!(at(FieldPath::Ipv4(Ipv4Field::TotalLength)), Some(33));
        assert_eq!(at(FieldPath::Ipv4(Ipv4Field::Protocol)), Some(17));
        assert_eq!(at(FieldPath::Ipv4(Ipv4Field::Flags)), Some(0));
        assert_eq!(at(FieldPath::Udp(UdpField::SrcPort)), Some(40000));
        assert_eq!(at(FieldPath::Udp(UdpField::Length)), Some(13));
        assert_eq!(at(FieldPath::Raw), None);
        // A link length past the frame reads nothing rather than panicking.
        assert_eq!(
            declared_value(&v4.spec, FieldPath::Ipv4(Ipv4Field::Ttl), 4096),
            None
        );

        let v6 = seed_spec(
            LinkFraming::Ethernet,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            443,
            L4Transport::Tcp,
            40001,
            b"probe",
            "v6".to_string(),
        )
        .expect("the v6 seed builds");
        let at = |field| declared_value(&v6.spec, field, 14);
        assert_eq!(at(FieldPath::Ipv6(Ipv6Field::HopLimit)), Some(64));
        assert_eq!(at(FieldPath::Ipv6(Ipv6Field::PayloadLength)), Some(25));
        assert_eq!(at(FieldPath::Ipv6(Ipv6Field::NextHeader)), Some(6));
        assert_eq!(at(FieldPath::Ipv6(Ipv6Field::FlowLabel)), Some(0));
        assert_eq!(at(FieldPath::Tcp(TcpField::SrcPort)), Some(40001));
        assert_eq!(at(FieldPath::Tcp(TcpField::DataOffset)), Some(5));
        assert_eq!(at(FieldPath::Tcp(TcpField::Flags)), Some(0x02));
        assert_eq!(at(FieldPath::Tcp(TcpField::Seq)), Some(0x0000_1000));
        assert_eq!(at(FieldPath::Ipv4(Ipv4Field::Ttl)), None, "no IPv4 layer");
    }

    /// Tester (stage 5): a hostile `arg`/`offset` pair never panics a byte
    /// mutator — every mutator at every extreme on a 1-byte, a 2-byte and a
    /// full-MTU payload, including offsets past the end and `u64::MAX`.
    #[test]
    fn raw_mutators_survive_extreme_offsets_and_args() {
        let full_mtu = vec![0x5a_u8; 1472];
        for payload in [&[0x01_u8][..], &[0x01, 0x02], full_mtu.as_slice()] {
            let seed = udp_seed(payload);
            for mutator in RawMutator::ALL {
                for offset in [0usize, 1, 2, payload.len(), usize::MAX] {
                    for arg in [0u64, 1, 7, 0xffff_ffff, u64::MAX] {
                        let case = Mutation::Raw {
                            mutator,
                            offset,
                            arg,
                        };
                        let mutated = case.apply(&seed, 1472).unwrap_or_else(|err| {
                            panic!(
                                "{} on {} bytes must apply: {err}",
                                case.label(),
                                payload.len()
                            )
                        });
                        let out = payload_of(&mutated);
                        assert!(out.len() <= 1472, "{}: {} bytes", case.label(), out.len());
                        if mutator == RawMutator::LongRun {
                            assert!(
                                [256, 1024, 1472].contains(&out.len()),
                                "{}: a long run is one of the three sizes, got {}",
                                case.label(),
                                out.len()
                            );
                        }
                    }
                }
            }
        }
        // A `Grow` past the ceiling is clamped to it, and one at or below the
        // payload's length is a no-op. (`apply` clamps the requested length
        // before it grows — see `grow_clamps_before_allocating`.)
        let seed = udp_seed(b"probe");
        let grown = Mutation::Grow {
            len: 100_000,
            fill: GrowFill::Repeat,
        }
        .apply(&seed, 64)
        .expect("grow applies");
        assert_eq!(payload_of(&grown).len(), 64);
        assert_eq!(&payload_of(&grown)[..10], b"probeprobe");
        let same = Mutation::Grow {
            len: 5,
            fill: GrowFill::Zeros,
        }
        .apply(&seed, 1472)
        .expect("grow applies");
        assert_eq!(payload_of(&same), b"probe".to_vec());
        // `Truncate` beyond the length keeps everything.
        let kept = Mutation::Truncate { len: usize::MAX }
            .apply(&seed, 1472)
            .expect("truncate applies");
        assert_eq!(payload_of(&kept), b"probe".to_vec());
    }

    /// Tester finding F3: the ceiling is applied to the requested length
    /// *before* a byte is allocated, so an absurd `Grow` costs the ceiling
    /// and nothing more.
    #[test]
    fn grow_clamps_before_allocating() {
        let seed = udp_seed(b"probe");

        let zeros = Mutation::Grow {
            len: usize::MAX,
            fill: GrowFill::Zeros,
        }
        .apply(&seed, 64)
        .expect("grow applies");
        assert_eq!(payload_of(&zeros).len(), 64);

        let repeat = Mutation::Grow {
            len: usize::MAX,
            fill: GrowFill::Repeat,
        }
        .apply(&seed, 64)
        .expect("grow applies");
        assert_eq!(payload_of(&repeat).len(), 64);
        assert_eq!(&payload_of(&repeat)[..10], b"probeprobe");

        let big = Mutation::Grow {
            len: 1_000_000,
            fill: GrowFill::Zeros,
        }
        .apply(&seed, 1472)
        .expect("grow applies");
        assert_eq!(payload_of(&big).len(), 1472);
    }

    /// Tester (fix round, F3): the clamped `Grow` with a ceiling at or below
    /// the payload's own length allocates nothing and still honours the
    /// ceiling — the payload is cut to it, down to empty.
    #[test]
    fn grow_clamped_below_the_payload_truncates_to_the_ceiling() {
        let seed = udp_seed(b"probe");

        let three = Mutation::Grow {
            len: usize::MAX,
            fill: GrowFill::Repeat,
        }
        .apply(&seed, 3)
        .expect("grow applies");
        assert_eq!(payload_of(&three), b"pro".to_vec());

        let exact = Mutation::Grow {
            len: usize::MAX,
            fill: GrowFill::Zeros,
        }
        .apply(&seed, 5)
        .expect("grow applies");
        assert_eq!(payload_of(&exact), b"probe".to_vec());

        let none = Mutation::Grow {
            len: usize::MAX,
            fill: GrowFill::Zeros,
        }
        .apply(&seed, 0)
        .expect("grow applies");
        assert_eq!(payload_of(&none), Vec::<u8>::new());

        // And the clamped zero fill really is zeros past the seed bytes.
        let zeros = Mutation::Grow {
            len: usize::MAX,
            fill: GrowFill::Zeros,
        }
        .apply(&seed, 16)
        .expect("grow applies");
        let mut expected = b"probe".to_vec();
        expected.extend(std::iter::repeat_n(0u8, 11));
        assert_eq!(payload_of(&zeros), expected);
    }
}
