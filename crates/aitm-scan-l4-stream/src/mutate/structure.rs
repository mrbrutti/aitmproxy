//! The structure-aware mutators (spec S6.4).
//!
//! Each mutator edits one node of a parsed [`Tree`] and re-renders the whole
//! message. The list for a node is fixed and ordered, so the same seed and
//! the same point always produce the same cases in the same order (spec C5):
//! no randomness is consumed here at all — that is stage 2's job
//! ([`crate::mutate::schedule`]).
//!
//! **Relation-aware rendering** (spec S6.4, C6). After the edit the tree is
//! re-satisfied: every `len`, `count` and `checksum` is recomputed from what
//! the message now holds — *except* the one the mutation targeted. So
//! `long_string` on a RESP bulk string yields a correct `$<len>`, while
//! `len_desync` on that same `len` yields an intact payload behind a lying
//! length. That asymmetry is the whole point of the structure-aware set.
//!
//! Nothing here opens a socket or reads a reply. A case that renders a
//! destructive command is dropped where the grammar's denylist says so
//! (spec S3), and the host checks again before any write.

use std::fmt;

use crate::denylist;
use crate::spec::{FieldKind, FieldSpec, GrammarKind, Literal, MessageSpec, Relation};
use crate::state::MAX_MESSAGE;
use crate::tree::{self, FieldPath, Node, Tree};

/// How many bytes `long_string` fills a field with, in order.
const LONG_STRING_SIZES: [usize; 3] = [256, 4096, 65535];

/// How many copies of an element `repeat_element` leaves behind, in order.
const REPEAT_COPIES: [usize; 3] = [2, 16, 256];

/// One rendered mutation of a seed.
///
/// `bytes` is the whole message as it would go on the wire; `field_bytes` is
/// just the mutated field, for the evidence record. Both hold target data, so
/// the `Debug` prints sizes only (spec S9).
#[derive(Clone, PartialEq, Eq)]
pub struct Case {
    /// Position in the schedule, `0..n` and contiguous.
    pub index: u32,
    /// The rendered message.
    pub bytes: Vec<u8>,
    /// The mutators that produced it, in order, as S6.4 names them.
    pub chain: Vec<String>,
    /// The mutated field's bytes, after re-satisfaction.
    pub field_bytes: Vec<u8>,
}

impl fmt::Debug for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Case")
            .field("index", &self.index)
            .field(
                "bytes",
                &format_args!("<{len} bytes>", len = self.bytes.len()),
            )
            .field("chain", &self.chain)
            .field(
                "field_bytes",
                &format_args!("<{len} bytes>", len = self.field_bytes.len()),
            )
            .finish()
    }
}

/// Every structure-aware case for the node at `path`, in S6.4's fixed order.
///
/// `spec` is the grammar the tree was parsed with: the tree keeps a field's
/// type and relation but not its `one_of` or `range`, which `type_subst` and
/// `int_boundary` need, so the spec comes along and the field is resolved by
/// walking it down the path.
///
/// Returns an empty list for a node no structure mutator applies to.
#[must_use]
pub fn structure_cases(
    tree: &Tree,
    spec: &MessageSpec,
    path: &FieldPath,
    kind: GrammarKind,
) -> Vec<Case> {
    let mut out = Vec::new();
    let Some(node) = tree.get(path) else {
        return out;
    };
    let field = resolve_field(spec, path);

    len_desync(&mut out, tree, kind, path, node);
    count_mismatch(&mut out, tree, kind, path, node);
    type_subst(&mut out, tree, kind, path, node, field);
    delim_cases(&mut out, tree, kind, path, node);
    long_string(&mut out, tree, kind, path, node, field);
    repeat_element(&mut out, tree, kind, path);
    checksum_invalid(&mut out, tree, kind, path, node);
    varint_overlong(&mut out, tree, kind, path, node);
    int_boundary(&mut out, tree, kind, path, node, field);

    for (i, case) in out.iter_mut().enumerate() {
        case.index = u32::try_from(i).unwrap_or(u32::MAX);
    }
    out
}

/// The mutators whose cases leave the frame incomplete by construction: the
/// declared size, the separator or the continuation no longer matches the
/// bytes that were sent (spec S6.4).
const FRAMING_MUTATORS: [&str; 5] = [
    "len_desync",
    "count_mismatch",
    "delim_remove",
    "delim_dup",
    "varint_overlong",
];

/// Whether a case on `node` built by `chain` leaves the frame incomplete,
/// which the latency oracle must not time (spec S6.1 as refined by F4).
///
/// A peer that frames on a declared length, an element count, a separator or
/// a varint continuation has no way to know the message ended: it waits for
/// the rest until its own idle timeout and only then answers. The latency
/// that measures is the peer's framing timeout, not its processing, so the
/// S6.2 rule would read every such case as an outlier on a target that is
/// behaving exactly as its protocol says.
///
/// True when any of:
///
/// * the node carries a `len` or `count` relation — a byte-level flip of
///   those bytes desyncs the frame just as `len_desync` does, so the node
///   decides this on its own, whatever the chain;
/// * the node is a `delim` or a `varint`, the other two fields framing
///   depends on;
/// * any entry of `chain` names one of [`FRAMING_MUTATORS`], which desync a
///   frame from a node elsewhere in the message. A chain entry names its
///   mutator up to the first `(`, so `Splice(len_desync)` is not one of them,
///   and `delim_inject` — which writes into the text *before* a separator and
///   leaves the framing intact — is deliberately off the list.
#[must_use]
pub fn affects_framing(node: &Node, chain: &[String]) -> bool {
    if matches!(
        node.relation,
        Some(Relation::Len { .. } | Relation::Count { .. })
    ) {
        return true;
    }
    if matches!(node.kind, FieldKind::Delim | FieldKind::Varint) {
        return true;
    }
    chain.iter().any(|entry| {
        let name = entry
            .split_once('(')
            .map_or(entry.as_str(), |(name, _rest)| name);
        FRAMING_MUTATORS.contains(&name)
    })
}

// ---------------------------------------------------------------------------
// The mutators
// ---------------------------------------------------------------------------

/// `len_desync`: the declared length lies, the body does not.
fn len_desync(out: &mut Vec<Case>, tree: &Tree, kind: GrammarKind, path: &FieldPath, node: &Node) {
    if !matches!(node.relation, Some(Relation::Len { .. })) {
        return;
    }
    let (Some(actual), Some(max)) = (satisfied_value(tree, path), max_value(node.kind)) else {
        return;
    };
    let plan = [
        ("+1", actual.saturating_add(1)),
        ("-1", actual.saturating_sub(1)),
        ("0", 0),
        ("max", max),
        ("past_buffer", actual.saturating_add(1000)),
    ];
    for (token, value) in plan {
        number_case(
            out,
            tree,
            kind,
            path,
            node.kind,
            format!("len_desync({path},{token})"),
            value,
        );
    }
}

/// `count_mismatch`: the declared element count disagrees with the elements.
fn count_mismatch(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    path: &FieldPath,
    node: &Node,
) {
    if !matches!(node.relation, Some(Relation::Count { .. })) {
        return;
    }
    let (Some(actual), Some(max)) = (satisfied_value(tree, path), max_value(node.kind)) else {
        return;
    };
    let plan = [
        ("+1", actual.saturating_add(1)),
        ("-1", actual.saturating_sub(1)),
        ("0", 0),
        ("max", max),
    ];
    for (token, value) in plan {
        number_case(
            out,
            tree,
            kind,
            path,
            node.kind,
            format!("count_mismatch({path},{token})"),
            value,
        );
    }
}

/// `type_subst`: every other value the field is allowed to take, then `0` and
/// `0xff`, then — for a token — a lowercase spelling and an unknown word.
///
/// This is the one mutator whose output the denylist filters here as well as
/// at send (spec S6.4): substituting a Modbus write function code or a RESP
/// `FLUSHALL` is exactly what the lane must never do.
fn type_subst(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    path: &FieldPath,
    node: &Node,
    field: Option<&FieldSpec>,
) {
    let Some(field) = field else {
        return;
    };
    if field.one_of.is_empty() {
        return;
    }

    let mut values: Vec<Vec<u8>> = field
        .one_of
        .iter()
        .filter_map(|literal| literal_bytes(literal, node.kind))
        .collect();
    for extra in [0i64, 0xff] {
        if let Some(encoded) = literal_bytes(&Literal::Int(extra), node.kind) {
            values.push(encoded);
        }
    }
    if node.kind == FieldKind::Token {
        values.push(node.bytes.to_ascii_lowercase());
        values.push(b"ZZZZ".to_vec());
    }

    // The field's own value is not a substitution, and a value is tried once.
    let mut seen = vec![node.bytes.clone()];
    for value in values {
        if seen.contains(&value) {
            continue;
        }
        seen.push(value.clone());
        let chain = format!(
            "type_subst({path},{param})",
            param = render_param(&value, node.kind)
        );
        edit_case(out, tree, kind, path, chain, true, move |target| {
            target.bytes = value;
            true
        });
    }
}

/// `delim_remove`, `delim_dup`, `delim_inject`: the separator goes missing,
/// doubles, or turns up early inside the field before it.
fn delim_cases(out: &mut Vec<Case>, tree: &Tree, kind: GrammarKind, path: &FieldPath, node: &Node) {
    if node.kind != FieldKind::Delim || node.bytes.is_empty() {
        return;
    }

    edit_case(
        out,
        tree,
        kind,
        path,
        format!("delim_remove({path})"),
        false,
        |target| {
            target.bytes.clear();
            true
        },
    );
    edit_case(
        out,
        tree,
        kind,
        path,
        format!("delim_dup({path})"),
        false,
        |target| {
            let again = target.bytes.clone();
            target.bytes.extend_from_slice(&again);
            true
        },
    );

    let Some(before) = preceding_text_field(tree, path) else {
        return;
    };
    let mut injections = vec![node.bytes.clone()];
    for candidate in [b"\r\n".to_vec(), vec![0], b" ".to_vec()] {
        if !injections.contains(&candidate) {
            injections.push(candidate);
        }
    }
    for injection in injections {
        let chain = format!("delim_inject({before},{param})", param = quote(&injection));
        edit_case(out, tree, kind, &before, chain, false, move |target| {
            target.bytes.extend_from_slice(&injection);
            true
        });
    }
}

/// `long_string`: fill the field with `A`s, keeping its terminator.
fn long_string(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    path: &FieldPath,
    node: &Node,
    field: Option<&FieldSpec>,
) {
    if !matches!(
        node.kind,
        FieldKind::Line | FieldKind::Bytes { .. } | FieldKind::CString | FieldKind::Token
    ) {
        return;
    }
    let terminator = kept_terminator(node, field);
    for size in LONG_STRING_SIZES {
        // The whole message is capped at 64 KiB; `push_case` drops a case
        // the rest of the message leaves no room for.
        if size.saturating_add(terminator.len()) > MAX_MESSAGE {
            continue;
        }
        let mut filled = vec![b'A'; size];
        filled.extend_from_slice(&terminator);
        edit_case(
            out,
            tree,
            kind,
            path,
            format!("long_string({path},{size})"),
            false,
            move |target| {
                target.bytes = filled;
                true
            },
        );
    }
}

/// `repeat_element`: the element appears 2, 16 or 256 times.
fn repeat_element(out: &mut Vec<Case>, tree: &Tree, kind: GrammarKind, path: &FieldPath) {
    let Some((parent_path, at)) = split_index(path) else {
        return;
    };
    let Some(parent) = tree.get(&parent_path) else {
        return;
    };
    if parent.kind != FieldKind::Repeat {
        return;
    }
    let Some(element) = parent.children.get(at) else {
        return;
    };
    let element_len = rendered_bytes(element).len();

    for copies in REPEAT_COPIES {
        // Bound the work as well as the result: 256 copies of a large
        // element would pass the message cap anyway.
        if element_len.saturating_mul(copies) > MAX_MESSAGE {
            continue;
        }
        let mut copy = tree.clone();
        let Some(repeat) = copy.get_mut(&parent_path) else {
            continue;
        };
        let Some(original) = repeat.children.get(at).cloned() else {
            continue;
        };
        let extra = vec![original; copies.saturating_sub(1)];
        repeat.children.splice(at + 1..at + 1, extra);
        repath(repeat, parent_path.clone());

        tree::resatisfy(&mut copy, None);
        push_case(
            out,
            kind,
            &copy,
            format!("repeat_element({path},x{copies})"),
            path,
            false,
        );
    }
}

/// `checksum_invalid`: one bit off, or zeroed outright.
fn checksum_invalid(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    path: &FieldPath,
    node: &Node,
) {
    if !matches!(node.relation, Some(Relation::Checksum { .. })) || node.bytes.is_empty() {
        return;
    }
    edit_case(
        out,
        tree,
        kind,
        path,
        format!("checksum_invalid({path},xor1)"),
        false,
        |target| match target.bytes.last_mut() {
            Some(last) => {
                *last ^= 1;
                true
            }
            None => false,
        },
    );
    edit_case(
        out,
        tree,
        kind,
        path,
        format!("checksum_invalid({path},zero)"),
        false,
        |target| {
            target.bytes.fill(0);
            true
        },
    );
}

/// `varint_overlong`: the same value in five bytes, a continuation that never
/// ends, and one past MQTT's largest encodable value.
fn varint_overlong(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    path: &FieldPath,
    node: &Node,
) {
    if node.kind != FieldKind::Varint {
        return;
    }
    let value = satisfied_value(tree, path)
        .or_else(|| tree::decode_number(FieldKind::Varint, &node.bytes))
        .unwrap_or(0);

    let plan = [
        ("5", five_byte_varint(value)),
        ("no_terminator", vec![0x80, 0x80, 0x80, 0x80]),
        // 268435456 is one past the four-byte maximum, so it needs five.
        ("268435456", vec![0x80, 0x80, 0x80, 0x80, 0x01]),
    ];
    for (token, encoded) in plan {
        edit_case(
            out,
            tree,
            kind,
            path,
            format!("varint_overlong({path},{token})"),
            false,
            move |target| {
                target.bytes = encoded;
                true
            },
        );
    }
}

/// `int_boundary`: the edges of the field's width, and of its declared range.
fn int_boundary(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    path: &FieldPath,
    node: &Node,
    field: Option<&FieldSpec>,
) {
    if !matches!(
        node.kind,
        FieldKind::U8 | FieldKind::U16 { .. } | FieldKind::U32 { .. } | FieldKind::Decimal
    ) {
        return;
    }
    let Some(max) = max_value(node.kind) else {
        return;
    };

    let mut plan = vec![
        ("0", 0i64),
        ("1", 1),
        ("max", max),
        ("max-1", max.saturating_sub(1)),
    ];
    // Only a decimal field can carry a sign on the wire.
    if node.kind == FieldKind::Decimal {
        plan.push(("-1", -1));
    }
    if let Some((_, hi)) = field.and_then(|field| field.range) {
        plan.push(("range_hi+1", hi.saturating_add(1)));
    }

    for (token, value) in plan {
        number_case(
            out,
            tree,
            kind,
            path,
            node.kind,
            format!("int_boundary({path},{token})"),
            value,
        );
    }
}

// ---------------------------------------------------------------------------
// Rendering one case
// ---------------------------------------------------------------------------

/// Apply `edit` to the node at `target` in a copy of the tree, re-satisfy and
/// render.
///
/// The edited node keeps its new value when it holds a relation (the
/// mutation targeted the relation); every other relation is recomputed.
/// `edit` returns `false` when it does not apply, and then no case is
/// produced.
fn edit_case<F>(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    target: &FieldPath,
    chain: String,
    deny_filter: bool,
    edit: F,
) where
    F: FnOnce(&mut Node) -> bool,
{
    let mut copy = tree.clone();
    let Some(node) = copy.get_mut(target) else {
        return;
    };
    let targets_relation = node.relation.is_some();
    if !edit(node) {
        return;
    }
    let except = targets_relation.then(|| target.clone());
    tree::resatisfy(&mut copy, except.as_ref());
    push_case(out, kind, &copy, chain, target, deny_filter);
}

/// Render a mutated tree into a case, dropping it when it is empty, over the
/// message cap, or — for `type_subst` — refused by the grammar's denylist.
fn push_case(
    out: &mut Vec<Case>,
    kind: GrammarKind,
    tree: &Tree,
    chain: String,
    field: &FieldPath,
    deny_filter: bool,
) {
    let bytes = tree::render(tree);
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
        return;
    }
    if deny_filter && denylist::refuses(kind, &bytes).is_some() {
        return;
    }
    let field_bytes = tree.get(field).map(rendered_bytes).unwrap_or_default();
    out.push(Case {
        index: 0,
        bytes,
        chain: vec![chain],
        field_bytes,
    });
}

/// Write `value` into the node, in the node's own width and byte order. A
/// value the field cannot hold produces no case.
fn number_case(
    out: &mut Vec<Case>,
    tree: &Tree,
    kind: GrammarKind,
    path: &FieldPath,
    field_kind: FieldKind,
    chain: String,
    value: i64,
) {
    let Some(encoded) = tree::encode_number(field_kind, value) else {
        return;
    };
    edit_case(out, tree, kind, path, chain, false, move |target| {
        target.bytes = encoded;
        true
    });
}

// ---------------------------------------------------------------------------
// Reading the tree and the spec
// ---------------------------------------------------------------------------

/// The value the relation at `path` would hold if it were honest.
fn satisfied_value(tree: &Tree, path: &FieldPath) -> Option<i64> {
    let mut copy = tree.clone();
    tree::resatisfy(&mut copy, None);
    let node = copy.get(path)?;
    tree::decode_number(node.kind, &node.bytes)
}

/// The largest value the field's width can hold: all ones, or — for a
/// `decimal`, which has no width — the 32-bit signed maximum a parser is
/// most likely to be reading it into.
fn max_value(kind: FieldKind) -> Option<i64> {
    match kind {
        FieldKind::U8 => Some(255),
        FieldKind::U16 { .. } => Some(65535),
        FieldKind::U32 { .. } => Some(4_294_967_295),
        FieldKind::Varint => Some(268_435_455),
        FieldKind::Decimal => Some(2_147_483_647),
        _ => None,
    }
}

/// The node's bytes, or a container's children concatenated.
fn rendered_bytes(node: &Node) -> Vec<u8> {
    if node.children.is_empty() {
        return node.bytes.clone();
    }
    let mut out = Vec::new();
    for child in &node.children {
        out.extend_from_slice(&rendered_bytes(child));
    }
    out
}

/// The trailing terminator `long_string` must keep so the field still ends
/// where the grammar says it does.
fn kept_terminator(node: &Node, field: Option<&FieldSpec>) -> Vec<u8> {
    if let Some(declared) = field.and_then(|field| field.terminator.as_ref()) {
        if node.bytes.ends_with(declared) {
            return declared.clone();
        }
    }
    match node.kind {
        FieldKind::CString if node.bytes.ends_with(&[0]) => vec![0],
        FieldKind::Line if node.bytes.ends_with(b"\r\n") => b"\r\n".to_vec(),
        FieldKind::Line if node.bytes.ends_with(b"\n") => b"\n".to_vec(),
        _ => Vec::new(),
    }
}

/// The [`FieldSpec`] the node at `path` was parsed from.
///
/// The path is walked component by component: a `group`'s or `choice`'s named
/// member resolves against its `fields`, and a `repeat` element's index is
/// dropped because every element shares the repeat's field list.
fn resolve_field<'a>(spec: &'a MessageSpec, path: &FieldPath) -> Option<&'a FieldSpec> {
    let mut level: &'a [FieldSpec] = &spec.message;
    let mut found: Option<&'a FieldSpec> = None;
    for component in path.as_str().split('.') {
        let name = match component.find('[') {
            Some(open) => component.get(..open)?,
            None => component,
        };
        let field = level.iter().find(|field| field.name == name)?;
        found = Some(field);
        level = &field.fields;
    }
    found
}

/// Split `args[1]` into `args` and `1`.
fn split_index(path: &FieldPath) -> Option<(FieldPath, usize)> {
    let text = path.as_str();
    if !text.ends_with(']') {
        return None;
    }
    let open = text.rfind('[')?;
    let index = text.get(open + 1..text.len() - 1)?.parse().ok()?;
    Some((FieldPath::new(text.get(..open)?), index))
}

/// The node list the node at `target` belongs to.
fn siblings_of<'a>(nodes: &'a [Node], target: &str) -> Option<&'a [Node]> {
    if nodes.iter().any(|node| node.path.as_str() == target) {
        return Some(nodes);
    }
    nodes
        .iter()
        .find_map(|node| siblings_of(&node.children, target))
}

/// The text field immediately before the delimiter at `path`, the one
/// `delim_inject` writes into.
///
/// A `choice` keeps only the alternative that parsed, so a delimiter written
/// as one alternative of a choice (a line grammar's optional separator) opens
/// a sibling list of its own. The search then steps out to the choice and
/// takes the field before *it*: the text before the separator on the wire is
/// the field `delim_inject` must write into, whatever container it is nested
/// in. Nothing else is stepped out of — a delimiter that opens a group is the
/// start of that group, and there is no text before it inside it.
fn preceding_text_field(tree: &Tree, path: &FieldPath) -> Option<FieldPath> {
    let mut at_path = path.clone();
    loop {
        let siblings = siblings_of(&tree.root, at_path.as_str())?;
        let at = siblings
            .iter()
            .position(|node| node.path.as_str() == at_path.as_str())?;
        match at.checked_sub(1).and_then(|before| siblings.get(before)) {
            Some(previous) => {
                return matches!(
                    previous.kind,
                    FieldKind::Line
                        | FieldKind::Bytes { .. }
                        | FieldKind::Token
                        | FieldKind::CString
                )
                .then(|| previous.path.clone())
            }
            None => {
                let parent = parent_path(&at_path)?;
                if tree.get(&parent)?.kind != FieldKind::Choice {
                    return None;
                }
                at_path = parent;
            }
        }
    }
}

/// The path of the container the node at `path` sits in, or `None` for a
/// top-level field: `a.b.c` is in `a.b`, and `a.b[2]` is in `a.b`.
fn parent_path(path: &FieldPath) -> Option<FieldPath> {
    let text = path.as_str();
    if text.ends_with(']') {
        let open = text.rfind('[')?;
        return Some(FieldPath::new(text.get(..open)?));
    }
    let dot = text.rfind('.')?;
    Some(FieldPath::new(text.get(..dot)?))
}

/// Renumber a container's descendants after its children changed, so every
/// path still names the node it is on.
fn repath(node: &mut Node, path: FieldPath) {
    let is_repeat = node.kind == FieldKind::Repeat;
    node.path = path;
    let base = node.path.clone();
    for (i, child) in node.children.iter_mut().enumerate() {
        let child_path = if is_repeat {
            base.index(i)
        } else {
            let name = child.path.last().to_string();
            base.child(&name)
        };
        repath(child, child_path);
    }
}

// ---------------------------------------------------------------------------
// Values and their chain parameters
// ---------------------------------------------------------------------------

/// A literal as the field would hold it on the wire.
fn literal_bytes(literal: &Literal, kind: FieldKind) -> Option<Vec<u8>> {
    match literal {
        Literal::Int(value) => match kind {
            FieldKind::U8
            | FieldKind::U16 { .. }
            | FieldKind::U32 { .. }
            | FieldKind::Varint
            | FieldKind::Decimal => tree::encode_number(kind, *value),
            // A number substituted into a text field is a byte when it fits
            // in one, and its digits otherwise.
            _ => Some(
                u8::try_from(*value)
                    .map(|byte| vec![byte])
                    .unwrap_or_else(|_| value.to_string().into_bytes()),
            ),
        },
        Literal::Text(text) => Some(text.as_bytes().to_vec()),
        Literal::Hex(bytes) => Some(bytes.clone()),
    }
}

/// How a substituted value is written in a chain entry: `0x08` for a binary
/// field, the text itself for a printable one.
fn render_param(bytes: &[u8], kind: FieldKind) -> String {
    let binary = matches!(
        kind,
        FieldKind::U8 | FieldKind::U16 { .. } | FieldKind::U32 { .. } | FieldKind::Varint
    );
    if !binary && !bytes.is_empty() && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut out = String::from("0x");
    for byte in bytes {
        out.push_str(&hex_byte(*byte));
    }
    out
}

/// An injected separator as a chain entry writes it: `"\r\n"`.
fn quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0 => out.push_str("\\0"),
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(char::from(byte)),
            other => {
                out.push_str("\\x");
                out.push_str(&hex_byte(other));
            }
        }
    }
    out.push('"');
    out
}

fn hex_byte(byte: u8) -> String {
    const DIGITS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let hi = usize::from(byte >> 4);
    let lo = usize::from(byte & 0x0f);
    let mut out = String::with_capacity(2);
    out.push(DIGITS[hi]);
    out.push(DIGITS[lo]);
    out
}

/// `value` in five varint bytes: the four low groups keep their continuation
/// bit set even though the value ended.
fn five_byte_varint(value: i64) -> Vec<u8> {
    let bits = u32::try_from(value).unwrap_or(u32::MAX);
    vec![
        u8::try_from(bits & 0x7f).unwrap_or(0) | 0x80,
        u8::try_from((bits >> 7) & 0x7f).unwrap_or(0) | 0x80,
        u8::try_from((bits >> 14) & 0x7f).unwrap_or(0) | 0x80,
        u8::try_from((bits >> 21) & 0x7f).unwrap_or(0) | 0x80,
        u8::try_from((bits >> 28) & 0x7f).unwrap_or(0),
    ]
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::denylist;
    use crate::grammar::by_kind;
    use crate::mutate::structure::{affects_framing, structure_cases, Case};
    use crate::spec::{
        Endian, FieldKind, FieldSpec, GrammarKind, LenOf, MessageSpec, Relation, Transport,
    };
    use crate::tree::{self, FieldPath, Node, Tree};

    /// The S2 Modbus example, with every function code the T10 speaker
    /// accepts in `one_of` — the write codes included, so the denylist has
    /// something to filter (task-13 decision 4).
    pub(crate) const MODBUS_YAML: &str = r#"
grammar: modbus
transport: tcp
default_ports: [502]
message:
  - name: header
    type: group
    fields:
      - { name: transaction_id, type: u16 be, mutable: false }
      - { name: protocol_id, type: u16 be, value: 0 }
      - { name: length, type: u16 be, len: { of: [unit_id, pdu] } }
      - { name: unit_id, type: u8, value: 1 }
  - name: pdu
    type: group
    fields:
      - { name: function, type: u8, one_of: [1, 2, 3, 4, 5, 6, 8, 15, 16] }
      - { name: address, type: u16 be, value: 0 }
      - { name: quantity, type: u16 be, range: [1, 125], value: 1 }
"#;

    /// The same RESP array grammar `tree.rs` tests against.
    pub(crate) const RESP_YAML: &str = r#"
grammar: resp
transport: tcp
default_ports: [6379]
message:
  - { name: star, type: delim, value: "*" }
  - { name: count, type: decimal, count: { of: args } }
  - { name: crlf, type: delim, value: "\r\n" }
  - name: args
    type: repeat
    count_from: count
    fields:
      - { name: dollar, type: delim, value: "$" }
      - { name: len, type: decimal, len: { of: [data] } }
      - { name: crlf, type: delim, value: "\r\n" }
      - { name: data, type: bytes }
      - { name: crlf2, type: delim, value: "\r\n" }
"#;

    /// The T10 benign Modbus read-holding-registers frame, function code 3.
    pub(crate) const MODBUS_FRAME: [u8; 12] = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
    ];

    /// The two-element RESP array `*2\r\n$4\r\nPING\r\n$3\r\nabc\r\n`.
    pub(crate) const RESP_FRAME: &[u8] = b"*2\r\n$4\r\nPING\r\n$3\r\nabc\r\n";

    pub(crate) fn modbus_spec() -> MessageSpec {
        MessageSpec::from_yaml(MODBUS_YAML).expect("the modbus grammar parses")
    }

    pub(crate) fn modbus_tree() -> Tree {
        tree::parse(&modbus_spec(), &MODBUS_FRAME).expect("the modbus frame parses")
    }

    pub(crate) fn resp_spec() -> MessageSpec {
        MessageSpec::from_yaml(RESP_YAML).expect("the resp grammar parses")
    }

    pub(crate) fn resp_tree() -> Tree {
        tree::parse(&resp_spec(), RESP_FRAME).expect("the resp frame parses")
    }

    /// The TLV spec task 8's inference produces for a two-field
    /// length-prefixed message, built inline so this test does not wait on
    /// `infer::descriptor_to_spec`.
    pub(crate) fn tlv_spec() -> MessageSpec {
        MessageSpec {
            grammar: "tlv".to_string(),
            transport: Transport::Tcp,
            message: vec![
                FieldSpec {
                    name: "length".to_string(),
                    kind: FieldKind::U16 { endian: Endian::Be },
                    relation: Some(Relation::Len {
                        of: LenOf::Rest,
                        inclusive: false,
                        adjust: 0,
                    }),
                    ..FieldSpec::default()
                },
                FieldSpec {
                    name: "payload".to_string(),
                    kind: FieldKind::Bytes { size: None },
                    ..FieldSpec::default()
                },
            ],
            ..MessageSpec::default()
        }
    }

    fn chains(cases: &[Case]) -> Vec<String> {
        cases.iter().map(|case| case.chain.concat()).collect()
    }

    /// A node with no relation and no framing kind, for the clauses that
    /// must read the kind alone.
    fn bare(kind: FieldKind) -> Node {
        Node {
            path: FieldPath::new("x"),
            kind,
            bytes: vec![0x00],
            children: Vec::new(),
            relation: None,
            mutable: true,
            secret: false,
            relation_broken: false,
        }
    }

    /// F4: the latency oracle must not judge a case that leaves the frame
    /// incomplete, because the delay it measures is the peer's framing
    /// timeout. The predicate decides that from the node and the chain.
    #[test]
    fn affects_framing_reads_node_and_chain() {
        let modbus = modbus_tree();
        let length = modbus
            .get(&FieldPath::new("header.length"))
            .expect("the MBAP frame has a length field");
        let address = modbus
            .get(&FieldPath::new("pdu.address"))
            .expect("the MBAP frame has a PDU address");

        // (a) a `len` relation: any mutation of those bytes, byte-level ones
        // included, makes the declared length disagree with what was sent.
        assert!(affects_framing(length, &[]));
        assert!(affects_framing(
            length,
            &["BitFlip(header.length,@13)".to_string()]
        ));
        assert!(affects_framing(
            length,
            &["len_desync(header.length,+1)".to_string()]
        ));

        // A plain field under a byte-level chain still gets timed.
        assert!(!affects_framing(address, &[]));
        assert!(!affects_framing(
            address,
            &["BytesInsert(pdu.address,@1,+3)".to_string()]
        ));

        // (c) the chain names a framing mutator, whatever the node is.
        for chain in [
            "len_desync(x,+1)",
            "count_mismatch(x,+1)",
            "delim_remove(x)",
            "delim_dup(x)",
            "varint_overlong(x,max)",
        ] {
            assert!(
                affects_framing(address, &[chain.to_string()]),
                "chain {chain}"
            );
        }
        // A chain entry that merely mentions one is not one.
        assert!(!affects_framing(
            address,
            &[
                "BytesInsert(pdu.address,@1,+3)".to_string(),
                "Splice(len_desync)".to_string()
            ]
        ));
        // `delim_inject` writes into the text before a delimiter and leaves
        // the framing intact, so it is not on the list.
        assert!(!affects_framing(
            address,
            &["delim_inject(pdu.address,\"\\r\\n\")".to_string()]
        ));

        // (a) a `count` relation.
        let resp = resp_tree();
        let count = resp
            .get(&FieldPath::new("count"))
            .expect("the RESP array has an element count");
        assert!(affects_framing(count, &[]));

        // (b) a delimiter node, which carries no relation of its own.
        let crlf = resp
            .get(&FieldPath::new("args[0].crlf"))
            .expect("the first bulk string has a CRLF");
        assert_eq!(crlf.relation, None);
        assert!(affects_framing(crlf, &[]));
        assert!(affects_framing(&bare(FieldKind::Delim), &[]));

        // (b) a varint node.
        let mqtt = by_kind(GrammarKind::Mqtt)
            .parse(&[0xc0, 0x00])
            .expect("the PINGREQ packet parses");
        let remaining = mqtt
            .get(&FieldPath::new("fixed.remaining_length"))
            .expect("the fixed header has a remaining length");
        assert_eq!(remaining.kind, FieldKind::Varint);
        assert!(affects_framing(remaining, &[]));
        assert!(affects_framing(&bare(FieldKind::Varint), &[]));

        // Nothing else is excluded.
        assert!(!affects_framing(
            &bare(FieldKind::U16 { endian: Endian::Be }),
            &[]
        ));
        assert!(!affects_framing(
            &bare(FieldKind::Bytes { size: None }),
            &[]
        ));
    }

    #[test]
    fn tlv_len_desync_chain_names() {
        let spec = tlv_spec();
        let tree =
            tree::parse(&spec, &[0x00, 0x03, b'a', b'b', b'c']).expect("the tlv seed parses");
        let cases = structure_cases(&tree, &spec, &FieldPath::new("length"), GrammarKind::Tlv);

        assert_eq!(
            chains(&cases)[..5],
            [
                "len_desync(length,+1)",
                "len_desync(length,-1)",
                "len_desync(length,0)",
                "len_desync(length,max)",
                "len_desync(length,past_buffer)",
            ]
        );
        for case in cases.iter().take(5) {
            assert_eq!(case.chain.len(), 1, "one structure mutator per case");
        }

        // The payload is never touched: only the declared length moves.
        assert_eq!(cases[0].bytes, vec![0x00, 0x04, b'a', b'b', b'c']);
        assert_eq!(cases[1].bytes, vec![0x00, 0x02, b'a', b'b', b'c']);
        assert_eq!(cases[2].bytes, vec![0x00, 0x00, b'a', b'b', b'c']);
        assert_eq!(cases[3].bytes, vec![0xff, 0xff, b'a', b'b', b'c']);
        assert_eq!(&cases[3].bytes[..2], &[0xff, 0xff]);
        // past_buffer is the real length plus 1000: 3 + 1000 = 0x03eb.
        assert_eq!(cases[4].bytes, vec![0x03, 0xeb, b'a', b'b', b'c']);
        assert_eq!(cases[0].field_bytes, vec![0x00, 0x04]);
        assert_eq!(cases[0].index, 0);
        assert_eq!(cases[4].index, 4);
    }

    /// C6's last clause: `checksum_invalid` on a synthetic `crc32` relation
    /// changes that node and nothing else, and the re-satisfaction pass does
    /// not quietly repair it.
    #[test]
    fn checksum_invalid_changes_only_the_checksum() {
        let spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: body, type: bytes, size: 9 }\n",
            "  - { name: crc, type: u32 be, checksum: { algo: crc32, over: [body] } }\n",
        ))
        .expect("the synthetic crc32 grammar parses");
        let mut wire = b"123456789".to_vec();
        wire.extend_from_slice(&[0xcb, 0xf4, 0x39, 0x26]);
        let tree = tree::parse(&spec, &wire).expect("the synthetic frame parses");

        let cases = structure_cases(&tree, &spec, &FieldPath::new("crc"), GrammarKind::Tlv);
        let chains = chains(&cases);
        assert!(
            chains.contains(&"checksum_invalid(crc,xor1)".to_string()),
            "{chains:?}"
        );
        assert!(
            chains.contains(&"checksum_invalid(crc,zero)".to_string()),
            "{chains:?}"
        );

        let xor1 = cases
            .iter()
            .find(|case| case.chain.concat() == "checksum_invalid(crc,xor1)")
            .expect("the xor1 case");
        assert_eq!(
            xor1.bytes,
            b"123456789\xcb\xf4\x39\x27".to_vec(),
            "only the checksum's last byte moved"
        );
        assert_eq!(&xor1.bytes[..9], b"123456789", "the body is untouched");

        let zero = cases
            .iter()
            .find(|case| case.chain.concat() == "checksum_invalid(crc,zero)")
            .expect("the zero case");
        assert_eq!(zero.bytes, b"123456789\x00\x00\x00\x00".to_vec());
        assert_eq!(&zero.bytes[..9], b"123456789");

        // A mutation of the body, by contrast, is followed by the checksum.
        let body = structure_cases(&tree, &spec, &FieldPath::new("body"), GrammarKind::Tlv);
        for case in &body {
            if case.bytes.len() == 13 {
                let want = crate::codec::crc32(&case.bytes[..9]).to_be_bytes();
                assert_eq!(
                    &case.bytes[9..],
                    &want[..],
                    "case {} left a stale checksum",
                    case.chain.concat()
                );
            }
        }
    }

    #[test]
    fn type_subst_skips_denylisted() {
        let spec = modbus_spec();
        let tree = modbus_tree();
        let cases = structure_cases(
            &tree,
            &spec,
            &FieldPath::new("pdu.function"),
            GrammarKind::Modbus,
        );

        let subst: Vec<&Case> = cases
            .iter()
            .filter(|case| case.chain.concat().starts_with("type_subst("))
            .collect();
        let codes: Vec<u8> = subst
            .iter()
            .filter_map(|case| case.bytes.get(7).copied())
            .collect();

        // Seed is function code 3: every other allowed value, then 0 and
        // 0xff — with the write/diagnostic codes filtered out.
        assert_eq!(codes, vec![1, 2, 4, 0, 0xff]);
        for refused in [5u8, 6, 8, 15, 16, 21, 22, 23] {
            assert!(
                !codes.contains(&refused),
                "function code {refused} is denylisted and must not be substituted"
            );
        }
        assert_eq!(
            chains(&cases)[..5],
            [
                "type_subst(pdu.function,0x01)",
                "type_subst(pdu.function,0x02)",
                "type_subst(pdu.function,0x04)",
                "type_subst(pdu.function,0x00)",
                "type_subst(pdu.function,0xff)",
            ]
        );

        // The filter, not luck, is what removes them.
        for case in &cases {
            assert!(
                denylist::refuses(GrammarKind::Modbus, &case.bytes).is_none(),
                "structure_cases emitted a denylisted message: {:?}",
                case.chain
            );
        }
    }

    #[test]
    fn long_string_is_bounded_by_the_message_cap() {
        let spec = resp_spec();
        let tree = resp_tree();
        let cases = structure_cases(
            &tree,
            &spec,
            &FieldPath::new("args[1].data"),
            GrammarKind::Resp,
        );
        let sizes: Vec<String> = cases
            .iter()
            .map(|case| case.chain.concat())
            .filter(|chain| chain.starts_with("long_string("))
            .collect();

        // 65535 bytes of payload plus the framing passes the 64 KiB cap.
        assert_eq!(
            sizes,
            vec![
                "long_string(args[1].data,256)",
                "long_string(args[1].data,4096)",
            ]
        );
    }
}
