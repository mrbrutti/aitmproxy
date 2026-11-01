//! The parsed message `Tree`, `Node`, `FieldPath`, and relation
//! re-satisfaction (spec S2).
//!
//! A [`MessageSpec`] describes a message; this module applies one to bytes.
//! [`parse`] is total over the spec: it never panics, it returns `None` when
//! the bytes are not that message, and a declared length is *read, not
//! trusted* — when it does not fit the buffer the field keeps its bytes and
//! the node records [`Node::relation_broken`], so a mutator knows the seed
//! was already desynced. [`render`] concatenates leaf bytes in order, so
//! `render(parse(bytes)?) == bytes` for every message the grammar accepts.
//! [`resatisfy`] recomputes every `len`, `count` and `checksum` node from its
//! targets, except the one the caller names: the mutation that targets a
//! relation keeps its deliberately wrong value.
//!
//! Paths are the S2 form: dotted for members, `[i]` for `repeat` elements
//! (`header.length`, `args[1].data`, `questions[0].name.labels[2].len`).
//! `InsertionPoint.path`, `L4Location.field_path` and every `mutation_chain`
//! entry use exactly this form.

use std::fmt;

use crate::codec::{crc32, internet_checksum};
use crate::spec::{
    ChecksumAlgo, Endian, FieldKind, FieldSpec, LenOf, Literal, MessageSpec, Relation, Until,
};

/// The deepest the parser recurses, whatever a spec declares. `validate`
/// already bounds a loaded grammar at `spec::MAX_DEPTH`; this bounds one
/// built by hand.
const MAX_PARSE_DEPTH: usize = 32;
/// The most elements an unbounded `repeat` (`until: end`) yields.
const MAX_REPEAT_ELEMENTS: usize = 4096;
/// How often [`resatisfy`] re-runs so that an outer length sees an inner
/// one's new width. Each round that changes nothing stops the loop.
const MAX_RESATISFY_ROUNDS: usize = 8;

// ---------------------------------------------------------------------------
// Field paths
// ---------------------------------------------------------------------------

/// A path naming one node of a parsed [`Tree`]: `header.length`,
/// `args[1].data`, `questions[0].name.labels[2].len`.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldPath(String);

impl FieldPath {
    /// The path written out, as it appears in a point or a mutation chain.
    #[must_use]
    pub fn new(text: &str) -> FieldPath {
        FieldPath(text.to_string())
    }

    /// The empty path: the parent of every top-level field.
    #[must_use]
    pub fn root() -> FieldPath {
        FieldPath(String::new())
    }

    /// This path's named member: `a` + `b` is `a.b`, and the root's member is
    /// `b`.
    #[must_use]
    pub fn child(&self, name: &str) -> FieldPath {
        if self.0.is_empty() {
            FieldPath(name.to_string())
        } else {
            FieldPath(format!("{parent}.{name}", parent = self.0))
        }
    }

    /// This path's `i`th `repeat` element: `args` + 1 is `args[1]`.
    #[must_use]
    pub fn index(&self, i: usize) -> FieldPath {
        FieldPath(format!("{parent}[{i}]", parent = self.0))
    }

    /// The name of the field this path ends at, without any index:
    /// `questions[0].name[2]` is named `name`. This is an
    /// `InsertionPoint`'s name.
    #[must_use]
    pub fn last(&self) -> &str {
        let tail = match self.0.rfind('.') {
            Some(dot) => &self.0[dot + 1..],
            None => self.0.as_str(),
        };
        match tail.find('[') {
            Some(open) => &tail[..open],
            None => tail,
        }
    }

    /// The path as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the root path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{path:?}", path = self.0)
    }
}

impl From<&str> for FieldPath {
    fn from(text: &str) -> FieldPath {
        FieldPath::new(text)
    }
}

impl From<String> for FieldPath {
    fn from(text: String) -> FieldPath {
        FieldPath(text)
    }
}

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

/// One parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// The grammar that parsed it, [`MessageSpec::grammar`].
    pub grammar: String,
    /// The top-level fields, in order.
    pub root: Vec<Node>,
}

/// One field of a parsed message.
///
/// A node is a leaf (bytes, no children) or a container (`group`, `repeat`,
/// `choice`, and a `repeat`'s elements): a container holds no bytes of its
/// own and renders as its children.
#[derive(Clone, PartialEq, Eq)]
pub struct Node {
    /// Where the node sits in the tree.
    pub path: FieldPath,
    /// The field's declared type.
    pub kind: FieldKind,
    /// The field's bytes. Empty for a container.
    pub bytes: Vec<u8>,
    /// The members of a container, in order.
    pub children: Vec<Node>,
    /// The relation this field holds, if any.
    pub relation: Option<Relation>,
    /// `false` for a field no mutator touches, inherited by every descendant
    /// of an immutable container.
    pub mutable: bool,
    /// `true` for a field whose bytes never enter an excerpt, inherited by
    /// every descendant of a secret container.
    pub secret: bool,
    /// `true` when the relation's parsed value did not fit the buffer: the
    /// seed was already desynced, so a check must not read a crash into it.
    pub relation_broken: bool,
}

// Hand-written so that no message byte ever reaches a log or a panic message
// (spec S9): bytes are printed as a count.
impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field(
                "bytes",
                &format_args!("<{len} bytes>", len = self.bytes.len()),
            )
            .field("children", &self.children)
            .field("relation", &self.relation)
            .field("mutable", &self.mutable)
            .field("secret", &self.secret)
            .field("relation_broken", &self.relation_broken)
            .finish()
    }
}

impl Tree {
    /// The node at `path`, or `None` when the tree has no such node.
    #[must_use]
    pub fn get(&self, path: &FieldPath) -> Option<&Node> {
        find(&self.root, path.as_str())
    }

    /// The node at `path`, mutably.
    #[must_use]
    pub fn get_mut(&mut self, path: &FieldPath) -> Option<&mut Node> {
        find_mut(&mut self.root, path.as_str())
    }

    /// Every leaf, in render order.
    #[must_use]
    pub fn leaves(&self) -> Vec<&Node> {
        let mut out = Vec::new();
        collect_leaves(&self.root, &mut out);
        out
    }

    /// Every leaf a mutator may touch, in render order.
    #[must_use]
    pub fn mutable_leaves(&self) -> Vec<&Node> {
        self.leaves().into_iter().filter(|n| n.mutable).collect()
    }
}

fn find<'a>(nodes: &'a [Node], path: &str) -> Option<&'a Node> {
    for node in nodes {
        let here = node.path.as_str();
        if here == path {
            return Some(node);
        }
        if is_under(here, path) {
            if let Some(found) = find(&node.children, path) {
                return Some(found);
            }
        }
    }
    None
}

fn find_mut<'a>(nodes: &'a mut [Node], path: &str) -> Option<&'a mut Node> {
    for node in nodes {
        let here = node.path.as_str();
        if here == path {
            return Some(node);
        }
        if is_under(here, path) {
            if let Some(found) = find_mut(&mut node.children, path) {
                return Some(found);
            }
        }
    }
    None
}

/// Whether `path` names something inside the node at `here`.
fn is_under(here: &str, path: &str) -> bool {
    if here.is_empty() {
        return true;
    }
    let Some(rest) = path.strip_prefix(here) else {
        return false;
    };
    rest.starts_with('.') || rest.starts_with('[')
}

fn collect_leaves<'a>(nodes: &'a [Node], out: &mut Vec<&'a Node>) {
    for node in nodes {
        if node.children.is_empty() {
            out.push(node);
        } else {
            collect_leaves(&node.children, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The message's bytes: every leaf's bytes, in order.
#[must_use]
pub fn render(tree: &Tree) -> Vec<u8> {
    let mut out = Vec::new();
    for node in &tree.root {
        render_node(node, &mut out);
    }
    out
}

fn render_node(node: &Node, out: &mut Vec<u8>) {
    if node.children.is_empty() {
        out.extend_from_slice(&node.bytes);
    } else {
        for child in &node.children {
            render_node(child, out);
        }
    }
}

fn rendered_len(node: &Node) -> usize {
    if node.children.is_empty() {
        node.bytes.len()
    } else {
        node.children.iter().map(rendered_len).sum()
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse `bytes` as the message `spec` describes.
///
/// Returns `None` when the bytes are not that message: a fixed-width field
/// runs past the end, a `delim` does not match, a `token` is not in `one_of`,
/// a counted `repeat` is short, or bytes are left over. A declared `len` is
/// read and checked, never trusted: when it does not fit, the node is marked
/// [`Node::relation_broken`] and the parse carries on.
#[must_use]
pub fn parse(spec: &MessageSpec, bytes: &[u8]) -> Option<Tree> {
    let mut parser = Parser {
        buf: bytes,
        pos: 0,
        limit: bytes.len(),
        budgets: Vec::new(),
        counts: Vec::new(),
        depth: 0,
    };
    let root = parser.level(&spec.message, &FieldPath::root(), true, false)?;
    if parser.pos != bytes.len() {
        return None;
    }
    Some(Tree {
        grammar: spec.grammar.clone(),
        root,
    })
}

struct Parser<'a> {
    buf: &'a [u8],
    /// The next byte to read.
    pos: usize,
    /// One past the last byte this message may use. A `len: { of: rest }`
    /// that fits narrows it for everything that follows, so a declared length
    /// bounds the body it measures.
    limit: usize,
    /// Byte counts declared by a `len: { of: [one_field] }`, waiting for the
    /// field they name. Keyed by name, consumed once.
    budgets: Vec<(String, usize)>,
    /// Element counts declared by a `count: { of: repeat }`.
    counts: Vec<(String, usize)>,
    depth: usize,
}

/// Everything a `choice` has to put back when an alternative does not parse.
struct Mark {
    pos: usize,
    limit: usize,
    budgets: Vec<(String, usize)>,
    counts: Vec<(String, usize)>,
}

impl<'a> Parser<'a> {
    fn mark(&self) -> Mark {
        Mark {
            pos: self.pos,
            limit: self.limit,
            budgets: self.budgets.clone(),
            counts: self.counts.clone(),
        }
    }

    fn restore(&mut self, mark: Mark) {
        self.pos = mark.pos;
        self.limit = mark.limit;
        self.budgets = mark.budgets;
        self.counts = mark.counts;
    }

    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.limit {
            return None;
        }
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn level(
        &mut self,
        fields: &[FieldSpec],
        prefix: &FieldPath,
        mutable: bool,
        secret: bool,
    ) -> Option<Vec<Node>> {
        if self.depth > MAX_PARSE_DEPTH {
            return None;
        }
        let mut out = Vec::with_capacity(fields.len());
        for spec in fields {
            out.push(self.field(spec, prefix, mutable, secret)?);
        }
        Some(out)
    }

    fn field(
        &mut self,
        spec: &FieldSpec,
        prefix: &FieldPath,
        parent_mutable: bool,
        parent_secret: bool,
    ) -> Option<Node> {
        if self.depth > MAX_PARSE_DEPTH {
            return None;
        }
        let path = prefix.child(&spec.name);
        let mutable = parent_mutable && spec.mutable;
        let secret = parent_secret || spec.secret;

        match spec.kind {
            FieldKind::Group => {
                self.depth += 1;
                let children = self.level(&spec.fields, &path, mutable, secret);
                self.depth -= 1;
                Some(container(
                    path,
                    FieldKind::Group,
                    children?,
                    mutable,
                    secret,
                ))
            }
            FieldKind::Repeat => self.repeat(spec, path, mutable, secret),
            FieldKind::Choice => self.choice(spec, path, mutable, secret),
            _ => self.leaf(spec, path, mutable, secret),
        }
    }

    fn repeat(
        &mut self,
        spec: &FieldSpec,
        path: FieldPath,
        mutable: bool,
        secret: bool,
    ) -> Option<Node> {
        let declared = spec
            .count_from
            .as_ref()
            .and_then(|name| self.take_count(name));
        let mut children = Vec::new();
        let mut i = 0usize;

        loop {
            // The element cap is the parser's, not the frame's: a declared
            // count is a number read off the wire, so a frame may declare a
            // million elements and must not be allowed to allocate them
            // (SEC-M1).
            if i >= MAX_REPEAT_ELEMENTS {
                break;
            }
            match declared {
                Some(n) if i >= n => break,
                None if self.stop_repeating(spec) => break,
                _ => {}
            }

            let element = path.index(i);
            let mark = self.mark();
            self.depth += 1;
            let parsed = self.level(&spec.fields, &element, mutable, secret);
            self.depth -= 1;

            let Some(fields) = parsed else {
                self.restore(mark);
                if declared.is_some() {
                    return None;
                }
                break;
            };
            if declared.is_none() && self.pos == mark.pos {
                // A zero-width element would repeat for ever.
                self.restore(mark);
                break;
            }
            children.push(container(
                element,
                FieldKind::Group,
                fields,
                mutable,
                secret,
            ));
            i += 1;
        }

        Some(container(
            path,
            FieldKind::Repeat,
            children,
            mutable,
            secret,
        ))
    }

    /// Whether an unbounded `repeat` stops before its next element.
    ///
    /// [`MAX_REPEAT_ELEMENTS`] is the caller's check, for every repeat.
    fn stop_repeating(&self, spec: &FieldSpec) -> bool {
        if self.pos >= self.limit {
            return true;
        }
        match (spec.until, spec.terminator.as_ref()) {
            (Some(Until::Terminator), Some(terminator)) => self
                .buf
                .get(self.pos..self.limit)
                .is_some_and(|rest| rest.starts_with(terminator)),
            _ => false,
        }
    }

    fn choice(
        &mut self,
        spec: &FieldSpec,
        path: FieldPath,
        mutable: bool,
        secret: bool,
    ) -> Option<Node> {
        for alternative in &spec.fields {
            let mark = self.mark();
            self.depth += 1;
            let parsed = self.field(alternative, &path, mutable, secret);
            self.depth -= 1;
            match parsed {
                Some(node) => {
                    return Some(container(
                        path,
                        FieldKind::Choice,
                        vec![node],
                        mutable,
                        secret,
                    ));
                }
                None => self.restore(mark),
            }
        }
        None
    }

    fn leaf(
        &mut self,
        spec: &FieldSpec,
        path: FieldPath,
        mutable: bool,
        secret: bool,
    ) -> Option<Node> {
        let bytes = match spec.kind {
            FieldKind::U8 => self.take(1)?.to_vec(),
            FieldKind::U16 { .. } => self.take(2)?.to_vec(),
            FieldKind::U32 { .. } => self.take(4)?.to_vec(),
            FieldKind::Varint => self.take_varint()?,
            FieldKind::Decimal => self.take_decimal()?,
            FieldKind::CString => self.take_through(&[0])?,
            FieldKind::Line => {
                let terminator = spec.terminator.clone().unwrap_or_else(|| b"\r\n".to_vec());
                self.take_through(&terminator)?
            }
            FieldKind::Token => self.take_token(&spec.one_of)?,
            FieldKind::Delim => self.take_literal(spec.value.as_ref()?)?,
            FieldKind::Bytes { size } => self.take_payload(size, &spec.name)?,
            FieldKind::Group | FieldKind::Repeat | FieldKind::Choice => return None,
        };

        let mut node = Node {
            path,
            kind: spec.kind,
            bytes,
            children: Vec::new(),
            relation: spec.relation.clone(),
            mutable,
            secret,
            relation_broken: false,
        };
        if let Some(relation) = spec.relation.clone() {
            self.register(&relation, &mut node);
        }
        Some(node)
    }

    /// Read a relation's declared value and remember it for the fields it
    /// names — or mark the node broken when it does not fit what is left.
    fn register(&mut self, relation: &Relation, node: &mut Node) {
        let Some(value) = decode_number(node.kind, &node.bytes) else {
            node.relation_broken = true;
            return;
        };

        match relation {
            Relation::Count { of } => match usize::try_from(value) {
                Ok(count) => {
                    // A declared count is reachable under two names: the
                    // count field's own (`count_from: qdcount`, the spelling
                    // spec S2 and S3 use) and the repeat it counts.
                    self.counts.push((node.path.last().to_string(), count));
                    self.counts.push((of.clone(), count));
                }
                Err(_) => node.relation_broken = true,
            },
            Relation::Len {
                of,
                inclusive,
                adjust,
            } => {
                let own = i64::try_from(node.bytes.len()).unwrap_or(i64::MAX);
                // Every term here comes off the wire, so every step is
                // checked: a declared length near i64's ends must mark the
                // relation broken, not overflow (SEC-M2).
                let body = value
                    .checked_sub(i64::from(*adjust))
                    .and_then(|v| v.checked_sub(if *inclusive { own } else { 0 }));
                let available = i64::try_from(self.remaining()).unwrap_or(i64::MAX);
                let Some(Ok(body)) = body.map(usize::try_from) else {
                    node.relation_broken = true;
                    return;
                };
                if body > available.try_into().unwrap_or(usize::MAX) {
                    node.relation_broken = true;
                    return;
                }
                match of {
                    LenOf::Rest => self.limit = self.limit.min(self.pos.saturating_add(body)),
                    LenOf::Fields(names) => {
                        if let [name] = names.as_slice() {
                            self.budgets.push((name.clone(), body));
                        }
                    }
                }
            }
            Relation::Checksum { .. } => {}
        }
    }

    fn take_count(&mut self, name: &str) -> Option<usize> {
        let at = self.counts.iter().position(|(n, _)| n == name)?;
        Some(self.counts.remove(at).1)
    }

    fn take_budget(&mut self, name: &str) -> Option<usize> {
        let at = self.budgets.iter().position(|(n, _)| n == name)?;
        Some(self.budgets.remove(at).1)
    }

    fn take_payload(&mut self, size: Option<usize>, name: &str) -> Option<Vec<u8>> {
        let n = match size {
            Some(fixed) => fixed,
            None => self
                .take_budget(name)
                .unwrap_or_else(|| self.remaining())
                .min(self.remaining()),
        };
        Some(self.take(n)?.to_vec())
    }

    fn take_varint(&mut self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(4);
        loop {
            let byte = *self.take(1)?.first()?;
            out.push(byte);
            if byte & 0x80 == 0 {
                return Some(out);
            }
            if out.len() == 4 {
                return None;
            }
        }
    }

    fn take_decimal(&mut self) -> Option<Vec<u8>> {
        let rest = self.buf.get(self.pos..self.limit)?;
        let mut width = 0usize;
        if matches!(rest.first(), Some(b'-' | b'+')) {
            width += 1;
        }
        let digits = rest
            .get(width..)?
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        Some(self.take(width + digits)?.to_vec())
    }

    /// Everything up to and including `terminator`, which belongs to the
    /// field (spec S2).
    fn take_through(&mut self, terminator: &[u8]) -> Option<Vec<u8>> {
        if terminator.is_empty() {
            return None;
        }
        let rest = self.buf.get(self.pos..self.limit)?;
        let at = rest
            .windows(terminator.len())
            .position(|window| window == terminator)?;
        Some(self.take(at + terminator.len())?.to_vec())
    }

    /// The longest `one_of` word that matches here, case-insensitively. The
    /// bytes returned are the buffer's, so the case on the wire survives.
    fn take_token(&mut self, one_of: &[Literal]) -> Option<Vec<u8>> {
        let rest = self.buf.get(self.pos..self.limit)?;
        let mut best: Option<usize> = None;
        for candidate in one_of.iter().map(literal_bytes) {
            let Some(head) = rest.get(..candidate.len()) else {
                continue;
            };
            if head.eq_ignore_ascii_case(&candidate) && best.is_none_or(|len| candidate.len() > len)
            {
                best = Some(candidate.len());
            }
        }
        Some(self.take(best?)?.to_vec())
    }

    fn take_literal(&mut self, value: &Literal) -> Option<Vec<u8>> {
        let wanted = literal_bytes(value);
        if wanted.is_empty() {
            return None;
        }
        let head = self.buf.get(self.pos..self.limit)?.get(..wanted.len())?;
        if head != wanted.as_slice() {
            return None;
        }
        Some(self.take(wanted.len())?.to_vec())
    }
}

fn container(
    path: FieldPath,
    kind: FieldKind,
    children: Vec<Node>,
    mutable: bool,
    secret: bool,
) -> Node {
    Node {
        path,
        kind,
        bytes: Vec::new(),
        children,
        relation: None,
        mutable,
        secret,
        relation_broken: false,
    }
}

/// A literal's bytes: text as written, `0x..` decoded, an integer as its
/// decimal digits.
fn literal_bytes(literal: &Literal) -> Vec<u8> {
    match literal {
        Literal::Int(v) => v.to_string().into_bytes(),
        Literal::Text(text) => text.as_bytes().to_vec(),
        Literal::Hex(bytes) => bytes.clone(),
    }
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

pub(crate) fn decode_number(kind: FieldKind, bytes: &[u8]) -> Option<i64> {
    match kind {
        FieldKind::U8 => bytes.first().map(|b| i64::from(*b)),
        FieldKind::U16 { endian } => {
            let pair = [*bytes.first()?, *bytes.get(1)?];
            Some(i64::from(match endian {
                Endian::Be => u16::from_be_bytes(pair),
                Endian::Le => u16::from_le_bytes(pair),
            }))
        }
        FieldKind::U32 { endian } => {
            let quad = [
                *bytes.first()?,
                *bytes.get(1)?,
                *bytes.get(2)?,
                *bytes.get(3)?,
            ];
            Some(i64::from(match endian {
                Endian::Be => u32::from_be_bytes(quad),
                Endian::Le => u32::from_le_bytes(quad),
            }))
        }
        FieldKind::Varint => {
            let mut value: i64 = 0;
            for (i, byte) in bytes.iter().enumerate() {
                if i == 4 {
                    return None;
                }
                value += i64::from(byte & 0x7f) << (7 * i);
            }
            Some(value)
        }
        FieldKind::Decimal => std::str::from_utf8(bytes).ok()?.trim().parse::<i64>().ok(),
        _ => None,
    }
}

pub(crate) fn encode_number(kind: FieldKind, value: i64) -> Option<Vec<u8>> {
    match kind {
        FieldKind::U8 => u8::try_from(value).ok().map(|v| vec![v]),
        FieldKind::U16 { endian } => u16::try_from(value).ok().map(|v| match endian {
            Endian::Be => v.to_be_bytes().to_vec(),
            Endian::Le => v.to_le_bytes().to_vec(),
        }),
        FieldKind::U32 { endian } => u32::try_from(value).ok().map(|v| match endian {
            Endian::Be => v.to_be_bytes().to_vec(),
            Endian::Le => v.to_le_bytes().to_vec(),
        }),
        FieldKind::Varint => {
            let mut left = u32::try_from(value).ok()?;
            if left > 268_435_455 {
                return None;
            }
            let mut out = Vec::with_capacity(4);
            loop {
                let byte = u8::try_from(left & 0x7f).ok()?;
                left >>= 7;
                if left == 0 {
                    out.push(byte);
                    return Some(out);
                }
                out.push(byte | 0x80);
            }
        }
        FieldKind::Decimal => Some(value.to_string().into_bytes()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Re-satisfaction
// ---------------------------------------------------------------------------

/// Recompute every `len`, `count` and `checksum` node from its targets,
/// except the one at `except`.
///
/// A relation whose new value does not fit its field is left alone and marked
/// [`Node::relation_broken`]; one that is recomputed is no longer broken. The
/// pass repeats until nothing changes, so an outer length sees the new width
/// of an inner `decimal` one.
pub fn resatisfy(tree: &mut Tree, except: Option<&FieldPath>) {
    for _ in 0..MAX_RESATISFY_ROUNDS {
        let mut updates = Vec::new();
        let mut scopes: Vec<&[Node]> = Vec::new();
        plan_level(&tree.root, tree, &mut scopes, except, &mut updates);

        let mut changed = false;
        for (path, computed) in updates {
            let Some(node) = tree.get_mut(&path) else {
                continue;
            };
            match computed {
                Some(bytes) => {
                    if node.bytes != bytes {
                        node.bytes = bytes;
                        changed = true;
                    }
                    node.relation_broken = false;
                }
                None => node.relation_broken = true,
            }
        }
        if !changed {
            return;
        }
    }
}

type Update = (FieldPath, Option<Vec<u8>>);

/// Walk a level deepest-first, so an inner relation is recomputed before the
/// outer one that measures it.
fn plan_level<'a>(
    nodes: &'a [Node],
    tree: &Tree,
    scopes: &mut Vec<&'a [Node]>,
    except: Option<&FieldPath>,
    out: &mut Vec<Update>,
) {
    scopes.push(nodes);
    for node in nodes {
        if !node.children.is_empty() {
            plan_level(&node.children, tree, scopes, except, out);
        }
    }
    for node in nodes {
        let Some(relation) = &node.relation else {
            continue;
        };
        if except.is_some_and(|skipped| skipped == &node.path) {
            continue;
        }
        out.push((node.path.clone(), compute(node, relation, tree, scopes)));
    }
    scopes.pop();
}

fn compute(node: &Node, relation: &Relation, tree: &Tree, scopes: &[&[Node]]) -> Option<Vec<u8>> {
    match relation {
        Relation::Len {
            of,
            inclusive,
            adjust,
        } => {
            let measured = match of {
                LenOf::Rest => rest_after(tree, &node.path)?,
                LenOf::Fields(names) => {
                    let mut sum = 0usize;
                    for name in names {
                        sum = sum.saturating_add(rendered_len(resolve(name, scopes)?));
                    }
                    sum
                }
            };
            let mut value = i64::try_from(measured).unwrap_or(i64::MAX);
            if *inclusive {
                value = value.saturating_add(i64::try_from(node.bytes.len()).unwrap_or(0));
            }
            value = value.saturating_add(i64::from(*adjust));
            encode_number(node.kind, value)
        }
        Relation::Count { of } => {
            let target = resolve(of, scopes)?;
            let count = i64::try_from(target.children.len()).unwrap_or(i64::MAX);
            encode_number(node.kind, count)
        }
        Relation::Checksum { algo, over } => {
            let mut covered = Vec::new();
            for name in over {
                render_node(resolve(name, scopes)?, &mut covered);
            }
            let value = match algo {
                ChecksumAlgo::Crc32 => i64::from(crc32(&covered)),
                ChecksumAlgo::Internet => i64::from(internet_checksum(&covered)),
            };
            encode_number(node.kind, value)
        }
    }
}

/// Resolve a relation target the way `MessageSpec::validate` does: the
/// field's own level first, then each enclosing level, so `header.length`
/// may name the top-level `pdu`.
fn resolve<'a>(name: &str, scopes: &[&'a [Node]]) -> Option<&'a Node> {
    scopes
        .iter()
        .rev()
        .find_map(|level| level.iter().find(|node| node.path.last() == name))
}

/// How many bytes the message has after the node at `path`.
fn rest_after(tree: &Tree, path: &FieldPath) -> Option<usize> {
    let mut cursor = 0usize;
    let mut ends_at = None;
    walk_offsets(&tree.root, path.as_str(), &mut cursor, &mut ends_at);
    Some(cursor.saturating_sub(ends_at?))
}

fn walk_offsets(nodes: &[Node], target: &str, cursor: &mut usize, ends_at: &mut Option<usize>) {
    for node in nodes {
        if node.children.is_empty() {
            *cursor += node.bytes.len();
        } else {
            walk_offsets(&node.children, target, cursor, ends_at);
        }
        if ends_at.is_none() && node.path.as_str() == target {
            *ends_at = Some(*cursor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Endian, MessageSpec};

    /// The spec S2 Modbus example, verbatim.
    const MODBUS_YAML: &str = r#"
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
      - { name: function, type: u8, one_of: [1, 2, 3, 4] }
      - { name: address, type: u16 be, value: 0 }
      - { name: quantity, type: u16 be, range: [1, 125], value: 1 }
"#;

    /// A small RESP array grammar: the `count` field counts the `args`
    /// elements, each element's `len` measures its own `data`.
    const RESP_YAML: &str = r#"
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

    /// The T10 benign Modbus read-holding-registers frame.
    const MODBUS_FRAME: [u8; 12] = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
    ];

    fn modbus() -> MessageSpec {
        MessageSpec::from_yaml(MODBUS_YAML).expect("the S2 modbus example parses")
    }

    fn resp() -> MessageSpec {
        MessageSpec::from_yaml(RESP_YAML).expect("the inline RESP grammar parses")
    }

    fn bytes_at(tree: &Tree, path: &str) -> Vec<u8> {
        tree.get(&FieldPath::new(path))
            .unwrap_or_else(|| panic!("the tree has a node at '{path}'"))
            .bytes
            .clone()
    }

    #[test]
    fn modbus_parse_render_round_trip() {
        let spec = modbus();
        let tree = parse(&spec, &MODBUS_FRAME).expect("the benign modbus frame parses");

        assert_eq!(tree.grammar, "modbus");
        assert_eq!(bytes_at(&tree, "header.length"), vec![0x00, 0x06]);
        assert_eq!(bytes_at(&tree, "pdu.function"), vec![0x03]);
        assert_eq!(bytes_at(&tree, "header.transaction_id"), vec![0x00, 0x01]);
        assert_eq!(bytes_at(&tree, "pdu.quantity"), vec![0x00, 0x01]);
        assert_eq!(
            tree.get(&FieldPath::new("header.length"))
                .expect("header.length")
                .kind,
            FieldKind::U16 { endian: Endian::Be }
        );
        assert!(
            !tree
                .get(&FieldPath::new("header.length"))
                .expect("header.length")
                .relation_broken,
            "the declared length fits the frame"
        );
        assert_eq!(render(&tree), MODBUS_FRAME.to_vec());
    }

    #[test]
    fn resatisfy_recomputes_length_after_growth() {
        let spec = modbus();
        let mut tree = parse(&spec, &MODBUS_FRAME).expect("the benign modbus frame parses");

        tree.get_mut(&FieldPath::new("pdu.address"))
            .expect("pdu.address")
            .bytes
            .extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        resatisfy(&mut tree, None);

        assert_eq!(bytes_at(&tree, "header.length"), vec![0x00, 0x09]);
        assert_eq!(bytes_at(&tree, "pdu.function"), vec![0x03]);
        assert_eq!(render(&tree).len(), 15);
    }

    #[test]
    fn resatisfy_skips_the_excepted_relation() {
        let spec = modbus();
        let mut tree = parse(&spec, &MODBUS_FRAME).expect("the benign modbus frame parses");
        let length = FieldPath::new("header.length");

        tree.get_mut(&length).expect("header.length").bytes = vec![0x00, 0x07];
        resatisfy(&mut tree, Some(&length));
        assert_eq!(bytes_at(&tree, "header.length"), vec![0x00, 0x07]);

        resatisfy(&mut tree, None);
        assert_eq!(
            bytes_at(&tree, "header.length"),
            vec![0x00, 0x06],
            "without the exception the relation is recomputed"
        );
    }

    #[test]
    fn resp_repeat_and_count() {
        let spec = resp();
        let wire = b"*2\r\n$4\r\nPING\r\n$3\r\nabc\r\n";
        let mut tree = parse(&spec, wire).expect("the two-element RESP array parses");

        assert_eq!(bytes_at(&tree, "args[1].data"), b"abc".to_vec());
        assert_eq!(bytes_at(&tree, "count"), b"2".to_vec());
        assert_eq!(bytes_at(&tree, "args[0].len"), b"4".to_vec());
        assert_eq!(render(&tree), wire.to_vec());

        let third = tree
            .get(&FieldPath::new("args[1]"))
            .expect("args[1]")
            .clone();
        tree.get_mut(&FieldPath::new("args"))
            .expect("args")
            .children
            .push(third);
        resatisfy(&mut tree, None);

        assert_eq!(bytes_at(&tree, "count"), b"3".to_vec());
        assert_eq!(
            render(&tree),
            b"*3\r\n$4\r\nPING\r\n$3\r\nabc\r\n$3\r\nabc\r\n".to_vec()
        );
    }

    /// SPEC-I1: `count_from` names the **count field**, and that field's
    /// value bounds the repeat.
    ///
    /// Three elements are on the wire and the count says two: the repeat
    /// takes two, the third is left over, and leftover bytes are not this
    /// message. A parser that ignored the count would take all three and
    /// call the frame well-formed.
    #[test]
    fn count_from_names_the_count_field_which_bounds_the_repeat() {
        let spec = resp();
        let short = b"*2\r\n$4\r\nPING\r\n$3\r\nabc\r\n$3\r\nxyz\r\n";

        assert!(
            parse(&spec, short).is_none(),
            "`*2` bounds the array at two elements, so the third is leftover"
        );

        // And the other direction: a count of three with two elements on the
        // wire is short, which is not this message either.
        assert!(
            parse(&spec, b"*3\r\n$4\r\nPING\r\n$3\r\nabc\r\n").is_none(),
            "`*3` with two elements on the wire is a short array"
        );
    }

    #[test]
    fn declared_length_past_buffer_is_marked_not_trusted() {
        let spec = modbus();
        let mut frame = MODBUS_FRAME;
        frame[4] = 0x00;
        frame[5] = 0xff;

        let tree = parse(&spec, &frame).expect("an over-declared length still parses");

        assert_eq!(bytes_at(&tree, "header.length"), vec![0x00, 0xff]);
        assert!(
            tree.get(&FieldPath::new("header.length"))
                .expect("header.length")
                .relation_broken,
            "the declared length does not fit the frame"
        );
        assert_eq!(render(&tree), frame.to_vec());
    }

    #[test]
    fn field_path_render() {
        let path = FieldPath::new("questions").index(0).child("name").index(2);

        assert_eq!(path.to_string(), "questions[0].name[2]");
        assert_eq!(path.last(), "name");
        assert_eq!(
            FieldPath::new("header").child("length").to_string(),
            "header.length"
        );
        assert_eq!(FieldPath::new("header").child("length").last(), "length");
        assert_eq!(FieldPath::new("count").last(), "count");
        assert_eq!(FieldPath::new("args").index(1).last(), "args");
    }

    #[test]
    fn leaves_skip_groups_and_immutable_fields() {
        let spec = modbus();
        let tree = parse(&spec, &MODBUS_FRAME).expect("the benign modbus frame parses");

        let leaves: Vec<String> = tree.leaves().iter().map(|n| n.path.to_string()).collect();
        assert_eq!(
            leaves,
            vec![
                "header.transaction_id",
                "header.protocol_id",
                "header.length",
                "header.unit_id",
                "pdu.function",
                "pdu.address",
                "pdu.quantity",
            ]
        );

        let mutable: Vec<String> = tree
            .mutable_leaves()
            .iter()
            .map(|n| n.path.to_string())
            .collect();
        assert_eq!(
            mutable,
            vec![
                "header.protocol_id",
                "header.length",
                "header.unit_id",
                "pdu.function",
                "pdu.address",
                "pdu.quantity",
            ],
            "transaction_id is mutable: false"
        );
    }

    #[test]
    fn debug_never_prints_message_bytes() {
        let spec = resp();
        let tree = parse(&spec, b"*1\r\n$11\r\nS3CR3TBYTES\r\n").expect("the RESP array parses");

        let rendered = format!("{tree:?}");
        assert!(
            !rendered.contains("S3CR3TBYTES"),
            "Debug printed message bytes: {rendered}"
        );
        assert!(
            rendered.contains("<11 bytes>"),
            "Debug prints byte counts: {rendered}"
        );
    }

    /// A varint is at most four bytes (MQTT's rule), and the fifth
    /// continuation byte is a parse refusal, not a silent truncation and not
    /// a panic.
    #[test]
    fn varint_is_bounded_at_four_bytes() {
        let spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: n, type: varint }\n",
            "  - { name: rest, type: bytes }\n",
        ))
        .expect("the synthetic varint grammar parses");

        // One byte, two bytes, and the four-byte maximum all parse.
        for (wire, want) in [
            (vec![0x00u8], 0i64),
            (vec![0x7f], 127),
            (vec![0x80, 0x01], 128),
            (vec![0xff, 0xff, 0xff, 0x7f], 268_435_455),
        ] {
            let tree = parse(&spec, &wire).expect("a well-formed varint parses");
            assert_eq!(bytes_at(&tree, "n"), wire);
            assert_eq!(decode_number(FieldKind::Varint, &wire), Some(want));
            assert_eq!(render(&tree), wire);
        }

        // A fifth continuation byte: refused outright.
        assert!(parse(&spec, &[0x80, 0x80, 0x80, 0x80, 0x01]).is_none());
        // A varint that never terminates before the buffer ends: refused.
        assert!(parse(&spec, &[0x80, 0x80]).is_none());
        // Nothing at all: refused, not a zero-length varint.
        assert!(parse(&spec, &[]).is_none());

        // Five bytes never decode, and a value past the four-byte range
        // never encodes, so a relation holding one is left broken rather
        // than written wrong.
        assert_eq!(
            decode_number(FieldKind::Varint, &[0x80, 0x80, 0x80, 0x80, 0x01]),
            None
        );
        assert_eq!(
            encode_number(FieldKind::Varint, 268_435_455),
            Some(vec![0xff, 0xff, 0xff, 0x7f])
        );
        assert_eq!(encode_number(FieldKind::Varint, 268_435_456), None);
        assert_eq!(encode_number(FieldKind::Varint, -1), None);
    }

    /// `decimal` carries a sign, and a value that does not fit an `i64` is a
    /// refusal rather than a wrapped number.
    #[test]
    fn decimal_signs_and_overflow() {
        let spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: n, type: decimal }\n",
            "  - { name: crlf, type: delim, value: \"\\r\\n\" }\n",
        ))
        .expect("the synthetic decimal grammar parses");

        for (wire, want) in [
            (&b"0\r\n"[..], 0i64),
            (b"-1\r\n", -1),
            (b"+7\r\n", 7),
            (b"9223372036854775807\r\n", i64::MAX),
        ] {
            let tree = parse(&spec, wire).expect("a signed decimal parses");
            let digits = &wire[..wire.len() - 2];
            assert_eq!(bytes_at(&tree, "n"), digits.to_vec());
            assert_eq!(decode_number(FieldKind::Decimal, digits), Some(want));
            assert_eq!(render(&tree), wire.to_vec(), "render is byte-identical");
        }

        // A sign with no digits is not a decimal.
        assert!(parse(&spec, b"-\r\n").is_none());
        assert!(parse(&spec, b"\r\n").is_none());

        // Twenty digits overflow an i64: the bytes still parse and render
        // unchanged, but no number is read out of them.
        let wire = b"99999999999999999999\r\n";
        let tree = parse(&spec, wire).expect("the digits are still a decimal field");
        assert_eq!(render(&tree), wire.to_vec());
        assert_eq!(
            decode_number(FieldKind::Decimal, b"99999999999999999999"),
            None
        );
        assert_eq!(
            decode_number(FieldKind::Decimal, b"-99999999999999999999"),
            None
        );
        assert_eq!(
            encode_number(FieldKind::Decimal, -42),
            Some(b"-42".to_vec())
        );
    }

    /// A `len` relation whose recomputed value does not fit the field is
    /// marked broken and left alone: a fuzzing lane never writes a wrong
    /// number over an operator's bytes.
    /// SEC-M1: a declared element count is bounded by
    /// [`MAX_REPEAT_ELEMENTS`] like any other, so a frame that declares a
    /// million elements allocates at most the cap.
    ///
    /// The element here is zero-width once the buffer is spent (`bytes` with
    /// no size takes what is left, which is nothing), so without the cap the
    /// loop runs the declared count to the end.
    #[test]
    fn a_declared_count_is_capped_like_an_unbounded_repeat() {
        let spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: n, type: decimal, count: { of: items } }\n",
            "  - { name: crlf, type: delim, value: \"\\r\\n\" }\n",
            "  - name: items\n",
            "    type: repeat\n",
            "    count_from: n\n",
            "    fields:\n",
            "      - { name: data, type: bytes }\n",
        ))
        .expect("the synthetic counted-repeat grammar parses");

        let parsed = parse(&spec, b"1000000\r\n");

        match parsed {
            None => {}
            Some(tree) => {
                let items = tree
                    .get(&FieldPath::new("items"))
                    .expect("an `items` repeat");
                assert!(
                    items.children.len() <= MAX_REPEAT_ELEMENTS,
                    "a declared million elements yielded {} nodes, over the \
                     {MAX_REPEAT_ELEMENTS} cap",
                    items.children.len(),
                );
            }
        }
    }

    /// SEC-M2: an extreme declared length is arithmetic the parser must not
    /// panic on — it is read, found not to fit, and the node is marked.
    #[test]
    fn an_extreme_declared_length_is_broken_not_a_panic() {
        let spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: len, type: decimal, len: { of: rest, inclusive: true } }\n",
            "  - { name: crlf, type: delim, value: \"\\r\\n\" }\n",
            "  - { name: body, type: bytes }\n",
        ))
        .expect("the synthetic decimal-length grammar parses");

        for declared in ["9223372036854775807", "-9223372036854775808"] {
            let wire = format!("{declared}\r\nabc").into_bytes();
            let tree = parse(&spec, &wire)
                .unwrap_or_else(|| panic!("`{declared}` is read, not trusted, and still parses"));
            assert!(
                tree.get(&FieldPath::new("len"))
                    .expect("a `len` node")
                    .relation_broken,
                "`{declared}` does not fit what is left, so the relation is broken"
            );
            assert_eq!(render(&tree), wire, "the message is still rendered whole");
        }
    }

    #[test]
    fn a_relation_that_does_not_fit_is_marked_broken() {
        let spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: len, type: u8, len: { of: [body] } }\n",
            "  - { name: body, type: bytes }\n",
        ))
        .expect("the synthetic u8-length grammar parses");

        let mut wire = vec![4u8];
        wire.extend_from_slice(b"abcd");
        let mut tree = parse(&spec, &wire).expect("the frame parses");
        resatisfy(&mut tree, None);
        assert_eq!(bytes_at(&tree, "len"), vec![4]);
        assert!(
            !tree
                .get(&FieldPath::new("len"))
                .expect("len")
                .relation_broken
        );

        // Grow the body past what a u8 length can express, the way a
        // `BytesInsert` mutator does.
        tree.get_mut(&FieldPath::new("body")).expect("body").bytes = vec![b'a'; 300];
        resatisfy(&mut tree, None);
        assert_eq!(
            bytes_at(&tree, "len"),
            vec![4],
            "the unencodable length is left as it was"
        );
        assert!(
            tree.get(&FieldPath::new("len"))
                .expect("len")
                .relation_broken,
            "and the node says so"
        );
        let mut want = vec![4u8];
        want.extend_from_slice(&vec![b'a'; 300]);
        assert_eq!(render(&tree), want, "the message is still rendered whole");
    }

    #[test]
    fn checksum_relations_are_recomputed_from_their_targets() {
        let crc_spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: body, type: bytes, size: 9 }\n",
            "  - { name: crc, type: u32 be, checksum: { algo: crc32, over: [body] } }\n",
        ))
        .expect("the synthetic crc32 grammar parses");
        let mut wire = b"123456789".to_vec();
        wire.extend_from_slice(&[0, 0, 0, 0]);
        let mut tree = parse(&crc_spec, &wire).expect("the synthetic frame parses");

        resatisfy(&mut tree, None);

        assert_eq!(
            bytes_at(&tree, "crc"),
            vec![0xcb, 0xf4, 0x39, 0x26],
            "crc32(b\"123456789\") is the published 0xcbf43926"
        );
        assert_eq!(bytes_at(&tree, "body"), b"123456789".to_vec());

        let internet_spec = MessageSpec::from_yaml(concat!(
            "grammar: synthetic\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: body, type: bytes, size: 20 }\n",
            "  - { name: sum, type: u16 be, checksum: { algo: internet, over: [body] } }\n",
        ))
        .expect("the synthetic internet-checksum grammar parses");
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let mut wire = header.to_vec();
        wire.extend_from_slice(&[0, 0]);
        let mut tree = parse(&internet_spec, &wire).expect("the synthetic frame parses");

        resatisfy(&mut tree, None);

        assert_eq!(
            bytes_at(&tree, "sum"),
            vec![0xb8, 0x61],
            "the RFC 1071 checksum of the example IPv4 header is 0xb861"
        );
    }
}
