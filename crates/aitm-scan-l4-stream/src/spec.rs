//! The `MessageSpec` grammar format (spec S2).
//!
//! A grammar is a YAML document that reads top to bottom as a description of
//! one message: typed fields, and relations that name other fields instead of
//! holding a value (umbrella **D8.5**: boofuzz's shape). This module owns the
//! format itself — the types, the YAML (de)serialisation and validation.
//! Parsing bytes *against* a spec is `crate::tree`'s job.
//!
//! The YAML keys are fixed (spec S2) and unknown keys are refused, so a typo
//! in an operator-authored grammar is an error at load, not a silently
//! ignored line.
//!
//! ```yaml
//! grammar: modbus
//! transport: tcp
//! default_ports: [502]
//! message:
//!   - name: header
//!     type: group
//!     fields:
//!       - { name: transaction_id, type: u16 be, mutable: false }
//!       - { name: length, type: u16 be, len: { of: [unit_id, pdu] } }
//!       - { name: unit_id, type: u8, value: 1 }
//! ```

use std::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

/// The deepest field nesting a grammar may declare (spec S2 validation).
pub const MAX_DEPTH: usize = 8;
/// The most fields a grammar may declare, counted over the whole tree.
pub const MAX_FIELDS: usize = 256;

// ---------------------------------------------------------------------------
// The format
// ---------------------------------------------------------------------------

/// One grammar: the description of a single message.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MessageSpec {
    /// The grammar's name, matching `grammars/<name>.yaml` and
    /// [`GrammarKind::name`] for the eight embedded grammars.
    pub grammar: String,
    /// The transport the grammar speaks.
    pub transport: Transport,
    /// Ports this grammar is selected for when no grammar is named.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_ports: Vec<u16>,
    /// `true` when the protocol mandates closing on a malformed message, so a
    /// close is not evidence of a fault (MQTT).
    #[serde(default, skip_serializing_if = "is_false")]
    pub close_on_malformed_is_expected: bool,
    /// Free prose describing the reply shape. Ignored by the parser; kept so
    /// the file explains itself to the operator reading it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
    /// The ordered field list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub message: Vec<FieldSpec>,
}

// `skip_serializing_if` hands a reference, so this takes one.
fn is_false(b: &bool) -> bool {
    !*b
}

/// The transport a grammar speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// A byte stream.
    #[default]
    Tcp,
    /// A datagram.
    Udp,
}

/// One field of a message.
///
/// Deserialised from, and serialised to, the S2 YAML shape: `type` carries the
/// [`FieldKind`] string (with `size` as a sibling key for `bytes`), and the
/// three relation keys `len`, `count` and `checksum` fold into
/// [`FieldSpec::relation`] — at most one of them may be present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpec {
    /// The field's name, unique among its siblings; the last component of
    /// every path that names it.
    pub name: String,
    /// The field's type.
    pub kind: FieldKind,
    /// The value the generator emits by default.
    pub value: Option<Literal>,
    /// The values the generator may pick from, and the type-substitution
    /// mutator cycles through. Required for `token`.
    pub one_of: Vec<Literal>,
    /// An inclusive `[lo, hi]` range for integer fields.
    pub range: Option<(i64, i64)>,
    /// The terminator bytes of a `line` or `cstring`, which belong to the
    /// field.
    pub terminator: Option<Vec<u8>>,
    /// `false` for a field no mutator touches: transaction ids, protocol ids,
    /// magic bytes. Defaults to `true`.
    pub mutable: bool,
    /// `true` when the field's bytes must never appear in an excerpt. The
    /// field is still fuzzable. Defaults to `false`.
    pub secret: bool,
    /// The relation this field holds, if any.
    pub relation: Option<Relation>,
    /// Children of a `group`, `repeat` or `choice`.
    pub fields: Vec<FieldSpec>,
    /// For a `repeat`: the name of the `count` field holding its element
    /// count.
    pub count_from: Option<String>,
    /// For a `repeat` without a `count_from`: where it stops.
    pub until: Option<Until>,
}

impl Default for FieldSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: FieldKind::Bytes { size: None },
            value: None,
            one_of: Vec::new(),
            range: None,
            terminator: None,
            mutable: true,
            secret: false,
            relation: None,
            fields: Vec::new(),
            count_from: None,
            until: None,
        }
    }
}

/// A field's type (the S2 `type` strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldKind {
    /// `bytes`: the rest of the buffer, or a fixed `size`.
    Bytes {
        /// A fixed width, or `None` for "the rest".
        size: Option<usize>,
    },
    /// `u8`.
    U8,
    /// `u16 be` / `u16 le`.
    U16 {
        /// Byte order.
        endian: Endian,
    },
    /// `u32 be` / `u32 le`.
    U32 {
        /// Byte order.
        endian: Endian,
    },
    /// `varint`: MQTT's 7-bit continuation encoding.
    Varint,
    /// `decimal`: ASCII digits, optionally signed (RESP, memcached).
    Decimal,
    /// `cstring`: bytes up to a NUL, which belongs to the field.
    CString,
    /// `line`: bytes up to the terminator, which belongs to the field.
    Line,
    /// `token`: an ASCII word from `one_of`, matched case-insensitively.
    Token,
    /// `delim`: a fixed separator; `value` is required.
    Delim,
    /// `group`: an ordered set of children.
    Group,
    /// `repeat`: zero or more elements, bounded by `count_from` or `until`.
    Repeat,
    /// `choice`: the first child whose parse succeeds.
    Choice,
}

impl FieldKind {
    /// The S2 type string for this kind, the inverse of the `type` key's
    /// parse. `bytes`' `size` is a sibling key and is not part of the string.
    #[must_use]
    pub fn type_str(self) -> &'static str {
        match self {
            FieldKind::Bytes { .. } => "bytes",
            FieldKind::U8 => "u8",
            FieldKind::U16 { endian: Endian::Be } => "u16 be",
            FieldKind::U16 { endian: Endian::Le } => "u16 le",
            FieldKind::U32 { endian: Endian::Be } => "u32 be",
            FieldKind::U32 { endian: Endian::Le } => "u32 le",
            FieldKind::Varint => "varint",
            FieldKind::Decimal => "decimal",
            FieldKind::CString => "cstring",
            FieldKind::Line => "line",
            FieldKind::Token => "token",
            FieldKind::Delim => "delim",
            FieldKind::Group => "group",
            FieldKind::Repeat => "repeat",
            FieldKind::Choice => "choice",
        }
    }

    fn from_type_str(text: &str) -> Option<FieldKind> {
        let mut words = text.split_whitespace();
        let base = words.next()?;
        let endian = words.next();
        if words.next().is_some() {
            return None;
        }
        let kind = match (base, endian) {
            ("bytes", None) => FieldKind::Bytes { size: None },
            ("u8", None) => FieldKind::U8,
            ("u16", Some("be")) => FieldKind::U16 { endian: Endian::Be },
            ("u16", Some("le")) => FieldKind::U16 { endian: Endian::Le },
            ("u32", Some("be")) => FieldKind::U32 { endian: Endian::Be },
            ("u32", Some("le")) => FieldKind::U32 { endian: Endian::Le },
            ("varint", None) => FieldKind::Varint,
            ("decimal", None) => FieldKind::Decimal,
            ("cstring", None) => FieldKind::CString,
            ("line", None) => FieldKind::Line,
            ("token", None) => FieldKind::Token,
            ("delim", None) => FieldKind::Delim,
            ("group", None) => FieldKind::Group,
            ("repeat", None) => FieldKind::Repeat,
            ("choice", None) => FieldKind::Choice,
            _ => return None,
        };
        Some(kind)
    }
}

/// Byte order of an integer field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    /// Big endian, network order.
    Be,
    /// Little endian.
    Le,
}

/// A literal in a grammar: `value`, a `one_of` entry or a terminator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Literal {
    /// A YAML integer.
    Int(i64),
    /// A quoted string.
    Text(String),
    /// A `0x..` string, decoded at load.
    Hex(Vec<u8>),
}

/// A relation: a field whose value is computed from other fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relation {
    /// `len`: the length of the named fields, or of the rest of the message.
    /// Width and byte order come from the field's own type.
    Len {
        /// What is measured.
        of: LenOf,
        /// Whether the length counts the length field itself.
        inclusive: bool,
        /// A constant added to the computed length.
        adjust: i32,
    },
    /// `count`: the number of elements of the named `repeat`.
    Count {
        /// The `repeat` field's name.
        of: String,
    },
    /// `checksum`: a checksum over the named fields.
    Checksum {
        /// The algorithm.
        algo: ChecksumAlgo,
        /// The fields covered.
        over: Vec<String>,
    },
}

/// What a `len` relation measures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LenOf {
    /// The named fields, in order. A name resolves against the field's own
    /// level first, then outwards.
    Fields(Vec<String>),
    /// Every byte after this field.
    Rest,
}

/// A checksum algorithm. None of the eight grammars needs one; the vocabulary
/// exists so a later grammar does not change the format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChecksumAlgo {
    /// CRC-32 (IEEE).
    Crc32,
    /// The RFC 1071 internet checksum.
    Internet,
}

/// Where a `repeat` without a `count_from` stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Until {
    /// At the end of the buffer.
    End,
    /// At the element terminator.
    Terminator,
}

// ---------------------------------------------------------------------------
// Grammar names
// ---------------------------------------------------------------------------

/// The nine grammars the lane ships: the eight of spec S3 plus the `raw`
/// fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrammarKind {
    /// Generic TLV, inferred from seeds (spec S4).
    Tlv,
    /// Redis RESP.
    Resp,
    /// memcached's text protocol.
    Memcached,
    /// DNS.
    Dns,
    /// Modbus/TCP.
    Modbus,
    /// MQTT 3.1.1.
    Mqtt,
    /// SMTP.
    Smtp,
    /// FTP.
    Ftp,
    /// The opaque fallback: one `bytes` field.
    Raw,
}

impl GrammarKind {
    /// The grammar's canonical name, as it appears in a profile, in
    /// `grammars/<name>.yaml` and in evidence.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            GrammarKind::Tlv => "tlv",
            GrammarKind::Resp => "resp",
            GrammarKind::Memcached => "memcached",
            GrammarKind::Dns => "dns",
            GrammarKind::Modbus => "modbus",
            GrammarKind::Mqtt => "mqtt",
            GrammarKind::Smtp => "smtp",
            GrammarKind::Ftp => "ftp",
            GrammarKind::Raw => "raw",
        }
    }

    /// The grammar named by an operator, or `None` when no grammar has that
    /// name. Names are matched exactly: `modbus-tcp` is the one accepted
    /// alias (spec A6), and `MODBUS` is not a grammar.
    #[must_use]
    pub fn parse(name: &str) -> Option<GrammarKind> {
        let kind = match name {
            "tlv" => GrammarKind::Tlv,
            "resp" => GrammarKind::Resp,
            "memcached" => GrammarKind::Memcached,
            "dns" => GrammarKind::Dns,
            "modbus" | "modbus-tcp" => GrammarKind::Modbus,
            "mqtt" => GrammarKind::Mqtt,
            "smtp" => GrammarKind::Smtp,
            "ftp" => GrammarKind::Ftp,
            "raw" => GrammarKind::Raw,
            _ => return None,
        };
        Some(kind)
    }
}

impl fmt::Display for GrammarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Why a grammar is not a valid [`MessageSpec`]. Every variant names the
/// offending field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// Two fields at one level share a name.
    DuplicateName(String),
    /// A `len`, `count` or `checksum` names a field that is not in scope.
    UnknownTarget {
        /// The field holding the relation.
        field: String,
        /// The name it could not resolve.
        target: String,
    },
    /// A `delim` without the required `value`.
    DelimWithoutValue(String),
    /// A `token` without the required `one_of`.
    TokenWithoutOneOf(String),
    /// A `repeat` with neither `count_from` nor `until`.
    RepeatWithoutCount(String),
    /// A `repeat` whose `count_from` names a field that does not carry
    /// `count: { of: <that repeat> }`.
    CountFromMismatch {
        /// The repeat holding the `count_from`.
        repeat: String,
        /// The field it names.
        field: String,
    },
    /// A relation on a field whose type cannot hold it. The string is
    /// `<field>: <why>`.
    BadRelationKind(String),
    /// Field nesting deeper than [`MAX_DEPTH`]. The number is the depth
    /// reached.
    TooDeep(usize),
    /// More than [`MAX_FIELDS`] fields. The number is the count.
    TooManyFields(usize),
    /// Two of `len`, `count` and `checksum` on one field. The string is
    /// `<field>: <first> and <second>`.
    TwoRelations(String),
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpecError::DuplicateName(name) => {
                write!(f, "field '{name}' is declared twice at the same level")
            }
            SpecError::UnknownTarget { field, target } => write!(
                f,
                "field '{field}' names '{target}', which is not a field in scope"
            ),
            SpecError::DelimWithoutValue(name) => {
                write!(f, "field '{name}' is a delim and needs a value")
            }
            SpecError::TokenWithoutOneOf(name) => {
                write!(f, "field '{name}' is a token and needs one_of")
            }
            SpecError::RepeatWithoutCount(name) => write!(
                f,
                "field '{name}' is a repeat and needs count_from or until"
            ),
            SpecError::CountFromMismatch { repeat, field } => write!(
                f,
                "field '{repeat}' takes its count from '{field}', which does not carry \
                 count: {{ of: {repeat} }}"
            ),
            SpecError::BadRelationKind(what) => write!(f, "field {what}"),
            SpecError::TooDeep(depth) => write!(
                f,
                "fields nest {depth} levels deep; at most {MAX_DEPTH} are allowed"
            ),
            SpecError::TooManyFields(count) => write!(
                f,
                "the grammar declares {count} fields; at most {MAX_FIELDS} are allowed"
            ),
            SpecError::TwoRelations(what) => write!(
                f,
                "field {what}: a field holds at most one of len, count and checksum"
            ),
        }
    }
}

impl std::error::Error for SpecError {}

impl MessageSpec {
    /// Parse a grammar document and validate it.
    ///
    /// # Errors
    ///
    /// When the YAML is not a `MessageSpec` (an unknown key, a bad `type`
    /// string, two relations on one field) or when [`validate`] refuses it.
    ///
    /// [`validate`]: MessageSpec::validate
    pub fn from_yaml(text: &str) -> anyhow::Result<MessageSpec> {
        let spec: MessageSpec = serde_yaml::from_str(text)
            .map_err(|e| anyhow::anyhow!("l4_stream: grammar is not a MessageSpec: {e}"))?;
        spec.validate().map_err(|e| {
            anyhow::anyhow!(
                "l4_stream: grammar '{grammar}' is invalid: {e}",
                grammar = spec.grammar
            )
        })?;
        Ok(spec)
    }

    /// Render the grammar back to YAML.
    ///
    /// # Errors
    ///
    /// When the serialiser refuses the value.
    pub fn to_yaml(&self) -> anyhow::Result<String> {
        serde_yaml::to_string(self).map_err(|e| {
            anyhow::anyhow!(
                "l4_stream: grammar '{grammar}' does not serialise: {e}",
                grammar = self.grammar
            )
        })
    }

    /// Check the S2 rules: unique names per level, resolvable relation
    /// targets, `delim` with a value, `token` with `one_of`, `repeat` with a
    /// bound, relations only on the types that can hold them, and the depth
    /// and field-count limits.
    ///
    /// # Errors
    ///
    /// The first rule broken, naming the field.
    pub fn validate(&self) -> Result<(), SpecError> {
        let total = count_fields(&self.message);
        if total > MAX_FIELDS {
            return Err(SpecError::TooManyFields(total));
        }
        let mut scopes: Vec<Vec<&str>> = Vec::new();
        let mut seen: Vec<&FieldSpec> = Vec::with_capacity(total);
        validate_level(&self.message, &mut scopes, &mut seen, 1)
    }
}

fn count_fields(fields: &[FieldSpec]) -> usize {
    fields
        .iter()
        .map(|f| 1 + count_fields(&f.fields))
        .sum::<usize>()
}

fn validate_level<'a>(
    fields: &'a [FieldSpec],
    scopes: &mut Vec<Vec<&'a str>>,
    seen: &mut Vec<&'a FieldSpec>,
    depth: usize,
) -> Result<(), SpecError> {
    if depth > MAX_DEPTH {
        return Err(SpecError::TooDeep(depth));
    }

    let mut names: Vec<&str> = Vec::with_capacity(fields.len());
    for field in fields {
        if names.contains(&field.name.as_str()) {
            return Err(SpecError::DuplicateName(field.name.clone()));
        }
        names.push(&field.name);
    }
    scopes.push(names);

    let result = (|| {
        for field in fields {
            // Pre-order, so when a `count_from` is resolved `seen` holds
            // exactly the fields declared before it in document order.
            validate_field(field, scopes, seen)?;
            seen.push(field);
            if !field.fields.is_empty() {
                validate_level(&field.fields, scopes, seen, depth + 1)?;
            }
        }
        Ok(())
    })();

    scopes.pop();
    result
}

fn validate_field(
    field: &FieldSpec,
    scopes: &[Vec<&str>],
    seen: &[&FieldSpec],
) -> Result<(), SpecError> {
    match field.kind {
        FieldKind::Delim if field.value.is_none() => {
            return Err(SpecError::DelimWithoutValue(field.name.clone()));
        }
        FieldKind::Token if field.one_of.is_empty() => {
            return Err(SpecError::TokenWithoutOneOf(field.name.clone()));
        }
        FieldKind::Repeat if field.count_from.is_none() && field.until.is_none() => {
            return Err(SpecError::RepeatWithoutCount(field.name.clone()));
        }
        _ => {}
    }

    if let Some(count_from) = &field.count_from {
        resolve_count_from(field, count_from, seen)?;
    }

    let Some(relation) = &field.relation else {
        return Ok(());
    };

    // A relation's value is an encoded number, so only the numeric types can
    // hold one; a checksum needs a fixed width (spec S2 validation).
    let numeric = matches!(
        field.kind,
        FieldKind::U8
            | FieldKind::U16 { .. }
            | FieldKind::U32 { .. }
            | FieldKind::Varint
            | FieldKind::Decimal
    );
    if !numeric {
        return Err(SpecError::BadRelationKind(format!(
            "'{name}': type '{ty}' cannot hold a relation",
            name = field.name,
            ty = field.kind.type_str()
        )));
    }

    match relation {
        Relation::Len { of, .. } => {
            if let LenOf::Fields(targets) = of {
                for target in targets {
                    resolve(field, target, scopes)?;
                }
            }
        }
        Relation::Count { of } => resolve(field, of, scopes)?,
        Relation::Checksum { over, .. } => {
            if matches!(field.kind, FieldKind::Varint | FieldKind::Decimal) {
                return Err(SpecError::BadRelationKind(format!(
                    "'{name}': type '{ty}' carries len or count only, not a checksum",
                    name = field.name,
                    ty = field.kind.type_str()
                )));
            }
            for target in over {
                resolve(field, target, scopes)?;
            }
        }
    }

    Ok(())
}

/// Resolve a `repeat`'s `count_from`, which names the **count field**:
/// RESP's `count`, DNS's `qdcount` (spec S2, S3).
///
/// Two rules. The field must be declared *earlier in document order* — its
/// own level, an ancestor, or a descendant of an earlier sibling, which is
/// where DNS's `qdcount` sits — because a parser can only bound a repeat by
/// a count it has already read. And it must carry
/// `count: { of: <this repeat> }`, so that the count field and the repeat it
/// counts name each other and neither spelling can drift from the other.
fn resolve_count_from(
    field: &FieldSpec,
    count_from: &str,
    seen: &[&FieldSpec],
) -> Result<(), SpecError> {
    let mut declared = false;
    for earlier in seen {
        if earlier.name != count_from {
            continue;
        }
        declared = true;
        if matches!(&earlier.relation, Some(Relation::Count { of }) if of == &field.name) {
            return Ok(());
        }
    }
    if declared {
        return Err(SpecError::CountFromMismatch {
            repeat: field.name.clone(),
            field: count_from.to_string(),
        });
    }
    Err(SpecError::UnknownTarget {
        field: field.name.clone(),
        target: count_from.to_string(),
    })
}

/// Resolve a relation target against the field's own level, then outwards:
/// `header.length`'s `len: { of: [unit_id, pdu] }` names a sibling and a
/// top-level field (spec S2's Modbus example).
fn resolve(field: &FieldSpec, target: &str, scopes: &[Vec<&str>]) -> Result<(), SpecError> {
    if scopes.iter().rev().any(|level| level.contains(&target)) {
        return Ok(());
    }
    Err(SpecError::UnknownTarget {
        field: field.name.clone(),
        target: target.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Serde: literals
// ---------------------------------------------------------------------------

fn hex_literal(text: &str) -> Option<Vec<u8>> {
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if body.is_empty() || body.len() % 2 != 0 {
        return None;
    }
    let digits: Vec<u8> = body.bytes().collect();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

impl Literal {
    /// A literal reading of `text`: a `0x..` string of whole bytes is
    /// [`Literal::Hex`], anything else is [`Literal::Text`].
    fn from_text(text: &str) -> Literal {
        match hex_literal(text) {
            Some(bytes) => Literal::Hex(bytes),
            None => Literal::Text(text.to_string()),
        }
    }
}

impl Serialize for Literal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Literal::Int(v) => serializer.serialize_i64(*v),
            Literal::Text(text) => serializer.serialize_str(text),
            Literal::Hex(bytes) => serializer.serialize_str(&encode_hex(bytes)),
        }
    }
}

impl<'de> Deserialize<'de> for Literal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LiteralVisitor;

        impl Visitor<'_> for LiteralVisitor {
            type Value = Literal;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer, a string, or a 0x.. hex string")
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Literal, E> {
                Ok(Literal::Int(v))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Literal, E> {
                i64::try_from(v)
                    .map(Literal::Int)
                    .map_err(|_| E::custom(format!("integer literal {v} does not fit in i64")))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Literal, E> {
                Ok(Literal::from_text(v))
            }
        }

        deserializer.deserialize_any(LiteralVisitor)
    }
}

// ---------------------------------------------------------------------------
// Serde: field kinds
// ---------------------------------------------------------------------------

impl Serialize for FieldKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.type_str())
    }
}

impl<'de> Deserialize<'de> for FieldKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        FieldKind::from_type_str(&text).ok_or_else(|| {
            de::Error::custom(format!(
                "unknown field type '{text}' (integer types carry an endian: 'u16 be', 'u32 le')"
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Serde: len targets
// ---------------------------------------------------------------------------

impl Serialize for LenOf {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            LenOf::Rest => serializer.serialize_str("rest"),
            LenOf::Fields(names) => names.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for LenOf {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LenOfVisitor;

        impl<'de> Visitor<'de> for LenOfVisitor {
            type Value = LenOf;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the string 'rest' or a list of field names")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<LenOf, E> {
                Ok(if v == "rest" {
                    LenOf::Rest
                } else {
                    LenOf::Fields(vec![v.to_string()])
                })
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<LenOf, A::Error> {
                let mut names = Vec::new();
                while let Some(name) = seq.next_element::<String>()? {
                    names.push(name);
                }
                Ok(LenOf::Fields(names))
            }
        }

        deserializer.deserialize_any(LenOfVisitor)
    }
}

// ---------------------------------------------------------------------------
// Serde: fields
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct LenWire {
    of: LenOf,
    #[serde(default)]
    inclusive: bool,
    #[serde(default)]
    adjust: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct CountWire {
    of: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct ChecksumWire {
    algo: ChecksumAlgo,
    over: Vec<String>,
}

fn yes() -> bool {
    true
}

/// The YAML shape of a field, one key per S2 key. [`FieldSpec`] is this with
/// `size` folded into the kind and `len`/`count`/`checksum` folded into one
/// `relation`.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct FieldSpecWire {
    name: String,
    #[serde(rename = "type")]
    ty: FieldKind,
    #[serde(default)]
    size: Option<usize>,
    #[serde(default)]
    value: Option<Literal>,
    #[serde(default)]
    one_of: Vec<Literal>,
    #[serde(default)]
    range: Option<(i64, i64)>,
    #[serde(default)]
    terminator: Option<Literal>,
    #[serde(default = "yes")]
    mutable: bool,
    #[serde(default)]
    secret: bool,
    #[serde(default)]
    len: Option<LenWire>,
    #[serde(default)]
    count: Option<CountWire>,
    #[serde(default)]
    checksum: Option<ChecksumWire>,
    #[serde(default)]
    fields: Vec<FieldSpec>,
    #[serde(default)]
    count_from: Option<String>,
    #[serde(default)]
    until: Option<Until>,
}

fn field_from_wire(wire: FieldSpecWire) -> Result<FieldSpec, String> {
    let kind = match (wire.ty, wire.size) {
        (FieldKind::Bytes { .. }, size) => FieldKind::Bytes { size },
        (other, None) => other,
        (other, Some(_)) => {
            return Err(format!(
                "field '{name}': 'size' is only valid on type bytes, not '{ty}'",
                name = wire.name,
                ty = other.type_str()
            ))
        }
    };

    let mut present: Vec<&str> = Vec::new();
    if wire.len.is_some() {
        present.push("len");
    }
    if wire.count.is_some() {
        present.push("count");
    }
    if wire.checksum.is_some() {
        present.push("checksum");
    }
    if present.len() > 1 {
        return Err(SpecError::TwoRelations(format!(
            "'{name}': {first} and {second}",
            name = wire.name,
            first = present[0],
            second = present[1]
        ))
        .to_string());
    }

    let relation = if let Some(len) = wire.len {
        Some(Relation::Len {
            of: len.of,
            inclusive: len.inclusive,
            adjust: len.adjust,
        })
    } else if let Some(count) = wire.count {
        Some(Relation::Count { of: count.of })
    } else {
        wire.checksum.map(|checksum| Relation::Checksum {
            algo: checksum.algo,
            over: checksum.over,
        })
    };

    let terminator = match wire.terminator {
        None => None,
        Some(Literal::Text(text)) => Some(text.into_bytes()),
        Some(Literal::Hex(bytes)) => Some(bytes),
        Some(Literal::Int(v)) => {
            return Err(format!(
                "field '{name}': terminator {v} must be a string or a 0x.. hex string",
                name = wire.name
            ))
        }
    };

    Ok(FieldSpec {
        name: wire.name,
        kind,
        value: wire.value,
        one_of: wire.one_of,
        range: wire.range,
        terminator,
        mutable: wire.mutable,
        secret: wire.secret,
        relation,
        fields: wire.fields,
        count_from: wire.count_from,
        until: wire.until,
    })
}

impl<'de> Deserialize<'de> for FieldSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = FieldSpecWire::deserialize(deserializer)?;
        field_from_wire(wire).map_err(de::Error::custom)
    }
}

impl Serialize for FieldSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("type", self.kind.type_str())?;
        if let FieldKind::Bytes { size: Some(size) } = self.kind {
            map.serialize_entry("size", &size)?;
        }
        if let Some(value) = &self.value {
            map.serialize_entry("value", value)?;
        }
        if !self.one_of.is_empty() {
            map.serialize_entry("one_of", &self.one_of)?;
        }
        if let Some((lo, hi)) = self.range {
            map.serialize_entry("range", &[lo, hi])?;
        }
        if let Some(terminator) = &self.terminator {
            map.serialize_entry("terminator", &terminator_literal(terminator))?;
        }
        if !self.mutable {
            map.serialize_entry("mutable", &false)?;
        }
        if self.secret {
            map.serialize_entry("secret", &true)?;
        }
        match &self.relation {
            None => {}
            Some(Relation::Len {
                of,
                inclusive,
                adjust,
            }) => map.serialize_entry(
                "len",
                &LenWire {
                    of: of.clone(),
                    inclusive: *inclusive,
                    adjust: *adjust,
                },
            )?,
            Some(Relation::Count { of }) => {
                map.serialize_entry("count", &CountWire { of: of.clone() })?;
            }
            Some(Relation::Checksum { algo, over }) => map.serialize_entry(
                "checksum",
                &ChecksumWire {
                    algo: *algo,
                    over: over.clone(),
                },
            )?,
        }
        if let Some(count_from) = &self.count_from {
            map.serialize_entry("count_from", count_from)?;
        }
        if let Some(until) = self.until {
            map.serialize_entry("until", &until)?;
        }
        if !self.fields.is_empty() {
            map.serialize_entry("fields", &self.fields)?;
        }
        map.end()
    }
}

/// A terminator round-trips as text when it is text, and as `0x..` otherwise.
fn terminator_literal(bytes: &[u8]) -> Literal {
    match std::str::from_utf8(bytes) {
        Ok(text) if hex_literal(text).is_none() => Literal::Text(text.to_string()),
        _ => Literal::Hex(bytes.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec S2 example, verbatim: `grammars/modbus.yaml`, abridged.
    const MODBUS_YAML: &str = r#"
grammar: modbus
transport: tcp
default_ports: [502]
reply: >
  The server answers with the same transaction id; a function code with the
  high bit set is an exception and carries one exception-code byte.
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

    #[test]
    fn modbus_example_round_trips() {
        let spec = MessageSpec::from_yaml(MODBUS_YAML).expect("the S2 modbus example parses");

        assert_eq!(spec.grammar, "modbus");
        assert_eq!(spec.transport, Transport::Tcp);
        assert_eq!(spec.default_ports, vec![502]);
        assert!(!spec.close_on_malformed_is_expected);
        assert_eq!(spec.message.len(), 2);
        assert_eq!(spec.message[0].name, "header");
        assert_eq!(spec.message[0].kind, FieldKind::Group);
        assert_eq!(
            spec.message[0].fields[2].relation,
            Some(Relation::Len {
                of: LenOf::Fields(vec!["unit_id".to_string(), "pdu".to_string()]),
                inclusive: false,
                adjust: 0,
            })
        );
        assert!(!spec.message[0].fields[0].mutable);
        assert!(spec.message[0].fields[1].mutable);
        assert_eq!(spec.message[0].fields[1].value, Some(Literal::Int(0)));
        assert_eq!(
            spec.message[1].fields[0].one_of,
            vec![
                Literal::Int(1),
                Literal::Int(2),
                Literal::Int(3),
                Literal::Int(4)
            ]
        );
        assert_eq!(spec.message[1].fields[2].range, Some((1, 125)));

        let yaml = spec.to_yaml().expect("the parsed spec serialises");
        let again = MessageSpec::from_yaml(&yaml).expect("the serialised spec parses back");
        assert_eq!(again, spec);
    }

    #[test]
    fn len_of_missing_field_names_it() {
        let yaml = concat!(
            "grammar: t\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: length, type: u16 be, len: { of: [nope] } }\n",
            "  - { name: body, type: bytes }\n",
        );

        let parsed: MessageSpec = serde_yaml::from_str(yaml).expect("the document parses");
        let err = parsed
            .validate()
            .expect_err("an unknown len target is refused");
        assert_eq!(
            err,
            SpecError::UnknownTarget {
                field: "length".to_string(),
                target: "nope".to_string(),
            }
        );
        assert!(err.to_string().contains("nope"), "display: {err}");

        let err = MessageSpec::from_yaml(yaml).expect_err("from_yaml validates");
        assert!(err.to_string().contains("nope"), "display: {err}");
    }

    /// SPEC-I1: `count_from` names a count field declared earlier, and that
    /// field must carry the matching `count: { of: <this repeat> }`.
    #[test]
    fn count_from_names_an_earlier_count_field() {
        // (a) The spelling spec S2 and S3 use: the repeat names the field
        // that counts it, and that field may sit inside an earlier group —
        // which is where DNS's `qdcount` is.
        let good = concat!(
            "grammar: t\n",
            "transport: udp\n",
            "message:\n",
            "  - name: header\n",
            "    type: group\n",
            "    fields:\n",
            "      - { name: qdcount, type: u16 be, count: { of: questions } }\n",
            "  - name: questions\n",
            "    type: repeat\n",
            "    count_from: qdcount\n",
            "    fields:\n",
            "      - { name: qtype, type: u16 be }\n",
        );
        MessageSpec::from_yaml(good).expect("a count field in an earlier group is in scope");

        // (b) A name no field carries.
        let unknown = good.replace("count_from: qdcount", "count_from: nope");
        let err = MessageSpec::from_yaml(&unknown).expect_err("an unknown count_from is refused");
        assert!(err.to_string().contains("nope"), "display: {err}");
        assert!(err.to_string().contains("questions"), "display: {err}");

        // (c) A field that exists but carries no `count: { of: questions }`.
        let mismatch = concat!(
            "grammar: t\n",
            "transport: udp\n",
            "message:\n",
            "  - { name: qdcount, type: u16 be }\n",
            "  - name: questions\n",
            "    type: repeat\n",
            "    count_from: qdcount\n",
            "    fields:\n",
            "      - { name: qtype, type: u16 be }\n",
        );
        let err = MessageSpec::from_yaml(mismatch)
            .expect_err("a count_from whose field does not count this repeat is refused");
        assert!(err.to_string().contains("qdcount"), "display: {err}");
        assert!(err.to_string().contains("questions"), "display: {err}");

        // (d) The old inverted spelling — the repeat naming itself — is no
        // longer a valid grammar.
        let inverted = concat!(
            "grammar: t\n",
            "transport: udp\n",
            "message:\n",
            "  - { name: qdcount, type: u16 be, count: { of: questions } }\n",
            "  - name: questions\n",
            "    type: repeat\n",
            "    count_from: questions\n",
            "    fields:\n",
            "      - { name: qtype, type: u16 be }\n",
        );
        let err = MessageSpec::from_yaml(inverted)
            .expect_err("a repeat may not name itself as its count field");
        assert!(err.to_string().contains("questions"), "display: {err}");
    }

    #[test]
    fn type_strings_parse() {
        let yaml = concat!(
            "grammar: t\n",
            "transport: udp\n",
            "message:\n",
            "  - { name: a, type: u16 be }\n",
            "  - { name: b, type: u32 le }\n",
            "  - { name: c, type: varint }\n",
            "  - { name: d, type: decimal }\n",
            "  - { name: e, type: line, terminator: \"\\r\\n\" }\n",
            "  - { name: f, type: bytes, size: 4 }\n",
            "  - { name: g, type: bytes }\n",
        );
        let spec = MessageSpec::from_yaml(yaml).expect("every S2 type string parses");

        let kinds: Vec<FieldKind> = spec.message.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FieldKind::U16 { endian: Endian::Be },
                FieldKind::U32 { endian: Endian::Le },
                FieldKind::Varint,
                FieldKind::Decimal,
                FieldKind::Line,
                FieldKind::Bytes { size: Some(4) },
                FieldKind::Bytes { size: None },
            ]
        );
        assert_eq!(spec.message[4].terminator.as_deref(), Some(&b"\r\n"[..]));

        let err = MessageSpec::from_yaml(concat!(
            "grammar: t\n",
            "transport: tcp\n",
            "message:\n",
            "  - { name: a, type: u16 }\n",
        ))
        .expect_err("an integer type without an endian is refused");
        assert!(err.to_string().contains("u16"), "display: {err}");
    }

    /// Hostile or malformed operator YAML is refused, never accepted and
    /// never a panic (S2 validation; Task 1 flagged that the depth limit is
    /// checked *after* deserialisation, so this pins what happens to a
    /// document deeper than the deserialiser itself will go).
    #[test]
    fn hostile_yaml_is_refused_not_accepted() {
        fn nested(depth: usize) -> String {
            let mut yaml = String::from("grammar: t\ntransport: tcp\nmessage:\n");
            let mut indent = String::from("  ");
            for i in 0..depth {
                yaml.push_str(&format!(
                    "{indent}- name: g{i}\n{indent}  type: group\n{indent}  fields:\n"
                ));
                indent.push_str("    ");
            }
            yaml.push_str(&format!("{indent}- {{ name: leaf, type: u8 }}\n"));
            yaml
        }

        // One level past MAX_DEPTH: our own check, naming the depth reached.
        let nine: MessageSpec =
            serde_yaml::from_str(&nested(9)).expect("nine levels still deserialise");
        assert_eq!(nine.validate(), Err(SpecError::TooDeep(9)));
        let err = MessageSpec::from_yaml(&nested(9)).expect_err("nine levels are refused");
        assert!(
            err.to_string()
                .contains("fields nest 9 levels deep; at most 8 are allowed"),
            "display: {err}"
        );

        // Far past it, the deserialiser's own recursion limit stops first.
        // The point is that it is an error and not a stack overflow: the
        // process is still running to make the next assertion.
        for depth in [64usize, 512, 4096] {
            let err = MessageSpec::from_yaml(&nested(depth))
                .err()
                .unwrap_or_else(|| panic!("depth {depth} must not be accepted"));
            assert!(
                err.to_string().contains("recursion limit exceeded"),
                "depth {depth} gave {err}"
            );
        }
    }

    /// The field-count ceiling counts the whole tree, not one level.
    #[test]
    fn field_count_ceiling_counts_the_whole_tree() {
        let mut flat = String::from("grammar: t\ntransport: tcp\nmessage:\n");
        for i in 0..MAX_FIELDS {
            flat.push_str(&format!("  - {{ name: f{i}, type: u8 }}\n"));
        }
        assert!(
            MessageSpec::from_yaml(&flat).is_ok(),
            "exactly {MAX_FIELDS} fields are allowed"
        );

        let mut over = flat.clone();
        over.push_str(&format!("  - {{ name: f{MAX_FIELDS}, type: u8 }}\n"));
        let err = MessageSpec::from_yaml(&over).expect_err("one field too many is refused");
        assert!(
            err.to_string()
                .contains("declares 257 fields; at most 256 are allowed"),
            "display: {err}"
        );

        // Nested fields count too: 2 groups x 128 children + the 2 groups.
        let mut nested = String::from("grammar: t\ntransport: tcp\nmessage:\n");
        for g in 0..2 {
            nested.push_str(&format!("  - name: g{g}\n    type: group\n    fields:\n"));
            for i in 0..128 {
                nested.push_str(&format!("      - {{ name: f{i}, type: u8 }}\n"));
            }
        }
        let spec: MessageSpec = serde_yaml::from_str(&nested).expect("the document parses");
        assert_eq!(spec.validate(), Err(SpecError::TooManyFields(258)));
    }

    /// An empty or non-grammar document is an error with the module prefix,
    /// not a default-valued `MessageSpec`.
    #[test]
    fn empty_and_junk_documents_are_errors() {
        for text in ["", "~", "[]", "grammar: t\n", "{\"grammar\": 7}"] {
            let err = MessageSpec::from_yaml(text)
                .expect_err("an incomplete document is not a MessageSpec");
            assert!(
                err.to_string().starts_with("l4_stream: grammar"),
                "text {text:?} gave {err}"
            );
        }
    }

    #[test]
    fn grammar_kind_names() {
        assert_eq!(GrammarKind::parse("modbus"), Some(GrammarKind::Modbus));
        assert_eq!(GrammarKind::parse("modbus-tcp"), Some(GrammarKind::Modbus));
        assert_eq!(GrammarKind::Modbus.name(), "modbus");
        assert_eq!(GrammarKind::parse("MODBUS"), None);
        assert_eq!(GrammarKind::parse("nope"), None);

        let names: Vec<&'static str> = [
            GrammarKind::Tlv,
            GrammarKind::Resp,
            GrammarKind::Memcached,
            GrammarKind::Dns,
            GrammarKind::Modbus,
            GrammarKind::Mqtt,
            GrammarKind::Smtp,
            GrammarKind::Ftp,
            GrammarKind::Raw,
        ]
        .iter()
        .map(|k| k.name())
        .collect();
        assert_eq!(
            names,
            vec![
                "tlv",
                "resp",
                "memcached",
                "dns",
                "modbus",
                "mqtt",
                "smtp",
                "ftp",
                "raw"
            ]
        );
        for name in &names {
            assert_eq!(
                GrammarKind::parse(name).map(GrammarKind::name),
                Some(*name),
                "{name} does not round trip"
            );
        }
    }
}
