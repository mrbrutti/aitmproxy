//! The `aitm-poc` artifact model and its YAML serde mapping.
//!
//! The Rust types are declared exactly as the platform spec's "aitm-poc — the
//! artifact model". The serde attribute mapping (left to the builder by the
//! PoC-language spec) renders the nuclei-style on-disk YAML — externally-tagged
//! steps (`http:`/`browser:`/`extract:`), an internally-tagged browser `action`,
//! and a matcher/`success` tree — into these types and back.
//!
//! `aitm_core::Value` carries no serde derives and this crate must not edit
//! `aitm-core`, so the `Option<Value>` and matcher payload conversions bridge
//! through `serde_yaml::Value` here.

use aitm_core::Value;
use serde::{Deserialize, Serialize};

/// A reproducible proof-of-concept: identity, metadata, variables, ordered steps,
/// and the `success` assertion that defines "triggered".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Poc {
    pub id: String,
    pub info: PocInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<Variable>,
    pub steps: Vec<Step>,
    pub success: Assertion,
}

/// Identification metadata. Carries no remediation / fix prose (platform
/// Non-goal), but the on-disk `description` / `author` / `metadata` keys are
/// preserved so a PoC round-trips faithfully (AC13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PocInfo {
    pub name: String,
    pub severity: Severity,
    #[serde(default, rename = "reference", skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_yaml::Value>,
}

/// Finding severity. Serializes as the lowercase nuclei vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A reusable `{{placeholder}}` with an optional default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    #[serde(default, with = "opt_value", skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
}

/// One ordered step. A single-key map names the step type (`http:`/`browser:`/
/// `extract:`/`script:`), the nuclei shape — not serde's `!Tag` external tagging.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Http(HttpStep),
    Browser(BrowserStep),
    Extract(ExtractStep),
    Script(ScriptStep),
}

impl Serialize for Step {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (key, inner) = match self {
            Step::Http(h) => ("http", serde_yaml::to_value(h)),
            Step::Browser(b) => ("browser", serde_yaml::to_value(b)),
            Step::Extract(e) => ("extract", serde_yaml::to_value(e)),
            Step::Script(s) => ("script", serde_yaml::to_value(s)),
        };
        let inner = inner.map_err(serde::ser::Error::custom)?;
        let mut m = serde_yaml::Mapping::new();
        m.insert(serde_yaml::Value::String(key.to_string()), inner);
        serde_yaml::Value::Mapping(m).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Step {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(d)?;
        let map = v
            .as_mapping()
            .ok_or_else(|| serde::de::Error::custom("step must be a single-key mapping"))?;
        let (k, inner) = map
            .iter()
            .next()
            .ok_or_else(|| serde::de::Error::custom("step mapping is empty"))?;
        let key = k
            .as_str()
            .ok_or_else(|| serde::de::Error::custom("step type key must be a string"))?;
        let inner = inner.clone();
        match key {
            "http" => Ok(Step::Http(
                serde_yaml::from_value(inner).map_err(serde::de::Error::custom)?,
            )),
            "browser" => Ok(Step::Browser(
                serde_yaml::from_value(inner).map_err(serde::de::Error::custom)?,
            )),
            "extract" => Ok(Step::Extract(
                serde_yaml::from_value(inner).map_err(serde::de::Error::custom)?,
            )),
            "script" => Ok(Step::Script(
                serde_yaml::from_value(inner).map_err(serde::de::Error::custom)?,
            )),
            other => Err(serde::de::Error::custom(format!(
                "unknown step type `{other}`"
            ))),
        }
    }
}

/// An HTTP request step. The model carries the request shape; on-disk keys it
/// does not interpret (`matchers`/`matchers-condition`/`raw`/`path`/…) are kept
/// in `extra` so the step round-trips faithfully (AC13). Per-step matcher
/// *evaluation* is still future work; top-level `success` is what M1 evaluates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpStep {
    pub method: String,
    pub url: String,
    #[serde(default, with = "header_map", skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extract: Vec<ExtractStep>,
    /// Unmodeled on-disk keys, preserved verbatim for round-trip fidelity.
    #[serde(
        flatten,
        default,
        skip_serializing_if = "serde_yaml::Mapping::is_empty"
    )]
    pub extra: serde_yaml::Mapping,
}

/// A browser-driver step carrying exactly one action.
#[derive(Debug, Clone, PartialEq)]
pub struct BrowserStep {
    pub action: BrowserAction,
}

/// The browser action vocabulary (internally tagged on-disk by `action:`).
#[derive(Debug, Clone, PartialEq)]
pub enum BrowserAction {
    Navigate { url: String },
    Click { target: String },
    Type { selector: String, text: String },
    Eval { expr: String },
    Screenshot { label: String },
}

/// A standalone extractor binding a variable from a prior response.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractStep {
    pub name: String,
    pub source: ExtractSource,
}

/// Where an extractor reads its value from.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractSource {
    Regex(String),
    JsonPath(String),
    Header(String),
    BrowserEval(String),
}

/// The reserved Rhai escape hatch: a top-level script body (not a function),
/// optionally named so `success` can reference its verdict via `step("name")`.
/// Execution is the scripting tier's job (M3 spec §10); this crate only models it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptStep {
    pub script: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Which part of a response a `word`/`regex` matcher is tested against
/// (nuclei `part`): the body (default), the headers, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchPart {
    #[default]
    Body,
    Header,
    All,
}

impl MatchPart {
    fn as_str(self) -> &'static str {
        match self {
            MatchPart::Body => "body",
            MatchPart::Header => "header",
            MatchPart::All => "all",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "body" => Some(MatchPart::Body),
            "header" | "headers" => Some(MatchPart::Header),
            "all" => Some(MatchPart::All),
            _ => None,
        }
    }
}

/// The matcher / `success` assertion tree (nuclei operator vocabulary).
#[derive(Debug, Clone, PartialEq)]
pub enum Assertion {
    Status(u16),
    Word { word: String, part: MatchPart },
    Regex { regex: String, part: MatchPart },
    Dsl(String),
    BrowserEval { expr: String, equals: Value },
    All(Vec<Assertion>),
    Any(Vec<Assertion>),
    Not(Box<Assertion>),
}

impl Assertion {
    /// A `word` matcher against the response body.
    pub fn word(word: impl Into<String>) -> Self {
        Assertion::Word {
            word: word.into(),
            part: MatchPart::Body,
        }
    }

    /// A `regex` matcher against the response body.
    pub fn regex(regex: impl Into<String>) -> Self {
        Assertion::Regex {
            regex: regex.into(),
            part: MatchPart::Body,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

// ---------------------------------------------------------------------------
// serde_yaml::Value <-> aitm_core::Value bridge
// ---------------------------------------------------------------------------

/// Convert an on-disk YAML scalar/collection into a transport-neutral `Value`.
pub(crate) fn yaml_to_value(y: &serde_yaml::Value) -> Value {
    match y {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::Bool(*b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(u) = n.as_u64() {
                Value::Int(u as i64)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_yaml::Value::String(s) => Value::Str(s.clone()),
        serde_yaml::Value::Sequence(seq) => Value::Array(seq.iter().map(yaml_to_value).collect()),
        serde_yaml::Value::Mapping(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (yaml_str(k), yaml_to_value(v)))
                .collect(),
        ),
        serde_yaml::Value::Tagged(t) => yaml_to_value(&t.value),
    }
}

/// Convert a `Value` back into the YAML representation it came from.
pub(crate) fn value_to_yaml(v: &Value) -> serde_yaml::Value {
    match v {
        Value::Null => serde_yaml::Value::Null,
        Value::Bool(b) => serde_yaml::Value::Bool(*b),
        Value::Int(i) => serde_yaml::Value::Number((*i).into()),
        Value::Float(f) => serde_yaml::Value::Number((*f).into()),
        Value::Str(s) => serde_yaml::Value::String(s.clone()),
        Value::Bytes(bytes) => serde_yaml::Value::Sequence(
            bytes
                .iter()
                .map(|b| serde_yaml::Value::Number((*b as u64).into()))
                .collect(),
        ),
        Value::Array(arr) => serde_yaml::Value::Sequence(arr.iter().map(value_to_yaml).collect()),
        Value::Object(obj) => {
            let mut map = serde_yaml::Mapping::new();
            for (k, val) in obj {
                map.insert(serde_yaml::Value::String(k.clone()), value_to_yaml(val));
            }
            serde_yaml::Value::Mapping(map)
        }
    }
}

/// Render a YAML scalar as the string a header key/value or matcher field expects.
fn yaml_str(y: &serde_yaml::Value) -> String {
    match y {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Null => String::new(),
        other => serde_yaml::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

// ---------------------------------------------------------------------------
// Variable.default: Option<Value>
// ---------------------------------------------------------------------------

mod opt_value {
    use super::{value_to_yaml, yaml_to_value};
    use aitm_core::Value;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Value>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(val) => value_to_yaml(val).serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
        let yv = Option::<serde_yaml::Value>::deserialize(d)?;
        Ok(yv.map(|y| yaml_to_value(&y)))
    }
}

// ---------------------------------------------------------------------------
// HttpStep.headers: Vec<(String, String)> <-> YAML mapping (order-preserving)
// ---------------------------------------------------------------------------

mod header_map {
    use super::yaml_str;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[(String, String)], s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(v.len()))?;
        for (k, val) in v {
            m.serialize_entry(k, val)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(String, String)>, D::Error> {
        let m = serde_yaml::Mapping::deserialize(d)?;
        Ok(m.iter().map(|(k, v)| (yaml_str(k), yaml_str(v))).collect())
    }
}

// ---------------------------------------------------------------------------
// BrowserStep: flat `{ action: <name>, <fields> }`
// ---------------------------------------------------------------------------

impl Serialize for BrowserStep {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        browser_to_yaml(&self.action).serialize(s)
    }
}

impl<'de> Deserialize<'de> for BrowserStep {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(d)?;
        browser_from_yaml(&v)
            .map(|action| BrowserStep { action })
            .map_err(serde::de::Error::custom)
    }
}

fn browser_to_yaml(action: &BrowserAction) -> serde_yaml::Value {
    let mut m = serde_yaml::Mapping::new();
    let mut put = |k: &str, v: &str| {
        m.insert(
            serde_yaml::Value::String(k.to_string()),
            serde_yaml::Value::String(v.to_string()),
        );
    };
    match action {
        BrowserAction::Navigate { url } => {
            put("action", "navigate");
            put("url", url);
        }
        BrowserAction::Click { target } => {
            put("action", "click");
            put("target", target);
        }
        BrowserAction::Type { selector, text } => {
            put("action", "type");
            put("selector", selector);
            put("text", text);
        }
        BrowserAction::Eval { expr } => {
            put("action", "eval");
            put("expr", expr);
        }
        BrowserAction::Screenshot { label } => {
            put("action", "screenshot");
            put("label", label);
        }
    }
    serde_yaml::Value::Mapping(m)
}

fn browser_from_yaml(v: &serde_yaml::Value) -> Result<BrowserAction, String> {
    let field = |k: &str| -> Result<String, String> {
        v.get(k)
            .and_then(|f| f.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("browser action missing `{k}`"))
    };
    match v.get("action").and_then(|a| a.as_str()) {
        Some("navigate") => Ok(BrowserAction::Navigate { url: field("url")? }),
        Some("click") => Ok(BrowserAction::Click {
            target: field("target")?,
        }),
        Some("type") => Ok(BrowserAction::Type {
            selector: field("selector")?,
            text: field("text")?,
        }),
        Some("eval") => Ok(BrowserAction::Eval {
            expr: field("expr")?,
        }),
        Some("screenshot") => Ok(BrowserAction::Screenshot {
            label: field("label")?,
        }),
        Some(other) => Err(format!("unknown browser action `{other}`")),
        None => Err("browser step missing `action`".to_string()),
    }
}

// ---------------------------------------------------------------------------
// ExtractStep: nuclei `{ name, type, <payload>, ... }`
// ---------------------------------------------------------------------------

impl Serialize for ExtractStep {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = serde_yaml::Mapping::new();
        let mut put = |k: &str, val: &str| {
            m.insert(
                serde_yaml::Value::String(k.to_string()),
                serde_yaml::Value::String(val.to_string()),
            );
        };
        put("name", &self.name);
        match &self.source {
            ExtractSource::Regex(p) => {
                put("type", "regex");
                put("regex", p);
            }
            ExtractSource::JsonPath(p) => {
                put("type", "json");
                put("json", p);
            }
            ExtractSource::Header(k) => {
                put("type", "kval");
                put("kval", k);
            }
            ExtractSource::BrowserEval(e) => {
                put("type", "browser-eval");
                put("expr", e);
            }
        }
        serde_yaml::Value::Mapping(m).serialize(s)
    }
}

impl<'de> Deserialize<'de> for ExtractStep {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(d)?;
        extract_from_yaml(&v).map_err(serde::de::Error::custom)
    }
}

fn extract_from_yaml(v: &serde_yaml::Value) -> Result<ExtractStep, String> {
    let name = v
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or("extractor missing `name`")?
        .to_string();
    let payload = |k: &str| -> Result<String, String> {
        v.get(k)
            .and_then(|f| f.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("extractor `{name}` of type requires `{k}`"))
    };
    let source = match v.get("type").and_then(|t| t.as_str()) {
        Some("regex") => ExtractSource::Regex(payload("regex")?),
        Some("json") => ExtractSource::JsonPath(payload("json")?),
        Some("kval") => ExtractSource::Header(payload("kval")?),
        Some("browser-eval") => ExtractSource::BrowserEval(payload("expr")?),
        Some(other) => return Err(format!("unsupported extractor type `{other}`")),
        None => return Err(format!("extractor `{name}` missing `type`")),
    };
    Ok(ExtractStep { name, source })
}

// ---------------------------------------------------------------------------
// Assertion: the matcher / success tree
// ---------------------------------------------------------------------------

impl Serialize for Assertion {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        assertion_to_yaml(self).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Assertion {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(d)?;
        assertion_from_yaml(&v).map_err(serde::de::Error::custom)
    }
}

fn assertion_to_yaml(a: &Assertion) -> serde_yaml::Value {
    let mut m = serde_yaml::Mapping::new();
    let str_entry = |m: &mut serde_yaml::Mapping, k: &str, v: &str| {
        m.insert(
            serde_yaml::Value::String(k.to_string()),
            serde_yaml::Value::String(v.to_string()),
        );
    };
    match a {
        Assertion::Status(n) => {
            str_entry(&mut m, "type", "status");
            m.insert(
                serde_yaml::Value::String("status".to_string()),
                serde_yaml::Value::Number((*n as u64).into()),
            );
        }
        Assertion::Word { word, part } => {
            str_entry(&mut m, "type", "word");
            str_entry(&mut m, "word", word);
            if *part != MatchPart::Body {
                str_entry(&mut m, "part", part.as_str());
            }
        }
        Assertion::Regex { regex, part } => {
            str_entry(&mut m, "type", "regex");
            str_entry(&mut m, "regex", regex);
            if *part != MatchPart::Body {
                str_entry(&mut m, "part", part.as_str());
            }
        }
        Assertion::Dsl(d) => {
            str_entry(&mut m, "type", "dsl");
            str_entry(&mut m, "dsl", d);
        }
        Assertion::BrowserEval { expr, equals } => {
            str_entry(&mut m, "type", "browser-eval");
            str_entry(&mut m, "expr", expr);
            m.insert(
                serde_yaml::Value::String("equals".to_string()),
                value_to_yaml(equals),
            );
        }
        Assertion::All(items) => {
            m.insert(
                serde_yaml::Value::String("all".to_string()),
                serde_yaml::Value::Sequence(items.iter().map(assertion_to_yaml).collect()),
            );
        }
        Assertion::Any(items) => {
            m.insert(
                serde_yaml::Value::String("any".to_string()),
                serde_yaml::Value::Sequence(items.iter().map(assertion_to_yaml).collect()),
            );
        }
        Assertion::Not(inner) => {
            m.insert(
                serde_yaml::Value::String("not".to_string()),
                assertion_to_yaml(inner),
            );
        }
    }
    serde_yaml::Value::Mapping(m)
}

fn assertion_from_yaml(v: &serde_yaml::Value) -> Result<Assertion, String> {
    // Sequence form (`success:` as a list) is an implicit `all`.
    if let serde_yaml::Value::Sequence(seq) = v {
        let items = seq
            .iter()
            .map(assertion_from_yaml)
            .collect::<Result<_, _>>()?;
        return Ok(Assertion::All(items));
    }
    let map = v
        .as_mapping()
        .ok_or("matcher must be a mapping or a list")?;

    if let Some(items) = map.get("all") {
        return Ok(Assertion::All(seq_of(items)?));
    }
    if let Some(items) = map.get("any") {
        return Ok(Assertion::Any(seq_of(items)?));
    }
    if let Some(inner) = map.get("not") {
        return Ok(Assertion::Not(Box::new(assertion_from_yaml(inner)?)));
    }

    let payload = |k: &str| -> Result<String, String> {
        v.get(k)
            .and_then(|f| f.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("matcher missing `{k}`"))
    };

    let base = match v.get("type").and_then(|t| t.as_str()) {
        Some("status") => {
            let code = v
                .get("status")
                .and_then(|s| s.as_u64())
                .ok_or("status matcher missing numeric `status`")?;
            Assertion::Status(code as u16)
        }
        Some("word") => Assertion::Word {
            word: payload("word")?,
            part: part_of(v)?,
        },
        Some("regex") => Assertion::Regex {
            regex: payload("regex")?,
            part: part_of(v)?,
        },
        Some("dsl") => Assertion::Dsl(payload("dsl")?),
        Some("browser-eval") => Assertion::BrowserEval {
            expr: payload("expr")?,
            equals: v.get("equals").map(yaml_to_value).unwrap_or(Value::Null),
        },
        Some(other) => return Err(format!("unknown matcher type `{other}`")),
        None => {
            // Shorthand `{ dsl: "..." }` with no explicit `type`.
            if let Some(expr) = map.get("dsl").and_then(|d| d.as_str()) {
                Assertion::Dsl(expr.to_string())
            } else {
                return Err("matcher missing `type`".to_string());
            }
        }
    };

    // `negative: true` wraps the matcher in `Not`.
    if v.get("negative").and_then(|n| n.as_bool()).unwrap_or(false) {
        Ok(Assertion::Not(Box::new(base)))
    } else {
        Ok(base)
    }
}

/// Parse the nuclei `part` modifier (`body` default / `header` / `all`).
fn part_of(v: &serde_yaml::Value) -> Result<MatchPart, String> {
    match v.get("part").and_then(|p| p.as_str()) {
        None => Ok(MatchPart::Body),
        Some(s) => MatchPart::parse(s).ok_or_else(|| format!("unknown matcher part `{s}`")),
    }
}

fn seq_of(v: &serde_yaml::Value) -> Result<Vec<Assertion>, String> {
    v.as_sequence()
        .ok_or("`all`/`any` must be a list")?
        .iter()
        .map(assertion_from_yaml)
        .collect()
}
