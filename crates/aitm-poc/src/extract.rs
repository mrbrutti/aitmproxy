//! Extractor evaluation (AC-L6): bind a named variable from a response so a later
//! step can consume it. `internal: true` keeps a binding out of the printed output
//! set (nuclei semantics) while still passing it between steps.
//!
//! These evaluation-side types carry what the extractor needs at run time (regex
//! `group`, the `internal` flag) that the thin on-disk `ExtractStep` model does
//! not; `From<&ExtractStep>` bridges a parsed step into one.

use std::collections::BTreeMap;

use aitm_core::Value;
use regex::Regex;

use crate::dsl::{self, DslContext};
use crate::matcher::MatchContext;
use crate::model::{ExtractSource, ExtractStep};

/// How an extractor reads its value.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractorKind {
    /// Regex with a capture-group index (0 = whole match).
    Regex { pattern: String, group: usize },
    /// A header/cookie value by kval-normalized key (`Set-Cookie` → `set_cookie`).
    Header(String),
    /// A dotted path into a JSON/YAML body (minimal subset).
    JsonPath(String),
    /// An observed browser expression result.
    BrowserEval(String),
    /// A DSL expression over the response context.
    Dsl(String),
}

/// A named extractor. `internal` bindings pass between steps without printing.
#[derive(Debug, Clone, PartialEq)]
pub struct Extractor {
    pub name: String,
    pub kind: ExtractorKind,
    pub internal: bool,
}

impl From<&ExtractStep> for Extractor {
    fn from(step: &ExtractStep) -> Self {
        let kind = match &step.source {
            ExtractSource::Regex { pattern, group } => ExtractorKind::Regex {
                pattern: pattern.clone(),
                group: *group,
            },
            ExtractSource::Header(k) => ExtractorKind::Header(k.clone()),
            ExtractSource::JsonPath(p) => ExtractorKind::JsonPath(p.clone()),
            ExtractSource::BrowserEval(e) => ExtractorKind::BrowserEval(e.clone()),
        };
        Extractor {
            name: step.name.clone(),
            kind,
            internal: false,
        }
    }
}

/// The bindings an extractor pass produced: `bound` is visible to later steps;
/// `printed` is the non-internal subset shown in output.
#[derive(Debug, Clone, Default)]
pub struct Extraction {
    pub bound: BTreeMap<String, Value>,
    pub printed: BTreeMap<String, Value>,
}

/// Evaluate every extractor, collecting bound (and printed) variables.
pub fn run_extractors(extractors: &[Extractor], ctx: &MatchContext) -> Extraction {
    let mut out = Extraction::default();
    for ex in extractors {
        if let Some(value) = apply(ex, ctx) {
            if !ex.internal {
                out.printed.insert(ex.name.clone(), value.clone());
            }
            out.bound.insert(ex.name.clone(), value);
        }
    }
    out
}

/// Evaluate a single extractor against the context.
pub fn apply(ex: &Extractor, ctx: &MatchContext) -> Option<Value> {
    match &ex.kind {
        ExtractorKind::Regex { pattern, group } => {
            let re = Regex::new(pattern).ok()?;
            let caps = re.captures(&ctx.body)?;
            caps.get(*group).map(|m| Value::Str(m.as_str().to_string()))
        }
        ExtractorKind::Header(key) => {
            let want = kval_normalize(key);
            ctx.headers
                .iter()
                .find(|(name, _)| kval_normalize(name) == want)
                .map(|(_, value)| Value::Str(value.clone()))
        }
        ExtractorKind::JsonPath(path) => json_path(&ctx.body, path),
        ExtractorKind::BrowserEval(expr) => ctx.browser.get(expr).cloned(),
        ExtractorKind::Dsl(expr) => dsl::eval(
            expr,
            &DslContext {
                status: ctx.status,
                body: ctx.body.clone(),
                vars: ctx.vars.clone(),
                steps: BTreeMap::new(),
            },
        )
        .ok(),
    }
}

/// kval key normalization: lowercase and dashes → underscores.
fn kval_normalize(key: &str) -> String {
    key.to_ascii_lowercase().replace('-', "_")
}

/// Largest response body `json_path` will parse. The body is target-controlled,
/// so an unbounded parse is a DoS vector; a dotted path into a sane JSON response
/// needs nothing like a megabyte, and larger bodies simply yield no binding.
const MAX_JSON_PATH_BODY: usize = 1024 * 1024;

/// A minimal dotted JSON path walk (`a.b.c`), enough for simple extractions.
///
/// Parsing uses `serde_json`, not `serde_yaml`: the body is controlled by the
/// (possibly hostile) target, and `serde_json` bounds recursion depth and has no
/// YAML anchors/aliases, so a deeply-nested or alias-bomb body is rejected as a
/// parse error rather than overflowing the stack or exhausting memory. The body
/// size is capped first so even a flat-but-huge document is not materialized.
fn json_path(body: &str, path: &str) -> Option<Value> {
    if body.len() > MAX_JSON_PATH_BODY {
        return None;
    }
    let doc: serde_json::Value = serde_json::from_str(body).ok()?;
    let mut cur = &doc;
    for seg in path
        .trim_start_matches('$')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        cur = cur.get(seg)?;
    }
    Some(json_to_value(cur))
}

/// Convert a parsed JSON value into the transport-neutral `Value`.
fn json_to_value(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(Value::Int)
            .or_else(|| n.as_f64().map(Value::Float))
            .unwrap_or(Value::Null),
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_value).collect()),
        serde_json::Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), json_to_value(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_path_reads_dotted_path() {
        let body = r#"{"data": {"token": "abc123"}}"#;
        assert_eq!(
            json_path(body, "data.token"),
            Some(Value::Str("abc123".into()))
        );
        assert_eq!(
            json_path(body, "$.data.token"),
            Some(Value::Str("abc123".into()))
        );
        assert_eq!(json_path(body, "data.missing"), None);
    }

    /// I4: a deeply-nested body is rejected (serde_json's recursion limit) instead
    /// of overflowing the stack, and an over-cap body yields no binding — neither
    /// panics or exhausts memory.
    #[test]
    fn json_path_rejects_hostile_body() {
        // ~100k levels of nesting: serde_yaml would recurse and could overflow;
        // serde_json returns a parse error, so we get `None`.
        let deep = format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000));
        assert_eq!(json_path(&deep, "x"), None);

        // Over the byte cap: not parsed at all.
        let huge = format!(r#"{{"k":"{}"}}"#, "a".repeat(MAX_JSON_PATH_BODY + 10));
        assert_eq!(json_path(&huge, "k"), None);
    }

    /// I7: a regex extractor with no capture group binds the whole match (group 0),
    /// where the old hardcoded group 1 bound nothing.
    #[test]
    fn whole_match_regex_extracts_with_group_zero() {
        let ctx = MatchContext::new(200, "id=4242 end");
        let ex = Extractor {
            name: "n".into(),
            kind: ExtractorKind::Regex {
                pattern: r"id=\d+".into(),
                group: 0,
            },
            internal: false,
        };
        assert_eq!(apply(&ex, &ctx), Some(Value::Str("id=4242".into())));
    }
}
