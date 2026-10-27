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
            ExtractSource::Regex(p) => ExtractorKind::Regex {
                pattern: p.clone(),
                group: 1,
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
            },
        )
        .ok(),
    }
}

/// kval key normalization: lowercase and dashes → underscores.
fn kval_normalize(key: &str) -> String {
    key.to_ascii_lowercase().replace('-', "_")
}

/// A minimal dotted JSON/YAML path walk (`a.b.c`), enough for simple extractions.
fn json_path(body: &str, path: &str) -> Option<Value> {
    let doc: serde_yaml::Value = serde_yaml::from_str(body).ok()?;
    let mut cur = &doc;
    for seg in path
        .trim_start_matches('$')
        .split('.')
        .filter(|s| !s.is_empty())
    {
        cur = cur.get(seg)?;
    }
    Some(crate::model::yaml_to_value(cur))
}
