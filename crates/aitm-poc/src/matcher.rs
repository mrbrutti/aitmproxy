//! Matcher evaluation (AC-L5): an `Assertion` tree judged true/false against a
//! response/browser context.
//!
//! The platform-spec `Assertion::Word`/`Regex` carry only a pattern (no `part`),
//! so M1 matches them against the response body; `BrowserEval` compares an
//! observed browser value; `All`/`Any`/`Not` compose; `Dsl` defers to the shared
//! evaluator. `negative` and `matchers-condition` are expressed by the serde layer
//! as `Not` / `All` / `Any`, so evaluation sees only this tree.

use std::collections::BTreeMap;

use aitm_core::Value;
use regex::Regex;

use crate::dsl::{self, DslContext};
use crate::model::{Assertion, MatchPart};

/// What an assertion is judged against: a response plus any observed browser
/// values and bound variables.
#[derive(Debug, Clone, Default)]
pub struct MatchContext {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    /// Observed browser expression results, keyed by the expression source.
    pub browser: BTreeMap<String, Value>,
    /// Variables bound by earlier extractors / bindings (for `dsl`).
    pub vars: BTreeMap<String, Value>,
}

impl MatchContext {
    /// A context over a response status and body.
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: Vec::new(),
            browser: BTreeMap::new(),
            vars: BTreeMap::new(),
        }
    }

    /// Add a response header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Record an observed browser value for `expr`.
    pub fn with_browser(mut self, expr: impl Into<String>, value: Value) -> Self {
        self.browser.insert(expr.into(), value);
        self
    }

    /// Bind a variable visible to `dsl` matchers.
    pub fn with_var(mut self, name: impl Into<String>, value: Value) -> Self {
        self.vars.insert(name.into(), value);
        self
    }

    fn dsl_context(&self) -> DslContext {
        DslContext {
            status: self.status,
            body: self.body.clone(),
            vars: self.vars.clone(),
        }
    }

    /// The text a `word`/`regex` matcher searches, per its `part`.
    fn part_text(&self, part: MatchPart) -> String {
        let headers = || {
            self.headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        match part {
            MatchPart::Body => self.body.clone(),
            MatchPart::Header => headers(),
            MatchPart::All => format!("{}\n{}", headers(), self.body),
        }
    }
}

/// Evaluate an assertion tree against `ctx`.
pub fn evaluate(assertion: &Assertion, ctx: &MatchContext) -> bool {
    match assertion {
        Assertion::Status(code) => ctx.status == *code,
        Assertion::Word { word, part } => ctx.part_text(*part).contains(word),
        Assertion::Regex { regex, part } => Regex::new(regex)
            .map(|re| re.is_match(&ctx.part_text(*part)))
            .unwrap_or(false),
        Assertion::Dsl(expr) => dsl::eval_bool(expr, &ctx.dsl_context()),
        Assertion::BrowserEval { expr, equals } => {
            ctx.browser.get(expr).is_some_and(|v| v == equals)
        }
        Assertion::All(items) => items.iter().all(|a| evaluate(a, ctx)),
        Assertion::Any(items) => items.iter().any(|a| evaluate(a, ctx)),
        Assertion::Not(inner) => !evaluate(inner, ctx),
    }
}
