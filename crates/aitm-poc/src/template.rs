//! Templating (AC-L4): `{{placeholder}}` interpolation into step strings.
//!
//! Resolution order is caller-supplied [`VarBindings`] first, then `variables`
//! defaults (held by [`PocTemplate`]). A placeholder is one of: a bare variable
//! name; a nuclei runtime placeholder (`{{BaseURL}}`, `{{RootURL}}`,
//! `{{Hostname}}`, `{{Host}}`, `{{Port}}`, `{{Path}}`, `{{Scheme}}`) computed from
//! the `target` binding; or a DSL expression (e.g. `{{url_encode(payload)}}`)
//! evaluated by the shared evaluator. DSL-wrapped `variables` defaults are
//! evaluated once by [`PocTemplate::from_poc`].

use std::collections::BTreeMap;

use aitm_core::Value;

use crate::dsl::{self, DslContext};
use crate::model::Poc;

/// Caller-supplied overrides of variable defaults (name → value).
#[derive(Debug, Clone, Default)]
pub struct VarBindings(BTreeMap<String, Value>);

impl VarBindings {
    /// An empty binding set.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Bind `name` to `value` (replacing any prior binding).
    pub fn insert(&mut self, name: impl Into<String>, value: Value) {
        self.0.insert(name.into(), value);
    }

    /// The value bound to `name`, if any.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    /// Builder form of [`VarBindings::insert`].
    pub fn with(mut self, name: impl Into<String>, value: Value) -> Self {
        self.insert(name, value);
        self
    }

    /// Iterate the bindings.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.0.iter()
    }
}

/// `{{var}}` substitution into URLs, headers, bodies, and expressions.
pub trait Template: Send + Sync {
    fn render(&self, input: &str, vars: &VarBindings) -> anyhow::Result<String>;
}

/// The default templater: holds `variables` defaults and renders against caller
/// bindings layered on top.
#[derive(Debug, Clone, Default)]
pub struct PocTemplate {
    defaults: VarBindings,
}

impl PocTemplate {
    /// A templater over the given variable defaults.
    pub fn new(defaults: VarBindings) -> Self {
        Self { defaults }
    }

    /// Build a templater from a PoC, evaluating DSL-wrapped `variables` defaults
    /// (e.g. `{{rand_text_alpha(8)}}`) once, in declaration order so later
    /// defaults may reference earlier ones.
    pub fn from_poc(poc: &Poc) -> anyhow::Result<Self> {
        let mut tmpl = PocTemplate::new(VarBindings::new());
        for var in &poc.variables {
            let Some(default) = &var.default else {
                continue;
            };
            let resolved = match default {
                Value::Str(s) if s.contains("{{") => {
                    Value::Str(tmpl.render(s, &VarBindings::new())?)
                }
                other => other.clone(),
            };
            tmpl.defaults.insert(var.name.clone(), resolved);
        }
        Ok(tmpl)
    }

    /// The merged variable lookup (defaults overlaid by caller bindings) a DSL
    /// expression evaluates against.
    fn merged_vars(&self, vars: &VarBindings) -> BTreeMap<String, Value> {
        let mut merged: BTreeMap<String, Value> = self.defaults.0.clone();
        for (k, v) in vars.iter() {
            merged.insert(k.clone(), v.clone());
        }
        merged
    }

    fn lookup(&self, name: &str, vars: &VarBindings) -> Option<Value> {
        vars.get(name).or_else(|| self.defaults.get(name)).cloned()
    }

    fn eval_placeholder(&self, expr: &str, vars: &VarBindings) -> anyhow::Result<String> {
        if let Some(value) = self.runtime_placeholder(expr, vars)? {
            return Ok(value);
        }
        if is_identifier(expr) {
            return self
                .lookup(expr, vars)
                .map(value_to_string)
                .ok_or_else(|| anyhow::anyhow!("unknown variable `{expr}`"));
        }
        let ctx = DslContext {
            status: 0,
            body: String::new(),
            vars: self.merged_vars(vars),
        };
        Ok(value_to_string(dsl::eval(expr, &ctx)?))
    }

    fn runtime_placeholder(
        &self,
        name: &str,
        vars: &VarBindings,
    ) -> anyhow::Result<Option<String>> {
        if !RUNTIME_PLACEHOLDERS.contains(&name) {
            return Ok(None);
        }
        let target = self
            .lookup("target", vars)
            .map(value_to_string)
            .ok_or_else(|| {
                anyhow::anyhow!("runtime placeholder `{{{{{name}}}}}` requires a `target` binding")
            })?;
        let parts = TargetUrl::parse(&target)?;
        Ok(Some(match name {
            "BaseURL" => parts.base,
            "RootURL" => parts.root,
            "Hostname" => parts.hostname,
            "Host" => parts.host,
            "Port" => parts.port,
            "Path" => parts.path,
            "Scheme" => parts.scheme,
            _ => unreachable!("guarded by RUNTIME_PLACEHOLDERS"),
        }))
    }
}

impl Template for PocTemplate {
    fn render(&self, input: &str, vars: &VarBindings) -> anyhow::Result<String> {
        let mut out = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(open) = rest.find("{{") {
            out.push_str(&rest[..open]);
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else {
                // No closing delimiter: emit the rest verbatim.
                out.push_str(&rest[open..]);
                return Ok(out);
            };
            let expr = after[..close].trim();
            out.push_str(&self.eval_placeholder(expr, vars)?);
            rest = &after[close + 2..];
        }
        out.push_str(rest);
        Ok(out)
    }
}

const RUNTIME_PLACEHOLDERS: [&str; 7] = [
    "BaseURL", "RootURL", "Hostname", "Host", "Port", "Path", "Scheme",
];

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn value_to_string(v: Value) -> String {
    match v {
        Value::Str(s) => s,
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => format!("{other:?}"),
    }
}

/// The pieces of a target URL the runtime placeholders expose.
struct TargetUrl {
    scheme: String,
    host: String,
    hostname: String,
    port: String,
    path: String,
    root: String,
    base: String,
}

impl TargetUrl {
    fn parse(url: &str) -> anyhow::Result<Self> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| anyhow::anyhow!("target `{url}` has no scheme"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (hostname, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.to_string())
            }
            _ => {
                let default = if scheme.eq_ignore_ascii_case("https") {
                    "443"
                } else {
                    "80"
                };
                (authority.to_string(), default.to_string())
            }
        };
        let root = format!("{scheme}://{authority}");
        Ok(TargetUrl {
            scheme: scheme.to_string(),
            host: authority.to_string(),
            hostname,
            port,
            path: path.to_string(),
            root: root.clone(),
            base: root,
        })
    }
}
