//! The shared nuclei-style DSL: helper functions plus a small expression
//! evaluator over response context, used by `dsl` matchers and by templating.
//!
//! M1 ships the minimal helper subset the PoC-language spec and plan name
//! (`contains`, `status_code`, `body`, `url_encode`, `rand_text_alpha`, `base64`),
//! plus `html_escape`/`to_lower`/`len`/`concat`, and `step("name")`, which reads
//! a script step's recorded outcome from the context (M3). The evaluator handles
//! string/int literals, identifiers (resolved against the context's variables and
//! the `body`/`status_code`/`content_length` built-ins), function calls, and the
//! `== != && || !` operators — enough for the declarative matcher surface. Real
//! control flow stays in the Rhai `script` step, not here.

use std::cell::Cell;
use std::collections::BTreeMap;

use aitm_core::Value;

/// The read-only context an expression evaluates against.
#[derive(Debug, Clone, Default)]
pub struct DslContext {
    pub status: u16,
    pub body: String,
    pub vars: BTreeMap<String, Value>,
    /// Script-step outcomes by step name, as the strings `step("name")` returns
    /// (`"pass"`, `"fail"`, `"neutral"`, `"error"`, …).
    pub steps: BTreeMap<String, String>,
}

impl DslContext {
    /// A context over a response status and body, with no bound variables or
    /// step outcomes.
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            vars: BTreeMap::new(),
            steps: BTreeMap::new(),
        }
    }
}

// --- Pure helpers (also callable from the evaluator by name) ----------------

/// Percent-encode everything outside the RFC 3986 unreserved set.
pub fn url_encode(s: &str) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(UPPER[(b >> 4) as usize] as char);
                out.push(UPPER[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Standard base64 (`+/`, `=` padding) of the input bytes.
pub fn base64(s: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// HTML-escape the five significant characters (used by the bundled target too).
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

thread_local! {
    // Per-run uniqueness without pulling a RNG crate: an xorshift seeded once
    // from process start time, advanced per draw. Determinism within a run is
    // not required — only that a marker is unique enough to confirm execution.
    static RNG: Cell<u64> = Cell::new(seed());
}

fn seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    nanos | 1
}

fn next_u64() -> u64 {
    RNG.with(|r| {
        let mut x = r.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        r.set(x);
        x
    })
}

/// Upper bound on a `rand_text_alpha` length. A unique marker needs only a
/// handful of characters; the cap stops a hostile or mistyped length argument
/// from allocating an arbitrarily large string (at precheck time, no less).
pub const MAX_RAND_TEXT_ALPHA: usize = 4096;

/// A random alphabetic string of length `n` (nuclei `rand_text_alpha`).
pub fn rand_text_alpha(n: usize) -> String {
    const ALPHA: &[u8; 52] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    (0..n)
        .map(|_| ALPHA[(next_u64() % 52) as usize] as char)
        .collect()
}

// --- Expression evaluation --------------------------------------------------

/// Evaluate a DSL expression to a `Value` against `ctx`.
pub fn eval(expr: &str, ctx: &DslContext) -> anyhow::Result<Value> {
    let tokens = tokenize(expr)?;
    let mut p = Parser {
        tokens: &tokens,
        pos: 0,
    };
    let v = p.parse_or(ctx)?;
    if p.pos != p.tokens.len() {
        anyhow::bail!("trailing tokens in DSL expression `{expr}`");
    }
    Ok(v)
}

/// Evaluate a DSL expression and coerce the result to a boolean (matcher use).
pub fn eval_bool(expr: &str, ctx: &DslContext) -> bool {
    eval(expr, ctx).map(|v| is_truthy(&v)).unwrap_or(false)
}

/// Check that `expr` tokenizes and parses (and names only known functions),
/// without any response context — so a malformed matcher fails when the PoC is
/// loaded, before any request is sent, instead of silently evaluating to false.
pub fn check(expr: &str) -> anyhow::Result<()> {
    eval(expr, &DslContext::default()).map(|_| ())
}

fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        Value::Str(s) => !s.is_empty() && s != "false",
        Value::Null => false,
        _ => true,
    }
}

fn as_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => format!("{other:?}"),
    }
}

fn is_numeric(v: &Value) -> bool {
    matches!(v, Value::Int(_) | Value::Float(_))
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Float(x), Value::Float(y)) => x == y,
        (Value::Int(x), Value::Float(y)) | (Value::Float(y), Value::Int(x)) => (*x as f64) == *y,
        // A number never equals a non-number, so no cross-type stringify can make
        // `Int(200) == Str("200")` true. Non-numeric values keep string-coercion
        // equality, which preserves the `step("x") == ""` null-is-empty idiom.
        (a, b) if is_numeric(a) || is_numeric(b) => false,
        (a, b) => as_string(a) == as_string(b),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    LParen,
    RParen,
    Comma,
    EqEq,
    NotEq,
    AndAnd,
    OrOr,
    Bang,
}

fn tokenize(s: &str) -> anyhow::Result<Vec<Tok>> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '\'' | '"' => {
                let quote = c;
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] as char != quote {
                    i += 1;
                }
                if i >= bytes.len() {
                    anyhow::bail!("unterminated string literal");
                }
                out.push(Tok::Str(s[start..i].to_string()));
                i += 1;
            }
            '=' if bytes.get(i + 1) == Some(&b'=') => {
                out.push(Tok::EqEq);
                i += 2;
            }
            '!' if bytes.get(i + 1) == Some(&b'=') => {
                out.push(Tok::NotEq);
                i += 2;
            }
            '!' => {
                out.push(Tok::Bang);
                i += 1;
            }
            '&' if bytes.get(i + 1) == Some(&b'&') => {
                out.push(Tok::AndAnd);
                i += 2;
            }
            '|' if bytes.get(i + 1) == Some(&b'|') => {
                out.push(Tok::OrOr);
                i += 2;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                    i += 1;
                }
                out.push(Tok::Int(s[start..i].parse()?));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < bytes.len()
                    && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                out.push(Tok::Ident(s[start..i].to_string()));
            }
            other => anyhow::bail!("unexpected character `{other}` in DSL expression"),
        }
    }
    Ok(out)
}

struct Parser<'a> {
    tokens: &'a [Tok],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn parse_or(&mut self, ctx: &DslContext) -> anyhow::Result<Value> {
        let mut left = self.parse_and(ctx)?;
        while self.peek() == Some(&Tok::OrOr) {
            self.pos += 1;
            let right = self.parse_and(ctx)?;
            left = Value::Bool(is_truthy(&left) || is_truthy(&right));
        }
        Ok(left)
    }

    fn parse_and(&mut self, ctx: &DslContext) -> anyhow::Result<Value> {
        let mut left = self.parse_eq(ctx)?;
        while self.peek() == Some(&Tok::AndAnd) {
            self.pos += 1;
            let right = self.parse_eq(ctx)?;
            left = Value::Bool(is_truthy(&left) && is_truthy(&right));
        }
        Ok(left)
    }

    fn parse_eq(&mut self, ctx: &DslContext) -> anyhow::Result<Value> {
        let left = self.parse_primary(ctx)?;
        match self.peek() {
            Some(Tok::EqEq) => {
                self.pos += 1;
                let right = self.parse_primary(ctx)?;
                Ok(Value::Bool(values_eq(&left, &right)))
            }
            Some(Tok::NotEq) => {
                self.pos += 1;
                let right = self.parse_primary(ctx)?;
                Ok(Value::Bool(!values_eq(&left, &right)))
            }
            _ => Ok(left),
        }
    }

    fn parse_primary(&mut self, ctx: &DslContext) -> anyhow::Result<Value> {
        match self.peek().cloned() {
            Some(Tok::Bang) => {
                self.pos += 1;
                let v = self.parse_primary(ctx)?;
                Ok(Value::Bool(!is_truthy(&v)))
            }
            Some(Tok::LParen) => {
                self.pos += 1;
                let v = self.parse_or(ctx)?;
                if self.peek() != Some(&Tok::RParen) {
                    anyhow::bail!("expected `)`");
                }
                self.pos += 1;
                Ok(v)
            }
            Some(Tok::Str(s)) => {
                self.pos += 1;
                Ok(Value::Str(s))
            }
            Some(Tok::Int(i)) => {
                self.pos += 1;
                Ok(Value::Int(i))
            }
            Some(Tok::Ident(name)) => {
                self.pos += 1;
                if self.peek() == Some(&Tok::LParen) {
                    let args = self.parse_args(ctx)?;
                    call(&name, args, ctx)
                } else {
                    Ok(resolve_ident(&name, ctx))
                }
            }
            other => anyhow::bail!("unexpected token {other:?} in DSL expression"),
        }
    }

    fn parse_args(&mut self, ctx: &DslContext) -> anyhow::Result<Vec<Value>> {
        self.pos += 1; // consume `(`
        let mut args = Vec::new();
        if self.peek() == Some(&Tok::RParen) {
            self.pos += 1;
            return Ok(args);
        }
        loop {
            args.push(self.parse_or(ctx)?);
            match self.peek() {
                Some(Tok::Comma) => self.pos += 1,
                Some(Tok::RParen) => {
                    self.pos += 1;
                    break;
                }
                other => anyhow::bail!("expected `,` or `)`, got {other:?}"),
            }
        }
        Ok(args)
    }
}

fn resolve_ident(name: &str, ctx: &DslContext) -> Value {
    match name {
        "body" => Value::Str(ctx.body.clone()),
        "status_code" => Value::Int(ctx.status as i64),
        "content_length" => Value::Int(ctx.body.len() as i64),
        _ => ctx.vars.get(name).cloned().unwrap_or(Value::Null),
    }
}

fn call(name: &str, args: Vec<Value>, ctx: &DslContext) -> anyhow::Result<Value> {
    let arg_str = |i: usize| -> String { args.get(i).map(as_string).unwrap_or_default() };
    match name {
        "contains" => Ok(Value::Bool(arg_str(0).contains(&arg_str(1)))),
        // A script step's recorded outcome; `null` when nothing was recorded under
        // that name, so `check()` (an empty context) still accepts the expression.
        "step" => Ok(ctx
            .steps
            .get(&arg_str(0))
            .map(|outcome| Value::Str(outcome.clone()))
            .unwrap_or(Value::Null)),
        "url_encode" => Ok(Value::Str(url_encode(&arg_str(0)))),
        "base64" => Ok(Value::Str(base64(&arg_str(0)))),
        "html_escape" => Ok(Value::Str(html_escape(&arg_str(0)))),
        "to_lower" => Ok(Value::Str(arg_str(0).to_lowercase())),
        // `len` counts Unicode scalar values (characters), not UTF-8 bytes.
        "len" => Ok(Value::Int(arg_str(0).chars().count() as i64)),
        "concat" => Ok(Value::Str(args.iter().map(as_string).collect())),
        "rand_text_alpha" => {
            let n = match args.first() {
                Some(Value::Int(i)) => *i,
                _ => 0,
            };
            if n < 0 {
                anyhow::bail!("rand_text_alpha length must be non-negative, got {n}");
            }
            if n as u64 > MAX_RAND_TEXT_ALPHA as u64 {
                anyhow::bail!(
                    "rand_text_alpha length {n} exceeds the maximum of {MAX_RAND_TEXT_ALPHA}"
                );
            }
            Ok(Value::Str(rand_text_alpha(n as usize)))
        }
        other => anyhow::bail!("unknown DSL function `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I6: a huge `rand_text_alpha` length errors at evaluation (which `check`
    /// runs at precheck) instead of allocating; a small one still works.
    #[test]
    fn rand_text_alpha_caps_length() {
        let ctx = DslContext::default();
        let v = eval("rand_text_alpha(8)", &ctx).expect("a small length is fine");
        assert_eq!(as_string(&v).chars().count(), 8);

        let huge = format!("rand_text_alpha({})", MAX_RAND_TEXT_ALPHA as i64 + 1);
        assert!(eval(&huge, &ctx).is_err(), "an oversize length must error");
        // `check` is the precheck entry point; it must reject it too.
        assert!(check(&huge).is_err());
    }

    /// Minor (a): `==` does not stringify across types — a number equals only a
    /// number, so `200 == "200"` is false.
    #[test]
    fn equality_is_type_aware() {
        let ctx = DslContext::default();
        assert_eq!(eval("200 == 200", &ctx).unwrap(), Value::Bool(true));
        assert_eq!(eval("200 == \"200\"", &ctx).unwrap(), Value::Bool(false));
        assert_eq!(eval("\"x\" == \"x\"", &ctx).unwrap(), Value::Bool(true));
        assert_eq!(eval("\"x\" != 1", &ctx).unwrap(), Value::Bool(true));
    }

    /// Minor (b): `len` counts characters, not UTF-8 bytes.
    #[test]
    fn len_counts_characters() {
        let ctx = DslContext::default();
        // "é" is two UTF-8 bytes but one character.
        assert_eq!(eval("len(\"é\")", &ctx).unwrap(), Value::Int(1));
        assert_eq!(eval("len(\"abc\")", &ctx).unwrap(), Value::Int(3));
    }
}
