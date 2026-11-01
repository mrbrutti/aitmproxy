//! The filter language: mitmproxy-style expressions, the portable text form of
//! the GUIs' stacked filters (foundation §2.7 "Filter bar", §3.2). A filter
//! copies between surfaces as text, so the grammar is fixed here:
//!
//! ```text
//! expr  := or
//! or    := and ( '|' and )*
//! and   := not ( '&'? not )*          juxtaposition is AND
//! not   := '!' not | atom
//! atom  := '(' expr ')' | '~' name [arg] | word      a bare word is ~u word
//! ```
//!
//! Atoms: `~u` url · `~d` host · `~m` method · `~s`/`~c` status (`200`, `4xx`) ·
//! `~h` header name/value · `~b` body text · `~t` content-type · `~client` process ·
//! `~comment` · `~mark` colour · flags `~a` agent-originated · `~scope` / `~oos` ·
//! `~ws` · `~paused` · `~killed` · `~replay` · `~e` edited · `~q` no response yet.
//! Text arguments match case-insensitively as substrings, with `*` and `?`
//! wildcards; a quoted argument may contain spaces. A slash-delimited
//! argument (`~u /^https:\/\/api\./`) is a regex, case-insensitive unless it
//! says `(?-i)`; `~u`, `~d`, `~h` and `~b` take one, and a bare `/re/` is
//! `~u /re/`. `~h` and `~b` need the flow's detail (F5) and are false until it
//! has arrived. Nesting (`!`, `(`) is bounded at [`MAX_DEPTH`].

use regex::{Regex, RegexBuilder};

use crate::model::{FlowDetail, FlowKind, FlowRow, Origin};

/// How deep `!`/`(` may nest; deeper input is refused, not recursed into.
pub const MAX_DEPTH: usize = 64;

/// The compiled-program size a filter regex may reach (the input is typed by
/// the operator, but a pasted expression should still fail fast, not grow).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// A text argument: a wildcard literal or a compiled regex.
#[derive(Debug, Clone)]
pub enum Pat {
    /// Case-insensitive substring with `*` / `?` (see [`wild`]).
    Wild(String),
    /// A `/re/` argument, compiled once at parse time.
    Re(Regex),
}

impl PartialEq for Pat {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Pat::Wild(a), Pat::Wild(b)) => a == b,
            (Pat::Re(a), Pat::Re(b)) => a.as_str() == b.as_str(),
            _ => false,
        }
    }
}

impl Eq for Pat {}

impl Pat {
    /// Whether `text` matches the pattern.
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Pat::Wild(p) => wild(p, text),
            Pat::Re(r) => r.is_match(text),
        }
    }

    fn regex(src: &str) -> Result<Self, String> {
        RegexBuilder::new(src)
            .case_insensitive(true)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map(Pat::Re)
            .map_err(|e| {
                let why = e.to_string();
                let first = why.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
                format!("bad regex /{src}/: {first}")
            })
    }
}

/// A parsed filter expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Url(Pat),
    Host(Pat),
    Method(String),
    /// Exact code, or a class pattern like `4xx`.
    Status(String),
    Header(Pat),
    Body(Pat),
    ContentType(String),
    Client(String),
    Comment(String),
    Mark(String),
    Agent,
    InScope,
    OutOfScope,
    WebSocket,
    Paused,
    Killed,
    Replay,
    Edited,
    Pending,
}

/// What `Expr::matches` needs besides the row.
pub struct Ctx<'a> {
    pub detail: Option<&'a FlowDetail>,
    pub in_scope: bool,
}

/// Parse an expression. Empty or whitespace-only input is `Ok(None)`.
pub fn parse(input: &str) -> Result<Option<Expr>, String> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut p = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let expr = p.or()?;
    if p.pos < p.tokens.len() {
        return Err(format!("unexpected `{}`", p.tokens[p.pos].text()));
    }
    Ok(Some(expr))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    LParen,
    RParen,
    And,
    Or,
    Not,
    /// `~name`
    Atom(String),
    Word(String),
    /// `/re/`: the source between the slashes.
    Regex(String),
}

impl Tok {
    fn text(&self) -> String {
        match self {
            Tok::LParen => "(".into(),
            Tok::RParen => ")".into(),
            Tok::And => "&".into(),
            Tok::Or => "|".into(),
            Tok::Not => "!".into(),
            Tok::Atom(a) => format!("~{a}"),
            Tok::Word(w) => w.clone(),
            Tok::Regex(r) => format!("/{r}/"),
        }
    }
}

/// Characters that end a bare word (and may follow a closing `/`).
fn is_delim(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '(' | ')' | '&' | '|')
}

/// A `/re/` starting at `chars[start]` (`'/'`): the source between the
/// slashes and the index after the closing one, when a closing `/` exists
/// that is followed by a delimiter or the end. `\` escapes the next char and
/// both are kept, so `\/` reaches the regex engine as an escaped slash. A
/// `/api/login` with no such closing slash is not a regex.
fn scan_regex(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut i = start + 1;
    let mut src = String::new();
    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() => {
                src.push('\\');
                src.push(chars[i + 1]);
                i += 2;
            }
            '/' if chars.get(i + 1).is_none_or(|&n| is_delim(n)) => {
                return Some((src, i + 1));
            }
            ch => {
                src.push(ch);
                i += 1;
            }
        }
    }
    None
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' => i += 1,
            '(' => {
                i += 1;
                out.push(Tok::LParen);
            }
            ')' => {
                i += 1;
                out.push(Tok::RParen);
            }
            '&' => {
                i += 1;
                out.push(Tok::And);
            }
            '|' => {
                i += 1;
                out.push(Tok::Or);
            }
            '!' => {
                i += 1;
                out.push(Tok::Not);
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut word = String::new();
                loop {
                    match chars.get(i) {
                        Some(&ch) if ch == quote => {
                            i += 1;
                            break;
                        }
                        Some(&ch) => {
                            word.push(ch);
                            i += 1;
                        }
                        None => return Err("unterminated quote".into()),
                    }
                }
                out.push(Tok::Word(word));
            }
            '~' => {
                i += 1;
                let mut name = String::new();
                while let Some(&ch) = chars.get(i) {
                    if ch.is_alphanumeric() || ch == '_' {
                        name.push(ch);
                        i += 1;
                    } else {
                        break;
                    }
                }
                if name.is_empty() {
                    return Err("`~` needs a name".into());
                }
                out.push(Tok::Atom(name));
            }
            '/' => {
                if let Some((src, next)) = scan_regex(&chars, i) {
                    out.push(Tok::Regex(src));
                    i = next;
                } else {
                    i = word(&chars, i, &mut out);
                }
            }
            _ => i = word(&chars, i, &mut out),
        }
    }
    Ok(out)
}

/// Read a bare word from `chars[start]`, push it, return the index after it.
fn word(chars: &[char], start: usize, out: &mut Vec<Tok>) -> usize {
    let mut i = start;
    let mut w = String::new();
    while let Some(&ch) = chars.get(i) {
        if is_delim(ch) {
            break;
        }
        w.push(ch);
        i += 1;
    }
    out.push(Tok::Word(w));
    i
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
    /// Current `!`/`(` nesting, checked against [`MAX_DEPTH`].
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    /// Run `f` one level deeper, refusing to go past [`MAX_DEPTH`].
    fn nested(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<Expr, String>,
    ) -> Result<Expr, String> {
        if self.depth >= MAX_DEPTH {
            return Err("expression too deep".into());
        }
        self.depth += 1;
        let out = f(self);
        self.depth -= 1;
        out
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut left = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut left = self.not()?;
        loop {
            match self.peek() {
                Some(Tok::And) => {
                    self.pos += 1;
                }
                Some(Tok::Or) | Some(Tok::RParen) | None => break,
                _ => {}
            }
            let right = self.not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.peek() == Some(&Tok::Not) {
            self.pos += 1;
            let inner = self.nested(Self::not)?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.atom()
    }

    /// A text-or-regex argument (`~u`, `~d`, `~h`, `~b`).
    fn pat(&mut self, name: &str) -> Result<Pat, String> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Ok(Pat::Wild(w))
            }
            Some(Tok::Regex(r)) => {
                let r = r.clone();
                self.pos += 1;
                Pat::regex(&r)
            }
            _ => Err(format!("`~{name}` needs an argument")),
        }
    }

    /// A literal-only argument (method, status, content type, …).
    fn arg(&mut self, name: &str) -> Result<String, String> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Ok(w)
            }
            Some(Tok::Regex(_)) => Err(format!("`~{name}` takes a literal, not a regex")),
            _ => Err(format!("`~{name}` needs an argument")),
        }
    }

    fn atom(&mut self) -> Result<Expr, String> {
        match self.peek().cloned() {
            Some(Tok::LParen) => {
                self.pos += 1;
                let e = self.nested(Self::or)?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err("missing `)`".into());
                }
                self.pos += 1;
                Ok(e)
            }
            Some(Tok::Word(w)) => {
                self.pos += 1;
                Ok(Expr::Url(Pat::Wild(w)))
            }
            Some(Tok::Regex(r)) => {
                self.pos += 1;
                Ok(Expr::Url(Pat::regex(&r)?))
            }
            Some(Tok::Atom(name)) => {
                self.pos += 1;
                Ok(match name.as_str() {
                    "u" | "url" => Expr::Url(self.pat(&name)?),
                    "d" | "host" | "domain" => Expr::Host(self.pat(&name)?),
                    "m" | "method" => Expr::Method(self.arg(&name)?),
                    "s" | "c" | "status" | "code" => Expr::Status(self.arg(&name)?),
                    "h" | "header" => Expr::Header(self.pat(&name)?),
                    "b" | "body" => Expr::Body(self.pat(&name)?),
                    "t" | "type" | "ct" => Expr::ContentType(self.arg(&name)?),
                    "client" | "app" => Expr::Client(self.arg(&name)?),
                    "comment" => Expr::Comment(self.arg(&name)?),
                    "mark" | "marked" => Expr::Mark(self.arg(&name)?),
                    "a" | "agent" => Expr::Agent,
                    "scope" | "in" => Expr::InScope,
                    "oos" | "out" => Expr::OutOfScope,
                    "ws" | "websocket" => Expr::WebSocket,
                    "paused" | "intercepted" | "p" => Expr::Paused,
                    "killed" | "k" => Expr::Killed,
                    "replay" | "r" => Expr::Replay,
                    "e" | "edited" => Expr::Edited,
                    "q" | "pending" => Expr::Pending,
                    other => return Err(format!("unknown filter `~{other}`")),
                })
            }
            Some(tok) => Err(format!("unexpected `{}`", tok.text())),
            None => Err("expression ends early".into()),
        }
    }
}

/// Case-insensitive substring match with `*` (any run) and `?` (one char)
/// wildcards. A pattern without wildcards matches anywhere in `text`.
pub fn wild(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    if !p.contains(&'*') && !p.contains(&'?') {
        return pattern.is_empty() || text.to_lowercase().contains(&pattern.to_lowercase());
    }
    // Implicit leading/trailing `*` so `api/*/login` finds itself mid-URL.
    let mut full = vec!['*'];
    full.extend(p);
    full.push('*');
    glob(&full, &t)
}

fn glob(p: &[char], t: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn status_matches(pattern: &str, status: Option<u16>) -> bool {
    let Some(code) = status else {
        return false;
    };
    let p = pattern.to_ascii_lowercase();
    if let Some(class) = p.strip_suffix("xx") {
        return class.parse::<u16>().is_ok_and(|c| code / 100 == c);
    }
    p.parse::<u16>().is_ok_and(|c| c == code)
}

impl Expr {
    /// Whether the row satisfies the expression.
    pub fn matches(&self, row: &FlowRow, ctx: &Ctx<'_>) -> bool {
        match self {
            Expr::And(a, b) => a.matches(row, ctx) && b.matches(row, ctx),
            Expr::Or(a, b) => a.matches(row, ctx) || b.matches(row, ctx),
            Expr::Not(a) => !a.matches(row, ctx),
            Expr::Url(p) => p.is_match(&row.url()),
            Expr::Host(p) => p.is_match(&row.authority),
            Expr::Method(p) => row.method.eq_ignore_ascii_case(p),
            Expr::Status(p) => status_matches(p, row.status),
            Expr::Header(p) => ctx.detail.is_some_and(|d| {
                d.request
                    .iter()
                    .chain(d.response.iter())
                    .flat_map(|m| m.headers.iter())
                    .any(|(n, v)| p.is_match(n) || p.is_match(v))
            }),
            Expr::Body(p) => ctx.detail.is_some_and(|d| {
                d.request
                    .iter()
                    .chain(d.response.iter())
                    .filter_map(|m| m.body_text())
                    .any(|t| p.is_match(t))
            }),
            Expr::ContentType(p) => row.content_type.as_deref().is_some_and(|t| wild(p, t)),
            Expr::Client(p) => row.client.as_deref().is_some_and(|c| wild(p, c)),
            Expr::Comment(p) => row.comment.as_deref().is_some_and(|c| wild(p, c)),
            Expr::Mark(p) => row.marks.iter().any(|m| m.eq_ignore_ascii_case(p)),
            Expr::Agent => row.origin == Origin::Agent,
            Expr::InScope => ctx.in_scope,
            Expr::OutOfScope => !ctx.in_scope,
            Expr::WebSocket => row.kind == FlowKind::WebSocket,
            Expr::Paused => row.paused(),
            Expr::Killed => row.killed(),
            Expr::Replay => row.is_replay,
            Expr::Edited => row.edited,
            Expr::Pending => row.pending(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(method: &str, url: &str, status: Option<u16>) -> FlowRow {
        let (scheme, rest) = url.split_once("://").unwrap();
        let (authority, path) = rest.split_once('/').map_or((rest, "/"), |(a, p)| (a, p));
        let mut r = FlowRow::from_summary(
            &json!({"id":"x","kind":"http","method":method,"scheme":scheme,"authority":authority,
                    "path":format!("/{}", path.trim_start_matches('/')),"status":status,"intercept":"observed"}),
            1,
        )
        .unwrap();
        r.path = if path == "/" {
            "/".into()
        } else {
            format!("/{path}")
        };
        r
    }

    fn ctx() -> Ctx<'static> {
        Ctx {
            detail: None,
            in_scope: true,
        }
    }

    #[test]
    fn empty_is_none_and_garbage_errors() {
        assert_eq!(parse("   ").unwrap(), None);
        assert!(parse("~zz").is_err());
        assert!(parse("(~m GET").is_err());
        assert!(parse("~m").is_err());
    }

    #[test]
    fn bare_word_is_a_url_match() {
        let e = parse("login").unwrap().unwrap();
        assert_eq!(e, Expr::Url(Pat::Wild("login".into())));
        assert!(e.matches(
            &row("POST", "https://auth.test/api/auth/login", Some(200)),
            &ctx()
        ));
        assert!(!e.matches(&row("GET", "https://auth.test/api/me", Some(200)), &ctx()));
    }

    #[test]
    fn and_or_not_and_parentheses() {
        let e = parse("~u login & ~m POST & ~s 200").unwrap().unwrap();
        assert!(e.matches(
            &row("POST", "https://auth.test/api/auth/login", Some(200)),
            &ctx()
        ));
        assert!(!e.matches(
            &row("GET", "https://auth.test/api/auth/login", Some(200)),
            &ctx()
        ));
        let e = parse("(~m GET | ~m HEAD) !~s 2xx").unwrap().unwrap();
        assert!(e.matches(&row("GET", "https://a.test/x", Some(404)), &ctx()));
        assert!(!e.matches(&row("GET", "https://a.test/x", Some(200)), &ctx()));
        assert!(!e.matches(&row("POST", "https://a.test/x", Some(404)), &ctx()));
    }

    #[test]
    fn wildcards_and_quotes() {
        let e = parse("~u \"api/*/items/??\"").unwrap().unwrap();
        assert!(e.matches(
            &row("PUT", "https://api.test/api/cart/items/42", Some(200)),
            &ctx()
        ));
        assert!(!e.matches(
            &row("PUT", "https://api.test/api/cart/items/4", Some(200)),
            &ctx()
        ));
        assert!(wild("SHOP", "api.shop-staging.test"));
        assert!(wild("*.test", "api.shop-staging.test"));
        assert!(!wild("*.example", "api.shop-staging.test"));
    }

    /// S9: recursion is bounded; 10 000 `!` (or `(`) is refused with a named
    /// error instead of overflowing the stack.
    #[test]
    fn deep_nesting_is_refused_not_overflowed() {
        let bangs = format!("{}~a", "!".repeat(10_000));
        assert_eq!(parse(&bangs).unwrap_err(), "expression too deep");
        let parens = format!("{}~a{}", "(".repeat(10_000), ")".repeat(10_000));
        assert_eq!(parse(&parens).unwrap_err(), "expression too deep");
        assert_eq!(
            parse(&format!("{}~a", "!".repeat(MAX_DEPTH + 1))).unwrap_err(),
            "expression too deep"
        );
        // Right at the limit still parses and evaluates.
        let ok = parse(&format!("{}~a", "!".repeat(MAX_DEPTH)))
            .unwrap()
            .unwrap();
        let mut r = row("GET", "https://a.test/x", None);
        r.origin = Origin::Agent;
        assert!(ok.matches(&r, &ctx()), "even number of negations");
    }

    /// I3: a slash-delimited argument is a regex, case-insensitive by default,
    /// on `~u`, `~d`, `~h` and `~b`; a bad regex is a parse error.
    #[test]
    fn slash_delimited_arguments_are_case_insensitive_regexes() {
        let e = parse(r"~u /^https:\/\/api\..*\/login$/").unwrap().unwrap();
        assert!(e.matches(&row("POST", "https://api.test/v1/login", Some(200)), &ctx()));
        assert!(!e.matches(
            &row("POST", "https://auth.test/v1/login", Some(200)),
            &ctx()
        ));
        assert!(!e.matches(
            &row("POST", "https://api.test/v1/login/x", Some(200)),
            &ctx()
        ));
        // `(?i)` is the default; `(?-i)` turns it off.
        let r = row("GET", "https://api.test/Login", Some(200));
        assert!(parse(r"~d /API\.TEST/")
            .unwrap()
            .unwrap()
            .matches(&r, &ctx()));
        assert!(parse("~u /login/").unwrap().unwrap().matches(&r, &ctx()));
        assert!(!parse("~u /(?-i)login/")
            .unwrap()
            .unwrap()
            .matches(&r, &ctx()));
        // A bare `/re/` is a URL regex; a quoted "/x/" stays a literal.
        assert!(parse("/^https/").unwrap().unwrap().matches(&r, &ctx()));
        assert_eq!(
            parse("\"/x/\"").unwrap().unwrap(),
            Expr::Url(Pat::Wild("/x/".into()))
        );
        // A path that merely starts with `/` is still a wildcard literal.
        assert_eq!(
            parse("~u /api/login").unwrap().unwrap(),
            Expr::Url(Pat::Wild("/api/login".into()))
        );
        // ~h and ~b search the detail.
        let d = FlowDetail::from_json(&json!({"id":"x",
            "request":{"headers":[["X-Request-Id","c1a4f0"]],
                       "body": crate::base64::encode(b"token=abc123&x=1")}}))
        .unwrap();
        let c = Ctx {
            detail: Some(&d),
            in_scope: true,
        };
        assert!(parse("~h /^x-request-id$/")
            .unwrap()
            .unwrap()
            .matches(&r, &c));
        // `&`, `|`, `(`, `)` inside the slashes belong to the regex.
        assert!(parse(r"~b /token=[a-z]+\d{3}&/")
            .unwrap()
            .unwrap()
            .matches(&r, &c));
        assert!(parse(r"~b /(abc|zzz)123/ & ~m GET")
            .unwrap()
            .unwrap()
            .matches(&r, &c));
        assert!(!parse(r"~b /^x=1/").unwrap().unwrap().matches(&r, &c));
        // Without a closing slash before a delimiter the word is a literal.
        assert_eq!(
            parse("~u /api/login & ~m GET").unwrap().unwrap(),
            Expr::And(
                Box::new(Expr::Url(Pat::Wild("/api/login".into()))),
                Box::new(Expr::Method("GET".into()))
            )
        );
        // Errors name the regex; literal-only atoms refuse a regex.
        assert!(
            parse("~u /(/").unwrap_err().starts_with("bad regex /(/: "),
            "{}",
            parse("~u /(/").unwrap_err()
        );
        assert_eq!(
            parse("~m /GET/").unwrap_err(),
            "`~m` takes a literal, not a regex"
        );
        // Still Clone + Debug + PartialEq (by source).
        let a = parse("~u /x/").unwrap().unwrap();
        assert_eq!(a.clone(), a);
        assert_ne!(a, parse("~u /y/").unwrap().unwrap());
        assert!(format!("{a:?}").contains("Re"));
    }

    #[test]
    fn flags_and_detail_dependent_atoms() {
        let mut r = row("GET", "https://api.test/api/orders", None);
        assert!(parse("~q").unwrap().unwrap().matches(&r, &ctx()));
        r.origin = Origin::Agent;
        assert!(parse("~a").unwrap().unwrap().matches(&r, &ctx()));
        assert!(!parse("~oos").unwrap().unwrap().matches(&r, &ctx()));
        // ~h needs a detail; without one it is false, with one it searches names and values.
        assert!(!parse("~h content-type")
            .unwrap()
            .unwrap()
            .matches(&r, &ctx()));
        let d = FlowDetail::from_json(
            &json!({"id":"x","request":{"headers":[["Content-Type","application/json"]]}}),
        )
        .unwrap();
        let c = Ctx {
            detail: Some(&d),
            in_scope: false,
        };
        assert!(parse("~h content-type").unwrap().unwrap().matches(&r, &c));
        assert!(parse("~h json").unwrap().unwrap().matches(&r, &c));
        assert!(parse("~oos").unwrap().unwrap().matches(&r, &c));
    }
}
