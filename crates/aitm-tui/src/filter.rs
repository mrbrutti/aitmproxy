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
//! wildcards; a quoted argument may contain spaces. `~h` and `~b` need the
//! flow's detail (F5) and are false until it has arrived.

use crate::model::{FlowDetail, FlowKind, FlowRow, Origin};

/// A parsed filter expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Url(String),
    Host(String),
    Method(String),
    /// Exact code, or a class pattern like `4xx`.
    Status(String),
    Header(String),
    Body(String),
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
    let mut p = Parser { tokens, pos: 0 };
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
        }
    }
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' => {
                chars.next();
            }
            '(' => {
                chars.next();
                out.push(Tok::LParen);
            }
            ')' => {
                chars.next();
                out.push(Tok::RParen);
            }
            '&' => {
                chars.next();
                out.push(Tok::And);
            }
            '|' => {
                chars.next();
                out.push(Tok::Or);
            }
            '!' => {
                chars.next();
                out.push(Tok::Not);
            }
            '"' | '\'' => {
                let quote = c;
                chars.next();
                let mut word = String::new();
                loop {
                    match chars.next() {
                        Some(ch) if ch == quote => break,
                        Some(ch) => word.push(ch),
                        None => return Err("unterminated quote".into()),
                    }
                }
                out.push(Tok::Word(word));
            }
            '~' => {
                chars.next();
                let mut name = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        name.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if name.is_empty() {
                    return Err("`~` needs a name".into());
                }
                out.push(Tok::Atom(name));
            }
            _ => {
                let mut word = String::new();
                while let Some(&ch) = chars.peek() {
                    if matches!(ch, ' ' | '\t' | '(' | ')' | '&' | '|') {
                        break;
                    }
                    word.push(ch);
                    chars.next();
                }
                out.push(Tok::Word(word));
            }
        }
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
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
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.atom()
    }

    fn arg(&mut self, name: &str) -> Result<String, String> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Ok(w)
            }
            _ => Err(format!("`~{name}` needs an argument")),
        }
    }

    fn atom(&mut self) -> Result<Expr, String> {
        match self.peek().cloned() {
            Some(Tok::LParen) => {
                self.pos += 1;
                let e = self.or()?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err("missing `)`".into());
                }
                self.pos += 1;
                Ok(e)
            }
            Some(Tok::Word(w)) => {
                self.pos += 1;
                Ok(Expr::Url(w))
            }
            Some(Tok::Atom(name)) => {
                self.pos += 1;
                Ok(match name.as_str() {
                    "u" | "url" => Expr::Url(self.arg(&name)?),
                    "d" | "host" | "domain" => Expr::Host(self.arg(&name)?),
                    "m" | "method" => Expr::Method(self.arg(&name)?),
                    "s" | "c" | "status" | "code" => Expr::Status(self.arg(&name)?),
                    "h" | "header" => Expr::Header(self.arg(&name)?),
                    "b" | "body" => Expr::Body(self.arg(&name)?),
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
            Expr::Url(p) => wild(p, &row.url()),
            Expr::Host(p) => wild(p, &row.authority),
            Expr::Method(p) => row.method.eq_ignore_ascii_case(p),
            Expr::Status(p) => status_matches(p, row.status),
            Expr::Header(p) => ctx.detail.is_some_and(|d| {
                d.request
                    .iter()
                    .chain(d.response.iter())
                    .flat_map(|m| m.headers.iter())
                    .any(|(n, v)| wild(p, n) || wild(p, v))
            }),
            Expr::Body(p) => ctx.detail.is_some_and(|d| {
                d.request
                    .iter()
                    .chain(d.response.iter())
                    .filter_map(|m| m.body_text())
                    .any(|t| wild(p, t))
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
        assert_eq!(e, Expr::Url("login".into()));
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
