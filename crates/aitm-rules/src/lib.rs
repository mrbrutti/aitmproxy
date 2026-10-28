//! Shared rule/condition match model for aitmproxy (M6 foundation).
//!
//! One matcher, reused by F3 (rule-based intercept), F9 (WS-frame rules) and
//! Map Local/Remote. A [`Rule`] carries a [`MatchCondition`]; [`compile`]
//! validates and pre-compiles it once (any regex is compiled here, so an invalid
//! pattern is rejected with [`RuleError::BadRegex`] rather than panicking at
//! match time), and [`CompiledRule::matches`] answers the single question every
//! feature asks: *does this flow, at this phase, match this condition?*
//!
//! ## URL match subject
//!
//! A [`UrlMatch`] clause (wildcard or regex) is evaluated against the request
//! **target** — the `path` (which already carries the query), e.g. `/api/login`
//! or `/v2/users?x=1`. Host/authority targeting is the separate [`HostMatch`]
//! clause. (The spec §0 prose describes matching against
//! `scheme://authority/path?query`; the plan's authoritative regex test is
//! path-anchored — `^/v[0-9]+/users$` against `/v2/users` — which cannot match a
//! `scheme://…` string, so the matcher runs URL clauses against the path.)

use aitm_core::{Flow, HttpRequest, WsDir};
use regex::{Regex, RegexBuilder};

/// Compiled-program size cap for a single pattern. Rules can be agent-supplied,
/// so a pattern that would compile to a larger automaton than this is rejected
/// (`RuleError::BadRegex`) rather than ballooning to the crate's 10 MiB default.
const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// One operator-authored match rule. `id` is the stable handle a command surface
/// uses to remove the rule; `name` is a human label.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub name: Option<String>,
    pub enabled: bool,
    pub condition: MatchCondition,
}

/// The clauses a [`Rule`] matches on. A `None` clause means "any"; every present
/// clause must match for the rule to fire.
#[derive(Debug, Clone)]
pub struct MatchCondition {
    /// Matched against the request target path (see the module docs).
    pub url: Option<UrlMatch>,
    /// Case-insensitive exact method; `None` == any.
    pub method: Option<String>,
    /// Authority (host) match; `None` == any.
    pub host: Option<HostMatch>,
    /// Which lifecycle point this rule fires at.
    pub phase: Phase,
    /// WS-frame rules only: match a frame direction; `None` == any direction.
    pub ws_dir: Option<WsDir>,
}

/// A URL clause: a shell-style wildcard (`*` = any run), or a `regex` crate
/// pattern.
#[derive(Debug, Clone)]
pub enum UrlMatch {
    Wildcard(String),
    Regex(String),
}

/// A host clause against the request authority (port-insensitive).
#[derive(Debug, Clone)]
pub enum HostMatch {
    Exact(String),
    Wildcard(String),
}

/// The lifecycle point a rule fires at. `Any` fires at every phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Request,
    Response,
    WsFrame,
    Any,
}

/// Why [`compile`] rejected a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    BadRegex { pattern: String, message: String },
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::BadRegex { pattern, message } => {
                write!(f, "invalid regex {pattern:?}: {message}")
            }
        }
    }
}

impl std::error::Error for RuleError {}

/// A [`Rule`] whose patterns have been validated and compiled once. Reused per
/// event; [`matches`](CompiledRule::matches) does no compilation.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    rule: Rule,
    url: Option<Regex>,
    host: Option<CompiledHost>,
}

#[derive(Debug, Clone)]
enum CompiledHost {
    Exact(String),
    Wildcard(Regex),
}

/// Validate and pre-compile a rule's condition, compiling any regex once. Returns
/// [`RuleError::BadRegex`] for an invalid pattern instead of panicking later.
pub fn compile(rule: Rule) -> Result<CompiledRule, RuleError> {
    let url = match &rule.condition.url {
        None => None,
        Some(UrlMatch::Wildcard(pat)) => Some(compile_pattern(&wildcard_to_regex(pat), pat)?),
        Some(UrlMatch::Regex(pat)) => Some(compile_pattern(pat, pat)?),
    };
    let host = match &rule.condition.host {
        None => None,
        Some(HostMatch::Exact(h)) => Some(CompiledHost::Exact(h.to_ascii_lowercase())),
        // Hosts are case-insensitive: lowercase the pattern so it matches the
        // lowercased authority (`authority_host`). Paths are *not* folded here —
        // URL matching above stays case-sensitive.
        Some(HostMatch::Wildcard(pat)) => Some(CompiledHost::Wildcard(compile_pattern(
            &wildcard_to_regex(&pat.to_ascii_lowercase()),
            pat,
        )?)),
    };
    Ok(CompiledRule { rule, url, host })
}

/// Compile `regex_src` under a fixed size cap, attributing any failure (bad
/// syntax or exceeding [`REGEX_SIZE_LIMIT`]) to the operator-facing `pattern`.
fn compile_pattern(regex_src: &str, pattern: &str) -> Result<Regex, RuleError> {
    RegexBuilder::new(regex_src)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| RuleError::BadRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })
}

/// Translate a shell-style wildcard (`*` = any run) into an anchored regex. Every
/// other character is matched literally, so the produced regex always compiles.
fn wildcard_to_regex(pattern: &str) -> String {
    let mut re = String::with_capacity(pattern.len() + 4);
    re.push('^');
    for ch in pattern.chars() {
        if ch == '*' {
            re.push_str(".*");
        } else {
            // Escape one char so regex metacharacters are matched literally.
            re.push_str(&regex::escape(&ch.to_string()));
        }
    }
    re.push('$');
    re
}

/// The host portion of an `authority` (`host[:port]`), lowercased, with any port
/// stripped. Handles bracketed IPv6 literals (`[::1]:443` → `[::1]`).
fn authority_host(authority: &str) -> String {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: host is up to and including the closing bracket.
        match rest.split_once(']') {
            Some((inner, _)) => format!("[{inner}]"),
            None => authority.to_string(),
        }
    } else {
        authority.split(':').next().unwrap_or(authority).to_string()
    };
    host.to_ascii_lowercase()
}

impl CompiledRule {
    /// The rule this was compiled from.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// The one matcher, reused everywhere. `phase` and `dir` are supplied by the
    /// dispatching plugin for the event being handled.
    ///
    /// Returns `true` iff the rule is enabled, its condition phase is `Any` or
    /// equals `phase`, and every present clause matches: `url` against the
    /// request target, `method` case-insensitively, `host` against the request
    /// authority, and `ws_dir` against `dir`. Clauses that need a request
    /// (`url`/`method`/`host`) never match a non-HTTP flow.
    pub fn matches(&self, flow: &Flow, phase: Phase, dir: Option<WsDir>) -> bool {
        let cond = &self.rule.condition;

        if !self.rule.enabled {
            return false;
        }
        if cond.phase != Phase::Any && cond.phase != phase {
            return false;
        }
        if let Some(want) = cond.ws_dir {
            if dir != Some(want) {
                return false;
            }
        }

        let req = http_request(flow);

        if let Some(url) = &self.url {
            match req {
                Some(req) if url.is_match(&req.path) => {}
                _ => return false,
            }
        }
        if let Some(method) = &cond.method {
            match req {
                Some(req) if req.method.eq_ignore_ascii_case(method) => {}
                _ => return false,
            }
        }
        if let Some(host) = &self.host {
            let Some(req) = req else { return false };
            let authority = authority_host(&req.authority);
            let ok = match host {
                CompiledHost::Exact(h) => &authority == h,
                CompiledHost::Wildcard(re) => re.is_match(&authority),
            };
            if !ok {
                return false;
            }
        }

        true
    }
}

/// The HTTP request backing a flow, if any. WebSocket flows carry no request.
fn http_request(flow: &Flow) -> Option<&HttpRequest> {
    match flow {
        Flow::Http(f) => Some(&f.request),
        Flow::WebSocket(_) => None,
    }
}
