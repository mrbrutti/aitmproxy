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
//! A [`UrlMatch`] clause is evaluated against two strings and matches when the
//! pattern matches **either**:
//!
//! 1. the full URL `{scheme}://{authority}{path}`, each field exactly as
//!    recorded on [`HttpRequest`]: scheme as the core set it (`http`, or
//!    `https` after TLS MITM), authority as the client sent it (`host` or
//!    `host:port`), path as sent including the query. An empty path gives
//!    `scheme://authority` with no synthesised slash;
//! 2. the path alone (`HttpRequest.path`, which carries the query).
//!
//! The second subject keeps path-anchored patterns (`/api/*`, `^/v1/`) working;
//! for every other pattern shape the path match is implied by the URL match, so
//! no URL-intended pattern gains a false match.
//!
//! **Wildcard** ([`UrlMatch::Wildcard`]): `*` matches any run of characters,
//! including an empty one; every other character is literal, `?` included (in a
//! URL it starts the query). A pattern containing a `*` is anchored to the whole
//! subject; a pattern with no `*` matches as a substring. Matching is
//! case-insensitive.
//!
//! A wildcard whose first character is `/` means the path (a URL never starts
//! with `/`), so it is evaluated against the path subject only: `/admin` does
//! not match `https://admin.example.com/transfer` at the `//` of `scheme://`.
//! Every other wildcard, and every regex, keeps the two-subject rule, so that
//! `//` remains a legitimate match boundary: `*/login*` matches
//! `https://login.example.com/x`, and the unanchored regex `/admin` matches the
//! URL above. Add a [`HostMatch`] clause, or anchor a regex with `^/`, when only
//! the path is meant.
//!
//! **Regex** ([`UrlMatch::Regex`]): `regex` crate syntax, compiled once under
//! the size cap and searched (unanchored) in each subject — anchor with `^`/`$`.
//! Case-insensitive by default; an inline `(?-i)` restores case sensitivity.
//!
//! A `url` clause is optional: omit it to match any URL. An empty pattern is
//! rejected ([`RuleError::EmptyPattern`]) rather than armed as a match-everything
//! rule, a pattern over [`MAX_PATTERN_BYTES`] is rejected before any regex is
//! built ([`RuleError::PatternTooLong`]), and a call carrying more than
//! [`MAX_RULES_PER_CALL`] rules is rejected whole ([`check_rule_count`]).
//!
//! Host/authority targeting on its own is the separate [`HostMatch`] clause.

use aitm_core::{Flow, HttpRequest, WsDir};
use regex::{Regex, RegexBuilder};

pub mod bus;

/// Compiled-program size cap for a single pattern. Rules can be agent-supplied,
/// so a pattern that would compile to a larger automaton than this is rejected
/// (`RuleError::BadRegex`) rather than ballooning to the crate's 10 MiB default.
const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// Longest pattern (url wildcard, url regex or host wildcard) [`compile`]
/// accepts, in bytes. Checked before any regex is built: the compiled-size cap
/// only bites after the parser has walked the whole pattern (a 1 MiB
/// case-folded literal took 263 ms to reject), so agent-supplied input is
/// bounded up front.
pub const MAX_PATTERN_BYTES: usize = 4096;

/// Most rules one `flow.intercept` / `ws.intercept` call may carry; the surfaces
/// run [`check_rule_count`] before compiling any of them.
pub const MAX_RULES_PER_CALL: usize = 256;

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
    /// Matched against the full request URL and against the path alone; either
    /// may match (see the module docs).
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

/// A URL clause: a shell-style wildcard (`*` = any run, every other character
/// literal, substring when star-less), or a `regex` crate pattern (searched).
/// Both are case-insensitive; see the module docs.
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
    BadRegex {
        pattern: String,
        message: String,
    },
    /// A pattern longer than [`MAX_PATTERN_BYTES`]; nothing was compiled.
    PatternTooLong {
        len: usize,
        max: usize,
    },
    /// More rules in one call than [`MAX_RULES_PER_CALL`]; nothing was compiled.
    TooManyRules {
        count: usize,
        max: usize,
    },
    /// An empty `url` wildcard or regex. It would be a substring of every
    /// subject and arm a match-everything rule by accident; omit `url` instead.
    EmptyPattern,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::BadRegex { pattern, message } => {
                write!(f, "invalid regex {pattern:?}: {message}")
            }
            RuleError::PatternTooLong { len, max } => {
                write!(f, "pattern is {len} bytes; the limit is {max}")
            }
            RuleError::TooManyRules { count, max } => {
                write!(f, "{count} rules supplied; the limit is {max} per call")
            }
            RuleError::EmptyPattern => write!(f, "empty url pattern; omit `url` to match any URL"),
        }
    }
}

impl std::error::Error for RuleError {}

/// A [`Rule`] whose patterns have been validated and compiled once. Reused per
/// event; [`matches`](CompiledRule::matches) does no compilation.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    rule: Rule,
    url: Option<CompiledUrl>,
    host: Option<CompiledHost>,
}

/// A compiled `url` clause: the regex and the subject(s) it runs against,
/// decided once at compile time.
#[derive(Debug, Clone)]
struct CompiledUrl {
    re: Regex,
    subject: UrlSubject,
}

/// Which subject(s) a `url` clause is evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlSubject {
    /// The full URL or the path; either may match.
    UrlOrPath,
    /// The path only: a wildcard that starts with `/` is path-intended (a URL
    /// never starts with `/`), and running it against the full URL would let
    /// it match at the `//` of `scheme://` when the host starts with the same
    /// segment (`/admin` vs `https://admin.example.com/transfer`).
    PathOnly,
}

#[derive(Debug, Clone)]
enum CompiledHost {
    Exact(String),
    Wildcard(Regex),
}

/// Reject a `rules` array with more than [`MAX_RULES_PER_CALL`] entries. Command
/// surfaces call this before compiling anything, so a rejected call leaves the
/// active rules unchanged.
pub fn check_rule_count(count: usize) -> Result<(), RuleError> {
    if count > MAX_RULES_PER_CALL {
        return Err(RuleError::TooManyRules {
            count,
            max: MAX_RULES_PER_CALL,
        });
    }
    Ok(())
}

/// Validate and pre-compile a rule's condition, compiling any regex once. Returns
/// [`RuleError::EmptyPattern`] for an empty `url` pattern, [`RuleError::PatternTooLong`]
/// for a pattern over [`MAX_PATTERN_BYTES`] (both before any regex is built) and
/// [`RuleError::BadRegex`] for an invalid pattern, instead of panicking later.
pub fn compile(rule: Rule) -> Result<CompiledRule, RuleError> {
    let url = match &rule.condition.url {
        None => None,
        Some(UrlMatch::Wildcard(pat)) => {
            check_url_pattern(pat)?;
            Some(CompiledUrl {
                re: compile_pattern(
                    &wildcard_to_regex(pat, Anchor::WholeIfStarred),
                    pat,
                    Case::Fold,
                )?,
                subject: if pat.starts_with('/') {
                    UrlSubject::PathOnly
                } else {
                    UrlSubject::UrlOrPath
                },
            })
        }
        Some(UrlMatch::Regex(pat)) => {
            check_url_pattern(pat)?;
            Some(CompiledUrl {
                re: compile_pattern(pat, pat, Case::Fold)?,
                subject: UrlSubject::UrlOrPath,
            })
        }
    };
    let host = match &rule.condition.host {
        None => None,
        Some(HostMatch::Exact(h)) => Some(CompiledHost::Exact(h.to_ascii_lowercase())),
        Some(HostMatch::Wildcard(pat)) => {
            check_len(pat)?;
            Some(CompiledHost::Wildcard(compile_pattern(
                &wildcard_to_regex(&pat.to_ascii_lowercase(), Anchor::Whole),
                pat,
                Case::Exact,
            )?))
        }
    };
    Ok(CompiledRule { rule, url, host })
}

/// A `url` pattern must be non-empty and under the byte cap.
fn check_url_pattern(pattern: &str) -> Result<(), RuleError> {
    if pattern.is_empty() {
        return Err(RuleError::EmptyPattern);
    }
    check_len(pattern)
}

/// The byte cap, applied to the operator's pattern before it is translated or
/// handed to the regex parser.
fn check_len(pattern: &str) -> Result<(), RuleError> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(RuleError::PatternTooLong {
            len: pattern.len(),
            max: MAX_PATTERN_BYTES,
        });
    }
    Ok(())
}

/// Compile `regex_src` under a fixed size cap, attributing any failure (bad
/// syntax or exceeding [`REGEX_SIZE_LIMIT`]) to the operator-facing `pattern`.
/// The cap applies to the program as built, so a [`Case::Fold`] compile is
/// capped on its (larger) folded form.
fn compile_pattern(regex_src: &str, pattern: &str, case: Case) -> Result<Regex, RuleError> {
    RegexBuilder::new(regex_src)
        .size_limit(REGEX_SIZE_LIMIT)
        .case_insensitive(case == Case::Fold)
        .build()
        .map_err(|e| RuleError::BadRegex {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })
}

/// How a compiled pattern treats letter case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    /// The regex crate's Unicode case fold. `url` clauses use it because the
    /// scheme and host are case-insensitive by RFC 3986 and lead the subject,
    /// and the macOS preview already folds; the fold also covers the path, the
    /// safe direction for a testing proxy (`/admin` also pauses `/Admin`).
    Fold,
    /// Match as written. Host wildcards take this route: the authority is
    /// ASCII-lowercased (`authority_host`) and the pattern is lowercased to
    /// meet it, which is cheaper than a folded program and all a host needs.
    Exact,
}

/// How a wildcard pattern is bound to its subject.
#[derive(Debug, Clone, Copy)]
enum Anchor {
    /// Always `^…$`: a star-less host wildcard is still an exact host.
    Whole,
    /// `^…$` only when the pattern has a `*`; a star-less pattern is a
    /// substring, so an operator typing `httpbin.org` gets that host rather
    /// than an exact-URL rule that can never fire.
    WholeIfStarred,
}

/// Translate a shell-style wildcard (`*` = any run) into a regex. Every other
/// character is matched literally, so the produced regex always compiles.
fn wildcard_to_regex(pattern: &str, anchor: Anchor) -> String {
    let anchored = match anchor {
        Anchor::Whole => true,
        Anchor::WholeIfStarred => pattern.contains('*'),
    };
    let mut re = String::with_capacity(pattern.len() + 4);
    if anchored {
        re.push('^');
    }
    for ch in pattern.chars() {
        if ch == '*' {
            re.push_str(".*");
        } else {
            re.push_str(&regex::escape(&ch.to_string()));
        }
    }
    if anchored {
        re.push('$');
    }
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
    /// equals `phase`, and every present clause matches: `url` against the full
    /// request URL or the path alone (the path only for a wildcard that starts
    /// with `/`), `method` case-insensitively, `host` against the request
    /// authority, and `ws_dir` against `dir`. Clauses that
    /// need a request (`url`/`method`/`host`) never match a non-HTTP flow.
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
            let Some(req) = req else { return false };
            let hit = match url.subject {
                UrlSubject::PathOnly => url.re.is_match(&req.path),
                UrlSubject::UrlOrPath => {
                    let full = format!("{}://{}{}", req.scheme, req.authority, req.path);
                    url.re.is_match(&full) || url.re.is_match(&req.path)
                }
            };
            if !hit {
                return false;
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
