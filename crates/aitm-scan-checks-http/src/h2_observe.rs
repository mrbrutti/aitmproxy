//! The five observe-only HTTP/2 conformance checks (spec D8.2, AC T3-3). Implemented
//! by T3 task 9.
//!
//! Each check opens **one** raw h2 connection to the point's own authority,
//! sends at most eight streams, reads what the server does, and closes. It
//! never retries, never floods and never sends a second request: the checks
//! ask how a server *reacts* to a malformed or rapidly cancelled stream, not
//! whether it can be made to fall over (spec anti-goals).
//!
//! | id | class | mode | streams | reports |
//! |---|---|---|---|---|
//! | `h2-settings-observe` | `h2-settings` | `SettingsOnly` | 0 | the advertised SETTINGS, as an `Info` observation |
//! | `h2-pseudo-header-validation` | `h2-pseudo-header` | `Blocks` | 3 | a variant the server answered instead of rejecting |
//! | `h2-header-crlf-tolerance` | `h2-header-crlf` | `Blocks` | 2 | a CR/LF variant the server answered |
//! | `h2-cl-te-downgrade-indicator` | `h2-smuggling-indicator` | `Blocks` | 2 | a length/encoding variant the server answered |
//! | `h2-rapid-reset-mitigation` | `h2-rapid-reset` | `RapidReset { pairs: 8 }` | 8 | whether any reset-rate mitigation showed |
//!
//! An observe-only check reports by returning [`Outcome::Vulnerable`] with a
//! [`CheckMeta::severity`] of `Info`: the engine opens an issue from a
//! vulnerable verdict and takes its severity from the meta (plan call B7). On a
//! conforming server the expected set is `h2-settings-observe` and
//! `h2-rapid-reset-mitigation` as `Info` observations, and the other three
//! clean.
//!
//! # When the raw connection may accept any certificate
//!
//! [`RealRawH2Runner`] is built over `TlsVerify::AcceptAny`. That is allowed
//! only while **all four** of these hold, and every check here keeps them:
//!
//! 1. the raw connection goes to the **same authority** as the insertion point
//!    (derived from `point.url`, userinfo dropped), and to no other;
//! 2. it is opened only **after `host.baseline()` succeeded** through the
//!    guarded job client, so the scope gate has already cleared that authority;
//! 3. **no cookie, authorization or session header** is ever sent: a plan holds
//!    only pseudo-headers plus the one field under test, and the driver itself
//!    refuses `cookie`, `authorization`, `proxy-authorization` and `set-cookie`;
//! 4. the probe is **observe-only**: its result is a note about the server's h2
//!    behaviour, not a trust decision, and nothing it reads is replayed.
//!
//! # One connection per authority
//!
//! The scheduler runs a check once per insertion point, but these are
//! properties of an origin (spec gap G1). Each check instance therefore keeps a
//! ten-minute once-per-authority guard: the first point of an authority probes,
//! later points return [`Outcome::Inconclusive`] and send nothing at all.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use aitm_poc::Severity;
use aitm_proto_http::raw_h2::{
    RawH2Client, RawH2Mode, RawH2Observation, RawH2Plan, RawH2Target, RawHeader, StreamOutcome,
    TlsVerify, MAX_RAW_STREAMS,
};
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, InsertionKind, InsertionPoint,
    Intensity, LaneKind, Outcome, ProbeHost, Technique, Verdict,
};
use futures::future::BoxFuture;

/// How long an authority stays "already observed" for one check instance.
const GUARD_TTL: Duration = Duration::from_secs(10 * 60);

/// The most authorities one guard remembers; the oldest is dropped past this.
const GUARD_CAP: usize = 1024;

/// How many reset pairs the rapid-reset check sends. Equal to the driver's cap.
const RESET_PAIRS: u8 = MAX_RAW_STREAMS;

/// The name of the one extra field a malformed variant adds.
const PROBE_FIELD: &str = "x-aitm-probe";

/// The detail every refused or failed raw probe carries.
const NO_H2: &str = "origin does not negotiate h2 (or the raw probe failed)";

/// What the check layer asks of the driver: run one plan, return one
/// observation. [`RealRawH2Runner`] is the production implementation; tests
/// script a fake, so no check test opens a socket.
pub trait RawH2Runner: Send + Sync {
    /// Run `plan` on one connection. An `Err` means the origin did not speak
    /// h2 or the probe could not complete; the checks report it as
    /// inconclusive.
    fn run<'a>(&'a self, plan: RawH2Plan) -> BoxFuture<'a, anyhow::Result<RawH2Observation>>;
}

/// The production runner: the frame-level driver, accepting any certificate
/// under the four conditions in this module's documentation.
pub struct RealRawH2Runner {
    client: RawH2Client,
}

impl RealRawH2Runner {
    /// A runner over [`RawH2Client`] with `TlsVerify::AcceptAny`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: RawH2Client::new(TlsVerify::AcceptAny),
        }
    }
}

impl Default for RealRawH2Runner {
    fn default() -> Self {
        Self::new()
    }
}

impl RawH2Runner for RealRawH2Runner {
    fn run<'a>(&'a self, plan: RawH2Plan) -> BoxFuture<'a, anyhow::Result<RawH2Observation>> {
        Box::pin(async move { self.client.probe(&plan).await })
    }
}

/// The five observe-only h2 checks, all probing through `runner`.
///
/// Each call builds fresh checks with fresh once-per-authority guards.
#[must_use]
pub fn h2_checks(runner: Arc<dyn RawH2Runner>) -> Vec<Arc<dyn Check>> {
    [
        Kind::Settings,
        Kind::PseudoHeader,
        Kind::HeaderCrlf,
        Kind::ClTe,
        Kind::RapidReset,
    ]
    .into_iter()
    .map(|kind| Arc::new(H2Check::new(kind, Arc::clone(&runner))) as Arc<dyn Check>)
    .collect()
}

/// Which of the five checks an [`H2Check`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Settings,
    PseudoHeader,
    HeaderCrlf,
    ClTe,
    RapidReset,
}

impl Kind {
    /// The malformed variants a `Blocks` check sends, in stream order.
    fn variant_labels(self) -> &'static [&'static str] {
        match self {
            Kind::PseudoHeader => &[
                "missing :path",
                "duplicate :method",
                "pseudo-header after a regular header",
            ],
            Kind::HeaderCrlf => &["CRLF in a header value", "CRLF in a header name"],
            Kind::ClTe => &[
                "content-length one byte longer than the body",
                "transfer-encoding: chunked",
            ],
            Kind::Settings | Kind::RapidReset => &[],
        }
    }

    fn meta(self) -> CheckMeta {
        let (id, name, class, technique, severity, confidence_max, cwe, description, remediation) =
            match self {
                Kind::Settings => (
                    "h2-settings-observe",
                    "HTTP/2 SETTINGS observation",
                    "h2-settings",
                    Technique::Observe,
                    Severity::Info,
                    Confidence::Certain,
                    None,
                    "Opens one HTTP/2 connection and records the SETTINGS the server \
                     advertises (concurrency, window and header-list limits).",
                    "None required; review the advertised limits against the deployment's \
                     intent.",
                ),
                Kind::PseudoHeader => (
                    "h2-pseudo-header-validation",
                    "HTTP/2 pseudo-header validation",
                    "h2-pseudo-header",
                    Technique::Malformed,
                    Severity::Info,
                    Confidence::Tentative,
                    Some(444),
                    "Sends three malformed header blocks (a missing :path, a duplicated \
                     :method, a pseudo-header after a regular header) on one HTTP/2 \
                     connection and reports a variant the server answered instead of \
                     rejecting (RFC 9113 section 8.3).",
                    "Reject requests with a malformed pseudo-header set with a stream error \
                     of type PROTOCOL_ERROR before they reach the application.",
                ),
                Kind::HeaderCrlf => (
                    "h2-header-crlf-tolerance",
                    "HTTP/2 header CRLF tolerance",
                    "h2-header-crlf",
                    Technique::Malformed,
                    Severity::Info,
                    Confidence::Tentative,
                    Some(113),
                    "Sends a CR LF inside a header value and inside a header name on one \
                     HTTP/2 connection and reports a variant the server answered instead \
                     of rejecting (RFC 9113 section 8.2.1).",
                    "Treat a header field containing CR or LF as malformed and reset the \
                     stream; never forward it to an HTTP/1.1 backend.",
                ),
                Kind::ClTe => (
                    "h2-cl-te-downgrade-indicator",
                    "HTTP/2 length and encoding downgrade indicator",
                    "h2-smuggling-indicator",
                    Technique::Observe,
                    Severity::Info,
                    Confidence::Tentative,
                    Some(444),
                    "Sends a content-length one byte longer than the body, and separately a \
                     transfer-encoding header, on one HTTP/2 connection and reports a \
                     variant the server answered instead of rejecting. Indicator only: it \
                     never sends a second request.",
                    "Reject HTTP/2 requests whose content-length disagrees with the body or \
                     that carry transfer-encoding (RFC 9113 sections 8.1.1 and 8.2.2).",
                ),
                Kind::RapidReset => (
                    "h2-rapid-reset-mitigation",
                    "HTTP/2 rapid-reset mitigation",
                    "h2-rapid-reset",
                    Technique::Observe,
                    Severity::Info,
                    Confidence::Firm,
                    Some(400),
                    "Opens and immediately cancels eight streams on one connection, once, \
                     and reports whether the server showed any reset-rate mitigation (a \
                     GOAWAY or a refused stream). It is a bounded probe, not a flood.",
                    "Apply a reset-rate limit per connection and close abusive connections \
                     with GOAWAY (CVE-2023-44487).",
                ),
            };
        CheckMeta {
            id: id.to_string(),
            name: name.to_string(),
            class: class.to_string(),
            lanes: vec![LaneKind::Http],
            kinds: vec![
                InsertionKind::Query,
                InsertionKind::BodyParam,
                InsertionKind::Header,
                InsertionKind::Cookie,
                InsertionKind::PathSegment,
            ],
            intensity: Intensity::Medium,
            cost: CheckCost::Light,
            technique,
            severity,
            confidence_max,
            needs_baseline: true,
            wants_traits: None,
            targets_session: false,
            cwe,
            description: description.to_string(),
            remediation: Some(remediation.to_string()),
            origin: CheckOrigin::Native,
        }
    }
}

/// Authorities already probed by one check instance, each with when.
struct OncePerAuthority {
    seen: Mutex<HashMap<String, Instant>>,
}

impl OncePerAuthority {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `key` was claimed less than [`GUARD_TTL`] before `now`.
    fn seen(&self, key: &str, now: Instant) -> bool {
        let map = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        map.get(key)
            .is_some_and(|at| now.saturating_duration_since(*at) < GUARD_TTL)
    }

    /// Claim `key` at `now`. True when this call made the claim; false when a
    /// live claim already existed.
    fn claim(&self, key: &str, now: Instant) -> bool {
        let mut map = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if map
            .get(key)
            .is_some_and(|at| now.saturating_duration_since(*at) < GUARD_TTL)
        {
            return false;
        }
        map.retain(|_, at| now.saturating_duration_since(*at) < GUARD_TTL);
        if map.len() >= GUARD_CAP {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
        map.insert(key.to_string(), now);
        true
    }
}

/// One of the five checks.
struct H2Check {
    kind: Kind,
    meta: CheckMeta,
    runner: Arc<dyn RawH2Runner>,
    guard: OncePerAuthority,
}

impl H2Check {
    fn new(kind: Kind, runner: Arc<dyn RawH2Runner>) -> Self {
        Self {
            kind,
            meta: kind.meta(),
            runner,
            guard: OncePerAuthority::new(),
        }
    }

    /// The plan this check sends to `target`, requesting `path`.
    fn plan(&self, target: &Target) -> RawH2Plan {
        let base = |extra: Option<RawHeader>| -> Vec<RawHeader> {
            let mut headers = vec![
                RawHeader::new(":method", "GET"),
                RawHeader::new(":scheme", &target.scheme),
                RawHeader::new(":authority", &target.authority),
                RawHeader::new(":path", &target.path),
            ];
            headers.extend(extra);
            headers
        };
        let (headers, mode, streams) = match self.kind {
            Kind::Settings => (Vec::new(), RawH2Mode::SettingsOnly, 0),
            Kind::RapidReset => (
                base(None),
                RawH2Mode::RapidReset { pairs: RESET_PAIRS },
                RESET_PAIRS,
            ),
            Kind::PseudoHeader => {
                let mut no_path = base(None);
                no_path.pop();
                let mut two_methods = base(None);
                two_methods.insert(1, RawHeader::new(":method", "GET"));
                let mut late_pseudo = base(None);
                let path = late_pseudo.pop();
                late_pseudo.push(RawHeader::new(PROBE_FIELD, "1"));
                late_pseudo.extend(path);
                (
                    Vec::new(),
                    RawH2Mode::Blocks(vec![no_path, two_methods, late_pseudo]),
                    3,
                )
            }
            Kind::HeaderCrlf => {
                let value = base(Some(RawHeader::raw(
                    PROBE_FIELD.as_bytes(),
                    b"a\r\nx-aitm-injected: 1",
                )));
                let name = base(Some(RawHeader::raw(
                    b"x-aitm-probe\r\nx-aitm-injected",
                    b"1",
                )));
                (Vec::new(), RawH2Mode::Blocks(vec![value, name]), 2)
            }
            Kind::ClTe => {
                // The probe's body is empty, so "real + 1" is one.
                let length = base(Some(RawHeader::new("content-length", "1")));
                let encoding = base(Some(RawHeader::new("transfer-encoding", "chunked")));
                (Vec::new(), RawH2Mode::Blocks(vec![length, encoding]), 2)
            }
        };
        RawH2Plan {
            target: RawH2Target {
                scheme: target.scheme.clone(),
                authority: target.authority.clone(),
            },
            headers,
            mode,
            streams,
        }
    }

    /// Turn what the driver saw into this check's verdict.
    fn verdict(&self, obs: &RawH2Observation) -> Verdict {
        match self.kind {
            Kind::Settings => settings_verdict(obs),
            Kind::RapidReset => rapid_reset_verdict(obs),
            Kind::PseudoHeader | Kind::HeaderCrlf | Kind::ClTe => {
                malformed_verdict(self.kind.variant_labels(), obs)
            }
        }
    }
}

impl Check for H2Check {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let Some(target) = point.url.as_deref().and_then(Target::parse) else {
                return inconclusive("the point has no usable http(s) url");
            };
            if !may_send(host) {
                return inconclusive(STOPPED);
            }
            let key = format!("{}://{}", target.scheme, target.authority);
            if self.guard.seen(&key, Instant::now()) {
                return inconclusive(ALREADY_OBSERVED);
            }
            // The scope gate: the guarded job client must reach this authority
            // before a single raw byte is written.
            if host.baseline().await.is_err() {
                return inconclusive("baseline refused; not probing");
            }
            if host.cancelled() || Instant::now() >= host.deadline() {
                return inconclusive(STOPPED);
            }
            // Claimed only now, so a refused baseline does not burn the
            // authority; atomic, so two concurrent points open one connection.
            if !self.guard.claim(&key, Instant::now()) {
                return inconclusive(ALREADY_OBSERVED);
            }
            match self.runner.run(self.plan(&target)).await {
                Ok(obs) => self.verdict(&obs),
                Err(error) => {
                    tracing::debug!(%error, check = %self.meta.id, "raw h2 probe did not complete");
                    inconclusive(NO_H2)
                }
            }
        })
    }
}

const STOPPED: &str = "stopped: the job was cancelled, out of budget or past its deadline";
const ALREADY_OBSERVED: &str = "already observed for this authority";

/// Whether the check may send another request right now (copy of the gate
/// `xss.rs` keeps; folding both into one helper is a later round).
fn may_send(host: &dyn ProbeHost) -> bool {
    !host.cancelled() && host.budget_left() > 0 && Instant::now() < host.deadline()
}

/// Where a raw probe goes, cut from a point's URL.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    /// `http` or `https`, lower-cased.
    scheme: String,
    /// `host[:port]`, lower-cased, userinfo dropped.
    authority: String,
    /// The request path without its query, or `/`.
    path: String,
}

impl Target {
    fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, after) = rest.split_at(end);
        // Userinfo is credential material; it never reaches the wire.
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
            .to_ascii_lowercase();
        let host_ok = !authority.is_empty()
            && authority.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
            });
        if !host_ok {
            return None;
        }
        let path = after.split(['?', '#']).next().unwrap_or("");
        let path = if path.starts_with('/') && path.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            path.to_string()
        } else {
            "/".to_string()
        };
        Some(Self {
            scheme,
            authority,
            path,
        })
    }
}

fn inconclusive(detail: &str) -> Verdict {
    no_finding(Outcome::Inconclusive, detail)
}

/// A verdict that concluded nothing, with no evidence and no hint.
fn no_finding(outcome: Outcome, detail: &str) -> Verdict {
    Verdict {
        outcome,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail: detail.to_string(),
        poc_hint: None,
    }
}

/// The name of a SETTINGS identifier (RFC 9113 section 6.5.2, RFC 8441).
fn setting_name(id: u16) -> String {
    match id {
        1 => "header_table_size".to_string(),
        2 => "enable_push".to_string(),
        3 => "max_concurrent_streams".to_string(),
        4 => "initial_window_size".to_string(),
        5 => "max_frame_size".to_string(),
        6 => "max_header_list_size".to_string(),
        8 => "enable_connect_protocol".to_string(),
        other => format!("setting_{other}"),
    }
}

fn settings_verdict(obs: &RawH2Observation) -> Verdict {
    if obs.settings.is_empty() {
        return no_finding(Outcome::Clean, "the peer sent no SETTINGS frame");
    }
    let listed = obs
        .settings
        .iter()
        .map(|(id, value)| format!("{}={value}", setting_name(*id)))
        .collect::<Vec<_>>()
        .join(", ");
    let listed = Evidence::excerpt(&crate::matching::scrub(&listed));
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Certain,
        evidence: Evidence {
            matched: Some(listed.clone()),
            ..Evidence::default()
        },
        detail: format!("the peer advertised SETTINGS: {listed}"),
        poc_hint: None,
    }
}

fn rapid_reset_verdict(obs: &RawH2Observation) -> Verdict {
    if let Some((last_stream, code)) = obs.goaway {
        return no_finding(
            Outcome::Clean,
            &format!(
                "the peer sent GOAWAY(last_stream_id={last_stream}, error_code={code}) during \
                 {RESET_PAIRS} reset pairs"
            ),
        );
    }
    if obs.streams.contains(&StreamOutcome::Refused) {
        return no_finding(
            Outcome::Clean,
            &format!("the peer refused a stream during {RESET_PAIRS} reset pairs"),
        );
    }
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Tentative,
        evidence: Evidence {
            matched: Some(format!(
                "{RESET_PAIRS} reset pairs, no GOAWAY, no refused stream"
            )),
            ..Evidence::default()
        },
        detail: format!("no reset-rate mitigation observed in {RESET_PAIRS} reset pairs"),
        poc_hint: None,
    }
}

/// What a malformed variant's stream outcome means.
enum Reading {
    /// The server rejected it: reset, refused, or an error status.
    Rejected,
    /// The server answered it as if nothing were wrong.
    Tolerated(String),
    /// Nothing came back.
    Unobserved,
}

fn read_stream(outcome: &StreamOutcome) -> Reading {
    match outcome {
        StreamOutcome::Reset { .. } | StreamOutcome::Refused => Reading::Rejected,
        StreamOutcome::Timeout => Reading::Unobserved,
        StreamOutcome::Headers { status: None } => {
            Reading::Tolerated("an unreadable status".to_string())
        }
        StreamOutcome::Headers { status: Some(s) } if (200..400).contains(s) => {
            Reading::Tolerated(format!("status {s}"))
        }
        StreamOutcome::Headers { status: Some(_) } => Reading::Rejected,
    }
}

/// The shared rule of the three malformed-header checks.
fn malformed_verdict(labels: &[&str], obs: &RawH2Observation) -> Verdict {
    let mut tolerated = Vec::new();
    let mut unobserved = labels.len().saturating_sub(obs.streams.len());
    for (index, outcome) in obs.streams.iter().enumerate().take(labels.len()) {
        match read_stream(outcome) {
            Reading::Rejected => {}
            Reading::Unobserved => unobserved += 1,
            Reading::Tolerated(how) => tolerated.push((index, how)),
        }
    }
    if !tolerated.is_empty() {
        let detail = tolerated
            .iter()
            .map(|(i, how)| {
                format!(
                    "variant {i} ({}) was answered with {how} instead of being rejected",
                    labels[*i]
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let matched = tolerated
            .iter()
            .map(|(i, _)| format!("variant {i}: {}", labels[*i]))
            .collect::<Vec<_>>()
            .join("; ");
        return Verdict {
            outcome: Outcome::Vulnerable,
            confidence: Confidence::Tentative,
            evidence: Evidence {
                matched: Some(Evidence::excerpt(&crate::matching::scrub(&matched))),
                ..Evidence::default()
            },
            detail,
            poc_hint: None,
        };
    }
    if unobserved > 0 {
        return inconclusive(&format!(
            "{unobserved} of {} variants did not reach an outcome before the probe stopped",
            labels.len()
        ));
    }
    no_finding(
        Outcome::Clean,
        &format!("all {} variants were rejected", labels.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::{OncePerAuthority, Target, GUARD_TTL};
    use std::time::{Duration, Instant};

    #[test]
    fn a_claim_expires_after_the_ttl_and_not_before() {
        let guard = OncePerAuthority::new();
        let t0 = Instant::now();

        assert!(guard.claim("https://origin.test", t0));
        assert!(!guard.claim(
            "https://origin.test",
            t0 + GUARD_TTL - Duration::from_secs(1)
        ));
        assert!(guard.seen(
            "https://origin.test",
            t0 + GUARD_TTL - Duration::from_secs(1)
        ));
        assert!(!guard.seen("https://origin.test", t0 + GUARD_TTL));
        assert!(guard.claim("https://origin.test", t0 + GUARD_TTL));
    }

    #[test]
    fn the_guard_is_bounded() {
        let guard = OncePerAuthority::new();
        let t0 = Instant::now();
        for i in 0..2000u64 {
            guard.claim(&format!("https://h{i}.test"), t0 + Duration::from_millis(i));
        }
        let len = guard.seen.lock().unwrap().len();
        assert_eq!(len, super::GUARD_CAP);
    }

    #[test]
    fn target_parse_cuts_scheme_authority_and_path() {
        let t = Target::parse("https://origin.test/x?y=1").unwrap();
        assert_eq!(
            (t.scheme.as_str(), t.authority.as_str(), t.path.as_str()),
            ("https", "origin.test", "/x")
        );
    }
}
