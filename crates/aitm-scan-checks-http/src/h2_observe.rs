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
//! | `h2-header-crlf-tolerance` | `h2-header-crlf` | `Blocks` | 2 | a CR/LF variant the server answered, as a `Medium` |
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
//!    (derived from `point.url`, userinfo dropped), **and that authority is one
//!    of the profile's own `target.origins`** (compared in one canonical form:
//!    lower-case host, the scheme's default port filled in), and to no other;
//! 2. it is opened only **after `host.baseline()` succeeded** through the
//!    guarded job client, so the scope gate has already cleared that authority;
//! 3. **no cookie, authorization or session header** is ever sent: a plan holds
//!    only pseudo-headers plus the one field under test, and the driver itself
//!    refuses `cookie`, `authorization`, `proxy-authorization` and `set-cookie`;
//! 4. the probe is **observe-only**: its result is a note about the server's h2
//!    behaviour, not a trust decision, and nothing it reads is replayed.
//!
//! # What the raw probe costs the job
//!
//! The streams a raw probe opens are requests the job made, but they do not
//! go through [`ProbeHost`] and nothing charges them: the trait has no
//! `charge`, so a check cannot spend the job's budget on them and the job's
//! pacing does not apply to them. Until the engine grows that hook (raised
//! with the coordinator as a T1b follow-up, plan amendment A5 item T3-6,
//! which replaces this with `host.charge(streams.max(1))`), each check does
//! the one thing it can from this side: it refuses to open a connection the
//! remaining budget could not have paid for, one unit per stream.
//!
//! # One connection per authority
//!
//! The scheduler runs a check once per insertion point, but these are
//! properties of an origin (spec gap G1). Each check instance therefore keeps a
//! ten-minute once-per-authority guard: the first point of an authority probes,
//! later points return [`Outcome::Inconclusive`] and send nothing at all.

use std::borrow::Cow;
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
    /// A runner over [`RawH2Client`] with `TlsVerify::AcceptAny`, gated by
    /// `ssrf` and `guard`.
    ///
    /// This is the **only** constructor: the driver checks both against every
    /// address the target's name resolves to, immediately before it dials, so
    /// a short-TTL record that flipped after the point cleared the lane's own
    /// client cannot steer an accept-any probe at an internal address. A
    /// runner that could skip that check would be a caller's mistake away
    /// from an ungated raw socket, so there is none (coordinator decision of
    /// 2026-11-01, option A).
    #[must_use]
    pub fn with_ssrf(
        ssrf: aitm_core::SsrfPolicy,
        guard: Arc<dyn aitm_core::ScopeRateGuard>,
    ) -> Self {
        Self {
            client: RawH2Client::new(TlsVerify::AcceptAny).with_ssrf(ssrf, guard),
        }
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
        let spec = self.spec();
        CheckMeta {
            id: spec.id.to_string(),
            name: spec.name.to_string(),
            class: spec.class.to_string(),
            lanes: vec![LaneKind::Http],
            kinds: vec![
                InsertionKind::Query,
                InsertionKind::BodyParam,
                InsertionKind::Header,
                InsertionKind::Cookie,
                InsertionKind::PathSegment,
            ],
            intensity: Intensity::Medium,
            cost: spec.cost,
            technique: spec.technique,
            severity: spec.severity,
            confidence_max: spec.confidence_max,
            needs_baseline: true,
            wants_traits: None,
            targets_session: false,
            cwe: spec.cwe,
            description: spec.description.to_string(),
            remediation: Some(spec.remediation.to_string()),
            origin: CheckOrigin::Native,
        }
    }

    /// This kind's catalogue entry, one named field at a time (review finding
    /// Q-M7: a nine-field positional tuple is unreadable and mis-orderable).
    fn spec(self) -> KindSpec {
        match self {
            Kind::Settings => KindSpec {
                id: "h2-settings-observe",
                name: "HTTP/2 SETTINGS observation",
                class: "h2-settings",
                technique: Technique::Observe,
                // Zero streams: the connection preface is the whole probe.
                cost: CheckCost::Light,
                severity: Severity::Info,
                // Observe is never `certain`: what a server advertises is not
                // a reflected or handshake proof (spec D2, review SP-1).
                confidence_max: Confidence::Firm,
                cwe: None,
                description: "Opens one HTTP/2 connection and records the SETTINGS the server \
                              advertises (concurrency, window and header-list limits).",
                remediation: "None required; review the advertised limits against the \
                              deployment's intent.",
            },
            Kind::PseudoHeader => KindSpec {
                id: "h2-pseudo-header-validation",
                name: "HTTP/2 pseudo-header validation",
                class: "h2-pseudo-header",
                technique: Technique::Malformed,
                cost: CheckCost::Light,
                severity: Severity::Info,
                confidence_max: Confidence::Tentative,
                cwe: Some(444),
                description: "Sends three malformed header blocks (a missing :path, a \
                              duplicated :method, a pseudo-header after a regular header) on \
                              one HTTP/2 connection and reports a variant the server answered \
                              instead of rejecting (RFC 9113 section 8.3).",
                remediation: "Reject requests with a malformed pseudo-header set with a \
                              stream error of type PROTOCOL_ERROR before they reach the \
                              application.",
            },
            Kind::HeaderCrlf => KindSpec {
                id: "h2-header-crlf-tolerance",
                name: "HTTP/2 header CRLF tolerance",
                class: "h2-header-crlf",
                technique: Technique::Malformed,
                cost: CheckCost::Light,
                // A CR or LF the origin accepted inside a header is what an
                // HTTP/1.1 backend downstream turns into a second request
                // (review finding C5), so this is not a note.
                severity: Severity::Medium,
                confidence_max: Confidence::Tentative,
                cwe: Some(113),
                description: "Sends a CR LF inside a header value and inside a header name on \
                              one HTTP/2 connection and reports a variant the server answered \
                              instead of rejecting (RFC 9113 section 8.2.1).",
                remediation: "Treat a header field containing CR or LF as malformed and reset \
                              the stream; never forward it to an HTTP/1.1 backend.",
            },
            Kind::ClTe => KindSpec {
                id: "h2-cl-te-downgrade-indicator",
                name: "HTTP/2 length and encoding downgrade indicator",
                class: "h2-smuggling-indicator",
                technique: Technique::Observe,
                cost: CheckCost::Light,
                severity: Severity::Info,
                confidence_max: Confidence::Tentative,
                cwe: Some(444),
                description: "Sends a content-length one byte longer than the body, and \
                              separately a transfer-encoding header, on one HTTP/2 connection \
                              and reports a variant the server answered instead of rejecting. \
                              Indicator only: it never sends a second request.",
                remediation: "Reject HTTP/2 requests whose content-length disagrees with the \
                              body or that carry transfer-encoding (RFC 9113 sections 8.1.1 \
                              and 8.2.2).",
            },
            Kind::RapidReset => KindSpec {
                id: "h2-rapid-reset-mitigation",
                name: "HTTP/2 rapid-reset mitigation",
                class: "h2-rapid-reset",
                technique: Technique::Observe,
                // Eight streams on one connection is not a light probe
                // (review SP-2); it is still bounded, and still sent once.
                cost: CheckCost::Medium,
                severity: Severity::Info,
                confidence_max: Confidence::Firm,
                cwe: Some(400),
                description: "Opens and immediately cancels eight streams on one connection, \
                              once, and reports whether the server showed any reset-rate \
                              mitigation (a GOAWAY, a refused stream or a closed \
                              connection). It is a bounded \
                              probe, not a flood.",
                remediation: "Apply a reset-rate limit per connection and close abusive \
                              connections with GOAWAY (CVE-2023-44487).",
            },
        }
    }
}

/// One kind's catalogue entry, before it becomes a [`CheckMeta`].
///
/// Everything the five checks share — the lanes, the insertion kinds, the
/// intensity, `needs_baseline`, the origin — lives in [`Kind::meta`]; this is
/// only what differs between them.
struct KindSpec {
    id: &'static str,
    name: &'static str,
    class: &'static str,
    technique: Technique,
    cost: CheckCost,
    severity: Severity,
    confidence_max: Confidence,
    cwe: Option<u32>,
    description: &'static str,
    remediation: &'static str,
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
                RawHeader::new(":authority", &target.wire_authority()),
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
                authority: target.wire_authority(),
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
            if !crate::gate::may_send(host, 1) {
                return inconclusive(STOPPED);
            }
            // The profile gate, before anything at all is sent: a raw probe
            // bypasses the lane's guarded client, so the authority it would
            // dial must be one the operator named in the job's profile.
            if !target.is_a_profile_origin(&host.profile().target.origins) {
                return inconclusive(NOT_A_PROFILE_ORIGIN);
            }
            let key = target.origin_key();
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
            // The raw connection cannot charge the job — `ProbeHost` has no
            // `charge` — so the check refuses to open one the budget could not
            // have paid for, counting one unit per stream the plan will open
            // (security review SEC-C2; see the module header).
            let plan = self.plan(&target);
            if host.budget_left() < u32::from(plan.streams).max(1) {
                return inconclusive(BUDGET_TOO_LOW);
            }
            // Claimed only now, so a refused baseline does not burn the
            // authority; atomic, so two concurrent points open one connection.
            if !self.guard.claim(&key, Instant::now()) {
                return inconclusive(ALREADY_OBSERVED);
            }
            match self.runner.run(plan).await {
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
const NOT_A_PROFILE_ORIGIN: &str = "raw probe target is not a profile origin";
const BUDGET_TOO_LOW: &str = "budget too low for the raw probe";

/// Where a raw probe goes, cut from a point's URL by [`crate::url`].
#[derive(Debug, PartialEq, Eq)]
struct Target {
    /// The point's authority, parsed once: lower-case host, the port as the
    /// URL wrote it, userinfo dropped.
    authority: crate::url::Authority,
    /// `http` or `https`, lower-cased.
    scheme: String,
    /// The request path without its query, or `/`.
    path: String,
}

impl Target {
    /// The target of a point's URL, or `None` when the URL names no authority
    /// this driver can dial. Only `http` and `https` are dialable.
    fn parse(url: &str) -> Option<Self> {
        let (authority, rest) = crate::url::split_url(url)?;
        let scheme = authority.scheme.clone()?;
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let path = rest.split(['?', '#']).next().unwrap_or("");
        let path = if path.starts_with('/') && path.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            path.to_string()
        } else {
            "/".to_string()
        };
        Some(Self {
            authority,
            scheme,
            path,
        })
    }

    /// `host[:port]` as a client writes it: the form that goes in the
    /// `:authority` pseudo-header and in [`RawH2Target`], with the scheme's
    /// default port left out as every HTTP client leaves it out.
    fn wire_authority(&self) -> String {
        self.authority.as_written()
    }

    /// The canonical `scheme://host:port`. Both the profile-origin gate and
    /// the once-per-authority guard key on this one string, so two spellings
    /// of one origin can never be compared as two (security review SEC-C3).
    fn origin_key(&self) -> String {
        self.authority
            .origin_key()
            .unwrap_or_else(|| format!("{}://{}", self.scheme, self.authority.as_written()))
    }

    /// Whether the job's profile names this origin.
    ///
    /// The raw probe does not go through the lane's guarded client, so this is
    /// the check that keeps it inside what the operator asked for: the
    /// authority about to be dialled must be one of
    /// `profile.target.origins`, compared in the canonical form above. An
    /// origin the profile wrote without a scheme names no origin and
    /// authorises nothing (interim gate for sender finding SEC-1, item C6).
    fn is_a_profile_origin(&self, origins: &[String]) -> bool {
        let key = self.origin_key();
        origins
            .iter()
            .filter_map(|origin| crate::url::authority_of(origin))
            .filter_map(|origin| origin.origin_key())
            .any(|origin| origin == key)
    }
}

fn inconclusive(detail: &str) -> Verdict {
    no_finding(Outcome::Inconclusive, detail)
}

/// A verdict that concluded nothing, with no evidence and no hint.
fn no_finding(outcome: Outcome, detail: &str) -> Verdict {
    crate::gate::no_finding(outcome, Confidence::Tentative, detail.to_string())
}

/// The name of a SETTINGS identifier (RFC 9113 section 6.5.2, RFC 8441).
///
/// Borrowed for every identifier the RFCs name; only an unknown one allocates.
fn setting_name(id: u16) -> Cow<'static, str> {
    match id {
        1 => Cow::Borrowed("header_table_size"),
        2 => Cow::Borrowed("enable_push"),
        3 => Cow::Borrowed("max_concurrent_streams"),
        4 => Cow::Borrowed("initial_window_size"),
        5 => Cow::Borrowed("max_frame_size"),
        6 => Cow::Borrowed("max_header_list_size"),
        8 => Cow::Borrowed("enable_connect_protocol"),
        other => Cow::Owned(format!("setting_{other}")),
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
        // Never `certain`: this is what the peer *said* it would do, read
        // once, not a behaviour the probe reproduced (spec D2, review SP-1).
        confidence: Confidence::Firm,
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
    // A reset or an answer is an observed outcome for the pair; a timeout is
    // not. Only the observed ones count towards the complete series.
    let observed = obs
        .streams
        .iter()
        .filter(|outcome| !matches!(outcome, StreamOutcome::Timeout))
        .count();
    // The peer dropped the connection on the resets without saying why: the
    // bluntest reset-rate mitigation there is, and the check's whole question
    // answered (tester finding T2-2). Before the series check, because a drop
    // is usually what cuts the series short.
    if obs.connection_closed {
        return no_finding(
            Outcome::Clean,
            &format!(
                "the peer closed the connection without a GOAWAY after {observed} of \
                 {RESET_PAIRS} reset pairs"
            ),
        );
    }
    // Fewer than eight observed pairs is not the "complete repeated
    // observation" the `firm` verdict below stands on (spec review SP-3).
    if observed < usize::from(RESET_PAIRS) {
        return inconclusive(&format!(
            "only {observed} of {RESET_PAIRS} reset pairs reached an outcome before the probe \
             stopped"
        ));
    }
    Verdict {
        outcome: Outcome::Vulnerable,
        // A complete repeated observation — all eight pairs sent, every one
        // answered or reset, nothing at all from the peer and the connection
        // still open — so the meta's `firm` ceiling is reachable (review
        // SP-3). It is still not `certain`: a mitigation could exist above
        // this threshold.
        confidence: Confidence::Firm,
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
        let t = Target::parse("https://origin.test/x?y=1").expect("a usable url");
        assert_eq!(t.scheme, "https");
        assert_eq!(t.wire_authority(), "origin.test");
        assert_eq!(t.path, "/x");
        assert_eq!(t.origin_key(), "https://origin.test:443");
    }

    /// The gate compares canonical origins, so every spelling of the one
    /// origin matches and a different scheme, host or port does not.
    #[test]
    fn the_profile_gate_matches_one_canonical_origin() {
        let target = Target::parse("https://origin.test:443/x").expect("a usable url");

        for origin in [
            "https://origin.test",
            "https://ORIGIN.test",
            "https://origin.test:443",
            "https://origin.test/ignored/path",
        ] {
            assert!(
                target.is_a_profile_origin(&[origin.to_string()]),
                "{origin} should authorise the probe"
            );
        }
        for origin in [
            "http://origin.test",
            "https://other.test",
            "https://origin.test:8443",
            "origin.test",
            "*.origin.test",
            "",
        ] {
            assert!(
                !target.is_a_profile_origin(&[origin.to_string()]),
                "{origin} must not authorise the probe"
            );
        }
        assert!(
            !target.is_a_profile_origin(&[]),
            "an empty origin list authorises nothing"
        );
    }
}
