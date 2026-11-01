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
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, HttpVersionPolicy,
    InsertionKind, InsertionPoint, Intensity, LaneKind, Outcome, ProbeHost, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::gate::{no_finding, STOPPED};

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
///
/// # What the gate it carries does, and does not do
///
/// The SSRF gate [`Self::with_ssrf`] installs is checked against **every
/// address** the target's name resolves to, immediately before the dial. It
/// refuses private, loopback and metadata addresses under the job's
/// `SsrfPolicy`, exactly as the reissue path's gate does. It does **not**
/// confine the probe to the job's scope (`confine_to_scope = false`, the
/// reissue path's posture: scope-confined egress is a browser-only rule).
/// Condition 1 of this module's documentation — the raw connection goes to
/// the point's own authority, and that authority is one of the profile's
/// `target.origins` — is enforced by `H2Check::run` before it hands a plan
/// to the runner, not by the runner itself; a caller that builds a plan by
/// hand gets the address gate and nothing more (security review FS-3).
///
/// Public because the integration tests build one to prove it refuses
/// session material before dialling; the catalogue builds it only inside
/// [`crate::checks_with`].
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
///
/// The contract between the checks and the runner: each check's
/// `H2Check::run` enforces, before it hands the runner a plan, that the
/// target is the point's own authority **and a profile origin** (condition 1
/// of the module documentation), that `host.baseline()` succeeded through
/// the scope-guarded job client (condition 2), and that the plan carries no
/// session header (condition 3). The runner adds only the address gate it
/// carries — [`RealRawH2Runner`] refuses private, loopback and metadata
/// addresses and does not confine to scope — so a runner that is handed a
/// plan by anything other than these checks has not had conditions 1 to 3
/// applied. Public because the tests script a fake runner through it; the
/// catalogue calls it only from [`crate::checks_with`] (security review
/// FS-3).
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
    /// The malformed variants a `Blocks` check sends to `target`, in stream
    /// order, each paired with the label its verdict names it by.
    ///
    /// One list, so the label at index `i` can only ever describe the block
    /// at index `i`: [`H2Check::plan`] takes the blocks from it and
    /// [`malformed_verdict`] the labels (quality re-review Q2-4). The two
    /// stream-less kinds have no variants.
    fn variants(self, target: &Target) -> Vec<(&'static str, Vec<RawHeader>)> {
        match self {
            Kind::PseudoHeader => {
                let mut no_path = target.base_headers(None);
                no_path.pop();
                let mut two_methods = target.base_headers(None);
                two_methods.insert(1, RawHeader::new(":method", "GET"));
                let mut late_pseudo = target.base_headers(None);
                let path = late_pseudo.pop();
                late_pseudo.push(RawHeader::new(PROBE_FIELD, "1"));
                late_pseudo.extend(path);
                vec![
                    ("missing :path", no_path),
                    ("duplicate :method", two_methods),
                    ("pseudo-header after a regular header", late_pseudo),
                ]
            }
            Kind::HeaderCrlf => vec![
                (
                    "CRLF in a header value",
                    target.base_headers(Some(RawHeader::raw(
                        PROBE_FIELD.as_bytes(),
                        b"a\r\nx-aitm-injected: 1",
                    ))),
                ),
                (
                    "CRLF in a header name",
                    target.base_headers(Some(RawHeader::raw(
                        b"x-aitm-probe\r\nx-aitm-injected",
                        b"1",
                    ))),
                ),
            ],
            Kind::ClTe => vec![
                (
                    // The probe's body is empty, so "real + 1" is one.
                    "content-length one byte longer than the body",
                    target.base_headers(Some(RawHeader::new("content-length", "1"))),
                ),
                (
                    "transfer-encoding: chunked",
                    target.base_headers(Some(RawHeader::new("transfer-encoding", "chunked"))),
                ),
            ],
            Kind::Settings | Kind::RapidReset => Vec::new(),
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
            // Every h2 check here probes the origin's connection once, never an
            // insertion point: the malformed-header kinds send their variants
            // on streams of that one connection too, and `OncePerAuthority`
            // refuses a second connection to the same origin within its window.
            // Origin scope says so to the scheduler, which then runs each check
            // once per origin rather than once per point (coordinator decision 3;
            // the T3-3 oracle counts exactly one connection per check).
            scope: aitm_scan_model::CheckScope::Origin,
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

    /// The plan this check sends to `target`, with the labels its verdict
    /// will quote for a `Blocks` plan (empty for the other two modes).
    fn plan(&self, target: &Target) -> Planned {
        let (headers, mode, streams, labels) = match self.kind {
            Kind::Settings => (Vec::new(), RawH2Mode::SettingsOnly, 0, Vec::new()),
            Kind::RapidReset => (
                target.base_headers(None),
                RawH2Mode::RapidReset { pairs: RESET_PAIRS },
                RESET_PAIRS,
                Vec::new(),
            ),
            Kind::PseudoHeader | Kind::HeaderCrlf | Kind::ClTe => {
                let (labels, blocks): (Vec<_>, Vec<_>) =
                    self.kind.variants(target).into_iter().unzip();
                // At most three blocks; the driver's cap is the only bound
                // that could ever be lower.
                let streams = u8::try_from(blocks.len()).unwrap_or(MAX_RAW_STREAMS);
                (Vec::new(), RawH2Mode::Blocks(blocks), streams, labels)
            }
        };
        Planned {
            plan: RawH2Plan {
                target: RawH2Target {
                    scheme: target.scheme.clone(),
                    authority: target.wire_authority.clone(),
                },
                headers,
                mode,
                streams,
            },
            labels,
        }
    }

    /// Turn what the driver saw into this check's verdict; `labels` are the
    /// ones [`Self::plan`] handed back for the plan that produced `obs`.
    fn verdict(&self, labels: &[&str], obs: &RawH2Observation) -> Verdict {
        match self.kind {
            Kind::Settings => settings_verdict(obs),
            Kind::RapidReset => rapid_reset_verdict(obs),
            Kind::PseudoHeader | Kind::HeaderCrlf | Kind::ClTe => malformed_verdict(labels, obs),
        }
    }
}

/// What [`H2Check::plan`] builds: the plan for the driver and, for a `Blocks`
/// plan, the label of each block in stream order, for the verdict.
struct Planned {
    plan: RawH2Plan,
    labels: Vec<&'static str>,
}

impl Check for H2Check {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    /// Nine gates stand between a point and the raw connection, in this
    /// order, and each one that fails returns `Inconclusive` with nothing
    /// sent:
    ///
    /// 1. **url** — the point's URL must name a dialable `http(s)` authority
    ///    ([`Target::parse`]);
    /// 2. **stop gate** — not cancelled, budget for at least one stimulus,
    ///    before the deadline ([`crate::gate::may_send`]);
    /// 3. **profile origin** — the authority is one of the profile's own
    ///    `target.origins`, compared canonically ([`Target::is_a_profile_origin`]);
    /// 4. **guard seen** — no live once-per-authority claim for this origin;
    /// 5. **baseline** — `host.baseline()` succeeds through the lane's guarded
    ///    client, so scope has cleared the authority before a raw byte moves;
    /// 6. **cancel/deadline re-check** — the baseline took time; a job that
    ///    stopped meanwhile sends nothing;
    /// 7. **budget** — the budget left covers one unit per stream the plan
    ///    will open (the raw connection cannot charge the job itself);
    /// 8. **guard claim** — the origin is claimed, atomically;
    /// 9. **dial** — the runner opens the one connection.
    ///
    /// `claim` is last because a claim lasts ten minutes and must not be
    /// burnt by a refused baseline, a stopped job or a short budget: an
    /// authority that was never actually probed stays probe-able. It is
    /// still before the dial, and atomic, so two points of one origin that
    /// race through gates 1–7 open one connection, not two.
    ///
    /// The re-check at 6 tests cancellation and the deadline but not the
    /// budget, because gate 7 immediately tests the budget against the
    /// plan's real stream count, which is at least the one unit gate 2
    /// asked for; a `budget_left() >= 1` clause there would be subsumed.
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
                return stopped();
            }
            // The profile forced HTTP/1.1 (spec D8.2 `http.version`): an HTTP/2
            // observe probe would contradict it, so none is sent. Found live
            // (T3-2 cell, 2026-11-01): these checks were the only h2 traffic
            // in a forced-h1 job.
            if matches!(host.profile().http.version, HttpVersionPolicy::H1) {
                return inconclusive(FORCED_H1);
            }
            // The profile gate, before anything at all is sent: a raw probe
            // bypasses the lane's guarded client, so the authority it would
            // dial must be one the operator named in the job's profile.
            if !target.is_a_profile_origin(&host.profile().target.origins) {
                return inconclusive(NOT_A_PROFILE_ORIGIN);
            }
            if self.guard.seen(&target.origin_key, Instant::now()) {
                return inconclusive(ALREADY_OBSERVED);
            }
            // The scope gate: the guarded job client must reach this authority
            // before a single raw byte is written.
            if host.baseline().await.is_err() {
                return inconclusive("baseline refused; not probing");
            }
            if host.cancelled() || Instant::now() >= host.deadline() {
                return stopped();
            }
            // The raw connection cannot charge the job — `ProbeHost` has no
            // `charge` — so the check refuses to open one the budget could not
            // have paid for, counting one unit per stream the plan will open
            // (security review SEC-C2; see the module header).
            let Planned { plan, labels } = self.plan(&target);
            if host.budget_left() < u32::from(plan.streams).max(1) {
                return inconclusive(BUDGET_TOO_LOW);
            }
            // Claimed only now, so a refused baseline does not burn the
            // authority; atomic, so two concurrent points open one connection.
            if !self.guard.claim(&target.origin_key, Instant::now()) {
                return inconclusive(ALREADY_OBSERVED);
            }
            match self.runner.run(plan).await {
                Ok(obs) => {
                    // Shape only: stream outcomes, GOAWAY codes and the two
                    // end flags. The observation carries no peer text.
                    tracing::debug!(
                        check = %self.meta.id,
                        streams = ?obs.streams,
                        goaway = ?obs.goaway,
                        closed = obs.connection_closed,
                        silent = obs.peer_silent,
                        "raw h2 observation"
                    );
                    self.verdict(&labels, &obs)
                }
                Err(error) => {
                    tracing::debug!(%error, check = %self.meta.id, "raw h2 probe did not complete");
                    inconclusive(NO_H2)
                }
            }
        })
    }
}

const ALREADY_OBSERVED: &str = "already observed for this authority";
const FORCED_H1: &str = "skipped: the profile forces http.version h1, so no HTTP/2 probe is sent";
const NOT_A_PROFILE_ORIGIN: &str = "raw probe target is not a profile origin";
const BUDGET_TOO_LOW: &str = "budget too low for the raw probe";

/// Where a raw probe goes, cut from a point's URL by [`crate::url`].
///
/// Everything here is a plain string computed once in [`Target::parse`],
/// which is the one place the URL's optional parts are handled: a `Target`
/// that exists has a scheme, a wire authority and a canonical origin, so no
/// accessor needs a fallback (quality re-review Q2-5).
#[derive(Debug)]
struct Target {
    /// `http` or `https`, lower-cased.
    scheme: String,
    /// `host[:port]` as a client writes it: the form that goes in the
    /// `:authority` pseudo-header and in [`RawH2Target`], with the scheme's
    /// default port left out as every HTTP client leaves it out; userinfo
    /// dropped, host lower-cased.
    wire_authority: String,
    /// The canonical `scheme://host:port`, the scheme's default port filled
    /// in. Both the profile-origin gate and the once-per-authority guard key
    /// on this one string, so two spellings of one origin can never be
    /// compared as two (security review SEC-C3).
    origin_key: String,
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
        // An absolute `http(s)` URL always has a canonical origin; the `?`
        // is for the type, not for a case this branch can reach.
        let origin_key = authority.origin_key()?;
        let path = rest.split(['?', '#']).next().unwrap_or("");
        let path = if path.starts_with('/') && path.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            path.to_string()
        } else {
            "/".to_string()
        };
        Some(Self {
            scheme,
            wire_authority: authority.as_written(),
            origin_key,
            path,
        })
    }

    /// The four pseudo-headers of a well-formed GET for this target, plus
    /// `extra` when a variant adds one field. Every block a check sends
    /// starts from this.
    fn base_headers(&self, extra: Option<RawHeader>) -> Vec<RawHeader> {
        let mut headers = vec![
            RawHeader::new(":method", "GET"),
            RawHeader::new(":scheme", &self.scheme),
            RawHeader::new(":authority", &self.wire_authority),
            RawHeader::new(":path", &self.path),
        ];
        headers.extend(extra);
        headers
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
        origins
            .iter()
            .filter_map(|origin| crate::url::authority_of(origin))
            .filter_map(|origin| origin.origin_key())
            .any(|origin| origin == self.origin_key)
    }
}

/// The verdict for a probe that was not sent, with nothing to show for it.
fn inconclusive(detail: impl Into<String>) -> Verdict {
    no_finding(Outcome::Inconclusive, detail)
}

/// The verdict for a run the job stopped before the probe: the shared stop
/// reason, prefixed so the detail reads as an event and not a cause.
fn stopped() -> Verdict {
    inconclusive(format!("stopped: {STOPPED}"))
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
        location: None,
        more: Vec::new(),
    }
}

fn rapid_reset_verdict(obs: &RawH2Observation) -> Verdict {
    if let Some((last_stream, code)) = obs.goaway {
        return no_finding(
            Outcome::Clean,
            format!(
                "the peer sent GOAWAY(last_stream_id={last_stream}, error_code={code}) during \
                 {RESET_PAIRS} reset pairs"
            ),
        );
    }
    if obs.streams.contains(&StreamOutcome::Refused) {
        return no_finding(
            Outcome::Clean,
            format!("the peer refused a stream during {RESET_PAIRS} reset pairs"),
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
    // is usually what cuts the series short. Only once at least one pair has
    // an outcome, though: a close before any was observed may be a close on
    // the preface, the SETTINGS or the first HEADERS, and says nothing about
    // resets (security review FS-2).
    if obs.connection_closed {
        if observed == 0 {
            return inconclusive("the peer closed before any reset pair was observed");
        }
        return no_finding(
            Outcome::Clean,
            format!(
                "the peer closed the connection without a GOAWAY after {observed} of \
                 {RESET_PAIRS} reset pairs"
            ),
        );
    }
    // The connection is still open after all eight pairs: no GOAWAY, no
    // refused stream, no hang-up. A correct server discards a cancelled
    // stream without a word, so the realistic shape of "no mitigation" is
    // eight pairs written and then silence (live run against hyper,
    // 2026-11-01); a server racing the cancel may answer or reset some of
    // them, which is no mitigation either. All eight pairs were written —
    // the batch mode writes every HEADERS before it reads, and a write
    // error is a probe error, not an observation — and the peer had the
    // whole read timeout to react, so this is the complete observation
    // the meta's `firm` ceiling stands on (spec review SP-3). It is still
    // not `certain`: a mitigation could exist above this threshold.
    let detail = if obs.peer_silent {
        format!(
            "no reset-rate mitigation observed in {RESET_PAIRS} reset pairs: the peer \
             neither reset, refused nor closed, and stayed silent with the connection \
             open"
        )
    } else {
        format!("no reset-rate mitigation observed in {RESET_PAIRS} reset pairs")
    };
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Firm,
        evidence: Evidence {
            matched: Some(format!(
                "{RESET_PAIRS} reset pairs, no GOAWAY, no refused stream, connection open"
            )),
            ..Evidence::default()
        },
        detail,
        poc_hint: None,
        location: None,
        more: Vec::new(),
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
    // A GOAWAY with an error code while the sequential blocks were in
    // flight is the peer rejecting the variant it was reading at the
    // connection level — the strictest rejection there is, and what a
    // conforming server does with a malformed header block (live run
    // against hyper, 2026-11-01). The rejected variant is the first slot
    // without an outcome; the slots after it were never written, since the
    // driver opens one connection per probe and the peer took it down.
    let connection_rejected =
        obs.connection_closed && matches!(obs.goaway, Some((_, code)) if code != 0);
    let mut at_connection: Option<usize> = None;
    let mut not_tried = 0usize;
    for (index, outcome) in obs.streams.iter().enumerate().take(labels.len()) {
        match read_stream(outcome) {
            Reading::Rejected => {}
            Reading::Unobserved if connection_rejected && at_connection.is_none() => {
                at_connection = Some(index);
            }
            Reading::Unobserved if at_connection.is_some() => not_tried += 1,
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
            location: None,
            more: Vec::new(),
        };
    }
    if let (Some(index), 0) = (at_connection, unobserved) {
        let code = obs.goaway.map_or(0, |(_, code)| code);
        return no_finding(
            Outcome::Clean,
            format!(
                "variant {index} ({}) was rejected at the connection level (GOAWAY \
                 error_code={code}); {not_tried} later variant(s) could not be tried on \
                 that connection",
                labels[index]
            ),
        );
    }
    let unobserved = unobserved + not_tried + usize::from(at_connection.is_some());
    if unobserved > 0 {
        let why = if obs.peer_silent {
            "were not answered within the read timeout; the peer stayed silent"
        } else {
            "did not reach an outcome before the probe stopped"
        };
        return inconclusive(format!("{unobserved} of {} variants {why}", labels.len()));
    }
    no_finding(
        Outcome::Clean,
        format!("all {} variants were rejected", labels.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::{H2Check, Kind, OncePerAuthority, RawH2Runner, Target, GUARD_TTL};
    use aitm_proto_http::raw_h2::{RawH2Mode, RawH2Observation, RawH2Plan, RawHeader};
    use futures::future::BoxFuture;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A runner for tests that never reach the wire.
    struct NeverRuns;

    impl RawH2Runner for NeverRuns {
        fn run<'a>(&'a self, _: RawH2Plan) -> BoxFuture<'a, anyhow::Result<RawH2Observation>> {
            Box::pin(async { anyhow::bail!("this test does not dial") })
        }
    }

    fn names(block: &[RawHeader]) -> Vec<&[u8]> {
        block.iter().map(|h| h.name.as_slice()).collect()
    }

    fn count(block: &[RawHeader], name: &str) -> usize {
        block.iter().filter(|h| h.name == name.as_bytes()).count()
    }

    fn value_of<'a>(block: &'a [RawHeader], name: &str) -> Option<&'a [u8]> {
        block
            .iter()
            .find(|h| h.name == name.as_bytes())
            .map(|h| h.value.as_slice())
    }

    /// The labels a malformed-header verdict quotes and the blocks the plan
    /// sends come from one list, so the label at index `i` can only describe
    /// the block at index `i` (Q2-4). Each label is checked against the shape
    /// of its own block, and the plan's `Blocks` are exactly those blocks.
    #[test]
    fn each_variant_label_names_the_block_at_its_index() {
        let target = Target::parse("https://origin.test/x").expect("a usable url");
        let runner: Arc<dyn RawH2Runner> = Arc::new(NeverRuns);

        for kind in [Kind::PseudoHeader, Kind::HeaderCrlf, Kind::ClTe] {
            let variants = kind.variants(&target);
            assert!(!variants.is_empty(), "{kind:?} sends variants");
            for (label, block) in &variants {
                match *label {
                    "missing :path" => assert_eq!(count(block, ":path"), 0, "{label}"),
                    "duplicate :method" => assert_eq!(count(block, ":method"), 2, "{label}"),
                    "pseudo-header after a regular header" => {
                        let names = names(block);
                        let first_regular = names
                            .iter()
                            .position(|n| !n.starts_with(b":"))
                            .expect("a regular header");
                        let last_pseudo = names
                            .iter()
                            .rposition(|n| n.starts_with(b":"))
                            .expect("a pseudo-header");
                        assert!(first_regular < last_pseudo, "{label}: {names:?}");
                    }
                    "CRLF in a header value" => {
                        assert!(
                            block
                                .iter()
                                .any(|h| h.value.windows(2).any(|w| w == b"\r\n")),
                            "{label}"
                        );
                        assert!(
                            block
                                .iter()
                                .all(|h| !h.name.windows(2).any(|w| w == b"\r\n")),
                            "{label}: the name must be clean"
                        );
                    }
                    "CRLF in a header name" => {
                        assert!(
                            block
                                .iter()
                                .any(|h| h.name.windows(2).any(|w| w == b"\r\n")),
                            "{label}"
                        );
                    }
                    "content-length one byte longer than the body" => {
                        assert_eq!(
                            value_of(block, "content-length"),
                            Some(&b"1"[..]),
                            "{label}"
                        );
                    }
                    "transfer-encoding: chunked" => {
                        assert_eq!(
                            value_of(block, "transfer-encoding"),
                            Some(&b"chunked"[..]),
                            "{label}"
                        );
                    }
                    other => panic!("{kind:?}: unexpected label {other:?}"),
                }
            }

            // The plan is cut from the same list, in the same order.
            let planned = H2Check::new(kind, Arc::clone(&runner)).plan(&target);
            let blocks: Vec<Vec<RawHeader>> = variants.iter().map(|(_, b)| b.clone()).collect();
            assert_eq!(planned.plan.mode, RawH2Mode::Blocks(blocks), "{kind:?}");
            assert_eq!(
                usize::from(planned.plan.streams),
                variants.len(),
                "{kind:?}"
            );
            let labels: Vec<&str> = variants.iter().map(|(l, _)| *l).collect();
            assert_eq!(planned.labels, labels, "{kind:?}");
        }

        // The three documented orders, pinned so a reordering is a visible
        // change to the issue text.
        let labels = |kind: Kind| -> Vec<&'static str> {
            kind.variants(&target).into_iter().map(|(l, _)| l).collect()
        };
        assert_eq!(
            labels(Kind::PseudoHeader),
            [
                "missing :path",
                "duplicate :method",
                "pseudo-header after a regular header"
            ]
        );
        assert_eq!(
            labels(Kind::HeaderCrlf),
            ["CRLF in a header value", "CRLF in a header name"]
        );
        assert_eq!(
            labels(Kind::ClTe),
            [
                "content-length one byte longer than the body",
                "transfer-encoding: chunked"
            ]
        );
        assert!(Kind::Settings.variants(&target).is_empty());
        assert!(Kind::RapidReset.variants(&target).is_empty());
    }

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

    /// The h2 checks' "stopped" detail is the shared sentence with a prefix,
    /// not a second spelling of it (Q2-2).
    #[test]
    fn the_stopped_detail_is_composed_from_the_shared_reason() {
        let v = super::stopped();
        assert_eq!(v.outcome, super::Outcome::Inconclusive);
        assert_eq!(v.detail, format!("stopped: {}", crate::gate::STOPPED));
        assert_eq!(
            v.detail,
            "stopped: the job was cancelled, out of budget or past its deadline"
        );
    }

    #[test]
    fn target_parse_cuts_scheme_authority_and_path() {
        let t = Target::parse("https://origin.test/x?y=1").expect("a usable url");
        assert_eq!(t.scheme, "https");
        assert_eq!(t.wire_authority, "origin.test");
        assert_eq!(t.path, "/x");
        assert_eq!(t.origin_key, "https://origin.test:443");

        // A written port stays on the wire form and in the key; userinfo and
        // case go; a non-http(s) scheme is not dialable.
        let t = Target::parse("HTTP://User:pw@Origin.TEST:8080/a/b#f").expect("a usable url");
        assert_eq!(t.scheme, "http");
        assert_eq!(t.wire_authority, "origin.test:8080");
        assert_eq!(t.path, "/a/b");
        assert_eq!(t.origin_key, "http://origin.test:8080");
        assert!(Target::parse("ftp://origin.test/").is_none());
        assert!(Target::parse("//origin.test/").is_none());
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
