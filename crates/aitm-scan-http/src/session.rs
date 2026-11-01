//! Session application, canary picking and `SessionMonitor` (task 13).
//!
//! The scanner reuses an observed session (spec **D7**): the cookies and secret
//! headers of a captured in-scope flow are replayed on every probe and every
//! crawl request, and a `GET`/`HEAD` canary is replayed periodically so a
//! session that stopped working is noticed instead of turning every later
//! finding into noise.
//!
//! **No value leaves this module.** `SessionMaterial`'s values are read here to
//! build a header, a cookie header or a `document.cookie` statement and nowhere
//! else: no type declared here derives `Debug` (they hold an `HttpRequest`,
//! whose `Debug` would print headers), the one `warn!` reports a method, a path
//! through [`redact::safe_request_url`] and two status codes, and
//! [`browser_partial`] reports cookie *names* only (AC T2-6).
//!
//! **The session-lost token.** After a canary loss under `OnLost::Stop`, every
//! `probe`/`baseline`/`probe_raw` of the job returns an error built by
//! [`SessionMonitor::lost_error`], whose message starts with
//! [`SESSION_LOST_PREFIX`]; T1b's engine maps that to
//! `stopped_reason: session_lost` (cross-track seam S1). The token is the
//! contract; on top of it, the host that saw the loss reports it once through
//! `JobCtx::report_session_lost` ([`CanaryOutcome::Lost`] carries `first` so
//! only that one call does), which sets `JobStatus.session.lost` (spec D7).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use aitm_core::{
    Body, Flow, FlowId, FlowKind, FlowQuery, FlowStore, HttpRequest, ProxyClient, SendOptions,
};
use aitm_scan_model::{Canary, CanaryMethod, OnLost, SessionMaterial};
use url::Url;

use crate::{limits, params, redact, url_norm};

/// The prefix of every error returned once a job's session is lost (seam S1).
pub(crate) const SESSION_LOST_PREFIX: &str = "scan: session_lost: ";

// --- applying the session to a request ------------------------------------

/// Add the session's headers and cookies to `req`, letting the request win.
///
/// A header whose name the request already carries is left alone (a probe that
/// deliberately mutates `Authorization` must not have it overwritten here), and
/// so is a cookie the request already carries: the session only fills gaps.
/// Session cookies that are absent are appended in the material's order behind
/// the request's own, and the `Cookie` header is rewritten as a single header
/// (`HeaderMap::set` appends, so a merge that did not remove first would send
/// two). The pairs of every `Cookie` header the request carries are merged in
/// order first, so a second header (legal, common on h2) is never dropped by
/// that rewrite. A request with no `Cookie` header gets one only when the
/// material has cookies to put in it.
///
/// Cookie names are compared exactly (RFC 6265 cookie names are
/// case-sensitive); header names case-insensitively, as HTTP defines them.
pub(crate) fn apply_session(req: &mut HttpRequest, material: &SessionMaterial) {
    for (name, value) in &material.headers {
        if !req.headers.has(name) {
            req.headers.set(name, value);
        }
    }

    // Every `Cookie` header, in order: a request may legally carry more than
    // one (common on h2), and the rewrite below removes them all.
    let mut merged: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, value)| params::cookie_pairs(value))
        .collect();
    for (name, value) in &material.cookies {
        if !merged.iter().any(|(existing, _)| existing == name) {
            merged.push((name.clone(), value.clone()));
        }
    }
    if merged.is_empty() {
        return;
    }

    // Keep the capture's own spelling of the header name when it had one.
    let header_name = req
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .map_or_else(|| "Cookie".to_string(), |(name, _)| name.to_string());
    req.headers.remove("cookie");
    req.headers
        .set(&header_name, &params::serialize_cookies(&merged));
}

// --- priming a browser profile --------------------------------------------

/// One `document.cookie = "name=value; path=/"` statement per session cookie,
/// for priming a browser crawl's profile with the observed session.
///
/// A name that is not an RFC 6265 token is skipped rather than escaped: a
/// cookie cannot carry such a name, so a statement built from one would set
/// something the server never sent. The characters that would end the value or
/// the statement early (`;`, `"`, `\`, CR, LF) are percent-encoded so the
/// assignment stays well formed and a crafted value cannot inject a second
/// cookie attribute or close the string.
pub(crate) fn browser_cookie_statements(material: &SessionMaterial) -> Vec<String> {
    material
        .cookies
        .iter()
        .filter(|(name, _)| is_cookie_name_token(name))
        .map(|(name, value)| {
            format!(
                "document.cookie = \"{name}={}; path=/\"",
                escape_cookie_value(value)
            )
        })
        .collect()
}

/// The session cookie **names** missing from a `document.cookie` read-back.
///
/// An empty vector means the browser profile holds every session cookie; a
/// non-empty one names the cookies the profile is missing, so a browser crawl
/// can report a partially primed session without ever naming a value.
pub(crate) fn browser_partial(material: &SessionMaterial, document_cookie: &str) -> Vec<String> {
    let present = params::cookie_pairs(document_cookie);
    material
        .cookies
        .iter()
        .filter(|(name, _)| !present.iter().any(|(read, _)| read == name))
        .map(|(name, _)| name.clone())
        .collect()
}

/// Whether `name` is an RFC 6265 cookie name (an RFC 7230 token).
fn is_cookie_name_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(
                    byte,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

/// Percent-encode the characters a `document.cookie` assignment cannot carry
/// literally in a value.
fn escape_cookie_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            ';' => out.push_str("%3B"),
            '"' => out.push_str("%22"),
            '\\' => out.push_str("%5C"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

// --- picking the canary ----------------------------------------------------

/// A replayable canary: a captured `GET`/`HEAD` request that carried the
/// session, plus the status it answered with.
///
/// No `Debug`: it holds an `HttpRequest`, whose `Debug` prints every header
/// value. [`SessionMonitor::canary`] is the one way its shape reaches a log or
/// a result, and that shape is names only.
pub(crate) struct CanaryRequest {
    /// The request to replay, body already forced empty.
    pub request: HttpRequest,
    /// `GET` or `HEAD`, never a method that could mutate state. Read by
    /// [`SessionMonitor::canary`], which reports the shape to the job.
    pub method: CanaryMethod,
    /// The request's path *without* the query, for the status shape: the
    /// contract names a path, and a query string can carry a value. The replay
    /// still goes to `request.path`, query and all. Read by
    /// [`SessionMonitor::canary`], which reports the shape to the job.
    pub path: String,
    /// The status the replay is expected to answer with.
    pub expected_status: u16,
}

/// Choose the canary for `origin`, preferring `from_flow` when it qualifies.
///
/// A flow qualifies when it is an HTTP flow, captured rather than replayed, a
/// `GET` or `HEAD` to `origin`, carrying at least one of the material's cookie
/// or header names, and holding a response (a canary with no expected status
/// cannot tell a working session from a broken one). When `from_flow` was given
/// but does not qualify, the substitution is logged at info and the search falls
/// through to the newest qualifying captured flow. `None` when nothing
/// qualifies — the job then runs with an unarmed monitor.
///
/// The search skips the scanner's own captures: a flow marked `crawl` or
/// `scan:<job>` (spec D5) is a crawl navigation the browser made with the
/// primed session, not the operator's traffic, and makes a poor canary (an
/// arbitrary route that may be slow or non-idempotent). A `from_flow` the
/// operator named explicitly is exempt from that rule.
pub(crate) fn pick_canary(
    store: &dyn FlowStore,
    origin: &Url,
    material: &SessionMaterial,
    from_flow: Option<FlowId>,
) -> Option<CanaryRequest> {
    if let Some(id) = from_flow {
        if let Some(canary) = store
            .get(id)
            .as_ref()
            .and_then(|flow| canary_from(flow, origin, material))
        {
            return Some(canary);
        }
        tracing::info!(
            "scan: canary substituted: the named source flow is not a captured GET/HEAD of this origin carrying the session"
        );
    }

    let query = FlowQuery {
        host: origin.host_str().map(str::to_ascii_lowercase),
        kind: Some(FlowKind::Http),
        is_replay: Some(false),
        ..FlowQuery::default()
    };
    // `query` answers in insertion order, so the newest match is the last.
    store.query(&query).into_iter().rev().find_map(|id| {
        store
            .get(id)
            .as_ref()
            .filter(|flow| !is_scanner_capture(flow))
            .and_then(|flow| canary_from(flow, origin, material))
    })
}

/// Whether `flow` is one the scanner produced itself: marked `crawl` or with a
/// job mark `scan:<job>` (spec D5). Such a capture is never picked as a canary
/// by the search; it is still accepted when named through `from_flow`.
fn is_scanner_capture(flow: &Flow) -> bool {
    let Flow::Http(http) = flow else {
        return false;
    };
    http.metadata
        .marks
        .iter()
        .any(|mark| mark == limits::MARK_CRAWL || mark.starts_with(limits::JOB_MARK_PREFIX))
}

/// The canary `flow` would make, or `None` when it does not qualify.
fn canary_from(flow: &Flow, origin: &Url, material: &SessionMaterial) -> Option<CanaryRequest> {
    let Flow::Http(http) = flow else {
        return None;
    };
    if http.metadata.is_replay {
        return None;
    }
    let method = match http.request.method.to_ascii_uppercase().as_str() {
        "GET" => CanaryMethod::Get,
        "HEAD" => CanaryMethod::Head,
        _ => return None,
    };
    if !url_norm::request_url(&http.request)
        .is_some_and(|parsed| url_norm::same_origin(&parsed, origin))
    {
        return None;
    }
    if !carries_material(&http.request, material) {
        return None;
    }
    let expected_status = http.response.as_ref()?.status;

    let mut request = http.request.clone();
    // A canary never carries a body, so it must not claim one either.
    request.body = Body::Empty;
    request.headers.remove("content-length");
    request.headers.remove("transfer-encoding");
    // The status shape is the path alone: `/account?tab=overview` reports as
    // `/account`, while the replay keeps the captured target.
    let path = params::split_path(&request.path).path.to_string();

    Some(CanaryRequest {
        request,
        method,
        path,
        expected_status,
    })
}

/// Whether `req` carries at least one of the material's cookie or header names.
fn carries_material(req: &HttpRequest, material: &SessionMaterial) -> bool {
    let cookies = req
        .headers
        .get("cookie")
        .map(params::cookie_pairs)
        .unwrap_or_default();
    material
        .cookies
        .iter()
        .any(|(name, _)| cookies.iter().any(|(carried, _)| carried == name))
        || material
            .headers
            .iter()
            .any(|(name, _)| req.headers.has(name))
}

// --- the monitor -----------------------------------------------------------

/// What one canary check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanaryOutcome {
    /// No canary: auth-lost detection is off for this job.
    Unarmed,
    /// The canary still answers as it did.
    Ok,
    /// The canary answered `2xx` when the session was observed and does not
    /// now (`after == 0` is a transport error or a timeout).
    Lost {
        /// The status the canary answered with when it was picked.
        before: u16,
        /// The status it answers with now.
        after: u16,
        /// Whether *this* check flipped the monitor's lost flag. True for
        /// exactly one check of a job, so the caller that sees it is the one
        /// that reports the loss through `JobCtx::report_session_lost`
        /// (spec D7); a later check of the same lost monitor sees `false`.
        first: bool,
    },
}

/// Replays a job's canary every `every` ticks and remembers a lost session.
///
/// Shared across a job's concurrent probes behind an `Arc`, so every field that
/// changes is an atomic and every method takes `&self`. No `Debug`: it holds a
/// [`CanaryRequest`].
pub(crate) struct SessionMonitor {
    canary: Option<CanaryRequest>,
    on_lost: OnLost,
    every: u32,
    ticks: AtomicU32,
    lost: AtomicBool,
    logged: AtomicBool,
}

impl SessionMonitor {
    /// A monitor over `canary`, checking every `every` ticks.
    pub(crate) fn new(canary: Option<CanaryRequest>, on_lost: OnLost, every: u32) -> Self {
        Self {
            canary,
            on_lost,
            every,
            ticks: AtomicU32::new(0),
            lost: AtomicBool::new(false),
            logged: AtomicBool::new(false),
        }
    }

    /// A monitor with no canary: [`SessionMonitor::tick`] is always false and
    /// [`SessionMonitor::check`] is [`CanaryOutcome::Unarmed`]. This is what a
    /// job with `session.mode: none`, no material or no eligible flow gets, so
    /// the probe path needs no `Option<SessionMonitor>`.
    pub(crate) fn unarmed(on_lost: OnLost) -> Self {
        Self::new(None, on_lost, 0)
    }

    /// Count one probe and report whether this one should run a check.
    ///
    /// False for an unarmed monitor and for `every == 0`, so neither can ask
    /// for a check or divide by zero.
    pub(crate) fn tick(&self) -> bool {
        if self.canary.is_none() || self.every == 0 {
            return false;
        }
        let count = self.ticks.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        count.is_multiple_of(self.every)
    }

    /// Whether a check has concluded the session is lost.
    pub(crate) fn is_lost(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }

    /// Mark this monitor lost, reporting whether *this* call flipped the flag.
    ///
    /// The flip is the one-shot the loss report hangs off: concurrent probes
    /// share the monitor, and only the one that flipped it tells the job.
    pub(crate) fn mark_lost(&self) -> bool {
        !self.lost.swap(true, Ordering::SeqCst)
    }

    /// Mark this monitor lost without running a check.
    ///
    /// Used when a lost monitor is evicted from the registry and later rebuilt
    /// for the same job: the rebuilt monitor starts lost, so probing does not
    /// resume after a `session_lost` stop (S-M5).
    pub(crate) fn force_lost(&self) {
        let _ = self.mark_lost();
    }

    /// Whether the job must stop: the session is lost and `on_lost` is `stop`.
    pub(crate) fn should_stop(&self) -> bool {
        self.is_lost() && matches!(self.on_lost, OnLost::Stop)
    }

    /// The canary's wire shape (a method, a path and a status — never a value).
    ///
    /// Reported to the job once, when its monitor is built, through
    /// `JobCtx::report_session_canary`; the engine mirrors it into
    /// `JobStatus.session.canary` (spec D5). [`Canary::None`] says auth-lost
    /// detection is off for this job.
    pub(crate) fn canary(&self) -> Canary {
        match &self.canary {
            None => Canary::None,
            Some(canary) => Canary::Flow {
                method: canary.method,
                path: canary.path.clone(),
                expected_status: Some(canary.expected_status),
            },
        }
    }

    /// Replay the canary and decide whether the session still works.
    ///
    /// The canary goes out with its captured headers unchanged and an empty
    /// body, bounded by `timeout`. A transport error or a timeout reads as
    /// status `0`, which counts as lost only when the canary was observed
    /// answering `2xx`: a canary that was never `2xx` cannot prove a loss. The
    /// loss is logged once, at warn, naming the path through
    /// [`redact::safe_request_url`] and the two statuses, and the outcome's
    /// `first` says whether this call is the one that flipped the monitor's
    /// lost flag (so exactly one caller reports the loss to the job).
    pub(crate) async fn check(
        &self,
        client: &dyn ProxyClient,
        opts: SendOptions,
        timeout: Duration,
    ) -> CanaryOutcome {
        let Some(canary) = self.canary.as_ref() else {
            return CanaryOutcome::Unarmed;
        };

        let mut request = canary.request.clone();
        request.body = Body::Empty;
        let before = canary.expected_status;
        let after = match tokio::time::timeout(timeout, client.send_opts(request, opts)).await {
            Ok(Ok(flow)) => flow.response.map_or(0, |response| response.status),
            // The error is dropped rather than logged: a client error can carry
            // the request it failed on, which this module never puts in a line.
            Ok(Err(_)) | Err(_) => {
                tracing::debug!(
                    canary = %redact::safe_request_url(&canary.request),
                    "scan: canary replay failed to reach the target"
                );
                0
            }
        };

        if before / 100 != 2 || after / 100 == 2 {
            return CanaryOutcome::Ok;
        }

        let first = self.mark_lost();
        if !self.logged.swap(true, Ordering::SeqCst) {
            tracing::warn!(
                canary = %redact::safe_request_url(&canary.request),
                before,
                after,
                "scan: session lost: the canary stopped answering 2xx"
            );
        }
        CanaryOutcome::Lost {
            before,
            after,
            first,
        }
    }

    /// The error every probe of a lost job returns: [`SESSION_LOST_PREFIX`]
    /// followed by `context` (a stage name, never a value).
    pub(crate) fn lost_error(&self, context: &str) -> anyhow::Error {
        anyhow::anyhow!("{SESSION_LOST_PREFIX}{context}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use aitm_core::{Body, Flow, FlowStore, MemFlowStore, SendOptions};
    use aitm_scan_model::{Canary, CanaryMethod, OnLost, SessionMaterial};

    use super::*;
    use crate::testutil::{captured_flow, request, response, ScriptedClient};
    use crate::url_norm::parse_absolute;

    /// Material from borrowed pairs, so a test reads as its literal names.
    fn session_of(cookies: &[(&str, &str)], headers: &[(&str, &str)]) -> SessionMaterial {
        let own = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect()
        };
        SessionMaterial {
            cookies: own(cookies),
            headers: own(headers),
        }
    }

    /// How many headers carry `name` (case-insensitively).
    fn count_header(req: &aitm_core::HttpRequest, name: &str) -> usize {
        req.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .count()
    }

    #[test]
    fn apply_session_merge() {
        let mut req = request(
            "GET",
            "http://t:8080/a",
            &[("cookie", "theme=dark; sid=old"), ("x-api-key", "mine")],
            None,
        );
        let material = session_of(
            &[("sid", "NEW"), ("lang", "en")],
            &[("Authorization", "Bearer T"), ("X-Api-Key", "K")],
        );

        apply_session(&mut req, &material);

        // A cookie the request already carries wins; an absent one is appended
        // in the material's order, behind what the request had.
        assert_eq!(
            req.headers.get("cookie"),
            Some("theme=dark; sid=old; lang=en")
        );
        // An absent header is added, a present one is left alone.
        assert_eq!(req.headers.get("authorization"), Some("Bearer T"));
        assert_eq!(req.headers.get("x-api-key"), Some("mine"));
        // `HeaderMap::set` appends, so the merge must not leave a duplicate.
        assert_eq!(count_header(&req, "cookie"), 1);
        assert_eq!(count_header(&req, "authorization"), 1);
        assert_eq!(count_header(&req, "x-api-key"), 1);

        // A request with no `Cookie` header gets one built from the material.
        let mut bare = request("GET", "http://t:8080/a", &[], None);
        apply_session(&mut bare, &material);
        assert_eq!(bare.headers.get("cookie"), Some("sid=NEW; lang=en"));
        assert_eq!(count_header(&bare, "cookie"), 1);

        // No cookies in the material and none on the request: no header appears.
        let mut none = request("GET", "http://t:8080/a", &[], None);
        apply_session(&mut none, &session_of(&[], &[("X-Tok", "T")]));
        assert!(!none.headers.has("cookie"));
    }

    /// Two `Cookie` headers (legal, common on h2) are merged in order before the
    /// session fills the gaps; the rewrite leaves exactly one header, so the
    /// second header's pairs are never dropped (stage-5 F4).
    #[test]
    fn apply_session_merges_every_cookie_header() {
        let mut req = request(
            "GET",
            "http://t:8080/a",
            &[("cookie", "a=1"), ("cookie", "b=2")],
            None,
        );
        apply_session(&mut req, &session_of(&[("sid", "S3")], &[]));
        assert_eq!(req.headers.get("cookie"), Some("a=1; b=2; sid=S3"));
        assert_eq!(count_header(&req, "cookie"), 1);
    }

    #[test]
    fn browser_statements() {
        let material = session_of(&[("sid", "S3"), ("bad name", "x"), ("v", "a;b")], &[]);

        // A name that is not an RFC 6265 token is skipped; a value's `;` is
        // percent-encoded so it cannot start a second cookie attribute.
        assert_eq!(
            browser_cookie_statements(&material),
            vec![
                "document.cookie = \"sid=S3; path=/\"".to_string(),
                "document.cookie = \"v=a%3Bb; path=/\"".to_string(),
            ]
        );

        let two = session_of(&[("sid", "S3"), ("hs", "H9")], &[]);
        assert_eq!(browser_partial(&two, "sid=S3"), vec!["hs".to_string()]);
        assert!(browser_partial(&two, "sid=S3; hs=H9").is_empty());
    }

    /// The store of `pick_canary_rules`, oldest first, with the ids of the
    /// older eligible `GET /older`, of the ineligible `POST /login` and of the
    /// scanner's own `GET /slow?ms=10` crawl capture for the `from_flow` cases.
    fn canary_store() -> CanaryStore {
        let store = Arc::new(MemFlowStore::default());

        store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/public", &[], None),
            200,
            &[],
            b"public",
        )));
        let older = store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/older", &[("cookie", "sid=S3")], None),
            200,
            &[],
            b"older",
        )));
        // Carries a query, so the canary's status `path` (the path alone) and
        // its replayed request target (path plus query) are distinguishable.
        store.insert(Flow::Http(captured_flow(
            request(
                "GET",
                "http://t:8080/account?tab=overview",
                &[("cookie", "sid=S3")],
                None,
            ),
            200,
            &[],
            b"account",
        )));
        let post = store.insert(Flow::Http(captured_flow(
            request(
                "POST",
                "http://t:8080/login",
                &[("cookie", "sid=S3")],
                Some(("application/x-www-form-urlencoded", b"u=a")),
            ),
            302,
            &[],
            b"",
        )));
        // Newer than `/account` but still not the canary: no response to
        // expect, and a replay rather than a capture.
        let mut pending = captured_flow(
            request(
                "GET",
                "http://t:8080/pending",
                &[("cookie", "sid=S3")],
                None,
            ),
            200,
            &[],
            b"",
        );
        pending.response = None;
        store.insert(Flow::Http(pending));
        let mut replay = captured_flow(
            request(
                "GET",
                "http://t:8080/replayed",
                &[("cookie", "sid=S3")],
                None,
            ),
            200,
            &[],
            b"replayed",
        );
        replay.metadata.is_replay = true;
        store.insert(Flow::Http(replay));
        // Newest of all and a real capture carrying the material, but the
        // scanner's own: a browser crawl primed with the session navigated
        // here, so it carries the job mark and the crawl mark (live finding
        // L4). The operator's `/account` must still win over it.
        let mut crawled = captured_flow(
            request(
                "GET",
                "http://t:8080/slow?ms=10",
                &[("cookie", "sid=S3")],
                None,
            ),
            200,
            &[],
            b"slow",
        );
        crawled.metadata.marks = vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()];
        let crawl = store.insert(Flow::Http(crawled));

        CanaryStore {
            store,
            older,
            post,
            crawl,
        }
    }

    /// The store of `canary_store` and the three ids its `from_flow` cases name.
    struct CanaryStore {
        store: Arc<MemFlowStore>,
        older: aitm_core::FlowId,
        post: aitm_core::FlowId,
        crawl: aitm_core::FlowId,
    }

    #[test]
    fn pick_canary_rules() {
        let fixture = canary_store();
        let store = &fixture.store;
        let origin = parse_absolute("http://t:8080/").unwrap();
        let material = session_of(&[("sid", "S3")], &[]);

        // Newest captured GET/HEAD to the origin carrying a material name: the
        // replay is skipped, the POST is not a canary method, `/public` has no
        // material name.
        let picked = pick_canary(store.as_ref(), &origin, &material, None).expect("a canary");
        // Not `/replayed` (a replay), not `/pending` (no response to expect),
        // not `/login` (not a canary method), not `/public` (no session name),
        // not the older `/older`, and not the newer `/slow?ms=10`: a capture
        // marked `scan:<job>` + `crawl` is the scanner's own crawl navigation,
        // not the operator's session (live finding L4).
        // The status shape is the path alone; the replay still targets the
        // captured request line, query and all.
        assert_eq!(picked.path, "/account");
        assert_eq!(picked.request.path, "/account?tab=overview");
        assert_eq!(picked.expected_status, 200);
        assert_eq!(picked.method, CanaryMethod::Get);
        assert_eq!(picked.request.method, "GET");
        assert!(matches!(picked.request.body, Body::Empty));

        // An ineligible `from_flow` falls back to the same substitution.
        let from_post =
            pick_canary(store.as_ref(), &origin, &material, Some(fixture.post)).expect("a canary");
        assert_eq!(from_post.path, "/account");
        assert_eq!(from_post.expected_status, 200);

        // An eligible `from_flow` is preferred over the newest flow.
        let from_older =
            pick_canary(store.as_ref(), &origin, &material, Some(fixture.older)).expect("a canary");
        assert_eq!(from_older.path, "/older");

        // The operator may name a marked flow explicitly: `from_flow` is exempt
        // from the own-capture rule.
        let from_crawl =
            pick_canary(store.as_ref(), &origin, &material, Some(fixture.crawl)).expect("a canary");
        assert_eq!(from_crawl.path, "/slow");
        assert_eq!(from_crawl.request.path, "/slow?ms=10");

        // A newer *unmarked* capture is still the operator's traffic and wins.
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/newest", &[("cookie", "sid=S3")], None),
            200,
            &[],
            b"newest",
        )));
        let newest = pick_canary(store.as_ref(), &origin, &material, None).expect("a canary");
        assert_eq!(newest.path, "/newest");

        // No flow carries a name of this material.
        let absent = session_of(&[("other", "X")], &[]);
        assert!(pick_canary(store.as_ref(), &origin, &absent, None).is_none());

        // Another origin's flows are not this origin's canary.
        let elsewhere = parse_absolute("http://other:8080/").unwrap();
        assert!(pick_canary(store.as_ref(), &elsewhere, &material, None).is_none());
    }

    #[tokio::test]
    async fn monitor_ticks_and_lost() {
        let fixture = canary_store();
        let store = &fixture.store;
        let origin = parse_absolute("http://t:8080/").unwrap();
        let material = session_of(&[("sid", "S3")], &[]);
        let canary = pick_canary(store.as_ref(), &origin, &material, None).expect("a canary");

        // The status the monitor's log line may name is a method, a path and a
        // status: never a cookie or header value.
        let monitor = SessionMonitor::new(Some(canary), OnLost::Stop, 2);
        assert_eq!(
            monitor.canary(),
            Canary::Flow {
                method: CanaryMethod::Get,
                path: "/account".to_string(),
                expected_status: Some(200),
            }
        );

        // Armed, every 2: only every second tick asks for a check.
        assert!(!monitor.tick());
        assert!(monitor.tick());
        assert!(!monitor.tick());
        assert!(monitor.tick());

        let calls = Arc::new(AtomicU32::new(0));
        let client = ScriptedClient::new(move |_req| {
            let nth = calls.fetch_add(1, Ordering::SeqCst);
            Ok(response(if nth == 0 { 200 } else { 302 }, &[], b""))
        });
        let timeout = Duration::from_secs(5);

        assert_eq!(
            monitor
                .check(&client, SendOptions::default(), timeout)
                .await,
            CanaryOutcome::Ok
        );
        assert!(!monitor.is_lost());

        // A 2xx that became a 302 is a lost session.
        assert_eq!(
            monitor
                .check(&client, SendOptions::default(), timeout)
                .await,
            CanaryOutcome::Lost {
                before: 200,
                after: 302,
                first: true
            }
        );
        assert!(monitor.is_lost());
        assert!(monitor.should_stop());
        assert!(monitor
            .lost_error("probe")
            .to_string()
            .starts_with("scan: session_lost: "));
        assert!(monitor
            .lost_error("probe")
            .to_string()
            .starts_with(SESSION_LOST_PREFIX));

        // The canary never mutates state: GET, no body. Taken as owned data so
        // the lock is not held across the awaits below.
        let seen: Vec<(String, String, bool)> = client
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(req, _)| {
                (
                    req.method.clone(),
                    req.path.clone(),
                    matches!(req.body, Body::Empty),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                ("GET".to_string(), "/account?tab=overview".to_string(), true),
                ("GET".to_string(), "/account?tab=overview".to_string(), true),
            ]
        );

        // `continue` keeps the job going on the same loss.
        let canary = pick_canary(store.as_ref(), &origin, &material, None).expect("a canary");
        let lenient = SessionMonitor::new(Some(canary), OnLost::Continue, 2);
        let always_302 = ScriptedClient::new(|_req| Ok(response(302, &[], b"")));
        assert_eq!(
            lenient
                .check(&always_302, SendOptions::default(), timeout)
                .await,
            CanaryOutcome::Lost {
                before: 200,
                after: 302,
                first: true
            }
        );
        assert!(lenient.is_lost());
        assert!(!lenient.should_stop());
    }

    /// Task 22: only the check that flips the lost flag is `first`, so only
    /// one caller reports the loss to the job (spec D7).
    #[tokio::test]
    async fn only_the_first_loss_flips_the_flag() {
        let canary = CanaryRequest {
            request: request("GET", "http://t:8080/me", &[("cookie", "sid=S3")], None),
            method: CanaryMethod::Get,
            path: "/me".to_string(),
            expected_status: 200,
        };
        let monitor = SessionMonitor::new(Some(canary), OnLost::Continue, 1);
        let gone = ScriptedClient::new(|_req| Ok(response(302, &[], b"")));
        let timeout = Duration::from_secs(5);

        assert_eq!(
            monitor.check(&gone, SendOptions::default(), timeout).await,
            CanaryOutcome::Lost {
                before: 200,
                after: 302,
                first: true
            }
        );
        assert_eq!(
            monitor.check(&gone, SendOptions::default(), timeout).await,
            CanaryOutcome::Lost {
                before: 200,
                after: 302,
                first: false
            },
            "the second check finds the flag already set"
        );

        // `force_lost` flips it just the same: a check after it is not first.
        let forced = SessionMonitor::new(
            Some(CanaryRequest {
                request: request("GET", "http://t:8080/me", &[("cookie", "sid=S3")], None),
                method: CanaryMethod::Get,
                path: "/me".to_string(),
                expected_status: 200,
            }),
            OnLost::Continue,
            1,
        );
        assert!(forced.mark_lost(), "the first mark flips the flag");
        assert!(!forced.mark_lost(), "a second mark does not");
    }

    #[tokio::test]
    async fn unarmed_never_ticks_true() {
        let monitor = SessionMonitor::unarmed(OnLost::Stop);
        for _ in 0..30 {
            assert!(!monitor.tick());
        }
        assert_eq!(monitor.canary(), Canary::None);

        let client = ScriptedClient::new(|_req| Ok(response(200, &[], b"")));
        assert_eq!(
            monitor
                .check(&client, SendOptions::default(), Duration::from_secs(5))
                .await,
            CanaryOutcome::Unarmed
        );
        assert!(client.sent.lock().unwrap().is_empty());
        assert!(!monitor.is_lost());
        assert!(!monitor.should_stop());
    }

    // --- tester additions (stage 5, whole branch) ----------------------------

    /// A loss is a status-class change away from 2xx and nothing else: a
    /// transport error or a timeout reads as 0 and counts only when the canary
    /// was observed answering 2xx; 200 -> 401 is a loss; 200 -> 204 is not; a
    /// canary that was never 2xx cannot prove a loss.
    #[tokio::test]
    async fn loss_is_a_class_change_from_2xx_only() {
        let timeout = Duration::from_secs(5);
        let canary = |expected: u16| CanaryRequest {
            request: request("GET", "http://t:8080/me", &[("cookie", "sid=S3")], None),
            method: CanaryMethod::Get,
            path: "/me".to_string(),
            expected_status: expected,
        };

        let failing = ScriptedClient::new(|_req| Err(anyhow::anyhow!("connection refused")));
        let monitor = SessionMonitor::new(Some(canary(200)), OnLost::Stop, 1);
        assert_eq!(
            monitor
                .check(&failing, SendOptions::default(), timeout)
                .await,
            CanaryOutcome::Lost {
                before: 200,
                after: 0,
                first: true
            }
        );
        assert!(monitor.should_stop());

        let unauthorised = ScriptedClient::new(|_req| Ok(response(401, &[], b"")));
        let monitor = SessionMonitor::new(Some(canary(200)), OnLost::Stop, 1);
        assert_eq!(
            monitor
                .check(&unauthorised, SendOptions::default(), timeout)
                .await,
            CanaryOutcome::Lost {
                before: 200,
                after: 401,
                first: true
            }
        );

        let no_content = ScriptedClient::new(|_req| Ok(response(204, &[], b"")));
        let monitor = SessionMonitor::new(Some(canary(200)), OnLost::Stop, 1);
        assert_eq!(
            monitor
                .check(&no_content, SendOptions::default(), timeout)
                .await,
            CanaryOutcome::Ok
        );
        assert!(!monitor.is_lost());

        let monitor = SessionMonitor::new(Some(canary(302)), OnLost::Stop, 1);
        assert_eq!(
            monitor
                .check(&failing, SendOptions::default(), timeout)
                .await,
            CanaryOutcome::Ok
        );
        assert!(!monitor.is_lost());
        assert!(!monitor.should_stop());

        // A canary that hangs is bounded by `timeout` and reads as a loss.
        let slow = ScriptedClient::new(|_req| Ok(response(200, &[], b"")))
            .with_delay(Duration::from_secs(5));
        let monitor = SessionMonitor::new(Some(canary(200)), OnLost::Stop, 1);
        let started = std::time::Instant::now();
        assert_eq!(
            monitor
                .check(&slow, SendOptions::default(), Duration::from_millis(100))
                .await,
            CanaryOutcome::Lost {
                before: 200,
                after: 0,
                first: true
            }
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    /// Every character that could break out of a `document.cookie` assignment
    /// is percent-encoded, a non-token name is skipped, and applying the
    /// session twice (the crawler and a probe host may both do it) changes
    /// nothing.
    #[test]
    fn cookie_statement_escaping_and_idempotent_apply() {
        let material = session_of(&[("v", "a\"b\\c\r\nd;e")], &[]);
        assert_eq!(
            browser_cookie_statements(&material),
            vec!["document.cookie = \"v=a%22b%5Cc%0D%0Ad%3Be; path=/\"".to_string()]
        );
        assert!(browser_cookie_statements(&session_of(
            &[("", "x"), ("a=b", "x"), ("a b", "x"), ("a;b", "x")],
            &[]
        ))
        .is_empty());

        let material = session_of(
            &[("sid", "S3"), ("lang", "en")],
            &[("Authorization", "Bearer T")],
        );
        let mut req = request("GET", "http://t:8080/a", &[("cookie", "theme=dark")], None);
        apply_session(&mut req, &material);
        let once: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        apply_session(&mut req, &material);
        let twice: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        assert_eq!(once, twice);
        assert_eq!(
            req.headers.get("cookie"),
            Some("theme=dark; sid=S3; lang=en")
        );
        assert_eq!(count_header(&req, "cookie"), 1);
        assert_eq!(count_header(&req, "authorization"), 1);
    }
}
