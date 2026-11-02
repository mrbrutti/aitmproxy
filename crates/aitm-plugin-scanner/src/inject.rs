//! The injector + correlator engine: for one `CheckDefinition`, mutate each
//! applicable injection point with each inert payload, send the mutated
//! request through the guarded [`aitm_core::ProxyClient`], and ask the
//! definition's own `confirm` whether the response proves the class.
//!
//! Deny-by-default throughout: the target host is gated through
//! [`aitm_core::ScopeRateGuard::check_active`] *before* the first point is even
//! looked at, so an unscoped target never issues a request
//! ([`aitm_core::GuardError::OutOfScope`]). Every mutated request still goes
//! through `host.client().send`, the one guarded chokepoint that re-checks
//! scope/rate/concurrency per request and captures the replay flow — this
//! module's own upfront check is a probe, not a substitute, and its permit is
//! dropped immediately rather than held across the whole run.
//!
//! The scan is bounded three ways, and each stop keeps what was already found
//! (`stopped_reason` says why; earlier `confirmed` hits are never discarded):
//! `budget` is decremented once per request sent (`"budget"`), `cfg.time_budget`
//! bounds the whole run *including* a send that never completes
//! (`"time_budget"`), and a guard refusal mid-run — rate limit, disabled host, a
//! scope or SSRF refusal — ends it (`"rate_limited"`, `"host_disabled"`,
//! `"scope"`). A plain transport error costs only that one attempt.
//!
//! Only the one targeted position in a cloned request is ever mutated: a query
//! or body parameter is rewritten through `url::form_urlencoded`/JSON
//! re-serialization (percent-/JSON-escaped, never spliced into raw text), so a
//! payload carrying `<`/`>`/`"` cannot desync the request it rides in.
//! `confirm` still matches the *decoded* marker in the response body — nothing
//! about the payload's value changes, only how it is safely placed on the
//! wire.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use aitm_core::{Body, CommandHost, Flow, FlowId, GuardError, HttpFlow, HttpRequest};

use crate::checks::{AttackMode, CheckDefinition};
use crate::discover::{body_bytes, enumerate, InjectionPoint, Location, REDACTED};
use crate::ScannerConfig;

/// One per-attempt confirmation: the injection point and payload that
/// triggered a hit, plus a non-sensitive description of what matched
/// ([`crate::checks::Evidence::matched`] — a scanner constant, never response
/// text, a header value, or a secret).
///
/// `injection_point.example` is always [`REDACTED`]: the raw value observed in
/// the source request (a redirect parameter can carry `?access_token=…`) never
/// rides along in a result that derives `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmed {
    pub injection_point: InjectionPoint,
    pub payload: String,
    pub evidence: String,
}

/// What one class's injection run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectOutcome {
    pub class: String,
    pub tested: usize,
    pub confirmed: Vec<Confirmed>,
    /// Why the run ended early, or `None` when every applicable point/payload
    /// combination was tried: `"budget"` (request budget spent),
    /// `"time_budget"` (wall-clock ceiling), `"rate_limited"` /
    /// `"host_disabled"` / `"concurrency_exceeded"` (the guard refused a send),
    /// `"scope"` (a scope or private-address refusal), or `"source_flow_missing"`
    /// (the run finished, but a point's source flow was no longer in the store
    /// so that point was never tried).
    pub stopped_reason: Option<String>,
}

/// Mutate, send, and correlate every applicable `(point, payload)` combination
/// for `def` against `target`.
///
/// Gated up front: `target`'s authority must already be in scope, or this
/// returns [`aitm_core::GuardError::OutOfScope`] (via `anyhow`) before
/// anything is sent. Points whose [`Location`] is not one `def.locations`
/// names are skipped; for each remaining point, up to
/// `cfg.per_class_payload_cap` payloads are tried (nuclei's "battering ram":
/// one point at a time, matching [`AttackMode::BatteringRam`] — the match is
/// exhaustive, so a new `AttackMode` variant fails the build here until this
/// function learns to drive it).
///
/// Each point's source request is read from the store once, before the first
/// send: every send captures a replay flow, and a busy store can evict the very
/// flows still being iterated. `*budget` is decremented once per request
/// attempted; a guard refusal sends nothing and costs nothing. Once the run
/// starts, no send error is returned: it ends the run with a partial
/// [`InjectOutcome`] (see the module docs) or, for a transport error, is
/// counted and skipped.
pub async fn inject(
    host: &CommandHost<'_>,
    target: &str,
    def: &CheckDefinition,
    points: &[InjectionPoint],
    budget: &mut usize,
    cfg: &ScannerConfig,
) -> anyhow::Result<InjectOutcome> {
    let authority = target_authority(target)?;
    // Deny-by-default before any point is looked at. The permit is a
    // scope/rate/error-budget probe only — it is not held across the run,
    // since `host.client().send` takes its own permit per request and a
    // `max_concurrency == 1` guard would otherwise refuse its own sends.
    drop(host.guard().check_active(&authority)?);

    let started = Instant::now();
    let mut tested = 0usize;
    let mut confirmed = Vec::new();
    let mut stopped_reason: Option<&'static str> = None;

    match def.mode {
        AttackMode::BatteringRam => {
            let applicable: Vec<&InjectionPoint> = points
                .iter()
                .filter(|p| def.locations.contains(&p.location))
                .collect();
            let (sources, skipped_points) = snapshot_sources(host, &applicable);

            'outer: for point in applicable {
                let Some(source) = sources.get(&point.flow) else {
                    continue;
                };
                for payload in def.payloads.iter().take(cfg.per_class_payload_cap) {
                    if *budget == 0 {
                        stopped_reason = Some("budget");
                        break 'outer;
                    }
                    let Some(remaining) = cfg
                        .time_budget
                        .checked_sub(started.elapsed())
                        .filter(|left| !left.is_zero())
                    else {
                        stopped_reason = Some("time_budget");
                        break 'outer;
                    };
                    let Some(req) = mutate_request(source, point, &payload.value) else {
                        continue;
                    };

                    let sent = match tokio::time::timeout(remaining, host.client().send(req)).await
                    {
                        Ok(Ok(flow)) => flow,
                        Ok(Err(err)) => {
                            if let Some(reason) = guard_stop_reason(&err) {
                                // The guard refused before anything left: keep
                                // what was found and report why we stopped.
                                stopped_reason = Some(reason);
                                break 'outer;
                            }
                            // A transport error (reset, WAF drop, bad TLS):
                            // that attempt is spent, the run is not. The
                            // guard's own error budget trips `HostDisabled`
                            // on a host that keeps failing.
                            *budget -= 1;
                            tested += 1;
                            continue;
                        }
                        Err(_elapsed) => {
                            // The send was in flight when the budget ran out.
                            *budget -= 1;
                            tested += 1;
                            stopped_reason = Some("time_budget");
                            break 'outer;
                        }
                    };
                    *budget -= 1;
                    tested += 1;

                    let (status, body, headers) = match &sent.response {
                        Some(resp) => (
                            resp.status,
                            response_text(&resp.body),
                            resp.headers
                                .iter()
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect::<Vec<_>>(),
                        ),
                        None => (0, String::new(), Vec::new()),
                    };

                    if let Some(evidence) = def.confirm(status, &body, &headers, payload) {
                        confirmed.push(Confirmed {
                            injection_point: InjectionPoint {
                                example: REDACTED.to_string(),
                                ..point.clone()
                            },
                            payload: payload.value.clone(),
                            evidence: evidence.matched,
                        });
                    }
                }
            }

            // A run that completed but never tried some point must not read as
            // complete.
            if stopped_reason.is_none() && skipped_points > 0 {
                stopped_reason = Some("source_flow_missing");
            }
        }
    }

    Ok(InjectOutcome {
        class: def.class.to_string(),
        tested,
        confirmed,
        stopped_reason: stopped_reason.map(str::to_string),
    })
}

/// The stored [`Flow::Http`] flows whose scheme, host and effective port
/// ([`url::Url::port_or_known_default`]) equal `target`'s, in store order:
/// every flow for `target == None`, none for an unparseable or hostless
/// `target`. Read-only — no traffic is issued and no scope/rate guard is
/// consulted — the "stored flows for this target" helper `scan.passive`,
/// `scan.inject` and `campaign` share.
pub fn target_flows(host: &CommandHost<'_>, target: Option<&str>) -> Vec<HttpFlow> {
    let wanted = match target {
        Some(t) => {
            let Ok(parsed) = url::Url::parse(t) else {
                return Vec::new();
            };
            if parsed.host_str().is_none() {
                return Vec::new();
            }
            Some(parsed)
        }
        None => None,
    };
    host.store()
        .list()
        .into_iter()
        .filter_map(|id| host.store().get(id))
        .filter_map(|flow| match flow {
            Flow::Http(http) => Some(http),
            _ => None,
        })
        .filter(|flow| match &wanted {
            None => true,
            Some(want) => flow_authority_matches(flow, want),
        })
        .collect()
}

/// Whether `flow`'s own scheme, host and effective port equal `target`'s.
fn flow_authority_matches(flow: &HttpFlow, target: &url::Url) -> bool {
    let Ok(flow_url) = url::Url::parse(&format!(
        "{}://{}/",
        flow.request.scheme, flow.request.authority
    )) else {
        return false;
    };
    flow_url.scheme() == target.scheme()
        && flow_url.host_str() == target.host_str()
        && flow_url.port_or_known_default() == target.port_or_known_default()
}

/// The points `def` applies to across `flows`: [`enumerate`] run over each
/// flow, kept only where the point's [`Location`] is one `def.locations`
/// names. Read-only — no traffic is issued. Shared with [`target_flows`] by
/// `scan.passive`, `scan.inject` and `campaign`.
pub fn class_points(flows: &[HttpFlow], def: &CheckDefinition) -> Vec<InjectionPoint> {
    flows
        .iter()
        .flat_map(enumerate)
        .filter(|p| def.locations.contains(&p.location))
        .collect()
}

/// Why a [`bounded`] future did not complete: the overall `deadline` had
/// already been reached when its internal timeout fired (`true`), or only the
/// fixed 60s cap had (`false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOut {
    pub at_deadline: bool,
}

/// Run `fut` under `tokio::time::timeout`, bounded by both `deadline` and a
/// fixed 60s cap — so a far-future `deadline` can never hold a slot for more
/// than a minute. `remaining = deadline.saturating_duration_since(now)`; the
/// timeout is `remaining.min(60s)`. Shared by `inject`, `reproduce_and_record`
/// and `run_class` so the time-bounding logic exists once.
pub async fn bounded<T>(
    deadline: Instant,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, TimedOut> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let budget = remaining.min(Duration::from_secs(60));
    match tokio::time::timeout(budget, fut).await {
        Ok(value) => Ok(value),
        Err(_elapsed) => Err(TimedOut {
            at_deadline: Instant::now() >= deadline,
        }),
    }
}

/// Read each applicable point's source request from the store once, so the run
/// iterates a stable snapshot rather than a store that its own replay flows are
/// evicting from. Returns the requests by flow id and how many points had no
/// source flow left to read.
fn snapshot_sources(
    host: &CommandHost<'_>,
    points: &[&InjectionPoint],
) -> (HashMap<FlowId, HttpRequest>, usize) {
    let mut sources: HashMap<FlowId, HttpRequest> = HashMap::new();
    let mut gone: HashSet<FlowId> = HashSet::new();
    let mut skipped_points = 0usize;
    for point in points {
        if sources.contains_key(&point.flow) {
            continue;
        }
        if gone.contains(&point.flow) {
            skipped_points += 1;
            continue;
        }
        match host.store().get(point.flow) {
            Some(Flow::Http(flow)) => {
                sources.insert(point.flow, flow.request);
            }
            _ => {
                gone.insert(point.flow);
                skipped_points += 1;
            }
        }
    }
    (sources, skipped_points)
}

/// The `stopped_reason` for a send error that is a guard refusal, or `None` for
/// anything else (a transport error). The match is exhaustive: a new
/// [`GuardError`] variant fails the build here until it is classified.
fn guard_stop_reason(err: &anyhow::Error) -> Option<&'static str> {
    Some(match err.downcast_ref::<GuardError>()? {
        GuardError::RateLimited { .. } => "rate_limited",
        GuardError::HostDisabled => "host_disabled",
        GuardError::OutOfScope(_) | GuardError::PrivateAddressBlocked(_) => "scope",
        GuardError::ConcurrencyExceeded => "concurrency_exceeded",
    })
}

/// Parse `target` into the `host:port` authority the scope/rate guard checks,
/// through the same parser the crawl uses for its seed
/// ([`crate::crawl::guard_authority_for`]): an absolute `http(s)` URL with a
/// host and no userinfo.
fn target_authority(target: &str) -> anyhow::Result<String> {
    crate::crawl::guard_authority_for(target).ok_or_else(|| {
        anyhow::anyhow!("inject: target is not an absolute, credential-free http(s) URL")
    })
}

/// Clone `original` and mutate only the one position `point` names, replacing
/// its current value with `value`. `None` when the named position is no
/// longer present (the flow's shape changed) or `point.location` is not one
/// any shipped [`CheckDefinition`] injects into (a header, cookie or path
/// segment): rather than guess at an unexercised mutation shape, the point is
/// skipped.
pub(crate) fn mutate_request(
    original: &HttpRequest,
    point: &InjectionPoint,
    value: &str,
) -> Option<HttpRequest> {
    let mut req = original.clone();
    match point.location {
        Location::Query => {
            req.path = mutate_query(&req.path, &point.name, value)?;
        }
        Location::BodyParam => {
            req.body = mutate_body(&req, &point.name, value)?;
        }
        // `discover::enumerate` reclassifies a URL-valued query *or* body
        // parameter as `Redirect`; the point no longer says which, so try the
        // query first, then the body.
        Location::Redirect => {
            if let Some(path) = mutate_query(&req.path, &point.name, value) {
                req.path = path;
            } else {
                req.body = mutate_body(&req, &point.name, value)?;
            }
        }
        Location::Header | Location::Cookie | Location::PathSegment => return None,
    }
    Some(req)
}

/// Rewrite the query parameter named `name` to `value`, percent-encoding it
/// through [`url::form_urlencoded`]'s serializer — never raw string
/// concatenation. `None` when there is no query string, or no parameter by
/// that name.
fn mutate_query(path: &str, name: &str, value: &str) -> Option<String> {
    let (base, query) = path.split_once('?')?;
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if !pairs.iter().any(|(k, _)| k == name) {
        return None;
    }
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    let mut replaced = false;
    for (k, v) in &pairs {
        if !replaced && k == name {
            out.append_pair(k, value);
            replaced = true;
        } else {
            out.append_pair(k, v);
        }
    }
    Some(format!("{base}?{}", out.finish()))
}

/// Rewrite the body parameter named `name` to `value`: a form-urlencoded field
/// is re-serialized (percent-encoded) the same way the query is; a JSON
/// object's top-level key is replaced with a JSON string (`serde_json` escapes
/// it). `None` when the body is neither shape, or carries no parameter by that
/// name.
fn mutate_body(req: &HttpRequest, name: &str, value: &str) -> Option<Body> {
    let bytes = body_bytes(&req.body)?;
    let ctype = req.headers.get("content-type").unwrap_or("");
    if ctype.contains("application/x-www-form-urlencoded") {
        let text = std::str::from_utf8(bytes).ok()?;
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if !pairs.iter().any(|(k, _)| k == name) {
            return None;
        }
        let mut out = url::form_urlencoded::Serializer::new(String::new());
        let mut replaced = false;
        for (k, v) in &pairs {
            if !replaced && k == name {
                out.append_pair(k, value);
                replaced = true;
            } else {
                out.append_pair(k, v);
            }
        }
        Some(Body::Bytes(out.finish().into_bytes()))
    } else if ctype.contains("application/json") {
        let mut json: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        let obj = json.as_object_mut()?;
        if !obj.contains_key(name) {
            return None;
        }
        obj.insert(
            name.to_string(),
            serde_json::Value::String(value.to_string()),
        );
        Some(Body::Bytes(serde_json::to_vec(&json).ok()?))
    } else {
        None
    }
}

/// Read a response body as text the same way `discover.rs`/`passive.rs` do: a
/// buffered body yields its bytes (lossily decoded), a still-streaming body
/// yields nothing.
fn response_text(body: &Body) -> String {
    body_bytes(body)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        ConnInfo, FlowId, FlowMeta, FlowStore, GuardError, HeaderMap, HttpFlow, HttpResponse,
        HttpVersion, InterceptState, MemFlowStore, ProxyClient, ScopeEntry, ScopeRateGuard,
        StdGuard,
    };
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use crate::discover::{enumerate, REDACTED};

    const TARGET: &str = "http://target.test/";

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn request(method: &str, path: &str, ctype: Option<&str>, body: Option<&str>) -> HttpRequest {
        let mut headers = HeaderMap::new();
        if let Some(ctype) = ctype {
            headers.set("Content-Type", ctype);
        }
        HttpRequest {
            method: method.into(),
            scheme: "http".into(),
            authority: "target.test".into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers,
            body: body.map_or(Body::Empty, |b| Body::Bytes(b.as_bytes().to_vec())),
            timestamp: SystemTime::now(),
        }
    }

    /// A completed (terminal) captured flow, as the store holds one after the
    /// proxy has seen the response.
    fn flow_of(request: HttpRequest) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request,
            response: Some(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                trailers: HeaderMap::new(),
                body: Body::Bytes(b"original".to_vec()),
                timestamp: SystemTime::now(),
                peer: None,
            }),
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    fn captured_flow(path: &str) -> HttpFlow {
        flow_of(request("GET", path, None, None))
    }

    fn captured_form_flow(path: &str, body: &str) -> HttpFlow {
        flow_of(request(
            "POST",
            path,
            Some("application/x-www-form-urlencoded"),
            Some(body),
        ))
    }

    fn scoped_guard() -> StdGuard {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "target.test".into(),
        });
        guard
    }

    fn query_value(path: &str, name: &str) -> Option<String> {
        let (_, query) = path.split_once('?')?;
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    fn form_value(req: &HttpRequest, name: &str) -> Option<String> {
        let bytes = body_bytes(&req.body)?;
        url::form_urlencoded::parse(bytes)
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    /// The captured flow a stub client answers a request with.
    fn reply(req: HttpRequest, status: u16, headers: &[(&str, &str)], body: &str) -> HttpFlow {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpFlow {
            id: FlowId::new(),
            request: req,
            response: Some(HttpResponse {
                status,
                version: HttpVersion::Http11,
                headers: map,
                trailers: HeaderMap::new(),
                body: Body::Bytes(body.as_bytes().to_vec()),
                timestamp: SystemTime::now(),
                peer: None,
            }),
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    /// An HTML page echoing `reflected`: raw (vulnerable) or HTML-escaped
    /// (patched).
    fn html_page(req: HttpRequest, reflected: &str, vulnerable: bool) -> HttpFlow {
        let shown = if vulnerable {
            reflected.to_string()
        } else {
            reflected.replace('<', "&lt;").replace('>', "&gt;")
        };
        reply(
            req,
            200,
            &[("Content-Type", "text/html; charset=utf-8")],
            &format!("<html><body>results for {shown}</body></html>"),
        )
    }

    /// A `ProxyClient` stub that reflects the `q` query parameter's *decoded*
    /// value back into an HTML response: raw (vulnerable) or HTML-escaped
    /// (patched). Mirrors `commands.rs`'s stub-client pattern.
    struct ReflectingClient {
        vulnerable: bool,
    }

    impl ProxyClient for ReflectingClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            let vulnerable = self.vulnerable;
            Box::pin(async move {
                let reflected = query_value(&req.path, "q").unwrap_or_default();
                Ok(html_page(req, &reflected, vulnerable))
            })
        }
    }

    /// A `ProxyClient` whose answer to each send is `script(n, request)` (`n` is
    /// the 0-based send index); it counts every send it receives.
    struct ScriptedClient<F> {
        sends: AtomicUsize,
        script: F,
    }

    impl<F> ScriptedClient<F>
    where
        F: Fn(usize, HttpRequest) -> anyhow::Result<HttpFlow> + Send + Sync,
    {
        fn new(script: F) -> Self {
            Self {
                sends: AtomicUsize::new(0),
                script,
            }
        }

        fn sends(&self) -> usize {
            self.sends.load(Ordering::SeqCst)
        }
    }

    impl<F> ProxyClient for ScriptedClient<F>
    where
        F: Fn(usize, HttpRequest) -> anyhow::Result<HttpFlow> + Send + Sync,
    {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            let n = self.sends.fetch_add(1, Ordering::SeqCst);
            let result = (self.script)(n, req);
            Box::pin(async move { result })
        }
    }

    /// Answers the first `fast` sends like a vulnerable page, then stalls
    /// forever, as a tarpit target does.
    struct TarpitClient {
        sends: AtomicUsize,
        fast: usize,
    }

    impl ProxyClient for TarpitClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            let n = self.sends.fetch_add(1, Ordering::SeqCst);
            if n < self.fast {
                let reflected = query_value(&req.path, "q").unwrap_or_default();
                return Box::pin(async move { Ok(html_page(req, &reflected, true)) });
            }
            Box::pin(futures::future::pending())
        }
    }

    /// Like the proxy's real client: every reply is captured into the store as a
    /// new replay flow, which can evict older ones.
    struct StoringClient {
        store: Arc<MemFlowStore>,
    }

    impl ProxyClient for StoringClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            let store = Arc::clone(&self.store);
            Box::pin(async move {
                let reflected = query_value(&req.path, "q").unwrap_or_default();
                let flow = html_page(req, &reflected, true);
                store.insert(aitm_core::Flow::Http(flow.clone()));
                Ok(flow)
            })
        }
    }

    /// A vulnerable open redirect: 302s to whatever `next` carries.
    fn redirecting(req: HttpRequest) -> HttpFlow {
        let next = query_value(&req.path, "next").unwrap_or_default();
        reply(req, 302, &[("Location", &next)], "")
    }

    async fn run(
        store: &dyn FlowStore,
        client: &dyn ProxyClient,
        guard: &StdGuard,
        def: &CheckDefinition,
        points: &[InjectionPoint],
        budget: &mut usize,
        cfg: &ScannerConfig,
    ) -> anyhow::Result<InjectOutcome> {
        let host = CommandHost::new(store, client, guard, None);
        inject(&host, TARGET, def, points, budget, cfg).await
    }

    fn store_with(flows: &[&HttpFlow]) -> MemFlowStore {
        let store = MemFlowStore::new();
        for flow in flows {
            store.insert(aitm_core::Flow::Http((*flow).clone()));
        }
        store
    }

    // ---- the engine: confirm / patched / budget ------------------------------

    #[tokio::test]
    async fn inject_confirms_on_vulnerable() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = ReflectingClient { vulnerable: true };
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.class, "reflected-xss");
        assert_eq!(outcome.tested, 8, "one point x the eight shipped payloads");
        assert_eq!(outcome.confirmed.len(), 8, "{outcome:?}");
        assert_eq!(
            outcome.stopped_reason, None,
            "a complete run reports no stop"
        );
        assert_eq!(budget, 92);
        let first = &outcome.confirmed[0];
        assert_eq!(first.injection_point.name, "q");
        assert_eq!(first.injection_point.location, Location::Query);
        assert_eq!(first.payload, "<aitm-canary-0001>");
        assert_eq!(first.evidence, "<aitm-canary-0001>");
    }

    #[tokio::test]
    async fn inject_empty_on_patched() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = ReflectingClient { vulnerable: false };
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(
            outcome.tested, 8,
            "the patched target was actually probed: {outcome:?}"
        );
        assert!(
            outcome.confirmed.is_empty(),
            "an escaped reflection must not confirm: {outcome:?}"
        );
        assert_eq!(outcome.stopped_reason, None);
    }

    #[tokio::test]
    async fn inject_stops_at_budget() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = ReflectingClient { vulnerable: true };
        let def = CheckDefinition::reflected_xss();
        assert!(
            def.payloads.len() > 1,
            "need more than one payload to observe the budget stop"
        );
        let points = enumerate(&flow);
        let mut budget = 1usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.tested, 1);
        assert_eq!(outcome.stopped_reason, Some("budget".to_string()));
        assert_eq!(budget, 0);
    }

    #[tokio::test]
    async fn inject_budget_spans_points() {
        // Two query points, sixteen payload sends in all; a budget of ten spends
        // all eight on `q` and the remaining two on `page`.
        let flow = captured_flow("/search?q=hello&page=2");
        let store = store_with(&[&flow]);
        let client = ReflectingClient { vulnerable: true };
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        assert_eq!(points.len(), 2, "{points:?}");
        let mut budget = 10usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.tested, 10);
        assert_eq!(outcome.stopped_reason, Some("budget".to_string()));
        assert_eq!(budget, 0);
        // Only `q` is reflected, so only its eight sends confirm.
        assert_eq!(outcome.confirmed.len(), 8, "{outcome:?}");
        assert!(outcome
            .confirmed
            .iter()
            .all(|c| c.injection_point.name == "q"));
    }

    #[tokio::test]
    async fn inject_out_of_scope_refused() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = ScriptedClient::new(|_, req| Ok(html_page(req, "", true)));
        let guard = StdGuard::default(); // empty scope: deny-by-default
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 10usize;

        let err = run(
            &store,
            &client,
            &guard,
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect_err("an out-of-scope target is refused before any send");

        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("target.test:80".to_string()))
        );
        assert_eq!(client.sends(), 0, "nothing was sent");
        assert_eq!(budget, 10);
    }

    // ---- other classes and locations -----------------------------------------

    #[tokio::test]
    async fn inject_open_redirect_confirms_on_location_at_sentinel() {
        let flow = captured_flow("/login?next=https://app.example/home");
        let store = store_with(&[&flow]);
        let client = ScriptedClient::new(|_, req| Ok(redirecting(req)));
        let def = CheckDefinition::open_redirect();
        let points = enumerate(&flow);
        assert!(
            points
                .iter()
                .any(|p| p.location == Location::Redirect && p.name == "next"),
            "`next` is classified as a redirect point: {points:?}"
        );
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.class, "open-redirect");
        assert_eq!(outcome.tested, 6);
        assert_eq!(outcome.confirmed.len(), 6, "{outcome:?}");
        assert_eq!(outcome.stopped_reason, None);
        let first = &outcome.confirmed[0];
        assert_eq!(first.injection_point.location, Location::Redirect);
        assert_eq!(first.injection_point.name, "next");
        assert_eq!(first.payload, "https://aitm-scan-sentinel.invalid/");
        assert_eq!(
            first.evidence,
            "Location header redirects to the off-origin scanner sentinel host"
        );
    }

    #[tokio::test]
    async fn inject_open_redirect_clean_when_location_is_fixed() {
        let flow = captured_flow("/login?next=https://app.example/home");
        let store = store_with(&[&flow]);
        let client =
            ScriptedClient::new(|_, req| Ok(reply(req, 302, &[("Location", "/home")], "")));
        let def = CheckDefinition::open_redirect();
        let points = enumerate(&flow);
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.tested, 6);
        assert!(outcome.confirmed.is_empty(), "{outcome:?}");
    }

    #[tokio::test]
    async fn inject_form_body_param() {
        let flow = captured_form_flow("/search", "q=hello&other=1");
        let store = store_with(&[&flow]);
        let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = Arc::clone(&bodies);
        let client = ScriptedClient::new(move |_, req| {
            let body = String::from_utf8(body_bytes(&req.body).unwrap_or_default().to_vec())
                .expect("utf-8 form body");
            seen.lock().expect("lock").push(body);
            let reflected = form_value(&req, "q").unwrap_or_default();
            Ok(html_page(req, &reflected, true))
        });
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        assert_eq!(
            points
                .iter()
                .filter(|p| p.location == Location::BodyParam)
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["q", "other"],
            "{points:?}"
        );
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.tested, 16);
        assert_eq!(outcome.confirmed.len(), 8, "{outcome:?}");
        assert!(outcome.confirmed.iter().all(|c| {
            c.injection_point.name == "q" && c.injection_point.location == Location::BodyParam
        }));
        // The payload went on the wire percent-encoded, the other field intact.
        assert_eq!(
            bodies.lock().expect("lock")[0],
            "q=%3Caitm-canary-0001%3E&other=1"
        );
    }

    // ---- Item 3: a send error must not discard the run -----------------------

    #[tokio::test]
    async fn inject_keeps_partial_results_when_the_guard_refuses_mid_run() {
        for (refusal, reason) in [
            (
                GuardError::RateLimited {
                    retry_after: Duration::from_secs(1),
                },
                "rate_limited",
            ),
            (GuardError::HostDisabled, "host_disabled"),
            (GuardError::OutOfScope("target.test:80".into()), "scope"),
            (
                GuardError::PrivateAddressBlocked("target.test:80".into()),
                "scope",
            ),
            (GuardError::ConcurrencyExceeded, "concurrency_exceeded"),
        ] {
            let flow = captured_flow("/search?q=hello");
            let store = store_with(&[&flow]);
            let err = refusal.clone();
            let client = ScriptedClient::new(move |n, req| {
                if n == 3 {
                    return Err(err.clone().into());
                }
                let reflected = query_value(&req.path, "q").unwrap_or_default();
                Ok(html_page(req, &reflected, true))
            });
            let def = CheckDefinition::reflected_xss();
            let points = enumerate(&flow);
            let mut budget = 100usize;

            let outcome = run(
                &store,
                &client,
                &scoped_guard(),
                &def,
                &points,
                &mut budget,
                &ScannerConfig::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("{refusal:?} must not discard the run: {e}"));

            assert_eq!(outcome.confirmed.len(), 3, "{refusal:?}: {outcome:?}");
            assert_eq!(outcome.tested, 3, "a refused request was never sent");
            assert_eq!(
                outcome.stopped_reason,
                Some(reason.to_string()),
                "{refusal:?}"
            );
            assert_eq!(budget, 97, "{refusal:?}");
            assert_eq!(client.sends(), 4, "the run stopped at the refusal");
        }
    }

    #[tokio::test]
    async fn inject_continues_past_a_transport_error() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = ScriptedClient::new(|n, req| {
            if n == 1 {
                return Err(anyhow::anyhow!("connection reset by peer"));
            }
            let reflected = query_value(&req.path, "q").unwrap_or_default();
            Ok(html_page(req, &reflected, true))
        });
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("a transport error is not fatal");

        assert_eq!(outcome.tested, 8, "the failed attempt still counts");
        assert_eq!(outcome.confirmed.len(), 7, "{outcome:?}");
        assert!(
            !outcome
                .confirmed
                .iter()
                .any(|c| c.payload == "<aitm-canary-0002>"),
            "the payload whose send failed cannot have confirmed"
        );
        assert_eq!(outcome.stopped_reason, None);
        assert_eq!(budget, 92);
    }

    // ---- Item 4: time_budget --------------------------------------------------

    #[tokio::test]
    async fn inject_stops_at_time_budget() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = ScriptedClient::new(|_, req| Ok(html_page(req, "", true)));
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;
        let cfg = ScannerConfig {
            time_budget: Duration::ZERO,
            ..ScannerConfig::default()
        };

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &cfg,
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.stopped_reason, Some("time_budget".to_string()));
        assert_eq!(outcome.tested, 0);
        assert_eq!(client.sends(), 0);
        assert_eq!(budget, 100);
    }

    #[tokio::test]
    async fn inject_time_budget_bounds_a_tarpit() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = TarpitClient {
            sends: AtomicUsize::new(0),
            fast: 2,
        };
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;
        let cfg = ScannerConfig {
            time_budget: Duration::from_millis(100),
            ..ScannerConfig::default()
        };

        // The outer timeout turns an unenforced budget into a failure, not a hang.
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            run(
                &store,
                &client,
                &scoped_guard(),
                &def,
                &points,
                &mut budget,
                &cfg,
            ),
        )
        .await
        .expect("the time budget must bound a send that never completes")
        .expect("inject succeeds");

        assert_eq!(outcome.stopped_reason, Some("time_budget".to_string()));
        assert_eq!(
            outcome.confirmed.len(),
            2,
            "earlier hits survive: {outcome:?}"
        );
        assert_eq!(outcome.tested, 3, "the stalled send counts");
        assert_eq!(budget, 97);
    }

    // ---- Item 5: source requests are snapshotted -----------------------------

    #[tokio::test]
    async fn inject_survives_source_flow_eviction() {
        // A store this small evicts the source flow as soon as the replays pile
        // up. Both points must still be tried in full.
        let flow = captured_flow("/search?q=hello&page=2");
        let store = Arc::new(MemFlowStore::with_capacity(2));
        store.insert(aitm_core::Flow::Http(flow.clone()));
        let client = StoringClient {
            store: Arc::clone(&store),
        };
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;

        let outcome = run(
            &*store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert!(
            store.get(flow.id).is_none(),
            "the scenario must actually evict the source flow"
        );
        assert_eq!(outcome.tested, 16, "{outcome:?}");
        assert_eq!(outcome.stopped_reason, None);
        assert_eq!(outcome.confirmed.len(), 8);
    }

    #[tokio::test]
    async fn inject_reports_source_flows_already_gone() {
        let kept = captured_flow("/search?q=hello");
        let gone = captured_flow("/other?q=hello");
        let store = store_with(&[&kept]); // `gone` was never stored (or was evicted)
        let client = ReflectingClient { vulnerable: true };
        let def = CheckDefinition::reflected_xss();
        let mut points = enumerate(&kept);
        points.extend(enumerate(&gone));
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.tested, 8, "only the surviving flow's point ran");
        assert_eq!(
            outcome.stopped_reason,
            Some("source_flow_missing".to_string()),
            "a run that skipped a point must not look complete"
        );
    }

    // ---- Item 6: no raw source value in the result ---------------------------

    #[tokio::test]
    async fn confirmed_never_carries_a_raw_source_value() {
        let flow = captured_flow("/go?next=https://app.example/cb?access_token=LEAKME99");
        let store = store_with(&[&flow]);
        let client = ScriptedClient::new(|_, req| Ok(redirecting(req)));
        let def = CheckDefinition::open_redirect();
        let points = enumerate(&flow);
        assert!(
            points.iter().any(|p| p.example.contains("LEAKME99")),
            "precondition: discovery kept the raw value: {points:?}"
        );
        let mut budget = 100usize;

        let outcome = run(
            &store,
            &client,
            &scoped_guard(),
            &def,
            &points,
            &mut budget,
            &ScannerConfig::default(),
        )
        .await
        .expect("inject succeeds");

        assert!(!outcome.confirmed.is_empty(), "{outcome:?}");
        for hit in &outcome.confirmed {
            assert_eq!(hit.injection_point.example, REDACTED);
        }
        assert!(
            !format!("{outcome:?}").contains("LEAKME99"),
            "the outcome's Debug output leaked a source value: {outcome:?}"
        );
    }

    // ---- Item 7: the target is parsed like the crawl seed --------------------

    #[tokio::test]
    async fn inject_rejects_a_target_with_userinfo() {
        let flow = captured_flow("/search?q=hello");
        let store = store_with(&[&flow]);
        let client = ScriptedClient::new(|_, req| Ok(html_page(req, "", true)));
        let guard = scoped_guard();
        let host = CommandHost::new(&store, &client, &guard, None);
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);

        for target in [
            "http://user:PW123SECRET@target.test/",
            "http://target.test@evil.example/",
            "ftp://target.test/",
            "not a url",
        ] {
            let mut budget = 10usize;
            let err = inject(
                &host,
                target,
                &def,
                &points,
                &mut budget,
                &ScannerConfig::default(),
            )
            .await
            .expect_err("a malformed or credentialed target is refused");
            assert!(
                !err.to_string().contains("PW123SECRET"),
                "the error echoed a credential: {err}"
            );
            assert_eq!(budget, 10);
        }
        assert_eq!(client.sends(), 0);
    }

    // ---- Item 10: the mutation primitives ------------------------------------

    fn bytes_of(body: &Body) -> &[u8] {
        body_bytes(body).expect("a buffered body")
    }

    #[test]
    fn mutate_query_replaces_only_the_named_value() {
        assert_eq!(
            mutate_query("/search?q=hello&page=2", "q", "<aitm-canary-0001>"),
            Some("/search?q=%3Caitm-canary-0001%3E&page=2".to_string())
        );
        // Duplicates: only the first occurrence is the injection point.
        assert_eq!(
            mutate_query("/s?q=a&q=b", "q", "X"),
            Some("/s?q=X&q=b".to_string())
        );
    }

    #[test]
    fn mutate_query_percent_encodes_instead_of_splicing() {
        assert_eq!(
            mutate_query("/s?q=a&z=1", "q", "<>\"&"),
            Some("/s?q=%3C%3E%22%26&z=1".to_string()),
            "`&` must not open a new parameter, nor `\"`/`<`/`>` reach the wire raw"
        );
        assert_eq!(
            mutate_query("/s?q=a", "q", "a b+c=d"),
            Some("/s?q=a+b%2Bc%3Dd".to_string())
        );
    }

    #[test]
    fn mutate_query_reencodes_the_other_params() {
        assert_eq!(
            mutate_query("/s?q=a&n=x%20y", "q", "P"),
            Some("/s?q=P&n=x+y".to_string())
        );
    }

    #[test]
    fn mutate_query_misses_are_none() {
        assert_eq!(mutate_query("/search", "q", "X"), None, "no query string");
        assert_eq!(mutate_query("/search?a=1", "q", "X"), None, "no such param");
    }

    #[test]
    fn mutate_body_form_percent_encodes() {
        let req = request(
            "POST",
            "/s",
            Some("application/x-www-form-urlencoded; charset=utf-8"),
            Some("q=hello&other=1"),
        );
        let body = mutate_body(&req, "q", "<>\"&").expect("form body mutates");
        assert_eq!(bytes_of(&body), b"q=%3C%3E%22%26&other=1");
    }

    #[test]
    fn mutate_body_json_escapes_instead_of_splicing() {
        let req = request(
            "POST",
            "/s",
            Some("application/json"),
            Some(r#"{"q":"hello","n":1}"#),
        );
        let body = mutate_body(&req, "q", "<>\"&").expect("json body mutates");
        let text = std::str::from_utf8(bytes_of(&body)).expect("utf-8");
        // The `"` is backslash-escaped inside one JSON string; nothing else moved.
        assert!(text.contains(r#""q":"<>\"&""#), "{text}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(text).expect("valid json"),
            serde_json::json!({"q": "<>\"&", "n": 1})
        );
    }

    #[test]
    fn mutate_body_misses_are_none() {
        let form = |body| {
            request(
                "POST",
                "/s",
                Some("application/x-www-form-urlencoded"),
                Some(body),
            )
        };
        let json = |body| request("POST", "/s", Some("application/json"), Some(body));
        assert!(
            mutate_body(&form("a=1"), "q", "X").is_none(),
            "no such field"
        );
        assert!(
            mutate_body(&json(r#"{"a":1}"#), "q", "X").is_none(),
            "no such key"
        );
        assert!(
            mutate_body(&json(r#"{"a":{"q":"x"}}"#), "q", "X").is_none(),
            "only top-level keys are injection points"
        );
        assert!(
            mutate_body(&json(r#"["q"]"#), "q", "X").is_none(),
            "not an object"
        );
        assert!(
            mutate_body(&json("{not json"), "q", "X").is_none(),
            "invalid json"
        );
        let text = request("POST", "/s", Some("text/plain"), Some("q=1"));
        assert!(mutate_body(&text, "q", "X").is_none(), "unsupported type");
        let bare = request("POST", "/s", None, Some("q=1"));
        assert!(mutate_body(&bare, "q", "X").is_none(), "no content type");
    }

    #[test]
    fn mutate_request_targets_exactly_the_named_position() {
        let flow = captured_flow("/s?q=hello");
        let at = |location, name: &str| InjectionPoint {
            flow: flow.id,
            location,
            name: name.to_string(),
            example: String::new(),
        };

        let mutated = mutate_request(&flow.request, &at(Location::Query, "q"), "X")
            .expect("query point mutates");
        assert_eq!(mutated.path, "/s?q=X");
        assert_eq!(flow.request.path, "/s?q=hello", "the original is untouched");

        // A redirect point is looked up in the query first.
        let redirected = mutate_request(&flow.request, &at(Location::Redirect, "q"), "X")
            .expect("redirect point mutates");
        assert_eq!(redirected.path, "/s?q=X");

        // ...then in the body.
        let form = request(
            "POST",
            "/s",
            Some("application/x-www-form-urlencoded"),
            Some("next=https%3A%2F%2Fapp.example%2F"),
        );
        let redirected = mutate_request(&form, &at(Location::Redirect, "next"), "Y")
            .expect("body redirect point mutates");
        assert_eq!(bytes_of(&redirected.body), b"next=Y");

        // A position that is gone, and locations no shipped class injects into.
        assert!(mutate_request(&flow.request, &at(Location::Query, "gone"), "X").is_none());
        for location in [Location::Header, Location::Cookie, Location::PathSegment] {
            assert!(mutate_request(&flow.request, &at(location, "q"), "X").is_none());
        }
    }

    // ---- stored-flow helpers: target_flows / class_points --------------------

    /// A captured flow at a given authority, carrying a header and a cookie
    /// alongside its `q` query parameter (so `class_points` has a header/cookie
    /// point to filter out).
    fn flow_at(authority: &str, path: &str) -> HttpFlow {
        let mut headers = HeaderMap::new();
        headers.set("X-Custom", "1");
        headers.set("Cookie", "session=abc");
        flow_of(HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        })
    }

    #[test]
    fn target_flows_and_class_points() {
        let t = flow_at("t.test:8080", "/search?q=hello");
        let other = flow_at("other.test:8080", "/search?q=hello");
        let store = store_with(&[&t, &other]);
        let client = ReflectingClient { vulnerable: true };
        let guard = StdGuard::default();
        let host = CommandHost::new(&store, &client, &guard, None);

        let only_t = target_flows(&host, Some("http://t.test:8080"));
        assert_eq!(only_t.iter().map(|f| f.id).collect::<Vec<_>>(), vec![t.id]);

        let both = target_flows(&host, None);
        let both_ids: HashSet<FlowId> = both.iter().map(|f| f.id).collect();
        assert_eq!(
            both_ids,
            HashSet::from([t.id, other.id]),
            "`None` returns every flow"
        );

        assert!(
            target_flows(&host, Some("not a url")).is_empty(),
            "an unparseable target returns none"
        );

        let points = class_points(std::slice::from_ref(&t), &CheckDefinition::reflected_xss());
        assert_eq!(
            points.len(),
            1,
            "only the `q` point: headers/cookies are not reflected-xss locations: {points:?}"
        );
        assert_eq!(points[0].name, "q");
        assert_eq!(points[0].location, Location::Query);
    }

    // ---- bounded ---------------------------------------------------------

    #[tokio::test]
    async fn bounded_respects_the_deadline() {
        let deadline = Instant::now() + Duration::from_millis(200);

        let result = bounded(deadline, tokio::time::sleep(Duration::from_secs(3))).await;
        assert_eq!(result, Err(TimedOut { at_deadline: true }));

        let result = bounded(deadline, futures::future::ready(7)).await;
        assert_eq!(result, Ok(7));
    }
}
