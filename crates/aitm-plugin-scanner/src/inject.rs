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
//! dropped immediately rather than held across the whole run. The scan is
//! additionally request-bounded: `budget` is decremented once per send and the
//! run stops the moment it reaches zero (`stopped_reason = Some("budget")`),
//! so a target that would otherwise exhaust the payload set across every point
//! cannot run unbounded.
//!
//! Only the one targeted position in a cloned request is ever mutated: a query
//! or body parameter is rewritten through `url::form_urlencoded`/JSON
//! re-serialization (percent-/JSON-escaped, never spliced into raw text), so a
//! payload carrying `<`/`>`/`"` cannot desync the request it rides in.
//! `confirm` still matches the *decoded* marker in the response body — nothing
//! about the payload's value changes, only how it is safely placed on the
//! wire.

use aitm_core::{Body, CommandHost, Flow, HttpRequest};

use crate::checks::{AttackMode, CheckDefinition};
use crate::discover::{body_bytes, InjectionPoint, Location};
use crate::ScannerConfig;

/// One per-attempt confirmation: the injection point and payload that
/// triggered a hit, plus a non-sensitive description of what matched
/// ([`crate::checks::Evidence::matched`] — a scanner constant, never response
/// text, a header value, or a secret).
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
    /// `Some("budget")` when the request budget ran out mid-run; `None` when
    /// every applicable point/payload combination was tried.
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
/// function learns to drive it). `*budget` is decremented once per request
/// actually sent; reaching zero stops the run immediately with
/// `stopped_reason = Some("budget")`.
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

    let mut tested = 0usize;
    let mut confirmed = Vec::new();
    let mut stopped_reason = None;

    match def.mode {
        AttackMode::BatteringRam => {
            'outer: for point in points
                .iter()
                .filter(|p| def.locations.contains(&p.location))
            {
                let Some(Flow::Http(flow)) = host.store().get(point.flow) else {
                    continue;
                };
                for payload in def.payloads.iter().take(cfg.per_class_payload_cap) {
                    if *budget == 0 {
                        stopped_reason = Some("budget".to_string());
                        break 'outer;
                    }
                    let Some(req) = mutate_request(&flow.request, point, &payload.value) else {
                        continue;
                    };

                    *budget -= 1;
                    tested += 1;

                    let sent = host.client().send(req).await?;
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
                            injection_point: point.clone(),
                            payload: payload.value.clone(),
                            evidence: evidence.matched,
                        });
                    }
                }
            }
        }
    }

    Ok(InjectOutcome {
        class: def.class.to_string(),
        tested,
        confirmed,
        stopped_reason,
    })
}

/// Parse `target` into the `host:port` authority the scope/rate guard checks —
/// the same fold `crate::crawl::crawl` uses for its seed. Duplicated here
/// (not exposed from `crawl`, and this module must not depend on it for a
/// private helper) rather than widened past an absolute, credential-free
/// `http(s)` URL.
fn target_authority(target: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(target.trim())
        .map_err(|_| anyhow::anyhow!("inject: target is not an absolute http(s) URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("inject: target is not an absolute http(s) URL");
    }
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow::anyhow!("inject: target has no host"))?;
    let port = url.port_or_known_default().unwrap_or(0);
    Ok(format!("{host}:{port}"))
}

/// Clone `original` and mutate only the one position `point` names, replacing
/// its current value with `value`. `None` when the named position is no
/// longer present (the flow's shape changed) or `point.location` is not one
/// any shipped [`CheckDefinition`] injects into (a header, cookie or path
/// segment): rather than guess at an unexercised mutation shape, the point is
/// skipped.
fn mutate_request(
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
        ConnInfo, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow, HttpResponse, HttpVersion,
        InterceptState, MemFlowStore, ProxyClient, ScopeEntry, ScopeRateGuard, StdGuard,
    };
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::SystemTime;

    use crate::discover::enumerate;

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn captured_flow(path: &str) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "target.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
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
                let body = if vulnerable {
                    format!("<html><body>results for {reflected}</body></html>")
                } else {
                    let escaped = reflected.replace('<', "&lt;").replace('>', "&gt;");
                    format!("<html><body>results for {escaped}</body></html>")
                };
                let mut headers = HeaderMap::new();
                headers.set("Content-Type", "text/html; charset=utf-8");
                Ok(HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(HttpResponse {
                        status: 200,
                        version: HttpVersion::Http11,
                        headers,
                        body: Body::Bytes(body.into_bytes()),
                        timestamp: SystemTime::now(),
                    }),
                    client_conn: conn(),
                    server_conn: None,
                    metadata: FlowMeta::default(),
                    intercept: InterceptState::Observed,
                })
            })
        }
    }

    #[tokio::test]
    async fn inject_confirms_on_vulnerable() {
        let flow = captured_flow("/search?q=hello");
        let store = MemFlowStore::new();
        store.insert(Flow::Http(flow.clone()));
        let guard = scoped_guard();
        let client = ReflectingClient { vulnerable: true };
        let host = CommandHost::new(&store, &client, &guard, None);
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;
        let cfg = ScannerConfig::default();

        let outcome = inject(
            &host,
            "http://target.test/",
            &def,
            &points,
            &mut budget,
            &cfg,
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.class, "reflected-xss");
        assert!(
            !outcome.confirmed.is_empty(),
            "expected a confirmed hit against the vulnerable stub: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn inject_empty_on_patched() {
        let flow = captured_flow("/search?q=hello");
        let store = MemFlowStore::new();
        store.insert(Flow::Http(flow.clone()));
        let guard = scoped_guard();
        let client = ReflectingClient { vulnerable: false };
        let host = CommandHost::new(&store, &client, &guard, None);
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 100usize;
        let cfg = ScannerConfig::default();

        let outcome = inject(
            &host,
            "http://target.test/",
            &def,
            &points,
            &mut budget,
            &cfg,
        )
        .await
        .expect("inject succeeds");

        assert!(
            outcome.confirmed.is_empty(),
            "an escaped reflection must not confirm: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn inject_stops_at_budget() {
        let flow = captured_flow("/search?q=hello");
        let store = MemFlowStore::new();
        store.insert(Flow::Http(flow.clone()));
        let guard = scoped_guard();
        let client = ReflectingClient { vulnerable: true };
        let host = CommandHost::new(&store, &client, &guard, None);
        let def = CheckDefinition::reflected_xss();
        assert!(
            def.payloads.len() > 1,
            "need more than one payload to observe the budget stop"
        );
        let points = enumerate(&flow);
        let mut budget = 1usize;
        let cfg = ScannerConfig::default();

        let outcome = inject(
            &host,
            "http://target.test/",
            &def,
            &points,
            &mut budget,
            &cfg,
        )
        .await
        .expect("inject succeeds");

        assert_eq!(outcome.tested, 1);
        assert_eq!(outcome.stopped_reason, Some("budget".to_string()));
        assert_eq!(budget, 0);
    }

    #[tokio::test]
    async fn inject_refuses_out_of_scope() {
        let flow = captured_flow("/search?q=hello");
        let store = MemFlowStore::new();
        store.insert(Flow::Http(flow.clone()));
        let guard = StdGuard::default(); // empty scope: deny-by-default
        let client = ReflectingClient { vulnerable: true };
        let host = CommandHost::new(&store, &client, &guard, None);
        let def = CheckDefinition::reflected_xss();
        let points = enumerate(&flow);
        let mut budget = 10usize;
        let cfg = ScannerConfig::default();

        let err = inject(
            &host,
            "http://target.test/",
            &def,
            &points,
            &mut budget,
            &cfg,
        )
        .await
        .expect_err("an out-of-scope target is refused before any send");

        assert_eq!(
            err.downcast_ref::<aitm_core::GuardError>(),
            Some(&aitm_core::GuardError::OutOfScope(
                "target.test:80".to_string()
            ))
        );
    }
}
