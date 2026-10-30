//! The `scan.discover` command: read-only endpoint discovery.
//!
//! It crawls one operator-authorized, in-scope target (same-origin, scope-bound,
//! budget-capped — see [`crate::crawl`]) and enumerates the parameter names
//! present in the requests already captured for the reached endpoints (see
//! [`crate::discover`]). It performs **no** injection and **no** fuzzing: it only
//! lists reachable URLs and the injection points visible in observed traffic.
//!
//! Deny-by-default throughout: the crawl gates the target host through
//! [`aitm_core::ScopeRateGuard::check_active`] before its first navigation, so
//! an out-of-scope target is refused before anything is fetched, and every page
//! the crawl then visits takes its own permit. The crawl also runs under a
//! campaign hold on the proxy's browser-egress posture
//! ([`aitm_core::EgressConfinement::confine`]), so the browser-facing connector
//! refuses an out-of-scope public host before dialing it; the hold is an RAII
//! token released when the command returns.
//!
//! The result carries no credentials: [`crate::discover::enumerate`] replaces a
//! secret-named point's example with a placeholder, and every free-text string
//! that reaches the caller is additionally run through
//! [`aitm_core::redact::scrub_text`], so a token embedded in a URL's query is
//! masked as well.

use std::collections::{BTreeMap, HashSet};

use aitm_core::redact::scrub_text;
use aitm_core::{
    Command, CommandHost, Flow, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::crawl::{block_on, crawl, normalize_url};
use crate::discover::enumerate;
use crate::ScannerConfig;

/// Upper bound on each array in the result, so a long crawl cannot return an
/// unbounded object to the caller.
const MAX_RESULT_ITEMS: usize = 1024;

/// `scan.discover` — list reachable in-scope URLs and the parameter names
/// present in captured requests. Registered by [`crate::ScannerPlugin`].
pub(crate) struct ScanDiscover {
    pub(crate) cfg: ScannerConfig,
}

impl Command for ScanDiscover {
    fn name(&self) -> &str {
        "scan.discover"
    }

    fn sensitivity(&self) -> Sensitivity {
        // A scope/rate-bounded testing verb: it drives the browser against an
        // authorized target. Read-only in intent, but it issues navigations, so
        // it is `Write`, not `Read`.
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Discover reachable in-scope URLs under `target` (same-origin, \
                          scope-bound, budget-capped) and enumerate the injection points \
                          visible in captured requests. No injection or fuzzing is performed. \
                          `max_depth`/`max_pages` may lower the configured caps, never raise them. \
                          A navigation that lands off-origin or out of scope (a redirect) aborts \
                          the crawl with `stopped_reason = \"left_scope\"`. While the crawl runs \
                          the proxy's browser-egress posture is held confined, so the embedded \
                          browser cannot fetch an out-of-scope public host (sub-resource or \
                          redirect target); the hold is released when the command returns."
                .into(),
            params: vec![
                ParamDef {
                    name: "target".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The in-scope seed URL, e.g. `https://app.example/`.".into(),
                },
                ParamDef {
                    name: "max_depth".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Link depth to follow (clamped to the configured cap).".into(),
                },
                ParamDef {
                    name: "max_pages".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Pages to visit (clamped to the configured cap).".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let target = args.get_str("target")?;

        // Optional budget overrides may only *lower* the configured caps, never
        // raise them — the operator's config is the ceiling.
        let mut cfg = self.cfg.clone();
        if args.get("max_depth").is_some() {
            let requested = usize::try_from(args.get_int("max_depth")?)
                .map_err(|_| anyhow::anyhow!("`max_depth` must be non-negative"))?;
            cfg.max_depth = cfg.max_depth.min(requested);
        }
        if args.get("max_pages").is_some() {
            let requested = usize::try_from(args.get_int("max_pages")?)
                .map_err(|_| anyhow::anyhow!("`max_pages` must be non-negative"))?;
            cfg.max_pages = cfg.max_pages.min(requested);
        }

        // Deny-by-default: the crawl gates the seed through the scope/rate
        // guard before its first navigation (and the no-browser fallback takes
        // one permit of its own), so an out-of-scope target returns
        // `GuardError::OutOfScope` before anything is fetched. The gate lives in
        // one place on purpose: a second `check_active` here for the same seed
        // would spend a second rate token and a second concurrency slot, and
        // with `max_concurrency == 1` would refuse the crawl's own permit.
        //
        // S2: run the whole crawl under a campaign hold on the proxy's
        // browser-egress posture, so the `SsrfConnector` refuses any
        // out-of-scope public host the browser is sent to (a redirect, a
        // sub-resource) *before* dialing it. The RAII token is dropped when
        // `invoke` returns — on success, error, or unwind — so a finished scan
        // never leaves the posture confined (`set_base` would). A host with no
        // posture wired crawls unconfined, as before; the `left_scope` abort in
        // the crawl stays as defense-in-depth.
        let _confine = host.egress_handle().map(|e| e.confine());
        let outcome = block_on(crawl(host, target, &cfg))?;

        // Enumerate injection points from the captured requests whose normalized
        // URL is one of the reached endpoints — observed traffic only.
        // Capped at MAX_RESULT_ITEMS to match the exposed `endpoints` array (which is
        // `.take(MAX_RESULT_ITEMS)` below), so `endpoint_flows` and `endpoints` stay in
        // lockstep and neither grows unbounded on a long crawl.
        let endpoint_set: HashSet<&str> = outcome
            .endpoints
            .iter()
            .take(MAX_RESULT_ITEMS)
            .map(String::as_str)
            .collect();
        let mut injection_points: Vec<Value> = Vec::new();
        // Map each reached endpoint (keyed by the same scrubbed URL the result
        // exposes in `endpoints`) to the first captured flow that served it, so a UI
        // can link an endpoint row to its flow (AC3). Bounded by `endpoint_set` (<=
        // MAX_RESULT_ITEMS), i.e. capped like the arrays; an endpoint with no captured
        // flow is simply absent from the map.
        let mut endpoint_flows: BTreeMap<String, Value> = BTreeMap::new();
        for id in host.store().list() {
            if injection_points.len() >= MAX_RESULT_ITEMS
                && endpoint_flows.len() >= endpoint_set.len()
            {
                break;
            }
            let Some(Flow::Http(flow)) = host.store().get(id) else {
                continue;
            };
            let req = &flow.request;
            let raw = format!("{}://{}{}", req.scheme, req.authority, req.path);
            let Some(normalized) = normalize_url(&raw) else {
                continue;
            };
            if !endpoint_set.contains(normalized.as_str()) {
                continue;
            }
            endpoint_flows
                .entry(scrub_text(&normalized))
                .or_insert_with(|| Value::Str(id.to_string()));
            if injection_points.len() >= MAX_RESULT_ITEMS {
                continue;
            }
            for point in enumerate(&flow) {
                if injection_points.len() >= MAX_RESULT_ITEMS {
                    break;
                }
                let mut obj = BTreeMap::new();
                obj.insert("flow".into(), Value::Str(point.flow.to_string()));
                obj.insert(
                    "location".into(),
                    Value::Str(point.location.as_str().to_string()),
                );
                obj.insert("name".into(), Value::Str(point.name));
                // `enumerate` has already replaced a secret-named example; this
                // catches a credential embedded inside an otherwise innocent
                // value (`next=…?access_token=…`).
                obj.insert("example".into(), Value::Str(scrub_text(&point.example)));
                injection_points.push(Value::Object(obj));
            }
        }

        let mut result = BTreeMap::new();
        result.insert(
            "endpoints".into(),
            Value::Array(
                outcome
                    .endpoints
                    .iter()
                    .take(MAX_RESULT_ITEMS)
                    // A reached URL can carry a token in its query string.
                    .map(|url| Value::Str(scrub_text(url)))
                    .collect(),
            ),
        );
        result.insert("injection_points".into(), Value::Array(injection_points));
        // endpoint URL (scrubbed, matching an entry in `endpoints`) -> flow id.
        result.insert("endpoint_flows".into(), Value::Object(endpoint_flows));
        result.insert(
            "pages_crawled".into(),
            Value::Int(i64::try_from(outcome.pages_crawled).unwrap_or(i64::MAX)),
        );
        result.insert(
            "stopped_reason".into(),
            outcome.stopped_reason.map_or(Value::Null, Value::Str),
        );
        Ok(Value::Object(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, BrowserDriver, ClickTarget, ConnInfo, EgressConfinement, FlowId, FlowMeta, FlowStore,
        GuardError, HeaderMap, HttpFlow, HttpRequest, HttpVersion, InterceptState, MemFlowStore,
        NavOutcome, ProxyClient, ScopeEntry, ScopeRateGuard, StdGuard,
    };
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    /// A browser that serves one fixed page and, at every `navigate()`, records
    /// whether the shared egress posture was confined at that instant — the
    /// moment the real browser would be issuing the request.
    struct PostureProbeBrowser {
        posture: Arc<EgressConfinement>,
        observed: Mutex<Vec<bool>>,
    }

    impl PostureProbeBrowser {
        fn new(posture: Arc<EgressConfinement>) -> Self {
            Self {
                posture,
                observed: Mutex::new(Vec::new()),
            }
        }

        /// `confined()` as seen at each navigation, in order.
        fn observed(&self) -> Vec<bool> {
            self.observed.lock().expect("observed lock").clone()
        }
    }

    impl BrowserDriver for PostureProbeBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed lock")
                    .push(self.posture.confined());
                Ok(NavOutcome {
                    final_url: url,
                    status: Some(200),
                })
            })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never clicks") })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never types") })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { unimplemented!("the crawler never screenshots") })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { unimplemented!("the crawler never evals") })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok(r#"<a href="/one">one</a>"#.to_string()) })
        }
    }

    /// A `ProxyClient` the command must never reach: discovery is read-only and
    /// crawls through the browser, never the proxy client.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("scan.discover must not send through the proxy client: {req:?}");
        }
    }

    fn params(pairs: &[(&str, Value)]) -> Params {
        Params::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn captured(path: &str, headers: HeaderMap) -> Flow {
        Flow::Http(HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "target.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers,
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        })
    }

    fn scoped_guard() -> StdGuard {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "target.test".into(),
        });
        guard
    }

    /// Every string anywhere in a result value.
    fn strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Str(s) => out.push(s.clone()),
            Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
            Value::Object(map) => map.iter().for_each(|(k, v)| {
                out.push(k.clone());
                strings(v, out);
            }),
            _ => {}
        }
    }

    fn endpoints_of(result: &Value) -> Vec<String> {
        let Value::Object(map) = result else {
            panic!("the result is an object: {result:?}");
        };
        let Some(Value::Array(items)) = map.get("endpoints") else {
            panic!("the result carries an endpoints array: {result:?}");
        };
        items
            .iter()
            .filter_map(|v| match v {
                Value::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn scan_discover_is_write() {
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };
        assert_eq!(cmd.sensitivity(), Sensitivity::Write);
    }

    #[test]
    fn scan_discover_out_of_scope_refused() {
        let store = MemFlowStore::new();
        let guard = StdGuard::default(); // empty scope: deny-by-default
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let err = cmd
            .invoke(
                params(&[("target", Value::Str("http://unscoped.example/".into()))]),
                &host,
            )
            .expect_err("an out-of-scope target is refused before any crawl");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("unscoped.example:80".into()))
        );
    }

    /// The anti-goal, at the command boundary: no secret the operator's captured
    /// traffic carried may appear anywhere in the structured result.
    #[test]
    fn discover_result_has_no_secret() {
        let mut headers = HeaderMap::new();
        headers.set("Authorization", "Bearer s3cr3t-value");
        // `PHPSESSID` carries no secret keyword in its name: it is caught only
        // because every cookie value is redacted.
        headers.set(
            "Cookie",
            "session_token=s3cr3t-value; PHPSESSID=s3cr3t-value; theme=dark",
        );
        let store = MemFlowStore::new();
        store.insert(captured("/x?access_token=s3cr3t-value&q=1", headers));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("an in-scope target with no browser falls back to the store");

        let mut found = Vec::new();
        strings(&result, &mut found);
        assert!(
            !found.iter().any(|s| s.contains("s3cr3t-value")),
            "a captured secret reached the result: {found:?}"
        );
        // The shape is still useful: the names survive, only the values go.
        assert!(
            found.iter().any(|s| s == "access_token"),
            "the injection point name must survive redaction: {found:?}"
        );
        assert!(
            found.iter().any(|s| s == "Authorization"),
            "the header point name must survive redaction: {found:?}"
        );
    }

    /// AC3: every reached endpoint is mapped to the flow that served it, so a UI
    /// can link an endpoint row to its capture. The mapping points at the same flow
    /// the endpoint's injection points were enumerated from.
    #[test]
    fn discover_links_each_endpoint_to_its_flow() {
        let store = MemFlowStore::new();
        store.insert(captured("/one?q=1", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("an in-scope target with no browser falls back to the store");

        let Value::Object(map) = &result else {
            panic!("object result: {result:?}");
        };
        let endpoint = endpoints_of(&result)
            .into_iter()
            .next()
            .expect("one reached endpoint");
        assert_eq!(endpoint, "http://target.test/one?q=1");

        // endpoint_flows links that endpoint to a flow id...
        let Some(Value::Object(ef)) = map.get("endpoint_flows") else {
            panic!("the result carries an endpoint_flows map: {result:?}");
        };
        let Some(Value::Str(flow_id)) = ef.get(&endpoint) else {
            panic!("the endpoint links to its flow: {result:?}");
        };

        // ...and it is the same flow the `q` injection point was found in.
        let Some(Value::Array(points)) = map.get("injection_points") else {
            panic!("injection_points array: {result:?}");
        };
        let q_point = points
            .iter()
            .find(
                |p| matches!(p, Value::Object(o) if o.get("name") == Some(&Value::Str("q".into()))),
            )
            .expect("a q injection point");
        let Value::Object(o) = q_point else {
            unreachable!()
        };
        assert_eq!(
            o.get("flow"),
            Some(&Value::Str(flow_id.clone())),
            "endpoint_flows points at the same flow as its injection point",
        );
    }

    /// The seed is gated exactly once: with a concurrency cap of one, a second
    /// `check_active` for the same seed would refuse the command's own crawl.
    #[test]
    fn scan_discover_runs_under_max_concurrency_one() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        let guard = StdGuard::new(aitm_core::LimitConfig {
            max_concurrency: 1,
            ..aitm_core::LimitConfig::default()
        });
        guard.add_scope(ScopeEntry {
            host: "target.test".into(),
        });
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("one permit for the seed, not two");

        assert_eq!(endpoints_of(&result), vec!["http://target.test/one"]);
    }

    /// `max_pages` may lower the configured cap.
    #[test]
    fn scan_discover_max_pages_lowers_the_cap() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        store.insert(captured("/two", HeaderMap::new()));
        store.insert(captured("/three", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let result = cmd
            .invoke(
                params(&[
                    ("target", Value::Str("http://target.test/".into())),
                    ("max_pages", Value::Int(1)),
                ]),
                &host,
            )
            .expect("scan.discover succeeds");

        assert_eq!(endpoints_of(&result), vec!["http://target.test/one"]);
    }

    /// `max_pages` may never raise it.
    #[test]
    fn scan_discover_max_pages_cannot_raise_the_cap() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        store.insert(captured("/two", HeaderMap::new()));
        store.insert(captured("/three", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig {
                max_pages: 2,
                ..ScannerConfig::default()
            },
        };

        let result = cmd
            .invoke(
                params(&[
                    ("target", Value::Str("http://target.test/".into())),
                    ("max_pages", Value::Int(500)),
                ]),
                &host,
            )
            .expect("scan.discover succeeds");

        assert_eq!(
            endpoints_of(&result),
            vec!["http://target.test/one", "http://target.test/two"],
            "the configured cap of 2 holds against a request for 500"
        );
    }

    #[test]
    fn scan_discover_rejects_a_negative_budget() {
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let err = cmd
            .invoke(
                params(&[
                    ("target", Value::Str("http://target.test/".into())),
                    ("max_depth", Value::Int(-1)),
                ]),
                &host,
            )
            .expect_err("a negative budget is an error, not a wrap-around");
        assert!(
            err.to_string().contains("non-negative"),
            "explains the refusal: {err}"
        );
    }

    /// S2, the real fix: the crawl runs under a campaign hold on the proxy's
    /// browser-egress posture, so every navigation the browser issues happens
    /// while the `SsrfConnector` refuses out-of-scope public hosts — and the
    /// hold is released the moment `invoke` returns, leaving the standing (off)
    /// base untouched.
    #[test]
    fn scan_discover_crawls_under_egress_confinement() {
        let posture = Arc::new(EgressConfinement::new(false));
        let browser = PostureProbeBrowser::new(posture.clone());
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let client = NoSendClient;
        let host =
            CommandHost::new(&store, &client, &guard, Some(&browser)).with_egress(posture.clone());
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };
        assert!(!posture.confined(), "fixture starts with the free posture");

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("an in-scope seed crawls");

        // The crawl really navigated (seed + the one harvested link).
        assert_eq!(
            endpoints_of(&result),
            vec!["http://target.test/", "http://target.test/one"]
        );
        // (a) every navigation saw the posture confined.
        assert_eq!(
            browser.observed(),
            vec![true, true],
            "each navigation must run while egress is confined"
        );
        // (b) the hold is released when the command returns: the base was off
        // and stays off, so a finished scan never leaves the browser confined.
        assert!(
            !posture.confined(),
            "the campaign hold must be released after invoke returns"
        );
    }

    /// Without a wired posture (a frontend that never attached one) the crawl
    /// runs exactly as before: there is nothing to hold, and nothing errors.
    #[test]
    fn scan_discover_without_egress_handle_still_crawls() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        assert!(host.egress_handle().is_none());
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("no posture wired is not an error");
        assert_eq!(endpoints_of(&result), vec!["http://target.test/one"]);
    }

    /// The target gate and the crawl use one parser, so a URL whose real host is
    /// `evil.com` is refused even under a `*.target.test` scope entry.
    #[test]
    fn scan_discover_refuses_a_backslash_host_bypass() {
        let store = MemFlowStore::new();
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "*.target.test".into(),
        });
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover {
            cfg: ScannerConfig::default(),
        };

        let err = cmd
            .invoke(
                params(&[(
                    "target",
                    Value::Str("http://evil.com\\.target.test/".into()),
                )]),
                &host,
            )
            .expect_err("the real host is out of scope");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("evil.com:80".into()))
        );
    }
}
