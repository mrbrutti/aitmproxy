//! The `scan.discover` command: read-only endpoint discovery.
//!
//! It crawls one operator-authorized, in-scope target (same-origin, scope-bound,
//! budget-capped — see [`crate::crawl`]) and enumerates the parameter names
//! present in the requests already captured for the reached endpoints (see
//! [`crate::discover`]). It performs **no** injection and **no** fuzzing: it only
//! lists reachable URLs and the injection points visible in observed traffic.
//!
//! Deny-by-default throughout: the target host is gated through
//! [`aitm_core::ScopeRateGuard::check_active`] before any navigation, so an
//! out-of-scope target is refused before the crawl begins, and every page the
//! crawl then visits takes its own permit.
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

use crate::crawl::{block_on, crawl, normalize_url, target_authority};
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
                          `max_depth`/`max_pages` may lower the configured caps, never raise them."
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

        // Deny-by-default: gate the target host through the scope/rate guard
        // before any navigation. An out-of-scope target returns
        // `GuardError::OutOfScope` here, before the crawl begins. The authority
        // is derived with the same WHATWG parser the crawl and the browser use,
        // so the host gated here is the host that is navigated.
        //
        // The permit is held across the crawl: this command occupies one
        // concurrency slot for its whole run, and every page inside the crawl
        // takes a further permit of its own.
        let authority = target_authority(target)?;
        let permit = host.guard().check_active(&authority)?;

        let outcome = block_on(crawl(host, target, &cfg))?;
        drop(permit);

        // Enumerate injection points from the captured requests whose normalized
        // URL is one of the reached endpoints — observed traffic only.
        let endpoint_set: HashSet<&str> = outcome.endpoints.iter().map(String::as_str).collect();
        let mut injection_points: Vec<Value> = Vec::new();
        for id in host.store().list() {
            if injection_points.len() >= MAX_RESULT_ITEMS {
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
        Body, ConnInfo, FlowId, FlowMeta, FlowStore, GuardError, HeaderMap, HttpFlow, HttpRequest,
        HttpVersion, InterceptState, MemFlowStore, ProxyClient, ScopeEntry, ScopeRateGuard,
        StdGuard,
    };
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::SystemTime;

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
        headers.set("Cookie", "session_token=s3cr3t-value; theme=dark");
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
