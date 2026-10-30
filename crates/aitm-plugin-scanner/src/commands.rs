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
//! out-of-scope target is refused before the crawl begins.

use std::collections::{BTreeMap, HashSet};

use aitm_core::{
    Command, CommandHost, Flow, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::crawl::{block_on, crawl, normalize_url};
use crate::discover::{enumerate, Location};
use crate::ScannerConfig;

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
        // `GuardError::OutOfScope` here, before the crawl begins. The permit is
        // dropped immediately — we only need the gate check.
        let authority = target_authority(target)?;
        let _permit = host
            .guard()
            .check_active(authority)
            .map_err(anyhow::Error::new)?;

        let outcome = block_on(crawl(host, target, &cfg))?;

        // Enumerate injection points from the captured requests whose normalized
        // URL is one of the reached endpoints — observed traffic only.
        let endpoint_set: HashSet<&str> = outcome.endpoints.iter().map(String::as_str).collect();
        let mut injection_points: Vec<Value> = Vec::new();
        for id in host.store().list() {
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
                let mut obj = BTreeMap::new();
                obj.insert("flow".into(), Value::Str(point.flow.to_string()));
                obj.insert(
                    "location".into(),
                    Value::Str(location_token(&point.location).to_string()),
                );
                obj.insert("name".into(), Value::Str(point.name));
                obj.insert("example".into(), Value::Str(point.example));
                injection_points.push(Value::Object(obj));
            }
        }

        let mut result = BTreeMap::new();
        result.insert(
            "endpoints".into(),
            Value::Array(outcome.endpoints.into_iter().map(Value::Str).collect()),
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

/// The lowercase wire token for a discovered injection point's location.
fn location_token(location: &Location) -> &'static str {
    match location {
        Location::Query => "query",
        Location::BodyParam => "body_param",
        Location::Header => "header",
        Location::Cookie => "cookie",
        Location::PathSegment => "path_segment",
        Location::Redirect => "redirect",
    }
}

/// The `host[:port]` authority the scope guard is asked about, parsed from an
/// absolute `http(s)` target URL. Userinfo is dropped; nothing is lowercased
/// here — the guard normalizes.
fn target_authority(target: &str) -> anyhow::Result<&str> {
    let (_scheme, rest) = target
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("target is not an absolute http(s) URL: {target:?}"))?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if authority.is_empty() {
        anyhow::bail!("target has no host: {target:?}");
    }
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
    use futures::future::BoxFuture;

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
        let guard_err = err.downcast_ref::<aitm_core::GuardError>();
        assert!(
            matches!(guard_err, Some(aitm_core::GuardError::OutOfScope(_)))
                || err.to_string().to_lowercase().contains("scope"),
            "expected an out-of-scope refusal, got: {err}"
        );
    }
}
