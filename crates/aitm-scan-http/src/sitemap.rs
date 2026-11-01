//! `SiteMapBuilder`, node ids and authentication marking (task 12).
//!
//! The site map is the scheduler's view of the target (spec D8.1, "Site map"):
//! one [`SiteNode`] per `(method, scheme, host, port, path_template)`, built
//! from crawl results *and* from already-captured in-scope flows, so proxied
//! traffic seeds an audit without a crawl. Collapsing variable segments into a
//! template ([`path_template`]) is what keeps `/account/1`, `/account/2`, …
//! from becoming a thousand nodes the audit would probe a thousand times.
//!
//! Three things a reviewer should be able to check here:
//!
//! - **The node key is the template, not the URL.** Two requests that differ
//!   only in an id, UUID or object id merge: their flows accumulate, their
//!   `(kind, name)` parameters union, and `auth` is the OR over every request
//!   that mapped to the node (one authenticated visit makes the node
//!   authenticated).
//! - **Ids are pure.** [`node_id`] hashes the key and nothing else, so the same
//!   target yields the same ids in every run, every process and every job —
//!   which is what lets a UI keep a selection across a re-scan.
//! - **No value is held here.** A node carries parameter *names*; the points it
//!   collects were already redacted by `points::enumerate_v2`. This module adds
//!   no example, no header value and no log line.

use std::collections::HashMap;

use aitm_core::{FlowId, HttpRequest};
use aitm_scan_model::{
    Discovery, FlowRef, InsertionKind, InsertionPoint, NodeId, ParamRef, SessionMaterial, SiteNode,
};

use crate::hash::fnv1a64;
use crate::points::Enumerated;
use crate::template::path_template;
use crate::url_norm::request_url;

/// The headers that mark a request as carrying credentials on their own.
///
/// `Cookie` covers session cookies and `Authorization` covers bearer, basic and
/// every other scheme; a bespoke API-key header is recognised only through the
/// job's own [`SessionMaterial`], because an arbitrary header name cannot be
/// told from an ordinary one.
const AUTH_HEADERS: [&str; 2] = ["cookie", "authorization"];

/// The site-map id for one node key: `n-` plus 16 lowercase hex of the FNV-1a
/// 64-bit hash of `"METHOD scheme host port template"`.
///
/// The method is upper-cased so a lower-case `get` on the wire lands on the
/// same node as `GET`. The id is a pure function of the key: no counter, no
/// clock and no job id enter it, so the same target yields the same ids in
/// every run. It is an identifier, never a security decision, which is why a
/// non-cryptographic hash is the right tool (see [`crate::hash`]).
pub(crate) fn node_id(
    method: &str,
    scheme: &str,
    host: &str,
    port: u16,
    path_template: &str,
) -> NodeId {
    let key = format!(
        "{} {scheme} {host} {port} {path_template}",
        method.to_ascii_uppercase()
    );
    format!("n-{:016x}", fnv1a64(key.as_bytes()))
}

/// Whether `req` was sent with credentials: it carries a `Cookie` or an
/// `Authorization` header, or any header the job's session material names.
///
/// Header names match case-insensitively (RFC 9110). The *values* are never
/// read, so nothing secret can escape through this function.
pub(crate) fn is_authenticated(req: &HttpRequest, session: Option<&SessionMaterial>) -> bool {
    if AUTH_HEADERS.iter().any(|name| req.headers.has(name)) {
        return true;
    }
    session.is_some_and(|material| {
        material
            .headers
            .iter()
            .any(|(name, _)| req.headers.has(name))
    })
}

/// The node key: everything that makes two requests the same route.
type NodeKey = (String, String, String, u16, String);

/// Collects requests into the site map of one discovery pass (spec D8.1).
///
/// Requests go in one at a time with the points they yielded; [`finish`] sorts
/// the nodes, resolves every point's `frequency` and hands back the
/// [`Discovery`] the engine schedules from.
///
/// [`finish`]: SiteMapBuilder::finish
pub(crate) struct SiteMapBuilder {
    /// Nodes in first-seen order; [`SiteMapBuilder::finish`] sorts them.
    nodes: Vec<SiteNode>,
    /// `NodeKey` to its index in `nodes`.
    ///
    /// Keyed by the tuple rather than by [`node_id`] so that a hash collision
    /// could never merge two different routes into one node.
    index: HashMap<NodeKey, usize>,
    /// Every point of every request, in the order they were added.
    points: Vec<InsertionPoint>,
}

impl Default for SiteMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SiteMapBuilder {
    /// An empty site map.
    pub(crate) fn new() -> Self {
        Self {
            nodes: Vec::new(),
            index: HashMap::new(),
            points: Vec::new(),
        }
    }

    /// Fold one request and its enumeration into the map, returning the node it
    /// landed on.
    ///
    /// Returns `None` — and changes nothing — when the request's parts do not
    /// form a URL this lane handles (see [`request_url`]): a captured request
    /// with an empty authority, a non-`http(s)` scheme or embedded credentials
    /// has no place on the map.
    ///
    /// Merging into an existing node appends the flow, unions the `(kind,
    /// name)` parameters the enumerator *saw* (so a node shows a session cookie
    /// it carries even though that cookie is never probed), ORs `auth`, and
    /// counts the points. Every point is stamped with the node's id.
    pub(crate) fn add(
        &mut self,
        flow_id: FlowId,
        req: &HttpRequest,
        enumerated: Enumerated,
        auth: bool,
    ) -> Option<NodeId> {
        let url = request_url(req)?;
        let host = url.host_str()?.to_string();
        let port = url.port_or_known_default()?;
        let scheme = url.scheme().to_string();
        let method = req.method.to_ascii_uppercase();
        let template = path_template(url.path());

        let key: NodeKey = (
            method.clone(),
            scheme.clone(),
            host.clone(),
            port,
            template.clone(),
        );
        let index = match self.index.get(&key) {
            Some(index) => *index,
            None => {
                self.nodes.push(SiteNode {
                    id: node_id(&method, &scheme, &host, port, &template),
                    method,
                    scheme,
                    host,
                    port,
                    path_template: template,
                    flows: Vec::new(),
                    params: Vec::new(),
                    auth: false,
                    points: 0,
                    audited: false,
                });
                let index = self.nodes.len() - 1;
                self.index.insert(key, index);
                index
            }
        };

        let Enumerated { points, seen, .. } = enumerated;
        let id = {
            let node = self.nodes.get_mut(index)?;
            node.flows.push(FlowRef::from(flow_id));
            node.auth = node.auth || auth;
            for param in seen {
                if !node.params.contains(&param) {
                    node.params.push(param);
                }
            }
            let added = u32::try_from(points.len()).unwrap_or(u32::MAX);
            node.points = node.points.saturating_add(added);
            node.id.clone()
        };

        for mut point in points {
            point.site_node = Some(id.clone());
            self.points.push(point);
        }
        Some(id)
    }

    /// The finished discovery: nodes sorted by `(host, path_template, method)`,
    /// points in the order they were added, every `frequency` resolved.
    ///
    /// `frequency` is how many *distinct nodes* carry a point's `(kind, name)`
    /// pair — the signal the scheduler uses to tell a site-wide parameter from
    /// a one-off. A point whose pair no node lists counts as the one node it
    /// sits on; the enumerator's `seen` is a superset of the points it emits,
    /// so that fallback is a floor, never a correction.
    pub(crate) fn finish(mut self) -> Discovery {
        let mut frequency: HashMap<(InsertionKind, String), u32> = HashMap::new();
        for node in &self.nodes {
            // A node's `params` are deduped on insert, so each node counts once.
            for ParamRef { kind, name } in &node.params {
                *frequency.entry((*kind, name.clone())).or_insert(0) += 1;
            }
        }

        for point in &mut self.points {
            point.frequency = frequency
                .get(&(point.kind, point.name.clone()))
                .copied()
                .unwrap_or(1);
        }

        self.nodes.sort_by(|a, b| {
            a.host
                .cmp(&b.host)
                .then_with(|| a.path_template.cmp(&b.path_template))
                .then_with(|| a.method.cmp(&b.method))
        });

        Discovery {
            points: self.points,
            nodes: self.nodes,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{is_authenticated, node_id, SiteMapBuilder};

    use aitm_core::{FlowId, HttpFlow, HttpRequest};
    use aitm_scan_model::{InsertionKind, InsertionPoint, ParamRef, ScanProfile, SessionMaterial};

    use crate::points::{enumerate_v2, CompiledIgnore, EnumerateOptions, Enumerated};
    use crate::testutil::{captured_flow, request};

    use InsertionKind::{Cookie, Query};

    /// Enumerate a flow's points exactly as the lane will: the default profile,
    /// its ignore rules compiled, no session material.
    fn enumerate(flow: &HttpFlow) -> Enumerated {
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let opts = EnumerateOptions::from_profile(&profile, &ignore, None);
        enumerate_v2(flow, &opts)
    }

    /// A captured `GET` of `url` with `headers`, answered 200 with no body.
    fn get(url: &str, headers: &[(&str, &str)]) -> HttpFlow {
        captured_flow(request("GET", url, headers, None), 200, &[], b"")
    }

    /// An enumeration that found nothing, for a request that never reaches the
    /// enumerator.
    fn nothing() -> Enumerated {
        Enumerated {
            points: Vec::new(),
            seen: Vec::new(),
            overflow: 0,
            ignored: 0,
            kind_filtered: 0,
        }
    }

    /// Every point of `kind` named `name`, in insertion order.
    fn named<'a>(
        points: &'a [InsertionPoint],
        kind: InsertionKind,
        name: &str,
    ) -> Vec<&'a InsertionPoint> {
        points
            .iter()
            .filter(|p| p.kind == kind && p.name == name)
            .collect()
    }

    #[test]
    fn template_merges_numeric_ids() {
        let one = get("http://t:8080/account/1?tab=x", &[]);
        let two = get("http://t:8080/account/2", &[]);

        let mut builder = SiteMapBuilder::new();
        let first = builder
            .add(one.id, &one.request, enumerate(&one), false)
            .expect("the first request maps to a node");
        let second = builder
            .add(two.id, &two.request, enumerate(&two), true)
            .expect("the second request maps to a node");
        assert_eq!(first, second, "both requests merge into one node");

        let discovery = builder.finish();
        assert_eq!(discovery.nodes.len(), 1);
        let node = &discovery.nodes[0];
        assert_eq!(node.path_template, "/account/{id}");
        assert_eq!(node.method, "GET");
        assert_eq!(node.scheme, "http");
        assert_eq!(node.host, "t");
        assert_eq!(node.port, 8080);
        assert_eq!(node.flows.len(), 2);
        assert_eq!(node.flows[0].to_string(), one.id.to_string());
        assert_eq!(node.flows[1].to_string(), two.id.to_string());
        // `auth` is the OR of every request that mapped here.
        assert!(node.auth);

        let tab = ParamRef {
            kind: Query,
            name: "tab".to_string(),
        };
        assert_eq!(
            node.params.iter().filter(|p| **p == tab).count(),
            1,
            "{:?}",
            node.params
        );
    }

    #[test]
    fn params_union_is_deduped_across_flows() {
        let one = get("http://t:8080/account/1?tab=x", &[]);
        let two = get("http://t:8080/account/2?tab=y&sort=desc", &[]);

        let mut builder = SiteMapBuilder::new();
        builder.add(one.id, &one.request, enumerate(&one), false);
        builder.add(two.id, &two.request, enumerate(&two), false);

        let discovery = builder.finish();
        assert_eq!(discovery.nodes.len(), 1);
        let names: Vec<&str> = discovery.nodes[0]
            .params
            .iter()
            .filter(|p| p.kind == Query)
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, vec!["tab", "sort"]);
    }

    #[test]
    fn frequency_counts_nodes() {
        // Inserted out of order so the sort in `finish` is exercised too.
        let urls = ["http://t:8080/c", "http://t:8080/a?q=1", "http://t:8080/b"];
        let mut builder = SiteMapBuilder::new();
        for url in urls {
            let flow = get(url, &[("Cookie", "theme=dark")]);
            builder
                .add(flow.id, &flow.request, enumerate(&flow), true)
                .expect("each request maps to a node");
        }

        let discovery = builder.finish();
        assert_eq!(discovery.nodes.len(), 3);
        let templates: Vec<&str> = discovery
            .nodes
            .iter()
            .map(|n| n.path_template.as_str())
            .collect();
        assert_eq!(templates, vec!["/a", "/b", "/c"], "nodes are sorted");

        let theme = named(&discovery.points, Cookie, "theme");
        assert_eq!(theme.len(), 3, "one `theme` point per node");
        for point in theme {
            assert_eq!(point.frequency, 3, "{point:?}");
        }

        let q = named(&discovery.points, Query, "q");
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].frequency, 1);
    }

    #[test]
    fn node_id_is_stable() {
        assert_eq!(
            node_id("GET", "http", "t", 8080, "/a"),
            node_id("GET", "http", "t", 8080, "/a")
        );
        assert_ne!(
            node_id("GET", "http", "t", 8080, "/a"),
            node_id("POST", "http", "t", 8080, "/a")
        );
        // Pinned: "n-" plus 16 lowercase hex of fnv1a64 over
        // "METHOD scheme host port template".
        assert_eq!(
            node_id("GET", "http", "t", 8080, "/a"),
            "n-21314a44841955a9"
        );
        assert_eq!(
            node_id("POST", "http", "t", 8080, "/a"),
            "n-d4d338e56b2bb839"
        );

        let build = || {
            let flow = get("http://t:8080/account/7?tab=x", &[]);
            let mut builder = SiteMapBuilder::new();
            builder.add(flow.id, &flow.request, enumerate(&flow), false);
            builder.finish()
        };
        let (one, two) = (build(), build());
        assert_eq!(one.nodes[0].id, two.nodes[0].id, "ids do not depend on run");
        assert_eq!(
            one.nodes[0].id,
            node_id("GET", "http", "t", 8080, "/account/{id}")
        );
        assert_eq!(one.nodes[0].id, "n-80d922cc7c631245");
    }

    #[test]
    fn auth_flag() {
        let cookie = request("GET", "http://t:8080/a", &[("Cookie", "sid=S3")], None);
        assert!(is_authenticated(&cookie, None));

        let bearer = request(
            "GET",
            "http://t:8080/a",
            &[("Authorization", "Bearer tok")],
            None,
        );
        assert!(is_authenticated(&bearer, None));

        let api = request("GET", "http://t:8080/a", &[("X-Api-Key", "k")], None);
        // Header names match case-insensitively (RFC 9110).
        let material = SessionMaterial {
            cookies: Vec::new(),
            headers: vec![("x-api-key".to_string(), "k".to_string())],
        };
        assert!(is_authenticated(&api, Some(&material)));
        assert!(!is_authenticated(&api, None), "no session, no auth header");

        let plain = request("GET", "http://t:8080/a", &[], None);
        assert!(!is_authenticated(&plain, Some(&material)));
        assert!(!is_authenticated(&plain, None));
    }

    #[test]
    fn points_count() {
        let flow = get("http://t:8080/search?q=1&page=2", &[("X-Client", "abc")]);
        let enumerated = enumerate(&flow);
        let expected = enumerated.points.len();
        assert!(expected > 0, "the request has points to attach");

        let mut builder = SiteMapBuilder::new();
        let id = builder
            .add(flow.id, &flow.request, enumerated, false)
            .expect("the request maps to a node");

        let discovery = builder.finish();
        assert_eq!(discovery.nodes[0].points as usize, expected);
        assert_eq!(discovery.points.len(), expected);
        for point in &discovery.points {
            assert_eq!(point.site_node.as_deref(), Some(id.as_str()), "{point:?}");
        }
    }

    #[test]
    fn unroutable_request_is_no_node() {
        let mut builder = SiteMapBuilder::new();

        // Userinfo is refused by `url_norm::request_url`: `t:8080@evil.test`
        // reads as the target to a human while the client talks to evil.test,
        // so such a request never becomes a node (and never a probe target).
        let mut credentials: HttpRequest = request("GET", "http://t:8080/a", &[], None);
        credentials.authority = "u:p@t:8080".to_string();
        assert_eq!(
            builder.add(FlowId::new(), &credentials, nothing(), false),
            None
        );

        // Neither does a scheme this lane does not speak.
        let mut other: HttpRequest = request("GET", "http://t:8080/a", &[], None);
        other.scheme = "ftp".to_string();
        assert_eq!(builder.add(FlowId::new(), &other, nothing(), false), None);

        let discovery = builder.finish();
        assert!(discovery.nodes.is_empty());
        assert!(discovery.points.is_empty());
    }
}
