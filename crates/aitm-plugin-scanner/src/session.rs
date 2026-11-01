//! Observed-session reuse and the auth-lost canary (spec D7).
//!
//! An audit of an authenticated surface is only worth running while the
//! session still works. Rather than ask the operator for credentials, the
//! engine lifts a session from traffic the operator's own proxy already
//! captured: the newest in-scope **captured** (never replayed) flow to the
//! origin that carries a `Cookie` or a secret-named header. The *values* live
//! in a [`SessionMaterial`] in the worker's memory and nowhere else — the only
//! bridge to a wire type is `SessionMaterial::names`, which keeps the names.
//! [`ObservedSession`]'s `Debug` is written by hand for the same reason: the
//! canary flow it holds would otherwise print the session cookie into a log.
//!
//! While the job runs, [`CanaryRunner`] replays a body-less `GET`/`HEAD` flow
//! every [`CANARY_EVERY`] probes; a `2xx` that turns into a redirect, a `401`
//! or a `403` is a lost session, which the worker reports and acts on per the
//! profile's `on_lost`.

use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aitm_core::{
    Body, Flow, FlowId, FlowKind, FlowQuery, FlowStore, HttpFlow, HttpRequest, ProxyClient,
    RecordPolicy, SendOptions,
};
use aitm_scan_model::{Canary, CanaryMethod, FlowRef, SessionMaterial, SessionProfile};

use crate::discover::is_secret_name;
use crate::util::{normalize_origin, origin_key, split_authority};

/// How many probes pass between two canary sends (spec D7).
pub const CANARY_EVERY: u32 = 25;

/// A session lifted from captured traffic: the live values, the names-only
/// profile that may go on the wire, and the flow the canary replays.
pub struct ObservedSession {
    /// The cookie and header **values**, for the worker's memory only.
    pub material: SessionMaterial,
    /// The same session as names only — the wire form (spec D7).
    pub profile: SessionProfile,
    /// The `GET`/`HEAD` flow the auth-lost canary replays, when one exists.
    pub canary_flow: Option<HttpFlow>,
}

impl fmt::Debug for ObservedSession {
    /// Print the names-only profile and the canary flow's identity. The canary
    /// flow's own `Debug` would print its `Cookie` header, so it is never used
    /// here (spec D7: no log carries a session value).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedSession")
            .field("material", &self.material)
            .field("profile", &self.profile)
            .field(
                "canary_flow",
                &self.canary_flow.as_ref().map(|flow| {
                    format!("{} {} {}", flow.id, flow.request.method, flow.request.path)
                }),
            )
            .finish()
    }
}

/// Pick the session to reuse for `origin` from what the proxy already captured.
///
/// Candidates are captured (not replayed) HTTP flows to `origin` that carry a
/// `Cookie` header or a secret-named header; the newest wins, unless
/// `from_flow` names one of them, which then wins outright. The canary is the
/// chosen flow itself when it is a `GET`/`HEAD`, else the newest `GET`/`HEAD`
/// candidate carrying the same material, else none at all — with no eligible
/// flow, auth-lost detection is simply off.
pub fn pick_observed(
    store: &dyn FlowStore,
    origin: &str,
    from_flow: Option<FlowId>,
) -> Option<ObservedSession> {
    let wanted = normalize_origin(origin).ok()?;

    // The store narrows by host, kind and replay first, so only this host's
    // captured HTTP flows are cloned out; the origin check (scheme and port)
    // runs on those alone.
    let authority = wanted
        .split_once("://")
        .map_or(wanted.as_str(), |(_, authority)| authority);
    let (host, _) = split_authority(authority);
    let mut candidates: Vec<HttpFlow> = store
        .query(&FlowQuery {
            host: Some(host.to_string()),
            kind: Some(FlowKind::Http),
            is_replay: Some(false),
            ..FlowQuery::default()
        })
        .into_iter()
        .filter_map(|id| match store.get(id) {
            Some(Flow::Http(flow)) => Some(flow),
            _ => None,
        })
        .filter(|flow| origin_of(&flow.request) == wanted)
        .filter(|flow| has_material(&material_of(&flow.request)))
        .collect();
    // Newest first, so "the newest carrying ..." is the first match below.
    candidates.sort_by_key(|flow| std::cmp::Reverse(flow.metadata.created));

    let source = from_flow
        .and_then(|id| candidates.iter().find(|flow| flow.id == id).cloned())
        .or_else(|| candidates.first().cloned())?;
    let material = material_of(&source.request);

    let canary_flow = if canary_method(&source.request.method).is_some() {
        Some(source.clone())
    } else {
        candidates
            .iter()
            .find(|flow| {
                canary_method(&flow.request.method).is_some() && carries(&material, &flow.request)
            })
            .cloned()
    };
    let canary = canary_flow
        .as_ref()
        .and_then(|flow| {
            Some(Canary::Flow {
                method: canary_method(&flow.request.method)?,
                // The bare path: the contract (and the lane's status shape) is
                // `/account`, never `/account?tab=1` (T2 live run 2, 2026-11-01).
                path: bare_path(&flow.request.path),
                expected_status: flow.response.as_ref().map(|r| r.status),
            })
        })
        .unwrap_or_default();

    let profile = material.names(
        &wanted,
        Some(FlowRef(source.id)),
        epoch_ms(source.metadata.created),
        canary,
    );
    Some(ObservedSession {
        material,
        profile,
        canary_flow,
    })
}

/// Merge the session into a probe request (spec D7): the probe's own headers
/// and cookies win, the session's are added by name.
///
/// A session header is set only when the request does not already carry that
/// name, and the cookies are merged by name into one re-serialised `Cookie`
/// header (`a=b; c=d`) in which the request's own value for a name is kept.
/// `path` without its query string or fragment: `/account?tab=1#x` → `/account`;
/// an empty path reads as `/`.
fn bare_path(path: &str) -> String {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    let bare = &path[..end];
    if bare.is_empty() {
        "/".to_string()
    } else {
        bare.to_string()
    }
}

pub fn apply(material: &SessionMaterial, req: &mut HttpRequest) {
    for (name, value) in &material.headers {
        if !req.headers.has(name) {
            req.headers.set(name, value);
        }
    }
    if material.cookies.is_empty() {
        return;
    }
    let mut merged = req
        .headers
        .get("cookie")
        .map(cookie_pairs)
        .unwrap_or_default();
    for (name, value) in &material.cookies {
        // Cookie names are case-sensitive (RFC 6265 4.1.1), so compare exactly.
        if !merged.iter().any(|(have, _)| have == name) {
            merged.push((name.clone(), value.clone()));
        }
    }
    let serialized = merged
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    req.headers.remove("cookie");
    req.headers.set("Cookie", &serialized);
}

/// What a canary send said about the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryOutcome {
    /// The session still works.
    Alive,
    /// The session stopped working; this is the status that proved it.
    Lost {
        /// The status the canary was answered with.
        status: u16,
    },
}

/// Replays one captured `GET`/`HEAD` flow every [`CANARY_EVERY`] probes to
/// notice a session that stopped working (spec D7).
pub struct CanaryRunner {
    /// The replayed request: the captured one, with any body dropped.
    template: HttpRequest,
    /// The status class the captured flow was answered with (`2` for a `200`).
    expected_class: u16,
    /// How many times [`CanaryRunner::due`] has been asked.
    counter: AtomicU32,
}

impl CanaryRunner {
    /// A runner over `flow`, or `None` when the flow is not a `GET`/`HEAD`.
    ///
    /// The body is dropped (with the framing headers that described it): a
    /// canary must not mutate state, so it never carries one.
    pub fn new(flow: &HttpFlow) -> Option<Self> {
        canary_method(&flow.request.method)?;
        let mut template = flow.request.clone();
        template.body = Body::Empty;
        template.headers.remove("content-length");
        template.headers.remove("transfer-encoding");
        Some(Self {
            template,
            expected_class: flow.response.as_ref().map(|r| r.status / 100).unwrap_or(0),
            counter: AtomicU32::new(0),
        })
    }

    /// Whether this probe is the one that owes a canary send: true on every
    /// [`CANARY_EVERY`]th call. Counting is the caller's probe counter, so the
    /// worker only has to ask once per probe.
    pub fn due(&self) -> bool {
        self.counter.fetch_add(1, Ordering::Relaxed) % CANARY_EVERY == CANARY_EVERY - 1
    }

    /// Send the canary and judge the session.
    ///
    /// The send is never recorded and is marked `canary`; the job's client adds
    /// its own `scan:<job>` mark.
    pub async fn check(&self, client: &dyn ProxyClient) -> anyhow::Result<CanaryOutcome> {
        let opts = SendOptions {
            record: RecordPolicy::Never,
            marks: vec!["canary".to_string()],
            ..SendOptions::default()
        };
        let flow = client.send_opts(self.template.clone(), opts).await?;
        let status = flow
            .response
            .as_ref()
            .map(|r| r.status)
            .ok_or_else(|| anyhow::anyhow!("the canary send produced no response"))?;
        Ok(self.judge(status))
    }

    /// A session that answered `2xx` and now answers a redirect, `401` or `403`
    /// is lost; anything else (including a server error) is not evidence.
    fn judge(&self, status: u16) -> CanaryOutcome {
        if self.expected_class == 2 && (status / 100 == 3 || status == 401 || status == 403) {
            CanaryOutcome::Lost { status }
        } else {
            CanaryOutcome::Alive
        }
    }
}

/// `GET` and `HEAD` are the only canary methods (spec D7).
fn canary_method(method: &str) -> Option<CanaryMethod> {
    if method.eq_ignore_ascii_case("GET") {
        Some(CanaryMethod::Get)
    } else if method.eq_ignore_ascii_case("HEAD") {
        Some(CanaryMethod::Head)
    } else {
        None
    }
}

/// The session values a request carries: every `Cookie` pair, and every
/// secret-named header other than `Cookie` itself (which is already the
/// cookies, and whose name the shared vocabulary also reads as a secret).
fn material_of(req: &HttpRequest) -> SessionMaterial {
    SessionMaterial {
        cookies: req
            .headers
            .get("cookie")
            .map(cookie_pairs)
            .unwrap_or_default(),
        headers: req
            .headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("cookie") && is_secret_name(name))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
            .collect(),
    }
}

/// Whether anything at all was observed.
fn has_material(material: &SessionMaterial) -> bool {
    !material.cookies.is_empty() || !material.headers.is_empty()
}

/// Whether `req` carries every pair of `material` — the rule for "the newest
/// `GET`/`HEAD` flow carrying the same material". A flow with *extra* cookies
/// still carries the session.
fn carries(material: &SessionMaterial, req: &HttpRequest) -> bool {
    let mine = material_of(req);
    material
        .cookies
        .iter()
        .all(|pair| mine.cookies.contains(pair))
        && material
            .headers
            .iter()
            .all(|pair| mine.headers.contains(pair))
}

/// Split a `Cookie` header into its `name=value` pairs, in wire order.
fn cookie_pairs(header: &str) -> Vec<(String, String)> {
    header
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), value.trim().to_string()))
        })
        .collect()
}

/// A request's origin in the one normal form, so `HTTP://Ex.test:80/` in a
/// profile and `Ex.test:80` in a captured request are one origin.
fn origin_of(req: &HttpRequest) -> String {
    origin_key(&req.scheme, &req.authority)
}

/// A capture time as epoch milliseconds, the scanner's timestamp unit. A clock
/// before the epoch reads as `0` rather than panicking.
fn epoch_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use aitm_core::{
        ConnInfo, Flow, FlowMeta, HeaderMap, HttpResponse, HttpVersion, InterceptState,
        MemFlowStore,
    };
    use futures::future::BoxFuture;

    /// The origin every fixture flow below was captured against.
    const ORIGIN: &str = "http://ex.test";

    /// A fixed flow id, so an assertion that a cookie *value* never reaches the
    /// wire cannot be fooled by a random UUID that happens to spell it.
    fn id(last: u32) -> FlowId {
        FlowId::from_str(&format!("00000000-0000-4000-8000-{last:012}")).expect("a UUID")
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

    fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> HttpRequest {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpRequest {
            method: method.to_string(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: path.to_string(),
            version: HttpVersion::Http11,
            headers: map,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    /// A captured (not replayed) flow to [`ORIGIN`], created `ms_ago`
    /// milliseconds ago so "newest" is deterministic.
    fn captured(
        flow_id: FlowId,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        ms_ago: u64,
    ) -> HttpFlow {
        HttpFlow {
            id: flow_id,
            request: request(method, path, headers),
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta {
                created: SystemTime::now() - Duration::from_millis(ms_ago),
                ..FlowMeta::default()
            },
            intercept: InterceptState::Observed,
        }
    }

    fn response(status: u16) -> HttpResponse {
        HttpResponse {
            status,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    fn answered(mut flow: HttpFlow, status: u16) -> HttpFlow {
        flow.response = Some(response(status));
        flow
    }

    /// A client that answers every send with one status and remembers what it
    /// was asked to send, so a test can see the canary's request and options.
    struct StubClient {
        status: u16,
        seen: Mutex<Vec<(HttpRequest, SendOptions)>>,
    }

    impl StubClient {
        fn new(status: u16) -> Self {
            Self {
                status,
                seen: Mutex::new(Vec::new()),
            }
        }

        fn only_send(&self) -> (HttpRequest, SendOptions) {
            let seen = self.seen.lock().expect("the stub lock");
            assert_eq!(seen.len(), 1, "exactly one send");
            seen[0].clone()
        }
    }

    impl ProxyClient for StubClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.send_opts(req, SendOptions::default())
        }

        fn send_opts(
            &self,
            req: HttpRequest,
            opts: SendOptions,
        ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.seen
                .lock()
                .expect("the stub lock")
                .push((req.clone(), opts));
            let status = self.status;
            Box::pin(async move {
                Ok(HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(response(status)),
                    client_conn: conn(),
                    server_conn: None,
                    metadata: FlowMeta {
                        is_replay: true,
                        ..FlowMeta::default()
                    },
                    intercept: InterceptState::Observed,
                })
            })
        }
    }

    /// The canary names the bare path: a flow captured as `/account?tab=1`
    /// gives `canary.path == "/account"` (contract shape; T2 live run 2).
    #[test]
    fn canary_path_drops_the_query_string() {
        let store = MemFlowStore::new();
        store.insert(Flow::Http(captured(
            id(1),
            "GET",
            "/account?tab=1&x=2",
            &[("Cookie", "sid=abc")],
            0,
        )));
        let picked = pick_observed(&store, ORIGIN, None).expect("a session");
        match &picked.profile.canary {
            Canary::Flow { path, method, .. } => {
                assert_eq!(path, "/account");
                assert_eq!(
                    *method,
                    canary_method("GET").expect("GET is a canary method")
                );
            }
            other => panic!("expected a flow canary, got {other:?}"),
        }
        assert_eq!(bare_path("/"), "/");
        assert_eq!(bare_path(""), "/");
        assert_eq!(bare_path("/a#frag"), "/a");
    }

    /// Spec D7: the session comes from the newest **captured** flow to the
    /// origin that carries a `Cookie`; a replay is never session material, and
    /// the profile carries names only.
    #[test]
    fn picks_newest_captured_flow_with_a_cookie() {
        let store = MemFlowStore::new();

        // Newest of all, but a replay: not a candidate.
        let mut replay = captured(id(1), "GET", "/replayed", &[("Cookie", "sid=zzz")], 0);
        replay.metadata.is_replay = true;
        store.insert(Flow::Http(replay));

        // Newer than the cookie flow, but carries no session material.
        store.insert(Flow::Http(captured(
            id(2),
            "GET",
            "/public",
            &[("Accept", "text/html")],
            5,
        )));

        // The one to pick.
        store.insert(Flow::Http(captured(
            id(3),
            "GET",
            "/account",
            &[("Cookie", "sid=abc; theme=dark")],
            10,
        )));

        // Older still.
        store.insert(Flow::Http(captured(
            id(4),
            "GET",
            "/old",
            &[("Cookie", "sid=older")],
            50,
        )));

        let picked = pick_observed(&store, ORIGIN, None).expect("a session");

        assert_eq!(picked.profile.source_flow, Some(FlowRef(id(3))));
        assert_eq!(picked.profile.origin, ORIGIN);
        assert_eq!(
            picked.profile.cookies,
            vec!["sid".to_string(), "theme".to_string()]
        );
        assert!(
            picked.profile.headers.is_empty(),
            "the `Cookie` header is material, not a secret header: {:?}",
            picked.profile.headers
        );
        assert_eq!(
            picked.material.cookies,
            vec![
                ("sid".to_string(), "abc".to_string()),
                ("theme".to_string(), "dark".to_string())
            ]
        );

        let json = serde_json::to_string(&picked.profile).expect("serializes");
        for value in ["abc", "dark"] {
            assert!(
                !json.contains(value),
                "value {value} reached the wire: {json}"
            );
        }
        let shown = format!("{picked:?}");
        for value in ["abc", "dark"] {
            assert!(
                !shown.contains(value),
                "value {value} reached Debug: {shown}"
            );
        }
    }

    /// Spec D7: a secret-named header (`Authorization`, `X-Api-Key`, ...) is
    /// session material on its own, and only its name reaches the profile.
    #[test]
    fn secret_header_counts_as_material() {
        let store = MemFlowStore::new();
        store.insert(Flow::Http(captured(
            id(5),
            "GET",
            "/api",
            &[("Authorization", "Bearer t0k"), ("Accept", "text/html")],
            0,
        )));

        let picked = pick_observed(&store, ORIGIN, None).expect("a session");

        assert_eq!(picked.profile.headers, vec!["authorization".to_string()]);
        assert!(picked.profile.cookies.is_empty());
        assert_eq!(
            picked.material.headers,
            vec![("authorization".to_string(), "Bearer t0k".to_string())]
        );
        let json = serde_json::to_string(&picked.profile).expect("serializes");
        assert!(!json.contains("t0k"), "value reached the wire: {json}");
    }

    /// Spec D7 header merge: a probe's own headers and cookies win; the
    /// session's are merged in by name.
    #[test]
    fn apply_merges_cookies_by_name_probe_wins() {
        let material = SessionMaterial {
            cookies: vec![
                ("sid".to_string(), "abc".to_string()),
                ("t".to_string(), "2".to_string()),
            ],
            headers: vec![("authorization".to_string(), "Bearer t0k".to_string())],
        };

        let mut probe = request("POST", "/p", &[("Cookie", "sid=probe; x=1")]);
        apply(&material, &mut probe);
        assert_eq!(probe.headers.get("Cookie"), Some("sid=probe; x=1; t=2"));
        assert_eq!(probe.headers.get("Authorization"), Some("Bearer t0k"));
        assert_eq!(
            probe
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                .count(),
            1,
            "one merged `Cookie` header, not two"
        );

        let mut own_auth = request("GET", "/p", &[("Authorization", "Bearer mine")]);
        apply(&material, &mut own_auth);
        assert_eq!(own_auth.headers.get("Authorization"), Some("Bearer mine"));
        assert_eq!(
            own_auth
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .count(),
            1,
            "the probe's own header is kept, not duplicated"
        );
        assert_eq!(
            own_auth.headers.get("Cookie"),
            Some("sid=abc; t=2"),
            "a probe with no cookies gains the session's"
        );
    }

    /// Spec D7: the canary is GET or HEAD only. A `from_flow` POST still picks
    /// the session, but the canary falls back to the newest GET/HEAD flow
    /// carrying the same material.
    #[test]
    fn canary_requires_get_or_head() {
        let store = MemFlowStore::new();
        store.insert(Flow::Http(answered(
            captured(id(6), "POST", "/login", &[("Cookie", "sid=abc")], 0),
            302,
        )));
        store.insert(Flow::Http(answered(
            captured(id(7), "GET", "/account", &[("Cookie", "sid=abc")], 20),
            200,
        )));

        let picked = pick_observed(&store, ORIGIN, Some(id(6))).expect("a session");

        assert_eq!(picked.profile.source_flow, Some(FlowRef(id(6))));
        assert_eq!(
            picked.profile.canary,
            Canary::Flow {
                method: CanaryMethod::Get,
                path: "/account".to_string(),
                expected_status: Some(200),
            }
        );
        assert_eq!(picked.canary_flow.as_ref().map(|f| f.id), Some(id(7)));

        let only_posts = MemFlowStore::new();
        only_posts.insert(Flow::Http(answered(
            captured(id(8), "POST", "/login", &[("Cookie", "sid=abc")], 0),
            200,
        )));

        let picked = pick_observed(&only_posts, ORIGIN, None).expect("a session");

        assert_eq!(picked.profile.canary, Canary::None);
        assert!(picked.canary_flow.is_none(), "no eligible canary flow");
    }

    /// Spec D7: the canary is sent every 25 probes.
    #[test]
    fn canary_due_every_25() {
        assert_eq!(CANARY_EVERY, 25);
        let runner = CanaryRunner::new(&answered(
            captured(id(9), "GET", "/account", &[("Cookie", "sid=abc")], 0),
            200,
        ))
        .expect("a GET canary");

        for call in 1..25 {
            assert!(!runner.due(), "call {call} is not due");
        }
        assert!(runner.due(), "the 25th call is due");
        for call in 26..50 {
            assert!(!runner.due(), "call {call} is not due");
        }
        assert!(runner.due(), "the 50th call is due");
    }

    /// Spec D7: a 2xx canary answered 3xx/401/403 is a lost session; the canary
    /// itself is never recorded and never carries a body.
    #[tokio::test]
    async fn canary_lost_on_class_change() {
        let mut flow = answered(
            captured(id(10), "GET", "/account", &[("Cookie", "sid=abc")], 0),
            200,
        );
        flow.request.body = Body::Bytes(b"junk".to_vec());
        flow.request.headers.set("Content-Length", "4");
        let runner = CanaryRunner::new(&flow).expect("a GET canary");

        let redirected = StubClient::new(302);
        assert_eq!(
            runner.check(&redirected).await.expect("the canary sends"),
            CanaryOutcome::Lost { status: 302 }
        );

        let alive = StubClient::new(200);
        assert_eq!(
            runner.check(&alive).await.expect("the canary sends"),
            CanaryOutcome::Alive
        );

        let (req, opts) = redirected.only_send();
        assert_eq!(
            opts.record,
            RecordPolicy::Never,
            "a canary is never recorded"
        );
        assert_eq!(opts.marks, vec!["canary".to_string()]);
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/account");
        assert!(
            matches!(req.body, Body::Empty),
            "the canary carries no body: {:?}",
            req.body
        );
        assert!(
            !req.headers.has("content-length"),
            "a body-less canary carries no content-length"
        );
        assert_eq!(
            req.headers.get("Cookie"),
            Some("sid=abc"),
            "replayed with its headers unchanged"
        );
    }

    // ---- tester additions ---------------------------------------------------

    /// Spec D7's status-class rule, every branch: a `2xx` canary that comes back
    /// `3xx`, `401` or `403` is lost; any other change (a `5xx`, a `404`, a
    /// different `2xx`) is not evidence; and a canary that was never `2xx`
    /// cannot report a loss at all.
    #[tokio::test]
    async fn canary_judges_every_status_class() {
        let ok = CanaryRunner::new(&answered(
            captured(id(11), "HEAD", "/me", &[("Cookie", "sid=abc")], 0),
            204,
        ))
        .expect("a HEAD canary");
        for (status, want) in [
            (200, CanaryOutcome::Alive),
            (204, CanaryOutcome::Alive),
            (301, CanaryOutcome::Lost { status: 301 }),
            (302, CanaryOutcome::Lost { status: 302 }),
            (307, CanaryOutcome::Lost { status: 307 }),
            (401, CanaryOutcome::Lost { status: 401 }),
            (403, CanaryOutcome::Lost { status: 403 }),
            (404, CanaryOutcome::Alive),
            (429, CanaryOutcome::Alive),
            (500, CanaryOutcome::Alive),
            (503, CanaryOutcome::Alive),
        ] {
            let client = StubClient::new(status);
            assert_eq!(
                ok.check(&client).await.expect("the canary sends"),
                want,
                "a 2xx canary answered {status}"
            );
            let (req, _) = client.only_send();
            assert_eq!(req.method, "HEAD", "the method is replayed as captured");
        }

        // Captured as a redirect: the session was never proven, so nothing
        // the canary sees can prove it lost.
        let never_2xx = CanaryRunner::new(&answered(
            captured(id(12), "GET", "/me", &[("Cookie", "sid=abc")], 0),
            302,
        ))
        .expect("a GET canary");
        for status in [302, 401, 403, 200] {
            assert_eq!(
                never_2xx
                    .check(&StubClient::new(status))
                    .await
                    .expect("sends"),
                CanaryOutcome::Alive,
                "a non-2xx canary answered {status} is not a loss"
            );
        }

        // A captured flow without a response is treated the same way.
        let unanswered =
            CanaryRunner::new(&captured(id(13), "GET", "/me", &[("Cookie", "sid=abc")], 0))
                .expect("a GET canary");
        assert_eq!(
            unanswered
                .check(&StubClient::new(401))
                .await
                .expect("sends"),
            CanaryOutcome::Alive
        );

        assert!(
            CanaryRunner::new(&captured(id(14), "DELETE", "/me", &[], 0)).is_none(),
            "a DELETE can never be a canary"
        );
    }

    /// `from_flow` that is not a candidate — unknown, a replay, or carrying no
    /// material — falls back to the newest candidate rather than failing.
    #[test]
    fn from_flow_that_is_not_a_candidate_falls_back_to_newest() {
        let store = MemFlowStore::new();
        let mut replay = captured(id(20), "GET", "/replay", &[("Cookie", "sid=zzz")], 0);
        replay.metadata.is_replay = true;
        store.insert(Flow::Http(replay));
        store.insert(Flow::Http(captured(id(21), "GET", "/public", &[], 1)));
        store.insert(Flow::Http(captured(
            id(22),
            "GET",
            "/account",
            &[("Cookie", "sid=abc")],
            5,
        )));

        for from in [Some(id(99)), Some(id(20)), Some(id(21)), None] {
            let picked = pick_observed(&store, ORIGIN, from).expect("a session");
            assert_eq!(
                picked.profile.source_flow,
                Some(FlowRef(id(22))),
                "from_flow {from:?} falls back to the newest candidate"
            );
            assert_eq!(picked.profile.cookies, vec!["sid".to_string()]);
        }
    }

    /// Origin matching is on the normal form: authority case and the scheme's
    /// default port do not split one origin, while another port or scheme does;
    /// and a store with nothing to lift yields `None`, never an empty session.
    #[test]
    fn origin_normal_form_and_nothing_observed() {
        let store = MemFlowStore::new();
        let mut upper = captured(id(30), "GET", "/a", &[("Cookie", "sid=abc")], 0);
        upper.request.authority = "EX.TEST:80".to_string();
        store.insert(Flow::Http(upper));
        let mut other_port = captured(id(31), "GET", "/b", &[("Cookie", "sid=other")], 0);
        other_port.request.authority = "ex.test:8080".to_string();
        store.insert(Flow::Http(other_port));
        let mut tls = captured(id(32), "GET", "/c", &[("Cookie", "sid=tls")], 0);
        tls.request.scheme = "https".to_string();
        store.insert(Flow::Http(tls));

        let picked = pick_observed(&store, "HTTP://ex.test/", None).expect("a session");
        assert_eq!(picked.profile.source_flow, Some(FlowRef(id(30))));
        assert_eq!(
            picked.material.cookies,
            vec![("sid".to_string(), "abc".to_string())]
        );
        assert_eq!(
            pick_observed(&store, "http://ex.test:8080", None)
                .expect("the other port has its own session")
                .profile
                .source_flow,
            Some(FlowRef(id(31)))
        );
        assert_eq!(
            pick_observed(&store, "https://ex.test", None)
                .expect("the tls origin has its own session")
                .profile
                .source_flow,
            Some(FlowRef(id(32)))
        );
        assert!(
            pick_observed(&store, "http://nobody.test", None).is_none(),
            "an origin with no captured flow has no session"
        );

        let bare = MemFlowStore::new();
        bare.insert(Flow::Http(captured(
            id(33),
            "GET",
            "/",
            &[("Accept", "*/*")],
            0,
        )));
        assert!(
            pick_observed(&bare, ORIGIN, None).is_none(),
            "a flow without material is not a session"
        );
        assert!(pick_observed(&MemFlowStore::new(), ORIGIN, None).is_none());
    }

    /// `apply` with nothing to apply leaves the request byte-for-byte alone, and
    /// a malformed `Cookie` header yields only its well-formed pairs.
    #[test]
    fn apply_with_empty_material_and_malformed_cookies() {
        let empty = SessionMaterial {
            cookies: Vec::new(),
            headers: Vec::new(),
        };
        let mut req = request("GET", "/p", &[("Accept", "text/html")]);
        let before = format!("{req:?}");
        apply(&empty, &mut req);
        assert_eq!(format!("{req:?}"), before, "no material, no change");
        assert!(!req.headers.has("cookie"), "no Cookie header is invented");

        assert_eq!(
            cookie_pairs(";; =novalue; a; b=1 ; c=x=y;"),
            vec![
                ("b".to_string(), "1".to_string()),
                ("c".to_string(), "x=y".to_string())
            ],
            "empty names and name-less parts are dropped; `=` inside a value is kept"
        );
        assert!(cookie_pairs("").is_empty());

        // A probe whose own Cookie header is malformed still gets the session.
        let material = SessionMaterial {
            cookies: vec![("sid".to_string(), "abc".to_string())],
            headers: Vec::new(),
        };
        let mut odd = request("GET", "/p", &[("Cookie", ";;junk;;")]);
        apply(&material, &mut odd);
        assert_eq!(odd.headers.get("Cookie"), Some("sid=abc"));
    }
}
