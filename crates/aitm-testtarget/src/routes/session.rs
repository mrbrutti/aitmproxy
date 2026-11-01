//! Cookie login and the authenticated-only reflected seed (child spec D3 row
//! `auth-only-account-tab`, infrastructure routes `/login` and
//! `/logout-after`). The session store is also what the `/ws` handshake asks
//! for `session_valid`.
//!
//! The session model is deliberately small: an id is minted on a correct
//! `POST /login`, `/account?tab=` needs it, and `/logout-after?n=N` arms a
//! countdown so that the session disappears after N further authenticated
//! requests. That gives the scanner an observed-session-reuse seed (AC T2-4)
//! and a deterministic auth-loss to detect (T2-5).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use sha1::{Digest as _, Sha1};

use crate::app::{html, redirect, reflect, AppState, RequestInfo, Resp};
use crate::seed::{SESSION_PASS, SESSION_USER};

/// One live login. `armed` is the number of authenticated requests left
/// before the session is dropped (`None`: never expires).
struct Session {
    armed: Option<u32>,
}

/// Login sessions minted by `POST /login` and checked by `/account?tab=`,
/// `/logout-after` and the `/ws` handshake.
pub(crate) struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
    /// Mixed into every id so two logins in the same nanosecond still differ.
    counter: AtomicU64,
}

impl SessionStore {
    pub(crate) fn new() -> Self {
        SessionStore {
            inner: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
        }
    }

    /// The map, recovering a poisoned lock (a panic elsewhere must not take
    /// the login store with it).
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Mint a session and return its id: the first 32 hex digits of
    /// `sha1(nanos || counter || port_hint)`. Inert (no `rand`): the id is an
    /// opaque handle for a fixture login, not a security token.
    pub(crate) fn create(&self, port_hint: u16) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha1::new();
        hasher.update(nanos.to_be_bytes());
        hasher.update(counter.to_be_bytes());
        hasher.update(port_hint.to_be_bytes());
        let mut id = format!("{:x}", hasher.finalize());
        id.truncate(32);
        self.lock().insert(id.clone(), Session { armed: None });
        id
    }

    /// Whether `id` names a live session.
    pub(crate) fn is_valid(&self, id: &str) -> bool {
        self.lock().contains_key(id)
    }

    /// Count one authenticated request against `id`. Returns whether the
    /// session was valid for this request. An armed session whose count
    /// reaches zero here is removed, so the *next* call sees it invalid.
    pub(crate) fn touch(&self, id: &str) -> bool {
        let expired = {
            let mut map = self.lock();
            let Some(session) = map.get_mut(id) else {
                return false;
            };
            match session.armed.as_mut() {
                Some(left) => {
                    *left = left.saturating_sub(1);
                    *left == 0
                }
                None => false,
            }
        };
        if expired {
            self.remove(id);
        }
        true
    }

    /// Arm `id` to expire after `n` further authenticated requests (`n == 0`
    /// drops it right away). Returns whether the session existed.
    pub(crate) fn arm(&self, id: &str, n: u32) -> bool {
        let mut map = self.lock();
        if !map.contains_key(id) {
            return false;
        }
        if n == 0 {
            map.remove(id);
        } else if let Some(session) = map.get_mut(id) {
            session.armed = Some(n);
        }
        true
    }

    /// Drop `id` (a no-op for an unknown id).
    pub(crate) fn remove(&self, id: &str) {
        self.lock().remove(id);
    }
}

/// The login form `GET /login` serves.
const LOGIN_FORM: &str = concat!(
    "<h2>Login</h2>",
    r#"<form action="/login" method="post">"#,
    r#"<input name="user" type="text">"#,
    r#"<input name="pass" type="password">"#,
    r#"<input type="submit" value="Sign in">"#,
    "</form>",
);

/// `GET /login`, `POST /login`, `GET /account` (exact path; `/account/{id}`
/// is the legacy IDOR seed and never reaches here), `GET /logout-after`.
pub(crate) async fn route(info: &RequestInfo, state: &Arc<AppState>) -> Option<Resp> {
    let resp = match (info.method.as_str(), info.path.as_str()) {
        ("GET", "/login") => html(StatusCode::OK, LOGIN_FORM.to_string()),
        ("POST", "/login") => login(info, state),
        ("GET", "/account") => account(info, state),
        ("GET", "/logout-after") => logout_after(info, state),
        _ => return None,
    };
    Some(resp)
}

/// The `session` cookie's id when it names a live session.
fn live_session<'a>(info: &'a RequestInfo, state: &AppState) -> Option<&'a str> {
    info.cookie("session")
        .filter(|id| state.sessions.is_valid(id))
}

/// `POST /login`: the fixture credentials mint a session; anything else is 401.
fn login(info: &RequestInfo, state: &AppState) -> Resp {
    let user = info.form_param("user").unwrap_or_default();
    let pass = info.form_param("pass").unwrap_or_default();
    if user != SESSION_USER || pass != SESSION_PASS {
        return html(
            StatusCode::UNAUTHORIZED,
            "<p>invalid credentials</p>".to_string(),
        );
    }
    let id = state.sessions.create(host_port(&info.host));
    let mut resp = redirect("/account?tab=overview");
    if let Ok(cookie) = format!("session={id}; HttpOnly; Path=/").parse() {
        resp.headers_mut().insert("set-cookie", cookie);
    }
    resp
}

/// `GET /account?tab=`: the authenticated-only reflection (raw in V, escaped
/// in P). Each hit counts against an armed session.
fn account(info: &RequestInfo, state: &AppState) -> Resp {
    // `touch` both checks the session and counts this request against it.
    if !info
        .cookie("session")
        .is_some_and(|id| state.sessions.touch(id))
    {
        return redirect("/login");
    }
    let tab = info.query_param("tab").unwrap_or_default();
    html(
        StatusCode::OK,
        format!("<h2>Account: {}</h2>", reflect(state.mode, &tab)),
    )
}

/// `GET /logout-after?n=N`: arm the presented session to die after N further
/// authenticated requests. Not itself counted.
fn logout_after(info: &RequestInfo, state: &AppState) -> Resp {
    let Some(id) = live_session(info, state) else {
        return redirect("/login");
    };
    let Some(n) = info
        .query_param("n")
        .and_then(|n| n.trim().parse::<u32>().ok())
    else {
        return html(
            StatusCode::BAD_REQUEST,
            "<p>n must be a number</p>".to_string(),
        );
    };
    if !state.sessions.arm(id, n) {
        return redirect("/login");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(format!("{{\"armed\":{n}}}"))))
        .expect("valid response")
}

/// The port in a `Host` header (0 when absent or unparsable); only a salt
/// for session ids.
fn host_port(host: &str) -> u16 {
    host.rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    //! Hermetic route tests: build a [`RequestInfo`] with
    //! [`RequestInfo::test_request`] and drive [`route`] directly.

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use http_body_util::BodyExt as _;
    use hyper::StatusCode;

    use super::*;
    use crate::log::ControlLog;
    use crate::seed::SeedMode;

    fn fresh(mode: SeedMode) -> Arc<AppState> {
        Arc::new(AppState::new(mode, ControlLog::new(mode)))
    }

    async fn body_text(resp: Resp) -> String {
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("full body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    fn header<'a>(resp: &'a Resp, name: &str) -> Option<&'a str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// `POST /login` with the fixture credentials; returns the session cookie
    /// value the response set.
    async fn login(state: &Arc<AppState>) -> String {
        let info = RequestInfo::test_request(
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            b"user=alice&pass=wonderland",
        );
        let resp = route(&info, state).await.expect("login is routed");
        assert_eq!(resp.status(), StatusCode::FOUND);
        let cookie = header(&resp, "set-cookie").expect("set-cookie").to_string();
        let id = cookie
            .strip_prefix("session=")
            .and_then(|rest| rest.strip_suffix("; HttpOnly; Path=/"))
            .expect("cookie shape");
        id.to_string()
    }

    async fn get_account(state: &Arc<AppState>, cookie: Option<&str>, tab: &str) -> Resp {
        let target = format!("/account?tab={tab}");
        let cookie_header = cookie.map(|c| format!("session={c}"));
        let headers: Vec<(&str, &str)> = cookie_header
            .as_deref()
            .map(|c| vec![("cookie", c)])
            .unwrap_or_default();
        let info = RequestInfo::test_request("GET", &target, &headers, b"");
        route(&info, state).await.expect("/account is routed")
    }

    #[tokio::test]
    async fn login_sets_cookie_and_account_opens() {
        let state = fresh(SeedMode::Vulnerable);

        // The login response: 302 to the overview tab plus the session cookie.
        let info = RequestInfo::test_request(
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            b"user=alice&pass=wonderland",
        );
        let resp = route(&info, &state).await.expect("login is routed");
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(header(&resp, "location"), Some("/account?tab=overview"));
        let cookie = header(&resp, "set-cookie").expect("set-cookie header");
        let id = cookie
            .strip_prefix("session=")
            .and_then(|rest| rest.strip_suffix("; HttpOnly; Path=/"))
            .unwrap_or_else(|| panic!("cookie shape: {cookie}"));
        assert_eq!(id.len(), 32, "32 hex: {id}");
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "lowercase hex: {id}"
        );

        // Vulnerable: the tab is reflected raw.
        let resp = get_account(&state, Some(id), "%3Ct%3E").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_text(resp).await, "<h2>Account: <t></h2>");

        // Patched: escaped, same gate.
        let patched = fresh(SeedMode::Patched);
        let pid = login(&patched).await;
        let resp = get_account(&patched, Some(&pid), "%3Ct%3E").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_text(resp).await, "<h2>Account: &lt;t&gt;</h2>");

        // No cookie: 302 /login.
        let resp = get_account(&state, None, "overview").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(header(&resp, "location"), Some("/login"));

        // An unknown session id is no better than none.
        let resp = get_account(&state, Some("0123456789abcdef0123456789abcdef"), "overview").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(header(&resp, "location"), Some("/login"));

        // Wrong password: 401.
        let info = RequestInfo::test_request(
            "POST",
            "/login",
            &[("content-type", "application/x-www-form-urlencoded")],
            b"user=alice&pass=nope",
        );
        let resp = route(&info, &state).await.expect("login is routed");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_text(resp).await, "<p>invalid credentials</p>");

        // The login form is served and posts back to /login.
        let info = RequestInfo::test_request("GET", "/login", &[], b"");
        let resp = route(&info, &state).await.expect("login form is routed");
        assert_eq!(resp.status(), StatusCode::OK);
        let form = body_text(resp).await;
        assert!(
            form.contains(r#"<form action="/login" method="post">"#),
            "{form}"
        );
        assert!(form.contains(r#"name="user""#), "{form}");
        assert!(form.contains(r#"name="pass""#), "{form}");

        // `/account/{id}` is the legacy IDOR seed, never this route.
        let info = RequestInfo::test_request("GET", "/account/1", &[], b"");
        assert!(route(&info, &state).await.is_none());
    }

    #[tokio::test]
    async fn logout_after_invalidates() {
        let state = fresh(SeedMode::Vulnerable);
        let id = login(&state).await;

        // Without a session the switch is gated.
        let info = RequestInfo::test_request("GET", "/logout-after?n=2", &[], b"");
        let resp = route(&info, &state).await.expect("routed");
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(header(&resp, "location"), Some("/login"));

        // Arm: two more authenticated requests, then the session is gone.
        let cookie = format!("session={id}");
        let info =
            RequestInfo::test_request("GET", "/logout-after?n=2", &[("cookie", &cookie)], b"");
        let resp = route(&info, &state).await.expect("routed");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "content-type"), Some("application/json"));
        assert_eq!(body_text(resp).await, r#"{"armed":2}"#);

        let mut statuses = Vec::new();
        for _ in 0..3 {
            let resp = get_account(&state, Some(&id), "overview").await;
            statuses.push(resp.status().as_u16());
        }
        assert_eq!(statuses, [200, 200, 302]);
        assert!(!state.sessions.is_valid(&id));
    }

    #[test]
    fn session_ids_are_unique() {
        let store = SessionStore::new();
        let ids: Vec<String> = (0..100).map(|_| store.create(1)).collect();
        for id in &ids {
            assert_eq!(id.len(), 32, "{id}");
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
            assert!(store.is_valid(id));
        }
        let distinct: BTreeSet<&String> = ids.iter().collect();
        assert_eq!(distinct.len(), 100);

        // The store API the routes build on.
        assert!(!store.is_valid("missing"));
        assert!(!store.arm("missing", 3));
        assert!(!store.touch("missing"));
        let id = store.create(2);
        assert!(store.touch(&id), "unarmed sessions never expire");
        assert!(store.arm(&id, 1));
        assert!(store.touch(&id), "the armed request itself still succeeds");
        assert!(!store.is_valid(&id), "gone after the count ran out");
        assert!(!store.touch(&id));
        let id = store.create(3);
        store.remove(&id);
        assert!(!store.is_valid(&id));
        let id = store.create(4);
        assert!(
            store.arm(&id, 0),
            "n=0: deleted after zero further requests"
        );
        assert!(!store.is_valid(&id));
    }

    // --- Tester additions (stage 5): bad `n`, n=0, no tab, login edge cases ---

    #[tokio::test]
    async fn logout_after_rejects_bad_n_and_n_zero_drops_at_once() {
        let state = fresh(SeedMode::Vulnerable);
        let id = login(&state).await;
        let cookie = format!("session={id}");
        for target in ["/logout-after?n=abc", "/logout-after", "/logout-after?n=-1"] {
            let info = RequestInfo::test_request("GET", target, &[("cookie", &cookie)], b"");
            let resp = route(&info, &state).await.expect("routed");
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{target}");
            assert_eq!(
                body_text(resp).await,
                "<p>n must be a number</p>",
                "{target}"
            );
        }
        // A bad arm request changes nothing: still logged in.
        assert!(state.sessions.is_valid(&id));
        // n=0: the session is gone before the next request.
        let info =
            RequestInfo::test_request("GET", "/logout-after?n=0", &[("cookie", &cookie)], b"");
        let resp = route(&info, &state).await.expect("routed");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_text(resp).await, r#"{"armed":0}"#);
        assert!(!state.sessions.is_valid(&id));
        let resp = get_account(&state, Some(&id), "overview").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        // An unknown session on /logout-after is the login redirect, not a 400.
        let info = RequestInfo::test_request(
            "GET",
            "/logout-after?n=abc",
            &[("cookie", "session=nope")],
            b"",
        );
        let resp = route(&info, &state).await.expect("routed");
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(header(&resp, "location"), Some("/login"));
    }

    #[tokio::test]
    async fn account_without_tab_and_login_edge_cases() {
        let state = fresh(SeedMode::Vulnerable);
        let id = login(&state).await;
        let cookie = format!("session={id}");
        let info = RequestInfo::test_request("GET", "/account", &[("cookie", &cookie)], b"");
        let resp = route(&info, &state).await.expect("routed");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_text(resp).await, "<h2>Account: </h2>");

        // Missing credentials, wrong user, wrong case, empty body: 401, no cookie.
        for body in [
            &b""[..],
            b"user=alice",
            b"pass=wonderland",
            b"user=bob&pass=wonderland",
            b"user=ALICE&pass=wonderland",
            b"user=alice&pass=Wonderland",
        ] {
            let info = RequestInfo::test_request("POST", "/login", &[], body);
            let resp = route(&info, &state).await.expect("routed");
            let shown = String::from_utf8_lossy(body);
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{shown}");
            assert!(header(&resp, "set-cookie").is_none(), "{shown}");
        }
        // Not this module's routes.
        for (method, target) in [
            ("POST", "/account"),
            ("GET", "/account/1"),
            ("GET", "/logout"),
            ("POST", "/logout-after"),
            ("GET", "/login/"),
        ] {
            let info = RequestInfo::test_request(method, target, &[], b"");
            assert!(route(&info, &state).await.is_none(), "{method} {target}");
        }
        assert_eq!(host_port("127.0.0.1:8080"), 8080);
        assert_eq!(host_port("localhost"), 0);
        assert_eq!(host_port("h:notaport"), 0);
    }
}
