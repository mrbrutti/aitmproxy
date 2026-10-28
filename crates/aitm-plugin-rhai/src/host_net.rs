//! Guarded async host functions (`http`, `browser`, `store`, `scope`) reached
//! from the synchronous engine via `Handle::block_on` (plan Task 7).
//!
//! Four [`ScriptCapability`] providers, one per namespace (spec §6a). Each is a
//! small `Clone` marker holding the shared [`ScriptServices`], registered as a
//! global constant so `http.send(...)` reads as a namespace. A namespace whose
//! provider is not registered simply does not exist for scripts — deny by
//! default, with no ambient authority.
//!
//! **The bridge.** Rhai is synchronous; the guarded capabilities are async. A
//! verb drives its future with the stored runtime handle (`services.rt`), and
//! the caller — `ScriptPlugin::on_event`, or a test — has already entered
//! `tokio::task::block_in_place`, so blocking this worker is legal and tokio
//! moves other tasks elsewhere. No second network path exists: every verb here
//! passes the same `ScopeRateGuard` / SSRF guard a Rust plugin passes.
//!
//! **Option C.** A read whose answer may simply be absent is forgiving —
//! `store.get(unknown)` is `()`, a query matching nothing is an empty array. A
//! **guard refusal is never forgiven**: it is a catchable Rhai error naming the
//! capability and the reason, because a denial is not an absence.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    classify_host, ssrf_check, Authority, Body, BrowserDriver, ClickTarget, Flow, FlowId, FlowKind,
    FlowQuery, GuardError, HeaderMap, HostClass, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    ScopeEntry, SsrfPolicy, Value,
};
use rhai::{Array, Blob, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Module, Position};

use crate::host_core::{ScriptCapability, ScriptServices};
use crate::marshal::{dynamic_to_value, value_to_dynamic};

/// The `API` version these providers require: M3's first and only one.
const API_1: &str = "1";

/// Log target for what a script's guarded verbs do, so an operator can filter
/// scope changes and refusals out of the rest of the log.
const HOST_TARGET: &str = "aitm_plugin_rhai::host";

/// `http.send(#{ method, url, headers, body }) -> #{ status, headers, body, flow_id }`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpCapability;

/// `browser.navigate/click/type_text/screenshot/eval/get_dom`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserCapability;

/// `store.get(id)` / `store.query(#{ … })`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoreCapability;

/// `scope.add(host)` / `scope.list()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScopeCapability;

/// The value behind the script-visible `http` constant.
#[derive(Clone)]
struct HttpNs(ScriptServices);

/// The value behind the script-visible `browser` constant.
#[derive(Clone)]
struct BrowserNs(ScriptServices);

/// The value behind the script-visible `store` constant.
#[derive(Clone)]
struct StoreNs(ScriptServices);

/// The value behind the script-visible `scope` constant.
#[derive(Clone)]
struct ScopeNs(ScriptServices);

impl ScriptCapability for HttpCapability {
    fn namespace(&self) -> &str {
        "http"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, services: &ScriptServices) {
        engine
            .register_type_with_name::<HttpNs>("http")
            .register_fn("send", |ns: &mut HttpNs, req: Map| send(&ns.0, req));
        set_namespace(engine, "http", HttpNs(services.clone()));
    }
}

impl ScriptCapability for BrowserCapability {
    fn namespace(&self) -> &str {
        "browser"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, services: &ScriptServices) {
        engine
            .register_type_with_name::<BrowserNs>("browser")
            .register_fn("navigate", |ns: &mut BrowserNs, url: &str| {
                navigate(&ns.0, url)
            })
            .register_fn("click", |ns: &mut BrowserNs, target: &str| {
                let driver = driver(&ns.0)?;
                block_on(
                    &ns.0,
                    driver.click(ClickTarget::Selector(target.to_string())),
                )
                .map_err(|err| failed("browser.click", err))
            })
            .register_fn(
                "type_text",
                |ns: &mut BrowserNs, selector: &str, text: &str| {
                    let driver = driver(&ns.0)?;
                    block_on(&ns.0, driver.type_text(selector, text))
                        .map_err(|err| failed("browser.type_text", err))
                },
            )
            .register_fn("screenshot", |ns: &mut BrowserNs| -> ScriptResult<Blob> {
                let driver = driver(&ns.0)?;
                block_on(&ns.0, driver.screenshot())
                    .map_err(|err| failed("browser.screenshot", err))
            })
            // `evaluate`, not `eval`: `eval` is a Rhai reserved word and cannot
            // be a method name, so no script could call it (spec §6). The MCP
            // and CLI tool is still named `browser.eval` — a tool name is not a
            // Rhai identifier.
            .register_fn("evaluate", |ns: &mut BrowserNs, expr: &str| {
                let driver = driver(&ns.0)?;
                block_on(&ns.0, driver.eval(expr))
                    .map(|value| value_to_dynamic(&value))
                    .map_err(|err| failed("browser.evaluate", err))
            })
            .register_fn(
                "get_dom",
                |ns: &mut BrowserNs| -> ScriptResult<ImmutableString> {
                    let driver = driver(&ns.0)?;
                    block_on(&ns.0, driver.get_dom())
                        .map(ImmutableString::from)
                        .map_err(|err| failed("browser.get_dom", err))
                },
            );
        set_namespace(engine, "browser", BrowserNs(services.clone()));
    }
}

impl ScriptCapability for StoreCapability {
    fn namespace(&self) -> &str {
        "store"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, services: &ScriptServices) {
        engine
            .register_type_with_name::<StoreNs>("store")
            .register_fn("get", |ns: &mut StoreNs, id: &str| get_flow(&ns.0, id))
            .register_fn("query", |ns: &mut StoreNs, q: Map| query_flows(&ns.0, q));
        set_namespace(engine, "store", StoreNs(services.clone()));
    }
}

impl ScriptCapability for ScopeCapability {
    fn namespace(&self) -> &str {
        "scope"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, services: &ScriptServices) {
        engine
            .register_type_with_name::<ScopeNs>("scope")
            .register_fn("add", |ns: &mut ScopeNs, host: &str| add_scope(&ns.0, host))
            .register_fn("list", |ns: &mut ScopeNs| -> Array {
                ns.0.guard
                    .list_scope()
                    .into_iter()
                    .map(|entry| Dynamic::from(entry.host))
                    .collect()
            });
        set_namespace(engine, "scope", ScopeNs(services.clone()));
    }
}

/// What every fallible verb returns: a Rhai error a script can `try`/`catch`.
type ScriptResult<T> = Result<T, Box<EvalAltResult>>;

/// Expose `value` to scripts as the global constant `name`.
fn set_namespace<T: Clone + Send + Sync + 'static>(engine: &mut Engine, name: &str, value: T) {
    let mut module = Module::new();
    module.set_var(name, value);
    engine.register_global_module(module.into());
}

/// Drive a guarded future from the synchronous engine. The caller has already
/// entered `block_in_place`, so this worker may block.
fn block_on<F: Future>(services: &ScriptServices, fut: F) -> F::Output {
    services.rt.block_on(fut)
}

// ---------------------------------------------------------------- http.send

/// `http.send(#{ … })`: scope/rate-gated, then reissued through the proxy's own
/// client (which captures the flow). The guard is checked here, on the same
/// `check_active` gate a Rust plugin passes, and the permit is held for the
/// whole send.
fn send(services: &ScriptServices, req: Map) -> ScriptResult<Map> {
    let request = parse_request(req)?;
    let authority = request.authority.clone();

    let _permit = services
        .guard
        .check_active(&authority)
        .map_err(|reason| denied("http.send", &authority, &reason))?;

    let flow = block_on(services, services.client.send(request))
        .map_err(|err| failed("http.send", err))?;
    Ok(response_map(&flow))
}

/// The keys `http.send(...)` accepts, for the error a typo gets.
const SEND_KEYS: [&str; 4] = ["method", "url", "headers", "body"];

/// Turn the script's request map into a captured-request shape. A malformed
/// request is a mistake, not an absence: it is refused with what to fix.
fn parse_request(req: Map) -> ScriptResult<HttpRequest> {
    if let Some(unknown) = req.keys().find(|k| !SEND_KEYS.contains(&k.as_str())) {
        return Err(error(format!(
            "http.send(...) has no field '{unknown}'; the fields are {}",
            SEND_KEYS.join(", ")
        )));
    }

    let url = match text_field(&req, "url", "http.send")? {
        Some(url) if !url.is_empty() => url,
        _ => {
            return Err(error(
                "http.send(...) needs a 'url' like \"http://host/path\"",
            ))
        }
    };
    let (scheme, authority, path) = parse_url("http.send", &url)?;
    let method = text_field(&req, "method", "http.send")?.unwrap_or_else(|| "GET".to_string());

    // Header names and values go through `try_set`, which refuses the control
    // characters a header-injection payload needs.
    let mut headers = HeaderMap::new();
    if let Some(value) = req.get("headers").filter(|value| !value.is_unit()) {
        let map = value.read_lock::<Map>().ok_or_else(|| {
            error("http.send(...) 'headers' must be a map like #{ \"Name\": \"value\" }")
        })?;
        for (name, value) in map.iter() {
            let text = scalar_text(value).ok_or_else(|| {
                error(format!(
                    "http.send(...) header '{name}' must be a string, got a {}",
                    value.type_name()
                ))
            })?;
            headers
                .try_set(name, &text)
                .map_err(|err| error(format!("http.send(...) header '{name}': {err}")))?;
        }
    }

    let body = match req.get("body") {
        None => Body::Empty,
        Some(value) if value.is_unit() => Body::Empty,
        Some(value) => match dynamic_to_value(value) {
            Ok(Value::Str(text)) => Body::Bytes(text.into_bytes()),
            Ok(Value::Bytes(bytes)) => Body::Bytes(bytes),
            _ => {
                return Err(error(
                    "http.send(...) 'body' must be a string or a blob".to_string(),
                ))
            }
        },
    };

    Ok(HttpRequest {
        method,
        scheme,
        authority,
        path,
        version: HttpVersion::Http11,
        headers,
        body,
        timestamp: SystemTime::now(),
    })
}

/// What a script sees back from `http.send`.
fn response_map(flow: &HttpFlow) -> Map {
    let mut out = Map::new();
    out.insert("flow_id".into(), Dynamic::from(flow.id.to_string()));
    match &flow.response {
        Some(resp) => {
            out.insert("status".into(), Dynamic::from_int(resp.status as i64));
            out.insert(
                "headers".into(),
                Dynamic::from_map(header_map(&resp.headers)),
            );
            out.insert("body".into(), Dynamic::from(body_text(&resp.body)));
        }
        None => {
            out.insert("status".into(), Dynamic::UNIT);
            out.insert("headers".into(), Dynamic::from_map(Map::new()));
            out.insert("body".into(), Dynamic::from(String::new()));
        }
    }
    out
}

// ------------------------------------------------------------------ browser

/// The wired browser, or a catchable error: a build with no browser cannot
/// perform the action at all, which is a failure, not an absent answer.
fn driver(services: &ScriptServices) -> ScriptResult<Arc<dyn BrowserDriver>> {
    services.browser.clone().ok_or_else(|| {
        error("no browser is configured; start aitm with the browser enabled to use browser.*")
    })
}

/// `browser.navigate(url)`: SSRF pre-flight first (a private/loopback target
/// that is not explicitly in scope is refused before anything is driven), then
/// the scope/rate gate, then the drive. Later verbs act on the page this
/// admitted; the browser's own proxy connector guards its sub-resources.
fn navigate(services: &ScriptServices, url: &str) -> ScriptResult<()> {
    let driver = driver(services)?;
    let (_, authority, _) = parse_url("browser.navigate", url)?;
    let authority = normalize_authority("browser.navigate", url, &authority)?;

    ssrf_preflight(services, &authority)
        .map_err(|reason| denied("browser.navigate", &authority, &reason))?;
    let _permit = services
        .guard
        .check_active(&authority)
        .map_err(|reason| denied("browser.navigate", &authority, &reason))?;

    block_on(services, driver.navigate(url))
        .map(|_| ())
        .map_err(|err| failed("browser.navigate", err))
}

/// The SSRF decision for a navigation target, on `aitm-core`'s own check (the
/// one the proxy connector uses), under the deny-by-default policy.
///
/// A host that is already an address — or `localhost` — is classified here. A
/// DNS name is classified where it is resolved: the browser's proxy connector,
/// which sees the actual connection (and therefore redirects, page `fetch` and
/// sub-resources too). `aitm-core` exposes no resolver, and resolving here
/// would be a second, divergent decision path.
fn ssrf_preflight(services: &ScriptServices, authority: &str) -> Result<(), GuardError> {
    let parsed = Authority::parse_with_default(authority, 80)
        .map_err(|_| GuardError::OutOfScope(authority.to_string()))?;
    let dst = match parsed.ip() {
        Some(ip) => Some(ip),
        None if classify_host(&parsed.host) == HostClass::Loopback => {
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        }
        None => None,
    };
    match dst {
        Some(ip) => ssrf_check(
            &SsrfPolicy::default(),
            &services.guard.list_scope(),
            authority,
            ip,
        ),
        None => Ok(()),
    }
}

// -------------------------------------------------------------------- store

/// `store.get(id)`: the flow, or `()` when the store does not hold it (option
/// C — absence is an answer). An id that is not a flow id at all is a typo, and
/// says so.
fn get_flow(services: &ScriptServices, id: &str) -> ScriptResult<Dynamic> {
    let id = FlowId::from_str(id)
        .map_err(|_| error(format!("store.get(...): \"{id}\" is not a flow id")))?;
    Ok(services
        .store
        .get(id)
        .map(|flow| Dynamic::from_map(flow_map(&flow)))
        .unwrap_or(Dynamic::UNIT))
}

/// The filters `store.query(...)` accepts.
const QUERY_KEYS: [&str; 5] = ["host", "method", "status", "kind", "is_replay"];

/// `store.query(#{ … })`: every stored flow matching every set filter. A query
/// that matches nothing is an empty array, not an error.
fn query_flows(services: &ScriptServices, q: Map) -> ScriptResult<Array> {
    if let Some(unknown) = q.keys().find(|k| !QUERY_KEYS.contains(&k.as_str())) {
        return Err(error(format!(
            "store.query(...) has no filter '{unknown}'; the filters are {}",
            QUERY_KEYS.join(", ")
        )));
    }

    let kind = match text_field(&q, "kind", "store.query")?.as_deref() {
        None => None,
        Some("http") => Some(FlowKind::Http),
        Some("websocket" | "ws") => Some(FlowKind::WebSocket),
        Some(other) => {
            return Err(error(format!(
                "store.query(...) unknown kind \"{other}\"; use http or websocket"
            )))
        }
    };
    let status = match q.get("status") {
        None => None,
        Some(value) if value.is_unit() => None,
        Some(value) => {
            let code = value.as_int().ok().and_then(|i| u16::try_from(i).ok());
            Some(code.ok_or_else(|| error("store.query(...) 'status' must be a status code"))?)
        }
    };
    let is_replay = match q.get("is_replay") {
        None => None,
        Some(value) if value.is_unit() => None,
        Some(value) => Some(
            value
                .as_bool()
                .map_err(|_| error("store.query(...) 'is_replay' must be true or false"))?,
        ),
    };

    let query = FlowQuery {
        host: text_field(&q, "host", "store.query")?,
        method: text_field(&q, "method", "store.query")?,
        status,
        kind,
        is_replay,
    };

    Ok(services
        .store
        .query(&query)
        .into_iter()
        .filter_map(|id| services.store.get(id))
        .map(|flow| Dynamic::from_map(flow_map(&flow)))
        .collect())
}

/// A stored flow as a script reads it. WebSocket flows carry no request or
/// response; those read as `()` rather than being absent keys, so
/// `flow.response == ()` is a question a script can ask of any flow.
fn flow_map(flow: &Flow) -> Map {
    let mut out = Map::new();
    out.insert("id".into(), Dynamic::from(flow.id().to_string()));
    match flow {
        Flow::Http(f) => {
            out.insert("kind".into(), Dynamic::from("http"));
            out.insert("is_replay".into(), Dynamic::from_bool(f.metadata.is_replay));
            out.insert("marks".into(), marks(&f.metadata.marks));
            out.insert("request".into(), Dynamic::from_map(request_map(&f.request)));
            out.insert(
                "response".into(),
                match &f.response {
                    Some(resp) => Dynamic::from_map(http_response_map(resp)),
                    None => Dynamic::UNIT,
                },
            );
        }
        Flow::WebSocket(f) => {
            out.insert("kind".into(), Dynamic::from("websocket"));
            out.insert("is_replay".into(), Dynamic::from_bool(f.metadata.is_replay));
            out.insert("marks".into(), marks(&f.metadata.marks));
            out.insert("request".into(), Dynamic::UNIT);
            out.insert("response".into(), Dynamic::UNIT);
        }
    }
    out
}

fn marks(marks: &[String]) -> Dynamic {
    Dynamic::from_array(marks.iter().map(|m| Dynamic::from(m.clone())).collect())
}

fn request_map(req: &HttpRequest) -> Map {
    let mut out = Map::new();
    out.insert("method".into(), Dynamic::from(req.method.clone()));
    out.insert(
        "url".into(),
        Dynamic::from(format!("{}://{}{}", req.scheme, req.authority, req.path)),
    );
    out.insert("path".into(), Dynamic::from(req.path.clone()));
    out.insert(
        "headers".into(),
        Dynamic::from_map(header_map(&req.headers)),
    );
    out.insert("body".into(), Dynamic::from(body_text(&req.body)));
    out
}

fn http_response_map(resp: &HttpResponse) -> Map {
    let mut out = Map::new();
    out.insert("status".into(), Dynamic::from_int(resp.status as i64));
    out.insert(
        "headers".into(),
        Dynamic::from_map(header_map(&resp.headers)),
    );
    out.insert("body".into(), Dynamic::from(body_text(&resp.body)));
    out
}

// -------------------------------------------------------------------- scope

/// `scope.add(host)`: widen the authorized scope through the guard itself, so
/// every later check — a script's and a Rust plugin's alike — sees it. Logged,
/// because an operator auditing a run wants to see scope grow.
fn add_scope(services: &ScriptServices, host: &str) -> ScriptResult<()> {
    let host = host.trim();
    if host.is_empty() || Authority::parse_with_default(host, 0).is_err() {
        return Err(error(format!(
            "scope.add(...): \"{host}\" is not a host, host:port or *.wildcard"
        )));
    }
    tracing::info!(target: HOST_TARGET, host, "script added a scope entry");
    services.guard.add_scope(ScopeEntry {
        host: host.to_string(),
    });
    Ok(())
}

// ------------------------------------------------------------------ helpers

/// Split `scheme://host[:port]/path?query`. Only `http`/`https` are
/// addressable from a script; userinfo is refused, because the guard keys on
/// the host and `user@host` reads as one.
fn parse_url(capability: &str, url: &str) -> ScriptResult<(String, String, String)> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        error(format!(
            "{capability}(...): URL \"{url}\" has no scheme; write http:// or https://"
        ))
    })?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(error(format!(
            "{capability}(...): only http and https URLs can be sent, got \"{scheme}\""
        )));
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    };
    if authority.is_empty() {
        return Err(error(format!(
            "{capability}(...): URL \"{url}\" has no host"
        )));
    }
    if authority.contains('@') {
        return Err(error(format!(
            "{capability}(...): URL \"{url}\" carries userinfo; give the host alone"
        )));
    }
    Ok((scheme.to_ascii_lowercase(), authority, path))
}

/// The authority a guard decision keys on: host folded, port filled in from
/// the scheme, IPv6 unbracketed — the same fold the rest of the system uses.
fn normalize_authority(capability: &str, url: &str, authority: &str) -> ScriptResult<String> {
    let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or("http");
    Authority::parse_with_default(authority, Authority::default_port(scheme))
        .map(|parsed| parsed.to_string())
        .map_err(|err| error(format!("{capability}(...): URL \"{url}\": {err}")))
}

/// An optional string field; present-but-not-a-string is an error naming it.
fn text_field(map: &Map, key: &str, capability: &str) -> ScriptResult<Option<String>> {
    match map.get(key) {
        None => Ok(None),
        Some(value) if value.is_unit() => Ok(None),
        Some(value) => scalar_text(value).map(Some).ok_or_else(|| {
            error(format!(
                "{capability}(...) '{key}' must be a string, got a {}",
                value.type_name()
            ))
        }),
    }
}

/// The text of a scalar Rhai value (a string, number or bool); `None` for a
/// map, array, blob or anything else that has no single-line spelling.
fn scalar_text(value: &Dynamic) -> Option<String> {
    match dynamic_to_value(value).ok()? {
        Value::Str(s) => Some(s),
        Value::Int(i) => Some(i.to_string()),
        Value::Float(f) => Some(f.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn header_map(headers: &HeaderMap) -> Map {
    headers
        .iter()
        .map(|(name, value)| (name.into(), Dynamic::from(value.to_string())))
        .collect()
}

/// A body as a script reads it. Only buffered bytes exist at this layer; a
/// still-streaming body reads as empty rather than blocking the hook.
fn body_text(body: &Body) -> String {
    match body {
        Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

/// A catchable runtime error; the engine fills in the call position.
fn error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.into()), Position::NONE).into()
}

/// A guard refusal, as the script sees it: catchable, naming the capability,
/// the host and why. Denial is never forgiven into an "absent" answer.
fn denied(capability: &str, host: &str, reason: &GuardError) -> Box<EvalAltResult> {
    tracing::warn!(target: HOST_TARGET, capability, host, %reason, "script capability denied");
    error(format!("{capability} to {host} denied: {reason}"))
}

/// An action that was allowed but did not succeed (upstream refused the
/// connection, the browser could not drive the page, …).
fn failed(capability: &str, err: anyhow::Error) -> Box<EvalAltResult> {
    error(format!("{capability} failed: {err}"))
}
