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
//! the caller — `LoadedScript::dispatch`, or a test — has already entered
//! `tokio::task::block_in_place`, so blocking this worker is legal and tokio
//! moves other tasks elsewhere. Every future is driven under
//! `tokio::time::timeout` for what is left of the run's wall-clock budget
//! ([`crate::engine::remaining_budget`]), so a peer that never answers ends
//! the hook at its deadline exactly as a busy loop would — the handle must
//! therefore come from a runtime with timers enabled. `browser.*` is the one
//! exception (T9): a navigation or DOM fetch legitimately outlives a hook
//! budget, so each browser call is bounded by the run's own
//! [`crate::engine::browser_budget`] instead, and on completion renews the
//! run's deadline ([`crate::engine::extend_deadline`]) so the script's next
//! operation is not aborted for the time the browser took. No second network
//! path exists: every verb here passes the same `ScopeRateGuard` / SSRF guard
//! a Rust plugin passes.
//!
//! **Who is calling matters** ([`crate::engine::current_run`]). `browser.*` is
//! refused inside a flow hook: the embedded browser routes through this proxy,
//! so the navigation would queue on the chain lock the hook is holding.
//! `scope.add` is refused from a PoC step always, and from plugins unless the
//! operator set `rhai: allow_scope_add: true`.
//!
//! **Option C.** A read whose answer may simply be absent is forgiving —
//! `store.get(unknown)` is `()`, a query matching nothing is an empty array. A
//! **guard refusal is never forgiven**: it is a catchable Rhai error naming the
//! capability and the reason, because a denial is not an absence.

use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_browser::{check_url, HostResolver, SystemResolver};
use aitm_core::{
    Authority, Body, BrowserDriver, ClickTarget, Flow, FlowId, FlowKind, FlowQuery, GuardError,
    HeaderMap, HttpFlow, HttpRequest, HttpResponse, HttpVersion, ScopeEntry, SsrfPolicy, Value,
};
use rhai::{
    Array, Blob, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Module, NativeCallContext,
    Position,
};

use crate::config::{DEFAULT_BROWSER_TIMEOUT, DEFAULT_HOOK_TIMEOUT};
use crate::engine::{
    browser_budget, current_run, extend_deadline, remaining_budget, AbortKind, RunKind,
};
use crate::host_core::{ScriptCapability, ScriptServices};
use crate::marshal::{dynamic_to_value, value_to_dynamic};

/// The `API` version these providers require: M3's first and only one.
const API_1: &str = "1";

/// A guard refusal as the script catches it: `e.capability`, `e.host`,
/// `e.reason`, and `"" + e` / `print(e)` render the one-line message. Thrown
/// as the payload of a runtime error so that, uncaught, the dispatcher can
/// recognise it and report the spec's pinned denial format rather than a
/// generic runtime failure (`ScriptError::from_eval`).
#[derive(Debug, Clone)]
pub struct DeniedToken {
    pub capability: String,
    pub host: String,
    pub reason: GuardError,
}

impl std::fmt::Display for DeniedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} to {} denied: {}",
            self.capability, self.host, self.reason
        )
    }
}

/// Make [`DeniedToken`] readable from a script. Idempotent; every provider
/// whose verbs can be refused registers it.
fn register_denial(engine: &mut Engine) {
    engine
        .register_type_with_name::<DeniedToken>("Denied")
        .register_get("capability", |d: &mut DeniedToken| -> ImmutableString {
            d.capability.as_str().into()
        })
        .register_get("host", |d: &mut DeniedToken| -> ImmutableString {
            d.host.as_str().into()
        })
        .register_get("reason", |d: &mut DeniedToken| -> ImmutableString {
            d.reason.to_string().into()
        })
        .register_fn("to_string", |d: &mut DeniedToken| -> ImmutableString {
            d.to_string().into()
        })
        .register_fn("to_debug", |d: &mut DeniedToken| -> ImmutableString {
            format!("{d:?}").into()
        });
}

/// Log target for what a script's guarded verbs do, so an operator can filter
/// scope changes and refusals out of the rest of the log.
const HOST_TARGET: &str = "aitm_plugin_rhai::host";

/// `http.send(#{ method, url, headers, body }) -> #{ status, headers, body, flow_id }`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpCapability;

/// `browser.navigate/click/type_text/screenshot/evaluate/get_dom`, with the
/// SSRF policy `navigate` checks a target against and the resolver it uses.
#[derive(Clone)]
pub struct BrowserCapability {
    policy: SsrfPolicy,
    resolver: Arc<dyn HostResolver>,
}

/// `store.get(id)` / `store.query(#{ … })`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoreCapability;

/// `scope.add(host)` / `scope.list()`; `add` only when the operator allowed it.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScopeCapability {
    allow_add: bool,
}

/// The value behind the script-visible `http` constant.
#[derive(Clone)]
struct HttpNs(ScriptServices);

/// The value behind the script-visible `browser` constant.
#[derive(Clone)]
struct BrowserNs {
    services: ScriptServices,
    policy: SsrfPolicy,
    resolver: Arc<dyn HostResolver>,
}

/// The value behind the script-visible `store` constant.
#[derive(Clone)]
struct StoreNs(ScriptServices);

/// The value behind the script-visible `scope` constant.
#[derive(Clone)]
struct ScopeNs {
    services: ScriptServices,
    allow_add: bool,
}

impl Default for BrowserCapability {
    /// The deny-by-default policy and the system resolver.
    fn default() -> Self {
        Self::new(SsrfPolicy::default())
    }
}

impl BrowserCapability {
    /// `navigate` decides under `policy` — the host's `browser.ssrf` — with
    /// the operating system's resolver.
    pub fn new(policy: SsrfPolicy) -> Self {
        Self {
            policy,
            resolver: Arc::new(SystemResolver),
        }
    }

    /// Resolve names through `resolver` instead (tests).
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }
}

impl ScopeCapability {
    /// `allow_add` is `rhai: allow_scope_add` — whether plugin scripts may
    /// widen the scope. PoC steps may not, whatever it says.
    pub fn new(allow_add: bool) -> Self {
        Self { allow_add }
    }
}

impl ScriptCapability for HttpCapability {
    fn namespace(&self) -> &str {
        "http"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, services: &ScriptServices) {
        register_denial(engine);
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
        register_denial(engine);
        engine
            .register_type_with_name::<BrowserNs>("browser")
            .register_fn("navigate", |ns: &mut BrowserNs, url: &str| {
                navigate(ns, url)
            })
            .register_fn("click", |ns: &mut BrowserNs, target: &str| {
                let driver = driver(ns, "browser.click")?;
                block_on_browser(
                    "browser.click",
                    &ns.services,
                    driver.click(ClickTarget::Selector(target.to_string())),
                )
            })
            .register_fn(
                "type_text",
                |ns: &mut BrowserNs, selector: &str, text: &str| {
                    let driver = driver(ns, "browser.type_text")?;
                    block_on_browser(
                        "browser.type_text",
                        &ns.services,
                        driver.type_text(selector, text),
                    )
                },
            )
            .register_fn("screenshot", |ns: &mut BrowserNs| -> ScriptResult<Blob> {
                let driver = driver(ns, "browser.screenshot")?;
                block_on_browser("browser.screenshot", &ns.services, driver.screenshot())
            })
            // `evaluate`, not `eval`: `eval` is a Rhai reserved word and cannot
            // be a method name, so no script could call it (spec §6). The MCP
            // and CLI tool is still named `browser.eval` — a tool name is not a
            // Rhai identifier.
            .register_fn("evaluate", |ns: &mut BrowserNs, expr: &str| {
                let driver = driver(ns, "browser.evaluate")?;
                block_on_browser("browser.evaluate", &ns.services, driver.eval(expr))
                    .map(|value| value_to_dynamic(&value))
            })
            .register_fn(
                "get_dom",
                |ns: &mut BrowserNs| -> ScriptResult<ImmutableString> {
                    let driver = driver(ns, "browser.get_dom")?;
                    block_on_browser("browser.get_dom", &ns.services, driver.get_dom())
                        .map(ImmutableString::from)
                },
            );
        set_namespace(
            engine,
            "browser",
            BrowserNs {
                services: services.clone(),
                policy: self.policy.clone(),
                resolver: Arc::clone(&self.resolver),
            },
        );
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
            .register_fn(
                "add",
                |ctx: NativeCallContext, ns: &mut ScopeNs, host: &str| add_scope(&ctx, ns, host),
            )
            .register_fn("list", |ns: &mut ScopeNs| -> Array {
                ns.services
                    .guard
                    .list_scope()
                    .into_iter()
                    .map(|entry| Dynamic::from(entry.host))
                    .collect()
            });
        set_namespace(
            engine,
            "scope",
            ScopeNs {
                services: services.clone(),
                allow_add: self.allow_add,
            },
        );
    }
}

/// What every fallible verb returns: a Rhai error a script can `try`/`catch`
/// (or, for a budget abort, a termination it cannot).
type ScriptResult<T> = Result<T, Box<EvalAltResult>>;

/// Expose `value` to scripts as the global constant `name`.
fn set_namespace<T: Clone + Send + Sync + 'static>(engine: &mut Engine, name: &str, value: T) {
    let mut module = Module::new();
    module.set_var(name, value);
    engine.register_global_module(module.into());
}

/// Drive a guarded future from the synchronous engine, for at most what is
/// left of the run's budget. The caller has already entered `block_in_place`,
/// so this worker may block. A future that outlives the budget aborts the run
/// with the same Timeout termination `on_progress` would raise — the hook
/// ends at its deadline whether it is computing or waiting. Outside any run
/// (a bare evaluation) the default hook budget applies.
fn block_on<T>(
    capability: &str,
    services: &ScriptServices,
    fut: impl Future<Output = anyhow::Result<T>>,
) -> ScriptResult<T> {
    let budget = remaining_budget().unwrap_or(DEFAULT_HOOK_TIMEOUT);
    drive(capability, services, budget, AbortKind::Timeout, fut)
}

/// [`block_on`] for a `browser.*` verb (T9): the future gets the run's whole
/// `browser_timeout` rather than the hook remainder, and once it has
/// completed — succeeded or failed — the run's deadline is renewed, so the
/// script's follow-up work (reading the DOM it just fetched, the next
/// navigation) is not aborted for the time the browser legitimately took. A
/// browser that never answers still ends the run, at `browser_timeout`, with
/// a termination naming that budget. Outside any run the default browser
/// budget applies.
fn block_on_browser<T>(
    capability: &str,
    services: &ScriptServices,
    fut: impl Future<Output = anyhow::Result<T>>,
) -> ScriptResult<T> {
    let budget = browser_budget().unwrap_or(DEFAULT_BROWSER_TIMEOUT);
    let result = drive(capability, services, budget, AbortKind::BrowserTimeout, fut);
    match &result {
        // The browser never answered: the run is over, nothing to renew.
        Err(err) if matches!(**err, EvalAltResult::ErrorTerminated(..)) => {}
        // Answered (or failed, catchably): the script carries on with a
        // fresh hook budget for its own work.
        _ => extend_deadline(),
    }
    result
}

/// The bridge itself: block this worker on `fut` for at most `budget`; a
/// future that outlives it terminates the run with `abort`.
fn drive<T>(
    capability: &str,
    services: &ScriptServices,
    budget: std::time::Duration,
    abort: AbortKind,
    fut: impl Future<Output = anyhow::Result<T>>,
) -> ScriptResult<T> {
    match services.rt.block_on(tokio::time::timeout(budget, fut)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(failed(capability, err)),
        Err(_) => {
            tracing::warn!(
                target: HOST_TARGET,
                capability,
                ?budget,
                "host call outlived its budget; aborting the run"
            );
            Err(EvalAltResult::ErrorTerminated(Dynamic::from(abort), Position::NONE).into())
        }
    }
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

    let flow = block_on("http.send", services, services.client.send(request))?;
    Ok(response_map(&flow))
}

/// The keys `http.send(...)` accepts, for the error a typo gets.
const SEND_KEYS: [&str; 4] = ["method", "url", "headers", "body"];

/// Turn the script's request map into a captured-request shape. A malformed
/// request is a mistake, not an absence: it is refused with what to fix.
///
/// Nothing reaches the request line unvalidated: the method must be an HTTP
/// token (RFC 9110 §5.6.2) and the path/query may carry no space or control
/// character, so a CR/LF assembled from extracted data cannot smuggle a
/// header or a second request. Header names and values go through `try_set`,
/// which refuses the same characters.
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
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(error(format!(
            "http.send(...): URL \"{}\" has a space or control character in its path; percent-encode it",
            url.escape_default()
        )));
    }
    let method = text_field(&req, "method", "http.send")?.unwrap_or_else(|| "GET".to_string());
    if !is_token(&method) {
        return Err(error(format!(
            "http.send(...) 'method' must be an HTTP token like GET or POST, got \"{}\"",
            method.escape_default()
        )));
    }

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

/// RFC 9110 `token`: one or more `tchar`.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
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

/// The wired browser, or a catchable error — and, first, the run-kind gate:
/// a flow hook may not drive the browser at all. The embedded browser sends
/// every request through this proxy, so a navigation from a hook would queue
/// on the chain lock that hook is holding until the navigation timeout; the
/// verbs are safe from a script command or a PoC step, where no lock is held.
fn driver(ns: &BrowserNs, capability: &str) -> ScriptResult<Arc<dyn BrowserDriver>> {
    if current_run() == Some(RunKind::Hook) {
        return Err(error(format!(
            "{capability} is not available inside a flow hook: the browser drives its pages \
             through this proxy, so the navigation would wait on the chain that is running \
             this hook. Drive the browser from a script command (reg.add_command) or a PoC \
             script step instead."
        )));
    }
    ns.services.browser.clone().ok_or_else(|| {
        error("no browser is configured; start aitm with the browser enabled to use browser.*")
    })
}

/// `browser.navigate(url)`: the same SSRF decision as the Rust
/// `browser.navigate` command — resolve the host and classify every address
/// under the host's policy, so a scoped *name* pointing at a private address
/// is refused — then the scope/rate gate, then the drive. Later verbs act on
/// the page this admitted; the browser's own proxy connector guards its
/// sub-resources.
fn navigate(ns: &BrowserNs, url: &str) -> ScriptResult<()> {
    let driver = driver(ns, "browser.navigate")?;
    let (_, authority, _) = parse_url("browser.navigate", url)?;
    let authority = normalize_authority("browser.navigate", url, &authority)?;

    check_url(
        url,
        &ns.policy,
        &ns.services.guard.list_scope(),
        ns.resolver.as_ref(),
    )
    .map_err(|reason| denied("browser.navigate", &authority, &reason))?;
    let _permit = ns
        .services
        .guard
        .check_active(&authority)
        .map_err(|reason| denied("browser.navigate", &authority, &reason))?;

    block_on_browser("browser.navigate", &ns.services, driver.navigate(url)).map(|_| ())
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
/// every later check — a script's and a Rust plugin's alike — sees it.
///
/// Widening the scope also lifts the SSRF block for an address named exactly,
/// so this is the one verb that is *not* available by default: a plugin
/// script gets it only when the operator set `rhai: allow_scope_add: true`,
/// and a PoC step — a shareable artifact that runs inside the scope the
/// operator set — never does. Every widening is logged at `warn` with the
/// script that did it, because an operator auditing a run wants to see scope
/// grow.
fn add_scope(ctx: &NativeCallContext, ns: &ScopeNs, host: &str) -> ScriptResult<()> {
    if current_run() == Some(RunKind::PocStep) {
        return Err(error(
            "scope.add(...) is not available from a PoC script step: a PoC runs inside the \
             scope the operator set. Add the host with the scope.add command or the `scope:` \
             config before running it.",
        ));
    }
    if !ns.allow_add {
        return Err(error(
            "scope.add(...) is disabled: a script may not widen the engagement scope unless \
             the config sets `rhai: allow_scope_add: true`. Add the host with the scope.add \
             command or the `scope:` config instead.",
        ));
    }
    let host = host.trim();
    if host.is_empty() || Authority::parse_with_default(host, 0).is_err() {
        return Err(error(format!(
            "scope.add(...): \"{host}\" is not a host, host:port or *.wildcard"
        )));
    }
    tracing::warn!(
        target: HOST_TARGET,
        script = ctx.call_source().unwrap_or("<unnamed script>"),
        host,
        "script widened the engagement scope"
    );
    ns.services.guard.add_scope(ScopeEntry {
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
    let token = DeniedToken {
        capability: capability.to_string(),
        host: host.to_string(),
        reason: reason.clone(),
    };
    EvalAltResult::ErrorRuntime(Dynamic::from(token), Position::NONE).into()
}

/// An action that was allowed but did not succeed (upstream refused the
/// connection, the browser could not drive the page, …).
fn failed(capability: &str, err: anyhow::Error) -> Box<EvalAltResult> {
    error(format!("{capability} failed: {err}"))
}
