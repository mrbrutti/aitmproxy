//! The `WsLanguage` and the `ws.*` namespace — written by task 8 of the T4 plan.
//!
//! An operator's Rhai command dials an **in-scope** WebSocket endpoint, sends a
//! frame, reads the replies and closes:
//!
//! ```rhai
//! let h = ws.dial(#{ url: "ws://target.test/ws", headers: #{ "Cookie": "sid=…" } });
//! ws.send(h, "{\"type\":\"chat\",\"msg\":\"hi\"}");
//! let reply = ws.recv(h, 1500);
//! ws.close(h);
//! ```
//!
//! Every dial is gated by [`ScopeRateGuard::check_active`] on the request's
//! authority **before** a socket is opened (the guard check lives inside
//! [`WsDialer::dial_request`], the only place the authority is known), and at
//! most [`MAX_HANDLES`] connections are open at once (spec D8.3, plan calls 7
//! and 17).
//!
//! ## Why there is a driver thread
//!
//! A seam [`HostFn`] is a **synchronous** closure, while a WebSocket
//! conversation is async and must survive across calls (`dial` … `send` …
//! `recv` … `close`). So the language owns one background thread running a
//! current-thread tokio runtime that holds the open [`WsConn`]s; each host fn
//! sends it a [`DriverCmd`] over `std::sync::mpsc` and blocks on the reply with
//! a timeout. The thread starts lazily on the first `ws.dial`.
//!
//! ## Redaction
//!
//! Nothing here puts a header value or a frame payload into an error, a log
//! line or a `Debug` output: a bad header is named, never quoted, and a refused
//! upgrade is reported by status alone.

use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use aitm_core::guard::ScopeRateGuard;
use aitm_core::{GuardError, StdGuard, Value};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallCtx, HostError, HostFn, HostFnSig, NamespaceCatalog, ParamSig,
    PocStepHandler, ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_scan_model::{Frame, FrameKind};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, Request};

use crate::dialer::{DialError, DialLimits, DialOutcome, WsConn, WsDialer, REGENERATED_HEADERS};
use crate::transport::TcpTransport;
use crate::types::{
    authority_with_port, TlsPolicy, HANDLE_IDLE_REAP, MAX_HANDLES, RECV_TIMEOUT_CAP_MS,
};

/// The namespace this crate contributes: the `ws.*` host fns.
pub const NAMESPACE: &str = "ws";

/// The `ws` namespace's API version (a per-namespace semver-ish token).
pub const API_VERSION: &str = "1";

/// The four verbs of the namespace, in catalog order.
const VERBS: [&str; 4] = ["dial", "send", "recv", "close"];

/// How long a `ws.dial` waits for the guard, a slot, the socket and the 101.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the production dialer waits for a TCP connect and a TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Slack added to a command's own timeout before the host fn gives up on the
/// driver answering at all.
const REPLY_GRACE: Duration = Duration::from_secs(2);

/// How often the idle driver wakes to reap handles nobody is using.
const REAP_TICK: Duration = Duration::from_secs(5);

/// Why a `ws.dial` is refused once [`MAX_HANDLES`] are open (plan call 24).
const HANDLE_BOUND_REASON: &str = "4 handles already open; close one first";

/// A [`MAX_HANDLES`]-bounded reply window: `ms` clamped into
/// `0..=`[`RECV_TIMEOUT_CAP_MS`].
///
/// A script cannot park a worker thread for longer than the cap however large
/// a `timeout_ms` it passes, and a negative timeout is "poll what is already
/// buffered" rather than an error.
#[must_use]
pub fn clamp_timeout(ms: i64) -> u32 {
    u32::try_from(ms.clamp(0, i64::from(RECV_TIMEOUT_CAP_MS))).unwrap_or(RECV_TIMEOUT_CAP_MS)
}

/// The `ws.*` protocol language: the namespace plus its live dialer.
///
/// Build it with [`WsLanguage::new`] for an engine that dials
/// ([`crate::language`] does, from `crates/aitm/src/main.rs`), or with
/// [`WsLanguage::for_catalog`] for the static [`NamespaceCatalog`] alone.
pub struct WsLanguage {
    link: Arc<DriverLink>,
}

impl WsLanguage {
    /// A language whose dials are gated by `guard` and made through `dialer`.
    ///
    /// The driver thread is **not** started here: it spawns on the first
    /// `ws.dial`, so an engine that merely has the namespace installed costs
    /// nothing.
    #[must_use]
    pub fn new(guard: Arc<dyn ScopeRateGuard>, dialer: Arc<WsDialer>) -> Self {
        Self {
            link: Arc::new(DriverLink {
                guard,
                dialer,
                sender: Mutex::new(None),
            }),
        }
    }

    /// A language for [`NamespaceCatalog`] assembly only.
    ///
    /// Its guard is a fresh [`StdGuard`] with an **empty** scope, so even if a
    /// catalog instance were somehow registered every dial would be refused
    /// `OutOfScope`. Nothing is dialled and no thread is started.
    #[must_use]
    pub fn for_catalog() -> Self {
        Self::new(
            Arc::new(StdGuard::default()),
            Arc::new(production_dialer(TlsPolicy::Verify)),
        )
    }
}

/// The production dialer: a real TCP/TLS socket under `tls`.
///
/// **Security review, named item (plan call 3; finding S2).** [`build`] passes
/// [`TlsPolicy::Verify`]: upstream certificates are checked against the webpki
/// roots, the same default `aitm-proto-http`'s `Http1Sender` has
/// (`Config.ssl_insecure = false`). [`TlsPolicy::AcceptAny`] skips chain
/// validation (the handshake signature is still verified) and is for the
/// operator's `ssl_insecure` setting through [`build_with`]. Either way every
/// dial passes the scope guard and the SSRF check before a socket is opened.
fn production_dialer(tls: TlsPolicy) -> WsDialer {
    WsDialer::new(Arc::new(TcpTransport::new(tls, CONNECT_TIMEOUT)))
}

/// The `ws.*` protocol language, or `None` while the namespace is unimplemented.
///
/// `crate::language()` delegates here, so flipping the slot is an edit inside
/// this module and `lib.rs` is written once (plan call 11). Every `ws.*` host
/// fn is `Guarded` through `guard`, and the dialer verifies upstream
/// certificates ([`TlsPolicy::Verify`]); see [`build_with`] for the
/// `ssl_insecure` posture.
#[must_use]
pub fn build(guard: Arc<dyn ScopeRateGuard>) -> Option<Box<dyn ProtocolLanguage>> {
    build_with(guard, TlsPolicy::Verify)
}

/// The `ws.*` protocol language with an explicit certificate policy.
///
/// `TlsPolicy::AcceptAny` is for `Config.ssl_insecure`; wiring that setting
/// through `main.rs` is a coordinator hand-off.
#[must_use]
pub fn build_with(
    guard: Arc<dyn ScopeRateGuard>,
    tls: TlsPolicy,
) -> Option<Box<dyn ProtocolLanguage>> {
    Some(Box::new(WsLanguage::new(
        guard,
        Arc::new(production_dialer(tls)),
    )))
}

impl ProtocolLanguage for WsLanguage {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn api_version(&self) -> &str {
        API_VERSION
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        for verb in VERBS {
            let link = Arc::clone(&self.link);
            let name = verb.to_string();
            let f: HostFn =
                Box::new(move |ctx: &HostCallCtx, args: &[Value]| host_fn(&link, &name, ctx, args));
            reg.register(NAMESPACE, verb, Guarded::new(Box::new(WsSeamGuard), f))?;
        }
        Ok(())
    }

    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        // No `ws:` PoC step in v2 (plan call 19): a WS finding is an issue, and
        // a hint would describe a step the runner cannot execute.
        None
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: NAMESPACE.to_string(),
            api_version: API_VERSION.to_string(),
            host_fns: catalog_host_fns(),
            poc_step: None,
            sources: Vec::new(),
        }
    }
}

/// The guard the seam installs around each `ws.*` host fn.
///
/// It admits the four verbs for **every** caller and refuses anything else. The
/// real authorization is not here and cannot be: the scope/rate check needs the
/// dial's *authority*, which only [`WsDialer::dial_request`] knows, so it runs
/// there — before any socket is opened — and the permit is held for the
/// connection's life.
///
/// **Known gap (plan call 17, as amended).** Spec D8.3 says a hook
/// (`on_ws_*`) cannot call `ws.*`, only commands and checks. The seam carries
/// no hook-vs-command signal today (`RunKind` is internal to
/// `aitm-plugin-rhai`), so that sentence is **not enforceable in this crate**
/// and is handed to the coordinator. T1b exposes the run kind through a
/// default-bodied method on `HostCallContextSource`; when it lands, the one
/// `match` below grows an arm that refuses a hook, and nothing else changes.
/// Until then `ws.*` stays scope-guarded, budgeted and bounded to
/// [`MAX_HANDLES`].
struct WsSeamGuard;

impl GuardHandle for WsSeamGuard {
    fn guard_name(&self) -> &str {
        NAMESPACE
    }

    fn permit(&self, ctx: &HostCallCtx, fn_name: &str) -> Result<(), HostError> {
        // The caller's trust is read but not gated on: an operator command and
        // an agent-driven check are both admitted here and both pass the same
        // scope guard inside `ws.dial`. This is the single place a run-kind
        // signal gets honoured when the seam grows one.
        let _ = ctx;
        match fn_name {
            "dial" | "send" | "recv" | "close" => Ok(()),
            other => Err(HostError::GuardRefused {
                namespace: NAMESPACE.to_string(),
                reason: format!("`{other}` is not a `ws` verb"),
            }),
        }
    }
}

/// The static signatures of the four verbs, in catalog order.
fn catalog_host_fns() -> Vec<HostFnSig> {
    vec![
        HostFnSig {
            name: "dial".to_string(),
            params: vec![ParamSig {
                name: "options".to_string(),
                ty: "object".to_string(),
                description:
                    "`#{ url: \"ws://host/path\", headers: #{ name: value } }`; the URL must be \
                     `ws://` or `wss://` and its authority must be in scope."
                        .to_string(),
            }],
            returns: "int".to_string(),
            description:
                "Open a scope-guarded WebSocket connection and return its handle; at most 4 are \
                 open at once."
                    .to_string(),
        },
        HostFnSig {
            name: "send".to_string(),
            params: vec![
                ParamSig {
                    name: "handle".to_string(),
                    ty: "int".to_string(),
                    description: "A handle returned by `ws.dial`.".to_string(),
                },
                ParamSig {
                    name: "frame".to_string(),
                    ty: "string|blob".to_string(),
                    description: "A string is sent as a Text frame, a blob as a Binary frame."
                        .to_string(),
                },
            ],
            returns: "null".to_string(),
            description: "Send one frame on an open handle.".to_string(),
        },
        HostFnSig {
            name: "recv".to_string(),
            params: vec![
                ParamSig {
                    name: "handle".to_string(),
                    ty: "int".to_string(),
                    description: "A handle returned by `ws.dial`.".to_string(),
                },
                ParamSig {
                    name: "timeout_ms".to_string(),
                    ty: "int".to_string(),
                    description: "How long to collect replies for, clamped to 30000 ms."
                        .to_string(),
                },
            ],
            returns: "object".to_string(),
            description:
                "Collect the frames the server sent, as `#{ frames: [ #{ kind, text, bytes } ] }`; \
                 Pings are answered."
                    .to_string(),
        },
        HostFnSig {
            name: "close".to_string(),
            params: vec![ParamSig {
                name: "handle".to_string(),
                ty: "int".to_string(),
                description: "A handle returned by `ws.dial`.".to_string(),
            }],
            returns: "null".to_string(),
            description: "Send a Close frame and free the handle.".to_string(),
        },
    ]
}

/// Dispatch one `ws.<verb>(..)` call to its implementation.
fn host_fn(
    link: &DriverLink,
    verb: &str,
    ctx: &HostCallCtx,
    args: &[Value],
) -> Result<Value, HostError> {
    let _ = ctx;
    match verb {
        "dial" => dial(link, args),
        "send" => send(link, args),
        "recv" => recv(link, args),
        "close" => close(link, args),
        other => Err(HostError::BadArgs(format!(
            "`ws.{other}` is not a websocket verb"
        ))),
    }
}

/// `ws.dial(#{ url, headers? }) -> int`.
fn dial(link: &DriverLink, args: &[Value]) -> Result<Value, HostError> {
    let options = match args {
        [Value::Object(options)] => options,
        _ => {
            return Err(HostError::BadArgs(
                "ws.dial takes one object: #{ url: \"ws://host/path\", headers: #{ .. } }"
                    .to_string(),
            ))
        }
    };
    let url = match options.get("url") {
        Some(Value::Str(url)) => url.as_str(),
        _ => {
            return Err(HostError::BadArgs(
                "ws.dial needs a string `url`".to_string(),
            ))
        }
    };
    let request = build_request(url, options.get("headers"))?;
    let authority = authority_of(&request);

    let sender = link.start()?;
    let handle = link.ask(&sender, DIAL_TIMEOUT + REPLY_GRACE, |reply| {
        DriverCmd::Dial {
            request: Box::new(request),
            authority,
            reply,
        }
    })?;
    Ok(Value::Int(handle))
}

/// `ws.send(handle, text | blob) -> ()`.
fn send(link: &DriverLink, args: &[Value]) -> Result<Value, HostError> {
    let (handle, frame) = match args {
        [Value::Int(handle), Value::Str(text)] => (
            *handle,
            Frame {
                kind: FrameKind::Text,
                payload: text.as_bytes().to_vec(),
            },
        ),
        [Value::Int(handle), Value::Bytes(bytes)] => (
            *handle,
            Frame {
                kind: FrameKind::Binary,
                payload: bytes.clone(),
            },
        ),
        _ => {
            return Err(HostError::BadArgs(
                "ws.send takes a handle and a string or a blob".to_string(),
            ))
        }
    };
    let sender = link.started().ok_or_else(|| unknown_handle(handle))?;
    link.ask(&sender, DIAL_TIMEOUT + REPLY_GRACE, |reply| {
        DriverCmd::Send {
            handle,
            frame,
            reply,
        }
    })?;
    Ok(Value::Null)
}

/// `ws.recv(handle, timeout_ms) -> #{ frames: [ .. ] }`.
fn recv(link: &DriverLink, args: &[Value]) -> Result<Value, HostError> {
    let (handle, timeout_ms) = match args {
        [Value::Int(handle), Value::Int(timeout_ms)] => (*handle, clamp_timeout(*timeout_ms)),
        _ => {
            return Err(HostError::BadArgs(
                "ws.recv takes a handle and a timeout in milliseconds".to_string(),
            ))
        }
    };
    let window = Duration::from_millis(u64::from(timeout_ms));
    let sender = link.started().ok_or_else(|| unknown_handle(handle))?;
    let frames = link.ask(&sender, window + REPLY_GRACE, |reply| DriverCmd::Recv {
        handle,
        window,
        reply,
    })?;
    let frames = frames.into_iter().map(frame_value).collect();
    Ok(Value::Object(BTreeMap::from([(
        "frames".to_string(),
        Value::Array(frames),
    )])))
}

/// `ws.close(handle) -> ()`.
fn close(link: &DriverLink, args: &[Value]) -> Result<Value, HostError> {
    let handle = match args {
        [Value::Int(handle)] => *handle,
        _ => return Err(HostError::BadArgs("ws.close takes a handle".to_string())),
    };
    let sender = link.started().ok_or_else(|| unknown_handle(handle))?;
    link.ask(&sender, DIAL_TIMEOUT + REPLY_GRACE, |reply| {
        DriverCmd::Close { handle, reply }
    })?;
    Ok(Value::Null)
}

/// One received frame as the script sees it.
///
/// A Text frame carries `text`; every other kind carries `bytes`, so a script
/// never has to guess which field is present for a kind.
fn frame_value(frame: Frame) -> Value {
    let kind = match frame.kind {
        FrameKind::Text => "text",
        FrameKind::Binary => "binary",
        FrameKind::Ping => "ping",
        FrameKind::Pong => "pong",
        FrameKind::Close => "close",
    };
    let mut fields = BTreeMap::from([("kind".to_string(), Value::Str(kind.to_string()))]);
    if frame.kind == FrameKind::Text {
        fields.insert(
            "text".to_string(),
            Value::Str(String::from_utf8_lossy(&frame.payload).into_owned()),
        );
    } else {
        fields.insert("bytes".to_string(), Value::Bytes(frame.payload));
    }
    Value::Object(fields)
}

/// The upgrade request for `url` with the script's `headers` applied.
///
/// Only `ws://` and `wss://` are accepted, and a header the dialer regenerates
/// for every connection ([`REGENERATED_HEADERS`]) cannot be set by a script: a
/// replayed `Sec-WebSocket-Key` would make the server's `Sec-WebSocket-Accept`
/// meaningless and a forged `Host` would lie about the authority the guard just
/// admitted. Errors name the offending header, never its value.
fn build_request(url: &str, headers: Option<&Value>) -> Result<Request<()>, HostError> {
    let scheme_ok = url.len() >= 5
        && (url[..5].eq_ignore_ascii_case("ws://")
            || (url.len() >= 6 && url[..6].eq_ignore_ascii_case("wss://")));
    if !scheme_ok {
        return Err(HostError::BadArgs(format!(
            "ws.dial needs a ws:// or wss:// url, not {url}"
        )));
    }
    let mut request = url
        .into_client_request()
        .map_err(|err| HostError::BadArgs(format!("{url} is not a websocket url: {err}")))?;

    let fields = match headers {
        None | Some(Value::Null) => return Ok(request),
        Some(Value::Object(fields)) => fields,
        Some(_) => {
            return Err(HostError::BadArgs(
                "ws.dial's `headers` must be an object of name/value strings".to_string(),
            ))
        }
    };
    for (name, value) in fields {
        let Value::Str(value) = value else {
            return Err(HostError::BadArgs(format!(
                "the value of header {name} must be a string"
            )));
        };
        if REGENERATED_HEADERS
            .iter()
            .any(|known| name.eq_ignore_ascii_case(known))
        {
            return Err(HostError::BadArgs(format!(
                "{name} is regenerated for every dial and cannot be set by a script"
            )));
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HostError::BadArgs(format!("{name} is not a valid header name")))?;
        let header = HeaderValue::from_str(value).map_err(|_| {
            HostError::BadArgs(format!(
                "the value of header {name} cannot be sent on the wire"
            ))
        })?;
        request.headers_mut().insert(name, header);
    }
    Ok(request)
}

/// The `host:port` the guard will be asked about, for the refusal reason.
///
/// Mirrors [`WsDialer::dial_request`]'s own derivation so the reason names the
/// authority the guard actually saw.
fn authority_of(request: &Request<()>) -> String {
    let uri = request.uri();
    let scheme = uri.scheme_str().unwrap_or("ws");
    let host = uri.host().unwrap_or_default();
    match uri.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => authority_with_port(scheme, host),
    }
}

/// The variant name of a [`GuardError`], for the refusal reason (plan call 24).
///
/// The *variant*, not the `Display` text: AC T4-4 greps for `OutOfScope`, and a
/// variant name carries nothing from the guard's internals.
fn guard_error_variant(err: &GuardError) -> &'static str {
    match err {
        GuardError::OutOfScope(_) => "OutOfScope",
        GuardError::PrivateAddressBlocked(_) => "PrivateAddressBlocked",
        GuardError::RateLimited { .. } => "RateLimited",
        GuardError::ConcurrencyExceeded => "ConcurrencyExceeded",
        GuardError::HostDisabled => "HostDisabled",
    }
}

/// The error for a handle no open connection answers to.
fn unknown_handle(handle: i64) -> HostError {
    HostError::BadArgs(format!("no open websocket handle {handle}"))
}

/// The error for a driver that is not running, or did not answer in time.
fn driver_unavailable() -> HostError {
    HostError::BadArgs("ws driver unavailable".to_string())
}

/// One command a host fn asks the driver thread to run.
///
/// Each carries the one-shot channel the driver answers on, so a host fn blocks
/// on exactly its own reply.
enum DriverCmd {
    /// Open a connection and register a handle for it.
    Dial {
        /// The upgrade request, already validated. Boxed: it is far larger than
        /// the other variants and only `Dial` needs it.
        request: Box<Request<()>>,
        /// The `host:port` the guard is asked about, for the refusal reason.
        authority: String,
        /// Where the new handle (or the refusal) goes.
        reply: SyncSender<Result<i64, HostError>>,
    },
    /// Send one frame on an open handle.
    Send {
        handle: i64,
        frame: Frame,
        reply: SyncSender<Result<(), HostError>>,
    },
    /// Collect the frames that arrive within `window`.
    Recv {
        handle: i64,
        window: Duration,
        reply: SyncSender<Result<Vec<Frame>, HostError>>,
    },
    /// Close a handle and free its connection.
    Close {
        handle: i64,
        reply: SyncSender<Result<(), HostError>>,
    },
}

/// The host fns' side of the driver: the live state plus the channel to it.
///
/// The thread starts on the first [`DriverLink::start`] (i.e. the first
/// `ws.dial`) and stops when the last clone of this link drops and the channel
/// disconnects — which also drops every open [`WsConn`], releasing its guard
/// permit and the dialer's connection slot.
struct DriverLink {
    guard: Arc<dyn ScopeRateGuard>,
    dialer: Arc<WsDialer>,
    sender: Mutex<Option<Sender<DriverCmd>>>,
}

impl DriverLink {
    /// The channel to the driver, starting the thread if this is the first call.
    fn start(&self) -> Result<Sender<DriverCmd>, HostError> {
        let mut slot = self.sender.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sender) = slot.as_ref() {
            return Ok(sender.clone());
        }
        let (sender, receiver) = mpsc::channel();
        let guard = Arc::clone(&self.guard);
        let dialer = Arc::clone(&self.dialer);
        thread::Builder::new()
            .name("aitm-ws-script".to_string())
            .spawn(move || run_driver(&receiver, &guard, &dialer))
            .map_err(|_| driver_unavailable())?;
        *slot = Some(sender.clone());
        Ok(sender)
    }

    /// The channel to the driver, or `None` when no `ws.dial` has run yet.
    fn started(&self) -> Option<Sender<DriverCmd>> {
        self.sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Send one command and block for its reply, at most `wait`.
    ///
    /// A driver that has gone away, or has not answered within `wait`, is
    /// [`driver_unavailable`] rather than a hang: a host fn runs on a worker
    /// thread a script is waiting on.
    fn ask<T>(
        &self,
        sender: &Sender<DriverCmd>,
        wait: Duration,
        command: impl FnOnce(SyncSender<Result<T, HostError>>) -> DriverCmd,
    ) -> Result<T, HostError> {
        let (reply, answers) = mpsc::sync_channel(1);
        sender
            .send(command(reply))
            .map_err(|_| driver_unavailable())?;
        match answers.recv_timeout(wait) {
            Ok(answer) => answer,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                Err(driver_unavailable())
            }
        }
    }
}

/// One open script connection and when it was last touched.
struct OpenHandle {
    conn: WsConn,
    last_used: Instant,
}

/// The driver thread: a current-thread runtime and the open connections.
///
/// `std::sync::mpsc` blocks the thread, so the loop waits for a command
/// *outside* the runtime and enters it per command; the [`REAP_TICK`] timeout
/// doubles as the idle sweep.
fn run_driver(
    commands: &Receiver<DriverCmd>,
    guard: &Arc<dyn ScopeRateGuard>,
    dialer: &Arc<WsDialer>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        // Nothing can be answered without a runtime; dropping the receiver
        // disconnects the channel and every host fn reports the driver gone.
        Err(err) => {
            tracing::debug!(error = %err, "the ws script driver could not start a runtime");
            return;
        }
    };
    let mut state = DriverState {
        handles: HashMap::new(),
        next_handle: 1,
    };
    loop {
        match commands.recv_timeout(REAP_TICK) {
            Ok(command) => runtime.block_on(state.run(command, guard, dialer)),
            Err(RecvTimeoutError::Timeout) => runtime.block_on(state.reap()),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    // The language is gone: close what is still open before the runtime drops.
    runtime.block_on(state.close_all());
}

/// The driver's own state: the open handles and the next handle number.
struct DriverState {
    handles: HashMap<i64, OpenHandle>,
    next_handle: i64,
}

impl DriverState {
    /// Run one command, answering on its reply channel.
    ///
    /// A receiver that has already given up (its host fn timed out) makes the
    /// send fail; that is expected and ignored — the handle table stays correct
    /// either way.
    async fn run(
        &mut self,
        command: DriverCmd,
        guard: &Arc<dyn ScopeRateGuard>,
        dialer: &Arc<WsDialer>,
    ) {
        self.reap().await;
        match command {
            DriverCmd::Dial {
                request,
                authority,
                reply,
            } => {
                let answer = self.dial(*request, &authority, guard, dialer).await;
                let _ = reply.send(answer);
            }
            DriverCmd::Send {
                handle,
                frame,
                reply,
            } => {
                let answer = self.send(handle, frame).await;
                let _ = reply.send(answer);
            }
            DriverCmd::Recv {
                handle,
                window,
                reply,
            } => {
                let answer = self.recv(handle, window).await;
                let _ = reply.send(answer);
            }
            DriverCmd::Close { handle, reply } => {
                let answer = self.close(handle).await;
                let _ = reply.send(answer);
            }
        }
    }

    /// Dial, register the connection and return its handle.
    async fn dial(
        &mut self,
        request: Request<()>,
        authority: &str,
        guard: &Arc<dyn ScopeRateGuard>,
        dialer: &Arc<WsDialer>,
    ) -> Result<i64, HostError> {
        if self.handles.len() >= MAX_HANDLES {
            return Err(HostError::GuardRefused {
                namespace: NAMESPACE.to_string(),
                reason: HANDLE_BOUND_REASON.to_string(),
            });
        }
        let deadline = Instant::now() + DIAL_TIMEOUT;
        let outcome = dialer
            .dial_request(request, guard.as_ref(), deadline, DialLimits::default())
            .await;
        match outcome {
            Ok(DialOutcome::Upgraded(conn)) => {
                let handle = self.next_handle;
                self.next_handle += 1;
                self.handles.insert(
                    handle,
                    OpenHandle {
                        conn,
                        last_used: Instant::now(),
                    },
                );
                Ok(handle)
            }
            // A non-101 is data to the lane (plan call 18) but a script asked
            // for an open connection and did not get one; the status is the
            // whole story, and no response header is quoted.
            Ok(DialOutcome::Refused { status, .. }) => Err(HostError::BadArgs(format!(
                "upgrade refused with status {status}"
            ))),
            Err(DialError::Guard(err)) => Err(HostError::GuardRefused {
                namespace: NAMESPACE.to_string(),
                reason: format!("{}: {authority}", guard_error_variant(&err)),
            }),
            Err(err) => Err(HostError::BadArgs(err.to_string())),
        }
    }

    /// Send one frame on `handle`.
    async fn send(&mut self, handle: i64, frame: Frame) -> Result<(), HostError> {
        let open = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| unknown_handle(handle))?;
        open.last_used = Instant::now();
        // The error text is tungstenite's own (a protocol or socket message);
        // the frame payload never reaches it.
        open.conn
            .send(frame)
            .await
            .map_err(|err| HostError::BadArgs(format!("the frame could not be sent: {err}")))?;
        open.last_used = Instant::now();
        Ok(())
    }

    /// Collect the frames that arrive on `handle` within `window`.
    async fn recv(&mut self, handle: i64, window: Duration) -> Result<Vec<Frame>, HostError> {
        let open = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| unknown_handle(handle))?;
        open.last_used = Instant::now();
        // The collection's own deadline is the window plus the grace the host
        // fn is waiting out, so `collect` ends on the window, never on this.
        let deadline = Instant::now() + window + REPLY_GRACE;
        let outcome = open.conn.collect(window, deadline, &|| false).await;
        open.last_used = Instant::now();
        Ok(outcome.frames)
    }

    /// Close `handle` and free its connection.
    async fn close(&mut self, handle: i64) -> Result<(), HostError> {
        let mut open = self
            .handles
            .remove(&handle)
            .ok_or_else(|| unknown_handle(handle))?;
        open.conn.close().await;
        Ok(())
    }

    /// Close every handle untouched for longer than [`HANDLE_IDLE_REAP`].
    async fn reap(&mut self) {
        let idle: Vec<i64> = self
            .handles
            .iter()
            .filter(|(_, open)| open.last_used.elapsed() > HANDLE_IDLE_REAP)
            .map(|(handle, _)| *handle)
            .collect();
        for handle in idle {
            tracing::debug!(handle, "reaping an idle ws script handle");
            if let Some(mut open) = self.handles.remove(&handle) {
                open.conn.close().await;
            }
        }
    }

    /// Close every open handle, whatever its age.
    async fn close_all(&mut self) {
        let open: Vec<i64> = self.handles.keys().copied().collect();
        for handle in open {
            if let Some(mut open) = self.handles.remove(&handle) {
                open.conn.close().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use aitm_core::{CallerTrust, ScopeEntry, ScopeRateGuard, StdGuard, Value};
    use aitm_plugin::language::{
        GuardHandle, HostCallContextSource, HostCallCtx, HostError, ProtocolLanguage,
    };
    use aitm_plugin_rhai::config::RhaiLimits;
    use aitm_plugin_rhai::engine::build_engine_with_languages;
    use aitm_plugin_rhai::host_registry::seed_call_context;
    use rhai::{Blob, Dynamic, Engine, Map};

    use super::{clamp_timeout, WsLanguage, WsSeamGuard};
    use crate::dialer::WsDialer;
    use crate::testing::{echo_handler, ws_server, DuplexTransport, ServerLog};
    use crate::transport::WsTransport;

    /// A guard with exactly the two loopback authorities the tests dial.
    fn scoped_guard() -> Arc<dyn ScopeRateGuard> {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8080".to_string(),
        });
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8443".to_string(),
        });
        Arc::new(guard)
    }

    /// An engine with `ws.*` installed over a real tungstenite echo server.
    fn engine_over(
        guard: Arc<dyn ScopeRateGuard>,
    ) -> (Engine, Arc<DuplexTransport>, Arc<ServerLog>) {
        let (transport, log) = ws_server(None, echo_handler);
        let dialer = Arc::new(WsDialer::new(Arc::clone(&transport) as Arc<dyn WsTransport>));
        let language = WsLanguage::new(guard, dialer);
        let engine = build_engine_with_languages(
            &RhaiLimits::default(),
            Duration::from_secs(2),
            &[&language],
        )
        .expect("the ws language installs");
        (engine, transport, log)
    }

    #[test]
    fn script_round_trips_a_frame() {
        let (engine, _transport, log) = engine_over(scoped_guard());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        let reply: String = engine
            .eval(
                r#"
                let h = ws.dial(#{ url: "ws://127.0.0.1:8080/ws", headers: #{ "Cookie": "a=b" } });
                ws.send(h, "hi");
                let r = ws.recv(h, 500);
                ws.close(h);
                r.frames[0].text
            "#,
            )
            .expect("the round trip evaluates");
        assert_eq!(reply, "echo:hi");

        let handshake = log.handshakes().first().cloned().expect("one handshake");
        assert!(
            handshake.contains(&("cookie".to_string(), "a=b".to_string())),
            "the replayed handshake kept the script's header: {handshake:?}"
        );
    }

    #[test]
    fn out_of_scope_url_is_refused_before_connect() {
        let (engine, transport, _log) = engine_over(scoped_guard());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        let err = engine
            .eval::<Dynamic>(r#"ws.dial(#{ url: "ws://evil.test/ws" })"#)
            .expect_err("an out-of-scope dial is refused");
        let text = err.to_string();
        assert!(text.contains("OutOfScope"), "unexpected refusal: {text}");
        assert!(text.contains("evil.test:80"), "unexpected refusal: {text}");
        assert_eq!(
            transport.connects(),
            Vec::new(),
            "the guard refused before any socket was opened"
        );
    }

    #[test]
    fn fifth_handle_is_refused() {
        let (engine, _transport, _log) = engine_over(scoped_guard());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        let fourth: i64 = engine
            .eval(
                r#"
                let last = 0;
                for i in 0..4 {
                    last = ws.dial(#{ url: "ws://127.0.0.1:8080/ws" });
                }
                last
            "#,
            )
            .expect("four dials evaluate");
        assert_eq!(fourth, 4);

        let err = engine
            .eval::<Dynamic>(r#"ws.dial(#{ url: "ws://127.0.0.1:8080/ws" })"#)
            .expect_err("the fifth handle is refused");
        assert!(
            err.to_string().contains("4 handles already open"),
            "unexpected refusal: {err}"
        );

        let reopened: i64 = engine
            .eval(r#"ws.close(1); ws.dial(#{ url: "ws://127.0.0.1:8080/ws" })"#)
            .expect("a dial after a close evaluates");
        assert_eq!(reopened, 5);
    }

    #[test]
    fn unknown_handle_is_bad_args() {
        let (engine, _transport, _log) = engine_over(scoped_guard());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        let err = engine
            .eval::<Dynamic>(r#"ws.send(99, "x")"#)
            .expect_err("an unknown handle is an error");
        assert!(
            err.to_string().contains("bad arguments"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn binary_frames_come_back_as_blobs() {
        let (engine, _transport, _log) = engine_over(scoped_guard());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        let frame: Map = engine
            .eval(
                r#"
                let h = ws.dial(#{ url: "ws://127.0.0.1:8080/ws" });
                let b = blob();
                b.push(1);
                b.push(2);
                b.push(3);
                ws.send(h, b);
                let r = ws.recv(h, 400);
                ws.close(h);
                r.frames[0]
            "#,
            )
            .expect("a binary round trip evaluates");
        let kind = frame
            .get("kind")
            .cloned()
            .expect("the frame names its kind")
            .into_string()
            .expect("the kind is a string");
        assert_eq!(kind, "binary");
        let bytes: Blob = frame
            .get("bytes")
            .cloned()
            .expect("a binary frame carries bytes")
            .into_blob()
            .expect("the bytes are a blob");
        assert_eq!(bytes, vec![1u8, 2, 3]);
        assert!(
            !frame.contains_key("text"),
            "a binary frame carries no text field"
        );
    }

    #[test]
    fn clamp_timeout_bounds() {
        assert_eq!(clamp_timeout(99_999), 30_000);
        assert_eq!(clamp_timeout(-5), 0);
        assert_eq!(clamp_timeout(250), 250);
    }

    #[test]
    fn catalog_is_static_and_complete() {
        let catalog = WsLanguage::for_catalog().catalog();
        assert_eq!(catalog.namespace, "ws");
        assert_eq!(catalog.api_version, "1");
        assert_eq!(
            catalog
                .host_fns
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["dial", "send", "recv", "close"]
        );
        assert!(catalog.poc_step.is_none());
        assert_eq!(catalog.sources, Vec::<String>::new());
    }

    #[test]
    fn slot_is_some() {
        let language = crate::language(Arc::new(StdGuard::default())).expect("the slot is filled");
        assert_eq!(language.namespace(), "ws");
        assert_eq!(language.api_version(), "1");
    }

    #[test]
    fn wss_url_requests_tls() {
        let (engine, transport, _log) = engine_over(scoped_guard());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        let handle: i64 = engine
            .eval(r#"ws.dial(#{ url: "wss://127.0.0.1:8443/ws" })"#)
            .expect("a wss dial evaluates");
        assert_eq!(handle, 1);
        assert_eq!(
            transport.connects(),
            vec![(
                std::net::SocketAddr::from(([127, 0, 0, 1], 8443)),
                true,
                "127.0.0.1".to_string()
            )]
        );
    }
    // --- Refusals the `ws.*` surface owes an operator (tester, stage 5) ---
    //
    // The namespace is deny-by-default: a url it does not understand, a header
    // the dialer regenerates, a handle that is not open and a verb that is not
    // one of the four must each come back as an error naming the reason, never
    // as a silent no-op or a connection.

    /// The text of an error a one-line script produced, with no socket opened.
    fn refusal(script: &str) -> String {
        let (engine, transport, _log) = engine_over(scoped_guard());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        let err = engine
            .eval::<Dynamic>(script)
            .expect_err("the script must be refused");
        assert_eq!(
            transport.connects(),
            Vec::new(),
            "a refused call may not open a socket: {script}"
        );
        err.to_string()
    }

    #[test]
    fn a_non_websocket_scheme_is_bad_args() {
        for url in [
            "http://127.0.0.1:8080/ws",
            "file:///etc/passwd",
            "",
            "wss:/",
        ] {
            let text = refusal(&format!(r#"ws.dial(#{{ url: "{url}" }})"#));
            assert!(
                text.contains("ws.dial needs a ws:// or wss:// url"),
                "unexpected refusal for {url}: {text}"
            );
        }
    }

    #[test]
    fn a_dial_without_a_url_is_bad_args() {
        let text = refusal(r#"ws.dial(#{ headers: #{ "X": "1" } })"#);
        assert!(
            text.to_lowercase().contains("bad arguments"),
            "unexpected refusal: {text}"
        );
    }

    #[test]
    fn a_script_may_not_set_a_regenerated_header() {
        // A replayed key would make `Sec-WebSocket-Accept` meaningless and a
        // forged Host would lie about the authority the guard just admitted.
        for header in [
            "Sec-WebSocket-Key",
            "host",
            "Upgrade",
            "Connection",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Accept",
        ] {
            let text = refusal(&format!(
                r#"ws.dial(#{{ url: "ws://127.0.0.1:8080/ws", headers: #{{ "{header}": "x" }} }})"#
            ));
            assert!(
                text.contains("is regenerated for every dial and cannot be set by a script"),
                "unexpected refusal for {header}: {text}"
            );
            assert!(
                text.contains(header),
                "the refusal must name the header: {text}"
            );
        }
    }

    #[test]
    fn a_non_string_header_value_is_refused_without_quoting_it() {
        let text =
            refusal(r#"ws.dial(#{ url: "ws://127.0.0.1:8080/ws", headers: #{ "X-N": 1 } })"#);
        assert!(
            text.contains("the value of header X-N must be a string"),
            "unexpected refusal: {text}"
        );
    }

    #[test]
    fn recv_and_close_on_an_unknown_handle_are_bad_args() {
        for script in ["ws.recv(42, 10)", "ws.close(42)"] {
            let text = refusal(script);
            assert!(
                text.contains("no open websocket handle 42"),
                "unexpected refusal for {script}: {text}"
            );
        }
    }

    #[test]
    fn the_seam_guard_admits_the_four_verbs_and_nothing_else() {
        /// The minimum a `HostCallCtx` needs: no tag, a named origin.
        struct NoTag;
        impl HostCallContextSource for NoTag {
            fn tag(&self) -> Option<Value> {
                None
            }
            fn call_source(&self) -> &str {
                "tester"
            }
        }

        let guard = WsSeamGuard;
        assert_eq!(guard.guard_name(), "ws");
        let source = NoTag;
        let ctx = HostCallCtx::new(CallerTrust::Operator, &source);
        for verb in ["dial", "send", "recv", "close"] {
            assert!(guard.permit(&ctx, verb).is_ok(), "{verb} must be admitted");
        }
        match guard.permit(&ctx, "exec") {
            Err(HostError::GuardRefused { namespace, reason }) => {
                assert_eq!(namespace, "ws");
                assert_eq!(reason, "`exec` is not a `ws` verb");
            }
            other => panic!("a verb outside the namespace must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_upgrade_is_reported_with_its_status() {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide: crate::testing::HandshakeDecision = Arc::new(|_request| {
            let mut response =
                tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(None);
            *response.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED;
            Err(response)
        });
        let (transport, _log) = ws_server(Some(decide), echo_handler);
        let dialer = Arc::new(WsDialer::new(Arc::clone(&transport) as Arc<dyn WsTransport>));
        let language = WsLanguage::new(scoped_guard(), dialer);
        let engine = build_engine_with_languages(
            &RhaiLimits::default(),
            Duration::from_secs(2),
            &[&language],
        )
        .expect("the ws language installs");
        let _seed = seed_call_context(CallerTrust::Operator, None, None);

        let err = engine
            .eval::<Dynamic>(r#"ws.dial(#{ url: "ws://127.0.0.1:8080/ws" })"#)
            .expect_err("a script that asked for a connection did not get one");

        let text = err.to_string();
        assert!(
            text.contains("upgrade refused with status 401"),
            "unexpected error: {text}"
        );
    }
}
