//! The `probe.*` host functions and the thread-local check context they read
//! (plan Task 13): a check closure calls `probe.send`/`probe.baseline`/… against
//! the point the scheduler seeded.
//!
//! **Why a thread-local.** A check's `ProbeHost` is built by the lane for one
//! insertion point and handed to [`crate::check_bridge::ScriptCheck::run`] as a
//! borrow. Rhai needs every value a host function touches to be `'static`, so
//! the bridge parks an **owning** handle (`Arc<dyn ProbeHost>`, from the
//! default-bodied `ProbeHost::shared`) plus the point in [`CHECK_CTX`] for the
//! length of the call and clears it on the way out — no `unsafe`, no borrowed
//! pointer (plan call B5). Rhai (`sync`) evaluates on the calling thread, so the
//! context is seen by exactly the check that seeded it and never by a concurrent
//! one, the same rule [`crate::host_registry`]'s caller context follows.
//!
//! **Outside a check there is no probe.** Every verb here refuses when no
//! context is live, naming `http.send` as the thing a command should call
//! instead: a probe is budgeted, paced and recorded by the job that scheduled
//! it, and there is no job outside a check.
//!
//! **Bounded.** `send`/`baseline`/`raw` drive the host's future under
//! `min(remaining, 30 s)` ([`crate::engine::probe_budget`]), so one unanswered
//! probe cannot eat the whole per-check wall budget (spec D4).

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use aitm_scan_model::point::{InsertionPoint, Payload, ProbeResponse, RawProbe};
use aitm_scan_model::traits::ProbeHost;
use aitm_scan_model::vocab::PayloadMode;
use rhai::{Dynamic, Engine, EvalAltResult, ImmutableString, Map, Module, Position, FLOAT, INT};

use crate::engine::{probe_budget, MAX_PROBE_TIMEOUT};
use crate::host_core::{ScriptCapability, ScriptServices};

/// The `API` version this provider requires: M3's first and only one.
const API_1: &str = "1";

/// How close the Pearson correlation must be to 1 for a timing fit to count as
/// correlated (ZAP's `CORR_ERROR_RANGE`, spec D4).
const CORR_ERROR_RANGE: f32 = 0.15;

/// How close the slope must be to 1 for a timing fit to count as correlated
/// (ZAP's `SLOPE_ERROR_RANGE`, spec D4).
const SLOPE_ERROR_RANGE: f32 = 0.30;

/// What a check closure is running against: the point it was scheduled for and
/// an owning handle to the lane's probe host for that point.
pub struct CheckCtx {
    /// The lane-built host every probe goes through; it owns the budget, the
    /// scope guard and the record policy, so a script cannot send around it.
    pub host: Arc<dyn ProbeHost>,
    /// The insertion point the check is aimed at.
    pub point: InsertionPoint,
}

thread_local! {
    /// The check running on this thread, if any (see [`enter`]).
    static CHECK_CTX: RefCell<Option<CheckCtx>> = const { RefCell::new(None) };
}

/// Restores the context that was live before, when dropped — including during
/// an unwind, so a panicking check never leaves its host on the thread.
#[must_use = "the check context is cleared when the guard drops"]
pub struct CheckCtxGuard {
    previous: Option<CheckCtx>,
}

/// Make `ctx` the check context for this thread until the guard drops. The
/// bridge opens this around one `ScriptCheck::run`; nesting restores the outer
/// context, as the run and caller-context guards do.
pub fn enter(ctx: CheckCtx) -> CheckCtxGuard {
    let previous = CHECK_CTX.with(|cell| cell.borrow_mut().replace(ctx));
    CheckCtxGuard { previous }
}

impl Drop for CheckCtxGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CHECK_CTX.with(|cell| *cell.borrow_mut() = previous);
    }
}

/// The `probe` namespace: the only way a check closure reaches the network.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeCapability;

/// The value behind the script-visible `probe` constant.
#[derive(Clone)]
struct ProbeNs(ScriptServices);

impl ScriptCapability for ProbeCapability {
    fn namespace(&self) -> &str {
        "probe"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, services: &ScriptServices) {
        engine
            .register_type_with_name::<ProbeNs>("probe")
            .register_fn("send", |ns: &mut ProbeNs, payload: &str| {
                send(&ns.0, text_payload(payload))
            })
            .register_fn("send", |ns: &mut ProbeNs, payload: Map| {
                send(&ns.0, payload_from_map(payload)?)
            })
            .register_fn("baseline", |ns: &mut ProbeNs| baseline(&ns.0))
            .register_fn("raw", |ns: &mut ProbeNs, req: Map| raw(&ns.0, req))
            .register_fn(
                "marker",
                |_: &mut ProbeNs| -> ScriptResult<ImmutableString> {
                    with_host("marker", |host| Ok(host.marker().into()))
                },
            )
            .register_fn("budget_left", |_: &mut ProbeNs| -> ScriptResult<INT> {
                with_host("budget_left", |host| Ok(INT::from(host.budget_left())))
            })
            .register_fn("timing_fit", |_: &mut ProbeNs, input: Map| {
                script_timing_fit(input)
            })
            .register_fn(
                "levenshtein_ratio",
                |_: &mut ProbeNs, a: &str, b: &str| -> FLOAT {
                    FLOAT::from(levenshtein_ratio(a, b))
                },
            );

        let mut module = Module::new();
        module.set_var("probe", ProbeNs(services.clone()));
        engine.register_global_module(module.into());
    }
}

/// What every fallible `probe.*` verb returns: a Rhai error a script can
/// `try`/`catch`.
type ScriptResult<T> = Result<T, Box<EvalAltResult>>;

/// Run `f` against the live check host, or refuse: `probe.*` is meaningless
/// outside a check, and a command that wants the network has `http.send`.
fn with_host<T>(
    name: &str,
    f: impl FnOnce(&Arc<dyn ProbeHost>) -> ScriptResult<T>,
) -> ScriptResult<T> {
    let host = CHECK_CTX.with(|cell| cell.borrow().as_ref().map(|ctx| Arc::clone(&ctx.host)));
    match host {
        Some(host) => f(&host),
        None => Err(error(format!(
            "probe.{name} is only available inside a check closure (reg.add_check); \
             use http.send in a command"
        ))),
    }
}

/// Drive one probe future for `min(remaining, 30 s)` (spec D4). A probe that
/// outlives it is an error the check can catch, not a terminated run: the check
/// still has budget for its remaining probes and must be able to conclude.
fn drive_probe<T>(
    services: &ScriptServices,
    name: &str,
    fut: impl Future<Output = anyhow::Result<T>>,
) -> ScriptResult<T> {
    let budget = probe_budget().unwrap_or(MAX_PROBE_TIMEOUT);
    match services.rt.block_on(tokio::time::timeout(budget, fut)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(error(format!("probe.{name} failed: {err}"))),
        Err(_) => Err(error(format!(
            "probe.{name} did not answer within {budget:?}"
        ))),
    }
}

/// The payload `probe.send("…")` builds: the text replaces the point's value,
/// which is what a check means nine times out of ten.
fn text_payload(value: &str) -> Payload {
    Payload {
        value: value.to_string(),
        mode: PayloadMode::Replace,
        bytes: None,
    }
}

/// The keys `probe.send(#{ … })` accepts.
const SEND_KEYS: [&str; 2] = ["value", "mode"];

/// The payload `probe.send(#{ value, mode })` builds. `mode` says how the
/// payload combines with the point's observed value — a check that appends to a
/// real parameter value keeps the request plausible, which is the difference
/// between a reflected-XSS probe that reaches the sink and one the application
/// rejects out of hand.
fn payload_from_map(map: Map) -> ScriptResult<Payload> {
    if let Some(unknown) = map.keys().find(|k| !SEND_KEYS.contains(&k.as_str())) {
        return Err(error(format!(
            "probe.send(...) has no field '{unknown}'; the fields are {}",
            SEND_KEYS.join(", ")
        )));
    }
    let value = text_field(&map, "value").ok_or_else(|| {
        error("probe.send(#{ … }) needs a 'value'; probe.send(\"payload\") is the short form")
    })?;
    let mode = match text_field(&map, "mode") {
        None => PayloadMode::Replace,
        Some(token) => {
            serde_json::from_value::<PayloadMode>(serde_json::Value::String(token.clone()))
                .map_err(|_| {
                    error(format!(
                        "probe.send(...) mode '{token}' is not a payload mode; they are \
                 replace, prefix, suffix"
                    ))
                })?
        }
    };
    Ok(Payload {
        value,
        mode,
        bytes: None,
    })
}

/// `probe.send(payload)`: place `payload` at the point the check was scheduled
/// for and send. The lane owns the encoding and the `Content-Length`; the check
/// only chooses the text and how it combines (spec D4).
fn send(services: &ScriptServices, payload: Payload) -> ScriptResult<Map> {
    with_host("send", |host| {
        drive_probe(services, "send", host.probe(&payload)).map(|r| response_map(&r))
    })
}

/// `probe.baseline()`: the point's unpayloaded response, cached by the host.
fn baseline(services: &ScriptServices) -> ScriptResult<Map> {
    with_host("baseline", |host| {
        drive_probe(services, "baseline", host.baseline()).map(|r| response_map(&r))
    })
}

/// The keys `probe.raw(...)` accepts, for the error a typo gets.
const RAW_KEYS: [&str; 4] = ["method", "url", "headers", "body"];

/// `probe.raw(#{ method, url, headers, body })`: a request the check built
/// itself, for a handshake or header check a payload-at-a-point cannot express.
/// The host applies the same scope, budget and deadline rules as `probe.send`.
fn raw(services: &ScriptServices, req: Map) -> ScriptResult<Map> {
    if let Some(unknown) = req.keys().find(|k| !RAW_KEYS.contains(&k.as_str())) {
        return Err(error(format!(
            "probe.raw(...) has no field '{unknown}'; the fields are {}",
            RAW_KEYS.join(", ")
        )));
    }
    let url = text_field(&req, "url")
        .ok_or_else(|| error("probe.raw(...) needs a 'url' like \"http://host/path\""))?;
    let method = text_field(&req, "method").unwrap_or_else(|| "GET".to_string());

    let mut headers = Vec::new();
    if let Some(value) = req.get("headers").filter(|value| !value.is_unit()) {
        let map = value.read_lock::<Map>().ok_or_else(|| {
            error("probe.raw(...) 'headers' must be a map like #{ \"Name\": \"value\" }")
        })?;
        for (name, value) in map.iter() {
            let text = value.read_lock::<ImmutableString>().ok_or_else(|| {
                error(format!(
                    "probe.raw(...) header '{name}' must be a string, got a {}",
                    value.type_name()
                ))
            })?;
            headers.push((name.to_string(), text.to_string()));
        }
    }

    let body = match req.get("body") {
        None => Vec::new(),
        Some(value) if value.is_unit() => Vec::new(),
        Some(value) => match value.read_lock::<ImmutableString>() {
            Some(text) => text.as_bytes().to_vec(),
            None => match value.read_lock::<rhai::Blob>() {
                Some(blob) => blob.clone(),
                None => return Err(error("probe.raw(...) 'body' must be a string or a blob")),
            },
        },
    };

    let probe = RawProbe {
        method,
        url,
        headers,
        body,
    };
    with_host("raw", |host| {
        drive_probe(services, "raw", host.probe_raw(probe.clone())).map(|r| response_map(&r))
    })
}

/// A string field of a script-supplied map, when present and a string.
fn text_field(map: &Map, key: &str) -> Option<String> {
    map.get(key)
        .and_then(|v| v.read_lock::<ImmutableString>().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
}

/// What a check sees back from a probe.
///
/// The same shape and the same header/body representation as `http.send`'s own
/// response map (`host_net::response_map`) — keys `status`, `headers`, `body`,
/// `elapsed_ms`, `flow_id`, headers as a map of name to string, body as lossy
/// UTF-8 — so a script reads a probe and a send the same way. It cannot call
/// that function: a `ProbeResponse` carries `Vec<(String, String)>` headers and
/// raw body bytes, not the `HeaderMap`/`Body` those helpers take. The parity is
/// pinned by `tests/check_bridge.rs::probe_response_has_the_http_send_shape`.
///
/// `status` and `flow_id` are `()` when the lane had none (an L4 probe has no
/// status; an unrecorded probe has no flow).
fn response_map(response: &ProbeResponse) -> Map {
    let mut out = Map::new();
    out.insert(
        "status".into(),
        match response.status {
            Some(status) => Dynamic::from_int(INT::from(status)),
            None => Dynamic::UNIT,
        },
    );
    let mut headers = Map::new();
    for (name, value) in &response.headers {
        headers.insert(name.as_str().into(), Dynamic::from(value.clone()));
    }
    out.insert("headers".into(), Dynamic::from_map(headers));
    out.insert(
        "body".into(),
        Dynamic::from(String::from_utf8_lossy(&response.body).to_string()),
    );
    out.insert(
        "elapsed_ms".into(),
        Dynamic::from_int(INT::from(response.elapsed_ms)),
    );
    out.insert(
        "flow_id".into(),
        match &response.flow {
            Some(flow) => Dynamic::from(flow.to_string()),
            None => Dynamic::UNIT,
        },
    );
    out
}

/// How a set of delay payloads correlated with the times observed (spec D4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimingFit {
    /// Whether the fit is a correlation under ZAP's rule.
    pub correlated: bool,
    /// Slope of observed seconds against requested seconds; ~1 when correlated.
    pub slope: f32,
    /// Pearson correlation coefficient of the fit.
    pub r: f32,
}

/// `probe.timing_fit(#{ requested_s: [..], observed_ms: [..] })`.
fn script_timing_fit(input: Map) -> ScriptResult<Map> {
    let requested = float_array(&input, "requested_s")?;
    let observed = int_array(&input, "observed_ms")?;
    if requested.len() != observed.len() {
        return Err(error(format!(
            "probe.timing_fit(...): requested_s has {} entries and observed_ms {}; \
             they describe the same probes and must match",
            requested.len(),
            observed.len()
        )));
    }
    let fit = timing_fit(&requested, &observed);
    let mut out = Map::new();
    out.insert("correlated".into(), Dynamic::from_bool(fit.correlated));
    out.insert("slope".into(), Dynamic::from_float(FLOAT::from(fit.slope)));
    out.insert("r".into(), Dynamic::from_float(FLOAT::from(fit.r)));
    Ok(out)
}

/// Read `key` as an array of numbers (a script may write `1` or `1.0`).
fn float_array(map: &Map, key: &str) -> ScriptResult<Vec<f32>> {
    let array = map
        .get(key)
        .and_then(|v| v.read_lock::<rhai::Array>().map(|a| a.clone()))
        .ok_or_else(|| error(format!("probe.timing_fit(...) needs an array '{key}'")))?;
    array
        .iter()
        .map(|v| {
            v.as_float()
                .map(|f| f as f32)
                .or_else(|_| v.as_int().map(|i| i as f32))
                .map_err(|_| {
                    error(format!(
                        "probe.timing_fit(...) '{key}' must hold numbers, got a {}",
                        v.type_name()
                    ))
                })
        })
        .collect()
}

/// Read `key` as an array of whole milliseconds.
fn int_array(map: &Map, key: &str) -> ScriptResult<Vec<u32>> {
    let array = map
        .get(key)
        .and_then(|v| v.read_lock::<rhai::Array>().map(|a| a.clone()))
        .ok_or_else(|| error(format!("probe.timing_fit(...) needs an array '{key}'")))?;
    array
        .iter()
        .map(|v| {
            v.as_int()
                .map(|i| i.clamp(0, INT::from(u32::MAX)) as u32)
                .or_else(|_| {
                    v.as_float()
                        .map(|f| f.clamp(0.0, f64::from(u32::MAX)) as u32)
                })
                .map_err(|_| {
                    error(format!(
                        "probe.timing_fit(...) '{key}' must hold numbers, got a {}",
                        v.type_name()
                    ))
                })
        })
        .collect()
}

/// Fit the observed response times against the delays the payloads asked for
/// (spec D4, ZAP's rule).
///
/// The fit is a least-squares slope of observed **seconds** over requested
/// seconds with its Pearson `r`. It counts as a correlation only when all three
/// hold: `r` is within [`CORR_ERROR_RANGE`] of 1, the slope is within
/// [`SLOPE_ERROR_RANGE`] of 1, and every observation at a longer requested delay
/// exceeded every observation at a shorter one — the alternating long/short
/// check that rejects a target which simply got slower while the probes ran.
/// Fewer than two distinct requested delays cannot show a correlation at all.
pub fn timing_fit(requested_s: &[f32], observed_ms: &[u32]) -> TimingFit {
    let n = requested_s.len().min(observed_ms.len());
    let xs = &requested_s[..n];
    let observed_s: Vec<f32> = observed_ms[..n]
        .iter()
        .map(|ms| *ms as f32 / 1000.0)
        .collect();

    let distinct: BTreeSet<u32> = xs.iter().map(|x| x.to_bits()).collect();
    if n < 2 || distinct.len() < 2 {
        return TimingFit {
            correlated: false,
            slope: 0.0,
            r: 0.0,
        };
    }

    let count = n as f32;
    let mean_x = xs.iter().sum::<f32>() / count;
    let mean_y = observed_s.iter().sum::<f32>() / count;
    let mut sxy = 0.0;
    let mut sxx = 0.0;
    let mut syy = 0.0;
    for (x, y) in xs.iter().zip(observed_s.iter()) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    let slope = if sxx > 0.0 { sxy / sxx } else { 0.0 };
    let denominator = (sxx * syy).sqrt();
    let r = if denominator > 0.0 {
        sxy / denominator
    } else {
        0.0
    };

    let correlated = (1.0 - r).abs() <= CORR_ERROR_RANGE
        && (slope - 1.0).abs() <= SLOPE_ERROR_RANGE
        && longer_delays_took_longer(xs, &observed_s);

    TimingFit {
        correlated,
        slope,
        r,
    }
}

/// Whether every observation at a longer requested delay exceeded every
/// observation at a shorter one (ZAP's alternating long/short rule).
fn longer_delays_took_longer(requested_s: &[f32], observed_s: &[f32]) -> bool {
    for (i, (xi, yi)) in requested_s.iter().zip(observed_s).enumerate() {
        for (xj, yj) in requested_s.iter().zip(observed_s).skip(i + 1) {
            let (shorter, longer) = if xi < xj {
                (yi, yj)
            } else if xj < xi {
                (yj, yi)
            } else {
                continue;
            };
            if longer <= shorter {
                return false;
            }
        }
    }
    true
}

/// How alike two strings are: `1 - distance / max(len)`, so `1.0` is identical
/// (two empty strings included) and `0.0` shares nothing. The boolean-blind
/// companion to [`timing_fit`]: a check compares a payloaded body against the
/// baseline without shipping its own string metric.
pub fn levenshtein_ratio(a: &str, b: &str) -> f32 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let longest = a.len().max(b.len());
    if longest == 0 {
        return 1.0;
    }
    let distance = levenshtein(&a, &b) as f32;
    1.0 - distance / longest as f32
}

/// Levenshtein edit distance over two character sequences, one row at a time.
fn levenshtein(a: &[char], b: &[char]) -> usize {
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != cb);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

/// A catchable runtime error; the engine fills in the call position.
fn error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.into()), Position::NONE).into()
}
