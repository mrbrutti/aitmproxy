# Scanner v2 track T4 (WebSocket lane) implementation plan

**Status:** Approved (T4 session, on Matt's autonomous-approval mandate, 2026-10-31)
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved), sections D1 (the two `aitm-scan-ws` slots), D2 (model types, `ws_*` insertion kinds, `Frame`, `ProbeResponse.ws_frames`), D4 (`Check`/`CheckMeta` contract), D5 (budget, record policy `issues_only`, held flows), D6 (`ws_path`), **D8.3** (the WS lane), D12 row T4 (exclusive ownership `crates/aitm-scan-ws/**`), Constraints (gate, deny-by-default, dependencies), Verification, ACs T4-1..T4-4; Architect's call 11 (direct dialer, 4 connections, no compression oracle) and A17 (the language takes the scope guard).
**Research:** `docs/research/19-ws-and-h2-active-scanning.md` §1-§3 (what Burp/ZAP do, the WS check classes and their oracles, the `tokio-tungstenite` 0.28 client API and the header replay rule).
**Branch / worktree:** `claude/scanner-v2-t4-384bc0` in `/Users/matt/Security/aitmproxy/.claude/worktrees/scanner-v2-t4-384bc0` (cut from `feat/scanner-v2-t1a`, PR #213; fast-forwarded to its head `e0464e0e`, which contains `main` v0.5.8).
**Size:** one PR; nineteen tasks in seven waves; roughly two days with parallel coders.

## Overview

T4 fills the `aitm-scan-ws` skeleton that T1a handed over. It turns both slots from `None`
to `Some`: `lane()` returns a `WsLane` that discovers insertion points from captured
WebSocket conversations, builds a per-point `WsProbeHost` over a direct `WsDialer`
(tokio-tungstenite over our own TCP/TLS, never the proxy listener), and ships eight native
checks (`cswsh`, `ws-auth-bypass-handshake`, `ws-input-reflection`, `ws-sql-error`,
`ws-ssti`, `ws-cmdi-echo`, `ws-oversize-frame`, `ws-subprotocol-observe`); `language(guard)`
returns a `WsLanguage` contributing the `ws.*` Rhai namespace (`dial`, `send`, `recv`,
`close`), every fn `Guarded`, every dial scope-checked by authority before any connect, at
most four handles open.

Nothing outside `crates/aitm-scan-ws/**` is edited by any task except the integration task
(a possible one-line re-pin of `crates/aitm/src/wire.rs`'s `skeleton_lane_slots_are_empty_today`
literal, which T1a's plan call A23 pre-authorises, and the integration-shared contract
lists only if a live `tools/list` shows a name this track added, which it does not). The
`ws` namespace is **not** added to `production_languages()` here: T4 exposes
`WsLanguage::for_catalog()` and the integration task records the one-line hand-off for
T1b/the coordinator (Architect's call 13 below).

Waves (tasks inside a wave touch disjoint files and fan out to parallel coders):

| Wave | Tasks | Depends on |
|---|---|---|
| 1 | Task 1 (scaffold: manifest, module tree, shared types, placeholders) | none |
| 2 | Task 2 (transport + testing helpers), Task 3 (discover), Task 4 (mutate), Task 5 (payload tables) | Task 1 |
| 3 | Task 6 (dialer) | Task 2 |
| 4 | Task 7 (probe host), Task 8 (`ws` language) | Task 7: 3, 4, 6; Task 8: 6 |
| 5 | Tasks 9-16 (one check each: cswsh, auth-bypass, reflection, sql-error, ssti, cmdi-echo, oversize, subprotocol) | Tasks 5, 7 |
| 6 | Task 17 (lane, `checks::all()`, slot flip) | Tasks 3, 7, 9-16 |
| 7 | Task 18 (live-proof tests), then Task 19 (integration) | Task 18: 8, 17; Task 19: 18 |

## Shared facts for every coder

- **TDD per task.** Write the named test first, run it and quote the red run (a compile
  error on a type that does not exist yet counts as red), implement, quote the green run.
  Commit after the task with the message `feat(scanner-v2): T4 task N - <name>` (fix tasks:
  `fix(scanner-v2): T4 <what>`), ending with the attribution line the session gives you.
- **Sandbox vs Terminal.** `cargo test -p aitm-scan-ws --offline`, `cargo clippy -p aitm-scan-ws --all-targets --offline -- -D warnings` and `cargo fmt --check` work in the
  sandbox (offline registry cache). **Binding a port does not**: every test that binds is in
  `crates/aitm-scan-ws/tests/` and marked `#[ignore = "binds a loopback port; run in the Terminal"]`;
  Task 19 runs them in the Terminal panel. Full gate from the worktree root before handing
  back: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  After any `Cargo.toml` edit run `cargo metadata --offline --format-version 1 >/dev/null; echo $?`
  and quote the exit code.
- **Hermetic by construction.** All in-crate tests drive the real tokio-tungstenite client
  and a real in-test tokio-tungstenite server (`accept_hdr_async`) over `tokio::io::duplex`
  through the `WsTransport` seam (Task 2). No mock of the WS protocol, no fake frames: the
  bytes on the duplex are RFC 6455 frames. Only the socket is replaced.
- **Offline dependencies (verified in the registry cache 2026-10-31):** `tokio-tungstenite 0.28.0`,
  `tungstenite 0.28.0`, `rustls 0.23.x`, `tokio-rustls 0.26.x`, `rustls-pki-types 1.12+`,
  `webpki-roots 0.26.11`, `form_urlencoded 1.2.2`, `serde_json 1.0.154`, `base64 0.22`.
  **Not** in the cache: `blake3` (so point ids do not use it; Task 3). The manifest is final
  after Task 1; no later task edits it. `tokio-tungstenite` 0.28 has **no** TLS feature on:
  TLS is done by us (`tokio-rustls` over a `TcpStream`, Task 2) and the tungstenite handshake
  runs over whatever `ByteStream` the transport returns via `client_async_with_config`.
- **Crate rules.** `#![forbid(unsafe_code)]` stays at the crate root; `[lints] workspace = true`
  stays. No `unwrap`/`expect`/indexing-that-can-panic on anything that came from the network
  or from a captured flow (headers, frame bytes, JSON): use `?`, `get`, `ok_or_else`. `unwrap`
  is fine in `#[cfg(test)]` code. Every `pub` item has a doc comment. `tracing` at `debug`
  only; no log line ever prints a header value or frame payload (log names and lengths).
- **Redaction rule (spec anti-goal; AC T2-6 style grep applies to us too).** Nothing that
  leaves this crate as a `Verdict.detail`, `Evidence.payload`, `Evidence.matched`,
  `InsertionPoint.example`, a `Debug` output or a log line may carry a cookie, an
  `Authorization` value or any header value of a point whose name `aitm_core::redact::is_secret_key`
  flags. Evidence excerpts are `aitm_scan_model::Evidence::excerpt(&aitm_core::redact::scrub_text(s))`
  (scrub first, then bound). `Evidence.matched` for signature checks is the **signature
  constant**, not the server text. `is_secret_key`/`scrub_text` are the only vocabulary (no
  `*_wide` variants exist in this tree).
- **Model facts (do not re-derive; `crates/aitm-scan-model/src/{traits,point,check,profile,vocab}.rs`).**
  `Lane`, `ProbeHost`, `JobCtx`, `Check` are object-safe, `Send + Sync`, async methods return
  `futures::future::BoxFuture`. T4 adds **no** method to any model trait. `ProbeResponse {
  status, headers, body (<= MAX_MATCH_BODY = 1 MiB), elapsed_ms, flow, ws_frames: Option<Vec<Frame>>, l4 }`;
  `Frame { kind: FrameKind::{Text,Binary,Ping,Pong,Close}, payload: Vec<u8> }`; `Payload { value, mode: PayloadMode::{Replace,Prefix,Suffix}, bytes }`;
  `RawProbe { method, url, headers: Vec<(String,String)>, body }`; `Verdict { outcome, confidence, evidence, detail, poc_hint }`;
  `CheckMeta { id, name, class, lanes, kinds, intensity, cost, technique, severity: aitm_poc::Severity, confidence_max, needs_baseline, wants_traits, targets_session, cwe, description, remediation, origin }`.
  `ScanProfile.ws: WsOptions { reply_window_ms: u32 (1500), max_frame_bytes: u32 (1_048_576) }`;
  `ScanProfile.http.record_probes: RecordProbes::{IssuesOnly, All}`; `ProfileTarget { origins: Vec<String>, l4 }`.
  `aitm_poc::Severity` has `Critical, High, Medium, Low, Info`. `Verdict` carries **no**
  severity: the issue's severity is `CheckMeta.severity` (see Architect's call 20 and the
  question list).
- **Core facts.** `aitm_core::{Flow::{Http(HttpFlow), WebSocket(WsFlow)}, HttpFlow { id, request: HttpRequest { method, scheme, authority, path, version: HttpVersion, headers: HeaderMap, body: Body, timestamp }, response: Option<HttpResponse { status, version, headers, trailers, body, timestamp }>, client_conn: ConnInfo { peer, sni, alpn, tls, established }, server_conn, metadata: FlowMeta { marks, comment, is_replay, created, duration, truncated, edited, source_app, capture_interface } (Default), intercept: InterceptState::Observed }, WsFlow { id, handshake: FlowId, messages: Vec<WsMessage { dir: WsDir, opcode: WsOpcode, data, timestamp, injected }>, client_conn, server_conn, metadata, intercept }}`;
  `Body::{Empty, Bytes(Vec<u8>), Streamed(_)}`; `FlowId::new()`; `HeaderMap::{new, get, set, remove, has, iter}` (case-insensitive);
  `FlowStore::{insert, get, query(&FlowQuery { host, method, status, kind: Option<FlowKind>, is_replay: Option<bool> }) -> Vec<FlowId>}`, `MemFlowStore::new()`;
  `ScopeRateGuard::{check_active(&str) -> Result<ActionPermit, GuardError>, add_scope(ScopeEntry { host })}`, `StdGuard::default()`,
  `GuardError::{OutOfScope, PrivateAddressBlocked, RateLimited { retry_after }, ConcurrencyExceeded, HostDisabled}` (read `crates/aitm-core/src/error.rs` for the exact payloads);
  `aitm_core::ByteStream = Pin<Box<dyn AsyncReadWrite + Send>>`; `aitm_core::Value::{Null,Bool,Int,Float,Str,Bytes,Array,Object(BTreeMap)}`.
- **Language seam facts (`crates/aitm-plugin/src/language.rs`).** `ProtocolLanguage { namespace, api_version, register_host_fns(&self, &mut dyn ScriptHostRegistry), poc_step() -> Option<Box<dyn PocStepHandler>>, catalog() -> NamespaceCatalog }`;
  `HostFn = Box<dyn Fn(&HostCallCtx, &[Value]) -> Result<Value, HostError> + Send + Sync>`; `Guarded::new(Box<dyn GuardHandle>, f)`;
  `GuardHandle { guard_name(); permit(&HostCallCtx, fn_name) }` (default refuses); `HostError::{GuardRefused { namespace, reason }, BadArgs(String)}` (the whole enum).
  Host fns are **synchronous** closures run on a blocking thread. Reference implementation:
  `crates/aitm-proto-l4/src/language.rs` (`L4Language::{new, for_catalog}`, `L4SeamGuard`,
  `host_fn` dispatch, `catalog_host_fns`). Test harness:
  `aitm_plugin_rhai::engine::build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(2), &[&lang])`
  + `aitm_plugin_rhai::host_registry::seed_call_context(CallerTrust::Operator, None, None)` + `engine.eval::<T>("ws.dial(...)")`
  (see `crates/aitm-plugin-rhai/tests/host_registry.rs`).
- **Call sites that are not ours.** `crates/aitm/src/wire.rs` (`aitm_scan_ws::lane()` in
  `collect_lanes`) and `crates/aitm/src/main.rs:225` (`aitm_scan_ws::language(handles.clone())`,
  `handles: Arc<LateHandles>` implementing `ScopeRateGuard`; unbound = refuse). Signatures are final.
- **Fixture rule.** `cargo test` is the inner loop and the gate; it is never acceptance
  evidence. Acceptance is Task 18's live proof, recorded in Shipped with observer output.

## Tasks

### Task 1: scaffold: final manifest, module tree, shared types, placeholders

- **Satisfies:** spec D12 row T4 (all edits inside the crate), Constraints "Dependencies"
  (per-crate TLS deps mirror `aitm-proto-http`), Architect's calls 1 (module layout) and 10.
- **Depends on:** none.
- **Files:** `crates/aitm-scan-ws/Cargo.toml` (modify; **final after this task**),
  `crates/aitm-scan-ws/src/lib.rs` (modify), `crates/aitm-scan-ws/src/types.rs` (create),
  placeholder files containing only a `//!` doc line naming the owning task: `src/transport.rs`,
  `src/testing.rs`, `src/dialer.rs`, `src/discover.rs`, `src/mutate.rs`, `src/payloads.rs`,
  `src/host.rs`, `src/lane.rs`, `src/language.rs`, `src/checks/mod.rs` (with the eight
  `pub mod` lines and a placeholder `all()`), `src/checks/{cswsh,auth_bypass,reflection,sql_error,ssti,cmdi_echo,oversize,subprotocol}.rs` (doc line only; an empty module compiles).
- **Change:**
  1. `Cargo.toml` `[dependencies]`: keep `aitm-core`, `aitm-plugin`, `aitm-scan-model`; add
     `anyhow.workspace`, `futures.workspace`, `serde_json.workspace`, `bytes.workspace`
     (tungstenite 0.28 `Message::Binary` carries `Bytes`), `tracing.workspace`,
     `tokio = { workspace = true, features = ["io-util", "net", "rt", "sync", "time", "macros"] }`,
     `tokio-tungstenite.workspace = true`, and per-crate, with a comment citing
     `aitm-proto-http`'s identical spec: `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }`,
     `tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12", "logging"] }`,
     `rustls-pki-types = { version = "1.9", features = ["std"] }`, `webpki-roots = "0.26"`,
     `form_urlencoded = "1"`. `[dev-dependencies]`: `tokio = { workspace = true, features = ["rt-multi-thread", "macros", "time"] }`,
     `rcgen = "0.14"` (self-signed cert for the TLS verifier tests), `rhai = { version = "1.27", features = ["sync"] }`
     (the version `aitm-plugin-rhai` pins), `aitm-plugin-rhai.workspace`, `aitm-proto-http.workspace`,
     `aitm-proto-ws.workspace`, `aitm-testtarget.workspace` (Task 18's live test). Each line
     carries a comment naming the task that uses it.
  2. `lib.rs`: keep the crate doc and `#![forbid(unsafe_code)]`; declare
     `pub mod types; pub mod transport; #[doc(hidden)] pub mod testing; pub mod dialer; pub mod discover; pub mod mutate; pub mod payloads; pub mod host; pub mod checks; pub mod lane; pub mod language;`;
     the two slot bodies become `lane::build()` and `language::build(guard)` (signatures
     unchanged); delete `skeleton_returns_none` (each placeholder carries its own pin test
     below).
  3. `types.rs` (shared by discover, mutate, host, lane; owned here so wave 2 compiles in parallel):
     `pub enum Locator { JsonPath(String), FormParam(String), WholeText, Binary, HandshakeHeader(String) }` (`Debug, Clone, PartialEq, Eq`);
     `pub struct PointSpec { pub ws_flow: aitm_core::FlowId, pub handshake: aitm_core::FlowId, pub frame_index: Option<usize>, pub locator: Locator }` (`Debug, Clone, PartialEq, Eq`);
     `pub struct HandshakeOverrides { pub set: Vec<(String, String)>, pub strip: Vec<String> }` (`Debug, Clone, Default, PartialEq, Eq`) with
     `pub fn set(name: &str, value: &str) -> Self`, `pub fn strip(name: &str) -> Self`, `pub fn and_strip(self, name: &str) -> Self`;
     `pub enum TlsPolicy { Verify, AcceptAny }` (`Debug, Clone, Copy, PartialEq, Eq`);
     `pub const MAX_CONNECTIONS: usize = 4;` `pub const HELD_PROBES: usize = 16;` `pub const MAX_HANDLES: usize = 4;` `pub const RECV_TIMEOUT_CAP_MS: u32 = 30_000;` `pub const HANDLE_IDLE_REAP: Duration = Duration::from_secs(30);`
     `pub fn default_port(scheme: &str) -> u16` (`https`/`wss` -> 443, else 80) and
     `pub fn authority_with_port(scheme: &str, authority: &str) -> String` (appends the default
     port when none is present; an IPv6 literal in brackets is handled by splitting on the last `:` outside `]`).
  4. `checks/mod.rs`: doc, the eight `pub mod` lines, and `pub fn all() -> Vec<Arc<dyn aitm_scan_model::Check>> { Vec::new() }`
     with a comment "filled by Task 17". `lane.rs` placeholder: `pub fn build() -> Option<Arc<dyn Lane>> { None }`.
     `language.rs` placeholder: `pub fn build(guard: Arc<dyn ScopeRateGuard>) -> Option<Box<dyn ProtocolLanguage>> { let _ = guard; None }`.
- **Test** (`types.rs` `#[cfg(test)]`): `default_port_by_scheme`: `default_port("wss") == 443`,
  `default_port("https") == 443`, `default_port("ws") == 80`, `default_port("http") == 80`;
  `authority_gets_default_port_once`: `authority_with_port("ws", "127.0.0.1") == "127.0.0.1:80"`,
  `authority_with_port("wss", "app.test:8443") == "app.test:8443"`, `authority_with_port("wss", "[::1]") == "[::1]:443"`;
  `overrides_builder`: `HandshakeOverrides::set("Origin", "x").and_strip("Cookie") == HandshakeOverrides { set: vec![("Origin".into(), "x".into())], strip: vec!["Cookie".into()] }`.
  `lane.rs` placeholder test `slot_is_none_until_task_17`: `crate::lane().is_none()`;
  `language.rs` placeholder test `slot_is_none_until_task_8`: `crate::language(Arc::new(StdGuard::default())).is_none()`.
- **Done when:** `cargo test -p aitm-scan-ws --offline` passes, `cargo metadata --offline` exits 0
  (quoted), `cargo test -p aitm --lib --offline wire` still passes (the slots still return `None`), full gate passes.

### Task 2: `transport.rs` + `testing.rs`: the `WsTransport` seam, TCP/TLS production transport, duplex test transport and test fixtures

- **Satisfies:** Constraints "Default `cargo test` stays hermetic", Architect's calls 1 and 3
  (TLS policy, accept-any verifier), 11.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-ws/src/transport.rs`, `crates/aitm-scan-ws/src/testing.rs` (replace placeholders),
  `crates/aitm-scan-ws/tests/tcp_transport.rs` (create; ignored).
- **Change (`transport.rs`):**
  - `pub trait WsTransport: Send + Sync { fn connect<'a>(&'a self, host: &'a str, port: u16, tls: bool, sni: &'a str) -> BoxFuture<'a, anyhow::Result<aitm_core::ByteStream>>; }`.
  - `pub struct TcpTransport { tls: TlsPolicy, connect_timeout: Duration, client_config: Arc<rustls::ClientConfig> }` with
    `pub fn new(tls: TlsPolicy, connect_timeout: Duration) -> Self`. `connect`: `tokio::time::timeout(connect_timeout, TcpStream::connect((host, port)))`,
    `set_nodelay(true)`, then when `tls` wrap with `tokio_rustls::TlsConnector::from(client_config)` using
    `ServerName::try_from(sni.to_owned())` (an IP literal SNI is allowed by rustls 0.23's `ServerName::IpAddress`); return `Box::pin(stream)`.
    The ALPN list is empty (HTTP/1.1 upgrade only). `client_config` for `Verify`: `webpki-roots` anchors;
    for `AcceptAny`: `.dangerous().with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))`.
  - `struct AcceptAnyVerifier` implementing `rustls::client::danger::ServerCertVerifier`
    (`verify_server_cert` -> `Ok(ServerCertVerified::assertion())`, `verify_tls12_signature`/`verify_tls13_signature` -> `Ok(HandshakeSignatureValid::assertion())`,
    `supported_verify_schemes` -> `rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()`),
    with a doc comment stating why it exists (the scanner dials only authorities the operator
    put in scope; lab targets are self-signed; `Http1Sender` has the same `insecure` posture) and
    the words `Security review: AcceptAny` so the reviewer finds it.
- **Change (`testing.rs`, `#[doc(hidden)] pub`, compiled always so `tests/` and every module's tests reuse it; no `#[cfg(test)]`):**
  - `pub struct DuplexTransport { .. }` implementing `WsTransport`: each `connect` creates
    `tokio::io::duplex(64 * 1024)`, records `(host, port, tls, sni)` in `pub fn connects(&self) -> Vec<(String, u16, bool, String)>`,
    hands the server half to the handler given at construction, returns the client half.
    `pub fn new<F>(on_connect: F) -> Arc<Self> where F: Fn(tokio::io::DuplexStream) + Send + Sync + 'static`.
  - `pub type HandshakeDecision = Arc<dyn Fn(&tungstenite::handshake::server::Request) -> Result<tungstenite::handshake::server::Response, tungstenite::handshake::server::ErrorResponse> + Send + Sync>`.
  - `pub fn ws_server<H, Fut>(decide: Option<HandshakeDecision>, handler: H) -> (Arc<DuplexTransport>, Arc<ServerLog>) where H: Fn(ServerConn) -> Fut + Send + Sync + Clone + 'static, Fut: Future<Output = ()> + Send`:
    for every connection it runs `tokio_tungstenite::accept_hdr_async(stream, callback)` where the
    callback records the request's headers into the `ServerLog` and applies `decide` (default:
    accept), then spawns `handler(ServerConn { ws: WebSocketStream<DuplexStream>, headers: Vec<(String, String)>, log: Arc<ServerLog> })`.
    After the handler returns the server half keeps reading until the stream ends so Close
    replies flow.
  - `pub struct ServerLog { .. }` with `pub fn handshakes(&self) -> Vec<Vec<(String, String)>>` (lowercase names, in order), `pub fn received(&self) -> Vec<Vec<u8>>` (every data frame payload the handlers pushed via `ServerConn::record`), `pub fn connections(&self) -> usize`.
  - `pub async fn echo_handler(conn: ServerConn)`: replies to each Text frame with `echo:<text>` and to each Binary frame with the same bytes, recording each; the standard "vulnerable to reflection" server.
  - `pub fn captured_conversation() -> (HttpFlow, WsFlow)`: the canonical fixture: handshake
    `GET /ws` to authority `127.0.0.1:8080`, scheme `http`, request headers exactly
    `Host: 127.0.0.1:8080`, `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`, `Sec-WebSocket-Version: 13`, `Origin: https://app.test`, `Cookie: sid=s3cr3t-cookie`, `Sec-WebSocket-Protocol: chat`, `User-Agent: fixture/1`;
    response `101` with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`, `Sec-WebSocket-Protocol: chat`;
    `WsFlow` messages in order: client Text `{"type":"hello"}`, client Text `{"msg":"hi","user":"bob"}`, server Text `{"ok":true,"echo":"hi"}`; `metadata.is_replay == false`; both `ConnInfo.peer == 127.0.0.1:8080`.
  - `pub struct TestJob { .. }` implementing `JobCtx`: `pub fn new(budget: u32) -> Arc<Self>` (job id `job-1`, profile = `ScanProfile::default()` with `ws.reply_window_ms = 300`, `target.origins = ["http://127.0.0.1:8080"]`, store `MemFlowStore::new()`, guard `StdGuard::default()` with `127.0.0.1:8080` in scope, deadline `now + 60 s`, marker `mk7f3a9e`), `pub fn with(budget: u32, edit: impl FnOnce(&mut ScanProfile)) -> Arc<Self>` (same, with the profile edited first; used for `record_probes: All` and `max_frame_bytes`), `pub fn over(store: Arc<dyn FlowStore>, guard: Arc<dyn ScopeRateGuard>, budget: u32, edit: impl FnOnce(&mut ScanProfile)) -> Arc<Self>` (Task 18's live test builds it over the real pipeline's store and guard), `pub fn cancel(&self)`, `pub fn charged(&self) -> u32`; `client()` returns a stub `ProxyClient` whose `send` is `Err("not used by the WS lane")`; `charge(units)` decrements an `AtomicU32`, returns `false` when it would go below zero.
  - `pub fn point(kind: InsertionKind, name: &str, path: Option<&str>, spec: PointSpec) -> InsertionPoint` (id `ws-test0001`, lane `Ws`, `flow: Some(spec.ws_flow)`).
- **Change (`tests/tcp_transport.rs`, ignored):** `tcp_plain_connect_loopback`: bind a
  `TcpListener` on `127.0.0.1:0`, `TcpTransport::new(TlsPolicy::AcceptAny, 2 s).connect("127.0.0.1", port, false, "127.0.0.1")` succeeds and a written byte arrives;
  `tcp_tls_accept_any_loopback`: a `tokio_rustls::TlsAcceptor` with an `rcgen` self-signed cert behind the listener; `AcceptAny` connects and completes the handshake; `Verify` returns `Err` whose text contains `certificate`.
- **Test** (`transport.rs`/`testing.rs` `#[cfg(test)]`, all hermetic):
  `duplex_transport_hands_server_half_to_handler`: a handler that reads 4 bytes and writes them back; `connect("h", 1, false, "h")`, write `ping`, read back `ping`; `connects() == vec![("h", 1, false, "h")]`;
  `accept_any_verifier_accepts_self_signed_over_duplex`: `TlsAcceptor` (rcgen cert for `localhost`) on the server half of a duplex, `TlsConnector::from(TcpTransport::new(AcceptAny, ..).client_config())` on the client half (expose `pub fn client_config(&self) -> Arc<rustls::ClientConfig>`), handshake completes;
  `verify_policy_rejects_self_signed_over_duplex`: same with `Verify` -> `Err` containing `certificate`;
  `ws_server_echoes_and_logs_handshake`: `ws_server(None, echo_handler)`; a `client_async_with_config` dial over the duplex with header `Cookie: a=b`; send `hi`, read `echo:hi`; `log.handshakes()[0]` contains `("cookie", "a=b")`; `log.received() == [b"hi"]`;
  `captured_conversation_shape`: `ws.messages.len() == 3`, `ws.messages[1].data == br#"{"msg":"hi","user":"bob"}"#`, `handshake.request.headers.get("cookie") == Some("sid=s3cr3t-cookie")`, `ws.handshake == handshake.id`;
  `test_job_charges_and_refuses_past_zero`: `TestJob::new(2)`: `charge(1) == true`, `charge(1) == true`, `charge(1) == false`, `budget_left() == 0`.
- **Done when:** `cargo test -p aitm-scan-ws --offline` passes; `cargo test -p aitm-scan-ws --offline --test tcp_transport -- --ignored` passes **in the Terminal** (quoted) or is recorded as deferred to Task 19 with the reason; full gate passes.

### Task 3: `discover.rs`: insertion points, point specs, traits, site node, origin matching

- **Satisfies:** spec D8.3 "Insertion points", D2 `InsertionPoint`/`PointTrait`, AC T4-1
  (the point-shape half; the live half is Task 18), Architect's call 4.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-ws/src/discover.rs` (replace placeholder).
- **Change:**
  - `pub struct IdGen { .. }` with `pub fn new(job_salt: &str) -> Self` and `pub fn id(&mut self, ws_flow: FlowId, locator: &Locator, kind: InsertionKind) -> String`:
    `ws-<8 lowercase hex>` from `std::hash::DefaultHasher::new()` fed `(job_salt, ws_flow, kind token, locator)`, lower 32 bits; stable within a process (which is all a job needs; `blake3` is not in the offline cache). A collision within one `discover` call appends a counter (`ws-xxxxxxxx-2`).
  - `pub fn origin_matches(handshake: &HttpFlow, origins: &[String]) -> bool`: builds
    `"{scheme}://{authority_with_port}"` from the handshake request (`ws`->`http`, `wss`->`https`), compares to each origin after the same default-port normalisation (`http://host` == `http://host:80`), case-insensitive host.
  - `pub fn infer_traits(name: &str, value: &str) -> Vec<PointTrait>` in enum order, rules exactly:
    `Url` (value starts with `http://`, `https://`, `ws://`, `wss://` or `/`); `Number` (parses as `f64`, not NaN/inf);
    `Email` (contains `@` and a `.` after it); `Base64` (len >= 16, only `[A-Za-z0-9+/=]`, `len % 4 == 0`);
    `Json` (value parses as a JSON object or array); `Id` (lowercase name ends with `id` or `_id`, or value is a UUID (`uuid::Uuid::parse_str` is not available: 36 chars, hyphens at 8/13/18/23, hex elsewhere), or value is non-empty all-digits);
    `Session` (`is_secret_key(name)`). `Filename` is never inferred for WS points.
  - `pub fn redacted_example(name: &str, value: &str, header: bool) -> String`: `<redacted>` when `is_secret_key(name)` or (`header` and name is `cookie`/`authorization`, case-insensitive); else `scrub_text(value)` truncated to 128 chars on a char boundary.
  - `pub struct Discovered { pub points: Vec<InsertionPoint>, pub specs: Vec<(String, PointSpec)>, pub node: SiteNode }`.
  - `pub fn discover_flow(ws: &WsFlow, handshake: &HttpFlow, ids: &mut IdGen) -> Discovered`:
    (1) handshake header points (`ws_handshake_header`): one per request header in this set, present or not case: `Origin`, `Cookie`, `Authorization`, `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions`, plus any header whose lowercase name is not in the fixed skip list
    `host, connection, upgrade, sec-websocket-key, sec-websocket-version, sec-websocket-accept, user-agent, accept, accept-encoding, accept-language, pragma, cache-control, content-length`; `name` = lowercase header name, `path = None`, `example = redacted_example(.., true)`, `frame_index = Some(index of the first client->server frame)` or `None` when there is none, locator `HandshakeHeader(original-case name)`.
    (2) For every client->server **Text** frame in order: if the payload parses as a JSON object/array, walk its leaves depth-first producing `ws_json_value` points with `path` = dotted/bracket path (`user.id`, `tags[0]`) and `name` = last object key on the path (`tags` for `tags[0]`, `id` for `user.id`), `example = redacted_example(name, leaf as string, false)`; else if the payload is `key=value(&key=value)*` with every pair URL-safe (`form_urlencoded::parse` yields >= 1 pair and the text contains `=`) produce `ws_form_param` points per name (`path = None`); else one `ws_text` point named `text` (`path = None`). Every client->server **Binary** frame produces one `ws_binary` point named `binary` (`example = None`).
    (3) Dedupe per `(kind, name, path)` across frames: first occurrence wins (`frame_index` = that frame's index in `ws.messages`), `frequency` counts repeats.
    (4) Every point: `lane: Ws`, `flow: Some(FlowRef(ws.id))`, `site_node: Some(node.id)`, `method: Some("GET")`, `url: Some("{scheme}://{authority}{path}")` from the handshake, `traits = infer_traits(...)` (handshake `Cookie`/`Authorization` points always include `Session`).
    (5) `node`: `SiteNode { id: "wsnode-<8 hex>" (same hasher over scheme/host/port/path), method: "GET", scheme (as captured, `ws`/`wss` normalised to `http`/`https`), host, port (default filled), path_template: handshake path without the query, flows: [FlowRef(handshake.id), FlowRef(ws.id)], params: one ParamRef per point (kind, name), auth: handshake has Cookie or Authorization, points: count, audited: false }`.
- **Test** (`#[cfg(test)]`, using `testing::captured_conversation()` and variants built in-test):
  `fixture_yields_expected_points`: `discover_flow` on the fixture gives exactly these `(kind, name, path)` in this order:
  `(WsHandshakeHeader, "origin", None)`, `(WsHandshakeHeader, "cookie", None)`, `(WsHandshakeHeader, "sec-websocket-protocol", None)`, `(WsJsonValue, "type", Some("type"))`, `(WsJsonValue, "msg", Some("msg"))`, `(WsJsonValue, "user", Some("user"))`; `points.len() == 6`; the cookie point has `example == Some("<redacted>")` and `traits == [Session]`; the origin point has `example == Some("https://app.test")` and `traits == [Url]`; the `msg` point has `frame_index == Some(1)` in its spec and `example == Some("hi")`; `node.path_template == "/ws"`, `node.port == 8080`, `node.auth == true`, `node.points == 6`, `node.params.len() == 6`;
  `nested_json_paths_and_traits`: a flow whose single client frame is `{"user":{"id":42,"email":"a@b.c"},"tags":["x","y"],"token":"abc"}` yields points with paths `user.id`, `user.email`, `tags[0]`, `tags[1]`, `token`; `user.id` has `traits == [Number, Id]`, `user.email` `== [Email]`, `tags[0]` has `name == "tags"`, `token` has `example == Some("<redacted>")` and `traits` containing `Session` (`is_secret_key("token")` is true: `token` is a needle);
  `form_pairs_become_form_points`: frame `a=1&b=hello` yields `(WsFormParam, "a", None)` with `traits == [Number, Id]` and `(WsFormParam, "b", None)` with `traits == []`;
  `plain_text_is_one_point`: frame `hello there` yields one `(WsText, "text", None)` with `example == Some("hello there")`;
  `binary_frame_is_one_point`: a Binary frame `[0,1,2]` yields one `(WsBinary, "binary", None)` with `example == None`;
  `repeats_count_frequency_and_keep_first_frame`: two client frames `{"msg":"a"}` then `{"msg":"b"}` yield one `msg` point with `frequency == 2`, spec `frame_index == Some(0)`, `example == Some("a")`;
  `origin_matching_normalises_ports_and_schemes`: fixture handshake matches `["http://127.0.0.1:8080"]` and not `["http://127.0.0.1:8081"]`; a handshake with scheme `wss`, authority `app.test` matches `["https://app.test:443"]` and `["https://APP.test"]`;
  `ids_are_stable_and_shaped`: two `discover_flow` runs with `IdGen::new("job-1")` over the fixture give identical id lists, each matching `^ws-[0-9a-f]{8}$`, all distinct.
- **Done when:** `cargo test -p aitm-scan-ws --offline discover` passes and the full gate passes.

### Task 4: `mutate.rs`: placing a payload at a locator

- **Satisfies:** spec D8.3 "Probe semantics" ("the point is mutated with the payload by the lane"), D2 `PayloadMode`, Architect's call 15.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-ws/src/mutate.rs` (replace placeholder).
- **Change:**
  - `pub fn place(frame: &[u8], locator: &Locator, payload: &Payload) -> anyhow::Result<Vec<u8>>`:
    `JsonPath(p)`: parse `frame` as `serde_json::Value`, walk `p` (segments split on `.`; `name[idx]` indexes an array), `Err` when the path is missing; the leaf becomes: `Replace` -> `Value::String(payload.value)`; `Prefix`/`Suffix` -> `Value::String(payload.value + leaf_as_string)` / `(leaf_as_string + payload.value)` where a string leaf contributes its text and any other leaf its compact JSON text; re-serialise with `serde_json::to_vec` (key order is serde_json's; call 15).
    `FormParam(n)`: `form_urlencoded::parse(frame)` to pairs; the **first** pair named `n` gets its value replaced/prefixed/suffixed (`Err` when absent); re-encode every pair in order with `form_urlencoded::Serializer` (space -> `+`).
    `WholeText`: `Replace` -> `payload.value` bytes; `Prefix` -> value + frame; `Suffix` -> frame + value.
    `Binary`: bytes = `payload.bytes.clone().unwrap_or_else(|| payload.value.as_bytes().to_vec())`, then the same three modes on raw bytes.
    `HandshakeHeader(_)`: `Err("handshake headers are placed by the probe host")`.
  - `pub fn canonical_len(frame: &[u8], locator: &Locator) -> anyhow::Result<usize>`: the length of `place(frame, locator, &Payload { value: "", mode: Suffix, bytes: None })` (the re-serialised baseline length Task 15 pads from).
  - `pub fn json_leaf<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value>` (shared walker, also used by Task 3's tests? no: Task 3 walks its own tree; this one is for probes).
- **Test** (`#[cfg(test)]`):
  `json_leaf_replace_by_dotted_path`: `place(br#"{"a":{"b":"x"},"c":1}"#, &JsonPath("a.b"), Replace "P")` parses to a value where `["a"]["b"] == "P"` and `["c"] == 1`;
  `json_bracket_path_replaces_array_element`: `{"items":[{"id":1},{"id":2}]}` + `items[1].id` Replace `"P"` -> `["items"][1]["id"] == "P"` and `["items"][0]["id"] == 1`;
  `json_non_string_leaf_prefix_stringifies`: `{"c":1}` + `c` Prefix `"P"` -> `["c"] == "P1"`; Suffix -> `"1P"`;
  `json_missing_path_is_err`: `{"a":1}` + `b` -> `Err` whose text contains `b`;
  `form_param_replaced_and_reencoded`: `place(b"a=1&b=h%20i", &FormParam("b"), Replace "x y") == b"a=1&b=x+y"`; `Suffix "!"` -> `b"a=1&b=h+i%21"`;
  `form_param_missing_is_err`;
  `whole_text_modes`: `place(b"hi", &WholeText, Prefix "P") == b"Phi"`, Suffix -> `b"hiP"`, Replace -> `b"P"`;
  `binary_uses_bytes_when_present`: `Payload { value: "ignored", bytes: Some(vec![9,9]), mode: Suffix }` on `[1,2]` -> `[1,2,9,9]`;
  `handshake_locator_is_err`;
  `canonical_len_of_compact_json`: `canonical_len(br#"{ "a" : "x" }"#, &JsonPath("a")) == 9` (the compact form `{"a":"x"}`).
- **Done when:** `cargo test -p aitm-scan-ws --offline mutate` passes and the full gate passes.

### Task 5: `payloads.rs`: the small payload and signature tables

- **Satisfies:** spec D8.3 "reuse the HTTP payload sets and signatures through the WS oracle" (duplicated here on purpose; Architect's call 1, last item), Architect's call 16.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-ws/src/payloads.rs` (replace placeholder).
- **Change:** pure data and pure fns, every table `pub const`/`pub static`:
  - `pub fn reflection_canary(marker: &str) -> String` = `format!("{marker}<'>")` (no `"` and
    no `\`: `serde_json` would escape them when the canary is placed in a JSON string, and the
    echoed `\"` would read as "encoded" at every JSON point; `<`, `>` and `'` pass through
    unescaped) and `pub enum Reflection { Unencoded, Encoded, Absent }` with
    `pub fn classify_reflection(body: &str, marker: &str) -> Reflection`: `Unencoded` when the
    body contains the exact canary; `Encoded` when it contains `marker` but not the exact
    canary; else `Absent`.
  - `pub const SQL_ERROR_PAYLOADS: [&str; 3] = ["'", "\"", "' OR '1'='1"]` and
    `pub const SQL_ERROR_SIGNATURES: [(&str, &str); 8]` of `(dbms, lowercase needle)`: `("mysql", "you have an error in your sql syntax")`, `("mysql", "warning: mysql")`, `("postgresql", "syntax error at or near")`, `("postgresql", "pg::syntaxerror")`, `("sqlite", "sqlite3::")`, `("sqlite", "unrecognized token")`, `("mssql", "unclosed quotation mark")`, `("oracle", "ora-01756")`; `pub fn sql_error_signature(body: &str) -> Option<&'static str>` returns the matched needle (the constant that becomes `Evidence.matched`), case-insensitive.
  - `pub const SSTI_A: u32 = 1543; pub const SSTI_B: u32 = 7;` (product `10801`), `pub fn ssti_probes(marker: &str) -> Vec<(String, String)>` of `(payload, expected)` for the templates `{{A*B}}`, `${A*B}`, `<%= A*B %>`, `#{A*B}` where payload = `format!("{marker}{template}")` and expected = `format!("{marker}10801")`; `pub fn ssti_hit(body: &str, payload: &str, expected: &str) -> bool` = body contains `expected` and not `payload`.
  - `pub fn cmdi_probes(marker: &str) -> Vec<String>` = `[";echo {m}", "|echo {m}", "$(echo {m})", "`echo {m}`", "& echo {m}"]`; `pub fn cmdi_hit(body: &str, payload: &str, marker: &str) -> bool` = body contains `marker` and not `payload`.
- **Test** (`#[cfg(test)]`): `reflection_canary_is_json_safe`: `reflection_canary("mk") == "mk<'>"` and `serde_json::to_string(&reflection_canary("mk")).unwrap() == "\"mk<'>\""` (no escaping);
  `reflection_classes`: `classify_reflection("x mk<'> y", "mk") == Unencoded`, `classify_reflection("x mk&lt;&#39;&gt;", "mk") == Encoded`, `classify_reflection("nothing", "mk") == Absent`;
  `sql_signature_is_case_insensitive_and_returns_the_constant`: `sql_error_signature("You have an error in your SQL syntax near ''") == Some("you have an error in your sql syntax")`, `sql_error_signature("ok") == None`;
  `ssti_pairs_marker_with_product`: `ssti_probes("mk")[0] == ("mk{{1543*7}}", "mk10801")`, `ssti_probes("mk").len() == 4`; `ssti_hit("mk10801", "mk{{1543*7}}", "mk10801") == true`; `ssti_hit("49", ..) == false`; `ssti_hit("mk{{1543*7}} mk10801", ..) == false` (literal echoed);
  `cmdi_hit_requires_marker_without_literal`: `cmdi_hit("mk\n", ";echo mk", "mk") == true`, `cmdi_hit(";echo mk", ";echo mk", "mk") == false`.
- **Done when:** `cargo test -p aitm-scan-ws --offline payloads` passes and the full gate passes.

### Task 6: `dialer.rs`: `WsDialer`, header replay rule, guard + semaphore, frame I/O, replay flows

- **Satisfies:** spec D8.3 "`WsDialer`" (every sentence), Architect's calls 2, 3, 5 (the dial half), 11.
- **Depends on:** Task 2.
- **Files:** `crates/aitm-scan-ws/src/dialer.rs` (replace placeholder).
- **Change:**
  - `pub const REGENERATED_HEADERS: [&str; 6] = ["host", "connection", "upgrade", "sec-websocket-key", "sec-websocket-version", "sec-websocket-accept"]`.
  - `pub fn build_request(handshake: &HttpFlow, overrides: &HandshakeOverrides) -> anyhow::Result<tungstenite::http::Request<()>>`:
    URL `"{ws|wss}://{authority}{path}"` (scheme from the captured `http`/`https`/`ws`/`wss`), `.into_client_request()` (tungstenite generates `Host`, `Connection`, `Upgrade`, `Sec-WebSocket-Version: 13` and a fresh `Sec-WebSocket-Key` via `generate_key()`), then copy every captured request header whose lowercase name is **not** in `REGENERATED_HEADERS` (so `Cookie`, `Origin`, `Authorization`, `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions`, custom headers are kept), then apply `overrides.strip` (remove) and `overrides.set` (replace or add). An override on a regenerated header is an `Err` (never let a check re-send a stale key).
  - `pub struct WsDialer { transport: Arc<dyn WsTransport>, slots: Arc<tokio::sync::Semaphore> (MAX_CONNECTIONS) }` with `pub fn new(transport: Arc<dyn WsTransport>) -> Self` and `pub fn slots_available(&self) -> usize`.
  - `pub struct DialLimits { pub max_frame_bytes: usize }` (`Debug, Clone, Copy`; `Default` = `WsOptions::default().max_frame_bytes as usize`, i.e. 1 MiB): per-dial because the dialer is shared by every host of a lane while the cap is the job profile's; it becomes the `WebSocketConfig { max_frame_size: Some(n), max_message_size: Some(n), .. }` of that connection.
  - `pub enum DialOutcome { Upgraded(WsConn), Refused { status: u16, headers: Vec<(String, String)> } }`;
    `pub enum DialError { Guard(GuardError), Timeout, Connect(String), Handshake(String) }` (`Display`, `std::error::Error`; `Connect`/`Handshake` carry the error text, never a header).
  - `pub async fn dial(&self, handshake: &HttpFlow, overrides: &HandshakeOverrides, guard: &dyn ScopeRateGuard, deadline: Instant, limits: DialLimits) -> Result<DialOutcome, DialError>` = `build_request` then `dial_request`.
  - `pub async fn dial_request(&self, req: Request<()>, guard: &dyn ScopeRateGuard, deadline: Instant, limits: DialLimits) -> Result<DialOutcome, DialError>`:
    (1) authority = `authority_with_port(scheme, host[:port])` from the request URI; `guard.check_active(&authority)`: `Ok(permit)` continue; `Err(RateLimited { retry_after })` -> when `retry_after <= deadline - now` sleep `retry_after` and retry **once** (a second `RateLimited` is returned as `DialError::Guard`), otherwise return `DialError::Guard(RateLimited { .. })` without waiting; any other `Err(e)` -> `DialError::Guard(e)`; (2) `slots.clone().acquire_owned()` bounded by the deadline (`Timeout`); (3) `transport.connect(host, port, tls = scheme is wss, sni = host)` bounded by the deadline (`Connect`/`Timeout`); (4) `client_async_with_config(req, stream, Some(config from limits))` bounded by the deadline: `Ok((ws, resp))` -> `Upgraded(WsConn)`, `Err(tungstenite::Error::Http(resp))` -> `Refused { status, headers }`, other -> `Handshake(text)`.
  - `pub struct WsConn { .. }` holding the stream, the `ActionPermit`, the `OwnedSemaphorePermit`, the request/response copies and a recorder; methods:
    `pub fn status(&self) -> u16`, `pub fn response_headers(&self) -> Vec<(String, String)>`,
    `pub async fn send(&mut self, frame: &Frame) -> anyhow::Result<()>` (Text/Binary/Ping/Pong/Close mapped to `Message`),
    `pub async fn collect(&mut self, window: Duration, deadline: Instant, cancelled: &dyn Fn() -> bool) -> CollectOutcome` where `pub struct CollectOutcome { pub frames: Vec<Frame>, pub ended: CollectEnd }` and `pub enum CollectEnd { Window, Close { code: Option<u16> }, Transport(String), Deadline, Cancelled }`: reads until the window elapses (polling `cancelled()` every 50 ms); a `Ping` is answered with a `Pong` (both recorded); a `Close` ends collection (recorded, `code` from the frame); a transport error ends it with `Transport`;
    `pub async fn close(&mut self) -> Vec<Frame>` sends `Close` (normal) and waits up to 200 ms for the peer's Close, recording and returning what arrived;
    `pub fn into_flows(self, marks: Vec<String>) -> (HttpFlow, WsFlow)`: the handshake `HttpFlow` (request as sent, response status/headers as received, `metadata.is_replay = true`, `marks`) and the conversation `WsFlow` (`handshake = that HttpFlow's id`, every frame sent and received in order with `WsDir`, `injected: true` for ours, `is_replay = true`, same marks). Releasing the connection drops both permits.
- **Test** (`#[cfg(test)]`, each with `testing::ws_server` + `DuplexTransport` + `StdGuard` with `127.0.0.1:8080` in scope, deadline `now + 5 s`):
  `handshake_regenerates_key_and_keeps_the_rest`: dial the fixture; `log.handshakes()[0]` has `sec-websocket-key != "dGhlIHNhbXBsZSBub25jZQ=="`, `cookie == "sid=s3cr3t-cookie"`, `origin == "https://app.test"`, `sec-websocket-protocol == "chat"`, `user-agent == "fixture/1"`, `host == "127.0.0.1:8080"`, `sec-websocket-version == "13"`, and no `sec-websocket-accept` key; `transport.connects() == [("127.0.0.1", 8080, false, "127.0.0.1")]`;
  `overrides_replace_and_strip`: `HandshakeOverrides::set("Origin", "https://attacker.invalid").and_strip("Cookie")` -> handshake has `origin == "https://attacker.invalid"` and no `cookie`;
  `override_of_regenerated_header_is_err`: `set("Sec-WebSocket-Key", "x")` -> `build_request` is `Err`;
  `out_of_scope_authority_never_connects`: guard without the host -> `Err(DialError::Guard(GuardError::OutOfScope(_)))` and `transport.connects().is_empty()`;
  `non_101_is_a_refused_outcome`: `decide` returns a 403 `ErrorResponse` -> `DialOutcome::Refused { status: 403, .. }` and `log.connections() == 1`;
  `at_most_four_connections_at_once`: a handler that awaits a `tokio::sync::Notify` before returning; four dials succeed; the fifth `dial` wrapped in `tokio::time::timeout(Duration::from_millis(200))` is `Err(Elapsed)`; dropping one `WsConn` lets the fifth complete; `dialer.slots_available() == 0` while four are held;
  `collect_answers_ping_and_stops_on_close`: a handler that sends `Ping(b"p")`, then `Text("a")`, then `Close(1000)`; `collect(1 s, ..)` returns `frames == [Ping p, Pong p, Text a, Close]` by kind (`frames.iter().map(|f| f.kind) == [Ping, Pong, Text, Close]`) and `ended == Close { code: Some(1000) }`; `log.received()` contains the pong payload `b"p"`? (tungstenite records pongs as `Message::Pong`; the handler pushes it) -> `log` shows one `Pong`;
  `into_flows_records_a_replay_conversation`: send `Text("hi")` to the echo handler, collect, `close()`, `into_flows(vec!["scan:job-1".into()])`: the `HttpFlow` has `response.status == 101`, `metadata.is_replay`, `marks == ["scan:job-1"]`, `request.headers.get("cookie") == Some("sid=s3cr3t-cookie")` (the replay request is recorded as sent; the store policy is Task 7's); the `WsFlow` has `handshake == http.id`, messages `[C2S Text hi, S2C Text echo:hi, C2S Close, S2C Close]` by `(dir, opcode)`, every C2S `injected == true`, `metadata.is_replay`;
  `rate_limited_waits_once_then_dials`: `StdGuard::new(LimitConfig { per_host_rps: 1, ..LimitConfig::default() })` (`StdGuard` answers the second call within a second with `GuardError::RateLimited { retry_after }`, `crates/aitm-core/src/guard.rs:495`): two dials back to back, deadline `now + 5 s`, both `Ok` and the second took >= 500 ms (quote the elapsed);
  `rate_limit_longer_than_deadline_is_a_guard_error`: same guard, second dial with deadline `now + 50 ms` -> `Err(DialError::Guard(GuardError::RateLimited { .. }))` returned in < 200 ms and `transport.connects().len() == 1`.
- **Done when:** `cargo test -p aitm-scan-ws --offline dialer` passes and the full gate passes.

### Task 7: `host.rs`: `WsProbeHost`

- **Satisfies:** spec D8.3 "Probe semantics", D5 budget/record policy/held flows, D2 `ProbeHost`, Architect's calls 2 (budget), 5.
- **Depends on:** Tasks 3, 4, 6.
- **Files:** `crates/aitm-scan-ws/src/host.rs` (replace placeholder).
- **Change:**
  - `pub struct WsProbeHost { .. }` with
    `pub fn new(point: InsertionPoint, spec: PointSpec, handshake: HttpFlow, ws: WsFlow, dialer: Arc<WsDialer>, job: Arc<dyn JobCtx>) -> anyhow::Result<Self>`
    (`Err` when `spec.frame_index` names a frame that is not a client->server frame of `ws`, or when the locator is not a handshake header and `frame_index` is `None`).
  - Internal `async fn conversation(&self, overrides: HandshakeOverrides, frame: Option<Frame>) -> anyhow::Result<ProbeResponse>`:
    (1) `Err("cancelled")` when `job.cancelled()`, `Err("deadline passed")` when past `job.deadline()`; `job.charge(1)` else `Err("budget exhausted")`;
    (2) `dialer.dial(&handshake, &overrides, &*job.guard(), deadline, DialLimits { max_frame_bytes: profile.ws.max_frame_bytes as usize })`; `Refused { status, headers }` -> `Ok(ProbeResponse { status: Some(status), headers, body: vec![], elapsed_ms, flow: None, ws_frames: Some(vec![]), l4: None })`; `Err(e)` -> `Err(e)`;
    (3) replay every client->server frame of `ws.messages` with index `< frame_index` unchanged (each `charge(1)`, `Err` when refused); then send `frame` when `Some` (the mutated or original chosen frame; `charge(1)`), or for a handshake-header locator the chosen frame unchanged when `frame_index` is `Some`;
    (4) `collect(Duration::from_millis(profile.ws.reply_window_ms), deadline, cancelled)`; then `close()` (its frames are appended);
    (5) `ProbeResponse { status: Some(conn.status()), headers: conn.response_headers(), body: concatenated Text payloads truncated to MAX_MATCH_BODY, elapsed_ms: since step 2, flow, ws_frames: Some(all frames in order), l4: None }`;
    (6) `into_flows(vec![format!("scan:{}", job.job_id())])`; under `RecordProbes::All` insert both into `job.store()` and set `flow = Some(FlowRef(ws_flow.id))`; under `IssuesOnly` `flow = None`; push both into the held ring (`VecDeque`, newest kept, capacity `HELD_PROBES` conversations for probes plus the baseline's own slot).
    A `CollectEnd::Transport(_)` is **not** an `Err`: the response is returned with what
    arrived. Checks receive only `&dyn ProbeHost`, so the host exposes no extra method for the
    ending; the frames are the contract (a response with no `Close` frame and
    `elapsed_ms < reply_window_ms` ended by a transport drop; Task 15 reads it that way).
  - **Pad sentinel (Architect's call 21).** `pub const PAD_SENTINEL: &str = "\u{0}aitm-pad:"` and
    `pub fn pad_payload() -> Payload` (`value = PAD_SENTINEL`, `mode: Suffix`, `bytes: None`).
    In `probe`, a payload whose `mode == Suffix` and whose `value` starts with `PAD_SENTINEL`
    is placed as `"A".repeat(target - canonical)` at the locator, where
    `target = min(2 * largest client->server frame payload length in ws.messages, profile.ws.max_frame_bytes as usize)`
    and `canonical = mutate::canonical_len(original_frame, locator)` (for `Binary`/`WholeText`
    the original length), so the frame sent is exactly `target` bytes; `target <= canonical`
    sends the frame unchanged. Every dial already passes `DialLimits { max_frame_bytes }` from
    the profile, so tungstenite does not refuse the frame on our side. The sentinel never
    leaves the process.
  - `impl ProbeHost for WsProbeHost`: `baseline()` = `conversation(HandshakeOverrides::default(), Some(original chosen frame))` cached in a `tokio::sync::Mutex<Option<ProbeResponse>>` (one dial, reused);
    `probe(payload)`: `HandshakeHeader(name)` -> overrides `set(name, value)` when `value` non-empty else `strip(name)`, frame = original; other locators -> `mutate::place(original, locator, payload)` as a frame of the original opcode;
    `probe_raw(req)`: `req.headers` are overrides (`(name, "")` strips), frame = original chosen frame, `Err` when `req.url` is non-empty and its authority differs from the handshake's;
    `marker()`/`budget_left()`/`deadline()`/`profile()`/`cancelled()` delegate to `job`; `held_flows()` returns every held `(HttpFlow, WsFlow)` as `Flow`s, baseline first, then probes newest first.
- **Test** (`#[cfg(test)]`, fixture + `TestJob::new(100)` + `ws_server(None, echo_handler)` unless stated; the `msg` point from `discover_flow`):
  `probe_replays_preceding_frames_then_the_mutated_one`: `probe(Payload { value: "X", mode: Replace, bytes: None })`: `log.received() == [br#"{"type":"hello"}"#, br#"{"msg":"X","user":"bob"}"#]`; `status == Some(101)`; `body == br#"echo:{"msg":"X","user":"bob"}"#`; `ws_frames` has exactly one `Text` frame and its last frame is `Close`; `elapsed_ms >= 300` (the reply window); `flow == None`;
  `budget_is_charged_per_dial_and_frame`: after the probe above `job.charged() == 3` (dial + 2 frames);
  `budget_exhausted_is_err_before_connect`: `TestJob::new(0)` -> `probe` is `Err` containing `budget` and `log.connections() == 0`;
  `cancelled_is_err_before_connect`: `job.cancel()` -> `Err` containing `cancelled`, `connections() == 0`;
  `baseline_is_dialled_once`: two `baseline()` calls -> `connections() == 1` and both bodies `== br#"echo:{"msg":"hi","user":"bob"}"#`;
  `handshake_header_point_sets_or_strips`: the `origin` point: `probe("https://attacker.invalid")` -> handshake `origin == "https://attacker.invalid"`; `probe("")` -> no `origin` header; the received frames are two `{"type":"hello"}` frames, one per probe (a handshake-header point's chosen frame is the first client frame, so nothing precedes it and only that frame is sent; T4 session correction 2026-11-01);
  `probe_raw_headers_are_overrides`: `probe_raw(RawProbe { headers: [("Cookie", ""), ("X-Test", "1")], url: "", .. })` -> handshake has no `cookie` and `x-test == "1"`; with `url: "ws://other.test/ws"` -> `Err`;
  `refused_upgrade_is_ok_with_status`: `decide` returns 401 -> `probe` is `Ok` with `status == Some(401)`, `ws_frames == Some(vec![])`, `body.is_empty()`;
  `issues_only_keeps_flows_in_memory_not_store`: after baseline + 2 probes `job.store().query(&FlowQuery::default()).len() == 0` and `held_flows().len() == 6`; every held `Flow` has `metadata().is_replay` and `marks == ["scan:job-1"]`;
  `record_all_inserts_each_conversation`: `TestJob` with `record_probes: All` -> after one probe the store holds 2 flows (one `Http`, one `WebSocket`), the probe's `flow == Some(FlowRef(ws id))`;
  `held_ring_is_bounded`: 20 probes -> `held_flows().len() == 32` (16 conversations x 2) and the first held probe conversation is the 20th (its `WsFlow` carries the frame with the 20th payload);
  `body_is_bounded`: a handler replying with a 2 MiB text -> `body.len() == MAX_MATCH_BODY` (the `TestJob` profile's `max_frame_bytes` is set to `4 << 20` so the dialer accepts the reply);
  `pad_sentinel_pads_to_twice_largest_frame`: fixture (largest client frame is the 25-byte `{"msg":"hi","user":"bob"}`), `msg` point, `probe(pad_payload())` -> `log.received()[1].len() == 50`; with the `TestJob` profile's `max_frame_bytes = 40` -> `== 40`; `evidence`-free: the sentinel text appears in no `ProbeResponse` field and in no held flow.
- **Done when:** `cargo test -p aitm-scan-ws --offline host` passes and the full gate passes.

### Task 8: `language.rs`: `WsLanguage` and the `ws.*` namespace

- **Satisfies:** spec D8.3 "`ws` Rhai namespace" (api_version `1`, four fns, `Guarded`, handles bounded at 4), D1 (`language()` slot), AC T4-4 (the hermetic half; live half Task 18), Architect's calls 2 (language bound), 3, 7, 17.
- **Depends on:** Task 6 (and Task 2's `DuplexTransport` for tests).
- **Files:** `crates/aitm-scan-ws/src/language.rs` (replace placeholder).
- **Change:**
  - `pub const NAMESPACE: &str = "ws"; pub const API_VERSION: &str = "1";`
  - `pub struct WsLanguage { .. }` with `pub fn new(guard: Arc<dyn ScopeRateGuard>, dialer: Arc<WsDialer>) -> Self` (spawns the driver thread lazily on first dial), `pub fn for_catalog() -> Self` (a `StdGuard::default()` with empty scope and a `WsDialer` over `TcpTransport::new(TlsPolicy::AcceptAny, 10 s)`; static data only, nothing is dialled), and
    `pub fn build(guard: Arc<dyn ScopeRateGuard>) -> Option<Box<dyn ProtocolLanguage>>` = `Some(Box::new(WsLanguage::new(guard, Arc::new(WsDialer::new(Arc::new(TcpTransport::new(TlsPolicy::AcceptAny, Duration::from_secs(10))))))))` (the slot body `lib.rs` already calls; flipping it is this task's slot test).
  - `impl ProtocolLanguage for WsLanguage`: `namespace() == "ws"`, `api_version() == "1"`, `register_host_fns` registers `dial`, `send`, `recv`, `close`, each `Guarded::new(Box::new(WsSeamGuard), host_fn)`, `poc_step() == None`, `catalog()` = `NamespaceCatalog { namespace: "ws", api_version: "1", host_fns: catalog_host_fns() (the four, in that order, params typed `object`/`int`/`string|blob` with one-sentence descriptions), poc_step: None, sources: vec![] }`.
  - `struct WsSeamGuard;` `impl GuardHandle`: `guard_name() == "ws"`; `permit(ctx, fn_name)` returns `Ok(())` for the four names and `GuardRefused` for anything else. Doc comment: the scope check runs inside `dial` by authority (the only place the authority is known); the seam exposes no hook-vs-command signal (`RunKind` is internal to `aitm-plugin-rhai`), so "a hook cannot call `ws.*`" is **not enforceable here** and is handed to the coordinator (Architect's call 17); when the seam grows such a signal, this `permit` is the one place to honour it.
  - Host fn contract (args marshalled as `aitm_core::Value`): `ws.dial(#{ url: String, headers?: #{ name: value } }) -> int handle`: parse `url` (`ws://`/`wss://` only, else `BadArgs`), build the request with `into_client_request()` plus the headers (a regenerated header name is `BadArgs`), `dialer.dial_request(req, &*guard, now + 10 s, DialLimits::default())`; `Refused { status }` -> `BadArgs(format!("upgrade refused with status {status}"))`; `DialError::Guard(e)` -> `GuardRefused { namespace: "ws", reason: format!("{variant}: {authority}") }` where `variant` is the `GuardError` variant name (`OutOfScope`, `RateLimited`, ...); when `MAX_HANDLES` are open -> `GuardRefused { reason: "4 handles already open; close one first" }`. `ws.send(handle, text | blob) -> ()` (`BadArgs` for an unknown handle or other type). `ws.recv(handle, timeout_ms: int) -> #{ frames: [ #{ kind: "text"|"binary"|"ping"|"pong"|"close", text?: String, bytes?: blob } ] }` collecting for `clamp_timeout(timeout_ms)` ms (`pub fn clamp_timeout(ms: i64) -> u32` = `ms.clamp(0, 30_000)`), pings answered. `ws.close(handle) -> ()` sends Close and frees the handle.
  - Driver: one `std::thread` per `WsLanguage` running a current-thread tokio runtime, owning `HashMap<i64, Handle { conn: WsConn, last_used: Instant }>`; host fns send `DriverCmd::{Dial{..}, Send{..}, Recv{..}, Close{..}}` with a `std::sync::mpsc::SyncSender` reply channel over `std::sync::mpsc`, blocking with `recv_timeout(timeout + 2 s)` (a driver that does not answer is `BadArgs("ws driver unavailable")`). Handles idle > `HANDLE_IDLE_REAP` are closed on the next command and by a 5 s tick. Handles are `1, 2, 3, ...` per language instance.
- **Test** (`#[cfg(test)]`, engine via `build_engine_with_languages` with a `WsLanguage::new(guard, Arc::new(WsDialer::new(duplex_transport)))`, `seed_call_context(CallerTrust::Operator, None, None)`, echo server):
  `script_round_trips_a_frame`: `engine.eval::<String>(r#"let h = ws.dial(#{ url: "ws://127.0.0.1:8080/ws", headers: #{ "Cookie": "a=b" } }); ws.send(h, "hi"); let r = ws.recv(h, 500); ws.close(h); r.frames[0].text"#) == "echo:hi"` and `log.handshakes()[0]` contains `("cookie", "a=b")`;
  `out_of_scope_url_is_refused_before_connect`: `ws.dial(#{ url: "ws://evil.test/ws" })` is `Err` whose text contains `OutOfScope` and `evil.test:80`; `transport.connects().is_empty()`;
  `fifth_handle_is_refused`: four `ws.dial`s succeed (handler holds the connection), the fifth is `Err` containing `4 handles already open`; after `ws.close(1)` a dial succeeds;
  `unknown_handle_is_bad_args`: `ws.send(99, "x")` is `Err` containing `bad arguments`;
  `binary_frames_come_back_as_blobs`: `ws.send(h, blob([1,2,3]))` then `recv` -> `frames[0].kind == "binary"` and `frames[0].bytes == blob([1,2,3])`;
  `clamp_timeout_bounds`: `clamp_timeout(99_999) == 30_000`, `clamp_timeout(-5) == 0`, `clamp_timeout(250) == 250`;
  `catalog_is_static_and_complete`: `WsLanguage::for_catalog().catalog()`: `namespace == "ws"`, `api_version == "1"`, `host_fns.iter().map(|f| f.name.as_str()) == ["dial", "send", "recv", "close"]`, `poc_step.is_none()`;
  `slot_is_some`: replaces Task 1's placeholder test: `crate::language(Arc::new(StdGuard::default()))` is `Some` and its `namespace() == "ws"`;
  `wss_url_requests_tls`: `ws.dial(#{ url: "wss://127.0.0.1:8443/ws" })` with `127.0.0.1:8443` in scope -> `transport.connects()[0] == ("127.0.0.1", 8443, true, "127.0.0.1")` (the duplex transport ignores `tls`; the handshake still completes).
- **Done when:** `cargo test -p aitm-scan-ws --offline language` passes; `cargo test -p aitm-plugin-rhai --offline --test api_catalog` still passes (we did **not** add `ws` to `production_languages()`; it must not drift); full gate passes.

### Tasks 9-16: the eight native checks (one file each, independent of each other)

Common to every check task:

- **Satisfies:** spec D8.3 "Checks" for the named check, D4 (full `CheckMeta`, `origin: Native`), D2 `Verdict`, Architect's call 6 (the fixed meta values) and the redaction rule.
- **Depends on:** Tasks 5, 7.
- **Shape:** `pub struct <Name>;` with `pub fn check() -> Arc<dyn Check>` and `pub const ID: &str`; `impl Check` with `meta()` returning a `&'static CheckMeta` built once via `std::sync::OnceLock`; `run` stops with `Outcome::Inconclusive` (`detail` = `"cancelled"`, `"budget exhausted"` or `"deadline passed"`) before any probe when `host.cancelled()`, `host.budget_left() == 0` or `host.deadline() <= now`, and when `probe`/`baseline` returns `Err(e)` returns `Inconclusive` with `detail = format!("connect error: {e}")` (the dialer's error text carries no header). `Verdict.confidence` for a `Clean`/`Inconclusive` outcome is `Tentative`. Evidence: `payload` = the payload string the check sent (never a header value; handshake checks set `payload: None`), `matched` = a scanner constant or `Evidence::excerpt(&scrub_text(..))`, `probe_flows`/`baseline_flow` = the `ProbeResponse.flow`s when present (so re-recording under `All` links; empty under `issues_only`, the engine uses `held_flows()`). `poc_hint: None` in v2 for every WS check (no WS PoC step exists; Architect's call 19).
- **Test shape:** `#[cfg(test)]` in the check's file; `TestJob::new(100)`, `testing::captured_conversation()`, the point named below from `discover_flow`, `WsProbeHost::new(..)` over `WsDialer::new(duplex)` and a `ws_server(decide, handler)` whose behaviour is described per case; each case asserts `(outcome, confidence)` literally and a `detail` substring; a redaction assertion `!format!("{:?}", verdict).contains("s3cr3t-cookie")` in every file's vulnerable case.

### Task 9: `checks/cswsh.rs`: `cswsh`

- **Files:** `crates/aitm-scan-ws/src/checks/cswsh.rs`.
- **Meta:** `id "cswsh"`, `name "Cross-site WebSocket hijacking"`, `class "cswsh"`, `lanes [Ws]`, `kinds [WsHandshakeHeader]`, `intensity Light`, `cost Light`, `technique Handshake`, `severity High`, `confidence_max Certain`, `needs_baseline true`, `wants_traits None`, `targets_session false`, `cwe Some(1385)`, description/remediation one sentence each.
- **Logic:** acts only when `point.name == "origin"` (else `Clean`, detail `"not the Origin point"`). `baseline()`; then `probe(Payload { value: "https://attacker.invalid", mode: Replace, bytes: None })` (cookies stay: the host replays them). Non-101 -> `Clean` (`detail` = `"upgrade refused with status {s} for a foreign Origin"`). 101 and the first **data** (Text/Binary) server frame equals the baseline's first data frame -> `Vulnerable`/`Certain`, detail `"upgrade completed with Origin https://attacker.invalid and the first reply equals the authenticated baseline"`, `evidence.matched = Some("first server frame identical to baseline")`. 101 with a data frame that differs -> `Vulnerable`/`Firm`, detail contains `"differs from the baseline"`. No data frame in either -> `Inconclusive`, detail `"no server frame within the reply window"`.
- **Tests:** `vulnerable_server_accepts_any_origin`: `decide: None`, echo handler -> `(Vulnerable, Certain)`, detail contains `attacker.invalid`, `handshakes()[1]` has `origin == "https://attacker.invalid"` and `cookie == "sid=s3cr3t-cookie"`; `patched_server_rejects_foreign_origin`: `decide` returns 403 unless `origin == "https://app.test"` -> `(Clean, Tentative)`, detail contains `403`; `different_reply_is_firm`: handler replies `{"ok":false}` when the handshake origin was not `https://app.test`, `echo` otherwise -> `(Vulnerable, Firm)`; `silent_server_is_inconclusive`: handler never writes -> `(Inconclusive, Tentative)`; `non_origin_point_is_clean`: the `cookie` point -> `Clean`.

### Task 10: `checks/auth_bypass.rs`: `ws-auth-bypass-handshake`

- **Files:** `crates/aitm-scan-ws/src/checks/auth_bypass.rs`.
- **Meta:** `id "ws-auth-bypass-handshake"`, `name "WebSocket upgrade without credentials"`, `class "ws-auth-bypass"`, `kinds [WsHandshakeHeader]`, `Light`, cost `Light`, `Handshake`, `High`, `confidence_max Firm`, `needs_baseline true`, `cwe Some(287)`.
- **Logic (Architect's call 22):** acts only on the `cookie` and `authorization` handshake
  points, which exist exactly when the captured handshake carried that header, so the spec's
  "skipped when the handshake carried neither" is "never scheduled"; on any other point
  (including `origin`) it returns `Clean` with detail `"acts on the cookie/authorization handshake points"`.
  Then `baseline()`; then `probe_raw(RawProbe { method: "GET", url: "", headers: [("Cookie", ""), ("Authorization", "")], body: vec![] })`
  (both stripped, whichever were present). 101 and the first data frame equals the baseline's
  first data frame -> `Vulnerable`/`Firm`, detail `"upgrade completed without Cookie/Authorization and the first reply equals the authenticated baseline"`,
  `matched = Some("first server frame identical to baseline")`, `payload: None`; 101 with a
  different first data frame or none -> `Clean`, detail `"reply differs or absent without credentials"`;
  non-101 -> `Clean`, detail `"upgrade refused with status {s} without credentials"`.
- **Tests** (the `cookie` point unless stated): `vulnerable_server_ignores_cookie`: `decide: None`, echo -> `(Vulnerable, Firm)`, `handshakes()[1]` has no `cookie` key and no `authorization` key while `handshakes()[0]` (the baseline) has `cookie == "sid=s3cr3t-cookie"`; `patched_server_requires_cookie`: `decide` returns 401 when `cookie` is absent -> `(Clean, Tentative)`, detail contains `401`; `different_reply_is_clean`: handler replies `{"error":"unauthenticated"}` when the handshake had no cookie, echo otherwise -> `(Clean, Tentative)`, detail contains `differs`; `origin_point_is_clean_with_reason`: the `origin` point -> `Clean`, detail contains `cookie/authorization`, `connections() == 0`.

### Task 11: `checks/reflection.rs`: `ws-input-reflection`

- **Files:** `crates/aitm-scan-ws/src/checks/reflection.rs`.
- **Meta:** `id "ws-input-reflection"`, `name "WebSocket input reflected in a reply"`, `class "ws-input-reflection"`, `kinds [WsJsonValue, WsText, WsFormParam]`, `Light`, cost `Light`, `Reflected`, `severity Medium`, `confidence_max Certain`, `needs_baseline false`, `cwe Some(79)`.
- **Logic:** `canary = payloads::reflection_canary(&host.marker())`; `probe(Payload { value: canary, Replace })`; `classify_reflection(body, marker)`: `Unencoded` -> `Vulnerable`/`Certain`, detail `"marker reflected with < and > unencoded"`, `matched = Some(canary)`; `Encoded` -> `Vulnerable`/`Certain`, detail `"marker reflected with special characters encoded (low impact)"`, `matched = Some(marker)`; `Absent` -> `Clean`.
- **Tests:** `unencoded_reflection_is_certain`: echo -> `(Vulnerable, Certain)`, detail contains `unencoded`, `evidence.payload == Some(canary)`; `encoded_reflection_is_flagged_low_impact`: handler HTML-escapes `<`, `>` and `'` (`&lt;`, `&gt;`, `&#39;`) before echoing -> `(Vulnerable, Certain)`, detail contains `encoded`; `no_reflection_is_clean`: handler replies `{"ok":true}` -> `(Clean, Tentative)`; `budget_zero_is_inconclusive`: `TestJob::new(0)` -> `(Inconclusive, Tentative)`, detail `"budget exhausted"`, `connections() == 0`.

### Task 12: `checks/sql_error.rs`: `ws-sql-error`

- **Files:** `crates/aitm-scan-ws/src/checks/sql_error.rs`.
- **Meta:** `id "ws-sql-error"`, `name "SQL error in a WebSocket reply"`, `class "sqli"`, `kinds [WsJsonValue, WsText, WsFormParam]`, `Medium`, cost `Light` (3 probes), `Error`, `High`, `Firm`, `needs_baseline true`, `cwe Some(89)`.
- **Logic:** `baseline()` first; if `sql_error_signature(baseline body).is_some()` -> `Clean`, detail `"baseline already carries a SQL error signature"`. For each of `SQL_ERROR_PAYLOADS` (stop on first hit): `probe(Replace)`; `sql_error_signature(body) == Some(sig)` -> `Vulnerable`/`Firm`, `matched = Some(sig)`, `payload = Some(p)`, detail `"SQL error signature '{sig}' after payload"`. Else `Clean`.
- **Tests:** `vulnerable_server_leaks_mysql_error`: handler replies `{"error":"You have an error in your SQL syntax near '''"}` when the `msg` field contains `'`, echo otherwise -> `(Vulnerable, Firm)`, `matched == Some("you have an error in your sql syntax")`, `payload == Some("'")`, `connections() == 2` (baseline + the first payload); `patched_server_is_clean_after_three_payloads`: echo -> `(Clean, Tentative)`, `connections() == 4` (baseline + 3); `noisy_baseline_is_clean`: handler always replies the MySQL text -> `(Clean, Tentative)`, detail contains `baseline`, `connections() == 1`.

### Task 13: `checks/ssti.rs`: `ws-ssti`

- **Files:** `crates/aitm-scan-ws/src/checks/ssti.rs`.
- **Meta:** `id "ws-ssti"`, `name "Server-side template injection via WebSocket"`, `class "ssti"`, same three kinds, `Medium`, cost `Medium` (4 probes), `Reflected`, `High`, `Certain`, `needs_baseline false`, `cwe Some(1336)`.
- **Logic:** for each `(payload, expected)` in `ssti_probes(&marker)` (stop on first hit): `probe(Replace)`; `ssti_hit(body, payload, expected)` -> `Vulnerable`/`Certain`, `matched = Some(expected)`, `payload = Some(payload)`, detail `"template expression evaluated: {A}*{B} rendered next to the marker"`. Else `Clean`.
- **Tests:** `vulnerable_server_evaluates_mustache`: handler replaces `{{1543*7}}` with `10801` in the echoed msg -> `(Vulnerable, Certain)`, `matched == Some(format!("{marker}10801"))`, `connections() == 1`; `patched_echo_is_clean`: `connections() == 4`; `bare_49_never_fires`: handler always replies `49` -> `Clean`; and a handler that always replies `10801` -> `Clean` (the marker must be adjacent).

### Task 14: `checks/cmdi_echo.rs`: `ws-cmdi-echo`

- **Files:** `crates/aitm-scan-ws/src/checks/cmdi_echo.rs`.
- **Meta:** `id "ws-cmdi-echo"`, `name "OS command injection echo via WebSocket"`, `class "cmdi"`, same three kinds, `Medium`, cost `Medium` (5 probes), `Reflected`, `High`, `Firm`, `needs_baseline false`, `cwe Some(78)`.
- **Logic:** for each payload in `cmdi_probes(&marker)` (stop on first hit): `probe(Replace)`; `cmdi_hit(body, payload, marker)` -> `Vulnerable`/`Firm`, `matched = Some(marker)`, `payload = Some(payload)`, detail `"echo of the marker without the literal payload"`. Else `Clean`.
- **Tests:** `vulnerable_server_runs_echo`: handler, when the msg contains `;echo `, replies only the text after it -> `(Vulnerable, Firm)`, `payload == Some(format!(";echo {marker}"))`, `connections() == 1`; `echoing_the_literal_is_clean`: echo handler -> `Clean`, `connections() == 5`.

### Task 15: `checks/oversize.rs`: `ws-oversize-frame`

- **Files:** `crates/aitm-scan-ws/src/checks/oversize.rs`.
- **Meta:** `id "ws-oversize-frame"`, `name "Oversized WebSocket frame accepted"`, `class "ws-oversize-frame"`, `kinds [WsText, WsJsonValue, WsBinary]`, `intensity Medium`, cost `Light` (1 probe), `Malformed`, `severity Info`, `Firm`, `needs_baseline false`, `cwe Some(400)`.
- **Logic (Architect's call 21):** a check holds only `&dyn ProbeHost`, so it cannot read the
  flow's largest frame; the host does the sizing. Exactly one `probe(host::pad_payload())`
  (Task 7's sentinel: the host pads the chosen frame at the locator to exactly
  `min(2 x largest observed client frame, profile.ws.max_frame_bytes)` bytes). Outcome by the
  returned frames: a `Close` frame whose close code is `1009` or `1002` -> `Clean`, detail
  `"server closed with {code} (frame-size limit enforced)"`; a `Text`/`Binary` reply present ->
  `Vulnerable`/`Firm`, detail `"no frame-size limit enforced: the oversized frame was processed"`;
  no data frame, no `Close`, and `elapsed_ms < profile.ws.reply_window_ms` (the collection ended
  early, i.e. a transport drop) -> `Vulnerable`/`Firm`, detail `"connection dropped without a Close frame after the oversized frame"`;
  no data frame and `elapsed_ms >= reply_window_ms` -> `Inconclusive`, detail `"no reaction within the reply window"`.
  `evidence.payload = Some("oversized frame (2 x largest observed, capped by max_frame_bytes)")`;
  the exact frame is in `held_flows()` for the engine. The close code is read from the `Close`
  frame's first two payload bytes (big-endian), `None` when the payload is shorter.
- **Tests (Task 15):** `vulnerable_server_processes_oversize_frame`: echo handler -> `(Vulnerable, Firm)`, detail contains `no frame-size limit`, `log.received()[1].len() == 50`, `connections() == 1`; `patched_server_closes_1009`: handler sends `Close(1009)` when a frame payload exceeds 40 bytes -> `(Clean, Tentative)`, detail contains `1009`; `dropped_connection_is_flagged`: handler drops the stream (returns, and the server half is dropped without a Close) on an oversize frame -> `(Vulnerable, Firm)`, detail contains `dropped`; `silence_is_inconclusive`: handler reads and never replies, `reply_window_ms = 300` -> `(Inconclusive, Tentative)`.

### Task 16: `checks/subprotocol.rs`: `ws-subprotocol-observe`

- **Files:** `crates/aitm-scan-ws/src/checks/subprotocol.rs`.
- **Meta:** `id "ws-subprotocol-observe"`, `name "WebSocket subprotocol negotiation"`, `class "ws-subprotocol"`, `kinds [WsHandshakeHeader]`, `Light`, cost `Light`, `Observe`, `severity Info`, `Firm`, `needs_baseline false`, `cwe None`.
- **Logic:** acts on `point.name == "origin"` or `"sec-websocket-protocol"` (else `Clean`, detail `"not a negotiation point"`). `requested = format!("aitm-{}", host.marker())`; `probe_raw(RawProbe { headers: [("Sec-WebSocket-Protocol", requested)], .. })`. 101 and a response header `sec-websocket-protocol` equal to `requested` -> `Vulnerable`/`Firm`, detail `"server echoed an arbitrary subprotocol"`, `matched = Some("echoed Sec-WebSocket-Protocol")`; 101 with no `sec-websocket-protocol` response header -> `Vulnerable`/`Firm`, detail `"upgrade completed without negotiating a subprotocol the client asked for"`; non-101 -> `Clean`, detail contains the status; 101 with a different protocol -> `Clean`, detail `"server selected its own subprotocol"`.
- **Tests:** `echoing_server_is_flagged`: `decide` copies the request's `sec-websocket-protocol` into the response -> `(Vulnerable, Firm)`, detail contains `echoed`; `server_completing_without_protocol_is_clean`: `decide: None` (tungstenite's default accepts without selecting) -> `(Vulnerable, Firm)`, detail contains `without negotiating`; `patched_server_refuses_unknown_protocol`: `decide` returns 400 unless the protocol is `chat` -> `(Clean, Tentative)`, detail contains `400`; `server_selecting_an_unrequested_protocol_is_flagged`: `decide` sets `sec-websocket-protocol: chat` -> `Clean`.

### Task 17: `lane.rs` + `checks/mod.rs::all()`: `WsLane` and the slot flip

- **Satisfies:** spec D1 (`lane()` returns `Some`), D8.3 discovery wiring, D2 `Lane`, AC T4-1 (hermetic half), Architect's calls 2 (lane-held semaphore via its dialer), 4 (registry), 5.
- **Depends on:** Tasks 3, 7, 9-16.
- **Files:** `crates/aitm-scan-ws/src/lane.rs` (replace placeholder), `crates/aitm-scan-ws/src/checks/mod.rs` (fill `all()`).
- **Change:**
  - `checks::all()` returns the eight checks in this order: `cswsh`, `auth_bypass`, `reflection`, `sql_error`, `ssti`, `cmdi_echo`, `oversize`, `subprotocol`.
  - `pub struct WsLane { dialer: Arc<WsDialer>, registry: Mutex<HashMap<String, Registered { spec: PointSpec, handshake: HttpFlow, ws: WsFlow }>> }` with `pub fn new(dialer: Arc<WsDialer>) -> Self`.
  - `impl Lane`: `lane() == LaneKind::Ws`; `discover(target, job)`: `job.store().query(&FlowQuery { kind: Some(FlowKind::WebSocket), is_replay: Some(false), ..Default::default() })`, for each id `store.get(id)` -> `Flow::WebSocket(ws)`, then `store.get(ws.handshake)` -> `Flow::Http(hs)` (skip silently when either is missing), skip when `!origin_matches(&hs, &target.origins)`, `discover_flow(&ws, &hs, &mut IdGen::new(job.job_id()))`, register every `(id, spec, hs, ws)`, collect points and nodes (one node per distinct `(scheme, host, port, path)`; a repeated node merges `flows`, `params`, `points`). `probe_host_for(point, job)`: look up `point.id` -> `WsProbeHost::new(point.clone(), spec, handshake, ws, dialer.clone(), job)`; unknown id -> `Err(anyhow!("unknown ws point {id}"))`. `checks()` -> `checks::all()`.
  - `pub fn build() -> Option<Arc<dyn Lane>>` = `Some(Arc::new(WsLane::new(Arc::new(WsDialer::new(Arc::new(TcpTransport::new(TlsPolicy::AcceptAny, Duration::from_secs(10))))))))` with the Security-review doc comment on the `AcceptAny` choice (Architect's call 3).
- **Test** (`#[cfg(test)]`):
  `discover_reads_only_captured_in_target_ws_flows`: a `TestJob` whose store holds (a) the fixture pair, (b) a copy with `metadata.is_replay = true` on both flows, (c) a copy whose handshake authority is `other.test:8080`; `discover(&job.profile().target, &*job)` -> `points.len() == 6`, `nodes.len() == 1`, `nodes[0].path_template == "/ws"`, every point's `flow == Some(FlowRef(fixture ws id))`;
  `probe_host_for_registered_point_builds_a_host`: after discover, `probe_host_for(&points[4] /* msg */, job)` is `Ok` and its `profile().ws.reply_window_ms == 300`;
  `probe_host_for_unknown_id_is_err`: a point with `id "ws-deadbeef"` -> `Err` containing `unknown ws point`;
  `checks_are_the_eight`: `lane.checks().iter().map(|c| c.meta().id.clone()).collect::<Vec<_>>() == ["cswsh", "ws-auth-bypass-handshake", "ws-input-reflection", "ws-sql-error", "ws-ssti", "ws-cmdi-echo", "ws-oversize-frame", "ws-subprotocol-observe"]`, every `meta().lanes == [Ws]`, every `origin == CheckOrigin::Native`;
  `slot_is_some` (replaces Task 1's placeholder test): `crate::lane()` is `Some` with `.lane() == LaneKind::Ws`.
- **Done when:** `cargo test -p aitm-scan-ws --offline` passes; `cargo test -p aitm --lib --offline wire` now **fails** on `skeleton_lane_slots_are_empty_today` (`collect_lanes(None).len() == 1`): quote the failure and leave it for Task 19's pre-authorised one-line re-pin (T1a call A23); full gate on this crate passes.

### Task 18: live-proof tests: `tests/live_lane.rs` and `tests/live_language.rs` (ignored by default)

- **Satisfies:** spec Verification ("a real scan, over the real bus, against a real target, observed independently") as far as this crate can carry it; ACs T4-1..T4-4 path B; Architect's calls 8, 12.
- **Depends on:** Tasks 8, 17.
- **Files:** `crates/aitm-scan-ws/tests/live_lane.rs`, `crates/aitm-scan-ws/tests/live_language.rs` (create; every test `#[ignore = "binds a loopback port; run in the Terminal"]`).
- **Change (`live_lane.rs`):** the real pipeline as `crates/aitm-proto-ws/tests/ws_capture.rs` builds it: a real `aitm_core::Proxy` with `HttpModule` + `WsModule` on a loopback port, a `MemFlowStore`, a `StdGuard` with the target in scope; the target is `aitm_testtarget::TestTarget::start_on(SeedMode::Vulnerable, 0)` (and `Patched` for the negative run) **when its `/ws` route exists** (T10); a real `tokio_tungstenite` client dials `ws://127.0.0.1:<proxy>` with `Host: 127.0.0.1:<target>`, `Origin: http://127.0.0.1:<target>`, `Cookie: sid=live-s3cr3t`, sends `{"msg":"hi"}`, reads the reply, closes. Then `WsLane::new(real TcpTransport dialer).discover(&target, &job)` over a `JobCtx` built on that store and guard (`testing::TestJob::over(store, guard, 200, |p| p.target.origins = vec![target origin])`), asserting: points include `(WsJsonValue, "msg")` (T4-1); running `cswsh` on the `origin` point yields `(Vulnerable, Certain)` on V and `Clean` on P, and the target's handshake log shows a `Sec-WebSocket-Key` different from the client's and the `Cookie` present (T4-2); `ws-input-reflection` on `msg` yields `Vulnerable` on V and `Clean` on P; `ws-oversize-frame` on `msg` sends exactly one frame of `2 x largest observed` (target frame log) (T4-3); the target's connection log never shows more than 4 concurrent dialer connections; a grep of `format!("{:?}", every verdict)` and of every held flow's `Debug` for `live-s3cr3t` is empty. When `TestTarget` has no `/ws` yet the test prints `SKIP: aitm-testtarget has no /ws route yet (T10)` and returns early **without** passing silently: it `panic!`s with that text so the Terminal run shows it as a failure to be read, never as a green.
- **Change (`live_language.rs`):** `aitm_scan_ws::language(guard)` with the real `TcpTransport`; a `rhai::Engine` from `build_engine_with_languages`; the script `let h = ws.dial(#{ url: "ws://127.0.0.1:<port>/ws" }); ws.send(h, "{\"msg\":\"ping\"}"); let r = ws.recv(h, 1000); ws.close(h); r.frames.len() > 0` is `true` against the target (or, until `/ws` exists, against an in-test tokio-tungstenite echo server on a real loopback `TcpListener`, which is a real socket but a test-authored target: the test name says `_against_loopback_echo` and the plan's Shipped section must not count it as acceptance); `ws.dial(#{ url: "ws://127.0.0.2:1/ws" })` (not in scope) is an error containing `OutOfScope` and no TCP connection is made (the listener on 127.0.0.2 is never bound; the error is the guard's, asserted by text) (T4-4).
- **Test:** the files are the tests. Each is run in the Terminal with
  `cargo test -p aitm-scan-ws --test live_lane --test live_language -- --ignored --nocapture 2>&1 | tee /tmp/claude/t4-live.log; echo exit=$?`.
- **Done when:** both files compile under `cargo test -p aitm-scan-ws --offline --no-run` in the sandbox and the Terminal run's output is quoted (pass, or the explicit `/ws`-missing failure text) in the Coder's report.

### Task 19: integration: merge `origin/main`, re-pin, gate, live proof, hand-off, PR

- **Satisfies:** spec D12 "Integration-shared files" (every track's plan ends with an integration task), Verification, Architect's calls 9, 13.
- **Depends on:** Task 18 (and every earlier task on the branch).
- **Files:** none new. Allowed edits, each only if its condition holds: `crates/aitm/src/wire.rs` test `skeleton_lane_slots_are_empty_today` (the `collect_lanes(None).len()` literal `0` -> `1`, and its comment; pre-authorised by T1a call A23; `collect_native_checks().len()` stays `0`); the integration-shared contract lists (`crates/aitm/tests/frontends.rs` `EXPECTED_TOOLS`, `crates/aitm-tui/src/lib.rs` `CORE_TOOLS`, `crates/aitm-tui/fixtures/bus-fixture.json`, `crates/aitm/tests/bundled_startup.rs`, `crates/aitm-plugin-rhai/tests/bundled_scripts.rs`) **only** if live `tools/list` shows a name this track added (T4 adds no verb; its `check.<id>` commands appear only once T1b's catalogue bridge is on `main` and the lane is wired, so the expected answer is "no re-pin"); `Cargo.lock` (derived, regenerated by the merge).
- **Steps** (Terminal for git/`gh` and anything binding a port; sandbox for the rest):
  1. `git fetch origin && git merge origin/main` on `claude/scanner-v2-t4-384bc0` (merge, not rebase; T1a was squash-merged as PR #213, so expect the T1a files to arrive as one commit and resolve conflicts, if any, in favour of `origin/main` for every file outside `crates/aitm-scan-ws/**`). Record whether T1b (`crates/aitm-plugin-scanner` engine) and T10 (`/ws` in `aitm-testtarget`) are on `main`.
  2. Re-pin `wire.rs` as above; run `cargo test -p aitm --lib --offline wire` and quote it.
  3. Full gate in the Terminal: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test 2>&1 | tee /tmp/claude/t4-gate.log; echo exit=${pipestatus[1]}`; quote the final `test result:` lines and the exit code (the exit status, never a grep). `cargo test -p aitm-plugin-rhai --test api_catalog` must still pass (no `ws` in `production_languages()`).
  4. Ignored tests in the Terminal: `cargo test -p aitm-scan-ws --test tcp_transport --test live_lane --test live_language -- --ignored --nocapture`; quote.
  5. **Live proof, path A** when T1b and T10 `/ws` are on `main`: `cargo build -p aitm -p aitm-testtarget`; `python3 tests/e2e/run.py scan -k t4` (T10's `test_t4_points.py`, `test_t4_cswsh.py`, `test_t4_injection_oversize.py`, `test_t4_ws_namespace.py`): a real core, a real WS conversation through the proxy to `/ws`, `scan.start { lanes: [ws] }`, issues on V and none on P, the target connection log showing <= 4 concurrent dialer connections and a regenerated `Sec-WebSocket-Key`, and an empty grep of every result/push/file for the session cookie value. Quote the runner's PASS lines and exit code; a SKIP (77) is **not** a pass.
     **Path B** otherwise: the Task 18 `live_lane.rs`/`live_language.rs` Terminal run against the real `aitm-testtarget` `/ws` (requires T10's route; if it is also absent, record the proof as **pending T10** with the exact failure text, run `live_language.rs`'s loopback-echo variant as a smoke only, and say so in the PR; the PR is then held for the live proof per Matt's rule, not merged on unit tests).
  6. `cargo tree -p aitm --offline -e normal | grep -c 'aitm-scan-ws'` quoted (the crate is linked), and `aitm` boot in the Terminal with `RUST_LOG=debug` grepped for `ws` language registration (the `main.rs` block logs the languages it installed; quote the line).
  7. Record the hand-off in this plan's Shipped section and in the PR: "T1b/coordinator: add `Box::new(aitm_scan_ws::WsLanguage::for_catalog())` to `production_languages()` in `crates/aitm-plugin-rhai/src/catalog_assembly.rs` and regenerate `docs/design/languages/rhai.api.json` (drift test `tests/api_catalog.rs`); requires `aitm-plugin-rhai` to depend on `aitm-scan-ws` (no cycle: `aitm-scan-ws` depends on `aitm-plugin`, not on `aitm-plugin-rhai`, for its library build; the dev-dependency the other way is test-only and Cargo permits it)". Also record the hook-signal gap (Architect's call 17) and the per-verdict severity gap (call 20) as follow-ups for T1b.
  8. Push with an explicit refspec (`git push origin claude/scanner-v2-t4-384bc0`) and open the PR against `main` (`baseRefName == main`, verify) with the plan path, the gate output, the ignored-test output, the live-proof output or its pending status, the three panel verdicts and the hand-off paragraph. Panel review (stage 6) runs on the whole branch before the merge request.
- **Done when:** the gate exits 0, the ignored tests are quoted, the live proof is recorded (path A or B, or explicitly pending with the reason), the `wire.rs` pin reads `1`, the PR carries the panel comment, and the panel has no open findings.

## File ownership matrix (disjointness check)

| Task | Files (all under `crates/aitm-scan-ws/` unless stated) |
|---|---|
| 1 | `Cargo.toml` (final), `src/lib.rs`, `src/types.rs`, placeholders `src/{transport,testing,dialer,discover,mutate,payloads,host,lane,language}.rs`, `src/checks/mod.rs`, `src/checks/{cswsh,auth_bypass,reflection,sql_error,ssti,cmdi_echo,oversize,subprotocol}.rs` |
| 2 | `src/transport.rs`, `src/testing.rs`, `tests/tcp_transport.rs` |
| 3 | `src/discover.rs` |
| 4 | `src/mutate.rs` |
| 5 | `src/payloads.rs` |
| 6 | `src/dialer.rs` |
| 7 | `src/host.rs` |
| 8 | `src/language.rs` |
| fix round (Q4) | `src/checks/common.rs`, `tests/common/live.rs` |
| 9 | `src/checks/cswsh.rs` |
| 10 | `src/checks/auth_bypass.rs` |
| 11 | `src/checks/reflection.rs` |
| 12 | `src/checks/sql_error.rs` |
| 13 | `src/checks/ssti.rs` |
| 14 | `src/checks/cmdi_echo.rs` |
| 15 | `src/checks/oversize.rs` |
| 16 | `src/checks/subprotocol.rs` |
| 17 | `src/lane.rs`, `src/checks/mod.rs` |
| 18 | `tests/live_lane.rs`, `tests/live_language.rs` |
| 19 | none new; conditionally `crates/aitm/src/wire.rs` (one literal), the integration-shared lists (expected: none), `Cargo.lock` (derived) |

Within a wave no two tasks share a file. `src/lib.rs` is edited only by Task 1 (the slot
bodies delegate to `lane::build()`/`language::build()`, so flipping a slot is an edit inside
`lane.rs`/`language.rs`). `src/checks/mod.rs` is written by Task 1 (module lines, empty
`all()`) and Task 17 (`all()` body), in different waves. `src/testing.rs` is written by Task 2
only. `Cargo.lock` is derived: Task 1 regenerates it
(new external crates: `rustls`, `tokio-rustls`, `rustls-pki-types`, `webpki-roots`,
`form_urlencoded`, `rcgen` (dev), `rhai` (dev); all already in the lock through other crates)
and Task 19 after the merge.

## Architect's calls in this plan (for the orchestrator/Matt to approve or correct)

Decisions 1-9 were made by the T4 session before this plan and are recorded as given; 10
onwards are this plan's.

1. **Module layout** inside `crates/aitm-scan-ws/src/`: `lib.rs` (slots + crate doc), `transport.rs` (`WsTransport` trait with `connect(&self, host, port, tls: bool, sni) -> BoxFuture<Result<ByteStream>>`; `TcpTransport` production impl: TCP connect with a connect timeout then optional tokio-rustls TLS), `dialer.rs` (`WsDialer`, `HandshakeOverrides { set, strip }`, `DialOutcome`/`WsConn`, the header replay rule, the 4-permit `tokio::sync::Semaphore`, ping/pong/close handling, the recorded `HttpFlow` + `WsFlow` with `is_replay: true`), `discover.rs` (points + nodes from captured `WsFlow`s), `mutate.rs` (place a `Payload` at a point: JSON leaf by dotted/bracket path, form pair, whole text, binary bytes, handshake header), `host.rs` (`WsProbeHost`), `checks/mod.rs` + one file per check, `lane.rs` (`WsLane`), `language.rs` (`WsLanguage`), `payloads.rs` (the small sqli-error / ssti / cmdi payload and signature tables, duplicated from the HTTP vocabulary on purpose because T3's crate is not a dependency; follow-up to share once T3 lands).
2. **Authority gating:** every dial calls `guard.check_active("host:port")` (the handshake request's authority, default port filled from the scheme) and holds the `ActionPermit` for the connection's life; `RateLimited { retry_after }` is waited out once (bounded by the deadline) then retried, every other `GuardError` is a probe error. Budget: `job.charge(1)` per dial and per frame sent, `Err` when it returns `false`. The lane holds one 4-permit semaphore shared by every probe host it builds (per-lane, which bounds each job at <= 4 and errs toward fewer connections when two jobs run); the language holds its own 4-handle bound.
3. **TLS:** `WsDialer` is built over a transport with a `TlsPolicy::{Verify, AcceptAny}`; `lane()` uses `AcceptAny` (the scanner dials only authorities the operator put in scope; lab targets have self-signed certificates; `Http1Sender` has the same `insecure` posture) with a doc comment and a named Security-review item; `language()` uses `AcceptAny` too for the same reason. The accept-any verifier is a ~30-line `rustls::client::danger::ServerCertVerifier` in `transport.rs`.
4. **Point identity:** `discover` fills a lane-held registry `Mutex<HashMap<String, PointSpec { ws_flow, handshake, frame_index: Option<usize>, locator: Locator::{JsonPath, FormParam, WholeText, Binary, HandshakeHeader} }>>` and `probe_host_for` looks the point up (unknown id -> `Err`). Point ids are `ws-<8 hex>` (hash or counter; stable within a job). Points are deduped per `(kind, name, path)` across frames of one flow with `frequency` counting repeats; the chosen frame is the first client->server frame carrying the field. `example` is `scrub_text` of the observed value, `<redacted>` when `is_secret_key(name)` or the point is a `Cookie`/`Authorization` handshake header; such points carry `PointTrait::Session`. Traits: `Number` (parses as f64), `Email` (contains `@` and `.`), `Url` (starts with `http://`, `https://`, `ws://`, `wss://`, `/`), `Base64` (len >= 16, base64 alphabet, len % 4 == 0), `Json` (value parses as a JSON object/array), `Id` (name ends with `id`/`_id`, or value is a UUID / all digits). A WsFlow is in target when its handshake flow's `scheme://authority` (`ws`->`http`, `wss`->`https`) equals one of `target.origins` after default-port normalisation. Only non-replay captured flows (`FlowQuery { kind: WebSocket, is_replay: Some(false) }`) are read. One `SiteNode` per handshake `(GET, scheme, host, port, path)`; `path_template` = the path as is.
5. **Probe semantics** (`WsProbeHost::probe`): dial with the captured handshake (plus the point's handshake override when the point is a handshake header: a non-empty payload value replaces the header, an empty value strips it), replay the client->server frames that precede the chosen frame unchanged, send the mutated frame, collect server frames for `profile.ws.reply_window_ms` (bounded by the deadline and `cancelled()`), send Close, return `ProbeResponse { status: Some(handshake status), headers: handshake response headers, body: concatenated text reply payloads bounded at MAX_MATCH_BODY, elapsed_ms, flow: None under issues_only, ws_frames: Some(all server frames incl. Close) }`. A failed handshake (non-101) is `Ok` with `status: Some(code)`; a TLS or TCP error is `Err`; checks treat a connect `Err` as inconclusive. `baseline()` = the same with the original frame, cached once. `probe_raw(RawProbe)` = a handshake-only dial where `headers` are overrides (`(name, "")` strips) followed by the same frame replay and collection. `held_flows()` returns the handshake `HttpFlow` and the conversation `WsFlow` of the baseline and of up to 16 probes (newest kept), each `is_replay: true`, marks `scan:<job>`; under `RecordProbes::All` they are inserted into `job.store()` as sent.
6. **Checks** (all `origin: Native`, `lanes: [ws]`, fixed `CheckMeta` values): `cswsh` (class `cswsh`, kinds `[ws_handshake_header]`, acts only on the `origin` point, `handshake`, `Light`, severity `High`, `confidence_max: Certain`, `needs_baseline: true`, cwe 1385): dial with `Origin: https://attacker.invalid` keeping cookies; vulnerable when the upgrade completes **and** the first server frame equals the baseline's first server frame (`Certain`), or the upgrade completes and a server frame arrives but differs (`Firm`); a non-101 is `Clean`; no server frames in either arm is `Inconclusive`. `ws-auth-bypass-handshake` (class `ws-auth-bypass`, kinds `[ws_handshake_header]`, `handshake`, `Light`, `High`, `Firm`, `needs_baseline: true`, cwe 287): `probe_raw` stripping `Cookie` and `Authorization`; vulnerable when 101 and the first server frame matches the baseline's; `Clean` on 401/403/non-101 or a different/absent reply; skipped (`Clean`, detail says why) when the captured handshake carried neither header. `ws-input-reflection` (class `ws-input-reflection`, kinds `[ws_json_value, ws_text, ws_form_param]`, `reflected`, `Light`, `Medium`, `Certain`, cwe 79): `<marker>"'<>`-style canary; reflected with `<`/`>` unencoded is `Medium`/`Certain`, reflected otherwise is low-impact/`Certain`, absent `Clean`. `ws-sql-error` (class `sqli`, `error`, `Medium`, `High`, `Firm`, cwe 89), `ws-ssti` (class `ssti`, `reflected`, `Medium`, `High`, `Certain`, cwe 1336, arithmetic canary with the marker so `49` alone never fires), `ws-cmdi-echo` (class `cmdi`, `reflected`, `Medium`, `High`, `Firm`, cwe 78, `echo <marker>` forms; marker present and literal payload absent): same three kinds as reflection; signatures in `payloads.rs`. `ws-oversize-frame` (class `ws-oversize-frame`, kinds `[ws_text, ws_json_value, ws_binary]`, `malformed`, `Medium` intensity, `Info`, `Firm`, cwe 400): exactly one frame padded to `min(2 x largest observed client frame in the flow, profile.ws.max_frame_bytes)`; `Vulnerable(Info, Firm)` when the server processes it (detail "no frame-size limit enforced"), `Vulnerable(Info, Firm)` with detail "connection dropped without a Close frame" on a transport drop, `Clean` on Close 1009 or 1002, `Inconclusive` on silence. `ws-subprotocol-observe` (class `ws-subprotocol`, kinds `[ws_handshake_header]`, `observe`, `Light`, `Info`, `Firm`): dial with `Sec-WebSocket-Protocol: aitm-<marker>`; `Vulnerable(Info)` when the 101 echoes that protocol back or when the client sent a subprotocol and the server completed the upgrade with none; else `Clean`. No compression oracle. Every check stops on `cancelled()`, `budget_left() == 0` or the deadline, returns `Inconclusive` on a connect error, and never puts a cookie or header value in `detail`, `evidence.payload` or `evidence.matched` (excerpts go through `scrub_text` then `Evidence::excerpt`).
7. **`ws` language:** `WsLanguage::new(guard, dialer)` and `WsLanguage::for_catalog()`; namespace `ws`, `api_version "1"`; host fns `ws.dial(#{ url, headers? }) -> int handle`, `ws.send(handle, text|blob) -> ()`, `ws.recv(handle, timeout_ms) -> #{ frames: [ #{ kind, text?, bytes? } ] }`, `ws.close(handle) -> ()`; `poc_step()` returns `None` in v2. Each fn is `Guarded` with a `WsSeamGuard` whose `permit` admits every caller for now (hook-signal gap) and whose `guard_name` is `ws`; the scope check `guard.check_active(authority)` runs inside `ws.dial` before any connect and the permit is held with the handle. Host fns are synchronous, so the language owns one background driver thread running a current-thread tokio runtime holding the open streams in a `HashMap<i64, Handle>`; host fns talk to it over `std::sync::mpsc` and block on the reply with a timeout. Handles are bounded at 4 (`ws.dial` with 4 open -> `HostError::GuardRefused` naming the bound), closed by `ws.close`, reaped after 30 s idle; `timeout_ms` in `ws.recv` is clamped to 30 000.
8. **Verification:** `cargo test` stays hermetic via the transport seam; port-binding and real-target tests are `#[ignore]`d and run in the Terminal; the live proof follows path A (T1b engine + T10 seed on `main`: real core, real WS conversation through the proxy, `scan.start { lanes: [ws] }`, the T10 `test_t4_*.py` cells) or path B (`tests/live_lane.rs` over the real `aitm-core` + `aitm-proto-http` + `aitm-proto-ws` pipeline on a loopback port to the real `aitm-testtarget` `/ws`) and is recorded in Shipped with the observer outputs quoted; no fixture, sample-data or in-process-model run is acceptance evidence.
9. **The integration task** (Task 19) merges `origin/main`, re-pins the integration-shared contract lists only if a name this track adds appears in live `tools/list` (T4 adds no bus verb; `check.<id>` commands exist only once T1b's bridge is on `main`), runs the full gate in the Terminal, runs the ignored live tests, records the `production_languages()` hand-off, and opens the PR with the panel verdicts and proofs.
10. **Scaffold-first (Task 1) and a shared `types.rs`.** `Locator`, `PointSpec`, `HandshakeOverrides`, `TlsPolicy` and the numeric bounds live in `types.rs`, written in wave 1, so discover/mutate/transport/payloads compile in parallel in wave 2 without sharing a file. The manifest is final after Task 1 (every dependency and dev-dependency declared up front with the task that uses it), so no later task touches `Cargo.toml`.
11. **Slot bodies delegate.** `lib.rs`'s `lane()`/`language()` call `lane::build()`/`language::build(guard)` from Task 1 on, so the only edit that flips a slot is inside the module that owns it; `lib.rs` is written once.
12. **`testing.rs` is a real-protocol harness, always compiled, `#[doc(hidden)]`.** `DuplexTransport`, `ws_server` (real `accept_hdr_async`, header log, pluggable handshake decision and connection handler), `echo_handler`, the one canonical `captured_conversation()` fixture, `TestJob` (a `JobCtx` over `MemFlowStore` + `StdGuard` with a countable budget) and `point(..)`. Checks and the lane test against the real `WsProbeHost` and the real tungstenite client/server; only the socket is a duplex. This is the inner loop, not evidence.
13. **`production_languages()` is a hand-off, not an edit.** T4 exposes `WsLanguage::for_catalog()`; adding `ws` to the catalogue and regenerating `rhai.api.json` is a one-line T1b/coordinator change recorded by Task 19. `cargo test -p aitm-plugin-rhai --test api_catalog` must keep passing on this branch.
14. **Point ids hash with `std::hash::DefaultHasher`** over `(job id, ws flow id, kind, locator)` (`blake3` is not in the offline cache); stable within a process, which is the spec's "stable within a job". Handshake-header points use the first client->server frame as their chosen frame (so a handshake check still sees the authenticated conversation), `None` when the flow has no client frame.
15. **JSON mutation re-serialises with `serde_json`** (compact; key order is serde_json's, not the original's) rather than splicing bytes or enabling `preserve_order` (which would change `serde_json::Value` behaviour workspace-wide through feature unification). A non-string leaf becomes a JSON string under `Replace`; `Prefix`/`Suffix` concatenate with the leaf's text. Form pairs re-encode with `form_urlencoded` (space -> `+`). `canonical_len` gives the exact re-serialised baseline length so padding is exact.
16. **Payload tables are tiny and fixed:** three SQL error payloads, eight DBMS signatures, four SSTI templates with `1543*7 = 10801` adjacent to the marker, five `echo` forms. `Evidence.matched` is the signature constant or the marker-bearing expectation, never server text. The reflection canary is `<marker><'>` rather than decision 6's `<marker>"'<>` sketch: a `"` (or `\`) is escaped by the JSON re-serialisation of call 15, so every JSON point would read as "encoded"; `<`, `>` and `'` pass through unescaped and still prove an unencoded HTML-context reflection.
17. **Hook-vs-command gap recorded, not papered over.** The language seam carries no `RunKind`; `WsSeamGuard::permit` admits the four fns for every caller and documents that "a hook cannot call `ws.*`" (spec D8.3) is unenforceable inside this crate today. The coordinator/T1b owns the fix (a caller-kind signal on `HostCallCtx` or the tag); `permit` is written so one `match` honours it when it arrives.
18. **`DialOutcome::Refused` is data, not an error.** A non-101 upgrade is an `Ok(ProbeResponse { status: Some(code), ws_frames: Some([]) })` so handshake checks can read 401/403 directly; only TCP/TLS/timeout failures are `Err`. A transport drop during collection ends the collection and is **not** an error either; the frames (no `Close`) and an early `elapsed_ms` are how `ws-oversize-frame` recognises it, because `ProbeHost` is the only surface a check has.
19. **No `PocHint` from any WS check in v2.** There is no `ws:` PoC step (`poc_step()` is `None`), so a hint would describe a PoC the runner cannot execute; WS findings are issues, not `FindingRecord`s. Follow-up: a `ws:` step handler plus hints once `aitm-poc` grows a WS step.
20. **Per-verdict severity cannot be expressed.** `Verdict` has no severity and `CheckMeta.severity` is per check, so `ws-input-reflection`'s "low otherwise" (spec D8.3) becomes `Certain` with a detail that says "encoded ... (low impact)" at the check's `Medium` severity. Recorded as a follow-up for T1b (a default-bodied `severity_override: Option<Severity>` on `Verdict` would be an additive model change T1b may make).
21. **The oversize pad is a host-interpreted sentinel payload.** The check cannot see the flow or the canonical frame length (checks hold only `&dyn ProbeHost`), so `WsProbeHost` recognises `host::pad_payload()` (a `Suffix` payload whose value begins with `"\u{0}aitm-pad:"`) and pads the chosen frame at the locator to exactly `min(2 x largest observed client frame, profile.ws.max_frame_bytes)` bytes. The sentinel never leaves the process; `evidence.payload` describes the frame in words.
22. **`ws-auth-bypass-handshake` acts on the `cookie`/`authorization` points** (they exist exactly when the handshake carried the header), so the spec's "skipped when the handshake carried neither" is "never scheduled"; on the `origin` point it returns `Clean` with a reason. `ws-subprotocol-observe` acts on `origin` or `sec-websocket-protocol`.
23. **Dialer semaphore lives in `WsDialer`;** the lane owns one dialer (so every host it builds shares the 4 permits, call 2) and the language owns another (its own 4, plus the 4-handle bound). Two jobs share the lane's dialer, so two concurrent WS jobs share 4 connections (fewer, never more, than the spec's "4 per job").
24. **The language's `GuardRefused` reason is `"{GuardError variant}: {authority}"`** (`OutOfScope: evil.test:80`) so AC T4-4's "refused (`OutOfScope`)" is greppable and no guard-internal text leaks; the 4-handle refusal reads `"4 handles already open; close one first"`.
25. **Live-proof fallback is explicit, never silent.** Until T10's `/ws` exists, `live_lane.rs` fails with a `SKIP:` text (a Terminal run cannot show green), and the loopback-echo variant of `live_language.rs` is labelled a smoke. The PR is held for the real proof per Matt's standing rule.
26. **Per-dial `DialLimits`.** The frame/message cap is the job profile's (`ws.max_frame_bytes`) while the `WsDialer` is shared by every host of a lane, so the cap travels with each `dial` call as `DialLimits` rather than being baked into the dialer; the language passes `DialLimits::default()` (1 MiB).
27. **Rate-limit wait is deadline-aware.** A `RateLimited { retry_after }` longer than the time left is returned at once as a guard error rather than slept on; within the deadline it is slept once and retried once (decision 2's "waited out once").

### T4 session decisions on the Architect's questions (autonomous mandate, 2026-10-31)

1. No live proof, no merge: if neither path A nor path B can run against T10's real `/ws` at integration time, the PR is opened as draft and **held**; the hermetic gate plus the loopback smoke never stand in for acceptance (call 25 stands).
2. Per-verdict severity: detail text at the check's `Medium` severity (call 20 stands); the additive `Verdict.severity_override` is handed to T1b as a follow-up, not requested now.
3. TLS: `AcceptAny` for lane and language (decision 3 stands); a `ws.tls_verify` profile key is a T1b follow-up and is listed in the hand-off.
4. Connection bound: shared 4 across concurrent WS jobs (call 23 stands).
5. `ws-oversize-frame`: a drop without a Close frame stays `Vulnerable(Info, Firm)` (decision 6 stands); the detail names it as a robustness observation.

### Coordinator decisions received 2026-10-31 (amend calls 13 and 17; Task 19)

- **Call 13 amended.** `crates/aitm-plugin-rhai/src/catalog_assembly.rs::production_languages()` and `docs/design/languages/rhai.api.json` are **integration-shared files** (same status as the contract lists). Task 19 (not T1b) adds `Box::new(aitm_scan_ws::WsLanguage::for_catalog())` to `production_languages()`, adds `aitm-scan-ws` to `aitm-plugin-rhai`'s `[dependencies]` for that one call, regenerates the golden `namespaces.ws` block from `assemble_namespaces`, and keeps `cargo test -p aitm-plugin-rhai --test api_catalog` green. These edits happen only in the final integration commit, after T1b is on `main`.
- **Call 17 amended.** T1b exposes the run kind (hook vs command/check) through a default-bodied method on `HostCallContextSource`; once it is on `main`, `WsSeamGuard::permit` refuses `ws.*` when the context reports a hook (Task 19 wires the one `match` arm if the method exists at integration time, otherwise it is the first follow-up). Until then `ws.*` stays scope-guarded, budgeted and bounded to 4 handles.
- The `/ws` seed shape T4 sent to the coordinator was relayed to T10 verbatim; Task 18's live tests are written against it: `ws://<target>/ws`, JSON `{"type":"chat","msg":"<text>"}` echoed (V unencoded, P HTML-escaped), V accepts any `Origin` / P 403 on a foreign one, cookie login from `/login` (P 401 without it), a handshake log (Origin, `Sec-WebSocket-Key`, cookie present yes/no) and a connection open/close log readable by the harness, `Sec-WebSocket-Protocol` echoed verbatim in V and ignored in P.

### Task 6 amendment (T4 session, 2026-11-01): the dialer drives the upgrade itself

tungstenite 0.28's client handshake (`VerifyData::verify_response`, `handshake/client.rs:275-294`) fails the handshake when the request carried `Sec-WebSocket-Protocol` and the 101 does not echo one, when the server echoes an unrequested one, or echoes a different one. A scanner must *observe* those server behaviours (D8.3 keeps `Sec-WebSocket-Protocol` in the replay; `ws-subprotocol-observe` reports "upgrade completed with none"), so `client_async_with_config` cannot be the handshake path. **Decision (call 28):** `WsDialer::dial_request` performs the HTTP/1.1 upgrade itself: `tungstenite::handshake::client::generate_request(request) -> (bytes, key)` writes the request; the response head is read with a bounded loop (at most 16 KiB, until `\r\n\r\n`; a larger or malformed head is `DialError::Handshake`) and parsed with `httparse::Response` (64 headers); a non-101 status is `DialOutcome::Refused { status, headers }`; a 101 must carry `Sec-WebSocket-Accept == tungstenite::handshake::derive_accept_key(key)` (mismatch is `DialError::Handshake`); `Upgrade`/`Connection` and the subprotocol are **recorded, not enforced** (`WsConn::response_headers` exposes them, and `WsConn::subprotocol() -> Option<String>` reads `Sec-WebSocket-Protocol` from the 101); the stream becomes `tokio_tungstenite::WebSocketStream::from_partially_read(stream, bytes_after_head, Role::Client, Some(config))` so a frame sent right after the 101 is not lost. `httparse = "1"` (1.10.1 in the offline cache, already in `Cargo.lock` through tungstenite) is added to `[dependencies]`; call 10's "manifest final after Task 1" is amended by exactly this line. Task 6's test `non_101_is_a_refused_outcome` asserts `log.handshakes().len() == 1` and `log.connections() == 0` (Task 2 landed `connections()` as completed upgrades). Budget charging (one unit per dial and per frame) is the probe host's job (Task 7), since the dialer signatures carry no `JobCtx`; Task 7's brief says so. A new Task 6 test `upgrade_without_subprotocol_echo_is_still_upgraded` dials the fixture (which carries `Sec-WebSocket-Protocol: chat`) against the default `ws_server(None, ..)` (no echo) and asserts `DialOutcome::Upgraded` with `subprotocol() == None`; and `wrong_accept_key_is_a_handshake_error` uses a `HandshakeDecision` that replaces `Sec-WebSocket-Accept` with a bogus value and asserts `DialError::Handshake`.

### Task 7 amendments (T4 session, 2026-11-01)

- **Call 29, prerequisite replies are drained.** After each replayed preceding client frame the host reads and discards that frame's answer (`drain_reply`: 25 ms steps, bounded by `reply_window_ms`; a silent server costs at most one window per prerequisite). If the drain ends with Close, a drop, the deadline or a cancel, the frames seen are kept, nothing further is sent and the response is what arrived. Without this an echoing server makes `ws_frames` carry the prerequisites' answers and the plan's own first Task 7 test cannot hold.
- **Call 30, `WsConn::collect`'s cancel callback is `&(dyn Fn() -> bool + Sync)`.** `ProbeHost` futures are `BoxFuture` (`Send`), and a `&dyn Fn()` held across an await is not; one token in `dialer.rs`, landed with Task 7's commit.
- **Call 31, the oversize probe's dial limit sits above the pad target.** The pad target stays `min(2 x largest observed client frame, profile.ws.max_frame_bytes)`, but the dial for a pad-sentinel probe uses `DialLimits { max_frame_bytes: max(2 x pad_target, pad_target + 4 KiB) }`, so an echo of the padded frame is readable by our own reader and a `Transport` end can only come from the server (otherwise `ws-oversize-frame` would report its own reader's limit as "connection dropped"). Test `pad_probe_raises_the_dial_limit_so_an_echo_is_readable`.
- `RawProbe.method`/`.body` are ignored by the WS host (an upgrade is a bodyless GET); a send failure on the wire ends the conversation as data, not `Err` (call 18).

### Tasks 9-16 amendment (T4 session, 2026-11-01): `aitm-poc` dependency, three check rulings

- **Call 32.** `CheckMeta.severity` is `aitm_poc::Severity` and the model crate does not re-export it, so `crates/aitm-scan-ws/Cargo.toml` gains `aitm-poc.workspace = true` (call 10 amended a second time; the session made the edit once, before any check file used it). Checks name the type as `aitm_poc::Severity`.
- `cswsh`: a probe that answers while the baseline was silent is `Vulnerable`/`Firm` ("differs from the baseline"); `Inconclusive` is gated on the *probe* having no data frame. The vulnerable test server models the seeded target (greets `{"type":"hello","user":"alice"}` after the upgrade when the cookie is present) rather than the bare echo handler; an extra test proves the Firm arm's excerpt is scrubbed (`sid=s3cr3t-cookie` never appears in `{:?}` of the verdict).
- Handshake-header points are named by the lowercased header name (`origin`, `cookie`, `authorization`, `sec-websocket-protocol`); their chosen frame is the first client frame, so no prerequisite is replayed for them.

### Task 16 ruling (T4 session, 2026-11-01, call 33)

`ws-subprotocol-observe`: a 101 that carries no `sec-websocket-protocol` (or an empty one) is **Clean** (RFC 6455 lets a server decline every offered subprotocol; the client is expected to fail such a connection), so the Patched target, which ignores the header, yields no issue. `Vulnerable(Info, Firm)` only when the 101 echoes the `aitm-<marker>` token (accepts any subprotocol) or selects a protocol the client never offered. Decision 6's "completed the upgrade with none" arm is withdrawn; the test is `server_completing_without_protocol_is_clean`. The check runs on both the `origin` and `sec-websocket-protocol` points (two dials per handshake); a per-handshake dedupe is an engine concern left as a follow-up.

### Task 15 amendment (T4 session, 2026-11-01, call 34): Close frames carry their code

The dialer recorded a received Close frame's payload as the reason text only, so no check could read the close code (`ProbeResponse` carries no `CollectEnd`, call 18) and `ws-oversize-frame`'s `Clean` arm (Close 1009/1002) was unreachable. `dialer.rs` now records a Close payload in the RFC 6455 layout (2-byte big-endian code + reason, the layout `aitm-proto-ws` captures) and reads a sent `FrameKind::Close` payload the same way (shorter than two bytes = code 1000, empty reason); test `close_frame_payload_carries_code_and_reason`. `ProbeResponse.elapsed_ms` is measured from the dial and includes the prerequisite drain (call 29), so the drop arm's early-`elapsed_ms` reading degrades to `Inconclusive` on a target whose prerequisite replies are slow; conservative, never a false `Vulnerable`.

- Call 33 addendum: the probe offers only `aitm-<marker>`, so a 101 selecting any other token (the test server's `chat`) is "a protocol the client did not offer" and is `Vulnerable(Info, Firm)` ("server selected an unrequested subprotocol"; RFC 6455 §4.1 step 6 makes the client fail such a connection). Task 16's tests are `echoing_server_is_flagged`, `server_completing_without_protocol_is_clean` (`(Clean, Tentative)`), `patched_server_refuses_unknown_protocol`, `server_selecting_an_unrequested_protocol_is_flagged` (`(Vulnerable, Firm)`).

### Task 18 amendment (T4 session, 2026-11-01, call 35): the real target is T10's binary

T10's `/ws` seed is on `feat/scanner-v2-t10-seeds` (not on `main` yet), so the in-tree `aitm-testtarget` library this branch builds has no `/ws`. The live tests therefore spawn the **real serve binary** named by `AITM_TESTTARGET_BIN` (the e2e harness's own convention, `tests/e2e/aitm_e2e/target.py`), built from T10's branch, with `--mode vulnerable|patched --port 0 --control-port 0`, and read `listening http://127.0.0.1:P` and `control http://127.0.0.1:P` from its stdout (then `ready`). Without the env var the tests `panic!` with `SKIP: set AITM_TESTTARGET_BIN to a serve binary that has /ws (T10 branch)`, never a silent green. Observers are the control origin's `GET /log/ws` (`entries[]` tagged `kind: handshake | frame | close`; a handshake carries `origin`, `sec_websocket_key`, `cookie_names`, `session_valid`, `accepted`, `status`, `subprotocol`; a frame carries `conn_id`, `dir`, `opcode`, `len`, `sha256`) and `GET /log/conns` (`entries[]` with `conn_id`, `opened_ms`, `closed_ms`), plus `POST /reset`. The login cookie is `session` from `POST /login` (`user=alice&pass=wonderland`). Target facts the assertions use: the server sends `{"type":"hello","user":"alice"|"anonymous"}` first; `{"type":"echo","msg":M}` is answered `{"type":"echo","msg":M,"html":"<b>M</b>"}` raw in V and escaped in P; V accepts any `Origin`, P answers 403 to a foreign one and 401 without the cookie; V echoes the first requested subprotocol token, P ignores it; frames above 1 MiB close 1009 in **both** modes, so `ws-oversize-frame` (pad target `min(2 x largest, 1 MiB)`) is answered the same way on V and P and its live assertion is AC T4-3's literal one (exactly one frame of `2 x largest observed` reached the target, by the frame log's `len`), not a V/P difference. The V-only issues the proof asserts are `cswsh`, `ws-input-reflection` and `ws-subprotocol-observe`; P yields none of them. Concurrency is read from `/log/conns` (at no instant more than 4 rows open). The dialer's regenerated key is the handshake entry's `sec_websocket_key` differing from the capture client's. The cookie grep is for the literal session value over every verdict `Debug`, every held flow `Debug` and the lane's `Discovery` JSON.

### Rulings from the first real-target run (T4 session, 2026-11-01, calls 36-38)

The Task 18 tests ran in the Terminal against T10's serve binary (`feat/scanner-v2-t10-seeds` at `f12a2f3e`) on the first attempt: V and P lane sweeps and the three `ws.*` script tests passed as written; peak concurrency 4 of 4; every dial carried a fresh `Sec-WebSocket-Key`; the cookie was absent from all 32 verdicts and the discovery JSON. Two verdicts on P were wrong and are fixed before review:

- **Call 36, encoded reflection is `Clean`.** `ws-input-reflection` on P reported `Vulnerable/Certain` "encoded (low impact)" because its `Encoded` arm was `Vulnerable` (call 20). An HTML-escaped reflection is not a vulnerability; the arm is now `Clean`/`Tentative` ("marker reflected with special characters encoded (not exploitable as written)"), test `encoded_reflection_is_clean`. AC T4-3 holds literally (V unencoded `Vulnerable/Certain`, P no issue). The spec's "low otherwise" arm waits on `Verdict.severity_override` (T1b follow-up).
- **Call 37, escaped payloads count as present.** `ws-cmdi-echo` on P reported `Vulnerable/Firm` because the form `& echo <marker>` came back HTML-escaped (`&amp; echo <marker>`), so "literal payload absent" was true although the server only echoed it. `payloads::cmdi_hit` (and `ssti_hit`, for symmetry) now treat the payload as present when it appears raw, HTML-escaped or JSON-string-escaped; tests `cmdi_hit_sees_an_html_escaped_payload_as_present`, `patched_escaping_echo_is_clean`.
- **Call 38, held flows carry the replayed cookie by design.** `held_flows()` returns the replay `HttpFlow`/`WsFlow` the engine re-records only when an issue is found (D5); like every captured flow in the store they carry the request headers. The redaction rule covers verdicts, evidence, points, `Debug` of the probe types and logs; the live test prints the held-flow fact and asserts the others.
- Observed, accepted: in the live sweep every check was run on every point regardless of `CheckMeta.kinds` (the test does not model the scheduler), so the handshake-header points saw frame-mutating payloads and `ws-oversize-frame` returned `Inconclusive` there ("header value cannot be sent on the wire"). In production the scheduler selects checks by `kinds` (spec D4); checks do not re-filter. `ws-oversize-frame` is `Vulnerable(Info)` on both modes because the seed's 1 MiB limit is not mode-dependent (call 35).

### Panel round 1 amendments (T4 session, 2026-11-01, calls 39-46)

The stage-6 panel (security, quality, spec, tester) ran on the whole branch at `80fd0816`; its findings and dispositions are the Review log rows below. The fix round (commits `844720e9`, `5cf7783b`, `a5a8a25e`, plus round 2) changed decisions this plan pins; each is recorded here, superseding the earlier text.

- **Call 39, `ws.*` handle lifetime.** D8.3 says handles are "closed when the call ends"; the seam exposes no end-of-call signal (the same gap as call 17), so a handle lives until `ws.close` or 30 s idle (`HANDLE_IDLE_REAP`), reaped by the driver. Accepted deviation; hand-off to T1b with the run-kind signal.
- **Call 40, TLS defaults to `Verify` (supersedes call 3 and session decision 3; security S2).** The parity claim behind call 3 was wrong: `Http1Sender` verifies against the webpki roots by default and relaxes only under `Config.ssl_insecure`. `lane::build()` and `language::build(guard)` now dial with `TlsPolicy::Verify`; `lane::build_with(TlsPolicy)` and `language::build_with(guard, TlsPolicy)` exist so the binary can pass `cfg.ssl_insecure` (hand-off: one line each in `crates/aitm/src/wire.rs` and `main.rs`, T1b/coordinator-owned files). `AcceptAnyVerifier` skips chain validation only; it verifies the handshake signature with the provider, as `aitm_proto_http::module::AcceptAnyServerCert` does. Consequence until the wiring lands: a `wss://` lab target with a self-signed certificate yields `Inconclusive` ("connect error") on every WS check; plain `ws://` is unaffected.
- **Call 41, resolve-time SSRF check and dial order (security S3, S8; supersedes Task 2's `connect(host, port, ..)` and Task 6's step order).** `WsTransport::connect(addr: SocketAddr, tls, sni)`; `WsDialer::dial_request` acquires a connection slot, then `check_active(authority)`, then resolves with `lookup_host` bounded by the deadline and runs `aitm_core::ssrf_check(policy, &guard.list_scope(), false, authority, ip)` per candidate (`SsrfPolicy::default()`: private and loopback blocked unless the literal address is scoped; `WsDialer::with_ssrf` overrides), connecting only to an admitted address. The guard permit is no longer held while waiting for a slot.
- **Call 42, bounded collection and outgoing frame cap (security S5, tester F2; supersedes call 26's one-field `DialLimits`).** `DialLimits { max_frame_bytes, max_collect_bytes (8 MiB), max_collect_frames (256) }`; `collect` ends with `CollectEnd::Limit` at either ceiling and the recorded replay conversation is capped the same way (`unrecorded()` counts the rest); `WsConn::send` refuses a frame above `max_frame_bytes` (the padded oversize frame stays under it by construction); the `ws.*` driver drains a handle's record after every `ws.recv`.
- **Call 43, per-job bounded registry and query-free urls (quality Q2, security S7; supersedes call 4's registry shape, Task 17's `Registered`, Task 3's `url`).** The lane registry holds `PointSpec`s only, keyed by job id, evicting the oldest job past `REGISTERED_JOBS = 16`; `probe_host_for` re-reads the `WsFlow` and its handshake from `job.store()` and errors when either is gone or the point belongs to another job. `InsertionPoint.url` and `SiteNode.path_template` carry the path without the query string.
- **Call 44, concurrent `ws.*` driver and error shapes (quality Q1, Q3, Q6, Q7; security S1, S4, S6, S9; supersedes Task 8's serial `std::sync::mpsc` loop).** One driver thread with a current-thread runtime and a `LocalSet`; commands arrive over `tokio::sync::mpsc`, each runs in its own `spawn_local` task, handles are per-handle `tokio::sync::Mutex`es (a same-handle collision is "websocket handle N is busy"), a `dialing` counter keeps concurrent dials under `MAX_HANDLES`, the reaper is its own task. `DialError::Request` names a request that could not be built or serialised; no `DialError`, `HostError` or `BadArgs` text carries a URL, query, header value or third-party error text (header values must be visible ASCII); `WsConn::send(Frame)` by value, `response_headers() -> &[..]`, `subprotocol() -> Option<&str>`; `dialer::request_authority` is the one `host:port` derivation.
- **Call 45, shared check pieces and test helpers (quality Q4).** `src/checks/common.rs` (`pub(crate)`: `stop_reason`, `inconclusive`, `connect_error`, `clean`, `first_data_frame`) is owned by the fix round and used by all eight checks; `testing::{host_for, point_and_host_for, handshake_header}` and `TestJob::{named, set_deadline, expire}` replace the per-file copies. The live-test harness (`Target`, control-origin helpers) lives in `tests/common/live.rs`, not in the library (call 12 amended: `testing.rs` stays the duplex harness).
- **Call 46, call 35 re-amended.** T10's seeds are on `main` (`395f9281`, merged in `310280f6`), so the live tests' target is the in-tree `aitm-testtarget-serve`; it stays a spawned process (isolation, real stdout contract) named by `AITM_TESTTARGET_BIN`, which Task 19 sets to `target/debug/aitm-testtarget-serve` after `cargo build -p aitm-testtarget`.
- Accepted without change (spec review Minors): the per-crate TLS/form/httparse/rcgen/rhai dependencies (T1a did not declare them; promotion to `[workspace.dependencies]` is a hand-off); the `wire.rs` re-pin landing at task 17; the named constants `REDACTED`/`EXAMPLE_CHARS` and the `#[doc(hidden)]` test accessors.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| whole branch | spec | Minor | `ws.*` handles outlive the call (30 s idle reap) while D8.3 says "closed when the call ends" | accepted (T4 session, 2026-11-01): the seam exposes no end-of-call signal; same class as the hook-signal gap (call 17); hand-off to T1b, recorded as call 39 |
| whole branch | spec | Minor | rustls/tokio-rustls/rustls-pki-types/webpki-roots/form_urlencoded/httparse/rcgen/rhai declared per-crate, not via `[workspace.dependencies]` | accepted (T4 session): T1a did not declare them and no lane track edits the root manifest; promotion is a hand-off for the next integration-shared edit |
| whole branch | spec | Minor | unrequested public API: `TcpTransport::tls_policy`, `html_escape_min`, `WsProbeHost::point`, `REDACTED`/`EXAMPLE_CHARS`, `testing.rs` accessors | fixed in a5a8a25e, bbc18c06: `tls_policy` and `html_escape_min` made `pub(crate)`; the rest accepted (test accessors on a `#[doc(hidden)]` harness; named constants for the plan's literals) |
| whole branch | spec | Minor | `wire.rs` re-pin landed in task 17's commit, not task 19's | accepted (T4 session): the content is the pre-authorised A23 edit; done early so the full gate could pass before review |
| whole branch | quality | Important | `ws.dial` panics on a URL whose byte 5/6 is inside a multi-byte char (`url[..5]`) | fixed in 5cf7783b: `get(..n)` + `eq_ignore_ascii_case`; test `ws_dial_rejects_a_non_ascii_scheme_without_panicking` |
| whole branch | quality | Important | lane point registry clones `HttpFlow`+`WsFlow` per point and is never pruned (process-lifetime leak) | fixed in a5a8a25e: registry holds `PointSpec` only, keyed per job with eviction past 16 jobs; `probe_host_for` re-reads both flows from `job.store()` and errors when gone |
| whole branch | quality | Important | `ws.*` driver executes commands serially; a long `ws.recv` starves other handles and misreports "ws driver unavailable" | fixed in 5cf7783b: `LocalSet` + `spawn_local` per command, per-handle async mutex; test overlapping recv/send on two handles |
| whole branch | quality | Minor | eight copies of stop/inconclusive/first-data-frame helpers and of test `host_for`; three authority derivations | fixed in a5a8a25e: `checks/common.rs`, `testing::host_for`, `dialer::request_authority` shared |
| whole branch | quality | Minor | deadline arm, `DialError::Timeout`, `CollectEnd::Deadline` untested; `TestJob` has no deadline knob | fixed in 844720e9: `TestJob::with_deadline`, deadline tests |
| whole branch | quality | Minor | `WsConn::send` copies the payload twice; owned returns from `response_headers`/`subprotocol` | fixed in 844720e9 |
| whole branch | quality | Minor | `build_request` errors surface as `DialError::Handshake` | fixed in 844720e9: `DialError::Request` |
| whole branch | quality | Minor | hygiene: stale mutate.rs note, wrong `clamp_timeout` doc, hard-coded "4", double `last_used` write | fixed in 5cf7783b, a5a8a25e |
| whole branch | quality | Minor | live tests never drain the child's stdout after `ready`; no ready timeout; helpers duplicated | fixed in a5a8a25e: drain thread, bounded ready loop, helpers in `testing.rs` |
| whole branch | security | Important | captured URL incl. query quoted into `DialError::Handshake` and every check's `detail` when the replay request cannot be built | fixed in 844720e9: context names scheme + authority only; test that a `?token=` path never reaches the error text |
| whole branch | security | Important | `TlsPolicy::AcceptAny` unconditional; the `Http1Sender` parity claim was false (it verifies by default, relaxes under `ssl_insecure`); verifier skipped signature verification | fixed in 844720e9: default `Verify` for lane and language, `build_with(TlsPolicy)` for the `ssl_insecure` wiring (hand-off: `wire.rs`/`main.rs` pass `cfg.ssl_insecure`), `AcceptAnyVerifier` verifies the handshake signature with the provider, docs corrected |
| whole branch | security | Important | dialer connects by name with no resolve-time SSRF/private-address check | fixed in 844720e9: dialer resolves with `lookup_host`, runs `aitm_core` `ssrf_check` per candidate against the guard's scope list, connects the transport to the validated `SocketAddr` |
| whole branch | security | Important | `ws.dial` panics on a non-ASCII URL prefix (same as quality Important 1) | fixed in 5cf7783b |
| whole branch | security | Important | received-frame volume unbounded per collect and for a script handle's life | fixed in 844720e9, 5cf7783b: per-collect byte and frame ceiling -> `CollectEnd::Limit`; the language drains `recorded` after each `recv` |
| whole branch | security | Minor | `ws.dial` echoes the script URL (userinfo, query) into `BadArgs` | fixed in 5cf7783b: scheme + authority only |
| whole branch | security | Minor | `InsertionPoint.url` carries the captured query string | fixed in a5a8a25e: query stripped from `url` |
| whole branch | security | Minor | guard concurrency permit taken before the up-to-deadline wait for a dialer slot | fixed in 844720e9: slot first, then guard |
| whole branch | tester | Important | D8.3 "a hook cannot call ws.*" not enforced (no run-kind signal in the seam) | accepted (T4 session, coordinator decision 3): T1b exposes the run kind; `WsSeamGuard::permit` has the arm; hand-off recorded |
| whole branch | tester | Important | `profile.ws.max_frame_bytes` bounds incoming frames only; an outgoing frame of any length can be sent | fixed in 844720e9: `WsConn::send` refuses a frame longer than the dial limit; test |
| whole branch | tester | Minor | two verdict-table deviations from D8.3 text (encoded reflection Clean; no-subprotocol upgrade Clean) recorded in the plan, not the spec | accepted (T4 session): plan calls 33/36 are the record; spec amendment listed in the hand-off |
| whole branch | tester | Minor | one justified `expect` in `transport.rs` on a static provider capability | accepted (T4 session): mirrors `ClientConfig::builder()`; no input reaches it |
| whole branch | tester | Minor | sweeps do not model the scheduler's `kinds` filter | accepted (T4 session): D4 is the engine's; the wider sweep strengthens the redaction grep |
| whole branch | tester | Minor | held flows carry the replayed cookie | accepted (call 38), countersigned by the security review ("by design, D5") |
| whole branch | tester | Info | acceptance via path B (real target binary), not the T10 cells | recorded in the PR and Shipped; path A pending T1b on main |
| fix range | quality (re-review) | Minor | module doc still says commands travel over `std::sync::mpsc` | fixed in bbc18c06 |
| fix range | quality (re-review) | Minor | `testing::live` (process spawner) compiled into the shipped library | fixed in bbc18c06: moved to `tests/common/live.rs` |
| fix range | quality (re-review) | Minor | blocking `control_json` inside the async lane proof; two HTTP clients for one origin | fixed in bbc18c06: one async helper |
| fix range | quality (re-review) | Minor | `common::connect_error`/`first_data_frame` push fix-ups back into checks | fixed in bbc18c06: `connect_error(e, probe_flows)`, `first_data_frame(&ProbeResponse)` |
| fix range | quality (re-review) | Minor | `host_for`/`point_and_host_for` transport parameter mismatch forces casts and `.1` | fixed in bbc18c06: both take `Arc<dyn WsTransport>` |
| fix range | quality (re-review) | Minor | same-handle contention reported as "ws driver unavailable" | fixed in bbc18c06: `try_lock` -> "websocket handle N is busy" |
| fix range | quality (re-review) | Minor | driver start failures logged at debug, never retried | fixed in bbc18c06: `warn!` + sender cleared so the next dial retries |
| fix range | quality (re-review) | Minor | concurrency test discards thread A's result | fixed in bbc18c06 |
| fix range | quality (re-review) | Minor | hygiene: catalog strings hard-code 4/30000, `host_err` unused in one test, fixture wrappers, `send` Close arm tail, `TestJob::named` duplication | fixed in bbc18c06 |
| fix range | security (re-review) | Important | S9: a non-ASCII captured header value reaches `DialError::Handshake` (and every `detail`) through tungstenite's `generate_request` error text | fixed in bbc18c06: third-party error text never passed through (fixed sentence / `DialError::Request` naming the header); both `build_request`s require visible-ASCII values; fixture gains a non-ASCII cookie so the redaction sweep covers it |
| fix range | security (re-review) | Minor | `testing::live` process-spawning harness compiled into the library | fixed in bbc18c06: moved to `tests/common/live.rs` (same as quality N2) |
| fix range | quality (re-review 2, `a5a8a25e..bbc18c06`) | Important | the N7 fix hands the driver thread a strong `Arc` to the slot holding its own sender, so the command channel never disconnects and the driver outlives the language | fixed in FIX3SHA: the thread holds a `Weak`; test `the_driver_ends_when_the_language_drops` |
| fix range | quality (re-review 2) | Minor | visible-ASCII header rule written twice (dialer and language) | fixed in FIX3SHA: `dialer::visible_ascii_header_value` shared |
| fix range | quality (re-review 2) | Minor | `auth_bypass` files the baseline flow under `probe_flows` on a connect error | fixed in FIX3SHA: `baseline_flow` via struct update, `probe_flows` empty |
| fix range | quality (re-review 2) | Minor | `live_language.rs` blocks the tokio test runtime on `engine.eval` | fixed in FIX3SHA: evals under `spawn_blocking` |
| fix range | quality (re-review 2) | Minor | `WsConn::unrecorded` is test-only while its counter is shipped | fixed in FIX3SHA: `pub(crate)` accessor, host logs the truncation count at debug |
| fix range | security (re-review 2, `a5a8a25e..bbc18c06`) | - | PASS: S9 and the Minor fixed; no new finding (observation for follow-ups: tungstenite's own `trace!` logs the full upgrade head under its target) | recorded |
| fix range | spec (re-review, `80fd0816..a5a8a25e`) | Important | plan not amended for the fix round (TLS default, transport/registry/driver signatures, `checks/common.rs` ownership, call 35 premise) | fixed in b3caedf8 (calls 39-46, ownership rows) |
| fix range | spec (re-review) | Minor | `with_ssrf`/`take_recorded`/`unrecorded`/`request_authority` public; `testing::live` in the library | fixed in bbc18c06: `request_authority`, `take_recorded`, `unrecorded` `pub(crate)`; live harness in `tests/common/live.rs`; `with_ssrf`, `build_with` kept `pub` as hand-off seams |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

- Merged: (SHA, PR)
- Live proof: (path A or B; the observer outputs quoted: target handshake log lines showing the regenerated `Sec-WebSocket-Key` and the kept `Cookie`, the connection-concurrency count, the one oversize frame and its byte length, the issue list on V and the empty list on P, the empty cookie-value grep, the `ws.*` script round-trip and the `OutOfScope` refusal)
- Hand-off to T1b/coordinator: `production_languages()` + `rhai.api.json` (call 13); hook-signal gap (call 17); per-verdict severity (call 20); `ws:` PoC step (call 19); shared payload vocabulary with T3 (call 1).
- Cut / deferred:
