# Protocol-general `CaptureIngress` — stream (TCP) dispatch path (prerequisite) implementation plan

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md` (L4OPS-AC17, the protocol-general capture seam). Unblocks `docs/superpowers/plans/2026-10-29-aitmproxy-macos-network-extension-plan.md` Band B (Tasks 2–9).
**Branch / worktree:** `feat/capture-ingress`

## Overview

This is a **standalone prerequisite**: it completes the protocol-general
`CaptureIngress` so that a captured **TCP/stream** flow is dispatched to the
registered `ProtocolModule`s behind the authoritative original destination, with
out-of-scope refusal and in-scope-unclaimed verbatim passthrough. The L4/UDP half
of the ingress already exists and is guarded by the real `L4Guard`; this plan adds
the stream half it is missing, plus a thin UDP flow adapter for symmetry, and
wires the result into the live proxy. It is pure Rust and provable by
sandbox-TDD against synthesized flows and mocks of existing public `aitm-core`
traits — no network bind, no signing, no Apple portal.

**What exists on `origin/main` (confirmed by reading the source).**

- `crates/aitm/src/ingress.rs` **already defines** `trait CaptureIngress { fn
  accept(&self, unit: CapturedUnit) -> IngressOutcome }`, `enum CapturedUnit`
  (`#[non_exhaustive]`, only an `L4 { target: L4Target, bytes: Vec<u8> }`
  variant), `enum IngressOutcome { Captured, Refused, Unhandled }`, and `struct
  CoreIngress { l4: Option<L4Dispatch> }` with `empty()` / `with_l4(guard,
  store)`. The L4 path routes through the real `aitm_proto_l4::guard::L4Guard`.
  **The brief's premise that `CaptureIngress` "does not exist anywhere" is
  outdated — it exists, L4-only.** (Flagged assumption A1.)
- `crates/aitm/src/wire.rs` builds `CoreIngress::with_l4(module.guard(),
  module.store())` only when `features.l4.enabled`, and stores it in
  `Assembled.l4_ingress`.
- `aitm-core` has `ProtocolModule`, `NextLayerHint { dst, is_tls,
  client_hello_sni, alpn, first_bytes, from_upgrade }`, `ModuleCtx::new(store,
  sink, connector)` + `.with_modules(..)` + `.with_hint(..)`, `EventSink`
  (impl'd by `Chain`), `UpstreamConnector`, `FlowStore`, `ScopeRateGuard`,
  `ByteStream`. `Proxy::accept_loop`/`handle_conn` do the only module dispatch
  today; they (gap 1) set `hint.dst = peer` (the accepted TCP peer, **not** the
  original destination) and (gap 2) **drop** unclaimed connections.
- `crates/aitm-proto-l4` depends on `aitm-core`. **Therefore `aitm-core` cannot
  reference `L4Guard`**, and the ingress cannot live in `aitm-core` without a
  dependency cycle. It must stay in `crates/aitm`, which is the only crate that
  sees **both** `aitm-core` (modules/hint/ctx) and `aitm-proto-l4` (`L4Guard`).
  (Flagged assumption A2 — contradicts the brief's suggested
  `crates/aitm-core/src/ingress.rs` location.)

**Shape of the work.** The dispatch wiring a stream needs (the module list, the
event sink, and a guarded upstream connector) is built privately inside `Proxy`
and is not exposed today. Task 1 adds **additive, guard-preserving** accessors to
`aitm-core` (no bypass: the connector still SSRF/scope-checks, the chain still
runs plugins) plus a read-only `in_scope` scope predicate. Task 2 adds the stream
dispatch to the ingress. Task 3 adds a symmetric UDP flow adapter over the
existing L4 path. Task 4 wires it into the live proxy.

**Order & independence.** Task 1 is independent (aitm-core only) and must land
first — Tasks 2–4 depend on its accessors. Tasks 2, 3, 4 all edit
`crates/aitm/src/ingress.rs` (2 and 3) or depend on them, so they are
**sequential**, in the order given (no two writers share a file).

## Flagged assumptions (confirm; see questions to Matt)

- **A1** `CaptureIngress` already exists (L4-only); this plan **extends** it, not
  creates it.
- **A2** It stays in `crates/aitm/src/ingress.rs` (not `aitm-core`), forced by the
  `aitm-core` ← `aitm-proto-l4` dependency direction. The brief's
  `crates/aitm-core/src/ingress.rs` is not viable.
- **A3** Captured TCP flows are scope-gated by the core `ScopeRateGuard` (the L7
  guard), with authority = `sni` if present else `dst.ip()`. (UDP stays on
  `L4Guard`, unchanged.)
- **A4** In-scope-unclaimed TCP passthrough dials via the **SSRF-guarded**
  connector (`ssrf = true`), so a private/loopback upstream still needs explicit
  scope.
- **A5** The macOS Band B free function becomes `dispatch_captured_tcp(ingress:
  &CoreIngress, flow: CapturedTcpFlow)` (concrete `&CoreIngress`, async; the plain
  object-safe `CaptureIngress` trait cannot carry the async, stream-wired method
  without a new `async-trait` dep). `CapturedTcpFlow.source_app: SourceAppId`
  (macOS) maps onto `peer_identity: Option<String>` here; the macOS backend
  converts. `CapturedTcpFlow` carries `first_bytes: Vec<u8>` (the backend's
  observed initial bytes; its `stream` must still yield them, mirroring today's
  `TcpStream::peek`).

## Tasks

### Task 1: expose stream-dispatch wiring and a scope predicate from `aitm-core`

- **Satisfies:** L4OPS-AC17 (foundation). Unblocks macOS-NE Band B (Task 2).
- **Depends on:** none (cut from current `origin/main`).
- **Independent:** yes (only `aitm-core`).
- **Files:**
  - `crates/aitm-core/src/proxy.rs` (modify — three accessors + their tests)
  - `crates/aitm-core/src/guard.rs` (modify — one trait method + its test)
  - `crates/aitm-core/src/lib.rs` (no new export needed — all returned types are
    already re-exported; confirm `ProtocolModule`, `UpstreamConnector`,
    `EventSink`, `ScopeRateGuard` remain exported)
- **Change:**
  - In `impl Proxy`, add:
    - `pub fn modules(&self) -> std::sync::Arc<[std::sync::Arc<dyn ProtocolModule>]>`
      → `self.inner.modules.clone()`.
    - `pub fn event_sink(&self) -> std::sync::Arc<dyn EventSink>` →
      `self.inner.chain.clone()` (coerced; `Chain: EventSink`).
    - `pub fn upstream_connector(&self, ssrf: bool) -> std::sync::Arc<dyn UpstreamConnector>`
      — constructs exactly what `handle_conn` builds: `SsrfConnector { policy:
      self.inner.browser_ssrf.clone(), guard: self.inner.guard.clone() }` when
      `ssrf`, else `PassiveConnector`. (No behaviour change to the acceptor; this
      only shares the existing construction.)
  - In `pub trait ScopeRateGuard`, add
    `fn in_scope(&self, host: &str) -> bool { false }` (default deny-by-default so
    every existing impl keeps compiling), and implement it on `StdGuard` by
    promoting the existing private `StdGuard::in_scope` to satisfy the trait
    method (same normalized host matching — no new matching logic).
- **Test:** in `crates/aitm-core/src/proxy.rs` `#[cfg(test)]` and
  `crates/aitm-core/src/guard.rs` `#[cfg(test)]`:
  - `proxy_exposes_stream_dispatch_wiring`: build a `Proxy` via `Proxy::builder()`
    with **one** registered test `ProtocolModule`; assert
    `proxy.modules().len() == 1`; assert `proxy.event_sink()` and
    `proxy.upstream_connector(true)` each return a value (compiles + non-panicking
    construction).
  - `upstream_connector_true_is_ssrf_guarded`: with an empty scope and default
    config, `proxy.upstream_connector(true).connect("10.1.2.3", "10.1.2.3:80".parse().unwrap()).await`
    returns **`Err`** (a private, out-of-scope target is refused before any dial).
  - `std_guard_in_scope_predicate`: a `StdGuard` with scope entry `"example.com"`
    returns `in_scope("example.com") == true` and `in_scope("evil.com") == false`.
- **Done when:** the three tests pass and the full gate passes
  (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`).

### Task 2: captured TCP/stream dispatch on the ingress (authoritative dst, refuse, passthrough)

- **Satisfies:** L4OPS-AC17 (stream half). Unblocks macOS-NE Band B Task 2
  (NE-AC1) and Task 4 (NE-AC3, TCP side).
- **Depends on:** Task 1.
- **Independent:** no (edits `crates/aitm/src/ingress.rs`; shared with Task 3).
- **Files:**
  - `crates/aitm/src/ingress.rs` (modify — add stream types, wiring, and method;
    add tests to its `#[cfg(test)]` module)
  - `crates/aitm/src/lib.rs` (modify only if `ingress` is not already `pub mod`;
    confirm the new public types are reachable — one line at most)
- **Change (exact):**
  - New public types in `ingress.rs`:
    ```
    pub struct CapturedTcpFlow {
        pub stream: aitm_core::ByteStream,
        pub dst: std::net::SocketAddr,       // authoritative original remote endpoint
        pub sni: Option<String>,             // remoteHostname / ClientHello SNI, if known
        pub first_bytes: Vec<u8>,            // backend's observed initial bytes (stream still yields them)
        pub peer_identity: Option<String>,   // source-app signing identity, if known
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StreamOutcome {
        Dispatched,     // a ProtocolModule claimed and was spawned
        PassedThrough,  // in-scope but unclaimed: original dst dialed, bytes tunneled verbatim
        Refused,        // out of scope: refused before any module / connector work
        Unhandled,      // stream dispatch not wired in this build
    }
    ```
  - Extend `CoreIngress` with an optional stream half:
    ```
    struct StreamDispatch {
        modules: std::sync::Arc<[std::sync::Arc<dyn aitm_core::ProtocolModule>]>,
        store: std::sync::Arc<dyn aitm_core::FlowStore>,
        sink: std::sync::Arc<dyn aitm_core::EventSink>,
        connector: std::sync::Arc<dyn aitm_core::UpstreamConnector>,
        guard: std::sync::Arc<dyn aitm_core::ScopeRateGuard>,
    }
    ```
    and `CoreIngress { l4: Option<L4Dispatch>, stream: Option<StreamDispatch> }`
    (update `empty()` / `with_l4` to set `stream: None`).
  - `pub fn CoreIngress::with_stream(mut self, modules, store, sink, connector,
    guard) -> Self` (builder-style; argument types as the `StreamDispatch`
    fields).
  - `pub async fn CoreIngress::dispatch_tcp(&self, flow: CapturedTcpFlow) -> StreamOutcome`:
    1. If `self.stream` is `None` → `StreamOutcome::Unhandled`.
    2. `authority = flow.sni.clone().unwrap_or_else(|| flow.dst.ip().to_string())`.
       If `!sd.guard.in_scope(&authority)` → `StreamOutcome::Refused` (before any
       module match, spawn, or connector dial).
    3. Build `NextLayerHint { dst: flow.dst, is_tls: flow.first_bytes.first() ==
       Some(&0x16), client_hello_sni: flow.sni.clone(), alpn: Vec::new(),
       first_bytes: flow.first_bytes.clone(), from_upgrade: false }` — `dst` is the
       **authoritative original destination** (gap 1 fix).
    4. `match sd.modules.iter().find(|m| m.matches(&hint)).cloned()`:
       - `Some(module)` → `ctx = ModuleCtx::new(sd.store.clone(), sd.sink.clone(),
         sd.connector.clone()).with_modules(sd.modules.clone()).with_hint(hint)`;
         `let _ = module.spawn(flow.stream, ctx).await;` → `StreamOutcome::Dispatched`.
       - `None` → **passthrough** (gap 2 fix): `let mut up =
         sd.connector.connect(&authority, flow.dst).await` — on `Ok(up)` run
         `tokio::io::copy_bidirectional(&mut *flow.stream, &mut *up).await` (ignore
         the byte-count result) → `StreamOutcome::PassedThrough`; on `Err`, log and
         still return `StreamOutcome::PassedThrough` (the flow was taken, not
         silently dropped).
  - `pub async fn dispatch_captured_tcp(ingress: &CoreIngress, flow: CapturedTcpFlow) -> StreamOutcome`
    (free fn delegating to `ingress.dispatch_tcp(flow)`), the entry macOS Band B
    Task 2 calls.
- **Test (in `ingress.rs` `#[cfg(test)]`, using a recording stub `ProtocolModule`,
  a mock `UpstreamConnector` over `tokio::io::duplex`, and a mock
  `ScopeRateGuard`):**
  - `tcp_flow_dispatches_to_http_with_original_dst`: stub module `matches()==true`,
    recording the `hint` it is spawned with; guard `in_scope==true`; flow `dst =
    "93.184.216.34:443".parse()`, `sni = Some("example.com")`, `first_bytes =
    vec![0x16, 0x03, 0x01]`. Assert `dispatch_tcp(flow).await == StreamOutcome::Dispatched`,
    the recorded `hint.dst.to_string() == "93.184.216.34:443"` (and **not**
    `"127.0.0.1:50000"`), and `hint.client_hello_sni.as_deref() == Some("example.com")`.
  - `out_of_scope_tcp_refused_before_any_work`: guard `in_scope==false`; a counting
    stub module and counting mock connector. Assert `dispatch_tcp(flow).await ==
    StreamOutcome::Refused`, stub `spawn` call-count `== 0`, and connector dial
    count `== 0`.
  - `in_scope_unclaimed_tcp_passes_through_not_dropped`: guard `in_scope==true`;
    stub module `matches()==false`; mock connector returns the near end of a
    `tokio::io::duplex`, the test holds the far end. Write `b"hello"` to the client
    side of `flow.stream` (a second duplex) and close it; assert the far upstream
    end reads `b"hello"`, `dispatch_tcp(flow).await == StreamOutcome::PassedThrough`,
    and connector dial count `== 1`.
- **Done when:** the three tests pass and the full gate passes.

### Task 3: captured UDP flow adapter over the existing L4 guard path

- **Satisfies:** L4OPS-AC17 (symmetry). Aligns with macOS-NE Band B Task 3
  (NE-AC2) — which may use this or its own direct `L4Guard` call.
- **Depends on:** Task 2 (same file; lands after it).
- **Independent:** no (edits `crates/aitm/src/ingress.rs`).
- **Files:** `crates/aitm/src/ingress.rs` (modify — add UDP type + method + tests).
- **Change (exact):**
  - ```
    pub struct CapturedUdpFlow {
        pub target: aitm_proto_l4::types::L4Target, // interface/direction/dst/port/proto
        pub datagrams: Vec<Vec<u8>>,
        pub peer_identity: Option<String>,
    }
    ```
  - `pub fn CoreIngress::dispatch_udp(&self, flow: CapturedUdpFlow) -> IngressOutcome`:
    if `self.l4` is `None` → `IngressOutcome::Unhandled`; else iterate
    `flow.datagrams`, calling the **existing** L4 path
    `self.accept(CapturedUnit::L4 { target: flow.target.clone(), bytes: datagram })`
    per datagram (reuses the real `L4Guard::check(Capture, target)` — **no new
    guard**); return `IngressOutcome::Captured` if ≥1 datagram was captured, else
    `IngressOutcome::Refused`.
- **Test (`udp_in_scope_admitted_out_of_scope_refused`, using the real `L4Guard` +
  `InMemoryL4FlowStore` as the existing `ingress_dispatches_by_protocol` test
  already does):** seed an `L4Config` with a `Capture` scope entry for `127.0.0.1`
  on interface `lo0`, outbound. An in-scope `CapturedUdpFlow` (target dst
  `127.0.0.1:9`, one datagram) → `dispatch_udp(..) == IngressOutcome::Captured`
  and `store.list().len() == 1`. An out-of-scope flow (target dst `127.0.0.2:9`)
  → `dispatch_udp(..) == IngressOutcome::Refused` and `store.list().len()` is
  **unchanged** (the out-of-scope datagram reached no store).
- **Done when:** the test passes and the full gate passes.

### Task 4: wire the stream ingress into the live proxy

- **Satisfies:** L4OPS-AC17 (wiring). Makes the live `Assembled` ingress capable of
  TCP dispatch, which macOS-NE Band B feeds.
- **Depends on:** Task 1, Task 2 (and Task 3 if UDP is exercised).
- **Independent:** no (edits `crates/aitm/src/wire.rs`).
- **Files:** `crates/aitm/src/wire.rs` (modify — build the ingress with the stream
  half for every build, add `.with_l4` only when L4 is enabled; one test).
- **Change (exact):** after `let proxy = builder.build()?;`, build the ingress
  unconditionally as
  `CoreIngress::empty().with_stream(proxy.modules(), proxy.store(),
  proxy.event_sink(), proxy.upstream_connector(true), proxy.guard())`, then, when
  `features.l4.enabled`, also thread the L4 guard/store (restructure the current
  `l4_ingress = None; if features.l4.enabled { … with_l4 … }` so the stream half is
  always present and the L4 half is added when enabled). Keep the
  `Assembled.l4_ingress` field (now carrying both halves); a rename is optional and
  out of scope. If `LateGuard` (in `wire.rs`) does not compile against the new
  `ScopeRateGuard::in_scope` default, forward `in_scope` to its bound guard (it is
  not on the ingress path, so the default is acceptable; forward only if needed).
- **Test (`assembled_ingress_dispatches_or_refuses_tcp`):** call the existing
  `assemble(..)` path (reuse the crate's current test setup for `Assembled`) with a
  config whose scope is **empty**; take `assembled.l4_ingress.unwrap()` and assert
  `dispatch_tcp(flow).await == StreamOutcome::Refused` for a synthesized flow to
  `"93.184.216.34:443"` (empty scope ⇒ out of scope ⇒ refused, no network). If a
  full `assemble(..)` is impractical to construct in a unit test, assert instead
  that `proxy.modules().len() > 0` for the assembled proxy and that a
  `CoreIngress::with_stream(..)` built from its accessors refuses the same flow.
- **Done when:** the test passes and the full gate passes.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
