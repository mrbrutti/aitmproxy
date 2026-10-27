# aitmproxy Milestone 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** approved (2026-10-27 by Matt)
**Spec:** `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md` (platform + M1, AC1–AC20); `docs/superpowers/specs/2026-10-27-aitmproxy-plugin-system-design.md` (AC-P1–AC-P5); `docs/superpowers/specs/2026-10-27-aitmproxy-poc-language-design.md` (AC-L1–AC-L7)
**Branch / worktree:** `feat/aitmproxy-m1`

**Goal:** Ship an HTTP/S + WebSocket intercepting proxy platform, driven over MCP, that captures traffic, reproduces a reflected XSS as a parameterized self-contained YAML PoC, and screenshots the vuln triggering in an embedded browser — all M1 acceptance criteria green.

**Architecture:** A Cargo workspace of small crates in three rings: a thin protocol-agnostic core (`aitm-core`: flow model, typed event bus + ordered plugin chain, command registry, flow store, scope/rate guard, proxy acceptor), modules/features behind seams (`aitm-plugin` protocol seam; `aitm-proto-http`/`aitm-proto-ws` protocols; `aitm-plugins` first-party feature plugins; `aitm-browser`; `aitm-poc`), and frontends over one command bus (`aitm-mcp`, `aitm-cli`), wired by the `aitm` binary from config. Everything above raw I/O is a plugin; every frontend is a client of one command surface.

**Tech Stack:** Rust (tokio, hyper 1.x, rustls/tokio-rustls, rcgen, moka, x509-parser, tokio-tungstenite, chromiumoxide, serde + serde_yaml, regex, uuid, anyhow). Pure-Rust TLS (rustls) is the default.

## Architect's structuring calls (reconciliations within the specs)

These resolve seams the specs left to the builder; they do not change any declared signature. Flagged in the Questions section for Matt's FYI. **Accepted by Matt (2026-10-27):** HTTP/1.1-first with HTTP/2 deferred, the `aitm-plugins` crate, and the test-only target fixture.

1. **Trait placement (authoritative per plugin-system spec worked examples; refined by call #4).** `Plugin`, `FlowCtx`, `Registry`, `Command`, `ParamSchema`, `Event`, `Verdict`, `Flow` and the flow/value/host types live in **`aitm-core`** (plugin-system Example 1 imports them from `aitm_core`). The protocol seam — `ProtocolModule`, `NextLayerHint`, `ModuleCtx`, `ByteStream`, `AsyncReadWrite` — is **defined in `aitm-core` and re-exported by `aitm-plugin`** (`pub use aitm_core::{...}`), because `aitm-core`'s public surface names these traits (`ProxyBuilder::register_module`, `ModuleCtx`) and cannot depend on a crate that depends on it. `aitm-plugin` depends on `aitm-core` and remains the public authoring surface, so Example 2's `use aitm_plugin::ProtocolModule` import is unchanged (it resolves through the re-export). The platform-spec crate-table summary ("aitm-plugin: Plugin, ProtocolModule…") is a loose summary; the code imports are authoritative. See call #4 for the full resolution.
2. **First-party feature plugins get their own crate `aitm-plugins`** (capture, replay, intercept, mutate, scope, rate-limit), so `aitm-core` hosts no feature code and AC-P3 (drop a plugin, no core edit) is true by construction. Browser commands live in `aitm-browser`; PoC commands in `aitm-poc`. Each crate registers its own `Command`s.
3. **M1 HTTP is HTTP/1.1 over cleartext and over TLS** (one HTTPS path, satisfying AC1), with the `HttpVersion::H2` variant and sans-IO seam present but full HTTP/2 multiplexing deferred — permitted by the platform spec's "Left to the builder" and "at least one HTTPS path." See Questions.
4. **Seam-trait placement — defined in `aitm-core`, protocol seam re-exported by `aitm-plugin`** (resolved during implementation, approved by orchestrator 2026-10-27). A Coder hit a real crate cycle: `aitm-core`'s public surface names the seam traits (`ProxyBuilder::register_module(Arc<dyn ProtocolModule>)`, `CommandHost`/`ModuleCtx`, `CommandHost::browser()->Option<&dyn BrowserDriver>`, `Config.browser: BrowserConfig`), and `aitm-core` cannot depend on crates that depend on it — cargo rejects the cycle. Resolution, refining call #1: **(a)** the **protocol seam** (`ProtocolModule`, `NextLayerHint`, `ModuleCtx`, `ByteStream`, `AsyncReadWrite`) is **defined in `aitm-core`** and **re-exported by `aitm-plugin`** (`pub use aitm_core::{...}`), so both documented import paths still work — `aitm_core::Proxy::builder().register_module(...)` (platform Example 1) and `use aitm_plugin::ProtocolModule` (plugin-system Example 2, proto crates); `aitm-plugin` stays the public authoring surface via the re-export. **(b)** The **browser seam** (`BrowserDriver`, `ClickTarget`, `NavOutcome`, `BrowserConfig`, `SsrfPolicy`) is **defined in `aitm-core`**; the concrete chromiumoxide impl and `SsrfGuard`/`ResolvedTarget` stay in `aitm-browser`. **Governing rule:** any trait/type named by the `aitm-core` surface (`CommandHost`, `ModuleCtx`, `ProxyBuilder`, `Config`) is defined in `aitm-core`; concrete impls live in their own crates; `aitm-plugin` re-exports the protocol seam. A reconciliation within the design: **no behavior change, no scope change, no signature change** — all documented import paths still work via the re-export. Reflected in Tasks 7, 8, 18, 19 and platform-spec Architect's-call #17.
5. **Frontend service handles via an additive `with_services(...)` builder** (resolved during implementation, approved by orchestrator 2026-10-27). A Coder building the frontends hit a real gap: `McpServer::new(Arc<Registry>, McpTransport)` and `Cli::new(Arc<Registry>)` receive only a `Registry`, but `tools/call` / `dispatch` must build a `CommandHost` to call `Command::invoke(args, &CommandHost)`, and a `CommandHost` needs the flow store, proxy client, scope/rate guard, and optional browser — none of which a `Registry` holds. Resolution (additive, declared `new` signatures unchanged): both `McpServer` and `Cli` gain `with_services(self, store: Arc<dyn FlowStore>, client: Arc<dyn ProxyClient>, guard: Arc<dyn ScopeRateGuard>, browser: Option<Arc<dyn BrowserDriver>>) -> Self`, fed from `Proxy::store()/client()/guard()/browser()`; the frontend builds a `CommandHost` per invoke, and an invoke without `with_services` returns a clear error. `tools/list`/schema derivation never need services. No behavior, scope, or signature change to `new`. Reflected in Tasks 25, 26, 28 and platform-spec Architect's-call #18.

## Global Constraints

Every task's requirements implicitly include these (verbatim from the specs):

- **Gate (AC19):** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` must pass before any review. A task is not done until its tests and the gate are green.
- **`unsafe`** requires a `// SAFETY:` comment stating the invariant and a signed-off Security-reviewer entry. Prefer none.
- **TDD:** no production code without a failing test first; the Coder's report includes both the failing and passing run outputs.
- **Declared signatures are authoritative.** Types/traits/fields/method signatures declared in the specs are copied exactly; bodies, internal fields marked `/* … */`, error payloads, and file layout are the builder's.
- **Public trait surface** (`Plugin`, `ProtocolModule`, `Command`, `ParamSchema`, `Event`, `FlowCtx`, `FlowStore`, `CommandHost`) is a semver-stable external-authoring contract; new `Event` variants are `#[non_exhaustive]`.
- **Performance posture:** async; bodies streamed by default (`Body::Streamed`), not buffered; allocation-light sans-IO; backpressure on upstream. Buffer a body only via explicit materialize-on-demand.
- **Security posture (built in from the start, not retrofitted):** deny-by-default scope; every active action (`flow.replay`, `request.send`, `browser.navigate`, `poc.run`) passes `ScopeRateGuard::check_active`; browser navigations also pass the SSRF guard (block private + loopback unless explicitly in scope); CA private key file mode `0o600`; MCP over stdio or loopback-only (127.0.0.1) TCP with a required token.
- **Platform:** macOS + Linux. No L4/transparent capture in M1 (affects only browser launch flags and path/permission handling).
- **No remediation/fix prose** anywhere in artifacts (`PocInfo` carries identification metadata only).
- **Dependencies** come from the stack in `docs/research/03-rust-proxy-stack.md`; concrete versions are the builder's within that stack.

## Review Focus

Input classes and failure modes the specs imply but that no single task's happy-path tests fully exercise; each has a pinned test in the owning task. Most likely to bite first:

1. **Large / chunked / streamed bodies (memory).** A multi-megabyte or `Transfer-Encoding: chunked` body must stream without full buffering; the proxy must not grow memory per body. Pinned in Task 10 (sans-IO chunked decode) and Task 30 (soak with large bodies, memory plateau).
2. **Header case-insensitivity and duplicate/order preservation.** `HeaderMap` must match `Content-Type`/`content-type` and preserve duplicate `Set-Cookie` order. Pinned in Task 2.
3. **SSRF guard bypass via DNS / IP-literal / scope-entry forms.** A hostname resolving to a private IP, a raw `127.0.0.1`, and `host:port` scope forms must all be classified correctly. Pinned in Task 6 (address classification) and Task 19 (browser guard: blocked then permitted after exact `scope.add`).
4. **Malformed / incomplete PoC documents.** Missing `id`, unknown step type, or bad enum value must be rejected with a clear error, not a silent partial parse. Pinned in Task 20 (AC-L7).
5. **Concurrency / rate-limit boundary under burst.** A burst above `per_host_rps`/`max_concurrency` must throttle or reject per policy and release permits on drop (RAII). Pinned in Task 6 (guard unit) and Task 17 (AC17 burst).

---

## Overview

Work proceeds in six phases. **Phase 0** (Tasks 1–6, mostly sequential on `aitm-core`) builds the workspace and core types every other crate consumes. **Phase 1** (Tasks 7–12) builds the plugin/protocol seam and the HTTP/WS protocols. **Phase 2** (Tasks 13–17) builds first-party feature plugins. **Phase 3** (Tasks 18–19) the browser. **Phase 4** (Tasks 20–24) the PoC engine. **Phase 5** (Tasks 25–26) the MCP and CLI frontends. **Phase 6** (Tasks 27–31) the test target, binary wiring, functional E2E, soak, and the exit gate.

**Parallelizable (disjoint files, after their dependencies land):**
- After Task 1: Task 9 (CertAuthority), Task 27 (test target) are independent of the core-type chain.
- After Tasks 2+4: Task 20 (PoC model/serde) can proceed in parallel with Phase 1.
- Phase 2 feature plugins (Tasks 13, 14, 15, 16, 17) touch disjoint files under `aitm-plugins/` and can fan out once Tasks 8 + 12 land.
- Tasks 25 (MCP) and 26 (CLI) are disjoint and parallel once the Registry + a few commands exist.
- Within Phase 4, Tasks 21 (templating) and 22 (DSL) are disjoint and parallel after Task 20.

Each task below marks **Independent:** with its parallel group.

## Tasks

### Task 1: Cargo workspace skeleton + gate

- **Satisfies:** AC19 (scaffold), foundation for all.
- **Depends on:** none. **Independent:** starts the tree.
- **Files:** Create `Cargo.toml` (workspace root), `rust-toolchain.toml`, `.gitignore`, and per-member `crates/<name>/Cargo.toml` + `crates/<name>/src/lib.rs` (empty) for: `aitm-core`, `aitm-plugin`, `aitm-proto-http`, `aitm-proto-ws`, `aitm-plugins`, `aitm-browser`, `aitm-poc`, `aitm-mcp`, `aitm-cli`; and `crates/aitm/src/main.rs` (binary). Create `crates/aitm-core/tests/smoke.rs`.
- **Change:** `[workspace]` with `members` for all ten crates and `resolver = "2"`. Dependency edges (declared in each member's `Cargo.toml`): `aitm-plugin → aitm-core`; `aitm-proto-http`/`aitm-proto-ws`/`aitm-plugins`/`aitm-browser`/`aitm-poc` → `aitm-core` (proto crates also → `aitm-plugin`; `aitm-poc` → `aitm-browser`); `aitm-mcp`/`aitm-cli` → `aitm-core`; `aitm` → all. No cycles; nothing depends on a frontend.
- **Test:** `smoke.rs::workspace_builds` asserts `aitm_core::VERSION` (a `pub const VERSION: &str = env!("CARGO_PKG_VERSION")`) is non-empty → equals the crate version string.
  - [ ] Write `smoke.rs::workspace_builds`.
  - [ ] Run `cargo test -p aitm-core` → FAIL (no `VERSION`).
  - [ ] Add `VERSION` const; create all members.
  - [ ] Run `cargo test` and `cargo fmt --check && cargo clippy --all-targets -- -D warnings` → PASS/clean.
  - [ ] Commit.
- **Done when:** the workspace builds, the smoke test passes, and the gate is clean.

### Task 2: Core flow model types

- **Satisfies:** foundation for AC1–AC6, AC-P1; Review Focus #2.
- **Depends on:** Task 1. **Independent:** no (blocks most of Phase 0/1).
- **Files:** Create `crates/aitm-core/src/flow.rs`, `crates/aitm-core/src/header.rs`, `crates/aitm-core/src/body.rs`; modify `crates/aitm-core/src/lib.rs` (re-export). Test: `crates/aitm-core/tests/flow_model.rs`.
- **Change:** Declare, exactly as in the platform spec "The core: flow, events, plugin chain": `FlowId`, `Flow` (`Http`/`WebSocket`), `HttpFlow`, `WsFlow`, `HttpRequest`, `HttpResponse`, `HttpVersion` (`Http11`, `H2`), `HeaderMap` (ordered, case-insensitive multimap), `Body` (`Empty`/`Bytes`/`Streamed`), `WsMessage`, `WsDir`, `WsOpcode`, `ConnInfo`, `FlowMeta`, `InterceptState`, `ResumeHandle`. `FlowId` UUID-backed (v4, builder's call). `HeaderMap` has at least `get`, `set`, `remove`, `has`, and an ordered iterator preserving insertion order and duplicates.
- **Test:**
  - `flow_model.rs::headermap_case_insensitive`: `set("Content-Type","text/html")`, then `get("content-type")` → `Some("text/html")`.
  - `flow_model.rs::headermap_preserves_duplicate_order`: two `Set-Cookie` sets, iteration yields them in insertion order → `["a=1","b=2"]`.
  - `flow_model.rs::httpflow_construct`: build an `HttpFlow` with `request.method == "GET"`, `response == None`; assert `intercept` is `InterceptState::Observed`.
  - Steps: write tests → run (FAIL, types missing) → implement → run (PASS) → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 3: Core events, verdicts, errors

- **Satisfies:** foundation for AC4, AC-P1.
- **Depends on:** Task 2. **Independent:** no.
- **Files:** Create `crates/aitm-core/src/event.rs`, `crates/aitm-core/src/error.rs`; modify `lib.rs`. Test: `crates/aitm-core/tests/event_types.rs`.
- **Change:** Declare `Event` (`#[non_exhaustive]`: `RequestHeaders`/`Request`/`ResponseHeaders`/`Response`/`WsStart`/`WsMessage{flow,index}`/`WsEnd`/`Error{flow,kind}`), `Verdict` (`Continue`/`Halt`), `FlowError` (`Tls`/`Upstream`/`Protocol`/`Timeout`/`Killed`/`Guard(GuardError)`), and `GuardError` (`OutOfScope`/`PrivateAddressBlocked`/`RateLimited{retry_after}`/`ConcurrencyExceeded`/`HostDisabled`) exactly as declared. Derive `Debug`; `GuardError`/`FlowError` impl `std::error::Error`.
- **Test:** `event_types.rs::guard_error_display` asserts `GuardError::OutOfScope("x".into()).to_string()` contains `"x"` and the word `scope`; `event_types.rs::event_variant` matches `Event::WsMessage{flow,index}` destructures `index == 3usize`.
  - [ ] test → FAIL → implement → PASS → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 4: Registry, Command, Params/Value, Plugin trait, FlowCtx

- **Satisfies:** foundation for AC4, AC7, AC8, AC-P1, AC-P2, AC-P4.
- **Depends on:** Tasks 2, 3. **Independent:** no (blocks Phase 2 + frontends).
- **Files:** Create `crates/aitm-core/src/registry.rs`, `crates/aitm-core/src/command.rs`, `crates/aitm-core/src/value.rs`, `crates/aitm-core/src/plugin.rs`, `crates/aitm-core/src/ctx.rs`; modify `lib.rs`. Test: `crates/aitm-core/tests/registry.rs`.
- **Change:** Declare, exactly as in platform spec "Command surface": `Registry` (`add_command`, `add_plugin`, `command(name)`, `commands()`), `Command` (`name`, `schema()->ParamSchema`, `invoke(Params,&CommandHost)->Result<Value>`), `ParamSchema`, `ParamDef`, `TypeDesc` (`Bool`/`Int`/`Float`/`Str`/`Bytes`/`FlowId`/`Array`/`Object`/`Any`), `Params` (name→`Value` map with typed getters), `Value` (`Null`/`Bool`/`Int`/`Float`/`Str`/`Bytes`/`Array`/`Object`), `CommandHost` (`store`/`client`/`browser`/`guard` accessors — accessor signatures only; concrete host built in Task 8). Declare `Plugin` (`name`, `load(&mut self,&mut Registry)` default, `on_event(&mut self,&Event,&mut FlowCtx)->Verdict` default `Continue`) and `FlowCtx` with method signatures `flow`/`flow_mut`/`set_response`/`intercept`/`resume`/`kill`/`backup`/`revert` (trait or struct facade; concrete impl in Task 8). **Also add the option API** (plugin-system "Options", mirrors `ParamDef`): `Registry::add_option(&mut self, name:&str, default:Value, description:&str)` and `Registry::option(&self, name:&str)->Option<Value>`.
- **Test:**
  - `registry.rs::register_and_lookup_command`: register a test `Command` named `demo.ping` returning `Value::Str("pong")`; `reg.command("demo.ping")` is `Some`; `invoke` on a stub host → `Value::Str("pong")`.
  - `registry.rs::option_roundtrip`: `add_option("tag", Value::Str("x"), "...")`; `option("tag")` → `Some(Value::Str("x"))`. (AC-P4 unit.)
  - `registry.rs::params_typed_get`: `Params` built from `{"id": Value::Str("u")}`; typed `get_str("id")` → `"u"`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 5: FlowStore trait + in-memory store

- **Satisfies:** foundation for AC1, AC6, AC9; `FlowStore::query` scanner seam.
- **Depends on:** Task 2. **Independent:** yes — parallel group **P-A** (disjoint from Tasks 3/4; needs only Task 2).
- **Files:** Create `crates/aitm-core/src/store.rs`; modify `lib.rs`. Test: `crates/aitm-core/tests/store.rs`.
- **Change:** Declare `FlowStore` (`insert`→`FlowId`, `get`, `update(id, &mut dyn FnMut(&mut Flow))`, `list`, `query(&FlowQuery)->Vec<FlowId>`), `FlowQuery` (`host`/`method`/`status`/`kind`/`is_replay`), `FlowKind` (`Http`/`WebSocket`). Provide `MemFlowStore` (default impl, `Send+Sync`, interior-mutable, e.g. `RwLock<IndexMap>`).
- **Test:**
  - `store.rs::insert_get_roundtrip`: insert an `HttpFlow` (method `GET`, path `/a`), `get(id)` returns a flow whose request path is `/a`.
  - `store.rs::query_by_host`: insert two flows (`authority` `a.test`, `b.test`); `query(FlowQuery{host:Some("a.test"),..})` returns exactly the first id (len == 1).
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 6: ScopeRateGuard + SSRF address classification + Config types

- **Satisfies:** AC12 (classification half), AC16, AC17; Review Focus #3, #5.
- **Depends on:** Task 3 (GuardError). **Independent:** yes — parallel group **P-A** (disjoint from Tasks 4/5; needs Tasks 2/3).
- **Files:** Create `crates/aitm-core/src/guard.rs`, `crates/aitm-core/src/config.rs`; modify `lib.rs`. Test: `crates/aitm-core/tests/guard.rs`.
- **Change:** Declare `ScopeRateGuard` (`check_active(host)->Result<ActionPermit,GuardError>`, `add_scope`, `list_scope`), `ActionPermit` (RAII slot; `Drop` releases concurrency), and a default `StdGuard` implementing deny-by-default scope matching (exact host, `host:port`, and wildcard), token-bucket `global_rps`/`per_host_rps`, `max_concurrency` cap, and `host_error_budget` disabling. Declare `Config`, `ScopeConfig`, `ScopeEntry`, `LimitConfig` (defaults: `global_rps=150`, `max_concurrency=25`), `BackoffConfig`, `CaConfig` (`key_mode=0o600`), `McpTransport` (`Stdio`/`LoopbackTcp{port,token}`), `McpConfig` exactly as declared. Add a helper `classify_host(host)->HostClass` (public) distinguishing private/loopback/public (IPv4+IPv6 ranges + `localhost`), used by the browser SSRF guard in Task 19.
- **Test:**
  - `guard.rs::deny_by_default`: fresh `StdGuard`, `check_active("ex.test")` → `Err(OutOfScope)`; after `add_scope(host "ex.test")`, `check_active("ex.test")` → `Ok(permit)`.
  - `guard.rs::classify_private`: `classify_host("127.0.0.1")` and `classify_host("10.0.0.5")` → private/loopback; `classify_host("93.184.216.34")` → public.
  - `guard.rs::concurrency_cap`: with `max_concurrency=1`, hold one permit, second `check_active` → `Err(ConcurrencyExceeded)`; drop first, next succeeds.
  - `guard.rs::rate_limit_burst`: with `per_host_rps=2`, a 5-call burst yields at least one `Err(RateLimited{..})`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 7: Protocol seam (`aitm-plugin`)

- **Satisfies:** AC-P5 (seam), foundation for AC1/AC2.
- **Depends on:** Tasks 2–5. **Independent:** no (blocks proto crates + Task 8).
- **Files:** Create/modify `crates/aitm-core/src/seam.rs` (the trait definitions), `crates/aitm-plugin/src/lib.rs` (re-exports), `crates/aitm-plugin/src/stream.rs`; modify `crates/aitm-core/src/lib.rs` (re-export). Test: `crates/aitm-plugin/tests/seam.rs`.
- **Change (per structuring call #4):** **Define in `aitm-core`**, exactly as platform spec "Protocol-module seam": `ProtocolModule` (`id`, `matches(&NextLayerHint)->bool`, `spawn(ByteStream,ModuleCtx)->BoxFuture<Result<()>>`), `NextLayerHint` (`dst`/`is_tls`/`client_hello_sni`/`alpn`/`first_bytes`/`from_upgrade`), `ModuleCtx` (`store()->&dyn FlowStore`, `emit(Event)->BoxFuture<Verdict>`, `connect_upstream(SocketAddr)->BoxFuture<Result<ByteStream>>`), `AsyncReadWrite` (marker trait: `AsyncRead+AsyncWrite+Send`), `ByteStream = Pin<Box<dyn AsyncReadWrite+Send>>`. These must be in `aitm-core` because its public surface names them (`ProxyBuilder::register_module`, `ModuleCtx`) and `aitm-core` cannot depend on `aitm-plugin`. **Then `aitm-plugin` re-exports the full set**: `pub use aitm_core::{ProtocolModule, NextLayerHint, ModuleCtx, ByteStream, AsyncReadWrite};` so the authoring import path `use aitm_plugin::ProtocolModule` (Example 2) is preserved. The seam test may import via either path.
- **Test:** `seam.rs::toy_module_claims_and_drives`: a `TestModule` whose `matches` returns true for `dst.port()==9999`; a minimal in-test driver constructs a `ModuleCtx` over a `MemFlowStore` + an in-memory duplex `ByteStream`, calls `matches` (→ true) then `spawn`, and the module inserts one flow + `emit`s `Event::Request(id)`; assert the store contains exactly 1 flow and the returned `Verdict` is `Continue`. (AC-P5: registration-only, no `aitm-core` edit.)
  - [ ] test → FAIL → implement → PASS → gate → commit.
- **Done when:** AC-P5 test passes and gate clean.

### Task 8: Proxy acceptor, ordered plugin chain, concrete FlowCtx, ProxyClient

- **Satisfies:** AC4, AC-P1, foundation for AC1/AC5/AC6; interception primitives.
- **Depends on:** Tasks 4, 5, 6, 7. **Independent:** no (central).
- **Files:** Create `crates/aitm-core/src/proxy.rs`, `crates/aitm-core/src/chain.rs`, `crates/aitm-core/src/client.rs`; modify `ctx.rs`, `lib.rs`. Test: `crates/aitm-core/tests/chain.rs`.
- **Change:** Declare `Proxy` (`builder()`, `async run(self, SocketAddr)->Result<()>`, `registry()->&Registry`), `ProxyBuilder` (`with_config`, `register_module(Arc<dyn ProtocolModule>)`, `register_plugin(Box<dyn Plugin>)`, `build()->Result<Proxy>`), `ProxyClient` (`send(HttpRequest)->BoxFuture<Result<HttpFlow>>`). **Per structuring call #4, `register_module` takes `Arc<dyn ProtocolModule>` where `ProtocolModule` is the `aitm-core`-defined trait (Task 7)** — this is why the trait must live in `aitm-core`, not `aitm-plugin`; the proto crates still name it via the `aitm-plugin` re-export and the two refer to the same trait. Implement the ordered chain dispatcher behind `ModuleCtx::emit`: dispatch an `Event` to plugins in registration order, stopping on `Verdict::Halt`; build the concrete `FlowCtx` giving each plugin `flow`/`flow_mut`/`set_response`/`intercept`/`resume`/`kill`/`backup`/`revert`. Implement interception as a pausable future (`ResumeHandle` oneshot-backed): `intercept()` parks, a later command fires the handle. Implement `ProxyClient::send` reissuing through the guard + pipeline, marking the resulting flow `is_replay=true`.
- **Test:**
  - `chain.rs::ordered_events_and_halt` (AC4 / AC-P1): register two recording plugins A then B; dispatch `Request`, `Response`, and a `WsMessage`; assert both record in order `["A","B"]`; make A return `Verdict::Halt` on `Request` and assert B does **not** see that `Request` (B's log for `Request` is empty) while both still see `Response`.
  - `chain.rs::intercept_resume_forwards`: a plugin calls `ctx.backup(); ctx.intercept()` on `Request`; assert flow state is `Intercepted`; fire resume via the handle; assert state becomes `Resumed`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC4/AC-P1 tests pass and gate clean.

### Task 9: CertAuthority (root gen, leaf mint + moka cache)

- **Satisfies:** AC3.
- **Depends on:** Task 1 (+ Task 3 error). **Independent:** yes — parallel group **P-B** (disjoint; can run alongside Phase 0 core work).
- **Files:** Create `crates/aitm-proto-http/src/ca.rs`; modify `crates/aitm-proto-http/src/lib.rs`. Test: `crates/aitm-proto-http/tests/ca.rs`.
- **Change:** Declare exactly as platform spec "aitm-proto-http — certificate authority": `CertAuthority` with `load_or_generate(dir:&Path, key_mode:u32)->Result<Self>`, `root_cert_pem(&self)->&str`, `leaf_for(&self, host:&str, sans:&[String])->Result<Arc<LeafCert>>`, `last_was_cache_hit(&self)->bool`; `LeafCert{cert_der,key_der}`. Use `rcgen` for generation and `moka` for the leaf cache; persist the root key with file mode `0o600`.
- **Test:** `ca.rs::mint_then_cache_hit` (AC3): in a temp dir, `load_or_generate` creates and persists a root (file exists, mode `0o600` on unix); `root_cert_pem()` starts with `-----BEGIN CERTIFICATE-----`; `leaf_for("ex.test", &["ex.test".into()])` succeeds and `last_was_cache_hit()==false`; a second `leaf_for("ex.test", …)` returns and `last_was_cache_hit()==true`.
  - [ ] test → FAIL → implement → PASS → gate → commit.
- **Done when:** AC3 test passes and gate clean.

### Task 10: sans-IO HTTP/1.1 state machine

- **Satisfies:** foundation for AC1/AC5; Review Focus #1.
- **Depends on:** Task 2 (flow types). **Independent:** yes — parallel group **P-B** (disjoint from Task 9; both in `aitm-proto-http` but different files — sequence Task 10 after Task 9 only if the same Coder; otherwise disjoint files allow parallel).
- **Files:** Create `crates/aitm-proto-http/src/sansio.rs`. Test: `crates/aitm-proto-http/tests/sansio.rs`.
- **Change:** Declare exactly as spec "sans-IO HTTP state machine": `HttpStateMachine` (`on_bytes(&mut self, Side, &[u8])->Result<Vec<HttpSansIoEvent>>`, `poll_outbound(&mut self, Side)->Option<Vec<u8>>`), `Side` (`Client`/`Server`), `HttpSansIoEvent` (`RequestHeaders`/`RequestBodyChunk`/`RequestComplete`/`ResponseHeaders`/`ResponseBodyChunk`/`ResponseComplete`/`Upgrade{flow,protocol}`). Implement a pure HTTP/1.1 parser/encoder (no sockets); handle `Content-Length` and `Transfer-Encoding: chunked` by emitting `*BodyChunk` events without buffering the whole body; detect `Connection: Upgrade`/`Upgrade: websocket` → `Upgrade` event.
- **Test:**
  - `sansio.rs::parse_request_headers_and_complete`: feed a raw `GET /x HTTP/1.1\r\nHost: h\r\n\r\n` on `Side::Client`; events are `[RequestHeaders(id), RequestComplete(id)]`.
  - `sansio.rs::chunked_body_streams`: feed a chunked body in two `on_bytes` calls; assert two `RequestBodyChunk` events arrive before `RequestComplete`, and no single buffer holds both chunks concatenated (chunk payloads equal `"ab"` then `"cd"`).
  - `sansio.rs::detects_ws_upgrade`: feed a `GET /chat` with `Upgrade: websocket`; last event is `Upgrade{protocol:"websocket",..}`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 11: HttpModule — TLS MITM + capture + forward

- **Satisfies:** AC1 (HTTPS capture, functional), AC5 (mutation reaches upstream).
- **Depends on:** Tasks 7, 8, 9, 10. **Independent:** no.
- **Files:** Create `crates/aitm-proto-http/src/module.rs`; modify `lib.rs`. Test: `crates/aitm-proto-http/tests/https_capture.rs`.
- **Change:** Declare `HttpModule` with `pub fn new() -> Self` implementing `ProtocolModule` (`id()=="http"`, `matches` claims TLS/CONNECT and cleartext HTTP, `spawn` drives the flow). `spawn`: read SNI → `ModuleCtx::connect_upstream` → read upstream leaf CN/SANs (x509-parser) → `CertAuthority::leaf_for` → complete client TLS handshake impersonating the host (tokio-rustls) → drive `HttpStateMachine`, insert `HttpFlow`, `emit` `RequestHeaders`/`Request`, forward upstream unless halted/short-circuited, then `ResponseHeaders`/`Response`, update the flow, stream back. Per data-flow 1.
- **Test:** `https_capture.rs::https_get_captured` (AC1): stand up a local rustls TLS echo/fixture server; run a `Proxy` with `HttpModule` + a `MemFlowStore` + a capture recorder; send an HTTPS `GET /hello` through the proxy (client trusts the proxy CA); assert the stored `HttpFlow` has `request.method=="GET"`, `request.path=="/hello"`, `response.status==200`, and the response body contains the fixture substring `"hello-aitm"`. `https_capture.rs::request_mutation_reaches_upstream` (AC5): register a plugin adding header `X-Aitm: on` in `Request`; the echo upstream reports it received `X-Aitm: on`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC1 + AC5 tests pass and gate clean.

### Task 12: WsModule — WebSocket after upgrade

- **Satisfies:** AC2.
- **Depends on:** Tasks 7, 8, 11. **Independent:** no.
- **Files:** Create `crates/aitm-proto-ws/src/module.rs`, `crates/aitm-proto-ws/src/sansio.rs`; modify `crates/aitm-proto-ws/src/lib.rs`. Test: `crates/aitm-proto-ws/tests/ws_capture.rs`.
- **Change:** Declare `WsModule` with `pub fn new()->Self` implementing `ProtocolModule` (`id()=="ws"`, `matches` true when `NextLayerHint.from_upgrade` and protocol is websocket); and `WsStateMachine` (`on_bytes`, `poll_outbound`, `send_frame(&mut self, Side, WsMessage)`), `WsSansIoEvent` (`Open`/`Message{index}`/`Close`) exactly as declared. On upgrade handoff create a `WsFlow` with `handshake: FlowId` linked to the 101 `HttpFlow`, `emit` `WsStart`, append each frame to `messages` and `emit` `WsMessage{flow,index}` before forwarding, `emit` `WsEnd` on close. Per data-flow 3.
- **Test:** `ws_capture.rs::ws_frames_captured_in_order` (AC2): upgrade a WS connection through the proxy to a local echo WS server; send one text frame client→server and receive one server→client; assert the resulting `WsFlow.handshake` equals the handshake `HttpFlow` id, and `messages` are `[WsMessage{dir:ClientToServer,..}, WsMessage{dir:ServerToClient,..}]` in that order, both opcode `Text`.
  - [ ] test → FAIL → implement → PASS → gate → commit.
- **Done when:** AC2 test passes and gate clean.

### Task 13: capture plugin (`flow.list`, `flow.get`)

- **Satisfies:** AC1/AC9 retrieval, AC-P3 baseline (capture survives when mutate dropped).
- **Depends on:** Tasks 4, 5, 8. **Independent:** yes — parallel group **P-C** (disjoint files under `aitm-plugins/`).
- **Files:** Create `crates/aitm-plugins/src/capture.rs`; modify `crates/aitm-plugins/src/lib.rs`. Test: `crates/aitm-plugins/tests/capture.rs`.
- **Change:** `pub struct CapturePlugin` impl `Plugin` (`name()=="capture"`) registering commands `flow.list` (→ `Value::Array` of flow-id strings) and `flow.get` (param `id:FlowId` → `Value::Object` summarizing the flow: method/path/status). Capture itself is passive (modules already insert flows); the plugin provides read commands.
- **Test:** `capture.rs::flow_list_and_get`: insert two flows into the store the `CommandHost` wraps; `flow.list` returns an array of length 2; `flow.get{id}` on the first returns an object whose `method` field == `"GET"`.
  - [ ] test → FAIL → implement → PASS → gate → commit.
- **Done when:** test passes and gate clean.

### Task 14: replay plugin (`flow.replay`)

- **Satisfies:** AC6.
- **Depends on:** Tasks 4, 8 (ProxyClient), 13-independent. **Independent:** yes — parallel group **P-C**.
- **Files:** Create `crates/aitm-plugins/src/replay.rs`; modify `lib.rs`. Test: `crates/aitm-plugins/tests/replay.rs`.
- **Change:** `pub struct ReplayPlugin` impl `Plugin` (`name()=="replay"`) registering `flow.replay` (param `id:FlowId`): loads the flow, calls `host.guard().check_active(host)` then `host.client().send(req)`, returns the new flow's id. Refuses with the guard error when out of scope.
- **Test:** `replay.rs::replay_marks_is_replay` (AC6): with host in scope and a stub `ProxyClient` echoing a 200, `flow.replay{id}` returns a new `FlowId` whose stored flow has `metadata.is_replay==true` and `response.status==200`. `replay.rs::replay_out_of_scope_refused`: with empty scope, `flow.replay` → error mentioning scope.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC6 test passes and gate clean.

### Task 15: intercept plugin (`flow.intercept`, `flow.resume`, `flow.kill`)

- **Satisfies:** data-flow 2 control; interception primitives surfaced as commands.
- **Depends on:** Tasks 4, 8. **Independent:** yes — parallel group **P-C**.
- **Files:** Create `crates/aitm-plugins/src/intercept.rs`; modify `lib.rs`. Test: `crates/aitm-plugins/tests/intercept.rs`.
- **Change:** `pub struct InterceptPlugin` impl `Plugin` (`name()=="intercept"`): an arm-able mode that on `Request` calls `ctx.backup(); ctx.intercept()`; registers `flow.intercept` (arm/park), `flow.resume` (fire the `ResumeHandle`), `flow.kill` (drop). Holds parked `ResumeHandle`s keyed by `FlowId` in `&mut self` state.
- **Test:** `intercept.rs::park_then_resume`: arm intercept; dispatch a `Request`; assert flow state `Intercepted`; call `flow.resume{id}`; assert state `Resumed`. `intercept.rs::kill_drops`: `flow.kill{id}` on a parked flow → state `Killed`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 16: mutate plugin (`flow.mutate`, `request.send`)

- **Satisfies:** AC5 (command path), AC16 (request.send gating half).
- **Depends on:** Tasks 4, 8. **Independent:** yes — parallel group **P-C**.
- **Files:** Create `crates/aitm-plugins/src/mutate.rs`; modify `lib.rs`. Test: `crates/aitm-plugins/tests/mutate.rs`.
- **Change:** `pub struct MutatePlugin` impl `Plugin` (`name()=="mutate"`) registering `flow.mutate` (params: `id:FlowId`, `edits` object for method/path/headers/body → applies via `FlowStore::update` to the backed-up flow) and `request.send` (craft a request object → `guard.check_active` → `client.send`, captured). Removing this plugin from the registration list must remove mutation+craft with no core edit (AC-P3 is asserted in Task 28).
- **Test:** `mutate.rs::mutate_edits_flow`: `flow.mutate{id, edits:{headers:{X-Aitm:on}}}`; stored flow's request now has header `X-Aitm: on`. `mutate.rs::request_send_scope_gated`: `request.send` to out-of-scope host → scope error; after scope added → returns a flow id.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** tests pass and gate clean.

### Task 17: scope + rate-limit plugins (`scope.add`, `scope.list`)

- **Satisfies:** AC16 (scope commands), AC17 (rate limiting), AC-P4 (option-driven behavior).
- **Depends on:** Tasks 4, 6, 8. **Independent:** yes — parallel group **P-C**.
- **Files:** Create `crates/aitm-plugins/src/scope.rs`, `crates/aitm-plugins/src/ratelimit.rs`; modify `lib.rs`. Test: `crates/aitm-plugins/tests/scope_rate.rs`.
- **Change:** `pub struct ScopePlugin` impl `Plugin` (`name()=="scope"`) registering `scope.add` (param `host:Str` → `guard.add_scope`) and `scope.list` (→ array). `pub struct RateLimitPlugin` impl `Plugin` (`name()=="rate-limit"`) declaring a `per_host_rps` option at `load` that configures the guard's per-host bucket (AC-P4: setting the option changes observed throttling).
- **Test:** `scope_rate.rs::scope_add_then_list`: `scope.add{host:"ex.test"}`; `scope.list` includes `"ex.test"`. `scope_rate.rs::rate_limit_throttles_burst` (AC17): with the rate-limit option set to a low per-host rps, a burst of N `request.send`/`flow.replay` yields at least one `RateLimited` refusal (rejection count ≥ 1). `scope_rate.rs::option_changes_behavior` (AC-P4): raising the `per_host_rps` option lets the same burst pass with zero refusals.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC16(scope)/AC17/AC-P4 tests pass and gate clean.

### Task 18: aitm-browser — driver + proxy routing + CA trust

- **Satisfies:** AC10 (routes through proxy), AC11 (primitives).
- **Depends on:** Tasks 4, 8, 11. **Independent:** no (needs a running proxy for AC10).
- **Files:** `crates/aitm-core/src/browser.rs` (trait + config-type definitions — see call #4); modify `crates/aitm-core/src/lib.rs` (re-export). Create `crates/aitm-browser/src/driver.rs`, `crates/aitm-browser/src/config.rs` (the chromiumoxide impl); modify `crates/aitm-browser/src/lib.rs`. Test: `crates/aitm-browser/tests/browser.rs`.
- **Change (per structuring call #4):** **Define in `aitm-core`**, exactly as spec "aitm-browser": `BrowserDriver` (`navigate`/`click`/`type_text`/`screenshot`→PNG bytes/`eval`→`Value`/`get_dom`), `ClickTarget` (`Selector`/`Point`), `NavOutcome{final_url,status}`, `BrowserConfig{proxy_addr,headless,ignore_cert_errors,nav_timeout,ssrf}`, `SsrfPolicy` — these are named by the `aitm-core` surface (`CommandHost::browser()->Option<&dyn BrowserDriver>`, `Config.browser: BrowserConfig`), so they cannot live in `aitm-browser`, which depends on `aitm-core`. **The concrete chromiumoxide `BrowserDriver` implementation lives in `aitm-browser`:** launch headless with `--proxy-server=<proxy_addr>`, trust the proxy CA via CDP `Security.setIgnoreCertificateErrors`.
- **Test:** `browser.rs::navigate_routes_through_proxy` (AC10, `#[ignore]` unless Chromium present — see Questions): launch the proxy + `HttpModule` over a local TLS fixture, navigate the browser to the fixture HTTPS URL; assert the page's request appears as a captured `HttpFlow` in the store (len ≥ 1, path matches). `browser.rs::primitives` (AC11): `screenshot()` returns bytes starting with the PNG magic `\x89PNG\r\n\x1a\n` and len > 0; `eval("1+1")` returns `Value::Int(2)`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC10 + AC11 tests pass and gate clean.

### Task 19: SSRF guard + browser.* commands

- **Satisfies:** AC12 (blocked then permitted), AC16 (browser.navigate gating), browser command surface.
- **Depends on:** Tasks 6, 18. **Independent:** no.
- **Files:** Create `crates/aitm-browser/src/ssrf.rs`, `crates/aitm-browser/src/commands.rs`; modify `lib.rs`. Test: `crates/aitm-browser/tests/ssrf.rs`.
- **Change (per structuring call #4):** `SsrfPolicy{block_private,block_loopback,allow_if_in_scope}` (defaults true/true/true) is **defined in `aitm-core`** (Task 18), since `BrowserConfig.ssrf` names it. In `aitm-browser`, declare `SsrfGuard` (`check(url)->Result<ResolvedTarget,GuardError>`) and `ResolvedTarget{host,addr}` exactly as declared — the concrete SSRF guard — and implement using `classify_host` (Task 6) + scope lookup. Register `browser.navigate`/`click`/`type`/`screenshot`/`eval`/`get_dom` commands that run the SSRF guard (navigate) + scope guard before delegating to `BrowserDriver`.
- **Test:** `ssrf.rs::private_blocked_then_scoped` (AC12): `browser.navigate{url:"http://127.0.0.1:PORT/"}` with empty scope → `Err(PrivateAddressBlocked)`; after `scope.add{host:"127.0.0.1:PORT"}`, the same navigate is permitted (reaches the driver). `ssrf.rs::dns_to_private_blocked` (Review Focus #3): a hostname resolving to a private IP is blocked.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC12 test passes and gate clean.

### Task 20: aitm-poc model + YAML serde + schema validation

- **Satisfies:** AC13 (round-trip), AC-L1, AC-L7; Review Focus #4.
- **Depends on:** Tasks 2, 4 (Value/types). **Independent:** yes — parallel group **P-D** (can run during Phase 1).
- **Files:** Create `crates/aitm-poc/src/model.rs`, `crates/aitm-poc/src/schema.rs`; modify `crates/aitm-poc/src/lib.rs`. Test: `crates/aitm-poc/tests/serde.rs`; fixture `crates/aitm-poc/tests/fixtures/reflected-xss-search-q.yaml` (copied verbatim from PoC-language spec Example 1).
- **Change:** Declare exactly as platform spec "aitm-poc — the artifact model": `Poc{id,info,variables,steps,success}`, `PocInfo` (no remediation field), `Severity` (`Info`/`Low`/`Medium`/`High`/`Critical`), `Variable`, `Step` (`Http`/`Browser`/`Extract`), `HttpStep`, `BrowserStep`, `BrowserAction` (`Navigate`/`Click`/`Type`/`Eval`/`Screenshot`), `ExtractStep`, `ExtractSource` (`Regex`/`JsonPath`/`Header`/`BrowserEval`), `Assertion` (`Status`/`Word`/`Regex`/`Dsl`/`BrowserEval{expr,equals}`/`All`/`Any`/`Not`). Add serde derives mapping the YAML language (PoC-language spec "Document structure") to these types. Implement `validate(&serde_yaml::Value)->Result<(), PocError>` rejecting missing required keys (`id`, `info`, `steps`, `success`) and unknown step types.
- **Test:** `serde.rs::example1_roundtrips` (AC-L1/AC13): deserialize the Example-1 fixture into `Poc`, assert `poc.id=="reflected-xss-search-q"` and `poc.info.severity==Severity::High`, re-serialize to YAML, deserialize again, assert the two `Poc` values are equal. `serde.rs::missing_id_rejected` (AC-L7): a PoC YAML with `id` removed → `validate` returns `Err` whose message contains `id`. `serde.rs::unknown_step_rejected` (AC-L7): a step with key `telnet` → `Err` mentioning the unknown step.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC-L1/AC13/AC-L7 tests pass and gate clean.

### Task 21: PoC templating (`{{var}}` + runtime placeholders)

- **Satisfies:** AC-L4.
- **Depends on:** Task 20. **Independent:** yes — parallel group **P-E** (disjoint from Task 22).
- **Files:** Create `crates/aitm-poc/src/template.rs`; modify `lib.rs`. Test: `crates/aitm-poc/tests/template.rs`.
- **Change:** Declare `Template` (`render(&self, input:&str, vars:&VarBindings)->Result<String>`) and `VarBindings` (name→`Value`) exactly as declared. Resolve `{{name}}` from `VarBindings` (caller overrides) then `variables` defaults; support runtime placeholders `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}`, `{{Host}}`, `{{Port}}`, `{{Path}}`, `{{Scheme}}`; support DSL-wrapped defaults evaluated once (e.g. `{{rand_text_alpha(8)}}` via Task 22 helpers — depend on Task 22 for the helper set, or stub `rand_text_alpha` here and share in Task 22).
- **Test:** `template.rs::var_and_override` (AC-L4): with `variables` default `param=q` and binding `param=qq`, `render("{{param}}")` → `"qq"`. `template.rs::runtime_placeholders`: given target `https://ex.test:8443/a`, `render("{{Hostname}}|{{Port}}|{{Scheme}}")` → `"ex.test|8443|https"`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC-L4 tests pass and gate clean.

### Task 22: Matcher/extractor DSL evaluation

- **Satisfies:** AC-L5, AC-L6; Review Focus (matcher combinators).
- **Depends on:** Task 20. **Independent:** yes — parallel group **P-E** (disjoint from Task 21).
- **Files:** Create `crates/aitm-poc/src/matcher.rs`, `crates/aitm-poc/src/extract.rs`, `crates/aitm-poc/src/dsl.rs`; modify `lib.rs`. Test: `crates/aitm-poc/tests/matcher.rs`.
- **Change:** Implement `Assertion` evaluation over a response/browser context: `Status(u16)`, `Word(String)` (part body/header), `Regex`, `BrowserEval{expr,equals}`, `All`/`Any`/`Not`, plus modifiers `negative`, `condition: and|or`, `matchers-condition`. Implement extractors `Regex(+group)`, `JsonPath`, `Header`(kval), binding named variables (`internal` keeps them out of output). Ship the minimal nuclei DSL helper subset needed for AC-L5 (`contains`, `status_code`, `body`, `url_encode`, `rand_text_alpha`, `base64`) — builder picks exact set.
- **Test:** `matcher.rs::status_word_regex_browser` (AC-L5): against a context with status 200 and body `window.__aitm='ABC'`: `Status(200)`→true; `Word("window.__aitm='ABC'")`→true; `Regex("__aitm='[A-Z]+'")`→true; `BrowserEval{expr:"window.__aitm", equals:Str("ABC")}` with browser value `"ABC"`→true. `matcher.rs::negative_and_or` (AC-L5): `Not(Word("patched"))`→true when body lacks it; `All([...])` vs `Any([...])` combine as specified. `extract.rs::regex_binds_later_var` (AC-L6): extract `csrf` via regex group 1 from `name="csrf" value="abc123"`; binding `csrf=="abc123"`; `internal:true` keeps it out of the printed output set.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC-L5/AC-L6 tests pass and gate clean.

### Task 23: PocBuilder (`poc.build`)

- **Satisfies:** AC13 (build side), data-flow 5.
- **Depends on:** Tasks 5, 20. **Independent:** no (needs model + store).
- **Files:** Create `crates/aitm-poc/src/builder.rs`; modify `lib.rs`. Test: `crates/aitm-poc/tests/builder.rs`.
- **Change:** Declare `PocBuilder` (`build(&self, &HttpFlow, PocSpec)->Result<Poc>`) and `PocSpec{info,variables,success}` exactly as declared. Parameterize the flow: replace concrete values with `{{var}}` placeholders per the chosen variables, order steps, attach `success`. Register a `poc.build` command.
- **Test:** `builder.rs::build_parameterizes_flow` (AC13 build): given a captured reflected-XSS flow and a `PocSpec` with variables `target`/`param`/`payload` and a `BrowserEval` success, `build` returns a `Poc` whose first `HttpStep.url` contains `{{target}}` and `{{param}}` (not the literal host), and whose `success` is the given `BrowserEval` assertion.
  - [ ] test → FAIL → implement → PASS → gate → commit.
- **Done when:** AC13 build test passes and gate clean.

### Task 24: PocRunner (`poc.run`) + three artifacts

- **Satisfies:** AC14, AC15, AC-L2, AC-L3 (functional; also feeds AC18). Depends on the test target (Task 27).
- **Depends on:** Tasks 8, 16, 18, 19, 20, 21, 22, 27. **Independent:** no.
- **Files:** Create `crates/aitm-poc/src/runner.rs`; modify `lib.rs`. Test: `crates/aitm-poc/tests/run.rs`.
- **Change:** Declare `PocRunner` (`run(&self, &Poc, VarBindings, &CommandHost)->BoxFuture<Result<PocRunResult>>`), `PocRunResult{passed,finding_capture,poc_path,screenshot_path,evaluated}`, `AssertionOutcome{assertion,matched}` exactly as declared. Execute each `Step`: HTTP steps template + `guard.check_active` + `client.send`; browser steps SSRF-guard + `BrowserDriver`; extract steps bind vars. Evaluate `success`; write the three artifacts (finding capture, YAML PoC file, screenshot PNG). Register a `poc.run` command.
- **Test:** `run.rs::pass_vs_patched` (AC14/AC-L2): run Example-1 PoC against the bundled **vulnerable** target → `PocRunResult.passed==true`; against the **patched** target → `passed==false`. `run.rs::three_artifacts` (AC15/AC-L3): a passing run writes `finding_capture` (a valid `FlowId` present in the store), a `poc_path` file that re-parses as the same `Poc`, and a `screenshot_path` whose bytes start with the PNG magic. (May be `#[ignore]` without Chromium — see Questions.)
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC14/AC15/AC-L2/AC-L3 tests pass and gate clean.

### Task 25: aitm-mcp — server, tool derivation, transports

- **Satisfies:** AC7 (tools/list exact set), AC9 (MCP-only capture), AC-P2 (command over MCP).
- **Depends on:** Task 4 (Registry) + at least capture commands (Task 13). **Independent:** yes — parallel group **P-F** (disjoint from Task 26).
- **Files:** Create `crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/src/schema.rs`, `crates/aitm-mcp/src/transport.rs`; modify `crates/aitm-mcp/src/lib.rs`. Test: `crates/aitm-mcp/tests/mcp.rs`.
- **Change:** Declare exactly as spec "Frontends: MCP and CLI": `McpSchemaDerive` (`to_mcp_tool(&self, &dyn Command)->McpTool`), `McpTool{name,description,input_schema}`, `McpServer` (`new(Arc<Registry>, McpTransport)`, `async serve()->Result<()>`). `tools/list` enumerates every registered command; `tools/call` → `Command::invoke`. JSON Schema derives from `ParamSchema`/`TypeDesc`. Implement stdio + loopback-TCP-with-required-token transports. **Per structuring call #5, add an additive builder `McpServer::with_services(self, store: Arc<dyn FlowStore>, client: Arc<dyn ProxyClient>, guard: Arc<dyn ScopeRateGuard>, browser: Option<Arc<dyn BrowserDriver>>) -> Self`** (the declared `new(Arc<Registry>, McpTransport)` signature is unchanged); `tools/call` builds a `CommandHost` from these handles at invoke time and passes it to `Command::invoke`. A `tools/call` when `with_services` was not called returns a clear error; `tools/list`/schema derivation never need services.
- **Test:** `mcp.rs::tools_list_exact_set` (AC7): with all M1 commands registered, `tools/list` tool names equal exactly the set `{flow.list, flow.get, flow.replay, flow.intercept, flow.resume, flow.kill, flow.mutate, request.send, browser.navigate, browser.click, browser.type, browser.screenshot, browser.eval, browser.get_dom, poc.build, poc.run, scope.add, scope.list}` (18 tools). `mcp.rs::mcp_only_capture` (AC9): drive a capture + `flow.get` entirely via an in-process MCP client → retrieves the flow. `mcp.rs::ping_over_mcp` (AC-P2): a plugin-registered `demo.ping` is callable over MCP → `"pong"`. `mcp.rs::loopback_requires_token`: a TCP call without the token is refused.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC7/AC9/AC-P2(MCP) tests pass and gate clean.

### Task 26: aitm-cli — same commands from argv

- **Satisfies:** AC8 (one surface, two frontends), AC-P2 (command over CLI).
- **Depends on:** Task 4 + capture commands (Task 13). **Independent:** yes — parallel group **P-F** (disjoint from Task 25).
- **Files:** Create `crates/aitm-cli/src/dispatch.rs`; modify `crates/aitm-cli/src/lib.rs`. Test: `crates/aitm-cli/tests/cli.rs`.
- **Change:** Declare `Cli` (`new(Arc<Registry>)`, `dispatch(&self, &[String])->Result<Value>`) exactly as declared. Subcommand path maps 1:1 to `Command::name()` (`flow replay` → `"flow.replay"`); flags map to `ParamDef` by name (`--id <uuid>`). **Per structuring call #5, add an additive builder `Cli::with_services(self, store: Arc<dyn FlowStore>, client: Arc<dyn ProxyClient>, guard: Arc<dyn ScopeRateGuard>, browser: Option<Arc<dyn BrowserDriver>>) -> Self`** (the declared `new(Arc<Registry>)` signature is unchanged); `dispatch` builds a `CommandHost` from these handles at invoke time and passes it to `Command::invoke`. A `dispatch` when `with_services` was not called returns a clear error.
- **Test:** `cli.rs::cli_matches_mcp` (AC8): register `flow.list`; invoke via `Cli::dispatch(["flow","list"])` and via the MCP `tools/call` path; assert both return equal `Value`s. `cli.rs::ping_over_cli` (AC-P2): `dispatch(["demo","ping"])` → `Value::Str("pong")`.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC8/AC-P2(CLI) tests pass and gate clean.

### Task 27: Bundled vulnerable + patched reflected-XSS target

- **Satisfies:** enables AC14/AC18/AC-L2 (deterministic pass-vs-patch).
- **Depends on:** Task 1. **Independent:** yes — parallel group **P-B** (fully standalone; can be built early).
- **Files:** Create `crates/aitm-poc/tests/support/target.rs` (shared test fixture; a tiny hyper server) — or, if preferred, a small `crates/aitm-target/` dev-only crate. Builder's call; keep it test/dev-only, not shipped in the `aitm` binary.
- **Change:** A minimal HTTP(S) app exposing `GET /search?q=...`. **Vulnerable:** reflects `q` unescaped into the HTML body. **Patched:** HTML-escapes `q`. A `TargetMode::{Vulnerable,Patched}` switch; a `spawn(mode)->SocketAddr` test helper. (The `/login`+`/notes` stored-XSS endpoints Example 4 assumes are later-milestone; M1 ships only `/search`.)
- **Test:** `target.rs::reflects_vs_escapes`: `GET /search?q=<b>x</b>` against `Vulnerable` returns a body containing the literal `<b>x</b>`; against `Patched` returns the escaped `&lt;b&gt;x&lt;/b&gt;` and **not** the raw tag.
  - [ ] test → FAIL → implement → PASS → gate → commit.
- **Done when:** the target test passes and gate clean.

### Task 28: aitm binary — wire everything from Config; AC-P3 + AC-P4 proof

- **Satisfies:** AC-P3 (removable plugin, no core edit), AC-P4 (options end-to-end), binary assembly.
- **Depends on:** Tasks 11, 12, 13–19, 25, 26. **Independent:** no.
- **Files:** Create `crates/aitm/src/main.rs` (wiring), `crates/aitm/src/wire.rs` (a `pub fn build_proxy(cfg:&Config)->Result<Proxy>` reusable by tests). Test: `crates/aitm/tests/wiring.rs`.
- **Change:** `build_proxy` registers `HttpModule`, `WsModule`, then the first-party plugins (capture, replay, intercept, mutate, scope, rate-limit) + browser + poc command providers, in order, from `Config`. `main` parses config, builds the proxy, starts the selected MCP transport and the CLI. **Per structuring call #5, wire the frontends with `with_services`:** after building the proxy, call `McpServer::new(...).with_services(...)` and `Cli::new(...).with_services(...)`, passing the proxy's own handles (`Proxy::store()/client()/guard()/browser()`), so each frontend can build a `CommandHost` per invoke. Wire `scripts`/Rhai is **not** in M1 (seam only).
- **Test:** `wiring.rs::drop_mutate_disables_mutation_no_core_edit` (AC-P3): build two proxies from the same config path, one registering the mutate plugin and one omitting it; assert `flow.mutate` is present in the first registry and **absent** in the second, while `flow.list` (capture) works in both — achieved by changing only the registration list, no `aitm-core` source change. `wiring.rs::option_from_config` (AC-P4): a config setting the rate-limit `per_host_rps` option changes the observed throttle threshold.
  - [ ] tests → FAIL → implement → PASS → gate → commit.
- **Done when:** AC-P3/AC-P4 tests pass and gate clean.

### Task 29: End-to-end reflected XSS over MCP (functional)

- **Satisfies:** AC18 (E2E), and consolidates AC10/AC14 as functional tests.
- **Depends on:** Tasks 18, 24, 25, 27, 28. **Independent:** no (top of the stack).
- **Files:** Create `crates/aitm/tests/e2e_reflected_xss.rs`.
- **Change:** No new production code — a full-stack integration test wiring the real binary path (`build_proxy`) + the bundled target + an in-process MCP client.
- **Test:** `e2e_reflected_xss.rs::reflected_xss_over_mcp` (AC18): driven **entirely over MCP** against the bundled vulnerable target — `scope.add` the target; capture the vuln (navigate/replay); `poc.build` a parameterized PoC; `poc.run` it with no agent → `passed==true`; assert all three artifacts exist (finding capture id in store, YAML file re-parses, screenshot PNG magic). Re-run against the patched target → `passed==false`. (`#[ignore]` without Chromium — see Questions.)
  - [ ] test → FAIL → implement/wire → PASS → gate → commit.
- **Done when:** AC18 test passes and gate clean.

### Task 30: Performance / soak test (throughput floor + bounded memory)

- **Satisfies:** AC20; Review Focus #1.
- **Depends on:** Task 11 (HTTP path), Task 28. **Independent:** no.
- **Files:** Create `crates/aitm/tests/soak.rs` (gated behind a feature/env flag so normal `cargo test` stays fast; the exit gate runs it explicitly).
- **Change:** No new production code — a load harness driving sustained traffic (small and large bodies) through the proxy to a local upstream, sampling RSS over the run.
- **Test:** `soak.rs::throughput_floor_and_memory_plateau` (AC20): over a sustained run, assert (i) measured throughput ≥ **2000 req/s** on a single instance, and (ii) resident memory plateaus — the last-quartile mean RSS is within a bounded delta of the first-quartile mean (no upward trend), with no crash/OOM. Load profile/duration are the builder's, long enough to expose a leak. (Run environment is a Question — likely outside the sandbox.)
  - [ ] test → FAIL → tune → PASS → gate → commit.
- **Done when:** AC20 assertions pass on the agreed rig and gate clean.

### Task 31: M1 exit-gate verification (whole branch)

- **Satisfies:** AC19 and the M1 exit gate (all AC1–AC20, AC-P1–P5, AC-L1–L7 green).
- **Depends on:** all prior tasks. **Independent:** no.
- **Files:** none (verification task); may add `README`/CA-trust instructions if missing (builder's call, docs only).
- **Change:** none beyond flakiness/formatting fixes surfaced by the full run.
- **Test:** run the full gate on the whole workspace: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` (plus the soak test on the agreed rig). Produce a mapping table showing each AC → the test that proves it, all green.
  - [ ] Run the gate; paste actual output.
  - [ ] Confirm every M1 AC maps to a passing test.
  - [ ] Commit (if any fixes) / tag the branch ready for integration.
- **Done when:** the full gate is green and every M1 AC maps to a passing, named test.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
