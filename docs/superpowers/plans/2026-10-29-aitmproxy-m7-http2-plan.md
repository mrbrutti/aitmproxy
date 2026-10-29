# aitmproxy Milestone 7 Implementation Plan — HTTP/2 MITM

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-m7-http2-design.md` (approved 2026-10-29 by Matt; §1 ALPN mirror, §2 serve_h2 per-stream tasking, §3 seam placement, §4 limits, §5 push off, §6 capability reuse, §7 capability table, AC-H2.1–.11; all four Open Questions resolved as recommended — mirror/fail-closed, h1 replay, the `h2` crate, push disabled).
**Branch / worktree:** `feat/m7-http2`, one worktree, cut from `main` (M6 is on `main`). The spec and this plan are committed on `claude/m7-http2-spec-63066a`.

**Goal:** Add HTTP/2 MITM so an `h2` stream is captured, shown and acted on exactly like an HTTP/1.1 flow — same `Flow::Http`, same `Event` sequence — giving every M3–M6 operator/agent capability over `h2` with no `aitm-core` protocol change.

**Architecture:** All work lands **inside `aitm-proto-http`** as a second arm of the existing `HttpModule`. `mitm()` learns ALPN: it offers `h2`+`http/1.1` on both TLS hops and **mirrors** the upstream's negotiated protocol down to the client, then branches — negotiated `h2` runs a new `serve_h2()` built on the **`h2` crate**; `http/1.1` runs the existing sans-IO `serve()` unchanged. `serve_h2` drives the connection-level `h2` halves continuously and spawns **one task per accepted stream**, so parking an intercepted stream at a breakpoint suspends only that stream, never the connection. Each stream becomes one `HttpFlow` (`version: H2`) emitting the ordinary `RequestHeaders → Request → ResponseHeaders → Response` events, so the intercept/mutate/kill/Map/replay/session/passthrough machinery above the wire needs no change.

**Tech Stack:** Rust; `h2` 0.4.x (the hyper HTTP/2 engine) + `http` 1.x (the `Request`/`Response`/pseudo-header types `h2` speaks), added to `crates/aitm-proto-http/Cargo.toml`; existing `tokio-rustls` 0.26 / `rustls` 0.23 (ALPN is a field change, no version bump); `tokio` tasks for per-stream concurrency.

## Global constraints

Every task's requirements implicitly include these (verbatim from the spec / WORKFLOW):

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` must pass before any review, per task. TDD: write the failing test first, watch it fail, write the minimum to pass, watch it pass. The Coder's report includes both runs.
- **`unsafe` stays forbidden.** The `h2` crate is safe Rust; a task reaching for `unsafe` has mis-designed — stop and report.
- **Additive-only core.** `Flow`/`HttpFlow`/`HttpRequest`/`HttpResponse`/`Event`/`InterceptState`/`FlowCtx`/`ConnInfo`/`ProtocolModule`/`NextLayerHint` are **reused, not changed**. `HttpVersion::H2` (`crates/aitm-core/src/flow.rs:151`) and `ConnInfo.alpn` already exist. The **only** permitted `aitm-core` edit in M7 is **one additive `LimitConfig` field** (`max_concurrent_streams`, Task 5); any other core touch means the task mis-read the seam — stop and report (WORKFLOW "stop on gaps").
- **Mirror ALPN, no h2↔h1 bridge.** The client is offered exactly the protocol the upstream negotiated. The common path is h2↔h2 or h1↔h1; cross-version translation is **not** built. The one unsatisfiable pair (h1-only client ↔ h2-only upstream) **fails closed with a logged error** (spec §1, Open Question 1).
- **No h2c, no HTTP/3, no gRPC decode, no server push, no WS-over-h2.** Only `h2` negotiated via ALPN over TLS. Push is disabled both directions (spec §5).
- **Deny-by-default, one guard, no new command.** M7 adds **no new command and no new agent gate**. Active egress from an h2 flow (Map Remote redirect, replay) rides the existing `ScopeRateGuard::check_active`; passthrough hosts never reach the h2 arm. Replay of an h2 flow goes over the existing h1 `Http1Sender` (spec Open Question 2).
- **Bounded memory.** Per-stream request buffer and captured response copy capped at `max_body_bytes` (as h1); concurrent streams capped via `SETTINGS_MAX_CONCURRENT_STREAMS`; HPACK max-header-list-size and dynamic-table size finite via the `h2` builder.
- **No h1 regression.** The existing `serve()`, `Http1Machine`, `Http1Sender` and WebSocket upgrade path keep working byte-for-byte; M7 is additive alongside them.
- **Dependency versions live in `crates/aitm-proto-http/Cargo.toml`** (not the root manifest), to avoid conflicts with sibling sessions (proto-http STATUS convention).
- **Declared signatures are authoritative.** Types/signatures in each task's Interfaces block are copied exactly; bodies and in-module file layout are the builder's.
- **Tests are hermetic.** Integration tests stand up an in-process `h2` origin (the `h2` crate's server) behind a forged-leaf TLS listener owned by the test and drive an `h2` client through the module via a registered chain; egress is asserted against the test origin. Port-binding e2e is gated/skipped where the sandbox forbids binding (`CLAUDE.md`); prefer a loopback listener the test owns.
- **Git/gh run through the Terminal panel** (`run_in_terminal`), never the sandboxed shell (`CLAUDE.md`). Commit after each task with `--no-gpg-sign`; push with an explicit refspec (`git push origin feat/m7-http2`).

## Review focus

Input classes the spec implies but a happy path does not exercise; each is pinned to a test in its task:

1. **Head-of-line stall under intercept.** Parking one stream's `emit().await` must not block the connection's frame loop or sibling streams. If `serve_h2` awaits a parked stream on the connection task instead of a per-stream task, streams B/C freeze and flow-control windows deadlock. Pinned in Task 3 (`intercept_one_stream_others_complete`), AC-H2.4.
2. **Hop-by-hop headers illegal in h2.** An `HttpRequest`/`HttpResponse` carrying `Connection`/`Transfer-Encoding`/`Keep-Alive`/`Upgrade`/`Proxy-*` (e.g. injected by `flow.mutate`, or copied from an h1-shaped fixture) must be **stripped on encode**, or `h2` emits a `PROTOCOL_ERROR` and drops the stream. Pinned in Task 1 (`encode_strips_hop_by_hop`, unit) and Task 2 (`forward_with_connection_header_succeeds`, e2e), AC-H2.9.
3. **h1 fallback must not regress.** Offering `h2` in ALPN must still serve an h1-only client and an h1-only origin. Pinned in Task 2 (`h1_only_origin_falls_back`, `h1_only_client_served_over_h1`), AC-H2.2.
4. **Unbounded streams / bodies.** A client opening more than `max_concurrent_streams`, or a response body over `max_body_bytes`, must be bounded (streams capped by SETTINGS; stored copy truncated while the client still gets the full stream). Pinned in Task 2 (`body_over_cap_truncated_copy`) and Task 5 (`concurrent_streams_bounded`), AC-H2.10.
5. **Map Remote cross-origin cannot smuggle egress past scope.** A redirect to a different host over an h2 connection opens a **second** upstream; an out-of-scope target is refused and the original is not sent. Pinned in Task 4 (`map_remote_h2_out_of_scope_refused`), AC-H2.8.

---

## Overview

M7 is **one deep feature in one crate**, so the tasks are mostly sequential, not a parallel fan-out like M6. Task 1 (pure translation helpers) is the only independently-startable unit; Task 2 (the `serve_h2` engine + ALPN) is the spine everything else hangs off. Tasks 3–5 layer interception semantics, Map Remote cross-origin, and config/limits onto the engine. Task 6 is the whole-branch integration sweep.

**Sequence (longest chain 1 → 2 → 3 → 6):**

| Wave | Tasks | Notes |
|---|---|---|
| **W0** | 1 | Pure `http`↔model head translation; unit-tested, no I/O. Blocks 2. |
| **W1** | 2 | ALPN mirror + branch + `serve_h2` driver (capture, multiplexing, fallback, forward, short-circuit, bodies/caps, push off, GOAWAY). Consumes Task 1. Blocks 3, 4, 5. |
| **W2** | 3 ∥ 4 ∥ 5 | 3 = interception semantics (park/mutate/kill→RST); 4 = Map Remote cross-origin upstream; 5 = `LimitConfig.max_concurrent_streams` + binary wiring. All touch `serve_h2`/its module — **run sequentially if one worktree**, or 5 (config/binary) may fan out since it is disjoint from 3/4. |
| **W3** | 6 | Whole-branch integration sweep + HAR/session version tag (AC-H2.11). |

**File ownership (so two writers never share a file):** all of Tasks 1–4 live in `crates/aitm-proto-http/src/` (new `h2.rs` + `module.rs` edits + a `translate.rs` helper); because they share `module.rs`/`h2.rs` they are **one writer at a time** unless split across worktrees that merge in order. Task 5 additionally owns `crates/aitm-core/src/config.rs` and `crates/aitm/src/**` (disjoint from the h2 module). Task 6 adds only tests.

---

## Tasks

### Task 1: `http`↔model head translation + hop-by-hop stripping (pure)

- **Satisfies:** AC-H2.9 (unit half). Foundation for Task 2.
- **Depends on:** none. **Independent:** yes — **W0**. Blocks Task 2.
- **Files:** Create `crates/aitm-proto-http/src/translate.rs`; register `mod translate;` in `crates/aitm-proto-http/src/lib.rs`. Add `h2 = "0.4"` and `http = "1"` to `crates/aitm-proto-http/Cargo.toml` `[dependencies]`. Tests `crates/aitm-proto-http/tests/h2_translate.rs` (or `#[cfg(test)]` in `translate.rs`).
- **Interfaces — Produces:**
  ```rust
  // h2 inbound request parts -> core model. `scheme`/`authority` fall back to the
  // connection's when a pseudo-header is absent. version is always H2.
  pub(crate) fn request_from_h2(head: &http::request::Parts, conn_scheme: &str, conn_authority: &str) -> aitm_core::HttpRequest;
  // core model -> h2 outbound request. Strips h1-only hop-by-hop headers (RFC 9113 §8.2.2).
  pub(crate) fn h2_request_from(req: &aitm_core::HttpRequest) -> http::Request<()>;
  // h2 inbound response parts -> core model (version H2).
  pub(crate) fn response_from_h2(head: &http::response::Parts) -> aitm_core::HttpResponse;
  // core model -> h2 outbound response. Strips hop-by-hop headers.
  pub(crate) fn h2_response_from(resp: &aitm_core::HttpResponse) -> http::Response<()>;
  // The connection-specific header names illegal in h2, stripped on encode.
  pub(crate) const HOP_BY_HOP: &[&str]; // connection, keep-alive, proxy-connection, proxy-authenticate, proxy-authorization, te, trailer, transfer-encoding, upgrade
  ```
- **Interfaces — Consumes:** `aitm_core::{HttpRequest, HttpResponse, HttpVersion, HeaderMap, Body}`. Mapping: pseudo-headers `:method`→`method`, `:scheme`→`scheme`, `:authority`→`authority`, `:path`→`path`; `:status`→`status`. `HeaderMap` iterate order preserved; header names lowercased on h2 encode (h2 requires lowercase).

- [ ] **Step 1: Write failing unit tests** in `h2_translate.rs`:
  - `request_from_h2_maps_pseudo_headers`: build `http::Request::builder().method("POST").uri("https://ex.com/v1/x").body(()).unwrap().into_parts()`, call `request_from_h2(&parts, "https", "ex.com:443")`, assert `method=="POST"`, `scheme=="https"`, `authority=="ex.com"`/`"ex.com:443"`, `path=="/v1/x"`, `version==HttpVersion::H2`.
  - `encode_strips_hop_by_hop`: an `HttpRequest` whose `headers` include `Connection: keep-alive` and `Transfer-Encoding: chunked` plus `X-Keep: 1`; assert `h2_request_from(&req)` contains `x-keep` and **does not** contain `connection` or `transfer-encoding`.
  - `response_status_round_trips`: `response_from_h2` of a parts with status 418 → `status==418`, `version==H2`; and `h2_response_from` of an `HttpResponse{status:418}` yields `http::StatusCode::IM_A_TEAPOT`.
- [ ] **Step 2: Run tests, verify they fail** (`request_from_h2` not defined). Run: `cargo test -p aitm-proto-http --test h2_translate`. Expected: FAIL (unresolved name).
- [ ] **Step 3: Implement** the four functions + `HOP_BY_HOP` in `translate.rs` per the Interfaces block. No I/O, no async.
- [ ] **Step 4: Run tests, verify pass.** Expected: PASS.
- [ ] **Step 5: Gate + commit.** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test -p aitm-proto-http`; commit `feat(m7): http<->model h2 head translation + hop-by-hop stripping`.

---

### Task 2: ALPN mirror negotiation + `serve_h2` driver (capture, multiplexing, fallback, forward, short-circuit, caps)

- **Satisfies:** AC-H2.1, AC-H2.2, AC-H2.3, AC-H2.7 (Map Local short-circuit), AC-H2.9 (e2e half), AC-H2.10 (body cap half). The spine of M7.
- **Depends on:** Task 1. **Blocks:** Tasks 3, 4, 5, 6.
- **Files:** Create `crates/aitm-proto-http/src/h2.rs` (`mod h2;` in `lib.rs`). Modify `crates/aitm-proto-http/src/module.rs`: make upstream ALPN dynamic, read client ALPN, negotiate, record, branch to `serve_h2`/`serve`. Tests `crates/aitm-proto-http/tests/h2_mitm.rs`.
- **Interfaces — Consumes:** Task 1's `translate::*`; existing `module.rs` helpers (`Conn`, `Target`, `ModuleCtx`, `flush` n/a for h2); `aitm_core::{Event, Flow, HttpFlow, FlowId, InterceptState, ConnInfo, Body}`; `ctx.emit`, `ctx.store()`, `ctx.connect_upstream`.
- **Interfaces — Produces:**
  ```rust
  // Drive one already-decrypted h2 connection. Both streams speak h2 (mirror).
  // Spawns one task per accepted client stream; returns when the connection closes.
  async fn serve_h2(ctx: ModuleCtx, client_tls: ByteStream, upstream_tls: ByteStream, conn: Conn, max_body: usize, max_concurrent: usize) -> anyhow::Result<()>;
  // HttpModule gains, mirroring with_max_body_bytes:
  pub fn with_max_concurrent_streams(self, max: usize) -> Self; // default const DEFAULT_MAX_CONCURRENT_STREAMS = 128
  ```
- **ALPN changes in `module.rs`** (spec §1):
  - `upstream_tls()` must become **per-connection ALPN**: add `fn upstream_tls_alpn(&self, offer: &[Vec<u8>]) -> Result<Arc<ClientConfig>>` building the client config with `alpn_protocols = offer` (keep a small cache keyed by offer, or rebuild). The old pinned `OnceLock` is replaced/augmented.
  - In `mitm()`: read the client's ALPN from `start.client_hello().alpn()` (iterator of `&[u8]`; absent ⇒ `vec![b"http/1.1".to_vec()]`). Connect upstream with that offer. After the upstream handshake read `upstream.get_ref().1.alpn_protocol()` → `P` (absent ⇒ `http/1.1`).
  - `impersonating_config(&self, leaf, negotiated: &[u8])` sets `alpn_protocols = vec![negotiated.to_vec()]`.
  - Set both `ConnInfo.alpn = Some(P_string)`.
  - Branch: `P == b"h2"` ⇒ `serve_h2(...)`; else existing `serve(...)` unchanged.
  - Fail-closed: if the client offered only `http/1.1` **and** `P == h2` cannot be mirrored (h2-only upstream), log and return an error (spec §1 edge case).
- **`serve_h2` shape** (spec §2): `let (mut srv, _) = h2::server::Builder::new().enable_push(false).max_concurrent_streams(max_concurrent as u32).handshake(client_tls).await?;` and `let (mut send_req, up_conn) = h2::client::Builder::new().enable_push(false).handshake(upstream_tls).await?;` then `tokio::spawn(up_conn)` (drive upstream I/O). Loop `while let Some(accepted) = srv.accept().await { let (req, respond) = accepted?; tokio::spawn(stream_task(...)); }`. Per-stream `stream_task` runs the lifecycle: insert `Flow::Http`, `emit(RequestHeaders)`, drain request body (cap at `max_body`), `emit(Request)`, read post-dispatch flow — if `flow.response` set ⇒ `respond.send_response(h2_response_from(&r), false)` + body, **no upstream** (covers Map Local + short-circuit); else `send_req.send_request(h2_request_from(&req), end_of_stream)` → upstream response → stage + `emit(ResponseHeaders)` → `respond.send_response(...)` → pump upstream `RecvStream` to client `SendStream` capturing a capped copy → set body + `emit(Response)`. (The `Killed`→RST_STREAM branch and response-phase park are **Task 3**; Task 2 handles forward + short-circuit only.)

- [ ] **Step 1: Write failing integration tests** in `h2_mitm.rs` (each stands up a test `h2` origin behind a forged-leaf TLS listener, drives an `h2` client via the module):
  - `h2_end_to_end_capture` (AC-H2.1): h2 client ⇄ h2 origin ⇒ captured `HttpFlow.request.version == HttpVersion::H2`, `client_conn.alpn == Some("h2")`, `server_conn.alpn == Some("h2")`, response body bytes equal the origin's.
  - `h1_only_origin_falls_back` + `h1_only_client_served_over_h1` (AC-H2.2): captured `version == Http11`, `alpn == Some("http/1.1")`; no panic.
  - `three_concurrent_streams_three_flows` (AC-H2.3): client opens 3 concurrent streams ⇒ store holds 3 distinct `FlowId`s, each with its own response.
  - `map_local_short_circuits_h2` (AC-H2.7): a test plugin sets `flow.response` on `Event::Request`; assert the client gets that body with `:status 200` and the origin records **zero** requests.
  - `forward_with_connection_header_succeeds` (AC-H2.9 e2e): a test plugin injects `Connection: keep-alive` via `flow_mut`; the stream completes (header stripped) rather than erroring.
  - `body_over_cap_truncated_copy` (AC-H2.10 half): origin returns a body > `max_body` (module built `with_max_body_bytes(small)`); client receives the **full** body, stored `HttpFlow.response.body` is truncated and `metadata.truncated == true`.
- [ ] **Step 2: Run tests, verify they fail.** Run: `cargo test -p aitm-proto-http --test h2_mitm`. Expected: FAIL (`serve_h2`/ALPN not wired; h2 negotiation absent).
- [ ] **Step 3: Implement** the ALPN changes in `module.rs` and `serve_h2`/`stream_task` in `h2.rs` per the Interfaces/shape above. Add `with_max_concurrent_streams`. Keep `serve()` (h1) untouched.
- [ ] **Step 4: Run tests, verify pass.** Expected: PASS.
- [ ] **Step 5: Gate + commit.** Full gate; commit `feat(m7): h2 ALPN mirror negotiation + serve_h2 driver (capture, multiplexing, h1 fallback, short-circuit)`.

---

### Task 3: Interception semantics on h2 — per-stream park (no stall), response-phase edit, kill modes

- **Satisfies:** AC-H2.4, AC-H2.5, AC-H2.6.
- **Depends on:** Task 2. Same files as Task 2 (`h2.rs`) — **one writer**.
- **Files:** Modify `crates/aitm-proto-http/src/h2.rs` (`stream_task` post-dispatch handling). Tests append to `crates/aitm-proto-http/tests/h2_mitm.rs`.
- **Interfaces — Consumes:** Task 2's `serve_h2`/`stream_task`; `InterceptState::Killed`; the intercept plugin (`aitm-plugins`) + `flow.mutate`/`flow.resume`/`flow.kill` commands driven through the registry in the test; `h2::server::SendResponse::send_reset`, `h2::Reason::{CANCEL, INTERNAL_ERROR}`.
- **Change:** extend `stream_task`'s post-dispatch match:
  - `InterceptState::Killed` with kill-mode `reset` ⇒ `respond.send_reset(h2::Reason::CANCEL)` on that stream (connection stays open). Kill-mode `429`/`503` are already a short-circuit (`flow.response` set by the kill command) ⇒ handled by Task 2's short-circuit branch; verify no upstream stream opened.
  - **Response-phase park:** the intercept plugin parks at `Event::ResponseHeaders`; because `emit(ResponseHeaders)` is awaited **before** `respond.send_response`, the parked stream task suspends and no response byte reaches the client until `flow.resume`; then the (possibly edited) status/headers/body are encoded. This is the h2 analogue of the h1 response-await guarantee (M6 F3 / spec §6).
  - Per-stream tasking (from Task 2) is what makes parking stream A not block B/C; this task adds the test that proves it.
- [ ] **Step 1: Write failing tests:**
  - `intercept_one_stream_others_complete` (AC-H2.4): an intercept rule matches `/admin`; client opens 3 concurrent streams (`/admin`, `/a`, `/b`). Assert `/admin`'s flow is `InterceptState::Intercepted` while `/a` and `/b` **complete** on the same connection; after `flow.resume` of `/admin`, it completes too.
  - `h2_request_mutate_reaches_origin` (AC-H2.5 req): park at request phase, `flow.mutate` adds `X-Edit: 1`, resume ⇒ the test origin receives `x-edit: 1`.
  - `h2_response_status_418` (AC-H2.5 resp): park at response phase, `flow.mutate {edits:{status:418}}`, resume ⇒ client receives h2 `:status 418` with the edited body.
  - `h2_kill_reset_is_rst_stream` (AC-H2.6): `flow.kill {mode:"reset"}` ⇒ client observes that stream reset while a second stream on the same connection still completes.
  - `h2_kill_429_no_upstream` (AC-H2.6): `flow.kill {mode:"429"}` ⇒ client gets `:status 429`, origin records **zero** requests for that flow.
- [ ] **Step 2: Run, verify fail.** `cargo test -p aitm-proto-http --test h2_mitm`. Expected: FAIL.
- [ ] **Step 3: Implement** the post-dispatch extensions in `stream_task`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Gate + commit.** `feat(m7): h2 interception — per-stream park, response-phase edit, kill-as-RST_STREAM`.

---

### Task 4: Map Remote cross-origin — a per-stream upstream to a rewritten host

- **Satisfies:** AC-H2.8. (AC Map Local is Task 2; AC Map Remote **same-origin** rides Task 2's forward path. This task is the **different-origin** case the spec §6 calls out.)
- **Depends on:** Task 2. Same file (`h2.rs`) — **one writer** (after Task 3, or a merge-ordered worktree).
- **Files:** Modify `crates/aitm-proto-http/src/h2.rs`. Tests append to `h2_mitm.rs`.
- **Interfaces — Consumes:** Task 2's `stream_task`; `ModuleCtx::connect_upstream` (scope/SSRF-guarded); the maprules plugin (`aitm-plugin-maprules`) driven through the registry; the upstream TLS+h2 handshake helper from Task 2.
- **Change:** when the forwarded request's `authority` differs from the connection's pinned origin (a Map Remote rewrite), `stream_task` must open a **second** upstream: `ctx.connect_upstream(&new_authority, addr)` (which runs `ScopeRateGuard::check_active`; an out-of-scope target returns `Err`, surfaced so the stream is refused and the original is not sent), TLS-connect + `h2::client::handshake` to the new origin, and send the request there. A small `get_or_open_upstream(authority) -> Result<SendRequest>` helper caches per-authority upstream handles for the connection's lifetime. The default (pinned) origin keeps using the connection's shared `send_req`.
- [ ] **Step 1: Write failing tests:**
  - `map_remote_h2_to_in_scope_host` (AC-H2.8): a Map Remote rule rewrites `old.example`→`new.example` (in scope); the request reaches the `new.example` test origin, not `old.example`.
  - `map_remote_h2_out_of_scope_refused` (AC-H2.8 / Review focus 5): the same rule to an out-of-scope target ⇒ the stream is refused (guard error surfaced) and **neither** origin records the request.
- [ ] **Step 2: Run, verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** `get_or_open_upstream` + the cross-origin branch.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Gate + commit.** `feat(m7): Map Remote cross-origin upstream for h2 streams (scope-gated)`.

---

### Task 5: `LimitConfig.max_concurrent_streams` + binary wiring + header-block caps

- **Satisfies:** AC-H2.10 (concurrent-stream bound). The one additive `aitm-core` edit.
- **Depends on:** Task 2 (`with_max_concurrent_streams`). **Disjoint files from Tasks 3/4** (may fan out).
- **Files:** Modify `crates/aitm-core/src/config.rs` (add field + default), `crates/aitm/src/**` (wire `limits.max_concurrent_streams` into `HttpModule::with_max_concurrent_streams`, alongside the existing `with_max_body_bytes` wiring), and the YAML config parsing (`deny_unknown_fields` must accept the new key). Tests in `aitm-proto-http/tests/h2_mitm.rs` (bound behaviour) + a config-parse test wherever the binary's config test lives.
- **Interfaces — Produces:** `LimitConfig.max_concurrent_streams: u32` (default e.g. `128`). **Consumes:** Task 2's `with_max_concurrent_streams`; the `h2` builder's `max_concurrent_streams` + `max_header_list_size` / `max_send_buffer_size` caps (finite values chosen by the builder, Review focus 4).
- **Change:** add the field additively to `LimitConfig` and its `Default`; thread it through the binary's module construction; set finite HPACK/header-list caps on both `h2` builders in `h2.rs` (if not already set in Task 2).
- [ ] **Step 1: Write failing tests:**
  - `concurrent_streams_bounded` (AC-H2.10): module built `with_max_concurrent_streams(2)`; a client attempting a 3rd concurrent stream is held to the SETTINGS bound (the 3rd does not proceed until one completes) rather than all three buffering.
  - `config_parses_max_concurrent_streams`: a YAML with `limits.max_concurrent_streams: 64` parses to `64`; default (absent) is `128`; an unknown sibling key still errors (`deny_unknown_fields`).
- [ ] **Step 2: Run, verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** the field + wiring + builder caps.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Gate + commit.** `feat(m7): max_concurrent_streams config + binary wiring + finite h2 header caps`.

---

### Task 6: Whole-branch integration sweep + session/HAR version tag

- **Satisfies:** AC-H2.11; confirms the full AC-H2.* set green together.
- **Depends on:** Tasks 1–5. **W3.**
- **Files:** Tests only — `crates/aitm-proto-http/tests/h2_mitm.rs` (or a new `h2_integration.rs`), plus a session/HAR round-trip test wherever `aitm-plugin-sessionio` tests live. No production change expected; if `HttpVersion::H2` does not already serialize to the right HAR/session tag, the **minimal** fix lands in `aitm-plugin-sessionio` (not core) and is called out in the Coder's report.
- **Interfaces — Consumes:** the whole branch; `aitm-plugin-sessionio`'s serde mirror + HAR mapping (M6 F10).
- [ ] **Step 1: Write tests:**
  - `h2_flow_session_round_trips` (AC-H2.11): capture an h2 flow, `session.save` then `session.load` into a fresh store ⇒ reloaded flow has `version == HttpVersion::H2`.
  - `h2_flow_har_version_tag` (AC-H2.11): `flow.export {format:"har"}` of an h2 flow records `httpVersion == "HTTP/2"` for that entry.
  - `full_h2_acceptance_sweep` (smoke): one test exercising capture → intercept → mutate → resume → response on an h2 flow end to end, as a regression guard over Tasks 2–3.
- [ ] **Step 2: Run, verify fail** (version tag / any gap). Expected: FAIL where the tag or behaviour is missing.
- [ ] **Step 3: Implement** the minimal `HttpVersion::H2` ↔ `"HTTP/2"` mapping in `aitm-plugin-sessionio` only if a test shows it missing; otherwise no production change.
- [ ] **Step 4: Run, verify pass.** Then run the **whole** gate across the workspace: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- [ ] **Step 5: Gate + commit.** `test(m7): whole-branch h2 integration sweep + session/HAR HTTP/2 tag`.

---

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 2 | spec | PASS | All 6 Task-2 ACs implemented + tested with literal values; deviations justified; scope clean; h1 `serve()` byte-for-byte unchanged. | No action. |
| 2 | security | Important | `serve_h2` applies no idle/read timeout (bare awaits on handshakes, `accept`, `req_body.data`, `resp_fut`, `resp_body.data`, `poll_capacity`); slowloris / hung-upstream pins stream tasks + connection forever (spec §4; h1 uses `READ_TIMEOUT`). | **Fixed in 42a97f1** — `wire()`/`wire_within()` bounds every h2 wire await at `READ_TIMEOUT=30s`; `emit` dispatch not wrapped; accept-loop teardown guarded by an in-flight `AtomicUsize` so a long-parked stream is never killed by the connection idle timeout. |
| 2 | quality | Important | h2 stream/connection errors swallowed into `tracing::debug!` with no `Event::Error` on the still-open flow, unlike h1 (`module.rs:684-691`); operator/agent + M4 error bus never learn the flow failed (spec §2). | **Fixed in 42a97f1** — `stream_task` splits setup from a fallible `drive_stream`; on any `Err` (incl. timeout) it emits `Event::Error{flow, FlowError::Upstream}` before bailing; upstream conn-future log raised debug→warn. |
| 2 | security | Minor | Oversized request body fully drained (keeps granting window) instead of reset at the cap; the 413 flow emits only `RequestHeaders`, left non-terminal. | **Fixed in 42a97f1** — breaks at the breach (stops granting window, RST_STREAMs inbound) and records the 413 as the flow response with ResponseHeaders/Response emitted. |
| 2 | quality | Minor | Request-oversized 413 branch untested (only the response cap is covered). | **Fixed in 42a97f1** — new test `request_body_over_cap_is_refused_413`. |
| 2 | quality | Minor | Plugin-replaced response body drops the upstream `RecvStream` undrained (no capacity release); reachable once Task 3 response-edit is active. | **Fixed in 42a97f1** — explicit `drop` of the undrained `RecvStream` (h2 sends RST_STREAM(CANCEL) + releases recv window on drop; documented inline). |
| 2 | security | Minor | `max_concurrent as u32` truncates for values > u32::MAX (latent; default 128). | **Fixed in 42a97f1** — `u32::try_from(..).unwrap_or(u32::MAX)` (saturating). |
| 2 | security | Minor | Explicit HPACK / max-header-list caps not yet set (relies on `h2` finite defaults). | **Fixed in 42a97f1** — both builders set `max_header_list_size`=64 KiB, `header_table_size`=4 KiB. |
| 2 | quality | Minor | Duplicated cap-and-send scaffolding (`cap_extend` / `send_buffered` not factored). | **Accepted** (optional cleanup; not blocking). |
| 2 | quality | Minor | `three_concurrent_streams_three_flows` proves fan-out, not in-flight independence. | **Accepted** — Task 3's `intercept_one_stream_others_complete` proves stall-independence. |
| fix | coder | tradeoff | No literal 30s wall-clock E2E stalled-origin test (would need a `with_read_timeout` builder in out-of-scope `module.rs`; a 30s gate test is undesirable). | **Accepted** — behaviour covered fast/hermetically by `wire_times_out_on_a_stalled_await` (20 ms) + `upstream_closing_early_emits_flow_error`; a `with_read_timeout` builder is a flagged optional follow-up. |

**Task 2 panel disposition (2026-10-29):** spec PASS; security + quality FAIL on two Important findings (no idle/read timeout; errors not surfaced as `Event::Error`). Both confirmed against spec §2/§4 — happy path, ALPN, guard routing, hop-by-hop all clean. Resolved by one fresh-Coder **fix task** merged at `4cdc425` (commit `42a97f1`): both Importants + all three bundled Minors + the two formerly-deferred Minors (u32 clamp, explicit HPACK caps) fixed; two Minors accepted. Task 3 (kill→RST_STREAM) merged at `3d2ee37`; Task 5 (max_concurrent_streams config + wiring, `fc58337`) merged at `4785ac1`. Remaining before integration: Task 4 (Map Remote cross-origin), main sync, Task 6 whole-branch gate + panel.

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
