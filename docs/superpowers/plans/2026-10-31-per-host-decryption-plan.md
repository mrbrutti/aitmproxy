# Per-host decryption and visible tunnels — implementation plan

**Status:** approved — self-approved 2026-10-31 by the per-host-decryption session
(autonomous mode). Implemented 2026-11-01; stage 5 PASS ×2, stage 6 panel re-checked
to PASS; PR mrbrutti/aitmproxy#228 open against `main` (head carries `origin/main`
42cdaf2e). Stage 7 (merge, Shipped section) is the orchestrator's.
**Spec:** `docs/superpowers/specs/2026-10-31-per-host-decryption-design.md`
**Branch / worktree:** `claude/youthful-kapitsa-c196d6` off `main` 144cdcc8,
`/Users/matt/Security/aitmproxy/.claude/worktrees/youthful-kapitsa-c196d6`

## Overview

Bottom up: the flow model and store rule first (Task 1), then the chain's passive
dispatch (2), then the scope seams every module reads (3) and the shared tunnel
recorder/relay (4). With those in place the two producers change: the passthrough
module (5) and the HTTP module's CONNECT path (6) plus passive stamping (7). Then the
surfaces (8), status/advice/session persistence (9), docs (10), the existing-test
migration and the live e2e cell (11). Tasks 1→2→3→4 are sequential; 5 and 6/7 depend
on 3+4 and touch disjoint crates (may run in parallel); 8 and 9 depend on 1 only and
touch disjoint files from 5–7 (may run in parallel with them); 10 is docs-only; 11
runs last on the whole branch. One Coder per task, commit per task, Tester after 7 and
after 11, panel on the whole branch.

Conventions for every task: TDD (failing test first, shown in the report); no
`unwrap()` on wire data; no new `warn` logs; `cargo fmt`, `clippy -D warnings` and the
crate's tests green before the commit; the full gate before hand-off.

## Tasks

### Task 1: Flow model — `FlowMeta.passive`, `FlowMeta.tunnel`, terminal rule

- **Satisfies:** AC12, groundwork for AC11
- **Depends on:** none
- **Files:** `crates/aitm-core/src/flow.rs` (modify), `crates/aitm-core/src/store.rs`
  (modify), `crates/aitm-core/src/lib.rs` (re-exports), every explicit `FlowMeta {`
  literal without `..Default::default()`: `crates/aitm-core/src/client.rs`,
  `crates/aitm-core/tests/flow_model.rs`, `crates/aitm-plugins/tests/{detail,mutate}.rs`,
  `crates/aitm-plugin-sessionio/src/native.rs` (`rec_to_meta` + two tests),
  `crates/aitm-mcp/tests/mcp.rs`, `crates/aitm-plugin-passthrough/src/module.rs`,
  `crates/aitm-proto-ws/src/module.rs` (tests), `crates/aitm-plugin-rhai/tests/{poc_step,host_net}.rs`;
  `crates/aitm-core/tests/store.rs` (add tests).
- **Change:** in `flow.rs` add
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum TunnelMode { Decrypted, Passthrough, Failed }
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum TunnelReason { OutOfScope, Pinned, ClientRejectedCertificate, ClientClosed,
      ClientTlsError, UpstreamUnreachable, UpstreamTlsFailed, ProtocolError }
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct TunnelInfo { pub mode: TunnelMode, pub reason: Option<TunnelReason>,
      pub bytes_up: Option<u64>, pub bytes_down: Option<u64> }
  impl TunnelMode { pub fn label(&self) -> &'static str }   // "decrypted" | "passthrough" | "failed"
  impl TunnelReason { pub fn label(&self) -> &'static str } // snake_case codes of spec D5/D7
  impl TunnelInfo { pub fn passthrough(reason: TunnelReason) -> Self; pub fn decrypted() -> Self;
      pub fn failed(reason: TunnelReason) -> Self; pub fn is_closed(&self, meta_duration: Option<Duration>) -> bool }
  ```
  `FlowMeta` gains `pub passive: bool` (default `false`) and `pub tunnel:
  Option<TunnelInfo>` (default `None`); `Default` and `with_attribution` set both
  defaults. `store.rs::is_terminal`: for `Flow::Http` with `metadata.tunnel.is_some()`
  return `metadata.duration.is_some()` (before the response rule; interception rules
  stay first). Re-export `TunnelInfo, TunnelMode, TunnelReason` from `lib.rs`.
- **Test:** `flow_model.rs`: `tunnel_labels_are_the_wire_codes` (every variant's
  `label()` equals the documented string, e.g. `TunnelReason::ClientRejectedCertificate
  .label() == "client_rejected_certificate"`), `flow_meta_defaults_are_not_passive_and_not_a_tunnel`.
  `store.rs` tests: `open_tunnel_row_is_kept_by_clear_and_eviction` (a `CONNECT`
  flow with `tunnel: Some(passthrough)`, `response: Some(200)`, `duration: None` →
  `clear()` returns `skipped_in_flight == 1`, `cleared == 0`; with `max_flows = 1`
  an insert does not evict it) and `closed_or_failed_tunnel_row_is_cleared`
  (`duration: Some(..)` with and without a response → `cleared == 1`).
- **Done when:** those tests pass, the workspace compiles (`cargo build --all-targets`),
  and the full gate passes.

### Task 2: Chain passive dispatch

- **Satisfies:** AC10
- **Depends on:** Task 1
- **Files:** `crates/aitm-core/src/plugin.rs` (modify), `crates/aitm-core/src/chain.rs`
  (modify), `crates/aitm-plugins/src/subscription.rs` (modify),
  `crates/aitm-core/tests/chain.rs` (add), `crates/aitm-plugins/tests/` (add a small
  `subscription.rs` or extend an existing file).
- **Change:** `Plugin` gains `fn observes_passive_flows(&self) -> bool { false }` with
  a doc comment (spec D4). `Chain::dispatch`: after cloning the flow compute
  `let passive = flow.metadata().passive || flow.metadata().tunnel.is_some();` and in
  the plugin loop `if passive && !p.observes_passive_flows() { continue; }`. A passive
  dispatch never parks: if `ctx.take_parked()` is `Some` on a passive flow, log at
  `debug` and ignore it (only an opted-in plugin could do it; none does). Keep the
  write-back merge. `SubscriptionPlugin::observes_passive_flows` → `true`.
- **Test:** `chain.rs`: `passive_flow_reaches_only_observers` — two recording
  plugins, one with `observes_passive_flows() == true`; dispatch `Event::Request` on a
  flow with `passive = true`: the observer's log has the event, the other's is empty,
  verdict `Continue`; repeat with `passive = false, tunnel: Some(..)` (same result);
  repeat with neither → both logs have the event. `passive_flow_is_never_parked` — an
  intercepting plugin (the existing `Intercept` test plugin) on a passive flow:
  `dispatch` returns immediately (`timeout(100ms)` completes) and the stored flow stays
  `Observed`. `subscription.rs`: `subscription_plugin_observes_passive_flows`
  asserts `SubscriptionPlugin::new(tx).observes_passive_flows()` and that an event on a
  passive flow dispatched through a real `Chain` arrives on the broadcast receiver.
- **Done when:** tests pass, gate passes.

### Task 3: Scope seams — `ModuleCtx::with_scope`, `tunnel_authority`, passthrough claims out-of-scope

- **Satisfies:** AC7, AC8, AC14; groundwork for AC1–AC4, AC16
- **Depends on:** Task 1
- **Files:** `crates/aitm-core/src/protocol.rs` (modify), `crates/aitm-core/src/proxy.rs`
  (modify: attach guard; make `parse_client_hello_sni` `pub`), `crates/aitm/src/ingress.rs`
  (modify: attach `sd.guard`), `crates/aitm/src/wire.rs` (modify: `LateGuard` for the
  passthrough module, bound after build), `crates/aitm-plugin-passthrough/src/module.rs`
  (modify), `crates/aitm-plugin-passthrough/tests/tunnel.rs` (modify: pass a scope),
  `crates/aitm/tests/m6_wiring.rs` (modify), `crates/aitm-core/tests/upgrade_handoff.rs`
  or a new `crates/aitm-core/tests/scope_seam.rs` (add).
- **Change:**
  - `ModuleCtx`: field `scope: Option<Arc<dyn ScopeRateGuard>>`; `pub fn
    with_scope(mut self, guard: Arc<dyn ScopeRateGuard>) -> Self`; `pub fn
    in_scope(&self, authority: &str) -> bool { self.scope.as_ref().is_some_and(|g| g.in_scope(authority)) }`;
    `for_upgrade` copies `scope`. Doc: deny-by-default.
  - `NextLayerHint::tunnel_authority(&self) -> Option<Authority>`: parse a leading
    `CONNECT <authority> ` from `first_bytes` (`Authority::parse_with_default(.., 443)`),
    else from `client_hello_sni` with port `self.dst.port()` when
    `capture_interface.is_some()` else 443; `None` otherwise. Lowercased/normalised by
    `Authority::new`.
  - `proxy.rs::handle_conn`: `.with_scope(inner.guard.clone())`; `ingress.rs::dispatch_tcp`:
    `.with_scope(sd.guard.clone())`.
  - `PassthroughModule`: field `scope: Option<Arc<dyn ScopeRateGuard>>`, `pub fn
    with_scope(self, guard) -> Self`; `matches`: `let Some(auth) = hint.tunnel_authority()
    else { return false; }` then `self.list.contains_host(&auth.host) || !self.scope.as_ref()
    .is_some_and(|g| g.in_scope(&auth.to_string()))` — pinned or not in scope (no scope
    handle ⇒ claims everything). Record which (`PassthroughCause`/`TunnelReason::Pinned`
    vs `OutOfScope`) for Task 5 via a small `fn passthrough_reason(&self, auth) -> TunnelReason`.
  - `wire.rs`: `let tunnel_guard = Arc::new(LateGuard::default());` passed into
    `ordered_modules(http, passthrough_list, inject, tunnel_guard.clone())` (signature
    gains the guard), bound right after `builder.build()` alongside `map_guard.bind`.
    `LateGuard::in_scope` already forwards.
- **Test:** `protocol.rs`/`scope_seam.rs`: `module_ctx_without_scope_is_never_in_scope`
  (`ModuleCtx::new(..).in_scope("example.com:443") == false`),
  `module_ctx_with_scope_forwards_to_the_guard` (a `StdGuard` with `example.com` →
  true for `example.com:443` and `example.com:8443`; false for `other.test:443`),
  `tunnel_authority_from_connect_line` (`b"CONNECT Example.COM:8443 HTTP/1.1\r\n..."` →
  `example.com:8443`; `CONNECT [::1]:443` → host `::1`), `tunnel_authority_from_sni_defaults_443_on_the_proxy_path`,
  `tunnel_authority_from_sni_uses_dst_port_on_the_capture_path` (`capture_interface:
  Some("macos-ne")`, `dst` port 8443 → `host:8443`). Passthrough `module.rs` tests:
  `claims_pinned_host_even_when_in_scope` (reason `Pinned`), `claims_out_of_scope_host`
  (reason `OutOfScope`), `does_not_claim_in_scope_unpinned_host`,
  `without_a_scope_handle_claims_every_tls_connection`, `matching_follows_scope_entry_rules`
  (bare host admits 8443; `host:443` rejects 8443; `*.example.com` admits `api.example.com`).
  `m6_wiring.rs`: `passthrough_module_ordered_before_http` passes a guard and asserts
  the module no longer claims an in-scope host. `ingress.rs` test: a stub module
  records `ctx.in_scope(authority)` for an in-scope captured flow → `true`.
- **Done when:** tests pass, gate passes (`tunnel.rs` already seeds `127.0.0.1` for
  its MITM host; pass the same `StdGuard` to the passthrough module there).

### Task 4: Shared tunnel recorder, relay and failure classifier (`aitm-core::tunnel`)

- **Satisfies:** AC5, AC6 (classification), groundwork for AC1–AC3, AC11
- **Depends on:** Task 1
- **Files:** `crates/aitm-core/src/tunnel.rs` (create), `crates/aitm-core/src/lib.rs`
  (export), `crates/aitm-core/src/proxy.rs` (reuse `is_client_abort` or move it).
- **Change:**
  ```rust
  pub struct TunnelRow { id: FlowId, created: SystemTime }
  impl TunnelRow {
      /// Insert the CONNECT row (request CONNECT host:port, headers, client/server conn,
      /// `metadata.created = opened_at`, `metadata.tunnel = info`, `response` = 200 for
      /// Decrypted/Passthrough, None for Failed; `duration` set now for Failed) and emit
      /// `Event::RequestHeaders`; for Failed also emit `Event::Response` and return.
      pub async fn open(ctx: &ModuleCtx, req: TunnelRequest, info: TunnelInfo) -> TunnelRow;
      /// Close: set `duration = now - created`, bytes (passthrough), emit `Event::Response`.
      pub async fn close(self, ctx: &ModuleCtx, bytes: Option<(u64, u64)>);
      /// Fail an already-open row (decrypted tunnel that errors before any request is
      /// not possible — open happens at establishment — so this is for passthrough
      /// relays that error at once): sets mode Failed + reason, duration, emits Response.
      pub async fn fail(self, ctx: &ModuleCtx, reason: TunnelReason);
  }
  pub struct TunnelRequest { pub authority: Authority, pub headers: HeaderMap,
      pub client: ConnInfo, pub server: Option<ConnInfo>, pub opened_at: SystemTime,
      pub source_app: Option<String>, pub capture_interface: Option<String> }
  /// Copy both ways until either side closes; counts survive an error.
  pub async fn relay(client: &mut ByteStream, upstream: &mut ByteStream) -> (u64, u64, io::Result<()>);
  /// By type only: client-side handshake/IO error → ClientRejectedCertificate |
  /// ClientClosed | ClientTlsError (alerts of the certificate family listed in spec D5
  /// → rejected; EOF/reset/broken pipe → closed; other rustls errors → tls error;
  /// anything else → ProtocolError).
  pub fn classify_client_failure(err: &anyhow::Error) -> TunnelReason;
  ```
  `relay` wraps the client in a `Counted` adapter (AsyncRead/AsyncWrite, two
  `AtomicU64`s or plain counters read after the copy) around `copy_bidirectional`, so a
  `ConnectionReset` mid-way still reports the bytes moved. The row's `scheme` is
  `"https"`, `path` empty, body `Body::Empty`, `intercept: Observed`, `passive: false`.
- **Test:** `tunnel.rs` unit tests with a recording `EventSink` and `MemFlowStore`:
  `open_passthrough_row_is_200_open_and_pushes_created` (row fields; one
  `RequestHeaders` event; `is_terminal`-visible: `store.clear()` skips it),
  `close_sets_duration_and_bytes_and_pushes_response`, `open_failed_row_has_no_status_and_is_closed`
  (`response == None`, `duration.is_some()`, events `RequestHeaders` + `Response`),
  `fail_after_open_flips_mode_to_failed`, `relay_counts_survive_a_reset` (duplex pair;
  write 5 bytes up, 7 down, drop the far end → `(5, 7, Err/Ok)`),
  `classifies_client_failures_by_type` (one assertion per code: `AlertReceived(UnknownCA)`
  → rejected, `AlertReceived(CertificateUnknown)` → rejected, `AlertReceived(HandshakeFailure)`
  → tls error, `io::ErrorKind::UnexpectedEof` → closed, `ConnectionReset` → closed,
  `FlowError::Protocol` → protocol error; wrapped in `anyhow` context like the module does).
- **Done when:** tests pass, gate passes.

### Task 5: Passthrough module records rows through the recorder

- **Satisfies:** AC1 (unit half), AC6 (passthrough dial failure), AC7
- **Depends on:** Tasks 3, 4
- **Files:** `crates/aitm-plugin-passthrough/src/module.rs` (modify),
  `crates/aitm-plugin-passthrough/tests/tunnel.rs` (modify/add),
  `crates/aitm-core/src/config.rs` + `crates/aitm/src/config_file.rs` doc comments
  on `TlsConfig` (the "every host is MITM'd until pinned" sentence is now wrong).
- **Change:** `tunnel()` records `opened_at` when the head is read; on dial failure
  opens a `TunnelInfo::failed(UpstreamUnreachable)` row and returns the error; on
  success acks, opens `TunnelInfo::passthrough(self.passthrough_reason(&auth))`,
  relays with `aitm_core::tunnel::relay`, then `close(Some((up, down)))`. Remove the
  `tunnelled` mark and the comment write. Carry the hint's attribution into the row
  (`source_app`, `capture_interface`), closing the follow-up noted in the
  ne-source-app plan.
- **Test:** `tunnel.rs`: the existing `passthrough_tunnels_mitm_still_decrypts`
  asserts the row via `metadata.tunnel == Some(passthrough, reason Pinned)` with
  `bytes_up > 0 && bytes_down > 0`, `duration.is_some()` after the client closes, and
  `response.status == 200`; new `out_of_scope_host_is_tunnelled_with_reason_out_of_scope`
  (not pinned, not in scope → passthrough row reason `OutOfScope`, client sees the
  origin's cert, no decrypted row); `passthrough_dial_failure_is_a_failed_row`
  (connector that errors → row `failed/upstream_unreachable`, `response == None`).
- **Done when:** tests pass, gate passes.

### Task 6: HTTP module — CONNECT rows (decrypted / failed) and the out-of-scope relay

- **Satisfies:** AC2 (unit), AC3 (unit), AC5, AC6, AC16
- **Depends on:** Tasks 3, 4
- **Files:** `crates/aitm-proto-http/src/module.rs` (modify: `drive`, `mitm`),
  `crates/aitm-proto-http/src/h2.rs` (no change expected beyond returning), new
  `crates/aitm-proto-http/tests/tunnel_rows.rs` (create; reuse the fixtures of
  `https_capture.rs`).
- **Change:** in `drive` on `CONNECT`: `opened_at = now`; parse (error →
  `TunnelRow::open(.., failed(ProtocolError))`, close client, return the error);
  `authority = Authority::parse_with_default(&authority, 443)`; if
  `!ctx.in_scope(&authority.to_string())` → `relay_out_of_scope(client, ctx, authority,
  opened_at)`: resolve, `connect_upstream` (error → failed row `UpstreamUnreachable`),
  ack, `TunnelRow::open(passthrough(OutOfScope))`, `relay`, `close(Some(bytes))`;
  return. Else ack and continue as today, passing `opened_at` + the CONNECT headers
  into `mitm`. In `mitm`: on each error path before the client handshake completes,
  open a failed row with the matching reason (`UpstreamUnreachable` for the dial,
  `UpstreamTlsFailed` for `tls_handshake`, `ProtocolError` for the h2 mirror refusal
  and the no-SNI case, `classify_client_failure(&e)` for the client handshake) and
  return the original error unchanged (log classification untouched). On success open
  `TunnelInfo::decrypted()` (200), run `serve`/`serve_h2`, then `close(None)` whatever
  the result (duration). The cleartext-inside-CONNECT branch opens a decrypted row
  with `client_conn.tls = false` and closes it after `serve`. Raw TLS (no CONNECT):
  the authority is `hint.tunnel_authority()` (or the SNI read by the acceptor with
  port 443 when the hint lacks it); `!in_scope` → the same relay (the `Prefixed` buffer
  still holds the ClientHello; extend `Prefixed::peek` to pull up to 16 KiB first so
  the SNI can be read with `aitm_core::proxy::parse_client_hello_sni`); no SNI →
  failed/`ProtocolError` row + today's error.
- **Test:** `tunnel_rows.rs` (real acceptor, `HttpModule` **only** — no passthrough
  module — so AC16 is proven by construction; a `StdGuard` seeded per test):
  `in_scope_connect_records_a_decrypted_row_and_its_inner_request` (row `CONNECT
  127.0.0.1:<port>`, `tunnel decrypted`, `status 200`, `duration None` while the client
  holds the connection, `Some` after it closes; the `GET /secret` row has `passive
  false`); `out_of_scope_connect_is_relayed_not_decrypted` (empty scope → client sees
  the origin's own cert, row `passthrough/out_of_scope` with bytes, no `GET` row);
  `client_that_rejects_our_leaf_is_a_failed_row` (client trusting only an unrelated
  root → handshake error; row `failed/client_rejected_certificate`, `status None`,
  `duration Some`); `connect_then_eof_is_client_closed`; `unreachable_origin_is_upstream_unreachable`
  (CONNECT to a closed loopback port in scope); `origin_tls_failure_is_upstream_tls_failed`
  (origin that closes after the TCP accept, in scope); `malformed_connect_is_protocol_error`;
  `scope_add_decrypts_the_next_connection_not_the_open_one` (AC2/AC4: open a
  passthrough connection, `guard.add_scope`, that connection stays a relay — a second
  request on it is still not captured — while a new connection is decrypted);
  `scope_remove_tunnels_the_next_connection_not_the_open_one` (AC3/AC4 mirror).
- **Done when:** tests pass, the existing `https_capture.rs` / `h2_mitm.rs` /
  `stale_upstream.rs` suites still pass, gate passes.

### Task 7: Passive stamping — cleartext per request, tunnel/h2/WS inheritance

- **Satisfies:** AC4 (inner requests), AC9 (unit)
- **Depends on:** Tasks 2, 3
- **Files:** `crates/aitm-proto-http/src/module.rs` (`Conn`, `serve`),
  `crates/aitm-proto-http/src/h2.rs` (`stream_task`), `crates/aitm-proto-ws/src/module.rs`
  (`inherit_attribution`), tests in `crates/aitm-proto-http/tests/tunnel_rows.rs`
  (extend) and `crates/aitm-proto-ws/src/module.rs` (extend the attribution tests).
- **Change:** `Conn` gains `passive: bool` (false for every tunnel; `Conn::plain(..)`
  with no tunnel starts false and `serve` recomputes per request: `let passive =
  conn.tunnel_authority.is_none() && !ctx.in_scope(&authority);` before inserting,
  stamped on the flow's `metadata.passive`). `Conn::flow_meta()` carries `passive`.
  `inherit_attribution` copies `passive` from the handshake meta (rename to
  `inherit_meta` if clearer; marks/comment/timing still fresh).
- **Test:** `tunnel_rows.rs`: `plain_http_to_an_out_of_scope_host_is_passive_and_not_acted_on`
  (empty scope; a test plugin that parks on `Request` is registered; `GET
  http://127.0.0.1:<port>/x` through the proxy returns 200 at once; the stored flow
  has `passive true`, `intercept Observed`; the parking plugin's log is empty) and the
  mirror `plain_http_to_an_in_scope_host_is_acted_on` (same plugin parks it; `passive
  false`); `requests_inside_a_decrypted_tunnel_are_not_passive_even_after_scope_remove`
  (AC4). WS: `websocket_flow_inherits_passive_from_its_handshake` (true→true, false→false).
- **Done when:** tests pass, gate passes.

### Task 8: Surfaces — rows, summary, detail, push, schemas

- **Satisfies:** AC11
- **Depends on:** Task 1
- **Files:** `crates/aitm-plugins/src/capture.rs` (`row_fields`, `flow_row`,
  `summary_fields`, `summarize`), `crates/aitm-plugins/src/detail.rs` (`meta`),
  `crates/aitm-mcp/src/server.rs` (`flow_summary`), `crates/aitm-plugins/tests/capture.rs`,
  `crates/aitm-plugins/tests/detail.rs`, `crates/aitm-mcp/tests/mcp.rs`
  (`push_summary_equals_flow_get_for_http_and_websocket_flows`: add a passthrough row,
  a failed row and a passive flow to the compared set).
- **Change:** add to both row and summary: `tunnel` (`Str|Null`), `tunnel_reason`
  (`Str|Null`), `bytes_up` / `bytes_down` (`Int|Null`), `passive` (`Bool`, required);
  WebSocket rows emit `tunnel: null`, `tunnel_reason: null`, `bytes_*: null`, `passive`
  from meta. `detail.rs::meta` adds `"passive": Bool` and `"tunnel": Object{mode, reason,
  bytes_up, bytes_down} | Null`. `flow_summary` mirrors the keys exactly (same spelling).
  Schema descriptions quote the value sets of spec D7.
- **Test:** `capture.rs`: `flow_table_and_flow_get_report_tunnel_fields` (three
  flows: passthrough `out_of_scope` with bytes 10/20, failed `client_rejected_certificate`,
  ordinary GET → literal expected values per key on both verbs) and
  `flow_table_and_flow_get_report_passive`; `schemas_declare_tunnel_and_passive`
  (the five names present with the right `TypeDesc`); `detail.rs`:
  `detail_meta_reports_tunnel_object_and_passive`; `mcp.rs` parity test extended and
  green.
- **Done when:** tests pass, gate passes.

### Task 9: `proxy.status.decrypt`, startup advice, session persistence, `scope.add` text

- **Satisfies:** AC13, AC15 (text only; gate untouched)
- **Depends on:** Task 1
- **Files:** `crates/aitm-plugins/src/control.rs` (modify), `crates/aitm-plugins/src/scope.rs`
  (descriptions only), `crates/aitm/src/web/mod.rs` (`startup_summary` gains
  `advice: Option<&str>`), `crates/aitm/src/main.rs` (pass the advice; bare `aitm`
  logs it once at `info`), `crates/aitm-plugin-sessionio/src/native.rs` (`MetaRec`
  gains `#[serde(default)] passive: bool` and `#[serde(default)] tunnel: Option<TunnelRec>`
  with mode/reason as strings = the labels, round-tripped), tests:
  `crates/aitm-plugins/tests/control.rs`, `crates/aitm/src/web/mod.rs` tests,
  `crates/aitm-plugin-sessionio/tests/session_roundtrip.rs`.
- **Change:** `ProxyStatus::invoke` adds `"decrypt": {"scope_hosts": Int, "decrypting":
  Bool, "advice": Str|Null}` from `host.guard().list_scope().len()`; the advice
  constant lives once in `aitm-core` (`pub const NOTHING_DECRYPTED_ADVICE: &str =
  "Nothing is decrypted until a host is in Scope.";` in `config.rs` or `guard.rs`) and
  is used by control.rs, main.rs and web/mod.rs. `scope.add` description: "Add a
  host, host:port, or *.wildcard to Scope. New connections to it are decrypted from
  now on; hosts outside Scope are tunnelled. Refused from an agent frontend (MCP)
  unless scope.allow_agent_widen is set." `summarize`: "added {host} to scope (new
  connections to it are decrypted)". Sessionio: unknown-reason strings load as
  `tunnel: None` rather than failing the load.
- **Test:** `control.rs`: `proxy_status_reports_decrypt_advice_on_empty_scope` and
  `..._after_scope_add` (literal objects of AC13); `web/mod.rs`:
  `startup_summary_prints_the_advice_only_when_given`; sessionio:
  `tunnel_and_passive_round_trip_through_a_native_session` and
  `legacy_document_without_the_fields_loads_as_defaults`.
- **Done when:** tests pass, gate passes.

### Task 10: Docs

- **Satisfies:** AC17
- **Depends on:** Tasks 8, 9 (names final)
- **Files:** `docs/design/languages/flow-kinds.json` (+ `validate.test.mjs` if it pins
  the `ssl` text), `aitmproxy-plugin/docs/tool-reference.md` (`flow.table`/`flow.get`/
  `flow.detail`/`proxy.status`/`scope.add` rows), `aitmproxy-plugin/commands/scope.md`,
  `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md`, `tests/e2e/proxy/README.md`
  (the new cell), `docs/research/MEMORY.md` (one bullet: the model changed on
  2026-10-31, Scope = decryption list).
- **Change:** `flow-kinds.json` http `list_cells.ssl`: "padlock from `tunnel`: open =
  decrypted (and every inner row), closed = passthrough (`tunnel_reason` out_of_scope
  offers Add to Scope; pinned does not), warning = failed (`tunnel_reason` text);
  `passive` rows are dimmed and read-only". Docs state the release-note paragraph of
  spec D8 and the frontend contract of D9 in operator words.
- **Test:** `node --test docs/design/languages/validate.test.mjs` green; reviewers
  check the prose against D7–D9.
- **Done when:** the validator passes and the files are committed.

### Task 11: Migration of existing tests + the live e2e cell

- **Satisfies:** AC1, AC2, AC3, AC5, AC9, AC13 (e2e), AC18
- **Depends on:** Tasks 5–9
- **Files:** `tests/e2e/proxy/test_per_host_decryption.py` (create),
  `tests/e2e/passthrough/test_tls_passthrough.py` (modify: the MITM contrast host goes
  into `scope_entries`; the "flagged" check reads `tunnel == "passthrough"` and
  `tunnel_reason == "pinned"`), any Rust test or e2e cell that decrypted or acted on a
  host with an empty Scope (found by running the gate and `python3 tests/e2e/run.py
  proxy passthrough proto scope flow` — expected: a few `Config::default()` proxies in
  `crates/aitm/tests/*.rs` that intercept plain HTTP; fix by adding the origin to
  `scope.entries`, never by weakening the rule).
- **Change:** the new cell (`# e2e: tier=T1 surface=proxy needs=openssl`), one real
  core with an **empty** scope, a loopback TLS echo origin (`aitm_e2e.tls`) and a
  plain HTTP `Upstream`, operator bus:
  1. **passthrough**: `curl --cacert <aitm ca> -x proxy https://127.0.0.1:<tls>/a` →
     rc 60 (verify failed: origin cert); `curl -k` → 200 + the origin's marker;
     `flow.table` → exactly one row for that authority, `CONNECT`, `tunnel ==
     "passthrough"`, `tunnel_reason == "out_of_scope"`, `status == 200`, `bytes_up > 0`,
     `bytes_down > 0`, `duration_ms is not None` (poll ≤ 3 s), `passive == false`; no
     row with `method == "GET"` for it.
  2. **scope.add flips live**: `scope.add 127.0.0.1` (operator) → `curl --cacert` → 200;
     table gains `CONNECT` row `tunnel == "decrypted"`, `status 200`, and a `GET /b`
     row with `passive == false`; the first passthrough row is byte-identical to
     before (same id, same fields).
  3. **scope.remove flips back**: `scope.remove 127.0.0.1` → `curl --cacert` fails (60)
     again; a new `passthrough` row; no new `GET` row.
  4. **CA refused**: `scope.add 127.0.0.1`; `curl -x proxy https://127.0.0.1:<tls>/c`
     (no `--cacert`, no `-k`) → rc 60; table gains `CONNECT` row `tunnel == "failed"`,
     `tunnel_reason == "client_rejected_certificate"`, `status is None`, `duration_ms
     is not None`.
  5. **plain HTTP out of scope is passive**: `scope.remove 127.0.0.1`;
     `flow.intercept {enabled: true, rules: [{url: "*127.0.0.1:<plain>*"}]}` (exactly as
     `test_intercept_url_rules.py` arms a breakpoint rule); `curl -x proxy http://127.0.0.1:<plain>/p` returns 200 immediately
     (no park), the `Upstream` record has `/p`, the row has `passive == true`,
     `proxy.status.paused == 0`; then `scope.add 127.0.0.1`, same request parks
     (`state == "intercepted"`, upstream record lacks `/q` until `flow.resume`), row
     `passive == false`.
  6. **status**: `proxy.status.decrypt` read back at the empty-scope start
     (`decrypting false`, the exact advice sentence) and after `scope.add`
     (`decrypting true`, `advice None`).
  Push proof: a `flow.subscribe` on the operator connection receives a `created` and
  a `response` notification for the passthrough row carrying `tunnel ==
  "passthrough"` (tie-in with AC11; use `wait_notification`).
- **Test:** the cell itself (exit 0 on a real core from the Terminal); the migrated
  cells/tests green; the full gate.
- **Done when:** `python3 tests/e2e/run.py proxy passthrough scope flow proto` passes
  (SKIPs only for missing real deps), the gate passes, and the output is in the PR
  body.

## Review log

Kept by the session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 4 | Coder (self-report) | Minor | `classify_client_failure` maps a received `close_notify` alert during the client handshake to `client_tls_error` (spec D5 literal: "any other alert"); a graceful close is better reported as `client_closed` | FIXED in d3513601 |
| 4 | Coder (self-report) | Minor | A `TunnelRow` opened as `Failed` is already closed; `close`/`fail` on it would set `duration` twice and push a second `Response` — documented, not enforced by type | OPEN — reviewers decide; Tasks 5/6 must not call it (checked in their tests) |
| 3 | Coder (self-report) | Info | A CONNECT line truncated inside the acceptor's peek yields `tunnel_authority() == None`, so the passthrough module does not claim it and the HTTP module decides (its re-check per D2 is Task 6) | CLOSED by design once Task 6 lands |
| 5 | Coder (self-report) | Minor | In `PassthroughModule::tunnel` only resolve/dial failures record a row; a CONNECT head that fails to read (EOF, >16 KiB, non-UTF-8) or an ack write that fails after the dial returns the error with **no row**, against D5 "every CONNECT is a row" | FIXED in d3513601 |
| 5 | Coder (self-report) | Info | CONNECT head fields that are not valid header fields are left off the row (lenient) rather than failing the tunnel; the connector now receives the normalised `host:port` | Reviewers decide; default keep |
| 7/11 | Gate 3 (Terminal) | Minor | A HAR export of the store now includes the CONNECT tunnel row as an entry (`httpVersion: HTTP/1.1`, true to the wire); browsers omit CONNECT from HAR. The h2 HAR test is being scoped to the h2 entry; whether `session.save`/`flow.export` HAR should skip tunnel rows is a product call | OPEN — ask Matt / follow-up spec; default keep (a tunnel is a flow) |
| 11 | Coder (self-report) | Minor | Plan Task 11 step 1 / AC1 and the Task 10 README bullet say "exactly one row" for the origin after `--cacert` then `-k`; two curls are two CONNECTs, so the cell asserts one row after the first curl and two passthrough rows (never a GET) after the second | FIXED in d3513601 |
| gate | Terminal gate 4 (445cefca) | Info | 241 suites, 1 red: `aitm-tui tests/tester_shell.rs::five_thousand_flows_ingest_and_render_within_bounds` (wall-clock bounds; untouched by this branch). Re-run alone: still red at load avg 60; the **same test fails on the main checkout** under the same load (refresh 351 ms). Earlier gates: `web_bus_write_deadline` + rhai `engine` budget test red only at load avg > 85, green at 50 | ACCEPTED as machine-load noise (evidence: /tmp/claude/phd-gate4.log, phd-tui-perf.log, phd-tui-perf-main.log) |
| branch | Tester (stage 5, ec686003) | Minor | T1: `HttpModule::tunnel` leaves no row when the CONNECT head names a host but fails to parse (non-UTF-8 header line); the read-head error path already records one | FIXED in 789a16df (test un-ignored, red then green) |
| branch | Tester (stage 5) | Minor | T2 (pre-existing): `Target::authority()` formats `[::1]:8443` as `::1:8443`, so the guarded connector's `ssrf_check` misparses an in-scope IPv6-literal CONNECT and refuses it; the passthrough module hands the bracketed form | FIXED in 789a16df (`Target::authority()` prints through `Authority`; caller audit in the coder report: no caller needs the unbracketed form; also fixes forward-proxy `GET http://[::1]:…` connector text) |
| branch | Tester (stage 5) | Minor | T3: D6 said raw TLS without SNI gets a row; the row exists only on the capture path (explicit-proxy `dst` is the client) | FIXED — spec D6 amended 2026-11-01 (this commit) |
| branch | Tester (stage 5) | Info | T4: bare-`aitm` `info!` advice line has no test (needs a real startup); T5: a cleartext-inside-CONNECT `decrypted` row never gets `server_conn` (origin dialled lazily by `serve`), permitted by D5 | ACCEPTED (T4: e2e read-back covers the bus side; T5: by design) |
| panel | Security (18073ee4) | **Important** | S1: the out-of-scope relay turns the main listener into a raw TCP CONNECT relay to any host:port (loopback/LAN included) by default; before the branch only a proxy-driven TLS handshake or `serve`-shaped HTTP reached an arbitrary target | FIXED in c16890e0 (both producers peek the first byte after the ack: `0x16` → relay including it, EOF → `failed/client_closed` with the dialled origin, else `failed/protocol_error` with nothing relayed and the client shut down; pins included; in-memory tests in both harnesses; spec D1/D6 + release note amended in a0917767) |
| panel | Security | Minor | S2: an idle passthrough relay pins an unevictable open row, a task and two sockets indefinitely (`copy_bidirectional` has no idle bound; open tunnel rows are in flight) | FIXED in 31f6bf5c (`RELAY_IDLE_TIMEOUT` = 10 min watchdog in `relay`; both halves shut, row closes with counts/duration; paused-time test) |
| panel | Security | Minor | S3: `Proxy-Authorization` is recorded on tunnel rows and persisted; `flow.detail` does not redact headers (the spec's Constraints sentence was wrong) | FIXED in 31f6bf5c (`TunnelRow::open` stores `<redacted>` for every `is_secret_key` header name; spec Constraints sentence corrected) |
| panel | Security | Minor | S4: ASCII control bytes in a CONNECT authority reach Display-formatted log/error text (`log_failed`, resolve contexts); the ingress Debug-escapes | FIXED in 31f6bf5c (`Authority::parse_with_default` rejects any ASCII control char; `log_failed` records the authority Debug-escaped) |
| panel | Security | Minor | S5: `scope.remove` now hides traffic with no agent gate, unlike `tls.passthrough.add` | OPEN — Matt's decision (kept unchanged per the brief; reviewer recommends the passthrough gate or trusted-control) |
| panel | Spec (18073ee4) | **Important** | P1: AC13's launch-line clause ("prints/logs the advice iff Scope is empty at launch, once") has no test on either surface | FIXED in c16890e0 for bare `aitm` (e2e: the sentence appears exactly once after an empty-Scope boot, is absent on a seeded Scope); the `aitm web` half rests on `startup_summary_prints_the_advice_only_when_given` plus the one shared `launch_advice` line the e2e exercises — ACCEPTED on that basis by the session in autonomous mode (Matt may ask for a web-mode harness check) |
| panel | Spec | Minor | P2: HAR export carries CONNECT tunnel rows (outside D1–D9) | OPEN — Matt's decision (default keep; follow-up spec to skip `tunnel.is_some()` rows in HAR if preferred) |
| panel | Spec + Quality | Minor | P3/Q8: `PassthroughModule::passthrough_reason` is `pub` with no external caller; `TunnelRow::id()` added beyond the plan | FIXED in c16890e0 (`passthrough_reason` is `pub(crate)`); `id()` ACCEPTED as a test-only accessor used by `aitm-core`'s own unit tests (producers read `row.id` off the stored flow) |
| panel | Spec | Minor | P4: the push-summary parity test lacks a `decrypted` row (AC11 names five kinds) | FIXED in 31f6bf5c (decrypted row added to the parity test; mutation-checked) |
| panel | Quality (18073ee4, PASS) | Minor | Q1: the "open a failed row, return the error" block is copied twelve times across `tunnel`/`raw_tls`/`relay_out_of_scope` while `mitm` got `Refused` | FIXED in c16890e0 (one `fail_tunnel(ctx, request, reason)` recorder used by `tunnel`, `raw_tls`, `relay_out_of_scope` and `mitm`'s `Refused` arm, plus `fail_before_authority` for the two no-authority-yet exits and `first_byte_after_ack`; relay resolve+dial is one `?`-chain; `client.tls` flips at the one point the handshake byte is seen; `tunnel_rows` tests unchanged and green) |
| panel | Quality | Minor | Q2: two CONNECT-head parsers, two head caps, two resolve-by-authority helpers; `DEFAULT_TLS_PORT` twice | ACCEPTED as follow-up (shared `aitm_core::tunnel::parse_connect_head` + `Authority::resolve`; cross-crate refactor after v0.5.9), by the session in autonomous mode |
| panel | Quality | Minor | Q3: sessionio reverses wire labels with a hand-enumerated list the compiler does not keep exhaustive | FIXED in 31f6bf5c (`TunnelMode::ALL`/`TunnelReason::ALL` + `from_label`; sessionio uses them; round-trip + count-witness tests) |
| panel | Quality | Minor | Q4: `i64::try_from(n).unwrap_or(i64::MAX)` written three times | FIXED in 31f6bf5c (`aitm_core::saturating_i64`, used by capture, detail, MCP summary) |
| panel | Quality | Minor | Q5: `peek_tls_record(..)?` in `raw_tls` is the one wire read that can return without a row on the capture path | FIXED in c16890e0 (a `peek_tls_record` error on the capture path records a `failed` row keyed on the capture destination with `classify_client_failure`; test: client reset mid-ClientHello → `failed/client_closed`; explicit-proxy path stays rowless per D6) |
| panel | Quality | Minor | Q6: `TunnelInfo::is_closed(&self, duration)` ignores `self` | FIXED in 31f6bf5c (`FlowMeta::tunnel_is_closed()`; `TunnelInfo::is_closed` removed; store `is_terminal` uses it) |
| panel | Quality | Minor | Q7: relay byte counts travel as a positional `(u64, u64)` | FIXED in 31f6bf5c (`RelayCounts { up, down }` from `relay`, taken by `TunnelRow::close`; two call sites updated) |
| panel | Quality | Minor | Q9: the passthrough in-memory harness attaches a scope guard the module never reads | FIXED in c16890e0 (the in-memory `start(..)` harness takes no scope guard; the module decides on its own handle) |
| panel | Quality | Minor | Q10: store pickers copied across four proto-http test modules | ACCEPTED as follow-up (`tests/common/mod.rs`), by the session in autonomous mode |
| re-check | Quality (57563aa3, PASS) | Minor | Q11: the passthrough module grew five inline "open failed row, return" copies while the HTTP module got one `fail_tunnel` | ACCEPTED as follow-up with Q2 (move the recorder to `aitm_core::tunnel` as `TunnelRow::fail_new`/`record_failed` and use it from both producers), by the session in autonomous mode |
| re-check | Quality | Minor | Q12: `Replayed` is a third prefix-stream adapter (with `Prefixed<S>`, mac `PrefixedStream<S>`) and `FIRST_READ` zero-allocates 16 KiB per CONNECT to look at one byte | FIXED in 3c322387 |
| re-check | Quality | Minor | Q13: producers disagree on `client.tls` for a CONNECT that fails before any inner byte (passthrough `true`, HTTP `false`); `TunnelRequest.client` doc is two-state | FIXED in 3c322387 |
| re-check | Quality | Minor | Q14: `Arc<Activity>` in `relay` where `&Activity` suffices | ACCEPTED (follow-up tidy), by the session in autonomous mode |
| re-check | Quality | Minor | Q15: two new byte-count expectations computed from `const.len()` instead of literals | FIXED in 3c322387 |
| re-check | Spec (57563aa3, PASS) | Minor | P5: P1 row stated only the bare-`aitm` half; P6: S1 not in the spec Intent / AC6; P7: `TunnelRow::id()` acceptance reason inaccurate | FIXED in this commit (plan rows and spec text amended) |
| re-check | Spec | Minor | P8: Task 10 docs do not state the TLS-only refusal (`MEMORY.md` still says "every other CONNECT is tunnelled byte for byte"; plugin docs list `protocol_error` without the non-TLS cause; e2e README bullet lacks the launch-line step) | FIXED in 3c322387 |
| re-check | Spec | Minor | P9: `RELAY_IDLE_TIMEOUT` re-exported at the crate root with no consumer | FIXED in 3c322387 |
| re-check | Security (57563aa3, PASS) | Minor | S6: the first-byte rule judges one byte; a `0x16`-prefixed raw protocol from a local/LAN client still reaches a junk-tolerant service (Redis, SMTP…) through an out-of-scope relay; the D1 sentence overclaimed | Spec sentence corrected in this commit; the port allow-list / private-network policy for relays is OPEN — Matt's decision (follow-up spec) |
| re-check | Security | Minor | S7: the first-byte wait after the ack is unbounded in time and sits before `RELAY_IDLE_TIMEOUT`, holding the dialled origin socket with no row | FIXED in 3c322387 |
| re-check | Security | Minor | S8: `parse_client_hello_sni` accepts any UTF-8, so an SNI with control bytes reaches `warn`-level error text and row data | FIXED in 3c322387 |
| re-check | Security | Minor | S9 (= Q13): passthrough EOF-after-ack row says `client.tls = true` | FIXED in 3c322387 |
| spot-check | Security (b3facc20, PASS) | Minor | S10: `Authority::parse_with_default` and the T8 label reject only ASCII controls, so C1/bidi format characters (U+202E) can reach a row's `authority` text (misleading label in bidi-aware UIs; TUI drops them; nothing dialled under a spoofed name) | ACCEPTED as follow-up by the session in autonomous mode — fix: reject `!c.is_ascii()` in `parse_with_default`, label keeps `is_ascii_graphic()` only |
| spot-check | Security | Minor | S11: `is_dns_name` rejects `_`, so an underscore host on the raw-TLS/capture path is `failed/protocol_error` instead of passthrough/decrypted (CONNECT path unaffected) | ACCEPTED as follow-up — fix: add `b'_'` to the accepted bytes + a test |
| spot-check | Security | Minor (pre-existing) | S12: in-scope `establish` waits unbounded for the full ClientHello and for the client's Finished after the origin is dialled and handshaked (S7's shape one step later) | ACCEPTED as follow-up — wrap both awaits in the module's existing `tls_handshake_timeout`, elapse → `Refused::client` |
| 2 | Coder (self-report) | Minor | In `Chain::dispatch`'s passive branch a parked receiver is dropped but the working copy's `Intercepted { .. }` state is still written back, so an opted-in plugin that parked a passive flow would leave the row marked intercepted with a handle nobody awaits (unreachable today: no observer parks) | FIXED in d3513601 |

## Shipped

Filled at stage 7.
