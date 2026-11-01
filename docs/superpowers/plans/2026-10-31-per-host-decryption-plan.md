# Per-host decryption and visible tunnels — implementation plan

**Status:** approved — self-approved 2026-10-31 by the per-host-decryption session
(autonomous mode).
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
| 2 | Coder (self-report) | Minor | In `Chain::dispatch`'s passive branch a parked receiver is dropped but the working copy's `Intercepted { .. }` state is still written back, so an opted-in plugin that parked a passive flow would leave the row marked intercepted with a handle nobody awaits (unreachable today: no observer parks) | FIXED in d3513601 |

## Shipped

Filled at stage 7.
