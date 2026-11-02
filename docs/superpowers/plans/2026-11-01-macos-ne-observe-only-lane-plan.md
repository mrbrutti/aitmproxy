# macOS NE observe-only lane — implementation plan

**Status:** approved — self-approved 2026-11-01 by the observe-only-lane session under
Matt's autonomous-mode rule (memory `aitmproxy-autonomous-approve-merge-mode`; Matt approved
the spec the same day and asked to proceed to the plan). The plan contains no product
decision beyond the approved spec. **Where and when implementation starts is the
orchestrator's/Matt's call** (coordination notes 1–3 below: the single protocol bump versus
the TCP-only-rule fix, and that fix landing before Task 15).
**Spec:** `docs/superpowers/specs/2026-10-31-macos-ne-observe-only-lane-design.md`
(approved 2026-11-01 by Matt; every OQ resolved to the Architect's recommendation; Part 1
superseded by PR #195).
**Branch / worktree:** `feat/macos-ne-observe-only-lane` off `main` (`cbfaaa09` or later), its
own worktree. Parallel coders in that one worktree commit by pathspec.
**Code read for this plan (2026-11-01, main `cbfaaa09`, v0.5.10):** `crates/aitm/src/macos_capture/{listener,adapter,feeder,config,status,mod}.rs`,
`crates/aitm/src/{wire,main,config_file,ingress}.rs`, `crates/aitm-core/src/{ctx,value,flow,registry,plugin}.rs`,
`crates/aitm-plugins/src/{capture,detail}.rs`, `crates/aitm-proto-l4/src/commands/agent.rs`,
`crates/aitm/tests/{frontends,macos_capture_gate,agent_surface}.rs`, `crates/aitm-tui/src/lib.rs`,
`apps/mac/Extension/Sources/{FlowHandoff,TransparentProxyProvider}.swift`, `apps/mac/tools/{ne-selfcheck,check-capture-operator-only,check-capture-toggle,cua-ne-drive}.sh`,
`apps/mac/Sources/AitmproxyKit/{EmbeddedCoreLaunch,CaptureStatus,CaptureAdvice,Flow,FlowSummary}.swift`,
`apps/mac/Sources/Aitmproxy/{SettingsView,App,Session}.swift`, `apps/mac/Sources/Aitmproxy/Bus/{BusService,EmbeddedCore,CoreHealthState}.swift`,
`apps/mac/Sources/Aitmproxy/Shell/{ShellView,SidebarView}.swift`, `apps/mac/CLAUDE.md`,
`apps/web/src/{state/app.ts,bus/normalize.ts,model/flow.ts,shell/Sidebar.tsx}`,
`tests/e2e/ne/*`, `docs/design/operator-ui-foundation.md`.
**Size:** two to three days with parallel coders: six Rust tasks (sandbox-testable), three
sysex tasks and four app/web tasks (written in the sandbox, built in the Terminal), one
real-Mac proof.

## Overview

The core grows two control messages (`FlowSeen` provider→core, `Observe` core→provider) and
the handoff protocol becomes version 2 (exact match). A new `ObserveStore` in the `aitm`
wiring layer keeps bounded rows behind two `Read` commands (`observe.apps`, `observe.events`)
that refuse `Frontend::Mcp` unless `macos_capture.observe.agent_readable`; the feeder sends
`Observe{enabled:true}` after `Scope` and inserts each `FlowSeen`. The provider emits one
`FlowSeen` per declined same-uid flow from a 2 048-entry drop-oldest queue drained by one
writer thread, caches its `isSelf` verdict per process and skips it while detached. The app
gets a second Capture toggle that writes `observe.enabled`, and its Apps page merges captured
and observed apps; the web sidebar gets an "All apps" group. Rust first (Tasks 1–6), the
sysex next (7–9), the app and web in parallel (10–14), then the live proof (15).

**Part 1 is not built here.** PR #195 already carries `FlowMeta.source_app` /
`capture_interface` onto `flow.get` / `flow.table` / the push summary and emits it as
`client_conn.process` on `flow.detail`; the Kit maps `source_app` → `ClientInfo(sourceApp:)`.
Task 0 verifies OL-AC1/OL-AC2 against that shipped shape and reports residual gaps as
stop-and-report items; it rewrites nothing.

## Coordination notes (the orchestrator resolves these)

1. **Protocol version 1 → 2 happens in this plan** (Task 1 Rust, Task 7 Swift, same PR). A
   separate proposed session, "Fix: TCP-only NE catch-all rule", may also change the wire
   (`ScopeSpec` or the rule). The two must compose: whichever lands second rebases onto the
   first and keeps **one** bump to 2 (never 3), and `HANDOFF_PROTOCOL_VERSION` and
   `HandoffConfig.protocolVersion` change in the same PR. Spec OQ9 wants the TCP-only rule
   fix on main before this plan's `[Mac]` acceptance (Task 15), so with a TCP-only rule the
   Apps page shows TCP connections only by default; Task 15's expectations say so.
2. **Observe needs capture.** The lane rides the feeder's control channel, so `observe.*`
   is registered iff `macos_capture.enabled && macos_capture.observe.enabled` on a macOS
   build; `EXPECTED_TOOLS` (`crates/aitm/tests/frontends.rs`) and the TUI `CORE_TOOLS` pin
   the **default** surface and do **not** change. The gate test for the agent refusal lives
   in a new integration test that enables both switches (Task 6).
3. **No snapshot, fixture or self-test evidence for UI work** (Matt's rule; the fixture
   modes were deleted by PRs #241/#244/#249). Every UI criterion is proven live in Task 15
   with the real app, the real core, and real traffic; the Kit and web unit tests prove
   decoding and merging logic only.

## Shared facts for every coder

- **TDD per task:** write the named test, run it and quote the red run (a compile error on a
  type that does not exist yet counts as red), implement, quote the green run.
- **Sandbox limits.** A coder sub-agent cannot build SwiftPM, sign, notarize, bind sockets,
  reach GitHub, or run `git`. Rust tests in this plan use `tokio::net::UnixStream::pair()`
  and in-memory stores only; nothing binds. Swift is **written** by the coder and **built and
  tested by the orchestrator in the Terminal panel**; a coder may try
  `NE_SELFCHECK_SCRATCH="$TMPDIR/ne-selfcheck" apps/mac/tools/ne-selfcheck.sh` (plain
  `xcrun swiftc`, which has worked in the sandbox before) and, if it fails for a sandbox
  reason, stops at "written, not built" and says so.
- **Rust gate** before every review, from the worktree root:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. In the
  sandbox run the crate-scoped tests (`cargo test -p aitm macos_capture`, `-p aitm --test
  frontends`, …); the full gate and the socket-binding integration tests
  (`tests/e2e/ne/ne_rust_handoff.sh`) run in the Terminal.
- **Swift gates** (Terminal): `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build`,
  `apps/mac/tools/ne-selfcheck.sh`, `apps/mac/tools/check-capture-operator-only.sh`,
  `apps/mac/tools/check-capture-toggle.sh`, `apps/mac/tools/grid-lint.sh`. The Extension has
  **no SwiftPM test target**: its tests are `enum HandoffSelfCheck` (`#if DEBUG`) at the
  bottom of `FlowHandoff.swift`, `static func run() -> [String]` returning `FAIL …` lines; a
  check is `r.check("label", <Bool>, <detail>)`.
- **Web gate** (sandbox if `node_modules` is present, else Terminal): `cd apps/web && npm test`.
- **Parallel coders, one worktree:** commit by pathspec (`git commit -- <files>`), never
  `git add -A`; format with per-file `rustfmt --edition 2021 <file>`, never `cargo fmt` on a
  crate root. Coders do not run `git` in the sandbox; they leave the files for the
  orchestrator to commit, listing the exact paths in the report.
- **Never log payload bytes.** The lane carries metadata only; no test or log line prints a
  body, a first-bytes buffer, or a DNS answer.
- **Pinned wire literals** (byte-exact in both halves; serde accepts any key order on decode,
  the Swift encoder emits exactly this order):
  - Hello v2: `{"Hello":{"protocol_version":2}}`
  - Observe: `{"Observe":{"enabled":true}}`
  - FlowSeen fixture **F1**:
    `{"FlowSeen":{"kind":"Tcp","remote":"1.1.1.1:443","remote_hostname":"example.com","source_app":"com.apple.Safari","source_path":null,"source_pid":501,"source_uid":501,"seen_at_ms":1730400000000,"dropped":0}}`
- **Pinned bus shapes:** `observe.apps` → `{enabled, received, dropped_provider,
  dropped_core, aggregate_evicted, apps: [{app, is_path, count, first_seen_ms, last_seen_ms,
  destinations: [{remote, hostname, kind, count, first_seen_ms, last_seen_ms, bytes_in,
  bytes_out}]}]}`; `observe.events {limit?}` → `{events: [{kind, remote, hostname, app,
  is_path, source_pid, source_uid, seen_at_ms}]}` newest first. `kind` on the bus is
  lowercase `"tcp"` / `"udp"`; `hostname`, `bytes_in`, `bytes_out`, `source_pid`,
  `source_uid` are `null` when absent. The app key is `source_app`, else `source_path`
  (`is_path: true`), else the literal `"unknown"`.
- **Pinned store fixture S3** (used by Tasks 3, 4, 11, 14): three `FlowSeen`s in this order —
  `com.apple.Safari` → `1.1.1.1:443` Tcp, hostname `example.com`, `seen_at_ms` 1000;
  the same app and remote at 2000; `com.apple.curl` → `93.184.216.34:80` Tcp, no hostname,
  at 3000. All `source_uid` 501, `dropped` 0.

## Tasks

### Task 0: verify Part 1 against the shipped PR #195 shape

- **Satisfies:** OL-AC1, OL-AC2 (verification of the shipped shape; records the naming
  mapping)
- **Depends on:** none
- **Files:** none modified in production. May add **test-only** pins where a surface has
  none: `apps/web/src/bus/normalize.test.ts` (a `toDetail` case), `crates/aitm-tui/src/model.rs`
  (a `Conn::parse` test).
- **Change:** none. Run and quote: `cargo test -p aitm-plugins` (the `source_app` /
  `capture_interface` tests on `flow.get`, `flow.table`, `flow.detail`); `grep -n
  'source_app' crates/aitm-plugins/src/detail.rs` showing `conn(&f.client_conn,
  Some(f.metadata.source_app.as_deref()))` (the `client_conn.process` emitter); the Kit
  mapping `FlowSummary.sourceApp` → `row().client == ClientInfo(sourceApp:)`
  (`apps/mac/Sources/AitmproxyKit/FlowSummary.swift`, `Flow.swift:138`); web `clientOf`
  reading `client_conn.process` (`apps/web/src/bus/normalize.ts`); TUI `Conn::parse`
  reading `process` (`crates/aitm-tui/src/model.rs`). Record the mapping: the spec's
  `"process"` on `flow.get`/`flow.table` **is** the shipped `source_app` key; `"process"`
  exists only under `flow.detail`'s `client_conn`. UDP identity is Part 2 only (spec).
- **Test:** if `normalize.test.ts` lacks a `client_conn.process` case, add
  `toDetail({..., client_conn: {peer: '127.0.0.1:1', process: 'com.apple.Safari'}}, 1).client.id === 'com.apple.Safari'`;
  if `model.rs` lacks one, add `Conn::parse(&json!({"process":"com.apple.Safari"})).process == Some("com.apple.Safari".into())`.
  The Kit mapping is covered by the existing `swift test` suite (Terminal; quote the
  `FlowSummary`/`ClientInfo` test names from the run).
- **Done when:** the report lists each surface with the quoted evidence and either "no
  gap" or a **stop-and-report** item (a surface that drops the identity). A gap is reported
  to the orchestrator, not fixed here.

### Task 1: wire types and protocol version 2 (Rust)

- **Satisfies:** OL-AC3, OL-AC4 (Rust half)
- **Depends on:** none
- **Files:** `crates/aitm/src/macos_capture/listener.rs` (modify), `crates/aitm/src/macos_capture/adapter.rs` (modify)
- **Change:**
  - `listener.rs`: add
    `pub struct FlowSeen { pub kind: FlowKind, pub remote: std::net::SocketAddr, pub remote_hostname: Option<String>, pub source_app: Option<String>, pub source_path: Option<String>, pub source_pid: Option<u32>, pub source_uid: Option<u32>, pub seen_at_ms: u64, pub dropped: u64 }`
    and `pub struct ObserveSpec { pub enabled: bool }`, both
    `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]`, with doc comments
    naming the spec table (Part 2) and "metadata-only by construction: no byte-typed field".
    `ControlMessage` gains `FlowSeen(FlowSeen)` and `Observe(ObserveSpec)`.
  - `adapter.rs`: `pub const HANDOFF_PROTOCOL_VERSION: u32 = 2;` (the `check_hello` message
    already names both numbers: "provider announced {}, core speaks {}"; keep it).
  - Existing listener wire tests that hard-code `protocol_version: 1` keep passing (the
    frame length is the same); switch them to `HANDOFF_PROTOCOL_VERSION` only if that is
    a one-line change.
- **Test** (all in `listener.rs` `#[cfg(test)]`, over `UnixStream::pair()`):
  - `flow_seen_round_trips_and_stays_small`: a maximal `FlowSeen` (every `Option` `Some`,
    a 253-byte hostname `"a".repeat(253)`, a 1 024-byte path `"/p".repeat(512)`,
    `source_pid: Some(u32::MAX)`, `source_uid: Some(u32::MAX)`, `seen_at_ms: u64::MAX`,
    `dropped: u64::MAX`) sent with `ControlChannel::send` and read with `recv` decodes
    `== original`, and `bytes_read() < 2_048`; after 100 such frames `bytes_read() < 204_800`.
  - `flow_seen_has_no_byte_field`: an exhaustive destructure
    `let FlowSeen { kind, remote, remote_hostname, source_app, source_path, source_pid, source_uid, seen_at_ms, dropped } = ..;`
    compiles (adding a field breaks it on purpose) with a comment citing OL-AC3.
  - `flow_seen_fixture_f1_decodes`: `serde_json::from_slice::<ControlMessage>(F1)` equals
    `ControlMessage::FlowSeen(FlowSeen { kind: FlowKind::Tcp, remote: "1.1.1.1:443".parse().unwrap(), remote_hostname: Some("example.com".into()), source_app: Some("com.apple.Safari".into()), source_path: None, source_pid: Some(501), source_uid: Some(501), seen_at_ms: 1_730_400_000_000, dropped: 0 })`,
    and `serde_json::to_string(&ControlMessage::Observe(ObserveSpec { enabled: true }))`
    equals `{"Observe":{"enabled":true}}`.
  - In `adapter.rs`: `check_hello_refuses_version_one_naming_both`:
    `check_hello(&Hello { protocol_version: 1 })` is `Err`, `kind() == InvalidData`, and
    the message contains both `"1"` and `"2"`; `check_hello(&Hello { protocol_version: 2 })`
    is `Ok`.
- **Done when:** the four tests are green and `cargo test -p aitm macos_capture` passes
  (the feeder tests use `hello(HANDOFF_PROTOCOL_VERSION)` and follow the constant).

### Task 2: `ObserveConfig` (Rust config)

- **Satisfies:** OL-AC15
- **Depends on:** none
- **Files:** `crates/aitm/src/macos_capture/config.rs` (modify), `crates/aitm/src/config_file.rs` (tests only)
- **Change:** in `config.rs` add
  `#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)] #[serde(default, deny_unknown_fields)] pub struct ObserveConfig { pub enabled: bool, pub agent_readable: bool }`
  with doc comments (spec Part 5: both config-file-only; `agent_readable` has no app
  control in v1), and `pub observe: ObserveConfig` on `MacosCaptureConfig` (which already
  carries `#[serde(default, deny_unknown_fields)]`). Update the module doc's YAML block to
  the spec's four-line shape.
- **Test:**
  - `config.rs`: `observe_defaults_off` —
    `MacosCaptureConfig::default().observe == ObserveConfig { enabled: false, agent_readable: false }`.
  - `config_file.rs`: `macos_capture_observe_round_trips` —
    `parse_settings("macos_capture:\n  enabled: true\n  observe:\n    enabled: true\n").unwrap().macos_capture.observe`
    is `ObserveConfig { enabled: true, agent_readable: false }`;
    `macos_capture_observe_unknown_key_errors` —
    `parse_settings("macos_capture:\n  observe:\n    enabld: true\n")` is `Err`;
    the existing `macos_capture_enable_round_trips` still passes with `observe` defaulted.
- **Done when:** the three tests are green and `cargo test -p aitm config` passes.

### Task 3: `ObserveStore` (Rust)

- **Satisfies:** OL-AC10, OL-AC11 (store half), OL-AC21 (structural half)
- **Depends on:** Task 1 (`FlowSeen`, `FlowKind`)
- **Files:** `crates/aitm/src/macos_capture/observe.rs` (create), `crates/aitm/src/macos_capture/mod.rs` (add `pub mod observe;`)
- **Change:**
  - `pub const DEFAULT_OBSERVE_EVENTS: usize = 20_000;`, `pub const DEFAULT_OBSERVE_KEYS: usize = 10_000;`,
    `pub const DEFAULT_OBSERVE_RATE_CAP: u64 = 5_000;` (per second), each with the spec's
    measured basis in its doc comment (survey §R1).
  - `#[derive(Debug, Clone, PartialEq, Eq, Hash)] pub struct AppKey { pub text: String, pub is_path: bool }`
    with `pub fn from_seen(seen: &FlowSeen) -> AppKey` (`source_app` → `is_path: false`;
    else `source_path` → `is_path: true`; else `"unknown"`).
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct ObservedFlow { pub kind: FlowKind, pub remote: SocketAddr, pub remote_hostname: Option<String>, pub app: AppKey, pub source_pid: Option<u32>, pub source_uid: Option<u32>, pub seen_at_ms: u64, pub bytes_in: Option<u64>, pub bytes_out: Option<u64>, pub closed_at_ms: Option<u64> }`
    (the three trailing slots stay `None` in v1: reserved for option (b)).
  - `pub struct ObserveStore { inner: Mutex<Inner>, max_events: usize, max_keys: usize, rate_cap: u64 }`
    with `pub fn shared() -> Arc<Self>` (defaults) and
    `pub fn with_limits(max_events: usize, max_keys: usize, rate_cap: u64) -> Arc<Self>`;
    `pub fn insert(&self, seen: FlowSeen, now_ms: u64) -> bool` (false when shed by the
    rate cap: more than `rate_cap` inserts whose `now_ms` falls in the same 1 000 ms
    window); a `VecDeque<ObservedFlow>` capped at `max_events` (drop-oldest →
    `dropped_core += 1`); an aggregate `HashMap<(AppKey, SocketAddr, FlowKind), Agg { count: u64, first_seen_ms: u64, last_seen_ms: u64, hostname: Option<String> }>`
    capped at `max_keys` (evict the smallest `last_seen_ms` → `aggregate_evicted += 1`);
    counters `received`, `dropped_core`, `aggregate_evicted`, `dropped_provider` (the max
    `FlowSeen.dropped` seen); `pub fn apps_value(&self) -> Value` and
    `pub fn events_value(&self, limit: usize) -> Value` rendering the pinned bus shapes
    (apps by `count` descending, ties by `app` ascending; destinations by `count`
    descending then `remote` ascending; events newest first; `limit` clamped to 1 000);
    `pub fn counts(&self) -> (u64, u64, u64, u64)` for tests. Uses `status::object` for
    `Value` building. **No** `std::fs`, `tokio::fs`, `.inject(`, `send_on_wire(`.
- **Test** (`observe.rs` `#[cfg(test)]`):
  - `store_is_bounded_and_counts_evictions` (OL-AC10): `with_limits(20_000, 10_000, u64::MAX)`;
    100 000 `FlowSeen`s with distinct remotes (`10.0.0.0/8` sweep + port) and
    `seen_at_ms = i`; then `events.len() == 20_000`, `aggregate.len() == 10_000`,
    `counts() == (received 100_000, dropped_core 80_000, aggregate_evicted 90_000, dropped_provider 0)`,
    and the oldest event present has `seen_at_ms == 80_000`.
  - `rate_cap_sheds_the_excess`: `with_limits(.., .., 5_000)`; 6 000 inserts with
    `now_ms = 0`: 5 000 return `true`, 1 000 return `false`, `dropped_core == 1_000`.
  - `apps_value_renders_fixture_s3` (OL-AC11 store half): after S3,
    `apps_value()["apps"][0]["app"] == "com.apple.Safari"`, `["count"] == 2`,
    `["destinations"][0]["remote"] == "1.1.1.1:443"`, `["hostname"] == "example.com"`,
    `["first_seen_ms"] == 1000`, `["last_seen_ms"] == 2000`, `["kind"] == "tcp"`;
    `["apps"][1]["app"] == "com.apple.curl"`, `["count"] == 1`,
    `["destinations"][0]["hostname"] == Value::Null`; `received == 3`.
  - `events_value_is_newest_first_and_clamped`: `events_value(2)` yields two events with
    `seen_at_ms` 3000 then 2000; `events_value(5_000)` yields at most 1 000.
  - `app_key_prefers_signing_id_then_path_then_unknown`: three `FlowSeen`s → `("com.apple.Safari", false)`, `("/usr/libexec/x", true)`, `("unknown", false)`.
  - `observe_store_touches_no_disk_and_no_wire` (OL-AC21 structural): read
    `observe.rs` and assert it contains none of `std::fs`, `tokio::fs`, `.inject(`,
    `send_on_wire(`.
- **Done when:** all six tests are green and `cargo test -p aitm observe` passes.

### Task 4: `observe.apps`, `observe.events`, `ObserveAgentGate`, `ObservePlugin` (Rust)

- **Satisfies:** OL-AC11 (command half), OL-AC13 (registry level)
- **Depends on:** Task 3
- **Files:** `crates/aitm/src/macos_capture/observe_commands.rs` (create), `crates/aitm/src/macos_capture/mod.rs` (add `pub mod observe_commands;`)
- **Change:**
  - `pub struct ObservePlugin { store: Arc<ObserveStore>, agent_readable: bool }` with
    `pub fn new(store: Arc<ObserveStore>, agent_readable: bool) -> Self`; `impl Plugin`
    (`name() == "observe"`, `load` registers the two gated commands; observes no events).
  - `struct ObserveApps { store: Arc<ObserveStore> }` → `name "observe.apps"`,
    `sensitivity Read`, no params, `invoke` = `store.apps_value()` with `"enabled": true`
    inserted (the command exists only when enabled); schema `result_fields()` describing
    every key of the pinned shape.
  - `struct ObserveEvents { store }` → `name "observe.events"`, `sensitivity Read`, one
    optional `limit: Int` param (`args.get_int("limit")`, default 200, clamp 1..=1_000),
    `invoke` = `store.events_value(limit)`.
  - `pub struct ObserveAgentGate { inner: Arc<dyn Command>, agent_readable: bool }`
    mirroring `L4AgentGate` (`crates/aitm-proto-l4/src/commands/agent.rs:35-80`): `name`,
    `schema`, `sensitivity`, `confirm_prompt` delegate; `invoke` refuses with
    `anyhow::bail!("`{}` refused: agent access to observed connections is disabled; an operator can set `macos_capture.observe.agent_readable: true` in the config file", self.inner.name())`
    when `!host.caller_is_trusted_control() && !self.agent_readable`, else delegates.
- **Test** (`observe_commands.rs` `#[cfg(test)]`; a `CommandHost` is built exactly as
  `status.rs`'s `command_is_read_only_and_parameterless` does —
  `CommandHost::new(&MemFlowStore::new(), &StubClient, &StdGuard::default(), None)` with a
  local `StubClient: ProxyClient` whose `send` bails — then `.with_frontend(..)`):
  - `observe_apps_renders_fixture_s3_with_enabled`: after S3 into a `shared()` store,
    `ObserveApps.invoke(Params::default(), &host)["enabled"] == Value::Bool(true)` and
    `["apps"][0]["app"] == "com.apple.Safari"`, `["apps"][1]["count"] == 1`.
  - `observe_events_limit_two_is_newest_first`: `Params` with `limit: 2` → two events,
    `events[0]["seen_at_ms"] == 3000`, `events[1]["seen_at_ms"] == 2000`; `limit: 0` and
    `limit: 5000` clamp to 1 and 1 000 (assert lengths against a store holding 3 events →
    1 and 3).
  - `agent_is_refused_unless_agent_readable` (OL-AC13): with `agent_readable = false`, a
    host `.with_frontend(Frontend::Mcp)` gets `Err` whose text contains `"agent_readable"`;
    `.with_frontend(Frontend::Operator)` and `Frontend::Cli` get `Ok`; with
    `agent_readable = true` Mcp gets `Ok`; both gated commands report
    `sensitivity() == Sensitivity::Read` and names `"observe.apps"` / `"observe.events"`.
  - `plugin_registers_exactly_two_commands`: `ObservePlugin::new(store, false).load(&mut Registry::default())`
    (or the registry constructor the crate uses) then `commands()` names are exactly
    `["observe.apps", "observe.events"]`.
- **Done when:** the four tests are green and `cargo test -p aitm observe` passes.

### Task 5: feeder — `Observe` push and `FlowSeen` intake (Rust)

- **Satisfies:** OL-AC5, OL-AC9, OL-AC4 (feeder half: no `Observe` after a refused `Hello`)
- **Depends on:** Task 1, Task 3
- **Files:** `crates/aitm/src/macos_capture/feeder.rs` (modify)
- **Change:**
  - `CaptureSession` gains `observe: Option<Arc<ObserveStore>>` (default `None`) and
    `#[must_use] pub fn with_observe(mut self, store: Arc<ObserveStore>) -> Self`.
  - `serve_control`: right after the initial `Scope` is sent and the attachment recorded,
    if `self.observe.is_some()` send `ControlMessage::Observe(ObserveSpec { enabled: true })`
    (a send error tears the attachment down like a scope push failure). Never send
    `Observe` when `observe.is_none()` (the config is fixed for the process, so there is no
    "changed" re-send in v1; say so in a comment).
  - The read loop gains `Ok(Some(ControlMessage::FlowSeen(seen))) => self.record_seen(seen)`
    where `record_seen` inserts into the store with `now_ms = SystemTime::now()` ms when
    `observe` is `Some`, else counts and `debug!`s (never detaches). It never touches
    `pairing`.
  - The detach log line becomes
    `info!(control_bytes_read = reader.bytes_read(), "capture provider detached")` (read
    after the `select!` so both loops have dropped their borrows) — the live oracle for
    OL-AC19.
  - Module doc: add the two new frames to the control-channel description.
- **Test** (`feeder.rs` tests, with the existing helpers `control_pair`, `attach`,
  `next_frame`, `hello`, `scope`, `session`, `new_pairing`, `pairing_len`):
  - `observe_frame_follows_scope_when_enabled` (OL-AC5): a session
    `.with_observe(ObserveStore::shared())`; after `Hello(2)` the provider receives
    `Scope("example.com")` then exactly `ControlMessage::Observe(ObserveSpec { enabled: true })`.
  - `no_observe_frame_when_disabled` (OL-AC5): the default session; after `Scope`, a
    `timeout(Duration::from_millis(300), provider.recv())` elapses (no second frame); then
    the provider sends `FlowOpen(open(1))` and the session still registers it
    (`pairing_len == 1`), proving the channel stayed up.
  - `flow_seen_is_stored_and_never_paired` (OL-AC9): enabled session; the provider sends
    one `FlowOpen(open(7))` and ten `FlowSeen`s (S3's first event repeated); then
    `pairing_len == 1` and `store.counts().0 == 10`; a stray `Scope` and a repeated `Hello`
    are still ignored without ending the task (extend
    `control_loop_acts_only_on_flow_open` or add this beside it).
  - `flow_seen_without_observe_is_ignored`: default session; ten `FlowSeen`s do not end the
    attachment (`!task.is_finished()`), and a later `FlowOpen` pairs.
  - `hello_mismatch_sends_no_observe`: an enabled session fed `hello(1)` ends the channel
    with **no** frame delivered (`next_frame == None`) — extends `hello_mismatch_tears_down`.
- **Done when:** the five tests are green and `cargo test -p aitm feeder` passes.

### Task 6: wiring, tripwires, wire-level gate test, docs (Rust)

- **Satisfies:** OL-AC12, OL-AC13 (wire level), OL-AC14 (Rust half), OL-AC21 (LF-AC13 extension), OL-AC22 (Rust gate)
- **Depends on:** Task 2, Task 4, Task 5
- **Files:** `crates/aitm/src/wire.rs` (modify), `crates/aitm/src/main.rs` (modify),
  `crates/aitm/src/ingress.rs` (modify: the `one_choke_point_survives_ingress` file list),
  `crates/aitm/tests/observe_gate.rs` (create), `docs/design/operator-ui-foundation.md`
  (modify: the verb table beside the `capture.status` row, line ~407)
- **Change:**
  - `wire.rs`: `pub fn build_observe_store(features: &Features) -> Option<Arc<ObserveStore>>`
    = `build_observe_store_on(features, cfg!(target_os = "macos"))`, and
    `pub(crate) fn build_observe_store_on(features: &Features, macos: bool) -> Option<Arc<ObserveStore>>`
    returning `Some(ObserveStore::shared())` iff
    `features.macos_capture.enabled && features.macos_capture.observe.enabled && macos`.
    In `assemble_with_scripts`, build it once; when `Some`, `register_plugin(Box::new(ObservePlugin::new(Arc::clone(&store), features.macos_capture.observe.agent_readable)))`
    right after `CaptureStatusPlugin`; `Assembled` gains `pub observe_store: Option<Arc<ObserveStore>>`.
    `build_capture_session` gains a trailing parameter `observe: Option<Arc<ObserveStore>>`
    and applies `.with_observe(store)` when `Some`. The `no_agent_path_to_capture_session`
    symbol list adds `"ObserveStore::"`, `"build_observe_store("`, `"ObservePlugin::"`
    (allow-list unchanged: `main.rs`, `wire.rs`, `macos_capture/`).
  - `main.rs`: destructure `observe_store` from `Assembled` and pass it to
    `build_capture_session` at the existing call (`~720`).
  - `ingress.rs`: `one_choke_point_survives_ingress` adds `"macos_capture/observe.rs"` and
    `"macos_capture/observe_commands.rs"` to its scanned list.
  - `docs/design/operator-ui-foundation.md`: two verb rows (`observe.apps`,
    `observe.events`) with the pinned shapes and "registered iff
    `macos_capture.enabled && macos_capture.observe.enabled` on macOS; `Read`; refused for
    the agent unless `macos_capture.observe.agent_readable`".
- **Test:**
  - `wire.rs`: `observe_commands_registered_iff_both_switches` (OL-AC12): with
    `Features::default()` and with `macos_capture.enabled = true` alone, the registry has
    no `observe.apps`/`observe.events`; with both switches on (and the test forcing
    `macos = true` through `build_observe_store_on`) both are present (assemble with the
    store registered; assert `proxy.registry().command("observe.apps").is_some()`).
    `observe_store_absent_off_macos`: `build_observe_store_on(&both_on, false).is_none()`.
    `no_agent_path_to_capture_session` passes with the new symbols.
  - `tests/observe_gate.rs` (OL-AC13 at the wire, modelled on
    `frontends.rs::capture_status_is_callable_by_the_agent_under_read_only`): assemble
    with both switches on and `agent_readable = false`, build `McpServer::new(proxy.registry_arc(), McpTransport::Stdio)`,
    `tools/call observe.apps` → the result is an error whose text contains
    `"agent_readable"`; with `agent_readable = true` → a result whose
    `structuredContent.enabled == true` and `received == 0`.
  - `ingress.rs`: `one_choke_point_survives_ingress` green with the two new files.
- **Done when:** the tests above are green, `cargo test -p aitm` passes in the sandbox,
  and the orchestrator's Terminal run of the full Rust gate is green.

### Task 7: provider wire — version 2, `Observe` decode, `FlowSeen` encode (Swift sysex)

- **Satisfies:** OL-AC4 (Swift half), OL-AC6 (decode part)
- **Depends on:** none (the literals are pinned above; Task 1 is its Rust twin)
- **Files:** `apps/mac/Extension/Sources/FlowHandoff.swift` (modify: `HandoffConfig`,
  `CoreMessage`, `HandoffMessages`, `HandoffSelfCheck`)
- **Change:**
  - `HandoffConfig.protocolVersion: UInt32 = 2`.
  - `enum CoreMessage: Equatable { case scope(String); case observe(Bool); case ignored }`;
    `decodeCore` maps `{"Observe":{"enabled":<Bool>}}` → `.observe(b)`; an `Observe` whose
    `enabled` is missing or not a Bool → `.ignored` (fail-open: nothing turns on).
  - `struct FlowSeenMessage: Equatable { var kind: FlowOpenMessage.Kind; var remote: String; var remoteHostname: String?; var sourceApp: String?; var sourcePath: String?; var sourcePid: UInt32?; var sourceUid: UInt32?; var seenAtMs: UInt64; var dropped: UInt64 }`
    and `static func flowSeen(_ m: FlowSeenMessage) throws -> Data` emitting the keys in
    exactly the F1 order, strings through the existing `literal`/`optional` escapers,
    integers unquoted, absent options as `null`.
- **Test** (`HandoffSelfCheck` additions; run `apps/mac/tools/ne-selfcheck.sh`):
  - `hello v2`: `HandoffMessages.hello()` bytes equal `{"Hello":{"protocol_version":2}}`.
  - `decodeCore observe`: `{"Observe":{"enabled":true}}` → `.observe(true)`;
    `{"Observe":{"enabled":false}}` → `.observe(false)`; `{"Observe":{}}` → `.ignored`;
    `{"Scope":{"spec":"a.test"}}` still → `.scope("a.test")`.
  - `flowSeen F1`: the fixture descriptor
    `FlowSeenMessage(kind: .tcp, remote: "1.1.1.1:443", remoteHostname: "example.com", sourceApp: "com.apple.Safari", sourcePath: nil, sourcePid: 501, sourceUid: 501, seenAtMs: 1730400000000, dropped: 0)`
    encodes to exactly the F1 literal; a maximal message (253-byte hostname, 1 024-byte
    path, `UInt32.max`/`UInt64.max`) framed with `HandoffWire.frame` is `<= 2_048` bytes.
- **Done when:** `ne-selfcheck.sh` prints `PASS: NE handoff self-check` (Terminal, or the
  sandbox with `NE_SELFCHECK_SCRATCH`), and the coder's report quotes the red run (a
  compile error on `.observe` counts) and the green run.

### Task 8: provider observe lane — queue, writer, uid filter, detach-clear (Swift sysex)

- **Satisfies:** OL-AC6, OL-AC7, OL-AC8
- **Depends on:** Task 7
- **Files:** `apps/mac/Extension/Sources/FlowHandoff.swift` (modify: `CoreLink`,
  `FlowHandoff`, new `ObserveQueue`, `ObserveWriter`, `FlowSeenDescriptor`,
  `HandoffSelfCheck`)
- **Change:**
  - `CoreLink.Attachment` gains `let observe: Bool` and `let coreUID: uid_t?`. `CoreLink`
    keeps `observe` (set from `.observe(b)` in `readControl`, reset to `false` in
    `detach` and at the start of `serve`) and `coreUID` (read once in `serve` after the
    peer check: `PeerAuth.peerAuditToken(of: handle.fd)` → euid, i.e. `token.val.1`, the
    field `audit_token_to_euid` returns). `current()` carries both.
  - `struct FlowSeenDescriptor { kind, remote: FlowEndpoint, remoteHostname: String?, sourceApp: String?, sourcePath: String?, sourcePid: UInt32?, sourceUid: UInt32?, seenAtMs: UInt64 }`
    plus `func message(dropped: UInt64) -> FlowSeenMessage`.
  - `final class ObserveQueue` (`init(capacity: Int = 2_048)`): `tryPush(_:) -> Bool`
    (O(1) under one `NSLock`, no I/O, drops the oldest when full and increments
    `dropped`), `drain(max: Int) -> [FlowSeenDescriptor]`, `clear()`, `var dropped: UInt64`,
    `var count: Int`, `let wake = DispatchSemaphore(value: 0)` signalled by `tryPush`.
  - `final class ObserveWriter` (`init(queue:, link:, sink: ((Data, CoreLink.Attachment) -> Bool)? = nil)`):
    one `Thread` waiting on `queue.wake`; per drained descriptor encodes
    `HandoffMessages.flowSeen(d.message(dropped: queue.dropped))` and calls the sink
    (default `link.send(_:on:)`, which already holds `writeLock` and tears the channel
    down on failure); on `false` → `queue.clear()` and back to waiting; `stop()` ends the
    thread. The writer shares `writeLock` with `claim()`'s `FlowOpen` send (spec Part 3,
    writeLock bullet): it may use `writeLock.try()` + re-queue or yield to a pending claim,
    builder's choice, provided the ≤ 2 s claim-path bound holds.
  - `FlowHandoff`: owns the queue and writer; `handleTCP`/`handleUDP`, when `claim`
    returns `nil`, call `observeDeclined(descriptor, token: flow.metaData.sourceAppAuditToken)`:
    requires `link.current()` with `observe == true`, a token whose euid `==
    attachment.coreUID` (nil token or nil `coreUID` → nothing), builds the
    `FlowSeenDescriptor` (`sourcePath` via `proc_pidpath_audittoken` **only when
    `sourceApp` is nil**, truncated to 1 024 bytes; `sourcePid` = `token.val.5`;
    `seenAtMs` = wall clock ms) and `queue.tryPush`. `CoreLink.detach` also clears the
    queue (through a `onDetach` hook the handoff installs).
  - Counters for the stats line (Task 9 adds the log): `observed`, `dropped`.
- **Test** (`HandoffSelfCheck`, using the existing `pair()`, `drainCount`, `setRecvTimeout`
  helpers and `FlowHandoff(link:requirement:dial:)` injection):
  - `observe enqueue rules` (OL-AC6): with an attached link whose `observe == false` a
    declined flow enqueues nothing; with `observe == true` and a same-uid token exactly
    one descriptor equal to the flow's fields; a token with another euid, a nil token, and
    a `coreUID == nil` attachment each enqueue nothing; a claimed flow (a test attachment
    whose scope matches and a dialer that returns a verified pair) enqueues nothing.
    (`isSelf` is not exercised here: the provider checks it before the handoff; Task 9.)
  - `tryPush never blocks and bounds` (OL-AC7): an `ObserveWriter` with a sink that
    blocks forever on a `DispatchSemaphore` (never draining); 10 000 `tryPush` calls →
    `queue.count == 2_048`, `queue.dropped == 7_952`, the sink was entered at most once
    and never from the pushing thread (assert by thread identity); the elapsed
    wall-clock of the 10 000 pushes is printed and checked `< 1.0 s`.
  - `writer failure detaches and clears` (OL-AC8): a sink returning `false` → after the
    writer runs, `queue.count == 0`; `CoreLink` after `detach` has `current() == nil`,
    `observe == false`; a descriptor pushed while detached is not kept.
  - `claim never waits unbounded behind the writer` (OL-AC8): a `pair()` whose peer never
    reads and whose send buffer is shrunk (`SO_SNDBUF` 4 096) with `setSendTimeout(fd, 2)`;
    fill it with observe frames until a write blocks (the writer thread), then on another
    thread call `link.send(flowOpenBody, on: attachment)`: it returns `false` within
    `<= 3.0 s` of wall-clock and `link.isAttached == false` afterwards.
- **Done when:** `ne-selfcheck.sh` passes with the new checks; report quotes red and green.

### Task 9: `isSelf` verdict cache, skip-while-detached, stats line (Swift sysex)

- **Satisfies:** OL-AC24 (Swift half; the `[Mac]` half is Task 15), OL-AC14 (no new agent
  surface: nothing here is reachable from the bus)
- **Depends on:** Task 8 (same files)
- **Files:** `apps/mac/Extension/Sources/FlowHandoff.swift` (modify: `SelfExclusion`,
  `FlowHandoff`, `HandoffSelfCheck`), `apps/mac/Extension/Sources/TransparentProxyProvider.swift` (modify)
- **Change:**
  - `SelfExclusion`: `final class VerdictCache` (cap `4_096`, LRU, keyed by
    `(pid: pid_t, pidversion: UInt32)` = `token.val.5` / `token.val.7`, one `NSLock`);
    `static let cache = VerdictCache()`;
    `static func isSelf(sourceAppAuditToken data: Data?, verify: (audit_token_t) -> Bool = { PeerAuth.verifyPeer(auditToken: $0, requirement: selfRequirement) }) -> Bool`
    consults the cache first and stores the verdict after one `verify` call. A nil or
    malformed token stays `false` and is not cached.
  - `FlowHandoff.isAttached: Bool { link.isAttached }`.
  - `TransparentProxyProvider.handleNewFlow` / `handleNewUDPFlow`: first
    `guard handoff.isAttached else { return false }` (detached: no Security call, no
    observe, direct), then the cached `isSelf`, then the handoff as today. Comment cites
    survey §R3 (3.6 ms median, ≈200 flows/s ceiling) and OL-AC24.
  - Stats line: a per-second counter under the handoff lock (`flowsThisSecond`,
    `maxPerSecond`, `flowsTotal`, plus Task 8's `observed`/`dropped`), logged once every
    60 s at default level as
    `handoff stats: flows=%llu max_1s=%llu observed=%llu dropped=%llu attached=%d` — no
    per-flow log line.
- **Test** (`HandoffSelfCheck`):
  - `isSelf caches per process`: a counting `verify`; two tokens with the same
    `(pid, pidversion)` → exactly 1 call and both verdicts equal; a token with the same pid
    and a different pidversion → a second call.
  - `isSelf cache is bounded`: 4 097 distinct keys then the first key again → 4 098 calls
    (the first was evicted).
  - `isSelf is not consulted while detached`: a `FlowHandoff` with a never-attached link has
    `isAttached == false`; the decision helper the provider uses (factor
    `FlowHandoff.gateDecision(attached:) -> Bool` or equivalent pure function) returns
    `false` without touching the cache (the counting verifier reports 0 calls).
  - `cached path microbenchmark`: 10 000 `isSelf` calls on one cached key complete in
    `< 1.0 s` (printed, generous bound; the median is expected near 1 µs) — the
    "ceiling > 1 000 flows/s" evidence the `[Mac]` half confirms with the burst recipe.
- **Done when:** `ne-selfcheck.sh` passes; the provider file compiles under `build.sh --ne`
  (orchestrator, Terminal); report quotes red and green.

### Task 10: Kit — `EmbeddedCoreLaunch.Config.observeEnabled` (Swift Kit)

- **Satisfies:** OL-AC16
- **Depends on:** none
- **Files:** `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (modify),
  `apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift` (modify)
- **Change:** `Config` gains `public var observeEnabled: Bool` and an `init` parameter
  `observeEnabled: Bool = false` appended after `captureEnabled` (existing call sites
  unchanged). `yaml()` emits, when `captureEnabled`,
  `"\nmacos_capture:\n  enabled: true\n"` as today and, when **also** `observeEnabled`,
  the two extra lines so the block reads exactly
  `macos_capture:\n  enabled: true\n  observe:\n    enabled: true\n`; when
  `captureEnabled` is false nothing of `macos_capture` is emitted whatever `observeEnabled`
  says. Doc comment cites spec Part 5 and the core's `macos_capture_observe_round_trips`.
- **Test** (`EmbeddedCoreLaunchTests`): `observeBlockEmittedOnlyWhenCaptureAndObserveOn` —
  `Config(…, captureEnabled: true, observeEnabled: true).yaml()` contains the exact
  substring `"macos_capture:\n  enabled: true\n  observe:\n    enabled: true"`;
  `captureEnabled: true, observeEnabled: false` contains `"macos_capture:\n  enabled: true"`
  and no `"observe"`; `captureEnabled: false, observeEnabled: true` contains no
  `"macos_capture"`; `Config(…)` with defaults has `observeEnabled == false`. The existing
  TG-AC1 substring test still passes.
- **Done when:** `swift test` is green (Terminal); the Rust `macos_capture_observe_round_trips`
  input in Task 2 is byte-identical to the emitted block.

### Task 11: Kit — `ObservedApps` decode and the Apps-page merge model (Swift Kit)

- **Satisfies:** OL-AC17 (Kit half)
- **Depends on:** none (the bus shape is pinned above)
- **Files:** `apps/mac/Sources/AitmproxyKit/ObservedApps.swift` (create),
  `apps/mac/Tests/AitmproxyKitTests/ObservedAppsTests.swift` (create)
- **Change:** modelled on `CaptureStatus.swift` (`init?(json: JSONValue)`, unknown wire
  values tolerated):
  - `public struct ObservedApps: Hashable, Sendable { public var enabled: Bool; public var received: UInt64; public var droppedProvider: UInt64; public var droppedCore: UInt64; public var aggregateEvicted: UInt64; public var apps: [ObservedApp]; public init?(json: JSONValue) }`
    (`nil` unless `enabled` is a Bool and `apps` an array); `public var notRecorded: UInt64 { droppedProvider + droppedCore }`.
  - `public struct ObservedApp: Hashable, Sendable { public var app: String; public var isPath: Bool; public var count: UInt64; public var firstSeen: Date; public var lastSeen: Date; public var destinations: [ObservedDestination] }`,
    `public var client: ClientInfo { isPath ? ClientInfo(name: (app as NSString).lastPathComponent, bundleID: nil) : ClientInfo(sourceApp: app) }`.
  - `public struct ObservedDestination: Hashable, Sendable { public enum Kind: String, Sendable { case tcp, udp, unknown }; public var remote: String; public var hostname: String?; public var kind: Kind; public var count: UInt64; public var firstSeen: Date; public var lastSeen: Date; public var label: String { hostname ?? remote } }`.
  - `public struct AppsPageEntry: Hashable, Sendable { public var client: ClientInfo; public var capturedCount: Int; public var observedCount: UInt64; public var destinations: [AppsPageDestination] }`,
    `public struct AppsPageDestination: Hashable, Sendable { public enum Source: Sendable { case captured, observed }; public var label: String; public var kind: ObservedDestination.Kind?; public var count: UInt64; public var source: Source; public var isInteractive: Bool { source == .captured } }`,
    `public static func merge(captured: [(ClientInfo, Int)], observed: ObservedApps?) -> [AppsPageEntry]`
    keyed by `bundleID ?? name`, captured entries first by count, then observed-only
    entries by count; a captured app's observed destinations append with `source: .observed`.
- **Test** (`ObservedAppsTests`): `decodesFixtureS3` — a `JSONValue` of the pinned
  `observe.apps` shape for S3 decodes to `apps.count == 2`,
  `apps[0].client.bundleID == "com.apple.Safari"`, `apps[0].count == 2`,
  `apps[0].destinations[0].label == "example.com"`, `apps[0].destinations[0].kind == .tcp`,
  `apps[1].destinations[0].label == "93.184.216.34:80"` (no hostname → remote);
  `kind: "icmp"` decodes as `.unknown`; a path app (`is_path: true`,
  `app: "/usr/libexec/trustd"`) gives `client.name == "trustd"` and `bundleID == nil`.
  `mergeGroupsByAppAndMarksObserved` (OL-AC17): `merge(captured: [(ClientInfo(sourceApp: "com.apple.Safari"), 3)], observed: S3)`
  yields two entries; the Safari entry has `capturedCount == 3`, `observedCount == 2`, and
  its observed destination has `source == .observed`, `isInteractive == false`; the curl
  entry has `capturedCount == 0`. `merge(captured:observed: nil)` returns captured-only
  entries unchanged.
- **Done when:** `swift test` is green (Terminal).

### Task 12: app — observe toggle, spawn read, menu command, tripwires (Swift app)

- **Satisfies:** OL-AC14 (Swift half), OL-AC16 (spawn half)
- **Depends on:** Task 10
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (modify: `spawn()`),
  `apps/mac/Sources/Aitmproxy/SettingsView.swift` (modify: `CaptureSettings`,
  `CaptureSwitch`), `apps/mac/Sources/Aitmproxy/App.swift` (modify: `FlowCommands`),
  `apps/mac/tools/check-capture-operator-only.sh` (modify), `apps/mac/tools/check-capture-toggle.sh` (modify)
- **Change:**
  - `spawn()`: beside the `capture.enabled` read,
    `let observeEnabled = captureEnabled && (defaults.object(forKey: "observe.enabled") as? Bool ?? false)`
    threaded as `observeEnabled:` into `EmbeddedCoreLaunch.Config`.
  - `CaptureSwitch`: `static func setObserve(_ on: Bool, session: Session) async` — guard
    `!health.captureBusy`, embedded core active, and `on != current`; write
    `Store.defaults.set(on, forKey: "observe.enabled")`; bump `session.restartCoreTick`
    (the core re-reads the gate; no extension action). Idempotent.
  - `CaptureSettings`: under the capture toggle, a second
    `Toggle("Show every app's connections (observe-only)", isOn: …)` bound through
    `setObserve`, `.disabled(!captureEnabled || health.captureBusy || !usesEmbedded)`,
    with the one-line copy "Lists each app's destinations without intercepting them.
    Nothing is decrypted or stored on disk." A `@AppStorage("observe.enabled", store: Store.defaults)`
    read for the toggle's value, like `captureEnabled`.
  - `App.swift` `FlowCommands`: a menu item whose label reflects state ("Show Every App's
    Connections" / "Hide Every App's Connections") calling `CaptureSwitch.setObserve`,
    disabled unless capture is on and the embedded core is active, with a keyboard
    shortcut that collides with none in `App.swift` (builder picks; the menu audit in
    Task 15 confirms).
  - `check-capture-operator-only.sh`: a rule that the literal `"observe.enabled"` appears
    only in `EmbeddedCore.swift`, `SettingsView.swift`, `App.swift` (each with an
    `expect`), and that the agent-reachable surfaces of rule 4 never mention `observe`;
    `setObserve(` appears only in `SettingsView.swift` and `App.swift`.
  - `check-capture-toggle.sh`: a check that `spawn()` reads `"observe.enabled"` and ANDs it
    with `captureEnabled`, and that `setObserve` bumps `restartCoreTick`.
- **Test:** both tripwires print `PASS` (sandbox-runnable, `bash`); a deliberate probe —
  temporarily adding `"observe.enabled"` to `Session.swift` — makes
  `check-capture-operator-only.sh` exit 1 naming the line (quote it, then revert).
  `swift test` and `./build.sh --debug` (Terminal) stay green.
- **Done when:** tripwires PASS, the probe FAILs as expected, the Terminal build is clean.

### Task 13: app — the Apps page consumes `observe.apps` (Swift app)

- **Satisfies:** OL-AC17 (app half; proven live in Task 15)
- **Depends on:** Task 11 (and Task 6 for a live core that answers)
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify: `pollLoop`),
  `apps/mac/Sources/Aitmproxy/Session.swift` (modify: `observedApps`),
  `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (modify: the `.apps` branches),
  `apps/mac/Sources/Aitmproxy/Panels/AppsPanel.swift` (create),
  `apps/mac/Sources/Aitmproxy/Shell/SidebarView.swift` (modify: the Apps count)
- **Change:**
  - `BusService.pollLoop`: when `tools` contains `observe.apps`, call it once per poll
    (after `flow.list`) and assign `session.observedApps = ObservedApps(json:)`; when the
    tool is absent set `session.observedApps = nil`.
  - `Session`: `var observedApps: ObservedApps?`; `var appsPage: [AppsPageEntry] { AppsPageEntry.merge(captured: clients, observed: observedApps) }`.
  - `ShellView` `.apps` page: when `session.observedApps != nil` show `AppsPanel`
    (observed lane on) instead of the flow table; when `nil` keep today's
    `AppsAttributionBanner` / `AppsEmptyState` / `flowTable` logic unchanged.
  - `AppsPanel`: a `List` of `appsPage` entries — app disc + name, counts "N captured ·
    M observed"; a disclosure per app listing destinations with `label`, `kind`, `count`;
    an **observed** destination renders muted with a small "observed" badge, has no
    context-menu actions and no inspector; a **captured** destination's click sets the
    Apps filter to that app (the existing `page: .apps, bundleID:` path). A footer line
    "N connections not recorded" when `notRecorded > 0`, and "Listening for connections…"
    when `apps.isEmpty`. `ContentUnavailableView` for the empty state; tokens from `Tok`/
    `Space`; `.gridArea`/`.gridProbe` on the custom list.
  - `SidebarView`: the Apps count becomes `session.appsPage.count` when the lane is on.
- **Test:** no fixture evidence. Kit logic is covered by Task 11; the view is proven live in
  Task 15 (real window shot via `tools/winshot.swift`). `tools/grid-lint.sh` PASS and
  `./build.sh --debug` clean (Terminal). The coder's report names the exact view
  hierarchy and the two accessibility labels ("observed", "captured") the live check reads.
- **Done when:** the build and grid-lint are green and Task 15's Apps-page check passes.

### Task 14: web — `observe.apps` normalization, polling, "All apps" sidebar (TypeScript)

- **Satisfies:** OL-AC18 (unit), OL-AC17's web analogue (live in Task 15)
- **Depends on:** none (bus shape pinned); live behaviour needs Task 6
- **Files:** `apps/web/src/model/observe.ts` (create), `apps/web/src/bus/normalize.ts`
  (modify: `toObservedApps`), `apps/web/src/bus/normalize.observe.test.ts` (create),
  `apps/web/src/state/app.ts` (modify), `apps/web/src/state/app.observe.test.ts` (create),
  `apps/web/src/shell/Sidebar.tsx` (modify)
- **Change:**
  - `model/observe.ts`: `export interface ObservedDestination { remote: string; hostname: string | null; kind: 'tcp' | 'udp' | 'unknown'; count: number; firstSeenMs: number; lastSeenMs: number }`,
    `export interface ObservedApp { id: string; name: string; isPath: boolean; count: number; destinations: ObservedDestination[]; observed: true }`,
    `export interface ObservedApps { enabled: boolean; received: number; notRecorded: number; apps: ObservedApp[] }`.
  - `normalize.ts`: `export function toObservedApps(raw: unknown): ObservedApps | null`
    (`null` unless `enabled` is a boolean and `apps` an array; `id = app`, `name` = the
    last path component for `is_path`, else the app; `notRecorded = dropped_provider + dropped_core`).
  - `state/app.ts`: a store field `observed: ObservedApps | null` (default `null`); in the
    tick loop beside `pollStatus`, every `STATUS_EVERY_MS` when `has('observe.apps')` call
    `bus.call('observe.apps')` → `setObserved(toObservedApps(..))`; when the tool is absent
    `observed` stays `null`. `entries` is never touched by it.
  - `Sidebar.tsx`: under the Apps group, when `app.observed` is non-null, an "All apps"
    group listing `observed.apps` as muted `Item`s (monogram, name, count, a title
    "observed, not captured"), non-selectable (no `pick`), plus a final muted line
    "N not recorded" when `notRecorded > 0`.
- **Test** (vitest):
  - `normalize.observe.test.ts`: `toObservedApps` of the pinned S3 shape yields
    `apps[0].id === 'com.apple.Safari'`, `apps[0].count === 2`,
    `apps[0].destinations[0].hostname === 'example.com'`, `apps[1].destinations[0].hostname === null`,
    `notRecorded === 0`, every app `observed === true`; a path app yields `name === 'trustd'`;
    a payload without `enabled` yields `null`.
  - `app.observe.test.ts` (OL-AC18), with `bridgeBus.testkit.ts`: a test bus advertising
    `observe.apps` and answering S3 → after bootstrap `app.observed?.apps.length === 2`
    and `app.entries.length` equals the flow count the bus served (unchanged by the
    observe poll); a bus without the tool leaves `app.observed === null` and never calls it.
- **Done when:** `npm test` is green (sandbox or Terminal) and `npm run build` succeeds.

### Task 15: `[Mac]` live proof (Terminal panel; Matt for every credentialed step)

- **Satisfies:** OL-AC17 (live), OL-AC18 (live analogue), OL-AC19, OL-AC20, OL-AC24 (`[Mac]`
  half), OL-AC22 (Swift/mac gates), and the live halves of OL-AC14/OL-AC16
- **Depends on:** every task above merged to the plan branch; the "TCP-only NE catch-all
  rule" fix on main (spec OQ9), else the UDP expectations below are read with `.any`.
- **Files:** none (a report; the orchestrator pastes the quoted outputs into the Review log)
- **Steps** (all Terminal panel; Matt signs/notarizes with his Developer ID + ASC key
  `G638JVUND7`, team `995PCLM9KH`; a coder or agent never runs these):
  1. **Build + install.** `cd apps/mac && NE_SIGN_IDENTITY=<id> ./build.sh --ne --allow-unnotarized --replace`,
     zip + `xcrun notarytool submit --wait` + `stapler staple` (the survey recipe), `open
     /Applications/Aitmproxy.app`. **Expect:** `systemextensionsctl list` shows the new
     `CFBundleVersion` `[activated enabled]` with **no** System Settings prompt (survey
     item 6); `codesign -d --entitlements :-` on the sysex shows only
     `app-proxy-provider-systemextension` (no new entitlement).
  2. **Gates.** `swift test …` green; `apps/mac/tools/ne-selfcheck.sh` PASS;
     `check-capture-operator-only.sh`, `check-capture-toggle.sh`, `grid-lint.sh` PASS;
     the full Rust gate green; `tests/e2e/ne/ne_rust_handoff.sh` PASS.
  3. **Default off (OL-AC14/16 live).** Settings ▸ Capture: capture ON (already approved),
     observe toggle OFF: the core log shows no `Observe` and the Apps page shows today's
     empty state; the embedded core's `config.yaml` (under the app's work dir) contains
     `macos_capture:\n  enabled: true` and no `observe`.
  4. **Observe on, empty scope (OL-AC19).** Turn the observe toggle ON (core restarts;
     `config.yaml` now carries the four-line block). With Scope empty, run
     `curl https://example.com` (HTTP 200). **Expect within 10 s:** the Apps page lists
     `curl` (`com.apple.curl`) with destination `example.com` count 1 and every other
     active app with counts; `flow.list` on the bus is empty;
     `log show --predicate 'process == "AitmproxyNE"' --last 2m | grep -c "accepted new flow"`
     is `0` while `grep -c "New flow"` is ≥ the Apps page's total; Safari browsing is
     normal. Window evidence: `swift apps/mac/tools/winshot.swift <pid> /tmp/claude/observe-apps.png`
     and read the badge text from the shot (the "observed" rows carry no inspector).
     With the TCP-only rule on main, no UDP rows appear; with `.any`, DNS/QUIC rows do.
  5. **Bytes bound (OL-AC19).** Turn observe OFF then ON (forces a detach): the core log's
     `capture provider detached control_bytes_read=<N>` satisfies
     `N <= 40 + events × 2_048` where `events` is `observe.apps`'s `received` at that
     moment. `bytes_read` counts provider→core frames only: with an empty scope those are
     the 36-byte `Hello` and the `FlowSeen`s (no `FlowOpen` is ever sent); `Scope` and
     `Observe` are the core's own sends and never enter it. With observe OFF for a minute,
     a detach reports `control_bytes_read <= 40` (the `Hello` alone).
  6. **Wedged core (OL-AC20).** `pid=$(pgrep -f Contents/Resources/core/aitm | head -1)`;
     `kill -STOP $pid`; browse in Safari and run `curl https://example.com` three times.
     **Expect:** every connection succeeds with no visible delay; within ~2 s of the
     provider's next write the sysex log shows `detached from core; failing open`;
     `kill -CONT $pid` → `attached to core` within ~4 s and new observed rows resume.
  7. **Burst and ceiling (OL-AC24 `[Mac]`).** The survey's recipe: a cold headless Chrome
     profile loading `https://www.theverge.com` (`chrome --headless=new --user-data-dir=$(mktemp -d) --virtual-time-budget=10000 …`).
     **Expect:** `log show … | grep "handoff stats:"` shows `max_1s` equal to the busiest
     arrival second counted from the framework's `New flow` lines (no backlog: handled
     tracks arrived), and the self-check microbenchmark (Task 9) reported `< 1.0 s` for
     10 000 cached calls (ceiling > 10 000/s). Record `max_1s`.
  8. **Agent gate live (OL-AC13).** With `agent_readable` unset, an MCP agent connection
     (`aitm` CLI as an agent, or the e2e harness) calling `observe.apps` gets the refusal
     naming `agent_readable`; the app (operator token) reads it fine.
  9. **Web (OL-AC18 live).** Point the web UI at a core the provider attaches to: run the
     bundle's signed core as `aitm web` with a config enabling `macos_capture` + `observe`
     while the app uses the external core (Settings ▸ Bus), or quit the app if the tunnel
     stays up (the orchestrator picks whichever keeps the tunnel connected; record which).
     **Expect:** the sidebar "All apps" group lists the observed apps with counts and the
     flow list stays empty with Scope empty.
  10. **Menu audit (OL-AC14 live).** The Proxy menu has the observe command with a working,
      non-colliding shortcut that drives the same steps as the toggle.
- **Done when:** every expectation above is quoted (log lines, counts, shot paths) in the
  report and the orchestrator records them in the Review log. A failed expectation is a
  fix task, not an accepted gap.

## Parallelization

| Task | Files (writer-exclusive) | Independent of | Depends on |
|---|---|---|---|
| 0 | test-only pins (web `normalize.test.ts`, TUI `model.rs` tests) | all | — |
| 1 | `macos_capture/listener.rs`, `adapter.rs` | 2, 7, 10, 11, 14 | — |
| 2 | `macos_capture/config.rs`, `config_file.rs` (tests) | 1, 3, 4, 5, 7–14 | — |
| 3 | `macos_capture/observe.rs`, `mod.rs` (one line) | 2, 4-less | 1 |
| 4 | `macos_capture/observe_commands.rs`, `mod.rs` (one line) | 5 | 3 |
| 5 | `macos_capture/feeder.rs` | 4 | 1, 3 |
| 6 | `wire.rs`, `main.rs`, `ingress.rs` (test list), `tests/observe_gate.rs`, `docs/design/operator-ui-foundation.md` | — | 2, 4, 5 |
| 7 | `Extension/Sources/FlowHandoff.swift` (wire region) | all Rust, 10, 11, 14 | — |
| 8 | `FlowHandoff.swift` (lane region) | — | 7 |
| 9 | `FlowHandoff.swift` (SelfExclusion), `TransparentProxyProvider.swift` | — | 8 |
| 10 | `AitmproxyKit/EmbeddedCoreLaunch.swift` + test | all | — |
| 11 | `AitmproxyKit/ObservedApps.swift` + test | all | — |
| 12 | `Bus/EmbeddedCore.swift`, `SettingsView.swift`, `App.swift`, two tripwires | 13 | 10 |
| 13 | `Bus/BusService.swift`, `Session.swift`, `Shell/ShellView.swift`, `Panels/AppsPanel.swift`, `Shell/SidebarView.swift` | 12 | 11 (live: 6) |
| 14 | `apps/web/src/{model/observe.ts,bus/normalize.ts,state/app.ts,shell/Sidebar.tsx}` + two tests | all Rust/Swift | — (live: 6) |
| 15 | none (report) | — | all |

- **Wave A (fan out 7):** Tasks 0, 1, 2, 7, 10, 11, 14 — disjoint files, no shared dependency.
  Tasks 3 and 4 both add one line to `macos_capture/mod.rs`; sequence them (3 then 4) or let
  the orchestrator resolve the one-line conflict.
- **Wave B (fan out 2):** Task 3 (after 1) ∥ Task 8 (after 7).
- **Wave C (fan out 4):** Task 4 (after 3) ∥ Task 5 (after 1, 3) ∥ Task 9 (after 8) ∥ Task 12 (after 10).
- **Wave D (fan out 2):** Task 6 (after 2, 4, 5) ∥ Task 13 (after 11).
- **Then:** whole-branch Tester (every OL-AC), the three-reviewer panel in parallel
  (security review mandatory: OL-AC23), fixes, then Task 15 on Matt's Mac, then integration.
- The Swift tasks (7–13) are written by coders and built by the orchestrator in the
  Terminal after each wave; a coder's report for a Swift task ends at "written; self-check
  / swift test to be run in the Terminal" when the sandbox cannot build it.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
