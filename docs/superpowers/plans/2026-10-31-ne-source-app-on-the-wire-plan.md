# NE capture: source app on the wire — implementation plan

**Status:** approved — self-approved 2026-10-31 by the orchestrator session (autonomous mode)
**Spec:** `docs/superpowers/specs/2026-10-31-ne-source-app-on-the-wire-design.md`
**Branch / worktree:** `feat/ne-source-app-on-the-wire` off `main` (2496fa1 or later), its own
worktree
**Size:** roughly half a day with parallel coders — T0 is one sitting on its own, then T1/T2/T3
run in parallel; not an hour.

## Overview

Four tasks. **T0 first, alone**: it adds the two `FlowMeta` fields and carries the identity from
`CapturedTcpFlow` through `NextLayerHint` into the HTTP/h2/WebSocket flows and the native
session format. T1 (read commands + doc), T2 (push summary) and T3 (Kit) depend only on T0's
`FlowMeta` fields and are **file-disjoint from each other**, so they fan out to three coders at
once after T0 merges to the plan branch. No task touches `apps/mac/Sources/Aitmproxy/**`,
`apps/mac/Extension/**`, `AitmproxyKit/EmbeddedCoreLaunch.swift`, `BusService.refreshScope`, or
`AitmproxyKit/CaptureStatus.swift`.

Shared facts for every coder:

- TDD per task: write the named test, run it and quote the red run (a compile error on a
  field that does not exist yet counts as red), implement, quote the green run.
- Rust gate from the worktree root:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  Port-binding tests (`EPERM` in the sandbox) need the Terminal panel; run the crate-scoped
  tests in the sandbox first, then the full gate in the Terminal.
- Swift gate: `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build`
  (Terminal) or `--scratch-path "$TMPDIR/aitm-swift-test"` (sandbox).
- Tripwire (SA-AC5): `apps/mac/tools/check-capture-operator-only.sh` must exit 0 on the branch
  (it is green on main ff35cb4 after #189 realigned its pins; `source_app`/`capture_interface`
  strings in `AitmproxyKit/FlowSummary.swift` do not trip it).
- Values used throughout the tests: identifier `com.apple.Safari`, interface `macos-ne`.

## Tasks

### Task 0: persist `source_app` / `capture_interface` from the capture ingress to the stored flow

- **Satisfies:** SA-AC0, SA-AC7; enables SA-AC1–SA-AC3
- **Depends on:** none
- **Files:**
  `crates/aitm-core/src/flow.rs` (modify: `FlowMeta`, its `Default`),
  `crates/aitm-core/src/protocol.rs` (modify: `NextLayerHint`),
  `crates/aitm-core/src/proxy.rs` (modify: hint literal `:231`),
  `crates/aitm/src/ingress.rs` (modify: `CapturedTcpFlow`, `dispatch_tcp`, test literals `:644 :699 :745 :915 :975`, new test),
  `crates/aitm/src/wire.rs` (modify: test literal `:643`),
  `crates/aitm/src/macos_capture/adapter.rs` (modify: `tcp_flow`, unit test `tcp_flow_maps_every_handoff_field`),
  `crates/aitm/tests/macos_capture_adapter.rs` (modify: `macos_tcp_flow_adapts_and_dispatches`),
  `crates/aitm-proto-http/src/module.rs` (modify: `Conn`, `drive`, `mitm`, h1 flow site, upgrade hint, tests),
  `crates/aitm-proto-http/src/h2.rs` (modify: flow site `:352`),
  `crates/aitm-proto-ws/src/module.rs` (modify: `WsFlow` site, new helper + test module),
  `crates/aitm-plugin-sessionio/src/native.rs` (modify: `MetaRec`, `meta_to_rec`, `rec_to_meta`, tests),
  test-literal-only: `crates/aitm-core/tests/upgrade_handoff.rs:88`,
  `crates/aitm-plugin-passthrough/tests/tunnel.rs:167`, `crates/aitm-plugin/tests/seam.rs:94`,
  `crates/aitm/tests/m6_wiring.rs:109,:124`.
- **Change** (spec D1–D3), in this order so each step compiles:
  1. `FlowMeta` gains `pub source_app: Option<String>` and `pub capture_interface: Option<String>`
     (doc comments as in spec D1); `Default` sets both `None`. `MetaRec` gains
     `#[serde(default)] pub source_app: Option<String>`,
     `#[serde(default)] pub capture_interface: Option<String>`; `meta_to_rec`/`rec_to_meta`
     copy them.
  2. `NextLayerHint` gains `pub peer_identity: Option<String>` and
     `pub capture_interface: Option<String>`; the eight literal sites above get `None`
     (except `ingress.rs:222` and `module.rs:1028`, below).
  3. `CapturedTcpFlow` gains `pub interface: String` (doc: the backend's interface name, the
     string an operator's L4 scope names it by). `dispatch_tcp` sets
     `peer_identity: flow.peer_identity.take()` and
     `capture_interface: Some(flow.interface.clone())` on the hint. `adapter.rs::tcp_flow`
     sets `interface: CAPTURE_INTERFACE.to_string()`. Test literals in `ingress.rs`/`wire.rs`
     use `interface: "test-if".to_string()` (or any literal; the ingress must not need
     `CAPTURE_INTERFACE`).
  4. `Conn` gains `pub(crate) source_app: Option<String>`,
     `pub(crate) capture_interface: Option<String>` and
     `pub(crate) fn flow_meta(&self) -> FlowMeta` (spec D3). The three live `Conn`
     constructions (`drive` `:267`, `:286`; `mitm` `:370`) carry `ctx.hint()`'s two values;
     `Conn::plain` keeps its signature. `module.rs:591` and `h2.rs:352` use
     `metadata: conn.flow_meta()`. The upgrade hint at `module.rs:1028` sets
     `peer_identity: conn.source_app.clone()`, `capture_interface: conn.capture_interface.clone()`.
     Test literals `Conn {` at `:2369`, `:3658` get the two `None`s.
  5. `aitm-proto-ws/src/module.rs`: `pub(crate) fn inherit_attribution(handshake: &FlowMeta) -> FlowMeta`
     (copies exactly `source_app` and `capture_interface` onto `FlowMeta::default()`); the
     match arm binds `h.metadata` and the `WsFlow` uses `metadata: inherit_attribution(&meta)`.
- **Tests** (all new unless noted; literal expectations):
  - `crates/aitm-plugin-sessionio/src/native.rs` tests:
    `meta_rec_without_attribution_loads_as_none` — a `MetaRec` document written with the
    pre-change key set (no `source_app`/`capture_interface`), deserialised through the
    format's reader the file's tests already use, gives `rec_to_meta(..).source_app == None`
    and `capture_interface == None`.
    `attribution_round_trips_the_native_format` — `FlowMeta { source_app: Some("com.apple.Safari".into()), capture_interface: Some("macos-ne".into()), ..Default::default() }`
    → `meta_to_rec` → serialise → deserialise → `rec_to_meta` yields
    `Some("com.apple.Safari")` / `Some("macos-ne")`.
  - `crates/aitm/src/ingress.rs` tests: `captured_tcp_identity_rides_the_hint` — the
    existing `StubModule`/`MockGuard::fixed(true)` harness (as `:636-690`), flow with
    `interface: "macos-ne".to_string()`, `peer_identity: Some("com.apple.Safari".to_string())`;
    expect `StreamOutcome::Dispatched`, recorded `hint.peer_identity.as_deref() == Some("com.apple.Safari")`,
    `hint.capture_interface.as_deref() == Some("macos-ne")`. The existing dispatch test with
    `peer_identity: None` additionally asserts `hint.peer_identity == None` and
    `hint.capture_interface.as_deref() == Some("test-if")`.
  - `crates/aitm/src/macos_capture/adapter.rs` `tcp_flow_maps_every_handoff_field` adds
    `assert_eq!(flow.interface, CAPTURE_INTERFACE)`.
    `crates/aitm/tests/macos_capture_adapter.rs` `macos_tcp_flow_adapts_and_dispatches` adds
    `assert_eq!(hint.peer_identity.as_deref(), Some("com.example.browser"))` and
    `assert_eq!(hint.capture_interface.as_deref(), Some(CAPTURE_INTERFACE))`.
  - `crates/aitm-core` (acceptor): `crates/aitm-core/tests/upgrade_handoff.rs` (or the
    nearest acceptor test) asserts a hint built by the proxied path has
    `peer_identity == None && capture_interface == None` — if no test drives
    `handle_conn` without a socket, state so in the report and rely on the literal.
  - `crates/aitm-proto-http/src/module.rs` tests:
    `conn_flow_meta_carries_only_attribution` — a `Conn::plain(unknown_peer(), None)` with
    `source_app = Some("com.apple.Safari")`, `capture_interface = Some("macos-ne")`:
    `flow_meta()` has those two, `marks.is_empty()`, `is_replay == false`.
    `drive_stamps_the_hint_attribution_on_the_stored_flow` — `HttpModule::new()`,
    `ctx_with(vec![upstream])` chained `.with_hint(NextLayerHint { dst: unknown_peer(), is_tls: false, client_hello_sni: None, alpn: vec![], first_bytes: b"GET ".to_vec(), from_upgrade: false, peer_identity: Some("com.apple.Safari".into()), capture_interface: Some("macos-ne".into()) })`,
    origin via `origin_serve(origin_end, vec!["first"], true)`, one `get_request("/one", "127.0.0.1:8080")`
    written on a duplex then closed, `module.spawn(Box::pin(proxy_side), ctx)` under
    `STALL_GUARD`; expect `stored_http(&ctx, "/one").metadata.source_app == Some("com.apple.Safari".into())`
    and `.capture_interface == Some("macos-ne".into())`. If `spawn` cannot be driven to
    completion with the duplex harness, fall back to `serve(..)` with the attributed `Conn`
    and say so in the report.
    Existing `serve_stores_the_usual_flow_when_the_host_names_the_tunnel_target` adds
    `assert_eq!(flow.metadata.source_app, None)` and `assert_eq!(flow.metadata.capture_interface, None)`.
  - `crates/aitm-proto-ws/src/module.rs` new `#[cfg(test)] mod tests`:
    `inherit_attribution_copies_only_the_two_fields` — handshake meta with
    `source_app: Some("com.apple.Safari")`, `capture_interface: Some("macos-ne")`,
    `marks: vec!["x".into()]`, `comment: Some("c".into())`, `is_replay: true` → result has the
    two `Some`s, `marks.is_empty()`, `comment == None`, `is_replay == false`.
- **Done when:** every test above is green, the h2 site uses `conn.flow_meta()` (reviewer
  checks; no dedicated h2 test required), and the full Rust gate passes. Commit on the plan
  branch; T1–T3 start from this commit.

### Task 1: emit `source_app` / `capture_interface` on `flow.get` and `flow.table` (+ schema doc)

- **Satisfies:** SA-AC1, SA-AC4 (its share)
- **Depends on:** Task 0
- **Files:** `crates/aitm-plugins/src/capture.rs` (modify: `summary_fields`, `summarize`,
  `row_fields`, `flow_row`), `crates/aitm-plugins/tests/capture.rs` (modify: new helper + two
  tests), `docs/design/operator-ui-foundation.md` (modify: line 389, the `flow.get` row).
- **Change** (spec D4): in `summarize` and `flow_row`, before the `match flow`, add
  `put("source_app", opt_str(&flow.metadata().source_app))` and
  `put("capture_interface", opt_str(&flow.metadata().capture_interface))` where
  `fn opt_str(v: &Option<String>) -> Value` maps `Some(s)` → `Value::Str(s.clone())`, `None` →
  `Value::Null`. `summary_fields` and `row_fields` each gain
  `field("source_app", TypeDesc::Str, false, "Signing identifier of the app that opened the connection, as the capture backend observed it; null for a proxied flow.")`
  and
  `field("capture_interface", TypeDesc::Str, false, "Capture backend that delivered the connection (`macos-ne`); null for a proxied flow.")`.
  Doc: the §4.3 `flow.get` summary shape becomes
  `{id, kind: http|websocket, intercept, is_replay, method, scheme, authority, path, status?, request_bytes?, response_bytes?, handshake?, messages?, source_app?, capture_interface?}`
  with a trailing clause "`source_app`/`capture_interface` are set on NE-captured flows, null on proxied ones".
- **Tests** (`crates/aitm-plugins/tests/capture.rs`):
  helper `fn attributed(mut flow: Flow) -> Flow` sets `metadata_mut().source_app = Some("com.apple.Safari".into())`
  and `capture_interface = Some("macos-ne".into())`.
  `flow_get_and_table_report_source_app` — store `attributed(http_flow("GET", "/cap", Some(200)))`,
  `http_flow("GET", "/proxied", Some(200))`, and `attributed(ws_flow(cap_id))`; `flow.get` on
  the captured flow has `source_app == Value::Str("com.apple.Safari")` and
  `capture_interface == Value::Str("macos-ne")`; on the proxied flow both are
  `Some(&Value::Null)` (keys present); on the WebSocket flow both `Str` values are present.
  `flow.table` rows (in insertion order) show the same three outcomes.
  `schemas_declare_source_app_and_capture_interface` — for `flow.get`'s result object and for
  `flow.table`'s `flows` array element object, both fields exist, `matches!(ty, TypeDesc::Str)`,
  `!required`, description contains `"proxied"` (pattern: `flow_get_schema_declares_body_sizes`).
- **Done when:** both tests green, `flow_table_rows`/`flow_list_and_get` still green, the doc
  line updated, full Rust gate passes.

### Task 2: mirror both fields on the `flow.subscribe` push summary

- **Satisfies:** SA-AC2, SA-AC4 (its share)
- **Depends on:** Task 0
- **Files:** `crates/aitm-mcp/src/server.rs` (modify: `flow_summary`, ≈`:2631`),
  `crates/aitm-mcp/tests/mcp.rs` (modify: one new test).
- **Change** (spec D4): both `json!` arms add
  `"source_app": f.metadata.source_app, "capture_interface": f.metadata.capture_interface`.
  Nothing else in `flow_summary` changes.
- **Test** (`crates/aitm-mcp/tests/mcp.rs`, using `push_server`, `conn_over`, `subscribe_on`,
  `NotificationSink` as `subscribe_on_an_open_sink_still_works` does):
  `pushed_summary_mirrors_source_app_and_capture_interface` — insert
  `http_flow("example.com:443", "/cap")` with `metadata.source_app = Some("com.apple.Safari")`,
  `capture_interface = Some("macos-ne")`, push `Event::RequestHeaders(id)`; the one line's
  `params.summary.source_app == "com.apple.Safari"` and
  `params.summary.capture_interface == "macos-ne"`. Then insert a plain
  `http_flow("example.com:443", "/proxied")`, push, and assert
  `summary.get("source_app") == Some(&JsonValue::Null)` and the same for
  `capture_interface` (present, null). Optionally a `ws` flow repeat.
- **Done when:** the test is green and the full Rust gate passes.

### Task 3: Kit decodes `source_app` into `FlowRow.client`

- **Satisfies:** SA-AC3, SA-AC4 (its share), SA-AC5's Swift and tripwire lines
- **Depends on:** Task 0 for the live contract only; the Swift tests are self-contained, so
  this task may start as soon as T0 is committed (or in parallel, against the JSON shape in
  spec D4).
- **Files:** `apps/mac/Sources/AitmproxyKit/FlowSummary.swift` (modify),
  `apps/mac/Sources/AitmproxyKit/Flow.swift` (modify: `ClientInfo` extension only),
  `apps/mac/Tests/AitmproxyKitTests/KitTests.swift` (modify: tests in or beside
  `FlowSummaryTests`).
- **Change** (spec D5):
  `FlowSummary`: `public var sourceApp: String?`, `public var captureInterface: String?`;
  memberwise `init` gains `sourceApp: String? = nil, captureInterface: String? = nil`;
  `init?(json:)` sets `sourceApp = Self.identifier(json["source_app"])`,
  `captureInterface = Self.identifier(json["capture_interface"])` where
  `private static func identifier(_ v: JSONValue?) -> String?` returns `nil` for absent,
  null, or empty string; `row(seq:coreID:)` passes `client: sourceApp.map { ClientInfo(sourceApp: $0) }`.
  `ClientInfo`: `public init(sourceApp identifier: String)`,
  `public static func displayName(forSourceApp identifier: String) -> String`,
  `public static let knownSourceApps: [String: String] = ["com.apple.WebKit.Networking": "Safari", "org.mozilla.firefox": "Firefox"]`.
  Rule as spec D5 (known map → else text after the last `.` → else whole identifier; casing
  kept). `FlowRow` is not changed.
- **Tests** (Swift Testing, `KitTests.swift`):
  `sourceAppBecomesTheClient` — summary JSON with `"source_app": "com.apple.Safari", "capture_interface": "macos-ne"`:
  `row(seq: 1).client == ClientInfo(name: "Safari", monogram: "S", bundleID: "com.apple.Safari")`,
  `summary.captureInterface == "macos-ne"`.
  `sourceAppAbsentNullOrEmptyLeavesClientNil` — three summaries (key absent; `.null`; `""`):
  `row(seq: 1).client == nil` and `summary.sourceApp == nil` for each.
  `displayNameRule` — `#expect(ClientInfo.displayName(forSourceApp: x) == y)` for
  `("com.apple.Safari","Safari")`, `("com.apple.curl","curl")`, `("obscura","obscura")`,
  `("com.google.Chrome","Chrome")`, `("com.apple.WebKit.Networking","Safari")`,
  `("org.mozilla.firefox","Firefox")`, `("trailing.","trailing.")`.
  `sameIdentifierGroupsAsOneClient` — two summaries with the same `source_app` produce equal
  `client` values (`Hashable` equality), so `Session.clients`-style counting yields one key.
  `webSocketSummaryCarriesClientToo` — a `websocket` summary with `source_app` set has
  `row().client?.bundleID == "com.apple.Safari"`.
- **Done when:** the new tests and the whole Kit suite are green under the Swift gate; the
  tripwire `VIOLATION` count equals `main`'s (both numbers quoted); no file outside the three
  listed changed.

## File-disjointness

| Task | Rust crates | Swift | Docs |
|---|---|---|---|
| T0 | aitm-core, aitm, aitm-proto-http, aitm-proto-ws, aitm-plugin-sessionio, aitm-plugin-passthrough (test), aitm-plugin (test) | — | — |
| T1 | aitm-plugins | — | `docs/design/operator-ui-foundation.md` |
| T2 | aitm-mcp | — | — |
| T3 | — | `AitmproxyKit/FlowSummary.swift`, `AitmproxyKit/Flow.swift`, `Tests/AitmproxyKitTests/KitTests.swift` | — |

T1, T2, T3 share no file and may run as three parallel coders once T0 is on the plan branch.

## Whole-branch verification (stage 5)

- Every SA-AC mapped to a test (SA-AC6 → manual on the v0.5.5 DMG, recorded in Shipped).
- Full Rust gate, Swift gate, and the tripwire count comparison, output quoted.
- One end-to-end check the Tester can run without the NE: start `aitm` with a config, store a
  flow via `flow.get` after `curl -x`, confirm `"source_app": null, "capture_interface": null`
  on `flow.get` and `flow.table`, and that the `flow.subscribe` push for a new flow carries the
  same two null keys.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| all | Tester (stage 5) | — | PASS (sandbox scope): every SA-AC mapped (SA-AC6 manual on the v0.5.5 DMG); 10/11 mutants killed, the survivor (`#[serde(default)]` on an `Option` field) equivalent; 781 test-only lines added; fmt/clippy exit 0; tripwire PASS on branch and base | Terminal gates on the merged tree 985c00f: see the rows below |
| 0 | Tester | Minor (test depth) | The coder suite left the TLS `mitm` `Conn` literal, the h2 `stream_task` stamping and the WS `drive` wiring unpinned — mutants b2/b3/c2 survived against it; these are the paths a live Safari capture takes | FIXED by the tester (test code only): real TLS/h2/duplex harness tests + WS wiring tests, commit 4584310 |
| 1 | Tester | Info | The core passes an empty `source_app` (`Some("")`) through verbatim; unreachable from the real provider (`FlowHandoff.swift` sends `nonEmpty(...)` → null) and the Kit normalises `""` → nil | ACCEPTED: no core change; both ends already guard it |
| 2 | Tester | Info | Spec non-goal and plan text still mention the `"kind": "ws"` push divergence that #191 removed; `push_summary_equals_flow_get_for_http_and_websocket_flows` now enforces equality | FIXED — wording removed from the plan's Task 2 note (this commit) |
| 0 | Tester | Info | `#[serde(default)]` on the two `MetaRec` `Option<String>` fields is redundant for JSON (serde already defaults a missing `Option`) | ACCEPTED: harmless, documents intent |
| all | Tester | Note | Replayed and imported flows carry None/None — consistent with the spec (not opened by an app) | — |
| all | Tester | — | New e2e cell `tests/e2e/flow/test_source_app_null_on_proxied.py` (canonical `aitm_e2e` harness) boots a real core and asserts both keys null on `flow.get`, the `flow.table` row and the `created` push | run by the main session in the Terminal (result below) |
| all | Security (stage 6) | — | PASS: identifier is untrusted text end to end (JSON-escaped on the way out, serde-decoded, never interpolated into logs/HTML, never read by any scope/guard/policy); session format forward and backward compatible (`aitm-session/1`, no `deny_unknown_fields`); no cross-connection leakage (one `Conn` per client connection, h2 streams share it); `capture_interface` is a fixed adapter string; no `unsafe` | — |
| 0 | Security | Minor | `source_app` was bounded only by the 1 MiB handoff frame and invisible to the store budget, so a hostile local signer with a huge identifier could bloat every stored flow clone | FIXED — `adapter.rs bounded_source_app`: empty or > `MAX_SOURCE_APP_BYTES` (256) → `None`, TCP and UDP, unit test. Counting the two strings in `store.rs meta_bytes` is a follow-up (outside the plan's files) |
| 3 | Security | Minor | The shown Apps-group name was signer-chosen text rendered verbatim (bidi override / C0 controls could mislead the sidebar); `sourceAppSigningIdentifier` attests signing, not honesty | FIXED — `ClientInfo.displayName(forSourceApp:)` strips C0/C1 and Unicode bidi formatting characters from the SHOWN name, keeps `bundleID` raw, falls back to "unknown app"; Swift test. Spoofing a known identifier remains display-only by design (recorded for SA-AC6: a `Safari` group proves nothing about the signer) |
| all | Spec (stage 6) | — | PASS: every SA-AC met or dispositioned; scope per commit exact; architect's calls implemented as written; non-goals and anti-goals honoured | — |
| 1,2 | Spec | Minor | T1 and T2 landed in one commit (6e70126) | ACCEPTED: #191's lock test `push_summary_equals_flow_get_for_http_and_websocket_flows` makes either half alone red at its own commit, which the gate rule forbids |
| 2 | Spec | Minor | Plan Task 2 / spec non-goal still described the `"kind": "ws"` push divergence #191 removed | FIXED — both texts updated |
| all | Spec | Minor | SA-AC6 and the constraint section said "v0.5.5 DMG"; the carrying release is v0.5.5 | FIXED — wording updated to v0.5.5; Shipped records the observation when the DMG exists |
| all | Spec | Minor | Branch is `fix/ne-source-app`, plan said `feat/ne-source-app-on-the-wire` | ACCEPTED: cosmetic |
| all | Spec | Minor | Tester additions were uncommitted and two files (`session_roundtrip.rs`, the e2e cell) are outside the plan's list | FIXED — committed as 4584310 (`test(...)`); the e2e cell is the plan's own stage-5 end-to-end check |
| 0 | Security (note) | Info | Tunnelled (passthrough) NE flows and `client.rs` flows build `FlowMeta` without attribution and report null/null | ACCEPTED as follow-up: pass the hint's values through the passthrough module when the Apps page needs tunnelled flows grouped |
| all | Quality (stage 6) | — | PASS: plumbing shape right (`String` interface matches the L4 types; ingress stays backend-agnostic), all three `Conn` sites via one helper incl. h2, WS reads the stored handshake, push/pull lock sufficient, every seam pinned by a literal test, tester touched no production line | — |
| 0 | Quality | Minor | The attribution-only `FlowMeta` was hand-built in two crates (HTTP `flow_meta`, WS `inherit_attribution`) | FIXED — `FlowMeta::with_attribution(source_app, capture_interface)` in aitm-core; both helpers call it; `inherit_attribution` is now private |
| 0 | Quality | Minor | One concept, two names (`NextLayerHint.peer_identity` ↔ `FlowMeta.source_app`) | ACCEPTED (architect's D2 kept the pre-existing `CapturedTcpFlow.peer_identity`); FIXED the readability half: both docs cross-reference each other |
| 0 | Quality | Minor | `NextLayerHint` header doc said only "what the acceptor peeks" | FIXED — names the capture-backend attribution too |
| 0 | Quality | Minor | `dispatch_tcp` used `take()` + `clone()` where moves read better | FIXED — plain moves |
| 1 | Quality | Minor | `opt_str(&Option<String>)` | FIXED — `opt_str(Option<&str>)` with `as_deref()` callers |
| 3 | Quality | Minor | Kit test asserted the `knownSourceApps` literal against itself | FIXED — line removed; the seven behaviour cases remain |
| 3 | Quality | Minor | `knownSourceApps` is `public` with no consumer outside the Kit | ACCEPTED — spec D5 writes `public static let`; the Status/UX session may read it |
| 3 | Quality | Minor | Sanitiser: hand-listed code points, non-private helper, inline fallback literal, rule doc stale | FIXED — filters Unicode categories Cc and Cf (covers ZWSP/WJ/BOM too), `private`, `ClientInfo.unnamedSourceApp`, `displayName` doc states the four-step rule |
| 0 | Quality | Minor | `MAX_SOURCE_APP_BYTES` was `pub(crate)` with no other user; test drove `tcp_flow` ×4 and skipped the UDP caller; doc cited "security review" | FIXED — plain `const`, test calls `bounded_source_app` directly + one `tcp_flow` wiring check, doc states the reason |
| all | Quality | Minor | e2e cell copies `env_core`/`collect_until` helpers from a sibling cell and reaches `BusClient` privates | ACCEPTED as follow-up: lift them into `aitm_e2e` (pre-existing pattern across six cells) |
| all | Quality | Minor | Tester's `read_one_200` re-implements `read_status_response_keep` for a generic stream; `test_ca` leaks a temp dir per run | ACCEPTED as follow-up (test-only): widen `read_status_response_keep<S: AsyncRead>` and add a `Drop` guard |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7. Record the SA-AC6 observation
(the exact `source_app` string Safari produces) here; if it is not
`com.apple.WebKit.Networking` or `com.apple.Safari`, the follow-up is one entry in
`ClientInfo.knownSourceApps`.
