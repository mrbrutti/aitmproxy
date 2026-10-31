# NE capture: source app on the wire — design

**Status:** approved — self-approved 2026-10-31 by the orchestrator session (autonomous
mode; v0.5.4 release item the orchestrator named after Matt's v0.5.3 report "I do not see
the apps").
**Research inputs:** none new; code evidence gathered 2026-10-31 (see "Where the identity
dies today"). Prior documents: `docs/superpowers/specs/2026-10-30-aitmproxy-macos-ne-live-feeder-design.md`
(the handoff carries `FlowOpen.source_app`), `docs/superpowers/specs/2026-10-31-ne-claim-rule-design.md`
(lists this as the "next PR"), `docs/design/operator-ui-foundation.md` §4.3 (the `flow.get`
summary shape), PR #179 (`request_bytes`/`response_bytes`: the pattern this follows), PR #181
(`CaptureAdvice`: the banner this retires live).
**Milestone:** v0.5.4.
**Branch / worktree:** `feat/ne-source-app-on-the-wire` off `main` (2496fa1 or later), its own
worktree.
**Size:** roughly half a day with parallel coders (one plumbing task first, then three
file-disjoint tasks), not an hour.

## Intent

The macOS app's Apps page (sidebar `Apps` group and the Apps flow page) groups flows by
`FlowRow.client`, but no flow ever carries its source app on the wire, so `Session.clients`
is always empty live and the page shows PR #181's "flows carry no source app yet" banner.
The provider already sends the signing identifier of the process that opened each captured
flow (`FlowOpen.source_app`, e.g. `com.apple.curl`), and the adapter maps it to
`CapturedTcpFlow.peer_identity` — where it dies: `CoreIngress::dispatch_tcp` never reads it,
and no type on the stored flow has a place for it. This change persists the identity and the
capture backend's name on the stored flow, emits them on `flow.get`, `flow.table` and the
`flow.subscribe` push summary as `source_app` / `capture_interface`, and teaches the Kit to
turn `source_app` into `FlowRow.client`. Proxied flows carry `null` for both. Nothing in the
app's UI changes; the Apps page lights up because the data arrives.

## Goals

- A captured (Network Extension) HTTP or WebSocket flow is stored with the identifier the
  provider observed and the backend name `"macos-ne"`, and every read surface reports them.
- A proxied flow reports both as `null` — present, never absent, never a placeholder.
- The macOS Kit turns `source_app` into `ClientInfo(name: <display name>, bundleID: <identifier>)`
  so the existing Apps grouping works unchanged; a Safari visit shows a `Safari` group.
- Old native session files still load; new ones round-trip the two fields.

## Non-goals

- UDP / L4 flows. `CapturedUdpFlow.peer_identity` stays as it is: L4 flows are a different
  record (`L4Meta`, `L4FlowStore`) and a different row, and the Apps page groups HTTP/WS
  rows. Not trivial, so out (coordinator's rule: `dispatch_udp` only if trivial).
- Resolving pid → process name, app icons, or a responsible-process walk in the core. The
  provider sends one string; the core stores that string; the Kit derives a display name.
- Any UI change under `apps/mac/Sources/Aitmproxy/**` (the mac UX session), anything under
  `apps/mac/Extension/**`, `AitmproxyKit/EmbeddedCoreLaunch.swift`, `BusService.refreshScope`
  (scope-persistence session), `AitmproxyKit/CaptureStatus.swift` (capture.status session).
- A `capture_interface` column or badge in the app. `FlowRow` has no suitable field
  (`FlowOrigin` is `client/human/agent/imported`; `TLSState` is unrelated), and inventing one
  is UI work. The Kit decodes the field; the row does not carry it (D5).
- Changing anything else in `flow_summary`: #191 already made the push summary equal `flow.get` field for
  field (`push_summary_equals_flow_get_for_http_and_websocket_flows` enforces it).
- The web UI, TUI, or Rhai surfaces showing the new fields. They receive them for free on
  `flow.get`/`flow.table`; rendering is theirs later.
- Changing the `CaptureAdvice` banner logic. It keys on `session.clients.isEmpty` and goes
  away by itself once rows carry a client.

## Anti-goals

- Emitting a placeholder (`"unknown"`, `""`, `"proxy"`) where the core has no identity. A
  proxied flow is `null`; a captured flow whose provider sent no `source_app` is `null`. A UI
  must never show a fake app group.
- Guessing the identity from the client socket (peer port → `lsof`-style lookups). The only
  source is the provider's `FlowOpen.source_app`.
- Letting the ingress name a backend. `crates/aitm/src/ingress.rs` stays
  protocol-general and backend-agnostic: the interface name arrives on the captured flow, it
  is not a constant in the ingress.
- Widening the hard boundaries above. The lifted boundary is exactly the plumbing list in
  D1–D3; nothing else outside the four task areas moves.
- Treating `source_app` as trusted. It is backend-supplied text about a client: stored and
  displayed as data, never interpolated into a log line unescaped, never used in a scope or
  guard decision.

## Constraints

- Rust gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- Swift gate: `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build`
  (Terminal panel; inside the sandbox use `--scratch-path "$TMPDIR/aitm-swift-test"`).
- `apps/mac/tools/check-capture-operator-only.sh` is green on main ff35cb4 (#189 realigned its
  pins to `Store.defaults`/`SettingsDomain`); SA-AC5 requires it to stay green.
- `aitm-core` has no serde derive by design (`crates/aitm-plugin-sessionio/src/native.rs`
  header: adding one would be non-additive). The two new `FlowMeta` fields are plain
  `Option<String>`; `#[serde(default)]` goes on the `MetaRec` mirror.
- Everything compiles on every target: `ingress.rs`, `protocol.rs`, `flow.rs` are not
  macOS-gated; `CAPTURE_INTERFACE` is referenced only from `macos_capture/adapter.rs`, as today.
- No new dependencies, no new crates.
- Live verification is impossible before release (an unnotarized sysext does not activate on
  Matt's Mac): SA-AC6 is verified on the v0.5.5 DMG.

## Design

### Where the identity dies today (evidence, 2026-10-31)

| Step | Location | State |
|---|---|---|
| Provider → core | `crates/aitm/src/macos_capture/adapter.rs:195` `tcp_flow()` maps `FlowOpen.source_app` → `CapturedTcpFlow.peer_identity` | done |
| Ingress struct | `crates/aitm/src/ingress.rs:96` `CapturedTcpFlow.peer_identity: Option<String>` | exists |
| Dispatch | `crates/aitm/src/ingress.rs:190-280` `dispatch_tcp` reads `flow.sni`, `flow.dst`, `flow.first_bytes`, `flow.stream`; **never `flow.peer_identity`**; builds `NextLayerHint {dst, is_tls, client_hello_sni, alpn, first_bytes, from_upgrade}` (`:222`) and `ModuleCtx::new(..).with_modules(..).with_hint(hint)` | **dropped** |
| Hint / ctx | `crates/aitm-core/src/protocol.rs:42` `NextLayerHint`, `:74` `ModuleCtx` | no slot |
| Stored record | `crates/aitm-core/src/flow.rs:194` `ConnInfo {peer, sni, alpn, tls, established}`, `:204` `FlowMeta {marks, comment, is_replay, created, duration, truncated, edited}` | no slot, no captured-vs-proxied marker |
| HTTP module | `crates/aitm-proto-http/src/module.rs:252` reads only `ctx.hint().map(|h| h.dst)`; `Conn` built at `:267`, `:286` (`Conn::plain`) and `:370` (TLS, inside `mitm`, which receives `ctx`); `HttpFlow` built at `module.rs:591` (h1) and `h2.rs:352` (h2) with `metadata: FlowMeta::default()` | nothing to copy |
| WS module | `crates/aitm-proto-ws/src/module.rs:95-119` copies `client_conn`/`server_conn` from the handshake `HttpFlow`, then `metadata: FlowMeta::default()` | would not inherit a `FlowMeta` field |
| Interface name | `CAPTURE_INTERFACE = "macos-ne"` (`adapter.rs:49`) is applied only to the UDP `L4Target.interface` (`udp_target`); `CapturedTcpFlow` has no interface | TCP flows cannot name their backend |

### D1. Home on the stored record: `FlowMeta` (coordinator's decision)

`crates/aitm-core/src/flow.rs` `FlowMeta` gains, after `edited`:

```rust
/// The signing identifier of the process that opened the client connection, as a
/// capture backend observed it (macOS NE: `com.apple.Safari`). `None` for a proxied flow.
pub source_app: Option<String>,
/// The capture backend that delivered the client connection (`"macos-ne"`). `None` for
/// a proxied flow.
pub capture_interface: Option<String>,
```

Both `None` in `impl Default for FlowMeta`. Reason for `FlowMeta` over `ConnInfo`: every
`FlowMeta {` literal in the tree (7 outside `flow.rs`/`native.rs`) uses `..Default::default()`
/ `..FlowMeta::default()`, so the ripple is one file (`native.rs rec_to_meta`), while
`ConnInfo` has 88 literal sites and is mirrored into the session format as `ConnRec`. Both
HTTP and WebSocket flows have `metadata`, so the field is kind-independent (unlike
`request_bytes`).

Session format, `crates/aitm-plugin-sessionio/src/native.rs`: `MetaRec` gains
`#[serde(default)] pub source_app: Option<String>` and
`#[serde(default)] pub capture_interface: Option<String>`; `meta_to_rec` and `rec_to_meta`
copy them. A file written before this change lacks the keys and loads with `None`
(SA-AC7). The `SCHEMA` constant does not change: the addition is backward-compatible.

### D2. Carrier: `CapturedTcpFlow.interface` + two `NextLayerHint` fields

- `crates/aitm/src/ingress.rs` `CapturedTcpFlow` gains `pub interface: String` — "the
  capture backend's interface name, the string an operator's L4 scope names it by". Set by
  `crates/aitm/src/macos_capture/adapter.rs::tcp_flow` to `CAPTURE_INTERFACE.to_string()`.
  The ingress stays backend-agnostic (Anti-goals): it copies, it does not know `"macos-ne"`.
- `crates/aitm-core/src/protocol.rs` `NextLayerHint` gains
  `pub peer_identity: Option<String>` and `pub capture_interface: Option<String>`, documented
  as "`None` on the explicit-proxy path; set by a capture ingress".
- `dispatch_tcp` (`ingress.rs:222`) populates them:
  `peer_identity: flow.peer_identity.take()` (or `clone()`),
  `capture_interface: Some(flow.interface.clone())`. Scope gating, module matching,
  passthrough: unchanged.
- The explicit-proxy acceptor (`crates/aitm-core/src/proxy.rs:231`) sets both `None`.
- The upgrade hint the HTTP module hands off (`module.rs:1028`) carries the `Conn`'s values
  (D3) so a re-dispatched module sees the same attribution.

### D3. Modules stamp `FlowMeta` at every construction site

- `crates/aitm-proto-http/src/module.rs` `Conn` (`:470`) gains
  `pub(crate) source_app: Option<String>` and `pub(crate) capture_interface: Option<String>`,
  filled from `ctx.hint()` wherever a `Conn` is built for a live connection (`drive`'s two
  `Conn::plain` calls at `:267`/`:286`, and the TLS literal at `:370` inside `mitm`, which
  already receives `ctx`). `Conn::plain`'s signature may stay as it is (12 test call sites);
  how the two values reach the struct is the builder's choice (a `with_attribution(ctx.hint())`
  step or a small `fn attribution(ctx: &ModuleCtx) -> (Option<String>, Option<String>)`).
- A `Conn` method `pub(crate) fn flow_meta(&self) -> FlowMeta` returns
  `FlowMeta { source_app: self.source_app.clone(), capture_interface: self.capture_interface.clone(), ..FlowMeta::default() }`.
  The h1 site (`module.rs:591`) and the h2 site (`h2.rs:352`) use it instead of
  `FlowMeta::default()`.
- `crates/aitm-proto-ws/src/module.rs:95-119`: the match arm that takes `client_conn`/`server_conn`
  from the handshake `HttpFlow` also takes its metadata, and the `WsFlow` is stored with
  `metadata: inherit_attribution(&h.metadata)` where
  `pub(crate) fn inherit_attribution(handshake: &FlowMeta) -> FlowMeta` copies exactly
  `source_app` and `capture_interface` onto a fresh default (marks, comment, timing are the
  WebSocket flow's own). **(Architect's call)** — the coordinator's note "WS inherits" holds
  for `ConnInfo`; with `FlowMeta` as the home this two-line copy is required, and
  `aitm-proto-ws` is not on any session's do-not-touch list.

### D4. Wire shape

`crates/aitm-plugins/src/capture.rs` (the `flow.get` / `flow.table` builders):

- `summarize` and `flow_row` both `put("source_app", ..)` and `put("capture_interface", ..)`
  in the kind-independent part (next to `id` / `state` / `marks` / `duration_ms`), as
  `Value::Str(s)` when `Some`, `Value::Null` when `None`. Both keys are always present on
  every row, HTTP or WebSocket.
- `summary_fields` and `row_fields` each gain two `ParamDef`s: `TypeDesc::Str`,
  `required: false` (the convention here for a nullable field: `status`, `duration_ms`),
  descriptions "Signing identifier of the app that opened the connection, as the capture
  backend observed it; null for a proxied flow." and "Capture backend that delivered the
  connection (`macos-ne`); null for a proxied flow."
- `docs/design/operator-ui-foundation.md:389` (the `flow.get` row of §4.3) adds
  `source_app?, capture_interface?` to the summary shape — the one place the field schema is
  documented in prose (`grep -rn request_bytes docs/` finds only this line).

`crates/aitm-mcp/src/server.rs:2631 flow_summary` (the `flow.subscribe` push): both arms
(`http` and `ws`) add `"source_app": f.metadata.source_app` and
`"capture_interface": f.metadata.capture_interface` — `serde_json` renders `None` as `null`,
so the keys are present on every push exactly as on `flow.get`.

Vocabulary: `capture_interface` is the backend's interface name, the same string the UDP
`L4Target.interface` and the operator's L4 scope already use — `"macos-ne"` today
(`CAPTURE_INTERFACE`). A future backend supplies its own; no enum.

### D5. Kit: `source_app` → `FlowRow.client`; `capture_interface` decoded, not on the row

`apps/mac/Sources/AitmproxyKit/FlowSummary.swift`:

- `public var sourceApp: String?` and `public var captureInterface: String?`, decoded from
  `json["source_app"]?.stringValue` / `json["capture_interface"]?.stringValue`; an absent key,
  `null`, or an empty string all read as `nil`. Memberwise `init` gains both with default
  `nil`.
- `row(seq:coreID:)` sets `client: sourceApp.map { ClientInfo(sourceApp: $0) }`. Nothing
  else on the row changes; `captureInterface` is not placed on `FlowRow` (Non-goals).

`apps/mac/Sources/AitmproxyKit/Flow.swift`, next to `ClientInfo`:

- `public init(sourceApp identifier: String)` — `bundleID = identifier`,
  `name = ClientInfo.displayName(forSourceApp: identifier)`, monogram the default (first
  character of the name), `pid = nil`.
- `public static func displayName(forSourceApp identifier: String) -> String` — the rule,
  written down **(Architect's call)**:
  1. If `knownSourceApps[identifier]` exists, that name.
  2. Otherwise the text after the last `.`; if there is no `.`, or the text after it is
     empty (trailing dot), the whole identifier.
  3. Casing is kept as sent (`com.apple.curl` → `curl`, `com.apple.Safari` → `Safari`,
     `obscura` → `obscura`, `com.google.Chrome` → `Chrome`), matching the fixtures'
     lowercase `curl`/`python3` and capitalised `Safari`.
- `public static let knownSourceApps: [String: String]` =
  `["com.apple.WebKit.Networking": "Safari", "org.mozilla.firefox": "Firefox"]`.
  `com.apple.WebKit.Networking` is the signing identifier of the process that opens Safari's
  sockets on current macOS, so without the entry a Safari visit would group as `Networking`;
  the raw identifier stays in `bundleID`, so nothing is lost if another WebKit host shares
  it. SA-AC6 verifies the identifier live; if it differs, the fix is one map entry.

Grouping: `Session.clients` (`apps/mac/Sources/Aitmproxy/Session.swift:450`) counts by
`ClientInfo` (`Hashable` over name, monogram, bundleID, pid); identical identifiers yield one
group. `FlowRow ==` already includes `client`. No change there, and none is permitted.

### D6. Compatibility

- Older core (no keys) → `FlowSummary.sourceApp == nil` → `client == nil` → the Apps page
  behaves exactly as on v0.5.3 (banner). Newer core, older app → extra keys ignored.
- Older session file → `MetaRec` defaults → `None`.
- No `tools/list` consumer breaks: two optional fields added to two result schemas.

### Ripple (measured)

| Type | Production sites | Test literals | Edit |
|---|---|---|---|
| `FlowMeta {` | `native.rs:361` (full literal) | 0 (all 7 use `..Default`) | +2 fields in one literal |
| `MetaRec` | `native.rs:131`, `:349`, `:361` | — | +2 fields, serde default |
| `NextLayerHint {` | `proxy.rs:231`, `module.rs:1028`, `ingress.rs:222` | `upgrade_handoff.rs:88`, `tunnel.rs:167`, `seam.rs:94`, `m6_wiring.rs:109`, `:124` | +2 fields (`None` except ingress/upgrade) |
| `CapturedTcpFlow {` | `adapter.rs:196` | `ingress.rs:644`, `:699`, `:745`, `:915`, `:975`, `wire.rs:643` | +`interface` |
| `Conn {` | `module.rs:370` (+ `Conn::plain` body) | `module.rs:2369`, `:3658` | +2 fields |
| `HttpFlow`/`WsFlow` `metadata:` | `module.rs:597`, `h2.rs:360`, `ws/module.rs:119` | — | use `flow_meta()` / `inherit_attribution` |

## Acceptance criteria

1. **SA-AC0 (plumbing).** Driving `CoreIngress::dispatch_tcp` with
   `CapturedTcpFlow { interface: "macos-ne", peer_identity: Some("com.apple.Safari"), .. }`
   gives the claiming module a hint with `peer_identity == Some("com.apple.Safari")` and
   `capture_interface == Some("macos-ne")`; the real HTTP module, serving one cleartext
   request on a connection whose attribution is those two values, stores an `HttpFlow` with
   `metadata.source_app == Some("com.apple.Safari")` and
   `metadata.capture_interface == Some("macos-ne")`; a connection with no attribution stores
   `None`/`None`; the WebSocket flow built from such a handshake copies both values and
   nothing else from the handshake's metadata. The adapter's `tcp_flow` sets
   `interface == CAPTURE_INTERFACE`, and the adapter integration test sees the identity on
   the recorded hint.
2. **SA-AC1 (core read).** `flow.get` and `flow.table` emit `source_app` and
   `capture_interface` on every row: `Value::Str` for a captured flow, `Value::Null` (key
   present) for a proxied flow, for HTTP and WebSocket alike. Both result schemas declare
   them as optional `TypeDesc::Str` with a description naming "proxied". The `flow.get` row
   of `docs/design/operator-ui-foundation.md` §4.3 lists them.
3. **SA-AC2 (core push).** A `notifications/aitm/flow` line's `params.summary` carries
   `source_app` and `capture_interface` with the same values as `flow.get` for the same
   flow, `null` on a proxied flow, on both the `http` and `ws` arms.
4. **SA-AC3 (Kit).** `FlowSummary(json:)` with `"source_app": "com.apple.Safari"` yields
   `row().client == ClientInfo(name: "Safari", monogram: "S", bundleID: "com.apple.Safari")`;
   with the key absent, `null`, or `""`, `row().client == nil`; `captureInterface` decodes
   (`"macos-ne"` / `nil`) and is not on `FlowRow`. `ClientInfo.displayName(forSourceApp:)`
   follows D5 exactly: `com.apple.Safari`→`Safari`, `com.apple.curl`→`curl`,
   `obscura`→`obscura`, `com.google.Chrome`→`Chrome`, `com.apple.WebKit.Networking`→`Safari`,
   `org.mozilla.firefox`→`Firefox`, `trailing.`→`trailing.`.
5. **SA-AC4 (tests).** Each of SA-AC0–SA-AC3 and SA-AC7 is pinned by a named test listed in
   the plan; the existing Apps grouping, `FlowRow ==`, and `CaptureAdvice` tests pass
   unchanged.
6. **SA-AC5 (gates).** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
   green; `swift test --package-path apps/mac ...` green;
   `apps/mac/tools/check-capture-operator-only.sh` exits 0 on the branch (it is green on main
   ff35cb4 after #189; output quoted in the Tester's report).
7. **SA-AC6 (manual, v0.5.5 DMG).** With capture working and an in-scope host, a Safari
   page load produces rows whose `flow.get` shows `"source_app"` set and
   `"capture_interface": "macos-ne"`, and the Apps page shows a `Safari` group (the banner is
   gone). A `curl` to the same host adds a `curl` group. A request through the explicit proxy
   (`-x 127.0.0.1:8080`) shows `null`/`null` and joins no group.
8. **SA-AC7 (session files).** A native session document whose `meta` lacks the two keys
   loads with `None`/`None`; a `FlowMeta` with `Some("com.apple.Safari")`/`Some("macos-ne")`
   survives `meta_to_rec` → serialise → deserialise → `rec_to_meta` unchanged.

## Left to the builder

- How the hint's two values reach `Conn` in the HTTP module (parameter, builder step, or
  helper), as long as all three live construction sites carry them and `Conn::plain`'s test
  callers keep compiling.
- Whether `dispatch_tcp` moves (`take()`) or clones `peer_identity`.
- The exact doc-comment wording; the names `flow_meta`, `inherit_attribution`,
  `knownSourceApps`, `displayName(forSourceApp:)` may be renamed if the surrounding code has a
  stronger convention — not relocated.
- Where in `KitTests.swift`'s `FlowSummaryTests` suite the new tests sit, or a sibling suite
  in the same file.

## Open questions

None. Decisions already taken by the coordinator (2026-10-31): boundary lifted for the
plumbing files named in D1–D3; home is `FlowMeta`; `CapturedTcpFlow.interface` is set by the
adapter; `NextLayerHint` is the carrier; `capture_interface` stays off `FlowRow`.

## Summary

Persist the provider's `source_app` and the backend name on `FlowMeta` by carrying them from
`CapturedTcpFlow` through `NextLayerHint` into the HTTP module's `Conn`, stamp them on every
HTTP/h2/WebSocket flow, emit them (or `null`) on `flow.get`, `flow.table` and the push
summary, and decode `source_app` in the Kit into `FlowRow.client` with a written
display-name rule — so the Apps page groups live capture without any UI change.

**Architect's calls** (correct any in the plan's Review log):
1. The WebSocket module copies the two fields from the handshake's `FlowMeta` via a pure
   `inherit_attribution` helper (a two-line change in `aitm-proto-ws`, required because the
   home is `FlowMeta`, not `ConnInfo`).
2. `required: false` for the two schema fields (the file's convention for nullable fields).
3. The two keys are always present (null for proxied), on WebSocket rows too.
4. Display-name rule: known map, else last dotted component, casing kept; the map holds
   `com.apple.WebKit.Networking → Safari` and `org.mozilla.firefox → Firefox`.
5. `FlowSummary.captureInterface` is decoded (wire mirror, tested) but not placed on
   `FlowRow`.
6. `""` on the wire reads as `nil` in the Kit (never an empty app group).
