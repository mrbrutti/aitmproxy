# aitmproxy M6 — mitmproxy / Proxyman feature-parity design

**Status:** approved (2026-10-28 by Matt)
**Research inputs:** `../ui-macos-8dc0c7/apps/mac/docs/CAPABILITIES.md` (parity/gap matrix — §2, §3.4/§3.5/§3.7, §4, §5/§6), `docs/research/01-mitmproxy.md`, `docs/design/operator-ui-foundation.md` (§5 core follow-ups F3/F9/F10/F11, §4.5 intercept sequence), `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md` (core types), `docs/superpowers/specs/2026-10-27-aitmproxy-plugin-system-design.md` (additive plugin/command seam), `docs/superpowers/specs/2026-10-27-aitmproxy-ui-scripting-highlight-l4-design.md` (M5 capability-extension pattern).

## Intent

aitmproxy's core captures and edits HTTP/1.1, HTTPS and WebSocket today, and the
operator UIs are built to Proxyman density, but six genuine parity gaps remain
between what an operator *should* be able to do with a mitmproxy/Proxyman-class
tool and what the core bus actually serves. Five of those gaps are additive
command/plugin work; the sixth, HTTP/2, is deep protocol work. This spec designs
the **five additive gaps** — rule-based and response-phase interception with kill
modes (F3), WebSocket inject/edit/drop (F9), sessions and import/export with HAR
as the interchange format (F10), per-host TLS passthrough (F11), and Map Local /
Map Remote — each additively on the existing `Flow`/`Event`/`Plugin`/`Command`
architecture, with a shared rule-match model that F3 and the Map rules reuse.
The sixth gap, **HTTP/2**, carries its own risk and conformance surface; Matt
approved splitting it into **its own milestone (M7)**, so it is left here as a
forward-pointing stub (§6) and is *not* designed in this spec.

## Goals

- **F3 — selective, two-phase interception.** Breakpoint *rules* (so interception
  is selective, not the current global all-requests arm), response-phase parking
  and edit (status/headers/body), and `flow.kill` abort *modes* (reset / 429 / 503).
- **F9 — WebSocket write control.** Compose and inject a frame (`ws.send`), and
  intercept / edit / drop a live frame, over the bus — the operator counterpart to
  the Rhai `on_ws_message`/`msg.drop()`/`msg.set_text()` surface that already exists.
- **F10 — sessions and portable capture.** `session.save`/`session.load` persist
  and restore the flow store; `flow.export`/`flow.import` move flows in and out
  with **HAR 1.2** as the primary interchange format.
- **F11 — per-host TLS passthrough.** A host include/exclude list that decides
  whether a TLS connection is MITM'd (decrypted) or tunnelled byte-for-byte, driven
  by the SNI the acceptor already peeks.
- **Map Local / Map Remote.** Serve a local file as the response for matching
  requests (Map Local), or rewrite a matching request's target host/URL before it
  goes upstream (Map Remote), driven by the same rule-match model as F3.
- **HTTP/2 — deferred to M7.** Not a goal of this spec; §6 records what the M7
  spec must cover and why the split was taken.
- **One shared rule-match model** (URL wildcard/regex, method, host, phase,
  WebSocket direction) used by F3 breakpoint rules, WS frame interception, and the
  Map rules — specified once, reused.
- **Every new capability stays additive and deny-by-default**, consistent with how
  M3 (scripts) and M5 (L4) extend the scope/rate/SSRF guards: new first-party
  plugins and commands register into the existing `Registry`; `aitm-core` is not
  edited where it can be avoided, and any unavoidable core touch is called out.

## Non-goals

- **No operator-UI work.** The mac/web/TUI rule sheets, response editor, WS frame
  composer, SSL list and import/export panels are app-side and already built or
  app-ready (CAPABILITIES §3); this spec delivers only the *core bus* they call.
- **No live push.** Response-phase intercept and WS frames produce updates that the
  operator sees — streaming them is F4 (M4, in flight), not this spec; M6 surfaces
  them through the existing request/response cycle and `flow.detail`.
- **No new filter/rule DSL beyond the shared model.** The rule-match model carries
  wildcard/regex/method/host/phase only; richer matching (JSONPath, GraphQL,
  body-content rules) is deferred.
- **No import of every proprietary format.** HAR 1.2 is in (import + export);
  mitmproxy `.flows` import is in; Proxyman `.proxyman`/Charles `.chlz` and export
  to Postman/OpenAPI are deferred (Open Question 2). CSV/cURL export stay app-side.
- **No HTTP/3 or QUIC, no gRPC decode, no SOCKS5.** Out of scope for M6 and M7.
- **Not re-specced here** (shipped or owned elsewhere): F5 `flow.detail`, F6
  mark/comment, F7 proxy/config, F12 `scope.remove`/agent-widen gate, F13 PoC
  artifacts, M3 Rhai (F8), M2 browser/CA; M4 (F1/F2/F4, agent policy); M5 raw L4.

## Anti-goals

- Interception that still stops *every* request once rules exist, or a response
  park that the client cannot be released from — a hung flow with no resume is a
  failure.
- A second, divergent rule type. If Map Local, Map Remote and F3 breakpoints each
  grow their own match struct, the "one shared rule-match model" goal has failed.
- HTTP/2 that forks the flow/event model. If h2 flows need a different `Flow`
  variant, a different `Event` set, or make intercept/mutate/plugins behave
  differently from h1, the "same surface" goal has failed and every downstream
  consumer must special-case h2.
- A Map Remote redirect or a `ws.send` injection that reaches a host the scope/rate
  guard would refuse — bypassing the guard on active traffic is a security failure.
- A TLS passthrough that the agent can add silently to hide traffic from the
  operator, or that is confused with scope (passthrough is "do not decrypt"; scope
  is "may act on").
- Bundling HTTP/2's protocol risk with the five additive items such that an h2
  regression blocks shipping response-phase edit, WS inject, sessions and
  passthrough that are otherwise ready.

## Constraints

- **Rust gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  must pass before any review. `unsafe` needs a `// SAFETY:` comment and a
  Security-reviewer sign-off.
- **Additive-only core.** New behavior is new crates/plugins/commands registered
  into the existing `Registry`; `aitm-core`'s `Flow`/`Event`/`InterceptState`/
  `FlowCtx`/`Command` shapes are reused, not changed. `HttpVersion::H2`,
  `Event::{ResponseHeaders, Response, WsMessage}`, `WsMessage.injected`,
  `WsStateMachine::send_frame`, `NextLayerHint.{client_hello_sni, alpn}` already
  exist and are the seams M6 fills in. Any genuinely unavoidable `aitm-core` edit
  is named and justified in Design.
- **Deny-by-default, guards reused.** Every command that causes active egress
  (`ws.send`, Map Remote redirect, any replay-on-import) passes
  `ScopeRateGuard::check_active` on the target host. Agent (`Frontend::Mcp`)
  mutation of behavior-changing configuration (TLS passthrough list, Map rules)
  is gated behind a config flag that defaults off, mirroring
  `ca.allow_agent_install`, `scope.allow_agent_widen`, `scripts.allow_agent_authoring`.
- **Performance/memory (platform hard requirement).** The M6 items add no new
  high-throughput path; `flow.import`/`session.load` and HAR export must stream or
  cap large captures rather than buffer unboundedly, and TLS passthrough must copy
  bytes without buffering whole streams. (The bounded-memory bar for HTTP/2's
  multiplexed streams is an M7 concern.)
- **Dependencies.** Prefer the approved stack: `tokio-tungstenite` (already in
  `aitm-proto-ws`) for WS control, `serde` + an existing JSON codec for
  HAR/session serialization, the `regex` crate for rule matching. No new TLS or
  async stack. (HTTP/2's `h2`-crate dependency is an M7 concern.)
- **Config via YAML**, `deny_unknown_fields` (platform M2 amendment): new config
  (`Config.tls`, Map rules persistence, session defaults) parses from the same
  YAML file and errors on an unknown key.
- **Workflow:** every item travels the seven stages in `docs/superpowers/WORKFLOW.md`.

## Design

The five M6 items decompose into **one shared rule-match crate** and **five
additive first-party plugins + command sets** (F3 extends the existing intercept
plugin; F9, F10, F11, Map are new plugins). HTTP/2, the sixth gap, is a deep
protocol extension in `aitm-proto-http` that is **deferred to M7** and only
stubbed here (§6). The sequencing subsection records that decision.

### 0. Shared rule-match model (`aitm-rules`, new crate) — **(Architect's call)**

F3 breakpoint rules, WS frame interception and the Map rules all answer the same
question: *does this flow, at this phase, match an operator-authored condition?*
That is specified once, in a small new crate both the intercept plugin and the Map
plugin depend on (neither `aitm-core` nor `aitm-plugin` is edited; `aitm-rules`
depends only on `aitm-core` types it matches against).

```rust
// aitm-rules — the one rule/condition type reused by F3, WS intercept, and Map
pub struct Rule {
    pub id: String,               // server-assigned, stable; the handle for remove
    pub name: Option<String>,
    pub enabled: bool,
    pub condition: MatchCondition,
}

pub struct MatchCondition {
    pub url: Option<UrlMatch>,    // matched against scheme://authority/path?query
    pub method: Option<String>,   // case-insensitive exact; None == any
    pub host: Option<HostMatch>,  // authority wildcard; None == any
    pub phase: Phase,             // which lifecycle point this rule fires at
    pub ws_dir: Option<WsDir>,    // WS-frame rules only; None == any direction
}

pub enum UrlMatch { Wildcard(String), Regex(String) }   // Regex uses the `regex` crate
pub enum HostMatch { Exact(String), Wildcard(String) }  // "*.example.com"
pub enum Phase { Request, Response, WsFrame, Any }

/// One matcher, reused everywhere. `flow`/`phase` come from the dispatching plugin.
pub fn matches(rule: &Rule, flow: &Flow, phase: Phase, dir: Option<WsDir>) -> bool;
```

Decision: `UrlMatch` carries both wildcard and regex because Proxyman and
mitmproxy both offer both and the operator rule sheets already expose the choice
(operator-ui-foundation §2.7 "URL wildcard/regex"). Regex is compiled once per
rule at add-time; an invalid pattern is rejected by the command that adds it.

### 1. F3 — rule-based + response-phase intercept + kill modes

**What it is (operator terms).** Today `flow.intercept {enabled?}` arms a global
request-phase breakpoint: every request parks, nothing else. F3 makes it (i)
*selective* via rules, (ii) *two-phase* so a response can be paused and its
status/headers/body edited, and (iii) gives `flow.kill` three abort modes.

**Command surface.** Extend the existing first-party **intercept plugin** (no new
plugin); extend two command schemas additively:

```
flow.intercept {enabled?: bool, rules?: [Rule]}  -> {enabled: bool, rules: [Rule]}
    # enabled with no rules == today's global request-phase arm (back-compatible).
    # rules present == park only flows matching a rule at its phase.
flow.kill {id: FlowId, mode?: "reset" | "429" | "503"}  -> ok
    # default "reset" == today's behavior (client sees a closed/reset connection).
    # "429"/"503" synthesize that status response to the client instead of a reset.
flow.mutate {id, edits: {method?, path?, headers?, body?, status?}}  -> ok
    # additive `status?: int`; when a flow is parked at the Response phase, edits
    # apply to the response and `status` is valid; otherwise edits apply to the
    # request and `status` is rejected.
```

**How it fits additively.**
- **Rules:** the intercept plugin holds the active `Vec<Rule>` (set by
  `flow.intercept`). On each `Event` it calls `aitm_rules::matches`; a match at the
  event's phase calls the existing `FlowCtx::intercept()` to park. No core edit —
  this is the plugin choosing *when* to park instead of always.
- **Response-phase parking (park at `ResponseHeaders` — confirmed 2026-10-28 by
  Matt):** the `ResponseHeaders` / `Response` events already exist and are
  dispatched through the chain and awaited by `aitm-proto-http`. In the current
  module the response head and body stream to the client **between** the
  `ResponseHeaders` emit (awaited, before the body is enqueued) and the `Response`
  emit (after the body has already streamed) — so a park on `Event::Response` is
  too late to edit what the client sees. The intercept plugin therefore calls
  `FlowCtx::intercept()` on **`Event::ResponseHeaders`**; because that emit is
  awaited before any client byte, the parked future suspends the response until
  `flow.resume`, and the edited status/headers/body reach the client (AC-F3.2).
  **No `aitm-core` edit is required** provided `aitm-proto-http` awaits the
  `ResponseHeaders` emit (it must, to honor short-circuit); the builder verifies
  this first (plan Task 2) and, if the module does not yet suspend there, the fix
  is additive in `aitm-proto-http`, not the core. This is the only place a
  core-vs-module await could bite.
- **Kill modes:** `reset` keeps `FlowCtx::kill()`. `429`/`503` build a minimal
  `HttpResponse` with that status and an empty body and call `FlowCtx::set_response`
  then release to the client — a short-circuit, not an upstream call, so no guard
  is needed (no egress).
- **Response edit:** `flow.mutate` applies to the parked phase; adding `status?`
  lets the operator change the response code. The mutate plugin already edits in
  place via `FlowCtx::flow_mut()`.

**Dependencies (not designed here):** response-phase parked updates are what F4
(M4) will stream; the rule sheet UI is operator-surface work.

### 2. F9 — WebSocket inject / edit / drop

**What it is.** WS frames are captured today (`WsFlow.messages`,
`WsMessage.injected` exists) but cannot be written. F9 lets the operator compose
and inject a frame, and intercept/edit/drop a live frame — the bus counterpart to
the Rhai `on_ws_message` surface.

**Command surface.** A new first-party plugin **`aitm-plugin-wsctl`** (in-tree,
depends on `aitm-core` + `aitm-proto-ws` + `aitm-rules`):

```
ws.send {id: FlowId, dir: "c2s" | "s2c", opcode: "text" | "binary" | "ping" | "pong" | "close", data: Bytes}
    -> {index: int}        # index of the appended WsMessage (injected == true)
ws.intercept {enabled?: bool, rules?: [Rule]}  -> {enabled: bool, rules: [Rule]}
    # rules with phase == WsFrame and optional ws_dir; parks matching frames.
ws.frame {id: FlowId, index: int, action: "forward" | "drop", data?: Bytes, opcode?: Str}
    -> ok                  # act on a parked frame: edit-then-forward, or drop.
```

**How it fits additively.**
- `WsStateMachine::send_frame(to, msg)` already exists — the inject seam. The
  problem is reaching the *live* connection's machine from a command. The wsctl
  plugin keeps an `Arc<Map<FlowId, FrameChannel>>`: on `Event::WsStart` the WS
  module registers the live connection's inject channel; on `Event::WsEnd` it is
  removed. `ws.send` resolves the channel and enqueues a frame the module forwards
  via `send_frame`, appending a `WsMessage { injected: true }`. This is shared
  state between `aitm-proto-ws` and the plugin via `Arc` — no `aitm-core` edit.
  (If registering that channel needs a hook the WS module does not expose, the
  addition is in `aitm-proto-ws`, additive; called out for the builder.)
- Frame interception reuses the rule model (`Phase::WsFrame`): the wsctl plugin
  parks a matching frame at `Event::WsMessage` via `FlowCtx::intercept()`;
  `ws.frame` edits the parked `WsMessage` in place (or marks it dropped) and
  releases it. Drop == do not forward the frame (mirrors Rhai `msg.drop()`).

**Guard (deny-by-default).** `ws.send` injects active traffic onto a live socket
to a host → it **must** pass `ScopeRateGuard::check_active(authority_of(flow))`;
an out-of-scope WS target is refused with the guard's error. `ws.frame`
forward/drop/edit acts on an **already-captured, already-parked** frame (no new
egress beyond what the flow already carries) → no additional guard, same as
editing a parked HTTP request.

### 3. F10 — sessions + import/export (HAR 1.2)

**What it is.** Persist and restore the whole capture (`session.save/load`) and
move flows across tools (`flow.export/import`) with HAR 1.2 as the interchange.

**Command surface.** A new first-party plugin **`aitm-plugin-sessionio`**:

```
session.save {path: Str}                      -> {flows: int, path: Str}
session.load {path: Str}                       -> {flows: int}      # replaces the store
flow.export {ids?: [FlowId], format: "har" | "aitm", path?: Str}
    -> {bytes?: Bytes, path?: Str, flows: int}  # ids omitted == whole store
flow.import {path?: Str, bytes?: Bytes, format: "har" | "aitm" | "mitmproxy"}
    -> {ids: [FlowId]}
```

**How it fits additively.**
- Serialization is a serde view over `Flow`/`HttpFlow`/`WsFlow`. The **`aitm`
  native session format** is a full-fidelity serde of the store (round-trips every
  field incl. `FlowMeta`, `InterceptState` collapsed to `Observed`, WS messages).
  **HAR 1.2** is a lossy interchange (request/response/timings/WS messages →
  HAR `log.entries` + `_webSocketMessages`); fields HAR cannot hold are dropped on
  export and defaulted on import.
- `session.load` and `flow.import` populate the store via `FlowStore::insert`;
  imported flows carry `FlowMeta` with an `imported` marker and `is_replay = false`.
- Formats: **in scope** — HAR 1.2 export+import, native `aitm` export+import,
  mitmproxy `.flows` **import**. **Deferred** (Open Question 2) — Proxyman/Charles
  import, Postman/OpenAPI export.

**Guard.** Import and session-load are **passive**: they populate the store from a
file and perform **no egress**, so they do not pass `ScopeRateGuard` — exactly as
passive capture is ungated (platform Reconciliation R1). Import **never
auto-replays**; replaying an imported flow is an explicit later `flow.replay`,
which is already guarded. This is stated so the builder does not add a
replay-on-import convenience that would smuggle active traffic past the guard.

### 4. F11 — per-host TLS passthrough

**What it is.** A host list deciding, per TLS connection, whether to MITM
(decrypt) or tunnel it byte-for-byte. A passthrough host is never decrypted, so it
produces no editable HTTP flows — the operator deliberately leaves it alone (e.g.
a pinned app, or traffic out of authorization's intent).

**Command surface + config.** A new first-party plugin **`aitm-plugin-passthrough`**
owning a shared passthrough list, plus `Config.tls`:

```
tls.passthrough.list {}                 -> {hosts: [Str]}
tls.passthrough.add {host: Str}          -> {hosts: [Str]}
tls.passthrough.remove {host: Str}        -> {hosts: [Str]}
```
```rust
// aitm (binary) Config — additive
pub struct TlsConfig {
    pub passthrough: Vec<String>,        // host or *.wildcard; seeds the list at start
    pub allow_agent_passthrough: bool,   // default false: agent cannot mutate the list
}
// Config gains: pub tls: TlsConfig,
```

**How it fits additively.** A `PassthroughModule: ProtocolModule` whose
`matches(&NextLayerHint)` returns true when `client_hello_sni` (or the CONNECT
authority) matches an entry in the shared list, **registered before
`aitm-proto-http`** so it wins the `matches` race. Its `spawn` opens the upstream
via `ModuleCtx::connect_upstream` and copies bytes both directions with no TLS
MITM — the client completes TLS directly against the real server's cert. It
records a minimal tunnel flow (host, bytes up/down, no body) so the SSL column can
show "tunnelled". Uses the **existing `ProtocolModule` seam** — no `aitm-core`
edit. The `tls.passthrough.*` commands mutate the same `Arc`-shared list the
module reads.

**Passthrough vs scope (be precise).** Passthrough and scope are orthogonal and
must not be conflated:
- **Scope** = "the operator/agent may take active action on this host." It gates
  `flow.replay`, `request.send`, `ws.send`, Map Remote, `browser.navigate`.
- **Passthrough** = "do not decrypt this host's TLS." It removes the host from
  MITM entirely; no editable flow is produced, so there is nothing to act on.
- A host may be in both: then it is tunnelled and scope is moot (no flows).
  Passthrough **never widens scope** and adding to scope **never** forces MITM of a
  passthrough host. Adding passthrough only ever *reduces* what the proxy sees, so
  it is safe for the operator; but an agent could use it to *hide* traffic, so
  agent mutation is gated by `allow_agent_passthrough` (default off), consistent
  with the M3/M5 agent-authoring gates.

### 5. Map Local / Map Remote

**What it is.** Map Local serves a local file as the response for matching
requests (a mock); Map Remote rewrites a matching request's target host/URL before
it goes upstream (a redirect). Both are operator-configured rules.

**Native commands, not bundled Rhai — recommended (Architect's call).**
CAPABILITIES §3.8 floats shipping these as bundled Rhai scripts with a form UI.
Recommend **native first-party commands + a plugin** instead, because: (a) they
share the rule-match core with F3 — bundling in Rhai would duplicate matching;
(b) the operator UIs build their forms from `tools/list` schemas, so a stable
typed command surface is what makes the Map rule sheet work the same on mac/web/
TUI; (c) Map Local's file serving and path confinement, and Map Remote's scope
gating, want deterministic Rust, not sandboxed script budget. Rhai remains the
escape hatch for *custom* rewrite logic. Flagged as Open Question 3.

**Command surface.** A new first-party plugin **`aitm-plugin-maprules`** (depends
on `aitm-rules`); one unified command set with a `kind` discriminator
(**(Architect's call)** — tighter than separate `map.local.*`/`map.remote.*`):

```
map.add {kind: "local" | "remote", condition: MatchCondition, action: MapAction}
    -> {id: Str}
map.list {}        -> {maps: [{id, kind, condition, action}]}
map.remove {id}    -> ok
```
```rust
// aitm-plugin-maprules — the action half (condition is the shared MatchCondition)
pub enum MapAction {
    Local  { path: String, status: Option<u16>, headers: Vec<(String,String)> },
    Remote { to: RemoteTarget },   // rewrite target before upstream
}
pub enum RemoteTarget { Url(String), Host { authority: String, scheme: Option<String> } }
```

**How it fits additively.**
- **Map Local:** on `Event::RequestHeaders`/`Request`, the plugin matches; on a
  match it reads the configured file, builds an `HttpResponse` (default status 200,
  content-type inferred unless overridden), calls `FlowCtx::set_response` and
  returns `Verdict::Halt` — short-circuit, no upstream. File paths are **confined
  to a configured map-local root** (no traversal outside it; the add command
  rejects an escaping path) — the path-confinement analog of the SSRF guard. Map
  Local performs **no egress**, so it does not pass `ScopeRateGuard`.
- **Map Remote:** on `Event::RequestHeaders`/`Request`, the plugin rewrites the
  request's `scheme`/`authority`/`path` in place via `FlowCtx::flow_mut()` before
  forwarding. Because the request now goes to a **different host**, the plugin
  **must** call `ScopeRateGuard::check_active` on the rewritten authority; if the
  redirect target is out of scope the mapping errors/declines and the original is
  not sent — this is the deny-by-default point for Map Remote.
- **Agent gate:** `map.add`/`map.remove` mutate traffic-shaping behavior, so agent
  (`Frontend::Mcp`) authoring is gated by `maps.allow_agent_authoring` (default
  off), mirroring `scripts.allow_agent_authoring`.

### 6. HTTP/2 — deferred to M7 (stub, not designed here)

HTTP/2 is the sixth parity gap but is **not designed in this spec**. Matt approved
splitting it into **its own milestone (M7)** because it is deep protocol work with
a distinct risk and conformance surface (see the sequencing table below), and
bundling it would let an h2 regression hold the five additive M6 items hostage.
This section is a forward-pointing stub; the real design is the M7 spec's job.

**What an M7 HTTP/2 spec must cover** (seed for that spec; the detailed sketch
lives in this file's git history at the draft commit, if useful): ALPN
negotiation offering `h2` on both the forged-leaf (downstream) and upstream TLS
configs, replacing today's pinned `http/1.1`; an h2 arm behind the existing
`HttpStateMachine` seam (the `h2` crate) that emits the **same `HttpSansIoEvent`/
`Event` variants** as h1 so intercept/mutate/plugins work on h2 flows unchanged;
each h2 stream mapped to one `HttpFlow` with a per-connection `stream_id → FlowId`
table (HPACK, flow control, `WINDOW_UPDATE`, `RST_STREAM`, `GOAWAY`); bodies kept
streamed with per-stream/per-connection caps honoring `LimitConfig` for bounded
memory; and full h2↔h1 version bridging in both directions (pseudo-headers ↔
request line/Host, trailers, hop-by-hop header stripping per RFC 9113). The
invariant it must hold: h2 does **not** fork the `Flow`/`Event` model. Its
acceptance criteria (ALPN+capture, multiplexing→distinct flows, intercept/mutate
on h2, h2↔h1 bridging, bounded memory under multiplexed load) move to the M7 spec.

### Milestone sequencing — HTTP/2 split to M7 (decided 2026-10-28 by Matt)

| # | Item | Size | Risk | Shares the rule-match core | New crate(s) |
|---|---|---|---|---|---|
| F3 | rules + response park + kill modes | **M** | Low–Med (response-await verify) | yes | — (extends intercept plugin) + `aitm-rules` |
| F9 | WS inject/edit/drop | **M** | Med (live-conn channel wiring) | yes | `aitm-plugin-wsctl` |
| F10 | sessions + import/export (HAR) | **M** | Low (serde surface) | no | `aitm-plugin-sessionio` |
| F11 | TLS passthrough | **S** | Low | no | `aitm-plugin-passthrough` |
| Map | Map Local / Map Remote | **M** | Low–Med (path confinement, scope) | yes | `aitm-plugin-maprules` |
| H2 | HTTP/2 core | **L** | **High** (protocol depth, h2↔h1 matrix) | no | — (deep change in `aitm-proto-http`) |

**Grouping (decided):**

- **M6 = F3 + F9 + F10 + F11 + Map Local/Remote** — the additive
  intercept/transform/IO completeness. Five items that reuse the existing
  `Flow`/`Event`/`InterceptState`/`ProtocolModule` seams, share the `aitm-rules`
  core (F3, F9, Map), carry Low–Med risk, and are each a plugin + command set with
  a bounded, deterministic test surface. They can be built and reviewed largely in
  parallel once `aitm-rules` lands first.
- **M7 = HTTP/2 core** — on its own. It is the only **L**/High-risk item; it is
  deep protocol work in one crate with a distinct test surface (h2 conformance,
  HPACK, flow control, multiplexing, GOAWAY/RST, and the full h2↔h1 translation
  matrix). Bundling it with M6 would let an h2 regression hold the five
  ready-to-ship items hostage, and would mix a protocol-engine review with five
  command/plugin reviews. Isolating it also lets M6's rule-match and command work
  land and stabilize the operator surfaces first, against the h1 path that already
  works.

The M7 HTTP/2 spec (§6 stub) is a separate Stage-1→2 effort, not part of M6.

### Deny-by-default / capability model (summary)

| New capability | Egress? | Guard | Agent gate |
|---|---|---|---|
| `flow.intercept` rules, response park, `flow.mutate` status | no | none (edits a captured flow) | n/a (operator intercept control) |
| `flow.kill {mode:429\|503}` | no (short-circuit) | none | n/a |
| `ws.send` | **yes** (live socket) | `ScopeRateGuard::check_active` | n/a (active, scope-gated) |
| `ws.frame` forward/drop/edit | no (parked frame) | none | n/a |
| `session.save/load`, `flow.export/import` | **no** (file I/O only; no replay) | none | n/a (passive) |
| `tls.passthrough.*` | no (reduces visibility) | none | `allow_agent_passthrough` (default off) |
| Map Local | no (serves local file) | none; path confined to map root | `maps.allow_agent_authoring` (default off) |
| Map Remote | **yes** (redirects upstream) | `ScopeRateGuard::check_active` on rewritten host | `maps.allow_agent_authoring` (default off) |
| HTTP/2 (M7, deferred) | n/a (protocol) | will inherit all existing h1 guards unchanged | n/a |

This matches the M3/M5 pattern: new mutating config is deny-by-default for agents
behind a config flag; new active traffic goes through the one `ScopeRateGuard`;
passive operations (edit-of-captured, import, passthrough-reduces-visibility) are
not guarded, and the reason is stated each time.

## Acceptance criteria

Each is observable via `cargo test` (integration tests may register the plugin,
stand up a local echo/WS/TLS server, and drive commands through the registry).
Literal expected values are given where a value is load-bearing.

**Shared rule-match (§0)**

1. **AC-R1:** `aitm_rules::matches` returns `true` for a `Rule` with
   `UrlMatch::Wildcard("*/login")` against a flow whose path is `/api/login`, and
   `false` against `/api/logout`.
2. **AC-R2:** a `Rule` with `UrlMatch::Regex("^/v[0-9]+/users$")` matches `/v2/users`
   and does not match `/v2/users/1`; an invalid regex passed to the add-command is
   rejected with an error (the command returns `isError: true`), not a panic.

**F3 (§1)**

3. **AC-F3.1:** with `flow.intercept {enabled:true, rules:[{url:"*/admin", phase:"request"}]}`,
   a request to `/admin` parks (its `InterceptState` is `Intercepted`) while a
   concurrent request to `/public` is **not** parked and completes normally.
4. **AC-F3.2:** a flow parked at the **response** phase can have its status changed
   via `flow.mutate {id, edits:{status:418}}` and, after `flow.resume`, the client
   receives HTTP status **418** with the edited body.
5. **AC-F3.3:** `flow.kill {id, mode:"429"}` on a parked request delivers HTTP
   **429** to the client and makes no upstream connection (the upstream server
   records **zero** requests for that flow); `mode:"reset"` (and default) still
   closes/resets the connection.

**F9 (§2)**

6. **AC-F9.1:** `ws.send {id, dir:"c2s", opcode:"text", data:"ping-inject"}` on a
   live WS flow causes the upstream WS echo server to receive a frame whose text is
   `ping-inject`, and the appended `WsMessage` has `injected == true`.
7. **AC-F9.2:** with `ws.intercept` armed by a `Phase::WsFrame` rule, a matching
   frame parks; `ws.frame {id, index, action:"drop"}` prevents it reaching the
   peer (the peer receives it **not at all**), and `action:"forward"` with `data`
   delivers the edited bytes.
8. **AC-F9.3:** `ws.send` to a WS flow whose host is **not in scope** is refused
   with the `ScopeRateGuard` out-of-scope error (`isError: true`); after
   `scope.add` of that host it succeeds.

**F10 (§3)**

9. **AC-F10.1:** `session.save {path}` then `session.load {path}` into a fresh
   store restores the same number of flows and a chosen flow's method, URL, status,
   headers and body round-trip byte-for-byte (native format).
10. **AC-F10.2:** `flow.export {format:"har"}` produces a document that parses as
    valid HAR 1.2 (`log.version == "1.2"`) and whose first entry's
    `request.url`/`response.status` equal the exported flow's; `flow.import` of that
    HAR yields a flow with the same URL and status.
11. **AC-F10.3:** `flow.import` populates the store and triggers **no** upstream
    request (the egress counter stays at its pre-import value) — import is passive.

**F11 (§4)**

12. **AC-F11.1:** with `tls.passthrough.add {host:"pinned.example"}`, a TLS
    connection to `pinned.example` is tunnelled: the client's TLS peer certificate
    is the **upstream's real cert** (issuer is **not** the aitm CA) and the flow
    store contains **no decrypted `HttpFlow`** for it; a non-passthrough host is
    still MITM'd (leaf issued by the aitm CA, `HttpFlow` captured).
13. **AC-F11.2:** `tls.passthrough.add` from an agent (`Frontend::Mcp`) is refused
    when `allow_agent_passthrough` is false and succeeds from `Frontend::Cli`;
    `tls.passthrough.list` reflects adds/removes.

**Map Local / Map Remote (§5)**

14. **AC-M1:** a Map Local mapping for `*/logo.png` → a fixture file makes a request
    to `/logo.png` return status **200** with a body equal to the fixture bytes and
    **no** upstream request made.
15. **AC-M2:** a Map Remote mapping rewriting `old.example` → `new.example` (in
    scope) causes the request to reach `new.example`; the same mapping to a target
    **not in scope** is refused by `ScopeRateGuard` and the original request is not
    sent.
16. **AC-M3:** `map.add` from an agent is refused when `maps.allow_agent_authoring`
    is false; a Map Local `path` escaping the configured map root is rejected at
    `map.add` time.

**HTTP/2 (§6)** — deferred to M7. The HTTP/2 acceptance criteria (ALPN+capture,
multiplexing→distinct flows, intercept/mutate on h2, h2↔h1 bridging, bounded
memory under multiplexed load) belong to the M7 spec and are not criteria for M6.

## Left to the builder

- Exact file layout of `aitm-rules`, `aitm-plugin-wsctl`, `aitm-plugin-sessionio`,
  `aitm-plugin-passthrough`, `aitm-plugin-maprules`.
- Rule id and map id generation scheme (UUID vs short id) and the stable ordering
  of `map.list`/`flow.intercept` rules.
- Whether to verify (and, if needed, add in `aitm-proto-http`) the `Response`-emit
  await point for response-phase parking (§1) — check this first.
- The exact live-WS inject channel type and whether the registry lives in
  `aitm-proto-ws` or `aitm-plugin-wsctl` (§2).
- The precise HAR 1.2 field mapping for WS messages and timing, and the native
  session JSON schema version tag.
- Content-type inference for Map Local when `headers` omit it; the default
  map-local root location.
- Whether `flow.export` returns inline `bytes` or writes a `path` by default when
  `path` is omitted.

(HTTP/2 builder details are out of scope — they belong to the M7 spec/plan.)

## Open questions

*(Resolved on approval, 2026-10-28 by Matt — Matt approved the spec and directed
proceeding to the Stage-3 plan, accepting each recommendation below.)*

1. **HTTP/2 milestone split — resolved: accepted.** **M6 = F3 + F9 + F10 + F11 +
   Map Local/Remote** (additive, shared rule-match, Low–Med risk); **M7 = HTTP/2**
   (deep protocol work, High risk, distinct test surface) on its own. The Stage-3
   implementation plan therefore covers the five M6 items; HTTP/2 (§6, AC-H2.*)
   gets its own separate spec→plan as M7.
2. **Import/export formats — resolved: as proposed.** In scope: HAR 1.2
   import+export, native `aitm` import+export, mitmproxy `.flows` **import**.
   Deferred: Proxyman/Charles import, Postman/OpenAPI export.
3. **Map Local/Remote — resolved: native commands.** First-party commands + the
   `aitm-plugin-maprules` plugin (shares the rule-match core, drives the operator
   forms from `tools/list`, deterministic file/scope handling); Rhai remains the
   custom-logic escape hatch.
4. **Agent-gate defaults — resolved: off.** `allow_agent_passthrough` and
   `maps.allow_agent_authoring` default **off**, consistent with
   `scope.allow_agent_widen` and `scripts.allow_agent_authoring`.
