# Scanner v2: current state of the seams it must build on

**Date read:** 2026-10-31 (every file:line below was read that day). **Method:** three prior in-repo surveys
(scanner backend, seams, UIs) re-checked against `main` at `0f000174`, plus six new questions. Read-only; no
code changed. Line numbers drift; treat them as pointers. Model: `11-protocol-descriptor-ui-current-state.md`.

## 1. Question

Which seams in the core, bus, scripting tier, findings store and UIs must a "scanner v2" (background jobs with
pushed progress, unified native+Rhai check catalogue, more insertion points, session reuse, issue dedupe by
severity x confidence, WebSocket and L4 fuzzing lanes) build on, and where does each fall short today?

## 2. Short answer

The scanner is three verbs (`scan.discover/passive/report`); its inject, PoC and record engines run only in
tests. Every missing v2 capability hits the same wall: `Command::invoke` is synchronous and borrows a
call-scoped `CommandHost`, so a job needs owned handles (a late-binding precedent exists). Push is hard-wired in
`aitm-mcp` to flow, state and audit lines, and a plugin cannot emit a new kind without an `aitm-mcp` or
`aitm-core` edit. Rhai `check.*` scripts carry no machine metadata, a 2 s default budget, no timing, and a
sealed registry. Findings have no dedupe key or confidence.

## 3. Findings

### 3.0 Prior surveys re-verified

All three held; none contradicted. Refinements and new facts:

| Claim | Verdict | Evidence |
|---|---|---|
| A: 3 verbs only; inject/build_poc/record_finding undriven | True. Only test call sites; `neg/test_agent_gated_refused.py:21` says `scan.inject` is not registered | `plugin.rs:27-33`; `inject.rs:90`; `reproduce.rs:116,605` |
| A: crawl follows `<a>/<area>/<form action>` via navigate+get_dom only | True; never click/type though `BrowserDriver` has them | `crawl.rs:138,186,471`; `ctx.rs:43-51` |
| A: `allow_agent_active`, `request_budget` unused; binary uses default | True (grep finds no reader) | `config.rs:16,22`; `wire.rs:330-332` |
| A: egress confinement only in scan.discover | True | `commands.rs:194` (only `.confine()` call site) |
| A: 2 classes, BatteringRam | True; dispatch is a closed `match` | `checks.rs:29-31,252-266` |
| A: discover lists Header/Cookie/PathSegment | True, but **new:** `mutate_request` refuses all three | `inject.rs:378` |
| B: hooks, no L4 hook | True: `Event` has 8 flow-id variants, no L4 | `loader.rs:50-61`; `event.rs:9-30` |
| B: script commands default Sensitive; one `args` map | True | `command.rs:57-76` (no `sensitivity` override) |
| B: registry sealed; no `script.run` | True | `rhai/commands.rs:18,168`; verbs are validate/reload/enable/disable/save/findings/list |
| B: Rust can call script cmd via Registry | Mechanically yes, but no Registry reaches a command: `invoke` gets only `CommandHost`; `Arc<Registry>` exists post-build | `ctx.rs:224-237`; `proxy.rs:55` |
| B: `Http1Sender` h1-only | True | `sender.rs:1-9` |
| C: only agent notifications ingested on mac | True, and **new:** mac never calls `flow.subscribe`, so on a live bus it gets none | `Session.swift:447`; no `subscribe` in `apps/mac/Sources` bar fixture text |
| C: no scan stories, no CommandMap scan | True | grep of `apps/mac/docs/STORIES.md`, `CommandMap.swift` empty |
| C: contract lists | True | `frontends.rs:85-87,300`; `aitm-tui/src/lib.rs:295-299`; `bus-fixture.json:66-68` |

New drift found: `docs/scanner.md:207-216` says discovery is "the only scanner command that exists" and lists
`scan.report` as planned, but `scan.passive`/`scan.report` shipped (#140). `docs/superpowers/specs/2026-10-30-
aitmproxy-scanner-active-backend-design.md` (draft) already specifies `scan.inject/run/status`, with live
progress deferred (lines 35-71, 115). Nothing registers `scan.inject/run/status`. Helper doc comments
reference `scan.run` as "later" (`commands.rs:213,391,486`) and nonexistent `run_class`, `reproduce_and_record`,
`campaign` (`inject.rs:214,279`).

### 3.1 Job model: the Command seam

- `Command::invoke(&self, Params, &CommandHost) -> Result<Value>` is synchronous; the trait has no job,
  progress or cancel concept (`command.rs:59-90`).
- `CommandHost<'a>` holds `&'a dyn` store, client, guard and browser, is not `Clone`, and lives for one call
  (`ctx.rs:224-237`). `McpServer` builds it per call from a private `Services` of `Arc`s
  (`server.rs:972-977,1858-1864`). A background job cannot keep it; it needs owned `Arc`s. Late-binding
  precedents: `LateHandles` (`scripts.rs:34`, `main.rs:188-199`) and `LateGuard` (`wire.rs:519`), both bound
  after `Proxy::build`. `ScriptServices` is the existing owned bundle (store, client, browser, guard, findings,
  runtime handle: `host_core.rs:47-54`).
- Dispatch: each `tools/call` runs on `spawn_blocking` (`transport.rs:178`, `http.rs:258`, `bridge.rs:448`).
  The stdio and loopback read loop **awaits each call before reading the next line** (`transport.rs:178-190`):
  a running `scan.discover` blocks a `scan.status` or cancel on the same connection. The web bridge runs
  frames concurrently, at most 16 (`bridge.rs:111,336-345`). There is no server-side call timeout (only
  `write_timeout`, `server.rs:37`). The TUI awaits the call inline inside its `select!`, so its poll tick and
  notification arm stall for the scan's duration (`bus.rs:127-145,432-455`); `aitm-bus-client` has no timeout
  token.
- No MCP `notifications/progress` or `notifications/cancelled`, and no `progressToken`, anywhere in
  `crates/aitm-mcp/src`; protocol version `2025-06-18` (`server.rs:78`). Client-side tool timeouts of external
  agents are unverified.
- Audit and the `notifications/aitm/agent` line are written **after** the command returns
  (`server.rs:1676-1720,1967-1973`), so a running scan is invisible in Agent activity. The policy gate runs
  once, at call time (`policy_decision`, `server.rs:2010`); nothing I read re-checks it, so `agent.set paused`
  would not stop a running scan (inference).
- Start/status/stop precedents: `l4.capture.start/stop/status` (`commands/capture.rs:57-199`): an
  `Arc<CaptureRegistry>` of handles keyed by flow id, a dedicated thread with an `AtomicBool` stop
  (`capture.rs:236`); status returns ids only, no progress. WS inject shares an `Arc<Mutex<HashMap<FlowId,
  UnboundedSender>>>` between module and plugin with "no `aitm-core` edit" (`aitm-proto-ws/src/module.rs:39`).
  `Governance` shares `AgentState` and `AuditRing` across servers by `Arc` (`wire.rs`, `tui.rs:8-14`).
- `scan.discover` is single-flight through an `AtomicBool` RAII slot and blocks on `block_on`
  (`commands.rs:63-103,203`; `crawl.rs:416-429`, which uses `block_in_place`).

### 3.2 Bus push path

- Emitters, all inside `McpServer` (`aitm-mcp`): **flow** (chain `Event` -> `SubscriptionPlugin` tap ->
  `broadcast` -> dispatcher task: `subscription.rs:37-60`; `server.rs:1215-1240,1299-1320`), **state**
  (`push_state`, `server.rs:1330`, takes arbitrary JSON, but has **no production caller**: only tests, plus
  the `lagged` marker at `server.rs:336`), **agent** (one line per audited command, `server.rs:1993-2003`;
  approval requests `:2129`).
- A plugin cannot emit a new kind: `Event` is flow-id-only and `#[non_exhaustive]`, `event_flow_id` returns
  `None` for an unknown variant so nothing is pushed (`server.rs:2601-2612`), and `Plugin::load` receives only
  a `Registry` (`plugin.rs:10-21`). Without touching `aitm-core`, a plugin could hold a sender the server
  subscribes to, the way `with_push` takes one (`server.rs:1147`); that is an `aitm-mcp` plus `wire.rs` edit.
  Reusing `notifications/aitm/state` would be silently dropped by the web (`onState` requires a complete state
  payload, `app.ts:356-372`).
- Fan-out reaches only connections holding at least one `flow.subscribe` subscription (`Subscription`
  `server.rs:418-428`; `fanout` `:556-575`), is role-aware, and is muted for agent roles under `paused`.
  `flow.subscribe` is special-cased in `call_tool`, not run as a command (`server.rs:2255-2290,2385`); its
  filter is host/method only. State and agent lines ignore filters.
- One process hosts several `McpServer`s over one registry (agent server, TUI in-process server, web bridge),
  each with its own subscription table. The TUI's in-process server has no push sink, and `push_tx` is not fed
  to the agent server in TUI mode (`tui.rs:15-21,296-310`). A scan push must reach every server.
- Clients on an unknown kind: web ignores it (`switch` with no default, `app.ts:469-497`; `ws.ts:141,172-178`
  subscribes on open and dispatches all methods); the bridge relays sink lines verbatim (`bridge.rs:373-375`).
  TUI turns any notification into a poll refresh (`app.rs:3895`). Mac drops all but `agent` (`Session.swift:447`)
  and never subscribes. Stdio agents get nothing unless they subscribe.

### 3.3 Config reaching a plugin

- `Settings { core, rhai, l4, macos_capture }` (`config_file.rs:42-51`); `ConfigFile` has
  `deny_unknown_fields` and keeps `l4`/`macos_capture` outside `aitm_core::Config` "to keep `aitm-core`
  untouched" (`:167-205`). A `scanner:` section follows that pattern (new `Option<ScannerFile>`, a field on
  `Settings`, destructured at `main.rs:155-160`).
- `CommandHost::config()` returns only `aitm_core::Config` (`ctx.rs:268-278`), so plugin config arrives through
  the plugin constructor (`ScannerPlugin::new(cfg)`, `plugin.rs:17`), which `wire.rs:330-332` feeds
  `ScannerConfig::default()`. `PocFile.allow_agent_run` (`config_file.rs:733-750`) is the template for the
  unread `allow_agent_active`. Findings dir is read as `host.config().findings.dir` (`reproduce.rs:605-612`).
  There is no named-profile mechanism anywhere; config is parsed once at startup (hot reload unverified).

### 3.4 The check catalogue

- Native: `CheckDefinition { class: &'static str, locations: &'static [Location], payloads, mode }`
  (`checks.rs:79-84`); `for_class`/`registered_classes` are a closed match (`:252-266`); confirmation reuses
  the `aitm_poc` matcher (`checks.rs:14-16`). Passive: 3 hard-coded checks (`passive.rs:69`).
- Rhai: 15 `check.*` commands, each `reg.add_command(name, one-line description, |args| ...)`
  (`scripts/bundled/active/*.rhai`, e.g. `check-sqli.rhai:26`). Declared metadata is the name, a prose
  description and a free-form `args` `Map(Any)` (`command.rs:62-76`). The result is free text
  (`"VULNERABLE: error-based SQLi confirmed"`, `check-sqli.rhai:43`). Findings go through `finding(#{name,
  severity, flow_id, detail, tags})`; those five keys are the whole schema (`host_core.rs:345`).
- **Missing for automatic scheduling:** vulnerability class (only free tags), applicable insertion kinds (all
  take `url`+`param` and append `?param=`, so Query only: `check-sqli.rhai:14-17`), lane (HTTP/WS/L4 is the
  directory name), request cost (sqli is up to 8 sends), severity and confidence as data (severity is a literal
  in the finding; confidence does not exist), baseline need, side-effect level, a machine verdict.
- Tier: script commands are `Sensitive`. Under policy `auto` an agent is refused; under `ask` every call parks
  for approval (`agent.rs:19-33`). The bundled README's "a cyber model drives them per parameter over MCP"
  therefore needs `all` or one approval per probe. A Write-tier scanner verb that internally invoked a
  Sensitive script would launder the tier, because the gate sees only the outer verb.
- Run limits: a command runs under the hook budget, **2 s** default wall-clock (`rhai/config.rs:70`;
  `command.rs:51,101`). `http.send` is bounded by the budget's remainder and does not renew it; only browser
  calls do (`host_net.rs:349,354-375`). A multi-send check on a slow target aborts unless `rhai.hook_timeout`
  is raised (`config_file.rs` `RhaiFile`). `sleep` is refused and the time package removed
  (`engine.rs:8-11,364-369`); `http.send` returns `status, headers, body, flow_id` with no timing, and
  `PipelineClient` leaves `FlowMeta.duration` unset (`client.rs:70-75`). Time-based blind checks are not
  expressible in Rhai today.
- Custom checks: a script that registers a command needs a restart (`rhai/commands.rs:18,163-170,476-482`);
  hooks go live without one. `finding()` writes a 10,000-entry in-memory ring (`host_core.rs:84-100`), read by
  `script.findings` ("not persisted", `rhai/commands.rs:640-650`), separate from the `FindingStore`. The
  bundled README says read passive findings with `findings.list` (`scripts/bundled/README.md`, Posture); that
  is wrong against the code.

### 3.5 Insertion points, sessions, the send path

- `enumerate` (`discover.rs:101`): Query, top-level form/JSON BodyParam, Header, Cookie, numeric PathSegment,
  Redirect; 1024 points per flow (`:48`). A URL-valued parameter is reclassified Redirect (`:191`), so it stops
  being a Query point for XSS/SSRF. Not enumerated: multipart, XML, nested JSON, non-numeric path segments,
  GraphQL variables. Mutable today: Query, BodyParam (form re-serialised; JSON key replaced by a **string**),
  Redirect (`inject.rs:362-378`).
- Session reuse is implicit: the probe is `original.clone()` of the captured request, so every captured header
  (Cookie, Authorization, CSRF body field) is replayed verbatim (`inject.rs:299-325,362`). There is no cookie
  jar, login macro, expiry or auth-lost detection. The crawl browser has no session unless an operator drove it.
- `PipelineClient::send` gates every request, **inserts every probe into the flow store** as `is_replay`
  (`client.rs:52-77`), so a 2000-request scan competes with real captures under the 50,000-flow / 512 MiB cap
  (`store.rs:113-117`). It records 5xx and transport errors against the host (`client.rs:56-63`); the default
  budget is 10 (`config.rs:190-200`). `host_disabled` ends the inject run (`inject.rs:330-336`): crash and 500
  probes are the signal, and they trip the guard. `per_host_rps` is 50 and a `rate_limited` refusal ends the run
  rather than pacing it (`inject.rs:143-148`). `Http1Sender` is h1 only, dials per send (`sender.rs:174`), caps a
  response at 60 s and 16 MiB (`:28-37`). `FlowMeta.marks` could tag scan traffic (`flow.rs:238-255`); nothing does.
- `inject` is serial per point and payload, and takes `budget: &mut usize` with no progress callback
  (`inject.rs:90-123`).

### 3.6 Findings and dedupe

`FindingRecord`: id, title, class, severity, target, origin, client_label, poc_ref, `reproduction {passed,
control_passed}`, artifacts (capture flow, poc path, screenshot path), flows, notes (`record.rs:22-36`).
The id is the class slug plus 8 random hex digits (`store.rs:175-181`) and `record` always writes
(`store.rs:73-98`): no dedupe key, no insertion point or location, no confidence. The model assumes a
PoC-backed reproduction with a patched control. `FindingFilter` filters target/class/severity/since
(`record.rs:93-98`). `record_finding` fails without `findings.dir` (`reproduce.rs:605`). Passive findings are
computed on demand and never persisted (`commands.rs:345-370`). Severity is `aitm_poc::Severity`, five levels.

### 3.7 WebSocket and L4 lanes

- WS: Rhai has `on_ws_*` observers only; the host API has no `ws.*` verbs (`rhai.api.json` globals). `ws.send`
  injects into a **live captured** conversation via `InjectRegistry` and returns only the appended index
  (`wsctl/src/lib.rs:375-440`); it is Sensitive by default (no override). No client dialer exists:
  `tokio-tungstenite` is a dev-dependency only (`wsctl/Cargo.toml:14-21`). Replies surface as
  `Event::WsMessage` on the flow. A `ProtocolLanguage` namespace is the sanctioned way to add `ws.*` host
  fns without an `aitm-core` edit (`language.rs:54-80`; installed at `main.rs:208-229`, only L4 today).
- L4: opt-in (`enabled: false`, `l4/config.rs:64`), its own scope (cidr, interface, direction, capability),
  guard and privilege probe. `l4.send_recv` sends one crafted packet and awaits a correlated reply on one
  dedicated thread with a fresh capture handle per call; its doc names it "the primitive the L4 fuzzing loop
  drives" and `NoResponse` the "candidate crash" (`sendrecv.rs:1-30`). There is no stateful socket client (no
  non-test `TcpStream`/`UdpSocket` in `aitm-proto-l4/src`). L4 flows are not on the push stream. Bundled L4
  scripts: recon, tcp_probe, udp_probe only.

### 3.8 UIs

TUI `ScanState` has one `running` bool (`app.rs:205-229`) and hard-codes `http://` (`:250-253`, a bug for
HTTPS targets); web state is component-local signals (`Scan.tsx:23-24`) under a `Match` that unmounts the
panel (`Shell.tsx:143`), so navigation drops the running flag and result (inference from Solid semantics);
mac has `running` (`Scan.swift:230`) and `http://` seeds (`:171,184`). No UI calls `scan.passive` or
`scan.report`. Results are untyped `Object(vec![])` (`commands.rs:151`). The web launch form is
schema-driven; results are bespoke. A new verb touches three contract lists
(`frontends.rs:85-87`, `aitm-tui/src/lib.rs:295-299`, `bus-fixture.json`) and drifting ones
(`Fixtures+Tools.swift:48` lists `scan.discover` only; `mock.ts`; `selftest-live.mjs`).

### 3.9 Test target and e2e harness

- `aitm-testtarget`: 6 vulns, one binary serving `vulnerable` or `patched` (`seed.rs:15-27`,
  `manifest.rs:56-103`), a built-in negative control and an inert-marker grader. Plain hyper HTTP/1
  (`app.rs:33-41`); no JSON, multipart, cookie/login, or WebSocket route. L4: UDP echo and TCP banner+one echoed
  read (`l4.rs:106-134`).
- **Missing seeds:** SQLi (error and boolean), cmdi, SSTI, traversal, XXE, CRLF, NoSQLi, LDAPi; a JSON-body
  endpoint, a header-reflecting endpoint, cookie auth plus CSRF login; a delayed endpoint (time-based); a 5xx-prone
  endpoint (guard interplay); a WS echo with an injectable handler; a TCP service with a crashable length-prefixed
  parser (L4 crash).
- Harness (`tests/e2e/aitm_e2e`): `Aitm.server/web` boots a real core (`core.py`), `BusClient` has
  `wait_notification` (`bus.py:146`) and keeps pushed lines, `WsBusClient` covers `/bus` (`ws.py`),
  `Target("vulnerable"|"patched")` (`target.py`), `CoreConfig.to_yaml` (`config.py`) emits no `scanner:`
  section. **No T1 scan cell exists**; the only e2e mention is the negative test. Rust: `discover_e2e.rs` is
  `AITM_OBSCURA`-gated. The harness does not set `AITM_NO_BUNDLED_SCRIPTS`, so a dev-checkout core likely
  loads the bundled catalogue (unverified). `tests/e2e/README.md` layout omits `target.py`, `tls.py`, `ws.py`.

### 3.10 Pre-existing bugs and limits v2 must not inherit

1. `scan.discover` blocks the bus call for up to `time_budget` (600 s); serial dispatch on stdio/TCP stalls
   everything else on that connection; the TUI stalls its own poll.
2. Caps of 1024: `MAX_RESULT_ITEMS` (`commands.rs:59`), `MAX_POINTS_PER_FLOW` (`discover.rs:48`), plus 512
   links per page, 4096 frontier, 2 MiB DOM (`crawl.rs:27-35`), 25 payloads per class (`config.rs`).
   `discover_value` rescans the whole store per call (`commands.rs:249`).
3. `inject`: serial, no progress, no rate pacing, guard refusal ends the run, `budget` as `&mut usize`.
4. Enumerated-but-unmutatable Header/Cookie/PathSegment points; JSON mutation always yields a string.
5. TUI `http://` seed; mac `http://` default; web defaults https.
6. `ScannerConfig.allow_agent_active`/`request_budget` unread; binary uses defaults.
7. Probes flood the flow store, untagged; 5xx probes trip the error budget.
8. Egress confinement exists only in `scan.discover` (`commands.rs:194`); any active job must take the hold.
9. Doc drift: `docs/scanner.md` roadmap, bundled README `findings.list` claim, stale doc comments in `inject.rs`.
10. In-flight work on `claude/scanner-vocab-7d36bb` (20 commits ahead of `main`, edits `discover.rs`,
    `reproduce.rs`, `redact.rs`) and `claude/scanner-w2` (5 ahead): a merge surface for v2.
11. Mac gets no pushes (never subscribes); TUI embedded has no push sink.

## 4. Candidate directions (not decisions)

**Job model.** (a) A `ScanJobs` registry as `Arc<Mutex<HashMap<JobId, Job>>>` shared by plugin and servers
(the `CaptureRegistry`/`InjectRegistry`/`Governance` shape), with `scan.start/status/cancel` verbs and a worker
on an owned-handle bundle (like `ScriptServices` via late binding). No `aitm-core` edit; poll-friendly for
stdio agents; cost is owning handles and re-checking policy and scope per step. (b) Extend `Command` with an
async/job method: cleanest, but an `aitm-core` edit touching every command. (c) Keep blocking verbs and fix
only dispatch: smallest, does not meet "cancel" or "progress".

**Progress push.** (a) Poll-only `scan.status` with counters (works everywhere today, including TUI embedded and
mac). (b) Add a plugin-fed broadcast the servers subscribe to, a new `notifications/aitm/scan` kind routed
through `fanout_state`-style fan-out; needs `aitm-mcp` + `wire.rs` edits, all servers, and mac/TUI to learn to
subscribe. (c) Both: push as a trigger, poll as truth, the pattern web already uses for flows (`app.ts:456-497`).

**Catalogue.** (a) Declared metadata in the script (a `const CHECK = #{class, kinds, lane, cost, severity}` or
`reg.add_check(...)`), read by a static scan like `scan_registers` (`loader.rs:70-75,400-530`), unified with native
`CheckDefinition` behind a trait object; needs a loader change and a machine verdict from scripts. (b) Native
checks only, Rhai stays operator-invoked (no loader change; two catalogues). (c) A YAML check format (nuclei-style,
as the active-backend spec's `payloads_dir` follow-up) for declarative checks plus Rust for the stateful ones.
Under (a), decide the tier question (scanner-level confirm versus per-script Sensitive) and raise the 2 s budget
or add a scan-run budget kind.

**Insertion points and sessions.** Extend `mutate_request` for Header/Cookie/PathSegment first (already
enumerated); add multipart/nested JSON/XML later. For sessions: an explicit "session profile" (header/cookie set
captured from a chosen flow, with auth-lost detection) versus today's per-source-flow clone.

**Dedupe and severity x confidence.** Add a derived key (class, normalised target path, location, name) and a
confidence field on a scan-owned record, either extending `FindingRecord` (`aitm-findings`, YAML schema change)
or a scanner-side index that references records. Decide whether non-PoC-backed (low confidence) findings may be
recorded at all, given `Reproduction` assumes a control run.

**WS and L4 lanes.** WS: a `ProtocolLanguage` `ws` namespace with a dialer (needs a production WS client
dependency) versus injecting only into live captured conversations. L4: build on `l4.send_recv` plus a
`PacketSpec` mutator, accept the per-call capture-handle cost, add a stateful TCP client only if the testtarget
needs it; a second authorization (L4 scope) must be part of any scan profile.

**Config.** `scanner:` section outside `aitm_core::Config`, mirroring `l4:`; wire `allow_agent_active` and
`request_budget`; profiles as a map inside that section.

## 5. Open questions

- Do external MCP clients (Claude Code, ChatGPT) impose tool-call timeouts that cap a blocking verb? Not found.
- Does `Event`/`McpServer` have a cheaper hook for plugin pushes than a new broadcast? Not found.
- Does the web panel survive navigation with its scan state? Inferred "no"; not run.
- Is config hot-reloaded? Not verified.
- Whether the e2e core loads the bundled catalogue by default. Not verified.
- Does the TUI README count of tools drift? Not re-checked.
- How `scanner-vocab` and `scanner-w2` interact with a v2 plan (rebase cost). Not assessed.

## 6. Sources

All paths are in `/Users/matt/Security/aitmproxy` on `main` (`0f000174`), read 2026-10-31:
`crates/aitm-plugin-scanner/src/{plugin,config,commands,inject,checks,discover,crawl,reproduce,passive}.rs`;
`crates/aitm-core/src/{command,ctx,client,event,guard,config,flow,store,registry,proxy,plugin}.rs`;
`crates/aitm-mcp/src/{server,transport,http}.rs`; `crates/aitm/src/{wire,main,tui,config_file,scripts}.rs`;
`crates/aitm/src/web/bridge.rs`; `crates/aitm-plugins/src/subscription.rs`;
`crates/aitm-plugin-rhai/src/{loader,command,commands,engine,host_core,host_net,config}.rs`;
`crates/aitm-plugin/src/language.rs`; `crates/aitm-findings/src/{record,store}.rs`;
`crates/aitm-plugin-wsctl/src/lib.rs`; `crates/aitm-proto-ws/src/module.rs`;
`crates/aitm-proto-l4/src/{capture,sendrecv,config}.rs`, `commands/capture.rs`;
`crates/aitm-proto-http/src/sender.rs`; `crates/aitm-testtarget/src/{seed,manifest,app,l4}.rs`;
`crates/aitm-tui/src/{app,bus,lib}.rs`; `apps/web/src/{state/app.ts,bus/ws.ts,panels/scan/*,shell/Shell.tsx}`;
`apps/mac/Sources/{Aitmproxy/Session.swift,AitmproxyKit/Panels/Scan.swift}`;
`scripts/bundled/README.md`, `scripts/bundled/active/check-sqli.rhai`, `check-path-traversal.rhai`,
`check-security-headers.rhai`; `docs/design/languages/rhai.api.json`; `docs/scanner.md`;
`docs/superpowers/specs/2026-10-30-aitmproxy-scanner-active-backend-design.md`;
`tests/e2e/README.md`, `tests/e2e/aitm_e2e/*.py`, `tests/e2e/neg/test_agent_gated_refused.py`;
`crates/aitm/tests/{frontends,discover_e2e}.rs`; `git diff --stat main...claude/scanner-vocab-7d36bb`.
