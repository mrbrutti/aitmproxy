# macOS BusService reconnect ownership (issue #192) — design

**Status:** approved — self-approved 2026-11-01 by the fix session (autonomous mode, memory
`aitmproxy-autonomous-approve-merge-mode`); all ten Architect's calls accepted as written, no
key account, identity or product-direction decision involved
**Issue:** [mrbrutti/aitmproxy#192](https://github.com/mrbrutti/aitmproxy/issues/192) — "mac: Scope
action right after Restart Core fails with 'the bus connection closed' while the bus shows
connected (BusService.run cleanup clobbers the new client)"; filed from
`docs/superpowers/plans/2026-10-31-macos-scope-persistence-plan.md` Review log row 20.
**Research inputs:** the fix session's research note
`~/Library/Application Support/Claude-3p/side-session-notes/local_9c8046c4-8fba-478a-88ef-3ee2f72ce30d/192-research-input.md`
(the issue verbatim, the code-read facts, the three candidate fixes, the test surfaces, the
constraints); the orchestrator's diagnosis
`…/local_75059306-ee27-4e35-9526-25f7809380be/issue-bus-reconnect-race.md`; its live-proof
recipe `…/scope-persist-live-proof.sh` (System Events click on Proxy ▸ Restart Core on a dev
bundle, respawn detection by the child's own `--config` path).
**Code read (2026-11-01):** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (the whole file;
`start`/`stop`/`run`/`pollLoop`/`refreshScope`/`refreshProxyStatus`/`live`/`call`/`scopeVerb`),
`Bus/EmbeddedCoreController.swift` (`handle(.ready)` → `useEmbeddedEndpoint`, `restart()`),
`Bus/EmbeddedCore.swift` (`spawn`, `childExited`, `retryOrFail`, `generation`, backoff 500 ms
doubling to 10 s, `maxRestarts` 5, `rendezvousTimeout` 15 s, `stopGrace` 5 s),
`Bus/LiveConnectionDriver.swift`, `Shell/ShellView.swift` (read only: `.onChange(reconnectTick)
{ bus?.start() }`, `.onChange(restartCoreTick) { embeddedCore?.restart() }`), `Shell/ShellToolbar.swift`
(read only: the connection cluster's `accessibilityLabel("aitmproxy: \(summary.spoken)")`),
`App.swift` (Proxy ▸ Reconnect Bus ⌃⌘R, Proxy ▸ Restart Core ⌃⇧⌘R, View ▸ Pause/Resume Proxy ⇧⌘R),
`Session.swift`, `Session+Verbs.swift` (`perform` → `lastError`), `Session+Palette.swift`
(`runCommand` → `commandRunner`), `Session+Connection.swift`, `SelfTest.swift`,
`SelfTest+Live.swift` (`settle`, `check`, `ObservationFlag`, the Scope block),
`Sources/AitmBusClient/BusClient.swift` (`connect` is not cancellation-aware; its own `generation`
guards stale callbacks), `Sources/AitmBusClient/BusError.swift` (`.disconnected` → "the bus
connection closed"), `Sources/AitmproxyKit/ConnectionSummary.swift` (`busLane` words; `compact`),
`tools/selftest-live.sh`, `tools/selftest-live-embedded.sh`, `tools/snap-dev.sh`,
`tools/check-connection-words.sh`, `apps/mac/CLAUDE.md`, `Package.swift`.

## Intent

`BusService.run()` is the macOS app's one connection task: it builds a `BusClient`, publishes it
as `self.client`, connects, and polls until the task is cancelled. Every operator action goes
through `live()`, which returns `self.client` or throws `BusError.disconnected` ("the bus
connection closed"). `start()` cancels the previous run and spawns a new one, and the new run
publishes its client *before* its first `await`. The previous run, woken by the cancellation,
then finishes its shared cleanup — `session.bus = .failed(…)`, `applyResolvedRole(nil)`, and an
unconditional `self.client = nil` — *after* the new run's assignments. From then on the new run's
`pollLoop` keeps working on its local `client` parameter (the status bar says connected, the flow
list keeps moving) while `self.client` is `nil`: every `FlowActions` call fails with the
misleading "the bus connection closed", `refreshScope()`/`refreshProxyStatus()` silently stop
following the core, and the palette's `commandRunner` throws, until the next reconnect. Every
`start()` while a client exists triggers it: Proxy ▸ Restart Core and Settings ▸ Proxy "Apply and
Restart Core" (`.ready` → `useEmbeddedEndpoint`), a crash-respawn, Proxy ▸ Reconnect Bus, and the
Settings ▸ Bus embedded↔external switch. This change makes the connection task's shared writes
**owner-checked**: a run that has been superseded (or stopped) may still close its own socket,
and nothing else. A run that is the owner and really loses its core keeps reporting `.failed`
exactly as today.

## Goals

- After any `start()` while connected, the first operator action through `BusService` succeeds
  as soon as `session.bus` reads `.connected`, and `session.scopeHosts`, `session.capturing` and
  `session.interceptArmed` keep following the core through the poll.
- A superseded run never writes `self.client`, `session.bus`, the resolved role, `serverInfo`,
  `tools`/`session.tools`, `session.listenAddress`, `session.commandRunner`, or `pollLoop`'s
  session data after it lost ownership; its only remaining act is `disconnect()` on its own client.
- A run that is still the owner and loses its connection still produces `.failed(<reason>)`, a
  `nil` role, a `nil` client (so `live()` throws honestly) and the existing back-off reconnect.
- The transient `.failed("The operation couldn't be completed. (Swift.CancellationError error 1.)")`
  that a cancelled run wrote over the new run's `.connecting(…)` disappears as a consequence.
- Two live regression checks exist and are part of the mac gate: one inside the real app's live
  self-test (`SelfTest+Live.swift`, via `tools/selftest-live.sh`, external core) and one shell
  check on a dev bundle with the embedded core (`tools/selftest-live-reconnect.sh`) that restarts
  and crashes the core and then performs an operator action **through the app's menu**, observed
  over the bus.
- The mac unit tests, the mac tripwires and the Rust gate stay green; no test is removed.

## Non-goals

- No change to `BusClient` (`connect()` stays non-cancellation-aware; its own `generation` already
  guards its callbacks); no change to `BusError` or its descriptions.
- No refactor of `BusService` into `AitmproxyKit`, no new test target for the app target, no
  protocol or seam extracted to unit-test `run()` in isolation. The verification is live, in the
  real app, against a real core (apps/mac/CLAUDE.md: no fixture, snapshot or mock run may exist).
- No change to the reconnect back-off (1 s doubling to 30 s), the poll interval (500 ms), or the
  words the toolbar shows during a restart. The transient "bus failed" while Proxy ▸ Restart Core
  tears the old core down is honest and stays.
- No change to `refreshScope()`/`refreshProxyStatus()`'s signatures or to `scopeVerb`; no
  plumbing of the client parameter into them.
- No change to `Bus/EmbeddedCore.swift`, `Bus/EmbeddedCoreController.swift`,
  `Bus/LiveConnectionDriver.swift`, `Session*.swift`, `App.swift`, or any view.
- No change to `tools/selftest-live-embedded.sh` (its contract is the shipped install path,
  AC6/AC7/AC14 of the ship spec).
- Not the other follow-ups the research mentions (an app SIGTERM handler; the seven
  `UserDefaultsActiveKindPersistence().load() ?? .embedded` copies).

## Anti-goals

- **Hiding a real connection failure.** A guard that also swallows the *owning* run's `.failed`, a
  retry that papers over a dead core, or a status bar that says connected while actions fail (the
  bug itself, in either direction) is a failure of this change even if the Scope click works.
- **A test-only switch in the app** (a fixture, snapshot, mock bus, injected clock, or a debug
  environment variable) added to make the race observable. The only observation surfaces are the
  real app, its real core, the real bus and the real menu bar.
- **A shell check whose "operator action" is a direct bus call.** The action must travel menu →
  `Session` → `BusService.live()`; a direct JSON-RPC `proxy.pause` proves nothing about the bug.
- **Masking by retry in the in-app check.** The first Scope action after the reconnect must
  succeed with `lastError == nil`; a loop that tries until one lands would pass on the broken build
  too.
- **Touching the operator's machine state.** No `defaults write` to the real domain, nothing
  installed over `~/Applications` or `/Applications`, no write under
  `~/Library/Application Support/Aitmproxy/`, no token printed or logged, no global `pkill`.
- **Widening into a reconnect-lifecycle redesign** (awaiting `stop()`'s detached disconnect,
  merging the three endpoint entry points, moving the service into the Kit).

## Constraints

- **Isolation.** The `Aitmproxy` target compiles with `defaultIsolation(MainActor.self)`;
  `BusService` is a main-actor `@Observable final class`; `BusClient` is an actor, so
  `connect()`, `call()`, `listTools()` and `disconnect()` are suspension points. An ownership check
  and the write it protects must sit in the same synchronous main-actor segment (no `await`
  between them); `stop()` runs on the main actor too, so a check-then-write cannot interleave with
  it.
- **Who cancels, who spawns.** Only `stop()` cancels `runTask`; `start()` always calls `stop()`
  before it spawns; only `run()` assigns a non-`nil` `client`. `stop()` is not called bare today
  (callers: `start()` via `awaitEmbeddedEndpoint`/`useEmbeddedEndpoint`/`useExternalEndpoint`, and
  `ShellView`'s `.onChange(reconnectTick)`), but the design must stay correct if it is.
- **`Task.sleep` under cancellation returns at once.** A cancelled task must therefore never loop
  on a condition that ignores cancellation, or it spins.
- **No app-target tests.** `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`
  covers `AitmBusClientTests` and `AitmproxyKitTests` only; it is Terminal-only (the Bash sandbox
  cannot run SwiftPM, bind ports, or run `osascript`/`open`). Every live run in this spec is a
  Terminal-panel run; coders write code and run syntax checks, the orchestrator runs the gates.
- **Harness isolation.** Under `APP_STORE`/`APP_LIVE` the app reads a wiped defaults suite
  (`SettingsDomain`), so a dev bundle launched with `APP_STORE=/tmp/…` defaults to the embedded
  core without any `defaults write`; the live self-test connects as operator with
  `APP_LIVE_OPERATOR_TOKEN` from the config (`tools/selftest-live.sh`).
- **Tripwires.** `tools/check-connection-words.sh` forbids connection-word literals in app views;
  it exempts `SelfTest*.swift` and does not scan `tools/`. `tools/grid-lint.sh`,
  `check-capture-operator-only.sh`, `check-capture-toggle.sh` must keep passing (no view changes,
  so trivially).
- **Dev-bundle traps (memory `aitmproxy-mac-live-proof-recipe`, `aitmproxy-fake-data-modes-removed`).**
  A SIGTERM to the app skips its AppKit teardown and orphans the embedded core: quit via the normal
  path and reap only by the bundle path (`pkill -f '<bundle>/Contents/Resources/core/'`). Never pick
  "the newest config.yaml in the temp dir": identify the child by its own command line. Each spawn
  mints **new** agent and operator tokens and a new per-launch `config.yaml`/`bus.endpoint`; a
  script must re-read both after every respawn. Keystrokes go to the frontmost app; menu clicks
  via System Events do not need pixel geometry.
- **First-run hygiene (memory `aitmproxy-operator-first-run-hygiene`).** Never print or log a
  token; the shell check reads it from the 0600 config into a variable and hands it to a
  subprocess argument only.
- **Files owned by concurrent sessions — do not touch:** `Shell/ShellView.swift`,
  `SettingsView.swift`, `Bus/ExtensionController.swift`, `CaptureAdvice.swift`.
- **Gates.** Rust: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  (no Rust change is expected; the gate still runs). Mac: the five-step gate in
  `apps/mac/CLAUDE.md`, plus the two checks this spec adds.

## Design

### The race, in one table

Today, on the main actor, after `start()` while connected (old run parked in `pollLoop`'s
`Task.sleep`):

| Step | Old run (cancelled) | New run |
|---|---|---|
| 1 | | `session.bus = .connecting(a')`; `self.client = C'`; `await C'.connect()` |
| 2 | sleep throws `CancellationError` → `catch`: `session.bus = .failed("…CancellationError…")`; `applyResolvedRole(nil)`; `await C.disconnect()` | |
| 3 | **`self.client = nil`**; `break` | |
| 4 | | `connect()` returns: `session.bus = .connected(a')`; role; tools; `commandRunner`; `pollLoop(C')` polls fine |
| 5 | | `live()` → `self.client == nil` → "the bus connection closed"; `refreshScope`/`refreshProxyStatus` `guard let client` → return silently |

Variants: the old run may instead be inside a non-cancellable `connect()` to a dead endpoint
(crash-respawn while the back-off reconnect is dialling) and later throw into the same `catch`;
or inside `connect()` to a live endpoint (a second `start()` ~ms after the first) and then write
`.connected(a)`, `serverInfo`, `tools`, `commandRunner` for a connection nobody owns before
`pollLoop` exits on cancellation and clears `self.client`.

### D1. Ownership by run generation **(Architect's call: candidate C)**

`BusService` gains one counter and `run` one parameter:

```swift
@ObservationIgnored private var runGeneration = 0        // the current run's number
private func run(generation: Int) async                   // was run()
private func pollLoop(_ client: BusClient, generation: Int) async throws   // was pollLoop(_:)
```

Rules:

1. **`stop()` retires the current run**: besides what it does today (cancel `runTask`, detached
   `disconnect()` of `client`, `client = nil`, `session.bus = .disconnected`,
   `applyResolvedRole(nil)`) it increments `runGeneration`. This is the single bump site.
2. **`start()`** is `stop()` followed by `runTask = Task { await run(generation: runGeneration) }`.
3. Inside `run`/`pollLoop`, **a run owns the connection iff `generation == runGeneration`**
   ("`owns`" below; a nested func, a local closure or an inline comparison — builder's choice).
4. **Loop conditions** become `!Task.isCancelled && owns` in both `run()`'s outer loop and
   `pollLoop`'s loop. Cancellation stays the wake-up mechanism (it is what makes the sleeps
   throw); ownership is the write permission. Keeping `!Task.isCancelled` guarantees a cancelled
   task can never spin on instantly-returning sleeps even if a future caller cancelled without
   retiring.
5. **Every write to shared state that follows a suspension point is owner-only**, checked
   synchronously right before the write. Concretely, in `run()`:
   - after `try await client.connect()` returns: if not `owns`, `await client.disconnect()` and
     return — before `serverInfo`, `.connected`, `applyResolvedRole(info.role)`,
     `session.listenAddress`;
   - after `try? await client.listTools()`: if not `owns`, disconnect and return — before
     `tools`/`session.tools`/`session.commandRunner`;
   - after `await refreshScope()`: if not `owns`, disconnect and return — before `pollLoop`;
   - in the `catch`: `session.bus = .failed(…)` and `applyResolvedRole(nil)` only if `owns`;
   - after `await client.disconnect()`: `self.client = nil` only if `owns`; a non-owner returns
     there instead of sleeping and looping.
   In `pollLoop`, the same rule one level down: after each `flow.get` await, and once more before
   the block that assigns `session.restoredFlows`/`session.rows`/the two rates, `guard owns else
   { return }` (returning unwinds through `run()`'s post-`pollLoop` path, which is itself
   owner-checked). The writes before the first await of an iteration (`throughput.reset()`,
   `refetch.reset()`) need no check: the loop condition just held.
6. **A superseded run's only remaining duty is `await client.disconnect()` on the client it
   built** (idempotent with `stop()`'s detached disconnect of the same object; it also covers the
   mid-`connect()` variant, where `stop()` ran before the socket existed). It never touches
   `self.client`, `session`, `serverInfo`, `tools`, `notificationTask`, `summaries`, `refetch`,
   `throughput`.
7. **`notificationTask`** keeps today's shape: the new run cancels and replaces it before its
   first await; a superseded run never reaches that line again because its loop condition fails.
8. **The owning run's failure path is unchanged**: `.failed(Self.describe(error))`,
   `applyResolvedRole(nil)`, `await client.disconnect()`, `self.client = nil` (so `live()` throws
   `.disconnected` honestly until the reconnect), back-off sleep, loop.

Why C and not A or B:

- **A (`!Task.isCancelled` as the only guard)** is the smallest diff and is correct today, but
  only through the unstated invariant "only `stop()` cancels and `start()` always cancels first".
  A reader of the `catch` sees a cancellation check and has to reconstruct that it means "I no
  longer own anything"; a future canceller (a deinit, a scene teardown) silently changes what it
  means. The generation says what it means.
- **B (`self.client === client` plus `!Task.isCancelled`)** answers one question ("is this run
  current?") with two different discriminators depending on which field is being written; a
  reviewer has to prove they agree at every site.
- **C** is the idiom this code base already uses for exactly this problem — a late async
  continuation writing shared state: `EmbeddedCore.generation` invalidates a superseded child's
  `terminationHandler` (`childExited(generation:)` → `guard generation == self.generation`), and
  `BusClient.generation` invalidates a stale `connect()`/`stateUpdateHandler`. One pattern in
  `Bus/` for one problem. Cost: one `Int`, one parameter on two private functions, one predicate.

### D2. What is deliberately not owner-checked

`refreshScope()` and `refreshProxyStatus()` keep reading `self.client` (not a parameter). They are
called from the poll (where the owner's `self.client` is its own client) and from `scopeVerb`
(an operator action on the current client). A superseded run cannot start a new poll iteration
(rule 4), and a mid-iteration call from a superseded run would hit the *new* client or `nil` and
either write the current core's fact or return silently — harmless, bounded to one call, and not
worth the signature change (non-goal). `pollLoop`'s `defer` that zeroes the rates runs for the
superseded run within one main-actor turn of cancellation, before the new connection has sampled
anything, as today.

**Orchestrator amendment (panel, security Minor, 2026-11-01).** The three refreshes at the top of a poll
iteration stay unplumbed, but the iteration is owner-checked between them: a `guard owns() else { return }`
follows each of `await refreshScope()`, `await refreshProxyStatus()` and the CA refresh, so a superseded
run never issues the next refresh through `self.client` (which a later `start()` may already own, possibly
mid-handshake — a frame ahead of the token line makes the core answer `unauthorized` and close).

### D3. `stop()` without a following `start()`

With rule 1, a bare `stop()` leaves `session.bus == .disconnected`, `resolvedRole == nil`,
`client == nil`, and the stopped run writes nothing more (no `.failed(CancellationError)`): its
`catch` is not the owner. Nobody calls `stop()` bare today; the behaviour is specified so the
design does not depend on that.

### D4. Observable consequences the checks pin

| Trigger | Before | After |
|---|---|---|
| Proxy ▸ Reconnect Bus while connected (core stays up) | `.connected` → `.disconnected` → `.connecting` → **`.failed(CancellationError…)`** → `.connected`; then every action "the bus connection closed"; Scope list frozen | `.connected` → `.disconnected` → `.connecting` → `.connected`; the first action succeeds; the poll follows the core |
| Proxy ▸ Restart Core / Settings ▸ Proxy Apply and Restart Core | old core SIGTERMed → owner's poll fails → `.failed("the bus connection closed")` (honest) → back-off dialling → `.ready` → `start()` → same clobber → actions fail "forever" | same honest `.failed` while the core is down → `.ready` → `start()` → `.connected`; actions succeed |
| Crash (`kill -KILL` the child) | as above, after the 500 ms respawn back-off | as above |
| Settings ▸ Bus external↔embedded | same clobber | clean hand-over |
| Core really dies, no respawn (external core stopped) | `.failed(…)`, back-off reconnects, `live()` throws `.disconnected` | unchanged |

### D5. Verification surface 1 — the in-app live self-test (`SelfTest+Live.swift`)

A new block in `runLive`, placed **right after** the existing Scope checks (after
"the self-test's own scope.add is recorded as an operator command") so that every later check in
the run exercises the *reconnected* connection **(Architect's call)**. It uses the real
`ShellView` wiring: `session.reconnectBus()` → `.onChange(reconnectTick)` → `bus?.start()` — the
same `start()` a core restart calls.

Scaffolding (test code in the app target, beside `ObservationFlag` at file scope): a
`BusStateRecorder` that re-arms `withObservationTracking { _ = session.bus }` on every change and
appends the post-mutation value on the main actor, so the sequence of `BusState` values is
recorded (each write happens in its own main-actor job; FIFO ordering gives one sample per write).

Checks, in order, with the exact names the Tester cites:

1. Arm the recorder; `session.reconnectBus()`;
   `await settle(timeout: .seconds(10)) { recorder.sawNonConnected && isConnected(session.bus) }`.
   **`check("Reconnect Bus while connected: the bus leaves connected and comes back, never failed", …)`**
   — true iff the recorder holds at least one value that is not `.connected`, no value that is
   `.failed`, and `session.bus` is `.connected(address)` with the same address as before the
   reconnect. Detail string: the recorded sequence.
2. `try? await Task.sleep(for: .seconds(1))` (two polls), then
   **`check("the bus is still connected two polls after Reconnect Bus", …)`** — `session.bus` is
   still `.connected` and `session.lastError == nil`.
3. `let host = "reconnect-<8-char lowercase uuid prefix>.test"`; `session.addScope(host)`;
   `await settle { session.scopeHosts.contains(host) }`;
   **`check("the first Scope action after Reconnect Bus succeeds and lands in scope.list", session.scopeHosts.contains(host) && session.lastError == nil, "scope \(session.scopeHosts) err \(session.lastError ?? "-")")`**.
   On the pre-fix build this FAILs with `err add to scope: the bus connection closed` — the
   issue's exact message — which is the red run the plan's TDD step quotes.
4. **`check("the earlier scope entry survives the reconnect (the core's list wins)", session.scopeHosts.contains(upstream))`**.
5. `_ = try? await session.runCommand("scope.remove", ["host": .string(host)])` (the palette
   seam: `commandRunner` → `self.client`; it issues **no** `refreshScope`);
   `await settle(timeout: .seconds(3)) { !session.scopeHosts.contains(host) }`;
   **`check("scopeHosts keeps following the core after Reconnect Bus (a palette scope.remove is dropped by the poll)", !session.scopeHosts.contains(host))`**.
   This proves both `commandRunner` and the poll's `refreshScope()` run on a non-`nil`
   `self.client`.
6. The mid-`connect()` probe: `let service = session.actions as? BusService`; `service?.start()`;
   `try? await Task.sleep(for: .milliseconds(1))`; `service?.start()`;
   `await settle(timeout: .seconds(10)) { isConnected(session.bus) }`; `session.addScope(host)`;
   `await settle { session.scopeHosts.contains(host) }`;
   **`check("a second start() during the first run's connect leaves the second run the owner (Scope action succeeds)", session.scopeHosts.contains(host) && session.lastError == nil, …)`**;
   then `_ = try? await session.runCommand("scope.remove", …)` and
   `await settle(timeout: .seconds(3)) { !session.scopeHosts.contains(host) }` to leave the
   core's scope as the earlier checks expect. Whether the 1 ms gap actually lands inside
   `connect()` is timing-dependent; the check must PASS on the fixed build in either case, and
   on the pre-fix build it FAILs whenever the gap lands inside `connect()`.

The block adds at most ~20 s to a run (the 240 s watchdog is untouched) and leaves the session
connected, capturing, with `scopeHosts == [upstream]`, so the following checks are unaffected.
The closing "every action is in the activity log" count stays `>= 11` (the block adds entries).

### D6. Verification surface 2 — the shell live check on the embedded path

**A new script, `apps/mac/tools/selftest-live-reconnect.sh`, not a step in
`tools/selftest-live-embedded.sh` (Architect's call).** Why:

- The embedded self-test's contract is the **shipped install path**: a release `cargo build`,
  `./build.sh` installed over `~/Applications/Aitmproxy.app`, process name `Aitmproxy` — which it
  shares with whatever copy the operator is running, so `tell process "Aitmproxy"` is ambiguous
  the moment the day-to-day app is open. It deliberately drives the bus *directly* and needs no
  Accessibility permission. Bolting menu clicks, AX reads and a `kill -KILL` onto it would make
  step 5 of the gate fail for reasons unrelated to AC6/AC7/AC14 and cost a release build plus an
  install per iteration.
- A snap-dev bundle (`/tmp/Aitmproxy-dev-<tag>.app`, executable `Aitmproxy-<tag>`) is
  process-name-unique (System Events, `pgrep`, `kill` all target it unambiguously), takes seconds
  to rebuild, never touches `~/Applications` or the real store, and is the recipe the live proof
  that found #192 already used.

Contract of `tools/selftest-live-reconnect.sh`:

- **Usage:** `DEV_TAG=<tag> [CORE_DIR=<dir with aitm>] tools/selftest-live-reconnect.sh`.
  Default `DEV_TAG=reconnect`. It builds and assembles the bundle with
  `NO_LAUNCH=1 DEV_TAG=$DEV_TAG CORE_DIR=… tools/snap-dev.sh` (so the bundle, scratch dir and
  binary-staleness check are snap-dev's), then launches `/tmp/Aitmproxy-dev-<tag>.app/Contents/MacOS/Aitmproxy-<tag>`
  itself with `APP_STORE=/tmp/Aitmproxy-dev-state-<tag>` (fresh), capturing the pid. It never
  runs `defaults write`.
- **Discovery:** the embedded child by `pgrep -f '<bundle>/Contents/Resources/core/aitm --config'`;
  its config path from `ps -o command=`; `bus.endpoint` beside that config; `operator_token:`
  from that config into a shell variable (never echoed). Re-done after every respawn.
- **Bus reads** (observation only, never the action): a small inline Python JSON-RPC client
  (token line, `initialize`, `tools/call`) as in `selftest-live-embedded.sh`, used for
  `proxy.status` (`capturing`) and `scope.list`.
- **App-state reads:** the toolbar connection cluster's accessibility label, which
  `ShellToolbar` sets to `"aitmproxy: " + ConnectionSummary.spoken`; via
  `osascript -e 'tell application "System Events" to tell process "Aitmproxy-<tag>" to …'`
  (the element path — `toolbar 1 of window 1` or `entire contents of window 1` filtered by a
  description beginning with `aitmproxy:` — is the builder's to find). The bus lane reads
  `bus: connected`, `bus: connecting…`, `bus failed` or `bus: offline` (per `ConnectionLane.compact`).
- **The operator action** (the thing under test): `set frontmost to true`, then
  `click menu item "Pause Proxy" of menu "View" of menu bar 1` → `Session.setCapturing(false)` →
  `BusService.call("proxy.pause")` → `live()`; observed over the bus as `proxy.status.capturing == false`;
  then `click menu item "Resume Proxy" …` → `capturing == true`. (If "Pause Proxy" is absent
  because the title already reads "Resume Proxy", resume first, then pause, then resume.) Why
  this action and not a Scope click: it is a menu item (no pixel geometry, no window-size
  assumption, no Edit Scope sheet keystrokes), it crosses the exact seam that throws in the bug,
  and its effect is readable by any bus client. The Scope path is pinned deterministically in-app
  (D5) **(Architect's call)**.
- **Triggers, in this order, each followed by the sub-procedure below:**
  - **T1 reconnect-bus:** `click menu item "Reconnect Bus" of menu "Proxy" of menu bar 1`
    (core stays up; child pid unchanged — assert it).
  - **T2 restart-core:** `click menu item "Restart Core" of menu "Proxy" of menu bar 1`; wait
    (≤ 20 s) for a child whose pid differs and whose `--config` path differs, with a non-empty
    `bus.endpoint`; re-read token and address.
  - **T3 crash-respawn:** `kill -KILL <child pid>`; within **5 s** the AX label must contain
    `bus failed` (the owner reporting a real loss — BR-AC4); then the same respawn wait as T2.
- **Sub-procedure after each trigger:** poll the AX label (≤ 250 ms apart) until it contains
  `bus: connected`, bounded at **20 s** from the trigger (covers Restart Core's up-to-5 s SIGTERM
  grace + spawn + rendezvous, and the crash's 500 ms back-off); for T1 additionally assert the
  label never contained `bus failed` between the click and `bus: connected` (BR-AC5). Then
  baseline `proxy.status.capturing == true` over the bus; then the operator action: **one** click
  on Pause Proxy, `capturing == false` observed over the bus within **10 s** (poll every 0.5 s), then
  one click on Resume Proxy, `capturing == true` within 10 s. No retry of the click: the AX label
  said connected, so `live()` must succeed at once. A `tools/winshot.swift <pid>
  /tmp/claude/reconnect-<tag>-<trigger>.png` after each sub-procedure is the attached evidence.
- **Teardown:** a System Events click, scoped to the dev process, on its own app menu's Quit item
  (`tell process "Aitmproxy-<tag>" to click menu item "Quit Aitmproxy" of menu 1 of menu bar item 2
  of menu bar 1`; the normal quit path, so `willTerminate` reaps the child). **Orchestrator
  amendment, panel security Minors (passes 1 and 2):** never a ⌘Q `keystroke` (it goes to whatever
  is frontmost on the operator's desktop) and never an application- or bundle-addressed `quit` Apple
  Event (the dev bundle shares its bundle id with the installed app, which is usually running), bounded wait, then `kill` + `pkill -f
  '<bundle>/Contents/Resources/core/'` as the fallback; the `EXIT` trap does the same. Never a
  global `pkill`.
- **Output:** one `reconnect-live: <trigger>: <what was observed>` line per step; final line
  `RECONNECT LIVE SELFTEST PASS (reconnect-bus, restart-core, crash-respawn: an operator action through the app succeeded after each)`
  and exit 0, or `RECONNECT LIVE SELFTEST FAIL: <trigger> <step> <detail>` and exit 1 at the
  first unmet bound. Every wait is bounded; the script cannot hang.
- On the pre-fix build the script exits 1 at **T1**'s pause step (`capturing` stays `true` for
  10 s) — the shell red run.

### D7. Gate wiring

`apps/mac/CLAUDE.md`'s "Live self-test" bullet gains one sentence naming
`tools/selftest-live-reconnect.sh` as a run-after-any-change-to-`Bus/` check next to
`tools/selftest-live.sh` **(Architect's call; Matt may strike it)**. No other doc or script
changes.

### D8. Files touched

`apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (the fix), `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`
(D5), `apps/mac/tools/selftest-live-reconnect.sh` (new, D6), `apps/mac/CLAUDE.md` (D7), this spec
and its plan. Nothing else. **Orchestrator amendment (Tester pass 2, F6):** plus the three window
shots the shell check writes after each trigger, committed as PR evidence under the repo's existing
convention, `apps/mac/docs/evidence/192-reconnect-ownership/after-{reconnect-bus,restart-core,crash-respawn}.png`
(byte-identical to the green run's `/tmp/claude/reconnect-r192fix-*.png`).

## Acceptance criteria

Numbered `BR-AC` so the plan and the Tester can cite them. "Observed" means printed by the named
check or script line, run in the Terminal panel, with the output quoted in the report.

1. **BR-AC1 — the first action after a `start()` succeeds.** After `session.reconnectBus()`
   while connected (D5 step 3) and after each of T1/T2/T3 in D6, the first operator action
   through `BusService` succeeds once `session.bus` reads `.connected`: in-app,
   `session.scopeHosts` contains the new host within 5 s and `session.lastError == nil`; in the
   shell, `proxy.status.capturing` flips to `false` within 10 s of **one** Pause Proxy menu click
   and back to `true` within 10 s of one Resume Proxy click.
2. **BR-AC2 — `scopeHosts` keeps following the core.** After the reconnect, a `scope.remove`
   issued through `session.runCommand` (no explicit refresh) is reflected in `session.scopeHosts`
   within 3 s (D5 step 5), and the host added before the reconnect is still listed (D5 step 4).
3. **BR-AC3 — a superseded run writes nothing.** After a later `start()` (or `stop()`) retired it,
   a run writes none of: `session.bus` (neither `.failed` nor `.connected`), the resolved role
   (`applyResolvedRole`), `self.client` (neither `nil` nor a client), `serverInfo`, `tools`,
   `session.tools`, `session.listenAddress`, `session.commandRunner`, `session.rows`,
   `session.restoredFlows`, the two rates; it only disconnects its own client. Observed by: D5
   step 1 (no `.failed` in the recorded sequence), D5 steps 3 and 5 (`self.client` and
   `commandRunner` intact), D5 step 6 (mid-`connect()` variant), D6 T1–T3 (the action succeeds
   after each). Review-verifiable: in `BusService.run(generation:)` and
   `pollLoop(_:generation:)` every one of those writes that follows a suspension point is
   dominated by an ownership check with no `await` between the check and the write (D1 rule 5).
4. **BR-AC4 — a real loss is still reported.** With no `start()`/`stop()` in between, a run whose
   connection fails writes `.failed(<describe(error)>)`, `applyResolvedRole(nil)` and
   `self.client = nil` (so `live()` throws `BusError.disconnected`, "the bus connection closed"),
   then reconnects with the existing back-off. Observed: D6 T3 — within 5 s of `kill -KILL` on
   the embedded child the toolbar AX label contains `bus failed`; within 20 s it reads
   `bus: connected` again (the respawn's `.ready` → `start()`); then BR-AC1 holds.
5. **BR-AC5 — no cancellation flicker.** After a `start()` whose target core is up, the sequence
   of `session.bus` values from the old `.connected` to the new `.connected` contains no `.failed`
   (in particular none whose text mentions `CancellationError`). Observed: D5 step 1's recorded
   sequence; D6 T1's AX poll never shows `bus failed`.
6. **BR-AC6 — the in-app regression check exists and is green.** `SelfTest+Live.swift` carries the
   six named checks of D5; `AITM_CONFIG=… tools/selftest-live.sh` prints `PASS` for each and ends
   `LIVE SELFTEST PASS <n> checks` with `n` at least the pre-change count plus six. On the
   pre-fix build (same self-test, `BusService.swift` reverted) the check "the first Scope action
   after Reconnect Bus succeeds and lands in scope.list" prints `FAIL … err add to scope: the bus
   connection closed`.
7. **BR-AC7 — the shell regression check exists and is green.** `apps/mac/tools/selftest-live-reconnect.sh`
   exists, is executable, follows D6's contract, and on the fixed build prints
   `RECONNECT LIVE SELFTEST PASS (…)` and exits 0 with the three winshots written under
   `/tmp/claude/`. On the pre-fix build it prints `RECONNECT LIVE SELFTEST FAIL: reconnect-bus …`
   and exits 1.
8. **BR-AC8 — hygiene of the shell check.** The script contains no `defaults write`, no path
   under `~/Applications`, `/Applications` (other than snap-dev's read-only borrowing of
   `Info.plist`/icons/core, which snap-dev performs) or `~/Library/Application Support/Aitmproxy`,
   no `echo`/`print` of the token variable, and no `pkill` whose pattern is not its own bundle
   path; every wait has a numeric bound (`grep` evidence quoted by the Tester).
9. **BR-AC9 — scope of the diff.** `git diff --stat <base>..<head>` lists only
   `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`, `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`,
   `apps/mac/tools/selftest-live-reconnect.sh`, `apps/mac/CLAUDE.md`, files under
   `docs/superpowers/`, and (orchestrator amendment, Tester pass 2 F6) the three evidence shots under
   `apps/mac/docs/evidence/192-reconnect-ownership/`. `BusClient.swift`, `BusError.swift`, `Session*.swift`, `App.swift`,
   `Shell/*.swift`, `SettingsView.swift`, `Bus/Embedded*.swift`, `Bus/LiveConnectionDriver.swift`,
   `Bus/ExtensionController.swift`, `CaptureAdvice.swift`, `Sources/AitmproxyKit/**`, `crates/**`
   are unchanged.
10. **BR-AC10 — gates stay green.** `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`
    passes with no fewer tests than on the base SHA; `tools/grid-lint.sh`,
    `tools/check-connection-words.sh`, `tools/check-capture-operator-only.sh`,
    `tools/check-capture-toggle.sh` exit 0; `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
    passes; `tools/selftest-live-embedded.sh` (unchanged) passes.

## Left to the builder

- The spelling of `owns` (nested `func owns() -> Bool`, a local closure, or inline
  `generation == runGeneration`) and whether the three "disconnect and return" sites in `run()`
  share a small private helper. Comments at the guard sites should say *why* in one line
  ("a superseded run owns nothing but its own socket"), in the file's existing voice.
- Whether `pollLoop`'s guards are `guard owns else { return }` or `throw CancellationError()`
  (either unwinds into `run()`'s owner-checked tail).
- `BusStateRecorder`'s exact shape (file-scope `@MainActor final class` with `values: [BusState]`,
  `sawNonConnected`, `sawFailed`; re-arming inside a `Task { @MainActor in … }` hop).
- The System Events element path for the toolbar label, the Python helper's layout (one function
  reused for `proxy.status` and `scope.list`), the AX poll cadence within the 250 ms bound, and
  the winshot file names.
- Where in `apps/mac/CLAUDE.md`'s live-self-test bullet the one sentence goes.
- Resolution of `CORE_DIR` when unset: the repo's `target/release` if it holds `aitm`, else let
  snap-dev borrow the installed bundle's core (its existing behaviour).

## Open questions

None that block. Every choice below is a default Matt can overturn at approval time.

## Summary

`BusService.run()` is given a run generation (`runGeneration`, bumped by `stop()`, passed to
`run(generation:)`/`pollLoop(_:generation:)`), and every shared write that follows a suspension
point — the connect-success writes, the `.failed`/role writes in `catch`, `self.client = nil`,
and `pollLoop`'s session writes — happens only while `generation == runGeneration`; a superseded
run only disconnects its own client. The owning run's real failures are reported exactly as
before. Two live checks pin it: a block in the in-app live self-test (Reconnect Bus while
connected, then the first Scope action must land with `lastError == nil`, the poll must keep
following the core, plus a mid-`connect()` double-start probe) and a new dev-bundle script that
drives Reconnect Bus, Restart Core and a `kill -KILL` crash through the real menu and asserts,
over the bus, that a menu-driven Pause/Resume Proxy takes effect within 10 s after each, and
that the crash shows `bus failed` first. No change to `BusClient`, views, Kit or Rust.

## Architect's calls (for Matt to approve or correct)

1. **Candidate C (generation counter), not A (`!Task.isCancelled`) or B (identity check).**
   Explicit, matches `EmbeddedCore.generation` and `BusClient.generation`, robust to future
   cancellers; the loops keep `!Task.isCancelled` so nothing can spin.
2. **`stop()` is the single bump site**; `start()` = `stop()` + spawn. A bare `stop()` therefore
   also silences the stopped run.
3. **`pollLoop` gets the same rule** (loop condition plus two guards) rather than leaving a
   one-iteration stale-write window; `refreshScope`/`refreshProxyStatus` signatures stay.
4. **The in-app block sits right after the first Scope checks**, so the rest of the self-test runs
   on the reconnected connection; it includes a best-effort mid-`connect()` double-`start()`
   probe that must pass either way on the fixed build.
5. **A new script `tools/selftest-live-reconnect.sh` on a snap-dev bundle**, not a step in
   `selftest-live-embedded.sh` (shipped-install contract, ambiguous process name, release-build
   cost, Accessibility dependency).
6. **The shell check's operator action is View ▸ Pause/Resume Proxy** (menu-driven, observed as
   `proxy.status.capturing`), not a pixel-click Scope remove; the Scope path is pinned in-app.
7. **Bounds:** `bus failed` within 5 s of a crash; `bus: connected` within 20 s of a trigger; the
   action's effect within 10 s of one menu click; the in-app Scope action within 5 s and the
   poll-driven follow within 3 s. No retries of the action in either check.
8. **Three triggers in the shell check** (Reconnect Bus, Restart Core, crash); the Settings ▸ Bus
   embedded↔external switch is covered by the same `start()` code path and is not scripted
   (it would need an external core and `SettingsView` driving).
9. **One sentence added to `apps/mac/CLAUDE.md`** naming the new script beside
   `tools/selftest-live.sh`.
10. **No new unit test**: there is no app-target test target and no meaningful pure decision to
    extract (`==` on an `Int` is not worth a Kit type); the live checks and the review checklist
    in BR-AC3 are the evidence.
