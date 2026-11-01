# macOS BusService reconnect ownership (issue #192) — implementation plan

**Status:** approved — self-approved 2026-11-01 by the fix session (autonomous mode, memory
`aitmproxy-autonomous-approve-merge-mode`); the eight Architect's calls accepted. Orchestrator note on
runbook step 9: `tools/selftest-live-embedded.sh` quits the app named `Aitmproxy` and pgreps
`Aitmproxy.app/Contents/Resources/core/aitm`; it is run only while the operator's own `/Applications`
app is not running (it was running, pid 34883, when this plan was approved) — see the Review log
**Spec:** `docs/superpowers/specs/2026-11-01-mac-bus-reconnect-ownership-design.md`
(approved 2026-11-01; acceptance criteria BR-AC1 … BR-AC10)
**Branch / worktree:** the existing branch `claude/cool-zhukovsky-c12370` in the existing worktree
`/Users/matt/Security/aitmproxy/.claude/worktrees/cool-zhukovsky-c12370`, based on main
`5db73a23`. **No new worktree and no `feat/<topic>` branch:** the fix session already owns this
worktree, the spec lives on it, and it ships as one PR to `main`.

**Environment adaptation.** Coder sub-agents run in the Bash sandbox: they read and edit files
and run syntax checks only — `xcrun swiftc -parse <file>` for Swift, `zsh -n <script>` for the
shell script, `grep` for the hygiene checks. They cannot run SwiftPM, bind a port, launch the
app, or run `osascript`/`open`; a sandbox-caused failure is not a code failure and is reported
as such, never worked around. **Every live run and every gate in this plan is the
orchestrator's**, in the Terminal panel: `swift test`, `tools/snap-dev.sh`,
`tools/selftest-live.sh`, the new `tools/selftest-live-reconnect.sh`,
`tools/selftest-live-embedded.sh`, the four tripwires and the Rust gate (the "Orchestrator
runbook" below). Each task's **Test** therefore names the command the orchestrator runs and the
literal line(s) it must print; each **Done when** says which runs are the orchestrator's. The
orchestrator also commits each task (pathspec commit, `git commit -- <files>`); coders do not
commit. A Coder report quotes the sandbox checks it ran and names the Terminal runs it could not.

**TDD shape of this plan.** There is no app-target unit test (spec constraint, Architect's call
10), so the failing tests are the two live checks: Task 1 (in-app) and Task 2 (shell) are
written first, run **red** by the orchestrator on a pre-fix build of the app, and only then does
Task 3 change `BusService.swift` and the same runs go **green**. The red runs are evidence the
checks detect the bug; the Coder of Task 3 is handed the red logs.

## Overview

Four tasks. **Wave A** fans out the two verification surfaces in parallel — they touch disjoint
files: Task 1 (the six named checks and the `BusStateRecorder` in `SelfTest+Live.swift`) and
Task 2 (the new dev-bundle script `tools/selftest-live-reconnect.sh`). The orchestrator then
builds the **pre-fix** dev bundle with those checks in and records the two red runs. **Wave B**
is Task 3, the owner-checked `BusService.run(generation:)` (spec D1 rules 1–8, D2, D3), after
which the same two runs are green. Task 4 (one sentence in `apps/mac/CLAUDE.md`) touches a
disjoint file and may run in parallel with Task 3 or after it; it is listed last so the
sentence names a script that exists.

- **Wave A (parallel, independent):** Task 1 ∥ Task 2.
- **Red runs (orchestrator):** rebuild `r192base`, run Task 1's check and Task 2's script → red.
- **Wave B:** Task 3 (after the red runs exist). Task 4 ∥ Task 3 (disjoint files; Task 4 after Task 2).
- **Green runs + gates (orchestrator):** build `r192fix`, both live checks green, `swift test`,
  the four tripwires, `tools/selftest-live-embedded.sh`, the Rust gate, `git diff --stat`.
- **Then:** whole-branch Tester (every BR-AC); the three-reviewer panel; integration.

**Do-not-touch (spec Constraints; owned by concurrent sessions or out of scope):**
`apps/mac/Sources/Aitmproxy/Shell/ShellView.swift`, `SettingsView.swift`,
`Bus/ExtensionController.swift`, `CaptureAdvice.swift`; and per BR-AC9 also
`Sources/AitmBusClient/BusClient.swift`, `BusError.swift`, `Session*.swift`, `App.swift`,
`Shell/*.swift`, `Bus/Embedded*.swift`, `Bus/LiveConnectionDriver.swift`,
`Sources/AitmproxyKit/**`, `crates/**`, `tools/selftest-live-embedded.sh`. A Coder that believes
its task needs a change in any of these **stops and reports**.

**Stop-and-report rule (every Coder):** a spec gap, a signature that does not exist as this plan
states it, a menu title or accessibility attribute that differs from the plan, or a need to add a
test-only switch to the app (an environment variable, a mock, a fixture — spec Anti-goals) is a
stop, not an improvisation.

**Gates.** Rust (unchanged production Rust; the gate still runs):
`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
Mac: the five-step gate in `apps/mac/CLAUDE.md` plus the two checks this plan adds
(BR-AC10, BR-AC6, BR-AC7).

---

## Tasks

### Task 1: In-app live regression check — the six named checks and `BusStateRecorder`

- **Satisfies:** BR-AC6 (the six checks exist; red on the pre-fix build, green on the fixed
  build); the in-app observations of BR-AC1 (D5 step 3), BR-AC2 (D5 steps 4, 5), BR-AC3 (D5
  steps 1, 3, 5, 6), BR-AC5 (D5 step 1).
- **Depends on:** none (Wave A; parallel with Task 2).
- **Files:** `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift` (modify). No other file.
- **Change:**
  1. **Where the block goes.** Inside `SelfTest.runLive(session:)`, **immediately after** the
     existing
     `check("the self-test's own scope.add is recorded as an operator command", …)` and
     **before** the comment `// flow.intercept both ways: the call that recursed in b7d3163.`
     — so every later check in the run exercises the reconnected connection (spec D5,
     Architect's call 4). Open the block with a comment naming the issue and the spec
     (`// #192 / spec 2026-11-01 bus-reconnect-ownership D5: …`).
  2. **Seams the block uses, as they exist today (read them, do not change them):**
     - `session.reconnectBus()` — `Session.swift`, `func reconnectBus() { reconnectTick += 1 }`;
       `ShellView`'s `.onChange(of: session.reconnectTick) { bus?.start() }` turns it into the
       same `BusService.start()` a core restart calls.
     - `session.addScope(_ host: String)` — `Session+Verbs.swift`; runs through
       `perform("add to scope") { … actions.addScope(host) }`, so a failure lands in
       `session.lastError` as `"add to scope: <describe(error)>"`.
     - `session.runCommand(_ name: String, _ args: [String: JSONValue]) async throws -> JSONValue`
       — `Session+Palette.swift`; the palette seam: `commandRunner` → `BusService.self.client`;
       it issues **no** `refreshScope`, so the poll must do the following.
     - `session.actions as? BusService` — `Session.actions` is `any FlowActions`; `ShellView`'s
       `.task` installs the live `BusService` there, so the cast succeeds in a live run and
       exposes the internal `start()`.
     - `session.bus: BusState` (`AitmproxyKit.BusState`, `Hashable`: `.disconnected`,
       `.connecting(String)`, `.connected(String)`, `.failed(String)`), `session.scopeHosts`,
       `session.lastError`, and the existing helpers `settle(timeout:until:)`, `check(_:_:_:)`.
     - `address` — the `String` already bound at the top of `runLive` by
       `guard case .connected(let address) = session.bus`; the block compares against it.
     - `upstream` — the `String` already bound at the top of `runLive`.
  3. **Scaffolding, at file scope at the end of the file, beside `ObservationFlag`:**
     ```swift
     @MainActor final class BusStateRecorder {
         private(set) var values: [BusState]
         init(session: Session)
         func arm()
         var sawNonConnected: Bool
         var sawFailed: Bool
         var sequence: String
     }
     ```
     Semantics: `arm()` calls `withObservationTracking { _ = session.bus } onChange: { … }`;
     the `onChange` closure is `@Sendable` and fires on **willSet** (before the new value is
     stored), so it must not read `session.bus` synchronously — it hops with
     `Task { @MainActor in … }`, appends the **post-mutation** `session.bus` to `values`, and
     re-arms by calling `arm()` again. `sawNonConnected` is true iff some value is not
     `.connected(_)`; `sawFailed` iff some value is `.failed(_)`; `sequence` is
     `values.map { "\($0)" }.joined(separator: " → ")` (so a FAIL detail reads, e.g.,
     `connected("127.0.0.1:18193") → disconnected → connecting("127.0.0.1:18193") → connected("127.0.0.1:18193")`).
     Doc comment: each `session.bus` write happens in its own main-actor job and the hop reads
     the value that write stored, so FIFO ordering gives one sample per write; a write that
     lands before the re-arm is still sampled by the pending hop (it reads the latest value).
     Also add, inside the `SelfTest` extension beside `exitText`:
     `private static func isConnected(_ state: BusState) -> Bool` (true iff `.connected(_)`).
  4. **The block, in order, with the check names spelled exactly as below (the Tester cites them):**
     1. `let recorder = BusStateRecorder(session: session)`; `recorder.arm()`;
        `session.reconnectBus()`;
        `await settle(timeout: .seconds(10)) { recorder.sawNonConnected && isConnected(session.bus) }`;
        **`check("Reconnect Bus while connected: the bus leaves connected and comes back, never failed", recorder.sawNonConnected && !recorder.sawFailed && session.bus == .connected(address), recorder.sequence)`**.
     2. `try? await Task.sleep(for: .seconds(1))` (two 500 ms polls), then
        **`check("the bus is still connected two polls after Reconnect Bus", isConnected(session.bus) && session.lastError == nil, "bus \(session.bus) err \(session.lastError ?? "-")")`**.
     3. `let host = "reconnect-\(String(UUID().uuidString.prefix(8)).lowercased()).test"`;
        `session.addScope(host)`; `await settle { session.scopeHosts.contains(host) }` (the
        default 5 s timeout is BR-AC1's bound);
        **`check("the first Scope action after Reconnect Bus succeeds and lands in scope.list", session.scopeHosts.contains(host) && session.lastError == nil, "scope \(session.scopeHosts) err \(session.lastError ?? "-")")`**.
        No retry, no second `addScope` (spec Anti-goals: masking by retry).
     4. **`check("the earlier scope entry survives the reconnect (the core's list wins)", session.scopeHosts.contains(upstream), "scope \(session.scopeHosts)")`**.
     5. `_ = try? await session.runCommand("scope.remove", ["host": .string(host)])`;
        `await settle(timeout: .seconds(3)) { !session.scopeHosts.contains(host) }`;
        **`check("scopeHosts keeps following the core after Reconnect Bus (a palette scope.remove is dropped by the poll)", !session.scopeHosts.contains(host), "scope \(session.scopeHosts)")`**.
     6. The mid-`connect()` probe: `let service = session.actions as? BusService`; if `service`
        is `nil` the check below must **FAIL** with detail `"session.actions is not a BusService"`
        (never SKIP). Else `service?.start()`; `try? await Task.sleep(for: .milliseconds(1))`;
        `service?.start()`; `await settle(timeout: .seconds(10)) { isConnected(session.bus) }`;
        `session.addScope(host)`; `await settle { session.scopeHosts.contains(host) }`;
        **`check("a second start() during the first run's connect leaves the second run the owner (Scope action succeeds)", session.scopeHosts.contains(host) && session.lastError == nil, "scope \(session.scopeHosts) err \(session.lastError ?? "-")")`**;
        then the clean-up `_ = try? await session.runCommand("scope.remove", ["host": .string(host)])`
        and `await settle(timeout: .seconds(3)) { !session.scopeHosts.contains(host) }`, so the
        core's scope is `[upstream]` again for the checks that follow.
  5. **Not changed:** the existing checks, their order, `settle`, `check`, `finishLive`, the
     240 s watchdog, the closing `recorded >= 11` check (the block adds entries, never
     removes). No new environment variable, no `SKIP`, no sleep-and-retry around a check.
- **Test:**
  - *Coder, sandbox:* `xcrun swiftc -parse apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`
    exits 0 with no output; `grep -c 'check("' apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`
    is the previous count plus at least 6 (seven if check 6's nil-service branch is a second `check(` call); `grep -n 'BusStateRecorder' …` shows the class and its one use.
  - *Orchestrator, red (pre-fix `BusService.swift`, this task's checks in; bundle
    `r192base`; external core at `/tmp/claude/192-ext/config.yaml`, listen `127.0.0.1:18192`,
    bus `18193`, upstream `python3 -m http.server 18099 --bind 127.0.0.1`):*
    ```
    AITM_CONFIG=/tmp/claude/192-ext/config.yaml \
    APP_BIN=/tmp/Aitmproxy-dev-r192base.app/Contents/MacOS/Aitmproxy-r192base \
    apps/mac/tools/selftest-live.sh 127.0.0.1:18099
    ```
    prints a line that **begins**
    `FAIL the first Scope action after Reconnect Bus succeeds and lands in scope.list: scope ["127.0.0.1:18099"] err add to scope: the bus connection closed`
    (the issue's exact message), and a line that begins
    `FAIL Reconnect Bus while connected: the bus leaves connected and comes back, never failed:`
    whose detail contains `failed("The operation couldn't be completed. (Swift.CancellationError error 1.)")`;
    the last line is `LIVE SELFTEST FAIL <k> of <n> checks` and the exit code is 1. (Checks 4
    and 5 may read PASS on the pre-fix build — vacuously, the host was never added; check 6 is
    timing-dependent there. Only checks 1 and 3 are the designated red.)
  - *Orchestrator, green (after Task 3; bundle `r192fix`; same core and upstream):* the same
    command prints exactly these six lines, in this order,
    ```
    PASS Reconnect Bus while connected: the bus leaves connected and comes back, never failed
    PASS the bus is still connected two polls after Reconnect Bus
    PASS the first Scope action after Reconnect Bus succeeds and lands in scope.list
    PASS the earlier scope entry survives the reconnect (the core's list wins)
    PASS scopeHosts keeps following the core after Reconnect Bus (a palette scope.remove is dropped by the poll)
    PASS a second start() during the first run's connect leaves the second run the owner (Scope action succeeds)
    ```
    and ends `LIVE SELFTEST PASS <n> checks` with `n` = the pre-change count the runbook's
    step 0b recorded + 6, exit 0.
- **Done when:** the sandbox checks pass; the orchestrator's red run on `r192base` shows the
  two FAIL lines above and exit 1; after Task 3 the orchestrator's green run on `r192fix` shows
  the six PASS lines and `LIVE SELFTEST PASS`, exit 0; `git diff --stat` for this task lists only
  `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`; `tools/check-connection-words.sh` still
  prints `PASS check-connection-words` (it exempts `SelfTest*.swift`, so a lane word in a check
  string is allowed).

---

### Task 2: Shell live regression check on the embedded path — `tools/selftest-live-reconnect.sh`

- **Satisfies:** BR-AC7 (the script exists, is executable, follows D6, red on the pre-fix
  build, green on the fixed build), BR-AC8 (hygiene); the shell observations of BR-AC1 (one
  Pause/Resume click takes effect after each trigger), BR-AC3 (the action succeeds after
  T1–T3), BR-AC4 (T3's `bus failed` within 5 s, then `bus: connected` within 20 s), BR-AC5
  (T1's label never reads `bus failed`).
- **Depends on:** none (Wave A; parallel with Task 1). Needs no change to any Swift file.
- **Files:** `apps/mac/tools/selftest-live-reconnect.sh` (create; `chmod +x`). No other file.
- **Change:** a `#!/bin/zsh` script with `set -u` (not `set -e`: bounded waits return non-zero
  on purpose), modelled on `tools/selftest-live-embedded.sh` (its `note`/`fail`/`cleanup`
  shape, its inline Python bus client) and `tools/snap-dev.sh` (its bundle paths). Header
  comment: what it proves (spec D6: three `start()` triggers through the real menu, then one
  menu-driven operator action observed over the bus), why a snap-dev bundle and not the
  installed app (process-name-unique, nothing installed, seconds to rebuild), usage, the bounds,
  and the hygiene rules. **The header, like the body, must not spell the operator's install or
  store paths** — say "the installed app" / "the operator's real store" (BR-AC8 is enforced by
  `grep`, comments included).

  **Usage and constants (top of file):**
  - `DEV_TAG=<tag> [CORE_DIR=<dir with aitm>] tools/selftest-live-reconnect.sh`; default
    `DEV_TAG=reconnect`; `tag=${DEV_TAG:-reconnect}`, `name=Aitmproxy`, `exe="$name-$tag"`,
    `dev="/tmp/$name-dev-$tag.app"`, `store="/tmp/$name-dev-state-$tag"`,
    `bin="$dev/Contents/MacOS/$exe"`, `core_pattern="$dev/Contents/Resources/core/aitm --config"`,
    `shots=/tmp/claude` (`mkdir -p`), `here=${0:A:h:h}` (apps/mac), `repo_root=${here:h:h}`.
  - `CORE_DIR` resolution (spec "Left to the builder"): `${CORE_DIR:-}`; else
    `"$repo_root/target/release"` when it holds an executable `aitm`; else leave it unset so
    `snap-dev.sh` borrows the installed bundle's core (its existing behaviour). Print which.
  - Bounds, each a named constant with the spec's number: `CONNECT_BOUND=20` (s, `bus: connected`
    after a trigger; T2/T3's respawn wait shares this one deadline, measured from the trigger),
    `FAILED_BOUND=5` (s, T3's `bus failed`), `ACTION_BOUND=10` (s, one menu click → `capturing`
    flips), `QUIT_BOUND=15` (s, ⌘Q → app gone), `AX_SLEEP=0.1` (s between AX reads; an
    `osascript` read itself takes ~100 ms, so reads land ≤ 250 ms apart), `BUS_SLEEP=0.5` (s
    between `proxy.status` polls), `T1_MIN_SETTLE=1` (s: after Reconnect Bus the label may still
    read the *old* `bus: connected`, so T1 keeps polling for at least this long before it
    accepts `bus: connected` — Architect's call, see below).
  - `AX_PILL`: the System Events element path of the toolbar connection pill
    (`ShellToolbar.swift` → `ListeningPill`, `.accessibilityElement(children: .combine)` +
    `.accessibilityLabel("aitmproxy: \(summary.spoken)")`), and the attribute to read
    (`description`, `name` or `value`). **The orchestrator supplies the verified System Events
    element path in the dispatch**; the Coder does not invent one. One variable, one comment,
    so a future toolbar change is a one-line fix.

  **Functions (names fixed; bodies the builder's):**
  - `note()` — `print -r -- "reconnect-live: $*"`.
  - `fail()` — `print -r -- "RECONNECT LIVE SELFTEST FAIL: $*"; exit 1` (the `EXIT` trap tears
    down). `setup_fail()` — same line prefixed `setup `, `exit 2` (build/prerequisite failures,
    so a broken rig is distinguishable from a product failure — Architect's call).
  - `se()` — `osascript -e "tell application \"System Events\" to tell process \"$exe\" to $1"`;
    returns osascript's status (a missing menu item must fail loudly, never be swallowed).
  - `menu_click <item> <menu>` — `se 'set frontmost to true'` then
    `se "click menu item \"$item\" of menu \"$menu\" of menu bar 1"`.
  - `ax_label()` — prints the pill's label via `$AX_PILL`; empty string on any error.
  - `t0` — a script-global (`zmodload zsh/datetime`; `t0=$EPOCHREALTIME`) set immediately
    before each trigger (and before the launch). Every bounded wait computes its deadline as
    `t0 + <bound>`, so a trigger's respawn wait and its `bus: connected` wait share one
    deadline measured from the trigger, as spec D6 words it; elapsed times in the notes are
    `EPOCHREALTIME - t0`, printed to one decimal.
  - `wait_label <needle> <bound_s> <min_s> [forbidden]` — polls `ax_label` every `AX_SLEEP`
    until `elapsed >= min_s` **and** the label contains `needle`, giving up at `t0 + bound_s`;
    records every distinct consecutive label into `labels_seen` (for the note) and sets
    `forbidden_seen=1` if any read contains `forbidden`; returns 0 on success, 1 at the bound.
  - `discover_child <old_pid> <old_cfg>` — until `t0 + CONNECT_BOUND`, polls
    `pgrep -f "$core_pattern"` excluding `old_pid`; for a hit, `ps -o command= -p <pid>` →
    `sed -n 's/.*--config \(.*config\.yaml\).*/\1/p'` gives `core_cfg`; requires
    `core_cfg != old_cfg`, `-s "$core_cfg"`, and `-s "${core_cfg:h}/bus.endpoint"`. Sets
    `child_pid`, `core_cfg`, `bus_addr` (first line of `bus.endpoint`, whitespace stripped),
    and `op_token` from `sed -n 's/^[[:space:]]*operator_token: "\(.*\)"/\1/p' "$core_cfg" | head -1`
    — **into a variable only; never echoed, never in a `note`, never in a file name**. Fails
    (`fail "<trigger> respawn …"`) at the bound. Re-run after every respawn: each spawn mints a
    new config, new tokens and a new `bus.endpoint` (spec Constraints).
  - `bus_json <tool>` — `python3 - "$bus_addr" "$op_token" "$tool" <<'PY' … PY`: the same
    newline-delimited JSON-RPC client as `tools/selftest-live-embedded.sh` step 7b (token line
    `{"token": …}`, `initialize` with `protocolVersion` `2025-06-18` and `clientInfo`
    `{"name": "reconnect-live-check", "version": "0"}`, then `tools/call` with empty
    `arguments`); prints the result's `structuredContent` as JSON when present, else the first
    `content[].text`; exits 1 on an RPC error or `isError`. The token travels as an argv item
    and is never printed. One function reused for `proxy.status` and `scope.list` (observation
    only — never the action, spec Anti-goals).
  - `bus_capturing()` — `bus_json proxy.status` piped through
    `python3 -c 'import json,sys; print(str(json.load(sys.stdin)["capturing"]).lower())'`;
    prints `true`/`false`.
  - `wait_capturing <true|false> <bound_s>` — polls `bus_capturing` every `BUS_SLEEP`; 0 on match,
    1 at the bound; records the elapsed time for the note.
  - `operator_action <trigger>` — the thing under test. Baseline: if `bus_capturing` is not
    `true`, `menu_click "Resume Proxy" View` once and `wait_capturing true $ACTION_BOUND` (the
    spec's "resume first"), else nothing. Then **one** `menu_click "Pause Proxy" View` (a missing
    item is `fail "<trigger> pause the View menu has no Pause Proxy item"`);
    `wait_capturing false $ACTION_BOUND || fail "<trigger> pause capturing stayed true for 10 s after one Pause Proxy click"`;
    then **one** `menu_click "Resume Proxy" View`;
    `wait_capturing true $ACTION_BOUND || fail "<trigger> resume capturing stayed false for 10 s after one Resume Proxy click"`;
    `note "<trigger>: Pause Proxy → proxy.status.capturing=false in <x> s; Resume Proxy → capturing=true in <y> s"`.
    **No retry of either click**: the label said connected, so `live()` must succeed at once.
  - `shot <trigger>` — `swift "$here/tools/winshot.swift" "$app_pid" "$shots/reconnect-$tag-<trigger>.png"`
    (the pid, not the name: a tagged bundle keeps the display name `Aitmproxy`).
  - `after_trigger <trigger> [forbidden]` — `wait_label "bus: connected" $CONNECT_BOUND <min> [forbidden]`
    (`min` = `T1_MIN_SETTLE` for T1, `0` otherwise; the deadline is the trigger's `t0 + 20`) or
    `fail "<trigger> connect bus label never read 'bus: connected' within 20 s (saw: <labels_seen>)"`;
    for T1, `[[ -z $forbidden_seen ]] || fail "<trigger> flicker bus label read 'bus failed' during Reconnect Bus (saw: <labels_seen>)"`;
    `note "<trigger>: bus: connected after <x> s (labels: <labels_seen>)"`; then
    `operator_action <trigger>`; then `shot <trigger>`.
  - `quit_app()` — `se 'set frontmost to true'`; `se 'keystroke "q" using command down'` (the
    normal quit path, so `willTerminate` reaps the child); wait ≤ `QUIT_BOUND` for `$app_pid` to
    exit; fallback `kill "$app_pid"`; then `pkill -f "$dev/Contents/Resources/core/"` (the
    **only** `pkill` in the file, its own bundle path); `app_pid=""`.
  - `cleanup()` — the `EXIT` trap: `quit_app` if `app_pid` is still set.

  **Main sequence:**
  1. **Build:** `NO_LAUNCH=1 DEV_TAG=$tag ${CORE_DIR:+CORE_DIR=$CORE_DIR} "$here/tools/snap-dev.sh"`
     (so the bundle, scratch dir and binary-staleness check are snap-dev's) or
     `setup_fail "snap-dev.sh failed"`; require `-x "$bin"` and `-x "$dev/Contents/Resources/core/aitm"`
     (`setup_fail "no core bundled; set CORE_DIR"`). `note "build: bundle $dev (core from …)"`.
  2. **Launch:** remove the bundle id's saved window state exactly as `snap-dev.sh` does on a
     launch (Architect's call: consistency with every existing dev launch; it is window state,
     not the operator's store); `rm -rf "$store"`, `mkdir "$store"` with snap-dev's refusal when
     it already exists; `unsetopt bg_nice`;
     `APP_STORE="$store" "$bin" >"$shots/reconnect-$tag-app.log" 2>&1 &`; `app_pid=$!`.
     Never `defaults write` (the harness suite is wiped under `APP_STORE` and defaults to the
     embedded core).
  3. **Rendezvous:** `t0=$EPOCHREALTIME`; `discover_child "" ""`; `wait_label "bus: connected" $CONNECT_BOUND 0`.
     If `ax_label` is empty at this point:
     `setup_fail "System Events could not read the toolbar label (is Accessibility granted to the terminal app?)"`.
     `note "launch: app pid $app_pid; embedded core pid $child_pid; bus: connected after <x> s"`.
  4. **T1 reconnect-bus:** `old_pid=$child_pid`; `t0=$EPOCHREALTIME`; `menu_click "Reconnect Bus" Proxy`;
     `after_trigger reconnect-bus "bus failed"`; then assert the child is unchanged:
     `[[ "$(pgrep -f "$core_pattern" | head -1)" == "$old_pid" ]] || fail "reconnect-bus child the embedded core pid changed (…)"`;
     `note "reconnect-bus: child pid unchanged ($old_pid)"`.
  5. **T2 restart-core:** `old_pid=$child_pid; old_cfg=$core_cfg`; `t0=$EPOCHREALTIME`;
     `menu_click "Restart Core" Proxy`; `discover_child "$old_pid" "$old_cfg"` (deadline
     `t0 + CONNECT_BOUND`; new pid, new `--config` path, non-empty `bus.endpoint`; token and
     address re-read); `note "restart-core: new core pid $child_pid after <x> s"`;
     `after_trigger restart-core`.
  6. **T3 crash-respawn:** `old_pid=$child_pid; old_cfg=$core_cfg`; `t0=$EPOCHREALTIME`;
     `kill -KILL "$old_pid"`; `wait_label "bus failed" $FAILED_BOUND 0 || fail "crash-respawn failed-report bus label never read 'bus failed' within 5 s of kill -KILL (saw: <labels_seen>)"`;
     `note "crash-respawn: bus failed seen <x> s after kill -KILL $old_pid"`;
     `discover_child "$old_pid" "$old_cfg"` (deadline `t0 + CONNECT_BOUND`); `after_trigger crash-respawn`.
  7. **Teardown:** `quit_app`; `note "teardown: app quit via ⌘Q; no core left under the bundle path"`;
     final line exactly
     `RECONNECT LIVE SELFTEST PASS (reconnect-bus, restart-core, crash-respawn: an operator action through the app succeeded after each)`;
     `exit 0`.

  **Output contract:** one `reconnect-live: <trigger>: <what was observed>` line per step
  (triggers: `build`, `launch`, `reconnect-bus`, `restart-core`, `crash-respawn`, `teardown`);
  on the first unmet bound `RECONNECT LIVE SELFTEST FAIL: <trigger> <step> <detail>` and exit 1;
  on a rig problem `RECONNECT LIVE SELFTEST FAIL: setup <detail>` and exit 2. Every wait is
  bounded by a named constant; the script cannot hang.

  **Hygiene (BR-AC8), checked by grep:** no `defaults write`; no path under the operator's
  install or store directories (the Tester greps for `Applications` and `Application Support` —
  neither string may appear, comments included); `op_token` appears only in its assignment, its
  `[[ -n … ]]` test and as a quoted argv item to `python3`; the only `pkill` pattern is
  `"$dev/Contents/Resources/core/"`; no global `kill` by name; the token is never written to a
  file.

- **Test:**
  - *Coder, sandbox:* `zsh -n apps/mac/tools/selftest-live-reconnect.sh` exits 0;
    `test -x apps/mac/tools/selftest-live-reconnect.sh`; the hygiene greps:
    `grep -c 'defaults write' <script>` → `0`;
    `grep -nE 'Applications|Application Support' <script>` → no output;
    `grep -n 'op_token' <script>` → only the assignment, the `-n` test and `python3 - "$bus_addr" "$op_token"` lines;
    `grep -n 'pkill' <script>` → only lines whose pattern is `"$dev/Contents/Resources/core/"`;
    `grep -nE 'while|for ' <script>` → every loop sits under a named bound.
  - *Orchestrator, red (pre-fix `BusService.swift`):* `DEV_TAG=r192base apps/mac/tools/selftest-live-reconnect.sh`
    prints `reconnect-live: launch: …`, then `reconnect-live: reconnect-bus: bus: connected after …`,
    then the last line
    `RECONNECT LIVE SELFTEST FAIL: reconnect-bus pause capturing stayed true for 10 s after one Pause Proxy click`
    and exits 1 (BR-AC7's pre-fix behaviour; the app is quit by the `EXIT` trap; no `aitm` under
    `/tmp/Aitmproxy-dev-r192base.app/Contents/Resources/core/` survives — `pgrep -f` prints nothing).
  - *Orchestrator, green (after Task 3):* `DEV_TAG=r192fix apps/mac/tools/selftest-live-reconnect.sh`
    prints one `reconnect-live: <trigger>: …` line per step, including
    `reconnect-live: crash-respawn: bus failed seen <x> s after kill -KILL <pid>` with x < 5, ends
    `RECONNECT LIVE SELFTEST PASS (reconnect-bus, restart-core, crash-respawn: an operator action through the app succeeded after each)`
    and exits 0; `ls /tmp/claude/reconnect-r192fix-reconnect-bus.png /tmp/claude/reconnect-r192fix-restart-core.png /tmp/claude/reconnect-r192fix-crash-respawn.png`
    lists three files.
- **Done when:** the sandbox checks pass; the orchestrator's red run on `r192base` ends with the
  FAIL line above and exit 1; after Task 3 the orchestrator's green run on `r192fix` ends with the
  PASS line, exit 0, three winshots; `git diff --stat` for this task lists only
  `apps/mac/tools/selftest-live-reconnect.sh` (mode `100755`).

---

### Task 3: The fix — ownership by run generation in `BusService`

- **Satisfies:** BR-AC1, BR-AC2, BR-AC3, BR-AC4, BR-AC5 (behaviour), BR-AC9 (scope of the diff).
- **Depends on:** Tasks 1 and 2 **landed and run red** (orchestrator sequencing, not a code
  dependency: the red logs are part of this task's dispatch so the Coder sees what it is fixing).
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify). **No other file**; no
  change to `BusClient`, `BusError`, `Session*`, views, Kit, Rust; no refactor beyond this task.
- **Change** (spec D1 rules 1–8, D2, D3; candidate C):
  1. **One counter** beside the other `@ObservationIgnored` fields:
     ```swift
     @ObservationIgnored private var runGeneration = 0
     ```
     Doc comment (the file's voice): the current run's number; `stop()` retires a run by
     bumping it; a run owns the connection — and may write `client`, `session.bus`, the role,
     `serverInfo`, `tools`, `session.listenAddress`, `session.commandRunner`, the poll's session
     data — iff its `generation` still equals this; a superseded run owns nothing but its own
     socket.
  2. **Signatures** (exact):
     ```swift
     func start()                                                           // body: stop(); runTask = Task { await run(generation: runGeneration) }
     func stop()                                                            // today's body plus `runGeneration += 1` — the single bump site
     private func run(generation: Int) async                                // was run()
     private func pollLoop(_ client: BusClient, generation: Int) async throws   // was pollLoop(_:)
     ```
     `owns` is the builder's spelling (a nested `func owns() -> Bool { generation == runGeneration }`
     in each function, a local closure, or inline `generation == runGeneration`); the three
     "disconnect and return" sites in `run` may share one small private helper or not.
  3. **Guard-site checklist** — the Coder ticks each line in its report; the panel verifies
     BR-AC3's review property against it:
     - [ ] **R1** `run`: outer loop `while !Task.isCancelled && generation == runGeneration`
       (cancellation stays the wake-up; ownership is the write permission; `!Task.isCancelled`
       stays so a cancelled task can never spin on instantly-returning sleeps).
     - [ ] **R2** after `let info = try await client.connect()`: if not owner →
       `await client.disconnect()` and `return` — before `serverInfo = info`,
       `session.bus = .connected(address)`, `session.applyResolvedRole(info.role)`,
       `session.listenAddress = …`.
     - [ ] **R3** `listTools`: split the statement so the await and the write are separate —
       `let listed = (try? await client.listTools()) ?? []`; if not owner → disconnect and
       `return`; then `tools = listed`, `session.tools = tools`, `session.commandRunner = …`.
     - [ ] **R4** after `await refreshScope()`: if not owner → disconnect and `return` — before
       `backoff = .seconds(1)` and `try await pollLoop(client, generation: generation)`.
     - [ ] **R5** `catch`: `session.bus = .failed(Self.describe(error))` and
       `session.applyResolvedRole(nil)` **only if owner** (so a bare `stop()` leaves
       `.disconnected`, spec D3, and a superseded run never writes the transient
       `.failed(CancellationError…)`, BR-AC5).
     - [ ] **R6** after the post-`catch` `await client.disconnect()`: if not owner → `return`;
       else `self.client = nil`, then today's `if Task.isCancelled { break }`, back-off sleep,
       `backoff = min(backoff * 2, .seconds(30))`, loop.
     - [ ] **R7** `pollLoop`: loop `while !Task.isCancelled && generation == runGeneration`.
     - [ ] **R8** inside `for id in ids`: split `if let json = try? await client.call("flow.get", …), let summary = …`
       so that after the await returns there is `guard owns else { return }` **before**
       `throughput.record(…)`, `summaries[id] = summary`, `refetch.didFetch(…)`.
     - [ ] **R9** immediately after the `for` loop, before `summaries = summaries.filter …`:
       `guard owns else { return }` — this one guard covers `summaries`, `refetch.retain`,
       `session.restoredFlows`, `session.rows`, `session.upBytesPerSecond`,
       `session.downBytesPerSecond` (the whole tail of the iteration has no further await
       before `Task.sleep`). Returning unwinds into `run`'s R6, which is itself owner-checked;
       `throw CancellationError()` is an acceptable alternative (spec "Left to the builder").
     - [ ] **R10 unchanged (do not add guards here, do not alter):** `session.bus = .connecting(address)`
       and `self.client = client` before the first await (the loop condition just held);
       `notificationTask?.cancel()` / replacement (rule 7); the no-endpoint branch
       (`.connecting("embedded core")` / `.failed("no bus configured")` + sleep + `continue`);
       `pollLoop`'s `throughput.reset()`, `refetch.reset()` and its `defer` that zeroes the rates
       (spec D2); `refreshScope()`, `refreshProxyStatus()`, `persistEmbeddedScope()`, `live()`,
       `call()`, every `FlowActions` method, `scopeVerb`, `awaitEmbeddedEndpoint`,
       `useEmbeddedEndpoint`, `useExternalEndpoint`, `resolveEndpoint`, `listenAddress`,
       `describe`. The back-off (1 s → 30 s) and `pollInterval` (500 ms) are unchanged.
  4. **Review-verifiable property (BR-AC3):** in `run(generation:)` and
     `pollLoop(_:generation:)`, every write to `self.client`, `session.bus`,
     `session.applyResolvedRole`, `serverInfo`, `tools`, `session.tools`,
     `session.listenAddress`, `session.commandRunner`, `summaries`, `refetch`, `throughput`,
     `session.restoredFlows`, `session.rows`, `session.upBytesPerSecond`,
     `session.downBytesPerSecond` that follows a suspension point is dominated by an ownership
     check with **no `await` between the check and the write**. The Coder's report lists each
     guard site with its line number and the protected writes; a reviewer reads each span.
  5. **Comments:** one line of *why* at each guard site, in the file's existing voice (e.g.
     "A superseded run owns nothing but its own socket."); the `run` doc comment gains one
     sentence on the generation. No commented-out code.
- **Test:**
  - *Coder, sandbox:* `xcrun swiftc -parse apps/mac/Sources/Aitmproxy/Bus/BusService.swift`
    exits 0; `grep -n 'runGeneration' apps/mac/Sources/Aitmproxy/Bus/BusService.swift` shows
    the declaration, exactly one `+= 1` (in `stop()`), the `run(generation: runGeneration)` spawn
    in `start()`, and the comparisons; `grep -n 'func run\|func pollLoop' …` shows the two new
    signatures and no old ones; `git diff --stat` lists only this file.
  - *Orchestrator, green:* `NO_LAUNCH=1 DEV_TAG=r192fix apps/mac/tools/snap-dev.sh` ends
    `== build only (NO_LAUNCH=1) · /tmp/Aitmproxy-dev-r192fix.app` (a compile error ends
    `build failed: …` instead); then Task 1's green command (six PASS lines,
    `LIVE SELFTEST PASS <n> checks`, exit 0) and Task 2's green command (the PASS line, exit 0,
    three winshots) as quoted in those tasks;
    `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` ends
    `✔ Test run with 31 tests in 6 suites passed after <t> seconds.` (no fewer than the base
    SHA's 31).
  - *Honest-failure control (BR-AC4), read from Task 2's green log:*
    `reconnect-live: crash-respawn: bus failed seen <x> s after kill -KILL <pid>` with `x < 5`,
    followed by `reconnect-live: crash-respawn: bus: connected after <y> s` with `y < 20`.
- **Done when:** the sandbox checks pass; the orchestrator's `r192fix` bundle builds; both live
  checks are green on it (the same commands that were red on `r192base`); `swift test` reports
  31 tests passed; `git diff --stat <base>..HEAD` lists only the four files of BR-AC9 plus
  `docs/superpowers/`.

---

### Task 4: Gate wiring — one sentence in `apps/mac/CLAUDE.md`

- **Satisfies:** spec D7 (Architect's call 9); supports BR-AC10 (the new check is part of the mac
  gate's "run after any change to `Bus/`" instruction).
- **Depends on:** Task 2 (the script it names must exist). May run in parallel with Task 3
  (disjoint file).
- **Files:** `apps/mac/CLAUDE.md` (modify: one sentence). No other file.
- **Change:** in the "Build and check" list, in the bullet that begins
  "Live self-test (every proxy action over the real bus, `SelfTest+Live.swift`): …", directly
  after the sentence "Run it after any change to `Bus/`.", insert this one sentence, verbatim
  (Markdown as shown; it stays inside the same bullet):

  ```markdown
  So is `tools/selftest-live-reconnect.sh` (`DEV_TAG=<tag> [CORE_DIR=<dir>]`): it builds a snap-dev bundle with the embedded core, drives Proxy ▸ Reconnect Bus, Proxy ▸ Restart Core and a `kill -KILL` of the core through the real menu bar, and asserts over the bus that one menu-driven View ▸ Pause/Resume Proxy takes effect after each — the #192 reconnect-ownership check.
  ```

  Nothing else in the file changes (not the five-step gate list, not the removed-modes block).
- **Test:** `grep -c 'selftest-live-reconnect.sh' apps/mac/CLAUDE.md` prints `1`;
  `git diff --stat` for this task lists `apps/mac/CLAUDE.md` alone with one changed line
  (`1 file changed, 1 insertion(+), 1 deletion(-)` or `1 insertion(+)` depending on wrapping).
- **Done when:** the grep prints `1`, the diff touches one file, and the sentence names the
  script's exact path and its `DEV_TAG`/`CORE_DIR` usage.

---

## Parallelization

| Task | Files | Independent of | Wave |
|---|---|---|---|
| 1 In-app check | `Aitmproxy/SelfTest+Live.swift` | 2, 4 | A |
| 2 Shell check | `tools/selftest-live-reconnect.sh` (new) | 1, 4 | A |
| 3 The fix | `Aitmproxy/Bus/BusService.swift` | 4 (file-disjoint); sequenced after the red runs of 1 and 2 | B |
| 4 CLAUDE.md sentence | `apps/mac/CLAUDE.md` | 1, 3 (needs 2 to exist) | B (∥ 3) |

Two writers never share a file. The orchestrator rebuilds the dev bundle twice: `r192base`
after Wave A (pre-fix, red runs) and `r192fix` after Task 3 (green runs).

## Traceability

| Spec AC | Proven by |
|---|---|
| BR-AC1 | Task 1 check 3 (in-app, 5 s, `lastError == nil`); Task 2 `operator_action` after T1, T2, T3 (one click, 10 s) |
| BR-AC2 | Task 1 checks 4 and 5 (3 s poll-driven follow) |
| BR-AC3 | Task 1 checks 1, 3, 5, 6; Task 2 T1–T3; panel review of Task 3's checklist R1–R9 (no `await` between check and write) |
| BR-AC4 | Task 2 T3: `bus failed` within 5 s of `kill -KILL`, `bus: connected` within 20 s, then the action; review of Task 3 R5/R6 (owner path unchanged) |
| BR-AC5 | Task 1 check 1 (`!sawFailed`, sequence quoted); Task 2 T1 (`forbidden_seen` empty) |
| BR-AC6 | Task 1: red on `r192base` (`FAIL … err add to scope: the bus connection closed`), six PASS lines + `LIVE SELFTEST PASS` on `r192fix` |
| BR-AC7 | Task 2: red on `r192base` (`FAIL: reconnect-bus pause …`, exit 1), `RECONNECT LIVE SELFTEST PASS (…)` + three winshots on `r192fix` |
| BR-AC8 | Task 2's hygiene greps (quoted by the Tester) |
| BR-AC9 | Runbook step 11 `git diff --stat main..HEAD` |
| BR-AC10 | Runbook steps 7–10 (`swift test` 31, four tripwires, `selftest-live-embedded.sh`, Rust gate) |

## Orchestrator runbook (Terminal panel, in this order)

`W=/Users/matt/Security/aitmproxy/.claude/worktrees/cool-zhukovsky-c12370`; run the mac commands
from `$W/apps/mac`. The external core is the one the orchestrator already staged:
config `/tmp/claude/192-ext/config.yaml` (`listen: "127.0.0.1:18192"`, bus `loopback_tcp` port
`18193`, agent + operator tokens), started with `/tmp/claude/192-ext/start-core.sh` (or
`AITM_CONFIG=/tmp/claude/192-ext/config.yaml <aitm>`), with the upstream
`python3 -m http.server 18099 --bind 127.0.0.1`. **Each self-test run needs a FRESH external core** (orchestrator correction, 2026-11-01): the
live self-test assumes the core's defaults. A core reused from an earlier run already has the
upstream in scope (so `settle { scopeHosts.contains(upstream) }` returns before the `scope.add`
reply lands) and keeps that run's last breakpoint rules, because `flow.intercept {enabled: false}`
leaves the core's rule set alone and the app sends `rules` only when it has some; the first
`arm(true)` then parks only the stale rule's matches ("a request through the armed proxy parks"
fails). Restart the core between runs (`/tmp/claude/192-ext/restart-core.sh`). Keep the logs under
`/tmp/claude/`.

| # | When | Command | Expected last line (and exit) |
|---|---|---|---|
| 0 | done | `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` | `✔ Test run with 31 tests in 6 suites passed after <t> seconds.` (0) |
| 0b | before Wave A lands (optional but gives BR-AC6's `n`) | `AITM_CONFIG=/tmp/claude/192-ext/config.yaml APP_BIN=/tmp/Aitmproxy-dev-r192base.app/Contents/MacOS/Aitmproxy-r192base tools/selftest-live.sh 127.0.0.1:18099` on the already-built pre-task `r192base` | `LIVE SELFTEST PASS <n_base> checks` (0) — record `n_base` |
| 1 | after Tasks 1 + 2 are committed | `NO_LAUNCH=1 DEV_TAG=r192base tools/snap-dev.sh` (rebuilds the same tag; snap-dev refuses a binary older than any source) | `== build only (NO_LAUNCH=1) · /tmp/Aitmproxy-dev-r192base.app` (0) |
| 2 | red, Task 1 | `AITM_CONFIG=/tmp/claude/192-ext/config.yaml APP_BIN=/tmp/Aitmproxy-dev-r192base.app/Contents/MacOS/Aitmproxy-r192base tools/selftest-live.sh 127.0.0.1:18099 2>&1 \| tee /tmp/claude/192-live-red.log` | contains `FAIL the first Scope action after Reconnect Bus succeeds and lands in scope.list: scope ["127.0.0.1:18099"] err add to scope: the bus connection closed`; last line `LIVE SELFTEST FAIL <k> of <n> checks` (1) |
| 3 | red, Task 2 | `DEV_TAG=r192base tools/selftest-live-reconnect.sh 2>&1 \| tee /tmp/claude/192-reconnect-red.log` | `RECONNECT LIVE SELFTEST FAIL: reconnect-bus pause capturing stayed true for 10 s after one Pause Proxy click` (1); afterwards `pgrep -f /tmp/Aitmproxy-dev-r192base.app/Contents/Resources/core/` prints nothing |
| — | dispatch Task 3 (with both red logs) and Task 4 | | |
| 4 | after Task 3 is committed | `NO_LAUNCH=1 DEV_TAG=r192fix tools/snap-dev.sh` | `== build only (NO_LAUNCH=1) · /tmp/Aitmproxy-dev-r192fix.app` (0) |
| 5 | green, Task 1 | `AITM_CONFIG=/tmp/claude/192-ext/config.yaml APP_BIN=/tmp/Aitmproxy-dev-r192fix.app/Contents/MacOS/Aitmproxy-r192fix tools/selftest-live.sh 127.0.0.1:18099 2>&1 \| tee /tmp/claude/192-live-green.log` | the six `PASS …` lines of Task 1; `LIVE SELFTEST PASS <n> checks` with `n = n_base + 6` (0) |
| 6 | green, Task 2 | `DEV_TAG=r192fix tools/selftest-live-reconnect.sh 2>&1 \| tee /tmp/claude/192-reconnect-green.log` | `RECONNECT LIVE SELFTEST PASS (reconnect-bus, restart-core, crash-respawn: an operator action through the app succeeded after each)` (0); `ls /tmp/claude/reconnect-r192fix-*.png` lists 3 files |
| 7 | gate 1 | `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` | `✔ Test run with 31 tests in 6 suites passed after <t> seconds.` (0) |
| 8 | gate 2 | `tools/grid-lint.sh; tools/check-connection-words.sh; tools/check-capture-operator-only.sh; tools/check-capture-toggle.sh` | `PASS grid-lint` · `PASS check-connection-words` · `PASS check-capture-operator-only (<N> agent-reachable surfaces checked)` · `PASS check-capture-toggle` (each 0) |
| 9 | gate 5 (unchanged script; it builds release `aitm` and installs over the user-level app, its contract) | `tools/selftest-live-embedded.sh` | `EMBEDDED LIVE SELFTEST PASS (AC6 …; AC14 …; AC7 …)` (0) |
| 10 | Rust gate, from `$W` | `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` | the final `test result: ok. …` and exit 0 |
| 11 | BR-AC9 | `git -C $W diff --stat main..HEAD -- . ':!docs/superpowers'` | exactly `apps/mac/CLAUDE.md`, `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`, `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`, `apps/mac/tools/selftest-live-reconnect.sh` |

Then: whole-branch Tester (every BR-AC, quoting steps 2–3 and 5–11), the three-reviewer panel,
`superpowers:finishing-a-development-branch`.

Traps the orchestrator already knows, restated for the runbook: the dev bundle's `pgrep` and
`kill` target only its own bundle path; a SIGTERM to the app skips its teardown (the scripts quit
via ⌘Q and reap by bundle path); `swift test`, the live scripts and `osascript` are Terminal-only;
the AX element path for `AX_PILL` comes from the orchestrator's System Events probe
(`/tmp/claude/192-ax-probe.sh`) and goes into Task 2's dispatch; if a first-run sheet is up on
the dev bundle, `window 1` may be the sheet — the probe decides the path. **Probe result
(2026-11-01, pre-fix `r192base` bundle):** the pill is `button 1 of group 1 of toolbar 1 of window
"aitmproxy"`; its `description` is the generic `button` (the SwiftUI accessibility label is not
exposed through System Events) and its `help` is `ConnectionSummary.tooltip`, three lines of the form
`Bus: connected — operator · 127.0.0.1:<port>` / `Bus: connecting… — <address>` / `Bus: bus failed —
<why>` / `Bus: offline — Embedded core`. `window 1` of the process is an unnamed `AXUnknown` window, so
the window is addressed by name. The script therefore reads `help` and matches the spec's needles
(`bus: connected`, `bus failed`) case-insensitively.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 2 | Owner (live run, pre-fix bundle) | Important | `bus_capturing()` declared `local status`; `status` is zsh's read-only last-exit-status parameter, so the function printed nothing and `operator_action` took the resume-first branch ("the View menu has no Resume Proxy item") | fixed in 48ae42aa (renamed to `reply_json`; every other `local` name checked against zsh's specials) |
| 2 | Owner (live run, pre-fix bundle) | Important | `menu "View" of menu bar 1` resolved to the SYSTEM View menu ("Enter Full Screen"): the menu bar carries two items named View, the app's `CommandMenu("View")` being the last; the click found no "Pause Proxy" | fixed in fc119ffe (`menu_click` addresses a menu as the last menu bar item of that name; one-statement form verified on the running bundle). Product follow-up: the app shows two View menus (see Shipped) |
| 3 | Coder (reported plan gap) | Important | Plan R8 treated `FlowRefetchPolicy.shouldFetch` as a read; it is `mutating`, so the first `shouldFetch` of an iteration followed the `flow.list` await with no ownership check between (Task 3 item 4 property did not hold literally) | fixed in 3687fa19: `guard owns() else { return }` right after the `flow.list` await (R8a), before the `for` loop |
| 3 | Owner (merge with main, 4762cdc2) | Minor | PR #254 (merged to main after the plan's base) added `await session.refreshCAStatus()` every 10th tick inside `pollLoop` and `session.forgetCATrust()` to its `defer`; the plan's R-list predates them | accepted by the orchestrator 2026-11-01: `refreshCAStatus` reaches the bus through `session.commandRunner` (the OWNER's client, or nil → returns false) and writes the OS store's fact, the same for every run; `forgetCATrust()` runs within one main-actor turn of cancellation like the rate zeroing spec D2 accepts, and the new run's tick 0 re-reads. Same category as D2's `refreshScope`/`refreshProxyStatus`; no guard added. Panel asked to confirm |
| 1 | Tester (stage 5) | Important | The pre-existing check "the self-test's own scope.add is recorded as an operator command" ran right after `settle { scopeHosts.contains(upstream) }`, which returns at once on a core that already lists the upstream, so it raced the in-flight call; and the D5 block reconnected while that first `scope.add` could still be in flight, so the reconnect cut it by design (`lastError` "add to scope: the bus connection closed") and check 2 failed for the wrong reason (first green attempt, reused core) | fixed in 78a1eb52: settle on the activity entry before the recording check; settle until the entry reads `.ok` and the list shows the upstream before `reconnectBus()`; check 5 additionally requires the palette `scope.remove` to land (`removed`), so it no longer passes vacuously when check 3 fails. Check strings unchanged |
| 2 | Tester (stage 5) | Minor | A core left under the dev bundle's path by an earlier run of the same DEV_TAG would be the one `discover_child` finds at the rendezvous | fixed in c148b0ff: the script refuses to start (exit 2) when `pgrep -f "$core_pattern"` already matches; reaps nothing |
| — | Tester F1 (stage 5) | Minor | A reused external core keeps the previous run's breakpoint rules (`flow.intercept {enabled: false}` leaves the rule set alone; the app sends `rules` only when it has some), so the first `arm(true)` parks only the stale rule's matches: "a request through the armed proxy parks" failed in the first green attempt | accepted by the orchestrator 2026-11-01: a pre-existing assumption of the live self-test (fresh core per run), recorded in the runbook (8e7c024c). Product follow-up in Shipped: disarming should send `rules: []` so the core's set follows the app's |
| — | Tester F2–F5 (stage 5) | Minor | F2 the saved-window-state `rm -rf` is shared with the installed app (same bundle id, as snap-dev and selftest-live.sh already do); F3 the token rides in `python3` argv (as the embedded self-test does); F4 BR-AC9 must diff against `origin/main`'s merge base; F5 the script's 250 ms AX cadence can miss a sub-250 ms flicker (the in-app recorder pins it) | accepted by the orchestrator 2026-11-01: F2/F3 are the existing harness conventions; F4 applied (runbook step 11 uses the merge base); F5 is why both surfaces exist |
| — | Owner (green run) | Minor | `LIVE SELFTEST PASS 97 checks`, not the 96 BR-AC6 predicted from the 90-check baseline | accepted by the orchestrator 2026-11-01: the one extra check is `PASS Proxy menu has Trust the aitmproxy CA`, a menu-coverage check PR #254 added to `SelfTest.swift` on main and merged into this branch at 4762cdc2; the branch itself adds exactly six (diff of the PASS names between `/tmp/claude/192-live-base.log` and `/tmp/claude/192-live-green.log`) |
| — | Owner (runbook step 9) | Minor | `tools/selftest-live-embedded.sh` installs over the user-level app, quits the process named `Aitmproxy` and pgreps `Aitmproxy.app/Contents/Resources/core/aitm`; the operator's own `/Applications/Aitmproxy.app` (pid 34883) and its core were running throughout this session | accepted by the orchestrator 2026-11-01: not run while the operator's app is up (it would quit his app and its pgrep would catch his core, a false AC7 failure); the embedded path's reconnect behaviour is proven by `tools/selftest-live-reconnect.sh` on a dev bundle with a unique process name (runbook step 6). The script itself is unchanged by this PR |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

| What | Where |
|---|---|
