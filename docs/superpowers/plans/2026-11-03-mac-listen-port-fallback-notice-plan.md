# macOS app: listen-port fallback notice implementation plan

**Status:** approved (2026-11-03 by the orchestrating session under Matt's standing autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-11-03-mac-listen-port-fallback-notice-design.md` (approved 2026-11-03)
**Branch / worktree:** `feat/mac-listen-port-fallback-notice` at
`/Users/matt/Security/aitmproxy/.claude/worktrees/port-fallback` (called `WT`), cut from `main` at `1e891779`
(`BASE`, the v0.5.20 release commit). Absolute paths everywhere; never `cd` to the main checkout. The spec file is
present untracked in `WT` and is committed together with this plan by the orchestrating session before Task 1 is
dispatched.

## Overview

Three Coder tasks, strictly sequential, each test-first, each one commit (by explicit path, never `git add -A`).
Task 1 puts the fact in Kit: `ListenPortFallback` (the three strings) and `CoreConnection.portFallback` (the
derivation), pinned in `CoreConnectionTests`. Task 2 threads it through `ConnectionSummary`: the member, the
`.warning` core lane with the remedy, the tooltip's fourth line, `coreAddressShown`, and the `coreRunning` step's
detail, pinned in `ConnectionSummaryTests`. Task 3 wires the app target: the pill branch, the Settings row and
button, the footnote sentence, the Flows empty-state argument and the per-poll `listenAddress` write, pinned by the
source tripwire `ListenPortFallbackTripwireTests`, plus the one `apps/mac/CLAUDE.md` layout line. Nothing fans out:
Task 2 needs Task 1's types and Task 3 needs Task 2's members, and `swift test` is one package.

**The test command.** Every task's proof is
`swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build-port-fallback --filter <Suite>` run from
`WT/apps/mac`, and Task 3 ends with the unfiltered run, the four `apps/mac/tools` scripts and a full `swift build`.
SwiftPM cannot run inside the Claude Bash sandbox (memory `sandbox-swift-and-git-switch-quirks`); the Coder runs
these in Matt's Terminal panel. Red and green runs are both quoted in the Coder's report. If the Coder has no
Terminal tool, it commits the test file first, stops with the SHA so the orchestrating session can record the red
run, then proceeds; its own pre-check is the sandbox typecheck from memory
`sandbox-swift-typecheck-in-process-plugins` (not evidence of a pass).

**Not Coder work.** The live proof (spec D10, AC7-AC11), the AC6 negative control (restore the literal
`"Bound address"` in `SettingsView.swift` once, watch the tripwire fail, revert) and the AC12 diff-stat check belong
to the orchestrating session after Task 3 is committed. The Coder must not launch a dev bundle, drive System Events,
call any bus verb, or read `log show`.

**Live-proof adaptation (orchestrating session; read before running D10).** The operator's installed core holds
`127.0.0.1:8080` on this Mac today, so the proof cannot occupy 8080 without touching the operator's core (spec
anti-goal). Instead it holds the dev bundle's *preferred* port: seed `proxy.preferredPort` = `18090` (an `Int`) into
the named isolated suite (`APP_DEFAULTS_SUITE=<name>`, alongside `systemProxy.promptSuppressed` true), start
`python3 -m http.server 18090 --bind 127.0.0.1`, then launch the dev bundle. `EmbeddedCore.swift:163` reads that key
for the pick and `EmbeddedCoreController.swift:123` for `appliedPort`, both from `Store.defaults`, so the same code
path runs with `preferred == 18090`: the notice reads `Port 18090 was busy; listening on <p>`, the remedy
`Port 18090 was busy; listening on <p> — Restart Core tries 18090 again`, the button `Restart on 18090`, and
`proxy.system.status.ours.port == <p>`. Every `8080` in AC7-AC9 is read as `18090`; AC8's success reading is
`proxy.status.address == "127.0.0.1:18090"`. AC10 (external core on 18080) and AC11 (environment unchanged) are
unchanged. Two reading notes: the Status page prints a lane's remedy as visible text (`StatusPanel.swift:254`) but
a Getting Started step's `detail` only as the row's help (`StatusPanel.swift:329`), so AC5's live reading is the
`coreRunning` row's AX help attribute, not a static text; and the pill's `.help` is likewise an AX help attribute.

## Tasks

### Task 1: the fact in Kit — `ListenPortFallback` and `CoreConnection.portFallback`

- **Satisfies:** AC1, AC2 (spec D1, D2).
- **Depends on:** none.
- **Files:** `apps/mac/Sources/AitmproxyKit/ListenPortFallback.swift` (create),
  `apps/mac/Sources/AitmproxyKit/CoreConnection.swift` (modify),
  `apps/mac/Tests/AitmproxyKitTests/CoreConnectionTests.swift` (modify).
- **Change:**
  - New file `ListenPortFallback.swift`, public, SwiftUI-free, doc comment citing the spec and the 0.5.18 incident
    line (`docs/testing/2026-11-03-release-acceptance-0.5.18/README.md`, "Incident: the harness took 8080 from the
    operator's core"):
    - `public struct ListenPortFallback: Hashable, Sendable`
    - `public let preferred: Int`, `public let bound: Int`
    - `public init(preferred: Int, bound: Int)`
    - `public var notice: String` → `"Port \(preferred) was busy; listening on \(bound)"` (no trailing full stop)
    - `public var restartTitle: String` → `"Restart on \(preferred)"`
    - `public var remedy: String` → `notice + " — Restart Core tries \(preferred) again"` (the separator is
      space, em dash, space, exactly as `TrafficRoute.line` joins)
  - In `CoreConnection.swift`, on `CoreConnection`, after `appliedSystemProxyBypass`:
    - `public var portFallback: ListenPortFallback?` (computed; it therefore takes no part in `Hashable` and the
      synthesized `init` is unchanged). Non-nil only when `kind == .embedded`, `status == .ready`,
      `appliedPort != nil`, `proxyAddress` parses to a port (the `Int` after the last `:`, the same parse as
      `SettingsView.port(from:)` today: `"127.0.0.1:8081"` → 8081, `"127.0.0.1"` → nil), and that port differs
      from `appliedPort`. Everything else gives nil.
    - The port parse is the builder's: a `private static func` on `CoreConnection` or a static on
      `ListenPortFallback`; the spec's "Left to the builder" allows either.
- **Test (write first, run red, then green):** in `CoreConnectionTests` (Swift Testing, `#expect`), using a helper
  that builds `CoreConnection(id: CoreID(rawValue: "embedded"), kind: .embedded, endpoint: endpoint(port: 9001), status: .ready, label: "Embedded core", proxyAddress: …, appliedPort: …)`:
  - `port_fallback_is_the_fact_when_an_embedded_ready_core_bound_another_port`:
    `proxyAddress: "127.0.0.1:8081", appliedPort: 8080` → `portFallback == ListenPortFallback(preferred: 8080, bound: 8081)`.
  - `port_fallback_is_nil_without_a_mismatch_or_a_known_pair`, each `== nil`:
    `proxyAddress: "127.0.0.1:8080", appliedPort: 8080`; `appliedPort: nil` with `"127.0.0.1:8081"`;
    `proxyAddress: nil, appliedPort: 8080`; `proxyAddress: "127.0.0.1", appliedPort: 8080`;
    `kind: .external` with `"127.0.0.1:8081"`/8080; `status: .starting` with the same;
    `status: .degraded(reason: "x")` with the same.
  - `port_fallback_words_are_the_spec_literals`: for `ListenPortFallback(preferred: 8080, bound: 8081)`,
    `notice == "Port 8080 was busy; listening on 8081"`, `restartTitle == "Restart on 8080"`,
    `remedy == "Port 8080 was busy; listening on 8081 — Restart Core tries 8080 again"`; and, so the
    interpolation is pinned on the numbers the live proof uses (plan call),
    `ListenPortFallback(preferred: 18090, bound: 18091).notice == "Port 18090 was busy; listening on 18091"` and
    `.restartTitle == "Restart on 18090"`.
  - `port_fallback_does_not_take_part_in_equality`: two connections equal in every stored field are `==` (the
    property is derived, so `Set` and the registry dirty-check behave as before).
  - Red run: the three new tests fail to compile against `BASE` (no `ListenPortFallback`, no `portFallback`); the
    report quotes the compiler error from
    `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build-port-fallback --filter CoreConnectionTests`.
    Green run: the same command, every `CoreConnectionTests` test passes (the 7 existing plus the 4 new).
- **Done when:** the filtered run is green and quoted; `git diff --stat` for the commit touches exactly the three
  files above; the commit message says what the operator can now rely on (the fact exists in Kit).

### Task 2: `ConnectionSummary` carries the fact; the core lane warns

- **Satisfies:** AC3, AC4, AC5 (spec D3).
- **Depends on:** Task 1.
- **Files:** `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift` (modify),
  `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (modify).
- **Change:** in `ConnectionSummary.swift`:
  - `ConnectionSummary` gains `public let portFallback: ListenPortFallback?` (after `listenAddress`; the only caller
    of the memberwise initializer is `make`, verified by grep, so no default is required; the builder may add an
    explicit `public init` with `portFallback: ListenPortFallback? = nil` last if preferred — spec "Left to the
    builder") and `public var coreAddressShown: Bool { core.state == .ok || portFallback != nil }`.
  - `make` sets `portFallback` to `connection?.portFallback` when `activeKind == .embedded`, else nil. No new
    `make` parameter; the `make` signature is unchanged.
  - `coreLane(_:activeKind:bus:)`, case `.ready`: when `connection.portFallback` is non-nil, return
    `ConnectionLane(kind: .core, state: .warning, word: "running", detail: address, remedy: fallback.remedy, actions: [.restartCore, .showCoreLog])`;
    otherwise the existing `.ok` lane, byte-identical.
  - `tooltip`: the three lane lines as today, then `"\n" + fallback.notice` only when `portFallback` is non-nil.
  - `steps(...)`: the `coreRunning` step gets `detail: portFallback?.notice` when the core lane is the fallback
    lane, nil otherwise. `steps` is a `private static func` that today receives `core: ConnectionLane`; the builder
    passes the fallback in (an added `portFallback: ListenPortFallback?` parameter on `steps`, or the connection)
    without changing `make`'s public signature. `title` stays `coreDone ? "Core is running" : "Start the core"`;
    note `coreDone` is `core.state == .ok || …` and must become true for the `.warning` fallback lane too (the
    core is running), so the builder widens that predicate to the fallback case rather than the lane state alone.
- **Test (write first, run red, then green):** in `ConnectionSummaryTests`, using the existing helpers
  (`core(_:proxy:)` builds `appliedPort: 8080`, so `core(.ready, proxy: "127.0.0.1:8081")` is the fallback
  connection; `make(...)` defaults `listenAddress: "127.0.0.1:8080"`, capability `.extensionNotInstalled`):
  - `theCoreLaneWarnsAndNamesTheRemedyWhileFallingBack`: with `let s = make(core: core(.ready, proxy: "127.0.0.1:8081"), bus: .connected("x"), role: "operator")`:
    `s.core == ConnectionLane(kind: .core, state: .warning, word: "running", detail: "Embedded · proxy 127.0.0.1:8081", remedy: "Port 8080 was busy; listening on 8081 — Restart Core tries 8080 again", actions: [.restartCore, .showCoreLog])`;
    `s.portFallback == ListenPortFallback(preferred: 8080, bound: 8081)`; `s.coreAddressShown == true`;
    `s.tooltip.hasSuffix("\nPort 8080 was busy; listening on 8081")`; and the whole tooltip is
    `"Core: running — Embedded · proxy 127.0.0.1:8081\nBus: connected — operator · x\nAll Apps: all apps off — extension not installed\nPort 8080 was busy; listening on 8081"`
    (four lines: `tooltip.split(separator: "\n", omittingEmptySubsequences: false).count == 4`).
  - `theFallbackIsTheWorstLaneWhenTheOthersAreFine` (spec Constraints): with
    `make(core: core(.ready, proxy: "127.0.0.1:8081"), bus: .connected("x"), role: "operator", capability: .capturing, hosts: 2)`:
    `overall == .warning`, `worst.kind == .core`, `worst.compact` begins with `"core: running"` (the accepted
    compact reading).
  - `theReadyLaneIsUnchangedWithoutAFallback`: with `let s = make(core: core(.ready), bus: .connected("x"), role: "operator")`:
    `s.core == ConnectionLane(kind: .core, state: .ok, word: "running", detail: "Embedded · proxy 127.0.0.1:8080", remedy: nil, actions: [.restartCore, .showCoreLog])`;
    `s.portFallback == nil`; `s.coreAddressShown == true`;
    `s.tooltip == "Core: running — Embedded · proxy 127.0.0.1:8080\nBus: connected — operator · x\nAll Apps: all apps off — extension not installed"`
    (three lines). The existing pins at lines 71-73 (`coreWords`), 235 (`"Core is running"` first in the titles)
    and 1195 (the three-line tooltip) are not edited and still pass.
  - `theCoreRunningStepCarriesTheNoticeAsItsDetail`: with the fallback summary,
    `step(s, .coreRunning)?.done == true`, `?.title == "Core is running"`, `?.action == nil`,
    `?.detail == "Port 8080 was busy; listening on 8081"`; without the fallback (`core(.ready)`),
    `step(s, .coreRunning)?.detail == nil` and `?.title == "Core is running"`.
  - `anExternalActiveKindSurfacesNoFallback`: with
    `make(core: core(.ready, proxy: "127.0.0.1:8081"), kind: .external, bus: .connected("127.0.0.1:9090"))`:
    `portFallback == nil`, `core.word == "external"`, `coreAddressShown == false`, tooltip has three lines; and
    `make(core: core(.starting, proxy: "127.0.0.1:8081")).coreAddressShown == false` (a working lane keeps the
    ` · core starting…` pill branch).
  - Red run: the new tests fail to compile against the Task 1 tree (no `portFallback` / `coreAddressShown` on
    `ConnectionSummary`); quote the error from
    `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build-port-fallback --filter ConnectionSummaryTests`.
    Green run: the same command, every `ConnectionSummaryTests` test passes, including the untouched 71-73, 235 and
    1195 pins.
- **Done when:** the filtered run is green and quoted; `--filter CoreConnectionTests` still green; the commit
  touches exactly the two files above.

### Task 3: the app surfaces, the poll write, the tripwire, the layout line

- **Satisfies:** AC6 (spec D4, D5, D6, D9 tripwire); prepares AC7-AC10 (live, orchestrating session).
- **Depends on:** Task 2.
- **Files:** `apps/mac/Tests/AitmproxyKitTests/ListenPortFallbackTripwireTests.swift` (create),
  `apps/mac/Sources/Aitmproxy/Shell/ShellToolbar.swift` (modify), `apps/mac/Sources/Aitmproxy/SettingsView.swift`
  (modify), `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (modify),
  `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify), `apps/mac/CLAUDE.md` (modify, one line).
- **Change:**
  - `ShellToolbar.swift`, `ListeningPill.body`: the branch condition `if summary.core.state == .ok` becomes
    `if summary.coreAddressShown`; the branch bodies (` · ` / ` · paused `, the address `Text`, ` · intercept armed`,
    the `else` ` · core \(summary.core.word)`) are unchanged, as are the dot (`summary.core.state.color`) and
    `.help(summary.tooltip + "\nOpens Status (⌘0)")`. No new words in this file.
  - `SettingsView.swift`, `ProxySettings`: the `if usesEmbedded, let bound = …, Self.port(from: bound) != port { LabeledContent("Bound address", value: bound) }`
    block (lines 200-203 today) is replaced by a block shown when `session.coreHealth.connection?.portFallback` is
    non-nil: `Text(fallback.notice)` with `.font(.callout)` and `.foregroundStyle(.secondary)` and
    `Button(fallback.restartTitle) { session.restartCoreTick += 1 }` (plain `Button`, same action as "Apply and
    Restart Core"). `LabeledContent`, an `HStack` or two rows: builder's choice within the section's style. The
    now-unused `private static func port(from:)` is deleted (its only caller was the removed row). The footnote's
    last sentence changes from `If the chosen port is taken, the core picks a free one, shown above as the bound address.`
    to `If the chosen port is taken, the core picks a free one and says so above.`; the first sentence of that
    footnote and the external-core alternative are unchanged. No `"Port ` or `was busy` literal anywhere in the
    file (doc comments included; keep them to "the notice" / "the fallback").
  - `ShellView.swift`, line 254: `EmptyFlows(filtered: …, listen: session.effectiveListenAddress, …)` replaces
    `listen: session.listenAddress`. Nothing else in the file changes.
  - `BusService.swift`, `refreshProxyStatus()`: after the `decrypt` write and before the `system_proxy` parse, read
    `status["address"]?.stringValue`; when it is non-empty and differs from `session.listenAddress`, assign it
    (change-guarded like the neighbours, so an `@Observable` set does not fire on equal values). The doc comment
    on the method gains one sentence naming the write (spec D6) and the order reason (so
    `effectiveListenAddress` is fresh for the facts parse on the same tick). `listenAddress()` at line 597 and the
    connect-time write at line 142 are unchanged.
  - `apps/mac/CLAUDE.md`, Layout: one bullet after the `Quit.swift` line, e.g.
    a bullet naming `Sources/AitmproxyKit/ListenPortFallback.swift` as the listen-port fallback fact, derived by
    `CoreConnection.portFallback` and printed by `ConnectionSummary` as one sentence on every surface that names the
    listener. Builder's wording; one line.
  - Watch `tools/check-connection-words.sh` rule 1: it excludes only lines that begin with `//`; a trailing
    comment such as `// word "running"` on a code line in `Sources/Aitmproxy` would trip it.
- **Test (write first, run red, then green):** new file `ListenPortFallbackTripwireTests.swift`, the
  `QuitRoutesTests` style (`#filePath` three levels up to `apps/mac`, `String(contentsOf:encoding:)`, `contains`),
  doc comment stating it is a source pin and the live proof (spec D10) is the behaviour test:
  - `settingsProxyPrintsTheKitWordsAndOffersTheRestart`: `Sources/Aitmproxy/SettingsView.swift` contains
    `portFallback` and `restartTitle`; does not contain `"Bound address"`, `"Port `, `was busy`, or
    `shown above as the bound address`; contains `picks a free one and says so above.` (plan call: the D5 footnote
    literal is pinned too).
  - `theToolbarPillReadsCoreAddressShown`: `Sources/Aitmproxy/Shell/ShellToolbar.swift` contains
    `coreAddressShown`; does not contain `summary.core.state == .ok` (plan call: the replaced condition must not
    survive beside the new one), `"Port `, or `was busy`.
  - `theFlowsEmptyStateQuotesTheEffectiveAddress`: `Sources/Aitmproxy/Shell/ShellView.swift` contains
    `listen: session.effectiveListenAddress` and does not contain `listen: session.listenAddress`.
  - `theProxyStatusPollWritesTheBoundAddress`: `Sources/Aitmproxy/Bus/BusService.swift` contains
    `status["address"]`.
  - Red run against the Task 2 tree: all four tests fail (each named literal absent or present the wrong way);
    quote `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build-port-fallback --filter ListenPortFallbackTripwireTests`.
    Green run: the same command, four passes.
- **Gate for this task (all in the Terminal, from `WT/apps/mac`; quote exit status and last lines of each):**
  1. `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build-port-fallback` (unfiltered; every suite
     green, including `QuitRoutesTests`, `CoreConnectionTests`, `ConnectionSummaryTests`).
  2. `tools/check-connection-words.sh`, `tools/grid-lint.sh`, `tools/check-capture-operator-only.sh`,
     `tools/check-capture-toggle.sh`: each prints its PASS line and exits 0.
  3. `swift build --scratch-path ~/Library/Developer/Aitmproxy/test-build-port-fallback` (the app target compiles;
     no new warnings in the touched files).
- **Done when:** the tripwire run, the unfiltered run, the four scripts and the build are all quoted green; the
  commit touches exactly the six files above; `git diff --stat BASE..HEAD` over the three commits lists only the
  AC12 files (`ListenPortFallback.swift`, `CoreConnection.swift`, `ConnectionSummary.swift`, `ShellToolbar.swift`,
  `ShellView.swift`, `SettingsView.swift`, `BusService.swift`, the three test files, `apps/mac/CLAUDE.md`, the spec
  and this plan) and nothing under `crates/`, `tests/e2e/`, `App.swift`, `EmbeddedCore.swift`,
  `EmbeddedCoreController.swift` or `tools/check-connection-words.sh`.

## Independence

None of the three tasks is independent; the order is 1 → 2 → 3. The Rust gate
(`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`) is run once by the orchestrating
session on the whole branch before integration (no Rust changes; it is the standing rule).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

Filled at stage 7 by the orchestrating session.

**What merged.** (branch, PR number, merge SHA; the Kit fact, the summary members, the four app surfaces, the
tripwire, the layout line.)

**What was cut.** (anything dropped from the spec during review.)

**Evidence.** (the `swift test` totals, the four tripwire exits, the live-proof matrix for AC7-AC11 with the 18090
adaptation noted, the AC6 negative control, the AC12 diff-stat, the Rust gate exit.)

**Follow-ups.** (candidates: the step `detail` is a help attribute only, so a visible one-line notice on the Status
page's step row could be a later UX call; the pending-edit Settings row dropped by D5.)
