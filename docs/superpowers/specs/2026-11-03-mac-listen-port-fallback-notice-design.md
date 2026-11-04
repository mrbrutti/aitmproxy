# macOS app: listen-port fallback notice design

**Status:** approved (2026-11-03 by the orchestrating session under Matt's standing autonomous-approve mode)
**Research inputs:** the facts note `mac-port-fallback-FACTS.md` (side-session notes `local_75059306-ee27-4e35-9526-25f7809380be`, 2026-11-03; every path and line verified on `main` at 1e891779) and the incident it cites, `docs/testing/2026-11-03-release-acceptance-0.5.18/README.md` ("Incident: the harness took 8080 from the operator's core"). Source re-read for this spec: `apps/mac/Sources/AitmproxyKit/CoreConnection.swift` (`proxyAddress`, `appliedPort`), `ConnectionSummary.swift:286-289,359-389,650-715` (`tooltip`, `coreLane`, `steps`), `apps/mac/Sources/Aitmproxy/Shell/ShellToolbar.swift:60-100` (`ListeningPill`), `SettingsView.swift:167-205,262-268,278-280` (`ProxySettings`, the footnote, `port(from:)`), `Shell/ShellView.swift:254,321-339` (`EmptyFlows`), `Bus/BusService.swift:376-399,596-607` (`refreshProxyStatus`, `listenAddress()`), `Session.swift:181`, `Session+SystemProxy.swift:36,106-118`, `Session+Connection.swift:14-33`, `Bus/EmbeddedCoreController.swift:115-143`, `UI/ConnectionLook.swift:6-13`, `tools/check-connection-words.sh`, `tests/e2e/acceptance/test_mac_journey.py:240-270,487-509`.

## Intent

When the preferred listen port (8080 by default) is busy at launch or at Restart Core, `EmbeddedCore.spawn()` picks a free port and the core comes up there. The app then shows only a different number in the toolbar pill: nothing says 8080 was busy, Settings ▸ Proxy shows a bare "Bound address" row with no action, the Flows empty state and `Session.listenAddress` can still say 8080 (read from the operator's `config.yaml` on disk, not from the running core), and a system proxy a previous core set at 8080 is left pointing at a dead port with no word about why. In the 0.5.18 acceptance run the operator saw nothing until a hand killed the stray process and pressed Restart Core again. This change makes the fallback a stated fact, in one sentence, everywhere the app shows the listener, with the one action that fixes it.

## Goals

- One sentence, exactly `Port 8080 was busy; listening on 8081` (numbers interpolated), defined once in `AitmproxyKit` and printed verbatim by every surface that names the fallback: the core lane's remedy (Status page card), the toolbar pill's tooltip, Settings ▸ Proxy, and the Getting Started `coreRunning` step's detail.
- The toolbar pill keeps showing the bound address while falling back, with the warning colour on its dot.
- Settings ▸ Proxy offers a button, `Restart on 8080` (number interpolated), that restarts the embedded core so it tries the preferred port again.
- `Session.listenAddress` is the running core's truth (`proxy.status.address`), for the embedded and the external core alike; the Flows empty state quotes the effective address.
- The fix is in `apps/mac` only; the lane word `running` and the acceptance literals are untouched.

## Non-goals

- No new Rust and no bus change: `proxy.status.address` already carries the bound address and `proxy.system.set` already writes the core's own listen port (`ours_from(listen)`, `crates/aitm-sysproxy/src/lib.rs:383-395`).
- No change to how the port is picked (`pickProxyPort`), to the crash-restart re-pick, or to the per-launch config.
- No change to the system-proxy route words or to `managed_by_us` for a system proxy left at the old port by a previous core instance: after a restart-time fallback the route line reads the core's own `proxy.status.system_proxy` as today; this change explains the move through the core lane and shows the port a Set as System Proxy would write.
- No change to the acceptance harness (`tests/e2e/acceptance`), to `check-connection-words.sh`'s rules, or to the Proxy menu (D8).
- No new app-target test (the executable has none); everything under `swift test` lives in `Tests/AitmproxyKitTests`.

## Anti-goals

- Changing the core lane word `running` while falling back: MAC-1 pins it in the lane dump.
- An alert, a modal, a sheet, or a beep for the fallback.
- Killing or naming the process that holds the preferred port.
- Changing the Rust core, the bus verbs, or the per-launch config.
- A view that composes its own fallback words (a `"Port "` or `"was busy"` literal in `Sources/Aitmproxy`).
- Touching the installed `Aitmproxy.app`, the operator's defaults, or the operator's Application Support store while proving this; calling `proxy.system.set` from the proof (it changes Matt's Mac).
- Printing the bus or operator token anywhere while proving this.

## Constraints

- `AitmproxyKit` is SwiftUI-free and the only allowed home for connection words; `tools/check-connection-words.sh` forbids lane-word literals in `Sources/Aitmproxy` and limits `connectionSummary` readers to `Shell/ShellToolbar`, `Shell/SetupSheet`, `Panels/StatusPanel`, `Panels/CoreLogPanel`, `SettingsView`, `Session+Connection`. The new surfaces are all already in that list; the allow-list does not grow.
- `CoreConnection` already holds both numbers: `appliedPort` (the preferred port, snapshotted from `proxy.preferredPort` at `.ready`) and `proxyAddress` (`"127.0.0.1:<bound>"`). Both are nil for a non-embedded core and until ready.
- `LaneState` is ordered `ok < working < off < warning < error`; a `.warning` core lane becomes `ConnectionSummary.worst` when the other lanes are ok. The compact surfaces that print `worst.compact` then read `core: running` with a warning dot; accepted.
- Acceptance literals that must survive: MAC-1 `running`, `connected`, `operator ·` in the Status dump; MAC-13 `Embedded core failed` absent; MAC-3 `system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.` and `All Apps is on`; the Kit pins `Core is running` and `Core: running — Embedded · proxy 127.0.0.1:8080` (ConnectionSummaryTests 235, 1195) stay true when there is no fallback.
- `swift test`, `snap-dev.sh`, System Events and the bus reads run in the Terminal panel, not the Bash sandbox. Dev bundles share the installed bundle id: drive by process name `Aitmproxy-<tag>`, never `tell application id`.

## Design

### D1. The fact: `ListenPortFallback` in Kit (decided)

New file `apps/mac/Sources/AitmproxyKit/ListenPortFallback.swift`:

```swift
public struct ListenPortFallback: Hashable, Sendable {
    public let preferred: Int
    public let bound: Int
    public init(preferred: Int, bound: Int)
    public var notice: String        // "Port 8080 was busy; listening on 8081"
    public var restartTitle: String  // "Restart on 8080"
    public var remedy: String        // "Port 8080 was busy; listening on 8081 — Restart Core tries 8080 again"
}
```

`notice` is the one sentence (no trailing full stop, like every lane remedy). `restartTitle` is the Settings button's title, in title case like `ConnectionAction.title`, so the view composes no words **(Architect's call)**. `remedy` is the notice, the route-line separator ` — `, and the clause that says what the lane's primary action does; it is the core lane's remedy and nothing else prints it **(Architect's call on the clause words)**.

### D2. `CoreConnection.portFallback` (decided)

In `CoreConnection.swift`:

```swift
public var portFallback: ListenPortFallback?
```

Non-nil only when all hold: `kind == .embedded`, `status == .ready`, `appliedPort != nil`, `proxyAddress` ends in `:<Int>` (the port after the last colon, the same parse as `SettingsView.port(from:)`), and the two ports differ. Any unknown (nil `appliedPort`, nil or unparseable `proxyAddress`), a non-embedded kind, or a non-ready status gives nil. It is a computed property on the value, so a crash-restart's fresh `.ready` (which re-picks the port) recomputes it, and a successful Restart Core on the preferred port clears it.

### D3. `ConnectionSummary` carries the fact; the core lane warns (decided)

- `ConnectionSummary` gains `public let portFallback: ListenPortFallback?`, set by `make` to `connection?.portFallback` when `activeKind == .embedded`, else nil. No new `make` parameter.
- `coreLane`, case `.ready`, when `connection.portFallback` is non-nil: `ConnectionLane(kind: .core, state: .warning, word: "running", detail: "Embedded · proxy 127.0.0.1:8081", remedy: fallback.remedy, actions: [.restartCore, .showCoreLog])`. Word, detail and actions are exactly today's; only `state` and `remedy` change. Without a fallback the `.ready` lane is byte-identical to today (`.ok`, no remedy).
- `tooltip` gains a fourth line, `fallback.notice`, after the three lane lines, only when `portFallback` is non-nil **(Architect's call: the pill's tooltip is the only place the pill can say why its dot is amber without growing the pill)**.
- `public var coreAddressShown: Bool { core.state == .ok || portFallback != nil }`: the pill's condition for drawing the address, so the decision is in Kit and pinned **(Architect's call)**.
- Getting Started: the `coreRunning` step keeps `title: "Core is running"` and `done: true` (the core is running); its `detail` becomes `fallback.notice` when falling back, else nil as today **(Architect's call: the title is a Kit pin and the step is true; the detail slot already exists for the route steps)**.

### D4. The toolbar pill (decided)

`ListeningPill`: the branch that draws ` · ` / ` · paused `, the address and ` · intercept armed` is taken when `summary.coreAddressShown` (today `summary.core.state == .ok`); the `else` branch (` · core <word>`) is unchanged for every other state. The address text stays `session.coreHealth.connection?.proxyAddress ?? session.listenAddress`. The dot already uses `summary.core.state.color`, so it takes `Tok.State.warning.fg` by itself. `.help` stays `summary.tooltip + "\nOpens Status (⌘0)"`, which now carries the notice.

### D5. Settings ▸ Proxy (decided)

`ProxySettings`: the `LabeledContent("Bound address", value:)` row and its view-side port compare are replaced by a row shown when `session.coreHealth.connection?.portFallback` is non-nil: `Text(fallback.notice)` in the section's secondary style and `Button(fallback.restartTitle) { session.restartCoreTick += 1 }`. The pending-edit case the old row also covered (the field differs from the applied port) is already served by `canApply` enabling "Apply and Restart Core"; it no longer shows a row **(Architect's call)**. The footnote under Apply and Restart Core changes its last sentence from `If the chosen port is taken, the core picks a free one, shown above as the bound address.` to `If the chosen port is taken, the core picks a free one and says so above.` **(Architect's call on words)**. The section's `.disabled(!usesEmbedded)` stays; `portFallback` is nil for a non-embedded core anyway.

### D6. `Session.listenAddress` is the running core's truth (decided)

`BusService.refreshProxyStatus()` reads `status["address"]?.stringValue` on every poll and, when it is a non-empty string that differs from `session.listenAddress`, writes it (change-guarded like the other per-tick writes), before the `system_proxy` facts parse so `effectiveListenAddress` is fresh on the same tick **(Architect's call on the order)**. `BusService.listenAddress()` (the `config.yaml` read on connect) stays as the pre-poll default. `ShellView` passes `listen: session.effectiveListenAddress` to `EmptyFlows` instead of `session.listenAddress`. An external core thus reports whatever it bound; the embedded core's value equals `proxyAddress`.

### D7. What Set as System Proxy writes (decided; no code)

`proxy.system.set` takes only `bypass`; the core writes `ours_from(listen)`, host `127.0.0.1` and its own bound port. The app sends no address. Its job is to show the port that will be written, and every surface that quotes an address for that purpose (the system-proxy route line, the facts parser, the Getting Started last step, the Flows empty state after D6) reads `effectiveListenAddress`, which is the bound address. This holds after the fix for both a launch-time and a restart-time fallback: `proxyAddress` is set from the `.ready` runtime each time.

### D8. The Proxy menu is left alone (Architect's call)

The menu shows no address today, every action here already has its menu item (Restart Core, ⌃⇧⌘R), and a disabled info item would be the only piece of state text in any of the app's menus. The brief's "wherever the app shows the listener" is satisfied by the pill, Status, Settings and Flows.

### D9. Tests (decided)

Kit-only, `swift test`:

- `CoreConnectionTests`: `portFallback` is `ListenPortFallback(preferred: 8080, bound: 8081)` for an embedded, ready connection with `appliedPort: 8080`, `proxyAddress: "127.0.0.1:8081"`; nil when the ports match, when `appliedPort` is nil, when `proxyAddress` is nil or has no port, when `kind == .external`, and when `status` is `.starting` or `.degraded`. `notice == "Port 8080 was busy; listening on 8081"`, `restartTitle == "Restart on 8080"`, `remedy == "Port 8080 was busy; listening on 8081 — Restart Core tries 8080 again"`.
- `ConnectionSummaryTests`: with the fallback connection, `core.state == .warning`, `core.word == "running"`, `core.detail == "Embedded · proxy 127.0.0.1:8081"`, `core.remedy == <remedy literal>`, `core.actions == [.restartCore, .showCoreLog]`, `coreAddressShown == true`, `tooltip` ends with `"\nPort 8080 was busy; listening on 8081"`, the `coreRunning` step is `done` with `title == "Core is running"` and `detail == <notice literal>`; without the fallback the `.ready` lane is `.ok` with `remedy == nil`, `portFallback == nil`, `coreAddressShown == true`, the tooltip has three lines, and the step's `detail == nil`; for an external active kind `portFallback == nil`.
- Tripwire, new file `Tests/AitmproxyKitTests/ListenPortFallbackTripwireTests.swift` (the `QuitRoutesTests` style, `#filePath` + `contains`): `Sources/Aitmproxy/SettingsView.swift` contains `portFallback` and `restartTitle` and does not contain `"Bound address"`; neither `SettingsView.swift` nor `Shell/ShellToolbar.swift` contains `"Port ` or `was busy`; `Shell/ShellToolbar.swift` contains `coreAddressShown`; `Shell/ShellView.swift` contains `listen: session.effectiveListenAddress` and not `listen: session.listenAddress`; `Bus/BusService.swift` contains `status["address"]` **(Architect's call: a source pin, not a behaviour test; the live proof is the behaviour test)**.

### D10. The live proof (owned by the orchestrating session; decided)

A dev bundle (`DEV_TAG=<tag> CORE_DIR=<dir> apps/mac/tools/snap-dev.sh`, isolated `APP_STORE=/tmp/Aitmproxy-dev-state-<tag>`, a named `APP_DEFAULTS_SUITE` seeded with `systemProxy.promptSuppressed` true so no Setup sheet opens), the operator token read from the 0600 per-launch config under the store and never echoed, the UI read through System Events by process name `Aitmproxy-<tag>`, the bus read with a loopback client calling `proxy.status` and `proxy.system.status` only. Cases and readings are AC7-AC10.

## Acceptance criteria

1. AC1 (the fact): `CoreConnection(kind: .embedded, …, status: .ready, proxyAddress: "127.0.0.1:8081", appliedPort: 8080).portFallback == ListenPortFallback(preferred: 8080, bound: 8081)`; the same with `proxyAddress: "127.0.0.1:8080"`, with `appliedPort: nil`, with `proxyAddress: nil`, with `proxyAddress: "127.0.0.1"`, with `kind: .external`, with `status: .starting`, and with `status: .degraded(reason: "x")` each gives nil. (Kit test.)
2. AC2 (the words): `ListenPortFallback(preferred: 8080, bound: 8081)` has `notice == "Port 8080 was busy; listening on 8081"`, `restartTitle == "Restart on 8080"`, `remedy == "Port 8080 was busy; listening on 8081 — Restart Core tries 8080 again"`. (Kit test.)
3. AC3 (the core lane): `ConnectionSummary.make(core: <fallback connection>, activeKind: .embedded, …)` gives `core == ConnectionLane(kind: .core, state: .warning, word: "running", detail: "Embedded · proxy 127.0.0.1:8081", remedy: <AC2 remedy>, actions: [.restartCore, .showCoreLog])`, `portFallback != nil`, `coreAddressShown == true`, and `tooltip.hasSuffix("\nPort 8080 was busy; listening on 8081")`. With `activeKind: .external` and the same connection, `portFallback == nil`. (Kit test.)
4. AC4 (no regression without a fallback): with `proxyAddress: "127.0.0.1:8080", appliedPort: 8080`, the core lane equals today's `.ready` lane (`state: .ok`, `word: "running"`, `detail: "Embedded · proxy 127.0.0.1:8080"`, `remedy: nil`, `actions: [.restartCore, .showCoreLog]`), `portFallback == nil`, `coreAddressShown == true`, `tooltip` has exactly three lines, and the existing pins at ConnectionSummaryTests 71-73, 235 and 1195 still pass unchanged. (Kit test.)
5. AC5 (the step): with the fallback connection the `coreRunning` step has `done == true`, `title == "Core is running"`, `detail == "Port 8080 was busy; listening on 8081"`; without it, `detail == nil`. (Kit test.)
6. AC6 (source pins): the tripwire in D9 passes; `tools/check-connection-words.sh`, `tools/grid-lint.sh`, `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh` exit 0; `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` passes. Negative control, run once and reverted by the orchestrating session: restoring the literal `"Bound address"` in `SettingsView.swift` makes the tripwire fail.
7. AC7 (launch-time fallback, live): with `python3 -m http.server 8080 --bind 127.0.0.1` running, the dev bundle launches and over the bus `proxy.status.address` is `127.0.0.1:<p>` with `<p> != 8080`, and `proxy.system.status.ours` is `{host: "127.0.0.1", port: <p>}` (the port Set as System Proxy would write; the verb is not called). System Events: the toolbar pill's text contains `127.0.0.1:<p>` and does not contain `core running`; the pill's help contains `Port 8080 was busy; listening on <p>`; after Proxy ▸ Status, the window's AX dump contains `running`, `Embedded · proxy 127.0.0.1:<p>` and `Port 8080 was busy; listening on <p> — Restart Core tries 8080 again`, and does not contain `Embedded core failed`; Settings ▸ Proxy shows a static text `Port 8080 was busy; listening on <p>` and a button `Restart on 8080`, and no text `Bound address`; the Flows page with zero rows shows `Point a client at 127.0.0.1:<p> or open the browser.`. No alert or sheet window exists for the process.
8. AC8 (the remedy works, live): after killing the `http.server` holder, pressing `Restart on 8080` in Settings ▸ Proxy brings a new core up with `proxy.status.address == "127.0.0.1:8080"`, `proxy.system.status.ours.port == 8080`; the pill shows `127.0.0.1:8080`; the Status dump contains `running` and does not contain `was busy`; Settings ▸ Proxy shows neither the sentence nor the `Restart on 8080` button; the Flows empty state says `127.0.0.1:8080`.
9. AC9 (restart-time fallback, live): with the core on 8080, start a holder that retries the bind (`until python3 -m http.server 8080 --bind 127.0.0.1; do sleep 0.1; done`), then Proxy ▸ Restart Core (⌃⇧⌘R). The new core reports `proxy.status.address == "127.0.0.1:<q>"`, `<q> != 8080`, and the AC7 readings (pill, tooltip, Status, Settings, Flows) hold with `<q>`. If the holder loses the bind race the run is repeated, not counted. Then AC8 again with this holder.
10. AC10 (the external core path, live): with the dev bundle switched to an external core (Settings ▸ Bus) started by hand on `127.0.0.1:18080`, the Flows empty state and the Getting Started last step quote `127.0.0.1:18080` within one poll, without an `AITM_CONFIG` pointing at that core's config; the core lane is `external` and `portFallback` surfaces nothing (no `was busy` in the dump).
11. AC11 (environment): throughout AC7-AC10 the installed `Aitmproxy.app` bundles' mtimes, `defaults read com.mrbrutti.aitmproxy` and `~/Library/Application Support/Aitmproxy` are unchanged (checked before and after), `scutil --proxy` is unchanged, `proxy.system.set` is never called, and no token appears in any saved log or dump.
12. AC12 (scope of the diff): `git diff --stat BASE..HEAD` touches only `apps/mac/Sources/AitmproxyKit/ListenPortFallback.swift` (new), `CoreConnection.swift`, `ConnectionSummary.swift`, `apps/mac/Sources/Aitmproxy/Shell/ShellToolbar.swift`, `Shell/ShellView.swift`, `SettingsView.swift`, `Bus/BusService.swift`, the three test files in D9, `apps/mac/CLAUDE.md` (one layout line), the spec and the plan. `crates/`, `tests/e2e/`, `App.swift`, `EmbeddedCore.swift`, `EmbeddedCoreController.swift` and `tools/check-connection-words.sh` are unchanged.

## Left to the builder

- Whether the port parse in `portFallback` is a private helper on `CoreConnection` or a static on `ListenPortFallback`; it must accept `"127.0.0.1:8081"` and reject `"127.0.0.1"`.
- The doc comments (they should cite this spec and the 0.5.18 incident line).
- The order of the `portFallback` and `coreAddressShown` members in `ConnectionSummary` and the `init` parameter default for `portFallback` (nil) so existing call sites and tests compile unchanged.
- Whether the Settings row is a `LabeledContent`, an `HStack`, or two rows, within the section's existing style (`.font(.callout)`, `.foregroundStyle(.secondary)` for the text; a plain `Button` for the action).
- How `ListenPortFallbackTripwireTests` counts and reads files (`String(contentsOf:encoding:)` + `contains` is enough).
- The one-line mention of `ListenPortFallback.swift` in `apps/mac/CLAUDE.md`'s Layout section.

## Open questions

None.

## Summary

The embedded core's silent fallback port becomes a stated fact derived once in Kit: `CoreConnection.portFallback`, a `ListenPortFallback { preferred, bound }` that is nil unless an embedded, ready core bound a port other than its applied preferred port, with the one sentence `Port 8080 was busy; listening on 8081`. `ConnectionSummary` carries it, turns the core lane `.warning` while keeping the word `running`, puts the sentence and "Restart Core tries 8080 again" in the lane's remedy, adds the sentence to the tooltip and the `coreRunning` step's detail, and exposes `coreAddressShown` so the pill keeps the bound address with an amber dot. Settings ▸ Proxy replaces the bare "Bound address" row with the sentence and a `Restart on 8080` button; `BusService` writes `proxy.status.address` into `Session.listenAddress` each poll so the Flows empty state and an external core quote what is actually bound. No Rust, no menu change, no alert; Kit tests pin the literals and a tripwire pins the view wiring; the live proof holds 8080 with `http.server` on a dev bundle and reads the bus and System Events only.

### Architect's calls

1. `ListenPortFallback` carries three strings: `notice`, `restartTitle` ("Restart on 8080"), and `remedy` = notice + ` — Restart Core tries 8080 again`; views compose no words.
2. The tooltip gains a fourth line (the notice) only when falling back, rather than widening the pill.
3. `ConnectionSummary.coreAddressShown` decides the pill's address branch in Kit (`core.state == .ok || portFallback != nil`).
4. The `coreRunning` step keeps its title `Core is running` and `done`; the notice goes in its `detail`.
5. Settings: the pending-edit case the old "Bound address" row also covered is dropped (Apply and Restart Core already lights up for it); the footnote's last sentence becomes "…picks a free one and says so above."
6. `refreshProxyStatus()` writes `listenAddress` before the `system_proxy` facts parse so `effectiveListenAddress` is fresh on the same tick.
7. The Proxy menu is left alone (no address there today; Restart Core already has its item).
8. The view wiring is guarded by a source tripwire test (`ListenPortFallbackTripwireTests`), stated as a pin, not a behaviour test.
9. The restart-time case is proven with a bind-retry holder started before Restart Core; a lost race is re-run, not counted.
10. AC10 proves D6 on an external core started by hand on 18080, so the "truth from the running core" claim is not embedded-only.
