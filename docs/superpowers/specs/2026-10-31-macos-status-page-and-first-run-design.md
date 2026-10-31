# macOS Status page and first-run flow design

**Status:** draft (2026-10-31, mac-review session; for the NE session + orchestrator to review, Matt approves)
**Research inputs:** `apps/mac/docs/review-2026-10-31.md` (live findings L1–L9), PR #181 spec
`2026-10-31-ne-no-scope-honest-state-design.md` (`CaptureAdvice`), the bama `mac-design`
(rules 3, 5, 27, 28, 56, 59, 64, 76) and `ux-design` (surface table, states, words) skills.

## Intent

On a fresh launch the operator cannot tell what is running and what to do first. The sidebar
lands on Apps (an empty or misleading page), and the three things that decide whether anything
will ever appear — the **core** (the proxy process), the **bus** (the app's link to it) and the
**capture extension** (system-wide capture) — are reported in three unrelated places with three
vocabularies: a toolbar pill (core port), two status-bar dots (core health, bus address, role)
and a Settings tab (extension). None of them says what to do next, and the enable/disable
controls are split between Settings tabs and menu items. Matt's words: "when we start it is not
clear on the sidebar what option the user needs to look at … expose the Core Bus and NE in the
UI so show them when it is active and when not, to enable / disable it."

This design adds one **Status** page that is the first thing a new session shows, feeds every
connection indicator from one pure model, and puts the enable/disable controls on the page that
shows the state.

## Goals

- A fresh launch answers "where am I, what can I do, where do I go" in one screen: the Status
  page shows the three lanes (Core, Bus, Capture), each with a state word, one fact, and its
  action; a **Getting started** list ticks off the steps that are already true.
- Every connection indicator (toolbar pill, status bar, sidebar row, Status page, Settings
  rows) draws its words from one `ConnectionSummary` so they never disagree (the B10 class of
  bug is closed by construction, not by review).
- Enable/disable lives where the state is shown: Start/Stop/Restart Core, Reconnect Bus,
  Capture on/off, Open Scope, Install/Uninstall extension — on the Status page, each a plain
  button with its menu-bar twin.
- "Not working" states are loud and specific: a failed core, a bus that rejected the token, an
  extension awaiting approval, capture on with an empty scope, an unnotarized build whose
  extension can never activate — each names the one thing that fixes it.
- Returning operators keep their place: the last page is restored; the Status page is the
  landing page only while the session has nothing to show yet.

## Non-goals

- No onboarding tour, splash, or wizard (rule 76). The Getting started list is live state, not
  a sequence the operator is pushed through, and it stays useful after first run.
- No new bus verbs. Scope persistence across core restarts (live finding: the scope is lost on
  every restart) is a core/orchestrator item; the Status page only shows the count honestly.
- No change to Settings ▸ Capture's toggle semantics or to `CaptureSwitch`/`ExtensionController`
  (operator-only, serialized); the Status page calls the same `CaptureSwitch` steps.
- Source-app attribution on the wire (the NE session's v0.5.4 spec).
- TUI and web: the model is Kit-only here; the words are written so the TUI/web can adopt them.

## Anti-goals

- A fourth indicator with a fourth vocabulary. If a surface cannot read `ConnectionSummary`, it
  does not show connection state.
- A green dot that lies: "Capturing" while the scope is empty, "listening" while the core
  failed, "connected" with the wrong role. Each lane's `state` must be derived from the
  published facts (`CoreConnection.Status`, `BusState`, `CaptureAdvice`), never from a
  preference key.
- Hiding flows behind a state page: the Status page never replaces the flow list; captured
  flows stay one click away and the Status page links to them.

## Constraints

- Swift 6 main-actor default isolation; Kit types are `Sendable` values with no SwiftUI.
- House style: flat monochrome SF Symbols, editorial hierarchy (tracked small-caps section
  labels, 20 pt document title), hue only on data; status colour is always paired with a word
  (rule 28). Spacing from `Space`; `.gridArea`/`.gridProbe` on the page and its cards.
- The capture controls stay operator-only: `tools/check-capture-operator-only.sh` and
  `check-capture-toggle.sh` must keep passing; no bus/MCP/agent path reaches `CaptureSwitch`.
- Settings stay preferences (settings.md): Bus tab keeps the external address/token; Capture tab
  keeps its toggle and uninstall. The Status page is the live control surface; the two must
  read the same `ConnectionSummary` words.
- File ownership while PR #181 is open: `ShellView.swift`, `SettingsView.swift`,
  `Bus/ExtensionController.swift`, `Bus/CoreHealthState.swift`, `Capture*` belong to the NE
  session; this design needs exactly one line in `ShellView.content` (`case .status:`) and
  nothing in the others.

## Design

### 1. One model: `ConnectionSummary` (Kit, pure, tested)

```swift
public enum LaneState: Sendable { case ok, working, warning, off, error }

public struct ConnectionLane: Equatable, Sendable {
    public enum Kind: Sendable { case core, bus, capture }
    public let kind: Kind
    public let state: LaneState
    /// The one word for the sidebar/status bar: "running", "connecting…", "capture on" …
    public let word: String
    /// The fact under it: "Embedded · proxy 127.0.0.1:8080", "operator · 127.0.0.1:60745",
    /// "3 hosts in scope".
    public let detail: String
    /// What fixes it when state is not .ok, as a sentence ("Restart the core", "Paste the
    /// operator token in Settings ▸ Bus", "Add a host to Scope"), nil when nothing is needed.
    public let remedy: String?
    /// The actions the surface may offer, in order; the first is primary.
    public let actions: [ConnectionAction]
}

public enum ConnectionAction: Equatable, Sendable {
    case startCore, stopCore, restartCore, showCoreLog, switchCore
    case reconnectBus, openBusSettings
    case captureOn, captureOff, openScope, approveInSystemSettings, uninstallExtension, openCaptureSettings
    case openBrowser, copyListenAddress
}

public struct ConnectionSummary: Equatable, Sendable {
    public let core: ConnectionLane
    public let bus: ConnectionLane
    public let capture: ConnectionLane
    /// Worst lane state, for the sidebar's Status row glyph and the toolbar pill's dot.
    public var overall: LaneState
    /// Getting-started steps with their done flag, in order.
    public let steps: [GettingStartedStep]

    public static func make(core: CoreConnection?, activeKind: ActiveCoreKind, bus: BusState,
                            role: String?, roleWarning: Bool, capture: CaptureAdvice,
                            captureSupported: Bool, scopeHostCount: Int, flowCount: Int,
                            listenAddress: String) -> ConnectionSummary
}

public struct GettingStartedStep: Equatable, Sendable {
    public enum Kind: Sendable { case coreRunning, busConnected, extensionOn, scopeSet, firstFlow }
    public let kind: Kind
    public let title: String      // "Core is running", "Install the capture extension", …
    public let done: Bool
    public let action: ConnectionAction?
}
```

Word table (the only place these strings live; the TUI/web may copy it):

| Lane | Facts | state | word | remedy |
|---|---|---|---|---|
| Core | embedded `.ready` | ok | running | — |
| Core | `.starting`/`.connecting` | working | starting… | — |
| Core | `.degraded(reason)` / `.stopped` | error | failed | "Restart the core" (reason as detail) |
| Core | external kind, no connection | off | external | "Configure the address in Settings ▸ Bus" |
| Bus | `.connected`, role ok | ok | connected | — |
| Bus | `.connected`, roleWarning | warning | connected as agent | "Paste the operator token in Settings ▸ Bus" |
| Bus | `.connecting` | working | connecting… | — |
| Bus | `.failed(why)` | error | bus failed | why |
| Bus | `.disconnected` | off | offline | "Start the core" / "Reconnect" |
| Capture | `.unsupported` | off | no extension | "This build has no capture extension; the signed app has it" |
| Capture | `.off` | off | capture off | "Turn on capture to see other apps' traffic" |
| Capture | `.awaitingApproval` | working | waiting for approval | "Approve the extension in System Settings" |
| Capture | `.degraded(reason)` | error | capture degraded | reason |
| Capture | `.onEmptyScope` | warning | on, nothing in scope | "Add a host to Scope" |
| Capture | `.on(n)` | ok | capture on · n hosts | — |

`CaptureAdvice` (PR #181) stays the capture source; `ConnectionSummary.make` maps it so the
advice's headline/detail and the lane word agree (the lane word is a shortened form; a Kit test
pins each pair).

### 2. The Status page (`Panels/StatusPanel.swift`, sidebar page `.status`)

Surface (ux-design table): a sidebar page — a place the operator comes back to.

```text
 STATUS                                                           [Open Browser] [Copy address]
 ─────────────────────────────────────────────────────────────────────────────────────────────
 CORE                        BUS                          CAPTURE
 ● running                   ● connected                  ◐ on, nothing in scope
 Embedded · 127.0.0.1:8080   operator · 127.0.0.1:60745   extension approved · 0 hosts
 [Restart Core] [Core Log…]  [Reconnect]                  [Turn Off] [Open Scope…] [⋯]
 ─────────────────────────────────────────────────────────────────────────────────────────────
 GETTING STARTED
 ✓ Core is running                                    127.0.0.1:8080
 ✓ Bus connected as operator
 ✓ Capture extension on
 ○ Add a host to Scope                                 [Open Scope…]
 ○ Point a client at 127.0.0.1:8080, or open the browser   [Open Browser]
 ─────────────────────────────────────────────────────────────────────────────────────────────
 RECENT                                               (last 5 flows, or "No flows yet")
```

- Three lane cards side by side (stack under 900 pt), each: a `Tok.Status`-coloured dot + the
  lane word (16/600), the detail in `Tok.Face.data`, the remedy in `Tok.Ink.secondary` when
  present, then the actions as `FlatButton`s (primary first). The `⋯` menu on Capture holds
  Uninstall Capture Extension… (destructive, confirmation dialog) and Open Settings ▸ Capture.
- Capture controls call `CaptureSwitch.set(_:session:)` / `.uninstall` exactly as Settings does
  and stand down on `captureBusy`; with an external core active the card says capture is the
  embedded core's and offers Switch to Embedded (→ Settings ▸ Bus) instead of the toggle.
- Getting started: five rows, each `✓` (done, `Tok.Status.success` + word) or `○` with its one
  action. Done rows stay (they are facts), so the list is a live checklist, not a tour. When all
  five are done the section collapses to one line: "Everything is connected — n flows captured".
- Recent: the last five flows as compact rows (method badge, URL, status) that select the flow
  and open the Domains page; "No flows yet" with the listen address otherwise.
- Empty/offline: when the bus is offline the Core and Capture cards still render their last
  known state and the Bus card carries the remedy; nothing on the page is blank.
- Keyboard: Proxy ▸ Status (⌘0) opens it; every card action is also a Proxy-menu item (Restart
  Core, Reconnect Bus, Enable/Disable Capture, Scope…, Core Log…, Browser) — all exist today.

### 3. Landing page and sidebar

- `SidebarPage.status` is the first row, in its own group **Proxy** above Working (noun, rule
  59); its trailing chip is the overall state glyph + word (`● running`, `◐ scope empty`,
  `✕ core failed`) in the lane's status colour, so the sidebar itself says when something is
  wrong (rule 56). No count.
- Landing (`Session.init`): the restored last page when the session had flows last time
  (`@SceneStorage("page")`); otherwise `.status`. A fresh install lands on Status; an operator
  mid-test lands where they left off. Apps stops being the default. **(Architect's call.)**
- The Apps and Domains rows keep their counts; the Status row never shows a count.

### 4. Toolbar pill and status bar read the same model

- `ListeningPill` becomes a `Button` to `.status` with three dots+words from the summary:
  `● core 8080 · ● bus · ◐ capture` (word only when not ok, to stay calm); `.help` lists all
  three lanes with their details. Intercept armed stays as today.
- The status bar's right group shows `core <word> · bus <word> · capture <word>` from the
  summary, each a `Button` to `.status` (the CoreHealthDot's click keeps opening the Core Log
  via the Status page card instead). Role mismatch is the bus lane's warning, not a fourth item.
- Settings ▸ Capture's Status row and Settings ▸ Bus's connection line read the lane words
  (NE session's files; one-line changes once #181 merges).

### 5. Words (GLOSSARY additions)

| Term | Means | Not |
|---|---|---|
| Status | The page that shows Core, Bus and Capture and what to do next | dashboard, home, overview (that is the traffic page) |
| Core | The aitm proxy process: embedded (the app runs it) or external (the operator runs it) | server, daemon, backend |
| Capture extension | The macOS system extension that captures other apps' traffic; on, off, waiting for approval, degraded | NE, sysext, network extension (in UI text) |
| Capture on / off | The operator's switch for the capture extension | enable/disable (buttons say Turn On / Turn Off) |
| Getting started | The Status page's live checklist | onboarding, wizard, tour |

Buttons: Turn On Capture, Turn Off Capture, Restart Core, Start Core, Stop Core, Reconnect,
Open Scope…, Core Log…, Open Browser, Copy Address, Uninstall Capture Extension…, Switch to
Embedded… (opens Settings ▸ Bus).

### 6. File split

| Piece | Files | Owner |
|---|---|---|
| `ConnectionSummary`, `ConnectionLane`, `GettingStartedStep` + tests | `AitmproxyKit/ConnectionSummary.swift`, `Tests/…/ConnectionSummaryTests.swift` | mac-review session |
| `StatusPanel` + its snapshot scenes (every lane state × light/dark) | `Panels/StatusPanel.swift`, `SnapshotScenes.swift`, `Snapshot.swift` | mac-review session |
| `SidebarPage.status` + landing rule | `Session.swift` | mac-review session |
| Sidebar Proxy group + Status row glyph | `Shell/SidebarView.swift` | mac-review session, after #181 |
| Pill + status bar from the summary | `Shell/ShellToolbar.swift`, `Shell/StatusBar.swift`, `Shell/CoreHealthDot.swift` | mac-review session |
| Proxy ▸ Status (⌘0) + CommandMap entry | `App.swift`, `AitmproxyKit/CommandMap.swift` | mac-review session (wave 3 touches App.swift's Flow menu only — coordinate) |
| `case .status: StatusPanel()` in `MainView.content` | `Shell/ShellView.swift` | NE session (one line in #181's follow-up) or mac-review after #181 |
| Settings rows reading lane words | `SettingsView.swift` | NE session |
| Glossary, brief IA line, docs | `apps/mac/docs/*` | mac-review session |

## Acceptance criteria

1. **ST-AC1 [kit-unit]** `ConnectionSummary.make` yields the word table above for every
   `CoreConnection.Status` × `ActiveCoreKind` × `BusState` × roleWarning × `CaptureAdvice`
   combination listed; `overall` is the worst lane; no lane word is "Capturing" while
   `scopeHostCount == 0`.
2. **ST-AC2 [kit-unit]** Getting-started steps are done exactly when the facts say so (core
   ready; bus connected without role warning; capture `.on`/`.onEmptyScope`; scope count > 0;
   flowCount > 0), and all-done collapses.
3. **ST-AC3 [mac-snapshot]** The Status page renders every lane state (15 scenes) in light and
   dark with no clipping; `grid-lint` and `check-layout` PASS; nothing on the page is blank when
   the bus is offline.
4. **ST-AC4 [self-test]** A fresh fixture session with `rows.isEmpty` lands on `.status`; a
   session restored with a saved page lands there; `Proxy ▸ Status` (⌘0) is in the menu bar and
   the `CommandMap`.
5. **ST-AC5 [structural]** The toolbar pill, status bar, sidebar Status row and Status page draw
   their words only from `ConnectionSummary` (grep: no other file defines core/bus/capture state
   words; the tripwire lists the allowed files). Both capture tripwires exit 0.
6. **ST-AC6 [self-test]** Each Status-page action calls the same `Session`/`CaptureSwitch` entry
   as its menu item (menu audit extended with Status's actions).
7. **ST-AC7 [manual, real app]** On Matt's Mac with the notarized DMG: fresh launch lands on
   Status; the three cards read the real state (core running on the bound port, bus connected
   as operator, capture state per the extension); turning capture off and on from the card
   changes Settings ▸ Capture and the sidebar glyph within one poll; adding a host from Open
   Scope… ticks the step; the first flow ticks the last step and Recent fills.
8. **ST-AC8 [manual]** A local unnotarized NE build shows the Capture card as `capture
   degraded` with the reason and the remedy "install the signed app"; nothing claims it works.

## Facts from the other sessions folded in (2026-10-31)

- **DNS black hole (NE session, live proof):** a bare hostname in Scope makes the provider claim
  the app's DNS datagram for that name and the core never answers it, so the host becomes
  unresolvable and no TCP flow ever opens. Until the provider fix lands (never claim port-53
  datagrams; hostname entries bind to TCP), the Getting-started "Add a host" step and the
  Capture card's remedy say to add `host:443` (and `host:80`) entries, and the Scope page's
  placeholder gets the same hint. Once the fix merges the hint is removed (one string).
- **No core verb reports extension attach state (orchestrator):** `CaptureCapability` in the
  core is dead code and `proxy.status.capturing` is the record/pause toggle, not the extension.
  The capture lane is therefore derived from the app's own tunnel status (`CaptureAdvice`). A
  read-only `capture.status` verb (enabled, feeder listening, provider attached, scope tokens
  pushed, flows handed off) is proposed as a separate card; `ConnectionSummary.make` takes an
  optional `coreCapture: CoreCaptureStatus?` that, when present, overrides the detail line and
  turns "capture on" into "capture on · attached · n flows handed off". Tunnel status stays the
  fallback.
- **Scope persistence is app-side** (persist-scope session): hosts saved in the app store and
  restored into the embedded config / re-pushed on connect. The Status page keeps reading
  `scope.list` as the truth; no change here.

## Left to the builder

- Exact card widths/breakpoint (side by side ≥ 900 pt, stacked below), icon choices per lane
  (monochrome: `cpu`, `point.3.connected.trianglepath.dotted`, `antenna.radiowaves.left.and.right`).
- Whether Recent reuses `FlowListRow` from the Overview breakdowns (preferred) or a lighter row.
- How the `@SceneStorage` landing rule handles a fixture/snapshot run (snapshots start on
  `.apps` as today unless a scene asks for `.status`).

## Open questions

- Matt: Status as the **first sidebar row in its own "Proxy" group** vs the first row of "All"?
  (Default: own group.)
- Matt: should Status replace Overview as the landing page even when flows exist? (Default:
  no — restore the last page; Status only when there is nothing to show yet.)
