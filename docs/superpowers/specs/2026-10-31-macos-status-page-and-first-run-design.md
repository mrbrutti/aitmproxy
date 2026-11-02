# macOS Status page and first-run flow design

**Status:** implemented on `claude/macos-connection-ux` (2026-10-31); panel-reviewed twice, revisions below; one open question left for Matt (the landing rule once flows exist)
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
- Every connection indicator (toolbar cluster, Status page, Core Log header, Settings
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
- No change to the on/off steps or their ordering in `CaptureSwitch`/`ExtensionController`
  (revision 2 adds only the status-bar message for a same-as-chosen click, §4)
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
public enum LaneState: Int, Comparable, Sendable { case ok, working, off, warning, error }  // off = intended absence, ranks below "on but wrong"

public struct ConnectionLane: Equatable, Sendable {
    public enum Kind: Sendable { case core, bus, capture }
    public let kind: Kind
    public let state: LaneState
    /// The one word for the toolbar pill and the Status card: "running", "connecting…", "capture on" …
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
    case startCore, restartCore, showCoreLog, switchToEmbedded
    case reconnectBus, openBusSettings
    case turnCaptureOn, turnCaptureOff, openScope, approveInSystemSettings, uninstallExtension, openCaptureSettings
    case openBrowser, copyListenAddress
}

public struct ConnectionSummary: Equatable, Sendable {
    public let core: ConnectionLane
    public let bus: ConnectionLane
    public let capture: ConnectionLane
    /// Worst lane state.
    public var overall: LaneState
    /// Getting-started steps with their done flag, in order.
    public let steps: [GettingStartedStep]

    public static func make(core: CoreConnection?, activeKind: ActiveCoreKind, bus: BusState,
                            role: String?, roleWarning: Bool, capability: CaptureCapability,
                            captureSupported: Bool, scopeHostCount: Int, flowCount: Int,
                            listenAddress: String, coreCapture: CoreCaptureStatus? = nil) -> ConnectionSummary
    // builds the CaptureAdvice itself from capability + supported + scope count (one call site)
    public var tooltip: String; public var spoken: String   // the three lanes, for .help / a11y
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
| Core | `.degraded(reason)` | error | failed | "Restart the core" (reason as detail) |
| Core | `.stopped` / no connection | off | stopped / not running | "Start the core" |
| Core | external kind | off | external | "The app does not manage this core; start and stop it yourself" (detail carries the bus address or "set the address in Settings ▸ Bus") |
| Bus | `.connected`, role ok | ok | connected | — |
| Bus | `.connected`, roleWarning | warning | connected as agent | "Paste the operator token in Settings ▸ Bus" |
| Bus | `.connecting` | working | connecting… | — |
| Bus | `.failed(why)` | error | bus failed | why as detail; remedy "Paste the operator token…" when why mentions the token, else "Reconnect, or check the address in Settings ▸ Bus" |
| Bus | `.disconnected` | off | offline | "Start the core" (embedded core down) / "Reconnect" |
| Capture | `.unsupported` | off | no extension | "This build has no capture extension; the signed app has it" |
| Capture | `.off` | off | capture off | "Turn on capture to see other apps' traffic" |
| Capture | `.awaitingApproval` | working | waiting for approval | "Approve the extension in System Settings" |
| Capture | `.degraded(reason)` | error | capture degraded | reason |
| Capture | `.onEmptyScope` | warning | on, nothing in scope | "Add a host to Scope" |
| Capture | `.on(n)` | ok | capture on · n hosts in scope | — (with `coreCapture.providerAttached == false`: warning, "on, core not attached", "Restart the core") |
| Capture | any, external core active | off | capture off | "Switch to the embedded core to capture other apps' traffic" |

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
  Core, Reconnect Bus, Capture / Stop Capturing All Apps, Scope…, Core Log…, Browser) — all exist today.

### 3. Sidebar information architecture and landing page (revised after Matt's review)

Matt's reading of the first cut: "the sidebars … are completely in a weird order or
priorities — what is the main work window, what are other things; now you have a Proxy
sidebar item and you also show the status in the bottom." The groups below are organised by
the operator's **jobs** (brief: watch/inspect, intercept, test, supervise), the main work
window comes first, and the connection state has **one** home.

```text
 ›•‹ aitmproxy                  ← the brand row is the product mark only (revision 2: the
                                    connection state has ONE home, the toolbar, §4)
 TRAFFIC                        ← the main work window: the flow list + inspector
   Flows                  104   all flows (the default page once connected)
   Apps                     0   flows grouped by source app (sub-rows per app)
   Domains                  3   flows grouped by host (sub-rows per host)
   Pinned                   2   the operator's working set (sub-rows)
   Connections                  the waterfall/dashboard view of the same flows
   Overview                     the statistics view of the same flows
 TESTING                        ← the security work on that traffic
   Scope                    1
   Scan                     6
   Findings                 3
   Browser              1 tab
 AUTOMATION                     ← what acts on the operator's behalf
   Scripts             1 active
   Agent                14/min
```

- **Saved** leaves the sidebar until saving exists (S-066): a dead row at the top of the list
  was the first thing a new operator saw. It returns under Traffic when the core can save.
- **Status** is reached from the toolbar's connection pill, Proxy ▸ Status (⌘0), and the
  palette. It is not a sidebar list row: it is the place the app sends you when something is
  wrong, not a place in the work hierarchy (rule 59). *Revision 2 (Matt, 2026-10-31): "you
  already have status in the top and in the sidebar and in the status bar below … pick a proper
  place and stick to it; the top, you already have a designated place."* So the brand row and
  the status bar carry no connection state at all; the toolbar is the one home (§4).
- **Status bar** shows the list's small facts only: counts, selection, paused, scope and
  findings counts, Undo after Clear, the last error, memory and throughput. No connection item
  (it was the third copy of the toolbar's state); the bottom stays free for other information.
- **Landing**: a fresh install lands on **Status** and stays there until the operator navigates
  once; after that the last list page is restored (a session that ended on Status or Saved
  comes back on Flows). Apps is no longer the default (its empty state was the second thing a
  new operator saw).
- Counts: Flows/Apps/Domains/Pinned show their flow counts; Scope/Scan/Findings show queue
  counts in the raised chip; Browser/Scripts/Agent keep their words.

`SidebarPage` gains `.flows` (all flows, no group) and the `.status` case stays for routing
and the menu; `.saved` stays in the enum (routing to `SavedPanel`) but `isInSidebar` is false.

### 4. The toolbar is the one home for connection state — and its two switches (revision 2)

```text
 [≡] [✎] [🗑]      ● aitmproxy · 127.0.0.1:8080   Proxy [●━]   Capture [━●]      [Agent ●━] [⌘] [▭ ▯ ⧉]
      leading                    principal: the connection cluster                 trailing
```

Three groups, as before; the record/pause button leaves the leading group because its job moves
into the cluster. Everything in the cluster reads `Session.connectionSummary`.

- **Pill** (`ListeningPill`): a `Button` to `.status`. Core dot + `aitmproxy` + the bound proxy
  address; ` · paused` while the proxy is paused and ` · intercept armed` while it is; then the
  bus and capture `LaneDot`s only while those lanes need attention. `.help` is `summary.tooltip`
  + "Opens Status (⌘0)". Drawn on `active` instead of `raised` while the Status page is showing,
  so the page has a selected entry even though it is not a sidebar row.
- **Proxy switch** (`ToolbarSwitch("Proxy")`): on = the proxy records flows, off = paused. Its
  position is the **core's** `capturing` fact: `BusService` reads `proxy.status.capturing` every
  poll and takes the value from each `proxy.pause` / `proxy.resume` reply, so a pause by any other
  client (agent, TUI, web) or a relaunch against an already-paused core shows here within one poll
  (panel round 2, security Important). Flips through `ToolbarSwitches.flipProxy` →
  `Session.setCapturing`, the same entry as View ▸ Pause Proxy / Resume Proxy (⇧⌘R) and the
  palette (traffic still passes, new flows are not recorded — the core has no verb that stops the
  listener). Track colour: the success colour when on, tertiary when paused or disabled. Pause is
  a bus call whichever core answers, so the switch is live while the **bus lane is `ok` and the
  resolved role is `operator`** (the role itself, not the lane's mismatch warning, which only
  fires against an Expected-role setting) and disabled otherwise — an agent-token connection
  included, so a pause from this switch is never logged as an agent action (the menu item and
  the palette entry carry no such gate; they predate this revision) — with "Bus <word> — connect
  as operator to pause or resume the proxy" in its help. The same `proxy.status` read drives the
  pill's "intercept armed" from `intercept_armed`, so arming by another client shows too. Help when live: "Pause the proxy: traffic still passes and new flows are not
  recorded (⇧⌘R)" / "Resume recording flows (⇧⌘R)".
- **All Apps switch** (`ToolbarSwitch("All Apps")`): system-wide capture through the extension, on/off (revision 3: Matt rejected "Capture" — it reads as the proxy's recording — and "Extension" — Proxyman's technology word; the feature is named for what it gives the operator: every Mac app's traffic without proxy settings, and the Apps page it feeds. Switch, lane title, Settings tab and menu all say *All Apps*; "the extension" appears only where macOS uses it: approval and uninstall). Its position
  is the published fact, never the preference key (§1): on whenever the capture lane is not
  `off` — capturing, waiting for approval, degraded — off when the lane is off;
  `coreHealth.captureChoice` carries it through a switch in flight. It flips through
  `CaptureSwitch.set`, the same
  steps as Settings ▸ All Apps, Proxy ▸ Capture All Apps / Stop Capturing All Apps (⌃⌘A) and the Status
  card. Its track colour is the **capture lane's state colour** when on — so "on, nothing in
  scope" shows the warning hue, "waiting for approval" the working hue, "capture degraded" the
  error hue — and tertiary when off; the help carries the lane's word, detail and remedy. Disabled
  when the controls are unavailable (no extension in this build, an external core is active, a
  switch is in flight), with the reason in the help. When the lane's fact and the persisted choice
  disagree (the choice says on, the tunnel dropped), a click asks for what is already chosen;
  `CaptureSwitch.set` then says so in the status bar instead of doing nothing. Operator-only: `Shell/ShellToolbar.swift`
  joins Settings, the Proxy menu and the Status page in the capture tripwire's allow-list with an
  `expect`; no bus verb, `Session` action or palette entry reaches it.
- **Words**: one word per idea. *Proxy* is the listener (on / paused); *Capture* is the
  extension, named *All Apps* in every label (GLOSSARY "All Apps"; its switch says All Apps, its menu
  Capture All Apps / Stop Capturing All Apps).
  "Pause Capture / Resume Capture" → "Pause Proxy / Resume Proxy" everywhere (menu, palette,
  command map, the status-bar error prefix, stories); "Enable Capture / Disable Capture" → "Turn
  On Capture / Turn Off Capture", then (review 3) → "Capture All Apps / Stop Capturing All Apps" (⌃⌘A). The command map
  also gains the Proxy menu's Reconnect Bus (⌃⌘R) and Restart Core (⌃⇧⌘R), which it had been
  missing, so the map lists every Proxy-menu item the Status cards twin.
- **Sidebar brand row**: `›•‹ aitmproxy`, a label, not a button; no badge, no summary.
- **Status bar**: no connection item (§3).
- **Why the top and not the bottom** (Matt asked, on seeing the first screenshots, whether the
  two switches belong in the status bar). Grouped by function: the toolbar holds what the
  operator *turns on* — the traffic sources (Proxy, Capture) and who may act (Agent) — plus the
  session actions; the status bar holds what *came out* — rows, paused, scope, findings, bytes
  and memory. Three reasons the controls stay up: (1) HIG and the trade: toolbars carry the
  frequent controls, bottom bars carry counts and view toggles (Finder, Mail, Xcode; Proxyman,
  Charles and Wireshark all put record/capture at the top and counts at the bottom);
  (2) Capture All Apps triggers macOS system-extension approval dialogs — a consequential action
  that should not look like a footer toggle; (3) the first-run flow lands on Status with the pill
  directly above the page it opens and the Getting-started row "Turn on the capture extension"
  pointing at a switch in view, not at the far corner. The bottom variant (`● 127.0.0.1:8080 ·
  Proxy [●] Capture [○] · 196 MB ↑ ↓`) stays documented here as the alternative; it would also
  need a 28 pt pill in a 28 pt bar.
- **Structural check** (`tools/check-connection-words.sh`, second rule): only
  `Shell/ShellToolbar.swift`, `Panels/StatusPanel.swift`, `Panels/CoreLogPanel.swift`,
  `SettingsView.swift`, `Session+Connection.swift`, `SelfTest.swift` and `SnapshotScenes.swift`
  may read `connectionSummary`; `Shell/SidebarView.swift` and `Shell/StatusBar.swift` must not
  mention it, `LaneDot`, `LaneState` or `ConnectionSummary`. Settings ▸ Capture's Status row and
  Settings ▸ Bus's Connection row keep reading the lane words (as built).

### 4b. Chip bar: raw-L4 protocols (revision 2)

Matt: "in the top where we filter by protocol we are still missing L4 type of packet traffic."
`ContentCategory` gains `tcp`, `udp` and `l4` in their own group after the application-layer
protocols: `All | HTTP HTTPS WebSocket | TCP UDP L4 | h1 h2 | JSON …`. `tcp`/`udp` match
`row.l4?.proto`; `l4` matches every row carrying `l4` (set on every packet-level row; ICMP, raw and other included — the
"All" of packet traffic, the word the L4 badge already uses). The ⌘1…⌘9 chip shortcuts follow
bar order as before (h1 is now ⌘7). Chips get `.help` for the three new ones.

### 5. Words (GLOSSARY additions)

| Term | Means | Not |
|---|---|---|
| Status | The page that shows Core, Bus and Capture and what to do next | dashboard, home, overview (that is the traffic page) |
| Core | The aitm proxy process: embedded (the app runs it) or external (the operator runs it) | server, daemon, backend |
| Capture extension | The macOS system extension that captures other apps' traffic; on, off, waiting for approval, degraded | NE, sysext, network extension (in UI text) |
| Capture on / off | The operator's switch for the capture extension | enable/disable (buttons say Turn On / Turn Off) |
| Getting started | The Status page's live checklist | onboarding, wizard, tour |

Buttons: Capture All Apps, Stop Capturing All Apps, Restart Core, Start Core, Stop Core, Reconnect,
Open Scope…, Core Log…, Open Browser, Copy Address, Uninstall Capture Extension…, Switch to
Embedded… (opens Settings ▸ Bus).

### 6. File split

| Piece | Files | Owner |
|---|---|---|
| `ConnectionSummary`, `ConnectionLane`, `GettingStartedStep` + tests | `AitmproxyKit/ConnectionSummary.swift`, `Tests/…/ConnectionSummaryTests.swift` | mac-review session |
| `StatusPanel` + its snapshot scenes (every lane state × light/dark) | `Panels/StatusPanel.swift`, `SnapshotScenes.swift`, `Snapshot.swift` | mac-review session |
| `SidebarPage.status` + landing rule | `Session.swift` | mac-review session |
| Sidebar groups; brand row a plain label (rev 2) | `Shell/SidebarView.swift` | mac-review session |
| `Session+Connection.swift` (summary + action glue), `UI/ConnectionLook.swift` (LaneState look, `LaneDot`), `SelfTest.swift` checks, `tools/check-capture-operator-only.sh` allow-list, `tools/check-connection-words.sh`, `Panels/CoreLogPanel.swift`, `Panels/ScopePanel.swift` prompt | — | mac-review session |
| Connection cluster (pill + Proxy/Capture switches); status bar without connection state (rev 2) | `Shell/ShellToolbar.swift`, `Shell/StatusBar.swift`, `UI/TokenMapping.swift` (`switchKnobInset`), `UI/AppearanceSettings.swift` (shares `SwitchGlyph`), `Bus/BusService.swift` (`proxy.status` poll), `Session+Verbs.swift` (error prefix) | mac-review session |
| Proxy ▸ Status (⌘0) + CommandMap entry | `App.swift`, `AitmproxyKit/CommandMap.swift` | mac-review session (wave 3 touches App.swift's Flow menu only — coordinate) |
| `case .status` / `case .saved` in `MainView.content` | `Shell/ShellView.swift` | mac-review session (after #181 merged) |
| Settings rows reading lane words | `SettingsView.swift` | mac-review session (after #181 merged) |
| Glossary, brief IA line, docs | `apps/mac/docs/*` | mac-review session |

## Acceptance criteria

1. **ST-AC1 [kit-unit]** `ConnectionSummary.make` yields the word table above for every
   `CoreConnection.Status` × `ActiveCoreKind` × `BusState` × roleWarning × `CaptureAdvice`
   combination listed; `overall` is the worst lane; no lane word is "Capturing" while
   `scopeHostCount == 0`.
2. **ST-AC2 [kit-unit]** Getting-started steps are done exactly when the facts say so (core
   ready; bus connected without role warning; capture `.on`/`.onEmptyScope`; scope count > 0;
   flowCount > 0), and all-done collapses.
3. **ST-AC3 [mac-snapshot]** The Status page renders every lane state (12 `status-*` scenes +
   the page walk) in light and dark with no clipping; `grid-lint` and `check-layout` PASS; nothing on the page is blank when
   the bus is offline.
4. **ST-AC4 [self-test]** The landing rule is a pure function (`Session.landingPage(saved:)`)
   pinned by the self-test: no saved page → `.status`; a saved list page → that page; a saved
   non-list page (Status, Saved) → `.flows`; an unknown value → `.status`. Fixture, snapshot and
   self-test runs start on Apps so their scenes stay deterministic. `Proxy ▸ Status` (⌘0) is in
   the menu bar and the `CommandMap`.
5. **ST-AC5 [structural]** No view spells a connection state word (`tools/check-connection-words.sh`
   exits 0: the lane words appear as literals only in the Kit models); both capture tripwires
   exit 0.
6. **ST-AC6 [self-test]** Each Status-page action calls the same `Session`/`CaptureSwitch` entry
   as its menu item (menu audit extended with Status's actions).
7. **ST-AC7 [manual, real app]** On Matt's Mac with the notarized DMG: fresh launch lands on
   Status; the three cards read the real state (core running on the bound port, bus connected
   as operator, capture state per the extension); turning capture off and on from the card
   changes Settings ▸ Capture and the toolbar's Capture switch within one poll; adding a host from Open
   Scope… ticks the step; the first flow ticks the last step and Recent fills.
8. **ST-AC8 [manual]** A local unnotarized NE build shows the Capture card as `capture
   degraded` with the reason and the remedy "install the signed app"; nothing claims it works.
9. **ST-AC9 [self-test]** Flipping the toolbar's Proxy switch (`ToolbarSwitches.flipProxy`)
   pauses and resumes through `Session.setCapturing`, the same entry as View ▸ Pause Proxy; the
   Capture switch's position is the lane's fact (on for capturing / waiting / degraded, off for
   inactive / not installed) with the in-flight choice overriding it, and its enabled state
   follows `captureControlsAvailable`/`captureBusy`/embedded; the pill is the only route to
   Status besides ⌘0 and the palette (`isInSidebar` false).
10. **ST-AC10 [structural]** `check-connection-words.sh` fails if `Shell/SidebarView.swift` or
    `Shell/StatusBar.swift` mentions `connectionSummary`, `LaneDot`, `LaneState` or
    `ConnectionSummary`, or if any file outside the allow-list reads `connectionSummary`.
11. **ST-AC11 [unit + self-test]** `ContentCategory.tcp/.udp/.l4` match the fixture L4 rows by
    protocol (the lo0 UDP capture and craft, the en0 TCP session); the chip narrows the list.
12. **ST-AC12 [manual, open]** With VoiceOver or the Accessibility Inspector, the toolbar switches
    read "Proxy, on" / "Capture, off" (label + value), not "toggle button". System Events cannot
    show this for SwiftUI-rendered elements; verified so far: value, AXPress, help.

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
  fallback. *(Folded 2026-11-02, F-1..F-4 below: the verb shipped in v0.5.5 (#200); the app polls it
  about every 2 s from an embedded core that lists it; `CoreCaptureStatus.reason` carries the core's
  `capability_reason` (else `feeder.reason`) under the Kit's wire-advice rule, and the "on, core not
  attached" detail appends it — "extension on · n hosts in scope · core not attached · macos_capture.enabled
  is false" — so the card says why. The word itself is R3-1's "all apps on · n hosts in scope".)*
- **Scope persistence is app-side** (persist-scope session): hosts saved in the app store and
  restored into the embedded config / re-pushed on connect. The Status page keeps reading
  `scope.list` as the truth; no change here.

## Live proof of revision 2 (2026-10-31, dev bundle with a real core, real traffic)

Matt: "the 150 self-test passes are fake … I would not rely on them for anything but UI look and
feel … test it with real live flow data you capture." So the switches were proven on a dev bundle
carrying the repo's release `aitm` (no extension, so its core never enables `macos_capture` and
leaves the installed app's rendezvous alone), with `curl -x` traffic through its proxy and real
input on its toolbar:

- 5 GETs → 5 rows, Response 577 B each, status bar ↓ 183 B/s; the pill showed the real bound
  address and `● no extension`; Proxy on (green), Capture disabled (grey, help "not in this build").
- A real click on the Proxy switch (CGEvent at the switch's AX-reported centre): the switch went
  grey, the pill read `· paused`, ↓ fell to 0 B/s, and 4 GETs sent while paused recorded nothing
  (26 rows before and after). A second click: green again, 2 GETs → 28 rows, ↓ 368 B/s.
- Finding, fixed: the first `ToolbarSwitch` was a plain `Button` with `.isToggle`; System Events
  saw a "toggle button" whose `click` did nothing. It is now a real `Toggle` under
  `ToolbarSwitchStyle`: System Events reads its value (1/0), its `click` flips it (pill reads
  "paused", value 0; click again, value 1) and its help carries the tooltip. The accessibility
  label is set on the rendered element (`accessibilityElement(children: .ignore)` +
  `accessibilityLabel`), the pattern every custom control here uses, but System Events exposes
  no AXTitle/AXDescription for any SwiftUI-rendered element in this toolbar (the pill included),
  so the spoken name is left to a VoiceOver / Accessibility Inspector check (ST-AC12 below).
- Panel round 2's Important, proven fixed the same way: with the dev app showing `Proxy` on, a
  second bus client (`tests/e2e/aitm_e2e` `BusClient`, operator token from the core's own
  config) called `proxy.pause` → the core answered `capturing: false` and, with no click in the
  app, the toolbar switch went grey and the pill read `· paused` within one poll; `proxy.resume`
  from the same client turned it green again.
- Live gaps the fixtures hide (not this PR's; routed): Time and Duration are `—` on every live row
  (`flow.get` carries no timing — orchestrator follow-up); Request is `0 B` on GETs (body bytes
  only; header bytes are a core follow-up); Client is `—` without the extension (expected until
  attribution); a run with `APP_STORE` set lands on Apps because `Store.isOverridden` forces it
  (harness rule — the Status landing is for real installs only).

## Left to the builder

- Exact card widths/breakpoint (side by side ≥ 900 pt, stacked below), icon choices per lane
  (monochrome: `cpu`, `point.3.connected.trianglepath.dotted`, `antenna.radiowaves.left.and.right`).
- Whether Recent reuses `FlowListRow` from the Overview breakdowns (preferred) or a lighter row.
- How the `@SceneStorage` landing rule handles a fixture/snapshot run (snapshots start on
  `.apps` as today unless a scene asks for `.status`).

## Open questions

- ~~Matt: Status as the **first sidebar row in its own "Proxy" group** vs the first row of "All"?~~
  Resolved 2026-10-31: neither. Connection state lives in the toolbar only (§4); Status is a
  page reached from the pill, ⌘0 and the palette, not a list row.
- Matt: should Status replace Overview as the landing page even when flows exist? (Default:
  no — restore the last page; Status only when there is nothing to show yet.)

## Review log

Stage-6 panel 2026-10-31 on `341b68a..07c6772` (security PASS, quality PASS with 10 Minors, spec
FAIL with 2 Critical + 5 Important). Dispositions, all applied on the branch:

| # | Reviewer | Sev | Finding | Disposition |
|---|---|---|---|---|
| 1 | Spec | Critical | No structural check for ST-AC5; Core Log header, Settings ▸ Capture row and the orphaned `CoreHealthDot` still spelled their own words | FIXED — `check-connection-words.sh`; `CoreHealthDot.swift` + `CoreHealth.statusWord` deleted; Core Log header and both Settings rows read the lanes |
| 2 | Spec | Critical | Landing rule untested; ST-AC4 contradicted "Left to the builder" | FIXED — `Session.landingPage(saved:)` pinned by four self-test checks; ST-AC4 and §3 reworded (Status until the operator navigates once) |
| 3 | Spec | Important | 8 scenes, not every lane state | FIXED — `status-core-starting/-stopped`, `status-bus-connecting/-agent` added (12 + page walk) |
| 4 | Spec | Important | Word table / signatures deviated from §1 unexplained | FIXED — §1 amended to the shipped words (stopped is off not failed; off ranks below warning; action names) |
| 5 | Spec | Important | Scope prompt lacked the `host:443` hint | FIXED — prompt reads "host:443 or host:80 (for now), …" |
| 6 | Spec | Important | Settings rows not reading lane words | FIXED (file free after #181) |
| 7 | Spec | Important | Undeclared files / `CoreHealthDot` untouched | FIXED — §6 lists them; the dot is deleted |
| 8 | Quality | Minor | `steps` read "external" back out of a display word | FIXED — `activeKind` passed in |
| 9 | Quality | Minor | `activeKind` unobserved | FIXED — `ActiveConnectionModel` is `@Observable` |
| 10 | Quality | Minor | `default:` in `StatusPanel.run`; dead `.stopCore`, `feederListening` | FIXED — exhaustive switch; both removed |
| 11 | Quality | Minor | Remedies sniff free-text reasons | ACCEPTED for now (the two enums are the NE session's); fallback branches pinned by tests |
| 12 | Quality | Minor | Tooltip/spoken/compact strings built per surface; pluralisation ×4 | FIXED — `tooltip`, `spoken`, `compact`, `overallWord`, `badge` on the model; `Format.count` |
| 13 | Quality | Minor | Landing read side unfiltered; raw `13` | FIXED |
| 14 | Quality | Minor | `RecentFlowRow` repeats `FlowListRow`'s shell | ACCEPTED (the two pages may drift; a `HoverRowButton` is a wave-3 cleanup) |
| 15 | Security | Minor | Both capture tripwires red on main since #183 | FIXED here — scripts follow the `Store.defaults` shapes; Kit doc comment no longer spells the key |

Matt's review 2 (2026-10-31, on the first cut of this branch): "you already have status in the top
and in the sidebar and in the status bar below … pick a proper place and stick to it; I think they
should belong in the top … leave the bottom for other important information. We also need a toggle
for the Network extension and for enabling/disabling the proxy that the user can see and easily
use. … In the top where we filter by protocol we are still missing L4 type of packet traffic."

| # | Point | Disposition |
|---|---|---|
| R2-1 | Status shown three times | FIXED — §3/§4: the toolbar cluster is the one home; brand row is a label; status bar has no connection item; structural rule in `check-connection-words.sh` |
| R2-2 | Visible toggles for the extension and the proxy | FIXED — §4: `ToolbarSwitch` ×2 in the cluster, wired to the existing operator-only entries (`CaptureSwitch.set`, `Session.setCapturing`); tripwire allow-list widened with an `expect` |
| R2-3 | Protocol chips miss L4 | FIXED — §4b: TCP / UDP / L4 chips, unit + self-test |
| R2-4 | Vocabulary: "Capture" meant both the proxy's recording and the extension | FIXED — Proxy (pause/resume) vs Capture (the extension); GLOSSARY, menus, palette, command map, S-018 |

Stage-6 panel round 2 (2026-10-31) on `591e1d0..9fe8b1d`: security FAIL (1 Important, 3 Minor),
quality PASS (11 Minor), spec FAIL (5 Important, 4 Minor). Dispositions, applied in the follow-up
commit on the branch:

| # | Reviewer | Sev | Finding | Disposition |
|---|---|---|---|---|
| P2-1 | Security | Important | The Proxy switch — now the one home — showed `Session.capturing`, a client flag, not the core's published fact; a pause by another client left it green | FIXED — `BusService` polls `proxy.status.capturing` each pass and takes the pause/resume reply's value; §4 amended; proven live (pause from a second bus client flips the switch) |
| P2-2 | Security | Minor | Lane/choice mismatch made the Capture switch a silent dead control | FIXED — `CaptureSwitch.set` reports the already-chosen state in the status bar; §4 amended |
| P2-3 | Security | Minor | `check-connection-words.sh` passed silently on a missing guarded file; no `pipefail`; unanchored exclusions | FIXED — file-exists check, `pipefail` + `LC_ALL=C`, path-anchored exclusions, `grep -nH` |
| P2-4 | Security | Minor | Proxy switch live on a connected-as-agent bus → pause logged as an agent action | FIXED — live only while the bus lane is `ok`; help says "connect as operator" |
| P2-5 | Quality | Minor | `ToolbarSwitch` discarded the Toggle's value; two callers negated different things | FIXED — `action: (Bool) -> Void`; `flipProxy`/`flipCapture` in `ToolbarSwitches` |
| P2-6 | Quality | Minor | Style carried an `enabled` flag `.disabled` already publishes | FIXED — `@Environment(\.isEnabled)` in the style |
| P2-7 | Quality | Minor | Proxy knob position encoded bus liveness | FIXED — `on: session.capturing`, `enabled: live` |
| P2-8 | Quality | Minor | Fourth spelling of "embedded core active" | FIXED for the app (`Session.embeddedCoreActive`); `CaptureSwitch` keeps its own read of the persisted kind on purpose — the tripwire pins that file as the one reader |
| P2-9 | Quality | Minor | Dead Kit API (`overallWord`, `badge`, `LaneState.symbol`) and stale comments | FIXED — deleted; comments name the surfaces that exist |
| P2-10 | Quality | Minor | `SwitchGlyph` hard-coded knob inset and colour; Appearance preview a fourth copy | FIXED — `Tok.Metric.switchKnobInset`; preview renders `SwitchGlyph`. The knob stays white in both appearances as the system switch draws it (the track is a status colour or grey, never the accent) — ACCEPTED with a comment |
| P2-11 | Quality | Minor | ⌘1…9 order derived twice | FIXED — `ContentCategory.shortcutChips` is the one owner |
| P2-12 | Quality | Minor | `.l4` matched `kind`, `tcp/udp` matched `l4?.proto` | FIXED — all three read `row.l4` |
| P2-13 | Quality | Minor | ST-AC9 checks restated the helpers | FIXED — the self-test drives `flipProxy` and settles on `capturing`; position checks per capability |
| P2-14 | Quality | Minor | Compound `#expect`s | FIXED — one fact per expectation |
| P2-15 | Quality | Minor | Tripwire file prefix on the first hit only | FIXED — `grep -nH` |
| P2-16 | Spec | Important | Proxy gate/colour deviated from §4 unamended | FIXED — §4 now states the shipped rule (bus lane `ok`, success tint) and why |
| P2-17 | Spec | Important | ST-AC9 only partly asserted | FIXED — flip driven; `captureOn` per capability; `capturePosition` in-flight override pinned |
| P2-18 | Spec | Important | Live proof claimed a VoiceOver result the range did not establish | FIXED — a11y label/value on the rendered element landed; claim softened to what System Events showed (value, AXPress, help); ST-AC12 added as an open manual check |
| P2-19 | Spec | Important | "pause capture" survived in the status-bar error prefix | FIXED — `Session+Verbs` says "pause proxy / resume proxy" |
| P2-20 | Spec | Important | Reconnect Bus / Restart Core command-map entries unrequested | ACCEPTED — §4 Words now asks for them (the map lists every Proxy item the Status cards twin) |
| P2-21 | Spec | Minor | Stale spec text (status line, §1 API, §2 words, §6 rows, ST-AC7, ST-AC9 wording) | FIXED |
| P2-22 | Spec | Minor | Undeclared files (comment ripples, gallery, `check-capture-toggle.sh`, and now `BusService`, `TokenMapping`, `AppearanceSettings`, `Session+Verbs`) | ACCEPTED — listed in §6 |
| P2-23 | Spec | Minor | Unrequested non-functional additions (`AgentToggle` shares `SwitchGlyph`; `isSelected` traits on the pill and chips) | ACCEPTED — one glyph, one selection idiom |
| P2-24 | Spec | Minor | S-001 / S-018 / CAPABILITIES still carried the old toolbar and words | FIXED |

Re-review of the fix commit (spec PASS, security PASS; Minors only), applied in the re-land:

| # | Reviewer | Sev | Finding | Disposition |
|---|---|---|---|---|
| P2-25 | Security | Minor | Bus lane `ok` ≠ operator: an agent-token connection with no Expected-role setting kept the Proxy switch live | FIXED — `proxyLive(summary, role:)` requires `resolvedRole == "operator"`; self-test pins agent/nil; §4 and S-072 reworded; menu/palette noted as ungated (pre-existing) |
| P2-26 | Security | Minor | `ToolbarSwitches.flipCapture` was a second spelling of the capture entry invisible to the tripwire | FIXED — rule 4 denies `ToolbarSwitches|flipCapture`; rule 2 scans `flipCapture` with ShellToolbar as its only file + expect |
| P2-27 | Security | Minor | Rule-1 exclusions still over-broad; grep errors masked | FIXED — `SelfTest(\+X)?\.swift:` anchor, `FilterRow(\.field,` shape, PIPESTATUS checked |
| P2-28 | Spec | Minor | Non-goals, Goals, §1 word comment, §4b `.l4` sentence, S-072 acceptance still carried old text | FIXED |
| P2-29 | Spec | Minor | ST-AC9's enabled clause pinned on one input | FIXED — `captureLive` checked for installed+embedded (live), external (off), busy (off) |
| P2-30 | Spec | Minor | ST-AC12 open on a spec marked implemented | OPEN for Matt — VoiceOver / Accessibility Inspector read-out of the switches |
| P2-31 | Orchestrator | — | The pill's "intercept armed" was a client flag (same class as P2-1) | FIXED — `refreshProxyStatus` also reads `intercept_armed` |

Matt's review 3 (2026-10-31, on the live app): "even with the extension on, the Apps sidebar is not
populated" and "the Capture button makes no sense — it is not clear what it refers to; it is always
capturing the proxy."

| # | Point | Disposition |
|---|---|---|
| R3-1 | "Capture" as the switch label reads as the proxy's recording; "Extension" (Proxyman's word) rejected too | FIXED — Matt chose *All Apps* from three proposals (All Apps / System-wide / Transparent): toolbar switch, lane title ("All Apps: all apps off"), Status card actions (Capture All Apps / Stop Capturing All Apps / Uninstall Extension…), Proxy menu (⌃⌘A), Settings tab (toggle "Capture traffic from all apps"), GLOSSARY. Kit identifiers (`CaptureSwitch`, `captureLane`, `turnCaptureOn`) keep their names; the tripwires follow the new labels |
| R3-2 | Apps sidebar empty with the extension on | ROUTED to its own session (`mac-attribution`): the extension sends `source_app`, the core maps it to `peer_identity` and then drops it (`detail.rs` writes `"process": null`), and the app never decodes a client — core → app end to end, separate PR |

Fold of the core's `capture.status` verb (2026-11-02, the "Facts from the other sessions folded in"
item, PR #200's verb shipped in v0.5.5; last unit in the mac order after attribution and system proxy):

| # | Point | Disposition |
|---|---|---|
| F-1 | The All Apps lane read only the app's tunnel status; the core's attach state and handoff count (`capture.status`) were decoded by `AitmproxyKit/CaptureStatus.swift` but never polled or shown | FIXED — `BusService.refreshCaptureStatus` reads the verb on the first tick and every 4th (~2 s), only from an embedded core that lists it, change-guarded into `Session.captureStatus` (nil on an external/older core, a failed read, or no connection); `Session+Connection` passes `CoreCaptureStatus(status)` as `make(coreCapture:)` |
| F-2 | `CoreCaptureStatus` had no mapping from the verb's reply and no room for the core's reason | FIXED — `init(_ status: CaptureStatus)`: `provider.state == attached`, TCP + UDP handoffs, `reason = capability_reason ?? feeder.reason`; the "on, core not attached" detail appends the reason ("… · core not attached · macos_capture.enabled is false"); the attached detail is unchanged ("attached · n hosts in scope · m flows handed off"). Kit test pins the four shapes (attached, gate off, bind failed, awaiting) with literal JSON |
| F-3 | `FlowSummary.swift` still said `source_app` is "nil for a proxied flow" after PR #283 taught the core to name proxied clients | FIXED — three comments; outside this spec's §6 (attribution is a non-goal here), ACCEPTED as a comment-only ripple of #283 |
| F-4 | Live proof: a dev bundle embeds no extension, so its advice is `.unsupported` and the lane reads "no extension" before the `.on` branch that reads `coreCapture` — the fold is NOT observable on a dev bundle's screen | What the dev-bundle run (2026-11-02, Aitmproxy-fold + the installed 0.5.13 core) honestly shows: real curl traffic through its proxy; its core's `capture.status` = `feeder_off / "macos_capture.enabled is false"`; the toolbar switch's AX help "All Apps capture is not in this build" (the fallback); the live self-test on a real external core passing the new "no capture fact for an external core" check. The installed 0.5.13 core, read read-only over its bus with the extension on, answered `approved_attached · provider attached · scope_tokens ["wikipedia.org"] · handoffs 0` — the shape the mapping turns into "attached · 1 host in scope · 0 flows handed off". **BLOCKING before Shipped:** the acceptance runner's window pass on the next installed build captures (a) the Status card reading "attached · n hosts in scope · m flows handed off" after a real in-scope Safari visit (m ≥ 1) and (b) the "on, core not attached · <reason>" detail — reachable on the real app for under 3 s after Proxy ▸ Restart Core with All Apps on (the provider re-attaches within ~3 s), so the runner polls the card at 500 ms during that window or records that the window was missed. Owner: orchestrator's acceptance runner (requested 2026-11-02). |

Panel on PR #303 (range dcc71166..d770ad65; security PASS, quality PASS, spec FAIL → fixed below):

| # | Reviewer | Sev | Finding | Disposition |
|---|---|---|---|---|
| P3-1 | Spec | Important | F-4 claimed a dev-bundle observation the code cannot produce; no live evidence in range | FIXED — F-4 rewritten to what was shown, with the installed-build rows as a blocking item and owner |
| P3-2 | Security | Minor | `tcpHandedOff + udpHandedOff` could trap on two huge wire counts | FIXED — `addingReportingOverflow`, saturates to `Int.max`; Kit test with the two-huge-counts literal |
| P3-3 | Security | Minor | The core's `reason` reached three surfaces with no one-line/length rule | FIXED — mapped through `DecryptStatus.displayAdvice` (blank → nil, newlines → spaces, cut at 512); Kit test |
| P3-4 | Quality | Minor | Cadence comment cited a spec requirement that does not exist | FIXED — the comment gives the real reason (in-memory read; attach/detach visible within ~2 s) |
| P3-5 | Quality | Minor | The who-is-asked policy was written three times | FIXED — policy lives on `refreshCaptureStatus`; call site and `Session.captureStatus` point at it |
| P3-6 | Quality | Minor | The session write after the await was not ownership-guarded | FIXED — `refreshCaptureStatus(generation:)` guards `generation == runGeneration` after the call, as `refreshL4State` does |
| P3-7 | Quality | Minor | `.bindFailed("")` and `.unknown` mapping branches untested; bind-failed asserted on `reason` only | FIXED — new test `coreCaptureStatusMappingIsTotalOverTheWire`; bind-failed compared as a whole value |
| P3-8 | Quality | Minor | Third spelling of "does the core list verb X" | FIXED — `BusService.lists(_:in:)`, used by the capture read and `pollsL4` |
| P3-9 | Quality | Minor | `why` computed on the attached path | FIXED — built inside the not-attached branch |
| P3-10 | Spec | Minor | `reason` and the reason suffix were not in the spec body | FIXED — the Facts item carries the sentence |
| P3-11 | Spec | Minor | `FlowSummary.swift` comment edits are outside this spec | ACCEPTED — F-3 |
| P3-12 | Spec | Minor | Declared vs touched files: `CaptureStatus.swift` and `CaptureStatusTests.swift` declared but untouched; `SelfTest+Live.swift` touched, declared late | ACCEPTED — recorded here; the live check is within §6's self-test family and runs over the real bus |
| P3-13 | Spec | Minor | No plan task; F-rows written by the implementing commit before the panel | ACCEPTED — the orchestrator granted the claims and the spec file; dispositions now follow the panel |

