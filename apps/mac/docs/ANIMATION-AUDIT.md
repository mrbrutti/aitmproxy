# Animation audit — apps/mac

Date: 2026-10-31. Commit audited: `1854fae7` (v0.5.4), re-checked against `0f000174`.
Method: the `improve-animations` workflow (recon, audit against its eight categories, vet
every finding at its file:line, plan the fixes). Evidence comes from real runs of a debug
bundle (`DEV_TAG=anim tools/snap-dev.sh none` → `/tmp/Aitmproxy-dev-anim.app`) with its
real embedded core and real `curl` traffic through that proxy; the fixture session was used
only for the first attribution pass and is marked as such. Plans live in
[`animation-plans/`](animation-plans/README.md).

## The bar

The brief (`BRIEF.md` ▸ Design plan ▸ Feeling) is the standard: *calm, precise, in control.
No entrance motion; keyboard actions never animate; new rows land without animation; the
only pulse is the armed-intercept dot (off under Reduce Motion).* Emil Kowalski's rules
sharpen it for a tool used all day: anything hit 100+ times a day gets no animation at all;
motion must be interruptible; Reduce Motion drops travel but keeps feedback; curves and
durations are tokens, never literals.

## Recon: where motion lives

The app is SwiftUI (Swift 6, macOS 26) with AppKit for the flow table and the split views.
Motion tokens are generated into `Sources/Aitmproxy/UI/Tokens.swift` from
`docs/design/tokens.json` by `tools/gen-tokens.swift` (`Tok.Motion`: `easeOut` (.23,1,.32,1),
`easeInOut` (.77,0,.175,1), `press` 120 ms, `hover` 100, `popover` 160, `sheet` 220,
`rowArrive` 0, `interceptPulse` 1200). The whole explicit motion surface is five sites:

| Site | File | What it does |
| --- | --- | --- |
| Intercept pulse | `Shell/InterceptBar.swift:46-53` | `withAnimation(.easeInOut(1200/2).repeatForever())` on the dot's opacity, 1 → 0.45 |
| Press feedback | `Shell/InterceptBar.swift:228-238` (`PressStyle`) | scale 0.97 over `Tok.Motion.press` ease-out; opacity dip 0.7 under Reduce Motion |
| Palette entrance | `Shell/ShellView.swift:49-62` | `.transition(scale 0.97 from top + opacity)` for mouse opens, `.identity` for keyboard, `.opacity` under Reduce Motion |
| Sidebar collapse | `Shell/ShellSplitView.swift:44-51` | `animator().isCollapsed`, plain assignment when `accessibilityDisplayShouldReduceMotion` |
| Row arrival | `FlowTable/FlowTableView.swift:116-122` | `insertRows(withAnimation: [])` for appends, `reloadData()` otherwise |

Everything else teleports by construction: chip and filter bars, inspector layouts, status
bar notices, lane cards, hover fills (`UI/HoverRowStyle.swift`, Overview, Scope, Connection
Log, Status recent rows, palette rows), tab underlines, the diff chevron
(`Inspector/DiffView.swift:62`), the drop overlay. Sheets, popovers, menus, switches and
spinners are system controls and keep the system's motion and its Reduce Motion handling.

Frequency map: flow rows and selection (continuous), ⌘K palette and chip keys (100+/day),
hover (tens/day), intercept bar (every paused flow, minutes at a time), sheets (occasional).

## Findings

Ordered by leverage. Every row was re-read at its file:line and, where it claims runtime
behaviour, measured on the real run described under Evidence.

| # | Severity | Category | Location | Finding | Fix |
| --- | --- | --- | --- | --- | --- |
| 1 | **HIGH** | Performance | `Shell/InterceptBar.swift:46-53` | The armed-intercept pulse is a SwiftUI `repeatForever` opacity animation. Every frame re-enters the SwiftUI graph and AppKit layout of the hosting view: **17–23 % of a core, continuously, for as long as any flow is paused** (real core, real paused request, nothing selected: an empty inspector). 0.1–0.6 % the moment the flow is resumed and intercept disarmed. The one motion the brief allows is the app's single biggest idle cost. | Drive the pulse from Core Animation (a layer-backed dot with a `CABasicAnimation` on `opacity`, autoreverses, repeats): the render server animates it, the main thread does nothing per frame. Plan [001](animation-plans/001-intercept-pulse-core-animation.md). |
| 2 | MEDIUM | Accessibility · Interruptibility | `Shell/InterceptBar.swift:49-53` | Reduce Motion is only consulted in `onAppear`. Toggled on while the bar is showing, the opacity jumps to 1 (right) but the repeating animation is only abandoned, not removed; toggled off again, `pulse` is already `true`, so the dot sits at 0.45 with no animation: a half-lit, static dot that reads as a wrong state. | Same plan as 1: the CA animation is added and removed from `updateNSView` as the environment's `accessibilityReduceMotion` changes, so both directions of a live toggle are correct. Proven with the switch toggled live. |
| 3 | MEDIUM | Cohesion · Tokens | `Shell/InterceptBar.swift:52`, `design/KIT.md:252`, `docs/design/tokens.json:225` | The pulse curve is SwiftUI's literal `.easeInOut`, not a token, and the period is `Tok.Motion.interceptPulse / 2` arithmetic at the call site. The docs disagree with the code and each other: tokens.json says "1 → 0.5", the code does 1 → 0.45, KIT.md says "still under Reduce Motion" where the brief and tokens say it stops. | Same plan as 1: add `motion.pulse` (cubic-bezier 0.42, 0, 0.58, 1 — a sine-like ease-in-out; the strong `easeInOut` token is for travel, not breathing) to tokens.json and regenerate; one period token; align KIT.md, DESIGN-SYSTEM.md and the token description with the code. |
| 4 | LOW | Purpose & frequency · Dead code | `Shell/ShellView.swift:49-62` | The mouse-opened palette is given a 160 ms scale-from-top entrance, but the `.animation(_:value:)` that should drive it sits inside the `if session.paletteVisible` branch it is meant to insert and remove, so it never applies. **Measured: a real toolbar click opens the palette in one frame and the backdrop click closes it in one frame.** The palette already behaves as the brief and the 100+/day rule want; the transition, the Reduce Motion branch and the keyboard/mouse distinction are dead code that promises motion the app does not have. | Delete the transition and the animation modifier, keep the instant behaviour, document that ⌘K never animates. Plan [002](animation-plans/002-palette-remove-dead-transition.md). `Session.paletteOpenedByKeyboard` then has no reader in ShellView; retiring the flag touches `Session.swift`, `ShellToolbar.swift`, `App.swift` and `SnapshotScenes.swift`, which other sessions hold — a follow-up. |
| 5 | LOW | Cohesion · Tokens | `UI/Tokens.swift:333-342`, `design/DESIGN-SYSTEM.md:33-36` | `Tok.Motion.hover` (100 ms) and `Tok.Motion.sheet` (220 ms) have no readers; `popover` will have none after 4. Hover fills snap on and off everywhere (correct for a dense tool: Finder and Raycast do the same). Sheets are system. | Documentation only: mark `hover`, `popover`, `sheet` as *reserved / system-provided* in DESIGN-SYSTEM.md and KIT.md so nobody "applies" them to a 100+/day surface. Folded into plan 001's docs step. No code change. |

### Vetted and not reported (by design)

- **Rows arrive without animation.** `insertRows(at:withAnimation: [])` for appends; the
  real-run recording shows each of five requests landing as a single changed frame with no
  intermediate frames (see Evidence). Keep.
- **Keyboard never animates.** ⌘K uses `.identity`; chips, tabs, inspector layouts, filter
  bar and sidebar pages switch without motion. The sidebar collapse on ⌃⌘S does slide
  (`animator()`), which is the platform's own convention for that control and respects
  Reduce Motion; not reported.
- **Press feedback** (`PressStyle`): 120 ms ease-out scale 0.97, opacity dip under Reduce
  Motion, disabled state kept legible. Symmetric press/release at 120 ms is within the
  100–160 ms budget; nothing to change.
- **Hover** is instant, see finding 5.
- **Sheets, popovers, menus, the toolbar switches** (`Toggle`, `Menu`, `Picker`,
  `ProgressView`) are system controls; their motion and Reduce Motion handling are Apple's.
- **Selection** in the AppKit table does not animate; the status-bar and lane-card dots
  change colour instantly (state indication, not decoration).
- **Status page lane cards, chip and filter bars, the intercept bar's own appearance** all
  teleport, as the brief asks ("no entrance motion").

### Missed opportunities (additive, not recommended now)

The brief's restraint wins each of these for v1; they are listed so the next motion pass does
not have to find them again.

- The **Undo Clear** notice (`Shell/StatusBar.swift:19-25`) lapses after 8 s by vanishing. A
  200 ms opacity-only fade on the *lapse* (never on click) would stop a line of the status
  bar from blinking out while the operator reads it, and is Reduce-Motion-safe.
- The **diff section chevron** (`Inspector/DiffView.swift:62`) snaps between 0° and 90° on a
  mouse disclosure; a 120 ms ease-out rotation (off under Reduce Motion) is the standard
  disclosure affordance. Keyboard disclosure would stay instant.
- The **Connection waterfall / Overview bars** redraw on each poll with no transition; data
  motion is explicitly not wanted here, so this is a note, not a plan.

## Evidence (real run)

Setup: `/tmp/Aitmproxy-dev-anim.app` built from this tree, launched with `APP_STORE` in `/tmp`
and **no fixtures**, so it spawned its bundled core (proxy on an auto-picked port, bus on an
ephemeral port, operator token read from the per-launch `config.yaml`). Upstream:
`python3 -m http.server 28199`. Scope added over the bus (`scope.add 127.0.0.1:28199`).
Traffic: `curl -x 127.0.0.1:<port>` through the proxy. Window captured by window id with a
ScreenCaptureKit stream at ~58 fps (frames are delivered only when the window's pixels change;
`AE` = count of differing pixels against the previous frame). CPU: `top -l … -s 2 -pid`.

| Measurement | Result |
| --- | --- |
| Idle CPU, 3 flows captured, nothing paused | 0.1–0.8 % |
| CPU with one **real** paused request, armed from Flow ▸ Arm Intercept, bar + pulse on screen, nothing selected (6 × 2 s samples) | **23.1, 18.1, 16.7, 16.9, 18.4, 17.4 %** |
| CPU after Flow ▸ Resume All + Disarm Intercept, same page | 0.2, 0.1, 0.1, 0.6 % |
| Fixture session (first pass): Apps page with the fixture's paused bar / Status page / Apps page disarmed | 17.4–18.5 % / 0.0 % / 0.0 % |
| Where the time goes (`sample`, 3 s, main thread) | `NSHostingView.beginTransaction → ViewGraphRootValueUpdater.updateGraph` and `NSWindow layoutIfNeeded → _layoutSubtreeWithOldSize` on every display-link tick; no app code |
| Six real requests landing (window-id recording, 5 s) | Five single-frame changes at 1167, 1625, 2152, 2673, 3199 ms (12 710 / 3 618 / 7 311 / 3 673 / 3 640 px); every other frame identical to its predecessor: **no row animation** |
| ⌘K from a real toolbar click, then a real backdrop click | Open: one changed frame at 2218 ms (42 986 px). Close: one changed frame at 4207 ms (42 986 px). **No entrance or exit motion runs** |

The operator-visible consequence of finding 1: the paused state is exactly when the operator
is reading and editing a request in the inspector, and the machine is spending a fifth of a
core on an 8 pt dot.

## Found on the way (not motion, handed to the orchestrator)

- **Intercept armed over the bus never shows the intercept bar.** `session.interceptArmed`
  is set only by the app's own `BusService.setIntercept`; nothing polls the core's armed
  state. With `flow.intercept {"enabled": true}` sent by an agent, a real request paused
  (row badge *Paused*, status bar "1 paused") and the amber bar — with Resume, Edit, Kill —
  never appeared. The MCP supervision story depends on this bar. Needs a poll or a push of the
  armed state (`BusService.swift:128-150`, `Session.swift:214`).
- `FlowTableView.updateNSView` calls `reloadData()` for any change that is not a pure append
  (`FlowTableView.swift:116-122`), so every response arriving for an existing row reloads
  the whole table. Not a motion issue; a throughput one.
- Harness notes for the next session that drives the app with real input are in
  `animation-plans/README.md` ▸ Verification harness.
