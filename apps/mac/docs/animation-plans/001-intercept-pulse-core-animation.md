# 001 — Move the armed-intercept pulse to Core Animation

- **Status**: DONE — #204
- **Commit**: written at 0f000174; implemented as aa3a1f9f (PR #204)
- **Severity**: HIGH (performance), with the MEDIUM Reduce Motion and token findings of the same site
- **Category**: Performance · Accessibility · Cohesion & tokens
- **Estimated scope**: 1 Swift file (`Shell/InterceptBar.swift`), 1 token JSON + regenerated `UI/Tokens.swift`, 2 design docs

## Problem

`apps/mac/Sources/Aitmproxy/Shell/InterceptBar.swift:46-53` — current:

```swift
Circle()
    .fill(Tok.Intercept.onBase.color)
    .frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
    .opacity(pulse && !reduceMotion ? 0.45 : 1)
    .onAppear {
        guard !reduceMotion else { return }
        withAnimation(.easeInOut(duration: Tok.Motion.interceptPulse / 2).repeatForever()) { pulse = true }
    }
```

1. **Cost.** A SwiftUI `repeatForever` animation re-enters the SwiftUI graph
   (`NSHostingView.beginTransaction → ViewGraphRootValueUpdater.updateGraph`) and the hosting
   view's AppKit layout on every display-link tick. Measured on a real run (embedded core, a
   real request paused, nothing selected so the inspector was empty): 17–23 % of a core for as long as any flow is paused;
   0.1–0.6 % once resumed and disarmed. The paused state is exactly when the operator is reading
   and editing in the inspector.
2. **Reduce Motion live toggle.** `reduceMotion` is read only in `onAppear`. Turned on while
   the bar shows, the opacity snaps to 1 (correct) but `pulse` stays `true`; turned off again,
   the dot sits at 0.45 with no animation — a dim, static dot.
3. **Tokens and docs.** The curve is SwiftUI's literal `.easeInOut`; the period is call-site
   arithmetic; `docs/design/tokens.json:225` says "1→0.5", the code does 0.45, and
   `design/KIT.md:252` says "still under Reduce Motion" where the brief says it stops.

## Target

The dot is an 8 pt layer-backed `NSView` whose `CALayer` carries a `CABasicAnimation` on
`opacity` from 1.0 to 0.45, `duration = Tok.Motion.interceptPulse / 2` (0.6 s),
`autoreverses = true`, `repeatCount = .infinity`, timing function from the new token
`motion.pulse` = cubic-bezier(0.42, 0, 0.58, 1). The render server runs it: the app's main
thread does nothing per frame. When `accessibilityReduceMotion` is true the animation is
removed and the layer's opacity is 1.0; when it becomes false again the animation is added
back. Both transitions happen from `updateNSView`, so a live toggle in System Settings ▸
Accessibility is handled in either direction. The dot's colour stays `Tok.Intercept.onBase`
and follows appearance changes (set `layer.backgroundColor` in `updateLayer`/`viewDidChangeEffectiveAppearance`
or from a `DynamicColor.nsColor` resolved in `updateNSView`).

Target code (new type in `InterceptBar.swift`, replacing the `Circle()` above):

```swift
/// The paused bar's 8 pt dot. Its pulse is a Core Animation opacity animation on the dot's own
/// layer, so the render server breathes it and the main thread does nothing per frame (a SwiftUI
/// `repeatForever` here cost a fifth of a core). Reduce Motion removes the animation and holds
/// opacity 1; it is re-added when the setting turns off again (live, from `updateNSView`).
struct PulseDot: NSViewRepresentable {
    var color: DynamicColor
    var reduceMotion: Bool

    func makeNSView(context: Context) -> DotView {
        let view = DotView()
        view.wantsLayer = true
        view.layer?.cornerRadius = Tok.Size.statusDot / 2
        return view
    }

    func updateNSView(_ view: DotView, context: Context) {
        view.fill = color.nsColor
        view.setPulsing(!reduceMotion)
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: DotView, context: Context) -> CGSize? {
        CGSize(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
    }

    final class DotView: NSView {
        static let pulseKey = "pulse"
        var fill: NSColor = .clear { didSet { needsDisplay = true } }
        private var pulsing = false

        override var wantsUpdateLayer: Bool { true }
        override func updateLayer() { layer?.backgroundColor = fill.cgColor }
        override func viewDidChangeEffectiveAppearance() { needsDisplay = true }

        func setPulsing(_ on: Bool) {
            guard on != pulsing || (on && layer?.animation(forKey: Self.pulseKey) == nil) else { return }
            pulsing = on
            guard let layer else { return }
            if on {
                let pulse = CABasicAnimation(keyPath: "opacity")
                pulse.fromValue = 1.0
                pulse.toValue = 0.45
                pulse.duration = Tok.Motion.interceptPulse / 2
                pulse.autoreverses = true
                pulse.repeatCount = .infinity
                pulse.timingFunction = Tok.Motion.pulseTiming
                layer.add(pulse, forKey: Self.pulseKey)
            } else {
                layer.removeAnimation(forKey: Self.pulseKey)
                layer.opacity = 1
            }
        }

        // Re-add the animation if the layer was torn down (window moved between displays, hidden).
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if pulsing, window != nil, layer?.animation(forKey: Self.pulseKey) == nil { pulsing = false; setPulsing(true) }
        }
    }
}
```

Use in `pausedBar`:

```swift
PulseDot(color: Tok.Intercept.onBase, reduceMotion: reduceMotion)
    .frame(width: Tok.Size.statusDot, height: Tok.Size.statusDot)
    .accessibilityHidden(true)
```

Remove `@State private var pulse` from `InterceptBar`.

Token (in `docs/design/tokens.json`, inside `"motion"`, after `easeInOut`):

```json
"pulse": { "$type": "cubicBezier", "$value": [0.42, 0, 0.58, 1], "$description": "Breathing curve for the one allowed pulse (the armed-intercept dot): a gentle sine-like ease-in-out, never for travel." },
```

and the `interceptPulse` description corrected to "pulses opacity 1→0.45 over 1200 ms (one
breath: 600 ms down, 600 ms up); removed under Reduce Motion".

Generated Swift: `tools/gen-tokens.swift` already emits every `cubicBezier` as
`static func <name>(_ duration: Double) -> Animation`. Extend the generator so a cubicBezier
also emits a `CAMediaTimingFunction`:

```swift
static let pulseTiming = CAMediaTimingFunction(controlPoints: 0.42, 0, 0.58, 1)
```

(Emit `<name>Timing` for every cubicBezier; `easeOutTiming` and `easeInOutTiming` become
available too. `Tokens.swift` already imports AppKit, which brings QuartzCore.)

## Repo conventions to follow

- Durations and curves come from `Tok.Motion`; nothing in a view is a literal. Exemplar:
  `PressStyle` in `Shell/InterceptBar.swift:228-238` uses `Tok.Motion.easeOut(Tok.Motion.press)`.
- `UI/Tokens.swift` is generated: edit `docs/design/tokens.json`, then run
  `swift apps/mac/tools/gen-tokens.swift` from the repo root (check the header of
  `Tokens.swift` for the exact invocation the file names) in the Terminal panel; never edit
  `Tokens.swift` by hand.
- Reduce Motion comes from `@Environment(\.accessibilityReduceMotion)` in SwiftUI views
  (exemplar: `InterceptBar.swift:9`, `ShellView.swift:13`); AppKit code may consult
  `NSWorkspace.shared.accessibilityDisplayShouldReduceMotion` (exemplar:
  `Shell/ShellSplitView.swift:46`). Here the SwiftUI environment is the source of truth and
  is passed into the representable so live toggles flow through `updateNSView`.
- AppKit-in-SwiftUI representables in this app: `Shell/ShellSplitView.swift`,
  `FlowTable/FlowTableView.swift` (an `NSViewRepresentable` with a `Coordinator`).
- Design docs that describe this part: `design/KIT.md` row "paused" (line 252),
  `design/DESIGN-SYSTEM.md` `Tok.Motion` bullet (lines 33-36). Keep them in the same words as
  the code.

## Steps

1. `docs/design/tokens.json`: add the `pulse` cubicBezier token and correct the
   `interceptPulse` description (values above).
2. `apps/mac/tools/gen-tokens.swift`: in the `case "cubicBezier":` branch, after the existing
   `Animation` function, also emit
   `static let \(ident(key))Timing = CAMediaTimingFunction(controlPoints: a, b, c, d)` with the
   four values formatted as `Float` literals. Regenerate `UI/Tokens.swift` and confirm the diff
   adds exactly `pulse(_:)`, `pulseTiming`, `easeOutTiming`, `easeInOutTiming` and the doc
   comment change.
3. `Shell/InterceptBar.swift`: add `PulseDot` (code above), replace the `Circle()` block in
   `pausedBar` with `PulseDot(color: Tok.Intercept.onBase, reduceMotion: reduceMotion)` framed
   at `Tok.Size.statusDot`, delete `@State private var pulse`.
4. `design/KIT.md:252`: "dot 8 pulsing 1 → 0.45 over 1200 ms (Core Animation; removed under
   Reduce Motion)". `design/DESIGN-SYSTEM.md:33-36`: `interceptPulse` 1200 "(a Core Animation
   opacity pulse, curve `pulse`; removed under Reduce Motion)"; add: "`hover`, `popover` and
   `sheet` are reserved: hover fills snap, popovers/menus/sheets are system controls — do not
   apply them to a surface the operator hits all day."
5. Full mac gate (see Verification), then the live before/after run.

## Boundaries

- Do NOT touch `Shell/ShellToolbar.swift`, `AitmproxyKit/ConnectionSummary.swift`,
  `Panels/StatusPanel.swift`, `SettingsView.swift`, `Bus/BusService.swift`,
  `AitmproxyKit/ContentCategory.swift`, `Shell/SidebarView.swift`, `Session.swift`.
- Do NOT change the bar's layout, words, colours or actions — the dot's implementation only.
- Do NOT add dependencies. Do NOT run `./build.sh` (it installs over the operator's app); use
  `DEV_TAG=<tag> tools/snap-dev.sh`.
- If `InterceptBar.swift` no longer matches the excerpt above, STOP and report.

## Verification

- **Mechanical** (Terminal panel, logs under `/tmp/claude`; no fixture, snapshot or `--selftest`
  runs — they are not evidence):
  - `swift build -c debug --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/ui-redesign-<tag>`
    and assemble `/tmp/Aitmproxy-dev-<tag>.app` from the installed bundle's Info.plist + `Resources/core`
    (the bundle half of the old snap-dev, without its snapshot pass).
  - `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build-<tag>` — exit 0.
  - `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh`,
    `tools/check-connection-words.sh`, `tools/grid-lint.sh` — all PASS.
- **Feel check / real run** (dev bundle with its embedded core, `APP_STORE` in /tmp, no
  fixtures; upstream `python3 -m http.server 28199`; `scope.add 127.0.0.1:28199` over the bus;
  arm from the app's Flow ▸ Arm Intercept; `curl -x 127.0.0.1:<proxy> http://127.0.0.1:28199/paused`):
  - `top -l 8 -s 2 -pid <app>` with the paused bar on screen: **≤ 2 %**
    (was 17–23 %).
  - A window-id recording of the bar shows the dot's opacity changing smoothly across
    consecutive frames over ~1.2 s per breath (it still pulses).
  - Toggle System Settings ▸ Accessibility ▸ Display ▸ Reduce Motion **on** while the bar is
    showing: within a frame or two the dot is static at full opacity (recording: no further
    changed frames in the dot's rect). Toggle it **off** again: the dot breathes again. Restore
    the setting to what it was.
  - Flow ▸ Resume All, Flow ▸ Disarm Intercept: the bar leaves; CPU ≤ 1 %.
- **Done when**: gate green, the live CPU number is ≤ 2 % with the pulse on screen, the live
  Reduce Motion toggle is correct in both directions, and the before/after numbers and frames
  are in the PR.
