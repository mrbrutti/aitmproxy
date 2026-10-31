# 002 — Remove the palette's dead entrance transition

- **Status**: TODO
- **Commit**: 0f000174
- **Severity**: LOW
- **Category**: Purpose & frequency · dead code
- **Estimated scope**: 1 Swift file (`Shell/ShellView.swift`), ~10 lines removed

## Problem

`apps/mac/Sources/Aitmproxy/Shell/ShellView.swift:49-62` — current:

```swift
.overlay(alignment: .top) {
    if session.paletteVisible {
        ZStack(alignment: .top) {
            Color.black.opacity(0.001).ignoresSafeArea().onTapGesture { session.paletteVisible = false }
            // Keyboard opens land in the same frame; the mouse gets the popover motion,
            // a fade only under Reduce Motion (S-069).
            CommandPalette()
                .padding(.top, Space.section * 2)
                .transition(session.paletteOpenedByKeyboard ? .identity
                            : reduceMotion ? .opacity
                            : .scale(scale: 0.97, anchor: .top).combined(with: .opacity))
        }
        .animation(session.paletteOpenedByKeyboard ? nil : Tok.Motion.easeOut(Tok.Motion.popover), value: session.paletteVisible)
    }
}
```

The `.animation(_:value:)` is attached to the `ZStack` *inside* the `if`. A transition only
animates when the transaction that inserts or removes the branch carries an animation; a
modifier that lives inside the branch cannot supply it. Measured on a real run (window-id
recording at ~58 fps, a real toolbar click, then a real backdrop click): the palette appears in
**one** changed frame and disappears in **one** changed frame. No motion runs in either
direction, with or without Reduce Motion.

That is also the behaviour the brief asks for: "no entrance motion", and ⌘K is a 100+/day
surface where the rule is *no animation, ever* (Raycast has none). The code promises a motion
the app does not have, carries a keyboard/mouse distinction and a Reduce Motion branch for it,
and would start animating the palette the day someone "fixes" the modifier placement.

## Target

```swift
.overlay(alignment: .top) {
    if session.paletteVisible {
        ZStack(alignment: .top) {
            Color.black.opacity(0.001).ignoresSafeArea().onTapGesture { session.paletteVisible = false }
            // ⌘K is used all day: it opens and closes in the same frame, from the keyboard
            // and from the toolbar alike, with or without Reduce Motion (brief: no entrance
            // motion; keyboard actions never animate).
            CommandPalette()
                .padding(.top, Space.section * 2)
        }
    }
}
```

and `@Environment(\.accessibilityReduceMotion) private var reduceMotion` in `ShellView` goes
away if it has no other reader in that file (it has none at the audited commit).

## Repo conventions to follow

- `CommandPalette.swift:5-8` already documents "keyboard open/close never animates"; extend
  the thought to the toolbar.
- `Session.paletteOpenedByKeyboard` (`Session.swift:261`) is still written by
  `App.swift:258`, `ShellToolbar.swift:34` and `SnapshotScenes.swift:109-112`. Leave it: those
  files belong to other sessions today. Add one line to the ANIMATION-AUDIT follow-ups that the
  flag has no reader once this lands.

## Steps

1. Edit `Shell/ShellView.swift` as in Target: delete the `.transition(...)` and the
   `.animation(...)` lines and the S-069 comment; add the new comment.
2. Remove the `reduceMotion` environment property from `ShellView` if unused.
3. Run the gate (below). `tools/check-capture-operator-only.sh` parses this file (it must
   still construct `ExtensionController` once and call `start()` once) — the edit is 60 lines
   away from that code, but run the tripwire.

## Boundaries

- Do NOT touch `Shell/ShellToolbar.swift`, `App.swift`, `Session.swift`, `SnapshotScenes.swift`,
  `Shell/CommandPalette.swift`.
- Do NOT add a working transition instead. The decision is "no motion"; if a reviewer wants the
  popover motion back, that is a design change for Matt, not a placement fix.
- If the excerpt no longer matches, STOP and report.

## Verification

- **Mechanical**: `DEV_TAG=<tag> tools/snap-dev.sh palette,palette-flows` builds and the
  `palette-*.png` snapshots are pixel-identical to a baseline from main (the palette never had
  a transition at rest); `swift test …` exit 0; `tools/selftest.sh` PASS (it opens the palette
  through the live self-test); the three `tools/check-*.sh` tripwires PASS; `grid-lint` PASS.
- **Feel check / real run**: dev bundle with its embedded core and real traffic captured; click
  the toolbar ⌘ button, then the backdrop; press ⌘K, then Escape. A window-id recording shows
  one changed frame per open and one per close — the same as before the change, which is the
  point. Under Reduce Motion, the same.
- **Done when**: the file no longer mentions `transition`, `animation` or `reduceMotion`; the
  recordings before and after are indistinguishable; gate green.
