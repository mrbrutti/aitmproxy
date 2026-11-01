# Animation plans

Written by the 2026-10-31 motion audit ([`../ANIMATION-AUDIT.md`](../ANIMATION-AUDIT.md)).
Each plan is self-contained: an executor with no context can run it from the file alone.

| # | Plan | Severity | Status |
| --- | --- | --- | --- |
| 001 | [Move the armed-intercept pulse to Core Animation](001-intercept-pulse-core-animation.md) | HIGH | DONE — #204 |
| 002 | [Remove the palette's dead entrance transition](002-palette-remove-dead-transition.md) | LOW | DONE — #203 |

## Order and dependencies

1. **001** first: it is the only finding with a measurable operator cost (a fifth of a core
   whenever a flow is paused) and it also closes the Reduce Motion live-toggle bug and the
   token/doc drift at the same site. It touches `docs/design/tokens.json`, regenerates
   `UI/Tokens.swift`, `Shell/InterceptBar.swift`, `design/KIT.md`, `design/DESIGN-SYSTEM.md`.
2. **002** is independent of 001 (different file) and can land in parallel or after.

Nothing in either plan touches the files other sessions hold on 2026-10-31
(`Shell/ShellToolbar.swift`, `AitmproxyKit/ConnectionSummary.swift`, `Panels/StatusPanel.swift`,
`SettingsView.swift`, `Bus/BusService.swift`, `AitmproxyKit/ContentCategory.swift`,
`Shell/SidebarView.swift`, `Session.swift`).

## Follow-ups that are not plans

- `Session.paletteOpenedByKeyboard` has no reader after 002; retire it when `Session.swift`,
  `App.swift`, `Shell/ShellToolbar.swift` and `SnapshotScenes.swift` are free.
- `Tok.Motion.popover` has no consumer after 002 and its token description ("scale from 0.97 at
  the trigger's origin") describes the motion 002 declared dead; retire or re-describe it the next
  time `docs/design/tokens.json` is touched.
- Product, not motion: `FlowTableView` reloads the whole table on any non-append change. (The
  intercept-bar-over-the-bus gap seen on `1854fae7` was already fixed by #196.)
- Fixture and snapshot modes are being deleted from every frontend (Matt, 2026-10-31); the
  verification sections above no longer rely on them.

## Verification harness (what worked on a shared Mac with sibling sessions)

- **Record by window id, not by screen region.** Sibling sessions' snapshot runs place their
  windows at the same 1440×900 frame; a region recording (`screencapture -V -R`) shows whichever
  window is on top. A ScreenCaptureKit `SCStream` with
  `SCContentFilter(desktopIndependentWindow:)` captures one window at up to 60 fps even when it
  is occluded, and only delivers frames whose pixels changed; count `magick compare -metric AE`
  between consecutive frames to tell a one-frame state change from an animation.
  (`CGWindowListCreateImage` is gone from the macOS 27 SDK.)
- **Clicks must be guarded.** A `CGEvent` posted to the HID tap goes to whatever window is on
  top at that point; the dev window was behind the Claude window and the first clicks landed
  there. Check that the topmost layer-0 window under the point belongs to the dev app's pid in
  the same process that posts the click (no sleep between the check and the click).
  `CGEvent.postToPid` reaches the process but did not act on an inactive window's controls.
- **Activation steals the operator's keyboard focus** and the operator may minimise the window
  that appears (un-minimise through AX `kAXMinimizedAttribute` = false). Keep activations to one
  short burst, move the window to a free display first (AX `kAXPositionAttribute`), hide the app
  afterwards.
- **Menus work without activation.** `AXUIElementPerformAction(kAXPressAction)` on a menu-bar
  item arms intercept, resumes, disarms and quits the dev app without bringing it forward.
  Quit through the app's own Quit item so `applicationWillTerminate` reaps the embedded core.
- **Arm intercept from the app**, not over the bus, when the test needs the intercept bar: the
  app only learns the armed state from its own `setIntercept` (audit ▸ Found on the way).
- **Idle CPU** with `top -l N -s 2 -pid`; attribute with `sample <pid> 3`.
