# macOS app: quit ends open sheets design

**Status:** approved (2026-11-03 by the orchestrating session under Matt's standing autonomous-approve mode; AC7 amended as noted; revision of 2026-11-03 re-approved by the orchestrating session)
**Research inputs:** the facts note `quit-ends-sheets-FACTS.md` (session gallant-hawking-61d70e side notes, 2026-11-03) and its unified-log reproduction `/tmp/claude/qsh/repro2.log` (dev bundle of `main`, pid 764, 2026-11-03 11:51); the diagnosis log `quit-ends-sheets-DIAG-principal-class-ignored.log` (same side notes, lldb attached to the Task 1 dev bundle `Aitmproxy-qes`, pid 15314). Source verified in the worktree on 2026-11-03: `apps/mac/Sources/Aitmproxy/App.swift` (`@main struct AitmproxyApp`, `.commands { FlowCommands(session:) }`, `AppDelegate.applicationDidFinishLaunching`), `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift:53-66,121` (the sheets), `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCoreController.swift:103-176` (`willTerminateNotification` → `terminateSynchronously`), `apps/mac/Sources/Aitmproxy/SelfTest.swift:98-111,155-160` (`checkMenuCoverage` pins only `CommandMap` entries, none of them Quit; `finish` ends one level of sheet, then `NSApp.terminate`), `apps/mac/Sources/AitmproxyKit/CommandMap.swift` and `apps/mac/docs/BRIEF.md` (no Quit entry), `tests/e2e/acceptance/test_mac_journey.py:568` (MAC-16 is a SKIP; the harness never quits the app), `apps/mac/Info.plist.in:16`, `apps/mac/build.sh:98`, `apps/mac/tools/snap-dev.sh:51-62`, `crates/aitm-sysproxy/src/lib.rs:1322` (`SystemProxy::on_orderly_exit`).

## Intent

With any SwiftUI `.sheet` attached to one of the app's windows, every quit of the macOS app is refused before the delegate runs: AppKit logs `terminate:` → `Attempting sudden termination (1st attempt)` → `Checking whether app should terminate` → `App termination blocked by modal sheet` → `Termination aborted`. Menu Quit and ⌘Q beep, the quit Apple event returns -128 "User canceled", and the v0.5.19 acceptance run had to SIGTERM the app, which orphans the embedded core and leaves the system proxy pointing at a dead port. Every sheet in the app is work-free, so there is nothing to ask: a quit should end the sheets and proceed down the ordinary orderly-exit path that already SIGTERMs the core and restores the system proxy.

## Goals

- A quit with any sheet open (Edit Scope, Compose, Rules, Setup, L4 confirm, Build PoC, nested or on the Inspector/Settings window) ends the sheets and exits the app, with no alert and no confirmation, on all three routes: menu Quit, ⌘Q, the quit Apple event (which is also what the Dock menu's Quit, log out and shut down send).
- The orderly-exit path is unchanged: `applicationShouldTerminate` is still asked (default `NSTerminateNow`), `willTerminateNotification` still fires, `EmbeddedCoreController` still SIGTERMs and reaps the core, and the core's `SystemProxy::on_orderly_exit` still restores the system proxy.
- Every bundle that can be run (the installed release bundle from `build.sh`, the dev bundle from `tools/snap-dev.sh`, and the bare scratch binary) takes the new quit path, because it lives in the app's own Swift source and needs no plist plumbing; a guard inside `swift test` fails when either of the two callers is removed.

## Non-goals

- No SIGTERM handler for the app (the follow-up noted in `snap-dev.sh`'s comments and `apps/mac/CLAUDE.md`; a `kill <pid>` of the app still needs the `pkill -f <bundle>/Contents/Resources/core/` stop line).
- No change to the acceptance harness (`tests/e2e/acceptance`), to its MAC-5 sheet-dismiss step added in #324, or to the Rust core.
- No `applicationShouldTerminate` in `AppDelegate`; AppKit's default `NSTerminateNow` stays.
- No "unsaved changes" or "discard?" logic, now or as a hook for later: every sheet is bus-backed and work-free (facts note, table "The sheets").
- No change to `SelfTest.finish` (`SelfTest.swift:158`), which ends one level of sheet before `NSApp.terminate(nil)`; it becomes redundant and harmless, and is left alone to keep this change small **(Architect's call)**.
- No change to how a sheet is presented (`.sheet(isPresented:)` / `.sheet(item:)`), no `preventsApplicationTerminationWhenModal` opt-in per sheet (rejected in the facts note: per-sheet, misses future sheets, leaves the sheet showing while the app exits).
- No `NSApplication` subclass and no `NSPrincipalClass` change (revision 2026-11-03: SwiftUI ignores the key; see the Design note).

## Anti-goals

- A quit that exits the process without running the AppKit termination path (any `exit()`, `_exit`, or a quit helper that does not end in `NSApp.terminate(_:)`): that orphans the embedded core and leaves the system proxy set.
- A quit that asks a question, shows an alert, or beeps.
- A Quit menu item whose title or key equivalent differs from the system default ("Quit Aitmproxy", ⌘Q): operators and the self-test's menu walk must see no change.
- A quit route that bypasses the sheet teardown: the two callers (menu/⌘Q and the Apple event) must call the one helper, never `NSApp.terminate` directly.
- Touching the installed `~/Applications/Aitmproxy.app` or `/Applications/Aitmproxy.app`, the operator's real defaults, or the operator's Application Support store while building or proving this.
- Printing the bus or operator token anywhere while proving this.

## Constraints

- The app is a SwiftUI `@main struct AitmproxyApp: App` with `@NSApplicationDelegateAdaptor(AppDelegate.self)`; both stay as they are. SwiftUI's `App.main()` instantiates its own `NSApplication` subclass (`SwiftUI.AppKitApplication`, diagnosis log) and does not consult `NSPrincipalClass`, so no `NSApplication` subclass of ours can ever be the running `NSApp` in this app. The hooks that do run before AppKit's modal-sheet check are therefore the SwiftUI command that replaces the Quit item, and the quit Apple event handler.
- The executable target compiles with `defaultIsolation(MainActor.self)`; `NSApp`, `NSWindow` and `NSAppleEventManager` callbacks are main-actor, so the helper and the handler need no isolation annotations.
- AppKit installs its own quit Apple event handler during `NSApplication.finishLaunching`, before `applicationDidFinishLaunching` is delivered; a handler registered in `applicationDidFinishLaunching` for the same class/ID pair replaces it (one handler per pair). It must not be registered earlier (`applicationWillFinishLaunching`), where AppKit's later installation could replace ours.
- Replacing the `.appTermination` command group removes SwiftUI's stock Quit item; the replacement must reproduce it exactly: title `"Quit Aitmproxy"`, `.keyboardShortcut("q")` (⌘Q). The dev bundle's display name stays `Aitmproxy` (`snap-dev.sh` only changes `CFBundleExecutable`), so the title is the same there. No pin exists on the Quit item anywhere: `CommandMap.swift` and `docs/BRIEF.md` have no Quit entry, so `SelfTest.checkMenuCoverage` never looks for it, and the acceptance harness's MAC-16 is a SKIP that never quits (verified 2026-11-03).
- Dev bundles share the bundle identifier `com.mrbrutti.aitmproxy` with the installed app, so the live proof addresses the dev process by name (`Aitmproxy-<tag>`) or pid through System Events / `NSRunningApplication`, never `tell application id`.
- Never touch the installed app or the operator's defaults: the live proof runs a dev bundle on its own `APP_STORE` and a named `APP_DEFAULTS_SUITE`.
- There is no test target for the app executable and `AitmproxyKit` has no AppKit; anything run by `swift test` lives in `Tests/AitmproxyKitTests` and may read repo files via `#filePath` (the `CommandMapTests` / `RemovedModesTests` pattern).
- `swift test`, `snap-dev.sh`, System Events and `log show` run in the Terminal panel, not the Bash sandbox.

## Design

> **Revision 2026-11-03.** The first approved design (D1 as originally written, plus D5, D6, AC8-AC10) put the sheet teardown in an `NSApplication` subclass `AitmApplication` named by `NSPrincipalClass`. Task 1 of the plan implemented it (commits `96ee47fe`, `cb2aa8a2`) and the live proof failed: lldb attached to the dev bundle (`quit-ends-sheets-DIAG-principal-class-ignored.log`) showed `[NSApp class]` is `SwiftUI.AppKitApplication` (superclass `NSApplication`) while `[[NSBundle mainBundle] objectForInfoDictionaryKey:@"NSPrincipalClass"]` is `AitmApplication` and the bundle path is the dev bundle. SwiftUI's `@main struct AitmproxyApp: App` instantiates its own `NSApplication` subclass and ignores `NSPrincipalClass`, so the override could never run. The same session confirmed the sheet facts: the windows were `SwiftUI.AppKitWindow` (`attachedSheet` = the sheet), `TUINSWindow`, `SwiftUI…SheetPresentationWindow` (`sheetParent` = the main window) and `SPRoundedWindow`, so the D2 walk (`sheetParent != nil && attachedSheet == nil`, ended through the parent's `endSheet`) stands. D1 is replaced below by a helper with two callers; D5, D6, AC8, AC9 and AC10 are **withdrawn in revision** (kept in place, struck through in prose, so the plan's Task 1 record stays readable); D2, D3, D4, D7 and AC1-AC7, AC12 stand; AC11 is updated; AC13 and AC14 are new. The orchestrating session decided the mechanism and re-approved the revision.

### D1. The mechanism: one quit helper, two callers (decided; revised 2026-11-03)

New file `apps/mac/Sources/Aitmproxy/Quit.swift`:

```swift
enum Quit { static func endSheetsAndTerminate() }
```

The helper ends every attached sheet on every window in `NSApp.windows` per D2, then calls `NSApp.terminate(nil)`. Nothing else lives in the file. Two callers cover the three routes:

(a) **Menu Quit and ⌘Q.** In `App.swift`, inside the existing `.commands { ... }` on the main `Window`, alongside `FlowCommands(session: session)`:

```swift
CommandGroup(replacing: .appTermination) { Button("Quit Aitmproxy") { Quit.endSheetsAndTerminate() }.keyboardShortcut("q") }
```

The item keeps the stock title and ⌘Q (Constraints), so the menu bar reads exactly as before.

(b) **The quit Apple event** (`tell application … to quit`, `NSRunningApplication.terminate()`, the Dock menu's Quit, log out, shut down). In `AppDelegate.applicationDidFinishLaunching`, after the two fail-closed refusals and before `setActivationPolicy`:

```swift
NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(handleQuitAppleEvent(_:withReplyEvent:)), forEventClass: AEEventClass(kCoreEventClass), andEventID: AEEventID(kAEQuitApplication))
```

with the handler on `AppDelegate`:

```swift
@objc func handleQuitAppleEvent(_ event: NSAppleEventDescriptor, withReplyEvent reply: NSAppleEventDescriptor)
```

whose body is the one call `Quit.endSheetsAndTerminate()`. This replaces AppKit's own quit handler, which did nothing but call `terminate:`.

Why this and not the alternatives: the `NSApplication` subclass cannot be loaded under SwiftUI's `@main` (revision note); a replaced `.appTermination` command alone misses the Apple event (the facts note's objection), which the second caller closes; a per-sheet `preventsApplicationTerminationWhenModal = false` misses future sheets and leaves the sheet showing while the app exits. Closing the last window (`applicationShouldTerminateAfterLastWindowClosed → true`) is not a fourth route: a window with an attached sheet cannot be closed from its title bar.

**The reply descriptor (considered, no trap).** AppKit's stock handler calls `terminate:` and, when the delegate answers `NSTerminateLater`, suspends the current Apple event so the reply can be sent from `replyToApplicationShouldTerminate(_:)`; when the quit is refused it writes `-128` into `reply`. Our handler does neither, and neither matters here: `AppDelegate` has no `applicationShouldTerminate`, so the answer is always `NSTerminateNow` and `NSApp.terminate(nil)` does not return; the process exits inside the call, before the handler would have returned and before any reply could be sent, which is exactly what AppKit's own handler does today for a quit with no sheet open (a sender such as `osascript` treats the target's exit as completion). Two consequences are recorded as accepted: (1) if a later change adds `applicationShouldTerminate` returning `NSTerminateLater`, the handler must also call `NSAppleEventManager.shared().suspendCurrentAppleEvent()` and the spec for that change must say so; (2) if AppKit still refuses the quit after the sheets are ended (D2's bound exhausted), the sender no longer receives `-128`, it receives an empty reply while the app stays up; the live proof's AC3 checks the process exit, not the reply, so this does not weaken it **(Architect's call)**.

### D2. The end order: innermost first (decided; stands)

Sheets nest (a `.sheet(item:)` presented from inside another sheet) and the Inspector and Settings windows can carry sheets too, so the walk covers every entry in `NSApp.windows`, not just the key window, and ends the innermost sheet of each chain first. A sheet is a window whose `sheetParent` is non-nil; the innermost one has no `attachedSheet` of its own. The helper ends such sheets through their parent's `endSheet(_:)` until no window has an attached sheet. The diagnosis log confirms these are the right properties on SwiftUI's windows (`SwiftUI.AppKitWindow.attachedSheet` is the `SheetPresentationWindow`; its `sheetParent` is the `AppKitWindow`).

The loop must terminate even if `endSheet` fails to detach a sheet: it is bounded by the number of windows at entry **(Architect's call)**. On exhaustion the helper still calls `NSApp.terminate(nil)`; AppKit then refuses as today, which is the existing behaviour and strictly no worse.

No Kit abstraction (no window→parent map type, no pure ordering function): the helper is a few lines over AppKit objects and would be the only caller of such a type. The AppKit glue is proven by the live proof (D7) and the log lines in AC1-AC4 **(Architect's call, orchestrator rule 7)**.


**Amendment 2026-11-03 (after the Task 2 live proof).** The ⌘Q route on the Task 2 build still logged `App termination blocked by modal sheet` in one proof run even though the backtrace showed the keystroke reaching `Quit.endSheetsAndTerminate()`: `endSheet(_:)` on a SwiftUI sheet can leave `attachedSheet` set at the moment AppKit checks it on the same call. The guarantee is the sheet window's own flag: an lldb experiment on the dev bundle (notes folder, `quit-ends-sheets-DIAG-modal-flag.log`) set `preventsApplicationTerminationWhenModal = false` on the attached `SheetPresentationWindow` and a stock `terminate:` then ran the full `Asking app delegate … NSTerminateNow … Termination complete` sequence with the sheet still attached. So the helper, before the end-sheets loop, sets `preventsApplicationTerminationWhenModal = false` on every window in `NSApp.windows` whose `sheetParent` is non-nil; the loop then ends the sheets as before (so nothing is left on screen during the exit), and `NSApp.terminate(nil)` can no longer be refused by a sheet whatever the detach timing. The flag is public AppKit API (`NSWindow.preventsApplicationTerminationWhenModal`, default true). AC13's tripwire gains the literal `preventsApplicationTerminationWhenModal = false` in `Quit.swift`.

### D3. The orderly-exit path is untouched (decided; stands)

`NSApp.terminate(nil)` is always called, after the sheets are ended, on the same call. AppKit then asks `applicationShouldTerminate` (no override in `AppDelegate`, so `NSTerminateNow`), posts `willTerminateNotification`, `EmbeddedCoreController.terminateSynchronously` runs `core.stop()` → SIGTERM → grace (`EmbeddedCoreLaunch.childStopGraceSeconds`, 5 s) → SIGKILL → reap, and the core's SIGTERM handler runs `SystemProxy::on_orderly_exit`, which restores the system proxy it set. Nothing in this change calls `exit`, `_exit`, `replyToApplicationShouldTerminate`, or bypasses `NSApp.terminate`. (`AppDelegate.applicationWillTerminate`'s existing `exit(SelfTest.exitCode)` under `--selftest` is pre-existing and runs after `willTerminateNotification`; it is not part of this change.)

### D4. No question for a work-free sheet (decided; stands)

The helper never presents an alert, a confirmation, or a beep, and does not inspect what the sheet contains. All six sheets (facts note table) are work-free: Scope adds apply over the bus as typed; Compose, Rules and Build PoC are bus-backed; Setup and the L4 confirm hold no edits.

### D5. ~~`snap-dev.sh` carries `NSPrincipalClass` into the dev bundle~~ (withdrawn in revision 2026-11-03)

Withdrawn: there is no principal class to carry. Task 1's insertion after `snap-dev.sh:58` (the `principal_class=` extract, the `plutil -replace NSPrincipalClass`, its two-line comment and the `· principal class` suffix on the `== bundle` echo) is reverted so the script is byte-identical to `main`.

### D6. ~~The drift guard: `PrincipalClassTests`~~ (withdrawn in revision 2026-11-03; replaced by D6′)

Withdrawn: the test pinned a class name that can never load. `Tests/AitmproxyKitTests/PrincipalClassTests.swift` is deleted.

### D6′. The drift guard: a tripwire Kit test on the two callers (Architect's call, orchestrator rule 6)

A new test file `apps/mac/Tests/AitmproxyKitTests/QuitRoutesTests.swift` (suite `QuitRoutesTests`), in the `RemovedModesTests` / `CommandMapTests` tripwire style (`#filePath`, `String(contentsOf:encoding:)`, `contains`), with three tests:

1. **The helper exists and ends in `NSApp.terminate`:** the text of `Sources/Aitmproxy/Quit.swift` contains `static func endSheetsAndTerminate()` and `NSApp.terminate(nil)`, and does not contain `exit(` (the Anti-goals' bypass).
2. **Both callers are wired:** the text of `Sources/Aitmproxy/App.swift` contains `CommandGroup(replacing: .appTermination)`, `"Quit Aitmproxy"`, `.keyboardShortcut("q")`, `kAEQuitApplication`, `withReplyEvent`, and at least two occurrences of `Quit.endSheetsAndTerminate()`.
3. **The principal-class detour is gone:** the text of `Info.plist.in` contains `<key>NSPrincipalClass</key><string>NSApplication</string>` exactly once and does not contain `AitmApplication`; the text of `tools/snap-dev.sh` does not contain `NSPrincipalClass`; `Sources/Aitmproxy/AitmApplication.swift` does not exist.

Chosen over no guard (live proof only) because the test runs inside gate step 1 (`swift test`) and cannot be skipped, and over a `tools/check-*.sh` tripwire because no entry in the `apps/mac/CLAUDE.md` gate list then changes. A weaker guard than a behavioural test, and said so: it proves the source still names both routes, not that they work; the live proof (D7) proves that.

### D7. The live proof (owned by the orchestrating session; decided; stands)

Dev bundle `DEV_TAG=<tag> tools/snap-dev.sh` (with `CORE_DIR` or the installed bundle's core), on its own `APP_STORE`, with `APP_DEFAULTS_SUITE=<name>` pre-seeded with `SystemProxyPreferences.promptSuppressedKey` (`systemProxy.promptSuppressed`) true so the Setup sheet does not open at launch; one extra run without the seed for the Setup sheet case. Drive the process by name `Aitmproxy-<tag>` through System Events only; the quit Apple event by pid (`NSRunningApplication(processIdentifier:).terminate()`, the side-notes script `qes-quit-by-pid.swift`). For each case the proof records `log show --predicate 'subsystem == "com.apple.AppKit"'` lines for the dev pid and `pgrep -f Resources/core/aitm` after the quit. Cases and routes are in AC1-AC5.

## Acceptance criteria

1. AC1 (menu Quit, Edit Scope sheet): with the dev bundle running, a scope populated with at least one host, and the Edit Scope sheet open (Proxy ▸ Scope…, then the sheet; field `scope-add-host` present), choosing the application menu's Quit item makes the dev process exit within 10 s. The AppKit log for that pid contains, in order, `terminate:`, `Asking app delegate whether applicationShouldTerminate:`, `applicationShouldTerminate: NSTerminateNow`, `Termination complete`, and does not contain `App termination blocked by modal sheet` or `Termination aborted` after the last `terminate:`. `pgrep -f Resources/core/aitm` prints nothing afterwards.
2. AC2 (⌘Q, Edit Scope sheet): the same state as AC1, quit via a System Events `keystroke "q" using command down` sent to the dev process by name. Same log sequence, same empty `pgrep`.
3. AC3 (quit Apple event, Edit Scope sheet): the same state as AC1, quit via the quit Apple event to the dev process (by pid or process name, never `tell application id`). The event is accepted (`NSRunningApplication.terminate()` returns true; no -128 is reported), same log sequence, same empty `pgrep`.
4. AC4 (Compose and Setup sheets): AC1-AC3 repeated with the Compose sheet (File ▸ Compose Request…, ⌘N) open; and once, on a run with no `promptSuppressed`/`sheetShown` seed and the Setup sheet showing, one quit route (menu Quit) with the same log sequence and empty `pgrep`. The orchestrating session may pick one route per Compose run as long as all three routes have passed on at least one sheet (AC1-AC3).
5. AC5 (no sheet, regression): a quit with no sheet open behaves as before this change: same log sequence as AC1 and empty `pgrep`.
6. AC6 (no question): in every run of AC1-AC5, no alert, sheet or dialog appears between the quit action and process exit (System Events reports zero new windows/sheets for the process after the action), and the system does not beep (the quit is accepted on the first attempt: exactly one `Attempting sudden termination (1st attempt)` after the last `terminate:`).
7. AC7 (orderly core stop): in every run of AC1-AC5 the embedded core child exits on the app's SIGTERM, not a SIGKILL: the app's stderr/stdout log for the run shows the core's own shutdown lines (or the app's reap of a normally exited child) and `pgrep -f Resources/core/aitm` is empty within `childStopGraceSeconds` of the app's exit. That is the path on which the core runs `SystemProxy::on_orderly_exit`. The machine-state check (`scutil --proxy` after a run whose core set the system proxy) changes the operator's system proxy and runs only with Matt's written yes (memory rule: live machine-state proofs need Matt's yes); without it, AC7 is the path proof above. *(Amended by the orchestrating session on 2026-11-03: the original AC7 required setting the system proxy from the dev core.)*
8. AC8 ~~(dev bundle plist)~~: **withdrawn in revision 2026-11-03** (no principal class; see AC14 for the revert check).
9. AC9 ~~(release plist)~~: **withdrawn in revision 2026-11-03** (no principal class).
10. AC10 ~~(drift guard `PrincipalClassTests`)~~: **withdrawn in revision 2026-11-03**; replaced by AC13.
11. AC11 (no other source change; updated in revision): the diff `BASE..HEAD` (`BASE` = `4349822b`) touches only `apps/mac/Sources/Aitmproxy/Quit.swift` (new), `apps/mac/Sources/Aitmproxy/App.swift` (the `CommandGroup` in `.commands`, the handler registration in `applicationDidFinishLaunching`, the `@objc` handler method on `AppDelegate`; nothing else in the file), `apps/mac/Tests/AitmproxyKitTests/QuitRoutesTests.swift` (new), and documentation (`apps/mac/CLAUDE.md` layout line naming `Quit.swift`, the spec and plan). `apps/mac/Info.plist.in` and `apps/mac/tools/snap-dev.sh` are byte-identical to `BASE` (Task 1's edits reverted), and `apps/mac/Sources/Aitmproxy/AitmApplication.swift` and `apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift` do not exist at `HEAD`. `EmbeddedCoreController.swift`, `SelfTest.swift`, `FlowCommands`, `tests/e2e/acceptance/`, and `crates/` are unchanged.
12. AC12 (gate): `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` passes; `tools/grid-lint.sh`, `tools/check-connection-words.sh`, `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh` exit 0; `DEV_TAG=<tag> tools/snap-dev.sh` builds and launches; `tools/selftest-live-embedded.sh` passes (its `SelfTest.finish` quit calls `NSApp.terminate` directly and is unaffected; its menu walk sees the same Quit item).
13. AC13 (drift guard, new): `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter QuitRoutesTests` passes with the three checks in D6′. Negative control, run once and reverted by the orchestrating session: deleting the `CommandGroup(replacing: .appTermination)` line from `App.swift` makes test 2 fail; that is the removal the guard exists to catch.
14. AC14 (the revert, new): `plutil -extract NSPrincipalClass raw -o - apps/mac/Info.plist.in` prints `NSApplication`; `grep -c NSPrincipalClass apps/mac/tools/snap-dev.sh` prints `0`; `git diff --stat 4349822b..HEAD -- apps/mac/Info.plist.in apps/mac/tools/snap-dev.sh` prints nothing. Menu check: in the running dev bundle the application menu's last item is titled `Quit Aitmproxy` with key equivalent `q` and the command modifier (System Events `name of last menu item of menu 1 of menu bar item 1`), identical to the installed 0.5.19 app.

## Left to the builder

- The exact loop shape in `Quit.endSheetsAndTerminate()` within D2 (a `while let` over `NSApp.windows` filtered on `sheetParent != nil && attachedSheet == nil`, or an equivalent), and the form of the bound.
- The doc comments on `Quit` and on the `@objc` handler (should cite this spec, the log line `App termination blocked by modal sheet`, and say that SwiftUI ignores `NSPrincipalClass`, which is why the teardown is not an `NSApplication` subclass).
- The name of the `@objc` handler method (`handleQuitAppleEvent(_:withReplyEvent:)` is the suggestion; the parameter signature `(_ event: NSAppleEventDescriptor, withReplyEvent reply: NSAppleEventDescriptor)` is fixed).
- Where in `.commands` the `CommandGroup` goes relative to `FlowCommands(session: session)` (either side; it replaces a group SwiftUI places last anyway).
- Whether `QuitRoutesTests` counts occurrences with `components(separatedBy:)` or `ranges(of:)`; the literals in D6′ are the floor.
- The one-line mention of `Quit.swift` in `apps/mac/CLAUDE.md`'s Layout section, replacing Task 1's `AitmApplication.swift` line.

## Open questions

None.

## Summary

The app refuses every quit while a SwiftUI sheet is attached, because AppKit's modal-sheet check runs before the delegate. The first design (an `NSApplication` subclass named by `NSPrincipalClass`) was implemented and proven not to load: SwiftUI's `@main` installs its own `NSApplication` subclass and ignores the plist key. This revision puts the teardown in one helper, `Quit.endSheetsAndTerminate()`, which ends every attached sheet on every window (innermost first) and then calls `NSApp.terminate(nil)`, reached from two callers: a replaced `.appTermination` command (menu Quit and ⌘Q, same title and shortcut as stock) and a quit Apple event handler registered in `applicationDidFinishLaunching` (the Apple event, Dock Quit, log out). All three routes then exit through the unchanged orderly path that SIGTERMs the embedded core and restores the system proxy. No sheet is ever asked about. Task 1's principal-class artefacts are reverted; a tripwire Kit test pins both callers and the revert; the live proof on a dev bundle covers Edit Scope, Compose and Setup on all three routes.

### Architect's calls

1. Leave `SelfTest.finish`'s one-level `endSheet` loop in place (redundant, harmless).
2. Bound the end-sheets loop by the window count at entry; on exhaustion still call `NSApp.terminate(nil)`.
3. No Kit abstraction for the end order; AppKit glue proven by the live proof only.
4. ~~`snap-dev.sh` reads `NSPrincipalClass` from `Info.plist.in`~~ (withdrawn with D5).
5. ~~Drift guard as `PrincipalClassTests`~~ (withdrawn with D6); replaced by call 7.
6. The Apple event handler does not suspend the event or write a reply: the delegate answers `NSTerminateNow`, so the process exits inside `terminate(_:)` before any reply matters, as AppKit's own handler does today; the `-128`-on-refusal courtesy is dropped and recorded.
7. Drift guard as a tripwire Kit test (`QuitRoutesTests`) on the helper, both callers, and the revert, rather than no guard; it is a source pin, not a behaviour test, and the spec says so.
