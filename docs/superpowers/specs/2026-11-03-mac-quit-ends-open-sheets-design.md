# macOS app: quit ends open sheets design

**Status:** approved (2026-11-03 by the orchestrating session under Matt's standing autonomous-approve mode; AC7 amended as noted)
**Research inputs:** the facts note `quit-ends-sheets-FACTS.md` (session gallant-hawking-61d70e side notes, 2026-11-03) and its unified-log reproduction `/tmp/claude/qsh/repro2.log` (dev bundle of `main`, pid 764, 2026-11-03 11:51). Source verified in the worktree on 2026-11-03: `apps/mac/Sources/Aitmproxy/App.swift` (`@main struct AitmproxyApp`, `AppDelegate`), `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift:53-66,121` (the sheets), `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCoreController.swift:103-176` (`willTerminateNotification` → `terminateSynchronously`), `apps/mac/Sources/Aitmproxy/SelfTest.swift:155-160` (`finish` ends one level of sheet, then `NSApp.terminate`), `apps/mac/Info.plist.in:16`, `apps/mac/build.sh:98`, `apps/mac/tools/snap-dev.sh:51-58`, `crates/aitm-sysproxy/src/lib.rs:1322` (`SystemProxy::on_orderly_exit`).

## Intent

With any SwiftUI `.sheet` attached to one of the app's windows, every quit of the macOS app is refused before the delegate runs: AppKit logs `terminate:` → `Attempting sudden termination (1st attempt)` → `Checking whether app should terminate` → `App termination blocked by modal sheet` → `Termination aborted`. Menu Quit and ⌘Q beep, the quit Apple event returns -128 "User canceled", and the v0.5.19 acceptance run had to SIGTERM the app, which orphans the embedded core and leaves the system proxy pointing at a dead port. Every sheet in the app is work-free, so there is nothing to ask: a quit should end the sheets and proceed down the ordinary orderly-exit path that already SIGTERMs the core and restores the system proxy.

## Goals

- A quit with any sheet open (Edit Scope, Compose, Rules, Setup, L4 confirm, Build PoC, nested or on the Inspector/Settings window) ends the sheets and exits the app, with no alert and no confirmation, on all three routes: menu Quit, ⌘Q, the quit Apple event.
- The orderly-exit path is unchanged: `applicationShouldTerminate` is still asked (default `NSTerminateNow`), `willTerminateNotification` still fires, `EmbeddedCoreController` still SIGTERMs and reaps the core, and the core's `SystemProxy::on_orderly_exit` still restores the system proxy.
- Every bundle that can be run (the installed release bundle from `build.sh` and the dev bundle from `tools/snap-dev.sh`) loads the new principal class; a guard inside `swift test` fails when the class name drifts between its three homes.

## Non-goals

- No SIGTERM handler for the app (the follow-up noted in `snap-dev.sh`'s comments and `apps/mac/CLAUDE.md`; a `kill <pid>` of the app still needs the `pkill -f <bundle>/Contents/Resources/core/` stop line).
- No change to the acceptance harness (`tests/e2e/acceptance`), to its MAC-5 sheet-dismiss step added in #324, or to the Rust core.
- No `applicationShouldTerminate` in `AppDelegate`; AppKit's default `NSTerminateNow` stays.
- No "unsaved changes" or "discard?" logic, now or as a hook for later: every sheet is bus-backed and work-free (facts note, table "The sheets").
- No change to `SelfTest.finish` (`SelfTest.swift:158`), which ends one level of sheet before `NSApp.terminate(nil)`; it becomes redundant and harmless, and is left alone to keep this change small **(Architect's call)**.
- No change to how a sheet is presented (`.sheet(isPresented:)` / `.sheet(item:)`), no `preventsApplicationTerminationWhenModal` opt-in per sheet, no replaced `.appTermination` command (both rejected in the facts note: per-sheet and misses the Apple event, respectively).

## Anti-goals

- A quit that exits the process without running the AppKit termination path (any `exit()`, `_exit`, or a `terminate` override that does not call `super`): that orphans the embedded core and leaves the system proxy set.
- A quit that asks a question, shows an alert, or beeps.
- A dev bundle that silently keeps `NSPrincipalClass = NSApplication` so the live proof exercises stock `NSApplication` while the source carries the subclass.
- Touching the installed `~/Applications/Aitmproxy.app` or `/Applications/Aitmproxy.app`, the operator's real defaults, or the operator's Application Support store while building or proving this.
- Printing the bus or operator token anywhere while proving this.

## Constraints

- The app is a SwiftUI `@main struct AitmproxyApp: App` with `@NSApplicationDelegateAdaptor(AppDelegate.self)`; both stay as they are. `NSApplicationMain` chooses the application class from `NSPrincipalClass` in the bundle's Info.plist, so the subclass needs an explicit ObjC name (`@objc(AitmApplication)`) or the plist would have to carry the mangled `Aitmproxy.AitmApplication`.
- The executable target compiles with `defaultIsolation(MainActor.self)`; `NSApplication` is main-actor, so the override needs no isolation annotations.
- The subclass loads only when the process starts from a bundle whose Info.plist names it. The bare scratch binary (`~/Library/Developer/Aitmproxy/.../debug/Aitmproxy`, as `APP_BIN` self-tests run it) keeps stock `NSApplication`; that is acceptable because the self-test has no sheet open at quit and ends sheets itself.
- `tools/snap-dev.sh` borrows the installed bundle's Info.plist (`plutil -convert xml1`, lines 51-58) and only rewrites `CFBundleExecutable`; it must now also set `NSPrincipalClass`. Dev bundles share the bundle identifier `com.mrbrutti.aitmproxy` with the installed app, so the live proof addresses the dev process by name (`Aitmproxy-<tag>`) or pid through System Events, never `tell application id`.
- Never touch the installed app or the operator's defaults: the live proof runs a dev bundle on its own `APP_STORE` and a named `APP_DEFAULTS_SUITE`.
- There is no test target for the app executable and `AitmproxyKit` has no AppKit; anything run by `swift test` lives in `Tests/AitmproxyKitTests` and may read repo files via `#filePath` (the `CommandMapTests` / `RemovedModesTests` pattern).
- `swift test`, `snap-dev.sh`, System Events and `log show` run in the Terminal panel, not the Bash sandbox.

## Design

### D1. The mechanism: an `NSApplication` subclass (decided)

New file `apps/mac/Sources/Aitmproxy/AitmApplication.swift`:

```swift
@objc(AitmApplication) final class AitmApplication: NSApplication
```

It overrides `terminate(_ sender: Any?)`: end every attached sheet on every window in `NSApp.windows`, then call `super.terminate(sender)`. Nothing else is overridden. `apps/mac/Info.plist.in:16` changes from `NSApplication` to `AitmApplication`. `App.swift` is not changed: `@main`, the `App` body and `AppDelegate` stay.

Why this and not the alternatives: the quit Apple event handler calls `terminate:` (the log shows the same path for ⌘Q and the event), so one override covers all three routes; a replaced `.appTermination` command misses the event; a per-sheet `preventsApplicationTerminationWhenModal = false` misses future sheets and leaves the sheet showing while the app exits.

### D2. The end order: innermost first (decided)

Sheets nest (a `.sheet(item:)` presented from inside another sheet) and the Inspector and Settings windows can carry sheets too, so the walk covers every entry in `NSApp.windows`, not just the key window, and ends the innermost sheet of each chain first. A sheet is a window whose `sheetParent` is non-nil; the innermost one has no `attachedSheet` of its own. The override ends such sheets through their parent's `endSheet(_:)` until no window has an attached sheet.

The loop must terminate even if `endSheet` fails to detach a sheet: it is bounded by the number of windows at entry **(Architect's call)**. On exhaustion the override still calls `super.terminate(sender)`; AppKit then refuses as today, which is the existing behaviour and strictly no worse.

No Kit abstraction (no window→parent map type, no pure ordering function): the override is a few lines over AppKit objects and would be the only caller of such a type. The AppKit glue is proven by the live proof (D6) and the log lines in AC1-AC4 **(Architect's call, orchestrator rule 7)**.

### D3. The orderly-exit path is untouched (decided)

`super.terminate(sender)` is always called, after the sheets are ended, on the same call. AppKit then asks `applicationShouldTerminate` (no override in `AppDelegate`, so `NSTerminateNow`), posts `willTerminateNotification`, `EmbeddedCoreController.terminateSynchronously` runs `core.stop()` → SIGTERM → grace (`EmbeddedCoreLaunch.childStopGraceSeconds`, 5 s) → SIGKILL → reap, and the core's SIGTERM handler runs `SystemProxy::on_orderly_exit`, which restores the system proxy it set. Nothing in this change calls `exit`, `_exit`, `replyToApplicationShouldTerminate`, or bypasses `super`.

### D4. No question for a work-free sheet (decided)

The override never presents an alert, a confirmation, or a beep, and does not inspect what the sheet contains. All six sheets (facts note table) are work-free: Scope adds apply over the bus as typed; Compose, Rules and Build PoC are bus-backed; Setup and the L4 confirm hold no edits.

### D5. `snap-dev.sh` carries `NSPrincipalClass` into the dev bundle (decided)

After the borrowed plist is written and `CFBundleExecutable` is replaced (line 59), `snap-dev.sh` reads `NSPrincipalClass` from `apps/mac/Info.plist.in` and writes it into the dev bundle's Info.plist with `plutil -replace NSPrincipalClass -string <value>`. The value is read from `Info.plist.in`, not spelled in the script, so the script cannot drift from the template by construction **(Architect's call)**; the `else` branch (no installed bundle) already generates from `Info.plist.in` and needs no change. `build.sh:98` already generates the installed plist from `Info.plist.in` and picks the new value up with no change.

### D6. The drift guard: a Kit test (Architect's call, orchestrator rule 6)

A new test file `apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift` (suite `PrincipalClassTests`) reads three repo files relative to `#filePath` and asserts, with the literal `"AitmApplication"` spelled once in the test:

1. `Sources/Aitmproxy/AitmApplication.swift` contains `@objc(AitmApplication) final class AitmApplication: NSApplication`.
2. `Info.plist.in` contains `<key>NSPrincipalClass</key><string>AitmApplication</string>` exactly once, and does not contain `<string>NSApplication</string>` (the negative control for the old value).
3. `tools/snap-dev.sh` contains `plutil -replace NSPrincipalClass` (so the dev bundle is written) and does not contain the literal `AitmApplication` (so the only spelling of the value outside the source and the template is this test; the script derives it from `Info.plist.in`, D5).

Chosen over a `tools/check-*.sh` tripwire because the Kit test runs inside gate step 1 (`swift test`) and cannot be skipped; no entry in the `apps/mac/CLAUDE.md` gate list changes. The three homes of the name are therefore the Swift source, `Info.plist.in`, and this test.

### D7. The live proof (owned by the orchestrating session; decided)

Dev bundle `DEV_TAG=<tag> tools/snap-dev.sh` (with `CORE_DIR` or the installed bundle's core), on its own `APP_STORE`, with `APP_DEFAULTS_SUITE=<name>` pre-seeded with `SystemProxyPreferences.promptSuppressedKey` (`systemProxy.promptSuppressed`) true so the Setup sheet does not open at launch; one extra run without the seed for the Setup sheet case. Drive the process by name `Aitmproxy-<tag>` through System Events only. For each case the proof records `log show --predicate 'subsystem == "com.apple.AppKit"'` lines for the dev pid and `pgrep -f Resources/core/aitm` after the quit. Cases and routes are in AC1-AC5.

## Acceptance criteria

1. AC1 (menu Quit, Edit Scope sheet): with the dev bundle running, a scope populated with at least one host, and the Edit Scope sheet open (Proxy ▸ Scope…, then the sheet; field `scope-add-host` present), choosing the application menu's Quit item makes the dev process exit within 10 s. The AppKit log for that pid contains, in order, `terminate:`, `Asking app delegate whether applicationShouldTerminate:`, `applicationShouldTerminate: NSTerminateNow`, `Termination complete`, and does not contain `App termination blocked by modal sheet` or `Termination aborted` after the last `terminate:`. `pgrep -f Resources/core/aitm` prints nothing afterwards.
2. AC2 (⌘Q, Edit Scope sheet): the same state as AC1, quit via a System Events `keystroke "q" using command down` sent to the dev process by name. Same log sequence, same empty `pgrep`.
3. AC3 (quit Apple event, Edit Scope sheet): the same state as AC1, quit via the quit Apple event to the dev process (by pid or process name, never `tell application id`). The event returns without error (no -128), same log sequence, same empty `pgrep`.
4. AC4 (Compose and Setup sheets): AC1-AC3 repeated with the Compose sheet (File ▸ Compose Request…, ⌘N) open; and once, on a run with no `promptSuppressed`/`sheetShown` seed and the Setup sheet showing, one quit route (menu Quit) with the same log sequence and empty `pgrep`. The orchestrating session may pick one route per Compose run as long as all three routes have passed on at least one sheet (AC1-AC3).
5. AC5 (no sheet, regression): a quit with no sheet open behaves as before this change: same log sequence as AC1 and empty `pgrep`.
6. AC6 (no question): in every run of AC1-AC5, no alert, sheet or dialog appears between the quit action and process exit (System Events reports zero new windows/sheets for the process after the action), and the system does not beep (the quit is accepted on the first attempt: exactly one `Attempting sudden termination (1st attempt)` after the last `terminate:`).
7. AC7 (orderly core stop): in every run of AC1-AC5 the embedded core child exits on the app's SIGTERM, not a SIGKILL: the app's stderr/stdout log for the run shows the core's own shutdown lines (or the app's reap of a normally exited child) and `pgrep -f Resources/core/aitm` is empty within `childStopGraceSeconds` of the app's exit. That is the path on which the core runs `SystemProxy::on_orderly_exit`. The machine-state check (`scutil --proxy` after a run whose core set the system proxy) changes the operator's system proxy and runs only with Matt's written yes (memory rule: live machine-state proofs need Matt's yes); without it, AC7 is the path proof above. *(Amended by the orchestrating session on 2026-11-03: the original AC7 required setting the system proxy from the dev core.)*
8. AC8 (dev bundle plist): after `NO_LAUNCH=1 DEV_TAG=<tag> tools/snap-dev.sh`, `plutil -extract NSPrincipalClass raw /tmp/Aitmproxy-dev-<tag>.app/Contents/Info.plist` prints `AitmApplication`. Negative control: the same command on the installed bundle `~/Applications/Aitmproxy.app/Contents/Info.plist` (built before this change) prints `NSApplication`, so the dev value provably came from the script, not from the borrowed plist.
9. AC9 (release plist): a plist generated from `Info.plist.in` by the `build.sh:98` sed line (run on the template alone, no install) contains `<key>NSPrincipalClass</key><string>AitmApplication</string>`.
10. AC10 (drift guard): `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter PrincipalClassTests` passes with the three checks in D6. Negative control, run once and reverted: changing `Info.plist.in`'s value to `NSApplication` makes the suite fail.
11. AC11 (no other source change): the diff touches only `apps/mac/Sources/Aitmproxy/AitmApplication.swift` (new), `apps/mac/Info.plist.in`, `apps/mac/tools/snap-dev.sh`, `apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift` (new), and documentation (`apps/mac/CLAUDE.md` layout line naming the new file, the spec and plan). `App.swift`, `EmbeddedCoreController.swift`, `SelfTest.swift`, `tests/e2e/acceptance/`, and `crates/` are unchanged.
12. AC12 (gate): `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` passes; `tools/grid-lint.sh`, `tools/check-connection-words.sh`, `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh` exit 0; `DEV_TAG=<tag> tools/snap-dev.sh` builds and launches; `tools/selftest-live-embedded.sh` passes (its `SelfTest.finish` quit goes through the new override).

## Left to the builder

- The exact loop shape in `terminate(_:)` within D2 (a `while let` over `NSApp.windows` filtered on `sheetParent != nil && attachedSheet == nil`, or an equivalent), and the form of the bound.
- The doc comment on `AitmApplication` (should cite this spec and the log line `App termination blocked by modal sheet`).
- How `snap-dev.sh` reads the value from `Info.plist.in` (`plutil -extract NSPrincipalClass raw`, or a `sed`), and where in the script the `echo` of the applied class goes, if any.
- Whether the Kit test reads the files with `String(contentsOf:encoding:)` and `contains`, or a stricter line match; the literals in D6 are the floor.
- The one-line mention of `AitmApplication.swift` in `apps/mac/CLAUDE.md`'s Layout section.

## Open questions

None.

## Summary

The app refuses every quit while a SwiftUI sheet is attached, because AppKit's modal-sheet check runs before the delegate. This spec adds one `NSApplication` subclass, `AitmApplication`, named in `Info.plist.in` and carried into dev bundles by `snap-dev.sh`, whose `terminate(_:)` ends every attached sheet on every window (innermost first) and then calls `super`, so menu Quit, ⌘Q and the quit Apple event all exit through the unchanged orderly path that SIGTERMs the embedded core and restores the system proxy. No sheet is ever asked about. A Kit test pins the class name across source, template and script; the live proof on a dev bundle covers Edit Scope, Compose and Setup on all three routes.

### Architect's calls

1. Leave `SelfTest.finish`'s one-level `endSheet` loop in place (redundant, harmless).
2. Bound the end-sheets loop by the window count at entry; on exhaustion still call `super`.
3. No Kit abstraction for the end order; AppKit glue proven by the live proof only.
4. `snap-dev.sh` reads `NSPrincipalClass` from `Info.plist.in` rather than spelling it, so the script cannot drift by construction.
5. Drift guard as a Kit test (`PrincipalClassTests`) run by `swift test`, not a `tools/check-*.sh` tripwire; the test holds the literal once and asserts the script does not.
