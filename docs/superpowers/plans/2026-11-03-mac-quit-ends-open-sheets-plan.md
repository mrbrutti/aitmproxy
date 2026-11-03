# macOS app: quit ends open sheets implementation plan

**Status:** approved (2026-11-03 by the orchestrating session under Matt's standing autonomous-approve mode; Task 2 added in the revision of 2026-11-03, re-approved by the orchestrating session)
**Spec:** `docs/superpowers/specs/2026-11-03-mac-quit-ends-open-sheets-design.md` (approved 2026-11-03; AC7 amended; revised 2026-11-03: D1 replaced, D5/D6/AC8-AC10 withdrawn, D6′/AC13/AC14 added)
**Branch / worktree:** `claude/gallant-hawking-61d70e` (the session's worktree branch; there is no `feat/<topic>` branch) at
`/Users/matt/Security/aitmproxy/.claude/worktrees/gallant-hawking-61d70e` (called `WT`). Base SHA `4349822b`
(`BASE`; `main` at the time of writing, the 0.5.19 acceptance follow-up #324). Absolute paths everywhere; never
`cd` to the main checkout. The spec file is already present untracked in `WT` and is committed with the plan.

## Overview

Two Coder tasks, strictly sequential. **Task 1 is done and superseded**: it implemented the first design (an
`NSApplication` subclass `AitmApplication` named by `NSPrincipalClass`; commits `96ee47fe` test, `cb2aa8a2`
production) and the live proof failed because SwiftUI's `@main` installs its own `NSApplication` subclass and
ignores the plist key (spec, revision note; lldb log `quit-ends-sheets-DIAG-principal-class-ignored.log`). Its
record stays below so the commits on the branch are explained. **Task 2 is the fix task**: it adds the
helper `Quit.endSheetsAndTerminate()` and its two callers (spec D1 as revised), reverts every Task 1 artefact
so `Info.plist.in` and `snap-dev.sh` are byte-identical to `BASE`, and replaces the drift guard. It is
test-first: the tripwire `QuitRoutesTests` (spec D6′) is written and committed first and run once against
the Task 1 tree so it fails red on all three tests (no `Quit.swift`, no `appTermination` group, the
principal-class detour still present), then the production change and the reverts are made and the suite
run green. Both outputs go in the Coder's report.

Why one fix task and not several: the production edit (two files), the reverts (four files) and the guard
(one file) are mutually dependent on `swift test` being green at the end (the deleted `PrincipalClassTests`
would fail against a reverted plist; the new `QuitRoutesTests` test 3 fails until the reverts land). There is
no fan-out; there are no independent tasks.

**Not Coder work.** The live proof (AC1-AC7, spec D7), the gate run of AC12 (`grid-lint`, the three
`check-*.sh` tripwires, a launched `snap-dev.sh` bundle, `selftest-live-embedded.sh`), the AC13 negative
control (delete the `CommandGroup(replacing: .appTermination)` line once, watch test 2 fail, restore) and
the AC14 menu check belong to the orchestrating session in the Terminal after Task 2 is committed. The
Coder's `Done when` is the unit suite, the typecheck and the build; it must not launch a dev bundle, drive
System Events, or read `log show`.

**Environment adaptation (read before dispatching Task 2).** SwiftPM cannot run inside the Claude Bash
sandbox (memory `sandbox-swift-and-git-switch-quirks`), and in this session the Coder has **no Terminal
tool**. So the Coder:

1. Makes its commits (by explicit path: `git add <file>` / `git rm <file>`; never `git add -A`; the shared
   stash is never used).
2. Runs the sandbox typecheck pre-check from memory `sandbox-swift-typecheck-in-process-plugins` (emit
   `AitmBusClient` then `AitmproxyKit` modules into `$TMPDIR/tc` with `-module-cache-path $TMPDIR/mc`, then
   `swiftc -typecheck -swift-version 6 -default-isolation MainActor -I $TMPDIR/tc` over
   `apps/mac/Sources/Aitmproxy/**/*.swift` with `-Xfrontend -in-process-plugin-server-path` and the toolchain
   and platform `-plugin-path`s) and quotes its exit status and any diagnostics. This catches a wrong
   selector, a missing `@objc`, or an isolation error in `App.swift` / `Quit.swift` before the Terminal gate.
   It is not evidence of a pass.
3. Reports **BLOCKED** on the three Terminal commands below, quoting them verbatim with the two commit SHAs,
   and does not claim a pass. The orchestrating session runs them, all from `WT/apps/mac`:

```
swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter QuitRoutesTests
swift build --scratch-path ~/Library/Developer/Aitmproxy/qes-build
swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build
```

The red run (step "Test" below) is therefore also the orchestrating session's: the Coder commits the test
file first and stops to report the SHA; the orchestrating session runs the filtered suite against that SHA,
records the red output, and tells the Coder (or a fresh Coder) to proceed with the production commit. If a
Terminal tool is available after all, the Coder runs the three commands itself and quotes the output.

## Tasks

### Task 1: `AitmApplication` principal class, its two bundle homes, and the drift guard — DONE, SUPERSEDED by Task 2

*Record of what was built on 2026-11-03 (commits `96ee47fe`, `cb2aa8a2`) under the first design. The live
proof showed the class never loads (spec revision note). Everything this task added is removed by Task 2.
Kept verbatim so the branch history reads; do not dispatch.*

- **Satisfied (as written then):** AC9, AC10 (both since withdrawn), AC11 (old file list).
- **Files it created/changed:** `apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift` (new),
  `apps/mac/Sources/Aitmproxy/AitmApplication.swift` (new), `apps/mac/Info.plist.in` line 16
  (`NSApplication` → `AitmApplication`), `apps/mac/tools/snap-dev.sh` (four lines inserted after line 58:
  a two-line comment, `principal_class="$(plutil -extract NSPrincipalClass raw -o - "$here/Info.plist.in")"`,
  `plutil -replace NSPrincipalClass -string "$principal_class" "$dev/Contents/Info.plist"`; and the
  `== bundle` echo gained `· principal class $principal_class`), `apps/mac/CLAUDE.md` (one Layout bullet
  naming `AitmApplication.swift`).
- **Outcome:** `PrincipalClassTests` red then green as planned; dev bundle launched; lldb showed
  `[NSApp class]` = `SwiftUI.AppKitApplication`, so `AitmApplication.terminate(_:)` never ran and AC1 failed.

### Task 2: `Quit.endSheetsAndTerminate()` with two callers; revert Task 1; tripwire guard

- **Satisfies:** AC11, AC13 (the green run; the negative control is the orchestrator's), AC14 (the file
  facts; the menu check is the orchestrator's); and is the whole production change behind AC1-AC7 and AC12,
  which the orchestrating session proves live.
- **Depends on:** Task 1 being on the branch (it reverts it). No other dependency.
- **Files:**
  - `apps/mac/Tests/AitmproxyKitTests/QuitRoutesTests.swift` (create; commit (a))
  - `apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift` (delete; commit (b))
  - `apps/mac/Sources/Aitmproxy/Quit.swift` (create; commit (b))
  - `apps/mac/Sources/Aitmproxy/App.swift` (modify: `.commands` block, `applicationDidFinishLaunching`, one
    new method on `AppDelegate`; commit (b))
  - `apps/mac/Sources/Aitmproxy/AitmApplication.swift` (delete; commit (b))
  - `apps/mac/Info.plist.in` (revert line 16 to `<key>NSPrincipalClass</key><string>NSApplication</string>`;
    commit (b))
  - `apps/mac/tools/snap-dev.sh` (revert the four inserted lines and the echo suffix; commit (b))
  - `apps/mac/CLAUDE.md` (replace the `AitmApplication.swift` Layout bullet with one naming `Quit.swift`;
    commit (b))
  - Nothing else. `SelfTest.swift`, `Bus/EmbeddedCoreController.swift`, `FlowCommands` (inside `App.swift`,
    not edited), `build.sh`, `tests/e2e/acceptance/`, `crates/` are not opened for editing (AC11).

- **Change:**

  **(a) The test, first.** `QuitRoutesTests.swift` in Swift Testing (`import Foundation`, `import Testing`;
  `@Suite struct QuitRoutesTests`, `@Test`, `#expect`; no `@testable import AitmproxyKit`, it reads files).
  Shape, the `PrincipalClassTests` / `CommandMapTests` idiom:

  - `static let macRoot: URL` = `URL(fileURLWithPath: #filePath)` with `deletingLastPathComponent()` three
    times (test file → `AitmproxyKitTests` → `Tests` → `apps/mac`).
  - `static func text(_ relativePath: String) throws -> String` reading `macRoot.appending(path:)` as UTF-8.
  - `static func count(of needle: String, in haystack: String) -> Int` via `components(separatedBy:)` − 1.
  - Three tests (spec D6′ items 1-3):
    1. `theQuitHelperEndsSheetsAndThenCallsTerminate`: the text of `Sources/Aitmproxy/Quit.swift` contains
       `"static func endSheetsAndTerminate()"` and `"NSApp.terminate(nil)"`, and does not contain `"exit("`.
    2. `bothQuitRoutesCallTheHelper`: the text of `Sources/Aitmproxy/App.swift` contains
       `"CommandGroup(replacing: .appTermination)"`, `"\"Quit Aitmproxy\""`, `".keyboardShortcut(\"q\")"`,
       `"kAEQuitApplication"`, `"withReplyEvent"`, and `count(of: "Quit.endSheetsAndTerminate()", in:) >= 2`.
    3. `thePrincipalClassDetourIsGone`: the text of `Info.plist.in` has exactly one
       `"<key>NSPrincipalClass</key><string>NSApplication</string>"` and no `"AitmApplication"`; the text of
       `tools/snap-dev.sh` does not contain `"NSPrincipalClass"`;
       `FileManager.default.fileExists(atPath: macRoot.appending(path: "Sources/Aitmproxy/AitmApplication.swift").path)`
       is false.

  Doc comment on the suite: two lines citing the spec (D6′) and saying this is a source pin on the two quit
  routes and the helper, with the live proof as the behavioural evidence.

  **(b) The production change and the reverts, only after the red run is recorded.**

  1. `apps/mac/Sources/Aitmproxy/Quit.swift` (new). `import AppKit`. One type:

     ```swift
     enum Quit { static func endSheetsAndTerminate() }
     ```

     Body, in prose (spec D2, D3; the loop form is the builder's): end the innermost attached sheets first,
     on every window in `NSApp.windows` (not just the key window), by repeatedly finding a window whose
     `sheetParent` is non-nil and whose own `attachedSheet` is nil and asking its `sheetParent` to
     `endSheet(_:)` it; stop when no window has an attached sheet, or after a bound equal to the number of
     entries in `NSApp.windows` at entry (Architect's call 2). Then, unconditionally and on the same call,
     `NSApp.terminate(nil)`. The helper must not call `exit`, `_exit`, `replyToApplicationShouldTerminate`,
     present any alert, beep, or inspect what a sheet shows (spec Anti-goals, D4). No isolation annotations
     (the target is `defaultIsolation(MainActor.self)`). Doc comment: cite the spec path and the log line
     `App termination blocked by modal sheet`; say the walk runs before `terminate` because AppKit's
     modal-sheet check runs before `applicationShouldTerminate`; say SwiftUI ignores `NSPrincipalClass`,
     which is why this is a helper and not an `NSApplication` subclass. `SelfTest.finish`'s one-level loop
     (`SelfTest.swift:158`) is the model for the AppKit calls and is left untouched (Architect's call 1).

  2. `apps/mac/Sources/Aitmproxy/App.swift`, three edits and nothing else:

     - In `var body: some Scene`, inside the existing `.commands { FlowCommands(session: session) }` on the
       main `Window`, add (either side of `FlowCommands`):

       ```swift
       CommandGroup(replacing: .appTermination) {
           Button("Quit Aitmproxy") { Quit.endSheetsAndTerminate() }
               .keyboardShortcut("q")
       }
       ```

       Title and shortcut are fixed (spec Constraints, Anti-goals). One-line comment citing the spec.

     - In `AppDelegate.applicationDidFinishLaunching`, after the two fail-closed `exit(1)` refusals and
       before `NSApp.setActivationPolicy(.regular)`:

       ```swift
       NSAppleEventManager.shared().setEventHandler(
           self,
           andSelector: #selector(handleQuitAppleEvent(_:withReplyEvent:)),
           forEventClass: AEEventClass(kCoreEventClass),
           andEventID: AEEventID(kAEQuitApplication))
       ```

       Two-line comment: this replaces AppKit's own quit handler (which only called `terminate:`) so the
       Apple event, Dock Quit, log out and shut down take the same teardown as menu Quit; it must be
       registered here, after `finishLaunching` installed AppKit's, not in `applicationWillFinishLaunching`.

     - On `AppDelegate`, one new method:

       ```swift
       @objc func handleQuitAppleEvent(_ event: NSAppleEventDescriptor, withReplyEvent reply: NSAppleEventDescriptor)
       ```

       whose body is the one call `Quit.endSheetsAndTerminate()`. Doc comment: the reply is never written
       and the event never suspended because the delegate answers `NSTerminateNow` and the process exits
       inside `terminate`, as AppKit's own handler does (spec D1, "The reply descriptor"); a future
       `NSTerminateLater` would need `suspendCurrentAppleEvent()` here.

     `FlowCommands`, `Store`, `VerbButton`, the `KeyboardShortcut` extension and the header comment are not
     touched.

  3. Delete `apps/mac/Sources/Aitmproxy/AitmApplication.swift` (`git rm`).

  4. Delete `apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift` (`git rm`).

  5. `apps/mac/Info.plist.in` line 16 back to `<key>NSPrincipalClass</key><string>NSApplication</string>`.
     Check: `git diff BASE -- apps/mac/Info.plist.in` prints nothing.

  6. `apps/mac/tools/snap-dev.sh`: remove the two comment lines, the `principal_class=` line and the
     `plutil -replace NSPrincipalClass` line inserted after `plutil -replace CFBundleExecutable`, and restore
     the echo to `echo "== bundle $dev ($exe)"`. Check: `git diff BASE -- apps/mac/tools/snap-dev.sh` prints
     nothing. (Simplest: `git checkout 4349822b -- apps/mac/tools/snap-dev.sh apps/mac/Info.plist.in`.)

  7. `apps/mac/CLAUDE.md`, Layout section: replace the bullet beginning
     `- \`Sources/Aitmproxy/AitmApplication.swift\`` with one sentence naming `Sources/Aitmproxy/Quit.swift`
     as the quit helper that ends open sheets and then calls `NSApp.terminate`, reached from the replaced
     Quit command and the quit Apple event handler in `App.swift`, so Quit is never refused by an attached
     sheet. No change to the gate list; the SIGTERM-handler follow-up note stays (spec Non-goals).

- **Test:**
  - Red, after commit (a) and before any production edit, in the Terminal from `WT/apps/mac`
    (orchestrating session; see Environment adaptation):
    `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter QuitRoutesTests`
    exits non-zero. Expected: test 1 fails by throwing (`Quit.swift` does not exist, so `text(_:)` throws
    and the test is recorded as a failure); test 2 fails on `#expect` (`App.swift` has none of
    `CommandGroup(replacing: .appTermination)`, `kAEQuitApplication`, `withReplyEvent`, and zero
    `Quit.endSheetsAndTerminate()`); test 3 fails on `#expect` (the template says `AitmApplication`, the
    script contains `NSPrincipalClass`, and `AitmApplication.swift` exists). Swift Testing's summary reports
    `3 tests` with 3 failed (e.g. `Suite QuitRoutesTests failed after ... with N issues`); the three failing
    test names are quoted in the report.
  - Green, after commit (b), same command: `Test run with 3 tests passed after ... seconds` for the filter;
    all three names listed as passed.
  - Independent file facts the Coder also quotes (sandbox-safe, read-only), from `WT`:
    `plutil -extract NSPrincipalClass raw -o - apps/mac/Info.plist.in` prints exactly `NSApplication`;
    `grep -c NSPrincipalClass apps/mac/tools/snap-dev.sh` prints `0`;
    `grep -c 'CommandGroup(replacing: .appTermination)' apps/mac/Sources/Aitmproxy/App.swift` prints `1`;
    `grep -c 'Quit.endSheetsAndTerminate()' apps/mac/Sources/Aitmproxy/App.swift` prints `2`;
    `grep -c 'kAEQuitApplication' apps/mac/Sources/Aitmproxy/App.swift` prints `1`;
    `test -e apps/mac/Sources/Aitmproxy/AitmApplication.swift; echo $?` prints `1`;
    `test -e apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift; echo $?` prints `1`.
  - `git diff --stat 4349822b..HEAD` lists exactly `apps/mac/CLAUDE.md`, `apps/mac/Sources/Aitmproxy/App.swift`,
    `apps/mac/Sources/Aitmproxy/Quit.swift`, `apps/mac/Tests/AitmproxyKitTests/QuitRoutesTests.swift`, and
    the spec and this plan under `docs/superpowers/`; `Info.plist.in`, `snap-dev.sh`, `AitmApplication.swift`
    and `PrincipalClassTests.swift` are absent from the stat (AC11, AC14).
  - Sandbox typecheck pre-check (Coder, not a pass): the `swiftc -typecheck` recipe over the app target exits
    0 with no diagnostics in `App.swift` or `Quit.swift`; its exit status and command are quoted.

- **Done when:** commit (a) and commit (b) are on `claude/gallant-hawking-61d70e`, each by explicit path,
  with messages saying what the user can now do (the second: quitting with a sheet open now quits, via the
  Quit command and the quit Apple event; the principal-class attempt is reverted); the typecheck pre-check
  and the file facts above are in the Coder's report; and the report is marked **BLOCKED** on the three
  Terminal commands (or, with a Terminal tool, quotes their output: the red and green filtered runs,
  `swift build --scratch-path ~/Library/Developer/Aitmproxy/qes-build` with no errors and no new warnings
  in `App.swift` / `Quit.swift`, and the full `swift test` green with every existing suite). `cargo` gate:
  no Rust file changes, so `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  is unaffected; the Tester runs it once on the whole branch as the workflow requires.

## After Task 2 (orchestrating session, not a Coder)

Recorded here so the plan is the single order of work; none of it is a task.

1. Run the three Terminal commands the Coder is BLOCKED on (the red run against commit (a) if it was not
   run before commit (b); then green, build, full suite); paste the output into the Coder's report.
2. Tester on the whole branch (`BASE..HEAD`): maps AC11, AC13, AC14 to the three tests, the diff stat and the
   file facts; runs the full `swift test` and the Rust gate; checks `Quit.swift` and the `App.swift` diff
   against the spec's Anti-goals (no `exit`, no alert, `NSApp.terminate` always reached, both callers call
   the helper, title `Quit Aitmproxy` and ⌘Q unchanged) by reading them.
3. AC13 negative control in the Terminal: delete the `CommandGroup(replacing: .appTermination)` line and its
   closing brace from `App.swift`, run the filtered suite, quote the failure of test 2,
   `git checkout -- apps/mac/Sources/Aitmproxy/App.swift`.
4. AC12 gate: `tools/grid-lint.sh`, the three `check-*.sh`, `DEV_TAG=qes tools/snap-dev.sh` (launches),
   `tools/selftest-live-embedded.sh`.
5. AC14 menu check on the launched dev bundle: System Events reports the application menu's last item titled
   `Quit Aitmproxy` with key equivalent `q` and the command modifier.
6. Live proof AC1-AC7 per spec D7 on the dev bundle with its own `APP_STORE` and a named
   `APP_DEFAULTS_SUITE`, driving `Aitmproxy-qes` by process name through System Events and the quit Apple
   event by pid (`qes-quit-by-pid.swift`), never `tell application id`; the AC7 `scutil --proxy`
   machine-state check only with Matt's written yes. If AC1 still fails, attach lldb as before and record
   which of the two callers ran (breakpoint on `Quit.endSheetsAndTerminate`) before touching the spec again.
7. Panel (security, quality, spec reviewers) on `BASE..HEAD` with the Coder's and Tester's reports.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1 | live proof (orchestrating session) | Critical | `AitmApplication` never loads: `[NSApp class]` is `SwiftUI.AppKitApplication`; SwiftUI `@main` ignores `NSPrincipalClass` | spec revised 2026-11-03 (D1 replaced; D5, D6, AC8-AC10 withdrawn); fixed by Task 2 |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
