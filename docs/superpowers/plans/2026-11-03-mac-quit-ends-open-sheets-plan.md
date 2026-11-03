# macOS app: quit ends open sheets implementation plan

**Status:** approved (2026-11-03 by the orchestrating session under Matt's standing autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-11-03-mac-quit-ends-open-sheets-design.md` (approved 2026-11-03; AC7 amended)
**Branch / worktree:** `claude/gallant-hawking-61d70e` (the session's worktree branch; there is no `feat/<topic>` branch) at
`/Users/matt/Security/aitmproxy/.claude/worktrees/gallant-hawking-61d70e` (called `WT`). Base SHA `4349822b`
(`BASE`; `main` at the time of writing, the 0.5.19 acceptance follow-up #324). Absolute paths everywhere; never
`cd` to the main checkout. The spec file is already present untracked in `WT` and is committed with the plan.

## Overview

One Coder task. The whole production change is three edits and one new Swift file in `apps/mac/`, pinned by
one new Kit test file; nothing else in the repo moves (spec AC11). The task is test-first in the strict sense:
the drift guard `PrincipalClassTests` (spec D6) is written and committed first, run once against the current
tree so that it fails red for all three homes of the class name (the template still says `NSApplication`,
`AitmApplication.swift` does not exist, `snap-dev.sh` has no `plutil -replace NSPrincipalClass`), and only
then are the production edits made and the suite run green. Both outputs go in the Coder's report.

Why a single task and not two: the four checks of the test file (D6's three plus the AC9 template-render
check) read the same three files the production edits touch, and splitting the plist edit from the subclass
would leave an intermediate commit whose bundle names a class that does not exist (a launch crash). There is
no fan-out; there are no independent tasks.

**Not Coder work.** The live proof (AC1-AC8, spec D7), the gate run of AC12 (`grid-lint`, the three
`check-*.sh` tripwires, a launched `snap-dev.sh` bundle, `selftest-live-embedded.sh`), and the AC10 negative
control (flip `Info.plist.in` to `NSApplication` once, watch the suite fail, revert) belong to the orchestrating
session in the Terminal after Task 1 is committed. The Coder's `Done when` is the unit suite, the typecheck and
the build; it must not launch a dev bundle, drive System Events, or read `log show`.

**Environment adaptation (read before dispatching Task 1).** SwiftPM cannot run inside the Claude Bash
sandbox (memory `sandbox-swift-and-git-switch-quirks`). The Coder runs every `swift build` and `swift test`
through the Terminal panel tool `mcp__terminal__run_in_terminal`, reads the output back, and quotes it. The
three commands, all from `WT/apps/mac`:

```
swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter PrincipalClassTests
swift build --scratch-path ~/Library/Developer/Aitmproxy/qes-build
swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build
```

If `mcp__terminal__run_in_terminal` is not available to the Coder, it reports **BLOCKED** with those exact
commands and the two commits it made, and does not claim a pass. Inside the sandbox it may still typecheck
the executable target with the in-process plugin recipe (memory `sandbox-swift-typecheck-in-process-plugins`)
as a fast pre-check; that is not evidence of a pass. Commits are by explicit path (`git add <file>`; never
`git add -A`); the shared stash is never used.

## Tasks

### Task 1: `AitmApplication` principal class, its two bundle homes, and the drift guard

- **Satisfies:** AC9, AC10 (the green run; the negative control is the orchestrator's), AC11; and is the
  whole production change behind AC1-AC8 and AC12, which the orchestrating session proves live.
- **Depends on:** none.
- **Files:**
  - `apps/mac/Tests/AitmproxyKitTests/PrincipalClassTests.swift` (create; commit (a))
  - `apps/mac/Sources/Aitmproxy/AitmApplication.swift` (create; commit (b))
  - `apps/mac/Info.plist.in` (modify, line 16 only; commit (b))
  - `apps/mac/tools/snap-dev.sh` (modify, insert after line 58; commit (b))
  - `apps/mac/CLAUDE.md` (modify, one Layout bullet; commit (b))
  - Nothing else. `App.swift`, `SelfTest.swift`, `Bus/EmbeddedCoreController.swift`, `build.sh`,
    `tests/e2e/acceptance/`, `crates/` are not opened for editing (AC11).

- **Change:**

  **(a) The test, first.** `PrincipalClassTests.swift` in Swift Testing (`import Testing`, `@Suite struct
  PrincipalClassTests`, `@Test`, `#expect`, `#require`; the framework and the `#filePath` idiom of
  `CommandMapTests.swift:8-10`). It needs `import Foundation` for `URL` and `String(contentsOf:encoding:)`;
  it does not need `@testable import AitmproxyKit` (it reads files, not Kit symbols). Shape:

  - `static let macRoot: URL` = `URL(fileURLWithPath: #filePath)` with `deletingLastPathComponent()` three
    times (test file → `AitmproxyKitTests` → `Tests` → `apps/mac`), as `CommandMapTests.briefURL` does.
  - `static let principalClass = "AitmApplication"` — the single spelling of the literal in the test
    (spec D6: "spelled once in the test"). Every assertion below interpolates it.
  - `static func text(_ relativePath: String) throws -> String` reading
    `macRoot.appending(path: relativePath)` as UTF-8.
  - Four tests (the first three are D6's items 1-3; the fourth is AC9):
    1. `theSourceDeclaresThePrincipalClassAsAnObjCNamedNSApplicationSubclass`: the text of
       `Sources/Aitmproxy/AitmApplication.swift` contains
       `"@objc(\(principalClass)) final class \(principalClass): NSApplication"`.
    2. `theTemplateNamesThePrincipalClassOnceAndNoLongerStockNSApplication`: the text of `Info.plist.in`
       has exactly one occurrence of `"<key>NSPrincipalClass</key><string>\(principalClass)</string>"`
       (count via `components(separatedBy:)` minus one, or a `ranges(of:)` count) and does not contain
       `"<string>NSApplication</string>"` (the negative control for the old value).
    3. `theDevBundleScriptWritesThePrincipalClassWithoutSpellingIt`: the text of `tools/snap-dev.sh`
       contains `"plutil -replace NSPrincipalClass"` and does not contain `principalClass`.
    4. `aPlistRenderedFromTheTemplateByTheReleaseSedCarriesThePrincipalClass` (AC9): take the template
       text, replace `__BUILD__` with `"0"` and `__VERSION__` with `"0.0.0"` in Swift (the same two
       substitutions `build.sh:98` makes with `sed`; no process is spawned), and assert the result contains
       `"<key>NSPrincipalClass</key><string>\(principalClass)</string>"`. The point is that the release
       plist is the template verbatim apart from those two tokens, so the Kit test is proof of the
       installed bundle's value without an install.

  Doc comment on the suite: one or two lines citing the spec and saying these are the three homes of the
  name plus the release-plist check.

  **(b) The production edits, only after the red run is recorded.**

  1. `apps/mac/Sources/Aitmproxy/AitmApplication.swift` (new). `import AppKit`. One type:

     ```swift
     @objc(AitmApplication) final class AitmApplication: NSApplication
     ```

     with exactly one override:

     ```swift
     override func terminate(_ sender: Any?)
     ```

     The executable target has `defaultIsolation(MainActor.self)` and `NSApplication` is main-actor, so no
     isolation annotations (spec Constraints). Body, in prose (spec D2, D3; the loop form is the builder's):
     end the innermost attached sheets first, on every window in `NSApp.windows` (not just the key window),
     by repeatedly finding a window whose `sheetParent` is non-nil and whose own `attachedSheet` is nil and
     asking its `sheetParent` to `endSheet(_:)` it; stop when no window has an attached sheet, or after a
     bound equal to the number of entries in `NSApp.windows` at entry (Architect's call 2: the loop must
     terminate even if `endSheet` fails to detach). Then, unconditionally and on the same call, call
     `super.terminate(sender)`. The override must not call `exit`, `_exit`,
     `replyToApplicationShouldTerminate`, present any alert, beep, or inspect what a sheet shows (spec
     Anti-goals, D4). The doc comment on the class cites the spec path and the log line
     `App termination blocked by modal sheet`, and says why the walk runs before `super`: AppKit's modal-sheet
     check runs before `applicationShouldTerminate`. The existing one-level loop in `SelfTest.finish`
     (`SelfTest.swift:158`) is the model for the AppKit calls and is left untouched (Architect's call 1).

  2. `apps/mac/Info.plist.in` line 16: `<key>NSPrincipalClass</key><string>NSApplication</string>` becomes
     `<key>NSPrincipalClass</key><string>AitmApplication</string>`. No other line changes; `build.sh:98`
     then picks it up with no change.

  3. `apps/mac/tools/snap-dev.sh`, immediately after line 58 (`plutil -replace CFBundleExecutable ...`),
     outside the `if/else` so it runs on both the borrowed-plist and the template branches: read the value
     from the template with `plutil -extract NSPrincipalClass raw -o - "$here/Info.plist.in"` into a
     variable, then `plutil -replace NSPrincipalClass -string "$value" "$dev/Contents/Info.plist"`. The
     literal `AitmApplication` must not appear anywhere in the script (D5, Architect's call 4; test 3
     enforces it). A two-line comment saying why (the borrowed installed plist predates the subclass and
     would silently run stock `NSApplication`, spec Anti-goals). Keep `set -u` happy: the variable is
     assigned before use. Optional: an `echo "== principal class $value"` beside the `== bundle` line
     (builder's choice, spec "Left to the builder"). The extract form was verified on the current template
     from the sandbox: it prints the bare value and exits 0.

  4. `apps/mac/CLAUDE.md`, Layout section: extend the first bullet (or add one after it) with one sentence
     naming `AitmApplication.swift` as the `NSApplication` subclass named by `Info.plist.in`'s
     `NSPrincipalClass`, whose `terminate(_:)` ends open sheets so Quit is never refused. No change to the
     gate list; the SIGTERM-handler follow-up note stays as is (spec Non-goals).

- **Test:**
  - Red, after commit (a) and before any production edit, in the Terminal from `WT/apps/mac`:
    `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter PrincipalClassTests`
    exits non-zero. Expected: test 1 fails by throwing (the file does not exist, so `text(_:)` throws and
    the test is recorded as a failure), tests 2, 3 and 4 fail on `#expect` (template has
    `<string>NSApplication</string>` and zero `AitmApplication`; script has no `plutil -replace
    NSPrincipalClass`). The summary line reports `4 tests` with `4` failed (Swift Testing's phrasing, e.g.
    `Suite PrincipalClassTests failed after ... with 4 issues`) — the exact count and the names of the four
    failing tests are quoted in the report.
  - Green, after commit (b), same command: `Test run with 4 tests passed after ... seconds` for the filter;
    all four names listed as passed.
  - Independent plist facts the Coder also quotes (sandbox-safe, read-only):
    `plutil -extract NSPrincipalClass raw -o - apps/mac/Info.plist.in` prints exactly `AitmApplication`;
    `grep -c AitmApplication apps/mac/tools/snap-dev.sh` prints `0`;
    `grep -c 'plutil -replace NSPrincipalClass' apps/mac/tools/snap-dev.sh` prints `1`.
  - `git diff --stat BASE..HEAD` lists exactly the five `apps/mac/` paths above plus the spec and this plan
    under `docs/superpowers/`, nothing else (AC11).

- **Done when:** the red and green outputs above are both in the Coder's report; `swift build --scratch-path
  ~/Library/Developer/Aitmproxy/qes-build` completes with no errors and no new warnings in
  `AitmApplication.swift`; the full `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`
  passes (every existing suite still green); the two commits are on `claude/gallant-hawking-61d70e` with
  messages saying what the user can now do (the second one: quitting with a sheet open now quits).
  `cargo` gate: no Rust file changes, so `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test` is unaffected; the Tester runs it once on the whole branch as the workflow requires.

## After Task 1 (orchestrating session, not a Coder)

Recorded here so the plan is the single order of work; none of it is a task.

1. Tester on the whole branch (`BASE..HEAD`): maps AC9-AC11 to the four tests and the diff stat; runs the
   full `swift test` and the Rust gate; checks the override body against the spec's Anti-goals (no `exit`,
   no alert, `super` always called) by reading `AitmApplication.swift`.
2. AC10 negative control in the Terminal: edit `Info.plist.in` to `NSApplication`, run the filtered suite,
   quote the failure of test 2 (and test 4), `git checkout -- apps/mac/Info.plist.in`.
3. AC12 gate: `tools/grid-lint.sh`, the three `check-*.sh`, `DEV_TAG=qes tools/snap-dev.sh` (launches),
   `tools/selftest-live-embedded.sh`.
4. AC8: `NO_LAUNCH=1 DEV_TAG=qes tools/snap-dev.sh`, then `plutil -extract NSPrincipalClass raw
   /tmp/Aitmproxy-dev-qes.app/Contents/Info.plist` prints `AitmApplication`; the installed bundle's plist
   prints `NSApplication` (negative control).
5. Live proof AC1-AC7 per spec D7 on the dev bundle with its own `APP_STORE` and a named
   `APP_DEFAULTS_SUITE`, driving `Aitmproxy-qes` by process name through System Events, never
   `tell application id`; the AC7 `scutil --proxy` machine-state check only with Matt's written yes.
6. Panel (security, quality, spec reviewers) on `BASE..HEAD` with the Coder's and Tester's reports.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
