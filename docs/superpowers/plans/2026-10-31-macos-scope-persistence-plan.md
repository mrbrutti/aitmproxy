# macOS Scope persistence across embedded-core restarts — implementation plan

**Status:** approved — self-approved 2026-10-31 by the owning session (autonomous mode)
**Spec:** `docs/superpowers/specs/2026-10-31-macos-scope-persistence-design.md`
(approved 2026-10-31; acceptance criteria SP-AC1 … SP-AC20)
**Branch / worktree:** `claude/nostalgic-grothendieck-467410`
(`/Users/matt/Security/aitmproxy/.claude/worktrees/nostalgic-grothendieck-467410`,
cut from main `4944058`; the nominal `feat/macos-scope-persistence` is superseded —
this worktree ships as one PR to main)

**Environment adaptation:** coder sub-agents run with a sandboxed Bash that cannot
write `~/Library/Developer`, so Swift coders write code + tests and run only
sandbox-safe checks (`swiftc -parse -module-cache-path "$TMPDIR/mc" <files>` for
syntax; `swift build --scratch-path "$TMPDIR/aitm-swift-build" --target AitmproxyKit`
*if* the sandbox permits — a sandbox-caused failure is not a code failure and must
be reported as such, not worked around); they do **not** build the app, run
`swift test`, or `git commit`. The owner runs the authoritative
`swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`, `./build.sh`
/ `snap-dev.sh`, `tools/selftest.sh`, `tools/selftest-live.sh`, and the full Rust
gate in the Terminal panel, and **commits each task**. The Rust coder (Task 3) may
run `cargo test -p aitm --test config_file`, `cargo fmt --check` and
`cargo clippy --all-targets -- -D warnings` in the sandbox (cargo works offline
after a Terminal-panel fetch; if a fetch is needed, report it and the owner runs
the gate). Every Coder report quotes the red run and the green run it was able to
produce, and names the checks it could not run.

## Overview

Four tasks. **Wave A** fans out three independent, file-disjoint tasks in parallel:
Task 1 (Kit model `EmbeddedScope`), Task 2 (Kit config emission in
`EmbeddedCoreLaunch`), Task 3 (one Rust parse test). **Wave B** is Task 4 (app
wiring: spawn reads the file, add/remove write it, launch seeds the display, the
self-tests prove the guards), which depends on Tasks 1 and 2 compiling. Then the
whole-branch Tester (every SP-AC) and the three-reviewer panel.

- **Wave A (parallel, independent):** Task 1 ∥ Task 2 ∥ Task 3.
- **Wave B (sequential):** Task 4 (depends on Tasks 1, 2).
- **Then:** owner runs `swift test` + Rust gate + `tools/selftest.sh` +
  `tools/selftest-live.sh` + Manual verification; whole-branch Tester; panel.

Cross-task note: Task 2's tripwire test
`scope_block_text_is_what_the_core_round_trip_test_parses` reads
`crates/aitm/tests/config_file.rs` and is green only once Task 3's test exists
with the exact literal below. The two tasks still touch disjoint files; the owner
runs `swift test` after Wave A completes, not per task.

**Rust gate** (unchanged production Rust; Task 3 adds a test):
`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
**Mac gate:** `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`,
`tools/selftest.sh` (exit 0), `tools/selftest-live.sh` against an external core
(exit 0), and the Manual verification at the end. No UI file changes, so no
snapshot diff is expected; the owner still glances at the Scope page light/dark
after a relaunch.

**Do-not-touch (owned by a concurrent session):**
`apps/mac/Sources/Aitmproxy/Shell/ShellView.swift`,
`apps/mac/Sources/Aitmproxy/SettingsView.swift`,
`apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`,
`apps/mac/Sources/Aitmproxy/CaptureAdvice.swift`. A Coder that believes its task
needs a change in one of these **stops and reports**.

**Stop-and-report rule:** if a Coder finds that the core does not parse the
emitted block, that `ProxyBuilder::build` does not seed the guard from
`config.scope.entries`, or that any production Rust change is needed, it stops and
reports instead of editing `crates/`.

**The shared literal** (Tasks 2 and 3 must spell it identically; Swift as one
string with `\n`/`\"` escapes, Rust as one plain `"…"` string literal, no
concatenation, no raw string):

```
scope:\n  entries:\n    - "api.example.test"\n    - "*.shop.test"\n    - "localhost:8099"\n
```

---

## Tasks

### Task 1: Kit model — `EmbeddedScope`

- **Satisfies:** SP-AC14, SP-AC15, SP-AC18; the `[kit]` halves of SP-AC1, SP-AC8(a),
  SP-AC10.
- **Depends on:** none.
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/EmbeddedScope.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/EmbeddedScopeTests.swift` (create)
- **Change:** a new public Codable value type, modelled on `Pins.swift`, plus three
  pure helpers. Exact signatures:

  ```swift
  public struct EmbeddedScope: Codable, Hashable, Sendable {
      public var hosts: [String]
      public init(hosts: [String] = [])
      public static func url(in store: URL) -> URL                       // store.appending(path: "scope.json")
      public static func load(from url: URL) -> EmbeddedScope            // missing/unreadable/undecodable → EmbeddedScope(); hosts = sanitized(decoded.hosts)
      public func save(to url: URL) throws                               // JSONEncoder prettyPrinted+sortedKeys; createDirectory(withIntermediateDirectories:); write(options: .atomic)
      public static func sanitized(_ hosts: [String]) -> [String]        // trim .whitespacesAndNewlines; keep iff isPersistable; drop later duplicates; order kept
      public static func isPersistable(_ host: String) -> Bool           // Scope.validate(host) == nil && host.rangeOfCharacter(from: .newlines.union(.controlCharacters)) == nil
      public static func seedsAtLaunch(activeKind: ActiveCoreKind, bundledCorePresent: Bool, usesFixtures: Bool) -> Bool
                                                                         // !usesFixtures && activeKind == .embedded && bundledCorePresent
  }
  ```

  `Scope.validate` is `AitmproxyKit.Scope.validate(_:)` in `Compose.swift`
  (do not edit it). `ActiveCoreKind` is in `ActiveConnection.swift`. The doc
  comment on the type states: the **embedded** core's operator scope only; JSON
  `{"hosts": [...]}`; written by the app after an operator Scope action, read at
  every embedded spawn; never written in fixture mode or for an external core.
- **Test:** `@Suite struct EmbeddedScopeTests` in the new test file (Swift Testing,
  `@testable import AitmproxyKit`, temp files under `$TMPDIR` or
  `FileManager.default.temporaryDirectory` with a UUID name, removed in `defer`):
  - `roundTripsThroughAFile`: save `EmbeddedScope(hosts: ["api.example.test", "*.shop.test"])`;
    `#expect(EmbeddedScope.load(from: url) == EmbeddedScope(hosts: ["api.example.test", "*.shop.test"]))`. (SP-AC18)
  - `missingFileLoadsEmpty`: `#expect(EmbeddedScope.load(from: url.appendingPathExtension("missing")) == EmbeddedScope())`
    and `.hosts == []`. (SP-AC15)
  - `corruptFileLoadsEmpty`: write `Data("{not json".utf8)` → `== EmbeddedScope()`;
    write `Data(#"{"hosts": "x"}"#.utf8)` → `== EmbeddedScope()`. (SP-AC15)
  - `loadDropsInvalidAndDuplicateEntries`: write the bytes
    `{"hosts": ["api.example.test", " api.example.test ", "*.shop.test", "", "http://x.test", "a b.test", "api.example.test", "bad\nhost.test", "localhost:8099"]}`
    (the `\n` inside `bad\nhost.test` is a real newline in the JSON string, i.e.
    the JSON escape `\n`); `#expect(EmbeddedScope.load(from: url).hosts == ["api.example.test", "*.shop.test", "localhost:8099"])`. (SP-AC14)
  - `sanitizedKeepsOrderAndFirstOccurrence`:
    `#expect(EmbeddedScope.sanitized(["b.test", "a.test", "b.test", "  a.test"]) == ["b.test", "a.test"])`.
  - `isPersistableRejectsControlCharactersScopeValidateAccepts`:
    `#expect(Scope.validate("bad\nhost.test") == nil)` (documents why the rule exists),
    `#expect(!EmbeddedScope.isPersistable("bad\nhost.test"))`,
    `#expect(!EmbeddedScope.isPersistable("bad\rhost.test"))`,
    `#expect(EmbeddedScope.isPersistable("localhost:8099"))`,
    `#expect(EmbeddedScope.isPersistable("*.shop.test"))`,
    `#expect(!EmbeddedScope.isPersistable(""))`.
  - `urlEndsInScopeJSONBesideThePins`: with `store = URL(fileURLWithPath: "/tmp/store", isDirectory: true)`,
    `#expect(EmbeddedScope.url(in: store).lastPathComponent == "scope.json")` and
    `#expect(EmbeddedScope.url(in: store).deletingLastPathComponent().path == "/tmp/store")`. (SP-AC18)
  - `emptyScopeRoundTripsAsAnEmptyList`: save `EmbeddedScope()`; the file text
    contains `"hosts"`; `load(from:) == EmbeddedScope()`.
  - `seedsAtLaunchOnlyForEmbeddedWithABundledCoreOutsideFixtures`:
    `seedsAtLaunch(activeKind: .embedded, bundledCorePresent: true,  usesFixtures: false) == true`,
    `seedsAtLaunch(activeKind: .external, bundledCorePresent: true,  usesFixtures: false) == false`,
    `seedsAtLaunch(activeKind: .embedded, bundledCorePresent: false, usesFixtures: false) == false`,
    `seedsAtLaunch(activeKind: .embedded, bundledCorePresent: true,  usesFixtures: true)  == false`.
    (SP-AC1, SP-AC8(a), SP-AC10)
  TDD: write the test file first (it fails to compile — the type does not exist);
  then the model; the owner's `swift test` shows all nine tests passing.
- **Done when:** all `EmbeddedScopeTests` pass under the owner's `swift test`;
  no other file changed; the Coder's sandbox syntax check passed.

---

### Task 2: Kit config emission — `scope:` block in the per-launch config

- **Satisfies:** SP-AC4, SP-AC5 (`[kit]` half), SP-AC6, SP-AC16, SP-AC17.
- **Depends on:** none (Task 3 must land before the tripwire test goes green; see
  Overview).
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (modify)
  - `apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift` (modify)
- **Change:**
  1. `EmbeddedCoreLaunch.Config`: add `public var scopeHosts: [String]` with a doc
     comment ("the embedded core's restored operator scope, emitted as
     `scope.entries`; empty → nothing emitted; `allow_agent_widen` is never
     emitted"). Extend the memberwise `public init(... sslInsecure: Bool = false, captureEnabled: Bool = false, scopeHosts: [String] = [])`
     — the new parameter is **last and defaulted** so every existing call site
     compiles unchanged.
  2. `ConfigError`: add `case hostContainsNewline(String)`.
  3. `yaml()`: after the `macos_capture` tail, when `!scopeHosts.isEmpty`, append
     `"\nscope:\n  entries:\n"` followed by `"    - \"\(escaped)\"\n"` per host in
     array order, where `escaped` is the `yamlDoubleQuoted` escaping of the host;
     a host containing `"\n"` or `"\r"` throws `ConfigError.hostContainsNewline(host)`
     (pre-check, or generalise `yamlDoubleQuoted` — builder's choice; the thrown
     case is the contract). Emit no `scope` text at all when empty. Never emit
     `allow_agent_widen`. Update the `yaml()` doc comment: replace "no `scope:`
     block is emitted, so startup scope stays deny-by-default/empty" with "a
     `scope:` block is emitted only when `scopeHosts` is non-empty (the operator's
     persisted embedded scope); `allow_agent_widen` is never emitted, so agents
     remain gated".
  4. In the existing test `generated_config_emits_the_operator_token_alongside_the_agent_token`
     keep both assertions (`!yaml.contains("scope:")`, `!yaml.contains("allow_agent_widen")`)
     and reword its comment to "none for the default, empty scope".
- **Test:** new tests in `EmbeddedCoreLaunchTests` under a `// MARK: Scope block (SP-AC4…)`
  section, with a private helper `config(scopeHosts: [String]) -> EmbeddedCoreLaunch.Config`
  mirroring `config(captureEnabled:)`:
  - `scope_block_is_byte_identical_to_the_core_parse_input`:
    `let yaml = try config(scopeHosts: ["api.example.test", "*.shop.test", "localhost:8099"]).yaml()`;
    `#expect(yaml.hasSuffix("scope:\n  entries:\n    - \"api.example.test\"\n    - \"*.shop.test\"\n    - \"localhost:8099\"\n"))`;
    `lines.filter { $0 == "scope:" }.count == 1`; the line after `scope:` is
    `"  entries:"`; the next three are `"    - \"api.example.test\""`,
    `"    - \"*.shop.test\""`, `"    - \"localhost:8099\""` in that order. (SP-AC4)
  - `scope_block_defaults_to_nothing`: `sampleConfig(...).scopeHosts == []`;
    `!yaml.contains("scope:")`; `!yaml.contains("entries")`. (SP-AC6)
  - `scope_block_never_emits_allow_agent_widen`: both the default YAML and the
    three-host YAML satisfy `!yaml.contains("allow_agent_widen")`. (SP-AC5)
  - `scope_block_escapes_quotes_and_backslashes`:
    `config(scopeHosts: [#"a"b.test"#, #"c\d.test"#]).yaml()` has lines
    `#"    - "a\"b.test""#` and `#"    - "c\\d.test""#`. (SP-AC17)
  - `scope_block_rejects_a_host_with_a_newline`:
    `#expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\nlisten: 0.0.0.0:1")) { try config(scopeHosts: ["ok.test", "evil.test\nlisten: 0.0.0.0:1"]).yaml() }`;
    `#expect(throws: (any Error).self) { try config(scopeHosts: ["evil.test\rx"]).yaml() }`. (SP-AC16)
  - `scope_block_follows_the_ssl_and_capture_tails`: a Config with
    `sslInsecure: true, captureEnabled: true, scopeHosts: ["api.example.test"]`:
    `lines.filter { $0 == "ssl_insecure: true" }.count == 1`,
    `lines.filter { $0 == "macos_capture:" }.count == 1`,
    `lines.filter { $0 == "scope:" }.count == 1`, and
    `lines.firstIndex(of: "ssl_insecure: true")! < lines.firstIndex(of: "macos_capture:")! < lines.firstIndex(of: "scope:")!`;
    and `config(captureEnabled: true).yaml().hasSuffix("macos_capture:\n  enabled: true\n")`
    still holds (scope-less configs are unchanged). (SP-AC4)
  - `scope_block_text_is_what_the_core_round_trip_test_parses` (tripwire, modelled
    on `capture_gate_text_is_what_the_core_round_trip_test_parses`): resolve the
    repo root five levels up from `#filePath`, read
    `crates/aitm/tests/config_file.rs`, and assert it contains
    `fn scope_entries_block_round_trips` and the Rust spelling of the shared
    literal (`"\"" + block.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n") + "\""`).
    Expected green only after Task 3 lands. (SP-AC7 linkage)
  TDD: add the tests first (compile failure on `scopeHosts:`/`hostContainsNewline`),
  then the production change; existing tests `capture_gate_composes_with_ssl_insecure_as_two_top_level_keys`
  and `capture_gate_text_is_what_the_core_round_trip_test_parses` must stay green
  untouched.
- **Done when:** every `EmbeddedCoreLaunchTests` test passes under the owner's
  `swift test` (the tripwire after Task 3); `grep -c "allow_agent_widen" apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift`
  finds it only in comments/doc text, never in an emitted string.

---

### Task 3: Rust — the core parses the exact bytes the app emits

- **Satisfies:** SP-AC7, SP-AC5 (`[rust]` half); the Rust half of SP-AC20.
- **Depends on:** none.
- **Files:**
  - `crates/aitm/tests/config_file.rs` (modify — append one test; no other file)
- **Change:** add, after `operator_gate_knobs_load`, a test with a doc comment
  naming the spec and the Swift test it mirrors
  (`EmbeddedCoreLaunchTests.scope_block_is_byte_identical_to_the_core_parse_input`):

  ```rust
  #[test]
  fn scope_entries_block_round_trips()
  ```

  Body: `redirect_home();` then
  `let cfg = parse("scope:\n  entries:\n    - \"api.example.test\"\n    - \"*.shop.test\"\n    - \"localhost:8099\"\n").expect("parse scope entries");`
  — **one plain string literal, exactly as spelled** (Task 2's tripwire greps for
  it). Assertions:
  - `let hosts: Vec<&str> = cfg.scope.entries.iter().map(|e| e.host.as_str()).collect();`
    `assert_eq!(hosts, ["api.example.test", "*.shop.test", "localhost:8099"]);`
  - `assert!(!cfg.scope.allow_agent_widen);`
  - `assert!(parse("scope:\n  entries: []\n").expect("parse empty entries").scope.entries.is_empty());`
  - composition with a sibling top-level key the app also emits:
    `let both = parse("ssl_insecure: true\nscope:\n  entries:\n    - \"api.example.test\"\n").expect("parse");`
    `assert!(both.ssl_insecure);` and `both.scope.entries` hosts `== ["api.example.test"]`.
  `ScopeConfig`/`ScopeEntry` come from `aitm_core::Config` (already imported as
  `Config`); access is by field (`cfg.scope.entries[i].host`).
- **Test:** `cargo test -p aitm --test config_file scope_entries_block_round_trips`
  prints `test scope_entries_block_round_trips ... ok` and `test result: ok`.
  TDD note: the production parser already accepts this, so the red step is the
  compile error before the test exists / a deliberately wrong expected list
  (`["api.example.test"]`) shown failing, then corrected — the Coder's report
  shows both runs.
- **Done when:** that test passes; `cargo fmt --check` and
  `cargo clippy --all-targets -- -D warnings` pass (sandbox, or owner);
  `git diff --stat -- crates/` lists only `crates/aitm/tests/config_file.rs`.

---

### Task 4: App wiring — read at spawn, write on add/remove, seed at launch, prove the guards

- **Satisfies:** SP-AC1, SP-AC2, SP-AC3, SP-AC8(b)(c), SP-AC9, SP-AC10 (`[selftest]`),
  SP-AC11, SP-AC12, SP-AC13, SP-AC19; the Swift half of SP-AC20.
- **Depends on:** Task 1 (`EmbeddedScope`), Task 2 (`Config.scopeHosts`).
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Session.swift` (modify)
  - `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify)
  - `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (modify)
  - `apps/mac/Sources/Aitmproxy/SelfTest.swift` (modify — one fixture check)
  - `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift` (modify — two live checks)
  - Optional, builder's choice (spec "Left to the builder"):
    `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCoreController.swift` only if the scope
    URL is injected at `EmbeddedCore.init` instead of `await Store.url`.
  - **Not** `ShellView.swift`, `SettingsView.swift`, `ExtensionController.swift`,
    `CaptureAdvice.swift`, nor any Panels file.
- **Change:**
  1. **`Session.swift`** — beside `pinsURL` (line ≈265):
     `var scopeURL: URL { EmbeddedScope.url(in: Store.url) }`. In `init()`, after
     `if !Store.usesFixtures { pins = Pins.load(from: pinsURL) }`:
     ```swift
     if EmbeddedScope.seedsAtLaunch(activeKind: UserDefaultsActiveKindPersistence().load() ?? .embedded,
                                    bundledCorePresent: EmbeddedCore.discoverBundled() != nil,
                                    usesFixtures: Store.usesFixtures) {
         scopeHosts = EmbeddedScope.load(from: scopeURL).hosts
     }
     ```
     with a comment: the Scope page shows the embedded core's persisted scope before
     the bus connects; `refreshScope()` replaces it with the core's `scope.list` on
     connect (D5). `loadFixtures()` is unchanged.
  2. **`BusService.swift`** — change `private func refreshScope() async` to
     `@discardableResult private func refreshScope() async -> Bool` (true iff
     `scope.list` succeeded and `session.scopeHosts` was assigned); add
     `private func persistEmbeddedScope()` that returns early unless
     `preferEmbedded && !Store.usesFixtures`, else
     `try? EmbeddedScope(hosts: session.scopeHosts).save(to: session.scopeURL)`.
     In `addScope` and `removeScope`: `if await refreshScope() { persistEmbeddedScope() }`.
     The call in `run()` stays `await refreshScope()` (discarded) — **no write on
     connect**. Doc comments state the snapshot semantics (D4) and that this is the
     only writer of `scope.json`.
  3. **`EmbeddedCore.swift`** — in `spawn()`, beside the fresh `UserDefaults`
     reads, read `let scopeHosts = EmbeddedScope.load(from: EmbeddedScope.url(in: await Store.url)).hosts`
     (or from an injected URL) **every spawn**, and pass `scopeHosts: scopeHosts`
     into `EmbeddedCoreLaunch.Config(...)`. Comment: restored operator scope rides
     the per-launch config so relaunch, crash-restart and Apply & Restart Core keep
     it; nothing is pushed over the bus (D3). Also update the actor doc's "Launch"
     bullet.
  4. **`SelfTest.swift`** — after the S-014 pins block (≈line 104), a fixture guard:
     ```swift
     session.addScope("persist-probe.test")
     await settle { session.scopeHosts.contains("persist-probe.test") }
     check("fixture mode never persists scope (no scope.json under Store.url)",
           !FileManager.default.fileExists(atPath: session.scopeURL.path) && EmbeddedScope.load(from: session.scopeURL).hosts.isEmpty)
     session.removeScope("persist-probe.test")
     await settle { !session.scopeHosts.contains("persist-probe.test") }
     ```
  5. **`SelfTest+Live.swift`** — immediately **before** the existing
     `session.addScope(upstream)`:
     `check("connecting issues no scope.add", !session.activity.visible.contains { $0.origin == .operator && $0.command == "scope.add" })`;
     and immediately **after** the existing `check("scope.add lands in scope.list", …)`:
     `check("an external core never writes scope.json", !FileManager.default.fileExists(atPath: session.scopeURL.path))`.
- **Test:** owner-run, with these literal PASS lines expected in the output:
  - `tools/selftest.sh` → `PASS fixture mode never persists scope (no scope.json under Store.url)`
    and the final `SELFTEST PASS <n> checks` with exit 0. (SP-AC10)
  - `AITM_CONFIG=… tools/selftest-live.sh` (external core + `python3 -m http.server 8099 --bind 127.0.0.1`)
    → `PASS connecting issues no scope.add` and
    `PASS an external core never writes scope.json`, exit 0. (SP-AC8(b), SP-AC9)
  - `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` → all
    green (Tasks 1–2 tests included). The app target has no unit-test target; its
    behaviour is proven by the self-tests above and the Manual verification below
    (SP-AC1, SP-AC2, SP-AC3, SP-AC11, SP-AC12, SP-AC13).
  - Sandbox-safe for the Coder: `swiftc -parse` on the five files; `grep -n '"scope.add"' apps/mac/Sources/Aitmproxy/Bus/BusService.swift`
    prints exactly one line (inside `addScope`) (SP-AC9 review aid);
    `git diff --name-only` contains none of the do-not-touch files.
  TDD: add the self-test checks first (they fail: `scopeURL` does not exist), then
  the production wiring; the owner's `tools/selftest.sh` run is the green step.
- **Done when:** the three owner-run commands above pass with the literal PASS
  lines; `./build.sh` (or `snap-dev.sh`) builds with no new warnings; the Manual
  verification done criterion holds; no hunk in a do-not-touch file.

---

## Parallelization

| Task | Files | Independent of | Wave |
|---|---|---|---|
| 1 Kit model | `AitmproxyKit/EmbeddedScope.swift`, `AitmproxyKitTests/EmbeddedScopeTests.swift` | 2, 3 | A |
| 2 Kit emission | `AitmproxyKit/EmbeddedCoreLaunch.swift`, `AitmproxyKitTests/EmbeddedCoreLaunchTests.swift` | 1, 3 (tripwire waits for 3) | A |
| 3 Rust test | `crates/aitm/tests/config_file.rs` | 1, 2 | A |
| 4 App wiring | `Aitmproxy/Session.swift`, `Aitmproxy/Bus/BusService.swift`, `Aitmproxy/Bus/EmbeddedCore.swift`, `Aitmproxy/SelfTest.swift`, `Aitmproxy/SelfTest+Live.swift` (opt. `Bus/EmbeddedCoreController.swift`) | — (needs 1, 2) | B |

## Traceability

| Spec AC | Proven by |
|---|---|
| SP-AC1 | Task 1 `seedsAtLaunch…` (kit) + Manual step 3 |
| SP-AC2, SP-AC3 | Manual steps 2, 5 + panel review of `persistEmbeddedScope` |
| SP-AC4 | Task 2 `scope_block_is_byte_identical_to_the_core_parse_input`, `scope_block_follows_the_ssl_and_capture_tails` |
| SP-AC5 | Task 2 `scope_block_never_emits_allow_agent_widen` + Task 3 `!allow_agent_widen` |
| SP-AC6 | Task 2 `scope_block_defaults_to_nothing` + existing `generated_config_emits_the_operator_token_alongside_the_agent_token` |
| SP-AC7 | Task 3 `scope_entries_block_round_trips` + Task 2 tripwire |
| SP-AC8 | Task 1 `seedsAtLaunch…` (a) + Task 4 live check (b) + review (c) |
| SP-AC9 | Task 4 live check + grep review aid |
| SP-AC10 | Task 4 fixture check + Task 1 `seedsAtLaunch…` + review of the refusal guards |
| SP-AC11 | Manual step 3 + `git diff` shows no `ShellView.swift` hunk |
| SP-AC12 | Manual step 6 |
| SP-AC13 | Manual step 4 |
| SP-AC14 | Task 1 `loadDropsInvalidAndDuplicateEntries`, `isPersistableRejectsControlCharactersScopeValidateAccepts` |
| SP-AC15 | Task 1 `missingFileLoadsEmpty`, `corruptFileLoadsEmpty` |
| SP-AC16 | Task 2 `scope_block_rejects_a_host_with_a_newline` |
| SP-AC17 | Task 2 `scope_block_escapes_quotes_and_backslashes` |
| SP-AC18 | Task 1 `roundTripsThroughAFile`, `urlEndsInScopeJSONBesideThePins` |
| SP-AC19 | Panel review of `addScope`/`removeScope` (`if await refreshScope() { … }`) |
| SP-AC20 | Owner's gates + `git diff --stat` |

## Manual verification (Terminal panel, owner)

Prerequisites: a signed dev build installed via `snap-dev.sh` (never `./build.sh`
per the redesign memory), Settings ▸ Bus = Embedded, an upstream to hit (e.g.
`python3 -m http.server 8099 --bind 127.0.0.1`). Use the operator's real store
only for this check (it is the point); note the pre-existing contents of
`~/Library/Application Support/Aitmproxy/scope.json` if any.

1. **Clean start.** Launch the app; the Scope page is empty and, once connected,
   the "No scope set" banner shows (baseline).
2. **Add persists (SP-AC2).** Add `localhost:8099` on the Scope page. Then
   `cat ~/Library/Application\ Support/Aitmproxy/scope.json` shows
   `"hosts" : [ "localhost:8099" ]` (pretty-printed).
3. **Relaunch display + banner (SP-AC1, SP-AC11) — the done criterion.** Quit
   (⌘Q) and relaunch. Before and after the bus connects, the Scope page lists
   `localhost:8099`; the banner does not appear. The new child's generated config
   `ls -t $TMPDIR/aitm-embedded-core/*/config.yaml | head -1 | xargs grep -A3 '^scope:'`
   prints `scope:` / `  entries:` / `    - "localhost:8099"`. (The app's
   `TMPDIR` is the per-user `$(getconf DARWIN_USER_TEMP_DIR)`; if the work dir is
   elsewhere, Proxy ▸ Core Log shows the config path at spawn.) `curl -x 127.0.0.1:8080 http://localhost:8099/`
   produces an in-scope (not read-only) flow.
4. **Apply & Restart Core keeps scope (SP-AC13).** Settings ▸ Proxy, change the
   preferred port, Apply & Restart Core. After the core is ready, the Scope page
   still lists `localhost:8099` and the new child's `config.yaml` carries the
   block.
5. **Remove persists (SP-AC3).** Remove `localhost:8099`. `scope.json` now reads
   `"hosts" : [ ]` (file still present). Quit, relaunch: the Scope page is empty
   and the banner shows again; the new config has no `scope:` line.
6. **NE first Scope frame (SP-AC12), if the capture extension is installed.**
   Re-add `localhost:8099`, enable Capture, quit, relaunch. With no Scope edit
   this run, a request from a non-curl app to `localhost:8099` is claimed by the
   extension and appears in the app (or the provider log recipe from memory
   `aitmproxy-ne-live-capture-diagnosis` shows the first Scope frame carrying
   `localhost:8099`).
7. **External core untouched (SP-AC8).** Settings ▸ Bus = External pointing at a
   running `aitm`; quit, relaunch: the Scope page shows the external core's scope
   (not `localhost:8099`), and adding a host there does not change
   `scope.json`'s mtime. Switch back to Embedded afterwards.
8. **Restore the operator's store** to its pre-check state if the operator had a
   scope set before step 1.

Done criterion (brief): add a host, quit, relaunch → the host is still in scope;
the new core's `config.yaml` carries the block; with capture on the extension
honours it.

## Review log

Stage 5 + 6 on the whole branch `4944058..be251fb`, 2026-10-31. Tester = FAIL (1 finding, F1)
with 21 tests added (committed as `967115c`). Security = FAIL (1 Important, 2 Minor). Quality =
PASS (3 Minor). Spec = PASS on the diff (1 Important verification gate: the `[manual]` steps).
Dispositions by the owning session (autonomous mode). **Fixed in the panel fix wave** (one
Coder fix task over the findings report `scope-persistence-FIX-FINDINGS.md` in the shared notes
folder; commit recorded in Shipped). The spec's "Panel amendments" subsection records the
ratified behaviour changes. **Re-review of the fix range `be251fb..60273db`:** security PASS
(2 new Minor), quality PASS (3 new Minor), spec FAIL (1 Important: unrequested public API; 2 doc
Minor) → fix wave 2 (rows 9–16).

| # | Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|---|
| 1 | 2 | Tester | Important (SP-AC16 contract) | `yamlDoubleQuoted` guards with Character-based `contains("\n")`; a CRLF grapheme passes, so a CRLF host does not throw | FIX — scalar-based guard; red test `scope_block_rejects_a_crlf_host` goes green — fix wave |
| 2 | 1 | Security | Important | `isPersistable` lets U+FFFE/U+FFFF through (Cn, not Cc/Cf); libyaml refuses them → config parse fails → 5 restarts → `failPermanently`, unrecoverable from the UI | FIX — libyaml-printable allow-list in `isPersistable` + Kit tests — fix wave |
| 3 | 1 | Security | Minor | `scope.json` read with no type/size/count/length cap (FIFO or multi-GB file; quadratic guard seeding) | FIX — regular-file + 1 MiB check in `load`; 10 000-entry / 1 024-char caps in `sanitized` — fix wave |
| 4 | 4 | Security | Minor | Swallowed save failure after a remove resurrects the host next launch | FIX — `persistEmbeddedScope() throws BusError.tool("Scope change not saved: …")`, landing in `lastError` as `"<action>: Scope change not saved: …"` via `Session.perform` — `55d0e9c`; supersedes OQ1's default; `[review]` (no app-target unit tests; chain verified by the spec and security re-reviews) |
| 5 | 4 | Quality | Minor | `preferEmbedded` read after two suspension points; a Bus switch mid-action could persist the other core's list | FIX — snapshot before the verb, require both — `68989ee`; `[review]` |
| 6 | 2 | Quality | Minor | The `\r` assertion accepts any error | FIX — assert `hostContainsNewline("evil.test\rx")` — fix wave |
| 7 | 4 | Quality | Minor | Seventh copy of `UserDefaultsActiveKindPersistence().load() ?? .embedded` | ACCEPTED — follow-up: add `loadOrDefault()` in Kit and point all seven sites at it (consolidation touches `SettingsView.swift`, owned by a concurrent session) |
| 8 | 4 | Spec | Important (gate) | `[manual]` SP-AC1/3/11/12/13 halves not evidenced in the logs at review time | RUN — `scope-persist-live-proof.sh` (shared notes): keystroke add → `scope.json`; Cmd-Q + relaunch → block + `scope.list` + screenshot with no banner (SP-AC1 display after connect, SP-AC11); Proxy ▸ Restart Core (same `restartCoreTick` path as Settings' Apply and Restart Core) keeps scope (SP-AC13); row ✕ remove → `scope.list []`, file kept as `{"hosts": []}` (SP-AC3). PASS, `/tmp/scope-persist-live-proof-full.log`. SP-AC12 ACCEPTED by reasoning: feeder sends `Scope(current_scope_spec())` right after Hello from `l7_guard.list_scope()`, which the config seeded and `scope.list` proved; the installed extension build belongs to the concurrent NE session's live run, so no second capture-enabled core was started — follow-up: observe the first Scope frame on the next NE live session. The pre-connect instant of SP-AC1 was not captured on screen; the seed is pinned by `seedsAtLaunch…` and the post-connect display by the screenshot |
| 9 | 1 | Spec (re-review) | Important | `maxFileBytes`/`maxHosts`/`maxHostLength` added as `public static let` — unrequested public API | FIX — internal `static let` — fix wave 2 |
| 10 | 4 | Security (re-review) | Minor | A failed `scope.list` after a successful verb returns normally (`lastError` cleared) while `scope.json` stays stale | FIX — the Scope action throws `"Scope change applied but not saved: scope.list failed"` when embedded — fix wave 2 |
| 11 | 1 | Security (re-review) | Minor | `save` applies none of `load`'s caps; a list whose JSON exceeds 1 MiB loads empty at the next launch with no signal | FIX — `save` writes `sanitized(hosts)` and throws `SaveError.tooLarge` over 1 MiB (surfaces via row 4's path) — fix wave 2 |
| 12 | 4 | Quality (re-review) | Minor | `addScope`/`removeScope` duplicate a three-line sequence; the why is commented once | FIX — one private `scopeVerb(_:host:)` helper — fix wave 2 |
| 13 | 2 | Quality (re-review) | Minor | `\r` assertion duplicated verbatim in two tests after the Q2 tightening | FIX — deleted from `scope_block_rejects_a_newline_anywhere_in_the_list` — fix wave 2 |
| 14 | 1,2,3,4 | Quality (re-review) | Minor | Provenance tags ("Tester —", "Fix wave —") in test MARKs and doc comments | ACCEPTED — cosmetic; git blame records authorship |
| 15 | 1 | Security (re-review) | residual | TOCTOU between `attributesOfItem` and `Data(contentsOf:)` in `load` | ACCEPTED — same-user only; future fd-based read mirroring `writeConfig` |
| 16 | — | Spec (re-review) | Minor | D4 bullet and row 4 understated the surfaced `lastError` text; rows 4–5 lacked a `[review]` basis | FIXED here (docs) |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
