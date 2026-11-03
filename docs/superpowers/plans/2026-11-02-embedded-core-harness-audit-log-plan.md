# Embedded-core harness audit log implementation plan

**Status:** approved (2026-11-02, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-11-02-embedded-core-harness-audit-log-design.md`
**Branch / worktree:** `claude/serene-villani-38530e` (the app's worktree branch; no `feat/` branch) at
`/Users/matt/Security/aitmproxy/.claude/worktrees/serene-villani-38530e` (called `WT`). Base SHA `61a5ae05`
(`BASE`), clean HEAD. Absolute paths everywhere; never `cd` to the main checkout.

## Overview

One Coder task touching four files, then the Tester on the whole branch, then the orchestrator's live proof
(AC6) in the Terminal, then the panel. Everything is sequential: Task 2 needs Task 1 committed, Task 3 needs
the Task 1 binary, Task 4 needs Tasks 2 and 3. No fan-out. Production code changes in two Swift files only;
the Rust change is one test.

**Environment adaptation (read before dispatching Task 1).** The Coder CANNOT run `swift test` or SwiftPM in
the Claude sandbox. Its Rust red/green is `cargo test -p aitm --offline config_file` in `WT`. For Swift it
typechecks with the in-process plugin recipe (memory `sandbox-swift-typecheck-in-process-plugins`):
`swiftc -emit-module -swift-version 6 -target arm64-apple-macos26.0` for `AitmBusClient`, then `AitmproxyKit`,
into `$TMPDIR/tc`; then `swiftc -typecheck -swift-version 6 -default-isolation MainActor -I $TMPDIR/tc` over
`apps/mac/Sources/Aitmproxy/**/*.swift` with
`-Xfrontend -in-process-plugin-server-path <toolchain>/lib/swift/host/libSwiftInProcPluginServer.dylib` plus
the toolchain and platform `-plugin-path`s (`<toolchain>` =
`$(xcode-select -p)/Toolchains/XcodeDefault.xctoolchain`). The Swift red/green **of record** is the
orchestrator's, in the Terminal: `cd WT/apps/mac && swift test --scratch-path
~/Library/Developer/Aitmproxy/test-build --filter EmbeddedCoreLaunchTests`, run once on the tests-only commit
(red: the new tests fail to compile or fail) and once on the production commit (green). The Coder therefore
makes TWO commits by explicit path (`git add <file>`; never `git add -A`; never `cargo fmt` on the crate
root, rustfmt the leaf file only if needed): (a) tests only, (b) production.

## Tasks

### Task 1: harness audit-log path in the per-launch config

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC7
- **Depends on:** none
- **Files:** `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (modify),
  `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (modify, one call site ~line 197),
  `apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift` (modify, append),
  `crates/aitm/src/config_file.rs` (modify, tests module only, beside `system_proxy_block_the_mac_app_emits_parses` ~line 1261)
- **Change:**
  - `EmbeddedCoreLaunch.Config`: `public var auditLogFile: URL?`; init gains `auditLogFile: URL? = nil` as the
    LAST parameter. `yaml()`: `let auditPath = try auditLogFile.map { try EmbeddedCoreLaunch.yamlDoubleQuoted($0.path) }`
    (or equivalent) and, when non-nil, the line `  audit_log: "<auditPath>"` inserted in `base` directly after
    `  operator_token: "..."` and before `browser:`. Nil emits nothing.
  - `public static func harnessAuditLogFile(environment: [String: String], workDir: URL) -> URL?` on
    `EmbeddedCoreLaunch` (spec Design 2): `APP_STORE` non-empty wins; else `APP_LIVE == "1"` gives
    `workDir.appending(path: "audit.jsonl")`; else `nil`.
  - `EmbeddedCore.spawn`: pass `auditLogFile: EmbeddedCoreLaunch.harnessAuditLogFile(environment:
    ProcessInfo.processInfo.environment, workDir: workDir)` as the last `Config` argument.
  - Rust: `#[test] fn mcp_audit_log_path_the_mac_app_emits_parses()` calling
    `parse("mcp:\n  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n").unwrap()`;
    `use aitm_core::AuditLogSetting` and `std::path::PathBuf` inside the test (or the module's imports).
    No production Rust.
- **Test:** Swift (snake_case, in `EmbeddedCoreLaunchTests`, new `// MARK: Harness audit log` section):
  - `audit_log_is_absent_by_default`: `sampleConfig(endpointFile:)` has `auditLogFile == nil`; its `yaml()` does
    not `contains("audit_log")`. (AC1)
  - `audit_log_line_sits_inside_the_mcp_block_and_is_what_the_core_parses`: `Config(... operatorToken: "11",
    ... auditLogFile: URL(fileURLWithPath: "/tmp/store/audit.jsonl"))` yaml `contains("  operator_token:
    \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\nbrowser:\n")`; and, five `deleteLastPathComponent` from
    `#filePath`, `crates/aitm/src/config_file.rs` contains the Rust literal
    `"mcp:\n  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n"` (as a Rust string, i.e.
    the text `"mcp:\n  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n"` with `\n` and `\"`
    spelled out) and `fn mcp_audit_log_path_the_mac_app_emits_parses()`. (AC2, AC5)
  - `audit_log_path_is_escaped_and_a_newline_is_refused`: `auditLogFile: URL(fileURLWithPath: #"/a/"b"\c/audit.jsonl"#)`
    yaml contains `audit_log: "/a/\"b\"\\c/audit.jsonl"`; a path `"/tmp/x\nlisten: evil"` makes `yaml()` throw
    `ConfigError.pathContainsNewline("/tmp/x\nlisten: evil")`. (AC4)
  - `harness_audit_log_file_follows_the_harness_variables`: with `workDir = URL(fileURLWithPath: "/tmp/wd",
    isDirectory: true)`: `[:]` is nil; `["APP_STORE": ""]` is nil; `["APP_LIVE": "0"]` is nil;
    `["APP_STORE": "/tmp/Aitmproxy-dev-state-x"]` has `.path == "/tmp/Aitmproxy-dev-state-x/audit.jsonl"`;
    `["APP_LIVE": "1"]` has `.path == "/tmp/wd/audit.jsonl"`; `["APP_STORE": "/tmp/Aitmproxy-dev-state-x",
    "APP_LIVE": "1"]` has `.path == "/tmp/Aitmproxy-dev-state-x/audit.jsonl"`. (AC1, AC2, AC3)
  - `audit_log_does_not_disturb_the_tails`: `auditLogFile` set AND `systemProxyAuto: true`: yaml
    `hasSuffix("\nsystem_proxy:\n  auto: true\n")` and the `audit_log` line's range precedes `browser:`. (AC7)
  - Rust: `mcp_audit_log_path_the_mac_app_emits_parses` asserts `cfg.mcp.audit_log ==
    AuditLogSetting::Path(PathBuf::from("/tmp/store/audit.jsonl"))` and `cfg.mcp.operator_token.as_deref() ==
    Some("11")` (`AuditLogSetting` derives `PartialEq`). (AC5)
- **Red/green of record:** Rust: `cargo test -p aitm --offline config_file` in `WT` (the new test is green
  immediately: it pins existing core behaviour, so its "red" is the Swift pin failing when the literal is
  absent). Swift red: the orchestrator's filtered `swift test` on commit (a) fails on the new tests; Swift
  green: the same command on commit (b) passes, and the Coder's sandbox typecheck of the app target exits 0.
- **Done when:** both commits are on the branch, the Coder's report quotes the cargo run and the typecheck
  exit code, and the orchestrator's filtered `swift test` is green.

### Task 2: Tester, whole branch

- **Satisfies:** AC1 to AC5, AC7 (mapping); AC6 is Task 3
- **Depends on:** Task 1 committed; head SHA given in the dispatch
- **Files:** tests only (both test files above), if a strengthening is needed
- **Change:** every AC mapped to a named test; weak tests strengthened. Gates, both in the Terminal with logs
  under `/tmp/claude/<name>.log`: Rust `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test -p aitm`; mac gate items 1 and 2 (`swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`,
  `tools/grid-lint.sh`, `tools/check-connection-words.sh`, `tools/check-capture-operator-only.sh`,
  `tools/check-capture-toggle.sh`, all exit 0). Gate on exit codes, never a grep.
- **Done when:** the report quotes each command's tail and exit code and the AC-to-test table has no gap.

### Task 3: live proof (AC6), orchestrator in the Terminal, not a Coder

- **Satisfies:** AC6
- **Depends on:** Task 1 (the Kit and app changes in the built bundle)
- **Files:** none in the repo; evidence goes in the PR body
- **Change (recipe):** `cargo build --release -p aitm` in `WT`; `REAL=~/Library/Application\ Support/aitmproxy/audit.jsonl`,
  record `stat -f '%z %m' $REAL` (before); `DEV_TAG=auditiso CORE_DIR=WT/target/release apps/mac/tools/snap-dev.sh`
  (store `/tmp/Aitmproxy-dev-state-auditiso`); wait for the core (the `aitm-embedded-core/<uuid>/bus.endpoint`
  file under the app's TMPDIR, or the Status page); make one bus call with the operator token read from the
  `0600` `config.yaml` in that per-run dir (`mcp.operator_token`; read it into a shell variable, never echo it,
  never put it in the log); `ls -la /tmp/Aitmproxy-dev-state-auditiso/audit.jsonl` (expect a new `0600` file
  with at least the `start` marker); re-stat `$REAL` (expect identical size and mtime); stop with the printed
  stop line (`kill <pid>; pkill -f <bundle>/Contents/Resources/core/`); delete the dev bundle and the store.
- **Done when:** the PR body shows before/after `stat` lines that are identical, the `ls -la` of the new store
  file, and no token anywhere in the evidence.

### Task 4: panel and PR

- **Satisfies:** workflow stage 6
- **Depends on:** Tasks 2 and 3
- **Change:** security, quality and spec reviewers in parallel on `git diff BASE..HEAD` with the spec, plan,
  Coder and Tester reports. Findings and dispositions in the Review log. PR opened from
  `claude/serene-villani-38530e` to `main` with the gate log paths and the AC6 evidence in the body; the
  Terminal gate log named in the PR body is the CI substitute while GitHub Actions is billing-blocked (Matt's
  ruling). Report "NNN ready <sha>" to the orchestrator; no self-merge.
- **Done when:** no open Critical or Important finding; Minor fixed or accepted by Matt in the Review log.

### Task 5: merge coherence with #308 and #313 (Amendment 2)

- **Satisfies:** AC2 (amended), AC8, AC9 (AC9's proof is Task 6)
- **Depends on:** the merge commit `76b99fa6` (origin/main `09553120`, which carries #308 and #313, merged into
  the branch); one fresh Coder, one sitting
- **Files:** `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (modify: `harnessAuditLogFile` ~179, the
  `// MARK: - Core pointer isolation` extension ~443),
  `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (modify: `spawn`, the `Config(...)` comment ~208 and the
  env block ~228-240),
  `apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift` (modify, append to `// MARK: Harness audit log`)
- **Change:** exactly spec Amendment 2, nothing else:
  - Design 2: `harnessAuditLogFile` takes its store branch from `SettingsDomain.overriddenStoreURL(environment:)`
    (`store.appending(path: "audit.jsonl")`), no longer reading `APP_STORE` itself; the `APP_LIVE` non-empty
    branch and the nil branch are unchanged.
  - Design 5: in the core-pointer-isolation extension, `public static let auditLogEnvironmentKey = "AITM_AUDIT_LOG"`
    beside `runDirEnvironmentKey`, and `public static func childEnvironment(_ environment: [String: String],
    harnessAuditLogFile: URL?) -> [String: String]`: returns `environment` unchanged when the file is nil,
    otherwise the same dictionary with `auditLogEnvironmentKey` removed. Doc comment says why (the core's
    `env.rs` precedence; #313's goal, a different mechanism) and names AC8.
  - Design 3 + 5 in `spawn`: bind `let harnessAuditLog = EmbeddedCoreLaunch.harnessAuditLogFile(environment:
    ProcessInfo.processInfo.environment, workDir: workDir)` once, pass it as `auditLogFile:` (the `Config(...)`
    argument stays where it is), and after the `AITM_RUN_DIR` block and before `process.environment = environment`
    call `environment = EmbeddedCoreLaunch.childEnvironment(environment, harnessAuditLogFile: harnessAuditLog)`.
    One comment block above the env block names the three store-following rules (settings suite =
    `SettingsDomain.select`; run dir = `AITM_RUN_DIR = isolatedRunDir`, #308 unchanged, explicit non-empty
    `AITM_RUN_DIR` still wins; audit log = `auditLogFile = harnessAuditLogFile` + the `AITM_AUDIT_LOG` removal)
    and says both helpers hang off `overriddenStoreURL`. No other app-target change; no Rust change.
- **Test:** Swift, in the `// MARK: Harness audit log` section:
  - `child_environment_drops_an_inherited_audit_log_override_only_in_a_harness_run` (AC8): with
    `let file = URL(fileURLWithPath: "/tmp/s/audit.jsonl")` and `let base = ["PATH": "/usr/bin", "RUST_LOG": "info"]`,
    for each `v` in `["on", "off", "/x/audit.jsonl"]`: `childEnvironment(base.merging(["AITM_AUDIT_LOG": v]) { $1 },
    harnessAuditLogFile: file) == base` (key gone, other keys identical); and
    `childEnvironment(base.merging(["AITM_AUDIT_LOG": "on"]) { $1 }, harnessAuditLogFile: nil) ==
    base.merging(["AITM_AUDIT_LOG": "on"]) { $1 }` (identical dictionary, key kept); `childEnvironment(base,
    harnessAuditLogFile: file) == base` (nothing to drop); `EmbeddedCoreLaunch.auditLogEnvironmentKey == "AITM_AUDIT_LOG"`.
  - `harness_audit_log_file_follows_the_harness_variables` (line ~909) keeps every expectation unchanged: it already
    pins the store cases (`/tmp/Aitmproxy-dev-state-x/audit.jsonl`, store wins over `APP_LIVE`), so it is the AC2
    regression guard across the `overriddenStoreURL` switch; the Coder adds no case to it.
- **Red/green of record:** as Task 1: the Coder's sandbox Kit probe or app-target typecheck (the Overview recipe)
  exits 0; the orchestrator's Terminal `cd WT/apps/mac && swift test --scratch-path
  ~/Library/Developer/Aitmproxy/test-build --filter EmbeddedCoreLaunchTests` is the gate of record, red on the
  tests-only commit (a), green on the production commit (b). Two commits by explicit path (`git add <file>`),
  never `git add -A`.
- **Done when:** both commits are on the branch, the Coder's report quotes the typecheck exit code, the
  orchestrator's filtered `swift test` is green, the mac gate items of Task 2 are re-run green on the new head,
  and the Task 4 panel has reviewed the Task 5 diff (its findings go in the Review log as `5`).

### Task 6: live proof (AC9), orchestrator in the Terminal, not a Coder

- **Satisfies:** AC9
- **Depends on:** Task 5 (the Kit and app changes in the built bundle)
- **Files:** none in the repo; evidence goes in the PR body
- **Change (recipe):** the Task 3 recipe on the merged head with two additions: the proof script exports
  `AITM_AUDIT_LOG=on` before `snap-dev.sh` (so the dev bundle's child would inherit it); after the core is up it
  records the child's environment (`ps -E -p <core pid>` or `ps eww -p <core pid>`, filtered to
  `AITM_AUDIT_LOG`/`AITM_RUN_DIR` only, never the whole line: the token must not be printed) showing no
  `AITM_AUDIT_LOG` and `AITM_RUN_DIR=/tmp/Aitmproxy-dev-state-<tag>/run/cores`; `ls -la` of
  `<store>/audit.jsonl`, `<store>/audit.agent.jsonl`, `<store>/audit.reads.jsonl` and of `<store>/run/cores/`
  (one pointer file, the dev core's); `stat -f '%z %m'` of the real `audit.jsonl` identical before and after.
  Stop and clean up as in Task 3.
- **Done when:** the PR body shows the exported variable, the filtered child-env lines, the three store streams,
  the `run/cores` listing, the identical before/after `stat` lines, and no token anywhere in the evidence.

## Review log

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1 | security | Minor | S-1: two definitions of "harness run" (`harnessAuditLogFile` matched `APP_LIVE == "1"`, `SettingsDomain.select` any non-empty `APP_LIVE`); `APP_LIVE=true` isolated the defaults suite but not the audit | fixed in 59f7d042 (round-1 fix) (spec Amendment 1: non-empty rule for both variables) |
| 1 | security | Minor | S-2: U+0085 / U+2028 / U+2029 pass the newline guard; libyaml folds NEL inside a double-quoted scalar (no injection, no token exposure) | fixed in 59f7d042 (round-1 fix) (`yamlDoubleQuoted` refuses them; NEL test) |
| 1 | security | Minor | S-3: a relative `APP_STORE` is resolved against the cwd, not refused | accepted by the orchestrator for Matt 2026-11-02 (autonomous mode): operator-controlled input, same as `Store.url`, the core hardens the resolved path, `snap-dev.sh` passes an absolute store; flagged in the PR body |
| 1 | quality | Minor | Q-1: `yaml()` doc comment said "both paths" with three spliced paths | fixed in 59f7d042 (round-1 fix) |
| 1 | quality | Minor | Q-2: Swift pin test hand-spelled the Rust literal instead of deriving it from the asserted fragment | fixed in 59f7d042 (round-1 fix) |
| 1 | quality | Minor | Q-3: `harnessAuditLogFile` doc comment claimed the same predicate as `SettingsDomain` while it differed | fixed in 59f7d042 (round-1 fix) (resolved with S-1) |
| 2 | quality | Minor | Q-4: golden default-document test named after the moment it was written | fixed in 59f7d042 (round-1 fix) (renamed `default_config_is_exactly_this_document`) |
| 1 | spec | Minor | P-1: AC4's `\r` half not exercised on `auditLogFile` | fixed in 59f7d042 (round-1 fix) |
| fix 1 | security | — | round 2: no findings; S-1/S-2 verified fixed, five-scalar set equals libyaml's break set | — |
| fix 1 | quality | Minor | Q2-1: `ConfigError` case docs still say "newline" though they fire on U+0085/U+2028/U+2029 | fixed in 2b2fdb16 (round-2 fix) |
| fix 1 | quality | Minor | Q2-2: host-list Unicode line-break refusal inherited but untested | fixed in 2b2fdb16 (round-2 fix) (NEL host case) |
| fix 1 | spec | Minor | P2-1: AC4's U+2029 case not exercised through `yaml()` on `auditLogFile` | fixed in 2b2fdb16 (round-2 fix) |
| fix 2 | security, quality, spec | — | round 3 on `59f7d042..2b2fdb16`: PASS, PASS, PASS, no findings; the branch has no open finding (S-3 accepted) | — |

## Shipped

Follow-up to record here when filled: isolating `ca.audit_log` / `ca.dir` for harness runs (spec Non-goals).
