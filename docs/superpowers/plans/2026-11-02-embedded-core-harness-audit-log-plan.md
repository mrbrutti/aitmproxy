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

## Review log

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

Follow-up to record here when filled: isolating `ca.audit_log` / `ca.dir` for harness runs (spec Non-goals).
