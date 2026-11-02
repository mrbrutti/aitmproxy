# Embedded-core harness audit log design

**Status:** approved (2026-11-02, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Research inputs:** none new. Facts verified in tree at `61a5ae05` on 2026-11-02 (found by the Jobs-view UX session): `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (`Config.yaml()`), `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (`spawn`, `makeWorkDir`), `apps/mac/Sources/Aitmproxy/App.swift` (`Store.url`), `apps/mac/Sources/AitmproxyKit/SettingsDomain.swift` (`harnessVariables`), `apps/mac/tools/snap-dev.sh`, `crates/aitm/src/config_file.rs` (`McpFile.audit_log`, `AuditLogFile::into_setting`), `crates/aitm-core/src/config.rs` (`AuditLogSetting`), `crates/aitm/src/audit_log.rs` (`start_at`, `stream_path`), and `docs/superpowers/specs/2026-10-31-durable-audit-design.md` Design 4.

## Intent

The macOS app spawns an embedded `aitm` core from a generated per-launch `config.yaml` that carries no `mcp.audit_log`, so the core falls back to `AuditLogSetting::Default`: Matt's real `~/Library/Application Support/aitmproxy/audit.jsonl` (plus the sibling `audit.agent.jsonl` and `audit.reads.jsonl` streams). Every dev-bundle run (`tools/snap-dev.sh`, `APP_STORE=/tmp/Aitmproxy-dev-state-<tag>`) and every live self-test (`APP_LIVE=1`) therefore appends to the operator's real integrity record. The app already isolates its own state under `APP_STORE`; this fix makes the embedded core's durable audit follow the same isolation, and changes nothing for the installed app.

## Goals

- A harness run (either of `SettingsDomain.harnessVariables`: `APP_STORE` non-empty or `APP_LIVE=1`) writes its durable audit under the harness's own directory, never under the operator's real config dir.
- A normal launch (no harness variable) generates a config byte-identical to today's: no `audit_log` key, the core keeps its default.
- The text the app emits is proven to parse in the core to `AuditLogSetting::Path`, with the literal pinned from the Swift test to the Rust test (the existing `system_proxy_block_the_mac_app_emits_parses` pattern).

## Non-goals

- `ca.audit_log` (default `ca-audit.jsonl` beside the audit log) and `ca.dir` stay untouched: the dev bundle must keep sharing the operator's trusted CA, and `ca-audit.jsonl` is written only by CA operations. Isolating the CA audit for harness runs is a follow-up, not this change.
- No change to `Store.url`, `SettingsDomain`, `snap-dev.sh`, or the Rust production code. No `AITM_AUDIT_LOG` environment variable set by the app (the config key is the lever the app already owns).
- No new operator setting; harness-only behaviour, driven by the existing harness variables.
- No cleanup of audit lines harness runs have already appended to the real file.

## Anti-goals

- The installed app's generated config changing in any byte (a stray `audit_log` key, a shifted tail).
- A value from the environment reaching the token-bearing YAML unescaped (YAML injection via `APP_STORE`).
- A harness core booting silently with the default audit path because the key was malformed or mis-nested: `McpFile` is `deny_unknown_fields` and an explicit `Path` makes a bad file fail the boot (durable-audit spec Design 4), so a mistake is loud, which is what we want.
- Printing the bus or operator token anywhere while proving this (log, PR body, test output).

## Constraints

- `mcp.audit_log` accepts `true | false | off | "/absolute/path"`; a relative path is a config error. Both harness destinations are absolute (`APP_STORE` as `snap-dev.sh` sets it, `workDir` under `NSTemporaryDirectory()`).
- The key must sit under `mcp:` at two-space indent, exactly `audit_log` (`deny_unknown_fields`).
- The core's writer preflight creates missing parent dirs `0700` and the files `0600` (`preflight_creates_private_dirs_and_files_with_a_start_marker`), so the app need not pre-create anything.
- The `ssl_insecure`, `macos_capture`, `scope`, `system_proxy` tails are byte-exact `hasSuffix` targets in existing tests and must keep their position and text.
- Swift tests cannot run in the Claude sandbox (`swift test` is Terminal-only); the Kit helper is pure and environment-injected so it is unit-testable without the process environment.

## Design

1. **`EmbeddedCoreLaunch.Config.auditLogFile: URL?`** (Kit), new stored property, init parameter with default `nil`, placed last so every existing call site and test is unchanged. When non-nil, `yaml()` emits one line inside the `mcp:` block directly after `operator_token`: `  audit_log: "<path>"`, with the path through the existing `yamlDoubleQuoted` (quotes and backslashes escaped; a newline throws `ConfigError.pathContainsNewline`, the same guard as `obscuraBinary` and `endpointFile`). When nil, no `audit_log` key appears anywhere. The line goes in the `mcp:` block, not as a tail, because the key belongs to `mcp` and the tails are pinned by `hasSuffix` tests.
2. **`EmbeddedCoreLaunch.harnessAuditLogFile(environment: [String: String], workDir: URL) -> URL?`** (Kit, `public static`, pure). Returns `nil` when `APP_STORE` is empty or absent AND `APP_LIVE != "1"`; `<APP_STORE>/audit.jsonl` when `APP_STORE` is non-empty (the store wins when both are set, matching `Store.url`); `<workDir>/audit.jsonl` when only `APP_LIVE=1` is set (there is no store to point into, and the manager deletes the per-run `0700` dir at teardown, so the record dies with the run). `APP_LIVE` is matched as exactly `"1"` because that is what the live harness sets and `SelfTest.live` checks **(Architect's call; the orchestrator's design said `APP_LIVE=1`, this pins the comparison)**. The sibling streams follow the base automatically via `stream_path`.
3. **Call site** in `EmbeddedCore.spawn` passes `auditLogFile: EmbeddedCoreLaunch.harnessAuditLogFile(environment: ProcessInfo.processInfo.environment, workDir: workDir)` as the last `Config` argument, right where `workDir` is already in scope. No other app-target change.
4. **Core round-trip pin**: one new Rust test beside `system_proxy_block_the_mac_app_emits_parses` parsing the literal `"mcp:\n  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n"`; the Swift test asserts its yaml contains the two-line fragment and that `crates/aitm/src/config_file.rs` contains the full literal and the test's name. The `mcp:\n` header is the minimal wrapper that makes the fragment a complete parse input (`transport` is optional); the Swift side pins the fragment because `transport` sits between `mcp:` and `operator_token` in the real output **(Architect's call on the pin shape)**.

## Acceptance criteria

1. **AC1** No harness variable (`[:]`, `APP_STORE: ""`, `APP_LIVE: "0"`): `harnessAuditLogFile` is `nil` and the generated yaml contains no `audit_log`; the installed app's config is byte-identical to today's.
2. **AC2** `APP_STORE` non-empty: `mcp.audit_log` is `"<APP_STORE>/audit.jsonl"`, on the line directly after `operator_token`, inside the `mcp:` block (before `browser:`), two-space indent. Both set: the store wins.
3. **AC3** `APP_LIVE=1` without `APP_STORE`: `mcp.audit_log` is `"<workDir>/audit.jsonl"`.
4. **AC4** The path is escaped like the other two paths (`"` and `\` backslash-escaped); a path containing `\n` or `\r` makes `yaml()` throw `ConfigError.pathContainsNewline`.
5. **AC5** The emitted text parses in the core: `parse("mcp:\n  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n")` gives `cfg.mcp.audit_log == AuditLogSetting::Path(PathBuf::from("/tmp/store/audit.jsonl"))` and `cfg.mcp.operator_token.as_deref() == Some("11")`; the Swift test pins that literal and the test name in the Rust source.
6. **AC6** Live proof: a dev bundle launched with `APP_STORE`, its core started, one bus call made, shows a new `<APP_STORE>/audit.jsonl` while `~/Library/Application Support/aitmproxy/audit.jsonl` keeps its byte size and mtime (`stat -f '%z %m'` before and after). The token is never printed.
7. **AC7** With `auditLogFile` set and `systemProxyAuto: true`, the yaml still ends in `system_proxy:\n  auto: true\n`; all existing `ssl_insecure`, `macos_capture`, `scope`, `system_proxy` tail tests pass unchanged.

## Left to the builder

- Doc-comment wording on the new property and helper (follow the file's existing voice: what, why, which AC).
- Whether the Swift helper reads `environment["APP_STORE"]` with `isEmpty` or `?? ""`, as long as AC1 holds.
- Test-name style: the file mixes snake_case and camelCase; the names in the plan are snake_case to match the neighbouring config tests.

## Open questions

None. The CA-audit follow-up (Non-goals) is noted for Matt but needs no answer for this change.
