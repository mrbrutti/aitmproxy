# Embedded-core harness audit log design

**Status:** approved (2026-11-02, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Research inputs:** none new. Facts verified in tree at `61a5ae05` on 2026-11-02 (found by the Jobs-view UX session): `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` (`Config.yaml()`), `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift` (`spawn`, `makeWorkDir`), `apps/mac/Sources/Aitmproxy/App.swift` (`Store.url`), `apps/mac/Sources/AitmproxyKit/SettingsDomain.swift` (`harnessVariables`), `apps/mac/tools/snap-dev.sh`, `crates/aitm/src/config_file.rs` (`McpFile.audit_log`, `AuditLogFile::into_setting`), `crates/aitm-core/src/config.rs` (`AuditLogSetting`), `crates/aitm/src/audit_log.rs` (`start_at`, `stream_path`), and `docs/superpowers/specs/2026-10-31-durable-audit-design.md` Design 4.

## Amendment 1 (post-panel), 2026-11-02

The Stage 6 panel (security PASS 3 Minor, quality PASS 4 Minor, spec PASS 1 Minor) found two definitions of "harness run" (S-1): `harnessAuditLogFile` matched `APP_LIVE` as exactly `"1"` while `SettingsDomain.select` picks the isolated defaults suite on any non-empty `APP_LIVE`, so `APP_LIVE=true` isolated its settings but still appended to the real `audit.jsonl`. This amendment makes the audit-log predicate the same non-empty rule `SettingsDomain.select` already uses, and extends the newline guard to the Unicode line breaks (S-2). No AC is added or renumbered; the Status line above stays the orchestrator's.

## Amendment 2 (merge with #308/#313), 2026-11-03

`origin/main` now carries #308 (`SettingsDomain.overriddenStoreURL(environment:)` is the one reading of `APP_STORE`; `EmbeddedCoreLaunch.isolatedRunDir` hangs off it and `spawn` sets `AITM_RUN_DIR` from it) and #313 (the web harness fails closed on an inherited `AITM_AUDIT_LOG`, Design 3 / Open question 1 there). This amendment makes the mac isolation one coherent rule with both: Design 2 derives its store branch from `overriddenStoreURL`; Design 3 names the three store-following rules in one block; new Design 5 strips an inherited `AITM_AUDIT_LOG` from a harness child, because the core's precedence (`crates/aitm/src/env.rs`, `apply`) lets `AITM_AUDIT_LOG=on` in the launch environment (or `tests/e2e/run.py`'s default `off`) silently defeat `mcp.audit_log`. AC2 is amended; AC8 and AC9 are added; AC1-AC7 keep their numbers. The plan is not changed by this amendment.

## Intent

The macOS app spawns an embedded `aitm` core from a generated per-launch `config.yaml` that carries no `mcp.audit_log`, so the core falls back to `AuditLogSetting::Default`: Matt's real `~/Library/Application Support/aitmproxy/audit.jsonl` (plus the sibling `audit.agent.jsonl` and `audit.reads.jsonl` streams). Every dev-bundle run (`tools/snap-dev.sh`, `APP_STORE=/tmp/Aitmproxy-dev-state-<tag>`) and every live self-test (`APP_LIVE=1`) therefore appends to the operator's real integrity record. The app already isolates its own state under `APP_STORE`; this fix makes the embedded core's durable audit follow the same isolation, and changes nothing for the installed app.

## Goals

- A harness run (either of `SettingsDomain.harnessVariables`: `APP_STORE` non-empty or `APP_LIVE` non-empty) writes its durable audit under the harness's own directory, never under the operator's real config dir.
- A normal launch (no harness variable) generates a config byte-identical to today's: no `audit_log` key, the core keeps its default.
- The text the app emits is proven to parse in the core to `AuditLogSetting::Path`, with the literal pinned from the Swift test to the Rust test (the existing `system_proxy_block_the_mac_app_emits_parses` pattern).

## Non-goals

- `ca.audit_log` (default `ca-audit.jsonl` beside the audit log) and `ca.dir` stay untouched: the dev bundle must keep sharing the operator's trusted CA, and `ca-audit.jsonl` is written only by CA operations. Isolating the CA audit for harness runs is a follow-up, not this change.
- No change to `Store.url`, `SettingsDomain`, `snap-dev.sh`, or the Rust production code. No `AITM_AUDIT_LOG` environment variable set by the app (the config key is the lever the app already owns; Amendment 2 REMOVES an inherited one from a harness child, Design 5, and still sets none).
- No new operator setting; harness-only behaviour, driven by the existing harness variables.
- No cleanup of audit lines harness runs have already appended to the real file.
- A relative `APP_STORE` is resolved against the cwd, exactly as `Store.url` does, and is not refused (S-3, accepted: operator-controlled input, the core hardens the resolved path, `snap-dev.sh` always passes an absolute store).
- A single shared `SettingsDomain.isHarnessRun(environment:)` predicate used by both `SettingsDomain.select` and `harnessAuditLogFile` is a follow-up; this spec makes no `SettingsDomain` change. (Amendment 2: that follow-up now has a natural home beside `overriddenStoreURL`, which #308 added; the other Non-goals are unchanged.)

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
2. **`EmbeddedCoreLaunch.harnessAuditLogFile(environment: [String: String], workDir: URL) -> URL?`** (Kit, `public static`, pure). Returns `nil` when `APP_STORE` is empty or absent AND `APP_LIVE` is empty or absent; `<store>/audit.jsonl` where `store` is `SettingsDomain.overriddenStoreURL(environment:)` when that is non-nil (the store wins when both are set, matching `Store.url`; the helper does not read `APP_STORE` itself, so the store predicate has one reading, shared with `isolatedRunDir`) **(Architect's call, Amendment 2)**; `<workDir>/audit.jsonl` when only `APP_LIVE` is set (non-empty) (there is no store to point into, and the manager deletes the per-run `0700` dir at teardown, so the record dies with the run). `APP_LIVE` is matched as NON-EMPTY, the same predicate `SettingsDomain.select` uses to pick the isolated defaults suite, so a run that isolates its settings always isolates its audit; `SelfTest.live`'s exact `"1"` is a different question (whether the live self-test RUNS) and is unchanged **(Architect's call, Amendment 1; supersedes the earlier exact-`"1"` call)**. The sibling streams follow the base automatically via `stream_path`. `yamlDoubleQuoted` also refuses the Unicode line breaks U+0085, U+2028 and U+2029, because libyaml folds them inside a double-quoted scalar (S-2); the error names stay `pathContainsNewline` / `hostContainsNewline`.
3. **Call site** in `EmbeddedCore.spawn` passes `auditLogFile: EmbeddedCoreLaunch.harnessAuditLogFile(environment: ProcessInfo.processInfo.environment, workDir: workDir)` as the last `Config` argument, right where `workDir` is already in scope. Amendment 2: `spawn` carries one comment block naming the three rules that follow an overridden store, so they read as one rule: the settings suite is `SettingsDomain.select`'s; the run dir is `AITM_RUN_DIR = isolatedRunDir` (#308, unchanged, an explicit non-empty `AITM_RUN_DIR` still wins); the audit log is `auditLogFile = harnessAuditLogFile` plus Design 5. Both helpers hang off `overriddenStoreURL`, so "store -> run dir -> audit log" is one predicate. The `Config(...)` argument stays where it is; the coherence is in the helpers and that comment block, not in moving code **(Architect's call, Amendment 2)**.
4. **Core round-trip pin**: one new Rust test beside `system_proxy_block_the_mac_app_emits_parses` parsing the literal `"mcp:\n  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n"`; the Swift test asserts its yaml contains the two-line fragment and that `crates/aitm/src/config_file.rs` contains the full literal and the test's name. The `mcp:\n` header is the minimal wrapper that makes the fragment a complete parse input (`transport` is optional); the Swift side pins the fragment because `transport` sits between `mcp:` and `operator_token` in the real output **(Architect's call on the pin shape)**.
5. **Inherited `AITM_AUDIT_LOG`** (Amendment 2). The core's `env.rs` `apply` lets `AITM_AUDIT_LOG` in the child's environment win over the file's `mcp.audit_log` (`off|false|0|no` -> off; `on|true|1|yes|default` -> the DEFAULT file, Matt's real `audit.jsonl`; an absolute path -> that path), and the child inherits `ProcessInfo.processInfo.environment`. So when `harnessAuditLogFile` returns non-nil (a harness run), `spawn` REMOVES `AITM_AUDIT_LOG` from the child's environment before launching: the config's `mcp.audit_log` is authoritative and the store isolation cannot be defeated by an inherited variable. With no harness variable the launch environment's `AITM_AUDIT_LOG` passes through untouched (the installed app, the core's own rule). The removal is a pure Kit helper so it is unit-testable: `EmbeddedCoreLaunch.auditLogEnvironmentKey = "AITM_AUDIT_LOG"` (a `public static let`, beside `runDirEnvironmentKey`) and `public static func childEnvironment(_ environment: [String: String], harnessAuditLogFile: URL?) -> [String: String]`, which returns `environment` unchanged when `harnessAuditLogFile` is nil and otherwise the same dictionary without `auditLogEnvironmentKey`; `spawn` calls it on the environment it already builds, with the same `harnessAuditLogFile` value it passed to `Config`, so one value drives both the key and the removal. The mac app differs from #313's "abort" because the app owns the child's environment and an abort would surface as a degraded core in a UI harness, while removing the override gives exactly the isolation this spec promises **(Architect's call, Amendment 2; the #313 ruling's goal, a different mechanism)**.

## Acceptance criteria

1. **AC1** No harness variable (`[:]`, `APP_STORE: ""`, `APP_LIVE: ""`): `harnessAuditLogFile` is `nil` and the generated yaml contains no `audit_log`; the installed app's config is byte-identical to today's.
2. **AC2** `APP_STORE` non-empty: `mcp.audit_log` is `"<store>/audit.jsonl"` with `<store>` the path of `SettingsDomain.overriddenStoreURL(environment:)` (Amendment 2; a relative `APP_STORE` therefore behaves exactly as `Store.url`, S-3 stays accepted), on the line directly after `operator_token`, inside the `mcp:` block (before `browser:`), two-space indent. Both set: the store wins.
3. **AC3** `APP_LIVE` non-empty (`"1"`, and also `"0"` or `"true"`) without `APP_STORE`: `mcp.audit_log` is `"<workDir>/audit.jsonl"`.
4. **AC4** The path is escaped like the other two paths (`"` and `\` backslash-escaped); a path containing `\n`, `\r`, U+0085, U+2028 or U+2029 makes `yaml()` throw `ConfigError.pathContainsNewline`.
5. **AC5** The emitted text parses in the core: `parse("mcp:\n  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n")` gives `cfg.mcp.audit_log == AuditLogSetting::Path(PathBuf::from("/tmp/store/audit.jsonl"))` and `cfg.mcp.operator_token.as_deref() == Some("11")`; the Swift test pins that literal and the test name in the Rust source.
6. **AC6** Live proof: a dev bundle launched with `APP_STORE`, its core started, one bus call made, shows a new `<APP_STORE>/audit.jsonl` while `~/Library/Application Support/aitmproxy/audit.jsonl` keeps its byte size and mtime (`stat -f '%z %m'` before and after). The token is never printed.
7. **AC7** With `auditLogFile` set and `systemProxyAuto: true`, the yaml still ends in `system_proxy:\n  auto: true\n`; all existing `ssl_insecure`, `macos_capture`, `scope`, `system_proxy` tail tests pass unchanged.
8. **AC8** (Amendment 2) `childEnvironment(_:harnessAuditLogFile:)` with a non-nil file returns no `AITM_AUDIT_LOG` key whatever the input held (`"on"`, `"off"`, `"/x/audit.jsonl"`), and every other key unchanged; with `nil` it returns the input dictionary unchanged, `AITM_AUDIT_LOG` included. In `EmbeddedCore.spawn` the call sits before `process.environment = environment` and uses the same `harnessAuditLogFile` value passed to `Config`.
9. **AC9** (Amendment 2, live) The AC6 proof re-run on the merged head with `AITM_AUDIT_LOG=on` exported to the dev bundle still shows the dev core's three streams (`audit.jsonl`, `audit.agent.jsonl`, `audit.reads.jsonl`) under `<APP_STORE>` and the real `audit.jsonl` with unchanged `stat -f '%z %m'`, AND `<APP_STORE>/run/cores` holds the dev core's pointer (the #308 rule, observed together). The token is never printed.

## Left to the builder

- Doc-comment wording on the new property and helper (follow the file's existing voice: what, why, which AC).
- Whether the Swift helper reads `environment["APP_STORE"]` with `isEmpty` or `?? ""`, as long as AC1 holds.
- Test-name style: the file mixes snake_case and camelCase; the names in the plan are snake_case to match the neighbouring config tests.

## Open questions

None. The CA-audit follow-up (Non-goals) is noted for Matt but needs no answer for this change.
