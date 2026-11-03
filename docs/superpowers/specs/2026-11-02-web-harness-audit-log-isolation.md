# Web live-harness audit-log isolation design

**Status:** approved (autonomous mode, 2026-11-02; open questions ruled below)
**Research inputs:** none new. Precedent: `docs/superpowers/specs/2026-11-02-embedded-core-harness-audit-log-design.md` (#310, the mac embedded core). Coordinator ruling 2026-11-02. Facts verified at `abbc6102`: `apps/web/scripts/live-env.mjs` (`renderConfig` ~84, `startAitm` ~263, spawn env ~294), its callers `scan-live.mjs` (~779, ~853), `cua-live.mjs` (~79), `cua-l4.mjs` (~288), `selftest-live.mjs` (~97), `apps/web/src/panels/scanner/tester.live-env.test.ts`, `apps/web/vite.config.ts` (vitest, `src/**/*.test.{ts,tsx}`, jsdom), `crates/aitm-core/src/config.rs` (`AuditLogSetting::resolved_path`, `default_ca_audit_log`), `crates/aitm/src/config_file.rs` (`CaFile.audit_log`, `McpFile.audit_log`, `fill_default_state_file`), `crates/aitm/src/env.rs` (`AITM_AUDIT_LOG` wins over the file), `crates/aitm/src/audit_log.rs` (explicit-path boot policy; the general log and `ca.audit_log` must not share a file).

## Intent

`startAitm` in the web live harness hands the core a config with no `mcp.audit_log` and no `ca.audit_log`. The general log is silenced by `AITM_AUDIT_LOG=off`, which breaks the project rule "no core, embedded or harness, without an audit log path under the run's store" and leaves proofs unable to read the core's audit trail (one `scan.cancel` per Cancel press, for example). The CA audit log falls back to Matt's real `~/Library/Application Support/aitmproxy/ca-audit.jsonl`. This fix points both logs into the run's own `mkdtemp` directory and makes the harness refuse to start a core whose config does not.

## Goals

- Every core `startAitm` spawns writes its general audit log to `<runDir>/audit.jsonl` (and the sibling `audit.agent.jsonl`, `audit.reads.jsonl`) and its CA audit log to `<runDir>/ca-audit.jsonl`, where `<runDir>` is the `aitm-live-*` dir `startAitm` already creates.
- `startAitm` aborts, before spawning, unless the config file it wrote carries both lines under that dir.
- A live `scan-live.mjs` run leaves Matt's real audit files byte-for-byte unchanged and leaves a non-empty `audit.jsonl` in its run dir.

## Non-goals

- No change to the callers (`scan-live.mjs`, `cua-live.mjs`, `cua-l4.mjs`, `selftest-live.mjs`): they all go through `startAitm`, so the guard covers them with no edit.
- No change to `ca.dir`: harness cores keep sharing the operator's CA, as in #310.
- No change to `tests/e2e/run.py`, which does `setdefault("AITM_AUDIT_LOG", "off")` for every suite, so `test_t8_web_live.py` run through the e2e runner still has its general log off (the environment wins, below). A follow-up, flagged to Matt.
- No cleanup of `aitm-live-*` dirs (today's behaviour is to leave them) and no cleanup of lines earlier runs appended to the real files.
- No Rust change. No new option to opt out of the isolation.

## Anti-goals

- An existing caller's rendered YAML changing in any byte when the new option is absent.
- A harness core starting with its CA audit log at the operator's default path.
- A token or secret in a log, a test output, or the evidence (the run's `config.yaml` holds two; the proof greps only the `audit_log` lines).

## Constraints

- `mcp.audit_log` accepts `true | false | off | "/absolute/path"`. An explicit path that cannot be used fails the boot (wanted: a mistake is loud). `ca.audit_log` is a plain path.
- Every level is `deny_unknown_fields`: the keys are exactly `audit_log`, two-space indent, under `mcp:` and under a top-level `ca:`.
- `<runDir>/audit.jsonl` and `<runDir>/ca-audit.jsonl` are distinct, so the core's shared-file check (`audit_log.rs` ~1999) passes, rotated names included.
- Setting `ca.audit_log` also moves the default `system_proxy.state_file` to `<runDir>/system-proxy-state.json` (`config_file.rs` `fill_default_state_file`). That is more isolation, not less: a harness core no longer reads the operator's system-proxy recovery state. Stated so nobody "fixes" it.
- `AITM_AUDIT_LOG` set in the caller's environment wins over the file (core rule). The harness fails closed: `off` is tolerated with a stderr warning (the core writes no general log; the proof's own assertions then fail, which is wanted), any other value makes `startAitm` throw before the spawn, because it could send the log to Matt's real file and no config check can see that (ruling, 2026-11-02).

## Design

1. **`renderConfig` gains `auditLogDir = null`** (a directory, not two paths: one value, and the guard compares against one dir) **(Architect's call)**. Absent or `null`: output unchanged. A string: it must be absolute (`path.isAbsolute`), otherwise `renderConfig` throws `Error('live-env: auditLogDir must be an absolute path; got ' + JSON.stringify(auditLogDir))`. Paths are joined with `path.join` and written with `JSON.stringify` (a YAML double-quoted scalar, so a quote or backslash in the dir cannot break the document) **(Architect's call)**. Two placements:
   - a new top-level block directly before `mcp:` (after `scanner:` when present):
     ```
     ca:
       audit_log: "<auditLogDir>/ca-audit.jsonl"
     ```
   - one line inside `mcp:`, directly after `  operator_token: <secret>` and before `  transport:`:
     ```
       audit_log: "<auditLogDir>/audit.jsonl"
     ```
2. **`export function assertAuditLogIsolated(cfgPath, runDir)`** in `live-env.mjs`. Reads the file at `cfgPath` (the bytes the core will read, not the rendered string). `expectedMcp = '  audit_log: ' + JSON.stringify(join(runDir, 'audit.jsonl'))`, `expectedCa = '  audit_log: ' + JSON.stringify(join(runDir, 'ca-audit.jsonl'))`. A line counts only if it equals the expected text exactly and the nearest preceding line that does not start with a space is `mcp:` (resp. `ca:`). If either is missing it throws:
   ```
   live-env: refusing to start aitm: <cfgPath> must carry mcp.audit_log "<runDir>/audit.jsonl" and ca.audit_log "<runDir>/ca-audit.jsonl" so the core's audit logs stay in the run dir; missing: <list>
   ```
   with the two paths written via `JSON.stringify` and `<list>` being `mcp.audit_log`, `ca.audit_log`, or `mcp.audit_log, ca.audit_log`, in that order. Returns `undefined` when both are present.
3. **`startAitm`** passes `auditLogDir: dir` (its own `mkdtemp` dir) to `renderConfig`, calls `assertAuditLogIsolated(cfg, dir)` right after `writeFileSync` and before `spawn` (the guard lives in `startAitm`, so every proof script gets it with no edit) **(Architect's call, per the ruling)**, and drops `AITM_AUDIT_LOG` from the spawn env object: the env becomes `{ ...process.env, RUST_LOG: process.env.RUST_LOG ?? 'info' }`, so nothing defaults to `off`. Before `renderConfig` it inspects `process.env.AITM_AUDIT_LOG`: `undefined` is the normal case; the exact string `off` writes one line with `console.error` (not the caller's `log` callback, which most callers filter to errors) and goes on; any other value throws before anything is written or spawned, never echoing the value:
   ```
   live-env: AITM_AUDIT_LOG=off is set in this environment; this core writes no general audit log (mcp.audit_log in <dir> is overridden)
   ```
   ```
   live-env: AITM_AUDIT_LOG is set to a value other than off in this environment; it would override mcp.audit_log and send this core's general audit log outside <dir>. Unset it (env -u AITM_AUDIT_LOG) and retry.
   ```
   The `startAitm` doc comment says all three things: the logs live in `dir`, `off` is tolerated with a warning, anything else aborts.
4. **Tests** go in a new vitest file `apps/web/src/panels/scanner/live-env.audit-log.test.ts`, loading `live-env.mjs` by file URL exactly as `tester.live-env.test.ts` does (that file is not edited). `npm test` already runs it (`vite.config.ts` include).
5. **Evidence** goes under `apps/web/live-proof/harness-audit-log-2026-11-02/`, beside the existing `apps/web/live-proof/t8-scan-2026-11-01/` (the web precedent; #310's mac evidence lived in its PR body) **(Architect's call)**.

## Acceptance criteria

The fixed inputs below are `BASE = { proxyPort: 1, browserProxyPort: 2, pocDir: '/p', pocOut: '/o', operatorSecret: 'opsecret-x', token: 'live-y' }`.

1. **AC1** `renderConfig(BASE)` equals exactly `'listen: 127.0.0.1:1\nbrowser:\n  proxy_addr: 127.0.0.1:2\nscope:\n  allow_agent_widen: true\npoc:\n  dir: /p\n  out_dir: /o\nmcp:\n  operator_token: opsecret-x\n  transport:\n    loopback_tcp:\n      port: 0\n      token: live-y-mcp\n'` (today's output, pinned), and `renderConfig({ ...BASE, auditLogDir: null })` equals the same string.
2. **AC2** `renderConfig({ ...BASE, auditLogDir: '/r/run' })` equals exactly `'listen: 127.0.0.1:1\nbrowser:\n  proxy_addr: 127.0.0.1:2\nscope:\n  allow_agent_widen: true\npoc:\n  dir: /p\n  out_dir: /o\nca:\n  audit_log: "/r/run/ca-audit.jsonl"\nmcp:\n  operator_token: opsecret-x\n  audit_log: "/r/run/audit.jsonl"\n  transport:\n    loopback_tcp:\n      port: 0\n      token: live-y-mcp\n'`. With `scanner: { max_jobs: 2 }` added, `ca:` comes after `  max_jobs: 2` and before `mcp:`.
3. **AC3** `renderConfig({ ...BASE, auditLogDir: 'rel/run' })` throws `live-env: auditLogDir must be an absolute path; got "rel/run"`.
4. **AC4** `assertAuditLogIsolated(path, '/r/run')` on a file holding AC2's document returns `undefined`; on AC1's document throws the Design 2 message ending `missing: mcp.audit_log, ca.audit_log`; on AC2's document with the `ca:` block removed throws ending `missing: ca.audit_log`; on a document whose only `audit_log` line is `  audit_log: "/r/run/audit.jsonl"` under `ca:` (none under `mcp:`) throws ending `missing: mcp.audit_log, ca.audit_log`. The full message for the AC1 case is literal-pinned.
5. **AC5** In `live-env.mjs`, inside `startAitm`: the text `assertAuditLogIsolated(cfg, dir)` occurs before `spawn(aitmBin`, `renderConfig(` is called with `auditLogDir: dir`, the source contains no `AITM_AUDIT_LOG: process.env.AITM_AUDIT_LOG ?? 'off'`, and contains both Design 3 texts (the `off` warning and the abort message). Behaviour: `startAitm()` with `process.env.AITM_AUDIT_LOG = 'on'` rejects with the abort message before any `aitm-live-*` dir exists (the test sets and restores the variable; the binary need not exist because the check precedes the binary check), and with `'off'` it proceeds past that check (the test observes the warning on `console.error` and then the binary-not-found error for a bogus `aitmBin`).
6. **AC6** `tester.live-env.test.ts` passes unedited, and `git diff` shows no change to `scan-live.mjs`, `cua-live.mjs`, `cua-l4.mjs`, `selftest-live.mjs`.
7. **AC7** Live: one `scan-live.mjs` run with `AITM_AUDIT_LOG` unset. For each of `audit.jsonl`, `audit.agent.jsonl`, `audit.reads.jsonl`, `ca-audit.jsonl`, `system-proxy-state.json` under `~/Library/Application Support/aitmproxy/`, the before and after lines (`<name> <size> <mtime> <sha256>`, or `<name> absent`) are identical. Every `aitm-live-*` dir the run created holds a `config.yaml` whose two `audit_log` lines name that dir, and a non-empty `audit.jsonl`. When step 05 PASSes, the first core's `audit.jsonl` has at least one `scan.cancel` line. No token appears in the evidence.
8. **AC8** `npm run build` and `npm test` in `apps/web` exit 0.

## Left to the builder

- How `assertAuditLogIsolated` splits lines (`\n`; a CRLF file simply fails the match, which is fine: `renderConfig` never writes one).
- Doc-comment wording, in the file's existing voice.
- Test names.

## Open questions

1. **Ruled (2026-11-02, autonomous mode): fail closed.** An inherited `AITM_AUDIT_LOG` other than `off` aborts `startAitm` before anything is written; `off` warns and proceeds (Design 3, AC5). Reason: the only values that can reach Matt's real file are the non-`off` ones, and a config-file guard cannot see them.
2. **Ruled: follow-up, not this PR.** `tests/e2e/run.py` defaults `AITM_AUDIT_LOG=off` for every suite, so the T8 web cell run through the runner keeps the general log off (tolerated by rule 1, so the cell still runs). The e2e lane should drop that default for cells whose core comes from `live-env.mjs`; flagged to the coordinator for T10.

## Summary

`renderConfig` gains `auditLogDir`, which adds `ca: audit_log: "<dir>/ca-audit.jsonl"` before `mcp:` and `audit_log: "<dir>/audit.jsonl"` after `operator_token`; without it the output is byte-identical. `startAitm` passes its `mkdtemp` dir, checks the written file with a new exported `assertAuditLogIsolated(cfgPath, runDir)` before spawning, and stops forcing `AITM_AUDIT_LOG=off` (an inherited `off` warns, any other inherited value aborts). No caller changes. A vitest file pins the two documents, the refusal messages and the wiring; one real `scan-live.mjs` run proves Matt's real audit files untouched.

**Architect's calls:** a single `auditLogDir` option rather than two paths; `JSON.stringify` quoting for the new values; `ca:` placed directly before `mcp:` and the `mcp` line directly after `operator_token`; the guard reads the written file and checks block membership; the guard is called inside `startAitm`, so callers are untouched; the inherited-env case warns instead of aborting; a new test file rather than edits to the existing pins; evidence under `apps/web/live-proof/harness-audit-log-2026-11-02/`.
