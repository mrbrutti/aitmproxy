# Web live-harness audit-log isolation implementation plan

**Status:** approved (autonomous mode, 2026-11-02)
**Spec:** `docs/superpowers/specs/2026-11-02-web-harness-audit-log-isolation.md`
**Branch / worktree:** `fix/web-harness-audit-log` at
`/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/web-harness-audit-log`
(called `WT`). Base SHA `abbc6102` (`BASE`). Absolute paths and `git -C "$WT"` everywhere.

## Overview

Two Coder tasks in one file (`apps/web/scripts/live-env.mjs`) plus one new test file, so they run in
order, not in parallel: Task 1 adds the pure pieces (`renderConfig` option, the guard), Task 2 wires
them into `startAitm`. Then the Tester, the live proof in the Terminal (the sandbox cannot bind ports),
and the panel. No Rust, no caller edits. Commit by explicit path (`git -C "$WT" commit -- <paths>`),
never `git add -A`. The gate for this branch is `npm run build && npm test` from `WT/apps/web`.

## Tasks

### Task 1: `auditLogDir` in `renderConfig` and the `assertAuditLogIsolated` guard

- **Satisfies:** AC1, AC2, AC3, AC4
- **Depends on:** none
- **Files:** `apps/web/scripts/live-env.mjs` (modify: `renderConfig`, new export, `node:fs` import gains
  `readFileSync`, `node:path` import gains `isAbsolute`),
  `apps/web/src/panels/scanner/live-env.audit-log.test.ts` (create)
- **Change:**
  - `renderConfig({ ..., auditLogDir = null })`: spec Design 1, exactly. Absent/`null` changes nothing.
  - `export function assertAuditLogIsolated(cfgPath: string, runDir: string): void` (JSDoc types; the
    file is plain `.mjs`): spec Design 2, exactly, including the message.
- **Test:** in the new file, loading the script by file URL as `tester.live-env.test.ts` does
  (`file://${resolve(here, '../../../scripts/live-env.mjs')}`, `/* @vite-ignore */`), with
  `BASE = { proxyPort: 1, browserProxyPort: 2, pocDir: '/p', pocOut: '/o', operatorSecret: 'opsecret-x', token: 'live-y' }`:
  - `without auditLogDir the document is byte-identical to today's`: `renderConfig(BASE)` and
    `renderConfig({ ...BASE, auditLogDir: null })` both `toBe` the AC1 literal. Write and run this one
    FIRST: it must pass on `BASE` before any production edit (it pins today's output).
  - `auditLogDir adds ca.audit_log before mcp and mcp.audit_log after operator_token`: `toBe` the AC2
    literal; and with `scanner: { max_jobs: 2 }` the output contains
    `'scanner:\n  max_jobs: 2\nca:\n  audit_log: "/r/run/ca-audit.jsonl"\nmcp:\n'`.
  - `a relative auditLogDir is refused`: `toThrow('live-env: auditLogDir must be an absolute path; got "rel/run"')`.
  - `the guard accepts the isolated document and names what is missing otherwise`: writes each AC4
    document to `join(mkdtempSync(join(tmpdir(), 'live-env-audit-')), 'config.yaml')` (`node:fs`,
    `node:os`), then: AC2 doc returns `undefined`; AC1 doc throws exactly
    `live-env: refusing to start aitm: <path> must carry mcp.audit_log "/r/run/audit.jsonl" and ca.audit_log "/r/run/ca-audit.jsonl" so the core's audit logs stay in the run dir; missing: mcp.audit_log, ca.audit_log`
    (with `<path>` the written file's path); AC2 doc minus its two `ca:` lines throws ending
    `missing: ca.audit_log`; the wrong-block doc (`ca:\n  audit_log: "/r/run/audit.jsonl"\nmcp:\n  operator_token: x\n`)
    throws ending `missing: mcp.audit_log, ca.audit_log`.
  - Red: the last three tests fail on `BASE` (no option, no export). Green: all pass.
- **Done when:** the Coder's report quotes the red and green `npx vitest run src/panels/scanner/live-env.audit-log.test.ts`
  output, `npm test` exits 0 with `tester.live-env.test.ts` unedited, and one commit holds both files.

### Task 2: wire the guard into `startAitm`

- **Satisfies:** AC5, AC6
- **Depends on:** Task 1 (same file)
- **Files:** `apps/web/scripts/live-env.mjs` (modify: `startAitm` and its doc comment),
  `apps/web/src/panels/scanner/live-env.audit-log.test.ts` (modify, append)
- **Change:** spec Design 3, exactly: `renderConfig({ ..., auditLogDir: dir })`;
  `assertAuditLogIsolated(cfg, dir)` after `writeFileSync(cfg, ...)` and before `spawn(aitmBin, ...)`;
  spawn env `{ ...process.env, RUST_LOG: process.env.RUST_LOG ?? 'info' }`; before `renderConfig`, the
  `process.env.AITM_AUDIT_LOG` check of spec Design 3 (undefined: nothing; `off`: the `console.error` warning;
  anything else: `throw new Error(<abort message>)` before any file or dir is written, the value never echoed);
  the doc comment names all three behaviours. Callers untouched.
- **Test:** `startAitm wires the guard before the spawn and no longer forces the audit log off`: reads
  `live-env.mjs` as text (`readFileSync` on the resolved path), slices from `export async function startAitm(`
  to the next `\nexport `, and asserts: `indexOf('assertAuditLogIsolated(cfg, dir)')` is `>= 0` and less
  than `indexOf('spawn(aitmBin')`; contains `auditLogDir: dir`; does not contain
  `AITM_AUDIT_LOG: process.env.AITM_AUDIT_LOG ?? 'off'`; contains
  `live-env: AITM_AUDIT_LOG=off is set in this environment; this core writes no general audit log (mcp.audit_log in ` and
  `live-env: AITM_AUDIT_LOG is set to a value other than off in this environment; it would override mcp.audit_log and send this core's general audit log outside `.
  Second test `startAitm refuses an inherited AITM_AUDIT_LOG other than off before writing anything`: with
  `process.env.AITM_AUDIT_LOG = 'on'` (saved and restored in `finally`) `await startAitm({ aitmBin: '/nonexistent/aitm' })`
  rejects with a message starting `live-env: AITM_AUDIT_LOG is set to a value other than off`; with `'off'` it rejects with
  the binary-not-found message (`aitm binary not found at /nonexistent/aitm`) and `console.error` (spied) received the
  `off` warning once; with the variable deleted it rejects with the binary-not-found message and `console.error` was not called.
  Red before the edit, green after.
- **Done when:** red/green quoted; `npm run build && npm test` exit 0; `git -C "$WT" diff --stat BASE` lists
  only `live-env.mjs` and the new test file (plus the spec and plan); one commit.

### Task 3: Tester, whole branch

- **Satisfies:** AC1 to AC6 and AC8 (mapping); AC7 is Task 4
- **Depends on:** Task 2
- **Files:** `apps/web/src/panels/scanner/live-env.audit-log.test.ts` only, if a test needs strengthening
- **Change:** an AC-to-test table with no gap; checks that the AC1 pin is a full-string `toBe`, not a
  `toContain`. Runs `npm run build` and `npm test` in `WT/apps/web` (sandbox is fine: no sockets), gating
  on exit codes.
- **Done when:** the report quotes both commands' tails and exit codes.

### Task 4: live proof (AC7), orchestrator in the Terminal

- **Satisfies:** AC7
- **Depends on:** Task 2 (Task 3 may run in parallel)
- **Files:** `apps/web/live-proof/harness-audit-log-2026-11-02/` (create: `proof.sh`, `real-before.txt`,
  `real-after.txt`, `scan-live.log`, `run-dirs.txt`, `README.md`)
- **Change (recipe):** build once in the Terminal: `cd "$WT/apps/web" && npm ci && npm run build`, then
  `cd "$WT" && cargo build -p aitm && cargo build -p aitm-testtarget --bin aitm-testtarget-serve`. Write
  this to `$WT/apps/web/live-proof/harness-audit-log-2026-11-02/proof.sh` (a file, because the Terminal
  hook mangles `#`, parentheses and long compound lines; never edit it while it runs) and run
  `bash <that path>`:

  ```bash
  set -u
  WT=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/web-harness-audit-log
  EV="$WT/apps/web/live-proof/harness-audit-log-2026-11-02"
  REAL="$HOME/Library/Application Support/aitmproxy"
  snap() {
    for f in audit.jsonl audit.agent.jsonl audit.reads.jsonl ca-audit.jsonl system-proxy-state.json; do
      if [ -e "$REAL/$f" ]; then
        echo "$f $(stat -f '%z %m' "$REAL/$f") $(shasum -a 256 "$REAL/$f" | cut -d' ' -f1)"
      else
        echo "$f absent"
      fi
    done
  }
  snap > "$EV/real-before.txt"
  touch "$EV/.marker"
  cd "$WT/apps/web"
  env -u AITM_AUDIT_LOG AITM_BIN="$WT/target/release/aitm" \
    AITM_TESTTARGET_BIN="$WT/target/release/aitm-testtarget-serve" \
    node scripts/scan-live.mjs > "$EV/scan-live.log" 2>&1
  echo "scan-live exit $?" >> "$EV/scan-live.log"
  snap > "$EV/real-after.txt"
  diff "$EV/real-before.txt" "$EV/real-after.txt" && echo "REAL FILES UNCHANGED" || echo "REAL FILES CHANGED"
  : > "$EV/run-dirs.txt"
  for d in $(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'aitm-live-*' -newer "$EV/.marker"); do
    {
      echo "== $d"
      grep -n 'audit_log' "$d/config.yaml"
      ls -la "$d"
      echo "audit.jsonl bytes: $(stat -f '%z' "$d/audit.jsonl")"
      echo "scan.cancel lines: $(grep -c 'scan.cancel' "$d/audit.jsonl")"
    } >> "$EV/run-dirs.txt"
  done
  rm -f "$EV/.marker"
  ```

  Expect: `REAL FILES UNCHANGED`; two `aitm-live-*` dirs (the startup core and the step-08b restart);
  each with two `audit_log` lines naming its own dir and `audit.jsonl bytes` > 0; `scan.cancel lines` >= 1
  in the startup core's dir when `scan-live.log` shows step 05 PASS. Never `cat` a run's `config.yaml`
  (it holds the operator secret and the bridge token). Before committing the evidence, run
  `grep -rE 'opsecret-|live-[a-z0-9]{12,}|#t=' "$EV"` and expect no output (redact `scan-live.log` if it
  prints a UI URL). The README maps AC7's clauses to the files. Delete the two run dirs and
  `$WT/target` afterwards (keep-environment-clean rule).
- **Done when:** the evidence is committed by explicit path and the README states each AC7 clause's result.

### Task 5: panel and PR

- **Satisfies:** workflow stage 6
- **Depends on:** Tasks 3 and 4
- **Change:** security, quality and spec reviewers in parallel on `git diff BASE..HEAD` with the spec,
  the plan and the Coder and Tester reports; findings and dispositions in the Review log. PR from
  `fix/web-harness-audit-log` to `main` with the gate output and the AC7 evidence path. Report
  "ready <sha>" to the orchestrator; no self-merge.
- **Done when:** no open Critical or Important finding; each Minor fixed or accepted by Matt in the Review log.

## Review log

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

Follow-ups to record here when filled: `tests/e2e/run.py`'s `AITM_AUDIT_LOG=off` default (spec Open
question 2); the strict inherited-env rule if Matt wants it (Open question 1).
