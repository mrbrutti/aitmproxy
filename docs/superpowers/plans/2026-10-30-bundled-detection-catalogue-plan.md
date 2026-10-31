# Bundled security-detection catalogue implementation plan

**Status:** Approved — 2026-10-30 (self-approved under autonomous-operation mandate)
**Spec:** `docs/superpowers/specs/2026-10-30-bundled-detection-catalogue-design.md` (Approved 2026-10-30)
**Branch / worktree:** `feat/bundled-detection-catalogue`

## Overview

Retroactive plan: the code already exists on `feat/bundled-detection-catalogue`;
this document groups it into tasks, each mapped to the spec's acceptance
criteria (AC1–AC16) and the test or observable artifact that proves it.

The work splits into four independent script-authoring tasks (Tasks 1–4, the
`http/`, `ws/`, `active/`, `l4/` catalogue groups — no shared files), one loader
task (Task 5, the Rust discovery/append/apply module plus startup wiring), one
validation-harness task (Task 6, the integration test file), one packaging task
(Task 7), and one documentation task (Task 8, the README). Tasks 1–4, 7, and 8
are mutually independent. Task 5 is independent of the scripts. Task 6 asserts
over the artifacts of Tasks 1–4 and the loader of Task 5, so for a fresh build it
would be ordered after them; as authored it depends only on those files existing.

## Tasks

### Task 1: Passive HTTP/HTTPS detector set (27 scripts)

- **Satisfies:** AC1 (http/ clause), AC2, AC3, AC4
- **Depends on:** none
- **Files:** `scripts/bundled/http/*.rhai` (create 27):
  `basic-auth-cleartext`, `cacheable-sensitive-response`, `cors-misconfiguration`,
  `csrf-token-missing`, `dangerous-http-methods`, `directory-listing`,
  `graphql-introspection`, `host-header-reflection`, `insecure-cookies`,
  `jwt-weakness`, `missing-csp`, `missing-frame-protection`, `missing-hsts`,
  `missing-nosniff`, `missing-permissions-policy`, `missing-referrer-policy`,
  `mixed-content`, `open-redirect-reflection`, `private-address-disclosure`,
  `reflected-input-indicator`, `request-smuggling-indicator`,
  `secret-in-response`, `secret-in-url`, `sensitive-path-exposed`,
  `server-banner-disclosure`, `sql-error-indicator`, `verbose-error-disclosure`.
- **Change:** each script declares `const NAME`/`const API = "1"` and implements
  observe-only `on_request`/`on_response` that read the flow, call
  `flow.mark(...)` and `finding(#{ name, severity, flow_id, detail, tags })`. No
  `http.send`, no `l4.*`, no mutation of request/response.
- **Test:** `every_bundled_script_compiles` compiles each; the floor assert is
  `files.len() >= 20`. `passive_scripts_run_without_error_and_record_findings`
  dispatches `Request`/`Response` over both an `http` and an `https`
  `vuln_http_flow` and asserts `errors.is_empty()` — because the test's
  `StubClient::send` bails, any detector that called `http.send` would surface as
  a runtime error, proving observe-only. Aggregate `findings.list().len() >= 10`.
- **Done when:** both tests pass and the full gate passes.

### Task 2: Passive WebSocket detector set (4 scripts)

- **Satisfies:** AC1 (ws/ clause), AC2, AC3, AC4
- **Depends on:** none
- **Files:** `scripts/bundled/ws/*.rhai` (create 4): `ws-cleartext-transport`,
  `ws-cross-site-hijack-indicator`, `ws-pii-in-frame`, `ws-secret-in-frame`.
- **Change:** each declares `NAME`/`API` and implements observe-only
  `on_ws_start`/`on_ws_message`; reads the frame/handshake, `flow.mark`s and
  records `finding`s; no outbound traffic, no mutation.
- **Test:** `every_bundled_script_compiles` (compile + ≥20 floor);
  `passive_scripts_run_without_error_and_record_findings` dispatches
  `WsStart` and `WsMessage{index:0}` against `ws_flow()` (a frame carrying a
  password and email) and asserts `errors.is_empty()`, contributing to the
  aggregate `findings.list().len() >= 10`.
- **Done when:** both tests pass and the full gate passes.

### Task 3: Active vulnerability-detection commands (15 `check.*`)

- **Satisfies:** AC1 (active/ clause), AC2, AC10, AC11
- **Depends on:** none
- **Files:** `scripts/bundled/active/*.rhai` (create 15): `check-command-injection`,
  `check-cors`, `check-crlf-injection`, `check-http-methods`, `check-ldap-injection`,
  `check-nosql-injection`, `check-open-redirect`, `check-path-traversal`,
  `check-security-headers`, `check-sensitive-paths`, `check-sqli`, `check-ssrf`,
  `check-ssti`, `check-xss`, `check-xxe`.
- **Change:** each declares `NAME`/`API` and a `fn load(reg)` that calls
  `reg.add_command("check.<name>", "<desc>", |args| { ... })`. The command body
  runs only on invocation, probes exclusively through `http.send(#{...})`
  (scope-/rate-gated), uses benign detection-grade payloads (single quote,
  `1=1`/`1=2` boolean differential, arithmetic/echo markers, cross-origin
  `Origin`, `OPTIONS`), records a `finding`, and returns a human-readable verdict
  string. No time-based techniques.
- **Test:** `command_scripts_register_their_commands` iterates `active/`, calls
  `loader.validate_with_registers(path)` and asserts
  `!v.registers.commands.is_empty()` for each — proving invoke-only registration.
  `every_bundled_script_compiles` covers compilation. AC11's "gated client only /
  benign payload" clause has no isolated automated assertion beyond compilation;
  it is proven by review of each script body and the README posture section.
- **Done when:** the registration test passes and the full gate passes.

### Task 4: L4 probe commands (3 `l4.*`)

- **Satisfies:** AC1 (l4/ clause), AC2, AC12
- **Depends on:** none
- **Files:** `scripts/bundled/l4/*.rhai` (create 3): `l4-recon` (`l4.recon`),
  `l4-tcp-syn-probe` (`l4.tcp_probe`), `l4-udp-probe` (`l4.udp_probe`).
- **Change:** each declares `NAME`/`API` and a `fn load(reg)` registering an
  `l4.*` command whose body runs only on invocation and uses `l4.*` host verbs
  (`l4.interfaces`, `l4.scope.list`, `l4.send_recv`, …) wrapped in `try/catch` so
  an absent L4 layer returns a message instead of erroring. Those verbs require
  the L4 layer enabled, the target in L4 scope, and the L4 Inject/Capture
  capability — gating enforced by the host, not the script.
- **Test:** `command_scripts_register_their_commands` iterates `l4/`,
  `validate_with_registers` + `!v.registers.commands.is_empty()` per file;
  `every_bundled_script_compiles` covers compilation. AC12's capability-gating
  clause is enforced by the L4 host verbs and is not separately asserted here;
  proven by review and the host's existing L4 gate tests.
- **Done when:** the registration test passes and the full gate passes.

### Task 5: Default-load discovery, opt-out/override, and startup wiring

- **Satisfies:** AC5, AC6, AC7, AC8, AC9, AC13
- **Depends on:** none
- **Files:** `crates/aitm/src/bundled.rs` (create), `crates/aitm/src/lib.rs`
  (modify — add `pub mod bundled;`), `crates/aitm/src/main.rs` (modify — wire into
  `run()`).
- **Change:**
  - `pub const BUNDLED_DIR: &str = "AITM_BUNDLED_SCRIPTS";`
  - `pub const NO_BUNDLED: &str = "AITM_NO_BUNDLED_SCRIPTS";`
  - `pub fn discover_dir(exe: Option<&Path>, lookup: impl Fn(&str) -> Option<String>) -> Option<PathBuf>`
    — opt-out (truthy `1`/`true`/`yes`) wins; else explicit `BUNDLED_DIR` when it
    is a directory; else first existing of the candidate list.
  - `fn candidates(exe_dir: Option<&Path>) -> Vec<PathBuf>` — in order:
    `<exe_dir>/share/aitm/scripts`, `../share/aitm/scripts`,
    `../../share/aitm/scripts`, `../../scripts/bundled` (dev fallback).
  - `pub fn append(cfg: &mut RhaiConfig, dir: &Path)` — recurse, collect `*.rhai`,
    name-sort, push each as `ScriptEntry::new(path)`, skipping any path a declared
    entry already names (compared after `canonicalize`).
  - `fn collect_rhai(dir: &Path, out: &mut Vec<PathBuf>)`.
  - `pub fn apply(cfg: &mut RhaiConfig, lookup: impl Fn(&str) -> Option<String>)` —
    canonicalize `current_exe`, `discover_dir`, then `append`.
  - `main.rs`: in `run()`, immediately after
    `env::apply_rhai(&mut rhai_cfg, ...)`, call
    `aitm::bundled::apply(&mut rhai_cfg, |k| std::env::var(k).ok());` so the
    catalogue is appended after config-file and `AITM_SCRIPTS` entries.
- **Test:** `bundled::tests::discover_honours_override_and_opt_out` — asserts
  `discover_dir(None, override_only) == Some(dir)` for a scratch dir, and
  `discover_dir(None, both) == None` when `NO_BUNDLED=1` is set alongside the
  override (AC6, AC7). `bundled::tests::append_walks_recursively_and_dedups_declared`
  — with a pre-declared `http/a.rhai` entry, after `append` the `a.rhai` count is
  exactly `1`, `b.rhai` and `c.rhai` (incl. the nested `ws/c.rhai`) are present,
  and `notes.txt` is absent (AC8, AC9). AC5's "appends every bundled `*.rhai` as
  an enabled `ScriptEntry`" is proven by the append test; the "after config-file
  and `AITM_SCRIPTS` entries" ordering clause and AC13's candidate-probe order
  have no dedicated automated test — proven by the `main.rs` call-site placement
  and the `candidates` list respectively (observable by code review).
- **Done when:** both unit tests pass and the full gate passes.

### Task 6: Validation harness

- **Satisfies:** AC2, AC3, AC4 (plus the registration proofs for AC10, AC12)
- **Depends on:** Tasks 1–4 (script files), Task 5 (loader APIs). Independent of
  Tasks 7–8.
- **Files:** `crates/aitm-plugin-rhai/tests/bundled_scripts.rs` (create).
- **Change:** three `#[tokio::test(flavor = "multi_thread")]` tests plus helpers
  (`bundled_dir`, `rhai_files`, `vuln_http_flow(scheme)`, `ws_flow`, `StubClient`,
  `services`, `loader`):
  - `every_bundled_script_compiles` — enumerate all `*.rhai`, assert
    `files.len() >= 20`, `loader.validate(path)` clean for every file.
  - `passive_scripts_run_without_error_and_record_findings` — load each `http/`
    and `ws/` script with an `ErrorSink`, dispatch over `http`+`https`
    `vuln_http_flow` and the `ws_flow`, assert `errors.is_empty()` and
    `findings.list().len() >= 10`.
  - `command_scripts_register_their_commands` — for `active/` and `l4/`,
    `validate_with_registers` and assert `!v.registers.commands.is_empty()`.
- **Test:** the three tests above are themselves the proof; literal expected
  values — `files.len() >= 20`, `errors.is_empty()` (empty vec),
  `findings.list().len() >= 10`, `!v.registers.commands.is_empty()`.
- **Done when:** all three tests pass and the full gate passes.

### Task 7: Packaging installs the catalogue

- **Satisfies:** AC14
- **Depends on:** Task 1–4/8 (the `scripts/bundled/` tree to copy)
- **Files:** `scripts/package.sh` (modify), `scripts/package-linux.sh` (modify),
  `scripts/nfpm.yaml` (modify).
- **Change:**
  - `package.sh`: `mkdir -p "$stage/share/aitm/scripts"`,
    `cp -R scripts/bundled/ "$stage/share/aitm/scripts/"`, and add `share` to the
    `tar -czf "$out" -C "$stage" aitm aitm-tui obscura share` payload.
  - `package-linux.sh`: `mkdir -p "$libdir/share/aitm/scripts"`,
    `cp -R scripts/bundled/ "$libdir/share/aitm/scripts/"`, then
    `find "$libdir/share/aitm/scripts" -type f -exec chmod 644 {} +`.
  - `nfpm.yaml`: add a `contents` entry mapping
    `${STAGEDIR}/usr/lib/aitmproxy/share/aitm/scripts` →
    `/usr/lib/aitmproxy/share/aitm/scripts` with `file_info.mode: 0o644`.
- **Test:** no automated test (packaging). Proof is observable: the macOS tarball
  lists a `share/aitm/scripts` tree (`tar -tzf dist/aitm-*.tar.gz`), and the
  built `.deb`/`.rpm` place the catalogue at
  `/usr/lib/aitmproxy/share/aitm/scripts` beside the installed binary so default
  discovery (Task 5 candidate #1) finds it. See OQ1 for the dir-mode caveat.
- **Done when:** the staged tarball/package layouts contain the catalogue at the
  discovered path and the full gate passes.

### Task 8: Catalogue README

- **Satisfies:** AC15 (and the documentary half of AC1)
- **Depends on:** none (content mirrors Tasks 1–4)
- **Files:** `scripts/bundled/README.md` (create).
- **Change:** document the observe-only posture of `http/`/`ws/` passives, the
  invoke-only/scope-rate-capability-gated posture of `active/` and `l4/` checks,
  the `AITM_NO_BUNDLED_SCRIPTS` opt-out and `AITM_BUNDLED_SCRIPTS` override, how
  discovery/declared-wins loading works, and per-script tables (script → detects →
  OWASP mapping) for all four groups.
- **Test:** no automated test. Proof is observable by reading the file: posture
  statements present, both env vars documented, and the four per-script tables
  with OWASP columns present.
- **Done when:** the README covers all four clauses of AC15 and the full gate
  passes.

### Gate (AC16)

- **Satisfies:** AC16
- Applies to every task: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` must pass on the branch.

## Review log

Kept by the main session during stage 6. One row per finding.

Panel ran 2026-10-30 on `main...df2d141` — security, quality, spec all **PASS**, no Critical or Important findings. Minor dispositions:

| Finding | Severity | Disposition |
|---|---|---|
| Security/Spec — nfpm maps the `share/aitm/scripts` tree with `file_info.mode: 0o644`; installed dirs may lose the traverse bit and discovery load nothing (OQ1) | Minor | Fixed — `scripts/nfpm.yaml` now uses `type: tree` so directories get 0755 (files stay 0644). Still verify on a built `.deb`/`.rpm` (sandbox cannot build packages); OQ1 stays open until then. |
| Security — `collect_rhai` skips symlinked `.rhai` entries (`file_type` does not follow links) | Minor | Accepted — no symlink-following is a mild defensive positive; bundled dirs are trusted plain files. Behaviour noted. |
| Quality — the canonicalize + declared-wins dedup loop is duplicated in `bundled.rs` and `config_file.rs` | Minor | Fixed — extracted `bundled::append_undeclared`; `config_file::append_scripts_dir_entries` now calls it. Covered by the existing `config_rhai` integration tests. |
| Quality — `fn q(url,param,value)` names two different behaviours (encoding vs raw) across active scripts | Minor | Fixed — the two raw-value scripts (`check-path-traversal`, `check-crlf-injection`) renamed their helper to `q_raw`. |
| Quality — `hget`/`abs`/`q` helpers duplicated across active scripts | Minor | Accepted — per-file duplication is acceptable for isolated one-check-per-file catalogue scripts; moving `hget` to `prelude.rhai` is deferred to avoid touching the shared prelude and its api-catalog bijection guard. |
| Quality — `secret-in-response` carries a `where`/header path its `on_response` never used | Minor | Fixed — `on_response` now also scans response header values, matching the script's stated coverage. |
| Quality — the runtime test's finding floor (`>= 10` aggregate) could mask half-broken detectors | Minor | Fixed — added per-directory script-count floors and switched the detection assertion to `>= 15` **distinct** finding names. |
| Quality — `check.nosqli` reads an optional `value` its usage string omits | Minor | Fixed — description and usage now read `{ url, param, value? }`. |

## Shipped

_Filled at stage 7._

## Open questions / risks

- **OQ1 — Linux package directory traverse bits.** `scripts/nfpm.yaml` sets
  `file_info.mode: 0o644` on the `share/aitm/scripts` tree. Confirm nfpm gives the
  intermediate directories `0755` (traverse bit) on the installed `.deb`/`.rpm` so
  discovery can read the tree, or make the directory permissions explicit.
  (`package-linux.sh` chmods only `-type f`, so its staging side is fine; this is
  specifically the nfpm entry.)
