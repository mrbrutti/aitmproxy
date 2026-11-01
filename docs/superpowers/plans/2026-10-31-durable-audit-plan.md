# Durable audit wiring implementation plan

**Status:** approved (2026-10-31, self-approved by the orchestrating session under Matt's autonomous-approve mode; the Architect's decisions 1-4 are accepted as written: AC38/AC41 amended in the spec to name `run.py` and `test_bus_endpoint_file.py`; the `#[doc(hidden)] pub` `Tuning`/`start_tuned` seam; the R1-R4/W1-W18 task ids; the AC54(a) and AC61 readings of ambiguities 14 and 26 stand as the plan reads them. Panel cadence deviates from WORKFLOW's panel-per-task as recorded in the plan.)

**Amendments 2 and 3 are descriptive.** They bring the plan in line with what shipped; the
orchestrating session approved them under Matt's autonomous-approve mode after three panel
rounds. The Status line stays approved. The plan's Review log and Shipped sections are the
orchestrator's and are not written here.

**Amendment 3 (whole-branch panel, 2026-11-01; folded in from the code at `e28a310e`).** Again the
code is the truth; no task's purpose changes. Marked `[Amended: Amendment 3, whole-branch panel]`
where it appears: this header, the Overview (the fix list), the order notes (what has landed), the
merge protocol (the redaction branch merged three times; `origin/main` merged once, and again
before the PR), the AC coverage table (AC1, AC2, AC4, AC25, AC37, AC44, AC47, AC52, AC55 to AC57,
AC61, AC64), the Files table, Calls 20 to 25, Ambiguities 41 to 49 (and 40 corrected), the Risks,
the "Chain R fix rounds" table (fixes 5, 6A and 6B; the writer-side fixes W10/W12, X, Y, Y2, Y3), and the task texts of R4, W12 to W15, W16 to W18, D1, D2 and C1 (the fence numbers
against `f2c9d70b`, the corpus mutation expectation, the mutations that survive, and the new
mutations 44 to 54). What changed in the code, in eight lines: (1) the redaction rounds fail
closed (`MAX_ROUNDS` 8, `[redacted]`; `"<redacted>"`), (2) a glued `\n`, `\r`, `\t` counts as a
line boundary, (3) registry JSON depths 1 to 3 and a fragment mask that makes room, (4) a wedged
rotation is held to twice its cap, (5) the `ca.audit_log` collision is on resolved files and
rotated names, (6) diagnostics never echo a value, (7) narrowed seams, `block_in_place`,
`FAILED_BOOT_TIMEOUT` 10 s, (8) the corpus exists, so W14 and W15 are done and AC52, AC55 to AC57
and AC61 are met.

**Amendment 2 (chain R fix rounds, 2026-11-01; folded in from the code at `f9c1f5b4`).** The plan
is brought in line with what the chain R fix rounds and the chain W tasks that have landed
actually built; the code is the truth. It changes no task's purpose. Marked
`[Amended: Amendment 2, chain R fix rounds]` where it appears: the header and Overview, the
task-order notes, the merge protocol (origin/main was **merged**, not rebased), the Symbols, the AC
coverage table (AC38, AC40, AC44 to AC46), the Files table, Calls 15 to 19, Ambiguities 29 to 40, the
notes of R1 to R4 (the 42 benign names and the 60 s hostile guard in R1 and R2; a "Chain R fix
rounds" list after R4: what each of the five rounds added, and what the bound constants are), W12 to
W15 and W18 (the writer-side facts), H1 (two more harness files, nine in all), the risks and the
clocks, and C1 (the fence numbers, the merge-base, mutations 32 to 43 and the survivor). Two
facts the reader must know first: the corpus tasks **W14 and W15 have not landed**
(`crates/aitm/tests/audit_log_redaction.rs` does not exist at `f9c1f5b4`), so AC52, AC55 to AC57
and AC61 are not yet true; and "Fix 5" (the unquoted-value rule, spec Design 14.3) was being
committed on `claude/durable-audit-redact` and is not in `f9c1f5b4`. Nothing in the numbered task
texts below is rewritten wholesale: a superseded sentence stays, with the amendment beside it.
**[Amended: Amendment 3, whole-branch panel: both "facts the reader must know first" are history.
W14 and W15 landed (`ed249691`, `1231f845`) and Fix 5 is `ba742893`.]**
**Spec:** `docs/superpowers/specs/2026-10-31-durable-audit-design.md` (approved, with Amendment 1:
Design 14 "Strict redaction on disk" and AC44 to AC65; committed `83b9e28`; and Amendment 2, the
chain R fix rounds, folded in 2026-11-01; and Amendment 3, the whole-branch panel, folded in
2026-11-01)
**Branch / worktree:** two chains.
- **Chain W** (the writer, wiring, plugins, docs, harness, closing): `claude/durable-audit-462ca8` in
  `/Users/matt/Security/aitmproxy/.claude/worktrees/durable-audit-462ca8` (the session worktree is the
  plan worktree; the spec and this plan are committed on it).
- **Chain R** (strict redaction, Tasks R1 to R4): branch `claude/durable-audit-redact` in a second
  worktree cut from the plan branch head (the orchestrator creates it, see "Parallel chains and the
  merge protocol"), merged back into the plan branch at merge point **M1**.
Base SHA for every diff and Tester/panel dispatch: `83b9e28` (the spec as amended), until the
orchestrator's rebase on `origin/main`, then the new merge-base. **[Amended: Amendment 2, chain R
fix rounds: there was no rebase. `origin/main` (v0.5.8) was merged into the plan branch
(`b3a2a8df`), so the base for every fence and diff is the merge-base with `origin/main`,
`f2c9d70b`, recomputed with `git merge-base HEAD origin/main` after any further merge; `83b9e28`
and `031b09c` are history.]**

## Overview

Twenty-six tasks. **Chain R (strict redaction, its own worktree):** R1 and R2 build
`aitm-core/src/redact_strict.rs` (R1: the strict key vocabulary, the benign-header test and passes P2
and P3; R2: passes P4, P5, P6); R3 builds `aitm-mcp/src/redact_args.rs` (rules S and D), the exact
`server.rs` call-path hunk and the one e2e assertion flip; R4 bounds the traversal. **Chain W (the
writer, the plan worktree):** W1 and W2 are `aitm-core`'s ring hook and the config key; W3 to W9 build
`crates/aitm/src/audit_log.rs` layer by layer (paths, hardened files, queues, gap markers, error policy,
rotation, re-check); W10 is the `SecretRegistry`; W11 the handle, `start` and the boot policy;
**merge point M1** brings chain R in; W12 and W13 are the writer's field pipeline (text fields, then
`args`); W14 and W15 are the 74-row corpus; W16, W17, W18 are the wiring proofs (in-process,
`agent.status`, `main.rs` with the real binary). **D1** (stale comments), **D2** (README and INSTALL),
**H1** (harness hermeticity) are independent; **C1** is the closing fence and mutation task.
**[Amended: Amendment 2, chain R fix rounds]** Chain R did not stop at R4: the panel found
shapes the four tasks missed, and each round was fixed as a named fix task on the chain R branch
(`R2 fix`, `R4 fix`, `R4 fix 2`, `R fix 3A`/`3B`, `R fix 4A`/`4B`, then "Fix 5"; the list, with what
each added, is under Task R4). They are not new task ids: they are fix tasks of the kind
WORKFLOW's stage 6 describes, dispatched from a findings report. The task count above is
unchanged. **[Amended: Amendment 3, whole-branch panel: the fix list grew. After "Fix 5" came
`R fix 6A` and `6B` (the fail-closed convergence), then fixes on the plan branch itself: the
writer-side `W10/W12 fix` (registry depths, a fragment mask that makes room), the whole-branch
panel's fix `X`, and the glued-escape fixes `Y` (P2), `Y2` (the frames pre-pass and P6) and `Y3` (P5,
committed `e28a310e`). The table under Task R4 lists them with their commits.]**

`audit_log.rs` and its three submodules (`audit_log/registry.rs`, `pipeline.rs`, `jsonscan.rs`; the spec
allows "a submodule of it") are edited only by chain W, strictly in sequence. Every task leaves the
workspace compiling and green. Task ids are final: `R1`..`R4`, `W1`..`W18`, `D1`, `D2`, `H1`, `C1`;
`M1` is a merge step, not a task. **A note on the letter R:** the spec numbers the corpus rows R1 to R74;
this plan always writes a corpus row as "row R7" or "corpus rows R7 and R11" and a task as "Task R3" or in the
order table, so a bare `R<n>` inside the corpus tasks (W14, W15) and C1's mutation table means a corpus row.

### Task order, chains and parallelism

| Task | Title | Chain / worktree | Depends on | May run alongside |
|---|---|---|---|---|
| R1 | strict vocabulary, benign headers, passes P2 and P3 (`aitm-core`) | R / redact worktree | none | W1..W11, H1 |
| R2 | passes P4, P5, P6 and the audit-only vocabulary test (`aitm-core`) | R | R1 | W-tasks, H1 |
| R3 | `redact_args.rs` rules S and D, the `server.rs` hunk, the e2e flip (`aitm-mcp`) | R | R2 | W-tasks, H1 |
| R4 | bounded traversal (`aitm-mcp`) | R | R3 | W-tasks, H1 |
| W1 | `aitm-core` ring hook, `AuditLogSetting`, core doc fixes | W / plan worktree | none | R-tasks, H1 |
| W2 | `mcp.audit_log` key and `AITM_AUDIT_LOG` | W | W1 | R-tasks, H1 |
| W3 | `audit_log.rs` skeleton: streams, paths, routing, limits | W | W2 | R-tasks, H1 |
| W4 | hardened file layer: `preflight`, start marker | W | W3 | R-tasks, H1 |
| W5 | writer core: queues, threads, routing, flush | W | W4 | R-tasks, H1 |
| W6 | drop-newest and `gap` markers | W | W5 | R-tasks, H1 |
| W7 | runtime error policy: reopen, degraded, throttled logging | W | W6 | R-tasks, H1 |
| W8 | rotation and retention | W | W7 | R-tasks, H1 |
| W9 | path re-check | W | W8 | R-tasks, H1 |
| W10 | `SecretRegistry` (`audit_log/registry.rs`) | W | W9 | R-tasks, H1 |
| W11 | `AuditLogHandle`, `start`, `start_at`, boot policy, source registration | W | W10 | R-tasks, H1 |
| M1 | merge chain R into the plan branch (orchestrator, local `git merge`) | plan worktree | R4 and its panel, W11 | none |
| W12 | field pipeline, text fields, registry and cut-secret masking | W | W11, M1 | D1, H1 |
| W13 | `args` pipeline: parse-first, tolerant JSON-text scan | W | W12 | D1, H1 |
| W14 | corpus A: rows R1 to R39, R50, R51, R53, R54, benign table, shape check | W | W13 | D1, H1 |
| W15 | corpus B: shapes, tools, known tokens, PoC, source registration | W | W14 | D1, H1 |
| W16 | in-process wiring tests: every server is audited | W | W15 | D1, H1, W17 |
| W17 | `agent.status.durable_audit` | W | W1 | D1, H1, W16 (see note) |
| W18 | `main.rs` registration of every source, real-binary tests | W | W11, W16 | D1, H1 |
| D1 | stale comments (`server.rs`, `aitm-ca`) | independent; plan worktree | M1 | any W task |
| D2 | README and INSTALL (audit log and redaction) | independent; plan worktree | W18 | H1 |
| H1 | harness hermeticity | independent; plan worktree | none | any task |
| C1 | whole-branch fences and 54 mutation checks (31 from the spec, 12 for the as-built rules (Amendment 2), 11 more (Amendment 3)) | W | all | none |

**[Amended: Amendment 3, whole-branch panel] What has landed at `e28a310e` (the commit of fix Y3):** R1 to R4 and fix rounds 1 to 6 (chain R merged three times: `bfe4483e`, `a6c4f344`, `320e1daa`), W1 to W18 (W14 `ed249691`, W15 `1231f845`, W16 `16960e9f`, W17, W18 `7ff3eeea`), D1 `f9c1f5b4`, D2 `6a1039e7`, H1 `0ffd0d15`, and the writer-side fixes `b1dfa3eb`, `f103d205`, `50d8efee`, `aa89d325` (Y2) and `e28a310e` (Y3). **Open:** the second merge of `origin/main` before the PR, and C1. The corpus tasks W14 and W15 are done, so the "W14 and W15 have not landed" notes of Amendment 2 below are history.

Valid orders: anything that respects Depends-on. **Default: chain R and chain W run concurrently in
two worktrees (one fresh Coder at a time per worktree); M1 happens at a quiet point of chain W after
W11 and R4's panel; W12 onward is strictly sequential.** W17 touches only `crates/aitm-plugins`, but
`aitm` links `aitm-plugins`: a half-edited `agent.rs` breaks a concurrent `cargo test -p aitm` in the
same worktree, so run W17 between other tasks, not beside a running W Coder (or in a child worktree).
H1 and D1 change only comments, Markdown, Python, shell and one test line.

### Parallel chains and the merge protocol

1. **Cut (orchestrator, Terminal panel).** After the plan is approved and committed on the plan branch:
   `git worktree add <path> -b claude/durable-audit-redact claude/durable-audit-462ca8`, with `<path>`
   next to the plan worktree (for example `.claude/worktrees/durable-audit-redact`). Chain R Coders get
   that path in their dispatch contract; chain W Coders keep the plan worktree path.
2. **Chain R** runs R1, R2, R3, R4 strictly in order in its worktree, one commit per task on its
   branch, a Tester after each, then the three-reviewer panel on the R1..R4 range with the
   **security reviewer first** (the redaction path is what Matt asked to be reviewed first).
3. **Chain W** runs W1..W11 in the plan worktree at the same time. By file the chains share exactly two
   merge points: `crates/aitm-core/src/lib.rs` (W1 edits the two `pub use` statements at about lines
   32 to 47, R1 adds `pub mod redact_strict;` at about line 26) and `crates/aitm-mcp/src/server.rs`
   (R3's code hunks versus D1's comment hunks; D1 is dispatched after M1 so it applies on top).
4. **M1 (orchestrator, Terminal panel, in the plan worktree):** when R4's panel is clean and W11 is
   committed: `git merge --no-ff claude/durable-audit-redact -m "merge: strict redaction chain (plan
   2026-10-31-durable-audit)"`. A conflict, if any, is `crates/aitm-core/src/lib.rs` only, a line-local
   union (keep W1's `pub use` lines and R1's `pub mod` line). **[Amended: Amendment 2, chain R fix
   rounds: M1 ran twice. The first merge (`bfe4483e`) brought in R1 to R4 and the fix rounds up to
   round 3; a second (`a6c4f344`) brought in round 4 (`R fix 4A` and `4B`).]** **[Amended: Amendment
   3, whole-branch panel: "twice" is now three times: `320e1daa` brought in rounds 5 and 6 (`R fix 5`,
   `6A`, `6B`). The R worktree still exists at `/private/tmp/claude-501/durable-audit-redact` (step 6
   did not happen yet) because the last rounds were cut there.]**
5. **After M1,** in the plan worktree: `cargo check --workspace --all-targets`, then `cargo test -p
   aitm-core -p aitm-mcp` (non-socket tests; socket tests are the orchestrator's). Both green before
   W12 is dispatched. W12 depends on `aitm_core::redact_strict` and `aitm_mcp::redact_args` existing
   on the plan branch.
6. **Afterwards** the R worktree is removed (`git worktree remove <path>`); its `target/` goes with it
   (each worktree carries a full Rust `target/`; use separate target directories, never a shared one,
   and `touch` edited sources before a red run). The R branch is not rebased and not pushed.
7. **Rebase on `origin/main`** happens once after M1 (before W18, the first edit to `main.rs`) and
   again before the whole-branch panel, never on the R branch. A sibling's in-place edit of
   `redact_value` is a manual merge into `redact_args.rs` (spec Rebase hazards). **[Amended: Amendment 2,
   chain R fix rounds: `origin/main` (v0.5.8) was merged in (`b3a2a8df`), not rebased, because the plan
   branch already carries merges of the R branch and a rebase would have replayed them. Where this
   plan says "rebase on `origin/main`" read "merge `origin/main`"; every fence is measured against
   the merge-base, `f2c9d70b`.]** **[Amended: Amendment 3, whole-branch panel: `origin/main` is merged
   twice in all, `b3a2a8df` and again before the PR. The second merge is not in the branch at
   `e28a310e`: the merge-base is still `f2c9d70b`, and the local `origin/main` ref has since moved
   (`1782353a`). Re-measure every fence and count after it.]**
8. **If chain R is not finished** when W11 is, W12 waits; W17, H1 and D1-after-M1 can be pulled forward.
9. **Panel cadence (deviation from WORKFLOW's panel per task, accepted by the orchestrator under
   autonomous mode, as PR 171 ran):** a Tester after **every** task; the three-reviewer panel at the
   group boundaries: chain R after R4 (security first), the writer group after W15, the wiring group
   after W18 (with D1, D2, H1), and once on the whole branch after C1's Part A.
10. **Dispatch.** Every Coder gets exactly: spec path, plan path, task id, and the worktree path of its
    chain (R tasks: the redact worktree; every other task: the plan worktree).

### Where each command runs (read this before dispatching)

- **Bash sandbox (Coder and Tester sub-agents).** `cargo build`, `cargo check`,
  `cargo fmt --check`, `cargo clippy -p <crate> --all-targets -- -D warnings`, and every test
  that binds no socket. `cargo` works offline once dependencies are fetched; if it cannot
  resolve, stop and ask the orchestrator to run `cargo fetch` in the Terminal panel. Scope
  every cargo command with `-p <crate>` and the test name (examples in each task). The full
  gate `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` is run
  by the orchestrator or Tester at the stage boundaries named below, never by a Coder per
  task.
- **Terminal panel (orchestrator only).** Every `git` write, `git push`, the `[socket]` tests
  (W18: `sigterm_flushes_a_real_boot`, `a_healthy_boot_says_one_line_and_never_the_token`,
  `the_generated_operator_bridge_token_never_reaches_disk`; the socket tests of `mcp.rs` and
  `web_bus_governance.rs` in R3's blast radius; R3's e2e run `python3 tests/e2e/run.py audit` against a built
  `aitm`), the chain merge M1, and the full gate. A Coder or Tester whose test fails only because the sandbox refuses a
  loopback bind reports "NOT RUN (socket)", never a pass or a fail; the orchestrator supplies
  the Terminal output. Tests marked `[socket]` still compile in the sandbox: run
  `cargo test -p aitm --test audit_log_binary --no-run` and quote it.
- **Two worktrees.** R1 to R4 run in the redact worktree on `claude/durable-audit-redact`; every other task
  runs in the plan worktree. A Coder verifies with `git rev-parse --show-toplevel` that it is in the worktree
  it was given and stops if not. The two worktrees have separate `target/` directories.
- **Two-step red for tasks that add API.** A test that names a symbol that does not exist yet
  fails to compile; that is a legitimate first red (quote the compiler line naming the missing
  item). Then add the minimum stub so it compiles (each task names it) and quote the
  assertion-level failure. Both outputs go in the report. "It failed as expected" is not a
  report.
- **Evidence, verbatim.** Every red and green run is the literal command and the literal
  output lines named in the task.
- **Stale target directories.** If `CARGO_TARGET_DIR` is shared with other worktrees (do not share it between
  the two chains), `touch`
  the edited sources before a red or green run so cargo does not reuse a stale artifact. A red
  run on a stale binary is worthless.
- **Gate exit status, not grep.** For the full run, redirect `cargo test` to a log and gate on
  its exit status. `rhai_e2e::script_cannot_escape_or_exceed_scope` is a known
  non-deterministic flake: judge it by whether the change touches Rhai (this one does not), not
  by an isolated rerun.

### Conventions for every task

- **Trust-gate scan.** `trust_gate_scan.rs` scans every `crates/*/src` file, `#[cfg(test)]`
  modules included, and bans `==`, `!=`, `matches!` and `if let` against `Frontend::Mcp` /
  `CallerTrust::Agent`. Classify origins with `Frontend::is_trusted_control()`; compare
  origins in tests with `aitm_core::origin_label(..)`. Passing `Frontend::Mcp` as an argument
  or a struct-field value is fine. Do not edit `origin_label` (`classifier_wildcard_free.rs`
  reads its body).
- **No `unsafe`, no new dependency** (`Cargo.lock` and every `Cargo.toml` unchanged), no
  field on `ConnCtx`, `AuditEntry` or `wire::Governance`. No `println!`/`eprintln!` in
  `audit_log.rs` or its submodules; output goes through `tracing` target `aitm::audit` only. No `unwrap()` or
  `expect()` on a path that handles a file, a channel or an entry in non-test code; tests may.
- **Building a connection in a test.** `ConnCtx::new(role)` then assign the `pub` fields
  (`conn_id = srv.next_conn_id()`, `client_label`); do not write a `ConnCtx { .. }` literal
  (a sibling adding a field would break it).
- **Dead code between tasks.** `audit_log.rs` grows over W3 to W13, so an item that
  non-test code does not use yet carries `#[allow(dead_code)] // used from <task id>`; the task
  that starts using it deletes the allow. C1 greps that none remains.
- **Strict redaction (every task that touches a redaction rule: R1 to R4, W10 to W15).** Passes run on
  **decoded plain text only**, never on JSON text (the writer decodes literals before calling `scrub_strict`);
  each is linear and idempotent; `scrub_text` is never called over JSON text anywhere in new code (C1 greps
  `audit_log` and `redact_args.rs` for it); no secret, canary, token or its length appears in any log line,
  `Debug` or panic message; tests use made-up canaries (`CNRY` + row + `x` + eight hex digits), never a real
  credential; a corpus or table test **collects** every failing row into one assertion message.
- **Test helpers, in the `#[cfg(test)] mod tests` of `audit_log.rs`** (created in W4,
  extended by later tasks, never in production code; the submodules' tests copy what they need): `scratch(tag)` returning a unique temp
  directory with a `Drop` guard that removes it (build the name from `std::process::id()`, a
  nanosecond clock and an atomic counter, as `crates/aitm/tests/audit_durable_connection_id.rs`
  does); `entry(command, origin, at_ms)` building an `AuditEntry` with explicit
  `at = UNIX_EPOCH + at_ms` (so `gap.from`/`gap.to` are exact), `connection_id: None`,
  `args_summary: "{}"`, `result: Ok`; `read_lines(path)` returning each line parsed as
  `serde_json::Value`; `entry_commands(path)` returning the `command` of every line that has
  that key (markers have none); `wait_until(timeout, cond) -> bool` polling every 5 ms (never a
  fixed sleep); `within(timeout, f)` running `f` on a thread and failing the test, not hanging
  it, when it is not done in time (a detached thread dies with the process).
- **No test sleeps for a production interval.** Intervals (re-check 5 s, reopen 1 s, rotation
  retry 60 s, warn throttle 60 s) are fields of `Tuning`, which the tests shorten.
- **Commit after each task** (protocol below). Report format is `coder.md`'s, plus the red and
  green runs the task names.

### The shared design of `audit_log.rs` and its submodules (names the tasks use)

The spec leaves the internals to the builder (`## Left to the builder`). The names below are this plan's,
so that W3 to W15 can refer to each other. A Coder who must rename one says so in the report and the next
Coder reads the file first. Items are `pub` only where marked; everything else is private to its module
(tests sit inside it). Submodules: `audit_log/registry.rs` (W10), `audit_log/pipeline.rs` (W12),
`audit_log/jsonscan.rs` (W13), each declared with `mod` in `audit_log.rs`.

```text
// audit_log.rs, W3
pub enum StreamKind { Control, Agent, Reads }          // Debug, Clone, Copy, PartialEq, Eq
impl StreamKind {
    pub const ALL: [StreamKind; 3];
    pub const fn index(self) -> usize;                 // 0, 1, 2
    pub const fn label(self) -> &'static str;          // "control", "agent", "reads"
    pub const fn queue_capacity(self) -> usize;        // 1024, 4096, 2048
    pub const fn max_bytes(self) -> u64;               // 4 MiB, 8 MiB, 8 MiB
    pub const fn keep_rotated(self) -> usize;          // 4, 5, 2
}
pub fn stream_path(base: &Path, kind: StreamKind) -> PathBuf;
pub fn stream_for(lane: AuditLane, origin: Frontend) -> StreamKind;
// W4
pub const MARKER_SCHEMA: u32 = 1;
struct FileId { dev: u64, ino: u64 }
trait LogFile: Send {
    fn append_line(&mut self, line: &str) -> io::Result<()>;   // ONE write of line + "\n"
    fn size(&self) -> u64;
    fn sync(&mut self) -> io::Result<()>;
    fn id(&self) -> Option<FileId>;                            // None for a fake: skips the re-check
}
struct FsFile;                                                  // the real LogFile
fn preflight(path: &Path, stream: StreamKind) -> io::Result<FsFile>;
fn start_marker_line(stream: StreamKind, at_ms: i64, pid: u32) -> String;
// W5
pub const SHUTDOWN_BUDGET: Duration;                           // 2 s
trait Backend: Send {
    fn open(&mut self, path: &Path, stream: StreamKind) -> io::Result<Box<dyn LogFile>>;
    fn rotate(&mut self, path: &Path, stream: StreamKind, keep: usize) -> io::Result<Box<dyn LogFile>>;
    fn recheck(&mut self, path: &Path, file: &dyn LogFile) -> Recheck;
}                                  // rotate/recheck default to Unsupported / Recheck::Same until W8, W9
struct FsBackend;                                               // open = preflight
struct StreamSpec { path: PathBuf, backend: Box<dyn Backend>, file: Option<Box<dyn LogFile>> }
struct Tuning { queue: [usize; 3], cap_bytes: [u64; 3], keep: [usize; 3],
                recheck: Duration, reopen: Duration, rotate_retry: Duration, warn_every: Duration }
impl Tuning { fn production() -> Tuning }                      // the spec's constants (pub from W11)
pub struct AuditLogWriter;                                      // impl DurableAudit, manual Debug
impl AuditLogWriter {
    fn from_specs(specs: [StreamSpec; 3], tuning: Tuning) -> io::Result<AuditLogWriter>;
    pub fn shutdown(&self, budget: Duration) -> ShutdownReport;
}
pub struct ShutdownReport { pub complete: bool, pub estimated_left: usize }
// W6
fn gap_marker_line(now_ms: i64, from: i64, to: i64, dropped: u64, failed: u64) -> String;
struct GapState;                                                // note_drop(at_ms), note_fail(at_ms), take()
// W7
struct WarnThrottle;                                            // new(every), admit(now: Instant) -> Option<u64>
// W9
enum Recheck { Same, Gone, Replaced, Refused(String) }

// audit_log/registry.rs, W10 (re-exported from audit_log)
pub enum Registration { Substring, WholeToken, Ignored }       // Debug, Clone, Copy, PartialEq, Eq
pub struct SecretRegistry;                                      // manual Debug "SecretRegistry { secrets: N }", no Display
impl SecretRegistry {
    pub fn new() -> SecretRegistry;                             // and Default
    pub fn register(&self, source: &str, secret: &str) -> Registration;
    pub fn mask(&self, text: &str) -> String;
    pub fn len(&self) -> usize;  pub fn is_empty(&self) -> bool;
    pub(crate) fn mask_trailing_fragment(&self, text: &str) -> String;   // W12
}
// audit_log.rs, W11
pub struct AuditLogHandle;                                      // Clone, manual Debug; holds the writer and its registry
impl AuditLogHandle {
    pub fn registry(&self) -> &Arc<SecretRegistry>;
    pub fn register_secret(&self, source: &str, secret: &str) -> Registration;
    pub fn generate_bridge_token(&self) -> String;              // web::generate_token(), registered before it returns
    pub fn shutdown(&self, budget: Duration) -> ShutdownReport;
    pub fn status(&self) -> DurableAuditStatus;
}
pub fn bridge_token(handle: Option<&AuditLogHandle>) -> String; // the one expression main.rs calls (W18)
pub fn start(cfg: &Config, ring: &Arc<AuditRing>, web_token: Option<&str>, env: &[(String, String)])
    -> anyhow::Result<Option<AuditLogHandle>>;
pub fn start_at(ring: &Arc<AuditRing>, base: &Path, ca_log: &Path, explicit: bool)
    -> anyhow::Result<Option<AuditLogHandle>>;
#[doc(hidden)] pub fn start_tuned(cfg: &Config, ring: &Arc<AuditRing>, web_token: Option<&str>,
    env: &[(String, String)], tuning: Tuning) -> anyhow::Result<Option<AuditLogHandle>>;
// audit_log/pipeline.rs, W12 (args_pass is the identity until W13)
pub(crate) fn render_line(entry: &AuditEntry, registry: &SecretRegistry) -> String;
// audit_log/jsonscan.rs, W13
pub(crate) fn redact_args_text(text: &str) -> String;           // parse-first, tolerant scan, plain-text fallback
```

Behaviour that is fixed across tasks: the queue is a `std::sync::mpsc::sync_channel` per stream carrying
`Entry(AuditEntry)` or `Close`; the producer side is `try_send` only; a stream thread is named
`aitm-audit-<label>`; a line is written with one `write_all` of the line plus `\n` and is never buffered (a
reader sees it at once); no lock is held across file I/O or across a registry mask; a stream's counters are
atomics shared with the producers through an `Arc`; masking and the pipeline run on the stream thread at
write time, so a late registration is seen by the next field masked.

### Symbols the tasks use (confirmed by reading on `abe5629` and `83b9e28`)

- `aitm_core` (re-exported at the crate root): `AuditEntry { at, origin, client_label,
  connection_id, command, args_summary, result }` (all `pub`, derives `Debug, Clone`, **no
  `PartialEq`**), `AuditResult::{Ok, Error(String)}`, `AuditLane::{Evidence, Routine}`,
  `AuditRing::{new, with_lane_capacities, append_in, recent, recent_for, count_since_for, len,
  is_empty, evidence_len, routine_len}` and `impl AuditSink` (`append` is the evidence lane),
  `origin_label`, `sanitize_client_label`, `DEFAULT_ARGS_SUMMARY_CAP` (512),
  `DEFAULT_RESULT_REASON_CAP` (1024), `Frontend::{Cli, Mcp, Operator}` with
  `is_trusted_control(self) -> bool`, `redact::scrub_text`. `AuditRing::count_since` is
  `#[cfg(test)]` inside `aitm-core`: integration tests use `len`, `recent` or
  `count_since_for`.
- `aitm_core::config::default_aitm_dir()` is **private** to `config.rs`; W1 calls it from
  `AuditLogSetting::resolved_path`, which lives in the same file.
- `TypeDesc`, `ParamDef`, `ParamSchema` derive `Debug, Clone` only (no `PartialEq`): tests
  pattern-match them.
- `aitm_ca::audit::entry_to_jsonl(&AuditEntry) -> String` (reachable as `aitm_ca::audit::..`;
  it is not re-exported at the `aitm_ca` root and this change edits `aitm-ca` comments only).
  `serde_json` without `preserve_order` sorts keys: an entry line's keys read `args, at,
  client_label, command, connection_id, origin, result`.
- `aitm::tui::{server, with_shared_governance, services, build_servers, TuiLog}`,
  `aitm::wire::{assemble, Assembled}` (`pub audit_ring: Arc<AuditRing>`, `pub agent_state`,
  `assembled.governance()`), `aitm_mcp::{McpServer, ConnCtx}` (`handle_on(&ConnCtx, &str) ->
  Option<String>`, `next_conn_id()`; `conn_id == 0` means "not a streaming connection" and
  yields `connection_id: null`). `tui::Services` is **not** `Clone`: call `tui::services(..)`
  again for a second consumer. `build_servers` returns `(Option<McpServer>, InProcessHandler)`.
- `aitm` already depends on `aitm-ca`, `aitm-core`, `aitm-mcp`, `serde_json`, `serde_yaml`,
  `tracing`, `tracing-subscriber`, `anyhow`; it has **no** `tempfile` and **no** `libc`.
  `aitm-plugins` has no `serde_json` and does not depend on `aitm-mcp`.
- `main.rs` (read at `abe5629`): `assembled.governance()` then the `Assembled { .. }`
  destructure at about lines 293 to 311 (it names `audit_ring`); the `Mode::Cli` branch
  returns at about 313 to 341; the pre-bind block starts at about 343; the shared tail (reap
  the browser, then `result`) is at about 603 to 614. `init_tracing` defaults to `info`, so an
  `info!` startup line shows by default on stdout; `aitm tui` has no tracing sink without
  `RUST_LOG`.
- `crates/aitm/tests/shutdown.rs`: `Aitm::spawn` builds the `Command` at about line 214
  (`.env("RUST_LOG", "info")` at 217). The binary prints errors through `main() ->
  anyhow::Result<()>`, so an `Err` from `run()` exits non-zero with `Error: <chain>` on stderr.
- (Amendment 1) `aitm_core::redact::{is_secret_key, scrub_text}` are called, never edited;
  `aitm_core::redact_strict::{scrub_strict, is_secret_key_strict, is_benign_header}` are R1/R2's.
  `aitm-core` depends on `regex` and `dirs` and has **no** `serde_json`; `aitm-mcp` depends on
  `serde_json`; `aitm` depends on `aitm-mcp` (so `aitm_mcp::redact_args::redact_value` is reachable from the
  writer), `aitm-poc` (`StdPocBuilder`, `PocSpec`, `Poc: Serialize`) and `serde_yaml`.
- `aitm_mcp::server`: `redact_value` (about 2447 to 2468) and the local `is_secret_key` (2476) are the
  deletions of R3's hunk; `record_audit` builds the reason as `AuditResult::Error(cap_reason(scrub_text(reason)))`
  at about line 1954; `redact_args(arguments)` clones the arguments into `redact_value` and cuts with
  `cap_text(.., 512)`.
  **[Amended: Amendment 2, chain R fix rounds: as built at `f9c1f5b4` `redact_value` and the local
  `is_secret_key` are gone from `server.rs`; the reason is `AuditResult::Error(cap_reason(aitm_core::
  redact_strict::scrub_strict_bounded(reason, crate::redact_args::REASON_EXAMINE_BYTES)))` at lines
  1966 to 1969; `redact_args(arguments)` still clones the arguments into `redact_value` (now imported
  from `crate::redact_args`) and cuts with `cap_text(.., 512)`.]**
- **[Amended: Amendment 2, chain R fix rounds]** The strict API as built: `aitm_core::redact_strict::{
  scrub_strict, scrub_strict_bounded(text, max_bytes), is_secret_key_strict, is_benign_header}`
  (`MAX_ROUNDS` 6 **[Amended: Amendment 3, whole-branch panel: 8, and a text no round settles is `[redacted]`]**; 42 benign names plus the `sec-fetch-` and `sec-ch-` prefixes) and
  `aitm_mcp::redact_args::redact_value` (`pub`; constants in Task R4's "bound as built"). The
  writer: `aitm::audit_log::{start, start_at, start_tuned, bridge_token, AuditLogHandle, SHUTDOWN_BUDGET
  (2 s), SecretRegistry, Registration}` and the crate-private `pipeline::render_line`,
  `jsonscan::redact_args_text`, `registry::CUT_MARK` (`…`).
- `aitm::wire`: `ScriptWiring { plugins, executor, poc_step_handlers, commands }` (`Default`);
  `commands: Vec<Box<dyn Plugin>>` is how a test registers its own stub commands into the assembled registry
  (`demo.accept`, `demo.fail`, `demo.echo`); `aitm_core::Plugin` has `name()` and `load(&mut self, &mut
  Registry)`.
- `aitm::web`: `generate_token() -> String` (64 hex characters), `WebSettings { listen, token, insecure_bind }`
  (the `token` is the web agent bridge token, resolved in `main.rs` before the config is loaded);
  `main.rs` mints the operator bridge token in the `web_server` block with `.then(web::generate_token)`. **[Amended: Amendment 2, chain R fix rounds: as built it is `.then(|| audit_log::bridge_token(audit.as_ref()))`
  (`main.rs:834` at `f9c1f5b4`); `start` is called at line 563 with the web token and the environment pairs; the
  tail flush is `handle.shutdown(audit_log::SHUTDOWN_BUDGET)` at line 920.]** **[Amended: Amendment 3,
  whole-branch panel: at `e28a310e` the flush is `tokio::task::block_in_place(|| handle.shutdown(audit_log::SHUTDOWN_BUDGET))`,
  `main.rs:922`; `start_at` is `#[doc(hidden)]`; `AuditLogWriter`, `stream_for` and the pipeline constants are private;
  `AuditLogHandle::registry()` returns the writer's one registry.]**
- Bus handshake for the binary tests: the first line on a loopback-TCP connection is `{"token":"<t>"}`
  (exactly one key); the operator token class wins over the agent class.
- `aitm_poc::builder::{PocBuilder, PocSpec, StdPocBuilder}`: `build(&self, &HttpFlow, PocSpec) ->
  anyhow::Result<Poc>`; `PocSpec { info, variables, success }`.

### AC coverage

`[red]`, `[guard]` and `[socket]` are the spec's labels; a note says where the plan departs (most
corpus and wiring tests are red by mutation, Call 4). One row per AC. Tests in `audit_log.rs` and its
submodules are run with `cargo test -p aitm --lib audit_log::<name>`; integration files with `cargo test
-p aitm --test <file>`; chain R's with `cargo test -p aitm-core --test redact_strict` and `cargo test -p
aitm-mcp --test audit_redaction`.

| AC | Task | Test (exact name) |
|---|---|---|
| AC1 | W2 | `audit_log_key_parses_every_spelling` (`audit_log_config.rs`) **[Amended: Amendment 3, whole-branch panel: the error never echoes the value; it ends `got a string that is neither off nor an absolute path` for a string and with the YAML kind (`a number`, `a list`, `a mapping`, ...) for another value; the never-echo test is `a_value_that_is_not_a_setting_is_never_echoed`, in the same file (`audit_log_config.rs`)]** |
| AC2 | W2 | `audit_log_env_wins_and_never_silently_disables` (`audit_log_config.rs`) **[Amended: Amendment 3, whole-branch panel: the warning says `AITM_AUDIT_LOG is <reason>; the audit log setting is unchanged` with `<reason>` one of `empty`, `a relative path`, `not one of off/on/default or an absolute path`, and never the value; `a_value_that_is_not_a_setting_is_never_echoed` pins it]** |
| AC3 | W3 | `stream_paths_follow_the_rule` (`audit_log_config.rs`; the `resolved_path` rows are green on arrival, W1 built them) |
| AC4 | W11 | `a_stream_path_equal_to_the_ca_log_is_refused` (`audit_log_config.rs`) **[Amended: Amendment 3, whole-branch panel: the collision is on resolved files and rotated names: `a_ca_log_that_is_a_stream_file_in_another_spelling_is_refused` (`audit_log_config.rs`) covers `..`, a link to the directory and `audit.jsonl.1`/`.4`, `audit.agent.jsonl.5`, `audit.reads.jsonl.2`, and the names just past what a stream keeps start normally]** |
| AC5 | W11 | `a_fresh_start_creates_private_files` (mechanism pinned earlier by W4's `preflight_creates_private_dirs_and_files_with_a_start_marker`) |
| AC6 | W11 | `restart_appends_never_truncates` (mechanism pinned earlier by W4's `preflight_appends_a_start_marker_and_repairs_a_torn_tail`) |
| AC7 | W4 | `hostile_paths_are_refused_without_hanging` |
| AC8 | W4 | `an_unwritable_parent_is_an_error` |
| AC9 | W11 | `explicit_fails_the_boot_default_degrades` (mechanism: W7's `a_stream_that_never_opened_counts_every_entry_as_a_failure`) |
| AC10 | W11 | `off_creates_nothing` (passes against the W11 stub: recorded) |
| AC11 | W5 | `entries_are_routed_by_lane_and_trust` |
| AC12 | W5 | `an_entry_line_has_exactly_the_seven_keys` (`[guard]`; stays green through W12 and W13) |
| AC13 | W16 | `a_real_server_call_reaches_the_file_with_its_connection_id` (`audit_log_wiring.rs`; red by mutation) |
| AC14 | W16 | `every_server_this_binary_builds_is_audited` (red by mutation) |
| AC15 | W16 | `the_tui_operator_server_stays_unaudited` (`[guard]`) |
| AC16 | W13 | `a_hostile_entry_is_sanitised_before_it_is_written` (the text fields' half is W12's `text_fields_are_scrubbed_registry_masked_controlled_and_capped`) |
| AC17 | W13 | `an_honest_entry_is_written_unchanged` (`audit_log_wiring.rs`; includes the two AC47 shapes; green on arrival, red by mutation C1 26) |
| AC18 | W6 | `a_stalled_disk_never_blocks_the_call_path` |
| AC19 | W6 | `a_flooded_stream_cannot_starve_another` (green on arrival: W5's separate queues; recorded) |
| AC20 | W7 | `a_write_error_loses_the_entry_and_marks_the_gap` |
| AC21 | W5 | `recording_after_shutdown_is_counted_never_blocking` |
| AC22 | W9 | `a_path_that_becomes_a_directory_costs_the_caller_nothing` |
| AC23 | W8 | `rotation_loses_no_line` |
| AC24 | W8 | `retention_deletes_only_the_oldest_rotated_file` |
| AC25 | W8 | `a_failed_rotation_never_drops_the_line` **[Amended: Amendment 3, whole-branch panel: the test is the same name but now records 12 lines (past the cap, under twice it) and asserts `degraded`; the ceiling is `a_wedged_rotation_holds_the_file_to_twice_its_cap` and the recovery `a_wedged_rotation_recovers_when_the_slot_is_free`; AC25 reads "no line is lost up to twice the cap"]** |
| AC26 | W8 | `an_oversized_file_rotates_on_its_first_write` |
| AC27 | W9 | `a_removed_file_or_directory_is_recreated_with_a_start_marker` |
| AC28 | W9 | `a_file_swapped_for_a_symlink_is_not_written_through` |
| AC29 | W5 | `shutdown_flushes_every_queued_entry` |
| AC30 | W5 | `shutdown_of_a_blocked_writer_returns_within_its_budget` |
| AC31 | W18 | `sigterm_flushes_a_real_boot` (`audit_log_binary.rs`, `[socket]`) |
| AC32 | W17 | `agent_status_reports_durable_audit_by_role` (`agent_status_durable.rs`) |
| AC33 | W17 | `agent_status_output_schema_declares_every_durable_audit_key` (description row green on arrival) |
| AC34 | W1 | `the_ring_hook_is_set_once_and_lock_free` (`durable_audit_hook.rs`) |
| AC35 | W17 | `no_command_reads_or_reveals_the_audit_file` (`[guard]`; whole-registry supplement `no_registered_command_name_starts_with_audit` in W16) |
| AC36 | W18 | `a_healthy_boot_says_one_line_and_never_the_token` (`[socket]`) |
| AC37 | W18 | `an_explicit_bad_path_fails_the_boot_loudly` (no socket) **[Amended: Amendment 3, whole-branch panel: the test's clock is `FAILED_BOOT_TIMEOUT` = 10 s (the criterion's 5 s is what the design promises; the boot fails in milliseconds)]** |
| AC38 | H1 | grep checks over seven files (C1 repeats them) **[Amended: Amendment 2, chain R fix rounds: nine files; the two orchestrator additions are `apps/web/scripts/live-env.mjs` and `apps/mac/tools/selftest-live-embedded.sh`]** |
| AC39 | W1, D1, D2 | grep checks (W1: core `audit.rs`; D1: `server.rs`, `aitm-ca`; D2: README, INSTALL; C1 repeats) |
| AC40 | C1 | the relaxed diff-fence commands of C1 Part A **[Amended: Amendment 2, chain R fix rounds: measured against the merge-base `f2c9d70b`; `grep -c '^+'` prints `6` and `grep -c '^-'` prints `24`; never count `@@` on the whole branch]** **[Amended: Amendment 3, whole-branch panel: re-measured at `e28a310e`: `6` and `24`, and `grep -c '^@@'` on `server.rs` is `7` on the whole branch (3 executable and D1's 4 comment hunks); re-measure after the second merge of `origin/main`]** |
| AC41 | C1 | the `git diff --name-status` checks of C1 Part A |
| AC42 | C1 | the Rust gate |
| AC43 | C1 | mutations 1 to 13 of C1 Part B |
| AC44 | R1, R2 | `scrub_strict_masks_every_pass_and_keeps_the_benign` (`redact_strict.rs`; R1 the P2, P3 and benign rows, R2 the rest; extras `is_secret_key_strict_vocabulary`, `is_benign_header_table`) **[Amended: Amendment 2, chain R fix rounds: the `otp` row is the mid-line form; the fix rounds add 18 tests to `crates/aitm-core/tests/redact_strict.rs` (`shapes_found_by_fuzzing_are_fixed_points`, `a_private_key_block_is_masked_whole_whatever_precedes_it`, `userinfo_runs_to_the_last_at_of_the_authority`, `a_compact_jwe_is_masked_to_its_tag`, `rust_debug_wrappers_around_a_secret_are_masked_whole`, `escaped_quote_frames_are_masked_to_their_matching_closer`, `camel_case_keys_are_secret_keys_in_text`, `folded_header_lines_and_zero_width_blanks_are_part_of_the_header`, `xml_elements_with_a_secret_name_are_masked`, `multipart_fields_with_a_secret_name_are_masked`, `cli_flags_with_a_secret_name_are_masked`, `the_pair_value_rule_matches_scrub_text`, `every_prefix_of_every_shape_fires`, `a_bounded_scrub_cuts_first_and_masks_what_straddles_the_cut`, `bracketed_values_under_a_secret_key_are_masked_whole`, `bracket_notation_form_keys_are_pairs`, `userinfo_may_hold_a_quote_and_ends_at_the_quote_that_opened_the_url`, `curl_user_flags_mask_the_password_part`) and 4 in-module tests in `redact_strict.rs`]** **[Amended: Amendment 3, whole-branch panel: 11 in-module tests and 28 in `tests/redact_strict.rs` at `e28a310e`; `the_rounds_are_bounded` was renamed and split into `a_text_that_never_settles_is_replaced_whole_after_max_rounds`, `a_text_that_settles_on_the_last_allowed_round_is_kept`, `a_shape_that_needs_seven_calls_settles_within_the_cap` and `the_replacement_is_itself_a_fixed_point`; new in the test file: `a_shape_that_needed_seven_rounds_is_masked_not_replaced`, `a_text_that_does_not_settle_is_replaced_whole`, `an_unquoted_value_runs_across_a_quote_that_does_not_end_it`, `a_header_after_an_escaped_line_break_is_masked_to_the_end_of_its_line`, `a_pair_after_an_escaped_line_break_is_masked_whatever_its_key`; and in the module `a_line_escape_glued_to_a_name_run_is_a_backslash_and_n_r_or_t`, `a_key_run_starts_after_a_glued_escape_letter`, `the_letter_of_an_escaped_break_is_n_r_or_t_after_a_backslash`, `every_entry_of_the_shape_table_is_found_after_an_escaped_break`; and, for fix Y3, `a_credential_shape_after_an_escaped_line_break_is_masked` in the test file]** |
| AC45 | R3 | `rules_s_and_d_redact_header_collections_and_siblings` (`audit_redaction.rs`) **[Amended: Amendment 2, chain R fix rounds: widened shapes are pinned by `header_pairs_lines_and_objects_are_default_deny`, `multi_line_and_multi_value_headers_are_default_deny`, `header_collection_context_is_default_deny` and `header_hardening_is_default_deny` in the same file, and by 46 in-module tests of `redact_args.rs`]** |
| AC46 | R4 | `redaction_work_is_bounded` (`audit_redaction.rs`; deterministic reds: `a_leaf_beyond_4096_bytes_is_cut_with_an_ellipsis`, `after_64_kib_every_later_leaf_is_an_ellipsis`, `redaction_output_is_bounded_in_size`) **[Amended: Amendment 2, chain R fix rounds: the clock is 20 s; the reason clause is `the_reason_work_is_bounded` (60 s clock), `the_reason_is_bounded_before_the_text_pass` and `a_frame_that_runs_past_the_cut_is_masked`]** |
| AC47 | R3, W13, W14 | `redaction_is_idempotent_and_json_safe` (`audit_redaction.rs`, source half, R3); `an_honest_entry_is_written_unchanged` (writer half, W13); `corpus_args_are_idempotent_under_redact_value` (corpus values, W14) **[Amended: Amendment 3, whole-branch panel: the writer half is in `audit_log_wiring.rs`, the corpus half now exists; `redact_value` is exactly idempotent because a value no walk round confirms is replaced whole by `"<redacted>"`]** |
| AC48 | W10 | `registry_tiers` |
| AC49 | W10 | `registry_masks_every_encoding` |
| AC50 | W12 | `a_late_registration_reaches_a_running_writer` |
| AC51 | W11 | `a_secret_never_appears_in_debug_display_or_logs` (registry half earlier: W10's `registry_debug_prints_only_a_count`) |
| AC52 | W15 | `start_registers_every_configured_source` (`audit_log_redaction.rs`; the registration mechanics are W11's `start_registers_the_configured_sources`) **[Amended: Amendment 2, chain R fix rounds: pending; `audit_log_redaction.rs` is not in the branch at `f9c1f5b4` (W14, W15 have not landed)]** **[Amended: Amendment 3, whole-branch panel: MET. `start_registers_every_configured_source` (line 3363 at `e28a310e`) is in `crates/aitm/tests/audit_log_redaction.rs` (W14 `ed249691`, W15 `1231f845`); the "pending" above is history]** |
| AC53 | W11 | `the_operator_bridge_token_is_registered_when_minted` |
| AC54 | W13 | `cut_secrets_and_the_tolerant_scan` (the fragment mask is W12's `a_cut_registered_secret_is_masked_at_a_field_end`; (a) uses the Ambiguity 14 arithmetic) |
| AC55 | W14, W15 | `no_canary_reaches_any_file_through_the_real_path` (`audit_log_redaction.rs`; W14 rows R1 to R39, R50, R51, R53, R54, W15 the other 35 of the 74; red by mutation) **[Amended: Amendment 2, chain R fix rounds: pending; `audit_log_redaction.rs` is not in the branch at `f9c1f5b4` (W14, W15 have not landed)]** **[Amended: Amendment 3, whole-branch panel: MET. `no_canary_reaches_any_file_through_the_real_path` is in `crates/aitm/tests/audit_log_redaction.rs` (W14 `ed249691`, W15 `1231f845`); the "pending" above is history]** |
| AC56 | W14 | `benign_values_survive_the_real_path_byte_for_byte` **[Amended: Amendment 2, chain R fix rounds: pending; `audit_log_redaction.rs` is not in the branch at `f9c1f5b4` (W14, W15 have not landed)]** **[Amended: Amendment 3, whole-branch panel: MET. `benign_values_survive_the_real_path_byte_for_byte` is in `crates/aitm/tests/audit_log_redaction.rs` (W14 `ed249691`, W15 `1231f845`); the "pending" above is history]** |
| AC57 | W14 | `every_line_is_valid_json_with_the_same_shape` (covers W15's rows once they are added) **[Amended: Amendment 2, chain R fix rounds: pending; `audit_log_redaction.rs` is not in the branch at `f9c1f5b4` (W14, W15 have not landed)]** **[Amended: Amendment 3, whole-branch panel: MET. `every_line_is_valid_json_with_the_same_shape` is in `crates/aitm/tests/audit_log_redaction.rs` (W14 `ed249691`, W15 `1231f845`); the "pending" above is history]** |
| AC58 | W18 | `the_generated_operator_bridge_token_never_reaches_disk` (`audit_log_binary.rs`, `[socket]`) |
| AC59 | R3 | the `X-Audit-Marker` assertion of `tests/e2e/audit/test_audit_log.py` (`[e2e]`, Terminal panel: `python3 tests/e2e/run.py audit`; `py_compile` in the sandbox) |
| AC60 | R3 | `the_reason_is_scrubbed_strictly_at_the_source` (`audit_redaction.rs`) |
| AC61 | W15 | `a_built_poc_passes_through_the_audit_clean` (placeholder clause per Ambiguity 26) **[Amended: Amendment 2, chain R fix rounds: pending; `audit_log_redaction.rs` is not in the branch at `f9c1f5b4` (W14, W15 have not landed)]** **[Amended: Amendment 3, whole-branch panel: MET. `a_built_poc_passes_through_the_audit_clean` is in `crates/aitm/tests/audit_log_redaction.rs` (W14 `ed249691`, W15 `1231f845`); the "pending" above is history]** |
| AC62 | R3, C1 | `[guard]` the existing redaction suites unmodified (R3's blast-radius runs; C1 Part A repeats them and the no-edit diff) |
| AC63 | R2 | `the_strict_vocabulary_is_audit_only` (`redact_strict.rs`) |
| AC64 | C1 | mutations 14 to 31 of C1 Part B (each AC64 clause maps to a numbered mutation) **[Amended: Amendment 2, chain R fix rounds: and mutations 32 to 43 for the as-built rules; 43 is the expected survivor]** **[Amended: Amendment 3, whole-branch panel: and mutations 44 to 54 (fail closed, the wedged ceiling and `degraded`, the CA collision, the echoed value, the glued escapes in P2, the frames pre-pass, P6 and P5, the registry depth, the fragment mask); mutations 35 and 37 are re-worded; 43 survives]** |
| AC65 | D2 | grep checks (`<redacted>`, `Set-Cookie`, `tokens`, `bare credential` in the README) |

### Files each task may touch

No two concurrently runnable tasks share a file, except the two merge points named under the table.
Chain W tasks that share files are sequential. "(c)" is create, "(m)" is modify.

| Task | Chain | Files |
|---|---|---|
| R1 | R | `crates/aitm-core/src/redact_strict.rs` (c), `crates/aitm-core/src/lib.rs` (m: `pub mod redact_strict;` only), `crates/aitm-core/tests/redact_strict.rs` (c) |
| R2 | R | `crates/aitm-core/src/redact_strict.rs` (m), `crates/aitm-core/tests/redact_strict.rs` (m) |
| R3 | R | `crates/aitm-mcp/src/redact_args.rs` (c), `crates/aitm-mcp/src/lib.rs` (m: `pub mod redact_args;` only), `crates/aitm-mcp/src/server.rs` (m: three hunks), `crates/aitm-mcp/tests/audit_redaction.rs` (c), `tests/e2e/audit/test_audit_log.py` (m: one assertion) |
| R4 | R | `crates/aitm-mcp/src/redact_args.rs` (m), `crates/aitm-mcp/tests/audit_redaction.rs` (m) |
| W1 | W | `crates/aitm-core/src/audit.rs` (m, production code and doc comments only; its existing `mod tests` is not edited), `crates/aitm-core/src/lib.rs` (m: the two existing `pub use` statements only), `crates/aitm-core/src/config.rs` (m), `crates/aitm-core/tests/durable_audit_hook.rs` (c) |
| W2 | W | `crates/aitm/src/config_file.rs` (m), `crates/aitm/src/env.rs` (m), `crates/aitm/tests/audit_log_config.rs` (c) |
| W3 | W | `crates/aitm/src/audit_log.rs` (c), `crates/aitm/src/lib.rs` (m), `crates/aitm/tests/audit_log_config.rs` (m) |
| W4 to W9 | W | `crates/aitm/src/audit_log.rs` (m) only |
| W10 | W | `crates/aitm/src/audit_log/registry.rs` (c), `crates/aitm/src/audit_log.rs` (m: `mod registry;` and one `pub use`) |
| W11 | W | `crates/aitm/src/audit_log.rs` (m), `crates/aitm/tests/audit_log_config.rs` (m) |
| W12 | W | `crates/aitm/src/audit_log/pipeline.rs` (c), `crates/aitm/src/audit_log/registry.rs` (m), `crates/aitm/src/audit_log.rs` (m) **[Amended: Amendment 2, chain R fix rounds: as built W12 also created `crates/aitm/tests/audit_log_wiring.rs` (80 lines), so W13 modified it rather than created it]** |
| W13 | W | `crates/aitm/src/audit_log/jsonscan.rs` (c), `crates/aitm/src/audit_log/pipeline.rs` (m), `crates/aitm/src/audit_log.rs` (m: `mod jsonscan;`), `crates/aitm/tests/audit_log_wiring.rs` (c) |
| W14 | W | `crates/aitm/tests/audit_log_redaction.rs` (c) |
| W15 | W | `crates/aitm/tests/audit_log_redaction.rs` (m) |
| W16 | W | `crates/aitm/tests/audit_log_wiring.rs` (m) |
| W17 | W | `crates/aitm-plugins/src/agent.rs` (m), `crates/aitm-plugins/tests/agent_status_durable.rs` (c) |
| W18 | W | `crates/aitm/src/main.rs` (m), `crates/aitm/tests/audit_log_binary.rs` (c) |
| D1 | indep. | `crates/aitm-mcp/src/server.rs` (m, comment lines), `crates/aitm-ca/src/audit.rs` (m, comment lines) **[Amended: Amendment 2, chain R fix rounds: as built D1 also edited comment lines of `crates/aitm-core/src/audit.rs` (17 lines: the `DEFAULT_AUDIT_CAPACITY` and `AuditSink` docs); no executable line changed]** |
| D2 | indep. | `README.md` (m), `INSTALL.md` (m) |
| H1 | indep. | `tests/e2e/aitm_e2e/core.py`, `tests/e2e/run.py`, `tests/e2e/cli/cli-startup.sh`, `tests/e2e/start/test_bus_endpoint_file.py`, `scripts/bus-agent-check.py`, `scripts/tui-live-check.sh`, `crates/aitm/tests/shutdown.rs` (one line) (all m) **[Amended: Amendment 2, chain R fix rounds: nine files as built; the two orchestrator additions are `apps/web/scripts/live-env.mjs` and `apps/mac/tools/selftest-live-embedded.sh`, one line each]** |
| C1 | W | none permanently; temporary mutations in the files each names |
| R fix rounds 1 to 5 **[Amended: Amendment 2, chain R fix rounds]** | R | `crates/aitm-core/src/redact_strict.rs` (m), `crates/aitm-core/tests/redact_strict.rs` (m), `crates/aitm-mcp/src/redact_args.rs` (m), `crates/aitm-mcp/tests/audit_redaction.rs` (m), `crates/aitm-mcp/src/server.rs` (m: the one reason statement, fix 4B only). Round 5 touches only the first two |
| Fix rounds 5 and 6, and the writer-side fixes **[Amended: Amendment 3, whole-branch panel]** | R / W | Rounds 5 (`ba742893`) and 6A (`a54c5abe`): `crates/aitm-core/src/redact_strict.rs` (m), `crates/aitm-core/tests/redact_strict.rs` (m). Round 6B (`b022f41b`): `crates/aitm-mcp/src/redact_args.rs` (m) only. `W10/W12 fix` (`b1dfa3eb`): `crates/aitm/src/audit_log/pipeline.rs`, `crates/aitm/src/audit_log/registry.rs`, `crates/aitm/tests/audit_log_redaction.rs` (m). Fix `X` (`f103d205`, 14 files): `crates/aitm/src/audit_log.rs`, `audit_log/{jsonscan,pipeline,registry}.rs`, `crates/aitm/src/{config_file,env,main}.rs`, `crates/aitm/tests/{audit_log_binary,audit_log_config,audit_log_redaction,audit_log_wiring}.rs`, and, comment lines only, `crates/aitm-core/src/audit.rs`, `crates/aitm-plugins/tests/agent_status_durable.rs` and `tests/e2e/aitm_e2e/core.py` (one comment line on the `AITM_AUDIT_LOG` assignment). Fixes `Y` (`50d8efee`), `Y2` (`aa89d325`) and `Y3` (`e28a310e`): `crates/aitm-core/src/redact_strict.rs` and its test file |

**Concurrency check.** Chain R's files and chain W's files are disjoint except two merge points, both
resolved by the sequential `git merge` of M1: (1) `crates/aitm-core/src/lib.rs`: W1 edits the two `pub use`
statements (about lines 32 to 47), R1 adds one `pub mod` line (about line 26), five unchanged lines apart,
so git merges them unaided and a conflict, if any, is a one-line union; (2) `crates/aitm-mcp/src/server.rs`:
R3's code hunks (the reason line near 1954, the deletion near 2447 to 2480, the `use` line) versus D1's
comment hunks (near 1057, 1136, 1917); D1 is dispatched after M1, so there is nothing to merge. H1's
`tests/e2e/audit/test_audit_log.py` neighbour is R3's file, but H1 does not touch it (it edits `core.py`,
`run.py`, the shell scripts and `test_bus_endpoint_file.py`). W17 is disjoint from W2 to W16 and W18 by
file (see the compile caveat above).

### Calls made in this plan (Architect's calls, for Matt to correct)

1. **Order.** `agent.status` (W17) sits after the in-process wiring tests (W16) and before `main.rs`
   (W18), so the most contested file (`main.rs`) is edited last among the code tasks and the rebase lands
   right before it. W17 depends only on W1 and may move earlier.
2. **Layering of the writer.** Counters and failure counting arrive in W5, gap markers in W6, reopen in W7,
   rotation in W8, the re-check in W9, the registry in W10, the handle and `start` in W11, the field
   pipeline in W12 and W13, so each task's tests are red against the previous task's code. The names of the
   internal seam are this plan's.
3. **`ShutdownReport { complete, estimated_left }`**: the spec lets the builder pick the shape.
4. **AC13, AC14 and the corpus are mutation-proven red**, not literally test-first: by the time they are
   written every piece exists, so the Coder proves the tests catch the defect by temporarily removing a rule
   (each task names the mutations) and quoting the failure and an empty `diff` after the restore.
5. **Extra tests beyond the AC list** (orchestrator decision: they stay), each named where it appears, pin
   mechanisms the ACs rely on. They add no scope.
6. **`create_new` when the file is absent (W4).** Step 3 of the spec's preflight says `append(true)`
   `.create(true)`. When step 2 found no file the Coder uses `create_new(true)` instead (same observable
   result, mode `0600`; it closes the window in which a symlink is planted between steps 2 and 3, because
   `O_EXCL` refuses a symlink even a dangling one). An existing regular file is opened with `append(true)`
   and no `create`.
7. **Harness (H1), orchestrator decisions:** H1 edits `tests/e2e/run.py` (one line covering every suite) and
   `tests/e2e/start/test_bus_endpoint_file.py` as well as the spec's files, and reports any further spawn
   site rather than editing it; `core.py` points the real writer at a per-launch file under the launch's
   temp directory so e2e cells exercise it (Ambiguity 19).
8. **Mutation checks (C1) are run by a fresh Coder**, not the Tester: WORKFLOW gives the Tester "tests only",
   and a mutation edits source. Each mutation is applied to a saved copy, reverted by hand and proven
   reverted by `diff`, as in the PR 171 plan.
9. **Submodules.** The registry, the field pipeline and the tolerant scan live in `audit_log/registry.rs`,
   `pipeline.rs` and `jsonscan.rs` (the spec's "or a submodule of it"), so `audit_log.rs` stays reviewable
   and the redaction tasks touch their own files.
10. **Chain R is four tasks, ids are prefixed.** The coordinator named R1 and R2; the passes are split
    across R1/R2 (about 300 production lines each) and the structural rules across R3/R4, so each task is
    one reviewable sitting. Ids `R1`..`R4`, `W1`..`W18`, `D1`, `D2`, `H1`, `C1` make the chain visible in
    every cross-reference.
11. **`start` signature.** `start(cfg, ring, web_token, env)` takes the web agent token and the process
    environment as arguments (the spec: the web token "passed to `start` as an argument", the environment
    lookup "injected"); `start_at(ring, base, ca_log, explicit)` is the path-level seam;
    `#[doc(hidden)] start_tuned(.., Tuning)` is the rotation seam the corpus needs (Ambiguity 17).
12. **AC17 is proved through the real writer** (files compared with `entry_to_jsonl` of the ring entries),
    not through a private `render_line`, so it covers the whole path.
13. **Panel cadence deviates from WORKFLOW's panel per task** (a Tester after every task; the panel at group
    boundaries and on the whole branch), accepted by the orchestrator under autonomous mode, as PR 171 ran.
14. **Interim `args_pass` identity (W12).** W12 passes `args` through unchanged until W13 lands, instead of
    running a text pass over JSON text; no intermediate commit is ever shipped (Ambiguity 23).

15. **[Amended: Amendment 2, chain R fix rounds] Merge, not rebase.** `origin/main` (v0.5.8) was merged into the
    plan branch (`b3a2a8df`) because the branch already carried a merge of chain R (`bfe4483e`) and a rebase would
    have replayed it; chain R's last round came in by a second merge (`a6c4f344`). Every fence and diff is measured
    against the merge-base with `origin/main`, `f2c9d70b`.
16. **[Amended: Amendment 2, chain R fix rounds] The fix rounds are fix tasks, not new task ids.** Five rounds
    (the list is under Task R4) were dispatched from panel findings reports to fresh Coders on the chain R branch,
    as WORKFLOW's stage 6 describes. `R1` to `R4` stay the task ids; the commit names (`R2 fix`, `R4 fix`,
    `R4 fix 2`, `R fix 3A`/`3B`, `R fix 4A`/`4B`) are the fix names.
17. **[Amended: Amendment 2, chain R fix rounds] `MAX_ROUNDS` is 6.** Neither the spec nor this plan stated a round
    count for `scrub_strict` ("idempotent" was the whole text). The code started at four (fix `R2 fix`) and has six
    since fix 4A; the sibling bounds are `SETTLE_ROUNDS` 3 and `OUTPUT_ROUNDS` 4. A text that has not settled is
    returned as the last round left it, and idempotence is a measured property, not a proof (spec Residual risks 22).
    **[Amended: Amendment 3, whole-branch panel: the constant is 8 since fix 6A, and the last two sentences are
    superseded: a text no round settles is replaced whole by `[redacted]` and `redact_value` replaces a value no walk
    round confirms by `"<redacted>"` (fix 6B), so idempotence is a property of the design (Call 20).]**
18. **[Amended: Amendment 2, chain R fix rounds] The mutation list is 43, not 31.** C1 Part B keeps the spec's 31 and
    adds 12 for the as-built rules (numbers 32 to 43), one of which (43, the tail `shutdown` in `main.rs`) is
    **expected to survive**. **[Amended: Amendment 3, whole-branch panel: the list is 54: mutations 44 to 54 are new,
    35 and 37 are re-worded, and 43 now covers the `block_in_place` wrapper too.]**
19. **[Amended: Amendment 2, chain R fix rounds] Clocks.** AC46's body-bound clock is 20 s, the reason-work test's is
    60 s, and the hostile-input guards of `redact_strict.rs` are `HOSTILE_SECS` = 60 s. They separate bounded work
    from unbounded work and are generous on purpose; the deterministic tests carry the bound.
20. **[Amended: Amendment 3, whole-branch panel] The redaction rounds fail closed.** `scrub_strict` repeats its round
    up to `MAX_ROUNDS` = 8 and a text no round settles is replaced whole by `[redacted]`; `redact_value` repeats its
    walk (the first plus `SETTLE_ROUNDS` = 3 further) and a value no round confirms is replaced whole by
    `"<redacted>"` (fixes 6A and 6B). Why: a bounded loop is bypassable by an adversary who chooses the layering unless
    hitting the bound fails closed. Cost: an attacker-built string can be forced to `[redacted]` (spec Residual risks 31).
21. **[Amended: Amendment 3, whole-branch panel] A wedged rotation is held to twice its cap.** It supersedes the first
    text's "a failed rotation never costs a line": no line is lost up to twice the cap, past it a line is refused,
    counted `dropped` and marked in the `gap`, and `degraded` is on (`rotation_wedged`). The 92 MiB bound holds while
    rotation works.
22. **[Amended: Amendment 3, whole-branch panel] Fix names `X`, `Y`, `Y2`, `Y3`.** The orchestrating session's labels for
    the whole-branch fixes: `X` the panel's writer/config/API fixes (`f103d205`), `Y` the glued escape in P2
    (`50d8efee`), `Y2` the same rule in the frames pre-pass and P6 (`aa89d325`), `Y3` the same rule at P5's left boundary
    (`e28a310e`, committed). The commit order in `git log` is `Y`, `X`, `Y2`, `Y3`.
23. **[Amended: Amendment 3, whole-branch panel] The CA-log collision is on resolved files, rotated names included, and
    diagnostics never echo a value.** Two small design decisions the panel forced (spec Design 2, AC1, AC2, AC4).
24. **[Amended: Amendment 3, whole-branch panel] The corpus seed.** The corpus draws one seed per process, prints it in
    every failure message and honours `AITM_CORPUS_SEED` so a failure replays; `FLUSH_TIMEOUT` (5 s) and
    `FAILED_BOOT_TIMEOUT` (10 s) are named test constants, and no test asserts on a wall-clock bound it does not need.
25. **[Amended: Amendment 3, whole-branch panel] Narrowed seams.** `start_at` is `#[doc(hidden)]`; `AuditLogWriter`,
    `stream_for` and the pipeline constants are private; `Tuning` and `start_tuned` stay `#[doc(hidden)] pub` (the corpus
    needs the rotation seam); one registry (`AuditLogHandle::registry()` returns the writer's); `io_refusal` and
    `io_context` are free functions. The tail flush in `main.rs` runs in `tokio::task::block_in_place`.

### Ambiguities and spec gaps

None blocks the build. Each has the default this plan chose and why. Items 1 to 13 are the first pass
(re-checked against Amendment 1: 3 and 4 unchanged, 4 reworded); 14 onward are new.

1. **Where a `gap` line lands relative to queued entries (Design 6, 7, AC18).** The spec writes it "before
   the next successful entry after any entry was lost". Under drop-newest the lost entries are newer than
   everything already queued, so the literal rule puts the line before the queued backlog, not after it.
   **Default:** the literal rule (the writer emits a pending gap before the next entry it writes), because
   AC18 asserts only the line's fields, and `from`/`to` plus the line's own `at` place the hole for a reader
   who sorts by `at` (D2's README says to sort by `at`). A positionally exact marker would be a different
   design.
2. **`start`, `start_at` parameters and behaviour (AC4, AC9, Design 14.4).** The spec names the seam only as
   "`start_at(path, explicit)`" and says the web token is passed to `start` as an argument and the
   environment lookup is injected. **Default:** `start(cfg, ring, web_token, env: &[(String, String)])`,
   `start_at(ring, base, ca_log, explicit)`, `start_tuned(cfg, ring, web_token, env, tuning)`; a relative
   `base` is unusable in both modes; the `ca.audit_log` collision is an error in both modes; if
   `attach_durable` returns `false` the new writer is shut down and an error is returned, so tests use a fresh
   ring per start (AC6's second start too); all secrets are registered **before** the sink is attached.
3. **AC9 "creates nothing" on an explicit failure.** Files created for an earlier stream of the same call are
   not rolled back (control is opened first). The AC's unusable path (under a regular file) fails on the
   first stream, so nothing exists. **Default:** no rollback.
4. **Design 6's "the pass is a no-op on honest entries" is not exact for a raw DEL or C1 character.**
   `serde_json` escapes below U+0020 but not DEL or U+0080 to U+009F, so a call whose argument carries one is
   rewritten by the writer's control step (its point). Amendment 1 fixed the other way an honest entry
   changed (the pipeline never runs `scrub_text` over JSON text), so AC17 holds for ordinary entries and for
   the two AC47 shapes. **Default:** keep the control step; AC17 and AC47 use those entries.
5. **Cut forms and order.** `command` is cut to 128 characters and `connection_id` to 64 bytes with **no**
   `…`; `args` and `result.error` keep the `…` as in the ring. Design 14.5's order is bound, pass, registry,
   **controls, cap**, trailing fragment; **default:** exactly that, so U+FFFD (three bytes) is counted by the
   cap and AC16's 515 and 1027 byte bounds hold.
6. **AC43 and AC64 mutations without an in-place form.** A `sync_channel` cannot drop its head, so "drop
   oldest instead of drop newest" is run as "record the `at` of the queued entry instead of the refused one"
   (C1 mutation 2); "sink on one server instead of the ring" is run as "remove `attach_durable` from
   `start_core`" (C1 mutation 10).
7. **AC35 in the plugins test sees only `aitm-plugins`' commands.** **Default:** write it as specified (W17)
   and add a whole-registry supplement in the wiring file (W16, `no_registered_command_name_starts_with_audit`).
8. **AC1 YAML value types the spec does not list** (a number, a list). **Default:** a catch-all variant makes
   every unsupported shape the same error naming `mcp.audit_log` and `absolute`; a quoted `"true"` is not the
   boolean and errors.
9. **`AITM_AUDIT_LOG` comparison.** ASCII-lowercased, **not** trimmed: `" off"` is "any other value" (the
   setting stays, one `warn!`). Stays on, the fail-safe direction.
10. **`ca.audit_log` collision is a lexical path comparison** (no canonicalisation): the stream paths are
    absolute and refuse symlinks, and `ca.audit_log` may not exist.
11. **Thread spawn failure** (never seen). **Default:** the policy of any other boot failure (explicit: `Err`;
    default: one `warn!` and `Ok(None)`).
12. **The spec's Files E list was incomplete** (`tests/e2e/run.py`, `test_bus_endpoint_file.py`). **Resolved
    by the orchestrator's decision:** H1 edits both and reports any further spawn site.
13. **`aitm_ca::entry_to_jsonl` (Design 6) is `aitm_ca::audit::entry_to_jsonl`.** No behaviour gap; no
    re-export is added.
14. **AC54 (a)'s arithmetic does not exercise a cut.** With `{"note":"` (9 bytes) + 470 `x` + the 26-byte secret
    + `"}` the text is 507 bytes, under 512, so the source never cuts it. **Default:** W13 builds the text so
    that exactly the first 10 bytes of the secret remain before the 512-byte cut and `…` (and R71 uses 483
    `x`, which cuts 20 bytes into the 64-hex token); both exceed the 6-byte fragment threshold.
15. **The trailing-fragment mask and the `…` marker (Design 14.4).** The source's cap appends `…` after the cut,
    so a field "ends with a prefix of the secret" only once that marker is set aside. **Default:**
    `mask_trailing_fragment` strips one trailing `…`, tests the end, masks the fragment, and restores the
    marker; AC54 (a)'s expected `[redacted]…` depends on it.
16. **AC47 "for every `args` value of the AC55 corpus".** The corpus lives in `aitm`'s tests; chain R cannot
    import it. **Default:** R3's `redaction_is_idempotent_and_json_safe` uses a local list (the AC45 inputs and
    the AC47 shapes); W14's extra `corpus_args_are_idempotent_under_redact_value` covers the corpus values
    themselves.
17. **A rotation seam for an integration test.** AC55 wants "a small rotation seam so at least one numbered
    file exists", from `crates/aitm/tests/`, where `#[cfg(test)]` items of the library are invisible.
    **Default:** `#[doc(hidden)] pub struct Tuning` with `pub fn production()` and `pub fn with_cap_bytes`,
    and `#[doc(hidden)] pub fn start_tuned`. The alternative (pre-filling a file to just under the cap) is
    uglier and slower. The corpus asserts a completeness guard (entry lines equal calls) so a rotated-away
    file cannot hide a leak.
18. **The `_confirm` clause.** The local `is_secret_key` in `server.rs` is `is_secret_key(key) ||
    key.to_ascii_lowercase().contains("_confirm")`; the spec says only that it is deleted. **Default:** the
    clause moves to `redact_args.rs`'s `is_secret_key_audit` (belt and braces: `_confirm` is stripped before
    redaction today).
19. **`run.py` and `core.py` interplay (orchestrator decisions 1 and 5).** If `run.py` sets
    `AITM_AUDIT_LOG=off` for every suite child and `core.py` used `setdefault`, no e2e cell would ever run the
    real writer. **Default:** `run.py` uses `setdefault(.., "off")` (for every spawn site without its own
    value); `core.py` **assigns** its per-launch file unless `AITM_E2E_AUDIT_LOG` is set.
20. **AC38 and AC41 name only `shutdown.rs` and the AC59 assertion.** H1 also edits `run.py` (a runner, not a
    test) and `test_bus_endpoint_file.py` (an existing e2e test: one environment line, the same class as
    `shutdown.rs`). **Default:** done under the orchestrator's decision; C1 lists both as the permitted
    modifications and the spec's AC38/AC41 wording should be amended by the orchestrator to match.
21. **AC58's host labels are longer than a DNS label** (a 64-hex token). The command may reject them; an
    audited call is recorded either way (`record_audit` runs after the gates and records refusals). **Default:**
    keep the spec's `<token>.example.test`.
22. **Recursion.** The tolerant scan is iterative, so a hostile 64 KiB of `[` cannot overflow the stack;
    `redact_value` recurses only to the depth `serde_json` accepts (128) when the text parses, and on a
    hand-built in-process `Value` it has no bound (no such producer exists). **Default:** as stated.
23. **W12's interim identity for `args`.** Between W12 and W13 the writer does not redact `args` text. No
    commit in that window is released; the corpus (W14, W15) and the writer-group panel run after W13.
24. **Submodule layout** (`audit_log/registry.rs`, `pipeline.rs`, `jsonscan.rs`): the spec lists
    `audit_log.rs` and says "(or a submodule of it)" for the registry and the scan; the pipeline module is
    this plan's call.
25. **P2's "line" and decoded text.** P2 masks to a real CR or LF in **decoded** text; the writer calls
    `scrub_strict` on decoded literals only, so a JSON-escaped `\r\n` is a real line break by then
    (AC47, AC54 (b)).
26. **AC61's placeholder assertion against the 512-byte cap.** A built PoC's YAML is longer than 512 bytes,
    so its tail is cut in the ring and the file alike. **Default:** assert the file's `args` equals the ring
    entry's and that every `{{...}}` placeholder present in the ring's `args` is present in the file's.
27. **Rule D and kept values.** R3 follows the spec's order: the name test decides (benign and not strict
    secret), a kept string value then passes `scrub_strict`; a non-string value under a non-benign name
    becomes `"<redacted>"` (AC45's `{"X-N":5}` row), a non-string under a benign name is kept.
28. **AC46 may not go red by time alone.** The unbounded 16 MiB scrub may finish inside 5 s on a fast host.
    **Default:** R4 adds deterministic tests (a 4096-byte cut, the 64 KiB budget, an output-size bound) beside
    the spec's wall-clock one; C1 mutation 30 is judged on those. **[Amended: Amendment 2, chain R fix rounds: the
    clock is 20 s, not 5 s (fix 4B); the three deterministic tests are unchanged and still carry the bound.]**
29. **[Amended: Amendment 2, chain R fix rounds] The AC44 `otp` row.** The spec's first text gave
    `"otp: 123456 done"` gives `"otp: [redacted] done"`; beside P2 that cannot hold (at the start of a line P2
    masks the whole line). **Default (done, `0b4b568`):** the row is the mid-line form `"x otp: 123456 done"`; the test's
    own comment is reworded, which is a code-side edit outside this document.
30. **[Amended: Amendment 2, chain R fix rounds] AC46's reason clause was missing.** The spec bounded the arguments
    only; fix 3B bounded the reason before the strict scrub and fix 4B made the server call `scrub_strict_bounded`.
    **Default:** the spec's AC46 gained a reason clause (`the_reason_work_is_bounded`,
    `the_reason_is_bounded_before_the_text_pass`, `a_frame_that_runs_past_the_cut_is_masked`); R4's text above is the
    first cut.
31. **[Amended: Amendment 2, chain R fix rounds] The benign list is 42 names, not 43.** R1's text counts 43;
    `sec-websocket-protocol` was removed in fix 3A (a bearer carrier). `is_benign_header_table` pins the list.
32. **[Amended: Amendment 2, chain R fix rounds] The hostile guard is 60 s, not 20 s** (`HOSTILE_SECS` in
    `crates/aitm-core/tests/redact_strict.rs`); R1 and R2 say 20 s.
33. **[Amended: Amendment 2, chain R fix rounds] R4's single budget is three pools** (leaf and name text 64 KiB,
    header-collection keys 64 KiB, other keys 64 KiB), with names and keys cut at 256 bytes, depth cut at 64 and
    the walk settling in up to four rounds. R4's text describes the first cut.
34. **[Amended: Amendment 2, chain R fix rounds] R3's "exactly three hunks" survives, but the reason statement is four
    lines** (`scrub_strict_bounded(reason, crate::redact_args::REASON_EXAMINE_BYTES)`). C1's fence numbers are
    therefore `6` `+` lines and `24` `-` lines against `f2c9d70b`, not the "3 `+` lines" of the first text.
35. **[Amended: Amendment 2, chain R fix rounds] The producer's `…` and the scan.** Ambiguity 15 sets the marker aside for
    the fragment mask only. The tolerant scan needs the same: when the cap's cut falls after a `,`, inside a number or
    inside a word, the marker is outside every string literal and the letter of spec 14.5 ("on anything else give up")
    would have sent the text to the plain-text pass. **Default (as built, W13):** one trailing `…` is set aside before
    the scan and restored; a word that is the start of `true`, `false` or `null` and runs to the end is the word the cut
    interrupted.
36. **[Amended: Amendment 2, chain R fix rounds] Environment values that are switches.** The spec registers every
    variable whose name says "secret". **Default (as built, W12):** a value that is empty, one of `true`, `false`,
    `null`, `none`, `yes`, `no`, `on`, `off`, `default`, `enabled`, `disabled` or `auto` (ASCII case-insensitive), or
    only digits and under 8 bytes is not registered (`is_benign_env_value`); a configured token always is.
37. **[Amended: Amendment 2, chain R fix rounds] Writer behaviours the spec leaves open, as built.** A pending `gap` is
    also written at shutdown; failure warnings carry the error's own text and never an entry field; the explicit-path
    error ends `; fix mcp.audit_log (or AITM_AUDIT_LOG) or set it to off`; `start` logs its one `info!` only when all
    three streams opened and warns once per failed stream.
38. **[Amended: Amendment 2, chain R fix rounds] The tolerant scan hides only the literal that directly follows a secret
    key,** and gives up on junk (plain text through `scrub_strict`, escapes undecoded). A number, a word or a
    container under a secret key is left alone there (spec Residual risks 17).
39. **[Amended: Amendment 2, chain R fix rounds] The tail `shutdown` in `main.rs` has no observable test.** Removing it
    leaves every test green; C1 mutation 43 is expected to survive and is recorded, not worked around.
40. **[Amended: Amendment 2, chain R fix rounds] `MAX_ROUNDS` prose.** The constant is 6; one doc comment on
    `scrub_strict` at `f9c1f5b4` still says "(four)". Fix 5 corrects it; a reviewer who reads "four" there reads a
    stale comment, not the contract. **[Amended: Amendment 3, whole-branch panel: resolved. The constant is 8, and
    no doc comment at `e28a310e` says "four" or "six": they say `MAX_ROUNDS`.]**
41. **[Amended: Amendment 3, whole-branch panel] Glued escapes.** The spec's P2 reads a real CR or LF; a raw request kept
    in a string reaches it with `\n`, `\r` or `\t` (any number of backslashes) glued to the next word. **Default (as
    built, fixes Y and Y2):** a backslash run followed by lowercase `n`, `r` or `t` immediately before a header name or
    key run counts as a line boundary in P2, the frames pre-pass, P6, bracket keys, multipart and CLI flags; the P2
    mask runs to the next real CR or LF or the end of the text, so escaped breaks and the headers after them are
    swallowed. `C:\temp\npw=abc` is masked (accepted over-redaction); `\u000a`, `\x0a` and `%0a` are not read
    (residual). Fix Y3 (`e28a310e`) extends it to P5's left boundary.
42. **[Amended: Amendment 3, whole-branch panel] Session export caveat.** `session.save`, `session.load`, `flow.export` and
    `flow.import` with `session_io.allow_agent_file_io: true` and no `session_io.root` take unconfined paths, so an agent
    can overwrite or truncate the audit files. **Default:** an operator authorization decision, not a code change;
    the README says so (spec Residual risks 26) and no test or command is added.
43. **[Amended: Amendment 3, whole-branch panel] The cap marker, the env literals, the glued escape and the session
    caveat are the four facts the spec was silent on.** Ambiguities 35 and 36 (cap marker, env literals) stand; 41 and
    42 add the other two; the spec records all four (Design 14.4, 14.5, 14.3, Residual risks 26).
44. **[Amended: Amendment 3, whole-branch panel] The writer's fragment mask makes room.** Design 14.5 step 5 said "cap,
    then the mask again", which can leave a field up to four bytes past its cap (a 10-byte mask over a fragment of 6).
    **Default (as built, `b1dfa3eb`):** the text before the fragment is cut a character at a time, never the mask and
    never inside a JSON escape, until the field is as its cap leaves it; a second pass is the identity.
45. **[Amended: Amendment 3, whole-branch panel] Registry forms.** The spec said "raw, JSON-escaped, percent-encoded".
    **Default (as built):** JSON depths 1 to 3 and the percent forms of the raw secret and of its JSON forms at
    depth 1 and 2, tier judged on the raw byte length; depth 4 and double percent encoding are residuals.
46. **[Amended: Amendment 3, whole-branch panel] The corpus mutation expectation.** W14's "skip the `scrub_strict` calls in
    `render_line`: rows R1 to R39 go red" is wrong: a real server call is clean at the source, so the writer's own
    passes are a no-op on those rows and only the hand-built row R25 reaches them. **Default:** C1 states that
    expectation (row 13 and the corpus note); the writer's passes are proved by the unit and writer tests.
47. **[Amended: Amendment 3, whole-branch panel] AC37's clock.** The criterion says 5 s; the test uses
    `FAILED_BOOT_TIMEOUT` = 10 s so a loaded machine does not fail it. The design's promise is unchanged.
48. **[Amended: Amendment 3, whole-branch panel] D1 had four comment-only hunks, not three.** The `record_audit` doc
    sentence about the lane became false and was corrected; the whole branch has seven `server.rs` hunks against
    the merge-base (three executable, four comment). C1's fence counts (6 and 24) are unchanged.
49. **[Amended: Amendment 3, whole-branch panel] `origin/main` is merged twice.** Once at `b3a2a8df`, and again before
    the PR; the second is not in the branch at `e28a310e` (merge-base still `f2c9d70b`; the local `origin/main` ref is
    `1782353a`). **Default:** re-measure every fence and count after it; the expected values are unchanged if the merge
    touches none of the lines a fence reads.

### Gate, commit and dispatch protocol

- **Per task.** The Coder works in its chain's worktree, reports the changed files and the quoted runs, and
  does not run `git` writes (the sandbox cannot create `.git` state: this plan overrides step 5 of
  `coder.md`, as the PR 171 plan did). The orchestrator commits after the task's Tester passes, **one commit
  per task**, in the Terminal panel (or with local sandbox `git add` / `git commit`, which work; push is
  Terminal only). Chain R commits go on `claude/durable-audit-redact`; chain W commits on the plan branch.
  Message: `feat(audit): task <id> - <title> (plan 2026-10-31-durable-audit)`, body wrapped, no word that
  begins with a hash sign (the terminal hook refuses it; write "PR 171"), ending with the trailer
  `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (the trailer of the model that is running).
  Keep each git line short and simple (the Terminal panel has mangled long compound lines); commit early.
- **Push.** Never a bare `git push`. Always `git push origin claude/durable-audit-462ca8`. The R branch is
  not pushed.
- **Full gate** (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`, redirected
  to a log and gated on exit status), by the orchestrator or Tester at these boundaries: in the R worktree
  after R4; in the plan worktree after W1, after W4, after M1 plus W11, after W15, after W18 (and after the
  rebase), and after C1. In between, scoped `-p` commands.
- **Panel cadence.** A Tester after every task. The three-reviewer panel (security reviewer first on anything
  touching redaction) after R4, after W15, after W18 (with D1, D2, H1), and on the whole branch.
- **Dispatch contract (WORKFLOW, with this change's paths).**

| Engine | Inputs |
|---|---|
| Coder, task | spec `docs/superpowers/specs/2026-10-31-durable-audit-design.md`, plan `docs/superpowers/plans/2026-10-31-durable-audit-plan.md`, task id (`R1`..`R4`, `W1`..`W18`, `D1`, `D2`, `H1`, `C1`), worktree: **the redact worktree for R tasks, `/Users/matt/Security/aitmproxy/.claude/worktrees/durable-audit-462ca8` for every other task** |
| Coder, fix task | the findings report instead of a task id, plus spec, plan, worktree |
| Tester | spec, plan, worktree, base and head SHA, task id(s) or "whole branch" |
| Each reviewer | spec, plan, worktree, base and head SHA, task id(s), the Coder's report, any prior review report for the range |

### Risks and rebase

- Sibling sessions edit `crates/aitm-mcp` (`server.rs`, `transport.rs`) and the `/bus` bridge
  (`crates/aitm/src/web/bridge.rs`). This change touches `server.rs` in three comment hunks (D1) **[Amended: Amendment 3, whole-branch panel: four]** and
  exactly three executable hunks (R3), and adds `redact_args.rs`; it does not touch `transport.rs`,
  `http.rs` or `bridge.rs`, and adds no field to `ConnCtx`, `AuditEntry` or `wire::Governance`. If a
  sibling edits `redact_value` in place meanwhile, that is a manual merge into `redact_args.rs`; the
  orchestrator checks for it at each rebase. A sibling's new `ConnCtx` field would not break this plan's
  tests (they never write a `ConnCtx` literal).
- Contested files that do change: `aitm-core/src/{audit,config,lib}.rs` (W1, R1: one-line merges in
  `lib.rs`), `aitm/src/{config_file,env,main,lib}.rs` (W2, W3, W18), `aitm-plugins/src/agent.rs` (W17),
  `tests/e2e/aitm_e2e/core.py` `_spawn` (H1: keep it to the one statement, the e2e sessions own the file) and
  `tests/e2e/audit/test_audit_log.py` (R3: one assertion). Everything else is new files.
- **[Amended: Amendment 2, chain R fix rounds: the orchestrator merged `origin/main` once (`b3a2a8df`, between W13 and
  W18) instead of rebasing, and merges again before the whole-branch panel if `main` has moved; read "rebase" in the
  rest of this bullet as "merge"; the semantic-merge trap below is unchanged.]**
- **The orchestrator rebases on `origin/main`** once after M1 (before W18, the first edit to `main.rs`) and
  again before the whole-branch panel, never on the R branch. After each rebase re-run the scoped tests of
  every task whose files conflicted, then the full gate. Run `git fetch origin` and `git rebase origin/main`
  in the Terminal panel; the rebased branch is pushed with `git push --force-with-lease origin
  claude/durable-audit-462ca8` only on the orchestrator's call (never bare).
- **Semantic-merge trap.** CI tests the branch merged with current `main`: a sibling's new struct literal
  missing a field this change adds (`McpConfig.audit_log`) fails only on CI. W1 adds that field; the only
  literal outside `config.rs` ends in `..McpConfig::default()` and is safe; after each rebase grep
  `McpConfig {` again.
- **Over-redaction.** Rule D hides every non-benign header value from the ring, the push, `agent.activity`
  and the file (spec Design 14.2, Residual risks 18); the capture store keeps the real request; the veto
  path is rule S alone (spec Open question 5). Over-scrub is guarded by AC44's benign table and AC56; a pass
  that changes a benign row is wrong.
- **Call-path cost.** The source runs the strict passes inside `record_audit`; R4 bounds the work (4 KiB per
  leaf, 64 KiB in all) and AC46 pins it. W12 and W13 run only on the writer threads. **[Amended: Amendment 2, chain
  R fix rounds: the bound is pools of 64 KiB (leaves and names, header-collection keys, other keys), a leaf cut at
  4096 bytes, names and keys at 256, depth 64, 2 to 4 walks, up to 5 bounded passes per leaf of up to 6 rounds each,
  and the reason cut to 8192 bytes before its pass; measured worst adversarial case 27 ms in a release build (the
  coders' report, not an assertion).]**
- **Two worktrees, two `target/` directories.** Each carries a full Rust build; the R worktree is removed at
  M1. Never share `CARGO_TARGET_DIR` across them; `touch` edited sources before a red or green run so cargo
  does not reuse a stale artifact.
- **Hermeticity.** `cargo test` never builds the writer (only `main.rs` does; `assemble()` does not), so no
  Rust test appends to the operator's real file. The only Rust tests that spawn the real binary are
  `shutdown.rs` (H1) and `audit_log_binary.rs` (W18, which sets `mcp.audit_log` and clears the environment).
- **Timing assertions** in AC18 (2 s), AC19 (2 s), AC30 (1.5 s), AC37 (5 s), AC46 (5 s) and the hostile-input
  guards (20 s) are wall-clock bounds on work that takes milliseconds; they are generous on purpose. A Coder
  who sees one flake reports it rather than raising the bound. **[Amended: Amendment 2, chain R fix rounds: AC46's
  clock is 20 s, the reason-work test's is 60 s and the hostile-input guards are 60 s (`HOSTILE_SECS`); they were
  raised from the first text's 5 s (AC46) and 20 s (hostile guards), because the clock only has to tell bounded
  work from unbounded work.]** **[Amended: Amendment 3, whole-branch panel: AC37's test clock is
  `FAILED_BOOT_TIMEOUT` = 10 s (the criterion says 5 s), and the writer tests no longer assert on a wall-clock bound
  they do not need.]**
- **Registered secrets live in process memory** (the registry), as the secrets already do; nothing prints
  them (AC51).
- **[Amended: Amendment 3, whole-branch panel] Risks the panel added.** (a) *Fail closed costs evidence, not
  safety:* an attacker-built string can be forced to `[redacted]` and a value no walk round confirms to
  `"<redacted>"`; honest input never reaches either (spec Residual risks 31). (b) *A wedged rotation drops lines
  past twice the cap* (counted, marked in the `gap`); the bound while it works is 92 MiB (Residual risks 25). (c) *The
  glued-escape rule over-redacts a Windows path* such as `C:\temp\npw=abc` (Residual risks 30). (d) *The session
  export caveat:* with `session_io.allow_agent_file_io: true` and no `session_io.root` an agent can overwrite the audit
  files (Residual risks 26; the operator's authorization decision). (e) *The tail flush is unobserved:* mutation 43
  survives by design. (f) *The glued-escape rule reads only `\n`, `\r` and `\t`:* `\u000a`, `\x0a` and `%0a` are
  residuals, and fix Y3 (`e28a310e`) extended it to P5's left boundary.

## Tasks

**Chain R: strict redaction (Tasks R1 to R4), in the redact worktree.** Spec Design 14.1 to 14.3, 14.6,
AC44 to AC47, AC59, AC60, AC62, AC63. The four tasks run strictly in order; none touches any file of
chain W except the two named merge points. Conventions for chain R: every pass is **linear**,
**idempotent** and replaces with the literal `[redacted]`; every pass runs on **plain decoded text**,
never on JSON text (Design 14.0); `redact.rs`, `is_secret_key` and `scrub_text` are **not edited**
(they are called); `aitm-core` has no `serde_json` dependency, so its tests compare plain strings; no
new dependency anywhere (`regex` is already an `aitm-core` dependency). A pass that changes a benign
row of AC44 is the pass's bug, not the table's.

### Task R1: strict vocabulary, benign headers, passes P2 and P3

- **Chain / worktree:** R, the redact worktree.
- **Satisfies:** AC44 (the P2, P3 and benign rows; R2 completes the table)
- **Depends on:** none
- **Files:** `crates/aitm-core/src/redact_strict.rs` (create), `crates/aitm-core/src/lib.rs` (modify:
  add the one line `pub mod redact_strict;` after `pub mod redact;`, nothing else; this is merge point
  M1's only expected conflict), `crates/aitm-core/tests/redact_strict.rs` (create)
- **Change.** A module doc: audit-only strict passes that sit beside the untouched `scrub_text`; plain
  text only; linear; idempotent. Public API (everything else private):
  - `pub fn is_secret_key_strict(key: &str) -> bool`: `crate::redact::is_secret_key(key)`, or, on the
    ASCII-lowercased key, it contains one of the needles `passphrase`, `private_key`, `private-key`,
    `privatekey`, `access_key`, `access-key`, `accesskey`, `signing_key`, `signing-key`, or any
    segment (split on every character that is not an ASCII alphanumeric) equals one of `pass`, `pw`,
    `otp`, `totp`. Whole segments, so `bypass`, `passed`, `compass`, `power` are not hit.
  - `pub fn is_benign_header(name: &str) -> bool`: ASCII-case-insensitive exact match against the 43
    names of spec Design 14.2 (`accept`, `accept-charset`, `accept-encoding`, `accept-language`,
    `accept-ranges`, `access-control-request-headers`, `access-control-request-method`,
    `cache-control`, `connection`, `content-disposition`, `content-encoding`, `content-language`,
    `content-length`, `content-type`, `date`, `dnt`, `expect`, `forwarded`, `host`,
    `if-modified-since`, `if-unmodified-since`, `origin`, `pragma`, `range`, `referer`,
    `sec-websocket-extensions`, `sec-websocket-protocol`, `sec-websocket-version`, `te`,
    `transfer-encoding`, `upgrade`, `upgrade-insecure-requests`, `user-agent`, `via`,
    `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-port`, `x-forwarded-proto`,
    `x-http-method-override`, `x-original-url`, `x-real-ip`, `x-requested-with`, `x-rewrite-url`) or a
    name that starts with `sec-fetch-` or `sec-ch-`. Callers (R3) combine it with
    `is_secret_key_strict`; this function alone says only "on the list". **[Amended: Amendment 2, chain R fix rounds: the list is
    **42** names, not 43. `sec-websocket-protocol` was removed in fix round 3 (`R fix 3A`) because its
    subprotocol list carries bearer tokens (`base64url.bearer.authorization.k8s.io.<token>`); the
    prefixes `sec-fetch-` and `sec-ch-` are unchanged. The test is `is_benign_header_table`, which says
    so.]**
  - `pub fn scrub_strict(text: &str) -> String`: `crate::redact::scrub_text(text)` first, then, in
    this task, **P2** and **P3**; R2 appends P4, P5, P6 after them in that order.
  - **P2 header lines.** The name `authorization`, `proxy-authorization`, `cookie`, `cookie2` or
    `set-cookie` (ASCII case-insensitive; preceded by the start of the text or a character that is not
    an ASCII alphanumeric, `_`, `.` or `-`) followed by optional blanks and `:` masks the **rest of the
    line** (to a real CR or LF, or the end of the text) with `[redacted]`, keeping the name and the
    colon and one blank (`Cookie: [redacted]`). At the **start of a line**, any name that
    `is_secret_key_strict` does the same, except that a `host:port` (an unquoted run containing a `.`
    followed by `:` and 1 to 5 ASCII digits and then `/`, `?`, `#`, a blank or the end) is a host, not a
    header (`auth.example.com:8443` is untouched). Prose without a `:` ("the Cookie header is
    described in RFC 6265") is untouched.
  - **P3 Basic credentials.** `basic` (any case) followed by blanks and a token of at least 8 characters
    from the base64 alphabet (`A-Za-z0-9+/` and `=`, also `-_`) is masked **only when** the token
    decodes (leniently, padding not required) to bytes that contain `:`; `basic information` has no
    such token. `negotiate` or `ntlm` followed by blanks and a token of 16 or more base64 characters
    masks the token.
  The builder may write the passes as regexes or as hand scans; the contract is linear time, idempotence
  (`scrub_strict(scrub_strict(x)) == scrub_strict(x)`) and AC44's literals.
- **Tests (written first)**, in `crates/aitm-core/tests/redact_strict.rs` (public API; failures are
  collected into one assertion message, so one run shows every wrong row):
  - `scrub_strict_masks_every_pass_and_keeps_the_benign` (AC44; the whole table lives in this one
    function and R2 appends its rows). **This task's rows:** P2: `"GET / HTTP/1.1\r\nCookie: a=b;
    c=SECRET44\r\nHost: x"` gives `"GET / HTTP/1.1\r\nCookie: [redacted]\r\nHost: x"`; `"Set-Cookie:
    JSESSIONID=\"S\"; Path=/"` gives `"Set-Cookie: [redacted]"`; `"x Authorization: Digest
    username=\"u\", response=\"R\"\nnext"` gives `"x Authorization: [redacted]\nnext"`; `"X-Api-Key: a b
    c\nok"` gives `"X-Api-Key: [redacted]\nok"`; `"Proxy-Authorization: Basic Zm9v"` gives
    `"Proxy-Authorization: [redacted]"`. P3: `"use Basic dXNlcjpwYXNz now"` gives `"use Basic
    [redacted] now"`; `"negotiate "` followed by 20 `A` gives `"negotiate [redacted]"`. **Unchanged
    byte for byte (these two passes must not touch them):** `"0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c"`;
    `"0123456789abcdef"` repeated 4 times; `"auth.example.com:8443"`; `"basic information"`; `"the Cookie
    header is described in RFC 6265"`; `"Accept: text/html"`; `"X-Forwarded-For: 203.0.113.9"`;
    `"author=bob&authority=example.com&inside=1&bypass=1&passed=true"`; `"{\"a\":1,\"b\":[true,null],\"c\":\"d\"}"`;
    `"{{target}}/login?user={{user}}"`. Every row also asserts `scrub_strict(scrub_strict(x)) ==
    scrub_strict(x)`. Hostile inputs, run on a thread that is given 20 s (a timeout fails the test, it
    does not hang the run): 4 MiB each of `Basic ` and of `Cookie: ` return without panicking. **[Amended: Amendment 2, chain R fix rounds:
    the guard is 60 s, the test's `HOSTILE_SECS` (the passes now run up to six rounds and two
    pre-passes over a 4 MiB text); a timeout still fails the test rather than hanging the run.]**
  - `is_secret_key_strict_vocabulary` (extra): true for `passphrase`, `private_key`, `Private-Key`,
    `access_key`, `signing-key`, `pass`, `PW`, `otp`, `totp`, `x_pass`, `user.pw`, and for everything
    `is_secret_key` says (`token`, `sid`, `Cookie`, `Authorization`); false for `author`, `authority`,
    `inside`, `bypass`, `passed`, `sessions`, `compass`, `power`, `path`, `host`.
  - `is_benign_header_table` (extra): true for `Accept`, `CONTENT-TYPE`, `X-Forwarded-Host`,
    `Sec-Fetch-Mode`, `sec-ch-ua`, `Referer`, `Host`; false for `Authorization`, `Cookie`, `X-Custom`,
    `X-Api-Key`, `Set-Cookie`, `X-Debug-Access`, `sec-fetchx`, `Sec-Fetch`.
- **Red.** `cargo test -p aitm-core --test redact_strict` first fails to compile (`unresolved import
  aitm_core::redact_strict`). With stubs (`scrub_strict` returning `scrub_text(text)`,
  `is_secret_key_strict` calling `is_secret_key`, `is_benign_header` returning `false`) it fails on
  assertions: the collected message names the first P2 row (`got "GET / HTTP/1.1\r\nCookie: a=b;
  c=SECRET44\r\nHost: x"`), the vocabulary test fails with `passphrase`, the benign test with
  `Accept`. Quote both outputs.
- **Green.** `cargo test -p aitm-core --test redact_strict` prints `test result: ok. 3 passed`;
  `cargo test -p aitm-core` prints `test result: ok` for every suite (`trust_gate_scan` and
  `classifier_wildcard_free` included, unedited); `cargo check --workspace --all-targets`;
  `git diff --stat` (orchestrator) shows `redact.rs` untouched; `cargo fmt --check` and `cargo clippy
  -p aitm-core --all-targets -- -D warnings` clean.
- **Do not touch:** `redact.rs`, any other crate, any existing test.
- **Done when:** both reds and the green runs are quoted.

### Task R2: passes P4, P5, P6 and the audit-only vocabulary

- **Chain / worktree:** R, the redact worktree.
- **Satisfies:** AC44 (completes the table), AC63
- **Depends on:** Task R1 (same files)
- **Files:** `crates/aitm-core/src/redact_strict.rs` (modify), `crates/aitm-core/tests/redact_strict.rs`
  (modify)
- **Change.** `scrub_strict` runs P4, P5, P6 after P2 and P3, in that order.
  - **P4 URL userinfo.** In `scheme://userinfo@host`, with `userinfo` the text up to the first `@` and
    containing no `/`, `?`, `#`, blank or quote: with a `:` the part after the first `:` becomes
    `[redacted]` and the user name stays (`https://user:[redacted]@host`); with no `:` the userinfo is
    masked only when it is 20 or more characters or matches a P5 shape (`https://ghp_...@github.com/`
    becomes `https://[redacted]@github.com/`; `ssh://git@github.com/o/r` is untouched).
  - **P5 credential shapes.** Distinctive prefix, fixed alphabet, minimum length, ASCII word boundary on
    both sides: a JWT (`eyJ` + base64url, two dots, each of the first two segments at least 8
    characters); a PEM block from `-----BEGIN ` through `PRIVATE KEY-----` to the matching `-----END
    ... PRIVATE KEY-----` or the end of the text; an AWS access key id (`AKIA`, `ASIA`, `AGPA`, `AIDA`,
    `AROA`, `ANPA` or `ANVA` + 16 of `[A-Z0-9]`); a GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` +
    at least 36 of `[A-Za-z0-9]`; `github_pat_` + at least 22 of `[A-Za-z0-9_]`); a GitLab token
    (`glpat-` + at least 20 of `[A-Za-z0-9_-]`); a Slack token (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`,
    `xoxs-` + at least 10 of `[A-Za-z0-9-]`); a Stripe key (`sk_live_`, `sk_test_`, `rk_live_`,
    `rk_test_` + at least 16 of `[A-Za-z0-9]`); an `sk-` API key (`sk-` + at least 32 of
    `[A-Za-z0-9_-]`); a Google API key (`AIza` + 35 of `[0-9A-Za-z_-]`).
  - **P6 extra key vocabulary.** A `key=value`, `key: value` or `"key":"value"` pair whose key
    `is_secret_key_strict` **only because of the extras** is masked with the value rule `scrub_text`
    documents (a quoted value to its closing quote; an unquoted one to a blank, `&`, `;`, `,`, quote or
    `}`). The `host:port` exemption of P2 applies. The extras are **not** added to `is_secret_key`.
- **Tests (written first)**, same file:
  - `scrub_strict_masks_every_pass_and_keeps_the_benign` gains **this task's rows.** P4:
    `"https://user:hunter2@host.test/p"` gives `"https://user:[redacted]@host.test/p"`; `"https://ghp_"`
    + 36 `a` + `"@github.com/"` gives `"https://[redacted]@github.com/"`. P5 (each gives
    `"[redacted]"`): the JWT `"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"`; `AKIA` + 16 `A`;
    `ghp_` + 36 `a`; `github_pat_` + 22 `a`; `glpat-` + 20 `a`; `xoxb-` + 12 `1`; `sk_live_` + 16 `a`;
    `sk-` + 32 `a`; `AIza` + 35 `a`; the PEM block `"-----BEGIN RSA PRIVATE
    KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"`; and `"x\n-----BEGIN PRIVATE KEY-----\nMII"` gives
    `"x\n[redacted]"`. P6: `"passphrase=hunter2&x=1"` gives `"passphrase=[redacted]&x=1"`;
    `"x=1&private_key=K&y=2"` gives `"x=1&private_key=[redacted]&y=2"`; `"{\"pass\":\"p\",\"user\":\"u\"}"`
    gives `"{\"pass\":\"[redacted]\",\"user\":\"u\"}"`; `"x otp: 123456 done"` gives `"x otp: [redacted] done"` (mid-line: at the start of a line P2 masks the whole line, so `"otp: 123456 done"` gives `"otp: [redacted]"`; orchestrator amendment 3 after R2).
    **Unchanged:** `"https://example.test/a/b?x=1&y=two#frag"`; `"ssh://git@github.com/o/r"`;
    `"git@github.com:o/r.git"`; `"sk-prod-eu-1.example.test"`; `"AKIA"`; `"AKIAFOO"`; `"ghp_short"`;
    `"eyJ"`. Hostile inputs (under the same 20 s thread guard): 4 MiB each of `eyJ`, of an unterminated
    `-----BEGIN PRIVATE KEY-----`, and of `https://a:` return without panicking.
  - `the_strict_vocabulary_is_audit_only` (AC63): `redact::is_secret_key("passphrase")` is false and
    `redact_strict::is_secret_key_strict("passphrase")` is true; `redact::scrub_text("pass=x")` is
    `"pass=x"` and `scrub_strict("pass=x")` is `"pass=[redacted]"`; `is_secret_key_strict` is false for
    `author`, `authority`, `inside`, `bypass`, `passed` and `sessions`.
- **Red.** Compiles against R1; fails on assertions: the AC44 test names the first P4 row (`got
  "https://user:hunter2@host.test/p"`) and every P5 and P6 row; `the_strict_vocabulary_is_audit_only`
  fails at `scrub_strict("pass=x")` (got `"pass=x"`, expected `"pass=[redacted]"`; the `is_secret_key`
  rows are green on arrival, state that).
- **Green.** `cargo test -p aitm-core --test redact_strict` prints `test result: ok. 4 passed`; `cargo
  test -p aitm-core`; fmt; `cargo clippy -p aitm-core --all-targets -- -D warnings`.
- **Do not touch:** `redact.rs`, `lib.rs`, any other crate.
- **[Amended: Amendment 2, chain R fix rounds] As built after R2** (the rest is under "Chain R fix
  rounds" after R4). The AC44 `otp` row is the mid-line form (`"x otp: 123456 done"` gives `"x otp:
  [redacted] done"`; at the start of a line P2 masks the whole line, `"otp: 123456 done"` gives
  `"otp: [redacted]"`); the test's own comment is reworded to say so, a code-side edit that is not part
  of this document. The PEM block is **no longer a P5 shape**: it is a pre-pass that runs before
  everything, with no word boundary (fix round 1). P4's userinfo runs to the **last** `@` of the
  authority (fix round 1). P5's left boundary is any byte that is not an ASCII alphanumeric, and a JWT's
  third segment may be empty (rounds 1 and 4).
- **Done when:** the red and green runs are quoted.

### Task R3: `redact_args.rs` rules S and D, the `server.rs` hunk, the e2e flip

- **Chain / worktree:** R, the redact worktree.
- **Satisfies:** AC45, AC47 (the source half), AC59, AC60, AC62 (guard)
- **Depends on:** Task R2
- **Files:** `crates/aitm-mcp/src/redact_args.rs` (create), `crates/aitm-mcp/src/lib.rs` (modify: the one
  line `pub mod redact_args;`), `crates/aitm-mcp/src/server.rs` (modify: exactly the three executable
  hunks below), `crates/aitm-mcp/tests/audit_redaction.rs` (create), `tests/e2e/audit/test_audit_log.py`
  (modify: the one assertion)
- **Change.**
  - `redact_args.rs` (module doc: rules S and D, the leaf text pass, why it is `pub`: the writer reuses
    it). `pub fn redact_value(value: &serde_json::Value) -> serde_json::Value`, moved from `server.rs`
    and extended. Private: `const KEY_REDACTED: &str = "<redacted>"`, the header-collection key list
    (`headers`, `header`, `request_headers`, `response_headers`, `req_headers`, `resp_headers`,
    `http_headers`; case-insensitive), the sibling name keys (`name`, `key`, `header`, `field`,
    `selector`, `label`), the sibling value keys (`value`, `val`, `text`, `data`, `content`, `input`,
    `keys`, `string`), `fn is_secret_key_audit(key: &str) -> bool` (`is_secret_key_strict(key)` or the
    ASCII-lowercased key contains `_confirm`; the `_confirm` clause moves here from the deleted local
    `is_secret_key`). Behaviour:
    - an object member whose key `is_secret_key_audit` has its value replaced by `"<redacted>"`
      (unchanged from today, now with the strict vocabulary);
    - **rule S**: an array of exactly two strings whose first element `is_secret_key_strict` has its
      second element replaced by `"<redacted>"`; an object with a string member among the sibling name
      keys whose value `is_secret_key_strict` has its members among the sibling value keys replaced by
      `"<redacted>"` (any JSON type); names and every other member stay;
    - **rule D** **[Amended: Amendment 2, chain R fix rounds: the header-collection key is any key
      whose lower-cased name *contains* `header` or `hdr`, or equals `trailer` or `trailers`, not the
      seven names below, and the shapes are those of spec Design 14.2 "as built"; the text that
      follows is the first cut]**: inside a header collection (an object under a header-collection key at any depth, or
      an array under such a key whose elements are two-string arrays or objects with a `name`, `key` or
      `header` member and a `value` member), a header's value is kept only if its name
      `is_benign_header` and not `is_secret_key_strict`, otherwise replaced by `"<redacted>"` whatever
      its JSON type; names stay; a kept string value still passes `scrub_strict`;
    - every other string leaf passes `aitm_core::redact_strict::scrub_strict`; numbers, booleans, nulls
      and names are untouched.
  - `server.rs`, **exactly these three hunks** (the AC40 fence): (a) the one reason line in
    `record_audit`, `AuditResult::Error(cap_reason(aitm_core::redact::scrub_text(reason)))` becomes
    `AuditResult::Error(cap_reason(aitm_core::redact_strict::scrub_strict(reason)))` **[Amended:
    Amendment 2, chain R fix rounds: as built it is `AuditResult::Error(cap_reason(aitm_core::
    redact_strict::scrub_strict_bounded(reason, crate::redact_args::REASON_EXAMINE_BYTES)))`,
    which rustfmt wraps to four lines (fix 4B); still one hunk. `REASON_EXAMINE_BYTES` is 8192 and
    `pub(crate)` in `redact_args.rs`, and `bound_text` stays private there, so `redact_args.rs` is
    not a fourth `server.rs` hunk]**; (b) delete the
    bodies of `redact_value` and the local `is_secret_key` (and their doc comments); (c) add `use
    crate::redact_args::redact_value;` with the other `use` lines. `redact_args(arguments)` and
    `cap_text` keep calling `redact_value` and are not otherwise edited (do not remove the clone in
    `redact_args`: that would be a fourth hunk).
  - `tests/e2e/audit/test_audit_log.py`: the expectation at about line 349 (`hdrs.get("X-Audit-Marker")
    == marker`, "survives verbatim") becomes `hdrs.get("X-Audit-Marker") == KEY_REDACTED` plus
    `"X-Audit-Marker" in hdrs` ("the name is still present"); the `Content-Type` assertion beside it
    is unchanged. Nothing else in the file. The Coder also greps `tests/e2e` for any other assertion
    that a header **value** survives in an audit `args` and reports it (none is expected).
- **Tests (written first)**, in `audit_redaction.rs` (copy the helpers of `audit_integrity.rs`:
  `StubClient`, an `audit_server(ring)` over a `Registry` with `AgentPlugin` and a stub command
  `demo.accept` (`Write`, optional `Any`-typed params `headers`, `pairs`, `entries`, `request`, `edits`,
  `selector`, `text`, `vars`, `note`, `raw`, `body`) and `demo.fail` (`Write`, `invoke` fails quoting
  `note`), an agent `ConnCtx::new(Frontend::Mcp)` per call, and an operator `ConnCtx` with a
  `NotificationSink` as `audit_redacts_secrets` in `mcp.rs` does, to read the pushed line and
  `agent.activity`):
  - `rules_s_and_d_redact_header_collections_and_siblings` (AC45): for every input below the ring
    entry's `args_summary` parses to exactly the output, and the pushed line and `agent.activity`'s
    entry carry the byte-identical string. `{"headers":{"Accept":"text/html","Authorization":"Bearer
    B","Content-Type":"application/json","X-Custom":"C"}}` gives `{"headers":{"Accept":"text/html",
    "Authorization":"<redacted>","Content-Type":"application/json","X-Custom":"<redacted>"}}`.
    `{"headers":[["Cookie","foo=C"],["Accept","text/html"],["X-Zed","z"]]}` gives `{"headers":[["Cookie",
    "<redacted>"],["Accept","text/html"],["X-Zed","<redacted>"]]}`. `{"headers":[{"name":"Cookie",
    "value":"C"},{"name":"Accept","value":"text/html"}]}` gives `{"headers":[{"name":"Cookie","value":
    "<redacted>"},{"name":"Accept","value":"text/html"}]}`. `{"pairs":[{"name":"Authorization","value":
    "C"}],"entries":[["Set-Cookie","C=1"]]}` gives both values `<redacted>` (rule S, no header key).
    `{"a":{"b":{"request_headers":{"X-Zed":"C","Host":"h.test"}}}}` gives `X-Zed` redacted and `Host`
    kept. `{"edits":{"headers":{"X-Forwarded-Host":"evil.test","X-Debug":"C"}}}` gives `X-Forwarded-Host`
    kept and `X-Debug` redacted. `{"headers":{"Referer":"https://x.test/cb?token=C"}}` gives
    `{"headers":{"Referer":"https://x.test/cb?token=[redacted]"}}`. `{"headers":{"X-N":5}}` gives
    `{"headers":{"X-N":"<redacted>"}}`. `{"selector":"#password","text":"C"}` and
    `{"selector":"input[name=api_token]","text":"C"}` give `text` `<redacted>`;
    `{"selector":"#q","text":"hello"}` is unchanged. `{"vars":{"admin_pass":"C","pw":"C",
    "target":"http://t.test","user":"admin"}}` gives the first two `<redacted>` and the last two
    unchanged.
  - `redaction_is_idempotent_and_json_safe` (AC47, source half): over a local list of argument values
    (every input of the AC45 test plus the two below plus `{"u":"x?next=a%2Bb"}`),
    `redact_value(&redact_value(&v)) == redact_value(&v)`; `demo.accept {"note":"Authorization: Bearer
    SECRET47"}` gives ring `args_summary` exactly `{"note":"Authorization: [redacted]"}` and it parses
    as JSON; `{"raw":"GET /\r\nCookie: a=b; z=SECRET47\r\nHost: x"}` gives `{"raw":"GET /\r\nCookie:
    [redacted]\r\nHost: x"}` with the line breaks as the JSON escapes. (These two are green on arrival
    at the source: the defect AC47 guards is a writer that re-scrubs the JSON text, tested in W13.)
  - `the_reason_is_scrubbed_strictly_at_the_source` (AC60): `demo.fail` with `note` `"bad header Cookie:
    a=b; z=SECRET60 at line 3"` gives a ring `Error(r)` equal to `"bad header Cookie: [redacted]"`, and a
    pushed line and an `agent.activity` entry with the same result, none containing `SECRET60`.
- **Red.** `cargo test -p aitm-mcp --test audit_redaction` fails on assertions against the old
  `server.rs` (it compiles: only the public server API is used): the first AC45 row (the `X-Custom`
  value `C` is still there), `the_reason_is_scrubbed_strictly_at_the_source` (got `Error("bad header
  Cookie: [redacted]; z=SECRET60 at line 3")`: the old pass masks to the first `;`);
  `redaction_is_idempotent_and_json_safe` passes (green on arrival). Quote them. The e2e flip is
  checked by `python3 -I -m py_compile tests/e2e/audit/test_audit_log.py`; the orchestrator runs
  `python3 tests/e2e/run.py audit` (Terminal panel, a built `aitm`) and pastes the output.
- **Green.** `cargo test -p aitm-mcp --test audit_redaction` prints `test result: ok. 3 passed`.
  **AC62 blast radius (all `test result: ok`, 0 failed; socket tests the orchestrator runs):** `cargo
  test -p aitm-mcp --test audit_integrity`, `cargo test -p aitm-mcp --test mcp audit_redacts`, `cargo
  test -p aitm-mcp --test mcp agent_activity`, `cargo test -p aitm-mcp --lib`, `cargo test -p aitm-core`,
  `cargo test -p aitm-plugins`, `cargo test -p aitm --test tui_mode_governance --test
  audit_durable_connection_id`, `cargo check --workspace --all-targets`. `grep -c "fn redact_value"
  crates/aitm-mcp/src/server.rs` prints `0`; the AC40 fence command (see C1) prints only the three
  hunks; fmt; `cargo clippy -p aitm-mcp --all-targets -- -D warnings` (a left-over `is_secret_key`
  would be dead code here).
- **Do not touch:** `redact.rs`, `transport.rs`, `http.rs`, `crates/aitm/src/web/`, any executable line
  of `server.rs` beyond the three hunks, any other e2e line, any existing Rust test.
- **Done when:** the red, the green, the blast-radius runs and the e2e Terminal output are quoted.

### Task R4: bounded traversal

- **Chain / worktree:** R, the redact worktree.
- **Satisfies:** AC46
- **Depends on:** Task R3 (same files)
- **Files:** `crates/aitm-mcp/src/redact_args.rs` (modify), `crates/aitm-mcp/tests/audit_redaction.rs`
  (modify)
- **Change.** Design 14.6, inside `redact_value` (no signature change). Private constants
  `LEAF_EXAMINE_BYTES: usize = 4096` and `TOTAL_EXAMINE_BYTES: usize = 64 * 1024`; a private traversal
  state counting the bytes of string text examined. A string leaf is examined only up to
  `min(LEAF_EXAMINE_BYTES, bytes left in the total budget)` (cut on a char boundary); a leaf longer than
  what is examined is output as the scrubbed prefix plus the single character `…`; once the total budget
  is spent every later string leaf is replaced by `…`. Numbers, booleans, nulls and names cost nothing; a
  value replaced by `"<redacted>"` is not examined and costs nothing. The traversal follows the
  object's own iteration order. A value cut by the bound is masked as an unquoted value (over-redaction,
  never a leak).
- **Tests (written first)**:
  - In-module `a_leaf_beyond_4096_bytes_is_cut_with_an_ellipsis`: `redact_value({"a": "x" * 5000})` is
    `{"a": "x" * 4096 + "…"}`.
  - In-module `after_64_kib_every_later_leaf_is_an_ellipsis`: an array of 20 leaves of 4096 `a` gives 16
    leaves of 4096 `a` followed by 4 leaves `"…"`.
  - `redaction_output_is_bounded_in_size` (extra, public function): `redact_value` of a 16 MiB string
    leaf returns a string of at most 4097 characters (the deterministic red: it is 16 MiB without the
    bound).
  - `redaction_work_is_bounded` (AC46, through the server): `demo.accept {"body": 16 MiB of "a"}` and
    `demo.accept {"list": [500000 strings "x"]}` each return within 5 s **[Amended: Amendment 2, chain R fix
    rounds: 20 s as built (fix 4B); the clock only separates bounded from unbounded work, the deterministic
    tests carry the bound]** with a ring entry of at most 515
    bytes whose `args_summary` begins `{"body":"aaaa` and `{"list":["x","x"` respectively; a leaf of
    5000 characters with `password=SECRET46` starting at character 4000 gives an entry that does not
    contain `SECRET46`, and with the secret starting at character 4100 the secret is absent from the
    entry (beyond the examined bound and beyond the 512-byte cap).
- **Red.** The two in-module tests and `redaction_output_is_bounded_in_size` fail on assertions (got a
  5000-character leaf; a 16 MiB string). `redaction_work_is_bounded` may pass on arrival if the
  unbounded passes finish inside 5 s: say which, and that the mutation "remove the bound" (C1 mutation
  30) is judged on the three deterministic tests.
- **Green.** `cargo test -p aitm-mcp --test audit_redaction` and `cargo test -p aitm-mcp --lib
  redact_args::` print `test result: ok`; the R3 blast-radius runs still pass; fmt and clippy clean.
- **Do not touch:** `server.rs`, `redact_strict.rs`, any existing test. **[Amended: Amendment 2,
  chain R fix rounds: this holds for R4 itself. The fix rounds below edited `server.rs` (the one reason
  statement, fix 4B) and `redact_strict.rs` (every round) by orchestrator-approved fix tasks dispatched
  from a findings report; a Coder of a numbered task still never touches them.]**
- **Done when:** red and green are quoted. Then the orchestrator runs chain R's panel (security first).
- **[Amended: Amendment 2, chain R fix rounds] The bound as built.** Constants in `redact_args.rs`:
  `LEAF_EXAMINE_BYTES` 4096, `TOTAL_EXAMINE_BYTES` 64 KiB, `NAME_EXAMINE_BYTES` 256, `MAX_DEPTH` 64,
  `SETTLE_ROUNDS` 3, `OUTPUT_ROUNDS` 4, `pub(crate) REASON_EXAMINE_BYTES` 8192; pools, per walk: leaf and name
  text 64 KiB, header-collection keys 64 KiB, other keys 64 KiB (at most 192 KiB). The single "total
  budget" of the R4 text above is the leaf pool; the two key pools are separate. `redact_value` runs 2 to 4 walks. Spec Design 14.6 states them.
  **[Amended: Amendment 3, whole-branch panel: `redact_value` fails closed (fix 6B): a value that no round of
  the walk (the first plus `SETTLE_ROUNDS` = 3 further) confirms is replaced whole by `"<redacted>"`, so the function is
  exactly idempotent; the strict text pass inside each bounded pass fails closed too (fix 6A, `MAX_ROUNDS` = 8).
  The settle test is `settle_stops_at_a_fixed_point_or_fails_closed_after_three_rounds`.]**

### Chain R fix rounds (Amendment 2): what each round added

**[Amended: Amendment 2, chain R fix rounds]** Each round followed a panel on the chain R range (security
first), was dispatched to a fresh Coder from the findings report, committed on
`claude/durable-audit-redact` and merged into the plan branch (M1, twice). These are fix tasks in WORKFLOW's
sense, not new plan tasks. The numbering is the commit names'. **[Amended: Amendment 3, whole-branch panel: merged
three times (`bfe4483e`, `a6c4f344`, `320e1daa`); rounds 5 and 6 were added below, and the fixes that were made on the
plan branch itself after the corpus and the panels (`W10/W12 fix`, `X`, `Y`, `Y2`, `Y3`) follow them. The labels
`X`, `Y`, `Y2` and `Y3` are the orchestrating session's, and the commit order in `git log` is `Y` (`50d8efee`), `X`
(`f103d205`), `Y2` (`aa89d325`), `Y3` (`e28a310e`).]**

| Round | Commits | What it added |
|---|---|---|
| 1 | `R2 fix` (`a9d23f76`), `R4 fix` (`cec2e706`) | A PEM body can no longer survive a key name in front of it (the PEM pre-pass); `scrub_strict` repeats a round until stable (at most 4 then; 6 from round 4); URL userinfo runs to the last `@`; a compact JWE is masked through its tag. A header string with line breaks is judged line by line, an array of three or more items is judged by its first element, and later lines of a kept value are judged by name |
| 2 | `R4 fix 2` (`2db8db86`) | Any key naming headers, `hdr` or trailers is a header collection; plain maps and nested containers inherit that context; a header line after a benign first element is judged by name; header names get the strict text pass |
| 3 | `R fix 3B` (`a3bbe0f2`), `R fix 3A` (`460b95f2`) | 3B: rule S covers a direct header array with a non-token first element; keys outside header collections take the text pass; value siblings and `header_name`/`header_value` pairs are hidden; non-token raw header lines are judged by name; nesting is cut at depth 64; the reason is bounded before the strict scrub. 3A: Rust `Debug`-printed values, JSON-escaped nested credentials and camelCase keys are masked; obs-fold continuations follow a masked header; XML, multipart and CLI-flag frames; `sec-websocket-protocol` is no longer benign (42 names); a parity test ties P6's value rule to `scrub_text` |
| 4 | `R fix 4B` (`ac13c6b3`), `R fix 4A` (`f2bc82df`) | 4B: `redact_value` settles to a fixed point; the reason statement calls `scrub_strict_bounded`, so the function the tests exercise is the one that runs; a direct header array reads as a name and its values at any length; the AC46 clock is 20 s. 4A: a list or object under a secret key is masked whole; `user[password]=...`-style keys are read as pairs; URL userinfo may hold an apostrophe; a secret XML start tag is scanned before its content; `curl -u user:pw` and multi-line multipart values are masked; the convergence cap is 6 |
| 5 | "Fix 5", **not in `f9c1f5b4`** (being committed on `claude/durable-audit-redact`, in `redact_strict.rs` and its test file only) **[Amended: Amendment 3, whole-branch panel: committed as `R fix 5`, `ba742893`; "not in `f9c1f5b4`" is history]** | An unquoted value under a strict-secret key continues across a quote followed by a non-delimiter (`password=O'Brien&remember=1`), in the frames pre-pass and in P6; a multipart field name is tested with `is_secret_key_strict` before the scan to the boundary (the scan was quadratic); group mode counts only `[`/`{` against `]`/`}` and Debug-wrapper mode keeps parentheses; the `MAX_ROUNDS` doc says six. Residuals it documents: a URL whose password holds the quote that opens it; `-u` and `-U` over-redact (`docker run -u 1000:1000 img`, `date -u +%H:%M`) |
| 6 **[Amended: Amendment 3, whole-branch panel; rows 6 to Y3 are new]** | `R fix 6A` (`a54c5abe`), `R fix 6B` (`b022f41b`), merged by `320e1daa` | 6A: `scrub_strict` fails closed: a text that no round within `MAX_ROUNDS` = 8 settles is replaced whole by `[redacted]`, never returned as the last round left it (the one 7-round fuzz input still settles with its mask intact); `scrub_strict_bounded`'s doc no longer claims a length bound. 6B: `redact_value` fails closed: a value no walk round (the first plus 3) confirms is replaced whole by `"<redacted>"`, so it is exactly idempotent |
| W10/W12 fix | `b1dfa3eb` (plan branch) | The registry masks a secret at every JSON escaping depth 1 to 3 and the percent forms of those; the fragment mask makes room so a capped field stays within its cap and a second pass is the identity. Found by the corpus (W15's two ignored reproductions) |
| `X` | `f103d205` (plan branch) | The whole-branch panel's fixes: a wedged rotation is held to twice its cap (refused lines counted `dropped`, in the `gap`, `degraded` on); the `ca.audit_log` collision is on resolved files and rotated names; the config error and env warning print a kind or reason, never a value; process-history comments removed, `start_at` hidden, naming collisions renamed, wall-clock assertions replaced, the corpus seed replayable, the tail flush in `block_in_place` |
| `Y` | `50d8efee` (plan branch) | A credential header after an escaped line break is masked to the end of its line: a backslash run and `n`, `r` or `t` glued to a header name is a line boundary in P2 |
| `Y2` | `aa89d325` (plan branch) | The same rule in the frames pre-pass and P6, bracket-notation keys, multipart and CLI flags: `pw`, `otp`, `pass` and the shared segment words after a glued escape are masked |
| `Y3` | `e28a310e` (plan branch) | The same rule at P5's left boundary: a token on a line of its own after a literal backslash-n, -r or -t (`ghp_`, `AKIA`, a JWT or JWE, `sk-`, `xox`, `glpat-`, `AIza`) was left whole because the escape letter is alphanumeric; P2, P6 and P5 now share one escape-letter definition (`is_escape_letter`); `nghp_...` with no backslash is still a word ending in `n` |

**[Amended: Amendment 3, whole-branch panel]** The "check before relying on round 5" note that stood here is
resolved: `ba742893` is in `git log`, the unquoted-value tests exist (`an_unquoted_value_runs_across_a_quote_that_does_not_end_it`),
and the constant is `MAX_ROUNDS: usize = 8` with no doc comment that says "four" or "six". Fix Y3 is `e28a310e`.

### Task W1: the ring hook and `AuditLogSetting` in `aitm-core`

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC34, part of AC39 (the `aitm-core` comment fixes)
- **Depends on:** none
- **Files:** `crates/aitm-core/src/audit.rs` (modify), `crates/aitm-core/src/lib.rs`
  (modify: only the two existing `pub use` statements; chain R's R1 adds a `pub mod redact_strict;` line
  elsewhere in the same file, the one expected merge conflict of M1), `crates/aitm-core/src/config.rs`
  (modify), `crates/aitm-core/tests/durable_audit_hook.rs` (create)
- **Change.**
  - `audit.rs`: add `pub struct DurableAuditStatus { pub degraded: bool, pub dropped: u64,
    pub write_failures: u64 }` (derive `Debug, Clone, Copy, PartialEq, Eq, Default`) and `pub
    trait DurableAudit: Send + Sync + std::fmt::Debug { fn record(&self, lane: AuditLane,
    entry: AuditEntry); fn status(&self) -> DurableAuditStatus; }`. The trait doc says: must not
    block and must not panic; runs on the appending caller's thread **after** the ring's lock is
    released, so calling back into the ring is safe; `status` reads atomics only.
  - `AuditRing` gains a private field `durable: OnceLock<Arc<dyn DurableAudit>>` (initialised in
    `with_lane_capacities`, the one constructor) and two methods: `pub fn attach_durable(&self,
    sink: Arc<dyn DurableAudit>) -> bool` (set-once: a second call returns `false` and keeps the
    first) and `pub fn durable_status(&self) -> Option<DurableAuditStatus>`.
  - `append_in(&self, lane: AuditLane, entry: AuditEntry)` keeps its signature. New behaviour:
    when a sink is attached, take one `AuditEntry::clone`; insert under the lock exactly as
    today; **release the lock** (scope the guard so it is dropped); then call
    `sink.record(lane, clone)`. With no sink attached the only new work is one `OnceLock::get`
    and no clone. `AuditSink::append` still routes to `append_in(Evidence, ..)`.
  - Doc fixes (comments only), found by grep for `subset`, `opt-in`, `once one is attached`:
    the module doc's "the same one format the CA plugin's log is a subset of (spec D3a.2)"
    (about lines 3 to 9), "Only a durable JSONL sink, once one is attached, keeps a complete
    record" (about 60 to 61) and the `AuditRing` doc's "once one is attached" (about 522 to
    523). Say instead: the ring is the bounded live view; the `aitm` binary attaches a
    `DurableAudit` file writer by default (config `mcp.audit_log`), which keeps the complete
    best-effort record; the CA log is a separate, differently shaped file (not a subset).
    `McpServer::with_durable_audit` remains a per-server `AuditSink` tap used by tests.
  - `config.rs`: add `#[derive(Debug, Clone, PartialEq, Eq, Default)] pub enum AuditLogSetting {
    #[default] Default, Off, Path(PathBuf) }` with `pub fn resolved_path(&self) ->
    Option<PathBuf>` (`Default` gives `default_aitm_dir().join("audit.jsonl")`, `Off` gives
    `None`, `Path(p)` gives `Some(p.clone())`) and doc comments (`Path` is "explicit": the
    operator asked for it; the default and `Off` spellings are in Design 2 of the spec). Add `pub
    audit_log: AuditLogSetting` to `McpConfig` and `AuditLogSetting::Default` to its `Default`
    impl.
  - `lib.rs`: add `DurableAudit` and `DurableAuditStatus` to the existing `pub use audit::{..}`
    statement and `AuditLogSetting` to the existing `pub use config::{..}` statement; nothing
    else.
- **Tests (written first)**, in `durable_audit_hook.rs` (public API only; helpers: a stub sink
  recording `(AuditLane, String command)` pairs in a `Mutex<Vec<..>>` and reporting a fixed
  status; a re-entrant sink holding an `Arc<AuditRing>` and calling `ring.len()` and
  `ring.recent(None, None)` inside `record`):
  - `the_ring_hook_is_set_once_and_lock_free` (AC34): `durable_status()` is `None` before
    `attach_durable` and `Some(DurableAuditStatus { degraded: true, dropped: 7, write_failures:
    3 })` after (the stub's fixed status); a second `attach_durable` returns `false` and the
    first sink still receives the next entry (second sink's list stays empty);
    `append_in(AuditLane::Routine, e)` delivers exactly `[(Routine, "e")]`; the trait
    `AuditSink::append` of `"f"` then delivers `(Evidence, "f")`; with the re-entrant sink
    attached, an `append_in` run on a spawned thread returns within 5 s (the main thread waits
    on a channel with `recv_timeout`; a timeout fails with "the ring lock was held across the
    hook"), and the ring then holds the entry (`len() == 1`).
  - `audit_log_setting_defaults_and_resolves` (extra; backs AC3 and AC10):
    `McpConfig::default().audit_log == AuditLogSetting::Default`;
    `AuditLogSetting::Default.resolved_path()` is `Some(p)` with `p.file_name()` equal to
    `audit.jsonl` and `p.parent()` equal to `CaConfig::default().audit_log.parent()`;
    `Off.resolved_path() == None`; `Path(PathBuf::from("/x/a.jsonl")).resolved_path() ==
    Some(PathBuf::from("/x/a.jsonl"))`.
- **Red.** `cargo test -p aitm-core --test durable_audit_hook` fails to compile with an
  `unresolved import` error naming `DurableAudit` (and `AuditLogSetting`). With stubs
  (`attach_durable` returning `false`, `durable_status` returning `None`, `resolved_path`
  returning `None`), it fails on assertions: the first `attach_durable` assertion in
  `the_ring_hook_is_set_once_and_lock_free`, and `left: None, right: Some(..)` in
  `audit_log_setting_defaults_and_resolves`.
- **Green.** `cargo test -p aitm-core --test durable_audit_hook` prints `test result: ok. 2
  passed`; `cargo test -p aitm-core` prints `test result: ok` for every suite (the existing
  ring tests, `trust_gate_scan` and `classifier_wildcard_free` included, unedited);
  `cargo check --workspace --all-targets` succeeds (the `McpConfig` literal in
  `crates/aitm-plugins/tests/control.rs` ends in `..McpConfig::default()`);
  `grep -c "is a subset of" crates/aitm-core/src/audit.rs` prints `0`;
  `cargo fmt --check` and `cargo clippy -p aitm-core --all-targets -- -D warnings` are clean.
- **Do not touch:** the existing `mod tests` in `audit.rs`, `origin_label`, `lane_for`, the lane
  and fair-share code, any other crate.
- **Done when:** both reds and the green runs are quoted, `git diff --stat` (orchestrator) shows
  only the four files, and fmt and clippy are clean.

### Task W2: the `mcp.audit_log` key and `AITM_AUDIT_LOG`

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC1, AC2
- **Depends on:** W1
- **Files:** `crates/aitm/src/config_file.rs` (modify), `crates/aitm/src/env.rs` (modify),
  `crates/aitm/tests/audit_log_config.rs` (create)
- **Change.**
  - `config_file.rs`: a private `#[derive(Deserialize)] #[serde(untagged)] enum AuditLogFile {
    Flag(bool), Text(String), Other(serde_yaml::Value) }` and `audit_log: Option<AuditLogFile>`
    on `McpFile` (its `deny_unknown_fields` stays). `McpFile::apply` becomes `fn apply(self, c:
    &mut McpConfig) -> anyhow::Result<()>`; its one call in `ConfigFile::apply` becomes
    `m.apply(&mut c.mcp)?;`. Mapping: `Flag(true)` gives `AuditLogSetting::Default`;
    `Flag(false)` gives `Off`; `Text(s)` equal to `off` (ASCII case-insensitive) gives `Off`;
    `Text(s)` with `Path::new(&s).is_absolute()` gives `Path(PathBuf::from(s))`; every other
    value (a relative path, `~/x`, `""`, a number, a list) is `bail!` with a message that
    contains `mcp.audit_log` and `absolute` (for example: `mcp.audit_log must be true, false,
    off, or an absolute path; got <debug-escaped value>`). An absent key leaves the default.
    Update the module doc line that lists what the file configures only if it enumerates keys.
  - `env.rs`: add `pub const AUDIT_LOG: &str = "AITM_AUDIT_LOG";`. In `apply`, after the
    existing two lookups: when the variable is set, `off|false|0|no` (ASCII case-insensitive,
    **not** trimmed) sets `cfg.mcp.audit_log = Off`; `on|true|1|yes|default` sets `Default`; a
    value for which `Path::new(raw).is_absolute()` sets `Path(PathBuf::from(raw))`; **every other
    value (including `""`) leaves the setting exactly as it was** and logs one
    `tracing::warn!(target: "aitm::audit", ..)` naming the variable and the Debug-escaped value
    and saying the setting is unchanged. `apply` stays infallible. Put the parse in a private
    `fn audit_log_from_env(raw: &str) -> Option<AuditLogSetting>`. Extend the module doc and
    `apply`'s doc: the environment wins over the file; this variable fails safe (stays on) where
    the `ALLOW_AGENT` family treats "anything else" as false.
- **Tests (written first)**, in `audit_log_config.rs` (public API: `aitm::config_file::parse`,
  `aitm::env::apply`; paths are Unix literals, the repo's CI is Unix):
  - `audit_log_key_parses_every_spelling` (AC1): a config without the key and one with `mcp:
    {audit_log: true}` give `AuditLogSetting::Default`; `false`, `off` and `OFF` give `Off`;
    `/var/log/aitm/audit.jsonl` gives `Path(PathBuf::from("/var/log/aitm/audit.jsonl"))`; each
    of `audit.jsonl`, `~/audit.jsonl`, `""` and (extra row) `5` makes `parse(..)` return an
    error whose `{err:#}` text contains both `mcp.audit_log` and `absolute`; `mcp: {audit_logg:
    off}` still errors (unknown field). Collect every failing row into one assertion message so
    a loop does not stop at the first.
  - `audit_log_env_wins_and_never_silently_disables` (AC2): a helper builds `Config::default()`,
    sets `cfg.mcp.audit_log` to the file's value and calls `env::apply(&mut cfg, |k|
    (k == "AITM_AUDIT_LOG").then(|| value.to_string()))`. Rows: `off`, `false`, `0`, `no`, `OFF`
    give `Off`; `on`, `true`, `1`, `yes`, `default` give `Default`; `/tmp/x/a.jsonl` gives
    `Path("/tmp/x/a.jsonl")`; with the file at `Path("/a/audit.jsonl")`, the values `ofd`,
    `relative.jsonl`, `""` and `" off"` leave it exactly `Path("/a/audit.jsonl")`; with the file
    at `Off`, `/tmp/x/a.jsonl` wins and gives that `Path`; with the variable unset the file's
    value survives for each of `Default`, `Off` and `Path`.
- **Red.** `cargo test -p aitm --test audit_log_config` compiles (Task W1 supplied the types) and
  fails on assertions: AC1 with an `unknown field `audit_log`` error where `Default` is
  expected, AC2 with `left: Default, right: Off` for the first `off` row.
- **Green.** The same command prints `test result: ok. 2 passed`. Then `cargo test -p aitm
  --test config_file` and `cargo test -p aitm --lib config_file:: env::` print `test result: ok`
  (the existing tests, unedited; `config_file.rs::remaining_fields` pins that no other default
  moved); `cargo fmt --check`; `cargo clippy -p aitm --all-targets -- -D warnings`.
- **Do not touch:** the existing `mod tests` in `config_file.rs` and `env.rs`, `main.rs`, any
  other `McpFile` field, `is_truthy`, the `ALLOW_AGENT` family's semantics.
- **Done when:** red and green are quoted, the three files are the only changes, and fmt and
  clippy are clean.

### Task W3: `audit_log.rs` skeleton: streams, paths, routing, limits

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC3
- **Depends on:** W2 (it adds a test to the file W2 created)
- **Files:** `crates/aitm/src/audit_log.rs` (create), `crates/aitm/src/lib.rs` (modify: `pub
  mod audit_log;` and one line in the crate doc), `crates/aitm/tests/audit_log_config.rs`
  (modify: add one test)
- **Change.** A module doc that says what the module is (the durable audit writer; best-effort,
  not tamper-evident; three streams; the spec path) and the first slice of the shared design:
  `StreamKind` and its `const fn` methods with the spec's numbers (queue 1024 / 4096 / 2048;
  4 MiB, 8 MiB, 8 MiB; keep 4 / 5 / 2), `pub fn stream_path(base: &Path, kind: StreamKind) ->
  PathBuf` (`Control` is `base`; `Agent` and `Reads` insert `.agent` / `.reads` before the final
  extension, or append it when there is none: `audit.jsonl` gives `audit.agent.jsonl`, `audit`
  gives `audit.agent`, `audit.v2.jsonl` gives `audit.v2.agent.jsonl`; build the file name from
  `file_stem` and `extension` as `OsString`s so a non-UTF-8 name works), and `pub fn
  stream_for(lane: AuditLane, origin: Frontend) -> StreamKind` (`Routine` gives `Reads`;
  `Evidence` gives `Control` when `origin.is_trusted_control()`, else `Agent`; it compares
  nothing against the agent role). Add `#[allow(dead_code)] // used from <task id>` only where
  needed (everything here is `pub`, so probably nowhere).
- **Tests (written first).**
  - `stream_paths_follow_the_rule` (AC3, in `audit_log_config.rs`): `/a/audit.jsonl` gives
    `/a/audit.jsonl`, `/a/audit.agent.jsonl`, `/a/audit.reads.jsonl`; `/a/audit` gives
    `/a/audit`, `/a/audit.agent`, `/a/audit.reads`; extra row `/a/audit.v2.jsonl` gives
    `/a/audit.v2.jsonl`, `/a/audit.v2.agent.jsonl`, `/a/audit.v2.reads.jsonl`;
    `AuditLogSetting::Default.resolved_path()` ends in `audit.jsonl` and has the same parent as
    `CaConfig::default().audit_log`; `Off.resolved_path()` is `None` (these two rows are green
    on arrival).
  - In-module `stream_for_routes_by_lane_and_trust` (extra): `(Routine, Cli|Mcp|Operator)` all
    give `Reads`; `(Evidence, Operator)` and `(Evidence, Cli)` give `Control`;
    `(Evidence, Mcp)` gives `Agent`.
  - In-module `stream_limits_total_92_mib` (extra): the sum over `StreamKind::ALL` of
    `max_bytes() * (1 + keep_rotated() as u64)` equals `96_468_992` (20 + 48 + 24 MiB), and the
    three `queue_capacity()` values are `[1024, 4096, 2048]`.
- **Red.** `cargo test -p aitm --test audit_log_config stream_paths` fails to compile (`unresolved
  import aitm::audit_log`). With stubs (`stream_path` returning `base.to_path_buf()`, `stream_for`
  returning `Control`, limits returning 0), it fails on assertions: `left: "/a/audit.jsonl",
  right: "/a/audit.agent.jsonl"`; `stream_for_routes_by_lane_and_trust` with `left: Control,
  right: Reads`; `stream_limits_total_92_mib` with `left: 0, right: 96468992`.
- **Green.** `cargo test -p aitm --test audit_log_config` prints `test result: ok. 3 passed`;
  `cargo test -p aitm --lib audit_log::tests` passes the two in-module tests;
  `cargo test -p aitm-core --test trust_gate_scan` still passes (the new file is scanned);
  fmt and `cargo clippy -p aitm --all-targets -- -D warnings` are clean.
- **Do not touch:** `config_file.rs`, `env.rs`, `main.rs`, any other test.
- **Done when:** both reds and the green runs are quoted and only the three files changed.

### Task W4: the hardened file layer: `preflight` and the start marker

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC7, AC8 (mechanism for AC5 and AC6)
- **Depends on:** W3
- **Files:** `crates/aitm/src/audit_log.rs` (modify) only.
- **Change.** Add `MARKER_SCHEMA`, `FileId`, the `LogFile` trait, `FsFile` (a real file handle
  that tracks its own size and `FileId`), `start_marker_line` and `preflight`, all per the
  shared design (private; `#[allow(dead_code)] // used from Task W5`). `start_marker_line` renders
  the `start` marker: the keys `at, marker, pid, schema, stream, version`, `marker` `"start"`,
  `schema` `MARKER_SCHEMA`, `version` `env!("CARGO_PKG_VERSION")`, `stream` the `label()`; one
  JSON object, no newline (use `serde_json::json!`; keys sort alphabetically).
  `preflight(path: &Path, stream: StreamKind) -> io::Result<FsFile>` does, in order, with every
  error built as `io::Error` whose message names the path and the reason:
  0. A non-absolute `path` is refused (message contains `absolute`).
  1. Create missing parent directories with `DirBuilder::recursive(true)` and mode `0700`
     (Unix). An **existing** immediate parent with mode bit `0o002` set and `0o1000` clear is
     refused (`world-writable`); `0775`, group- and other-readable parents are accepted.
  2. `symlink_metadata(path)`: a symlink is refused (`symbolic link`); anything that is not
     `is_file()` (directory, FIFO, socket, device) is refused (`regular file`) **without
     opening it**; a regular file with `nlink > 1` is refused (`hard link`); `NotFound` is the
     fresh-file case.
  3. Open for append with mode `0600`: `create_new(true)` when step 2 found no file (call 6),
     else `append(true)` and no create; then `symlink_metadata` again and require the same
     `(dev, ino)` as the handle (else refuse: the path changed while it was opened). Also open
     with `read(true)` so step 5 can read the last byte.
  4. An existing file with any group or other mode bit is set to `0600` through the handle
     (`File::set_permissions`); if that fails the path is refused.
  5. When the file is non-empty and its last byte is not `\n`, append `\n` first (a torn tail);
     then append the start marker line plus `\n`. The returned `FsFile::size()` equals the file's
     length afterwards.
  Mode, `nlink` and identity checks are `#[cfg(unix)]`; on other targets the file is created
  with default permissions and `id()` is `None`; the module still compiles. `FsFile::append_line`
  does one `write_all` of the line plus `\n`; `sync` is `File::sync_data`.
- **Tests (written first)**, in the in-module `tests` (create it with the shared helpers listed
  under "Conventions"; `within(2s, ..)` guards every preflight call):
  - `hostile_paths_are_refused_without_hanging` (AC7, `#[cfg(unix)]`): in a fresh scratch
    directory, each of these returns `Err` within 2 s whose message contains the quoted text: a
    symlink to a regular file (`symbolic link`); a directory (`regular file`); a FIFO made with
    `Command::new("mkfifo")` (`regular file`; if `mkfifo` cannot be spawned, print `SKIPPED` and
    skip that row only); a regular file with `std::fs::hard_link` to a second name (`hard
    link`); a path whose parent directory is set to mode `0777` with no sticky bit
    (`world-writable`). A parent set to `0775` is accepted (`Ok`). A pre-existing regular file
    with mode `0644` succeeds and `metadata().permissions().mode() & 0o777 == 0o600` afterwards.
  - `an_unwritable_parent_is_an_error` (AC8, `#[cfg(unix)]`): a directory with mode `0500`;
    preflight of `<dir>/audit.jsonl` returns `Err` whose message contains the path. First try to
    create a file in the `0500` directory: if that succeeds (the process is root) print `SKIPPED
    (running as root)` and return.
  - `preflight_creates_private_dirs_and_files_with_a_start_marker` (extra, `#[cfg(unix)]`):
    `<scratch>/a/b/audit.jsonl`: `a` and `a/b` are mode `0700`, the file `0600`, it holds exactly
    one line, a JSON object with exactly the keys `at, marker, pid, schema, stream, version`,
    `marker == "start"`, `schema == 1`, `stream == "control"`, `pid == std::process::id()`,
    `version == env!("CARGO_PKG_VERSION")`; `FsFile::size()` equals the file length.
  - `preflight_appends_a_start_marker_and_repairs_a_torn_tail` (extra, backs AC6): a file holding
    `{"a":1}\n{"b"` (no trailing newline) is never truncated: after preflight its lines are
    `{"a":1}`, `{"b"`, then a `start` marker (three lines), and `size()` equals the file length.
  - `preflight_refuses_a_relative_path` (extra): `preflight(Path::new("rel/audit.jsonl"), ..)` is
    `Err` containing `absolute`, and nothing is created.
- **Red.** `cargo test -p aitm --lib audit_log::tests` fails to compile (missing `preflight`). With
  a stub `preflight` that does `OpenOptions::new().append(true).create(true).open(path)` and
  nothing else, it fails on assertions or by timeout: the symlink row (`expected an error for a
  symbolic link`), and the FIFO row fails with `preflight blocked for more than 2 s` (the stub
  opens the FIFO). Quote both.
- **Green.** `cargo test -p aitm --lib audit_log::tests` prints `test result: ok`; fmt and
  `cargo clippy -p aitm --all-targets -- -D warnings` clean. Orchestrator runs the full gate
  after this task.
- **Do not touch:** any file other than `audit_log.rs`; no writer type yet.
- **Done when:** both reds (including the timeout) and the green are quoted.

### Task W5: the writer core: three queues, threads, routing, flush

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC11, AC12, AC21, AC29, AC30
- **Depends on:** W4
- **Files:** `crates/aitm/src/audit_log.rs` (modify) only.
- **Starts from:** `StreamKind`, `stream_for`, `LogFile`, `FsFile`, `preflight` (W3, W4);
  `aitm_core::{DurableAudit, DurableAuditStatus}` (Task W1).
- **Change.** The writer's skeleton, per the shared design: `Backend` (with `rotate` defaulting
  to `Err(io::ErrorKind::Unsupported)` and `recheck` to `Recheck::Same`, so add the one-variant
  `Recheck` now and the other variants in Task W9; `#[allow(dead_code)]` on the unused ones),
  `FsBackend` (`open` is `preflight`, boxed), `StreamSpec`, `Tuning` with `production()` (the
  spec's constants from `StreamKind`, re-check 5 s, reopen 1 s, rotation retry 60 s, warn
  throttle 60 s), `pub const SHUTDOWN_BUDGET: Duration = 2 s`, `pub struct ShutdownReport {
  pub complete: bool, pub estimated_left: usize }`, `pub struct AuditLogWriter` with a manual
  `Debug`, `fn from_specs(specs: [StreamSpec; 3], tuning: Tuning) -> io::Result<AuditLogWriter>`
  (`#[allow(dead_code)] // used from Task W11`) and `pub fn shutdown(&self, budget: Duration) ->
  ShutdownReport`, and `impl DurableAudit for AuditLogWriter`.
  - Per stream: a `sync_channel(tuning.queue[i])` carrying `Msg::{Entry(AuditEntry), Close}`;
    one thread named `aitm-audit-<label>` owning the `StreamSpec`; a shared `Arc` of atomics:
    `dropped: AtomicU64`, `write_failures: AtomicU64`, `degraded: AtomicBool`, `closed:
    AtomicBool`, `dead: AtomicBool`, `queued: AtomicUsize`. A drop guard in the thread sets
    `dead` when it exits without `closed` (a panic or a lost receiver).
  - `record(&self, lane, entry)`: `stream_for(lane, entry.origin)`, `queued += 1`, `try_send`;
    on `Full` or `Disconnected` undo `queued`, `dropped += 1` (Task W6 adds the gap note). It never
    blocks, never panics, performs no file I/O.
  - Thread loop (this task): receive in order; `Entry` renders with
    `aitm_ca::audit::entry_to_jsonl` (W12 swaps in `render_line`) and calls `append_line` on
    the open file; success clears `degraded`; an error does `write_failures += 1` and
    `degraded = true` and drops the entry (no reopen yet: Task W7); `queued -= 1` after each
    entry; `Close` calls `sync` (error ignored), sets `closed`, exits.
  - `status()`: `dropped` and `write_failures` summed over the three streams; `degraded` is true
    when any stream is `degraded` or `dead` (a `closed` stream is not degraded). A stream whose
    `StreamSpec.file` is `None` starts `degraded`.
  - `shutdown(budget)`: for each stream, `try_send(Close)` in a retry loop (sleep 1 ms between
    tries) until it is accepted, the receiver is gone, or the budget ends; then poll
    `JoinHandle::is_finished` until all are finished or the budget ends; join the finished ones
    and leave the rest detached. `complete` is "every thread finished"; `estimated_left` is the
    sum of `queued` when it is not. It never blocks past the budget, is idempotent (a second
    call finds no handles and reports `complete: true`), and works through `&self` (the handles
    sit in a `Mutex`).
- **Tests (written first)**, in-module. Helpers added: `fs_writer(dir, tuning) -> (Arc<AuditRing>,
  Arc<AuditLogWriter>, [PathBuf; 3])` (builds the three paths with `stream_path`, runs
  `preflight` for each, wraps them in `StreamSpec`s with `FsBackend`, calls `from_specs`, creates
  a fresh `AuditRing`, calls `attach_durable(writer.clone())`); and a fake file backend
  (`FakeState` shared through an `Arc`: collected lines, an optional gate that blocks inside the
  first `append_line` and exposes `inside()`/`release()`), used from here on by W6 and W7.
  - `entries_are_routed_by_lane_and_trust` (AC11): on `fs_writer` with `Tuning::production()`:
    `ring.append_in(Evidence, op_e)` (origin `Operator`), `append_in(Evidence, ag_e)` (origin
    `Mcp`), `append_in(Routine, ag_r)` (`Mcp`), `append_in(Routine, op_r)` (`Operator`) and the
    trait `ring.append(cli_e)` (origin `Cli`); `shutdown(5 s)`; `entry_commands` of the control
    file is `["op_e", "cli_e"]`, of the agent file `["ag_e"]`, of the reads file `["ag_r",
    "op_r"]`; and `op_e.visible_to(Frontend::Mcp)` is `false` yet its line is present (assert
    both).
  - `an_entry_line_has_exactly_the_seven_keys` (AC12, `[guard]`): one entry through the writer;
    the parsed entry line has the keys `args, at, client_label, command, connection_id, origin,
    result`; the raw line equals `aitm_ca::audit::entry_to_jsonl(&entry)`; for an error entry
    `result` is `{"error": reason}`.
  - `recording_after_shutdown_is_counted_never_blocking` (AC21): `shutdown(5 s)` on an idle
    writer, then ten `ring.append_in` calls (mixed origins and lanes) return at once (wrap in
    `within(1 s)`) and `status().dropped == 10` exactly, no panic.
  - `shutdown_flushes_every_queued_entry` (AC29): 2000 agent-origin evidence entries `e0` to
    `e1999`, then `shutdown(5 s)` at once: `complete == true`, `estimated_left == 0`, and the
    agent file's `entry_commands` is exactly `e0..e1999` in order with the `start` marker as the
    first line.
  - `shutdown_of_a_blocked_writer_returns_within_its_budget` (AC30): the agent stream is a fake
    blocking inside its first write; record one agent entry, `wait_until(2 s, inside)`; then
    `shutdown(300 ms)` returns in under 1.5 s with `complete == false` and `estimated_left >= 1`.
    Release the gate at the end so the thread can exit.
- **Red.** `cargo test -p aitm --lib audit_log::tests` fails to compile (missing `from_specs`,
  `AuditLogWriter`). With a stub writer whose `record` does nothing and whose `shutdown` returns
  `{ complete: true, estimated_left: 0 }`, it fails on assertions: AC11 `left: [] , right:
  ["op_e", "cli_e"]`; AC12 no entry line; AC21 `left: 0, right: 10`; AC29 `left: 0, right:
  2000`; AC30 `assertion failed: !report.complete`.
- **Green.** The five tests pass with `cargo test -p aitm --lib audit_log::tests`; fmt and
  `cargo clippy -p aitm --all-targets -- -D warnings` clean.
- **Do not touch:** other files; no sanitising, gap, reopen, rotation or re-check logic.
- **Done when:** both reds and the green are quoted.

### Task W6: drop-newest and `gap` markers

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC18, AC19
- **Depends on:** W5
- **Files:** `crates/aitm/src/audit_log.rs` (modify) only.
- **Starts from:** the writer and the fake blocking backend of Task W5.
- **Change.** Add `gap_marker_line(now_ms, from, to, dropped, failed) -> String` (keys `at,
  dropped, failed, from, marker, to`, `marker` `"gap"`) and `GapState { dropped: u64, failed:
  u64, from: Option<i64>, to: Option<i64> }` with `note_drop(at_ms)`, `note_fail(at_ms)` (both
  widen `from`/`to`) and `take() -> Option<GapState>` (returns the pending state and resets it,
  `None` when nothing is pending). Each stream holds one `Mutex<GapState>` shared with the
  producers; the critical section is a few integer operations, tolerates poisoning, and holds no
  I/O. In `record`, a `Full` or `Disconnected` result now also calls `note_drop(entry.at_millis())`
  (the live `dropped` counter stays separate and monotonic). In the thread, before writing an
  entry, `take()` the pending gap; if there is one, write the gap line first through
  `append_line`; if that write fails, put the gap back (merge) and treat the entry as a failed
  write (Task W5's accounting). The stream's file is untouched when nothing is pending.
- **Tests (written first)**:
  - `a_stalled_disk_never_blocks_the_call_path` (AC18): the agent stream is the fake blocking
    inside its first write; entries use `entry(command, Mcp, at_ms)` with `at_ms = 1_700_000_000_000
    + i` for `a<i>`. Record `a0`, `wait_until(2 s, inside)`, then record `a1` to `a5095` from a
    worker thread under `within(2 s)`; `ring.durable_status().unwrap().dropped == 999` exactly.
    Release the gate, `shutdown(5 s)` returns `complete == true`; the fake's entry lines are
    exactly `a0` to `a4096` in order (4097 entries), and exactly one line is a `gap` marker with
    `dropped == 999`, `failed == 0`, `from == 1_700_000_000_000 + 4097`, `to == 1_700_000_000_000
    + 5095`.
  - `a_flooded_stream_cannot_starve_another` (AC19): same blocked agent stream with its queue
    full (record `a0` to `a5095` as above), control and reads on real files (`preflight`): record
    10 operator-origin evidence entries and 10 `append_in(Routine, ..)` successful reads;
    `wait_until(2 s)` the control file has 10 entry lines and the reads file 10, while the fake
    is still blocked (assert the gate has not been released); `durable_status().dropped` is
    still `999`. Release and `shutdown` at the end.
  - `gap_marker_line_has_exactly_the_documented_keys` (extra): the parsed line's keys are `at,
    dropped, failed, from, marker, to` and `marker == "gap"`.
  - `gap_state_merges_and_resets` (extra): `note_drop(10)`, `note_drop(30)`, `note_fail(20)`;
    `take()` equals `Some(GapState { dropped: 2, failed: 1, from: Some(10), to: Some(30) })`; a
    second `take()` is `None`.
- **Red.** `cargo test -p aitm --lib audit_log::tests` fails to compile (missing
  `gap_marker_line`, `GapState`). With stubs (`gap_marker_line` returning an empty string,
  `GapState::take` returning `None`), it fails on assertions: AC18 `expected exactly one gap
  line, found 0` (its `dropped == 999` assertion already passes: record that); the two extra tests
  on their literals. **AC19 passes on arrival** (Task W5's separate queues already isolate
  streams): record it as the guard for the "route everything to one stream" mutation.
- **Green.** All pass with `cargo test -p aitm --lib audit_log::tests`; fmt and clippy clean.
- **Do not touch:** other files. The gap line is written before the next entry (Ambiguity 1);
  do not add a position scheme.
- **Done when:** both reds (and the AC19 note) and the green are quoted.

### Task W7: the runtime error policy: reopen, degraded, throttled logging

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC20 (mechanism for AC9)
- **Depends on:** W6
- **Files:** `crates/aitm/src/audit_log.rs` (modify) only.
- **Starts from:** the writer, `GapState` and the fake backend (now with a failing mode).
- **Change.** Per spec Design 9, in the stream thread: one write attempt per entry. On a write
  error, drop the entry, `write_failures += 1`, `degraded = true`, `note_fail(at)`, close the
  handle (`file = None`) and stamp `last_open_attempt = now`. An entry that finds `file == None`
  tries `Backend::open(path, kind)` only when `now - last_open_attempt >= tuning.reopen`; a
  success installs the handle and proceeds to write (gap line first, then the entry); a failure
  stamps `last_open_attempt`, counts that entry as a failure (`note_fail`) and drops it; inside
  the interval the entry fails fast with no `open` call. A stream whose spec arrived with `file:
  None` treats boot as its last attempt. The first successful write after failures clears
  `degraded` and logs one `info!(target: "aitm::audit", ..)` naming the stream and the number of
  failures since the last line. Add `struct WarnThrottle` (`new(every: Duration)`, `admit(&mut
  self, now: Instant) -> Option<u64>`: `Some(n)` when a line may be logged, `n` being how many
  were suppressed since the last one, else `None`), one per stream, and log each failure at
  `warn!(target: "aitm::audit", path, error kind, suppressed, ..)` only when it admits. Messages
  name the path and the `io::ErrorKind`, never an entry field. Extend the fake backend: a
  shared `fail_next: AtomicUsize` (the next N entry writes return `ErrorKind::StorageFull`), an
  `open_calls` counter, and an option for `open` to fail.
- **Tests (written first)**:
  - `a_write_error_loses_the_entry_and_marks_the_gap` (AC20): control stream on the failing fake
    (`fail_next = 5`), `Tuning { reopen: Duration::ZERO, ..production() }`; record 5 operator
    entries `c1..c5` with explicit `at`s; `wait_until(2 s, write_failures == 5)`; assert
    `degraded == true`; record `c6`; `shutdown(5 s)`; `degraded == false`; the fake's lines
    contain exactly one `gap` marker with `failed == 5`, `dropped == 0`, `from == at(c1)`, `to ==
    at(c5)`, and it sits immediately before the line for `c6`; the entry lines are `["c6"]`; no
    panic.
  - `a_stream_that_never_opened_counts_every_entry_as_a_failure` (extra, backs AC9): a stream
    spec with `file: None` and a backend whose `open` always errs, `reopen` one hour: three
    entries give `write_failures == 3`, `degraded == true`, `open_calls == 0` (boot counted as
    the last attempt); with `reopen: Duration::ZERO` the same three entries give `open_calls ==
    3`.
  - `warn_throttle_logs_first_then_once_per_interval` (extra): `WarnThrottle::new(60 s)` with
    fixed `Instant`s `t0`, `t0 + 1 s`, `t0 + 2 s`, `t0 + 60 s`, `t0 + 61 s` returns `Some(0)`,
    `None`, `None`, `Some(2)`, `None`.
  - `a_dead_writer_thread_reports_degraded` (extra): a fake file whose `append_line` panics;
    after one entry `wait_until(2 s, status().degraded)`; five more `record` calls return and
    `dropped == 5`; no panic reaches the caller.
- **Red.** First a compile error naming `WarnThrottle`; with it stubbed (`admit` returning `None`)
  the tests compile against Task W6's code and fail on assertions: AC20 (`expected exactly one
  gap marker with failed == 5, found 0`; Task W5's counting already gives `write_failures == 5`),
  `a_stream_that_never_opened_...` (`open_calls` is `0`, expected `3` in the second case),
  `warn_throttle_...` (the stub returns `None` first). `a_dead_writer_thread_reports_degraded`
  may already pass (Task W5's drop guard sets `dead`): state in the report whether it was green on
  arrival.
- **Green.** All pass with `cargo test -p aitm --lib audit_log::tests`; fmt and clippy clean.
  Orchestrator runs the full gate at the end of Task W11.
- **Do not touch:** other files; do not add rotation or the re-check.
- **Done when:** both reds and the green are quoted.

### Task W8: rotation and retention

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC23, AC24, AC25, AC26
- **Depends on:** W7
- **Files:** `crates/aitm/src/audit_log.rs` (modify) only.
- **Starts from:** `Tuning { cap_bytes, keep, rotate_retry }`, `Backend::rotate` (default
  `Unsupported`), `FsFile`, `start_marker_line`.
- **Change.** `FsBackend::rotate(path, stream, keep)` per spec Design 8: (the stream has already
  called `sync` on its handle) remove `F.keep` only when `symlink_metadata` says it is a regular
  file and it exists (a symlink, directory or other file there makes the rotation fail, deleting
  nothing); rename `F.(keep-1)` to `F.keep` down to `F.1` to `F.2` (skipping absent ones); rename
  `F` to `F.1`; create a new `F` with `create_new(true)` and mode `0600`; write its `start`
  marker; return it boxed. Names are `F` plus `.1`, `.2`, ... appended to the full stream file
  name. In the thread, before writing a line (the pending gap line, if any, counts toward its
  length), when `file.size() > 0 && file.size() + pending_len > tuning.cap_bytes[i]` and the
  rotation retry time has passed: call `rotate`; on success replace the handle (the old one
  drops) and write the line to the new file; on failure keep the old handle, write the line to
  it anyway (the cap is soft while rotation fails), set the next retry to `now +
  tuning.rotate_retry`, and log through the stream's `WarnThrottle`. A failed rotation is not a
  write failure. Rotation happens at most once per line; an entry larger than the cap is written
  into a fresh file.
- **Tests (written first)**, in-module, real files, `Tuning { cap_bytes: [2048; 3], keep:
  [k; 3], ..production() }`, entries from `entry(..)` with `args_summary` of 150 `x` (lines of
  about 250 bytes), origin `Mcp`, evidence lane (agent stream, base name `audit.jsonl`, so the
  files are `audit.agent.jsonl`, `.1`, `.2`, ...):
  - `rotation_loses_no_line` (AC23): `k = 100`; record `c0..c99`; `shutdown`. Concatenating
    `F.n ... F.1, F` (highest index first, only the files that exist) yields entry commands
    exactly `c0..c99`, each once, in order; every file is at most 2048 bytes; every file's first
    line is a `start` marker.
  - `retention_deletes_only_the_oldest_rotated_file` (AC24): `k = 2`; `c0..c99`; exactly `F`, `F.1`,
    `F.2` exist for the stream (no `F.3`); their entries, oldest file first, are a contiguous run
    ending at `c99` that starts after `c0`; `c99` is in `F` or `F.1`; the control and reads
    streams' files hold only their `start` marker (untouched).
  - `a_failed_rotation_never_drops_the_line` (AC25, `#[cfg(unix)]`): after start, `chmod 0500` the
    stream directory (skip with `SKIPPED (running as root)` when a file can still be created in
    it); record 100 entries; `shutdown` (restore the mode first so the scratch guard can clean
    up): all 100 are in `F` (its length exceeds 2048), none lost, `write_failures == 0`, no panic.
  - `an_oversized_file_rotates_on_its_first_write` (AC26): pre-fill the agent file with 5000 bytes
    of whole lines before `preflight`; record one entry; `F.1` begins with the old content (the
    boot `start` marker follows it), `F` holds a `start` marker then the entry.
  - `rotation_never_deletes_a_non_regular_oldest_slot` (extra, `#[cfg(unix)]`): `k = 2` with a
    directory made at `F.2` (and `F.1` present); recording enough lines to rotate leaves the
    directory in place, loses no line, and counts no write failure.
- **Red.** Compiles against W7's code; fails on assertions: AC23 (`F.1` does not exist; the
  active file holds all 100 and exceeds 2048 bytes), AC24 (no `F.1`/`F.2`), AC26 (no `F.1`);
  AC25 and the directory test pass on arrival (nothing rotates yet): record that, they are guards
  for the mutations "write the triggering line before rotating, or drop it".
- **Green.** All pass; `cargo test -p aitm --lib audit_log::tests`; fmt and clippy clean.
- **Do not touch:** other files; the re-check arrives in Task W9.
- **Done when:** both reds and the green are quoted.

### Task W9: the path re-check

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC22, AC27, AC28
- **Depends on:** W8
- **Files:** `crates/aitm/src/audit_log.rs` (modify) only.
- **Change.** Make `Recheck` `{ Same, Gone, Replaced, Refused(String) }` and implement
  `FsBackend::recheck(path, file)`: `symlink_metadata(path)`: `NotFound` gives `Gone`; any other
  error, a symlink or a non-regular file gives `Refused(reason)`; a regular file whose `(dev,
  ino)` equals `file.id()` gives `Same`, a different one `Replaced`; a file with no `id()` (a
  fake) gives `Same`. In the thread, `last_recheck` starts at the thread's start time (so the
  first interval-based check happens one interval after boot); when `now - last_recheck >=
  tuning.recheck`, **and always before a rotation**, call `recheck`; `Gone` or `Replaced`
  reopens at once through `Backend::open` (the
  `preflight`, which recreates the directory `0700` and writes a `start` marker); a failed reopen
  counts the entry as a failure, sets `file = None` and stamps `last_open_attempt`; `Refused`
  counts the entry as a failure (`note_fail`), sets `degraded`, drops the handle (`file = None`)
  and writes nothing; later entries follow Task W7's reopen policy, whose `open` refuses a
  symlink, directory or FIFO without opening it.
- **Tests (written first)**, in-module, real files, `Tuning { recheck: Duration::ZERO, ..production()
  }`, operator-origin evidence entries (control stream), `shutdown` before reading:
  - `a_path_that_becomes_a_directory_costs_the_caller_nothing` (AC22): after start, delete the
    control file and create a directory at its path; record 100 entries through a real ring with
    the writer attached, under `within(2 s)`: every call returns, `write_failures == 100`,
    `degraded == true`, and `ring.len() == 100`. Second case (`#[cfg(unix)]`, skipped with
    `SKIPPED` if `mkfifo` cannot be spawned): replace the file with a FIFO instead: the same
    results, and neither the 100 calls nor `shutdown(2 s)` hang.
  - `a_removed_file_or_directory_is_recreated_with_a_start_marker` (AC27): delete the active
    file, record one entry: a new file exists whose lines are a `start` marker then the entry.
    Second case: remove the whole stream directory, record one entry: the directory exists again
    (mode `0700` on Unix) and its file's lines are a `start` marker then that entry.
  - `a_file_swapped_for_a_symlink_is_not_written_through` (AC28, `#[cfg(unix)]`): replace the
    active file with a symlink to a regular file `V` holding known bytes; record an entry: `V`'s
    size and bytes are unchanged and `write_failures >= 1`.
  - `rotation_rechecks_the_path_first` (extra): with `recheck` set to one hour (so no interval
    check is due) and `cap_bytes` 2048, a file pre-filled past the cap before `preflight`, then
    deleted after start: the next entry makes a rotation due, the pre-rotation check finds
    `Gone`, the writer reopens a fresh file whose lines are a `start` marker then the entry, and
    no `F.1` is created from the deleted file.
- **Red.** Compiles against W8; fails on assertions: AC22 `left: 0, right: 100`
  (`write_failures` stays `0`: the writer keeps writing to the unlinked inode), AC27 (no new file
  at the path), AC28 (`V` grew), `rotation_rechecks_the_path_first` (an `F.1` exists or the
  entry is missing).
- **Green.** All pass; fmt and clippy clean.
- **Do not touch:** other files.
- **Done when:** both reds and the green are quoted.

### Task W10: the `SecretRegistry` (`audit_log/registry.rs`)

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC48, AC49 (and the registry half of AC51)
- **Depends on:** W9 (same worktree; no code dependency on chain R)
- **Files:** `crates/aitm/src/audit_log/registry.rs` (create), `crates/aitm/src/audit_log.rs` (modify:
  `mod registry;` and `pub use registry::{Registration, SecretRegistry};` only)
- **Change.** Spec Design 14.4. In `registry.rs`:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Registration { Substring, WholeToken, Ignored }`
    (no value in it).
  - `pub struct SecretRegistry` with a manual `Debug` that prints exactly `SecretRegistry { secrets: N }`
    (`N` = the number of stored secrets, ignored ones not counted) and **no `Display`**; `impl Default`;
    `pub fn new() -> SecretRegistry`; `pub fn register(&self, source: &str, secret: &str) ->
    Registration`; `pub fn mask(&self, text: &str) -> String`; `pub fn len(&self) -> usize` and
    `pub fn is_empty(&self) -> bool`. (`mask_trailing_fragment` is added by W12.)
  - Tiers by byte length: 8 or more is `Substring` (masked anywhere); 4 to 7 is `WholeToken` (masked only
    when bounded on both sides by a character that is not an ASCII alphanumeric, `_`, `-` or `.`, or by
    the edge of the field); under 4, or empty, or a substring of the mask literals (`redacted`,
    `[redacted]`, `<redacted>`), is `Ignored`.
  - Forms: each secret is stored raw and, when different, JSON-escaped (as `serde_json` writes a string
    body, without the quotes), percent-encoded with upper-case hex (ASCII letters, digits, `-`, `.`, `_`,
    `~` kept, every other byte `%XX`) and, when different again, with lower-case hex; all masked longest
    first; the replacement is `[redacted]`.
  - Lifetime: a copy-on-write snapshot (an `RwLock<Arc<Snapshot>>` is the suggestion): `register` builds
    a new snapshot and swaps it; `mask` clones the `Arc` and masks **without holding the lock**, so a
    registration made while the writer runs is seen by the next field it masks. With no secrets `mask`
    returns the text unchanged.
  - Logging: registering a secret of 4 to 7 bytes (or an `Ignored` one shorter than 4 bytes that is not
    empty) emits one `tracing::warn!(target: "aitm::audit", ..)` whose text contains the **source label**
    and `shorter than 8` and which never contains the value or its length. Nothing else in the module
    logs, and no error or panic message can carry a secret.
- **Tests (written first)**, in the in-module `tests` of `registry.rs`. Tracing is captured with a small
  `MakeWriter` over `Arc<Mutex<Vec<u8>>>` and `tracing::subscriber::with_default` (`tracing-subscriber`
  is already a dependency of `aitm`):
  - `registry_tiers` (AC48): with `ABCD1234EFGH` registered (returns `Substring`), `"x ABCD1234EFGH y"`
    gives `"x [redacted] y"` and `"prefixABCD1234EFGHsuffix"` gives `"prefix[redacted]suffix"`. With
    `wxyz` registered (`WholeToken`): `"a wxyz b"` gives `"a [redacted] b"`, `"(wxyz)"` gives
    `"([redacted])"`, `"awxyzb"` and `"a-wxyz"` are unchanged. With `abc` registered (`Ignored`): `"abc
    abcd"` is unchanged. `redacted` (8 bytes) registers as `Ignored` and `mask("[redacted]")` is
    `"[redacted]"`. For the `wxyz` and `abc` registrations a captured `tracing` event contains the source
    label and `shorter than 8`, and neither the value nor its length.
  - `registry_masks_every_encoding` (AC49): with `Zm9v+YmFy/Ymf=ZZ99` and `ab"cd\ef12345` registered, each
    of these masks the whole secret to `[redacted]`: the raw form; `Zm9v%2BYmFy%2FYmf%3DZZ99`; the lower-case
    `Zm9v%2bYmFy%2fYmf%3dZZ99`; the JSON form `ab\"cd\\ef12345`; and `http://127.0.0.1:8082/#t=` + the raw
    form gives `http://127.0.0.1:8082/#t=[redacted]`. In the JSON text `{"u":"x?next=Zm9v%2BYmFy%2FYmf%3DZZ99"}`
    the result is `{"u":"x?next=[redacted]"}` and `serde_json::from_str` still parses it.
  - `registry_debug_prints_only_a_count` (extra): after two non-ignored registrations and one `Ignored`,
    `format!("{:?}", registry)` equals `SecretRegistry { secrets: 2 }` and `format!("{:?}",
    Registration::Substring)` equals `Substring`.
- **Red.** `cargo test -p aitm --lib audit_log::registry` first fails to compile (missing module). With
  stubs (`register` returning `Ignored`, `mask` returning its input) it fails on assertions: `left: "x
  ABCD1234EFGH y", right: "x [redacted] y"` and the encoding rows.
- **Green.** The three tests pass with `cargo test -p aitm --lib audit_log::registry`; `grep -rn "Display
  for" crates/aitm/src/audit_log.rs crates/aitm/src/audit_log/` prints nothing; fmt and `cargo clippy -p
  aitm --all-targets -- -D warnings` clean.
- **Do not touch:** every other file; no use of the registry by the writer yet.
- **Done when:** both reds and the green are quoted.
- **[Amended: Amendment 3, whole-branch panel] As built after `b1dfa3eb`.** The registry stores a secret in more
  forms than this task's text: raw; JSON-escaped at depths 1, 2 and 3 (`JSON_DEPTHS` = 3); and the percent-encoded
  form (upper- and lower-case hex) of the raw secret and of its JSON forms at depths 1 and 2
  (`PERCENT_OF_JSON_DEPTHS` = 2); the tier is judged on the **raw** byte length. A fourth JSON level, a double
  percent encoding, PHP `\/` and Python `\uXXXX` are not stored (spec Residual risks 27). `Debug` still prints a
  count; the number of forms changes neither it nor any log line. Tests added to `registry.rs` (19 at `e28a310e`):
  `the_secret_91_constants_are_the_forms_they_name`, `a_secret_is_masked_at_every_escaping_depth`,
  `a_short_secret_is_masked_at_every_depth_as_a_whole_token`, `masking_at_each_depth_keeps_the_json_valid`,
  `many_forms_change_neither_the_count_nor_the_log`.

### Task W11: `AuditLogHandle`, `start`, `start_at`, the boot policy and source registration

- **Chain / worktree:** W, the plan worktree. Merge point M1 follows this task.
- **Satisfies:** AC4, AC5, AC6, AC9, AC10, AC51, AC53
- **Depends on:** W10 (and W9)
- **Files:** `crates/aitm/src/audit_log.rs` (modify), `crates/aitm/tests/audit_log_config.rs` (modify:
  add AC4)
- **Change.**
  - `AuditLogWriter` gains `registry: Arc<SecretRegistry>` (an empty registry created in `from_specs`)
    and `pub fn registry(&self) -> &Arc<SecretRegistry>`. The stream threads do not use it yet (W12).
  - `Tuning` becomes `pub` with `#[doc(hidden)]`, `pub fn production() -> Tuning` and
    `#[doc(hidden)] pub fn with_cap_bytes(self, bytes: u64) -> Tuning` (sets the three caps); its fields
    stay `pub(crate)`. (The corpus tests of W14 and W15 need a small rotation cap from an integration
    test; Ambiguity 17.)
  - `#[derive(Clone)] pub struct AuditLogHandle { writer: Arc<AuditLogWriter>, registry: Arc<SecretRegistry> }`
    with a manual `Debug` (it prints the counts only: `AuditLogHandle { secrets: N }`), and
    `pub fn registry(&self) -> &Arc<SecretRegistry>`, `pub fn register_secret(&self, source: &str,
    secret: &str) -> Registration`, `pub fn generate_bridge_token(&self) -> String` (calls
    `crate::web::generate_token()` and registers the result under the label `web.operator_bridge_token`
    **before returning it**), `pub fn shutdown(&self, budget: Duration) -> ShutdownReport`, `pub fn
    status(&self) -> DurableAuditStatus`. And `pub fn bridge_token(handle: Option<&AuditLogHandle>) ->
    String` (`handle.generate_bridge_token()` when `Some`, else `crate::web::generate_token()`): the one
    expression `main.rs` (W18) calls.
  - `pub fn start(cfg: &Config, ring: &Arc<AuditRing>, web_token: Option<&str>, env: &[(String, String)])
    -> anyhow::Result<Option<AuditLogHandle>>`; `pub fn start_at(ring: &Arc<AuditRing>, base: &Path,
    ca_log: &Path, explicit: bool) -> anyhow::Result<Option<AuditLogHandle>>` (no sources registered,
    production tuning); `#[doc(hidden)] pub fn start_tuned(cfg, ring, web_token, env, tuning: Tuning) ->
    anyhow::Result<Option<AuditLogHandle>>` (`start` is `start_tuned` with `Tuning::production()`). All
    three end in a private `start_core(ring, base, ca_log, explicit, tuning, secrets: Vec<(String,
    String)>)`.
  - `start_tuned`: `cfg.mcp.audit_log.resolved_path()` of `None` (`Off`) gives `Ok(None)` and touches
    nothing; otherwise it collects the secrets to register (empty values are skipped): the transport token
    of `cfg.mcp.transport` (`LoopbackTcp` or `StreamableHttp`), label `mcp.transport.token`;
    `cfg.mcp.operator_token`, label `mcp.operator_token`; `cfg.mcp.agent_token` when set, label
    `mcp.agent_token`; `web_token`, label `web.agent_bridge_token`; and every `env` pair whose name
    contains (ASCII case-insensitively) `token`, `secret`, `password`, `passwd`, `credential`, `api_key`,
    `apikey`, `private_key`, `passphrase` or `access_key`, label `env:<NAME>` (a name, never a value;
    `SSH_AUTH_SOCK` and `HOME` do not match). Then `start_core(.., matches!(cfg.mcp.audit_log,
    AuditLogSetting::Path(_)), ..)`.
  - `start_core`, in order (Ambiguity 2): (1) if any of the three `stream_path(base, ..)` equals `ca_log`
    (lexical comparison), return an error whose text contains `ca.audit_log` and the colliding path,
    creating nothing; (2) a non-absolute `base` is unusable; (3) `preflight` each stream in the order
    control, agent, reads; (4) **explicit:** the first failure returns `Err` (message: the path and the
    reason, for example `audit log <path> cannot be used: <reason>; fix mcp.audit_log or set it to
    off`), before any thread is spawned; **default:** a failed stream (or an unusable `base`) becomes a
    `StreamSpec` with `file: None` and one `warn!(target: "aitm::audit", path, error ..)` names the path
    and the reason; (5) build `StreamSpec`s with `FsBackend` and the given tuning, call `from_specs` (a
    spawn failure is an error when explicit, one `warn!` plus `Ok(None)` when default); (6) **register
    every secret in `secrets` on the writer's registry** (so no entry can reach a file before the
    registrations); (7) `ring.attach_durable(writer.clone())`: `false` means shut the writer down and
    return an error; (8) on a healthy start log **one** `info!(target: "aitm::audit", path = %<control
    path>, ..)` naming the control file and nothing else (no token, label, count or secret), return
    `Ok(Some(handle))`. Remove the `dead_code` allows that `start_core` makes unnecessary.
- **Tests (written first)**:
  - `a_stream_path_equal_to_the_ca_log_is_refused` (AC4, in `audit_log_config.rs`): a `Config` with
    `mcp.audit_log = Path(<dir>/audit.jsonl)` and `ca.audit_log = <dir>/audit.jsonl`: `start(&cfg, &ring,
    None, &[])` returns `Err` whose `{err:#}` contains `ca.audit_log`, and `<dir>` still holds no file;
    the same with `ca.audit_log = <dir>/audit.reads.jsonl`.
  - `a_fresh_start_creates_private_files` (AC5, in-module, `#[cfg(unix)]`): `start` with
    `Path(<scratch>/a/b/audit.jsonl)`: `<scratch>/a` and `<scratch>/a/b` are mode `0700`, all three files
    mode `0600`, each holds exactly one line, a `start` marker with exactly the keys `at, marker, pid,
    schema, stream, version`, `schema == 1`, and `stream` equal to `control`, `agent`, `reads`.
  - `restart_appends_never_truncates` (AC6): record `c1`, `c2`, `c3` (operator evidence), `shutdown`;
    start again on the same path with a **fresh ring**; record `c4`, `c5`; `shutdown`. The control file's
    lines are `start, c1, c2, c3, start, c4, c5` in that order.
  - `explicit_fails_the_boot_default_degrades` (AC9): with a regular file `F` in a scratch directory and
    `base = F/audit.jsonl`: `start_at(&ring, base, ca, true)` is `Err` and the directory still holds only
    `F`; `start_at(&ring, base, ca, false)` is `Ok(Some(handle))`, `ring.durable_status().is_some()`,
    `degraded == true` at once, and after one recorded entry `write_failures == 1`. A relative `base`:
    `Err` when explicit, `Ok(Some(..))` degraded when not (and `rel/` is not created).
  - `off_creates_nothing` (AC10): `start` with `Off` returns `Ok(None)`, the scratch directory stays
    empty, `ring.durable_status()` is `None`.
  - `the_operator_bridge_token_is_registered_when_minted` (AC53, in-module): from a `start_at` handle,
    `handle.generate_bridge_token()` returns a 64-hex-digit `t` and `handle.registry().mask(&format!("a
    {t} b"))` gives `"a [redacted] b"`; a second call returns a different token, also masked;
    `bridge_token(None)` returns a 64-hex-digit token and a handle's `registry().len()` is unchanged by
    it (the audit-off fallback registers nothing).
  - `a_secret_never_appears_in_debug_display_or_logs` (AC51, in-module): five canaries `CNRY51a...`
    registered through a handle (one of them 5 bytes, so the short-secret warning fires); `format!("{:?}",
    ..)` of the registry, of a `Registration`, of the `AuditLogHandle` and of the `AuditLogWriter`
    contains none of them (the registry's is exactly `SecretRegistry { secrets: N }`), and the captured
    `tracing` output of `start_tuned` and of a failing write (a fake file that fails, as in W7) contains
    none of them; `grep -rn "Display for" crates/aitm/src/audit_log.rs crates/aitm/src/audit_log/` prints
    nothing (no `Display` anywhere).
  - `start_registers_the_configured_sources` (extra): `start_tuned` with `LoopbackTcp {token: T1}`,
    `operator_token: T2`, `agent_token: T3`, web token `T4` and env pairs `[("GITHUB_TOKEN", E),
    ("SSH_AUTH_SOCK", S), ("HOME", H)]` gives `handle.registry().len() == 5`, `mask` turns each of
    `T1`..`T4` and `E` into `[redacted]` and leaves `S` and `H` unchanged; the same for a
    `StreamableHttp` transport token.
- **Red.** `cargo test -p aitm --lib audit_log::tests` and `cargo test -p aitm --test audit_log_config`
  first fail to compile (missing `start`, `start_at`, `AuditLogHandle`). With stubs returning `Ok(None)`
  they fail on assertions: AC4 `expected an error, got Ok(None)`; AC5 (`<scratch>/a/b` does not exist);
  AC6 (control file missing); AC9 (`expected Err` for explicit; `expected Some` for default); AC53 and
  AC51 on the missing handle. `off_creates_nothing` **passes against the stub** (record that).
- **Green.** All pass; `cargo test -p aitm --test audit_log_config` prints `test result: ok. 4 passed`;
  fmt and clippy clean. **Orchestrator runs the full gate here** (the writer is complete) and then
  merge point M1.
- **Do not touch:** `main.rs` (W18), the wiring test file, `web/`.
- **Done when:** both reds (and the AC10 note) and the green are quoted.

### Task W12: the field pipeline, text fields (replaces the old sanitising task)

- **Chain / worktree:** W, the plan worktree, **after M1** (it calls `aitm_core::redact_strict::scrub_strict`).
- **Satisfies:** AC50 (and the text-field half of AC16; AC12 stays green)
- **Depends on:** W11 and M1
- **Files:** `crates/aitm/src/audit_log/pipeline.rs` (create), `crates/aitm/src/audit_log/registry.rs`
  (modify: `mask_trailing_fragment`), `crates/aitm/src/audit_log.rs` (modify: `mod pipeline;` and the
  stream thread calls `render_line`)
- **Change.** Spec Design 6 and 14.5. In `pipeline.rs`:
  - Constants `FIELD_BOUND_BYTES = 64 * 1024`, `MAX_COMMAND_CHARS = 128`, `MAX_CONNECTION_ID_BYTES = 64`.
  - `pub(crate) fn render_line(entry: &AuditEntry, registry: &SecretRegistry) -> String`: clone the entry
    and, on the writer thread, run for each field, in this order: **(1) bound** each string field to
    `FIELD_BOUND_BYTES` (char boundary); **(2) pass:** `client_label` through
    `aitm_core::sanitize_client_label` then `scrub_strict`; `result.error`, `command` and `connection_id`
    through `scrub_strict`; **`args` through an identity function in this task**, named
    `args_pass(text: &str) -> String` with a comment that W13 replaces it (no `scrub_text` or `scrub_strict`
    may ever run over `args` as plain text, Design 14.0); **(3) registry:** `registry.mask` on every string
    field (the stream thread holds an `Arc<SecretRegistry>` cloned from the writer and masks **at write
    time**, so a late registration is seen); **(4) controls:** in `args`, `result.error`, `command` and
    `connection_id` a whitespace control becomes one blank and every other `char::is_control` character
    (C0, DEL, C1) becomes U+FFFD; **(5) cap:** `args` to `DEFAULT_ARGS_SUMMARY_CAP` bytes and
    `result.error` to `DEFAULT_RESULT_REASON_CAP` bytes on a char boundary plus `…` only when cut, `command`
    to `MAX_COMMAND_CHARS` characters and `connection_id` to `MAX_CONNECTION_ID_BYTES` bytes (no marker),
    then `registry.mask_trailing_fragment` on each; **(6) render** with `aitm_ca::audit::entry_to_jsonl`.
    Controls run before the cap so that U+FFFD (three bytes) is counted by the cap.
  - `SecretRegistry::mask_trailing_fragment(&self, text: &str) -> String` (`pub(crate)`): Design 14.4 "cut
    secrets": strip one trailing `…` (U+2026) from `text`, then, if what remains ends with a prefix of 6 or
    more bytes of a registered secret of 8 or more bytes (any stored form), replace that fragment with
    `[redacted]`; restore the `…` (Ambiguity 15: the source's cap puts its marker after the cut).
  - The stream thread (W5) switches from `entry_to_jsonl` to `render_line(&entry, &registry)`.
- **Tests (written first)**:
  - `a_late_registration_reaches_a_running_writer` (AC50, in `audit_log.rs` tests, using the fake blocking
    backend of W5/W6): the control stream's fake blocks inside its first write; record `e0`, wait until
    inside; record `e1` whose `args_summary` holds `LATE50TOKENVALUE`; register `LATE50TOKENVALUE` through
    `writer.registry()` while `e1` is queued; release the file; record `e2` (also holding it) after the
    registration; `shutdown(5 s)`. The fake's lines for `e1` and `e2` both lack `LATE50TOKENVALUE` and hold
    `[redacted]`.
  - In-module `text_fields_are_scrubbed_registry_masked_controlled_and_capped` (extra): a hand-built entry
    with `client_label` `"web-bridge\u{202E}\n token=LABELSECRET12"`, `result` `Error("Bearer REASONSECRET12
    \u{1b}[31m \u{9b}2J\u{7f}\nnext")`, `command` `"a\nb"` + 200 `z`, `connection_id` 10 KiB of `c`, with
    `REGSECRET12XYZ` registered and present in `command`: through `render_line` the parsed
    `client_label` is at most 64 chars and holds no `LABELSECRET12`; `result.error` is at most 1027 bytes,
    holds no `REASONSECRET12` and no U+009B or DEL; `command` is at most 128 characters and holds no
    `REGSECRET12XYZ`; `connection_id` is at most 64 bytes.
  - In-module `a_cut_registered_secret_is_masked_at_a_field_end` (extra): with `CUT12SECRETVALUE0123456789`
    registered, a `result` of `Error("see CUT12SECRE…")` (the source's marker after a cut 10 bytes in) renders
    `result.error` equal to `"see [redacted]…"`; a fragment of 5 bytes (`CUT12`) is **not** masked (the
    documented residual, 14.4).
  - In-module `an_honest_text_entry_renders_unchanged` (extra): command `flow.list`, label `aitm-mac`,
    `connection_id` `conn_00ff-1`, `result` `Error("plain reason")`, args `{}`: `render_line(&entry,
    &SecretRegistry::new())` equals `aitm_ca::audit::entry_to_jsonl(&entry)`.
  - In-module `render_line_caps_after_it_replaces_controls` (extra): `args_summary` `"\u{9b}".repeat(400)`
    renders with `args` of at most 515 bytes and no U+009B.
- **Red.** Fails to compile (missing `pipeline`, `render_line`, `mask_trailing_fragment`). With stubs
  (`render_line` delegating to `entry_to_jsonl`, `mask_trailing_fragment` returning its input) it fails on
  assertions: AC50 (`LATE50TOKENVALUE` still in the line), the text-field test (`LABELSECRET12` present),
  the cut-secret test, the control test (U+009B present). `an_honest_text_entry_renders_unchanged` passes
  on the stub (a guard). Quote the failures.
- **Green.** `cargo test -p aitm --lib audit_log::` passes (AC12's `an_entry_line_has_exactly_the_seven_keys`
  from W5 included); fmt and `cargo clippy -p aitm --all-targets -- -D warnings` clean.
- **Do not touch:** `aitm-ca`, `aitm-core`, `aitm-mcp`, any other file; do not add `args` redaction here.
- **Done when:** both reds and the green are quoted.
- **[Amended: Amendment 2, chain R fix rounds] As built (`f21b1202`).** `render_line` is `render_with(entry, registry,
  PASSES)`, where `PASSES` is `scrub_strict` for the text fields and `redact_args_text` for `args`; the label's
  `LABEL` tail has no control step (`sanitize_client_label` already dropped them); every field of `AuditEntry` is
  named in `render_with`, so a field added to it is a compile error until someone decides what the pipeline does with
  it. The same commit adds the **environment value rule** to `start` (spec 14.4): `is_benign_env_value` keeps an
  empty value, a switch literal (`true`, `false`, `null`, `none`, `yes`, `no`, `on`, `off`, `default`, `enabled`,
  `disabled`, `auto`, ASCII case-insensitive) and an all-digit value under 8 bytes (`ENV_DIGITS_MIN_BYTES`) out of the
  registry (pinned by `the_environment_rule_skips_values_that_are_not_secrets` and
  `a_flag_like_environment_value_never_masks_ordinary_text`); a configured token is always registered. Extra tests
  in `pipeline.rs`: `every_text_field_gets_the_strict_pass`, `no_text_pass_reads_more_than_the_bound`,
  `a_label_the_pass_lengthens_is_cut_back_to_its_cap`, `a_field_is_bounded_before_any_pass_runs`,
  `the_pipeline_never_scrubs_args_as_plain_text`, `controls_are_replaced_by_class`,
  `caps_cut_on_a_character_boundary_and_mark_only_what_they_cut`, `hostile_args_of_a_megabyte_render_within_the_cap`.
  **[Amended: Amendment 3, whole-branch panel: `b1dfa3eb` changed the fragment mask. As first written the mask
  (10 bytes) could leave a field up to four bytes past its cap and a second pass would cut it again; now the text
  before the fragment gives way a character at a time (never the mask, never inside a JSON escape) until the field is as
  its cap leaves it, and a field cut this way ends with `…` when its cap marks cuts. Tests added to `pipeline.rs`
  (18 at `e28a310e`): `a_fragment_mask_at_the_cap_edge_leaves_args_within_its_cap`,
  `a_fragment_mask_at_the_cap_edge_leaves_every_field_within_its_cap`,
  `the_cut_before_a_fragment_lands_on_a_character_boundary`, `a_cut_before_a_fragment_never_leaves_a_lone_backslash`,
  `an_escaped_backslash_before_the_cut_is_kept`, `nested_json_that_holds_a_registered_secret_is_masked_end_to_end`;
  and, in the corpus, `a_masked_short_fragment_keeps_args_within_the_cap` and
  `a_registered_secret_with_a_quote_is_masked_inside_json_text_in_a_string`.]**

### Task W13: the `args` pipeline: parse-first and the tolerant JSON-text scan

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC16, AC17, AC47 (the writer half), AC54
- **Depends on:** W12 and M1 (it calls `aitm_mcp::redact_args::redact_value`)
- **Files:** `crates/aitm/src/audit_log/jsonscan.rs` (create), `crates/aitm/src/audit_log/pipeline.rs`
  (modify: `args_pass` calls it), `crates/aitm/src/audit_log.rs` (modify: `mod jsonscan;`),
  `crates/aitm/tests/audit_log_wiring.rs` (create: the rig of the wiring tests and AC17)
- **Change.** Spec Design 14.5. In `jsonscan.rs`:
  - `pub(crate) fn redact_args_text(text: &str) -> String`: (1) if `serde_json::from_str::<Value>(text)`
    parses, return `aitm_mcp::redact_args::redact_value(&v).to_string()` (parse-first: the source's own
    function, rules S and D); (2) else `scan_json_text(text)`; (3) when the scan gives up, `scrub_strict(text)`
    as plain text.
  - `fn scan_json_text(text: &str) -> Option<String>`: **iterative** (no recursion), linear. Outside string
    literals only JSON structure characters (`{ } [ ] , :`), JSON whitespace, number characters (digits,
    `+ - . e E`) and the complete words `true`, `false`, `null` are accepted; anything else returns `None`
    (give up, the whole text is plain). Inside a literal the content is decoded (`\" \\ \/ \b \f \n \r \t`
    and `\uXXXX` with surrogate pairs; a literal cut off by the end of the text is decoded as far as it goes,
    dropping a partial escape), passed through `scrub_strict`, and re-encoded with the escaping `serde_json`
    uses (an unchanged ASCII literal is byte-identical); a literal that is not closed is re-emitted without
    a closing quote. A closed literal followed (after blanks) by `:` is a **key**; when it
    `is_secret_key_strict` the **next literal** is replaced by `"<redacted>"` (cut: `"<redacted>` with no
    closing quote). Structure characters are never touched, so what parsed before still parses.
  - `pipeline.rs`: `args_pass` becomes `crate::audit_log::jsonscan::redact_args_text`, run **before** the
    registry mask and the controls (W12's order).
- **Tests (written first)**:
  - `a_hostile_entry_is_sanitised_before_it_is_written` (AC16, in `audit_log.rs` tests, real files through
    `fs_writer`): one hand-built entry with origin `Mcp` (so it lands in the agent file), `client_label`
    `"web-bridge\u{202E}\n token=LABELSECRET9"`, `args_summary` `" password=ARGSECRET9 "` followed by 1 MiB of
    `x`, `result` `Error("Bearer REASONSECRET9 \u{1b}[31m \u{9b}2J\u{7f}\nnext")`, `connection_id` 10 KiB of
    `c`, `command` `"a\nb"` + 200 characters. Through `ring.append`, then `shutdown(5 s)`. In the agent file:
    none of `LABELSECRET9`, `ARGSECRET9`, `REASONSECRET9`; exactly two `\n` bytes; no byte below `0x20` other
    than those two; no `0xC2 0x9B` and no `0x7F`; parsed `client_label` at most 64 chars, `args` at most 515
    bytes (this `args` is not JSON, so it is plain text and `password=` is masked), `result.error` at most 1027
    bytes, `connection_id` at most 64 bytes, `command` at most 128 chars.
  - `cut_secrets_and_the_tolerant_scan` (AC54, in `audit_log.rs` tests, through `render_line`/the writer): (a)
    with `CUT54SECRETVALUE0123456789` registered, an `args` of `{"note":"` + `x` repeated so that the text is 512
    bytes with exactly its **first 10 bytes of the secret** at the end, then `…` (so it ends mid-token; Ambiguity
    14 explains why not 470 `x`) is written with no `CUT54S` and ends `[redacted]…`. (b) The cut text
    `{"headers":{"Cookie":"a=b; s=SECRET54","X":"v"},"note":"GET /\r\nCookie: a=b; z=SECRET54b\r\nHo` (with real
    JSON escapes for `\r\n`, inside a literal, not JSON) is written with `SECRET54` and `SECRET54b` absent,
    `"X":"v"` unchanged (rule D is source-only, Residual risks 17), and every character outside string literals
    identical to the input (delete the literal contents from both and compare). `{"password":"SECRET54c","n":1`
    gives `{"password":"<redacted>","n":1`. (c) ` password=SECRET54d x` (not JSON) gives ` password=[redacted] x`.
    (d) the complete hand-built `{"headers":{"X-Custom":"SECRET54e"}}` gives `{"headers":{"X-Custom":"<redacted>"}}`
    (parse-first).
  - In-module (`jsonscan.rs`) `tolerant_scan_never_changes_structure` (extra): over a list of cut and odd texts
    (a cut string, a cut escape `"a\u00`, nested arrays cut mid-element, an unquoted word `{"a": hello}` which
    gives up) every result that is not `None` equals the input with only literal contents changed; and
    `redact_args_text("{\"a\": hello password=P1}")` equals `"{\"a\": hello password=[redacted]}"`.
  - `an_honest_entry_is_written_unchanged` (AC17, in the new `audit_log_wiring.rs`, no mutation of entries): a rig
    that builds `assemble_with_scripts` (a `ScriptWiring { commands: vec![Box::new(DemoPlugin)],
    ..Default::default() }` registering `demo.echo`, `Write`, one optional `Any` param `note` and one `raw`,
    returning `Value::Str("ok")`) with `cfg.ca.dir` and `cfg.ca.audit_log` in a scratch directory,
    `tui::services(..)`, `tui::server(..)` and `tui::with_shared_governance(.., &assembled.agent_state,
    &assembled.audit_ring)` (copy helpers from `audit_durable_connection_id.rs`; build connections with
    `ConnCtx::new` and assign `conn_id`), and `aitm::audit_log::start_at(&assembled.audit_ring, &base, &ca_log,
    true)`. An agent connection calls `flow.list` (ok), `agent.set {policy:"auto"}` (refused), `demo.echo
    {"note":"Authorization: Bearer SECRET47"}` and `demo.echo {"raw":"GET /\r\nCookie: a=b; z=SECRET47\r\nHost:
    x"}`. After `handle.shutdown(..)`: the sorted set of entry lines across the three files equals the sorted
    set of `entry_to_jsonl(&e)` for every `e` in `ring.recent(None, None)` (four entries); the two AC47 shapes'
    file `args` are exactly `{"note":"Authorization: [redacted]"}` and `{"raw":"GET /\r\nCookie: [redacted]\r\nHost:
    x"}` (as JSON escapes) and parse as JSON; `SECRET47` is in no file.
- **Red.** Fails to compile (missing `jsonscan`); with `args_pass` still the identity (W12) it fails on assertions:
  AC16 (`ARGSECRET9` present), AC54 (a) (`CUT54S` present), (b), (c), (d) (the secret strings present), the
  scan test; `an_honest_entry_is_written_unchanged` **passes on arrival** (identity leaves honest entries
  unchanged): say so, and that its red is the mutation C1 26 (`scrub_text` over JSON text), proved by running
  that mutation once here and quoting the failure of the two AC47 shapes.
- **Green.** `cargo test -p aitm --lib audit_log::` and `cargo test -p aitm --test audit_log_wiring` pass; `grep
  -rn "scrub_text" crates/aitm/src/audit_log.rs crates/aitm/src/audit_log/` prints nothing; fmt and clippy
  clean.
- **Do not touch:** `aitm-mcp`, `aitm-core`, `aitm-ca`, `entry_to_jsonl`, any other file.
- **Done when:** the reds, the mutation proof and the green are quoted.
- **[Amended: Amendment 2, chain R fix rounds] As built (`44ea8e06`).** `redact_args_text` is parse-first, then
  `scan_json_text`, then `scrub_strict`. The scan sets one trailing `…` (`registry::CUT_MARK`) aside before it
  walks and restores it after (Ambiguity 35); a word that starts `true`, `false` or `null` and runs to the end is the
  word the cut interrupted; it tracks a three-state `Pair` (`Idle`, `Named`, `Hide`) so that **only the string
  literal directly after a secret key** is hidden (`"<redacted>"`, or `"<redacted>` with no closing quote when cut),
  and a number, a word or a container under a secret key ends the state and is left alone (Ambiguity 38). Hostile
  nesting is scanned without recursion. Extra tests in `jsonscan.rs`:
  `a_literal_is_encoded_the_way_serde_json_encodes_it`, `a_secret_key_hides_the_literal_that_follows_it`,
  `a_text_cut_outside_a_literal_is_still_scanned`, `text_that_parses_goes_through_the_source_function`,
  `no_plain_text_pass_runs_over_json_text`, `what_the_source_wrote_is_a_fixed_point_of_the_writer_pass`,
  `a_text_cut_anywhere_by_the_cap_comes_back_unchanged`, `deeply_nested_text_is_scanned_without_recursion`,
  `deeply_nested_text_goes_through_the_whole_pass`, `hostile_texts_are_scanned_in_linear_time`,
  `generated_texts_hold_every_property_of_the_pass`, `the_hidden_value_is_what_the_source_writes`,
  `a_literal_content_gets_the_strict_text_pass`. **[Amended: Amendment 3, whole-branch panel: unchanged in
  behaviour since `44ea8e06`. `jsonscan.rs` is 1122 lines with 14 tests at `e28a310e`; fix `X` changed 14 lines of it,
  all comments and test labels (process-history references such as "plan Ambiguity 15" were removed). Its
  `scrub_strict` calls inherit the fail-closed rounds (a literal that no round settles reads `[redacted]`), and its
  hidden value is `"<redacted>"` as the source writes it.]**

### Task W14: the corpus, part A (`audit_log_redaction.rs`)

- **[Amended: Amendment 2, chain R fix rounds] Status and what changed under it.** Not landed at `f9c1f5b4`:
  `crates/aitm/tests/audit_log_redaction.rs` does not exist. The rows run against the **as-built** rules, not the
  first cut: header collections are any key containing `header` or `hdr` (or `trailer`/`trailers`); rule D reads
  pairs, `name`/`value` objects, plain maps, raw lines and line-broken text; the benign list is 42 names
  (`Sec-WebSocket-Protocol` is hidden, so a row must not expect it kept); a hidden raw header line reads
  `Name: [redacted]`; keys are masked and cut at 256 bytes. Re-derive every expected `args` from the as-built
  rules when writing the row, and keep AC56's benign table unchanged (it uses none of the changed names). A
  corpus row whose canary is a header value under an innocuous name is red by mutation of rule D (C1 mutation 14).
  **[Amended: Amendment 3, whole-branch panel: landed as `ed249691` (105 audited calls) and extended by W15
  (`1231f845`, 313); the "Not landed" above is history. As built `audit_log_redaction.rs` is 3587 lines and has 10
  tests, so `cargo test -p aitm --test audit_log_redaction` prints `test result: ok. 10 passed`, not the 4 of the Green
  line below. Besides the AC55 to AC57 functions it has `corpus_args_are_idempotent_under_redact_value`,
  `a_built_poc_passes_through_the_audit_clean`, `start_registers_every_configured_source`, `print_the_seed`,
  `the_seed_repeats_the_run_and_every_failure_says_how`, `a_masked_short_fragment_keeps_args_within_the_cap` and
  `a_registered_secret_with_a_quote_is_masked_inside_json_text_in_a_string`. The seed is one per process, printed in every
  failure, and `AITM_CORPUS_SEED` replays it. The first-cut mutation expectation below, "skip the `scrub_strict`
  calls in `render_line` and rows R1 to R39 go red", is wrong: a real server call is already clean at the source, so
  the writer's own passes are a no-op on those rows and only the hand-built row R25 reaches them (Ambiguity 46); mutation
  (2) below (`redact_args_text` returns its input) turns R25 red as stated.]**

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC55 (rows R1 to R39, R50, R51, R53, R54), AC56, AC57 (and the corpus half of AC47)
- **Depends on:** W13
- **Files:** `crates/aitm/tests/audit_log_redaction.rs` (create)
- **Change.** Test code only; the proof layer of Design 14.7. Header comment: no socket; the path is the real one
  (`McpServer` call -> `record_audit` -> ring -> writer -> files); failures are collected and asserted once.
  - **Rig.** `assemble_with_scripts` with `ScriptWiring.commands` holding a `DemoPlugin` that registers
    `demo.accept` (`Write`; every parameter optional and `TypeDesc::Any`: `headers`, `pairs`, `entries`, `request`,
    `edits`, `selector`, `text`, `vars`, `note`, `raw`, `body`, `poc_text`, `source`, `url`, `form`, `row`;
    returns `Value::Str("ok")`) and `demo.fail` (`Write`; `invoke` returns `Err(anyhow!("rejected: {note}"))`);
    `tui::server` and `tui::with_shared_governance` over one `assemble`; the writer from
    `aitm::audit_log::start_tuned(&cfg, &assembled.audit_ring, Some(&t4), &env, Tuning::production()
    .with_cap_bytes(12 * 1024))` where `cfg` carries `T1` (the `LoopbackTcp` token), `T2` (`operator_token`),
    `T3` (`agent_token`), `t4` is the web agent token, `E` is in `env` as `("ANTHROPIC_API_KEY", E)`, and `T5` is
    minted later with `handle.generate_bridge_token()` (each of `T1`..`T5` a 64-hex-digit string from
    `aitm::web::generate_token()`); calls go through `srv.handle_on(&conn, line)` on an agent
    `ConnCtx::new(Frontend::Mcp)` with `conn_id = srv.next_conn_id()`. `cfg.ca.dir` and `cfg.ca.audit_log` are
    scratch paths. A canary is `CNRY` + the row number as two digits + `x` + eight hex digits (unique per row and
    per run). After the run: `handle.shutdown(5 s)`; **every file whose name starts with `audit`** in the scratch
    directory (active and numbered) is read as bytes. **Completeness guard:** the total number of entry lines
    across all files equals the number of audited calls (so a rotated-away file cannot hide a leak), the agent
    stream has a numbered file (`audit.agent.jsonl.1` exists) and no `.6`; if the cap needs another value, raise
    or lower the cap, never weaken the guard.
  - **A row** is `{ id, input args (serde_json::Value), forbidden: Vec<String> }` (the canary and each listed
    encoding); the builder's words around a canary are free as long as the row keeps the shape its carrier names.
    Tiny test-local helpers: a base64 encoder (no new dependency) and a pad-to-length helper.
  - **Rows in this task (spec AC55):** headers R1 (map `Authorization: Bearer C`), R2 (map `authorization: Basic
    <base64 of user:C>`), R3 (`Proxy-Authorization`), R4 (`Cookie: a=1; b=2; session=C`), R5 (`Set-Cookie:
    id=C; Path=/; HttpOnly`), R6 (`X-Api-Key: C`), R7 (`X-Debug-Access: C`), R8 (`X-Forwarded-Host: evil.test`,
    must **stay**, asserted by AC56), R9 (`["Cookie","foo=C"]`), R10 (`["Authorization","Basic <b64 of user:C>"]`),
    R11 (`["X-Custom","C"]`), R12 (`{name:"Cookie",value:C}`), R13 (`{name:"Authorization",value:C}` under `pairs`),
    R14 (`["Set-Cookie","C=1"]` under `entries`), R15 (`request.meta.request_headers {"X-Zed":"C"}`), R16
    (`response_headers {"Set-Cookie":"C=1"}`), R17 (`edits.headers {"X-Evil":"C"}`); text R18 (`raw` CRLF block with
    `Authorization: Bearer C`), R19 (`raw` with `Cookie: a=b; c=C; d=e`), R20 (a `Set-Cookie: x=C; Path=/` line),
    R21 (`Cookie: sid="C"`), R22 (`Set-Cookie: JSESSIONID="C"; Path=/`), R23 (`Authorization: Digest username="u",
    response="C"`), R24 (a header line as the last text of its string), R25 (a hand-built entry through
    `ring.append` with an unparseable truncated `args` carrying an escaped `\r\nCookie: a=b; z=C\r\n`), R26
    (`Proxy-Authorization: Basic C`), R27 (prose then `Cookie: a=b; z=C` on one line); bodies and URLs R28 (`body`
    JSON string with escaped quotes `{\"user\":\"u\",\"password\":\"C\"}`), R29 (`{"login":"u","pass":"C"}`), R30
    (`{"u":"x","pw":"C"}`), R31 (form `user=u&passphrase=C`), R32 (form `private_key=C&x=1`), R33 (form
    `access_key=C`), R34 (`?access_token=C&page=2`), R35 (`?api_key=C`), R36 (`https://user:C@host.test/p`), R37
    (`https://<ghp_ shape C>@github.com/`), R38 (`Basic <b64 of user:C>` outside any header), R39 (`otp=C` and
    `totp: C`); tools R50 (`vars {"admin_pass": C}`), R51 (`vars {"pw": C}`), R53 (`{selector:"#password",
    text:C}`), R54 (`{selector:"input[name=api_token]", text:C}`). The row numbers R40 to R49, R52, R55 to R74 are
    W15's.
- **Tests (written first)**:
  - `no_canary_reaches_any_file_through_the_real_path` (AC55; this task's rows; W15 appends the rest to the same
    function): for each row the canary (and each listed encoding) is absent from every file's bytes; every
    offending row id is collected into one failure message; the completeness guard above holds.
  - `benign_values_survive_the_real_path_byte_for_byte` (AC56): each of AC44's benign strings (the two lists of
    R1 and R2: flow-style ids, the 64-hex hash x4, `auth.example.com:8443`, the ordinary URL, `ssh://git@github.com/o/r`,
    `git@github.com:o/r.git`, `basic information`, the `Cookie` prose, `sk-prod-eu-1.example.test`, the `author=bob`
    line, the ordinary JSON, `Accept: text/html`, `X-Forwarded-For: 203.0.113.9`, `AKIA`, `AKIAFOO`, `ghp_short`,
    `eyJ`, `{{target}}/login?user={{user}}`) is sent as `note` with a sibling `row` id, and these header values in a
    `headers` map: `Accept: text/html`, `Content-Type: application/json`, `Host: h.test`, `User-Agent: Mozilla/5.0
    (X11; Linux x86_64)`, `X-Forwarded-For: 203.0.113.9`, `X-Forwarded-Host: evil.test`, `Referer:
    https://x.test/a?x=1`, `Sec-Fetch-Mode: cors`, `Accept-Language: en-US,en;q=0.9`. For each, the file's `args`
    (joined to the ring entry by the `row` id) equals `entry_to_jsonl(&ring_entry)`'s `args`, and the value read
    back from the parsed `args` equals the value sent.
  - `every_line_is_valid_json_with_the_same_shape` (AC57): every line of every file of the run parses as JSON; an
    entry line has exactly the seven keys and a marker line has `marker`; and for every row whose ring `args`
    parses, the file's `args` parses and has the same paths as the ring's (the JSON value with every string
    replaced by `""` is equal).
  - `corpus_args_are_idempotent_under_redact_value` (extra; the corpus half of AC47, Ambiguity 16): for every row's
    input `args` value `v`, `aitm_mcp::redact_args::redact_value(&redact_value(&v)) == redact_value(&v)`.
- **Red, by mutation (state it plainly in the report).** Every piece exists by now, so the corpus passes on
  arrival. The Coder proves it catches leaks with two temporary mutations, each restored and proved restored by
  `diff` against a saved copy: (1) in `render_line` skip the `scrub_strict` calls (rows R1 to R39 that rely on text
  passes go red, collected in one message); (2) in `jsonscan.rs` make `redact_args_text` return its input (R25 goes
  red). Quote both failures and both empty diffs. The full mutation list is C1's.
- **Green.** `cargo test -p aitm --test audit_log_redaction` prints `test result: ok. 4 passed`; fmt and clippy
  clean.
- **Do not touch:** `audit_log.rs` and its submodules (except the two temporary, restored mutations), every other
  file.
- **Done when:** the two mutation reds, the empty diffs and the green are quoted.

### Task W15: the corpus, part B (shapes, tools, known tokens, PoC) and source registration

- **[Amended: Amendment 2, chain R fix rounds] Status.** Not landed at `f9c1f5b4` (see W14). The shape rows
  (R40 to R49) exercise the as-built P5, whose JWT third segment may be empty and whose left boundary is any byte
  that is not an ASCII alphanumeric (`_` counts: `KEY_ghp_...` is masked, `task-<uuid>` is not an `sk-` key). The
  environment row (R72) and `start_registers_every_configured_source` follow the as-built **environment value
  rule** (a switch literal or a short digit run is not registered): use a value that is a real-looking secret.
  **[Amended: Amendment 3, whole-branch panel: landed as `1231f845`; "Not landed" is history. Its two ignored
  reproductions of writer defects found by probing (a registered secret containing a quote or backslash inside JSON
  text; a cap overrun after the trailing-fragment mask) are no longer ignored: `b1dfa3eb` fixed both. The run is over
  300 audited calls (313 at that commit) with extra rows from R75 and generated rows from R100; `cargo test -p aitm
  --test audit_log_redaction` prints 10 passed in all.]**

- **Chain / worktree:** W, the plan worktree. The writer-group panel follows this task.
- **Satisfies:** AC55 (rows R40 to R49, R52, R55 to R74), AC52, AC61
- **Depends on:** W14
- **Files:** `crates/aitm/tests/audit_log_redaction.rs` (modify)
- **Change.** Test code only, same rig. Rows appended to the AC55 function: shapes R40 (JWT
  `eyJhbGciOiJIUzI1NiJ9.eyJ` + C + `.` + C), R41 (a PEM block around C), R42 (`AKIA` + 16 uppercase hex digits
  from C), R43 (`ghp_` + C padded to 36), R44 (`github_pat_` + C padded to 22), R45 (`glpat-` + C padded to 20),
  R46 (`xoxb-123456789012-` + C), R47 (`sk_live_` + C padded to 16), R48 (`sk-` + C padded to 32), R49 (`AIza` +
  C padded to 35); tools R52 (the YAML of a real `StdPocBuilder` build, see AC61), R55 (a script `source` with
  `const PASSWORD = "C";` and a `sk_live_` shape); known tokens R56 to R60 (`T1` to `T5` bare under `note`), R61
  to R65 (`T1` to `T5` as `http://127.0.0.1:8082/#t=<T>`), R66 (`T1` as a `Referer` header value: a benign name, so
  only the registry catches it), R67 (a token containing `+/=` in its raw, upper-case and lower-case
  percent-encoded forms; registered with `handle.register_secret`), R68 (a token containing `"` and `\` in raw and
  JSON forms), R69 (`T2` quoted in the reason of `demo.fail`), R70 (`T3` as the declared client label: a
  `ConnCtx` whose `client_label` is set), R71 (`T4` straddling the 512-byte cap: `note` = 483 `x` + `T4`, so the
  source's cut falls 20 bytes into `T4`; assert the ring `args_summary` ends with `…` before the writer's mask is
  judged), R72 (`E` bare); multi R73 (one string carrying `Bearer C`, `password=C`, an AKIA shape, a JWT and a
  `Cookie:` line), R74 (`T1` and `T2` in one header value).
- **Tests (written first)**:
  - `no_canary_reaches_any_file_through_the_real_path` (AC55) now holds all 74 rows (the function of W14 gains
    the rows above; the completeness guard still holds, with the call count raised).
  - `start_registers_every_configured_source` (AC52): a config with `LoopbackTcp {token: T1}`, `operator_token:
    T2`, `agent_token: T3`, a web token argument `T4`, and an injected environment `{ANTHROPIC_API_KEY: E,
    SSH_AUTH_SOCK: /tmp/sock52xxxxxxxx, HOME: /home/u52xxxxxx}`. After `start`, hand-built entries (through
    `ring.append`) carrying each of `T1` to `T4` and `E` bare, in a `#t=` URL and as a `Referer` header value reach
    the files with none of them present, while `/tmp/sock52xxxxxxxx` and `/home/u52xxxxxx` are present unmasked.
    The same for a `StreamableHttp` transport token.
  - `a_built_poc_passes_through_the_audit_clean` (AC61): a real `aitm_poc::builder::StdPocBuilder::build(&flow,
    spec)` over an `HttpFlow` whose request has `Authorization: Bearer SECRET61A`, `Cookie: sid=SECRET61B;
    theme=dark`, path `/x?access_token=SECRET61C&q=hi` and body `user=a&password=SECRET61D` (build the flow and the
    `PocSpec` as `crates/aitm-poc/tests/builder.rs` does), serialised with `serde_yaml::to_string(&poc)` and sent as
    `poc_text`: none of the four appears in any file, the file's `args` equals the ring entry's `args`, and every
    `{{...}}` placeholder of the YAML that appears in the ring's `args` appears in the file's (the 512-byte cap
    cuts a long YAML, Ambiguity 26).
- **Red, by mutation (state it plainly).** Passes on arrival; the Coder proves it with three temporary,
  restored mutations: (1) the registry mask skipped in `render_line` (R56 to R72 and AC52 go red); (2) in
  `start_tuned` register only the `cfg` tokens (AC52 and R72 go red); (3) remove the trailing-fragment mask (R71
  goes red). Quote the failures and the empty `diff`s.
- **Green.** `cargo test -p aitm --test audit_log_redaction` prints `test result: ok. 6 passed` (W14's four
  plus these two; AC55 is the same function); fmt and clippy clean. **Orchestrator runs the full gate, then the
  writer-group panel** (security reviewer first on the redaction path).
- **Do not touch:** `audit_log.rs` and its submodules (except the temporary, restored mutations), every other
  file.
- **Done when:** the three mutation reds, the empty diffs and the green are quoted.

### Task W16: in-process wiring tests: every server is audited

- **[Amended: Amendment 3, whole-branch panel] As built (`16960e9f`).** Landed. `crates/aitm/tests/audit_log_wiring.rs`
  is 675 lines with 5 tests at `e28a310e` (W12 and W13 created and grew the file; W16 added 436 lines):
  `a_real_server_call_reaches_the_file_with_its_connection_id`, `every_server_this_binary_builds_is_audited`,
  `the_tui_operator_server_stays_unaudited`, `no_registered_command_name_starts_with_audit` and W13's
  `an_honest_entry_is_written_unchanged`.

- **Chain / worktree:** W, the plan worktree.
- **Satisfies:** AC13, AC14, AC15
- **Depends on:** W13 (it extends the wiring file and its rig), W15 (writer group done)
- **Files:** `crates/aitm/tests/audit_log_wiring.rs` (modify)
- **Change.** Test code only. Reuse the W13 rig of `audit_log_wiring.rs` (copy, do not share, helpers
  from `audit_durable_connection_id.rs`). Header comment: no socket is bound; the writer is attached
  with the production function `aitm::audit_log::start_at(&assembled.audit_ring, &base, &ca_log,
  true)` on a scratch directory (`start` itself needs a `Config` with a `Path` setting and is already
  covered by W11), never with `with_durable_audit`. `cfg.ca.dir` and `cfg.ca.audit_log` are scratch
  paths so the operator's CA directory is untouched; the handle's `shutdown(Duration::from_secs(5))`
  precedes every file read.
- **Tests (written first)**:
  - `a_real_server_call_reaches_the_file_with_its_connection_id` (AC13): servers built by
    `tui::server` and `tui::with_shared_governance` from one `assemble`, writer attached to
    `assembled.audit_ring`. An operator connection (`ConnCtx::new(Frontend::Operator)` with `conn_id =
    srv.next_conn_id()`) calls `initialize` (read its `connection_id`) then `agent.set
    {policy:"auto"}`; an agent connection calls `initialize` then `flow.list`. The control file's
    last line is the `agent.set` entry with `origin` `operator` and `connection_id` equal to the
    operator's `initialize` id; the reads file's last line is `flow.list`, `origin` `mcp`, with the
    agent connection's id.
  - `every_server_this_binary_builds_is_audited` (AC14): from one `Assembled` with the writer
    attached, build (1) a primary-shaped server and (2) a web-shaped server, each `tui::server` plus
    `tui::with_shared_governance`, and (3) the agent arm of `tui::build_servers` over a config whose
    `mcp.transport` is `McpTransport::LoopbackTcp { port: 0, token: .., endpoint_file: None }`
    (nothing is bound; call `handle_on`); `tui::Services` is not `Clone`, so call `tui::services(..)`
    once per consumer. One `flow.list` on a minted agent connection per server. After `shutdown`, the
    reads file holds exactly three entry lines with three distinct non-null `connection_id` values.
  - `the_tui_operator_server_stays_unaudited` (AC15, `[guard]`): invoke the `InProcessHandler` from
    `tui::build_servers` with a `tools/call` of `flow.list` and one of `agent.status` (JSON-RPC
    lines): after `shutdown`, none of the three files has an entry line (each holds only its `start`
    marker) and `ring.len()` is unchanged (0 before and after).
  - `no_registered_command_name_starts_with_audit` (extra, supplements AC35): `tools/list` on a
    server built by `tui::server` over the assembled registry lists no tool whose name starts with
    `audit.`; every `name` is read from the reply.
- **Red, by mutation (Call 4).** The tests pass on arrival once W11 exists. Prove they catch the
  defect: save `crates/aitm/src/audit_log.rs` to `$TMPDIR/audit_log.rs.orig`, comment out the
  `ring.attach_durable(..)` call in `start_core`, run `cargo test -p aitm --test audit_log_wiring`
  and quote the failures (AC13 and AC14 fail: the files hold only `start` markers; AC15 and the
  `audit.` test still pass), then restore from the copy and quote `diff crates/aitm/src/audit_log.rs
  $TMPDIR/audit_log.rs.orig` printing nothing. State plainly in the report that the red was produced
  by mutation.
- **Green.** `cargo test -p aitm --test audit_log_wiring` prints `test result: ok` for every test of
  the file (W13's plus these four); fmt and clippy clean.
- **Do not touch:** `audit_log.rs` and its submodules (except the temporary, restored mutation),
  `tui.rs`, `wire.rs`.
- **Done when:** the mutation red, the restored green and the empty `diff` are quoted.

### Task W17: `agent.status.durable_audit`

- **[Amended: Amendment 3, whole-branch panel] As built.** Landed. `crates/aitm-plugins/tests/agent_status_durable.rs`
  (383 lines, 3 tests): `agent_status_reports_durable_audit_by_role`,
  `agent_status_output_schema_declares_every_durable_audit_key` and `no_command_reads_or_reveals_the_audit_file`.
  `degraded` is also true while a stream's rotation is wedged (spec Design 7 and 11); the file's only post-W17 edit
  is a comment line (fix `X`).

- **Chain / worktree:** W, the plan worktree (no code dependency on chain R; see the note on W17 in the order table).
- **Satisfies:** AC32, AC33, AC35
- **Depends on:** W1
- **Files:** `crates/aitm-plugins/src/agent.rs` (modify), `crates/aitm-plugins/tests/agent_status_durable.rs`
  (create)
- **Change.** In `AgentStatus`: declare `durable_audit` in the result `TypeDesc::Object` as a
  **required** member that is itself `TypeDesc::Object` with `enabled` (`Bool`, required),
  `degraded` (`Bool`, required), `dropped` (`Int`, optional) and `write_failures` (`Int`,
  optional), each with a one-line description (the outputSchema is generated with
  `additionalProperties: false`, so every key must be declared). `invoke` reads
  `self.audit.durable_status()` (the ring it already holds): `enabled` is `status.is_some()`,
  `degraded` is the status's flag or `false`; when `host.caller_is_trusted_control()` it also
  sets `dropped` and `write_failures` (from the status, else `0`); for any other caller those two
  keys are absent. Never report the path. The command **description string is unchanged**
  (`aitmproxy-plugin/docs/tool-reference.md` lists only parameters and the description, so it
  needs no edit). Update the module doc, the `AgentStatus` doc comment and its signature line
  (`-> {policy, actions_last_minute, connected_clients, durable_audit}`): the field describes the
  disk, not anyone's activity; counters are trusted-control only because a global drop count
  would be a second channel for hidden operator entries (spec Design 11).
- **Tests (written first)**, in `agent_status_durable.rs` (copy the `StubClient`/`call` shape
  from `crates/aitm-plugins/tests/control.rs`; register `AgentPlugin::new(state)
  .with_audit_ring(ring.clone())` in a `Registry`; hosts via `CommandHost::new(..)
  .with_frontend(Frontend::Operator)` and the default `Frontend::Mcp`; a stub `DurableAudit`
  with a fixed status, `record` a no-op):
  - `agent_status_reports_durable_audit_by_role` (AC32): with no sink, an operator's
    `agent.status` has `durable_audit == {enabled: false, degraded: false, dropped: 0,
    write_failures: 0}` and an agent caller's has exactly the keys `degraded`, `enabled`. With the
    stub (`{degraded: true, dropped: 7, write_failures: 3}`) attached to the ring, the operator
    sees `{enabled: true, degraded: true, dropped: 7, write_failures: 3}` and the agent sees
    `{enabled: true, degraded: true}`; the agent's `Debug` rendering never contains `dropped` or
    `write_failures`. Compare `Value::Object` maps.
  - `agent_status_output_schema_declares_every_durable_audit_key` (AC33): `schema().result` is
    `TypeDesc::Object(defs)`; the names are `policy, actions_last_minute, connected_clients,
    durable_audit`, with the first three unchanged (types `Str`, `Int`, `Array(Object[role,
    client, since])`, all required) and `durable_audit` required; its inner names sorted are
    exactly `degraded, dropped, enabled, write_failures` and its required set exactly `{degraded,
    enabled}`; `schema().description` equals, byte for byte, `Report the current agent policy and
    recent agent activity. Read-only and readable by any role, but the activity count covers only
    the entries the caller may see: a caller that is not trusted control does not count entries
    made by trusted control (operator, CLI).` (verify against the base: the description assertion
    must pass before the change).
  - `no_command_reads_or_reveals_the_audit_file` (AC35, `[guard]`): register `AgentPlugin` and
    `ControlPlugin` (the two this test needs; the whole-registry check is W16's); no
    registered command name starts with `audit.`; `config.get` over a `Config` whose `mcp.audit_log` is
    `Path("/secret/audit.jsonl")` has a `Debug` rendering containing neither `/secret/audit.jsonl`
    nor the substring `audit_log`; no `agent.status` result (operator and agent, sink attached)
    contains `/secret/audit.jsonl`.
- **Red.** `cargo test -p aitm-plugins --test agent_status_durable` compiles (W1 supplied the
  types) and fails on assertions: AC32 `missing durable_audit in {...}`; AC33 `left: [policy,
  actions_last_minute, connected_clients], right: [..., durable_audit]` (its description row
  passes). AC35 passes on arrival (a guard): record it.
- **Green.** The same command prints `test result: ok. 3 passed`; `cargo test -p aitm-plugins`
  and `cargo test -p aitm-mcp --test mcp agent` pass (every existing `agent.status` consumer
  reads keys by name); fmt and `cargo clippy -p aitm-plugins --all-targets -- -D warnings` clean.
- **Do not touch:** `aitmproxy-plugin/docs/tool-reference.md`, `docs/research/mcp-tool-catalog.txt`,
  the TUI, web and macOS decoders, any other plugin.
- **Done when:** red and green are quoted and fmt and clippy are clean.

### Task W18: `main.rs` wiring and the real-binary tests

- **Chain / worktree:** W, the plan worktree. The orchestrator rebases on `origin/main` first. **[Amended:
  Amendment 2, chain R fix rounds: it merged `origin/main` instead (`b3a2a8df`); W18 landed as `7ff3eeea`.]**
- **Satisfies:** AC31, AC36, AC37, AC58
- **Depends on:** W11, W16 (and, for the tokens to be masked on disk, W12 to W15 and M1)
- **Files:** `crates/aitm/src/main.rs` (modify), `crates/aitm/tests/audit_log_binary.rs` (create)
- **Change.** Four small hunks in `main.rs`, no change to `Mode` or `parse_mode`:
  1. add `audit_log` to the `use aitm::{..}` list;
  2. after the `Mode::Cli` branch has returned and **before** the pre-bind block that calls
     `bind_service_port`: build the environment pairs
     (`std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?,
     v.into_string().ok()?))).collect::<Vec<(String, String)>>()`, so a non-UTF-8 variable is
     skipped, never a panic) and `let audit = audit_log::start(&cfg, &audit_ring,
     web_settings.as_ref().map(|s| s.token.as_str()), &env_pairs)?;`, with a short comment (an
     explicit unusable path fails the boot here, before any port is bound or the browser spawned;
     `audit_ring` is already named in the `Assembled` destructure; `web_settings` is resolved before
     the config is loaded, so the web agent token is known; the `start` call registers every token it
     is given before the sink is attached);
  3. in the `web_server` block, the operator bridge token expression `.then(web::generate_token)`
     becomes `.then(|| audit_log::bridge_token(audit.as_ref()))` (one expression: with the audit on it
     mints through `AuditLogHandle::generate_bridge_token`, which registers the token before
     returning it; with the audit off it is `web::generate_token()` as before; `web/mod.rs` is not
     edited);
  4. in the shared tail, after the browser is reaped and before `result` is returned, `if let Some(h)
     = &audit { let report = h.shutdown(audit_log::SHUTDOWN_BUDGET); .. }` with a
     `warn!(target: "aitm::audit", ..)` naming `report.estimated_left` only when `!report.complete`.
  Update the file's module doc by one sentence (the durable audit file, `mcp.audit_log`, and that the
  tokens never reach it). `tui::run`, `with_shared_governance`, `build_servers`, `wire::Governance`,
  `bridge.rs`, `web/mod.rs` and every `McpServer` are untouched.
- **Tests (written first)**, in `audit_log_binary.rs` (copy `TempDir`, `free_addr`, `write_config`,
  `Aitm::spawn`, `pump`, `wait_for_line` and a `serial()` lock from `shutdown.rs`; never edit it; for
  the WebSocket legs copy `ws_connect` and the token-line handshake from `tests/support/web_bus.rs`
  into a local helper; header comment: three tests bind loopback sockets and run from the Terminal
  panel). Every spawn does `.env_clear()`, then sets `PATH`, `RUST_LOG=info`, and `HOME` and
  `XDG_CONFIG_HOME` to the temp directory (so no ambient `*_TOKEN` variable in the test host can add
  a registration or a warning line), and the config names a scratch `ca.dir` and `ca.audit_log`, a
  non-existent `browser.obscura.binary` (a missing engine only warns; verify by reading
  `aitm_browser::launch_owned`), free `listen` and `browser.proxy_addr` ports, and a `loopback_tcp`
  bus on a free port with a known agent token (**loopback TCP, never stdio**: with stdin at EOF a
  stdio MCP arm ends the `select!` and the process exits at once).
  - `an_explicit_bad_path_fails_the_boot_loudly` (AC37, no socket is bound on the passing path):
    `mcp.audit_log` is a path under a regular file. The child exits non-zero within 5 s (kill it and
    fail the test otherwise), its combined output contains the path, and contains no `proxy
    listening` line.
  - `sigterm_flushes_a_real_boot` (AC31, `[socket]`): `mcp.audit_log: <P>/audit.jsonl`. Wait until
    the proxy and bus ports accept; connect to the bus; send the line `{"token":"<token>"}`, then
    JSON-RPC lines `initialize`, `tools/call flow.list`, `tools/call proxy.status`, `tools/call
    agent.set {policy:"auto"}` (one reply line per request; the agent is refused); `kill -TERM
    <pid>` through `Command::new("kill")`; the process exits within 10 s. Then `<P>/audit.reads.jsonl`
    holds exactly the entry lines `flow.list` and `proxy.status` (origin `mcp`),
    `<P>/audit.agent.jsonl` holds exactly one entry line, `agent.set`, whose `result` is an object
    with an `error` string, and `<P>/audit.jsonl` holds only its `start` marker line.
  - `a_healthy_boot_says_one_line_and_never_the_token` (AC36, `[socket]`): token
    `TOKEN-CANARY-8841`, 20 `flow.list` calls over the bus, then SIGTERM. The child's combined stdout
    and stderr contain exactly one line that mentions `aitm::audit` or the audit file path, contain
    the control file's path, and do not contain `TOKEN-CANARY-8841`; none of the three audit files
    contains it either.
  - `the_generated_operator_bridge_token_never_reaches_disk` (AC58, `[socket]`): boot `aitm web
    --no-open --listen 127.0.0.1:<free> --token <web agent token>` with `mcp.operator_token` set
    (a 64-hex value) and `mcp.audit_log: <P>/audit.jsonl`; read the operator link's token from the
    child's stdout (`web::startup_summary` prints it: read that function for the exact label); over
    the real `/bus` WebSocket as the operator, call `scope.add {host: "<operator bridge
    token>.example.test"}`, then on a second connection with the web agent token call `scope.add
    {host: "<web agent token>.example.test"}` (the label is longer than a DNS label; the command may
    reject it, which does not matter: a refused or failed call is still audited); `kill -TERM`. None
    of the operator bridge token, the web agent token or `mcp.operator_token` appears in any file under
    `<P>`, and the control file has an entry whose `args` contains `[redacted].example.test` (written,
    masked).
- **Red.** `cargo test -p aitm --test audit_log_binary an_explicit_bad_path` (sandbox): before the
  `main.rs` change the binary ignores the key, so the child does not exit within 5 s (or exits on a
  bind error with a message that lacks the path): the assertion fails with `the child did not exit
  within 5 s` or `output does not contain <path>`; quote it. For AC31, AC36 and AC58 the Coder
  quotes `cargo test -p aitm --test audit_log_binary --no-run` (it must compile) and reports `NOT RUN
  (socket)`; **the orchestrator runs them in the Terminal panel** and pastes the outputs, red before
  the `main.rs` hunks (before them the binary never starts the writer, so `<P>` holds no file and the
  assertions fail with `the control file does not exist`; for AC58 that is also why the operator bridge
  token is trivially absent from disk, so its red is the missing control-file entry) and
  green after: `cargo test -p aitm --test audit_log_binary` prints `test result: ok. 4 passed`.
- **Green.** `cargo build -p aitm`; the sandbox-safe test passes; `cargo test -p aitm --test shutdown
  --no-run` still compiles; fmt and clippy clean. **Orchestrator runs the full gate** after this task
  and after the rebase, then the wiring-group panel.
- **Do not touch:** `tui.rs`, `wire.rs`, `web/` (including `web/mod.rs`), `Mode`, `parse_mode`,
  `crates/aitm/tests/shutdown.rs` (Task H1 owns its one line).
- **Done when:** the sandbox red and green are quoted, the Terminal outputs are pasted by the
  orchestrator, and fmt and clippy are clean.
- **[Amended: Amendment 2, chain R fix rounds] As built (`7ff3eeea`).** `main.rs` changed in five places, 40 lines:
  the module doc, the `use`, the `start` call with `env_pairs` (line 563), the `bridge_token` expression (line 834)
  and the tail flush (line 920, `handle.shutdown(audit_log::SHUTDOWN_BUDGET)` then a `warn!` with
  `estimated_left` only when the flush was incomplete). `audit_log_binary.rs` holds exactly the four tests above.
  **The tail `shutdown` has no observable test**: removing it leaves every test green (C1 mutation 43, expected
  to survive, spec Residual risks 24). `start` logs its one `info!` only when all three streams opened and warns
  once per failed stream (Ambiguity 37). **[Amended: Amendment 3, whole-branch panel: fix `X` (`f103d205`) changed
  two things here. The tail flush is `tokio::task::block_in_place(|| handle.shutdown(audit_log::SHUTDOWN_BUDGET))`
  (`main.rs:922` at `e28a310e`), because it sleeps while the stream threads drain; that wrapper is as unobservable as
  the call (mutation 43 covers both). And `an_explicit_bad_path_fails_the_boot_loudly` waits `FAILED_BOOT_TIMEOUT` =
  10 s, not the 5 s of AC37, so a loaded machine does not fail it; the boot still fails in milliseconds. The file is 889
  lines with 4 tests.]**

### Task D1: stale comments

- **Chain / worktree:** independent of the chains by file, but dispatched **after M1** in the plan
  worktree, so its `server.rs` comment hunks apply on top of R3's code hunks (the hunks are
  separate regions; applying after the merge removes any chance of a conflict).
- **Satisfies:** AC39 (the `server.rs` and `aitm-ca` greps; the `aitm-core` part is W1's)
- **Depends on:** M1
- **Files:** `crates/aitm-mcp/src/server.rs` (modify, comment lines only),
  `crates/aitm-ca/src/audit.rs` (modify, comment lines only)
- **Change.** `server.rs`, three hunks, **comment lines only** (every changed line starts with `//`
  after its indentation, so the AC40 fence passes): the `durable_audit` field doc (about 1057 to
  1061: "opt-in by config", "the CA plugin's log is a subset of this one format"), the
  `with_durable_audit` doc (about 1136 to 1137: "Opt-in: when absent ..."), and the `record_audit`
  doc (about 1917 to 1919: "the optional durable sink"). Say: the `aitm` binary attaches its durable
  writer to the shared ring by default (`mcp.audit_log`, see `aitm::audit_log`); `with_durable_audit`
  is a per-server tap used by tests, and attaching it as well as the ring sink writes each entry
  twice; the CA log is a separate file in a different shape. (Line numbers drift after R3's
  deletion; find the hunks by grep for `opt-in by config`, `Opt-in: when absent` and `optional
  durable sink`.) `aitm-ca/src/audit.rs`, two comment hunks (about 158 to 165 and 191 to 197): the CA
  log is its own eight-key, fail-closed, never-rotated file, **not** a subset of the general audit;
  `FileAuditLog`'s `AuditSink` impl and `entry_to_jsonl` are the per-server tap's renderer and keep
  their behaviour. The text `is a line of one format` and `subset of it` must not remain.
- **Tests.** No Rust test. Each check is a command with a literal expected output, run by the
  Coder: `grep -c "opt-in by config" crates/aitm-mcp/src/server.rs` prints `0`; `grep -c "subset of
  this one format" crates/aitm-mcp/src/server.rs` prints `0`; `grep -c "is a line of one format\|subset
  of it" crates/aitm-ca/src/audit.rs` prints `0`; `cargo check -p aitm-mcp -p aitm-ca` succeeds
  (comments only, but prove it). The orchestrator runs the AC40 fence: its output is still only the
  redaction hunks of R3.
- **Do not touch:** any executable line, `transport.rs`, `crates/aitm/src/web/`, `aitmproxy-plugin/`,
  `crates/aitm-tui/README.md`, the PR 171 plan.
- **Done when:** every grep above is quoted with its output and `cargo check` passes.
- **[Amended: Amendment 3, whole-branch panel] As built (`f9c1f5b4`).** D1 changed four comment-only hunks of
  `server.rs`, not three: the `record_audit` doc sentence about the lane became false once the ring hook existed
  and was corrected as well (hunks at about 1058, 1140, 1926 and 1935 at `e28a310e`). On the whole branch `git
  diff -U0 <merge-base>..HEAD -- crates/aitm-mcp/src/server.rs | grep -c '^@@'` is `7` (three executable and four
  comment); the comment-filtered AC40 fence still prints `6` and `24`. D1 also corrected comment lines of
  `crates/aitm-core/src/audit.rs` (17 lines). Re-run at `e28a310e`: `grep -c "opt-in by config"` and `grep -c
  "subset of this one format"` on `server.rs` and `grep -c "is a line of one format\|subset of it"` on
  `crates/aitm-ca/src/audit.rs` each print `0`.

### Task D2: README and INSTALL (the audit log and what is redacted)

- **Chain / worktree:** independent; plan worktree, written **after W18** so the text matches the
  built behaviour.
- **Satisfies:** AC39 (README, INSTALL), AC65
- **Depends on:** W18 (and M1)
- **Files:** `README.md` (modify), `INSTALL.md` (modify)
- **Change.**
  - `README.md`: add an "Audit log" subsection (a `###` heading inside Quick start, after the
    config example near the scope snippet) covering: the default path per platform (`~/Library/
    Application Support/aitmproxy/audit.jsonl` on macOS, `~/.config/aitmproxy/audit.jsonl` on
    Linux); the three files (`audit.jsonl` operator and CLI evidence, `audit.agent.jsonl` agent
    evidence, `audit.reads.jsonl` successful reads) and that the bus never serves them;
    `mcp.audit_log` (true, false, `off`, an absolute path) and `AITM_AUDIT_LOG` including `off`; the
    size bound (at most 92 MiB with the defaults; numbered rotation `.1`, `.2`); the line shape (seven
    keys) and the two markers (`start`, `gap`, told apart by `has(.marker)`); `jq` recipes (`jq -c
    'select(.marker|not)' audit.agent.jsonl` and `cat audit*.jsonl | jq -s 'map(select(.command)) |
    sort_by(.at)'`); and the honest limits (best-effort, not tamper-evident, a same-user process can
    delete it, no fsync per line, the `aitm tui` in-process UI and one-shot CLI commands are not
    recorded, sort by `at` because a `gap` line's position in the file is not exact, do not attach the
    files to a bug report unreviewed). Make the sentence at about line 43 ("every call lands in one
    audit log with the operator named") and the bullet at about line 501 ("One audit log of every
    command ...") precise instead of absolute.
  - **(Amendment 1) A "What is redacted" paragraph in the same subsection**, which must contain the
    literal strings `<redacted>`, `Set-Cookie` and `tokens` (AC65): no token, secret or credential
    value reaches the file; the configured tokens (the bus, operator and agent tokens, the web agent
    token, the per-run operator bridge token) and secret-named environment variables are masked by
    exact value; every `Authorization`, `Proxy-Authorization`, `Cookie`, `Cookie2` and `Set-Cookie`
    line in text; `Basic` credentials and URL passwords; credential shapes (JWT, PEM private keys,
    AWS, GitHub, GitLab, Slack, Stripe, `sk-`, Google); and the keys the shared vocabulary and the
    extras (`passphrase`, `private_key`, `access_key`, `pass`, `pw`, `otp`, `totp`) name. Header
    values: every header value outside a short benign list (`Accept*`, `Content-*`, `Host`,
    `User-Agent`, `Origin`, `Referer`, `Sec-Fetch-*`, the routing and override headers) reads
    `<redacted>` in the ring, the push, `agent.activity` and the file; the name stays; the capture
    store (`flow.detail`) keeps the real request. Then the sentence naming what cannot be caught (AC65):
    a bare credential with no frame, no registered value and no known shape (a password typed into a
    free-text field under an innocuous key, an application session id in a body) is not caught, and
    a token shorter than 8 characters is only partly covered by value masking.
  - `INSTALL.md`: a five-line "Audit log" note after the config example (about lines 44 to 56) saying
    where the files are, that they are on by default and hold no tokens or credentials, and how to
    turn them off (`mcp.audit_log: off` or `AITM_AUDIT_LOG=off`).
- **Tests.** No Rust test. Greps with literal expected output, run by the Coder: `grep -c
  "audit.jsonl" README.md` prints a number `>= 3`; `grep -c "AITM_AUDIT_LOG" README.md` and `grep -c
  "mcp.audit_log" README.md` each print `>= 1`; `grep -c "mcp.audit_log" INSTALL.md` prints `>= 1`;
  `grep -c "<redacted>" README.md`, `grep -c "Set-Cookie" README.md` and `grep -c "tokens" README.md`
  each print `>= 1`; `grep -c "bare credential" README.md` prints `>= 1` (the sentence of AC65 uses
  that phrase).
- **Do not touch:** any other file; `crates/aitm-tui/README.md`; the site (`site/`).
- **Done when:** every grep above is quoted with its output. A reviewer checks the wording.
- **[Amended: Amendment 3, whole-branch panel] As built (`6a1039e7`, corrected by `5feec81b` after the
  whole-branch panel).** The INSTALL note is a `## Audit log` section of 7 text lines, not five (accepted, not
  trimmed), and points to the README's section. The README gained, after the panel: the 92 MiB bound holds while
  rotation works and what a wedged rotation does; the session-export exception; that `origin` may be `cli`
  (no `cli` line is written today: one-shot commands build no writer); valid `jq` for the markers and for a torn
  line (`jq -R 'fromjson?'` first); and that custom header values are absent from the ring, `agent.activity` and the
  push as well as the files. Greps at `e28a310e`: `audit.jsonl` in `README.md` prints `6`, `AITM_AUDIT_LOG` `2`,
  `mcp.audit_log` `2`, `<redacted>` `3`, `Set-Cookie` `1`, `tokens` `3`, `bare credential` `1`; `mcp.audit_log` in
  `INSTALL.md` prints `1`.

### Task H1: test-harness hermeticity

- **Chain / worktree:** independent. Runs in the plan worktree at a task boundary (never while a W
  Coder is mid-run: a shared `target` is locked by cargo), or in any throwaway worktree.
- **Satisfies:** AC38 (extended by the orchestrator's decision to `run.py` and
  `test_bus_endpoint_file.py`, Ambiguities 12 and 20)
- **Depends on:** none
- **Files:** `tests/e2e/aitm_e2e/core.py`, `tests/e2e/run.py`, `tests/e2e/cli/cli-startup.sh`,
  `tests/e2e/start/test_bus_endpoint_file.py`, `scripts/bus-agent-check.py`,
  `scripts/tui-live-check.sh`, `crates/aitm/tests/shutdown.rs` (one line) (all modify). The Coder
  verifies each by reading; a miss is noise, not a failure. Touches no file of any R or W task.
- **Change.**
  - `core.py` `_spawn`: the real writer runs in every cell that launches through `core.py`, on a
    per-launch file that cannot touch the operator's: one statement beside the existing `RUST_LOG`
    default, `env["AITM_AUDIT_LOG"] = os.environ.get("AITM_E2E_AUDIT_LOG") or
    os.path.join(self.workdir, "audit.jsonl")` (`workdir` is a `tempfile.mkdtemp` path, absolute).
    It is an assignment, not `setdefault`, **on purpose**: `run.py` (below) sets `off` for its
    children, and a `setdefault` here would then be dead and no e2e cell would ever run the real
    writer (decision 5). `AITM_E2E_AUDIT_LOG` is the escape hatch for a run that wants another
    path. One-shot `cli(..)` builds no writer: leave it.
  - `run.py`: in `run_suite`'s child environment (the `child_env` passed to every suite), one line
    `child_env.setdefault("AITM_AUDIT_LOG", "off")` (or at the place `child_env` is built; read
    the file), so every suite that spawns the binary without its own value, including
    `cli-startup.sh`, inherits `off`. Do not mutate `os.environ`; copy as the file does.
  - `cli-startup.sh`: `export AITM_AUDIT_LOG="${AITM_AUDIT_LOG:-off}"` once near the top, after
    `AITM_BIN` is resolved (so a direct run is hermetic too and a caller's value wins); check that
    no assertion in the script counts files in the config directory.
  - `test_bus_endpoint_file.py`: its `child_env(level)` builds the child environment from
    `os.environ`; add `env.setdefault("AITM_AUDIT_LOG", "off")` there (one line, same class as the
    `shutdown.rs` line; a direct run of the file is hermetic; under `run.py` it inherits).
  - `scripts/bus-agent-check.py`: pass `env={**os.environ, "AITM_AUDIT_LOG": "off"}` to the server
    `subprocess.Popen`.
  - `scripts/tui-live-check.sh`: the embedded run is started through `tmux new-session -d ...
    "RUST_LOG=info $AITM ..."`; an `export` in the script does **not** reach a command string run by
    an existing tmux server, so put `AITM_AUDIT_LOG=off` inline in that command string, and `export`
    it for the backgrounded `bus` mode run.
  - `crates/aitm/tests/shutdown.rs`: add `.env("AITM_AUDIT_LOG", "off")` to the `Command` in
    `Aitm::spawn`, beside `.env("RUST_LOG", "info")`. A sanctioned edit to an existing Rust test
    (AC41).
  - **Report, do not edit:** grep `crates/*/tests`, `tests/` and `scripts/` for any other
    `CARGO_BIN_EXE_aitm` or `target/*/aitm` or `AITM_BIN` spawn. Known: the one-shot-only
    `tests/e2e/start/test_env_overrides.py` and `tests/e2e/config/test_config_get_set.py` build no
    writer and need nothing; `crates/aitm-testtarget/tests/serve_bin.rs` spawns a different binary.
    Quote the grep output and list anything else found.
- **Tests (AC38).** `grep -c AITM_AUDIT_LOG tests/e2e/aitm_e2e/core.py tests/e2e/run.py
  tests/e2e/cli/cli-startup.sh tests/e2e/start/test_bus_endpoint_file.py scripts/bus-agent-check.py
  scripts/tui-live-check.sh crates/aitm/tests/shutdown.rs` prints a count of at least `1` for each
  of the seven files **[Amended: Amendment 2, chain R fix rounds: nine, with `apps/web/scripts/live-env.mjs` and `apps/mac/tools/selftest-live-embedded.sh`]**; `python3 -I -m py_compile tests/e2e/aitm_e2e/core.py tests/e2e/run.py
  tests/e2e/start/test_bus_endpoint_file.py scripts/bus-agent-check.py` succeeds; `bash -n
  tests/e2e/cli/cli-startup.sh scripts/tui-live-check.sh` succeeds; `cargo test -p aitm --test
  shutdown --no-run` compiles. The orchestrator (Terminal panel, built `aitm`) runs `python3
  tests/e2e/run.py audit` once after R3 and H1 are both in: the audit cells pass with the real
  writer on a per-launch file.
- **Do not touch:** any other e2e cell, any other test.
- **Done when:** the greps, syntax checks and the compile are quoted with their output and the
  candidate-spawn report is in the Coder's report.
- **[Amended: Amendment 2, chain R fix rounds] As built (`0ffd0d15`): nine files, not seven.** Two more
  sites that spawn the real binary were added as orchestrator amendments, one line each:
  `apps/web/scripts/live-env.mjs` (`AITM_AUDIT_LOG: process.env.AITM_AUDIT_LOG ?? 'off'` in the web live selftest's
  child environment) and `apps/mac/tools/selftest-live-embedded.sh` (the embedded-core run is launched with
  `AITM_AUDIT_LOG="${AITM_AUDIT_LOG:-off}"`). The AC38 grep therefore covers nine files: the seven above plus
  these two; `python3 -I -m py_compile` still covers the four Python files, and `bash -n` the shell scripts. The
  commit is 9 files, 12 insertions and 4 deletions.

### Task C1: whole-branch fences and mutation checks

- **Chain / worktree:** W, the plan worktree, after every other task, after M1 and after the final rebase.
- **Satisfies:** AC40, AC41, AC42, AC43, AC64 (and repeats AC38, AC39, AC62, AC65)
- **Depends on:** all
- **Files:** none permanently. Mutations are temporary, in the files each names.
- **Part A, fences and checks** (commands by the orchestrator in the Terminal panel; `<base>` is
  the merge-base after the rebase). Literal expected output: **[Amended: Amendment 2, chain R fix rounds:
  `<base>` is `git merge-base HEAD origin/main`, which is `f2c9d70b` after the merge of v0.5.8 (no rebase
  happened); recompute it, and every number below, after any further merge.]** **[Amended: Amendment 3,
  whole-branch panel: re-measured at `e28a310e` against `f2c9d70b`, all as below: the AC40 fence prints `6` `+` and
  `24` `-` lines; `grep -c '^@@'` on `server.rs` is `7` (three executable, four comment: D1 has four, not three); the
  chain R range alone is three hunks; `git diff --name-status <base>..HEAD | grep '^M' | grep tests/` prints six
  lines (three tests, three harness files); the no-diff checks on `redact.rs`, the scanner, findings, `aitm-poc`,
  `web/`, `wire.rs`, `tui.rs` and the Cargo files print nothing, and no `ConnCtx` or `AuditEntry` field changed;
  the hygiene greps print nothing except two `info!(` lines in `audit_log.rs`; and no `scrub_text` appears in
  `audit_log*` or `redact_args.rs`. `origin/main` is merged again before the PR: re-measure then, since the base may
  move. The expected values are the same if that merge touches none of the lines a fence reads.]**
  - `git diff --stat <base>..HEAD` names only: `crates/aitm-core/src/{audit,config,lib,redact_strict}.rs`,
    `crates/aitm-core/tests/{durable_audit_hook,redact_strict}.rs`,
    `crates/aitm-mcp/src/{server,lib,redact_args}.rs`, `crates/aitm-mcp/tests/audit_redaction.rs`,
    `crates/aitm/src/{audit_log,config_file,env,lib,main}.rs`,
    `crates/aitm/src/audit_log/{registry,pipeline,jsonscan}.rs`,
    `crates/aitm/tests/{audit_log_config,audit_log_wiring,audit_log_binary,audit_log_redaction,shutdown}.rs`,
    `crates/aitm-plugins/src/agent.rs`, `crates/aitm-plugins/tests/agent_status_durable.rs`,
    `crates/aitm-ca/src/audit.rs`, `README.md`, `INSTALL.md`, `apps/web/scripts/live-env.mjs`,
    `apps/mac/tools/selftest-live-embedded.sh` **[Amended: Amendment 2, chain R fix rounds: the two
    orchestrator additions of H1]**, `tests/e2e/aitm_e2e/core.py`,
    `tests/e2e/run.py`, `tests/e2e/cli/cli-startup.sh`, `tests/e2e/start/test_bus_endpoint_file.py`,
    `tests/e2e/audit/test_audit_log.py`, `scripts/bus-agent-check.py`, `scripts/tui-live-check.sh`,
    and the spec and plan.
  - AC40 (relaxed by Amendment 1): `git diff -U0 <base>..HEAD -- crates/aitm-mcp/src
    crates/aitm/src/web ':!crates/aitm-mcp/src/redact_args.rs' | grep '^[+-]' | grep -v
    '^+++\|^---' | grep -v '^[+-][[:space:]]*//'` prints only: the pure deletion of the bodies of
    `redact_value` and the local `is_secret_key` in `server.rs`, one `-`/`+` pair for the reason
    line (`scrub_text` to `scrub_strict`), `+use crate::redact_args::redact_value;`, and `+pub mod
    redact_args;`. The same command piped through `grep '^+'` prints exactly those three `+` lines
    (`... | grep '^+' | wc -l` prints `3`). Nothing under `crates/aitm/src/web`. **[Amended: Amendment 2,
    chain R fix rounds: the numbers on the whole branch, measured against `f2c9d70b`: the reason statement is
    four lines (`scrub_strict_bounded(reason, crate::redact_args::REASON_EXAMINE_BYTES)`), so
    `... | grep -c '^+'` prints `6` (`+pub mod redact_args;`, `+use crate::redact_args::redact_value;`, and the four
    reason lines) and `... | grep -c '^-'` prints `24` (the replaced reason line and the deleted bodies of
    `redact_value` and `is_secret_key`, blank lines included). Do not assert on a count of `@@` hunks on the whole
    branch: D1's comment-only hunks add to them (the chain R range alone is exactly three `server.rs` hunks).
    The first text above ("3 `+` lines") is superseded.]**
  - `git diff --stat <base>..HEAD -- crates/aitm-core/src/redact.rs crates/aitm-plugin-scanner
    crates/aitm-findings crates/aitm-poc crates/aitm/src/web crates/aitm/src/wire.rs
    crates/aitm/src/tui.rs` prints nothing (AC40, AC62); `git diff <base>..HEAD -- Cargo.lock
    crates/aitm/Cargo.toml crates/aitm-mcp/Cargo.toml crates/aitm-core/Cargo.toml
    crates/aitm-plugins/Cargo.toml` is empty.
  - `git diff -U0 <base>..HEAD -- crates/aitm-mcp/src/server.rs | grep -E "^[-+] +pub
    (role|client_label|conn_id|out):"` prints nothing; `git diff -U0 <base>..HEAD --
    crates/aitm-core/src/audit.rs | grep -E "^[-+] +pub
    (at|origin|client_label|connection_id|command|args_summary|result):"` prints nothing.
  - AC41: `git diff --name-status <base>..HEAD | grep '^M' | grep tests/` lists only
    `crates/aitm/tests/shutdown.rs`, `tests/e2e/start/test_bus_endpoint_file.py` (one environment
    line, orchestrator decision, see Ambiguity 20) and `tests/e2e/audit/test_audit_log.py` (the one
    AC59 assertion: `git diff <base>..HEAD -- tests/e2e/audit/test_audit_log.py` is one hunk that
    names `X-Audit-Marker`); every other test file is `A`. **[Amended: Amendment 2, chain R fix rounds: the
    command prints six `M` lines at `f9c1f5b4`, because `grep tests/` also matches three harness files that are
    not tests: `tests/e2e/aitm_e2e/core.py`, `tests/e2e/run.py` and `tests/e2e/cli/cli-startup.sh` (H1's one-line
    edits). The three test files above are the ones AC41 allows; the three harness files are AC38's.]** `git diff <base>..HEAD --
    crates/aitm-core/src/audit.rs | grep "^[-+].*#\[test\]"` prints nothing. These pass unmodified:
    `cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free` (prints `test
    result: ok` twice), `cargo test -p aitm-mcp --test mcp the_durable_audit_sink_keeps_every_entry`,
    `cargo test -p aitm --test audit_durable_connection_id`, `cargo test -p aitm-ca --test audit`.
  - AC62: `cargo test -p aitm-mcp --test mcp audit_redacts`, `cargo test -p aitm-mcp --test
    audit_integrity`, `cargo test -p aitm-core --lib redact::`, `cargo test -p aitm-poc`, `cargo test
    -p aitm-plugin-scanner`, `cargo test -p aitm-findings` print `test result: ok`.
  - Hygiene: `grep -rn "allow(dead_code)" crates/aitm/src/audit_log.rs crates/aitm/src/audit_log/`,
    `grep -rn "unsafe" crates/aitm/src/audit_log.rs crates/aitm/src/audit_log/
    crates/aitm-core/src/audit.rs crates/aitm-core/src/redact_strict.rs
    crates/aitm-mcp/src/redact_args.rs`, `grep -rn "println!\|eprintln!" crates/aitm/src/audit_log.rs
    crates/aitm/src/audit_log/` and `grep -rn "Display for" crates/aitm/src/audit_log.rs
    crates/aitm/src/audit_log/` each print nothing; `grep -rn "info!(" crates/aitm/src/audit_log.rs
    crates/aitm/src/audit_log/` shows at most the startup line and the recovery line (a reviewer
    confirms neither is on a per-entry success path); `grep -rn "scrub_text" crates/aitm/src/audit_log.rs
    crates/aitm/src/audit_log/ crates/aitm-mcp/src/redact_args.rs` prints nothing (no `scrub_text`
    over JSON text anywhere in the new code; `scrub_strict` calls `scrub_text` internally and lives in
    `aitm-core`).
  - AC38, AC39 and AC65 greps from Tasks H1, W1, D1 and D2 print the same values.
  - AC42: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`, redirected
    to a log and gated on exit status `0` (socket tests included, run unsandboxed;
    `rhai_e2e::script_cannot_escape_or_exceed_scope` is the known flake, judged by whether this
    change touches Rhai: it does not). Then `python3 tests/e2e/run.py audit` (AC59, Terminal panel,
    a built `aitm`).
- **Part B, mutation checks (AC43 and AC64), run by a fresh Coder in the sandbox** (decision: the
  Tester may not touch source). Before the first mutation the Coder copies each file it will touch
  to `$TMPDIR/<name>.orig`. Each mutation is applied, the named test is run and its
  **assertion-level** failure quoted, then the file is restored from the copy and `diff <file>
  $TMPDIR/<name>.orig` prints nothing, and the named test is re-run green. The Coder runs no `git`.
  A mutation whose named test stays green is a finding, reported, not worked around.
  **[Amended: Amendment 3, whole-branch panel: the table has 54 rows. Three things the Coder must know. (1) Row 43
  (the tail `shutdown` in `main.rs`, and its `block_in_place` wrapper) is **expected to survive**: record it as
  an accepted survivor, not a finding. (2) Row 13, and any mutation of the writer's own text passes, turns red the
  writer and pipeline tests and the hand-built corpus row R25 only, not corpus rows R1 to R39 (Ambiguity 46). (3)
  Rows 44 to 54 are new, and rows 35 and 37 are re-worded, because the redaction rounds fail closed: setting
  `SETTLE_ROUNDS` to 0 is no longer a targeted mutation. Fix `Y3` is committed (`e28a310e`), so mutations of
  `redact_strict.rs` run against a clean tree; row 54 is its mutation.]**

  | # | Mutation | Must turn red |
  |---|---|---|
  | 1 | `try_send` replaced by a blocking `send` in `record` | `a_stalled_disk_never_blocks_the_call_path` (its `within` guard fails; it must not hang the run) |
  | 2 | the gap bookkeeping records the `at` of the entry already queued instead of the refused one (Ambiguity 6) | `a_stalled_disk_never_blocks_the_call_path` (`from`/`to`) |
  | 3 | remove the DEL and C1 replacement in the control step | `a_hostile_entry_is_sanitised_before_it_is_written` |
  | 4 | remove the `0600` create mode, then separately the `set_permissions` tighten | `a_fresh_start_creates_private_files`, `hostile_paths_are_refused_without_hanging` (the `0644` row) |
  | 5 | `append(true)` replaced by `truncate(true)` (with `write(true)`) | `restart_appends_never_truncates`, `preflight_appends_a_start_marker_and_repairs_a_torn_tail` |
  | 6 | call `sink.record` while the ring's guard is still held | `the_ring_hook_is_set_once_and_lock_free` (its 5 s check) |
  | 7 | write the triggering line before rotating, then separately drop it | `rotation_loses_no_line`, `a_failed_rotation_never_drops_the_line` |
  | 8 | in `rotate`, delete the newest rotated file and keep the oldest | `retention_deletes_only_the_oldest_rotated_file` |
  | 9 | replace the `Close` message by an atomic flag checked before each `recv` | `shutdown_flushes_every_queued_entry` |
  | 10 | in `start_core`, remove `ring.attach_durable(..)` (Ambiguity 6) | `a_real_server_call_reaches_the_file_with_its_connection_id`, `every_server_this_binary_builds_is_audited` |
  | 11 | in `stream_for`, send every evidence entry to `Control` | `entries_are_routed_by_lane_and_trust`, `a_flooded_stream_cannot_starve_another` |
  | 12 | `FsBackend::recheck` always returns `Same` | `a_removed_file_or_directory_is_recreated_with_a_start_marker`, `a_file_swapped_for_a_symlink_is_not_written_through` |
  | 13 | `render_line` skips every pass and calls `entry_to_jsonl` directly (sanitising pass removed) | `a_hostile_entry_is_sanitised_before_it_is_written` (**[Amended: Amendment 3, whole-branch panel:** this turns red the writer and pipeline tests and the hand-built corpus row R25, **not** corpus rows R1 to R39, which a real server call has already made clean at the source; see Ambiguity 46**]**) |
  | 14 | remove rule D | `rules_s_and_d_redact_header_collections_and_siblings`; corpus rows R7, R11, R15, R17 |
  | 15 | remove rule S | the same AC45 test; corpus rows R9, R10, R12 to R14, R53, R54 |
  | 16 | remove P2 | `scrub_strict_masks_every_pass_and_keeps_the_benign`; corpus rows R19 to R22, R25 to R27 |
  | 17 | remove P3 | AC44 test; corpus row R38 |
  | 18 | remove P4 | AC44 test; corpus rows R36, R37 |
  | 19 | remove one P5 shape at a time (all ten: JWT, PEM, AWS, GitHub, GitLab, Slack, Stripe, `sk-`, Google, and `github_pat_` as its own) | AC44 test and that shape's row (R40 to R49) |
  | 20 | remove the extra vocabulary (P6 and `is_secret_key_strict`'s extras) | AC44 test, `the_strict_vocabulary_is_audit_only`; corpus rows R29 to R33, R39, R50, R51 |
  | 21 | substring-mask every registered length (remove the tiers) | `registry_tiers` |
  | 22 | remove the percent forms, then separately the JSON form | `registry_masks_every_encoding`; corpus rows R67, R68 |
  | 23 | remove the trailing-fragment mask | `cut_secrets_and_the_tolerant_scan` (a); corpus row R71 |
  | 24 | take the registry snapshot once at writer start (no late registration) | `a_late_registration_reaches_a_running_writer`, `the_operator_bridge_token_is_registered_when_minted`, and (orchestrator, Terminal panel) `the_generated_operator_bridge_token_never_reaches_disk` |
  | 25 | register only from `cfg` (drop the argument and the environment) | `start_registers_every_configured_source` |
  | 26 | run `scrub_text` over the JSON text of `args` in the writer | `an_honest_entry_is_written_unchanged` (the two AC47 shapes) |
  | 27 | remove the tolerant scan (fall straight to plain text) | `cut_secrets_and_the_tolerant_scan` (b); corpus row R25 |
  | 28 | remove parse-first | `cut_secrets_and_the_tolerant_scan` (d) |
  | 29 | revert the reason line from `scrub_strict` to `scrub_text` | `the_reason_is_scrubbed_strictly_at_the_source` |
  | 30 | remove the bound in `redact_value` | the in-module bound tests and `redaction_output_is_bounded_in_size` (and `redaction_work_is_bounded` if the unbounded work exceeds its 20 s **[Amended: Amendment 2, chain R fix rounds: was 5 s]**) |
  | 31 | revert the `server.rs` hunk to the old `redact_value` (the pre-R3 file) | `rules_s_and_d_redact_header_collections_and_siblings` |
  | 32 **[Amended: Amendment 2, chain R fix rounds; rows 32 to 43 are new]** | remove the PEM and PGP pre-pass from the round in `redact_strict.rs` | `a_private_key_block_is_masked_whole_whatever_precedes_it` and the PEM rows of `scrub_strict_masks_every_pass_and_keeps_the_benign` |
  | 33 | remove the frames pre-pass, one frame at a time (Debug wrapper, escaped quotes, `[..]`/`{..}` group, XML element, multipart field, CLI flag, curl `-u`) | the frame's own test: `rust_debug_wrappers_around_a_secret_are_masked_whole`, `escaped_quote_frames_are_masked_to_their_matching_closer`, `bracketed_values_under_a_secret_key_are_masked_whole`, `xml_elements_with_a_secret_name_are_masked`, `multipart_fields_with_a_secret_name_are_masked`, `cli_flags_with_a_secret_name_are_masked`, `curl_user_flags_mask_the_password_part` |
  | 34 | remove the camelCase reading from `is_secret_key_strict` | `camel_case_keys_are_secret_keys_in_text`, `is_secret_key_strict_vocabulary` |
  | 35 | set `MAX_ROUNDS` to 1 (one round, no repetition) | `rounds_repeat_until_the_output_equals_the_input`, `the_rounds_are_bounded`, `shapes_found_by_fuzzing_are_fixed_points` **[Amended: Amendment 3, whole-branch panel: `the_rounds_are_bounded` no longer exists (renamed and split); with `MAX_ROUNDS` 8 and fail closed the tests that turn red are `rounds_repeat_until_the_output_equals_the_input`, `a_shape_that_needed_seven_rounds_is_masked_not_replaced`, `a_shape_that_needs_seven_calls_settles_within_the_cap` and `shapes_found_by_fuzzing_are_fixed_points`; the mutation is "set `MAX_ROUNDS` to 1"]** |
  | 36 | the reason statement in `record_audit` calls `scrub_strict` (unbounded) instead of `scrub_strict_bounded(.., REASON_EXAMINE_BYTES)` | `the_reason_is_bounded_before_the_text_pass` (the 12000-byte block keeps its tail) |
  | 37 | `settle` returns its last round instead of failing closed **[Amended: Amendment 3, whole-branch panel: the Amendment 2 row said "`SETTLE_ROUNDS` set to 0"; with fail closed that mutation now replaces every value by `"<redacted>"` and turns almost everything red, so it is no longer a targeted check]** | `settle_stops_at_a_fixed_point_or_fails_closed_after_three_rounds` (renamed from `settle_stops_at_a_fixed_point_or_after_three_rounds`), `one_walk_settles_the_known_divergences` |
  | 38 | narrow `is_header_collection_key` back to the seven exact names | `header_collection_context_is_default_deny`, `keys_naming_headers_or_trailers_are_header_collections` |
  | 39 | remove the bracket-notation key reading from P6 | `bracket_notation_form_keys_are_pairs` |
  | 40 | remove the `MAX_DEPTH` guard in `redact_value` | `hostile_nesting_is_cut_at_the_depth_bound` |
  | 41 | make `is_benign_env_value` always false (register every secret-named variable's value) | `the_environment_rule_skips_values_that_are_not_secrets`, `a_flag_like_environment_value_never_masks_ordinary_text` |
  | 42 | remove the trailing-`…` set-aside in `scan_json_text` (no `strip_suffix(CUT_MARK)`) | `a_text_cut_outside_a_literal_is_still_scanned`, `a_text_cut_anywhere_by_the_cap_comes_back_unchanged` |
  | 43 | remove the `handle.shutdown(..)` call from the tail of `main.rs` | **None: expected to survive.** No test observes the call (spec Residual risks 24); report the survivor, do not work around it, and do not count it as a failed check **[Amended: Amendment 3, whole-branch panel: the call is wrapped in `tokio::task::block_in_place`; removing the wrapper alone is as unobservable, so it survives too]** |
  | 44 **[Amended: Amendment 3, whole-branch panel; rows 44 to 54 are new]** | `converge` in `redact_strict.rs` returns the last round's output instead of `[redacted]` when no round settles | `a_text_that_never_settles_is_replaced_whole_after_max_rounds` (module), `a_text_that_does_not_settle_is_replaced_whole` (`tests/redact_strict.rs`), `the_replacement_is_itself_a_fixed_point` |
  | 45 | make `past_ceiling` always false (no wedged ceiling) | `a_wedged_rotation_holds_the_file_to_twice_its_cap` (the file grows past 4096 bytes) |
  | 46 | do not feed `rotation_wedged` into `status().degraded` | `a_wedged_rotation_holds_the_file_to_twice_its_cap`, `a_failed_rotation_never_drops_the_line` (both assert `degraded: true`) |
  | 47 | compare the CA log by its spelled path (drop `resolved`) in `ca_log_collision` | `a_ca_log_that_is_a_stream_file_in_another_spelling_is_refused` (the `..`, link and not-there rows) |
  | 48 | make `ca_log_collision` skip the rotated names `F.1` to `F.keep` | `a_ca_log_that_is_a_stream_file_in_another_spelling_is_refused` (the rotated-name rows) |
  | 49 | print the value in the `mcp.audit_log` error (replace `yaml_kind(..)`/the kind text by `{v:?}`) or in the `AITM_AUDIT_LOG` warning (`{raw:?}`), separately | `a_value_that_is_not_a_setting_is_never_echoed` |
  | 50 | make `glued_line_escape` always false (P2 reads only a real line break) | `a_header_after_an_escaped_line_break_is_masked_to_the_end_of_its_line`, `a_line_escape_glued_to_a_name_run_is_a_backslash_and_n_r_or_t` |
  | 51 | make `key_start_after_escape` return `start` (the frames pre-pass and P6 ignore a glued escape) | `a_pair_after_an_escaped_line_break_is_masked_whatever_its_key`, `a_key_run_starts_after_a_glued_escape_letter` |
  | 52 | store the registry's JSON forms at depth 1 only (`JSON_DEPTHS` = 1) | `a_secret_is_masked_at_every_escaping_depth`, `nested_json_that_holds_a_registered_secret_is_masked_end_to_end`, `the_secret_91_constants_are_the_forms_they_name` |
  | 53 | make the fragment mask append the mask without cutting the text before it | `a_fragment_mask_at_the_cap_edge_leaves_args_within_its_cap`, `a_fragment_mask_at_the_cap_edge_leaves_every_field_within_its_cap`, and the corpus test `a_masked_short_fragment_keeps_args_within_the_cap` |
  | 54 | make `is_escape_letter` false at P5's left boundary (a shape after a glued escape is not read; fix Y3) | `a_credential_shape_after_an_escaped_line_break_is_masked`, `every_entry_of_the_shape_table_is_found_after_an_escaped_break`, `the_letter_of_an_escaped_break_is_n_r_or_t_after_a_backslash` |

  Mutations 14 to 20 and 29 to 31 edit chain R's files, which are on the plan branch after M1; the
  Coder works in the plan worktree. **[Amended: Amendment 2, chain R fix rounds: mutations 32 to 40 edit
  chain R's files too, 41 and 42 the writer's, and 43 `main.rs`; 43 is the one expected survivor.]** The report holds every red output, every restored green output
  and every empty `diff`.
- **Done when:** every Part A check is quoted with its output, every Part B mutation has its red,
  green and empty diff, and the orchestrator has confirmed `git status` shows no stray change.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
