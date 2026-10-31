# Audit ring integrity implementation plan

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-10-30-audit-ring-integrity-design.md`
**Branch / worktree:** `claude/competent-cori-43f38a` in
`/Users/matt/Security/aitmproxy/.claude/worktrees/competent-cori-43f38a` (the session
worktree is the plan worktree; the spec and this plan were authored on it, cut from
`main` at `bd0f9b7`). Base SHA for every diff and Tester/panel dispatch: `bd0f9b7`
until the pre-panel rebase onto `main`, then the new merge-base.

## Overview

Eleven tasks: two independent chains, two leaves that need only Task 4, a socket
test, and a final task. **Chain A (redaction, `aitm-core/src/redact.rs`, then the PoC
builder):** Task 1 (`is_secret_key` vocabulary), Task 2 (quote-aware `scrub_text` pair
pass), Task 3 (builder delegates). **Chain B (ring and labels):** Task 4 (label
sanitiser, caps, constants), Task 5 (two lanes, fair share, source table), Task 6
(`record_audit` lane routing and the new server-level test file), Task 7 (label
consumption helper, reason cap, redaction at the server). **Leaves:** Task 8
(`transport.rs` capture) and Task 9 (`bridge.rs` helper) need only Task 4. Task 10
(socket test, Terminal panel) needs Tasks 7 and 9. Task 11 (docs, mutation checks, final
verification) is last.

### Order and independence, stated once

| Task | Depends on | Files | Can run beside |
|---|---|---|---|
| 1 | none | `crates/aitm-core/src/redact.rs` | 4, 5, 6, 7, 8, 9 |
| 2 | 1 | `crates/aitm-core/src/redact.rs` | 4, 5, 6, 8, 9 |
| 3 | 2 | `crates/aitm-poc/src/builder.rs` | 4 to 9 |
| 4 | none | `crates/aitm-core/src/audit.rs`, `crates/aitm-core/src/lib.rs` | 1, 2, 3 |
| 5 | 4 | `crates/aitm-core/src/audit.rs`, `crates/aitm-core/src/lib.rs` | 1, 2, 3, 8, 9 |
| 6 | 5 | `crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/tests/audit_integrity.rs` (create) | 1, 2, 3, 8, 9 |
| 7 | 2, 4, 6 | `crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/tests/audit_integrity.rs` | 3, 8, 9 |
| 8 | 4 | `crates/aitm-mcp/src/transport.rs` | 1, 2, 3, 5, 6, 7, 9 |
| 9 | 4 | `crates/aitm/src/web/bridge.rs` | 1, 2, 3, 5, 6, 7, 8 |
| 10 | 7, 9 | `crates/aitm/tests/web_bus_audit_label.rs` (create) | 11 (docs part) |
| 11 | all | `crates/aitm-plugins/src/agent.rs` | none |

Two writers never share a file: Tasks 1/2 share `redact.rs`, 4/5 share `audit.rs` and
`lib.rs`, 6/7 share `server.rs` and `audit_integrity.rs`, so each pair is sequential.
The default is to run chain A and chain B in parallel child sessions (each on a branch
cut from the plan branch, merged back when its panel review passes), with Tasks 8 and 9
fanned out after Task 4. Run strictly sequentially in numeric order if only one
worktree is available; every order that respects the Depends-on column is valid, and
every task leaves the workspace compiling and green.

### Where each command runs (read this before dispatching)

- **Bash sandbox (Coder and Tester sub-agents).** `cargo build`, `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, and every test that binds no socket.
  `cargo` works offline once dependencies are fetched; if it cannot resolve
  dependencies, stop and ask the orchestrator to run `cargo fetch` in the Terminal
  panel, and do not report a result you did not get.
- **Terminal panel (orchestrator only).** Every `git` command, the one socket test
  (Task 10), and the final full `cargo test`. A Coder or Tester that sees a test fail
  only because the sandbox refuses a loopback bind reports "NOT RUN (socket)", never a
  pass or a fail; the orchestrator supplies the output. Do not use a `#`-leading word in
  a commit message (the terminal hook refuses it); write "PR 145", not the hash form.
- **Coders do not commit.** The sandbox cannot run `git` writes, so this plan overrides
  step 5 of `coder.md`: the Coder reports the files it changed and the orchestrator
  commits in the Terminal panel after the task's Tester passes. Commit messages name the
  plan and task. Wherever a task says "`git diff --stat` shows only X", the Coder lists
  the files it changed and the orchestrator confirms with `git diff --stat` in the
  Terminal panel.
- **Two-step red for tasks that add API.** A test that names a symbol that does not
  exist yet fails to compile; that is a legitimate first red (quote the compiler line
  naming the missing item). Then add the signature with the old behaviour (for example
  `append_in` that ignores its lane) so the test compiles, and quote the assertion-level
  failure. Both outputs go in the report. "It failed as expected" is not a report.
- **Evidence, verbatim.** Every red and green run is the literal command and the literal
  output lines named in the task.
- **Stale target directories.** If `CARGO_TARGET_DIR` is shared with other worktrees,
  `touch` the edited sources before a red or green run so cargo does not reuse a stale
  artifact. A red run on a stale binary is worthless.
- **Gate exit status, not grep.** For the full run, redirect `cargo test` to a log and
  gate on its exit status. `rhai_e2e::script_cannot_escape_or_exceed_scope` is a known
  non-deterministic flake: judge it by whether the change touches Rhai (this one does
  not), not by an isolated rerun.
- **Code constraints for every task.** `trust_gate_scan.rs` bans `==`, `!=`,
  `matches!`, and `if let` against `Frontend::Mcp` in any `crates/*/src` file including
  `#[cfg(test)]` modules: compare origins through `aitm_core::origin_label(..)`. Do not
  edit `origin_label` (`classifier_wildcard_free.rs` reads its body). In new tests, build
  a labelled connection as `ConnCtx::new(role)` and then assign the `pub client_label`
  field; do not write a `ConnCtx { .. }` literal (a sibling adding a field would break
  it). No `unsafe`, no new dependencies, no code in doc comments longer than a signature.

### Symbols the tasks use (confirmed by reading on `bd0f9b7`)

- `aitm_core::audit`: `AuditEntry { at, origin, client_label, command, args_summary,
  result }`, `AuditResult::{Ok, Error(String)}`, `AuditSink::append(&self, AuditEntry)`,
  `AuditRing::{new, recent, count_since, len, is_empty}` and `Default`,
  `origin_label(Frontend) -> &'static str`, `DEFAULT_AUDIT_CAPACITY` (4096),
  `DEFAULT_ARGS_SUMMARY_CAP` (512). `aitm_core::Sensitivity::{Read, Write, Sensitive}`
  is `Copy + Eq` (`command.rs`). `aitm_core::redact::{is_secret_key, scrub_text}`.
- `aitm_core::Registry::command(&self, &str) -> Option<&Arc<dyn Command>>`;
  `Command::sensitivity(&self) -> Sensitivity`.
- `aitm_mcp::McpServer::{new, with_services, with_agent_state, with_audit_ring,
  handle_on(&self, &ConnCtx, &str) -> Option<String>, next_conn_id}`;
  `ConnCtx { role, client_label, conn_id, out }` (all `pub`), `ConnCtx::new(Frontend)`;
  `NotificationSink::new(usize)`. `record_audit` is the only production
  `AuditEntry` constructor (`server.rs`, about line 1605); `run_tool` sets
  `CommandHost::with_client_label` from `conn.client_label` (about line 1564).
- `transport.rs`: `client_label_from_initialize(message: &str) -> Option<String>` is
  private, has a `#[cfg(test)] mod tests`, and is called once, from `serve_lines`,
  where `conn.client_label` is set only while it is `None`. The HTTP transport
  (`http.rs`) builds `ConnCtx::new(Frontend::Mcp)` per request and captures no label.
  `bridge.rs` builds the one `ConnCtx` per authenticated connection (about line 252),
  never parses `clientInfo`, and has a `#[cfg(test)] mod tests` (about line 552).
- `aitm-plugins/src/agent.rs`: `agent.status` reads `AuditRing::count_since`;
  `agent.activity` reads `AuditRing::recent`; both descriptions are plain strings no
  other file pins (grep: only `agent.rs` contains them).
- `crates/aitm-poc/src/builder.rs`: `EXTRA_SECRET_KEY_SEGMENTS` and
  `SESSION_KEY_SUBSTRINGS` are used only inside `is_secret_poc_key`; the builder has no
  `#[cfg(test)]` module (its tests are `crates/aitm-poc/tests/builder.rs`).

**Claims traced by reading, not run.** That naively widening `scrub_text`'s regex would
break `reproduce::tests::scrub_embedded_handles_quotes_and_escapes` is a trace of the
code, not an experiment; Task 2's oracle run is the check, and if an oracle test fails
the Coder stops and reports rather than editing the test.

### AC coverage

| AC | Task | Test (exact name) |
|---|---|---|
| AC1 | 1 | `redact::tests::is_secret_key_covers_the_session_and_auth_family` |
| AC2 | 1 | `redact::tests::is_secret_key_leaves_lookalikes_alone` (guard) |
| AC3 | 2 | `redact::tests::scrub_text_masks_unframed_session_credentials` |
| AC4 | 2 | `redact::tests::scrub_text_leaves_lookalike_pairs_alone` (guard) |
| AC5 | 2 | `redact::tests::scrub_text_masks_quoted_values_whole` |
| AC6 | 2 | `redact::tests::scrub_text_sees_pairs_nested_in_a_non_secret_value` |
| AC7 | 2 | `redact::tests::scrub_text_does_not_mask_a_host_port` |
| AC8 | 2 | `redact::tests::scrub_text_and_is_secret_key_share_one_vocabulary` |
| AC9 | 2 | `redact::tests::scrub_text_survives_hostile_inputs` (guard) |
| AC10 | 2, 3 | oracle runs of the scanner, poc, findings, plugins, mcp suites (guard) |
| AC11 | 3 | grep count `0` plus `crates/aitm-poc/tests/builder.rs` (guard) |
| AC12 | 4 | `audit::tests::sanitize_client_label_bounds_a_hostile_label` |
| AC13 | 4 | `audit::tests::declared_client_label_rewrites_a_reserved_name` |
| AC14 | 8 | `transport::tests::client_label_from_initialize_is_bounded_and_unforgeable` |
| AC15 | 9 | `web::bridge::tests::bridge_conn_ctx_carries_the_server_minted_label` |
| AC16 | 7 | `a_hostile_label_is_bounded_in_the_ring_and_the_host` |
| AC17 | 5 | `audit::tests::lane_for_routes_only_successful_reads_to_routine` |
| AC18 | 5 | `audit::tests::recent_merges_both_lanes_oldest_first` |
| AC19 | 5 | `audit::tests::a_routine_flood_never_evicts_evidence` |
| AC20 | 5 | `audit::tests::a_lone_source_uses_the_whole_lane_then_evicts_its_own_oldest` (guard) |
| AC21 | 5 | `audit::tests::fair_share_protects_a_quiet_source_from_a_flooder` |
| AC22 | 5 | `audit::tests::fair_share_ties_evict_the_globally_oldest` (guard) |
| AC23 | 5 | `audit::tests::a_source_flood_of_distinct_labels_cannot_flush_a_tracked_source` |
| AC24 | 6 | `a_read_burst_cannot_evict_a_refused_sensitive_call` |
| AC25 | 6 | `a_refused_flood_cannot_evict_another_sources_entry` (guard after Task 5) |
| AC26 | 6 | `routing_follows_sensitivity_and_outcome` |
| AC27 | 6 | `actions_last_minute_counts_both_lanes` (guard) |
| AC28 | 7 | `an_oversized_error_reason_is_capped_in_the_ring` |
| AC29 | 7 | `args_summary_hides_unframed_credentials` |
| AC30 | 10 | `bridge_calls_are_attributed_to_web_bridge` (socket) |
| AC31 | all | existing suites unmodified (guard) |
| AC32 | 11 | `git diff` checks |
| AC33 | 2, 4, 5, 11 | review-checked doc updates |
| AC34 | 11 | mutation runs |
| AC35 | 11 | the Rust gate |

Tests in `audit_integrity.rs` are run with `cargo test -p aitm-mcp --test
audit_integrity`.

### Calls made in this plan (Architect's calls, for Matt to correct)

1. Server-level tests go in a **new** file, `crates/aitm-mcp/tests/audit_integrity.rs`,
   not in `mcp.rs` (a 4000-line file sibling sessions edit); it duplicates the few small
   helpers it needs (house style).
2. Redaction is split into two tasks (vocabulary, then the pair pass) so each fits one
   sitting and the vocabulary is verifiable alone.
3. AC25 is green on arrival at Task 6 (Task 5's fair share already protects another
   source); it is kept as the server-level integration guard, and the unit-level AC21
   is its genuine red.
4. The mutation checks (AC34) are done by a Coder at Task 11, in the sandbox, with the
   mutation reverted by hand and proven reverted by a saved `git diff`; a Tester may not
   touch source.
5. The scanner is not edited, including its now-stale doc comments (`reproduce.rs` near
   the `scrub_embedded` doc, `discover.rs` near `EXTRA_SECRET_NEEDLES`); the
   "scanner vocabulary consolidation" follow-up owns them.

## Tasks

### Task 1: `is_secret_key` carries the session and auth vocabulary

- **Satisfies:** AC1, AC2, part of AC33
- **Depends on:** none
- **Files:** `crates/aitm-core/src/redact.rs` (modify)
- **Change:** In `SECRET_KEY_NEEDLES` add `"sessionid"` and `"phpsessid"`. Add `const
  SECRET_KEY_SEGMENTS: &[&str] = &["sid", "jwt", "csrf", "session", "auth"];`.
  `pub fn is_secret_key(key: &str) -> bool` keeps its signature and becomes: true when
  the ASCII-lowercased key contains any needle, or when any segment of the lowercased
  key (split on every character that is not an ASCII alphanumeric) equals a
  `SECRET_KEY_SEGMENTS` entry. Rewrite the doc comments of the two consts and the
  function to say so (segments are whole-word so `author`, `authority`, `inside`,
  `side` are not hit; the substring list is unchanged except the two additions). Do not
  touch `patterns()` or `scrub_text` in this task.
- **Test (written first):** in `redact.rs` `mod tests`, add
  `is_secret_key_covers_the_session_and_auth_family`: for each of `sid`, `SID`, `jwt`,
  `csrf`, `_csrf`, `session`, `auth`, `x-auth`, `connect.sid`, `sessionId`,
  `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`, assert `is_secret_key(key)` with the
  message "`{key}` should be a secret key". Add `is_secret_key_leaves_lookalikes_alone`:
  assert `!is_secret_key(key)` for `author`, `authority`, `authenticated`, `inside`,
  `side`, `sidebar`, `subsidiary`, `sessions`, `path`, `host`, `body`, `note`,
  `method`.
- **Red:** `cargo test -p aitm-core --lib redact::tests::is_secret_key_covers_the_session_and_auth_family`
  fails with a panic whose message is "`sid` should be a secret key". The second test
  passes both before and after (a guard).
- **Green:** the same command prints `test result: ok. 1 passed`; then
  `cargo test -p aitm-core --lib redact::` prints `test result: ok` with the six
  original tests (`secret_keys_matched_as_substring_case_insensitively`,
  `scrubs_token_in_query_string`, `scrubs_credential_in_form_body`,
  `scrubs_secret_in_json_body`, `scrubs_authorization_and_bearer_in_free_text`,
  `leaves_innocuous_text_untouched`) still passing, unedited.
- **Blast-radius runs (all must print `test result: ok`, 0 failed):**
  `cargo test -p aitm-core`, `cargo test -p aitm-poc`, `cargo test -p aitm-findings`,
  `cargo test -p aitm-plugin-scanner`, `cargo test -p aitm-mcp --test mcp audit`.
  (Widening the key predicate is a superset for the scanner's `is_secret_name`.)
- **Done when:** the red and green runs are quoted, the blast-radius runs pass, and
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings` is clean.

### Task 2: `scrub_text`'s pair pass is a quote-aware scan over `is_secret_key`

- **Satisfies:** AC3, AC4, AC5, AC6, AC7, AC8, AC9, AC10, part of AC33
- **Depends on:** Task 1
- **Files:** `crates/aitm-core/src/redact.rs` (modify)
- **Change:** Remove the third entry (the `key=value` regex) from `patterns()`, leaving
  the `Authorization` and `Bearer` passes. Add private functions, signatures only here:
  `fn mask_secret_pairs(text: &str) -> String`, `fn is_key_byte(b: u8) -> bool`
  (ASCII alphanumeric, `_`, `.`, `-`, or any byte at or above `0x80`),
  `fn ends_value(b: u8) -> bool` (ASCII whitespace, `&`, `;`, `,`, `"`, `'`, `}`),
  `fn closing_quote(bytes: &[u8], from: usize, quote: u8) -> Option<usize>` (a backslash
  skips the next byte), and `fn is_host_port(...)` for the exemption. `pub fn
  scrub_text(text: &str) -> String` keeps its signature: run the two regex passes, then
  `mask_secret_pairs`. The scan follows the spec's Design 4: key run, optional closing
  quote, blanks, `=` or `:`, blanks, optional opening quote, value; mask the value only
  when `is_secret_key(run)` and the value is non-empty; resume after the **key run** when
  the key is not secret and after the **value** when it is masked; quoted value to its
  matching unescaped quote, else to the first `ends_value` byte; the host:port
  exemption (separator `:`, unquoted key run containing a `.`, 1 to 5 ASCII digits
  immediately after the colon, then `/`, `?`, `#`, whitespace, a pair delimiter, or
  end). Rewrite the module doc and the `scrub_text` doc to describe the single
  vocabulary, the quote rule, and the exemption (no code, no list copies). Do not
  introduce a second vocabulary constant.
- **Tests (written first)**, in `redact.rs` `mod tests`, with these literal values:
  - `scrub_text_masks_unframed_session_credentials`: `sid=abc123` to `sid=[redacted]`;
    `/cb?next=/home&sid=S1&page=2` to `/cb?next=/home&sid=[redacted]&page=2`;
    `session=abc; theme=dark` to `session=[redacted]; theme=dark`; `auth=xyz` to
    `auth=[redacted]`; `jwt=eyJa.b.c` to `jwt=[redacted]`; `csrf=c1` to `csrf=[redacted]`;
    `PHPSESSID=p1` to `PHPSESSID=[redacted]`; `connect.sid=s%3Aabc` to
    `connect.sid=[redacted]`; `x-auth: v1` to `x-auth: [redacted]`; `{"sid":"S1","n":1}`
    to `{"sid":"[redacted]","n":1}`.
  - `scrub_text_leaves_lookalike_pairs_alone`: each unchanged byte for byte: `author=bob`,
    `authority=example.com`, `inside=1`, `side=left`, `sidebar=1`, `authenticated=true`,
    `subsidiary=acme`, `page=2&q=hello`, `sid=&x=1`.
  - `scrub_text_masks_quoted_values_whole`: `{"password":"hunter 2"}` to
    `{"password":"[redacted]"}`; `{"sid":"a\"b c","n":1}` (a raw string in the test) to
    `{"sid":"[redacted]","n":1}`; `{'jwt' : 'a b','n':1}` to `{'jwt' : '[redacted]','n':1}`;
    `sid="abc&x=1` to `sid="[redacted]&x=1`; `{"sid":"","n":1}` unchanged.
  - `scrub_text_sees_pairs_nested_in_a_non_secret_value`: `next=/cb?sid=S1` to
    `next=/cb?sid=[redacted]`.
  - `scrub_text_does_not_mask_a_host_port`: unchanged `https://auth.example.com:8443/login`,
    `auth.example.com:8443`, `token.example.com:8443/x`; masked `sid:12345` to
    `sid:[redacted]`, `auth=1` to `auth=[redacted]`, `{"sid":12345}` to
    `{"sid":[redacted]}`.
  - `scrub_text_and_is_secret_key_share_one_vocabulary`: for every key in Task 1's two
    lists plus `authorization`, `token`, `password`, `passwd`, `pwd`, `secret`, `cookie`,
    `api_key`, `apikey`, `api-key`, `bearer`, `credential`, assert `is_secret_key(k)` equals
    `scrub_text(&format!("{k}=VALUE9")) != format!("{k}=VALUE9")`.
  - `scrub_text_survives_hostile_inputs`: `"sid=".repeat(1 << 20)` returns exactly
    `sid=[redacted]`; `"a".repeat(4 << 20)`, `"\"".repeat(2 << 20)`,
    `"\\".repeat(2 << 20)`, and `"sid='x ".repeat(150_000)` return without panicking.
  The six original tests listed under Task 1 are not edited and must pass.
- **Red:** `cargo test -p aitm-core --lib redact::tests` fails on: the first row of
  `scrub_text_masks_unframed_session_credentials` (got `sid=abc123`);
  `scrub_text_masks_quoted_values_whole` (the first row got
  `{"password":"[redacted] 2"}`); `scrub_text_sees_pairs_nested_in_a_non_secret_value`
  (got `next=/cb?sid=S1`); `scrub_text_does_not_mask_a_host_port` (the `token.` row got
  `token.example.com:[redacted]`); `scrub_text_and_is_secret_key_share_one_vocabulary`
  (key `sid`). `..._leaves_lookalike_pairs_alone` and `..._survives_hostile_inputs` pass
  before and after (guards).
- **Green, then the oracle (AC10).** `cargo test -p aitm-core --lib redact::tests` prints
  `test result: ok`. Then each of these prints `test result: ok` with 0 failed:
  `cargo test -p aitm-plugin-scanner` (including
  `reproduce::tests::scrub_embedded_handles_quotes_and_escapes` and
  `reproduce::tests::scrub_embedded_leaves_innocent_text_and_empty_values_alone`),
  `cargo test -p aitm-poc`, `cargo test -p aitm-findings`, `cargo test -p aitm-plugins`,
  `cargo test -p aitm-ca`, `cargo test -p aitm-mcp --test mcp audit`. If any oracle
  test fails, **stop and report** the failing test and the actual output; do not edit
  it (AC10 forbids it), and do not weaken the new pass.
- **Done when:** the red, green, and oracle runs are quoted, `git diff --stat` shows only
  `redact.rs`, and the fmt and clippy commands are clean.

### Task 3: the PoC builder delegates to the shared vocabulary

- **Satisfies:** AC11, AC10 (builder side), part of AC33
- **Depends on:** Task 2
- **Files:** `crates/aitm-poc/src/builder.rs` (modify)
- **Change:** Delete `const EXTRA_SECRET_KEY_SEGMENTS` and `const SESSION_KEY_SUBSTRINGS`
  and their doc comments. Keep `fn is_secret_poc_key(key: &str) -> bool` (three call
  sites) and make its body one call to `aitm_core::redact::is_secret_key(key)`; rewrite
  its doc comment to say the vocabulary lives in `aitm-core`. Correct the stale
  sentence near the top of `build_poc` ("The shared `aitm_core::redact::scrub_text` /
  `is_secret_key` are unchanged here") and the comment on `scrub_embedded_credentials`
  that says the shared set does not know `jwt`/`sid`: say the builder's per-part scrub
  is kept for placeholder handling, not for vocabulary. No other change.
- **Test:** no new test; the proof is equivalence. `crates/aitm-poc/tests/builder.rs`
  (unmodified) passes, and Task 1's tables contain every name the builder's old
  predicate matched or refused (`jwt`, `sid`, `csrf`, `auth`, `session`, `PHPSESSID`,
  `sessionid`, `inside`).
- **Check:** `grep -c "EXTRA_SECRET_KEY_SEGMENTS\|SESSION_KEY_SUBSTRINGS" crates/aitm-poc/src/builder.rs`
  prints exactly `0`. `cargo test -p aitm-poc` prints `test result: ok`, 0 failed.
- **Done when:** the grep prints `0`, the poc suite passes unmodified, `git diff --stat`
  shows only `builder.rs`, and fmt and clippy are clean.

### Task 4: client-label sanitiser, reserved guard, and entry-size constants

- **Satisfies:** AC12, AC13, part of AC33
- **Depends on:** none
- **Files:** `crates/aitm-core/src/audit.rs` (modify), `crates/aitm-core/src/lib.rs`
  (modify: the one `pub use audit::{..}` statement)
- **Change:** In `audit.rs` add, with doc comments: `pub const WEB_BRIDGE_CLIENT_LABEL:
  &str = "web-bridge";`, `pub const MAX_CLIENT_LABEL_CHARS: usize = 64;`, `pub const
  DEFAULT_RESULT_REASON_CAP: usize = 1024;`, private `const RESERVED_CLIENT_LABELS:
  &[&str] = &[WEB_BRIDGE_CLIENT_LABEL];` and private `const LABEL_SCAN_CHARS: usize =
  1024;`. Add `pub fn sanitize_client_label(raw: &str) -> Option<String>`: read at most
  the first `LABEL_SCAN_CHARS` chars; drop every `char::is_control` char and the chars
  U+200B..=U+200F, U+2028..=U+202E, U+2060..=U+2069, U+FEFF; `crate::redact::scrub_text`;
  trim; truncate to `MAX_CLIENT_LABEL_CHARS` chars; trim again; `None` if empty; must be
  idempotent and must not rewrite a reserved name. Add `pub fn declared_client_label(raw:
  &str) -> Option<String>`: `sanitize_client_label`, then if the result equals (trimmed,
  ASCII case-insensitive) an entry of `RESERVED_CLIENT_LABELS`, return
  `format!("{label} (declared)")`. Re-export the three constants and two functions from
  `lib.rs`. Do not edit `origin_label` or any existing item.
- **Tests (written first)**, in `audit.rs` `mod tests`:
  - `sanitize_client_label_bounds_a_hostile_label`: `"A".repeat(10 << 20)` to
    `Some("A".repeat(64))`; `"\u{0}".repeat(10 << 20)` to `None`; `"a\u{0}b\nc\u{202E}d"`
    to `Some("abcd")`; `"token=abc123"` to a `Some` whose text does not contain
    `abc123` and contains `[redacted]`; `""` and `"   "` to `None`; `"aitm-mac"` to
    `Some("aitm-mac")`; `"web-bridge"` to `Some("web-bridge")`; and for each input
    above `sanitize(sanitize(x))` equals `sanitize(x)`.
  - `declared_client_label_rewrites_a_reserved_name`: `"web-bridge"` to
    `Some("web-bridge (declared)")`; `"  WEB-BRIDGE "` to `Some("WEB-BRIDGE (declared)")`;
    `"aitm-mac"` to `Some("aitm-mac")`.
- **Red:** `cargo test -p aitm-core --lib audit::tests::sanitize_client_label` fails to
  compile with an error naming `sanitize_client_label` (first red); after adding both
  signatures returning `None`, the same command fails with an assertion whose left value
  is `None` and right value is `Some("AAAA...")` (second red).
- **Green:** `cargo test -p aitm-core --lib audit::` prints `test result: ok` with the
  three original ring tests still passing; `cargo test -p aitm-core` passes
  (`trust_gate_scan` and `classifier_wildcard_free` included).
- **Done when:** both red outputs and the green output are quoted, `git diff --stat`
  shows only `audit.rs` and `lib.rs`, and fmt and clippy are clean.

### Task 5: two lanes, fair-share eviction, bounded source table

- **Satisfies:** AC17, AC18, AC19, AC20, AC21, AC22, AC23, part of AC33
- **Depends on:** Task 4 (same files)
- **Files:** `crates/aitm-core/src/audit.rs` (modify), `crates/aitm-core/src/lib.rs`
  (modify: the same `pub use audit::{..}` statement)
- **Change:** In `audit.rs` add `pub const DEFAULT_ROUTINE_AUDIT_CAPACITY: usize =
  DEFAULT_AUDIT_CAPACITY / 2;`, `pub const MAX_AUDIT_SOURCES: usize = 32;`, `#[derive(Debug,
  Clone, Copy, PartialEq, Eq)] pub enum AuditLane { Evidence, Routine }`, and `pub fn
  lane_for(sensitivity: Option<crate::command::Sensitivity>, result: &AuditResult) ->
  AuditLane` (`Routine` iff `Some(Sensitivity::Read)` and `AuditResult::Ok`, else
  `Evidence`). Rework `AuditRing` internals (private types such as `RingState`, `Lane`,
  `SourceKey`, `Stamped`; the exact layout is the builder's, per the spec): one `Mutex`,
  one monotonic `u64` sequence assigned under it, two lanes, each evicting by fair share
  with the source table bound and per-origin overflow source; the source key is
  `(origin_label(entry.origin), entry.client_label.clone())`. Public surface:
  `pub fn new(capacity: usize) -> Self` (evidence `capacity`, routine
  `(capacity / 2).max(1)`), `pub fn with_lane_capacities(evidence: usize, routine: usize)
  -> Self` (each clamped to at least 1), `pub fn append_in(&self, lane: AuditLane, entry:
  AuditEntry)`, `pub fn evidence_len(&self) -> usize`, `pub fn routine_len(&self) ->
  usize`; `recent`, `count_since`, `len`, `is_empty` keep their signatures and now span
  both lanes (`recent` merges by sequence, oldest first, applying `since` then `limit`
  exactly as before); `impl Default` equals `new(DEFAULT_AUDIT_CAPACITY)`; `impl
  AuditSink for AuditRing` routes `append` to `AuditLane::Evidence`. Rewrite the
  module doc and the `AuditRing` doc (lanes, fair share, the bound, durable audit as the
  complete answer). Re-export `AuditLane`, `lane_for`, `DEFAULT_ROUTINE_AUDIT_CAPACITY`,
  `MAX_AUDIT_SOURCES` from `lib.rs`. Key the source with `origin_label(..)`; never
  compare an origin against `Frontend::Mcp`; do not edit `origin_label`.
- **Tests (written first)**, in `audit.rs` `mod tests`; use a helper that builds an
  `AuditEntry` with a given origin, label, and command, and compare origins with
  `origin_label`:
  - `lane_for_routes_only_successful_reads_to_routine`: `(Some(Read), Ok)` is
    `AuditLane::Routine`; `(Some(Read), Error("x"))`, `(Some(Write), Ok)`,
    `(Some(Sensitive), Ok)`, `(None, Ok)` are `AuditLane::Evidence`.
  - `recent_merges_both_lanes_oldest_first`: lanes `(8, 8)`; `append_in` of `E1`
    (Evidence), `R1` (Routine), `E2`, `R2`; `recent(None, None)` commands equal
    `["E1","R1","E2","R2"]`; `recent(None, Some(3))` equals `["R1","E2","R2"]`;
    `len() == 4`; `evidence_len() == 2`; `routine_len() == 2`;
    `count_since(UNIX_EPOCH) == 4`.
  - `a_routine_flood_never_evicts_evidence`: lanes `(4, 2)`; three evidence entries then
    100 routine; `evidence_len() == 3` and the three commands unchanged;
    `routine_len() == 2` and they are the last two appended.
  - `a_lone_source_uses_the_whole_lane_then_evicts_its_own_oldest`: lanes `(5, 1)`, one
    source; after five appends `evidence_len() == 5` and the first command is still
    present; after a sixth the first is gone and `evidence_len() == 5`.
  - `fair_share_protects_a_quiet_source_from_a_flooder`: lanes `(8, 1)`; source A appends
    3 (`a1..a3`), source B appends 100 (`b1..b100`); `recent` is exactly
    `[a1,a2,a3,b96,b97,b98,b99,b100]`.
  - `fair_share_ties_evict_the_globally_oldest`: lanes `(3, 1)`; three different
    single-entry sources `s1,s2,s3`, then `s4`; `recent` commands equal
    `["s2","s3","s4"]`.
  - `a_source_flood_of_distinct_labels_cannot_flush_a_tracked_source`: lanes `(330, 1)`;
    source A (origin `Frontend::Mcp`, label `a`) appends 200; then 5000 entries, each
    with a distinct label, same origin; `evidence_len() == 330`; the count of A's entries
    in `recent(None, None)` is at least `330 / (MAX_AUDIT_SOURCES + 3) - 1`, which is 8.
  The three original tests (`ring_is_bounded_and_evicts_oldest`, `recent_honours_limit`,
  `error_renders_with_reason`) are not edited and must pass.
- **Red (two steps):** `cargo test -p aitm-core --lib audit::tests` first fails to
  compile naming `AuditLane` / `append_in` / `lane_for`; after adding the signatures with
  the old single-FIFO behaviour (`append_in` ignores its lane, `lane_for` returns
  `Evidence`), it fails on assertions: `lane_for_routes_only_successful_reads_to_routine`
  (left `Evidence`, right `Routine`), `recent_merges_both_lanes_oldest_first`
  (`evidence_len()` is `4`, expected `2`), `a_routine_flood_never_evicts_evidence`,
  `fair_share_protects_a_quiet_source_from_a_flooder` (A's entries gone), and
  `a_source_flood_of_distinct_labels_cannot_flush_a_tracked_source` (A holds `0`).
  `a_lone_source_...` and `fair_share_ties_...` pass on the FIFO (guards).
- **Green:** `cargo test -p aitm-core` prints `test result: ok` (all `aitm-core`
  suites, `trust_gate_scan` and `classifier_wildcard_free` included); `cargo build
  --workspace` succeeds (nothing downstream calls a removed item).
- **Done when:** both red outputs and the green output are quoted, `git diff --stat`
  shows only `audit.rs` and `lib.rs`, and fmt and clippy are clean.

### Task 6: `record_audit` routes by lane; the server-level test file

- **Satisfies:** AC24, AC25, AC26, AC27
- **Depends on:** Task 5
- **Files:** `crates/aitm-mcp/src/server.rs` (modify `record_audit` only),
  `crates/aitm-mcp/tests/audit_integrity.rs` (create)
- **Change:** In `McpServer::record_audit`, replace `self.audit_ring.append(entry.clone())`
  with: look up `self.registry.command(name).map(|c| c.sensitivity())`, compute
  `aitm_core::lane_for(sensitivity, &entry.result)`, and call
  `self.audit_ring.append_in(lane, entry.clone())`; durable sink and `push_agent` are
  unchanged. Update the doc comment above `record_audit` (lane choice; a durable sink and
  the push still get every entry). No other `server.rs` change in this task.
  Create `audit_integrity.rs` with the helpers it uses and no others (copy the shape from
  `mcp.rs` about lines 316-325 and 3041-3070): `struct StubClient` (a `ProxyClient` whose
  `send` returns a boxed future that bails), `struct TierCmd { name: &'static str, sens:
  Sensitivity }` (a `Command` with no params returning `Value::Str("ran")`), `struct
  ErrEchoCmd` (`demo.errecho`, `Read`, one required `reason` string param, `invoke` fails
  with that reason), `fn audit_server(ring: Arc<AuditRing>) -> McpServer` (a `Registry`
  with `demo.read` Read, `demo.write` Write, `demo.sensitive` Sensitive, `ErrEchoCmd`, and
  `AgentPlugin::new(state.clone()).with_audit_ring(ring.clone())`; policy `Auto`;
  `.with_services(Arc::new(MemFlowStore::new()), Arc::new(StubClient),
  Arc::new(StdGuard::default()), None)`, `.with_agent_state(state)`,
  `.with_audit_ring(ring)`), `fn labelled(label: &str) -> ConnCtx` (`ConnCtx::new(
  Frontend::Mcp)` then assign `client_label`), and `fn call(srv: &McpServer, conn:
  &ConnCtx, name: &str, args: JsonValue) -> JsonValue`.
- **Tests (written first)**, in `audit_integrity.rs`:
  - `a_read_burst_cannot_evict_a_refused_sensitive_call`: one `ConnCtx` labelled
    `aitm_core::WEB_BRIDGE_CLIENT_LABEL`; call `demo.sensitive` once (refused), then
    `agent.status` `DEFAULT_AUDIT_CAPACITY + 64` times (4160). Expect
    `ring.recent(None, None)[0].command == "demo.sensitive"` with an `AuditResult::Error`
    result; `ring.evidence_len() == 1`; `ring.routine_len() == 2048`; `ring.len() == 2049`.
  - `a_refused_flood_cannot_evict_another_sources_entry`: source A labelled `agent-a`
    calls `demo.sensitive` once; source B labelled `agent-b` calls it `2 *
    DEFAULT_AUDIT_CAPACITY` times. Expect A's entry present (label `agent-a`),
    `ring.evidence_len() == 4096`, exactly 4095 entries labelled `agent-b`,
    `ring.routine_len() == 0`.
  - `routing_follows_sensitivity_and_outcome`: on a fresh ring, `(evidence_len,
    routine_len)` after each call: `demo.read` `(0, 1)`; `demo.errecho {reason: "x"}`
    `(1, 1)`; `demo.write` `(2, 1)`; `demo.sensitive` `(3, 1)`.
  - `actions_last_minute_counts_both_lanes`: `demo.read`, then `demo.sensitive`
    (refused), then `agent.status`: `result.structuredContent.actions_last_minute == 2`.
  Use `aitm_core::origin_label(e.origin)` for any origin comparison.
- **Red:** at the start of this task (Task 5 done, `record_audit` still on `append`),
  `cargo test -p aitm-mcp --test audit_integrity` fails: `a_read_burst_cannot_evict_a_refused_sensitive_call`
  (`recent[0]` is not `demo.sensitive`, or `evidence_len()` is `4096` not `1`) and
  `routing_follows_sensitivity_and_outcome` (first row `(1, 0)`, expected `(0, 1)`).
  `a_refused_flood_...` and `actions_last_minute_counts_both_lanes` already pass
  (Task 5's fair share and counting): record that, they are guards.
- **Green:** the same command prints `test result: ok. 4 passed`. Then
  `cargo test -p aitm-mcp --test mcp` (the existing suite, unmodified; socket tests in it
  that cannot bind are reported NOT RUN) shows `every_invoke_is_audited_including_refusals`,
  `agent_activity_returns_recent`, `audit_redacts_secrets`,
  `audit_redacts_secret_inside_non_secret_named_value`,
  `audit_redacts_secret_in_error_reason`, and
  `subscription_refusal_is_audited_but_success_is_not` passing.
- **Done when:** red and green are quoted, `git diff --stat` shows only the two files,
  and fmt and clippy are clean. The orchestrator rebases on `main` first (rebase hazard,
  spec Design 7).

### Task 7: one consumption-time label helper, the reason cap, redaction at the server

- **Satisfies:** AC16, AC28, AC29
- **Depends on:** Tasks 2, 4, 6 (same files as Task 6)
- **Files:** `crates/aitm-mcp/src/server.rs` (modify), `crates/aitm-mcp/tests/audit_integrity.rs`
  (modify: add helpers and tests)
- **Change:** In `server.rs` add private `fn conn_audit_label(conn: &ConnCtx) ->
  Option<String>` (`conn.client_label.as_deref().and_then(aitm_core::sanitize_client_label)`)
  and use it in exactly two places: the `CommandHost` builder in `run_tool` (replace the
  `host.with_client_label(label.clone())` match arm's source) and the `AuditEntry`
  literal in `record_audit` (`client_label: conn_audit_label(conn)`). Add private `fn
  cap_reason(reason: String) -> String` (truncate to `aitm_core::DEFAULT_RESULT_REASON_CAP`
  bytes on a char boundary and append `…` only when truncated; the builder may share a
  helper with `redact_args`) and apply it to the scrubbed reason in `record_audit`:
  `AuditResult::Error(cap_reason(scrub_text(reason)))`. Update the doc comments on
  `ConnCtx::client_label` and `record_audit` to say the label is sanitised on consumption
  and the reason is capped. The tool result returned to the caller is unchanged.
  Extend `audit_integrity.rs` with `struct ClientLabelCmd` (`demo.client`, `Read`, returns
  `host.client_label().unwrap_or("<none>")` as a string), `struct EchoCmd` (`demo.echo`,
  `Read`, params `note: Str` and `headers: Map<Str>`, returns its args), registered in
  `audit_server`.
- **Tests (written first)**, in `audit_integrity.rs`:
  - `a_hostile_label_is_bounded_in_the_ring_and_the_host`: a `ConnCtx` whose
    `client_label` is `Some("B".repeat(10 << 20))` calls `demo.client`: the reply's
    `structuredContent` equals `"B".repeat(64)`; the ring entry's `client_label` equals
    `Some("B".repeat(64))`; after 20 such calls the sum of `client_label.len()` over
    `ring.recent(None, None)` equals `20 * 64` (1280). (Twenty, not more: on the unfixed
    code every call retains a 10 MiB clone in the ring, so the red run must stay under
    about 200 MiB.)
  - `an_oversized_error_reason_is_capped_in_the_ring`: `demo.errecho` with `reason =
    "x".repeat(1 << 20)`: the ring entry is `AuditResult::Error(r)` with `r.len() <=
    1024 + 3`, `r.starts_with("xxxx")`, `r.ends_with('…')`; the tool result's text still
    contains all 1 MiB of the reason.
  - `args_summary_hides_unframed_credentials`: a subscribed operator `ConnCtx` (with a
    `NotificationSink`, as `audit_redacts_secrets` in `mcp.rs` does) and an agent call to
    `demo.echo` with `note = "go sid=SECRET1 session=SECRET2 auth=SECRET3 jwt=SECRET4
    author=bob"` and `headers = {"X-Session": "SECRET5"}`: the ring entry's `args_summary`
    and the drained pushed line contain none of `SECRET1`, `SECRET2`, `SECRET3`,
    `SECRET4`, `SECRET5`, and `args_summary` contains `author=bob`.
- **Red:** `cargo test -p aitm-mcp --test audit_integrity` fails:
  `a_hostile_label_is_bounded_in_the_ring_and_the_host` (reply length `10485760`, not
  `64`), `an_oversized_error_reason_is_capped_in_the_ring` (reason length over
  `1 << 20`), and `args_summary_hides_unframed_credentials` only if Task 2 is not yet in
  this branch (otherwise it is green on arrival: state which in the report).
- **Green:** the same command prints `test result: ok` for all seven tests. The existing
  `mcp.rs` suite still passes (`client_label_captured_from_initialize`,
  `audit_redacts_secret_in_error_reason` named).
- **Done when:** red and green are quoted, `git diff --stat` shows only the two files, and
  fmt and clippy are clean.

### Task 8: the transport captures a bounded, unforgeable label

- **Satisfies:** AC14
- **Depends on:** Task 4
- **Files:** `crates/aitm-mcp/src/transport.rs` (modify)
- **Change:** `fn client_label_from_initialize(message: &str) -> Option<String>` keeps
  its signature and its checks (method is `initialize`, `params.clientInfo.name` is a
  string) and returns `aitm_core::declared_client_label(name)` instead of the raw
  non-empty name. The `serve_lines` capture block (`if conn.client_label.is_none()`) is
  not changed. Update the doc comment of the function (bounded, scrubbed, reserved
  names rewritten).
- **Test (written first):** in `transport.rs` `mod tests` add
  `client_label_from_initialize_is_bounded_and_unforgeable`: with a helper that renders
  `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":N}}}`:
  `N = "A".repeat(10 << 20)` returns `Some("A".repeat(64))`; `N = "web-bridge"` returns
  `Some("web-bridge (declared)")`; `N = "aitm-mac"` returns `Some("aitm-mac")`; `N = ""`
  returns `None`; a message with no `clientInfo` returns `None`.
- **Red:** `cargo test -p aitm-mcp --lib transport::tests::client_label_from_initialize_is_bounded_and_unforgeable`
  fails on the first assertion (left length `10485760`, right `64`).
- **Green:** the same command prints `test result: ok. 1 passed`; `cargo test -p aitm-mcp
  --lib transport::` passes (the socket-binding tests there are reported NOT RUN if the
  sandbox refuses the bind, and the orchestrator runs them in the Terminal panel);
  `client_label_captured_from_initialize` in `mcp.rs` is run by the orchestrator in the
  Terminal panel (it binds a socket) and passes.
- **Done when:** red and green are quoted, `git diff --stat` shows only `transport.rs`,
  and fmt and clippy are clean.

### Task 9: the bridge builds its `ConnCtx` through a helper that sets the label

- **Satisfies:** AC15
- **Depends on:** Task 4
- **Files:** `crates/aitm/src/web/bridge.rs` (modify)
- **Change:** Add `pub(crate) fn bridge_conn_ctx(role: Frontend, conn_id: u64, out:
  NotificationSink) -> ConnCtx` that returns the `ConnCtx` with `client_label:
  Some(aitm_core::WEB_BRIDGE_CLIENT_LABEL.to_string())`, the given role, id, and
  `out: Some(out)`. Replace the `ConnCtx { role, client_label: None, conn_id:
  state.mcp.next_conn_id(), out: Some(sink.clone()) }` literal (about line 252) with
  `Arc::new(bridge_conn_ctx(role, state.mcp.next_conn_id(), sink.clone()))`. Add a doc
  comment naming why the bridge never reads `clientInfo` (any holder of the token can
  open the socket) and that the label names the path, not the client. Keep the hunk as
  small as possible (rebase hazard with the `/bus` sessions); do not touch the frame
  loop.
- **Test (written first):** in `bridge.rs` `mod tests` add
  `bridge_conn_ctx_carries_the_server_minted_label`: for `Frontend::Operator` and for
  `Frontend::Mcp`, `bridge_conn_ctx(role, 7, NotificationSink::new(4))` has
  `client_label.as_deref() == Some("web-bridge")`, `conn_id == 7`, `out.is_some()`, and
  `aitm_core::origin_label(ctx.role)` equals `"operator"` and `"mcp"` respectively.
- **Red (two steps):** `cargo test -p aitm --lib web::bridge::tests::bridge_conn_ctx_carries_the_server_minted_label`
  first fails to compile naming `bridge_conn_ctx`; with a stub that sets
  `client_label: None` it fails on the label assertion (left `None`, right
  `Some("web-bridge")`).
- **Green:** the same command prints `test result: ok. 1 passed`; `cargo build -p aitm`
  succeeds. The bridge's other unit tests in `mod tests` still pass.
- **Done when:** both red outputs and the green output are quoted, `git diff --stat`
  shows only `bridge.rs`, and fmt and clippy are clean.

### Task 10: socket test, the bridge is attributed end to end (Terminal panel)

- **Satisfies:** AC30
- **Depends on:** Tasks 7 and 9
- **Files:** `crates/aitm/tests/web_bus_audit_label.rs` (create)
- **Change:** One test file modelled on `crates/aitm/tests/web_bus_governance.rs`: its
  `start(tag, policy)` rig (build the web server with `aitm::tui::server`, then
  `tui::with_shared_governance`, `.with_push(..)`, `spawn_push_dispatcher()`, serve
  `web::serve` on `127.0.0.1:0` with both bridge tokens), `ws_connect`, and the small
  send/receive helpers it needs, copied rather than shared (house style; do not edit the
  governance file). Header comment states it binds loopback sockets and runs from the
  Terminal panel.
- **Test:** `bridge_calls_are_attributed_to_web_bridge`: agent connection sends the token
  line, then `initialize` with `clientInfo.name = "forged"`, then `tools/call
  agent.status`; operator connection sends its token, then `agent.status`, then
  `agent.activity`. Expect in the `agent.activity` list: an entry with `command ==
  "agent.status"`, `origin == "mcp"`, `client_label == "web-bridge"`; an entry with
  `command == "agent.status"`, `origin == "operator"`, `client_label == "web-bridge"`;
  and no entry whose `client_label` is `forged`.
- **Red:** (run by the orchestrator in the Terminal panel) on the branch with Task 9
  stubbed or reverted, `cargo test -p aitm --test web_bus_audit_label` fails with `client_label`
  `null` where `"web-bridge"` is expected. The Coder in the sandbox reports `cargo test -p
  aitm --test web_bus_audit_label --no-run` (it must compile) and "NOT RUN (socket)".
- **Green:** (Terminal panel) `cargo test -p aitm --test web_bus_audit_label` prints
  `test result: ok. 1 passed`; `cargo test -p aitm --test web_bus_governance` still prints
  `test result: ok` (PR 145 AC5, `actions_last_minute == 2`, unmodified).
- **Done when:** the orchestrator pastes both Terminal outputs into the report and fmt and
  clippy are clean.

### Task 11: docs, mutation checks, final verification

- **Satisfies:** AC31, AC32, AC33, AC34, AC35
- **Depends on:** all
- **Files:** `crates/aitm-plugins/src/agent.rs` (modify: doc comments and description
  strings only)
- **Change:** In `agent.rs`: the module doc (lines 1 to 12) says the ring has two lanes
  and that `actions_last_minute` counts both; the `actions_last_minute` result
  description says it counts invocations still held in the audit ring in the last minute
  across both lanes and every surface (a polling UI counts) and saturates at what the
  ring holds; the `agent.activity` doc comment and schema description say entries merge
  oldest-first across the lanes, a source's retention depends on its own volume and fair
  share, an unlimited call can return up to 6144 entries, and `limit` is advisable; the
  `client_label` result description says it is the server-minted `web-bridge` for the web
  bridge, otherwise the client's declared `initialize.clientInfo.name`, sanitised to at
  most 64 characters, display-only (`origin` is authoritative). No code change, no
  signature change. README: run `grep -n "audit\|agent.activity" README.md`, and edit it
  only if a line is now factually wrong (the table row at about line 472 is not).
  **Mutation checks (AC34), in the sandbox, each reverted by hand.** The Coder runs no
  `git`: before the first mutation it copies `crates/aitm-mcp/src/server.rs` and
  `crates/aitm-mcp/src/transport.rs` to `$TMPDIR/server.rs.orig` and
  `$TMPDIR/transport.rs.orig`. (a) In `record_audit` replace `append_in(lane,
  entry.clone())` with `append(entry.clone())` and run `cargo test -p aitm-mcp --test
  audit_integrity`: expect `a_read_burst_cannot_evict_a_refused_sensitive_call` and
  `routing_follows_sensitivity_and_outcome` to fail on assertions; revert and re-run
  green. (b) Replace `conn_audit_label(conn)` in `record_audit` with
  `conn.client_label.clone()`: expect `a_hostile_label_is_bounded_in_the_ring_and_the_host`
  to fail on its ring-entry assertion; revert. (c) In `transport.rs` replace
  `declared_client_label(name)` with `sanitize_client_label(name)`: expect the
  `web-bridge` row of `client_label_from_initialize_is_bounded_and_unforgeable` to fail;
  revert. After each revert, `diff crates/aitm-mcp/src/server.rs $TMPDIR/server.rs.orig`
  and `diff crates/aitm-mcp/src/transport.rs $TMPDIR/transport.rs.orig` print nothing.
  The red output, the restored green output, and the two empty diffs go in the report.
- **Final checks, each with its literal expected output.** Every `git` command here is
  run by the orchestrator in the Terminal panel, not by the Coder:
  - `git diff --stat bd0f9b7..HEAD -- crates/aitm-plugin-scanner crates/aitm-ca crates/aitm-findings apps`
    prints nothing.
  - `git diff -U0 bd0f9b7..HEAD -- crates/aitm-mcp/src/server.rs | grep -E "^[-+] +pub (role|client_label|conn_id|out):"`
    prints nothing; `git diff -U0 bd0f9b7..HEAD -- crates/aitm-core/src/audit.rs | grep -E "^[-+] +pub (at|origin|client_label|command|args_summary|result):"`
    prints nothing.
  - `git diff --stat bd0f9b7..HEAD` names only: `crates/aitm-core/src/{audit,redact,lib}.rs`,
    `crates/aitm-mcp/src/{server,transport}.rs`, `crates/aitm-mcp/tests/audit_integrity.rs`,
    `crates/aitm/src/web/bridge.rs`, `crates/aitm/tests/web_bus_audit_label.rs`,
    `crates/aitm-poc/src/builder.rs`, `crates/aitm-plugins/src/agent.rs`, and the spec and
    plan, and no existing test file.
  - `grep -c "EXTRA_SECRET_KEY_SEGMENTS\|SESSION_KEY_SUBSTRINGS" crates/aitm-poc/src/builder.rs`
    prints `0`.
  - `cargo test -p aitm-core --test trust_gate_scan --test classifier_wildcard_free`
    prints `test result: ok` twice.
  - The gate, by the orchestrator in the Terminal panel, redirected to a log and gated on
    exit status: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo
    test` exits `0`.
  - Optional live confirmation, orchestrator, Terminal panel, if the e2e harness is
    available: the `tests/e2e/audit` and `tests/e2e/neg` cells (their labels are
    `aitm-e2e-audit-agent-<8 hex>` and similar, under the 64-char cap, so they must
    still match `client_label`).
- **Done when:** every check above is quoted with its output, the three mutation red runs
  and restored green runs are in the report, and the doc strings are updated.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7. Follow-ups already named by
the spec: "durable audit wiring" (config key, path, rotation, 0600, blocking I/O),
"scanner vocabulary consolidation" (the scanner drops its own `redact_needle_pairs` and
pre-pass and fixes its stale doc comments), "agent-stream filtering" (the
`notifications/aitm/agent` push for routine entries), and the PR 145 follow-ups that
remain ("tui-mode governance", "unified agent hub", "configurable startup policy").
