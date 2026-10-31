# Durable audit wiring design

**Status:** approved. **Amendment 1 (Design 14, strict redaction on disk) approved 2026-10-31 by the orchestrating session at Matt's direction (relayed by the lead session: default-on confirmed; "NO tokens, secrets, or credential values EVER hit disk"). Its one existing-test change, the `tests/e2e/audit/test_audit_log.py` `X-Audit-Marker` assertion (AC59), is approved; so is the one-hunk relaxation of the `aitm-mcp` fence (the `server.rs` call-path hunk and the new `redact_args.rs`). Rule D's evidence cost (custom header values leave the audit copy) is flagged for Matt in the PR; the veto path is rule S alone (Open question 5).** Original approval: (2026-10-31, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief; the Architect's calls listed at the end stand as written, with one orchestrator amendment: `crates/aitm/tests/shutdown.rs`, the one Rust test that spawns the real `aitm` binary, joins the hermeticity group in Files E and AC38 and is the single exception to AC41's "no existing test is edited", as a one-line environment addition. Default-on (call 1) is the decision flagged for Matt's veto in the PR.)
**Research inputs:** no `docs/research/` note. This is the follow-up PR 171 named
"durable audit wiring" (`docs/superpowers/specs/2026-10-30-audit-ring-integrity-design.md`,
Design 1 "`durable_audit` wiring: not in this change", Residual risks 1, 2, 3, 7, 8, 10,
11; its plan's Shipped section, `docs/superpowers/plans/2026-10-30-audit-ring-integrity-plan.md`
lines 806-825) and builds on PR 172
(`docs/superpowers/specs/2026-10-30-bus-audit-connection-id-design.md`: `connection_id`,
role-filtered view) and PR 162 / PR 145
(`docs/superpowers/specs/2026-10-30-tui-mode-governance-design.md`,
`.../2026-10-30-web-bus-agent-governance-design.md`: the servers that share one ring).
Code read at `15009b2` (main `f979040` plus one docs commit):
`crates/aitm-core/src/{audit,config,ctx,lib}.rs`,
`crates/aitm-core/tests/trust_gate_scan.rs`,
`crates/aitm-mcp/src/{server,schema}.rs`, `crates/aitm-mcp/tests/mcp.rs` (~5374-5425),
`crates/aitm-ca/src/audit.rs`, `crates/aitm-plugins/src/{agent,control}.rs`,
`crates/aitm/src/{main,lib,tui,wire,env,config_file}.rs`, `crates/aitm/tests/{audit_durable_connection_id,shutdown}.rs`,
`crates/aitm/Cargo.toml`, `Cargo.toml`, `Cargo.lock`, the UI decoders of `agent.status`
(`crates/aitm-tui/src/model.rs`, `apps/mac/Sources/**/Activity.swift`, `apps/web/src/state/app.ts`,
`apps/web/src/bus/noise.ts`), the macOS embedded-core launcher
(`apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift`), and the e2e harness
(`tests/e2e/aitm_e2e/core.py`).

**Amendment 1 (strict redaction on disk, Matt's hard requirement; code re-read at
`abe5629`).** Design 14 and AC44 to AC65 are new; Intent, Goals, Anti-goals, Constraints,
Design 6 (sanitising), Design 13, Semantics, Rebase hazards, Residual risks, Files, AC16, AC17,
AC40, Left to the builder, Open questions, Summary and Architect's calls are amended in place
and marked "(Amendment 1)". The amendment also reads `crates/aitm-core/src/redact.rs`,
`crates/aitm-mcp/src/server.rs` (2395-2480), `crates/aitm-plugins/src/mutate.rs` (50-140,
262-320), `crates/aitm-poc/src/{builder,runner}.rs`, `crates/aitm-browser/src/commands.rs`
(150-230), `crates/aitm/src/web/mod.rs` (132-192), `crates/aitm/src/main.rs` (516-579), and the
existing redaction tests (`crates/aitm-mcp/tests/{mcp,audit_integrity}.rs`,
`tests/e2e/audit/test_audit_log.py`). Nothing was run: every claim about current behaviour is
from reading.

## Intent

The F2 audit ring is a bounded, fair, in-memory live view. It is still the only audit
record the binary keeps: `McpServer::with_durable_audit` has no production caller and the
YAML config has no key for it, so a restart empties the record and a flood that outruns the
ring's fair share still evicts entries. This change makes the audit durable by default: every
audited call, from every server this binary builds, is appended to a JSONL file under the
operator's config directory, through one choke point, by a writer that can never slow or
break the command that produced the entry. The file is best-effort, not tamper-evident, and
says so: gaps (dropped or unwritable entries) are recorded in the file itself and counted in
`agent.status`. No token, secret or credential value may ever reach the file (Amendment 1):
the redaction path is strict, layered, and proven by a corpus test through the real server and
the real writer (Design 14). The design adds no dependency, no `unsafe`, and no field on
`ConnCtx`, `AuditEntry` or `wire::Governance`; its executable change in `aitm-mcp` is exactly
the redaction hunk Design 14 names (Amendment 1).

## Goals

- After a restart the operator's and the agent's history is still on disk, in order, appended
  to rather than truncated.
- Every audited call reaches the file whichever server served it: the primary agent server,
  the `aitm web` `/bus` server, and the `aitm tui` loopback agent server, and a future fourth
  server that shares the ring cannot forget to attach the sink.
- A flood of agent-origin calls can never push operator or CLI evidence out of the file, and a
  flood of successful reads can never push any evidence out of it.
- `record_audit` never performs file I/O: the hand-off is a bounded, non-blocking queue per
  stream, and a stalled, full or failing disk costs the call path nothing.
- A lost entry is never silent: it is counted (`agent.status.durable_audit`) and marked in the
  file (a `gap` line).
- Disk use is bounded (at most 92 MiB with the defaults) and rotation never loses the line
  being written.
- The file never contains a raw control character, or a label, reason or argument longer than
  the ring's own caps.
- (Amendment 1) No token, secret or credential value ever reaches the file: the bus/operator
  and agent tokens (all five sources, including the per-run operator bridge token minted after
  the writer starts), any `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` or
  auth header in any carrier shape, PoC credentials, and everything the existing scrubber
  flags. Each class is covered by a structural or literal rule, not a heuristic (Design 14.8).
- (Amendment 1) Redaction never corrupts what it keeps: ids, hashes, hostnames, `host:port`,
  URLs and ordinary JSON survive byte for byte, and a redacted `args` that parsed as JSON still
  parses.
- (Amendment 1) The ring, the `notifications/aitm/agent` push, `agent.activity` and the file
  are equally clean of header and free-text credentials, because the structural and text rules
  run at the one source all three take `args_summary` from.
- Turning it off, and pointing it elsewhere, are one explicit key and one env var.

## Non-goals

- **Tamper evidence** (hash chaining, signing, an append-only file attribute). A same-user
  process can delete or edit the file (Residual risks 1).
- **A per-origin or per-source write budget** (rate limiting what a flooder may put on disk).
  Stream separation (Design 5) protects operator evidence; a sustained agent flood can still
  rotate out earlier agent evidence (Residual risks 3). Named follow-up "audit write budget".
- **Auditing what never reaches `McpServer::record_audit`**: the `aitm tui` in-process UI server
  (Design 10, deliberate), one-shot `aitm <subcommand>` invocations, and protocol-level
  failures (an unknown tool or invalid arguments is a JSON-RPC error and is not audited today).
  Named follow-up "audit the TUI-facing operator server and the CLI".
- **Multi-process coordination.** Two `aitm` processes sharing one audit path are not locked
  against each other (Residual risks 8).
- A reader subcommand (`aitm audit tail`), any UI surface for `durable_audit` (TUI, web, macOS
  app), time-based retention, compression, or shipping to syslog or a remote sink.
- A configurable size or retention (the caps are constants, Design 5).
- `fsync` per line, encryption of the file, and permission enforcement on non-Unix targets.
- Any change to `ca.audit_log`, `AuditRecord`, `FileAuditLog` behaviour, `entry_to_jsonl`,
  the ring's lanes or fair share, `agent.activity`, or the `notifications/aitm/agent` push.
- Removing `McpServer::with_durable_audit` (existing tests use it; it stays a per-server tap).

## Anti-goals

- A `record_audit` that waits on anything but a short in-memory critical section.
- A command, tool or registry surface that reads, tails, rotates, relocates, disables, or
  reveals the path of the log to any role. The file is read by the operator's shell, never by
  the bus.
- A token, an unsanitised label, an argument or a per-call line in the operator's terminal
  or in `tracing` output. One startup line, no per-write line at `info` or above.
- An explicitly configured log that silently does not work, or an audit that a typo in an
  env var turns off.
- A write through a symbolic link, a hard link, a FIFO, or a CWD-relative path.
- A second definition of the line format or of redaction.
- A field added to `ConnCtx`, `AuditEntry` or `Governance`, an edit to `crates/aitm/src/web/bridge.rs`,
  or any executable edit in `crates/aitm-mcp` beyond the redaction hunk Design 14.1 names
  (Amendment 1; sibling sessions are editing that crate).
- (Amendment 1) Editing `crates/aitm-core/src/redact.rs`, `is_secret_key` or `scrub_text`: both
  are shared with the scanner, findings and the PoC builder, were just panel-reviewed, and an
  idle scanner session is consolidating them. Every new rule is an addition beside them.
- (Amendment 1) A redaction pass that rewrites JSON structure or a non-secret value, a pass
  that is not idempotent, or `scrub_text` run over JSON-rendered text (Design 14.0).
- (Amendment 1) Masking a short configured token by raw substring (it would corrupt ordinary
  text), and any log line, `Debug` or `Display` output that contains a registered secret or
  its length.
- A comparison against the agent role by `==`, `!=`, `matches!` or `if let` anywhere in
  `crates/*/src` (`trust_gate_scan.rs`); roles are classified with `is_trusted_control()`.
- Test runs of the binary (the e2e harness, `cargo test`) appending to the operator's real
  audit file.

## Constraints

- **No new dependency, no `unsafe`.** `crates/aitm/Cargo.toml` and `Cargo.lock` are unchanged.
  `aitm` already has `aitm-core`, `aitm-ca`, `aitm-mcp`, `serde_json`, `tracing`; the writer
  uses `std::thread`, `std::sync::mpsc`, `std::fs` and `std::os::unix::fs` only. `libc` is in
  the lock file but is not a dependency of `aitm`, and the workspace forbids `unsafe`, so
  `O_NOFOLLOW` and `geteuid` are not available: the hardening in Design 4 is `symlink_metadata`
  checks and an identity comparison, not open flags.
- **Hot path.** With no sink attached the only new work in the ring hook is one
  `OnceLock::get`. With a sink it is that plus one `AuditEntry::clone` and one `try_send`. No
  lock is held across the hook, there is no I/O, and nothing is allocated beyond the clone. The
  writer's sanitising and rendering happen on the writer threads. (Amendment 1) The strict
  redaction of Design 14 runs on the call path inside `record_audit` (that is where `args_summary`
  and the reason are made), so it is **bounded**: it examines at most 4 KiB of any one string and
  64 KiB of text in all, whatever the size of the arguments (Design 14.6, AC46).
- **Memory.** Three bounded queues (1024, 4096, 2048 entries). Every entry field is capped
  before the entry is queued (ring caps), so the queues add at most about 18 MiB worst case
  and typically under 4 MiB, on top of the ring's own bound.
- **Compatibility.** `agent.status` gains one declared result field and nothing else
  changes shape (Design 11). `agent.status`'s `outputSchema` is generated with
  `additionalProperties: false` (`crates/aitm-mcp/src/schema.rs:159`), so the new field and
  every key under it MUST be declared in the result `TypeDesc`.
- **Trust-gate scan and `classifier_wildcard_free`** stay green (`trust_gate_scan.rs:1-30`).
- **Platform.** File modes, ownership-adjacent checks and `nlink` are Unix-only (`#[cfg(unix)]`);
  other targets compile and write with default permissions, documented.
- **Edits stay in** the files named under "Files". Sandbox: every test runs in the Bash sandbox
  except the ones marked `[socket]`, which bind loopback and need the Terminal panel.

## Facts the design rests on

All verified by reading code at `15009b2`.

| Fact | Where |
|---|---|
| `with_durable_audit(Arc<dyn AuditSink>)` stores a per-server `Option`; the only callers are tests | `crates/aitm-mcp/src/server.rs:1061, 1138-1141`; `crates/aitm-mcp/tests/mcp.rs:5396`; `crates/aitm/tests/audit_durable_connection_id.rs:91` |
| `record_audit` runs inline on the call path: build entry, `lane_for`, `audit_ring.append_in(lane, entry.clone())`, `durable.append(entry.clone())`, `push_agent` | `server.rs:1958-1973` |
| The entry is already bounded and scrubbed there: reason `scrub_text` + `cap_reason`, label `conn_audit_label`, args `redact_args`; `cap_text` is idempotent (cuts to `cap` bytes plus `…` only when longer) | `server.rs:1954, 1961, 1964`; defs `2409-2434, 2442` |
| `AuditRing` is `Debug`, holds one `Mutex<RingState>`; `append_in` locks, inserts, unlocks; the trait `append` is the evidence lane; the trait is "infallible by contract" | `crates/aitm-core/src/audit.rs:374-378, 524-527, 555-560, 678-684` |
| `lane_for`: a successful `Read` is routine, everything else evidence | `audit.rs:364-369` |
| `to_value` renders exactly seven keys (`at, origin, client_label, connection_id, command, args, result`); `visible_to` delegates to `is_trusted_control` | `audit.rs:175-177, 182-217` |
| `FileAuditLog` opens a fresh `O_APPEND` handle per line, `0600` only at creation, parent `0700` only in `open`, no symlink/hard-link/mode checks, no rotation; its `AuditSink` impl is best-effort with `tracing::warn` per failed line | `crates/aitm-ca/src/audit.rs:101-147, 158-189` |
| `entry_to_jsonl` renders the same seven keys and "trusts its caller" (label, args, reason raw) | `aitm-ca/src/audit.rs:191-213` |
| The CA log is a different eight-key shape (`ts, command, frontend, outcome, scope, platform, fingerprint_sha256, detail`), opened fail-closed by `ca.*` commands, never rewritten or truncated; default `<config_dir>/aitmproxy/ca-audit.jsonl`; key `ca.audit_log` | `aitm-ca/src/audit.rs:26-47, 91-99, 101-102`; `crates/aitm-core/src/config.rs:259-271`; `crates/aitm/src/config_file.rs:493-518` |
| The doc comments that call the CA log "a subset of" one general JSONL format, and the durable sink "opt-in by config", are stale | `aitm-ca/src/audit.rs:158-165, 191-197`; `server.rs:1057-1061, 1136-1137, 1917-1919`; `aitm-core/src/audit.rs:3-9, 60-61, 522-523` |
| `McpFile` is `deny_unknown_fields` with three keys; `apply(&mut McpConfig)` | `config_file.rs:521-546` |
| `McpConfig` has five fields; its only literal outside `config.rs` ends in `..McpConfig::default()` | `crates/aitm-core/src/config.rs:323-352`; `crates/aitm-plugins/tests/control.rs:266-275` |
| `default_config_path()` is derived from the CA audit log's directory | `config_file.rs:33-35` |
| Env overrides are injected lookups applied after the file; `apply` is infallible | `crates/aitm/src/env.rs:40-50`; `main.rs:161-162, 169` |
| Modes: `operator-token` is a `parse_mode` arm outside the registry; bare, `tui`, `web` share one tail; one-shot CLI returns before any server is built | `main.rs:61-90, 313-341, 603-613` |
| The two bare-path servers go through `with_shared_governance`; the shared `audit_ring` comes out of `Assembled` | `main.rs:293-311, 496-502, 518-525` |
| `with_shared_governance` shares exactly the policy state and the ring; "by convention" on the bare path | `crates/aitm/src/tui.rs:205-213` and its doc above |
| `build_servers` applies it to the loopback agent arm from the sealed `Governance`; the TUI-facing `ui` server is built by `server(..)` alone, private ring, "unrecorded on purpose" | `tui.rs:308-345` (agent arm `313-331`, `ui` `333-344`) |
| `Assembled.audit_ring` and `Governance` are `pub`/sealed, with a doc-example struct literal; the ring is created at assembly and also handed to `AgentPlugin` | `crates/aitm/src/wire.rs:126, 208-211, 368, 383` |
| `agent.status` reads the ring through its own `Arc<AuditRing>`; its result is a declared `TypeDesc::Object` | `crates/aitm-plugins/src/agent.rs:99-102, 129-156, 160-187` |
| Decoders of `agent.status` read keys by name and ignore the rest | `crates/aitm-tui/src/model.rs:805-820`; `apps/mac/Sources/AitmproxyKit/Panels/Activity.swift:129-148`; `apps/web/src/state/app.ts:855`; `tests/e2e/**` use `.get("policy")` |
| `config.get` shows `ca.dir` and the transport kind, not `ca.audit_log`; there is no runtime config setter | `crates/aitm-plugins/src/control.rs:278-305` |
| The web UI's own background reads include `flow.detail` with `body:none` and its comment says the server's audit, "ring, durable log", keeps them | `apps/web/src/bus/noise.ts:12-29` |
| The embedded macOS core and the e2e harness both launch `aitm --config <per-launch temp file>` | `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift:172, 196, 345-352`; `tests/e2e/aitm_e2e/core.py:92, 116, 127-135` |
| `tracing_subscriber::fmt()` is installed with its default writer; the existing startup line is `info!` | `main.rs:748-752`; `crates/aitm-core/src/proxy.rs:142` |
| The shutdown path: a `select!` arm ends, the browser is reaped, `result` returns; `shutdown.rs` is obscura-gated | `main.rs:590-613`; `crates/aitm/tests/shutdown.rs:50-58, 124` |
| `rust-version = 1.97`; `unsafe_code = "forbid"` | `Cargo.toml:35, 42` |
| An existing test pins that the durable sink keeps entries an agent cannot read | `crates/aitm-mcp/tests/mcp.rs:5393-5425` |
| README claims "every call lands in one audit log" and "One audit log of every command" | `README.md:43, 501`; config examples `README.md:187-194`, `INSTALL.md:44-56` |
| Idle web UI polling is about 150 calls a minute, origin `mcp` | PR 171 spec, Intent (3) |

## Design

### 1. The shape in one paragraph

A new module `crates/aitm/src/audit_log.rs` owns the writer. `aitm-core` gains one small
extension point on the ring: a set-once `DurableAudit` sink that `AuditRing::append_in` hands
every entry to, after its lock is released. `main.rs` builds the writer once, before any port
is bound, attaches it to the ring `Assembled` already shares with every server, and flushes it
in the shared tail. The writer routes each entry into one of three on-disk streams, each with
its own bounded queue, thread, file and rotation. `agent.status` reports the writer's health
from the ring it already holds.

### 2. Config key, env var, precedence, and how "off" is spelled (Q1)

**Decision.** One key, `mcp.audit_log`, and one env var, `AITM_AUDIT_LOG`. No CLI flag.

| Spelling | Meaning |
|---|---|
| key absent, or `true` | `Default`: `<config_dir>/aitmproxy/audit.jsonl` (the directory `default_aitm_dir()` resolves, beside `ca-audit.jsonl` and `config.yaml`) |
| `false`, or the string `off` (any case) | `Off`: no writer, no files |
| an absolute path string | `Path(p)`: the control stream file is `p` (Design 5 names the other two) |
| anything else (a relative path, `~/x`, an empty string) | a config error naming `mcp.audit_log` and "absolute" |

`AuditLogSetting { Default, Off, Path(PathBuf) }` lives in `aitm-core::config` beside
`McpConfig` (a new field `audit_log`, default `Default`), with `resolved_path(&self) ->
Option<PathBuf>`. `McpFile` gains `audit_log: Option<..>` (its `deny_unknown_fields` still
rejects a misspelled sibling). `Path(_)` is "explicit": the operator asked for it.

`AITM_AUDIT_LOG` follows the existing env bridge (`aitm::env`), in which the environment wins
over the file:
`off|false|0|no` selects `Off`; `on|true|1|yes|default` selects `Default`; an absolute path
selects `Path`. Any other value (a relative path, a typo, empty) **leaves the file's setting
alone** and logs one `warn!`, unlike the `is_truthy` rule (where "anything else is false"):
for an audit control the fail-safe direction is "stay on", so a typo in `AITM_AUDIT_LOG=ofd`
cannot silently disable the trail. `env::apply` stays infallible.

**Relationship to `ca.audit_log`.** Independent keys, independent files, independent shapes.
The CA log is fail-closed per `ca.*` command, never rewritten, never rotated, eight keys. The
general audit is best-effort, rotated, seven keys. They must not share a file: a boot-time
check fails (with `ca.audit_log` in the message) when any of the three stream paths equals
`ca.audit_log`. The "one format" sentence in the doc comments is wrong and is corrected
(Design 13): the CA's `ca.*` calls appear in the general audit as ordinary entries (who called
what, outcome) and in the CA log as the CA's own detail; neither is a subset of the other.

**Alternatives rejected.** *A CLI flag* (`--audit-log`): needs `split_*` plumbing for no
capability the env var lacks, and `audit` is better kept free as a future subcommand name.
*A nested object* (`audit_log: {path, max_mib, keep}`): the caps are constants for now
(Design 5), so a scalar is enough and stays forward-compatible (an object form can be added
later). *Env "any other value is false"*: fail-open on typos. *Resolve a relative path against
the config file's directory*: magic, and the CA log and `default_ca_dir` already refuse CWD
anchoring.

### 3. Default: on (Q2) (Architect's call)

**Decision.** The default is on, at the default path, with an explicit `off`.

- *Why on.* The task exists because "off" is today's state: an audit trail that is off unless
  configured is absent in exactly the deployments (an agent-driven engagement run from the
  macOS app) where nobody edited YAML. The project's deny-by-default principle governs
  capabilities; an audit trail is a safety net, and every other safety net here (the ring, the
  evidence lane, the gates) is on by default. The README already promises it (`README.md:43,
  501`).
- *Why that is acceptable.* The file lives in the per-user config directory, mode `0600`, in a
  `0700` directory, beside the CA key and `config.yaml` (which holds the bus tokens): the same
  trust domain. Its arguments are redacted by the shared vocabulary and capped; it holds no
  token and no body. It does name hosts, URLs, flow ids and paths (Residual risks 5), which is
  engagement metadata, so `off` is one key and one env var.
- *Quiet first run.* On success the operator sees exactly one `info!` line at startup, target
  `aitm::audit`, naming the control file path and nothing else; no token, no label, no
  per-write line. The line goes through `tracing` (the channel `proxy listening` uses today),
  never `println!`, so it cannot corrupt the stdio transport's stdout framing any more than the
  existing startup lines do. Failures are `warn!` and throttled (Design 9).
- *Test hermeticity.* A default-on file must not be written by test runs. `cargo test` never
  builds the writer (only `main.rs` does, and `assemble()` does not). Binary-spawning
  harnesses must pass `AITM_AUDIT_LOG` (path or `off`); the e2e harness is updated (Files). A
  harness that forgets appends to the operator's file, which is noise, never a failure.

**Alternatives rejected.** *Default off*: the status quo. *On only when an agent token is
configured*: the web link's agent token always exists, so it is "on" anyway and harder to
explain. *Default beside the config file in use*: hermetic for the e2e harness, but the macOS
embedded core launches with a per-launch temp config (`EmbeddedCore.swift:172, 345-352`), so
its audit would land in an orphaned temp directory on every launch.

### 4. Path, permissions, hardening, and boot policy (Q3, Q6)

**Default path** is `Default.resolved_path()`; per-user, absolute. If the platform yields no
config or home directory, `default_aitm_dir()` falls back to a CWD-relative `.aitm`; the audit
log treats a non-absolute resolved path as unusable (a CWD-relative audit file is an
anti-goal), which the boot policy below handles as a bad default.

**Preflight** runs once at boot on each of the three stream paths and creates them:

1. Create missing parent directories mode `0700` (`DirBuilder::recursive`, as
   `FileAuditLog::open` does). An existing parent that is world-writable and not sticky is
   refused (any user could rename or replace the file and redirect the log). A group-writable
   or group- or other-readable parent is allowed: on distributions with per-user groups a
   group-writable `~/.config` is the default, and the file itself is `0600`. (Where the group is
   shared this leaves a same-group attacker able to rename the file; Residual risks 1.)
2. `symlink_metadata` on the file: a symlink, a directory, a FIFO, a socket or a device is
   refused (`is_file()` must hold), so a FIFO cannot make `open` block forever. A regular file
   with `nlink > 1` is refused (a hard link planted by another party).
3. Open `append(true).create(true)` with mode `0600`; then re-`symlink_metadata` the path and
   require the same `(dev, ino)` as the opened handle (closes the swap window; the file is never
   created through a dangling link because step 2 already refused a link).
4. An existing file with any group or other bit is tightened to `0600`; if that `chmod` fails
   (not the owner) the path is refused.
5. Append a newline first when the file does not end in one (a torn tail from a crash or a full
   disk), then the `start` marker (Design 6).

On non-Unix targets steps 1 (mode), 2 (`nlink`), 3 (identity) and 4 are skipped; the file is
created with default ACLs. Documented, not enforced.

**Boot policy (Architect's call).** An *explicit* path (`Path`, from the file or the env) that
fails preflight **fails the boot** with an error naming the path and the reason, before any port
is bound or the browser is spawned: the operator asked for an audit trail, and a silently
missing one is the failure this feature exists to prevent (the CA log is fail-closed for the
same reason). A *default* path that fails preflight (a read-only container, no home directory,
a pre-existing wrong-mode directory) does **not** stop the boot: a new default-on feature must
not turn a working deployment into a refusal to start. The writer starts degraded: one `warn!`
names the path and the reason, `agent.status.durable_audit` reports `enabled: true, degraded:
true`, and each entry is counted as a write failure until the path becomes usable (the writer
retries opening at most once a second, Design 9). `Off` creates nothing.

**Alternatives rejected.** *Always fail the boot*: breaks read-only containers on upgrade.
*Always degrade*: an explicit trail that quietly is not there. *`chmod` the parent directory*:
`aitm` should not edit directory modes it did not create.

### 5. Which entries are written, and into which stream (Q4)

**Decision.** Every audited call is written, once, to one of three streams. The sink sees every
entry the ring appends, including entries a role filter hides from an agent
(`the_durable_audit_sink_keeps_every_entry_even_those_an_agent_may_not_read`, `mcp.rs:5393`,
still holds): the file is never served by the bus, and each line carries `origin` and
`connection_id` so a reader filters.

| Stream | File (base `P`) | Gets | Queue | Size cap |
|---|---|---|---|---|
| `control` | `P` | evidence-lane entries whose origin `is_trusted_control()` (operator, CLI) | 1024 | 4 MiB x (1 active + 4 rotated) = 20 MiB |
| `agent` | `P` with `.agent` before the extension | evidence-lane entries of every other origin | 4096 | 8 MiB x (1 + 5) = 48 MiB |
| `reads` | `P` with `.reads` before the extension | routine-lane entries (successful `Read`), any origin | 2048 | 8 MiB x (1 + 2) = 24 MiB |

For `audit.jsonl` the files are `audit.jsonl`, `audit.agent.jsonl`, `audit.reads.jsonl`; for a
base with no extension (`audit`) they are `audit`, `audit.agent`, `audit.reads`. The routing
function is `stream_for(lane, origin)` in `audit_log.rs`: `Routine` goes to `reads`; `Evidence`
goes to `control` iff `origin.is_trusted_control()`, otherwise `agent`. An origin the classifier
does not know is not trusted, so it lands in `agent` (an evidence entry is never unclassified).
It compares nothing against the agent role.

**Why three, not one.** Volume decides it. An idle web UI makes about 150 calls a minute, all
successful reads; written to one file that is about 65 MB a day, so any realistic cap would be
spent on polling within a day and the evidence rotated out, which is the ring's original defect
moved to disk. A `flow.detail` read is how captured credentials leave, so reads are kept (in
their own, shorter-lived stream) rather than dropped. And the agent is the untrusted principal
(PR 172): with one evidence file an agent that floods refused calls rotates out operator
evidence (`agent.set`, `scope.add`, approvals). With `control` separate it cannot, whatever it
sends, because it cannot produce an operator-origin entry and the origin is server-assigned.

**Sizes (Architect's call).** The control stream is human-rate: 20 MiB is on the order of
fifty thousand entries. The agent stream's 48 MiB is on the order of 135 thousand entries (an
agent fuzzing at 20 requests a second fills it in about two hours; Residual risks 3). Reads'
24 MiB is about nine hours of one idle web UI. The total is at most 92 MiB on disk. These are
constants in `audit_log.rs`, not config (Non-goals).

**Alternatives rejected.** *One file, all entries*: polling erases evidence within a day.
*One file, evidence only*: loses the read trail the PR 171 spec called out (Residual risks 3)
and the web UI's own comment promises ("ring, durable log"). *Dropping reads by command name*
(`flow.list`, `proxy.status`, ...): `flow.detail {body:none}` is both the poll and a header
read, and a name list fails open the day a command is added. *Two streams (evidence, reads)*:
lets an agent flood erase operator evidence. *Per-origin write budgets now*: a real answer to a
sustained flood but a feature of its own (follow-up).

### 6. The line format, markers, and sanitising (Q9)

**Entry lines.** The existing renderer, unchanged: `aitm_ca::entry_to_jsonl`, the seven keys
of `AuditEntry::to_value` (`at` in epoch milliseconds, `origin`, `client_label`,
`connection_id`, `command`, `args`, `result`), one JSON object per line, `\n` terminated. The
existing test `durable_line_has_the_same_keys_as_to_value` (`aitm-ca/tests/audit.rs`) already
pins that parity, so there is one definition of the shape. No schema version and no sequence
number are added to entry lines: adding a key would change `to_value`, which `agent.activity`
and the push share, and an `AuditEntry` field is forbidden.

**Marker lines.** The writer, not the entry renderer, writes two kinds of line that have no
`command` key, so a reader tells them apart by `has(.marker)`:

- `{"marker":"start","schema":1,"at":<ms>,"version":"<crate version>","pid":<n>,"stream":"control|agent|reads"}`:
  the first line of every file the writer creates, and one more at every boot that appends to an
  existing file. It marks a restart (the ring was emptied here) and carries the schema version.
- `{"marker":"gap","at":<ms>,"from":<ms>,"to":<ms>,"dropped":<n>,"failed":<n>}`: written before
  the next successful entry after any entry was lost. `dropped` counts entries refused by a
  full queue, `failed` counts entries lost to write errors, `from`/`to` are the `at` of the
  first and last lost entry. Every lost entry is accounted for in exactly one `gap` line, or,
  if the process ends first, only in the live counters.

**Sanitising (both layers, Architect's call).** `entry_to_jsonl` stays as it is, trusting its
caller. The writer applies a final pass to every entry before rendering, because the ring hook
means any future caller of `AuditRing::append_in` reaches the file with a hand-built entry:

- `client_label`: `sanitize_client_label` (64 characters, controls and invisibles dropped,
  scrubbed), then the strict text pass.
- `args`: cut to `DEFAULT_ARGS_SUMMARY_CAP` bytes plus `…` (work bounded first), then the
  `args` pipeline of Design 14.5 (not `scrub_text`: see Design 14.0), cut again.
- `result.error`: the strict text pass (Design 14.3), cut with `DEFAULT_RESULT_REASON_CAP`
  (1024).
- `command`: at most 128 characters. `connection_id`: at most 64 bytes.
- In `args`, `result.error`, `command` and `connection_id`, a whitespace control becomes one
  blank and every other `char::is_control` character (C0, DEL and C1) becomes U+FFFD.
- Every field then passes the known-secret registry (Design 14.4).

(Amendment 1.) For an entry `record_audit` produced the whole pass changes nothing: every step
is idempotent over the ring's own caps and masks, so honest entries are byte-for-byte what
`entry_to_jsonl` renders (AC17, AC47). The first version of this paragraph said the pass
applied `scrub_text` to `args`; that is wrong, because `args` is JSON text and `scrub_text`
is not safe over JSON text (Design 14.0).

**Log injection.** `serde_json` escapes every character below U+0020, `"` and `\`, so a value
cannot start a new line. It does not escape DEL, the C1 controls (U+009B is a CSI to a UTF-8
terminal) or U+2028/9, so a hostile target echoed into an error reason could drive the terminal
of an operator who runs `cat` or `tail` on the file; the control replacement above closes that.
The file therefore has exactly one `\n` per line and no control byte other than that `\n`.

**Alternatives rejected.** *A `kind` or `schema` key on every entry*: changes the shape the
ring shares. *Markers only in `agent.status`*: a reader of the file alone could not see the
gap. *Hardening `entry_to_jsonl` in `aitm-ca`*: that file also serves the CA's own log and its
tests; the writer is the new choke point, and the renderer keeps one job.

### 7. The hand-off, the queue bound, the counter, and shutdown (Q7)

**The ring hook (in `aitm-core`).** A trait `DurableAudit: Send + Sync + Debug` with
`record(&self, lane: AuditLane, entry: AuditEntry)` (must not block and must not panic; it runs
outside the ring's lock, so calling back into the ring is safe) and `status(&self) ->
DurableAuditStatus`
(`{degraded: bool, dropped: u64, write_failures: u64}`, atomics only). `AuditRing` gains
`attach_durable(&self, sink: Arc<dyn DurableAudit>) -> bool` (set-once, `OnceLock`; a second call
returns `false` and keeps the first) and `durable_status(&self) -> Option<DurableAuditStatus>`.
`append_in(lane, entry)` clones the entry only when a sink is attached, inserts under the lock
as today, **releases the lock**, then calls `sink.record(lane, clone)`. The trait `append`
reaches it through `append_in(Evidence, ..)`. The hook runs outside the lock so a sink can
never deadlock the ring or lengthen its critical section; the cost is that two concurrent
appends may reach a queue in the opposite order to their ring sequence, so file order can differ
from ring order by an in-flight append and `at` (milliseconds) is the order a reader trusts.

**The writer (in `audit_log.rs`).** `AuditLogWriter` implements `DurableAudit`. It owns three
stream writers. Each is a `std::sync::mpsc::sync_channel` of the stream's capacity, one named
OS thread (`aitm-audit-control`, `aitm-audit-agent`, `aitm-audit-reads`), and its own file,
rotation and counters. `record` picks the stream (Design 5) and calls `try_send`.

- **A full queue drops the newest entry** (the one `try_send` returns), increments the
  stream's `dropped` and records the entry's `at` in the pending gap. Newest-dropped keeps
  everything already accepted contiguous and needs no producer-side lock; the gap marker
  records where the hole is. Queues are per stream, so a flood of one stream cannot make
  another drop.
- A writer thread that blocks (a stalled network mount, a hung disk) stops draining only its
  own stream; its producers keep dropping and counting, and nothing waits.
- `record` after shutdown or thread death counts the entry as `dropped`; it never panics or
  blocks.

**The counter, and where it is surfaced.** `status()` sums `dropped` and `write_failures` over
the three streams and sets `degraded` when any stream's writer has died (a writer that exited
through a normal `Close` is closed, not degraded) or its most recent write attempt failed
(cleared by the next success). It is read through
`AuditRing::durable_status()` by `agent.status` (Design 11): the counter lives beside what
`agent.status` already reads, so no new handle is plumbed to `AgentPlugin`.

**Shutdown.** `AuditLogWriter::shutdown(budget) -> ShutdownReport` sends a `Close` message to
each stream (retrying `try_send` until the budget ends, never a blocking `send`), each writer
drains every message queued before `Close`, `sync_data`s its file and exits, and the caller waits
for the threads with `JoinHandle::is_finished` polling until the budget ends. If the budget
ends first (a blocked writer) it returns with `complete: false` and an estimate of the entries
left, and the process exits regardless: shutdown never hangs. `main.rs` calls it with a 2 s
budget in the shared tail, after the browser is reaped, in every non-CLI mode; the `select!` has
ended by then, so blocking that task is harmless. A `warn!` is logged only if the flush was
incomplete. SIGKILL and a crash lose what was queued (at most the queue bounds) and may leave a
torn last line, which the next boot repairs (Design 4 step 5).

**Alternatives rejected.** *One writer thread and one queue*: a stalled disk or an agent flood
would starve operator evidence, and a priority queue needs a custom `Mutex` plus `Condvar`
where three `mpsc` channels reuse a tested primitive. *A tokio task and `tokio::fs`*: ties the
writer to the runtime that is shut down under it, and a runtime worker is exactly where the
call path must not wait. *Drop-oldest*: needs a producer-side lock or a custom ring to pop the
head, and discards the accepted prefix a gap marker is anchored on. *A blocking `send` with a
timeout*: the call path would wait. *`fsync` per entry*: a burst of refused calls would
throttle the drain into drops for no durability a crash does not already take.

### 8. Rotation, retention, and the size cap (Q5)

**Decision.** Classic numbered rotation per stream, std only. For a stream file `F` with cap
`M` bytes and `K` rotated files kept (`K` and `M` from the table in Design 5):

- Before writing a line, if the active file is non-empty and `size + line.len() > M`, rotate.
  An existing oversized file (a restart after a long run) therefore rotates on its first write.
- *Rotation:* `sync_data` the active file; delete `F.K` if it exists; rename `F.(K-1)` to `F.K`,
  down to `F.1` to `F.2`; rename `F` to `F.1`; create a new `F` (`create_new`, mode `0600`);
  write its `start` marker; then write the line that triggered the rotation. The line is
  written **after** rotation, to the new file, so it is never lost to the boundary; no file is
  ever split mid-line.
- *What is kept:* the active file and up to `K` rotated files. *What is deleted:* only the
  oldest rotated file `F.K`, only at the moment a rotation needs its slot, and only if it is a
  regular file. The active file is never deleted or truncated; no file of another stream, and
  nothing outside the three stream names, is touched. A restart appends (`append(true)`, never
  `truncate`).
- *At the cap, when rotation fails* (a rename or create error): the line is written to the
  still-open file, which then exceeds `M` (the cap is soft only while rotation is failing),
  the failure is logged under the Design 9 throttle, and rotation is retried at most once a
  minute. The line is never dropped for being at the cap.
- *Re-check:* at most every 5 s, and at every rotation, the writer compares the path with the
  open handle (`symlink_metadata`, `(dev, ino)`). If the path is gone or names another file
  (the operator removed it, an external `logrotate` renamed it) it reopens through the
  Design 4 preflight and writes a `start` marker; a symlink or non-regular file at the path is
  refused and counted as write failures. Without this the writer would keep appending to an
  unlinked inode and the lines would vanish silently.

**Time.** There is no time-based retention: only size. How long history survives depends on
call volume, and the sizes in Design 5 say how long at typical volumes.

**Alternatives rejected.** *Timestamped rotated names*: needs a date formatter (`aitm` has no
`time` dependency) and gives a name that sorts less obviously than `.1`. *Copy-truncate
rotation*: loses lines between the copy and the truncate. *Rotating after the write*: the
oversized line would be in the old file, and a failed rotation would then surface as a lost
write.

### 9. Runtime write errors, disk full, and a vanished path (Q6)

**Decision.** Best effort; never break or slow a command; never retry in a way that stalls.
The writer makes **one** attempt per entry. On a write error (disk full, I/O error, the path
removed, permissions changed) it drops that entry (`write_failures += 1`), closes the handle,
sets `degraded`, and records the entry's `at` in the pending gap. The next entry attempts a
reopen (the Design 4 preflight) if at least one second has passed since the last attempt, and
fails fast otherwise, so a broken disk costs one `open` a second, not one per entry. On the
first success after failures the writer writes the `gap` line (`failed: n`, plus any `dropped`),
clears `degraded`, and logs one `info!`. Failures are logged at `warn!` target `aitm::audit`
once, then at most once a minute with the count since the last line, naming the path and the
error kind. A command is never told, refused or delayed. The ring and the push still have the
entry.

### 10. Wiring into every server (Q8) (Architect's call)

**Decision: option (b), the sink is attached to the shared `AuditRing`.** In `main.rs`, after
the one-shot CLI branch returns and before any port is pre-bound, `audit_log::start(&cfg,
&audit_ring)` resolves the setting (`Off` returns `Ok(None)`), runs the explicit/default boot
policy of Design 4, builds the `AuditLogWriter`, attaches it with `attach_durable`, logs the one
`info!` line, and returns the writer for the tail's `shutdown`. `audit_ring` is already named
in `main.rs`'s destructure of `Assembled`. Nothing else changes: `with_shared_governance`,
`build_servers`, `wire::Governance` (and its doc-example literal), `bridge.rs` and every
`McpServer` stay as they are, because the ring `Arc` they already share carries the sink.

*Why (b).* (1) One choke point and one writer set for the primary server, the `aitm web` server
and the `aitm tui` loopback agent server. (2) A future third server that shares the ring (the
only way it gets governance and `agent.activity`) is audited with no line of wiring, so it
cannot be forgotten. (3) The counter sits beside what `agent.status` reads. (4) The diff in
the contested crates is zero executable lines: `aitm-mcp` changes comments only; the new code
is a new module in `aitm`, a small extension in `aitm-core`, and a few hunks in `main.rs`.

*Why not (a)* (`with_durable_audit` on each server in `main.rs` and `build_servers`): three
attach sites that a fourth server must copy; each server would need its own writer (three
writers, three sets of counters, three rotators racing on one file) or a shared `Arc` handed to
each; `build_servers` would need a new parameter or a field on the sealed `Governance`, which
ripples through its doc-example literal and its tests; and the counter would live on a server
that `AgentPlugin` cannot see. (c) *Attach inside `with_shared_governance`*: it only receives the
state and the ring, so the sink would have to ride the ring anyway.

**Residual (stated, not hidden).** Sharing the ring is still "by convention" on the bare path
(PR 162's recorded residual): a server built without `with_shared_governance` has a private
ring and is neither governed nor audited. This change does not make that worse and does not fix
it. `McpServer::with_durable_audit` remains a per-server tap used by tests; attaching both it
and a ring sink writes each entry twice, and production uses only the ring sink.

**The TUI's in-process operator server stays unaudited (Architect's call).** It is built by
`server(..)` alone with a private ring on purpose (`tui.rs:333-344`); the hook rides the shared
ring, so it is not covered, and a test pins that. It is the operator's own hands on their own
keyboard, which is a different threat class from an agent, and recording it would need a
signature change on `build_servers` or the sealed `Governance`. Operator-token clients of the
same process (the macOS app, the web operator link, `aitm-tui --bus`) are audited because they
arrive on the shared-ring servers. Named follow-up "audit the TUI-facing operator server".

### 11. `agent.status` surface (Q7)

**Decision.** One additive result field, `durable_audit`, an object:

| Key | Type | Shown to |
|---|---|---|
| `enabled` | bool | every role: a sink is attached |
| `degraded` | bool | every role: any stream's writer stopped or its last write failed |
| `dropped` | int | trusted control only |
| `write_failures` | int | trusted control only |

When no sink is attached it is `{enabled: false, degraded: false}` plus, for trusted control,
`dropped: 0, write_failures: 0`. The viewer split uses `host.caller_is_trusted_control()`, the
sanctioned predicate. *Why split:* PR 172 accepted one residual channel (an agent learns the
count and timing of hidden operator entries from its own evictions) and named its fix a
follow-up; a global drop counter that an agent can read and that moves when anyone's entry is
dropped would be a second instance of it. `enabled` and `degraded` describe the disk, not
anyone's activity. The path is never reported (an agent need not learn the host's layout).

The result `TypeDesc` declares `durable_audit` as a required object whose members are
`enabled` and `degraded` (required) and `dropped` and `write_failures` (optional), because the
generated `outputSchema` forbids undeclared properties. The command description string is
unchanged (so `aitmproxy-plugin/docs/tool-reference.md`, which lists only parameters and the
description, needs no edit); the field descriptions carry the explanation. No consumer changes:
the TUI (`model.rs:805-820`), the macOS app (`Activity.swift:129-148`) and the web store
(`app.ts:855`) read the keys they know and ignore the rest.

**Alternatives rejected.** *A new command (`audit.status`)*: a new tool ripples into pinned
tool lists, and gives agents a second route to the same facts. *Counters visible to every role*:
above. *Reporting the path or per-stream numbers*: path disclosure, and nobody consumes them yet.

### 12. A reader (Q10) (Architect's call)

**Decision: documentation only.** The README documents the files, the line format, the markers
and `jq` recipes (`jq -c 'select(.marker|not)' audit.agent.jsonl`; `cat audit*.jsonl | jq -s
'map(select(.command)) | sort_by(.at)'`), and the startup line tells the operator where the
control file is. No `aitm audit` subcommand and no registry command.

*Why.* A reader is a feature: a follow mode must survive rotation and reopen, formatting is a UI
decision, and the three-stream merge is ordering-sensitive; each needs its own tests and none
is needed to make the record durable. The format should soak first. A bus command that returns
file contents or the path would hand an agent a route to the operator-only trail and to the
host filesystem (anti-goal), so any later reader is a CLI-only verb dispatched like
`operator-token` in `parse_mode`, outside the registry.

### 13. Docs and comments (Q11)

- `README.md`: add a short "Audit log" subsection near the config example (`README.md:187-194`):
  default path per platform, the three files, `mcp.audit_log` and `AITM_AUDIT_LOG` including
  `off`, the size bound, the line and marker shapes, `jq` recipes, and the honest limits
  (best-effort, not tamper-evident, `aitm tui`'s own UI and one-shot CLI commands not
  recorded). Make `README.md:43` and `501` precise instead of absolute. (Amendment 1) It also
  states what is never written (tokens, auth and cookie headers and their values, credential
  shapes), that header values other than a short benign list show as `<redacted>` while the
  names stay, and what cannot be caught (Design 14.8).
- `INSTALL.md`: a five-line "Audit log" note after the config example (`INSTALL.md:44-56`)
  saying where the files are and how to turn them off.
- `crates/aitm-tui/README.md` mentions `operator_token` only for connection and needs no
  change.
- Stale comments to fix, comments only: `server.rs:1057-1061` ("opt-in by config", "the CA
  plugin's log is a subset of this one format"), `server.rs:1136-1137` ("Opt-in: when absent"),
  `server.rs:1917-1919` ("the optional durable sink"); `aitm-core/src/audit.rs:3-9` ("the same
  one format the CA plugin's log is a subset of"), `:60-61` and `:522-523` ("once one is
  attached": it is now the default-on file); `aitm-ca/src/audit.rs:158-165` and `:191-197`
  ("one format ... CA entries are a subset", "reuses the same ... log the CA log uses").
- The PR 171 plan's Shipped follow-up text is history and is not edited; this change's own
  Shipped section records its closure.

### 14. Strict redaction on disk (Amendment 1)

**Requirement.** Matt: no token, secret or credential value ever reaches `audit.jsonl` (or its
siblings): the bus/operator and agent tokens, any Authorization, Cookie, Set-Cookie or auth
header, PoC credentials, and anything the existing scrubber flags. The security panel reviews
this path first. "Airtight" means: every credential class named is covered by a structural or
literal rule, not by a heuristic; 14.8 lists what no rule can catch.

#### 14.0 What reading the code found

| Leak shape | Today | Closed by |
|---|---|---|
| A header as an array pair `["Cookie","foo=bar"]`, `["Authorization","Basic dXNlcjpwdw=="]` or an object `{name, value}` | `redact_value` drops a value only when its **key** is secret (`server.rs:2453-2468`); the leaf `foo=bar` has no secret key and no `Bearer`/`Authorization` prefix | 14.2 rule S |
| A header with an innocuous name in a name-to-value map: `request.send` `headers` and `flow.mutate` `edits.headers` are string maps (`mutate.rs:64-69, 124-132`) | leaks | 14.2 rule D |
| `Cookie:` or `Set-Cookie:` lines in free text; a value ends at the first `;`, so later cookies leak; a quoted cookie value (PR 171 Residual risks 14) | leaks (`redact.rs:75` masks only `Authorization` lines) | 14.3 P2 |
| `Basic <base64>` outside an `Authorization` line | leaks | 14.3 P3 |
| URL userinfo `https://user:pass@host` | leaks | 14.3 P4 |
| A bare JWT, PEM block or vendor key with no `key=` frame | leaks | 14.3 P5 |
| `poc.run` `vars` named `pass`, `pw` (`runner.rs:996-1001`); `form` fields | leaks (neither word is in the vocabulary) | 14.3 P6 and 14.2 rule S |
| `browser.type {selector, text}` with `selector: "#password"` (`browser/commands.rs:190-215`): the secret is in `text`, named by a sibling | leaks | 14.2 rule S |
| The five configured tokens, wherever they are echoed | leaks | 14.4 registry |
| **This spec's own Design 6:** `scrub_text` over the JSON-rendered `args` text | not idempotent and not JSON-safe: the `Authorization` pass is `.+` (`redact.rs:75`), which stops only at a real newline, and the `Bearer` pass is `\S+` (`redact.rs:79`). In JSON text a line break is the two characters `\r\n` and a value is followed by `"}`, so a second pass over the honest text `{"note":"Authorization: [redacted]"}` consumes `[redacted]"}` and writes `{"note":"Authorization: [redacted]` | 14.5 (`scrub_text` and every new pass run on **decoded string content only**, never on JSON text) |

What was read to check that no existing expectation moves: the two `redact_value` tests
(`mcp.rs:3284-3420`: `Authorization` under `headers` becomes absent, `keep-this` survives,
`[redacted]` appears; `audit_integrity.rs:455-520`: `X-Session` is dropped, `author=bob`
survives); the grep over every test, fixture and script for the new key words (`passphrase`,
`private_key`, `access_key`, `pass` and `pw` as keys: no hit outside unrelated verdict strings
such as `== "pass"`); and `tests/e2e/audit/test_audit_log.py:345-360`, which asserts
`X-Audit-Marker` survives verbatim. **That one assertion contradicts rule D by design** and is
the only existing test expectation this amendment changes (14.2, AC59).

#### 14.1 Where each rule lives

| Rule | Home | Why there |
|---|---|---|
| Text passes P1 to P6, `is_secret_key_strict`, the benign-header test | **new** `crates/aitm-core/src/redact_strict.rs` (`pub mod redact_strict;` in `lib.rs`) | `regex` is an `aitm-core` dependency and not an `aitm` or `aitm-mcp` one, so putting them anywhere else would add an edge to `Cargo.toml` and `Cargo.lock`. A new file leaves `redact.rs`, `is_secret_key` and `scrub_text` untouched; the new passes call their public API (`scrub_text`, `is_secret_key`) and add to it |
| Structural rules S and D, the sibling rule, the bounded traversal, `redact_value` | **new** `crates/aitm-mcp/src/redact_args.rs` (`pub mod redact_args;` in `lib.rs`) | `redact_value` works on `serde_json::Value`, which `aitm-core` does not depend on. A new file keeps the contested `server.rs` hunk to a deletion plus one import. It is `pub` so the writer can reuse the same function |
| The call-path hunk | `crates/aitm-mcp/src/server.rs`: delete `redact_value` and the local `is_secret_key` (now only used by it, and dead code under `-D warnings`), add `use crate::redact_args::redact_value;`, and change the one reason line in `record_audit` (`server.rs:1954`) from `aitm_core::redact::scrub_text(reason)` to `aitm_core::redact_strict::scrub_strict(reason)` | `args_summary` and the reason are made there, so the ring, the push and the file are equally clean |
| The known-secret registry, the field pipeline, the tolerant JSON-text scan | `crates/aitm/src/audit_log.rs` (or a submodule of it) | disk only: the registry is the file's own net, and the writer is the last line for an entry from any caller of `AuditRing::append_in` |

**Alternatives rejected.** *Editing `redact.rs`*: the coordinator's constraint and the above;
the only thing that truly needs `mask_secret_pairs`'s internals is a stricter key predicate,
which P6 covers for the few extra keys with its own small scan. *Writer-only structural
redaction*: `args_summary` is often cut at 512 bytes, so the writer usually cannot parse it,
and the ring and push would stay leakier than the file. *A schema flag on `ParamDef` marking
header parameters*: ripples through every command's schema literal for what a key name already
says.

#### 14.2 Header collections: rule S everywhere, rule D inside header collections (Architect's call)

**Rule S (structural, container-agnostic).** Anywhere in the arguments:
- an array of exactly two strings whose first element `is_secret_key_strict` has its second
  element replaced by `"<redacted>"` (`["Cookie","foo=bar"]` becomes `["Cookie","<redacted>"]`);
- an object with a string member `name`, `key`, `header`, `field`, `selector` or `label` whose
  value `is_secret_key_strict` has its members `value`, `val`, `text`, `data`, `content`,
  `input`, `keys` and `string` replaced by `"<redacted>"`
  (`{"selector":"#password","text":"hunter2"}` and `{"name":"Cookie","value":"x"}`).
Names and every other member stay.

**Rule D (default-deny inside header collections).** A *header collection* is, at any depth,
(a) an object under a key named (case-insensitively) `headers`, `header`, `request_headers`,
`response_headers`, `req_headers`, `resp_headers` or `http_headers`, or (b) an array under such
a key whose elements are two-string arrays or objects with a `name`/`key`/`header` member and a
`value` member. Inside one, a header's value is kept **only if its name is benign and not
`is_secret_key_strict`**; otherwise it is replaced by `"<redacted>"`, the same literal a
secret-named key already produces. Names stay visible. A kept value still passes the strict text
pass (a `Referer` carrying `?token=` is masked inside).

**Benign names** (exact, case-insensitive): `accept`, `accept-charset`, `accept-encoding`,
`accept-language`, `accept-ranges`, `access-control-request-headers`,
`access-control-request-method`, `cache-control`, `connection`, `content-disposition`,
`content-encoding`, `content-language`, `content-length`, `content-type`, `date`, `dnt`,
`expect`, `forwarded`, `host`, `if-modified-since`, `if-unmodified-since`, `origin`, `pragma`,
`range`, `referer`, `sec-websocket-extensions`, `sec-websocket-protocol`,
`sec-websocket-version`, `te`, `transfer-encoding`, `upgrade`, `upgrade-insecure-requests`,
`user-agent`, `via`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-port`,
`x-forwarded-proto`, `x-http-method-override`, `x-original-url`, `x-real-ip`,
`x-requested-with`, `x-rewrite-url`; and the prefixes `sec-fetch-` and `sec-ch-`. The list
keeps the routing and override headers an injection test sends, because a header-injection
payload is the evidence this log exists to keep.

**Evidence cost, stated plainly.** The value of every other header (`X-Audit-Marker`, a vendor
or custom header, a bespoke debug header) no longer appears in the ring, the push, or the file;
only its name does. An operator reviewing "what did the agent send" sees
`{"X-Custom":"<redacted>"}`. The capture store keeps the real request (`flow.detail`), so
nothing is lost to the investigation, only to the audit copy. Matt asked for strict, and rule S
alone cannot know that an application's `X-Debug-Access` carries a password. Rule D is the only
way to make "no credential in any header" true by construction.

**Existing-test impact (one).** `tests/e2e/audit/test_audit_log.py:349` asserts
`hdrs.get("X-Audit-Marker") == marker` ("non-secret header ... survives verbatim"). Under rule D
that value is `<redacted>`. That single assertion is changed (AC59) to expect `KEY_REDACTED` and
that the name `X-Audit-Marker` is still present; the `Content-Type` assertion beside it is
unchanged because `content-type` is benign. The entry is still found by the marker in `path` and
`body`, which survive. The cargo suites are unaffected (read: `mcp.rs:3304`,
`audit_integrity.rs:472`, both secret-named).

**Alternatives rejected.** *Rule S alone* (the sibling or preceding-name variant): zero
test impact and no evidence cost, but it cannot see a credential under an innocuous name; kept
as the container-agnostic core because rule D only reaches header collections. *Rule D alone*:
misses `browser.type`, `{name,value}` objects outside a headers key, and form descriptors.
*Allowlisting by prefix `x-`*: nullifies D. *Hiding header names too*: names are not secret and
the operator needs them.

#### 14.3 Strict text passes (`aitm_core::redact_strict::scrub_strict`)

`scrub_strict(text: &str) -> String` runs `redact::scrub_text` first (unchanged), then the
passes below, each linear in the length of the text, none changing a character outside the
span it masks, all idempotent (`scrub_strict(scrub_strict(x)) == scrub_strict(x)`), all
replacing with the literal `[redacted]`. It runs on **plain** text: a decoded string leaf, an
error reason, a label, an id; never on JSON text (14.0, 14.5).

- **P2 header lines.** The name `authorization`, `proxy-authorization`, `cookie`, `cookie2` or
  `set-cookie` (case-insensitive, preceded by a start or a character that is not an ASCII
  alphanumeric, `_`, `.` or `-`) followed by optional blanks and `:` masks the **rest of the
  line** (to a real CR or LF, or the end of the text). At the **start of a line**, any name that
  `is_secret_key_strict` does the same (`X-Api-Key: a b c`, `X-Auth-Token: ...`), except that
  the `host:port` exemption `scrub_text` documents applies here too (`auth.example.com:8443` at
  the start of a line is a host, not a header). Prose such as
  "the Cookie header" has no `:` and is untouched. This closes the cookie-after-the-first-`;`,
  quoted-cookie and `Digest username=..., response=...` shapes.
- **P3 Basic credentials.** `basic` followed by blanks and a token of at least 8 characters
  from the base64 alphabet masks the token **only when** it decodes (leniently, no padding
  required) to bytes containing `:`, the `user:pass` shape; `basic information` has no such
  token and survives. `negotiate` or `ntlm` followed by a token of 16 or more base64
  characters masks the token. (`Digest` credentials are a list, not a token; they are caught as
  an `Authorization` line by P2.)
- **P4 URL userinfo.** In `scheme://userinfo@host`, with `userinfo` the text up to the first
  `@` and no `/`, `?`, `#`, blank or quote in it: with a `:` the part after the first `:`
  becomes `[redacted]` and the user name stays (`https://user:[redacted]@host`); with no `:` the
  userinfo is masked only when it is 20 or more characters or matches a P5 shape (`https://
  ghp_...@github.com` is masked; `ssh://git@github.com/o/r` is not).
- **P5 credential shapes.** Distinctive prefix, fixed alphabet, minimum length, ASCII word
  boundary on both sides: a JWT (`eyJ` + base64url, two dots, each of the first two segments of
  at least 8 characters); a PEM block from `-----BEGIN ` ... `PRIVATE KEY-----` through the
  matching `-----END ... PRIVATE KEY-----` or the end of the text; an AWS access key id
  (`AKIA`, `ASIA`, `AGPA`, `AIDA`, `AROA`, `ANPA` or `ANVA` + 16 of `[A-Z0-9]`); a GitHub token
  (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + at least 36 of `[A-Za-z0-9]`; `github_pat_` + at
  least 22 of `[A-Za-z0-9_]`); a GitLab token (`glpat-` + at least 20 of `[A-Za-z0-9_-]`);
  a Slack token (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-` + at least 10 of `[A-Za-z0-9-]`);
  a Stripe key (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` + at least 16 of `[A-Za-z0-9]`);
  an `sk-` API key (`sk-` + at least 32 of `[A-Za-z0-9_-]`, which covers `sk-proj-` and
  `sk-ant-`); a Google API key (`AIza` + 35 of `[0-9A-Za-z_-]`).
- **P6 extra key vocabulary** (`is_secret_key_strict`: everything `is_secret_key` says, plus the
  needles `passphrase`, `private_key`, `private-key`, `privatekey`, `access_key`, `access-key`,
  `accesskey`, `signing_key`, `signing-key`, and the whole segments `pass`, `pw`, `otp`, `totp`).
  A `key=value`, `key: value` or `"key":"value"` pair whose key matches only the extras is masked
  with the same value rule `scrub_text` documents (a quoted value to its closing quote; an
  unquoted one to a blank, `&`, `;`, `,`, quote or `}`). The same predicate decides keys in
  14.2. These words are **not** added to the shared `is_secret_key`: that would change the
  scanner's, the findings store's and the PoC builder's output, and the grep above shows they
  are not needed to keep any existing test green, but they are not mine to change.

**False-positive discipline (the over-scrub lesson).** Every shape needs a prefix and a minimum
length, and no pass fires on a bare hex string, a UUID, a hostname, a `host:port` or an ordinary
URL. The benign table of AC44 and AC56 (flow ids, a 64-hex hash, `auth.example.com:8443`,
`ssh://git@github.com/o/r`, `basic information`, the `Cookie` header named in prose, a short
`sk-prod-eu-1` slug, `author=bob`, ordinary JSON and a PoC YAML with `{{var}}` placeholders) must
come through byte for byte. A pass is wrong, not the table, when one of them changes. Known
over-redaction, accepted as the safe direction: prose such as `pass: ok` loses `ok`, and a
`Cookie:` mentioned mid-sentence loses the rest of its line.

#### 14.4 The known-secret registry (A)

**What it is.** `SecretRegistry` in the writer module: an `Arc`-shared, thread-safe set of
secrets that the writer masks in every string field **by exact value**, independent of any `key=`
framing, `Bearer` prefix or header name. Replacement is `[redacted]`.

**What is registered, and where (five sources plus the environment).**
1. The transport token of `cfg.mcp.transport` (`LoopbackTcp` or `StreamableHttp`), label
   `mcp.transport.token`: by `start`, which receives `cfg`.
2. `cfg.mcp.operator_token`: by `start`.
3. `cfg.mcp.agent_token` when set: by `start`.
4. The web agent bridge token (`web::WebSettings.token`, resolved in `main.rs` before the
   config is loaded): passed to `start` as an argument.
5. The fresh per-run **operator bridge token**, minted by `web::generate_token()` inside the
   `web_server` block of `main.rs`, after `start` ran: registered **late**, through
   `AuditLogHandle::generate_bridge_token()`, which calls `web::generate_token()` and registers
   the result before returning it. The `web_server` block calls that instead of
   `web::generate_token` directly (one expression changes; `web/mod.rs` is not edited). With the
   audit off the handle is absent and `web::generate_token` is called as before. Nobody can use
   a token before it is printed, so registering before returning cannot race a use.
6. The environment: every variable of the process, taken once at `start`, whose name contains
   (case-insensitively) `token`, `secret`, `password`, `passwd`, `credential`, `api_key`,
   `apikey`, `private_key`, `passphrase` or `access_key` (`AITM_WEB_TOKEN`, `GITHUB_TOKEN`,
   `AWS_SECRET_ACCESS_KEY`, ...). The environment lookup is injected so tests supply their own.
   Names such as `SSH_AUTH_SOCK` are deliberately not matched.

**Forms.** Each secret is stored in its raw form and, when different, its JSON-escaped form
(the way `serde_json` writes it inside a string), its percent-encoded form (unreserved
characters kept, the rest as `%XX` in upper case, and in lower case when that differs), and all
are masked longest first. A secret that is a substring of the mask literals (`redacted`) is
ignored, so masking is idempotent.

**Minimum length (decided).** A secret of 8 or more bytes is masked as a substring anywhere. One
of 4 to 7 bytes is masked **only as a whole token**: bounded on both sides by a character that is
not an ASCII alphanumeric, `_`, `-` or `.`, or by the edge of the field. One of fewer than 4
bytes is not literal-masked at all. Substring-masking a 3-byte token such as `abc` would corrupt
every word that contains it. A shorter secret is still caught wherever the other rules reach it
(`token=abc`, `Bearer abc`, a secret-named header or key), and one `warn!` per registration
(target `aitm::audit`) says that the source `mcp.operator_token` is shorter than 8 characters and
is only partly covered by value masking. **It names the source label and the threshold, never
the value and never its length.**

**API and lifetime.** `register(&self, source: &str, secret: &str) -> Registration`
(`Registration` is `Substring`, `WholeToken` or `Ignored`, no value in it) and `mask(&self, text:
&str) -> String`. The set is a copy-on-write snapshot behind a lock: `register` builds a new
snapshot and swaps it, and every `mask` call on any writer thread clones the current snapshot
first, so a registration made while the writer runs is seen by the next field it masks. Masking
happens on the writer thread when the entry is written, so an entry queued before a registration
is masked if the writer reaches it after. Registration is not retroactive for lines already on
disk. The registry is held by the writer and by the `AuditLogHandle` that `start` returns.
`Debug` prints only a count (`SecretRegistry { secrets: 6 }`); there is no `Display`; no
`warn!`, error or panic message carries a secret.

**Cut secrets.** Producers cap a field and the cap can cut a registered secret in half. After
every cut the writer masks a trailing fragment: if a field ends with a prefix of 6 or more bytes
of a registered secret (of 8 or more), that fragment is masked too (the source's own passes run
before its cap, so only registered secrets need this).

**Alternatives rejected.** *No registry* (rely on `Bearer`/`token=`/`Authorization` framing): a
token echoed under an innocuous key, in `#t=<token>` or in a URL path is not framed, and these
five values are exactly what Matt named. *Registering in the ring too*: the ring is memory, and
the requirement is disk. *A regex alternation of the secrets*: `aitm` has no `regex`
dependency, and a handful of `str` scans per field on the writer thread is cheaper than a new
edge. *Substring-masking every length*: corrupts text. *Refusing to boot on a short token*:
a lab token like `tok` is legal today.

#### 14.5 The writer's field pipeline (Amendment 1; replaces the Design 6 sanitising of `args`)

For each entry, on the writer thread, in this order:
1. **Bound.** Each string field is first cut to 64 KiB (work bound).
2. **Pass.**
   - `args`: if the text parses as JSON, apply `aitm_mcp::redact_args::redact_value` (the
     source's own function: rules S and D, the leaf text pass) and render the result. If it does
     not parse (it was cut at the cap, or it is not JSON) run the **tolerant JSON-text scan**:
     walk the text; outside string literals accept only JSON structure characters, blanks,
     number characters and the words `true`, `false`, `null`, and on anything else give up and
     treat the whole text as plain; inside a literal, decode the content (a literal cut off by the
     end of the text is decoded as far as it goes), apply `scrub_strict`, and re-encode with the
     escaping `serde_json` uses, so an unchanged literal is byte-identical; a literal followed by
     `:` is a key, and when it `is_secret_key_strict` the next literal is replaced by
     `<redacted>`. Structure characters are never touched, so what parsed before still parses.
     Non-JSON text goes through `scrub_strict` as plain text.
   - `result.error`, `client_label`, `command`, `connection_id`: `scrub_strict` (the label also
     through `sanitize_client_label`).
3. **Registry** (14.4), including the trailing-fragment mask.
4. **Controls** (Design 6): whitespace controls to a blank, other controls to U+FFFD.
5. **Cap** to the Design 6 sizes, then the trailing-fragment mask again.
6. **Render** with `entry_to_jsonl`.

For an entry `record_audit` produced, steps 2 to 5 are the identity (AC17, AC47).

#### 14.6 Bounded work at the source

`redact_value` runs on the call path. Today it scrubs every leaf in full, so one 16 MiB string
costs a pass over 16 MiB, and eight more passes would multiply that. It becomes bounded: a leaf
is examined only up to its first 4 KiB, text beyond which is dropped and replaced by the single
character `…`, and once 64 KiB of text has been examined in total every later string leaf is
replaced by `…` (numbers, booleans, nulls and names are free). This cannot change what an entry
shows: the rendered `args` is cut at 512 bytes, so no byte past the first 4 KiB of a leaf, and
no leaf after 64 KiB, can reach the entry; a value cut by the examined bound is masked as an
unquoted value (over-redaction, never a leak). The traversal follows the object's own
iteration order, which is deterministic, so the same arguments always give the same entry.

#### 14.7 The proof (D)

Four layers, each a test that fails when its rule is removed:
1. **Unit** (`crates/aitm-core/tests/redact_strict.rs`): every pass with exact input and output
   literals, the benign table, idempotence, hostile-input shapes (AC44).
2. **Source** (`crates/aitm-mcp/tests/audit_redaction.rs`, a real `McpServer`): rules S and D, the
   reason line, ring/push/`agent.activity` parity, bounded work (AC45 to AC47, AC60).
3. **Writer** (`audit_log.rs` tests): registry tiers, forms, late registration, `Debug`, the
   tolerant scan, the cut-secret mask (AC48 to AC54).
4. **Corpus** (`crates/aitm/tests/audit_log_redaction.rs`): 74 secret-bearing shapes, each with a
   unique canary, through the real path (a real `McpServer` call to a stub command -> `record_audit`
   -> ring -> writer -> the three files and every rotated file), plus a benign table that must
   survive byte for byte (AC55 to AC58). The StdPocBuilder row feeds a real built PoC through
   the audit so the builder's own redaction and this one are shown not to fight (R52, AC61).

The corpus assertions are collect-and-assert: every offending row is listed in one failure
message, so one run shows every leak. A canary is `CNRY` + the row number as two digits + `x` +
eight hex digits; for a shape row the canary is the shape's body built by the recipe in AC55.

#### 14.8 What "airtight" means, and what no rule catches

Covered by a structural or literal rule: every configured token and every environment secret
(by value, in three encodings, mid-field and cut); every header value in any container shape
(by name, by sibling or preceding name, or by default-deny); every `Authorization`,
`Proxy-Authorization`, `Cookie`, `Cookie2` and `Set-Cookie` line wherever it appears in text;
`Basic` credentials, URL userinfo; the credential shapes of P5; every key the shared and extra
vocabularies name, in pairs, JSON, forms and PoC `vars`. **Not catchable by any rule:** a bare
credential with no frame, no registered value and no known shape (`my password is hunter2`
typed into a free-text field under an innocuous key; an application-specific session id in a
body); a secret carried in a non-string under an innocuous key; a secret split by the 512-byte
`args` cap where the first half is all that remains (the source masks before it cuts, so a
fragment is what is left, which is fine for an unregistered value and handled for a registered
one); and a short token in an unframed position (14.4). These are Residual risks 14 to 18.

## Semantics changes by surface

| Surface | Changes | Does not change |
|---|---|---|
| Process boot (`aitm`, `aitm web`, `aitm tui`) | Three files appear under the config dir; one `info!` startup line; an explicit unusable path fails the boot before any port is bound; an unusable default path warns and runs degraded | `Off` creates nothing and logs nothing; `aitm <subcommand>` builds no writer |
| `agent.status` | Additive `durable_audit` object (Design 11), counters for trusted control only | `policy`, `actions_last_minute`, `connected_clients`, the description string, `exclude_self` |
| `agent.activity`, the `notifications/aitm/agent` push, the ring, lanes, fair share | None to lanes, fair share, the role filter, or the entry shape. **(Amendment 1) The `args` and `result.error` text changes** (the one source of all three): a header value other than the benign list reads `"<redacted>"` (names stay); `Cookie`, `Set-Cookie`, `Authorization` and secret-named header lines in free text are masked to the end of the line; `Basic` credentials, URL userinfo passwords, credential shapes (JWT, PEM, AWS, GitHub, GitLab, Slack, Stripe, `sk-`, Google) and the extra keys (`passphrase`, `private_key`, `access_key`, `pass`, `pw`, `otp`, `totp`) read `[redacted]`; a value typed into a `selector` that names a secret reads `"<redacted>"`; a string argument longer than 4 KiB is cut at 4 KiB with `…` (it was already cut at 512 bytes of the whole) | Everything else, including that `args` is a JSON text of the arguments, `flow.detail` (the capture store keeps the raw request), and `flow.detail {id, body:"none"}` which the web UI's poll filter reads |
| Apps that show `args` (macOS `Activity.swift`, web `AgentPanel` and `activity.ts`, the TUI Agent page) | None in code: they show the string or its parsed object and read only `args.body` of a `flow.detail` poll | A header's value in an Activity row is `<redacted>` for a non-benign name where it used to show; an operator wanting it opens the flow |
| `ca.audit_log`, `ca.*` commands, `FileAuditLog` | Doc comments only | Format, location, fail-closed behaviour |
| `config.get` | None (it does not show the audit path) | Shape |
| TUI, web UI, macOS app | None in code. The embedded macOS core writes the default file, shared across launches | Decoders read keys by name |
| Findings, scanner, PoC builder | None: `redact.rs`, `is_secret_key` and `scrub_text` are not edited, so their output and tests are untouched. (Amendment 1) The new key words apply to the audit path only | Everything |
| e2e harness and scripts | `AITM_AUDIT_LOG` is set per run so they stay hermetic. (Amendment 1) `tests/e2e/audit/test_audit_log.py:349` flips to expect `<redacted>` for `X-Audit-Marker` (AC59) | What the rest of them test |
| Operators | Can read the files with `jq` | There is still no command that reads them |

## Rebase hazards with the sibling sessions

Sessions are editing `crates/aitm-mcp` (`server.rs`, `transport.rs`) and the `/bus` bridge
(`crates/aitm/src/web/bridge.rs`). This change touches `server.rs` in three comment-only hunks
(about 1057-1061, 1136-1137, 1917-1919) and, **(Amendment 1)**, exactly three executable hunks
for strict redaction, and nothing else there: (a) the one reason line in `record_audit`
(`server.rs:1954`), `scrub_text` to `scrub_strict`; (b) the deletion of `redact_value` and the
local `is_secret_key` (`server.rs:2447-2480`, a pure deletion: both move to `redact_args.rs`);
(c) one `use crate::redact_args::redact_value;`. `crates/aitm-mcp/src/lib.rs` gains one
`pub mod redact_args;` line and `crates/aitm-core/src/lib.rs` one `pub mod redact_strict;`
line. `transport.rs`, `http.rs` and `bridge.rs` are not edited. If a sibling edits
`redact_value` in place meanwhile, that is a manual merge into `redact_args.rs`; the orchestrator
checks for it at the rebase. `ConnCtx`, `AuditEntry`, `wire::Governance` and
`tui::build_servers` gain no field and no parameter. The scanner-vocabulary session is idle and
`redact.rs` is not edited: if it later changes what `scrub_text` or `is_secret_key` do, the
strict module rides along and AC44's tables and AC47's idempotence test are the guard. The
contested files that do change:

- `crates/aitm-core/src/audit.rs` (the hook, two methods, doc fixes) and `lib.rs` (one
  `pub use audit::{..}` statement and one `pub use config::{..}` statement; a sibling adding an
  export is a one-line merge) and `config.rs` (`McpConfig` field, one enum).
- `crates/aitm/src/main.rs`: three hunks (the `start` call after the CLI branch, the tail
  `shutdown`, one `use`), no change to `Mode` or `parse_mode`.
- `crates/aitm/src/config_file.rs` (`McpFile` field and `apply`) and `env.rs` (one function).
- `crates/aitm-plugins/src/agent.rs` (`AgentStatus` schema and `invoke`).
- `tests/e2e/aitm_e2e/core.py` `_spawn` (one line): the e2e sessions own it; keep the edit to
  that line and rebase on theirs.
- (Amendment 1) `tests/e2e/audit/test_audit_log.py:349`: one assertion flips (AC59). The e2e
  sessions own the file; the edit is that one expectation and one added `in` check, nothing else.

New code lives in new files (`audit_log.rs`, `redact_strict.rs`, `redact_args.rs`, and eight
new test files). The existing tests named in AC41 are not edited, with the one e2e exception
above. The orchestrator rebases on `main` before dispatching the wiring task and again before
the panel.

## Residual risks

1. **Not tamper-evident, and a same-user attacker can erase it.** `0600` does not stop the same
   user, and there is no hash chain, signature or append-only attribute (an operator can set
   `chflags uappnd` or `chattr +a` outside `aitm`; rotation then fails and the file grows past
   its cap). An agent that runs as the operator's own OS user with a shell tool can read the
   file, as it can already read `config.yaml` and its tokens, or delete it (the writer then
   reopens and marks a `start`, so the deletion is visible as lost history, not as a continuous
   record). This is a best-effort record, not evidence-grade.
2. **A writer outrun by a flood loses entries, visibly.** If a source produces entries faster
   than a stream's writer drains for long enough to fill its queue, the newest are dropped
   (counted, with a `gap` line). Because streams are separate, an agent flood can drop only
   `agent` and `reads` entries; operator and CLI entries (`control`) are untouchable without the
   operator token. The hole is detectable, not preventable.
3. **Retention is size-bounded, so a sustained agent flood rotates out earlier agent
   evidence.** With the defaults that takes on the order of two hours of 20 refused or write
   calls a second for the `agent` stream, and the flood itself is on disk. It cannot reach the
   `control` stream. "Audit write budget" is the follow-up.
4. **Reads are best-effort.** Their stream keeps about nine hours of one idle UI; a `flow.detail`
   read can be forgotten sooner than evidence (PR 171 Residual risks 3, improved, not closed).
5. **Redaction misses now persist.** (Amendment 1: narrowed by Design 14, not removed.) What
   `scrub_text` and the strict passes both let through (PR 171 Residual risks 6, 11, 12, 13:
   a credential with no frame, no registered value and no known shape, the `host:port`
   exemption that leaves `db.password:1234`, malformed unclosed-quote shapes) survives a restart
   in a file. PR 171's Residual risks 14 (a quoted cookie value) is closed by P2. The args also
   name hosts, URLs, flow ids and paths: engagement metadata on disk. The `is_host_port`
   tightening PR 171's plan names becomes more worthwhile. Do not attach the files to a bug
   report unreviewed.
6. **No fsync per line.** An OS crash or power loss can lose recent lines; a process crash loses
   the queued entries; a torn tail is repaired at the next start. Rotation and shutdown sync.
7. **Cross-file order is millisecond-granular, and queue order can differ from ring order** for
   concurrent calls. The ring's private sequence number is not on an entry.
8. **Two `aitm` processes sharing one audit path** are not locked: lines never interleave within
   a line (one `O_APPEND` write per line), but two rotations at once can lose a rotated file.
   Give each process its own `mcp.audit_log`. The default ports already stop two default-config
   cores running together.
9. **Not recorded:** the `aitm tui` in-process UI's own calls, one-shot CLI subcommands,
   protocol-level failures; Streamable-HTTP POST calls are recorded with `connection_id: null`.
10. **`aitm tui` without `RUST_LOG`** has no visible `tracing` sink, so a boot-degrade warning is
    invisible there; `agent.status.durable_audit.degraded` reports it, and nothing renders it yet.
11. **Non-Unix:** modes, `nlink` and identity checks are not enforced.
12. **A network or removable mount** can stall a writer; the call path is unaffected and entries
    drop, counted.
13. **Clock changes** reorder `at`. It is wall-clock milliseconds.
14. **(Amendment 1) A bare credential cannot be caught.** A secret with no frame, no registered
    value and no known shape (`my password is hunter2` typed into a free-text field under an
    innocuous key, an application-specific session id in a body, a number under an innocuous key)
    reaches the file. No rule can see it; every class Matt named is covered (Design 14.8).
    "Airtight" is a claim about those classes, not about all text.
15. **(Amendment 1) Cut secrets.** The 512-byte `args` cap cuts after the source has masked, so
    an unregistered secret that straddles the cap leaves a fragment (it is cut, not masked, and
    the rendered entry never carries more than the first half). A registered secret's trailing
    fragment of 6 or more bytes is masked (14.4); a fragment of 5 or fewer bytes of a registered
    token is not (at most about 20 bits of a 32-hex token).
16. **(Amendment 1) Short tokens.** A configured token shorter than 8 bytes is value-masked
    only as a whole token (4 to 7 bytes) or not at all (under 4), and is otherwise caught only
    where a rule frames it. The warning at registration says so, without the value or its length.
    The registry itself holds the secrets in process memory, as the process already does.
17. **(Amendment 1) Hand-built entries get the net, not the whole structure.** The source's
    rules S and D reach an entry only through `record_audit` or, for an `args` that parses as
    JSON, through the writer's re-application of the same function. A hand-built `args` that does
    not parse (cut or not JSON) gets the tolerant scan: key-named values and every string pass
    `scrub_strict`, but a header collection inside it gets rule S's key part only, not rule D, and
    a scalar under a secret key is not masked. No such producer exists today.
18. **(Amendment 1) Over-redaction, accepted.** Rule D hides every non-benign header value, so
    an operator's own payload headers are not in the audit copy (Design 14.2). `pass:` in prose,
    a mid-sentence `Cookie:`, a `Basic` word followed by something that decodes to text with a
    colon, a short registered token equal to an ordinary word, and the whole rest of a secret-named
    header line all lose text. The flow store keeps the originals.

**What this answers of PR 171's residuals.** (1) A source overwriting its own history: answered
for the file (the ring's eviction no longer erases the record), except for a sustained agent
flood (above, 3). (2) The 32-source table floor: answered for the file, which has no source
table. (3) Reads not evidence-grade: improved by the `reads` stream. (7) `entry_to_jsonl` trusts
its caller: answered by the writer's pass (the renderer itself is unchanged and still trusts a
direct caller). (8) No durability: answered. (10) Every bridge connection is one source: the
file keeps `connection_id` per line, so connections are tellable apart (the ring's eviction
semantics are unchanged). (11) The `host:port` exemption: **not answered**, and worsened by
persistence (above, 5). Unchanged: 4, 5, 9. (Amendment 1) PR 171's residual 14 (a quoted
`Cookie` or `Set-Cookie` value leaks) is closed for the audit path by Design 14.3 P2; its
residuals 6, 12 and 13 remain, narrowed.

## Files

Disjoint groups, so the plan can split tasks. Each line is the one-line reason.

**A. `aitm-core`**
- `crates/aitm-core/src/audit.rs`: `DurableAudit`, `DurableAuditStatus`, `attach_durable`,
  `durable_status`, the hook in `append_in`; doc fixes (Design 13).
- `crates/aitm-core/src/lib.rs`: re-export the new audit and config items.
- `crates/aitm-core/src/config.rs`: `AuditLogSetting` and `McpConfig.audit_log`.
- `crates/aitm-core/tests/durable_audit_hook.rs` (new): the hook's behaviour through the public API.

**B. `aitm` (the writer and its wiring)**
- `crates/aitm/src/audit_log.rs` (new): setting resolution, path derivation, preflight, the three
  stream writers, sanitising pass, markers, rotation, shutdown, `start`, in-module seam tests.
- `crates/aitm/src/lib.rs`: `pub mod audit_log;`.
- `crates/aitm/src/config_file.rs`: `McpFile.audit_log` and its `apply`.
- `crates/aitm/src/env.rs`: `AITM_AUDIT_LOG`.
- `crates/aitm/src/main.rs`: `start` call, tail `shutdown`.
- `crates/aitm/tests/audit_log_config.rs`, `audit_log_wiring.rs`, `audit_log_binary.rs` (new).

**C. `aitm-plugins`**
- `crates/aitm-plugins/src/agent.rs`: `durable_audit` in the result schema and `invoke`; module doc.
- `crates/aitm-plugins/tests/agent_status_durable.rs` (new).

**D. Docs and comments (no executable change)**
- `crates/aitm-mcp/src/server.rs`: three stale comments.
- `crates/aitm-ca/src/audit.rs`: two stale doc comments.
- `README.md`, `INSTALL.md`: Design 13.

**E. Test harness hermeticity**
- `tests/e2e/aitm_e2e/core.py`: `AITM_AUDIT_LOG` into the child environment in `_spawn`.
- `tests/e2e/cli/cli-startup.sh`, `scripts/bus-agent-check.py`, `scripts/tui-live-check.sh`: export
  `AITM_AUDIT_LOG=off` where they spawn the binary (verify each by reading; a miss is noise).
- `crates/aitm/tests/shutdown.rs` (orchestrator amendment): add `AITM_AUDIT_LOG=off` to the child
  `Command`'s environment (the only Rust test that spawns the real `aitm`; obscura-gated). A
  one-line environment addition and an exception to AC41 (the other is the e2e assertion of
  AC59). The coder greps `crates/*/tests` and `tests/` for any other `CARGO_BIN_EXE_aitm` or
  `target/*/aitm` spawn and reports it rather than editing it silently.
- (Amendment 1) `tests/e2e/audit/test_audit_log.py` (line 349): the `X-Audit-Marker` assertion
  flips to `KEY_REDACTED`, plus an `in hdrs` check that the name is still there (AC59). The
  only existing test expectation Design 14 changes.

**F. Strict redaction (Amendment 1)**
- `crates/aitm-core/src/redact_strict.rs` (new): `scrub_strict`, `is_secret_key_strict`,
  `is_benign_header`, passes P2 to P6. `redact.rs` is not edited.
- `crates/aitm-core/src/lib.rs`: `pub mod redact_strict;` (the same file group A edits).
- `crates/aitm-mcp/src/redact_args.rs` (new): `redact_value` (moved from `server.rs`),
  rules S and D, the bounded traversal.
- `crates/aitm-mcp/src/lib.rs`: `pub mod redact_args;`.
- `crates/aitm-mcp/src/server.rs`: the three executable hunks of Rebase hazards (reason line,
  deletion, import), in the same file group D edits for comments.
- `crates/aitm/src/audit_log.rs` (group B's file): `SecretRegistry`, `AuditLogHandle`
  (`generate_bridge_token`, `register_secret`), the field pipeline, the tolerant scan.
- `crates/aitm/src/main.rs` (group B's file): pass the web token to `start`; the `web_server`
  block calls `generate_bridge_token()` instead of `web::generate_token`.
- Tests (new): `crates/aitm-core/tests/redact_strict.rs`, `crates/aitm-mcp/tests/audit_redaction.rs`,
  `crates/aitm/tests/audit_log_redaction.rs`, and AC58 in `crates/aitm/tests/audit_log_binary.rs`.

Group A must land before B, C and F compile against it (F's `redact_strict.rs` is independent of
the ring hook and can start first); D and E are independent of everything. Within B and F,
`audit_log.rs` is one file, so its internals are one task or a strict sequence, and
`server.rs` is edited by D (comments) and F (code), which must be sequenced or done by one task.

## Acceptance criteria

`[red]` means the test fails before the change; `[guard]` pins behaviour that must not change;
`[socket]` needs the Terminal panel. Test names are exact; `P` is a temp directory. Writer
tests run through a small in-module seam (a fake file that can block, fail or succeed, and
shortened intervals) so no test sleeps for the production intervals.

**Config and precedence** (`crates/aitm/tests/audit_log_config.rs`)

1. **AC1** `[red]` `audit_log_key_parses_every_spelling`: absent and `true` give `Default`;
   `false`, `off` and `OFF` give `Off`; `/var/log/aitm/audit.jsonl` gives
   `Path("/var/log/aitm/audit.jsonl")`; `audit.jsonl`, `~/audit.jsonl` and `""` each error with a
   message containing both `mcp.audit_log` and `absolute`; `mcp: {audit_logg: off}` still errors.
2. **AC2** `[red]` `audit_log_env_wins_and_never_silently_disables`: `off|false|0|no|OFF` give
   `Off`; `on|true|1|yes|default` give `Default`; `/tmp/x/a.jsonl` gives that `Path`; with the file
   at `Path("/a/audit.jsonl")`, the values `ofd`, `relative.jsonl` and `""` leave it exactly
   `Path("/a/audit.jsonl")`; with the file at `Off`, env `/tmp/x/a.jsonl` wins; unset leaves the
   file's value.
3. **AC3** `[red]` `stream_paths_follow_the_rule`: `/a/audit.jsonl` gives `/a/audit.jsonl`,
   `/a/audit.agent.jsonl`, `/a/audit.reads.jsonl`; `/a/audit` gives `/a/audit`, `/a/audit.agent`,
   `/a/audit.reads`; `Default.resolved_path()` ends in `audit.jsonl` and has the same parent as
   `CaConfig::default().audit_log`; `Off.resolved_path()` is `None`.
4. **AC4** `[red]` `a_stream_path_equal_to_the_ca_log_is_refused`: `start` with
   `audit_log = Path(ca.audit_log)` returns an error whose text contains `ca.audit_log`, and no
   file is created; `audit_log = Path(<dir>/audit.jsonl)` with `ca.audit_log =
   <dir>/audit.reads.jsonl` (a derived stream path collides) is refused the same way.

**Files, permissions, boot policy** (`audit_log.rs` tests, `#[cfg(unix)]` where noted)

5. **AC5** `[red]` `a_fresh_start_creates_private_files`: with a not-yet-existing nested `P/a/b`,
   `start` creates `P/a` and `P/a/b` mode `0700` and all three files mode `0600`; each file holds
   exactly one line, a `start` marker with exactly the keys `at, marker, pid, schema, stream,
   version`, `schema == 1`, and `stream` equal to `control`, `agent`, `reads` respectively.
6. **AC6** `[red]` `restart_appends_never_truncates`: record `c1,c2,c3` (operator evidence),
   `shutdown`; start again on the same path; record `c4,c5`; `shutdown`. The control file's lines
   are `start, c1, c2, c3, start, c4, c5` in that order (commands read from the lines).
7. **AC7** `[red]` `hostile_paths_are_refused_without_hanging` (unix): each of these makes
   preflight return an error within 2 s: a symbolic link at the path (message contains
   `symbolic link`); a directory at the path (`regular file`); a FIFO made with `mkfifo`
   (`regular file`); a regular file with a second hard link (`hard link`); a parent directory
   mode `0777` without the sticky bit (`world-writable`). A parent directory mode `0775` is
   accepted. A pre-existing regular file mode `0644` starts, and afterwards is mode `0600`.
8. **AC8** `[red]` `an_unwritable_parent_is_an_error` (unix; skipped when the process can write
   into a mode `0500` directory, as root can): preflight returns an error naming the path.
9. **AC9** `[red]` `explicit_fails_the_boot_default_degrades`: `start_at(path, explicit: true)`
   (the seam `start` calls with the resolved path and whether the setting was a `Path`)
   on an unusable path returns `Err` and creates nothing; `start_at(path, explicit: false)` on the
   same path returns `Ok(Some(writer))` attached to a ring whose `durable_status()` is
   `Some(..)`; after one recorded entry `write_failures == 1` and `degraded == true`; a relative
   path is unusable in both cases.
10. **AC10** `[red]` `off_creates_nothing`: `start` with `Off` returns `Ok(None)`, the directory
    stays empty, and `ring.durable_status()` is `None`.

**Entries, streams, format** (`audit_log.rs` tests and `crates/aitm/tests/audit_log_wiring.rs`)

11. **AC11** `[red]` `entries_are_routed_by_lane_and_trust`: on one ring with a writer attached,
    `append_in(Evidence, op_e)` (origin operator), `append_in(Evidence, ag_e)` (origin mcp),
    `append_in(Routine, ag_r)` (origin mcp), `append_in(Routine, op_r)` (origin operator) and the
    trait `append(cli_e)` (origin cli): after `shutdown` the control file's entry commands are
    `[op_e, cli_e]`, the agent file's are `[ag_e]`, the reads file's are `[ag_r, op_r]`. The line
    for `op_e` is present although `op_e.visible_to(Frontend::Mcp)` is false.
12. **AC12** `[guard]` `an_entry_line_has_exactly_the_seven_keys`: a parsed entry line has the
    keys `args, at, client_label, command, connection_id, origin, result`; and
    `line == entry_to_jsonl(&entry)` for an honest entry (`result` is `"ok"` or
    `{"error": reason}`).
13. **AC13** `[red]` `a_real_server_call_reaches_the_file_with_its_connection_id`
    (`audit_log_wiring.rs`, in process): servers built through `tui::server` and
    `tui::with_shared_governance` from one `assemble` with a writer attached to
    `assembled.audit_ring` and **no** `with_durable_audit`; an operator connection calls
    `agent.set {policy:"auto"}` (Sensitive, evidence) and an agent connection calls `flow.list`
    (a successful `Read`). After `shutdown`: the control file's last line is the `agent.set`
    entry with `origin` `operator` and `connection_id` equal to the id that connection's
    `initialize` returned; the reads file's last line is `flow.list`, `origin` `mcp`, with the
    agent connection's id.
14. **AC14** `[red]` `every_server_this_binary_builds_is_audited`: from one `Assembled` with the
    writer attached to its ring, build (1) a primary-shaped server and (2) a web-shaped server,
    each `tui::server(..)` plus `tui::with_shared_governance(..)`, and (3) the agent arm of
    `tui::build_servers` over a `LoopbackTcp` config (nothing is bound; calls go through
    `handle_on`). One `flow.list` on a minted agent connection per server: the reads file holds
    exactly three entry lines with three distinct non-null `connection_id` values. It fails if
    the sink is attached per server and one is skipped.
15. **AC15** `[guard]` `the_tui_operator_server_stays_unaudited`: invoke the `InProcessHandler`
    returned by `tui::build_servers` with a `tools/call` of `flow.list` and one of `agent.status`:
    after `shutdown`, none of the three files has any entry line (each holds only its `start`
    marker), and `ring.len()` is unchanged.

**Sanitising** (`audit_log.rs` tests)

16. **AC16** `[red]` `a_hostile_entry_is_sanitised_before_it_is_written`: one hand-built entry
    (origin `mcp`, so it lands in the agent file) through `append`: `client_label`
    `"web-bridge\u{202E}\n token=LABELSECRET9"`; `args_summary`
    ` password=ARGSECRET9 ` followed by 1 MiB of `x`; `result` `Error` of `"Bearer REASONSECRET9
    \u{1b}[31m \u{9b}2J\u{7f}\nnext"`; `connection_id` 10 KiB of `c`; `command` `"a\nb"` plus 200
    characters. In the written file: none of `LABELSECRET9`, `ARGSECRET9`, `REASONSECRET9`
    appears; the file has exactly two `\n` (the `start` marker line and the entry line); no byte
    below `0x20` other than those two `\n`; the byte pair `0xC2 0x9B` and byte `0x7F` are absent;
    parsed `client_label` has at most 64 chars, `args` at most 515 bytes, `result.error` at most
    1027 bytes, `connection_id` at most 64 bytes, `command` at most 128 chars. (Amendment 1:
    this `args` is not JSON, so Design 14.5 treats it as plain text and `password=` is masked
    in it.)
17. **AC17** `[guard]` `an_honest_entry_is_written_unchanged`: the entry `record_audit` produced
    for a real call (read back from `ring.recent`) is written as exactly
    `entry_to_jsonl(&entry)` (the sanitising pass is a no-op on it). (Amendment 1: this holds
    for an entry whose argument is `{"note":"Authorization: Bearer SECRET47"}` and for one whose
    argument carries escaped `\r\n` line breaks, the two shapes where `scrub_text` over JSON text
    was not a no-op; AC47.)

**Hand-off and failure** (`audit_log.rs` tests)

18. **AC18** `[red]` `a_stalled_disk_never_blocks_the_call_path`: the agent stream's fake file
    blocks inside the write of its first entry. Record agent-origin evidence entry `a0`, wait
    until the fake reports it is inside that write, then record `a1 ... a5095` (5096 in all, the
    4096 queue capacity plus 1000) from the test thread: all calls return within 2 s in total and
    `durable_status().dropped == 999` exactly (`a0` is in the stalled write, `a1 ... a4096` fill
    the queue). Releasing the file and calling `shutdown(5 s)` returns `complete == true`; the
    file's entries are exactly `a0 ... a4096` in order (the oldest are kept, the newest
    dropped), and one `gap` line has `dropped == 999`, `from` equal to `a4097`'s `at` and `to`
    equal to `a5095`'s `at`.
19. **AC19** `[red]` `a_flooded_stream_cannot_starve_another`: with the agent stream's file
    blocked and its queue full (as in AC18), record 10 operator-origin evidence entries and 10
    successful reads: within 2 s, while the agent file is still blocked, the control file shows
    10 entry lines and the reads file 10; `durable_status().dropped` is still 999 (only
    agent-stream drops).
20. **AC20** `[red]` `a_write_error_loses_the_entry_and_marks_the_gap`: a fake file fails the
    next 5 entry writes (`ErrorKind::StorageFull`) then works; record 5 entries, then 1 more
    (reopen interval shortened to zero): `write_failures == 5` and `degraded == true` after the
    5; after the 6th and `shutdown`, `degraded == false`, the file holds a `gap` line with
    `failed == 5` immediately before the 6th entry's line, and no call or `record` panicked.
21. **AC21** `[red]` `recording_after_shutdown_is_counted_never_blocking`: after `shutdown`,
    ten `record` calls return immediately, `dropped` rises by exactly 10, no panic.
22. **AC22** `[red]` `a_path_that_becomes_a_directory_costs_the_caller_nothing`: after start,
    delete the control file and create a directory at its path; record 100 operator-origin
    evidence entries through a real ring with the writer attached (re-check interval zero): every
    call returns, `write_failures == 100`, `degraded == true`, and the ring holds all 100. A
    second case replaces the file with a FIFO (`mkfifo`) instead: the same results, and neither
    the 100 calls nor `shutdown(2 s)` hang, because the writer never opens a non-regular file.

**Rotation, retention, reopen** (`audit_log.rs` tests; seam cap 2048 bytes, line about 250 bytes)

23. **AC23** `[red]` `rotation_loses_no_line`: keep 100; record `c0 ... c99`. Concatenating
    `F.k ... F.1, F` (highest index first) yields entry commands exactly `c0 ... c99`, each once,
    in order; every file is at most 2048 bytes; every file's first line is a `start` marker.
24. **AC24** `[red]` `retention_deletes_only_the_oldest_rotated_file`: keep 2; record `c0 ... c99`.
    Exactly the files `F`, `F.1`, `F.2` exist for the stream (no `F.3`); their entries, oldest
    file first, are a contiguous run ending at `c99` that starts after `c0`; `c99` is in `F` or
    `F.1`; the other two streams' files are untouched.
25. **AC25** `[red]` `a_failed_rotation_never_drops_the_line` (unix; skipped when the process can
    still create a file in the directory after the `chmod`, as root can): after start, `chmod 0500`
    the stream directory so every rename and create fails while the open file stays writable;
    record 100 entries: all 100 are in `F` (its size exceeds 2048), none lost,
    `write_failures == 0`, no panic.
26. **AC26** `[red]` `an_oversized_file_rotates_on_its_first_write`: start on a file pre-filled
    past the cap; record one entry: `F.1` begins with the old content, `F` holds a `start` marker
    then the entry.
27. **AC27** `[red]` `a_removed_file_or_directory_is_recreated_with_a_start_marker`: delete the
    active file, record one entry (re-check interval zero): a new file exists at the path whose
    lines are a `start` marker then the entry. In a second case remove the whole stream
    directory: after one more entry the directory exists again (mode `0700` on unix) and its
    file's lines are a `start` marker then that entry.
28. **AC28** `[red]` `a_file_swapped_for_a_symlink_is_not_written_through` (unix): replace the
    active file with a symlink to a file `V`; record an entry: `V` is unchanged (size and
    content) and `write_failures >= 1`.

**Shutdown** (`audit_log.rs` tests; `audit_log_binary.rs` for the process)

29. **AC29** `[red]` `shutdown_flushes_every_queued_entry`: record 2000 agent-origin evidence
    entries (within the 4096 queue, so none can drop) and call `shutdown(5 s)` at once: it returns
    `complete == true` and the agent file holds all 2000 entry lines, in order, after its `start`
    marker.
30. **AC30** `[red]` `shutdown_of_a_blocked_writer_returns_within_its_budget`: with a stream's
    file blocked, `shutdown(300 ms)` returns in under 1.5 s with `complete == false` and a
    positive estimate of entries left.
31. **AC31** `[red]` `[socket]` (`audit_log_binary.rs`) `sigterm_flushes_a_real_boot`: spawn the
    real binary with `--config` naming `mcp.audit_log: P/audit.jsonl` and a loopback-TCP bus; send
    `initialize` and, with the agent token, `flow.list`, `proxy.status` and `agent.set
    {policy:"auto"}` (refused: an agent cannot set policy); `kill -TERM`; the process exits within
    10 s and `P/audit.reads.jsonl` holds the two reads, `P/audit.agent.jsonl` holds the refused
    `agent.set` with an `error` result, and `P/audit.jsonl` holds only its `start` marker.

**Surfaces** (`crates/aitm-plugins/tests/agent_status_durable.rs`, `crates/aitm-core/tests/durable_audit_hook.rs`)

32. **AC32** `[red]` `agent_status_reports_durable_audit_by_role`: with no sink, an operator
    `agent.status` has `durable_audit == {enabled:false, degraded:false, dropped:0,
    write_failures:0}` and an agent caller's has exactly the keys `degraded`, `enabled`. With a
    stub `DurableAudit` reporting `{degraded:true, dropped:7, write_failures:3}` attached, the
    operator sees `{enabled:true, degraded:true, dropped:7, write_failures:3}` and the agent sees
    `{enabled:true, degraded:true}`; the agent's result never contains `dropped` or
    `write_failures`.
33. **AC33** `[red]` `agent_status_output_schema_declares_every_durable_audit_key`: the
    `agent.status` result schema's `durable_audit` properties are exactly `degraded, dropped,
    enabled, write_failures`, and its required set is exactly `{degraded, enabled}`; `policy`,
    `actions_last_minute` and `connected_clients` are unchanged; the description string is
    byte-identical to `15009b2`.
34. **AC34** `[red]` `the_ring_hook_is_set_once_and_lock_free`: `durable_status()` is `None`
    before `attach_durable` and `Some(..)` after; a second `attach_durable` returns `false` and the
    first sink keeps receiving; `append_in(Routine, e)` delivers `(Routine, e)` to the sink once;
    the trait `append(e)` delivers `(Evidence, e)`; a sink whose `record` calls `ring.len()` and
    `ring.recent(None, None)` does not deadlock (so the ring's lock is released first); with no
    sink attached `append_in` behaves exactly as before (the ring's existing tests are unmodified
    and green).
35. **AC35** `[guard]` `no_command_reads_or_reveals_the_audit_file`: no registered command name
    starts with `audit.`; `config.get` with `mcp.audit_log = Path("/secret/audit.jsonl")` contains
    neither `/secret/audit.jsonl` nor the key `audit_log`; no `agent.status` result contains the
    path.

**Quiet, secrets, hygiene**

36. **AC36** `[red]` `[socket]` `a_healthy_boot_says_one_line_and_never_the_token`: boot with a
    token `TOKEN-CANARY-8841`, make 20 calls; the child's combined stdout and stderr contain
    exactly one line that mentions `aitm::audit` or the audit file path, contain the control
    file path, and do not contain `TOKEN-CANARY-8841`; none of the three files contains it.
37. **AC37** `[red]` (`audit_log_binary.rs`, no socket: it fails before any port is bound)
    `an_explicit_bad_path_fails_the_boot_loudly`: the real binary with `mcp.audit_log` naming a
    path under a regular file exits non-zero within 5 s with a message containing the path and
    prints no `proxy listening` line (it failed before any listener was bound).
38. **AC38** `[guard]` Harness hermeticity by grep (exit 0): `tests/e2e/aitm_e2e/core.py`,
    `tests/e2e/run.py`, `tests/e2e/start/test_bus_endpoint_file.py`, `tests/e2e/cli/cli-startup.sh`,
    `scripts/bus-agent-check.py`, `scripts/tui-live-check.sh` and
    `crates/aitm/tests/shutdown.rs` each contain `AITM_AUDIT_LOG` (orchestrator amendment 2:
    `run.py` and `test_bus_endpoint_file.py` also spawn the real binary). The behaviour it relies on is AC2 (the env wins) and AC9 (a
    path set that way is the only place files appear).

**Docs, fences, gate**

39. **AC39** `[guard]` Doc fixes by grep (exit 0): `server.rs` contains none of `opt-in by
    config`, `subset of this one format`; `aitm-core/src/audit.rs` does not contain `is a subset
    of`; `aitm-ca/src/audit.rs` contains neither `is a line of one format` nor `subset of it`;
    `README.md` contains `audit.jsonl`, `AITM_AUDIT_LOG` and `mcp.audit_log`; `INSTALL.md`
    contains `mcp.audit_log`. (Review-checked for wording.)
40. **AC40** `[guard]` **(Amendment 1: the fence is relaxed to exactly the redaction hunk.)**
    Diff fence: `git diff -U0 <merge-base>..HEAD -- crates/aitm-mcp/src crates/aitm/src/web
    ':!crates/aitm-mcp/src/redact_args.rs' | grep '^[+-]' | grep -v '^+++\|^---' | grep -v
    '^[+-][[:space:]]*//'` prints only: in `server.rs`, the pure deletion of the bodies of
    `redact_value` and the local `is_secret_key`, the one changed reason line
    (`scrub_strict` for `scrub_text`), and the line `use crate::redact_args::redact_value;`; in
    `lib.rs`, the line `pub mod redact_args;`. Nothing under `crates/aitm/src/web`.
    `crates/aitm-core/src/redact.rs` is byte-identical to `15009b2`. `pub struct ConnCtx`,
    `pub struct AuditEntry` and the sealed `Governance` have the same fields as `15009b2`;
    `git diff <merge-base>..HEAD -- Cargo.lock crates/aitm/Cargo.toml crates/aitm-mcp/Cargo.toml
    crates/aitm-core/Cargo.toml` is empty.
41. **AC41** `[guard]` No existing test is edited (the exceptions are the one-line environment
    additions of AC38, in `crates/aitm/tests/shutdown.rs` and
    `tests/e2e/start/test_bus_endpoint_file.py`, and the one e2e assertion of AC59), in
    particular `mcp.rs`
    `the_durable_audit_sink_keeps_every_entry_even_those_an_agent_may_not_read`,
    `audit_durable_connection_id.rs`, `crates/aitm-ca/tests/audit.rs`,
    `crates/aitm-core/tests/{trust_gate_scan,classifier_wildcard_free}.rs`, and every
    `agent.status` test; all pass.
42. **AC42** The Rust gate passes: `cargo fmt --check && cargo clippy --all-targets -- -D warnings
    && cargo test`.

**Mutation checks** (tester or orchestrator; each reported red, then restored green)

43. **AC43** Each of these turns the named test red on an assertion: `try_send` replaced by a
    blocking `send` (AC18 times out); drop-oldest instead of drop-newest (AC18's first and last
    entries); removing the C1 and DEL replacement (AC16); removing the `chmod` or the create mode
    (AC5, AC7); `append(true)` replaced by `truncate(true)` (AC6); the hook called inside the ring
    lock (AC34); writing the triggering line before rotating, or dropping it (AC23, AC25); keeping
    the oldest file and deleting the newest (AC24); `Close` handled before earlier queued entries
    (AC29); attaching the sink to one server instead of the ring (AC14); routing every evidence
    entry to one stream (AC11, AC19); skipping the re-check (AC27, AC28); sanitising pass
    removed (AC16).

**Strict redaction (Amendment 1)**

Canary `C(n)` below is `CNRY` + the row number as two digits + `x` + eight hex digits, unique
per row and per run. `T1` to `T5` are the five registered tokens (the transport token,
`mcp.operator_token`, `mcp.agent_token`, the web agent bridge token, and a token from
`generate_bridge_token()`), each a 64-hex-digit string; `E` is a registered environment secret.

44. **AC44** `[red]` (`crates/aitm-core/tests/redact_strict.rs`)
    `scrub_strict_masks_every_pass_and_keeps_the_benign`: exact input to output.
    P2: `"GET / HTTP/1.1\r\nCookie: a=b; c=SECRET44\r\nHost: x"` gives
    `"GET / HTTP/1.1\r\nCookie: [redacted]\r\nHost: x"`; `"Set-Cookie: JSESSIONID=\"S\"; Path=/"`
    gives `"Set-Cookie: [redacted]"`; `"x Authorization: Digest username=\"u\", response=\"R\"\nnext"`
    gives `"x Authorization: [redacted]\nnext"`; `"X-Api-Key: a b c\nok"` gives
    `"X-Api-Key: [redacted]\nok"`; `"Proxy-Authorization: Basic Zm9v"` gives
    `"Proxy-Authorization: [redacted]"`. P3: `"use Basic dXNlcjpwYXNz now"` gives
    `"use Basic [redacted] now"`; `"negotiate "` + 20 `A` gives `"negotiate [redacted]"`. P4:
    `"https://user:hunter2@host.test/p"` gives `"https://user:[redacted]@host.test/p"`;
    `"https://ghp_"` + 36 `a` + `"@github.com/"` gives `"https://[redacted]@github.com/"`. P5
    (each gives `"[redacted]"`): the JWT `"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"`;
    `AKIA` + 16 `A`; `ghp_` + 36 `a`; `github_pat_` + 22 `a`; `glpat-` + 20 `a`; `xoxb-` + 12 `1`;
    `sk_live_` + 16 `a`; `sk-` + 32 `a`; `AIza` + 35 `a`; the PEM block
    `"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"`; and
    `"x\n-----BEGIN PRIVATE KEY-----\nMII"` gives `"x\n[redacted]"`. P6:
    `"passphrase=hunter2&x=1"` gives `"passphrase=[redacted]&x=1"`; `"x=1&private_key=K&y=2"` gives
    `"x=1&private_key=[redacted]&y=2"`; `"{\"pass\":\"p\",\"user\":\"u\"}"` gives
    `"{\"pass\":\"[redacted]\",\"user\":\"u\"}"`; `"x otp: 123456 done"` gives `"x otp: [redacted] done"` (mid-line: at the start of a line P2 masks the whole line, so `"otp: 123456 done"` gives `"otp: [redacted]"`; orchestrator amendment 3 after R2).
    **Unchanged byte for byte:** `"0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c"`; `"0123456789abcdef"` x4;
    `"auth.example.com:8443"`; `"https://example.test/a/b?x=1&y=two#frag"`;
    `"ssh://git@github.com/o/r"`; `"git@github.com:o/r.git"`; `"basic information"`;
    `"the Cookie header is described in RFC 6265"`; `"sk-prod-eu-1.example.test"`;
    `"author=bob&authority=example.com&inside=1&bypass=1&passed=true"`;
    `"{\"a\":1,\"b\":[true,null],\"c\":\"d\"}"`; `"Accept: text/html"`;
    `"X-Forwarded-For: 203.0.113.9"`; `"AKIA"`; `"AKIAFOO"`; `"ghp_short"`; `"eyJ"`;
    `"{{target}}/login?user={{user}}"`. Every row: `scrub_strict(scrub_strict(x)) ==
    scrub_strict(x)`. Hostile inputs (4 MiB each of `eyJ`, an unterminated `-----BEGIN PRIVATE
    KEY-----`, `https://a:`, `Basic `, `Cookie: `) return without panicking.
45. **AC45** `[red]` (`crates/aitm-mcp/tests/audit_redaction.rs`, a real `McpServer`; a stub
    command with `Any`-typed `headers`, `pairs`, `entries`, `request`, `edits`, `selector`,
    `text`, `vars`) `rules_s_and_d_redact_header_collections_and_siblings`: the ring entry's
    `args_summary` parses to exactly these, and the pushed line and `agent.activity`'s entry carry
    the byte-identical string.
    `{"headers":{"Accept":"text/html","Authorization":"Bearer B","Content-Type":"application/json",
    "X-Custom":"C"}}` gives `{"headers":{"Accept":"text/html","Authorization":"<redacted>",
    "Content-Type":"application/json","X-Custom":"<redacted>"}}`.
    `{"headers":[["Cookie","foo=C"],["Accept","text/html"],["X-Zed","z"]]}` gives
    `{"headers":[["Cookie","<redacted>"],["Accept","text/html"],["X-Zed","<redacted>"]]}`.
    `{"headers":[{"name":"Cookie","value":"C"},{"name":"Accept","value":"text/html"}]}` gives
    `{"headers":[{"name":"Cookie","value":"<redacted>"},{"name":"Accept","value":"text/html"}]}`.
    `{"pairs":[{"name":"Authorization","value":"C"}],"entries":[["Set-Cookie","C=1"]]}` gives both
    values `<redacted>` (rule S, no header key). `{"a":{"b":{"request_headers":{"X-Zed":"C",
    "Host":"h.test"}}}}` gives `X-Zed` redacted and `Host` kept. `{"edits":{"headers":
    {"X-Forwarded-Host":"evil.test","X-Debug":"C"}}}` gives `X-Forwarded-Host` kept and `X-Debug`
    redacted. `{"headers":{"Referer":"https://x.test/cb?token=C"}}` gives
    `{"headers":{"Referer":"https://x.test/cb?token=[redacted]"}}`. `{"headers":{"X-N":5}}` gives
    `{"headers":{"X-N":"<redacted>"}}`. `{"selector":"#password","text":"C"}` and
    `{"selector":"input[name=api_token]","text":"C"}` give `text` `<redacted>`;
    `{"selector":"#q","text":"hello"}` is unchanged. `{"vars":{"admin_pass":"C","pw":"C",
    "target":"http://t.test","user":"admin"}}` gives the first two `<redacted>` and the last two
    unchanged.
46. **AC46** `[red]` `redaction_work_is_bounded` (same file): `redact_args` of `{"body": 16 MiB of
    "a"}` and of `{"list": 500000 strings "x"}` each return within 5 s with an entry of at most
    515 bytes that begins `{"body":"aaaa` and `{"list":["x","x"` respectively; a leaf whose first
    4096 characters end in `password=SECRET46` starting at character 4000 shows `password=[redacted]`
    in the entry only if the entry reaches that far (it does not at the 512-byte cap), and starting
    at character 4100 the secret is absent from the entry (it is beyond the examined bound).
47. **AC47** `[red]` `redaction_is_idempotent_and_json_safe` (`audit_redaction.rs`, and AC17
    through the writer): for every `args` value of the AC55 corpus,
    `redact_value(redact_value(v)) == redact_value(v)`. `demo.echo {"note":"Authorization: Bearer
    SECRET47"}` gives ring `args_summary` exactly `{"note":"Authorization: [redacted]"}`, the
    writer writes that string byte for byte, and it parses as JSON; `{"raw":"GET /\r\nCookie: a=b;
    z=SECRET47\r\nHost: x"}` gives `{"raw":"GET /\r\nCookie: [redacted]\r\nHost: x"}` (the line
    breaks as the JSON escapes) and the writer writes it unchanged. Running `scrub_text` over the
    JSON text instead turns both red, which is the Design 14.0 defect.
48. **AC48** `[red]` (`audit_log.rs` tests) `registry_tiers`: with `ABCD1234EFGH` registered
    (returns `Substring`), `"x ABCD1234EFGH y"` gives `"x [redacted] y"` and
    `"prefixABCD1234EFGHsuffix"` gives `"prefix[redacted]suffix"`. With `wxyz` registered
    (`WholeToken`): `"a wxyz b"` gives `"a [redacted] b"`, `"(wxyz)"` gives `"([redacted])"`,
    `"awxyzb"` and `"a-wxyz"` are unchanged. With `abc` registered (`Ignored`): `"abc abcd"` is
    unchanged. `redacted` (8 bytes) registers as `Ignored`, and `mask("[redacted]")` is
    `"[redacted]"`. For the two short registrations a captured `tracing` event contains the
    source label and `shorter than 8`, and neither the value nor its length.
49. **AC49** `[red]` `registry_masks_every_encoding`: with `Zm9v+YmFy/Ymf=ZZ99` and
    `ab"cd\ef12345` registered, each of these gives `[redacted]` for the whole secret: the raw
    form; `Zm9v%2BYmFy%2FYmf%3DZZ99`; the lower-case `Zm9v%2bYmFy%2fYmf%3dZZ99`; the JSON form
    `ab\"cd\\ef12345`; and `http://127.0.0.1:8082/#t=` + the raw form gives
    `http://127.0.0.1:8082/#t=[redacted]`. In a parsed `args` `{"u":"x?next=<percent form>"}` the
    result is `{"u":"x?next=[redacted]"}` and still parses.
50. **AC50** `[red]` `a_late_registration_reaches_a_running_writer`: the writer's fake file blocks;
    record an entry whose `args` holds `LATE50TOKENVALUE`; register `LATE50TOKENVALUE` while it is
    queued; release the file: that line and a second entry recorded after the registration both
    lack it.
51. **AC51** `[red]` `a_secret_never_appears_in_debug_display_or_logs`: `format!("{:?}", ..)` of the
    registry, of the `Registration`, of the `AuditLogHandle` and of the writer contains none of five
    registered canaries (the registry's is exactly its count), a registry has no `Display`, and
    the captured `tracing` output of `start` (with a short secret among them) and of a failing write
    contains none of them.
52. **AC52** `[red]` (`audit_log_redaction.rs`) `start_registers_every_configured_source`: a config
    with `LoopbackTcp {token: T1}`, `operator_token: T2`, `agent_token: T3`, a web token argument
    `T4`, and an injected environment `{ANTHROPIC_API_KEY: E, SSH_AUTH_SOCK: /tmp/sock52xxxxxxxx,
    HOME: /home/u52xxxxxx}`. After `start`, hand-built entries carrying each of `T1` to `T4` and
    `E` bare, in a `#t=` URL and as a `Referer` header value reach the files with none of them
    present, while `/tmp/sock52xxxxxxxx` and `/home/u52xxxxxx` are present unmasked. The same for a
    `StreamableHttp` transport token.
53. **AC53** `[red]` `the_operator_bridge_token_is_registered_when_minted`:
    `handle.generate_bridge_token()` returns a 64-hex-digit `t` and `registry.mask("a t b")`
    gives `"a [redacted] b"`; a second call returns a different token, also masked; with the audit
    off (`start` returned `None`) the `web_server` expression's fallback returns a 64-hex-digit
    token and registers nothing.
54. **AC54** `[red]` `cut_secrets_and_the_tolerant_scan` (`audit_log.rs` tests): (a) with
    `CUT54SECRETVALUE0123456789` registered, an `args` of `{"note":"` + 470 `x` +
    `CUT54SECRETVALUE0123456789"}` cut by the source at 512 bytes plus `…` (so it ends mid-token)
    is written with no `CUT54S` and ends `[redacted]…`. (b) The cut text
    `{"headers":{"Cookie":"a=b; s=SECRET54","X":"v"},"note":"GET /\r\nCookie: a=b; z=SECRET54b\r\nHo`
    (inside a literal, not JSON) is written with `SECRET54` and `SECRET54b` absent, `"X":"v"`
    unchanged (rule D is source-only, Residual risks 17), and every character outside string
    literals identical to the input (delete the literal contents from both and compare).
    `{"password":"SECRET54c","n":1` gives `{"password":"<redacted>","n":1`. (c) ` password=SECRET54d x`
    (not JSON) gives ` password=[redacted] x`. (d) the complete hand-built
    `{"headers":{"X-Custom":"SECRET54e"}}` gives `{"headers":{"X-Custom":"<redacted>"}}` (the
    writer reuses the source function for text that parses).
55. **AC55** `[red]` (`audit_log_redaction.rs`) `no_canary_reaches_any_file_through_the_real_path`:
    the corpus below, through a real `McpServer` (built by `tui::server` and
    `tui::with_shared_governance` from one `assemble`), its ring, the writer, and the three
    files, with a small rotation seam so at least one numbered file exists. A `Write` stub
    `demo.accept` takes `Any`-typed `headers`, `pairs`, `entries`, `request`, `edits`, `selector`,
    `text`, `vars`, `note`, `raw`, `body`, `poc_text`, `source`, `url`, `form`; `demo.fail` returns
    an error quoting its `note`. After `shutdown`, every file whose name starts with `audit` (active
    and numbered) is read as bytes, and for each row the canary (and each listed encoding) must be
    absent; every offending row id is collected into one failure message. **Rows (74):**
    - **Headers.** R1 map `Authorization: Bearer C`; R2 map `authorization: Basic <base64 of
      user:C>`; R3 map `Proxy-Authorization`; R4 map `Cookie: a=1; b=2; session=C`; R5 map
      `Set-Cookie: id=C; Path=/; HttpOnly`; R6 map `X-Api-Key: C`; R7 map `X-Debug-Access: C`
      (innocuous name); R8 map `X-Forwarded-Host: evil.test` (must stay, checked by AC56); R9
      pairs `["Cookie","foo=C"]`; R10 pairs `["Authorization","Basic <b64 of user:C>"]`; R11 pairs
      `["X-Custom","C"]`; R12 `{name:"Cookie",value:C}`; R13 `{name:"Authorization",value:C}` under
      `pairs`; R14 `["Set-Cookie","C=1"]` under `entries`; R15 `request.meta.request_headers`
      `{"X-Zed":"C"}`; R16 `response_headers` `{"Set-Cookie":"C=1"}`; R17 `edits.headers
      {"X-Evil":"C"}`.
    - **Text.** R18 `raw` CRLF block with `Authorization: Bearer C`; R19 `raw` with `Cookie:
      a=b; c=C; d=e`; R20 a `Set-Cookie: x=C; Path=/` line; R21 `Cookie: sid="C"`; R22
      `Set-Cookie: JSESSIONID="C"; Path=/`; R23 `Authorization: Digest username="u",
      response="C"`; R24 a header line as the last text of its string; R25 a hand-built entry
      with an unparseable truncated `args` carrying an escaped `\r\nCookie: a=b; z=C\r\n`; R26
      `Proxy-Authorization: Basic C`; R27 prose then `Cookie: a=b; z=C` on one line.
    - **Bodies and URLs.** R28 `body` JSON string with escaped quotes `{\"user\":\"u\",\"password\":\"C\"}`;
      R29 `{"login":"u","pass":"C"}`; R30 `{"u":"x","pw":"C"}`; R31 form `user=u&passphrase=C`; R32
      form `private_key=C&x=1`; R33 form `access_key=C`; R34 `?access_token=C&page=2`; R35
      `?api_key=C`; R36 `https://user:C@host.test/p`; R37 `https://<ghp_ shape C>@github.com/`; R38
      `Basic <b64 of user:C>` outside any header; R39 `otp=C` and `totp: C`.
    - **Shapes in free text.** R40 JWT `eyJhbGciOiJIUzI1NiJ9.eyJ` + C + `.` + C; R41 PEM block
      around C; R42 `AKIA` + 16 uppercase hex digits from C; R43 `ghp_` + C padded to 36; R44
      `github_pat_` + C padded to 22; R45 `glpat-` + C padded to 20; R46 `xoxb-123456789012-` + C; R47
      `sk_live_` + C padded to 16; R48 `sk-` + C padded to 32; R49 `AIza` + C padded to 35.
    - **Tools.** R50 `poc.run`-shaped `vars {"admin_pass": C}`; R51 `vars {"pw": C}`; R52 the YAML of
      a real `StdPocBuilder` build (AC61); R53 `{selector:"#password", text:C}`; R54
      `{selector:"input[name=api_token]", text:C}`; R55 a script `source` with `const PASSWORD = "C";`
      and a `sk_live_` shape.
    - **Known tokens.** R56 to R60 `T1` to `T5` bare under `note`; R61 to R65 `T1` to `T5` as
      `http://127.0.0.1:8082/#t=<T>`; R66 `T1` as a `Referer` header value (a benign name, so only
      the registry catches it); R67 a token containing `+/=` in its raw, upper-case and lower-case
      percent-encoded forms; R68 a token containing `"` and `\` in raw and JSON forms; R69 `T2`
      quoted in the reason of `demo.fail`; R70 `T3` as the declared client label; R71 `T4` straddling
      the 512-byte cap (AC54a); R72 `E` bare.
    - **Multi.** R73 one string carrying `Bearer C`, `password=C`, an AKIA shape, a JWT and a
      `Cookie:` line; R74 `T1` and `T2` in one header value.
56. **AC56** `[red]` `benign_values_survive_the_real_path_byte_for_byte`: each of AC44's benign
    strings is sent as `note`, and these headers as header values: `Accept: text/html`,
    `Content-Type: application/json`, `Host: h.test`, `User-Agent: Mozilla/5.0 (X11; Linux x86_64)`,
    `X-Forwarded-For: 203.0.113.9`, `X-Forwarded-Host: evil.test`, `Referer: https://x.test/a?x=1`,
    `Sec-Fetch-Mode: cors`, `Accept-Language: en-US,en;q=0.9`. For each the file's `args` equals
    `entry_to_jsonl(&ring_entry)`'s `args`, and the value read back from the parsed `args` equals the
    value sent.
57. **AC57** `[red]` `every_line_is_valid_json_with_the_same_shape`: every line of every file of
    the AC55 run parses as JSON; an entry line has exactly the seven keys and a marker line has
    `marker`; and for every row whose ring `args` parses, the file's `args` parses and has the same
    paths as the ring's (the JSON value with every string replaced by `""` is equal).
58. **AC58** `[red]` `[socket]` (`audit_log_binary.rs`)
    `the_generated_operator_bridge_token_never_reaches_disk`: boot the real binary as `aitm web`
    with `mcp.operator_token` set and `--token <web agent token>`; read the operator link's token
    from stdout; over the real `/bus` as the operator, call `scope.add {host: "<operator bridge
    token>.example.test"}`, then with the web agent token call `scope.add {host: "<web agent
    token>.example.test"}`; `kill -TERM`; none of the operator bridge token, the web agent token, or
    `mcp.operator_token` appears in any file under the audit directory, and the control file has
    an entry whose `args` contains `[redacted].example.test` (the entry was written, masked).
59. **AC59** `[red]` `[e2e]` (Terminal panel; a built `aitm`) `tests/e2e/audit/test_audit_log.py`:
    the `X-Audit-Marker` expectation becomes `KEY_REDACTED` plus an `in hdrs` check that the name is
    still present; `Content-Type` is still `application/x-www-form-urlencoded`; `Authorization`,
    `X-Api-Key` and `Cookie` are still `KEY_REDACTED`; the whole-response secret sweeps still pass;
    `python3 tests/e2e/run.py audit` passes.
60. **AC60** `[red]` `the_reason_is_scrubbed_strictly_at_the_source`: `demo.fail` with a `note`
    of `"bad header Cookie: a=b; z=SECRET60 at line 3"` gives a ring `Error(r)` equal to
    `"bad header Cookie: [redacted]"`, a pushed line and an `agent.activity` entry with the same
    result, none containing `SECRET60`.
61. **AC61** `[red]` `a_built_poc_passes_through_the_audit_clean`: a real `StdPocBuilder::build`
    over an `HttpFlow` whose request has `Authorization: Bearer SECRET61A`, `Cookie:
    sid=SECRET61B; theme=dark`, `?access_token=SECRET61C&q=hi` and body `user=a&password=SECRET61D`,
    serialised with `serde_yaml::to_string` and sent as `poc_text`: none of the four appears in
    any file, and every `{{...}}` placeholder of the YAML is present in the file's `args`.
62. **AC62** `[guard]` Existing redaction suites pass unmodified, and nothing they cover moved:
    `mcp.rs` `audit_redacts_secrets`, `audit_redacts_secret_inside_non_secret_named_value`,
    `audit_redacts_secret_in_error_reason`; `audit_integrity.rs`
    `args_summary_hides_unframed_credentials` and `a_directly_assigned_label_is_stripped_and_scrubbed_at_the_server`;
    the `redact.rs` unit tests; `crates/aitm-poc/tests/builder.rs`; the scanner `scrub_embedded_*`
    tests; the findings suites. `git diff` shows no edit under `crates/aitm-core/src/redact.rs`,
    `crates/aitm-plugin-scanner`, `crates/aitm-findings` or `crates/aitm-poc`.
63. **AC63** `[red]` `the_strict_vocabulary_is_audit_only`: `redact::is_secret_key("passphrase")` is
    false and `redact_strict::is_secret_key_strict("passphrase")` is true; `scrub_text("pass=x")`
    is `"pass=x"` and `scrub_strict("pass=x")` is `"pass=[redacted]"`; `is_secret_key_strict("author")`,
    `"authority"`, `"inside"`, `"bypass"`, `"passed"` and `"sessions"` are false.
64. **AC64** Mutation checks for Design 14 (tester or orchestrator; each reported red on an
    assertion, then restored green). Removing rule D turns AC45 and R7, R11, R15, R17 red; removing
    rule S turns AC45 and R9, R10, R12 to R14, R53, R54 red; removing P2 turns AC44, R19 to R22,
    R25 to R27 red; removing P3 turns AC44 and R38 red; removing P4 turns AC44, R36, R37 red;
    removing any one P5 shape turns AC44 and that shape's row (R40 to R49) red; removing the extra
    vocabulary turns AC44, AC63, R29 to R33, R39, R50, R51 red; raw-substring masking of every
    registered length turns AC48 red; removing the percent or JSON forms turns AC49, R67, R68 red;
    removing the trailing-fragment mask turns AC54a and R71 red; removing late registration turns
    AC50, AC53, AC58 red; registering only from `cfg` and not the argument or the environment turns
    AC52 red; running `scrub_text` over JSON text in the writer turns AC47 and AC17 red; removing
    the tolerant scan turns AC54b and R25 red; removing parse-first turns AC54d red; reverting
    `scrub_strict` to `scrub_text` on the reason line turns AC60 red; removing the bound turns AC46
    red; reverting the `server.rs` hunk to the old `redact_value` turns AC45 red.
65. **AC65** `[guard]` Docs by grep (exit 0): the README's audit-log subsection contains
    `<redacted>`, `Set-Cookie`, `tokens` and the sentence naming what cannot be caught (a bare
    credential with no frame, registered value or known shape).

## Left to the builder

- The internal structure of `audit_log.rs`: a `StreamWriter` type generic over a file seam, the
  seam's trait name, thread bodies, and how the pending gap is held (three atomics or a small
  `Mutex`), provided AC9, AC11, AC18 to AC30 hold and no lock is held across I/O.
- How `DurableAudit` satisfies `Debug` for `AuditRing`'s derive (a supertrait or a hand-written
  impl), and whether `ShutdownReport` is a struct or a tuple.
- The exact wording of the startup line, warnings and error messages, provided the substrings
  AC4, AC7, AC36 and AC37 require appear.
- Whether the preflight and the runtime reopen share one function (they should).
- Helper duplication across the new test files (the repo's house style), and the exact form of
  the temp-directory helper.
- The exact `jq` recipes in the README, provided the three files, the markers and the limits are
  stated.
- The in-module seam's shortened intervals; production intervals are 5 s (re-check), 1 s
  (reopen), 60 s (warn throttle), 2 s (shutdown budget).
- (Amendment 1) How the P2 to P6 passes are written in `redact_strict.rs` (one combined regex per
  pass or several, a hand-written scan where a regex cannot express the rule, for instance the
  Basic base64 test and the P4 userinfo choice), provided every pass is linear, idempotent, and
  meets AC44's literals and benign table; and which exact byte values the base64 decoder
  accepts. The shapes' minimum lengths in Design 14.3 are decided; a shape that fires on a
  benign row is the pass's bug.
- (Amendment 1) The internal layout of `SecretRegistry` (a sorted `Vec` of needles per tier
  behind an `RwLock<Arc<..>>` is the suggestion), how the whole-token tier finds a boundary, and
  where the tolerant scan lives, provided AC48 to AC54 hold, no lock is held across a mask, and
  nothing prints a secret.
- (Amendment 1) The corpus rows' exact surrounding text (the words around a canary), provided each
  row keeps the shape its carrier names and every canary is unique.

## Open questions

All have a default; none blocks approval or the build.

1. **Default on?** Default: on, at the default path, with `mcp.audit_log: off` and
   `AITM_AUDIT_LOG=off`. Veto path: default `Off`; the writer, tests and docs are unchanged
   (AC10 and AC38 already cover it), only `McpConfig`'s default and the README sentence flip.
2. **The TUI's own in-process operator server.** Default: stays unaudited (Design 10).
3. **Three streams and the sizes** (20 + 48 + 24 MiB). Default: as specified. Veto path: one
   file for all entries is a change to `stream_for` and the table, not to the hook, the writer
   or the surfaces.
4. **A reader.** Default: documentation only (Design 12); an `aitm audit` subcommand is a later,
   CLI-only change.
5. **(Amendment 1) Header values: default-deny or name-only?** Default: default-deny with the
   benign list (Design 14.2), which hides every non-benign header value from the audit copy and
   flips one e2e assertion (AC59). Veto path: keep rule S (names, siblings, preceding elements)
   and drop rule D: no test changes and no evidence cost, but a credential under an innocuous
   header name reaches the ring, the push and the file. Matt's "NO secrets EVER" is why the
   default is D.

## Summary

This change makes the audit durable by default. A new `aitm` module writes every audited call,
from every server that shares the ring (the primary server, the `aitm web` server and the `aitm
tui` loopback agent server, with no per-server wiring), to JSONL files under the operator's
config directory, via a small set-once hook on the `AuditRing` and one bounded queue plus one
thread per stream, so `record_audit` never touches the disk. Entries go to three streams
(operator and CLI evidence, agent evidence, successful reads) so an agent flood or UI polling
cannot push operator evidence out of the file. Files are `0600` in a `0700` directory, refuse
links and FIFOs, append across restarts, rotate by size with no lost line, are re-sanitised by
the writer, record a `start` marker per boot and a `gap` marker for any lost entry, and are
flushed at shutdown. `mcp.audit_log` and `AITM_AUDIT_LOG` configure it (an explicit bad path
fails the boot, a bad default degrades with a warning); `agent.status` reports health. It is a
best-effort record with in-band gap detection, not tamper evidence.

(Amendment 1.) Redaction on disk is strict: the call-path source that makes `args_summary` and the
reason (the one place the ring, the push and the file all read) gains structural rules for
header collections and name/value siblings (every header value outside a short benign list
reads `<redacted>`, names stay), new strict text passes in a new `aitm-core` module (header
lines, `Basic`, URL userinfo, credential shapes, extra key words) that sit beside the untouched
`scrub_text`, and a bounded traversal; the writer adds a registry that masks the five configured
tokens (the per-run operator bridge token registered the moment it is minted) and secret-named
environment variables by exact value in three encodings, and a field pipeline that never runs
`scrub_text` over JSON text (which would have broken this spec's own "honest entry is
unchanged" guarantee). A 74-row corpus with unique canaries, run through a real `McpServer`, the
ring, the writer and every rotated file, plus a benign table that must survive byte for byte, is
the proof. What cannot be caught is stated: a bare credential with no frame, no registered value
and no known shape.

## Architect's calls (for Matt to approve or correct)

1. **Default on** at `<config_dir>/aitmproxy/audit.jsonl`, off by `mcp.audit_log: off` or
   `AITM_AUDIT_LOG=off` (Design 3). The one most worth a veto.
2. **Three on-disk streams** (control, agent, reads) with caps of 20, 48 and 24 MiB and queues of
   1024, 4096 and 2048; constants, not config (Design 5).
3. **Reads are written**, in their own short-lived stream, rather than dropped or filtered by
   command name.
4. **One ring-level hook** (`DurableAudit`, `attach_durable`) in `aitm-core`, not per-server
   `with_durable_audit`; zero executable change in `aitm-mcp`; `ConnCtx`, `AuditEntry` and
   `Governance` unchanged (Design 10).
5. **The TUI's in-process operator server stays unaudited**; recorded as a residual with a
   named follow-up.
6. **Explicit path fails the boot, default path degrades** (Design 4); the general log is not
   fail-closed like the CA's.
7. **Drop-newest** on a full queue, with an in-file `gap` marker and a counter; no write-rate
   budget in this change (named follow-up).
8. **Env var wins over the file; an unparseable `AITM_AUDIT_LOG` leaves the setting unchanged**
   rather than disabling; relative paths are refused; no CLI flag.
9. **Sanitise in the writer as well as in `record_audit`**; `entry_to_jsonl` and `aitm-ca`
   behaviour are not edited; C1 and DEL controls are replaced with U+FFFD.
10. **`agent.status.durable_audit`**: `enabled` and `degraded` for every role, `dropped` and
    `write_failures` for trusted control only; no path is ever reported.
11. **Documentation only for a reader**; no `aitm audit` verb and no registry command.
12. **Numbered rotation, size-only retention, re-check every 5 s**, shutdown budget 2 s, no
    per-line `fsync`.
13. **Separate files from `ca.audit_log`**, with a boot-time check that they differ; the "one
    format" doc comments are corrected rather than made true.
14. **Test hermeticity by environment**: `AITM_AUDIT_LOG` in the e2e harness and scripts, rather
    than deriving the default from the config file's location.

**Amendment 1 (strict redaction on disk), for Matt to approve or correct**

15. **Strict redaction is new code beside the shared vocabulary, not an edit of it.** A new
    `aitm-core/src/redact_strict.rs` and `aitm-mcp/src/redact_args.rs`; `redact.rs`,
    `is_secret_key` and `scrub_text` are untouched, so the scanner, the findings store and the PoC
    builder cannot change. The extra key words (`passphrase`, `private_key`, `access_key`,
    `signing_key`, `pass`, `pw`, `otp`, `totp`) are audit-only (Design 14.3 P6).
16. **Header values are default-deny** inside header collections (any depth, map, pair array or
    `{name,value}`), with a benign list (`accept*`, `content-*`, `host`, `user-agent`, `origin`,
    `referer`, `sec-fetch-*`, and the routing and override headers an injection test sends);
    names stay, the literal is `<redacted>`. **This is a real evidence cost:** an operator's custom
    or vendor header value is no longer in the audit copy (the flow store keeps it). **It flips
    one existing e2e assertion** (`test_audit_log.py:349`, `X-Audit-Marker`), the only existing
    test expectation the amendment changes (AC59). Veto path: rule S alone (Open question 5).
17. **Rule S is container-agnostic**: a secret header name as a sibling `name`/`key`/`selector`
    field, or as the preceding array element, redacts the value or `text` next to it, so
    `browser.type {selector:"#password", text}` and header pairs outside a `headers` key are
    covered.
18. **Redaction moves to the call-path source** (a deletion plus an import and a one-line reason
    change in `server.rs`, a new file, one `mod` line), so the ring, the push, `agent.activity`
    and the file are equally clean. This relaxes the spec's "comment-only edits in `aitm-mcp`"
    fence to exactly that hunk (AC40). The source is made **bounded** (4 KiB per string, 64 KiB
    in all) because the added passes would otherwise multiply a call-path cost that is already
    linear in the argument size.
19. **A known-secret registry in the writer**: exact masking of the five configured tokens and of
    secret-named environment variables, in raw, JSON-escaped and percent-encoded forms; 8 bytes
    or more as a substring, 4 to 7 as a whole token only, under 4 not literal-masked with a
    `warn!` that never prints the value or its length; late registration through
    `AuditLogHandle::generate_bridge_token()`; a trailing fragment of a cut registered secret is
    masked.
20. **The writer never runs `scrub_text` over JSON text.** This corrects this spec's own Design 6:
    `scrub_text`'s `Authorization` and `Bearer` passes swallow `"}` and `\r\n` escapes in JSON
    text and are not idempotent. `args` is parsed and re-redacted with the source function when it
    parses, scanned literal by literal when it does not (structure characters untouched), and
    treated as plain text when it is not JSON at all.
21. **What "airtight" means**: every credential class Matt named is covered by a structural or
    literal rule; a bare credential with no frame, registered value or known shape is not, and the
    spec says so (Residual risks 14 to 18).
