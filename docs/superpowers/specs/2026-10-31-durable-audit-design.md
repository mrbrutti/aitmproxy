# Durable audit wiring design

**Status:** approved (2026-10-31, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief; the Architect's calls listed at the end stand as written, with one orchestrator amendment: `crates/aitm/tests/shutdown.rs`, the one Rust test that spawns the real `aitm` binary, joins the hermeticity group in Files E and AC38 and is the single exception to AC41's "no existing test is edited", as a one-line environment addition. Default-on (call 1) is the decision flagged for Matt's veto in the PR.)
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

## Intent

The F2 audit ring is a bounded, fair, in-memory live view. It is still the only audit
record the binary keeps: `McpServer::with_durable_audit` has no production caller and the
YAML config has no key for it, so a restart empties the record and a flood that outruns the
ring's fair share still evicts entries. This change makes the audit durable by default: every
audited call, from every server this binary builds, is appended to a JSONL file under the
operator's config directory, through one choke point, by a writer that can never slow or
break the command that produced the entry. The file is best-effort, not tamper-evident, and
says so: gaps (dropped or unwritable entries) are recorded in the file itself and counted in
`agent.status`. The design adds no dependency, no `unsafe`, no field on `ConnCtx`,
`AuditEntry` or `wire::Governance`, and no executable change in `aitm-mcp`.

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
- The file never contains a credential the ring would not, a raw control character, or a
  label, reason or argument longer than the ring's own caps.
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
- A field added to `ConnCtx`, `AuditEntry` or `Governance`, or an executable edit in
  `crates/aitm-mcp` or `crates/aitm/src/web/bridge.rs` (sibling sessions are editing them).
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
- **Hot path.** With no sink attached the only new work on the call path is one
  `OnceLock::get`. With a sink it is that plus one `AuditEntry::clone` and one `try_send`. No
  lock is held across the hook, there is no I/O, and nothing is allocated beyond the clone. All
  sanitising and rendering happen on the writer threads.
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
  scrubbed).
- `args`: cut to `DEFAULT_ARGS_SUMMARY_CAP` bytes plus `…` (work bounded first), `scrub_text`,
  cut again.
- `result.error`: the same with `DEFAULT_RESULT_REASON_CAP` (1024).
- `command`: at most 128 characters. `connection_id`: at most 64 bytes.
- In `args`, `result.error`, `command` and `connection_id`, a whitespace control becomes one
  blank and every other `char::is_control` character (C0, DEL and C1) becomes U+FFFD.

For an entry `record_audit` produced the pass changes nothing (it is idempotent over the ring's
own caps and masks), so honest entries are byte-for-byte what `entry_to_jsonl` renders. Applying
`scrub_text` twice can only mask more, as the PR 171 spec records for the label.

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
  recorded). Make `README.md:43` and `501` precise instead of absolute.
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

## Semantics changes by surface

| Surface | Changes | Does not change |
|---|---|---|
| Process boot (`aitm`, `aitm web`, `aitm tui`) | Three files appear under the config dir; one `info!` startup line; an explicit unusable path fails the boot before any port is bound; an unusable default path warns and runs degraded | `Off` creates nothing and logs nothing; `aitm <subcommand>` builds no writer |
| `agent.status` | Additive `durable_audit` object (Design 11), counters for trusted control only | `policy`, `actions_last_minute`, `connected_clients`, the description string, `exclude_self` |
| `agent.activity`, the `notifications/aitm/agent` push, the ring, lanes, fair share | None | Everything, including the role filter |
| `ca.audit_log`, `ca.*` commands, `FileAuditLog` | Doc comments only | Format, location, fail-closed behaviour |
| `config.get` | None (it does not show the audit path) | Shape |
| TUI, web UI, macOS app | None in code. The embedded macOS core writes the default file, shared across launches | Decoders read keys by name |
| Findings, scanner, PoC | None | Everything |
| e2e harness and scripts | `AITM_AUDIT_LOG` is set per run so they stay hermetic | What they test |
| Operators | Can read the files with `jq` | There is still no command that reads them |

## Rebase hazards with the sibling sessions

Sessions are editing `crates/aitm-mcp` (`server.rs`, `transport.rs`) and the `/bus` bridge
(`crates/aitm/src/web/bridge.rs`). This change touches `server.rs` in three comment-only hunks
(about 1057-1061, 1136-1137, 1917-1919) and nothing else there; `transport.rs`, `http.rs` and
`bridge.rs` are not edited. `ConnCtx`, `AuditEntry`, `wire::Governance` and `tui::build_servers`
gain no field and no parameter. The contested files that do change:

- `crates/aitm-core/src/audit.rs` (the hook, two methods, doc fixes) and `lib.rs` (one
  `pub use audit::{..}` statement and one `pub use config::{..}` statement; a sibling adding an
  export is a one-line merge) and `config.rs` (`McpConfig` field, one enum).
- `crates/aitm/src/main.rs`: three hunks (the `start` call after the CLI branch, the tail
  `shutdown`, one `use`), no change to `Mode` or `parse_mode`.
- `crates/aitm/src/config_file.rs` (`McpFile` field and `apply`) and `env.rs` (one function).
- `crates/aitm-plugins/src/agent.rs` (`AgentStatus` schema and `invoke`).
- `tests/e2e/aitm_e2e/core.py` `_spawn` (one line): the e2e sessions own it; keep the edit to
  that line and rebase on theirs.

New code lives in new files (`audit_log.rs`, five new test files). The existing tests named in
AC41 are not edited. The orchestrator rebases on `main` before dispatching the wiring task and
again before the panel.

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
5. **Redaction misses now persist.** Whatever `scrub_text` lets through (PR 171 Residual risks
   6, 11, 12, 13, 14: a credential with no `key=` or `Bearer` frame, the `host:port` exemption
   that leaves `db.password:1234`, malformed unclosed-quote shapes) survives a restart in a file.
   The writer's second pass has the same exemption. The args also name hosts, URLs, flow ids and
   paths: engagement metadata on disk. The `is_host_port` tightening PR 171's plan names becomes
   more worthwhile. Do not attach the files to a bug report unreviewed.
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

**What this answers of PR 171's residuals.** (1) A source overwriting its own history: answered
for the file (the ring's eviction no longer erases the record), except for a sustained agent
flood (above, 3). (2) The 32-source table floor: answered for the file, which has no source
table. (3) Reads not evidence-grade: improved by the `reads` stream. (7) `entry_to_jsonl` trusts
its caller: answered by the writer's pass (the renderer itself is unchanged and still trusts a
direct caller). (8) No durability: answered. (10) Every bridge connection is one source: the
file keeps `connection_id` per line, so connections are tellable apart (the ring's eviction
semantics are unchanged). (11) The `host:port` exemption: **not answered**, and worsened by
persistence (above, 5). Unchanged: 4, 5, 9.

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
  one-line environment addition and the single exception to AC41. The coder greps
  `crates/*/tests` and `tests/` for any other `CARGO_BIN_EXE_aitm` or `target/*/aitm` spawn and
  reports it rather than editing it silently.

Group A must land before B and C compile against it; D and E are independent of everything.
Within B, `audit_log.rs` is one file, so its internals are one task or a strict sequence.

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
    1027 bytes, `connection_id` at most 64 bytes, `command` at most 128 chars.
17. **AC17** `[guard]` `an_honest_entry_is_written_unchanged`: the entry `record_audit` produced
    for a real call (read back from `ring.recent`) is written as exactly
    `entry_to_jsonl(&entry)` (the sanitising pass is a no-op on it).

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
    `tests/e2e/cli/cli-startup.sh`, `scripts/bus-agent-check.py`, `scripts/tui-live-check.sh` and
    `crates/aitm/tests/shutdown.rs` each contain `AITM_AUDIT_LOG`. The behaviour it relies on is AC2 (the env wins) and AC9 (a
    path set that way is the only place files appear).

**Docs, fences, gate**

39. **AC39** `[guard]` Doc fixes by grep (exit 0): `server.rs` contains none of `opt-in by
    config`, `subset of this one format`; `aitm-core/src/audit.rs` does not contain `is a subset
    of`; `aitm-ca/src/audit.rs` contains neither `is a line of one format` nor `subset of it`;
    `README.md` contains `audit.jsonl`, `AITM_AUDIT_LOG` and `mcp.audit_log`; `INSTALL.md`
    contains `mcp.audit_log`. (Review-checked for wording.)
40. **AC40** `[guard]` Diff fence: `git diff -U0 <merge-base>..HEAD -- crates/aitm-mcp/src
    crates/aitm/src/web | grep '^[+-]' | grep -v '^+++\|^---' | grep -v '^[+-][[:space:]]*//'`
    prints nothing (comments only); `pub struct ConnCtx`, `pub struct AuditEntry` and the
    sealed `Governance` have the same fields as `15009b2`; `git diff <merge-base>..HEAD --
    Cargo.lock crates/aitm/Cargo.toml` is empty.
41. **AC41** `[guard]` No existing test is edited (the one exception is the one-line environment
    addition to `crates/aitm/tests/shutdown.rs`, AC38), in particular `mcp.rs`
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
