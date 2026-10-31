# Audit ring integrity design

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief; the Architect's calls listed at the end stand as written)
**Research inputs:** no `docs/research/` note; this closes the three Minors the
PR 145 security panel accepted as follow-ups
(`docs/superpowers/plans/2026-10-30-web-bus-agent-governance-plan.md`, Review log
row 3, and the "audit signal-to-noise" follow-up) and the spec Non-goal they came
from (`docs/superpowers/specs/2026-10-30-web-bus-agent-governance-design.md`,
Design 6 items 4 and 5). Code read on `bd0f9b7`:
`crates/aitm-core/src/{audit,redact,ctx,command,lib}.rs`,
`crates/aitm-mcp/src/{server,transport,http}.rs` (`record_audit`, `run_tool`,
`call_tool`, `redact_args`, `redact_value`, `client_label_from_initialize`),
`crates/aitm/src/web/bridge.rs`, `crates/aitm-plugins/src/agent.rs`,
`crates/aitm-ca/src/audit.rs`, `crates/aitm-findings/src/{store,commands}.rs`,
`crates/aitm-poc/src/{builder,runner}.rs`,
`crates/aitm-plugin-scanner/src/{discover,reproduce,crawl,commands}.rs`, the ring
tests in `crates/aitm-mcp/tests/mcp.rs` (~3043-3430), `crates/aitm-core/tests/{trust_gate_scan,classifier_wildcard_free}.rs`,
and the UI consumers in `apps/web` and `apps/mac`.

## Intent

The F2 audit ring is the only audit record in production (`durable_audit` has no
production caller and no config key), and since PR 145 the `aitm web` bridge writes
to it. Four defects make it unreliable as evidence. (1) One connection can evict the
whole ring: the bridge lets a connection send 16 frames x 256 lines = 4096 calls in
one burst, and TCP, stdio and HTTP have no such cap at all. (2) Bridge entries are
`origin: mcp, client_label: null`, indistinguishable from a TCP agent that sent no
`clientInfo`; and `client_label` itself is an uncapped, unscrubbed, first-writer
string that is cloned into every entry, every finding and the durable JSONL.
(3) The web UI's own polling (~150 calls a minute at idle, over the default link
that carries the *agent* token) turns the ring over in ~27 minutes. (4) The shared
redaction vocabulary misses `sid=`, `session=`, `auth=`, `jwt=` and `csrf=`, so they
pass through `args_summary`. This change makes the ring a bounded, fair, attributable
record that polling and floods cannot erase, bounds every field of an entry, and
widens redaction, with the smallest diff that does it: no field is added to
`ConnCtx` or `AuditEntry`.

## Goals

- One source (a distinct origin plus client label) cannot evict another source's
  entries from the ring, however many calls it makes.
- Successful `Read` calls (UI polling, status checks) can never evict a refused,
  failed, `Write` or `Sensitive` entry.
- Every bridge connection's entries carry a server-minted `client_label` of
  `web-bridge`, and no client can declare that name.
- A client label and an error reason are bounded in size and scrubbed before they
  reach the ring, the durable sink, the pushed `agent` line, or a finding.
- `args_summary` and every other `scrub_text` consumer masks `sid`, `jwt`, `csrf`,
  `session` and `auth` credentials without a `Bearer`/`Authorization` frame, while
  `author=`, `authority=`, `inside=`, `side=` and `auth.example.com:8443` are left
  alone.
- Every behavioural change is listed per surface (Semantics changes by surface) so
  the macOS app, the web UI, the TUI and agents are not surprised.

## Non-goals

- **Wiring `durable_audit`.** Decided below (Design 1); named follow-up "durable
  audit wiring", its own spec.
- **Rate-limiting or refusing calls**, at the bridge or elsewhere. The ring must
  protect itself on every transport; throttling legitimate use is a different change.
- **Auditing protocol-level failures.** An unknown tool or invalid arguments is a
  JSON-RPC error, not a tool result, and is not audited today. Unchanged.
- **Tamper evidence** (signing, hash chaining). A source can still overwrite its own
  history (Residual risks).
- **Changing the shape of `agent.activity`, `agent.status`, or the
  `notifications/aitm/agent` push**, or adding a default `limit` to `agent.activity`.
- **A field on `ConnCtx` or `AuditEntry`.** See Constraints.
- **Authenticating labels.** A declared label stays an unauthenticated display
  string; only server-minted labels and `origin` carry meaning.
- **Consolidating the scanner's own vocabulary** (`EXTRA_SECRET_NEEDLES`,
  `redact_needle_pairs`). It keeps its wider substring list as a superset; named
  follow-up "scanner vocabulary consolidation". The scanner is not edited at all.
- **camelCase compound keys** (`userSession=`). The shared vocabulary matches whole
  segments and a fixed substring list, as the PoC builder always did.
- Any change to `aitm-ca` (including `entry_to_jsonl`) or `aitm-findings`.

## Anti-goals

- A ring that drops or rejects the newest entry, or evicts anything while it is not
  full. A lone busy source must still be able to use a whole lane.
- A fix that works only for the web bridge. The ring protects itself for stdio, TCP
  and HTTP agents too.
- Quietly changing which calls are audited. The count of audited calls does not
  change; only where they are kept and for how long.
- A label that lets a TCP agent impersonate server-minted attribution, or that
  carries an unscrubbed credential into a finding or the JSONL.
- A redaction widening that corrupts hostnames, JSON structure, or the scanner's
  quote-aware output, or that creates a fourth secret list.
- Config keys, new dependencies, or a compile ripple for sibling sessions.

## Constraints

- **No field added to `ConnCtx` or `AuditEntry`.** Both are built by struct literal
  in many places, including tests, and sibling sessions are editing `aitm-mcp` and
  the `/bus` bridge. Literal sites, all left untouched: `ConnCtx` at
  `server.rs` (definition), `crates/aitm-mcp/tests/mcp.rs` (six sites),
  `crates/aitm/tests/web_bus_ask_split.rs:149`, and `bridge.rs:252` (which this
  change replaces with a helper call, not a field change); `AuditEntry` at
  `server.rs:1631` (the only production constructor), `crates/aitm-ca/tests/audit.rs:136`,
  and the `audit.rs` unit-test helper. Everything new is an additive `pub` item, an
  inherent method, a free function, or a const.
- **Trust-gate scan.** `crates/aitm-core/tests/trust_gate_scan.rs` bans `==`, `!=`,
  `matches!`, and `if let` against the agent role in any `crates/*/src` file,
  including `#[cfg(test)]` modules. New code compares origins through
  `origin_label(..)` (a `&'static str`), never against the `Mcp` variant. `Frontend`
  is `Copy + Eq` but not `Hash`, so a ring key uses `origin_label`.
  `crates/aitm-core/tests/classifier_wildcard_free.rs` reads the body of
  `origin_label` textually: that function is not edited.
- **Bounded memory, in bytes as well as entries.** After this change every field of
  an entry has a cap: `command` (a registered name or one of three server verbs),
  `args_summary` (512 bytes plus an ellipsis, existing), `client_label` (64 chars,
  new), `AuditResult::Error` reason (1024 bytes, new). With lanes of 4096 and 2048
  entries the ring is bounded at roughly 6144 entries x about 2 KiB worst case, about
  12 MiB, and typically a few MiB.
- **One short critical section per call, no I/O under the lock.** The ring stays one
  `Mutex`; an append is O(number of tracked sources, at most 35), a `recent` is
  O(n log n) over at most 6144 entries.
- **Fail closed.** An unknown sensitivity, a failed or refused call, and the trait
  method `AuditSink::append` all land in the evidence lane. A `Sensitivity` variant
  added later is evidence until someone classifies it as routine.
- **Edits stay in:** `aitm-core` (`audit.rs`, `redact.rs`, `lib.rs` re-exports),
  `aitm-mcp` (`server.rs`, `transport.rs`), `aitm` (`web/bridge.rs`), `aitm-poc`
  (`builder.rs`, delegation only), `aitm-plugins` (`agent.rs`, description strings
  and doc comments only), and new tests. Nothing under `aitm-ca`, `aitm-findings`,
  `aitm-plugin-scanner`, `apps/`, or any existing test file.
- No new dependencies, no `unsafe`, no config keys. `regex` is already an `aitm-core`
  dependency and stays used by the two header/bearer passes.
- Sandbox: every test except the one socket test (AC30) runs in the Bash sandbox.

## Design

### 1. Flooding: two lanes, per-source fair share, a bounded source table

**Decision (Architect's call on the details; the two-lane shape is the lead's).**
`AuditRing` holds two bounded lanes behind its one mutex.

- **Evidence lane**, capacity `DEFAULT_AUDIT_CAPACITY` (4096, unchanged). Holds every
  entry that is not a successful `Read`: every refused or failed entry of any
  sensitivity, and every successful `Write` or `Sensitive` run.
- **Routine lane**, capacity `DEFAULT_ROUTINE_AUDIT_CAPACITY` = 2048
  (`DEFAULT_AUDIT_CAPACITY / 2`, Architect's call: about 13 minutes of one polling UI
  by itself, and it keeps the worst-case `agent.activity` reply at 1.5x what it is
  today). Holds only successful `Read` invocations.

`AuditRing::new(capacity)` keeps its signature: evidence capacity is `capacity`,
routine capacity is `(capacity / 2).max(1)`. A new
`AuditRing::with_lane_capacities(evidence, routine)` sets both. `Default` equals
`new(DEFAULT_AUDIT_CAPACITY)`.

**Routing.** A new free function `lane_for(sensitivity: Option<Sensitivity>, result:
&AuditResult) -> AuditLane` in `aitm-core` is the single, unit-tested rule: `Routine`
iff `sensitivity` is `Some(Sensitivity::Read)` and `result` is `AuditResult::Ok`;
everything else, including `None`, is `Evidence`. `AuditSink::append` (the trait
method, used by durable sinks and any caller that does not know) routes to the
evidence lane. A new inherent `AuditRing::append_in(&self, lane: AuditLane, entry:
AuditEntry)` takes the lane explicitly. `McpServer::record_audit` looks the
sensitivity up with `self.registry.command(name).map(|c| c.sensitivity())` and calls
`lane_for` then `append_in`. No `Sensitivity` or lane is stored on the entry: routing
is a write-time decision, not entry data, and storing it would force the three
`AuditEntry` literal sites and change the `agent.activity` and JSONL shapes.
Server-handled verbs behave as before: `flow.subscribe`/`unsubscribe` are audited only
when they error, so they are evidence; `agent.approve` is registered as `Sensitive`,
so it is evidence.

**Order across lanes.** Each stored entry gets a monotonic sequence number (a private
`u64`, assigned under the lock). `recent` merges both lanes by sequence, oldest first,
so call order is preserved exactly; `since` and `limit` keep their meaning across both
lanes; `count_since` and `len` sum both lanes. Two new read helpers,
`evidence_len()` and `routine_len()`, let tests and diagnostics see the lanes.

**Fair-share eviction inside each lane.** A lane never exceeds its capacity: when it
holds more than its capacity after an insert, it evicts the **oldest entry of the
source that holds the most entries in that lane**; on a tie it evicts the entry with
the smallest sequence number among the tied sources' oldest entries. A *source* is
`(origin_label(entry.origin), entry.client_label)`. The new entry is inserted first
and is never the victim (every candidate victim is older), and nothing is evicted
while the lane is not full, so a lone busy source still uses the whole lane and the
existing `ring_is_bounded_and_evicts_oldest` behaviour (one source, oldest out) is
unchanged.

**A bounded source table.** Each lane tracks at most `MAX_AUDIT_SOURCES` (32) distinct
sources. An entry from an untracked source, when the table is full, is filed under a
shared per-origin overflow source (one per origin label, at most three). A source
leaves the table when its last entry is evicted. The effect is a hard floor: with at
most `MAX_AUDIT_SOURCES + 3` = 35 buckets, a source that holds entries keeps at least
`capacity / 35 - 1` of them (about 116 of 4096) against **any** flood by others,
including a flood that mints a fresh label per connection. Without the table, a
flooder minting labels makes every bucket a singleton and fair share degrades to
"evict the honest source down to one entry". Origin is server-assigned and cannot be
forged, so a hostile `mcp`-origin flood fills the `mcp` overflow bucket and never
`operator`'s.

**Why both lanes and fair share (each alone leaves a hole).** Lanes alone: a source
that floods *refused* calls, or a polling UI that is being refused under `paused` or
`readonly` (120 refusals a minute from one UI), fills the evidence lane and evicts
everyone's evidence. Fair share alone: a source's own successful polls evict its own
earlier refusals (the same-source case, which fair share cannot help). Together: polls
never touch evidence, and a flood in either lane only ever eats the flooder's own
oldest entries.

**Alternatives rejected.**

- *Dropping, sampling, or coalescing entries under load.* An audit record that
  silently omits calls is worse than one that forgets old ones; and the count of
  audited calls is observable (`actions_last_minute`, PR 145 AC5).
- *Per-origin rings.* The default `aitm web` link and every TCP agent are both origin
  `mcp`, so an origin split does not separate the noise from the agent it must not
  evict, and a flood inside one origin is untouched.
- *A larger single ring.* Moves the cliff; one 16 MiB frame of tiny lines still wins.
- *Not auditing `Read` calls, or only trusted-control `Read` calls.* Loses the read
  trail (a `flow.detail` read is how captured credentials leave) and breaks PR 145
  AC5; and the trusted-control variant silences only the operator link (see Design 3).
- *Throttling at the bridge* (`MAX_IN_FLIGHT`, `MAX_LINES_PER_FRAME`). The other three
  transports have no such cap, and throttling legitimate use is out of scope.
- *Storing the lane or sensitivity on the entry.* See Routing.

**`durable_audit` wiring: not in this change (Architect's call).** No production code
calls `McpServer::with_durable_audit`, and `McpFile` (`config_file.rs`) has
`deny_unknown_fields` and no audit key, so it is not a wiring fix but a feature: a new
config key (name, precedence, default off or on), a default path and 0600/0700
permissions, rotation and retention, disk-full behaviour, and a decision on blocking
file I/O, because `AuditSink::append` is synchronous and runs inline in `record_audit`
on the call path. It is the complete answer to every residual below and deserves its
own spec and panel. This change makes the in-memory record sound; it does not make it
durable.

### 2. Attribution and label hygiene

**Decision.** Three small pieces, all in `aitm-core::audit` so one definition serves
every surface.

1. `pub const WEB_BRIDGE_CLIENT_LABEL: &str = "web-bridge";` The bridge builds its one
   `ConnCtx` per authenticated connection through a new
   `pub(crate) fn bridge_conn_ctx(role: Frontend, conn_id: u64, out: NotificationSink)
   -> ConnCtx` in `bridge.rs` that sets `client_label` to that constant. The label
   names the *path*, not the client: the bridge deliberately never parses
   `initialize.clientInfo` (today it does not), because any holder of the agent
   token, browser script or not, can open the socket. Operator-token bridge
   connections get the same label with `origin: operator`.
2. `pub fn sanitize_client_label(raw: &str) -> Option<String>`: the one sanitiser.
   Reads at most the first 1024 chars of `raw` (so work is bounded no matter the
   input), drops every `char::is_control` character and the invisible and bidi set
   U+200B..=U+200F, U+2028..=U+202E, U+2060..=U+2069, U+FEFF (so a label cannot
   spoof another in a UI), runs `redact::scrub_text`, trims, truncates to
   `MAX_CLIENT_LABEL_CHARS` (64) chars, and returns `None` if nothing is left. It is
   idempotent, and it does not rewrite `web-bridge`.
3. `pub fn declared_client_label(raw: &str) -> Option<String>`: `sanitize_client_label`
   plus a reserved-name guard. If the sanitised label equals (trimmed, ASCII
   case-insensitive) a server-minted label, `web-bridge` today, it becomes
   `"<label> (declared)"`. Applied **only where a client declares a label**
   (`transport.rs` capture), never to the server-minted one.

**Where the sanitiser runs.** At capture (`client_label_from_initialize` returns
`declared_client_label(name)`), so `ConnCtx.client_label` is small and clean from the
start; and again on **consumption**, through one private helper in `server.rs`,
`conn_audit_label(conn: &ConnCtx) -> Option<String>`, used both where the
`CommandHost` is built (`run_tool`, today `host.with_client_label(label.clone())`) and
where the `AuditEntry` is built (`record_audit`). `ConnCtx.client_label` is a `pub`
field that tests and future transports set directly, so capture-only sanitising can
be bypassed; consumption-time sanitising cannot. On the capture path the re-sanitise
costs O(64). The reserved-name guard is not applied on consumption, so `web-bridge`
passes through unchanged.

**Interaction with findings (decided, with the code paths).** A finding's
`client_label` comes from `host.client_label()` in `findings.record`
(`aitm-findings/src/commands.rs`, `client_label: host.client_label().map(..)`) and in
`poc.run` (`aitm-poc/src/runner.rs`, same expression). `CommandHost.client_label` is
set in exactly one place, `run_tool`. After this change that place uses
`conn_audit_label`, so (a) findings recorded over the bridge carry `client_label:
"web-bridge"` instead of `null`; (b) every finding label is at most 64 chars,
control-free and scrubbed; (c) the schema is unchanged (`Option<String>`), and
existing records keep their stored values, including `null`; (d) `DiskFindingStore::
record` keeps its own `scrub_text` on the label, now a harmless second application
because the sanitiser's output is stable under `scrub_text`; (e) a TCP agent that
declares `web-bridge` cannot reach a finding under that name, only
`web-bridge (declared)`. No `aitm-findings` edit is needed.

**Interaction with the CA and durable JSONL (decided).** `crates/aitm-ca/src/audit.rs`
`entry_to_jsonl` writes `entry.client_label` raw. Its only production feed is
`record_audit`, whose single `AuditEntry` value is cloned to the ring, to the durable
sink, and to the push line, so the label is already sanitised when it gets there. JSON
string escaping already prevents line injection. `entry_to_jsonl` is therefore not
edited (it is outside this spec's file list and not wired in production); the
residual is that a future caller that hand-builds an entry and calls it directly
bypasses the sanitiser, and the "durable audit wiring" spec owns that contract.

**Alternatives rejected.**

- *Honour a declared `clientInfo.name` on the bridge* (for example
  `web-bridge:<declared>`). Forgeable by any token holder and never parsed today;
  adds an attacker-controlled string to a server-minted one.
- *A new `transport` field on `AuditEntry` or `ConnCtx`.* Compile ripple across
  sibling sessions for what a label already carries.
- *Reserving the `aitm-*` family.* First-party clients (`aitm-mac`, `aitm-tui`)
  legitimately declare those names; only labels the server itself mints can be
  reserved.
- *Trusting the label.* It stays display-only (Residual risks): `origin` is the only
  authoritative field.

### 3. Noise: lanes and fair share are the fix; no trusted-control exemption

**Decision.** The retention problem is cured by Design 1, not by changing which calls
are audited. With the default link, the UI's `flow.list` (500 ms) and `proxy.status`
(2 s) polls are agent-token calls, origin `mcp`, source `(mcp, web-bridge)`. They are
successful `Read` calls, so they go to the routine lane and can never touch the
evidence lane; inside the routine lane they are one source and are evicted first
whenever another source needs room. The evidence lane's turnover then depends only on
non-`Read` and refused or failed calls. The case lanes do not cover, a UI being
refused every tick under `paused` or `readonly`, is exactly what fair share inside the
evidence lane covers.

**Why not exempt trusted-control `Read` calls.** The default `aitm web` link carries
the agent token, so its polls are `Frontend::Mcp`, gated and audited as `mcp`, not
trusted control. An exemption would silence only the operator link (the macOS app and
the operator URL) and leave the default link, which is the noise, untouched. **Why not
a per-origin ring:** see Design 1.

**`agent.status.actions_last_minute`: unchanged, counts both lanes (Architect's
call).** PR 145 AC5 pins `== 2` after one allowed `Read` and one refused `Write`.
It still counts every held entry recorded in the last minute across both lanes, so a
polling UI inflates it exactly as it did after PR 145, and it saturates at what the
lanes hold (6144) rather than 4096 under a sustained extreme rate. Clients that want a
per-source rate filter `agent.activity` (with `since`) by `origin` and `client_label`,
which now separates the UI from agents.

**`notifications/aitm/agent`: unchanged (Architect's call).** Every audited call,
routine ones included, is still pushed to every subscribed connection. The push
volume from a polling UI is a separate signal-to-noise question (the stream is not
the ring), named follow-up "agent-stream filtering"; the entries now at least carry
`client_label: "web-bridge"` so a subscriber can drop them.

### 4. Redaction: one vocabulary, a quote-aware pair pass

**Decision.** Promote the PoC builder's vocabulary into `aitm-core::redact` as the
single source for both `is_secret_key` and `scrub_text`, and make the pair pass decide
by calling `is_secret_key`, so the two cannot diverge by construction.

**The vocabulary.** `is_secret_key(key)` is true when the ASCII-lowercased key

- contains any substring needle: the existing twelve (`authorization`, `token`,
  `password`, `passwd`, `pwd`, `secret`, `cookie`, `api_key`, `apikey`, `api-key`,
  `bearer`, `credential`) plus `sessionid` and `phpsessid` (so `JSESSIONID`,
  `sessionId`, `ASP.NET_SessionId`, `PHPSESSID` match), or
- has any whole segment equal to `sid`, `jwt`, `csrf`, `session`, or `auth`, where
  segments are the maximal runs of ASCII alphanumerics (split on every other
  character). So `x-auth`, `connect.sid`, `_csrf` match; `author`, `authority`,
  `authenticated`, `inside`, `side`, `sidebar`, `subsidiary` do not.

This is exactly the union the PoC builder's `is_secret_poc_key` computes today, so
promoting it is behaviour-preserving there and the builder then holds no list of its
own (Design 4a). The scanner's `is_secret_name` is `is_secret_key` OR its own wider
substring list; a superset of the new predicate, so its name decisions do not change.

**The pair pass, and why a regex edit is not enough (found by reading, to be
confirmed by the Task 2 oracle run).** `scrub_text` today has three passes: an
`Authorization` line, a `Bearer <token>`, and a regex for `key=value`/`"key":"value"`
pairs. The scanner's `scrub_embedded` is `redact_needle_pairs(scrub_text(..))`: its
second step is a careful linear scan that handles quoted values with escapes. If the
third regex is merely widened with `sid|session|auth|jwt|csrf`, `scrub_text` masks
those keys first with its cruder value rule (a value ends at the first
space/quote/`&`/`;`/`,`/`}`), and the scanner's scan never sees the original. By
reading, `scrub_embedded(r#"{"sid":"a\"b c","n":1}"#)` would then become
`{"sid":"[redacted]"b c","n":1}` (leaking `b c`) and `scrub_embedded("{'jwt' : 'a b',
'n':1}")` would leak `b`; both are asserted correct by
`reproduce::tests::scrub_embedded_handles_quotes_and_escapes`. The same defect already
exists in `scrub_text` for `{"password":"hunter 2"}` (it yields `{"password":"[redacted]
2"}`, leaking `2`). So the pair pass must be quote-aware, and a regex cannot also
call `is_secret_key`, so the third pass becomes a private linear scan (the first two
passes stay regex):

- A **key run** is a maximal run of ASCII alphanumerics, `_`, `.`, `-`, and any
  non-ASCII char (as the old Unicode `\w` did). Optional one closing quote, optional
  blanks, then `=` or `:` (the separator), optional blanks, optional one opening
  quote, then the value.
- If `is_secret_key(run)` and the value is non-empty, the value is replaced by
  `[redacted]` and the scan resumes after the value. If the key is not secret the scan
  resumes **after the key run, not after the value**, so a pair nested in a non-secret
  value (`next=/cb?sid=S1`) is still seen.
- **Value rule.** If the value opened with a quote and a matching unescaped quote
  exists, the value is everything up to it (a backslash skips the next char). Otherwise
  (unquoted, or an opening quote that never closes) it runs to the first whitespace,
  `&`, `;`, `,`, `"`, `'`, or `}`. An empty value is left alone. This is the rule
  `redact_needle_pairs` and its `closing_quote` already implement, so the scanner's
  pipeline gives the same output after the change.
- **host:port exemption (Architect's call).** A pair with separator `:`, an unquoted
  key run that contains a `.`, and a value that is 1 to 5 ASCII digits immediately
  after the `:` followed by a terminator (`/`, `?`, `#`, whitespace, a pair delimiter,
  or end of text) is a `host:port`, not a credential, and is left alone. Without it,
  `auth.example.com:8443` (a common SSO host on a lab port) becomes
  `auth.example.com:[redacted]` in audit args, findings `target`, and scanner output,
  because `auth` is now a secret segment. `=` is never exempt; a key with no `.`
  (`sid:12345`) is not exempt; a quoted JSON key is not exempt.

Linear time, no per-key allocation except at candidates (a key run followed by a
separator), as the scanner's scan already is. `scrub_text`'s doc comments and the
module doc are rewritten to describe the one vocabulary, the quote rule, and the
exemption.

**4a. The PoC builder delegates.** `aitm-poc/src/builder.rs` deletes
`EXTRA_SECRET_KEY_SEGMENTS` and `SESSION_KEY_SUBSTRINGS`; `is_secret_poc_key` keeps its
name (three call sites) and its body becomes one call to
`aitm_core::redact::is_secret_key`. Its two stale doc comments (the "shared ... are
unchanged here" note near the top of the builder, and the comment above the old
constants) are corrected. The builder's own per-part scrubbing of embedded query
values stays as is: redundant for the vocabulary now, harmless, and re-architecting it
is not this change. Its existing tests are the equivalence oracle.

**Blast radius (callers checked, and what each existing suite asserts).**

| Caller | Effect | Oracle |
|---|---|---|
| `aitm-mcp` `redact_value` / `redact_args` / `record_audit` | the point of the change: `sid`, `jwt`, `csrf`, `session`, `auth` keys and `key=value` content masked in `args_summary` and error reasons | `audit_redacts_*` in `mcp.rs` unmodified, plus AC29 |
| `aitm-plugin-scanner` `discover::is_secret_name` | none (superset) | `discover` tests, unmodified |
| `aitm-plugin-scanner` `reproduce::scrub_embedded` | same output: step 2 now masks the shared vocabulary with the same value rule, step 3 sees `[redacted]` and rewrites it to `[redacted]`; its wider substring needles (`subsidiary=acme`) are still masked by step 3 | the `scrub_embedded_*` tests, unmodified (`..._handles_quotes_and_escapes`, `..._leaves_innocent_text_and_empty_values_alone`, the JSON, form, and Referer cases) |
| `aitm-plugin-scanner` `crawl::safe_target`, `commands.rs` endpoint rows and `endpoint_flows` keys | URLs with `?sid=`, `?session=`, `?auth=`, `?jwt=`, `?csrf=` now show `[redacted]` (a leak fix); both sides of the url-to-flow link pass through the same `scrub_text`, so the link holds; two URLs that differ only in such a value collapse to one key | the scanner suite, unmodified (no scanner test asserts a `sid`/`session`/`auth` query value survives `scrub_text`; checked by grep) |
| `aitm-findings` `DiskFindingStore::record` (`title`, `notes`, `target`, `client_label`) | the same masking in stored YAML; `https://auth.example.com:8443/x` is untouched by the exemption | findings suites, unmodified |
| `aitm-poc` builder | none (Design 4a) | `crates/aitm-poc/tests/builder.rs`, unmodified |

**Alternatives rejected.**

- *Extend the regex literal.* Two vocabularies in one file again, the pre-emption
  defect above, no word-boundary control (a regex without lookbehind cannot say "start
  of the key run").
- *Substring semantics for `sid` and `auth`.* Catches `author`, `inside`, `subsidiary`
  and `authority`, which the brief and the existing core test require to stay
  non-secret. (The scanner keeps substring semantics as a deliberate superset.)
- *Widen `is_secret_key` only.* Leaves `sid=` unframed inside values, the reported
  defect.
- *A third list.* The PoC builder's already exists and is reviewed.

### 5. Per-entry size bound: the error reason

**Decision (Architect's call, found while verifying the label vector).**
`record_audit` stores `AuditResult::Error(scrub_text(reason))` with no length cap, and
a command's error text can echo caller input (the existing test
`audit_redacts_secret_in_error_reason` exists because a header error quotes the
offending value). That is the same memory-amplification shape as the label: up to the
16 MiB message cap, times 4096 entries. The reason is therefore capped at
`DEFAULT_RESULT_REASON_CAP` (1024 bytes) on a char boundary with a trailing `…`,
after scrubbing (the implementation may pre-truncate to a larger bound first to bound
the scrub's work). The caller still receives the full text in the tool result; only
the audit copy is capped. No policy refusal text is anywhere near the cap.

### 6. Semantics changes by surface

| Surface | Changes | Does not change |
|---|---|---|
| `agent.activity` (TUI Agent page, `apps/web` `AgentPanel`, macOS `Activity.swift`, agents) | Merged oldest-first by call order across the two lanes; a source's retention depends on its own volume and on lane fair share, not on other sources' polling; default-link entries now carry `client_label: "web-bridge"`; labels are at most 64 chars and scrubbed; error reasons are at most 1 KiB; a full ring can hold up to 6144 entries, so an unlimited call can be 1.5x as large | Entry shape, `since`/`limit` meaning, oldest-first order, that every audited call is present while the ring is not full |
| `agent.status.actions_last_minute` | Counts both lanes; saturates at what is held; documented as including every surface's polling | The value in PR 145 AC5 (`== 2`); the field and its type |
| `notifications/aitm/agent` push | `client_label` is sanitised; bridge entries carry `web-bridge` | One push per audited call, routine ones included; shape |
| Findings (`findings.record`, `poc.run`) | `client_label` is `web-bridge` for bridge-recorded findings (was `null`); every label is at most 64 chars, control-free and scrubbed | Schema; old records; the store's own `scrub_text` |
| CA and durable JSONL (`entry_to_jsonl`, `FileAuditLog`) | Receives the sanitised label | Format; not wired in production |
| macOS app, TUI | Their own polls land in the routine lane under their declared label; nothing reads `client_label`, so no code change | Everything they call |
| `aitm web` UI (default link) | Its polls are the `(mcp, web-bridge)` source; evidence is no longer evicted by them; it still inflates `actions_last_minute` | Poll cadence; the link's agent role and gating |
| Scanner output, findings text, audit args | More keys masked (`sid`, `jwt`, `csrf`, `session`, `auth`, `sessionid`, `phpsessid`); quoted values masked whole; `host:port` left alone | Names the scanner already masked |
| PoC builder | None observable | |

### 7. Rebase hazards with the sibling sessions

Sessions are editing `crates/aitm-mcp` and the `/bus` bridge now. Mitigations: every
edit in a shared file is the smallest hunk that works; `crates/aitm-mcp/tests/mcp.rs`
is not touched (new tests go in a new file, `crates/aitm-mcp/tests/audit_integrity.rs`,
with its own small helpers, the house style); `ConnCtx` and `AuditEntry` gain no field;
the hunks are `server.rs` `record_audit` (about 1600-1645) and the one host-label
`match` in `run_tool` (about 1564); `transport.rs` `client_label_from_initialize`
(about 141-148); `bridge.rs` the `ConnCtx { .. }` literal (about 252-257) plus a new
test module entry at the end of the file; `lib.rs` the one `pub use audit::{..}`
statement (a sibling adding an export there is a one-line merge). The orchestrator
rebases the branch on `main` before dispatching Task 6 and again before the panel.

### 8. Residual risks

1. **A source can overwrite its own history.** A rogue agent that floods its own
   source evicts its own earlier refusals; fair share protects *other* sources only.
   Only durable audit (a follow-up) answers this; this ring is a live view, not
   tamper-evident storage.
2. **A source table floor, not a wall.** With 35 buckets a source keeps at least
   `capacity / 35 - 1` entries against any flood. A source that first appears *after* a
   hostile client has saturated the 32 slots shares its origin's overflow bucket with
   that client and gets no isolation from it; origin still separates `mcp` from
   `operator`.
3. **Reads are not evidence-grade.** Successful `Read` calls, including a `flow.detail`
   read that exfiltrates captured credentials, live in the shorter routine lane and
   can be forgotten sooner. That is the price of keeping polling out of evidence.
4. **Labels are display strings.** The reserved-name guard is an exact match after
   sanitising; a homoglyph (`web‑bridge` with U+2011) or a first-party name such as
   `aitm-mac` can still be declared by any client. Nothing may grant trust by label;
   `origin` is the only authoritative field.
5. **`actions_last_minute` is inflated by polling UIs** and saturates under extreme
   rates (documented).
6. **Redaction is conservative and bounded.** Prose such as `session: expired` or
   `auth: none` is masked after the colon; `session-store:6379` (no `.`) is masked;
   `userSession=` (camelCase) and a bare credential with no `key=`/`Bearer` frame are
   not caught; a numeric `host:port`-shaped credential written `a.sid:1234` is
   exempted.
7. **`entry_to_jsonl` trusts its caller.** A future direct caller with a hand-built
   entry bypasses the sanitiser.
8. **No durability.** A restart empties the ring.
9. **The push stream is unfiltered**, so a polling UI still produces one push per call.

## Acceptance criteria

`[red]` means the test fails on `bd0f9b7` (or at the start of its task, for the ones
that need an earlier task's API); `[guard]` means it passes before and pins behaviour
that must not change. Test names are exact. No existing test is edited.

**Redaction (`crates/aitm-core/src/redact.rs`, `mod tests`)**

1. **AC1** `[red]` `is_secret_key_covers_the_session_and_auth_family`: `is_secret_key`
   is true for `sid`, `SID`, `jwt`, `csrf`, `_csrf`, `session`, `auth`, `x-auth`,
   `connect.sid`, `sessionId`, `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`.
2. **AC2** `[guard]` `is_secret_key_leaves_lookalikes_alone`: false for `author`,
   `authority`, `authenticated`, `inside`, `side`, `sidebar`, `subsidiary`, `sessions`,
   `path`, `host`, `body`, `note`, `method`. (The existing
   `secret_keys_matched_as_substring_case_insensitively` still passes.)
3. **AC3** `[red]` `scrub_text_masks_unframed_session_credentials`:
   `sid=abc123` becomes `sid=[redacted]`;
   `/cb?next=/home&sid=S1&page=2` becomes `/cb?next=/home&sid=[redacted]&page=2`;
   `session=abc; theme=dark` becomes `session=[redacted]; theme=dark`;
   `auth=xyz` becomes `auth=[redacted]`; `jwt=eyJa.b.c` becomes `jwt=[redacted]`;
   `csrf=c1` becomes `csrf=[redacted]`; `PHPSESSID=p1` becomes `PHPSESSID=[redacted]`;
   `connect.sid=s%3Aabc` becomes `connect.sid=[redacted]`;
   `x-auth: v1` becomes `x-auth: [redacted]`;
   `{"sid":"S1","n":1}` becomes `{"sid":"[redacted]","n":1}`.
4. **AC4** `[guard]` `scrub_text_leaves_lookalike_pairs_alone`: unchanged, byte for
   byte: `author=bob`, `authority=example.com`, `inside=1`, `side=left`, `sidebar=1`,
   `authenticated=true`, `subsidiary=acme`, `page=2&q=hello`, `sid=&x=1` (empty value).
5. **AC5** `[red]` `scrub_text_masks_quoted_values_whole`:
   `{"password":"hunter 2"}` becomes `{"password":"[redacted]"}`;
   `{"sid":"a\"b c","n":1}` becomes `{"sid":"[redacted]","n":1}`;
   `{'jwt' : 'a b','n':1}` becomes `{'jwt' : '[redacted]','n':1}`;
   `sid="abc&x=1` becomes `sid="[redacted]&x=1`; `{"sid":"","n":1}` is unchanged.
6. **AC6** `[red]` `scrub_text_sees_pairs_nested_in_a_non_secret_value`:
   `next=/cb?sid=S1` becomes `next=/cb?sid=[redacted]`.
7. **AC7** `[red]` (the `token.` row) `scrub_text_does_not_mask_a_host_port`: unchanged:
   `https://auth.example.com:8443/login`, `auth.example.com:8443`,
   `token.example.com:8443/x`; still masked: `sid:12345` becomes `sid:[redacted]`,
   `auth=1` becomes `auth=[redacted]`, `{"sid":12345}` becomes `{"sid":[redacted]}`.
8. **AC8** `[red]` `scrub_text_and_is_secret_key_share_one_vocabulary`: for a table of
   keys (every key in AC1 and AC2 plus the twelve substring needles),
   `is_secret_key(k)` equals `scrub_text(&format!("{k}=VALUE9")) != format!("{k}=VALUE9")`.
9. **AC9** `[guard]` `scrub_text_survives_hostile_inputs`: 4 MiB of `sid=` repeated
   returns exactly `sid=[redacted]` (the whole remainder is one unquoted value); 4 MiB
   of `a`, 2 MiB of `"`, 2 MiB of `\`, and 1 MiB of `sid='x ` repeated each return
   without panicking (a guard against a quadratic scan, not a timing assertion).
10. **AC10** `[guard]` The scanner, PoC, findings, plugins, and MCP suites pass
    unmodified after Tasks 1 and 2, in particular
    `reproduce::tests::scrub_embedded_handles_quotes_and_escapes` and
    `scrub_embedded_leaves_innocent_text_and_empty_values_alone`; `git diff` shows no
    change under `crates/aitm-plugin-scanner`.
11. **AC11** `[guard]` After Task 3 `crates/aitm-poc/src/builder.rs` contains neither
    `EXTRA_SECRET_KEY_SEGMENTS` nor `SESSION_KEY_SUBSTRINGS` (a grep that counts `0`),
    `is_secret_poc_key` has no vocabulary of its own, and
    `crates/aitm-poc/tests/builder.rs` passes unmodified.

**Labels**

12. **AC12** `[red]` (`audit.rs`) `sanitize_client_label_bounds_a_hostile_label`:
    a 10 MiB string of `A` yields `Some("A" x 64)`; a 10 MiB string of `\u{0}` yields
    `None`; `"a\u{0}b\nc\u{202E}d"` yields `Some("abcd")`; `"token=abc123"` yields a
    string with no `abc123` that contains `[redacted]`; `""` and `"   "` yield `None`;
    `"aitm-mac"` yields `Some("aitm-mac")`; `"web-bridge"` yields `Some("web-bridge")`;
    `sanitize(sanitize(x)) == sanitize(x)` for each of these.
13. **AC13** `[red]` (`audit.rs`) `declared_client_label_rewrites_a_reserved_name`:
    `"web-bridge"` yields `Some("web-bridge (declared)")`; `"  WEB-BRIDGE "` yields
    `Some("WEB-BRIDGE (declared)")`; `"aitm-mac"` yields `Some("aitm-mac")`.
14. **AC14** `[red]` (`transport.rs`) `client_label_from_initialize_is_bounded_and_unforgeable`:
    an `initialize` whose `clientInfo.name` is 10 MiB of `A` yields a 64-char label;
    name `web-bridge` yields `web-bridge (declared)`; `aitm-mac` yields `aitm-mac`;
    an empty or missing name yields `None`. The existing
    `client_label_captured_from_initialize` in `mcp.rs` still passes (`[guard]`).
15. **AC15** `[red]` (`bridge.rs`) `bridge_conn_ctx_carries_the_server_minted_label`:
    for the operator and the agent role, the returned `ConnCtx` has `client_label ==
    Some("web-bridge")`, the given `conn_id`, and `out.is_some()`; the role is passed
    through (compared with `origin_label`).
16. **AC16** `[red]` (`audit_integrity.rs`) `a_hostile_label_is_bounded_in_the_ring_and_the_host`:
    a `ConnCtx` whose `client_label` is set to 10 MiB of `B` calls a command that
    reports `host.client_label()`: the reply is the 64-char string `"B" x 64`; the ring
    entry's label is the same string; across 20 such calls the labels stored in the
    ring total exactly `20 * 64` bytes. (20, not more: on the unfixed code each call
    retains a 10 MiB clone, so the red run must stay small.)

**Ring**

17. **AC17** `[red]` (`audit.rs`) `lane_for_routes_only_successful_reads_to_routine`:
    `(Some(Read), Ok)` is `Routine`; `(Some(Read), Error(..))`, `(Some(Write), Ok)`,
    `(Some(Sensitive), Ok)`, and `(None, Ok)` are `Evidence`.
18. **AC18** `[red]` `recent_merges_both_lanes_oldest_first`: with lanes (8, 8),
    `append_in` of `E1` (evidence), `R1` (routine), `E2`, `R2` gives `recent(None,
    None)` commands `[E1, R1, E2, R2]`, `recent(None, Some(3))` gives `[R1, E2, R2]`,
    `len() == 4`, `evidence_len() == 2`, `routine_len() == 2`, and
    `count_since(UNIX_EPOCH)` is `4`.
19. **AC19** `[red]` `a_routine_flood_never_evicts_evidence`: lanes (4, 2), three
    evidence entries then 100 routine entries: `evidence_len() == 3` and the three are
    unchanged; `routine_len() == 2` and they are the last two appended.
20. **AC20** `[guard]` `a_lone_source_uses_the_whole_lane_then_evicts_its_own_oldest`:
    lane capacity 5, one source: five appends hold five entries with none evicted; the
    sixth evicts the first.
21. **AC21** `[red]` `fair_share_protects_a_quiet_source_from_a_flooder`: evidence
    capacity 8, source A appends 3, source B appends 100: A still holds exactly 3 (its
    original three), B holds exactly 5 (its last five), and `recent` lists A's three
    before B's five.
22. **AC22** `[guard]` `fair_share_ties_evict_the_globally_oldest`: capacity 3, three
    different single-entry sources, then a fourth: the oldest source's entry is the
    one evicted. The existing `ring_is_bounded_and_evicts_oldest` also passes.
23. **AC23** `[red]` `a_source_flood_of_distinct_labels_cannot_flush_a_tracked_source`:
    evidence capacity 330, source A appends 200 (more than its share, so eviction of A
    is exercised); then 5000 entries each from a distinct label (same origin):
    `evidence_len() == 330` and A still holds at least
    `330 / (MAX_AUDIT_SOURCES + 3) - 1` (that is, 8) entries. On the old FIFO ring A
    holds none.
24. **AC24** `[red]` (`audit_integrity.rs`) `a_read_burst_cannot_evict_a_refused_sensitive_call`:
    a real `McpServer` over a real `AgentPlugin` and a `Sensitive` stub, policy `Auto`,
    one shared `Arc<AuditRing>`. One connection labelled `web-bridge`, origin `mcp`,
    first calls the stub (refused), then calls `agent.status` `DEFAULT_AUDIT_CAPACITY +
    64` (4160) times. Then `ring.recent(None, None)[0]` is the stub's entry with an
    `Error` result, `ring.evidence_len() == 1`, `ring.routine_len() == 2048`,
    `ring.len() == 2049`. (The same source on purpose: fair share cannot save it, only
    the lanes can.)
25. **AC25** `[guard]` (red on `bd0f9b7`; already green once Task 5 lands)
    `a_refused_flood_cannot_evict_another_sources_entry`: source A (`agent-a`, origin
    `mcp`) makes one refused stub call; source B (`agent-b`) makes `2 *
    DEFAULT_AUDIT_CAPACITY` refused stub calls. A's entry is still in the ring,
    `evidence_len() == 4096`, B holds exactly 4095 entries, `routine_len() == 0`.
26. **AC26** `[red]` `routing_follows_sensitivity_and_outcome`: on a fresh ring,
    `(evidence_len, routine_len)` after each call is: a successful `Read` stub `(0,1)`;
    a failing `Read` stub (an error-echo command) `(1,1)`; a successful `Write` stub
    `(2,1)`; a refused `Sensitive` stub `(3,1)`.
27. **AC27** `[guard]` `actions_last_minute_counts_both_lanes`: one successful `Read`
    stub and one refused `Sensitive` stub, then `agent.status`:
    `structuredContent.actions_last_minute == 2`.

**Entry bounds and redaction at the server**

28. **AC28** `[red]` `an_oversized_error_reason_is_capped_in_the_ring`: an error-echo
    command given a reason of 1 MiB of `x`: the ring entry's `Error(r)` has `r.len() <=
    DEFAULT_RESULT_REASON_CAP + 3`, starts with `xxxx`, and ends with `…`; the tool
    result still carries the full reason.
29. **AC29** `[red]` (green only after Task 2) `args_summary_hides_unframed_credentials`:
    an echo command given `note = "go sid=SECRET1 session=SECRET2 auth=SECRET3
    jwt=SECRET4 author=bob"` and `headers = {"X-Session": "SECRET5"}`: the ring entry's
    `args_summary` and the line pushed to a subscribed operator contain none of
    `SECRET1` to `SECRET5`, and the entry contains `author=bob`.
30. **AC30** `[red]` `[socket, Terminal panel]` (`web_bus_audit_label.rs`)
    `bridge_calls_are_attributed_to_web_bridge`: over a real loopback `/bus` (the PR
    145 rig), a web agent connection sends `initialize` declaring
    `clientInfo.name = "forged"`, then calls `agent.status`. An operator bridge
    connection calls `agent.status` and then `agent.activity`. The listing contains the
    agent's `agent.status` entry with `origin: "mcp"` and `client_label: "web-bridge"`,
    the operator's `agent.status` entry with `origin: "operator"` and `client_label:
    "web-bridge"`, and no entry whose `client_label` is `forged`.

**Global**

31. **AC31** `[guard]` No existing test is edited and all still pass, in particular
    `every_invoke_is_audited_including_refusals`, `agent_activity_returns_recent`,
    `audit_redacts_*`, `subscription_refusal_is_audited_but_success_is_not`, and
    `client_label_captured_from_initialize` in `mcp.rs`; PR 145's
    `crates/aitm/tests/web_bus_governance.rs` (AC5, `actions_last_minute == 2`);
    `crates/aitm-ca/tests/audit.rs`; `trust_gate_scan.rs`;
    `classifier_wildcard_free.rs`; the three `audit.rs` unit tests. `git diff --stat`
    names none of those files.
32. **AC32** `[guard]` Diff scope: only the files listed under Constraints change; the
    `pub struct ConnCtx` and `pub struct AuditEntry` bodies are byte-identical to
    `bd0f9b7`.
33. **AC33** Review-checked: the `audit.rs` module doc, the `agent.activity` and
    `agent.status` description strings and the `agent.rs` module doc describe the two
    lanes, fair share, the label rules, and that `actions_last_minute` counts both
    lanes and every surface; `redact.rs` docs describe the one vocabulary, the quote
    rule, and the host:port exemption.
34. **AC34** Mutation check (orchestrator, Task 11): replacing `append_in(lane, ..)` in
    `record_audit` with `append(..)` turns AC24 and AC26 red on an assertion; replacing
    `conn_audit_label(conn)` with `conn.client_label.clone()` turns AC16 red on an
    assertion; replacing `declared_client_label(..)` in the transport with
    `sanitize_client_label(..)` turns AC14's `web-bridge` row red. The report shows
    each red run and the restored green run.
35. **AC35** The Rust gate passes: `cargo fmt --check && cargo clippy --all-targets --
    -D warnings && cargo test`.

## Left to the builder

- The ring's internal layout (per-source deques versus one deque with counts), the
  private `SourceKey` type, and how the overflow source is represented, provided AC17
  to AC23 hold and an append stays O(sources).
- Whether the pair pass allocates a lowercase key per candidate or compares
  case-insensitively in place, provided it is linear.
- Whether `sanitize_client_label` pre-truncates before or after `scrub_text`, provided
  AC12 holds (output at most 64 chars, idempotent, work bounded by a fixed prefix).
- Whether the reason cap shares a helper with `redact_args`' truncation.
- Duplicating small test helpers (a `Sensitivity` stub command, the error-echo and
  label-echo commands, the socket helpers) per new test file rather than factoring
  them; and the exact assertion form for text, as long as the literal values above
  are asserted.
- Wording of doc comments and the PR description, provided Semantics changes by
  surface and Residual risks are stated.

## Open questions

All have a default and none blocks approval or the build.

1. **Durable audit wiring.** Should it be the next change, and with which config key
   and default? **Default:** a separate spec (named follow-up), not in this change.
2. **`actions_last_minute` meaning.** Should polling or `web-bridge` traffic be
   excluded or reported per source? **Default:** unchanged (PR 145 AC5 pins it).
3. **Vocabulary extensions** (`xsrf`, camelCase compounds). **Default:** none; promote
   the PoC builder's set exactly.
4. **Agent-stream filtering.** Should the push drop or tag routine entries?
   **Default:** unchanged; follow-up.

## Summary

This change makes the F2 audit ring a sound record without adding a field to
`ConnCtx` or `AuditEntry`: two bounded lanes (evidence and routine) with per-source
fair-share eviction and a bounded source table, so neither polling nor any single
flooding source can erase other sources' refused or state-changing entries;
bridge connections are attributed `web-bridge` through one sanitiser (control and bidi
characters stripped, scrubbed, 64 chars, reserved-name guard) applied at capture and
at consumption, which also bounds what reaches findings and the durable JSONL; the
error reason is capped; and the PoC builder's session/auth vocabulary is promoted into
`redact.rs` as the single source, with a quote-aware pair pass (required so the
scanner's pipeline does not regress) and a host:port exemption (so `auth.example.com:8443`
survives). Durable audit stays a named follow-up.

## Architect's calls (for Matt to approve or correct)

1. Two lanes with fair share in **both** lanes (the lead proposed fair share only in
   the evidence lane); routine lane 2048; a 32-source table with per-origin overflow.
2. `AuditSink::append` routes to evidence (fail closed); the lane is chosen by
   `lane_for` in `record_audit`; no field on `AuditEntry` or `ConnCtx`.
3. No trusted-control exemption; `actions_last_minute` and the push stream unchanged.
4. `web-bridge` for every bridge connection (operator too); the bridge never honours
   `clientInfo`; declared `web-bridge` becomes `web-bridge (declared)` at capture only.
5. Sanitise at capture **and** at consumption (`conn_audit_label`), including the
   `CommandHost` label that feeds findings; invisible and bidi characters stripped.
6. `entry_to_jsonl` and `aitm-findings` are not edited.
7. The error reason in the ring is capped at 1024 bytes (not in the brief; found while
   verifying the label vector).
8. Redaction: the PoC builder's vocabulary promoted exactly; `scrub_text`'s pair pass
   becomes a quote-aware linear scan that calls `is_secret_key`; `host:port`
   exemption (dotted unquoted key, `:`, 1-5 digits, terminator).
9. The PoC builder delegates; the scanner is not touched, including its now-stale doc
   comments, which the "scanner vocabulary consolidation" follow-up fixes.
10. `durable_audit` wiring is deferred to its own spec.
