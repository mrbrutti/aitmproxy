# The scanner

The scanner audits an authorized, in-scope target: it crawls it, enumerates the
**insertion points** on what it found, runs checks against them, and records
what it concludes as **issues**. It is a plugin (`aitm-plugin-scanner`), so its
verbs are reachable from every frontend — MCP, the one-shot CLI, the TUI, the
web UI and the macOS app — under the same scope, sensitivity and agent-policy
rules as every other command.

Like everything else in aitmproxy the scanner is deny-by-default and
scope-bound. Every origin in a profile is checked against the HTTP scope before
a job is admitted, every L4 target against the L4 inject scope, and every probe
goes out through the job's own client, which is scope-checked, paced, budgeted
and bounded.

## What a scan job is

`scan.start` **accepts** work; it does not do it. It validates and clamps the
profile, resolves the lanes, checks scope and the gates, mints a job id
(`scan-<8 hex>`), hands the job to a worker and returns — normally with
`state: queued`. Everything after that is read back from the job:

- **`scan.status { job }`** is the truth: state, phase, elapsed, probe, crawl,
  point, check and issue counters, the lane report, the clamps, the session
  status and the stopped reason.
- **`notifications/aitm/job`** is a **trigger, not the truth**. A subscribed
  client gets one line per `started`, `phase`, `progress`, `issue`, `finished`,
  `cancelled` or `failed` event, carrying `job`, `kind` (`"scan"`), `event`,
  `seq` (strictly increasing within the job), `ts_ms`, a `JobSummary` and, on an
  `issue` line, an `IssueSummary`. `progress` lines are coalesced to at most
  **4 per second per job**: a coalesced line is never published and never
  takes a `seq`, so the sequence a subscriber sees stays dense — a gap means
  the subscriber's own MCP dispatcher skipped a lagged line, not that the
  engine dropped one. Either way the lines are not a state machine: a UI that
  reconstructs job state from them alone will be wrong, so refresh from
  `scan.status` and `scan.issues` when a line arrives.
- **`scan.cancel { job }`** asks a job to stop. It is idempotent, it returns the
  status (`cancelling`, then `cancelled`), and the issues the job already raised
  are kept.

A job's lifecycle states are `queued`, `running`, `cancelling`, `done`,
`cancelled`, `failed`; its phases are `queued`, `crawling`, `passive`,
`auditing`, `reporting`, `done`. When a job ends early, `stopped_reason` is one
of `budget`, `time`, `cancelled`, `session_lost`, `errors`, `policy`,
`guard_refused`, `failed`.

Refusals are uniform: every `scan.*` verb fails with the string
`scan: <code>: <message>`, where `<code>` is one of nine tokens — `not_found`,
`busy`, `out_of_scope`, `refused_agent`, `refused_l4`, `lane_unavailable`,
`invalid_profile`, `unknown_check`, `confirm_required`. Match on the code, never
on the prose. Clamping and cancellation are not errors and have no code, and
`confirm_required` is reserved for a frontend: the engine itself answers a
missing confirmation through the bus `_confirm` handshake below.

### What runs today

The **WebSocket lane is wired**: `aitm-scan-ws` contributes a real `ws` lane
with eight checks, each also reachable by hand as its own `check.<id>` verb
(`check.cswsh` and seven `check.ws-*`). The HTTP lane crate
(`aitm-scan-http`) and the native check slot (`aitm-scan-checks-http`) are
still empty, so the engine falls back to the **interim HTTP lane** built
into the scanner plugin; `aitm-scan-l4-packet` and `aitm-scan-l4-stream` are
still skeletons that contribute no lane. A profile that asks for a lane this
build does not have is not refused: the lane is reported in `lanes.skipped`
with the reason "lane not available on this build" and the job runs the lanes
it has. Only when **every** requested lane is missing is the call
`lane_unavailable`.

The interim HTTP lane carries five checks — two active (`xss-reflected`,
`open-redirect`) and three passive (`reflection`, `security-header`,
`cookie-flag`) — and derives query and body points from captured requests.
Those are check **ids**; the issue **classes** they emit are `reflected-xss`
and `open-redirect`.

Its crawl has three modes, and the lane picks one per origin:

- **Browser crawl** when the core has an embedded browser bound and
  `crawl.use_browser` is not `never`. It runs the page's script, so it is the
  only mode that reaches a route only JavaScript builds.
- **Client crawl** when there is no browser, or `crawl.use_browser: never`.
  The lane fetches pages itself: breadth-first `GET`s of the links it
  extracts, plus one navigation per `<form>` when `crawl.submit_forms` is set
  (a GET form becomes a query, a POST form a body). Every fetch goes through
  the job's own client, so it is paced, scoped and charged to the one job
  budget like a probe. This is a fallback, not "nothing is fetched". Every
  request that fails is counted in `crawl.errors`, and a crawl that made
  requests and fetched no page at all names why on `crawl.last_error`.
- **No crawl at all** when `crawl.max_pages: 0`. That one setting turns every
  crawl off; the lane maps and audits only what the proxy has already
  captured for the origin.

(`scan.map` uses the same crawl, `submit_forms` included: spec D8.1 makes form filling with inert generated values a crawl step, so a map job reaches the same routes a scan does and sends no probe)

## The verbs

| Verb | Tier | Parameters | Result | Refusal codes |
|---|---|---|---|---|
| `scan.start` | Sensitive | `profile?`, `profile_name?`, `target?`, `overrides?` | `StartResult`: `job`, `status`, `clamped`, `lanes`, `dry_run?` | `invalid_profile`, `not_found`, `unknown_check`, `lane_unavailable`, `out_of_scope`, `refused_l4`, `refused_agent`, `busy` |
| `scan.map` | Write | the same four | `StartResult` | the same, minus `refused_l4` |
| `scan.status` | Read | `job` | `JobStatus` | `not_found` |
| `scan.list` | Read | `active_only?` (false), `limit?` (`scanner.history`) | `{ jobs: [JobSummary] }` | — |
| `scan.cancel` | Write | `job` | `JobStatus` | `not_found` |
| `scan.issues` | Read | `job?`, `target?`, `severity_min?`, `confidence_min?`, `class?`, `lane?`, `status?`, `since?`, `limit?` (100, max 1024), `cursor?` | `{ issues, next_cursor, by_severity }` | `invalid_profile`, `not_found` |
| `scan.issue` | Read | `id` | `Issue` | `not_found` |
| `scan.issue.update` | Write | `id`, `status`, `note?` | `Issue` | `not_found`, `invalid_profile` |
| `scan.sitemap` | Read | `job?`, `target?` (neither ⇒ the newest job of all), `cursor?`, `limit?` (1024, max 4096) | `{ nodes, points, next_cursor }` | `invalid_profile`, `not_found` |
| `scan.checks` | Read | `lane?`, `class?`, `origin?` | `{ checks: [CheckMeta], lanes: [{ lane, source: crate \| interim }] }` | `invalid_profile` |
| `scan.profile.list` | Read | — | `{ profiles: [{ name, builtin, summary }] }` | — |
| `scan.profile.get` | Read | `name` | `ScanProfile` | `not_found`, `invalid_profile` |
| `scan.profile.save` | Write | `profile` | `{ saved, path }` | `invalid_profile` |
| `scan.profile.delete` | Write | `name` | `{ deleted }` | `invalid_profile` |
| `scan.session.preview` | Read | `target` | `SessionProfile` (names only) | `invalid_profile` |
| `check.<id>` | Sensitive | `url`, `param`, `value?` (`1`) | `Verdict` | `invalid_profile`, `out_of_scope` |
| `scan.discover` *(deprecated)* | Write | `target`, `max_depth?`, `max_pages?` | the Stage-1 discovery shape | the `scan.map` set, `busy` rephrased |
| `scan.passive` | Read | `target?` | `{ findings: [...] }` | — |
| `scan.report` | Read | `target?` | `{ report_md, index, issues_md }` | — |

Exactly one of `profile` (a complete profile inline), `profile_name` (a
built-in, configured or saved profile) and `target` (one origin, scanned with
`scanner.default_profile`) selects what a start-shaped verb runs; `overrides` is
a partial profile merged over it key by key, and a mistyped override key is an
`invalid_profile` naming the key rather than a line that silently does nothing.

`scan.map` is `scan.start` with `lanes: [http]` and `intensity: passive` forced:
it crawls, runs the passive checks and enumerates insertion points, and sends no
probe. Its crawl honours the profile's `crawl.submit_forms` (default on): form
filling with inert generated values is part of the crawl, not a probe
(coordinator decision, 2026-11-01). Plainly: the map crawl **submits same-origin
forms** with inert values and the observed session, **skips** logout-looking and
destructive-looking forms — an action path or field name containing `delete`,
`remove`, `destroy`, `password`, `transfer`, `pay`, `purchase`, `unsubscribe` or
`confirm`, matched as whole words — and counts every form it skipped in
`JobStatus.crawl.forms_skipped`; `crawl.submit_forms: false` turns form
submission off altogether. Read its result with `scan.sitemap` and
`scan.issues`.

`scan.discover` is **deprecated**. It is now a `scan.map` job plus a bounded
wait, kept so an older UI keeps working; the wait is bounded by the configured
scan time budget, after which the job is cancelled and the result reports
`stopped_reason = "time_budget"`. Use `scan.map` and poll `scan.status`.

## Profiles

A profile is the one knob an operator turns. It is operator-authored YAML:
every field has a default, so a profile names only what it changes, and an
unknown key is an error rather than a silently ignored line.

### The built-ins

Seven profiles ship with aitmproxy. Their names are reserved —
`scan.profile.save` and `scan.profile.delete` refuse them.

| Name | What it changes from the defaults |
|---|---|
| `passive-only` | `intensity: passive`, `crawl.max_pages: 0`, `crawl.use_browser: never` — passive checks over already-captured in-scope flows, no crawl, no probe |
| `map-only` | `intensity: passive` — crawl and passive checks, no probe |
| `light-http` | `intensity: light`, `speed: fast` |
| `standard` | `lanes: [http, ws]` (the default `scanner.default_profile`) |
| `thorough` | `lanes: [http, ws]`, `speed: thorough`, `accuracy: fewer_false_negatives`, `crawl.strategy: thorough` |
| `l4-stream-safe` | `lanes: [l4_stream]`, `l4.cases: 200` |
| `l4-full` | `lanes: [l4_packet, l4_stream]`, `l4.cases: 500` |

Every built-in carries an empty `target`: `scan.start` fills it from the
caller's origin or L4 endpoint.

### The YAML

Below is the whole tree with every default. A profile needs a `name`, at least
one lane, and at least one origin or L4 target; `budget.probes`, `budget.time_s`
and `budget.check_timeout_s` must each be at least 1; an `audit.ignore` rule
that sets no key is refused, because it would ignore every point.

```yaml
name: my-api                  # required, non-empty
target:                       # at least one origin or one l4 entry
  origins: []                 # "http(s)://host[:port]", checked against the HTTP scope
  l4: []                      # - { ip: "10.0.0.5", port: 9000, proto: tcp, grammar: null }
lanes: [http]                 # http | ws | l4_packet | l4_stream
intensity: medium             # passive | light | medium | intrusive
speed: normal                 # fast | normal | thorough
accuracy: normal              # fewer_false_negatives | normal | fewer_false_positives
checks:
  include: []                 # empty = every check the intensity and lanes allow
  exclude: []                 # applied after include
crawl:
  strategy: normal            # fast | normal | thorough
  max_depth: 3
  max_pages: 200              # 0 disables crawling
  submit_forms: true
  click_handlers: true
  robots: true
  sitemap: true
  use_browser: auto           # auto | always | never
audit:
  kinds:                      # the default is every insertion kind, in this order
    [query, body_param, json_value, xml_value, xml_attr, multipart_value,
     multipart_filename, header, cookie, path_segment, path_filename,
     param_name_query, param_name_body, entire_body, ws_json_value, ws_text,
     ws_form_param, ws_binary, ws_handshake_header, l4_field]
  ignore:
    - trait: session          # the default rule; write `ignore: []` to audit session points
  max_points_per_request: 64
  frequent_point_threshold: 8
session:
  mode: observed              # observed | none
  from_flow: null             # a captured flow id to lift the session from
  on_lost: stop               # stop | continue
budget:
  probes: 2000
  time_s: 600
  max_issues: 1024
  check_timeout_s: 60
  per_host_errors:
    consecutive: 10           # consecutive transport errors or timeouts from
                              # one host trip the breaker; a 5xx is an answer
    ratio: 0.5                # or this error-to-probe ratio
http:
  version: auto               # auto | h1 | h2 | h2c
  record_probes: issues_only  # issues_only | all
ws:
  reply_window_ms: 1500
  max_frame_bytes: 1048576
l4:
  cases: 500
  reproduce_count: 3
  liveness_every: 25
  consecutive_timeouts: 20
  max_bytes_per_s: 65536
  seeds: []                   # - { hex: "0001" } | { base64: "AAE=" } | { flow: <flow id> }
  fields: []                  # empty = the lane's own default table
  dry_run: false              # build and report every case, send nothing
```

A `checks.include`/`exclude` entry is a check id, a check class, or
`lane:<lane>`. An entry that names nothing the catalogue holds is refused with
`unknown_check`, quoting the entry.

`budget.per_host_errors` counts only probes that got **no answer**: connect and
transport errors, a guard refusal other than a rate limit, and a per-probe
timeout. A 5xx is an answer — it is handed to the check and it resets the host's
consecutive run — so a target that errors on every payload never trips the
breaker (amendment 40). A host that does trip is dropped for the rest of the
job, and a job that stops because the next item's host is tripped reports
`stopped_reason: errors`, as before.

### Where profiles come from

`scan.profile.get` and `scan.start { profile_name }` look in three places, in
this order: a profile saved under `<findings.dir>/scan/profiles/<name>.yaml`,
then the `scanner.profiles:` config section, then the built-ins. A saved profile
shadows a configured one, which shadows a built-in. `scan.profile.list` returns
all of them with `builtin: true|false`.

`scan.profile.save` writes human-readable YAML to
`<findings.dir>/scan/profiles/<name>.yaml`. The name must not be a built-in's,
must be lowercase letters, digits, `.`, `_` or `-`, must start with a letter or
digit, and the profile must validate; with no findings directory configured
there is nowhere to save and the call is refused with `invalid_profile`.

### Clamping

A profile is the operator's dial; a **ceiling** is the administrator's wall. A
profile figure above its ceiling is **clamped, not refused**: the job runs,
bounded, and every cut is reported in `scan.start`'s `clamped` list as
`{ field, requested, applied }` and kept on `JobStatus.clamped`. The clamped
fields are `budget.probes`, `budget.time_s`, `budget.max_issues`,
`budget.check_timeout_s`, `l4.cases`, `l4.max_bytes_per_s` and
`ws.max_frame_bytes`. `budget.check_timeout_s` is clamped by the lower of
`scanner.check_timeout_s` and `scanner.ceilings.time_s`: one check may never
outlast the whole job.

## The `scanner:` config section

The scanner's own section of `config.yaml`. An absent section, `scanner: {}`
and `scanner: ~` all mean the defaults below; a misspelled key is an error
naming the key.

| Key | Default | What it does |
|---|---|---|
| `allow_agent_active` | `false` | Let an agent (MCP) frontend start an active scan. |
| `allow_agent_l4_fuzz` | `false` | Let an agent start a job whose profile runs an L4 fuzz lane. Independent of `allow_agent_active`. |
| `max_jobs` | `2` | How many scan jobs may run at once; a further `scan.start` is `busy`. |
| `history` | `50` | How many finished jobs the registry keeps, and `scan.list`'s default `limit`. |
| `check_timeout_s` | `60` | Per-check wall-clock ceiling, in seconds. |
| `default_profile` | `"standard"` | The profile `scan.start { target }` resolves. |
| `profiles` | `{}` | Profiles declared in the config file, by name. |
| `ceilings.probes` | `20000` | Maximum stimuli (probes, crawl requests, L4 cases) one job may send. |
| `ceilings.time_s` | `7200` | Wall-clock ceiling for one job, in seconds. |
| `ceilings.l4_cases` | `5000` | Maximum L4 fuzz cases one job may send. |
| `ceilings.l4_bytes_per_s` | `1048576` | Maximum L4 send rate, in bytes per second. |
| `ceilings.l4_icmp_pace_ms_min` | `1000` | Floor for a profile's `l4.icmp_pace_ms`: a lower value is raised to it and reported in `clamped` (amendment 46). |
| `ceilings.ws_frame_bytes` | `4194304` | Maximum WebSocket frame payload one job may send, in bytes. |
| `ceilings.max_issues` | `4096` | Maximum issues one job may record. |

Every ceiling key is independent: raising one leaves the other six alone.
`l4_icmp_pace_ms_min` is the one floor among them: a profile `l4.icmp_pace_ms`
below it is clamped **up** to the floor, and the raise appears in `scan.start`'s
`clamped` list like any other clamp.

**Legacy `scan.discover` budgets.** `ScannerConfig` carries five more fields,
left over from the Stage 1 crawl that the legacy `scan.discover` /
`scan.passive` / `scan.report` verbs still run. A v2 job is bounded by its
profile and by the ceilings above and never reads them.

| Field | Default | What it does |
|---|---|---|
| `max_depth` | `3` | Link depth the legacy crawl follows from each seed. |
| `max_pages` | `200` | Distinct pages the legacy crawl visits. |
| `request_budget` | `2000` | Requests the whole legacy run may issue. |
| `time_budget` | `600s` | Wall-clock ceiling for a legacy run. |
| `per_class_payload_cap` | `25` | Payloads tried per class per insertion point. |

These five are **not** `config.yaml` keys: the `scanner:` section refuses them
like any other unknown key, and they keep the defaults above. They are listed
here so the table above can be read as the complete set of keys the file
accepts.

```yaml
scanner:
  allow_agent_active: false
  max_jobs: 2
  default_profile: standard
  ceilings:
    probes: 20000
    time_s: 7200
  profiles:
    my-api:
      name: my-api
      lanes: [http]
      target:
        origins: ["https://app.example"]
```

Two values the scanner uses are **not** keys of this section: the state
directory is `findings.dir`, copied in by the binary, and the agent L4 injection
gate is `l4.allow_agent_inject`, read from the `l4:` section.

## Gates: operator versus agent

`scan.start` is **`Sensitive`** whatever its profile does. The job's gate is
taken once, at start, and the catalogue then runs every check — script checks
included — without a per-call policy decision, so a profile that would only read
is still started by a `Sensitive` verb. `check.<id>` is `Sensitive` for the same
reason. `scan.map` and `scan.cancel` are `Write`; the read verbs are `Read`.

An **operator** (the CLI, or an operator-token bus connection) may start any
profile. An **agent** (an MCP connection) is gated:

- Under `agent.policy: auto` an agent cannot start a scan at all — the refusal
  is `refused_agent`, "the agent policy is `auto`; an operator can
  switch to `all` with agent.set". A **`scan.map` job is exempt**
  from everything below it, but not from the policy itself.
- An active scan needs `scanner.allow_agent_active: true`, else
  `refused_agent`, "an agent needs `scanner.allow_agent_active` to
  start an active scan".
- **`intensity: intrusive` is operator-only**: `refused_agent`,
  "`intensity: intrusive` is operator-only".
- An L4 lane needs `scanner.allow_agent_l4_fuzz: true` **and**
  `l4.allow_agent_inject: true` — both, because packet and stream fuzzing is
  the most invasive thing the scanner does.

An L4 lane also needs the L4 layer itself: with `l4.enabled: false` (the
default) any L4 profile is `scan: refused_l4: the l4 layer is disabled`,
whoever asks. Beyond that, **the stream lane needs an L4 scope entry with
`interface: "*"`, `direction: outbound`, the target CIDR and port range, and the
`Inject` capability**; every `target.l4` entry is checked against it before the
job is admitted, and one that does not match is
`scan: out_of_scope: <ip>:<port> is not in the l4 inject scope: ...`.

```yaml
l4:
  enabled: true
  allow_agent_inject: false     # leave false unless an agent must fuzz
  scope:
    - cidr: { addr: 10.0.0.5, prefix: 32 }
      ports: { lo: 9000, hi: 9000 }
      interface: "*"
      direction: outbound
      capability: inject
```

Finally, a job that runs an L4 lane or `intensity: intrusive` asks a human
frontend to confirm first: *"This scan sends malformed traffic to &lt;targets&gt;
and may disrupt the target. Continue?"* An operator connection answers it with
the bus `_confirm` handshake; an agent is never offered the handshake and stays
governed by the config gates above.

Two more confinements are always on, whoever starts the job: the target origins
are checked against the HTTP scope before anything is sent, and only one scan
runs against a given origin at a time (a second is `busy`).

## What a scan records

`http.record_probes` decides what reaches the flow store:

- **`issues_only`** (the default) — probes are sent with `record: Never`, so a
  scan cannot evict an operator's real captures. A lane's crawl captures are
  still recorded, and when a check concludes `vulnerable` the engine re-records
  the probe flows it held in memory for that issue.
- **`all`** — every probe is recorded.

Recorded scan flows carry marks, so they can be filtered back out of the capture
list: `scan:<job>` on every flow the job produced, `crawl` on a lane's crawl
captures, and `issue:<id>` on the flows re-recorded as an issue's evidence.

Three reading notes from the 2026-11-01 live runs: `elapsed_ms` is live while
the job runs (wall time since `started_at`, fixed at the terminal transition);
`crawl.errors` counts both a crawl of an origin that failed outright (a browser
crawl that timed out or was refused, after which the client crawl stands in) and
every single client-crawl request that failed, so a job that ran on fewer points
than it could have says so, and when a crawl made requests and fetched no page
at all `crawl.last_error` carries one of `h2_not_negotiated`, `connect_refused`,
`tls`, `timeout`, `transport` or `other` (amendment 39; a partial failure leaves
it unset). That is a reading, not a verdict: the job still runs its passive
checks over what it captured and ends `done`, with `stopped_reason` and `error`
untouched. `poc_ref` on an issue is
present only when `findings.dir` is set, because the reproduction's
`FindingRecord` is what it points at (no findings dir, no record, no `poc_ref`).

## Issues

An issue is one weakness at one place. It carries a **class** (`sqli`,
`reflected-xss`, ...), a **severity** (`info`, `low`, `medium`, `high`,
`critical`) and a **confidence** (`tentative`, `firm`, `certain`, never above
the check's declared `confidence_max`), the evidence that produced it (payload,
a bounded scrubbed excerpt of what matched, timing correlation, response diff,
the probe flows and the baseline flow), and its triage **status**: `open`,
`confirmed` or `false_positive`, set with `scan.issue.update` and persisted.

An issue belongs to **every job that found it**: spec D6 dedupes across jobs,
so a later job that re-finds a known weakness merges into the existing record
(`occurrences` grows, `last_seen` moves, evidence is replaced only on higher
confidence); `job` names the first finder and `jobs` lists every job that found
or re-found it, and `scan.issues { job }` and a job's `issues` tally include the
issue for each of them (amendment 27c). An `issue` push line means found **or**
re-found. `scan.sitemap` names the job its map came from in `job`, also when it
fell back to the newest job (27b).

**Dedupe.** One weakness at one place is one issue however many checks report
it: the dedupe key is a blake3 digest of the **class plus the location**, and
the check id is deliberately not part of it, so a second check finding the same
thing raises the occurrence count of the existing issue and keeps the
higher-confidence evidence. The location is the origin, method, path template,
insertion kind, parameter name and field path for an HTTP or WebSocket issue;
just the origin for a passive issue (which lists the paths it saw in
`evidence.matched` instead of splitting into one issue per path); and the
target, transport, grammar field and mutation class for an L4 issue.

**On disk.** With `findings.dir` configured the scanner writes
`<findings.dir>/scan/jobs/<job>.json` (reloaded into `scan.list` at startup),
`<findings.dir>/scan/issues/<id>.json` with a `key -> id` `index.json` beside
them, `<findings.dir>/scan/profiles/<name>.yaml`, and reproduction PoCs under
`<findings.dir>/scan/pocs/`. With no findings directory everything is in memory
only and nothing is written.

### Issue classes

The class vocabulary is pinned. A UI may key off these tokens:

| Class | Lane |
|---|---|
| `reflected-xss`, `stored-xss` | http |
| `sqli`, `nosqli`, `ldapi`, `ssti`, `cmdi` | http |
| `path-traversal`, `crlf`, `xxe`, `ssrf`, `open-redirect` | http |
| `cors`, `missing-security-headers`, `risky-http-methods` | http |
| `exposed-path` (one issue per path) | http |
| `information-disclosure` (generic leaks only) | http |
| `h2-settings-observe`, `h2-pseudo-header-validation`, `h2-header-crlf-tolerance`, `h2-cl-te-downgrade-indicator`, `h2-rapid-reset-mitigation` | http |
| `cswsh`, `ws-auth-bypass`, `ws-input-reflection`, `ws-oversize-frame`, `ws-subprotocol` | ws |
| `l4-protocol-reaction`, `l4-parser-fault`, `l4-crash` | l4_stream, l4_packet |

The h2 tokens are one per observe-only check, spelled exactly as the check id.
Injection carried over a WebSocket frame reports the **family** token, not a
`ws-` one: an SQL injection reachable over HTTP and over WS is one `sqli`
family, so the shipped WS lane's injection checks report `sqli`, `ssti` and
`cmdi` (`crates/aitm-scan-ws/src/checks/`).

The **technique** a check used (`reflected`, `error`, `boolean`, `timing`,
`handshake`, `malformed`, `observe`, `passive`) is never part of the class, and
the dedupe key hashes class + location — so a timing-based and an error-based
SQL injection at one parameter are one `sqli` issue, while `exposed-path` at
`/.git/` and at `/.env` are two.

Today the only HTTP-lane classes a run actually produces are the interim
lane's: `reflected-xss` and `open-redirect` from its two active checks, plus
`reflection`, `security-header` and `cookie-flag` from its passive ones. The
first two keep their spec tokens when T2's lane crate replaces the interim
lane; the last three are **interim, removed with T2's integration** — do not
pin them in a UI. Every other HTTP token above arrives with T3.

## Writing a check in Rhai

A script registers a check from its `load(reg)` hook. The check then sits in the
same catalogue as a compiled-in one: `scan.checks` lists it, a profile selects
it by id, class or lane, the scheduler runs it inside jobs, and it gets its own
manual `check.<id>` command.

```rhai
fn load(reg) {
    reg.add_check(#{
        id: "demo.sleep-sqli",
        name: "Time-based SQL injection",
        class: "sqli",
        lanes: ["http"],
        kinds: ["query", "body_param"],
        intensity: "medium",
        cost: "medium",
        technique: "timing",
        severity: "high",
        confidence_max: "firm",
        description: "Asks the database to wait and checks whether it did.",
        remediation: "Use parameterised queries.",
        cwe: 89,
    }, |point| {
        let requested = [1, 3];
        let observed = [];
        for seconds in requested {
            if probe.budget_left() < 1 { return "out of budget"; }
            let r = probe.send("1' AND SLEEP(" + seconds + ")-- ");
            observed.push(r.elapsed_ms);
        }
        let fit = probe.timing_fit(#{ requested_s: requested, observed_ms: observed });
        if !fit.correlated { return #{ outcome: "clean", confidence: "firm" }; }
        #{
            outcome: "vulnerable",
            confidence: "firm",
            detail: "Response time tracks the requested delay (slope " + fit.slope + ").",
            evidence: #{ payload: "1' AND SLEEP(3)-- ", matched: "delay honoured" },
            poc_hint: #{ matchers: [#{ type: "status", status: 200 }] },
        }
    });
}
```

**The meta map.** Its keys are exactly `CheckMeta`'s wire names. Required:
`id`, `name`, `class`, `lanes`, `kinds`, `intensity`, `cost`, `technique`,
`severity`, `confidence_max`, `description`. Optional: `remediation`, `cwe`,
`needs_baseline` (false), `wants_traits` (null — when set, the check is
scheduled only on points carrying one of those traits, and the restriction is
ignored at `speed: thorough`), `targets_session` (false), `scope` (`point`, or
`node` to run once per site-map node, or `origin` to run once per origin). An
origin-scoped HTTP check runs once per origin whether or not any insertion point
was discovered there (amendment 38): the origins are the profile's targets plus
every origin a surviving point belongs to, each scheduled as a synthesized
`GET <origin>/` item that the interim HTTP lane serves with a probe host over
that request. An origin is not a point, so no point gate applies to it —
`audit.kinds`, `wants_traits`, the frequent-point rule and the session rule are
not consulted and only the check's `intensity` can leave it out. A
script may **not** declare `origin`: aitm records where the script came from
(`native`, `bundled` or `custom`). A missing or mistyped meta key is a **load
error naming the key**, not a default — the catalogue cannot schedule what it
cannot classify. An id a script already registered is a load error naming the
source that holds it; an id that clashes across sources (lane checks, then the
native checks, then bundled scripts, then custom scripts) is resolved in favour
of the **first** claim, and the clash is logged and reported by
`scan.checks`' catalogue at load.

**The point map.** The closure receives `#{ kind, name, path, url, method,
example, traits }`. `path`, `url`, `method` and `example` are `()` when the lane
has none; `traits` is an array of trait tokens (`url`, `filename`, `number`,
`email`, `base64`, `json`, `id`, `session`).

**The verdict.** Return one of three things:

- a **map** with `outcome` (required: `vulnerable`, `clean`, `inconclusive` or
  `error`), `confidence` (default `tentative`), `detail`, `evidence`
  (`#{ payload, matched }`; `matched` is bounded to 256 bytes by the model),
  `poc_hint` and `location`;
- a **plain string**, read as `inconclusive` with that string as the detail;
- an **array of verdict maps**: the first is the root verdict and the rest are
  its siblings, each becoming its own issue. A verdict's optional
  `location: #{ path, name }` overrides the issue location, which is how an
  origin-scoped check reports one `exposed-path` issue per path. Siblings nest
  one level only.

An unknown key in a verdict map, or a closure that throws, produces an `error`
verdict naming the problem: a check never fails the job.

`poc_hint` is `#{ matchers: [...], control: #{ payload, matchers: [...] } }`.
`matchers` is a list in the PoC-YAML vocabulary (`type: status | word | regex |
dsl`, plus `all`/`any`/`not`); a list is an implicit `all`. The optional
`control` is a benign payload whose response must *not* look vulnerable. When a
`vulnerable` verdict of confidence `firm` or better carries a hint, the engine
reproduces the issue, runs the control, and links the resulting PoC and finding
to the issue.

**The `probe.*` functions.** They belong inside a check closure; the five that
reach the job's host refuse anywhere else with *"probe.&lt;name&gt; is only
available inside a check closure (reg.add_check); use http.send in a command"*.
Every probe is spent from the job's budget, paced, scope-checked, marked and
recorded under the job's record policy, and each is bounded by the smaller of
the remaining check time and 30 seconds.

| Function | Rule |
|---|---|
| `probe.send(payload)` | Place a payload at the point. A string replaces the observed value; `#{ value, mode }` with `mode` of `replace` (default), `prefix` or `suffix` chooses how it combines. Returns `#{ status, headers, body, elapsed_ms, flow_id }`. |
| `probe.baseline()` | The point's unpayloaded response, cached per point, to diff against. |
| `probe.raw(#{ method, url, headers, body })` | A request the check builds itself, for a handshake or header case a payload-at-a-point cannot express. Same origin, same budget. `method` must be an HTTP token (letters, digits and ``!#$%&'*+-.^_`\|~``, at most 32 bytes); default `GET`. |
| `probe.marker()` | The job's collision-resistant marker token, for a reflection canary or callback label. |
| `probe.budget_left()` | Probes still affordable for this point; zero means send nothing more. |
| `probe.timing_fit(#{ requested_s, observed_ms })` | Fit observed times against the delays asked for; returns `#{ correlated, slope, r }`. The two arrays must be the same length. |
| `probe.levenshtein_ratio(a, b)` | How alike two strings are, `1.0` identical and `0.0` nothing in common, for boolean-blind comparisons. Each input is truncated to 32 KiB. |

Response **header names are lower-case** — index `r.headers["content-type"]`,
not `r.headers["Content-Type"]` — `body` is lossy UTF-8, and `status` and
`flow_id` are `()` when the lane had none (an L4 probe has no status; an
unrecorded probe has no flow). There is **no `sleep`**: measure with
`elapsed_ms` and conclude with `probe.timing_fit`. A closure's own `http.send`
runs through the job's client too, so it is budgeted and marked exactly like a
probe.

## Session reuse

Rather than ask for credentials, a job with `session.mode: observed` (the
default) lifts a session from traffic the proxy already captured: the newest
in-scope **captured** (never replayed) flow to the origin that carries a
`Cookie` header or a secret-named header. `session.from_flow` names a specific
flow instead.

The **values** live in the worker's memory and nowhere else. No verb, push line,
issue, PoC or log carries a session value — `scan.session.preview { target }`
returns the cookie and header **names** only, the flow they came from, and the
canary that would be used, and an origin with nothing observed comes back empty
with `canary: none`, which is also how "auth-lost detection is off" reads.

While the job runs, a body-less `GET`/`HEAD` canary — the chosen flow itself if
it is one, else the newest `GET`/`HEAD` flow carrying the same material — is
replayed **every 25 probes**. A `2xx` that turns into a redirect, a `401` or a
`403` means the session is gone. Under `session.on_lost: stop` (the default) the
job ends with `stopped_reason: session_lost`; under `continue` it keeps going
unauthenticated.

Two consequences for anyone seeding a session for a scan: points whose **name**
looks like session material (cookies such as `sid`, headers such as
`Authorization`, token-like parameters) carry the `session` trait and the
default `audit.ignore` rule skips them (`points.skipped.ignored`); the canary
request's own point is **not** excluded from the audit. Seed the session with
the cookie alone, on `/`, and send the pages you want audited without session
headers; a fabricated `Authorization` header is re-sent on every probe and a
target that refuses it answers nothing worth reflecting.

## Running one check by hand

Every catalogue entry gets a uniform `check.<id>` command —
`check.xss-reflected`, `check.open-redirect`, `check.demo.sleep-sqli` — so a
check can be run against one **query parameter** by hand, without starting a
job:

```text
check.xss-reflected { url: "https://app.example/search?q=1", param: "q" }
```

It is **not** a way around the job model. The command builds a one-shot job over
the same client: the URL's origin must be in the HTTP scope (else
`scan: out_of_scope:`), probes are budgeted to **64**, the run is bounded by
`scanner.check_timeout_s`, and the record policy applies as usual. The request
is synthesized in memory in a private store and never enters the operator's
capture list. `param` must be a query parameter of `url` — the command sets it,
replacing any value the URL already had — and `value` is its benign baseline
value, `1` by default. The result is the check's `Verdict`. If a script has
already registered a command of that name, the scanner leaves it alone and logs
that it did.
