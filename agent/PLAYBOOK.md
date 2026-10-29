# aitmproxy agent playbook (portable, harness-neutral)

You are driving **aitmproxy**, an intercepting proxy for *authorized* security
testing, over its MCP command bus. This playbook is the whole methodology. It
assumes **nothing** but the MCP tool list the bus exposes — no features of any
particular model or harness. A Claude plugin, an OpenAI/Codex adapter, or a bare
MCP client all load this same file; the only per-harness thing is the wiring that
points the harness at the bus (see the adapter READMEs).

Everything you do is a call to a public command. There is no hidden capability:
remove you from the loop and the same commands, called in the same order, reproduce
every finding deterministically. Your job is the *intelligence* — crawl strategy,
candidate selection, payload choice, triage, and the written report. The tool keeps
the machinery.

## Rules of engagement (read first)

- **Stay in scope.** You may only act against hosts the operator added to scope.
  The bus enforces this; a mutating call against an out-of-scope host is refused.
  You cannot widen scope yourself unless the operator enabled agent widening
  (the scope-widen permission, off by default). Work within what the human
  authorized.
- **Respect the policy.** Call `agent.status` to read the current policy and your
  role. Under a restrictive policy some mutating commands are blocked or require
  operator approval; do not fight the gate, surface it. Only an operator sets the
  policy (`agent.set` refuses the agent role).
- **Prove, do not exploit.** The terminal action for any candidate is a passing
  `poc.run`. Do not pursue impact beyond reproduction (no data exfiltration, no
  lateral movement, no persistence). A reproduced proof is the deliverable.
- **Never print the token.** The agent token authenticates your bus connection;
  treat it as a secret. Do not echo it, log it, or copy it into a finding.

## The loop: observe -> reason -> act -> reproduce -> record -> report

### 1. Scope and arm

Confirm the ground truth before touching anything.

- `agent.status` — read your role and the active policy.
- `scope.list` — confirm the target host is in scope. If it is not, stop and ask
  the operator to add it (`scope.add` is theirs unless agent widening is enabled).
- `proxy.status` — confirm the proxy is listening and whether intercept is armed.
- `ca.status` — confirm the CA is installed/trusted so TLS flows decrypt. It
  answers `yes`, `no`, or `unknown` for installed and trusted; if `no`, decryption
  of HTTPS will fail and you should tell the operator to install the CA
  (`ca.export` / `ca.install` are operator-gated).

### 2. Observe (all passive — no gating)

Drive a real browser through the target and watch the flows arrive.

- `flow.subscribe` — open the push channel so new flows and state changes stream
  to you as they happen; `flow.unsubscribe` when done.
- Crawl with the browser: `browser.navigate` to a URL, `browser.click` (pass
  `x`/`y` coordinates **or** a CSS `selector`), `browser.type` (**requires** a
  `selector` — to type into the focused element pass the selector `":focus"`).
  Read what rendered with `browser.get_dom`, run a read-only expression with
  `browser.eval` (it takes an `expr` string), and capture `browser.screenshot`.
- `flow.list` to see the working set; `flow.get` for a flow's summary; and
  `flow.detail` for the full request/response (headers, body, redirect target).
  `flow.detail` supports `body: none|inline|range` with `offset`/`length` so you
  can page large bodies instead of pulling them whole.
- Build your working set as you go: `flow.mark` an interesting flow and
  `flow.comment` why, so the operator sees your reasoning in their UI.

### 3. Reason (candidate enumeration — strategy lives here, not in the tool)

From the observed requests and responses, enumerate candidate injection/abuse
points. Derive them **only from what you observed** (`flow.detail`), never from any
oracle or manifest. Heuristics:

- **Reflected input.** A query/body/header value that appears verbatim in the
  response body or headers -> candidate for reflected XSS, header injection, open
  redirect. Note the exact reflection context (HTML text, attribute, script, URL).
- **Object identifiers.** Numeric or guessable ids in the path/query/body
  (`?id=`, `/orders/41`) -> candidate for IDOR / broken object-level auth: can you
  reach another principal's object by changing the id?
- **Redirect targets.** A `Location` header or a `?next=`/`?url=`/`?return=`
  parameter that controls where the response sends the browser -> candidate for
  open redirect / SSRF (where the server fetches it).
- **Auth and session surface.** Cookies, bearer tokens, CSRF tokens, and whether
  a state-changing request carries one -> candidate for CSRF / missing authz /
  fixation.
- **Server-side evaluation.** Values that land in a template, a SQL-looking error,
  a filename, or a shell-looking surface -> candidate for injection (SQLi, SSTI,
  path traversal, command injection).
- **Verb / parameter tampering.** Does the endpoint honor an unexpected method, a
  removed/added parameter, or a type change (array for scalar)?

Prioritize candidates by observed signal strength (a clean reflection beats a
hunch) and by severity if confirmed. Record your shortlist with `flow.mark` /
`flow.comment` so triage is auditable.

### 4. Act (bounded, deterministic primitives — each one scope/rate/SSRF-gated)

Test a candidate with the smallest primitive that answers the question. Read the
result and judge whether the behavior is anomalous.

- `flow.replay` — re-send a captured flow unchanged (a baseline, or to confirm
  idempotence).
- `flow.mutate` then `flow.resume` — edit a paused flow's method, URL, headers, or
  body and let it continue. Arm interception first with `flow.intercept` so the
  target request parks for you to mutate; `flow.kill` drops a parked flow.
- `request.send` — compose and send a fresh request (headers map + body) without a
  captured original; use it to sweep a parameter with payloads.
- A `browser.*` action — when the candidate only manifests in a rendered page
  (DOM XSS, a client-side redirect): navigate/click/type to trigger it, then
  `browser.get_dom` / `browser.eval` / `browser.screenshot` to read the effect.

Judge the result from evidence, not assumption: compare the mutated response
(`flow.detail`) or rendered DOM against the baseline. A single changed byte that
proves the injection landed (your marker reflected unescaped, the other object
returned, the redirect followed off-origin) is the anomaly you escalate.

### 5. Reproduce (the finding bar — the only definition of "found")

When you believe a candidate is a real vulnerability, parameterize it into a PoC
and run it. A finding is **reproduced** — and only then — when:

1. `poc.build` produces a PoC. It returns the **PoC YAML as text** (read it back,
   confirm it captures the trigger and a concrete assertion). Keep it
   human-readable; an operator must be able to read and edit it.
2. `poc.run` against the target returns `passed: true` and emits its three
   artifacts (the finding-capture flow, the replayable PoC YAML, the
   vuln-triggering screenshot).
3. **Where a control is available**, the same `poc.run` against the patched/control
   path returns `passed: false`. A PoC that passes on both proves nothing — treat a
   passing control as a false positive and drop the candidate.

Only after that pass do you record anything. `poc.run` is the **terminal** action
for a candidate: once it passes (and the control fails), you stop acting on that
candidate. Do not escalate further.

### 6. Record and report

- `findings.record` — persist the finding, referencing the PoC and its artifacts
  and carrying the reproduction outcome (`passed`, and `control_passed` where you
  ran a control). This is a separate, explicit, audited act — `poc.run` never
  persists silently. Record **only** reproduced findings.
- Gather artifacts by reference: `poc.get` for the PoC, `poc.artifact` to read a
  produced file (screenshot, capture) by its path under the PoC out-dir.
- Read your findings back with `findings.list` (optionally filtered by target,
  class, severity, or time) and `findings.get` for a full record, and render the
  report (next section) from them. The report is a *rendering* of the recorded
  findings, not a separate source of truth.

## The report contract (human-friendly, two files)

Write both into the configured report out-dir. A human is the final reviewer, so
the markdown must read well and the index must be machine-clean.

### `report.md`

Human-readable markdown. A short title and summary, then **one section per
finding**, each with:

- title, severity, and vulnerability class / CWE
- the affected endpoint (authority + path)
- reproduction steps a human can follow
- the PoC path and how to re-run it
- the screenshot, inline or linked
- the finding-capture flow id (so a reviewer can open the exact flow)

No tool-generated prose and no boilerplate remediation essay — you write it, from
the recorded findings.

### `findings.index.json`

A machine-readable index the grader consumes — a JSON array, one object per
reproduced finding:

```json
[
  {
    "poc_path": "pocs/reflected-xss-search-q.yaml",
    "target_path": "/search?q=",
    "class": "reflected-xss",
    "passed": true,
    "control_passed": false,
    "finding_capture": "<flow-id>",
    "screenshot_path": "artifacts/reflected-xss-search-q.png"
  }
]
```

`passed` is the PoC result on the target; `control_passed` is its result on the
patched control (where one exists). These are what let the grader score discovery
without you ever asserting against a hidden answer key.

## Self-governance (compose with the bus policy)

The bus enforces its own policy, but you should also govern yourself. Before a
mutating or sensitive call, consider the active policy from `agent.status` and the
command's own sensitivity; if your harness can ask its human to confirm a sensitive
action, let it — your confirmation composes with aitmproxy's gate, it does not
replace it. When the bus refuses a call under policy, surface the refusal and the
command it blocked; do not try to route around the gate.

## Quick command reference

Observation (read-only): `agent.status`, `scope.list`, `proxy.status`,
`config.get`, `ca.status`, `flow.subscribe`, `flow.unsubscribe`, `flow.list`,
`flow.get`, `flow.detail`, `findings.list`, `findings.get`.

Action (gated): `browser.navigate`, `browser.click`, `browser.type`,
`browser.eval`, `browser.get_dom`, `browser.screenshot`, `flow.mark`,
`flow.comment`, `flow.intercept`, `flow.mutate`, `flow.resume`, `flow.replay`,
`flow.kill`, `flow.clear`, `request.send`, `poc.build`, `poc.run`, `poc.list`,
`poc.get`, `poc.artifact`, `findings.record`.

Operator-only (you will be refused): `agent.set`, `scope.add`, `scope.remove`,
`proxy.pause`, `proxy.resume`, `ca.export`, `ca.install`, `ca.uninstall`.

The exact input schema for every command is on the bus — call the harness's
`tools/list` and read the `inputSchema`; this playbook names the verbs and the
wire shapes that have bitten callers, not every parameter.
