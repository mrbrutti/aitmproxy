# Automated scanner

The automated scanner is a **deterministic crawler and injection-point finder**
built into aitmproxy as the `aitm-plugin-scanner` plugin — the discovery stage of
a Burp-style scanner. It crawls an in-scope target and discovers **injection
points** — the places in a request where a value can be tampered with — so an
operator (human or AI) starts from a concrete map of the attack surface instead
of a blank page. It does not attack anything: active fuzzing and injection are
roadmap, not shipped.

It is **deterministic and AI-free**: the same target and the same configuration
produce the same crawl and the same injection points, driven only by the shape of
the traffic, never by a model's judgement or a manifest. That is the point — the
scanner **augments** an AI operator's own free-form detection; it does not
replace it. The agent still decides what is interesting and how to exploit it.
The scanner just makes sure nothing in scope is missed.

> **Stage 1 — Discovery.** This documents the shipped first stage: **crawl +
> injection-point discovery**, exposed as the `scan.discover` command. Discovery
> is **read-only** — it navigates and enumerates, it never injects or mutates.
> The **active** stages (fuzz / inject / campaign) are **not built yet** and are
> on the roadmap, not present features; see
> [Roadmap: the active stages](#roadmap-the-active-stages).

## Deny-by-default and scope-bound

Like every action in aitmproxy, the scanner is **deny-by-default and strictly
scope-bound**. It will only touch hosts you have explicitly put in scope:

- The target host is checked against the scope/rate guard (`check_active`)
  **before any navigation**. An out-of-scope target fails immediately with
  `GuardError::OutOfScope` — nothing is fetched.
- Every page the crawl reaches is gated the same way; a link to an out-of-scope
  or cross-origin host is skipped, not followed.
- The crawl runs through the proxy's **scope-confined egress gate**: the
  browser-facing listener refuses an out-of-scope *public* host rather than
  relaying it (`confine_egress_to_scope`), so a redirect or sub-resource cannot
  pull the crawl off-scope. This is the chokepoint that confines the whole crawl,
  on top of the per-navigation guard checks above.
- The crawl is **same-origin and in-scope only**, bounded by depth, page, and
  time caps (below).
- `scan.discover` is a `Write`-sensitivity command: it is bound by the agent
  policy when an agent runs it (it runs under `all`, `auto` and `ask`; it is
  refused under `readonly` and `paused`), and always by scope, rate and SSRF
  checks.

Discovered examples are **scrubbed of secrets**: credential-bearing values
(`Authorization`, `Cookie` values, and parameters whose names look like session
or auth material) are returned as `<redacted>`, never echoed in the result.

## Running it

`scan.discover` is a plugin command, so — like every command in aitmproxy — it is
registered once and reachable from MCP, the one-shot CLI and the UIs, with the
same scope and sensitivity rules. It is **operator-run and agent-taskable**.

A real crawl needs a **running proxy with its embedded browser**: the bare `aitm`
server (the MCP server), `aitm web` and `aitm tui` each launch the configured
engine (obscura by default; see [INSTALL.md](../INSTALL.md) if it is not found)
and register `scan.discover`. Drive it through one of those, not the one-shot CLI.

### MCP

Call the `scan.discover` tool with the same parameters (`target`, and optionally
`max_depth` and `max_pages`) from any connected agent or MCP client. It is both
**agent-taskable** (an agent can run a discovery pass on its own) and
**operator-driven**.

### CLI (one-shot, no crawl)

```bash
aitm scan discover --target https://example.test/
# optionally narrow the crawl:
aitm scan discover --target https://example.test/ --max_depth 2 --max_pages 50
```

The `aitm <family> <verb>` form is a **one-shot, in-process** dispatch: it builds a
fresh core with an empty flow store and **no browser**, runs this one command and
exits. It never connects to a proxy you have running, so it cannot crawl and
cannot see that proxy's flows. Against a target whose host is in scope it returns
no endpoints, `pages_crawled: 0` and `stopped_reason: "no_browser"` (the
store-only fallback has nothing to list); against any other host it fails with an
out-of-scope error before fetching anything. The one-shot process takes its scope
from `scope.entries` in `config.yaml`; an `aitm scope add` run in a separate
process neither persists nor reaches the running proxy. Treat the CLI form as a
way to check argument parsing and scope, and use MCP or a UI for actual scans.

### UIs

All three operator UIs — the **web UI**, the **TUI**, and the **macOS app** —
have a **Scan** view that launches `scan.discover` against an in-scope target and
renders the result: the discovered endpoints and injection points. The
injection-point rows **link back to the flow** they were found in, and an endpoint
row links to the newest captured flow that served it (`endpoint_flows`), so an
operator can jump straight from a discovered point to the captured request
behind it. In the web UI the Scan item appears in the sidebar only when the
connected core offers the `scan.discover` tool; in the TUI, `r` launches a scan
from the Scan view.

### One discovery at a time

All crawls share the one embedded-browser page, so two at once would interleave
their navigations and each would harvest the other's pages. A `scan.discover`
started while another is still running is therefore **refused immediately** with
`scan.discover is already running; wait for it to finish before starting
another …` — it never touches the browser. The running scan gives the slot back
however it ends, and the next one then runs normally; scans run back to back
need no reset in between.

A scan is **not cancelled when its client goes away**. If you disconnect the MCP
client or close the panel, the crawl keeps running and keeps the slot until it
finishes or hits its time budget (default **10 minutes**), so you can be refused
by your own earlier scan. Wait for it to end rather than retrying.

## Inputs

| Parameter | Type | Required | Description |
|---|---|---|---|
| `target` | string | yes | The seed URL to crawl (`scheme://host[:port]/path`). Its host must be in scope. |
| `max_depth` | int | no | Crawl depth limit. Clamped to the configured cap (default **3**) — it can only lower the cap, never raise it. |
| `max_pages` | int | no | Maximum pages to crawl. Clamped to the configured cap (default **200**). |

The remaining limit is a crawl time budget (default **10 minutes**). These
defaults are built in: there is no `config.yaml` key for them, and `max_depth` /
`max_pages` overrides are always clamped **down** to the caps — a caller can
tighten a scan but never exceed them.

## Output

`scan.discover` returns a structured object:

| Key | Type | Description |
|---|---|---|
| `endpoints` | array of strings | The in-scope URLs the crawl reached. A link that redirects within the origin contributes both the URL the crawl requested and the page it landed on. |
| `injection_points` | array of objects | The discovered injection points (below). Repeated scans of the same site do not accumulate: a point is unique per `(endpoint URL, location, name)` and carries the newest captured flow that showed it. |
| `endpoint_flows` | object (URL to flow id) | Maps each endpoint URL (as in `endpoints`) to the id of the newest captured flow that served it. An endpoint with no capture is absent. |
| `pages_crawled` | int | Number of pages successfully navigated. |
| `stopped_reason` | string or null | Why the crawl stopped early: `"max_pages"`, `"max_depth"`, `"time_budget"`, `"left_scope"` (a navigation landed off-origin or out of scope, such as a redirect, and the crawl aborted there), `"navigation_failed"` (every navigation failed), `"guard_refused"` (the guard refused every link), or `"no_browser"` (no browser engine attached; see below). `null` if the reachable graph was exhausted. |

Each array is capped at 1024 entries.

Each entry in `injection_points` is an object:

| Field | Type | Description |
|---|---|---|
| `flow` | string | The id of the captured flow the point was found in. |
| `location` | string | Where in the request the value sits — one of `query`, `body_param`, `header`, `cookie`, `path_segment`, `redirect`. |
| `name` | string | The parameter / header / cookie / segment name. |
| `example` | string | An example value observed for it — `<redacted>` when the value is credential or session material. |

### How injection points are found

Injection points come from the **shape of the captured request**, not from a
template or manifest. For each in-scope flow the crawl produced, the enumerator
reads the request and yields a point for each:

- **`query`** — each URL query-string parameter (percent-decoded).
- **`body_param`** — each form-encoded body parameter, and each top-level JSON
  object key in a JSON body.
- **`header`** — each request header other than `Cookie` and `Host` (a header whose
  name reads as a secret, such as `Authorization`, carries `<redacted>`).
- **`cookie`** — each request cookie (value always redacted).
- **`path_segment`** — numeric path segments (likely identifiers), e.g. the `42`
  in `/users/42/profile`.
- **`redirect`** — a query or body parameter whose value is itself a URL
  (starts with `http://`, `https://` or `//`; an open-redirect candidate).

Because discovery is driven purely by the request, it finds the same points a
human would read off the traffic, every time.

## Example

```jsonc
// scan.discover { "target": "https://example.test/" }
{
  "endpoints": [
    "https://example.test/",
    "https://example.test/search",
    "https://example.test/account/",
    "https://example.test/redirect"
  ],
  "endpoint_flows": { "https://example.test/": "…", "https://example.test/search": "…" },
  "injection_points": [
    { "flow": "…", "location": "query",    "name": "q",       "example": "test" },
    { "flow": "…", "location": "cookie",   "name": "session", "example": "<redacted>" },
    { "flow": "…", "location": "redirect", "name": "next",    "example": "https://example.test/home" }
  ],
  "pages_crawled": 4,
  "stopped_reason": null
}
```

## How it crawls

The crawl is a bounded breadth-first walk driven over aitmproxy's embedded
[obscura browser](../README.md#embedded-browser): it navigates the seed,
harvests same-origin in-scope links (tag-aware — only `<a>`/`<area>` `href` and
`<form>` `action`, never script or comment bodies), and enqueues them under the
depth / page / time caps. The browser proxies through aitmproxy, so each
navigation produces captured flows that the enumerator then reads. When no
browser engine is attached (obscura not found, or a one-shot CLI call), discovery
does not navigate: it lists the distinct same-origin, in-scope request URLs
already in the flow store (up to `max_pages`) and enumerates their injection
points, reporting `stopped_reason: "no_browser"` and `pages_crawled: 0`. That
store-only run still honours scope and rate state.

## Roadmap: the active stages

Discovery (`scan.discover`) is the **only** scanner command that exists today.
The **active** stages are designed but **not built yet** — they are on the
roadmap, not present features. Do not expect these commands on a current build:

- **`scan.inject`** *(planned)* — send payloads to the discovered injection
  points.
- **`scan.run`** *(planned)* — run a bounded, scope-confined scan campaign over a
  target.
- **`scan.report`** *(planned)* — turn confirmed hits into reproducible PoCs and
  recorded findings via the
  [PoC engine](../README.md#scripting-and-reproducible-pocs).

Until those land, treat `scan.discover` as a **read-only reconnaissance** step:
it tells you *where* to look; injection, confirmation, and reporting stay with
the operator and the existing flow, scripting, and PoC tooling.
