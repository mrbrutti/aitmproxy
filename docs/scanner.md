# Automated scanner

The automated scanner is a **deterministic, Burp-style scanner** built into
aitmproxy as the `aitm-plugin-scanner` plugin. It crawls an in-scope target and
discovers **injection points** — the places in a request where a value can be
tampered with — so an operator (human or AI) starts from a concrete map of the
attack surface instead of a blank page.

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
- `scan.discover` is a `Write`-sensitivity command, so it is subject to the
  operator approval gate when an agent runs it.

Discovered examples are **scrubbed of secrets**: credential-bearing values
(`Authorization`, `Cookie` values, and parameters whose names look like session
or auth material) are returned as `<redacted>`, never echoed in the result.

## Running it

`scan.discover` is a plugin command, so — like every command in aitmproxy — it is
**auto-surfaced over MCP, the CLI, and the UIs** at once, with the same scope and
sensitivity rules. It is **operator-run and agent-taskable**.

### CLI

```bash
aitm scan discover --target https://example.test/
# optionally narrow the crawl:
aitm scan discover --target https://example.test/ --max_depth 2 --max_pages 50
```

### MCP

Call the `scan.discover` tool with the same parameters from any connected agent
or MCP client. It is both **agent-taskable** (an agent can run a discovery pass
on its own) and **operator-driven**.

### UIs

All three operator UIs — the **web UI**, the **TUI**, and the **macOS app** —
have a **Scan** view that launches `scan.discover` against an in-scope target and
renders the result: the discovered endpoints and injection points. Both the
endpoint rows and the injection-point rows **link back to the flow** they were
found in, so an operator can jump straight from a discovered point to the
captured request behind it.

## Inputs

| Parameter | Type | Required | Description |
|---|---|---|---|
| `target` | string | yes | The seed URL to crawl (`scheme://host[:port]/path`). Its host must be in scope. |
| `max_depth` | int | no | Crawl depth limit. Clamped to the configured cap (default **3**) — it can only lower the cap, never raise it. |
| `max_pages` | int | no | Maximum pages to crawl. Clamped to the configured cap (default **200**). |

The remaining limits come from the plugin's `ScannerConfig` and are not
per-call overridable in Stage 1: a request budget (default **2000**) and a crawl
time budget (default **10 minutes**). `max_depth` / `max_pages` overrides are
always clamped **down** to these configured caps — a caller can tighten a scan
but never exceed the operator-set bounds.

## Output

`scan.discover` returns a structured object:

| Key | Type | Description |
|---|---|---|
| `endpoints` | array of strings | The in-scope URLs the crawl reached. A link that redirects within the origin contributes both the URL the crawl requested and the page it landed on. |
| `injection_points` | array of objects | The discovered injection points (below). Repeated scans of the same site do not accumulate: a point is unique per `(endpoint URL, location, name)` and carries the newest captured flow that showed it. |
| `endpoint_flows` | object | endpoint URL (as in `endpoints`) -> id of the newest captured flow that served it; an endpoint with no capture is absent. |
| `pages_crawled` | int | Number of pages successfully navigated. |
| `stopped_reason` | string or null | Why the crawl stopped early (e.g. `"navigation_failed"`, `"guard_refused"`, or a cap being hit); `null` if it completed normally. |

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
- **`header`** — request headers that carry attacker-influenceable values.
- **`cookie`** — each request cookie (value always redacted).
- **`path_segment`** — numeric path segments (likely identifiers), e.g. the `42`
  in `/users/42/profile`.
- **`redirect`** — a parameter whose value is itself a URL (an open-redirect
  candidate).

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
[obscura browser](../README.md#the-obscura-browser): it navigates the seed,
harvests same-origin in-scope links (tag-aware — only `<a>`/`<area>` `href` and
`<form>` `action`, never script or comment bodies), and enqueues them under the
depth / page / time caps. The browser proxies through aitmproxy, so each
navigation produces captured flows that the enumerator then reads. When no
browser engine is attached, discovery falls back to enumerating injection points
from flows already in the store, so a store-only run still honours scope and rate
state.

## Roadmap: the active stages

Discovery (`scan.discover`) is the **only** scanner command that exists today.
The **active** stages are designed but **not built yet** — they are on the
roadmap (targeted for a later release, v0.6), not present features. Do not expect
these commands on a current build:

- **`scan.inject`** *(planned)* — send payloads to the discovered injection
  points.
- **`scan.run`** *(planned)* — run a bounded, scope-confined scan campaign over a
  target.
- **`scan.report`** *(planned)* — turn confirmed hits into reproducible PoCs and
  recorded findings via the
  [PoC / check engine](../README.md#poc--check-engine).

Until those land, treat `scan.discover` as a **read-only reconnaissance** step:
it tells you *where* to look; injection, confirmation, and reporting stay with
the operator and the existing flow, scripting, and PoC tooling.
