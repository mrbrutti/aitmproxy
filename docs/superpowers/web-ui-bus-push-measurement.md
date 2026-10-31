# Web UI `/bus` push: before/after measurement

**Spec:** `docs/superpowers/specs/2026-10-30-web-ui-bus-push-design.md` (D9, AC25)
**Plan:** `docs/superpowers/plans/2026-10-30-web-ui-bus-push-plan.md` (Task 0 is the instrument, Task 7 fills this note)
**Instrument:** `apps/web/scripts/bus-load.mjs` (`--help` for the flags; `--selftest` for the pure counters; `--seed N` to fill the store)
**Status:** measured 2026-10-30 (one run per variant; see the caveats under Reading the result).

## Headline

Under 20 req/s of live traffic the UI's `flow.list` rate falls from **1.97/s to 0.13/s** (about 93% fewer, bar was at most 0.3/s) because it now subscribes over `/bus` and learns of new flows by push; `flow.detail` stays at about one call per new flow (1.00 before, 1.02 after); idle is unchanged by design (the poll runs every 500 ms until a push proves the stream alive: 2.50 calls/s before, 2.17 after in single runs). In a real browser a flow captured into an already-open page was visible 172 ms later, with no reload.

## Method

What is measured is the UI's own call rate against the core. The server audits every tool call
(`crates/aitm-core/src/audit.rs`: `origin`, `at` in epoch milliseconds, `command`, ...) and
pushes each entry as a `notifications/aitm/agent` line to every subscribed connection
(`server.rs` `push_agent`). The measuring script is a **separate** bridge connection: it
subscribes once with `flow.subscribe {}` and then only listens, counting the UI's calls from
that stream, so it cannot disturb what it measures.

The instrument is the stream and **not** `agent.activity`, which spec D9 named: over `aitm web`
that ring is empty. The web server is a second `McpServer` with its own audit ring, while the
`AgentActivity` command reads the primary server's ring (`crates/aitm/src/main.rs:429` attaches
the ring to the primary only). A first run against the before-binary showed `agent.activity`
returning `[]` while the same connection's subscription received audit lines at 2.47/s idle and
21.79/s under traffic. The server-side mismatch is a follow-up, not part of this change.

Both the UI and the script are bridge connections with `client_label: null` (spec R2), so calls
are attributed by `origin` (`--ui-origin`, default `mcp`: the page opened at `aitm web`'s
default URL is an agent-token connection). The script's own calls are `flow.subscribe` (not
audited; the e2e contract pins that) and one `flow.list` after the last window, whose line is
stamped after the window end; nothing the script does lands inside a window.

Two windows per binary, both with the page open in a real browser:

- **idle**: no traffic, 30 s.
- **traffic**: 20 plain-HTTP req/s for 30 s through the proxy (`127.0.0.1:8080`) to a loopback
  origin the script starts, plus a 1 s settle. The store is seeded with at least 500 flows
  beforehand so `flow.list` has a real cost.

A run is reported as unusable (exit code 3; `valid: false` and the reasons in `warnings` in the
JSON; the tables still print) when a window received no audit line with the UI's origin (page not
open, not on this server, or a wrong `--ui-origin`), when no request got through the proxy, or
when the script's own subscription reported `lagged` during a window (dropped lines make the
counts a floor). A run with only advisory warnings (some requests failed) stays valid and lists
them. The bus URL is printed and saved without userinfo, query and fragment.

Window bounds are the script's clock; audit lines are stamped by the server at record time and
filtered on `at` within the window. The script, the proxy and the browser share one host (the
origin is loopback), so those are the same clock. After a window closes the script waits 250 ms
for lines stamped inside it that are still in flight; the bound itself is not widened. Rates
are counts divided by the window length. Notification rates per kind are counted by arrival.

### A/B with two binaries

`apps/web/dist` is embedded into `aitm` at compile time (`crates/aitm/build.rs`), so each variant
is a build of the UI followed by a build of `aitm`, copied aside:

- `aitm-before`: this branch's starting commit (`e887ad1`, the UI before Task 1 with PR #137's
  server), built at Step 0 before any task landed.
- `aitm-after`: the finished branch.

Each is run alone and measured at its own printed URL. Serving a second UI build through
`vite preview` is **not** an option: the bridge refuses an `Origin` whose authority differs from
`Host` (`crates/aitm/src/web/bridge.rs`), and the repo's dev proxy sets `changeOrigin: true`. The
shared cargo target dir can hand back a stale embed, so `crates/aitm/build.rs` is touched before
each build. A real browser only has to hold the page open.

### Commands

Build a variant (run once per variant, copy the result aside):

```bash
touch crates/aitm/build.rs
(cd apps/web && npm run build)
cargo build -p aitm
cp target/debug/aitm "$TMPDIR/aitm-after"   # or aitm-before, at the starting commit
```

Run a variant. The proxy is deny-by-default, so the loopback origin's address must be a scope
entry; `aitm web` reads scope from the config file, and `--config` is the first argument. Keep
the process in a foreground Terminal tab (it exits when stdin closes):

```bash
printf 'listen: 127.0.0.1:8080\nscope:\n  entries:\n    - "127.0.0.1"\n' > "$TMPDIR/aitm-load.yaml"
"$TMPDIR/aitm-after" --config "$TMPDIR/aitm-load.yaml" web --listen 127.0.0.1:8082 --token T --no-open
```

Open the printed `web UI (agent)` URL in a real browser and leave the page open. Seed the store
(no bus connection, no windows; 10 requests in flight at a time), then measure:

```bash
node apps/web/scripts/bus-load.mjs --seed 500
AITM_WEB_TOKEN=T node apps/web/scripts/bus-load.mjs --label after --json "$TMPDIR/after.json"
```

The token goes in `AITM_WEB_TOKEN` rather than `--token`: argv is visible to other local users
via `ps`. Repeat with `aitm-before` and `--label before`. If the page was opened at the
`web UI (operator)` URL, pass that URL's `t=` token in `AITM_WEB_TOKEN` and add
`--ui-origin operator`. A non-zero exit means the numbers must not be used (`--help` lists the
exit codes).

## Results

Rates are UI calls per second by command (origin `mcp`, i.e. the page opened at `aitm web`'s default
agent URL), counted from the audit lines the measuring script's own subscription received. Runs:
`aitm-before` = the UI at `e887ad1` (PR #137's server, no UI subscribe); `aitm-after` = this branch
at `33e3600`. Real browser: headless Chrome 1248 (`chrome-headless-shell`) holding the page open,
`aitm web` on loopback, 20 req/s for 30 s through the proxy to a loopback origin; the store held
about 600 flows (before) and 500 (after) when each traffic window began. Raw output is in
`before.txt` / `after.txt` (and their `--json`) in the session notes folder.

### Before (`aitm-before`)

| command | idle calls/s | traffic calls/s |
|---|---|---|
| `flow.list` | 2.00 | 1.97 |
| `proxy.status` | 0.50 | 0.48 |
| `flow.detail` | 0.00 | 19.34 |
| **total** | **2.50** (75 calls / 30.0 s) | **21.79** (676 calls / 31.0 s) |

- `flow.list` after traffic: 1200 ids, 46801 bytes (result JSON), 100914 bytes (reply frame)
- Subscriber notifications/s (idle / traffic): flow 0.00 / 77.36 · agent 2.50 / 21.79 · state 0.00 / 0.00
- Requests: 600 sent / 600 ok / 0 failed; `flow.detail` per new flow: 1.00
- Subscription lagged during a window: no

### After (`aitm-after`)

| command | idle calls/s | traffic calls/s |
|---|---|---|
| `flow.list` | 1.67 | **0.13** |
| `proxy.status` | 0.50 | 0.48 |
| `flow.detail` | 0.00 | 19.75 |
| **total** | **2.17** (65 calls / 30.0 s) | **20.37** (632 calls / 31.0 s) |

- `flow.list` after traffic: 1100 ids, 42901 bytes (result JSON), 92514 bytes (reply frame)
- Subscriber notifications/s (idle / traffic): flow 0.00 / 77.34 · agent 2.17 / 20.37 · state 0.00 / 0.00
- Requests: 600 sent / 600 ok / 0 failed; `flow.detail` per new flow: 1.02 (spec R3 threshold 2.5: not reached, `PUSH_COALESCE_MS` stays 100)
- Subscription lagged during a window: no

### Real-browser live check (no reload)

With the `aitm-after` page already open, 5 requests were sent through the proxy with a unique path
marker. The marker was absent from the page text before and present 172 ms after the requests
started, the footer read `1105 / 1105 rows`, and the new rows were fully populated (status 200,
timings, sizes), i.e. refetched through `flow.detail`, not painted from the sparse push summary.
Screenshot `live-after.png` in the session notes folder.

## Reading the result

- **`flow.list` under traffic: 1.97/s to 0.13/s.** The remaining 0.13/s is the 10 s heartbeat plus
  the bootstrap and reconnect snapshots. At the end-of-window list sizes the reply bytes/s
  go from about 1.97 x 100.9 kB = 199 kB/s to 0.13 x 92.5 kB = 12 kB/s (upper bounds: the list grew
  during the window). AC25's bar (at most 0.3/s) is met.
- **`flow.detail` per new flow is unchanged (1.00 to 1.02):** a push triggers one refetch per
  coalesced flow, replacing the poll's one-time discovery fetch. Total calls/s under traffic fall
  only 7% (21.79 to 20.37), as predicted: the win is the list scan, its payload and the latency
  (a new flow is visible about 100 ms plus one round trip after capture, not up to a poll tick later).
- **Idle is unchanged by design (spec R1):** with no traffic no flow notification arrives, so
  freshness is never proven and the loop keeps its 500 ms cadence. The measured idle difference
  (2.50 to 2.17, `flow.list` 2.00 to 1.67) is not explained by any code path that changed at idle
  and is taken as run-to-run variance (one 30 s window per variant); do not read it as a gain.
- **What the UI now receives that it did not:** about 77 flow notifications/s and the audit echo of
  its own calls (about 20/s) under traffic. Flow lines are coalesced into one refetch per flow; audit
  lines for its own background reads are dropped on arrival (spec D7). The audit echo is a server
  behaviour (every audited call is pushed to every subscriber) the client can only filter.
- **Caveats.** Single run per variant on one machine, debug builds, loopback origin (0 ms upstream,
  so flows complete before the first fetch and the "pending re-read" path is not exercised here).
  The `before` store was larger at the start of its traffic window (about 600 vs 500 flows).
  Headless Chrome, not a desktop browser. The audit-line instrument counts every audited call on the
  web server, so another client on the same server would be counted with its own origin (none was
  connected).
