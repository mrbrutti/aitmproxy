# Web UI `/bus` push: before/after measurement

**Spec:** `docs/superpowers/specs/2026-10-30-web-ui-bus-push-design.md` (D9, AC25)
**Plan:** `docs/superpowers/plans/2026-10-30-web-ui-bus-push-plan.md` (Task 0 is the instrument, Task 7 fills this note)
**Instrument:** `apps/web/scripts/bus-load.mjs` (`--help` for the flags; `--selftest` for the pure counters; `--seed N` to fill the store)
**Status:** measured 2026-10-30 at three commits (see Results); the numbers to quote are the HEAD run's (`306754f`: the merge of `main` with PR #145, plus the Activity snapshot filter).

## Headline

Under 20 req/s of live traffic the UI's `flow.list` rate falls from **1.97/s to 0.10/s** (about 95% fewer; the bar was at most 0.3/s) because it now subscribes over `/bus` and learns of new flows by push; `flow.detail` stays at about one call per new flow (1.00 before, 1.02 at head); idle is NOT reduced, by design (the poll runs every 500 ms until a push proves the stream alive; observed 2.50 calls/s before and 2.17 at head, 13% lower, cause not isolated). At head, in a real browser, a flow captured into an already-open page was visible 169 ms later with no reload, and a freshly loaded page, whose bootstrap snapshot comes from an audit ring holding thousands of the UI's own polling lines, showed an Activity log of two rows.

## Method

What is measured is the UI's own call rate against the core. The server audits every tool call
(`crates/aitm-core/src/audit.rs`: `origin`, `at` in epoch milliseconds, `command`, ...) and
pushes each entry as a `notifications/aitm/agent` line to every subscribed connection
(`server.rs` `push_agent`). The measuring script is a **separate** bridge connection: it
subscribes once with `flow.subscribe {}` and then only listens, counting the UI's calls from
that stream, so it cannot disturb what it measures.

The instrument is the stream and **not** `agent.activity`, which spec D9 named: over `aitm web`
that ring was empty when this was first measured (before PR #145, which since shares the primary's ring with the web server; the stream is unaffected). The web server was a second `McpServer` with its own audit ring, while the
`AgentActivity` command reads the primary server's ring (`crates/aitm/src/main.rs:429` attaches
the ring to the primary only). A first run against the before-binary showed `agent.activity`
returning `[]` while the same connection's subscription received audit lines at 2.47/s idle and
21.79/s under traffic. The server-side mismatch was fixed by PR #145 independently of this change.

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
open, not on this server, or a wrong `--ui-origin`), when no request got through the proxy, when the script's own subscription reported `lagged` during a window (dropped lines make the
counts a floor), or when both windows were skipped (nothing was measured). A run with only advisory warnings (some requests failed) stays valid and lists
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
agent URL), counted from the audit lines the measuring script's own subscription received. Four
runs, all on one machine with debug builds, a real browser (headless Chrome 1248,
`chrome-headless-shell`) holding the page open, `aitm web` on loopback, and 20 req/s for 30 s through
the proxy to a loopback origin:

- **before**: `aitm-before`, the UI at `e887ad1` (PR #137's server, no UI subscribe).
- **after (33e3600)**: the first complete implementation, measured before the review rounds.
- **4e28994**: the branch after three panel rounds, before `main` was merged in.
- **head**: `aitm-merged`, built at branch head `306754f` (the merge of `main`, which brought PR #145's
  shared audit ring, plus the fix that filters the Activity snapshot too). This is the run to quote.

Raw output, `--json` and screenshots are committed next to this note in
`web-ui-bus-push-measurement-data/` (`merged.*` is the head run; the JSON of `before` and `after`
predates the `valid` and `warnings` fields the script gained in review round 1; the `$TMPDIR` in the
`json:` lines replaces the session path the runs wrote to).

| command | before idle | before traffic | 33e3600 idle | 33e3600 traffic | 4e28994 idle | 4e28994 traffic | **head idle** | **head traffic** |
|---|---|---|---|---|---|---|---|---|
| `flow.list` | 2.00 | 1.97 | 1.67 | 0.13 | 1.67 (1.43) | 0.10 | **1.67** | **0.10** |
| `proxy.status` | 0.50 | 0.48 | 0.50 | 0.48 | 0.50 (0.50) | 0.52 | **0.50** | **0.52** |
| `flow.detail` | 0.00 | 19.34 | 0.00 | 19.75 | 0.00 | 20.62 | **0.00** | **19.66** |
| **total** | **2.50** | **21.79** | **2.17** | **20.37** | **2.17** (1.93) | **21.24** | **2.17** | **20.27** |

(Parentheses: a second idle sample.)

- Calls counted at head: 65 idle / 629 traffic, over 30.0 s idle and 31.0 s traffic windows (before: 75 / 676).
- `flow.detail` per new flow: before 1.00, 33e3600 1.02, 4e28994 1.07, **head 1.02** (spec R3 threshold 2.5:
  not reached, `PUSH_COALESCE_MS` stays 100).
- `flow.list` after traffic: before 1200 ids, 46801 bytes (result JSON), 100914 bytes (reply frame);
  head 1100 ids, 42901 bytes, 92514 bytes.
- Subscriber notifications/s (idle / traffic): before flow 0.00 / 77.36, agent 2.50 / 21.79; head flow
  0.00 / 77.35, agent 2.17 / 20.27; state 0.00 throughout.
- Requests: 600 sent, 600 ok, 0 failed in every traffic window. No subscription lagged. The runs at 4e28994
  and head report `valid: true`.

### Real-browser checks

- **A flow captured into an open page is visible in 169 ms (head; 172 ms at 33e3600).** With the page
  already open, 5 requests were sent through the proxy with a unique path marker. The marker was absent
  from the page text before and present 169 ms after the requests started, without a reload; the footer
  read `1105 / 1105 rows` and the new rows were fully populated (status 200, timings, sizes), i.e.
  refetched through `flow.detail`, not painted from the sparse push summary. Screenshots at head: `live-after.png`
  (the new rows at the end of the list) and `activity-merged-fresh.png`.
- **The Activity log is not flooded, on a fresh page load against the shared ring (head).** After the
  runs above the audit ring held thousands of this UI's own polling lines (since PR #145 `agent.activity`
  over `aitm web` returns the shared ring: the Agent panel's counter read `130 actions / min` with the page
  open). A brand-new page was then loaded, so its bootstrap snapshot came from that ring: the Activity log
  held two rows, both `script.list` (one from the earlier page, found in the snapshot, one from this page),
  i.e. the snapshot's history is kept and the polling is filtered. Screenshot
  `activity-merged-fresh.png`. Before the snapshot filter was added this path would have shown the newest
  500 polling lines. At 4e28994 (live push only) a page left open for about 20 minutes held one row
  (`activity-final.png`).
- **Subscribing adds no per-call latency (head).** A sequential `proxy.status` probe on one connection
  measured 0.3 ms mean, median and p90 both before and after `flow.subscribe` on the same connection
  (`merged-rtt.txt`; `rtt-probe.txt` at 4e28994 says the same).

## Reading the result

- **`flow.list` under traffic: 1.97/s to 0.10/s.** The remaining rate is the 10 s heartbeat plus the
  bootstrap and reconnect snapshots. At the end-of-window list sizes the reply bytes/s go from about
  1.97 x 100.9 kB = 199 kB/s to 0.10 x 92.5 kB = 9 kB/s (upper bounds: the list grew during the
  window). AC25's bar (at most 0.3/s) is met at every measured commit.
- **`flow.detail` per new flow is unchanged (1.00 to 1.02):** a push triggers one refetch per coalesced
  flow, replacing the poll's one-time discovery fetch. Total calls/s under traffic fall only 7% (21.79 to
  20.27), as predicted: the win is the list scan, its payload and the latency (a new flow is visible about
  100 ms plus one round trip after capture, not up to a poll tick later).
- **Idle is not reduced, by design (spec R1):** with no traffic no flow notification arrives, so
  freshness is never proven and the loop keeps its 500 ms cadence. The observed idle rate was lower
  after (2.17 at three commits, 1.93 once, against 2.50), 13% to 23% lower, with `flow.list` periods of
  about 600 to 700 ms instead of 500 ms. No code path that changed at idle explains it and the latency
  probe above rules out slower replies, so the likely cause is timer slip in the headless page on a
  machine that was running other test suites at the time; this was not isolated and a controlled idle A/B
  on a quiet machine was not run. Do not read it as a gain.
- **What the UI now receives that it did not:** about 77 flow notifications/s and the audit echo of its
  own calls (about 20/s) under traffic. Flow lines are coalesced into one refetch per flow; audit lines
  for its own background reads are dropped on arrival, on the live push and on the snapshot (spec D7). The
  audit echo is a server behaviour (every audited call is pushed to every subscriber) the client can only
  filter.
- **Side effect of PR #145, not of this change:** with the shared ring, `agent.status` counts this UI's
  own polling as agent actions (`130 actions / min` in the Agent panel while the sidebar badge says
  `0/min`), because the page runs on the agent token. Follow-up.
- **Caveats.** One run per variant (a second idle sample at 4e28994), debug builds, loopback origin (0 ms
  upstream, so flows complete before the first fetch and the "pending re-read" path is not exercised).
  The `before` store was larger at the start of its traffic window (about 600 vs 500 flows). Headless
  Chrome, not a desktop browser. The instrument counts every audited call on the web server, so another
  client on the same server would be counted with its own origin (none was connected).
