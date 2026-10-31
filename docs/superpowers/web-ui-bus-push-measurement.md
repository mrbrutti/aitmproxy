# Web UI `/bus` push: before/after measurement

**Spec:** `docs/superpowers/specs/2026-10-30-web-ui-bus-push-design.md` (D9, AC25)
**Plan:** `docs/superpowers/plans/2026-10-30-web-ui-bus-push-plan.md` (Task 0 is the instrument, Task 7 fills this note)
**Instrument:** `apps/web/scripts/bus-load.mjs` (`--help` for the flags; `--selftest` for the pure counter)
**Status:** skeleton; numbers pending Task 7.

## Headline

_Filled by Task 7: one sentence with the traffic-window `flow.list` rate before and after, and whether
idle is unchanged. The PR body quotes this line._

## Method

What is measured is the UI's own call rate against the core, read from the server's audit ring
(`crates/aitm-core/src/audit.rs`: every audited call is recorded with `origin`, `at` in epoch
milliseconds, `command`), through `agent.activity {since}` (`crates/aitm-plugins/src/agent.rs`).
The measuring script is a **separate** bridge connection: it subscribes once with
`flow.subscribe {}` (only to count what a subscriber is sent) and from then on calls nothing but
`agent.activity`, so it cannot disturb what it measures. Both the UI and the script are bridge
connections with `client_label: null` (spec R2), so calls are attributed by `origin`
(`--ui-origin`, default `mcp`: the page opened at `aitm web`'s default URL is an agent-token
connection) and the script's own `agent.activity` reads are excluded and reported as such.

Two windows per binary, both with the page open in a real browser:

- **idle**: no traffic, 30 s.
- **traffic**: 20 plain-HTTP req/s for 30 s through the proxy (`127.0.0.1:8080`) to a loopback
  origin the script starts, plus a 1 s settle. The store is seeded with at least 500 flows
  beforehand so `flow.list` has a real cost. 30 s at that rate stays well under the 4096-entry
  ring; the script warns if a read returns a full ring.

Each window's start is the newest ring entry's `at` (server clock); the end is the script's clock
when it reads the ring back. The script, the proxy and the browser share one host (the origin is
loopback), so those are the same clock. Rates are counts divided by the window length.

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

Open the printed `web UI (agent)` URL in a real browser and leave the page open. Seed the store,
then measure (the seed is the script's own traffic generator with the idle window skipped):

```bash
node apps/web/scripts/bus-load.mjs --token T --idle-secs 0 --traffic-secs 25 --rate 20
node apps/web/scripts/bus-load.mjs --token T --label after --json "$TMPDIR/after.json"
```

Repeat with `aitm-before` and `--label before`. If the page was opened at the
`web UI (operator)` URL, pass that URL's `t=` token as `--token` and add `--ui-origin operator`.

## Results

Rates are UI calls per second by command, attributed by `origin`, from the script's table.
Empty cells are filled by Task 7 from the `--json` output.

### Before (`aitm-before`, UI at `e887ad1`)

| command | idle calls/s | traffic calls/s |
|---|---|---|
| `flow.list` | | |
| `proxy.status` | | |
| `flow.detail` | | |
| `agent.status` | | |
| `agent.activity` (UI's own) | | |
| _other (list them)_ | | |
| **total** | | |

- `flow.list` after traffic: _n_ ids, _n_ bytes (result JSON)
- Subscriber notifications/s (idle / traffic): flow _/_ · agent _/_ · state _/_
- Requests: _sent_ / _ok_ / _failed_; `flow.detail` per new flow: _n_
- Ring wrapped: no / yes

### After (`aitm-after`, UI at the branch head)

| command | idle calls/s | traffic calls/s |
|---|---|---|
| `flow.list` | | |
| `proxy.status` | | |
| `flow.detail` | | |
| `agent.status` | | |
| `agent.activity` (UI's own) | | |
| _other (list them)_ | | |
| **total** | | |

- `flow.list` after traffic: _n_ ids, _n_ bytes (result JSON)
- Subscriber notifications/s (idle / traffic): flow _/_ · agent _/_ · state _/_
- Requests: _sent_ / _ok_ / _failed_; `flow.detail` per new flow: _n_ (spec R3: above 2.5 means
  raising `PUSH_COALESCE_MS` to 250 in a follow-up)
- Ring wrapped: no / yes

## Reading the result

Stated up front (spec D9) so a surprise is a finding:

- Under traffic `flow.list` falls from about 2/s to the heartbeat (about 0.1/s); AC25 requires at
  most 0.3/s after.
- `flow.detail` per new flow stays within about a factor of 2 of before.
- Idle is unchanged (spec R1: the freshness gate cannot trust a quiet subscription), and is
  reported as such.
- Total calls/s under traffic may not fall; the win is the list scan, its payload and latency.

_Task 7 writes the verdict here, and, if a real browser could not be driven, says so and records
that only the e2e contract (`tests/e2e/web/test_bus_push_ui_contract.py`) and the unit suites
support the claim; the script is not a substitute for the UI._
