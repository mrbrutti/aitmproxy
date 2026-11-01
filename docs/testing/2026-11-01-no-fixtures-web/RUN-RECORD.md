# Run record — web UI with the mock bus removed (2026-11-01)

Spec `docs/superpowers/specs/2026-10-31-remove-fake-data-ui-modes-design.md`, plan tasks W1–W5.
Everything below is a real run: the web UI built from this branch, served by a real `aitm web`
built from this branch (main merged in), with real traffic through its proxy. No mock, fixture,
snapshot or seeded-store run exists any more in `apps/web`, and none is cited.

## What ran

| Step | Command | Result |
|---|---|---|
| Unit gate | `npm run typecheck && npm test` in `apps/web` | 51 files, 531 tests, exit 0 |
| UI build | `npm run build` | `dist/` built (embedded into the core by `crates/aitm/build.rs`) |
| Core | `cargo build -p aitm` from this branch | `target/debug/aitm` (copied to `/tmp/claude/aitm-web-branch-2`) |
| Live gate | `AITM_BIN=… node scripts/selftest-live.mjs` | **23 PASS / 0 FAIL / 4 SKIP, exit 0** — `selftest-live-final.log` |
| Real browser | Safari opened on the operator URL `aitm web` printed (`#t=<token>`); two `curl -x <proxy>` requests sent through the proxy | `safari-flows.png` |

## The live script, after W5

Before W5 the same script reported 8 PASS / 13 FAIL against this very core: every FAIL was the
script's expectation lagging the core (a 37-tool pin against 73 served tools, sensitive commands
refused because it connected as an agent under the `auto` policy, a removed `findings.list limit`
parameter, and four "gap" checks that failed because the gaps had closed). W5 made the script connect
as the operator (the token from the `Operator` line of `aitm web`'s start-up block), assert the
current shapes, and report the closed gaps as PASS. Nothing was weakened: a refusal or an error is
still a FAIL with the core's text. The four SKIPs are honest and unchanged in meaning: no embedded
browser on this host, no header-deletion form in `flow.mutate`, the script never subscribes
(`flow.subscribe` exists; a probe is a follow-up), and no `browser.tabs` tool.

Summary line of `selftest-live-final.log`:

```
{"pass":23,"fail":0,"skip":4,"gaps":["F3: flow.mutate edits.headers is {name: \"string\"} — replaces only, no removal form","F4: 0 server notifications after 23 steps of traffic — this script never calls flow.subscribe, so it sees no push …","F14: no browser.tabs tool …"]}
```

Steps that prove the UI's data path with real traffic: `capture: GET /api/me through the proxy lands
in flow.list with full detail`, `intercept: arm, park a POST, review, mutate, resume — upstream sees
the edit`, `intercept: … kill it — client fails, detail says killed`, `replay`, `compose` (in scope
and the out-of-scope refusal), `poc.build` / `poc.list` / `poc.get` / `poc.run` / `poc.artifact`,
`proxy.pause` / `proxy.resume`, `flow.clear`.

## The real browser

`safari-flows.png`: Safari at `127.0.0.1:51121`, the UI built from this branch (`v0.5.8` in the
sidebar at the time of the shot; the status bar reads `bus 127.0.0.1:51121`, listening
`127.0.0.1:51119`). The list shows six real flows: four made by the live script (`/api/me`,
`/api/echo?compose=1`, `/search?q=probe`) and the two curl requests sent by hand through the proxy
(`GET http://127.0.0.1:51118/api/me 200`, `GET http://127.0.0.1:8099/ 200` against a
`python3 -m http.server 8099`). Apps 1, Domains 2, Scope 1, Findings 1 — all from real data.
Nothing is seeded.

## Reproduce

```
cd apps/web && npm ci && npm run build
cargo build -p aitm
AITM_BIN=../../target/debug/aitm node scripts/selftest-live.mjs --keep   # prints the UI URL
open -a Safari "<the UI URL>"
curl -x 127.0.0.1:<proxy port> http://127.0.0.1:<target port>/api/me
```
