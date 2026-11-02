# Run record — TUI with the recorded fixture and the snapshot mode removed (2026-11-01)

Spec `docs/superpowers/specs/2026-10-31-remove-fake-data-ui-modes-design.md`, plan tasks T1–T4 and
the stage-6 fix round. Everything below is a real run or a test whose inputs are literals written in
the test. `aitm-tui --fixture`, `--snapshot`, `fixtures/bus-fixture.json` and `src/fixture.rs` no
longer exist; none is cited.

## The gate (Terminal, full workspace, merged head)

`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` from the branch
worktree with main merged in (`gate-final.log`, tail):

```
GATE EXIT=0
```

264 `test result: ok`, 0 `FAILED`. The TUI's own binaries in that run:

| Binary | Result |
|---|---|
| `aitm-tui` lib / bin unit tests | 128 / 5 passed |
| `tests/bus_task.rs` (scripted `BusTransport`, replies are literals) | 3 passed — refused token not retried, back-off ≥ 400 ms, malformed `flow.detail` → warn toast + `DetailFailed` |
| `tests/cli_usage.rs` (the built binary) | 3 passed — `--fixture` / `--snapshot` / `--snapshot-core` / `--cols` / `--rows` exit 2 with `unknown argument` + usage; no args + no `AITM_BUS` exits 2 |
| `tests/complete.rs`, `tests/syntax.rs` | 4 / 7 passed (unchanged: the shared completion-conformance contract and the highlighter) |
| `tests/core_sync.rs` | 7 passed (the core's wire shapes, inline) |
| `tests/tester_edge_cases.rs` | 11 passed |
| `tests/robustness.rs` | 31 passed (26 salvaged + scope gate, screenshot placeholder, L4 inject confirm, empty and 10 003-entry tool lists, mid-session disconnect) |
| `tests/perf.rs` | 2 passed (the wall-clock-bounded tests, in their own binary) |

Real-server tests in the same run (they bind loopback ports, so they run only in the Terminal):

```
test tui_bus_task_runs_against_the_live_loopback_server ... ok     (crates/aitm/tests/tui_live_bus.rs — CORE_TOOLS pinned against the real server)
test tui_l4_cua_against_a_live_core ... ok                         (crates/aitm/tests/l4_cua_tui.rs — real input events against a real core, 37 s)
```

## The real run

`tui-screen.txt`: `aitm tui` built from this branch (in-process bus, operator role) with
`listen: 127.0.0.1:18280` and a scope of `127.0.0.1`, then three requests through its proxy against
`python3 -m http.server 8099`:

```
curl -x 127.0.0.1:18280 http://127.0.0.1:8099/            → 200
curl -x 127.0.0.1:18280 http://127.0.0.1:8099/index.html  → 200
curl -x 127.0.0.1:18280 http://127.0.0.1:8099/missing     → 404
```

The screen (read back from the Terminal panel) lists the three rows with their real statuses and
times, the sidebar counts come from them (`All flows 3`, `Domains 1`, `Scope 2`), the inspector
shows curl's real request headers and the real 404 body, and the status bar reads
`3 / 3 rows · 3 in scope … ● bus in-process · operator`. Nothing is seeded.

## The rejected flags (the built binary, `cli_usage.rs` pins the same)

```
aitm-tui --fixture            → unknown argument `--fixture`       + usage, exit 2
aitm-tui --snapshot out.svg   → unknown argument `--snapshot`      + usage, exit 2
aitm-tui                      → usage, exit 2  (no --bus, no AITM_BUS)
```

## Reproduce

```
cargo build -p aitm
cat > /tmp/tui.yaml <<EOF
listen: 127.0.0.1:18280
scope:
  entries: ["127.0.0.1"]
browser:
  proxy_addr: 127.0.0.1:18281
mcp:
  transport:
    loopback_tcp:
      port: 19290
      token: "<random>"
EOF
python3 -m http.server 8099 --bind 127.0.0.1 &
target/debug/aitm --config /tmp/tui.yaml tui        # in one terminal
curl -x 127.0.0.1:18280 http://127.0.0.1:8099/        # in another
```
