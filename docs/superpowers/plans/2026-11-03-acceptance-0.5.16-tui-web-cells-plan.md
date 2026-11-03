# 0.5.16 acceptance: red TUI and web cells, implementation plan

**Status:** approved (2026-11-03, self-approved under Matt's autonomous mode; investigation card from the 0.5.16 acceptance)
**Spec:** `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md` (D4, D5, D7, new D12) and, for Task 1, `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` D5 (amended)
**Branch / worktree:** `claude/modest-wilson-66c5e0` (`.claude/worktrees/modest-wilson-66c5e0`)

## Overview

The 0.5.16 run (`docs/testing/2026-11-03-release-acceptance-0.5.16/run-20261103T162722Z`) was
the first live run of TUI-1, TUI-2, N2-TUI, TUI-5a, TUI-6 and WEB-6a (0.5.10 and 0.5.11 SKIPped
them on a held port). Reproduced on a main build through the same pty harness and a real
Chrome over CDP (findings: side-session note `acceptance-0.5.16-tui-web-cells-FINDINGS.md`):

- **One product regression** (#255, after v0.5.11): `aitm tui` calls `flow.subscribe` on its
  in-process connection, the core refuses (no push sink), and the Warn toast replaces the
  startup log note within milliseconds. Task 1 fixes it.
- **Everything else is harness or spec drift**: the cell reads the screen while the startup
  checklist card is still up; the TUI's words lost their em dashes (Matt's TUI-wide rule, #255
  rounds G/H); the status-bar count is flows in scope, not hosts; the TUI's in-process server
  is unaudited by design (durable-audit spec), so the one-shot CLI is the bus truth; the local
  CA `n` toasts `ca.install cancelled` (system-proxy spec D17.11); the web cell read the toolbar
  pill as the intercept bar and `Disarm<kbd>i</kbd>` as `Disarmi`. Tasks 2–4.

Tasks 1, 2, 3 and 4 touch disjoint files and run in parallel. Task 5 is the live proof.

## Literals (the single table the cells and the spec rows pin)

| Where | Literal |
|---|---|
| TUI flows pane, empty | `No flows yet: point a client at 127.0.0.1:8080 or open the browser.` (generic: `No flows yet: point a client at the proxy or open the browser.`) |
| TUI startup toast | prefix `embedded proxy · log: ` (or `embedded proxy · log location not reported`, or `embedded proxy · logging disabled: could not open `) |
| TUI status bar | regex `bus \S.*? · operator` (reads `● bus in-process · operator`) |
| TUI scope prompt hint | `host · host:port · *.wildcard (a human action)` |
| TUI Scope panel, empty | `Scope is empty: every flow is dimmed and read-only. Press a to add a host.` |
| TUI sidebar host count | regex `^\s*Scope\s+(\d+)`: exactly 1 for a fresh Scope, ≥ 1 only when the host pre-existed (the status bar's ` · N in scope` counts flows) |
| TUI armed bar | `Intercept armed: every request pauses here`; pill gains ` · intercept armed` (asserted while armed); toasts `Intercept armed: every request pauses` (transient, a survey fact in D12, not asserted) / `Intercept disarmed` (asserted) |
| TUI CA confirm | prompt `confirm: ca.install` (the cell's regex `confirm: ca\.install`; the row continues `: <description> [y/N]`); hint `y runs it · n / Esc cancels` is **not asserted** (the description pushes it off 180 cols); `n` → toast `ca.install cancelled` |
| TUI bus truth | `aitm scope list` (JSON array contains the host), `aitm proxy status` (`intercept_armed`) run as one-shot verbs on the operator's default config while `aitm tui` runs |
| Web intercept bar | the `[role=status]` element whose text starts `Intercept armed — every request pauses here` (toolbar pill is also `[role=status]`); buttons by their text nodes only (`<kbd>` excluded): `Disarm`, `Rules…`, `Resume`, `Apply & Resume` |

## Tasks

### Task 1: `aitm tui` does not call `flow.subscribe` on the in-process transport

- **Satisfies:** acceptance spec D4 TUI-1 (startup toast visible); T7 spec D5 as amended
- **Depends on:** none
- **Files:** `crates/aitm-tui/src/bus.rs` (modify), `crates/aitm-tui/src/lib.rs` (modify), `crates/aitm-tui/tests/bus_task.rs` (modify), and the two TCP callers of `connector`/`bus::run` in `crates/aitm/tests/l4_cua_tui.rs` and `crates/aitm/tests/tui_live_bus.rs` (modify; amended 2026-11-03 after the coder's gap report: `crates/aitm/src/tui.rs` goes through `RunOptions` and needs nothing)
- **Change:** `bus::run(connect, req_rx, ev_tx, poll)` gains a `push: bool` (name it as the module's vocabulary wants, e.g. `subscribe: bool`): when `false`, `subscribe()` returns `Ok(())` without calling `flow.subscribe` and without any toast. `lib::connector(choice)` returns the flag beside the label: `TransportChoice::Tcp` → `true`, `TransportChoice::InProcess` → `false`; `lib::run` passes it. Doc comments on `subscribe()` and `connector()` say why (the in-process server has no push sink by design; poll is truth, T7 D5). No other behaviour changes; the TCP path still subscribes once per connection.
- **Test:** in `tests/bus_task.rs`, `the_in_process_handshake_never_subscribes`: `start`-style helper with the flag `false` against `refusing_subscribe` (the bus that refuses `flow.subscribe`): the recorded request lines contain no `flow.subscribe` and no `BusEvent::Toast` is emitted during the handshake (the existing `the_handshake_subscribes_once_when_the_bus_offers_flow_subscribe` and `a_failed_subscribe_is_a_warn_toast_not_a_session_loss` keep passing with the flag `true`). Run `cargo test -p aitm-tui` first failing (the new test cannot compile or fails), then passing.
- **Done when:** the test passes and the gate passes (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` in the Terminal; the sandbox cannot bind sockets).

### Task 2: the TUI journey cell reads the frame, the new words and the one-shot truth

- **Satisfies:** acceptance spec D4 TUI-1, TUI-2, TUI-5, TUI-6, D7 N2 as amended
- **Depends on:** none (the literals table above is the contract)
- **Files:** `tests/e2e/acceptance/test_tui_journey.py` (modify)
- **Change:**
  1. TUI-1 waits for the ratatui frame, not the checklist card: `wait_for(r"No flows yet", 30)` (the card prints `aitmproxy` first), then `wait_for(r"bus \S.*? · operator", 5)`, then polls for the startup toast (`wait_for` over the `TOAST_LOG` prefixes, 6 s). A `flow.subscribe failed` text anywhere in `term.raw` at that point is a FAIL naming it (the #255 regression, Task 1). `NO_FLOWS`/`NO_FLOWS_GENERIC` take the colon wording.
  2. TUI-2: hint `(a human action)`; Scope-empty words with the colon; the host count is read from the sidebar row (`^\s*Scope\s+(\d+)`) and the status bar's ` · N in scope` is **recorded** after the toast clears (`wait_for(r" · \d+ in scope", 8)`), not required to be 1. Bus truth: `aitm scope list` as a one-shot (`subprocess.run([AITM, "scope", "list"], timeout=40)`, stdout JSON) contains the host; the audit grep goes, with a one-line comment citing the durable-audit spec's "TUI in-process server unaudited" follow-up. Result detail reads `bus truth: one-shot CLI` instead of `audit only`.
  3. TUI-5a: regex `Intercept armed: every request pauses here`; bus truth `aitm proxy status` `intercept_armed` true after arm and false after disarm (both recorded; FAIL if either is wrong).
  4. TUI-6: prompt `confirm: ca\.install`; the hint is observed and reported, not asserted; `n` → `wait_for(r"ca\.install cancelled", 5)`; `ca-audit.jsonl` still must hold no `install` row from this run.
  5. Module docstring: `aitm tui` now serves the loopback operator bus (one-shot CLI truth); keep the `# e2e: tier=manual surface=acceptance` header line as is.
  No other cell's logic changes; `PAUSE_HINT` and the `removed <host>` cleanup words are verified against `crates/aitm-tui/src/ui/bars.rs` / `app.rs` and left as they are if unchanged.
- **Test:** `python3 -m py_compile tests/e2e/acceptance/test_tui_journey.py`; `python3 tests/e2e/acceptance/lib/test_installed_helpers.py` still passes; the live proof is Task 5.
- **Done when:** the file compiles, the helpers test passes, and Task 5's run against the dev build shows every amended assertion true.

### Task 3: the web journey cell reads the intercept bar and the buttons' labels

- **Satisfies:** acceptance spec D5 WEB-6a (and keeps WEB-6b/6c/6d honest) as amended
- **Depends on:** none
- **Files:** `tests/e2e/acceptance/lib/web_journey.mjs` (modify)
- **Change:** `status()` selects the intercept bar: the `[role=status]` whose `innerText` starts with `Intercept armed` or matches `/^\d+ paused/` (empty string when none; WEB-6d's "bar gone" keeps working). A `btnLabel(b)` helper joins a button's text nodes only (excluding `<kbd>`): WEB-6a's `Disarm`/`Rules…` checks, WEB-6b's `Resume|Apply & Resume` check use it. Everything else unchanged; comments at the two sites say why (toolbar pill is `[role=status]` too; `Button` renders `<kbd>` inside the button).
- **Test:** `node --check tests/e2e/acceptance/lib/web_journey.mjs`; the live proof is Task 5.
- **Done when:** the file parses and Task 5 shows WEB-6a judged PASS on the dev build.

### Task 4: spec rows dated, the 0.5.16 re-survey recorded

- **Satisfies:** AC1/AC2 of the acceptance spec (every quoted string exists in the source)
- **Depends on:** none
- **Files:** `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md` (modify), `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (modify)
- **Change:** in the acceptance spec, amend rows TUI-1, TUI-2, TUI-5, TUI-6 (D4) and WEB-6a/6b (D5) with the literals table, each with `amended 2026-11-03:` and the reason; add **D12. Words re-surveyed for the 0.5.16 release** after D11 recording: the 0.5.10/0.5.11 SKIPs, the checklist-card timing, the em-dash rule (#255 G/H), flows-vs-hosts count, the unaudited in-process server and the one-shot CLI truth, D17.11 cancel wording, the hint clipped at 180 cols (product polish candidate), the web `[role=status]` and `<kbd>` facts, and the #255 `flow.subscribe` regression (fixed by Task 1). In the T7 spec, amend D5's first bullet: on the in-process transport the TUI does not attempt `flow.subscribe` and shows no toast (dated 2026-11-03, this plan).
- **Test:** none (docs); the spec-reviewer checks the rows against the source.
- **Done when:** both files carry the dated amendments.

### Task 5: live proof against the dev build (tester)

- **Satisfies:** every amended assertion, Matt's real-binary rule
- **Depends on:** Tasks 1–3
- **Files:** none in the repo (transcripts under `/tmp/claude/`)
- **Change:** build `aitm` with the web dist; run the amended TUI cell's logic (its constants and regexes imported from the module) through `tui_pty.Terminal` against `target/debug/aitm --config <isolated cfg> tui` on 18080/18081 and the one-shot verbs with the same `--config`; run the amended `web_journey.mjs` helpers against `aitm --config <cfg> web` on 18082 through the cua-driver. The installed-build cells themselves need 8080-8082 free (the app holds 8080) and run on Matt's next acceptance.
- **Done when:** transcripts show TUI-1 (pills, status bar, startup toast visible, no `flow.subscribe failed`), TUI-2 (hint, toast, listed, sidebar count 1, `aitm scope list` contains the host), N2, TUI-5a (bar + `intercept_armed` true/false), TUI-6 (`ca.install cancelled`, no ca-audit row) and WEB-6a (bar text, Disarm, Rules…) all true.

## Review log

Stage-6 panel on `abeda7d6..77c5aef4` (security, quality, spec; 2026-11-03): three PASS verdicts, no Critical or Important, twelve Minors. Re-review of the fix round `77c5aef4..61719d0a` (quality, spec): PASS, one wording Minor, fixed.

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| 1–5 | security | — | PASS, no findings; no `unsafe` in range | — |
| 1 | quality | Minor | `push: bool` threaded positionally through `connector`/`bus::run`/`Session` (a 3-tuple) | Accepted 2026-11-03 (autonomous mode): the plan allowed the bool; a `pushes()` property on `BusTransport` is the follow-up if a fourth transport fact appears |
| 1 | quality | Minor | tautological `flows.is_empty()` assert in the in-process handshake test | Fixed in the fix commit |
| 1 | quality | Minor | reconnect timeout message hard-codes 6 s | Fixed in the fix commit |
| 1 | quality | Minor | module doc line over-long after rewrap | Fixed in the fix commit |
| 2 | quality | Minor | `test_tui_oneshot_json` covers two functions; stale docstring; env pop outside `finally`; E303 | Fixed in the fix commit (split, docstring, `finally`) |
| 2 | quality | Minor | TUI-5a duplicated isinstance expression, 330-char step line | Fixed in the fix commit (`armed_flag` helper) |
| 2 | quality | Minor | regression detector searches the raw escape stream | Fixed in the fix commit (escapes stripped before the search) |
| 4 | quality | Minor | plan Literals row `confirm: ca.install:` vs cell regex without the colon | Fixed in the plan (row softened to what the cell pins) |
| 4 | spec | Minor | D12 names no survey SHA (AC2 anchor) | Fixed: D12 heading names `abeda7d6` (survey tree) and `96101377` (Task 1 fix) |
| 2/4 | spec | Minor | TUI-5 row lists the pill suffix and the arm toast, the cell asserted neither | Fixed: the cell asserts the pill ` · intercept armed`; the arm toast is a D12 survey fact, moved out of the "must show" words |
| 2 | spec | Minor | sidebar count asserted `>= 1`, the row says `Scope 1` | Fixed: `== 1`, or `>= 1` when the host pre-existed |
| 2/4 | spec (re-review of `77c5aef4..61719d0a`) | Minor | plan Literals row lacked the word "only" the spec row has | Fixed in the plan |
| 1/2 | spec | Minor | tester's tests ride in the coder commits, not `test(...): tester —` commits | Accepted 2026-11-03: the orchestrator committed the shared tree in three logical commits; the tests are doc-commented "Tester" |

## Shipped
