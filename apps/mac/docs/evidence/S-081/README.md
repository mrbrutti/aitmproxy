# S-081 — A Scope add that fails says so, and lands after a core restart

Real app, real core, real input. Dev bundle `/tmp/Aitmproxy-dev-il.app` (`DEV_TAG=il tools/snap-dev.sh`,
core = the installed 0.5.10 release core, isolated `APP_STORE`), driven with System Events
(menu clicks, keystrokes) and `tools/cgclick.swift`, read back with `tools/winshot.swift` and the
core's own `scope.list` over the bus (operator token from the core's `config.yaml`). Nothing here
touched the installed app. Logs are the scripts' stdout with timestamps.

## before/ — the build with the row state but without the bus fix

1. (no frame) `during.restart` typed, Proxy ▸ Restart Core clicked, Return. The shot at Return
   +0.7 s was already past the reconnect, so there is no frame of the row while that core was
   down; the row's `queued` state during a restart is shown in after/1 instead.
2. `2-still-queued-6s-after-reconnect.png` — at Return +0.7 s and again at +6 s (the two shots are
   byte-identical) the title shows the new core connected (new proxy port), the row still reads
   `queued — added when the core is back`, the status bar `add to scope: the bus connection
   closed`; `proof2.log`: `scope.list` on the new core = `["a..host","queued.test","up.test"]`,
   no `during.restart`.
3. `3-remove-after-restart-bus-closed.png` + `remove-verb.log` — a row ✕ after that restart:
   `remove from scope: the bus connection closed` under a connected title, host still listed.
   That is the second cause (FIXLOG 2026-11-01): the superseded bus run's teardown cleared the
   new run's client; polling kept its own reference, so the window looked connected while every
   verb failed until the next reconnect.
4. `4-not-added-row-overflowed.png` — first cut of the failed row: Retry beside a full-width state
   cell overflowed the row (host clipped at the leading edge, ✕ pushed out, Retry off-screen).

## after/ — the fixed build

1. `1-queued-77ms-after-return.png` — `burst.test` typed, Restart Core, Return; the first burst
   frame (`b02-59.051` against `58.974 return pressed`, see `proof4-burst-frames.log`): title
   `connecting…`, Proxy switch off, row `queued — added when the core is back`.
2. `2-landed-315ms-after-return.png` — the next frame (`b03-59.289`): connected to the new core,
   `burst.test` a plain row, pill 4, status bar clear. `proof4-burst.log`: `scope.list` names it.
3. `3-three-restarts-all-landed.png` + `proof3-three-restarts.log` — `restart1/2/3.test`, each typed
   during a Restart Core; `scope.list` after each: all three present.
4. `4-remove-after-restart-works.png` — ✕ on a row after the third restart removes it on the first
   try (`scope.list` drops `restart1.test`); a plain add (`up2.test`) lands within the poll.
5. `5-refused-host-not-added-retry.png` + `5b-after-retry-same-refusal.png` + `gate/scope-json.log`
   (branch tip, after the merge with main and the panel fixes) — a host the core refuses
   (`tab<TAB>here.test`, pasted: the page's own validator cannot catch a control character and the
   keyboard cannot type one; `core-accepts-most-hosts.log` shows the core accepts `*`, `a..host`,
   unicode, `_`, leading `-`, so a control character is the only live refusal): the row reads
   `not added — scope.add: "tab\there.test" is not a host, host:port, or *.wildcard` in red with
   Retry and ✕; the status bar carries the same reason; `scope.list` = `["ok.test"]` only, and the
   dev store's `scope.json` is `{"hosts":["ok.test"]}` before the add, after the refusal, after Retry
   and after ✕ (the log reads the file at each step). The frame after Retry is identical to the one
   before it: the core refuses again with the same words.
6. `6-refused-host-dropped-with-x.png` — ✕ on that row drops it; `scope.list` unchanged
   (`proof6b-retry-drop-restart.log`). Frame from the previous build; the ✕ path (`remove` →
   `dropScopeAdd`) is unchanged on the tip, where the final run's ✕ click landed on an inactive
   window and only activated it (`gate/scope-json.log`, "after x": row still there, file unchanged).
7. `7-add-during-restart-landed-tip.png` + `gate/scope-json.log` — branch tip: `during.restart`
   typed during Proxy ▸ Restart Core lands; `scope.list` = `["ok.test","during.restart"]`,
   `scope.json` = `{"hosts":["ok.test","during.restart"]}`. The first burst frame (+143 ms,
   `final-burst-frames.log`) already shows it landed: this restart was faster than the frame; the
   `queued` moment is after/1.
8. `8-remove-after-restart-tip.png` — branch tip: ✕ on `ok.test` right after that restart removes it on
   the first try; `scope.list` = `["during.restart"]`, `scope.json` follows.

## gate/ — the merged tree (origin/main c65ed0f2 merged, commit after the merge)

- `swift-test.log` — 725 Kit tests in 83 suites + 31 bus-client tests, all pass.
- `live.log` — `tools/selftest-live.sh` over a private 0.5.10 release core: `LIVE SELFTEST PASS 98 checks`.
- `reconnect.log` — `tools/selftest-live-reconnect.sh` (the #192 ownership check, required after any
  `Bus/` change): Reconnect Bus, Restart Core, kill -KILL → `RECONNECT LIVE SELFTEST PASS`.
- `scope-json.log` — the final run on the tip (items 5, 7, 8 above): `scope.json` read before and after
  every step; a refused host writes nothing to it.
- `gate-summary.log` — the gate script's exit lines on the tip.

## busy/ — a core that is merely busy, and every surface after a successful add

Asked by the orchestrator after the diagnosis of the installed 0.5.10 (Scope empty on the core; the
add had never left the app). Dev bundle, 0.5.10 release core; the embedded core is made "busy" with
`kill -STOP` (bus socket open, nothing answers) and released with `kill -CONT` — no restart, no
reconnect, no operator action in between.

1. `1-status-before-add.png` → `3-status-after-add.png` (`2-scope-0.7s-after-add.png` between): one add
   of `ok.test`, and 0.7 s later the Scope row is a plain entry, the pill reads `1 hosts in scope`,
   the sidebar badge 1; the Status page's step turns from "Add a host to Scope (for now as
   example.com:443)" to "Scope: 1 host decrypted" ✓; the Flows banner's "Nothing is decrypted
   until a host is in Scope" line is gone (after/5 shows the banner with a host in Scope).
2. `4-core-stopped-queued-33s.png` — `busy.test` typed while the core is stopped: 33 s later (past the
   bus client's 30 s call timeout) the row reads `queued — added when the core is back`, the
   status bar `add to scope: the bus did not reply in time`, the title still "connected".
3. `5-landed-3s-after-cont.png` — 3 s after `kill -CONT`, with no reconnect: `busy.test` is a plain
   row, pill `2 hosts in scope`, badge 2; `scope.list` = `["ok.test","busy.test"]` (`run1.log`).
4. `run1.log` also shows the gap the first run exposed: `scope.json` still `{"hosts":["ok.test"]}`
   after the late landing — the core had applied the timed-out call when it woke, so the app's own
   verb path (the only `scope.json` writer) never ran. Fixed on the tip: a scope.list that confirms
   an operator add in flight persists the snapshot too; `run2.log` reads the file after SIGCONT.
