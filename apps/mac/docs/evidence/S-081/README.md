# S-081 — A Scope add that fails says so, and lands after a core restart

Real app, real core, real input. Dev bundle `/tmp/Aitmproxy-dev-il.app` (`DEV_TAG=il tools/snap-dev.sh`,
core = the installed 0.5.10 release core, isolated `APP_STORE`), driven with System Events
(menu clicks, keystrokes) and `tools/cgclick.swift`, read back with `tools/winshot.swift` and the
core's own `scope.list` over the bus (operator token from the core's `config.yaml`). Nothing here
touched the installed app. Logs are the scripts' stdout with timestamps.

## before/ — the build with the row state but without the bus fix

1. `1-queued-during-restart.png` — `during.restart` typed, Proxy ▸ Restart Core clicked, Return:
   the row reads `queued — added when the core is back`, the status bar
   `add to scope: the bus connection closed`.
2. `2-still-queued-6s-after-reconnect.png` — six seconds later the title shows the new core
   connected (new proxy port) and the row is still `queued`; `proof2.log`: `scope.list` on the
   new core = `["a..host","queued.test","up.test"]`, no `during.restart`.
3. `3-remove-after-restart-bus-closed.png` + `remove-verb.log` — a row ✕ after that restart:
   `remove from scope: the bus connection closed` under a connected title, host still listed.
   That is the second cause (FIXLOG 2026-11-01): the superseded bus run's teardown cleared the
   new run's client; polling kept its own reference, so the window looked connected while every
   verb failed until the next reconnect.
4. `4-not-added-row-overflowed.png` — first cut of the failed row: Retry beside a full-width state
   cell overflowed the row (host clipped at the leading edge, ✕ pushed out, Retry off-screen).

## after/ — the fixed build

1. `1-queued-77ms-after-return.png` — `burst.test` typed, Restart Core, Return; 77 ms later: title
   `connecting…`, Proxy switch off, row `queued — added when the core is back`.
2. `2-landed-315ms-after-return.png` — 315 ms after Return: connected to the new core, `burst.test`
   a plain row, pill 4, status bar clear. `proof4-burst.log`: `scope.list` names it.
3. `3-three-restarts-all-landed.png` + `proof3-three-restarts.log` — `restart1/2/3.test`, each typed
   during a Restart Core; `scope.list` after each: all three present.
4. `4-remove-after-restart-works.png` — ✕ on a row after the third restart removes it on the first
   try (`scope.list` drops `restart1.test`); a plain add (`up2.test`) lands within the poll.
5. `5-refused-host-not-added-retry.png` + `proof6-refused.log` — a host the core refuses
   (`tab<TAB>here.test`, pasted: the page's own validator cannot catch a control character and the
   keyboard cannot type one; `core-accepts-most-hosts.log` shows the core accepts `*`, `a..host`,
   unicode, `_`, leading `-`, so a control character is the only live refusal): the row reads
   `not added — scope.add: "tab\there.test" is not a host, host:port, or *.wildcard` in red with
   Retry and ✕; the status bar carries the same reason; `scope.list` = `["ok.test"]` only.
6. `6-refused-host-dropped-with-x.png` — ✕ on that row drops it; `scope.list` unchanged. (Retry was
   clicked between 5 and 6; the core refuses again identically, so the frame after Retry is the
   same as 5 — Retry's re-send is covered by `ScopeAddQueueTests`, not distinguishable on screen.)
7. `7-add-during-restart-landed-rebuilt.png` + `proof6b-retry-drop-restart.log` — the rebuilt
   bundle (row-width fix) once more: `during.restart` typed during Restart Core lands,
   `scope.list` = `["ok.test","during.restart"]`.
