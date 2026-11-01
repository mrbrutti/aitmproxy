# Run record — macOS app with the fixture, snapshot and gallery modes removed (2026-11-01)

Spec `docs/superpowers/specs/2026-10-31-remove-fake-data-ui-modes-design.md`, plan tasks M1–M6 and
the stage-6 fix round. Everything below is a real run of the real app with a real core and real
traffic, or a Kit unit test whose inputs are literals written in the test. `APP_FIXTURES`,
`APP_SNAPSHOT`, `APP_KIT_GALLERY`, the fixture session, the fixture bus, the snapshot scenes, the
parts gallery, the fixture self-test and the six tools that ran them no longer exist; none is cited.

## The gate (apps/mac/CLAUDE.md "The gate")

| Step | Command | Result |
|---|---|---|
| 1 unit tests | `swift test --package-path apps/mac --scratch-path …` (Terminal) | `524 tests in 71 suites passed` (Kit) + `31 tests in 6 suites passed` (bus client), exit 0 — `swift-test.log`. Baseline on main was 526: minus the three tests whose subject was the sample set, plus three for `RemovedModes`. |
| 2 tripwires | `tools/grid-lint.sh`, `tools/check-connection-words.sh`, `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh` | all `PASS`, exit 0, no `NOTE`/`not found` line |
| 3 dev bundle | `DEV_TAG=nf CORE_DIR=/Users/matt/Security/aitmproxy/target/release tools/snap-dev.sh` | built, assembled `/tmp/Aitmproxy-dev-nf.app`, launched LIVE on `APP_STORE=/tmp/Aitmproxy-dev-state-nf`, printed pid/store/kill — `snap-dev.log` |
| 4 real traffic | `curl -sS -x 127.0.0.1:61649 http://127.0.0.1:8099/` against `python3 -m http.server 8099 --bind 127.0.0.1` | the upstream page, `HTTP 200` — `curl-through-embedded-proxy.txt`; the row in the real window — `dev-bundle-after-curl.png` |
| 5 live self-tests | `AITM_CONFIG=… APP_BIN=<dev bundle binary> tools/selftest-live.sh 127.0.0.1:8099` against an external `aitm` (v0.5.8 release build) | `LIVE SELFTEST PASS 90 checks`, exit 0; 44 of them are the S-069 menu audit, now part of the live run — `selftest-live.log` |

## What the window shows

- `dev-bundle-open.png` — the dev bundle right after launch, connected to its embedded core
  (`127.0.0.1:61649`, "no extension"): Flows 0, Apps 0, Domains 0, Pinned 0, the honest
  "No scope set" banner, and the Apps page's own empty state. Nothing is seeded; the fresh store
  holds only `columns.json` (the table layout the app writes at launch), no `pins.json`.
- `dev-bundle-after-curl.png` — the same window after the curl: `GET http://127.0.0.1:8099/ 200`,
  3 ms, 76 B; Flows 1, Domains 1. (A shot taken two seconds after the curl still showed 0 rows —
  the poll had not landed yet; this one is a minute later.)

## The refusals (AC2 and spec D3 items 5 and 8) — `selftest-refusals.log`

Run on the dev bundle's binary with stderr dropped, so only the app's own stdout shows:

```
== --selftest without APP_LIVE (stdout only) ==
SELFTEST refused: the fixture self-test was removed on 2026-10-31; run tools/selftest-live.sh (APP_LIVE=1)
exit=1
aitm processes before=3 after=3
== --selftest without APP_STORE (stdout only) ==
SELFTEST refused: set APP_STORE to a folder in /tmp
exit=1
== APP_FIXTURES=1 (removed switch, stdout only) ==
APP_FIXTURES was removed on 2026-10-31 with the fixture modes; see apps/mac/CLAUDE.md
exit=1
== APP_SNAPSHOT=/tmp/x (removed switch, stdout only) ==
APP_SNAPSHOT was removed on 2026-10-31 with the fixture modes; see apps/mac/CLAUDE.md
exit=1
aitm processes at the end=3
```

One line each, exit 1, and the count of `aitm` processes is unchanged: the refusals are decided in
`applicationDidFinishLaunching`, before any window, bus or embedded core exists.

## Finding recorded during this run (not this change's; follow-up)

`kill <pid>` on the dev bundle (the stop line `snap-dev.sh` prints) terminates the app by SIGTERM,
which does not run the AppKit teardown, so the embedded core (`Resources/core/aitm`) and its
`obscura` child survive with parent 1. Observed twice (pids 94104/94107 from the first bundle,
54836/54845 from the second); reaped by hand with a `pkill -f` scoped to the bundle path.
`snap-dev.sh`'s stop line now names that too. The root cause — the app has no SIGTERM handler that
calls `NSApp.terminate` — is a follow-up card for the macOS session (the live self-test quits
through `NSApp.terminate`, which does reap the child).

## Reproduce

```
cd apps/mac
swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build
tools/grid-lint.sh; tools/check-connection-words.sh; tools/check-capture-operator-only.sh; tools/check-capture-toggle.sh
python3 -m http.server 8099 --bind 127.0.0.1 &
DEV_TAG=nf CORE_DIR=<dir with aitm> tools/snap-dev.sh          # prints the pid
lsof -nP -iTCP -sTCP:LISTEN | grep '^aitm '                       # the embedded core's listen port
curl -sS -x 127.0.0.1:<listen> http://127.0.0.1:8099/
swift tools/winshot.swift <pid> /tmp/claude/after.png
AITM_CONFIG=<config of a running aitm> APP_BIN=/tmp/Aitmproxy-dev-nf.app/Contents/MacOS/Aitmproxy-nf tools/selftest-live.sh 127.0.0.1:8099
```
