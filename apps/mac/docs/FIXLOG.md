# Fix log

Bugs found after the fact, with the rule each one taught. Newest first.

## 2026-11-01 — A Scope add that never reached the core stayed on the page as "pending"

Symptom: on the installed 0.5.10 Matt "added to scope" and the app "still claims
nothing is in scope". The bus truth agreed with the app: `scope.list` was empty,
`proxy.status.decrypt.scope_hosts` was 0, and the operator audit had no `scope.add`
from the app at all — the add had never reached the core.
Cause: the Scope page appended the typed host to a view-local `pending` list before
the bus call and only removed it when `scope.list` named it. When the call failed
(the embedded core was restarting — five restarts that afternoon; `OfflineActions`
and a dropped bus both throw `disconnected`) the host stayed listed as a tertiary
"pending" row for ever, the only error signal a transient status-bar line. The page
showed the host; every other surface said nothing was in scope. (A second path to
the same symptom is the core's: `aitm scope add --host` is a one-shot in-process
dispatch that never reaches the running core — the CLI UX session owns that.)
Fix: `ScopeAddQueue` (Kit) holds the adds in flight on the Session: `sending…`,
`queued — added when the core is back` (bus absence; replayed when the bus
reconnects, `BusService` calls `replayQueuedScopeAdds` after its connect-time
`scope.list`), or `not added — <reason>` with Retry and ✕ (the core refused). The
Scope page renders that state on the row instead of a silent pending entry.
Rule: a surface must never show an operator's intent as if it were the system's
state; an in-flight or failed action carries its state on the row it created, and a
failure the bus could not deliver is queued and replayed, not forgotten.

Found by the live proof of that fix (dev bundle, add typed during Proxy ▸ Restart
Core): the row read `queued`, the title showed the new core connected, and the add
still never landed; a row ✕ after the restart failed with "remove from scope: the
bus connection closed" under that connected title. Second cause, in `BusService`:
`start()` (which every embedded `.ready` calls) cancels the previous run task and
begins another, but the superseded task still ran its unconditional teardown —
`session.bus = .failed`, `self.client = nil` — after the new run had installed its
client. Polling kept working (it holds its own reference), so the window looked
connected, while every verb went through `live()`, found no client and failed with
"the bus connection closed" until the next reconnect. On the installed app that is
"I pressed Apply and Restart Core / the core restarted, and now nothing I do lands".
Fix: a run checks cancellation right after its connect, sets the failed state only
when it is still the current run, and clears `client` only if it is still its own.

## 2026-10-31 — The Flows page stopped redrawing after intercept was armed

Symptom: on the installed v0.5.6, Flows page, a parked row kept reading `Paused`
after Resume and new rows never appeared, for as long as you watched, while the
sidebar count, the status bar and the inspector strip all moved; switching to Apps
and back redrew everything. Reproduced on a dev bundle with a real core in one
process: the Apps page updated within a poll, the Flows page not at all.
Cause: `Session.visibleRows` caches the filtered rows and, when `rowsVersion` is
unchanged, returns the cache without reading `rows`. With `@Observable` a view
depends only on what it read during its last body evaluation, so a re-evaluation
for any other reason while the cache was warm (arming intercept shows the bar in
the same `listAndInspector` view; selection; focus) left the flow table with no
dependency on `rows` — later polls changed `rows` and nothing re-rendered until a
page switch changed the query and missed the cache. The Apps page was spared only
because its "no source app" banner reads `session.rows` on every evaluation.
Fix: `visibleRows` reads `rows` and `details` unconditionally before consulting the
cache (the cache still spares the re-filtering).
Rule: a cached computed property on an `@Observable` model must read every
observed input it depends on, on every access, or the views that use it lose the
dependency the first time they re-render for an unrelated reason.

## 2026-10-31 — Breakpoint rules never reached a live core

Symptom: with any rule in Rules… (S-040), arming intercept on a real `aitm` failed
with `bus error -32602: param rules: [0]: unknown param match`, so the whole
`flow.intercept` call was refused and the rules only ever "worked" on fixtures.
Found while proving S-041 live (a response-phase rule is the only way to park a
response).
Cause: `BreakpointRule.arguments` sent the app's own fields (`match`, `flag`) and
the phase token `both`; the core accepts only `id name enabled phase url method
host ws_dir`, phases `request|response|any`, and rejects one unknown key for the
whole call. It also sent a regex pattern as a bare `url` string, which the core
reads as a wildcard, and the core anchors a wildcard (`^…$` on the path) where the
app's preview matches a plain pattern as a substring.
Fix: the wire form carries only the core's fields, `any` for both phases, and
`url` as the core's `{regex}` object: a regex rule travels as written, a wildcard
as the regex the app's own preview uses (`*` any run, `?` one character, no
`*`/`?` a substring, case-insensitive), because the core's wildcard form has no
`?`, no substring match and is case-sensitive, so the preview and the core would
disagree. `BusService.setIntercept` sends the objects unchanged. The live self-test arms a response rule and a
request rule on a real core: the matching request parks, the other passes, and
the edited response is what curl receives.
Rule: a wire form is proven against the real core, never against the fixture
double — one unknown key refuses the whole call and the fixture never says so.

Superseded 2026-10-31 by #208: the core's wildcard now has the preview's semantics
(`*` any run, `?` literal, substring when star-less, leading `/` path-only,
case-insensitive, full URL or path), so a wildcard travels as `{wildcard}` as
typed and `wildcardRegex` is gone; the field discipline above stands.

## 2026-10-31 — The inspector kept the parked copy after Apply & Resume

Symptom: after editing a parked response's status to 203 and pressing Apply &
Resume, the row read 203 with the Edited pencil while the Response pane still
showed `HTTP/1.1 200 OK` — the head cached when the flow was selected while parked.
Cause: `flow.detail` is fetched on selection; `flow.mutate` + `flow.resume` change
the flow on the core but nothing fetched the detail again.
Fix: `applyAndResume` loads the detail again after the resume when edits were sent.
Rule: after a command that changes a flow on the core, refresh what the inspector
shows from the core; the row's summary is polled, the detail is not.

## 2026-10-28 — Removing a header from a paused request was a silent no-op

Symptom: deleting a request header (the Headers table ✕, or deleting the line in
the Raw editor) appeared to work — the row/line vanished — but the header was
still forwarded on Apply & Resume. Found in Stage-6 review of PR #9.
Cause: `RequestEdits.diff` only walks `edited.headers` (added/changed), so a
*removed* header is never encoded; `changeCount` reads 0 and `flow.mutate` is
skipped. Root cause is partly core: `flow.mutate` has no header-removal form yet
(it only replaces), so the UI can't actually remove a header today.
Fix: make the UI honest rather than silently dropping the action —
`RequestEdits.removedHeaderNames` detects attempted removals; the Headers table's
✕ is disabled with a tooltip explaining it needs a core follow-up; the Raw editor
footer warns "Header removal needs a core follow-up — <names> will still be sent".
Real deletion wires up when the core `flow.mutate` gains a removal form.
Rule: never let an edit affordance appear to succeed when the command path can't
apply it — disable it or surface why, so the operator is never misled.

## 2026-10-28 — `BusService.call` called itself

Symptom: the compiler warned "function call causes an infinite recursion" at
`Bus/BusService.swift:127` on the S-069 build; on a live bus every action (arm,
resume, kill, replay, scope.add…) would have overflowed the stack. Shipped in
b7d3163; the self-test runs on fixtures (`FixtureActions`), so nothing exercised it.
Cause: the activity-log wrapper `call(_:_:)` was added with the same name as the
`BusClient` method it wraps, and the body said `try await call(name, args)` instead
of `try await live().call(name, args)`.
Fix: 7ce8963, one token.
Rule: a wrapper never shares the name of the call it wraps inside the same type,
and a build with any warning is not a clean build (`build.sh` shows warnings; read
them before the commit message says "zero warnings").
