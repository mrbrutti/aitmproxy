# Fix log

Bugs found after the fact, with the rule each one taught. Newest first.

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
