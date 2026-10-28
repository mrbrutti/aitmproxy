# Fix log

Bugs found after the fact, with the rule each one taught. Newest first.

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
