# Fix log

Bugs found after the fact, with the rule each one taught. Newest first.

## 2026-10-28 — `BusService.call` called itself

Symptom: the compiler warned "function call causes an infinite recursion" at
`Bus/BusService.swift:127` on the S-069 build; on a live bus every action (arm, resume, kill,
replay, scope.add…) would have overflowed the stack. Shipped in b7d3163; the self-test runs on
fixtures (`FixtureActions`), so nothing exercised it.
Cause: the activity-log wrapper `call(_:_:)` was added with the same name as the `BusClient`
method it wraps, and the body said `try await call(name, args)` instead of
`try await live().call(name, args)`.
Fix: 7ce8963, one token.
Rule: a wrapper never shares the name of the call it wraps inside the same type, and a build
with any warning is not a clean build (`build.sh` shows warnings; read them before the commit
message says "zero warnings").
