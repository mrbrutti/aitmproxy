---
name: aitmproxy-reason
description: Use when enumerating candidate injection or abuse points from observed aitmproxy flows, before testing them. Covers the candidate heuristics and the observation-only rule.
---

# Reason — candidate enumeration

Load the **Reason** section of `${CLAUDE_PLUGIN_ROOT}/../PLAYBOOK.md`. Derive
candidates **only** from what you observed in `flow.detail` — never from an oracle
or manifest. The heuristics:

- **Reflected input** reflected verbatim into a response -> XSS / header injection
  / open redirect. Note the reflection context.
- **Object identifiers** in path/query/body -> IDOR / broken object-level authz.
- **Redirect targets** (`Location`, `?next=`/`?url=`) -> open redirect / SSRF.
- **Auth/session surface** (cookies, tokens, missing CSRF) -> CSRF / missing authz.
- **Server-side evaluation** (templates, SQL errors, filenames) -> injection.
- **Verb / parameter tampering** (unexpected method, added/removed/typed params).

Prioritize by observed signal strength and by severity if confirmed. Record your
shortlist with `flow.mark` / `flow.comment` so triage stays auditable.
