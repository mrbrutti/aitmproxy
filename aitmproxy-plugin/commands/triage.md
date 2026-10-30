---
description: Sweep recent flows for interesting ones (errors, auth, interesting params) and summarise.
argument-hint: "[optional focus, e.g. 'auth' or '5xx']"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. Triage is read-only: survey the
captured traffic and surface what deserves a closer look. Send nothing.

1. Pull the flow summaries with **`flow.table`** (fall back to **`flow.list`**
   plus **`flow.detail`** per id if needed).
2. For candidates, pull **`flow.detail`** (`--id <flow-id>`) to confirm.
   Flag flows that are interesting for authorized testing:
   - error or unexpected statuses (4xx/5xx, especially 500/401/403);
   - authentication/authorization signals (Authorization headers, Set-Cookie,
     session tokens, JWTs, API keys);
   - interesting parameters (ids, `redirect`/`url`/`next`, `file`/`path`,
     `cmd`, SQL-ish or template-ish values, reflected input);
   - unusual methods (PUT/DELETE/PATCH), mixed-content, or missing security
     headers (CSP, HSTS, CORS wildcards).
3. If $ARGUMENTS names a focus, prioritise it.
4. Render with the **`aitmproxy-rendering`** skill: a ranked table of the
   notable flows (id, URL, status, why-interesting) followed by a short prose
   summary and suggested next steps (e.g. /explain-request, /generate-curl).

Report only what the traffic shows; do not invent vulnerabilities.
