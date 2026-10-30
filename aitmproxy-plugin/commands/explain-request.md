---
description: Explain one captured request and its response in plain language.
argument-hint: "[flow-id] (defaults to the latest flow)"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. This command is read-only: it
inspects a captured flow and explains it. Do not replay, mutate, or send.

1. Determine the flow id. If the user supplied one in $ARGUMENTS, use it.
   Otherwise call **`flow.list`** and take the last (newest) id.
2. Call **`flow.detail`** with `--id <flow-id>` (default `--body inline` so you
   get headers and bodies). For a large body use `--body range` with
   `--offset`/`--length` rather than pulling megabytes.
3. Explain, in plain language, for the operator:
   - the request: method, scheme, authority, path, notable headers
     (auth, cookies, content-type), and what the body appears to do;
   - the response: status, content-type, size, and what it returned;
   - anything security-relevant you notice — auth tokens, session cookies,
     reflected parameters, error leakage, redirects, CORS/CSP headers.
4. Render using the **`aitmproxy-rendering`** skill: a short summary line
   then two labelled sections (Request / Response). Redact obvious secret values
   to their last 4 characters in prose.

Keep it factual. Flag things worth a closer look; do not fabricate findings.
