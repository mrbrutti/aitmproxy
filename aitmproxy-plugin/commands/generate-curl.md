---
description: Emit an equivalent curl command for a captured flow (method, headers, body).
argument-hint: "[flow-id]"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. This command only reads a
captured flow and formats a `curl` line; it sends nothing.

1. Read the flow id from $ARGUMENTS (required). If none was given, call
   **`flow.list`** and ask the operator which id, or use the newest and say so.
2. Call **`flow.detail`** with `--id <flow-id>` and `--body inline` to get the
   method, URL (scheme + authority + path), request headers, and request body.
3. Build an equivalent **`curl`** command:
   - `-X <METHOD>` when not GET;
   - the full URL from scheme/authority/path;
   - one `-H 'Name: value'` per request header (drop hop-by-hop headers such as
     `Host`, `Content-Length`, `Connection` that curl sets itself);
   - `--data-raw '<body>'` (or `--data-binary @file` for binary) when there is a
     body; shell-quote safely.
4. Render using the **`aitmproxy-rendering`** skill: a single fenced
   `bash` code block, line-continued for readability, plus a one-line note that
   the operator should only run it against systems they are authorized to test.

Preserve the request exactly; do not add headers that were not captured.
