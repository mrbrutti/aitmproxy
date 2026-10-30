---
description: List recent captured flows as a table (method, URL, status, duration, state).
argument-hint: "[optional filter hint, e.g. 'errors' or a host]"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. Only report on captured traffic;
never widen scope or send new requests from this command.

Goal: show the operator the most recent flows as a compact table.

1. Call the MCP tool **`flow.table`** (no arguments). It returns
   `{ "flows": [ { id, kind, method, authority, path, status, duration_ms,
   state, marks }, ... ] }`, oldest first.
2. If `flow.table` is unavailable, fall back: call **`flow.list`** to get the
   ids, then **`flow.detail`** (`--id <flow-id>`) for each of the most recent
   rows and assemble the same columns yourself.
3. Render the result using the **`aitmproxy-rendering`** skill — a
   text/markdown table with columns: id, method, authority+path (as the URL),
   status, duration (ms), state, marks. Put the newest flows at the bottom.
   Use the palette tokens the rendering skill defines; never invent colours.

If the user passed an argument ($ARGUMENTS), treat it as a filter hint and only
show rows whose URL, status, or state match it; otherwise show the latest ~30.
Close by noting how many flows are in the store and the id of the newest.
