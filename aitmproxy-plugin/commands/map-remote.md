---
description: Create a Map "remote" rule that rewrites a request target before upstream.
argument-hint: "[from-host/url] [to-host/url]"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. A Map remote rule rewrites where
matching requests are sent — a powerful change, so confirm scope before writing.

1. Gather intent from $ARGUMENTS and the conversation: which requests to match
   (host / path / method) and the new target to rewrite them to.
2. Show the current rules first with **`map.list`** so the operator sees context.
3. Before writing, state plainly: the match condition, the rewrite target, and
   that this affects every matching request until removed. Get explicit
   confirmation. Note that `map.add` is **refused from the agent/MCP frontend
   unless `maps.allow_agent_authoring` is set** — if it is refused, tell the
   operator to author it themselves or enable that flag deliberately.
4. On confirmation, call **`map.add`** with:
   - `--kind "remote"`
   - `--condition` a JSON object selecting the requests (e.g. host/path/method)
   - `--action` a JSON object describing the rewritten target
   Use the shapes the tool schema documents; do not guess fields.
5. Confirm with **`map.list`** and render the rule table via the
   **`aitmproxy-rendering`** skill. Remind the operator of
   **`map.remove --id <id>`** to undo.

Only rewrite to targets inside the authorized test scope.
