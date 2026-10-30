---
description: Show and adjust the proxy scope and TLS passthrough; explain agent-widen gating.
argument-hint: "[add <host> | remove <host> | passthrough add/remove <host>]"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. Scope defines which hosts are in
bounds; keep it tight and only ever within the operator's authorization.

1. Always start by showing the current state:
   - **`scope.list`** — the active scope entries;
   - **`tls.passthrough.list`** — hosts tunnelled (not decrypted).
   Render both as tables via the **`aitmproxy-rendering`** skill.
2. Interpret $ARGUMENTS as the requested change, and act:
   - add a host: **`scope.add --host <host|host:port|*.wildcard>`**
   - remove a host: **`scope.remove --host <host>`**
   - stop decrypting a host: **`tls.passthrough.add --host <host>`**
   - resume decrypting: **`tls.passthrough.remove --host <host>`**
3. Explain the **agent-widen gating** clearly:
   - `scope.add` is **refused from the agent/MCP frontend unless
     `scope.allow_agent_widen` is set**; **narrowing (`scope.remove`) is always
     allowed**.
   - `tls.passthrough.add`/`remove` are **refused from the agent frontend unless
     `tls.allow_agent_passthrough` is set**.
   If a call is refused, say so and tell the operator to make the change
   themselves or enable the flag deliberately — do not try to work around it.
4. Re-show the lists after any change so the operator sees the result.

Never widen scope to a host the operator has not confirmed is authorized.
