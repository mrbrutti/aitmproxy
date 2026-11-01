---
description: Show and adjust the proxy Scope (the decryption list) and TLS passthrough pins; explain what each does to live traffic and the agent-widen gating.
argument-hint: "[add <host> | remove <host> | passthrough add/remove <host>]"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. Scope defines which hosts are in
bounds; keep it tight and only ever within the operator's authorization.

**Scope is the decryption list.** The proxy decrypts TLS only for hosts in Scope
and tunnels every other HTTPS connection byte for byte, so an empty Scope decrypts
nothing. Every CONNECT is still a row in `flow.table`: `tunnel` is `decrypted`
(its inner requests are their own rows), `passthrough` (`tunnel_reason`
`out_of_scope` or `pinned`, with `bytes_up` / `bytes_down` and a duration once it
closes) or `failed` with a reason — `client_rejected_certificate` means the client
refused the proxy's certificate (an untrusted aitm CA), the usual cause of a
capture that looks empty. Plain HTTP to a host outside Scope is shown but
`passive`: no script, breakpoint or map rule touches it.

The flip is live and per connection: `scope.add` decrypts the next connection to
that host, `scope.remove` tunnels it; connections already open are left alone.
`tls.passthrough` pins win over Scope: a pinned host is tunnelled even when it is
in Scope. A `passthrough` row with `tunnel_reason` `out_of_scope`, or a `passive`
row, is the cue to offer `scope.add` for its host (the `authority` without the
port); a `pinned` row is not — the way back is `tls.passthrough.remove`.
`proxy.status` reports `decrypt` (`scope_hosts`, `decrypting`, `advice`); when
nothing is decrypted, `advice` is the one sentence to show the operator, verbatim.

1. Always start by showing the current state:
   - **`scope.list`** — the active scope entries (the hosts that are decrypted);
   - **`tls.passthrough.list`** — hosts pinned as tunnelled (never decrypted, even
     when in Scope);
   - **`proxy.status`** — read `decrypt.decrypting` and `decrypt.advice`.
   Render the lists as tables via the **`aitmproxy-rendering`** skill.
2. Interpret $ARGUMENTS as the requested change, and act:
   - add a host (decrypt new connections to it): **`scope.add --host <host|host:port|*.wildcard>`**
   - remove a host (tunnel new connections to it): **`scope.remove --host <host>`**
   - pin a host as never decrypted: **`tls.passthrough.add --host <host>`**
   - unpin it (decrypted again only if it is in Scope): **`tls.passthrough.remove --host <host>`**
3. Explain the **agent-widen gating** clearly; the decryption model did not change it:
   - `scope.add` is **refused from the agent/MCP frontend unless
     `scope.allow_agent_widen` is set**; **narrowing (`scope.remove`) is always
     allowed**.
   - `tls.passthrough.add`/`remove` are **refused from the agent frontend unless
     `tls.allow_agent_passthrough` is set**.
   If a call is refused, say so and tell the operator to make the change
   themselves or enable the flag deliberately — do not try to work around it.
4. Re-show the lists after any change so the operator sees the result, and say
   that the change applies to new connections only.

Never widen scope to a host the operator has not confirmed is authorized.
