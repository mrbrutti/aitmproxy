# aitmproxy — generic MCP-client adapter

For any MCP-capable harness or script that is not Claude or Codex. Adding a harness
is just a new adapter like this one — never a change to the tool. The methodology
is the portable [`../PLAYBOOK.md`](../PLAYBOOK.md); this directory only wires a
client to the bus.

## How a client reaches the bus

aitmproxy's loopback-TCP transport speaks newline-delimited JSON-RPC, gated by a
one-line token handshake (`{"token": "<agent-token>"}` as the first line). Two ways
to connect:

- **Standard MCP stdio client** — spawn the bridge
  ([`../bridge.py`](../bridge.py)) as the MCP server command. `mcp.json` here is a
  ready template: it runs the bridge against `127.0.0.1:8084`, reading the token
  from `./agent.token`. The bridge relays stdio <-> the loopback bus. Point your
  client's MCP config at it; set the port to your aitm config and the token file to
  your token.
- **Raw client** — connect a TCP socket to `127.0.0.1:<port>`, send
  `{"token": "<agent-token>"}\n`, then exchange JSON-RPC lines directly (this is
  what the deterministic scripted-driver gate does, with no harness at all).

## Setup

1. Start `aitm` with `mcp.transport: {loopback_tcp: {port: 8084, token: "<token>"}}`
   and a target in scope.
2. Put the same token in the token file (and lock it down):

   ```bash
   printf '%s' '<the same agent token>' > agent.token
   chmod 600 agent.token
   ```

3. Point your harness at `mcp.json` (stdio transport, `python3` on PATH), or
   implement the raw handshake above.
4. Load `../PLAYBOOK.md` as the agent's instructions.

## Token file

The token is never committed. `./agent.token` (git-ignored by convention) or any
path you pass to the bridge's `--token-file` holds it; the bridge reads it at
connect time and never prints it.

## Safety

Scope and policy are enforced by the bus, not the client. The target must be
authorized and in scope; the client cannot widen scope or raise the policy.
