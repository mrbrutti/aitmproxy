# aitmproxy — Claude adapter

The reference harness for driving aitmproxy. A thin [Claude Code
plugin](https://docs.claude.com/en/docs/claude-code) over the portable
[`../PLAYBOOK.md`](../PLAYBOOK.md): it wires the MCP bus and loads the playbook as
skills. No Anthropic SDK is involved — the adapter only points Claude at the bus.

## Layout

```
claude/
  .claude-plugin/plugin.json   plugin manifest
  .mcp.json                    MCP server wiring (the loopback bus, via the bridge)
  skills/
    aitmproxy-agent/           entry skill: the loop + the reproduction bar
    aitmproxy-observe/         per-phase skills, each loading a playbook section
    aitmproxy-reason/
    aitmproxy-act/
    aitmproxy-reproduce/
    aitmproxy-report/
```

## Prerequisites

1. Start `aitm` with the loopback-TCP transport and an agent token, and a target
   in scope. In the aitmproxy config:

   ```yaml
   scope:
     entries: ["target.example:443"]
   mcp:
     transport:
       loopback_tcp:
         port: 8084
         token: "<a long random agent token>"
   ```

2. Write that **same token** into a file the adapter can read, and lock it down:

   ```bash
   mkdir -p ~/.config/aitm
   printf '%s' '<the same agent token>' > ~/.config/aitm/agent.token
   chmod 600 ~/.config/aitm/agent.token
   export AITM_AGENT_TOKEN_FILE="$HOME/.config/aitm/agent.token"
   ```

   The token never appears in this repo or in the plugin; the bridge
   ([`../bridge.py`](../bridge.py)) reads it from that file at connect time.

3. `python3` on PATH (standard library only — the bridge has no dependencies).

## Wiring

`.mcp.json` registers one MCP server, `aitmproxy`, whose command is the stdio
<->loopback-TCP bridge pointed at `127.0.0.1:8084` and the token file. Adjust the
port to match your config; override the token file with `AITM_AGENT_TOKEN_FILE`.
Install the plugin (or point your project's `.mcp.json` at this one), then let
Claude drive: the `aitmproxy-agent` skill establishes the loop.

## Safety

Scope and policy are enforced by the bus, not by the harness — the plugin cannot
widen scope or raise its own policy. Keep the target authorized and in scope.
