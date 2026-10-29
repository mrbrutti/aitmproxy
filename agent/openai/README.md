# aitmproxy — OpenAI/Codex adapter

A thin adapter that points an OpenAI/Codex harness at the aitmproxy MCP bus and
carries the portable [`../PLAYBOOK.md`](../PLAYBOOK.md). No OpenAI SDK is involved.

## Files

- `config.toml` — the Codex `[mcp_servers.aitmproxy]` block; merge into your Codex
  config (e.g. `~/.codex/config.toml`).
- `instructions.md` — the system prompt / instructions carrying the playbook.

## Setup

1. Start `aitm` with the loopback-TCP transport, an agent token, and a target in
   scope (same config shown in [`../claude/README.md`](../claude/README.md)); here
   the example port is `8084`.
2. Write the agent token into a file and `chmod 600` it:

   ```bash
   mkdir -p ~/.config/aitm
   printf '%s' '<the same agent token>' > ~/.config/aitm/agent.token
   chmod 600 ~/.config/aitm/agent.token
   ```

3. Edit `config.toml`: set the bridge path to the absolute path of
   [`../bridge.py`](../bridge.py) in your checkout, the `--port` to match your
   config, and `--token-file` to the token file. Merge it into your Codex config.
4. Give the harness `instructions.md` as its system prompt (or concatenate
   `PLAYBOOK.md` into it, per that file).

`python3` (standard library only) must be on PATH for the bridge.

## Safety

Scope and policy are enforced by the bus. The adapter cannot widen scope or raise
its policy. Keep the target authorized and in scope.
