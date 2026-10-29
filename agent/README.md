# agent/ — the harness-neutral driver surface

aitmproxy's thesis is that an AI agent drives the whole tool over the MCP command
bus. MCP is vendor-neutral, so **any** MCP-capable harness can drive every command;
nothing model-specific lives in the core and no provider SDK is a dependency. What
is per-harness is only the *packaging* of the strategy. This directory is that
packaging, in three layers:

1. **[`PLAYBOOK.md`](PLAYBOOK.md)** — the portable, harness-neutral playbook: the
   observe -> reason -> act -> reproduce -> record -> report loop, the candidate
   heuristics, the reproduction bar, and the report contract. It assumes only the
   MCP tool list. This is the single source of the methodology.
2. **Per-harness adapters** — thin shells that point a harness at the bus and load
   the playbook:
   - [`claude/`](claude/) — a Claude Code plugin (the reference / live-gate
     harness): `.mcp.json`, `SKILL.md`, and per-phase skills.
   - [`openai/`](openai/) — an OpenAI/Codex adapter: its MCP server config +
     instructions.
   - [`generic/`](generic/) — a generic MCP-client config + README for any other
     harness.
3. **[`bridge.py`](bridge.py)** — a dependency-free stdio <-> loopback-TCP shim so a
   standard MCP client can speak the bus's token-gated line protocol. A transport
   bridge, not an agent and not an SDK.

Adding a harness is a new adapter here — never a change to the tool. The
deterministic scripted-driver gate reproduces the same loop with no harness at all,
proving the surface is public and the split holds.
