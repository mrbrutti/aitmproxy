# aitmproxy — feature video recording kit

Short, Proxyman-style clips of aitmproxy's UI in action, recorded by you with
QuickTime. Everything here uses **benign sample traffic** (a tiny "Acme" demo
shop) — no security content. Each clip is ~15–40s.

Why you record it (and not me): these are native-GUI screencasts with a real
mouse. This kit stands up the exact scenario and gives you click-by-click steps,
so each clip takes a couple of minutes.

---

## 0. One-time prep

1. Screen recorder: press **⌘⇧5** → choose **Record Selected Portion** (drag a box
   around just the aitmproxy window) → **Options → Save to: Desktop** → **Record**.
   Stop from the menu-bar ⏹ (or ⌘⇧5 again). (QuickTime → File → New Screen
   Recording works too.)
2. Start the scenario (one command, from a terminal):
   ```
   zsh /Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/demo-site/kit/start.sh
   ```
   It prints the **web UI URL** (open in a browser), the **TUI command**, the
   **proxy** (127.0.0.1:18080) and **bus** (127.0.0.1:18090) addresses.
3. In a second terminal, start the live traffic stream (leave it running while you record):
   ```
   zsh /Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/demo-site/kit/traffic.sh
   ```
4. When finished with all clips:
   ```
   zsh /Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/demo-site/kit/stop.sh
   ```

**Pick a surface per clip:** the **web UI** (browser, most Proxyman-like) or the
**TUI** (terminal). The **macOS app** works too if installed — point it at the
external core on the bus `127.0.0.1:18090`, operator token `aitmdemo-operator`.
Record the window region only, and move the mouse deliberately — pauses read as
"nothing happening," so keep clicking.

---

## Clip 1 — Live traffic inspector (flows streaming)

Shows requests arriving in real time. **Surface: web UI** (or TUI).

1. With `traffic.sh` running, open the **web UI URL** from start.sh.
2. Start recording the window.
3. Watch the flow list stream — new rows every fraction of a second, methods
   (GET/POST) and status codes filling in.
4. Hover/scroll the list so it's clearly live. ~15–20s. Stop.

TUI variant: run the printed `aitm-tui …` command; the flow list fills the same way.

---

## Clip 2 — Inspect a request & response

**Surface: web UI.**

1. Recording on. Click any flow in the list (e.g. `/api/products.json`).
2. The inspector opens — click through **Request → Headers**, then
   **Response → Body** (the JSON is shown, pretty/raw tabs).
3. Click a second flow (an HTML page) to show the inspector updating. ~20s. Stop.

TUI variant: ↑/↓ to move the selection, the detail pane updates live; tabs along
the top (Headers / Body / Raw / JSON).

---

## Clip 3 — Edit & replay a request  ★ signature feature

**Surface: TUI (precise hotkeys) or web UI.**

TUI:
1. Recording on. ↑/↓ to select a flow (e.g. `/api/products.json`).
2. Press **`e`** (edit) — the request opens for editing.
3. Change something benign — e.g. add a query param `?limit=2`, or change a header
   value. Type it so the edit is visible.
4. Press **`r`** (replay) — a **new flow** appears in the list with your edited
   request and its fresh response. ~25–30s. Stop.

Web UI: select a flow → **Replay/Edit** (or **Compose**) → change a field → **Send**;
the new flow lands in the list.

---

## Clip 4 — Intercept → modify → forward

**Surface: TUI or web UI.**

1. Recording on. Press **`i`** (intercept) to arm interception.
2. In the traffic terminal the stream pauses on the next request (it's held).
3. The held request shows in the inspector — edit a header or the path (benign).
4. Press the **forward/resume** key (shown in the footer) to release it; the
   (modified) request goes through and its response appears.
5. Disarm intercept. ~30s. Stop.

(The footer always lists the live hotkeys: `i intercept  e edit  r replay  n compose`.)

---

## Clip 5 — Scope & filtering

**Surface: web UI or TUI.**

1. Recording on. Open the **Scope** panel (sidebar) — show the single in-scope host.
2. Use the top **filter / tabs** (All · HTTP · JSON · Document · …) to filter the
   live list to just JSON responses, then back to All. ~15–20s. Stop.

---

## Clip 6 — Driving aitm from a fresh Claude session (MCP)  ★

Record a brand-new Claude Code session using aitm's MCP tools to inspect and
tamper with traffic — your questions and Claude's actions on screen.

**Note:** this uses MCP-over-stdio, which also binds the proxy, so first run
`stop.sh` to free the web-UI core. Keep `traffic.sh` running (it points at the
same proxy port).

1. Register aitm as an MCP server for Claude (once):
   ```
   claude mcp add aitm -- /Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/target/release/aitm --config /Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/demo-site/kit/kit-mcp-config.yaml
   ```
2. Start `traffic.sh` so there's live traffic to inspect.
3. Open a **fresh Claude Code session**, start recording that window.
4. Ask it things like (it drives aitm's MCP tools — `flow.list`, `flow.detail`,
   `request.send`, `flow.replay`, `flow.intercept`):
   - "List the most recent requests the proxy has captured."
   - "Show the response body of the last `/api/products.json` request."
   - "Replay that request but add the query parameter `limit=2`, and show me the new response."
   - "Intercept the next request, change its `User-Agent` header, and forward it."
5. The clip shows your prompt → Claude calling the aitm tool → the result. ~40–60s. Stop.
6. When done: `claude mcp remove aitm`, then `stop.sh`.

---

## Files in this kit
- `start.sh` / `stop.sh` — bring the scenario up / down.
- `traffic.sh` — the continuous benign request stream.
- `kit-config.yaml` — proxy + web UI + bus (web/TUI/app surfaces).
- `kit-mcp-config.yaml` — MCP-over-stdio (Clip 6).
- `../www/` — the benign sample site.

Ports: proxy 18080, obscura 18081, web UI 18082, bus 18090, sample site 19000.
