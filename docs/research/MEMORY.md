# Project memory — aitmproxy

Durable facts and decisions. Keep this current as the project evolves. (This
mirrors, in-repo, the memory the assistant also keeps in its own store, per the
user's request to keep research docs and memory inside `docs/research`.)

## What this is

- **aitmproxy** = "AI-in-the-middle proxy": a Rust intercepting-proxy **platform**
  for authorized security testing. Owner: GitHub `mrbrutti` (private repo
  `mrbrutti/aitmproxy`). Local path: `/Users/matt/Security/aitmproxy`.

## Product requirements (from the user, 2026-10-26)

1. **Rust** — performance and memory-safety are first-class; must be fast and scale.
2. **Plugins + automation** like mitmproxy, plus **nuclei-style** declarative
   vulnerability reproduction/automation.
3. **Headless browser** support (connect to / embed).
4. **Platform with a pluggable core**; terminal UI like mitmproxy is one of many
   interfaces.
5. **MCP** as a pluggable interface that can control **100%** of the tool (AI-driven).
6. The MCP embeds a **CUA-style driver** (ref cua.ai) to script vulnerabilities in
   the embedded headless browser.
7. Start with **HTTP/S**, extend to **WebSockets**, then **raw L4 packet** MITM for
   data-plane testing (scapy-style custom crafted packets).

## Working decisions / conventions

- Research docs and project memory live in `docs/research/`.
- Design documents live in `docs/superpowers/specs/` (brainstorming workflow).
- Nothing is built until the design document is approved (brainstorming gate).
- Development workflow (7 engines, 7 stages) is defined in `docs/superpowers/WORKFLOW.md`;
  engines live in `.claude/agents/`; `CLAUDE.md` points every session at it (2026-10-27).

## Environment constraints (this machine, 2026-10-26)

- The Claude **Bash sandbox blocks creating `.git`** in the working dir and
  **blocks GitHub network**, even with bypass mode / `dangerouslyDisableSandbox`.
  Run all git/gh operations through the **Terminal panel** (`run_in_terminal`),
  which runs in the user's real login shell outside the sandbox.
- SSH to GitHub fails (`Permission denied (publickey)`) — the local SSH key is
  not tied to `mrbrutti`. Use an **HTTPS remote** + `gh auth setup-git` so pushes
  authenticate with the `mrbrutti` gh token. (`gh` API itself works: it created
  the repo.) The keyring "login failing" warning is cosmetic; the token is valid.

## Web UI (`aitm web`, F15 — 2026-10-27)

- Build the UI once: `cd apps/web && npm ci && npm run build` (writes the git-ignored
  `apps/web/dist`), then rebuild `aitm` — `crates/aitm/build.rs` embeds `dist/`; without it
  `/` serves a "not built" page.
- Run `aitm web [--listen 127.0.0.1:8082] [--token …] [--no-open]`; it prints
  `web UI: http://127.0.0.1:8082/#t=<token>` — the UI takes the token from `#t=` and sends it
  as the first `/bus` WebSocket message (`{"token":"…"}`, as LoopbackTcp). Env: `AITM_WEB_LISTEN`,
  `AITM_WEB_TOKEN`; a non-loopback bind is refused until TLS lands (`AITM_WEB_INSECURE_BIND=1` overrides).

## Status

- [x] Research on reference tools (mitmproxy, nuclei, Rust proxy stack,
  Playwright/CUA) — see this folder.
- [x] Private repo `mrbrutti/aitmproxy` created + pushed —
  https://github.com/mrbrutti/aitmproxy (branch `main`).
- [x] Development workflow, engines, and templates (2026-10-27).
- [ ] Product brainstorming / definition.
- [ ] Design document.
