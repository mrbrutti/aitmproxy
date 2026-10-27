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

## Environment constraints (this machine, 2026-10-26)

- The Claude sandbox **blocks creating `.git`** in the working dir and **blocks
  GitHub API/network**. Git init, remote creation, and push must be run by the
  user in their own terminal. See `docs/research/../../README`-level notes / the
  session for the exact commands.
- `gh` has the `mrbrutti` account configured but keyring login was failing.

## Status

- [x] Research on reference tools (mitmproxy, nuclei, Rust proxy stack,
  Playwright/CUA) — see this folder.
- [ ] Private repo `mrbrutti/aitmproxy` created + pushed (blocked on user's
  terminal).
- [ ] Product brainstorming / definition.
- [ ] Design document.
