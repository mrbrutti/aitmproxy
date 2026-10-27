# Playwright & CUA — headless browser + computer-use-agent reference

Sources: github.com/microsoft/playwright, playwright-rs (deepwiki
padamson/playwright-rust), crates.io/crates/chromiumoxide, github.com/trycua/cua,
cua.ai/docs, deepwiki.com/trycua/cua.

## 1. Playwright architecture & controlling it from Rust

- **Layered model:** (a) Client API (your test language), (b) **Playwright
  driver** — a bundled, self-contained Node.js executable (`playwright-core` + a
  pinned Node runtime), (c) patched browser builds. The driver speaks each
  engine's native protocol; clients never touch the browser directly.
- **Browser control:** Chromium via **CDP (Chrome DevTools Protocol / CDP+)**;
  Firefox and WebKit via Playwright's **own patched protocols** baked into custom
  browser builds (why Playwright ships its own browser binaries).
- **Bindings model:** All non-JS bindings (Python, Java, .NET — and community
  `playwright-rs`) are **thin clients of one wire protocol**. They launch
  `playwright run-driver` and exchange **JSON-RPC over stdio pipes or a
  WebSocket**. The protocol schema ships as `protocol.yml`. A sync-over-async
  bridge is needed per language.
- **Rust host options (concrete):**
  1. **Playwright driver over stdio/WebSocket** — port the JSON-RPC client (see
     `playwright-rs`: `protocol/`, `server/`, a `Transport` trait abstracting
     Pipe vs WebSocket). Heavy (ships Node + browsers) but cross-engine parity.
     `playwright-rs` is early/incomplete.
  2. **CDP directly via a Rust crate — recommended for a Chromium-only proxy
     tool.** `chromiumoxide` (v0.9.x, async/tokio, full generated CDP types,
     headless by default) is the mature choice; `headless_chrome` is simpler but
     less maintained; `chaser-oxide` is a stealth fork. CDP-only means
     Chromium/Chrome/Edge, not Firefox/WebKit.
  3. Skip Playwright entirely and drive Chromium over CDP yourself — lowest
     footprint for a tool that needs one engine.

## 2. Proxy integration with a headless browser

- **Upstream proxy:** launch flag `--proxy-server=http://user:pass@host:port`
  (chromiumoxide: `BrowserConfig::builder().arg(...)`). Routes all browser
  traffic through aitmproxy.
- **Trusting the proxy CA / cert errors:** `--ignore-certificate-errors` launch
  flag, OR the runtime CDP command **`Security.setIgnoreCertificateErrors({ignore:true})`**
  (chromiumoxide exposes the Security domain via `page.execute`) — runtime
  version is cleaner, toggleable, more reliable. Supplementary flags when a
  wildcard cert still throws `net::ERR_INSECURE_RESPONSE`: `--ignore-ssl-errors-yes`,
  `--allow-running-insecure-content`, `--ignore-certificate-errors-spki-list`.
  For Docker add `--no-sandbox --disable-dev-shm-usage`. (Alternative to blanket
  cert-ignore: install the proxy CA into the browser's cert store — more faithful
  but heavier.)

## 3. CUA (trycua/cua) — what it is & architecture

- **What:** open-source framework to "give AI agents computers they can use" —
  cross-OS sandboxes + drivers + benchmarks for computer-use. MIT, ~22 packages.
- **Three layers:** SDKs → Infrastructure → Execution Environments.
  - **Execution envs / sandboxes:** macOS & Linux **VMs on Apple Silicon via
    `Lume`** (Apple Virtualization.framework), `Lumier` (Docker-compatible wrapper),
    **gVisor containers** (`cua sb create ubuntu`), Windows VMs, and cloud
    (AWS/GCP/Modal). **"Cua Spaces"** is a Tauri desktop app exposing these.
  - **In-sandbox agent:** images ship **`cua-spacesd` (port 3211)** exposing
    processes, files, screenshots, input, low-latency A/V over **gRPC + gRPC-Web**
    plus `/media`, `/mcp`, `/health`. Sandboxes need **no agent inside** — you
    drive them from your own harness.
  - **`cua-daemon`:** host runtime (socket + loopback, `cua.daemon.v1`), hosts the
    SDK out-of-process so CLI/MCP/app share the same Spaces.
  - **Cua Driver (`cua-driver`):** background OS automation (macOS/Windows/Linux)
    using Accessibility + Screen Recording + Input Synthesis, **without stealing
    focus**. Exposes these as **MCP tools** (`cua-driver mcp`); on macOS proxies to
    a signed `CuaDriver.app` daemon to retain TCC permission grants.
- **Agent loop (illustrative `ComputerAgent`):** classic **screenshot → VLM
  reasoning → action execution** loop, provider loops for Anthropic/OpenAI/
  UITARS/Gemini, callbacks for trajectory recording. The current SDK deliberately
  has **no agent layer** — you supply the reasoning loop.

## 4. CUA "driver style" — scripting abstraction & primitives

- Core interface: a **`Computer`/`Sandbox` object exposing namespaced
  primitives**, identical across Linux container / Windows VM / macOS VM:
  - `sb.shell.run` (exec), `sb.screen` / `screenshot`, `sb.mouse.click(x,y)`,
    `sb.keyboard.type(...)`, `sb.files` (move/read), `sb.mobile.gesture`.
  - CLI mirrors: `cua sb create/exec/screenshot`.
- These five verbs (**shell, screenshot, mouse.click, keyboard.type,
  mobile.gesture**) are the stable surface an AI agent calls. Coordinates are
  pixel-based; screenshots are PNG.

## 5. Embedding a CUA-style driver in a Rust host with an MCP interface

- **CUA already ships a Rust SDK** — directly usable:
  - `cargo add cua-sdk` (full SDK), `cua-spacesd-client` (typed Space client:
    screenshot/click/type/shell/files surface), `cua-proto` (generated types +
    `.proto` contracts).
  - Connect from Rust: `cua_sdk::Cua::embedded().spacesd(url, token)`. gRPC under
    the hood, so any gRPC language works.
- **Two architectural paths for aitmproxy's "CUA driver so an AI can script the
  browser":**
  1. **Reuse CUA:** run a CUA sandbox (Lume VM or gVisor container) with a browser
     inside, drive it from Rust via `cua-sdk`, and re-export the primitives
     (screenshot/click/type/navigate) as **your own MCP tools**. CUA's own MCP
     server is a reference for the tool schema.
  2. **Thin Playwright/CDP-backed MCP driver (lighter, browser-focused):** drive
     headless Chromium via `chromiumoxide` through aitmproxy, and expose a small
     MCP tool set — `navigate`, `screenshot`, `click(selector|x,y)`, `type`,
     `eval`, `get_dom` — for AI-scripted vuln reproduction. Keeps the whole loop
     in-process in Rust, avoids VM overhead, and the proxy/cert handling from
     section 2 drops straight in. CUA's primitive naming is a good template for
     the MCP tool surface.
- **Recommendation signal:** for a **browser-only** security tool, option 5.2
  (chromiumoxide + CDP + your own MCP tools, proxy via `--proxy-server`, trust via
  `Security.setIgnoreCertificateErrors`) is the lean path; reach for CUA (5.1)
  only if you need **full-desktop/native-app** control or multi-OS VMs beyond the
  browser.
