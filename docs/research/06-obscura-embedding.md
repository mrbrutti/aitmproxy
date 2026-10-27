# Embedding obscura as aitmproxy's browser engine

> **Provenance:** AI-generated research summary produced by the Researcher
> engine reading public obscura sources (obscura.sh, docs.obscura.sh,
> github.com/h4ckf0r0day/obscura) and the aitmproxy tree on **2026-10-27**.
> Starting-point synthesis, not an authoritative spec. The obscura library API
> and its TLS behaviour must be verified against the actual crate source /
> `cargo doc` before any M2 code depends on them. One docs page
> (`sitemap.md`) carried an injected instruction to call a query endpoint; it
> was ignored and all docs were treated as data.

## 1. Question

Can aitmproxy replace its external-Chrome + chromiumoxide browser with an
**embedded obscura engine** behind the **same CDP/MCP driver**, keeping
proxy-routing-for-MITM and CA trust, and what does that take?

## 2. Short answer

Partly. obscura **is** embeddable in-process as the Rust `obscura` crate
(`Browser`/`Page`/`Element`), and it **also** runs as a CDP WebSocket server
(`obscura serve`) that chromiumoxide can attach to via `Browser::connect` —
so the driver barely changes. It implements the CDP surface aitmproxy uses
(navigate, input, screenshot, evaluate, DOM) and takes an upstream `--proxy`.
**The blocking gap is MITM trust:** obscura does its own HTTP(S) fetching
(reqwest/BoringSSL), not a Chromium network stack, and documents **no** way to
trust a custom CA or ignore cert errors — `Security.setIgnoreCertificateErrors`
has no equivalent. Without a patch, HTTPS through aitmproxy's forged certs will
fail. Keep the Chrome driver as fallback.

## 3. Findings

All sources read 2026-10-27. Marketing/vendor claims are flagged; nothing below
was reproduced or benchmarked.

### 3.1 Embeddable or service? — both

- obscura is an Apache-2.0, Rust, multi-crate workspace: a **headless browser
  engine embedding V8** (via `deno_core`), implementing CDP, with an MCP
  server. Crates: `obscura-cli`, `obscura-cdp`, `obscura-browser`, `obscura-js`,
  `obscura-dom`, `obscura-net`, `obscura-mcp`, `obscura-render`, and **`obscura`
  — the embeddable library API** (`Browser`, `Page`, `Element`, `CookieStore`).
  (architecture-overview.md; github README.)
- **In-process embedding is real.** The "Use as a Rust library" guide adds
  `obscura = { git = "https://github.com/h4ckf0r0day/obscura" }` (git dep, not
  on crates.io; pin a tag such as `v0.1.7`), plus `tokio` and `anyhow`, and
  describes "embedding the engine … with no CDP round-trips." The engine "runs
  in-process"; all pages share **one V8 isolate** (CPU-heavy JS on one page
  delays others). (use-as-a-rust-library.md; architecture-overview.md.)
- **Library API** (from docs, not yet verified in source):
  `Browser::builder().stealth(bool).proxy(url).user_agent(ua).storage_dir(dir).build()`
  or `Browser::new()`; `browser.new_page()`; `Page::goto(url)`, `content()`
  (rendered HTML), `url()`, `evaluate(js) -> serde_json::Value`,
  `query_selector(css)`, `wait_for_selector`, `settle(max_ms)`, interception
  hooks (`on_request`/`on_response`, `enable_interception`),
  `add_preload_script(js)`; `Element::text()`, `attribute()`, **`click()`**.
  **No `type`/`screenshot` method is documented on the library `Page`/`Element`.**
  (use-as-a-rust-library.md.)
- **Service forms:** CLI `fetch`/`scrape`/`serve`/`mcp`; `obscura serve
  --port 9222` is a CDP WebSocket server (`ws://host:port`); Docker image
  `h4ckf0r0day/obscura` (distroless). Release archives ship `obscura` +
  `obscura-worker` binaries. (github README; cli-reference.)

### 3.2 CDP surface — most of what we use exists; one domain does not

From the github README's domain list and the Puppeteer/Playwright connect guide:

- **Present:** `Page.navigate`, `getFrameTree`, `lifecycleEvents`,
  **`captureScreenshot`** (viewport/clip/full-page), `printToPDF`,
  start/stopScreencast; **`Runtime.evaluate`**, `callFunctionOn`,
  `getProperties`, `addBinding`; **`DOM.getDocument`/`querySelector`/
  `getOuterHTML`**; `Network.*`, `Fetch.continueRequest/fulfillRequest/
  failRequest`, `Target.*`, `Storage.*`, `IO.*`; **`Input.dispatchMouseEvent`
  / `dispatchKeyEvent`** (no `dispatchClick`/`insertText`, but the
  Playwright-over-CDP guide confirms higher-level `click`/`type`/`fill` work).
- **Absent / breaking:** **No `Security` domain** — there is **no
  `Security.setIgnoreCertificateErrors`**. aitmproxy's
  `driver.rs` calls exactly this today (line 76).
- Known CDP limits: live DOM mutation events not published (re-request the
  document), limited shadow/frame traversal, one shared V8 isolate, raster-only
  PDFs. (connect-puppeteer-or-playwright.md.)

### 3.3 Upstream proxy + CA trust — the MITM problem

- **Proxy: yes, but engine-level, not browser-flag.** `--proxy` (HTTP or
  SOCKS5; HTTP creds inline `http://user:pass@host:port`) applies to
  `fetch`/`serve`/`mcp`/scrape workers; the library builder has `.proxy(url)`;
  env `OBSCURA_PROXY` covers scrape workers. There is no per-context proxy and
  (crucially) obscura has **no Chromium network stack**: requests are made by
  `obscura-net/client.rs` using **reqwest by default**, or **`wreq`/BoringSSL in
  `--stealth` builds** (Chrome-like TLS fingerprint). The proxy is applied at
  that HTTP-client layer. (configure-stealth-and-proxies.md;
  architecture-overview.md; environment-variables.md.)
- **CA trust / ignore-cert-errors: not documented anywhere.** No
  `ignore-cert-errors`, no custom-CA path, no "disable TLS verify", no CDP
  `Security` domain. The only trust-related statement: **stealth builds "bundle
  webpki roots instead of relying on the system store"** — so even installing
  aitmproxy's CA in the OS store would not be trusted by a stealth build.
  `OPENSSL_NO_VENDOR` only chooses which OpenSSL compiles, not cert handling.
  (configure-stealth-and-proxies.md; environment-variables.md.)
- **Consequence for MITM:** aitmproxy forges per-host leaf certs signed by its
  own CA and relies on the browser trusting them (today via
  `Security.setIgnoreCertificateErrors(true)`). obscura's reqwest/BoringSSL
  client will perform normal TLS verification against those forged certs and
  **reject them**, breaking HTTPS interception. This is a hard blocker for both
  integration paths and is **not** solvable with any documented flag/env.
- **SSRF interaction:** obscura ships its own SSRF guard
  (`OBSCURA_ALLOW_PRIVATE_NETWORK` / `--allow-private-network`, **off by
  default**, blocks loopback/RFC1918/link-local/metadata, re-checks DNS at
  connect time). aitmproxy's proxy listens on loopback, and aitmproxy already
  uses `--proxy-bypass-list=<-loopback>` so Chrome routes loopback through it.
  Whether obscura's SSRF guard blocks a **loopback upstream proxy** (vs. only
  the fetch target) is unverified; `--allow-private-network` may be required,
  which widens SSRF exposure and partly overlaps aitmproxy's own guard in
  `ssrf.rs`. (environment-variables.md.)

### 3.4 Licensing, maturity, platforms, build, perf

- **License:** Apache-2.0, "no feature gating, ever"; a hosted "Obscura Cloud"
  is waitlist-only. (github README; obscura.sh.)
- **Maturity:** large/active (README ~1.5k commits at an earlier read; a search
  hit cites ~15.5k stars and a v0.2.1 release dated August — **unverified**,
  secondary source). Library API published as a **git dependency**, versions
  like `v0.1.7` — pre-1.0, API churn likely.
- **Platforms:** prebuilt binaries for Linux x86_64/ARM64, **macOS Apple
  Silicon + Intel**, Windows (manual zip), NixOS. Linux release builds target
  Ubuntu 22.04 / glibc 2.35+. Covers aitmproxy's macOS+Linux need.
- **Build from source:** Rust 1.75+; **V8 compiled from source** (~5 min first
  build, then cached). `--stealth` additionally compiles **BoringSSL** and
  needs **CMake, Clang, libclang/LLVM**. Features: `render`, `stealth`, or
  `--no-default-features`. Binary ~70 MiB. (build-from-source.md; github README.)
- **Perf/memory claims (vendor, no methodology/hardware/versions):** memory
  **30 MB vs 200+ MB** Chrome (≈6–7×, **not** the "10×" in the brief); startup
  "Instant" (the "<50ms" figure is on obscura.sh marketing, not the README);
  page load 85 ms vs ~500 ms; micro-benchmarks 51/84/78 ms for static/XHR/dynamic
  pages. Full suite said to live in a separate repo; **not independently
  verified.** (github README; obscura.sh.)

### 3.5 What the current aitmproxy driver needs (baseline)

From `crates/aitm-browser/src/{driver.rs,commands.rs,ssrf.rs}`: launches
Chromium with `--proxy-server={proxy_addr}` and `--proxy-bypass-list=<-loopback>`
(driver.rs:29-34); spawns a `Handler` task polling CDP events (64-72); opens one
page; calls `Security.setIgnoreCertificateErrors(true)` when
`config.ignore_cert_errors` (75-78); implements `BrowserDriver`:
`navigate` (goto + wait_for_navigation, status always `None` — comes from the
proxy flow), `click` (selector or point), `type_text` (find → click → type_str),
`screenshot` (PNG), `eval` (→ `Value`), `get_dom` (`content()`). The six
`browser.*` commands wrap these; `browser.navigate` runs aitmproxy's own SSRF +
scope/rate guard first (commands.rs:120-132).

## 4. Candidate directions (for the Architect — not decisions)

### Candidate A — Point the existing CDP driver at `obscura serve` (least code change)

chromiumoxide 0.9 has **`Browser::connect(url) -> (Browser, Handler)`** and
`connect_with_config` (docs.rs, read 2026-10-27) — the same tuple the driver
already destructures. So:

- Spawn `obscura serve --port <p> --proxy http://127.0.0.1:<proxy>` (likely
  `--allow-private-network` for the loopback proxy) as a **bundled child
  process** instead of Chrome; then `Browser::connect("ws://127.0.0.1:<p>")`.
- Drop the `SetIgnoreCertificateErrorsParams` call (no `Security` domain).
- `navigate`/`click`/`type`/`screenshot`/`eval`/`get_dom` map unchanged — the
  Playwright-over-CDP guide confirms click/type/screenshot/evaluate/content work.
- **Trade-offs:** smallest diff; keeps the whole CDP command surface. But it is
  **not in-process** (a child process, though shipped with aitmproxy — so
  "self-contained distribution," not "embedded engine"), proxy is set per-server
  not per-session, and **the CA-trust blocker (3.3) remains**.

### Candidate B — Link the `obscura` crate and drive it in-process (truest to the M2 goal)

- `obscura = { git = ... , tag = "…" }`; rewrite `ChromeDriver` to an
  `ObscuraDriver` over `Browser::builder().proxy(...).build()` + `new_page()`:
  `navigate`→`goto`, `get_dom`→`content`, `eval`→`evaluate`, `click`→
  `query_selector().click()`.
- **Trade-offs:** lowest memory, truly self-contained, no child process, best
  fit for "embedded engine." But a **larger rewrite** (obscura's API is typed,
  not CDP), and the documented library `Page`/`Element` API **lacks `type` and
  `screenshot`** — two of aitmproxy's six commands — so either those live only
  on the CDP path, or they need the preload-script/`evaluate` workaround, or the
  crate exposes them undocumented (must check source). Same CA-trust blocker.

Both candidates **must first solve CA trust** (3.3). That almost certainly means
a **patch/fork of `obscura-net`** to accept aitmproxy's CA or a
"danger: no-verify" mode (reqwest/rustls `dangerous()` or a custom
`ServerCertVerifier`; BoringSSL equivalent for stealth). Since a source patch
looks unavoidable regardless, embedding the crate (B) and patching its net layer
is the cleaner end-state; A is the fastest way to a running spike.

### Candidate C — Hybrid: ship obscura, keep the Chrome driver as fallback

Keep `ChromeDriver` behind the `BrowserDriver` trait and add `ObscuraDriver`
(A or B), selected by config. Rationale: obscura is pre-1.0, its rendering
"may differ from Chromium" on long-tail CSS / some Web APIs / media, and the
MITM/cert path is unproven — a fallback de-risks M2 and lets vuln repros that
need real Chromium fidelity still run. Strongly worth considering given the
`BrowserDriver` trait already makes the engine swappable.

## 5. Open questions (for Matt / the Architect before the M2 spec)

1. **CA trust — the gate.** Will obscura accept a `obscura-net` patch to trust
   aitmproxy's CA / disable verification? Does maintaining a fork fit M2's
   budget? Without this, MITM of HTTPS does not work. **Unverified from docs.**
2. **Loopback proxy vs SSRF guard.** Does obscura's SSRF guard block a loopback
   **upstream proxy**, or only fetch targets? Is `--allow-private-network`
   required, and does it then defeat part of aitmproxy's own SSRF guard? Needs a
   spike.
3. **`screenshot` + `type` in the library API.** Are they on the real `obscura`
   crate (source), or CDP-only? Decides A vs B feasibility for all six commands.
4. **Stealth vs render build.** Stealth (BoringSSL, Chrome TLS fingerprint,
   bundled webpki roots, tracker blocking) changes TLS and cert behaviour and
   adds CMake/Clang build weight. Which build does aitmproxy want, and does
   stealth's bundled-roots posture make CA trust harder?
5. **HTTP status + response bodies.** obscura caps retained bodies (>2 MiB
   dropped by default); aitmproxy relies on the proxy flow for status/bodies
   anyway — confirm this still holds when obscura (not Chrome) is the client.
6. **Build/distribution weight.** V8-from-source (~5 min, cached) and a ~70 MiB
   binary / git dependency in aitmproxy's build + CI — acceptable?
7. **Maturity/version pinning.** Pre-1.0 git dependency; which tag, and what is
   the churn risk over M2's lifetime? Star/release figures are unverified
   secondary data.

## 6. Sources

- obscura.sh — product/marketing page. Read 2026-10-27.
- docs.obscura.sh — `sitemap.md`, `guides/use-as-a-rust-library.md`,
  `guides/configure-stealth-and-proxies.md`,
  `quickstart/connect-puppeteer-or-playwright.md`,
  `contributing/architecture-overview.md`,
  `reference/environment-variables.md`. Read 2026-10-27.
- github.com/h4ckf0r0day/obscura — README. Read 2026-10-27.
- docs.rs/chromiumoxide/0.9.0 — `Browser::connect` / `connect_with_config`.
  Read 2026-10-27.
- aitmproxy tree: `crates/aitm-browser/src/{driver.rs,commands.rs,ssrf.rs}`,
  `docs/research/03-rust-proxy-stack.md`, `docs/research/04-playwright-cua.md`.
  Read 2026-10-27.
- Secondary/unverified: DEV.to, deepwiki, and blog summaries (star count,
  v0.2.1 release date, crate breakdown) surfaced via web search 2026-10-27.
