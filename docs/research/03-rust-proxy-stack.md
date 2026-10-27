# Rust proxy references + best-practice stack

Sources: github.com/BarisSenel/RustProxy, github.com/h4ckf0r0day/obscura,
github.com/omjadas/hudsucker (+ docs.rs/hudsucker), hatoo "Building a
mitmproxy-like tool in Rust".

## 1. BarisSenel/RustProxy

- **What/scope:** A reverse SOCKS5 tunneling tool. Lets a device behind a
  firewall/NAT expose its internet as a SOCKS5 proxy via a public relay. Includes
  a web dashboard and an Android client. Small (~4 commits, 7 stars), MIT.
- **Crates:** `tokio` (full), `dashmap`, `socket2`, `clap`, `inquire`,
  `serde`/`serde_json`, `qrcode`, `anyhow`, `log`/`env_logger`, `colored`,
  `lazy_static`; Android-only `jni` + `android_logger`. **No TLS crate at all.**
- **Architecture:** Plain `tokio` TCP. A control port (agents/clients connect) +
  an API/dashboard port. Source split into `tunnel.rs`, `tunnel_common.rs`,
  `socks5.rs`, `udp.rs`, `cache.rs`, `security.rs`. Multiplexes data streams back
  through the reverse control connection; raw bidirectional byte copying.
- **Interception/MITM:** **None.** Transport tunnel, not an intercepting proxy.
- **Usefulness:** Toy-to-small tier. Reference only for SOCKS5 handshake parsing,
  UDP-associate, and a tokio reverse-tunnel/relay pattern. Not a TLS-MITM
  reference.

## 2. h4ckf0r0day/obscura

- **What/scope:** Not a proxy — an ambitious open-source **headless browser
  engine in Rust** for AI agents/scraping: embeds V8, implements Chrome DevTools
  Protocol (CDP), ships an MCP server. Large/active (~1,576 commits, Apache-2.0,
  multi-crate workspace). CLI: `fetch`, `scrape`, `serve` (CDP), `mcp`.
- **Crates/structure:** Workspace: `obscura-browser`, `obscura-cdp`,
  `obscura-dom`, `obscura-js`, `obscura-net`, `obscura-render`, `obscura-ssrf`,
  `obscura-cli`, `obscura-mcp`. Embedded V8, `rustls` (render builds),
  `wreq`/BoringSSL (stealth builds). Uses `deny.toml` (cargo-deny).
- **Architecture:** Multi-worker pool with a load balancer (503 when no worker
  ready; crashed workers restart). Networking in `obscura-net`.
- **Interception/MITM:** No MITM proxy, no CA/cert management. Interception is
  **CDP-level** (`Fetch.continueRequest/fulfillRequest/failRequest`) over the
  browser's *own* requests — the Playwright/Puppeteer model. Blocks private-IP
  fetches by default (SSRF guard in `obscura-ssrf`).
- **Usefulness:** Genuinely usable, well-structured — but a reference for a
  **browser engine / CDP interception / stealth fingerprinting / SSRF defenses**,
  not a classic intercepting HTTP/S proxy. Relevant for workspace layout,
  worker-pool design, rustls usage, SSRF hardening.

## 3. hudsucker — the actual MITM-proxy model

Neither repo above is a direct MITM-proxy reference. The de-facto Rust reference
is **hudsucker** (intercepting HTTP/S + WS proxy library). Mirror its dependency
choices.

## 2025/2026 best-practice stack (async intercepting HTTP/S + WS + raw TCP)

- **Async runtime:** `tokio` (full) — universal.
- **HTTP:** `hyper` 1.x + `http` 1.x + `http-body-util` + `hyper-util`. Hyper 1.x
  gives raw control over upgrades (CONNECT, WS) that a high-level client won't.
- **TLS:** `rustls` via `tokio-rustls` (pure Rust, enable `tls12`),
  `hyper-rustls` for upstream. Use `native-tls`/`openssl` only if you need
  platform trust stores or OpenSSL-specific behavior.
- **MITM cert generation:** `rcgen` (0.14) for a per-host leaf cert signed by your
  own CA, `x509-parser` to read SNI/upstream certs, and a cache (`moka`) so each
  host cert is minted once. Standard pattern: generate+install a root CA, then
  forge leaf certs on the fly after CONNECT.
- **WebSocket:** `tokio-tungstenite` (0.28) — intercept after the HTTP Upgrade.
- **Raw TCP / passthrough:** `tokio::io::copy_bidirectional` for tunneled/
  non-MITM traffic (and hosts you choose not to intercept).
- **L4 / packet capture (only if below-socket/transparent capture is needed):**
  `pnet` or `pcap`, or on Linux a TPROXY/nfqueue approach. Tradeoff: far more
  OS-specific and complex than an explicit/CONNECT proxy — avoid unless you truly
  need transparent interception or raw packet crafting (scapy-style).

## Tradeoffs

- **rustls vs native-tls:** rustls is simpler to build and the modern default but
  doesn't use the OS trust store and historically lagged on some legacy cert
  quirks. Stealth/anti-fingerprint work (like obscura) pushes people to
  BoringSSL/`wreq` to match Chrome's TLS ClientHello (JA3/JA4).
- **Build vs reuse:** building on hudsucker directly (or forking it) saves weeks
  vs assembling hyper+rustls+rcgen by hand; rolling your own is worth it only for
  unusual protocol control (HTTP/2 multiplexing correlation, custom TCP). For
  WS+TCP+HTTP in one proxy, hyper 1.x's upgrade handling is the linchpin.
