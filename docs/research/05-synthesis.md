# Synthesis — design inputs for aitmproxy

This pulls the four research docs together against aitmproxy's stated goals. These
are **candidate directions and open questions**, not decisions. Decisions are made
during brainstorming and recorded in the design document.

## The product in one line

A Rust, high-performance, memory-safe intercepting proxy platform for authorized
security testing: a thin pluggable core (mitmproxy-style) + a declarative
vulnerability check/reproduction engine (nuclei-style) + an embedded headless
browser with a computer-use-agent driver (Playwright/CUA-style) + an MCP interface
so an AI can drive 100% of the tool. HTTP/S and WebSocket first, with a path to
raw L4 packet crafting (scapy-style).

## Where each reference lands

| Requirement | Primary reference | Candidate approach |
|-------------|-------------------|--------------------|
| Pluggable core + many UIs | mitmproxy | Thin core emits typed events + flow store; every feature is a plugin; TUI/web/MCP are separate frontends over one core crate |
| Fast, memory-safe proxy | hudsucker, Rust stack | tokio + hyper 1.x + rustls/tokio-rustls + rcgen + moka cert cache + tokio-tungstenite |
| Declarative, reproducible checks | nuclei | Declarative template (id/info/requests/matchers/extractors) with a first-class flow/orchestration layer; proxy-capture → template |
| Headless browser | Playwright, obscura, chromiumoxide | chromiumoxide (CDP) in-process; browser's upstream = aitmproxy; trust CA via `Security.setIgnoreCertificateErrors` |
| CUA driver for AI-scripted browser | trycua/cua | Either reuse `cua-sdk`, or a thin CDP-backed MCP driver exposing navigate/click/type/screenshot/eval |
| AI control of everything | mitmproxy commands + MCP | Expose plugin-registered commands as MCP tools; MCP is "just another frontend" over the core |
| Raw L4 / custom packets | scapy, pnet/pcap | Separate below-socket capability (pnet/pcap, TPROXY/nfqueue); OS-specific, keep out of the v1 happy path |

## Architectural spine (the recurring pattern)

Every reference converges on the same shape, which is the strongest signal for our
design:

1. **Thin core, everything-is-a-plugin.** mitmproxy makes even its own UIs and
   interception addons. aitmproxy's core should only: accept connections, run
   sans-IO protocol state machines, hold a flow store, and emit typed events to an
   ordered plugin chain with halt/short-circuit semantics.
2. **sans-IO protocol logic separated from async I/O.** Pure state machines
   (testable, synchronous) under a tokio driver layer. Matches mitmproxy's modern
   core and is idiomatic in Rust.
3. **One Flow model** (HTTP / WS / TCP / UDP / DNS) with uniform
   intercept / resume / kill / backup; interception modeled as a pausable future.
4. **Frontends are clients of the core**, not part of it: TUI, web, headless dump,
   and **MCP**. The MCP interface controls the tool by invoking the same
   plugin-registered commands a human would.
5. **Declarative checks are plugins too.** The nuclei-style engine is a plugin
   that consumes flows, issues requests (via the proxy's own client), drives the
   browser, matches/extracts, and chains steps — with a real orchestration layer
   instead of a bolted-on DSL.

## Open questions to resolve in brainstorming

- **Build vs fork hudsucker** for the proxy core (saves weeks vs. maximum control
  over HTTP/2 correlation and custom TCP).
- **Plugin language/boundary:** native Rust trait objects? WASM plugins? an
  embedded scripting language (Lua/Rhai/Starlark)? a declarative YAML engine? —
  likely several, with the declarative engine as the first-class one.
- **Browser path:** in-process chromiumoxide (lean) vs. full CUA sandboxes
  (desktop/native-app control, multi-OS VMs, heavier).
- **L4 scope for v1:** is raw packet crafting a day-one requirement or a later
  capability behind a separate subsystem?
- **MCP surface:** which commands are exposed, and how the AI-driven loop
  (observe → reason → act → reproduce) is structured.
- **TLS fidelity:** rustls simplicity vs. BoringSSL/`wreq` for Chrome-accurate
  ClientHello (JA3/JA4) when evading fingerprint-based defenses matters.

## Reproducibility & safety mechanisms to adopt early

- Template **validation + signing** (nuclei signs templates because free-form
  checks are a supply-chain risk).
- **Proxy-capture → reproducible template** so an observed request/vuln becomes a
  versionable artifact.
- Rate limiting, per-host back-off, concurrency caps from the start.
- SSRF/private-IP guards (obscura) given an embedded browser + AI driver.
- CA generation/trust UX: the single biggest adoption-friction point in mitmproxy.
