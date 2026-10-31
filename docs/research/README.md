# aitmproxy — Research

This folder holds the reference research gathered while defining **aitmproxy**
(AI-in-the-middle proxy), a Rust-based security-testing platform.

> **Provenance:** The documents here are AI-generated research summaries produced
> by subagents reading public project sources (READMEs, official docs, wikis) on
> 2026-10-26. They are starting-point syntheses, not authoritative specs. Verify
> specific API/crate details against upstream before relying on them in code.

## Index

| Doc | Reference | What it covers |
|-----|-----------|----------------|
| [01-mitmproxy.md](01-mitmproxy.md) | mitmproxy | Core/addon architecture, event hooks, flow model, TLS MITM |
| [02-nuclei.md](02-nuclei.md) | nuclei | Declarative template engine, matchers/extractors, workflows |
| [03-rust-proxy-stack.md](03-rust-proxy-stack.md) | RustProxy, obscura, hudsucker | Rust proxy references + best-practice crate stack |
| [04-playwright-cua.md](04-playwright-cua.md) | Playwright, trycua/cua | Headless-browser control + computer-use-agent driver |
| [05-synthesis.md](05-synthesis.md) | — | Combined design takeaways for aitmproxy |
| [06-obscura-embedding.md](06-obscura-embedding.md) | obscura | Embedding obscura as aitmproxy's browser engine: embeddability, CDP surface, MITM/CA gap |
| [07-ca-install.md](07-ca-install.md) | mkcert, mitmproxy, Burp, OS trust-store tools | Exporting/installing/uninstalling/checking the root CA on macOS, Linux, Windows: exact commands, exit codes, idempotency, SHA-256 vs SHA-1 keys |
| [07-rhai-embedding.md](07-rhai-embedding.md) | Rhai | Embedding Rhai (M3): compile/call_fn, type marshalling, sandbox limits, the sync/async host-fn bridge, hot-reload |
| [08-l4-packet-rust.md](08-l4-packet-rust.md) | pnet, pcap, socket2/nix, etherparse, scapy, boofuzz | Raw-L4 / packet capture + injection in Rust for M5: crate comparison, per-OS privilege model (`CAP_NET_RAW`, `/dev/bpf*`), macOS/Linux limits, how scapy/boofuzz separate crafting from sending and bound rate |
| [09-l4-inpath-interception.md](09-l4-inpath-interception.md) | NFQUEUE/libnetfilter_queue, `nfq`, TPROXY, pf divert, Network Extension, Suricata, NetfilterQueue, WinDivert | In-path / transparent L4 packet interception for M5 (park, mutate, forward or drop a live packet): Linux NFQUEUE verdict + payload-mangle model, `nfq` crate versions and `unsafe` placement, TPROXY vs NFQUEUE, why macOS has no userspace packet-mangle path (pf rejects `divert-to`, Network Extension filters only allow/drop/delay), privilege per OS (`CAP_NET_ADMIN`), held-packet lifecycle and drop defaults, kernel rule as first scope boundary |
| [10-linux-packaging.md](10-linux-packaging.md) | obscura@aitm-v1 Linux assets | Linux obscura payload shape (single self-contained binary) + authoritative `DT_NEEDED` → the `.deb`/`.rpm` deps (`libc6, libgcc-s1` / `glibc, libgcc`); symlink discovery across `/usr/bin`→`/usr/lib/aitmproxy` |
| [10-macos-network-extension.md](10-macos-network-extension.md) | `NETransparentProxyProvider`, `NEPacketTunnelProvider`, `NEFilterDataProvider`, mitmproxy_rs macOS redirector, Proxyman Network Extension, SystemExtensions, Developer ID signing | macOS Network/System Extension capture path for L4 Phase 2: provider comparison (transparent proxy is the system-wide, byte-mutating, flow-level choice; no raw-packet mutate on macOS), NE entitlement is self-service (`-systemextension` values, two App IDs and Developer ID profiles, `system-extension.install`), sysex packaging/activation/two-prompt approval, what `build.sh`/`notarize-dmg.sh` must add (entitlements, embedded profiles, sysex-first signing), extension-to-core handoff (per-flow Unix sockets vs XPC vs loopback) against the `ProtocolModule` seam, field risks |
| [08-chatgpt-apps-sdk.md](08-chatgpt-apps-sdk.md) | OpenAI plugins/Apps SDK docs, MCP Apps (SEP-1865), Claude MCP Apps + Claude Code docs | Making aitm's MCP server render rich UI in ChatGPT and clean output in Claude, plus the dual-target plugin format: exact `_meta` keys and placement (`ui.resourceUri`/`openai/outputTemplate`, CSP, domain, invocation strings), `text/html;profile=mcp-app` vs legacy `text/html+skybridge`, `window.openai` and the MCP Apps bridge, result `structuredContent`/size limits, ChatGPT dev-mode/Secure MCP Tunnel/submission flow (streamable HTTP required; aitm is stdio-only today), which Claude surfaces render UI (not Claude Code; Claude Code feeds its model `structuredContent` over `content`), `_meta` extensibility evidence, and Claude Code `plugin.json`/`marketplace.json`/`.mcp.json` schemas with OpenAI's Agent Plugins differences |
| [11-protocol-descriptor-ui-current-state.md](11-protocol-descriptor-ui-current-state.md) | aitmproxy source (TUI, web, macOS, core, seam, bus) | Survey for the protocol-descriptor-driven UI milestone: where each UI hard-codes per-protocol presentation (kind branch census, L4/WS/scanner code, row models, inspector dispatch, gates), the finding that `flow-kinds.json` is unconsumed prose, the core's closed `Flow` enum and L4-owned store, the bus and capability model (`tools/list`, `initialize.role`, `Command::sensitivity`, role-blind gating), existing seams to copy, and pre-existing bugs the milestone must not inherit |
| [12-macos-observe-only-lane.md](12-macos-observe-only-lane.md) | `NETransparentProxyProvider` declined-flow metadata, `NEFilterDataProvider`/`NEFilterReport`, Little Snitch, LuLu, Proxyman, mitmproxy local capture, aitmproxy macOS provider + core ingress | Observe-only lane for the macOS Apps page (every app's connections without claiming out-of-scope flows): (a) metadata-only `FlowSeen` from the transparent proxy (exact NE fields and availability macros read from the SDK headers, no bytes/duration/close, audit-token resolution, `handleNewFlow` backpressure), (b) an `NEFilterDataProvider` in the same sysex (bytes via `NEFilterReport`, ICMP, `filterFlowIdentifier`, both A1 profiles already allow `content-filter-provider-systemextension`, third consent prompt, field risks), (c) claim-and-relay-all (why it breaks fail-open and today's ingress); the tree finding that source-app identity is dropped at `ingress.rs`, `flow.list` has no per-row agent gating; comparison table and open experiments |
| [MEMORY.md](MEMORY.md) | — | Project memory: durable facts and decisions |

## Reference projects

- mitmproxy — https://github.com/mitmproxy/mitmproxy (+ addon examples: https://docs.mitmproxy.org/stable/addons/examples/)
- nuclei — https://github.com/projectdiscovery/nuclei
- RustProxy — https://github.com/BarisSenel/RustProxy
- obscura — https://github.com/h4ckf0r0day/obscura
- Playwright — https://github.com/microsoft/playwright
- cua — https://github.com/trycua/cua
