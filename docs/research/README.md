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
| [MEMORY.md](MEMORY.md) | — | Project memory: durable facts and decisions |

## Reference projects

- mitmproxy — https://github.com/mitmproxy/mitmproxy (+ addon examples: https://docs.mitmproxy.org/stable/addons/examples/)
- nuclei — https://github.com/projectdiscovery/nuclei
- RustProxy — https://github.com/BarisSenel/RustProxy
- obscura — https://github.com/h4ckf0r0day/obscura
- Playwright — https://github.com/microsoft/playwright
- cua — https://github.com/trycua/cua
