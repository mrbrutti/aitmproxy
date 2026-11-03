# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

One product with three operator surfaces, each in its platform's own design language: a native macOS app (`apps/mac`, SwiftUI, macOS 26+), a web UI (`apps/web`, Solid), and a terminal UI (`crates/aitm-tui`, ratatui). All three are clients of one command bus, exactly as the MCP agent is.

## Users

- Matt, a security professional running an authorized penetration test: one operator, often with a long scan running in the background while doing other work, glancing back between tasks. (Confirmed 2026-11-02.)
- The same operator supervising an AI agent that drives the tool over MCP: scans the agent started appear in the same views; the operator checks what the agent is doing and can stop it. Both situations matter equally. (Confirmed 2026-11-02.)

## Product Purpose

aitmproxy is a Rust intercepting-proxy platform for authorized security testing: a thin pluggable core (mitmproxy-style) plus a declarative vulnerability check and reproduction engine (nuclei-style), an embedded headless browser with a computer-use driver, and an MCP interface so an AI can drive the whole tool. HTTP/S and WebSocket first, with raw L4 packet and stream lanes. Success is an operator (or an agent under the operator's eye) finding and proving real issues on an in-scope target, with every action visible and every number on screen a value the core returned.

## Positioning

Every surface and the AI agent are equal clients of one command bus; nothing a human can do is hidden from the agent and nothing the agent does is hidden from the human (agent-originated actions are marked in teal). ~31,000 req/s throughput on the proxy path is Matt's real measured number. No competitor offers a proxy, a scanner, a browser driver and an MCP agent surface on one core.

## Operating Context

- The Scan page (Profiles / Jobs / Site map / Issues) is where a scan is started from a profile, watched as a job, and triaged. A job runs minutes to hours against in-scope origins; the engine runs at most two jobs at once and one per origin.
- Facts on screen come from the bus (`scan.list`, `scan.status`, `scan.cancel`, `scan.start`); push lines are triggers, never values. Values never go blank; a failed read keeps the last values and says so inline.
- Live proof is the rule: the real app, a real core and real traffic (`aitm-testtarget-serve --latency-ms N`). No fixture, snapshot or sample-data evidence for UI.
- Design truth lives in `docs/design/operator-ui-foundation.md` and `docs/design/tokens.json` (palette, type, spacing, motion tokens shared by the three surfaces); names live in `docs/design/GLOSSARY.md`.

## Capabilities and Constraints

- Scanner v2 (shipped v0.5.13): job states queued / running / cancelling / done / cancelled / failed; phases crawling / passive / auditing / reporting; counters for probes (with a budget), points, checks (with errors and samples), crawl, issues by severity and confidence; a stopped reason; lanes HTTP / WebSocket / L4 packet / L4 stream.
- Constraint: no bus verb or engine change for UI work unless specified; the UI degrades when a field is missing.
- Constraint: hue on data, not chrome (foundation principle 3): method, status, severity and syntax carry colour; the accent touches the active tab, focus ring, selection tint and product mark; the armed-intercept bar is the one saturated fill. Flat monochrome icons; editorial, typography-forward restraint.
- Constraint: Apple's controls and system styles on macOS; custom chrome only where the system has nothing, with a comment saying why.
- Terminology: see `docs/design/GLOSSARY.md` (Job, Profile, Target, Phase, Probe, Point, Check, Issue, Severity, Confidence, Lane; Start Scan, Cancel Scan, Scan Again).

## Brand Commitments

- Name `aitmproxy`, product mark `›•‹` (two chevrons facing a dot) in the accent, wordmark in the UI face at 500.
- Palette and type from `docs/design/tokens.json`: blue accent, amber intercept, teal agent, severity pairs; UI face (SF Pro / Inter / system) and data face (SF Mono / JetBrains Mono); six-step type scale; 4 pt grid. (Matt, 2026-11-02: "colours matching our palette".)
- Finish bar for the Jobs view redesign (Matt, 2026-11-02): Linear, Raycast, Xcode / Instruments, and the category (Burp Suite Pro, Proxyman). Direction: committed, not restrained, inside the palette; native controls stay native.

## Evidence on Hand

- Real-app frames of the current Jobs view: `docs/design/evidence/jobs-view-2026-11-02/` (twelve states; AX dump).
- Engine facts from live runs: a `standard` job on the test target at 400 ms latency sends ~2 probes/s against a 2,000 budget while scheduling ~6,500 checks; `light-http` runs several minutes; a dead target ends `done` + `stopped_reason: errors` with check-error samples naming "Connection refused".
- Research and specs under `docs/research/` and `docs/superpowers/specs/`. No testimonials, customers or pricing exist; none may be invented.

## Product Principles

1. Bus truth only: every number is a value the core returned; derived values are named as derived.
2. Degrade honestly: a missing field, a lost bus or a frozen core is said in words with the age of what is shown; nothing is silently dropped or left looking live.
3. The human and the agent share the controls, visibly.
4. Dense, monospaced data; quiet, system-font chrome; colour does a job or is absent.
5. Proof on the real thing: a change is done when the real app with a real core shows it.

## Accessibility & Inclusion

Keyboard-only and VoiceOver parity with the pointer on every surface; meaning never by colour alone; text ≥ 11 pt; token pairs ≥ 4.5:1 in both appearances; Reduce Motion keeps opacity and drops travel.
