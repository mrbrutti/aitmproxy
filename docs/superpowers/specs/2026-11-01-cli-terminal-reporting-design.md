# CLI terminal reporting design

**Status:** approved (2026-11-01 by the orchestrator under Matt's autonomous-approve mode; Architect's calls 1–15 stand; amendments A–D from the approval are folded into D1, D10 and D14 below). Matt may veto any call; a veto is a spec amendment, not a plan change. Panel amendments 2026-11-01 (security S1–S4, quality Q3, spec Sp2/Sp4/Sp5/Sp10; AC-W1-31/32 added) folded in. Panel pass 2 amendments 2026-11-01 (security S5/S6, spec Sp14/Sp17; D4 only) folded in. Live dry-run finding D1 2026-11-01 (`Reporter::quiesce` in D4/D7, AC-W1-33) folded in. Live dry-run findings D2–D4 2026-11-01 (AC-W1-23 re-pinned to the card's `Log:` row and the D13 `wait_ready` row; T7/D10 browser version word) folded in. Live dry-run findings D5/D6 2026-11-01 (AC-W1-30 thread clause) folded in. E2 2026-11-01: the quiesce hook sits after the system-proxy restore and before the browser reap (D4/D7). Panel pass 3 amendments 2026-11-01 (S7/S9, Sp21–Sp23; T7, D4/D7, AC-W1-30/32/33) folded in.
**Research inputs:** `docs/research/24-cli-terminal-reporting.md` (R1–R25, F1–F39, directions 4.A–4.E), `docs/design/tokens.json`, `docs/design/operator-ui-foundation.md` §1–§2, `docs/research/MEMORY.md`, memories `aitmproxy-ui-icon-editorial-rule`, `aitmproxy-operator-first-run-hygiene`, `aitmproxy-web-stdin-eof-exit`, `aitmproxy-cli-first-run-fixes`.
**Prior specs touched:** `2026-10-30-aitm-web-startup-hygiene-design.md` (the token-free `web::log_listening` pin stays), `2026-10-29-operator-token-ux-design.md` (the `operator-token` confirmation line stays).

## Intent

`aitm` today reports like a web server: 98 ANSI-coloured INFO lines on stdout before every command, `--version` that boots the host, mints a root-CA key and exits 1, raw JSON for every result, errors that say what but not why or how to fix it, a 189-line usage dump as the only help (research R1–R25). Matt's bar: "the tool needs a massive improvement from a UI/UX PoV", "on brand", "fully animated and with in-place UI that does not just spit things like a web server", and "much better output … even with the help and other areas". This spec rethinks the command line as a product: what a new operator sees in the first ten seconds, the ready state and its next steps (CA trust, Scope, system proxy), every error, help that teaches by example, results humans can read, and one written terminal design system that every later command inherits. It introduces one small reusable reporting layer, the crate `crates/aitm-term`, that every human-facing line of `aitm`, `aitm web` and `aitm tui` startup goes through, and splits delivery into three waves (three PRs, three plans).

## Goals

- G1. Three channels, never mixed: results on stdout; every human line (header, phases, card, warnings, errors, help) on stderr; diagnostics in a log file or behind `-v`/`RUST_LOG` on stderr. Tracing never writes to stdout in any mode.
- G2. Startup is a live checklist drawn in place on a TTY, one plain line per phase when piped, and ends in a ready card that says what is listening and what to do next.
- G3. `aitm --version` and `aitm --help` answer from a pre-boot fast path: nothing created, nothing loaded, exit 0.
- G4. Every error is a panel: what happened, the likely cause, the exact fix command on its own line, and where the log is.
- G5. One vocabulary with the TUI, web and mac surfaces (`· CA trusted`, the `●` pill, lane words, `NOTHING_DECRYPTED_ADVICE` verbatim) and one glyph set with an ASCII fallback.
- G6. A written terminal design system (glyphs, colour roles, spacing, motion, width, text rules) in this document that waves 2 and 3 and every later command inherit.
- G7. Help as a product (wave 2) and results as humans want them (wave 3), each with `--json`/plain forms for machines.
- G8. No consumer in the tree breaks: every string another script, test, app or formula reads is listed here with its disposition.

## Non-goals

- The ratatui TUI's own screens, widgets and status bar (`crates/aitm-tui`), beyond the terminal handover in §D11.
- The web UI (`apps/web`) and the mac app (`apps/mac`), beyond the one dev-script consumer update in §D13.
- The bus/MCP protocol, command schemas, verbs, or any wire format. `--json` (wave 3) prints exactly what the bus returns.
- One-shot verbs reaching a running core (research R14): decided and specified in `2026-11-01-cli-oneshot-live-core-design.md`, which also re-pins AC-W1-6, AC-W1-30 and AC-W3-7 (see Open question 1).
- The `aitm web` stdin-EOF exit (memory `aitmproxy-web-stdin-eof-exit`): a lifecycle decision, not a rendering one; this spec only states how the ready card behaves around it (Open questions).
- `aitm web --no-open` doing something (R24), the confirmation prompt's wording (R25, already a good what/fix shape), and quieting benign WARNs in `aitm_core::proxy` (memory `operator-first-run-hygiene` item 1): all out of scope here.
- Windows. Shipped targets are macOS and Linux.

## Anti-goals

- Emoji soup, box-drawing frames around everything, truecolor gradients, a logo splash. Hue only on data and state glyphs; chrome stays monochrome.
- A scrolling web-server log as the default view. INFO lines belong in the log file.
- A second vocabulary: no "CA not trusted", "daemon", "backend"; the words come from the TUI/web/mac surfaces or the core.
- A token (bus, web bridge, operator) in any tracing sink, phase line, warning, error or log file. Only the `aitm web` card's URL rows carry the bridge token, on purpose, on stderr.
- Animation that hides information: nothing animates on completion, no line is cleared without its content surviving in a collapsed line or the card, and a non-TTY stream never receives cursor movement.
- Breaking a consumer: `tests/e2e/cli/cli-startup.sh`, the python e2e harness, the mac Core Log, the Homebrew formula, the web live scripts and the integration tests all keep working (§D13).
- A new dependency in wave 1.

## Constraints

- **Brand.** Monochrome glyphs, editorial restraint, typography-forward hierarchy, hue only on data and state (memory `aitmproxy-ui-icon-editorial-rule`). The emoji glyphs in `tokens.json` `icon.glyph.tui` (`✋`, `🔓`, `🔒`) are never printed by the CLI (research F37). Wordmark `aitmproxy`, mark `›•‹` printed as text, version from `CARGO_PKG_VERSION`.
- **Dependencies.** Zero new crates in wave 1 **(Orchestrator's call, direction B1)**: `crossterm 0.29` (already in `Cargo.lock` via `aitm-tui`; `aitm-term` declares it with default features plus nothing new) and `unicode-width 0.2` (in the lock). No `indicatif`, `console`, `anstyle`, `anstream`, `clap`, `miette`, `comfy-table`, `tracing-appender`. A later wave that wants a table or pager crate says so in its own plan with the lock delta.
- **Performance.** `aitm --version` < 100 ms wall on Matt's machine and creates no file; the reporter adds < 5 ms to startup in any mode; no busy loop (the ticker sleeps on a channel timeout and only while a phase is live past its first-draw delay); one extra OS thread while phases run, none after `finish()`.
- **Platform.** macOS and Linux; `TERM=linux` and non-UTF-8 locales get ASCII glyphs.
- **Security.** The workspace forbids `unsafe` (`unsafe_code = "forbid"`); crossterm hides the ioctls. The log file is opened `0600`, `O_APPEND`, `O_CREAT`, never follows a symlink into another user's file (`O_NOFOLLOW` on open), lives under the per-user aitmproxy directory. No token reaches any sink, line or file (AC-W1-22). The pre-boot paths read no config and touch no key material.
- **Shared-file discipline.** Another session (L4 privilege) is editing `crates/aitm/src/main.rs` and `crates/aitm/src/wire.rs` now. Wave 1 makes **no edit to `wire.rs`**, and its edits to `main.rs` are additive and small: one `Reporter` handle created in `main`, `phase()`/`done()` calls around the existing steps, the error branch at the top of `main` routed to one `render_error`, the `init_tracing` call replaced by `startup::init_tracing`, the `aitm web` `println!` replaced by `reporter.card(...)`, the one-shot `eprintln!` replaced by `reporter.error(...)`. All new code lives in `crates/aitm-term` and the new module `crates/aitm/src/startup.rs`. `addr_in_use_error` keeps its signature and its `Display` text (§D6).
- **Proof is live, never fixtures** (Matt's hard rule). Every acceptance criterion is provable on the real binary through the Terminal panel: a `script`-recorded real-terminal session (cursor-up sequences and the final screen read from the captured bytes), the same binary piped to a file (zero ESC bytes), a real holder on the port for the port-in-use panel, `/usr/bin/time aitm --version` in a fresh `HOME`, the log file's existence, mode and content, and `tests/e2e/cli/cli-startup.sh` green. Unit tests drive the renderer through its `io::Write` seam with a fake `Caps`; that is allowed because it tests the renderer, not the product's evidence.

## Waves and the acceptance-criteria map

| Wave | PR | Scope | ACs |
|---|---|---|---|
| W1 | this PR | `aitm-term` crate; tracing plumbing (log file, `UiLayer`, `-v/-vv/-q/--color`, `RUST_LOG` raw stream); pre-boot `--version`/`--help`; phases + ready card for bare `aitm`, `aitm web`, `aitm tui`; every `main.rs` and one-shot error as a panel; exit codes; consumer pins; no-bypass test | AC-W1-1 … AC-W1-33 |
| W2 | next | help as a product: grouped `aitm --help`, `aitm <group>`, `aitm <group> <verb> --help`, did-you-mean, dotted names never in prose, one usage form per mode, plain when piped; a schema-only command registry | AC-W2-1 … AC-W2-10 |
| W3 | after | results as humans want them: table / card / list / scalar-or-bytes renderer, `--json` everywhere, status words, `ca export` PEM, `ca status`/`proxy status` cards, tables, `$PAGER`, honest one-shot change lines | AC-W3-1 … AC-W3-12 |

Each wave is its own plan; the W2 and W3 sections below fix the design so the W1 crate API does not have to change for them.

## The terminal design system

Every later command inherits this section. It is the CLI's half of `docs/design/operator-ui-foundation.md` §2.

### T1. Glyphs

| Role | Rich (UTF-8 TTY) | ASCII | Width class (F39) | Used for |
|---|---|---|---|---|
| ready / listening | `●` | `*` | Ambiguous (line start only) | the pill, a live listener row |
| pending | `○` | `o` | Ambiguous (line start only) | a phase not yet started |
| done | `✓` | `+` | Neutral | a completed phase |
| failed | `✕` | `x` | Neutral | a failed phase, the error panel headline |
| warning | `!` | `!` | ASCII | a WARN event folded into the view **(Architect's call: `!`, gh's choice, present in every font)** |
| fix pointer | `▸` | `>` | Neutral | the one copy-safe fix command line |
| separator | `·` | `-` | Ambiguous | between facts on one line |
| rule | `─` | `-` | Ambiguous | the card rule, 60 columns max |
| ellipsis | `…` | `...` | Ambiguous | truncation |
| spinner | `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` | `- \ | /` | Neutral | a running phase, TTY only |
| mark | `›•‹` | (omitted) | mixed | the header line only |

Ambiguous-width glyphs appear only at a line start or between words, never inside an aligned column, so a CJK-ambiguous-wide terminal cannot break alignment. ASCII is chosen when `AITM_TERM=ascii|plain`, `TERM=linux`, or none of `LC_ALL`/`LC_CTYPE`/`LANG` ends in `UTF-8`/`UTF8` (case-insensitive). When the ASCII set is selected the renderer also substitutes `·` with `-` and `…` with `...` on every line it writes, because the pill and the phase summaries are composed with the rich separator; a path or hostname containing those two characters is rewritten too (spec amendment 2026-11-01, panel Sp5). A non-TTY stream still uses the locale's set (the mac Core Log and log files are UTF-8).

### T2. Colour roles

Only the 16 ANSI colours plus bold, dim and reverse; no truecolor, no 256-colour assumptions. Roles map to `tokens.json` `tui` names.

| Role | ANSI | Token | On dark terminals | On light terminals | Used for |
|---|---|---|---|---|---|
| accent | blue (`SetForegroundColor(Blue)`) | `accent.base.tui` | reads as the brand blue | reads as the brand blue | the mark, the header wordmark |
| success | green | `state.success.tui` | | | `●` listening, `✓` done |
| warning | yellow | `state.warning.tui` | | darker terminals' yellow reads fine; light themes render ANSI yellow as olive, still legible | `!` warnings, `○`, the `CA` row value `untrusted` (the pill text itself is plain; the `CA` row value carries the colour; spec amendment 2026-11-01, panel Sp4) |
| danger | red | `state.danger.tui` | | | `✕`, the error headline glyph |
| dim | the terminal's dim attribute (never dark-grey `90`, which vanishes on light themes) | `text.tertiary` | | | descriptions, the `Log` row, paths, `(SSRF-filtered)` |
| bold | bold | weight | | | the wordmark, a card label the eye should land on |
| plain | none | `text.primary` | | | everything else |

Rules: colour goes on glyphs and state words, never on whole lines or chrome; never bright variants (`90–97`) because light themes lose them; never a background colour except the terminal's own reverse for nothing in wave 1. `NO_COLOR` set and non-empty disables colour; `CLICOLOR_FORCE` non-empty forces it when `NO_COLOR` is unset (anstream/uv precedence); `--color=always|never|auto` beats both **(Orchestrator's call)**. Forcing applies only where the stream is a TTY whose `TERM` is set and not `dumb` (there it overrides `NO_COLOR`): on a dumb TTY, under `CI`, on a pipe or a file — on every stream that does not animate (D2 rule 5, plan C6) — the plain path renders and never emits an escape byte, whatever `Caps.color` says, so `CLICOLOR_FORCE` and `--color=always` never put an escape byte into a pipe or a file (D4; the mac Core Log and the e2e logs read those streams) and never paint a dumb terminal, which cannot render SGR (spec amendment 2026-11-01, live run D7).

### T3. Spacing and layout

- Two-space indent for every line under a header or headline.
- Label column: 14 characters (`System proxy` is the longest label at 12, plus 2), values start at column 17 after the indent. Labels are `Proxy`, `Browser`, `Bus`, `Web UI`, `Operator`, `CA`, `Scope`, `System proxy`, `Detections`, `Log`, `Config`.
- One blank line between blocks (header → checklist → card; headline → body → fix → log in an error panel).
- Rules are 60 columns or the terminal width minus 2, whichever is smaller; a card never draws a rule when the terminal is narrower than 40 columns.
- A next-step command sits on its own line under its row, indented to the value column, prefixed by the fix pointer.

### T4. Motion

- Feedback only (`tokens.json` `motion`): a spinner runs only while a phase is running; nothing animates on completion; a done phase is drawn once.
- Nothing is drawn for a phase that finishes in under **100 ms** (cargo's delayed first draw; the 49-script load takes about 9 ms, so one-shot commands normally print nothing on stderr) **(Orchestrator's call)**.
- Frames at **100 ms** (within the 80–120 ms band) **(Architect's call on the exact figure)**.
- Reduced motion = plain: `AITM_TERM=plain`, `--color=never` with `CI` set, or any non-TTY stream prints the plain line per phase.
- The live region is at most the running phases plus the one most recent collapsed line; completed phases scroll into the normal stream as ordinary lines, so the in-place region stays small and resize-safe.

### T5. Width

- Width is measured on stderr's own file descriptor with `crossterm::terminal::size()` **only after** `std::io::stderr().is_terminal()` is true (crossterm opens `/dev/tty` first and would return a width for a pipe, research F28 rule 7). 80 when unknown. `COLUMNS` is not read.
- Re-measured on each redraw tick (no SIGWINCH handler in wave 1; a resize shows on the next frame).
- Lines longer than the width are truncated with the ellipsis glyph, measured with `unicode-width`. A fix command line is **never** truncated or wrapped; if it is wider than the terminal it is printed whole and the terminal wraps it.
- Prose in an error panel wraps at the width to the 2-space indent.

### T6. Text

- Phase labels are lowercase clauses in progress form: `loading detections`, `checking CA trust`, `starting obscura`. Done summaries are lowercase clauses with the fact first: `49 detections ready`, `obscura probed 0.3.1`, `proxy listening 127.0.0.1:8080`.
- Error headlines we compose start lowercase and carry no trailing period (rustc's rule). Sentences the core already composes (`cannot start: …`, `Nothing is decrypted until a host is in Scope.`, anyhow context strings) are printed verbatim, never re-cased or re-punctuated.
- Card labels are capitalised words; state words are lowercase (`untrusted`, `off`, `ready`).
- Dotted wire names never appear in prose; `scope add`, not `scope.add` (W2 enforces it in the dispatcher's error strings; W1 does not touch `aitm-cli`).
- `$HOME` is shortened to `~` in phase lines and cards **(Architect's call)**; error panels print paths exactly as the core composed them (the port-in-use remedy keeps the full config path).
- Numbers are plain digits; durations are shown only in `-v` (`in 412 ms`).

### T7. Vocabulary (shared with the TUI, web and mac)

- Pill: `● aitmproxy · listening 127.0.0.1:8080 · CA trusted` exactly as `crates/aitm-tui/src/ui/bars.rs` composes it; `· intercept armed` / `· capture paused` suffixes when true.
- CA: `· CA trusted`, `· CA untrusted`; reduction over the store statuses: any store `trusted == yes` → trusted; else any `no` → untrusted; else **no word** (an unread state never renders as untrusted, TUI D17.5). Card row value: `trusted` / `untrusted`; row omitted when unread.
- Scope: `NOTHING_DECRYPTED_ADVICE` verbatim when Scope is empty; `n hosts in Scope` otherwise (`1 host in Scope`).
- System proxy, from `proxy.status.system_proxy.state` (`aitm_sysproxy::State`) **(Architect's call, aligned with the mac `SystemProxyRoute` cases `.thisCore`/`.off`/`.other`)**: `points_at_us` → `points at this proxy`; `other` → `points at <host>:<port>`; `off` → `off`; `needs_privilege` → `needs privilege`; `unsupported` → `unsupported on this platform`; `unknown` → `unknown`. Next step `▸ aitm proxy system set` for `off` and `other`; none otherwise.
- Bus: `stdio (MCP)`, `loopback 127.0.0.1:<port>`, `http <addr>`, `ready` (the `aitm web` card keeps its current word).
- Detections: `49 detections ready` (the bundled catalogue's count plus `--script` extras).
- Browser: `obscura probed <version>` on success, where `<version>` is the engine's `--version` text with its leading `obscura ` word stripped (matched case-insensitively, surrounding whitespace trimmed; a bare engine word or an empty text counts as no version, so the line is `obscura probed`) — the raw text is `obscura aitm-v1`, the line is `obscura probed aitm-v1`, never `obscura probed obscura aitm-v1` (amended 2026-11-01, dry-run D4; the matching clause added 2026-11-01, panel pass 3 Sp21); `embedded browser unavailable` on failure (the existing WARN message, kept so `cli-startup.sh` keeps matching).

## Before / after mock-ups

Exact bytes the operator sees, ANSI omitted for print (colour roles noted in brackets where they matter). `~` is `/Users/matt`. Version numbers are illustrative.

### M1. Bare `aitm`, first run, TTY (W1)

Before (0.5.10): 98 INFO lines on stdout (`2026-11-01T19:24:44.033789Z  INFO aitm_plugin_rhai::loader: loaded script script=check-command-injection path=/opt/homebrew/Cellar/aitm/0.5.10/libexec/share/aitm/scripts/active/check-command-injection.rhai hooks=[load]` × 49, `script loaded into the host` × 49), then `INFO aitm_core::proxy: proxy listening listen=127.0.0.1:8080 ssrf=…`, `INFO aitm_browser::obscura: obscura probed …`, `INFO aitm_browser::obscura: CDP endpoint is loopback-only and unauthenticated`, `INFO aitm: Nothing is decrypted until a host is in Scope.`, then silence.

After, while loading (frames redraw in place; shown mid-way):

```text
›•‹ aitmproxy 0.5.11

  ✓ config defaults · ~/Library/Application Support/aitmproxy/config.yaml not found
  ✓ 49 detections ready
  ✓ CA created · ~/Library/Application Support/aitmproxy/ca/ca.crt
  ⠹ starting obscura
```

After, ready (final screen):

```text
›•‹ aitmproxy 0.5.11

  ✓ config defaults · ~/Library/Application Support/aitmproxy/config.yaml not found
  ✓ 49 detections ready
  ✓ CA created · ~/Library/Application Support/aitmproxy/ca/ca.crt
  ✓ obscura probed 0.3.1
  ✓ proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081

● aitmproxy · listening 127.0.0.1:8080 · CA untrusted
  Bus           stdio (MCP)
  Scope         Nothing is decrypted until a host is in Scope.
                ▸ aitm scope add --host <host>
  CA            untrusted
                ▸ aitm ca install
  System proxy  off
                ▸ aitm proxy system set
  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log
```

Colour: mark and wordmark accent; `✓` success; `●` success; `untrusted` and `off` warning; the `Log` row dim; the three `▸` lines plain (copy-safe). The `CA created` line appears only on a first run; later runs show `✓ CA loaded · ~/…/ca/ca.crt`. When Scope is non-empty the `Scope` row reads `2 hosts in Scope` with no next step. When the CA is trusted the pill says `· CA trusted` and the `CA` row is omitted.

### M1p. Bare `aitm`, piped or `2>file` (W1)

```text
aitmproxy 0.5.11
config defaults · /Users/matt/Library/Application Support/aitmproxy/config.yaml not found
49 detections ready
CA created · /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt
obscura probed 0.3.1
proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081
Bus: stdio (MCP)
Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>
CA: untrusted · aitm ca install
System proxy: off · aitm proxy system set
Log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log
```

Zero ESC bytes, no cursor movement, no `~` shortening (a pipe may not be the operator's shell), one line per completed phase, the card as `Label: value · command` lines. `proxy listening` and `obscura probed` are present for `cli-startup.sh`.

### M2. Port in use (W1)

Before (0.5.10, after the 98 INFO lines):

```text
Error: cannot start: the proxy port 127.0.0.1:8080 is already in use.
It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.
Free it, or set `listen:` to another address in /Users/matt/Library/Application Support/aitmproxy/config.yaml.
Find the holder with:  lsof -nP -iTCP:8080 -sTCP:LISTEN
```

After, TTY:

```text
›•‹ aitmproxy 0.5.11

  ✓ config ~/Library/Application Support/aitmproxy/config.yaml
  ✓ 49 detections ready
  ✓ CA loaded · ~/Library/Application Support/aitmproxy/ca/ca.crt
  ✕ binding ports

✕ cannot start: the proxy port 127.0.0.1:8080 is already in use
  It is most likely held by another running `aitm`, the aitmproxy macOS app's
  embedded core, or another program.
  Free it, or set `listen:` to another address in
  /Users/matt/Library/Application Support/aitmproxy/config.yaml.

  ▸ lsof -nP -iTCP:8080 -sTCP:LISTEN

  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log
```

Exit 1. The headline glyph is danger; the headline text is the first sentence of the existing message minus its trailing period; the two prose sentences are the existing ones verbatim, wrapped; the `lsof` command is the existing one on its own line.

After, piped (`2>file` or the e2e merged log):

```text
aitmproxy 0.5.11
config /Users/matt/Library/Application Support/aitmproxy/config.yaml
49 detections ready
CA loaded · /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt
error: binding ports
error: cannot start: the proxy port 127.0.0.1:8080 is already in use
  It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.
  Free it, or set `listen:` to another address in /Users/matt/Library/Application Support/aitmproxy/config.yaml.
  fix: lsof -nP -iTCP:8080 -sTCP:LISTEN
  log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log
```

`already in use` and the port are present; `os error 48` is absent; `web UI (agent):` is absent.

### M3. `aitm --version` and `aitm --help` (W1 fast paths, W2 restyle)

Before: `aitm --version` → 98 INFO lines on stdout, `expected a command before flags, got `--version`` plus 189 usage lines on stderr, exit 1, and a root-CA key created on a fresh `HOME`.

After (W1), stdout, exit 0, nothing created:

```text
$ aitm --version
aitm 0.5.11
```

After (W1), `aitm --help` / `-h` / `help`, stdout, exit 0 — a static synopsis **(Architect's call; see D8 for why the registry's existing text cannot be printed without side effects)**:

```text
aitm 0.5.11 — intercepting proxy for authorized security testing

Usage:
  aitm                      run the proxy with the MCP agent transport
  aitm web [options]        run the proxy and the web operator UI
  aitm tui                  run the proxy and the terminal operator UI
  aitm <group> <verb> [--flag <value>]...
                            run one command and exit
  aitm operator-token generate [--force]

Groups:
  agent  browser  ca  capture  config  findings  flow  map  poc  proxy
  request  scan  scope  script  session  tls  ws

Options:
  --config <path>           config file (env AITM_CONFIG)
  --script <path>           load an extra Rhai script (repeatable)
  -v, -vv                   show INFO / DEBUG tracing on stderr
  -q                        errors only
  --color <auto|always|never>
  --version, -V             print the version and exit
  --help, -h                print this help

Learn more:
  aitm web --help           the web UI's options
  Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>
  Trust the CA:  aitm ca install
```

After (W2), `aitm --help` is grouped with every verb (19 groups, 91 verbs; `l4` appears when `l4.enabled`), two aligned columns, dim descriptions wrapped to width, an `Examples:` block and the `Learn more:` footer; `aitm scope` prints the `scope` group's help; `aitm scope add --help` prints the flags with types and defaults and one or two examples. Mock-up of a group page (W2):

```text
aitm scope — which hosts are decrypted

Usage:
  aitm scope <verb> [--flag <value>]...

Verbs:
  add --host <host>         Add a host, host:port or *.wildcard to Scope.
  remove --host <host>      Remove a host from Scope.
  list                      List the Scope entries.
  example                   Print an example Scope entry.

Examples:
  $ aitm scope add --host app.example.test
  $ aitm scope add --host '*.example.test'

Nothing is decrypted until a host is in Scope.
```

### M4. `aitm ca status` (W3)

Before: 24 lines of JSON after 98 INFO lines.

After (W3), TTY:

```text
● CA untrusted
  Certificate   ~/Library/Application Support/aitmproxy/ca/ca.crt
  SHA-256       5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE
  Platform      macos

  Store         Installed   Trusted
  user          absent      no
  system        absent      no

  ▸ aitm ca install

  macOS: presence from `security find-certificate`; trust from `security verify-cert` …
  the embedded browser (obscura) does not use the OS trust store; it trusts this CA through --ca-cert at launch
```

The headline uses the pill glyph and the CA word; `detail[]` lines are dim; `--json` prints today's object unchanged.

### M5. `aitm scope add` / `scope list` / `flow table` (W3)

Before: `scope add --host example.test` prints `example.test` (and the entry does not outlive the process, R14); `scope list` prints `[]`; `flow table` prints `{"flows": []}`.

After (W3):

```text
$ aitm scope add --host example.test
✓ example.test added to Scope · this one-shot proxy only; a running aitm does not see it
$ aitm scope list
  (Scope is empty)
  Nothing is decrypted until a host is in Scope.
  ▸ aitm scope add --host <host>
$ aitm flow table
  (no flows)
$ aitm flow table            # with rows, TTY, aligned and truncated to width
  #   method  status  host                  path                              size    time
  1   GET     200     app.example.test      /                                 1.2 kB  41 ms
  2   POST    302     app.example.test      /login                            318 B   88 ms
  3   GET     200     cdn.example.test      /assets/app.3f9c1e.js             92 kB   12 ms
```

Piped, `flow table` prints tab-separated rows without a header and without truncation (gh's rule); `--json` prints the bus object. The `✓` and the honest R14 clause go to stderr; stdout carries the bare result (`example.test`) as today, so scripts keep working.

### M6. `aitm web` ready card (W1)

```text
›•‹ aitmproxy 0.5.11

  ✓ config ~/Library/Application Support/aitmproxy/config.yaml
  ✓ 49 detections ready
  ✓ CA loaded · ~/Library/Application Support/aitmproxy/ca/ca.crt
  ✓ obscura probed 0.3.1
  ✓ proxy listening 127.0.0.1:8080 · browser proxy 127.0.0.1:8081
  ✓ web UI listening 127.0.0.1:8082

● aitmproxy · listening 127.0.0.1:8080 · CA trusted
  Web UI        http://127.0.0.1:8082/#t=3f2a…c91e
  Operator      http://127.0.0.1:8082/#t=7b10…04ad&expect=operator
  Proxy         127.0.0.1:8080
  Browser       127.0.0.1:8081  (SSRF-filtered)
  Bus           ready
  Scope         Nothing is decrypted until a host is in Scope.
                ▸ aitm scope add --host <host>
  System proxy  points at this proxy
  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log
```

The URL rows are printed whole (tokens shown shortened here only). The whole card is on **stderr**; stdout stays free for stdio MCP **(Architect's call; see D13 item 3 for the one consumer this moves)**. The `Operator` row appears only when `mcp.operator_token` is configured.

### M7. `aitm tui` pre-screen (W1)

```text
›•‹ aitmproxy 0.5.11

  ✓ config ~/Library/Application Support/aitmproxy/config.yaml
  ✓ 49 detections ready
  ✓ CA loaded · ~/Library/Application Support/aitmproxy/ca/ca.crt
  ⠼ starting obscura
```

When the last phase completes the reporter clears its lines (cursor up + clear per line) and returns the cursor to the header's column; ratatui then enters the alternate screen. No card is printed for `aitm tui` (its status bar is the card). On TUI exit the main screen shows the header line only.

## Design

### D1. Crate layout

- `crates/aitm-term/` (new, `aitm-term`, lib only): `caps.rs`, `style.rs`, `glyphs.rs`, `reporter.rs` (the renderer, ticker thread, live region), `card.rs`, `error.rs`, `tracing_layer.rs`, `text.rs` (width, truncate, wrap, `~` shortening), `lib.rs` re-exports. Dependencies: `crossterm 0.29` (default features), `unicode-width 0.2`, `tracing 0.1`, `tracing-subscriber 0.3` (`registry`, `std`; the `env-filter` feature is `aitm`'s), `anyhow 1`. Workspace member and `workspace.dependencies` entry.
- `crates/aitm/src/startup/` (new module, split into `mod.rs`, `args.rs`, `errors.rs`, `log.rs`, `card.rs` so parallel builders never share a file): everything that knows aitmproxy — `TermOpts` parsing, pre-boot dispatch, tracing composition and the log file, `StartupError`, `report_for`, `ReadyInputs → Card`, the CA/system-proxy word mapping. `main.rs` calls into it.
- `crates/aitm-core`: **no edit** (amendment B). The log directory is derived the way `config_file::default_config_path` already derives the config path, `aitm_core::CaConfig::default().audit_log.with_file_name("logs")`, so the file is `<aitm dir>/logs/aitm.log` with the same platform fallbacks.
- `crates/aitm-ca`: expose the store-status read the `ca.status` command already performs as a method the ready card can call (shape left to the builder) so the CA word cannot diverge between `ca status` and the card.
- `crates/aitm/src/tui.rs`: `init_tracing` is replaced by the shared composition; `TuiLog::File(path)` is returned for the toast (`embedded proxy · log: <path>`).

### D2. Capability detection (`aitm_term::Caps`)

```rust
pub enum ColorChoice { Auto, Always, Never }
pub enum TermMode { Rich, Ascii, Plain }          // AITM_TERM=rich|ascii|plain

pub struct Caps {
    pub tty: bool,       // the written stream is a terminal
    pub color: bool,
    pub unicode: bool,   // rich glyphs
    pub animate: bool,   // in-place drawing and the spinner
    pub width: u16,      // 80 when unknown
    pub ci: bool,
}

impl Caps {
    pub fn detect_stderr(color: ColorChoice) -> Caps;
    pub fn from_parts(stream_is_tty: bool, measured_width: Option<u16>,
                      color: ColorChoice, env: &dyn Fn(&str) -> Option<String>) -> Caps;
    pub fn plain() -> Caps;
}
```

Rules, in precedence order **(Orchestrator's call, with the `AITM_TERM` hatch as Architect's call)**:
1. `--color=never` → `color=false`; `--color=always` → `color=true`.
2. `AITM_TERM=plain` → `color=false, unicode=false, animate=false`; `ascii` → `unicode=false`; `rich` → `unicode=true` (animation still needs a TTY).
3. `NO_COLOR` non-empty → `color=false`; else `CLICOLOR_FORCE` non-empty → `color=true`.
4. Otherwise `color = tty && TERM set && TERM != dumb`.
5. `animate = tty && color-eligible-terminal (TERM set, not dumb) && CI unset && mode != Plain`. `CI` set → plain lines even on a TTY. `-v`/`-vv`/`RUST_LOG` active → `animate=false` (the raw stream and the live region never interleave; cargo-style collapse to lines) **(Architect's call)**. Rules 1 and 3 can set the `color` flag on a dumb TTY (`TERM=dumb CLICOLOR_FORCE=1`, `--color=always`), but never `animate`: animation needs a real, non-dumb TTY, and a stream that does not animate renders through the plain path (D4, plan C6), which never emits an escape byte. Colour forcing (`CLICOLOR_FORCE`, `--color=always`) therefore takes effect only on a TTY whose `TERM` is set and not `dumb`, where it overrides `NO_COLOR`; on a dumb TTY, under `CI`, or on a pipe the flag may read `true` but is inert — the operator sees plain lines with no SGR and no cursor movement. A dumb terminal cannot render SGR, so forcing colour onto it is not a behaviour worth building (orchestrator's call). The `Caps` unit tests pin the flag; the renderer tests pin the bytes (spec amendment 2026-11-01, live run D7; replaces the tester-F1 amendment's "painted plain lines" wording).
6. `unicode` per T1. `width` per T5. `detect_stderr` uses `std::io::IsTerminal` on stderr and `crossterm::terminal::size()` only when that is true.
7. `CLICOLOR_FORCE` and `--color=always` affect what is drawn only where the stream is a TTY whose `TERM` is set and not `dumb` (rule 5): a non-TTY stream, a dumb TTY and a `CI` run render through the plain path (D4, plan C6), which never emits an escape byte, whatever `color` says. `Caps.color` may read `true` for a pipe or a dumb TTY under those settings; it is set but inert there (the `Caps` unit tests pin the flag, the renderer tests pin the bytes; live run D7, 2026-11-01).

### D3. Style and glyphs

```rust
pub enum Role { Accent, Success, Warning, Danger, Dim, Bold, Plain }
pub fn paint(caps: &Caps, role: Role, text: &str) -> String;   // text unchanged when !caps.color

pub struct Glyphs { pub ready: &'static str, pub pending: &'static str, pub done: &'static str,
    pub failed: &'static str, pub warn: &'static str, pub fix: &'static str, pub sep: &'static str,
    pub rule: &'static str, pub ellipsis: &'static str, pub mark: &'static str,
    pub spinner: &'static [&'static str] }
pub static RICH: Glyphs;  pub static ASCII: Glyphs;
impl Glyphs { pub fn for_caps(caps: &Caps) -> &'static Glyphs; }
```

`paint` emits `crossterm::style` SGR sequences through `SetForegroundColor`/`SetAttribute` and always resets; it never uses `Stylize` on a stream (crossterm never tests for a TTY, F27).

### D4. Reporter and phases

```rust
pub enum Verbosity { Quiet, Normal, Verbose, Debug }

pub struct Reporter { /* Arc<Inner>: caps, glyphs, verbosity, channel to the render thread */ }
impl Clone for Reporter {}
pub struct Phase { /* id + Reporter clone; not Clone */ }

impl Reporter {
    pub fn new(caps: Caps, sink: Box<dyn std::io::Write + Send>, verbosity: Verbosity) -> Reporter;
    pub fn stderr(caps: Caps, verbosity: Verbosity) -> Reporter;
    pub fn header(&self, wordmark: &str, version: &str);        // "›•‹ aitmproxy 0.5.11"
    pub fn phase(&self, label: &str) -> Phase;                    // "loading detections"
    pub fn warn(&self, line: &str);                               // "! …" above the live region
    pub fn note(&self, line: &str);                               // a one-line success note outside any phase (`✓ <line>` rich, bare line plain);
                                                                  // the one message that keeps its glyph after `finish()` (used for the stdin-closed line)
    pub fn quiesce(&self);                                        // after an orderly exit: tracing events no longer reach the view; note/warn/error still print (D7)
    pub fn card(&self, card: &Card);
    pub fn error(&self, report: &ErrorReport);                    // stops the live region first
    pub fn finish(&self);                                         // stop the ticker, keep collapsed lines
    pub fn finish_and_clear(&self);                               // TUI handover: erase the live region
    pub fn events(&self) -> EventSender;                          // for UiLayer
}
impl Phase {
    pub fn progress(&self, done: u64, total: Option<u64>);        // "⠹ loading detections 12/49"
    pub fn done(self, summary: &str);                             // "✓ 49 detections ready"
    pub fn fail(self, what: &str);                                // "✕ binding ports"
}
impl Drop for Phase { /* an undropped-by-API phase ends as done(label) */ }
```

Behaviour:
- Every public call enqueues a message; one render thread (`std::thread`, named `aitm-term`) owns the sink and draws. It is started lazily on the first `phase()` and sleeps on `recv_timeout(100 ms)`; it ticks only while a phase is live and older than 100 ms. `finish()`, `error()` and `card()` block until the queue is drained, so `main` can exit right after. **(Architect's call: an OS thread, not a tokio task, because errors and pre-boot lines happen before the runtime exists and a blocked worker must not freeze the display.)**
- TTY (`animate`): the live region is redrawn with `MoveUp(n)`, `MoveToColumn(0)`, `Clear(CurrentLine)` per line, wrapped in `BeginSynchronizedUpdate`/`EndSynchronizedUpdate`; the cursor is hidden while a spinner runs and shown again by `finish`, `error`, and a `Drop` guard; `Ctrl-C` during startup restores the cursor through the same guard (the existing `shutdown_signal` path returns through `main`).
- Non-TTY or `animate=false`: `phase()` prints nothing; `done()`/`fail()` print one line (`<summary>` / `error: <what>`); `warn()` prints `warning: <line>`; `card()` prints `Label: value · command` lines; no ESC bytes ever.
- `Quiet`: phases, header and card are suppressed; `warn` and `error` still print.
- A phase that spawns an OS process for the report itself (`checking CA trust`, which shells out to the trust store) exists only in the serving modes (`Server`, `Web`, `Tui`); a one-shot `aitm <group> <verb>` and the pre-boot paths never add a process spawn (amendment A; AC-W1-30 keeps the one-shot within 5 ms of 0.5.10).
- A phase that fails is followed by the error panel from `main`; the panel is never printed twice (the `Phase::fail` line and the panel are distinct: the line names the step, the panel the cause).
- Every content string entering the renderer (header, phase label and summary, warning and event text and fields, card headline and values, error panel text, paths) is sanitized first: every control character (C0, DEL, C1), every Unicode bidi/format control (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) and the invisible format characters U+00AD, U+180E, U+200B, U+2060–U+2064, U+FEFF, U+FFF9–U+FFFB and the tag block U+E0000–U+E007F (U+200C/U+200D are kept for joiner-dependent scripts; the deprecated format controls U+206A–U+206F are left as-is in wave 1) becomes U+FFFD; `\n`/`\r`/`\t` become one space, and U+2028/U+2029 become a space like `\n`, so wire-derived text (a client-supplied authority inside a WARN, an anyhow chain, a Rhai `log.warn`) can never carry an escape sequence to the operator's terminal; the renderer's own SGR and cursor codes are added after sanitizing (AC-W1-31, whose literal is unchanged; spec amendment 2026-11-01, panel S1; bidi/format controls and U+2028/U+2029 added 2026-11-01, panel pass 2 S6; the invisible format characters and the tag block added 2026-11-01, panel pass 3 S9).
- The channel between tracing emitters and the render thread (the `events()` sender that D7's `UiLayer` writes to) is bounded (256); when it is full, WARN/ERROR events are counted and dropped and the renderer prints one `! n warnings suppressed` line when it next drains (plain: `warning: n warnings suppressed`) (`1 warning suppressed` for a single drop); non-droppable messages (`phase`, `done`, `card`, `error`, `finish`) wait at most 2 s for a slot and then abandon the render thread, so a stalled stderr never blocks startup (plan C10) (spec amendment 2026-11-01, panel S3; the singular literal and the non-droppable rule added 2026-11-01, panel pass 2 Sp17/S5).
- Once the serving loop has ended on an orderly exit (Ctrl-C, SIGTERM, or the stdio MCP arm ending on EOF) and the system-proxy restore (§D9 (a)) has run — its warning stays visible: a failed restore that leaves a dead port as the OS proxy must be seen — the reporter is quiesced (`Reporter::quiesce()`) before the browser is reaped (whose CDP-socket teardown is the source of the noise): further tracing events are no longer folded into the view (they still reach the log file); the reporter's own `note`, `warn` and `error` calls still print; the audit log's `did not finish flushing` warning is emitted through the reporter's own `warn` as well, so it stays visible after quiesce (panel pass 3 S7). Teardown noise from dependencies (the browser's CDP socket closing) therefore never ends an operator's session — the concrete case: chromiumoxide logs `WS Connection error: Ws(Protocol(ResetWithoutClosingHandshake))` at ERROR when the embedded browser is closed, and before this rule `UiLayer` printed it as the operator's last line (`error: WS Connection error …`) (AC-W1-33; spec amendment 2026-11-01, live dry-run finding D1, orchestrator's call).

### D5. Card

```rust
pub struct Card { pub headline: String, pub headline_role: Role, pub rows: Vec<Row> }
pub struct Row { pub label: &'static str, pub value: String, pub value_role: Role,
                 pub next: Option<String> /* a fix command, printed under the row */ }
```

Rendering per T3; the headline is the pill line. In plain mode each row is `Label: value` plus ` · <command>` when `next` is set.

### D6. Errors

```rust
pub enum ErrorKind { Usage, Failure }                       // exit 2 / exit 1
pub struct FixCommand(pub String);
pub struct ErrorReport {
    pub kind: ErrorKind,
    pub what: String,              // headline, lowercase start when we compose it
    pub why: Vec<String>,          // cause sentences / the anyhow chain, one per entry
    pub fix: Option<String>,       // prose remedy
    pub command: Option<FixCommand>,
    pub log: Option<std::path::PathBuf>,
}
impl ErrorReport {
    pub fn failure(what: impl Into<String>) -> Self;
    pub fn usage(what: impl Into<String>) -> Self;           // adds command "aitm --help"
    pub fn exit_code(&self) -> i32;                          // 2 for Usage, 1 otherwise
}
```

`crates/aitm/src/startup.rs`:

```rust
pub enum StartupError {
    PortInUse { role: String, addr: std::net::SocketAddr, remedy: String },
    ConfigFile { path: std::path::PathBuf, source: anyhow::Error },
    StrictScripts { failed: usize },
    LogFile { path: std::path::PathBuf, source: std::io::Error },    // never fatal; rendered as a warning
}
impl std::fmt::Display for StartupError { /* PortInUse prints today's four-line sentence verbatim */ }
impl std::error::Error for StartupError {}
pub fn report_for(err: &anyhow::Error, log: Option<&std::path::Path>) -> ErrorReport;
```

Mapping rules for `report_for`, first match wins over `err.chain()`:
1. `StartupError::PortInUse` → `what` = `cannot start: {role} port {addr} is already in use`; `why` = [`It is most likely held by another running \`aitm\`, the aitmproxy macOS app's embedded core, or another program.`]; `fix` = the remedy sentence verbatim; `command` = `lsof -nP -iTCP:{port} -sTCP:LISTEN`.
2. `StartupError::ConfigFile` → `what` = `in config file {path}`, `why` = the source chain (`parsing config YAML`, the serde line/column message), `fix` = `Fix the file, or pass --config <path> to use another.`, `command` = None. The missing-file case (`reading config file {path}` / `No such file or directory`) gets `fix` = `Create it, or run without --config to use the defaults.`
3. `StartupError::StrictScripts` → `what` as today's message, `fix` = `Fix the scripts above, or unset rhai.strict.`
4. A `aitm_cli` dispatch error whose text starts with `unknown command`, `expected a command`, `unknown flag`, `missing required flag`, `flag --` or `unexpected argument`, or a message that starts with `--` and contains ` requires ` (the global flags' `--config requires a path`, `--script requires a path`, `--bus-endpoint-file requires a path` from `parse_invocation`; tester pass 2 F2) → `ErrorKind::Usage` (exit 2 — today these exit 1; see AC-W1-13 and the calls list) with `command` = `aitm --help` (W2: the group/verb help instead).
5. Anything else → `what` = `err.to_string()` (top message), `why` = each `source()` in order, no fix, `kind=Failure`.

`addr_in_use_error(addr, role, remedy)` keeps its signature and returns `anyhow::Error::new(StartupError::PortInUse { .. })`; its `Display` is byte-identical to today's text, so the `main.rs` unit test `starts_with("cannot start: the proxy port 127.0.0.1:18080 is already in use.")` and `cli-startup.sh`'s `already in use` keep passing.

`main()` changes from `-> anyhow::Result<()>` to rendering: on `Err(e)` from `run`, `reporter.error(&startup::report_for(&e, log_path))` then `std::process::exit(report.exit_code())`. The one-shot branch's `eprintln!("{err}")` becomes the same call.

### D7. Tracing composition

```rust
pub struct TermOpts { pub verbosity: Verbosity, pub color: ColorChoice }
pub struct LogSink { pub path: Option<std::path::PathBuf>, pub problem: Option<String> }
pub fn split_term_args(argv: Vec<String>) -> Result<(TermOpts, Vec<String>), String>;
pub fn init_tracing(opts: &TermOpts, reporter: &Reporter, log_dir: &std::path::Path) -> LogSink;
pub fn open_log_file(dir: &std::path::Path) -> std::io::Result<(std::fs::File, std::path::PathBuf)>;
pub struct UiLayer { /* EventSender, min level */ }       // in aitm_term::tracing_layer
pub struct UiEvent { pub level: tracing::Level, pub target: String, pub message: String,
                     pub fields: Vec<(String, String)> }
```

One `tracing_subscriber::registry()` with three layers, each with its own filter **(Orchestrator's call)**:
- **File layer**: `fmt::layer().with_ansi(false).with_writer(Mutex<File>)`, filter = `RUST_LOG` when set and non-empty, else `-vv` → `debug,<noisy crates>=warn`, else `DEFAULT_LOG_DIRECTIVE` (INFO with the curated noisy-crate caps). The file is `CaConfig::default().audit_log.with_file_name("logs").join("aitm.log")` (`~/Library/Application Support/aitmproxy/logs/aitm.log` on macOS, `$XDG_CONFIG_HOME/aitmproxy/logs/aitm.log` on Linux; no `aitm-core` edit, amendment B), overridable by `AITM_LOG_FILE=<path>` **(Architect's call; `AITM_TUI_LOG` stays honoured in tui mode for one release)**; directory created `0700`; file opened `O_CREAT|O_APPEND|O_WRONLY|O_NOFOLLOW` mode `0600`; the opened file must be a regular file (a device, FIFO or socket at the path is refused with the `log file unavailable` warning), its mode is forced to `0600` if an existing file was wider, and the open uses `O_NONBLOCK` so a reader-less FIFO fails instead of hanging (spec amendment 2026-11-01, panel S2); if it is larger than **10 MiB** at open it is renamed to `aitm.log.1` (replacing any older `.1`) before opening **(Orchestrator's call; the figure is the Architect's)**; no mid-run rotation in W1. If the file cannot be opened, `LogSink.problem` is set, one `warn` line is printed (`! log file unavailable: <why> · running without a log`), and startup continues.
- **UiLayer**: `filter = LevelFilter::WARN` on every target (so the noisy crates' WARNs still surface); `on_event` records the `message` field and the other fields and sends a `UiEvent` over the bounded channel (D4; overflow is counted and reported, never blocks the emitter); the reporter prints it as `! <message> · k=v · k=v` (dim fields) above the live region, or as `warning: <message> k=v` in plain mode. ERROR events render with the failed glyph. Never on stdout. Once the serving loop has ended on an orderly exit (Ctrl-C, SIGTERM, or the stdio MCP arm ending on EOF) and the system-proxy restore (§D9 (a)) has run — its warning stays visible: a failed restore that leaves a dead port as the OS proxy must be seen — the reporter is quiesced (`Reporter::quiesce()`) before the browser is reaped (whose CDP-socket teardown is the source of the noise): further tracing events are no longer folded into the view (they still reach the log file); the reporter's own `note`, `warn` and `error` calls still print; the audit log's `did not finish flushing` warning is emitted through the reporter's own `warn` as well, so it stays visible after quiesce (panel pass 3 S7). Teardown noise from dependencies (the browser's CDP socket closing) therefore never ends an operator's session (AC-W1-33; D4 has the API).
- **Stderr layer** (optional): installed only when `RUST_LOG` is set and non-empty (back-compat raw stream, filter = `RUST_LOG`), or `-v` (filter INFO + curated caps) or `-vv` (DEBUG + caps); `with_ansi(caps.color)`, writer `std::io::stderr`. When it is installed the UiLayer is not (no double warnings) and `Caps.animate` is false.
- Per-script lines: `aitm_plugin_rhai::loader` `loaded script` and `aitm::scripts` `script loaded into the host` drop from INFO to DEBUG (two one-word edits in `loader.rs` and `main.rs`). `CDP endpoint is loopback-only and unauthenticated` stays INFO in the file (not a WARN; it is a fact, not a problem — R20 is addressed by it no longer reaching the terminal).
- `-q` affects only the reporter (`Verbosity::Quiet`), never the file.
- Nothing ever writes to stdout from tracing: the file layer and the stderr layer are the only `fmt` layers; a unit test greps `crates/aitm/src` and `crates/aitm-term/src` for `fmt()`/`fmt::layer()` without `with_writer` (AC-W1-29).

### D8. Pre-boot dispatch

```rust
pub enum PreBoot { Version, Help }
pub fn pre_boot(argv: &[String]) -> Option<PreBoot>;      // first token ∈ {--version,-V,version} | {--help,-h,help}
pub fn version_line() -> String;                            // "aitm 0.5.11"
pub const SYNOPSIS: &str;                                   // M3's W1 text, with the version interpolated
```

`main()` calls `startup::pre_boot` **before** `parse_invocation`, before the runtime, before any config read, tracing sink, script tier or CA: `Version` prints `version_line()` + `\n` on stdout and exits 0; `Help` prints `SYNOPSIS` on stdout and exits 0. `pre_boot` steps over `--config <p>`/`--config=<p>` **and** the terminal flags (`-v`, `-vv`, `--verbose`, `-q`, `--quiet`, `--color <v>`, `--color=<v>`) before matching the alias, so `aitm --config x --version`, `aitm -v --version` and `aitm --color never -h` all answer pre-boot and create nothing (tester pass 2 F3: before the fix a leading terminal flag booted the host). **Why a static synopsis and not the existing registry text (Architect's call, deviating from the orchestrator's "existing usage text"):** the registry's usage is `Cli::usage()` over `Registry::commands()`, and the registry is built by `wire::assemble`, which calls `Ca::load_or_generate` (`crates/aitm-proto-http/src/ca.rs:42`) and so mints the CA key; there is no side-effect-free registry in wave 1, and `wire.rs` is frozen. The static group list is pinned by a unit test that assembles the registry in a temp CA dir and compares first segments (AC-W1-9). W2 adds the schema-only registry and restyles the whole help.

`aitm-tui --help` keeps exit 2 and `usage: aitm-tui` **(Orchestrator's call, Homebrew pin)**; `aitm web --help` keeps `web operator UI` in its text (W1 leaves `web::USAGE` untouched; W2 restyles it with that phrase kept).

### D9. Flags

`split_term_args` strips, anywhere before the first positional word (like `--config`): `-v`, `-vv`, `--verbose` (twice = debug), `-q`, `--quiet`, `--color <v>`, `--color=<v>`. Unknown `-x` single-dash tokens are left for the mode parser (today's behaviour). `-v` and `-q` together → usage error (exit 2). The one additive line in `parse_invocation` is the call; `Invocation` gains `term: TermOpts`. Mode usage errors (`tui`, `operator-token`, `sysproxy-watchdog`, `web`) render through a reporter built from the already-parsed `--color`/`-q`, so D2 rule 1 holds for them; only a `split_term_args` failure itself (`-v -q`, a bad `--color` value) falls back to `ColorChoice::Auto`, because nothing has been parsed yet (spec amendment 2026-11-01, panel Q3/Sp3).

### D10. Ready card inputs and sources

```rust
pub enum ModeWord { Server, Web, Tui }
pub enum BusWord { Stdio, Loopback(u16), Http(std::net::SocketAddr), Off }
pub enum CaWord { Trusted, Untrusted }
pub struct ReadyInputs<'a> {
    pub mode: ModeWord,
    pub proxy: std::net::SocketAddr, pub browser: std::net::SocketAddr,
    pub bus: BusWord,
    pub web_url: Option<&'a str>, pub operator_url: Option<&'a str>,
    pub ca: Option<CaWord>, pub scope_hosts: usize,
    pub system_proxy: &'a aitm_sysproxy::Summary,
    pub intercept_armed: bool, pub capture_paused: bool,
    pub log: Option<&'a std::path::Path>,
}
pub fn ready_card(i: &ReadyInputs) -> Card;
pub fn ca_word(stores: &[aitm_ca::store::StoreStatus]) -> Option<CaWord>;   // T7 reduction
pub fn system_proxy_row(s: &aitm_sysproxy::Summary) -> (String, Option<FixCommand>);
```

Sources, all in-process in `run()` where the values already exist: `proxy`/`browser` from the pre-bound listeners; `bus` from `cfg.mcp.transport` and `configured_agent_port`; `web_url`/`operator_url` from `web::ui_url`/`operator_ui_url` (W1 keeps those functions); `ca` from the aitm-ca store read (a phase `checking CA trust`, since it shells out to `security`; **serving modes only**, never for a one-shot `aitm <group> <verb>` and never on the pre-boot paths, amendment A; on error or all-`unknown` → `None`); `scope_hosts` = `cfg.scope.entries.len()`; `system_proxy` = `sysproxy.summary()` after the startup recovery; `log` from `LogSink`. The headline is composed exactly as the TUI pill (T7). Next-step rows: `Scope` when empty (`NOTHING_DECRYPTED_ADVICE` + `aitm scope add --host <host>`); `CA` when `Untrusted` (`aitm ca install`); `System proxy` when `off`/`other` (`aitm proxy system set`). The `Log` row is always last and dim.

Phases in `run()`, in the real order of `crates/aitm/src/main.rs` (amendment C), with their done summaries: `reading config` (`load_settings` plus the env bridge) → `config <path>` / `config defaults · <path> not found`; `loading detections` (the Rhai tier `build_with_languages`, built before the proxy) → `<n> detections ready`; `preparing CA` (wraps `assemble_with_scripts`, which mints or loads the CA) → `CA loaded · <path>` / `CA created · <path>` (whether a key was created is read by comparing the key file's existence before and after, since `wire.rs` is frozen); `binding ports` → `proxy listening <addr> · browser proxy <addr>` (+ ` · web UI listening <addr>` for `aitm web`); `restoring system proxy` (only when the recovery did something; summary from the `Recovery` outcome); `starting obscura` → `obscura probed <version>` (`<version>` = the engine's `--version` text minus its leading `obscura ` word, T7; `browser_summary` strips it) / `fail`-less `warn`: the existing `embedded browser unavailable; browser.* commands will error` WARN reaches the view through `UiLayer`, so the phase ends `done("browser unavailable")`; `checking CA trust` (serving modes only, amendment A) → `CA trusted` / `CA untrusted` / `CA trust unknown`. One-shot `aitm <verb>` runs the first three phases only (a `Mode::Cli` process returns before the ports, the browser and the trust read); they finish under 100 ms, so nothing is drawn (M5's stderr stays empty on success).

### D11. `aitm tui` handover

`run()` calls `reporter.finish_and_clear()` immediately before `tui::run(...)` (which enters the alternate screen inside `aitm_tui::run`). `finish_and_clear` stops the ticker, erases every live-region line, leaves the header line, shows the cursor and flushes; the TUI then owns stdout and stderr. Tracing in tui mode uses the same composition (file layer always; no stderr layer even with `RUST_LOG`, because the TUI owns the terminal — `RUST_LOG` only sets the file filter, as today); `TuiLog::File(path)` feeds the toast. No card for `aitm tui`.

### D12. Mode matrix (research F30)

| Invocation | stdout carries | stderr carries | What the operator sees |
|---|---|---|---|
| one-shot `aitm <group> <verb>` | the result only (`render_cli_value`; W3 adds human renderers + `--json`) | errors as panels; phases only if > 100 ms; warnings | the bare result, or a panel |
| bare `aitm`, `mcp.transport: stdio` | **JSON-RPC only**; nothing else, ever | header, phases, card, warnings, panels | in a terminal: the checklist and card; under an agent launcher: plain lines in the launcher's stderr log |
| bare `aitm`, loopback TCP / streamable HTTP | nothing | same as above | same; `Bus` row names the port |
| `aitm web` | JSON-RPC when stdio MCP is configured; otherwise nothing | header, phases, the card with the `Web UI`/`Operator` URLs, warnings, panels | the card with the link to open |
| `aitm tui` | ratatui after handover | phases until handover, then ratatui | a short checklist, then the TUI |
| mac embedded core (`aitm --config <file>`, both `Pipe()`) | JSON-RPC if stdio (the app uses loopback TCP: nothing) | plain lines, zero ESC bytes | lines in the Core Log |
| e2e harness (`--bus-endpoint-file`, both streams to files) | nothing | plain lines | files for diagnostics |
| `tests/e2e/cli/cli-startup.sh` (`>log 2>&1`) | merged | merged plain lines | `proxy listening`, `obscura probed`, `already in use`, the `#t=` URL all greppable |

### D13. Consumers that must not break

| Consumer | Reads | Today | Decision |
|---|---|---|---|
| `tests/e2e/cli/cli-startup.sh:106` `wait_ready` | merged log, `web UI \(agent\):\|proxy listening` | INFO `proxy listening listen=…` | **re-pin: readiness = the card's `Log:` row** (or `warning: log file unavailable`): the W1 checklist prints `proxy listening <addr> · browser proxy <addr>` right after the ports bind, before the browser launch and the ready card, so a grep on it fires early and stops the server before `obscura probed` and the `#t=` row appear (AC-W1-23 amended 2026-11-01, dry-run D2; the one change to the script) |
| same `:231` | `proxy listening` for `aitm web` | same | keep (same line) |
| same `:160/178/194/206` | `obscura probed` present, `embedded browser unavailable` absent | INFO/WARN messages | **keep**: browser phase plain line `obscura probed <version>`; the WARN message text unchanged and folded through `UiLayer` as `warning: embedded browser unavailable; …` |
| same `:219` | `http://127.0.0.1:[0-9]+/#t=[0-9a-f]+` | stdout card | **move to stderr, keep the URL shape**; the merged log still matches |
| same `:251/269` | `already in use` and the port present, `os error 48` absent, `web UI \(agent\):` absent | anyhow `Error:` block | **keep**: panel headline carries the sentence (AC-W1-3) |
| `tests/e2e/web/test_bus_audit_visibility.py:58-62`, `test_web_intercept.py:93-97` | `t=([^&\s]+)&expect=operator` over stdout **and** stderr files | stdout card | keep the `Operator` row's URL shape; stream move is safe (both files are searched) |
| `apps/web/scripts/live-env.mjs:180-186` | readiness: `/web UI listening/i` on **stderr** or `/^\s*Web UI\s+https?:\/\//m` on **stdout**; operator URL `/^\s*Operator\s+(https?:\/\/\S+)/m` on **stdout** | stdout card + stderr INFO (it sets `RUST_LOG=info`) | **re-pin**: W1's plan includes a one-line change so `opMatch()` and the `Web UI` regex run over `out + stderr`; the row shapes `  Web UI        http://…` and `  Operator      http://…` are kept byte-for-byte (label padded to 14, value at column 17, URL, per T3; the earlier literal with the value at column 14 was the old `startup_summary` padding). Readiness still resolves on `web UI listening` because `RUST_LOG=info` restores the raw stream **(Architect's call: stderr card + script update, not a stdout exception)** |
| `tests/e2e/aitm_e2e/core.py` | the `--bus-endpoint-file` rendezvous only; stdout/stderr to files for diagnostics | — | unaffected |
| mac app `EmbeddedCore.swift:210-224`, `CoreHealth.swift` | every line of both pipes into the Core Log; parses nothing (`CoreHealthTests.swift:43` is a fixture string) | ANSI bytes probably reach the panel today | **fix for free**: non-TTY = zero ESC bytes (AC-W1-5) |
| Homebrew `Formula/aitm.rb` `test do` | `web operator UI` in `aitm web --help`; exit 2 + `usage: aitm-tui` from `aitm-tui --help 2>&1` | — | **keep** both (AC-W1-26, AC-W1-27); `caveats` text unchanged |
| `crates/aitm/tests/sysproxy_watchdog_dispatch.rs:206` | `usage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]` | stderr, exit 2 | keep (mode usage errors print their existing `usage: …` line verbatim as the panel headline or, for a two-line error, as its first cause line; exit 2; W1 renders them as a `Usage` panel) |
| `crates/aitm-tui/tests/cli_usage.rs:19`, `aitm-tui/src/main.rs:278` | `usage: aitm-tui …` | — | keep (not touched) |
| `crates/aitm/src/main.rs` tests `web_listening_log_has_no_token`, `no_tracing_call_site_logs_a_tokened_url`, `default_filter_quiets_connection_noise`, `rust_log_overrides_the_curated_default`, `empty_rust_log_falls_back_to_the_curated_default`, `port_conflict_never_sets_the_system_proxy` (`starts_with("cannot start: the proxy port …")`) | `web UI listening`, `#t=`, `proxy listening`, filter behaviour, the `Display` text | — | keep: `web::log_listening` untouched (hygiene spec pin); `build_env_filter` untouched; `StartupError::PortInUse` `Display` byte-identical |
| `README.md:181`, `apps/web/README.md:29`, `docs/research/MEMORY.md:57` | prose describing the `web UI (agent): http://…` line | stale already | update the prose in W1 (docs only) |
| `tests/e2e/proxy/test_per_host_decryption.py`, `tests/e2e/passthrough/test_tls_passthrough.py` | `proxy.status.decrypt.advice` on the bus | — | unaffected |

### D14. The no-bypass rule

No human-facing text bypasses the layer. Allowed direct writers: `crates/aitm-term/src/**` (the renderer), `crates/aitm/src/render.rs` (`render_cli_value`, results to stdout), `crates/aitm/src/startup/mod.rs` (`write_stdout`: the pre-boot `--version`/`--help` text, `aitm web --help`'s usage text and the `operator-token` confirmation), `crates/aitm-cli/src/confirm.rs` (the `[y/N]` prompt, until W3 routes it), and `#[cfg(test)]` code. A unit test in `crates/aitm` (`tests/no_bypass.rs`) walks `crates/aitm/src` and `crates/aitm-cli/src` (recursively) and fails on any `println!`, `print!`, `eprintln!`, `eprint!` outside those files and outside `#[cfg(test)] mod tests` blocks; the allow-list lives in the test and every entry carries a one-line reason. The test tail starts at a column-0 `#[cfg(test)]` whose next non-empty line begins with `mod ` (the trailing `mod tests { … }`); a `#[cfg(test)]`-gated `mod x;` declaration (one line, `#[cfg(test)] pub(crate) mod x;`, or the attribute on its own line — today `crates/aitm/src/macos_capture/mod.rs`'s `test_support`) does not end the scan, and every production line after it is still scanned (tester pass 2 F1). The file walker and the tail rule are the shared helpers in `crates/aitm/tests/common/mod.rs`, used by both source-scan pins (`no_bypass.rs`, `no_stdout_tracing.rs`; quality Q5). `crates/aitm-tui/src` is out of wave 1's scope (the TUI is a non-goal and wave 1 edits no file under `crates/aitm-tui`); it joins the scan in a later wave (amendment D). W2 removes `confirm.rs` from the list when the prompt goes through the layer.

### D15. Wave 2 design (fixed now so W1's API holds)

- A schema-only registry: `aitm::wire::describe_commands(features: &Features) -> Vec<(String /*dotted*/, aitm_core::ParamSchema)>` that constructs no proxy and no CA (W2 may edit `wire.rs`; the L4 session will have landed). Every command's `schema()` is pure data today, so each plugin gains a `describe()` or the registry is built over inert handles — the W2 plan decides.
- Help renderer in `aitm-term`: `pub fn help_page(caps: &Caps, page: &HelpPage) -> String` with `HelpPage { title, usage: Vec<String>, sections: Vec<HelpSection { heading, rows: Vec<(String, String)> }>, examples: Vec<String>, footer: Vec<String> }`; two columns aligned to the longest left cell capped at 28, descriptions dim and wrapped to width, plain when `!caps.color`; `aitm help` and `aitm --help` identical; `aitm <group>` → the group page; `aitm <group> <verb> --help` → flags with `<type>`, `[default]`, required marks and one or two examples from a new optional `example` field on `ParamSchema` or a static examples table in `startup.rs`.
- Did-you-mean: own Damerau–Levenshtein over group and verb names, suggesting up to 3 within distance 2: `unknown command \`scpe\`` / `  did you mean: scope` / `  ▸ aitm --help`. No new crate.
- Dotted names never in prose: `aitm-cli` error strings print `cmd.replace('.', " ")`; the one-shot usage form becomes `Usage: aitm <group> <verb> [--flag <value>]...`; `tui`, `operator-token` and `web` usage lines all use the `Usage:` form and `web`'s keeps the phrase `web operator UI`.
- Exit codes: usage → 2 everywhere (already W1), failures → 1.

### D16. Wave 3 design (fixed now)

- `aitm_term::table::{Table, Column, Align}` and `render_table(caps, &Table) -> String`: TTY → aligned, header dim, cells truncated with the ellipsis to fit the width (widest-first shrinking), numbers right-aligned; non-TTY → tab-separated, no header, no truncation (gh's rule).
- Four-way choice per command from the result shape and a static override table in `startup.rs` (research F10): array of objects or `{xs:[objects]}` → table; object → card (nested objects as indented sub-cards; `config get` as a YAML-like tree); array of scalars → one per line; `Str`/`Bytes` → as today. `--json` on every command prints the bus JSON, pretty on a TTY and compact when piped.
- `ca export` → the PEM on stdout as text (the current object behind `--json`); `ca status` and `proxy status` → cards with the T7 words; the state-changing one-shots print their result on stdout as today and a `✓ <what changed> · this one-shot proxy only; a running aitm does not see it` line on stderr (R14, honest until the product decision lands).
- Paging: when stdout is a TTY and the rendered output has more lines than the terminal height, spawn `$AITM_PAGER`, else `$PAGER`, else `less`, with `LESS=FRX` set only if unset; `--no-pager` and an empty/`cat` pager disable it; never when piped.
- The `[y/N]` prompt goes through the layer: wrapped to width, the fingerprint and location on their own dim lines, the question last.

## Acceptance criteria

Each is observable on the real binary unless marked (unit). W1 unless tagged.

1. **AC-W1-1** `aitm --version`, `aitm -V` and `aitm version` print exactly `aitm <CARGO_PKG_VERSION>\n` on stdout, nothing on stderr, exit 0; `aitm -v --version` and `aitm --config x --version` print the same line, and `aitm --color never -h` prints the synopsis (the leading flags are stepped over, D8); in a fresh empty `HOME` no file or directory is created under it by any of these (`find "$HOME" -newer marker` is empty); `/usr/bin/time` wall < 100 ms.
2. **AC-W1-2** `aitm --help`, `aitm -h` and `aitm help` print the synopsis (M3) on stdout, exit 0, nothing created, < 100 ms; the `Groups:` block lists exactly the built-in registry's first segments — the registry the binary assembles with an empty script tier (no bundled catalogue, so no `check`/`l4` script commands; `l4.enabled` off), 17 groups (unit test assembles it in a temp dir and compares).
3. **AC-W1-3** With a real holder on the proxy port, bare `aitm` and `aitm web` exit 1 and stderr contains the headline `cannot start: the proxy port 127.0.0.1:<port> is already in use`, the sentence `It is most likely held by another running \`aitm\``, the remedy sentence with the config path, a line whose trimmed content is exactly `lsof -nP -iTCP:<port> -sTCP:LISTEN` preceded by the fix glyph (TTY) or `fix: ` (plain), and the `Log` footer; `os error 48` is absent; stdout is empty.
4. **AC-W1-4** TTY startup draws in place: a `script -q` capture of bare `aitm` in Terminal contains at least one cursor-up sequence (`ESC [ <n> A`) and a clear-line sequence, the braille spinner frames appear only while a phase runs, and the final screen (last 14 lines of the capture after stripping SGR) equals M1's ready block for that machine's values.
5. **AC-W1-5** Piped startup (`aitm 2>out.txt </dev/null` with loopback MCP, and the e2e merged log) contains zero `0x1b` bytes, no `\r`, one line per completed phase, and the `Label: value` card lines of M1p.
6. **AC-W1-6** The ready card for bare `aitm` shows the `Scope` row with `NOTHING_DECRYPTED_ADVICE` verbatim and the `▸ aitm scope add --host <host>` line when Scope is empty, and `n hosts in Scope` with no next step when not.
7. **AC-W1-7** The ready card shows `· CA untrusted` in the pill and the `▸ aitm ca install` line when the CA is untrusted, `· CA trusted` and no CA row when trusted, and no CA word when the read fails (proved both ways: the untrusted path by the script's fresh-`HOME` runs — the TTY recording, T14 §14(a), asserts `· CA untrusted` in the pill and the `▸ aitm ca install` line, and the piped run, §2, asserts the `CA: untrusted · aitm ca install` row; the trusted path on the operator's own `HOME`, where the CA is trusted — live proof recipe step 10; tester pass 2 F5).
8. **AC-W1-8** The `System proxy` row shows `off`/`points at this proxy`/`points at <host>:<port>` per T7 and the `▸ aitm proxy system set` line only for `off` and `other`. The script's fresh-`HOME` runs pin the row's presence (`System proxy: ` in §2, `  System proxy  ` in §14(a)); its value is the machine's real state, so the T7 words are pinned by the `startup/card.rs` unit tests and read off the live card in the recipe (tester pass 2 F5).
9. **AC-W1-9** The header line is `›•‹ aitmproxy <version>` on a UTF-8 TTY and `aitmproxy <version>` when ASCII or plain (unit through the seam + the `script` capture).
10. **AC-W1-10** `LANG=C aitm` (or `TERM=linux`) in a TTY uses only ASCII glyphs (`* o + x ! > - ...`, `- \ | /`), proved by a `script` capture containing no byte ≥ 0x80 outside the operator's own paths.
11. **AC-W1-11** `NO_COLOR=1 aitm` in a TTY prints no SGR sequence; `TERM=dumb CLICOLOR_FORCE=1 aitm` in a TTY prints plain lines with no SGR and no cursor movement (forcing cannot override a dumb terminal; D2 rules 5 and 7) and `TERM=dumb aitm` prints none either; in a TTY `--color=never` beats `CLICOLOR_FORCE` (no SGR) and, on a capable TTY, `--color=always` beats `NO_COLOR` (`NO_COLOR=1 aitm --color=always` prints SGR); `CI=1 aitm` in a TTY prints plain lines (no cursor movement). A non-TTY stream never receives an escape byte under any of these variables (D4; the `2>file` form is proved by AC-W1-5). (The tester-F1 amendment's `TERM=dumb CLICOLOR_FORCE=1 … prints SGR` observable contradicted D4 and plan C6; replaced 2026-11-01, live run D7.)
12. **AC-W1-12** `-q` suppresses the header, phases and card but not the port-in-use panel; `-v` prints the raw INFO stream on stderr plus plain phase lines; `-vv` adds DEBUG including the 49 `loaded script` records; `-v -q` exits 2 with a usage panel.
13. **AC-W1-13** Exit codes: 0 for `--help`/`--version`; 2 for `aitm tui extra`, `aitm operator-token`, `aitm nonsense`, `aitm flow list --bogus 1`, `aitm --flag-first`, `aitm --config` (no value; the panel headline is `--config requires a path`); 1 for config errors, port in use, strict-script failure and command failures (`findings get --id nope`).
14. **AC-W1-14** Mode usage errors (`tui`, `operator-token`, `sysproxy-watchdog`) print their existing `usage: …` line verbatim as the panel headline or, for a two-line error, as its first cause line; exit 2 (on stderr; a two-line mode error's own first line is then the headline; the `sysproxy_watchdog_dispatch.rs:206` pin passes).
15. **AC-W1-15** After any server start, `<aitm dir>/logs/aitm.log` exists with mode `0600` (`stat -f %Lp` on macOS, `stat -c %a` on Linux prints `600`), contains `proxy listening` and `web UI listening` (for `aitm web`) INFO records and **no** `loaded script` record at the default level; with `-vv` or `RUST_LOG=debug` it contains 49 `loaded script` records; the file contains no `0x1b` byte.
16. **AC-W1-16** A log file larger than 10 MiB at open is renamed to `aitm.log.1` and a fresh `aitm.log` is written (proved with `mkfile`/`truncate -s 11m`).
17. **AC-W1-17** With the log directory unwritable (`chmod 500`), startup continues, stderr shows one `! log file unavailable: …` line (`warning: log file unavailable` when plain), the card's `Log` row is omitted, exit is 0 at shutdown.
18. **AC-W1-18** `AITM_LOG_FILE=/tmp/claude/x.log aitm` writes there (mode 0600) and the card's `Log` row names that path.
19. **AC-W1-19** A WARN emitted during startup (`AITM_OBSCURA_BIN=/nonexistent aitm`) appears once on stderr as `! embedded browser unavailable; browser.* commands will error · engine=obscura · error=…` above the live region (TTY) or as `warning: embedded browser unavailable; …` (plain), and once in the log file; it never appears on stdout.
20. **AC-W1-20** `RUST_LOG=info aitm 2>err.txt` restores the raw tracing stream on stderr (`INFO aitm_core::proxy: proxy listening` present), with no in-place drawing even on a TTY; stdout is still empty.
21. **AC-W1-21** Bare `aitm` with `mcp.transport: stdio`: stdout receives no byte before the first JSON-RPC message (`aitm 2>/dev/null | head -c 1` blocks until a client writes; proved by `aitm 2>/dev/null </dev/null | wc -c` printing `0` after the stdin-EOF exit).
22. **AC-W1-22** No token in any stream or file: with `aitm web --token deadbeefcafebabe` and an operator token configured, the merged stderr of a run, the log file and the raw `-v` stream are grepped for the bridge token, the operator bridge token and `mcp.operator_token`'s value; the only hits are the two card URL rows on stderr (unit: `no_tracing_call_site_logs_a_tokened_url` still passes; the `UiLayer` formatter test feeds an event with a `token` field and asserts it is rendered as `token=<redacted>` **(Architect's call 13: field names ending in `token`, `secret`, `password`, `authorization`, `cookie`, `passwd`, `credential`, `credentials`, `api_key`, `apikey` or `bearer` — suffix match, case-insensitive — are redacted by the UiLayer and the plain `warn` formatter; list extended 2026-11-01, panel S4)**).
23. **AC-W1-23** `tests/e2e/cli/cli-startup.sh` passes end to end with exactly one change, its `wait_ready` heuristic now waits for the ready card's `Log: ` row (or `warning: log file unavailable`) instead of the bind-time `proxy listening` line; every assertion is unchanged (amended 2026-11-01, live dry-run D2).
24. **AC-W1-24** The `aitm web` card is on stderr, keeps the rows `  Web UI        http://127.0.0.1:<port>/#t=<token>` and `  Operator      http://127.0.0.1:<port>/#t=<token>&expect=operator` byte-for-byte in shape (label padded to 14, value at column 17, per T3), and `apps/web/scripts/live-env.mjs` (updated to read both streams) reaches readiness and captures the operator URL in a real run (`npm run live:env` or its documented equivalent).
25. **AC-W1-25** `aitm tui` in a real terminal: the `script` capture shows the phases, then clear-line sequences for each live line, then the alternate-screen enter (`ESC [ ? 1049 h`); after quitting the TUI the main screen shows only the header line from the reporter.
26. **AC-W1-26** `aitm-tui --help 2>&1; echo $?` prints a text containing `usage: aitm-tui` and `2`.
27. **AC-W1-27** `aitm web --help` prints a text containing `web operator UI` on stdout, exit 0.
28. **AC-W1-28** No-bypass test (unit, `crates/aitm/tests/no_bypass.rs`): fails on any `println!`/`print!`/`eprintln!`/`eprint!` in `crates/aitm/src` and `crates/aitm-cli/src` (recursively) outside the allow-list in D14 and outside `#[cfg(test)]` blocks; passes on the W1 tree. `crates/aitm-tui/src` joins the scan in a later wave (amendment D).
29. **AC-W1-29** No stdout tracing (unit): a test scans `crates/aitm/src` and `crates/aitm-term/src` for `tracing_subscriber::fmt()` / `fmt::layer()` / `.init()` / `.try_init()` calls and asserts each is in `crates/aitm/src/startup/log.rs` (the layers are built in `compose`, installed by `init_tracing`) and carries a `with_writer`; plus the existing `web_listening_log_has_no_token`.
30. **AC-W1-30** Performance: `/usr/bin/time` of `aitm scope list` (one-shot) and of `aitm --version` are within 5 ms of the 0.5.10 binary's medians for the one-shot and under 100 ms for `--version`; after the ready card no thread named `aitm-term` exists in the process (macOS `sample <pid>`, Linux `/proc/<pid>/task/*/comm`; this check needs no 0.5.10 binary and SKIPs, with the reason, only when the thread names are unreadable — `sample` missing or failed, no `/proc` — panel pass 3 Sp22); the total thread count is reported beside 0.5.10's and may differ by threads main has since added (today: the three `aitm-audit-*` threads) (thread clause amended 2026-11-01, dry-run D6: `sample` measured 21 threads vs 18, the extras being `aitm-audit-reads`, `aitm-audit-control`, `aitm-audit-agent` from main's durable audit log #259, not wave 1; no `aitm-term` thread in either).
31. **AC-W1-31** A WARN whose field value contains `ESC ] 0 ; x BEL`, a C1 CSI (U+009B) and a newline renders as one line on stderr containing no `ESC ]`, no `0x07`, and only the renderer's own `ESC [` sequences (unit, `aitm-term`).
32. **AC-W1-32** Bare `aitm` or `aitm web` with `mcp.transport: stdio`, run `</dev/null`: when the stdio MCP arm ends on EOF, stderr contains exactly one line whose text is `stdin closed · stdio MCP transport ended` (rich: prefixed by `✓`; plain: the bare words) and it is the reporter's last line unless the §D9 (a) system-proxy restore failed or the audit log did not finish flushing, whose warnings then follow it (D4; panel pass 3 Sp23); stdout is empty; the process exits on its own (live, `term-reporting.sh` §9).
33. **AC-W1-33** After Ctrl-C or the stdin-EOF exit of bare `aitm` with obscura attached, stderr's last line is the stdin-closed note (EOF case) or the last card/phase line (Ctrl-C case) — or, when the §D9 (a) system-proxy restore failed, its warning, which follows them (D4) — and stderr contains no `WS Connection error` line; the log file does contain it (live, `term-reporting.sh` §2/§9 assert `grep -c 'WS Connection error' stderr == 0`).
34. **AC-W2-1** `aitm --help` on a TTY prints the grouped help (19 groups, every registered verb) with aligned columns, dim descriptions wrapped to width, `Examples:` and `Learn more:`, exit 0, no file created; piped, the same text with zero ESC bytes.
35. **AC-W2-2** `aitm <group>` for every group prints that group's page, exit 0; `aitm <group> <verb> --help` prints the verb's flags with types, required marks, defaults and at least one example, exit 0, nothing booted (no log record written).
36. **AC-W2-3** `aitm scpe add --host x` prints `unknown command \`scpe\`` and `did you mean: scope` and exits 2; `aitm scan` (a group) prints the `scan` page, exit 0.
37. **AC-W2-4** No stderr line in any usage error contains a dotted command name (`scope.add`); a unit test runs every dispatcher error path and asserts no `[a-z]+\.[a-z]+` command token.
38. **AC-W2-5** `aitm tui --bad`, `aitm operator-token`, `aitm web --bad` and `aitm --bad` all print a `Usage:`-form first line, exit 2; `aitm web --help` still contains `web operator UI`; `aitm-tui --help` still exits 2 with `usage: aitm-tui`.
39. **AC-W2-6** The help's `Groups:`/verbs list is generated from the schema-only registry (unit: equals the live registry's names); `l4` appears when `l4.enabled`.
40. **AC-W2-7** `aitm help` and `aitm --help` are byte-identical; `aitm help scope` equals `aitm scope`.
41. **AC-W2-8** The `[y/N]` prompt for `ca install` is wrapped to width with the fingerprint on its own line (real run, declined with `n`).
42. **AC-W2-9** `cli-startup.sh` and the Homebrew pins still pass.
43. **AC-W2-10** No new crate in `Cargo.lock` for W2 (own edit distance, own wrapping).
44. **AC-W3-1** `aitm ca export > ca.pem` writes a file that `openssl x509 -in ca.pem -noout -subject` parses; `aitm ca export --json` prints today's object.
45. **AC-W3-2** `aitm ca status` prints the M4 card with the one verdict word matching the TUI's for the same machine; `--json` unchanged.
46. **AC-W3-3** `aitm proxy status` prints a card whose headline is the T7 pill and whose `System proxy` row uses the T7 words; `--json` unchanged.
47. **AC-W3-4** `findings list`, `script list`, `flow table`, `poc list`, `map list`, `agent activity` print aligned tables on a TTY (header dim, cells truncated with `…` to the width) and tab-separated untruncated rows without a header when piped; each has `--json`.
48. **AC-W3-5** Every registered command accepts `--json` and prints the bus value (pretty on a TTY, compact when piped); a unit test iterates the registry.
49. **AC-W3-6** `aitm script list` on a 24-line terminal opens `$PAGER` (`PAGER=cat` prints inline; `--no-pager` prints inline); piped, never pages.
50. **AC-W3-7** `aitm scope add --host example.test` prints `example.test` on stdout and the stderr line `✓ example.test added to Scope · this one-shot proxy only; a running aitm does not see it`; `scope remove`, `flow clear`, `proxy pause/resume`, `ca install/uninstall` print an equivalent honest line.
51. **AC-W3-8** Empty results print a dim empty-state line on stderr (`(no flows)`, `(Scope is empty)` + the advice and next step) and the machine value on stdout.
52. **AC-W3-9** `config get` prints a YAML-like tree on a TTY; `--json` prints today's object.
53. **AC-W3-10** `scan report` prints the Markdown text to stdout (not a JSON string with `\n`); `--json` prints the object.
54. **AC-W3-11** `capture status` prints a three-lane card with the mac lane words (`capture off`, `waiting for approval`, `capture degraded`, `on, nothing in scope`, `capture on · n hosts in scope`).
55. **AC-W3-12** Any table or pager crate added in W3 is named in the W3 plan with its lock delta; otherwise zero new crates.

## Left to the builder

- Internal module split inside `aitm-term`, the message enum between the API and the render thread, and the exact `Drop` guard type.
- The exact wording of phase labels not fixed in D10 (keep T6's form), the `-v` duration suffix format, and the dim-field joiner in warning lines.
- The `aitm-ca` method shape for the store-status read (D1) and how `CaWord` is reduced from `Vec<(Scope, StoreStatus)>`.
- How the CA phase detects "created" vs "loaded" without editing `wire.rs` (key-file existence before/after `assemble` is the suggested route).
- Wrapping algorithm (greedy by words, `unicode-width` measured) and the ellipsis placement for truncated paths (truncate the middle, keeping the file name, is preferred).
- The unit-test seam details: a `Vec<u8>` sink behind `Arc<Mutex<_>>`, a fake clock for the 100 ms rule, and a fake `Caps`.
- Test file names and the exact allow-list comments in `no_bypass.rs`.
- Whether the render thread uses `std::sync::mpsc` or `crossbeam-channel` (both in the lock); `std` is preferred.

## Open questions

Status at approval (2026-11-01): questions 1–3 are routed to Matt through the orchestrator with the defaults below in force; questions 4–6 were decided at approval with their defaults. A different answer from Matt is a spec amendment.

1. **R14, one-shot verbs and a running core** — *decided 2026-11-01 (Matt, via the orchestrator): yes.* Specified in `docs/superpowers/specs/2026-11-01-cli-oneshot-live-core-design.md`: every surface serves a loopback operator bus by default and publishes a pointer file, one-shot verbs act on the running core and refuse with a panel when none is reachable. That spec re-pins AC-W1-6 (the Scope next-step line appears only when the card's own core is reachable by a one-shot), AC-W1-30 (the one-shot timing subject becomes `aitm ca status`, a local verb) and AC-W3-7 (the honest stderr line names the core for live verbs; M5's `this one-shot proxy only` clause applies to local verbs only).
2. **R11 for other one-shot verbs** — *routed to Matt; default in force.* `aitm scope list` still boots the host (and mints a CA on a fresh `HOME`) because the registry needs the proxy. Should read-only verbs get a side-effect-free path? Default: W2's schema-only registry covers help; verbs keep booting (quietly, with the log file) until the R14 decision.
3. **`aitm web` stdin EOF** — *routed to Matt; default in force and implemented.* With the card now on stderr and nothing on stdout, `aitm web </dev/null` still exits 0 when the stdio MCP arm ends. Default: W1 prints `stdin closed · stdio MCP transport ended` as the reporter's last line (rich: `✓` prefix) when the stdio MCP arm ends on EOF, so the silence is gone (AC-W1-32); the lifecycle decision (whether `aitm web` should exit at all) stays routed to Matt.
4. **`AITM_TERM` naming** — *decided: keep `AITM_TERM=rich|ascii|plain`* (one variable, three words; cargo's two-variable split is not adopted).
5. **Usage errors exit 2 for registry errors** (today 1) — *decided: exit 2* (uv, cargo-ish; our own mode usage errors already exit 2). No script in the tree relies on exit 1 for `unknown command`.
6. **Log location on macOS** — *decided: the data dir*, `~/Library/Application Support/aitmproxy/logs/aitm.log`, beside the CA and the config (not `~/Library/Logs/aitmproxy/`), derived per amendment B.

## Summary

One small crate, `aitm-term`, becomes the only way `aitm` talks to a human on the terminal: capability detection with a plain fallback, a brand glyph set with ASCII twins, an in-place checklist with a 100 ms delayed spinner that collapses to one line per phase, a ready card that reuses the TUI pill and names the next step (`scope add`, `ca install`, `proxy system set`), and an error panel with what/why/fix/log. Tracing leaves stdout for good: INFO goes to a 0600 log file, WARN+ folds into the view, `-v/-vv/-q/--color/RUST_LOG` control the rest. `--version` and `--help` answer before anything boots. Wave 1 ships that with every consumer pinned; wave 2 turns help into a product; wave 3 renders results as tables, cards, lists and PEMs with `--json` everywhere.

## Calls made in this spec

Orchestrator's calls followed: B1 renderer on crossterm + unicode-width, zero new crates; channel contract; animation gate and env precedence; 100 ms first draw, braille/line spinners; glyph set and vocabulary; log file location/mode/rotation at open; two exit codes; pre-boot fast paths; consumer pins; mode matrix; shared-file discipline; live proof.

Architect's calls (veto any):
1. `aitm --help` in W1 prints a **static synopsis**, not the registry's existing usage, because the registry cannot be built without minting the CA and `wire.rs` is frozen; a unit test pins the static group list to the live registry.
2. The `aitm web` card moves to **stderr** (no stdout exception); `apps/web/scripts/live-env.mjs` is updated in the W1 plan to read both streams; row shapes are kept byte-for-byte.
3. Render thread = one **OS thread** (`aitm-term`), not a tokio task; started lazily, gone after `finish()`.
4. `-v`, `-vv` and `RUST_LOG` switch the reporter to **plain lines** (no in-place drawing) so the raw stream and the live region never interleave.
5. Spinner frame interval **100 ms**; log rotation threshold **10 MiB** at open; no mid-run rotation in W1.
6. `AITM_TERM=rich|ascii|plain` escape hatch exists; `AITM_LOG_FILE=<path>` overrides the log path (`AITM_TUI_LOG` honoured in tui mode for one release).
7. Warning glyph `!` in both sets; `✕` for errors; `●○✓▸·─` per the orchestrator.
8. Phase lines are glyph + lowercase clause (no label column); the card has the 14-char label column; `$HOME` → `~` in phases and cards, verbatim paths in error panels.
9. Registry usage errors exit **2** (today 1); mode usage lines stay verbatim as panel headlines.
10. System-proxy words: `points at this proxy` / `points at <host>:<port>` / `off` / `needs privilege` / `unsupported on this platform` / `unknown`.
11. The ready card reads CA trust once at startup through the same aitm-ca code path as `ca.status` (a `checking CA trust` phase); unread → no word.
12. `aitm tui` prints phases and no card, and the reporter clears its lines before ratatui (per the orchestrator), leaving only the header line.
13. The UiLayer and plain warning formatter redact fields whose name ends in `token`, `secret`, `password`, `authorization`, `cookie`, `passwd`, `credential`, `credentials`, `api_key`, `apikey` or `bearer` (suffix match, case-insensitive; the last eight were added 2026-11-01 from the panel's S4).
14. `CDP endpoint is loopback-only and unauthenticated` stays INFO (file only); per-script lines drop to DEBUG.
15. W2 gets a schema-only `wire::describe_commands`; W3's pager is hand-rolled (`$AITM_PAGER`, `$PAGER`, `less`, `LESS=FRX`), tables are hand-rolled unless the W3 plan argues for a crate.
