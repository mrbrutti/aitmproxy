# CLI terminal reporting, wave 2 (help as a product) — implementation plan

**Status:** approved 2026-11-01 (session lead, under Matt's autonomous-approve mode; plan calls C28–C52 stand; questions 1–5 go to Matt with the release notes, defaults in force)
**Spec:** `docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md` (approved 2026-11-01; this plan covers AC-W2-1 … AC-W2-10 and the W2 clauses of T1–T7, D6 rule 4, D8, D14 and D15)
**Research:** `docs/research/24-cli-terminal-reporting.md` (R2, R5, R11, R15, R22; F21 help layouts; F34 message rules)
**Branch / worktree:** `claude/cli-ux-help-wave2` in the nested worktree
`/Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/.wt/w2`, cut from the wave-1 tip `ddbc77bf` (PR #271, awaiting merge). **Stacked:** wave 2 lands as its own PR after #271. While #271 is open the W2 PR is opened with base `claude/cli-ux-terminal-reporting-64b09b`; once #271 merges, rebase onto `main` in the Terminal, `gh pr edit --base main`, and verify `baseRefName == main` before merging (memory `aitmproxy-merge-check-base-is-main`). Task 15 (the only `main.rs` task) runs after that rebase, or at least after every other task.

## Overview

Wave 2 turns help into a product without a second source of truth: a **schema-only registry** (`crates/aitm/src/describe.rs`) assembles the same plugins `wire.rs` registers, over inert handles and the same Rhai tier composition, so it lists exactly what this install can run — 19 groups and every verb, the bundled `check.*` / `l4 recon|tcp_probe|udp_probe` scripts included — without a proxy, a CA or a log file; a pin test compares it with the live registry. On top of it sit a `HelpPage` renderer in `aitm-term` (two columns at a fixed description column, dim descriptions wrapped to width, plain when piped), page builders and a static catalogue of group purposes and examples in `crates/aitm/src/help/`, typed usage errors from `aitm-cli` (did-you-mean over an own Damerau–Levenshtein, dotted names never in prose, one `Usage:` form per mode, the right help pointer per error), and a structured `[y/N]` prompt through the layer. Sixteen tasks; `wire.rs` is never touched (#267 owns it), `main.rs` is touched once, last.

### The premise, measured (2026-11-01, this worktree's debug build, `HOME` in `$TMPDIR`)

The brief asked whether help may load the Rhai catalogue. On the debug binary the bundled catalogue's compile span is **29 ms** (DEBUG records 01:11:19.4577 `bundled detection catalogue loaded` → .4864 last `script loaded into the host`, 49 scripts); a one-shot `aitm scope list` is 30–50 ms wall with the catalogue and 10 ms without; `aitm --version` is 0 ms at `time -p` resolution. So a help page that compiles the catalogue (no subscriber installed → no log record, nothing written) costs about 30–40 ms on a debug build and less on the release binary, inside AC-W2-1/2's 100 ms. **Decision: help loads the catalogue (C30).** The `help.sh` script measures it live (§1).

### Dependency order

| Wave | Tasks (parallel within a wave) | Depends on |
|---|---|---|
| A | **T1** `aitm-term` skeleton (`lib.rs` +2 modules, `Caps::detect_stdout`, `ErrorReport: Display + Error`) · **T4** `aitm-cli` skeleton + `suggest.rs` · **T7** aitm-ca prompt restructure · **T8** `aitm` skeleton (`lib.rs` +2 modules, `help/mod.rs`, stubs) | — |
| B | **T2** `aitm-term/src/help.rs` · **T3** `aitm-term/src/prompt.rs` · **T9** `describe.rs` + the registry pin · **T11** `help/request.rs` | T2, T3: T1 · T9, T11: T8 |
| C | **T5** `aitm-cli/src/dispatch.rs` (typed errors, `locate`, did-you-mean) · **T6** `aitm-cli/src/confirm.rs` · **T10** `help/catalog.rs` · **T12** `startup/{args,errors,mod}.rs` + delete the synopsis pins | T5: T1, T4 · T6: T3, T4 · T10: T9 · T12: T1, T9 |
| D | **T13** `help/pages.rs` | T2, T5, T9, T10 |
| E | **T14** `help/answer.rs` | T5, T9, T11, T13 |
| F | **T15** `main.rs` / `tui.rs` / `web/mod.rs` / `no_bypass.rs` / `term-reporting.sh` §4 — the ONE shared-file task; runs after #271 merges or after a rebase onto it | T6, T7, T12, T14 |
| G | **T16** `tests/e2e/cli/help.sh` + README; then the full gate and the live proof from the Terminal panel | T15 |

Independent sets: {T1, T4, T7, T8}; {T2, T3, T9, T11}; {T5, T6, T10, T12}. Everything else is sequential as listed. `Cargo.lock` is touched by T4 only (one new edge, `aitm-cli → aitm-term`; zero new crates, AC-W2-10).

### Files touched by wave 2 (the claims list — the orchestrator sends it before the first coder)

Create: `crates/aitm-term/src/help.rs`, `crates/aitm-term/src/prompt.rs`, `crates/aitm-cli/src/suggest.rs`, `crates/aitm/src/describe.rs`, `crates/aitm/src/help/mod.rs`, `crates/aitm/src/help/request.rs`, `crates/aitm/src/help/catalog.rs`, `crates/aitm/src/help/pages.rs`, `crates/aitm/src/help/answer.rs`, `crates/aitm/tests/describe_registry.rs`, `tests/e2e/cli/help.sh`.

Modify: `Cargo.lock`, `crates/aitm-term/src/lib.rs`, `crates/aitm-term/src/caps.rs`, `crates/aitm-term/src/error.rs`, `crates/aitm-cli/Cargo.toml`, `crates/aitm-cli/src/lib.rs`, `crates/aitm-cli/src/dispatch.rs`, `crates/aitm-cli/src/confirm.rs`, `crates/aitm-cli/tests/cli.rs`, `crates/aitm-ca/src/commands.rs`, `crates/aitm-ca/tests/commands.rs`, `crates/aitm/src/lib.rs`, `crates/aitm/src/startup/mod.rs`, `crates/aitm/src/startup/args.rs`, `crates/aitm/src/startup/errors.rs`, `crates/aitm/src/main.rs`, `crates/aitm/src/tui.rs`, `crates/aitm/src/web/mod.rs`, `crates/aitm/tests/support/mod.rs`, `crates/aitm/tests/no_bypass.rs`, `tests/e2e/cli/term-reporting.sh` (§4 literals only), `tests/e2e/cli/README.md`.

Delete: `crates/aitm/tests/synopsis_groups.rs`, `crates/aitm/tests/synopsis_groups_l4.rs` (replaced by `describe_registry.rs`).

Never touched in wave 2: `crates/aitm/src/wire.rs` (frozen until #267 merges), anything under `crates/aitm-core/`, `crates/aitm-tui/`, `apps/`, `crates/aitm/src/startup/{card,log}.rs`, `crates/aitm-term/src/{reporter,card,text,tracing_layer,style,glyphs,event,clock,testing}.rs`.

Coordination: the sibling branch `claude/cli-oneshot-live-core` (R14, worktree `.wt/r14`) is also stacked on `ddbc77bf` and had no commits of its own on 2026-11-01. It will want `main.rs`'s one-shot branch and possibly `aitm-cli`; wave 2 claims `crates/aitm-cli/src/*` and the `main.rs` hunks listed in T15. Whichever lands second rebases.

### Rules every task obeys

Wave 1's nine rules hold verbatim (test first with the red and green runs quoted; hermetic unit tests — no socket, no pty, no network in the sandbox; literal assertions; the per-package offline gate `cargo clippy -p <crate> --all-targets --offline -- -D warnings && cargo test -p <crate> --offline [--lib | --test <name>]` plus `cargo fmt -p <crate> -- --check`; zero new crates; no token anywhere; `unsafe_code = "forbid"`; stop on gaps; `touch` before a gate that looks impossible), plus:

10. **Shared worktree, shared index.** Parallel coders share this ONE nested worktree and ONE git index: touch only the files your task lists; `rustfmt --edition 2021 <your leaf files>` only — never `cargo fmt`, never `rustfmt` on `lib.rs`, `main.rs` or a `mod.rs` (crate and module roots reformat everything beneath them; verify those with `cargo fmt -p <crate> -- --check`); never `git add`, `git add -A`, `git stash` or `git commit`; the orchestrator commits each wave with explicit pathspecs.
11. **Frozen files.** `crates/aitm/src/wire.rs` is not edited by anyone in this wave, whatever the temptation (D15's `wire::describe_commands` is realised as `describe::registry` instead, C28). `crates/aitm/src/main.rs`, `tui.rs` and `web/mod.rs` are edited by T15 only.
12. **Nothing written by help.** Any code on the help path (`describe`, `help::*`) may read the config file, the environment, the executable's directory and script files; it never creates a file or directory, never opens a log, never spawns a process, never binds. The `describe_registry` pin asserts the CA directory it is pointed at does not exist afterwards.
13. **Hermetic help tests** build the schema-only registry in-process (`describe::registry` with `Settings` defaults, the CA dir under `std::env::temp_dir()` — never created — and an injected env closure; the bundled catalogue is reached through the `AITM_BUNDLED_SCRIPTS` key of that closure pointing at `concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/bundled")`), then render pages through `Caps` fixtures to strings. Two fixtures are used throughout: `piped_utf8()` = `Caps { tty: false, color: false, unicode: true, animate: false, width: 80, ci: false }` (what a UTF-8 pipe gets) and `tty80()` = `Caps { tty: true, color: true, unicode: true, animate: true, width: 80, ci: false }`.
14. **Text rules** (spec T6): descriptions we compose are lowercase clauses with no trailing period (the W1 synopsis precedent); sentences the core composes (command and parameter descriptions, `NOTHING_DECRYPTED_ADVICE`) are printed verbatim, never re-cased or re-punctuated; dotted wire names never appear in prose — every error string prints `aitm_cli::dispatch::spaced(name)`.

### Plan-level calls (Architect; how the spec is read where it left wording open — veto any; numbering continues wave 1's C1–C27)

- **C28** D15's `aitm::wire::describe_commands` cannot live in `wire.rs` (frozen until #267). The schema-only registry is `crates/aitm/src/describe.rs`: it constructs the same plugins in the same order `wire::assemble_with_scripts` does, over inert handles (`LateHandles` never bound, `StdGuard::default()` for the map guard, `SystemProxy::with_mechanism(.., Mechanism::None)`, `L4Privilege::available()` so no probe runs, `CaPlugin::new` whose `FileAuditLog` opens nothing until a write), and registers them into a bare `aitm_core::Registry` — no `Proxy::builder`, no `CertAuthority`. The duplication of the plugin list is accepted and pinned: `tests/describe_registry.rs` compares names, order and schema fingerprints with the live registry for the default features, for `l4.enabled`, and with the bundled catalogue. Follow-up (not W2): once #267 lands, `wire.rs` and `describe.rs` share one plugin-list builder and `run()`'s tier composition moves into `scripts.rs` for both.
- **C29** The Rhai tier for help is composed exactly as `run()` composes it (config `rhai:` entries, `AITM_SCRIPTS` via `env::apply_rhai`, the bundled catalogue via `bundled::apply`, then `--script` entries; `rhai.ssrf = browser.ssrf`; the `ws` language and, when `l4.enabled`, the `L4Language` installed before compile), on a private current-thread tokio runtime the `Described` value owns, so a script registered by the operator's own `load(reg)` appears in help too. Compile errors are ignored by help (`strict` is a boot concern).
- **C30** Help loads the bundled catalogue (measured above). With `AITM_NO_BUNDLED_SCRIPTS=1` help lists 17 groups, otherwise 19; `l4` therefore appears whenever the catalogue is on (its three script verbs) and grows by the `L4Module`'s verbs when `l4.enabled` — AC-W2-6's observable ("`l4` appears when `l4.enabled`") holds in both configurations and the pin covers both.
- **C31** The help path **reads the config file** (read-only; `config_file::load_settings`, then `env::apply`/`apply_rhai`/`apply_l4`) to honour `l4.enabled` and the operator's scripts. Spec D8's "pre-boot paths read no config" is narrowed to `--version`: `aitm --help` still creates nothing, opens no log, boots nothing (AC-W2-1/2's literal observables are unchanged). An unreadable or invalid config does not fail help: the page is built from `Settings` defaults and one reporter `warn` line is printed first — rich `! config not read · <path>: <first line of the error> · help lists the default command set`, plain `warning: config not read · …` (routed to Matt as question 2).
- **C32** `startup::pre_boot` answers `--version`/`-V`/`version` only; `PreBoot::Help`, `SYNOPSIS` and `GROUPS` are deleted. Every help form — `--help`, `-h`, `help [topic…]`, `<group>`, `<group> <verb> --help`, `web --help`, `tui --help`, `operator-token --help` — is recognised by `help::request::parse` inside `parse_invocation` (after the `--config`/`--script`/`--bus-endpoint-file` splits, before the web and mode parsers) and becomes the new `Mode::Help(HelpRequest)`, dispatched in `main()` before the runtime like `OperatorToken`. `sysproxy-watchdog` is never intercepted (hidden; its test pins its own usage line).
- **C33** A single bare token that is not a mode word (`aitm scope`, `aitm scpe`) is an **implicit** help request: when it names a group the group page prints (exit 0, AC-W2-3); when it does not, the request is dropped and the invocation continues as today's `Mode::Cli` (boot, dispatch, `unknown command` with did-you-mean, exit 2). Rule: **help is pre-boot; usage errors stay post-boot** (spec open question 2 keeps verbs booting; a general pre-boot validation would compile the tier twice and break AC-W1-30's 5 ms budget). The one exception: an *explicit* help request that cannot be answered (`aitm help scpe`, `aitm scope ad --help`) is an error pre-boot, because it is a help request.
- **C34** Mode usage errors take the cargo/uv shape, not a `Usage:` headline: headline = what happened, lowercase (T6); first cause line = the mode's `Usage:` form; pointer = the relevant help command. `tui takes no further arguments, got \`--bad\`` / `Usage: aitm [--config <path>] tui` / `▸ aitm --help`. AC-W2-5's "`Usage:`-form first line" is read as the first line after the headline; the alternative reading (the `Usage:` line as the headline, W1's stopgap) contradicts T6's lowercase rule. Routed to Matt as question 1 with this default.
- **C35** `aitm-cli` returns **typed** errors: every usage error is an `aitm_term::error::ErrorReport` (which gains `Display` and `std::error::Error` in T1) wrapped in `anyhow::Error`, carrying `what`, `why` (did-you-mean, then the `Usage:` line), and `command` (`aitm --help`, `aitm <group>`, or `aitm <group> <verb> --help`). `startup::errors::report_for` gains rule 0: an `ErrorReport` anywhere in the chain is used as is (plus the log footer). The string-protocol rule 4 stays for `main.rs`'s own mode parsers and accepts both `usage:` and `Usage:`. `aitm-cli` therefore depends on `aitm-term` (one lock edge, no new crate).
- **C36** `web::parse_args` errors are typed the same way with pointer `aitm web --help`; `main.rs`'s `tui`/`operator-token` parsers stay strings (`"<what>\n<Usage line>"`) because their pointer is `aitm --help`.
- **C37** Did-you-mean: optimal-string-alignment Damerau–Levenshtein over `char`s in `aitm_cli::suggest`, in two rules so that a near-miss yields one name, not a list of equally wrong ones (amended 2026-11-01 after Task 4 found that the one-rule form yields `scope, scan` for `scpe` while D15/AC-W2-3/M-W2-4 pin `did you mean: scope`): **(1) prefix wins** — when the (non-empty) input is a prefix of one or more candidates, those are the suggestions (`sc` → `scan, scope, script`); **(2) else the closest tier only** — candidates at distance ≤ 2 are kept only at the minimum distance found (`scpe` → `scope` alone, since `scan` is at 2). Either way distinct names, sorted by name, at most 3. The headline names the first unknown token: `unknown command \`scpe\`` with suggestions over group names and pointer `aitm --help`; `unknown command \`scope ad\`` with suggestions over the group's verbs (as spaced full names, `scope add`) and pointer `aitm scope`; `unknown flag --hsot for \`scope add\`` with suggestions over the schema's flags (`did you mean: --host`) and pointer `aitm scope add --help`. One `why` line: `did you mean: scope, script`.
- **C38** Trailing tokens after a known command (`aitm scope add extra`) are `unexpected argument \`extra\` for \`scope add\``, not an unknown command. A bare group reaching the dispatcher (`aitm scope --yes`) is `missing verb after \`scope\`` with `Usage: aitm scope <verb> [--flag <value>]...` and pointer `aitm scope`.
- **C39** `Cli::usage()` stays (two tests use it) with its first line restyled to `Usage: aitm <group> <verb> [--flag <value>]...`; no error embeds it any more.
- **C40** Help pages use a **fixed description column**: `DESC_COL = 28` (0-based), two-space indent, a left cell of at most 24 columns padded so the description starts at column 28; a wider left cell stands alone and its description starts on the next line at column 28 (M3's `aitm <group> <verb> [--flag <value>]...` row). D15's "aligned to the longest left cell capped at 28" is read as this fixed column, which is what M3's two blocks show and keeps the eye in one place across pages. Descriptions wrap greedily to `caps.width` with continuation at column 28 (room `max(width − 28, 20)`); usage lines wrap with a four-space continuation indent; example lines (`$ …`) and footer command lines are never wrapped (copy-safe, plan C5).
- **C41** The `HelpPage` model is ordered: `HelpPage { title, about: Vec<String>, usage: Vec<String>, blocks: Vec<Block> }` with `Block::Section(HelpSection { heading, rows })`, `Block::Examples(Vec<String>)`, `Block::Text(Vec<String>)`, rendered title → about → `Usage:` → blocks, one blank line between blocks. D15's `sections / examples / footer` fields are the three block kinds; the ordered list exists so `Examples:` can precede `Learn more:` on the top page and the verb page can open with its description paragraph (cargo's shape). On a rich TTY headings are `Role::Bold`, descriptions `Role::Dim`; everything else plain; when `!caps.animate || !caps.color` no escape byte is written (C6). When `!caps.unicode`, `·`/`…` follow T1's substitution and the title's ` — ` becomes ` - `.
- **C42** Placeholders: group-page verb rows and the verb page's `Usage:` line show required flags as `--name <name>` (`add --host <host>`, M3) and omit optional flags on group rows (`[--name <name>]` on the usage line); the `Flags:` rows show the type (`--host <string>`, today's `type_hint` words) with ` [required]` appended to a required flag's description. A `Bool` placeholder is `<true|false>` everywhere.
- **C43** Verb rows carry the **first sentence** of the command's description, verbatim: the text up to and including the first `.` that is followed by a space and an uppercase letter, or the whole text when there is none (so `(e.g. colour names)` and `{ url, param }` texts stay whole). The verb page prints the whole description as its opening paragraph and has no title line (cargo's shape). Group pages are titled `aitm <group> — <purpose>` (M3). The top page is titled `aitm <version> — intercepting proxy for authorized security testing`.
- **C44** Group purposes, footers, the mode rows, the option rows, the top-page examples and the "learn more" rows are a static catalogue in `crates/aitm/src/help/catalog.rs` (the Architect's text, below). The 19 purposes are the Architect's call; a group with no catalogue entry renders `(no description)` and fails the catalogue pin, so a new group cannot ship without a purpose.
- **C45** Examples are a **static table keyed by dotted name and by group name** (`catalog::EXAMPLES`), not a new `ParamSchema` field (that edits `aitm-core` and every plugin; routed to Matt as question 3, default no). Rules for every example: one runnable `aitm <group> <verb> …` line, concrete values (`app.example.test`, `https://app.example.test/login`, the flow id `3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e`, paths under `~/`), globs single-quoted, no secret, at most 72 columns, no trailing period. A group page shows its own entry or, failing that, the first example of each of its verbs (at most 4). A verb page with no entry falls back to its usage form (never breaks) — and the catalogue pin fails, so the fallback never ships.
- **C46** Defaults are not a separate column: there is no default in `ParamSchema`, and the parameter descriptions already state them verbatim (`Body mode: \`none\`, \`inline\` (default), or \`range\`.`, eleven such params today). AC-W2-2's "defaults" observable is `aitm flow detail --help` containing `(default inline)` and `(default 0)`.
- **C47** The `[y/N]` prompt becomes structured text from the command and a renderer in the layer: `aitm_term::prompt::ConfirmPrompt::parse` reads a `\n`-separated prompt (first line = the question; a line beginning with two spaces = a detail printed whole and dim; the last line, when it ends with `?`, = the short final ask; the rest = notes wrapped to width behind a two-space indent), and `render_confirm` ends with `[y/N] `. `aitm-ca`'s `Op::prompt` is restructured into that shape (fingerprint on its own line); every other command's single-line prompt renders as the wrapped question plus ` [y/N] `. `TtyConfirmer` gains `with_caps` and writes the rendered text; `confirm.rs` leaves the no-bypass allow-list (D14).
- **C48** `aitm web --help`, `aitm tui --help` and `aitm operator-token --help` are `HelpPage`s built from constants in `help/pages.rs`; `web::USAGE` is replaced by `web::USAGE_LINE` (the one `Usage:` line, used by its errors), `tui::USAGE` becomes the `Usage:` line, and `OPERATOR_TOKEN_USAGE` likewise; the Homebrew phrase `web operator UI` stays in the web page's opening sentence. `aitm-tui --help` (the sibling binary) is untouched: exit 2, `usage: aitm-tui`.
- **C49** Help is rendered for **stdout's** capabilities (`Caps::detect_stdout(term.color)`, new in T1, the mirror of `detect_stderr`), because the page goes to stdout through `startup::write_stdout` (already on the D14 allow-list; no new direct writer).
- **C50** Group order on the top page is alphabetical (the W1 `Groups:` block); verbs within a group keep registration order (the order `wire.rs` registers them, which is the order the operator meets them in the registry dump today).
- **C51** `tests/e2e/cli/term-reporting.sh` is edited in exactly three literals of §4 (the `tui`, `operator-token` and `flow list --bogus` expectations, T15) and nowhere else; wave 2's live proof is the sibling script `tests/e2e/cli/help.sh` (no ports, no server, so it has a small skeleton of its own).
- **C52** `Cargo.lock` gains the one edge `aitm-cli → aitm-term` (T4). Nothing else changes in the lock (AC-W2-10).

---

## Mock-ups (exact bytes; width 80; ANSI omitted — the rich forms paint headings bold and descriptions dim, nothing else)

### M-W2-1. `aitm --help` (= `aitm -h` = `aitm help`), catalogue present, 19 groups

```text
aitm 0.5.11 — intercepting proxy for authorized security testing

Usage:
  aitm                      run the proxy with the MCP agent transport
  aitm web [options]        run the proxy and the web operator UI
  aitm tui                  run the proxy and the terminal operator UI
  aitm <group> <verb> [--flag <value>]...
                            run one command and exit
  aitm operator-token generate [--force]
                            write a new operator token into the config file

Groups:
  agent                     agent policy, approvals and the activity log
  browser                   drive the embedded browser
  ca                        the root CA: export, status, install, uninstall
  capture                   the macOS capture extension's status
  check                     active checks that confirm one finding at a URL
  config                    the running configuration, redacted
  findings                  the persistent findings store
  flow                      captured flows: list, inspect, intercept, replay
  l4                        raw packet recon, probes and capture (opt-in)
  map                       Map Local and Map Remote rules
  poc                       reproducible proofs of concept
  proxy                     proxy state, pause/resume and the system proxy
  request                   craft and send a request through the proxy
  scan                      discovery, passive checks and the findings report
  scope                     which hosts are decrypted
  script                    the Rhai detection scripts
  session                   save and load the flow store
  tls                       TLS passthrough: hosts tunnelled, not decrypted
  ws                        WebSocket frame interception and injection

Options:
  --config <path>           config file (env AITM_CONFIG)
  --script <path>           load an extra Rhai script (repeatable)
  --yes                     answer a verb's confirmation prompt without asking
  -v, -vv                   show INFO / DEBUG tracing on stderr
  -q                        errors only
  --color <auto|always|never>
                            force or disable colour (NO_COLOR, CLICOLOR_FORCE)
  --version, -V             print the version and exit
  --help, -h                print this help

Examples:
  $ aitm
  $ aitm web --no-open
  $ aitm scope add --host app.example.test
  $ aitm flow table

Learn more:
  aitm <group>              a group's verbs (aitm scope)
  aitm <group> <verb> --help
                            a verb's flags and examples (aitm scope add --help)
  aitm web --help           the web UI's options

Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>
Trust the CA:  aitm ca install
```

With `AITM_NO_BUNDLED_SCRIPTS=1` the `check` and `l4` rows are absent (17 groups). The first line, the `Groups:` heading and the literal `aitm scope add --host <host>` are what `term-reporting.sh` §1 pins, unchanged. Piped: the same bytes with zero `0x1b` (AC-W2-1).

### M-W2-2. `aitm scope` (= `aitm help scope` = `aitm scope --help`)

The real verbs are `add`, `remove`, `list` (spec M3's `example` verb does not exist; the real `scope.add` sentence has an Oxford comma).

```text
aitm scope — which hosts are decrypted

Usage:
  aitm scope <verb> [--flag <value>]...

Verbs:
  add --host <host>         Add a host, host:port, or *.wildcard to Scope.
  remove --host <host>      Remove a scope entry (exact match).
  list                      List the current scope entries.

Examples:
  $ aitm scope add --host app.example.test
  $ aitm scope add --host '*.example.test'
  $ aitm scope list

Nothing is decrypted until a host is in Scope.
```

### M-W2-3. `aitm scope add --help` (= `aitm help scope add`)

```text
Add a host, host:port, or *.wildcard to Scope. New connections to it are
decrypted from now on; hosts outside Scope are tunnelled. Refused from an agent
frontend (MCP) unless scope.allow_agent_widen is set.

Usage:
  aitm scope add --host <host>

Flags:
  --host <string>           The scope entry to add. [required]

Examples:
  $ aitm scope add --host app.example.test
  $ aitm scope add --host '*.example.test'

Nothing is decrypted until a host is in Scope.
```

A verb with optional flags, for the shapes: `aitm flow detail --help` has `Usage:` `  aitm flow detail --id <id> [--body <body>] [--offset <offset>] [--length <length>]` (wrapped at 80 with a four-space continuation when needed) and `Flags:` rows `--id <flow-id>`, `--body <string>` with the description `Body mode: \`none\`, \`inline\` (default), or \`range\`.` verbatim (C46).

### M-W2-4. Did-you-mean (AC-W2-3), `aitm scpe add --host x`, exit 2

TTY:

```text
✕ unknown command `scpe`
  did you mean: scope

  ▸ aitm --help

  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log
```

Plain (`2>file`):

```text
error: unknown command `scpe`
  did you mean: scope
  fix: aitm --help
  log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log
```

(The `Log` footer is there because this error is post-boot, C33.) `aitm scope ad` → `unknown command \`scope ad\`` / `did you mean: scope add` / `▸ aitm scope`. `aitm flow list --bogus 1` → `unknown flag --bogus for \`flow list\`` / `Usage: aitm flow list` / `▸ aitm flow list --help`. `aitm help scpe` (explicit, pre-boot) → the same panel without the `Log` footer.

### M-W2-5. The `Usage:`-form errors (AC-W2-5), plain forms as the scripts read them; exit 2 each

```text
error: tui takes no further arguments, got `--bad`
  Usage: aitm [--config <path>] tui
  fix: aitm --help
```

```text
error: operator-token needs a verb
  Usage: aitm [--config <path>] operator-token generate [--force]
  fix: aitm --help
```

```text
error: unknown argument to `aitm web`: --bad
  Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]
  fix: aitm web --help
```

```text
error: expected a command before flags, got `--bad`
  Usage: aitm <group> <verb> [--flag <value>]...
  fix: aitm --help
  log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log
```

(The last one is post-boot today and stays so, C33; the rich forms are `✕ <what>`, the indented lines, a blank, `  ▸ <command>`.)

### M-W2-6. The `[y/N]` prompt (AC-W2-8), `aitm ca install` on a TTY, width 80

```text
Install the aitmproxy root CA into the login keychain (scope user)?
  SHA-256 5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE
  Every TLS client that uses that store will then trust certificates this proxy
  mints. The embedded obscura browser is unaffected; it trusts the CA via
  --ca-cert.
Install it? [y/N] 
```

The `SHA-256` line is dim and printed whole (105 columns; the terminal wraps it); the question wraps at width when the real location path is long; `n` or EOF answers no and the command ends `aborted: ca install not run` (exit 1, no dotted name). The uninstall prompt is `Remove the aitmproxy root CA from <location> (scope <scope>)?` / `  SHA-256 <fp>` / `Remove it?`.

### M-W2-7. `aitm web --help` (restyled through the same renderer; the Homebrew phrase kept)

```text
aitm web — the proxy and the web operator UI

Run the proxy (as `aitm` does) and also serve the web operator UI.

Usage:
  aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]

Options:
  --listen <addr>           Bind address for the UI and its /bus bridge
                            [default: 127.0.0.1:8082; env: AITM_WEB_LISTEN]
  --token <token>           Bridge token the UI must present as its first
                            message [default: generated; env: AITM_WEB_TOKEN]
  --no-open                 Do not open a browser (accepted; nothing is opened
                            yet)
  -h, --help                Print this help

Non-loopback addresses are refused until TLS for remote access lands (F15); use
an SSH tunnel, or set AITM_WEB_INSECURE_BIND=1 to bind anyway.
```

(The option sentences are today's `web::USAGE` text verbatim, hence capitalised.) `aitm tui --help`: title `aitm tui — the proxy and the terminal operator UI`, about `Run the proxy (as \`aitm\` does) and the terminal operator UI in this terminal; tracing goes to the log file, never to the screen.`, usage `aitm [--config <path>] tui`. `aitm operator-token --help`: title `aitm operator-token — the operator token`, about `Write a new random mcp.operator_token into the config file and print a confirmation (never the token); --force replaces an existing one. Restart aitm afterwards.`, usage `aitm [--config <path>] operator-token generate [--force]`.

---

## Tasks

### Task 1: `aitm-term` skeleton — two new modules declared, `Caps::detect_stdout`, `ErrorReport: Display + Error`

- **Satisfies:** the seams for AC-W2-1 (stdout caps), AC-W2-3/4/5 (typed errors), AC-W2-8 (prompt module).
- **Depends on:** none.
- **Shared-worktree rule:** rule 10; `lib.rs` is a crate root — verify with `cargo fmt -p aitm-term -- --check`, never `rustfmt` it.
- **Files:** `crates/aitm-term/src/lib.rs` (modify: `pub mod help;` after `glyphs`, `pub mod prompt;` after `help` — the only `lib.rs` edit of the wave, C1), `crates/aitm-term/src/caps.rs` (modify, additive), `crates/aitm-term/src/error.rs` (modify, additive), `crates/aitm-term/src/help.rs` (create, a `//!` stub for T2), `crates/aitm-term/src/prompt.rs` (create, a `//!` stub for T3).
- **Change:**
  - `caps.rs`: `impl Caps { pub fn detect_stdout(color: ColorChoice) -> Caps }` — `std::io::stdout().is_terminal()`, `measure_width()` only when that is true, then `from_parts(.., &|k| std::env::var(k).ok())`; doc: the mirror of `detect_stderr` for the help pages (C49).
  - `error.rs`: `impl std::fmt::Display for ErrorReport` — `what`, then `"\n  " + why` for each `why`, then `"\n  " + fix` when set; `command` and `log` are rendering concerns and are not part of `Display`. `impl std::error::Error for ErrorReport {}`. Doc on the struct: "also the typed usage error `aitm-cli` returns (plan C35); `report_for` passes it through".
- **Tests** (`error.rs`):
  - `display_is_the_headline_and_indented_causes`: `ErrorReport::usage("unknown command `scpe`").with_why(vec!["did you mean: scope".into()]).to_string() == "unknown command `scpe`\n  did you mean: scope"`; `ErrorReport::failure("x").to_string() == "x"`.
  - `error_report_round_trips_through_anyhow`: `let r = ErrorReport::usage("a").with_command("aitm scope"); anyhow::Error::new(r.clone()).downcast_ref::<ErrorReport>() == Some(&r)`.
- **Done when:** `cargo clippy -p aitm-term --all-targets --offline -- -D warnings && cargo test -p aitm-term --offline` pass; `cargo fmt -p aitm-term -- --check` passes; `git diff Cargo.lock` is empty.

### Task 2: `aitm-term/src/help.rs` — the `HelpPage` model and renderer

- **Satisfies:** AC-W2-1 (aligned columns, dim wrapped descriptions, plain when piped), AC-W2-2 (page shapes), AC-W2-7 (one renderer), T1–T5 for help.
- **Depends on:** T1.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm-term/src/help.rs` (replace the stub).
- **Change:**
  `pub const DESC_COL: usize = 28; pub const LEFT_MAX: usize = 24; pub const USAGE_CONT_INDENT: &str = "    ";`
  `#[derive(Debug, Clone, PartialEq, Eq)] pub struct HelpRow { pub left: String, pub right: String }`; `pub struct HelpSection { pub heading: String, pub rows: Vec<HelpRow> }`; `pub enum Block { Section(HelpSection), Examples(Vec<String>), Text(Vec<String>) }`; `pub struct HelpPage { pub title: String, pub about: Vec<String>, pub usage: Vec<String>, pub blocks: Vec<Block> }` (C41, C27 derives).
  `pub fn row_lines(left: &str, right: &str, width: usize) -> Vec<String>` (C40, unpainted); `pub fn wrap_usage(line: &str, width: usize) -> Vec<String>` (a usage line is split into units — a unit is a run of tokens starting at a token that begins with `--` or `[`, so `--length <length>` and `[--length <length>]` are one unit each — and packed greedily into lines of at most `width − 4` columns, the first prefixed `"  "`, the rest `USAGE_CONT_INDENT`; a unit wider than the room stands alone); `pub fn help_page(caps: &Caps, page: &HelpPage) -> String`.
  Rendering order: `title` (when non-empty) then a blank line; each `about` paragraph `text::wrap(p, width, "")` then a blank line; `Usage:` heading + each usage line through `wrap_usage`, then a blank line; each block, separated by one blank line: `Section` → heading + `row_lines` per row (empty `left` → the right text as indented, unwrapped-at-28 but width-wrapped plain lines starting at column 2 — reserved for future use, not used by W2 pages); `Examples` → `Examples:` + `"  $ " + example` (never wrapped, C40); `Text` → paragraphs wrapped at `width` with no indent, one blank line between paragraphs. The output ends with exactly one `\n` and has no trailing blank line. Rich (`caps.animate && caps.color`): headings `paint(Bold)`, every physical description line `paint(Dim)`; otherwise no SGR at all. Every content string passes `text::sanitize` first. When `!caps.unicode`: `·` → `glyphs.sep`, `…` → `glyphs.ellipsis` on every line, and the title's ` — ` → ` - ` (C41). Width = `usize::from(caps.width)`.
- **Tests:**
  - `row_that_fits_pads_to_the_description_column`: `row_lines("add --host <host>", "Add a host, host:port, or *.wildcard to Scope.", 80) == vec!["  add --host <host>         Add a host, host:port, or *.wildcard to Scope."]`.
  - `row_too_wide_for_the_left_column_breaks_before_its_description`: `row_lines("aitm <group> <verb> [--flag <value>]...", "run one command and exit", 80) == vec!["  aitm <group> <verb> [--flag <value>]...", "                            run one command and exit"]`.
  - `row_description_wraps_at_the_description_column`: `row_lines("flow", "captured flows: list, inspect, intercept, replay, edit, export and import", 80) == vec!["  flow                      captured flows: list, inspect, intercept, replay,", "                            edit, export and import"]`.
  - `help_page_plain_renders_the_scope_page`: the M-W2-2 `HelpPage` (title `aitm scope — which hosts are decrypted`, usage `["aitm scope <verb> [--flag <value>]..."]`, blocks `[Section("Verbs:", 3 rows), Examples(3), Text(["Nothing is decrypted until a host is in Scope."])]`) rendered with `piped_utf8()` equals the M-W2-2 block byte for byte (ending `"Nothing is decrypted until a host is in Scope.\n"`).
  - `help_page_rich_paints_headings_bold_and_descriptions_dim_only`: with `tty80()` the same page contains `"\x1b[1mUsage:\x1b[0m\n"` and `"  list                      \x1b[2mList the current scope entries.\x1b[0m\n"`, the examples lines carry no `0x1b`, and `text::strip_sgr(&rich) == plain`.
  - `help_page_plain_never_emits_an_escape_even_with_colour_forced`: `Caps { tty: false, color: true, unicode: true, animate: false, width: 80, ci: false }` → no `0x1b` byte (C6).
  - `help_page_about_wraps_at_width`: about = the `scope.add` description → the first three lines of M-W2-3 exactly: `"Add a host, host:port, or *.wildcard to Scope. New connections to it are\n"`, `"decrypted from now on; hosts outside Scope are tunnelled. Refused from an agent\n"`, `"frontend (MCP) unless scope.allow_agent_widen is set.\n"`.
  - `help_page_usage_continuation_indents_four`: usage `["aitm findings record --title <title> --class <class> --severity <severity> --target <target> --poc_ref <poc_ref>"]` at width 80 → `"  aitm findings record --title <title> --class <class> --severity <severity>\n    --target <target> --poc_ref <poc_ref>\n"`.
  - `wrap_usage_never_splits_a_flag_from_its_placeholder`: `wrap_usage("aitm flow detail --id <id> [--body <body>] [--offset <offset>] [--length <length>]", 80) == vec!["  aitm flow detail --id <id> [--body <body>] [--offset <offset>]", "    [--length <length>]"]` (a plain word wrap would have put `[--length` on the first line).
  - `help_page_narrow_width_keeps_twenty_columns_for_descriptions`: width 40, the `flow` row → every description line is ≤ 48 columns wide and starts at column 28 (room is `max(40 − 28, 20) = 20`).
  - `help_page_sanitizes_content`: a row right `"x\x1b]0;evil\x07y"` renders with no `0x1b`, no `0x07` and a U+FFFD.
  - `help_page_ascii_substitutes_separator_ellipsis_and_the_title_dash`: `Caps::plain()` (unicode false) → title `aitm scope - which hosts are decrypted`; a `Text` line `a · b …` → `a - b ...`.
- **Done when:** the twelve tests pass and the `aitm-term` package gate passes.

### Task 3: `aitm-term/src/prompt.rs` — `ConfirmPrompt` and `render_confirm`

- **Satisfies:** AC-W2-8 (unit half), D16's prompt-through-the-layer clause, D14.
- **Depends on:** T1.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm-term/src/prompt.rs` (replace the stub).
- **Change:**
  `pub const YES_NO: &str = "[y/N]";` `#[derive(Debug, Clone, PartialEq, Eq)] pub struct ConfirmPrompt { pub question: String, pub details: Vec<String>, pub notes: Vec<String>, pub ask: String }`; `impl ConfirmPrompt { pub fn parse(text: &str) -> ConfirmPrompt }` per C47 (lines split on `\n`; blank lines skipped; the first line is `question`; a line starting with two spaces is a `detail` (trimmed); the last line, when there is more than one line and it ends with `?` and is not a detail, is `ask`; everything else is a `note`; a single-line text is `question` only with `ask == ""`). `pub fn render_confirm(caps: &Caps, prompt: &ConfirmPrompt) -> String`: question `text::wrap(q, width, "")` lines; each detail as `"  " + paint(Dim, detail)` whole; each note `text::wrap(note, width, "  ")`; then `ask + " " + YES_NO + " "` when `ask` is non-empty, else ` [y/N] ` is appended to the question's last line instead. Every string sanitized; ASCII substitution as in T2; no trailing newline (the cursor waits after the space). Plain when `!caps.animate || !caps.color`.
- **Tests:**
  - `parse_splits_question_details_notes_and_ask`: the CA text `"Install the aitmproxy root CA into the login keychain (scope user)?\n  SHA-256 AB:CD\nEvery TLS client that uses that store will then trust certificates this proxy mints. The embedded obscura browser is unaffected; it trusts the CA via --ca-cert.\nInstall it?"` → `ConfirmPrompt { question: "Install the aitmproxy root CA into the login keychain (scope user)?", details: ["SHA-256 AB:CD"], notes: ["Every TLS client … --ca-cert."], ask: "Install it?" }`.
  - `parse_single_line_is_a_bare_question`: `"Inject 1 packet to 127.0.0.1:9 on lo0?"` → `question` = the text, `details`/`notes` empty, `ask == ""`.
  - `render_confirm_puts_the_fingerprint_on_its_own_line` (`piped_utf8()`): with the 95-character fingerprint `5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE` the output equals `"Install the aitmproxy root CA into the login keychain (scope user)?\n  SHA-256 5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE\n  Every TLS client that uses that store will then trust certificates this proxy\n  mints. The embedded obscura browser is unaffected; it trusts the CA via\n  --ca-cert.\nInstall it? [y/N] "` (M-W2-6).
  - `render_confirm_single_line_appends_the_tail`: `"Inject 1 packet to 127.0.0.1:9 on lo0? [y/N] "`.
  - `render_confirm_rich_dims_the_details_only`: `tty80()` → the detail line is `"  \x1b[2mSHA-256 …\x1b[0m\n"` and the ask line carries no `0x1b`.
  - `render_confirm_plain_has_no_escape_byte`.
- **Done when:** the six tests pass and the package gate passes.

### Task 4: `aitm-cli` skeleton — the `aitm-term` edge and `suggest.rs`

- **Satisfies:** AC-W2-3 (did-you-mean), AC-W2-10 (own edit distance, no crate).
- **Depends on:** none.
- **Shared-worktree rule:** rule 10; `crates/aitm-cli/src/lib.rs` is a crate root — verify with `cargo fmt -p aitm-cli -- --check`.
- **Files:** `crates/aitm-cli/Cargo.toml` (modify: `aitm-term.workspace = true` with the comment `# Typed usage errors (ErrorReport) and the [y/N] prompt renderer (CLI terminal reporting wave 2).`), `Cargo.lock` (cargo adds the one edge), `crates/aitm-cli/src/lib.rs` (modify: `pub mod suggest;` after `pub mod dispatch;`; module doc gains one sentence on did-you-mean and typed errors), `crates/aitm-cli/src/suggest.rs` (create).
- **Change:** `pub const MAX_DISTANCE: usize = 2; pub const MAX_SUGGESTIONS: usize = 3;` `pub fn distance(a: &str, b: &str) -> usize` (optimal string alignment Damerau–Levenshtein over `char`s: insert, delete, substitute, adjacent transposition; case-sensitive); `pub fn suggest<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str>` (C37's two rules: the distinct candidates that start with a non-empty `input`, else the distinct candidates at the minimum `distance ≤ MAX_DISTANCE`; sorted by name, truncated to `MAX_SUGGESTIONS`); `pub fn did_you_mean(suggestions: &[&str]) -> Option<String>` (`None` when empty, else `format!("did you mean: {}", suggestions.join(", "))`).
- **Tests:**
  - `distance_counts_edits_and_one_transposition`: `distance("scpe", "scope") == 1`, `distance("scoep", "scope") == 1`, `distance("flwo", "flow") == 1`, `distance("abc", "abc") == 0`, `distance("", "abc") == 3`, `distance("kitten", "sitting") == 3`, `distance("ca", "ab") == 2`.
  - `suggest_returns_close_names_sorted_and_capped`: with the 19 group names, `suggest("scpe", …) == vec!["scope"]`, `suggest("sc", …) == vec!["scan", "scope", "script"]` (rule 1), `suggest("scpe", …)` is `["scope"]` and not `["scope", "scan"]` (rule 2: `scan` is at distance 2, `scope` at 1), `suggest("flwo", …) == vec!["flow"]`, `suggest("zzzzzz", …).is_empty()`; `suggest("a", ["ab", "ac", "ad", "ae"]) == vec!["ab", "ac", "ad"]`; `suggest("tabel", ["list", "get", "table"]) == vec!["table"]`; duplicates collapse: `suggest("ab", ["abc", "abc"]) == vec!["abc"]`.
  - `did_you_mean_joins_with_commas`: `did_you_mean(&["scope", "script"]) == Some("did you mean: scope, script".into())`; `did_you_mean(&[]) == None`.
- **Done when:** `cargo clippy -p aitm-cli --all-targets --offline -- -D warnings && cargo test -p aitm-cli --offline --lib` pass; `cargo fmt -p aitm-cli -- --check` passes; `git diff Cargo.lock` shows only the `aitm-term` edge under `aitm-cli`.

### Task 5: `aitm-cli/src/dispatch.rs` — `locate`, typed usage errors, spaced names, help pointers

- **Satisfies:** AC-W2-3 (did-you-mean texts), AC-W2-4 (no dotted name in any dispatcher error), AC-W2-5 (`aitm --bad`'s `Usage:` line), D6 rule 4's W2 clause, D15 bullets 3–5.
- **Depends on:** T1, T4.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm-cli/src/dispatch.rs` (modify), `crates/aitm-cli/tests/cli.rs` (modify: the four assertions named below).
- **Change:**
  - New `pub` items: `pub const USAGE_FORM: &str = "Usage: aitm <group> <verb> [--flag <value>]...";` `pub const TOP_HELP: &str = "aitm --help";` `pub fn spaced(dotted: &str) -> String` (`'.'` → `' '`); `pub fn group_help(group: &str) -> String` (`aitm <group>`); `pub fn verb_help(dotted: &str) -> String` (`aitm <spaced> --help`); `pub fn type_hint(ty: &TypeDesc) -> &'static str` (now `pub`, same words); `pub fn placeholder(def: &ParamDef) -> String` (`<true|false>` for `Bool`, else `<{name}>`, C42); `pub fn usage_form(cmd: &dyn Command) -> String` (`aitm <spaced>` + ` --name <placeholder>` per required param + ` [--name <placeholder>]` per optional, schema order); `pub fn usage_line(cmd: &dyn Command) -> String` (`"Usage: " + usage_form`); `pub fn group_usage_line(group: &str) -> String` (`Usage: aitm <group> <verb> [--flag <value>]...`).
  - `pub enum Located<'a> { Group { name: String, commands: Vec<&'a Arc<dyn Command>> }, Command { cmd: &'a Arc<dyn Command>, rest: &'a [String] } }` (derive `Debug`).
  - `pub fn locate<'a>(&'a self, argv: &'a [String]) -> Result<Located<'a>, ErrorReport>` (replaces the private `resolve`): empty argv → `usage("expected a command").with_why([USAGE_FORM]).with_command(TOP_HELP)`; a leading flag → `usage(format!("expected a command before flags, got `{tok}`"))` + `USAGE_FORM` + `TOP_HELP`; `path` = leading non-flag tokens; the longest prefix of `path` whose dotted join is a registered command wins → `Command { cmd, rest: &argv[prefix_len..] }` (so `aitm scope add extra --host x` resolves `scope.add` with `rest = ["extra", "--host", "x"]`); else when `path.len() == 1` and some command starts with `"{path[0]}."` → `Group { name, commands }` (registration order); else: when `path[0]` is a group → `usage(format!("unknown command `{}`", path.join(" ")))` + `did_you_mean(suggest(path[1], that group's verbs))` written as spaced full names (`scope add`) + `group_help(path[0])`; otherwise `usage(format!("unknown command `{}`", path[0]))` + `did_you_mean(suggest(path[0], groups))` + `TOP_HELP` (C37). An already-dotted token (`flow.get`) still resolves (one token, dotted join unchanged).
  - `fn parse_flags(tokens, cmd: &dyn Command) -> Result<Params, ErrorReport>`: a non-flag token → `unexpected argument `{tok}` for `{spaced}``; unknown flag → `unknown flag --{name} for `{spaced}`` with `did_you_mean(suggest(name, schema flag names))` as the first `why` when any; duplicates `flag --{name} given more than once`; `flag --{name} needs a value`; value errors `flag --{name}: {e}`; `missing required flag --{name} for `{spaced}``. Every one gets `.with_why(.. + [usage_line(cmd)]).with_command(verb_help(cmd.name()))` (the `accepted: …` list is dropped — the usage line lists the flags).
  - `dispatch`: `locate` → `Group { name, .. }` → `Err(usage(format!("missing verb after `{name}`")).with_why([group_usage_line(&name)]).with_command(group_help(&name)))` (C38); `Command` → `--yes` filter over `rest` → `parse_flags` → confirm with `.with_context(|| spaced(cmd.name()))` → a "no" → `anyhow::bail!("aborted: {} not run", spaced(cmd.name()))` → `invoke`. Every `ErrorReport` is returned as `anyhow::Error::new(report)`.
  - `usage()`: first line `USAGE_FORM` (C39); the `--yes` sentence and the rows unchanged.
  - Module doc: the typed-error contract (C35), help pointers, and that help pages themselves are built by the binary over `locate`.
  - `tests/cli.rs`: line 374–380 — `dispatch(&[])` now asserts `e.contains("expected a command") && e.contains("Usage: aitm <group> <verb>")` (the registry dump is gone); line 379 → `` e.contains("unknown command `flow nope`") ``; line 392's `e.contains("--id")` still holds through the usage line; any `aborted: … not run` assertion → the spaced form.
- **Tests** (unit, `dispatch.rs`, over a registry of fakes `flow.get --id <flow-id> [--body <string>]`, `flow.list`, `scope.add --host <string>`, `scope.list`, `browser.confine --on <bool>`, `ca.install` whose `confirm_prompt` is `Some("Install it?")`, `tls.passthrough.add --host`; `Cli` built as the existing `cli()` helper with a `Confirmer` fake):
  - `locate_names_the_unknown_group_and_suggests`: `["scpe", "add", "--host", "x"]` → `Err(r)` with `r.what == "unknown command `scpe`"`, `r.why == vec!["did you mean: scope"]`, `r.command == Some(FixCommand("aitm --help".into()))`, `r.exit_code() == 2`.
  - `locate_names_the_unknown_verb_inside_a_known_group`: `["scope", "ad"]` → `what == "unknown command `scope ad`"`, `why == ["did you mean: scope add"]`, `command == Some(FixCommand("aitm scope".into()))`.
  - `locate_returns_the_group_for_a_bare_group`: `["scope"]` → `Located::Group { name == "scope", commands names == ["scope.add", "scope.list"] }`.
  - `locate_resolves_the_longest_command_prefix`: `["tls", "passthrough", "add", "--host", "h"]` → `Command` named `tls.passthrough.add` with `rest == ["--host", "h"]`; `["scope", "add", "extra"]` → `Command` with `rest == ["extra"]`.
  - `locate_rejects_a_leading_flag_with_the_usage_form`: `["--bad"]` → `what == "expected a command before flags, got `--bad`"`, `why == ["Usage: aitm <group> <verb> [--flag <value>]..."]`, command `aitm --help`; `[]` → `what == "expected a command"`.
  - `dispatch_trailing_token_is_an_unexpected_argument`: `["scope", "add", "extra"]` → `what == "unexpected argument `extra` for `scope add`"`, `why == ["Usage: aitm scope add --host <host>"]`, command `aitm scope add --help`.
  - `dispatch_flag_errors_carry_the_usage_line_and_the_verb_help`: `["flow", "get", "--bogus", "1"]` → `what == "unknown flag --bogus for `flow get`"`, `why == ["Usage: aitm flow get --id <id> [--body <body>]"]`, command `aitm flow get --help`; `["flow", "get", "--di", "x"]` → `why == ["did you mean: --id", "Usage: aitm flow get --id <id> [--body <body>]"]`; `["scope", "add"]` → `what == "missing required flag --host for `scope add`"`; `["flow", "get", "--id"]` → `what == "flag --id needs a value"`; `["flow", "get", "--id", "not-a-uuid"]` → `what` starts with `"flag --id: not a valid flow id"`; `["flow", "get", "--id", "x", "--id", "y"]` → `what == "flag --id given more than once"`.
  - `dispatch_bare_group_points_at_the_group_page`: `["scope", "--yes"]` → `what == "missing verb after `scope`"`, `why == ["Usage: aitm scope <verb> [--flag <value>]..."]`, command `aitm scope`.
  - `dispatch_declined_confirmation_names_the_spaced_command`: a `Confirmer` answering `Ok(false)` → `dispatch(["ca", "install"])` error text `== "aborted: ca install not run"`.
  - `no_dispatcher_error_carries_a_dotted_command_name` (AC-W2-4): collects every `ErrorReport` (and the aborted text) from the cases above and asserts the regex `[a-z_]+\.[a-z_]+` matches none of `what`, any `why`, `fix`, `command`.
  - `usage_first_line_is_the_usage_form`: `cli.usage().lines().next() == Some("Usage: aitm <group> <verb> [--flag <value>]...")`; the text still contains `--yes` exactly once.
  - `usage_form_uses_name_placeholders_and_brackets_optionals`: `usage_form(flow.get) == "aitm flow get --id <id> [--body <body>]"`; `usage_form(browser.confine) == "aitm browser confine --on <true|false>"`; `spaced("tls.passthrough.add") == "tls passthrough add"`; `verb_help("scope.add") == "aitm scope add --help"`.
  - `errors_downcast_to_error_report`: `dispatch(["scpe"]).unwrap_err().downcast_ref::<ErrorReport>().is_some()`.
- **Done when:** the thirteen unit tests and `cargo test -p aitm-cli --offline --test cli` pass; the package gate passes.

### Task 6: `aitm-cli/src/confirm.rs` — the prompt through the layer

- **Satisfies:** AC-W2-8 (wiring half), D14 (confirm.rs leaves the allow-list in T15).
- **Depends on:** T3, T4.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm-cli/src/confirm.rs` (modify).
- **Change:** `TtyConfirmer { interactive: bool, caps: Caps }`; `from_stdin()` and `new(interactive)` set `caps = Caps::detect_stderr(ColorChoice::Auto)`; `pub fn with_caps(mut self, caps: Caps) -> Self`. `confirm` calls `pub(crate) fn confirm_with(&self, prompt: &str, out: &mut dyn Write, input: &mut dyn BufRead) -> anyhow::Result<bool>` with locked stderr and stdin: non-interactive → the existing `bail!` text unchanged; interactive → `out.write_all(aitm_term::prompt::render_confirm(&self.caps, &ConfirmPrompt::parse(prompt)).as_bytes())`, flush, `read_line`, `is_yes`. Module doc updated (the structured prompt, C47).
- **Tests:**
  - `interactive_prompt_renders_through_the_layer`: `TtyConfirmer::new(true).with_caps(piped_utf8())`, the M-W2-6 prompt text, input `"n\n"` → `Ok(false)` and `out` equals the M-W2-6 literal (as in T3's test).
  - `yes_and_eof`: `"y\n"` → `Ok(true)`; `"YES\n"` → `Ok(true)`; `""` → `Ok(false)`.
  - `non_interactive_refuses_and_points_at_yes`: `TtyConfirmer::new(false)` → `Err` whose text contains `pass --yes to confirm non-interactively`; `out` is empty.
- **Done when:** the three tests pass and the package gate passes.

### Task 7: `aitm-ca` — the install/uninstall prompt in the structured shape

- **Satisfies:** AC-W2-8 (the fingerprint line exists to be printed on its own).
- **Depends on:** none.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm-ca/src/commands.rs` (modify: `Op::prompt` only), `crates/aitm-ca/tests/commands.rs` (modify: `confirm_prompts`).
- **Change:** `Op::Install` → `format!("Install the aitmproxy root CA into {location} (scope {scope})?\n  SHA-256 {fingerprint}\nEvery TLS client that uses that store will then trust certificates this proxy mints. The embedded obscura browser is unaffected; it trusts the CA via --ca-cert.\nInstall it?")`; `Op::Uninstall` → `format!("Remove the aitmproxy root CA from {location} (scope {scope})?\n  SHA-256 {fingerprint}\nRemove it?")`. Doc comment on `prompt`: the line protocol (C47) and that the CLI renders it through `aitm_term::prompt`.
- **Tests** (`tests/commands.rs::confirm_prompts`): `p.starts_with("Install the aitmproxy root CA into ")`; `p.contains(&format!("\n  SHA-256 {FIXTURE_FP256}\n"))`; `p.contains(&format!("into {K_USER} (scope user)?"))`; `p.contains(OBSCURA_FLAG)`; `p.ends_with("\nInstall it?")`; the system-scope assertion unchanged; the uninstall prompt `== format!("Remove the aitmproxy root CA from {K_USER} (scope user)?\n  SHA-256 {FIXTURE_FP256}\nRemove it?")`.
- **Done when:** `cargo test -p aitm-ca --offline --test commands` passes and the `aitm-ca` package gate passes.

### Task 8: `aitm` skeleton — `describe` and `help` declared, stubs for the leaf modules

- **Satisfies:** the C1 discipline for T9–T14.
- **Depends on:** none.
- **Shared-worktree rule:** rule 10; `crates/aitm/src/lib.rs` and `help/mod.rs` are roots — verify with `cargo fmt -p aitm -- --check`, never `rustfmt` them.
- **Files:** `crates/aitm/src/lib.rs` (modify: `pub mod describe;` after `config_file`, `pub mod help;` after `env`; the crate doc gains one sentence: "`describe` assembles the schema-only command registry help and the pins read; `help` builds the pages"), `crates/aitm/src/describe.rs` (create, `//!` stub), `crates/aitm/src/help/mod.rs` (create: module doc naming the four leaves and that this file is never edited again in wave 2; `pub mod answer; pub mod catalog; pub mod pages; pub mod request;`), `crates/aitm/src/help/{answer,catalog,pages,request}.rs` (create, `//!` stubs).
- **Done when:** `cargo build -p aitm --offline` passes; `cargo clippy -p aitm --offline -- -D warnings` passes; `cargo fmt -p aitm -- --check` passes.

### Task 9: `describe.rs` — the schema-only registry, and its pin against the live registry

- **Satisfies:** AC-W2-6 (the generated list equals the live registry's names; `l4` with `l4.enabled`), AC-W2-2 (nothing booted), D15 bullet 1 (as C28).
- **Depends on:** T8, and the one-word pre-step `pub fn type_hint` in `crates/aitm-cli/src/dispatch.rs` (done by the session lead on 2026-11-01 when T9 found it private; T5 keeps it `pub`).
- **Shared-worktree rule:** rule 10. **No edit to `wire.rs`.** `wire::PocCommands` is a private struct of the frozen file, so `describe.rs` carries a private twin (`struct PocProvider { executor, step_handlers }` whose `load` makes the same three calls in the same order: `aitm_poc::builder::register(reg)`, `aitm_poc::runner::register_with_executor_and_steps(reg, executor, step_handlers)`, `aitm_poc::library::register(reg)`); the registry pin guards the duplication like the rest of C28, and follow-up 1 removes it with the shared builder.
- **Files:** `crates/aitm/src/describe.rs` (replace the stub), `crates/aitm/tests/describe_registry.rs` (create), `crates/aitm/tests/support/mod.rs` (modify: add `live_commands`; leave `built_in_groups` in place — T12 removes it with its callers).
- **Change:**
  - `pub struct DescribeInputs<'a> { pub settings: &'a config_file::Settings, pub script_args: &'a [PathBuf], pub env: &'a dyn Fn(&str) -> Option<String> }`; `pub struct Described { pub registry: Arc<Registry>, pub script_errors: Vec<String>, runtime: tokio::runtime::Runtime }`; `pub fn registry(inputs: &DescribeInputs) -> anyhow::Result<Described>`; `pub fn groups(registry: &Registry) -> Vec<(String, Vec<Arc<dyn Command>>)>` (alphabetical groups, verbs in registration order, C50); `pub fn fingerprint(schema: &ParamSchema) -> String` (`"{description}|{name}:{type_hint}:{required};…|{result type_hint}"` using `aitm_cli::dispatch::type_hint`); `pub fn is_group(registry: &Registry, name: &str) -> bool`.
  - `registry()` composes, in order: clone `settings.core`/`rhai`/`l4` and apply `env::apply`, `env::apply_rhai`, `env::apply_l4` with `inputs.env`; `rhai.ssrf = core.browser.ssrf.clone()`; `bundled::apply(&mut rhai, inputs.env)`; extend `rhai.scripts` with `script_args` as `ScriptEntry::new`; build a `tokio::runtime::Builder::new_current_thread().enable_all().build()?`; `LateHandles::new()` + `MemoryFindingSink` + `ScriptServices { rt: runtime.handle().clone(), .. }`; `l4_shared` + `L4Language` when `l4.enabled` (same as `run()`), `aitm_scan_ws::language(handles.clone())`; `build_with_languages(rhai, services, &languages)?` (C29); `script_errors = tier.errors.iter().map(ToString::to_string)`; then `Registry::new()` and `add_plugin` for, in `wire.rs` order: `CapturePlugin::new()`, `SubscriptionPlugin::new(broadcast::channel(aitm_mcp::DEFAULT_BROADCAST_CAPACITY).0)`, `DetailPlugin::new()`, `MetaPlugin::new()`, `ScannerPlugin::new(ScannerConfig::default()).with_lanes(wire::collect_lanes(l4_shared.as_ref())).with_native_checks(wire::collect_native_checks())`, `ReplayPlugin::new()`, `InterceptPlugin::new()` (keeping its `armed_flag()`), `ControlPlugin::new(armed, listening).with_system_proxy(sysproxy)` where `sysproxy = Arc::new(SystemProxy::with_mechanism(Arc::new(aitm_ca::exec::RealExecutor::new()), &settings.system_proxy, aitm_sysproxy::ours_from(core.listen), None, Mechanism::None))`, `SysProxyPlugin::new(sysproxy, listening)`, `CaptureStatusPlugin::new(CaptureStatus::channel(settings.macos_capture.enabled).1)`, `MutatePlugin::new()` (`Features::default().mutate` is true), `ScopePlugin::new(core.scope.allow_agent_widen)`, `RateLimitPlugin::new(core.limits.per_host_rps)`, `WsCtlPlugin::new()`, `SessionIoPlugin::new(core.session_io.allow_agent_file_io).with_session_root(core.session_io.root.clone())`, `PassthroughPlugin::new(core.tls.passthrough.clone(), core.tls.allow_agent_passthrough)`, `MapRulesPlugin::new(core.maps.root.clone().unwrap_or_default(), core.maps.allow_agent_authoring, Arc::new(StdGuard::default()))`, the tier's `host.with_max_body(..)` plugin, `BrowserPlugin::new(core.browser.ssrf.clone())`, the private twin `PocProvider { executor: Some(tier.executor.clone()), step_handlers: PocStepRegistry::new() + the l4/ws `poc_step` handlers as `run()` builds them }` (see the shared-worktree rule above), `CaPlugin::new(core.ca.clone())`, `AgentPlugin::new(Arc::new(AgentState::new(core.mcp.policy))).with_audit_ring(Arc::new(AuditRing::default()))`, `tier.commands`, `FindingsPlugin::new()`, and when `l4.enabled` the `L4Module::with_shared(shared.guard, shared.store, l4.intercept.clone(), L4Privilege::available())` (no probe). A doc block at the top names `wire::assemble_with_scripts` as the source of truth and the pin as the guard (C28), and the follow-up.
  - `tests/support/mod.rs`: `pub fn live_commands(features: &Features, rhai: RhaiConfig) -> Vec<(String, String)>` — the body of `built_in_groups` generalised (its own current-thread runtime, the `ScriptServices` with `LateHandles`, `build_with_languages(rhai, services, &[])`, `assemble_with_scripts` with the same `ScriptWiring`), returning `(name, describe::fingerprint(&schema))` in registration order and removing its temp CA dir. (`built_in_groups` stays until T12 deletes it.)
- **Tests** (`tests/describe_registry.rs`, plain `#[test]`s; the env closure is a `BTreeMap` lookup):
  - `describe_matches_the_live_registry_with_the_default_features`: `Settings` defaults with `core.ca.dir = temp_ca_dir("describe")`, env `{AITM_NO_BUNDLED_SCRIPTS: "1"}` → `describe::registry` names+fingerprints `==` `live_commands(&Features::default(), RhaiConfig::default())`; the group set is the 17 built-ins `agent browser ca capture config findings flow map poc proxy request scan scope script session tls ws`; and `!cfg.ca.dir.exists()` after `describe::registry` (rule 12).
  - `describe_matches_the_live_registry_with_l4_enabled`: `settings.l4.enabled = true` vs `Features { l4: L4Config { enabled: true, .. }, l4_privilege: Some(L4Privilege::available()), .. }` → equal; the `l4` group is present and `is_group(&reg, "l4")`.
  - `describe_with_the_bundled_catalogue_lists_check_and_l4_scripts`: env `{AITM_BUNDLED_SCRIPTS: <repo>/scripts/bundled}` on both sides (the live side's `RhaiConfig` via `bundled::append`) → equal; groups are the 19 names of M-W2-1; the `check` group has exactly 15 verbs; the `l4` group is exactly `["l4.recon", "l4.tcp_probe", "l4.udp_probe"]` when `l4.enabled` is off; `script_errors.is_empty()`.
  - `fingerprint_distinguishes_type_and_required`: two schemas differing only in `required` or in `ty` have different fingerprints; equal schemas have equal ones.
  - `groups_are_alphabetical_with_verbs_in_registration_order`: `groups()` over the catalogue registry → first group `agent`, last `ws`; `scope`'s verbs `["scope.add", "scope.remove", "scope.list"]`.
- **Done when:** `cargo test -p aitm --offline --test describe_registry` passes (it assembles but never serves — no port); the `aitm` package gate passes; `cargo test -p aitm --offline --test synopsis_groups --test synopsis_groups_l4` still pass (untouched until T12).

### Task 10: `help/catalog.rs` — group purposes and footers, the examples table, the top-page rows

- **Satisfies:** AC-W2-1 (purposes, examples, learn more), AC-W2-2 (at least one example per verb), C44–C46.
- **Depends on:** T9.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm/src/help/catalog.rs` (replace the stub).
- **Change:**
  `pub const TAGLINE: &str = "intercepting proxy for authorized security testing";` `pub struct GroupInfo { pub name: &'static str, pub purpose: &'static str, pub footer: Option<&'static str> }`; `pub const GROUPS: &[GroupInfo]` — the 19 entries of M-W2-1, alphabetical, with footers: `scope` → `aitm_core::NOTHING_DECRYPTED_ADVICE`; `l4` → `Most l4 verbs need l4.enabled in the config and capture privilege; recon and the probes are bundled scripts.`; `check` → `Active checks send requests to the target; run them only against hosts you are authorized to test.`; `ca` → `The embedded browser trusts this CA on its own (--ca-cert); install it for other TLS clients.`; the rest `None`. `pub fn group_info(name: &str) -> Option<&'static GroupInfo>`. `pub const EXAMPLES: &[(&str, &[&str])]` sorted by key, keys = every dotted command name of the 19-group registry (91 today) plus the group keys that want a curated set (`scope` → the three M-W2-2 lines; others optional), values per C45 (the Coder writes them from the command descriptions; `ca.install` carries `aitm ca install` and `aitm ca install --yes`; `flow.detail` carries `aitm flow detail --id 3f2a9c1e-7b10-4c4d-9e21-04ad5b6c7d8e --body range --offset 0 --length 512`). `pub fn examples_for(key: &str) -> &'static [&'static str]`. `pub const MODE_ROWS: &[(&str, &str)]` (the five `Usage:` rows of M-W2-1), `pub const OPTION_ROWS: &[(&str, &str)]` (the eight `Options:` rows), `pub const TOP_EXAMPLES: &[&str]` (the four), `pub const LEARN_MORE_ROWS: &[(&str, &str)]` (the three), `pub const TOP_FOOTER: &[&str]` (`Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>` built with the core const, and `Trust the CA:  aitm ca install`). `pub const NO_PURPOSE: &str = "(no description)";`
- **Tests:**
  - `groups_are_alphabetical_unique_and_nineteen`: names sorted, distinct, `len() == 19`, equal to the M-W2-1 list.
  - `every_registered_command_and_group_has_a_purpose_and_an_example`: `describe::registry` with the catalogue and `l4.enabled` → every group name has `group_info`, every `GROUPS` name is a registry group, every command name has `!examples_for(name).is_empty()`, and every `EXAMPLES` key is a registered command or group (so the table cannot carry a stale name).
  - `every_example_is_a_runnable_aitm_line`: each starts with `aitm `, has no `\n`, no trailing `.`, width ≤ 72, and its second and third words (when the key is dotted) equal the key's spaced form.
  - `examples_are_sorted_by_key_and_unique`.
  - `top_rows_match_the_mockup`: `MODE_ROWS[3] == ("aitm <group> <verb> [--flag <value>]...", "run one command and exit")`; `OPTION_ROWS[2] == ("--yes", "answer a verb's confirmation prompt without asking")`; `TOP_FOOTER == ["Nothing is decrypted until a host is in Scope.  aitm scope add --host <host>", "Trust the CA:  aitm ca install"]`.
- **Done when:** the five tests pass and the `aitm` package gate passes.

### Task 11: `help/request.rs` — recognising a help request in argv

- **Satisfies:** AC-W2-2/3/7 (which invocations are help), C32, C33.
- **Depends on:** T8.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm/src/help/request.rs` (replace the stub).
- **Change:** `pub const HELP_FLAGS: &[&str] = &["--help", "-h"]; pub const HELP_WORD: &str = "help"; pub const MODE_WORDS: &[&str] = &["tui", "web", "operator-token", "sysproxy-watchdog", "version", "help"];` `#[derive(Debug, Clone, PartialEq, Eq)] pub struct HelpRequest { pub topic: Vec<String>, pub explicit: bool, pub argv: Vec<String> }`; `pub fn parse(argv: &[String]) -> Option<HelpRequest>`: `None` for empty argv or when `argv[0] == "sysproxy-watchdog"`; `argv[0] ∈ HELP_FLAGS ∪ {help}` → explicit, `topic` = the leading non-flag tokens of `argv[1..]`; else any token `∈ HELP_FLAGS` → explicit, `topic` = the leading non-flag tokens of `argv` before the first `--`/`-` token; else `argv.len() == 1`, not a flag, not a mode word → implicit, `topic = [argv[0]]`; else `None`. `argv` is always the original slice.
- **Tests** (literal): `["--help"]` → `Some({topic: [], explicit: true})`; `["-h"]`, `["help"]` → same; `["help", "scope"]` → `topic ["scope"]`; `["help", "scope", "add"]` → `["scope", "add"]`; `["scope", "add", "--host", "x", "--help"]` → `["scope", "add"]` explicit; `["scope", "--help"]` → `["scope"]`; `["web", "--listen", "x", "-h"]` → `["web"]`; `["tui", "--help"]` → `["tui"]`; `["scope"]` → `["scope"]` implicit; `["scpe"]` → implicit; `["tui"]`, `["web"]`, `["operator-token"]`, `["version"]` → `None`; `["sysproxy-watchdog", "--help"]` → `None`; `["--bad"]` → `None`; `["scope", "add", "--host", "x"]` → `None`; `[]` → `None`.
- **Done when:** the test passes and the `aitm` package gate passes.

### Task 12: `startup/{args,mod,errors}.rs` — `pre_boot` answers `--version` only; typed errors pass through `report_for`; the synopsis pins go

- **Satisfies:** AC-W2-5 (`Usage:` detection), AC-W2-7 (one help path), C32, C35.
- **Depends on:** T1, T9.
- **Shared-worktree rule:** rule 10; `startup/mod.rs` is a module root — verify with `cargo fmt -p aitm -- --check`.
- **Files:** `crates/aitm/src/startup/args.rs` (modify), `crates/aitm/src/startup/mod.rs` (modify: the re-export line and its doc), `crates/aitm/src/startup/errors.rs` (modify), `crates/aitm/tests/synopsis_groups.rs` (delete), `crates/aitm/tests/synopsis_groups_l4.rs` (delete), `crates/aitm/tests/support/mod.rs` (modify: delete `built_in_groups`; `live_commands` stays).
- **Change:**
  - `args.rs`: `pre_boot` returns `Some(PreBoot::Version)` for `--version`/`-V`/`version` after the same stepping-over, `None` otherwise (the help aliases are the help resolver's, C32); the `PreBoot::Help` variant stays declared but is returned by nothing, with the doc line "returned by nothing since wave 2; T15 deletes it together with `main.rs`'s match arm", so `main.rs` keeps compiling until T15 — the one deliberate dead variant of the wave; delete `SYNOPSIS`, `GROUPS` and their tests; the module doc's help paragraph points at `crate::help`. Tests: `pre_boot_recognises_the_version_aliases_and_steps_over_flags` (every alias and the `--config x`/`-v`/`--color never` forms → `Some(Version)`), `pre_boot_leaves_help_to_the_help_resolver` (`["--help"]`, `["-h"]`, `["help"]`, `["help", "scope"]`, `["--color", "never", "-h"]` → `None`); the other `split_term_args`/`caps` tests unchanged.
  - `mod.rs`: `pub use args::{pre_boot, split_term_args, version_line, PreBoot, TermOpts};` and the doc line about `SYNOPSIS` removed.
  - `errors.rs`: rule 0 in `report_for` — `err.chain().find_map(|c| c.downcast_ref::<ErrorReport>())` → `report.clone()` with `log` applied only when `report.log.is_none()`; `usage_report` recognises `Usage:` as well as `usage:` in the headline and in the following line (`USAGE_LINES: [&str; 2] = ["usage:", "Usage:"]`); `REGISTRY_DUMP_HEADER` also matches `aitm_cli::dispatch::USAGE_FORM` (harmless; no error embeds the dump any more). Doc of rule 4 updated (W2: the pointer is the group/verb help when the error is typed). Tests: `typed_error_report_passes_through_and_gains_the_log_footer` (`anyhow::Error::new(ErrorReport::usage("unknown command `scpe`").with_why(vec!["did you mean: scope".into()]).with_command("aitm --help"))` with `Some(LOG)` → `kind Usage`, same `what`/`why`/`command`, `log == Some(LOG)`); `typed_report_keeps_its_own_log` (a report with `log` set is not overwritten); `capitalised_usage_line_is_a_usage_error` (`anyhow!("tui takes no further arguments, got `--bad`\nUsage: aitm [--config <path>] tui")` → `what == "tui takes no further arguments, got `--bad`"`, `why == ["Usage: aitm [--config <path>] tui"]`, `command == Some(FixCommand("aitm --help".into()))`, exit 2); the existing rule-4 tests unchanged.
- **Done when:** `cargo test -p aitm --offline --lib startup::` passes; `cargo test -p aitm --offline --test describe_registry` passes (the only surviving registry pin); `cargo build -p aitm --offline` still builds the binary (`main.rs` is untouched and still matches `PreBoot::Help`); `cargo clippy -p aitm --all-targets --offline -- -D warnings` and `cargo fmt -p aitm -- --check` pass.

### Task 13: `help/pages.rs` — the page builders

- **Satisfies:** AC-W2-1, AC-W2-2, AC-W2-7 (byte-identical pages), the M-W2-1/2/3/7 mock-ups, C42–C48.
- **Depends on:** T2, T5, T9, T10.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm/src/help/pages.rs` (replace the stub).
- **Change:**
  `pub const WEB_USAGE_LINE: &str = "Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]"; pub const TUI_USAGE_LINE: &str = "Usage: aitm [--config <path>] tui"; pub const OPERATOR_TOKEN_USAGE_LINE: &str = "Usage: aitm [--config <path>] operator-token generate [--force]";` `pub fn top_level(registry: &Registry, version: &str) -> HelpPage` (title `aitm {version} — {TAGLINE}`; `usage` empty — the top page's `Usage:` rows carry descriptions, so they are a `Section("Usage:", MODE_ROWS)` and align like every other section, while the renderer's `usage` field is for the bare forms of the group, verb and mode pages; blocks: `Section("Usage:")`, `Section("Groups:")` from `describe::groups` with `group_info(..).purpose` or `NO_PURPOSE`, `Section("Options:", OPTION_ROWS)`, `Examples(TOP_EXAMPLES)`, `Section("Learn more:", LEARN_MORE_ROWS)`, `Text(TOP_FOOTER)`); `pub fn group(registry: &Registry, name: &str) -> Option<HelpPage>` (title `aitm {name} — {purpose}`; usage `["aitm {name} <verb> [--flag <value>]..."]`; `Section("Verbs:")` rows `verb_row(cmd)` / `first_sentence(&schema.description)`; `Examples(examples_for(name) or the first example of each verb, max 4)`; `Text([footer])` when the group has one); `pub fn verb(cmd: &dyn Command) -> HelpPage` (title empty; about `[description]`; usage `[usage_form(cmd)]`; `Section("Flags:")` when params exist with rows `--{name} <{type_hint}>` / `{description}` + ` [required]`; `Examples(examples_for(name) or [usage_form])`; the group footer when the group has one); `pub fn web() -> HelpPage`, `pub fn tui() -> HelpPage`, `pub fn operator_token() -> HelpPage` (M-W2-7); `pub fn first_sentence(text: &str) -> &str` (C43); `pub fn verb_row(cmd: &dyn Command) -> String` (verb + required flags as `--name <placeholder>`); `pub fn render(caps: &Caps, page: &HelpPage) -> String` (= `aitm_term::help::help_page`, so callers import one module).
- **Tests** (hermetic, rule 13; `CATALOGUE_ENV` points `AITM_BUNDLED_SCRIPTS` at the repo's `scripts/bundled`):
  - `top_level_matches_the_mockup_with_the_catalogue`: `render(&piped_utf8(), &top_level(&reg, "0.5.11"))` `==` the M-W2-1 block byte for byte (the version string is injected, so the literal is stable).
  - `top_level_without_the_catalogue_has_seventeen_groups`: env `{AITM_NO_BUNDLED_SCRIPTS: "1"}` → the `Groups:` block has 17 rows, no `check`, no `l4`; the first line and the two footer lines are unchanged.
  - `scope_group_page_matches_the_mockup`: `render(&piped_utf8(), &group(&reg, "scope").unwrap())` `==` M-W2-2.
  - `scope_add_verb_page_matches_the_mockup`: `render(&piped_utf8(), &verb(reg.command("scope.add").unwrap().as_ref()))` `==` M-W2-3.
  - `flow_detail_page_keeps_the_core_default_words`: contains `(default inline)` and `(default 0)`, and the usage lines `  aitm flow detail --id <id> [--body <body>] [--offset <offset>]\n    [--length <length>]\n` (`wrap_usage` at 80: the `[--length <length>]` unit moves whole to the continuation line).
  - `first_sentence_stops_at_a_sentence_end_not_inside_eg`: `first_sentence("Add a host, host:port, or *.wildcard to Scope. New connections to it are decrypted.") == "Add a host, host:port, or *.wildcard to Scope."`; `first_sentence("Replace a flow's highlight mark set (e.g. colour names); an empty array clears it.")` == the whole text; `first_sentence("Confirm SQL injection in { url, param, value? } (error + boolean)")` == the whole text.
  - `verb_row_uses_name_placeholders_and_omits_optional_flags`: `verb_row(flow.detail) == "detail --id <id>"`; `verb_row(browser.confine) == "confine --on <true|false>"`; `verb_row(scope.list) == "list"`.
  - `web_page_keeps_the_formula_phrase`: `render(&piped_utf8(), &web())` `==` M-W2-7 and contains `web operator UI`.
  - `a_group_without_a_catalogue_entry_renders_the_placeholder`: a hand-built `Registry` with one fake `zzz.one` → the `Groups:` row right text is `(no description)`.
  - `unknown_group_is_none`: `group(&reg, "scpe").is_none()`.
- **Done when:** the ten tests pass and the `aitm` package gate passes.

### Task 14: `help/answer.rs` — from a `HelpRequest` to a page, an error, or "not help"

- **Satisfies:** AC-W2-2 (nothing booted, no log record), AC-W2-3 (`aitm scan` page; explicit unknown topics), AC-W2-6, AC-W2-7, C31, C33.
- **Depends on:** T5, T9, T11, T13.
- **Shared-worktree rule:** rule 10.
- **Files:** `crates/aitm/src/help/answer.rs` (replace the stub).
- **Change:** `pub struct HelpInputs<'a> { pub config_path: Option<&'a Path>, pub script_args: &'a [PathBuf], pub env: &'a dyn Fn(&str) -> Option<String>, pub caps: &'a Caps, pub version: &'a str }`; `pub enum Answer { Page(String), Error(ErrorReport), NotHelp }` (derive `Debug, PartialEq`); `pub fn settings_for_help(config_path: Option<&Path>, reporter: &Reporter) -> Settings` (`config_file::load_settings`; on `Err(e)` → `Settings` defaults after one `reporter.warn(&format!("config not read · {}: {} · help lists the default command set", path.display(), first_line(e)))`, C31); `pub fn answer(req: &HelpRequest, inputs: &HelpInputs, reporter: &Reporter) -> Answer`: topic `[]` → `Page(render(top_level))`; `["web"]`/`["tui"]`/`["operator-token"]` → the mode pages (no registry built); otherwise `describe::registry(&DescribeInputs { settings: &settings_for_help(..), .. })` (an `Err` here — the tier itself failed to build — is `Answer::Error(ErrorReport::failure(e.to_string()))`), then `aitm_cli::Cli::new(described.registry.clone()).locate(&req.topic)`: `Group` → the group page; `Command { cmd, .. }` → the verb page (any `rest` ignored); `Err(report)` → `NotHelp` when `!req.explicit`, else `Error(report)`. Nothing here opens a file for writing or installs a subscriber.
- **Tests** (hermetic; a `Reporter::new(Caps::plain(), Box::new(SharedSink), Normal)` for the warning; the env closure as in rule 13):
  - `top_level_is_a_page` (`starts_with("aitm 0.5.11 — ")`), `group_topic_is_the_group_page` (`["scope"]` implicit → `Page` starting `aitm scope — which hosts are decrypted\n`), `verb_topic_is_the_verb_page` (`["scope", "add"]` → `Page` starting `Add a host, host:port, or *.wildcard to Scope.`), `help_and_group_forms_are_identical` (`help scope` explicit and `scope` implicit produce equal `Page`s — AC-W2-7), `scan_is_a_group` (`["scan"]` → `Page` starting `aitm scan — `), `implicit_unknown_token_is_not_help` (`["scpe"]` implicit → `NotHelp`), `explicit_unknown_token_is_an_error_with_did_you_mean` (`["scpe"]` explicit → `Error(r)` with `r.what == "unknown command `scpe`"`, `r.why == ["did you mean: scope"]`, `r.command == Some(FixCommand("aitm --help".into()))`), `explicit_unknown_verb_points_at_the_group` (`["scope", "ad"]` explicit → `why == ["did you mean: scope add"]`, command `aitm scope`), `mode_topics_render_without_a_registry` (`["web"]` → `Page` containing `web operator UI`; `["tui"]`, `["operator-token"]` → pages whose `Usage:` line is the respective const), `bad_config_falls_back_to_defaults_and_warns_once` (a temp file containing `listen: [` → `Page`, and the sink text is exactly one line starting `warning: config not read · ` and ending ` · help lists the default command set\n`), `answer_creates_nothing` (a `config_path` under a temp dir that does not exist → `Page`; the dir still does not exist).
- **Done when:** the eleven tests pass and the `aitm` package gate passes.

### Task 15: `main.rs` integration — the ONE shared-file task (plus `tui.rs`, `web/mod.rs`, `no_bypass.rs`, `term-reporting.sh` §4)

- **Satisfies:** the wiring half of AC-W2-1 … AC-W2-9; D14 (confirm.rs leaves the allow-list); the §4 pins.
- **Depends on:** T6, T7, T12, T14 (and transitively everything else). **Runs after #271 merges and this branch is rebased onto `main`, or, if #271 is still open, last on the stack**; before starting, `git status` and `git diff --stat crates/aitm/src/main.rs crates/aitm/src/tui.rs crates/aitm/src/web/mod.rs` must be clean — stop and report if not. **No edit to `wire.rs`.** `main.rs` is a crate root: verify formatting with `cargo fmt -p aitm -- --check`.
- **Files:** `crates/aitm/src/main.rs` (modify), `crates/aitm/src/tui.rs` (modify: one const + its doc), `crates/aitm/src/web/mod.rs` (modify), `crates/aitm/src/startup/args.rs` (modify: delete the `PreBoot::Help` variant T12 left), `crates/aitm/tests/no_bypass.rs` (modify), `tests/e2e/cli/term-reporting.sh` (modify: three §4 literals, C51).
- **Change (the complete list; nothing else in `main.rs`):**
  1. Imports: `use aitm::help::{answer::{answer, Answer, HelpInputs}, request::{self as help_request, HelpRequest}, pages};`, `use aitm_term::caps::Caps;`.
  2. `enum Mode` gains `Help(HelpRequest)` with a doc line (C32/C33).
  3. `OPERATOR_TOKEN_USAGE` → `pages::OPERATOR_TOKEN_USAGE_LINE`; `parse_operator_token`: `[]` → `Err(format!("operator-token needs a verb\n{OPERATOR_TOKEN_USAGE}"))`; `[other]` (not `generate`) → `Err(format!("unknown verb `{other}` for operator-token\n{OPERATOR_TOKEN_USAGE}"))`; the `--oops` arm unchanged (`unknown argument …\n{USAGE}`).
  4. `parse_mode`: `Some("tui")` with extra tokens → `Err(format!("tui takes no further arguments, got `{}`\n{}", argv[1], tui::USAGE))`.
  5. `parse_invocation`: after the three splits and before the `web` parse: `if let Some(req) = help_request::parse(&argv) { return Ok(Some(Invocation { config_arg, script_args, bus_endpoint_file, web_args: None, mode: Mode::Help(req), term })); }`; the `WebCommand::Help` arm becomes `Mode::Help(HelpRequest { topic: vec!["web".into()], explicit: true, argv })` (unreachable in practice, kept so `web::parse_args` is unchanged).
  6. `main()`: the pre-boot `match` becomes `if let Some(startup::PreBoot::Version) = startup::pre_boot(&argv) { … exit(0) }`; `invocation` is `mut`; after the reporter is built and before the `OperatorToken`/`SysproxyWatchdog` dispatch: `if let Mode::Help(req) = &invocation.mode { let caps = Caps::detect_stdout(invocation.term.color); let env = |k: &str| std::env::var(k).ok(); let config_path = invocation.config_arg.clone().or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from)); match answer(req, &HelpInputs { config_path: config_path.as_deref(), script_args: &invocation.script_args, env: &env, caps: &caps, version: env!("CARGO_PKG_VERSION") }, &reporter) { Answer::Page(text) => { let _ = startup::write_stdout(&text); reporter.finish(); std::process::exit(0) } Answer::Error(report) => exit_with(&report, Some(&reporter)), Answer::NotHelp => invocation.mode = Mode::Cli(req.argv.clone()) } }` (the `NotHelp` arm is the implicit single-token fall-through, C33). `Mode::Help(_)` joins the `Mode::Server | Mode::Cli(_) | Mode::Tui | Mode::Web => {}` arm of the dispatch `match` below it (it has been answered or rewritten by then), and any exhaustive `match` on `mode` inside `run()` gets a `Mode::Help(_) => return Ok(())` arm with the comment "answered in main before the runtime" — never `unreachable!`.
  7. One-shot branch: `.with_confirmer(Arc::new(aitm_cli::TtyConfirmer::from_stdin().with_caps(reporter.caps().clone())))` after `.with_egress(..)`.
  8. `tui.rs`: `pub const USAGE: &str = crate::help::pages::TUI_USAGE_LINE;` with its doc ("the `Usage:` line; the page is `help::pages::tui`").
  9. `web/mod.rs`: `pub const USAGE` → `pub const USAGE_LINE: &str = crate::help::pages::WEB_USAGE_LINE;` (doc: the page is `help::pages::web`); `parse_args`'s unknown-argument arm → `return Err(anyhow::Error::new(ErrorReport::usage(format!("unknown argument to `aitm web`: {other}")).with_why(vec![USAGE_LINE.to_string()]).with_command("aitm web --help")))`; `value_of` → the same shape with `what = format!("{flag} requires a value")`; the `WebCommand::Help` doc line updated; the module's own tests that referenced `USAGE` updated to `USAGE_LINE`.
  10. `args.rs`: delete `PreBoot::Help` (T12 left it so `main.rs` compiled).
  11. `main.rs` tests: `tui_with_extra_arguments_is_a_usage_error` → `Err("tui takes no further arguments, got `extra`\nUsage: aitm [--config <path>] tui".to_string())`; the operator-token tests keep passing (`contains("operator-token generate")`); `usage_does_not_mention_the_watchdog`: the `("web::USAGE", aitm::web::USAGE)` entry → `("web page", aitm_term::help::help_page(&Caps::plain(), &aitm::help::pages::web()))` plus `("tui page", …tui())` and `("operator-token page", …operator_token())`; new `help_forms_select_the_help_mode`: `parse_invocation(args(&["scope", "add", "--help"]))` → `Mode::Help(req)` with `req.topic == ["scope", "add"]` and `req.explicit`; `["scope"]` → `Mode::Help` with `!explicit`; `["help"]` → topic `[]`; `["web", "--help"]` → topic `["web"]`; `["tui"]` → `Mode::Tui`; `["flow", "list"]` → `Mode::Cli`; `["sysproxy-watchdog"]` → the watchdog usage error as before.
  12. `tests/no_bypass.rs`: remove the `crates/aitm-cli/src/confirm.rs` entry (`ALLOWED` becomes `[(&str, &str); 2]`); add, after the walk, `assert!(walked.iter().any(|rel| rel == Path::new("crates/aitm-cli/src/dispatch.rs")), "the walk never reached aitm-cli")` so both roots are still proven reached; the doc comment's "W2 removes `confirm.rs`" sentence becomes "removed in W2: the prompt renders through `aitm_term::prompt`".
  13. `tests/e2e/cli/term-reporting.sh` §4: `ec "aitm tui extra" 2 'tui takes no further arguments' 'Usage: aitm [--config <path>] tui'`; `ec "aitm operator-token" 2 'operator-token needs a verb' 'Usage: aitm [--config <path>] operator-token'`; `ec "aitm flow list --bogus 1" 2 'error: unknown flag --bogus' 'fix: aitm flow list --help'`. Every other line of the script is untouched.
- **Done when:** `cargo test -p aitm --offline --lib` green; `cargo test -p aitm --offline --test no_bypass --test no_stdout_tracing --test sysproxy_watchdog_dispatch --test describe_registry --test operator_token_dispatch` green; `cargo clippy -p aitm --all-targets --offline -- -D warnings` and `cargo fmt -p aitm -- --check` pass; `bash -n tests/e2e/cli/term-reporting.sh` passes; `git diff --stat crates/aitm/src/main.rs` is under 150 changed lines; `grep -n 'println!\|eprintln!\|print!(\|eprint!(' crates/aitm/src/main.rs crates/aitm/src/web/mod.rs` returns only lines inside `#[cfg(test)]` modules.

### Task 16: the proof script `tests/e2e/cli/help.sh` and the README section

- **Satisfies:** the live halves of AC-W2-1 … AC-W2-10 (executed by the orchestrator from the Terminal panel; the script is the reproducible recipe).
- **Depends on:** T15 (and a Terminal-built `target/debug/aitm` with `aitm-tui` beside it for the Homebrew pin).
- **Shared-worktree rule:** rule 10; `bash -n` and `shellcheck` (if installed) instead of a formatter.
- **Files:** `tests/e2e/cli/help.sh` (create, `chmod +x`), `tests/e2e/cli/README.md` (modify: one section "Help" naming the script, its env vars and the TTY sections' `[ -t 1 ]` guard).
- **Change:** a small skeleton (no ports, no server): `set -uo pipefail`, `umask 077`, `AITM_BIN` discovery as `term-reporting.sh`, `AITM_EXPECT_VERSION`, `AITM_HELP_SECTIONS`, `ROOT=$(mktemp -d)` with trap, `pass/fail/skip/note/check/count_fx/count_re/bytecount/stripped/median_of/log_path_for` and the §14 TTY-recording helpers (the `script` wrapper with its PID-tracked anonymous-pipe feeder, dry-run D5) copied from `term-reporting.sh`, the same env scrub (`unset RUST_LOG NO_COLOR CLICOLOR_FORCE AITM_TERM CI AITM_LOG_FILE AITM_CONFIG XDG_CONFIG_HOME AITM_NO_BUNDLED_SCRIPTS AITM_BUNDLED_SCRIPTS AITM_SCRIPTS`), `LANG=en_US.UTF-8` when no UTF-8 locale is set, a fresh `HOME` per section, `RESULT: n passed, n failed, n skipped`, non-zero exit on any failure. Sections and literal expectations:
  1. **Top page** (AC-W2-1, AC-W2-7, AC-W2-10): fresh `HOME`; `touch marker; sleep 1`; `aitm --help`, `aitm -h`, `aitm help` → exit 0, stderr empty, stdout byte-identical across the three (`cmp`); first line `== "aitm $EXPECT_VERSION — intercepting proxy for authorized security testing"`; contains `^Groups:$`, `^Options:$`, `^Examples:$`, `^Learn more:$`, the row `^  scope +which hosts are decrypted$`, and the literal `aitm scope add --host <host>`; the number of lines between `Groups:` and the next blank line is 19 when `$repo_root/scripts/bundled` exists (else 17, noted), and exactly 17 with `AITM_NO_BUNDLED_SCRIPTS=1`; `count_fx $'\x1b'` == 0; `find "$HOME" -mindepth 1 -newer marker | wc -l` == 0 and `! -e "$(log_path_for "$HOME")"`; median of five `/usr/bin/time -p aitm --help` runs `< 0.100`; the lock check (AC-W2-10): `base=$(git merge-base HEAD claude/cli-ux-terminal-reporting-64b09b 2>/dev/null || git merge-base HEAD origin/main)` and `git diff "$base" -- Cargo.lock | grep -c '^+name = '` == 0 (no new package since the wave-1 tip; SKIP with the reason when `git` or both refs are unavailable).
  2. **Group pages** (AC-W2-2, AC-W2-3, AC-W2-7): every group name parsed from the top page's `Groups:` rows: `aitm <g>` exit 0, stderr empty, first line starts `aitm <g> — `, contains `^Usage:$` and `^Verbs:$`; `aitm help <g>` and `aitm <g> --help` byte-identical to it; `aitm scope`'s last line `== "Nothing is decrypted until a host is in Scope."` and its `Verbs:` rows are exactly `add --host <host>`, `remove --host <host>`, `list`; `aitm scan` exit 0 (AC-W2-3's group case).
  3. **Verb pages** (AC-W2-2): every `<g> <v>` pair parsed from the group pages' `Verbs:` rows (first word of each row): `aitm <g> <v> --help` exit 0, stderr empty, contains `^Usage:$`, `^  aitm <g> <v>`, `^Examples:$` and at least one `^  \$ aitm <g> <v>` line; `aitm scope add --help` contains `--host <string>` and `[required]`, and its first line is `Add a host, host:port, or *.wildcard to Scope. New connections to it are`; `aitm flow detail --help` contains `(default inline)`; `aitm help scope add` byte-identical to `aitm scope add --help`; after the whole loop `find "$HOME" -mindepth 1 -newer marker | wc -l` == 0 and no log file exists (nothing booted, no record written).
  4. **Did-you-mean and dotted names** (AC-W2-3, AC-W2-4), a second fresh `HOME` (these boot): `aitm scpe add --host x` exit 2, stderr has `` unknown command `scpe` ``, `did you mean: scope`, `fix: aitm --help`; `aitm scope ad` exit 2 with `` unknown command `scope ad` ``, `did you mean: scope add`, `fix: aitm scope`; `aitm flow tabel` exit 2 with `did you mean: flow table`; `aitm flow list --bogus 1` exit 2 with `` unknown flag --bogus for `flow list` ``, `Usage: aitm flow list`, `fix: aitm flow list --help`; `aitm scope add` exit 2 with `` missing required flag --host for `scope add` ``; `aitm help scpe` exit 2 with the same did-you-mean and **no** `log:` line and nothing created (pre-boot); for every stderr above, after dropping its `log:` line, `grep -c -E '[a-z_]+\.[a-z_]+'` == 0.
  5. **`Usage:`-form errors and the formula pins** (AC-W2-5, AC-W2-9): `aitm tui --bad` exit 2, stderr has `tui takes no further arguments` and `Usage: aitm [--config <path>] tui`; `aitm operator-token` exit 2 with `operator-token needs a verb` and `Usage: aitm [--config <path>] operator-token generate [--force]`; `aitm web --bad` exit 2 with `` unknown argument to `aitm web`: --bad ``, `Usage: aitm [--config <path>] web` and `fix: aitm web --help`; `aitm --bad` exit 2 with `` expected a command before flags, got `--bad` `` and `Usage: aitm <group> <verb> [--flag <value>]...`; `aitm web --help` exit 0, stdout has `web operator UI` and `^Usage:$`; `aitm tui --help` exit 0, stdout has `^Usage:$` and `^  aitm \[--config <path>\] tui$`; `aitm operator-token --help` exit 0, stdout has `^  aitm \[--config <path>\] operator-token generate \[--force\]$`; `aitm-tui --help 2>&1` exit 2 with `usage: aitm-tui` (SKIP without the binary); stdout empty for every error case.
  6. **`[y/N]` prompt** (AC-W2-8), only when `[ -t 1 ]` and `script` can allocate a pty, else SKIP: fresh `HOME`; `aitm scope list` once to mint the CA (the prompt loads it); then a `script -q` recording of `aitm ca install` with the W1 anonymous-pipe feeder writing `n\n` after 2 s (the feeder PID-tracked, no FIFO; dry-run D5); assert exit 1, the stripped cast contains a line matching `^  SHA-256 ([0-9A-F]{2}:){31}[0-9A-F]{2}$`, a line matching `^Install it\? \[y/N\]`, and `aborted: ca install not run`; `grep -c -E '[a-z_]+\.[a-z_]+'` over the stripped cast minus path-bearing lines == 0; nothing is written to any keychain because the answer is `n` (the section never passes `--yes`; memory `aitmproxy-live-proof-needs-matts-yes`: a declined prompt reads the trust store and writes nothing).
  7. **Sibling scripts** (AC-W2-9): `tests/e2e/cli/cli-startup.sh` → its `RESULT:` reports `0 failed`; `AITM_TERM_SECTIONS=preboot,exitcodes tests/e2e/cli/term-reporting.sh` → `0 failed` (the §1 synopsis pins and the amended §4 literals).
  8. **TTY rendering** (AC-W2-1 rich half), only when `[ -t 1 ]`: `script -q` recording of `aitm --help` → `grep -c $'\x1b\[2m'` ≥ 19 (dim descriptions) and `grep -c $'\x1b\[1m'` ≥ 5 (bold headings), zero cursor-movement sequences (`$'\x1b\[[0-9]*A'` == 0); `NO_COLOR=1` recording → zero SGR; the SGR-stripped recording equals the piped output of §1 line for line.
- **Tests:** `bash -n tests/e2e/cli/help.sh`; `AITM_BIN=/nonexistent tests/e2e/cli/help.sh` prints the FATAL line and exits 2.
- **Done when:** `bash -n` passes and the orchestrator's Terminal run ends in `RESULT: … 0 failed` (SKIPs only for: no TTY / no pty for §6 and §8; no `aitm-tui` beside the binary; no `scripts/bundled` beside the binary, noted in §1; `git` unavailable for the lock check).

---

## Live proof recipe (orchestrator, Terminal panel, after the full gate)

All commands run from the nested worktree root in Matt's real shell. Nothing here writes the system proxy or a keychain: the one `ca install` is declined with `n` (memory `aitmproxy-live-proof-needs-matts-yes` is honoured; routed as question 5).

1. Build and stage: `cargo build -p aitm -p aitm-tui && scripts/fetch-obscura-dev.sh`. Record `git rev-parse HEAD` and whether #271 has merged (and the rebase SHA if so).
2. Full Rust gate (Terminal, because the `aitm` integration suite binds ports): `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test 2>&1 | tee /tmp/claude/help-gate.log; echo "gate exit ${PIPESTATUS[0]}"` — judge by the exit status (memory `gate-exit-status-not-grep`). Expected `0`.
3. `script -q /tmp/claude/help-proof.log tests/e2e/cli/help.sh` → `RESULT: … 0 failed` (recorded with `script` so §6 and §8 see a TTY).
4. `tests/e2e/cli/cli-startup.sh 2>&1 | tee /tmp/claude/help-cli-startup.log` → `0 failed`; `script -q /tmp/claude/help-term.log tests/e2e/cli/term-reporting.sh` → `0 failed` (the whole wave-1 script, with its three amended §4 literals).
5. Manual TTY confirmation for the PR body: `./target/debug/aitm --help` (paste the page; it must equal M-W2-1 for this build's version), `./target/debug/aitm --help | wc -l`, `./target/debug/aitm --help | grep -c $'\x1b'` → `0`, `./target/debug/aitm scope` (M-W2-2), `./target/debug/aitm scope add --help` (M-W2-3), `./target/debug/aitm scpe add --host x; echo "exit $?"` (M-W2-4, `exit 2`), `./target/debug/aitm tui --bad; echo "exit $?"` (M-W2-5 first block, `exit 2`), `./target/debug/aitm web --bad; echo "exit $?"`.
6. Nothing created and fast: `export HOME=/tmp/claude/help-home; mkdir -p $HOME; touch /tmp/claude/help-marker; sleep 1; ./target/debug/aitm --help >/dev/null; ./target/debug/aitm scope >/dev/null; ./target/debug/aitm scope add --help >/dev/null; find $HOME -mindepth 1 -newer /tmp/claude/help-marker | wc -l` → `0`; `for i in 1 2 3 4 5; do /usr/bin/time -p ./target/debug/aitm --help >/dev/null; done 2>&1 | grep real` → every `real` < 0.10.
7. The prompt: in the same fresh `HOME`, `./target/debug/aitm scope list` (mints the CA), then `./target/debug/aitm ca install` → the M-W2-6 shape (fingerprint on its own line), answer `n`, `echo "exit $?"` → `1`, stderr `aborted: ca install not run`; `security find-certificate -c aitmproxy ~/Library/Keychains/login.keychain-db 2>&1 | head -1` unchanged from before the run (nothing installed).
8. Homebrew-style pins: `./target/debug/aitm web --help | grep -c 'web operator UI'` → `1`; `./target/debug/aitm-tui --help 2>&1; echo "exit $?"` → `usage: aitm-tui …` and `2`.
9. On Matt's real `HOME` (read-only): `./target/debug/aitm --help` lists `check` and `l4` (the catalogue is found beside the dev binary) and any command the operator's own config scripts register.

**The PR body must show:** the gate exit status line; the three `RESULT:` lines; the pasted `aitm --help`, `aitm scope`, `aitm scope add --help` pages and the `wc -l`/ESC counts; the did-you-mean and `tui --bad` panels with their exit codes; the `find … | wc -l` zero and the five `real` timings; the declined `ca install` prompt and the unchanged keychain line; the two Homebrew pins; a statement that no system-proxy or keychain write occurred; the stage-6 panel comment and the dispositions table (memory `aitmproxy-pr-definition-of-ready`).

## Follow-ups recorded by this plan (not wave 2)

1. When #267 has merged and `wire.rs` is free: one plugin-list builder shared by `wire::assemble_with_scripts` and `describe::registry`, and `run()`'s script-tier composition moved into `scripts.rs` and called by both (C28/C29 duplication removed; the pin stays as the guard).
2. Plugin-composed failure texts still carry dotted names (`findings.get: …` in `FindingsPlugin`, `scope.add refused: …` in `ScopeAdd`): a T6 pass over the plugins' own error prefixes (W3 or a fix PR; AC-W2-4 covers usage errors only).
3. `ParamDef.default` (question 3) would let the verb page print a `[default: …]` field instead of relying on the description prose.
4. R14 (`claude/cli-oneshot-live-core`): if one-shot verbs come to reach a running core, usage errors can be validated against the schema-only registry pre-boot for free (C33's exception becomes the rule) — the tier is then built once.
5. `aitm-tui --help` keeps its exit 2 and 200-column usage line (Homebrew pin); restyling it means a formula change first.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

## Questions only Matt can answer (defaults in force under autonomous-approve mode)

1. **Mode usage error shape (C34).** Cargo/uv shape — `✕ tui takes no further arguments, got \`--bad\`` then `Usage: aitm [--config <path>] tui` then `▸ aitm --help` — or the literal reading of AC-W2-5 with the `Usage:` line as the headline (`✕ Usage: aitm [--config <path>] tui`, which breaks T6's lowercase rule and reads `error: Usage: …` when piped)? **Default: cargo shape.**
2. **Help reads the config file (C31).** `aitm --help` reads `config.yaml` (never writes) so `l4.enabled` and the operator's own scripts' commands show; a broken config yields the default list plus one warning line. Or should help ignore the config entirely (then `l4` appears only through the catalogue's three scripts, and `aitm --help` never warns)? **Default: read it.**
3. **Defaults field (C45/C46).** Leave defaults in the parameter descriptions (eleven already say `(default …)`) and keep examples in a static table, or add `default: Option<Value>` / `examples` to `aitm_core::ParamDef`/`ParamSchema` now (an aitm-core edit plus every plugin's struct literals)? **Default: leave it; revisit in W3.**
4. **Pre-boot usage errors (C33).** Should `unknown command` and flag errors be answered from the schema-only registry before boot (no CA mint, no log, exit 2 in ~30 ms) in W2, at the cost of compiling the Rhai tier twice on a successful one-shot (AC-W1-30's 5 ms budget), or stay post-boot as the spec's open question 2 implies until R14 decides how one-shots boot? **Default: post-boot in W2 (help only pre-boot).**
5. **The `[y/N]` live proof (T16 §6, recipe step 7)** runs `aitm ca install` in a fresh `HOME` and declines it with `n`: the trust store is read (`security find-certificate`/`verify-cert`), nothing is written. OK to include in the proof, or prove the prompt only through the unit tests and a `--dry-run`-free manual look? **Default: include it, declined.**
