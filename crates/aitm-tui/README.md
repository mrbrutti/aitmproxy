# aitm-tui

The terminal operator UI for aitmproxy: a ratatui client of the command bus
(the MCP server in `aitm-mcp`), one binary for macOS and Linux. It shows the
same shell as the macOS app and the web UI (sidebar, chip bar, flow list,
intercept bar, inspector, status bar), built from the same tokens file.
Design, degradations and the bus contract are in
[`docs/design/operator-ui-foundation.md`](../../docs/design/operator-ui-foundation.md)
(§2.9, §2.10(c), §4.2).

## Run

```
usage: aitm-tui --bus host:port (--token-file p | --token t (insecure: visible in ps)) [--allow-remote-bus] [--expect-role agent|operator] [--poc-dir dir] [--ansi|--truecolor] [--poll ms]
       --poc-dir: where P (poc.build) writes the PoC YAML; use the proxy's poc.dir so poc.run can read it
       --expect-role: the role you expect the token to resolve to; the status line warns if it does not (it is never sent to the server)
```

With no `--bus` and no `AITM_BUS` it prints this usage and exits with status 2.

**Against a running proxy.** The proxy's loopback TCP transport and its token.
Configure that transport in the proxy's `config.yaml`, start the proxy (`aitm`), and
put the same token in a file:

```yaml
mcp:
  transport:
    loopback_tcp:
      port: 9090
      token: <a long random token>
```

```sh
aitm-tui --bus 127.0.0.1:9090 --token-file ~/.aitm/bus.token --poc-dir ~/engagement/pocs
```

The token line decides the role: the loopback token connects as an **agent**
(gated like any MCP agent); the proxy's `mcp.operator_token` (create one with
`aitm operator-token generate`) connects as an **operator**. `--expect-role` only
makes the status line warn when the role the proxy assigned differs.

`--poc-dir` names the directory a built PoC is written to. The core's
`poc.build` answers with the PoC's **YAML text**, not a file; the TUI writes
it as `<poc-dir>/<name>.yaml` (never overwriting: `-2`, `-3`, … on a
collision), toasts the path and lists it in Findings for `r` to run. Point it
at the proxy's `poc.dir`, because `poc.run` only reads PoCs under that
directory. Without the flag the TUI uses `config.get`'s `poc_dir` when it
has fetched it, else a temp directory — and the toast says so, since
`poc.run` will refuse a path outside `poc.dir`. `aitm tui` (the embed) passes
`poc.dir` itself.

`--token t` passes the token inline; it is accepted but **insecure: the token
is visible to every process on the machine in `ps`** — prefer `--token-file`
or `AITM_BUS_TOKEN`. With neither flag, `AITM_BUS_TOKEN` is read; with no
`--bus`, `AITM_BUS` and `AITM_BUS_TOKEN` are used. A bus address that is not
on loopback is **refused** unless `--allow-remote-bus` is given, because the
token travels in cleartext until the TLS bus lands (core follow-up F15). The
TUI writes the token line, sends `initialize` as client `aitm-tui`, then
`tools/list` once and builds the palette from it. The flow list is polled
every `--poll` ms (default 500, floor 100); the TUI does not use the core's
`flow.subscribe` push yet. A lost
connection reconnects with back-off (0.5 s doubling to 10 s); the status bar
shows the bus state.

**Embedded.** `aitm tui` starts the proxy and the TUI in one process over an
in-process channel; the bus contract is unchanged. While the TUI owns the
terminal the stdio agent transport is skipped with a warning; a loopback TCP
agent transport is still served. The proxy's `tracing` output would paint
over the UI, so it goes to a file instead, and only when `RUST_LOG` is set:
`AITM_TUI_LOG=<path>` names the file (created, or appended to if it exists);
otherwise a fresh `aitm-tui-<pid>.log` is created under the system temp
directory for this run. Either way the file is owner-only (`0600`) on Unix,
and the status bar's startup toast says where it went — or that there is no
log because `RUST_LOG` is unset.

`--ansi` forces the 16-colour palette, `--truecolor` the hex palette;
otherwise the terminal is detected (see Terminal capabilities).

## Screen

Top to bottom: toolbar (record/compose/clear, listening pill, agent toggle),
chip bar (content-type chips, `1`–`9`/`0` select), sidebar (28 columns,
`b` hides, `[`/`]` move), flow list, intercept bar when armed or when flows
are paused, inspector (request pane left, response pane right, tabs per
pane), status bar (key hints · row counts · total size and throughput · bus
state; the total reads `—` until a size is known from `flow.detail`, and the
throughput cluster `↑ — ↓ — (F4)` until the push stream). The listening pill
follows `proxy.status`: the address while serving, `not serving` when the
proxy never bound, `capture paused` while `:pause` is in effect.
Layout is horizontal (inspector below) or vertical (inspector right); below
120 columns the inspector takes the whole screen on `Enter` and returns on
`Esc`. The intercept bar sits above the inspector when it is shown, else
above the status bar.

Degradations, by design (§2.10(c)): no inline images — image bodies show
`[image W×H type · o to open]` and `o` writes the bytes to a private temp
file and opens it with the desktop (`open` / `xdg-open`); inline images are
not built in this pass (`caps` detects kitty/sixel). No browser viewport: the
Browser view shows the URL, the DOM as a text outline and the last screenshot
as a placeholder (`o` opens it); navigate, eval, screenshot and DOM refresh
still work (see **Browser** below). Diff is unified when the response pane is
narrower than 120 cells and side by side when it is ≥ 120 cells. Split view:
not built in this pass (`:split` says so; it would need ≥ 160 columns). No
drag-and-drop (`:import <path>`); clipboard via OSC 52 where allowed; mouse
optional, keyboard complete.

## Keys

`Ctrl-C` quits from any mode. `?` opens help in most modes; any key leaves it.

**Flows**

| Key | Action |
|---|---|
| `↑`/`k`, `↓`/`j`, `PgUp`, `PgDn`, `Home`/`g`, `End`/`G` | move |
| `Enter` / `Esc` / `Space` | open inspector / back / quick look |
| `Tab`/`→`, `Shift-Tab`/`←`, `1`–`9`, `0` | next / previous / nth chip |
| `b`, `[`, `]` | toggle sidebar, previous / next sidebar item (Scope filters the list; Findings, Browser, Agent and Scan open their panels) |
| `i` · `a` / `A` · `d` or `x` | arm/disarm interception · resume one / all (out-of-scope flows are skipped and counted) · kill |
| `e` · `r` · `n` | edit the paused request · replay · compose from selection |
| `p` / `m` / `c` · `P` | pin host / mark / comment · build PoC (name, then param) |
| `F` / `S` / `@` | findings / scope / agent panel |
| `l` · `t` | toggle layout (inspector below or right) · toggle auto-select |
| `y` / `o` | copy URL (OSC 52) / open the image or large body externally |
| `/` or `Ctrl-F` · `:` or `Ctrl-K` · `q` | filter prompt · command palette · quit |

**Inspector / Quick look**

| Key | Action |
|---|---|
| `Esc` / `q` | back |
| `Tab` / `Shift-Tab` | switch request / response pane |
| `←`/`h`, `→`/`l` | previous / next tab (`Cookies (F5)`, `Timing (F5)`, `Set-Cookie (F5)` are listed, dim, and explain themselves) |
| `↑`/`k`, `↓`/`j`, `PgUp`, `PgDn`/`Space`, `Home`/`g`, `End`/`G` | scroll |
| `z` | fold (JSON tree) |
| `e`, `a`, `d`/`x`, `r`, `n`, `P`, `y`, `o`, `i`, `:`, `/`, `?` | as in Flows |
| `b` / `s` | on an L4 flow only: build a craft / inject (confirmed with `y`); no-op on HTTP flows |

**Edit** (a paused request): `Ctrl-S` or `F5` apply and resume · `Ctrl-R`
revert · `Esc` back · arrows, `Home`, `End`, `Enter`, `Backspace`, `Tab` and
printable keys edit.

**Prompt** (filter, palette, scope add, PoC name/param, PoC target/vars, CA
export, confirm): `Enter` submit · `Esc` back · `↑`/`↓` move (palette also
`Tab`/`Shift-Tab`) · text edits. The confirm prompt takes `y` to run and
anything else to cancel.

**Compose**: `Ctrl-Enter` or `Ctrl-S` send · `Enter` submit field ·
`Tab`/`↓`, `Shift-Tab`/`↑` next / previous field · `Esc` back.

**Findings**: move keys · `Enter` open the capture · `r` run the PoC (asks
for the target, then `k=v …` vars; blank = none) · `o` open the screenshot
(a local file on a loopback bus, else fetched through `poc.artifact` into a
private temp file) · `Esc`/`q` back. The list is the PoC library
(`poc.list`: every file under `poc.dir`, shown `· not run · r to run`) merged
with this session's `poc.run` results (✓/✗, assertions, capture, screenshot)
and whatever Rhai scripts recorded with `finding(...)` (`findings.list`,
shown with their script's name). The YAML and description come from
`poc.get`; on a loopback bus without it the YAML is read from `poc_path`.

**Config** (`:config`): the redacted `config.get` object, one line per leaf
(`scope.entries  a.test, *.b.test`), read-only · `Esc`/`q` back.

**Scope**: move keys · `a`/`n`/`+` add host · `d`/`x`/`-` remove selected ·
`Esc`/`q` back.

**Agent**: `1`/`a` all tools · `2`/`r` read-only · `3`/`p` paused ·
`↑`/`k`, `↓`/`j` scroll the log · `Esc`/`q` back. When the bus serves the `l4.*`
commands (L4 enabled in the core's `config.yaml`; privileged, Linux first), `c`,
`i`, `n` and `w` toggle the per-feature L4 agent gates (capture, inject,
intercept, scope widening).

**Scan** (`:scan`, or the sidebar's Scan item; shown only when the bus offers
`scan.discover`): `r` crawls the selected flow's host or the first concrete scope
entry (the host must be in scope) · `Tab`/`Shift-Tab` switch between the
endpoints and injection-point lists · `↑`/`k`, `↓`/`j`, `PgUp`, `PgDn`,
`Home`/`g`, `End`/`G` move · `Enter`/`→` open the selected row's flow in the
inspector · `F` findings · `:` palette · `Esc`/`q` back. It is discovery only; the
core must have its embedded browser for a real crawl (without one,
`scan.discover` answers `stopped_reason: "no_browser"` from stored flows).

**CA** (`:ca`): `e` export (asks `[pem|der] [path]`) · `i` install · `u`
uninstall (both confirmed with `y/N` first) · `Esc`/`q` back.

**Browser** (`:browser`, the sidebar item, or `]` onto it): the embedded
browser (obscura) over the six `browser.*` commands, degraded as §2.10(c)
says — no viewport. Line 1 is the URL (a dash until you navigate; the bus has
no "where are you" call); then `[screenshot W×H PNG · N KB · o to open]` or
`[no screenshot yet · s]`; then the DOM outline — one indented `tag#id.class`
line per element, `script`/`style` bodies skipped, the first 200 elements,
with the cursor's path (`html › body › h1#title`) in its header; then the
last `eval` result; then `live viewport and tabs need core follow-up F14`.
Keys: `g` URL prompt, prefilled with the current URL (`browser.navigate`,
then the DOM and screenshot are re-read) · `e` expression prompt
(`browser.eval`; the argument name follows the tool's schema) · `d` re-read
the DOM (`browser.get_dom`) · `s` screenshot (`browser.screenshot`) · `o`
write the screenshot to a private temp file and open it · `↑`/`k`, `↓`/`j`,
`PgUp`/`PgDn`, `Home`/`End` walk the outline · `:` palette · `Esc`/`q` back.
Opening the view asks for the DOM and a screenshot once. While a call is in
flight the panel says so (`⟳ navigating…`); when one fails — a bus with the
tools but no engine, or a bus without `browser.*` at all — the error is shown
in the panel, not only as a toast. `:browser.navigate url=…` from anywhere
feeds the same view. Flows the browser makes appear with client `obscura`
once the core resolves the peer to its process (`flow.detail` reports
`client_conn.process: null` until then — foundation Q6); a dash today.

## `:` commands

`:` opens the palette; type to fuzzy-match, `Enter` runs. Built in:

| Command | Does |
|---|---|
| `intercept` | Arm/disarm interception (`i`) |
| `resume` / `resume all` | Resume the targeted paused flow / every paused flow |
| `kill` | Kill the targeted paused flow (always `flow.kill` with the default `reset` mode; for `429`/`503` run `:flow.kill id=… mode=429`) |
| `replay` | Repeat the selected flow unchanged (`r`) |
| `compose` | Compose a request, prefilled from the selection (`n`) |
| `compose get\|post-json\|post-form\|ws` | Compose from a template (`ws` is not built: it only toasts) |
| `curl <command>` | Import a curl command line into compose |
| `filter <expr>` | Set the filter expression (`/`) |
| `scope add <host>` | Add a host to scope (scope-as-authorisation) |
| `scope` | Open the scope panel (`scope rm <host>` removes via `scope.remove`; the rate-limit readout is `config.get`'s `limits`) |
| `findings` | Open the PoC findings panel |
| `poc build` | Build a PoC from the selected flow (name, then param); the YAML is written under `--poc-dir` |
| `poc run <path> [target]` | Run a PoC YAML |
| `agent all\|readonly\|paused` | Set the agent policy |
| `agent` | Open the agent panel and activity log |
| `ca` | CA panel: `ca.status` facts, export, install, uninstall |
| `config` | Config panel: the redacted `config.get` view |
| `browser` | Browser view: URL, DOM outline, screenshot; navigate and eval |
| `scan` / `scan <host>` | Scan view (`scan.discover`): `:scan` only opens it; `:scan <host>` crawls that host, and `r` in the view crawls the selected flow's host or the first concrete scope entry. Out-of-scope hosts are refused client-side. Needs the scanner plugin on the bus. |
| `layout h\|v` | Inspector below or right |
| `split` | Split view — not built in this pass |
| `export` | Export flows — not built in the TUI (the toast names `flow.export`; run `:flow.export`, which takes `ids`, `format` and `path`) |
| `sidebar` | Toggle the sidebar (`b`) |
| `pin [host]` | Pin a host to the top of the list (`p`) |
| `import <path>` | Import flows from a file (`flow.import`: `aitm`, HAR or mitmproxy `.flows`); needs the tool on the bus |
| `clear` | Clear completed flows (`flow.clear`; the toast says `cleared N flows · M in flight kept`) |
| `pause` / `record` | Pause / resume capture (`proxy.pause` / `proxy.resume`) |
| `copy` | Copy the selected URL (OSC 52) |
| `auto` | Toggle auto-select of new flows |
| `refresh` | Poll the bus now |
| `help` | Keys and commands |
| `quit` | Leave the TUI |

Any tool the bus lists is also a command, with `key=value` arguments:
`:flow.replay id=f12`, `:browser.navigate url=https://example.test`. Values
are coerced by the tool's schema (integer, number, boolean, object, array are
parsed as JSON; everything else is a string); a missing required parameter is
an error before anything is sent. New bus tools appear in the palette without
a TUI change.

## Filter expressions

mitmproxy-style, the portable text form of the GUIs' stacked filters:

```
expr  := or
or    := and ( '|' and )*
and   := not ( '&'? not )*          juxtaposition is AND
not   := '!' not | atom
atom  := '(' expr ')' | '~' name [arg] | word | /re/     a bare word is ~u word, a bare /re/ is ~u /re/
```

Atoms: `~u` url · `~d` host · `~m` method · `~s`/`~c` status (`200`, `4xx`) ·
`~h` header name/value · `~b` body text · `~t` content-type · `~client`
process · `~comment` · `~mark` colour · flags `~a` agent-originated ·
`~scope` / `~oos` · `~ws` · `~paused` · `~killed` · `~replay` · `~e` edited ·
`~q` no response yet. Text arguments match case-insensitively as substrings,
with `*` and `?` wildcards; a quoted argument may contain spaces. A
slash-delimited argument is a **regex** — `~u`, `~d`, `~h` and `~b` take one —
compiled once when the expression is parsed, case-insensitive unless it says
`(?-i)`; `&`, `|` and parentheses inside the slashes belong to the regex, and
`\/` is a literal slash. A word that only starts with `/` (`~u /api/login`)
stays a literal. `~h` and `~b` need the flow's detail (F5) and are false
until it has arrived. Nesting of `!` and `(` is limited to 64 levels.

```
login                              URLs containing "login"
~m POST ~s 200                     POST with a 200
(~m GET | ~m HEAD) !~s 2xx         GET/HEAD that did not succeed
~d "*.shop-staging.test" ~t json   JSON from any shop-staging host
~a | ~paused                       agent-originated or currently paused
~u /^https:\/\/api\..*\/login$/    regex on the URL
~h /^x-request-id$/                a header named exactly that
```

## When the core lacks a tool

The TUI builds its palette from `tools/list` and never assumes a tool exists.
A feature whose tool is absent renders disabled with the label
`needs core follow-up F<n>`, where F<n> is the row in foundation §5; it is
never hidden and never fails silently. The follow-ups were:

| Follow-up | Tool(s) | What is disabled |
|---|---|---|
| F1 | `agent.status`, `agent.set` | agent policy toggle (read-only); confirmations over the bus |
| F2 | audit ring, `notifications/aitm/agent` | activity log rows, Origin column, agent ticks |
| F3 | `flow.intercept {rules}`, `flow.kill {mode}` | breakpoint rules (`Rules…`), response-phase intercept/edit, kill abort modes 429/503 |
| F4 | `flow.subscribe`, server push | live list (polling instead), status-bar throughput (`↑ — ↓ — (F4)`) |
| F5 (rest) | timing phases, cookies, peer→process | `Cookies`, `Timing`, `Set-Cookie` tabs; the Client column (`client_conn.process` is null until the core resolves it) |
| F9 | `ws.send` | WebSocket compose (`:compose ws`) and replay of WS flows |
| F10 | `session.save/load`, `flow.export`, `flow.import` | `:export`, `:import`, Saved sessions |
| F11 | `tls.passthrough.list/add/remove` | SSL include/exclude list (which hosts to MITM) |
| F13 (rest) | findings export | export of a finding (YAML + PNG + HAR) |
| F14 | `browser.tabs`, `browser.screencast` | a live browser viewport and the tab count in the sidebar (the Browser view itself is built; see **Browser** above) |

The current core (`CORE_TOOLS`, pinned against the running server by
`crates/aitm/tests/tui_live_bus.rs`) serves the tools for every row
above except F5 (rest), F13 (rest) and F14. A few surfaces still show their
`needs core follow-up` label anyway, because the TUI itself has not built the
feature, not because the core lacks the tool: the `Rules…` breakpoint editor (F3),
kill modes `429`/`503` from the `d` key (F3; use `:flow.kill id=… mode=429`),
push instead of polling (F4), `:compose ws` (F9), and `:export` and Saved
sessions (F10).

**Lit up with the core of 2026-10-28** (the merge that brought `tools/list`
to 37): F5 `flow.detail` (bodies, headers, connections, metadata, sizes,
durations, WebSocket messages, raw edit, `~h`/`~b` filters); F6 `flow.mark` /
`flow.comment` (`m`, `c`; the row's swatch and comment refresh from the
re-fetched detail); F7 `proxy.status` (the pill, the record toggle, the
store's paused count), `proxy.pause` / `proxy.resume` (`:pause` / `:record`),
`flow.clear` (`:clear`), `config.get` (`:config`, the scope panel's
rate-limit readout); F12 `scope.remove` (`d` in the scope panel, `:scope rm`);
F13 `poc.list` / `poc.get` / `poc.artifact` (the Findings library, its YAML
and descriptions, screenshots off-loopback); M3 `findings.list` (script
findings in the panel). `script.reload` / `script.validate` are on the
palette like any tool; the script editor itself is F8/M3. A bus without any
of these (an older core) still gets the labels above — the tests connect to
such a bus as `PRE_MERGE_TOOLS`.

Confirmations are **local** until F1: `ca.install` and `ca.uninstall` (the
`CONFIRM_TOOLS` list) ask for `y/N` in the TUI before anything is sent, because
the bus has no `confirm` on the wire yet and the TUI's server identity is
`Frontend::Mcp`; `dry_run=true` skips the prompt. The core serves the F1 tools
in their real shape; `CORE_TOOLS` in `src/lib.rs` lists what the TUI expects
and `crates/aitm/tests/tui_live_bus.rs` pins it against the running server.
Sidebar items whose feature is further out carry their label (`F10` saved
sessions, `M3` scripts); the Browser item's count is the open tab count, a
dash until F14 (`browser.tabs`).

## Not in this pass

TUI-side features from the foundation's catalog that are not built yet (no
core dependency; build-or-descope is Matt's call):

- split view (two lists side by side ≥ 160 columns) — `:split` says so
- saved filters by name; match highlighting in body viewers; the sidebar quick filter
- compose templates Multipart and WebSocket (`:compose ws` only toasts); the compose Query field and body modes; edit templates
- WebSocket sent/received direction filter
- setup-guide text; column hide; a Comment column (≥ 170 columns); palette recent/pinned
- custom columns, multi-select with a summary, overview dashboard text
- JSONPath/jq and full-text filter operators (grammar to be fixed in the foundation)
- Protobuf / MessagePack viewers, an SSE event list, rendered Markdown/HTML preview (plain text / hex today)
- code generator / copy as cURL, export body (`:curl` imports only)
- mark swatch beyond the first colour
- JSON tree: copy node value, filter, sort keys (fold and copy node path are built)
- inline images: not built in this pass (`caps` detects kitty/sixel)
- PoC YAML editable with Save (the YAML is shown, from `poc.get`; on a loopback bus without that tool it is read from `poc_path` — a regular `.yaml`/`.yml` file of at most 256 KiB)
- the `ssl_insecure` toggle (the value is shown in `:config`, read-only)

## Terminal capabilities

Detected once at start from the environment (`caps.rs`):

- **truecolor** — `COLORTERM` is `truecolor`/`24bit`, `TERM` contains
  `direct`, `TERM_PROGRAM` is iTerm.app / WezTerm / Ghostty / kitty /
  Alacritty / VS Code, or `KITTY_WINDOW_ID` / `WEZTERM_PANE` is set. Otherwise
  the 16-colour `tui` names from the tokens file.
- **kitty graphics** — `TERM` contains `kitty`, `KITTY_WINDOW_ID` set, or
  `TERM_PROGRAM` is Ghostty / WezTerm.
- **sixel** — `TERM_PROGRAM` is WezTerm / mlterm / foot, or `TERM` contains
  `sixel` or starts with `foot`.
- **OSC 52 clipboard** — any kitty terminal, the truecolor programs above,
  `TMUX` set, or `TERM` starting with `xterm` or `foot`. The UI says
  "copied (OSC 52)"; whether it reached the system clipboard is the
  terminal's decision.

`--ansi` and `--truecolor` override detection.

## Testing

Three kinds of check, and nothing else counts as evidence:

- **Unit and integration tests with inline inputs.** `cargo test -p aitm-tui`.
  Every test builds its `App` from literals in the core's wire shapes. The
  starting point is `tests/common/mod.rs`'s `connected_app(cols, rows)`: an
  `App` of that size on a bus offering every `CORE_TOOLS` name and nothing
  else — no flows, details, scope or findings; the test feeds those as
  `BusEvent` literals (`summary` builds a `flow.get` row, `sample_app` two
  in-scope flows with details). For a degradation case — what a *missing*
  tool does — use `App::new` + `connect` with `PRE_MERGE_TOOLS` (the bus
  before the newer tools) or any list. The `scan_v2_*` suites also read
  the `aitm-scan-model` contract pack (`fixture("scan.issue.json")` and
  its siblings): wire-shape examples pinned against the engine by that
  crate's own tests, not a recorded session. `draw` / `text_of` read the
  screen through `ui::render` into an off-screen buffer. The wall-clock-bounded
  tests are their own binary, `tests/perf.rs`; the bus task's are
  `tests/bus_task.rs`, against a transport whose replies are literals.
- **The real-server contract.** `cargo test -p aitm --test tui_live_bus`
  spawns a real core and pins `CORE_TOOLS` against its `tools/list`. It binds
  a port, so it runs in a real shell (the Terminal panel), never the sandbox.
- **The real run.** `aitm tui` (in-process), or `aitm-tui --bus 127.0.0.1:9090
  --token-file …` against a running proxy, with real traffic:
  `curl -x 127.0.0.1:<listen> http://127.0.0.1:8099/` against
  `python3 -m http.server 8099 --bind 127.0.0.1`, and the row appears in the
  list. A capture of that screen is what a PR body shows.

The recorded bus fixture and the snapshot mode (`bus-fixture.json`, its
loaders and the SVG/ANSI renderer) were removed on 2026-10-31 (spec
`2026-10-31-remove-fake-data-ui-modes`): they rendered sample data that let
broken builds look healthy. They must not come back; a test that needs data
writes it inline. `docs/design/tui/main-screen*.svg` are design-history
images from that removed snapshot mode and are not regenerable.

## Development

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

- `src/tokens.rs` is generated at build time by `build.rs` from
  `docs/design/tokens.json` (colours, `icon.glyph.*.tui`, sidebar width).
  Edit the JSON, never the generated file; an unrecognised token shape fails
  the build on purpose.
- `aitm-bus-client`'s TCP tests bind `127.0.0.1:0`. The Claude sandbox cannot
  bind ports, so run them in a real shell (the Terminal panel).
- No `unsafe` (workspace `forbid`); the only dependency added since the
  skeleton is `regex` (already in `Cargo.lock`).

### Live checks against a real core

Both need a real shell (they bind ports) and nothing else: a local echo server
stands in for the upstream, so they run offline and deterministically.

```sh
scripts/bus-agent-check.py            # an agent over the loopback bus, every command the UIs rely on
scripts/tui-live-check.sh embed       # tmux keystrokes into `aitm tui`: capture → i → paused → review → e edit → ^S → F5 body → P/poc run → F → :config
scripts/tui-live-check.sh bus         # the same against a separate `aitm` over `--bus … --token … --poc-dir …`
```

Each prints `ok`/`FAIL` per step and keeps the pane captures under a temp dir;
the exit status is the number of failed steps. Browser steps need an engine
configured on the host and are reported as unavailable otherwise.
