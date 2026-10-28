# aitm-tui

The terminal operator UI for aitmproxy: a ratatui client of the command bus
(the MCP server in `aitm-mcp`), one binary for macOS and Linux. It shows the
same shell as the macOS app and the web UI (sidebar, chip bar, flow list,
intercept bar, inspector, status bar), built from the same tokens file and
the same recorded fixture. Design, degradations and the bus contract are in
[`docs/design/operator-ui-foundation.md`](../../docs/design/operator-ui-foundation.md)
(§2.9, §2.10(c), §4.2).

## Run

```
usage: aitm-tui (--bus host:port (--token-file p | --token t (insecure: visible in ps)) [--allow-remote-bus] | --fixture [path]) [--poc-dir dir] [--ansi|--truecolor] [--poll ms]
       aitm-tui --snapshot out.svg [--cols N --rows N]
       aitm-tui --snapshot-core out.svg [--cols N --rows N]   (fixture limited to the 37 core tools)
       --poc-dir: where P (poc.build) writes the PoC YAML; use the proxy's poc.dir so poc.run can read it
```

**Against a running proxy.** The proxy's loopback TCP transport and its token:

```sh
aitm-tui --bus 127.0.0.1:9090 --token-file ~/.aitm/bus.token --poc-dir ~/engagement/pocs
```

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
every `--poll` ms (default 500, floor 100) until F4 adds push. A lost
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

**Fixture.** `aitm-tui --fixture` runs against the built-in
`fixtures/bus-fixture.json`; `--fixture path/to.json` against another recording.

**Snapshot.** `aitm-tui --snapshot out.svg --cols 200 --rows 50` renders the
main screen from the fixture and exits. The extension picks the format:
`.svg`, `.ans`/`.ansi` (escape codes), anything else plain text. Default 200×50.
`--snapshot-core` renders the same screen against the fixture limited to the
37 tools the core serves today (`CORE_TOOLS`), so the two pictures show what
is real now and what the remaining F-tools (the F1 agent pair) add.

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
| `b`, `[`, `]` | toggle sidebar, previous / next sidebar item (Scope filters the list; Findings, Browser, Agent open their panels) |
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
`↑`/`k`, `↓`/`j` scroll the log · `Esc`/`q` back.

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
| `kill` | Kill the targeted paused flow (abort mode: reset; 429/503 need F3) |
| `replay` | Repeat the selected flow unchanged (`r`) |
| `compose` | Compose a request, prefilled from the selection (`n`) |
| `compose get\|post-json\|post-form\|ws` | Compose from a template (`ws` needs F9) |
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
| `layout h\|v` | Inspector below or right |
| `split` | Split view — not built in this pass |
| `export` | Export flows — needs F10 |
| `sidebar` | Toggle the sidebar (`b`) |
| `pin [host]` | Pin a host to the top of the list (`p`) |
| `import <path>` | Import HAR / mitmproxy / Proxyman flows — needs F10 |
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
never hidden and never fails silently. Against today's core that is:

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
`Frontend::Mcp`; `dry_run=true` skips the prompt. The fixture contains the
F1 tools in their proposed shape and every lit tool in the core's real shape.
Sidebar items whose feature is further out carry their label (`F10` saved
sessions, `M3` scripts); the Browser item's count is the open tab count, a
dash until F14 (`browser.tabs`).

## Not in this pass

TUI-side features from the foundation's catalog that are not built yet (no
core dependency; build-or-descope is Matt's call):

- split view (two lists side by side ≥ 160 columns) — `:split` says so
- saved filters by name; match highlighting in body viewers; the sidebar quick filter
- compose templates Multipart and WebSocket (`:compose ws` names F9); the compose Query field and body modes; edit templates
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

## Fixture and snapshots for UI work

`fixtures/bus-fixture.json` is a recorded bus: server info, listening address,
scope, agent state, the `tools/list` reply, 15 flows (the mockup's rows
41–54 plus `f40`, the 101 upgrade the WebSocket flow `f47` names as its
handshake — on the real bus a WebSocket summary carries only that id, and
the row takes its URL from it), a PoC library of 3 files (`pocs`, what
`poc.list` / `poc.get` serve), 2 recorded `poc.run` results (`findings`,
replayed as `CallOk { name: "poc.run" }` since the core keeps no run
history), `poc.artifact` bytes, and the redacted `config.get` object. Per
foundation §2.10 it is the one fixture shared by the macOS, web and TUI
surfaces, so a screen renders the same data everywhere. Bodies are readable
`body_text` and WebSocket messages `data_text`; the fixture transport
base64-encodes them as `body` / `data` with `body_size` / `length` the way
`flow.detail` does. Mutating commands update it in memory the way the core
would (resume attaches the recorded `on_resume` response, kill marks the
flow, replay and `request.send` append, `flow.clear` drops completed flows).
In tests, `aitm_tui::fixture_app(cols, rows)` loads it into an `App`
(`fixture_app_core` with only the 37 core tools); `snapshot::render` draws to
a buffer and `to_text` / `to_svg` / `to_ansi` serialise it.
`docs/design/tui/main-screen.svg` is such a snapshot with every proposed tool
present; `docs/design/tui/main-screen-core.svg` is the same screen against
today's 37 core tools — the F1 agent toggle is the one labelled surface.

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
