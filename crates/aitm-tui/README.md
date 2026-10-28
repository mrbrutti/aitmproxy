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
usage: aitm-tui (--bus host:port (--token-file p | --token t) | --fixture [path]) [--ansi|--truecolor] [--poll ms]
       aitm-tui --snapshot out.svg [--cols N --rows N]
```

**Against a running proxy.** The proxy's loopback TCP transport and its token:

```sh
aitm-tui --bus 127.0.0.1:9090 --token-file ~/.aitm/bus.token
```

`--token t` passes the token inline; with neither, `AITM_BUS_TOKEN` is read.
With no `--bus`, `AITM_BUS` and `AITM_BUS_TOKEN` are used. The TUI writes the
token line, sends `initialize` as client `aitm-tui`, then `tools/list` once
and builds the palette from it. The flow list is polled every `--poll` ms
(default 500, floor 100) until F4 adds push. A lost connection reconnects
with back-off (0.5 s doubling to 10 s); the status bar shows the bus state.

**Embedded (landing in the same branch).** `aitm tui` starts the proxy and the
TUI in one process over an in-process channel; the bus contract is unchanged.
While the TUI owns the terminal the stdio agent transport is skipped with a
warning; a loopback TCP agent transport is still served.

**Fixture.** `aitm-tui --fixture` runs against the built-in
`fixtures/bus-fixture.json`; `--fixture path/to.json` against another recording.

**Snapshot.** `aitm-tui --snapshot out.svg --cols 200 --rows 50` renders the
main screen from the fixture and exits. The extension picks the format:
`.svg`, `.ans`/`.ansi` (escape codes), anything else plain text. Default 200×50.

`--ansi` forces the 16-colour palette, `--truecolor` the hex palette;
otherwise the terminal is detected (see Terminal capabilities).

## Screen

Top to bottom: toolbar (record/compose/clear, listening pill, agent toggle),
chip bar (content-type chips, `1`–`9`/`0` select), sidebar (28 columns,
`b` hides, `[`/`]` move), flow list, intercept bar when flows are paused,
inspector (request pane left, response pane right, tabs per pane), status bar
(key hints · row counts · size · bus state). Layout is horizontal (inspector
below) or vertical (inspector right); below 120 columns the inspector takes
the whole screen on `Enter` and returns on `Esc`.

Degradations, by design (§2.10(c)): no inline images (image bodies show
`[image W×H type · o to open]`; kitty/sixel graphics only if the terminal
advertises them); no browser viewport (URL, DOM outline, last-screenshot
placeholder; navigate/eval still work); diff is unified under 120 columns;
split view needs 160 or more; no drag-and-drop (`:import <path>`); clipboard
via OSC 52 where allowed; mouse optional, keyboard complete.

## Keys

`Ctrl-C` quits from any mode. `?` opens help in most modes; any key leaves it.

**Flows**

| Key | Action |
|---|---|
| `↑`/`k`, `↓`/`j`, `PgUp`, `PgDn`, `Home`/`g`, `End`/`G` | move |
| `Enter` / `Esc` / `Space` | open inspector / back / quick look |
| `Tab`/`→`, `Shift-Tab`/`←`, `1`–`9`, `0` | next / previous / nth chip |
| `b`, `[`, `]` | toggle sidebar, previous / next sidebar item |
| `i` · `a` / `A` · `d` or `x` | arm/disarm interception · resume one / all · kill |
| `e` · `r` · `n` | edit the paused request · replay · compose from selection |
| `p` / `m` / `c` · `P` | pin host / mark / comment · build PoC |
| `F` / `S` / `@` | findings / scope / agent panel |
| `l` · `t` | toggle layout (inspector below or right) · toggle auto-select |
| `y` / `o` | copy URL (OSC 52) / open externally |
| `/` or `Ctrl-F` · `:` or `Ctrl-K` · `q` | filter prompt · command palette · quit |

**Inspector / Quick look**

| Key | Action |
|---|---|
| `Esc` / `q` | back |
| `Tab` / `Shift-Tab` | switch request / response pane |
| `←`/`h`, `→`/`l` | previous / next tab |
| `↑`/`k`, `↓`/`j`, `PgUp`, `PgDn`/`Space`, `Home`/`g`, `End`/`G` | scroll |
| `z` | fold (JSON tree) |
| `e`, `a`, `d`/`x`, `r`, `n`, `P`, `y`, `o`, `i`, `:`, `/`, `?` | as in Flows |

**Edit** (a paused request): `Ctrl-S` or `F5` apply and resume · `Ctrl-R`
revert · `Esc` back · arrows, `Home`, `End`, `Enter`, `Backspace`, `Tab` and
printable keys edit.

**Prompt** (filter, palette, scope add, PoC target): `Enter` submit · `Esc`
back · `↑`/`↓` move (palette also `Tab`/`Shift-Tab`) · text edits.

**Compose**: `Ctrl-Enter` or `Ctrl-S` send · `Enter` submit field ·
`Tab`/`↓`, `Shift-Tab`/`↑` next / previous field · `Esc` back.

**Findings**: move keys · `Enter` open · `r` run the PoC again · `o` open
screenshot · `Esc`/`q` back.

**Scope**: move keys · `a`/`n`/`+` add host · `d`/`x`/`-` remove selected ·
`Esc`/`q` back.

**Agent**: `1`/`a` all tools · `2`/`r` read-only · `3`/`p` paused ·
`↑`/`k`, `↓`/`j` scroll the log · `Esc`/`q` back.

## `:` commands

`:` opens the palette; type to fuzzy-match, `Enter` runs. Built in:

| Command | Does |
|---|---|
| `intercept` | Arm/disarm interception (`i`) |
| `resume` / `resume all` | Resume the targeted paused flow / every paused flow |
| `kill` | Kill the targeted paused flow |
| `replay` | Repeat the selected flow unchanged (`r`) |
| `compose` | Compose a request, prefilled from the selection (`n`) |
| `curl <command>` | Import a curl command line into compose |
| `filter <expr>` | Set the filter expression (`/`) |
| `scope add <host>` | Add a host to scope (scope-as-authorisation) |
| `scope` | Open the scope panel (`scope rm <host>` removes; needs F12) |
| `findings` | Open the PoC findings panel |
| `poc build` | Build a PoC from the selected flow |
| `poc run <path> [target]` | Run a PoC YAML |
| `agent all\|readonly\|paused` | Set the agent policy |
| `agent` | Open the agent panel and activity log |
| `layout h\|v` | Inspector below or right |
| `sidebar` | Toggle the sidebar (`b`) |
| `pin [host]` | Pin a host to the top of the list (`p`) |
| `import <path>` | Import HAR / mitmproxy / Proxyman flows |
| `clear` | Clear the session |
| `pause` / `record` | Pause / resume capture |
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
atom  := '(' expr ')' | '~' name [arg] | word      a bare word is ~u word
```

Atoms: `~u` url · `~d` host · `~m` method · `~s`/`~c` status (`200`, `4xx`) ·
`~h` header name/value · `~b` body text · `~t` content-type · `~client`
process · `~comment` · `~mark` colour · flags `~a` agent-originated ·
`~scope` / `~oos` · `~ws` · `~paused` · `~killed` · `~replay` · `~e` edited ·
`~q` no response yet. Text arguments match case-insensitively as substrings,
with `*` and `?` wildcards; a quoted argument may contain spaces. `~h` and
`~b` need the flow's detail (F5) and are false until it has arrived.

```
login                              URLs containing "login"
~m POST ~s 200                     POST with a 200
(~m GET | ~m HEAD) !~s 2xx         GET/HEAD that did not succeed
~d "*.shop-staging.test" ~t json   JSON from any shop-staging host
~a | ~paused                       agent-originated or currently paused
```

## When the core lacks a tool

The TUI builds its palette from `tools/list` and never assumes a tool exists.
A feature whose tool is absent renders disabled with the label
`needs core follow-up F<n>`, where F<n> is the row in foundation §5; it is
never hidden and never fails silently. Against today's core that is:

| Follow-up | Tool(s) | What is disabled |
|---|---|---|
| F1 | `agent.status`, `agent.set` | agent policy toggle (read-only) |
| F5 | `flow.detail` | inspector bodies, raw edit, `~h`/`~b` filters |
| F6 | `flow.mark`, `flow.comment` | `m` mark, `c` comment |
| F7 | `proxy.pause`, `flow.clear` | `:pause`, `:record`, `:clear` |
| F12 | `scope.remove` | `d` in the scope panel, `:scope rm` |
| F13 | `poc.list` | findings export |

The fixture already contains these tools in their proposed shape, so the
screens can be built and tested before the core has them. Sidebar items
whose feature is further out carry their label (`F10` saved sessions, `F14`
browser view, `M3` scripts).

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
scope, agent state, the `tools/list` reply, 14 flows mirroring the mockup's
rows and 2 findings. Per foundation §2.10 it is the one fixture shared by the
macOS, web and TUI surfaces, so a screen renders the same data everywhere.
Bodies are readable `body_text`; the fixture transport base64-encodes them as
`body` the way `flow.detail` will. Mutating commands update it in memory the
way the core would (resume attaches the recorded `on_resume` response, kill
marks the flow, replay and `request.send` append). In tests,
`aitm_tui::fixture_app(cols, rows)` loads it into an `App`; `snapshot::render`
draws to a buffer and `to_text` / `to_svg` / `to_ansi` serialise it.
`docs/design/tui/main-screen.svg` is such a snapshot.

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
- No `unsafe` (workspace `forbid`), no new dependencies beyond `Cargo.lock`.
