# Installing aitmproxy

aitmproxy ships two ways from the public Homebrew tap
`mrbrutti/homebrew-aitmproxy` (tap name `mrbrutti/aitmproxy`). The tap and its
release binaries are public: no GitHub account, token, or
`HOMEBREW_GITHUB_API_TOKEN` is needed. (The source repository
`mrbrutti/aitmproxy` is private; the downloadable artifacts live on the tap's
[releases page](https://github.com/mrbrutti/homebrew-aitmproxy/releases).)

```bash
brew tap mrbrutti/aitmproxy
```

Then pick the one that matches how you work:

| You want… | Install | What you get |
|---|---|---|
| The macOS app | `brew install --cask aitmproxy` | A self-contained `Aitmproxy.app` |
| The CLI / headless proxy | `brew install aitm` | The `aitm` binary (proxy, `aitm web`, `aitm tui`, MCP server, one-shot commands) |

Both are **Apple Silicon (arm64) only**, and the app needs **macOS 26 or later**.
Intel macOS and Windows are not supported; for Linux see
[Linux native packages](#linux-native-packages).

## The macOS app is self-contained

**The cask ships a self-contained app.** `Aitmproxy.app` bundles its own
embedded `aitm` core (and the `obscura` browser engine) and manages it for you:
it starts the core on launch and stops it on quit. **You do not need to install
`aitm` separately to use the app** — install the cask, open the app, and it
proxies out of the box.

**The `aitm` formula stays** for anyone who runs the core directly: CLI and
headless operators, scripting, CI, and anyone who wants to run an external core
and point the app at it.

## Pointing the app at an external core

The app defaults to its bundled embedded core. To use a core you run yourself
instead — for example an `aitm` installed from the formula — switch the app to
**external** in **Settings ▸ Bus**.

The external core must serve the loopback-TCP MCP transport the app speaks to,
so give its `config.yaml` (macOS: `~/Library/Application Support/aitmproxy/config.yaml`)
a `mcp.transport.loopback_tcp` block, then start it with `aitm`. That transport
binds `127.0.0.1` only, so a core on another host needs a tunnel (for example SSH
port forwarding) to a local port:

```yaml
mcp:
  transport:
    loopback_tcp:
      port: 9090
      token: <a long random token>
```

1. Set **Active core** to **External**. The embedded core stops while external
   is active and starts again when you switch back; the choice persists across
   launches.
2. Tell the app where the external core's command bus is, by any one of:
   - **Settings ▸ Bus ▸ External connection** — enter the host, port, and a
     token file, or leave **Read address and token from aitmproxy's
     config.yaml** on to pick `mcp.transport.loopback_tcp.port` and `.token`
     up from `config.yaml`.
   - **Launch arguments** — start the app with
     `--bus <host:port>` plus `--token <token>` or `--token-file <path>`.
   - **`config.yaml`** — the app reads the bus address and token from the same
     `config.yaml` the core uses (the toggle above).

Over the embedded core the app connects as an **operator** (`clientInfo
aitm-mac`). Over an external core it connects as an **agent**, gated like any
agent, using the `config.yaml` token — unless you paste an operator token in
**Settings ▸ Bus ▸ Role** (the core's `mcp.operator_token`; create one with
`aitm operator-token generate`) and reconnect (**Proxy ▸ Reconnect Bus**).

## Building from source (`cargo` / bare binary)

Building needs Rust 1.97 or newer (the workspace `rust-version`); on Linux also
the libpcap development files (`libpcap-dev` on Debian/Ubuntu), which the L4
capture module links against. `cargo build` and `cargo install --path crates/aitm` do **not** produce the `obscura` browser
engine — it is a separate artifact published as a GitHub Release (tag `aitm-v1`)
of the private `mrbrutti/obscura` repository. They also do not build the web UI:
`aitm`'s `build.rs` embeds `apps/web/dist` if it exists, so without
`(cd apps/web && npm ci && npm run build)` first, `aitm web` serves a "not built"
placeholder. An `aitm` with no `obscura` reachable runs the proxy fine, but the
browser engine fails to launch with `obscura (the embedded browser engine) was
not found.` and a list of the places it looked.

`aitm` looks for `obscura` in this order (first hit wins; a `browser.obscura.binary`
that points at a missing file is an error, not a fall-through):

1. `browser.obscura.binary` in `config.yaml`
2. the `AITM_OBSCURA_BIN` environment variable
3. `obscura` next to the `aitm` executable
4. `obscura` on `PATH`

So after building from source, make `obscura` reachable by any one of:

- **Bundle it beside `aitm` (recommended).** `scripts/package.sh` builds the web
  UI, then release `aitm` and `aitm-tui`, downloads the matching
  `obscura-<target>.tar.gz` for your host, verifies it against the release
  `SHA256SUMS`, and writes `dist/aitm-<version>-<target>.tar.gz` holding `aitm`,
  `aitm-tui` and `obscura` side by side. Extract it anywhere and run `./aitm` —
  discovery step 3 finds `obscura` automatically, with no `PATH` entry or config
  key. It needs `cargo`, `npm`, `shasum`, `tar` and `gh`, and because
  `mrbrutti/obscura` is a private repository, `gh` must be authenticated with
  read access to it.
- **Dev checkout.** `scripts/fetch-obscura-dev.sh` downloads the same engine
  (needs `gh` access to `mrbrutti/obscura`, or `OBSCURA_GH_TOKEN`) and drops it
  next to the `aitm` in `target/debug/` and `target/release/`; see
  [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
- **Point at an existing engine.** `export AITM_OBSCURA_BIN=/path/to/obscura`, or
  set `browser.obscura.binary: /path/to/obscura` in `config.yaml`.

`obscura` must be the aitmproxy fork: `aitm` probes it, and a binary whose
`--help` does not list `--ca-cert` is rejected. On macOS, clear the download
quarantine with `xattr -d com.apple.quarantine /path/to/obscura` or it will fail
to spawn.

## Linux native packages

The Homebrew formula and cask above are Apple-Silicon macOS only. On Linux, the
primary install route is a native `.deb` or `.rpm` package — download the one for
your distro family and CPU from the
[releases page](https://github.com/mrbrutti/homebrew-aitmproxy/releases) (public,
no token), then:

**Debian / Ubuntu (`.deb`, `aitm-<ver>-amd64.deb` or `aitm-<ver>-arm64.deb`):**

```bash
sudo apt install ./aitm-<ver>-<arch>.deb
# or, without apt resolving dependencies:
sudo dpkg -i ./aitm-<ver>-<arch>.deb
```

**Fedora / RHEL (`.rpm`, `aitm-<ver>-x86_64.rpm` or `aitm-<ver>-aarch64.rpm`):**

```bash
sudo dnf install ./aitm-<ver>-<arch>.rpm
```

Packages are published for **x86_64** (`amd64`) and **aarch64** (`arm64`). The
release also carries a generic tarball per arch
(`aitm-<ver>-<arch>-unknown-linux-gnu.tar.gz`) holding `aitm`, `aitm-tui` and
`obscura`. **Windows is not supported.**

### What the package installs

```
/usr/lib/aitmproxy/aitm        the proxy / web / CLI core
/usr/lib/aitmproxy/aitm-tui    the detached operator TUI
/usr/lib/aitmproxy/obscura     the browser engine
/usr/bin/aitm      → /usr/lib/aitmproxy/aitm        (on PATH)
/usr/bin/aitm-tui  → /usr/lib/aitmproxy/aitm-tui    (on PATH)
```

After install, `aitm` and `aitm-tui` are on your `PATH`; just run `aitm`.
**`aitm-tui` is included** (unlike a bare `cargo build`), so the standalone
operator UI is available out of the box.

**`obscura` is auto-discovered** — you do **not** set `AITM_OBSCURA_BIN`, a
config key, or a `PATH` entry. `obscura` is intentionally not placed on `PATH`
(it is not a user command); instead it sits beside the core in
`/usr/lib/aitmproxy`. Running `/usr/bin/aitm` resolves through the symlink to
`/usr/lib/aitmproxy/aitm`, so discovery step 3 (`obscura` next to the resolved
`aitm`) finds `/usr/lib/aitmproxy/obscura` automatically. This is the same
"bundle obscura beside aitm" arrangement described under
[Building from source](#building-from-source-cargo--bare-binary) above, done for
you by the package.

### Linux from source (fallback)

If no native package fits your system, build from source as above: `obscura`
ships Linux release assets for both `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` at `mrbrutti/obscura@aitm-v1`, so `scripts/package.sh`
run **on the Linux host** produces a `dist/aitm-<version>-<target>.tar.gz` with
`aitm`, `aitm-tui`, and `obscura` bundled together, exactly as on macOS.

---

## Release note: where the Homebrew files live

The Homebrew cask and formula live in the separate public
`mrbrutti/homebrew-aitmproxy` tap, **not** in this repository, and the same
repository's Releases host the binaries they download. CI mirrors every release
asset there (see [`docs/RELEASE.md`](docs/RELEASE.md)); the formula and cask
`version`/`sha256` bump is done by hand in the tap, with plain public URLs and no
download strategy or token. The cask installs an app that bundles its own core
(see [The macOS app is self-contained](#the-macos-app-is-self-contained)); the
formula installs the CLI.
