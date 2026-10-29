# Installing aitmproxy

aitmproxy ships two ways from the private Homebrew tap
`mrbrutti/homebrew-aitmproxy` (tap name `mrbrutti/aitmproxy`). Pick the one that
matches how you work:

| You want… | Install | What you get |
|---|---|---|
| The macOS app | `brew install --cask mrbrutti/aitmproxy/aitmproxy` | A self-contained `Aitmproxy.app` |
| The CLI / headless proxy | `brew install mrbrutti/aitmproxy/aitm` | The `aitm` binary (proxy, `web`, `tui`) |

The tap is private, so `brew` needs a GitHub token with `repo` scope to fetch
the release assets:

```bash
export HOMEBREW_GITHUB_API_TOKEN=$(gh auth token)
brew tap mrbrutti/aitmproxy https://github.com/mrbrutti/homebrew-aitmproxy
```

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
instead — for example an `aitm` installed from the formula, or one on another
host — switch the app to **external** in **Settings ▸ Bus**:

1. Set **Active core** to **External**. The embedded core stops while external
   is active and starts again when you switch back; the choice persists across
   launches.
2. Tell the app where the external core's command bus is, by any one of:
   - **Settings ▸ Bus ▸ External connection** — enter the host, port, and a
     token file, or leave **Read address and token from aitmproxy's
     config.yaml** on to pick them up from `config.yaml`.
   - **Launch arguments** — start the app with
     `--bus <host:port>` plus `--token <token>` or `--token-file <path>`.
   - **`config.yaml`** — the app reads the bus address and token from the same
     `config.yaml` the core uses.

The app always connects as an operator (`clientInfo aitm-mac`) over loopback
TCP and never acts as the agent.

---

## Release note: Homebrew tap self-sufficiency (applied in the tap, not here)

The Homebrew cask and formula live in the separate
`mrbrutti/homebrew-aitmproxy` tap, **not** in this repository. This section
specifies the wording the release step applies there; nothing in this repo
commits the `.rb` files.

**`Casks/aitmproxy.rb` — state self-sufficiency.** The cask installs an app that
bundles its own core; no separate `aitm` is required to use it. Add a comment at
the top of the cask and a `caveats` note to that effect, for example:

```ruby
# Casks/aitmproxy.rb
#
# Self-contained: Aitmproxy.app bundles and manages its own embedded `aitm`
# core (and obscura). No separate `aitm` install is needed to use the app.
# The `aitm` formula remains for CLI / headless / external-core operators.

cask "aitmproxy" do
  # ... version, sha256, url (private release strategy), name, desc, homepage ...

  app "Aitmproxy.app"

  caveats <<~EOS
    Aitmproxy.app is self-contained: it bundles and manages its own aitm core,
    so no separate `aitm` install is required to use the app.

    To point the app at a core you run yourself, switch to External in
    Settings > Bus (host/port/token-file, or read from config.yaml), or launch
    the app with `--bus host:port` and `--token`/`--token-file`.

    For the CLI / headless proxy, install the formula:
      brew install mrbrutti/aitmproxy/aitm
  EOS
end
```

**`Formula/aitm.rb` — unchanged.** The formula continues to install the
CLI/proxy/web/tui for headless and CLI operators and for anyone running an
external core. The self-contained-app work does not change it.
