# Core-connection model and a self-contained macOS app — design

**Status:** draft
**Research inputs:** `docs/research/05-synthesis.md`; `docs/research/07-ca-install.md`;
`apps/mac/docs/CAPABILITIES.md`; the first-run hygiene findings from running the
packaged binary (memory `aitmproxy-operator-first-run-hygiene`).

## Intent

Today each UI reaches the `aitm` core over the loopback-TCP MCP bus. `aitm tui`
and `aitm web` run the core *in-process* and are self-contained; the native
macOS app is only a bus **client** — it needs a separately-installed,
separately-run `aitm` to connect to, discovered from the shared `config.yaml`
or typed into Settings. A user who installs just the cask has nothing to connect
to, which reads as broken ("the app does not ship with the bus"). This design
makes the macOS app own an **embedded core** it bundles, spawns, and manages,
exactly as `tui`/`web` already own theirs — just as a managed child process
instead of an in-process task — and wraps the "where does this UI get its core"
question in a small **connection abstraction** that is deliberately shaped so we
can later run several cores at once and route traffic between them. It also
folds in three independently-shippable log/token hygiene fixes, because the
embedded app will capture the core's stdout and must not bury warnings or leak
the bus token.

## Goals

- **Self-contained macOS app.** Installing only the cask yields a working proxy:
  on launch the app spawns and manages an embedded `aitm` core (loopback bus on
  an ephemeral port with a freshly-generated token) and its bundled `obscura`
  browser engine, and the in-app bus client auto-connects. No separate install,
  no manual start, no config editing.
- **Full child lifecycle.** The embedded core starts on app launch, stops on
  quit, restarts on crash (bounded), is never left orphaned, and degrades
  legibly when a port it needs is already taken or another core is already
  running.
- **A connection abstraction.** Every UI connects to a *core connection* that is
  either **embedded** (this UI launched it) or **external** (operator supplies
  `host:port`+token via Settings / `--bus` / `config.yaml`). Embedded is the
  default for app/tui/web; external is opt-in. Each UI launches its own core by
  default.
- **One core now, multi-core-ready.** Exactly one active connection ships in this
  milestone, but every flow and every connection carries a per-core identity and
  there is a clean seam for (a) several simultaneous connections and (b)
  rule-based routing (which core traffic comes from / goes to).
- **Quiet, secret-safe first run.** A normal browsing session no longer spams the
  terminal with benign TLS-handshake warnings; the bus/web token never appears in
  the structured log stream; the default log level is curated, not raw `info`.
- **Install story that matches reality.** The cask is self-sufficient; the `aitm`
  formula stays for CLI/headless operators; the custom-connector setting is
  documented.

## Non-goals

- **Multiple simultaneous connections in the UI, and the routing rules
  themselves.** We wire exactly one active connection. The multi-core picker and
  the rule engine that chooses a core per flow are explicitly out of scope — we
  only avoid foreclosing them in the data model.
- **Remote / cross-machine cores.** Connecting to a core on another computer means
  taking the bus off loopback, which needs TLS + strong auth (mTLS or a strong
  token), off by default, and its own milestone and security review. We shape the
  connection abstraction so a future `remote` connection type slots in without
  rework, but we do **not** design or build the secure transport here.
- **Changing the bus protocol, the MCP command surface, or how `tui`/`web` embed
  the core in-process.** Those stay as they are; the app reuses the same
  loopback-TCP contract the other clients use.
- **A universal (arm64 + x86_64) build, unless Matt wants it** (open question).

## Anti-goals

- An orphaned `aitm` or `obscura` process surviving app quit or crash, or a second
  embedded core silently stacking on top of a first.
- The bus token written into any file, log line, or captured stdout the app
  retains or an operator might ship.
- A connection model that bakes in "exactly one, always embedded, always local"
  so that multi-core or remote later needs a rewrite of the flow identity or the
  client wiring.
- Embedding that quietly diverges the `.app`'s core from the `aitm` the formula
  ships (two different binaries, two behaviours).

## Constraints

- **Loopback only, this milestone.** The embedded bus binds `127.0.0.1` on an
  ephemeral port; the proxy and browser-proxy listeners stay local. No
  off-loopback bind, no TLS work here.
- **bama build pipeline.** The macOS app is built with the bama skill suite
  (`apps/mac/build.sh`, generated `Sources/Aitmproxy/UI/Tokens.swift`); bundling
  executables changes `build.sh`'s packaging step. `Tokens.swift` stays generated.
  The app build and every verify tool run in the Terminal panel (SwiftPM cannot
  write inside the Claude sandbox).
- **Signing/notarization.** The app today ships **without** App Sandbox (no
  `.entitlements`), which is what lets it spawn a child and bind ports — this
  design keeps App Sandbox off. Bundling `aitm` and `obscura` inside the `.app`
  means both nested executables must be signed (Developer ID, hardened runtime)
  and the notarization step (`scripts/notarize-dmg.sh`) must sign them before the
  outer app. See `aitmproxy-release-pipeline`.
- **Reuse the real core.** The bundled `aitm` is the same binary the formula/tap
  ship, built by the same `scripts/package.sh` (which also fetches `obscura`).
  No macOS-only fork of the core.
- **Discovery already works in our favour.** The loopback transport resolves an
  ephemeral port via `local_addr()` after binding `:0`
  (`crates/aitm-mcp/src/transport.rs`); `obscura` discovery already prefers
  `<exe_dir>/obscura` (`crates/aitm-browser/src/obscura.rs`), so co-locating the
  two binaries inside the bundle is enough for the core to find its browser.
- **No token in the structured log stream** (standing operator requirement).

## Design

The work splits into three layers that can land in order: **(A)** Rust log/token
hygiene (ships ahead, no dependency on the rest), **(B)** the connection
abstraction (a model, mostly macOS-side, that also names what `tui`/`web`
already do), **(C)** the embedded-core manager and self-contained bundle.

### A. Log & token hygiene (Rust, independently shippable)

**A1 — Classify connection-handler errors (`crates/aitm-core/src/proxy.rs:95`).**
Today every connection whose handler returns `Err` is logged `warn!(… "connection
handler ended with an error")`. A client that aborts the TLS handshake against an
untrusted CA — the normal case for every request before the CA is trusted —
trips this on *every* connection. Introduce a classification at the log site: an
**expected/benign** disconnect (client TLS-handshake abort/alert, connection
reset, EOF before a request, broken pipe) logs at `debug`; anything else stays
`warn`. **(Architect's call)** the classifier is a small function over the error
chain (downcast/`io::ErrorKind` match plus the TLS layer's handshake-abort
variant); its exact shape is left to the builder, but the set of demoted
conditions is a named, tested list, not a substring match on message text.

**A2 — Keep the token out of the log stream (`crates/aitm/src/main.rs:284–286`).**
`aitm web` currently both `println!`s the URL with `#t=<token>` *and*
`info!(url = %url, "web UI listening")` with that same tokened URL. Change the
structured log to record the **address only** (`info!(addr = %local_addr, "web UI
listening")`); keep a single `println!` of the full tokened URL to stdout as the
one deliberate, minimal disclosure (it is how a human opens the UI). Audit the
`tui`/server paths for any other tokened log line and apply the same rule.

**A3 — A curated default log filter (`crates/aitm/src/main.rs:372`).** The server
path defaults to `EnvFilter::new("info")`. Replace the bare `info` with a curated
default directive that keeps operator-relevant info (proxy listening, lifecycle)
while silencing per-connection and dependency chatter — e.g. a quieter baseline
with noisy targets pinned lower. **(Architect's call)** the exact directive
string is the builder's, reviewed against a real browsing session; `RUST_LOG`
still overrides it wholesale. The `tui` path (file-backed, only when `RUST_LOG`
is set) is unchanged.

These three are gated only by the Rust gate and can merge before any Swift work.
They also make the captured-stdout path in layer C safe by construction.

### B. The connection abstraction

Define, as the shared vocabulary every frontend uses, a **core connection**:

```
CoreConnection
  id:        CoreID            // stable per-core identity (opaque, e.g. a UUID/string)
  kind:      .embedded | .external | (reserved) .remote
  endpoint:  BusEndpoint       // host, port, token  (loopback now)
  status:    .starting | .connecting | .ready | .degraded(reason) | .stopped
  label:     String            // operator-facing name ("Embedded core", a host:port…)
```

- **`CoreID` on every flow.** Each flow/row the UI holds carries the `CoreID` of
  the connection it came from. With one connection this is a constant, but it is
  present in the model and in the store keys from day one, so a second connection
  is additive, not a migration. **(Architect's call)** in the macOS app this is a
  field on the row/flow model and on `Session`'s active-connection handle; the
  wire protocol is unchanged (the id is assigned client-side per connection).
- **`kind` is a closed set with `remote` reserved.** `.embedded` and `.external`
  are implemented; `.remote` is a named case with no behaviour yet, present so the
  future secure-transport milestone adds a variant and its endpoint/auth fields
  rather than reshaping the type.
- **One active connection now.** The app holds a single active `CoreConnection`.
  The default is `.embedded`. `.external` is selected in Settings (the existing
  `BusSettings` hooks: host/port/token-file, or "read from config.yaml") or by
  launch argument (`--bus host:port` + `--token`/`--token-file`, already parsed by
  `BusEndpoint.fromArguments`). The seam for "several at once" is that nothing in
  the flow store, the bus client, or the row model assumes the active connection
  is the only one — they are keyed by `CoreID`; the UI simply exposes one today.
- **`tui`/`web` are embedded too.** This names what they already do: an in-process
  core is a degenerate `.embedded` connection (no socket). No code change is
  required there now; the vocabulary just lines up so a future external-connect
  option for `tui`/`web` reuses it.
- **Routing seam (named, not built).** Rule-based routing ("take traffic from core
  X, send it to core Y") is a future layer that selects a `CoreConnection` per
  flow. The only thing this milestone owes it is the per-flow `CoreID` and a
  connection registry that can hold more than one entry — both present above. The
  rules, their config surface, and the multi-core UI are out of scope.

### C. The embedded-core manager and self-contained bundle

**C1 — What ships in the `.app`.** `scripts/package.sh` already produces `aitm`
+ `obscura` together. The bundle places both inside the app — **(Architect's
call)** under `Contents/Resources/core/` (or `Contents/Helpers/`; builder's
choice within signing rules) with `obscura` beside `aitm` so the existing
`<exe_dir>/obscura` discovery finds it; the app passes the bundled core path
explicitly and sets `AITM_OBSCURA_BIN`/`browser.obscura.binary` to the bundled
`obscura` as belt-and-braces. `build.sh` gains a packaging step that copies the
two binaries in and signs them (nested, hardened runtime) before the outer app;
`notarize-dmg.sh` signs them in the same order.

**C2 — `EmbeddedCore`, a managed child (Swift, new).** A small actor that owns the
lifecycle of one `aitm` child:

- **Launch.** Generate a fresh random bus **token** (CSPRNG, ample entropy) per
  app launch — never persisted, never logged. Spawn the bundled `aitm` configured
  for a **loopback bus on an ephemeral port** (bus `port: 0`) with that token, a
  proxy listener and browser-proxy listener, and the curated-quiet default log
  level. Config is handed to the child via a **per-launch temp config file**
  written `0600` in the app's container (or via flags/env) — **(Architect's call)**
  a written config is clearest and reuses `aitm`'s existing `--config` path;
  builder may instead use env/flags if cleaner, but the token must not land in a
  world-readable or persisted file.
- **Learning the endpoint.** The app chose the token but not the port (it is
  ephemeral). The child publishes its **resolved bus address** (host:port, *no
  token* — the app already has it) via a **rendezvous file** it writes `0600`
  after bind and removes on clean exit, mirroring the existing obscura ready-file
  pattern (`crates/aitm-browser/src/obscura.rs`). This needs a **small Rust
  addition**: a config/flag (e.g. `--bus-endpoint-file <path>`) that makes the
  core write its bound bus `host:port` to that path once the loopback transport
  binds. The app watches the file, reads the endpoint, builds a `BusEndpoint`, and
  connects its existing `BusClient`. **(Architect's call)** rendezvous-file over
  parsing stdout, because it keeps the token out of stdout entirely and is
  idempotent/crash-legible like the obscura precedent.
- **Stop.** On app quit, send `SIGTERM`, wait a grace budget, then `SIGKILL`;
  reap the child; remove the rendezvous and temp-config files. The core already
  closes its `obscura` child on every orderly exit path including signals
  (`main.rs`), so a clean `SIGTERM` tears the whole tree down.
- **Restart on crash.** If the child exits unexpectedly while the app runs,
  restart it with bounded exponential backoff and a cap; after the cap, enter
  `.degraded` and surface the failure (with the captured stderr tail) rather than
  looping forever. Each restart uses a fresh token and fresh ephemeral port.
- **No orphans.** Make teardown idempotent and crash-safe: the manager reaps on
  every exit path; a stale rendezvous file from a killed prior run is detected and
  ignored/cleaned (the obscura code already warns on stale ready-files, the
  precedent to follow).
- **Captured output.** The app captures the child's stdout/stderr for the
  core-log/health surface (C4). Because of layer A, that stream carries no token
  and no handshake spam.

**C3 — Port-in-use / already-running core.** The bus port is ephemeral, so the
*bus* never collides. The **proxy** (`listen`, default `8080`) and
**browser-proxy** (`browser.proxy_addr`) are fixed ports and can be taken — by a
previous `aitm`, another app, or a formula-run core the user already started.
Behaviour: the embedded core fails to bind, exits with a clear error; the manager
catches it, enters `.degraded`, and the app surfaces a legible choice rather than
retry-looping. **(Architect's call)** the surfaced options are: retry, pick an
alternate proxy port, or switch this connection to **external** (connect to the
core that already holds the port) — the exact affordance is a UX question for
Matt (open question O3). A user who deliberately runs their own core and wants
the app to use it chooses external in Settings; embedded stays the default.

**C4 — Core logs & health in the app.** The app owns the only window onto an
embedded core's health (there is no terminal). It shows connection status
(`CoreConnection.status`) and exposes the captured core log. **(Architect's
call)** reuse the existing Connection Log / Overview surfaces the app already has;
the precise presentation — live tail, health indicator, where "restarting…" and
`.degraded` reasons appear — is an open UX question for Matt (O2).

### Install & docs (layer C, shipping artifacts)

- **Cask is self-sufficient.** `Casks/aitmproxy.rb` installs an app that bundles
  its own core; no separate `aitm` is required to use it.
- **Formula stays.** `Formula/aitm.rb` continues to install the CLI/proxy/web/tui
  for headless/CLI operators and for anyone who wants an external core.
- **Document the custom connector.** `INSTALL.md` and the app's Bus settings help
  text explain: embedded is the default and needs nothing; to point the app at an
  external core, set host/port/token in Settings ▸ Bus (or `--bus`/`config.yaml`).

## Acceptance criteria

1. **AC1 — Benign disconnects are `debug`, real errors `warn`.** With the demoted
   set exercised (a client that aborts the TLS handshake, a reset, an EOF before a
   request), `proxy.rs` logs at `debug`; an injected genuine handler error still
   logs at `warn`. Covered by a unit test over the classifier.
2. **AC2 — The token never enters the structured log stream.** `aitm web`'s
   `info!` "web UI listening" line contains the address and **not** the token; the
   full tokened URL appears only via the single `println!`. A test asserts the log
   field set; a grep of the server/tui log call sites finds no tokened URL in a
   `tracing` macro.
3. **AC3 — Curated default log level.** With no `RUST_LOG`, a representative
   browsing session produces no per-connection warning spam and still logs
   "proxy listening"/lifecycle; `RUST_LOG` overrides the default wholesale.
4. **AC4 — A flow carries its `CoreID`.** Every flow/row in the macOS model has a
   `CoreID` identifying its connection; with one connection it is the embedded
   core's id. A unit test asserts the id is set on flows arriving over the bus.
5. **AC5 — `kind` is a closed set with `remote` reserved.** The connection type
   enumerates `embedded`, `external`, and a reserved `remote` with no behaviour; a
   test covers construction of embedded and external and that the active-connection
   registry can hold more than one entry (even though the UI exposes one).
6. **AC6 — Cask-only install works out of the box.** Launching the app with no
   `aitm` on `PATH` and no `config.yaml` spawns the bundled core, connects, and
   shows live flows through the embedded proxy. Verified by the app's live
   self-test driving the embedded core (no externally-started `aitm`).
7. **AC7 — Clean teardown, no orphans.** Quitting the app terminates the embedded
   `aitm` and its `obscura`; no `aitm`/`obscura` process and no rendezvous/temp
   files survive. Verified by a process/file check after quit.
8. **AC8 — Restart on crash.** Killing the embedded `aitm` while the app runs
   triggers a bounded restart that reconnects; after the backoff cap the app shows
   `.degraded` with the stderr tail rather than looping.
9. **AC9 — Port-in-use is legible.** With the proxy port already bound, the
   embedded core's bind failure surfaces as a `.degraded` connection with a clear
   message and the operator choice (not a silent retry loop or a crash).
10. **AC10 — External opt-in still works.** Selecting an external core in Settings
    (or `--bus`+token) connects to an already-running core and does **not** spawn
    an embedded one; switching back to embedded spawns and connects.
11. **AC11 — Bundled binaries are signed & notarized.** `aitm` and `obscura`
    inside the `.app` are signed (Developer ID, hardened runtime) and the DMG
    notarizes and staples with them nested.
12. **AC12 — Docs updated.** `INSTALL.md`/cask notes state the cask is
    self-sufficient and the formula is for CLI/headless; the custom-connector
    setting is documented.

## Left to the builder

- The exact representation of the error classifier in A1 (downcast vs. a small
  error enum) and the precise demoted-condition list, as long as it is named and
  tested, not a message-substring match.
- The exact curated `EnvFilter` directive string in A3, reviewed against a real
  browsing session.
- Where in the bundle the two binaries live (`Resources/core/` vs `Helpers/`) and
  the nested-signing invocation, within the signing/notarization rules.
- Whether the child config is a written temp file or flags/env, provided the token
  never lands in a persisted or world-readable place.
- The `CoreID` type (UUID vs opaque string) and exactly which store/model keys it
  threads through, provided every flow carries it and the registry holds many.
- Backoff constants, grace-period budget, and the stderr-tail length for restart.
- The rendezvous-file path/location and format, following the obscura ready-file
  precedent.

## Open questions

Only Matt can answer these; empty before approval.

- **O1 — Both external *and* embedded configured: which wins, and is it visible?**
  If an operator has set an external core in Settings but the app can also spawn an
  embedded one, is external an explicit override (and embedded never starts), or
  does the app offer a choice at launch? Recommendation: external in Settings is an
  explicit override — the app does not spawn embedded when external is selected.
- **O2 — How should the app surface core logs and health?** A live log tail in the
  Connection Log, a health dot in the toolbar/Overview, a "restarting…" banner —
  how much, and where? This drives C4.
- **O3 — Port-in-use affordance.** When the proxy/browser port is taken, should the
  app offer to (a) retry, (b) auto-pick an alternate proxy port, (c) switch to
  external and adopt the running core, or some subset? This drives C3/AC9.
- **O4 — Universal vs arm64-only bundling.** Ship an arm64-only `.app` (matches the
  current target: Apple Silicon, macOS 26+) or a universal binary? Universal
  roughly doubles the bundled-binary size and the build matrix.
- **O5 — Is the small Rust `--bus-endpoint-file` addition acceptable**, or do you
  prefer the app learn the port another way (pre-bind-and-pass, parse a stdout
  line)? The rendezvous file keeps the token off stdout and matches the obscura
  precedent, which is why it is the recommendation.
- **O6 — Phasing.** Ship layer A (hygiene) as its own change now, ahead of B/C?
  Recommendation: yes — it is low-risk, operator-visible, and unblocks nothing it
  depends on.
