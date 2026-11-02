# aitmproxy

**Intercept anything — by hand or by agent.**

aitmproxy is an intercepting-proxy platform for authorized security testing. It
captures, intercepts, edits, replays and reproduces traffic across four layers of
the wire — HTTP/1.1, HTTP/2, WebSocket and raw L4 (TCP/UDP) — from one core that
an operator and an AI agent drive with the same commands. Written in memory-safe
Rust; runs on macOS and Linux.

**Website: [mrbrutti.github.io/aitmproxy](https://mrbrutti.github.io/aitmproxy/)**
— features, documentation, demos and downloads.

![release](https://img.shields.io/badge/release-v0.5.13-555?style=flat-square)
![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-555?style=flat-square)
![platforms](https://img.shields.io/badge/platforms-macOS%20%C2%B7%20Linux-555?style=flat-square)

![The aitmproxy web UI with eleven requests held by interception](site/assets/web-dark.png)

> **Authorized engagements only.** aitmproxy is deny-by-default and strictly
> scope-bound — it will not touch a host you have not explicitly put in scope —
> and its active tools send real traffic. Operate it solely against systems you
> own or are covered by a written engagement to test.

[Install](#install) · [Quick start](#quick-start) · [Surfaces](#the-three-surfaces) ·
[Capabilities](#capabilities) · [Agents](#agents-over-mcp) ·
[Reference](#reference) · [Documentation](#documentation)

Elsewhere: [Docs](https://mrbrutti.github.io/aitmproxy/docs.html) ·
[Features](https://mrbrutti.github.io/aitmproxy/features.html) ·
[Scripting](https://mrbrutti.github.io/aitmproxy/scripting.html) ·
[PoC format](https://mrbrutti.github.io/aitmproxy/poc.html) ·
[Demos](https://mrbrutti.github.io/aitmproxy/demos/) ·
[Download](https://mrbrutti.github.io/aitmproxy/download.html)

---

## Overview

Every action in aitmproxy is a registered command. A person drives a running core
from the web UI, the terminal UI or the macOS app; an AI agent calls the very
same commands over MCP. There is no second API for agents and no hidden menu for
humans. Every call that arrives over MCP or the command bus is audit-logged with
its origin named, in memory and by default in files on disk; the
[Audit log](#audit-log) section says what is not recorded.

```mermaid
%%{init: {"theme": "neutral"}}%%
flowchart LR
    person(["Operator"])
    agent(["AI agent"])
    subgraph surfaces["Surfaces"]
        direction TB
        web["Web UI"]
        tui["Terminal UI"]
        mac["macOS app"]
    end
    subgraph core["aitm core"]
        direction TB
        registry["Command registry<br/>scope · sensitivity · audit log"]
        chain["Plugin chain<br/>flow store · rules · scripts · PoC · scanner"]
        http["HTTP/1.1 + HTTP/2"]
        ws["WebSocket"]
        l4["L4 TCP/UDP"]
        registry --> chain
        chain --- http
        chain --- ws
        chain --- l4
    end
    net[("Clients and servers")]
    person --> surfaces
    surfaces -->|"command bus"| registry
    agent -->|"MCP: stdio, loopback TCP, streamable HTTP"| registry
    http <--> net
    ws <--> net
    l4 <--> net
```

### At a glance

| | |
|---|---|
| **Four layers of the wire** | HTTP/1.1, HTTP/2, WebSocket and raw L4, under one flow model. → [Capabilities](#four-layers-of-the-wire) |
| **Three surfaces** | A web UI, a terminal UI and a native macOS app, all clients of one core. → [Surfaces](#the-three-surfaces) |
| **Agent-ready** | Every command is an MCP tool, gated by scope and sensitivity. → [Agents](#agents-over-mcp) |
| **Embedded browser** | A headless engine that already trusts the proxy. → [Browser](#embedded-browser) |
| **Attack-surface scanner** | Crawl an in-scope target and map its injection points. → [Scanner](#attack-surface-scanner) |
| **Scripting and PoCs** | Rhai plugins and declarative YAML reproductions. → [Scripting](#scripting-and-pocs) |

### Anatomy of a flow

Everything aitmproxy sees is a flow with a short lifecycle. Observed flows are
recorded and forwarded untouched. A rule can intercept one: the request pauses,
readable and editable, until you resume it or kill it.

```mermaid
%%{init: {"theme": "neutral"}}%%
stateDiagram-v2
    direction LR
    [*] --> Observed: request arrives
    Observed --> Intercepted: a rule matches, or interception is armed
    Intercepted --> Resumed: resume, with any edits
    Intercepted --> Killed: kill
    Observed --> [*]: forwarded and recorded
    Resumed --> [*]
    Killed --> [*]
```

Here is what an agent sends to hold a request, edit it and let it go. Flow ids are
UUIDs; `flow.list` returns them.

```text
flow.intercept({ rules: [{ method: "POST", url: "*/api/cart/*" }] })   // hold matching requests
flow.mutate({ id: "<flow-id>", edits: { body: "{\"qty\":999}" } })     // edit the held request
flow.resume({ id: "<flow-id>" })                                       // release it, as edited
```

Arming interception is a sensitive call, so an agent can make it only under the
`ask` policy, with the operator approving; `flow.mutate` and `flow.resume` are
ordinary write calls. An operator does the same three moves in a UI: arm
interception, edit the held row, press Resume.

---

## Install

aitmproxy supports macOS (Apple Silicon) and Linux (x86_64 and aarch64). **Windows
is not supported.** The Homebrew tap and the release binaries are public; no
account or token is needed.

**macOS**

```bash
brew tap mrbrutti/aitmproxy
brew install aitm                  # CLI, web UI, terminal UI, MCP server
brew install --cask aitmproxy      # the native macOS app (self-contained)
```

The formula is the `aitm` core; the cask is the app, which bundles its own core,
does not need the formula, and requires macOS 26 or later.

**Linux**

Download a package from the
[release page](https://github.com/mrbrutti/homebrew-aitmproxy/releases/latest),
then install it. Packages place `aitm` and `aitm-tui` on your `PATH` with obscura
beside them.

```bash
sudo apt install ./aitm-0.5.13-amd64.deb     # Debian / Ubuntu
sudo dnf install ./aitm-0.5.13-x86_64.rpm    # Fedora / RHEL
```

The release also ships `aitm-<version>-<target>.tar.gz` for Linux and macOS, and
a signed, notarized `Aitmproxy-<version>.dmg`.

**Cargo**

```bash
cargo install --git https://github.com/mrbrutti/aitmproxy aitm
```

Cargo builds only `aitm`; see [Build](#build) for obscura. The source repository
is private, so this needs git credentials with access to it.

To point the app at an external core, or to see how `aitm` finds obscura, read
[INSTALL.md](INSTALL.md). The website's
[download page](https://mrbrutti.github.io/aitmproxy/download.html) lists every
asset with its checksum.

## Quick start

```bash
# 1. Trust the local CA. It asks first; `aitm ca export` writes a PEM for other devices.
aitm ca install

# 2. Run the proxy with a UI.
aitm web          # proxy on 127.0.0.1:8080, web UI on 127.0.0.1:8082
aitm tui          # or the terminal UI
aitm              # or headless: proxy plus the stdio MCP server
```

`aitm web` prints a ready card on stderr whose `Web UI` row is
`http://127.0.0.1:8082/#t=…` (and an `Operator` row with `&expect=operator` when
operator access is configured); open it in a browser. Nothing is opened for you.

Point a browser, simulator or client at `127.0.0.1:8080` and flows appear in
whichever UI you launched. Active tools — replay, `request.send`, the browser,
the scanner and PoC runs — only reach hosts in scope, so list your targets in the
config file (`~/Library/Application Support/aitmproxy/config.yaml` on macOS,
`~/.config/aitmproxy/config.yaml` on Linux):

```yaml
scope:
  entries: ["example.test", "*.staging.example.test"]
```

Instead of pointing every client at the port by hand, the core can set itself as
the system HTTP/HTTPS proxy. The `system_proxy:` block in the same file controls
it:

```yaml
system_proxy:
  auto: false       # set the system proxy at startup, restore it at exit
  bypass: []        # extra hosts that skip the proxy, merged with the defaults
  state_file: ~     # where the previous setting is saved; default: beside the CA audit log
```

The same thing is available live over the bus and in every UI: `proxy.system.status`
reads the current system proxy and whether this core set it; `proxy.system.set`
(optional `bypass` list; operator-only) saves the previous setting and points the
system at the core; `proxy.system.unset` (operator-only) puts the previous setting
back. The previous setting is
restored on quit, after a crash by a watchdog, and at the next start; `aitm proxy system unset` restores by hand.
On a headless Linux box with no GNOME or KDE session there is no system proxy to
set; export the variables instead:

```bash
export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 no_proxy=localhost,127.0.0.1,::1
```

A running core can also have scope changed live from a UI. From there, hold and
edit a flow, discover the attack surface, build a PoC from a captured request, or
hand the whole thing to an agent. The website's
[getting-started guide](https://mrbrutti.github.io/aitmproxy/docs.html) walks the
same path step by step.

### Audit log

Every call that arrives over MCP or the command bus is recorded with its origin,
client label, command, arguments and outcome. The recent ones stay in memory (read
them with `agent.activity`). By default they are also appended to files on disk,
so the record outlives a restart and the in-memory ring. Nothing needs switching
on. The files belong to the core: no command and nothing on the bus reads or
serves them, with one exception that the operator's own opt-in creates. With
`session_io.allow_agent_file_io: true` and no `session_io.root`, the paths given to
`session.save`, `session.load`, `flow.export` and `flow.import` are not confined,
so an agent could overwrite or truncate any file the proxy can write, the audit
files included. That opt-in is the operator's authorization decision; set
`session_io.root` whenever agents get file access.

They sit in the per-user config directory, beside `config.yaml`, with mode `0600`
in a directory created `0700`:

- macOS: `~/Library/Application Support/aitmproxy/audit.jsonl`
- Linux: `~/.config/aitmproxy/audit.jsonl`

A flood of one kind of call must not push another kind off the disk, so each kind
has its own file, queue and size cap:

| File | Holds | Size cap |
|---|---|---|
| `audit.jsonl` | The operator's calls (the macOS app, the web operator link, `aitm-tui --bus`) and any call with origin `cli` | 20 MiB: 4 MiB each, the active file plus 4 rotated |
| `audit.agent.jsonl` | The agent's calls other than successful reads: writes, sensitive calls, refusals and failures | 48 MiB: 8 MiB each, the active file plus 5 rotated |
| `audit.reads.jsonl` | Successful reads such as `flow.list` and `flow.detail`, from any origin | 24 MiB: 8 MiB each, the active file plus 2 rotated |

A file that reaches its cap rotates to `.1`, `.2` and so on (`audit.agent.jsonl.1`
is the newest rotated file; the highest number is the oldest, and the only one
ever deleted). While rotation works, the three streams use at most 92 MiB with the
defaults. If rotation is wedged (for example a non-regular file planted at the
oldest rotated name), the active file is held to twice its size cap and further
lines are counted as dropped; `agent.status.durable_audit.degraded` turns true and
a `gap` marker records the dropped lines. Retention is by size, not time, so how
far back the files reach depends on call volume.

Configure it with `mcp.audit_log` in the same `config.yaml`:

```yaml
mcp:
  audit_log: true    # true (the default) | false | off | an absolute path
```

`false` or `off` turns the files off and creates nothing. An absolute path moves
the operator's file there; the other two sit beside it with `.agent` and `.reads`
before the extension (`/var/aitm/audit.jsonl` gives `audit.agent.jsonl` and
`audit.reads.jsonl` in `/var/aitm`). A relative path, `~/x` or an empty string is a
config error. The log is separate from `ca.audit_log`, the CA's own fail-closed
log, and the two must not share a file.

The environment variable `AITM_AUDIT_LOG` overrides the file. `off`, `false`, `0`
or `no` turn the log off; `on`, `true`, `1`, `yes` or `default` select the default
path; an absolute path names the file. Any other value is ignored with one
warning and leaves the file's setting alone, so a typo such as
`AITM_AUDIT_LOG=ofd` cannot silently turn the log off.

At startup the core logs one line, `durable audit log on`, naming the operator's
file. A path you set that cannot be used (a symlink, a directory, a parent that
other users can write to) stops the boot with the path and the reason, before any
port is bound. A default path that cannot be used (a read-only home, no config
directory) does not: the core warns once, runs with the log degraded and retries
about once a second. `agent.status` reports the state in `durable_audit`:
`enabled` and `degraded` to every caller, `dropped` and `write_failures` to the
operator only.

#### Reading the files

Each line is one JSON object. An entry has seven keys:

```json
{"at":1730419200123,"origin":"mcp","client_label":"claude-code","connection_id":"conn_1f3a9c05d2b84e77-3","command":"request.send","args":"{\"authority\":\"example.test\",\"headers\":{\"Authorization\":\"<redacted>\",\"X-Debug\":\"<redacted>\"},\"method\":\"GET\"}","result":"ok"}
```

`at` is epoch milliseconds. `origin` is `operator` for the operator's calls, `mcp`
for an agent's and `cli` for a CLI call, which lands in `audit.jsonl` with the
operator's. A one-shot that reaches a running core is recorded by that core as
`operator` with the client label `aitm-cli`; a verb that runs locally
(`aitm ca status`) still writes no line. `args` is the JSON text of the arguments,
redacted and cut at 512 bytes. `result` is `"ok"` or `{"error":"<reason>"}`.
`client_label` and `connection_id` are `null` when the call has none.

The writer adds two kinds of marker line. Neither has a `command` key, so an entry
is the line where `select(.command)` is true, and `select(has("marker"))` picks
out the markers:

- `{"marker":"start","schema":1,"at":…,"version":"…","pid":…,"stream":"agent"}` is
  the first line of every file the writer creates, and one more at every boot that
  appends to an existing file. It marks a restart: the in-memory ring was emptied
  there. `stream` is `control`, `agent` or `reads`.
- `{"marker":"gap","at":…,"from":…,"to":…,"dropped":…,"failed":…}` is written
  before the next entry after any were lost. `dropped` counts entries refused by a
  full queue, `failed` counts entries lost to write errors, and `from` and `to` are
  the `at` of the first and last lost entry.

Run these in the directory that holds the files:

```bash
jq -c 'select(.marker|not)' audit.agent.jsonl                    # entries only, no markers
jq -c 'select(has("marker"))' audit.agent.jsonl                  # restarts and gaps
cat audit*.jsonl | jq -s 'map(select(.command)) | sort_by(.at)'  # all three streams, in time order
jq -r 'select(.command) | [(.at/1000|floor|todate), .origin, .command] | @tsv' audit.jsonl
```

`audit*.jsonl` does not match rotated files; add `audit*.jsonl.*` to read those
too.

#### Limits

- **Best effort, not tamper-evident.** There is no hash chain or signature, and
  mode `0600` does not stop a process running as the same user. An agent with a
  shell on the operator's account can read the files and delete them. A deleted
  file is recreated with a `start` marker, so the loss shows as a break in the
  history, not as a continuous record. Do not treat the files as evidence-grade.
- **No `fsync` per line.** An OS crash or power loss can lose recent lines, and a
  process crash loses whatever was queued. The next start closes a torn last line
  with a newline but leaves it in the file, and `jq -s` stops at it. Put
  `jq -R 'fromjson?'` first to skip such a line:
  `cat audit*.jsonl | jq -R 'fromjson?' | jq -s 'map(select(.command))'`.
  Rotation and a clean shutdown do sync.
- **A flood drops the newest entries.** The call path never waits for the disk.
  When a stream's queue is full the newest entries are dropped, counted in
  `agent.status` and marked by a `gap` line. The streams are separate, so an agent
  flood cannot drop the operator's entries, but a sustained one does rotate earlier
  agent entries out of the size cap.
- **Sort by `at`, never by position.** A `gap` line's place in the file is not
  exact, two concurrent calls can be written in either order, and `at` is
  wall-clock milliseconds, so a clock change reorders it.
- **Not recorded:** the built-in UI of `aitm tui` (the operator and agent clients
  of that same process are recorded) and the local one-shot verbs such as
  `aitm ca status`, which run in their own process with no writer (a one-shot
  that reaches a running core is recorded by that core). Calls over
  streamable HTTP are recorded with `connection_id: null`.
- **One path per process.** Two `aitm` processes sharing one `mcp.audit_log` are
  not locked against each other; give each its own path.
- **Review before sharing.** The files name hosts, URLs, flow ids and paths. Do not
  attach them to a bug report unreviewed.

#### What is redacted before anything is written

One redaction applies at the source, and the writer checks every field again, more
strictly, just before it writes. The aim is that no token, secret or credential
value reaches a file. The rules below enforce it; the last item names what no rule
can see.

- **Configured tokens and environment secrets, by exact value.** The configured
  transport, operator and agent tokens, the web agent token, the per-run operator
  bridge token, and the value of every environment variable whose name says secret
  (`token`, `secret`, `password`, `passwd`, `credential`, `api_key`, `apikey`,
  `private_key`, `passphrase`, `access_key`) are masked as `[redacted]` wherever
  they appear and whatever frames them: raw, JSON-escaped and percent-encoded. An
  environment value that is plainly a switch (`true`, `false`, `off`) or a number
  under 8 digits is not treated as a secret, or masking it would corrupt ordinary
  JSON. A token of 4 to 7 characters is masked only as a whole word, and one under
  4 characters is not masked by value at all. The core warns at startup about any
  such secret shorter than 8 characters, naming where it came from and never the
  value.
- **Header values are default-deny.** Inside a header collection (`headers`, a
  list of name and value pairs, `edits.headers`), a header keeps its value only
  when its name is on a short benign list: `Accept*`, `Cache-Control`,
  `Connection`, `Content-Type`, `Content-Length` and the other plain content
  descriptors, `Date`, `Host`, `Origin`, `Referer`, `User-Agent`, `Sec-Fetch-*`,
  `Sec-CH-*`, and the routing and override headers (`X-Forwarded-*`, `X-Real-IP`,
  `X-HTTP-Method-Override`, `X-Original-URL`, `X-Rewrite-URL`). Every other value
  reads `<redacted>` and the name stays: `{"X-Debug":"<redacted>"}`. This is
  deliberate over-redaction, because a name cannot tell a debug header from one
  that carries a password. The capture store keeps the real request; open the flow
  (`flow.detail`) to see what was sent.
- **Credential lines and shapes in text.** Every `Authorization`,
  `Proxy-Authorization`, `Cookie`, `Cookie2` and `Set-Cookie` line is masked to its
  end (`Cookie: [redacted]`), folded continuation lines included. `Basic`,
  `Negotiate` and `NTLM` credentials, the password in a URL
  (`https://user:[redacted]@host`), JWT and JWE tokens, PEM and PGP private key
  blocks, and well-known vendor key shapes (AWS access key ids, GitHub, GitLab,
  Slack, Stripe, `sk-` and Google API keys) are masked wherever they appear.
- **Secret-named keys.** The value under a key such as `password`, `token`,
  `secret`, `cookie`, `authorization` or `api_key` is masked in JSON, form fields
  (`user[password]=`), XML and HTML elements, multipart fields, command-line flags
  (`--password x`, `-u user:pw`) and Debug-printed values. The audit adds the words
  `pass`, `pw`, `otp`, `totp`, `passphrase`, `private_key`, `access_key` and
  `signing_key`, and reads camelCase names such as `userPass`, `adminPw` and
  `totpCode`. A value typed into a field whose `selector` or `name` names a secret
  (`browser.type` into `#password`) reads `<redacted>`.
- **The same text everywhere.** The source applies the redaction before anything
  is stored, so the in-memory ring, `agent.activity` and the pushed
  `notifications/aitm/agent` audit line carry it too, not only the files. Custom
  header values no longer appear in them.
- **What no rule can catch.** A bare credential: one with no frame around it, no
  registered value and no known shape. A password typed into a free-text field
  under an innocuous key (`"note":"my password is hunter2"`), an application's own
  session id in a request body, or a number under an innocuous key reaches the
  file. A configured token shorter than 8 characters is only partly covered by
  value masking. Percent-encoded frames and SQL (`SET PASSWORD = 'x'`) are not
  read. The rules also err the other way: `pass: ok` in prose loses `ok`, and a
  `Cookie:` in the middle of a sentence loses the rest of its line.

---

## The three surfaces

The web UI, the terminal UI and the native macOS app are all clients of the core.
They show the same flows, scope, scanner results and commands, and each has a
**Scan** view that launches `scan.discover`. None of them is the core.

### Web UI

`aitm web` serves the embedded SolidJS UI on `127.0.0.1:8082` and prints the link
to open. The flow list filters by protocol and content type; the inspector shows
the request and response side by side, with headers, cookies, query, body and
timing.

![The web UI inspector showing a request and its JSON response](site/assets/web-detail-dark.png)

### Terminal UI

`aitm tui` runs the proxy and a ratatui interface in one process, and it works
over SSH. `aitm-tui` is the standalone UI that attaches to a running core. It is
keyboard-complete: held flows, editing, replay, compose and PoC building all have
keys.

![The terminal UI with two flows paused and the intercept bar showing resume, kill and edit](site/assets/tui.png)

### macOS app

A native SwiftUI app, signed and notarized, that bundles and manages its own core
and obscura, or attaches to an external core you run. See
[INSTALL.md](INSTALL.md#pointing-the-app-at-an-external-core).

![The macOS app overview with status, top hosts and timing](site/assets/mac-dark.png)

---

## Capabilities

### Four layers of the wire

| Layer | What you can do |
|---|---|
| **HTTP/1.1** | Hold requests and responses, edit method, URL, headers and body, replay, craft requests, and map to a local file or another upstream. |
| **HTTP/2** | Negotiated over ALPN and decrypted with the local CA. Each multiplexed stream is an ordinary flow you can hold and edit. |
| **WebSocket** | Every frame in both directions. Hold one, change it, or inject a frame toward either side. |
| **Raw L4 (TCP/UDP)** | Capture segments, craft and inject packets, send and receive, and — where the host allows — hold and edit bytes in the path. |

All four share one flow model, one command surface and one scripting API, so a
new protocol needs no new language. TLS is terminated with a CA generated on your
machine; hosts that pin certificates can be excluded with TLS passthrough.

**L4 platform support, stated plainly.** Live-wire L4 runs today on a privileged
`aitm` core, Linux first: capture and inject need `CAP_NET_RAW`, and in-path
hold-and-edit uses NFQUEUE with `CAP_NET_ADMIN`. `l4.enabled` defaults to off, and
without privilege the wire commands return a typed `L4Unavailable` rather than
failing silently. On a loopback interface Linux injection goes out at layer 3
through a header-included raw socket, because a layer-2 frame written to `lo` is
visible to sniffers but is never processed by the IP stack — the same workaround
scapy documents as its `L3RawSocket` (prior art; the capability needed is still
`CAP_NET_RAW`). The macOS app's embedded core degrades the same way; since
v0.5.2 the app ships a Network Extension capture path, off by default behind an
operator toggle.

### Embedded browser

aitmproxy bundles a headless browser engine, **obscura** — a Rust engine
embedding V8 and speaking CDP — behind the same `browser.*` commands. It starts
with aitmproxy as its upstream and the MITM CA already trusted, so an agent or an
operator can log in, click through a flow, take the screenshot that proves a
finding, and capture the resulting traffic, all in scope and all through the
proxy. An optional **scope-confined egress mode** (`confine_egress_to_scope`)
refuses out-of-scope public hosts rather than relaying them, which keeps a crawl
or browser-driven campaign inside the engagement.

obscura is a separate artifact, not produced by `cargo build`. The macOS app, the
Linux `.deb`/`.rpm` and the release tarballs bundle it; see [Build](#build) for a
source checkout.

### Attack-surface scanner

The scanner crawls an authorized, in-scope target, enumerates its **injection
points** — query and body parameters, headers, cookies, path segments — and runs
a catalogue of checks over them. It is deterministic and AI-free, and every step
is bounded by scope and by probe, page and time budgets.

```mermaid
%%{init: {"theme": "neutral"}}%%
flowchart LR
    target["scan.start<br/>target"] --> gate{"In scope?"}
    gate -- no --> refused["Refused before<br/>any page opens"]
    gate -- yes --> crawl["Crawl in obscura<br/>same-origin, capped"]
    crawl --> flows["Captured flows"]
    flows --> points["Endpoints and<br/>injection points"]
    points --> checks["Catalogue checks<br/>budgeted, paced"]
    checks --> issues["Issues<br/>scan.issues"]
```

```text
scan.start({ target: "https://staging.example.com/" })
```

A scan is a **job**: `scan.start` accepts it against an in-scope target and
returns a job id immediately. Poll `scan.status` for state, counters and why it
stopped; read what it found with `scan.issues` and `scan.issue`, the crawled
tree with `scan.sitemap`, and stop it with `scan.cancel`. `scan.map` crawls and
runs the passive checks without sending a probe. `scan.checks` lists the
catalogue, and `check.<id>` runs one check by hand against one parameter. Run
these from the **Scan** view in any UI, over MCP, or from the one-shot CLI,
which acts on the running core: a crawl needs that core's embedded browser, and
with no core running the CLI refuses rather than crawling nothing. Issues link
back to the flows they came from. Details in [docs/scanner.md](docs/scanner.md).

### Scripting and PoCs

**Rhai plugins** see each flow as it passes and can edit it, answer it, or record
a finding. Scripts run in a deny-by-default sandbox: they reach the network only
through gated host calls such as `http.send`, held to the same scope, SSRF and
rate guards as the commands; they run under time and operation limits; and they
cannot widen scope unless the operator turns on `allow_scope_add`. A hook that
fails or is refused is discarded and the flow carries on unchanged.

**PoCs** are declarative YAML — a few steps, a few matchers and a success
condition — so a finding can be re-run later and diffed like code. Steps can
drive HTTP, the browser, scripting and native L4. `poc.run` executes a PoC with
no agent in the loop and writes its artifacts; a **finding** (`findings.record`)
links back to the PoC that proves it.

```yaml
id: reflected-xss-search-q
info:
  name: Reflected XSS in search 'q' parameter
  severity: high

variables:
  - name: target
    required: true

steps:
  - http:
      method: GET
      url: "{{target}}/search?q=x"
      matchers:
        - type: status
          status: 200

success:
  all:
    - type: status
      status: 200
```

Both languages are written to be read and written by people first and agents
second. Their canonical, machine-checked catalogs — `rhai.api.json` and
`poc-yaml.schema.json` — live in [`docs/design/languages/`](docs/design/languages)
and the shipped engine is asserted against them in CI. The website has the full
[scripting reference](https://mrbrutti.github.io/aitmproxy/scripting.html) and
[PoC format](https://mrbrutti.github.io/aitmproxy/poc.html).

### And the rest of the proxy

- **Intercept rules** by method, host and URL, at the request, response or
  WebSocket-frame phase; arm and disarm live.
- **Replay and compose** — resend any captured request, or craft one from scratch
  with `request.send`; the result is captured as a new flow.
- **Map rules** to answer a request from a file or redirect it to another
  upstream.
- **Sessions and HAR** — save and reload a capture; import and export HAR.
- **Certificate management** — export, inspect, install and uninstall the CA
  (`ca.*`). An agent can export and check status; installing is gated behind a
  human.

---

## Agents over MCP

aitmproxy is an MCP server (`aitm-mcp`): every command is exposed to an agent
under the same name and shape, over **stdio**, **loopback TCP** or **streamable
HTTP**. Launching `aitm` with no arguments serves MCP over stdio.

```bash
claude mcp add aitmproxy -- aitm
```

For Claude Desktop, add `{"mcpServers": {"aitmproxy": {"command": "aitm"}}}` to
`claude_desktop_config.json`. Hosts that reach a URL rather than launch a command
use the token-guarded loopback or streamable-HTTP transport.

The operator governs the agent with a policy — `all`, `auto`, `ask`, `readonly`
or `paused` — that the agent cannot change. Sensitive verbs (installing the CA,
widening scope, TLS passthrough, running a PoC) also sit behind their own config
opt-ins, such as `scope.allow_agent_widen` and `poc.allow_agent_run`. Under `ask`,
a sensitive call waits for the operator's approval; under `auto`, it is refused
unless its opt-in allows it. The operator token (`aitm operator-token generate`)
is CLI-only: no agent can run it.

```mermaid
%%{init: {"theme": "neutral"}}%%
sequenceDiagram
    participant A as AI agent
    participant M as MCP server
    participant G as Gate
    participant C as Core
    participant O as Operator
    A->>M: tools/call, for example flow.mutate
    M->>G: command, arguments, operator = agent
    alt routine command
        G->>C: invoke
        C-->>A: result
    else sensitive command, for example ca.install
        G-->>O: under the ask policy, park for approval
        O-->>G: approve or deny
        Note right of G: under auto, refused unless its config opt-in allows it
    end
    Note over C: every call is audit-logged: who, what, outcome
```

The macOS app's **Agent** view shows that traffic live: each call with its
operator, the agent policy, and a pending sensitive command waiting for you to
approve or deny it.

![The macOS app Agent view: an audit trail of agent and operator calls, with a ca.install request awaiting approval](site/assets/mac-agent-dark.png)

The [`aitmproxy-plugin/`](aitmproxy-plugin/) package wires the server into AI
hosts, with rich MCP Apps widgets in ChatGPT and Claude Desktop / claude.ai and
clean text in Claude Code. Start at
[`aitmproxy-plugin/README.md`](aitmproxy-plugin/README.md); the transport threat
model is in [`aitmproxy-plugin/docs/security.md`](aitmproxy-plugin/docs/security.md).

---

## Reference

### Architecture

One spine throughout: **a thin core, and everything else is a plugin or a
client.**

- **Thin core (`aitm-core`).** Accepts connections, runs sans-IO protocol state
  machines, holds the flow store, and emits typed events to an ordered plugin
  chain with halt and short-circuit semantics. It owns the deny-by-default
  **scope and rate guard** that every action passes through.
- **Protocol modules are plugins.** `aitm-proto-http` (HTTP/1.1 and HTTP/2),
  `aitm-proto-ws` and `aitm-proto-l4` plug in behind one `ProtocolModule` seam.
  The seam is protocol-extensible: new protocols register through the same
  guards with no change to the core.
- **Features are plugins.** Scripting, map rules, session I/O, WebSocket control,
  findings, the PoC engine and the scanner each register commands.
- **Frontends are clients.** The MCP server, the web UI, the TUI and the macOS
  app all drive the core by invoking registered commands. The one-shot CLI
  (`aitm <family> <verb> --flag value`) acts on the running core: it finds the
  core's operator bus (every `aitm`, `aitm web`, `aitm tui` and the macOS app's
  core serve one on loopback by default), runs the command there and prints the
  answer; with no core running it refuses and says so. A few verbs run on this
  machine instead of a core: `ca`, `findings list|get|remove`,
  `poc list|get|artifact`, `scan report`, `script validate`,
  `proxy system unset`.

Adding a command to the core exposes it over MCP and in every UI at once, under
the same scope, sensitivity and confirmation rules.

### The command surface

A representative selection, grouped by family. Any connected MCP client can list
every tool with its parameters, and the generated catalog is in
[`aitmproxy-plugin/docs/tool-reference.md`](aitmproxy-plugin/docs/tool-reference.md).

| Family | Commands | What it covers |
|---|---|---|
| Flows | `flow.list` `flow.detail` `flow.intercept` `flow.mutate` `flow.replay` `flow.resume` `flow.kill` `flow.mark` `flow.comment` `flow.export` `flow.import` `flow.subscribe` | Inspect, pause, modify, replay and stream HTTP and WebSocket flows |
| Requests | `request.send` | Craft and send an arbitrary request |
| WebSocket | `ws.intercept` `ws.frame` `ws.send` | Intercept and inject frames |
| Proxy | `proxy.status` `proxy.pause` `proxy.resume` | Control the accept loop |
| Scope | `scope.add` `scope.list` `scope.remove` | The in-scope allow-list (deny-by-default) |
| TLS | `tls.passthrough.add` `tls.passthrough.list` `tls.passthrough.remove` | Bypass MITM for named hosts |
| CA | `ca.export` `ca.status` `ca.install` `ca.uninstall` | Manage the MITM CA (agent install is gated) |
| Browser | `browser.navigate` `browser.click` `browser.type` `browser.get_dom` `browser.screenshot` `browser.eval` | Drive the embedded browser |
| Mapping | `map.add` `map.list` `map.remove` | Map and redirect rules |
| Scripting | `script.list` `script.validate` `script.save` `script.reload` | Manage Rhai scripts |
| PoC and findings | `poc.build` `poc.run` `poc.get` `poc.list` `poc.artifact` `findings.list` | Build, run and record reproducible checks |
| Scanner | `scan.discover` | Crawl an in-scope target and discover injection points |
| Agent | `agent.set` `agent.status` `agent.activity` `agent.approve` | Agent policy, the audit view and the operator approval gate |
| Session | `session.save` `session.load` | Persist and restore a working session |
| L4 | `l4.capture.start` `l4.intercept.start` `l4.craft` `l4.inject` `l4.send_recv` `l4.flow.list` `l4.scope.add` … | Raw TCP and UDP capture, interception and packet crafting |

### Repository layout

A Cargo workspace of focused crates under `crates/`, operator UIs under `apps/`,
and the MCP plugin package at the root.

- **Core and proxy** — `aitm-core`, the protocol crates `aitm-proto-http`,
  `aitm-proto-ws`, `aitm-proto-l4` and `aitm-proto-test`, plus `aitm-rules` and
  `aitm-ca`.
- **Plugins and scripting** — `aitm-plugin`, `aitm-plugins`, and
  `aitm-plugin-rhai`, `-maprules`, `-passthrough`, `-wsctl`, `-sessionio` and
  `-scanner`.
- **Findings and PoC** — `aitm-poc`, `aitm-findings`.
- **MCP** — `aitm-mcp`: the tool registry, the MCP Apps widgets and the stdio,
  loopback-TCP and streamable-HTTP transports.
- **Binary and UIs** — `aitm`, `aitm-cli`, `aitm-tui`, `aitm-browser`,
  `aitm-bus-client`, `aitm-testtarget`; the macOS and web UIs live in `apps/mac`
  and `apps/web`.

### Built to be trusted on the wire

- **No `unsafe` Rust** anywhere in the workspace.
- **~31,000 requests per second**, sustained on a single instance with flat
  memory.
- **Deny-by-default** at every layer: scope, scripting, agent privileges and the
  scanner each refuse before they act.
- **One audit trail** for every command that arrives over MCP or the command bus:
  its origin, its arguments (credentials redacted) and its outcome, kept in memory
  and in best-effort files on disk. It is not tamper-evident; the limits are under
  [Audit log](#audit-log).

## Build

```bash
cargo build                                        # whole workspace
cargo build --release                              # release binary
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The release binary is `target/release/aitm`, or `cargo install --path crates/aitm`.
A bare `cargo build` produces **only** `aitm`, not obscura. The proxy runs
without it, but the browser commands (and so the scanner) need obscura reachable.
In a dev checkout, `scripts/fetch-obscura-dev.sh` downloads the matching build
beside `target/debug` and `target/release`; `scripts/package.sh` builds a release
`aitm` and bundles obscura next to it. The discovery order is in
[INSTALL.md](INSTALL.md#building-from-source-cargo--bare-binary).

## Documentation

- **[Website](https://mrbrutti.github.io/aitmproxy/)** — features, getting
  started, scripting and PoC references, demos, downloads.
- [INSTALL.md](INSTALL.md) — install on macOS and Linux, build from source, point
  the app at an external core.
- [docs/scanner.md](docs/scanner.md) — the scanner: scan jobs, the `scan.*`
  and `check.<id>` verbs, profiles, the `scanner:` config section, issues,
  and writing a check in Rhai.
- [`aitmproxy-plugin/README.md`](aitmproxy-plugin/README.md) — the MCP plugin for
  ChatGPT, Claude Desktop / claude.ai and Claude Code.
- [docs/design/languages/](docs/design/languages) — the canonical Rhai and
  PoC-YAML catalogs.
- [docs/RELEASE.md](docs/RELEASE.md) — the release runbook.
- Research, design and process live in [`docs/`](docs/) — start with
  `docs/research/05-synthesis.md` and `docs/research/MEMORY.md`. Contributor
  conventions are in [CLAUDE.md](CLAUDE.md).

## License

Licensed under either of MIT or the Apache License, Version 2.0
(`MIT OR Apache-2.0`) at your option.
