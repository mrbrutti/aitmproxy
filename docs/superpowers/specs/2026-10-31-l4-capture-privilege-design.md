# L4 capture privilege, obtained by the product design

**Status:** Draft, awaiting Matt (design forks i–iv open; bundle-layout section to the orchestrator before implementation)
**Research inputs:** `docs/research/13-l4-capture-privilege-without-cli.md` (primary), `docs/research/12-l4-parity-audit.md`
(defect D0, the honest-availability requirement, the rig), `docs/research/08-l4-packet-rust.md` (privilege model,
candidate F, guard placement), `docs/research/10-macos-network-extension.md` and
`docs/research/experiments/2026-10-29-macos-ne-spike.md` (what the sysex is), `docs/RELEASE.md`,
`scripts/notarize-dmg.sh`, `apps/mac/build.sh`, `apps/mac/tools/snap-dev.sh`.
**Related specs:** `2026-10-31-l4-parity-fixes-design.md` (sibling, UI defects D1–D15; consumes this spec's
availability seam, §8), `2026-10-31-macos-status-page-and-first-run-design.md` (`ConnectionSummary`, Getting
started), `2026-10-30-macos-ne-ship-and-toggle-design.md` (the NE session; owns every sysex change).

## Intent

Raw L4 capture and injection are unreachable in every shipped build: the core probes `/dev/bpf*` or
`CAP_NET_RAW` once at start and tells the operator to "install ChmodBPF or run with privilege" or to type
`setcap` (D0). Matt: "I should not have to do anything in the command line; if I need to use something as
root you should trigger the right permission." The bar is Proxyman: a first-launch card that says what the
privileged helper does, one standard OS approval, and a later "this will fix it" nudge where the missing
privilege shows up. This design makes the product obtain the privilege itself, with at most one standard
OS prompt, on macOS and Linux, and makes every frontend (macOS app, TUI, web UI, CLI) able to show the
state honestly and offer the one action that fixes it.

## Goals

- G1. Every core answers `l4.privilege` with the real per-capability state and, when something is
  missing, the one action that gets it. No reply ever tells the operator to type a command.
- G2. macOS: one click in the app plus one System Settings approval makes `/dev/bpf*` usable by the
  operator's account, persistently across reboots, for every `aitm` on the Mac (app-embedded, Homebrew,
  tarball). An already-running core notices without a restart.
- G3. Linux: one polkit dialog (graphical, or textual on the tty) starts a small privileged helper that
  does capture and injection for the core, which itself stays unprivileged.
- G4. TUI, web UI and CLI trigger the same action through the core (`l4.privilege.request`); on a Mac
  they hand off to the installed app; with no way to prompt they say so plainly.
- G5. The agent can never trigger a privilege request by any path.
- G6. After approval, the audit walk (capture lo/lo0, real TCP and UDP, inject with `injected: true`,
  `send_recv` echo, out-of-scope refusal) passes live on a real core.

## Non-goals

- No change to the Network Extension or sysex (option A, frames-in-the-sysex, is out; §6).
- No L4 UI parity work: live L4 rows in the mac app, capture/intercept controls, L4 scope add, polling
  churn, `l4.flow.get` bytes. Those are the sibling parity spec's (D1–D15), except the two seams named in §8.
- No in-path interception through the helper (Linux NFQUEUE stays "core holds `CAP_NET_ADMIN` itself").
- No macOS `pkg`, no `osascript ... with administrator privileges` installer, no SMJobBless, no legacy
  `/Library/LaunchDaemons` plist. **(Architect's call:** one privileged install path per OS.)
- No Windows.
- No setcap on `aitm`, ever; no setuid binaries.
- No new authorization model: scope stays the authorization; this design only obtains OS privilege.

## Anti-goals

- A reply, toast, label, log line or doc string in the product that tells the operator to run `sudo`,
  `setcap`, `chmod`, `chgrp`, `dseditgroup`, `launchctl` or `pkexec` as the way forward. (Docs may describe
  the headless Linux fallback; the product never points at it as the default.)
- A privilege request that fires without a human operator's act: from an agent, from a gated verb that
  failed, from a URL a web page opened, or from a background poll.
- A privileged component that checks less than today's `L4Guard` where it writes.
- A dev bundle (`/tmp/Aitmproxy-dev*.app`) or `~/Applications` build registering a root daemon.
- "Allow Packet Capture" that succeeds in the OS but leaves the running core still saying unavailable.
- A fourth connection vocabulary in the mac app that does not come from `ConnectionSummary`.
- Fixture, snapshot, self-test or seeded-store runs offered as proof that any of this works.

## Constraints

- **Zero `aitm-core` edits.** Everything lives in `aitm-proto-l4`, a new `aitm-l4-helper` crate, the `aitm`
  binary's wiring, the frontends and packaging. The agent refusal uses the existing
  `CommandHost::caller_is_trusted_control()`; `l4.privilege.request` is not added to
  `aitm-mcp` `defers_to_command_gate` (no `aitm-mcp` edit either).
- Workspace `unsafe_code = "forbid"` stays. The Linux helper uses safe APIs (`nix`, `caps` or equivalent).
  Phase 1 passes no fds. Any later `unsafe` goes in a leaf crate in the `aitm-peer-token` style with a
  `// SAFETY:` comment and Security-reviewer sign-off.
- The `L4 unavailable: ` error prefix stays (frontends match on it today).
- macOS: `SMAppService.daemon` needs macOS 13+; the app's floor is 26.0. A daemon-bearing app must be
  Developer-ID-signed, hardened-runtime, notarized, and live in `/Applications`.
- Linux: polkit (`pkexec`) available on Debian/Ubuntu (`pkexec` package) and Fedora/RHEL (`polkit`);
  headless hosts may have no agent.
- Quiet logs: one `warn` line at start when L4 is enabled and not available, one `info` line per state
  change. Never log the operator token or a frame's payload.
- New bus verbs update the three contracts: `EXPECTED_TOOLS`, `CORE_TOOLS`, `bus-fixture.json`.
- macOS UI words follow the Status-page spec: "All Apps" is the extension. This feature is **Packet
  capture** in UI text; never "BPF", "L4 capture" or "daemon".

## Design

### 1. Shape of Phase 1

| Piece | macOS | Linux |
|---|---|---|
| Who opens the wire | the core, in process, through `pcap` (unchanged) | `aitm-l4-helper`, a separate process, through `pcap` |
| What gets privilege | `/dev/bpf*` become `root:access_bpf 0660`; the operator joins `access_bpf` (B2, the Wireshark model) | the helper runs as the operator with only `CAP_NET_RAW` after pkexec (L-C) |
| Who installs it | the app registers `aitm-l4-helper bpf-permissions` with `SMAppService.daemon` | the deb/rpm ships the helper + a polkit `.policy` |
| The one prompt | Login Items & Extensions approval (+ admin auth if macOS asks) | the polkit dialog, once per core run |
| Re-applied | at every boot (launchd `RunAtLoad`) | per core run (helper lives as long as the core) |
| Who triggers | the app's button; TUI/web/CLI ask the app (§3.4) | the core runs `pkexec` on `l4.privilege.request` |

One binary, `aitm-l4-helper` (Rust), has the macOS permission-fix mode in Phase 1 and the Linux serve
mode in Phase 1; Phase 2 brings serve mode to macOS (candidate 1) and retires the permission fix.
**(Architect's call:** Rust, not a Swift tool or a zsh script: one artifact on both OSes, built by
`scripts/package.sh` like `aitm`, and the path to candidate 1 is the same binary.)

### 2. Core

#### 2.1 `PrivilegeState` (new, `crates/aitm-proto-l4/src/privilege/`)

One shared `Arc<PrivilegeState>` replaces the cached `L4Privilege` as the source of truth. It is read by
the `l4.privilege` verb, by `L4Gated` on every invocation, and by a routing backend.

- `PrivilegeState::new(cfg: &PrivilegeConfig) -> Arc<Self>`
- `PrivilegeState::report(&self) -> PrivilegeReport` (re-probes when the cached result is unavailable
  and older than 1 s; **Architect's call** for the TTL)
- `PrivilegeState::request(&self) -> RequestOutcome` (non-blocking; starts the platform action)
- `PrivilegeState::backend(&self) -> Arc<dyn CaptureInjectBackend>` (in-process `PcapBackend` when the
  process itself is privileged; `HelperBackend` when a Linux helper session is up)
- `fn derive(inputs: &ProbeInputs) -> PrivilegeReport` in `privilege/derive.rs`: pure, no I/O, the whole
  decision table below. Platform files gather `ProbeInputs`: `privilege/macos.rs`, `privilege/linux.rs`.

`L4Privilege` and `probe()` stay as the low-level probe (`ProbeInputs` uses them); their reason strings
lose the hand-typed commands. `L4Gated` holds the `Arc<PrivilegeState>` instead of a fixed reason string,
so a core started before approval serves capture after it. Every caller of `PcapBackend::new()`
(`capture.rs`, `sendrecv.rs`, `language.rs` for the Rhai/PoC `l4:` step) takes `state.backend()` instead.

#### 2.2 `l4.privilege` (Read, always answers)

Registered by the `aitm` binary whether or not `l4.enabled` (so a frontend can say "L4 is off in this
core's config"). Agents may call it. Result:

| Field | Type | Meaning |
|---|---|---|
| `enabled` | bool | `l4.enabled` in this core's config |
| `platform` | `"macos"` \| `"linux"` \| `"other"` | |
| `capabilities.capture`, `.inject`, `.intercept` | `Capability` | see below |
| `helper` | `Helper` | the privileged component as this core sees it |
| `request` | `RequestProgress` \| null | the last `l4.privilege.request` on this core |
| `checked_at` | RFC 3339 string | when the probe last ran |

`Capability` is one of:

- `{"state": "available", "via": "process" | "helper"}`
- `{"state": "needs_approval", "reason": str, "how": {"kind": "app_action" | "os_dialog" | "package" | "pkexec", "label": str, "action": Action}}`
- `{"state": "unsupported", "reason": str}`

`Action` is `{"type": "bus_verb", "verb": "l4.privilege.request"}` or
`{"type": "open_url", "url": "https://mrbrutti.github.io/aitmproxy/download.html"}`. Never a shell
command. `kind` tells a frontend what will happen: `app_action` (the Aitmproxy app does it),
`os_dialog` (this core already handed the request to the app; macOS is waiting for the operator's approval), `package` (install something
first), `pkexec` (a polkit password prompt).

`Helper` is `{"kind": "macos_bpf_permissions" | "linux_pkexec_helper" | "linux_cap_helper" | "none",
"status": "not_installed" | "installed" | "applied" | "running" | "version_mismatch" | "unknown",
"version": str | null, "detail": str | null}`.

`RequestProgress` is `{"state": "pending" | "handed_to_app" | "approved" | "dismissed" | "failed",
"at": RFC 3339, "message": str}`.

**macOS decision table** (`derive`), first match wins:

| Inputs | capture/inject | helper.status |
|---|---|---|
| `l4.enabled` false | `unsupported`, "L4 is off in this core's config (l4.enabled)" | as found |
| a `/dev/bpf*` opens read+write | `available`, via `process` | `applied` if the receipt exists, else `unknown` (someone else fixed it, e.g. Wireshark) |
| receipt exists, open fails | `needs_approval` `app_action`, reason from the receipt's `errors`, else "Packet capture is set up but this account cannot use it yet; open the Aitmproxy app to finish" (the app knows whether re-login or re-approval is needed) | `applied` |
| no receipt, this core's `request.state` is `handed_to_app` | `needs_approval` `os_dialog`, label "Approve Aitmproxy in System Settings ▸ General ▸ Login Items & Extensions" | `installed` |
| app at `macos_app_path` embeds the helper plist, no receipt | `needs_approval` `app_action`, label "Allow packet capture in the Aitmproxy app" | `installed` |
| otherwise | `needs_approval` `package`, label "Install the Aitmproxy app (DMG or Homebrew cask); it asks macOS for packet-capture permission", `open_url` | `not_installed` |

`intercept` on macOS is always `unsupported`, "in-path interception is Linux only". The receipt is
`/Library/Application Support/Aitmproxy/l4-helper.json` (§3.1). The core cannot read `SMAppService`
status (it belongs to the app bundle); **(Architect's call:** nobody relays it. The core reads the receipt
and the bundle; the app, which can read `SMAppService.status`, shows the finer states itself.)

**Linux decision table**, first match wins:

| Inputs | capture/inject | helper |
|---|---|---|
| `l4.enabled` false | `unsupported`, as macOS | as found |
| process `CapEff` has `CAP_NET_RAW` | `available`, via `process` | `none` |
| a helper session is connected | `available`, via `helper` | `running` |
| helper found and its `--probe` reports `CAP_NET_RAW` effective (file caps) | `available`, via `helper` (session starts lazily on first use, no prompt) | `linux_cap_helper`, `installed` |
| helper found, root-owned path, policy file present, `pkexec` present, a prompt is possible (§5.5) | `needs_approval` `pkexec`, label "Allow packet capture (asks for an administrator password)" | `linux_pkexec_helper`, `installed` |
| helper found, root-owned, but no prompt is possible | `needs_approval` `package`, "No password prompt can be shown here (no desktop session or terminal); see the headless setup in the docs" | `installed` |
| helper found but its path or a parent is not root-owned, or is group/world-writable | `needs_approval` `package`, "Install the aitm .deb or .rpm to get the packet-capture helper" | `not_installed`, detail names the path |
| otherwise | `needs_approval` `package`, same label, `open_url` | `not_installed` |

`intercept` on Linux: `available` when the process holds `CAP_NET_ADMIN` (today's path), else
`unsupported`, "in-path interception needs the core itself to hold CAP_NET_ADMIN; the packet-capture
helper does not provide it yet".

Helper discovery order: `l4.privilege.helper_path` from config, then `<exe dir>/aitm-l4-helper`,
`/usr/lib/aitmproxy/aitm-l4-helper`, `/run/wrappers/bin/aitm-l4-helper`.

#### 2.3 `l4.privilege.request` (Sensitive, operator-only, confirm)

- Self-gates first line: if `!host.caller_is_trusted_control()`, refuse with
  `l4.privilege.request refused: only an operator can ask for packet-capture permission; an agent never can.`
  Not in `defers_to_command_gate`, so policy `All` cannot defer it.
- `sensitivity()` is `Sensitive`; `confirm_prompt` is always `Some`: macOS "Ask the Aitmproxy app to set up
  packet capture? macOS will ask an administrator to approve a background helper." Linux "Ask for
  administrator approval to start the packet-capture helper? A password prompt will appear on your
  desktop or in the terminal running aitm."
- No params. Returns at once (`invoke` never blocks on the OS): `{"outcome": "already_available" |
  "pending" | "handed_to_app" | "cannot_prompt", "message": str, "privilege": PrivilegeReport}`. Frontends
  poll `l4.privilege` for `request` progress.
- One request at a time; a second call while one is pending returns `pending` with the same progress.
- macOS: `handed_to_app` after `/usr/bin/open -a <macos_app_path> aitmproxy://packet-capture/allow`
  (§3.4); `cannot_prompt` when the app is absent.
- Linux: `pending` after spawning `pkexec <helper> serve --connect <socket>` (§5); the progress moves to
  `approved` when the helper connects and passes peer checks, `dismissed` on pkexec exit 126, `failed` on
  127 or any other exit, or after 300 s.

#### 2.4 Other core changes

- `l4.capture.status` is no longer privilege-gated: it returns `{"captures": [...], "privilege":
  PrivilegeReport}` on any core. **This spec owns that change** (the `l4.capture.status` half of D11),
  because it is the same edit to the gate list in `module.rs`; the parity spec owns the
  `l4.scope.add` confirm half of D11 and every UI that renders the result.
- `L4Gated` error text: `L4 unavailable: packet capture is not allowed yet (<how.label>)`.
- Config, under `l4.privilege` (**Architect's call** for names and defaults): `helper_path` (none),
  `macos_app_path` (`/Applications/Aitmproxy.app`), `request` (`manual` | `at_start`, default `manual`).
  `at_start` makes the core call the request itself once at start when capture needs approval: the
  operator wrote that config, so it is an operator act. This is the CLI path for `aitm` and `aitm web`
  that needs no new command.
- The start-up `warn` line becomes `L4 enabled; packet capture needs approval: <how.label>`.
- `aitm l4.privilege` and `aitm l4.privilege.request` work as one-shot CLI verbs through the registry,
  like every other verb.

### 3. macOS (B2)

#### 3.1 The permission helper (`aitm-l4-helper bpf-permissions`)

Runs as root under launchd, at registration and at every boot, then exits. Takes no input: fixed
argv, no environment trust, no IPC, no network. In order:

1. Pre-create the device nodes: open each of `/dev/bpf0` to `/dev/bpf255` read-only until 256 exist
   (XNU clones a node when the last one is opened; `BPF_MAX_DEVICES` is 256).
2. For every `/dev/bpfN` (N in 0–255): refuse unless it is a character device with the major number
   of `/dev/bpf0`; `chown root:access_bpf`; `chmod 0660`.
3. Ensure group `access_bpf` exists (create it if absent, as Wireshark's installer does).
4. If a console user is logged in and is a member of `admin`, add them to `access_bpf`. At boot there is
   none and nothing is added; membership persists from the first run.
5. Write the receipt atomically: `/Library/Application Support/Aitmproxy/l4-helper.json` (directory
   0755 `root:wheel`, file 0644 `root:wheel`; refuse if the directory is a symlink or not root-owned).
   Fields: `schema` (1), `helper_version`, `applied_at`, `group`, `gid`, `nodes` (count set), `members_added`
   (user names), `errors` (strings).
6. Log one line per run to the unified log, subsystem `com.mrbrutti.aitmproxy.l4-helper`.

`aitm-l4-helper bpf-permissions --dry-run` prints the plan and changes nothing; it runs unprivileged
(the developer loop, §4.6). Group `access_bpf` is the recommended default, fork (ii). If spike S4 shows a
running process does not see the new membership until re-login, the card says "log out and back in once
to finish" and the default is reconsidered with Matt.

#### 3.2 The app (`apps/mac`)

- `Kit/PacketCapture.swift` (pure, tested): decodes `l4.privilege`; `PacketCaptureGate.canRegister(bundlePath:
  helperPresent:) -> Bool` (true only for `/Applications/Aitmproxy.app` with the helper and plist
  present); `PacketCaptureAdvice.make(privilege:, helperStatus:, canRegister:)` returns the lane word,
  detail, remedy and actions. `helperStatus` is the app's view of `SMAppService.Status`
  (`notRegistered`, `enabled`, `requiresApproval`, `notFound`).
- `Aitmproxy/Privilege/PacketCaptureHelper.swift`: the only file that touches `SMAppService`. `register()`
  (unregister first when the bundled helper version differs from the receipt), `unregister()`,
  `status`, `openLoginItems()` (`SMAppService.openSystemSettingsLoginItems()`). Every call is behind
  `canRegister`.
- `ConnectionSummary` gains a `packets` lane, shown on the Status page and never in the toolbar, plus a
  Getting started step `packetCaptureAllowed`, "Allow packet capture (optional, for raw TCP and UDP)",
  present whenever the bundle embeds the helper. **(Architect's call:** a fourth Status card, not a modal
  or wizard. Status-page rule 76 forbids onboarding tours.) Words:

| Facts | state | word | remedy |
|---|---|---|---|
| capture `available` | ok | packet capture allowed | — |
| `notRegistered`, can register | off | packet capture not allowed | "Allow packet capture to see raw TCP and UDP" |
| `requiresApproval` | working | waiting for approval | "Turn on Aitmproxy in System Settings ▸ General ▸ Login Items & Extensions" |
| `enabled`, probe still fails | warning | allowed, not active yet | the core's reason |
| cannot register (not in /Applications, dev bundle, no helper) | off | packet capture unavailable | "Move Aitmproxy to Applications" or "Needs the signed app from the download page" |

- **The card** (Status page, and the same view in Settings ▸ Packets), a plain checklist like Proxyman's:
  title "Allow packet capture (needs administrator approval)", then
  1. "Adds a small background helper that runs as root once each time your Mac starts."
  2. "It lets the access_bpf group read and write the packet-capture devices, as Wireshark does, and adds you to that group."
  3. "It does nothing else: no network connections, no listening socket, no other files changed."
  4. "Any app you run can then capture and send raw packets. Aitmproxy itself still sends only to your L4 scope."
  5. "Remove it any time in System Settings ▸ General ▸ Login Items & Extensions."

  Buttons: **Allow Packet Capture…** (primary; registers, then opens Login Items when
  `requiresApproval`) and **Not Now** (collapses the card to its one-line lane; never shown again
  unprompted on this machine; the Getting started row stays).
- **The nudge**: where packets would appear (the L4 empty state, and the notice after a failed
  `l4.capture.start`), when capture is `needs_approval`: "No packets? Packet capture isn't allowed on
  this Mac yet. **Allow Packet Capture…** will fix it." The L4 surface is the parity spec's; this spec
  owns only this line and its button.
- Settings ▸ Packets (new tab): the card, the helper status, and **Remove Packet Capture…** (confirm;
  `unregister()`; then "Removed. The devices go back to root-only after the next restart.").
- `L4Availability.resolve` is re-derived from the decoded `l4.privilege`. The `embeddedReason` text
  ("the embedded core … cannot open /dev/bpf") is deleted: B2 makes it false.
- Update: on launch, when `status == .enabled` and the receipt's `helper_version` differs from the
  bundle's, the app re-registers (unregister then register). Spike S3 decides whether this re-prompts.
  The card shows whatever results.

#### 3.3 What the operator sees, start to finish

First launch → Status shows the Packets card → **Allow Packet Capture…** → macOS shows its "background
item added" notice and the app opens Login Items & Extensions → the operator turns on Aitmproxy under
"Allow in the Background" (and authenticates if macOS asks) → launchd runs the helper → within seconds
the card reads "packet capture allowed" and every core on the Mac can capture. Nothing is typed.

#### 3.4 TUI, web and CLI on a Mac

The core cannot register a daemon. On `l4.privilege.request` it runs
`/usr/bin/open -a <macos_app_path> aitmproxy://packet-capture/allow`.

- The app declares the `aitmproxy` URL scheme (`CFBundleURLTypes`) and accepts exactly that one URL.
  Anything else is ignored and logged.
- On that URL the app comes forward, opens Status and highlights the Packets card with "Requested from
  another aitmproxy window". **It never registers until the operator clicks Allow Packet Capture… in the
  app.** The URL can come from any local process or web page, so the click is the operator's act
  (threat T4).
- **(Architect's call:** a URL, not `open -b <id> --args …`. `open(1)` passes `--args` only when it
  launches the app and drops them when the app is already running. `-a <path>`, not `-b <id>`: the dev
  bundle shares the bundle id `com.mrbrutti.aitmproxy`, and `-b` can resolve to `/tmp/Aitmproxy-dev*.app`.
  Spike S5 confirms delivery in both states.)
- No app at `macos_app_path`: the reply is `cannot_prompt`. Frontends show the `package` label and the
  download link.
- No GUI session (SSH): `open` fails and the reply is `cannot_prompt`, "No desktop session to show the
  Aitmproxy app in; approve packet capture from the Mac's screen".

Frontend placement (**Architect's call**; exact spot is the builder's):

- TUI: one banner line in the L4 view when capture is `needs_approval`, a key (`A`) and a palette entry
  "Allow packet capture". Confirm, then send the request.
- Web: a banner at the top of the L4 page with an **Allow Packet Capture…** button, a confirm dialog, then
  the request. `package` renders as a link.
- CLI: `l4.privilege.request = at_start`, or the one-shot verbs.

### 4. Bundle layout and release pipeline (for the orchestrator before implementation)

#### 4.1 Paths inside `Aitmproxy.app` (release build only)

| Path | What | Signed |
|---|---|---|
| `Contents/MacOS/Aitmproxy` | app (unchanged) | last, with the app entitlements |
| `Contents/MacOS/aitm-l4-helper` | the helper (Rust, arm64, from the tarball) | yes, before the app |
| `Contents/Library/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist` | the daemon plist | sealed by the app signature |
| `Contents/Resources/core/{aitm,obscura,share/…}` | embedded core (unchanged) | unchanged |
| `Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension` | sysex (unchanged) | unchanged |

**(Architect's call:** `Contents/MacOS`, not `Contents/Library/Helpers` or `Resources`. It is where Apple
puts bundle executables. The helper is not the core's, so it does not go under `Resources/core`.)

#### 4.2 Plist keys (`apps/mac/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist`, copied verbatim)

| Key | Value | Why |
|---|---|---|
| `Label` | `com.mrbrutti.aitmproxy.l4-helper` | the launchd service name |
| `BundleProgram` | `Contents/MacOS/aitm-l4-helper` | SMAppService resolves it relative to the bundle |
| `ProgramArguments` | `["aitm-l4-helper", "bpf-permissions"]` | fixed argv; the only mode launchd runs |
| `AssociatedBundleIdentifiers` | `["com.mrbrutti.aitmproxy"]` | Login Items shows "Aitmproxy" with the app icon, not a bare binary |
| `RunAtLoad` | `true` | runs on approval and at every boot |
| `ProcessType` | `Background` | |
| `SpawnConstraint` | team `995PCLM9KH` + signing identifier `com.mrbrutti.aitmproxy.l4-helper` | a launch constraint (macOS 14+) so launchd refuses a substituted binary. Spike S3 confirms the key shape on macOS 27; dropped if launchd rejects it |

No `KeepAlive`, no `MachServices`, no `Sockets` in Phase 1 (no IPC). Phase 2 adds a `Sockets` or
`MachServices` entry.

#### 4.3 Signing: what SMAppService needs instead of SMJobBless keys

- No `SMPrivilegedExecutables` (app Info.plist) and no `SMAuthorizedClients` (helper Info.plist). Those
  are SMJobBless-era and must not be added.
- Helper: Developer ID Application, team `995PCLM9KH`, `--identifier com.mrbrutti.aitmproxy.l4-helper`,
  `--options runtime --timestamp`, **no entitlements and no provisioning profile** (research 13 §3.4,
  Disk Drill precedent).
- App: unchanged entitlements; the app needs no new entitlement for `SMAppService`.
- The bundle must be notarized (the SDK header: "Apps that contain LaunchDaemons must be notarized"),
  which `scripts/notarize-dmg.sh` already does for the DMG. Changing the helper or plist after signing
  breaks the app seal, so both are in place before the app is signed.

#### 4.4 `scripts/notarize-dmg.sh` sign order and checks

Inside-out, as today, with one step added: (a) code nested in the sysex, (b) the sysex, (c) `core/obscura`,
`core/aitm`, **(c2) `Contents/MacOS/aitm-l4-helper`** with the identifier above, (d) the app last. New
verify-or-fail checks before the DMG is built:

- the plist and the helper are both present or both absent (exit 1 otherwise);
- `plutil -extract BundleProgram` equals `Contents/MacOS/aitm-l4-helper` and that file is a signed Mach-O;
- `AssociatedBundleIdentifiers` contains `com.mrbrutti.aitmproxy`;
- helper `codesign -dv`: `Identifier=com.mrbrutti.aitmproxy.l4-helper`, `^TeamIdentifier=995PCLM9KH$`,
  `flags=.*runtime`, `Authority=Developer ID Application`;
- helper has no entitlements.

`scripts/tests/run-notarize-dmg-stubbed.sh` is extended to pin the order and the refusals. It is a
source tripwire, not evidence (AC section).

#### 4.5 `apps/mac/build.sh`, `scripts/package.sh`, release runbook

- `scripts/package.sh` builds `cargo build --release -p aitm-l4-helper` and puts `aitm-l4-helper` in the
  tarball beside `aitm` (macOS and Linux tarballs).
- `build.sh --ne` (the Developer ID, `/Applications`, release build) copies `aitm-l4-helper` from the
  same tarball or `AITM_CORE_DIR` into `Contents/MacOS/`, copies the plist into
  `Contents/Library/LaunchDaemons/`, and signs the helper after the core and before the app. A release
  build with no helper in its source fails (like the catalogue check).
- `build.sh` without `--ne` (ad hoc or Apple Development, `~/Applications`) **does not embed** the helper
  or plist and prints `no packet-capture helper embedded (release builds only: --ne)`. **(Architect's
  call:** an unnotarized `~/Applications` bundle cannot register a daemon, so embedding it would only
  produce an error path.) The app then reads "packet capture unavailable — needs the signed app".
- `docs/RELEASE.md` step 3 gains one line saying the helper ships inside the app. Step 6 gains
  `codesign -dv …/aitm-l4-helper` and `plutil -p` of the plist.

#### 4.6 `/Applications` and the dev bundle

- The helper only registers from `/Applications/Aitmproxy.app` (`PacketCaptureGate`). The DMG drag
  target and the Homebrew cask both install there. `~/Applications` is refused with "Move Aitmproxy to
  Applications". This matches the header's recommendation and the sysex's existing rule.
- `tools/snap-dev.sh` copies only `Contents/MacOS/<exe>`, `Info.plist`, icons and `Resources/core`. It
  must never copy `Contents/Library/LaunchDaemons` or `aitm-l4-helper` (a tripwire greps it). A /tmp dev
  bundle therefore has no plist, `canRegister` is false, and the card says unavailable.
- Developing the helper: unit tests of its pure logic (node list, mode decision, receipt encoding),
  `--dry-run` without root, and, for the real thing, Matt's Terminal recipe: `build.sh --ne
  --allow-unnotarized --replace`, `notarize-dmg.sh`, install the DMG, approve. There is no shortcut that
  registers an unnotarized daemon.

### 5. Linux (L-C)

#### 5.1 The helper (`aitm-l4-helper serve --connect <socket>`)

- Spawned by the core, either through `pkexec` (default) or directly when the helper binary has file
  caps (the headless fallback). It validates argv: exactly `serve --connect <path>`. The path must be a
  socket, not a symlink, inside a directory owned by the invoking user with mode 0700. The invoking user
  is `PKEXEC_UID`, or `getuid()` when run directly.
- Under pkexec it drops privilege before doing anything else: keep capabilities across the uid change,
  set gid, groups and uid to the invoking user, then reduce permitted and effective to `CAP_NET_RAW`
  only. Clear the bounding and ambient sets, set `no_new_privs`, and set `PR_SET_PDEATHSIG` so it dies
  with the core.
- Connects to the core's socket. The core checks `SO_PEERCRED`: uid equals the core's uid and pid equals
  the child it spawned. The helper checks that the socket's owner and the peer uid equal the invoking
  user. A failed check closes the connection and the helper exits.
- Exits on EOF, on any protocol error, or when the core dies. There is never an orphaned privileged
  process.

#### 5.2 Protocol (`crates/aitm-proto-l4/src/helper/`, shared by both ends)

Frames on a `SOCK_STREAM` Unix socket: u32 big-endian length (max 256 KiB), a 1-byte type, then the
payload. Control payloads are JSON; `Frame` and `Inject` carry a small binary header plus the raw bytes.

| Dir | Type | Content |
|---|---|---|
| core → helper | `Hello` | `proto: 1`, core version |
| helper → core | `HelloAck` | `proto`, helper version, effective caps |
| core → helper | `ScopeSet` | the guard's current scope entries and limits (`global_inject_pps`, `max_packet_bytes`, `max_packets_per_call`), resent on every scope change |
| core → helper | `CaptureOpen` / `CaptureClose` | id, interface, BPF filter, read timeout |
| helper → core | `Frame` / `CaptureClosed` | capture id, timestamp, bytes / reason |
| core → helper | `Inject` | request id, interface, frame bytes |
| helper → core | `InjectResult` | request id, ok or the guard or wire error text |

A proto mismatch, an unknown type, an oversized length or malformed JSON closes the session. The core
then reports `helper.status: "version_mismatch"` or `failed`. `HelperBackend` implements the existing
`CaptureInjectBackend` trait over this session, so the commands do not change.

#### 5.3 The helper enforces the guard itself

For every `Inject` the helper parses the frame itself (it never trusts a target the core claims), then
runs the same `L4Guard::check(L4Action::Inject, &target)` and `L4Permit::authorize_packet(len)` code as
the core, over the scope it holds from `ScopeSet`, with its own rate buckets. For `CaptureOpen` it
refuses an interface outside the capture scope and ANDs the scope-derived filter (`scope_filter`) onto
the requested one. Same crate, same functions, no re-implementation. **(Architect's call:** the helper
links `aitm-proto-l4` for the guard and protocol and links nothing else of the product: no Rhai, no MCP,
no HTTP.)

#### 5.4 Packaging (`scripts/nfpm.yaml`, `scripts/package-linux.sh`)

- `/usr/lib/aitmproxy/aitm-l4-helper`, mode 0755, `root:root`. No `/usr/bin` symlink: it is not a user
  command.
- `/usr/share/polkit-1/actions/com.mrbrutti.aitmproxy.l4-helper.policy`: action
  `com.mrbrutti.aitmproxy.l4-helper.run`, annotation `org.freedesktop.policykit.exec.path` =
  `/usr/lib/aitmproxy/aitm-l4-helper`, `allow_gui` true, defaults `allow_any`/`allow_inactive`
  `auth_admin`, `allow_active` `auth_admin_keep`. Message: "Allow aitmproxy to capture and send raw
  packets (only within the L4 scope you configured)".
- `recommends`: deb `pkexec`, rpm `polkit`. **No maintainer scripts, no setcap, no new group.**
- The tarball also carries `aitm-l4-helper`, but user-owned. The core never pkexecs it (§2.2), so it
  serves only the documented fallback.

#### 5.5 Who sees the prompt

The core decides "a prompt is possible" before spawning pkexec: `DISPLAY` or `WAYLAND_DISPLAY` is set
(a graphical agent is likely), or the core's stdin is a tty (pkexec's textual agent). Otherwise the
reply is `cannot_prompt` and pkexec is never run. **(Architect's call.)**

- Web UI on a desktop: the graphical polkit dialog names the helper path and the policy message.
- Web UI started from an SSH terminal: the textual prompt appears in that terminal. The web banner says
  "Enter an administrator password in the terminal running aitm".
- `aitm tui` (core and TUI on one tty): before sending the request the TUI leaves the alternate screen
  and raw mode and prints "Waiting for administrator approval…". It restores its screen when the request
  progress leaves `pending`. It does this every time, because a graphical dialog leaves the tty alone and
  suspending costs nothing.
- `aitm` (CLI) with `l4.privilege.request: at_start`: the textual or graphical prompt at start.

#### 5.6 Headless fallback, NixOS, Homebrew on Linux

- `docs/packet-capture.md` (new) documents, for admins of headless hosts only: copy the helper to a
  root-owned path, restrict it to a group (0750 `root:aitm-l4`), give it `cap_net_raw+ep`, and set
  `l4.privilege.helper_path`. Caps go on the helper, never on `aitm`. Upgrades replace the file and drop
  the caps, so the step is redone after each upgrade (stated in the doc).
- NixOS: the doc gives a `security.wrappers.aitm-l4-helper` entry (`source` = the package's helper,
  `capabilities = "cap_net_raw+ep"`, owner root, group `aitm-l4`, permissions group-execute only).
  Discovery already checks `/run/wrappers/bin`. The CVE-2026-25740 lesson is why the helper has no
  scripting or exec surface.
- Homebrew on Linux and tarball users: `needs_approval` `package`, "Install the aitm .deb or .rpm to get
  the packet-capture helper", with the download link. No root path exists for a formula.

### 6. Phase 2 and option A

- **Phase 2, candidate 1 on macOS:** `aitm-l4-helper serve`, launched by launchd through the same
  SMAppService plist (adds a `Sockets` or `MachServices` entry). The core connects to the helper. The
  helper checks the client's code signature (`macos_capture::peer_auth` precedent, `LOCAL_PEERTOKEN`) and
  enforces the guard as in §5.3. `bpf-permissions` mode is retired, and on its first boot the new helper
  returns `/dev/bpf*` to `root:wheel 0600`. Linux keeps the same protocol. In-path NFQUEUE through the
  helper (`CAP_NET_ADMIN`) lands here too. Frame streaming is the default. Fd passing only if spike S2
  works, and then in a leaf `unsafe` crate (libpcap cannot wrap a live fd, research 13 §3.6, so passing
  an fd also means a non-pcap backend).
- **Option A (frames in the sysex)** stays out unless spike S1 proves a network-entitled sysex opens
  `/dev/bpf*`. Any sysex change belongs to the NE session ("Ship macOS NE in DMG + app enable/disable
  toggle"), since a frames lane changes `listener.rs` and `FlowHandoff.swift` together.

### 7. Security

- **Unchanged:** deny-by-default L4 scope; scope is the authorization; `L4Guard` sits at the one lowest
  write in the core (`wire::send_on_wire`); the agent capability gates.
- **T1, group-wide `/dev/bpf*` (B2).** Any process running as a member of `access_bpf` can sniff every
  interface and write arbitrary frames with no aitmproxy guard. This is a machine-level permission, the
  one Wireshark asks for, and the card says so in plain words (line 4). Mitigations: only admin console
  users are added; removal is one button; Phase 2 replaces B2 with a guard-enforcing helper. Little
  Snitch's optional BPF gate may prompt on the first open; that is expected and is not suppressed.
- **T2, the macOS permission helper** takes no input. It verifies each node is a bpf character device
  before changing it, writes only under `/Library/Application Support/Aitmproxy/`, refuses symlinked or
  foreign-owned directories, and is constrained by `SpawnConstraint` and the bundle seal.
- **T3, the Linux helper.** pkexec does not validate arguments, so the helper does (§5.1). It drops to
  the invoking user with only `CAP_NET_RAW` before doing any I/O. Peer authentication runs both ways.
  It re-runs the guard on every frame it writes (§5.3) and dies with the core. A user-owned helper is
  never pkexec'd, because approving a user-writable file to run as root is a privilege escalation. Its
  limit: a compromised core can send a wider `ScopeSet`. The helper protects against everything that is
  not its parent core, and against core paths that skip `send_on_wire`. It is not a boundary against
  the core itself. The setcap fallback makes the helper an oracle for every user who can execute it,
  which is why the doc restricts it to a group.
- **T4, agent and remote triggers.** `l4.privilege.request` self-refuses non-operators and is not
  deferrable. Gated verbs never start a request when they fail. On macOS the URL path only brings the
  app forward; registration needs an in-app click, then the OS approval. On Linux the polkit dialog is
  the human gate. An agent with a shell could run `open` or `pkexec` itself; that is outside the
  product, and it still ends at the in-app click or the OS dialog.
- **T5, audit.** Every `l4.privilege.request` call lands in the audit ring with caller and outcome, as
  every verb does. State changes log one `info` line.

### 8. Ownership and coordination

| Change | Owner |
|---|---|
| `PrivilegeState`, `l4.privilege`, `l4.privilege.request`, live gating, probe strings, `l4.capture.status` un-gating | this spec |
| `aitm-l4-helper` (both modes), protocol, `HelperBackend`, Linux packaging, headless doc | this spec |
| Bundle layout, `build.sh`, `notarize-dmg.sh`, `package.sh`, RELEASE.md lines | this spec |
| Mac: `PacketCapture` Kit model, `PacketCaptureHelper`, URL handler, Packets card and lane, Settings ▸ Packets, the nudge line, `L4Availability` re-derivation | this spec |
| TUI and web: the banner, the Allow action, TUI suspend | this spec |
| Everything else in the L4 UIs (D1–D15), `l4.scope.add` confirm, setting `l4.enabled` in the embedded core's config | parity spec |
| Any sysex or NE change | NE session |
| `ConnectionSummary` shape | Status-page spec. This spec adds one lane kind and one step kind and changes nothing else |

The availability seam the parity spec consumes is the `l4.privilege` result (§2.2) and, on macOS, the
Kit `PacketCaptureAdvice`.

### 9. Spikes before Phase 1 (each an `experiment/<topic>` session)

| # | Question | Blocks |
|---|---|---|
| S3 | On macOS 27, what does `SMAppService.daemon.register()` show: a Login Items toggle only, or a toggle plus admin auth? Does re-register after an update re-prompt? Is a `~/Applications` bundle refused? Is `SpawnConstraint` accepted? | §3.2 words, §4.2, AC6, AC13 |
| S4 | After `dseditgroup` adds the console user to `access_bpf`, does an already-running process open a `0660 root:access_bpf` node without re-login? | fork (ii) default, AC7 |
| S5 | Does `open -a /Applications/Aitmproxy.app aitmproxy://packet-capture/allow` deliver the URL both when the app is running and when it is not? | §3.4, AC9 |
| S7 | Linux: does pkexec's textual agent work while the core's stdio is redirected? Does pkexec close fds above 2? Does the privilege drop keep `CAP_NET_RAW` usable by `pcap` for open and inject on `lo`? Is `CAP_NET_RAW` alone enough (research 08 Q8)? | §5.1, AC16, AC22 |
| S8 | macOS 27: does a BPF write of a DLT_NULL frame on `lo0` reach a UDP socket on 127.0.0.1:9053, and is it read back by a capture (08 Q7)? | AC8 steps W3–W4 on macOS |
| S6 (optional) | Can an unprivileged process read `launchctl print system/com.mrbrutti.aitmproxy.l4-helper` to enrich `helper.status`? | nothing; enrichment only |
| S1, S2 | Sysex `/dev/bpf*` open; `SCM_RIGHTS` of a bpf fd on macOS 27 | Phase 2 / option A only |

### 10. Phase 1 file map

New files:

- `crates/aitm-proto-l4/src/privilege/{mod,derive,macos,linux}.rs`
- `crates/aitm-proto-l4/src/commands/privilege.rs`
- `crates/aitm-proto-l4/src/helper/{mod,proto,client}.rs`
- `crates/aitm-proto-l4/src/backend/helper.rs`
- `crates/aitm-l4-helper/` (binary: `bpf-permissions` on macOS, `serve` on Linux, `--probe`,
  `--version`, `--dry-run`)
- `apps/mac/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist`
- `apps/mac/Sources/AitmproxyKit/PacketCapture.swift` and tests
- `apps/mac/Sources/Aitmproxy/Privilege/PacketCaptureHelper.swift`
- `apps/mac/Sources/Aitmproxy/Panels/PacketCaptureCard.swift`
- `apps/mac/tools/check-packet-helper.sh` (tripwires)
- `packaging/linux/com.mrbrutti.aitmproxy.l4-helper.policy`
- `docs/packet-capture.md`
- `tests/e2e/l4/test_privilege_*.py` (on the canonical `tests/e2e/aitm_e2e` harness)

Changed files:

- `crates/aitm-proto-l4/src/{module,capture,sendrecv,language,config}.rs`, `commands/capture.rs`
- `crates/aitm/src/{wire,main}.rs`
- `apps/mac/Info.plist.in` (URL type), `ConnectionSummary.swift`, `L4.swift`, `StatusPanel.swift`,
  `SettingsView.swift`, `App.swift` (URL handler)
- `apps/mac/build.sh`, `scripts/notarize-dmg.sh` and its stub test, `scripts/package.sh`,
  `scripts/nfpm.yaml`, `scripts/package-linux.sh`, `docs/RELEASE.md`
- `crates/aitm-tui/src/{app,l4,keys}.rs`, `ui/l4.rs`
- `apps/web/src/panels/l4/L4PrivilegeBanner.tsx` (new) and the L4 store
- the three tool contracts (`EXPECTED_TOOLS`, `CORE_TOOLS`, `bus-fixture.json`)

## Acceptance criteria

**Evidence rule (Matt's).** Only these count as evidence or as a regression gate: a real frontend
driving a real core with real traffic; Rust or Kit unit tests of pure logic; source tripwires. No
fixture, snapshot, self-test or seeded-store run counts. The contract pins and the stubbed
`notarize-dmg.sh` test are tripwires, never proof that a feature works.

**Rig R.** `aitm web` with `l4.enabled: true` and config scope `lo0` (macOS) or `lo` (Linux),
`127.0.0.1/32`, ports `9000-9999`, one entry each for capture, inject and intercept. Targets:
`python3 -m http.server 9099` and a UDP echo on 9053. Driven by the real web UI in a browser, the real
TUI in a pty, the mac app connected to R as its external core, and the python `aitm_e2e.bus` client as
operator and as agent.

**Walk W** (operator, after approval):

- W1. `l4.capture.start {interface, direction: "inbound"}` returns an id.
- W2. Fetch `http://127.0.0.1:9099/`: `l4.flow.get` shows at least one packet whose `layers` contain
  `"TCP"`. Then send `ping` to UDP 9053: at least one packet with `"UDP"`.
- W3. `l4.inject` of a crafted UDP datagram to 127.0.0.1:9053, payload `aitm-inject`: returns ok, and the
  capture shows a new packet with `injected: true`.
- W4. `l4.send_recv` to 127.0.0.1:9053 with payload `aitm-sr` returns reply bytes equal to `aitm-sr`.
- W5. `l4.inject` to 127.0.0.1 port 8999 is refused with a guard error containing `scope`, and the capture
  gains no packet.

Tags: **[unit]** Rust or Kit unit test. **[trip]** source tripwire. **[linux-ci]** real core on a Linux
CI runner or systemd container. **[mac-any]** any Mac and any build, against rig R. **[mac-signed]** a
real Mac with the Developer-ID-signed, notarized bundle installed in `/Applications`; the dev bundle
cannot register a daemon, so these run on Matt's Mac via the Terminal and CUA recipe. **[linux-desk]** a
Linux desktop VM, by hand.

1. **L4PRIV-AC1 [linux-ci, mac-any]** On an unprivileged R, operator and agent `l4.privilege` both answer
   within 500 ms with `capabilities.capture.state == "needs_approval"`. On macOS,
   `capabilities.intercept.state == "unsupported"`. `how.kind` is `"pkexec"` on Linux with the deb
   installed, `"app_action"` on a Mac with the signed app in `/Applications`, and `"package"` with
   `l4.privilege.macos_app_path` set to a missing path.
2. **L4PRIV-AC2 [linux-ci, mac-any]** With `l4.enabled: false`, `l4.privilege` answers `"enabled": false`
   with all three capabilities `unsupported`.
3. **L4PRIV-AC3 [unit, trip]** `derive` yields the §2.2 tables row for row. No `reason` or `label` in any
   variant, and no string in `module.rs` `probe()`, matches
   `\b(sudo|setcap|chmod|chgrp|chown|dseditgroup|launchctl|pkexec)\b`.
4. **L4PRIV-AC4 [linux-ci, mac-any]** On an unprivileged R, `l4.capture.status` returns
   `{"captures": [], "privilege": {...}}` and no error.
5. **L4PRIV-AC5 [linux-ci, mac-any, trip]** Agent `l4.privilege.request` under policies `auto` and `all`
   returns an error starting `l4.privilege.request refused: only an operator`. No `pkexec` process
   appears within 2 s (Linux) and Aitmproxy is not launched (macOS). Tripwires: the verb is absent from
   `defers_to_command_gate`, `sensitivity() == Sensitive`, and `confirm_prompt` is `Some`. Its audit-ring
   entry records the agent caller.
6. **L4PRIV-AC6 [mac-signed]** On a Mac where `stat -f '%Sp %Su %Sg' /dev/bpf0` prints
   `crw------- root wheel`: first launch shows the Packets card with its five lines and the Getting
   started row ○. Click **Allow Packet Capture…**, System Settings opens on Login Items & Extensions with
   Aitmproxy under Allow in the Background, and turn it on. Within 10 s: `/dev/bpf0` prints
   `crw-rw---- root access_bpf`; `/dev/bpf255` exists; the receipt has `"group": "access_bpf"` and
   `helper_version` equal to the app's `CFBundleShortVersionString`; `dscl . -read /Groups/access_bpf
   GroupMembership` lists the console user; the card reads "packet capture allowed" and the row is ✓.
   The operator typed nothing. The observer may read state in Terminal.
7. **L4PRIV-AC7 [mac-signed]** An R core started before AC6's approval reports capture `available`
   within 5 s of it, without a restart. A Homebrew or tarball `aitm l4.privilege` one-shot (not the
   bundle's binary) reports `available`.
8. **L4PRIV-AC8 [mac-signed, linux-ci]** Walk W passes on R: macOS on `lo0` in process after AC6, Linux on
   `lo` through the helper in both AC16 mode and AC17 mode. On macOS, W3–W4 depend on spike S8.
9. **L4PRIV-AC9 [mac-signed]** From the TUI (pty) and from the web UI (browser) against R on the Mac,
   with the app running and with it quit: the Allow action plus confirm brings Aitmproxy forward on
   Status with the Packets card highlighted. Its SMAppService status stays `notRegistered` until the
   click in the app, and after the click the AC6 flow completes. Opening
   `aitmproxy://packet-capture/allow` from a browser page brings the app forward and registers nothing.
10. **L4PRIV-AC10 [mac-any]** With `macos_app_path` missing, the TUI and web UI show the `package` label
    and a link to `https://mrbrutti.github.io/aitmproxy/download.html`, and no shell command. The request
    returns `"outcome": "cannot_prompt"`.
11. **L4PRIV-AC11 [mac-any, unit, trip]** A `snap-dev.sh` bundle and a plain `build.sh` bundle show
    "packet capture unavailable" with no Allow button. `PacketCaptureGate.canRegister` is true only for
    `/Applications/Aitmproxy.app` with the helper present (Kit truth table). Tripwires: `SMAppService` is
    referenced only in `PacketCaptureHelper.swift`, every call sits behind `canRegister`, and
    `snap-dev.sh` contains neither `LaunchDaemons` nor `aitm-l4-helper`.
12. **L4PRIV-AC12 [mac-signed, trip]** On the notarized bundle: `BundleProgram` equals
    `Contents/MacOS/aitm-l4-helper`; `AssociatedBundleIdentifiers` equals `["com.mrbrutti.aitmproxy"]`;
    helper `codesign -dv` shows `Identifier=com.mrbrutti.aitmproxy.l4-helper`,
    `TeamIdentifier=995PCLM9KH`, `runtime`, Developer ID; `codesign --verify --deep --strict` passes on the
    app; `stapler validate` passes on the DMG. The stub test proves the script exits 1 for a plist without
    a helper, for a helper without a plist, and for a helper signed after the app.
13. **L4PRIV-AC13 [mac-signed]** Installing a newer notarized build over an approved one: the receipt's
    `helper_version` changes to the new version within 10 s of first launch, and capture stays or
    becomes `available`. If S3 says re-register re-prompts, the card shows "waiting for approval" and the
    AC6 flow repeats.
14. **L4PRIV-AC14 [mac-signed]** **Remove Packet Capture…**, then reboot: `/dev/bpf0` prints
    `crw------- root wheel`, and `l4.privilege` shows capture `needs_approval`.
15. **L4PRIV-AC15 [linux-ci]** The deb and the rpm, installed in clean containers, carry the helper
    (0755 root:root) and the policy (action id and `exec.path` as §5.4). `getcap` is empty for both `aitm`
    and the helper. Tripwire: `nfpm.yaml` has no scripts and no `setcap`.
16. **L4PRIV-AC16 [linux-ci]** With a test-only polkit rule granting the CI user
    `com.mrbrutti.aitmproxy.l4-helper.run`: operator `l4.privilege.request` returns `"pending"`, then
    `l4.privilege` shows capture `available` via `helper` within 10 s. `/proc/<helper pid>/status` shows
    all four `Uid:` fields equal to the CI uid and `CapEff:` equal to `0000000000002000`.
17. **L4PRIV-AC17 [linux-ci]** A helper copy with `cap_net_raw+ep` in a root-owned 0750 path, named by
    `l4.privilege.helper_path`, starts without pkexec. `helper.kind` is `"linux_cap_helper"` and capture
    is `available`.
18. **L4PRIV-AC18 [linux-ci]** The real helper connected to a test socket owner (not the core) that sends
    `ScopeSet` (9000-9999) and then an `Inject` to port 8999 returns an `InjectResult` error containing
    `scope`, and an independent capture sees no packet to 8999. An oversized length makes the helper
    exit. A socket in a directory not owned by the invoking user is refused at start.
19. **L4PRIV-AC19 [linux-ci]** After `kill -9` of the core, no `aitm-l4-helper` process exists within 2 s.
20. **L4PRIV-AC20 [linux-ci]** A helper under `$HOME` (the tarball layout) gives `how.kind == "package"`.
    The request returns `cannot_prompt` and no pkexec runs.
21. **L4PRIV-AC21 [linux-desk]** On a GNOME VM, the web UI's Allow shows the graphical polkit dialog with
    the helper path and the policy message. Approve, and walk W passes. Cancel instead, and
    `request.state == "dismissed"` while the banner says "Approval was cancelled".
22. **L4PRIV-AC22 [linux-ci]** In a systemd container (polkitd running, user `tester` with a password and
    in the admin group, no graphical agent), with `aitm tui` in a pty: Allow plus confirm restores the
    normal screen, and a prompt containing `com.mrbrutti.aitmproxy.l4-helper.run` appears. The harness
    types the password, the TUI redraws, and the banner is gone with capture `available`.
23. **L4PRIV-AC23 [linux-ci]** With `DISPLAY` and `WAYLAND_DISPLAY` unset and stdin not a tty, the request
    returns `cannot_prompt` with a message naming `docs/packet-capture.md`, and no pkexec runs.
24. **L4PRIV-AC24 [linux-ci, mac-any, trip]** With L4 enabled and capture not available, the start-up log
    has exactly one line `L4 enabled; packet capture needs approval: …`, matching neither the AC3 regex
    nor the operator token. The three tool contracts list `l4.privilege` and `l4.privilege.request`.
25. **L4PRIV-AC25 [mac-any, linux-ci]** With capture `needs_approval`, the L4 empty state in the mac app,
    the TUI and the web UI shows the "No packets?" nudge with its Allow action, and a failed
    `l4.capture.start` shows the same nudge.

## Left to the builder

- The JSON field order, exact Rust type names under `privilege/` and `helper/`, and how `ProbeInputs`
  is gathered, provided `derive` stays pure.
- The privilege-drop crate (`caps`, `nix`, or both), the UDS directory layout under `XDG_RUNTIME_DIR`
  (fallback `/tmp/aitm-<uid>/`, verified 0700), and the frame-header byte layout within §5.2's limits.
- Card layout, icon, and the exact spot of the TUI and web banners within the L4 view or page.
- How the bundle's helper version reaches the app (a generated constant or a `--version` call).
- Test file names inside the named directories.

## Open questions

Only Matt can answer these. Most important first; each has a recommended default.

1. **(i) B2 now, or straight to the candidate-1 helper on macOS?** *Default: B2 now (Phase 1), candidate 1
   in Phase 2.* B2 is a plist, one small mode of the helper, and a register call. Capture works for
   every frontend within one release. Candidate 1 on macOS needs a launchd socket protocol, code-signature
   peer auth and the helper backend on macOS: weeks, not days. The cost of B2 is T1 (group-wide device
   access, the Wireshark trade-off) until Phase 2.
2. **(ii) Group `access_bpf` or `admin`?** *Default: `access_bpf`.* It is Wireshark's group, so the two
   ChmodBPF daemons agree at boot instead of overwriting each other, and it can exclude other admin
   accounts. `admin` needs no group work and no re-login, because you are already in it. If spike S4 shows
   `access_bpf` membership needs a re-login, I would switch the default to `admin`.
3. **(iii) Linux helper in deb/rpm only, or also a Homebrew cask `pkg` for macOS CLI-only users?**
   *Default: deb/rpm only.* On macOS the app is the privilege path, and the cask that installs it already
   exists. A second `pkg` installer would be a second privileged install path, and `brew` would prompt
   for sudo in the terminal anyway.
4. **(iv) One "Allow packet capture" that also turns on All Apps (the extension), or separate
   switches?** *Default: separate.* They are different OS approvals (Login Items vs extension plus proxy
   configuration) with different risks. They give different things (raw frames vs other apps' flows),
   neither needs the other, and the Status page already names them differently.
5. Is the plain checklist wording in §3.2 (especially line 4's "Any app you run can then capture and
   send raw packets") the honesty level you want on the card? *Default: yes, as written.*

## Summary

Phase 1 gives the core an always-answering `l4.privilege` verb and an operator-only, confirmed, non-blocking
`l4.privilege.request`, and makes the privilege gate live so approval needs no restart. On macOS the app
registers the bundled Rust `aitm-l4-helper` in `bpf-permissions` mode with `SMAppService.daemon`. After
one Login Items approval it makes `/dev/bpf*` `root:access_bpf 0660` at every boot, and every `aitm` on the
Mac captures in process. TUI, web and CLI ask the app through a URL that only brings it forward. On
Linux the deb/rpm ships the same helper and a polkit policy. One pkexec prompt starts it for the core's
lifetime; it drops to the operator with only `CAP_NET_RAW` and enforces the same `L4Guard` on every frame
it writes. Phase 2 moves macOS to that helper and retires the group-wide permission. No `aitm-core` edits,
no sysex change, no shell command in any product string.

**Architect's calls (approve or correct):**

1. One Rust `aitm-l4-helper` binary for both OSes (`bpf-permissions` on macOS, `serve` on Linux), not a Swift tool or zsh script.
2. Helper at `Contents/MacOS/aitm-l4-helper`; plist `com.mrbrutti.aitmproxy.l4-helper.plist`; label and signing identifier `com.mrbrutti.aitmproxy.l4-helper`; `SpawnConstraint` on team and identifier.
3. The helper is embedded only in `build.sh --ne` (release) builds; plain and dev bundles never carry it; registration only from `/Applications`.
4. TUI, web and CLI reach the app with `open -a <path> aitmproxy://packet-capture/allow` (a URL, not `--args`; a path, not `-b`), and the app registers only on an in-app click.
5. The core does not read SMAppService status; it reads a root-written receipt plus the bundle, and the app shows the finer states.
6. `l4.privilege` is registered even when `l4.enabled` is false.
7. `l4.privilege.request` returns at once; progress is read from `l4.privilege`; 300 s timeout on Linux.
8. This spec owns un-gating `l4.capture.status` (the D11 half); the parity spec owns the rest of D11 and setting `l4.enabled` in the embedded core.
9. Linux helper lifetime is one core run (one prompt per run), not a standing service.
10. The core never pkexecs a helper whose path is user-owned or writable; it never pkexecs when no prompt is possible.
11. Linux intercept through the helper is deferred to Phase 2.
12. No osascript installer, legacy daemon, pkg or SMJobBless path.
13. A fourth Status card plus a Getting started row, not a modal; "Packet capture" is the UI word.
14. Config keys `l4.privilege.{helper_path, macos_app_path, request}`, with `request: at_start` as the CLI path.
15. Re-probe TTL of 1 s while unavailable.

## Orchestrator conditions on the bundle layout (2026-10-31, approved in principle)

Recorded verbatim in intent from the orchestrator session ("aitmproxy: Rust MITM platform
design"); the release-pipeline files stay claimed through it and it reviews those diffs.

1. `aitm-l4-helper` is a workspace crate with `version.workspace = true` so app, core, sysex
   and helper carry one version; `scripts/package.sh` ships it in the tarball and
   `apps/mac/build.sh` copies it from the tarball only under `--ne` (never from
   `AITM_CORE_DIR` or a dev build; `tools/snap-dev.sh` tripwire).
2. `scripts/notarize-dmg.sh`: sign order sysex-nested → sysex → core → helper → app; the helper
   signed with hardened runtime + timestamp and no entitlements; the post-sign assertions
   (team 995PCLM9KH, Developer ID authority, runtime) extend to the helper; refuse a bundle with
   only one of plist/helper; assert the plist's `BundleProgram` points at an existing Mach-O;
   `scripts/tests/run-notarize-dmg-stubbed.sh` gains the helper cases (present / absent /
   plist-only).
3. Homebrew cask: `uninstall launchctl: "com.mrbrutti.aitmproxy.l4-helper"`; the app
   unregisters the daemon on Settings ▸ Uninstall; documented in `docs/RELEASE.md`.
4. Linux deb/rpm: helper 0755 root + polkit policy via nfpm `contents`, no maintainer scripts.
5. The core's `open -a <path> aitmproxy://packet-capture/allow` handoff resolves the INSTALLED
   app path from the running core's own bundle, never a `/tmp` dev bundle.
6. **Spike rule.** Any spike that changes system state on Matt's Mac (chmod `/dev/bpf*`, group
   creation or membership, installing a LaunchDaemon, Login Items prompts) is announced to the
   orchestrator BEFORE it runs with its exact revert steps, runs only on its go after Matt has
   been told, and is reverted in the same session. Spikes that can run in a VM run there.
