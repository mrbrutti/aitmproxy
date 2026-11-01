# L4 capture privilege, obtained by the product design

**Status:** Approved (Matt, 2026-11-01: the recommended defaults for forks i–v). Decided: (i) macOS phase 1 ships B2, the SMAppService-registered permission daemon, with the single privileged helper (candidate 1) as phase 2; (ii) device group `access_bpf` (switch to `admin` only if spike S4 shows a re-login is needed); (iii) the Linux helper + polkit policy ship in deb/rpm only, no Homebrew cask pkg; (iv) "Allow packet capture" stays a separate switch from All Apps; (v) the first-run card keeps line 4 ("Any app you run can then capture and send raw packets"). Open: Matt's written acceptance of the headless `setcap` doc pointer. The orchestrator's bundle-layout conditions are folded into the body; the spikes run under the spike rule before phase 1 code. **Matt, 2026-11-01 (relayed by the orchestrator, recorded by the p2 session):** no third-party privilege daemon is ever used (ChmodBPF is dead, including as a fallback or a doc pointer); phase 2, our own component performing capture and injection for the core (the `serve` mode; the architect may revisit frames-in-the-sysex as its carrier), is the REQUIRED end state; phase 1 (bpf permissions via SMAppService and this helper) stays the stepping stone that the scanner-v2 L4 packet lane (track T5 of `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`) uses for its macOS live cells.
**Research inputs:** `docs/research/13-l4-capture-privilege-without-cli.md` (primary), `12-l4-parity-audit.md` (D0,
D11a, the rig), `08-l4-packet-rust.md` (privilege model, candidate F), `10-macos-network-extension.md` and
`experiments/2026-10-29-macos-ne-spike.md` (the sysex), `docs/RELEASE.md`, `scripts/notarize-dmg.sh`,
`apps/mac/build.sh`, `apps/mac/tools/snap-dev.sh`.
**Related specs:** `2026-10-31-l4-parity-fixes-design.md` (sibling, UI defects D1–D15; owns the status shape and the
`AvailabilitySource` this spec extends, §2.4), `2026-10-31-capture-status-verb-design.md` (unrelated: NE flows vs raw
frames), `2026-10-31-macos-status-page-and-first-run-design.md` (`ConnectionSummary`, Getting started),
`2026-10-30-macos-ne-ship-and-toggle-design.md` (the NE session; owns every sysex change).

## Intent

Raw L4 capture and injection are unreachable in every shipped build: the core probes `/dev/bpf*` or `CAP_NET_RAW` once
at start and tells the operator to "install ChmodBPF or run with privilege" or to type `setcap` (D0). Matt: "I should
not have to do anything in the command line; if I need to use something as root you should trigger the right
permission." The bar is Proxyman: a first-launch card that says what the privileged helper does, one standard OS
approval, and a later "this will fix it" nudge where the missing privilege shows up. This design makes the product
obtain the privilege itself, with at most one standard OS prompt, on macOS and Linux, and makes every frontend (macOS
app, TUI, web UI, CLI) able to show the state honestly and offer the one action that fixes it.

## Goals

- G1. Every core answers `l4.privilege` with the real per-capability state and, when something is missing, the one
  action that gets it. No reply ever tells the operator to type a command.
- G2. macOS: one click in the app plus one System Settings approval makes `/dev/bpf*` usable by the operator's
  account, persistently across reboots, for every `aitm` on the Mac (app-embedded, Homebrew, tarball). An
  already-running core notices without a restart.
- G3. Linux: one polkit dialog (graphical, or textual on the tty) starts a small privileged helper that does capture
  and injection for the core, which itself stays unprivileged.
- G4. TUI, web UI and CLI trigger the same action through the core (`l4.privilege.request`); on a Mac they hand off to
  the installed app; with no way to prompt they say so plainly.
- G5. The agent can never trigger a privilege request by any path.
- G6. After approval, the audit walk (capture lo/lo0, real TCP and UDP, inject with `injected: true`, `send_recv`
  echo, out-of-scope refusal) passes live on a real core.

## Non-goals

- No change to the Network Extension or sysex (option A, frames-in-the-sysex, is out; §6).
- No L4 UI parity work: live L4 rows in the mac app, intercept controls, L4 scope add, polling churn, `l4.flow.get`
  bytes. Those are the sibling parity spec's (D1–D15), except the seams named in §8.
- No in-path interception through the helper (Linux NFQUEUE stays "core holds `CAP_NET_ADMIN` itself").
- No macOS `pkg`, no `osascript ... with administrator privileges` installer, no SMJobBless, no legacy
  `/Library/LaunchDaemons` plist. **(Architect's call:** one privileged install path per OS.)
- No Windows. No setcap on `aitm`, ever; no setuid binaries.
- No new authorization model: scope stays the authorization; this design only obtains OS privilege.

## Anti-goals

- A reply, toast, label, log line or doc string in the product that tells the operator to run `sudo`, `setcap`,
  `chmod`, `chgrp`, `dseditgroup`, `launchctl` or `pkexec` as the way forward. (Whether the docs may describe the
  headless Linux fallback is the open item (headless `setcap` doc); the product never points at it as the default.)
- A privilege request that fires without a human operator's act: from an agent, from a gated verb that failed, from a
  URL a web page opened, or from a background poll.
- A privileged component that checks less than today's `L4Guard` where it writes.
- A dev bundle (`/tmp/Aitmproxy-dev*.app`) or `~/Applications` build registering a root daemon.
- "Allow Packet Capture" that succeeds in the OS but leaves the running core still saying unavailable.
- A fourth connection vocabulary in the mac app that does not come from `ConnectionSummary`.
- Fixture, snapshot, self-test or seeded-store runs offered as proof that any of this works.

## Constraints

- **Zero `aitm-core` edits.** Everything lives in `aitm-proto-l4`, a new `aitm-l4-helper` crate, the `aitm` binary's
  wiring, the frontends and packaging. The agent refusal uses the existing `CommandHost::caller_is_trusted_control()`.
- **One explicit `aitm-mcp` exception.** `l4.privilege.request` is added to `is_operator_only` in
  `crates/aitm-mcp/src/server.rs`, so an agent call is refused by the policy gate under every policy and is never
  parked under `Ask`. It stays out of `defers_to_command_gate`. No other `aitm-mcp` change.
- Workspace `unsafe_code = "forbid"` stays. The Linux helper uses safe APIs (`nix`, `caps` or equivalent). Phase 1
  passes no fds. Any later `unsafe` goes in a leaf crate in the `aitm-peer-token` style with a `// SAFETY:` comment
  and Security-reviewer sign-off.
- The `L4 unavailable: ` error prefix stays (frontends match on it today).
- macOS: `SMAppService.daemon` needs macOS 13+; the app's floor is 26.0. A daemon-bearing app must be
  Developer-ID-signed, hardened-runtime, notarized, and live in `/Applications`.
- macOS: a working launch constraint on the helper is a **hard requirement** (§4.2), proven by spike S3's substitution
  test. Without it, Phase 1 macOS does not ship.
- Linux: polkit (`pkexec`) available on Debian/Ubuntu (`pkexec` package) and Fedora/RHEL (`polkit`); headless hosts
  may have no agent.
- Quiet logs: one `warn` line at start when L4 is enabled and not available, one `info` line per state change. Never
  log the operator token or a frame's payload.
- New bus verbs update the three contracts: `EXPECTED_TOOLS`, `CORE_TOOLS`, `bus-fixture.json`.
- macOS UI words follow the Status-page spec: "All Apps" is the extension. This feature is **Packet capture** in UI
  text; never "BPF", "L4 capture" or "daemon".
- **Spike rule.** Any spike that changes system state on Matt's Mac (chmod `/dev/bpf*`, group creation or membership,
  installing a LaunchDaemon, Login Items prompts) is announced to the orchestrator before it runs, with its exact
  revert steps; it runs only on the orchestrator's go after Matt has been told, and is reverted in the same session.
  Spikes that can run in a VM run there.

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

One binary, `aitm-l4-helper` (Rust), has the macOS permission-fix modes in Phase 1 and the Linux serve mode in Phase
1; Phase 2 brings serve mode to macOS (candidate 1) and retires the permission fix. **(Architect's call:** Rust, not a
Swift tool or a zsh script: one artifact on both OSes, built by `scripts/package.sh` like `aitm`, and the path to
candidate 1 is the same binary.) Subcommands: `bpf-permissions`, `bpf-revert` (macOS), `serve` (Linux), `probe`,
`version`; `--dry-run` applies to the macOS modes.

### 2. Core

#### 2.1 `PrivilegeState` (new, `crates/aitm-proto-l4/src/privilege/`)

One shared `Arc<PrivilegeState>` replaces the cached `L4Privilege` as the source of truth. It is read by the
`l4.privilege` verb, by `L4Gated` on every invocation, by the status verbs through the parity spec's
`AvailabilitySource` (§2.4), and by a routing backend.

- `PrivilegeState::new(cfg: &PrivilegeConfig) -> Self` (callers wrap it in `Arc`)
- `PrivilegeState::report(&self) -> PrivilegeReport` (re-probes when the cached result is unavailable and older than 1
  s; **Architect's call** for the TTL)
- `PrivilegeState::request(&self) -> RequestOutcome` (non-blocking; starts the platform action)
- `PrivilegeState::backend(&self) -> Arc<dyn CaptureInjectBackend>` (in-process `PcapBackend` when the process itself
  is privileged; `HelperBackend` when a Linux helper session is up)
- `fn derive(inputs: &ProbeInputs) -> PrivilegeReport` in `privilege/derive.rs`: pure, no I/O, the whole decision
  table below. Platform files gather `ProbeInputs`: `privilege/macos.rs`, `privilege/linux.rs`.

`L4Privilege` and `probe()` stay as the low-level probe (`ProbeInputs` uses them); their reason strings lose the
hand-typed commands. `L4Gated` holds the `Arc<PrivilegeState>` instead of a fixed reason string, so a core started
before approval serves capture after it. Every production caller of `PcapBackend::new()` takes `state.backend()`
instead: `crates/aitm-proto-l4/src/commands/mod.rs:414` (`wire_commands`), `src/language.rs:192` (the Rhai `l4.*`
namespace), and `crates/aitm/src/main.rs:216` (the scripting engine's `L4Language`). Line numbers are at b109ca80 and
drift. Test callers keep building their own.

#### 2.2 `l4.privilege` (Read, always answers)

Registered by the `aitm` binary whether or not `l4.enabled`, so a frontend can say "L4 is off in this core's config".
**(Architect's call.)** Agents may call it. Result:

| Field | Type | Meaning |
|---|---|---|
| `enabled` | bool | `l4.enabled` in this core's config |
| `platform` | `"macos"` \| `"linux"` \| `"other"` | |
| `capabilities.capture`, `.inject`, `.intercept` | `Capability` | see below |
| `helper` | `Helper` | the privileged component as this core sees it |
| `request` | `RequestProgress` \| null | the last `l4.privilege.request` on this core |
| `checked_at` | integer, epoch ms | when the probe last ran |

`Capability` is one of:

- `{"state": "available", "via": "process" | "helper"}`
- `{"state": "needs_approval", "reason": str, "how": {"kind": "app_action" | "os_dialog" | "package" | "pkexec",
  "label": str, "action": Action}}`
- `{"state": "unsupported", "reason": str}`

`Action` is `{"type": "bus_verb", "verb": "l4.privilege.request"}` or `{"type": "open_url", "url":
"https://mrbrutti.github.io/aitmproxy/download.html"}`. Never a shell command. `kind` tells a frontend what will
happen: `app_action` (the Aitmproxy app does it), `os_dialog` (this core already handed the request to the app; macOS
is waiting for the operator's approval), `package` (install something first), `pkexec` (a polkit password prompt).

`Helper` is `{"kind": "macos_bpf_permissions" | "linux_pkexec_helper" | "linux_cap_helper" | "none", "status":
"not_installed" | "installed" | "applied" | "running" | "version_mismatch" | "unknown", "version": str | null,
"detail": str | null}`.

`RequestProgress` is `{"state": "pending" | "handed_to_app" | "approved" | "dismissed" | "failed", "at": integer epoch
ms, "message": str}`.

**macOS decision table** (`derive`), first match wins:

| Inputs | capture/inject | helper.status |
|---|---|---|
| `l4.enabled` false | `unsupported`, "L4 is off in this core's config (l4.enabled)" | as found |
| a `/dev/bpf*` opens read+write | `available`, via `process` | `applied` if the receipt exists, else `unknown` (someone else fixed it, e.g. Wireshark) |
| receipt exists, open fails | `needs_approval` `app_action`, reason from the receipt's `errors`, else "Packet capture is set up but this account cannot use it yet; open the Aitmproxy app to finish" (the app knows whether re-login or re-approval is needed) | `applied` |
| no receipt, this core's `request.state` is `handed_to_app` | `needs_approval` `os_dialog`, label "Approve Aitmproxy in System Settings ▸ General ▸ Login Items & Extensions" | `installed` |
| the handoff app (§2.3) embeds the helper plist, no receipt | `needs_approval` `app_action`, label "Allow packet capture in the Aitmproxy app" | `installed` |
| otherwise | `needs_approval` `package`, label "Install the Aitmproxy app (DMG or Homebrew cask); it asks macOS for packet-capture permission", `open_url` | `not_installed` |

`intercept` on macOS is always `unsupported`, "in-path interception is Linux only". The receipt is
`/Library/Application Support/Aitmproxy/l4-helper.json` (§3.1). The core cannot read `SMAppService` status (it belongs
to the app bundle); **(Architect's call:** nobody relays it. The core reads the receipt and the bundle; the app, which
can read `SMAppService.status`, shows the finer states itself.)

**Linux decision table**, first match wins:

| Inputs | capture/inject | helper |
|---|---|---|
| `l4.enabled` false | `unsupported`, as macOS | as found |
| process `CapEff` has `CAP_NET_RAW` | `available`, via `process` | `none` |
| a helper session is connected | `available`, via `helper` | `running` |
| helper found and `aitm-l4-helper probe` reports `CAP_NET_RAW` effective (file caps) | `available`, via `helper` (session starts lazily on first use, no prompt) | `linux_cap_helper`, `installed` |
| helper at the policy's exec path (§5.4), root-owned path, policy file present, `pkexec` present, a prompt is possible (§5.5) | `needs_approval` `pkexec`, label "Allow packet capture (asks for an administrator password)" | `linux_pkexec_helper`, `installed` |
| helper at the policy's exec path, but no prompt is possible | `needs_approval` `package`, "No password prompt can be shown here (no desktop session or terminal)" | `installed` |
| helper found but its path or a parent is not root-owned, or is group/world-writable | `needs_approval` `package`, "Install the aitm .deb or .rpm to get the packet-capture helper" | `not_installed`, detail names the path |
| otherwise | `needs_approval` `package`, same label, `open_url` | `not_installed` |

`intercept` on Linux: `available` when the process holds `CAP_NET_ADMIN` (today's path), else `unsupported`, "in-path
interception needs the core itself to hold CAP_NET_ADMIN; the packet-capture helper does not provide it yet". No `how`
is offered because no Phase 1 helper provides it; `l4.intercept.status` still reports `code: needs_privilege` for it
(§2.4).

Helper discovery order: `l4.privilege.helper_path` from config, then `<exe dir>/aitm-l4-helper`,
`/usr/lib/aitmproxy/aitm-l4-helper`, `/run/wrappers/bin/aitm-l4-helper`. Discovery finds a helper to probe; only the
policy's exec path is ever run through `pkexec` (§5.1).

#### 2.3 `l4.privilege.request` (Sensitive, operator-only, confirm)

- Refused for agents twice over: `aitm-mcp` lists it in `is_operator_only` (Constraints), so the policy gate refuses
  it under every policy and never parks it; and its `invoke` self-gates first line: if
  `!host.caller_is_trusted_control()`, refuse with `l4.privilege.request refused: only an operator can ask for
  packet-capture permission; an agent never can.` Not in `defers_to_command_gate`.
- `sensitivity()` is `Sensitive`; `confirm_prompt` is always `Some`: macOS "Ask the Aitmproxy app to set up packet
  capture? macOS will ask an administrator to approve a background helper." Linux "Ask for administrator approval to
  start the packet-capture helper? A password prompt will appear on your desktop or in the terminal running aitm."
- No params. Returns at once (`invoke` never blocks on the OS): `{"outcome": "already_available" | "pending" |
  "handed_to_app" | "cannot_prompt", "message": str, "privilege": PrivilegeReport}`. Frontends poll `l4.privilege` for
  `request` progress. **(Architect's call.)**
- One request at a time; a second call while one is pending returns `pending` with the same progress.
- macOS handoff target: the running core's own bundle when the core runs from inside one (its executable is
  `<X>.app/Contents/Resources/core/aitm`); otherwise `l4.privilege.macos_app_path`. Either way the core validates the
  path before using it: an existing `*.app` directory not under `/tmp`, `/private/tmp` or `/var/folders`;
  `CFBundleIdentifier` equal to `com.mrbrutti.aitmproxy`; and a valid code signature whose team is `995PCLM9KH`. Only
  then does it run `/usr/bin/open -a <path> aitmproxy://packet-capture/allow` (§3.4) and reply `handed_to_app`. A
  missing or failing app is `cannot_prompt`.
- Linux: `pending` after spawning `pkexec /usr/lib/aitmproxy/aitm-l4-helper serve --connect <socket>` (§5); the
  progress moves to `approved` when the helper connects and passes peer checks, `dismissed` on pkexec exit 126,
  `failed` on 127 or any other exit, or after 300 s. **(Architect's call** for the timeout.)

#### 2.4 The status verbs, `L4Gated`, config, CLI

- **Status shape.** The parity spec's unit (a) owns un-gating `l4.capture.status` and `l4.intercept.status` (D11a) and
  their stable contract `{available, code, reason, captures | sessions}`. This spec only **adds** an optional
  `privilege` key beside those keys, holding the `PrivilegeReport`, and supplies the parity spec's
  `AvailabilitySource` over `PrivilegeState`. Both specs carry the same vocabulary:

  | `code` | `available` | When |
  |---|---|---|
  | `available` | true | the class works on this core now |
  | `needs_privilege` | false | the platform supports the class and this process lacks the privilege: capture/inject without read+write `/dev/bpf*` (macOS) or `CAP_NET_RAW` (Linux); intercept on Linux without `CAP_NET_ADMIN` |
  | `unsupported_platform` | false | no backend for the class on this OS: intercept on macOS and every non-Linux OS; capture/inject outside macOS and Linux |
  | `not_configured` | false | supported and privileged, but intercept has no `l4.intercept` config block |

  Mapping: a capability `available` is `code: available`; `needs_approval` is `code: needs_privilege`; Linux intercept
  without `CAP_NET_ADMIN` is `needs_privilege`; every other `unsupported` is `unsupported_platform`, with parity's
  precedence (privilege outranks configuration) kept. `reason` becomes the capability's reason, so the reason literals
  the parity plan's A9 live check quotes change when this lands; this spec's plan updates that check. Tests here
  assert `code` and `privilege`, not reason text.
- **`L4Availability.resolve`** (the frontends' decoding of the status object) is the parity spec's; this spec's
  frontends layer the `privilege` decoding on top of it and change nothing in it.
- `L4Gated` error text: `L4 unavailable: packet capture is not allowed yet (<how.label>)`. `L4Gated` forwards the
  wrapped command's `confirm_prompt` and `sensitivity` unchanged, so after availability flips to available
  `tools/list` still shows `confirmable: true` for `l4.inject`, `l4.send_recv`, `l4.intercept.forward` and
  `l4.intercept.drop`.
- Config, under `l4.privilege` (**Architect's call** for names and defaults): `helper_path` (none), `macos_app_path`
  (`/Applications/Aitmproxy.app`), `request` (`manual` | `at_start`, default `manual`). `at_start` makes the core call
  the request itself once at start when capture needs approval: the operator wrote that config, so it is an operator
  act. This is the CLI path for `aitm` and `aitm web` that needs no new command.
- The start-up `warn` line becomes `L4 enabled; packet capture needs approval: <how.label>`.
- `aitm l4.privilege` works as a one-shot CLI verb through the registry on every OS. The one-shot `aitm
  l4.privilege.request` is macOS only (it hands off to the app, which outlives the command). On Linux it refuses with
  "a one-shot command exits before the helper could serve it; set l4.privilege.request: at_start or use Allow in the
  TUI or web UI", because the helper dies with the core that spawned it.

### 3. macOS (B2)

#### 3.1 The permission helper (`aitm-l4-helper bpf-permissions`, `bpf-revert`)

`bpf-permissions` runs as root under launchd, at registration and at every boot, then exits. It takes no input: fixed
argv, no environment trust, no IPC, no network. In order:

1. Pre-create the device nodes: open each of `/dev/bpf0` to `/dev/bpf255` read-only until 256 exist (XNU clones a node
   when the last one is opened; `BPF_MAX_DEVICES` is 256).
2. For every `/dev/bpfN` (N in 0–255): refuse unless it is a character device with the major number of `/dev/bpf0`;
   `chown root:access_bpf`; `chmod 0660`.
3. Ensure group `access_bpf` exists (create it if absent, as Wireshark's installer does).
4. Only on the first run after registration (no receipt yet): if a console user is logged in and is a member of
   `admin`, add that user to `access_bpf`. That user is the operator who clicked Allow and approved in System
   Settings. Later runs, including every boot, add nobody; membership persists.
5. Write the receipt atomically: `/Library/Application Support/Aitmproxy/l4-helper.json` (directory 0755 `root:wheel`,
   file 0644 `root:wheel`; refuse if the directory is a symlink or not root-owned). Fields: `schema` (1),
   `helper_version`, `applied_at` (epoch ms), `group`, `gid`, `nodes` (count set), `members_added` (user names this
   helper added, carried forward), `errors` (strings).
6. Log one line per run to the unified log, subsystem `com.mrbrutti.aitmproxy.l4-helper`.

`bpf-revert` is the same binary under a second bundled daemon (§4.1) and is equally input-free: it returns every
`/dev/bpfN` to `root:wheel 0600`, removes each receipt `members_added` user from `access_bpf` (never a user it did not
add, so a Wireshark install keeps its members), deletes the receipt, logs one line and exits.

`aitm-l4-helper bpf-permissions --dry-run` (and `bpf-revert --dry-run`) prints the plan and changes nothing; it runs
unprivileged (the developer loop, §4.6). Group `access_bpf` is the recommended default, fork (ii). If spike S4 shows a
running process does not see the new membership until re-login, the card says "log out and back in once to finish" and
the default is reconsidered with Matt.

#### 3.2 The app (`apps/mac`)

- `Kit/PacketCapture.swift` (pure, tested): decodes `l4.privilege` and the status object's `privilege` key on top of
  the parity `L4Availability.resolve`; `PacketCaptureGate.canRegister(bundlePath: helperPresent:) -> Bool` (true only
  for `/Applications/Aitmproxy.app` with the helper and both plists present); `PacketCaptureAdvice.make(privilege:,
  helperStatus:, canRegister:)` returns the lane word, detail, remedy and actions; `PacketCaptureURL.accepts(_ url:
  URL) -> Bool` (true only for exactly `aitmproxy://packet-capture/allow`). `helperStatus` is the app's view of
  `SMAppService.Status` (`notRegistered`, `enabled`, `requiresApproval`, `notFound`).
- `Aitmproxy/Privilege/PacketCaptureHelper.swift`: the only file that touches `SMAppService`. `register()` (unregister
  first when the bundled helper version differs from the receipt), `remove()` (§3.2 Remove), `status`,
  `openLoginItems()` (`SMAppService.openSystemSettingsLoginItems()`). Every call is behind `canRegister`.
- `ConnectionSummary` gains a `packets` lane, shown on the Status page and never in the toolbar, plus a Getting
  started step `packetCaptureAllowed`, "Allow packet capture (optional, for raw TCP and UDP)", present whenever the
  bundle embeds the helper. **(Architect's call:** a fourth Status card, not a modal or wizard. Status-page rule 76
  forbids onboarding tours.) Words:

| Facts | state | word | remedy |
|---|---|---|---|
| capture `available` | ok | packet capture allowed | — |
| `notRegistered`, can register | off | packet capture not allowed | "Allow packet capture to see raw TCP and UDP" |
| `requiresApproval` | working | waiting for approval | "Turn on Aitmproxy in System Settings ▸ General ▸ Login Items & Extensions" |
| `enabled`, probe still fails | warning | allowed, not active yet | the core's reason |
| cannot register (not in /Applications, dev bundle, no helper) | off | packet capture unavailable | "Move Aitmproxy to Applications" or "Needs the signed app from the download page" |

- **The card** (Status page, and the same view in Settings ▸ Packets), a plain checklist like Proxyman's: title "Allow
  packet capture (needs administrator approval)", then
  1. "Adds a small background helper that runs as root once each time your Mac starts."
  2. "It lets the access_bpf group read and write the packet-capture devices, as Wireshark does, and adds you to that
     group."
  3. "It does nothing else: no network connections, no listening socket, no other files changed."
  4. "Any app you run can then capture and send raw packets. Aitmproxy itself still sends only to your L4 scope."
  5. "Remove it any time in Settings ▸ Packets."

  Buttons: **Allow Packet Capture…** (primary; registers, then opens Login Items when `requiresApproval`) and **Not
  Now** (collapses the card to its one-line lane; never shown again unprompted on this machine; the Getting started
  row stays).
- **The nudge**: where packets would appear (the L4 empty state, and the notice after a failed `l4.capture.start`),
  when capture is `needs_approval`: "No packets? Packet capture isn't allowed on this Mac yet. **Allow Packet
  Capture…** will fix it." The L4 surface is the parity spec's; this spec owns only this line and its button.
- **Capture controls** (this spec owns them; the parity spec defers them here): Start capture (interface picker,
  inbound/outbound) and Stop per running capture, in the L4 surface, sending `l4.capture.start` / `l4.capture.stop`.
  While capture is not `available` Start is disabled with the core's reason and the nudge is shown.
- **Embedded core config.** `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift` writes `l4.enabled: true` into
  the embedded core's config (with no `l4.scope`, so nothing is captured until the operator declares scope). Without
  it the embedded core registers no `l4.*` verb and none of this is reachable.
- **Remove.** Settings ▸ Packets (new tab) holds the card, the helper status, and **Remove Packet Capture…**
  (confirm). Remove reverts now, not at the next restart: the app registers the bundled revert daemon, waits up to 10
  s for the receipt to disappear, then unregisters both services, and the card reads "Removed. The packet-capture
  devices are root-only again." If macOS asks for approval for the revert daemon (S3), the card says so and completes
  after it. If the app quits mid-way, it finishes the unregister at its next launch. Settings ▸ Uninstall runs the
  same Remove before its own steps. **(Architect's call:** a second input-free daemon rather than an input to the
  first.)
- `L4Availability.resolve` stays as the parity spec built it (the parity spec already removed the Kit
  `embeddedReason`); the Packets lane reads `PacketCaptureAdvice`.
- Update: on launch, when `status == .enabled` and the receipt's `helper_version` differs from the bundle's, the app
  re-registers (unregister then register). Spike S3 decides whether this re-prompts. The card shows whatever results.

#### 3.3 What the operator sees

L4PRIV-AC6, start to finish: the card, one click, one Login Items approval, nothing typed.

#### 3.4 TUI, web and CLI on a Mac

The core cannot register a daemon. On `l4.privilege.request` it validates the handoff app (§2.3) and runs
`/usr/bin/open -a <path> aitmproxy://packet-capture/allow`.

- The app declares the `aitmproxy` URL scheme (`CFBundleURLTypes`) and accepts exactly that one URL
  (`PacketCaptureURL.accepts`). Anything else is ignored and logged with the URL cut to its first 256 characters.
- On that URL the app comes forward, opens Status and highlights the Packets card with the neutral line "Another
  program asked to allow packet capture. Allow it only if you started this." **It never registers until the operator
  clicks Allow Packet Capture… in the app.** The URL can come from any local process or web page, so the click is the
  operator's act (threat T4). When the card was surfaced by a URL:
  - Allow is not the default button (Return does not press it);
  - a further URL within 10 s of the last one is ignored (rate limit), not re-highlighted;
  - a URL that launches the app starts nothing else: no embedded core, no proxy, no extension, no capture. It only
    shows the card.
- **(Architect's call:** a URL, not `open -b <id> --args …`. `open(1)` is reported to pass `--args` only when it
  launches the app; `-a <path>`, not `-b <id>`, because the dev bundle shares the bundle id `com.mrbrutti.aitmproxy`
  and `-b` can resolve to `/tmp/Aitmproxy-dev*.app`. Spike S5 confirms both claims and URL delivery whether the app is
  running or not.)
- No valid app (§2.3): the reply is `cannot_prompt`. Frontends show the `package` label and the download link.
- No GUI session (SSH): `open` fails and the reply is `cannot_prompt`, "No desktop session to show the Aitmproxy app
  in; approve packet capture from the Mac's screen".

Frontend placement (**Architect's call**; exact spot is the builder's):

- TUI: one banner line in the L4 view when capture is `needs_approval`, a key (`A`) and a palette entry "Allow packet
  capture". Confirm, then send the request.
- Web: a banner at the top of the L4 page with an **Allow Packet Capture…** button, a confirm dialog, then the
  request. `package` renders as a link.
- CLI: `l4.privilege.request = at_start`, or the macOS one-shot verb.

### 4. Bundle layout and release pipeline (for the orchestrator before implementation)

#### 4.1 Paths inside `Aitmproxy.app` (release build only)

| Path | What | Signed |
|---|---|---|
| `Contents/MacOS/Aitmproxy` | app (unchanged) | last, with the app entitlements |
| `Contents/MacOS/aitm-l4-helper` | the helper (Rust, arm64, from the tarball) | yes, before the app |
| `Contents/Library/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist` | the apply daemon plist | sealed by the app signature |
| `Contents/Library/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper-revert.plist` | the revert daemon plist (§3.1) | sealed by the app signature |
| `Contents/Resources/core/{aitm,obscura,share/…}` | embedded core (unchanged) | unchanged |
| `Contents/Library/SystemExtensions/com.mrbrutti.aitmproxy.ne.systemextension` | sysex (unchanged) | unchanged |

**(Architect's call:** `Contents/MacOS`, not `Contents/Library/Helpers` or `Resources`. It is where Apple puts bundle
executables. The helper is not the core's, so it does not go under `Resources/core`.)

#### 4.2 Plist keys (`apps/mac/LaunchDaemons/*.plist`, copied verbatim)

| Key | Value | Why |
|---|---|---|
| `Label` | `com.mrbrutti.aitmproxy.l4-helper` (revert: `…l4-helper-revert`) | the launchd service name |
| `BundleProgram` | `Contents/MacOS/aitm-l4-helper` | SMAppService resolves it relative to the bundle (SDK header) |
| `ProgramArguments` | `["aitm-l4-helper", "bpf-permissions"]` (revert: `"bpf-revert"`) | fixed argv; the only mode launchd runs |
| `AssociatedBundleIdentifiers` | `["com.mrbrutti.aitmproxy"]` | intended so Login Items shows "Aitmproxy" with the app icon; S3 confirms |
| `RunAtLoad` | `true` | runs on approval and (apply daemon) at every boot |
| `ProcessType` | `Background` | |
| `SpawnConstraint` | team `995PCLM9KH` + signing identifier `com.mrbrutti.aitmproxy.l4-helper` | a launch constraint so launchd refuses a substituted binary. **Hard requirement** (Constraints): S3 confirms the key shape on macOS 27 and runs the substitution test; if launchd rejects every working shape, Phase 1 macOS is blocked |

No `KeepAlive`, no `MachServices`, no `Sockets` in Phase 1 (no IPC). Phase 2 adds a `Sockets` or `MachServices` entry.

#### 4.3 Signing: what SMAppService needs instead of SMJobBless keys

- No `SMPrivilegedExecutables` or `SMAuthorizedClients` (SMJobBless-era; never added). App entitlements unchanged.
- Helper: Developer ID Application, team `995PCLM9KH`, `--identifier com.mrbrutti.aitmproxy.l4-helper`, `--options
  runtime --timestamp`, **no entitlements and no provisioning profile** (research 13 §3.4, Disk Drill).
- The bundle is notarized ("Apps that contain LaunchDaemons must be notarized", SDK header), as `notarize-dmg.sh`
  already does; the helper and plists are in place before the app is signed, so the seal covers them.

#### 4.4 `scripts/notarize-dmg.sh` sign order and checks

Inside-out, as today, with one step added: (a) code nested in the sysex, (b) the sysex, (c) `core/obscura`,
`core/aitm`, **(c2) `Contents/MacOS/aitm-l4-helper`** with the identifier above, hardened runtime and a timestamp, (d)
the app last. New verify-or-fail checks before the DMG is built:

- the two plists and the helper are all present or all absent (exit 1 otherwise: helper only, plist only, or one plist
  of two);
- each plist's `BundleProgram` (`plutil -extract`) equals `Contents/MacOS/aitm-l4-helper` and that file is an
  existing, signed Mach-O;
- `AssociatedBundleIdentifiers` contains `com.mrbrutti.aitmproxy`;
- the existing post-sign assertions extend to the helper: `codesign -dv` shows
  `Identifier=com.mrbrutti.aitmproxy.l4-helper`, `^TeamIdentifier=995PCLM9KH$`, `flags=.*runtime`,
  `Authority=Developer ID Application`;
- helper has no entitlements.

`scripts/tests/run-notarize-dmg-stubbed.sh` gains the helper cases (all present, all absent, plist only, helper only,
helper signed after the app). It is a source tripwire, not evidence (AC section).

#### 4.5 `apps/mac/build.sh`, `scripts/package.sh`, release runbook, Homebrew cask

- `scripts/package.sh` builds `cargo build --release -p aitm-l4-helper` and puts `aitm-l4-helper` in the tarball
  beside `aitm` (macOS and Linux tarballs).
- `build.sh --ne` (the Developer ID, `/Applications`, release build) copies `aitm-l4-helper` **only from the release
  tarball**, never from `AITM_CORE_DIR` or a dev build, into `Contents/MacOS/`; copies both plists into
  `Contents/Library/LaunchDaemons/`; and signs the helper after the core and before the app. A release build with no
  helper in its tarball fails (like the catalogue check).
- `build.sh` without `--ne` (ad hoc or Apple Development, `~/Applications`) **does not embed** the helper or plists
  and prints `no packet-capture helper embedded (release builds only: --ne)`. **(Architect's call:** an unnotarized
  `~/Applications` bundle cannot register a daemon, so embedding it would only produce an error path.) The app then
  reads "packet capture unavailable — needs the signed app".
- Homebrew cask (tap repo `mrbrutti/homebrew-aitmproxy`, `Casks/aitmproxy.rb`): `uninstall launchctl:
  ["com.mrbrutti.aitmproxy.l4-helper", "com.mrbrutti.aitmproxy.l4-helper-revert"]`. The tap repo is outside this tree;
  its change is a release-pipeline step the orchestrator owns.
- `docs/RELEASE.md` step 3 gains one line saying the helper ships inside the app; step 6 gains `codesign -dv
  …/aitm-l4-helper` and `plutil -p` of both plists; the cask section records the `uninstall launchctl:` stanza and
  that Settings ▸ Uninstall runs Remove (§3.2).

#### 4.6 `/Applications` and the dev bundle

- The helper only registers from `/Applications/Aitmproxy.app` (`PacketCaptureGate`), where the DMG and the cask
  install; `~/Applications` is refused with "Move Aitmproxy to Applications" (the header's advice, the sysex's rule).
- `tools/snap-dev.sh` copies only `Contents/MacOS/<exe>`, `Info.plist`, icons and `Resources/core`. It must never copy
  `Contents/Library/LaunchDaemons` or `aitm-l4-helper` (a tripwire greps it). A /tmp dev bundle therefore has no
  plist, `canRegister` is false, and the card says unavailable.
- Developing the helper: unit tests of its pure logic, `--dry-run` without root, and Matt's Terminal recipe for the
  real thing (`build.sh --ne --allow-unnotarized --replace`, `notarize-dmg.sh`, install, approve).

### 5. Linux (L-C)

#### 5.1 The helper (`aitm-l4-helper serve --connect <socket>`)

Spawned by the core, through `pkexec` (default) or directly when the helper binary has file caps (the headless
fallback). The core runs `pkexec` only on the installed policy's exec path, `/usr/lib/aitmproxy/aitm-l4-helper`, never
on a configured or discovered path. Start-up, in this order; a failed step exits non-zero before any other I/O:

1. Record `getppid()`. Validate argv: exactly `serve --connect <path>`, `<path>` absolute, at most 107 bytes.
2. Determine the invoking user. `PKEXEC_UID` is trusted only when the real uid is 0 (started by pkexec); otherwise the
   invoking user is `getuid()` and `PKEXEC_UID` is ignored.
3. If root: while `CAP_SETPCAP` is still held, drop every capability except `CAP_NET_RAW` from the bounding set and
   clear the ambient set; set `PR_SET_KEEPCAPS`; set groups, gid, then uid to the invoking user; reduce permitted and
   effective to `CAP_NET_RAW`; clear keepcaps. Then, root or not, set `no_new_privs`.
4. Only now, as the invoking user, check the path: `lstat` reports a socket, not a symlink; its directory is owned by
   the invoking user, mode 0700, and not a symlink. This applies equally to the `XDG_RUNTIME_DIR` directory and to the
   fallback `/tmp/aitm-<uid>/`.
5. Connect. The core checks `SO_PEERCRED`: uid equals the core's uid and pid equals the child it spawned. The helper
   checks that the peer uid equals the invoking user. A failed check closes the connection and the helper exits.
6. Last, set `PR_SET_PDEATHSIG` (SIGKILL), then exit if `getppid()` differs from step 1 (the core died before the
   signal was armed).

It exits on EOF, on any protocol error, or when the core dies. There is never an orphaned privileged process.

#### 5.2 Protocol (`crates/aitm-proto-l4/src/helper/`, shared by both ends)

Frames on a `SOCK_STREAM` Unix socket: u32 big-endian length (max 256 KiB), a 1-byte type, then the payload. Control
payloads are JSON; `Frame` and `Inject` carry a small binary header plus the raw bytes.

| Dir | Type | Content |
|---|---|---|
| core → helper | `Hello` | `proto: 1`, core version |
| helper → core | `HelloAck` | `proto`, helper version, effective caps |
| core → helper | `ScopeSet` | the guard's current scope entries and limits (`global_inject_pps`, `max_packet_bytes`, `max_packets_per_call`) and the core's self-exclusion ports (parity spec §2.1), resent on every change |
| core → helper | `CaptureOpen` / `CaptureClose` | id, interface, direction, read timeout. No filter string |
| helper → core | `Frame` / `CaptureClosed` | capture id, timestamp, bytes / reason |
| core → helper | `Inject` | request id, interface, frame bytes |
| helper → core | `InjectResult` | request id, ok or the guard or wire error text |

A proto mismatch, an unknown type, an oversized length or malformed JSON closes the session. The core then reports
`helper.status: "version_mismatch"` or `failed`. `HelperBackend` implements the existing `CaptureInjectBackend` trait
over this session, so the commands do not change.

#### 5.3 The helper enforces the guard itself

For every `Inject` the helper parses the frame itself (it never trusts a target the core claims), then runs the same
`L4Guard::check(L4Action::Inject, &target)` and `L4Permit::authorize_packet(len)` code as the core, over the scope it
holds from `ScopeSet`, with its own rate buckets. Its frame parser has unit tests for truncated, oversized, non-IP and
IPv6 frames. For `CaptureOpen` it refuses an interface outside the capture scope and compiles its own BPF filter from
its `ScopeSet` with the same `scope_filter` function; it never accepts, or string-ANDs, a filter from the core. Same
crate, same functions, no re-implementation. **(Architect's call:** the helper links `aitm-proto-l4` for the guard and
protocol and links nothing else of the product: no Rhai, no MCP, no HTTP.)

#### 5.4 Packaging (`scripts/nfpm.yaml`, `scripts/package-linux.sh`)

- `/usr/lib/aitmproxy/aitm-l4-helper`, mode 0755, `root:root`. No `/usr/bin` symlink: it is not a user command.
- `scripts/packaging/com.mrbrutti.aitmproxy.l4-helper.policy`, installed to `/usr/share/polkit-1/actions/`: action
  `com.mrbrutti.aitmproxy.l4-helper.run`, annotation `org.freedesktop.policykit.exec.path` =
  `/usr/lib/aitmproxy/aitm-l4-helper`, `allow_gui` true, defaults `allow_any`, `allow_inactive` and `allow_active` all
  `auth_admin` (no `auth_admin_keep`: every request is a fresh authentication; a tripwire fails on `_keep`). Message:
  "Allow aitmproxy to capture and send raw packets (only within the L4 scope you configured)".
- `recommends`: deb `pkexec`, rpm `polkit`. **No maintainer scripts, no setcap, no new group.** Both files arrive
  through nfpm `contents`.
- The tarball also carries `aitm-l4-helper`, but user-owned. The core never pkexecs it (§5.1), so it serves only the
  documented fallback.

#### 5.5 Who sees the prompt

The core decides "a prompt is possible" before spawning pkexec: `DISPLAY` or `WAYLAND_DISPLAY` is set (a graphical
agent is likely), or the core's stdin is a tty (pkexec's textual agent). Otherwise the reply is `cannot_prompt` and
pkexec is never run. **(Architect's call.)**

- Web UI on a desktop: the graphical polkit dialog. From an SSH terminal: the textual prompt in that terminal, and the
  web banner says "Enter an administrator password in the terminal running aitm".
- `aitm tui` (core and TUI on one tty): before sending the request the TUI leaves the alternate screen and raw mode
  and prints "Waiting for administrator approval…", restoring its screen when progress leaves `pending`.
- `aitm` (CLI) with `l4.privilege.request: at_start`: the textual or graphical prompt at start.

#### 5.6 Headless fallback, NixOS, Homebrew on Linux

- `docs/packet-capture.md` (new) would document, for admins of headless hosts only: copy the helper to a root-owned
  path, restrict it to a group (0750 `root:aitm-l4`), give it `cap_net_raw+ep`, and set `l4.privilege.helper_path`.
  Caps go on the helper, never on `aitm`. Upgrades replace the file and drop the caps, so the step is redone after
  each upgrade. **This doc, and any product message pointing at it, needs Matt's written acceptance first** (the
  open item, the headless `setcap` doc): it is a command-line step. Until then the `cannot_prompt` message names no doc.
- NixOS: the same doc gives a `security.wrappers.aitm-l4-helper` entry (`source` = the package's helper, `capabilities
  = "cap_net_raw+ep"`, owner root, group `aitm-l4`, permissions group-execute only). Discovery already checks
  `/run/wrappers/bin`. The CVE-2026-25740 lesson is why the helper has no scripting or exec surface.
- Homebrew on Linux and tarball users: `needs_approval` `package`, "Install the aitm .deb or .rpm to get the
  packet-capture helper", with the download link. No root path exists for a formula.

### 6. Phase 2 and option A

- **Phase 2, candidate 1 on macOS:** `aitm-l4-helper serve` under the same SMAppService plist (plus a `Sockets` or
  `MachServices` entry); the helper checks the client's code signature (`macos_capture::peer_auth`) and enforces the
  guard as in §5.3; `bpf-permissions` retires and the new helper runs the `bpf-revert` logic on first boot. In-path
  NFQUEUE through the helper lands here too. Frame streaming is the default; fd passing only if spike S2 works, in a
  leaf `unsafe` crate with a non-pcap backend (research 13 §3.6).
- **Option A (frames in the sysex)** stays out unless spike S1 proves a network-entitled sysex opens `/dev/bpf*`; any
  sysex change, including a frames lane, belongs to the NE session.

### 7. Security

- **Unchanged:** deny-by-default L4 scope; scope is the authorization; `L4Guard` sits at the one lowest write in the
  core (`wire::send_on_wire`); the agent capability gates.
- **T1, group-wide `/dev/bpf*` (B2).** Any process of an `access_bpf` member can sniff every interface and write
  arbitrary frames with no aitmproxy guard: the machine-level permission Wireshark asks for, stated on the card
  (line 4). Mitigations: only the approving admin is added; Remove reverts at once; Phase 2 replaces B2. Little
  Snitch's optional BPF gate may prompt on first open; that is expected.
- **T2, the macOS helper modes** take no input. Each verifies every node is a bpf character device before changing it,
  writes only under `/Library/Application Support/Aitmproxy/`, refuses symlinked or foreign-owned directories, and is
  constrained by `SpawnConstraint` (a hard requirement) and the bundle seal.
- **T3, the Linux helper.** It validates its own argv, checks nothing as root (§5.1), authenticates its peer both
  ways, re-runs the guard on every frame and builds its own capture filter (§5.3), and dies with the core. Only the
  policy's root-owned path is ever pkexec'd. Its limit: a compromised core can send a wider `ScopeSet`, so it is a
  boundary against everything except its parent core. The setcap fallback makes it an oracle for every user who can
  execute it, which is why the doc restricts it to a group.
- **T4, agent and remote triggers.** `l4.privilege.request` is operator-only at the policy gate and in the command,
  and is never parked; gated verbs never start a request. The macOS URL only brings the app forward (§3.4); the
  in-app click and the OS approval, or the polkit dialog on Linux, are the human gates. An agent with a shell could
  run `open` or `pkexec` itself, which still ends at those gates.
- **T5, audit.** Every `l4.privilege.request` call lands in the audit ring with caller and outcome, as every verb
  does. State changes log one `info` line.

### 8. Ownership, coordination and order

| Change | Owner |
|---|---|
| `l4.capture.status` / `l4.intercept.status` un-gating, the status shape and vocabulary, `AvailabilitySource`, `L4Availability.resolve` | parity spec, unit (a) |
| The status object's optional `privilege` key and the `AvailabilitySource` over `PrivilegeState`; `PrivilegeState`, `l4.privilege`, `l4.privilege.request`, live gating, probe strings, the `is_operator_only` entry | this spec |
| `aitm-l4-helper` (all modes), protocol, `HelperBackend`, Linux packaging, headless doc | this spec |
| Bundle layout, `build.sh`, `notarize-dmg.sh`, `package.sh`, RELEASE.md lines, the cask stanza | this spec (reviewed by the orchestrator) |
| Mac: `PacketCapture` Kit model, `PacketCaptureHelper`, URL handler, Packets card and lane, Settings ▸ Packets and Remove, the nudge line, the capture start/stop controls, `EmbeddedCoreLaunch.swift` writing `l4.enabled: true` | this spec |
| TUI and web: the banner, the Allow action, TUI suspend, `privilege` decoding | this spec |
| Everything else in the L4 UIs (D1–D15), `l4.scope.add` confirm (D11b) | parity spec |
| Any sysex or NE change | NE session |
| `ConnectionSummary` shape | Status-page spec. This spec adds one lane kind and one step kind and changes nothing else |

**Order.** This spec's core branch is cut after parity unit (a) merges, because it builds on (a)'s status shape and
`AvailabilitySource`. Its TUI, web and mac branches are cut after parity units (b), (c) and (d) merge, because they
touch the same files.

### 9. Spikes before Phase 1 (each an `experiment/<topic>` session, under the spike rule)

| # | Question | Research §7 Q | Blocks |
|---|---|---|---|
| S3 | On macOS 27, what does `SMAppService.daemon.register()` show: a Login Items toggle only, or a toggle plus admin auth? Does re-register after an update re-prompt? Does registering the revert daemon from an approved app prompt? Is a `~/Applications` bundle refused? Does `AssociatedBundleIdentifiers` show the app name and icon? Which `SpawnConstraint` shape does launchd accept, and does it refuse a substituted helper (substitution test)? | 3 | §3.2 words, §4.2, Phase 1 macOS, AC6, AC13, AC14, AC28 |
| S4 | After `dseditgroup` adds the console user to `access_bpf`, does an already-running process open a `0660 root:access_bpf` node without re-login? | 5 | fork (ii) default, AC7 |
| S5 | Does `open -a /Applications/Aitmproxy.app aitmproxy://packet-capture/allow` deliver the URL both when the app is running and when it is not? Does `open --args` really drop arguments for a running app? | — (new) | §3.4, AC9 |
| S7 | Linux: does pkexec's textual agent work while the core's stdio is redirected? Does pkexec close fds above 2? Does the §5.1 drop keep `CAP_NET_RAW` usable by `pcap` for open and inject on `lo`? Is `CAP_NET_RAW` alone enough? | 8 | §5.1, AC16, AC22 |
| S8 | macOS 27: does a BPF write of a DLT_NULL frame on `lo0` reach a UDP socket on 127.0.0.1:9053, and is it read back by a capture? | 7 | AC8 steps W3–W4 on macOS |
| S6 (optional) | Can an unprivileged process read `launchctl print system/com.mrbrutti.aitmproxy.l4-helper` to enrich `helper.status`? | 4 | nothing; enrichment only |
| S1, S2 | Sysex `/dev/bpf*` open; `SCM_RIGHTS` of a bpf fd on macOS 27 | 1, 2 | Phase 2 / option A only |

### 10. Phase 1 file map

New: `crates/aitm-proto-l4/src/{privilege/{mod,derive,macos,linux},commands/privilege,helper/{mod,proto,client},
backend/helper}.rs`; `crates/aitm-l4-helper/` (workspace crate, `version.workspace = true` so app, core, sysex and
helper carry one version); `apps/mac/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper{,-revert}.plist`;
`apps/mac/Sources/AitmproxyKit/PacketCapture.swift` and tests; `apps/mac/Sources/Aitmproxy/{Privilege/
PacketCaptureHelper,Panels/PacketCaptureCard}.swift`; `apps/mac/tools/check-packet-helper.sh` (tripwires);
`scripts/packaging/com.mrbrutti.aitmproxy.l4-helper.policy`; `docs/packet-capture.md` (only after the open item, the
headless `setcap` doc, is accepted);
`tests/e2e/l4/test_privilege_*.py` (on the canonical `tests/e2e/aitm_e2e` harness).

Changed:

- `crates/aitm-proto-l4/src/{module,capture,sendrecv,language,config}.rs`, `commands/{capture,intercept,mod}.rs`
- `crates/aitm/src/{wire,main}.rs`; `crates/aitm-mcp/src/server.rs` (`is_operator_only` only)
- `apps/mac/Info.plist.in` (URL type), `ConnectionSummary.swift`, `EmbeddedCoreLaunch.swift`, `StatusPanel.swift`,
  `SettingsView.swift`, `App.swift` (URL handler), the L4 surface file that hosts the capture controls (named in the
  plan: `Panels/L4CaptureControls.swift`, new). Privilege decoding lives in the new `PacketCapture.swift` (plan
  P3.1); `L4.swift` is not changed.
- `apps/mac/build.sh`, `scripts/notarize-dmg.sh` and its stub test, `scripts/package.sh`, `scripts/nfpm.yaml`,
  `scripts/package-linux.sh`, `docs/RELEASE.md`; the tap repo's `Casks/aitmproxy.rb`
- `crates/aitm-tui/src/{app,l4,keys}.rs`, `ui/l4.rs`
- `apps/web/src/panels/l4/L4PrivilegeBanner.tsx` (new) and the L4 store
- the three tool contracts (`EXPECTED_TOOLS`, `CORE_TOOLS`, `bus-fixture.json`)

Also claimed by the plan (Architect's call, plan 2026-10-31), per unit; the files marked **behaviour surfaces, flagged
for Matt** carry user-visible change this spec did not list:

- (p1a) new `crates/aitm-proto-l4/src/privilege/contract.rs`, `helper/{frame,enforce}.rs`; changed
  `crates/aitm-proto-l4/src/lib.rs`, `crates/aitm-proto-l4/Cargo.toml` (none expected)
- (p1b) new `crates/aitm-proto-l4/src/privilege/{report,availability,state}.rs`, `backend/routed.rs`,
  `crates/aitm-proto-l4/tests/privilege.rs`; changed `crates/aitm-proto-l4/src/{lib,guard}.rs`, `helper/mod.rs`,
  `backend/mod.rs`, `crates/aitm-proto-l4/Cargo.toml` (`tracing`, Linux `nix`), `crates/aitm/tests/frontends.rs`,
  `crates/aitm-tui/src/lib.rs` (`CORE_TOOLS` only), `crates/aitm-tui/tests/tester_shell.rs` (two count pins),
  `tests/e2e/l4/{test_l4_parity_core,test_l4_parity_priv}.py`, `docs/research/mcp-tool-catalog.txt`,
  `aitmproxy-plugin/docs/tool-reference.md`, `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md`
- (p2) new `tests/e2e/l4/linux-privilege-rig.sh`; changed the root `Cargo.toml` (`members`, workspace dep),
  `Cargo.lock`
- (p3) new `apps/mac/Sources/AitmproxyKit/L4Capture.swift`, `apps/mac/Tests/AitmproxyKitTests/L4CaptureTests.swift`,
  `apps/mac/Sources/Aitmproxy/Panels/L4CaptureControls.swift`, `apps/mac/tools/{check-packet-capture-ui,
  cua-packet-capture}.sh`; changed `apps/mac/Tests/AitmproxyKitTests/{ConnectionSummaryTests,
  EmbeddedCoreLaunchTests}.swift`, `apps/mac/tools/check-connection-words.sh`, and — **behaviour surfaces, flagged for
  Matt** — `apps/mac/Sources/Aitmproxy/Session.swift`, `apps/mac/Sources/Aitmproxy/Panels/ScopePanel.swift`,
  `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (L4 empty state)
- (p5) new `scripts/tests/check-linux-packaging.sh`
- (p6) new `crates/aitm-tui/tests/l4_privilege.rs`, `apps/web/src/panels/l4/{privilege.ts,privilege.test.ts}`,
  `apps/web/scripts/cua-l4-privilege.mjs`; changed `crates/aitm-tui/src/{action,bus,lib}.rs`, and — **behaviour
  surfaces, flagged for Matt** — `crates/aitm/src/tui.rs` (in-process flag only),
  `apps/web/src/panels/l4/CaptureControls.tsx`, `apps/web/src/panels/l4/PacketList.tsx`

## Acceptance criteria

**Evidence rule (Matt's).** Only these count as evidence or as a regression gate: a real frontend driving a real core
with real traffic; Rust or Kit unit tests of pure logic; source tripwires. No fixture, snapshot, self-test or
seeded-store run counts. The contract pins and the stubbed `notarize-dmg.sh` test are tripwires, never proof that a
feature works.

**The privilege rig.** `aitm web` with `l4.enabled: true` and config scope `lo0` (macOS) or `lo` (Linux),
`127.0.0.1/32`, ports `9000-9999`, one entry each for capture, inject and intercept. Targets: `python3 -m http.server
9099` and a UDP echo on 9053. Driven by the real web UI in a browser, the real TUI in a pty, the mac app connected to
the rig as its external core, and the python `aitm_e2e.bus` client as operator and as agent. Hygiene: `umask 077`;
config and logs mode 600; core logs deleted after each check.

**Walk W** (operator, after approval):

- W1. `l4.capture.start {interface, direction: "inbound"}` returns an id. W2. After fetching
  `http://127.0.0.1:9099/` and sending `ping` to UDP 9053, `l4.flow.get` shows packets whose `layers` contain `"TCP"`
  and `"UDP"`. W3. `l4.inject` of a crafted UDP datagram to 127.0.0.1:9053, payload `aitm-inject`, returns ok and the
  capture shows a new packet with `injected: true`. W4. `l4.send_recv` to 127.0.0.1:9053 with payload `aitm-sr`
  returns `aitm-sr`. W5. `l4.inject` to 127.0.0.1 port 8999 is refused with a guard error containing `scope`, and
  the capture gains no packet.

Tags: **[unit]** Rust or Kit unit test. **[trip]** source tripwire. **[linux-ci]** real core on a Linux CI runner or
systemd container. **[mac-any]** any Mac and any build, against the privilege rig. **[mac-signed]** a real Mac with
the Developer-ID-signed, notarized bundle installed in `/Applications`; the dev bundle cannot register a daemon, so
these run on Matt's Mac via the Terminal and CUA recipe. **[linux-desk]** a Linux desktop VM, by hand.

1. **L4PRIV-AC1 [linux-ci, mac-any]** On an unprivileged rig, operator and agent `l4.privilege` both answer within 500
   ms with `capabilities.capture.state == "needs_approval"`. On macOS, `capabilities.intercept.state ==
   "unsupported"`. `how.kind` is `"pkexec"` on Linux with the deb installed, `"app_action"` on a Mac with the signed
   app in `/Applications`, and `"package"` with `l4.privilege.macos_app_path` set to a missing path. `checked_at` is
   an integer (epoch ms).
2. **L4PRIV-AC2 [linux-ci, mac-any]** With `l4.enabled: false`, `l4.privilege` answers `"enabled": false` with all
   three capabilities `unsupported`.
3. **L4PRIV-AC3 [unit, trip]** `derive` yields the §2.2 tables row for row. No `reason` or `label` in any variant, and
   no string in `module.rs` `probe()`, matches `\b(sudo|setcap|chmod|chgrp|chown|dseditgroup|launchctl|pkexec)\b`.
4. **L4PRIV-AC4 [linux-ci, mac-any, unit]** On an unprivileged rig, `l4.capture.status` returns, with no error, the
   parity status object (`available: false`, `code: "needs_privilege"`, `captures: []`) plus a `privilege` key holding
   a `PrivilegeReport` whose `capabilities.capture.state` is `needs_approval`; `l4.intercept.status` has `code:
   "unsupported_platform"` on macOS and `"needs_privilege"` on Linux without `CAP_NET_ADMIN`. Unit: the mapping of
   §2.4 for each capability state.
5. **L4PRIV-AC5 [linux-ci, mac-any, trip]** Agent `l4.privilege.request`: under `ask` it is refused at once and never
   parked (`agent.pending` stays empty); under `auto` and `all` it is refused by the policy gate, with text starting
   `` `l4.privilege.request` refused: the agent policy is ``. No `pkexec` process appears within 2 s (Linux) and
   Aitmproxy is not launched (macOS). Its audit-ring entry records the agent caller. Tripwires:
   `is_operator_only("l4.privilege.request")` is true; the verb is absent from `defers_to_command_gate`;
   `sensitivity() == Sensitive`; `confirm_prompt` is `Some`; and an untrusted `CommandHost` calling `invoke` directly
   gets `l4.privilege.request refused: only an operator`.
6. **L4PRIV-AC6 [mac-signed]** On a Mac where `stat -f '%Sp %Su %Sg' /dev/bpf0` prints `crw------- root wheel`: first
   launch shows the Packets card with its five lines and the Getting started row ○. Click **Allow Packet Capture…**,
   System Settings opens on Login Items & Extensions with Aitmproxy under Allow in the Background, and turn it on.
   Within 10 s: `/dev/bpf0` prints `crw-rw---- root access_bpf`; `/dev/bpf255` exists; the receipt has `"group":
   "access_bpf"`, `helper_version` equal to the app's `CFBundleShortVersionString`, and `members_added` equal to the
   console user only; `dscl . -read /Groups/access_bpf GroupMembership` lists the console user; the card reads "packet
   capture allowed" and the row is ✓. The operator typed nothing. The observer may read state in Terminal.
7. **L4PRIV-AC7 [mac-signed]** A rig core started before AC6's approval reports capture `available` within 5 s of it,
   without a restart. A Homebrew or tarball `aitm l4.privilege` one-shot (not the bundle's binary) reports
   `available`.
8. **L4PRIV-AC8 [mac-signed, linux-ci]** Walk W passes on the rig: macOS on `lo0` in process after AC6, Linux on `lo`
   through the helper in both AC16 mode and AC17 mode. On macOS, W3–W4 depend on spike S8.
9. **L4PRIV-AC9 [mac-signed]** From the TUI (pty) and from the web UI (browser) against the rig on the Mac, with the
   app running and with it quit: the Allow action plus confirm brings Aitmproxy forward on Status with the Packets
   card highlighted and the §3.4 neutral line; Return does not press Allow; when quit, the URL launch starts no
   embedded core. SMAppService status stays `notRegistered` until the click in the app, and after the click the AC6
   flow completes. Opening `aitmproxy://packet-capture/allow` from a browser page brings the app forward and registers
   nothing; a second open within 10 s does not re-highlight.
10. **L4PRIV-AC10 [mac-any]** With `macos_app_path` missing, or pointing at a `/tmp` bundle, or at a bundle with
    another bundle id or team, and the core not running from a bundle: the TUI and web UI show the `package` label and
    a link to `https://mrbrutti.github.io/aitmproxy/download.html`, and no shell command. The request returns
    `"outcome": "cannot_prompt"` and `open` is not run.
11. **L4PRIV-AC11 [mac-any, unit, trip]** A `snap-dev.sh` bundle and a plain `build.sh` bundle show "packet capture
    unavailable" with no Allow button. `PacketCaptureGate.canRegister` is true only for `/Applications/Aitmproxy.app`
    with the helper and both plists present (Kit truth table). `PacketCaptureURL.accepts` is true for
    `aitmproxy://packet-capture/allow` and false for `aitmproxy://packet-capture/allow?x=1`,
    `aitmproxy://packet-capture/remove`, `aitmproxy://other` and `http://packet-capture/allow`; the logged form of a
    10,000-character URL is 256 characters (Kit unit). Tripwires: `SMAppService` is referenced only in
    `PacketCaptureHelper.swift`, every call sits behind `canRegister`, and `snap-dev.sh` contains neither
    `LaunchDaemons` nor `aitm-l4-helper`.
12. **L4PRIV-AC12 [mac-signed, trip]** On the notarized bundle: both plists' `BundleProgram` equals
    `Contents/MacOS/aitm-l4-helper`; `AssociatedBundleIdentifiers` equals `["com.mrbrutti.aitmproxy"]`; helper
    `codesign -dv` shows `Identifier=com.mrbrutti.aitmproxy.l4-helper`, `TeamIdentifier=995PCLM9KH`, `runtime`,
    Developer ID; `codesign --verify --deep --strict` passes on the app; `stapler validate` passes on the DMG.
    Tripwire: the stub test fails if the script does not exit 1 for a plist without a helper, a helper without the
    plists, one plist of two, or a helper signed after the app.
13. **L4PRIV-AC13 [mac-signed]** Installing a newer notarized build over an approved one: the receipt's
    `helper_version` changes to the new version within 10 s of first launch, and capture stays or becomes `available`.
    If S3 says re-register re-prompts, the card shows "waiting for approval" and the AC6 flow repeats.
14. **L4PRIV-AC14 [mac-signed]** **Remove Packet Capture…**, with no reboot: within 10 s `/dev/bpf0` prints
    `crw------- root wheel`, the receipt is gone, `dscl` no longer lists the user the receipt had added (a member
    added by anyone else stays), both services report `notRegistered`, and `l4.privilege` shows capture
    `needs_approval`. Settings ▸ Uninstall produces the same end state.
15. **L4PRIV-AC15 [linux-ci, trip]** The deb and the rpm, installed in clean containers, carry the helper (0755
    root:root) and the policy (action id and `exec.path` as §5.4). `getcap` is empty for both `aitm` and the helper.
    Tripwires: `nfpm.yaml` has no scripts and no `setcap`; the policy's `allow_active` is `auth_admin` and the string
    `auth_admin_keep` appears nowhere in it.
16. **L4PRIV-AC16 [linux-ci]** With a test-only polkit rule granting the CI user
    `com.mrbrutti.aitmproxy.l4-helper.run`: operator `l4.privilege.request` returns `"pending"`, then `l4.privilege`
    shows capture `available` via `helper` within 10 s. `/proc/<helper pid>/status` shows all four `Uid:` fields equal
    to the CI uid, `CapEff:` and `CapPrm:` equal to `0000000000002000`, `CapBnd:` equal to `0000000000002000`,
    `CapAmb:` all zero, and `NoNewPrivs: 1`.
17. **L4PRIV-AC17 [linux-ci]** A helper copy with `cap_net_raw+ep` in a root-owned 0750 path, named by
    `l4.privilege.helper_path`, starts without pkexec. `helper.kind` is `"linux_cap_helper"` and capture is
    `available`. Setting `helper_path` to a non-policy path never causes a `pkexec` of it.
18. **L4PRIV-AC18 [linux-ci, unit]** The real helper connected to a test socket owner (not the core) that sends
    `ScopeSet` (9000-9999) and then an `Inject` to port 8999 returns an `InjectResult` error containing `scope`, and
    an independent capture sees no packet to 8999. An oversized length makes the helper exit. A socket in a directory
    not owned by the invoking user is refused at start, and so is a `/tmp/aitm-<uid>/` fallback owned by another uid.
    Run directly (not root) with `PKEXEC_UID=0` set, the helper takes `getuid()` as the invoking user. Unit: the
    helper's frame parser and its scope-built BPF filter.
19. **L4PRIV-AC19 [linux-ci]** After `kill -9` of the core, no `aitm-l4-helper` process exists within 2 s.
20. **L4PRIV-AC20 [linux-ci]** A helper under `$HOME` (the tarball layout) gives `how.kind == "package"`. The request
    returns `cannot_prompt` and no pkexec runs. The one-shot `aitm l4.privilege.request` on Linux refuses with the
    §2.4 message and spawns nothing.
21. **L4PRIV-AC21 [linux-desk]** On a GNOME VM, the web UI's Allow shows the graphical polkit dialog with the helper
    path and the policy message. Approve, and walk W passes. Cancel instead, and `request.state == "dismissed"` while
    the banner says "Approval was cancelled". A second Allow prompts again (no cached grant).
22. **L4PRIV-AC22 [linux-ci]** In a systemd container (polkitd running, user `tester` with a password and in the admin
    group, no graphical agent), with `aitm tui` in a pty: Allow plus confirm restores the normal screen, and a prompt
    containing `com.mrbrutti.aitmproxy.l4-helper.run` appears. The harness types the password, the TUI redraws, and
    the banner is gone with capture `available`.
23. **L4PRIV-AC23 [linux-ci]** With `DISPLAY` and `WAYLAND_DISPLAY` unset and stdin not a tty, the request returns
    `cannot_prompt` and no pkexec runs. Its message names `docs/packet-capture.md` only if Matt accepted that doc
    (the open item, the headless `setcap` doc), and otherwise names no doc.
24. **L4PRIV-AC24 [linux-ci, mac-any, trip]** With L4 enabled and capture not available, the start-up log has exactly
    one line `L4 enabled; packet capture needs approval: …`, matching neither the AC3 regex nor the operator token.
    The three tool contracts list `l4.privilege` and `l4.privilege.request`.
25. **L4PRIV-AC25 [mac-any, linux-ci]** With capture `needs_approval`, the L4 empty state in the mac app, the TUI and
    the web UI shows the "No packets?" nudge with its Allow action, and a failed `l4.capture.start` shows the same
    nudge.
26. **L4PRIV-AC26 [unit, mac-any, mac-signed]** Kit unit: the config `EmbeddedCoreLaunch` writes contains `l4.enabled:
    true` and no `l4.scope`. Against the privilege rig the mac L4 surface shows Start capture disabled with the core's
    reason [mac-any]; after AC6, Start on `lo0` returns an id and Stop ends it, both visible in the rig's audit ring
    from the mac connection [mac-signed].
27. **L4PRIV-AC27 [unit]** A module whose `PrivilegeState` flips from `needs_approval` to `available`: `tools/list`
    built from its registry shows `confirmable: true` for `l4.inject`, `l4.send_recv`, `l4.intercept.forward` and
    `l4.intercept.drop` both before and after the flip.
28. **L4PRIV-AC28 [mac-signed]** Spike S3's substitution test is written up and passed: with the helper replaced by a
    binary that does not meet the `SpawnConstraint`, launchd refuses to run it and the receipt is not rewritten.
    Without this AC, Phase 1 macOS does not ship.
29. **L4PRIV-AC29 [mac-signed, trip]** Tripwire: the tap's `Casks/aitmproxy.rb` contains the §4.5 `uninstall
    launchctl:` stanza with both labels. On the signed Mac, `brew uninstall --cask aitmproxy` after AC6 leaves
    `launchctl print system/com.mrbrutti.aitmproxy.l4-helper` failing.

## Left to the builder

- The JSON field order, exact Rust type names under `privilege/` and `helper/`, and how `ProbeInputs` is gathered,
  provided `derive` stays pure.
- The privilege-drop crate (`caps`, `nix`, or both), the UDS directory layout under `XDG_RUNTIME_DIR` (fallback
  `/tmp/aitm-<uid>/`, verified per §5.1), and the frame-header byte layout within §5.2's limits.
- Card layout, icon, and the exact spot of the TUI and web banners within the L4 view or page.
- How the bundle's helper version reaches the app (a generated constant or a `version` call).
- Test file names inside the named directories.

## Open questions

Forks (i)–(v) were decided by Matt on 2026-11-01 (see Status). One item stays open: Matt's written acceptance that `docs/packet-capture.md` may describe `setcap` on the helper as the headless Linux fallback (never the product's default path).

## Amendment log

| # | Date | Source | Change |
|---|---|---|---|
| S1 | 2026-11-01 | spike S7 (`docs/research/experiments/2026-11-01-l4-s7-pkexec-helper.md`, PR 240), recorded by the p2 session on the orchestrator's instruction | **Proven:** pkexec + the §5.1 order gives a helper holding exactly `CAP_NET_RAW` that matches AC16 byte for byte, captures and injects on `lo` through libpcap, dies with the core, and cannot be fed an fd (pkexec closes fds above 2 and execs in place, so the `SO_PEERCRED` pid is the spawned pid). **§5.1:** the order is a correctness requirement: `PR_SET_KEEPCAPS` before the uid/gid change, bounding-set drop while `CAP_SETPCAP` is held, `setgroups([primary gid])` not `initgroups`, `PR_SET_PDEATHSIG` strictly after the credential change. **§5.2 / §5.3 / AC8 (Linux):** an inject to a local destination goes through a raw IP socket (`AF_INET`, `SOCK_RAW`, `IPPROTO_RAW`, `IP_HDRINCL`, also `CAP_NET_RAW`); `pcap_inject` of an L2 frame on `lo` is a martian under default sysctls. **§5.4:** `allow_gui` is dropped; `pkexec` is a separate package on Debian trixie (deb `recommends`). **§5.5:** "prompt possible" is `DISPLAY` or `WAYLAND_DISPLAY` set, or `open("/dev/tty")` succeeds; the textual agent never returns 126 (wrong password, Ctrl-D and no terminal are all 127; Ctrl-C is SIGINT to the whole foreground group), so the request-outcome mapping is: 126 → `dismissed`, 127 + agent-creation error → `cannot_prompt`, 127 + controlling-terminal EOF → `dismissed`, 127 + `Not authorized` → `failed`, SIGINT → `dismissed`; the core keeps a SIGINT handler (never `SIG_IGN`) while a pkexec child lives. **AC22:** the prompt's first line is `==== AUTHENTICATING FOR com.mrbrutti.aitmproxy.l4-helper.run ====`. **AC23:** same shape, with the new predicate. The socket path appears in the journal; it carries nothing secret. |
| S2 | 2026-11-01 | p1a panel (spec reviewer SP-M1, SP-M2), recorded by the p2 session | **§5.2:** control payloads are strict JSON (unknown keys close the session as malformed) EXCEPT the two handshake bodies `Hello` and `HelloAck`, which tolerate unknown keys so the `proto` comparison runs first and a newer peer is reported as `version_mismatch`. **§5.3:** the helper decodes an inject frame strictly and refuses, before the guard runs, a frame whose IP payload carries no transport the guard can name (unknown IP protocol, fragment) with a `NoTransport` error; the core's in-process path admits the same bytes as `L4Proto::Raw`. Deny-side only, documented in `helper/frame.rs`. **§5.1 (S1 follow-up, from S7):** a local-destination inject on Linux uses a raw IP socket with `IP_HDRINCL` through `socket2` (safe API), not nix's macro.
| S3 | 2026-11-01 | p2 panel (spec reviewer SP-M9, tester F3), recorded by the p2 session | **§3.1 step order:** the group is created (step 3) before the nodes are chowned (step 2) because `chown root:access_bpf` needs the gid; the plan's P2.2 order is binding. **§3.1 step 4:** the console user is added to `access_bpf` only when the run also changed at least one `/dev/bpf*` node (no receipt yet, admin console user, and a valid node); a run that fixed nothing changes no directory-service state. **§5.2 `HelloAck`:** `caps` names the capabilities the core understands (`CAP_NET_ADMIN`, `CAP_NET_RAW`) that are present in the helper's effective set, read from `/proc/self/status` after the drop; empty when it holds neither. **§5.3:** a new `ScopeSet` closes any open capture whose interface the new scope no longer covers (`CaptureClosed`, reason `scope changed`, sent by the capture's own thread after its last frame so no `Frame` follows the close); the helper's rate buckets start fresh with the new scope. **§5.1 step 4 / §3.1 step 5:** "mode 0700" and "0755" are exact (`mode & 0o7777`), setuid/setgid/sticky bits are refused.

