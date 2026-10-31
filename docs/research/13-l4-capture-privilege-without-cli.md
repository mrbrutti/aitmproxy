# L4 capture/inject privilege without a command line (macOS and Linux)

**Date:** 2026-10-31. **Method:** SDK headers read from the local macOS 27 Xcode SDK; installed
Proxyman 26.3.0, Little Snitch and Disk Drill inspected read-only (`plutil`, `codesign -d
--entitlements`); this repo (`module.rs` `probe()`, `apps/mac/Extension`, `macos_capture/listener.rs`,
`scripts/nfpm.yaml`, `docs/RELEASE.md`); Apple Developer Forums, Wireshark, Homebrew, Debian,
freedesktop, man7, docs.rs via WebFetch/WebSearch. **Caveat:** WebFetch summarises pages with a small
model, so web quotes are second-hand; SDK-header and local-bundle facts are first-hand. Nothing was
run as root and no privileged experiment was done. Builds on 08 (privilege model), 09 (NFQUEUE), 10
(NE design); it does not repeat them.

**Headline.** Nobody in this product class does raw capture with zero prompts. Wireshark is the only
one of the named tools that captures raw frames, and it needs a root-installed launch daemon
(macOS) or setcap (Linux). Proxyman, Little Snitch and Charles work at flow/DNS level and never open
`/dev/bpf*`. One standard OS dialog is achievable on both OSes.

## 1. Question

How can aitmproxy get raw L4 capture and injection privilege on macOS and Linux without the user
typing a command, with at most one standard OS admin prompt, for the macOS app, TUI, web UI and CLI?

## 2. Short answer

On macOS, the app registers a root daemon with `SMAppService.daemon` (one admin approval in Login
Items) that re-applies ChmodBPF-style permissions at boot; because `/dev/bpf*` is system-wide, the TUI,
web and CLI cores gain capture too, and `probe()` needs no change. Capture inside the NE sysex is
unverified and tied to the proxy. On Linux, a small polkit/pkexec-launched helper, or `setcap` on a
helper in the deb/rpm. Homebrew formulae can do neither. The core should answer `l4.privilege`
instead of erroring.

## 3. Findings

### 3.1 Ground truth (read 2026-10-31)

- `probe()` on macOS opens `/dev/bpf0..255` read+write and drops the handle at once
  (`crates/aitm-proto-l4/src/module.rs`, tree). On Linux it reads `CapEff` from `/proc/self/status`
  for `CAP_NET_RAW` (capture/inject) and `CAP_NET_ADMIN` (NFQUEUE); its error text tells the user to
  run `setcap cap_net_raw+ep` by hand. `setcap ...+p` alone would read as "unavailable" because the
  probe checks the *effective* set (inference from the code; the `+p` vs `+ep` split is also seen in
  the mtuspy PR in sources).
- This Mac: only 4 nodes exist, `crw------- root` (`ls -l /dev/bpf0`), user is in `admin`. Nodes
  appear on demand: XNU `bpf_make_dev_t` creates them `UID_ROOT, GID_WHEEL, 0600`, capped at 256
  (`BPF_MAX_DEVICES`) (apple-oss-distributions/xnu `bsd/net/bpf.c`, via WebFetch). The same read
  found **no privilege check in `bpfopen`, `bpfioctl` or `bpf_setif`**, so open is the gate;
  `bpfwrite` has an extra entitlement gate only for "management" interfaces. Quinn (forums 708765):
  "the process that calls `open` must have an effective user ID of 0".
- `aitm` today is stdlib-only for fds: workspace `unsafe_code = "forbid"`; audited `unsafe` lives in
  a leaf crate (`aitm-peer-token`, one `getsockopt(LOCAL_PEERTOKEN)`); `macos_capture::peer_auth`
  already verifies a peer's code signature on a UDS (tree).
- Linux package: nfpm `.deb`/`.rpm`, binaries in `/usr/lib/aitmproxy`, symlinks in `/usr/bin`,
  no scripts and no caps today (`scripts/nfpm.yaml`). macOS: DMG plus Homebrew cask in the tap
  `mrbrutti/homebrew-aitmproxy`; formula `aitm` and cask `aitmproxy` bumped by hand
  (`docs/RELEASE.md`).

### 3.2 What the reference products actually do on macOS

| Product | Capture level | Privileged pieces | User sees | Source |
|---|---|---|---|---|
| Proxyman 26.3.0 | flows (`app-proxy` transparent-proxy sysex) | SMJobBless helper `com.proxyman.NSProxy.HelperTool` (sets system proxy) + sysex | helper install on first launch, Login Items allow (macOS 13+), sysex approval | local bundle: `SMPrivilegedExecutables`, `NEProviderClasses`; docs.proxyman.com |
| Charles | HTTP proxy | SMJobBless `com.xk72.charles.ProxyHelper` | "Grant Privileges" plus password | search summary, Delinea/Jamf pages |
| Little Snitch | flows, DNS, process | legacy daemon in `/Library/LaunchDaemons`, NE filter + DNS sysex (`app-sandbox=false` explicitly), Endpoint Security sysex | installer + approvals | local bundle and plist |
| Wireshark | **raw frames** | `ChmodBPF` LaunchDaemon from a pkg | installer admin prompt, reboot or re-login | Wireshark docs, Apple Community thread |

Two consequences. (1) "Proxyman-class UX" for raw frames has no Proxyman precedent; the real
precedent is Wireshark's pkg. (2) Proxyman itself needs a helper and a Login Items approval, and its
own CLI cannot trigger them silently: `proxyman --install-privileged-components` launches the GUI app,
which auto-installs the helper and "Require[s] permission" (maintainer, issue 1767, Sep 2023). The
"CLI asks the installed app" pattern is thus already shipping.

### 3.3 macOS option A: capture inside the existing sysex

- The sysex is a `NETransparentProxyProvider` (+ `NEAppProxyUDPFlowHandling`,
  `apps/mac/Extension/Sources/TransparentProxyProvider.swift:24`): it sees **flows** (TCP streams,
  UDP datagrams), never frames. Its entitlements carry only
  `com.apple.developer.networking.networkextension = app-proxy-provider-systemextension` plus
  identifiers; no sandbox key. NE owner: the session "Ship macOS NE in DMG + app enable/disable
  toggle".
- It runs as root: spike #4 saw `peer uid=0` (`experiments/2026-10-29-macos-ne-spike.md`); Quinn
  (forums 133761, Jun 2020): "a sysex runs as root".
- **Can it open `/dev/bpf*`? Unverified.** The spike never tried. Evidence is contradictory on the
  sandbox: Quinn (forums 132641, May 2020) "NetworkExtension providers must be sandboxed regardless
  of how they are packaged", while ES sysexes are not sandboxed; shipping Developer ID NE sysexes
  (Proxyman, mitmproxy, aitm) carry no sandbox key and Little Snitch sets `app-sandbox=false`.
  Quinn (forums 128528): a sandbox is a second barrier on top of node permissions. No source states
  what a network-entitled sysex may open; `AF_NDRV` was not researched at all.
- If it works, the cost: the sysex process exists only while the transparent-proxy configuration is
  started (inference: NE launches it), which needs the second "Add Proxy Configurations" prompt
  (10 §3.5); a root, always-on raw-injection oracle must authenticate its peer and enforce scope and
  rate inside the sysex (guard placement, 08); Linux is untouched; TUI/web/CLI work only if the app
  already activated the sysex.
- Transport, if chosen: the handoff is a core-owned UDS directory (`/private/tmp/aitmproxy-capture.d/
  {control,data}.sock`, rendezvous file `/private/tmp/aitmproxy-capture.rendezvous`); control carries
  `ControlMessage {Hello, Scope, FlowOpen}` (`listener.rs:125`), each flow gets a data socket opened
  with `DataHandshake {flow_id}`, and the provider verifies the core's code signature before any
  send (`FlowHandoff.swift` header). A frames lane means a new `ControlMessage` variant plus a
  datagram data socket (`write_datagram`/`recv_datagram` exist, `listener.rs:439,461`). Per the NE
  session, an unknown variant makes the core detach the provider, so both sides version together
  (not re-verified by me). XPC is the Apple-recommended control plane (`NEMachServiceName`, 10 §3.7).

### 3.4 macOS option B: privileged daemon via `SMAppService`

**API facts (SDK header `ServiceManagement/SMAppService.h`, macOS 27 SDK, read first-hand):**
macOS 13+; `daemon(plistName:)` needs a plist in `Contents/Library/LaunchDaemons`, optional
`BundleProgram` key; "the LaunchDaemon will not be bootstrapped until an admin approves the
LaunchDaemon in System Settings", then bootstrapped on every boot; status `.requiresApproval`
when the user has not (or has revoked) consent; `register` returns `kSMErrorLaunchDeniedByUser`
if unapproved; "Apps that contain LaunchDaemons must be notarized"; the bundle should live in
`/Applications`; re-register (unregister first) when plist or executable change;
`openSystemSettingsLoginItems()` jumps to the pane; **"Legacy LaunchDaemons installed in
/Library/LaunchDaemons will continue to be bootstrapped without explicit approval"**.
`SMJobBless` is "deprecated in favor of using SMAppService APIs" (`ServiceManagement.h`).
Quinn (708765): for ongoing privileges without an installer, "use `SMAppService`"; the daemon can
restrict XPC clients by code signature (caveat: plug-ins in the client are indistinguishable).

**Entitlements.** The header names none. Disk Drill (installed here) ships an SMAppService daemon
(`Contents/Library/LaunchDaemons/com.cleverfiles.BackService_11.plist`, `BundleProgram`) with no
provisioning profile and only two non-restricted entitlements. So unlike the NE path, **no Apple
approval or A1-style profile is needed** (one product observed; still not an Apple statement).

**Prompt.** One approval in System Settings, Login Items & Extensions; whether an admin
password/Touch ID follows is stated by theevilbit ("prompted for authentication, as installing a
daemon requires root") and by the header ("an admin approves"), not tested on macOS 27 by me. After
approval, re-register needs no further authentication (theevilbit).

**B2: the daemon only fixes permissions (the Wireshark model).** Wireshark's ChmodBPF installs
`/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist` (`RunAtLoad`, runs
`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`), a zsh script that pre-creates
`/dev/bpf0..255` by reading each node (`FORCE_CREATE_BPF_MAX=256`), then `chgrp access_bpf /dev/bpf*`
and `chmod g+rw /dev/bpf*`; the pkg creates group `access_bpf` and adds the installing user (Apple
Community thread 255594684; Homebrew cask `wireshark-chmodbpf` 4.6.9: "added to the access_bpf group
automatically", "must reboot"). libpcap ships a variant with group `admin` (08). Fit here: the existing
`probe()` and `pcap` crate work unchanged; every frontend, including a Homebrew-installed `aitm`, gains
capture once the daemon ran, because permissions are system-wide. Costs: any process of the group can
sniff and inject on any interface (the same exposure Wireshark accepts); Little Snitch's optional ES
extension gates `/dev/bpf` opens like network connections and asks the user (help.obdev.at); the
daemon needs root-side group-membership work for the console user (`dseditgroup`, not researched);
reusing the name `access_bpf` would let it coexist with Wireshark's pkg (inference).

**B1/B3: the daemon does the capture or opens the fd.** B1: the daemon runs libpcap, streams
frames over a UDS or XPC and validates inject requests (scope, rate, size) before writing: the
only variant where the privileged side enforces policy (08, candidate F). B3: the daemon opens
`/dev/bpfN` for an allowed interface and passes the fd (see 3.6). Needs an XPC or UDS protocol with
peer authentication (`peer_auth` exists), a new helper binary and a new core backend.

**Legacy and one-shot routes.** `SMJobBless` still works (Proxyman ships it) but is deprecated and
needs `SMAuthorizedClients`/`SMPrivilegedExecutables` plists. A signed **pkg** (Wireshark route) is
"by far the easiest solution" when privilege is only needed to install (Quinn); one Installer.app
admin prompt; a plain pkg-installed legacy daemon needs no Login Items approval (header sentence
above) though it appears as a background item (an Apple Community thread shows ChmodBPF listed
as an "unidentified developer" item because its script is unsigned). `brew install --cask` of a
pkg runs `sudo installer`, so it prompts in the terminal and fails without a TTY (Homebrew issues
10852, ansible 29403, via search). Quinn lists `osascript ... with administrator privileges` and
`AuthorizationExecuteWithPrivileges` as one-shot options for "an ad hoc solution to a limited
audience" and says not to use the latter in a widely distributed product (`Authorization.h`:
"deprecated and should no longer be used"). Inference: the core could call `osascript` to show
the standard auth dialog and install a legacy daemon, one dialog, no app required; it needs a GUI
login session and was not tested here.

**Homebrew.** Formulae are built and installed "as the owning account"; the formula `service`
block has `require_root` (default false) and only hints at sudo (docs.brew.sh Formula-Cookbook, FAQ).
A formula therefore cannot register a root daemon or change `/dev/bpf*`; only a cask `pkg` can, with a
terminal sudo prompt. (A formula's caveats can only tell the user to do something.)

### 3.5 Linux

- **File capabilities.** Stored in `security.capability`, writing needs `CAP_SETFCAP`; running a
  file with file caps clears the ambient set; `CAP_NET_RAW` = RAW and PACKET sockets; `CAP_NET_ADMIN`
  includes promiscuous mode and firewall admin (capabilities(7), man7). `nosuid` mounts and
  filesystems without xattrs defeat them; replacing the file on upgrade drops them; caps live on the
  real file, not a symlink (rustnet/mping/mtuspy PRs via search; `nosuid` is not in capabilities(7)
  itself). nfpm has no cap field: packages call `setcap` in a postinstall, which receives `configure`
  on deb and `1`/`2` on rpm (mping PR 60); depends `libcap2-bin` (deb) / `libcap` (rpm).
- **Debian/Wireshark.** `wireshark-common.postinst` asks debconf `install-setuid`, creates system
  group `wireshark`, `chown root:wireshark` the `dumpcap` binary, `setcap cap_net_raw,cap_net_admin=eip`,
  falling back to setuid root; execution is limited to the group; default is "no" and the user runs
  `dpkg-reconfigure wireshark-common` and `adduser $USER wireshark` (sources.debian.org postinst;
  search summary for the default and the manual steps). That is the CLI step Matt rejects.
- **polkit/pkexec.** `pkexec` runs a program as root after administrator authentication, shows the
  program path in the dialog, clears the environment, uses the session's polkit agent or a textual
  one; per-program policy via `org.freedesktop.policykit.exec.path`; args are not validated for you;
  exit 126 = dialog dismissed, 127 = failed (pkexec(1)). A `.policy` file in
  `/usr/share/polkit-1/actions` with `allow_active=auth_admin_keep` gives a ~5-minute grant
  (polkit(8)). Headless or SSH-only hosts have no graphical agent; the textual agent prompts on the tty.
- **systemd.** `AmbientCapabilities=` and `CapabilityBoundingSet=` work for system services; for
  per-user managers only with `PrivateUsers=` implied (needs unprivileged userns) (systemd.exec).
  A system service needs root to install and gives a standing privileged daemon.
- **NixOS.** `security.wrappers.<n>.capabilities = "cap_net_raw+ep"` builds a wrapper in
  `/run/wrappers/bin` that raises ambient caps (NixOS option docs). CVE-2026-25740 (captive-browser
  module granting `CAP_NET_RAW` to a program that ran arbitrary commands) is the cautionary tale for
  putting caps on a scriptable tool.
- **Homebrew on Linux** installs under `/home/linuxbrew/.linuxbrew` owned by the managing account:
  no root, so no `setcap`, no polkit policy, no group creation from a formula.
- **Exposure argument for the whole-binary setcap.** `aitm` parses hostile traffic and runs Rhai,
  MCP callers and a browser child; a cap-bearing `aitm` hands `CAP_NET_RAW` (and `CAP_NET_ADMIN` for
  NFQUEUE) to any bug in that surface. File caps are not inherited by non-privileged children
  (inference from the capabilities(7) transformation rules), so obscura would not get them. Wireshark's split exists
  for this reason (dumpcap).

### 3.6 Fd passing and libpcap: possible and impossible

- **libpcap has no "wrap an already-open live device" API.** `pcap_create(source)` takes a device
  name; `pcap_activate` opens it itself (tcpdump.org man pages). The `pcap` crate 2.5 matches: from
  docs.rs, `Capture::from_raw_fd` is `unsafe`, **Offline only** (a savefile), non-Windows; there is
  no `Active` constructor from an fd; `Capture<Active>` implements `AsRawFd` outward. A raw fd for
  a live capture therefore cannot feed the existing `pcap` backend.
- **BPF fd on macOS.** `open` is the privileged act; the ioctls (`BIOCSETIF` etc.) show no privilege
  check in XNU, so an inherited fd can be configured by an unprivileged process with raw ioctls
  (pnet's `bpf.rs` issues those ioctls, 08). `SCM_RIGHTS` should carry it (a BPF node is a plain
  fd) but **no source confirms it for `/dev/bpf` on macOS** and Little Snitch's docs do not say whether
  gating follows the fd. Needs an experiment.
- **AF_PACKET fd on Linux** is likewise an ordinary socket; frame I/O on it needs `nix`/`socket2`,
  not `pcap`.
- **Rust plumbing.** std's `SocketAncillary` is nightly-only (`unix_socket_ancillary_data`, #76915);
  `nix::sys::socket::ControlMessageOwned::ScmRights(Vec<RawFd>)` yields raw fds, so turning them into
  `OwnedFd` is an `unsafe` step: a leaf crate in the `aitm-peer-token` style (inference from the
  precedent).
- **Stream alternative (no fd passing).** A helper that captures and writes a pcap stream (the dumpcap
  and tcpdump `-w -` model); the core reads it with `Capture::from_raw_fd` (unsafe) or by opening
  `/dev/fd/N` through the safe `Capture::from_file` (inference, untested), or a pure-Rust parser
  (not evaluated). Injection needs a reverse channel, validated in the helper.
- **Honest limit.** Passing a raw BPF/AF_PACKET fd moves the *open* but not the *policy*: whoever
  holds the fd can write any frame. Only B1/L-C-style helpers that validate frames are a boundary.

### 3.7 The availability state and one-click actions

Audit finding (12): `l4.capture.status` errors with `L4 unavailable` instead of answering. The state
the UIs need is a read verb that always answers. Fields grounded in the above:

- `state`: `available` | `needs_approval` | `unsupported`; per capability (`capture`, `inject`,
  `intercept`) a state plus `reason` (intercept stays `unsupported` on macOS by design, 09).
- `how` (only when `needs_approval`): `kind` (`app_action`, `os_dialog`, `package`, `pkexec`), a human
  label, and the exact action a frontend may trigger; never a shell command as the only path.
- `helper`: installed / registered / `requires_approval` (the macOS app can read
  `SMAppService.status`; the core cannot, see §7).

| Frontend | macOS action | Linux action |
|---|---|---|
| macOS app | `SMAppService.daemon(...).register()`; on `.requiresApproval` call `openSystemSettingsLoginItems()` | n/a |
| TUI / web / CLI | ask the installed app: `open -b <bundle-id> --args <flag>` (Proxyman precedent, 3.2; flag name is mine); no app: inference, `osascript` admin dialog installing the legacy daemon | core runs `pkexec <helper>` (polkit dialog) |
| Agent over MCP | never: operator-only verb, like `ca.allow_agent_install` (10 §3.5) | never |

## 4. Comparison

| Option | Prompt the user sees | Runs as | Who ships it | TUI/web/CLI | Inject | Effort | Risk |
|---|---|---|---|---|---|---|---|
| A. frames in the NE sysex | sysex approval + Add Proxy Configurations | root (sysextd) | Mac app, NE session | only if app activated it | if bpf open works (unverified) | high: sysex, new lane, in-sysex guard | sandbox/`/dev/bpf` unverified; tied to proxy being on |
| B2. SMAppService chmod daemon | one Login Items approval (+ auth, unverified) | root daemon, core as user | Mac app | **yes**, perms system-wide | yes (via pcap) | low: plist, script, register call, notarize | group-wide sniff/inject; Little Snitch prompts |
| B1/B3. daemon streams or passes fd | same as B2 | root daemon + user core | Mac app | via UDS to daemon (app must be installed) | yes, validated in B1 | high: protocol, helper, new backend, leaf `unsafe` | most code, best boundary |
| Pkg ChmodBPF (Wireshark) | Installer admin password | root at boot | DMG or cask | yes | yes | low | same as B2; cask prompts on tty |
| `osascript` legacy daemon | standard auth dialog | root at boot | `aitm` itself | yes, no app needed | yes | low-medium | needs GUI session, Quinn: ad hoc only |
| SMJobBless | auth + Login Items | root | Mac app | via app | yes | medium | deprecated |
| L-A. `setcap` on `aitm` | none after install (package) | user + caps | deb/rpm postinst, nixos wrapper | yes | yes | low | whole product holds caps; lost on upgrade; no Homebrew |
| L-B. cap helper, group-gated | add user to group (the CLI step) | user + caps on helper | deb/rpm | yes | yes | medium | group step; cap helper is an oracle |
| L-C. pkexec + polkit helper | one polkit dialog | root helper on demand | deb/rpm (policy + helper) | yes (GUI agent or tty agent) | yes | medium | arg validation, headless hosts |
| L-D. systemd service ambient caps | none after install | root-installed service | deb/rpm | yes via socket | yes | medium-high | standing daemon |

## 5. Candidate directions (not decisions)

1. **One small privileged helper, two launchers (08 candidate F).** A Rust `aitm-l4-helper` (leaf
   `unsafe` crate for fd/ioctl) speaks a framed UDS protocol with peer authentication and enforces
   scope, rate and size at the lowest write. Launcher: launchd daemon on macOS (B1/B3), pkexec on Linux
   (L-C). Best boundary, one protocol, most work, and a new core backend beside `pcap`.
2. **Permission-fix first (B2 on macOS, setcap helper or L-C on Linux).** Smallest change, keeps
   `pcap` and `probe()`. Weaker boundary on macOS (group-wide). Can later be replaced by 1.
3. **Frames in the sysex (A).** Only if an experiment proves the open works; otherwise rejected by
   evidence. Couples capture to the proxy toggle.
4. **Installer-only (pkg / package postinst).** Works for the DMG and deb/rpm; leaves Homebrew
   formulas, nix and tarball users with a CLI step, so it cannot be the only path.

## 6. Recommendation (candidate, for the Architect)

- **macOS default: B2, registered by the app via `SMAppService.daemon`** (daemon plist and a small
  root script/binary in the bundle; group `access_bpf` to coexist with Wireshark, or `admin` as
  libpcap does; pre-create 256 nodes; re-apply at boot). One approval, no Apple entitlement, every
  frontend benefits, `probe()` unchanged. Ship it with a CLI-only path: `open -b ... --args <flag>`, and consider the `osascript` legacy-daemon fallback for hosts without the app.
  Keep A out of Phase 1 unless a spike (`experiment/`) shows a network-entitled sysex can open
  `/dev/bpf*`; name the **NE session ("Ship macOS NE in DMG + app enable/disable toggle")** as the
  owner of any sysex change, since a frames lane touches `listener.rs` and `FlowHandoff.swift`
  together.
- **Linux default: L-C**, a small helper plus a `.policy` shipped in the deb/rpm, launched with
  `pkexec`, rather than caps on `aitm`; document `setcap` on the helper (not `aitm`) as the headless
  fallback and a NixOS `security.wrappers` snippet. Packages must re-apply caps on upgrade if L-B is used.
- **Direction to plan for: candidate 1**, so macOS B1/B3 and Linux L-C converge on one helper.
- **Core:** add the always-answering `l4.privilege` read verb (3.7) and an operator-only
  `l4.privilege.request`; change `probe()` consumers to state `needs_approval{how}` instead of a
  hand-typed command. All frontends show one "Allow packet capture" action.

## 7. Open questions

1. Does a network-entitled, unsandboxed Developer ID sysex succeed at `open("/dev/bpf0")`, and at
   `socket(AF_NDRV)`? (spike needed; Quinn's 2020 "must be sandboxed" vs shipping products.)
2. Does `SCM_RIGHTS` of a `/dev/bpfN` fd work on macOS 27, and does Little Snitch gate the fd or the open?
3. Exact SMAppService daemon prompt on macOS 27: toggle only, or toggle plus admin credentials?
   Is a daemon in `~/Applications` refused (header recommends `/Applications`)? (`build.sh` installs to
   `~/Applications` today, 10 open question 1.)
4. Can the Rust core read `SMAppService` status? It belongs to the app bundle; the core likely cannot,
   so `l4.privilege` on a standalone core can only infer from the failed open. Who relays it?
5. Group membership: how does the root daemon learn the console user safely (XPC audit token) and
   add them to the group? macOS 27 behaviour for `dseditgroup` not checked.
6. Does the `osascript ... with administrator privileges` dialog work from a non-GUI-parented
   process (launchd, tmux, SSH)? Not tested.
7. 08's open question on macOS 26/27 BPF write to `lo0` still applies to B2: permission fixes do
   not change what the kernel accepts.
8. Linux: `CAP_NET_ADMIN` rationale for promiscuous mode is in capabilities(7); is `CAP_NET_RAW`
   alone enough for the `pcap` crate to open and inject? (08 left this unverified.)
9. Debian's debconf default for `install-setuid` was only confirmed through a search summary.

## 8. Sources

Read 2026-10-31 unless noted. Local: macOS 27 SDK `ServiceManagement/{SMAppService,ServiceManagement}.h`,
`Security/{Authorization,AuthorizationTags}.h`; `/Applications/Proxyman.app` (Info.plist,
SystemExtensions, entitlements), `/Applications/Little Snitch.app` and
`/Library/LaunchDaemons/at.obdev.littlesnitch.daemon.plist`, `/Applications/Disk Drill.app`; repo files
named above.

- Apple Forums: BSD Privilege Escalation on macOS https://developer.apple.com/forums/thread/708765;
  pcap_open_live /dev/bpf0 sandbox https://developer.apple.com/forums/thread/128528; NE restrictive
  sandbox https://developer.apple.com/forums/thread/133761; sandbox for NE/ES
  https://developer.apple.com/forums/thread/132641; privileged helper
  https://developer.apple.com/forums/thread/739940
- XNU `bsd/net/bpf.c` https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.c
- theevilbit, SMAppService https://theevilbit.github.io/posts/smappservice/
- Wireshark: macOS install https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallOSXInstall.html;
  ChmodBPF files https://discussions.apple.com/thread/255594684; cask
  https://formulae.brew.sh/cask/wireshark-chmodbpf and
  https://raw.githubusercontent.com/Homebrew/homebrew-cask/master/Casks/w/wireshark-chmodbpf.rb
- Proxyman: https://proxyman.com/docs/basic-features/proxy-setting-tool;
  https://github.com/ProxymanApp/Proxyman/issues/1767; Charles helper via
  https://docs.delinea.com/online-help/privilege-manager/computer-groups/policies/platform-specific/macos/examples/elevate-charles-proxy.htm
- Little Snitch BPF https://help.obdev.at/littlesnitch6/adv-bpf
- Homebrew: https://docs.brew.sh/Formula-Cookbook, https://docs.brew.sh/Cask-Cookbook,
  https://docs.brew.sh/FAQ, https://docs.brew.sh/Homebrew-on-Linux;
  https://github.com/Homebrew/homebrew-cask/issues/10852; https://github.com/ansible/ansible/issues/29403
- Linux: https://man7.org/linux/man-pages/man7/capabilities.7.html;
  https://man7.org/linux/man-pages/man7/unix.7.html;
  https://sources.debian.org/src/wireshark/latest/debian/wireshark-common.postinst/;
  https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html;
  https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html;
  https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html;
  https://mynixos.com/nixpkgs/option/security.wrappers;
  CVE-2026-25740 https://discourse.nixos.org/t/security-advisory-privilege-escalation-to-the-cap-net-raw-capability-via-the-programs-captive-browser-nixos-module-cve-2026-25740/75162;
  nfpm/setcap PRs https://github.com/servak/mping/pull/60, https://github.com/oetiker/mtuspy/pull/9,
  https://github.com/domcyrus/rustnet/blob/main/INSTALL.md
- libpcap/Rust: https://www.tcpdump.org/manpages/pcap_create.3pcap.html;
  https://docs.rs/pcap/latest/pcap/struct.Capture.html;
  https://docs.rs/nix/latest/nix/sys/socket/enum.ControlMessageOwned.html;
  https://doc.rust-lang.org/std/os/unix/net/struct.SocketAncillary.html
