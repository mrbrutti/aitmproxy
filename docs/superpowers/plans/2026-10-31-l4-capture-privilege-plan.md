# L4 capture privilege implementation plan

**Status:** Approved (Matt, 2026-11-01, defaults for the spec's forks); tasks P7.1 and the AC5 `all`-case half of P1b.17 blocked on Question 2; spikes first. S7 proven (PR #240, 2026-11-01): P1b.12–14 and P2.6–P2.8 unblocked; amendments folded (rows marked "(S7)"; write-up `docs/research/experiments/2026-11-01-l4-s7-pkexec-helper.md`, spec §5.7).
**Spec:** `docs/superpowers/specs/2026-10-31-l4-capture-privilege-design.md` (approved 2026-11-01, forks i–v on the
recommended defaults; acceptance criteria L4PRIV-AC1 … L4PRIV-AC29). Still open: Matt's written acceptance of the
headless `setcap` doc (spec open question; blocks Task P5.4 only).
**Research:** `docs/research/13-l4-capture-privilege-without-cli.md`, `docs/research/12-l4-parity-audit.md`
**Builds on (on `main`):** parity unit (a) (#215: `AvailabilitySource`, `L4Availability`, `UnavailableCode`,
`L4Gated` in `crates/aitm-proto-l4/src/module.rs`), unit (e) docs (#216), system-proxy PR 1 (#214, touched
`is_operator_only`).
**Branches / worktrees:** one per unit, each cut from `origin/main` at the time its "Cut after" condition holds, each
its own PR against `main`. Worktrees are created by the orchestrator in the Terminal.

| Unit | Branch | Worktree | Cut after | Tasks |
|---|---|---|---|---|
| (p1a) shared contracts | `feat/l4priv-contracts` | `.claude/worktrees/l4priv-contracts` | now | P1a.1–P1a.4 |
| (p1b) core | `feat/l4priv-core` | `.claude/worktrees/l4priv-core` | p1a merged and parity (a') merged | P1b.1–P1b.18 |
| (p2) helper crate | `feat/l4priv-helper` | `.claude/worktrees/l4priv-helper` | p1a merged | P2.1–P2.9 |
| (p3) macOS app | `feat/l4priv-mac` | `.claude/worktrees/l4priv-mac` | parity (d) merged; S3, S5 written up | P3.1–P3.13 |
| (p4) release pipeline | `feat/l4priv-release` | `.claude/worktrees/l4priv-release` | S3 written up; orchestrator's go on §4 layout | P4.1–P4.7 |
| (p5) Linux packaging | `feat/l4priv-linux-pkg` | `.claude/worktrees/l4priv-linux-pkg` | p2 merged | P5.1–P5.4 |
| (p6) TUI, web, CLI | `feat/l4priv-frontends` | `.claude/worktrees/l4priv-frontends` | p1b merged; parity (b) and (c) merged | P6.1–P6.10 |
| (p7) `aitm-mcp` exception | `fix/l4priv-mcp-operator-only` | `.claude/worktrees/l4priv-mcp` | now (rebase on `main`: system-proxy PR 1 edited the same function) | P7.1 |

## Overview

Phase 0 is five experiment sessions (S3, S4, S5, S7, S8). None of their code is ever merged. Each one answers a spec
question that a Phase 1 task depends on. Phase 1 is eight PRs. Their files do not overlap at any moment two of them
are open.

**Two changes from the brief, both forced by the gate (Architect's calls):**

1. **p1 lands as two PRs.** The helper crate (p2) links `aitm-proto-l4` for the receipt schema, the helper wire
   protocol, the frame parser and the guard checks. It cannot depend on code that is still sitting on an unmerged
   core branch, and a second copy of those types in the helper would drift. So (p1a) puts those shared contracts on
   `main` first. Then (p1b), the core, and (p2), the helper, fan out in parallel.
2. **The tool-contract pins move with p1b, not p7.** `EXPECTED_TOOLS` (`crates/aitm/tests/frontends.rs`) and
   `CORE_TOOLS` (`crates/aitm-tui/src/lib.rs`) are exact-set tests over the live `tools/list`; `tui_live_bus.rs`
   compares `CORE_TOOLS` to it. (Panel, 2026-11-01: two contracts, not three; `bus-fixture.json` and
   `tester_shell.rs` were deleted on `main` by #244, the TUI is live-only.) The PR that registers the two verbs
   (p1b) is red without them, and a PR that bumps them before the verbs exist (p7) is red the other way. p7 keeps
   only the `is_operator_only` entry and its test. That entry is a name match and is safe to merge before or after
   p1b.

Dependency graph (an arrow means "is cut or started after"):

```
S3 ──► p4 (plists, notarize) ──► p3 live [mac-signed]
S3, S5 ──► p3 ;  S5 ──► P1b.11 ;  S7 ──► P1b.12–14, P2.6–P2.8 ;  S4 ──► P2.2–P2.4 ;  S8 ──► AC8 W3–W4 on macOS
p1a ──► p1b, p2 ;  p2 ──► p4 P4.3/P4.4, p5 ;  p1b ──► p6, every live check ;  parity (b),(c) ──► p6 ;  parity (d) ──► p3
p7: independent, any time
```

**Inside a unit, tasks are sequential** in the order listed, unless a task says "independent". Each task gets one
fresh Coder, is test-first, and ends in one commit. The independent sets are listed at the end.

### Rules every task obeys (Matt's; repeat them in every Coder report)

1. **No fixture, snapshot, self-test or seeded-store evidence.** This covers macOS `Fixtures+*.swift`,
   `tools/snap.sh` / `snap-dev.sh` images, `selftest.sh` with `APP_FIXTURES`, the web mock bus (`?bus=mock`,
   `bus/mock.ts`), TUI `--fixture` / `fixture.rs` / `fixture_app`, and `bus-fixture.json`. Evidence is exactly one
   of three things:
   1. a Rust, Kit or vitest unit test of pure logic whose input is built inside the test;
   2. a source tripwire;
   3. the real frontend driving a real core on the rig with real traffic, or an honest `blocked: <reason>` line
      quoting the core's reply.

   The contract pins and the stubbed `notarize-dmg.sh` run are tripwires, never proof that a feature works.
   `snap-dev.sh` is used only to build the dev bundle.
2. **Never ask the operator to type a command.** No reply, label, toast, log line or doc string in the product tells
   anyone to run `sudo`, `setcap`, `chmod`, `chgrp`, `chown`, `dseditgroup`, `launchctl` or `pkexec`. Tripwires
   P1b.3, P3.7 and P6.4 enforce it. An observer reading state in the Terminal during a live check is fine.
3. **The product triggers the OS prompt.** macOS shows the Login Items & Extensions approval (SMAppService). Linux
   shows the polkit dialog (pkexec). Nothing in this plan uses `osascript … with administrator privileges`, `sudo`,
   SMJobBless or a legacy `/Library/LaunchDaemons` plist.
4. **Helper and extension bundle-layout changes go to the orchestrator (release driver) before implementation.**
   This covers p4 entirely, plus `apps/mac/Info.plist.in` (P3.9). The Coder sends the task's Files list and the
   exact paths, keys and sign order. The Coder waits for the orchestrator's go before the first edit.
5. **The spike rule (HARD RULE, verbatim from the spec's Constraints):** Any spike that changes system state on
   Matt's Mac (chmod `/dev/bpf*`, group creation or membership, installing a LaunchDaemon, Login Items prompts) is
   announced to the orchestrator before it runs, with its exact revert steps; it runs only on the orchestrator's go
   after Matt has been told, and is reverted in the same session. Spikes that can run in a VM run there.
6. **The live checks tagged [mac-signed] change machine state.** They install a LaunchDaemon, change `/dev/bpf*`,
   change group membership, and raise a Login Items prompt. They follow the same rule: announce with the revert
   steps (Remove Packet Capture…, then the AC14 read-back), run only on the orchestrator's go after Matt says yes
   (silence is not go), and revert in the same session.
7. **Zero `aitm-core` edits.** Every unit's Done-when includes this check:
   `git diff --stat origin/main...HEAD -- crates/aitm-core` prints nothing.
8. **`unsafe_code = "forbid"` holds.** `grep -rn "unsafe" crates/aitm-l4-helper/src crates/aitm-proto-l4/src`
   must find no new hits. If fd passing ever proves necessary (it is not in Phase 1), it goes in a leaf crate with a
   `// SAFETY:` comment and a Security-reviewer sign-off. That would be a stop-and-report, not a Coder decision.
9. **Never print a bus token.** Tokens are read from 0600 files into variables. Core logs carry the Operator URL
   and are deleted after their output is quoted. Run `umask 077` first in every rig script.
10. **Stop on gaps.** A Coder who needs a file outside the task's Files list, or who finds the spec or this plan
    wrong, stops and reports.
11. **Nobody merges.** No Coder, Tester or reviewer merges or closes a PR. Every PR number goes to the orchestrator
    as soon as it exists.

### Known traps

- The sandbox cannot bind ports, reach GitHub, run SwiftPM, run `open`, or fetch new crates. Those run in the
  **Terminal panel**: `aitm web`, the targets, the TUI against the bus, the mac bundle, `npm ci`, `git push`, `gh`,
  and `cargo fetch` for a new dependency. Push with an explicit refspec (`git push origin <branch>`).
- New crates: the Linux helper needs a capability crate (`caps`, not in `Cargo.lock`). The macOS helper's unified
  log needs `oslog` (not in `Cargo.lock`). `nix` 0.31 is already locked. A Coder who adds a crate runs `cargo fetch`
  once in the Terminal, then works offline. Every new dependency is named in the PR body for the security reviewer.
- Stale shared `target/`: `touch` the crate's `src/lib.rs` or `src/main.rs` before every gate. Gate on the exit
  status written to a log (`…; echo EXIT=$?`), never on a grep of the output.
- `tui_live_bus` binds a port, so the full `cargo test` must run once per unit in the Terminal. Sandbox green is not
  CI green.
- Never `./build.sh` in `apps/mac` for development. Use `DEV_TAG=<tag> apps/mac/tools/snap-dev.sh`. `build.sh --ne`
  is the release driver's, in the Terminal.
- Never kill a process you did not start, and never `pkill -f` by name. The shared Swift scratch path
  (`~/Library/Developer/Aitmproxy/test-build`) allows one `swift test` at a time.

### The rigs

**Privilege rig (spec AC section), Mac [mac-any].**
- Location: `/tmp/claude/l4priv-rig/`, modelled on the parity rig.
- Config `config.yaml` (mode 600): proxy 28180, browser 28181, bus 27431, web 28182, `l4.enabled: true`.
- Config scope: `lo0`, `127.0.0.1/32`, ports `9000-9999`, one entry each for capture, inject and intercept. No
  `l4.intercept` block.
- Targets: `python3 -m http.server 9099 --bind 127.0.0.1` and a UDP echo on 127.0.0.1:9053 (`udpecho.py`).
- Start: `sleep 86400 | AITM_CONFIG=… <worktree>/target/release/aitm web --listen 127.0.0.1:28182`.
- Drivers: `tests/e2e/aitm_e2e/bus.py` (operator and agent tokens from `op.token` / `agent.token`), the TUI in a pty
  (160×44), the web UI in a real browser at the Operator URL (never copied into a report), and the mac app attached
  to the rig as its external core.
- This Mac is unprivileged: `/dev/bpf*` is `crw------- root wheel`.

**Signed Mac [mac-signed].**
- The Developer-ID-signed, notarized DMG from P4.7 installed in `/Applications/Aitmproxy.app` on Matt's Mac.
- Driven by the CUA recipe (`apps/mac/tools/cua-packet-capture.sh`, P3.13) and real clicks.
- State is read in the Terminal: `stat -f '%Sp %Su %Sg' /dev/bpf0`, `dscl . -read /Groups/access_bpf
  GroupMembership`, `cat "/Library/Application Support/Aitmproxy/l4-helper.json"`, and `launchctl print
  system/com.mrbrutti.aitmproxy.l4-helper` (read-only).
- Only under Rule 6.

**Linux rig [linux-ci].** **(Architect's call:** "Linux CI" in this plan means the systemd container on the Lima VM
`cis-lab`, driven from the Terminal; adding a GitHub Actions job is left to the orchestrator as a follow-up, so no
task here edits `.github/workflows/`.)
- (S7) `cis-lab` has **no container runtime** (no `nerdctl`, `docker` or `podman`). The rig script
  (`linux-privilege-rig.sh`, P2.8) installs `podman` from Ubuntu's apt inside the VM, or the orchestrator keeps one
  installed; the S7 spike purged it at revert.
- Fedora 42 and Debian trixie systemd containers in `cis-lab`, run rootful as `podman run -d --systemd=always
  --privileged` (S7: `polkitd`'s unit needs `CAP_SYS_ADMIN`; unprivileged it fails `status=217/USER` and every
  `pkexec` dies after 25 s with `Error getting authority … Timeout was reached`, exit 127). Packages: Debian
  `systemd dbus polkitd pkexec`; Fedora `systemd dbus-broker polkit` (plus `libpcap` at run time).
- User `tester` with a password, in the admin group (`wheel` / `sudo`). No graphical agent.
- (S7) On the Ubuntu 24.04 host (`cis-lab`), unload the `unix-chkpwd` AppArmor profile (`apparmor_parser -R
  /etc/apparmor.d/unix-chkpwd`) before Fedora's PAM can authenticate inside a container, and reload it (`-r`) when
  the rig comes down. Debian is unaffected.
- The core is built inside the VM.
- Scope: `lo`, `127.0.0.1/32`, `9000-9999`. Same targets.
- For AC16 only, a test-only rule `/etc/polkit-1/rules.d/49-aitm-test.rules` returns `polkit.Result.YES` for
  `tester` on `com.mrbrutti.aitmproxy.l4-helper.run` (S7: confirmed, the helper connects with no prompt at once). It
  is removed for AC22 and AC21. `pkaction --verbose --action-id com.mrbrutti.aitmproxy.l4-helper.run` checks the
  policy was read as written.

**Linux desktop [linux-desk].** A GNOME VM in Lima (or UTM), by hand, with the `.deb` from P5.3 installed. Used for
AC21 only.

### Gates (before any panel review of a unit)

| Unit | Gate (each must exit 0; output quoted) |
|---|---|
| p1a, p1b, p2, p7 | sandbox: `cargo fmt --check && cargo clippy --all-targets --offline -- -D warnings && cargo test --offline`; once per unit the same in the Terminal (for `tui_live_bus`) |
| p1b (Panel 3, 2026-11-01) | the row above, plus `cargo test --offline -p aitm --bin aitm` in the per-stage (per-package) gate: the `main.rs` tests `tui_shutdown_arm_consults_the_prompt_hold` and `the_prompt_hold_handed_to_the_shutdown_arms_is_the_states` live in the binary target, and `cargo test -p aitm --lib` skips them. The full workspace `cargo test --offline` above already covers the binary target; only the `-p aitm --lib` shortcut misses it. |
| p3 | Terminal: `DEV_TAG=l4priv apps/mac/tools/snap-dev.sh` (prints `Build complete`), `cd apps/mac && swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`, `apps/mac/tools/check-packet-capture-ui.sh`, `apps/mac/tools/check-connection-words.sh`, `apps/mac/tools/grid-lint.sh` (P3.8, P3.10 change layout) |
| p4 | `scripts/tests/run-notarize-dmg-stubbed.sh`, `apps/mac/tools/check-packet-helper.sh`, `shellcheck` on every changed script, plus the Rust gate if `package.sh` changed |
| p5 | `scripts/tests/check-linux-packaging.sh`, `shellcheck scripts/package-linux.sh`, the Rust gate |
| p6 | the Rust gate (sandbox and Terminal), and `cd apps/web && npm run typecheck && npm test && npm run build` (Terminal, after `npm ci`) |

---

## Claims (files per unit, for the orchestrator to register)

A file in two units is never open in both at once. The "after" column says why.

| Unit | Creates | Modifies |
|---|---|---|
| p1a | `crates/aitm-proto-l4/src/privilege/{mod,contract}.rs`, `crates/aitm-proto-l4/src/helper/{mod,proto,frame,enforce}.rs` | `crates/aitm-proto-l4/src/lib.rs`, `crates/aitm-proto-l4/Cargo.toml` (none expected) |
| p1b | `crates/aitm-proto-l4/src/privilege/{report,derive,availability,state,macos,linux}.rs`, `crates/aitm-proto-l4/src/commands/privilege.rs`, `crates/aitm-proto-l4/src/helper/client.rs`, `crates/aitm-proto-l4/src/backend/{helper,routed}.rs`, `crates/aitm-proto-l4/tests/privilege.rs`, `tests/e2e/l4/test_privilege_core.py` | `crates/aitm-proto-l4/src/{lib,module,config,guard,language}.rs`, `crates/aitm-proto-l4/src/privilege/mod.rs`, `crates/aitm-proto-l4/src/helper/mod.rs`, `crates/aitm-proto-l4/src/backend/mod.rs`, `crates/aitm-proto-l4/src/commands/{mod,capture,intercept}.rs`, `crates/aitm-proto-l4/Cargo.toml` (`tracing`, Linux `nix`), `crates/aitm/src/{wire,main}.rs` (after unit (a), merged), `crates/aitm/tests/frontends.rs`, `crates/aitm-tui/src/lib.rs` (`CORE_TOOLS` only; panel 2026-11-01: `bus-fixture.json` and `tester_shell.rs` dropped, deleted by #244), `Cargo.lock` (panel 2026-11-01: the derived line for the `Cargo.toml` change only; p2 owns the lock for the new crate), `crates/aitm/src/lib.rs` (panel 2026-11-01: `shutdown_signal` consults the prompt hold, P1b.14), `crates/aitm/src/tui.rs` (Panel 3, 2026-11-01: the `aitm tui` shutdown arm consults the hold, P1b.14; granted from P6.3), `crates/aitm/tests/l4_cua_tui.rs` (Panel 3, 2026-11-01: the AC27 branch and the bounded wait, P1b.16/P1b.17), `tests/e2e/l4/{test_l4_parity_core,test_l4_parity_priv}.py`, `docs/research/mcp-tool-catalog.txt`, `aitmproxy-plugin/docs/tool-reference.md`, `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md` |
| p2 | `crates/aitm-l4-helper/{Cargo.toml,src/main.rs,src/cli.rs,src/bpf.rs,src/bpf_exec.rs,src/log.rs,src/probe.rs,src/serve.rs,src/serve_loop.rs}`, `tests/e2e/l4/test_privilege_helper_linux.py`, `tests/e2e/l4/linux-privilege-rig.sh` | root `Cargo.toml` (`members`, workspace dep), `Cargo.lock` |
| p3 | `apps/mac/Sources/AitmproxyKit/{PacketCapture,L4Capture}.swift`, `apps/mac/Tests/AitmproxyKitTests/{PacketCaptureTests,L4CaptureTests}.swift`, `apps/mac/Sources/Aitmproxy/Privilege/PacketCaptureHelper.swift`, `apps/mac/Sources/Aitmproxy/Panels/{PacketCaptureCard,L4CaptureControls}.swift`, `apps/mac/tools/check-packet-capture-ui.sh`, `apps/mac/tools/cua-packet-capture.sh` | `apps/mac/Info.plist.in` (orchestrator first), `apps/mac/Sources/AitmproxyKit/{ConnectionSummary,EmbeddedCoreLaunch}.swift`, `apps/mac/Tests/AitmproxyKitTests/{ConnectionSummaryTests,EmbeddedCoreLaunchTests}.swift`, `apps/mac/Sources/Aitmproxy/{App,SettingsView,Session}.swift`, `apps/mac/Sources/Aitmproxy/Panels/{StatusPanel,ScopePanel}.swift`, `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (L4 empty state), `apps/mac/tools/check-connection-words.sh` (after parity (d)) |
| p4 | `apps/mac/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist`, `apps/mac/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper-revert.plist`, `apps/mac/tools/check-packet-helper.sh` | `scripts/notarize-dmg.sh`, `scripts/tests/run-notarize-dmg-stubbed.sh`, `scripts/package.sh`, `apps/mac/build.sh`, `docs/RELEASE.md`; the tap repo `mrbrutti/homebrew-aitmproxy` `Casks/aitmproxy.rb` (orchestrator executes) |
| p5 | `scripts/packaging/com.mrbrutti.aitmproxy.l4-helper.policy`, `scripts/tests/check-linux-packaging.sh`, `docs/packet-capture.md` (P5.4, blocked on the open question) | `scripts/nfpm.yaml`, `scripts/package-linux.sh` |
| p6 | `crates/aitm-tui/tests/l4_privilege.rs`, `apps/web/src/panels/l4/{privilege.ts,privilege.test.ts,L4PrivilegeBanner.tsx}`, `apps/web/scripts/cua-l4-privilege.mjs`, `tests/e2e/l4/test_privilege_tui.py` | `crates/aitm-tui/src/{l4,app,keys,action,bus,lib}.rs`, `crates/aitm-tui/src/ui/l4.rs`, `crates/aitm/src/tui.rs` (in-process flag only), `apps/web/src/panels/l4/{store.ts,CaptureControls.tsx,PacketList.tsx}`, the L4 page component that hosts the banner (parity (c)'s; named by the Coder from the merged tree) |
| p7 | — | `crates/aitm-mcp/src/server.rs` (`is_operator_only` and one test only) |

Overlaps, all sequential: `crates/aitm-tui/src/lib.rs` is touched by p1b (`CORE_TOOLS`) and then by p6 (cut after p1b
merges). `crates/aitm-proto-l4/src/{lib.rs, privilege/mod.rs, helper/mod.rs}` are touched by p1a and then by p1b (cut
after p1a merges). `crates/aitm/src/{wire,main,tui}.rs` were touched by parity unit (a), which is merged.
`crates/aitm-proto-l4/src/guard.rs`, `crates/aitm-proto-l4/src/commands/mod.rs`,
`tests/e2e/l4/test_l4_parity_core.py`, `aitmproxy-plugin/docs/tool-reference.md` and
`aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md` are touched by parity (a') and then by p1b, which is why p1b
is cut only after (a') merges. `crates/aitm-mcp/src/server.rs` was touched by system-proxy PR 1, which is merged: p7
is cut from current `main`.

---

## Phase 0: spikes (experiment sessions)

Each spike is a separate session with its own worktree on its `experiment/<topic>` branch. It builds the spike itself
and writes `docs/research/experiments/2026-11-0X-<topic>.md` from the experiment template. Nothing from a spike
branch is reused as code. The **spike rule** (Rule 5, verbatim above) governs every spike: **any spike that changes
system state on Matt's Mac (chmod /dev/bpf*, group creation or membership, installing a LaunchDaemon, Login Items
prompts) is announced to the orchestrator BEFORE it runs with its exact revert steps, runs only on its go after Matt
has been told, and is reverted in the same session; spikes that can run in a VM run there.**

**Where (Architect's call):** S7 runs in the Lima VM `cis-lab`. S3, S4 and S8 run in a macOS 27 guest VM if one is
available (question 1 at the end), using `sudo` freely inside the VM. They fall back to Matt's Mac only if there is
none. In that fallback, S4 and S8 run inside S3's session window, against S3's own spike daemon. This means one
announcement, one approval window and one revert, and never a typed `sudo` on Matt's Mac. Each spike still has its
own branch and write-up. S5 can run anywhere. It touches only LaunchServices registration, which is not in the rule's
list, and it is announced anyway.

### S3: SMAppService prompt shape and launch-constraint substitution test

- **Branch:** `experiment/l4priv-s3-smappservice`. **Blocks:** p3 (card words, register/re-register/Remove flow), p4
  (P4.1 `SpawnConstraint` shape), AC6, AC13, AC14, AC28.
- **Question:** On macOS 27:
  1. What does `SMAppService.daemon(plistName:).register()` show: a Login Items toggle only, or a toggle plus admin
     auth?
  2. Does re-registering after an update (version bump) re-prompt?
  3. Does registering a second (revert) daemon from an already-approved app prompt?
  4. Is a bundle in `~/Applications` refused, and with what error?
  5. Does `AssociatedBundleIdentifiers` make Login Items show the app's name and icon?
  6. Which `SpawnConstraint` dictionary shape (team `995PCLM9KH` + signing identifier) does launchd accept?
  7. Does launchd refuse to run a substituted helper? Try both an ad hoc binary and a same-team Developer ID binary
     with a different identifier. Record the `com.apple.xpc.launchd` log line, and confirm the receipt's mtime does
     not change.
- **Setup:**
  - Bundle: `AitmSpikeL4.app`, bundle id `com.mrbrutti.aitmproxy.spike-l4`. Signed Developer ID, hardened runtime,
    timestamp. Notarized through the release driver (ASC key per `docs/research/MEMORY.md`).
  - Helper: `Contents/MacOS/spike-helper`, a tiny Mach-O with fixed argv modes `apply` and `revert`.
    - `apply`: chown `root:access_bpf` + chmod 0660 every `/dev/bpfN`; create `access_bpf` if absent, recording that
      it did; add the console admin user; write `/Library/Application Support/AitmSpikeL4/receipt.json`.
    - `revert`: the inverse, including deleting the group if the receipt says the spike created it.
  - Plists: `Contents/Library/LaunchDaemons/com.mrbrutti.aitmproxy.spike-l4-helper{,-revert}.plist`, one variant per
    `SpawnConstraint` shape tried.
  - App UI: buttons Register, Register revert, Unregister all, Status.
- **Revert steps (exact, same session):**
  1. In the spike app, click **Register revert**. Wait until `/Library/Application Support/AitmSpikeL4/receipt.json`
     is gone, at most 30 s. If the substitution test left a foreign binary in the bundle, first restore the original
     signed `spike-helper` from the notarized DMG.
  2. Verify `stat -f '%Sp %Su %Sg' /dev/bpf0` and the same for the highest `/dev/bpfN` both print
     `crw------- root wheel`.
  3. Verify `dscl . -read /Groups/access_bpf` reports `eDSRecordNotFound` if the spike created the group. Otherwise
     its `GroupMembership` no longer lists the user the spike added.
  4. Click **Unregister all**, which unregisters both services. Verify `launchctl print
     system/com.mrbrutti.aitmproxy.spike-l4-helper` and `…-revert` both exit non-zero (read-only).
  5. Screenshot System Settings ▸ General ▸ Login Items & Extensions to show no AitmSpikeL4 entry. Never run
     `sfltool resetbtm`.
  6. `lsregister -u /Applications/AitmSpikeL4.app`, then delete the bundle (user-owned). Verify
     `ls "/Library/Application Support/AitmSpikeL4"` reports no such file.
  7. Put a before/after table of steps 2–6 in the write-up.
- **Output the plan needs:** the accepted `SpawnConstraint` XML (copied into P4.1), the exact prompt sequence (into
  P3.8's words), and whether re-register re-prompts (into P3.6 and AC13). If launchd rejects every shape, or runs a
  substituted helper, **Phase 1 macOS stops** (spec hard requirement). Only p1a, p1b, p2's Linux half, p5, p6 and p7
  continue.

### S4: group membership without re-login

- **Branch:** `experiment/l4priv-s4-group-relogin`. **Blocks:** P2.2–P2.4 (the fork (ii) default), P3.8's "log out
  and back in" line, AC7.
- **Question:** After `dseditgroup` adds the console user to `access_bpf`, three processes try to open a
  `0660 root:access_bpf` `/dev/bpf0` read+write. Which of them succeed without a re-login?
  1. a process that was already running;
  2. a process spawned afterwards from a pre-existing login session (Terminal opened before the change);
  3. a process in a new login session.
- **Setup:** a probe binary run as the user. It loops `open("/dev/bpf0", O_RDWR)` once a second for 120 s and logs
  each result with a timestamp.
  - VM: as root, `dseditgroup -o create access_bpf`, chgrp/chmod the nodes, start the probe, then
    `dseditgroup -o edit -a <user> -t user access_bpf`.
  - Mac fallback: start the probe, then let S3's spike `apply` daemon make the change after Matt approves it in
    System Settings.
- **Revert steps:**
  - VM: discard the VM snapshot taken before the spike.
  - Mac fallback: S3's revert steps 1–7, in the same session. Also stop the probe by its PID.
- **Output:** a three-row table: already-running / new process in an old session / new session. If case 1 or 2 needs
  a re-login, the orchestrator takes "switch to `admin`" back to Matt before P2.2 starts (spec fork ii).

### S5: URL handoff delivery

- **Branch:** `experiment/l4priv-s5-url-handoff`. **Blocks:** P1b.11 (the handoff and its "no GUI" detection), P3.9
  (URL handler and launch-by-URL), AC9, AC10.
- **Question:**
  1. Does `/usr/bin/open -a /Applications/<App>.app <scheme>://packet-capture/allow` deliver the URL both when the
     app is running and when it is not?
  2. When launched by the URL, can the app tell, before `applicationDidFinishLaunching`, that it was launched by a
     URL (`kAEGetURL` as the launch event)?
  3. Does `open -a … --args x` drop the arguments for a running app?
  4. With two copies sharing one bundle id (one in `/Applications`, one in `/tmp`), which does `open -b <id>` pick?
  5. In an SSH session: what does `open` exit with, and what does `/bin/launchctl managername` print? Compare with a
     GUI Terminal, where `Aqua` is expected.
  6. Does a browser page setting `location = '<scheme>://packet-capture/allow'` deliver the URL, and what does the
     browser show first?
- **Setup:** an ad-hoc-signed `AitmSpikeURL.app`, bundle id `com.mrbrutti.aitmspike.url`, scheme `aitmspike` (never
  `aitmproxy`, so the installed app is not disturbed). It logs argv, every URL and the launch event class to
  `~/Library/Logs/AitmSpikeURL.log`. Copies live in `/Applications` and `/tmp`. Question 5 runs in the VM, or over
  `ssh localhost` only if Remote Login is already on. The spike never turns it on.
- **Revert steps:**
  1. Quit both copies.
  2. Unregister both copies from LaunchServices:
     `/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u
     /Applications/AitmSpikeURL.app`, and the same for `/tmp/AitmSpikeURL.app`.
  3. Delete both bundles and the log.
  4. Verify `open aitmspike://x` fails with "no application".

### S7: pkexec details (Linux)

- **Branch:** `experiment/l4priv-s7-pkexec`. Runs in `cis-lab` only, so nothing on Matt's Mac changes. **Blocks:**
  P1b.12–P1b.14, P2.6–P2.8, AC16, AC22.
- **Question:**
  1. Does pkexec's textual agent prompt on the tty while the parent's stdout and stderr are redirected?
  2. Does pkexec close fds above 2?
  3. Does pkexec exec in place, so the `SO_PEERCRED` pid of the helper equals the pid the core spawned?
  4. Is `PKEXEC_UID` set, and are the exit codes 126 (dismissed) and 127 (not authorized)?
  5. After the spec §5.1 drop (bounding set to `CAP_NET_RAW`, keepcaps, setgroups/setgid/setuid, permitted and
     effective = `CAP_NET_RAW`, `no_new_privs`), can `pcap` still open `lo` and `sendpacket` on it?
  6. Is `CAP_NET_RAW` alone enough, or does capture need `CAP_NET_ADMIN` too?
  7. Do `/proc/<pid>/status` lines match AC16's literals?
- **Setup:** Fedora and Debian systemd containers (the [linux-ci] rig) holding a ~100-line Rust spike binary at
  `/usr/lib/aitmproxy-spike/helper`, a matching `.policy`, and user `tester`.
- **Revert steps:**
  1. `nerdctl rm -f` both containers.
  2. `nerdctl rmi` the spike images.
  3. `rm -rf ~/l4priv-s7` inside `cis-lab`.
  4. Verify `nerdctl ps -a` lists none of them.
- **Output:** the exact drop order that works, the pid answer (decides P1b.12's peer check), and the exit codes
  (decide P1b.14's mapping). If `CAP_NET_RAW` alone is not enough, stop: the spec's AC16 literals change, and that
  goes to Matt.
- **Answered (S7, 2026-11-01, `docs/research/experiments/2026-11-01-l4-s7-pkexec-helper.md`, PR #240): PROVEN.**
  1 yes (the agent opens `/dev/tty`, not stdin; no controlling terminal gives exit 127 with `Error creating textual
  authentication agent`); 2 yes; 3 yes (`SO_PEERCRED.pid == Popen.pid` in all 17 pkexec runs); 4 `PKEXEC_UID` set,
  but the textual agent **never exits 126**: wrong password, Ctrl-D and no-tty are all 127 with distinct stderr
  texts and Ctrl-C is death by SIGINT that also reaches the core; 5 yes; 6 **`CAP_NET_RAW` alone**, the stop
  condition did not fire, AC16's literals stand; 7 yes, byte for byte. New: a `pcap_inject` frame on `lo` is a
  martian and never reaches a local socket; local destinations go through a raw IP socket with `IP_HDRINCL`. The
  rig ran under `podman --systemd=always --privileged` (the revert steps above named `nerdctl`, which `cis-lab`
  lacks). Folded into spec §5.7 and the rows below marked "(S7)".

### S8: inject on lo0 (macOS)

- **Branch:** `experiment/l4priv-s8-lo0-inject`. **Blocks:** AC8 W3–W4 on macOS only. No code waits on it.
- **Question:** On macOS 27, does a BPF write of a `DLT_NULL` IPv4/UDP frame on `lo0` to 127.0.0.1:9053 reach a UDP
  socket bound there? Is it read back by a capture on `lo0`?
- **Setup:** a `pcap` spike binary run as a user with read+write `/dev/bpf*`. In the VM, chmod as root there. In the
  Mac fallback, run it inside S3's window while the spike daemon's permissions are applied. Also a UDP listener on
  9053.
- **Revert steps:**
  - VM: discard the snapshot.
  - Mac fallback: stop the listener and the spike by PID. Then S3's revert steps, which run after S8 in the same
    window.
- **Output:** yes or no. A no turns AC8 W3–W4 on macOS into an honest `blocked: S8` line in P3.13 and leaves W1, W2
  and W5.

S6 (optional enrichment) and S1/S2 (Phase 2 only) are not scheduled.

---

## Unit (p1a) shared contracts: `feat/l4priv-contracts`

Pure types and functions both ends of the privilege boundary share, in `aitm-proto-l4`. No behaviour change, no new
verb, no new dependency.

### Task P1a.1: the privilege contract constants and the receipt

- **Satisfies:** AC6 (receipt fields), AC13, AC14 (receipt read by core and app)
- **Depends on:** none
- **Files:** `crates/aitm-proto-l4/src/privilege/mod.rs` (create: `pub mod contract;`), `crates/aitm-proto-l4/src/privilege/contract.rs` (create), `crates/aitm-proto-l4/src/lib.rs` (`pub mod privilege;`)
- **Change:**
  - Constants:
    - `pub const BPF_GROUP: &str = "access_bpf";`
    - `pub const RECEIPT_DIR: &str = "/Library/Application Support/Aitmproxy";`
    - `pub const RECEIPT_PATH: &str = "/Library/Application Support/Aitmproxy/l4-helper.json";`
    - `pub const RECEIPT_SCHEMA: u32 = 1;`
    - `pub const HELPER_LABEL: &str = "com.mrbrutti.aitmproxy.l4-helper";`
    - `pub const REVERT_LABEL: &str = "com.mrbrutti.aitmproxy.l4-helper-revert";`
    - `pub const HELPER_IDENTIFIER: &str = "com.mrbrutti.aitmproxy.l4-helper";`
    - `pub const TEAM_ID: &str = "995PCLM9KH";`
    - `pub const APP_BUNDLE_ID: &str = "com.mrbrutti.aitmproxy";`
    - `pub const ALLOW_URL: &str = "aitmproxy://packet-capture/allow";`
    - `pub const HELPER_PLIST_REL: &str = "Contents/Library/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist";`
    - `pub const LINUX_HELPER_PATH: &str = "/usr/lib/aitmproxy/aitm-l4-helper";`
    - `pub const POLKIT_ACTION: &str = "com.mrbrutti.aitmproxy.l4-helper.run";`
    - `pub const DOWNLOAD_URL: &str = "https://mrbrutti.github.io/aitmproxy/download.html";`
  - The receipt: `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct Receipt { pub schema: u32,
    pub helper_version: String, pub applied_at: u64, pub group: String, pub gid: u32, pub nodes: u32, pub
    members_added: Vec<String>, pub errors: Vec<String> }`.
  - Its methods: `Receipt::parse(bytes: &[u8]) -> Result<Receipt, ReceiptError>` and
    `Receipt::to_json(&self) -> Vec<u8>`.
  - The error: `pub enum ReceiptError { Json(String), Schema(u32) }`. It implements `Display`.
- **Test (first, failing):** `contract::tests::receipt_round_trips_and_refuses_other_schemas`.
  - A receipt with `members_added: ["matt"]` round-trips through `to_json` and `parse`.
  - `{"schema":2,…}` gives `Err(ReceiptError::Schema(2))`.
  - `b"{"` gives `Err(ReceiptError::Json(_))`.
  - `ALLOW_URL == "aitmproxy://packet-capture/allow"`.
- **Done when:** the test passes, the unit gate passes, and the `aitm-core` diff is empty.

### Task P1a.2: helper wire protocol framing

- **Satisfies:** AC18 (oversized length closes the session), spec §5.2
- **Depends on:** P1a.1
- **Files:** `crates/aitm-proto-l4/src/helper/mod.rs` (create: `pub mod proto; pub mod frame; pub mod enforce;` as they land), `crates/aitm-proto-l4/src/helper/proto.rs` (create), `crates/aitm-proto-l4/src/lib.rs` (`pub mod helper;`)
- **Change:**
  - Constants: `pub const PROTO: u32 = 1;` and `pub const MAX_FRAME: usize = 256 * 1024;`.
  - `pub struct ScopeSet { pub scope: Vec<L4ScopeEntry>, pub global_inject_pps: u32, pub max_packet_bytes: usize,
    pub max_packets_per_call: u32, pub self_ports: Vec<u16> }`, with
    `ScopeSet::to_config(&self) -> L4Config` (`enabled: true`, everything else default).
  - `pub enum Msg`, one type byte each:

    | Type byte | Variant |
    |---|---|
    | 0x01 | `Hello { proto: u32, core_version: String }` |
    | 0x02 | `HelloAck { proto: u32, helper_version: String, caps: Vec<String> }` |
    | 0x03 | `ScopeSet(ScopeSet)` |
    | 0x04 | `CaptureOpen { id: u64, interface: String, direction: L4Direction, read_timeout_ms: u32 }` |
    | 0x05 | `CaptureClose { id: u64 }` |
    | 0x06 | `Frame { capture_id: u64, ts_us: u64, bytes: Vec<u8> }` |
    | 0x07 | `CaptureClosed { capture_id: u64, reason: String }` |
    | 0x08 | `Inject { request_id: u64, interface: String, bytes: Vec<u8> }` |
    | 0x09 | `InjectResult { request_id: u64, error: Option<String> }` |

  - `pub fn encode(msg: &Msg) -> Vec<u8>` and `pub fn read_msg(r: &mut impl std::io::Read) -> Result<Msg,
    ProtoError>`.
  - `pub enum ProtoError { TooLong(usize), UnknownType(u8), BadJson(String), BadBinary, Eof, Io(String) }`.
  - Framing: control payloads are JSON. `Frame` and `Inject` use the binary header (ids and the timestamp big-endian
    u64, then a u16-length interface string) followed by the raw bytes. The exact layout is the builder's, within
    `MAX_FRAME`.
- **Test (first, failing):** `proto::tests`:
  - `every_variant_round_trips` covers all nine.
  - `length_over_max_is_too_long`: a header of `262_145` gives `Err(ProtoError::TooLong(262145))`.
  - `unknown_type_is_refused`: type `0x7f` gives `Err(ProtoError::UnknownType(127))`.
  - `malformed_json_is_bad_json`: a `Hello` with payload `{` gives `BadJson`.
  - `clean_eof_is_eof`: an empty reader gives `Eof`.
- **Done when:** the tests pass and the unit gate passes.

### Task P1a.3: inject-frame target parser

- **Satisfies:** AC18 (unit: truncated, oversized, non-IP, IPv6 frames)
- **Depends on:** P1a.2
- **Files:** `crates/aitm-proto-l4/src/helper/frame.rs` (create)
- **Change:**
  - `pub enum LinkType { Null, Ethernet, Raw }`.
  - `pub fn inject_target(interface: &str, link: LinkType, frame: &[u8], max_len: usize) -> Result<L4Target,
    FrameError>`. It decodes with the existing `PacketSpec::endpoints` / etherparse path. It never trusts a target
    supplied by the other side. `direction` is `Outbound`.
  - `pub enum FrameError { Truncated, Oversized(usize), NotIp, NoTransport }`.
- **Test (first, failing):** `frame::tests`:
  - A `DLT_NULL` IPv4/UDP frame crafted with `crate::craft` to 127.0.0.1:9053 gives
    `L4Target { interface: "lo0", dst: Some(127.0.0.1), dst_port: Some(9053), proto: Udp, .. }`.
  - Ethernet IPv6/UDP to `::1` port 9053 gives `dst == Some(::1)`.
  - A 10-byte buffer gives `Err(Truncated)`.
  - A `max_len + 1` buffer gives `Err(Oversized(max_len + 1))`.
  - An ARP Ethernet frame gives `Err(NotIp)`.
- **Done when:** the tests pass and the unit gate passes.

### Task P1a.4: helper-side guard enforcement and capture filter

- **Satisfies:** AC18 (unit: scope refusal, scope-built filter), spec §5.3
- **Depends on:** P1a.3
- **Files:** `crates/aitm-proto-l4/src/helper/enforce.rs` (create)
- **Change:** `pub struct HelperGuard`, which wraps an `L4Guard` built from `ScopeSet::to_config()`, with
  `self_ports` set.
  - `HelperGuard::from_scope_set(s: &ScopeSet) -> Self`
  - `HelperGuard::check_inject(&self, interface: &str, link: LinkType, frame: &[u8]) -> Result<(), String>`: runs
    `inject_target`, then `L4Guard::check(L4Action::Inject, &target)`, then `permit.authorize_packet(len)`, with its
    own rate buckets. Errors are the guard's `Display` text.
  - `HelperGuard::capture_filter(&self, interface: &str) -> Result<Option<String>, String>`: refuses an interface no
    capture scope entry covers. Otherwise it returns `crate::capture::scope_filter(&guard, interface)`. It takes no
    filter argument at all.
- **Test (first, failing):** `enforce::tests`, over a `ScopeSet` of `lo`, `127.0.0.1/32`, `9000-9999` (capture and
  inject):
  - `check_inject` of a UDP frame to 127.0.0.1:8999 gives an `Err` containing `scope`.
  - To 127.0.0.1:9053 it gives `Ok(())`.
  - `capture_filter("eth9")` is an `Err`.
  - `capture_filter("lo")` equals `Ok(scope_filter(&L4Guard::new(&s.to_config()), "lo"))`.
- **Done when:** the tests pass, the unit gate passes, and the `aitm-core` diff is empty. **Unit close:** a Tester
  run plus the panel. No live check: p1a changes no behaviour.

---

## Unit (p1b) core: `feat/l4priv-core`

Builds the `PrivilegeState`, the two verbs, live gating through the parity `AvailabilitySource` seam, the status
`privilege` key, the macOS handoff and the Linux pkexec session. Cut from `main` after p1a merges.

**Reason text (Architect's call, a spec conflict resolved for the parity contract).** The parity spec defines status
`reason` as "the exact text the gated verbs return after `L4 unavailable: `". L4PAR-AC3 asserts that `l4.capture.start`
fails with exactly that reason. This spec, meanwhile, says the status `reason` "becomes the capability's reason" and
that `L4Gated` says `packet capture is not allowed yet (<how.label>)`. Those two cannot both hold. The parity contract
wins, because this spec declares itself additive.

So, for `needs_approval`, both the status `reason` and the `L4Gated` text are
`packet capture is not allowed yet (<how.label>)`. The descriptive capability reason lives in
`privilege.capabilities.capture.reason`. For `unsupported`, both the status `reason` and the `L4Gated` text are the
capability's reason.

### Task P1b.1: report types and the macOS decision table

- **Satisfies:** AC3 (macOS rows), spec §2.2
- **Depends on:** p1a merged
- **Files:** `crates/aitm-proto-l4/src/privilege/report.rs` (create), `crates/aitm-proto-l4/src/privilege/derive.rs` (create), `crates/aitm-proto-l4/src/privilege/mod.rs`
- **Change:**
  - In `report.rs`, the report and its parts:
    - `pub struct PrivilegeReport { pub enabled: bool, pub platform: Platform, pub capture: Capability, pub inject:
      Capability, pub intercept: Capability, pub helper: Helper, pub request: Option<RequestProgress>, pub
      checked_at: u64 }`
    - `pub enum Platform { Macos, Linux, Other }`
    - `pub enum Capability { Available { via: Via }, NeedsApproval { reason: String, how: How }, Unsupported {
      reason: String } }`
    - `pub enum Via { Process, Helper }`
    - `pub struct How { pub kind: HowKind, pub label: String, pub action: Action }`
    - `pub enum HowKind { AppAction, OsDialog, Package, Pkexec }`
    - `pub enum Action { BusVerb, OpenUrl(String) }`
    - `pub struct Helper { pub kind: HelperKind, pub status: HelperStatus, pub version: Option<String>, pub detail:
      Option<String> }`, with the spec §2.2 enum values for both enums
    - `pub struct RequestProgress { pub state: RequestState, pub at: u64, pub message: String }` and
      `pub enum RequestState { Pending, HandedToApp, Approved, Dismissed, Failed }`
  - `PrivilegeReport::to_value(&self) -> aitm_core::Value` renders the exact §2.2 JSON shape.
    `capabilities.{capture,inject,intercept}` are nested, and `action` is
    `{"type":"bus_verb","verb":"l4.privilege.request"}` or `{"type":"open_url","url":…}`.
  - In `derive.rs`:
    - `pub struct ProbeInputs { pub enabled: bool, pub platform: Platform, pub mac: Option<MacInputs>, pub linux:
      Option<LinuxInputs>, pub request: Option<RequestProgress>, pub now_ms: u64 }`
    - `pub struct MacInputs { pub bpf_rw_opens: bool, pub receipt: Option<Receipt>, pub handoff_app_embeds_helper:
      bool }`
    - `pub fn derive(inputs: &ProbeInputs) -> PrivilegeReport`: pure, first match wins, rows exactly as spec §2.2.
- **Test (first, failing):** `derive::tests`, one test per macOS row, asserting `capture` and `helper.status`
  literally:
  1. `l4_off_is_unsupported`: reason `"L4 is off in this core's config (l4.enabled)"`, and all three capabilities
     `Unsupported`.
  2. `rw_open_is_available_process`: with a receipt, `helper.status == Applied`; without one, `Unknown`.
  3. `receipt_but_no_open_is_app_action`: the reason is the receipt's first `errors` entry, else the spec's literal.
  4. `handed_to_app_is_os_dialog`: label `"Approve Aitmproxy in System Settings ▸ General ▸ Login Items &
     Extensions"`, status `Installed`.
  5. `embedded_plist_is_app_action`: label `"Allow packet capture in the Aitmproxy app"`.
  6. `otherwise_is_package_with_download_url`: label `"Install the Aitmproxy app (DMG or Homebrew cask); it asks
     macOS for packet-capture permission"`, action `OpenUrl(DOWNLOAD_URL)`, status `NotInstalled`.

  Also: `intercept` on macOS is always `Unsupported { reason: "in-path interception is Linux only" }`. And
  `to_value` of row 6 has `capabilities.capture.how.kind == "package"` and an integer `checked_at`.
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.2: the Linux decision table

- **Satisfies:** AC3 (Linux rows), AC20 (unit half), spec §2.2
- **Depends on:** P1b.1
- **Files:** `crates/aitm-proto-l4/src/privilege/derive.rs`
- **Change:**
  - `pub struct LinuxInputs { pub cap_net_raw: bool, pub cap_net_admin: bool, pub session_connected: bool, pub
    helper: Option<HelperCandidate>, pub policy_file_present: bool, pub pkexec_present: bool, pub prompt_possible:
    bool }`
  - `pub struct HelperCandidate { pub path: PathBuf, pub at_policy_path: bool, pub root_owned_chain: bool, pub
    file_caps_net_raw: bool }`
  - `derive` gains the eight Linux rows and the intercept rule (spec §2.2), first match wins.
- **Test (first, failing):** one test per row, asserting `capture` state, `how.kind` and `helper.kind/status`:
  - `process_cap_net_raw_is_available_process`
  - `connected_session_is_available_helper`
  - `file_caps_helper_is_available_helper_cap_kind`, giving `LinuxCapHelper` / `Installed`
  - `policy_helper_with_prompt_is_pkexec`: label `"Allow packet capture (asks for an administrator password)"`
  - `policy_helper_without_prompt_is_package`: reason `"No password prompt can be shown here (no desktop session or
    terminal)"`
  - `helper_under_home_is_package_not_installed`: `root_owned_chain: false`, with `detail` naming the path. This is
    AC20's unit half.
  - `nothing_is_package_with_download_url`

  Intercept: `cap_net_admin` gives `Available { via: Process }`. Without it, `Unsupported` with the spec's literal,
  and no `how`.
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.3: no reply names a command (tripwire) and the probe strings

- **Satisfies:** AC3 (tripwire half), Rule 2
- **Depends on:** P1b.2
- **Files:** `crates/aitm-proto-l4/src/module.rs` (`probe()` reason strings only), `crates/aitm-proto-l4/src/privilege/derive.rs` (test only)
- **Change:** rewrite the three `probe()` reason literals in `module.rs` so that none names a command.
  - Linux capture: `"missing CAP_NET_RAW (raw capture and inject need the packet-capture helper or a privileged
    process)"`.
  - Linux intercept: `"missing CAP_NET_ADMIN (in-path interception needs the core itself to hold CAP_NET_ADMIN)"`.
  - macOS capture: `"no read+write access to any /dev/bpf* device"`.

  The texts are the Architect's call.
- **Test (first, failing):** `derive::tests::no_reason_or_label_names_a_command`. It builds every row's report and
  collects every `reason` and `label`. It reads `module.rs` with `include_str!` and extracts the string literals
  inside `fn probe`. It asserts that none matches
  `\b(sudo|setcap|chmod|chgrp|chown|dseditgroup|launchctl|pkexec)\b`, using a hand-rolled word match (no new regex
  dependency). It fails today on the ChmodBPF and setcap strings.
- **Done when:** the test passes and the unit gate passes.

### Task P1b.4: status mapping onto the parity vocabulary

- **Satisfies:** AC4 (unit: the mapping for each capability state)
- **Depends on:** P1b.3
- **Files:** `crates/aitm-proto-l4/src/privilege/availability.rs` (create)
- **Change:**
  - `pub fn capture_availability(r: &PrivilegeReport) -> L4Availability`
  - `pub fn intercept_availability(r: &PrivilegeReport, configured: bool) -> L4Availability`
  - `pub fn gated_reason(c: &Capability) -> Option<String>`, which gives `packet capture is not allowed yet
    (<label>)` for `NeedsApproval`, the reason for `Unsupported`, and `None` for `Available`.
  - The mapping:

    | Capability | Platform | `L4Availability` |
    |---|---|---|
    | `Available` | any | `Available` |
    | `NeedsApproval` | any | `Unavailable { NeedsPrivilege, gated_reason }` |
    | `Unsupported`, intercept without `CAP_NET_ADMIN` | Linux | `NeedsPrivilege` |
    | any other `Unsupported` | any | `UnsupportedPlatform` |

    An available intercept that is not configured gives `NotConfigured` with `INTERCEPT_NOT_CONFIGURED`. Privilege
    outranks configuration.
- **Test (first, failing):** `availability::tests`:
  - `needs_approval_maps_to_needs_privilege`: the reason is `"packet capture is not allowed yet (Allow packet capture
    in the Aitmproxy app)"` for the row-5 report.
  - `mac_intercept_is_unsupported_platform`
  - `linux_intercept_without_admin_is_needs_privilege`
  - `privileged_unconfigured_intercept_is_not_configured`
  - `available_is_available`
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.5: platform gatherers (pure parts)

- **Satisfies:** AC10 (unit), AC17 (never pkexec a non-policy path), AC20, AC23 (unit halves)
- **Depends on:** P1b.4
- **Files:** `crates/aitm-proto-l4/src/privilege/macos.rs` (create), `crates/aitm-proto-l4/src/privilege/linux.rs` (create)
- **Change:**
  - In `macos.rs`:
    - `pub fn bundle_of_exe(exe: &Path) -> Option<PathBuf>`: `<X>.app` when `exe` ends in
      `.app/Contents/Resources/core/aitm`.
    - `pub struct AppFacts { pub is_dir: bool, pub bundle_id: Option<String>, pub team_ok: bool }`
    - `pub enum HandoffRefusal { Missing, NotAnApp, TempPath, WrongBundleId(String), BadSignature }`
    - `pub fn validate_handoff_app(path: &Path, facts: &AppFacts) -> Result<(), HandoffRefusal>`: refuses `/tmp`,
      `/private/tmp` and `/var/folders` prefixes, and anything not ending in `.app`.
    - `fn app_facts(path: &Path) -> AppFacts` (I/O). It runs `/usr/bin/plutil -extract CFBundleIdentifier raw -o -
      <path>/Contents/Info.plist` and `/usr/bin/codesign --verify --strict -R='anchor apple generic and certificate
      leaf[subject.OU] = "995PCLM9KH"' <path>`, taking the exit status. Results are cached by `(path, mtime)`
      **(Architect's call:** the signature check is not run on every 1 s probe).
    - `fn gather_mac(cfg: &PrivilegeConfig) -> MacInputs` (I/O): the existing bpf read+write loop, the receipt read,
      and the helper plist's presence (`HELPER_PLIST_REL`) in the validated handoff app.
  - In `linux.rs`:
    - `pub fn parse_cap_eff(status: &str) -> Option<u64>`
    - `pub fn candidates(helper_path: Option<&Path>, exe_dir: &Path) -> Vec<PathBuf>`: in the order configured,
      `<exe dir>`, `LINUX_HELPER_PATH`, `/run/wrappers/bin/aitm-l4-helper`.
    - `pub struct PathMeta { pub uid: u32, pub mode: u32, pub is_symlink: bool }`
    - `pub fn root_owned_chain(chain: &[PathMeta]) -> bool`: every element uid 0, no group or other write bits, and
      no symlink.
    - `pub fn prompt_possible(display: Option<&str>, wayland: Option<&str>, tty_opens: bool) -> bool` (S7: the third
      input is "a controlling terminal opens", i.e. `open("/dev/tty")` succeeded, **not** `isatty(stdin)`; pkexec's
      textual agent uses `/dev/tty` and prompts fine with all three stdio fds redirected).
    - `fn controlling_tty_opens() -> bool` (I/O): `OpenOptions::new().read(true).write(true).open("/dev/tty")`
      succeeds; false under `setsid` or with no terminal.
    - `fn gather_linux(cfg, session_connected) -> LinuxInputs` (I/O; runs `<helper> probe` for the file-caps row;
      `prompt_possible` is fed `controlling_tty_opens()`).
- **Test (first, failing):**
  - `macos::tests`:
    - `bundle_of_exe("/Applications/Aitmproxy.app/Contents/Resources/core/aitm") == Some("/Applications/Aitmproxy.app")`
    - `bundle_of_exe("/opt/homebrew/bin/aitm") == None`
    - `/tmp/Aitmproxy-dev.app` is refused with `TempPath`, and so are `/private/tmp/…` and `/var/folders/xy/…/A.app`
    - a bundle id of `com.example` gives `WrongBundleId("com.example")`
    - `team_ok: false` gives `BadSignature`
    - a valid `/Applications/Aitmproxy.app` gives `Ok`
  - `linux::tests`:
    - `parse_cap_eff("CapEff:\t0000000000002000\n") == Some(0x2000)`
    - the candidate order with `helper_path: Some("/opt/x")` is
      `["/opt/x", "<exe>/aitm-l4-helper", "/usr/lib/aitmproxy/aitm-l4-helper", "/run/wrappers/bin/aitm-l4-helper"]`
    - a chain with `/home/u` (uid 1000) is `false`
    - mode `0o775` is `false`
    - `prompt_possible(None, None, false) == false`
    - `prompt_possible(Some(":0"), None, false) == true`
    - `prompt_possible(None, Some("wayland-0"), false) == true`
    - `prompt_possible(None, None, true) == true` (S7: a controlling terminal with stdin on `/dev/null` is a prompt)
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.6: `PrivilegeState`, config, re-probe and state-change logging

- **Satisfies:** AC7 (unit half: no restart), AC24 (one `info` per change), spec §2.1, §2.4 config
- **Depends on:** P1b.5
- **Files:** `crates/aitm-proto-l4/src/privilege/state.rs` (create), `crates/aitm-proto-l4/src/privilege/mod.rs`, `crates/aitm-proto-l4/src/config.rs`, `crates/aitm-proto-l4/Cargo.toml` (`tracing.workspace = true`), `crates/aitm-proto-l4/src/privilege/linux.rs` and `macos.rs` (panel, 2026-11-01: the two `allow` removals only, lint allowances the state's consumers made dead)
- **Change:**
  - Config: `L4Config` gains `pub privilege: L4PrivilegeConfig { pub helper_path: Option<PathBuf>, pub
    macos_app_path: PathBuf, pub request: RequestMode }`. The defaults are `None`,
    `/Applications/Aitmproxy.app` and `RequestMode::Manual`. `pub enum RequestMode { Manual, AtStart }` is serde
    `snake_case`. Both keep `deny_unknown_fields`.
  - `pub struct PrivilegeConfig { pub enabled: bool, pub l4: L4PrivilegeConfig, pub lifetime: ProcessLifetime }` and
    `pub enum ProcessLifetime { Serving, OneShot }`.
  - The prober seam: `pub trait Prober: Send + Sync { fn gather(&self, request: Option<&RequestProgress>) ->
    ProbeInputs; }`.
  - The state:
    - `PrivilegeState::new(cfg: &PrivilegeConfig) -> Self` uses the platform prober.
    - `PrivilegeState::with_prober(cfg: &PrivilegeConfig, prober: Box<dyn Prober>, clock: Arc<dyn Fn() -> u64 +
      Send + Sync>) -> Self` is for tests.
    - `pub fn report(&self) -> PrivilegeReport` re-probes when the cached capture is not `Available` and is older
      than 1000 ms. It logs one `tracing::info!` line on each capture-state change, with no token and no payload.
      `request` moves `HandedToApp` / `Pending` → `Approved` when capture becomes available.
  - `pub fn startup_line(r: &PrivilegeReport) -> Option<String>` gives
    `Some("L4 enabled; packet capture needs approval: <how.label>")` when enabled and `NeedsApproval`.
- **Test (first, failing):** `state::tests`:
  - `flip_is_seen_without_rebuild`: a prober that returns row 6, then row 2. A `report()` at t=0 gives `needs_approval`.
    After the flip at t=500 ms it still gives `needs_approval` (cached). At t=1100 ms it gives `available`.
  - `info_logged_once_per_change`: a counting subscriber, or a counted change hook, sees exactly 1 change for that
    sequence.
  - `startup_line_literal`: for row 5, `startup_line` gives `"L4 enabled; packet capture needs approval: Allow packet
    capture in the Aitmproxy app"`.
  - `config.rs`: YAML `privilege: {request: at_start}` parses to `AtStart`; `privilege: {bogus: 1}` errors; the
    defaults are as above.
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.7: live gating in `L4Gated`, forwarded confirm prompts

- **Satisfies:** AC7 (no restart), AC27
- **Depends on:** P1b.6
- **Files:** `crates/aitm-proto-l4/src/module.rs`, `crates/aitm-proto-l4/tests/privilege.rs` (create)
- **Change:**
  - `L4Gated` becomes `{ inner: Arc<dyn Command>, state: Arc<PrivilegeState>, class: GateClass }`, with
    `enum GateClass { CaptureInject, Intercept { configured: bool } }`.
    - `invoke` reads `state.report()`. When the class's availability is `Available`, it delegates to `inner.invoke`.
      Otherwise it returns `L4Error::Unavailable(<gated_reason>)`.
    - `confirm_prompt` and `sensitivity` delegate to `inner`.
  - `fn gate(cmds, state: &Arc<PrivilegeState>, class)` always wraps.
  - The module constructors:
    - `L4Module::with_state(cfg: &L4Config, state: Arc<PrivilegeState>) -> Self`
    - `L4Module::with_shared(guard, store, intercept_cfg, state: Arc<PrivilegeState>) -> Self`
    - `with_privilege` and `with_parts` stay for tests and wrap a fixed prober.
  - The two `AvailabilitySource`s close over the `Arc<PrivilegeState>` (P1b.4 mapping).
- **Test (first, failing):** `tests/privilege.rs`:
  - `gated_verbs_flip_live_and_stay_confirmable`: one module over a flipping prober.
    1. Before the flip, `l4.capture.start {interface:"lo0"}` errors with exactly `L4 unavailable: packet capture is
       not allowed yet (Allow packet capture in the Aitmproxy app)`.
    2. After the flip and 1.1 s on the injected clock, it reaches the inner command; the mock backend records an
       open.
    3. (Reworded by the panel, 2026-11-01.) For `l4.inject`, `l4.send_recv`, `l4.intercept.forward` and
       `l4.intercept.drop`, `cmd.confirm_prompt(params)` and `cmd.sensitivity()` answer identically before and after
       the flip for every `params` tried: `Params::default()` (which gives `None` for all four, with or without
       privilege, since inject/send_recv need `spec`/`dst`/`interface` and the verdict verbs a parked id) and in-scope
       params; for `l4.inject` and `l4.send_recv` with in-scope params the answer is `Some` while still gated.
       `confirm_prompt(&Params::default()).is_some()` is the expression `aitm-mcp`'s `schema.rs` uses for
       `confirmable`, so `confirmable` never changes with privilege. It failed before P1b.7: `L4Gated` did not forward
       `confirm_prompt`.
  - `status_reason_equals_gated_text`: the `l4.capture.status` `reason` equals the start error's text after
    `L4 unavailable: `. This is L4PAR-AC3 kept.
- **Done when:** the tests pass, the unit gate passes, and the existing `module.rs` and parity tests still pass.

### Task P1b.8: one routed backend for commands, Rhai and the scripting engine

- **Satisfies:** spec §2.1 (every production `PcapBackend::new()` caller takes `state.backend()`), AC8 (Linux via
  helper)
- **Depends on:** P1b.7
- **Files:** `crates/aitm-proto-l4/src/backend/routed.rs` (create), `crates/aitm-proto-l4/src/backend/mod.rs`, `crates/aitm-proto-l4/src/commands/mod.rs` (`wire_commands` takes a backend), `crates/aitm-proto-l4/src/privilege/state.rs`, `crates/aitm-proto-l4/src/module.rs`, `crates/aitm-proto-l4/src/commands/capture.rs` (test `wire_commands_registered` only: the fourth argument; added 2026-11-01 by the p1b orchestrator on the Coder's Rule 10 report, since the test call is `wire_commands`' second caller and P1b.9 touches the file only after P1b.8), `crates/aitm-proto-l4/tests/hard_gates.rs` (test `exactly_one_production_wire_write` only: the expected sites become `backend/routed.rs` ×1 and `wire.rs` ×1, each pinned to exactly one, with the doc sentence that the router site is `RoutedBackend::inject`'s backend-layer delegation, still reached only through `send_on_wire`; added 2026-11-01 by the p1b orchestrator on the Coder's second Rule 10 report; flagged for the security reviewer)
- **Change:**
  - `pub struct RoutedBackend { state: Weak<…> or Arc<PrivilegeState> }` implements `CaptureInjectBackend`. Each
    `open_capture` / `inject` asks the state for its current backend: the in-process `PcapBackend` when
    `capture.via == Process`, the `HelperBackend` session when `via == Helper` (P1b.13), else
    `L4Error::Unavailable`.
  - `PrivilegeState::backend(&self) -> Arc<dyn CaptureInjectBackend>` returns it. **(Architect's call:** one routed
    backend rather than a swap, so a Linux session that starts after the commands were built is picked up.)
  - `wire_commands(guard, store, capture: AvailabilitySource, backend: Arc<dyn CaptureInjectBackend>)`.
    `L4Language::for_catalog` keeps its pure `PcapBackend` (catalogue only).
- **Test (first, failing):** `routed::tests`:
  - `routes_to_process_backend_when_available_via_process`: an inject through `wire_commands` built over a state whose
    prober says `Available { via: Process }` reaches the injected mock. It fails until the param exists.
  - `unavailable_state_refuses_without_touching_a_backend`: the result is `Err(L4Error::Unavailable(_))` and the mock
    is never called.
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.9: the status replies gain `privilege`

- **Satisfies:** AC4 (unit), parity contract unchanged
- **Depends on:** P1b.8
- **Files:** `crates/aitm-proto-l4/src/commands/capture.rs`, `crates/aitm-proto-l4/src/commands/intercept.rs`, `crates/aitm-proto-l4/src/module.rs`, `crates/aitm-proto-l4/src/commands/mod.rs` (panel, 2026-11-01: the `PrivilegeReportSource` alias, `with_privilege`, `privilege_field`, and the fifth `wire_commands` argument), `crates/aitm-proto-l4/src/backend/routed.rs` (panel, 2026-11-01: the test call to `wire_commands` only)
- **Change:**
  - `pub(crate) type PrivilegeReportSource = Arc<dyn Fn() -> Option<PrivilegeReport> + Send + Sync>;` (panel,
    2026-11-01: named `PrivilegeReportSource`, not `PrivilegeSource`, because `PrivilegeSource` is `module.rs`'s gate
    enum from P1b.7's recorded deviation).
  - The `l4.capture.status` and `l4.intercept.status` builders take it. When it returns `Some`, the reply gains
    `"privilege": report.to_value()`. The keys `available`, `code`, `reason` and `captures` / `sessions` are
    unchanged.
- **Test (first, failing):** `capture::tests::status_carries_privilege_additively`.
  - With the row-6 prober, the reply has exactly the keys `{available, code, reason, captures, privilege}`, with
    `code == "needs_privilege"`, `captures == []` and `privilege.capabilities.capture.state == "needs_approval"`.
  - With a `None` source, the key set is the parity four.
  - Intercept on macOS: `code == "unsupported_platform"`. On Linux without `CAP_NET_ADMIN`: `"needs_privilege"`.
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.10: `l4.privilege` and `l4.privilege.request` commands

- **Satisfies:** AC1, AC2 (unit halves), AC5 (command half), spec §2.2, §2.3
- **Depends on:** P1b.9
- **Files:** `crates/aitm-proto-l4/src/commands/privilege.rs` (create), `crates/aitm-proto-l4/src/commands/mod.rs`, `crates/aitm-proto-l4/src/privilege/state.rs` (panel, 2026-11-01: `request`, `RequestOutcome`, `Outcome`, as the Change list below demands)
- **Change:**
  - `pub struct PrivilegeRead { state: Arc<PrivilegeState> }`: name `l4.privilege`, `Sensitivity::Read`, no params,
    returns `report().to_value()`.
  - `pub struct PrivilegeRequest { state: Arc<PrivilegeState> }`: name `l4.privilege.request`,
    `Sensitivity::Sensitive`.
    - `confirm_prompt` always `Some`, with the spec §2.3 literal per `cfg!(target_os)`.
    - `invoke` first line: if `!host.caller_is_trusted_control()`, error `l4.privilege.request refused: only an
      operator can ask for packet-capture permission; an agent never can.`
    - Otherwise it returns `state.request()` as `{"outcome", "message", "privilege"}`.
  - `pub struct RequestOutcome { pub outcome: Outcome, pub message: String, pub privilege: PrivilegeReport }` and
    `pub enum Outcome { AlreadyAvailable, Pending, HandedToApp, CannotPrompt }`.
  - `PrivilegeState::request(&self) -> RequestOutcome`:
    - already available: `AlreadyAvailable`;
    - a request in flight: `Pending` with the same `at`;
    - otherwise it dispatches to the platform (P1b.11, P1b.14). `Other` platforms give `CannotPrompt`.
    - `enabled == false` gives `CannotPrompt` with `"L4 is off in this core's config (l4.enabled)"`
      **(Architect's call:** the verb is registered even when L4 is off, §2.2; the spec gives no outcome for that
      case).
  - `pub fn privilege_commands(state: Arc<PrivilegeState>) -> Vec<Arc<dyn Command>>` and a `PrivilegePlugin` that
    registers them.
- **Test (first, failing):** `privilege::tests`:
  - `agent_host_is_refused_first`: an untrusted `CommandHost` gets an error starting
    `l4.privilege.request refused: only an operator`, and the prober's request hook is never called.
  - `request_is_sensitive_and_confirmable`
  - `available_is_already_available`
  - `second_call_while_pending_returns_same_progress`
  - `read_verb_answers_with_l4_off`: `enabled:false` gives `"enabled": false` and three `unsupported`.
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.11: macOS handoff to the installed app

- **Satisfies:** AC9 (core half), AC10, spec §2.3, §3.4
- **Depends on:** P1b.10; spike **S5** written up (the delivery, and the `launchctl managername` answer for "no GUI
  session")
- **Files:** `crates/aitm-proto-l4/src/privilege/macos.rs`
- **Change:**
  - `pub trait MacRunner: Send + Sync { fn run(&self, argv: &[&str], timeout: Duration) -> Result<i32, String>; }`.
    The real implementation is `std::process::Command` with an absolute program path, no shell, and a bounded wait.
  - `pub fn request_mac(cfg: &PrivilegeConfig, exe: &Path, runner: &dyn MacRunner, facts: &dyn Fn(&Path) ->
    AppFacts) -> (Outcome, String)`. The steps:
    1. Resolve the app: `bundle_of_exe(exe)`, else `macos_app_path`.
    2. `validate_handoff_app`. If it fails: `CannotPrompt` with the `package` label. `open` is not run.
    3. GUI check: `/bin/launchctl managername` must print `Aqua`. Otherwise: `CannotPrompt`, `"No desktop session to
       show the Aitmproxy app in; approve packet capture from the Mac's screen"`.
    4. Run `["/usr/bin/open", "-a", <path>, ALLOW_URL]` with a 2 s wait. Exit 0 gives `HandedToApp` with `"Aitmproxy
       is open on this Mac: click Allow Packet Capture… there, then approve it in System Settings"`. Non-zero gives
       `CannotPrompt` with the no-desktop text.

    The messages and the 2 s bound are the Architect's call. If S5 shows `managername` is not reliable, use S5's
    alternative and record it.
- **Test (first, failing):** `macos::tests` with a recording runner:
  - `tmp_bundle_never_opens`: `macos_app_path: /tmp/Aitmproxy-dev.app` gives `CannotPrompt`, with zero runner calls.
  - `valid_app_opens_exact_argv`: the recorded argv is exactly
    `["/usr/bin/open","-a","/Applications/Aitmproxy.app","aitmproxy://packet-capture/allow"]`, and the result is
    `HandedToApp`.
  - `non_aqua_is_cannot_prompt`: `managername` prints `Background` gives `CannotPrompt` and `open` is never run.
  - `own_bundle_wins_over_config`
- **Live check [mac-any]:** in P1b.17 (AC10).
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.12: Linux helper session, core end (listener, peer checks, handshake)

- **Satisfies:** AC16 (core half), AC18 (core-side protocol errors), spec §5.1 step 5, §5.2
- **Depends on:** P1b.10; spike **S7** written up (the pid answer for the peer check). (S7) Answered: pkexec execs
  the helper in place, so `expected_pid` **is the pkexec child's pid** as returned by the spawner; the helper connects
  about 0.4 s after the password, well inside the 10 s AC16 budget.
- **Files:** `crates/aitm-proto-l4/src/helper/client.rs` (create), `crates/aitm-proto-l4/src/helper/mod.rs`, `crates/aitm-proto-l4/Cargo.toml` (Linux-target `nix` with `socket,user`), `Cargo.lock` (panel, 2026-11-01: the one derived edge for that `nix` change; p2 owns the lock for the new crate)
- **Change:**
  - `pub fn socket_dir(xdg_runtime: Option<&Path>, uid: u32) -> PathBuf`: `$XDG_RUNTIME_DIR/aitm`, else
    `/tmp/aitm-<uid>`. It creates the directory with mode 0700 and verifies owner and mode. (S7) The full socket
    path appears on the helper's argv and therefore in the journal (`pkexec[…]: … [COMMAND=… --connect <path>]`),
    readable by any journal reader: the name is `l4-helper-<core pid>.sock` and **never** carries a token, a
    random secret or anything else that must stay private. The core resolves it to an absolute path before spawning
    (the helper's `cwd` is `/root` and `XDG_RUNTIME_DIR` is not in its environment).
  - `pub struct HelperListener` with
    - `bind(dir: &Path) -> io::Result<Self>`, which creates `l4-helper-<core pid>.sock`, and
    - `accept_checked(&self, expected_pid: u32, timeout: Duration) -> Result<HelperSession, SessionError>`, which
      checks that the `SO_PEERCRED` uid equals the core's uid and the pid equals `expected_pid`.
  - `pub struct HelperSession`: `handshake(core_version: &str) -> Result<HelloAck, SessionError>` (proto mismatch
    gives `VersionMismatch`), `send_scope(&ScopeSet)`, plus a reader thread demultiplexing `Frame` / `CaptureClosed` /
    `InjectResult`.
  - `pub enum SessionError { PeerUid(u32), PeerPid(u32), Timeout, VersionMismatch(u32), Proto(ProtoError) }`.
  - `#[cfg(target_os = "linux")]`. Elsewhere the type exists and every call is `Unavailable`.
- **Test (first, failing):** `client::tests` (Linux):
  - `wrong_pid_is_refused`: a thread in the test process connects, and `expected_pid` is set to `pid+1`. The result
    is `Err(PeerPid(_))`.
  - `version_mismatch_is_reported`: the fake peer answers `HelloAck { proto: 2 }`, giving `Err(VersionMismatch(2))`.
  - `oversized_frame_closes_session`
  - `socket_dir_refuses_foreign_owner`: a `PathMeta`-style pure check over uid 0, mode 0700, for a user 1000 core
    gives `Err`.
- **Done when:** the tests pass and the unit gate passes (macOS builds the stub).

### Task P1b.13: `HelperBackend` over the session

- **Satisfies:** AC8 (Linux via helper), spec §5.2 ("`HelperBackend` implements `CaptureInjectBackend`")
- **Depends on:** P1b.12
- **Files:** `crates/aitm-proto-l4/src/backend/helper.rs` (create), `crates/aitm-proto-l4/src/backend/mod.rs`, `crates/aitm-proto-l4/src/guard.rs` (`scope_generation`), `crates/aitm-proto-l4/tests/hard_gates.rs` (test `exactly_one_production_wire_write` only: `backend/helper.rs` ×1 joins `backend/routed.rs` ×1 and `wire.rs` ×1, each pinned to exactly one; added 2026-11-01 by the p1b orchestrator on the Coder's Rule 10 report, same disposition as P1b.8; flagged for the security reviewer)
- **Change:**
  - `pub struct HelperBackend { session: Arc<HelperSession>, guard: Arc<L4Guard>, sent_gen: AtomicU64 }` implements
    `CaptureInjectBackend`.
    - `open_capture` sends `CaptureOpen` and returns a `CaptureSource` fed by a channel of that capture's `Frame`s.
      `next_frame` honours the read timeout. The `filter` argument is **not** sent: the helper builds its own.
    - `inject` sends `Inject` and waits up to 2 s for its `InjectResult`.
  - `L4Guard::scope_generation(&self) -> u64` is bumped by `add_runtime_scope`, `remove_scope` and `set_self_ports`.
  - Before each `CaptureOpen` / `Inject` whose generation differs from `sent_gen`, the backend sends `ScopeSet`
    first. It also sends it once at session start. **(Architect's call:** resend-before-use, so every frame the
    helper acts on was checked against the current scope; the core's own `admit_frame` still filters every received
    frame.)
- **Test (first, failing):** `helper::tests` (Linux), over a fake helper peer in a thread:
  - `scope_resent_after_change`: `add_runtime_scope`, then `inject` puts `ScopeSet` then `Inject` on the wire, in that
    order.
  - `inject_error_text_is_returned`: the peer answers `error: Some("target … is out of L4 scope")`, giving
    `Err(L4Error::WireWrite(..))` containing `scope`.
  - `capture_frames_arrive_in_order`
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.14: Linux request: pkexec, the file-caps path, progress, one-shot refusal

- **Satisfies:** AC16, AC17, AC20, AC22, AC23 (core halves), spec §2.3, §2.4 (one-shot), §5.1, §5.5
- **Depends on:** P1b.13; spike **S7** (exit codes). (S7) Answered; the mapping and the tests below are the
  corrected ones (spec §5.5 table). The original "126 dismissed, 127 failed" rule is wrong for the textual agent.
- **Files:** `crates/aitm-proto-l4/src/privilege/linux.rs`, `crates/aitm-proto-l4/src/privilege/state.rs`, `crates/aitm/src/lib.rs` (panel, 2026-11-01: `shutdown_signal` consults the prompt hold; the fix task), `crates/aitm-proto-l4/src/privilege/derive.rs` (panel, 2026-11-01: the `last_session_error` row; the fix task), `crates/aitm/src/tui.rs` (panel 2, 2026-11-01: the `aitm tui` shutdown arm consults the hold, one line, plus threading the hold into `tui::run`; granted to p1b from P6.3)
- **Change:**
  - `pub trait Spawner: Send + Sync { fn spawn(&self, argv: &[OsString]) -> io::Result<Box<dyn Child>>; }` and
    `pub trait Child: Send { fn id(&self) -> u32; fn try_wait(&mut self) -> io::Result<Option<ChildExit>>; fn
    stderr_tail(&mut self) -> String; fn kill(&mut self); }` with `pub enum ChildExit { Exited(i32), Signaled(i32) }`
    (S7: the watcher must tell "exit 127" from "killed by SIGINT"; the real implementation reads
    `ExitStatus::code()` and `ExitStatusExt::signal()`). The real spawner gives the child **a pipe for stderr** and
    leaves stdin and stdout inherited (S7: the textual prompt goes to the controlling terminal, not to stdio, so the
    pipe costs nothing and lets the core classify the failure text); a drain thread copies the pipe into a bounded
    tail buffer (last 4 KiB, **Architect's call**) for as long as the child lives, because the helper inherits that
    stderr and must never block on a full pipe. `stderr_tail` returns the buffer.
  - `pub struct HoldCount` (`Clone`; clones share one counter) with `pub fn hold(&self) -> HoldToken`, `pub fn
    is_held(&self) -> bool` and `pub fn count(&self) -> usize`, and `pub struct HoldToken` whose `Drop` lowers the
    count, both in `privilege/linux.rs` (Panel 3, 2026-11-01: replaces the `SignalGuard` trait and its `Box<dyn Any +
    Send>` token, deleted in fix task C; the only operation is `hold`, so nothing can install an ignore through it)
    (S7; corrected by the panel, 2026-11-01, replacing the `sigaction` design and the leaf-crate follow-up). **The Ctrl-C hold lives in the `aitm`
    binary.** `aitm` already owns SIGINT through tokio's `ctrl_c` (`crates/aitm/src/lib.rs` `shutdown_signal`), so
    the signal never kills the process; the shutdown future resolving is what stops the core. The `PrivilegeState`
    owns a `HoldCount` that `hold()` raises (a `HoldToken`) while a pkexec child is alive and the dropped token lowers
    when the child ends or the helper connects; `shutdown_signal` is given that count and, on Ctrl-C while it is non-zero, logs
    `Ctrl-C cancelled the packet-capture prompt; the core keeps serving` and keeps waiting for the next signal. The
    child has the default disposition after exec, dies of the SIGINT, and `classify_exit_full` records `dismissed`. Never
    `SIG_IGN` (inherited across `execve`, it makes the prompt un-cancellable). No `sigaction`, no `unsafe`, no new
    crate; the shape of the count is the builder's. **(Architect's call:** during that window Ctrl-C cancels the
    prompt and does not shut the core down; see Questions, Q6 stays flagged for Matt.)
    (Panel 2, 2026-11-01) Both serving shutdown futures consult the hold: `shutdown_signal` in `lib.rs` (`aitm`,
    `aitm web`) and the `aitm tui` select arm in `tui.rs`, which receives the hold through `tui::run`. On a held
    Ctrl-C each arm calls `pub fn PrivilegeState::cancel_prompt(&self)`, which kills the live launcher child (SIGINT,
    so `classify_exit_full` records `dismissed`), so a Ctrl-C delivered to the core alone (no shared foreground process
    group) still ends the prompt and never waits out the 300 s timeout; with no child alive it is a no-op. The
    watcher thread carries an unwind guard (a drop guard) that moves a still-`pending` request to `failed` and
    releases the hold if the thread panics, so a panic never leaves the request `pending` or the hold raised
    (**Architect's call** on `failed` as the terminal state).
    (Panel 3, 2026-11-01) The guard's `failed` message is exactly `The packet-capture request ended unexpectedly`
    (`msg::ENDED_UNEXPECTEDLY`), and on a panic the guard also kills the launcher child best-effort.
    `cancel_prompt()` signals only the request's own launcher child, never a serving helper and never a helper
    started directly on the file-caps row; `Child::interrupt()` sends SIGINT on Linux and is a no-op off Linux (no
    launcher exists there). The prompt-child slot `cancel_prompt()` reads is cleared only by the watch that set it
    (`Arc::ptr_eq` on the child), and the `watching` flag is owned by a watch generation, so a watch that outlives a
    newer request can neither unregister the newer child nor clear the newer watch's flag.
  - `pub(crate) fn classify_exit_full(exit: ChildExit, stderr: &str) -> (ExitClass, RequestState, String)` (pure;
    Panel 3, 2026-11-01: was `classify_exit(exit, stderr) -> (Progress, String)`; `ExitClass { Dismissed, AuthFailed,
    NoAgent, TimedOut, Other }` names the §5.5 row the watcher branches on, never the message text), the spec §5.5
    table:
    - `Exited(126)` → `Dismissed`, `"Approval was cancelled"` (graphical agent's Cancel);
    - `Exited(127)` with stderr containing `Got unexpected EOF while reading from controlling terminal` →
      `Dismissed`, `"Approval was cancelled"` (Ctrl-D at the textual prompt);
    - `Signaled(SIGINT)` → `Dismissed`, `"Approval was cancelled"` (Ctrl-C);
    - `Exited(127)` with `Not authorized` → `Failed`, `"Administrator authentication failed (wrong password or not
      authorized)"`;
    - `Exited(127)` with `Error creating textual authentication agent` → `Failed`, `"No password prompt could be
      shown here (no desktop session or terminal)"` (the request should have been `cannot_prompt`; this is the
      safety net, and the watcher logs one `warn` that the predicate and pkexec disagreed);
    - any other `Exited(n)` or `Signaled(_)` → `Failed`, `"The packet-capture helper did not start (pkexec exit
      <n>)"` (for a signal, `signal <n>`).
  - (Panel, 2026-11-01; the fix task.) `LinuxInputs` gains `last_session_error: Option<SessionError>`, set by the
    watcher when the handshake fails after the child connected and cleared when a session connects. `derive_linux`
    gains a row after the connected-session row (`running`) and before the file-caps row: no session connected and a
    last error gives `helper.status` `version_mismatch` for `SessionError::VersionMismatch(peer)` with `detail` naming
    both proto numbers (ours and the peer's), and `unknown` for any other `SessionError` with `detail` carrying its
    text. The request's progress is `failed`; its message is the builder's wording (outside the P1b.3 tripwire) and
    must name neither a command nor the socket path. `failed` is never a `Helper.status` value (spec §5.2).
    (Panel 2, 2026-11-01) The carrier type is `pub enum SessionFailure { VersionMismatch(u32), Protocol(String) }`
    in `privilege/derive.rs` (the name `SessionError` is taken by `helper::client`); the watcher maps
    `SessionError::VersionMismatch(theirs)` to `VersionMismatch(theirs)` and every other `SessionError` to
    `Protocol(<its text, bounded by TEXT_BOUND>)`. `Protocol(_)` reads `helper.status: unknown` with the text in
    `detail`; only `VersionMismatch(_)` reads `version_mismatch`.
  - `pub fn request_linux(cfg, inputs: &LinuxInputs, spawner: &dyn Spawner, hold: &HoldCount, socket: &Path,
    display_set: bool) -> LinuxRequest` (panel, 2026-11-01: the signature as landed; Panel 3, 2026-11-01: `hold:
    &HoldCount` replaces `signal: &dyn SignalGuard`; the checks run in this order):
    - `lifetime == OneShot` gives `CannotPrompt`, `"a one-shot command exits before the helper could serve it; set
      l4.privilege.request: at_start or use Allow in the TUI or web UI"`, and nothing is spawned.
    - Not packaged (panel, 2026-11-01: evaluated before the prompt predicate): the helper is not at the policy path,
      or its chain is not root-owned, or the policy file is missing, or `pkexec` is absent gives `CannotPrompt` with
      the `package` install label.
    - `!prompt_possible` gives `CannotPrompt`, `"No password prompt can be shown here (no desktop session or
      terminal)"`. That message names no doc until P5.4 is unblocked.
    - Otherwise spawn exactly `["/usr/bin/pkexec", LINUX_HELPER_PATH, "serve", "--connect", <socket>]` (panel,
      2026-11-01: the launcher by absolute path, `PKEXEC_PATH`, never a `PATH` lookup) with the child's environment
      cleared and only `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY` passed through (no `SHELL`: pkexec refuses a value
      absent from `/etc/shells`; no `LANG`/`LC_*`: the stderr literals `classify_exit_full` matches stay the English ones
      S7 measured), and return `Pending`.
      The message is `"Waiting for administrator approval in the polkit dialog"` when `DISPLAY` or
      `WAYLAND_DISPLAY` is set, else `"Enter an administrator password in the terminal running aitm"`. The messages
      are the Architect's call.
  - A watcher thread moves the progress (S7 mapping):
    - the session passes `accept_checked` (pid == child id): `Approved`; the stderr drain keeps running for the
      helper's lifetime, the prompt hold is released;
    - the child ends before connecting: `classify_exit_full(exit, stderr_tail)` as above, then the hold is released;
    - (panel, 2026-11-01) the handshake fails after connecting: `last_session_error` is set, the progress is
      `failed`, the hold is released;
    - 300 s on the injected clock: kill and `Failed`, `"No approval within 5 minutes"`.
  - File-caps row: `state.backend()` spawns `[<helper path>, "serve", "--connect", <socket>]` directly, without
    pkexec, on first use. (Panel, 2026-11-01) It requires `root_owned_chain` on the helper's path and is serving-only:
    a one-shot on that row refuses (the helper is not wired) and spawns nothing. When any helper session ends, the
    cache is marked dirty so the next `report()` re-probes and capture returns to `needs_approval` (spec §2.1).
    (Panel 2, 2026-11-01) `probe` runs only for a candidate with `root_owned_chain`, and its result is cached per
    path identity (device, inode, size, mtime, ctime) for the process lifetime (`linux::ProbeCache`).
  - `pkexec` is never given any path but `LINUX_HELPER_PATH`.
- **Test (first, failing):** `linux::tests` with a fake spawner and clock:
  - `one_shot_refuses_and_spawns_nothing`
  - `no_prompt_is_cannot_prompt_and_spawns_nothing`
  - `pkexec_argv_is_policy_path_only`: with `helper_path: /home/u/aitm-l4-helper` configured, no spawned argv
    contains `/home/u`. The argv is the literal above.
  - `exit_126_is_dismissed` (the graphical case; stderr `Error executing command as another user: Request
    dismissed`)
  - `exit_127_not_authorized_is_failed` (S7): stderr `polkit-agent-helper-1: pam_authenticate failed: Authentication
    failure\n==== AUTHENTICATION FAILED ====\nError executing command as another user: Not authorized` gives
    `Failed` and a message containing `wrong password`
  - `exit_127_eof_is_dismissed` (S7): stderr containing `Got unexpected EOF while reading from controlling terminal`
    followed by the same FAILED lines gives `Dismissed`, `"Approval was cancelled"`
  - `no_agent_text_is_failed` (S7): exit 127 with `Error creating textual authentication agent: Error opening
    current controlling terminal for the process (`/dev/tty'): No such device or address` gives `Failed` and a
    message containing `No password prompt`
  - `sigint_is_dismissed` (S7): `Signaled(2)` gives `Dismissed`, `"Approval was cancelled"`
  - `other_exit_is_failed`: `Exited(2)` gives `"The packet-capture helper did not start (pkexec exit 2)"`
  - `sigint_handler_installed_not_ignored` (S7; panel 2026-11-01: the name is kept, it now pins the hold count): with
    a `HoldCount` (Panel 3, 2026-11-01: was "a counting `SignalGuard`"), `count()` is 1 from spawn until the child ends or connects, and 0 after; the fake
    refuses (panics) on any `SIG_IGN`-style call. Nothing is spawned without a hold.
  - `held_ctrl_c_keeps_serving` (panel, 2026-11-01; in `crates/aitm/src/lib.rs`, pure): the shutdown decision for a
    Ctrl-C with the hold count at 1 is "keep serving" and its log line is exactly `Ctrl-C cancelled the
    packet-capture prompt; the core keeps serving`; with the count at 0 it is "shut down". (Panel 2, 2026-11-01:
    delivered by the Tester as `lib.rs::tests::held_ctrl_c_keeps_serving`; this is the Ctrl-C literal test.)
  - `held_ctrl_c_alone_cancels_the_prompt` (panel 2, 2026-11-01; `state::tests`, fake spawner): with a child alive
    and the hold at 1, `cancel_prompt()` kills the fake child, the progress reads `dismissed` with `"Approval was
    cancelled"`, and the hold is 0; with no child it changes nothing. (Name the Architect's; the fix-task coder
    reports the delivered name.)
  - `watcher_panic_releases_hold_and_ends_pending` (panel 2, 2026-11-01; `state::tests`): a fake child whose
    `try_wait` panics leaves the request `failed`, not `pending`, and the hold at 0. (Panel 3, 2026-11-01) The message is
    exactly `The packet-capture request ended unexpectedly`; the prompt-child slot and `watching` are clear.
  - `tui_shutdown_arm_consults_the_prompt_hold` (Panel 3, 2026-11-01; `crates/aitm/src/main.rs`): a source tripwire,
    the `aitm tui` select arm in `crates/aitm/src/tui.rs` goes through `interrupt_unless_held` with the hold.
  - `the_prompt_hold_handed_to_the_shutdown_arms_is_the_states` (Panel 3, 2026-11-01; `crates/aitm/src/main.rs`): the
    `HoldCount` the binary hands both shutdown arms is a clone of the `PrivilegeState`'s own (`sigint_hold()`), so a
    hold taken by a request is seen by the arms: `count()` reads 1 on both after one `hold()` on the state's.
  - `linux_session_failure_is_version_mismatch_until_a_session_connects` (panel, 2026-11-01; `derive::tests`;
    panel 2: the delivered name, was `version_mismatch_after_handshake_failure`): no session, `last_session_error =
    Some(SessionFailure::VersionMismatch(2))` gives `helper.status == "version_mismatch"` and a `detail` containing
    both `1` and `2`; a connected session gives `"running"` whatever the last error.
  - `protocol_failure_is_unknown_with_detail` (panel 2, 2026-11-01; `derive::tests`): no session,
    `last_session_error = Some(SessionFailure::Protocol(..))` gives `helper.status == "unknown"` with the error text
    in `detail`.
  - `pkexec_env_is_cleared_but_for_display` (panel, 2026-11-01): the spawned child's environment is exactly the
    subset of `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY` that is set in the core; `SHELL`, `LANG` and `LC_ALL` are
    absent. Proven live only by the [linux-ci] run (P2.8).
  - `stderr_pipe_is_drained_after_approval`: a fake child writing 64 KiB to stderr after `Approved` never blocks and
    `stderr_tail` is at most 4 KiB.
  - `timeout_is_failed_after_300s`
  - `file_caps_helper_spawns_directly`: the argv starts with the candidate path, not `pkexec`.
- **Done when:** the tests pass and the unit gate passes.

### Task P1b.15: binary wiring

- **Satisfies:** AC1, AC2, AC7, AC24 (wiring), spec §2.4 (`at_start`, warn line, one-shot)
- **Depends on:** P1b.14
- **Files:** `crates/aitm/src/wire.rs`, `crates/aitm/src/main.rs`, `crates/aitm-proto-l4/src/language.rs` (constructor callers only), `crates/aitm-proto-l4/src/lib.rs` (panel, 2026-11-01: two re-exports)
- **Change:**
  - `Features` gains `l4_privilege_state: Option<Arc<PrivilegeState>>`. When `None`, `assemble_with` builds one
    from `features.l4`. The existing `l4_privilege` test override maps to a fixed prober.
  - `assemble_with` always registers `PrivilegePlugin`, whether or not `l4.enabled`, and builds `L4Module::with_shared`
    over the same state.
  - The warn line is replaced by `startup_line(&state.report())`: one `warn!`, emitted only when `Some`.
  - `main.rs`:
    - builds the state before `l4_shared` and passes `state.backend()` to `L4Language::new` (line ~404);
    - sets `ProcessLifetime::OneShot` on the one-shot CLI path;
    - after assembly, calls `state.request()` once when `request == AtStart` and capture is `NeedsApproval`.
      `pub fn should_request_at_start(mode: RequestMode, r: &PrivilegeReport) -> bool` holds that decision.
- **Test (first, failing):** in `wire.rs` tests:
  - `privilege_verbs_registered_with_l4_off`: with `l4.enabled: false`, the registry has `l4.privilege` and
    `l4.privilege.request` and no other `l4.*` name.
  - `l4_on_registers_24_l4_names`: 22 module names + 2 (panel, 2026-11-01: was "25 parity names + 2 = 27"; the
    parity verbs are not on this branch. The 3 bundled Rhai `l4.*` commands make 27 names in `tools/list` on a core
    with the catalogue, but they are not registry entries this test counts).
  - In `main.rs` tests, or the new `privilege::state` tests: `should_request_at_start(AtStart, row6) == true`,
    `(Manual, row6) == false`, `(AtStart, available) == false`.
- **Done when:** the tests pass and the unit gate passes (sandbox). The Terminal full gate is deferred to P1b.16.

### Task P1b.16: the two tool-contract pins

(Panel, 2026-11-01: "three" became two. `bus-fixture.json` and `tester_shell.rs` were deleted on `main` by #244; the
TUI is live-only, and `tui_live_bus.rs` compares `CORE_TOOLS` to the live `tools/list`.)

- **Satisfies:** AC24 (contracts list both verbs)
- **Depends on:** P1b.15
- **Files:** `crates/aitm/tests/frontends.rs` (`EXPECTED_TOOLS` `[&str; 62]` → `[&str; 64]`, two names), `crates/aitm-tui/src/lib.rs` (`CORE_TOOLS` + `"l4.privilege"`, `"l4.privilege.request"` with a comment naming this spec)
- **Change:** pins only. The counts above are the values at branch cut. If `main` moved, add 2 to whatever they read.
- **Test (first, failing):** before the edit, `cargo test --offline -p aitm --test frontends` fails on the set
  difference (quote it). After the edit, it passes. In the Terminal: `cargo test -p aitm --test tui_live_bus` passes
  (the TUI pin fails only there, since it binds a port). (Panel 2, 2026-11-01) The Terminal `cargo test -p aitm
  --test l4_cua_tui` result (the AC27 branch fixed in e79aeab0) is quoted in the Review log at ready time.
- **Done when:** the full gate passes in the Terminal.

### Task P1b.17: live core checks on the rig (e2e)

- **Satisfies:** AC1, AC2, AC4, AC5 (live, once p7 is on `main`), AC10, AC20, AC23, AC24 (live); updates parity A9
- **Depends on:** P1b.16
- **Files:** `tests/e2e/l4/test_privilege_core.py` (create), `tests/e2e/l4/test_l4_parity_core.py`, `tests/e2e/l4/test_l4_parity_priv.py`
- **Change:**
  - A new script `test_privilege_core.py`:
    - header `# e2e: tier=T1 surface=l4 needs=l4`;
    - exit 0 pass, 1 fail, 77 skip;
    - the soft-assert battery style of `test_l4_capture_flow.py`, run as operator and as agent.
  - Its checks:
    1. AC1: `l4.privilege` answers within 500 ms with `capabilities.capture.state == "needs_approval"`, an integer
       `checked_at`, and on macOS `intercept.state == "unsupported"`. `how.kind` must be `"package"` with
       `macos_app_path: /nonexistent.app`, and `"app_action"` only on the signed Mac (P3.13).
    2. AC2: a second config with `l4.enabled: false` gives `enabled: false` and three `unsupported`.
    3. AC4: `l4.capture.status` has `code == "needs_privilege"`, `captures == []` and `privilege` present.
       `l4.intercept.status` code by OS.
    4. AC10: with `macos_app_path` set to `/nonexistent.app`, then to `/tmp/Aitmproxy-dev-l4priv.app` (a snap-dev
       bundle), the operator request gives `outcome == "cannot_prompt"`. `pgrep -nf "open -a"` after it finds no
       process the script did not start.
    5. AC24: the rig core's log has exactly one line starting `L4 enabled; packet capture needs approval: `, and it
       matches neither the AC3 regex nor the token. The log is deleted afterwards.
    6. AC5, skipped with exit 77 until `tools/list` and `agent.status` show p7's behaviour. Under `ask`: the agent
       call is refused at once, `agent.pending` stays empty, and no Aitmproxy launch (`pgrep -x Aitmproxy` unchanged)
       / no `pkexec` within 2 s. Under `auto`: the text starts with `` `l4.privilege.request` refused: the agent
       policy is ``. Under `all`: the text starts with `` `l4.privilege.request` refused: `` and contains `operator`
       (see Questions: the spec's `all` literal does not match the current gate text). `agent.activity` shows the
       agent caller.
    7. Linux only, AC20 and AC23 in the [linux-ci] container: the tarball helper under `$HOME` gives `how.kind ==
       "package"` and the request gives `cannot_prompt`. With `DISPLAY` and `WAYLAND_DISPLAY` unset and **no
       controlling terminal** (S7: the core is started under `setsid`, so `open("/dev/tty")` fails; stdin being a
       pipe alone is not enough, the textual agent would still prompt on the terminal), the request gives
       `cannot_prompt`. The one-shot `aitm l4.privilege.request` refuses with the §2.4 text. In all three cases,
       `pgrep -x pkexec` finds nothing.
  - `test_l4_parity_core.py`: drop the literal `R_CAP`. Assert `reason == "packet capture is not allowed yet (" +
    privilege.capabilities.capture.how.label + ")"` and that the start error equals `L4 unavailable: ` + `reason`.
    The intercept literal becomes `"in-path interception is Linux only"`. The `l4.*` count becomes 24 module/binary
    verbs (panel, 2026-11-01: was 27; 27 only with the 3 bundled Rhai `l4.*` commands on a core with the catalogue).
  - `test_l4_parity_priv.py`: its blocked line becomes `blocked: needs approval: <reason>`.
- **Test first:** `python3 -m py_compile` all three. Against a rig built from `origin/main`, `test_privilege_core.py`
  exits 1 (no `l4.privilege`).
- **Live check [mac-any], rig on this branch (Terminal):** `test_privilege_core.py` exits 0 (77 on the AC5 block
  until p7), `test_l4_parity_core.py` exits 0, `test_l4_parity_priv.py` exits 77. **[linux-ci]:** the same three in
  the Fedora container, output quoted. (Panel 2, 2026-11-01) The Terminal `l4_cua_tui` run result is quoted in the
  Review log at ready time alongside these.
  (Panel 3, 2026-11-01) The first gated invoke after the privilege cache's 1 s TTL (`REPROBE_MS`) can pay the probe cost
  synchronously: on macOS that is `codesign --verify --strict` on the handoff bundle, bounded at 5 s (`TOOL_WAIT`).
  The `l4_cua_tui` wait bound is 20 s for that reason, not because the drive itself is slow; a run that trips it
  is a real failure. A background probe thread is the follow-up recorded after P1b.18.
  (Panel 3, 2026-11-01) The AC3 scan in `test_privilege_core.py` exempts exactly the two pinned §5.5 forms of the generic
  row, `The packet-capture helper did not start (pkexec exit <n>)` and `The packet-capture helper did not start
  (killed by signal <n>)` with `<n>` an integer, and nothing wider (the row's message names `pkexec` because the
  spec pins it verbatim; progress messages are otherwise outside the P1b.3 tripwire).
- (Panel, 2026-11-01) The `[linux-ci]` half (AC20, AC23 and the Linux cells of `test_privilege_core.py`) is
  re-scoped to P2.8 [linux-ci], the helper unit, which builds the container rig this needs (`cis-lab` has none yet:
  podman, `--systemd=always --privileged`), pending Matt's acceptance (Review log row "P1b.17 [linux-ci]"). Until
  accepted, the p1b PR body states that the Linux request path is unit-tested only.
- **Done when:** the checks pass with output quoted and the unit gate passes (the [linux-ci] half per the line above).

### Task P1b.18: tool docs

- **Satisfies:** L4PAR-AC32 kept true (24 verbs + 3 bundled scripts = 27 names; panel, 2026-11-01), G4 docs
- **Depends on:** P1b.17
- **Files:** `docs/research/mcp-tool-catalog.txt`, `aitmproxy-plugin/docs/tool-reference.md` (via `aitmproxy-plugin/scripts/gen-tool-reference.mjs` if it is the generator), `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md` (one line: an agent can read `l4.privilege`; only an operator can request it)
- **Test:** the unit (e) AC32 diff script reports the 24 module/binary `l4.*` verbs and the 3 bundled Rhai `l4.*`
  commands (27 names; panel, 2026-11-01) in both files.
- **Done when:** the diff check passes. **Unit close:** a Tester run on the whole unit and the panel. AC5's live half is
  re-run after p7 merges (orchestrator re-dispatches P1b.17's AC5 block).

**Follow-ups Panel 3, 2026-11-01, p1b, not blocking the unit):** a background probe thread, so no gated invoke pays the
privilege probe synchronously after the 1 s TTL (today the first one after the TTL can wait up to the 5 s
`codesign` bound on macOS; P1b.17 note). Orchestrator to schedule after p1b merges; a spec amendment to §2.1's
cache sentence goes with it.

---

## Unit (p2) helper crate: `feat/l4priv-helper`

`crates/aitm-l4-helper`, `version.workspace = true`, `[lints] workspace = true`, no `unsafe`. Its normal-edge
dependency tree contains `aitm-proto-l4` and its own small dependencies only: no Rhai, no `aitm-mcp`, no HTTP.

### Task P2.1: crate skeleton and argv parsing

- **Satisfies:** spec §1 (subcommands), §5.1 step 1 (argv), Constraints (one version)
- **Depends on:** p1a merged
- **Files:** `crates/aitm-l4-helper/Cargo.toml`, `crates/aitm-l4-helper/src/main.rs`, `crates/aitm-l4-helper/src/cli.rs` (create), root `Cargo.toml` (`members` + `aitm-l4-helper = { path = … }`), `Cargo.lock`
- **Change:**
  - `pub enum Mode { BpfPermissions { dry_run: bool }, BpfRevert { dry_run: bool }, Serve { connect: PathBuf },
    Probe, Version }`.
  - `pub fn parse(args: &[OsString]) -> Result<Mode, UsageError>`: exact subcommands; `serve` only as
    `serve --connect <abs path ≤ 107 bytes>`; no extra arguments; no environment read.
  - `main` dispatches and exits non-zero on `UsageError`. `version` prints `aitm-l4-helper <CARGO_PKG_VERSION>`.
- **Test (first, failing):** `cli::tests`:
  - `["serve","--connect","/run/user/1000/aitm/l4-helper-1.sock"]` gives `Serve`.
  - A relative path is an `Err`.
  - A 108-byte path is an `Err`.
  - `["serve","--connect","/a","x"]` is an `Err`.
  - `["bpf-permissions","--dry-run"]` gives `BpfPermissions { dry_run: true }`.
  - `["serve","--dry-run"]` is an `Err`.

  Tripwire, quoted in the report: `cargo tree -p aitm-l4-helper -e normal --offline | grep -E
  "rhai|aitm-mcp|aitm-proto-http|hyper"` prints nothing.
- **Done when:** the tests pass and the Rust gate passes.

### Task P2.2: the bpf apply/revert plan (pure)

- **Satisfies:** AC6, AC14 (unit halves), spec §3.1, T2
- **Depends on:** P2.1; spike **S4** written up, with the group decided
- **Files:** `crates/aitm-l4-helper/src/bpf.rs` (create)
- **Change:**
  - Types:
    - `pub struct NodeFacts { pub n: u32, pub is_char: bool, pub rdev: u64, pub uid: u32, pub gid: u32, pub mode:
      u32 }`
    - `pub fn bpf_major(rdev: u64) -> u32` (macOS `major()` = `(rdev >> 24) & 0xff`)
    - `pub struct ConsoleUser { pub name: String, pub is_admin: bool }`
    - `pub enum Step { CreateGroup, Chown { n: u32, gid: u32 }, Chmod { n: u32, mode: u32 }, Refuse { n: u32, why:
      String }, AddMember(String), RemoveMember(String), WriteReceipt, DeleteReceipt }`
  - `pub fn plan_apply(nodes: &[NodeFacts], group_gid: Option<u32>, prior: Option<&Receipt>, console:
    Option<&ConsoleUser>) -> Vec<Step>`:
    - `CreateGroup` comes first if the gid is absent.
    - Each node whose type or major differs from `/dev/bpf0`'s gets `Refuse`.
    - `AddMember` only when `prior` is `None` and the console user is an admin.
  - `pub fn plan_revert(nodes: &[NodeFacts], prior: Option<&Receipt>) -> Vec<Step>`:
    - root:wheel 0600 for each valid node;
    - `RemoveMember` for exactly `prior.members_added`;
    - `DeleteReceipt`.
  - `pub fn render(steps: &[Step]) -> Vec<String>` for `--dry-run`.
- **Test (first, failing):** `bpf::tests`:
  - `foreign_major_is_refused`
  - `non_char_is_refused`
  - `receipt_present_adds_nobody`
  - `non_admin_console_adds_nobody`
  - `revert_removes_only_members_added`: the receipt holds `["matt"]` and the group holds `["matt","wsuser"]`, so the
    steps hold exactly one `RemoveMember("matt")`.
  - `render` literal: `["create group access_bpf", "chown root:access_bpf /dev/bpf0", "chmod 0660 /dev/bpf0", …]`.
- **Done when:** the tests pass and the Rust gate passes.

### Task P2.3: the bpf executor and receipt write

- **Satisfies:** AC6, AC14 (helper half), spec §3.1 steps 1–5, T2
- **Depends on:** P2.2
- **Files:** `crates/aitm-l4-helper/src/bpf_exec.rs` (create)
- **Change:**
  - `pub trait MacSys`: `list_nodes`, `precreate_nodes`, `chown`, `chmod`, `group_gid`, `run_dseditgroup(argv:
    &[&str]) -> Result<(), String>`, `console_user`, `read_receipt`, `write_receipt_atomic`, `delete_receipt`, and
    `receipt_dir_meta`. The real implementation is std `fs` and `os::unix::fs::chown`.
    - `precreate_nodes` opens `/dev/bpf0..255` read-only until 256 exist.
    - `dseditgroup` is run at `/usr/sbin/dseditgroup` with fixed argv.
    - The console user comes from the owner of `/dev/console`, with admin membership from `dseditgroup -o
      checkmember -m <user> admin`.
  - `pub fn apply(sys: &dyn MacSys, version: &str, now_ms: u64) -> Result<Receipt, String>` and
    `pub fn revert(sys: &dyn MacSys) -> Result<(), String>`.
  - `fn ensure_receipt_dir(meta) -> Result<(), String>` refuses a symlink, or a directory not owned by root:wheel
    with mode 0755.
- **Test (first, failing):** `bpf_exec::tests` with a recording fake `MacSys`:
  - `symlinked_receipt_dir_writes_nothing`
  - `dseditgroup_argv_exact`: the create argv is `["/usr/sbin/dseditgroup","-o","create","-r","Aitmproxy packet
    capture","access_bpf"]` and the add argv is `["/usr/sbin/dseditgroup","-o","edit","-a","matt","-t","user",
    "access_bpf"]`.
  - `receipt_fields`: `schema 1`, `group "access_bpf"`, `nodes 256`, `members_added ["matt"]`, and the
    `helper_version` equals the argument.
  - `second_apply_carries_members_forward`
- **Done when:** the tests pass and the Rust gate passes.

### Task P2.4: unified-log line and the macOS mode dispatch

- **Satisfies:** spec §3.1 step 6, quiet logs
- **Depends on:** P2.3
- **Files:** `crates/aitm-l4-helper/src/log.rs` (create), `crates/aitm-l4-helper/src/main.rs`, `crates/aitm-l4-helper/Cargo.toml` (macOS-target `oslog`, fetched in the Terminal)
- **Change:**
  - `pub fn run_line(mode: &str, r: &Result<Receipt, String>) -> String`: one line, no user input echoed beyond user
    names. It is logged with subsystem `com.mrbrutti.aitmproxy.l4-helper`.
  - `main` runs `apply` or `revert`. The `--dry-run` variants print `render` and change nothing, and they run as any
    user.
- **Test (first, failing):** `log::tests::run_line_literal`: an Ok receipt gives `"bpf-permissions applied: 256
  nodes, group access_bpf, added matt"`.
- **Live check [mac-any]:** `target/debug/aitm-l4-helper bpf-permissions --dry-run` exits 0 and prints the plan.
  `stat -f '%Sp %Su %Sg' /dev/bpf0` is `crw------- root wheel` before and after (quoted).
- **Done when:** the test passes, the live check passes, and the Rust gate passes.

### Task P2.5: `probe` subcommand

- **Satisfies:** spec §2.2 (file-caps row input), AC17
- **Depends on:** P2.1 (independent of P2.2–P2.4)
- **Files:** `crates/aitm-l4-helper/src/probe.rs` (create), `crates/aitm-l4-helper/src/main.rs`
- **Change:** `pub fn probe_json(cap_eff: Option<u64>, bpf_rw: Option<bool>) -> String`: one JSON line
  `{"cap_net_raw":bool,"cap_net_admin":bool,"bpf_rw":bool|null,"version":"…"}`. Linux reads `/proc/self/status` via
  `aitm_proto_l4::privilege::linux::parse_cap_eff`.
- **Test (first, failing):** `probe::tests::cap_net_raw_bit`: `probe_json(Some(0x2000), None)` contains
  `"cap_net_raw":true,"cap_net_admin":false`.
- **Done when:** the test passes and the Rust gate passes.

### Task P2.6: `serve` start-up: invoking user, privilege drop, path and peer checks, death signal

- **Satisfies:** AC16, AC18 (path refusals, `PKEXEC_UID`), AC19, spec §5.1, T3
- **Depends on:** P2.1; spike **S7** written up (the drop order that keeps `pcap` working). (S7) Answered: the spec
  §5.1 order works as written and is necessary; details below.
- **Files:** `crates/aitm-l4-helper/src/serve.rs` (create), `crates/aitm-l4-helper/Cargo.toml` (Linux-target `caps`, and `nix` with `user,process,prctl,socket,fs`)
- **Change:**
  - `pub fn invoking_user(real_uid: u32, pkexec_uid: Option<&str>) -> Result<u32, String>` (pure).
    `PKEXEC_UID` is trusted only when `real_uid == 0`. Root without it is an `Err`.
  - `pub fn check_socket_path(sock: &PathMeta, dir: &PathMeta, invoking: u32) -> Result<(), String>` (pure): the
    socket is a socket and not a symlink; the directory is owned by the invoking user, mode 0700, and not a symlink.
  - `fn drop_to(user: u32, gid: u32) -> Result<(), String>` (Linux) follows spec §5.1 step 3 in S7's proven order,
    then sets `no_new_privs`. (S7) In `caps`/`nix` terms, in this order: `caps::drop(None, CapSet::Bounding, cap)`
    for every capability except `NET_RAW` (while `CAP_SETPCAP` is still held; all 40 succeed on 6.8);
    `caps::clear(None, CapSet::Ambient)`; `prctl(PR_SET_KEEPCAPS, 1)` (**mandatory**: without it the `caps::set`
    below fails `EPERM` and the helper has no capability left); `nix::unistd::setgroups(&[gid])` (**not**
    `initgroups`, which keeps the admin group `sudo`/`wheel`); `setresgid(gid, gid, gid)`; `setresuid(uid, uid,
    uid)`; `caps::set(None, CapSet::Permitted, {NET_RAW})` and `caps::set(None, CapSet::Effective, {NET_RAW})`;
    `caps::clear(None, CapSet::Inheritable)`; `prctl(PR_SET_KEEPCAPS, 0)`; `prctl(PR_SET_NO_NEW_PRIVS, 1)`. `gid` is
    the invoking user's primary gid from `getpwuid`. `CAP_NET_RAW` alone suffices for libpcap on `lo`; nothing asks
    for `CAP_NET_ADMIN`.
  - (S7) `PKEXEC_UID` is a decimal string; `invoking_user` parses it with `str::parse::<u32>` and any other form is
    an `Err`.
  - `pub fn startup(args, env_pkexec_uid) -> Result<UnixStream, String>` follows steps 1–6 exactly:
    1. record `getppid`;
    2. determine the user;
    3. drop;
    4. check the path;
    5. connect, and check the peer uid equals the invoking user;
    6. set `PR_SET_PDEATHSIG(SIGKILL)` and re-check `getppid`. (S7) **Strictly after step 3**: the kernel clears the
       parent-death signal during the credential change (the task becomes non-dumpable), so a signal armed before
       the drop reads back as 0 and the helper would outlive the core. A debug assertion reads
       `PR_GET_PDEATHSIG` back and expects `SIGKILL`.

    (S7) The helper starts with `cwd` `/root`, no `XDG_RUNTIME_DIR`, `TERM` or `DISPLAY` in its environment, and
    every fd above 2 closed; it uses nothing but argv and `PKEXEC_UID`. A failure exits non-zero before any other
    I/O. On non-Linux, `serve` exits non-zero with "serve is Linux only in
    Phase 1".
- **Test (first, failing):** `serve::tests`:
  - `invoking_user(1000, Some("0")) == Ok(1000)`
  - `invoking_user(0, Some("1000")) == Ok(1000)`
  - `invoking_user(0, None)` is an `Err`
  - `check_socket_path` with the directory owned by uid 1001 for invoking 1000 is an `Err`; mode 0755 is an `Err`; a
    symlinked socket is an `Err`; an owned 0700 directory is `Ok`
  - `invoking_user(0, Some("1000x"))` and `invoking_user(0, Some(""))` are `Err` (S7: decimal string only)
- **Done when:** the tests pass and the Rust gate passes.

### Task P2.7: `serve` loop: handshake, scope, capture, inject

- **Satisfies:** AC18 (scope refusal by the real helper, oversized exit), AC8 (Linux), spec §5.2, §5.3
- **Depends on:** P2.6
- **Files:** `crates/aitm-l4-helper/src/serve_loop.rs` (create), `crates/aitm-l4-helper/src/main.rs`
- **Change:**
  - `pub trait Wire: Send { fn open(&self, iface: &str, filter: Option<&str>, timeout: Duration) -> Result<Box<dyn
    CaptureSource>, String>; fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), String>; fn inject_local(&self,
    ipv4_packet: &[u8]) -> Result<(), String>; fn link(&self, iface: &str) -> LinkType; fn local_addrs(&self) ->
    Vec<IpAddr>; }`. The real implementation is `pcap` for `open`/`inject`, and for `inject_local` (S7) a
    `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` with `IP_HDRINCL` set, `sendto` the IPv4 packet (Ethernet header
    stripped) to its own destination address; `local_addrs` lists the host's interface addresses (`nix::ifaddrs`)
    plus 127/8.
  - `pub fn inject_path(target: &InjectTarget, local: &[IpAddr]) -> InjectPath` (pure): `Local` when the IPv4
    destination is in 127/8 or in `local`, else `Interface` (S7: a `pcap_inject` frame on `lo` has no route and is
    dropped as a martian before any local socket sees it; the raw-IP path goes through `ip_output` with a route and
    is still seen by the `lo` capture, so W3's `injected: true` holds).
  - `pub fn serve_loop(stream: impl Read + Write, wire: &dyn Wire, version: &str) -> Result<(), ServeExit>`:
    - `Hello` gives `HelloAck { caps: ["CAP_NET_RAW"] }`.
    - `ScopeSet` replaces the `HelperGuard`.
    - `CaptureOpen` gives `capture_filter(iface)?` then `wire.open(iface, filter)`, and streams `Frame`s from a
      reader thread.
    - `Inject` gives `check_inject(..)` first (the guard precedes either path), then by `inject_path`: `Local` gives
      `wire.inject_local(ipv4 bytes)`, `Interface` gives `wire.inject(iface, frame)`; then `InjectResult`. (S7)
    - EOF, any `ProtoError`, or an `Inject` before any `ScopeSet` ends the loop.
- **Test (first, failing):** `serve_loop::tests` over an in-memory duplex with a recording fake `Wire`:
  - `inject_out_of_scope_is_refused_before_the_wire`: `ScopeSet 9000-9999`, then `Inject` to 8999, gives an
    `InjectResult.error` containing `scope`, and `wire.inject` is called 0 times.
  - `oversized_length_exits`
  - `inject_before_scope_exits`
  - `capture_open_outside_scope_is_refused`
  - `filter_is_helper_built`: the filter `wire.open` receives equals `scope_filter` of the helper's guard.
  - `loopback_inject_uses_raw_ip_not_pcap` (S7): `ScopeSet 9000-9999`, `Inject` of an Ethernet+IPv4+UDP frame to
    127.0.0.1:9053 calls `wire.inject_local` once with the 45-byte IPv4 packet (Ethernet header stripped) and
    `wire.inject` 0 times; a frame to an address outside `local_addrs` calls `wire.inject` once and `inject_local` 0
    times.
  - `out_of_scope_local_target_never_reaches_either_path`: `Inject` to 127.0.0.1:8999 calls neither.
  - `loopback_inject_reaches_udp_socket` (S7, Linux, `#[ignore]`; **Architect's call:** it needs `CAP_NET_RAW`, so it
    runs by name in P2.8 inside the container as the dropped helper's user with the file-caps copy, and the P2.8
    script asserts it passes): bind a UDP socket on 127.0.0.1:0, send a crafted IPv4+UDP packet to it through the
    real `inject_local`, and receive the payload `aitm-inject` within 1 s with `net.ipv4.conf.lo.route_localnet` read
    back as `0` (the test skips with a message if the sysctl is not 0, so the martian path can never come back
    unnoticed).
- **Done when:** the tests pass and the Rust gate passes.

### Task P2.8: Linux live checks (helper)

- **Satisfies:** AC8 (Linux, both modes), AC16, AC17, AC18 (live), AC19
- **Depends on:** P2.7; p1b merged (the core end). The helper is installed at the policy path by copying from the
  build into the container as root:root 0755, until p5's `.deb` exists. The policy file comes from p5 P5.1 if merged,
  else is copied from that branch for the check only. (S7) The rig is the one in "The rigs": `podman` installed
  in `cis-lab` by the script if absent, containers `--systemd=always --privileged`, Debian `polkitd pkexec dbus`,
  Fedora `polkit dbus-broker`, the `unix-chkpwd` AppArmor profile unloaded on the host for the Fedora run and reloaded
  after; `pkaction --verbose` on the action id as the first check. The test rule `49-aitm-test.rules` is installed
  for AC16 and removed before anything that must prompt.
- **Files:** `tests/e2e/l4/linux-privilege-rig.sh` (create; builds and starts the [linux-ci] container in `cis-lab`), `tests/e2e/l4/test_privilege_helper_linux.py` (create)
- **Change:** the script checks, as operator, on `lo`:
  1. AC16: with the test polkit rule, `l4.privilege.request` gives `pending`, then `capture.state == "available"` and
     `via == "helper"` within 10 s. `/proc/<helper pid>/status` shows the four `Uid:` fields equal to the tester uid,
     `CapEff: 0000000000002000`, `CapPrm: 0000000000002000`, `CapBnd: 0000000000002000`,
     `CapAmb: 0000000000000000` and `NoNewPrivs: 1`.
  2. Walk W (W1–W5) through the helper. (S7) W3–W4 to 127.0.0.1:9053 pass with `sysctl net.ipv4.conf.lo.route_localnet`
     printed and equal to `0` (the raw-IP path, P2.7); the script also runs `cargo test -p aitm-l4-helper --
     --ignored loopback_inject_reaches_udp_socket` in the container and quotes it.
  3. AC17: a copy with `cap_net_raw+ep` in a root-owned 0750 directory, named by `helper_path`, gives
     `helper.kind == "linux_cap_helper"`, capture `available` with no pkexec process ever seen (`pgrep -x pkexec`
     polled), and walk W passes again. Setting `helper_path` to `/tmp/x/aitm-l4-helper` never yields a `pkexec`
     whose argv contains `/tmp/x`.
  4. AC18 live: a test socket owner (a python `socket.socketpair`-free UDS server, not the core) starts the real
     helper as the tester user (`aitm-l4-helper serve --connect <sock>`), sends `ScopeSet 9000-9999` and `Inject` to
     8999, and gets an error containing `scope`; a parallel `tcpdump -i lo udp port 8999 -c 1 -W 1` (container
     root) times out with 0 packets. The oversized length makes the helper exit. A socket in a directory owned by
     another uid is refused at start, and so is a `/tmp/aitm-<uid>/` owned by another uid. `PKEXEC_UID=0` run
     unprivileged takes `getuid()`.
  5. AC19: `kill -9 <core pid>`, after which `pgrep -x aitm-l4-helper` is empty within 2 s.
- **Live check [linux-ci]:** both scripts exit 0 in the Fedora container and in the Debian container, output quoted.
- **Done when:** the checks pass with output quoted.

### Task P2.9: helper reaches `version.workspace` and the release version sync

- **Satisfies:** AC6 (`helper_version` == app version)
- **Depends on:** P2.1 (independent of P2.2–P2.8)
- **Files:** none expected beyond P2.1's `Cargo.toml`. If `scripts/sync-release-version.sh` needs to learn the new
  crate, **stop and report** (that file is the release driver's).
- **Test:** `cargo pkgid -p aitm-l4-helper` ends `@<workspace version>`. `target/debug/aitm-l4-helper version`
  prints `aitm-l4-helper <same>`.
- **Done when:** both are quoted. **Unit close:** a Tester run and the panel. The security reviewer signs off on the
  new dependencies (`caps`, `oslog`) and on the absence of `unsafe`.

---

## Unit (p3) macOS app: `feat/l4priv-mac`

Cut after parity (d) merges and S3 and S5 are written up. `Info.plist.in` goes to the orchestrator first (Rule 4).
Kit tests are pure. Every UI claim is proven live (P3.13), never by snapshot or fixture.

### Task P3.1: Kit `PacketCapture` decoding and the register gate

- **Satisfies:** AC11 (Kit truth table)
- **Depends on:** none in the unit
- **Files:** `apps/mac/Sources/AitmproxyKit/PacketCapture.swift` (create), `apps/mac/Tests/AitmproxyKitTests/PacketCaptureTests.swift` (create)
- **Change:**
  - `public struct PacketCapturePrivilege: Equatable, Sendable { captureState, howKind, howLabel, actionURL, helperStatus, request }`,
    with:
    - `static func decode(_ json: JSONValue) -> PacketCapturePrivilege?` (an `l4.privilege` reply), and
    - `static func decode(status: JSONValue) -> PacketCapturePrivilege?` (the status object's `privilege` key, on top
      of the parity `L4Availability.resolve`, which is unchanged).
  - `public enum PacketCaptureGate { public static func canRegister(bundlePath: String, helperPresent: Bool) -> Bool }`.
    `helperPresent` means `Contents/MacOS/aitm-l4-helper` and both plists exist. The result is true only for
    exactly `/Applications/Aitmproxy.app` with `helperPresent`.
  - `public enum HelperServiceStatus { case notRegistered, enabled, requiresApproval, notFound }`
- **Test (first, failing):** `PacketCaptureTests`:
  - `testDecodeNeedsApprovalAppAction`, input JSON built in the test
  - `testDecodeStatusPrivilegeKey`
  - `testCanRegisterTruthTable`: `/Applications/Aitmproxy.app`+true gives true. These all give false:
    `/Applications/Aitmproxy.app`+false, `~/Applications/Aitmproxy.app`+true, `/tmp/Aitmproxy-dev.app`+true,
    `/Applications/Other.app`+true.
- **Done when:** `swift test` (Terminal) passes, with the red run quoted first.

### Task P3.2: Kit URL acceptance, logged form, rate limit

- **Satisfies:** AC11 (URL truth table, 256-character log), AC9 (rate limit unit)
- **Depends on:** P3.1
- **Files:** `apps/mac/Sources/AitmproxyKit/PacketCapture.swift`, `apps/mac/Tests/AitmproxyKitTests/PacketCaptureTests.swift`
- **Change:**
  - `public enum PacketCaptureURL { public static func accepts(_ url: URL) -> Bool; public static func loggedForm(_
    s: String) -> String }`
  - `public struct PacketCaptureURLGate { public init(window: TimeInterval = 10); public mutating func admit(at: Date)
    -> Bool }`: true for the first URL, false for any within 10 s of the last admitted one.
- **Test (first, failing):**
  - `accepts` is true for `aitmproxy://packet-capture/allow`, and false for `aitmproxy://packet-capture/allow?x=1`,
    `aitmproxy://packet-capture/remove`, `aitmproxy://other` and `http://packet-capture/allow`.
  - `loggedForm` of a 10,000-character string has `count == 256`.
  - `admit` at t=0 gives true, at t=5 false, at t=11 true.
- **Done when:** `swift test` passes.

### Task P3.3: Kit `PacketCaptureAdvice` (lane words, remedy, actions)

- **Satisfies:** AC6 (words), AC11 ("packet capture unavailable", no Allow), spec §3.2 table
- **Depends on:** P3.2
- **Files:** `apps/mac/Sources/AitmproxyKit/PacketCapture.swift`, `apps/mac/Tests/AitmproxyKitTests/PacketCaptureTests.swift`
- **Change:** `public struct PacketCaptureAdvice { state: LaneState; word: String; remedy: String?; actions:
  [PacketCaptureAction] }` and `static func make(privilege: PacketCapturePrivilege?, helperStatus:
  HelperServiceStatus, canRegister: Bool) -> PacketCaptureAdvice`. The five rows of spec §3.2 are literal.
  `PacketCaptureAction` is one of `.allow`, `.openLoginItems`, `.remove`, `.openDownloadPage`.
- **Test (first, failing):** one test per row, e.g.
  - `testNotRegisteredCanRegister` gives `.off`, `"packet capture not allowed"`, remedy `"Allow packet capture to
    see raw TCP and UDP"`, actions `[.allow]`.
  - `testCannotRegister` gives `"packet capture unavailable"`, with no `.allow`.
  - `testRequiresApproval` gives `.working`, `"waiting for approval"`.

  Plus `testNoForbiddenWords`: no word or remedy contains `BPF`, `L4 capture`, `daemon`, `sudo`, `setcap`, `chmod`
  or `launchctl`.
- **Done when:** `swift test` passes.

### Task P3.4: `ConnectionSummary` packets lane and Getting started step

- **Satisfies:** AC6 (row ○ → ✓), spec §3.2 (never in the toolbar)
- **Depends on:** P3.3
- **Files:** `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift`, `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift`, `apps/mac/tools/check-connection-words.sh`
- **Change:**
  - `ConnectionLane.Kind` gains `.packets` (title "Packet capture").
  - The summary builder takes an optional `PacketCaptureAdvice` and a `bundleEmbedsHelper: Bool`.
  - `GettingStartedStep` gains `.packetCaptureAllowed`, "Allow packet capture (optional, for raw TCP and UDP)",
    present iff `bundleEmbedsHelper`.
  - The toolbar's compact lanes exclude `.packets`.
  - The word tripwire learns the five packet words.
- **Test (first, failing):**
  - `testPacketsLanePresentButNotInToolbar`
  - `testPacketStepOnlyWhenHelperEmbedded`
  - `testPacketStepDoneWhenAvailable`
- **Done when:** `swift test` and `check-connection-words.sh` pass.

### Task P3.5: embedded core writes `l4.enabled: true`

- **Satisfies:** AC26 (Kit unit)
- **Depends on:** none in the unit (independent of P3.1–P3.4)
- **Files:** `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift`, `apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift`
- **Change:** `Config.yaml()` appends `l4:\n  enabled: true\n` and no `scope`. **Note:** the brief said "when the
  helper is applied". The approved spec (§3.2, AC26) says always, because otherwise the embedded core never reports
  `needs_approval` and the nudge cannot show. This plan follows the spec.
- **Test (first, failing):** `testYamlEnablesL4WithoutScope`: the YAML contains `"l4:\n  enabled: true"`, does not
  contain `"scope:"` under `l4`, and contains no other `l4.` key.
- **Done when:** `swift test` passes.

### Task P3.6: `PacketCaptureHelper` (the only `SMAppService` file) and the Remove state machine

- **Satisfies:** AC6, AC13, AC14 (app half), spec §3.2 (register, update, Remove, finish at next launch)
- **Depends on:** P3.3; spike **S3** written up (prompt and re-register behaviour)
- **Files:** `apps/mac/Sources/Aitmproxy/Privilege/PacketCaptureHelper.swift` (create), `apps/mac/Sources/AitmproxyKit/PacketCapture.swift` (`PacketCaptureRemoval`), `apps/mac/Tests/AitmproxyKitTests/PacketCaptureTests.swift`
- **Change:**
  - Kit: `public struct PacketCaptureRemoval { public enum Phase { idle, revertRegistered(since: Date),
    unregistering, done, waitingApproval, pendingAtNextLaunch } ; public mutating func step(receiptExists: Bool,
    revertStatus: HelperServiceStatus, now: Date) -> [RemovalEffect] }`. Each effect is one of `.registerRevert`,
    `.unregisterBoth`, `.persistPending`, `.clearPending`, `.showRemoved`, `.showNeedsApproval`.
  - App: `@MainActor final class PacketCaptureHelper` with these members. Each one's first statement is
    `guard PacketCaptureGate.canRegister(...) else { return … }`.
    - `var status: HelperServiceStatus`
    - `func register() async throws`: unregisters first when the receipt's `helper_version` differs from
      `CFBundleShortVersionString`.
    - `func remove() async`: runs `PacketCaptureRemoval`, polling the receipt every 0.5 s for up to 10 s, and
      persists `packetCapture.pendingUnregister` until done.
    - `func finishPendingRemovalAtLaunch() async`
    - `func reregisterIfUpdated() async` (launch)
    - `func openLoginItems()`: `SMAppService.openSystemSettingsLoginItems()`
- **Test (first, failing):** `PacketCaptureTests`:
  - `testRemovalHappyPath`: receipt gone at 3 s gives `[.unregisterBoth, .clearPending, .showRemoved]`.
  - `testRemovalNeedsApproval`: revert `requiresApproval` gives `.showNeedsApproval`.
  - `testRemovalTimeoutPersistsPending`: 10 s with the receipt still present gives `.persistPending`.
- **Done when:** `swift test` passes.

### Task P3.7: UI tripwires

- **Satisfies:** AC11 (tripwires), Rule 2
- **Depends on:** P3.6
- **Files:** `apps/mac/tools/check-packet-capture-ui.sh` (create)
- **Change:** a zsh script that exits 1 with a named message when any of these is broken:
  1. `SMAppService` appears in any Swift file but `Privilege/PacketCaptureHelper.swift`.
  2. A `func` in that file does not begin with `guard PacketCaptureGate.canRegister`.
  3. `PacketCaptureCard.swift`, `PacketCapture.swift` or `L4CaptureControls.swift` contain any of `BPF`,
     `L4 capture`, `daemon`, `sudo`, `setcap`, `chmod`, `chgrp`, `dseditgroup`, `launchctl` or `pkexec` inside a
     string literal.
  4. `L4Availability.embeddedReason` exists anywhere. Parity (d) removed it; if it is back, the check fails.
- **Test (first, failing):** run against a scratch copy with one `SMAppService` reference added to `Session.swift`.
  It exits 1 naming the file. On the branch it exits 0.
- **Done when:** both runs are quoted.

### Task P3.8: the Packets card, the Status page, Settings ▸ Packets

- **Satisfies:** AC6 (card, five lines), AC14 (Remove in Settings), spec §3.2 card and Remove
- **Depends on:** P3.7
- **Files:** `apps/mac/Sources/Aitmproxy/Panels/PacketCaptureCard.swift` (create), `apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift`, `apps/mac/Sources/Aitmproxy/SettingsView.swift` (`SettingsTab.packets`, title "Packets"), `apps/mac/Sources/Aitmproxy/Session.swift` (helper and advice state only)
- **Change:**
  - `struct PacketCaptureCard: View`: the title, the five lines verbatim from spec §3.2, **Allow Packet Capture…**
    (primary) and **Not Now**. Not Now persists `packetCapture.cardDismissed`, collapses the card to the lane line,
    and leaves the step in place.
  - `urlSurfaced: Bool` mode: the neutral line "Another program asked to allow packet capture. Allow it only if you
    started this.", and Allow without `.keyboardShortcut(.defaultAction)`.
  - S3's words for the approval step.
  - The Status page gets a fourth card.
  - Settings ▸ Packets: the card, the helper status, and **Remove Packet Capture…** behind a confirm, with the
    "Removed. The packet-capture devices are root-only again." result.
- **Test:** layout via `grid-lint.sh`. Behaviour is proven live in P3.13. There is no snapshot test.
- **Done when:** the unit gate passes.

### Task P3.9: URL scheme, handler and launch-by-URL

- **Satisfies:** AC9 (app half), AC11 (others ignored)
- **Depends on:** P3.8; spike **S5**; orchestrator's go on `Info.plist.in` (Rule 4)
- **Files:** `apps/mac/Info.plist.in` (`CFBundleURLTypes` with scheme `aitmproxy`), `apps/mac/Sources/Aitmproxy/App.swift`, `apps/mac/Sources/AitmproxyKit/PacketCapture.swift` (`LaunchIntent`), `apps/mac/Tests/AitmproxyKitTests/PacketCaptureTests.swift`
- **Change:**
  - Kit: `public enum LaunchPlan { case normal, cardOnly }` and `public enum LaunchIntent { public static func plan(launchEventIsURL:
    Bool) -> LaunchPlan }`.
  - App: the `AppDelegate` handles `application(_:open:)`. Each URL goes through `accepts`. A rejected URL is
    ignored and logged with `loggedForm`. An accepted one goes through `PacketCaptureURLGate.admit`, and an admitted
    one brings the app forward, opens Status and highlights the card with `urlSurfaced = true`.
  - A launch whose first event is the URL (S5's method) takes `.cardOnly`: no embedded core, proxy, extension or
    capture start.
- **Test (first, failing):** `testLaunchByURLIsCardOnly` and `testNormalLaunchIsNormal`.
- **Done when:** `swift test` passes. Live in P3.13.

### Task P3.10: capture controls and the nudge

- **Satisfies:** AC25 (mac), AC26 (Start disabled with the reason; Start/Stop after approval)
- **Depends on:** P3.8 (independent of P3.9)
- **Files:** `apps/mac/Sources/AitmproxyKit/L4Capture.swift` (create), `apps/mac/Tests/AitmproxyKitTests/L4CaptureTests.swift` (create), `apps/mac/Sources/Aitmproxy/Panels/L4CaptureControls.swift` (create), `apps/mac/Sources/Aitmproxy/Panels/ScopePanel.swift` (embed the controls in the parity L4 section), `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (the nudge in the L4-chip empty state)
- **Change:**
  - Kit: `public enum L4CaptureArgs { static func start(interface: String, direction: String) -> [String:
    JSONValue]; static func stop(id: String) -> [String: JSONValue] }` and `public enum PacketNudge { static let text
    = "No packets? Packet capture isn't allowed on this Mac yet."; static func shows(privilege:
    PacketCapturePrivilege?) -> Bool }` (true iff the state is `needs_approval`).
  - View: an interface picker fed by `l4.interfaces`, inbound/outbound, Start, and Stop per running capture.
    - While capture is not `available`, Start is disabled with the core's `reason` and the nudge plus **Allow Packet
      Capture…** is shown.
    - After a failed `l4.capture.start`, the same nudge is shown.
  - **(Architect's call:** the controls live on the Scope page's L4 section, where parity decision 6 put the L4
    availability lines.)
- **Test (first, failing):**
  - `testStartArgs`: `start("lo0","inbound") == ["interface": "lo0", "direction": "inbound"]`
  - `testStopArgs`
  - `testNudgeOnlyWhenNeedsApproval`
- **Done when:** `swift test` and `grid-lint.sh` pass.

### Task P3.11: Settings ▸ Uninstall runs Remove first

- **Satisfies:** AC14 (Uninstall end state)
- **Depends on:** P3.6; **Matt's answer to question 3** (the default here is the spec's literal reading)
- **Files:** `apps/mac/Sources/Aitmproxy/SettingsView.swift` (`CaptureSwitch.uninstall`), `apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` (the confirm message)
- **Change:** `CaptureSwitch.uninstall(session:)` first awaits `PacketCaptureHelper.remove()` when the helper status
  is not `notRegistered`, then runs its own steps. The confirm message gains "Packet capture permission is removed
  too."
- **Test:** live only (P3.13, AC14 second half). The decision is a two-line ordering with no pure logic to unit-test.
- **Done when:** the unit gate passes.

### Task P3.12: wire the helper state into the session poll

- **Satisfies:** AC7 (the app shows `available` within 5 s), AC13 (re-register at launch)
- **Depends on:** P3.9, P3.10
- **Files:** `apps/mac/Sources/Aitmproxy/Session.swift`, `apps/mac/Sources/Aitmproxy/App.swift` (launch hooks: `finishPendingRemovalAtLaunch`, `reregisterIfUpdated`)
- **Change:** the session polls `l4.privilege` on the existing L4 status tick. It feeds `PacketCaptureAdvice` with
  `PacketCaptureHelper.status` and `canRegister(Bundle.main.bundlePath, …)`. It never polls faster than the parity
  budget.
- **Test:** live only (P3.13).
- **Done when:** the unit gate passes.

### Task P3.13: live mac checks (CUA)

- **Satisfies:**
  - [mac-any]: AC10 (mac app half), AC11 (dev bundle), AC25, AC26 (disabled half)
  - [mac-signed]: AC6, AC7, AC8 (macOS walk), AC9, AC13, AC14, AC26 (Start/Stop), AC28 (re-run on the real bundle)
- **Depends on:** P3.12; p1b merged. [mac-signed] also needs p4 merged and the P4.7 notarized DMG installed, under
  Rule 6.
- **Files:** `apps/mac/tools/cua-packet-capture.sh` (create)
- **Change:** a CUA script on the parity recipe: real clicks, `winshot` light and dark, the rig core as external core,
  state read-back in the Terminal.
- **Live check [mac-any]:**
  - The `snap-dev.sh` bundle and a plain `build.sh` bundle (Terminal) both show "packet capture unavailable" with no
    Allow (AC11).
  - The L4 empty state shows the nudge. Start capture is disabled with the core's reason. A forced failed start shows
    the nudge (AC25, AC26). Screenshots are looked at and described.
- **Live check [mac-signed] (Rule 6; announce, Matt's yes, revert in session):**
  1. AC6: from `crw------- root wheel`, click **Allow Packet Capture…** and approve in Login Items. Within 10 s:
     - `crw-rw---- root access_bpf`;
     - `/dev/bpf255` exists;
     - the receipt has `"group":"access_bpf"`, `helper_version` equal to `CFBundleShortVersionString`, and
       `members_added` equal to the console user only;
     - `dscl` lists the user;
     - the card reads "packet capture allowed" and the row is ✓.
  2. AC7: a rig core started before step 1 reports `available` within 5 s. `/opt/homebrew/bin/aitm l4.privilege`,
     the cask's or tarball's binary, reports `available`.
  3. AC8: walk W on `lo0` in process. W3–W4 are reported per S8.
  4. AC9: from the TUI (pty) and the web UI, with the app running and quit: the Allow action plus confirm brings
     Aitmproxy forward on Status, highlighted, with the neutral line. Return does not press Allow. A quit app
     launched by the URL starts no embedded core (`pgrep -f Resources/core/aitm` empty). SMAppService stays
     `notRegistered` until the click. A browser-page open registers nothing, and a second open within 10 s does not
     re-highlight.
  5. AC26: Start on `lo0` returns an id and Stop ends it, with both in `agent.activity` from `aitm-mac`.
  6. AC13: install the next notarized build over it. `helper_version` changes within 10 s of first launch, and
     capture stays or becomes `available` (or "waiting for approval" per S3).
  7. AC28: repeat S3's substitution test on the real bundle. launchd refuses, and the receipt mtime is unchanged.
     Then restore the signed helper.
  8. AC14 (the revert, last): **Remove Packet Capture…**. Within 10 s:
     - `crw------- root wheel`;
     - the receipt is gone;
     - `dscl` no longer lists the added user (a pre-existing member stays);
     - both services are `notRegistered`;
     - `l4.privilege` shows `needs_approval`.

     Then repeat 1 and finish through Settings ▸ Uninstall for the same end state.
- **Done when:** every check is quoted with SHAs and timestamps, or carries an honest `blocked:` line. The machine
  ends in the AC14 state.

---

## Unit (p4) release pipeline: `feat/l4priv-release`

Everything here is bundle layout. The Coder sends the orchestrator (release driver) each task's exact paths, keys and
sign order and waits for its go (Rule 4). The orchestrator reviews the diffs.

### Task P4.1: the two LaunchDaemon plists

- **Satisfies:** AC12 (plist keys), spec §4.2
- **Depends on:** spike **S3** (the accepted `SpawnConstraint` shape)
- **Files:** `apps/mac/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist` (create), `apps/mac/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper-revert.plist` (create)
- **Change:** the keys of spec §4.2 verbatim:
  - `Label`
  - `BundleProgram` = `Contents/MacOS/aitm-l4-helper`
  - `ProgramArguments` = `["aitm-l4-helper","bpf-permissions"]`, or `"bpf-revert"` in the revert plist
  - `AssociatedBundleIdentifiers` = `["com.mrbrutti.aitmproxy"]`
  - `RunAtLoad` true
  - `ProcessType` Background
  - `SpawnConstraint` in S3's shape

  No `KeepAlive`, `MachServices` or `Sockets`.
- **Test (first, failing):** in `apps/mac/tools/check-packet-helper.sh` (created here):
  - `plutil -lint` both;
  - `plutil -extract BundleProgram raw` equals `Contents/MacOS/aitm-l4-helper`;
  - `plutil -extract ProgramArguments.1 raw` equals `bpf-permissions` / `bpf-revert`;
  - `plutil -extract SpawnConstraint xml1` is non-empty;
  - there is no `KeepAlive`, `MachServices` or `Sockets` key.

  The check exits 1 before the files exist.
- **Done when:** the check exits 0.

### Task P4.2: `notarize-dmg.sh` presence, sign order and post-sign checks

- **Satisfies:** AC12 (tripwire), spec §4.4
- **Depends on:** P4.1
- **Files:** `scripts/notarize-dmg.sh`, `scripts/tests/run-notarize-dmg-stubbed.sh`
- **Change:**
  - **Presence:** before any signing, the helper and the two plists must be all present or all absent. Otherwise
    exit 1 with `notarize-dmg.sh: <app> has <which> but not <which>; the packet-capture helper and both plists ship
    together or not at all`.
  - **Plist checks:** each plist's `BundleProgram` (`plutil -extract`) equals `Contents/MacOS/aitm-l4-helper` and
    points at an existing Mach-O (`file` reports `Mach-O`). `AssociatedBundleIdentifiers` contains
    `com.mrbrutti.aitmproxy`.
  - **Step (c2):** after `core/aitm` and before the app: `cs --force --options runtime --timestamp --identifier
    com.mrbrutti.aitmproxy.l4-helper --sign "$dev_id" "$app/Contents/MacOS/aitm-l4-helper"`, with no
    `--entitlements`.
  - **Post-sign:** `codesign -dv --verbose=4` on the helper must show `Identifier=com.mrbrutti.aitmproxy.l4-helper`,
    `^TeamIdentifier=995PCLM9KH$`, `flags=.*runtime` and `Authority=Developer ID Application`. `codesign -d
    --entitlements -` must be empty.
- **Test (first, failing):** the stub test gains cases:
  - 6a: all present, which reaches the DMG step with the helper signed before the app (stub order log);
  - 6b: all absent, which passes as today;
  - 6c, 6d, 6e: plist only, helper only, one plist of two, each exiting 1 with the message;
  - 6f: the helper signed after the app, which exits 1;
  - 6g: a wrong `BundleProgram`, which exits 1;
  - 6h: a helper carrying entitlements, which exits 1.

  The new cases fail against the unmodified script, quoted via `NOTARIZE_DMG_SCRIPT=<old copy>`.
- **Done when:** `run-notarize-dmg-stubbed.sh` exits 0 and `shellcheck` is clean.

### Task P4.3: `package.sh` ships the helper

- **Satisfies:** spec §4.5 (tarball beside `aitm`, macOS and Linux)
- **Depends on:** p2 merged
- **Files:** `scripts/package.sh`
- **Change:** `cargo build --release -p aitm-l4-helper`, then `cp` and `chmod 755` the helper into the stage. The tar
  list gains `aitm-l4-helper`.
- **Test:** before the change, `tar -tzf dist/aitm-*-<triple>.tar.gz | grep -x aitm-l4-helper` prints nothing. After
  it, it prints `aitm-l4-helper` (Terminal; `package.sh` downloads obscura).
- **Done when:** the run is quoted.

### Task P4.4: `build.sh` embeds only under `--ne`, from the tarball only

- **Satisfies:** AC11 (plain `build.sh` bundle unavailable), spec §4.5, §4.6
- **Depends on:** P4.3
- **Files:** `apps/mac/build.sh`, `apps/mac/tools/check-packet-helper.sh`
- **Change:**
  - When `want_ne`: copy `aitm-l4-helper` only from the extracted tarball (never `AITM_CORE_DIR`) into
    `Contents/MacOS/`, and copy both plists into `Contents/Library/LaunchDaemons/`. A tarball without the helper
    fails the build with `build failed: the release tarball has no aitm-l4-helper; run scripts/package.sh`.
  - Without `--ne`: embed nothing and print `no packet-capture helper embedded (release builds only: --ne)`.
- **Test (first, failing):** the tripwire gains three checks:
  1. every `aitm-l4-helper` or `LaunchDaemons` reference in `build.sh` sits inside the `want_ne` branch;
  2. no `AITM_CORE_DIR` path is used for the helper;
  3. `apps/mac/tools/snap-dev.sh` contains neither `LaunchDaemons` nor `aitm-l4-helper`.

  Check 1 fails before the edit only if the branch is wrong; quote both runs.
- **Done when:** the check exits 0. A plain `build.sh` run (Terminal) prints the "no packet-capture helper embedded"
  line, quoted.

### Task P4.5: snap-dev tripwire stays green (no change to `snap-dev.sh`)

- **Satisfies:** AC11 (tripwire), spec §4.6
- **Depends on:** P4.4
- **Files:** none (verifies P4.4's check against `snap-dev.sh`). If `snap-dev.sh` needs an edit, **stop and report**.
- **Test:** `check-packet-helper.sh` exits 0. A scratch copy of `snap-dev.sh` with `cp -R …/LaunchDaemons` appended
  makes it exit 1.
- **Done when:** both runs are quoted.

### Task P4.6: `docs/RELEASE.md` and the cask stanza

- **Satisfies:** AC29 (tripwire half), spec §4.5
- **Depends on:** P4.2
- **Files:** `docs/RELEASE.md`; the tap repo's `Casks/aitmproxy.rb` (the orchestrator makes this edit in
  `mrbrutti/homebrew-aitmproxy`)
- **Change:**
  - Step 3: one line that the helper ships inside the app.
  - Step 6: `codesign -dv …/Contents/MacOS/aitm-l4-helper` and `plutil -p` of both plists.
  - The cask section records `uninstall launchctl: ["com.mrbrutti.aitmproxy.l4-helper",
    "com.mrbrutti.aitmproxy.l4-helper-revert"]` and that Settings ▸ Uninstall runs Remove.
  - `check-packet-helper.sh` gains an optional `TAP_DIR` check: `grep -F` for the stanza with both labels.
- **Test:** `TAP_DIR=<tap checkout> apps/mac/tools/check-packet-helper.sh` exits 0 after the orchestrator's tap
  commit, and 1 before it.
- **Done when:** both runs are quoted by the orchestrator.

### Task P4.7: notarized-bundle checks

- **Satisfies:** AC12, AC29 (live), and supplies the DMG for P3.13 [mac-signed]
- **Depends on:** P4.6; p2 and p3 merged (the release driver builds from `main`)
- **Files:** none (release driver's Terminal run)
- **Live check [mac-signed]:** run `build.sh --ne`, then `notarize-dmg.sh`.
  - The bundle checks: `plutil -extract BundleProgram raw` on both plists, `AssociatedBundleIdentifiers` equal to
    `["com.mrbrutti.aitmproxy"]`, the helper's `codesign -dv` lines, `codesign --verify --deep --strict` on the app,
    and `stapler validate` on the DMG.
  - AC29, under Rule 6 and after P3.13's AC6: `brew uninstall --cask aitmproxy` leaves `launchctl print
    system/com.mrbrutti.aitmproxy.l4-helper` failing. Revert: confirm the AC14 read-back, then reinstall the cask if
    Matt wants the app back.
- **Done when:** the outputs are quoted.

---

## Unit (p5) Linux packaging: `feat/l4priv-linux-pkg`

### Task P5.1: the polkit policy and its tripwire

- **Satisfies:** AC15 (tripwire), spec §5.4
- **Depends on:** none (can start before p2 merges; P5.2 waits)
- **Files:** `scripts/packaging/com.mrbrutti.aitmproxy.l4-helper.policy` (create), `scripts/tests/check-linux-packaging.sh` (create)
- **Change:** the policy:
  - action `com.mrbrutti.aitmproxy.l4-helper.run`;
  - `org.freedesktop.policykit.exec.path` = `/usr/lib/aitmproxy/aitm-l4-helper`;
  - **no** `org.freedesktop.policykit.exec.allow_gui` annotation (S7: was `true`; the helper has no GUI and the
    dialog is pkexec's agent's, so the annotation only leaked `DISPLAY`/`XAUTHORITY` into the root helper's
    environment);
  - defaults `allow_any`, `allow_inactive` and `allow_active` all `auth_admin`;
  - the message `Allow aitmproxy to capture and send raw packets (only within the L4 scope you configured)`.
- **Test (first, failing):** `check-linux-packaging.sh` exits 1 unless all of these hold:
  - the action id and the exec.path are exact;
  - every default is exactly `auth_admin`;
  - `auth_admin_keep` appears nowhere in the file;
  - `allow_gui` appears nowhere in the file (S7);
  - `xmllint --noout` passes (when present).

  (S7) The deb `recommends` entry `pkexec` in P5.2 stands and is deliberate: on Debian trixie `pkexec` is a separate
  package from `polkitd`.

  It exits 1 before the file exists.
- **Done when:** the check exits 0.

### Task P5.2: nfpm contents and `package-linux.sh`

- **Satisfies:** AC15, spec §5.4 (no maintainer scripts, no setcap, `recommends`)
- **Depends on:** P5.1; p2 merged
- **Files:** `scripts/nfpm.yaml`, `scripts/package-linux.sh`, `scripts/tests/check-linux-packaging.sh`
- **Change:**
  - `contents` gains two entries:
    - `/usr/lib/aitmproxy/aitm-l4-helper`, with `file_info` mode `0o755`, owner `root`, group `root`;
    - the policy at `/usr/share/polkit-1/actions/com.mrbrutti.aitmproxy.l4-helper.policy`, mode `0o644`.
  - There is no `/usr/bin` symlink for the helper.
  - `recommends`: `pkexec` (deb), and `polkit` in `overrides.rpm`.
  - `package-linux.sh` builds `-p aitm-l4-helper` and stages it.
- **Test (first, failing):** the tripwire gains four checks:
  1. `nfpm.yaml` has no `scripts:` key and no `setcap`;
  2. the helper's `dst` and mode are exact;
  3. `recommends` holds `pkexec`;
  4. no symlink targets the helper.
- **Done when:** the check exits 0 and `shellcheck` is clean.

### Task P5.3: packages in clean containers

- **Satisfies:** AC15 (live)
- **Depends on:** P5.2
- **Files:** none (Terminal and `cis-lab` run)
- **Live check [linux-ci]:** build the deb and rpm in `cis-lab`. Install each in a clean `debian:trixie` and
  `fedora` container. Then:
  - `stat -c '%a %U:%G' /usr/lib/aitmproxy/aitm-l4-helper` gives `755 root:root`;
  - the policy file exists with the action id;
  - `getcap /usr/lib/aitmproxy/aitm /usr/lib/aitmproxy/aitm-l4-helper` prints nothing.
- **Done when:** the outputs are quoted.

### Task P5.4: `docs/packet-capture.md` (headless fallback and NixOS)

- **Satisfies:** spec §5.6. Makes AC23's doc-naming branch possible.
- **Depends on:** **BLOCKED until Matt's written acceptance** of the headless `setcap` doc (spec open question). Until
  then the `cannot_prompt` message names no doc, and this task is not dispatched.
- **Files:** `docs/packet-capture.md` (create); after acceptance only, `crates/aitm-proto-l4/src/privilege/linux.rs`
  (one message string). That second edit is a p1b follow-up PR, not part of p5.
- **Change:** for admins of headless hosts only:
  - the root-owned copy, restricted to a group (`0750 root:aitm-l4`), with `cap_net_raw+ep` on the helper and never
    on `aitm`, set via `l4.privilege.helper_path`;
  - redo the step after each upgrade;
  - a NixOS `security.wrappers.aitm-l4-helper` snippet (`source`, `capabilities = "cap_net_raw+ep"`, owner root,
    group `aitm-l4`, group-execute only).
- **Test:** AC23's doc branch in `test_privilege_core.py` (the message names `docs/packet-capture.md`).
- **Done when:** Matt's acceptance is recorded in the Review log and the check passes.

---

## Unit (p6) TUI, web, CLI: `feat/l4priv-frontends`

Cut after p1b, parity (b) and parity (c) merge. The TUI chain (P6.1–P6.4) and the web chain (P6.5–P6.8) touch
disjoint files and may fan out as two child branches of `feat/l4priv-frontends`, merged back before P6.9. The
frontends show the core's `message` for every outcome. They invent no status text beyond the banner and nudge lines
**(Architect's call)**.

The nudge text **(Architect's call):** "No packets? Packet capture isn't allowed on this Mac yet." on macOS, and "No
packets? Packet capture isn't allowed on this machine yet." on Linux.

### Task P6.1: TUI privilege model

- **Satisfies:** AC25 (unit), AC10 (no shell command shown)
- **Depends on:** p1b merged
- **Files:** `crates/aitm-tui/src/l4.rs`, `crates/aitm-tui/tests/l4_privilege.rs` (create)
- **Change:**
  - `pub struct L4PrivilegeView { pub capture: String, pub how_kind: Option<String>, pub how_label: Option<String>,
    pub url: Option<String>, pub request: Option<(String, String)>, pub platform: String }`
  - `L4PrivilegeView::from_json(v: &Value) -> Option<Self>` reads an `l4.privilege` reply or a status `privilege`
    key.
  - `banner(&self) -> Option<String>` and `nudge(&self) -> Option<&'static str>`.
- **Test (first, failing):** `l4_privilege.rs`, with input JSON built in the test, never `fixture_app`:
  - pkexec gives `"Packet capture isn't allowed yet: Allow packet capture (asks for an administrator password). Press
    A to allow."`
  - package gives the label plus `https://mrbrutti.github.io/aitmproxy/download.html` and no `A` hint
  - available gives `None`
  - `nudge` on Linux is the machine wording
  - no banner contains a word from the AC3 regex
- **Done when:** the tests pass and the Rust gate passes.

### Task P6.2: TUI action, key, palette, polling

- **Satisfies:** AC9 (TUI half), AC22 (send path), AC25
- **Depends on:** P6.1
- **Files:** `crates/aitm-tui/src/{action,keys,app,bus}.rs`, `crates/aitm-tui/tests/l4_privilege.rs`
- **Change:**
  - `Action::AllowPacketCapture`. Key `A` maps to it **only while the L4 view has focus and the banner is shown**;
    everywhere else `A` stays `ResumeAll` (question 4). A palette entry reads "Allow packet capture".
  - The action opens the confirm with the core's `confirm_prompt`, then sends `l4.privilege.request {}`.
  - `l4.privilege` is polled on the L4 status tick, after every failed `l4.capture.start`, and every 2 s while
    `request.state == "pending"` (at most 150 polls).
- **Test (first, failing):** `allow_key_in_l4_view_requests_after_confirm`: an `App` built in the test, holding a
  `needs_approval` view and the L4 focus. Pressing `A` emits no bus request until the confirm. Confirming emits
  exactly one `BusRequest` for `l4.privilege.request` with `{}`. In the flow list, `A` still yields `ResumeAll`.
- **Done when:** the tests pass and the Rust gate passes.

### Task P6.3: TUI suspend while pkexec prompts on the same tty

- **Satisfies:** AC22
- **Depends on:** P6.2
- **Files:** `crates/aitm-tui/src/lib.rs` (terminal suspend and restore around the request), `crates/aitm/src/tui.rs` (passes `core_shares_tty: true` in `aitm tui` mode only; panel 2, 2026-11-01: its shutdown arm's hold consult is p1b's, P1b.14, already landed)
- **Change:**
  - `pub fn should_suspend(platform: &str, core_shares_tty: bool, outcome: &str) -> bool` is true iff `linux`,
    `core_shares_tty` and `pending`.
  - When true, the run loop calls `ratatui::restore()`, prints `Waiting for administrator approval…`, and
    re-`init`s when the polled `request.state` leaves `pending`. (S7) Once raw mode is off, Ctrl-C at the password
    is a SIGINT to the whole foreground process group, which in `aitm tui` is this process; the `aitm` binary's
    prompt hold (P1b.14; panel 2026-11-01: a hold count the tokio `ctrl_c` shutdown future consults while the pkexec
    child lives) is what keeps the TUI alive, and the TUI must not install `SIG_IGN` or its own exit-on-SIGINT during
    this window. After the prompt ends with `dismissed`, the TUI redraws with the banner
    "Approval was cancelled". (Panel 2, 2026-11-01) The `aitm tui` shutdown arm already consults the prompt hold
    (p1b, P1b.14); P6.3 keeps only the raw-mode suspend and restore and the `core_shares_tty` flag, and adds no
    signal or shutdown code.
- **Test (first, failing):** `should_suspend("linux", true, "pending") == true`. The cases `("macos", true,
  "handed_to_app")`, `("linux", false, "pending")` and `("linux", true, "cannot_prompt")` are all `false`.
- **Done when:** the tests pass and the Rust gate passes.

### Task P6.4: TUI rendering of the banner and the nudge

- **Satisfies:** AC25 (TUI)
- **Depends on:** P6.3
- **Files:** `crates/aitm-tui/src/ui/l4.rs`, `crates/aitm-tui/tests/l4_privilege.rs`
- **Change:** one banner line at the top of the L4 view. The nudge plus "press A" sits in the L4 empty state and in
  the notice after a failed start.
- **Test (first, failing):** render the L4 view of an `App` built in the test into a `ratatui` `Buffer` and assert
  the nudge line's text is present. This is a unit assertion on one string, not a snapshot comparison.
- **Done when:** the tests pass and the Rust gate passes.

### Task P6.5: web privilege model

- **Satisfies:** AC25 (unit), AC10
- **Depends on:** p1b merged (independent of P6.1–P6.4)
- **Files:** `apps/web/src/panels/l4/privilege.ts` (create), `apps/web/src/panels/l4/privilege.test.ts` (create)
- **Change:**
  - `export type L4Privilege = {…}` (§2.2)
  - `export function parsePrivilege(v: unknown): L4Privilege | null`
  - `export function bannerFor(p: L4Privilege): { text: string; action: "request" | "link" | null; href?: string }
    | null`
  - `export function nudgeFor(p: L4Privilege): string | null`
- **Test (first, failing):** with objects built in the test:
  - pkexec gives `action: "request"`
  - package gives `action: "link"` and `href` equal to the download URL
  - available gives `null`
  - no text matches the AC3 regex
- **Done when:** `npm test` passes (Terminal).

### Task P6.6: web store: polling and the request

- **Satisfies:** AC9 (web half), AC21 (send path), AC25
- **Depends on:** P6.5
- **Files:** `apps/web/src/panels/l4/store.ts`, `apps/web/src/panels/l4/privilege.test.ts`
- **Change:**
  - `privilege` state.
  - Poll `l4.privilege` on the parity 10 s idle tick (inside the AC23 budget), after a failed `l4.capture.start`, and
    every 2 s while `pending` (at most 150 polls).
  - `requestPrivilege()` sends `l4.privilege.request` with `{}` after the confirm dialog's yes.
- **Test (first, failing):** `requestPrivilege` builds the call `{name: "l4.privilege.request", arguments: {}}`. The
  pending poll stops on `approved` and on `dismissed`.
- **Done when:** `npm test` passes.

### Task P6.7: `L4PrivilegeBanner`

- **Satisfies:** AC9, AC10, AC21, AC25 (web)
- **Depends on:** P6.6
- **Files:** `apps/web/src/panels/l4/L4PrivilegeBanner.tsx` (create), the parity (c) L4 page component (mount point; the Coder names it from the merged tree and adds it to the claim)
- **Change:**
  - A banner at the top of the L4 page: **Allow Packet Capture…** opens the confirm (the core's `confirm_prompt`
    text), then requests.
  - `package` renders as a link.
  - It shows the core's `message`: pending, "Enter an administrator password in the terminal running aitm",
    "Approval was cancelled", handed to app.
  - No `innerHTML`.
- **Test:** typecheck and build. Behaviour is proven live in P6.10.
- **Done when:** the web gate passes.

### Task P6.8: web nudge in the empty state and after a failed start

- **Satisfies:** AC25 (web)
- **Depends on:** P6.7
- **Files:** `apps/web/src/panels/l4/PacketList.tsx`, `apps/web/src/panels/l4/CaptureControls.tsx`
- **Change:** `nudgeFor(privilege)` plus the Allow button in the empty packet list, and after a failed start.
- **Test:** typecheck and build. Live in P6.10.
- **Done when:** the web gate passes.

### Task P6.9: CLI path check

- **Satisfies:** G4 (CLI), AC20 (one-shot refusal is core-side, P1b.14)
- **Depends on:** P6.4, P6.8
- **Files:** none expected. If the one-shot `aitm l4.privilege.request` does not show the confirm prompt through
  `crates/aitm-cli/src/confirm.rs`, **stop and report** (the file is not claimed).
- **Live check [mac-any]:**
  - `aitm l4.privilege` against the rig config prints the report JSON with `platform: "macos"`.
  - `aitm l4.privilege.request` shows the macOS confirm text. Answering no sends nothing.
- **Live check [linux-ci]:** the one-shot request refuses with the §2.4 text.
- **Done when:** the outputs are quoted.

### Task P6.10: live TUI and web checks

- **Satisfies:**
  - [mac-any]: AC10, AC25
  - [linux-ci]: AC22, AC25
  - [linux-desk]: AC21
  - [mac-signed]: AC9, run in P3.13 step 4 with these scripts
- **Depends on:** P6.9
- **Files:** `tests/e2e/l4/test_privilege_tui.py` (create; the pty driver), `apps/web/scripts/cua-l4-privilege.mjs` (create; real Chrome over CDP against the rig)
- **Live check [mac-any]:** against the rig.
  - The TUI and the web show the nudge in the L4 empty state, and after a forced failed start.
  - With `macos_app_path: /nonexistent.app`, both show the `package` label and the download link and no shell
    command. The request gives `cannot_prompt`.
  - Screenshots are looked at.
- **Live check [linux-ci] (AC22):** in the systemd container without the test polkit rule (`49-aitm-test.rules`
  removed), `aitm tui` in a pty. Allow plus confirm restores the normal screen. A prompt appears whose first line is
  `==== AUTHENTICATING FOR com.mrbrutti.aitmproxy.l4-helper.run ====` (S7: the harness matches on this line; the
  policy message, `Authenticating as: tester` and `Password: ` follow, with ANSI colour codes stripped). The harness
  types the password. The TUI redraws, the banner is gone, and capture is `available`. A second run answers the prompt
  with Ctrl-C: the TUI stays alive and redraws with "Approval was cancelled" (S7).
- **Live check [linux-desk] (AC21):** on the GNOME VM, the web UI's Allow shows the graphical polkit dialog with the
  helper path and the policy message.
  - Approve: walk W passes.
  - Cancel instead: `request.state == "dismissed"` and the banner reads "Approval was cancelled".
  - A second Allow prompts again.
- **Done when:** every check is quoted with SHAs, or carries an honest `blocked:` line. **Unit close:** a Tester run
  and the panel.

---

## Unit (p7) the `aitm-mcp` exception: `fix/l4priv-mcp-operator-only`

### Task P7.1: `l4.privilege.request` is operator-only, never parked

- **Satisfies:** AC5 (tripwires: `is_operator_only` true, not in `defers_to_command_gate`), G5
- **Depends on:** none. Cut from current `main` (system-proxy PR 1's `proxy.system.*` entries are already in this
  function).
- **Files:** `crates/aitm-mcp/src/server.rs`: the `is_operator_only` match arm, with a comment naming this spec and
  L4PRIV-AC5, plus one test in its `tests` module.
- **Change:** `| "l4.privilege.request"` in `is_operator_only`. Nothing else in `aitm-mcp`.
- **Test (first, failing):** `l4_privilege_request_is_operator_only_never_parked`, modelled on
  `proxy_system_verbs_are_operator_only_never_parked`, with a `Sensitive` stand-in named `l4.privilege.request` and
  a `Read` stand-in `l4.privilege`. Under `All`, `Auto` and `Ask`, the agent call:
  - is a tool error whose text starts with `` `l4.privilege.request` refused: `` and contains `operator`;
  - under `Auto` starts with `` `l4.privilege.request` refused: the agent policy is ``;
  - leaves `srv.parked` empty;
  - pushes no `approval_requested` line;
  - runs the stand-in 0 times.

  `l4.privilege` runs under `ReadOnly`. `is_operator_only("l4.privilege.request")` is true,
  `defers_to_command_gate("l4.privilege.request")` is false, and `is_operator_only("l4.privilege")` is false. The
  test fails under `Ask` before the edit (the call parks).
- **Done when:** the test passes, the Rust gate passes, and `git diff origin/main -- crates/aitm-mcp` touches only
  `is_operator_only` and the test. **Unit close:** the panel. The live half runs in P1b.17 once both are on `main`.

---

## Acceptance criteria map

| AC | Unit tests / tripwires | Live (where) |
|---|---|---|
| AC1 | P1b.1, P1b.2, P1b.10 | P1b.17 [mac-any, linux-ci]; `app_action` in P3.13 [mac-signed] |
| AC2 | P1b.1, P1b.10, P1b.15 | P1b.17 |
| AC3 | P1b.1, P1b.2, P1b.3 | — |
| AC4 | P1b.4, P1b.9 | P1b.17 |
| AC5 | P1b.10, P7.1 | P1b.17 (after p7) |
| AC6 | P1a.1, P2.2, P2.3, P3.3, P3.4, P3.6 | P3.13 [mac-signed] |
| AC7 | P1b.6, P1b.7 | P3.13 [mac-signed] |
| AC8 | P1b.8, P1b.13, P2.7 (`inject_path`, `loopback_inject_uses_raw_ip_not_pcap`; S7) | P2.8 [linux-ci] (W3–W4 via raw IP with `route_localnet=0`, plus the ignored `loopback_inject_reaches_udp_socket`; S7); P3.13 [mac-signed] (W3–W4 per S8) |
| AC9 | P3.2, P3.9, P6.2, P6.6 | P3.13 step 4 with P6.10's scripts [mac-signed] |
| AC10 | P1b.5, P1b.11, P6.1, P6.5 | P1b.17, P6.10 [mac-any] |
| AC11 | P3.1, P3.2, P3.7, P4.4, P4.5 | P3.13 [mac-any] |
| AC12 | P4.1, P4.2 | P4.7 [mac-signed] |
| AC13 | P3.6 | P3.13 [mac-signed] |
| AC14 | P2.2, P2.3, P3.6 | P3.13 [mac-signed] |
| AC15 | P5.1, P5.2 | P5.3 [linux-ci] |
| AC16 | P1b.12, P2.6 | P2.8 [linux-ci] (test rule `49-aitm-test.rules` present; literals confirmed by S7) |
| AC17 | P1b.5, P1b.14 | P2.8 [linux-ci] |
| AC18 | P1a.2, P1a.3, P1a.4, P2.6, P2.7 | P2.8 [linux-ci] |
| AC19 | P2.6 | P2.8 [linux-ci] |
| AC20 | P1b.2, P1b.14 | P1b.17 [linux-ci] (panel 2026-11-01: re-scoped to P2.8 pending Matt) |
| AC21 | P6.6 | P6.10 [linux-desk] |
| AC22 | P6.3, P1b.14 (`sigint_is_dismissed`, `sigint_handler_installed_not_ignored`; S7; panel 2, 2026-11-01: `held_ctrl_c_keeps_serving` in `crates/aitm/src/lib.rs`, Tester) | P6.10 [linux-ci] (test rule removed; harness matches `==== AUTHENTICATING FOR com.mrbrutti.aitmproxy.l4-helper.run ====`; S7) |
| AC23 | P1b.5 (`prompt_possible` with `tty_opens`; S7), P1b.14 (`no_prompt_is_cannot_prompt_and_spawns_nothing`, `no_agent_text_is_failed`) | P1b.17 [linux-ci] (core under `setsid`; S7; panel 2026-11-01: re-scoped to P2.8 pending Matt); doc branch after P5.4 |
| AC24 | P1b.6, P1b.16 | P1b.17 |
| AC25 | P3.10, P6.1, P6.4, P6.5 | P3.13, P6.10 [mac-any, linux-ci] |
| AC26 | P3.5, P3.10 | P3.13 [mac-any, mac-signed] |
| AC27 | P1b.7 (`gated_verbs_flip_live_and_stay_confirmable`: identical `confirm_prompt`/`sensitivity` before and after the flip for every params, `Some` for in-scope inject/send_recv while gated; reworded by the panel 2026-11-01) | — |
| AC28 | S3 write-up | P3.13 step 7 [mac-signed] |
| AC29 | P4.6 | P4.7 [mac-signed] |

## Independent sets (may run at the same time)

- **Now:** S3, S5 and S7 (S4 and S8 in a VM, or inside S3's window). p1a. p7.
- **After p1a merges:** p1b P1b.1–P1b.10 run in parallel with p2 P2.1, P2.5 and P2.9, and with p5 P5.1. P2.2–P2.4
  start once S4 is written up. P1b.11 starts once S5 is. P1b.12–P1b.14 and P2.6–P2.7 start once S7 is (S7 is written up, PR #240: they are unblocked).
- **After S3 and the orchestrator's go:** p4 P4.1–P4.2 (in parallel with the above). P4.3–P4.5 wait for p2.
- **After p2 merges:** p5 P5.2–P5.3, and p4 P4.3–P4.5.
- **After parity (d), S3 and S5:** p3 P3.1–P3.10 (P3.5 is independent of P3.1–P3.4; P3.10 is independent of
  P3.9). The P3.13 [mac-signed] half waits for p4 and the P4.7 DMG.
- **After p1b, parity (b) and parity (c):** p6. The TUI chain (P6.1–P6.4) and the web chain (P6.5–P6.8) run in
  parallel.

## Questions only Matt can answer (most important first)

1. **Is there a macOS 27 VM the spike sessions may use?** If yes, S3, S4 and S8 run there with no change to your
   Mac. If not, they run on your Mac in one announced window: you approve a spike helper in Login Items once, and
   the same session reverts it.
2. **AC5's `all`-policy literal.** The spec says the agent refusal under `all` starts with `` `l4.privilege.request`
   refused: the agent policy is ``. Today's gate text for a Sensitive verb under `all` reads "…refused: a sensitive
   command is not allowed to the agent under the `all` policy…". Matching the literal needs a second `aitm-mcp`
   change, which the spec forbids. The plan asserts the system-proxy SP-AC16 form instead: the prefix
   `` `l4.privilege.request` refused: `` plus "operator", and the exact literal under `auto` only. Accept, or allow
   the extra `aitm-mcp` edit?
3. **Does "Settings ▸ Uninstall" mean the All Apps extension's Uninstall?** It is the only Uninstall in Settings.
   Running Remove Packet Capture inside it ties the two features together, which fork (iv) kept separate. The plan
   follows the spec literally (P3.11) unless you say otherwise.
4. **TUI key `A`.** `A` is already Resume All. The plan binds Allow to `A` only in the L4 view while the banner
   shows. Keep that, or pick a free key?
5. **Still open from the spec:** written acceptance of `docs/packet-capture.md` (headless `setcap` and the NixOS
   wrapper). P5.4 is blocked until then.
6. **(S7) Ctrl-C while the password prompt is up.** The plan (P1b.14) makes Ctrl-C during a pkexec prompt cancel the
   prompt only; the core keeps running, and a Ctrl-C after the prompt has ended behaves as before. The alternative is
   "Ctrl-C always quits aitm, prompt or not". The Architect chose the first because the operator pressed it to
   decline a password, not to stop the proxy. Confirm or reverse. (Panel, 2026-11-01: the mechanism is now a hold
   count in the `aitm` binary's tokio `ctrl_c` shutdown future, spec §5.5; the question itself is unchanged and
   still awaits your answer.)

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| P1b.14 (S7 amendment) | Architect (e74b0b98) | Decision | Ctrl-C at the pkexec prompt: the core installs a SIGINT handler while a pkexec child is alive; Ctrl-C cancels the prompt only (`dismissed`) and does not shut the core down; the prior disposition returns once the child is gone. `aitm`'s shutdown future (`crates/aitm/src/lib.rs` `shutdown_signal`, tokio `ctrl_c`) must yield to this handler for the prompt window only. | Approved as written by the orchestrator 2026-11-01 under Matt's autonomous-approve mode (**flagged for Matt**): the operator-visible change is confined to the prompt window and is stated in spec §5.5; `aitm web` has no help text documenting Ctrl-C, so nothing else to update. |
| P1b.7 | Coder (1d47a9bd) | Deviation | `L4Gated` holds a private `PrivilegeSource { Live(Arc<PrivilegeState>), Fixed(L4Privilege) }` instead of the plan's bare `Arc<PrivilegeState>`: production constructors (`new`, `with_state`, `with_shared_state`) are `Live`; the test constructors (`with_privilege`, `with_parts`, `with_shared(.., L4Privilege)`) stay `Fixed` because `tests/surface.rs`, `tests/inpath.rs` and `crates/aitm/tests/l4_operator_surfaces.rs` (outside p1b's files) pin the literal reason strings they pass in. | Open for the panel (spec reviewer). Follow-up if the plan-literal shape is wanted: migrate those three tests to a scripted `Prober` and drop `Fixed` (needs a Files-list amendment). |
| P1b.7 / AC27 | Coder (1d47a9bd) | Spec gap | L4PRIV-AC27 assumes `tools/list` shows `confirmable: true` for `l4.inject`, `l4.send_recv`, `l4.intercept.forward`, `l4.intercept.drop`; their `confirm_prompt(&Params::default())` is `None` today even on a privileged core (inject.rs, sendrecv.rs need `spec`/`dst`/`interface`; the verdict verbs need a parked id), so `confirmable` was never true for them. `L4Gated` now forwards `confirm_prompt` (mutation-checked); the test pins `Some` for in-scope `l4.inject`/`l4.send_recv` params before and after the flip and identical answers for all four on empty params. | Open: AC27 wording needs an Architect amendment ("the gated and ungated `confirm_prompt` answers are identical for every params value"), orchestrator/Matt to accept. |
| P1b.8 | Coder (Rule 10 report) | Tripwire change | `tests/hard_gates.rs::exactly_one_production_wire_write` counted `RoutedBackend::inject`'s delegation (`self.route(&report.inject)?.inject(iface, bytes)`) as a second production wire write. The router carries no permit and is reached only via `send_on_wire(permit, backend, ..)`; the tripwire now pins `backend/routed.rs` ×1 beside `wire.rs` ×1 so a second call in either file still fails. | Granted by the p1b orchestrator 2026-11-01; **security reviewer to confirm** the pin (the alternative, respelling the call to dodge the scan, was refused). |
| P1b.13 | Coder (Rule 10 report) | Tripwire change | `hard_gates.rs::exactly_one_production_wire_write` also counts `HelperBackend::inject`'s one delegation to `HelperSession::inject`; pinned `backend/helper.rs` ×1 beside the P1b.8 pin. | Granted by the p1b orchestrator 2026-11-01; **security reviewer to confirm** (three pinned sites: helper.rs, routed.rs, wire.rs). |
| P1b.13 | Coder | Spec gap | `CaptureInjectBackend::open_capture(iface, filter, read_timeout)` carries no direction, so `HelperBackend` sends `CaptureOpen { direction: Inbound }` as a constant; the helper's `capture_filter` is by interface today, so the field is informational on the wire. Also: the protocol has no `CaptureOpen` ack, so a helper refusal arrives as `CaptureClosed` and surfaces on the first `next_frame` (an empty capture flow, not a failed `l4.capture.start`). | Open for the Architect: add `direction` to the trait (touches backend/mod.rs, pcap.rs, routed.rs, capture.rs, mocks) and consider a `CaptureOpened`/ack frame in a proto 2; not Phase 1 blocking. |
| P1b.15 | Coder (558ec344) | Interpretation | `request: at_start` fires only in serving modes (`aitm`, `aitm web`, `aitm tui`), after the one-shot `Cli` early return, so a one-shot `aitm flow list` never hands off to the app or spawns pkexec; spec §2.4 names serving cores and the Linux one-shot refusal. The module registers 22 `l4.*` names on this branch, so the wire pin is 24 (22 + 2), not the plan's 27 (parity verbs not landed here); P1b.17/P1b.18 use 24. | Open for the spec reviewer; p1b orchestrator accepts the serving-only reading. |
| P1b.15 | Coder | Observation | `crates/aitm/tests/l4_cua_tui.rs` (outside p1b's files) runs over the live state now and asserts the pre-P1b.7 reason literal; it binds a port, so it shows only in the Terminal gate. | Red in the Terminal run (line 572: the test encoded the pre-AC27 suppressed confirm prompt). File claimed for p1b by the orchestrator 2026-11-01 (l4-parity unit (b) also edits it; whoever lands second re-merges); fixed in e79aeab0: the else-branch expects `Mode::L4Confirm`, presses `y`, then asserts the typed `L4 unavailable`. |
| Spec Status (phase 2) | Matt via the orchestrator | Decision | No third-party privilege daemon on any operator machine, ever; ChmodBPF dead as idea and fallback. Phase 2 (our own component in serve mode doing capture and injection for the core) is the REQUIRED end state; the Architect may revisit option A (frames in the system extension), which Matt allows expanding. Phase 1 (SMAppService bpf permissions) stays as the stepping stone for T5's Mac proof. | Matt, 2026-11-01 ("yes I think we need to build our own solutions and our network extension should handle it; if we need to expand it so be it"). Folded into the spec Status line; p1b code stays on phase 1; the phase-2 carrier is a spec amendment, not a p1b task. |
| P1b.14 | Coder (8d185d1e) | Gap (Rule 8) | The real SIGINT handler install needs `nix::sys::signal::sigaction`, which is `unsafe fn`; under `unsafe_code = "forbid"` it cannot live in `aitm-proto-l4`. `SignalGuard` is a seam (`NoopSignalGuard` in production) pinned by `sigint_handler_installed_not_ignored`; spec §5.5's "Ctrl-C at the prompt does not shut the core down" is NOT delivered by p1b. | Open follow-up: a leaf crate (`aitm-peer-token` style) with a `// SAFETY:` comment and Security-reviewer sign-off, per spec Constraints; orchestrator to schedule. Until then Ctrl-C at a textual pkexec prompt reaches the core with its normal disposition. |
| P1b.14 | Coder (8d185d1e) | Interpretation | A helper session's end marks the privilege cache dirty so the next `report()` re-probes (capture flips back to `needs_approval`); the lazy direct start of a file-caps helper is Serving-only (a one-shot on that row gets `HELPER_NOT_WIRED`); the generic failure message names `pkexec` because spec §5.5 pins "The packet-capture helper did not start (pkexec exit <n>)" verbatim (progress messages are outside the P1b.3 tripwire). `PrivilegeState::set_guard` must be called from the binary wiring. | Open for the panel (spec reviewer on the first two; Rule 2 reading on the third). `set_guard` fixed in 33c2e16d: `L4Module::from_parts` attaches the module's guard on every live constructor (`module::tests::live_constructors_attach_the_guard_to_the_privilege_state`). |
| p1b panel (stage 6, range 1abac42a..048e0c03) | Tester / Security / Quality / Spec | Verdicts | Tester PASS (7 Minor); Security PASS (7 Minor; three-site `hard_gates` pin and `SignalGuard` seam confirmed acceptable); Quality FAIL (1 Important: `PrivilegeState::report()` holds the cache mutex across the subprocess-spawning probe, `request()` probes twice; 13 Minor); Spec FAIL (5 Important: SIGINT hold not delivered and the Rule-8 justification incomplete; `[linux-ci]` half of P1b.17 not run; `helper.status: version_mismatch` unreachable; six undeclared per-task files; unrecorded spawn-path deviations). | Fix task dispatched 2026-11-01 for every Important and the cheap Minors; the rest below. |
| P1b.6/8/9/10/12/15 | Spec reviewer | Rule 10 (unrecorded files) | P1b.6 edited privilege/{linux,macos}.rs (allow removals); P1b.8 tests/privilege.rs (one comment); P1b.9 commands/mod.rs (`PrivilegeReportSource`, `with_privilege`, `privilege_field`, 5th `wire_commands` arg) and backend/routed.rs (test call); P1b.10 privilege/state.rs (`request`, `RequestOutcome`, `Outcome`: demanded by the task's own Change list); P1b.12 Cargo.lock (one derived edge); P1b.15 crates/aitm-proto-l4/src/lib.rs (two re-exports). | Granted retroactively by the p1b orchestrator 2026-11-01: all inside p1b's unit claims except `Cargo.lock`, whose edit is the derived lock line for the declared Cargo.toml change (p2 owns the lock for the new crate only). Files lists of P1b.9/P1b.10/P1b.15 amended by the Architect. |
| P1b.13/P1b.14 | Spec reviewer | Unrecorded deviations | (a) argv is `/usr/bin/pkexec …` (absolute `PKEXEC_PATH`), not `"pkexec"`; (b) child env is `env_clear()` plus `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY` only (no `SHELL`: pkexec refuses a value absent from /etc/shells; no `LANG`/`LC_*`: the S7 stderr literals stay English); (c) `request_linux` checks the packaged rows before `prompt_possible`; (d) `add_self_ports` also bumps `scope_generation`; (e) `L4Guard::scope_set()` is new public API. | (a), (d), (e) accepted by the p1b orchestrator 2026-11-01 (improvements the §5.2 `ScopeSet` needs). (b), (c): Architect sentence in §5.5 / P1b.14; (b) is proven only by the [linux-ci] run. |
| P1b.14 (SIGINT) | Spec reviewer | Correction of the disposition above | `signal-hook` 0.3 is in Cargo.lock and safe, so the "needs unsafe sigaction" premise was incomplete. Better still, `aitm` already owns SIGINT through tokio's `ctrl_c` (`crates/aitm/src/lib.rs` `shutdown_signal`), so the process does not die from the signal; what shuts the core down is the shutdown future. The hold therefore belongs in the binary: a hold count the `PrivilegeState` raises around the pkexec child and `shutdown_signal` consults (Ctrl-C while held logs and keeps serving). No unsafe, no new crate. | Fix task 2026-11-01 (replaces the leaf-crate follow-up). Matt's Question 6 stays flagged. |
| P1b.17 [linux-ci] | Spec reviewer | Evidence gap | The Linux live half (AC20, AC23 and the Linux cells of `test_privilege_core.py`) was not run: `cis-lab` has no container rig yet (S7 write-up: podman must be installed, containers need `--systemd=always --privileged`), and P2.8 builds exactly that rig. | Proposed re-scope to P2.8 [linux-ci] (the helper unit, which needs the same container), approved by the orchestrator 2026-11-01 under Matt's autonomous-approve mode, **flagged for Matt** (evidence rule): the Linux live half runs on the rig p2 builds (P2.8); the p1b PR states the Linux request path is unit-tested only until then. |
| Minors accepted (fixed or carried) | Tester / Security / Quality | Minor | Carried as accepted follow-ups, not fixed in p1b: split `state.rs` into state/watch/request modules; one `privilege/text.rs` for the operator literals; lift the e2e soft-assert scaffolding into `aitm_e2e`; one shared poison-recovering `lock` helper; named derive row builders; `/tmp/aitm-<uid>` squat fallback (honest refusal today); `Mode → ProcessLifetime` unit test (main.rs has no test module); p7's `is_operator_only` entry (separate unit). | Accepted by the p1b orchestrator 2026-11-01 under Matt's autonomous-approve mode (**flagged for Matt**); everything else Minor is in the fix task. |
| Fix task A (panel) | Coder (57adb301, 855b7a21, 9ee33e18) | Fixed + Rule 10 | All three Important items fixed (single-flight probe outside the cache lock; SIGINT hold count in the binary's shutdown future with the literal line "Ctrl-C cancelled the packet-capture prompt; the core keeps serving"; `helper.status: version_mismatch` from `LinuxInputs.last_session_error`), Security S1–S5 and Quality T2/Q2/Q4–Q7/Q9/Q10/Q12 fixed. Two one-line test-literal edits outside the task's list (`availability.rs:116`, `commands/intercept.rs:1316`: `last_session_error: None`) were required to compile. `Requester`, `LiveBackend`, `with_requester`, `set_helper_backend` became `pub`. `aitm tui`'s own `shutdown_signal` await (`crates/aitm/src/tui.rs`) does not consult the hold yet. | Rule 10 edits granted retroactively by the p1b orchestrator 2026-11-01 (both in p1b's unit files). The `pub` widening and the TUI shutdown arm go to the re-review panel; the TUI arm is p6's (P6.3) unless the panel rates it Important. Fix B e79aeab0 (e2e exemption, l4_cua_tui AC27 branch). |
| p1b re-review (fix range 048e0c03..0661937b) | Security / Quality / Spec (Tester pending) | Verdicts | Security PASS (5 Minor: `aitm tui` shutdown arm without the hold; a held Ctrl-C delivered to the core alone kills nothing; no unwind guard on `watching`; probe cache keyed on settable mtime; bundle stamp misses an in-place executable overwrite). Quality PASS (13 Minor: vestigial `SignalGuard`/`Box<dyn Any>` hold token; `PlatformRequester` does not override `spawner()`; test-only `classify_exit` pair form; repeated watcher epilogue; file-caps rule spelled thrice; double `refuse_by_path`; duplicate `is_live`; `should_shut_down` trivial; sleep-poll loops; `bundle_stamp` positional options; env-dependent macOS test; self-referential expected message; `aitm tui` arm). Spec FAIL (3 Important: a protocol handshake error must read `helper.status: unknown` per amended §5.2; the `aitm tui` select arm must consult the hold; the plan's `pkexec_env_is_cleared_but_for_display` and `held_ctrl_c_keeps_serving` tests are absent from the committed range; plus Minors: stale "bus fixture" comment in wire.rs, e2e exemption wider than the pinned literal, `pub` surface wider than needed, `SessionFailure` name unrecorded, S1–S5/Q10 literals absent from the spec, §10 lacks lib.rs, test names differ from the AC map, `l4_cua_tui` Terminal result not yet quoted). | Fix task C dispatched 2026-11-01 for the three Important items, the Security Minors, and the cheap Quality/Spec Minors; Architect pass for the spec sentences. Accepted as follow-ups by the p1b orchestrator (**flagged for Matt**): the `Condvar` replacement of the two sleep-poll loops. `crates/aitm/src/tui.rs` one-line hold wiring granted to p1b by the orchestrator 2026-11-01 (p6's row amended: the hold is already wired). |
| Fix task C (panel 2) | Coder (d6b2b42b, 2634ff00, 698eef43) | Fixed | C1 `Protocol` handshake failure → `helper.status: unknown` (`protocol_failure_is_unknown_with_detail`); C2 `aitm tui` shutdown arm consults the hold (`PromptHold` threaded into `tui::run`; `tui_shutdown_arm_consults_the_prompt_hold` tripwire); C3 `pkexec_env_is_cleared_but_for_display` (real `StdSpawner`, load-bearing: fails with `env_clear()` removed); C4 `PrivilegeState::cancel_prompt()` sends SIGINT via `Child::interrupt()` (nix `signal` feature on the Linux-target dep, no new crate), `interrupt_unless_held(.., on_held)` cancels on a held Ctrl-C (`held_ctrl_c_alone_cancels_the_prompt`); C5 watcher unwind guard `Watch` (`watcher_panic_releases_hold_and_ends_pending`) with the one `end_request` epilogue (C11); C6 `ProbeKey { dev, ino, size, mtime, ctime }`; C7 `BundleStamp::new` with the main executable's mtime+size; C8–C10, C12–C21 as listed (SignalGuard deleted, `pub(crate)`/`#[cfg(test)]` tightening, e2e regex exact, `l4_cua_tui` bounded wait). Fixed-first evidence for C1–C7; C8–C21 compile-driven. | Granted/accepted by the p1b orchestrator 2026-11-01; `crates/aitm-proto-l4/Cargo.toml` edit (one feature) granted. Third review round dispatched on bbd198cc..HEAD. |
| p1b round 3 (fix C range bbd198cc..b2809361) | Tester / Security / Quality / Spec | Verdicts | All four PASS. Tester d2ef7a8d added S1-ordering tests for the accept-errors and panic arms, `cancel_prompt_never_signals_a_serving_helper`, a real-child `interrupt` test, and a stricter tui tripwire; 4 Minor. Security 3 Minor (predecessor watch clearing a successor's slot/flag during reap; panic path left the child alive; env test could print a value fragment). Quality 8 Minor. Spec 6 Minor (recording gaps; e2e `waitpid` alternative; new `pub` items; `l4_cua_tui.rs` not in the claims row). | Fix task D (ca0d2385, ade367a9) fixed: watch-owned prompt slot (`Arc::ptr_eq`) and `watching` generation (CAS); unwind kills the child; env test hygiene (first partial line dropped, keys-only messages, `RestoreEnv`); `cancel_prompt` via `try_lock`; `prompt = hold.is_some()`; `write_progress`; off-Linux `interrupt` no-op; `pub(crate)` + `cfg_attr(allow(dead_code))` on the per-OS cache types; `BundleStamp` plist `FileStamp`; e2e regex exactly the two pinned forms; `l4_cua_tui` bound 20 s (post-TTL probe cost: synchronous `codesign --verify --strict`, 5 s bound, when `/Applications/Aitmproxy.app` exists). Architect eb77bc13 recorded the literals, stamp wording, `HoldCount`/`classify_exit_full`, claims, `--bin aitm` gate line, probe-cost follow-up. Accepted as follow-ups by the p1b orchestrator (**flagged for Matt**): `Watch::serve` extraction (the live arm still pokes `Watch` fields; the `Err(Timeout)` branch in `accept` is unreachable); `cancel_prompt` `try_lock` may drop a Ctrl-C landing inside one 100 ms watcher slice (a second Ctrl-C cancels; the pid-signal alternative cannot be faked); background probe thread so a gated invoke never pays the probe synchronously. |
| P1b.14 (S7 amendment) | Architect (e74b0b98) | Decision | pkexec exit 127 with `Error creating textual authentication agent` after a `pending` reply maps to progress `failed` with the no-prompt message plus one `warn` line; `cannot_prompt` stays the outcome of the pre-spawn check. | Approved as written by the orchestrator 2026-11-01 under Matt's autonomous-approve mode (**flagged for Matt**): the two paths stay distinguishable in the audit line. |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
