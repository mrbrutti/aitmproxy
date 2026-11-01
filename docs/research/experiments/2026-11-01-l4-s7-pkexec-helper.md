# Experiment: S7, pkexec details for the Linux L4 capture helper

**Date:** 2026-11-01
**Branch:** `experiment/l4-s7-pkexec` (never merged; the plan names it `experiment/l4priv-s7-pkexec`, the
orchestrator's brief named this one). Spike code lives only on this branch's session scratch and is not in git.
**Session:** separate session with its own worktree, GO from the orchestrator for the lab only
**Plan:** `docs/superpowers/plans/2026-10-31-l4-capture-privilege-plan.md`, Phase 0, S7
**Spec:** `docs/superpowers/specs/2026-10-31-l4-capture-privilege-design.md` §5.1, §5.4, §5.5, AC16, AC22, AC23
**Where:** Lima VM `cis-lab` only (Ubuntu 24.04.4, kernel 6.8.0-134-generic, aarch64). Nothing on Matt's Mac changed.
**Result: PROVEN**, with three corrections to the spec (prompt-possible test, exit-code mapping, loopback inject path).

## Question

Does `pkexec` with a shipped `.policy` (`auth_admin` everywhere) start the helper as root with `PKEXEC_UID` set, and
does the spec §5.1 start-up order leave a process that holds exactly `CAP_NET_RAW`, can open and inject on `lo`
through libpcap, and nothing else? Plus the plan's seven sub-questions:

1. Does pkexec's textual agent prompt while the core's stdout and stderr are redirected?
2. Does pkexec close fds above 2?
3. Does pkexec exec in place, so the `SO_PEERCRED` pid equals the pid the core spawned?
4. Is `PKEXEC_UID` set, and are the exit codes 126 (dismissed) and 127 (not authorized)?
5. After the §5.1 drop, can `pcap` still open `lo` and inject on it?
6. Is `CAP_NET_RAW` alone enough, or does capture need `CAP_NET_ADMIN` too?
7. Do `/proc/<pid>/status` lines match AC16's literals?

Also asked by the brief: can a passed Unix-socket fd be used after the drop; what the agent needs on a headless host;
what a GNOME desktop shows (documented, not run); exact texts for a cancelled prompt.

## Setup

**Rig (differs from the plan's assumption).** `cis-lab` has no `nerdctl`, `docker` or `podman`. `podman` 4.9.3 was
installed from Ubuntu's apt inside the VM for the spike and purged at revert. Two systemd containers under rootful
podman:

| Container | Image | polkit | Admin rule (`50-default.rules`) |
|---|---|---|---|
| `s7-debian` | `debian:trixie` + `systemd dbus polkitd pkexec gcc libcap-dev libpcap-dev python3` | 126-2 | `unix-group:sudo` |
| `s7-fedora` | `fedora:42` + `systemd dbus-broker polkit gcc libcap-devel libpcap-devel python3` | 126-3.fc42.2 | `unix-group:wheel` |

Users: `tester` (password, in `sudo`/`wheel`) and `plain` (password, no admin group). Policy at
`/usr/share/polkit-1/actions/com.mrbrutti.aitmproxy.l4-helper.policy` exactly as spec §5.4 (action
`com.mrbrutti.aitmproxy.l4-helper.run`, `exec.path` = `/usr/lib/aitmproxy-spike/helper`, `allow_gui` true, all three
defaults `auth_admin`). `pkaction --verbose` reported it as written.

Two lab-only facts cost a run each and matter for the P2.8 rig:

- **`polkitd` does not start in an unprivileged container.** Its unit carries `PrivateDevices`, `ProtectSystem=strict`
  and friends; without `CAP_SYS_ADMIN` systemd fails it with `status=217/USER`, `Failed to keep CAP_SYS_ADMIN:
  Operation not permitted`, and every `pkexec` then dies after 25 s with `Error getting authority: Error initializing
  authority: Error calling StartServiceByName for org.freedesktop.PolicyKit1: Timeout was reached` (exit 127). The
  containers ran `podman run -d --systemd=always --privileged`, which also gives root inside the full bounding set
  (`CapBnd 000001ffffffffff`), the same ceiling a real host gives pkexec.
- **Fedora's PAM failed with the right password** until the Ubuntu host's AppArmor profile `unix-chkpwd` was unloaded
  in the VM (`apparmor_parser -R /etc/apparmor.d/unix-chkpwd`, reloaded at revert). It attaches by path inside the
  container and denies `unix_chkpwd` `dac_read_search`, and Fedora's `pam_unix` always uses the helper when the real
  uid is not root (`polkit-agent-helper-1` is setuid, real uid 1000). Debian reads `/etc/shadow` directly as euid 0
  and was unaffected.

**Spike code** (throwaway, ~330 lines C + ~260 lines Python, built inside each container with `gcc -lcap -lpcap`):

- `helper.c`: `serve --connect <abs path>` following §5.1 steps 1-6 verbatim, reporting every step first to a buffer,
  then over the socket once connected. Variant flags turned single steps off to see what each one buys:
  `--pdeathsig-early`, `--no-keepcaps`, `--no-bounding`, `--initgroups`. After the drop it ran the capability probes
  in the table below, then set `PR_SET_PDEATHSIG` and re-checked `getppid()`.
- `core.py`: binds `l4-helper-<pid>.sock` in `$XDG_RUNTIME_DIR/aitm` (0700), binds UDP `127.0.0.1:9053` as the inject
  target, spawns `pkexec /usr/lib/aitmproxy-spike/helper serve --connect <path>` (or the helper directly), accepts,
  reads `SO_PEERCRED`, relays the helper's report, asks for a second inject, then closes.
- `harness.py`: runs the core under a pty as `tester` or `plain`, logs the pty, answers `Password:` with the password,
  a wrong one, Ctrl-C or Ctrl-D, or runs the core with `setsid` and no controlling terminal at all.

Each distro ran 21 scenarios. Skipped: tests, error handling beyond reporting, the GNOME desktop (no GUI VM here).

## Result

### The happy path (scenario A, both distros identical)

What `tester` sees on the terminal, byte for byte apart from ANSI colour codes:

```
==== AUTHENTICATING FOR com.mrbrutti.aitmproxy.l4-helper.run ====
Allow aitmproxy to capture and send raw packets (only within the L4 scope you configured)
Authenticating as: tester
Password:
==== AUTHENTICATION COMPLETE ====
```

0.4 s after the password the helper connected. The core's `SO_PEERCRED` read `pid=142 uid=1000 gid=1000`, and 142
was the pid `Popen` returned for `pkexec`. The helper's own report:

```
step1 pid=142 ppid=141 uid=0 euid=0 gid=0 egid=0
step1 isatty stdin=1 stdout=1 stderr=1
step1 open(/dev/tty): ok
step1 cwd=/root
step1 fd3 inherited: no
env SHELL=/bin/bash
env LC_CTYPE=C.UTF-8
env XAUTHORITY=/home/tester/.Xauthority
env PATH=/usr/sbin:/usr/bin:/sbin:/bin:/root/bin
env LOGNAME=root
env USER=root
env HOME=/root
env PKEXEC_UID=1000
step1 CapPrm: 000001ffffffffff   CapEff: 000001ffffffffff   CapBnd: 000001ffffffffff   CapAmb: 0
step2 root, PKEXEC_UID=1000 -> invoking uid 1000
step3 bounding: dropped 40, failed 0, CAP_LAST_CAP=40
step3 ambient cleared
step3 keepcaps=1
step3 setgroups([1000])
step3 setresgid/setresuid done uid=1000 euid=1000
step3-after-setuid CapPrm: 000001ffffffffff  CapEff: 0000000000000000  CapBnd: 0000000000002000
step3 capset(cap_net_raw=ep): ok
step3 no_new_privs=1
step3-done Uid: 1000 1000 1000 1000
step3-done Gid: 1000 1000 1000 1000
step3-done Groups: 1000
step3-done CapInh: 0000000000000000
step3-done CapPrm: 0000000000002000
step3-done CapEff: 0000000000002000
step3-done CapBnd: 0000000000002000
step3-done CapAmb: 0000000000000000
step3-done NoNewPrivs: 1
step4 socket: is_sock=1 is_lnk=0
step4 dir /run/user/1000/aitm: is_dir=1 is_lnk=0 uid=1000 mode=0700
step5 connected; peer pid=141 uid=1000 gid=1000
step6 pdeathsig=9 ppid now 141 (recorded 141) same
READY
```

`final` status lines equalled `step3-done`. Every `Uid:` field, `CapEff`, `CapPrm`, `CapBnd`, `CapAmb` and
`NoNewPrivs` match **AC16's literals exactly** on Debian trixie and Fedora 42.

### What the dropped helper can and cannot do (after `step3-done`, both distros)

| Probe | Needs | Result |
|---|---|---|
| `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)`, `bind` to `lo` | `CAP_NET_RAW` | ok |
| `PACKET_ADD_MEMBERSHIP` `PACKET_MR_PROMISC` on `lo` | `CAP_NET_RAW` | ok |
| `pcap_create("lo")`, promisc, immediate, `pcap_activate` | `CAP_NET_RAW` | ok, `datalink=1` (EN10MB) |
| `pcap_setfilter("udp and port 9053")` | nothing | ok |
| `pcap_inject` 53-byte Ethernet+IPv4+UDP frame to 127.0.0.1:9053 | `CAP_NET_RAW` | ok, 53 bytes |
| `pcap_dispatch` sees the injected frame | | yes, 1 frame |
| `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` | `CAP_NET_RAW` | ok (expected; raw IP is the same capability) |
| `bind` TCP 127.0.0.1:80 | `CAP_NET_BIND_SERVICE` | `Permission denied` |
| `ioctl(SIOCSIFFLAGS, IFF_PROMISC)` on `lo` | `CAP_NET_ADMIN` | `Operation not permitted` |
| `open("/etc/shadow")` | root | `Permission denied` |
| `setuid(0)` | `CAP_SETUID` | `Operation not permitted`, uid stays 1000 |
| `PR_CAPBSET_READ` `CAP_NET_ADMIN` / `CAP_NET_RAW` | | 0 / 1 |
| `cap_set_proc("cap_net_raw,cap_net_admin=ep")` | | `Operation not permitted` |
| `PR_CAP_AMBIENT_RAISE CAP_NET_RAW` | inheritable bit | `Operation not permitted` |
| `exec /usr/bin/pkexec --disable-internal-agent /bin/true` under `no_new_privs` | | exit 127, `pkexec must be setuid root` |

**`CAP_NET_RAW` alone is enough** for libpcap to open `lo` in promiscuous mode, filter, capture and inject. libpcap
uses `PACKET_ADD_MEMBERSHIP`, not `SIOCSIFFLAGS`, so `CAP_NET_ADMIN` is never asked for. The spec's AC16 literals
stand; the plan's stop condition ("if `CAP_NET_RAW` alone is not enough, stop") does not fire.

### What each drop step buys (variants, both distros)

| Variant | Effect |
|---|---|
| `--no-keepcaps` (skip `PR_SET_KEEPCAPS` before `setresuid`) | `capset(cap_net_raw=ep)` fails `Operation not permitted`; `CapPrm`/`CapEff` end `0`; `AF_PACKET` and `pcap_activate` fail `Operation not permitted`. **Keepcaps is mandatory.** |
| `--no-bounding` (skip the bounding-set drop) | capture still works; `CapBnd` stays `000001ffffffffff`. The bounding drop is defence in depth only, and it worked for all 40 capabilities (CAP_LAST_CAP=40 on 6.8) because `CAP_SETPCAP` was still held. |
| `--pdeathsig-early` (set `PR_SET_PDEATHSIG` before the drop) | `PR_GET_PDEATHSIG` reads **0** after `setresuid`. The kernel clears the parent-death signal when `commit_creds` makes the task non-dumpable. **PDEATHSIG must be set after the drop**, as §5.1 step 6 says; it is a correctness requirement, not a style choice. |
| `--initgroups` (use `initgroups(user)` instead of `setgroups([gid])`) | `Groups:` becomes `27 1000` (Debian) / `10 1000` (Fedora): the helper keeps the admin group. `setgroups([primary gid])` gives `Groups: 1000` only. |
| `kill -9` the core once `READY` (scenario H) | `pgrep -af aitmproxy-spike/helper` finds nothing 2.5 s later on both distros. |

### The seven questions

1. **Textual agent with redirected stdio: yes.** With the core's stdout+stderr sent to a file (B), and with stdin on
   `/dev/null` as well so `isatty` is 0 on all three (C), the prompt still appeared on the pty and the password
   worked (exit 0, helper connected). The agent opens the **controlling terminal** (`/dev/tty`), not stdin. With no
   controlling terminal at all (`setsid`, scenario D) pkexec fails in 0.5 s, exit **127**, before any authorization:

   ```
   Error creating textual authentication agent: Error opening current controlling terminal for the process (`/dev/tty'): No such device or address
   ```

   The core's helper spawned directly saw `isatty 0 0 0` and `open(/dev/tty): ok` in C, which is the test that
   predicts a prompt.
2. **fds above 2: pkexec closes them.** The control run M2 (helper spawned directly with a socketpair end dup'd onto
   fd 3) shows `fd3 inherited: yes (socket)` at step 1 and the core read `hello-from-helper-fd3` from it after the
   drop. The same spawn through pkexec shows `fd3 inherited: no` at step 1 on both distros. Nothing can be passed to
   the helper by inheritance; the connect-by-path design in §5.1 is the only option (and works, see step 5).
3. **Exec in place: yes.** In all 17 pkexec scenarios `SO_PEERCRED.pid == Popen.pid`. The helper's own exit code is
   pkexec's: an unknown flag made the helper exit 2 and the core saw `PKEXEC_EXIT 2` (scenario O). Note pkexec
   authenticated *before* the helper rejected its argv.
4. **`PKEXEC_UID` is set** (`PKEXEC_UID=1000`). The whole environment the helper gets is the eight variables above:
   `XDG_RUNTIME_DIR`, `TERM`, `DISPLAY` are gone, `cwd` is `/root`, and `XAUTHORITY` is passed because of
   `allow_gui`. **Exit codes on a tty are not 126/127 as the spec assumes:**

   | Case | What the user sees on the tty | pkexec exit |
   |---|---|---|
   | Wrong password (G) | `polkit-agent-helper-1: pam_authenticate failed: Authentication failure` / `==== AUTHENTICATION FAILED ====` / `Error executing command as another user: Not authorized` / `This incident has been reported.` | **127** after 2.5 s (`pam_faildelay`) |
   | Ctrl-D at the prompt (F) | `** (process:210): WARNING **: 16:59:32.828: Got unexpected EOF while reading from controlling terminal.` then the same three FAILED lines | **127** |
   | Ctrl-C at the prompt (E, E3) | nothing more is printed | **killed by SIGINT** (wait status signal 2); the core, in the same foreground process group, gets SIGINT too |
   | No controlling terminal, no agent (D) | `Error creating textual authentication agent: …` (above) | **127** |
   | Not an admin (`plain`, E) | `Authenticating as: tester` (the admin-rule identity, not the caller) then `Password:` | as above |
   | Test rule `polkit.Result.YES` (N) | nothing; the helper connected at t=0.0 s | 0 |

   **126 (`Request dismissed`) never occurs with the textual agent.** pkexec(1) documents 126 for an agent that
   reports cancellation; only the graphical agents do that.
5. **Yes.** See the probe table: open, promisc, filter, inject and read-back on `lo` all work after the drop.
6. **`CAP_NET_RAW` alone.** `CAP_NET_ADMIN` is only needed for `SIOCSIFFLAGS`, which libpcap does not use.
7. **Yes**, byte for byte: `Uid: 1000 1000 1000 1000`, `CapPrm`/`CapEff`/`CapBnd` `0000000000002000`,
   `CapAmb 0000000000000000`, `NoNewPrivs: 1` (also `CapInh 0`, `Groups: 1000`).

### Ctrl-C needs care in the core (scenarios E, E2, E3)

Ctrl-C at the password prompt sends SIGINT to the foreground process group, which contains the core. Three runs:

- E, core with default SIGINT: the **core died** (`KeyboardInterrupt`) and pkexec with it. In the product that is
  `aitm` or `aitm tui` exiting because the user declined a prompt.
- E2, core with `SIG_IGN` on SIGINT around the spawn: **the prompt hangs.** `SIG_IGN` survives `execve`, so pkexec
  and its agent ignore Ctrl-C as well; the harness killed it after 15 s.
- E3, core with a SIGINT *handler*: the core logged the signal and kept running; pkexec died of SIGINT in 0.5 s;
  the handler is reset to default across exec, so the child behaves normally. **This is the shape to build.**

### Loopback inject: an L2 frame on `lo` is a martian (scenarios A, P, P2)

The frame the helper injected through `pcap_inject` was seen by its own capture but **never reached the core's UDP
socket** on `127.0.0.1:9053`. With `log_martians=1` the kernel said why:

```
IPv4: martian destination 127.0.0.1 from 127.0.0.1, dev lo
```

Locally generated loopback traffic carries a route; a frame injected through a packet socket does not, so
`ip_route_input_slow` refuses the 127/8 destination unless `net.ipv4.conf.lo.route_localnet=1`. With that sysctl set
(P) the drop moved to `IPv4: martian source 127.0.0.1 from 127.0.0.1, on dev lo`, which needs
`net.ipv4.conf.lo.accept_local=1` as well. With **both** sysctls (P2) the UDP socket finally received the injected
datagram. Both are root-only sysctls the product can never ask for and the helper cannot set with `CAP_NET_RAW`.

The fix needs no sysctl: injecting the same IPv4 packet (Ethernet header stripped) through
`socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` with `IP_HDRINCL` is allowed by `CAP_NET_RAW`, goes through `ip_output` with
a route attached, **was delivered to the UDP socket on every run with default sysctls**, and was also seen by the
pcap capture on `lo` (`T pcap_capture after rawip: saw 1 frame(s) to udp/9053 on lo`). Measured on both distros:

```
T pcap_inject: ok 53 bytes
T pcap_capture: saw 1 frame(s) to udp/9053 on lo
T rawip_sendto(127.0.0.1): ok 45 bytes (IP_HDRINCL, AF_INET SOCK_RAW)
CORE udp/9053 after start: [('rawip-s7-inject-1', ('127.0.0.1', 49153))]
```

This is the Linux half of AC8 W3-W4 (`l4.inject` and `l4.send_recv` to 127.0.0.1:9053); S8 covers the macOS half.

### Audit trail

Every attempt is in the journal, with the **core's full command line** and the helper's argv:

```
polkitd[154]: Operator of unix-process:201:194919520 FAILED to authenticate to gain authorization for action com.mrbrutti.aitmproxy.l4-helper.run for unix-process:201:194919520 [/usr/bin/python3 /s7/core.py --pass-fd3] (owned by unix-user:tester)
pkexec[202]: tester: Error executing command as another user: Not authorized [USER=root] [TTY=/dev/pts/0] [CWD=/home/tester] [COMMAND=/usr/lib/aitmproxy-spike/helper serve --connect /run/user/1000/aitm/l4-helper-201.sock]
pkexec[142]: tester: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/home/tester] [COMMAND=/usr/lib/aitmproxy-spike/helper serve --connect /run/user/1000/aitm/l4-helper-141.sock]
```

So the socket path and anything else on the helper's argv or the core's argv is visible to any journal reader.
Neither carries a token today; keep it that way.

### Headless hosts and GNOME (documented, not run)

- **Headless / SSH (measured here):** no logind session exists for a `su`'d or container process, and an SSH session
  is not local, so polkit evaluates `allow_any`. The spec's "all three defaults `auth_admin`" is what makes the
  prompt appear in both cases. The textual agent needs only a controlling terminal; the prompt names the admin
  identity (`Authenticating as: tester`), which for a non-admin caller is somebody else's account.
- **GNOME desktop (from pkexec(1) and polkit(8), not measured):** the session's registered agent (gnome-shell's)
  shows a dialog with the policy `message`, an identity chooser when several admins exist, the password field, and a
  "Details" disclosure with the action id and the program path from `exec.path`. The local active session evaluates
  `allow_active`. Cancel makes pkexec print `Error executing command as another user: Request dismissed` and exit
  **126**; a failed authentication exits **127** as on the tty. `allow_gui` passes `DISPLAY` and `XAUTHORITY` to the
  helper, which has no use for them. AC21 on the [linux-desk] rig is where this gets measured.

### Revert

All run through the Terminal panel into `cis-lab`; nothing ran on the Mac:

1. `sudo podman rm -f s7-debian s7-fedora`, `sudo podman rmi -f localhost/s7-debian localhost/s7-fedora
   docker.io/library/debian:trixie registry.fedoraproject.org/fedora:42`, `sudo podman image prune -af`.
2. `sudo rm -rf ~/l4priv-s7` (the `podman cp` output was root-owned).
3. `sudo apparmor_parser -r /etc/apparmor.d/unix-chkpwd` (profile back).
4. `sudo apt-get purge -y podman uidmap slirp4netns` and autoremove of what it pulled in.
5. Verified `podman ps -a` / `podman images` empty before the purge, `~/l4priv-s7` gone, `podman` binary gone.

## Conclusion

**Proven.** pkexec plus the spec §5.1 order gives a helper that holds `CAP_NET_RAW` and nothing else, matches AC16
literally, can capture and inject on `lo` through libpcap, dies with the core, and cannot be fed an fd. Three
assumptions in the spec are wrong and one gap is new:

1. The "prompt is possible" test in §5.5 ("the core's stdin is a tty") is the wrong predicate. The textual agent
   needs a **controlling terminal**, which is independent of where stdin, stdout and stderr point.
2. The exit-code mapping in §2 ("`dismissed` on 126, `failed` on 127") does not describe the textual agent, which
   never returns 126: a wrong password, Ctrl-D and a missing terminal are all 127, and Ctrl-C is death by SIGINT
   that also hits the core.
3. `pcap_inject` of an L2 frame on `lo` is dropped as a martian before it reaches a local socket. AC8 W3-W4 on
   Linux need the helper to inject local-destination IPv4 through a raw IP socket with `IP_HDRINCL`.
4. The [linux-ci] rig as the plan describes it does not exist yet, and when built it needs privileged containers.

## Carry into the spec

Nothing from this branch is reused as code. The spec and plan should state:

**§5.1 / P2.6 (helper start-up).** Keep the order; it is necessary, not just tidy. Say explicitly: `PR_SET_KEEPCAPS`
before `setresgid`/`setresuid` (without it `capset` fails and `CAP_NET_RAW` is gone); drop the bounding set while
`CAP_SETPCAP` is still held (it works for every capability on 6.8); `setgroups([primary gid])`, not `initgroups`, so
the helper leaves the admin group behind; `PR_SET_PDEATHSIG` strictly after the credential change because the kernel
clears it there. `cwd` arrives as `/root` and `XDG_RUNTIME_DIR` is not in the environment, so the socket path must be
absolute on argv (already the case). `PKEXEC_UID` arrives as a decimal string. The Rust `caps` crate equivalents:
`caps::drop(None, Bounding, cap)` per cap, `caps::clear(None, Ambient)`, `prctl keepcaps`, `nix setgroups/setresgid/
setresuid`, then `caps::set(None, Permitted|Effective, {NET_RAW})` and `caps::clear(None, Inheritable)`.

**§5.4 / P5 (policy).** Validated as written; `pkaction --verbose` is a cheap rig check. Drop `allow_gui` (or set it
false): the helper has no GUI and the dialog belongs to pkexec, so the only effect is leaking `DISPLAY`/`XAUTHORITY`
into the root helper's environment. Add `pkexec` to the deb `recommends` by name: on Debian trixie `pkexec` is a
separate package from `polkitd`.

**§5.5 / P1b.14 (prompt possible, exit mapping, signals).**

- "Prompt possible" = `DISPLAY` or `WAYLAND_DISPLAY` set, **or `open("/dev/tty")` succeeds**. Replace "stdin is a
  tty". With neither, pkexec itself fails in 0.5 s with the `Error creating textual authentication agent` text, so a
  wrong guess is safe but wasteful.
- Give pkexec a **pipe for stderr** and keep stdin, stdout and the controlling terminal as they are; the prompt still
  reaches the terminal and the core can classify the failure text. Mapping: exit 126 → `dismissed` (graphical agent
  only); exit 127 with `Error creating textual authentication agent` → `cannot_prompt`; exit 127 after
  `Got unexpected EOF while reading from controlling terminal` → `dismissed`; exit 127 with `Not authorized` →
  `failed` ("wrong password" is the message); killed by SIGINT → `dismissed`; any other non-zero → `failed`.
- The core must **handle SIGINT with a handler, never `SIG_IGN`**, while a pkexec child is alive: `SIG_IGN` is
  inherited across exec and makes the prompt un-cancellable, while the default disposition kills the core. The TUI
  already leaves raw mode before the prompt (§5.5), which is exactly when Ctrl-C becomes a signal.
- Expect the prompt to name an **admin** identity; for a non-admin operator that is another user's account. The web
  banner text "Enter an administrator password in the terminal running aitm" is right.

**P1b.12 (peer check).** `expected_pid` is the `pkexec` child's pid; pkexec execs in place. The helper connects about
0.4 s after the password; the 10 s AC16 budget is generous. The socket path is in the journal, so it must never
carry anything secret.

**§5.2 / P2.7 / AC8 W3-W4 (inject).** For a target that is a local address (any address the host owns, 127/8 in the
default scope) the helper must inject the IPv4 packet through `AF_INET`/`SOCK_RAW`/`IPPROTO_RAW` with `IP_HDRINCL`,
not through `pcap_inject`; both are `CAP_NET_RAW`. `pcap_inject` stays for frames leaving a real interface. The guard
check happens before either path. Add a Linux unit test that a loopback inject is received by a UDP socket with
`route_localnet=0` (the default), so the martian path can never come back.

**P2.8 / [linux-ci] rig.** `cis-lab` has no container runtime; the rig script installs `podman` (apt) or the
orchestrator keeps one installed. Containers must run `--systemd=always --privileged` or `polkitd` does not start.
Debian needs `polkitd pkexec dbus`; Fedora needs `polkit dbus-broker`. `tester` in `sudo`/`wheel` with a password.
On an Ubuntu 24.04 host, unload the `unix-chkpwd` AppArmor profile before Fedora PAM can authenticate inside a
container. The test rule `49-aitm-test.rules` returning `polkit.Result.YES` works (no prompt, connect at once) and
is the right AC16 mechanism; remove it for AC22.

**AC22.** The prompt contains `==== AUTHENTICATING FOR com.mrbrutti.aitmproxy.l4-helper.run ====`, the policy
message, `Authenticating as: <admin>` and `Password: `; the harness should match on the action id line.

**AC23.** Confirmed shape, with the predicate above instead of "stdin not a tty".
