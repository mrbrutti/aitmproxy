# 24 - Resolving the client process behind an accepted loopback TCP connection

Researcher note, stage 1. Read 2026-11-01. Worktree `friendly-tu-2d144a`. Local checks ran on macOS 27.0
(build 26A428, uid 501 `matt`, a Mac with 1 583 live pids) inside the Claude Bash sandbox, against the Xcode
SDK at `/Applications/Xcode.app/.../MacOSX.sdk`. The app floor is macOS 26. Labels: **(V)** verified by a command
or probe on this Mac, **(H)** read in a header or the libc crate on disk, **(S)** read in upstream source,
**(D)** vendor or man-page doc, **(W)** other web source, **(I)** inference, **(U)** unverified. Linux was
**not run** (no Linux host in the sandbox; `limactl` exists but was not tried), so every Linux row is (D)/(S)/(I).

## 1. Question

How does an unprivileged userspace proxy that accepted a loopback TCP connection, and so knows the peer
`ip:port`, find the client process that owns the other end on macOS and Linux, and what does it cost?

## 2. Short answer

macOS: scan same-user processes with libproc (`proc_listpids`, `PROC_PIDLISTFDS`, `PROC_PIDFDSOCKETINFO`) and match
the 4-tuple with the ports **byte-swapped** (`insi_lport` is network order in a 4-byte `int`). A full scan of 1 583
pids took about 7 ms (V). Linux: `/proc/net/tcp{,6}` row (or `uid`) gives the inode, then `readlink
/proc/*/fd/*` finds `socket:[inode]` in same-uid processes. Both are racy (pid and port reuse, exited peers),
so resolve once at accept, off the forwarding path, and treat the result as best-effort.

## 3. Findings

### 3.1 macOS: the libproc recipe, call by call

**Prior statement of the recipe.** Note 23 section 3.5 (F5) describes it from a "proxymate" PR: "Loopback peer
port to pid with a libproc FD scan (about 3 ms)", scans coalesced one at a time in `spawn_blocking`, late answers
delivered by a `ClientResolved` event, pid mapped to the outermost `.app` "using the pid macOS holds
responsible" (W, github.com/charlie-niekirk/proxymate/pull/5, read 2026-11-01). That PR text does not name
`responsibility_get_pid_responsible_for_pid`, port byte order or IPv6. Proxyman's own binary imports
`proc_listpids`, `proc_pidinfo`, `proc_pidfdinfo`, `proc_name`, `proc_pidpath`, `sysctl`, `NSRunningApplication`
(`apps/mac/docs/reference/proxyman/BUNDLE.md` section 4b, nm of ProxymanCore); the loop itself "was not traced".
BUNDLE.md live-confirmed twelve named apps with the extension off.

**Constants and structs (H, `usr/include/sys/proc_info.h`, `libproc.h`, SDK on this Mac).**

| Item | Value / shape |
|---|---|
| `PROC_ALL_PIDS` | `1` (line 51); `PROC_UID_ONLY` = 4 |
| `PROC_PIDLISTFDS` | `1`; entries are `struct proc_fdinfo {int32 proc_fd; uint32 proc_fdtype}` (8 bytes, V) |
| `PROX_FDTYPE_SOCKET` | `2` |
| `PROC_PIDFDSOCKETINFO` | `3`; output `struct socket_fdinfo` |
| `SOCKINFO_IN` / `SOCKINFO_TCP` | `1` / `2` (V by printing the macros) |
| `soi_kind` | `int` in `struct socket_info`, selects the `soi_proto` union arm |
| path | `proc_pidpath(pid, buf, size)`; buffer `PROC_PIDPATHINFO_MAXSIZE` = `4*MAXPATHLEN` (4096) |
| names | `proc_name(pid, buf, size)`; `pbi_comm[MAXCOMLEN=16]`, `pbi_name[32]` in `proc_bsdinfo` |
| parent | `proc_bsdinfo.pbi_ppid`; also `pbi_start_tvsec/tvusec` (process start time), `pbi_uid` |
| `PROC_PIDTBSDINFO` | `3` (136-byte `proc_bsdinfo`, V); `PROC_PIDT_SHORTBSDINFO` = `13` (`pbsi_ppid`, `pbsi_comm`) |

Layout measured with a C `offsetof` probe (V): `sizeof(struct socket_fdinfo)` = **792**, `pfi` 24 bytes, `psi` at
24, `soi_kind` at 232, `soi_proto` at 240; inside `in_sockinfo` (80 bytes): `insi_fport` 0, `insi_lport` 4,
`insi_vflag` 24, `insi_faddr` 32, `insi_laddr` 48; `tcpsi_state` at 80 in the 120-byte `tcp_sockinfo`. Address
unions are `in4in6_addr` (`i46a_pad32[3]` then `i46a_addr4`) or `in6_addr`; `insi_vflag` is `INI_IPV4`
(0x1) or `INI_IPV6` (0x2) (H, lines 366-392). `tcpsi_state` uses the BSD enum `TSI_S_*` (LISTEN=1,
ESTABLISHED=4, ...) (H, lines 414-425).

**Byte order of `insi_lport` / `insi_fport`.** The header comments say only "foreign port" / "local port"; it does
not state the order (H). Evidence that it is **network order stored in a 32-bit `int`**:
- XNU `bsd/kern/socket_info.c` `fill_socketinfo` copies `insi->insi_fport = inp->inp_fport; insi->insi_lport =
  inp->inp_lport;` with no byte-order conversion; the PCB holds ports in network order (S, via WebFetch of
  `apple-oss-distributions/xnu` main, 2026-11-01; "PCB holds network order" is the BSD convention, I).
- A gist reads them as `ntohs(insi_lport)` (W, gist.github.com/andrewkroh/83e3ac2c07f212974de42175d55d9701).
- `netstat2` 0.11.2 byte-swaps the low 16 bits with `NetworkEndian::read_u16(&i32::to_le_bytes(insi_lport))`
  (S, `ohadravid/netstat2-rs` `src/integrations/osx/netstat.rs`).
- **Measured (V):** four loopback listeners owned by our `aitm` core showed raw `insi_lport` 16495, 16751, 17007
  (0x406f, 0x416f, 0x426f; step 256) which `ntohs` turns into 28480, 28481, 28482 (step 1), as sequential binds
  would be. Compare with `ntohs((u16)insi_lport)` and never with the raw `int`; mask to 16 bits first.

**Addresses.** For `INI_IPV4` the address is `insi_laddr.ina_46.i46a_addr4` (a network-order `in_addr`); for
`INI_IPV6` it is `ina_6`. A v4-mapped v6 socket (dual-stack listener or client) is `INI_IPV6` with `::ffff:a.b.c.d`
in `ina_6`, or with both vflag bits set; **I did not observe a client socket of either kind** (the sandbox forbids
creating one, see below), so the vflag handling of a dual-stack client is (U). XNU `socket_info.c` copies the
whole `ina_6` union and has no `INI_IPV4`/`in4in6` logic (S). Candidate rule: match on ports plus an address
comparison that treats `127.0.0.1`, `::1` and `::ffff:127.0.0.1` as equal.

**Which socket is "the client's".** The accepted socket in our own process has `local=proxy_port`,
`foreign=client_ephemeral`; the client's socket has `local=client_ephemeral`, `foreign=proxy_port`. Both sit in
the scan. A matcher must pick the entry whose `lport == peer_port && fport == proxy_port`, and must **skip our
own pid** (or it matches nothing useful when the roles are swapped). The client socket may be in more than one
process (fd inherited across `fork`, or sent over a UNIX socket); there is no unique answer then (I).

**Privilege: what fails for whom (V from a probe as uid 501, H/S from the XNU source).**

| Call | Same-uid process | Root/other-uid process (e.g. pid 1) | pid 0 | dead pid |
|---|---|---|---|---|
| `proc_listpids(PROC_ALL_PIDS)` | lists all 1 583 | n/a | n/a | n/a |
| `proc_pidinfo(PIDLISTFDS)` | ok | **EPERM (1)** | EPERM | **ESRCH (3)** |
| `proc_pidinfo(PIDTBSDINFO)` | ok | **EPERM** | | |
| `proc_pidfdinfo(PIDFDSOCKETINFO)` | ok | **EPERM** | | ESRCH |
| `proc_pidpath` | ok | **ok** (`/sbin/launchd`, 13 bytes) | **ESRCH** | ESRCH |
| `proc_pidinfo(PIDT_SHORTBSDINFO)` | ok | **ok** (`comm=launchd`, `ppid=0`) | | |
| `proc_name` | ok | returned **0** for pid 1 (nothing written) | | |

Counted (V): of 1 583 pids, `PROC_PIDLISTFDS` succeeded for 1 222 and failed for 361, **all with EPERM, none with
another errno**. The source agrees (S, `bsd/kern/proc_info.c`): `proc_pidinfo` sets `check_same_user =
NO_CHECK_SAME_USER` only for `PROC_PIDT_SHORTBSDINFO`, `PROC_PIDUNIQIDENTIFIERINFO`, `PROC_PIDPATHINFO`,
`PROC_PIDCOALITIONINFO`, `PROC_PIDPLATFORMINFO`; every other flavor (including `PIDLISTFDS`, `PIDTBSDINFO`) and
`proc_pidfdinfo` use `CHECK_SAME_USER`. `proc_security_policy` returns `EPERM` on a uid mismatch unless the
caller passes `priv_check_cred(PRIV_GLOBAL_PROC_INFO)`; `proc_listpids` has no same-user check. So, unprivileged:
you **can** list every pid and read every pid's path and short name, and you can read fds and sockets of
**same-uid processes only**. A root or other-user daemon (`trustd`, `mDNSResponder`) that connects to a loopback
proxy will therefore not be found by the fd scan; its pid is unknown (I: the fallback for such a client is no
attribution, not a wrong one). Proxyman's note says "system daemons resolve by name only" (BUNDLE.md 4b); how it
gets the name for daemons whose sockets it cannot read is (U).

**Do not touch vnode fds.** A hermes-agent issue reports an indefinite hang in `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`
on one process stuck in uninterruptible I/O on an SMB share (about 14 hours; `lsof` hung the same way); the
reporter's fix is a worker thread with a wall-clock deadline (W, github.com/NousResearch/hermes-agent/issues/113187).
Sockets were not implicated, but this is a general hazard of walking other processes. Our scan would call
`proc_pidfdinfo` **only on `PROX_FDTYPE_SOCKET` entries**; also bound the whole scan with a deadline (I).

**Binding availability.** `libc` 0.2.191 (on disk, H, `src/unix/bsd/apple/mod.rs`) declares `proc_listpids`,
`proc_listallpids`, `proc_pidinfo`, `proc_pidfdinfo`, `proc_pidpath`, `proc_name` (extern, lines 5463-5502) and
has `proc_fdinfo`, `proc_bsdinfo`, `proc_bsdshortinfo`, `PROC_PIDLISTFDS`, `PROC_PIDTBSDINFO`,
`PROC_PIDT_SHORTBSDINFO`, `PROX_FDTYPE_SOCKET`. It does **not** have `socket_fdinfo`, `in_sockinfo`,
`PROC_PIDFDSOCKETINFO`, `SOCKINFO_TCP`, `INI_IPV4` or `PROC_ALL_PIDS` (a grep found none). A caller must define
the `#[repr(C)]` structs itself (pinned to size 792 and the offsets above) or use the `libproc` crate (3.3).
The workspace sets `unsafe_code = "forbid"` (`Cargo.toml:46-49`), and `crates/aitm-peer-token` is the existing
precedent: a leaf crate at `deny` with one audited `#[allow(unsafe_code)]` site that returns `Option` and fails
closed (`crates/aitm-peer-token/{Cargo.toml,src/lib.rs}`).

### 3.2 macOS: cost (V, measured here)

Probe: a C program in `$TMPDIR` that only reads (`proc_listpids`, `PIDLISTFDS`, `PIDFDSOCKETINFO` on socket fds,
`proc_pidpath`/`proc_name`/`PIDTBSDINFO`). Three consecutive full scans, `clock_gettime(CLOCK_MONOTONIC)`:

| Measure | Result |
|---|---|
| pids / listable / EPERM | 1 583 / 1 222 / 361 |
| fds seen / socket fds / TCP sockets / loopback-v4 TCP | 21 779 / 1 875 / 330 / 129 |
| `proc_listpids` | 0.12-0.22 ms |
| **full scan** (all pids, `PIDFDSOCKETINFO` on every socket fd) | **6.8, 7.0, 7.05 ms** |
| of which `PIDLISTFDS` / `PIDFDSOCKETINFO` | about 3.1 ms / 3.5 ms |
| `PROC_UID_ONLY` list, same scan, 5 runs | 10.1-12.5 ms (noisier; machine load not controlled) |
| `proc_pidpath` over 1 564 pids | 12.2 ms total (about 8 us each; 1 440 ok) |

Cost per pid is about 4.4 us and per socket about 1.9 us. This Mac has **three times** the 500 processes the brief
assumed, so the order of magnitude agrees with proxymate's "about 3 ms" (W) at roughly 500 pids (scaling, I).
A portcheck PR reports socket listing falling from about 43 ms to about 4 ms by moving to
`proc_listallpids` + `PIDLISTFDS` + `PIDFDSOCKETINFO` (W, github.com/roystondwork-dev/portcheck/pull/22, via
search summary only). The cost is per scan, not per connection: a burst of N new connections needs one scan if
the scan starts after the last of them accepted (the proxymate coalescing, W). A cold cache is not separated
from warm in these numbers. Nothing here can be conclusive about heavy-load behaviour.

**What the sandbox refused (V).** `bind(127.0.0.1:0)` and `connect(127.0.0.1:<port>)` both fail with `EPERM`, so I
could not create a live loopback pair and match it end to end. `ps` ("operation not permitted") and `netstat`
(no output) also refused, and `curl` to raw.githubusercontent.com was denied (WebFetch worked instead). Read-only
`libproc`/`dlsym` calls all worked. The byte-order claim therefore rests on the sequential-listener evidence plus
the XNU source and two independent third-party readers, not on a live pair. **End-to-end proof on a real
accepted connection (and a dual-stack client) is still owed**, and per the project's rules belongs in an
experiment or the coder's live proof, not in a fixture.

### 3.3 macOS: process to identity

**`responsibility_get_pid_responsible_for_pid`.** (V, V, H, D) It exists: `dlsym(RTLD_DEFAULT, ...)` is non-nil in
a plain C process and `dladdr` places it in **`/usr/lib/system/libquarantine.dylib`** (current-version 217.0.4).
The SDK text stub lists `_responsibility_get_pid_responsible_for_pid`, `_responsibility_get_responsible_for_pid`,
`_responsibility_get_uniqueid_responsible_for_pid`, `_responsibility_set_pid_responsible_for_pid`,
`_responsibility_init` and, for the newer arm64e targets, `_responsibility_get_attribution_for_audittoken`,
`_responsibility_get_responsible_audit_token_for_audit_token` in `usr/lib/system/libquarantine.tbd`, and
`usr/lib/libSystem.B.tbd` re-exports `libquarantine`. A C file declaring `extern int
responsibility_get_pid_responsible_for_pid(int);` **compiled and linked against only `libSystem`**, no extra
`-l` flag (V). No public header declares it (a grep of `usr/include` found none), so it is private SPI; the
signature `pid_t f(pid_t)` and the return `<= 0` on failure are what I observed, not documented. Safe-to-link
verdict: linkable with no extra library, but unsupported API with no stability promise; the safe pattern is
`dlsym` with a null check and a fallback, or a direct extern that is guarded by a runtime test (candidate, not
decision). Apple DTS calls the underlying problem "the responsibility problem" and names only an Endpoint
Security client's `responsible_audit_token` as the sanctioned route (note 21 Q1, forum thread 739414).

Observed results of the call for every pid (V): of 1 535 pids, responsible == self for 657, differs for 518, call
failed for 358 (the root/other-user pids, I). Cases:
- `WebKit.Networking` pid 45835 -> `/Applications/SoundSource.app`; pid 4750 -> `/usr/libexec/textunderstandingd`.
  So the shared per-host-app WebKit network process does resolve to its **host app**, as note 21 predicted from
  `NSRunningApplication` ("Safari Networking", "Mail Networking"). No Safari-hosted instance was running to test.
- Chrome helper renderers and Python processes launched from within **Claude.app** resolved to
  `/Applications/Claude.app/Contents/MacOS/Claude` (or the nested `claude` binary), not to Chrome or Python.
  Responsibility follows who **spawned** the process, so a Chrome that Claude started is "Claude" by this rule
  while Chrome itself launched from the Dock would be Chrome (the last Chrome helper at pid 86469 returned itself).
  **Trap:** the responsible pid is "who is accountable", not "what binary is talking", and it can hide the
  true client (a `curl` run in Terminal would likely resolve to Terminal; not run, I). Proxymate says CLI tools
  "keep their own name such as curl" (W), so it applies the responsible pid only to XPC/framework helpers.

**Outermost `.app` walk (no AppKit).** Split the `proc_pidpath` result into components and take the first
component ending in `.app`, read `<prefix>/<that>.app/Contents/Info.plist` and its `CFBundleIdentifier` (a plist
parser is needed; binary or XML). Note 21 already requires the outermost `.app` for nested Chrome/Electron
helpers. New evidence (V) that "outermost" alone is wrong in one common case:
- `/usr/bin/python3` (the xcode-select shim) execs
  `/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python`.
  `proc_pidpath` returns that path. Outermost `.app` is **Xcode.app** (`com.apple.dt.Xcode`); the innermost,
  `Python.app`, has `CFBundleIdentifier` and signing id `com.apple.python3`. The same applies to anything under
  `Xcode.app/Contents/Developer/...` (swift-frontend, swift-plugin-server, git). Chrome renderers are the
  opposite case: path `.../Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/.../Google
  Chrome Helper (Renderer).app/...`, outermost `Google Chrome.app` is right and the helper's signing id is
  `com.google.Chrome.helper.renderer` (V).
- A homebrew/nix interpreter (here `/nix/store/...-python3-3.14.7/bin/python3.14`) has no `.app`; no bundle.
So the walk needs a rule for toolchain-internal `.app`s (candidate: if the outermost `.app` contains
`/Contents/Developer/`, use the innermost; or only trust the outermost when the executable sits under a
`Contents/MacOS`/`Helpers`/`Frameworks` path, I). `NSRunningApplication(processIdentifier:)` is the AppKit
alternative with `localizedName` and `icon`, available when the pid is a running regular app (note 21).

### 3.4 Linux, unprivileged

**`/proc/net/tcp` and `/proc/net/tcp6` row format (S).** `get_tcp4_sock` prints
`"%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX %08X %5u %8d %llu %d ..."` (`net/ipv4/tcp_ipv4.c`): slot
`sl`, `local_address` = `inet_rcv_saddr` as `%08X` and `ntohs(port)` as `%04X`, `rem_address` likewise, `st`
(`%02X`), `tx_queue:rx_queue`, `tr:tm->when`, `retrnsmt`, **`uid` (`%5u`)**, timeout, **`inode` (`%llu`,
`sock_i_ino`)**. The IPv4 address is printed from the raw `__be32` with no `ntohl`, so its hex is the
**host-endian reading of the network-order bytes**: on little-endian, `127.0.0.1` prints as `0100007F`; the port
is host-order hex via `ntohs` (so `C2C8` is port 49864). The kernel doc says only that fields are annotated
"local IPv4 address", "connection state", "uid", "inode" and gives no state table or byte-order note (D,
docs.kernel.org/networking/proc_net_tcp.html); the hex-endian statement is inference from the code (the WebFetch
summary says the same, I). `get_tcp6_sock` prints `"%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X ..."` from
`src->s6_addr32[0..3]` (`net/ipv6/tcp_ipv6.c`): four 32-bit words, each in host endian. So `::1` on little-endian
is `00000000000000000000000001000000`, and an IPv4-mapped `::ffff:127.0.0.1` is
`0000000000000000FFFF00000100007F` (computed from the format, I; **not seen live**). A connection from
a dual-stack client to a `127.0.0.1` listener appears in `tcp6` (client side) with the mapped form and in `tcp` or
`tcp6` for the proxy's own listener depending on how it bound (I). Matching therefore must read both files and
compare after decoding.

`st` values (hex, S, `include/net/tcp_states.h`): ESTABLISHED 01, SYN_SENT 02, SYN_RECV 03, FIN_WAIT1 04,
FIN_WAIT2 05, TIME_WAIT 06, CLOSE 07, CLOSE_WAIT 08, LAST_ACK 09, LISTEN 0A, CLOSING 0B, NEW_SYN_RECV 0C. The
client end of an accepted connection is normally `01`; a client that has closed first gives the proxy's side
`08`.

**Matching.** Accepted socket: `(local=proxy:P, remote=client:C)`. Client row: `local=client:C`, `remote=proxy:P`.
Look for that row in `/proc/net/tcp` and `/proc/net/tcp6`; its `inode` and `uid` are the result. `uid` alone
already says whether the client is the same user (a free privilege test, I). Matching is by the 4-tuple, which
is unique at one instant, except inside a **network namespace**: `/proc/net` is the reader's namespace, and a
container's loopback is not visible from the host namespace (OpenSnitch notes container connections under
`/proc/<pid>/net/`, W, see 3.5).

**Inode to process (D, S).** `readlink /proc/<pid>/fd/<n>` returns `socket:[<inode>]` (D, `proc_pid_fd(5)`).
Reading or dereferencing the link needs a **ptrace access-mode `PTRACE_MODE_READ_FSCREDS` check** (same man page).
That check passes when the caller's fsuid/fsgid matches the target's real, effective and saved ids, **or** the
caller has `CAP_SYS_PTRACE`, and it also fails when the target's `dumpable` attribute is not 1 (D, `ptrace(2)`).
The Yama `ptrace_scope` restricts only `PTRACE_MODE_ATTACH`, not READ modes (D, same page). Result: unprivileged
you can resolve **same-uid** clients; root or other-user clients fail with `EACCES` on the link (the errno is
my inference from the access-mode wording, (U); not run), and **non-dumpable same-uid processes** (setuid
helpers, processes that called `prctl(PR_SET_DUMPABLE, 0)`) are also unreadable. A multithreaded process whose
main thread has exited exposes no `fd` directory (D, `proc_pid_fd(5)`). Scan only pids where the row's `uid`
equals ours, and also check `/proc/<pid>/task/<tid>/fd` if the main-thread directory is empty (OpenSnitch hits
this with Firefox/Chrome, W).

**Process identity files.** `/proc/<pid>/exe`: a symlink to the executable, permission by the same
`PTRACE_MODE_READ_FSCREDS`; for a deleted binary the target has `" (deleted)"` appended (D, `proc_pid_exe(5)`).
`/proc/<pid>/comm`: the 15-character thread name (I, not fetched). `/proc/<pid>/cmdline`: NUL-separated argv as
laid out in process memory, a process can change it after `execve` (D, `proc_pid_cmdline(5)`). The privacy
rule below forbids reading `cmdline`; note that the kernel doc says the process can rewrite it, so it is also
untrusted.

**`hidepid` (D, `proc(5)`).** `hidepid=0` default, everybody reads every `/proc/<pid>`; `hidepid=1` other users'
`/proc/<pid>` stay visible but their files (`cmdline`, `status`) become unreadable; `hidepid=2` also hides other
users' directories; `gid=` (since Linux 3.3) names a group exempt from it; `subset=pid` (since 5.8) hides all
non-process top-level entries. Effects here: a same-uid scan is unaffected by `hidepid=1|2`; `subset=pid` would
**remove `/proc/net`** from a mount that uses it, which would break this technique (I; the page says
"hiding all top level files and directories in the procfs" that are not task-related, which includes `net`).

**Equivalents.** `ss -p` ("Show processes using sockets") and `ss -e` (adds `uid:<n> ino:<n>`) (D, `ss(8)`); the
man page states no privilege requirement for `-p`, but only same-uid processes can be identified (I, same ptrace
rule). `lsof -i` does the same walk by `/proc/*/fd` (I, not verified). The kernel also offers the netlink
`NETLINK_SOCK_DIAG` / `inet_diag` interface: `idiag_uid`, `idiag_inode` and `idiag_sport`/`dport` in network
byte order (D, `sock_diag(7)`, UNIX sockets only in its example). Whether an unprivileged process may query
inet sockets that way is **not stated** on that page (U). It is the interface `ss` uses (I) and avoids parsing
text.

**Cost (not measured).** `/proc/net/tcp` is one kernel text dump per call, scaling with the number of TCP sockets
on the host (kernel-side `seq_file` formatting, I). The inode-to-pid walk is `O(processes x fds)`
`readlink`s; OpenSnitch calls the `/proc` method "slow, not always reliable, and can be fooled" and mitigates
with caches and a list of pids known to hold sockets (W). Measuring it on a Linux box is an open item. The
`procfs` crate (0.18.0) has `net::tcp()` and `net::tcp6()` that decode these tables; whether its address
fields are already decoded `SocketAddr`s is not shown on its docs page (U).

### 3.5 Prior art

| Tool | How it attributes a client process | Source, read 2026-11-01 |
|---|---|---|
| **Proxyman** | On macOS, libproc imports in ProxymanCore plus `NSRunningApplication`/`iconForFile:`; named apps from the plain system proxy with the NE off; shows `Claude Helper`, `Codex (Service)`, `codex`, `trustd`, `Mail`, `Google Chrome` (see 3.6) | `apps/mac/docs/reference/proxyman/BUNDLE.md` 4b, `SCREENS.md` shot 34, `DELTA.md` 2.1 |
| **Charles** | A "Client Process" tool, **local requests only**, process name as a note on each request; "will introduce a short delay before each connection is accepted"; mechanism not stated | charlesproxy.com/documentation/tools/client-process/ (D) |
| **mitmproxy** | Local capture (`--mode local[:curl|:42]`) is OS-level; process spec is matched by name or pid; platform mechanisms are not named on the page. It is **not** a loopback-peer lookup: the redirector knows the pid when it diverts the flow. Regular/transparent modes: the page says nothing about processes. | docs.mitmproxy.org/stable/concepts/modes/ (D); note 10 for the NE and the macOS redirector |
| **Little Snitch** | NE content filter; attributes helper processes to the parent app (6.2.1) | note 23 (secondary) |
| **LuLu / NE tools** | NE `sourceAppAuditToken` | note 23 |
| **Wireshark / tcpdump** | Per-packet process info from the macOS PKTAP pseudo-interface needs `/dev/bpf*` (root); not loopback-peer lookup, so not an unprivileged route | note 8, note 13 (BPF is root-only on this Mac); PKTAP detail (U) |
| **`lsof -i` / `netstat`** | libproc on macOS; `/proc/*/fd` on Linux | gopsutil issue #164 recounts `lsof` use; `lsof` internals (I) |
| **OpenSnitch (Linux)** | eBPF (default), audit, or `/proc`: inode from `/proc/net/*` or netlink, then `/proc/<pid>/fd` scan; known misses (threads, containers, speed) | github.com/evilsocket/opensnitch wiki and discussion 569, LWN 988401 (W via search) |
| **gopsutil (Go)** | Process connections via `net.ConnectionsPid`; early macOS used `lsof`, later libproc is discussed; the current `net_darwin.go` does not show it | github.com/shirou/gopsutil issue 164 (W, partly (U)) |

Rust crates (crates.io API, 2026-11-01):

| Crate | Version / licence / last update | What it does | Fit |
|---|---|---|---|
| `libproc` | 0.14.11, MIT, 2025-10-01, 11.3 M downloads (repo `andrewdavidmackenzie/libproc-rs`) | process info macOS+Linux; `net_info.rs` defines `#[repr(C)]` `SocketFDInfo`, `SocketInfo`, `InSockInfo`, `TcpSockInfo`, enums `SocketInfoKind`, `TcpSIState`; `insi_*port` as plain `c_int`, no byte-order note (S) | closest reuse of the struct layout; **MIT, adds a dependency, still needs `unsafe` at the call site or its safe wrappers** (wrappers not read, (U)) |
| `netstat2` | 0.11.2, MIT OR Apache-2.0, 2025-08-14, 1.14 M downloads | socket tables; macOS = `proc_listpids` + `PIDLISTFDS` + `PIDFDSOCKETINFO`, skips pids that fail (`PermissionDenied`), returns pid only, no name/path (S) | does the scan; no process identity; uses own binding |
| `listeners` | 0.6.1, MIT, 2026-08-02 (repo `GyulyVGC/listeners`) | "find out processes listening on network ports"; README sample lists ESTABLISHED rows too; internals and permission notes not given (W) | listening side first; an ESTABLISHED lookup by 4-tuple is (U) |
| `procfs` | 0.18.0, MIT OR Apache-2.0, 2025-08-30, 92 M downloads | Linux procfs; `net::tcp()`, `tcp6()`, `tcp` entries use `inode` as `u64` (D) | would replace hand parsing; entry field types not verified |
| `sysinfo` | not looked at | processes only; sockets not offered (I) | out of scope |

I looked at no maintenance signal beyond last-update and download counts. None of these resolve a **loopback
peer to a process**; they enumerate sockets, and the match is ours.

### 3.6 The identity string to emit

Evidence of what the three candidates give (V unless noted):

| Process | executable basename (`proc_name`/path) | owner bundle id | signing id (codesign) | what Proxyman shows |
|---|---|---|---|---|
| `curl` | `curl` | none | `com.apple.curl` | not recorded in the repo; **(U)** |
| `/usr/bin/python3` | `Python` (from `Python.app/.../MacOS/Python`) | outermost `com.apple.dt.Xcode`, innermost `com.apple.python3` | `com.apple.python3` | not recorded; **(U)** |
| nix `python3.14` | `python3.14` | none | ad-hoc `python3.14-<hex>` or similar (I; note 21 shows the `name-<hex>` pattern) | not recorded; **(U)** |
| Safari browsing | `com.apple.WebKit.Networking` (from `.xpc`) | none (system XPC); responsible pid = host app | `com.apple.WebKit.Networking` | not recorded; the screenshots show `Mail`, `Google Chrome`, never Safari; **(U)** |
| Safari app itself | `Safari` | `com.apple.Safari` | `com.apple.Safari` | **(U)** |
| Chrome renderer | `Google Chrome Helper (Renderer)` | outermost `com.google.Chrome` | `com.google.Chrome.helper.renderer` | screenshots show `Google Chrome` (W/V from SCREENS.md shot 34, may be the main process) |
| Electron helper | `Claude Helper` | outermost `com.anthropic.claudefordesktop` | `<appid>.helper` (note 21) | **`Claude Helper`** (SCREENS.md shot 34) |
| Apple daemons | `trustd`, `cloudd`, `dataaccessd` | none | `com.apple.trustd` ... | the basename, e.g. `trustd` |

From the Proxyman list in `SCREENS.md` shot 34 (`System, Mail, Claude Helper, Codex (Service), codex, trustd,
Google Chrome, searchpartyuseragent, exchangesyncd, cloudd, nsurlsessiond, dataaccessd`), the display names are the
helper's **own** bundle/process name (`Claude Helper`, `Codex (Service)`), not the outermost app (`Claude`,
`Codex`) and lowercase CLI binaries stay as `codex`. This contradicts the "outermost `.app`" rule proxymate claims
(W). It is consistent with `NSRunningApplication(processIdentifier:).localizedName` on the connecting pid (I,
from BUNDLE.md 4b's inference). The aitmproxy answer is a product call; the three options are in section 4.

**Privacy posture.** The macOS recipe needs only the path, a short name and bundle ids; none needs argv.
`sysctl(KERN_PROCARGS2)` exists (it is `KERN_PROCARGS2 = 49` in libc) and is exactly what to **not** call
(I, project rule: "never args, never the full cmdline"). On Linux, never read `/proc/<pid>/cmdline` or
`environ`. A full path can also reveal a username (`/Users/matt/...`) and a project directory; the spec should
decide whether to emit the path or only basename + bundle id (note 23 already carries `source_path` truncated to
1 024 bytes in the NE lane). Strip control characters and bidi marks as note 21 does (U+200E in WhatsApp).

### 3.7 Caching, pid reuse and races

- **Process exits before the scan.** A short-lived client (`curl`) can finish before a scan that starts after
  `accept`. The row's socket may already be closed or in TIME_WAIT (`TSI_S_TIME_WAIT`=10), and the proxy's own
  socket stays until the proxy closes it, but the client's fd is gone: no match, no attribution. A
  `ClientResolved`-style late event (proxymate, W) fixes order but not a miss. (I from the mechanism; not
  reproduced because the sandbox cannot make a live pair.)
- **Race inside the scan.** `proc_pidinfo(PIDLISTFDS)` returns a snapshot; the fd can close or be reused before
  `proc_pidfdinfo`. The source returns `ESRCH` for a missing pid and `ENOTSOCK` for a non-socket fd (S); also
  `EBADF` is plausible (U). Treat any per-fd failure as "skip", never as "no such client".
- **Ephemeral port reuse.** The 4-tuple is unique only while the client's socket exists. Between accept and
  scan the ephemeral port can be reused by another process connecting to the same proxy port only after the first
  connection is fully closed (TIME_WAIT on the client side blocks reuse of the same 4-tuple for the 2MSL
  period, I). Safer: match **while the proxy's accepted socket is still open** (the tuple is then held by us).
- **pid reuse.** A cached `pid` -> identity entry can go stale when the pid is recycled. macOS gives
  `pbi_start_tvsec/tvusec` in `proc_bsdinfo` (H) and a private unique id (`PROC_PIDUNIQIDENTIFIERINFO` appears in
  the XNU source, not in the public header, (S/H)); key a cache by `(pid, start_time)` (I). Linux: field 22 of
  `/proc/<pid>/stat` is the start time (I, not fetched). Caching a **result per connection** (done once at
  accept, never re-resolved) avoids most of this.
- **Fork/inherited sockets.** Several processes can hold the same socket; pick one deterministically and mark
  the match as ambiguous (I).
- **Cost control.** One scan at a time; coalesce; a deadline (3.1); a per-owner icon cache (note 21).
  Rate-limit scans so a connection flood cannot turn each accept into a 7 ms scan (a scan every 100 ms is 7 % of
  a core, I from the measurement above).

## 4. Candidate directions (not decisions)

**Where to resolve.** A. In the Rust core, at accept, in a new leaf crate (follows the `aitm-peer-token`
pattern) with a `PeerProcess { pid, start, name, path, bundle_id, ... }` result. B. In the macOS app from the
flow's `client` address (BUNDLE.md and DELTA.md 2.1 allow either). C. A in the core, display resolution
(icon, localized name) in the app, which already has NSWorkspace (note 21).

| Direction | For | Against |
|---|---|---|
| A. Core, Rust leaf crate with own `#[repr(C)]` structs | Linux and macOS share one trait; the TUI, web, CLI all get the field on the bus; one audited `unsafe` | We maintain the struct layout (pin with a size/offset test and a scan that finds the test's own socket, as proxymate does); no Swift niceties |
| A'. Same, but depend on `libproc` 0.14 for the structs | Less layout code | New dependency (MIT), wrappers still unsafe-adjacent, `insi_*port` byte order left to us |
| B. App-only | Reuses `NSRunningApplication`; no wire change | macOS only; TUI/web/CLI do not benefit; the core accepted the socket and already holds the address |
| C. Core pid + path, app localizes | Matches the note 21 resolver; Linux still works | Needs a wire field (the spec) |

**Scan strategy.** (1) On-demand scan at accept, coalesced, `spawn_blocking`, with deadline: simple; misses
short-lived clients. (2) Periodic snapshot (every N ms) keyed by 4-tuple: makes the lookup a map read but burns
a core and goes stale. (3) Scan only after the first byte is read, still before the response. (4) A hybrid: an
immediate scan and a retry once. The measured 7 ms scan is small beside a TLS handshake (I).

**Identity policy** (macOS), choose one primary and a fallback chain:
1. Own bundle/app display name of the connecting pid (`Claude Helper`), as Proxyman appears to do.
2. Outermost `.app` owner (`Claude`), as proxymate does; needs the Xcode-toolchain exception (3.3).
3. Responsible-pid owner for helpers only (WebKit.Networking -> host app); needs a runtime-checked SPI.
4. Basename (`curl`, `trustd`); bundle id is `null` for bare executables. Signing id is a poor primary for the
   xcode-select shim and ad-hoc `name-<hex>` ids (note 21 Q2).
Emit more than one field (`name`, `bundle_id`, `path_basename`, `owner_pid`) rather than one string, so the UI
can choose.

**Linux.** Hand parse `/proc/net/tcp{,6}` plus `/proc/*/fd` readlink (works anywhere, same-uid only); or the
`procfs` crate; or `NETLINK_SOCK_DIAG` (inet) for the inode and uid if an unprivileged query is confirmed. Add
`/proc/<pid>/exe` basename and `comm`. No bundles on Linux, so the identity is exe basename (and optionally a
`.desktop` lookup, which I did not research).

## 5. Open questions

1. **No live loopback pair was proven.** The sandbox denies socket `bind`/`connect`. Needed: an end-to-end run
   (proxy on loopback, `curl` and Safari as clients) that matches `lport/fport` after `ntohs`, shows what
   `insi_vflag` is for `127.0.0.1` and `::1` clients and for a dual-stack client, and measures scan latency
   with the proxy under load.
2. **What does the scan return for a root/other-user client?** Expect no match (EPERM on 361 pids here); how
   Proxyman names `trustd`/`cloudd` is (U). Is "unknown client" shown, or is an NE path required for those?
3. **Responsible pid for Terminal-launched `curl`/`python3`**, and for Safari-hosted `WebKit.Networking` (not
   running here), and whether `responsibility_get_pid_responsible_for_pid` still behaves the same on macOS 26.
4. **Linux was not run.** Verify the `tcp6` mapped-address hex, `EACCES` for other-uid fd readlinks, the
   non-dumpable case, a measured scan time, and whether `sock_diag` gives unprivileged inet queries.
5. **Short-lived clients.** How often a coalesced post-accept scan misses `curl` on a real run.
6. **Proxyman identity.** What it shows for `curl`, `python3`, Safari; the screenshots do not include them.
7. **`libproc` crate** safe wrappers and layout assertions, and `netstat2`'s `repr` assumptions on arm64/x86_64,
   were not read in full.
8. **Does the helper's own name or the owner's name** match what Matt wants on the Apps page (product call)?
9. Hardened-runtime or future macOS tightening of `PROC_PIDLISTFDS` for same-user processes (none seen on 27.0;
   macOS 26 not tested).

## 6. Sources

- Local, read 2026-11-01: `docs/research/21-macos-app-icon-resolution.md`; `docs/research/23-macos-observe-only-lane.md`
  (3.5 F5); `apps/mac/docs/reference/proxyman/{BUNDLE,DELTA,SCREENS}.md`; `Cargo.toml` (workspace lints);
  `crates/aitm-peer-token/{Cargo.toml,src/lib.rs}`; `docs/research/experiments/2026-10-31-macos-ne-observe-survey.md`
  (cost of `proc_pidpath_audittoken`).
- Headers (H): `MacOSX.sdk/usr/include/sys/proc_info.h`, `libproc.h`, `usr/lib/system/libquarantine.tbd`,
  `usr/lib/libSystem.B.tbd`; `libc-0.2.191/src/unix/bsd/apple/mod.rs` (`~/.cargo/registry`).
- XNU (S): https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/proc_info.c ,
  https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/socket_info.c
- Linux kernel (S): https://raw.githubusercontent.com/torvalds/linux/master/net/ipv4/tcp_ipv4.c ,
  https://raw.githubusercontent.com/torvalds/linux/master/net/ipv6/tcp_ipv6.c ,
  https://raw.githubusercontent.com/torvalds/linux/master/include/net/tcp_states.h ,
  https://docs.kernel.org/networking/proc_net_tcp.html
- man7.org (D): `proc(5)` https://man7.org/linux/man-pages/man5/proc.5.html ; `proc_pid_fd(5)`, `proc_pid_exe(5)`,
  `proc_pid_cmdline(5)` ; `ptrace(2)` https://man7.org/linux/man-pages/man2/ptrace.2.html ; `sock_diag(7)` ;
  `ss(8)` https://man7.org/linux/man-pages/man8/ss.8.html
- Prior art (W): https://github.com/charlie-niekirk/proxymate/pull/5 ;
  https://gist.github.com/andrewkroh/83e3ac2c07f212974de42175d55d9701 ;
  https://github.com/NousResearch/hermes-agent/issues/113187 ;
  https://github.com/roystondwork-dev/portcheck/pull/22 (search summary) ;
  https://github.com/shirou/gopsutil/issues/164 (search summary) ;
  https://www.charlesproxy.com/documentation/tools/client-process/ ;
  https://docs.mitmproxy.org/stable/concepts/modes/ ;
  https://github.com/evilsocket/opensnitch/wiki/Why-OpenSnitch-does-not-intercept-application-XXX ,
  https://lwn.net/Articles/988401/ , https://github.com/evilsocket/opensnitch/discussions/569 (search summary)
- Crates: https://crates.io/api/v1/crates/{netstat2,listeners,libproc,procfs} ;
  https://raw.githubusercontent.com/andrewdavidmackenzie/libproc-rs/master/src/libproc/net_info.rs ;
  https://raw.githubusercontent.com/ohadravid/netstat2-rs/main/src/integrations/osx/netstat.rs ;
  https://github.com/GyulyVGC/listeners ; https://docs.rs/procfs/latest/procfs/net/index.html
- Probes (V, throwaway C files in `$TMPDIR/probe`, read-only, not committed): full-scan timer with per-flavor
  errno counts; listener `lport` dump (byte order); `offsetof`/`sizeof` print; `dlsym` + responsible-pid walk;
  `ctypes` `proc_pidpath` of `/usr/bin/python3`; `codesign -dv`/`defaults read` for bundle ids.

## For the Architect

Decisions the spec must take:
1. **Where resolution lives**: core leaf crate (unsafe isolated like `aitm-peer-token`), app, or both; and
   whether to depend on the `libproc` crate or own the 792-byte `#[repr(C)]` layout with a self-test.
2. **Scan policy**: on-demand at accept vs periodic; coalescing, deadline (socket fds only, never vnode fds),
   rate limit, and what the proxy does while a scan runs (resolve asynchronously, update the flow later).
3. **Match rule**: ports compared after `ntohs` (low 16 bits), address equality including `::1` and
   `::ffff:127.0.0.1`, skip our own pid, ambiguity handling for inherited sockets.
4. **Unattributable clients**: root/other-user daemons (EPERM) and clients that exited: show "unknown", never
   guess; whether a `uid` hint from Linux `/proc/net/tcp` is exposed.
5. **Identity policy and wire shape**: which of helper-name, outermost-app, responsible-pid owner, basename wins;
   the Xcode-toolchain `.app` exception; which fields to emit (`name`, `bundle_id`, `path`, `pid`); whether to
   emit the full path (username leak) or basename only.
6. **Private SPI**: whether `responsibility_get_pid_responsible_for_pid` is used at all (linkable via
   libSystem, undocumented), and the fallback if the symbol or behaviour changes.
7. **Privacy contract**: never argv, never `cmdline`/`environ`/`KERN_PROCARGS2`; sanitise strings.
8. **Linux scope**: hand parse vs `procfs` vs `sock_diag`, same-uid only, and behaviour under `hidepid`/
   `subset=pid`/containers.
9. **Cache keys and lifetime**: per connection (resolve once), `(pid, start_time)` for any pid cache.
10. **Proof**: an operator-journey live proof on a real accepted loopback connection (curl, Safari, Chrome,
    Terminal python) on macOS and a Linux host, since the sandbox probe here could not make a pair.
