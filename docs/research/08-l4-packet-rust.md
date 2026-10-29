# Raw-L4 / packet-level capture and injection in Rust (M4 input)

> **Provenance:** AI-generated research summary produced by the Researcher
> engine reading public crate registries, docs.rs, man pages, and upstream
> repos on **2026-10-27**, plus the aitmproxy tree. Starting-point synthesis,
> not an authoritative spec. **Method caveat:** the Bash sandbox denied `curl`
> to crates.io, so every crates.io / docs.rs / GitHub figure below (versions,
> dates, download counts, MSRV, API signatures, `cfg` gates) was read through
> the WebFetch tool, which summarises the page with a small model. Treat those
> as second-hand until re-checked with `cargo info` / `cargo doc` on a
> networked machine. Man pages and upstream source were read the same way. No
> fetched page carried instructions aimed at this task. **Scope:** this is
> tooling-architecture research for an operator with written authorization to
> test an in-scope target. It contains no exploit recipes and deliberately
> stops at "what the building blocks are and what they cost".

## 1. Question

Which Rust crates and OS mechanisms can give `aitm-proto-l4` packet capture
and crafted-packet injection on macOS and Linux, what privileges and platform
limits come with them, and how do established tools (scapy, boofuzz) separate
crafting from sending and keep sending bounded?

## 2. Short answer

On macOS and Linux the lowest-risk stack is libpcap via the `pcap` crate
(2.5.0, Aug 2026, active) for capture and L2 injection (`sendpacket`), plus
`etherparse` or `pnet_packet` to build and parse. `pnet` is the one
all-Rust datalink option, but its last release was May 2024. Least privilege
is `CAP_NET_RAW` on Linux and read/write on `/dev/bpf*` on macOS (no
capability model). Raw send skips normal socket policy, so scope, rate, and
size limits must sit at the single lowest send function. Unprivileged L4 is not
possible on either OS.

## 3. Findings

All sources read 2026-10-27. "Inference" marks my reading, not a source claim.

### 3.1 Capture and inject crate options

| Option | Capture | Inject | Platforms | Version / maintenance (2026-10-27) | Pros | Cons |
|---|---|---|---|---|---|---|
| **`pnet` / `pnet_datalink`** | yes (AF_PACKET on Linux, BPF on macOS/BSD) | yes, L2 (`DataLinkSender::send_to` / `build_and_send`); Linux can also do L3 "cooked" via `ChannelType::Layer3` | Linux, macOS/BSD, Windows (needs WinPcap/Npcap + `Packet.lib`) | **0.35.0, published 2024-05-30** (~29 months old); ~3.0M recent downloads; repo `pushed_at` 2026-05-01, newest commits are merges of Windows fixes, 151 open issues | One API for both OSes; no libpcap dependency; BPF backend already handles `/dev/bpf*` scan, `BIOCSHDRCMPLT`, and the loopback header quirk; `Packet` types in the same family | No release in ~2.4 years while `main` moves; `next()` blocks (see 3.3); `promiscuous` defaults to `true`; `send_to` ignores its destination argument; `channel_type`/`read_timeout` docs are Linux/BPF-only; contains `unsafe` internally |
| **`pnet_transport`** | yes, per IP protocol | yes, `Layer4` (kernel builds IP header) or `Layer3` (IPv4 only, caller supplies IP header via `IP_HDRINCL`) | Linux, macOS/BSD, Windows | 0.35.0 (same release train) | Closest thing to "send crafted IP/TCP without L2"; BSD length/offset fixups done for you | Doc: on OS X and FreeBSD you cannot implement protocols the kernel already implements (TCP/UDP); `Layer3` IPv4-only |
| **`pcap`** (libpcap bindings) | yes, live + savefile; BPF filter; optional `capture-stream` (tokio) | yes, `Capture<Active>::sendpacket(&mut self, buf: B) -> Result<(), Error>` (L2, link-layer header included) | Linux, macOS (libpcap ships with the OS per README), Windows (Npcap loaded at runtime) | **2.5.0, 2026-08-15**; releases 2.3.0 (Jul 2025), 2.4.0 (Nov 2025), 2.5.0; latest commits 2026-10-12/18 incl. "Remove the From impls that result in segfault (#418)"; ~1.06M recent downloads | Best maintained of the group; same code path on macOS and Linux; savefile writer (craft to a file without sending); libpcap already encodes per-OS BPF/AF_PACKET detail | C dependency (needs `libpcap-dev`/`pkg-config` on Linux, `LIBPCAP_LIBDIR` otherwise); L2 inject only; `sendpacket` is blocking; `stream()` errors if the capture is blocking or the fd is not `select()`-able; `setcap` guidance grants both `cap_net_raw` and `cap_net_admin` |
| **`socket2` raw** | no (raw IPv4 sockets on macOS never see TCP/UDP, see 3.3) | yes: `Type::RAW`, `set_header_included_v4/v6` (`IP_HDRINCL`) | Linux, macOS, Windows (each item has its own `cfg`) | **0.6.5, 2026-07-13**; ~348M recent downloads (std-adjacent) | Very well maintained; safe `send_to` with `std` socket addresses; `bind_device` (Linux `SO_BINDTODEVICE`) and `bind_device_by_index_v4/v6` (`IP_BOUND_IF`, macOS + Linux) for interface binding | Raw items need crate feature `all`. `Domain::PACKET` (AF_PACKET) is Linux/Android only. Building a `sockaddr_ll` needs `unsafe` (`SockAddr::new` / `try_init` are `unsafe`; no safe AF_PACKET constructor seen). No BPF support |
| **`nix` raw** | Linux AF_PACKET only | yes | Linux/Android (`AddressFamily::Packet`, `SockProtocol::EthAll` are Linux/Android-gated; no `AF_LINK`); `SockType::Raw` everywhere except Redox | **0.31.3, 2026-05-11**; ~220M recent downloads | Maintained; typed wrappers over `libc` | No BPF/macOS L2 path found on its `socket` module page; per-item `net`/`socket` features; whether a *safe* `LinkAddr` constructor exists was not confirmed |
| **`nfq`** (NFQUEUE) | in-path packet queue, not a tap | in-path verdict + reinject of modified packets (`Queue::open/bind/recv`, `Verdict`, `queue.verdict(msg)`) | Linux only | **`nfq` 0.2.5, 2022-01-26 (stale)**; fork `nfq-updated` 0.2.6, 2025-12-28 (~3k downloads); `nfqueue` 0.9.1 is from 2017 | Talks netlink directly, no `libnetfilter_queue` (GPL) link; verdict model fits "mutate then forward" | Stale / small; Linux only; needs a firewall rule to steer traffic into the queue (host config change) |

Details behind the table:

- **pnet_datalink** (docs.rs, `pnet_datalink/src/{lib,linux,bpf}.rs`). `channel()`
  dispatches at compile time: AF_PACKET on Linux/Android, `bpf.rs` on
  macOS/BSD, pcap/winpkfilter on Windows with features. `Config` defaults: 4096
  read/write buffers, no timeouts, `Layer2`, `bpf_fd_attempts` 1000,
  `promiscuous: true`. Linux: `SOCK_RAW`+`ETH_P_ALL` for `Layer2`,
  `SOCK_DGRAM` for `Layer3`; promiscuous via `PACKET_ADD_MEMBERSHIP`/
  `PACKET_MR_PROMISC`. macOS BPF: loops `/dev/bpf0..N`, then `BIOCSBLEN`,
  `BIOCSETIF`, `BIOCIMMEDIATE`, `BIOCGDLT`; `BIOCSHDRCMPLT` on non-loopback
  only; `BIOCFEEDBACK` on loopback only, which its own comment says is a no-op
  on macOS/OpenBSD.
- **pnet_transport** (source, `lib.rs`). `Layer4` sets `IP_HDRINCL=0`, `Layer3`
  sets `1` and received packets carry the IPv4 header. On macOS/FreeBSD the
  crate converts total length / fragment offset byte order on send and fixes
  them on receive, citing `man 4 ip`.
- **pcap** (docs.rs, README, repo API). README: `setcap cap_net_raw,cap_net_admin=eip`
  for non-root on Linux; `capture-stream` depends on `tokio` 1.x. **Discrepancy:**
  crates.io reports `rust_version` 1.64 for 2.5.0 while the README says
  edition 2024 / compiler 1.85+; unresolved. aitmproxy's workspace
  `rust-version` is 1.97 either way.
- **socket2 / nix** (docs.rs). Quoted gates above come from the item pages;
  `set_mark` (Linux) is documented as needing `CAP_NET_ADMIN`.

### 3.2 Packet building and parsing, and "scapy-style" layering in Rust

| Crate | Version / maintenance | Model | Pros | Cons |
|---|---|---|---|---|
| **`etherparse`** | **0.21.0**; releases 2026-06-14, 07-04, 07-21; ~2.6M recent downloads; README: "still in development and can & will still change" | Zero-alloc slice parsers (`SlicedPacket`, `LaxSlicedPacket`) and header structs; typestate **`PacketBuilder`** chain (`ethernet2` -> `ipv4`/`ipv6` -> `tcp`/`udp`/`icmp` -> `write`) | Layered feel closest to scapy's `/`; **lax parsers for cut-off or malformed packets**; protocol list: Ethernet II, VLAN, MACsec, ARP, IPv4, IPv6 (common extension headers, not all), UDP, TCP, ICMP/ICMPv6 (not all types), IGMP | `PacketBuilder` "automatically calculates lengths & checksums" and `ip(header)` overwrites length/protocol/checksum, so it is a *well-formed-packet* builder; invalid checksums need `write_raw`, which the page lists for `Ipv4Header` only (TCP not confirmed) |
| **`pnet_packet`** | 0.35.0 (see 3.1) | `#[packet]`-macro zero-copy views: `Foo` (read) and `MutableFoo` (write over a caller buffer); `MutableIpv4Packet` exposes setters for every field including `set_version`, `set_header_length`, `set_total_length`, `set_checksum`, `set_fragment_offset`; `new()` returns `None` if the buffer is below minimum size; `tcp::ipv4_checksum`/`ipv6_checksum` helpers exist | Field-level control: every field is settable, so inconsistent or invalid packets are expressible; protocols include Ethernet, ARP, IPv4/6, TCP, UDP, ICMP/v6, VLAN, GRE, VXLAN, DHCP, DNS | No layered builder: you size a buffer and fill each layer by hand; IPv6 extension-header support unconfirmed; same stale release train as `pnet` |
| Scapy-like Rust crates (`wiry` 0.1.0, `wiry-capture`, `pnet_layers` 0.1.0, `packet_rs` 0.4.0, `pkts` 0.2.1, `crafter` 0.3.5) | all pre-1.0; `wiry*` published 2026-09-17 (about 24 recent downloads); `pnet_layers` Aug 2025; `packet_rs` Apr 2023 | Scapy-style wrappers | n/a | **None has meaningful adoption**; code not reviewed. Listed only to show there is no established Rust scapy equivalent |

Inference: in Rust, "layered crafting" is either a typestate builder
(`etherparse`) or macro-generated mutable views (`pnet_packet`). The
second is what lets a tester deliberately write out-of-spec fields; the first
is a safer default and gives an easy lax *parser* for validating what is about
to be sent.

### 3.3 Privilege model per OS

| Task | Linux (least privilege) | macOS (least privilege) |
|---|---|---|
| (a) Capture | **`CAP_NET_RAW`**. packet(7): creating a packet socket requires it "in the user namespace that governs its network namespace"; pcap(3pcap): "you must have `CAP_NET_RAW` in order to capture". packet(7) does not name `CAP_NET_ADMIN` for promiscuous mode; Wireshark and `pcap` still tell you to grant `cap_net_raw,cap_net_admin`. **Why `CAP_NET_ADMIN` is added is not stated in any page I read (unverified).** | **Read access to `/dev/bpf*`** (pcap(3pcap); libpcap README.macos). No capability system. |
| (b) Injection | **`CAP_NET_RAW`** (packet sockets and raw sockets, capabilities(7): "Use RAW and PACKET sockets"). `SO_MARK` needs `CAP_NET_ADMIN` (socket2 doc); NFQUEUE needs `CAP_NET_ADMIN` (libnetfilter_queue doc). | **Write access** to `/dev/bpf*` (libpcap README.macos). Raw `AF_INET` sockets: `EACCES` for a non-privileged process (ip(4) DIAGNOSTICS). |
| How to get it without full root | File capabilities via `setcap`, stored in the `security.capability` xattr; writing it needs `CAP_SETFCAP`; ambient caps are cleared when a program with file capabilities is exec'd (capabilities(7)). Wireshark's fallback is setuid root when the filesystem lacks file-cap support. Systemd-style ambient grants not read. | devfs cannot persist permissions, so a launch daemon re-applies them at boot: libpcap ships `ChmodBPF` (group `admin`, `rw-rw----`); Wireshark's cask ships a launchd job with group `access_bpf`, expected `crw-rw---- root access_bpf` (search-result summaries of Wireshark/Homebrew pages; libpcap README.macos). Needs root once to install. |
| Sandboxing | n/a | Apple DTS (2020): `/dev/bpf*` is root-readable; the App Sandbox is a *second* barrier that group ownership does not fix; live capture "not feasible in an App Store app". Not relevant to a CLI tool; relevant if the Mac app (`apps/mac`) ever tried to capture itself. |
| Privilege separation precedent | Wireshark: GUI/`tshark` unprivileged, only `dumpcap` privileged (wiki.wireshark.org CapturePrivileges). | Same pattern, same source. |

Additional Linux angles:

- **User-namespace lab path.** Because the `CAP_NET_RAW` check is relative to the
  user namespace that owns the net namespace (packet(7), raw(7)), an
  unprivileged process that creates its own user+net namespace can in principle
  hold it there, for a private veth/lo lab. **Caveat:** Ubuntu 24.04's AppArmor
  policy denies capabilities inside unprivileged user namespaces for unconfined
  programs (`kernel.apparmor_restrict_unprivileged_userns`; release notes and
  AppArmor wiki via search). I did not test either.
- **Unprivileged ICMP echo.** icmp(7): the `ping_group_range` sysctl lists the
  groups allowed to create ICMP Echo sockets; default `"1 0"` means none. That is
  the only unprivileged "raw-ish" path I found, and it is ICMP Echo only.
- **Windows (note only, not a target).** Npcap's `/admin_only` install option
  restricts capture and injection devices to SYSTEM and Administrators with UAC
  per capture process; loopback capture and injection are supported from
  0.9983 without a special option; the free edition is non-commercial and
  silent install/redistribution needs Npcap OEM (npcap.com guides). `pnet`
  needs `Packet.lib` and `pcap` resolves Npcap entry points at runtime.

### 3.4 Cross-platform limits that shape the design

- **Raw sockets are not packet capture on macOS.** Apple DTS: "You can't use raw
  sockets to read TCP or UDP", quoting Stevens (UNP vol 1, 2nd ed., 25.4):
  received TCP/UDP packets are never passed to a raw socket. Linux differs:
  raw(7) says raw sockets "may tap all IP protocols... even TCP", delivered to
  both the kernel and the socket, "not to be relied on in portable programs".
  Consequence: macOS capture for anything TCP/UDP **must** go through BPF.
- **`IP_HDRINCL` is not uniform.** Linux (raw(7)): the kernel *always* fills the
  IP checksum and total length, and fills source and packet ID only when zero, so
  a Linux L3 raw socket **cannot emit a bad IP checksum or length**; that needs
  L2 (AF_PACKET/BPF). macOS (ip(4)): you must set all header fields, and
  `ip_off`/`ip_len` go in host byte order; `ip_id=0` and `INADDR_ANY` source are
  filled. Sources disagree on macOS *receive* byte order (Hackaday vs older BSD
  notes), so it needs a test on the target OS version.
- **L2 injection needs the right link-layer header per interface type.**
  pcap_inject(3pcap): the buffer "must include the link-layer header", and on
  some platforms the source link-layer address may be rewritten to the
  interface's own; opening an interface does not prove sending will work (check
  `PCAP_IF_NO_INJECT`). BPF: `BIOCSHDRCMPLT` is 0 by default, so the kernel
  fills the source address; set it to 1 to preserve yours (bpf(4)). That same
  1996 BSD man page says only writes to Ethernets and SLIP links are supported.
  **Dated; do not rely on it for current macOS.**
- **Loopback differs between the two target OSes.**
  - *macOS `lo0`*: DLT_NULL, a 4-byte header holding the address family in host
    byte order (tcpdump.org LINKTYPE_NULL; IPv6 has several OS-specific values,
    24/28/30). Writes need that header; a wrong value gives `EAFNOSUPPORT`
    ("looutput: af=0 unexpected", FreeBSD list, 2014). Scapy's BPF code
    comments that Darwin `if_lo` and `if_utun` need the header while `tuntaposx`
    does not. `pnet`'s BPF loopback path discards the Ethernet header and says
    "the OS will prepend the packet with 4 bytes set to AF_INET"; **inference:**
    that path is IPv4-centric, so IPv6 on `lo0` is unproven.
  - *Linux `lo`*: Ethernet framing with all-zero MACs (secondary sources:
    tcpdump list thread and blog write-ups; I found no man page that states it).
    So one Ethernet frame builder works on Linux `lo` but not on macOS `lo0`.
  - A frame written to a BPF device may be read back on the same device
    (Apple Community thread, OS X 10.4; `BIOCFEEDBACK` is the FreeBSD answer and
    is a no-op on macOS per `pnet`). Dated; re-test.
- **User-space TCP crafting collides with the host kernel.** Several scapy
  tutorials report that a crafted SYN's SYN-ACK reply reaches the kernel, which
  sends a RST because it has no matching socket; the usual workaround is an
  outgoing-RST firewall drop rule (not in scapy's official docs; secondary
  sources only). Any stateful raw-TCP test therefore either stays stateless, or
  changes host firewall state (which needs `CAP_NET_ADMIN` and is a
  scope/authorization question, not just a coding one).
- **Interface binding.** Linux: AF_PACKET `sll_ifindex` (packet(7)), raw
  `SO_BINDTODEVICE` (raw(7); socket2 `bind_device`, Linux only). macOS: BPF
  `BIOCSETIF` by name (bpf(4)); raw sockets `IP_BOUND_IF` (socket2
  `bind_device_by_index_v4`, macOS + Linux). Unbound AF_PACKET with
  `sll_protocol` set receives that protocol from *every* interface (packet(7)).
- **Async.** `pnet` `next()` on Linux `poll`s with the read timeout; with no
  timeout "poll blocks until data arrives", and BPF uses `pselect`: inference,
  needs a blocking thread or a timeout. `pcap`'s `stream()` needs a
  non-blocking, `select()`-able capture; a macOS `select()`-on-BPF caveat is
  not documented on that page and is unverified.
- **Promiscuous capture.** `pnet` defaults it on, which would capture other
  hosts' traffic on a shared segment; `pcap` exposes `promisc` on
  `Capture<Inactive>` before `open()`.
- **Raw send bypasses ordinary socket policy.** packet(7): packets are "queued
  unmodified to the driver of the interface named by the destination address";
  `PACKET_QDISC_BYPASS` (Linux 3.14+) even skips the qdisc, documented for
  traffic generators ("use at your own risk"). Inference: host egress firewall
  rules and per-socket policy are not a safety net for this path, so the guard
  must live in aitmproxy.
- **Can L4 run unprivileged?** Not for raw packets on either OS, in any source
  read. Partial exceptions: Linux ICMP Echo sockets (if `ping_group_range` is
  set) and a user-namespace lab (distro-dependent). What degrades on macOS vs
  Linux: no capability model (device-file ACLs instead); no raw-socket receive of
  TCP/UDP; no `AF_PACKET`/`SO_BINDTODEVICE`/`PACKET_*` tuning; loopback header
  differs; Wi-Fi injection is driver-fragile (libpcap issue #922: kernel panic
  on `pcap_inject` after monitor mode on macOS 10.15; old, anecdotal).

### 3.5 In-path interception vs raw send (Linux and macOS)

Three different shapes, not interchangeable:

| Shape | Mechanism | What the app sees | Privilege | Fit to today's seam |
|---|---|---|---|---|
| **Stream-shaped, in-path** | Linux TPROXY (`IP_TRANSPARENT` before `bind`, mangle-table rule, fwmark route; nf_tables support from Linux 4.18, kernel docs) or `iptables REDIRECT`; macOS `pf rdr` | Ordinary TCP/UDP sockets, original destination preserved by TPROXY | Needs root for the rules (mitmproxy doc: macOS needs `sudo pfctl`, proxy must run as another user to avoid loops; Linux transparent mode "does require root"). `capabilities(7)` lists "bind to any address for transparent proxying" under `CAP_NET_RAW` | **Natural fit**: yields a `ByteStream`; no raw packets involved |
| **Packet-shaped, in-path** | Linux NFQUEUE via `nfq`/libnetfilter_queue: userspace verdict plus modified-packet reinjection | Each IP packet, with accept/drop/modify | `CAP_NET_ADMIN` | Packet-shaped; Linux only; stale crate |
| **Packet-shaped, out-of-band** | Capture tap + inject (libpcap/BPF/AF_PACKET) | Copies of frames, plus the ability to write arbitrary ones | `CAP_NET_RAW` / `/dev/bpf*` | Packet-shaped; the "raw send" half of the question |

Platform-level in-path redirection that does not use pf: `mitmproxy_rs` uses a
WinDivert redirector on Windows, a **Network Extension** on macOS (binary-only
on PyPI "due to code signing and notarization"), and an **Aya eBPF** program on
Linux (GitHub README). Its README does not state privileges per OS.

### 3.6 How established tools structure crafting vs sending

**Scapy** (docs `usage`, `build_dissect`, `api/scapy.sendrecv`):

- *Layered model.* A layer is a `Packet` subclass with a `fields_desc` list.
  Layers compose with `/`; the lower layer's defaults adapt to what is above it
  (explicit values still win). A plain string is a raw payload layer.
- *Craft is separate from build and from send.* Fields left unset are filled when
  the packet is built; `post_build()` "is typically what is required to compute
  checksums or lengths" and runs "starting from the end" (innermost first).
  `show2()` displays the assembled packet before anything is sent.
- *Send is a small family keyed by layer.* `send` is layer 3 (scapy handles
  routing and L2, using its own routing table); `sendp` is layer 2 ("it's up to
  you to choose the right interface and the right link layer protocol"); `sr`,
  `sr1`, `srp` send and match answers; `sendpfast` replays via tcpreplay with
  `pps`/`mbps`.
- *Pacing is opt-in.* `inter` is "time (in s) between two packets (default 0)";
  `count` defaults to one packet; `loop=1` sends "indefinitely". Docs show no
  default rate cap or scope check. Root is required to send.
- *`fuzz()`* replaces default field values with random values suited to each
  field, "except for fields computed automatically such as checksums", so by
  default checksums stay valid; it does not randomize IP `src`/`dst` (use
  `RandIP()` explicitly).

**boofuzz** (docs `quickstart`, `protocol-definition`, `Session`; source
`connections/`):

- *Definition vs transmission.* A protocol is a tree of `Request` -> `Block` ->
  primitives (`Static`, `String`, `Byte`/`Word`/`DWord`, `Group`, `Delim`...).
  Each element yields a `mutations` generator of "pre-rendered" values and
  keeps a valid `default_value`; the page "does not describe sending".
- *Transport is a narrow interface.* `ITargetConnection`: `open`, `close`,
  `recv`, `send`, `info`. Implementations: TCP, UDP, SSL, raw L2/L3, serial. A
  `Target` wraps one connection; a `Session` owns the message graph
  (`connect()` orders prerequisites) and drives `fuzz()`.
- *Raw L2 transport rails.* `RawL2SocketConnection` opens `AF_PACKET`/`SOCK_RAW`,
  binds to an interface and ethertype, has `send_timeout`/`recv_timeout` (5 s
  default), and **truncates every send to `max_send_size`**, derived from `mtu`
  (default 1514).
- *Pacing and health.* `Session(sleep_time=...)` "Time in seconds to sleep in
  between tests. **Default 0**"; `restart_interval`, `crash_threshold_request`
  (12), `crash_threshold_element` (3), `restart_threshold`/`restart_timeout`
  (default: retry indefinitely), `receive_data_after_each_request`, and
  `ignore_connection_reset`. Results go to a SQLite DB per run and `boo open`
  replays them. The docs I read show no scope allowlist.

Takeaways (observations, not decisions): (1) crafting/mutation is pure, data-only
and testable; (2) sending hides behind a tiny trait; (3) rate pacing exists in
both tools but defaults to **off**, so aitmproxy's deny-by-default stance would
invert their defaults; (4) the transport object is where interface binding and a
size cap live; (5) boofuzz's per-run results DB matches aitmproxy's
reproducible-artifact goal.

### 3.7 What is already in the aitmproxy tree (read 2026-10-27)

- **The seam is stream-shaped.** `ProtocolModule::spawn(io: ByteStream, ctx)` and
  `matches(&NextLayerHint)`, where the hint is a TCP connection's `dst`,
  `is_tls`, SNI, ALPN, first bytes (`crates/aitm-core/src/protocol.rs`,
  `stream.rs`). `ModuleCtx::connect_upstream` returns a `ByteStream`. A raw
  capture/inject module has no accepted connection and no byte stream, so it
  does not fit this contract without a new entry path. The platform spec
  (lines ~555-557) says L4 would "implement the **same trait** over `pnet`/`pcap`
  or TPROXY/nfqueue"; the evidence in 3.5 says that holds for TPROXY and not for
  raw send. **That is a design question for the Architect.**
- **`Flow` has two variants** (`Http`, `WebSocket`); no L4/packet flow type exists
  (`crates/aitm-core/src/flow.rs`).
- **The guard is host-string, request-rate shaped.** `ScopeRateGuard::check_active(host: &str)`;
  `ScopeEntry { host: String }` (host, `host:port`, or `*.wildcard`); token
  buckets in requests/sec (global and per host), a concurrency permit,
  per-host error budget with exponential backoff
  (`crates/aitm-core/src/guard.rs`, `config.rs`). No CIDR, interface,
  packets/sec, bytes/sec, or frame-size notion.
- **`unsafe_code = "forbid"`** at workspace level, with a comment that a future
  `unsafe` crate "is a deliberate, reviewed decision"; WORKFLOW.md requires a
  `// SAFETY:` comment and Security-reviewer sign-off.

## 4. Candidate directions (for the Architect, not decisions)

**Candidate A: libpcap via the `pcap` crate, plus `etherparse` / `pnet_packet`.**
One capture+inject backend on both OSes; `sendpacket` is L2 only, caller adds the
link-layer header (Ethernet on Linux `lo`/NICs, DLT_NULL on macOS `lo0`). Our
crate can stay unsafe-free (the `unsafe` is in the dependency). Best maintenance
signal. Costs: C library dependency (headers on Linux), per-interface link-type
handling in our code, blocking send.

**Candidate B: `pnet_datalink` + `pnet_packet` (+ `pnet_transport`).** Fewer
moving parts than A and already special-cases the macOS loopback header.
Costs: last release May 2024 against an active `main`, `next()` blocking,
`promiscuous` default on, `send_to` ignoring its destination, IPv6-on-`lo0`
unproven. If chosen, consider a git pin or a fork decision.

**Candidate C: own per-OS backends (AF_PACKET on Linux, BPF on macOS) via
`socket2`/`nix`/`libc`.** Maximum control (e.g. `PACKET_QDISC_BYPASS`, exact
ioctls) and no libpcap. Costs: the most code, and `unsafe` is unavoidable (BPF
ioctls; `sockaddr_ll`), which means lifting the workspace `forbid` for one
isolated crate with the review the workflow requires.

**Candidate D: raw IPv4 L3 sockets via `socket2` (no `unsafe`).** Good for
"kernel supplies L2, we supply IP+": `Type::RAW`, `set_header_included_v4`,
`bind_device*`. Costs: send-only on macOS for TCP/UDP; on Linux the kernel
overwrites IP checksum and total length, so it cannot express malformed IP
headers; needs `all` feature; macOS host-order fields.

**Candidate E: in-path complements.** TPROXY / `pf rdr` for stream-shaped
interception that fits the existing `ByteStream` seam with no raw packets; NFQUEUE
for Linux packet-level in-path edits. These address a different need
(transparent interception, per-packet mutate-and-forward) than crafted injection,
and could be sequenced separately.

**Candidate F: privilege separation (orthogonal to A to E).** A small privileged
helper holding `CAP_NET_RAW` or `/dev/bpf*` write, with the main process
unprivileged and every frame validated at the helper boundary (the Wireshark
`dumpcap` precedent). Costs: IPC, packaging, a one-time root install step on
macOS.

**Guard placement (candidate, applies to any of A to D).** Put scope + rate + size
checks in the single lowest function that writes to the wire, not in the
crafting API, because (3.4) nothing below it will stop a bad frame and plugins,
Rhai, or MCP callers could hand in raw bytes. Observed rails to map onto: boofuzz's
`max_send_size` and `sleep_time`, scapy's `inter`/`count`, existing `StdGuard`
buckets. Possible additions the current guard lacks: IP/CIDR and interface
allowlists, packets/sec and bytes/sec, source-address restriction, promiscuous
off by default, and a dry-run that writes a savefile instead of sending
(`pcap` lists savefile writing).

## 5. Implications for aitmproxy

- **Best-fit pair (evidence-weighted, still a candidate):** A for capture and L2
  injection on both OSes, with `etherparse` for building and *validating*
  frames and `pnet_packet` only if field-level malformed construction is needed.
  Reasons: only option that is actively released, one code path on macOS and
  Linux, and keeps the workspace `forbid(unsafe_code)` intact. B is the fallback
  if libpcap as a C dependency is unacceptable.
- **Spec must plan for privilege as a first-class mode,** not an error path:
  Linux `CAP_NET_RAW` via `setcap` (caps and xattr caveats above), macOS
  `/dev/bpf*` read+write via a root-installed daemon (same pattern as the CA
  install work in `07-ca-install.md`), no L4 when unprivileged, and a clear
  "degraded" report that says which capability is missing. A capability-detection
  command is implied (inference).
- **Spec must decide the seam.** Raw send does not fit `ByteStream`/`spawn`
  (3.7). Either a new entry path beside `ProtocolModule`, or TPROXY-style
  stream interception as the part that does. Not decided here.
- **The guard must grow** (3.7 vs 3.6): host-string scope cannot express "this
  frame goes to 203.0.113.5 out of `en0`".
- **Per-OS behaviours that need tests, not assumptions:** macOS `lo0` header,
  IPv6 AF value, BPF read-back of injected frames, raw-socket byte order, Linux
  kernel RST interference. These are good **experiment** candidates on
  `experiment/<topic>`, not research.
- **Authorization posture:** the rails above reduce harm if misused but cannot
  prove authorization; the existing "deny-by-default scope is the authorization
  mechanism" decision (platform spec) would carry over as the only gate unless
  Matt wants a recorded authorization for L4, which is a bigger blast radius than
  HTTP (a policy call, not a research one).

## 6. Open questions

1. **Release status of `pnet`:** is anything unreleased on `main` since 0.35.0
   that matters? (GitHub's Releases page was empty; only commit lists were read.)
2. **Why `CAP_NET_ADMIN`?** Wireshark and `pcap` README grant it with
   `CAP_NET_RAW`; packet(7) and pcap(3pcap) name only `CAP_NET_RAW`. Is
   `CAP_NET_RAW` alone enough for capture with promiscuous mode?
3. **macOS current state:** `/dev/bpf*` permission model on the current macOS
   (Tahoe, 26): no source found; does ChmodBPF still apply, does BPF write to
   `en0` (non-monitor Wi-Fi) succeed, does SIP/notarization affect a helper?
4. **macOS `lo0` IPv6 injection** and BPF read-back of injected frames: not
   verified; `pnet`'s loopback path suggests IPv4 only.
5. **macOS raw-socket receive byte order** (`ip_len`/`ip_off`): sources disagree.
6. **`nix`:** is there a safe `LinkAddr`/AF_PACKET path that avoids `unsafe`?
   `socket2` has none (`SockAddr::new` is `unsafe`).
7. **`pcap` MSRV:** README (edition 2024, 1.85+) vs crates.io (`rust_version` 1.64).
8. **Linux `lo` Ethernet framing:** only secondary sources; no man page found.
9. **Kernel-RST interference:** only secondary sources; any firewall-mutation
   workaround touches host state and needs an explicit authorization decision.
10. **Async integration** (e.g. wrapping a raw fd with tokio's `AsyncFd` instead
    of a blocking thread): not read, so unverified for both `pnet` and `pcap`.
11. **Licensing:** libpcap's and `pcap`/`pnet`'s licences vs aitmproxy's
    `MIT OR Apache-2.0` (`pnet` is `MIT OR Apache-2.0` per crates.io; others not
    checked); Npcap redistribution terms if Windows is ever added.
12. **Re-verify registry data** (versions, dates, MSRV, feature gates) with
    `cargo info` / `cargo doc` on a networked machine; this run could not curl
    crates.io (see provenance).

## 7. Sources

All read 2026-10-27 unless noted.

- crates.io API (via WebFetch): `pnet`, `pcap`, `socket2`, `nix`, `etherparse`,
  `nfq`, `smoltcp`, `pdu`, plus search listings for `nfqueue`, `scapy`,
  `packet crafting`. https://crates.io/api/v1/crates/{name}
- docs.rs: `pnet_datalink`, `pnet_transport`, `pnet_packet` (+ `tcp`,
  `ipv4::MutableIpv4Packet`), `pcap::Capture`, `socket2` (`Domain`, `Type`,
  `Socket`, `SockAddr`), `nix::sys::socket` (`AddressFamily`, `SockType`,
  `SockProtocol`, `LinkAddr`), `etherparse` (+ `PacketBuilder`), `nfq`.
- GitHub: libpnet/libpnet (README; `pnet_datalink/src/{lib,linux,bpf}.rs`,
  `pnet_transport/src/lib.rs`; repo API and commits), rust-pcap/pcap (README;
  commits API), JulianSchmid/etherparse (README), mitmproxy/mitmproxy_rs
  (README), the-tcpdump-group/libpcap (`doc/README.macos`),
  secdev/scapy (`scapy/arch/bpf/supersocket.py`), jtpereyda/boofuzz
  (`connections/raw_l2_socket_connection.py`, `itarget_connection.py`).
- Man pages: man7.org `packet(7)`, `raw(7)`, `capabilities(7)`, `icmp(7)`,
  `user_namespaces(7)`; tcpdump.org `pcap_inject(3pcap)`, `pcap(3pcap)`,
  `pcap_activate(3pcap)`; keith.github.io/xcode-man-pages `bpf(4)` (1996 text),
  `ip(4)`; tcpdump.org LINKTYPE_NULL.
- Kernel/netfilter: docs.kernel.org `networking/tproxy`; kernel.org
  `networking/filter`; netfilter.org libnetfilter_queue doxygen.
- Wireshark: wiki.wireshark.org `CaptureSetup/CapturePrivileges`,
  `CaptureSetup/Loopback`; Wireshark/Homebrew ChmodBPF summaries via web search.
- Apple Developer Forums: threads 724580 (raw sockets cannot read TCP/UDP) and
  128528 (BPF permissions and sandbox).
- Npcap: npcap.com `npcap-users-guide`, `npcap-devguide`.
- mitmproxy: docs.mitmproxy.org `howto/transparent`.
- Scapy docs: scapy.readthedocs.io `usage`, `build_dissect`,
  `api/scapy.sendrecv`.
- boofuzz docs: boofuzz.readthedocs.io `user/quickstart`,
  `user/protocol-definition`, `source/Session`.
- Secondary / weaker: web-search summaries for Ubuntu AppArmor userns
  restriction, ChmodBPF details, macOS lo0 DLT_NULL write behaviour (FreeBSD
  net list 2014, Scapy PRs), Linux `lo` Ethernet framing, kernel-RST scapy
  tutorials, libpcap issue #922, Hackaday raw-socket article.
- aitmproxy tree: `docs/research/{03,05,06}-*.md`,
  `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md`,
  `crates/aitm-core/src/{protocol,stream,flow,guard,config}.rs`, root
  `Cargo.toml`.
