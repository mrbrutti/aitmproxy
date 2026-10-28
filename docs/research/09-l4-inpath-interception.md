# In-path / transparent L4 packet interception: park, mutate, forward (M5 input)

> **Provenance:** AI-generated research summary produced by the Researcher
> engine reading public crate registries, docs.rs, man pages, kernel source and
> mailing-list archives, Apple developer documentation and forums, and upstream
> repos on **2026-10-28**, plus the aitmproxy tree and three read-only commands
> on the author's Mac. Starting-point synthesis, not an authoritative spec.
> **Method caveat:** same as `08-l4-packet-rust.md`. Every crates.io / docs.rs /
> GitHub / kernel-source / Apple-docs figure below (versions, dates, download
> counts, API signatures, kernel behaviour) was read through the WebFetch or
> WebSearch tools, which summarise the page with a small model. This run did
> not use `cargo info` or `curl`. Treat registry data and kernel behaviour as
> second-hand until re-checked with `cargo info` / `cargo doc` and a test on a
> target kernel. Apple's `developer.apple.com/documentation` pages are
> JavaScript-rendered, so several were read through the site's JSON endpoint or
> came back as title-only; those items are marked unverified. The only first-hand
> observations are the three local commands in 3.4. No fetched page carried
> instructions aimed at this task. **Scope:** tooling-architecture research for
> an operator with written authorization to test an in-scope data-plane target.
> It contains no exploit recipes and stops at "what the building blocks are and
> what they cost".

## 1. Question

Which OS mechanisms and Rust crates can park a live, in-flight packet so an
operator or agent can mutate it and then forward or drop it (the packet-layer
analog of `flow.intercept` / `flow.mutate`) on Linux and macOS, what privilege
and setup does each need, and how do established tools handle the held packet?

## 2. Short answer

On Linux, packet park/mutate/forward is NFQUEUE: an `nft queue` rule hands
matching packets to a userspace process that returns accept, drop, or repeat,
optionally with a rewritten payload. It needs `CAP_NET_ADMIN`; the `nfq` crate
keeps our crate `unsafe`-free (its release dates from 2022). Parking is ours to
build: the kernel has no verdict timeout and drops on overflow, crash, or no
listener. macOS has no equivalent: this host's pf rejects `divert-to`, and
Apple's packet filter provider can only allow, drop, or delay. TPROXY yields
streams, not packets.

## 3. Findings

All sources read 2026-10-28. "Inference" marks my reading, not a source claim.

### 3.1 Linux NFQUEUE: how the park / verdict / mangle loop works

- **Roles.** A firewall rule sends matching packets to queue number N; a
  userspace process binds N over an nfnetlink socket and must issue a verdict
  per packet. libnetfilter_queue's main page (v1.0.5): the program "must issue a
  verdict"; accept and drop each remove the packet from the queue; verdicts can
  be **asynchronous** because only the packet ID is needed; the program can
  alter contents or metadata (packet mark, conntrack mark) and reinject; the
  kernel drops packets it cannot enqueue because the queue is full; "needs the
  CAP_NET_ADMIN capability". The page says the old `LibrarySetup` API is
  deprecated; it names `libmnl` and `libnfnetlink` as dependencies.
- **Rule side.** nftables: `queue [num N | num N-M] [fanout] [bypass]`; needs
  Linux 3.14+ (wiki.nftables.org "Queueing to userspace"). iptables:
  `-j NFQUEUE --queue-num N [--queue-balance a:b] [--queue-bypass]
  [--queue-cpu-fanout]` (iptables-extensions(8)). Queue numbers are 0 to 65535.
  A `queue` statement is a terminal verdict: "Queue the packet to userspace and
  stop the remain rules evaluation" (nftables quick reference).
- **Verdicts the kernel accepts** (kernel `nfnetlink_queue.c` and `nf_queue.c`,
  read via WebFetch of the GitHub master files). `NF_STOLEN` from userspace is
  rejected with `-EINVAL`. `NF_REPEAT` re-runs the current hook. `NF_ACCEPT`
  continues through remaining hooks. `NF_QUEUE` re-queues (to another queue
  number). `NF_DROP` frees the skb. A verdict for an unknown packet ID returns
  `-ENOENT`. `NFQA_MARK` is applied before reinjection. The `nfq` crate exposes
  these as `Verdict::{Drop, Accept, Queue(u16), Repeat, Stop}` (docs.rs).
- **Payload mangling.** The verdict message carries `NFQA_PAYLOAD`; the kernel
  calls `nfqnl_mangle()`, and **if mangling fails the verdict becomes
  `NF_DROP`** (kernel master). Constraints read in the same file: IPv4 and IPv6
  only; IPv4 total length must equal the new data length and IP options must be
  unchanged; IPv6 payload length must match and the extension-header chain must
  be unchanged, jumbograms rejected; growth fails above 0xFFFF bytes; shrinking
  must keep the transport header. After a successful write the checksum state is
  `CHECKSUM_NONE` and conntrack sequence adjustment runs if length changed.
  Python `NetfilterQueue` agrees on the user's side: "Checksums and lengths must
  be fixed by the user after changes" (README). Inference: our mutation layer
  needs a checksum/length fixup step, which `etherparse` (08, 3.2) can validate.
- **The kernel is tightening mangling in 2026.** An RFC (May 2026) makes
  `nfqnl_mangle()` return `-EPERM` when the queue's netns is owned by a
  **non-initial user namespace**; the netfilter pull request of 2026-05-22 lists
  "Disable netfilter payload mangling in user namespaces (nft_payload.c and
  nf_queue)" as item 5. A v3 series of 2026-06-09 ("add restrictions/validations
  for packet rewrite") adds the IPv4/IPv6 header validation above and **rejects
  writes on the bridge family** (userspace does not see the L2 header; the
  author knows of no users). That archive page shows no review replies, and I
  did not confirm which stable releases carry either change. The raw-file read
  of master describes the same checks, so treat the exact behaviour as a moving
  target to re-test on the target kernel. Consequences if the checks are in the
  target kernel: no payload edits from an unprivileged user-namespace lab
  (08's "user-namespace lab path" can still queue and accept or drop, unverified),
  and bridge-family queues cannot mutate; the stated workaround is queueing at
  the IPv4/IPv6 hooks with `br_netfilter` (search summary of the patch thread).
- **GSO.** `NFQA_CFG_F_GSO` lets the queue deliver GSO packets without software
  segmentation; the kernel file read describes it as opt-in (second-hand).
  `nfq` exposes it as `set_recv_gso`.

### 3.2 Rust crates for NFQUEUE (and the `unsafe` question)

| Crate | Version / maintenance (2026-10-28) | Model | Pros | Cons |
|---|---|---|---|---|
| **`nfq`** (crates.io) | **0.2.5, 2022-01-26**; 9 releases since 2019-09; ~59k recent downloads (142k total); `MIT OR Apache-2.0`; edition 2018, no `rust_version`; only dependency `libc ^0.2`; GitHub `nbdd0121/nfq-rs`: 38 stars, 2 open issues, last push **2026-06-03** | Direct NETLINK sockets, no `libnetfilter_queue` (that library is GPL-2.0 per the README). `Queue::open() -> io::Result<Queue>`, `bind(u16)`, `recv(&mut self) -> io::Result<Message>`, `verdict(&mut self, Message) -> io::Result<()>`, plus `set_fail_open`, `set_queue_max_len`, `set_copy_range`, `set_recv_enobufs`, `set_recv_gso`, `set_nonblocking`, `unbind`. `Message`: `get_payload`, `get_payload_mut`, `set_payload`, `get_packet_id`, `get_hook`, `get_indev/outdev`, `get_nfmark/set_nfmark`, `get_original_len`, `set_verdict` | Public API is safe `fn`s, so **our crate can keep `forbid(unsafe_code)`**. `Message` has no lifetime parameter (holds an `Arc` of the receive buffer), so it can be stored after `recv` and verdicted later: parking is natural. `get_payload_mut`/`set_payload` mark the payload modified, and it is sent unless the verdict is `Drop` | Release is 4.7 years old while `master` moved on. Published `lib.rs` has about three dozen `unsafe` blocks plus `unsafe impl Send/Sync for Message` (count and detail from a WebFetch summary, unverified), so the `unsafe` lives in the dependency, not in ours. Published 0.2.5 shows **no `AsRawFd`** (summary of `lib.rs`), so no `poll`/`AsyncFd` on it. `verdict` takes `&mut self`, so `recv` and `verdict` must share one owner. No timeouts of any kind |
| `nfq` on GitHub `master` | `Cargo.toml` says **0.2.6**, edition 2024, `rust-version = 1.85.0`; deps `libc`, `bytes`, `rustix` (`param`, `net`), `zerocopy 0.8`; commits 2025-10-08 "Move to zerocopy", 2025-10-17 "Remove some use of unsafe", "Add conversion from/to OwnedFd", fix 2026-06-03 | Same API; `impl AsRawFd`/`AsFd for Queue` plus `From<OwnedFd>` (summary of master `lib.rs`); `rustix` does socket/bind/sendto/recv; two remaining `unsafe` blocks seen (`setsockopt`, `buf.set_len`) | Fewer `unsafe` blocks; fd is exposed for `AsyncFd` or `poll` | **Not published to crates.io under `nfq`** (0.2.5 is latest there). Would need a git pin |
| **`nfq-updated`** | **0.2.6, 2025-12-28**, single release; ~3.0k recent downloads; repo `dilluti0n/nfq-rs`, 0 stars, a GitHub fork of the above | Unclear whether identical to upstream `master` | A published 0.2.6 exists | Fork with no stated rationale; one maintainer; docs.rs page for it returned 404 (docs build status unknown) |
| `nf-queue` | 0.1.0, 2025-11-26; 6 recent downloads; MIT | "thin wrapper around libmnl" | Newest | C dependency (`libmnl`); effectively no adoption |
| `nfqueue` / `libnfqueue` / `netfilter_queue` / `libnetfilter_queue` | 0.9.1 (2017-06-27, ~448 recent), 0.1.0 (2015), 0.2.1 (2015), 0.0.3 (2015) | Bindings to the C `libnetfilter_queue` | none | Abandoned; C library link means `unsafe` somewhere |
| `netlink-packet-netfilter` | 0.4.0, 2026-08-22; ~13.8k recent; MIT; `rust-netlink` org | Netlink message types for the netfilter subprotocol | Maintained; a possible base for hand-built queue messages | Modules seen: `conntrack`, `nflog`, `nftables`, `none`; **no queue module seen** (docs.rs top-level page only), so NFQUEUE would be hand-rolled |

Crates for *installing the rule* (not needed if the operator does it):
`nftables` 0.6.3 (2025-08-15, ~610k recent, `MIT OR Apache-2.0`, "Safe
abstraction for nftables JSON API"; JSON API implies driving the `nft` binary,
unverified), `rustables` 0.9.0 (2026-09-21, ~24k recent, **GPL-3.0-or-later** per
the version entry, which is a licence conflict with an `MIT OR Apache-2.0`
workspace if linked), `crabtables` 0.1.0 (2026-10-24, 22 recent downloads).

### 3.3 TPROXY versus NFQUEUE: which is the packet-level intercept

| | **TPROXY** | **NFQUEUE** |
|---|---|---|
| Unit | A whole TCP/UDP flow: kernel delivers it to a local listener "without changing the packet header in any way" (iptables-extensions) | One IP packet at a time |
| Userspace sees | Ordinary sockets (`IP_TRANSPARENT` set before `bind`); no raw packets (docs.kernel.org `networking/tproxy`) | Raw IP packets plus metadata: packet ID, hook, in/out device index, mark |
| Setup | `mangle` table `PREROUTING` rule, fwmark, policy route to table 100; nf_tables equivalent `tproxy to :50080` from Linux 4.18 (kernel doc) | `queue num N` rule in any hook |
| Fit to `ProtocolModule::spawn(ByteStream)` | **Direct**: yields a connection | None: no connection, no byte stream |
| `flow.intercept`/`mutate` analog | At the **stream** level only: park and edit bytes of a connection, TCP semantics handled by the kernel | **The packet-level analog**: park one packet, edit, accept or drop |
| Privilege | `CAP_NET_ADMIN` for rules; binding to a non-local address: "bind to any address for transparent proxying" is listed under both `CAP_NET_ADMIN` and `CAP_NET_RAW` (capabilities(7)) | `CAP_NET_ADMIN` (3.5) |

Evidence-weighted reading: NFQUEUE is the only Linux mechanism read that gives
per-packet park, mutate, and verdict. TPROXY is a different tool (flow-shaped)
that already fits the stream seam. A third Linux stream-shaped route exists:
`mitmproxy_rs` local capture uses a `BPF_PROG_TYPE_CGROUP_SOCK` eBPF program
plus a tun device and a user-space TCP stack, needs `sudo`, Linux 6.8+, and
chose eBPF because "iptables/nftables could not match traffic by process name"
(mitmproxy.org Linux local-capture post). Inference: nft rules scope by
address, port, and interface, not by process.

### 3.4 macOS: can a userspace process park and mangle an in-flight packet?

**Short version: not the way NFQUEUE does, and not from a plain CLI binary.**
Evidence in four parts.

**(a) First-hand checks on this host** (read-only; `sw_vers` reports
`ProductVersion 27.0`, `BuildVersion 26A428`, xnu-13432.1.9, not macOS 26 as the
brief assumed):

- `/sbin/ipfw` does not exist; `/sbin/pfctl` does.
- `man pf.conf` contains **zero** occurrences of "divert".
- `sysctl -a | grep -i divert` returns nothing.
- Parse-only (`pfctl -n -f`, nothing loaded) of three one-line rulesets on `lo0`:
  `divert-to 127.0.0.1 port 700` gives `syntax error`; `divert-packet port 700`
  gives `syntax error`; a control `rdr pass ... -> 127.0.0.1 port 8080` parses
  cleanly. (The pipeline's `exit=` echo was `head`'s, so ignore it.) The system
  headers under `/usr/include/netinet` and `/usr/include/net` were not present
  in this sandbox, so no header check was possible locally.

**(b) Kernel source corroboration** (apple-oss-distributions/xnu `main`, via
WebFetch, so second-hand and partial): `bsd/netinet/in.h` still defines
`IPPROTO_DIVERT 254` ("divert pseudo-protocol"), but `bsd/netinet/in_proto.c`
shows no divert entry in its protocol switch table and no match for
`divert`/`IPDIVERT`/`div_usrreqs`; `ip_divert.c` returns 404 on `main`;
`bsd/net/pfvar.h`'s rule-action enum (`PF_PASS` ... `PF_NORDR`,
`PF_SYNPROXY_DROP`, `PF_DUMMYNET`, `PF_NODUMMYNET`, `PF_NAT64`, ...) and the
routing enum (`PF_NOPFROUTE, PF_FASTROUTE, PF_ROUTETO, PF_DUPTO, PF_REPLYTO`)
contain no divert action. Only about the first 1000 of 2495 lines of
`pfvar.h` were visible. Inference: the constant is vestigial; there is no
`SOCK_RAW, IPPROTO_DIVERT` socket implementation. For context, OpenBSD has
`divert(4)` sockets integrated with pf (`divert-packet port N`, superuser to
bind) and FreeBSD ties them to ipfw (`IPDIVERT`) (man.openbsd.org and search
summary). Those are other BSDs. ipfw was removed in OS X 10.10 and replaced by
pf (search summaries of third-party pages; the date is second-hand).

**(c) Apple's stated position.**

- **pf is not API.** TN3165, "Packet Filter is not API": "It is not considered
  API. Do not use Packet Filter in a software product that you distribute to a
  wide audience"; rules "might clash" with the user's, system services' (now or
  later), or other products'. Its migration table: "Inspecting or blocking
  network packets: packet filter provider"; TCP/UDP flows: content filter
  provider; anything else: `NETransparentProxyProvider`. WWDC25 session 234:
  "Avoid using Packet Filter or directly modifying the routing table on the Mac.
  This is not supported." DTS also lists pf, utun, and NKEs as "ad hoc
  techniques" it does not support (forums thread 741544).
- **Filter providers cannot modify.** WWDC25 session 234 transcript: "Filter
  providers cannot modify traffic, but simply provide a filter verdict to the
  system, either to allow or drop the flow"; "For mac apps, a subclass of
  NEFilterPacketProvider will get Layer 2 packets." The `NEFilterPacketProvider`
  doc abstract (JSON endpoint): "decides whether to block, allow, or delay the
  packets"; macOS 10.15+; `delayCurrentPacket(_:) -> NEPacket` ("Delay a packet
  currently processed by a packet handler") and `allow(_: NEPacket)` ("Allow
  delivery of a previously-delayed packet"). So Apple's API **can park a packet
  and release or drop it, but no source read says the packet can be edited**
  (DTS in thread 767780, asked exactly this: "Your summary of the available
  facilities is pretty accurate", where the asker's summary was allow/block
  only, no reinjection). Whether the `NEPacket` handed to `allow` is editable is
  not stated on any page read (open question).
- **Tunnel and proxy providers are not a packet-munging facility.** DTS (thread
  87484, 2017): packet tunnel and app proxy providers "are _not_ intended to be
  a general-purpose 'munge all the packets' facility"; WWDC25: "Use
  NEPacketTunnelProvider only to tunnel IP traffic". DTS (thread 799252, Sep
  2025): "I strongly recommend that you avoid trying to re-inject packets. I've
  never found a way to do that reliably." DTS (767780) points at a **transparent
  proxy** instead ("you get the TCP flow, and thus you don't have to mess around
  with all the low-level TCP gubbins"), which is flow-level, not packet-level.
  The asker there objected that a TCP flow does not map to one packet, which is
  exactly the packet-level need.

**(d) What a provider needs, and whether a CLI can be one.**

- TN3134 (JSON endpoint) lists **Packet filter: system extension, macOS 10.15+,
  no "App Store only" restriction**; Content filter: system extension only.
- DTS (thread 800887): a sysex is embedded at
  `MyApp.app/Contents/Library/SystemExtensions/MyExtension.systemextension/`, "is
  effectively a `launchd` daemon", runs as root while the container app runs as
  the user, and is copied to a protected location on activation (so frameworks
  must live inside the sysex).
- Entitlement `com.apple.developer.networking.networkextension` is "a restricted
  entitlement, that is, it must be authorised by a provisioning profile". For
  Developer ID distribution use the `-systemextension` suffixed values (for
  example `content-filter-provider-systemextension`), plus Developer ID
  provisioning profiles for both app and extension (threads 800887, 737894).
  `mitmproxy` ships a "signed and notarized system extension" for its macOS
  redirector (mitmproxy.org post). Whether Apple must grant the entitlement
  value first is not stated on the pages read.
- The system checks that the container app "is installed in an appropriate
  `Applications` directory" (Apple system-extension doc, JSON endpoint). The
  user-approval step in System Settings and the `…system-extension.install`
  entitlement were **not** on the pages read; I know them only from the
  summariser's general knowledge: **unverified**.
- **Can a plain CLI binary do it?** No source read says one can host a provider;
  the packaging above is bundle-based and the question is "not discussed" in the
  DTS threads. Reading: the provider must be a signed, notarized sysex inside an
  app bundle, and the CLI would be at best the container's IPC peer (as
  `mitmproxy` does over a Unix pipe).
- **Root-only route without entitlements: utun.** A root process can create a
  `utun` device through `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` plus
  `com.apple.net.utun_control` (forum poster on macOS 14.4 via `sudo`; the
  `mac_utun` crate README says root is required; both are second-hand summaries
  and the crate is ~10 years old). Inference: route-based capture of selected
  destinations into a tun gives raw IP packets to userspace, but **forwarding
  them onward is the re-injection problem again** (DTS above, plus 08's BPF
  write caveats): TCP/UDP cannot be written back through a raw socket on macOS
  (08, 3.4), so a full solution needs its own TCP/IP stack, which is what
  `mitmproxy_rs` does on Linux. DTS says it does not support utun or pf for
  products.

**What the closest macOS option is, by need** (inference from the above):

| Need | Closest macOS mechanism | Gap versus Linux NFQUEUE |
|---|---|---|
| Park packet, then release or drop | `NEFilterPacketProvider` in a signed sysex (`delayCurrentPacket` / `allow`) | No edit; needs bundle, entitlement, notarization, approval; L2 packets; scope enforced in provider code |
| Mutate stream bytes in flight | `NETransparentProxyProvider` / App Proxy (what `mitmproxy --mode local` uses) or pf `rdr` (`sudo pfctl`, proxy under another user) | Flow-level; TCP and UDP only; pf is "not API" |
| Mutate a raw packet and forward | None supported. Root utun plus own stack is unsupported ad hoc | Re-injection is unreliable per DTS |
| Capture only | BPF (08) | Not in-path |

### 3.5 Privilege per OS

| Task | Linux | macOS |
|---|---|---|
| Bind an NFQUEUE and issue verdicts | **`CAP_NET_ADMIN`.** libnetfilter_queue docs: "needs the CAP_NET_ADMIN capability". Kernel `nfnetlink_rcv()`: `if (!netlink_net_capable(skb, CAP_NET_ADMIN)) { netlink_ack(skb, nlh, -EPERM, NULL);` before any message is dispatched (read via GitHub blob). `CAP_NET_RAW` is not needed: no source read names it for NFQUEUE (absence of evidence) | n/a |
| Install the steering rule | `CAP_NET_ADMIN` ("administration of IP firewall, masquerading, and accounting", capabilities(7)) | `sudo pfctl` (mitmproxy howto); pf unsupported by Apple |
| Edit payload | As above, **plus** initial user namespace (kernel master, RFC May 2026) | n/a |
| TPROXY listener | `IP_TRANSPARENT`: "bind to any address for transparent proxying" is under both `CAP_NET_ADMIN` and `CAP_NET_RAW`; rules need `CAP_NET_ADMIN` | n/a |
| Park-and-release equivalent | n/a | Signed, notarized system extension in an app bundle; restricted NE entitlement; user approval (unverified); sysex runs as root |
| Without full root | File capabilities via `setcap` (08, 3.3): the binary would need `cap_net_admin` | No supported path for a plain CLI |

Answer to 08 open question 2: capabilities(7) lists "set promiscuous mode"
under `CAP_NET_ADMIN`, which is the likely reason Wireshark and the `pcap`
README grant `cap_net_admin` alongside `cap_net_raw` (inference; the page does
not link the two). Not needed for NFQUEUE, where nothing is captured
promiscuously.

### 3.6 Held-packet lifecycle: what the kernel does and what tools do

**Kernel facts** (`nfnetlink_queue.c` master via WebFetch, unless noted):

| Event | What happens |
|---|---|
| Packet queued, no verdict yet | Entry stays queued. **The file has no timeout or timer**: until a verdict arrives, the queue is flushed, or the instance is destroyed |
| Queue reaches `queue_maxlen` (default **1024**, `NFQNL_QMAX_DEFAULT`) | New packet is **dropped** (`queue_dropped` counter, rate-limited log, `-ENOBUFS`), or **accepted** if `NFQA_CFG_F_FAIL_OPEN` is set. Held packets count against the 1024 |
| Netlink unicast to userspace fails | Dropped (`queue_user_dropped`), or accepted with fail-open |
| Verdict process exits or its netlink socket closes | Instance destroyed via deferred work; `nfqnl_flush()` reinjects every queued entry with **`NF_DROP`** |
| Queue unbound (`unbind`) or interface goes down | Same flush with `NF_DROP` for matching entries |
| No process bound to the queue | Packets dropped: "QUEUE == DROP if no one is waiting, to be safe" (`nf_queue.c` comment). Without a listener `-j NFQUEUE` drops "all packets that are to be queued"; `--queue-bypass` / `bypass` makes the rule "behave like ACCEPT" (iptables-extensions, nft wiki) |
| Rules are rebuilt by deleting a table | Kernel drops packets waiting in **every** nfqueue of the netns, not only that table's; fail-open does not help; avoid by replacing a rule in place (GitHub issue kubernetes-sigs/kube-network-policies #402, September 2026, root-cause analysis on kernel v6.18 by the reporter; measured 338 lost packets per 10 s with rebuild, 0 with chain flush) |
| Mangle fails validation | Verdict becomes `NF_DROP` (3.1) |
| Receiver too slow | `recv()` can return `ENOBUFS`; mitigations are a bigger socket buffer (`nfnl_rcvbufsiz()`), `NETLINK_NO_ENOBUFS`, or `--queue-balance` across several queues (libnetfilter_queue main page). `nfq`'s `open()` turns ENOBUFS reporting **off** by default, so overruns are silent unless `set_recv_enobufs(true)` is called (summary of master `lib.rs`) |
| Observability | `/proc/net/netfilter/nfnetlink_queue` shows queue depth and drops (search summary of Eric Leblond's guide; page itself returned 404) |

**What established tools do with a held packet**

| Tool | Behaviour read | Source |
|---|---|---|
| **Python `NetfilterQueue`** | `max_len` default 1024: "new packets are dropped if the size of the queue reaches this number"; packets awaiting a verdict count against it; README warns holding many hurts performance; **no verdict timeout mentioned**; `unbind()` makes matching packets drop; `repeat()` restarts the hook; `retain()` keeps payload after the callback; fixed 4096-byte payload buffer | README |
| **Suricata (inline NFQ)** | `queue bypass` is the documented fail-open: it "avoids link downtime when Suricata is stopped, but blocking is then not enforced"; `mode: accept` stops later rules, `repeat` marks and re-injects at the first rule (rule must skip marked packets to avoid a loop), `route` hands to a second queue; a Suricata-side `fail-open` for "queue full" (search summary, weaker) | docs.suricata.io |
| **Scapy** | No NFQUEUE layer in the docs read. Its in-path tool is `bridge_and_sniff(if1, if2, xfrm12, xfrm21)`: a callback returns a packet (forwarded in place of the original), `True` (forward as is), or `False`/`None` (discard). It is synchronous per packet: no parking | scapy.readthedocs.io api |
| **WinDivert (divert-based precedent)** | `WINDIVERT_PARAM_QUEUE_TIME`: "minimum time, in milliseconds, a packet can be queued before it is automatically dropped"; `QUEUE_LENGTH` and `QUEUE_SIZE` bound the queue; `SNIFF` copies instead of diverting. Numeric defaults appear only in third-party bindings (4096 packets, 2000 ms, 4 MB in 2.x) and disagree across them: weak | github.com/basil00/WinDivert wiki; search summaries |
| **mitmproxy transparent mode** | Stream-level only (iptables `REDIRECT` / pf `rdr`); parks **flows** at L7, never packets; nothing about timeouts | docs.mitmproxy.org howto/transparent |

Inferences (not read in any source):

- A packet-level `intercept` therefore has **no OS-provided deadline**. The
  parker must own a per-packet timer and a default verdict on expiry, and keep
  the number parked well below the queue limit, or the kernel starts dropping
  unrelated packets that match the same rule.
- The kernel defaults are all **fail-closed** (drop on no listener, overflow,
  crash, flush), except where `bypass` / fail-open is set. Fail-closed disrupts
  the target when aitmproxy dies; fail-open lets traffic through unmodified and
  unrecorded. Which is right is a policy call.
- Parking one TCP segment stalls that stream, and the sender's retransmissions
  also match the rule and also enter the queue. One search found no source on
  this; the mechanism is standard TCP behaviour.
- To avoid stalling unrelated traffic: narrow the steering rule (3.7), size
  the queue for the parked count, use `queue-balance`/`fanout` only if
  throughput needs it, and never rebuild the table (3.6 row above).

### 3.7 The kernel rule as a first scope boundary

- **What reaches userspace is decided by the rule.** Only packets matching the
  `queue` rule are copied to the process; everything else is never seen.
  nftables match syntax from the quick reference: `ip daddr 192.168.0.1`,
  `tcp dport 22`, `meta iifname "eth0"`, in a chain declared
  `type filter hook <input|forward|...> priority N`. Suricata's page says rules
  "can be narrowed by protocol, port, or interface" and that the queue chain
  should sit **after** the firewall rules. A rule like
  `ip daddr <in-scope CIDR> tcp dport <port> queue num N bypass` is therefore
  the kernel-side scope (rule composition is my inference from the pieces).
- **It is not process-aware.** nft cannot match by process name (mitmproxy
  Linux post), and `Message` metadata offers `get_uid`/`get_gid` only when
  `set_recv_uid_gid` is enabled (docs.rs).
- **Userspace guard still needed.** The rule can be edited, mistyped, or
  drift; the process owns the verdict, so a second check per packet is cheap
  (`Message::get_payload` gives the IP header; `get_indev`/`get_outdev`/
  `get_hook` give where it was seen). 08, 3.7 notes the current guard is
  host-string and requests-per-second shaped, with no CIDR, interface, or
  packets/sec notion.
- **macOS has no equivalent pre-filter I could verify.** For a packet filter
  provider the filtering decision happens in provider code; `NEFilterSettings`
  rules for packet providers were not read (open question).

### 3.8 What is already in the tree (read 2026-10-28)

- M5 spec (`docs/superpowers/specs/2026-10-27-aitmproxy-m5-l4-packet-mitm-design.md`)
  lists in-path interception as a non-goal and **Open Question 5**: "in-path
  L4 interception in M5, or deferred?", recommended default deferral. It names
  "TPROXY (Linux) / `pf` divert (macOS) / nfqueue" as the options. **This note's
  evidence says the macOS `pf` divert option does not exist on this host.**
- 08 (3.5, 3.7) already established the seam is stream-shaped
  (`ProtocolModule::spawn(ByteStream)`), `Flow` has no packet variant, and the
  workspace sets `unsafe_code = "forbid"`.

## 4. Candidate directions (for the Architect, not decisions)

**Candidate A: Linux-only NFQUEUE interception on the published `nfq` 0.2.5.**
Safe API, no `unsafe` in our crate, `Message` is parkable. Costs: 2022 release
with `unsafe` inside; no `AsRawFd`, so integration is a dedicated thread that
owns the `Queue` (blocking `recv`, or `set_nonblocking` with a short sleep) and
takes verdicts over a channel because `verdict` needs `&mut Queue`. Parking,
deadlines, and default verdicts are ours.

**Candidate B: same, on `nfq` git `master` or `nfq-updated` 0.2.6.** Exposes the
fd (so `AsyncFd` or `poll` can multiplex verdicts and receives), fewer `unsafe`
blocks, `rustix`. Costs: a git pin or an unexplained single-maintainer fork;
`edition 2024` and `rust-version` 1.85 (the workspace is 1.97 per 08, fine);
whether `nfq-updated` equals `master` is unverified.

**Candidate C: hand-built netlink queue client** on `netlink-packet-netfilter`.
Maximum control; but no queue module was seen, and we would own message
encoding. Likely only worth it if A and B both fail review.

**Candidate D: C-library bindings** (`nfqueue` 0.9.1, 2017). Evidence points
against: abandoned, links a GPL-2.0 C library, `unsafe` in the dependency chain
with no maintainer.

**Candidate E: TPROXY / `pf rdr` as the stream-shaped complement.** Fits the
existing `ByteStream` seam with no raw packets; works on both OSes (pf
unsupported by Apple). Does not satisfy "mutate a live packet", only "mutate a
live stream". Could ship independently of A to D.

**Candidate F: macOS, three non-exclusive options.**
1. *Document as unsupported for packet-level interception* and offer E plus
   capture-only L4 (08) there. Cheapest, matches the evidence.
2. *Signed system extension with `NEFilterPacketProvider`* for park-and-release
   (no edit unless the `NEPacket` turns out editable). Adds an app bundle,
   Swift code, a restricted entitlement, notarization, user approval, and a
   privileged IPC peer; belongs in `apps/mac` territory, not a CLI crate.
3. *`NETransparentProxyProvider` / App Proxy* for flow-level interception on
   macOS (Apple's and mitmproxy's route).

**Candidate G: who installs the kernel rule.** Operator-installed (documented
`nft` snippet; aitmproxy only binds the queue, still `CAP_NET_ADMIN`) versus
aitmproxy-installed (via the `nftables` crate or by shelling to `nft`; makes
the proxy a firewall mutator, which 08 flagged as a scope and authorization
question). A rule-in-place replace, not a table rebuild, is the evidence-backed
update method (3.6).

**Candidate H: privilege separation** (08 F): a small root/`CAP_NET_ADMIN`
helper owns the queue and rule, the main process is unprivileged and talks to it
over IPC; the helper enforces scope and the parked-packet deadline. Matches the
Wireshark `dumpcap` precedent already cited in 08.

## 5. Implications for aitmproxy

- **Linux-first is what the evidence supports; "cross-platform packet-level
  in-path" is not available.** NFQUEUE has no macOS counterpart: pf lacks
  divert on this host, ipfw is gone, and Apple's packet provider is
  allow/drop/delay. macOS can reach flow-level interception (E, F3) but not
  packet-level mutate. That is a candidate reading for the Architect to weigh
  against Open Question 5.
- **`forbid(unsafe_code)` can stay intact for Linux** because the crates in
  A and B expose safe APIs; the `unsafe` sits in a dependency. The
  Security reviewer should still review it, because WORKFLOW.md requires a
  signed-off entry for `unsafe`, and 08 already treats a dependency's `unsafe`
  as acceptable.
- **The seam question from 08 recurs.** NFQUEUE yields packets, not a
  `ByteStream`; the spec must either add an entry path beside `ProtocolModule`
  or accept that this mode is a separate packet-flow type. Not decided here.
- **The parked-packet contract must be specified, not inherited**: per-packet
  deadline, default verdict on expiry and on crash (fail-open versus
  fail-closed), maximum parked count below the kernel queue length, `bypass`
  setting, and a note to the operator never to rebuild the table (3.6).
- **Kernel rule plus userspace guard.** Two layers: an operator-supplied or
  generated `nft queue` rule scoped by CIDR, port, and interface, and a
  per-packet guard check before any verdict that mutates. The existing guard is
  host-string shaped (08, 3.7) and would need CIDR and interface notions.
- **Mutation needs a fixup step**: length and checksum recomputation, with the
  kernel rejecting or dropping malformed rewrites, and the kernel's rewrite
  checks may tighten further (3.1). Plan per-kernel tests.
- **Capability detection:** a command that reports `CAP_NET_ADMIN`
  present/absent, the queue bound, and whether the rule exists would extend the
  "degraded mode" report 08 already implies (inference).
- **Authorization:** in-path interception can drop or alter live traffic of
  the target and, if fail-closed, interrupt it. That raises the blast radius
  beyond 08's L4 send. Whether it needs a recorded authorization, a dry-run
  mode, or both is a policy call, not research.

## 6. Open questions

1. **Kernel payload-mangle policy by release.** Which stable kernels carry the
   non-initial-userns `-EPERM` and the v3 header validation / bridge rejection?
   The mailing-list page shows no review replies while a raw-file read of
   `master` describes the same checks.
2. **`nfq` `master` versus `nfq-updated` 0.2.6:** identical? Is `AsFd` in the
   fork? Will upstream publish to crates.io?
3. **`nfq` 0.2.5 `unsafe` audit** (count, soundness of `&'static mut` payload
   pointing into an `Arc` buffer, `unsafe impl Send/Sync for Message`).
4. **Can the `NEPacket` passed to `NEFilterPacketProvider.allow(_:)` be edited,
   or replaced?** Not stated on any page read. Does a packet provider receive
   packets in both directions on `lo0`? Which `NEFilterSettings` rules scope a
   packet provider?
5. **macOS system-extension approval flow and entitlement grant:** user
   approval step in System Settings, the `com.apple.developer.system-extension.install`
   entitlement, and whether Apple must approve the Network Extension entitlement
   for Developer ID were not on the pages read (general knowledge only).
6. **macOS 26 versus this host (macOS 27.0, build 26A428):** the local pf checks
   were run on 27.0. Re-run `pfctl -n -f` on a 26.x machine; also check
   `/usr/include/net/pfvar.h` in an installed SDK.
7. **xnu `in_proto.c` and `pfvar.h`:** only the visible part of each GitHub page
   was searched; confirm there is no divert socket or action elsewhere.
8. **Does `nft` rule-in-place replace (as opposed to table delete) keep parked
   packets on every kernel?** Issue #402 shows it on v6.18 only, through the
   reporter's analysis.
9. **TCP behaviour when a segment is parked** (retransmissions entering the
   queue, interaction with conntrack sequence adjustment on length-changing
   edits): no source read; a good **experiment** candidate.
10. **`CAP_NET_ADMIN` via systemd ambient capabilities or `setcap`** for the
    binary: not read (08 left the same gap).
11. **Linux bridge deployments:** if the target sits behind an L2 bridge, does
    queueing at IPv4/IPv6 hooks via `br_netfilter` work end to end? Only a
    search summary of a patch thread says so.
12. **Re-verify registry and kernel data** with `cargo info`, `cargo doc`,
    and a test on the target kernel (see provenance).

## 7. Sources

All read 2026-10-28 unless noted. "(S)" = search-result summary only, not the
page itself.

- crates.io API (via WebFetch): `nfq`, `nfq-updated`, `nf-queue`,
  `netlink-packet-netfilter`, `nftables`, `rustables`, plus search listings for
  `nfqueue` and `netfilter_queue`. https://crates.io/api/v1/crates/{name}
- docs.rs: `nfq` (crate root, `Queue`, `Message`, `Verdict`; source of 0.2.5
  `Cargo.toml` and `src/lib.rs`), `netlink-packet-netfilter`.
- GitHub: nbdd0121/nfq-rs (repo API, README, `master` `Cargo.toml` and
  `src/lib.rs`, commits API), dilluti0n/nfq-rs, oremanj/python-netfilterqueue
  (README), basil00/WinDivert wiki "WinDivert Documentation",
  kubernetes-sigs/kube-network-policies issue 402,
  apple-oss-distributions/xnu (`bsd/netinet/in.h`, `in_proto.c`, `ip_input.c`,
  `bsd/net/pfvar.h`; `bsd/netinet` listing and `ip_divert.c` 404),
  torvalds/linux (`net/netfilter/nfnetlink.c`, `nfnetlink_queue.c`, `nf_queue.c`
  via GitHub raw and blob views; kernel.org and Bootlin returned 403 or
  navigation-only pages).
- Netfilter: netfilter.org libnetfilter_queue project page and doxygen main page
  (v1.0.5) and `group__Queue` page; man7.org `iptables-extensions(8)`
  (NFQUEUE, TPROXY); wiki.nftables.org "Queueing to userspace" and "Quick
  reference-nftables in 10 minutes"; docs.kernel.org `networking/tproxy`.
- Linux man pages: man7.org `capabilities(7)`.
- Mailing lists: ratatoskr.run archive of netfilter-devel and netdev:
  "[RFC] netfilter: disable payload mangling in userns" (May 2026), "[PATCH net
  00/10] netfilter: updates for net" (2026-05-22), "[PATCH v3 nf-next 0/3]
  netfilter: add restrictions/validations for packet rewrite" (2026-06-09).
  Search summaries for the bridge and `br_netfilter` remarks (S).
- Suricata: docs.suricata.io `ips/setting-up-ipsinline-for-linux`,
  `configuration/suricata-yaml` (nfq section); fail-open details (S).
- Scapy: scapy.readthedocs.io `api/scapy.sendrecv` (`bridge_and_sniff`).
- mitmproxy: docs.mitmproxy.org `howto/transparent`; mitmproxy.org posts
  "Intercepting macOS Applications" and "Intercepting Linux Applications";
  modes page summary (S).
- Apple: developer.apple.com forums threads 767780, 87484, 799252, 741544,
  800887, 737894, 795579, 707294; JSON endpoints for
  `networkextension/nefilterpacketprovider`, `technotes/tn3134-network-extension-provider-deployment`,
  `technotes/tn3165-packet-filter-is-not-api`,
  `systemextensions/installing-system-extensions-and-drivers`; WWDC25 session
  234 transcript. Title-only or JavaScript-shell pages (documentation HTML for
  `nefilterpacketprovider`, TN3120, TN3134, the `networkextension` entitlement
  page) yielded no usable text.
- OpenBSD and FreeBSD divert: man.openbsd.org `divert(4)`, `pf.conf(5)`,
  FreeBSD forum thread on pf `divert-to` (S).
- macOS utun: Apple forums thread 758461, `gin66/mac_utun` README (S).
- ipfw removal: codemancers/invoker issue 79, WaterRoof page, Wikipedia "PF
  (firewall)" (S).
- Local first-hand checks on the author's Mac (2026-10-28, read-only):
  `sw_vers`, `uname -a`, `ls /sbin/ipfw /sbin/pfctl`, `man pf.conf | grep`,
  `sysctl -a | grep -i divert`, `pfctl -n -f <file>` parse-only on three
  one-line rulesets in `$TMPDIR`.
- aitmproxy tree: `docs/research/08-l4-packet-rust.md`,
  `docs/superpowers/specs/2026-10-27-aitmproxy-m5-l4-packet-mitm-design.md`
  (non-goals; Open Question 5), `docs/superpowers/WORKFLOW.md`.
