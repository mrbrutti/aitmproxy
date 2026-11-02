# Experiment: T5 packet lane, real-traffic live proof (Linux and macOS)

**Date:** 2026-11-01
**Branch:** n/a: a proof record for the merged lane (PR #231) and the live-proof PR; nothing here is throwaway code
**Session:** the T5 live-proof session (worktree `t5-live-proof`, branch `worktree-t5-live-proof`)
**Rig:** Lima VM `cis-lab` (Ubuntu 24.04 aarch64, kernel 6.8, cargo 1.99.1, passwordless sudo, `tcpdump`, python 3.12). The Mac home is not mounted; the worktree is synced with `tar | limactl shell cis-lab -- tar -x` into `~/aitm-src`.

## Question

Does the merged packet lane (`aitm-scan-l4-packet`, PR #231), over the real `send_recv` of `aitm-proto-l4`, classify real kernel reactions (TCP RST, ICMP port unreachable, a correlated UDP echo) and find the real userland crash on a real loopback, on Linux and on macOS, with raw-socket privilege obtained the product's way and nothing installed on Matt's Mac?

Until this run the lane had only ever been exercised against `MockBackend`. The T5 plan's Live-proof section recorded SKIP 77 on the Mac (`/dev/bpf*` is root-only there) and nothing on Linux.

## Setup

- **Privilege on the rig** is given only by file capabilities on the built test binary or core: `sudo setcap cap_net_raw,cap_net_admin+ep <binary>` (`CAP_NET_ADMIN` for pcap's promiscuous open). Cargo never runs as root. A rebuild drops the caps, so `setcap` is re-run after every build and the test binary is executed directly (cargo would relink it). Driver: `scripts/t5-live-proof-linux.sh` (modes `lane`, `cells`, `all`).
- **Independent observer:** `sudo tcpdump -i lo -nn -U -w <pcap>` with the filter `'icmp or udp or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)'`, so no TCP payload frame is ever recorded (a loopback capture with payload holds the bus's plaintext token line; lesson of PR #205). The pcap files stay in the VM; only text excerpts leave it, under `/tmp/claude/t5-proof-linux/` on the Mac.
- **Privilege on macOS:** only the product's own `aitm-l4-helper bpf-permissions` through the app's SMAppService registration, after Matt's explicit yes relayed by the coordinator. No ChmodBPF, no `sudo`, no manual `chmod` on `/dev/bpf*`. Driver: `scripts/t5-live-proof-macos.sh` (`record`, `verify`, `cells`, `restore-doc`, `all`; never escalates; exits 77 when the helper or the privilege is absent).
- **Skipped:** no fixtures, no synthetic captures, no mock counts. The lane-level tests are `crates/aitm-scan-l4-packet/tests/live_loopback.rs` (`#[ignore]`, `AITM_L4_TESTS=1`). The real-bus cells (`tests/e2e/scan/test_t5_*.py`) need PR #232's engine on `main` and are covered in Result (iv).

## Result

### (i) The capture sees the stimulus itself: the first run looked alive and was not

**Run 1** (rig, `main` at v0.5.10 plus the lane, before any fix; `/tmp/claude/t5-proof-linux/live-loopback-run1.log`):

```
test live_closed_tcp_port_yields_reset ... reaction: Clean | 20 cases sent on 127.0.0.1:40169/tcp field raw; no protocol reaction
counters: Some(L4Counters { cases: 20, crashes: 0, liveness_failures: 0, retired_elements: 0 })
  left: Clean
 right: Vulnerable
FAILED
test live_closed_udp_port_yields_icmp_3_3 ... reaction: Clean | 20 cases sent on 127.0.0.1:36709/udp field raw; no protocol reaction
FAILED
test live_udp_echo_hundred_clean ... crash: Clean | ... reaction: Clean | 100 cases ... no protocol reaction
ok
test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 4 filtered out; finished in 9.96s
```

The closed ports drew no reaction and the echo test passed only because its verdicts are `Clean` either way. `tcpdump` on the closed-UDP point (`/tmp/claude/t5-proof-linux/closed-udp-run1.txt`) shows 21 frames, every one of them ours (`127.0.0.1.40000 > 127.0.0.1.48446: UDP`), and not one ICMP frame:

```
18:42:50.981184 ... 127.0.0.1.40000 > 127.0.0.1.48446: UDP, length 16
18:42:51.047172 ... 127.0.0.1.40000 > 127.0.0.1.48446: UDP, length 17
...
18:42:52.313208 ... 127.0.0.1.40000 > 127.0.0.1.48446: UDP, length 16
```

Root cause (Finding 1, plan Task 1): libpcap on Linux `lo` delivers the injected frame back to the capture that `send_recv` opens before it injects (macOS BPF sees sent frames the same way), and `Correlation::classify` under `ReplyMatch::FiveTuple` classified it `Other` (same host, same protocol, wrong port), ending every case before any real reply could arrive. The liveness probes "passed" on their own echo. Fixed in commit `19108a50` (`is_own_stimulus`: byte-equality or same-direction tuple, asked first in every match mode); `MockBackend` now echoes the stimulus first by default so every unit test runs over a self-echoing wire.

### (ii) Linux `lo` never processes a frame injected at layer 2

**Run 2** (rig, with the self-echo fix; `/tmp/claude/t5-proof-linux/run2-console.txt`): with the echo ignored, no case ever saw a reply and the lane hit its deadline before the first case:

```
test live_closed_tcp_port_yields_reset ... reaction: Error | the packet lane stopped before any case on 127.0.0.1:41649/tcp field raw: job deadline passed
counters: Some(L4Counters { cases: 0, ... })
classes: []
FRAMES=30
ICMP_FRAMES=0
```

The frames on the wire were well-formed (`/tmp/claude/t5-proof-linux/run2-checksums.txt`: `tcpdump -vv` prints `cksum 0xa1bf (correct)` for the SYN, `[udp sum ok]` for the datagrams, and `grep -c incorrect` over the whole pcap prints `0`), so craft was not the cause. A root probe (`/tmp/claude/t5-inject-probe.py`, output `/tmp/claude/t5-proof-linux/inject-probe.txt`) sent the same UDP datagram to a listener two ways:

```
listener 127.0.0.1:39945
L2 inject (AF_PACKET on lo, Ethernet header): NOT delivered to the UDP socket within 1 s
L3 inject (SOCK_RAW IP_HDRINCL): DELIVERED b'probe-L3' from ('127.0.0.1', 40000)
L2 to closed port: no ICMP within 1 s
L3 to closed port: ICMP type=3 code=3
```

Finding 3: on Linux loopback a frame written through `AF_PACKET` (the path `PcapBackend::inject` → `pcap::Capture::sendpacket` takes) is seen by `tcpdump` but never enters the IP stack; a layer-3 raw socket with `IP_HDRINCL` is processed normally. This is the loopback behaviour scapy documents and works around with `L3RawSocket`. Every `l4.inject` and `l4.send_recv` on Linux loopback was therefore inert before this PR. Fix: `PcapBackend::inject` strips the link header and writes through `AF_INET`/`AF_INET6` `SOCK_RAW` with the header included when the device is Linux loopback; pcap `sendpacket` stays for real NICs and macOS `lo0` (DLT_NULL framing). Commit `88d35aea` (coordinator amendment 49): the loopback decision uses libpcap's `IFF_LOOPBACK` flag rather than the name, the destination is read from the frame's own IP header, the raw socket lives only inside the call, and the root probe is now the Linux-only ignored test `linux_loopback_inject_reaches_the_ip_stack`. Run on the rig at `88d35aea` with `cap_net_raw,cap_net_admin+ep` on `target/debug/deps/aitm_proto_l4-2eb4db62711b289a` (`/tmp/claude/t5-proof-linux/run3-proto-live-console.txt`, rig `~/t5-proof/proto-live-20261101T194427Z/proto-live.log`):

```
test backend::pcap::tests::linux_loopback_inject_reaches_the_ip_stack ... ok
```

The listener received the injected datagram and the closed port answered ICMP type 3 code 3 through `PcapBackend::inject` itself, the same probe that failed at layer 2 in (ii). `tcpdump` alongside: `127.0.0.1.40000 > 127.0.0.1.45817: UDP, length 8` twice, then `ICMP 127.0.0.1 udp port 45817 unreachable`. (The run was stopped afterwards because the pre-existing ignored `capture::tests::capture_excludes_out_of_scope` hangs under `--ignored` on the rig; it is unrelated to this change and is listed as a follow-up for the `aitm-proto-l4` owner.)

**What the layer-3 path costs the fuzzer.** With `IP_HDRINCL`, Linux `raw_send_hdrinc` (net/ipv4/raw.c, v6.8) unconditionally rewrites `iph->tot_len` to the real length and recomputes `iph->check`, and fills `iph->id` / `iph->saddr` only when they are zero. So on Linux loopback a mutation of `ipv4.total_length` or `ipv4.checksum` never reaches the receiving stack (the kernel repairs it on the way out), while every other IPv4 field, the whole IPv6 header and everything above IP are delivered verbatim. The injector therefore does not police lengths itself (a refusal would turn a legitimate fuzz case into a `WireWrite` job stop); it only requires Ethernet framing whose ethertype matches the IP version and a full fixed header, and it cross-checks the destination it reads against the guard's own parse of the same frame (tester finding F1, two rounds), refusing a frame that parser cannot decode. After the stage-6 panel (commit `ef2d1ce3`) the raw socket is also bound to the named device (`SO_BINDTODEVICE`), and a missing `CAP_NET_RAW` is reported as the typed `Unavailable` like every other inject path. Rig run 4 then showed that a bound socket does not *refuse* an off-host destination: the kernel emitted `127.0.0.1.40000 > 10.255.255.254.59518: UDP` on `lo`, where it died (`/tmp/claude/t5-proof-linux/run4-proto-live-console.txt`). Confinement to the device held but was not observable, so commit `60b8ab9f` refuses any non-loopback destination on the layer-3 path before a socket is opened (`WireWrite("linux loopback inject: destination is not a loopback address")`); the packet lane only ever targets loopback, and the binding stays as defence in depth. IPv6 is sent verbatim by `rawv6_send_hdrinc` (the kernel-owned fields are IPv4's); `IPV6_HDRINCL` needs Linux ≥ 4.5 and only `::1` is live-tested. A second kernel effect on the self-echo rule: the kernel fills a zero IPv4 id and recomputes the checksum, so a portless (ICMP) stimulus's own RX copy is no longer byte-equal to the stimulus; `send_recv` now compares the transport slice for the same-host portless case (`a25bd093`). Real NICs and macOS `lo0` keep `sendpacket`, where the kernel touches nothing.

### (iii) Lane-level counters on the rig at the fixed head (Task 2, run 3)

**Run 3** (`scripts/t5-live-proof-linux.sh lane`; rig evidence `~/t5-proof/20261101T194235Z/{summary.txt,lane.log}`, copied as text to `/tmp/claude/t5-proof-linux/run3-summary.txt`, `run3-lane.log` and `run3-console.txt`). Header of the summary:

```
source commit (.synced-sha): 88d35aeae1806b6671b9bfeb6774e7ad2e06a67b+dirty
kernel: Linux lima-cis-lab 6.8.0-134-generic ... aarch64
capture filter: icmp or udp or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)
  net.ipv4.icmp_ratelimit = 1000
  net.ipv4.icmp_ratemask = 6168
  net.ipv4.icmp_msgs_per_sec = 1000
  net.ipv4.icmp_msgs_burst = 50
getcap: .../target/debug/deps/live_loopback-c89e705b2fd94dba cap_net_admin,cap_net_raw=ep
```

(`+dirty` is this write-up, untracked at sync time; every source file matched `88d35aea`.) The three ignored tests, with `tcpdump` watching `lo`:

```
test live_closed_tcp_port_yields_reset ... reaction: Vulnerable | l4 reactions on 127.0.0.1:38715/tcp field raw: reset x 20; latency outliers 0
crash: Clean | 20 cases sent on 127.0.0.1:38715/tcp field raw; no crash
counters: Some(L4Counters { cases: 20, crashes: 0, liveness_failures: 0, retired_elements: 0 })
classes: [("reset", 20)]
test live_closed_udp_port_yields_icmp_3_3 ... reaction: Vulnerable | l4 reactions on 127.0.0.1:40104/udp field raw: icmp(3,3) x 20; latency outliers 0
crash: Clean | 20 cases sent on 127.0.0.1:40104/udp field raw; no crash
counters: Some(L4Counters { cases: 20, crashes: 0, liveness_failures: 0, retired_elements: 0 })
classes: [("icmp(3,3)", 20)]
closed udp port: 20 of 20 cases drew icmp(3,3), 0 were silent, 0 were noted no_reply (icmp_ratelimit); paced at 1.1s, elapsed 22.207001323s; baseline Some(Icmp { icmp_type: 3, code: 3 })
test live_udp_echo_hundred_clean ... crash: Clean | 100 cases sent on 127.0.0.1:51816/udp field raw; no crash
reaction: Clean | 100 cases sent on 127.0.0.1:51816/udp field raw; no protocol reaction
counters: Some(L4Counters { cases: 100, crashes: 0, liveness_failures: 0, retired_elements: 0 })
classes: [("clean", 100)]
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 32.93s
```

What the independent witness saw (`run3-summary.txt`): 439 frames, 126 ICMP, 231 UDP, 41 RST. The RSTs come from the closed TCP port to our source port (`127.0.0.1.38715 > 127.0.0.1.40000: Flags [R.]`). The ICMP for the closed UDP port arrives once per case, `tcpdump -ttt` deltas of 1.10 to 1.11 s, exactly the pace:

```
00:00:00.000000 IP 127.0.0.1 > 127.0.0.1: ICMP 127.0.0.1 udp port 40104 unreachable, length 52
00:00:01.106158 IP 127.0.0.1 > 127.0.0.1: ICMP 127.0.0.1 udp port 40104 unreachable, length 53
00:00:01.101587 IP 127.0.0.1 > 127.0.0.1: ICMP 127.0.0.1 udp port 40104 unreachable, length 54
...
```

Datagram counts by destination port: 105 to the echo service (`51816`, 100 cases + 1 baseline + 4 scheduled probes) and 105 back to our source port `40000`, plus 21 to the closed port `40104` (20 cases + the baseline). The echo replies to our crafted source port have no socket behind them, so the kernel answers each with its own ICMP port unreachable: 105 of them, unpaced, at 73 to 126 ms spacing. **That is the honest ICMP rate-limit observation: on loopback the kernel did not rate-limit per destination at all** (105 ICMP errors in about 8 s to one address, `icmp_ratelimit = 1000`). The plan's fact 3 ("about one per second") was an inference from the sysctls that this run does not support for `lo`; it is the kernel's documented exemption: `net/ipv4/icmp.c` `icmpv4_xrlim_allow` (v6.8) reads `/* No rate limit on loopback */ if (dst->dev && (dst->dev->flags&IFF_LOOPBACK)) goto out;` before the per-peer check. The pace therefore proved its mechanics (20 of 20 classified, spacing on the wire equal to the configured pace, zero `no_reply` notes), not the limit it exists for; that limit applies to a remote target, which is what the lane fuzzes in practice.

**Final-head confirmation (runs 5 and 6; run 6 at `c4a4d610`, `/tmp/claude/t5-proof-linux/run6-{summary.txt,lane.log,proto-live-console.txt}`, rig `~/t5-proof/20261101T213044Z/`):** after the stage-6 fix rounds the same three tests pass with the same histograms (`reset x 20`, `icmp(3,3) x 20` at 22.14 s, `clean x 100`), tcpdump 439 frames with **105 datagrams each way** on the echo port (run 4's 102 was the capture missing the last three exchanges; the driver now waits before stopping tcpdump), and `linux_loopback_inject_reaches_the_ip_stack ... ok` including the refusal of a non-loopback destination.

### (iv) The ICMP rate limit and amendment 46 (ICMP-paced points)

Linux rate-limits ICMP errors per destination (`net.ipv4.icmp_ratelimit = 1000` ms, `net.ipv4.icmp_ratemask = 6168` includes destination-unreachable, `icmp_msgs_per_sec = 1000`, `icmp_msgs_burst = 50` as read on the rig). Before run 3 the plan inferred from those sysctls (fact 3) that twenty rapid stimuli to a closed UDP port would draw a burst and then about one ICMP per second, the rest reading `Silence`, so that an unpaced liveness rule could call a closed port a crashed service. Umbrella amendment 46 (decided by the coordinator for Matt on that inference) adds `L4Options.icmp_pace_ms` (default 1100, floor 1000) and a per-point pace in `PointRunner` for points whose baseline is an ICMP error; a silent case on such a point is recorded `no_reply (icmp_ratelimit)` and can never yield `l4-crash`. Implemented in commits `93a9109d` (lane and model) and `9bf6822b` (spec D2/D8.4/D11, amendment-log row 46); the unit pair `paced_closed_port_classifies_every_case` / `unpaced_closed_port_on_a_ratelimiting_host_reads_silence` fails when the pace and the guard are removed (mutation check in the coder's report).

**What run 3 showed about the inference (section iii):** the kernel does not apply the per-peer limit on loopback at all (`icmpv4_xrlim_allow`, "No rate limit on loopback"; 105 unpaced ICMP errors in about 8 s to one address), so there is no before/after histogram to show from `lo`: an unpaced closed-UDP run on loopback would also classify 20 of 20. The rate limit, and therefore the pace, is real for a remote target, which is what the lane fuzzes in practice; the coordinator is amending 46's wording to say so. The rig proved the pace's mechanics: 20 of 20 classified, wire spacing equal to the configured pace, zero `no_reply` notes, zero liveness probes spent.

### (v) Real-bus cells on the rig (Task 4b, follow-up PR off main 7f942f9f)

**Result:** all three T5 cells PASS on the rig through the real engine (`run.py scan`, real `aitm` core with file caps, real `aitm-testtarget-serve`, `tcpdump` witness), both in the runner and each alone on a quiet `lo`, at the final code head `4bcd6c6f` (run 16, 2026-11-02 09:54 UTC, rig `~/t5-proof/20261102T095438Z/`, Mac copies `/tmp/claude/t5-proof-linux/cells-run16-{summary.txt,scan.log,t5-lines.txt,test_t5_*.log}`), after passing in the runner at `ef950434` (run 11), `c5c96d1e` (run 12), `346a1156` (run 13), `c8180905` (run 14) and `e9ff8566` (run 15, direct leg too):

```
  PASS  scan/test_t5_bounded_clean.py  (5.9s)
  PASS  scan/test_t5_pins_dryrun.py  (0.8s)
  PASS  scan/test_t5_crash_oracle.py  (41.7s)
e2e summary: 29 pass, 6 skip, 3 fail
  ledger: 18/18 scan verbs called by at least one cell
direct test_t5_bounded_clean exit: 0 (19 ok lines, 0 FAIL lines)
direct test_t5_pins_dryrun exit: 0 (14 ok lines, 0 FAIL lines)
direct test_t5_crash_oracle exit: 0 (34 ok lines, 0 FAIL lines)
```

The three FAILs in the runner leg are other tracks' cells (`test_t1_contract`, `test_t3_h2_observe`, `test_t2_session_reuse`, unchanged since run 14; not verified on plain main, reported to the coordinator). The independent witness on the closed-UDP oracle job and on the job-derived source ports:

```
ICMP port-unreachable lines by quoted port:
      105 udp port 29166 unreachable      <- the kernel answering the echo replies to a job's socketless source port
      105 udp port 23733 unreachable      <- the other echo job's (both ports are in the 16384..32768 window of amendment 73 b)
       11 udp port 43449 unreachable      <- the closed-UDP oracle job: 10 cases + 1 baseline
closed-UDP oracle reactions (quoted port 43449; +gap to the previous reaction of this port):
  +0.000s ... ICMP 127.0.0.1 udp port 43449 unreachable, length 52
  +1.108s ... length 53
  +1.103s ... length 54
  +1.106s ... length 68
  +1.107s ... length 100
  +1.100s ... length 292
  +1.103s ... length 556
  +1.105s ... length 556
  +1.105s ... length 53
  +1.112s ... length 54
  +1.097s ... length 68
```

Ledger (spec D3, from the runner): the T5 cells exercised `scan.start`, `scan.status` and `scan.checks` (all three), and `scan.issues` + `scan.issue` (`test_t5_crash_oracle`), all at the operator role. `tcpdump` on `lo` for the whole surface (run 16, the surface now holding the T2/T4/T6 cells too): 67 674 frames, 226 ICMP, 2 125 UDP, 805 RST; 106 datagrams to each of the two echo targets (bounded-clean and the P job: 100 cases + 1 baseline + 4 scheduled probes + one liveness probe for a case the loaded rig read as silent; run 11 saw the same 106/106), 11 ICMP reactions quoting the closed UDP port (10 cases + baseline), 105 kernel port-unreachables for each echo job's replies to its socketless derived source port.

What the cells proved. The runner prints a cell's own lines only when it fails, so the per-assertion detail below comes from run 10 (`cells-run10-scan.log`, the run in which `test_t5_crash_oracle` still failed on `location.l4` and printed every line, and `test_t5_bounded_clean` on the frame count), from the lane's traced trail of that run (`cells-run10-vjob-trail.txt`), and, for the passing cells, from run 16's direct per-cell logs (`cells-run16-test_t5_*.log`, each cell run once more on its own with stdout kept):

- `test_t5_bounded_clean`: `scan.start` → job `done`, `lanes.run == ["l4_packet"]`, `points: found 1, audited 1`, `checks: scheduled 2, done 2`, `status.l4 = { cases: 100, crashes: 0, liveness_failures: 0, retired_elements: 0 }`, zero issues; the operator's own `l4.capture` (inbound) holds every frame to the pinned port with `dst 127.0.0.1`; the patched target logged no downtime.
- `test_t5_pins_dryrun`: `scan.start` with `fields: ["ipv4.src"]` and with `["dst"]` refused synchronously with `scan: invalid_profile: field path "ipv4.src" is pinned and cannot be fuzzed` (no job created); a dry run reports `dry_run: true`, finishes `done`, sends nothing (`status.l4.cases == 0`, no frame on the capture).
- `test_t5_crash_oracle`: (a) the closed UDP port job (`raw`, 10 cases) ends with `classes={"icmp(3,3)": 10}`, one `l4-protocol-reaction` Info issue whose oracle is `{"kind": "icmp", "type": 3, "code": 3}`; the closed TCP port job (`tcp.flags`) with `classes={"reset": 8, "silence": 2}` and oracle `{"kind": "reset"}`; neither invents an `l4-crash`. (b) the V job (100 cases, `reproduce_count: 3`) against the Vulnerable `l4-udp-payload-crash`: the traced trail reads `candidate case index=1 class=silence` → `liveness pair first=false second=false` → `triage replay sent round=1 waited_for_recovery=true waited_ms=3282 class=silence` → `judged ... reproduced=1` → rounds 2 and 3 the same (`waited_ms=3513`, `3601`) → `triage finished attempts=3 reproduced=3 recovered=true` → `crash decision crashed=true` → `point run finished sent_cases=2 cases=2 ... crash=true`; `status.l4 = { cases: 5, crashes: 1, liveness_failures: 14, retired_elements: 1 }`; exactly one `l4-crash` issue, `critical`/`firm`, `evidence.l4 = { oracle: { kind: liveness_failed }, reproduced: [3, 3], mutation_chain: ["grow:8"], liveness_before: true, liveness_after: false, seed_id: "127.0.0.1:<port>/udp#0" }`, `sent_hex` ending `deadbeef00000000` (the T10 trigger); the target's downtime log shows four 5 s windows (the find and the three replays), each replay sent only after a recovery probe passed; after retirement the trigger was never sent again; `location.l4` names the fuzzed `udp` endpoint (run 11). (c) the P job against the patched target: zero issues, no downtime.

**What it took.** The cells had never run against a real engine before (PR #232 landed after the lane). Eleven rig runs peeled: two cell defects (no profile `name`; no `intensity: intrusive`, so the scheduler, which skips a check above the profile's intensity, scheduled none of the lane's intrusive checks); one lane gap (`PacketLane::validate` was never implemented, so a pinned field was refused only inside discovery in the worker, not at `scan.start`); a harness reader bug (`l4.flow.get` sets `truncated` only when the reply's byte budget cuts a page, so `read_capture_packets` stopped after one page of 500); and three lane bugs no mock or quiet-loopback test could see:

1. **Runner registry keyed by the engine's marker** (6581396a). `JobCtx::marker()` in the engine is a reflection-canary generator that returns a new token per call; the lane registered a point's runner under one call and looked it up under another, every lookup missed, the check returned an Error verdict the worker records nowhere, and every job finished `done` in ~1 s with zero cases and zero frames on the wire. Fixed by keying on `job_id()`; regression test with an engine-shaped fresh-marker job.
2. **Reply correlation on a busy loopback** (9387314e, amendment 66). Under `FiveTuple` any captured frame whose source host equalled the stimulus destination was accepted as `Other` when protocol or ports mismatched. On loopback every frame is from 127.0.0.1, so the e2e bus TCP, the target's HTTP control and other cells' UDP were read as the target's "protocol reaction" within ~100 ms: the V job's down-window cases classified `protocol_error` 35/100, never `silence`, and no candidate ever formed; even the never-down P job showed `protocol_error` 9/100. Now a reply is the reversed tuple with matching protocol; a reaction is only an ICMP error whose quoted inner packet is our stimulus (this also excludes the kernel's port-unreachables for the target's echo replies to our socketless source port) or a RST from the target port; everything else is ignored until the window ends. Baseline and liveness probes now correlate on the pinned tuple like replays (06168c6d).
3. **No site node per target** (ef950434): the engine places an L4 issue (`location.l4`) only from a `SiteNode` the lane returned; the lane returned none, so the confirmed crash reached the operator with an empty location.

4. **A blocking libpcap read never returns on a quiet interface** (e9ff8566 + 4bcd6c6f, umbrella amendment 77; pre-existing in `aitm-proto-l4`, found only when the cells ran one at a time). `PcapBackend::open_capture` trusted libpcap's read timeout to bound `next_frame`. On the rig (Linux 6.8, libpcap 1.10.4) a blocking `pcap_next_ex` on `lo` with a filter no frame matches does not return within 3 s in plain or immediate mode, while a non-blocking read reports `TimeoutExpired` in 4 µs (`quiet-stages.txt`). Every earlier run had either replies or three other cells' traffic on `lo`, so `await_reply` always got a frame to wake on and its deadline looked honoured; alone on the interface, the first silent case froze the check until the engine's 60 s timeout and `l4.capture.stop` froze on the thread join (run 14's direct leg: `cells-run14-test_t5_*.log`, `cells-run14-direct-*.txt`). The source now reads non-blocking and enforces the timeout itself (1 ms nap doubling to 20 ms between empty reads); the new live test `linux_quiet_interface_read_returns_within_the_timeout` was red at c8180905 and is green at the fix (`quiet-probe-red.txt`, `quiet-probe-green.txt`), and run 15's direct leg passed all three cells alone on a quiet `lo` (`cells-run15-test_t5_*.log`). The first variant of the fix (e9ff8566) also switched the handle to immediate mode, and run 15's runner leg caught what that costs: libpcap then maps a `TPACKET_V2` ring, one frame per `snaplen`-sized slot, about thirty 64 KiB slots in the 2 MiB default, and the three concurrent cells' traffic overran it during one reader nap, so the operator's capture recorded 103 of the 106 datagrams tcpdump saw (`cells-run15-scan.log:99`). The shipped variant (4bcd6c6f) keeps the packed `TPACKET_V3` ring and sets libpcap's timeout to a 10 ms block handover, the ceiling on the reply latency a case pays for it. An operator fuzzing a single target on a quiet machine, the normal case, would have hit the hang on the first silent case.

Diagnostics kept from the hunt: the lane logs its stop reasons, the triage trail and a per-run class histogram (`RUST_LOG=aitm::scanner::l4_packet=debug`); the harness keeps the core's workdir with `AITM_E2E_KEEP_WORKDIR=1`; the cells print the job's error, lanes, points and checks at the terminal status.

### (vi) macOS

Blocked on the product's privilege units. `aitm-l4-helper` phase 1 (unit p2: `bpf-permissions --dry-run`, `bpf-revert --dry-run`, `probe`, `version`) exists in its own PR; the notarized bundle that lets the app register it and trigger a real apply (units p3/p4) does not yet. On this Mac the three T5 cells are expected to SKIP 77 with exactly:

```
packet-capture permission not granted (aitm-l4-helper phase 1 pending)
```

The cells gate on `l4.privilege` (both `capabilities.capture` and `capabilities.inject` must be `state == "available"` with `via == "process"`) and fall back to `l4.capture.status` on a core without the verb. **State of this build:** the engine (PR #232) is in this tree, so on this Mac the cells reach `packet_lane_gate` and the literal above is what it prints for a core whose `l4.privilege` reports no `process` capture; that literal is pinned by the tester's direct probe of all eleven gate branches (`/tmp/claude/t5-tester/pygate.log`, stage 5 report of PR #264) and by `tests/e2e/aitm_e2e/scan.py`; a Mac run of the three cells from this tree has not been made (the Mac leg is blocked on the helper), so the exact line has not yet been observed from a cell on this Mac. Nothing was installed and no `/dev/bpf*` mode changed on Matt's Mac. State recorded read-only by `scripts/t5-live-proof-macos.sh record` at `19372ae4` (`/tmp/claude/t5-proof-mac/record-20261101T195150Z.txt`):

```
$ ls -l /dev/bpf0 /dev/bpf1
  crw-------  1 root  wheel  0x17000000 Nov  1 03:00 /dev/bpf0
  crw-------  1 root  wheel  0x17000001 Oct 30 03:23 /dev/bpf1
group access_bpf (absent is normal before the grant): Operation failed with error: eServerError
aitmproxy LaunchDaemons (absent is normal before the grant): (none)
receipt /Library/Application Support/Aitmproxy/l4-helper.json: absent
exit 77: aitm-l4-helper not present: Mac leg pending the notarized bundle (units p3/p4)
```

## Conclusion

**Linux: proven at lane level and through the real engine.** (Section (v): all three real-bus cells PASS at ef950434; the crash oracle found, reproduced three times and retired a real userland crash on the rig.) On a real kernel with real privilege the merged lane classifies real reactions exactly as designed: 20 of 20 RSTs from a closed TCP port, 20 of 20 ICMP port-unreachables from a closed UDP port, 100 of 100 clean correlated echoes, zero false crashes and zero liveness failures, with an independent `tcpdump` agreeing frame for frame. Getting there exposed two pre-existing Critical transport defects no mock could show (the capture reads its own stimulus; layer-2 injection is inert on Linux loopback) and corrected one assumption (loopback is exempt from the ICMP per-peer rate limit, so the pace is for remote targets).

**macOS:** blocked on the helper bundle; recorded as SKIP 77 with the exact reason above. The lane needs read+write on `/dev/bpf*` for the core process (`via: process`); nothing in the lane needs the system extension.

## Carry into the spec

- `send_recv` invariant (D8.4/D12): the capture ignores the stimulus's own direction (same src addr/port, dst addr/port, protocol) before any match; a mock backend echoes the stimulus first so unit tests keep the regression covered.
- Linux loopback injects at layer 3 (`SOCK_RAW` + `IP_HDRINCL`, `IPV6_HDRINCL` for v6), decided by libpcap's `IFF_LOOPBACK` flag; layer-2 `sendpacket` only for real NICs and macOS `lo0`. Spec D8.4 should state the Linux-loopback limitation: `ipv4.total_length` and `ipv4.checksum` mutations are repaired by the kernel on that path and cannot be fuzzed there; the injector requires Ethernet framing (ethertype ↔ version) and compares its destination with the guard's parse.
- Strict reply correlation (amendment 66): a reply is the reversed tuple with matching protocol; a reaction is only an ICMP error quoting our stimulus or a RST from the target port; anything else is ignored until the window ends; baseline and liveness probes correlate on the pinned tuple. The engine's `JobCtx::marker()` is fresh per call: a lane keys nothing on it (T1b follow-up 57). An L4 lane returns one `SiteNode` per target so the engine can place its issues.
- ICMP-paced points (amendment 46): `L4Options.icmp_pace_ms` default 1100, ceiling `l4_icmp_pace_ms_min: 1000`, `no_reply (icmp_ratelimit)` note, a closed port never yields `l4-crash`.
- Linux ICMP facts for D8.4: `icmp_ratelimit` 1000 ms per destination, `icmp_ratemask` 6168, `icmp_msgs_per_sec` 1000, `icmp_msgs_burst` 50 as read on the rig; loopback is exempt from the per-peer limit (kernel source and run 3), so the pace is for remote targets.
- Privilege spec: on macOS the lane needs read+write on `/dev/bpf*` in the core process (`via: process`); the Linux rig uses file capabilities (`cap_net_raw,cap_net_admin+ep`) on the binary, never a root cargo. Nothing in the lane needs the NE system extension.
