# Experiment: macOS NE observe-only survey (fields, rates, costs, UDP `false`)

**Date:** 2026-10-31 (Matt's Mac: macOS 27.0 build 26A428, Apple Silicon, Xcode 27.1 toolchain)
**Measured windows:** shipped v0.5.3 provider 08:49–13:27 PDT (framework log only, 4 h 38 min,
16 957 flows); logging variant 13:35–15:43 PDT (2 h 8 min, 15 846 declined flows with the full
field set), until the v0.5.4 release installed by another session replaced it. Together: one
Saturday working day of Matt's real use plus controlled bursts.
**Branch:** `experiment/macos-ne-observe-survey` (never merged; delete or leave untouched).
The session's worktree branch is `claude/cranky-vaughan-0e27b2`; the commits are pushed under
the experiment name. Base: `origin/main` at `341b68a` (PR #183).
**Session:** separate session with its own worktree, started by the observe-only-lane
research/spec session (PR #184).
**Inputs:** `docs/research/12-macos-observe-only-lane.md` §3.2, §5 items 6, 7, 8;
`docs/superpowers/specs/2026-10-31-macos-ne-observe-only-lane-design.md` Part 3, Part 4,
Open question 6.

## Question

Before the implementation plan sizes the provider-side queue (spec Part 3: 2 048 entries,
drop-oldest) and the core-side soft cap (spec Part 4: 5 000 `FlowSeen`/s), measure on a real
Mac for a working day:

1. **Field survey (research §5 item 6).** At `handleNewFlow` / `handleNewUDPFlow`, how often
   is `sourceAppAuditToken` nil, `remoteFlowEndpoint` nil or hostname-typed, `remoteHostname`
   set, `sourceAppSigningIdentifier` empty; what is the audit-token euid distribution.
2. **Rates and costs (item 7).** New flows per second sustained and in bursts; the per-flow
   cost of `SelfExclusion.isSelf` and of one `proc_pidpath_audittoken` call.
3. **UDP `return false` on macOS 27 (item 8).** Under the shipped catch-all `.any` rule, with
   the provider returning `false` for every UDP flow, do DNS, QUIC/HTTP3 (Safari, Chrome,
   Firefox) and Chromium UDP work normally (research §3.2.2 header inconsistency, §3.2.7
   DevForums thread 770707)?

## Setup

### What was built (throwaway)

`apps/mac/Extension/Sources/TransparentProxyProvider.swift` replaced by a logging-only
variant. Claiming is unchanged (same `SelfExclusion.isSelf`, same
`FlowHandoff.handleTCP/handleUDP`, same fail-open `false`). Added, for every flow the
provider **declines**, one `os_log` line (subsystem `com.mrbrutti.aitmproxy.ne`, category
`survey`, level default so it persists):

```
SURVEY k=T|U why=self|unclaimed ep=<ip:port | name:<port> | nil> hn=<-1 | len> sid=0|1
       tok=0|1|2 euid=N pid=N ffid=0|1 if=<iface> self_ns=N pp_ns=N pp_len=N claim_ns=N total_ns=N
```

`hn` is the `remoteHostname` UTF-8 length (text withheld), `pp_len` the byte count
`proc_pidpath_audittoken` returned (path withheld), `euid`/`pid` are `val[1]`/`val[5]` of the
audit token (what libbsm's `audit_token_to_euid/pid` return). The three `*_ns` fields are
`clock_gettime_nsec_np(CLOCK_UPTIME_RAW)` deltas around `isSelf`, one
`proc_pidpath_audittoken` call, and the claim call. A `SURVEY-RATE` line every 60 s carries
in-process counters (total, per-kind, busiest second) so a throttled log store cannot hide a
burst. No payload bytes, no `open()`, no hostname or path text. Skipped: tests, any change to
the app, any wire change.

Scripts (all throwaway) are in `spike/observe-survey/` on the branch: `build-install.sh`,
`udp-test.sh`, `udp-dontfrag.sh` / `dontfrag-core.py`, `capture-control.sh`, `gui-quic.sh`,
`apple-h3.swift` + `apple-h3.sh`, `burst-test.sh`, `survey-pull.sh`, `dump-framework-log.sh`,
`analyze.py`, `restore.sh` (unused, see R5). Test outputs and the three `analyze.py` reports
are in `spike/observe-survey/results/`. The raw per-flow logs (15 846 `SURVEY` lines, the
framework `New flow` lines) hold the remote endpoints of Matt's own traffic, so they stay out
of the repo, in the session group's notes folder (`observe-survey-raw/`), gzipped.

### A free second data source

The NetworkExtension framework itself logs, at default level in the `AitmproxyNE` process,
one `New flow: NEFlow type = stream|datagram, app = <signing id>, name = <hostname>, <local>
<-> <remote>, filter_id = <uuid>, interface = <if>` line plus `Calling handleNewFlow with …`
and `provider rejected new flow …` per flow. So the **shipped v0.5.3 provider's whole morning
was already measurable** with `log show --predicate 'process == "AitmproxyNE"'` before anything
was built. Those lines lack the audit-token facts and the timings, which is what the variant
added.

### Environment facts that shape the numbers

- Extensions active alongside ours: Little Snitch 6.5 network extension (a content filter)
  and endpoint-security extension; a UniFi `IdentityWireGuardProvider`. Little Snitch is why
  `filterFlowIdentifier` is set on most flows.
- All day the embedded core was **not listening** for the provider (no
  `/private/tmp/aitmproxy-capture.rendezvous`), so the provider was detached and declined
  every flow. Every "claim path" timing below is therefore the detached fast path
  (`link.current() == nil`). This also means the item-8 condition (every UDP flow declined)
  held for the shipped provider all morning.
- Builds and `log show` ran in the Terminal panel; the sandbox cannot build Swift, sign,
  notarize or read the unified log.

### Build, notarize, install (exact commands, `build-install.sh`)

```bash
# identity = the Developer ID both A1 profiles list (tools/ne-preflight.sh checks it)
IDENT=1D24F95FCA65C06129134FA5ABE114DF9C728B98
TARBALL=~/Library/Caches/Homebrew/downloads/faf0c660…--aitm-0.5.3-aarch64-apple-darwin.tar.gz   # the 0.5.3 core
osascript -e 'quit app "Aitmproxy"'
NE_SIGN_IDENTITY=$IDENT CORE_TARBALL=$TARBALL apps/mac/build.sh --ne --allow-unnotarized
#   -> /Applications/Aitmproxy.app, app + sysex CFBundleVersion 202610311334, 75 s swift build
ditto -c -k --keepParent /Applications/Aitmproxy.app /tmp/claude/ne-survey/Aitmproxy-survey.zip
xcrun notarytool submit …/Aitmproxy-survey.zip --keychain-profile aitm-notary --wait   # Accepted, ~60 s
xcrun stapler staple /Applications/Aitmproxy.app
spctl -a -t exec -vv /Applications/Aitmproxy.app        # accepted, source=Notarized Developer ID
open /Applications/Aitmproxy.app
```

Build to activated extension took 2 min 17 s. Notarizing the `.app` as a zip (no DMG) was
enough for activation, as in the Task-1 spike.

### What Matt had to click

**Nothing.** `capture.enabled` was already on, so the app's `start()` submitted the
activation request at launch. sysextd logged `activateDecision found existing entry of same
version: state activated_enabled … found entry to replace: … CFBundleVersion "202610310840"
… initial activation decision: requestAppReplaceAction`; the app's delegate returned
`.replace`, and `systemextensionsctl list` showed `0.5.3/202610311334 [activated enabled]`
10 s after launch, the previous build `terminated waiting to uninstall on reboot`. A
same-team, same-short-version, newer-`CFBundleVersion` replacement raised no System Settings
prompt on macOS 27.0. (The capture-off/on control below also needed no prompt: an approved
extension's tunnel is stopped and restarted by the app's own Proxy ▸ Disable/Enable Capture.)

## Result

### R1. Rates (item 7) — shipped provider, framework lines, 08:49:40–13:27:28 (4 h 38 min)

16 957 new flows: 10 403 TCP (61 %), 6 554 UDP (39 %).

| Hour (PDT) | Flows | Avg /s |
|---|---|---|
| 08:49–09:00 (11 min) | 1 276 | 1.9 |
| 09 | 2 642 | 0.73 |
| 10 | 3 855 | 1.07 |
| 11 | 4 076 | 1.13 |
| 12 | 3 421 | 0.95 |
| 13:00–13:27 | 1 687 | 1.0 |

Bursts, with the cause read off the `app =` field:

| Window | Flows | Rate | Cause |
|---|---|---|---|
| busiest 1 s (13:17:46) | 60 | 60/s | `com.anthropic.claude-code`, 60 TCP:443 opens in one second |
| other top seconds | 56, 56, 53, 51, 50 | | the same app in four of the five, plus `remotepairingd`/`usbmuxd` |
| busiest 10 s (08:50:58) | 282 | 28/s | `aitm` (the embedded core, 217 TCP:443 + 58 TCP:80, self-excluded) |
| busiest minute (10:29) | 634 | 10.6/s | `com.apple.CoreDevice.remotepairingd`: 296 TCP:49152 + 294 UDP:3722 |
| per active second | p50 2, p90 7, p99 25, max 60 | | 4 631 seconds had ≥1 flow |

The variant's in-process counter (`SURVEY-RATE max_1s`) agreed with the log-derived peaks
(17/s in its first two minutes versus 17 counted from lines), so the log store did not drop
lines at these rates.

**Controlled bursts (`burst-test.sh`, variant active, 14:04–14:05):** a heavy page in a
cold headless Chrome profile is the worst case seen all day.

| Load | New flows | Duration | Peak second | Note |
|---|---|---|---|---|
| Chrome headless, cold profile, theverge.com | **1 243** | 8 s | **336/s** | arrivals per second: 2, 101, 187, 235, 336, 122, 92, 141, 24 |
| Chrome headless, cold profile, cnn.com | 176 | 3 s | 108/s | |
| Chrome headless, cold profile, nytimes.com | 66 | 2 s | 55/s | |
| Safari (Matt's warm profile), theverge.com | ≈420 | 11 s | 66/s | 38, 50, 42, 34, 66, 59, 17, 18, 34, 36, 23 |

**Provider throughput ceiling (measured from the same burst).** The framework logs `New
flow` when a flow *arrives*; the variant logs `SURVEY` when `handleNewFlow` *returns*. Over
the whole burst both counted 1 260 flows (nothing dropped), but per second they diverge:

| Second | arrived (framework) | handled (SURVEY) |
|---|---|---|
| 14:04:22 | 101 | 103 |
| 14:04:23 | 187 | 158 |
| 14:04:24 | 235 | 197 |
| 14:04:25 | 336 | 200 |
| 14:04:26 | 122 | 199 |
| 14:04:27 | 92 | 203 |
| 14:04:28 | 141 | 156 |

Handling saturates at **≈200 flows/s** (`SURVEY-RATE max_1s=201` for that minute), i.e.
one flow per ≈5 ms, which is the `isSelf` cost (R3). A backlog of ≈200 flows built up by
14:04:25 and drained by 14:04:28, so during that page load new connections waited up to
about a second inside the provider before going direct. This is the shipped provider's
behaviour today, before any observe-lane work.

Remote ports (morning window): TCP 443 (4 998), UDP 53 (3 969), UDP 443 (1 517, QUIC
attempts), TCP 80 (1 424), TCP 49152 + 62078 and UDP 3722 (Apple device pairing, 2 400+),
UDP 123 (125). Interfaces: `en15` 76 %, `en15(bound)` 14 %, `en0(bound)` 6 %,
`utun10/12(bound)` 2.6 %, `lo0` 1 flow.

**Variant window, 13:35–15:43 (afternoon, Matt browsing in Safari; my controlled bursts at
14:04–14:06 excluded):** 13 370 organic flows, **1.74/s sustained** over 128 min (the busier
half of the day). Organic peaks: busiest second **70** (Safari, 68 of them), five more seconds
of 55–67 (Safari, Chrome helper, claude-code); busiest 10 s **235** (Safari page load,
23.5/s); busiest minute **790** (`remotepairingd`, 13.2/s); per active second p50 2, p90 11,
p99 29.

### R2. Field survey (item 6)

Framework lines (16 957 flows, shipped provider, morning) and the variant's `SURVEY` lines
(15 846 declined flows, 13:35–15:43: 8 369 TCP, 7 477 UDP, 452 of them self-excluded, 333
distinct source pids):

| Field | TCP | UDP | Source |
|---|---|---|---|
| `remoteHostname` set | 68 % (7 069/10 403) | 55 % (3 587/6 554) | framework `name =`, morning |
| `remoteHostname` set | **76 %** (6 367/8 369) | **48 %** (3 592/7 477) | variant `hn > 0`, afternoon |
| `sourceAppSigningIdentifier` empty | 0 of 10 403 | 0 of 6 554 | framework `app =` (also 0 of 15 846 in the variant) |
| `sourceAppAuditToken` nil | **0 of 8 369** | **0 of 7 477** | variant `tok` (always 32 bytes) |
| `remoteFlowEndpoint` / initial remote nil or hostname-typed | **0** | **0** | variant `ep` (always `ip:port`) |
| `filterFlowIdentifier` nil | 0 of 10 403 | 31 % (2 051/6 554) | framework `filter_id`, morning |
| `filterFlowIdentifier` nil | 0 of 8 369 | **25 %** (1 878/7 477) | variant `ffid` |
| `proc_pidpath_audittoken` failed (`pp_len == 0`) | **4.9 %** overall (777/15 846) | | variant; 13 pids, all euid 501 |
| euid of the audit token | 501 (`matt`) **93.2 %**, 213 (`_usbmuxd`) 4.8 %, 65 (`_mdnsresponder`) 1.5 %, 0 (`root`) 0.45 %, `_timed`/`_locationd`/`_cmiodalassistants`/`_accessoryupdater` 20 flows | | variant, 15 846 flows |

Notes. `_usbmuxd`'s 755 flows are all TCP without a hostname (device pairing);
`_mdnsresponder`'s are UDP:53 with the queried name set; root's 71 flows were mostly UDP:53
and :443 from system daemons. `sourceAppUniqueIdentifier` was 20 bytes (a cdhash) on every
framework line. The hostname is present even on UDP:53 flows made by connect-by-name
resolvers (`name = example.com` on a `com.apple.curl` DNS datagram). The 13 pids whose path
lookup fails are long-lived user processes (one made 337 flows); for them the Security
check in `isSelf` also returns in ≈120 µs instead of milliseconds, and securityd logs
`UNIX error exception: 2` (ENOENT), consistent with an executable no longer at its on-disk
path (inference; not confirmed by inspecting the processes).

### R3. Per-flow cost (item 7) — variant, all 15 846 declined flows

| Call | p50 | p90 | p99 | max | mean |
|---|---|---|---|---|---|
| `SelfExclusion.isSelf` (SecCodeCopyGuestWithAttributes + SecCodeCheckValidity) | **3.6 ms** | 6.0 ms | 11.4 ms | 32.2 ms | 3.9 ms |
| `proc_pidpath_audittoken` | 12.5 µs | 19 µs | 37 µs | 317 µs | 14 µs |
| claim path, detached (`handleTCP/handleUDP` → `link.current() == nil`) | 51 µs | 80 µs | 259 µs | 1.7 ms | 63 µs |
| whole `handleNewFlow` to the log call | 3.7 ms | 6.1 ms | 11.5 ms | 32.3 ms | 4.0 ms |

`isSelf` dominates by three orders of magnitude and runs on **every** new flow on the Mac
today, claimed or not, attached or not. The framework log shows the companion
`com.apple.securityd … UNIX error exception: 2` line per flow. It is **not cached per
process**: the first flow of a pid costs p50 4.0 ms and later flows of the same pid p50
3.6 ms (15 846 flows, 333 pids). The cost is per binary, not per call: per-pid medians range
from 0.9 ms to 11.1 ms (a Chromium-sized bundle; `aitm` itself 5.6 ms, Safari ≈2.9 ms with
4 164 flows) for normal processes, and ≈120 µs for the 13 pids whose `proc_pidpath_audittoken`
also fails (the Security lookup fails fast). At the measured ≈200 flows/s ceiling the provider
is CPU-bound in this call during any page load (R1, controlled bursts).

### R4. UDP `return false` on macOS 27 (item 8)

All runs with the extension `[activated enabled]`, provider declining every flow (detached).

**Works unchanged (measured):**

- DNS over UDP from user processes: `dig` to 1.1.1.1, 8.8.8.8 and the LAN resolver
  10.9.10.1 (10–41 ms); `dig +tcp` control; `dscacheutil`, `nslookup`, `host`, `ping`,
  Python `getaddrinfo` (system resolver via `mDNSResponder`, which runs as euid 65 and whose
  UDP:53 flows the provider declined); a 30-name `curl` loop (Apple's curl resolves with its
  own UDP:53 flow, `app = com.apple.curl`): 30/30 resolved, none over 2 s. One earlier `curl`
  in the first baseline run failed to resolve `example.com` for 30 s; not reproduced in 60
  later lookups, cause unknown (labelled as such).
- NTP: `sntp time.apple.com` answered.
- A hand-built DNS query over a **connected** UDP socket got its 61-byte reply in 5–6 ms,
  even though `setsockopt(IP_DONTFRAG)` on that socket had failed (next item).

**Fails (measured, with control):** `setsockopt(IPPROTO_IP, IP_DONTFRAG, 1)` on a
**connected UDP socket to any non-loopback destination returns `ECONNRESET`** while the
transparent proxy is active, for UDP:443, UDP:53 and UDP:123 alike; loopback is unaffected.
`send()` on the same socket still succeeds. With capture turned **off** through the app's
Proxy ▸ Disable Capture (provider `stopProxy`, 0 flows seen for 12 s) the same calls all
succeed; turned back on, `ECONNRESET` returns. This is the mechanism DevForums thread 770707
describes, reproduced on macOS 27.0 with a provider that returns `false`.

Consequence for Chromium (headless Chrome, fresh profiles):

| Run | Capture ON | Capture OFF |
|---|---|---|
| `--origin-to-force-quic-on=cloudflare-quic.com:443` | **`Page load failed: net::ERR_CONNECTION_RESET`**, empty DOM | page loads, "your browser used **HTTP/3**" |
| `--origin-to-force-quic-on=quic.nginx.org:443` | `ERR_CONNECTION_RESET` | "Congratulations! You're connected over QUIC" |
| normal load of cloudflare-quic.com, second visit | loads, "your browser used **HTTP/2**" (silent TCP fallback) | HTTP/3 |

So with capture on, Chrome (and anything on Chromium's QUIC stack) silently loses HTTP/3 and
falls back to HTTP/2; QUIC-only destinations fail. The provider did see the attempts (UDP:443
flows from `com.google.Chrome.helper` were declined). Firefox and Safari: see R4b.

### R4b. Firefox, Safari and Apple's URLSession (GUI + a Swift probe), capture ON

- **Firefox works.** A separate Firefox instance with a throwaway profile
  (`open -na Firefox --args --no-remote -profile … https://cloudflare-quic.com/`, two ⌘R
  reloads, window shot `ff-gui-variant1.png`) rendered "your browser used **HTTP/3**" while
  the provider was declining its UDP:443 flow to 104.18.27.14 (seen in the framework log as
  `org.mozilla.firefox -> 104.18.27.14:443`, datagram). So Firefox's QUIC stack tolerates
  the `IP_DONTFRAG` failure that Chromium treats as fatal.
- **Safari: HTTP/2 on the first load**, no UDP:443 attempt seen from Safari in that window
  (`safari-variant1.png`; the scripted ⌘R reloads failed with an AppleEvent timeout, so only
  the first, always-TCP load is proven). The Apple-stack probe below is the controlled test.
- **Apple's stack works.** A Swift `URLSession` probe (`spike/observe-survey/apple-h3.swift`,
  `assumesHTTP3Capable`, `URLSessionTaskMetrics.networkProtocolName`) negotiated **h3** to
  cloudflare-quic.com (three loads, connection reused) and to quic.nginx.org with capture
  **on**, identically with capture **off**; the provider log shows its UDP:443 flows declined
  (`apple-h3 cloudflare-quic.com -> 10.9.10.1:53` then `-> 3.125.64.247:443` datagram). Safari
  shares that stack: after Alt-Svc was known it opened `com.apple.Safari cloudflare-quic.com ->
  104.18.26.14:443` as a datagram flow too. So Safari and Firefox keep HTTP/3; only Chromium's
  QUIC (Chrome, Electron apps) fails on the `IP_DONTFRAG` error.

### R5. Restore (what is installed now)

`restore.sh` (quit, `brew reinstall --cask aitmproxy` from the cached 0.5.3 DMG, relaunch) was
**not run**: while the survey was collecting, another session cut and installed the
**v0.5.4 release** over `/Applications/Aitmproxy.app` (app binary 15:01 PDT, tag `v0.5.4`
published 22:01Z). Its launch at 15:43:19 submitted an activation request, sysextd again
chose `requestAppReplaceAction`, and `0.5.4/202610311454` has been `[activated enabled]`
since, with the variant `0.5.3/202610311334` (and the earlier `0.5.3/202610310840`)
`terminated waiting to uninstall on reboot`. Verified 15:57 PDT:

```
spctl -a -t exec -vv /Applications/Aitmproxy.app   -> accepted, source=Notarized Developer ID,
                                                      origin=Developer ID Application: Section 9 Labs LLC (995PCLM9KH)
codesign --verify --deep --strict                   -> ok;  CFBundleShortVersionString 0.5.4, CFBundleVersion 202610311454
Contents/Resources/core/{aitm,obscura}              -> present (15:01)
systemextensionsctl list                            -> com.mrbrutti.aitmproxy.ne (0.5.4/202610311454) [activated enabled]
```

Putting v0.5.3 back would downgrade Matt's app, so the newer release stays. One loose end
for whoever installed it: Homebrew still records the cask at 0.5.3 (`brew info --cask
aitmproxy` says `0.5.3 → 0.5.4`); `brew upgrade --cask aitmproxy` would reconcile the
bookkeeping with the same 0.5.4 bundle. Nothing of the experiment remains on disk except
the retired extension copy that macOS removes at the next reboot. Matt clicked nothing for
this replacement either.

## Conclusion

- **Fields (item 6): proven.** On this Mac every one of 15 846 declined flows carried a
  32-byte `sourceAppAuditToken`, a non-empty `sourceAppSigningIdentifier` (system daemons
  report their own id, e.g. `com.apple.mDNSResponder`), and an `ip:port` remote endpoint
  (never nil, never hostname-typed). `remoteHostname` is present on three quarters of TCP
  and half of UDP flows. `filterFlowIdentifier` is unreliable on UDP (nil on a quarter to a
  half) even with a content filter installed. `proc_pidpath_audittoken` fails on 4.9 % of
  flows (13 long-lived user processes). Euid is overwhelmingly the operator's (93 %), then
  `_usbmuxd` (4.8 %), `_mdnsresponder` (1.5 %) and root (0.45 %).
- **Rates and costs (item 7): measured.** Sustained 1–1.7 flows/s (morning 0.7–1.1/s per
  hour, afternoon 1.74/s); organic bursts of 60–70/s for a second, 235 flows in 10 s (a
  Safari page load), 790 in a minute (`remotepairingd`); a cold Chromium profile loading a
  heavy page is the worst case at 1 243 flows in 8 s, 336/s peak. The enqueue work the spec
  adds (`proc_pidpath_audittoken` ≈13 µs, integer extraction) is negligible; the existing
  `isSelf` at 3.6 ms median / 11.4 ms p99 per flow is the real per-flow cost, is already
  paid today, and caps the provider at ≈200 flows/s.
- **UDP `false` (item 8): partly disproven.** Datagram traffic itself flows after `false`
  (DNS, NTP, QUIC packets), so the macOS-15 header's "the flow is terminated" is wrong for a
  transparent proxy. But the active catch-all `.any` rule makes `setsockopt(IP_DONTFRAG)`
  fail with `ECONNRESET` on every connected UDP socket, which breaks Chromium QUIC (Chrome
  and Electron apps silently lose HTTP/3 while capture is on; Safari and Firefox keep it).
  This is present in the shipped v0.5.3 and v0.5.4 providers and is independent of the
  observe-only lane.

## Carry into the spec

1. **Queue (Part 3): keep 2 048.** The worst burst measured (cold Chrome, theverge.com) is
   1 243 flows in 8 s, peak 336/s; organic peaks are 60–70/s for a second and 235 flows over
   10 s. 2 048 drop-oldest entries hold the whole worst burst with room for a second one, and ≈6 s
   of a sustained 336/s; 1 024 would already drop the tail of a heavy page load if the writer
   stalled for 3 s. Memory is ≈400 KiB at ≈200 B/entry. The writer's 2 s `SO_SNDTIMEO` is the
   binding constraint, not the queue.
2. **Core soft cap (Part 4):** 5 000/s is 15× the worst observed arrival second (336/s) and
   25× the provider's current handling ceiling (≈200/s); it only guards against a
   pathological loop. 1 000/s would still be 3× the worst burst; either is fine. Size the
   `ObserveStore` for ≈1–2 flows/s sustained (3 600–6 300/h, so 20 000 events ≈ 3–5 h of
   this day's traffic; the 8 905-flow hour with page loads fills it in ≈2 h).
3. **`isSelf` must leave the per-flow hot path** (new requirement for the plan, not in the
   spec): it is 3.6 ms median / 11 ms p99 per flow, uncached by the framework, and it caps
   the provider at ≈200 flows/s, so a heavy page load queues connections for up to a second
   inside the provider today. Cache the verdict per source process, keyed by the audit
   token's `(pid, pidversion)` or the 20-byte `sourceAppUniqueIdentifier` cdhash, bounded
   LRU; and skip it entirely while detached (nothing can be claimed, so a self flow and a
   foreign flow get the same `false`). With that, `handleNewFlow` is ≈60 µs (`proc_pidpath`
   + detached claim) and the ceiling moves to >10 000/s.
4. **Observe-lane fields:** `sourceAppAuditToken` and the euid are always available, so the
   same-uid filter (Open question 4) is implementable as written and would drop ≈7 % of
   flows (`_usbmuxd`, `_mdnsresponder`, root and four other daemons); `remoteHostname` must
   stay optional (absent on 1/4 of TCP, 1/2 of UDP); `remoteFlowEndpoint` can be treated as
   always `ip:port` (a nil/hostname-typed case was never seen in 15 846 flows, keep the
   fail-open guard); `source_path` fallback will be empty ≈5 % of the time (the signing id is
   still present on those, so the row is never nameless); do not key anything on
   `filterFlowIdentifier` for UDP.
5. **UDP `false` is not safe as shipped:** a transparent proxy whose rule covers UDP breaks
   `IP_DONTFRAG` on every connected UDP socket (DevForums 770707 confirmed on macOS 27.0),
   and Chromium QUIC fails over it. The spec should state that the observe lane inherits this
   and the plan should either (a) exclude UDP from the catch-all rule by default (TCP `.any`
   rule plus UDP only when the operator scopes a UDP target; rules need a restart to change),
   or (b) exclude UDP:443 via `excludedNetworkRules` and accept blind QUIC, and in either
   case file an Apple Feedback citing thread 770707 with this reproduction
   (`spike/observe-survey/dontfrag-core.py`). Until then, Chromium-based apps on Matt's Mac
   have no HTTP/3 while capture is on.
6. **Operational facts for the plan's install story:** a same-version, newer-build,
   same-team extension replaces the activated one with no user prompt; notarizing the `.app`
   zip is enough for activation; the framework's own per-flow log lines are a zero-cost
   verification oracle for any provider change (`log show --predicate 'process ==
   "AitmproxyNE"'`, one `New flow` line per flow with app, hostname, endpoints, interface).

Nothing from the branch is reused as code; the real implementation goes through all seven
stages.
