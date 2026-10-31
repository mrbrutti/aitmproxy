# Experiment: macOS NE observe-only survey (fields, rates, costs, UDP `false`)

**Date:** 2026-10-31 (Matt's Mac: macOS 27.0 build 26A428, Apple Silicon, Xcode 27.1 toolchain)
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
`udp-test.sh`, `udp-dontfrag.sh` (+ `dontfrag-core.py` inline), `capture-control.sh`,
`gui-quic.sh`, `survey-pull.sh`, `dump-framework-log.sh`, `analyze.py`, `restore.sh`.

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
| other top seconds | 56, 56, 53, 51, 50 | | same app (four of five), plus `remotepairingd`/`usbmuxd` |
| busiest 10 s (08:50:58) | 282 | 28/s | `aitm` (the embedded core, 217 TCP:443 + 58 TCP:80, self-excluded) |
| busiest minute (10:29) | 634 | 10.6/s | `com.apple.CoreDevice.remotepairingd`: 296 TCP:49152 + 294 UDP:3722 |
| per active second | p50 2, p90 7, p99 25, max 60 | | 4 631 seconds had ≥1 flow |

The variant's in-process counter (`SURVEY-RATE max_1s`) agreed with the log-derived peaks
(17/s in its first two minutes versus 17 counted from lines), so the log store did not drop
lines at these rates.

Remote ports: TCP 443 (4 998), UDP 53 (3 969), UDP 443 (1 517, QUIC attempts), TCP 80 (1 424),
TCP 49152 + 62078 and UDP 3722 (Apple device pairing, 2 400+), UDP 123 (125).
Interfaces: `en15` 76 %, `en15(bound)` 14 %, `en0(bound)` 6 %, `utun10/12(bound)` 2.6 %, `lo0` 1 flow.

### R2. Field survey (item 6)

Framework lines (16 957 flows, shipped provider, 4 h 38 min) and the variant's `SURVEY` lines
(first 392 declined flows, 13:35:01–13:37:47; the full-window table is updated at the end of
the run):

| Field | TCP | UDP | Source |
|---|---|---|---|
| `remoteHostname` set | 68 % (7 069/10 403) | 55 % (3 587/6 554) | framework `name =` |
| `remoteHostname` set | 61 % (103/170) | 42 % (93/222) | variant `hn > 0` |
| `sourceAppSigningIdentifier` empty | 0 of 10 403 | 0 of 6 554 | framework `app =` (also 0/392 in the variant) |
| `sourceAppAuditToken` nil | 0 of 170 | 0 of 222 | variant `tok` (always 32 bytes) |
| `remoteFlowEndpoint` / initial remote nil or hostname-typed | 0 | 0 | variant `ep` (always `ip:port`) |
| `filterFlowIdentifier` nil | 0 of 10 403 | 31 % (2 051/6 554) | framework `filter_id` |
| `filterFlowIdentifier` nil | 0 of 170 | 58 % (129/222) | variant `ffid` |
| `proc_pidpath_audittoken` failed (`pp_len == 0`) | 3/170 | 17/222 | variant; all euid 501 |
| euid of the audit token | 501 (Matt) 95.4 %, 65 (`_mdnsresponder`) 3.1 %, 0 (root) 1.5 % | | variant, 392 flows, 64 distinct pids |

Notes. The euid-65 flows are `mDNSResponder` UDP:53; the root flows were 3 UDP:53, 2 TCP:443,
1 UDP:443 (system daemons). `sourceAppUniqueIdentifier` was 20 bytes (a cdhash) on every
framework line. The hostname is present even on UDP:53 flows made by connect-by-name
resolvers (`name = example.com` on a `com.apple.curl` DNS datagram).

### R3. Per-flow cost (item 7) — variant, first 392 declined flows

| Call | p50 | p90 | p99 | max | mean |
|---|---|---|---|---|---|
| `SelfExclusion.isSelf` (SecCodeCopyGuestWithAttributes + SecCodeCheckValidity) | **3.9 ms** | 7.0 ms | 11.5 ms | 20.7 ms | 4.4 ms |
| `proc_pidpath_audittoken` | 10 µs | 16 µs | 22 µs | 48 µs | 11 µs |
| claim path, detached (`handleTCP/handleUDP` → `link.current() == nil`) | 47 µs | 59 µs | 275 µs | 393 µs | 49 µs |
| whole `handleNewFlow` to the log call | 4.0 ms | 7.1 ms | 11.7 ms | 20.8 ms | 4.5 ms |

`isSelf` dominates by three orders of magnitude and runs on **every** new flow on the Mac
today, claimed or not, attached or not. The framework log shows the companion
`com.apple.securityd … UNIX error exception: 2` line per flow. At the observed 60-flow
second that is ~240 ms of serialized provider time; at the 28/s 10-s burst ~110 ms per
second.

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

### R5. Restore

_Filled in after `restore.sh`._

## Conclusion

- **Fields (item 6): proven.** On this Mac every declined flow carried a 32-byte
  `sourceAppAuditToken`, a non-empty `sourceAppSigningIdentifier` (system daemons report
  their own id, e.g. `com.apple.mDNSResponder`), and an `ip:port` remote endpoint (never
  nil, never hostname-typed). `remoteHostname` is present on about two thirds of TCP and half
  of UDP flows. `filterFlowIdentifier` is unreliable on UDP (nil on a third to a half) even
  with a content filter installed. `proc_pidpath_audittoken` fails on ~5 % of flows
  (short-lived processes). Euid is overwhelmingly the operator's (95 %), with root and
  `_mdnsresponder` the rest.
- **Rates and costs (item 7): measured.** Sustained ~1 flow/s, hourly peak 1.13/s; bursts of
  60/s for a second, 28/s over 10 s, 10.6/s over a minute, each attributable to one app. The
  enqueue work the spec adds (`proc_pidpath_audittoken` ~10 µs, integer extraction) is
  negligible; the existing `isSelf` at 3.9 ms median / 11.5 ms p99 per flow is the real
  per-flow cost and is already paid today.
- **UDP `false` (item 8): partly disproven.** Datagram traffic itself flows after `false`
  (DNS, NTP, QUIC packets), so the macOS-15 header's "the flow is terminated" is wrong for a
  transparent proxy. But the active catch-all `.any` rule makes `setsockopt(IP_DONTFRAG)`
  fail with `ECONNRESET` on every connected UDP socket, which breaks Chromium QUIC (HTTP/3 is
  silently disabled machine-wide while capture is on). This is a shipped v0.5.3 regression
  independent of the observe-only lane.

## Carry into the spec

1. **Queue (Part 3):** 2 048 drop-oldest entries hold 34 s of the worst observed second
   (60/s) and 73 s of the worst 10-s burst (28/s). 1 024 would still hold 17 s / 36 s. Keep
   2 048 or lower to 1 024; the writer's 2 s `SO_SNDTIMEO` is the binding constraint, not
   memory (≈200 B × 2 048 ≈ 400 KiB).
2. **Core soft cap (Part 4):** 5 000/s is ~80× the observed peak second; it only guards
   against a pathological loop. 1 000/s would be ample on this evidence; either is fine.
3. **`isSelf` must leave the per-flow hot path** (new requirement for the plan, not in the
   spec): cache the verdict per source process, keyed by the audit token's
   `(pid, pidversion)` (or the 20-byte `sourceAppUniqueIdentifier` cdhash), bounded LRU; and
   skip it entirely while detached (nothing can be claimed, so a self flow and a foreign
   flow get the same `false`). This cuts 4–12 ms of serialized provider time per new
   connection on the Mac today.
4. **Observe-lane fields:** `sourceAppAuditToken` and the euid are always available, so the
   same-uid filter (Open question 4) is implementable as written; `remoteHostname` must stay
   optional (absent on 1/3 of TCP, 1/2 of UDP); `remoteFlowEndpoint` can be treated as
   always `ip:port` (a nil/hostname-typed case was never seen, keep the fail-open guard);
   `source_path` fallback will be empty ~5 % of the time; do not key anything on
   `filterFlowIdentifier` for UDP.
5. **UDP `false` is not safe as shipped:** a transparent proxy whose rule covers UDP breaks
   `IP_DONTFRAG` on every connected UDP socket (DevForums 770707 confirmed on macOS 27.0),
   and Chromium QUIC fails over it. The spec should state that the observe lane inherits this
   and the plan should either (a) exclude UDP from the catch-all rule by default (TCP `.any`
   rule plus UDP only when the operator scopes a UDP target; rules need a restart to change),
   or (b) exclude UDP:443 via `excludedNetworkRules` and accept blind QUIC, and in either
   case file an Apple Feedback citing thread 770707 with this reproduction
   (`spike/observe-survey/dontfrag-core.py`). Until then, Matt's Mac has no HTTP/3 while
   capture is on.
6. **Operational facts for the plan's install story:** a same-version, newer-build,
   same-team extension replaces the activated one with no user prompt; notarizing the `.app`
   zip is enough for activation; the framework's own per-flow log lines are a zero-cost
   verification oracle for any provider change (`log show --predicate 'process ==
   "AitmproxyNE"'`, one `New flow` line per flow with app, hostname, endpoints, interface).

Nothing from the branch is reused as code; the real implementation goes through all seven
stages.
