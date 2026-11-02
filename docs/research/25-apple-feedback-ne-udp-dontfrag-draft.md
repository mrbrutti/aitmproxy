# Draft Apple Feedback: a catch-all `NETransparentProxyProvider` rule breaks `IP_DONTFRAG` on every UDP socket

> **Status: DRAFT. Not filed.** Matt files this, if he decides to. Written by the
> Researcher engine on **2026-11-01** from the survey experiment
> (`docs/research/experiments/2026-10-31-macos-ne-observe-survey.md` §R4, §R4b), its raw
> outputs on the unmerged branch `origin/experiment/macos-ne-observe-survey`
> (`spike/observe-survey/results/dontfrag-variant1.out`, `capture-control.out`,
> `gui-quic-variant1.out`) and research note 24
> (`docs/research/24-ne-tcp-only-catch-all-rule.md`). Nothing in this file was run again
> today.

## For Matt, before you paste (not part of the Feedback text)

- **What to paste.** Only the text between the two markers below. Feedback Assistant is a
  plain-text form, so the body has no markdown tables and no markdown emphasis. The script
  is in a fenced block here so it survives this file; in Feedback Assistant, attach
  `dontfrag-core.py` as a file as well and either drop the two fence lines from the pasted
  copy or leave them (they are harmless).
- **Area and Type.** Pick the nearest entries the form offers for "Network Extension
  framework / Networking, macOS" and "Incorrect/Unexpected behaviour".
- **Already filed by someone else.** DevForums 770707 names two reports, `FB23636906` (the
  `IP_DONTFRAG`/`IP_RECVTOS` finding, filed Jul 2026 by the poster) and `FB18141248` (found
  by Quinn, Jul 2026; the thread does not say it covers this exact failure). The text cites
  both. Quinn's advice in that thread: include a minimal NE provider test project and a
  sysdiagnose taken after the repro with extra NE debugging on ("Bug Reporting > Profiles
  and Logs"). The text below says both are available on request; attaching them at filing
  time is what Quinn asked the other poster for.
- **Two caveats to resolve first.**
  1. The measurements were made with our full shipping provider (core detached, so every
     flow returns `false`), not a minimal project. The reduced provider shown in step 1
     was **not built or run** by us. Building it and running steps 3 to 6 once is the
     cheapest way to confirm the text.
  2. The survey did not record the Chrome version. Chrome on this Mac now reads
     **156.0.8078.80** (`Info.plist`, 2026-11-01); confirm it is what ran on 2026-10-31
     before keeping that line.
- **The script as saved** contains the survey network's addresses (LAN resolver
  `10.9.10.1`, public IPs for cloudflare-quic, a Google QUIC host and time.apple.com). It
  sends 64 zero bytes to each and one DNS query to 1.1.1.1 and to the LAN resolver. Any
  non-loopback destination reproduces; replace `10.9.10.1` if you would rather not publish
  your resolver address.
- **Not measured, so not claimed as ours:** `IP_RECVTOS` (the thread says it fails too) and
  a TCP-only rule (the workaround's effect is untested; the Notes say only that we changed
  to it).

=== COPY FROM HERE ===

TITLE

A NETransparentProxyProvider with a catch-all outbound rule makes setsockopt(IP_DONTFRAG) fail with ECONNRESET on every connected non-loopback UDP socket, even when the provider declines every flow

AREA

Network Extension framework / Networking, macOS

TYPE

Incorrect/Unexpected behaviour

DESCRIPTION

A system extension containing an NETransparentProxyProvider with one catch-all outbound rule (protocol .any, remote and local endpoints nil) whose handleNewFlow and handleNewUDPFlow return false for every flow makes setsockopt(IPPROTO_IP, IP_DONTFRAG, 1) fail with ECONNRESET on every connected, non-loopback UDP socket on the system, for as long as the proxy is active. The same call succeeds on loopback and with the proxy stopped, and send() on the affected socket still works, so this is not a flow-handling failure. This is the mechanism described in Apple Developer Forums thread 770707 (https://developer.apple.com/forums/thread/770707, FB23636906), reproduced here on macOS 27.0 with a provider that claims no flows at all and a rule that is not limited to port 443. Chromium treats the error as fatal when it configures a QUIC socket, so Chrome and Electron apps silently lose HTTP/3 while the proxy is active and fail outright against QUIC-only origins; Firefox and URLSession (Apple's networking stack) are unaffected.

STEPS TO REPRODUCE

1. Build a system extension whose NEProviderClasses maps com.apple.networkextension.app-proxy to an NETransparentProxyProvider subclass. We observed this with our full shipping provider while its control channel was detached, so it returned false for every flow. Reduced to its rule and its two flow handlers (this reduction was not built separately):

    override func startProxy(options: [String: Any]?,
                             completionHandler: @escaping (Error?) -> Void) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let rule = NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0,
                                 localNetworkEndpoint: nil, localPrefix: 0,
                                 protocol: .any, direction: .outbound)
        settings.includedNetworkRules = [rule]
        setTunnelNetworkSettings(settings) { error in completionHandler(error) }
    }
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool { return false }
    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow,
                          initialRemoteFlowEndpoint remoteEndpoint: NWEndpoint) -> Bool { return false }

2. Sign (Developer ID), notarize, install and activate the extension, save an NETransparentProxyManager configuration for it and start the tunnel. Confirm with: systemextensionsctl list   (the extension shows [activated enabled]).

3. Save the script below as dontfrag-core.py and run it with the tunnel running:

    python3 dontfrag-core.py

4. Observe (proxy active). Every connected non-loopback UDP socket fails the setsockopt; send() works; loopback succeeds:

    cloudflare-quic 104.18.27.14:443   connect ok | setsockopt(DONTFRAG) ECONNRESET | send ok | send2 ok
    same, no DONTFRAG                  connect ok | send ok | send2 ok
    google quic 142.250.73.110:443     connect ok | setsockopt(DONTFRAG) ECONNRESET | send ok | send2 ok
    1.1.1.1:53 (DNS)                   connect ok | setsockopt(DONTFRAG) ECONNRESET | send ok | send2 ok
    LAN resolver 10.9.10.1:53          connect ok | setsockopt(DONTFRAG) ECONNRESET | send ok | send2 ok
    time.apple.com 17.253.16.125:123   connect ok | setsockopt(DONTFRAG) ECONNRESET | send ok | send2 ok
    loopback 127.0.0.1:443             connect ok | setsockopt(DONTFRAG) ok | send ok | send2 ok
    cloudflare v6 [2606:4700::6812:1b0e]:443   connect EHOSTUNREACH | setsockopt(DONTFRAG) ECONNRESET | send EDESTADDRREQ | send2 EDESTADDRREQ
    real DNS query, connected socket, DONTFRAG set:  1.1.1.1: DONTFRAG ECONNRESET; reply 61 bytes in 6 ms
                                                     10.9.10.1: DONTFRAG ECONNRESET; reply 61 bytes in 5 ms

   (The IPv6 line is a host with no IPv6 route: connect fails with EHOSTUNREACH, yet IPV6_DONTFRAG still returns ECONNRESET with the proxy active.)

5. Stop the tunnel (stopVPNTunnel, and switch the saved configuration off) and run the script again. The provider logs stopProxy and sees no flows for 12 seconds. Every setsockopt now succeeds:

    cloudflare-quic 104.18.27.14:443   connect ok | setsockopt(DONTFRAG) ok | send ok | send2 ok
    google quic 142.250.73.110:443     connect ok | setsockopt(DONTFRAG) ok | send ok | send2 ok
    1.1.1.1:53 (DNS)                   connect ok | setsockopt(DONTFRAG) ok | send ok | send2 ok
    LAN resolver 10.9.10.1:53          connect ok | setsockopt(DONTFRAG) ok | send ok | send2 ok
    time.apple.com 17.253.16.125:123   connect ok | setsockopt(DONTFRAG) ok | send ok | send2 ok
    loopback 127.0.0.1:443             connect ok | setsockopt(DONTFRAG) ok | send ok | send2 ok
    cloudflare v6 [2606:4700::6812:1b0e]:443   connect EHOSTUNREACH | setsockopt(DONTFRAG) ok | send EDESTADDRREQ | send2 EDESTADDRREQ
    1.1.1.1: DONTFRAG set; reply 61 bytes in 6 ms
    10.9.10.1: DONTFRAG set; reply 61 bytes in 1 ms

6. Start the tunnel again and re-run. ECONNRESET returns (that pass was cut to the first four output lines, so only these were captured):

    -- IPv4, connected UDP sockets --
    cloudflare-quic 104.18.27.14:443   connect ok | setsockopt(DONTFRAG) ECONNRESET | send ok | send2 ok
    same, no DONTFRAG                  connect ok | send ok | send2 ok
    google quic 142.250.73.110:443     connect ok | setsockopt(DONTFRAG) ECONNRESET | send ok | send2 ok

7. Chromium consequence (Google Chrome, headless, a fresh profile for each run). With the tunnel running, then with it stopped:

    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir=<fresh dir> --origin-to-force-quic-on=cloudflare-quic.com:443 --dump-dom https://cloudflare-quic.com/
    (and the same with quic.nginx.org:443 and https://quic.nginx.org/)

The script, dontfrag-core.py (unmodified):

```python
import socket, errno, time
IP_DONTFRAG = 28          # <netinet/in.h> on macOS
IPV6_DONTFRAG = 62
def trial(label, family, addr, dontfrag=True, send=True):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    res = []
    try:
        s.connect(addr); res.append("connect ok")
    except OSError as e:
        res.append(f"connect {errno.errorcode.get(e.errno, e.errno)}")
    if dontfrag:
        try:
            if family == socket.AF_INET: s.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG, 1)
            else: s.setsockopt(socket.IPPROTO_IPV6, IPV6_DONTFRAG, 1)
            res.append("setsockopt(DONTFRAG) ok")
        except OSError as e:
            res.append(f"setsockopt(DONTFRAG) {errno.errorcode.get(e.errno, e.errno)}")
    if send:
        try:
            s.send(b"\x00" * 64); res.append("send ok")
        except OSError as e:
            res.append(f"send {errno.errorcode.get(e.errno, e.errno)}")
        try:
            s.send(b"\x00" * 64); res.append("send2 ok")
        except OSError as e:
            res.append(f"send2 {errno.errorcode.get(e.errno, e.errno)}")
    s.close()
    print(f"  {label:34s} {' | '.join(res)}")
print("-- IPv4, connected UDP sockets --")
trial("cloudflare-quic 104.18.27.14:443", socket.AF_INET, ("104.18.27.14", 443))
trial("same, no DONTFRAG", socket.AF_INET, ("104.18.27.14", 443), dontfrag=False)
trial("google quic 142.250.73.110:443", socket.AF_INET, ("142.250.73.110", 443))
trial("1.1.1.1:53 (DNS)", socket.AF_INET, ("1.1.1.1", 53))
trial("LAN resolver 10.9.10.1:53", socket.AF_INET, ("10.9.10.1", 53))
trial("time.apple.com 17.253.16.125:123", socket.AF_INET, ("17.253.16.125", 123))
trial("loopback 127.0.0.1:443", socket.AF_INET, ("127.0.0.1", 443))
print("-- IPv6 --")
try: trial("cloudflare v6 [2606:4700::6812:1b0e]:443", socket.AF_INET6, ("2606:4700::6812:1b0e", 443))
except Exception as e: print("  v6 trial error", e)
print("-- real DNS query over a CONNECTED UDP socket WITH DONTFRAG (does a reply arrive?) --")
import struct, random
def dnsq(name):
    tid = random.randrange(65536)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."): q += bytes([len(part)]) + part.encode()
    return q + b"\x00\x00\x01\x00\x01"
for server in ("1.1.1.1", "10.9.10.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.connect((server, 53))
    try: s.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG, 1); df = "DONTFRAG set"
    except OSError as e: df = f"DONTFRAG {errno.errorcode.get(e.errno, e.errno)}"
    t0 = time.time()
    try:
        s.send(dnsq("example.com")); r = s.recv(512); print(f"  {server}: {df}; reply {len(r)} bytes in {1000*(time.time()-t0):.0f} ms")
    except OSError as e: print(f"  {server}: {df}; {errno.errorcode.get(e.errno, e.errno) if e.errno else e}")
    s.close()
```

EXPECTED RESULTS

setsockopt(IPPROTO_IP, IP_DONTFRAG, 1) succeeds on a connected UDP socket whether or not a transparent proxy extension is active, exactly as it does with the tunnel stopped. A provider that returns false for a flow ("the flow proceeds to communicate directly with the flow's ultimate destination", NETransparentProxyProvider.h) should leave the socket as if the proxy were not there.

ACTUAL RESULTS

With the catch-all rule active, setsockopt(IP_DONTFRAG) returns ECONNRESET (errno 54) on every connected non-loopback UDP socket, for UDP 443, 53 and 123 alike; loopback is unaffected; send() on the same socket succeeds; with the tunnel stopped every call succeeds; started again, ECONNRESET returns. Headless Chrome, forced QUIC, a fresh profile per run:

    Run                                              Tunnel running                               Tunnel stopped
    --origin-to-force-quic-on=cloudflare-quic.com:443   Page load failed: net::ERR_CONNECTION_RESET, empty DOM   page loads, "your browser used HTTP/3"
    --origin-to-force-quic-on=quic.nginx.org:443        ERR_CONNECTION_RESET                         "Congratulations! You're connected over QUIC"
    normal load of cloudflare-quic.com, second visit    loads, "your browser used HTTP/2" (silent TCP fallback)   HTTP/3

The provider did see the attempts: the UDP 443 flows from com.google.Chrome.helper were declined (false). Chromium's QUIC code applies IP_DONTFRAG (and IP_RECVTOS) right after connect() and abandons the QUIC session on any error other than ERR_NOT_IMPLEMENTED (net/quic/quic_session_pool.cc, QuicSessionPool::FinishConnectAndConfigureSocket), so ECONNRESET becomes net::ERR_CONNECTION_RESET.
Checked with the tunnel running: Firefox (its own profile) loaded cloudflare-quic.com over HTTP/3, and a URLSession probe (assumesHTTP3Capable, URLSessionTaskMetrics.networkProtocolName) negotiated h3 to cloudflare-quic.com and quic.nginx.org, identically with the tunnel stopped. Safari: its first load of cloudflare-quic.com was HTTP/2 (always TCP) and the provider log shows Safari opening a UDP 443 flow to cloudflare-quic.com, but we did not confirm that it completed HTTP/3, so we make no claim about Safari.

IMPACT

Every Chromium-based app (Chrome, Electron apps; thread 770707 reports Brave and Opera too) loses HTTP/3 while any transparent proxy covering UDP is active, even one that declines every UDP flow, and QUIC-only destinations fail with ERR_CONNECTION_RESET. The loss is silent for ordinary browsing (fallback to HTTP/2) and visible only against QUIC-only or forced-QUIC origins. Firefox and URLSession are unaffected. Because the rule need not be a catch-all (thread 770707 reproduces with rules limited to UDP port 443), any transparent-proxy product with a UDP rule is exposed. Returning false from the provider does not avoid it (measured above), and we know of no provider-side setting that does while a UDP rule is present.

ENVIRONMENT

macOS 27.0 (build 26A428), Apple Silicon. Xcode 27.1 toolchain (build 27A9269). Developer ID signed and notarized system extension, NETransparentProxyProvider, extension bundle identifier com.mrbrutti.aitmproxy.ne. Measured on version 0.5.3 build 202610311334, our provider plus diagnostic log lines (claim path unchanged, detached, every flow declined); the shipped 0.5.3 and 0.5.4 builds install the same rule. Google Chrome 156.0.8078.80 (version read after the test), Firefox 158.0.1, Safari 27.0, Python 3. Other network extensions installed and active during the runs: Little Snitch 6.5 (content filter and endpoint security extension) and a WireGuard-based provider; the failure is absent when only our provider is stopped (they stay active), so neither causes it.

NOTES

1. Related reports on thread 770707: FB23636906 (IP_DONTFRAG and IP_RECVTOS fail with ECONNRESET on a flow-diverted UDP socket) and FB18141248 (cited by Apple in the thread). Differences from that thread: our rule is a catch-all with protocol .any, our provider claims no flows (it returns false for every flow), and the failure covers UDP 53 and 123 and IPv6, not only port 443 and Chromium.
2. Workaround on our side: we are changing the default rule to TCP-only and adding UDP rules only for an operator-chosen UDP target. This is a mitigation, not a fix: a rule that covers UDP triggers the failure for the destinations it covers (as thread 770707 reports for UDP 443 rules).
3. A sysdiagnose taken after the repro with the Network Extension debug profile, and a minimal provider project, are available on request.
4. We did not measure IP_RECVTOS ourselves.

=== COPY TO HERE ===

## Evidence behind each claim (not part of the Feedback text)

- Rows in steps 4 and 6 and the "tunnel running" / "tunnel stopped" Chrome results: survey §R4
  and `dontfrag-variant1.out` (13:41 PDT 2026-10-31), `capture-control.out` (13:44 PDT; the
  stop was Proxy > Disable Capture in the app, provider log `stopProxy 1`, 0 flows in the
  next 12 s; the re-enable pass piped the script through `head -4`, so only the heading and
  the first three result lines, quoted in step 6, were captured).
- Firefox, URLSession and Safari lines: survey §R4b (`gui-quic-variant1.out`,
  `apple-h3.out`, `apple-h3.swift`). The survey's conclusion says "Safari and Firefox keep
  it", but §R4b proves Safari only for its first, always-TCP load; the Safari UDP 443 flow
  to cloudflare-quic.com is in the provider log in `apple-h3.out`, with no completion
  check, which is why the text makes no Safari claim.
- The Chromium code path: research note 24 §3.3 (read 2026-11-01 from
  `chromium.googlesource.com`, `refs/heads/main`).
- Thread 770707 facts (title, dates, the accepted answer's `IP_DONTFRAG`/`IP_RECVTOS`
  finding, `FB23636906`, `FB18141248`, no workaround, no Apple statement of cause): research
  note 24 §3.3.
