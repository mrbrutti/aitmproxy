# macOS NE: a TCP-only catch-all rule, runtime rule changes, and the `IP_DONTFRAG` defect (DevForums 770707)

> **Provenance:** AI-generated research summary produced by the Researcher engine on
> **2026-11-01**. Sources: the Xcode 27.1 MacOSX 27.0 SDK headers and Swift overlay on the
> author's Mac (macOS 27.0, build 26A428), Apple developer documentation and DevForums
> threads, Chromium, Firefox and mitmproxy_rs source, mitmproxy, Proxyman and Little Snitch
> public pages, the survey experiment write-up and its raw outputs on the unmerged branch
> `origin/experiment/macos-ne-observe-survey`, and the aitmproxy tree at `ecbf58ac`
> (this worktree).
> **Method caveat:** every web page below was read through the WebFetch or WebSearch tools,
> which summarise the page with a small model; quotes are as the summariser returned them
> (the tool capped quotes from some sites at 125 characters, so long code is quoted line by
> line, with indentation reconstructed). Apple's `developer.apple.com/documentation` pages
> are JavaScript-rendered, so they were read through the site's `tutorials/data/...json`
> endpoint; DevForums threads were read as rendered pages and show month and year only.
> Markers: **(header)** first-hand in the SDK on this Mac; **(tree)** first-hand in this
> repo; **(local)** a read-only check on this Mac; **(W)** a web page read through WebFetch
> (summariser quote); **(S)** a search-result summary only; **(3P)** a third-party report,
> not an Apple statement; **(DTS)** a reply by Apple Developer Technical Support on
> DevForums. Anything marked **unverified** was not seen in a source. No fetched page
> carried instructions aimed at this task.
> **Sandbox limits on this run:** `curl` to `developer.apple.com` and
> `raw.githubusercontent.com` was refused, and nothing was built or run. **No experiment was
> performed**: every statement about what the OS does on macOS 27 is either a header or
> page quote, a forum report, or the survey's own measurement.
> **Scope:** tooling-architecture research for an operator with written authorization to
> test in-scope targets. Nothing here is a design decision; "candidate" marks where the
> evidence points.

## 1. Question

What does the macOS Network Extension API allow for the included rules of a
`NETransparentProxyProvider` (TCP-only catch-all, per-host UDP), can a running provider
change them without a restart, how does the host app restart the tunnel today, and what
are the Apple and Chromium facts behind the `IP_DONTFRAG` defect that a catch-all `.any`
rule causes (Open question 9 of the observe-only-lane spec, option (a))?

## 2. Short answer

A TCP-only catch-all is expressible (nil remote and local, protocol `.TCP`, outbound), and
a UDP rule for one scoped IP is expressible (address plus prefix, port or `0`; /32 and /128
are unexemplified). Runtime replacement is unresolved: the macOS 27 header says
`setTunnelNetworkSettings` may be called many times, a 2020 DTS reply says settings can be
reloaded, but a 2022 DTS reply says rule changes need a provider restart; nothing says what
happens to existing flows, and nobody measured it on macOS 27. The app's stop/start path
exists; `startTunnel` options reach `startProxy(options:)`, but our code uses neither.

## 3. Findings

### 3.1 Q1: `NENetworkRule` and `includedNetworkRules`

**(a) Initializers.** Read from `NENetworkRule.h` **(header)**, SDK `MacOSX27.0.sdk`, on
2026-11-01, and from the Swift overlay `NetworkExtension.swiftinterface` **(header)**.

- macOS 15+ (`API_AVAILABLE(macos(15.0))`), the one the provider already uses
  (`apps/mac/Extension/Sources/TransparentProxyProvider.swift:44-46`, **(tree)**):

  ```objc
  - (instancetype)initWithRemoteNetworkEndpoint:(nullable nw_endpoint_t)remoteNetwork
                                   remotePrefix:(NSUInteger)remotePrefix
                           localNetworkEndpoint:(nullable nw_endpoint_t)localNetwork
                                    localPrefix:(NSUInteger)localPrefix
                                       protocol:(NENetworkRuleProtocol)protocol
                                      direction:(NETrafficDirection)direction;
  ```

  Swift overlay: `init(remoteNetworkEndpoint: Network.NWEndpoint?, remotePrefix: Int,
  localNetworkEndpoint: Network.NWEndpoint?, localPrefix: Int, protocol:
  NENetworkRule.Protocol, direction: NETrafficDirection)`.
- Two more macOS 15+ initializers share the file: `initWithDestinationNetworkEndpoint:
  prefix:protocol:` (address or network) and `initWithDestinationHostEndpoint:protocol:`
  (a hostname or DNS domain; its header examples match "all DNS queries for names in the
  example.com DNS domain").
- Deprecated `macos(10.15, 15.0)`: `initWithRemoteNetwork:remotePrefix:localNetwork:
  localPrefix:protocol:direction:` (takes `NWHostEndpoint`), with
  `initWithDestinationNetwork:prefix:protocol:` and `initWithDestinationHost:protocol:`.
  Apple's page for `NENetworkRule` lists the three deprecated ones with abstracts and the
  three new ones with none **(W)**, `tutorials/data/documentation/networkextension/
  nenetworkrule.json`, 2026-11-01.
- Read-back properties: `matchRemoteHostOrNetworkEndpoint`, `matchRemotePrefix`,
  `matchLocalNetworkEndpoint`, `matchLocalPrefix`, `matchProtocol`, `matchDirection`
  (**header**).

**(b) Protocol cases (header).** `NENetworkRuleProtocolAny = 0` ("Matches TCP and UDP
traffic"), `NENetworkRuleProtocolTCP = 1` ("Matches TCP traffic"),
`NENetworkRuleProtocolUDP = 2` ("Matches UDP traffic"); Swift name
`NENetworkRule.Protocol` (`.any`, `.TCP`, `.UDP`), `API_AVAILABLE(macos(10.15))`.
`NETrafficDirection`: `Any = 0`, `Inbound = 1`, `Outbound = 2`.

**(c) A specific remote host with a specific port; port `0`.** Yes for addresses, with
rules. The header on the macOS 15 remote-network initializer **(header)**:

> "If both remoteNetwork and localNetwork are nil then the rule will match all traffic of
> the given protocol and direction, except for loopback traffic."
> "This endpoint must contain an address, not a hostname."
> "If the address is a wildcard address (0.0.0.0 or ::) then the rule will match all
> destinations except for loopback (127.0.0.1 or ::1)."
> "If the port string of the endpoint is "0" or is the empty string, then the rule will
> match traffic on any port coming from the remote network."

and `NETransparentProxyNetworkSettings.h` **(header)** adds, for `includedNetworkRules`:

> "If the port string of the endpoint is "0" or is the empty string, then the address of
> the endpoint must be a non-wildcard address (i.e. "0.0.0.0" or "::")."
> "If the address is a wildcard address (i.e. "0.0.0.0" or "::"), then the port string of
> the endpoint must be non-empty and must not be "0"."
> "A port string of "53" is not allowed. Destination Domain-based rules must be used to
> match DNS traffic."

Apple's page for the property repeats the same five restrictions in prose, and states no
count limit **(W)**, `.../netransparentproxynetworksettings/includednetworkrules.json`,
2026-11-01. So: a host rule is `remoteNetworkEndpoint = <ip>:<port or 0>`, protocol
`.UDP` or `.TCP`, `remotePrefix` the prefix length. A nil remote with protocol `.TCP` is
the TCP-only catch-all (loopback excluded by the header's own sentence). **Prefix traps:**
no source I read shows a `/32` or `/128` host rule (the header only says the prefix "in
combination with the address ... specifies the remote network"; /32 and /128 matching a
single host is therefore **unverified**). DevForums 698626, "Transparent Proxy IPv6
problem" (Jan 2022, **(DTS)** Matt Eaton, **(W)**): a UDP rule with `remoteNetwork`
`172.217.0.0`:443 and `remotePrefix: 0` did not work for Chrome while prefix 16 did; Eaton:
"the `remotePrefix` may not have been matching any part of the `remoteNetwork` with the
prefix set to 0", and after his general rules (`remoteNetwork: nil`, prefix 0) "everything
worked". The nil-remote form with prefix 0 is what the shipped provider uses.

**(d) Local-network fields.** Not "ignored": **required to be nil.** Verbatim
(`NETransparentProxyNetworkSettings.h`, **header**): "The matchLocalNetwork property must
be nil." and "The matchDirection property must be NETrafficDirectionOutbound." The only
"ignored" wording in `NENetworkRule.h` is `localPrefix`: "This parameter is ignored if
localNetwork is nil." What an out-of-contract rule does at runtime (an error from
`setTunnelNetworkSettings`, presumably `NETunnelProviderErrorNetworkSettingsInvalid` in the
header's `NETunnelProviderError`) is **unverified**. `NETransparentProxyProvider.h`
separately says `NEDNSSettings` and `NEProxySettings` in these settings "are ignored".

**(e) Limit on the number of rules.** None documented: not in the headers, not on Apple's
page for `includedNetworkRules` ("The page does not state a maximum number of rules" per
the summariser), and none in any thread I read. A UDP rule list that grows with scope is
therefore bounded only by what the OS tolerates, **unverified**. A related field report:
DevForums 762804, "Transparent Proxy Provider, UDP, mbufs, and inevitable panics" (Aug
2024, **(3P)**, **(W)**, FB14844573): a provider with a UDP rule in `includedNetworkRules`
leaked about 4 mbufs per second to a kernel panic even with `handleNew*Flow` returning
`false`; the poster later wrote "seems to be resolved as of 15.1 or later" (Dec 2024); no
Apple technical reply. Removing the UDP rule stopped it.

**(f) `excludedNetworkRules`.** Exists on `NETransparentProxyNetworkSettings`
(`API_AVAILABLE(macos(10.15))`) with the identical five restrictions, and the header says
it is an array that "collectively specify the traffic that will not be routed through the
transparent proxy" (**header**). The header states no precedence against
`includedNetworkRules` (note 10 §3.7 records "exclusion wins"; I did not find that sentence
in the header). Field: DevForums 677981, "excludedNetworkRules does not take effect" (Apr
to Sep 2021, **(3P)** poster, **(DTS)** Matt Eaton, **(W)**): hostname-based exclusions
appeared to have no effect in the poster's logs; Eaton reported his own test with include
`0.0.0.0:443` and exclude `apple.com` sent all `*.apple.com` traffic direct; no resolution
in the thread. An IP-based exclusion in the same thread stopped capture of all port 443
traffic rather than one host. Note 10 §3.9 also records a (S) report of a port in
`excludedNetworkRules` still receiving flows. Excluding UDP 53 cannot be written as an
address rule (port `53` is disallowed); only a domain rule can name DNS.

**The `false` contract (header).** `NETransparentProxyProvider.h`: "Returning NO from
handleNewFlow: and handleNewUDPFlow:initialRemoteEndpoint: causes the flow to proceed to
communicate directly with the flow's ultimate destination, instead of closing the flow with
a 'Connection Refused' error." Apple's page says the same of `handleNewFlow` and
`handleNewUDPFlow` **(W)**. The macOS 15 UDP variant
`handleNewUDPFlow:initialRemoteFlowEndpoint:` in `NEAppProxyProvider.h` says only "NO ...
In this case the flow is terminated", which the survey measured as wrong for a transparent
proxy (datagram traffic flows after `false`) (survey §R4).

### 3.2 Q2: can a running provider change its rules?

**The header says settings may be set again (header).** `NETunnelProvider.h`, on
`setTunnelNetworkSettings:completionHandler:`: "This method can be called multiple times
during the lifetime of a particular tunnel. It is not necessary to call this function with
nil to clear out the existing settings before calling this function with a non-nil
configuration." It does not say what happens to flows already routed, or to rules in
particular. `reasserting`: "A flag that indicates to the framework if this NETunnelProvider
is currently re-establishing the tunnel. Setting this flag will cause the session status
visible to the user to change to "Reasserting". ... Setting and clearing this flag only has
an effect if the session is in the "Connected" state." Apple's page says only "Indicate to
the system that the tunnel is being re-established" **(W)**. Neither text ties `reasserting`
to rule application, flow flushing or settings reload; it is a status indicator.

**Apple's `setTunnelNetworkSettings` page is silent on repeat calls.** It describes the
call as "part of the process of establishing the tunnel" in five steps, and "contains no
notes on calling this method more than once or on reasserting settings" **(W)**,
`.../netunnelprovider/settunnelnetworksettings(_:completionhandler:).json`, 2026-11-01.

**Three DTS statements, not consistent with each other, none on macOS 27, none about
existing flows.**

- DevForums 659298, "setTunnelNetworkSettings outside startProxyWithOptions" (Sep 2020,
  **(DTS)** Matt Eaton, transparent app proxy on Catalina, **(W)**): "call
  setTunnelNetworkSettings again at some point to reload the network configuration" and
  "After that, the settings can be reloaded." It does not mention rule changes
  specifically.
- DevForums 98366, "Update Tunnel Network Settings" (Mar 2018, **(DTS)** Quinn, provider
  type not named, probably a packet tunnel, **(W)**): "the system should do the right thing
  if you change the tunnel settings while the tunnel is up", "apply any changes with the
  minimum amount of disruption", and "I've never tried this myself so there could be some
  subtlety here". An expectation, not a guarantee.
- DevForums 699972, "Any way to update filter rule on the run for app proxy" (Feb 2022,
  **(DTS)** Matt Eaton, **(W)**). The poster asked: "I wonder is it possible to update
  these rules without restarting the proxy." The reply: "The provider needs to be
  restarted for any rules you add/remove to take affect." and "I should mention that
  hot-restarting the provider over and over on the fly is not a recommended path either."
  This is the only statement in my sources that is about changing *rules* on a running
  transparent or app proxy provider, and it says no. It does not address whether a second
  `setTunnelNetworkSettings` replaces them. Note 10 §3.7 and the existing provider comment
  (`TransparentProxyProvider.swift:38`, "Provider *rules* cannot be hot-edited without a
  restart") rest on this thread, now read first-hand.
- Related, not a rule change: DevForums 668369 (Dec 2020, **(DTS)** Matt Eaton, **(W)**), a
  mail account edited while the proxy ran was not captured: "I'm not sure why that does
  not work mid-stream"; he captured the ports only "if you start with those ports in your
  NETransparentProxyNetworkSettings".

**mitmproxy_rs (the macOS redirector) never re-applies.** `mitmproxy-macos/redirector/
network-extension/TransparentProxyProvider.swift`, read 2026-11-01 **(W)**: one included
rule, protocol `.any`, direction `.outbound`, and no `excludedNetworkRules`; `setTunnelNetworkSettings`
is called once, in `startProxy` (`try await setTunnelNetworkSettings(proxySettings)`); no
`handleAppMessage`; the intercept spec arrives on a control channel and "only assigns
`self.spec` without reapplying tunnel settings". There is no `handleNewUDPFlow`; UDP is
handled inside `handleNewFlow` (`flow as? NEAppProxyUDPFlow`), and the provider returns
`false` for "Skipping flow without process info", no spec, "Flow not in scope". So the one
public transparent-proxy provider I could read keeps a fixed `.any` rule and scopes per
flow, as aitmproxy does today.

**Proxyman, Little Snitch, Charles: nothing public found** on re-applying or hot-editing
provider rules (Proxyman's NE rule shapes are not public; Little Snitch is a content
filter, see 3.4; I did not search Charles beyond note 22). **Unverified.**

**A restart risk on macOS 26+ (3P).** DevForums 811866, "startProxy delegate for
NETransparentProxyProvider class is being called twice for the same pid extension
sometimes" (Jan to Jul 2026, **(W)**): `startProxy` sometimes runs twice for one extension
pid, and calling `setTunnelNetworkSettings` inside it then crashes with "Over-resume of an
object"; the poster says "only in Mac OS Tahoe" and "Even in Golden Gate Beta 4 we are
seeing this issue"; FB21464147; DTS (Quinn, Jul 2026): "I have no news to report on this
front." Apple gave no idempotency guidance. Our `startProxy` calls `handoff.start()` and
`setTunnelNetworkSettings` unconditionally (`TransparentProxyProvider.swift:34-48`,
**(tree)**), so every `startProxy` is exposed to this, restart path or not.

#### The fallback: the host app restarts the tunnel

- **API (header).** `NEVPNConnection.h`: `startVPNTunnelWithOptions:andReturnError:` with
  `NSDictionary<NSString *,NSObject *> *`, "This function is used to start the VPN tunnel
  using the current VPN configuration. The VPN tunnel connection process is started and
  this function returns immediately", "A dictionary that will be passed to the tunnel
  provider during the process of starting the tunnel"; `stopVPNTunnel`: "The VPN tunnel
  disconnect process is started and this function returns immediately." Swift:
  `startVPNTunnel(options: [String : NSObject]? = nil) throws` **(W)**,
  `.../nevpnconnection/startvpntunnel(options:).json`, 2026-11-01. `NETunnelProviderSession`
  (a subclass of `NEVPNConnection`, **header**) also has `startTunnelWithOptions:
  andReturnError:` with `NSDictionary<NSString *,id> *` ("A dictionary that will be passed
  as-is to the tunnel provider during the process of starting the tunnel") and `stopTunnel`;
  Swift `startTunnel(options: [String : Any]? = nil) throws` **(W)**. That
  `NETransparentProxyManager.connection` is an `NETunnelProviderSession` instance (so the
  cast works) is stated only in a search-result summary of a Quinn post **(S)**; the
  `connection` property's declared type is `NEVPNConnection` (`NEVPNManager.h`, **header**).
- **Options reach `startProxy(options:)` (header).** `NEAppProxyProvider.h`,
  `startProxyWithOptions:completionHandler:`: "options: A dictionary containing keys and
  values passed by the provider's containing app. If the containing app did not start the
  proxy then this parameter will be nil." DevForums 717140 (Oct 2022, **(DTS)** Quinn,
  **(W)**): the options come from the app's `startTunnel(options:)`; "These are the dynamic
  options, the ones that vary from connection-to-connection."; the options saved in the
  configuration are read from the provider's `protocolConfiguration`, not from `options`
  ("options always nil" was that poster's symptom when only `providerConfiguration` was
  set). `NETunnelProvider.h` on `protocolConfiguration`: "The value of this property may
  change during the lifetime of the tunnel ... KVO can be used to detect when changes
  occur"; Apple's page: "`NETunnelProvider` subclasses can observe this property using KVO
  to be notified when the configuration changes" **(W)**.
- **Value types of the start options: not documented in anything I read.** The two header
  declarations differ only by `id` versus `NSObject`; the `NEVPNConnection` header names
  two keys, `NEVPNConnectionStartOptionUsername` and `...Password` ("The value is a
  string"). The documented restriction is on the *saved* dictionary:
  `NETunnelProviderProtocol.providerConfiguration`, "All of the keys and values in this
  dictionary must conform to the NSSecureCoding and NSCopying protocols" **(W)**,
  `.../netunnelproviderprotocol/providerconfiguration.json`. (`NEAppPushManager.h` says
  "must be one of the data types supported by property list", but that is an iOS-only
  push-provider property.) Whether the start options carry the same restriction is
  **unverified**; strings and numbers are the only types any source exercises.
- **What exists today (tree).** `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`:
  `enableAndStartTunnel` (line 282) loads or creates the `NETransparentProxyManager`, sets a
  `NETunnelProviderProtocol` with `providerBundleIdentifier` and `serverAddress = "localhost"`
  (lines 285-287; **no `providerConfiguration`**), `saveToPreferences`, `loadFromPreferences`,
  then starts only when the status is not `.connected`, `.connecting` or `.reasserting`, and
  with **no options**: `manager.connection.startVPNTunnel()` (line 300). `disable()` (line 377)
  removes the status observer, calls `stopVPNTunnel()` (line 394), then `switchOff` saves
  `isEnabled = false` (lines 413-420). `observeTunnel` (line 321) maps
  `NEVPNStatusDidChange` through `applyTunnelStatus` (line 341): `.connected` becomes
  `.tunnelConnected`, `.disconnected` and `.invalid` become `.tunnelDisconnected`, and the
  intermediate states are ignored. In `CaptureCapability.applying`
  (`AitmproxyKit/CaptureCapability.swift:90-93`) `.tunnelDisconnected` turns `.capturing`
  into `.approvedAttached`, which `isCaptureOn` (line 104) still reads as "on". So a
  stop-then-start by the app would read `.capturing`, `.approvedAttached`, `.capturing`,
  never `.degraded`, **by reading the code, not by running it**. There is no restart-with-
  new-rules function today. The provider ignores its `options` parameter
  (`TransparentProxyProvider.swift:28`). The reconcile schedule is
  `TunnelReconcilePolicy.standard`: 2 s settle after a replacement, up to 4 attempts, 6 s
  connect window per attempt, backoff 1/2/4 s (`CaptureCapability.swift:155-161`).
- **Measured today.** The survey's control run (`capture-control.out`, **(local)**,
  13:44 PDT 2026-10-31) stopped the tunnel through Proxy > Disable Capture (provider log
  `stopProxy 1`, reason `NEProviderStopReasonUserInitiated`, then 0 flows seen for 12 s) and
  restarted it through Proxy > Enable Capture with no System Settings prompt; flows
  reached the provider again within the script's 10 s wait. It was not separately timed.
- **Start while `.disconnecting`: undocumented.** No source says whether
  `startVPNTunnel` right after `stopVPNTunnel` waits for the stop to finish; the header
  says only that each "returns immediately".
- **When the provider learns the scope: after `startProxy`.** `startProxy` begins looking for
  the core (`handoff.start()`, line 34) and applies the rules in the same call; the `Scope`
  push arrives later over the control link (`FlowHandoff.swift`, `ControlMessage`/`Scope`
  at lines 221-272, **(tree)**). At rule-application time the provider has no scope.

### 3.3 Q3: DevForums 770707 and the Chromium side

**The thread (W, 2026-11-01; two reads, the second asked for verbatim text).** Title as
rendered: "Cannot open Chrome UDP flows in Transparent Proxy Provider" (App & System Services
> Networking; tags Network Extension, QUIC). Created Dec 2024 by the poster Pelea; nine
replies; the page header says three participants (only Pelea's and Quinn's posts were
visible to me); day-level dates are not visible. The accepted answer is Pelea's own post of Jul 2026.

- *Setup.* A transparent proxy "for HTTPS (via TCP and QUIC)" with four included rules:
  `0.0.0.0` and `::`, port `443`, prefix 0, each for `.TCP` and `.UDP` (the deprecated
  `NWHostEndpoint` initializer). TCP worked; UDP flows from Chrome or Brave failed with
  `NEAppProxyFlowErrorDomain Code=2 "The peer closed the flow"` ("Doing the same for Firefox
  works!"; Safari also worked). **The poster's provider claims flows**; ours declines them.
- *Apple.* Quinn (Dec 2024) asked about Firefox and Safari. In Jul 2026 he (**(DTS)**) wrote
  that he found `FB18141248`, "which looks like it was filed by you (or perhaps one of your
  colleagues)"; asked for a "minimal NE provider test project" and a sysdiagnose "after
  reproducing the issue" with extra NE debugging ("It looks like you've done the first
  thing (thanks!) but not the second"); and, after the poster's finding, wrote "That's some
  excellent debugging! ... Thanks for that." **No workaround and no root-cause statement
  from Apple.**
- *The finding (Pelea, Jul 2026, marked accepted).* "on a flow-diverted UDP socket,
  `setsockopt(..., IPPROTO_IP, IP_DONTFRAG, ...)` and `setsockopt(..., IPPROTO_IP,
  IP_RECVTOS, ...)` fail with `ECONNRESET` (errno 54). Without the proxy, they succeed."
  Repro without Chrome: "create a UDP socket, connect() to any destination covered by the
  proxy's rules, then call setsockopt(..., IPPROTO_IP, IP_DONTFRAG, ...): It returns
  ECONNRESET whenever the transparent proxy is active." Chromium "aborts QUIC session
  creation on any failure". The poster's `change_fdguard_np` theory was tested and ruled out
  by the poster.
- *Feedback numbers.* `FB18141248` (cited by Quinn, thread does not say it covers this
  issue) and `FB23636906` ("Created new bug report", Pelea, Jul 2026, for the
  `IP_DONTFRAG`/`IP_RECVTOS` finding). Quinn noted that including the bug number
  "speeds things up" and pointed to his "Top Ten DevForums Tips" (tip 7).
- *What our survey adds to the thread.* The thread's rules cover UDP/TCP 443 and the
  provider claims flows. Survey §R4 ran a catch-all `.any` rule with a provider that
  **declines every flow** and saw the same `ECONNRESET` on every connected non-loopback UDP
  socket: UDP 443 to two destinations, UDP 53 (1.1.1.1 and the LAN resolver), UDP 123, and
  an IPv6 socket whose `connect` failed with `EHOSTUNREACH` (`IPV6_DONTFRAG`), loopback
  unaffected, `send()` still succeeding, and the same calls succeeding with the tunnel
  stopped (raw lines in note 25). The thread's `IP_RECVTOS` failure was not measured by the
  survey's script (**unmeasured on this Mac**).

**Chromium: failure is fatal for the session, not only the socket (W, 2026-11-01,
`chromium.googlesource.com/chromium/src/+/refs/heads/main/net/quic/quic_session_pool.cc`,
`refs/heads/main`; whether the shipping Chrome 156.0.8078.80 on this Mac, read from its
`Info.plist` **(local)**, has the same lines is unverified).** In
`QuicSessionPool::FinishConnectAndConfigureSocket`:

```cpp
rv = socket->SetDoNotFragment();
// SetDoNotFragment is not implemented on all platforms, so ignore errors.
if (rv != OK && rv != ERR_NOT_IMPLEMENTED) {
  OnFinishConnectAndConfigureSocketError(
      std::move(callback), QuicSocketConfigStep::kSetDoNotFragment, rv);
  return;
}
rv = socket->SetRecvTos();
if (rv != OK) {
  OnFinishConnectAndConfigureSocketError(
      std::move(callback), QuicSocketConfigStep::kSetReceiveEcn, rv);
  return;
}
```

(Indentation reconstructed; the comment says "ignore errors" but only `ERR_NOT_IMPLEMENTED`
is ignored.) `CreateSessionAsync` discards the step and forwards the code
(`std::move(cb).Run(rv);`), and `FinishCreateSession` returns before `CreateSessionHelper`
(`if (rv != OK) { CHECK_NE(rv, ERR_IO_PENDING); std::move(callback).Run(base::unexpected(rv));`),
so **no `QuicChromiumClientSession` is constructed**; the synchronous path records
`HistogramCreateSessionFailure(CREATION_ERROR_SETTING_DO_NOT_FRAGMENT)`. On POSIX,
`UDPSocketPosix::SetDoNotFragment` on macOS sets `IPV6_DONTFRAG` for an IPv6 socket and
`IP_DONTFRAG` otherwise and returns `MapSystemError(errno)` **(W)**,
`.../net/socket/udp_socket_posix.cc`; `SetRecvTos` sets `IP_RECVTOS` (and
`IPV6_RECVTCLASS` for v6) the same way; and `MapSystemError` sends `ECONNRESET` to
`ERR_CONNECTION_RESET` (`case ECONNRESET: case ENETRESET: case EPIPE: return
ERR_CONNECTION_RESET;`, **(W)**, `.../net/base/net_errors_posix.cc`). That matches the
survey's `net::ERR_CONNECTION_RESET` for a forced-QUIC origin. So the answer to "aborts the
connection or just the socket" is: the QUIC *session creation* aborts, so no handshake
starts, and the error is returned to the job that asked for it. How the job layer then
treats an Alt-Svc (not forced) attempt, and whether it marks the alternative service
broken, was **not visible** in my reads; the survey observed a normal load silently
falling back to HTTP/2 (survey §R4, third row).

**Why Firefox and Apple's stack tolerate it: not found.** Observations only:

- Firefox 158.0.1 **(local)** kept HTTP/3 with the proxy active (survey §R4b), and its UDP
  flows to `104.18.27.14:443` were declined by the provider in the framework log.
- Firefox's vendored `quinn-udp` `UdpSocketState::new` (`third_party/rust/quinn-udp/src/
  unix.rs`, **(W)** searchfox, 2026-11-01) applies options to a socket that already has a
  local address (`io.local_addr()?`) without connecting it in that function; on Apple it
  sets `IP_DONTFRAG` only `if is_ipv4`, via `set_socket_option_supported(...)?`, which
  returns `Ok(false)` only for `ENOPROTOOPT`/`EOPNOTSUPP` and otherwise propagates;
  `IP_RECVTOS` failure is ignored and logged ("Ignoring error setting IP_RECVTOS on
  socket"). So an `ECONNRESET` from `IP_DONTFRAG` would **not** be swallowed by that code
  (it would propagate). I did not find that Firefox on macOS uses that path (a search
  summary says the `quinn-udp` I/O path replaced NSPR and is on by default beyond Nightly,
  **(S)**), nor whether its socket is AF_INET or dual-stack AF_INET6 (which would take the
  `IPV6_DONTFRAG` branch). **Candidate explanation, an inference**: options applied *before*
  `connect()` succeed, because thread 770707 ties the failure to a socket "connect()"-ed to
  a covered destination, while Chromium applies them *after* `connect()`. A one-line
  variant of the repro (call `setsockopt` before `connect`) would test it; not run.
- Apple's own stack: a `URLSession` probe negotiated h3 with the proxy active (survey §R4b,
  `apple-h3.swift`, `apple-h3.out`); its source is closed. Not found. Safari is weaker
  evidence than the survey's conclusion suggests: only its first, always-TCP load was proven
  HTTP/2, and `apple-h3.out` lists a declined Safari UDP 443 flow to `cloudflare-quic.com`
  with no check that it completed h3.
- A second Apple thread, 775253 "Don't fragment bit doesn't get set in Sequoia" (Feb 2025,
  **(DTS)** Quinn, **(W)**), is a different defect (the DF bit not set on macOS 15 with SIP
  on, a `ping -D` regression, "I can reproduce the problems as you've described it ... but
  other internal folks can't"); no Feedback number appears. Not the same mechanism; listed
  so the Feedback does not conflate them.

### 3.4 Q4: what peers do about UDP in their rules

**mitmproxy local capture.** Its macOS redirector installs one included rule with protocol
`.any` (3.2, `TransparentProxyProvider.swift`, **(W)**), so its rule covers UDP, and it
decides per flow in a single `handleNewFlow`. The 2023-12-05 announcement says it uses
Apple's App Proxy Provider, which is "limited to TCP and UDP only" but "allows us to leave
some flows to the operating system to handle" (**(W)**,
`mitmproxy.org/posts/local-capture/macos/`; it never mentions QUIC). The docs' Local
Capture section (macOS part) lists one limitation, "Egress only", and says nothing about UDP,
QUIC or HTTP/3 (**(W)**, `docs.mitmproxy.org/stable/concepts/modes/`). The maintainer
(mhils, Discussion 7243, **(3P)**, **(W)**): "Transparent QUIC interception works in
WireGuard and local redirect mode"; Chromium "doesn't trust user-added CAs for HTTP/3"
(Discussion 7625); the QUIC status tracker (Issue 7025) has one macOS row, cURL, and no
Chrome row. I found **no public report that links mitmproxy's macOS local mode to
`IP_DONTFRAG`**; since the rule shape matches ours, whether it shares the defect is
**unverified**.

**Proxyman.** Its Network Extension "refuses that connection for traffic it handles" on UDP
443 so a client falls back to TCP (HTTP/2), and "does not decode native QUIC traffic"
(**(W)**, `proxyman.com/posts/how-to-capture-http3-traffic-chrome-macos`, dated 2026-10-15):
macOS 26 or later, Pro, "BETA, off by default", the fallback covers UDP 443 only, and an
HTTP/3-only client fails. That implies Proxyman's rules cover at least UDP 443; its rule
shapes are not public and I found no Proxyman note about `IP_DONTFRAG` or Chromium QUIC.
Note 22 and 23 record the product's other behaviour.

**Little Snitch (a different mechanism).** It is a Network Extension **content filter**,
not a transparent proxy: macOS asks "whether Little Snitch should be allowed to filter
network content", plus a system-extension approval (**(W)**,
`help.obdev.at/littlesnitch6/intro-install`, 2026-11-01); WWDC19 714 says a data filter
sees each new TCP or UDP flow as an `NEFilterFlow` and allows or drops it, read-only, and
cannot modify the flow (**(S)**). A content filter's rules are `NEFilterSettings`/`NEFilterRule` (headers in the SDK), not
`includedNetworkRules`, so none of the Q1 rule semantics apply to it. It is a useful control: the survey's machine ran Little Snitch 6.5 (a content
filter) alongside our provider (survey "Environment facts"), and with our provider stopped
`IP_DONTFRAG` and Chrome forced-QUIC succeeded (survey §R4), so an active content filter
alone does not cause the failure. Whether Little Snitch's own filter rules cover UDP 443 is
not public in what I read. Note 23 §3.3.8 has the longer comparison.

## 4. Implications for the spec (facts only)

1. **Rule shapes available.** A TCP-only catch-all is a rule with nil remote and nil local
   endpoints, `protocol: .TCP`, `direction: .outbound`; loopback is excluded by the header.
   A UDP rule for one scoped IP is an address-plus-prefix rule with `protocol: .UDP`,
   outbound, nil local; the port is the target's port or `0` (any), and a wildcard address
   needs a non-zero port. Port 53 cannot appear in an address rule. The rule count has no
   documented limit. `/32`, `/128` and the "prefix 0 with a specific network did not match"
   report (698626) mean the prefix on a host rule should be treated as unverified until
   measured.
2. **Which scope entries need a UDP rule today.** The provider's `ScopeMatcher` claims a UDP
   flow only through an IP token (`ip` or `ip:port`, optionally from the core's L4 scope),
   never for remote ports 53, 5353, 853, and never through a `host`, `host:port` or
   `*.suffix` token (`FlowHandoff.swift:506-511, 529-544`, **(tree)**). A UDP rule that
   matches what the provider can claim is therefore one per IP token; hostnames never need
   one.
3. **Rule application time.** `startProxy` applies the rules before the core pushes any
   scope, so the provider has no scope at that moment (3.2).
4. **Runtime replacement is undocumented for rules and contradicted by one DTS reply.** For:
   the macOS 27 header ("can be called multiple times during the lifetime of a particular
   tunnel") and a 2020 DTS reply ("settings can be reloaded"). Against: a 2022 DTS reply
   ("needs to be restarted for any rules you add/remove to take affect"). Silent: what
   happens to flows already routed, whether `reasserting` is needed (the header describes
   it as a status flag only). Not measured on macOS 27 by us or by any source I found. The
   one public provider I could read (mitmproxy_rs) never re-applies.
5. **Restart fallback.** The host app starts and stops with `startVPNTunnel(options:)` /
   `stopVPNTunnel()` (or the `NETunnelProviderSession` forms); options arrive as
   `startProxy(options:)`, nil when the app did not start the proxy; the value-type rule for
   start options is undocumented, and the saved `providerConfiguration` must be
   `NSSecureCoding` and `NSCopying`. Today's app passes no options and sets no
   `providerConfiguration`; the provider ignores `options`. Both `stopVPNTunnel` and
   `startVPNTunnel` return immediately and the status arrives through
   `NEVPNStatusDidChange`. Starting while `.disconnecting` is undocumented. DTS says
   repeated hot restarts are "not a recommended path"; `startProxy` can run twice on macOS
   26+ (FB21464147). A stop and start through the app's own Disable/Enable path was
   observed to need no prompt.
6. **Effect of a TCP-only rule on `IP_DONTFRAG`: not measured.** The defect was measured
   with `.any`; thread 770707's mechanism ("flow-diverted UDP socket", sockets "covered by
   the proxy's rules") suggests a TCP-only rule leaves UDP sockets alone, but no source
   confirms it, and thread 698626 reports Chrome breaking over IPv6 beside a TCP-only rule
   pair on a provider that returned `false` (2022, pre-macOS 15, unresolved, **(3P)**).
7. **What the Apple Feedback should cite.** Thread 770707 and its two numbers
   (`FB23636906`, `FB18141248`); the difference from the thread (catch-all rule, provider
   declines every flow, also UDP 53 and 123, IPv6, control with the tunnel stopped, Firefox
   and `URLSession` unaffected, Safari unproven); Quinn's two asks (minimal provider project, NE
   debug sysdiagnose); that `IP_RECVTOS` is reported failing too and unmeasured here. Draft in
   note 25.

## 5. Candidate directions (for the Architect, not decisions)

- **A. TCP-only catch-all by default, UDP rules decided at tunnel start, changes by a
  host-app restart.** Evidence for: the only DTS statement on changing rules says restart;
  the restart path and its capability mapping exist; mitmproxy_rs-style fixed rules are
  proven in the field. Cost: UDP scope changes interrupt claimed flows and cost the
  reconcile time (~33 s worst case per the policy comment; the survey's disable/enable cycle
  finished within the script's 10 s wait); the provider needs the UDP IP list when it applies
  the rules, and the core's `Scope` push arrives after `startProxy` today, so it would have
  to come from start options, from `providerConfiguration` (read via `protocolConfiguration`),
  or from deferring the rule application until the core attaches (that last one is
  untested against the `startProxy` completion contract); the Tahoe double-`startProxy`
  bug applies; DTS discourages repeated hot restarts.
- **B. Same rule shapes, but the provider re-calls `setTunnelNetworkSettings` in place when
  the core pushes a scope with or without a UDP IP.** Evidence for: header text and the
  2020 DTS reply. Against: the 2022 DTS reply, no statement about existing flows, the
  Tahoe double-call crash; untested on macOS 27. It needs an experiment before it can be
  chosen, and A is its fallback if the replacement does not take effect.
- **C. Static TCP-only rule, UDP never routed through the NE** (UDP L4 targets stay on the
  L4 lanes, not the NE). Evidence for: removes the defect and the rule-change problem at
  once; a UDP rule is also the only thing that ever engaged the mbuf-leak report (762804,
  fixed by 15.1 by the poster's account). Cost: it drops the spec's own "UDP rule when
  scoped" behaviour, so it is Matt's call.
- **D. Keep `.any` and add `excludedNetworkRules` for UDP 443** (spec option (b)).
  Evidence against: the header gives no exclusion precedence, 677981 reports hostname
  exclusions with no visible effect, port 53 cannot be written as an address rule, and
  UDP 53 and 123 sockets are hit by the defect too (survey §R4), so excluding 443 would
  not clear them.

## 6. Open questions

1. Does re-calling `setTunnelNetworkSettings` with changed `includedNetworkRules` take
   effect on macOS 27, for new flows and for flows already routed, and does removing the UDP
   rule restore `IP_DONTFRAG` on existing sockets? Needs an experiment on a real Mac
   (provider that swaps rules after N seconds, then `dontfrag-core.py` before and after).
2. With a TCP-only nil-remote rule, does `IP_DONTFRAG` succeed on every UDP socket, and does
   Chrome keep HTTP/3 and work over IPv6 (the 698626 symptom)? Not measured.
3. With a UDP rule for one IP, does only a socket connected to that IP fail
   `IP_DONTFRAG`? Do `/32` and `/128` host rules match a single host?
4. Do the options fail only after `connect()`? (a repro variant; also explains Firefox if so)
5. Does `IP_RECVTOS` fail on this Mac as the thread reports?
6. Do flows a provider declined (going direct) survive `stopVPNTunnel`, and what happens to
   claimed flows? Is starting during `.disconnecting` safe?
7. Value types allowed in `startVPNTunnel(options:)`; whether changing `providerConfiguration`
   (a `saveToPreferences` on a running tunnel) reaches the provider through KVO on
   `protocolConfiguration` without a restart. Documented hooks exist (KVO, and
   `handleAppMessage`/`sendProviderMessage` in `NETunnelProvider.h` and
   `NETunnelProviderSession.h`); behaviour not measured.
8. Does mitmproxy's macOS local mode (one `.any` rule) show Chromium QUIC failing? No report
   found either way.
9. Has Apple responded to `FB23636906`, and does it cover declined flows? The thread shows
   no Apple statement of cause or fix as of Jul 2026.
10. Why Firefox (`quinn-udp`) and Apple's stack tolerate it: not found (3.3).

## 7. Sources

First-hand on this Mac, read 2026-11-01 (**header**): `H=$(xcrun --show-sdk-path --sdk
macosx)/System/Library/Frameworks/NetworkExtension.framework/Headers`:
`$H/NENetworkRule.h`, `$H/NETransparentProxyNetworkSettings.h`,
`$H/NETransparentProxyProvider.h`, `$H/NEAppProxyProvider.h`, `$H/NETunnelProvider.h`,
`$H/NETunnelProviderSession.h`, `$H/NEVPNConnection.h`, `$H/NEVPNManager.h`,
`$H/NETunnelProviderProtocol.h`, `$H/NEProvider.h`, `$H/NEAppPushManager.h`;
`.../Modules/NetworkExtension.swiftmodule/arm64e-apple-macos.swiftinterface`.
**(local)** `Info.plist` versions of Chrome 156.0.8078.80, Firefox 158.0.1, Safari 27.0;
`sw_vers` 27.0 (26A428); `xcodebuild -version` Xcode 27.1 (27A9269).

Repo **(tree)** at `ecbf58ac`: `apps/mac/Extension/Sources/TransparentProxyProvider.swift`,
`apps/mac/Extension/Sources/FlowHandoff.swift`,
`apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`,
`apps/mac/Sources/AitmproxyKit/CaptureCapability.swift`;
`docs/research/experiments/2026-10-31-macos-ne-observe-survey.md`;
`docs/superpowers/specs/2026-10-31-macos-ne-observe-only-lane-design.md` (Open question 9);
`docs/research/10-macos-network-extension.md`, `docs/research/23-macos-observe-only-lane.md`.
Survey raw outputs (unmerged branch, read with `git show`):
`origin/experiment/macos-ne-observe-survey:spike/observe-survey/dontfrag-core.py`,
`.../results/dontfrag-variant1.out`, `.../results/capture-control.out`,
`.../results/gui-quic-variant1.out`.

Apple docs (JSON endpoint), read 2026-11-01:
- https://developer.apple.com/tutorials/data/documentation/networkextension/netransparentproxynetworksettings/includednetworkrules.json
- https://developer.apple.com/tutorials/data/documentation/networkextension/nenetworkrule.json
- https://developer.apple.com/tutorials/data/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:).json
- https://developer.apple.com/tutorials/data/documentation/networkextension/netunnelprovider/reasserting.json
- https://developer.apple.com/tutorials/data/documentation/networkextension/netunnelprovider/protocolconfiguration.json
- https://developer.apple.com/tutorials/data/documentation/networkextension/netunnelprovidersession/starttunnel(options:).json
- https://developer.apple.com/tutorials/data/documentation/networkextension/nevpnconnection/startvpntunnel(options:).json
- https://developer.apple.com/tutorials/data/documentation/networkextension/netunnelproviderprotocol/providerconfiguration.json
- https://developer.apple.com/tutorials/data/documentation/networkextension/netransparentproxyprovider.json

Apple DevForums, read 2026-11-01:
- https://developer.apple.com/forums/thread/770707 (Chrome UDP flows; `IP_DONTFRAG`; FB23636906, FB18141248)
- https://developer.apple.com/forums/thread/699972 (update rules on the run: restart)
- https://developer.apple.com/forums/thread/659298 (`setTunnelNetworkSettings` again)
- https://developer.apple.com/forums/thread/98366 (update tunnel network settings)
- https://developer.apple.com/forums/thread/668369 (mid-stream, accountsd)
- https://developer.apple.com/forums/thread/717140 (`startProxy` options)
- https://developer.apple.com/forums/thread/698626 (IPv6 problem, prefix 0)
- https://developer.apple.com/forums/thread/677981 (`excludedNetworkRules`)
- https://developer.apple.com/forums/thread/762804 (UDP rule, mbufs; FB14844573)
- https://developer.apple.com/forums/thread/811866 (`startProxy` twice on Tahoe; FB21464147)
- https://developer.apple.com/forums/thread/775253 (DF bit on Sequoia)
- https://developer.apple.com/forums/thread/742655 (read; nothing on runtime rules)
- https://developer.apple.com/forums/tags/networkextension?page=3 (tag page)

Chromium and Firefox source, read 2026-11-01:
- https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/quic/quic_session_pool.cc
- https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/socket/udp_socket_posix.cc
- https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/base/net_errors_posix.cc
- https://searchfox.org/firefox-main/source/third_party/rust/quinn-udp/src/unix.rs
- https://searchfox.org/firefox-main/source/third_party/rust/neqo-udp/src/lib.rs (truncated; no socket setup visible)

Peers, read 2026-11-01:
- https://github.com/mitmproxy/mitmproxy_rs/blob/main/mitmproxy-macos/redirector/network-extension/TransparentProxyProvider.swift
- https://www.mitmproxy.org/posts/local-capture/macos/
- https://docs.mitmproxy.org/stable/concepts/modes/
- https://github.com/mitmproxy/mitmproxy/discussions/7243
- https://github.com/mitmproxy/mitmproxy/discussions/7625
- https://github.com/mitmproxy/mitmproxy/issues/7025
- https://proxyman.com/posts/how-to-capture-http3-traffic-chrome-macos
- https://help.obdev.at/littlesnitch6/intro-install
- https://developer.apple.com/videos/play/wwdc2019/714/ (search summary only)
