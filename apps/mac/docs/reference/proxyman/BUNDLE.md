# Proxyman bundle anatomy (read-only)

Reference for aitmproxy's macOS app. Every fact below was produced by the
command quoted next to it, run against `/Applications/Proxyman.app`
(Proxyman 26.3.0, build 260300) on 2026-10-31. Nothing was patched, launched
or licensed; the app was not running during the inspection.

Companion documents: [FLOWS.md](FLOWS.md) (operator flows and prompts),
[SCREENS.md](SCREENS.md) (screen index, when captured), [DELTA.md](DELTA.md)
(what aitmproxy does differently).

## 1. Layout

```
ls Contents Contents/MacOS Contents/Library; find Contents/Library -maxdepth 3
```

| Path | What |
|---|---|
| `Contents/MacOS/Proxyman` (19 MB) | the app |
| `Contents/MacOS/mcp-server` (5.3 MB) | stdio MCP server, launched by the agent, talks to the app over a local bridge |
| `Contents/MacOS/proxyman-cli` (2.7 MB) | CLI for scripts and agents |
| `Contents/Library/LaunchServices/com.proxyman.NSProxy.HelperTool` (190 kB) | privileged helper (launchd daemon) |
| `Contents/Library/SystemExtensions/com.proxyman.NSProxy.PacketTunnel.systemextension` (512 kB) | the Network Extension |
| `Contents/Frameworks/ProxymanCore.framework` | the proxy engine (SwiftNIO + BoringSSL, see §10) |
| `Contents/Frameworks/{Sparkle,Sentry,HexFiend,ProtobufCore}.framework` | updates, crash reports, hex view, protobuf |
| `Contents/Resources/InternetAccessPolicy.plist` | Little Snitch access policy (declares every outbound host) |
| `Contents/embedded.provisionprofile` | Developer ID profile with NE entitlements |

What this means for aitmproxy: one app bundle carries all four privileged or
agent-facing pieces. Our DMG should do the same (helper + extension + MCP
binary inside `Aitmproxy.app`), nothing installed by hand.

## 2. Info.plist

```
plutil -p Contents/Info.plist
```

| Key | Value |
|---|---|
| `CFBundleIdentifier` | `com.proxyman.NSProxy` |
| `CFBundleShortVersionString` / `CFBundleVersion` | `26.3.0` / `260300` |
| `LSMinimumSystemVersion` | `14.0` |
| `LSUIElement` | **absent**: Proxyman is a regular Dock app; the menu-bar extra is optional (§9) |
| `CFBundleURLSchemes` | `proxyman` (handlers seen in strings: `proxyman://action`, `proxyman://activate`, `proxyman://github-callback`, `proxyman://workspace-login`) |
| `SMPrivilegedExecutables` | `com.proxyman.NSProxy.HelperTool` → `anchor apple generic and identifier "com.proxyman.NSProxy.HelperTool" and (certificate leaf[field.1.2.840.113635.100.6.1.9] or certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "3X57WP8E8V")` |
| `NSSystemExtensionUsageDescription` | "Capture HTTP and HTTPS from apps that do not use the system proxy." |
| `NSAppleEventsUsageDescription` | "Proxyman needs to use AppleScript to run a pre-configured script for Automatic Setup or Android Emulator Setup." |
| `NSAppTransportSecurity` | `NSAllowsArbitraryLoads = true` |
| `SUFeedURL` / `SUEnableAutomaticChecks` | `https://proxyman.com/osx/version.xml` / `false` (Sparkle, manual check) |
| `CFBundleDocumentTypes` | `.proxymanlog`, `.proxymanlogv2`, `.proxymansession`, `.proxymansessionv2`, `.har`, Charles `.chls/.chlsj/.chlz` |
| `LSApplicationCategoryType` | `public.app-category.developer-tools` |

What this means for aitmproxy: `SMPrivilegedExecutables` in the app plus
`SMAuthorizedClients` in the helper (§3) is the SMJobBless pairing; the
requirement string pins the helper to the team's Developer ID certificate.
The usage-description strings are the words macOS shows in its own prompts,
so they are operator-facing copy and belong in our design review.

## 3. Privileged helper: `com.proxyman.NSProxy.HelperTool`

### 3.1 Identity and embedded plists

```
H=Contents/Library/LaunchServices/com.proxyman.NSProxy.HelperTool
codesign -dvvv $H
launchctl plist __TEXT,__launchd_plist $H
launchctl plist __TEXT,__info_plist $H
```

- `Identifier=com.proxyman.NSProxy.HelperTool`, `TeamIdentifier=3X57WP8E8V`,
  `Format=Mach-O universal (x86_64 arm64)`, flags `runtime` (hardened).
- Embedded launchd plist:
  `Label = com.proxyman.NSProxy.HelperTool`,
  `MachServices = { com.proxyman.NSProxy.HelperTool = true }`,
  `AssociatedBundleIdentifiers = (com.proxyman.NSProxy, com.proxyman.NSProxy-setapp)`.
  No `KeepAlive`, no `RunAtLoad`: launchd starts it on demand when the app
  connects to the Mach service.
- Embedded Info.plist: `CFBundleShortVersionString = 1.7.0`,
  `PMHelperToolVersion = 1.7.0`, `SMAuthorizedClients` = the same designated
  requirement for `com.proxyman.NSProxy` and `com.proxyman.NSProxy-setapp`.
- There is **no** `Contents/Library/LaunchDaemons/*.plist` in the bundle:
  the launchd plist lives only in the `__TEXT,__launchd_plist` section, which
  is exactly what `SMJobBless` consumes.

### 3.2 SMJobBless-era, with an SMAppService status probe

```
nm -u -arch arm64 Contents/MacOS/Proxyman | grep -E 'SMJobBless|SMAppService'
strings -a Contents/MacOS/Proxyman | grep -E 'SMAppService|PrivilegedHelperTools|LaunchDaemons|Helper Tool Status'
```

- The app imports `_SMJobBless` **and** `_OBJC_CLASS_$_SMAppService`.
- Strings: `/Library/PrivilegedHelperTools/%@`, `/Library/LaunchDaemons/`,
  `[SMAppService] statusForLegacyPlist = `, `Helper Tool Status: Installed`,
  `Helper Tool Status: Need Allow in System Setting`,
  `Helper Tool Status: Need Update`, `Helper Tool Status: Not Install`,
  `Required your permission to properly work in Login Items`,
  `Open Login Items`.
- ProxymanCore carries the uninstall recipe as a shell fragment:
  `rm /Library/PrivilegedHelperTools/` … ` && rm /Library/LaunchDaemons/`.
- Not installed on this Mac (`ls /Library/PrivilegedHelperTools /Library/LaunchDaemons | grep -i proxyman` is empty;
  `defaults read com.proxyman.NSProxy` shows `IsPresentHelperToolInstaller = 1`,
  `IsOverridenMacOSProxy = 0`).

Reading: installation is classic **SMJobBless** (admin Authorization prompt,
copies the helper to `/Library/PrivilegedHelperTools`, writes the launchd plist
to `/Library/LaunchDaemons`). On macOS 13+ the app then calls
`SMAppService.statusForLegacyPlist` to learn whether Login Items has the
daemon enabled, and shows "Need Allow in System Setting" with an "Open Login
Items" button when it does not. This is the "Comply with new macOS 13 Ventura
Requirements for Helper Tool" line of the install sheet.

### 3.3 XPC protocol and what the helper can do

```
strings -a $H | grep -E 'Proxy|Authorization|xpc|Protocol'
nm -u -arch arm64 $H
otool -L $H
```

Exported protocol `HelperToolProtocol`, three selectors:

| Selector | Authorization right |
|---|---|
| `getVersionWithReply:` | none |
| `overrideProxySystemWithAuthorization:setting:reply:` | `com.proxyman.NSProxy.HelperTool.overrideProxySystemWithAuthorization` |
| `revertProxySystemWithAuthorization:restore:reply:` | `com.proxyman.NSProxy.HelperTool.revertProxySystemWithAuthorization` |

- The right's prompt text (shown by macOS in the auth dialog):
  **"Proxyman is trying to override Proxy config in System Preferences."**
  Rights are registered with `AuthorizationRightSet` on first use
  (`setupAuthorizationRights:`, `authRightDefault`, `authRightDescription`).
- Setting object class `EPProxyModifiy` with keys `http`, `https`, `socks`,
  `port`, `isEnabled`, `exceptionList`; state `originalNetworkSetting` /
  `orverrideNetworkSetting` (sic).
- Writes the proxy through **SystemConfiguration, not `networksetup`**:
  imports `SCPreferencesCreateWithAuthorization`, `SCPreferencesPathSetValue`
  (path format `/%@/%@/%@`, i.e. `/NetworkServices/<service-id>/Proxies`),
  `SCPreferencesCommitChanges`, `SCPreferencesApplyChanges`,
  `SCPreferencesSynchronize`. Log lines: `Overriding proxy system with new
  settings`, `Successfully overrode proxy system`, `Override network settings
  for device %{public}@: %{public}@`, `Reverting proxy system with restore:
  %{public}d`, `Revert network settings for device …`.
- Client validation before accepting an XPC connection:
  `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity` +
  `SecTaskValidateForRequirement` against the `SMAuthorizedClients`
  requirement, and it refuses callers without hardened-runtime flags:
  `ERROR: invalid code signing flags. Missing kSecCodeSignatureLibraryValidation
  or kSecCodeSignatureForceHard`.
- Links only CFNetwork, Foundation, AppKit, SystemConfiguration, Security.

### 3.4 Crash restore

```
strings -a $H | grep -E 'timer|PID|proc_'
nm -u -arch arm64 $H | grep -E 'proc_|sysctl'
```

Selectors `setConnectionPID:`, `startTimer`, `stopTimer`, `timerOnTick`,
`scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:`, and imports
`proc_listpids`, `proc_pidpath`, `sysctl`, `runningApplicationWithProcessIdentifier:`.
Together with `originalNetworkSetting` this is the whole mechanism: the helper
remembers the caller's PID and the pre-override proxy dictionary, polls on a
timer, and when the PID is gone it applies the original setting itself. That
is the install sheet's "Graceful Revert the Proxy if the app is crashed
unexpectedly" and "Persist and Restore to your previous Proxy setting".

### 3.5 Fallback without the helper

```
strings -a Contents/Frameworks/ProxymanCore.framework/ProxymanCore | grep networksetup
```

`networksetup -setwebproxy "`, `networksetup -setsecurewebproxy "`,
`networksetup -setwebproxystate "`, `networksetup -setsecurewebproxystate "`.
UI copy: `Your HTTP/HTTPS Proxy is currently overridden by `networksetup` CLI.
It works, but slow!`, `Proxy Helper tool is better performance than using
networksetup CLI`, and the status-bar badge text `Overridden by %@`
(`networksetup` CLI or Proxy Helper Tool). The docs add that for a non-admin
or guest user `networksetup` fails outright, which is the second reason for
the helper.

What this means for aitmproxy:

- The **system proxy is a helper job, not an extension job**. A ~200 kB
  Objective-C daemon with two authorized verbs (override, revert), writing
  `SCPreferences` with an `AuthorizationRef`, is all Proxyman needs. The
  admin password is asked **once**, at install, by macOS's own SMJobBless
  dialog; later launches never prompt because the daemon is already root.
- Crash safety lives in the daemon (PID watch + stored original), not in the
  app. Our `aitm-sysproxy` must do the same or a crashed app leaves the Mac
  pointing at a dead port (which is what happened tonight with Proxyman
  itself when it quit while another copy still "owned" the override).
- Expect two macOS surfaces: the Authorization dialog at install, and on
  macOS 13+ a Login Items toggle the app must detect and explain
  (`statusForLegacyPlist`). SMAppService.daemon would replace SMJobBless for a
  new app; Proxyman keeps the legacy path for upgrade continuity.
- Keep a `networksetup` fallback only as a degraded mode with a visible
  "slow / needs admin" warning, exactly as Proxyman words it.

## 4. Network Extension: `com.proxyman.NSProxy.PacketTunnel`

```
X=Contents/Library/SystemExtensions/com.proxyman.NSProxy.PacketTunnel.systemextension
plutil -p $X/Contents/Info.plist
nm -u -arch arm64 $X/Contents/MacOS/com.proxyman.NSProxy.PacketTunnel | grep -E 'NE|nw_'
strings -a $X/Contents/MacOS/com.proxyman.NSProxy.PacketTunnel | swift demangle | grep -o 'com_proxyman_NSProxy_PacketTunnel\.[A-Za-z]*' | sort -u
otool -L $X/Contents/MacOS/com.proxyman.NSProxy.PacketTunnel
```

- `CFBundlePackageType = SYSX`, `LSMinimumSystemVersion = 26.0`
  (the app itself allows 14.0; the extension is macOS 26 only, matching the
  UI string `Network Extension capture requires macOS 26 or later.`).
- `NetworkExtension.NEProviderClasses =
  { com.apple.networkextension.app-proxy =
    com_proxyman_NSProxy_PacketTunnel.TransparentProxyProvider }`.
  Despite the bundle name "PacketTunnel", the provider class is a
  **`NETransparentProxyProvider`** (an app-proxy provider in transparent
  mode), not a packet tunnel and not a content filter.
- `NSSystemExtensionUsageDescription = "Redirect traffic to Proxyman"`.
- Imports: `NETransparentProxyProvider`, `NETransparentProxyNetworkSettings`,
  `NENetworkRule`, `NEAppProxyTCPFlow` (UDP flow class referenced in Swift
  metadata too), `handleNewFlow:`, `setIncludedNetworkRules:`.
- Flow metadata read: `sourceAppSigningIdentifier`, `sourceAppAuditToken`,
  `processID`, `processPath`, `remoteEndpoint`; and config keys
  `excludedPorts`, `excludedProcessIDs`.
- Swift types: `TransparentProxyProvider`, `TransparentTCPRelay`,
  `TransparentFlowStream`, `TransparentNetworkStream`,
  `TransparentByteStream`, `TransparentCaptureConnection`; constants
  `com.proxyman.transparent-provider`, `com.proxyman.transparent-relay(s)`.
- Human strings: `The Proxyman capture server is unavailable.`, `The Network
  Extension session could not be authenticated.`, `Invalid Network Extension
  connection metadata.`, `Update Proxyman to communicate with the installed
  Network Extension.`
- Links NetworkExtension, Network (nw_connection relay), Foundation, Swift
  runtime only. No TLS, no HTTP parser: the extension **relays bytes** to the
  app's capture server and the app does the MITM.
- App side (ProxymanCore): `TransparentProxyIngress`,
  `TransparentProxyHandshake`, `TransparentProxyControlMessage`,
  `TransparentProxySession`, `TransparentProxyFlowMetadata`,
  `TransparentProxyStatus`; the app imports `NETransparentProxyManager`
  (`loadAllFromPreferences`, `saveToPreferences`, `removeFromPreferences`,
  `providerBundleIdentifier`, `serverAddress`) and
  `OSSystemExtensionManager` / `OSSystemExtensionRequest` /
  `OSSystemExtensionsWorkspace` for activation.
- UI strings that encode the state machine: `Network Extension is waiting for
  approval`, `Network Extension needs a restart`, `Restart your Mac to
  finish`, `Another copy of Proxyman replaced the Network Extension. Quit the
  other copy, then turn Network Extension on again.`, `A Network Extension
  operation is already in progress. Read status and complete any macOS
  approval first.`, `In General → Login Items & Extensions, scroll down to
  Extensions, choose By Category, click ⓘ next to Network Extensions, then
  turn on Proxyman.`, `Network Extension and the system proxy can't run at the
  same time. Turning on Network Extension turns off the system proxy.`,
  `Network Extension is capturing HTTP and HTTPS from all apps on this Mac.`,
  `Buy Pro to unlock Network Extension capture.`
- Not installed on this Mac: `systemextensionsctl list` shows no
  `3X57WP8E8V` entry (`defaults` has `NetworkExtensionCaptureEnabled = 0`).

What this means for aitmproxy:

- **Per-app attribution comes from the transparent proxy provider**:
  `NEAppProxyFlow.metaData.sourceAppSigningIdentifier` /
  `sourceAppAuditToken` give the bundle id and audit token of the process that
  opened the socket, which is how Proxyman's Apps sidebar gets `Codex
  (Service)` or `dataaccessd` with a real icon. A packet-tunnel provider sees
  only IP packets and cannot do this; a content filter can see the app but
  cannot redirect the bytes. Our `com.mrbrutti.aitmproxy.ne` is the same
  provider type, so the data is there.
- Proxyman's extension is deliberately dumb (relay + metadata); decryption,
  HTTP parsing and the UI stay in the app. Keep ours the same: the extension
  must never need the CA key.
- Proxyman treats NE and system proxy as **mutually exclusive** and tells the
  operator which one is on in the status bar. Our "Proxy" and "All Apps"
  switches should state the same rule in one sentence.
- The macOS prompts are: the system-extension approval (Login Items &
  Extensions ▸ Network Extensions), the "add network configuration / VPN"
  Allow, and possibly a reboot. Proxyman names every one of them in a UI
  string; so should we.

### 4b. App attribution without the extension

```
nm -u -arch arm64 Contents/Frameworks/ProxymanCore.framework/ProxymanCore | grep -E 'proc_|sysctl|NSRunningApplication'
strings -a -arch arm64 Contents/Frameworks/ProxymanCore.framework/ProxymanCore | grep -E 'ProcessNameForPID|Client'
```

The demo video and Matt's screenshots show a real icon and name in the
`Client` column for **plain system-proxy flows**, with no Network Extension
installed (`iStat Menus Menubar`, `Proxyman` itself, `Codex (Service)`).
ProxymanCore imports `proc_listpids`, `proc_pidinfo`, `proc_pidfdinfo`,
`proc_name`, `proc_pidpath`, `sysctl`, `sysctlbyname`, and
`NSRunningApplication`; symbols `macProcessNameForPID:`,
`fullKernelProcessNameForPID:`, `clientName`, and the Swift initializer
`ProxymanCore.Client.init(name:bundlePath:icon:)`. That is the libproc
recipe: for a loopback connection whose peer port is known, walk
`proc_listpids`, ask `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` for each socket
until one matches the client's local port, then `proc_pidpath` → bundle →
`NSRunningApplication(processIdentifier:)` for `localizedName` and `icon`
(`iconForFile:` as the fallback for bare executables such as `dataaccessd`).
No privilege is needed for the user's own processes; system daemons resolve
by name only.

What this means for aitmproxy: the `Client —` column in every proxied flow
of our app (see DELTA.md) is not waiting on the extension. The core (or the
Mac app, from the flow's `client` address `127.0.0.1:<port>`) can resolve
the owning process the same way; the extension then only adds the apps that
never touch the proxy.

## 5. Entitlements

`codesign -d --entitlements :- <path>` prints `binary contains an invalid
entitlements blob` for every Proxyman binary on this macOS (both inside the
sandbox and from the Terminal). The XML blob is still present in the code
signature; it was read with a 40-line Python parser of the `LC_CODE_SIGNATURE`
superblob (slot magic `0xfade7171`), and `codesign -d --entitlements - --xml`
from the Terminal agrees:

```
codesign -d --entitlements - --xml <path> | plutil -p -
```

| Binary | Entitlements |
|---|---|
| `Proxyman` | `com.apple.application-identifier = 3X57WP8E8V.com.proxyman.NSProxy`; `com.apple.developer.networking.networkextension = [app-proxy-provider-systemextension]`; `com.apple.developer.system-extension.install = true`; `com.apple.developer.team-identifier`; `com.apple.security.automation.apple-events = true` |
| `HelperTool` | `com.apple.application-identifier = 3X57WP8E8V.com.proxyman.NSProxy.HelperTool` only |
| `PacketTunnel` sysext | `application-identifier = 3X57WP8E8V.com.proxyman.NSProxy.PacketTunnel`; `networkextension = [app-proxy-provider-systemextension]`; `team-identifier` |
| `mcp-server` | `application-identifier = 3X57WP8E8V.` (team prefix only) |
| `proxyman-cli` | `application-identifier = 3X57WP8E8V.com.proxyman.NSProxy.CLI` |

No app sandbox, no `keychain-access-groups` in the signed entitlements, no
`com.apple.security.cs.*` exceptions. The provisioning profiles
(`openssl smime -verify -noverify -inform der -in Contents/embedded.provisionprofile | plutil -p -`)
are wider than what is signed: team `3X57WP8E8V` ("TablePlus Inc"), profile
"Proxyman - Production", `networkextension = [packet-tunnel-provider-systemextension,
app-proxy-provider-systemextension, content-filter-provider-systemextension,
dns-proxy-systemextension, dns-settings, relay, url-filter-provider,
hotspot-provider]`, `vpn.api = [allow-vpn]`, `keychain-access-groups =
3X57WP8E8V.*`; the extension's profile adds
`com.apple.security.application-groups = 3X57WP8E8V.*`.

What this means for aitmproxy: the minimum entitlement set for the whole
Proxyman story is tiny: `system-extension.install` + `networkextension:
app-proxy-provider-systemextension` on the app, the same NE entitlement on the
extension, nothing on the helper. The Apple-events entitlement exists only for
the "Automatic Setup" AppleScript into Terminal/Chrome, which we do not need.
Our NE App IDs already carry the app-proxy capability (see
`aitmproxy-a1-asc-automation`).

## 6. Certificate authority

```
strings -a Contents/Frameworks/ProxymanCore.framework/ProxymanCore Contents/MacOS/Proxyman \
  | grep -iE 'add-trusted-cert|Keychain|Proxyman CA|-ca\.pem|SecTrust'
nm -u -arch arm64 Contents/Frameworks/ProxymanCore.framework/ProxymanCore | grep -E 'Sec(Item|PKCS12|Certificate|Identity)'
ls "$HOME/Library/Application Support/com.proxyman.NSProxy"
```

- Generated in-process with BoringSSL (`proxyman-ca.srl`, `-ca.pem`,
  `-certificate.pem`, `.p12` naming; `CN=%@`), stored under
  `~/Library/Application Support/com.proxyman.NSProxy/certificates/`
  (that folder exists here and is empty, matching the Settings label
  `Proxyman CA (not installed)` Matt saw; the `defaults` key
  `IsOpenProxymanFirstTime = 0` shows the app has been launched).
- Two install paths, both through the `security` CLI (the docs page
  `/docs/debug-devices/macos` names the tabs):
  - **Automatic** tab, button `Install & Trust Certificate`: runs
    `security add-trusted-cert -r trustRoot …` inside an AppleScript
    `do shell script "…" with administrator privileges` (both fragments are
    in the binary, which is what the `com.apple.security.automation.apple-events`
    entitlement is for). macOS shows its own **administrator password**
    dialog; no sudo, no Terminal. Settings copy: `Automatically Trust
    Proxyman Certificate in your Keychain Access (Require root privileges)`.
    The `sudo security add-trusted-cert -d -r trustRoot -k
    /Library/Keychains/System.keychain "…"` string is the same command in
    its system-keychain form.
  - **Manual** tab, button `Generate and Add…`: `SecItemAdd` into the
    keychain without trust and without a password (macOS may ask which
    keychain, `Make sure you Select System or Login Keychains.`), then the
    operator opens Keychain Access and sets `Always Trust` (`1. Open
    "Keychain Access" app -> Search "Proxyman CA" -> Double-click to Open`,
    `2. Select "Always Trust" -> Close this Windows & Save`).
  - A user-keychain variant also exists:
    `security add-trusted-cert -r trustRoot -k $(security default-keychain -d user | sed 's/"//g') "<path>/proxyman-ca.pem"`.
  Removal: `security find-certificate -c "<name>" -a -Z | awk '/SHA-1/{system("security delete-certificate -Z "$NF)}'`.
- Programmatic APIs imported for custom CAs: `SecItemAdd`, `SecPKCS12Import`,
  `SecCertificateCreateWithData`, `SecIdentityCopyCertificate`;
  `SecTrustSettingsSetTrustSettings` is **not** imported: trust is only ever
  set by `security add-trusted-cert`, which is why macOS shows its own
  keychain password / "Always Trust" prompt.
- Status words: `Installed & Trusted`, `Installed, but not Trusted!`,
  `Not installed`, `Root Certificate Expired`, `Root Certificate Not Yet
  Valid`, `Root Certificate Removed`, `This certificate is marked as trusted
  for this account`. Menu: `Install Certificate on this Mac…`, `Install
  Certificate on iOS`, `… on Android`, `… on Firefox Browsers…`, `… on Java
  VMs`, `Root Certificate as PEM/DER/P12...`, `Generate new Proxyman CA`,
  `Generate new...`, `Reset All`. Settings ▸ General: `Proxyman CA`,
  `Generate new…`, `More`.
- The CA is also served over plain HTTP from the proxy itself at
  `http://cert.proxyman.io` / `http://proxy.man/ssl`
  (`inline; filename=proxyman-ca.pem`), for devices and Firefox.
- A pre-flight check exists: `Require Trusted Proxyman Certificate in Keychain
  Access` with help text `Proxyman won't prompt the Mac Setup Guide Window if
  the certificate is not properly trusted in Keychain Access for domain/app
  SSL Proxying`.

What this means for aitmproxy: Proxyman never asks for sudo in a Terminal
for the CA. The recommended path is `security add-trusted-cert -r trustRoot`
run "with administrator privileges", which triggers macOS's own admin
password dialog and nothing else; the manual path needs no password but
leaves trust to Keychain Access.
Our `aitm ca install` already has the recipe (research `07-ca-install`); the
app must call it in-process on first run, show the three states (not
installed / installed not trusted / trusted) and serve the PEM from the proxy
for other devices. The untrusted-CA finding in
`aitmproxy-ca-trust-root-cause` is exactly the "Installed, but not Trusted!"
state Proxyman names.

## 7. MCP integration

```
M=Contents/MacOS/mcp-server
otool -L $M; strings -a $M | grep -E '^[a-z]+(_[a-z0-9]+)+$' | sort -u
```

- Stand-alone stdio binary (`MCP/StdioTransport.swift`, plus
  `StatefulHTTPServerTransport` / `StatelessHTTPServerTransport` /
  `HTTPClientTransport` in the same Swift MCP package). Clients register it
  as `claude mcp add proxyman --transport stdio -- "/Applications/Proxyman.app/Contents/MacOS/mcp-server"`.
  It forwards to the running app over a loopback HTTP bridge authenticated by
  a per-session token in `~/Library/Application Support/com.proxyman.NSProxy/mcp-handshake.json`
  (0600); strings `Failed to write handshake file`, `Invalid handshake file.
  Please restart Proxyman.`, `Proxyman is not running, MCP is stopped, or MCP
  has been disabled by your organization. Open Proxyman Settings > MCP to
  check its status.`
- Settings ▸ MCP has `Enable MCP Server` and `Redact Sensitive Data Before
  Sending to AI` (`Automatically redact sensitive information before sending
  to AI tools.`).
- Tool names found (verbs the agent can call), grouped:
  - read: `get_version`, `get_proxy_status`, `get_system_proxy_status`,
    `get_network_extension_status`, `get_certificate_status`,
    `get_http_version_mode`, `get_flows`, `filter_flows`, `get_flow_detail`,
    `get_flow_timing`, `get_traffic_overview`, `list_tool_status`,
    `list_rules`, `list_rule_folders`, `get_ssl_proxying_list`,
    `get_external_proxy`, `list_websocket_sessions`,
    `get_websocket_messages`, `list_dns_spoofing`,
    `list_network_conditions`, `list_reverse_proxies`, `search_docs`,
    `get_proxyman_cli_help`, `get_terminal_manual_command`
  - session: `toggle_recording`, `clear_session`, `open_proxyman`,
    `open_proxyman_screen`, `quit_proxyman`
  - system state: `set_system_proxy`, `install_network_extension`,
    `set_network_extension_enabled`, `retry_network_extension`,
    `uninstall_network_extension`, `install_certificate`,
    `uninstall_certificate`, `enable_ssl_proxying`, `disable_ssl_proxying`,
    `toggle_ssl_proxying_domain`, `set_http_version_mode`,
    `set_external_proxy`
  - rules: `create_breakpoint`, `update_breakpoint`, `create_map_local`,
    `create_map_local_from_flow`, `update_map_local`, `create_map_remote`,
    `update_map_remote`, `create_blacklist`, `update_blacklist`,
    `create_allow_list`, `update_allow_list`, `create_scripting_rule`,
    `create_dns_spoofing`, `update_dns_spoofing`, `create_network_condition`,
    `create_reverse_proxy`, `create_rule_folder`, `rename_rule_folder`,
    `delete_rule_folder`, `toggle_rule_folder`, `toggle_rule`, `toggle_tool`,
    `toggle_no_caching`, `delete_rule`, `delete_rules`
  - compose / export: `create_compose_http`, `create_compose_http_from_flow`,
    `update_compose_http`, `send_compose_http`, `get_compose_http`,
    `delete_compose_http`, `close_websocket_session`, `export_flow_curl`,
    `generate_code`, and an export-flows tool (HAR / proxymanlogv2)
  - guided setup: `list_setup_workflows`, `list_popular_workflows`,
    `run_guided_setup`, `answer_setup_question`, `recommend_capture_path`,
    `troubleshoot_missing_traffic`, `inject_terminal`, `inject_electron`,
    `explain_vpn_or_atlantis_choice`
- Design notes embedded in tool descriptions: "Ask the user for the save
  path before calling this tool", "Explain mutations and sensitive values
  before execution. Ask for confirmation before license changes,
  imports/exports, certificate changes, clearing a session, proxy changes,
  rule mutations, or commands that write files", "Never pass a license key,
  password, token, or proxy credential back through MCP output",
  "Query get_network_extension_status before mutations and afterwards to
  distinguish accepted requests from active capture".

What this means for aitmproxy: Proxyman exposes **system-state verbs to the
agent** (`set_system_proxy`, `install_network_extension`,
`install_certificate`) and relies on tool-description etiquette plus the
app's own macOS prompts for safety. Our bus already gates these behind
operator-only / `proxy.system.*` with the sealed governance; keep that, but
match the read side (`get_system_proxy_status`,
`get_network_extension_status`, `get_certificate_status`,
`get_traffic_overview`, `get_flow_timing`) so an agent can diagnose "no
traffic" the way Proxyman's `troubleshoot_missing_traffic` does.

## 8. CLI

`proxyman-cli` (Swift, `3X57WP8E8V.com.proxyman.NSProxy.CLI`). From the MCP
help strings: `mcp <on|off>` (works with the app closed), `breakpoint
<on|off|open>`, `rules <tool> <action>` with folders, `export --mode
<all|enabledRules>`, `export-log --format <proxymansession|har|raw>`;
installed into PATH from `Tools > Install 'proxyman-cli' Command in PATH`.

What this means for aitmproxy: the CLI is secondary and installed from the
app, never the other way round. Our `aitm` binary is the core, but the Mac
app should offer the same "install command in PATH" menu rather than asking
for Homebrew steps.

## 9. Menu-bar extra, Dock, updates, telemetry

```
strings -a Contents/MacOS/Proxyman | grep -iE 'MenuBar|StatusItem'
plutil -convert json -o - Contents/Resources/en.lproj/Preferences.strings
```

- `MenuBarService`, `setMenuBarVisible:`, `NSStatusItem`; Settings ▸
  Appearance has `Menu Bar: Show Proxyman Icon on Menu Bar` and `Proxyman
  Dock Icon`, `Status Bar: Show Resource Usage in Bottom Bar` (`Include
  memory usage and upload/download speed.`), which is the `• 177 MB ↑ 2 KB/s
  ↓ 7 KB/s` in the status bar.
- Sparkle with automatic checks off (`Show Update Notification at Launch`),
  Sentry crash reports and analytics both opt-in toggles under Settings ▸
  Privacy (`Share crash report with Proxyman`, `Share analytics with
  Proxyman`). `InternetAccessPolicy.plist` declares `proxyman.com`,
  `proxyman.io`, `in.appcenter.ms`, `*.sentry.io`, `proxy.man`,
  `cert.proxyman.io`, `httpbin.proxyman.app` and `*` :443 "because Proxyman
  acts as Man-In-the-Middle Proxy".

## 10. Linked libraries

```
otool -L Contents/MacOS/Proxyman
otool -L Contents/Frameworks/ProxymanCore.framework/ProxymanCore
```

App: ProxymanCore, Sparkle, Sentry (via framework), HexFiend, ProtobufCore,
WebKit, SwiftUI + AppKit, Charts, NetworkExtension, SystemExtensions,
ServiceManagement, SystemConfiguration, Security, SecurityInterface,
MetricKit, AVKit/AVFoundation, Combine, CoreData, libz, libc++.

ProxymanCore: CFNetwork, Network, Security, SystemConfiguration (uses
`SCDynamicStoreCreate` + `SCDynamicStoreSetNotificationKeys` on
`kSCDynamicStorePropNetPrimaryInterface` to follow the primary interface,
which feeds `Listening on <LAN ip>:9090`), CryptoKit, JavaScriptCore
(Scripting tool), LocalAuthentication, WebKit, ProtobufCore, libcompression;
source paths show SwiftNIO (`swift-nio-ssl` / CNIOBoringSSL), Alamofire.

Helper: CFNetwork, Foundation, AppKit, SystemConfiguration, Security.
Extension: NetworkExtension, Network, Foundation, Swift runtime.

What this means for aitmproxy: nothing exotic. The whole privileged story is
SystemConfiguration + Security + NetworkExtension + ServiceManagement, all of
which our Swift app already links or can link; the engine stays in Rust.

## 11. One-paragraph answer to the three questions

**Helper vs extension for the system proxy:** helper. A launchd daemon
installed once with SMJobBless (admin password once), driven over XPC with
two authorized verbs, writing SCPreferences with an AuthorizationRef, and
watching the app's PID to revert on crash. The extension never touches proxy
settings.

**Which NE provider type gives per-app attribution:** the transparent
app-proxy provider (`NETransparentProxyProvider`, entitlement
`app-proxy-provider-systemextension`), reading `sourceAppSigningIdentifier` /
`sourceAppAuditToken` / `processPath` from each flow's metadata and relaying
bytes to the app.

**How they never ask for sudo:** macOS asks instead. SMJobBless shows the
Authorization dialog with Proxyman's own sentence; `security add-trusted-cert`
run with administrator privileges shows the admin password dialog (manual
mode: no password, trust set in Keychain Access); the system extension shows
the Login Items & Extensions approval and the network-configuration Allow.
Everything else (networksetup fallback, CA generation, MCP, CLI) runs as the
user.
