# 14 — macOS "Set as system proxy" toggle (Developer ID, hardened runtime, not sandboxed)

Stage 1 research for the apps/mac Status page follow-up. All sources read 2026-10-31.
Tags: **(H)** SDK header read locally (`MacOSX27.0.sdk`), **(M)** man page read locally,
**(P)** primary vendor doc/page, **(S)** secondary (forum, blog, search snippet, issue
thread), **(I)** inference by the researcher, **(U)** unverified.

## 1. Question

How should a Developer ID signed, hardened-runtime, non-sandboxed macOS app set the system
HTTP/HTTPS proxy of the active network service(s) to `127.0.0.1:<port>`, restore the previous
settings on quit, crash or "off", and read the current state back honestly?

## 2. Short answer

Both routes end in the same call: `networksetup` itself uses `SCPreferencesCreateWithAuthorization`
and the right `system.services.systemconfiguration.network`. Without a helper the user gets an
auth dialog per change, the credential lives about five minutes, and a crash or force-quit cannot
be restored in-session. Proxyman and Charles restore on quit; only Proxyman's optional root helper
claims crash revert. Read back with `SCDynamicStore` (global effective settings, change
notifications), never from our own flag. Proxyman makes the system proxy and its NE mutually exclusive.

## 3. Findings

**Probe note.** Read-only probes (`networksetup -listallnetworkservices`, `-getwebproxy Wi-Fi`,
`scutil --proxy`) cannot run in this sandbox: `networksetup` printed `AuthorizationCreate() failed:
-60008` even for a getter and `scutil --proxy` printed an empty dictionary. Nothing below states
this Mac's proxy state. The probes need the Terminal panel to be meaningful.

### Q1. Implementation routes and privilege

| # | Fact | Source |
|---|---|---|
| 1.1 | `networksetup` "requires at least admin privileges to change network settings"; root if "Require an administrator password to access system-wide preferences" is on. `-setwebproxy`/`-setsecurewebproxy` take `<service> <domain> <port> [authenticated user pass]` and "Turns proxy on"; `-set{web,secureweb}proxystate <service> on\|off`; `-setproxybypassdomains <service> d1 [d2…]` ("Empty" clears); `-setautoproxyurl` sets and enables PAC. | (M) `man networksetup` |
| 1.2 | `strings /usr/sbin/networksetup` contains `SCPreferencesCreateWithAuthorization() failed: %s` and the right name `system.services.systemconfiguration.network`. So route (a) and route (b) are the same Authorization-Services path; (a) is just Apple's own client of (b). The string `system.preferences.network` was NOT found in the binary (only the `system.preferences` prefix); I could not read the authorization DB (sandbox) to see the right's rule. | local `strings`, (U) for rule contents |
| 1.3 | `SCPreferencesCreateWithAuthorization(alloc, name, prefsID, AuthorizationRef)`: "authorization … to authorize any access to the enhanced privileges needed to manage the preferences session". `SCPreferencesCommitChanges` "commits changes to persistent storage. Call `SCPreferencesApplyChanges` … to apply the changes to the running system". `SCPreferencesLock/Unlock`, `SCNetworkSetCopyCurrent`/`SCNetworkSetCopyServices`/`SCNetworkServiceGetEnabled` enumerate services. Keys: `kSCPropNetProxies{HTTP,HTTPS}{Enable,Proxy,Port}`, `ExceptionsList`, `ExcludeSimpleHostnames`, `ProxyAutoConfig{Enable,URLString,JavaScript}`, `ProxyAutoDiscoveryEnable`. | (H) `SCPreferences.h`, `SCNetworkConfiguration.h`, `SCSchemaDefinitions.h` |
| 1.4 | Apple DTS (Quinn) on this exact task: "Modifying system-wide preferences does require privileges. I think you can do this without a separate privileged helper by way of `SCPreferencesCreateWithAuthorization`" (hedged: "it's been a while"). Follow-up: with it "you'll need to re-authorise every time the associated credential expires, which is typically every five minutes. If that's not acceptable" install a privileged helper that does its own authorisation check (EvenBetterAuthorizationSample, TN2095). | (S, Apple DTS) developer.apple.com/forums/thread/74672 |
| 1.5 | A working SCPreferences-with-authorization demo (codinn/SystemProxySettingsDemo, SOCKS) shows the dialog again after the app relaunches; attempts to persist the right with `AuthorizationRightSet` did not help (thread has 0 replies). | (S) developer.apple.com/forums/thread/82777 |
| 1.6 | `AuthorizationExecuteWithPrivileges` is deprecated since 10.7 ("Use a launchd-launched helper tool and/or the Service Management framework"). `SMJobBless` is deprecated since 13.0 ("Please use SMAppService instead"). | (H) `Authorization.h`, `ServiceManagement.h` |
| 1.7 | `SMAppService.daemon(plistName:)`: plist in `Contents/Library/LaunchDaemons`, may use `BundleProgram`; "the LaunchDaemon will not be bootstrapped until an admin approves [it] in System Settings"; "Apps that contain LaunchDaemons must be notarized"; app should live in `/Applications`; status values `notRegistered/enabled/requiresApproval/notFound`. `SMJobBless` still needs `SMPrivilegedExecutables`, `SMAuthorizedClients`, an embedded launchd plist, helper in `Contents/Library/LaunchServices`. | (H) `SMAppService.h`, `ServiceManagement.h` |
| 1.8 | Proxyman: default is `networksetup` ("slow and can delay starting or quitting the app"; fails for guest/non-admin users). Optional "Proxy Helper Tool" installed at `/Library/PrivilegedHelperTools/com.proxyman.NSProxy.HelperTool`; asked on first launch, skippable (Settings → Advanced); macOS 13+ needs it enabled under Login Items; MDM install `sudo …/proxyman --install-privileged-components` (4.12.0+). Maintainer: installed with `SMJobBless`; a CLI-only install is hard because it needs the app's plist. | (P) proxyman.com/docs/basic-features/proxy-setting-tool; (S) github.com/ProxymanApp/Proxyman/issues/1767 |
| 1.9 | Charles: "When you first install Charles you will be prompted to grant permissions to Charles to autoconfigure the proxy settings." Helper name `com.xk72.charles.ProxyHelper` copied to `/Library/PrivilegedHelperTools` with a LaunchDaemon plist (Jamf thread, ~2000 days old; page itself returned 403, from a search snippet). | (P) charlesproxy.com/documentation/configuration/browser-and-system-configuration/; (S, stale) community.jamf.com thread 232970 |
| 1.10 | Helper-security precedent: Proxyman helper XPC (`overrideProxySystemWithAuthorization`, `revertProxySystemWithAuthorization`, `legacySetProxySystemPreferencesWithAuthorization`) accepted callers by code-signing requirement but not hardened runtime / library validation, so a `DYLD_INSERT_LIBRARIES` build could silently set a MITM proxy (CVE-2023-45732, fixed in helper 1.5.0: callers must be notarized, signed with the vendor cert, with Library Validation and the hardened flag). | (S) nccgroup.com technical advisory (2023-10-31); (P) Proxyman helper changelog |
| 1.11 | Entitlements/notarization: no header or doc I read lists an entitlement for SCPreferences or `networksetup`. Proxyman ships a hardened-runtime app plus the helper (NCC: "current builds use the hardened runtime"). Our `Aitmproxy.entitlements` carries only NE + system-extension keys; `build.sh` signs with `--options runtime`. A helper would be a new nested binary to sign before the app. | (I) from the above; `apps/mac/*.entitlements`, `apps/mac/build.sh:169-205` |
| 1.12 | Apple does not state a recommendation between (a) and (b) in anything I could read; the only Apple-staff statement is 1.4 (SCPreferences-with-authorization is workable but short-lived; helper if that is not acceptable). Apple's doc pages are JS-rendered and returned no body, so `developer.apple.com/documentation` text is **not** cited. | (U) |

### Q2. Read-back and notifications

| # | Fact | Source |
|---|---|---|
| 2.1 | `SCDynamicStoreCopyProxies(NULL)`: "current internet proxy settings", dictionary with `ExceptionsList`, `HTTPEnable/Proxy/Port`, `HTTPSEnable/Proxy/Port`, FTP…; `NULL` if none defined or error. | (H) `SCDynamicStoreCopySpecific.h` |
| 2.2 | `CFNetworkCopySystemProxySettings()`: "current system internet proxy settings"; the dictionary format is what `CFNetworkCopyProxiesForURL` consumes, i.e. what CFNetwork-based clients actually see. | (H) `CFProxySupport.h` |
| 2.3 | `scutil --proxy` "reports the current system proxy configuration". It reads the dynamic-store key `State:/Network/Global/Proxies`; the dump has top-level keys plus a `__SCOPED__` dictionary keyed by interface (`en0`). | (M) `man scutil`; (S) clash-verge-rev issue 8083 |
| 2.4 | Per-service (persisted) vs global (effective) differ. Persisted values are at `Setup:/Network/Service/<UUID>/Proxies` and are what `networksetup -getwebproxy <service>` shows; the global top level follows the **primary service**. Reports: `networksetup -getwebproxy Wi-Fi` "Enabled: Yes" while `scutil --proxy` showed `HTTPEnable 0` because a VPN/Tailscale service was primary; the Wi-Fi values appeared only under `__SCOPED__`. A CFNetwork client then got `kCFProxyTypeNone`. | (S) clash-verge-rev issue 8083; Emanboiee/proxy-router issue 124 (search snippet); (I) for the "follows primary" reading |
| 2.5 | Notifications: `SCDynamicStoreKeyCreateProxies` "can be used in conjunction with `SCDynamicStoreSetNotificationKeys` to receive notifications when the current network proxy settings … are changed". An **empty** changed-keys list means configd restarted: discard cached state. Primary service key: `State:/Network/Global/IPv4` → `PrimaryService` (`kSCDynamicStorePropNetPrimaryService`). `SCPreferencesSetCallback` fires on commit/apply but only for an open session. | (H) `SCDynamicStoreKey.h`, `SCDynamicStore.h`, `SCSchemaDefinitions.h`, `SCPreferences.h` |
| 2.6 | Other apps and VPNs rewrite the proxy: "Some VPN apps revert the HTTP proxy in the network settings as soon as Proxyman overrides it"; "some apps can change it back". | (P) proxyman.com/docs/troubleshooting/i-couldnt-see-any-traffics-on-proxyman |
| 2.7 | Proxyman's own status surface exposes `systemProxyEnabled` and `captureActive` as separate fields. | (P) proxyman.com/docs/command-line |

### Q3. Restore semantics

| # | Fact | Source |
|---|---|---|
| 3.1 | Charles: "Charles will configure and then reconfigure the macOS proxy settings whenever Charles is started or quit." If it stops abnormally "it doesn't have an opportunity to reset your proxy settings … It should notice that when it is restarted"; manual fix is Network ▸ Proxies, untick Web/Secure Web Proxy. | (P) charlesproxy.com browser-and-system-configuration; (P) charlesproxy.com/documentation/faqs/ |
| 3.2 | Proxyman: "overrides the HTTP proxy at launch and reverts it when it quits, but some apps can change it back". Helper changelog: 1.2.0 reverts the HTTP proxy if Proxyman crashes; 1.3.0 "remembers and restores your previous proxy setting"; 1.6.0 fixed restoring the PAC URL. Its bypass list is also swapped in at launch and restored on quit. | (P) proxy-setting-tool; (P) proxyman.com/docs/basic-features/bypass-proxy-list |
| 3.3 | How the helper detects a crash is not documented (XPC invalidation is the obvious mechanism). | (U), (I) |
| 3.4 | Restoring a disabled-but-configured endpoint on macOS: enabling is a side-effect of writing the endpoint, so write the saved host/port, then switch the state off. Setters are several commands and not atomic; the app must snapshot and roll back itself. | (S) sysproxy-rs README via search summary; (M) 1.1 ("Turns proxy on") |
| 3.5 | Without a helper, restore-on-quit costs a second authorization if more than ~5 min passed (1.4); crash/SIGKILL/power loss leave the proxy at a dead port, which breaks browsing for every proxy-aware app until fixed. | (I) from 1.4 + 3.1 |

### Q4. Which services, exceptions, PAC, apps that ignore the proxy

| # | Fact | Source |
|---|---|---|
| 4.1 | `-listallnetworkservices` (asterisk = disabled), `-listnetworkserviceorder` (asterisk = inactive). API: `SCNetworkSetCopyServices` + `SCNetworkServiceGetEnabled`. | (M), (H) |
| 4.2 | Primary-only has a known hole: with GlobalProtect, `PrimaryService` was `gpd.pan`, which maps to no `SCNetworkService`, so a primary-only setter failed; the issue's suggested fix was fall back to a real service from `ServiceOrder` or let the user pick. | (S) clash-verge-rev issue 8083 |
| 4.3 | Which services Proxyman/Charles set is not documented. Proxyman's docs verify the result under System Settings → Network → Wi-Fi → Details → Proxies (HTTP + HTTPS, 127.0.0.1, same port). | (P) i-couldnt-see-any-traffics; service choice (U) |
| 4.4 | Default bypass list on macOS is `*.local, 169.254/16`; `-setproxybypassdomains` **replaces** the whole list. | (S) Apple Community thread 255622770, Mozilla bug 470207 (search snippets); (M) |
| 4.5 | Proxyman replaces the bypass list with its own at launch and restores the original on quit; its own docs list no defaults. Charles has a "Bypass Proxies" box in Proxy Settings ▸ Options. | (P) bypass-proxy-list; (P) charlesproxy.com/documentation/faqs/ |
| 4.6 | Whether CFNetwork/Network.framework auto-bypass loopback destinations under a system proxy: not found in any source. Our own `BusClient` uses `NWConnection` to a loopback bus address (`apps/mac/Sources/AitmBusClient/BusClient.swift:116`); whether that connection would be proxied is **unverified**. | (U) |
| 4.7 | PAC vs explicit: Charles and Proxyman docs both describe explicit HTTP/HTTPS settings (Proxyman's changelog mentions PAC only as a user setting it failed to restore, 3.2). Explicit avoids hosting a PAC file. | (P) 3.1/3.2; (I) |
| 4.8 | CLI tools: curl and most Unix tools do not read the system proxy; they use `http_proxy`, `https_proxy`, `ALL_PROXY`, `NO_PROXY` (lower case wins; curl ignores upper-case `HTTP_PROXY`). The system exceptions list is invisible to them. | (M) `man curl` (env var section); (S) proxymonkey.io, byteful.com |

### Q5. Interaction with our Network Extension

| # | Fact | Source |
|---|---|---|
| 5.1 | Proxyman: NE `enable` "starts capture and turns off the helper-based system proxy. The system proxy cannot be enabled while Network Extension capture is on." After NE disable/uninstall "the system proxy follows Auto Override System Proxy Settings at Launch". Its VPN page says NE "works independently of the system proxy". Its docs say nothing about double capture or loops. | (P) proxyman.com/docs/command-line; (P) …/proxyman-does-not-work-with-vpn-apps; (P) …/2026-10-06-introducing-network-extension |
| 5.2 | Our provider: one catch-all outbound rule (`remoteNetworkEndpoint: nil`, protocol any); loopback is not delivered for wildcard rules (header: wildcard "will match all destinations except for loopback"); DevForums reports on explicit loopback rules conflict. Self-exclusion = audit-token → Developer ID team requirement, fail-open (`isSelf`), covers aitm and obscura. The core listens on `127.0.0.1:<proxyPort>`. | `apps/mac/Extension/Sources/TransparentProxyProvider.swift:35-47,74`; `FlowHandoff.swift:145-185`; `EmbeddedCoreLaunch.swift:245`; research 10 §3.2 |
| 5.3 | Inference with both on: an app that honours the system proxy dials `127.0.0.1:<port>`, a loopback flow the NE should not see (no double capture at that hop); the core's upstream dial is `isSelf` so it fails open (no loop); apps that ignore the system proxy are picked up by the NE if in scope. This rests on the loopback exclusion holding on macOS 27 (research 10 open question 4) and has **not been measured**. | (I) |
| 5.4 | Coverage differs: the core's passive proxy "is not gated by the scope allowlist (an intercepting proxy must relay what the client sends)"; the NE lane is deny-by-default scoped. System proxy ON therefore sends **every** proxy-aware app's traffic through the core regardless of Scope, while NE only sends in-scope hosts. | `crates/aitm-core/src/proxy.rs:331-336`; PR #181 notes in MEMORY |

### Q6. UX conventions

| # | Fact | Source |
|---|---|---|
| 6.1 | Proxyman: menu "Tools → Proxy Setting → Override macOS System" (same logic as the Raycast "Toggle HTTP/HTTPS System Proxy"); `proxyman-cli proxy on\|off` (4.8.0+); setting "Auto Override System Proxy Settings at Launch"; Settings → Advanced → Proxy Helper Tool → Install/Uninstall and an **Open Login Items…** button when macOS 13+ approval is missing; a third-party guide names "Automatically Disable Proxy When App Exits" (not confirmed in vendor docs). | (P) command-line; (P) proxy-setting-tool; (S) raycast.com/noah_tran/proxyman |
| 6.2 | Charles: "Proxy" menu → "macOS Proxy" with a checkmark when enabled; tutorials cite Cmd+Shift+P and a "Grant Privileges" first-run prompt. Charles docs say prompted once at install, then it reconfigures on start/quit. | (S) analystadmin.com, viblo.asia (search snippets); (P) charlesproxy.com |
| 6.3 | Prompt frequency: Proxyman with helper = one install + one Login Items approval, none per toggle; Charles = once at first install, then silent (a helper is implied, 1.9); SCPreferences-only = per ~5 min and per relaunch (1.4, 1.5). | (P)/(S) as cited; (I) |
| 6.4 | Our house rules: lanes and actions come from `ConnectionSummary` (`core/bus/capture`, Title Case action titles such as "Turn On Capture"), states are derived from published facts "never from a preference key", and privileged actions are operator-only, enforced by `tools/check-capture-operator-only.sh` with explicit allow-lists and `expect` lines that must be updated in the same commit. | `ConnectionSummary.swift`; status-page spec; the script |

## 4. Candidate directions (not decisions)

| | Route | Privilege | Crash safety | Cost / risk |
|---|---|---|---|---|
| **A** | In-app `SCPreferences` + `AuthorizationCreate` (or shelling `networksetup`, same right) | System auth dialog per enable and again for restore if >~5 min | None in-session; stale-state recovery on next launch needs another auth | No pipeline change, no root code, no XPC attack surface. A force-quit leaves the user's proxy dead. |
| **B** | `SMAppService` LaunchDaemon helper, narrow XPC (`set 127.0.0.1:port`, `restore`), restores when the client's XPC connection drops | One Login Items approval; no per-toggle prompt | Yes (mechanism (I), not documented by Proxyman) | Nested helper to sign/notarize in `build.sh`/`notarize-dmg.sh`; app must be in `/Applications`; unnotarized dev builds cannot register it (same class of limit as the sysex); a root daemon needs strict client validation (1.10: require hardened runtime + library validation + team requirement). |
| **C** | Ask the already-approved NE system extension (root) to write SCPreferences | Reuses the sysex approval | Sysex lifecycle, not app | **(U)** whether a sysex may write SCPreferences; couples the system proxy to the NE being approved, which is the opposite of the "no NE" use case. Needs a spike. |

Common design points the evidence supports under any route:
- **Read-back:** register `SCDynamicStore` notification keys for `SCDynamicStoreKeyCreateProxies` and `State:/Network/Global/IPv4`; derive the lane word from the **global effective** dictionary (2.1/2.2), not from persisted per-service values and not from a preference. Five honest states: off; on (global top level equals `127.0.0.1:<port>`, HTTP and HTTPS); partial (only one of HTTP/HTTPS); overridden (service Setup points at us but global does not, the VPN-primary case, 2.4); changed (global points elsewhere). Treat an empty changed-keys list as "re-read everything".
- **Snapshot and restore:** before writing, persist per-service the full Proxies subset we touch (HTTP/HTTPS enable/host/port, `ExceptionsList`, PAC enable/URL, auto-discovery) in a 0600 file with our port and pid. Restore writes saved endpoint then state (3.4), and only fields that still equal what we wrote, so a user's later change is not clobbered (I). Run on `applicationWillTerminate` and on "off". At next launch, a snapshot file plus a global proxy equal to our port with no core listening is a **stale** state: surface "System proxy still points at 127.0.0.1:<port>" with Restore (3.1 Charles notices the same).
- **Services:** all enabled services with an interface, versus primary only. Evidence: global follows the primary (2.4) and the primary can change or be a pseudo-service (4.2), which favours all-enabled; primary-only gives a smaller blast radius. Offer a per-service view only if Matt wants it.
- **Exceptions:** union of the user's list with `127.0.0.1`, `localhost`, `*.local`, `169.254/16` (keep the macOS defaults, 4.4). Proxyman swaps instead of merging (4.5). Whether loopback needs adding is open (4.6).
- **Mode:** explicit HTTP + HTTPS, no PAC, no SOCKS (4.7). State plainly that curl and other CLI tools are not covered (4.8); `export https_proxy=…` is the CLI path.
- **NE interplay, three options:** (i) mutual exclusion as Proxyman does (5.1); (ii) independent, with the Status card saying "System proxy: all proxy-aware apps" next to "Capture: n hosts in scope" because coverage differs (5.4); (iii) coexist silently (not advised: the double-lane scope difference would mislead). Evidence only supports "no loop" by inference (5.3).
- **Operator-only:** a new lane or sub-row must be reached by operator surfaces only; `check-capture-operator-only.sh` needs a matching rule (and `expect`s) in the same commit, and no bus verb, palette entry or agent surface may mention it. The state itself may be reported read-only if Matt wants `ConnectionSummary` to show it.
- **Wording (house style, candidate):** actions "Set as System Proxy" / "Restore System Proxy"; lane word derived from read-back ("system proxy on · 127.0.0.1:8080", "system proxy off", "changed by another app").

## 5. Open questions

For Matt:
1. Is a root `SMAppService` helper (route B) acceptable for the DMG and notarization pipeline, given the extra signing step, `/Applications` requirement, a root daemon's attack surface (1.10), and that dev builds cannot register it? If not, is route A's "force-quit leaves the proxy dead, restored at next launch with a prompt" acceptable?
2. All enabled services or primary only? Merge or replace the exceptions list?
3. System proxy and NE: mutually exclusive (Proxyman) or independent with honest wording?
4. Should the Status page show the system proxy as a fourth lane, a Capture sub-row, or Settings only?

For a measurement spike (cannot be answered by reading):
5. With both NE and system proxy on, on macOS 27: does a proxy-aware app's flow to `127.0.0.1:<port>` ever reach the provider? Does anything loop? (research 10 open question 4 is the same unknown.)
6. Does `NWConnection` (our `BusClient`) or `URLSession` honour the system proxy for a loopback destination, and does CFNetwork bypass loopback by default?
7. What right rule and timeout does `system.services.systemconfiguration.network` have on macOS 27 (`security authorizationdb read` needs the Terminal panel), and does a long-lived `AuthorizationRef` with `kAuthorizationFlagExtendRights` avoid the 5-minute re-prompt? (Apple DTS hedged; nothing verified.)
8. Which services do Proxyman and Charles set, and how does Proxyman's helper detect a crash? (Not documented; needs a run or a binary inspection.)
9. Can a Network Extension system extension write SCPreferences (route C)?
10. Live `scutil --proxy` / `networksetup -getwebproxy` on Matt's Mac for a baseline (blocked here).

## 5a. Live observation on Matt's Mac (2026-10-31, apps-attribution session, Terminal panel, read-only)

The researcher's probes failed inside the sandbox (`AuthorizationCreate() failed: -60008`); these
were taken from the real shell while the installed 0.5.4 app ran its embedded core on `127.0.0.1:8080`
with the Network Extension attached:

```
$ scutil --proxy
<dictionary> {
  ExceptionsList : <array> { 0 : *.local  1 : 169.254/16 }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
}
```

So the effective system proxy is OFF; Safari bypassed the core while the extension (empty scope)
rejected its flows, which is why the Flows and Apps counts stayed at 0 (diagnosis note in the
macOS-review shared folder, `live-sidebar-not-loading-diagnosis.md`). `networksetup
-listallnetworkservices` was not run; the service names are still owed.

## 5b. Correction with live evidence (2026-10-31, system-proxy-automation session)

Changes route A's cost column: `codesign -d --entitlements - /usr/sbin/networksetup` on Matt's
Mac shows `com.apple.private.AuthorizationServices = [system.services.systemconfiguration.network]`
and `com.apple.private.admin.writeconfig`; the right's rule is k-of-1 of `[is-root, entitled,
_mbsetupuser-nonshared, authenticate-admin-nonshared]`. Measured: `networksetup -setwebproxystate
"Display Ethernet" off` run as the admin user without sudo exited 0, changed the state and showed
NO dialog (restored within three minutes). So `networksetup` from a non-root admin user never
prompts and has no five-minute credential; only raw `SCPreferences` writes from our own process hit
`authenticate-admin`. The privileged helper is a follow-up for standard users and for
`SCPreferences` speed, not a prerequisite. Service names on this Mac: "Display Ethernet" (en15)
and "Wi-Fi" (en0), both enabled; at the time of the probe both carried Proxyman's
`127.0.0.1:9090` HTTP+HTTPS, so a `SystemProxyState.other(host, port)` reading is a real case,
not a hypothetical. The spec for this work lives with the system-proxy-automation session.

## 6. Sources

Local (read 2026-10-31): `apps/mac/CLAUDE.md`; `apps/mac/build.sh`; `apps/mac/Aitmproxy.entitlements`; `apps/mac/EmbeddedObscura.entitlements`; `apps/mac/Extension/Aitmproxy-Extension.entitlements`; `apps/mac/Extension/Sources/TransparentProxyProvider.swift`; `apps/mac/Extension/Sources/FlowHandoff.swift`; `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift`; `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift`; `apps/mac/Sources/AitmBusClient/BusClient.swift`; `apps/mac/tools/check-capture-operator-only.sh`; `docs/superpowers/specs/2026-10-31-macos-status-page-and-first-run-design.md`; `docs/research/10-macos-network-extension.md`; `crates/aitm-core/src/proxy.rs`; man pages `networksetup`, `scutil`, `curl`; `strings /usr/sbin/networksetup`; SDK headers under `/Applications/Xcode.app/…/MacOSX.sdk/System/Library/Frameworks/` (`SystemConfiguration.framework`: `SCPreferences.h`, `SCDynamicStore*.h`, `SCNetworkConfiguration.h`, `SCSchemaDefinitions.h`; `CFNetwork.framework/CFProxySupport.h`; `Security.framework/Authorization.h`; `ServiceManagement.framework/ServiceManagement.h`, `SMAppService.h`).

Web (read 2026-10-31):
- https://proxyman.com/docs/basic-features/proxy-setting-tool
- https://proxyman.com/docs/command-line
- https://proxyman.com/docs/basic-features/bypass-proxy-list
- https://proxyman.com/docs/troubleshooting/i-couldnt-see-any-traffics-on-proxyman
- https://proxyman.com/docs/troubleshooting/proxyman-does-not-work-with-vpn-apps
- https://proxyman.com/posts/2026-10-06-introducing-network-extension
- https://www.raycast.com/noah_tran/proxyman
- https://github.com/ProxymanApp/Proxyman/issues/1767
- https://www.nccgroup.com/research/technical-advisory-insufficient-proxyman-helpertool-xpc-validation/
- https://www.charlesproxy.com/documentation/configuration/browser-and-system-configuration/
- https://www.charlesproxy.com/documentation/faqs/
- https://community.jamf.com/t5/jamf-pro/allow-standard-user-to-enable-macos-proxy-when-use-charles-web/m-p/232970 (via search snippet; page 403)
- https://developer.apple.com/forums/thread/74672 (Apple DTS)
- https://developer.apple.com/forums/thread/82777
- https://developer.apple.com/forums/thread/66272 (SMJobBless install location; no SCPreferences content)
- https://github.com/clash-verge-rev/clash-verge-rev/issues/8083
- https://github.com/zzzgydi/sysproxy-rs (search summary only; the page fetch 404ed)
- https://github.com/Emanboiee/proxy-router/issues/124 (search snippet only)
- Search snippets only (not fetched): Apple Community thread 255622770, bugzilla.mozilla.org 470207, proxymonkey.io and byteful.com macOS proxy blogs.
- Not retrievable: developer.apple.com/documentation pages (no body), raw.githubusercontent.com (sandbox denied), Apple's configd source (so the "global follows primary service" rule is cited from issue reports plus the header text, not from `IPMonitor`).
