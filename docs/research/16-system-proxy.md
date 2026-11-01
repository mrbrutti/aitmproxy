# Setting, reading back and restoring the OS system proxy on macOS and Linux

> **Provenance:** Researcher engine, read on **2026-10-31**. Items marked
> **(observed)** were run on this machine (macOS 27.0, build 26A428, user `matt`
> uid 501, member of `admin`) either by me inside the Claude Bash sandbox
> (read-only) or by the orchestrator outside it (files in `/tmp/claude/sysproxy/`,
> cited by name). Items marked **(unverified)** were not seen in a source or run.
> Items marked **(search summary)** come from a search-result summary, not a page
> I read. Nothing here is a design decision; "candidate" means the evidence points
> that way and the Architect decides.

## 1. Question

How should aitmproxy (Rust core `aitm`, default `127.0.0.1:8080`) set itself as the
OS HTTP/HTTPS proxy on macOS and Linux, read back honestly whether the system
currently points at it, record what it changed, and restore the previous setting
on unset, on quit and after a crash, with no command-line step for the operator
and any privileged step going through the OS's own permission dialog (never a
`sudo` line)?

## 2. Short answer

On macOS, `/usr/sbin/networksetup` carries the private right for network changes,
so an admin user can set and restore per-service proxies with no dialog (observed
once); it needs root when "Require an administrator password" is on and fails for
standard users, where only a privileged helper works. Honest read-back means the
primary service via `scutil --proxy` / SCDynamicStore, not per-service reads.
Every surveyed tool restores after a crash from saved state or a parent-liveness
watcher. Linux needs no privilege (`gsettings`; KDE `kwriteconfig` plus a D-Bus
signal) but fails silently without a session bus or dconf.

## 3. Findings

### 3.0 Where the evidence contradicts or sharpens the brief

1. **"Admin user, no prompt" is conditional, not a rule.** `networksetup`'s own
   help text and binary say it needs root instead of admin when "Require an
   administrator password to access system-wide preferences" is on; a FlClash
   user hit `** Error: Command requires admin privileges.` (3.1.3, 3.1.4).
2. **`org.gnome.system.proxy.http enabled` is dead.** The schema summary reads
   "Unused; ignore". `mode = 'manual'` is the switch (3.6.1).
3. **`scutil --proxy` omits host and port when a proxy is disabled, and shows
   only the primary service.** Per-service `networksetup -get*` shows the residue
   (`127.0.0.1:9090`) on the same Mac at the same moment (observed, 3.2.1).
4. **Proxyman's crash revert is a parent-PID poll inside the helper (a 5 second
   timer), not an XPC-invalidation hook** (3.5.2). Charles reverts only on its next
   start: it "should notice that when it is restarted" (3.5.1). **mitmproxy does
   not set the system proxy** (its docs describe manual client configuration only,
   3.5.2).
5. **Chrome never proxies `localhost`, `127.0.0.1/8`, `::1`, link-local**, whatever
   the system proxy says; Proxyman says the same of macOS in general. A system
   proxy cannot capture a localhost test target (3.1.9).
6. **The Mullvad `system-configuration` 0.8.0 crate cannot do the write path
   safely.** Its safe `SCPreferences` has constructors only; the authorization and
   commit calls exist only in `system-configuration-sys` 0.6.0 (raw FFI) (3.2.4).
7. **The system proxy changed twice on this Mac around the orchestrator's
   scripts, by something not recorded in those files** (3.1.8). Restore-to-previous must
   not assume nobody else is writing.
8. **The Proxyman "No HTTP Traffic? ... Don't ask again" nudge text was not found
   in any page I could read.** Only the troubleshooting page's "By default,
   Proxyman overrides the system HTTP proxy with the networksetup command line
   tool, but it can fail in some cases" and one debug log line were found (3.8).

### 3.1 macOS write path (`networksetup`)

**3.1.1 Entitlements (observed, read by me with `codesign -d --entitlements -
/usr/sbin/networksetup`, 2026-10-31).** The binary is platform-signed
(`Identifier=com.apple.networksetup`, `Platform identifier=26`, no Team ID) and
carries exactly:

| Key | Value |
|---|---|
| `com.apple.private.AuthorizationServices` | `[system.services.systemconfiguration.network]` |
| `com.apple.private.admin.writeconfig` | `true` |
| `keychain-access-groups` | `[apple]` |

No `SCPreferences-write-access` key. `private` in the key names suggests only
Apple-signed binaries can carry them, so a third-party app could not obtain the
same shortcut (**inference**, no source read).

**3.1.2 The right's rule (observed, `/tmp/claude/sysproxy/probe.txt`, orchestrator
run 2026-10-31 16:32).** `security authorizationdb read
system.services.systemconfiguration.network`: `class = rule`, `k-of-n = 1`, `rule
= [is-root, entitled, _mbsetupuser-nonshared, authenticate-admin-nonshared]`,
comment "For making change to network configuration via System Configuration."
So any one of: root; a caller entitled for this right (networksetup is); the
setup-assistant user; or an admin authenticating, non-shared. The same file shows
`system.preferences` and `system.preferences.network` as `class = user`, `group =
admin`, **`shared = true`**.

**3.1.3 What the binary does with that (observed, `strings -a
/usr/sbin/networksetup`, by me, 2026-10-31).** It contains `runningWithAdminPrivileges
= %d, isAdminUser = %d, sysPrefsRequireAdminPassword = %d`, the right names
`system.preferences` and `system.services.systemconfiguration.network`,
`AuthorizationCreate() failed: %ld`, `SCPreferencesCreateWithAuthorization() failed:
%s`, `Command requires admin privileges.`, and the usage sentence "The networksetup
tool requires at least admin privileges to change network settings. If the
"Require an administrator password to access system-wide preferences" option is
selected in System Preferences > Security & Privacy, then root privileges are
required to change network settings." **Inference (not a source):** the tool
checks root / admin / the system-wide-password setting itself, then calls
`AuthorizationCreate` and `SCPreferencesCreateWithAuthorization`; the `entitled`
clause is what lets it skip the admin dialog. Apple's man text (manp.gs, 2026-10-31)
repeats the usage sentence.

**3.1.4 Non-root admin, observed to work once.** Orchestrator run, uid 501 in
`admin`, outside the sandbox (`/tmp/claude/sysproxy/lima-probe.txt`, ~16:33):
`networksetup -setwebproxystate "Display Ethernet" off` printed `exit=0`; `-getwebproxy`
went from `Enabled: Yes` to `Enabled: No`; `scutil --proxy` then showed `HTTPEnable
: 0`, `HTTPSEnable : 1`. `/tmp/claude/sysproxy/restore.txt` (~16:34):
`-setwebproxystate "Display Ethernet" on` printed `restored: exit=0`, and
`scutil --proxy` then showed `HTTPEnable : 1`. The orchestrator reports no dialog
appeared; the files record only exit codes and states. The Mac's `system.preferences`
has `shared = true` (3.1.2). The CIS benchmark's way of enabling the system-wide
password requirement is to set `shared` to false in `system.preferences` (Tenable
CIS audit item and the ordonez.tv write-up, **search summary**), so this Mac
plausibly has the requirement **off**, which would explain the success
(**inference**).

**3.1.5 Where it needs root or fails.**
- FlClash issue 2425 (opened 2026-09-14, no replies): `networksetup -setwebproxystate
  "Wi-Fi" off` without sudo gave `** Error: Command requires admin privileges.`;
  `sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 7890` and `-setsecurewebproxy`
  worked; turning "Require an administrator password" off made the unprivileged
  call work. macOS version and user type were not stated (page read 2026-10-31).
- Standard (non-admin) user: Proxyman's docs say that without its helper
  "networksetup" fails for non-admin and guest users (2026-10-31). The exact text
  for a real standard user was **not seen**; the string in 3.1.3 is the likely one
  (**unverified**). Proxyman issue 177 (2019-06-14) says "Non-admin users needed
  root access".
- Whether failure also sets a non-zero exit code is **unverified**: the FlClash
  report implies a failure, haiopass issue 2 complains that apps never check exit
  code or stderr (search summary of tool behaviour, no exact code given). A caller
  must read back after every write (3.2).
- Inside the Claude Bash sandbox, every `networksetup` call, even `-listallnetworkservices`,
  fails with `AuthorizationCreate() failed: -60008` (observed, 2026-10-31), and
  `scutil --proxy` returns an **empty** `<dictionary> { }` (observed). A caller in
  a restricted context gets empty data, not "proxy off".
- Sequoia claim: haiopass issue 2 says "Apple made system proxy modification
  root-only" on macOS 15, with no source. Contradicted by 3.1.4 for macOS 27 on
  this Mac; treat as **unverified**.

**3.1.6 Speed.** Proxyman: the `networksetup` route "is slow and can delay starting
or quitting the app" (https://proxyman.com/docs/basic-features/proxy-setting-tool,
2026-10-31). No timing number found; I could not time it (the sandbox blocks the
tool). A full set or restore is several process spawns per service (get web, get
secure, set web, set web state, set secure, set secure state), each an
`AuthorizationCreate` plus an SCPreferences session. The existing
`RealExecutor` timeouts are 15 s query, 180 s mutate (`crates/aitm-ca/src/exec.rs`,
read 2026-10-31).

**3.1.7 Which services.**
- `networksetup -listallnetworkservices`: first line is the header "An asterisk (*)
  denotes that a network service is disabled." then one name per line, disabled
  ones prefixed `*` (observed in probe.txt: header, `Display Ethernet`, `Wi-Fi`;
  man text, 2026-10-31). `-listnetworkserviceorder` adds `(Hardware Port: ..., Device:
  en15)` and the order number (observed).
- The Rust crate `sysproxy` (zzzgydi) filters the header and `*` lines and fails if
  no enabled service remains (source read via WebFetch, 2026-10-31).
- Practice: BaoLianDeng PR 117 sets HTTP, HTTPS and SOCKS "on every enabled network
  service" via `networksetup` (2026-10-31); a mitmproxy blog script loops over
  every listed service (search summary). ClashX.Meta's helper can filter to
  AirPort/Wi-Fi/Ethernet only (source read, 2026-10-31).
- Why more than one: macOS applies the proxy of the **primary** interface. Quinn
  (Apple DTS), Developer Forums thread 92039: "if you configure a proxy on Wi-Fi and
  then connect Ethernet, which becomes primary, the Wi-Fi proxy settings won't apply"
  (read 2026-10-31). On this Mac the order is Display Ethernet (en15) then Wi-Fi
  (en0) and `scutil --proxy` followed Display Ethernet when the two differed
  (observed, restore.txt "before": Display Ethernet HTTP No, HTTPS Yes; Wi-Fi both
  Yes; scutil `HTTPEnable : 0`, `HTTPSEnable : 1`).
- Stale and VPN services: `/Library/Preferences/SystemConfiguration/preferences.plist`
  holds 23 `NetworkServices` entries on this Mac (UUID-keyed, many stale
  `Ethernet Adapter (enN)` and `Thunderbolt Bridge`) against 2 in the current set
  (observed: root-owned, mode 0644, readable unprivileged). Proxyman issue 457
  (2020-03): `SCNetworkServiceCopyAll` "returns a network service, which does not
  exist in the Network", e.g. `Thunderbolt Bridge`. A direct-API implementation must
  walk the current set, not all services. VPN services carry a `Proxies` dict too
  (`s9labsVPN`, observed) and Proxyman's docs say some VPN apps "revert the HTTP
  proxy in the network settings as soon as Proxyman overrides it".

**3.1.8 Concurrent writers (observed).** Timeline from the orchestrator's files:
16:32:32 probe.txt, `scutil` `HTTPEnable : 0`, `HTTPSEnable : 0`, all four per-service
reads `Enabled: No` (residue 127.0.0.1:9090). ~16:33 lima-probe.txt: Display Ethernet
web proxy was already `Enabled: Yes` (the script assumed off). ~16:34 restore.txt:
Wi-Fi web and secure proxies `Enabled: Yes`, Display Ethernet secure `Yes`. 16:37
`preferences.plist` modified; at 16:42 every service in it has `HTTPEnable 0` and
`HTTPSEnable 0` (observed, plist read by me). So the proxies were on at 16:33 to
16:34, after being off at 16:32:32, and off again by 16:42, and none of the three
scripts' files records who did either switch (the orchestrator may know of an
unrecorded step). I did not find the actor. This is the strongest local argument that a saved "previous state"
can be stale or already replaced by the time we restore.

**3.1.9 Read the previous state per service and restore it.**
- `-getwebproxy <svc>` / `-getsecurewebproxy <svc>` print four lines (observed,
  probe.txt): `Enabled: Yes|No`, `Server: <host>`, `Port: <n>`, `Authenticated Proxy
  Enabled: 0|1`. Never-configured prints `Enabled: No`, empty `Server:`, `Port: 0`,
  `Authenticated Proxy Enabled: 0` (Snowflake docs sample for `-getsecurewebproxy`,
  2026-10-31; the `sysproxy` crate parses it as `Enabled:`/`Server:`/`Port:` and
  maps empty host to port 0).
- On disk the two cases differ (observed, preferences.plist): a **disabled residue**
  has `HTTPEnable 0` plus `HTTPProxy 127.0.0.1`, `HTTPPort 9090` (Display Ethernet,
  Wi-Fi); a **never-configured** service has a `Proxies` dict with only
  `ExceptionsList` and `FTPPassive`, no `HTTP*` keys. Both read back through
  `networksetup` as disabled; only the residue has a non-empty server.
- Write: `-setwebproxy <svc> <host> <port> [on|off <user> <password>]` "Turns proxy
  on" (help text, observed in `networksetup -help`); `-setwebproxystate <svc>
  on|off` flips the switch only; likewise `-setsecurewebproxy`,
  `-setsecurewebproxystate`.
- A restore of a **disabled residue** is `-setwebproxy svc host port` (which turns
  it on) then `-setwebproxystate svc off`; the `sysproxy` README states exactly
  that ("Restoring a disabled, configured endpoint writes the saved value and then
  switches it off") and that setters "are not atomic" (README read 2026-10-31).
  A restore of **never-configured** can restore "disabled" but may not remove the
  keys: whether `-setwebproxy svc "" 0` clears them is **unverified**; the
  `sysproxy` crate skips the endpoint write when the host is empty and only sets
  the state, and warns clearing a PAC URL "does not guarantee removal of the
  underlying SystemConfiguration key". Direct SCPreferences can remove keys
  (3.3).
- Authenticated proxies: the get output shows only the flag; where the saved
  password lives and whether a restore can reproduce it is **unverified**.
- PAC and discovery are separate switches (`-setautoproxyurl` "set proxy auto-config
  to url ... and enable it", manp.gs; `-getproxyautodiscovery` and
  `-setproxyautodiscovery` are present in the binary's strings, observed). A manual
  proxy set while a PAC URL is enabled may be shadowed; precedence is
  **unverified**. Proxyman's changelog has "v1.6.0: Fixed a bug where Proxyman
  couldn't restore the PAC URL when closed" (proxy-setting-tool page).

**3.1.10 Bypass list.** `-getproxybypassdomains <svc>` / `-setproxybypassdomains
<svc> <d1> ...`; `Empty` as the first value clears the list (help text, observed;
man text). Observed default `ExceptionsList`: `*.local`, `169.254/16`. ClashX.Meta
writes its own exceptions (private ranges, `127.0.0.1`, `localhost`, `*.local`,
`timestamp.apple.com`) and reads a user plist (`ProxySettingTool.m`, read
2026-10-31); Surge applies its skip-proxy list on "Set as System Proxy" (search
summary). Touching the list adds a second thing to snapshot and restore. Separate
from that list, Chrome's **implicit** bypass is `localhost`, `*.localhost`, `[::1]`,
`127.0.0.1/8`, `169.254/16`, `[FE80::]/10` and "Specifying an HTTPS proxy is
generally not possible through system proxy settings" (Chromium `net/docs/proxy.md`,
2026-10-31). Proxyman: "By default, on macOS, localhost requests don't go through
the system HTTP proxy" and offers a launched Chrome or `localhost.proxyman.io`
(proxyman.com troubleshooting page, 2026-10-31). Whether non-Chrome macOS clients
bypass localhost on their own is **unverified**.

### 3.2 macOS read path (unprivileged)

**3.2.1 `scutil --proxy` format (observed, probe.txt and restore.txt).**

```
<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 9090
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 9090
  HTTPSProxy : 127.0.0.1
}
```

With a protocol disabled, only `HTTPEnable : 0` (no `HTTPProxy`, `HTTPPort`) is
printed, while `-getwebproxy` still prints the residue (observed). Output is a
`key : value` text dump with nested `<array> {` blocks, not JSON or plist. Inside the
Claude sandbox it printed `<dictionary> {` `}` (observed), indistinguishable from
"no proxy".

**3.2.2 API keys.** `SCDynamicStoreCopyProxies(store)` (Apple, read 2026-10-31):
returns "key-value pairs that represent the current internet proxy settings, or
NULL if no proxy settings have been defined or if an error occurred"; keys
`kSCPropNetProxiesHTTPEnable` (CFNumber 0/1), `...HTTPProxy` (CFString),
`...HTTPPort` (CFNumber), the same three for `HTTPS`, `FTP`, plus
`...ExceptionsList` (CFArray of CFString) and `...FTPPassive`. The dictionary
printed by `scutil` uses these names without the prefix (`HTTPEnable`, etc.).
`CFNetworkCopySystemProxySettings()` returns the same shape for apps, plus a
`"__SCOPED__"` dictionary keyed by BSD interface name, each holding its own copy of
the keys (Developer Forums 92039, macOS 10.12.6 sample; Apple's CFNetwork page
points at "Global Proxy Settings Constants" for key names).

**3.2.3 Change notifications.** The store key behind the global answer is
`State:/Network/Global/Proxies` (Pythonmac-SIG 2005 post: `show
State:/Network/Global/Proxies` in `scutil` is the current state, `Setup:/Network/Service/N/Proxies`
the saved config; Google macops `systemconfig.py` reads the same key; hahnlee/aim
issue 112 proposes watching it; all **search summaries**, not Apple docs).
`SCDynamicStoreSetNotificationKeys(store, keys, patterns)` "specifies a set of keys
and key patterns that should be monitored for changes" (Apple, 2026-10-31); the
Mullvad crate exposes `set_notification_keys` and `create_run_loop_source` (3.2.4).
A run loop or dispatch queue is needed to receive callbacks (Apple page has no
discussion; **inference** from the API shape).

**3.2.4 Rust crates.** `system-configuration` **0.8.0**, license **MIT OR Apache-2.0**
(docs.rs, 2026-10-31). Safe modules: `dynamic_store`, `network_configuration`,
`network_reachability`, `preferences`.
- `SCDynamicStore`: `get_keys`, **`get_proxies() -> Option<CFDictionary<CFString,
  CFType>>`**, `get`, `set`, `set_raw`, `remove`, **`set_notification_keys`**,
  **`create_run_loop_source`**.
- `SCPreferences`: `default`, `group`, `new` only. No authorization, no commit, no
  apply, no lock.
- `SCNetworkService`: `get_services(prefs)`, `enabled()`, `network_interface()`,
  `id()`. `SCNetworkInterface`, `SCNetworkSet`, `get_interfaces` also exist.
- `system-configuration-sys` **0.6.0** (raw FFI) lists `SCPreferencesCreateWithAuthorization`,
  `SCPreferencesCommitChanges`, `SCPreferencesApplyChanges`, `SCPreferencesLock`,
  `SCNetworkProtocolSetConfiguration`, `SCNetworkSetCopyCurrent`,
  `SCNetworkServiceCopyProtocol` (names only; each marked unsafe). Its license was
  **not read**.
- Repo facts (read 2026-10-31): `system-configuration` is **not** in `Cargo.lock`
  (grep count 0). `security-framework 3.7.0` and `core-foundation 0.10` are, as
  macOS-only dependencies of `aitm` (`crates/aitm/Cargo.toml`). The workspace sets
  `unsafe_code = "forbid"`, and the repo's precedent for needing FFI is a tiny
  isolating crate (`aitm-peer-token` "holds the one `unsafe` `getsockopt` call so that
  this crate can keep the workspace `unsafe_code = "forbid"`").
- A text-parse of `scutil --proxy` through `Executor` needs no crate but is the
  format in 3.2.1; the sandbox case in 3.2.1 must map to "unknown".

**3.2.5 Reading honestly.** Four different "truths" were observed or sourced:
1. Persisted per-service config: `preferences.plist`, `networksetup -get*` (shows
   residue for disabled).
2. Effective global state for the primary service: `scutil --proxy`, `State:/Network/Global/Proxies`.
3. Session-scoped dynamic-store proxies: opencodex issue 5853 reports per-service
   `networksetup` reads "reported `Enabled: No` on every configured network
   service while the system proxy was in fact active" because "proxy clients
   commonly publish the proxy through the session-scoped system configuration
   dynamic store" (page read 2026-10-31).
4. What an app sees: `CFNetworkCopySystemProxySettings`.
A status that says "points at us" would be the global answer (2) matching our
host and port with `*Enable = 1`; a mismatch with (1) after our own write is a
signal that another actor or a VPN overrode it (3.1.7, 3.1.8).

### 3.3 macOS direct API write (`SCPreferencesCreateWithAuthorization`)

- Apple: `SCPreferencesCreateWithAuthorization(allocator, name, prefsID, authorization)`
  "Initiates access to the per-system set of configuration preferences with the
  specified authorization"; `authorization` is "an authorization reference that is
  used to authorize any access to the enhanced privileges needed to manage the
  preferences session"; no rights are named (page read 2026-10-31).
  `SCPreferencesCommitChanges` "commits changes to persistent storage. To apply the
  changes to the running system, use the SCPreferencesApplyChanges function".
- The right in play is `system.services.systemconfiguration.network` (named in
  networksetup's strings, 3.1.3). For a caller that is **not** entitled, the rule in
  3.1.2 leaves root or `authenticate-admin-nonshared`: an admin authentication,
  non-shared (**inference** from the rule; no run).
- BaoLianDeng PR 117 (2026-10-31): "`SystemProxyConfigurator` runs
  `/usr/sbin/networksetup` instead of using SCPreferences ... The tool carries the
  private entitlement for `system.services.systemconfiguration.network`, so admins
  avoid a password prompt ... calling `SCPreferencesCreateWithAuthorization` from
  the app would prompt on every change." Secondary (a PR description), consistent
  with 3.1.1.
- Who uses the API: ClashX.Meta's root helper `ProxySettingTool.m` calls
  `AuthorizationCreate(... kAuthorizationRightExecute ...)`, `SCPreferencesCreate(nil,
  CFSTR("ClashX"), nil)`, enumerates `kSCPrefNetworkServices`, writes
  `/NetworkServices/<id>/Proxies` with `SCPreferencesPathSetValue`, then
  `SCPreferencesCommitChanges`, `SCPreferencesApplyChanges`,
  `SCPreferencesSynchronize` (source read 2026-10-31). Proxyman's helper is "the
  Network Configuration framework": issue 177's changelog (2019-06-22) lists "Able
  to override proxy config by using Network Configuration framework", issue 457 says
  it calls `SCNetworkServiceCopyAll`, and its debug log line is "[NetworkSystem]
  HTTP Override by HelperTool (New APIs)" (issue 1743). NCC Group's advisory lists
  the helper's methods `overrideProxySystemWithAuthorization:setting:reply:`,
  `revertProxySystemWithAuthorization:restore:reply:`,
  `legacySetProxySystemPreferencesWithAuthorization:enabled:host:port:reply:`,
  `getVersionWithReply:`, `connectWithEndpointReply:`. So yes: Proxyman's "high
  performance" helper is the direct SystemConfiguration route run as root, with
  no `networksetup` process spawn (the performance claim itself is Proxyman's).
- Removing keys exactly (the never-configured case in 3.1.9) is possible here and
  not through `networksetup` (**inference**).

### 3.4 Privileged helper on macOS (candidate "helper")

**3.4.1 Apple's guidance** (Quinn, DTS, "BSD Privilege Escalation on macOS",
forum thread 708765, revised 2025-03-24, read 2026-10-31): `sudo`, `authopen`,
`osascript` are "not appropriate to use as API"; `AuthorizationExecuteWithPrivileges`
"deprecated for many years. Do not use it in a widely distributed product"; AppleScript
`do shell script ... with administrator privileges` is for "an ad hoc solution to
distribute to a limited audience"; "If you need ongoing privileges but don't want
to ship an installer package, use `SMAppService`. If you need to deploy to older
systems, use `SMJobBless`." "Do not use a setuid-root executable. Ever." A helper
authorising the XPC client by code signature "is a challenge"; the check "is based
on the code signature of the process's main executable", so an in-process plug-in
is indistinguishable. "Do not run GUI code as root."

**3.4.2 SMJobBless (deprecated macOS 13.0).** Apple's page (read 2026-10-31):
the calling app is signed and its `Info.plist` has `SMPrivilegedExecutables`
(label to code-signing requirement); the helper has an embedded `Info.plist` with
`SMAuthorizedClients`; the helper sits in `Contents/Library/LaunchServices` named
by its launchd label; the caller passes an authorization reference holding
`kSMRightBlessPrivilegedHelper`. Installed location `/Library/PrivilegedHelperTools/<label>`
(Proxyman docs; Charles via a Jamf thread, **search summary**: label
`com.xk72.charles.ProxyHelper`, plist in `/Library/LaunchDaemons` with a `MachServices`
entry). The prompt is the standard admin authentication dialog ("Click Install
Helper Tool and enter your password when prompted", Kodeco tutorial; Delinea docs
name the right "Bless Helper Authorization Right (com.apple.ServiceManagement.blesshelper)"
and say Charles uses SMJobBless). Failure mode seen in the wild: `CFErrorDomainLaunchd
error 9` (Proxyman issue 1113, 2021, macOS 11.6.1; a Charles write-up) and `Code=4`
when run from a CLI binary (issue 1767).

**3.4.3 SMAppService daemon (macOS 13+).** Apple's page (read 2026-10-31):
"For `SMAppServices` initialized as `LaunchDaemons`, the `register()` and
`unregister()` methods provide a replacement for installing property lists in
`/Library/LaunchDaemons`"; `register()` "Registers the service so it can begin
launching subject to user approval"; `daemon(plistName:)`, `status`,
`openSystemSettingsLoginItems()`. The `Status` case names (`notRegistered`,
`enabled`, `requiresApproval`, `notFound`) come from the theevilbit post
(2026-10-31) and the Apple page does not list them in the text I could read.
Layout (a working sample, malpern/privileged_helper_help, archived 2025-08-22,
read 2026-10-31): daemon plist in `Contents/Library/LaunchDaemons/<label>.plist`
with `Label`, `BundleProgram` (`Contents/MacOS/<helper>`, relative to the bundle),
`AssociatedBundleIdentifiers` (the main app's bundle id) and `MachServices`; the
`.plist` extension is required in `daemon(plistName:)`; mixing in legacy
`SMAuthorizedClients`/`SMPrivilegedExecutables` gives error 108 "Unable to read
plist". Nothing is moved to `/Library/PrivilegedHelperTools` (theevilbit).
Approval: user approves the background item in System Settings, General, Login
Items (and Extensions on 15+), "if users approve, they will be prompted for
authentication, as installing a daemon requires root privileges", and "if the
daemon was approved once, unregistering and registering it again doesn't require
further authentication" (theevilbit, secondary); WWDC22 "What's new in privacy"
says a daemon "with elevated permissions ... needs admin approval to enable"
(search summary). `register()` itself shows no password dialog; `requiresApproval`
is the normal first result and the app opens Login Items (secondary: two sample
projects and Apple Developer Forums 707482/719862). Known pain: Apple forums 707482,
the engineer: "The state is persisted to preserve user intent" and the recovery is
`sfltool resetbtm` plus reboot; 721919 (macOS 13.1): closing the approval
notification can leave no way to approve. MDM can pre-approve (DEV Community,
search summary). I did **not** test any of this on macOS 27.

**3.4.4 Notarization of nested code.** Apple's notarization requirements (read
2026-10-31): Developer ID certificate, hardened runtime, secure timestamp, valid
signatures on "all of the executables you distribute". The page does not discuss
nested helpers. Local fact (research 10, `apps/mac/build.sh`, `scripts/notarize-dmg.sh`,
read 2026-10-31): the build already signs inside-out (obscura, `aitm`, then the
app; sysex first when present) and research 10 records "nested code is covered by
notarizing the DMG". A helper binary and its plist under `Contents/Library/LaunchDaemons`
would be another nested item in that sequence.

**3.4.5 Authenticating the XPC peer.** `NSXPCConnection.setCodeSigningRequirement(_:)`
(macOS 13.0+, Apple, 2026-10-31): "Use this method to enforce a code-signing
requirement on the peer process"; "If new messages don't match the requirement, the
connection becomes invalidated"; call before `resume()`. Cautionary record:
- Proxyman issue 364 (2019-12-29, closed same day): "we don't validate the codesign
  of incoming NSXPCConnection"; fixed by "Validate the code-sign of connections".
- NCC Group advisory, CVE-2023-45732 (read 2026-10-31): the helper's
  `listener:shouldAcceptNewConnection:` holds six requirement strings (identifier
  plus Apple Development leaf or Team ID `3X57WP8E8V`); the unsigned, flagless
  Proxyman 1.3.4 satisfied the Team ID form and, with `DYLD_INSERT_LIBRARIES`,
  set the system proxy of an up-to-date install to 127.0.0.1:5555. Fix in helper
  1.5.0 (Proxyman 4.13.0): caller must be notarized, signed with the team cert, with
  Library Validation and the hardened-runtime flag.
- ClashX.Meta's helper: the validity check is commented out in source
  (`// if (![self connectionIsValid:newConnection]) {`); any local process that can
  reach the Mach service can change the system proxy (source read 2026-10-31).
So a helper whose API is "set the system proxy to X" is a standing local
proxy-redirection primitive; its peer requirement is the whole security boundary.

**3.4.6 Crash-safe revert in a helper.**
- Proxyman: issue 420 (2020-02-28, "All done" 2020-02-29): acceptance "Monitor the
  parent app (Proxyman) and gratefully revert the HTTP Proxy config"; changelog "Start
  5 seconds timers on the Helper Tool to check whether or not the parent app is
  quitted unexpectedly", "Revert the HTTP Proxy changes", "Get the pid when
  accepting the NSXPCConnection". Helper 1.2.1 shipped "Graceful revert Proxy config
  if the app is crashed" (changelog, 2021-02-17, Proxyman 2.18.0). Helper 1.3.0
  (2021-07-17, 2.30.0): "Remember and restore your previous HTTP/HTTPS/SOCKS Proxy
  config" (issue 923: "change back to the original IP/Port").
- ClashX.Meta: the helper does not own the revert; the app passes a settings
  dictionary to `restoreProxyWithCurrentPort:...info:...`; the helper quits when no
  clients remain (source read).
- Apple's `NSXPCConnection` `interruptionHandler` is "called if the remote process
  exits or crashes" and `invalidationHandler` fires when "the connection has
  terminated and may not be re-established" (Apple, 2026-10-31); Proxyman's notes
  say they chose a PID timer, not this (reason not stated).

**3.4.7 Who else.** Charles: SMJobBless helper, `com.xk72.charles.ProxyHelper`
(Delinea, Jamf summary); its doc says "When you first install Charles you will be
prompted to grant permissions to Charles to autoconfigure the proxy settings" and
that Charles configures "whenever Charles is started or quit". Surge: a helper;
"If the Surge Mac Helper is abnormal, it will cause the system proxy to not be set"
and the reset flow has the user click Remove Helper, enter the password twice and
reboot (Surge KB FAQ, 2026-10-31). Shadowrocket-style tools were not researched
(**unverified**). mitmproxy's macOS redirector is a Network Extension, not a
system-proxy setter (3.5.2).

**3.4.8 What a helper costs this repo (facts, not a decision).** No
`SMAppService`/`SMJobBless` code exists today (grep of the repo, 2026-10-31). The
Mac app is a Swift package with `build.sh` and `scripts/notarize-dmg.sh`; the core
`aitm` is also run as a bare CLI and on Linux (research `10-linux-packaging`). An
`SMAppService` helper can only be registered by an app bundle: Proxyman's maintainer
said a CLI binary cannot SMJobBless ("it's not technically possible", issue 1767,
2023-09-14) and shipped `sudo .../proxyman --install-privileged-components` instead,
which is a `sudo` line. Helper version skew is real: Proxyman says "You must
reinstall it when Proxyman ships a new Helper Tool version".

### 3.5 Crash-safe revert without a helper

**3.5.1 Mechanisms.**
- **Saved-state file, restored next start.** Charles: "if Charles is stopped
  abnormally (such as a crash) it doesn't have an opportunity to reset your proxy
  settings. It should notice that when it is restarted" (Charles FAQ, 2026-10-31).
  BaoLianDeng PR 117: "a persisted 'applied' flag lets the app clean up leftovers
  on the next launch" plus a synchronous clear in `willTerminateNotification`.
  Covers SIGKILL, panic, power loss and reboot, but only when `aitm` runs again;
  the proxy setting itself survives reboot (it lives in `preferences.plist`,
  observed). Until then the operator has no working network if the port is dead
  (Proxyman issue 420's own problem statement: "the entire system couldn't access to
  the Internet").
- **Watcher process.** `kqueue` `EVFILT_PROC` with `NOTE_EXIT`: "The process has
  exited"; "If a process can normally see another process, it can attach an event to
  it"; `ESRCH` if the pid does not exist (kqueue(2), 2026-10-31); a non-child
  watch is implied but not stated. Plain `getppid()` polling or stdin EOF are the other
  portable watchers (none was verified here; the auto-memory index mentions an
  `aitm web` stdin-EOF exit, but a grep of `crates/aitm/src` for stdin, EOF and
  parent found nothing). Proxyman's helper is exactly a watcher
  (5 s poll).
- **Linux `prctl(PR_SET_PDEATHSIG)`**: signal sent when "the thread that created
  this process" terminates (not the whole parent); cleared for the child of a
  `fork`, cleared on exec of a set-user-ID/capability binary; "If the parent thread
  and all ancestor subreapers have already terminated by the time of the
  PR_SET_PDEATHSIG operation" no signal is sent (man7.org, 2026-10-31). Its absence
  on macOS is **unverified** (not in any source I read).
- A watcher must be a separate process that survives the death of the thing it
  watches, so it cannot be a child that is signalled with its parent
  (**inference**), and it cannot cover reboot or power loss.

**3.5.2 What the references do.** Proxyman: helper-side parent poll (3.4.6).
Charles: restart-time notice only (3.5.1). BaoLianDeng: applied flag. ClashX.Meta:
the app restores. mitmproxy: the modes page (read 2026-10-31) says regular mode
needs "explicitly setting an HTTP proxy"; local capture on macOS "uses low-level
operating system APIs" and is egress only; no system-proxy feature is mentioned and
I found no request for one. mitmproxy_rs's macOS redirector is a signed Network
Extension app that needs a one-time approval and, on stop, is left installed with
an empty intercept spec to avoid repeated prompts (search summary of
mitmproxy_rs README and markmals/recon issue 62).

### 3.6 Linux

**3.6.1 GNOME `gsettings` (read from `gsettings-desktop-schemas`
`org.gnome.system.proxy.gschema.xml.in`, 2026-10-31).**

| Schema | Key | Type | Default | Note |
|---|---|---|---|---|
| `org.gnome.system.proxy` | `mode` | enum `none`,`manual`,`auto` | `'none'` | the switch |
| | `autoconfig-url` | s | `''` | PAC |
| | `ignore-hosts` | as | `['localhost', '127.0.0.0/8', '::1']` | bypass |
| | `use-same-proxy` | b | `true` | "Use HTTP proxy for all protocols" |
| `.http` | `host` / `port` | s / i | `''` / `8080` | |
| `.http` | `enabled` | b | `false` | "Unused; ignore" |
| `.http` | `use-authentication`, `authentication-user`, `authentication-password` | b,s,s | | |
| `.https` | `host` / `port` | s / i | `''` / `0` | |
| `.ftp`, `.socks` | `host` / `port` | s / i | `''` / `0` | |

Writes are `gsettings set <schema> <key> <value>`, reads `gsettings get`, live
watch `gsettings monitor` (command forms from the gsettings tool; the man page
fetch failed, **unverified here**). Value text is GVariant (`'manual'`, `['a','b']`).
XFCE: v2rayN's script routes XFCE through the same `gsettings` function
(issue 6937, 2025-03; secondary).

**3.6.2 What `gsettings set` needs and how it fails.** It needs the dconf
GSettings backend and a reachable session D-Bus. Texts seen in sources
(2026-10-31, search summaries unless stated):
- no bus and no `$DISPLAY`: `dconf-WARNING **: ... failed to commit changes to
  dconf: Cannot autolaunch D-Bus without X11 $DISPLAY` (Baeldung, Ardour forum,
  FreeBSD forum);
- stale `DBUS_SESSION_BUS_ADDRESS`: `Could not connect: Connection refused`;
- no `dbus-launch`: `failed to commit changes to dconf: Failed to execute child
  process "dbus-launch" (No such file or directory)` (Red Hat Bugzilla 1337612,
  closed WONTFIX);
- no dconf module: `GLib-GIO-Message: Using the 'memory' GSettings backend. Your
  settings will not be saved or shared with other applications.` (Ubuntu bug
  757866, closed Invalid: "glib provides only a memory backend for testing and
  hacking ... you likely want to install dconf", page read directly).
Whether `gsettings set` exits non-zero in these cases is **unverified**; the memory
backend case looks like a **silent success that persists nothing**, so the honest
check is a separate `gsettings get` process after the set (**inference**).
A temporary bus from `dbus-run-session` does not write the database a real desktop
session reads (same sources); a process started by systemd, SSH or a service lacks
the session variables (the sing-box issue shows `kwriteconfig6` exiting 2 under
systemd). Observed in the Lima VM `default` (Ubuntu 24.10, `/tmp/claude/sysproxy/lima-probe.txt`):
`gsettings` and `dbus-run-session` are installed, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/501/bus`,
`DISPLAY` and `XDG_CURRENT_DESKTOP` are empty, no `kwriteconfig`. I tried a read-only
`gsettings get` there but the sandbox blocks `limactl` (`connect ... ssh.sock:
Operation not permitted`), so the VM's real behaviour is **not observed**.

**3.6.3 KDE Plasma.** Commands in use (v2rayN issue 6937 script; Throne issue
1017 log; both 2025-2026, secondary):

```
kwriteconfig6 --file kioslaverc --group "Proxy Settings" --key ProxyType 1
kwriteconfig6 --file kioslaverc --group "Proxy Settings" --key httpProxy  <value>
kwriteconfig6 --file kioslaverc --group "Proxy Settings" --key httpsProxy <value>
kwriteconfig6 --file kioslaverc --group "Proxy Settings" --key NoProxyFor <list>
dbus-send --type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration string:""
```

`kwriteconfig5` for `KDE_SESSION_VERSION` other than 6; unset is `ProxyType 0`.
`ProxyType` values follow `KProtocolManager::ProxyType` (`NoProxy, ManualProxy,
PACProxy, WPADProxy, EnvVarProxy`, KDE 4.14 API docs; the integers 0 to 4 are by
declaration order and a third-party note, not stated in the docs). Value format is
inconsistent in the wild: `http://127.0.0.1 2080` (space before the port, Throne
log) versus `http://ip:port` (v2rayN); a FlClash report (issue 2488, search summary)
says an `https://` scheme on `httpsProxy` broke Chromium and `http://` fixed it.
The correct form is **unverified**. Throne issue 1017: setting only KDE left GTK
apps unproxied until `gsettings set org.gnome.system.proxy mode manual` was added.
No `kwriteconfig` on this Mac (observed), so nothing here was run.

**3.6.4 NetworkManager.** Proxy support is per connection and PAC-based: `proxy.method`
`none` (0, default) or `auto` (1), `pac-url`, `pac-script`, `browser-only`; there
is no manual-proxy method and no global proxy (NetworkManager `nm-settings` /
libnm `NMSettingProxy` reference and an Arch forum thread, search summary,
2026-10-31).

**3.6.5 Who honours what.**
- **Firefox**: `nsUnixSystemProxySettings.cpp` reads `org.gnome.system.proxy`
  (`mode` `manual` uses per-protocol host/port and `ignore-hosts`; `auto` returns
  `autoconfig-url`; any other mode, including `none`, falls through to environment
  variables `<scheme>_proxy`, `all_proxy`, `no_proxy`); no GConf, **no KDE**
  reference (source read, 2026-10-31). Needs "Use system proxy settings" selected
  (Mozilla and Charles docs).
- **Chromium**: header comment says settings come "from environment variables,
  gconf, gsettings, or kioslaverc (KDE)", gsettings on the glib main thread
  (`proxy_config_service_linux.h`, read 2026-10-31); it cannot express an HTTPS proxy
  via system settings (net/docs/proxy.md).
- **curl** reads environment variables (`http_proxy`, `HTTPS_PROXY`, `ALL_PROXY`,
  `NO_PROXY`) and `-x` overrides them (curl manual, 2026-10-31); the page does not
  mention desktop settings.
- Terminal emulators of GNOME may export `http_proxy` into shells they open;
  `sudo`, SSH and systemd services never see it (a guide, search summary).
  `/etc/environment` semantics were not read (**unverified**); a running process's
  environment cannot be changed from outside.

**3.6.6 What the reference tools do on Linux.** Charles' browser-and-system page
lists Windows, macOS and Firefox as auto-configured and has no Linux section
(2026-10-31); manual steps only. mitmproxy: nothing (3.5.2). Burp: not researched
(**unverified**). Commercial Proxyman for Linux: no documentation found on how it
sets the system proxy (**unverified**); the open-source `himanshub16/ProxyMan`
is a different project that scripts `gsettings` (`mode manual`, host/port keys;
`none` to unset; search summary).

### 3.7 Windows (seam only)

WinINET proxy settings are values under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet
Settings`: `ProxyEnable` (DWORD 1/0), `ProxyServer` (string), `ProxyOverride`,
`AutoConfigURL`; after writing, apps pick it up only if the writer calls
`InternetSetOption` with `INTERNET_OPTION_SETTINGS_CHANGED` (39) and
`INTERNET_OPTION_REFRESH` (37) (INCY-DEV issue 4 and the Microsoft-authored
`WinInetProxy` PowerShell module, 2026-10-31; search summary). HKCU needs no admin;
the `WinInetProxy` module's "requires local admin" note concerns its HKLM/policy
variants (**inference**, not a Microsoft page read). Charles: "By default Charles
will configure and then reconfigure the Windows proxy settings whenever Charles is
started or quit" (Charles docs). The repo's `aitm-ca` already has a `windows.rs`
platform module (read 2026-10-31).

### 3.8 UX prior art

- **Proxyman first launch.** Kodeco: "When you open Proxyman for the first time,
  it'll prompt you to Install Proxy Helper Tool ... Click Install Helper Tool and
  enter your password when prompted"; alt text on the screenshot only, the dialog's
  checklist text is not in the article. Proxyman's 2019 launch post lists
  "Automatically override your HTTP/HTTPS Proxy in System Network Preference",
  "Prompt to install Proxyman Helper Tool", and "Gracefully revert the HTTP/HTTPS
  Proxy if the app is unexpectedly crashed" as benefits of the helper (2026-10-31).
  Your quoted button text "Install Helper Tool (Required Root Privileges)" and the
  checklist wording were **not found in a page I could read**; cite them as your
  observation.
- **Proxyman fallback and nudge.** If skipped, install later in Settings, Advanced
  (docs). Troubleshooting page: "By default, Proxyman overrides the system HTTP proxy
  with the networksetup command line tool, but it can fail in some cases ... Install
  the Proxy Helper Tool." On macOS 13+ the helper must also be allowed under System
  Settings, Login Items (Login Items & Extensions on 15+), and Settings, Advanced has
  a button that opens that pane. Issue 1743's log shows `[HelperToolSuggestion] Skip
  because the user ask for it!`, so a decline is stored; the "No HTTP Traffic ...
  Don't ask again" alert text itself was **not found**. Proxyman also has
  `proxyman-cli proxy on|off` from 4.8.0 and `--install-privileged-components` from
  4.12.0 (docs; the latter is run under `sudo`). Issue 1767's reporter asked for a
  silent managed install and was told it is "technically hard"; a participant notes the
  flag still opens the app and needs a click.
- **Charles.** First install: "you will be prompted to grant permissions to Charles to
  autoconfigure the proxy settings" (Charles docs); the dialog's button is Grant
  Privileges and the menu entry is Proxy, macOS Proxy with a tick (setup guides,
  search summary; the Charles page I read has no such wording); toggle with
  Cmd+Shift+P (Kodeco, search summary). Delinea: with a policy "Grant Privileges"
  approves the install without an admin prompt.
- **Surge.** First "Set as System Proxy" asks for the system password (older guide,
  search summary).
- **Coexistence warnings.** Proxyman: some VPN apps revert the proxy; the system proxy
  "cannot be enabled while Network Extension capture is on" (search summary, not
  confirmed on the page); issue 1743 maintainer reply: AnyConnect "is incompatible
  with Proxyman and Charles Proxy".

### 3.9 Existing seam in the repo (facts, read 2026-10-31)

- `crates/aitm-ca/src/exec.rs`: `CmdLine { program, args, stdin, mutating }` (no
  env or cwd field), `CmdOutput { code, stdout, stderr }`, trait `Executor { run,
  read_file, dir_exists, home_dir, is_root }`, `RealExecutor` (15 s query / 180 s
  mutate timeouts, kills on expiry), `DryRunExecutor` (records `mutating` commands
  and returns synthetic success), and `absolute_program` which maps only `sudo`,
  `security`, `tee`, `rm`, `id` to absolute paths: `networksetup`, `scutil`,
  `gsettings`, `kwriteconfig6`, `dbus-send` are not in it.
- `crates/aitm-ca/src/platform/{macos,linux,windows}.rs`: all compile on every
  host and are tested against canned output; `mod.rs` holds the helpers `cmd`,
  `run`, `stderr_tail`, and `sudo_if_needed` (prefixes `sudo --` when not root,
  "the process never escalates itself"). That privilege model is the one this task
  rules out, so `sudo_if_needed` is not reusable as is. `macos.rs` has a precedent
  for headless detection by stderr markers (`HEADLESS_MARKERS`) and for a
  check-first, parse-stdout style. `unsafe_code = "forbid"` (3.2.4).
- Default listen `127.0.0.1:8080` (`crates/aitm-core/src/config.rs`).

## 4. Candidate directions (not decisions)

**A. `networksetup` shell-out through `Executor` (macOS), user-level.** One
`Command` list per operation (list services, per-service get web/secure, set,
state, restore), parsers over canned output, snapshot file, read-back after every
write.
- Pro: no privilege handling for an admin user with the setting off (observed);
  fits the `Executor`/canned-output tests and `unsafe_code = "forbid"`; same
  recipe as BaoLianDeng, Proxyman's fallback and the `sysproxy` crate.
- Con: needs root when "Require an administrator password" is on and fails for
  standard users (3.1.5); slow, multiple spawns per service; not atomic;
  cannot remove keys; `networksetup` exit code on failure unverified; no change
  notification.

**B. A plus an in-process SCDynamicStore reader.** `system-configuration` 0.8.0
`get_proxies` for status and `set_notification_keys` + run loop for live updates;
or parse `scutil --proxy` text through `Executor`.
- Pro: unprivileged, matches what apps see, no polling; answers the primary-service
  question. Crate is MIT OR Apache-2.0 and safe-API for this part.
- Con: new macOS-only dependency and CoreFoundation types; the notification path
  needs a run loop thread; text parse is more testable but brittle; must map an
  empty dictionary (sandbox, error) to "unknown", never "off".

**C. Privileged helper via `SMAppService.daemon` (macOS app only).** A root daemon
inside the app bundle (plist in `Contents/Library/LaunchDaemons`, `BundleProgram`,
`AssociatedBundleIdentifiers`, `MachServices`), XPC with
`setCodeSigningRequirement`, SystemConfiguration writes, parent-liveness revert.
- Pro: the only documented route that serves standard users and the
  "administrator password required" case; fast; revert after crash is the helper's
  job (Proxyman model); the OS shows its own approval and authentication UI.
- Con: Swift target, plist, entitlement and signing steps in `build.sh` and
  `notarize-dmg.sh`; first-run needs a user trip to System Settings (daemon
  `requiresApproval`) and has known stuck states; helper version-skew; the XPC
  requirement is a standing local-redirect risk (CVE-2023-45732, ClashX.Meta);
  unreachable from the bare CLI or Linux; I could not test it on macOS 27.

**D. Direct SCPreferences with `AuthorizationCreate` from the app or core.**
- Pro: exact key control, no process spawn, one commit for all services.
- Con: unentitled caller means an admin prompt per authorization (3.3, inference);
  needs `unsafe` FFI (`-sys` only) or a Swift shim; evidence in 3.3 suggests it is
  dominated by A for admins and by C for standard users.

**E. A, with an `osascript ... with administrator privileges` retry only for the
"requires admin privileges" case.** Apple DTS lists it for "an ad hoc solution"
(3.4.1). Pro: the dialog is the OS's. Con: needs a GUI session (same headless
failure family as `add-trusted-cert`, research 07 3.1); a password dialog on every
change; root-owned side effects; DTS advises against it in widely distributed
products.

**F. Crash revert options, combinable.** (1) Atomic state file written before the
first change (service, protocol, enabled, host, port, bypass untouched, our own
host:port, timestamp), read at start; (2) a detached watcher process
(`kqueue NOTE_EXIT` or `getppid` poll) that restores after `aitm` dies, which
also covers a `SIGKILL`; (3) helper-side watcher (C). A and B alone cover
quit and panic only if the restore runs in-process, so (1) is the floor.
Restore should be conditional: restore a field only if the system still equals
what we set, because other actors write (3.1.8) and VPN apps revert (3.1.7).
Trade-off: a watcher is a second process to supervise and test; reboot and power
loss need (1).

**G. Linux: `gsettings` (GNOME, XFCE, Cinnamon-family) and `kwriteconfig6/5`
plus `dbus-send` (KDE), chosen by desktop detection, user-level, no privilege.**
Read-back by a separate `gsettings get` / `kreadconfig` process. Report
"unsupported on this desktop" with env-var guidance rather than claiming success.
- Pro: no prompt, simple `Executor` fit.
- Con: silent non-persistence on memory backend (3.6.2); session-bus
  discovery under services; KDE value format unverified; NetworkManager and bare
  window managers have no global proxy; curl and most CLIs never read it;
  Firefox ignores KDE settings.

**H. Status model.** A reply per attempt with: which services were touched, before
snapshot, after read-back, and a verdict among {points at us, points elsewhere,
not set, unknown}, with "unknown" for an empty or failed read. Pro: keeps the
honesty constraint explicit. Con: the primary-service rule and scoped proxies
(3.2.5) make "points elsewhere" harder to explain.

**I. Windows seam.** A trait method per platform with the registry plus
`InternetSetOption` behind it; not built now (3.7).

## 5. Open questions

1. **Latency of `networksetup`.** Not timed (sandbox blocks it). Needs a run outside
   the sandbox: per-call and per-full-restore on this Mac.
2. **Exact standard-user failure.** Text, exit code and whether any dialog appears
   for a non-admin account; also for an admin with "Require an administrator
   password" on, on macOS 27. Needs a second user account or a VM.
3. **Does `-setwebproxy svc "" 0` clear the keys, and does setting a never-configured
   service back to off leave the `Proxies` dict as it was?** Compare `preferences.plist`
   before and after.
4. **Which actor flipped the proxies between 16:32 and 16:42 today.** Unknown; check
   `log show --predicate 'subsystem == "com.apple.SystemConfiguration"'` or the
   other running proxy tools.
5. **Precedence of PAC / auto-discovery over a manual proxy** on a service that has
   one enabled, and how to snapshot it.
6. **Authenticated proxies**: where the password lives and whether it restores.
7. **SMAppService daemon on macOS 27**: the actual prompts, the admin authentication
   step, and the stuck-state recovery; all sources are macOS 13 to 15 era.
8. **Proxyman's first-launch sheet and "No HTTP Traffic" alert**: only your screenshot
   observation; no readable source for the exact text.
9. **Linux behaviours** unobserved: `gsettings set` exit codes in the three failure
   modes, whether the memory-backend case exits 0, dconf presence in the Lima VM,
   KDE value format, Burp and Proxyman-for-Linux behaviour, `/etc/environment`.
10. **Whether the system proxy and NE "All Apps" capture can both be on**
    (Proxyman says not; unconfirmed).
11. **Which macOS clients bypass localhost without being told** (Chrome does).
12. **`system-configuration-sys` license** was not read.

## 6. Sources

Local (read or run 2026-10-31):
- `/tmp/claude/sysproxy/probe.txt`, `lima-probe.txt`, `restore.txt` and the scripts `probe.sh`, `lima-probe.sh`, `restore.sh` (orchestrator runs, ~16:32 to 16:34)
- `codesign -d --entitlements - /usr/sbin/networksetup`; `strings -a /usr/sbin/networksetup`; `networksetup -help` (sandbox); `/Library/Preferences/SystemConfiguration/preferences.plist` (read via `plutil -p` and Python `plistlib`); `ls -l` of that folder; `limactl shell default` (blocked)
- Repo: `docs/superpowers/WORKFLOW.md`, `docs/research/07-ca-install.md`, `docs/research/10-macos-network-extension.md`, `crates/aitm-ca/src/exec.rs`, `crates/aitm-ca/src/platform/{mod,macos}.rs`, `crates/aitm/Cargo.toml`, `crates/aitm-core/src/config.rs`, `Cargo.toml`, `Cargo.lock`, `apps/mac/build.sh`, `apps/mac/CLAUDE.md`, `scripts/notarize-dmg.sh`

macOS and Apple:
- SMAppService: https://developer.apple.com/documentation/servicemanagement/smappservice
- SMJobBless: https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless
- SCDynamicStoreCopyProxies, SCDynamicStoreSetNotificationKeys, SCPreferencesCreateWithAuthorization, SCPreferencesCommitChanges, CFNetworkCopySystemProxySettings (developer.apple.com documentation pages, read as JSON)
- NSXPCConnection `setCodeSigningRequirement(_:)`, `invalidationHandler`, `interruptionHandler`
- Notarizing macOS software before distribution
- BSD Privilege Escalation on macOS: https://developer.apple.com/forums/thread/708765
- CFNetworkCopySystemProxySettings dump (`__SCOPED__`, primary-interface note): https://developer.apple.com/forums/thread/92039
- SMAppService forums: https://developer.apple.com/forums/thread/707482 , https://developer.apple.com/forums/thread/739940 , https://developer.apple.com/forums/thread/721919 (search summary)
- kqueue(2): https://keith.github.io/xcode-man-pages/kqueue.2.html
- networksetup man text: https://manp.gs/mac/8/networksetup
- Authorization right `com.apple.ServiceManagement.daemons.modify`: https://www.dssw.co.uk/reference/authorization-rights/com-apple-servicemanagement-daemons-modify/
- theevilbit SMAppService notes: https://theevilbit.github.io/posts/smappservice/
- malpern sample: https://github.com/malpern/privileged_helper_help
- Snowflake `networksetup -getsecurewebproxy` sample: https://docs.snowflake.com/en/user-guide/client-connectivity-troubleshooting/mac-linux
- FlClash 2425: https://github.com/chen08209/FlClash/issues/2425 ; haiopass 2: https://github.com/haioco/haiopass/issues/2 ; opencodex 5853: https://github.com/lidge-jun/opencodex/issues/5853 ; BaoLianDeng PR 117: https://github.com/madeye/BaoLianDeng/pull/117
- Pythonmac-SIG 2005, Google macops `systemconfig.py`, hahnlee/aim 112, ordonez.tv, Tenable CIS audit item (search summaries only)
- Rust: https://docs.rs/system-configuration/latest/system_configuration/ (and `dynamic_store::SCDynamicStore`, `preferences::SCPreferences`, `network_configuration`), https://docs.rs/system-configuration-sys/latest/system_configuration_sys/ ; https://github.com/zzzgydi/sysproxy-rs (README; macOS source via raw.githubusercontent.com)

Tools and helpers:
- Proxyman helper docs: https://proxyman.com/docs/basic-features/proxy-setting-tool ; troubleshooting: https://proxyman.com/docs/troubleshooting/i-couldnt-see-any-traffics-on-proxyman , https://proxyman.com/docs/troubleshooting/couldnt-see-any-request-from-localhost-server ; changelog: https://proxyman.com/changelog-archive ; launch post: https://proxyman.com/posts/2019-06-14-getting-started-with-proxyman ; issues 177, 364, 420, 457, 923, 1113 (search summary), 1743, 1767 at https://github.com/ProxymanApp/Proxyman/issues/
- NCC Group advisory CVE-2023-45732: https://www.nccgroup.com/research/technical-advisory-insufficient-proxyman-helpertool-xpc-validation/
- Kodeco Proxyman tutorial: https://www.kodeco.com/25354003-using-proxyman-to-inspect-network-traffic
- Charles: https://www.charlesproxy.com/documentation/configuration/browser-and-system-configuration/ , https://www.charlesproxy.com/documentation/faqs/ ; Delinea: https://docs.delinea.com/online-help/privilege-manager/computer-groups/policies/platform-specific/macos/examples/elevate-charles-proxy.htm ; Jamf thread (search summary; direct fetch 403): https://community.jamf.com/t5/jamf-pro/allow-standard-user-to-enable-macos-proxy-when-use-charles-web/m-p/232970
- ClashX.Meta (`ProxyConfigHelper/ProxySettingTool.m`, `ProxyConfigHelper.m` via the GitHub contents API): https://github.com/MetaCubeX/ClashX.Meta
- Surge FAQ: https://kb.nssurge.com/surge-knowledge-base/faq/common-faqs
- mitmproxy modes: https://docs.mitmproxy.org/stable/concepts/modes/ ; mitmproxy_rs macOS README and recon issue 62: https://github.com/markmals/recon/issues/62

Linux and cross-platform:
- GNOME schema: https://gitlab.gnome.org/GNOME/gsettings-desktop-schemas/-/raw/master/schemas/org.gnome.system.proxy.gschema.xml.in
- Firefox: https://raw.githubusercontent.com/mozilla/gecko-dev/master/toolkit/system/unixproxy/nsUnixSystemProxySettings.cpp
- Chromium: https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md , `net/proxy_resolution/proxy_config_service_linux.h`
- curl manual: https://curl.se/docs/manual.html
- Ubuntu bug 757866: https://bugs.launchpad.net/bugs/757866 ; Red Hat Bugzilla 1337612 , Baeldung gsettings remote shell (403 on direct fetch), Ardour forum, FreeBSD forum (search summaries)
- KDE: v2rayN issue 6937 https://github.com/2dust/v2rayN/issues/6937 ; Throne issue 1017 https://github.com/throneproj/Throne/issues/1017 ; KProtocolManager 4.14 API (search summary)
- NetworkManager `NMSettingProxy` / `nm-settings` (search summary): https://networkmanager.dev/docs/libnm/latest/NMSettingProxy.html
- prctl: https://man7.org/linux/man-pages/man2/pr_set_pdeathsig.2const.html
- Windows: INCY-DEV issue 4, `WinInetProxy` module https://www.powershellgallery.com/packages/WinInetProxy/0.1.0/Content/WinInetProxy.psm1 (search summary)

Not retrievable: Baeldung (403), Jamf community (403 on direct fetch), gsettings man page (404),
Apple Developer pages by HTML (JS-rendered; the JSON data endpoints were used),
`raw.githubusercontent.com`/`crates.io` from Bash (sandbox denied; WebFetch used).
