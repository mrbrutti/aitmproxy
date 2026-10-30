# Experiment: macOS Network Extension signing + activation spike (Task 1, GATING)

**Date:** 2026-10-30 (run on Matt's Mac, macOS 27.0 / Xcode 27.1, Apple Silicon)
**Branch/worktree:** `experiment/macos-ne-spike` (throwaway, never merged)
**Owner:** macos-ne-build session
**Plan:** `docs/superpowers/plans/2026-10-29-aitmproxy-macos-network-extension-plan.md` Task 1
**Result: PASS.** All four pass conditions met on a real Mac. The `[Mac]`/`[Build]`
band (Tasks 10-18) is unblocked.

## Hypothesis / risky parts being de-risked

Before building the real sysex, prove the scariest unknowns:
- Can a `NETransparentProxyProvider` **system extension** be **manually
  Developer-ID-codesigned** with the restricted `app-proxy-provider-systemextension`
  entitlement and **activate** on macOS 27 (research OQ3/6/7, spec OQ5/6)?
- Does activation work with the **A1-created App IDs + Developer ID profiles**?
- Which **parent-bundle location** works (`/Applications` vs `~/Applications`)?
- Is **peer authentication** over the Unix control socket feasible (`LOCAL_PEERTOKEN`/
  `LOCAL_PEERCRED`)?
- Is the **source-app identity** available per flow (for self-exclusion, NE-AC8)?

## Method

Throwaway host app (`AitmproxySpike.app`, bundle id `com.mrbrutti.aitmproxy`) with an
embedded do-nothing sysex (`com.mrbrutti.aitmproxy.ne.systemextension`). Built with
`xcrun swiftc` (no Xcode project), assembled by hand, signed inside-out with Developer
ID + the A1 profiles embedded as `Contents/embedded.provisionprofile`, notarized with
`notarytool`, stapled. The host submits `OSSystemExtensionRequest.activationRequest`,
sets up an `NETransparentProxyManager`, and runs a `0700`-dir Unix-socket listener. The
provider installs a catch-all outbound-TCP rule, reports each new flow's metadata over
the socket, and returns `false` (fail open). Sources live in the experiment worktree
under `spike/`; the captured host log is `spike-host.log`.

## Results (all four PASS)

**#2 — Signing / entitlements (automatable, no human):** `codesign -d --entitlements :-`
shows `app-proxy-provider-systemextension` on **both** the sysex and the app, and
`com.apple.developer.system-extension.install` on the app. `codesign --verify --deep
--strict` passes. **Manual Developer ID codesigning of a restricted-entitlement sysex on
macOS 27 / Xcode 27.1 works.**

**#1 — Activation:** after Matt approved the two System Settings prompts,
`systemextensionsctl list` shows:
```
*  *  995PCLM9KH  com.mrbrutti.aitmproxy.ne (0.1/1)  AitmproxyNE  [activated enabled]
```
Delegate log: `activation: didFinish result=0` → `proxy: configuration saved` →
`proxy: startVPNTunnel requested`.

**#3 — One flow across the 0700 socket:** the provider reported real flows to the host
over `/tmp/aitmproxy-spike/control.sock` (dir mode `0700`), including the deliberate test
flow right after `curl https://example.com` returned HTTP 200:
```
control<= (peer uid=0) sysex: startProxy OK, catch-all rule installed
control<= (peer uid=0) sysex: FLOW remote=example.com   sourceApp=com.apple.curl
control<= (peer uid=0) sysex: FLOW remote=alive.github.com sourceApp=com.apple.Safari
control<= (peer uid=0) sysex: FLOW remote=github.com    sourceApp=com.apple.git-remote-http
```

**#4 — Peer-auth + parent-bundle + source-app identity:**
- `getsockopt(..., LOCAL_PEERCRED, ...)` on the host returns the connecting peer's uid =
  **0** (the sysex runs as root) — **peer-credential auth is feasible**.
- Per-flow `flow.metaData.sourceAppSigningIdentifier` is populated
  (`com.apple.Safari`, `com.apple.curl`, `aitm-7728c895773169c7`, `com.openai.codex.helper`,
  …) — **self-exclusion by source-app identity (NE-AC8) is feasible**.
- Fail-open confirmed: `curl` got HTTP 200 while the provider returned `false`.

## Findings the real build (Band C) MUST adopt

1. **Parent bundle = `/Applications` only.** `~/Applications` is rejected with
   `OSSystemExtensionError Code=3 ("App ... must be in /Applications folder")`. **Resolves
   spec OQ1/OQ6: `/Applications` is required; `~/Applications` does NOT work.** Band C
   Tasks 14/18 must install to `/Applications`.
2. **Notarization is MANDATORY even for local activation on this Mac.** Before notarizing,
   activation failed with `Code=8 "code signature invalid"`. `systemextensionsctl developer
   on` is **SIP-blocked** ("cannot be used if System Integrity Protection is enabled"), so
   the usual dev-mode shortcut is unavailable — the sysex must be notarized to activate.
   Notarizing the app bundle with the existing ASC key (`notarytool submit --wait` →
   Accepted, `stapler staple`) works end-to-end. **This de-risks Band C Task 15 and means
   the dev loop itself must notarize (not just releases).**
3. **Peer auth:** `LOCAL_PEERCRED` (uid) works today; the full code-requirement check
   (`LOCAL_PEERTOKEN` → `SecCode`/requirement) is Band C Task 11's job. The uid read proves
   the socket-credential path is available.
4. **Build toolchain:** a plain `xcrun swiftc` + hand-assembled bundle + manual `codesign`
   works — an Xcode project is not strictly required for the sysex, though D6 still
   recommends Xcode for the real nested-signing ergonomics.
5. **NEProviderClasses:** `com.apple.networkextension.app-proxy` → `TransparentProxyProvider`
   (with `@objc(TransparentProxyProvider)`) resolved correctly.

## Reusable for Band C (head start)

The spike's working, signed, notarized Swift is a direct template for Band C:
- `spike/sysex/Provider.swift` → Task 10 (`NETransparentProxyProvider` skeleton, catch-all
  rule, fail-open `handleNewFlow`).
- `spike/sysex/main.swift` → Task 10 (`startSystemExtensionMode` + `dispatchMain`).
- `spike/host/main.swift` activation delegate + `NETransparentProxyManager` setup → Task 13.
- `spike/{sysex,host}/*.entitlements` → Task 14.
- The `swiftc`/`codesign`/`notarytool`/`stapler` sequence in `spike/build.sh` → Tasks 14/15.

## Teardown

Host app killed (stops logging immediately — the control socket is gone and the provider
fails open). The sysex itself cannot be removed via `systemextensionsctl uninstall` (also
SIP-blocked); clean removal is a System Settings toggle (Login Items & Extensions → Network
Extensions → turn off AitmproxyNE) plus removing `/Applications/AitmproxySpike.app`. This is
exactly the uninstall flow Band C Task 17 implements programmatically via
`OSSystemExtensionRequest.deactivationRequest` + removing the `NETransparentProxyManager`
configuration. Nothing from this branch is reused as code; only this write-up lands.
