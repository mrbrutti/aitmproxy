# CA trust first-run step: execution record

**Status:** in progress (2026-10-31; the spec is §D17 of
`docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md`, approved under
Matt's standing mandate; the tasks are 32–42 of
`docs/superpowers/plans/2026-10-31-system-proxy-automation-plan.md`, approved the same
way; Task 41 additionally needs Matt's explicit go). This file is the CA-trust session's
own record so the system-proxy plan file is never edited by two sessions.

## What ships, in which PR

| PR | Tasks | Files |
|---|---|---|
| A core (PR #219) | 32 (probe), 33, 34, 42 | `crates/aitm-ca/src/{commands,store}.rs`, `crates/aitm-ca/src/platform/macos.rs`, `crates/aitm-ca/tests/{commands,macos}.rs`, `docs/design/operator-ui-foundation.md`, this file |
| B TUI | 35 | `crates/aitm-tui/src/{model,app}.rs`, `crates/aitm-tui/src/ui/bars.rs`, `crates/aitm-tui/tests/ca_pill.rs` |
| C web | 36 | `apps/web/src/state/caTrust.ts` (+ test), `bus/types.ts`, `state/app.ts`, `palette/{groups,setup}.ts`, `palette/CommandPalette.tsx`, `shell/Toolbar.tsx` |
| D mac | 37–41 | `Session+CATrust.swift` (new), `Session.swift`, `Session+Connection.swift`, `Bus/BusService.swift`, `Panels/{CAPanel,StatusPanel}.swift`, `App.swift`, `SettingsView.swift`, `Shell/ShellToolbar.swift`, `Shell/SetupSheet.swift` (new), `AitmproxyKit/CommandMap.swift`, `AitmproxyKit/CATrustFacts.swift` (new, the attribution spec's type, one home), `tools/check-ca-trust-path.sh` |

Deviations from the plan text, each stated where it applies:

- PR 2 (TUI sys-proxy pill) and PR 3 (web pill menu) have not merged, so the CA pill
  word is appended directly after the listening text; when the sys-proxy word lands it
  goes between them (§D12 order). The TUI test file is `tests/ca_pill.rs`, not an
  addition to PR 2's `tests/sysproxy_pill.rs`.
- PR 4 Task 28 (`Shell/SystemProxySheet.swift`) has not merged, so the first-run sheet
  is created here as `Shell/SetupSheet.swift` with the CA row as step 1 and a placeholder
  slot for the system-proxy row; PR 4 fills the slot.
- mac-attribution's traffic-route PR has not merged; `CATrustFacts` lives in
  `AitmproxyKit/CATrustFacts.swift` here with that spec's exact names, and
  `ConnectionSummary.swift` is not edited (orchestrator's claim).

## Task 32 result (read-only probe, Matt's Mac, Terminal panel, 2026-10-31 late)

Script `/tmp/claude/ca-probe/probe.sh` and `probe2.sh`; nothing installed, no keychain or
trust setting modified, no dialog appeared. The login and System keychains hold 0
aitmproxy certificates (`find-certificate -a -c aitmproxy -Z` → 0 `SHA-256` lines each).

| Command | Exit | Output |
|---|---|---|
| `security verify-cert -c apple-root.pem -l -L -p ssl` | 1 | `Cert Verify Result: Invalid Extended Key Usage for policy` |
| `security verify-cert -c apple-root.pem -l -L -p basic` | 0 | `...certificate verification successful.` |
| `security verify-cert -c apple-root.pem -L -p basic` | 0 | `...certificate verification successful.` |
| `security verify-cert -c probe.crt -l -L -p ssl` (untrusted self-signed CA) | 1 | `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED` |
| `security verify-cert -c probe.crt -l -L -p basic` | 1 | `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED` |
| `security trust-settings-export user.plist` | 0 | `...Trust Settings exported successfully.`; `trustList` keyed by SHA-1 upper hex (DigiCert `A8985D3A…5436` matches its `find-certificate -Z` SHA-1); entries carry `trustSettings` arrays with `kSecTrustSettingsPolicyName` (`sslServer`) and `kSecTrustSettingsResult` integers (1, 2, 4 seen) |
| `security dump-trust-settings` | 0 | 3 user-domain certs listed by name |

**Decision:** `verify-cert` is the read-back, with policy **`basic`** (the `ssl` policy
rejects every CA certificate with "Invalid Extended Key Usage for policy", trusted or not,
so it cannot separate the two). Rendered line:
`security verify-cert -c <ca.crt> -l -L -p basic`. Literals: success = exit 0 and stdout
containing `certificate verification successful`; not trusted = non-zero exit (the output
tail, `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED`, goes into `detail`). Caveat recorded in
`detail`: our install sets both the `ssl` and `basic` policies, and Keychain Access's
"Always Trust" sets all, so a `basic` evaluation reflects HTTPS trust for every path the app
offers; a certificate trusted for `ssl` only by hand would read as not trusted.
`trust-settings-export` stays the documented fallback (keys are SHA-1 upper hex, confirmed).

## Task 41 go

_(Matt's words and date go here; until then the live install step has not run.)_

## Task 41 first half: the not-trusted state, live (2026-11-01 ~23:40, Matt's Mac, display lock held)

Dev bundle `/tmp/Aitmproxy-dev-ca.app` (debug app from `claude/ca-trust-mac` e4647ce6, release core
from `claude/ca-trust-first-run-6b7cf3` 02695642), isolated `APP_STORE=/tmp/ca-store`, launched
from the Terminal; nothing installed, no `ca.install`, login and System keychains held 0
aitmproxy certificates before and after, `scutil --proxy` unchanged (HTTP/HTTPS off). Artifacts in
`/tmp/claude/ca-proof/`:

- `1-sheet.png`: the first-run sheet "Set up aitmproxy on this Mac" appeared on its own: step 1
  "Trust the aitmproxy CA" with the amber fact "HTTPS is not captured until the CA is trusted",
  the remedy line, the button, the QUIC caveat; step 2 "Add a host to Scope — Nothing is decrypted
  until a host is in Scope" with Open Scope…; "Not Now".
- `2-status.png`: Status page, Core card "running · Embedded · proxy 127.0.0.1:61763", under it
  the CA fact row (amber dot, the line, the remedy, buttons "Trust the aitmproxy CA" and
  "Certificate Authority…"); Getting started: Core ✓, Bus ✓, "Trust the aitmproxy CA" (button)
  between Bus and All Apps, then Scope and the first-flow step.
- `3-ca-panel.png`: Certificate Authority panel: badge "Not installed", SHA-256, the remedy in
  amber, the QUIC caveat, Install… / Export.
- `shots.txt`: System Events read `{"Trust the aitmproxy CA", enabled: true}` from the Proxy menu.
- `bus-1-before.json` (token never read into any log): `ca.status` → `exists: true`, `platform:
  macos`, `stores.user = {installed: absent, trusted: no, location: …/login.keychain-db}`,
  `stores.system = {installed: absent, trusted: no}`, `detail[0]` = the new DETAIL line;
  `proxy.status.version` 0.5.8. On every installed release this read `trusted: unknown`.

Second half (press Trust → macOS dialog → trusted → Safari HTTPS rows on a non-h3 host →
Uninstall) waits for Matt's explicit yes; it runs only through the app's own step.

## Spec and plan corrections (decided by this session under the standing mandate; for the Architect to fold into §D17)

1. **D17.3 / Task 34 policy.** `verify-cert` runs with `-p basic`, not `-p ssl` (Task 32 result above); the `DETAIL` constant names the basic policy.
2. **Task 33 predicate.** `!frontend.is_trusted_control()` instead of `frontend == Frontend::Mcp` (the latter is forbidden by `crates/aitm-core/tests/trust_gate_scan.rs`); same decision for every `Frontend` variant.
3. **Task 33 files.** `frontend_label` (commands.rs) and the audit vocabulary (audit.rs `FRONTENDS`) gain `"operator"`, which SP-AC29's `frontend == "operator"` requires.
4. **D17.6 pill column.** `· CA needs admin` is a mac-fact-only row: `ca.status` carries no needs-admin reading, so the TUI and web (D17.11, D17.12, which derive the word from `ca.status` + the in-flight flag) render three words plus nothing; the mac app latches `needsAdmin` from the install reply. Their install error toast carries the core's NeedsRoot/HeadlessAuth text.
5. **D17.6 in-flight row.** One in-flight word, `· CA trusting…` / "trusting CA…", for install and uninstall alike (accepted; no fourth form).
6. **Task 35 files.** `crates/aitm-tui/tests/tester_shell.rs` was edited: its connect-contract assertion now pins `[Refresh, Call ca.status]`, which D17.11's connect-time request forces.
7. **D17.2 scope guard (core security Important).** A non-CLI frontend may not ask for `scope: "system"` on a platform that has a user scope (macOS, Windows): refused in `Change::invoke` right after `resolve_scope`, before any executor run, as `TrustErrorKind::UnsupportedScope` with the message `system scope needs a terminal: run \`aitm ca <install|uninstall> --scope system\` yourself; the app and the bus clients use the login keychain` (verb substituted), audited `outcome == "error"` (through `audit.fail`, like the Linux `UnsupportedScope` path), one WARN `refused: the System keychain is reachable from the CLI only`; `dry_run` is not exempt. So the operator token can never make the core spawn `sudo` against the System keychain (D17.1, D17.14). Linux is unchanged (its only scope is system; D17.13). SP-AC29 gains the clause: the same call from `Operator` (and from `Mcp` with the flag on) with `scope: "system"` on macOS or Windows is `Err` of kind `UnsupportedScope` with that message and zero executor runs; from `Cli` it proceeds through `sudo`; Linux `system` from any frontend is unchanged. D17.2 reads: the agent gate refuses only an agent; separately, the System keychain is reachable from the CLI alone where a user scope exists. The command descriptions' "dry_run is always allowed" becomes "dry_run is never gated by `ca.allow_agent_install`".
8. **D17.3 install on a present-but-untrusted certificate.** `install` no longer returns "already present" on presence alone. Present and `verify_trust` says **Yes** → `changed == false`, detail `already present and trusted in <keychain>`. Present and **No** → delete our copy (`-Z <sha256>`, then `-Z <sha1>` as `uninstall` does) and re-add it with trust settings: `changed == true`, details `replaced the untrusted copy in <keychain>` then the usual `added to <keychain> as a trusted root for ssl and basic`; a cancelled re-add is classified and rolled back like a first install; a failed delete is `ToolFailed` `could not remove the untrusted copy from <keychain>: <failure text>` with nothing added (fail-closed, never two copies). Present and `verify_trust` **could not run** → `changed == false`, detail `already present in <keychain>` plus the error text (`Trust::Unknown` never deletes).
9. **D17.3 tail.** A failed `verify-cert` puts the output tail (stdout first, where `Cert Verify Result:` is printed, then stderr) in `detail`, not the stderr tail alone.
10. **SP-AC31 literals.** `-l -L -p basic`; not trusted = `Cert Verify Result: CSSMERR_TP_NOT_TRUSTED`.
11. **Task 32 Result line** in the system-proxy plan points at this record's "Task 32 result".
12. **D17.8 / D17.9 / Task 42 order.** The first-run sheet and the Status checklist use Matt's order: 1 set the system proxy, 2 trust the CA, 3 add a host to Scope (nothing is decrypted until a host is in Scope); the operator docs already say so.
13. **D17.5 / D17.8 / D17.9 homes.** `CATrustFacts` and the two `CAStatus` fields ship in this session's PR D (`AitmproxyKit/CATrustFacts.swift`), not mac-attribution's; the sheet file is `Shell/SetupSheet.swift` (PR 4's `SystemProxySheet.swift` does not exist yet); the three enum cases in `ConnectionSummary.swift` land in PR D before mac-attribution's PR (orchestrator's ruling, 2026-11-01).
14. **Linux `sudo` from a bus client** keeps prompting on the core's own terminal (pre-existing, D17.13); `sudo -n` for non-CLI frontends is a follow-up, not in C1.

15. **D17.4 cancelled prefix.** Frontends accept `ca.(install|uninstall) cancelled`; the core emits only the install form today, and classifying a cancelled `remove-trusted-cert` dialog as `Cancelled` is a core follow-up.

16. **`confirm_prompt` and a doomed system request.** `confirm_prompt` has no frontend, so a hand-rolled bus client sending `scope: "system"` is prompted and then refused by correction 7's guard; accepted as a residual (no frontend sends `"system"`, SP-AC34), a `Command` trait change is the follow-up.
17. **PR A files.** Besides the table above, PR A touches `crates/aitm-ca/src/audit.rs`, `crates/aitm-ca/tests/audit.rs`, `crates/aitm-ca/src/platform/mod.rs` (shared tail rendering) and `crates/aitm-ca/src/testing.rs` (test literals, `unspawnable`).

18. **SP-AC33 `overall` assertions deferred.** `make(caTrust:).overall` composition and the index-2 pin need `ConnectionSummary.make(caTrust:)`, which belongs to mac-attribution's rebase (correction 13); until then `overall` excludes the CA state and the Status view inserts the step after Bus (app target, proven live).
19. **PR D files.** `Shell/ShellView.swift` (the sheet attachment) replaces `Shell/ShellToolbar.swift` in the table; PR 4's toolbar condition ORs into `Session.setupSheetDue`. `AitmproxyKit/Panels/CAStatus.swift` (two fields), `AitmproxyKit/SetupWords.swift` (new), `AitmproxyKit/Panels/Activity.swift` (`_confirm` elision), `UI/ConnectionLook.swift` (dot/remedy parts), `Session+Palette.swift` and `Panels/AgentPanel.swift` (confirm-gated CA verbs kept off the generic paths) join the table. `SetupRow` numbers are 1 and 2 today; PR 4 renumbers to 2 and 3.
20. **`CATrustFacts` surface.** `platform` (chooses the Linux vs macOS needs-admin remedy), `isCancelled`, `signalsNeedsAdmin`, `notGeneratedStep()` are part of the type; the tripwire's extra checks (tree-wide `.string("system")`, `FixtureBus.swift`, fixture files denied the runners) are accepted.
21. **D17.6 `exists == false` row** renders as the step "CA not generated yet — the core creates it on first start" (no action) on the Status page and the sheet; the CA panel keeps its "No certificate" badge.

22. **PR C files.** Besides the table above, PR C touches `apps/web/src/palette/CommandPalette.test.tsx`, `apps/web/src/bus/confirm.ts` (+ `confirm.test.ts`, the one home of the bus `needs_confirmation` envelope guard and the stale-token literal, shared with the L4 panel), `apps/web/src/lib/isRecord.ts`, `apps/web/src/panels/l4/inject.ts`, `apps/web/src/panels/l4/model.ts` (+ `model.test.ts`): the L4 panel now imports the shared guard. The palette performs the bus confirm handshake (spec D4) itself; a `needs_confirmation` reply requires the server's `prompt`.

23. **PR D after M1.** `tools/check-connection-words.sh` joins PR D's table (its readers gain `Shell/SetupSheet`, because the sheet now reads the `.scopeSet` step from `connectionSummary`): the sheet's Scope row is the Getting-started step verbatim (title "Add a host to Scope (for now as example.com:443)" / "Scope has N hosts", done state) plus `SetupWords.scopeCaption` while not done; `1-sheet.png` predates this and is re-shot in Task 41's second half. `CATrustFacts` also carries `operatorOnlyNote` ("not approved from the Agent log — the operator uses Trust the aitmproxy CA"; the Agent log refuses to approve a parked `ca.install`/`ca.uninstall`), `laneTitle`, `readBackFailedLine`, `notOperatorLine`. SP-AC34 rule 3: `.string("user")` lives in `CATrustFacts.scopeArgs`; `Session+CATrust.swift` is pinned to call it and never to spell `"system"`. SP-AC33's assertions live in `CATrustFactsTests` (`trustedInTheUserKeychain`, `notTrustedOffersTheTrustStep`, `everyStoreUnknownIsNoFact`, `actionTitles`, `trustedWinsOverTheNeedsAdminLatch`, `stepFollowsStateAndActions`) until attribution's `make(caTrust:)` brings `caTrustActionsAndStepButton`.

24. **PR D after M2.** New Kit type `CATrustFailure { command, message, line, resolved(by:) }`: the last trust failure is keyed to its verb, so a trusted read-back clears an install failure and a not-trusted read-back clears an uninstall failure, and nothing else does; `Session.caTrustLastError` is that type. `Tests/AitmproxyKitTests/SetupWordsTests.swift` holds the sheet-words pin. `Session.forgetCATrust()` resets the read-back, the latch and the failure when the bus connection ends; `LaneDot(state:word:title:)` and `RemedyText` are the two parts every CA surface uses. `refreshCAStatus` logs a failed or undecodable `ca.status` read at debug (`os.Logger`, subsystem `com.mrbrutti.aitmproxy`, category `ca-trust`; the error text only, never the token or the reply) so a "could not be read" report has a cause. `CATrustFacts.storesUnknownLine` names a read-back that landed with every store `unknown`.

## Review log

| Date | PR | Reviewer | Finding | Severity | Disposition |
|---|---|---|---|---|---|
| 2026-11-01 | D mac | M3 note (c6c5283d) | `CATrustFailure.Verb` + `resolved(by:)` is the one clearing rule (the Kit spells no verb literal; the string→Verb map lives in `Session+CATrust.swift`); `changeCATrust` still clears on success and on a cancelled dialog before the forced re-read (not store-driven; accepted) | — | Swift gate: build clean, 545 Kit tests passed |
| 2026-11-01 | C web | W5 note (e49fa835) | stale-not-awaited → error notice; `isMalformedConfirm` + `MALFORMED_CONFIRM_MESSAGE` in `bus/confirm.ts`, palette treats a malformed envelope as `failed`; `beginInject`/`confirmInject` keep their own "unexpected result" refusal | — | web gate on the final head: gen 0, vitest 567/567, tsc 0, build 0 |
| 2026-11-01 | B TUI | gate | merged head bd0bda79: fmt 0, clippy 0, `cargo test -p aitm-tui --no-fail-fast` exit 0 (15 binaries) | — | ready to open on the orchestrator's SHA |
| 2026-11-01 | D mac | security (M2 re) | a trust change in flight across a core restart re-writes its failure after `forgetCATrust()` | Minor | accepted: the text is honest ("the bus connection closed"); a connection generation check is a follow-up |
| 2026-11-01 | D mac | quality (M2 re) | failure-clearing rule split across two callers, untested; `notOperatorLine`/`readBackFailedLine` emitted for causes they do not name | Minor | fix task M3: `CATrustFailure.resolved(by:)` + tests; connected guard; `storesUnknownLine` |
| 2026-11-01 | D mac | spec (M2 re) | unrequested debug logging; `CATrustFailure`/`SetupWordsTests.swift` unrecorded | Minor | correction 24 |
| 2026-11-01 | C web | quality (W4 re) | not-awaited `stale` silent; `isMalformedConfirm` lives in the L4 panel | Minor | fix task W5 |
| 2026-11-01 | C web | security (W4 re) | none | — | PASS |
| 2026-11-01 | C web | spec (W4 re) | not-awaited `failed` → error notice is new behaviour | Minor | accepted: a failure of a run the operator left is never silently lost |
| 2026-11-01 | D mac | security (M1 re) | self-check has no rule-3 plant; rule 2 misses a bare member reference; CA panel buttons not gated on the operator role | Minor | fix task M2 |
| 2026-11-01 | D mac | quality (M1 re) | VoiceOver label twice; trusted read-back clears an uninstall error; stale-fact sentence outside the Kit; "E:" test comment; three fields reset from BusService + redundant latch mask | Minor | fix task M2 |
| 2026-11-01 | D mac | spec (M1 re) | `check-connection-words.sh` undeclared; sheet Scope row words changed; `operatorOnlyNote` unrecorded; rule-3 home; SP-AC33 test names | Important (disposition) / Minor | correction 23 |
| 2026-11-01 | C web | quality (W3 re) | result arms write over a left stage; `heldBus` not used everywhere | Minor | fix task W4 |
| 2026-11-01 | C web | security (W3 re) | superseded CA run's late ending releases a newer run's flag; malformed envelope reads as done in the L4 panel | Minor | fix task W4 |
| 2026-11-01 | C web | spec (W3 re) | `CommandPalette.test.tsx` missing from correction 22; superseded `done` CA path untested | Minor | correction 22 amended; fix task W4 |
| 2026-11-01 | C web | quality (W2 re) | `prompt` optional with three invented fallbacks; l4 re-export only for a test; "left meanwhile" arm untested | Minor | fix task W3 |
| 2026-11-01 | C web | security (W2 re) | late `needs_confirmation` for run A attaches to a newer run B | Minor | fix task W3: `runSeq` |
| 2026-11-01 | C web | spec (W2 re) | l4 invented prompts; PR C files unrecorded; Esc exit untested | Minor | fix task W3; correction 22 |
| 2026-11-01 | A core | gate | merged head 0bfe98e1: fmt 0, clippy 0, 235 test binaries ok, 4 failing binaries = known wall-clock tests (web_bus_write_deadline ×2, rhai engine budget, tui browser_screenshot, tui five_thousand_flows), three reproduced on untouched main | — | PR #219 opened with the panel comment |
| 2026-11-01 | A core | C2 note | `Op::delete_copy` returns `Result<Option<String>, TrustError>` (None = gone; Some = both attempts' failure texts), not the `(CmdLine, CmdOutput)` the task sketched, so the replace-path error keeps the SHA-256 attempt's real reason | — | accepted; the `dry_run` param text reads "Never gated by `ca.allow_agent_install`." |
| 2026-11-01 | D mac | security + quality | needs-admin latch overrides the read-back; step done while state warning | Important | fix task M1 (A) |
| 2026-11-01 | D mac | security | `changeCATrust` trusts its callers; Status row buttons not gated | Minor | fix task M1 (B) |
| 2026-11-01 | D mac | security + spec | tripwire: dotted-only rule 2, absent rule-4 file skipped, harness files not denied, self-check proves one rule | Minor / Important (spec) | fix task M1 (J) |
| 2026-11-01 | D mac | security | palette/approve can issue `ca.install` by name (pre-existing; no handshake, never completes) | Minor | fix task M1 (M) |
| 2026-11-01 | D mac | security | consumed `_confirm` token lands in the activity log | Minor | fix task M1 (N) |
| 2026-11-01 | D mac | quality | `refreshCAStatus` swallows a failed post-change read-back | Minor | fix task M1 (C) |
| 2026-11-01 | D mac | quality | prefix matching inconsistent; audit-context prefix breaks it | Minor | fix task M1 (D) |
| 2026-11-01 | D mac | quality | sheet's Scope sentence has no Kit home | Minor | fix task M1 (E) |
| 2026-11-01 | D mac | quality | three hand-rolled dot/remedy renderings | Minor | fix task M1 (F) |
| 2026-11-01 | D mac | quality | sheet row repeats the same sentence three times | Minor | fix task M1 (G) |
| 2026-11-01 | D mac | quality | sticky `caTrustLastError` hides export errors; CA panel says "No certificate" when the bus is down | Minor | fix task M1 (H) |
| 2026-11-01 | D mac | quality | `onChange(of: setupSheetDue)` without `initial:` | Minor | fix task M1 (I) |
| 2026-11-01 | D mac | quality | tripwire helpers copied from the capture script | Minor | accepted (two scripts, two invariants; a shared lib is a follow-up) |
| 2026-11-01 | D mac | quality | test name vs fixture; `caDone` recomputed; `step.action`; `allStepsDone` unused | Minor | fix task M1 (L); `allStepsDone` stays for attribution's `make(caTrust:)` |
| 2026-11-01 | D mac | spec | SP-AC33 `overall` assertions and index-2 pin absent | Important (disposition) | correction 18 |
| 2026-11-01 | D mac | spec | `ShellView.swift` undeclared, `ShellToolbar.swift` untouched | Important (disposition) | correction 19 |
| 2026-11-01 | D mac | spec | D17.6 `exists == false` row not rendered | Important | fix task M1 (K), correction 21 |
| 2026-11-01 | D mac | spec | `CATrustFacts` surface beyond the record; extra tripwire checks | Minor | correction 20 |
| 2026-11-01 | D mac | spec | `isCancelled` install-only | Minor | fix task M1 (D), correction 15 |
| 2026-11-01 | A core | security (re) | delete arm in `install` matches `Trust::Unknown` too | Minor | fix task C2: key on `Trust::No` |
| 2026-11-01 | A core | security (re) + quality (re) | re-trust delete has no SHA-1 fallback; third copy of the delete line | Minor | fix task C2: `Op::delete_copy` |
| 2026-11-01 | A core | security (re) + spec (re) | `confirm_prompt` still prompts a doomed non-CLI system request | Minor | correction 16: accepted residual |
| 2026-11-01 | A core | quality (re) | scope/frontend policy inline in `invoke` | Minor | fix task C2: into `resolve_scope(platform, wanted, frontend)` |
| 2026-11-01 | A core | quality (re) | "fix task C1 (finding N)" test comments; `VERIFY_USER` misnomer | Minor | fix task C2 |
| 2026-11-01 | A core | quality (re) | double-negative WARN assertion | Minor | fix task C2 |
| 2026-11-01 | A core | spec (re) | correction 7 literals / SP-AC29 clause missing from the record | Important (record) | correction 7 extended (this commit) |
| 2026-11-01 | A core | spec (re) | correction 8 outcomes/strings unrecorded | Minor | correction 8 extended (this commit) |
| 2026-11-01 | A core | spec (re) | Review log row named `sudo -n` as part of C1 | Minor | row amended |
| 2026-11-01 | A core | spec (re) | three files outside PR A's list | Minor | correction 17 |
| 2026-11-01 | B TUI | quality (re) | connect-clears-flag asserted twice | Minor | accepted (one assertion in a neighbouring test) |
| 2026-11-01 | B TUI | security (re) | pre-existing `tester_pass2` temp-file race (out of range) | Minor | follow-up for the TUI owner; not this PR |
| 2026-11-01 | C web | security (re) + quality (re) | CA flag sticks if the palette is disposed during phase 1 | Minor | fix task W2: `disposed` flag |
| 2026-11-01 | C web | security (re) | handshake guard applies to every tool's reply | Minor | accepted (core-authored root shape; harmless extra call at worst) |
| 2026-11-01 | C web | quality (re) | second envelope parser vs l4; `run` phase sentinel; stale-token + onInput tests missing | Minor | fix task W2 |
| 2026-11-01 | C web | spec (re) | both-verb cancelled prefix beyond D17.4 text | Minor | correction 15 |
| 2026-11-01 | A core | quality | Cancelled branch drops stderr (same as security Minor) | Minor | fix task C1 |
| 2026-11-01 | A core | quality | `verify_failure_text` duplicates `failure_text`/`stderr_tail` | Minor | fix task C1: shared tail helpers |
| 2026-11-01 | A core | quality | two-pass kind/message with wildcard arm | Minor | fix task C1 |
| 2026-11-01 | A core | quality | kind word lives in commands.rs not on the type | Minor | fix task C1: `TrustErrorKind::label` |
| 2026-11-01 | A core | quality | test literals/helpers duplicated, `MACOS_DETAIL` means two things | Minor | fix task C1: `testing.rs` literals + `unspawnable` builder |
| 2026-11-01 | A core | quality | priming call and vacuous assertion in two tests | Minor | fix task C1 |
| 2026-11-01 | A core | quality | comments cite "Task 32" | Minor | fix task C1 |
| 2026-11-01 | A core | spec | audit.rs + tests/audit.rs undeclared in Task 33; record not committed at head | Important (disposition) | correction 3 committed in this record |
| 2026-11-01 | A core | spec | D17.3/SP-AC31/Task 34 say `-p ssl` and stderr tail | Important (spec text) | corrections 1, 9, 10, 11 |
| 2026-11-01 | A core | spec | Task 33 predicate text | Minor | correction 2 |
| 2026-11-01 | A core | spec | docs order/step differs from D17.8 and Task 42 | Minor | correction 12 (Matt's order) |
| 2026-11-01 | A core | spec | PR D design section contradicts D17.5/D17.8/D17.9 | Minor | correction 13 |
| 2026-11-01 | B TUI | quality | `ca_installing` never cleared on Connected/Disconnected: pill can read `· CA trusting…` forever after a bus drop mid-dialog | Important | fix task T1: clear on both arms + assertion |
| 2026-11-01 | B TUI | quality | `CONFIRM_TOOLS` used to mean "CA trust tool" | Minor | fix task T1: `CA_TRUST_TOOLS` |
| 2026-11-01 | B TUI | quality | `ca.status` ask copied four times | Minor | fix task T1: `ask_ca_status` helper |
| 2026-11-01 | B TUI | quality | seven-scenario test with a two-scenario name; `ca_status == None` branch untested | Minor | fix task T1 |
| 2026-11-01 | B TUI | spec | `tests/tester_shell.rs` edited outside the file list | Important (disposition) | recorded as correction 6; no code change |
| 2026-11-01 | B TUI | spec | `· CA needs admin` has no source in the TUI/web (D17.6 vs D17.11) | Important (spec) | correction 4: mac-fact-only row |
| 2026-11-01 | B TUI | spec | `· CA trusting…` also for uninstall | Minor | correction 5: accepted |
| 2026-11-01 | B TUI | spec | `ca.uninstall cancelled` not special-cased | Minor | consistent with the core; none |
| 2026-11-01 | A core | security | Operator-token client may request `scope: "system"` → core spawns `sudo` | Important | fix task C1: correction 7 guard + test; `sudo -n` deferred per correction 14 |
| 2026-11-01 | A core | security | Cancelled path drops the tool's stderr from log and audit | Minor | fix task C1: warn the tail on the Cancelled branch |
| 2026-11-01 | A core | security | Present-but-untrusted certificate is a dead end for the Trust step | Minor | fix task C1: correction 8 |
| 2026-11-01 | C web | security | The palette never performs the bus confirm handshake (`needs_confirmation` envelope shown as `ok`), so `ca.install` from the web could never run | Minor (security) / Important (function) | fix task W1: generic handshake in `run`, server prompt, `_confirm` re-call, tests |
| 2026-11-01 | C web | security | `isCACancelled` keys on `ca.install cancelled` only; the core's uninstall path never emits `Cancelled` | Minor | fix task W1: match both verbs; core uninstall cancel classification is a follow-up |
| 2026-11-01 | C web | spec | No `· CA needs admin` pill word (D17.6 row 4); `ca.status` carries no needs-admin reading, D17.12 and SP-AC36 do not ask for it | Minor | accepted: spec gap D17.6 vs D17.11/D17.12; Architect addendum if Matt wants the word on TUI/web (the mac app latches it from the install error) |
| 2026-11-01 | C web | spec | No `ca.uninstall` palette test for the in-flight flag and re-read | Minor | fix task W1 |
| 2026-11-01 | C web | spec | `caPillWord(unknown, false) === null` covered only by composition | Minor | fix task W1 |
| 2026-11-01 | C web | quality | Hedged selector and `?.value ?? ''` let the Linux no-scope test pass vacuously | Minor | fix task W1 |
| 2026-11-01 | C web | quality | `refreshCA` swallows a failed post-install read-back; pill may stay stale silently | Minor | fix task W1: returns Bool, palette notices |
| 2026-11-01 | C web | quality | Fourth copy of the plain-object guard | Minor | fix task W1: shared `isRecord` in lib |
| 2026-11-01 | C web | quality | CA-tool knowledge split across three modules | Minor | fix task W1: `isCATrustTool` in caTrust.ts |

## Shipped

_(filled by the orchestrator at merge)_

## PR D design as built (Tasks 37–40 adapted to the claims and the merged tree)

Order of the first-run steps (Matt, 2026-10-31, per-host decryption): 1 set the system proxy,
2 trust the CA, 3 add a host to Scope. PR 4 (system proxy, mac) has not merged, so this PR
ships rows 2 and 3 in that order and PR 4 inserts row 1 above them.

**Kit, `AitmproxyKit/CATrustFacts.swift` (new; the attribution spec's type, one home).**

```swift
public struct CATrustFacts: Hashable, Sendable {
    public var trusted: Bool
    public var scope: String?          // "user" | "system" | nil
    public var fingerprint: String?
    public var installing: Bool = false
    public var needsAdmin: Bool = false // Linux NeedsRoot / macOS HeadlessAuth came back from the last change
    public init?(status: CAStatus)     // nil unless status.trustReported (some store said yes|no)
    public var text: String            // D17.6: "CA trusted (user keychain)" | "CA trusted (System keychain)" |
                                       //        "HTTPS is not captured until the CA is trusted" | "trusting CA…" |
                                       //        "CA trust needs an administrator"
    public var state: LaneState        // ok | warning | working | warning
    public var remedy: String?         // D17.6 remedies; nil when trusted/installing
    public var actions: [ConnectionAction]  // [.openCAPanel] | [.trustCA, .openCAPanel] | [] | [.openCAPanel]
    public var step: GettingStartedStep     // kind .caTrusted; done == trusted && !installing
    public static let quicCaveat = "HTTPS apps that use QUIC are not captured until the CA is trusted; browsers fall back to TCP once it is."
    public static let notTrustedLine = "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"
    public static func unknownStep() -> GettingStartedStep  // "CA trust unknown — open the Certificate Authority panel", .openCAPanel
    public static func scopeArgs(platform: String) -> [String: JSONValue]  // ["scope": .string("user")] for macos|windows, [:] otherwise
}
```

`CAStatus` (`AitmproxyKit/Panels/CAStatus.swift`) gains `trustedScope: String?` (the first
store whose `trusted == "yes"`, user before system) and `trustReported: Bool` (any store says
`yes` or `no`). `ConnectionAction` gains `.trustCA` / `.openCAPanel` and `GettingStartedStep.Kind`
gains `.caTrusted` (the orchestrator granted this additive exception on
`ConnectionSummary.swift` on 2026-11-01: exactly the three cases and the two title lines,
nothing else; mac-attribution rebases onto it). `ConnectionSummary.make` is not touched; the
Status view inserts the CA step after `.busConnected` itself. PR D order: removal-mac PR →
this PR → mac-attribution → system-proxy PR 4.

**App.** `Session.caStatus: CAStatus?`, `Session.caTrustInstalling`, `Session.caTrust:
CATrustFacts?` (facts with `installing`/`needsAdmin` applied). `Session+CATrust.swift` is the
only home of `"ca.install"`/`"ca.uninstall"`: `trustCA()`, `untrustCA()`, `caTrustControlLive`
(bus connected, `resolvedRole == "operator"`, not installing); the confirm re-call re-sends the
identical args plus `_confirm` (spec D4 of the bus); an error starting `ca.install cancelled` is
silent; `HeadlessAuth`/`NeedsRoot` text sets `needsAdmin`; every path ends in
`refreshCAStatus()`. `BusService.pollLoop` reads `ca.status` on the first tick and every 10th
tick (500 ms × 10) directly on the client (no activity-log entry), assigning `session.caStatus`
only when changed. `CAPanel` reads `session.caStatus`, calls `trustCA()`/`untrustCA()` after
its `NSAlert`, shows the facts' remedy only when the re-read says not trusted, and the QUIC
caveat as a footnote. `StatusPanel`: CA fact row under the Core card (text, state dot, remedy,
actions) and the `.caTrusted` step row after Bus; `run(.trustCA)` → `Task { await
session.trustCA() }`; `.openCAPanel` → `perform` → `show(.ca)`. `Shell/SetupSheet.swift` (new):
title "Set up aitmproxy on this Mac", rows "Trust the aitmproxy CA" (fact text, primary button
hidden when trusted, "trusting CA…" while in flight, the QUIC caveat under it) and "Add a host
to Scope" ("nothing is decrypted until a host is in Scope", button Open Scope…); no `NSAlert`
before `trustCA()`; buttons "Not Now" / "Done" (when both rows are done); shown once per store
(`Store.defaults` keys `systemProxy.sheetShown`, `systemProxy.promptSuppressed`, shared with
PR 4) when the embedded core is `.ready`, the bus is connected as operator and the CA facts are
non-nil and not trusted. Proxy menu: "Trust the aitmproxy CA" ⌃⌘T above "Certificate
Authority…", disabled unless `caTrustControlLive` and not trusted; `CommandMap` entry and the
`docs/BRIEF.md` command-map line (the Kit test pins them to each other). Settings ▸ Proxy:
the QUIC caveat as a footnote. Tripwire `tools/check-ca-trust-path.sh` per Task 40.
