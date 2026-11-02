# Scanner v2 macOS Scan surface (T9) design

**Status:** approved (2026-10-31, self-approved under Matt's autonomous mode; child of the approved umbrella spec)
**Parent spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (D3, D5, D6, D10, D12; ACs UI-1..UI-5)
**Research inputs:** `docs/research/20-scanner-v2-current-state.md` §3.8 and §3.10 (mac: `running` bool, `http://` seed, never subscribes), `docs/research/17-burp-style-scanner-architecture.md` (the four-surface model)
**UX pass:** this document is the `ux-design` pass for stories S-085..S-089 in `apps/mac/docs/STORIES.md`; new terms are in `apps/mac/docs/GLOSSARY.md`

## Intent

The macOS app's Scan page today is a one-shot `scan.discover` form: it crawls one URL, blocks until the crawl ends, and lists endpoints and injection points. Scanner v2 replaces that with the four-surface Scan model every operator UI shares (D10): **Profiles** (what to scan and how), **Jobs** (what is running, with live counters and Cancel), **Site map** (what the crawl found, down to insertion points) and **Issues** (what the checks found, grouped by severity, with evidence, probe flows, PoC and status). The mac app also starts listening to the bus (`flow.subscribe`) so a running job's counters and new issues arrive without a manual refresh, with `scan.status` polled for truth. The legacy one-shot form stays reachable until `scan.discover` is removed from the core.

## Goals

- From the Profiles editor, start a `standard` job against an in-scope target and watch the Jobs row's probes counter rise and the phase word change, cancel it and see `cancelled`; every number the row shows is a `scan.status` value (UI-1).
- Issues appear grouped by severity while the job runs; the detail shows evidence and opens a probe flow in the inspector and the PoC in the Findings page; marking one `false_positive` round-trips through `scan.issue.update` (UI-2).
- A profile with an L4 lane shows the engine's "may disrupt the target" prompt and performs the `_confirm` handshake; without an L4 scope entry the launch is disabled with the reason (UI-3).
- The app calls `flow.subscribe` on every live connection and treats `notifications/aitm/job` as a refresh trigger (UI-4; blocked on the `Session.swift` / `BusService.swift` claims).
- The Site map renders nodes and insertion points from a real `scan.sitemap` (UI-5).
- Every verb result the engine can return parses in `swift test` against the fixture pack `crates/aitm-scan-model/fixtures/` (inner loop only; never evidence).

## Non-goals

- No scanning logic in the app: the engine decides what to probe, dedupes issues, builds PoCs. The app renders and sends verbs.
- No reconstruction of job state from push lines. Push is a trigger; `scan.status` / `scan.issues` / `scan.list` are truth (D3).
- No new check authoring, no profile YAML editor: profiles are edited as a form and saved through `scan.profile.save`.
- No changes to the Findings page beyond opening it on a given finding from an issue.
- No fixture or snapshot evidence of anything (Matt's rule). Fixtures exist for development and `swift test` parsing only.

## Anti-goals

- A counter that moves without a `scan.status` read behind it (a client-side animation, an increment from push lines).
- A launch that reaches the bus for an out-of-scope origin, or for an L4 lane without the operator having seen the prompt text.
- Any secret value on screen: session preview shows cookie and header **names** only; insertion-point examples arrive redacted and are shown verbatim.
- A page that goes blank when the core lacks the scanner: it degrades to the legacy form (scan.discover only) or to "Scan is unavailable" (neither verb).
- Hue anywhere but data: severity pills and the stacked bar use `Tok.Severity.*`; every other element is ink on ground.

## Constraints

- **Claims (D12), as ruled by the orchestrator on 2026-10-31.** Granted: `apps/mac/Sources/AitmproxyKit/Panels/Scan*.swift`, `apps/mac/Sources/Aitmproxy/Panels/ScanPanel*.swift`, their tests, and `apps/mac/docs/STORIES.md` + `GLOSSARY.md` (append-only). Denied: `Fixtures+Tools.swift`, `SnapshotScenes.swift`, `Bus/FixtureBus.swift` (deleted by the fake-data removal PR; no scene ids, no fixture answers). Waiting behind other PRs, delivered as a follow-on additive PR: `Session.swift`, `Bus/BusService.swift` (subscribe wiring, UI-4), `CommandMap.swift`, the Proxy menu in `App.swift`, `docs/BRIEF.md`. `Shell/ShellView.swift`, `Shell/SidebarView.swift` and `Session+Palette.swift` are not edited: the shell already renders `ScanPanel(state: session.scan)` and the sidebar reads `session.scan.points.count`. The surface itself builds and runs without the waiting files because the Scan page polls while visible (D8).
- **Wire shapes** are exactly `aitm-scan-model`'s (`crates/aitm-scan-model/src/*.rs`); the fixture pack is the parsing contract. Unknown enum values decode to a `.other(String)` case and render as their raw text, so a newer core never breaks the surface.
- **SwiftPM only in the Terminal.** `swift test`, `tools/snap-dev.sh`, `tools/verify.sh` run there; sub-agents write code the orchestrating session builds.
- **Design.** Flat monochrome SF Symbols, no glass capsules, editorial typography-forward restraint, hue only on data, 4 pt grid (`tools/grid-lint.sh`), existing kit parts (`PageHeader`, `PaneTabs`, `Badge`, `FlatButton`, `PrimaryButton`, `FlatMenu`, `FlatToggle`, `Hint`, `Rule`, `VRule`), `Tokens.swift` never hand-edited.
- **Engine availability.** The surface is offered when the bus lists `scan.start`; the legacy form when it lists only `scan.discover`. Both are feature-detected from `tools/list`, never assumed.

## Design

### D1. Names (glossary)

| Term | Means | Not |
|---|---|---|
| Scan | The Testing page that holds Profiles, Jobs, Site map and Issues | scanner (the engine, in UI text), audit |
| Profile | A saved recipe for a scan: target origins, lanes, intensity, speed, accuracy, checks, budgets, session mode | config, preset, template |
| Lane | One protocol family a scan can run: HTTP, WebSocket, L4 packet, L4 stream | module, engine, plugin |
| Intensity | How far a profile's checks go: Passive, Light, Medium, Intrusive | level, aggressiveness |
| Start Scan | Launch a job from the selected profile (⌘⏎ on the Profiles tab) | run, launch, execute |
| Map Only | Launch a crawl-and-passive job with no probes (`scan.map`) | discover, spider |
| Job | One running or finished scan: its state, phase, counters and issues | run, task, session |
| Phase | Where a job is: Queued, Crawling, Passive, Auditing, Reporting, Done | stage, step |
| Probe | One request the scan sent to test a point; counted against the budget | payload, attack, hit |
| Budget | The probe and time ceilings a job runs under | limit, quota |
| Cancel Scan | Stop a running job; its issues stay (⌥⌘.) | abort, kill, stop |
| Site map | The tree of endpoints a job reached, by host and path | tree, crawl results, endpoints |
| Insertion point | One place in a request a probe can go: query, body param, JSON value, header, cookie, path segment, WebSocket field, L4 field | injection point (legacy form only), parameter |
| Issue | One thing a check found on one point, with its evidence | finding (that is a PoC run), vuln, alert |
| Severity | Critical, High, Medium, Low or Info | risk, priority |
| Confidence | Certain, Firm or Tentative | certainty, score |
| Evidence | What the check saw: payload, what matched, timing, diff, probe flows | proof, details |
| Probe flow | A flow the engine recorded for an issue; opens in the inspector | request, capture |
| Status (issue) | Open, Confirmed or False positive; set by the operator | state, triage, verdict |
| Session mode | Observed (reuse cookies and auth headers seen through the proxy, names only shown) or None | auth, login |

The legacy form keeps its words (Target, Scan, Endpoints, Injection points) because it is the shipped `scan.discover` surface and goes away with the verb.

### D2. Where it opens

**Surface: sidebar page** (a place the operator comes back to) with **four tabs** on one `PaneTabs` strip under the page header: Profiles · Jobs · Site map · Issues. Tabs are state inside the page (not sidebar sub-items) because the operator moves between them around one job. Jobs and Issues carry a count in the tab title when non-zero ("Jobs 2", "Issues 7"), the sidebar Scan row's count is the number of running jobs (queue style) when any, else the open-issue count.

| Piece | Surface | Table row that picked it |
|---|---|---|
| Profiles editor | inline form on the right of the profiles list | changes values on something already on screen |
| Start Scan confirm (L4 / intrusive) | sheet with the engine's prompt text | one short task that must finish or cancel before going on |
| Delete Profile | confirmation dialog | destroys data and cannot be undone |
| Job detail | inline right pane of the Jobs tab | details of the selection while people keep working |
| Issue detail | inline right pane of the Issues tab | details of the selection while people keep working |
| Probe flow | the flow inspector (Apps page, flow selected) | existing surface for a flow |
| PoC | the Findings page with that finding selected | existing surface for a PoC |
| Session preview names | inline, read-only, under the Session mode control | information that needs no action |
| Launch refused (scope, L4 scope, engine, busy) | inline text under the launch buttons, never an alert | error inline next to the problem |

One modal at a time: the confirm sheet never stacks on the delete dialog.

### D3. Flows (one line each)

- **Start a scan.** Proxy ▸ Scan (⌥⌘S) or sidebar Scan → Profiles tab → pick `standard` (or any) → origins seeded from scope (first concrete host) → Start Scan (⌘⏎) → [L4 or Intrusive: sheet shows the engine's prompt → Start Scan / Cancel (⎋)] → Jobs tab opens with the new job selected, phase "Queued" → counters rise → Done. Way back: ⎋ cancels the sheet; Cancel Scan (⌥⌘.) stops the job.
- **Map only.** Same, Map Only button → `scan.map` → Jobs tab.
- **Cancel.** Jobs tab, running row → Cancel (row hover button, context menu, detail header, ⌥⌘.) → state "Cancelling" → "Cancelled"; issues stay. No confirmation (reversible in spirit: start again).
- **Triage.** Issues tab → list grouped by severity → click → detail → Open Flow on a probe flow (inspector) / Open PoC (Findings) → Status: Open | Confirmed | False positive → `scan.issue.update` → pill updates in list. Way back: set Status back to Open.
- **Browse the site map.** Site map tab → Job menu (newest job default) → host → node → right pane: insertion points for the node, flows → Open Flow. Load More when the result has `next_cursor`.
- **Edit a profile.** Profiles tab → pick a custom profile (or Duplicate… a builtin) → change fields → Save Profile (⌘S on the tab; title "Save Profile") → `scan.profile.save` → list updates. Delete Profile… → dialog "Delete Profile “my-api”?" Delete / Cancel.
- **Legacy.** A core that lists `scan.discover` and not `scan.start` opens the existing one-shot form unchanged.

### D4. Profiles tab

Left (320 pt): the profile list from `scan.profile.list`, builtins first then custom (alphabetical), each row: name (ui md medium), a `BUILTIN` grey badge when builtin, second line `lanes · intensity · speed` in data sm secondary. Right: the editor, a `ScrollView` of sections:

- **Target.** "Origins" — the profile's `target.origins` as removable rows (data md) plus a `FlatMenu` "Add in-scope host" listing `ScanForm.concreteHosts(scopeHosts)` → appends `http://host` (the scheme menu beside it offers https). A typed origin whose authority is not in scope shows "Out of scope — add host to scope to scan it" under it and disables Start Scan; the inline button "Add Host to Scope…" opens the scope sheet (existing path). Empty origins: "Choose at least one in-scope origin." L4 targets (`target.l4`) are shown read-only as `ip:port/proto` rows when present (editing L4 targets is left to the TUI/config; builder may add later).
- **Lanes.** Four `FlatToggle`s: HTTP, WebSocket, L4 packet, L4 stream. An L4 lane on with no L4 scope entry carrying Inject (feature-detected via `l4.scope.list` when the bus lists it; when the verb is absent the lane is treated as unavailable) renders the launch disabled with the parent spec's hint: "The L4 lanes need an L4 scope entry with interface *, direction outbound, the target CIDR and port range and the Inject capability."
- **Intensity / Speed / Accuracy.** Three segmented controls (system `Picker(.segmented)` is allowed; system control, no custom chrome): Passive Light Medium Intrusive · Fast Normal Thorough · Fewer false negatives / Normal / Fewer false positives. Intrusive shows a Hint: "Intrusive checks may disrupt the target; the engine asks before starting."
- **Checks.** A disclosure tree from `scan.checks` grouped by lane then class; each leaf row: name, class, intensity badge, cost, origin (native / bundled / custom) in tertiary, and a tri-state control "Default · Include · Exclude" (a `FlatMenu` per row; the group header offers Include all / Exclude all / Reset). The profile's `checks.include` / `checks.exclude` are the only state; "Default" means in neither list. A search field above filters by id/name/class. Checks above the chosen intensity render tertiary with the help "Above this profile's intensity; raise Intensity to run it."
- **Budget.** Probes, Time (s), Max issues, Check timeout (s) as numeric fields; the engine's ceilings are unknown to the app, so a clamp is reported after launch from the `clamped` list ("Clamped budget.probes 50000 → 20000") in the Jobs detail.
- **Session.** Segmented Observed / None; under Observed a read-only preview from `scan.session.preview {target: first origin}`: "Cookies: sid · Headers: authorization · from flow <method path> · observed <relative time>" or "No session seen yet for this origin." and the canary line ("Canary: GET /account" / "Auth-lost detection off: no GET/HEAD flow seen"). On lost: Stop / Continue segmented.
- **Footer (sticky).** `PrimaryButton("Start Scan", hint: "⌘⏎")`, `FlatButton("Map Only")`, `FlatButton("Save Profile")` (disabled for builtins; "Duplicate…" instead, which asks for a name in a popover), `FlatButton("Delete Profile…")` (custom only). One status line under them: the refusal reason (scope, L4 scope, engine missing, "A scan on this origin is already running (busy)"), or the last launch error (`scan: <code>: <message>` rendered as the message with the code in tertiary), or idle: "Opening this page never scans. Start Scan sends probes to the origins above."

A builtin's fields are editable in place to launch with `overrides` (the edits are not saved); the status line says "Edited builtin — Start Scan uses these values; Duplicate… to keep them." `scan.start` is always sent as `{ profile: <the profile the gate checked> }`, never `{ profile_name }`, so the origins the operator saw are the origins the engine scans (a `profile_name` launch would let another bus client's save change the target between the gate and the start).

### D5. Jobs tab

Left: job rows from `scan.list` (newest first; a job the app started is inserted at once from the `scan.start` result), 2-line rows:

- Line 1: state word (Queued / Running / Cancelling / Done / Cancelled / Failed; Running shows the phase word instead: "Crawling", "Auditing"…), profile name, target host(s) (middle-truncated).
- Line 2: `probes 418 / 2000 · points 80 / 120 audited · 0:42` in data sm, then the **severity bar**: a 6 pt-high stacked bar of `issues.by_severity` in `Tok.Severity.*` fg colours, width proportional, with the total as a number at its end; an empty bar is a 1 pt rule. Accessibility label reads the counts in words.
- Running rows show a hover **Cancel** `FlatButton`; every row has a context menu: Cancel Scan (running only), Show Issues, Show Site Map, Copy Job ID.

Right: the selected job's detail from `scan.status` (polled every 1 s while the job is not terminal and the page is visible; on notification at once, coalesced to 4/s):

- Header (`inspectorHeader`): state word · phase · elapsed (`m:ss`), `PrimaryButton("Cancel Scan")` while running, `FlatButton("Show Issues")`, `FlatButton("Show Site Map")`.
- Sections (tracked xs caps titles): **Probes** sent / budget (a thin progress rule, ink on raised, no hue), errors, timeouts, rate waits, by lane; **Crawl** pages, queued, depth, forms; **Points** found, queued, audited, skipped (ignored / frequent / limit); **Checks** scheduled / done, running ids (data sm, up to 8); **Issues** by severity (the stacked bar, large) and by confidence; **Lanes** requested / run / skipped with reasons; **Clamped** rows; **Session** reused / lost / canary / browser partial; **L4** when present; **Stopped** `stopped_reason` and `error` verbatim in `Tok.Status.serverError` ink when failed.
- Empty: "No jobs yet — pick a profile and Start Scan." with a `FlatButton("Open Profiles")`.

### D6. Site map tab

Top bar: `FlatMenu` Job (newest first; "All jobs" sends no `job` filter), a search field matching host/path. Left: the node tree from `scan.sitemap`, grouped by `scheme://host:port` (disclosure row, tertiary count), then node rows: method `Badge`, `path_template` (data md), trailing `points` count and a `checkmark` glyph when `audited`, a `lock` glyph when `auth`. Right: the selected node: its URL line, **Insertion points** for it (`points` filtered by `site_node`): kind badge (grey), name, `path` when present (json path), traits as tertiary words, example verbatim (redacted ones read `<redacted>`), frequency; **Flows**: the node's `flows` as method+URL rows when still listed, else the id in tertiary, each with Open Flow (double-click, chevron, context menu; the existing `ScanEndpointRow` behaviour). "Load More" `FlatButton` at the bottom when `next_cursor` is set (passes `cursor`). Empty: "No site map yet — a running job fills this as it crawls."

### D7. Issues tab

Top bar: filters as `FlatMenu`s — Job (All), Severity ≥ (Info…Critical), Confidence ≥, Lane, Class (from the loaded issues), Status (Open / Confirmed / False positive / All). Left (360 pt): sections per severity with a tracked header "HIGH 1" in the severity fg colour (the one place the header carries hue, because it is the datum), rows: `Badge(severity)`, name (ui md medium), second line `GET /search · query q · firm` in data sm; a `checkmark.seal` glyph when `confirmed`, `xmark.seal` when `false_positive`; a `flag.checkered` glyph when `finding_id` is set. Arrow keys move the selection (the Findings list pattern). Right: detail from `scan.issue {id}`:

- Header: name (ui xl medium), `Badge(severity)`, `Badge(confidence, grey)`, `Badge(lane, grey)`, trailing **Status** segmented Open · Confirmed · False positive (→ `scan.issue.update`; a failure restores the old value and shows the reason inline).
- **Where**: `scheme://host:port` + `method path` (path_template in tertiary when it differs) + `kind name` + `field_path` / `ws_path` / l4 fields when present.
- **Description** (ui md). **Remediation** when present.
- **Evidence**: Payload (data, selectable, raised box), Matched (same), Timing (slope, r, and requested_s / observed_ms / baseline_ms as a 3-column table) when present, Diff (baseline / true / false lengths as three numbers) when present, L4 evidence fields when present.
- **Probe flows**: one row per flow id (method+URL when listed, else id) with Open Flow; **Baseline flow** likewise.
- **Links**: `FlatButton("Open PoC")` when `poc_ref` (opens Findings with the finding whose `pocPath` ends with the ref or whose id equals `finding_id`; when the Findings list has none, it opens Findings and shows "PoC poc-3b1c is not in this app's findings list"); `finding_id`, when set, is shown as text ("Finding <id>"): the mac `Finding` carries no core record id to resolve it against.
- **Note**: a text field; Save Note → `scan.issue.update { id, status: <current>, note }`.
- Meta line: `first seen · last seen · occurrences · check id · job`.
- Empty list: "No issues — start a scan, or widen the filters." Empty detail: "Select an issue to read its evidence."

### D8. Live updates and polling (UI-4)

- `ScanPanelState` holds a `ScanSurfaceModel` (Kit, no SwiftUI): profiles, checks, jobs (summaries), statuses by job id, sitemap pages, issues pages, selected ids, filters, pending launch, confirm request, errors.
- **Push.** `Session.attachActivityHooks` already routes `notifications/aitm/agent`; the sink gains `notifications/aitm/job` → `scan.noteJobEvent(params)`. The Kit's `JobNotification` parses it; the model records `seq` per job (an out-of-order or duplicate `seq` is ignored) and sets `refreshNeeded` for that job (and `issuesRefreshNeeded` on `issue` / terminal events). A 250 ms coalescing task then reads `scan.status {job}` (and `scan.list`, `scan.issues` as flagged). The app never updates a counter from the notification's `status` field.
- **Subscribe.** `BusService.run()` after `listTools`: when the tools list has `flow.subscribe`, call `flow.subscribe {}` once per connection (no filter: the scanner's job lines fan out to every subscribed connection, D3). The call is not retried in the poll loop; a reconnect subscribes again. **Delivered in the follow-on PR once the `BusService.swift` claim is granted**; without it the surface still works through D8's poll.
- **Poll.** While the Scan page is visible: `scan.list` every 2 s; the selected job's `scan.status` every 1 s while non-terminal; the Issues tab's `scan.issues` every 2 s while any job is running. Off-page: nothing (the sidebar count comes from the last `scan.list`).
- The subscribe handshake is observable in the core's audit log (`flow.subscribe` from `aitm-mac`), which is UI-4's proof.

### D9. Launch handshake (UI-3)

`scan.start` / `scan.map` are sent through `session.runCommand`. The result is read as:
1. `L4ConfirmRequest(json:)` non-nil → `confirm = request` → sheet "Start Scan?" with `request.prompt` verbatim, buttons Cancel / Start Scan (prominent) → re-send the identical args plus `_confirm: token`.
2. A `StartResult` → insert `status` into jobs, select it, switch to Jobs; show `clamped` and `lanes.skipped` as one-line notices in the job detail.
3. A thrown error → the status line shows the message; the `scan: <code>` token is extracted into a tertiary code label; `busy` and `out_of_scope` phrases get the app's own words ("A scan on this origin is already running", "Out of scope — add … to scope").

### D10. Menu, palette, command map (follow-on PR; the files wait on other PRs)

- Proxy ▸ **Scan** — ⌥⌘S (exists; added to `CommandMap` and the brief's command map line). Proxy ▸ **Start Scan…** — ⌃⌘⏎ (opens Scan on Profiles and focuses the launch; the ellipsis because the sheet may ask) and Proxy ▸ **Cancel Scan** — ⌥⌘. (the selected or the only running job; disabled otherwise). Both disabled when the bus lacks `scan.start`.
- Palette (Setup group): "Scan…" (exists, description updated: "Open the scanner: profiles, jobs, site map, issues"), "Start Scan…", "Cancel Scan", "Scan Issues", "Scan Site Map".
- The brief's command-map Proxy line gains `Scan — ⌥⌘S · Start Scan… — ⌃⌘⏎ · Cancel Scan — ⌥⌘.`.

### D11. States

| View | Empty | Loading | Error | Too much | Done |
|---|---|---|---|---|---|
| Profiles list | "No profiles — the core lists none." (cannot happen with builtins; shown if `scan.profile.list` fails: "Unable to load profiles: …" with Retry) | cached list first; a thin `ProgressView` in the header only past 500 ms | inline under the header | names middle-truncate; help shows the full name | — |
| Editor | — | — | inline under the field | long origin lists scroll | Save Profile → the row updates, status line "Saved my-api" for 4 s |
| Jobs list | "No jobs yet — pick a profile and Start Scan." | — | "Unable to list jobs: …" inline | 50 rows scroll (the core keeps `history`) | Cancel → "Cancelling" then "Cancelled" in the row |
| Job detail | "Select a job." | counters keep the last values while a refresh is in flight (never blank) | `error` field verbatim | `running` check ids capped at 8 by the engine | — |
| Site map | "No site map yet — a running job fills this as it crawls." | — | inline | Load More per page | — |
| Issues | "No issues — start a scan, or widen the filters." | — | inline | 1024 per page, Load More | Status change → pill updates |
| Confirm sheet | — | Start Scan button shows a spinner while the confirmed call is in flight | the sheet closes and the status line shows the error | prompt wraps | the sheet closes, Jobs opens |
| Legacy form | unchanged | | | | |
| Scan unavailable | "Scan is unavailable — the core lists neither scan.start nor scan.discover (it needs the scanner plugin)." | | | | |

### D12. Words

Buttons: Start Scan, Map Only, Cancel Scan, Save Profile, Duplicate…, Delete Profile…, Show Issues, Show Site Map, Open Flow, Open PoC, Save Note, Load More, Add in-scope host, Add Host to Scope…, Open Profiles, Retry. Status words: Queued, Running, Cancelling, Done, Cancelled, Failed; phases Crawling, Passive, Auditing, Reporting. Issue status: Open, Confirmed, False positive. Help strings start with a verb and end with the shortcut: "Start a scan with this profile (⌘⏎)", "Stop this job; its issues stay (⌥⌘.)", "Open this flow in the inspector", "Open the PoC in Findings". Errors: "Unable to load profiles: <reason>", "Out of scope — add <host> to scope to scan it", "A scan on this origin is already running", "The L4 lanes need an L4 scope entry with interface *, direction outbound, the target CIDR and port range and the Inject capability." Confirm: title "Start Scan?", body = the engine's prompt verbatim, buttons Start Scan / Cancel. Delete: "Delete Profile “<name>”?" / "This removes the saved profile file. Jobs that used it keep their results." / Delete / Cancel.

**Words added by the implementation (panel round 1, 2026-11-01).** Error lines follow one shape, `Unable to <what>: <reason>`, for every read and write the surface makes (load profiles, load profile <name>, load checks, list jobs, read job <id>, cancel job <id>, save profile, delete profile <name>, load issues, load issue <id>, update the issue, save the note, load the site map). Placeholders: "Select a job.", "Select an issue to read its evidence.", "Select an endpoint.", "No endpoints match.", "None on this endpoint.", "None recorded for this endpoint.", "No evidence recorded for this issue.", "Nothing to delete: <name> is not on the core", the Duplicate… hint "Use lowercase letters, digits, - _ . (start with a letter or digit)" (the engine's saved-profile rule `^[a-z0-9][a-z0-9._-]{0,63}$`, lowercase only, builtin names refused; the Kit mirrors it before any save and renders `invalid_profile` verbatim). The check-group menu is titled "Set all". Help strings on text buttons and menus are allowed when they start with a verb and add what the label does not say; the confirm sheet carries a flat `exclamationmark.triangle` beside its title (the L4 confirm sheet's precedent). "Endpoint" is the site-map row's word (D1), "Endpoints" the legacy form's. The Issues detail shows one "Open PoC" button when `poc_ref` is set and the `finding_id` as text; the mac `Finding` has no core record id to resolve `finding_id` against. Field placeholders ("Add a note", "Search checks", "Search host or path", "Name"), the filter fallbacks ("Any", "None", "at least …"), "No concrete host in scope", the Session caption "Mode", the Duplicate… hint, "Finding <id>", and the captions that label spec-named wire fields in the Issues detail (field path, ws path, l4 field path, sent hex, grammar, mutation, mutation chain, oracle, prior messages, reproduced, liveness before/after, rng seed, scope entry, seed id) are labels, not vocabulary; they are allowed as written. Every sentence-length string lives in `ScanSurface.swift` (`ScanFormat` or a `scan*` constant).

### D13. Accessibility

- Keyboard: Tab order header → tabs → list → detail; ↑↓ move list selections (profiles, jobs, nodes, issues); ⌘⏎ Start Scan on Profiles; ⌥⌘. Cancel; ⎋ closes the sheet; ⌘1…4 are taken by chips, so tabs are reached by Tab/arrow or the palette entries.
- VoiceOver: every row is one element whose label reads the row's words ("Running, auditing, standard, 127.0.0.1:8080, 418 of 2000 probes, 80 of 120 points audited, 3 issues: 1 high, 1 medium, 1 low"); the severity bar is `accessibilityHidden` behind the row label; severity never by colour alone (the pill carries the word).
- Reduce Motion: no entrance motion anywhere (the app's rule); the only motion is the counter text changing.
- Contrast: all text ≥ 11 pt; severity pills use the kit pairs which pass in Increase Contrast.

### D14. Fixture pack in tests only (never evidence)

The 22 files of `crates/aitm-scan-model/fixtures/` are read by `swift test` from the repo path (the `CommandMapTests.briefURL` pattern) as the parsing contract for the Kit wire types. Nothing else uses them: the orchestrator's claim ruling (2026-10-31) denies `Fixtures+Tools.swift`, `SnapshotScenes.swift` and `Bus/FixtureBus.swift`, which the fake-data removal PR deletes, so the Scan surface registers no snapshot scene, no fixture bus answer and no fixture tool entry. The design loop is the real `.app` from `tools/snap-dev.sh` run live (`APP_LIVE=1`) against a core; the PR's evidence is that app against a live core and `aitm-testtarget`.

### D15. Kit model (no SwiftUI)

`AitmproxyKit/Panels/ScanModel.swift` (wire types): `ScanJobState`, `ScanPhase`, `ScanStoppedReason`, `ScanLane`, `ScanIntensity`, `ScanSpeed`, `ScanAccuracy`, `ScanConfidence`, `ScanIssueStatus` (all `RawRepresentable` with `.other(String)`), `ScanProbeCounters`, `ScanPointCounters`, `ScanIssueCounters` (+ `BySeverity`, `ByConfidence`), `ScanJobStatus`, `ScanJobSummary`, `ScanStartResult`, `ScanListResult`, `ScanIssueSummary`, `ScanIssue` (+ `ScanEvidence`, `ScanTiming`, `ScanIssueLocation`, `ScanTarget`), `ScanIssuesResult`, `ScanSiteNode`, `ScanInsertionPoint`, `ScanSitemapResult`, `ScanCheckMeta`, `ScanChecksResult`, `ScanProfile` (all sections, Codable both ways; unknown keys preserved by round-tripping through `JSONValue` where the app does not edit them), `ScanProfileListEntry`, `ScanProfileListResult`, `ScanProfileSaveResult`, `ScanSessionProfile`, `ScanJobNotification`. Each has `init(json: JSONValue) throws` like `ScanResult`.
`AitmproxyKit/Panels/ScanSurface.swift` (state): `ScanSurface` (offered when `scan.start` is listed; `legacyOffered` when only `scan.discover`), `ScanSurfaceModel` (the tab, lists, selections, filters, `noteJobEvent`, `refreshFlags`, `launchArguments(for:overrides:)`, `launchRefusal(scopeHosts:l4ScopeAvailable:tools:)`, `issuesGroupedBySeverity(filters)`, `sitemapGroupedByOrigin`, `severityBarSegments`), `ScanCheckTree` (grouping and the tri-state), `ScanLaunchError` (code parsing). Formatting helpers: `elapsed(ms)` → `m:ss` / `h:mm:ss`, `probesText`, `pointsText`.

## Acceptance criteria

1. **MS-AC1 (parse pack).** `swift test` has a test per fixture file in `crates/aitm-scan-model/fixtures/` (22 files, read from the repo path) that decodes it into its Kit type and pins at least three literals per file (e.g. `scan.status.json` → `state == .running`, `probes.sent == 418`, `issues.bySeverity.high == 1`); an unknown enum value (`"state": "paused"`) decodes to `.other("paused")` and renders as `paused`.
2. **MS-AC2 (launch gate).** `ScanSurfaceModel.launchRefusal` returns nil for an in-scope `standard` profile; "Out of scope — …" for an origin not in scope; the L4 hint for a profile with an L4 lane when no Inject L4 scope entry is known; "scan.start is not on this bus" when the tool is absent; nothing reaches `commandRunner` in the refused cases (unit).
3. **MS-AC3 (confirm handshake).** Given a `needs_confirmation` result, the model exposes `confirm` with the prompt text and the re-sent arguments equal the original plus `_confirm: token`; given a `StartResult`, the job appears first in `jobs` and is selected, the tab is Jobs (unit).
4. **MS-AC4 (push is a trigger).** `noteJobEvent` with the `job.progress.json` line sets `refreshNeeded[job]` and changes no counter; a line with a `seq` ≤ the last seen is ignored; `issue` and terminal events also set `issuesRefreshNeeded` (unit).
5. **MS-AC5 (grouping).** `issuesGroupedBySeverity` over `scan.issues.json` yields sections High(1) and Medium(1) in severity order with Critical/Low/Info absent; the status filter `false_positive` hides both; `sitemapGroupedByOrigin` over `scan.sitemap.json` yields one origin `http://127.0.0.1:8080` with node `/account/{id}` carrying 2 points (unit).
6. **MS-AC6 (profiles round-trip).** `scan.profile.get.json` decodes to `ScanProfile`, re-encodes to JSON equal to the file after normalisation, and `checks.include = ["http.sqli-error"]` edits survive the round trip (unit).
7. **MS-AC7 (command map; follow-on PR).** `CommandMap.all` has Proxy ▸ Scan ⌥⌘S, Start Scan… ⌃⌘⏎, Cancel Scan ⌥⌘.; `mapMatchesTheBrief` passes with the brief updated; the self-test's menu walk finds the three items (after the `CommandMap.swift`, `App.swift`, `BRIEF.md` claims).
8. **MS-AC8 (build and lint).** `swift build` has no errors or warnings in the new files; `tools/grid-lint.sh` PASS; `swift tools/check-layout.swift` PASS on the dev scenes (development loop only).
9. **MS-AC9 (live, UI-1).** The real `.app` (snap-dev bundle, `APP_LIVE=1`) against a live core with the engine and `aitm-testtarget` in `vulnerable` mode: Start Scan with `standard` → the Jobs row's probes counter rises across at least three distinct values and the phase word changes; Cancel Scan → the row reads Cancelled within 5 s; a concurrent `scan.status` read by the harness matches the row's numbers at the capture instants. Evidence: window-id recording frames + the harness log in the PR.
10. **MS-AC10 (live, UI-2).** During the same run, issues appear in the Issues tab grouped by severity without a click; opening a probe flow selects it in the inspector; Open PoC lands on Findings; setting False positive is visible in a harness `scan.issue {id}` read.
11. **MS-AC11 (live, UI-3).** Launching `l4-stream-safe` shows the sheet with the engine's prompt text (recorded), and Cancel sends nothing further (audit log shows one `scan.start` without `_confirm`); without an L4 scope entry the Start Scan button is disabled with the hint.
12. **MS-AC12 (live, UI-4; follow-on PR).** The core's audit/activity log shows `flow.subscribe` from the mac client on connect, and the Jobs row updates with no pointer or keyboard input for 30 s (recording). Attempted only in the follow-on PR, once the `BusService.swift` claim is granted.
13. **MS-AC13 (live, UI-5).** The Site map tab renders the nodes and insertion points of the harness's `scan.sitemap` read: the rendered path templates equal the result's set.
14. **MS-AC14 (legacy).** Against a core that lists `scan.discover` only (v0.5.8 on main), the Scan page shows the existing form and a crawl still completes (live, one run).

## Left to the builder

- Row heights and exact column widths inside the 4 pt grid; the disclosure glyphs; whether the check tree uses `DisclosureGroup` or a flat indented list.
- The popover for Duplicate… (name field + Duplicate button).
- How the `.other(String)` enum cases are spelled (an `enum` with an associated case, or a struct wrapping the raw string with static members).
- Debounce internals (a `Task` per job or one coalescing task).

## Open questions

None. Numbering of the new stories starts at S-085 to leave S-073..S-079 to the sibling macOS sessions.

## Review log

Dispositions live in the plan's Review log (`docs/superpowers/plans/2026-10-31-scanner-v2-mac-scan-surface-plan.md`,
rows MS-R1 and MS-R2, post-release 0.5.14). Design consequence recorded here: **D8 amendment (MS-R1)** — the
page's `surface` is one `@Observable` value, so every non-gesture write (poll tick, push line) compares the
model before assigning and publishes only on a real change; the `ScanCheckTree` is derived once per distinct
(catalogue, selection, intensity, query), not per body pass. The tick cadence, the flag semantics and D11 are
unchanged. The run-dir isolation of dev-bundle cores (MS-R2) is owned by the one-shot spec
(`2026-11-01-cli-oneshot-live-core-design.md` §D4 `AITM_RUN_DIR`, §D11 mac follow-up) and is recorded in that
plan's Review log; it travelled in the same PR because the 0.5.14 acceptance run surfaced both.
