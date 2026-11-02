# Scanner Jobs view UX design

**Status:** draft (stage 1 UX pass done 2026-11-02; stage 2 design section and ACs pending the architect)
**Research inputs:** this document's *Current state* section (real-app frames in `docs/design/evidence/jobs-view-2026-11-02/`), `docs/design/operator-ui-foundation.md` (§2.2 palette, §2.3 type, §2.8 interaction rules), `docs/design/tokens.json`, `docs/design/GLOSSARY.md`, `docs/superpowers/specs/2026-10-31-scanner-v2-mac-scan-surface-design.md` (D5, D11, D13), the engine's `JobStatus` in `crates/aitm-scan-model/src/job.rs`
**Parent:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (D5 job status, D10 UI parity)

## Intent

The Jobs tab is where an operator watches a scan happen. Today it is a dump of
the engine's counters: eleven flat stat groups, the probe *budget* drawn as if
it were progress, no sentence that says what the job is doing or why it
stopped, and a detail pane that goes stale the moment a job ends. Matt's words
after using it: "it needs a lot of work". This spec redesigns the Jobs view so
a running job reads at a glance (state, how far along, what it is doing now,
issues so far, elapsed), every end state is explained in words with the next
action beside it, and the view is good to look at: the project palette and
type, calm monochrome motion that only bridges real state changes, flat
icons, editorial restraint. macOS first through the bama pipeline, then the
same words, states and progress rule on the web UI and the TUI.

## Goals

- A running job's row and detail answer, without reading numbers: is it
  running, how far along, what is it doing now, how long has it run, what has
  it found.
- Every end state (Done, Cancelled, Failed, and Done-with-a-stopped-reason) is
  one plain sentence that says what happened and what to do next, with the
  next action as a button.
- The operator can inspect and cancel without leaving the view; cancel is one
  click, idempotent, and the view shows Cancelling then Cancelled on its own.
- Empty, queued, cancelling, bus-disconnected, many-jobs and check-error cases
  each have a designed look and words.
- Keyboard-only and VoiceOver can do everything a pointer can.
- The view uses the palette, type scale and motion tokens in
  `docs/design/tokens.json`; hue appears only where the foundation allows it
  (severity, error text).
- Web and TUI reach parity on words, states, progress definition and
  stopped-reason sentences.

## Non-goals

- No new bus verbs, no engine changes. Everything on screen is a value the
  bus already returns (`scan.list`, `scan.status`, `scan.cancel`, `scan.start`).
  If a field the design needs is missing from the wire, the spec says so and
  the UI degrades; the ask goes to the coordinator as a KEY decision.
- No changes to the Profiles, Issues or Site map tabs beyond the two jumps
  the Jobs view already makes (Show Issues, Show Site Map).
- No pause/resume (the engine has none).
- No charts, sparklines or history graphs of a job.
- No per-check progress list (the engine caps `checks.running` at 8 ids).

## Anti-goals

- A dashboard: tiles, gauges, coloured status chips, gradients, glass. The
  foundation's rule stands: flat, typographic, hue only on the one datum that
  carries it.
- Motion that performs: entrances, bounces, pulses on counters. Motion here
  only bridges a change the operator would otherwise see jump.
- Numbers the view computes that the bus did not return, except the
  derived progress fraction and percentages, which are named as derived.
- A detail pane that can disagree with its row (the stale-status bug below).

## Constraints

- **Bus truth only.** Push lines (`notifications/aitm/job`) are triggers;
  values come from `scan.status`/`scan.list` (parent spec D8, mac spec D8).
- **One running job per origin, `max_jobs` concurrent** (engine
  `jobs.rs`): the engine refuses a third start with `scan: busy: 2 scan jobs
  are already running`. The Jobs view cannot queue; it can only show what
  runs.
- **Hostile-core bounds** (TUI D6): strings from the core are bounded before
  they reach the screen; the mac Kit's existing decoders keep their defaults
  for missing fields.
- **Palette and type** from `tokens.json`: UI face / data face, six sizes,
  tabular figures on every number; `Tok.*` on mac, CSS variables on web,
  theme tokens on TUI. No hard-coded colours, radii or durations in views.
- **Motion tokens**: `easeOut` `(0.23, 1, 0.32, 1)`, `easeInOut`
  `(0.77, 0, 0.175, 1)`, press 120 ms, hover 100 ms, popover 160 ms, sheet
  220 ms. Keyboard-initiated actions never animate. Reduce Motion drops
  travel and keeps opacity.
- **Evidence rule.** Proof is the real app, a real core and real traffic
  (`aitm-testtarget-serve --latency-ms N`); no snapshot, fixture or self-test
  evidence for UI.
- **Performance.** The detail pane re-renders once per second per running
  job; list rows once per 2 s. No per-frame work, no timers in views.

## Current state (2026-11-02, real app, core built from this branch, target with 400 ms latency)

Frames in `docs/design/evidence/jobs-view-2026-11-02/` (window captures of
the dev bundle `Aitmproxy-jobsux`, 1862×1130 pt). Each finding names its frame.

| # | Finding | Frame |
| --- | --- | --- |
| C1 | **Stale detail after a terminal state.** After Cancel Scan the row reads *Cancelled* while the detail header still reads *Cancelling · Auditing · 1:55*, Cancel Scan stays enabled and *Running: header-reflection* stays on screen, for ever. Cause: `pollStatuses` re-reads the selected job only while its *list summary* is non-terminal; the stored status is the pre-terminal one from `scan.cancel`. Push wiring (which would have flagged it) is not in the app yet. | `09-cancelled.png`, `10-cancelled-later.png` |
| C2 | **A finished job shows its first status.** Selecting the Done `light-http` job shows *Running · Crawling · 0:00*, every counter 0, Cancel Scan enabled. Cause: each listed job's status is read once (at first sight, here while crawling) and never again once the list calls it terminal. | `13-first-row-detail.png`, `15-list-later.png` |
| C3 | **The probe budget is drawn as progress.** The one large number and the only bar are `probes.sent / probes.budget` (107 / 2,000, a 5 % fill) while checks are 3,101 of 6,468 done. The operator's real progress is not on screen. | `05-selected-running.png` |
| C4 | **The row's severity bar reads as a progress bar.** A full-width blue bar under every row with issues (all four are *low*, so the bar is 100 % blue). Severity *mix* drawn as a bar of shares says nothing about quantity and looks like completion. | `11-many-jobs.png` |
| C5 | **Row line 2 truncates the elapsed time** at the 360 pt list width: `probes 17 / 2000 · points 0 / 0 audited · 0:…`. | `03-running-b.png` |
| C6 | **No sentence for an end state.** `stopped_reason` is printed as its raw token (`errors`) in a *Stopped* section at the bottom; the dead-target job ended *Done* with `stopped_reason: errors` and 7 check errors that say *Connection refused*, and the view shows *Done* and nothing else. The mac Kit does not decode `checks.errors`, `checks.error_samples`, `checks.skipped`, `crawl.errors`, `crawl.last_error`, `crawl.forms_skipped`. | `15-list-later.png`, bus `scan.status` of `scan-22cfb48c` |
| C7 | **"What is it doing now" is buried.** The only live hint, `checks.running`, sits two thirds down the detail under *Checks ▸ Running*. The phase word is the header's second token. | `06-selected-later.png` |
| C8 | **A job started elsewhere is not selected.** A job started over the bus (CLI, MCP, another UI) appears as a row while the detail says *Select a job.* | `02-running-a.png` |
| C9 | **Noise sections for every job.** *Session* (reused no / lost no / browser partial no / "Auth-lost detection off: no GET/HEAD flow seen") and *Lanes* repeat the same text on every job; *Points ▸ Queued 6468* is larger than *Found 1020* with no explanation; *Skipped frequent 722* is jargon. | `05-selected-running.png` |
| C10 | **Rows are not in the accessibility tree.** An AX dump of the window lists every button and static text but no element for a job row (`accessibilityElement(children: .ignore)` inside a `LazyVStack` yields nothing). To verify by the tester with VoiceOver. | `ax-dump.tsv` |
| C11 | **Started / finished / started-by are not shown** on mac although `scan.status` carries them (the web view shows them). | all detail frames |
| C12 | **Disconnected core.** With the core frozen (SIGSTOP) the list keeps its values and the inline error *Unable to list jobs: the bus did not reply in time* appears above the rows after the 30 s timeout; Cancel Scan and the hover Cancel stay enabled, nothing says how old the values are, and the error line is the only red text on the page. | `17-core-frozen.png` |

The engine fact behind C3: a `standard` job against the test target with 400 ms
latency sends ~2 probes/s against a 2,000 budget while scheduling 6,468 checks
for 1,020 points; the budget would last 16 minutes and the checks about 2.
`elapsed_ms` is live. A `thorough` job runs for minutes; a `light-http` job
ends in ~70 s. The dead-target job ended `done` + `stopped_reason: errors`
after 30 s with `crawl.errors 1, pages 1` and 7 check errors whose first
sample says `Connection refused (os error 61)`.

## UX

Written per the `ux-design` skill's eight steps. Terms are in
`docs/design/GLOSSARY.md` (§Scanner, §Job states, §Job actions, §Progress words).

### Names (step 1)

Job, Profile, Target, Phase, Probe, Probe budget, Time budget, Point, Check,
Check error, Issue, Severity, Confidence, Lane, Site map, Session; states
Queued / Running / Cancelling / Done / Cancelled / Failed; actions Start
Scan, Cancel Scan, Scan Again, Show Issues, Show Site Map, Copy Job ID, Open
Profiles; progress words Progress, Elapsed, Now, Started, Finished. One name
per idea; "stop", "abort", "finding", "run", "task" never appear.

### Flow (step 2)

```text
Profiles ▸ Start Scan (⌘⏎) | Map Only | a start from CLI/MCP/another UI | a row click
  -> Jobs tab, the job selected, its card live (progress, now, issues, elapsed)
  -> watch: ↑↓ walk the rows, Return/→ moves focus to the detail, ⌥⌘. or Cancel Scan (header, row hover, context menu) asks the engine to stop
  -> Cancelling (button disabled, says "Cancelling…") -> Cancelled | Done | Failed: one sentence says why, with Scan Again · Show Issues · Show Site Map beside it
  -> Escape returns focus to the list; nothing to undo (a job cannot be un-cancelled; what it found stays)
```

Entry points: Profiles footer (Start Scan ⌘⏎, Map Only), Proxy ▸ Scan
(⌥⌘S) then the Jobs tab, the command palette ("Jobs"), a push for a job
started elsewhere (the row appears; it is selected only when nothing else is
selected), the Issues tab's job filter (Show Jobs is not added; non-goal).

### Surface (step 3)

- **List + inspector**, as today (table row *Shows details of the selection
  while people keep working → Inspector*). The list is the at-a-glance surface,
  the inspector the inspect-and-act surface.
- **Cancel** stays inline (header button, hover button, context menu, ⌥⌘.).
  No confirmation dialog: the row *A rare action that destroys data and
  cannot be undone* does not apply; nothing found is lost and Scan Again
  exists. Cancel is idempotent: a second press while Cancelling sends nothing.
- **Check errors, clamped values, skipped lanes** are inline disclosures in
  the inspector (*Information that needs no action goes inline, never in an
  alert*).
- **Bus disconnected** is an inline banner above the list, not an alert.

### States (step 4)

Every state below is a real-app frame in the live proof.

| State | List row | Inspector |
| --- | --- | --- |
| Empty | Keep: glyph, "No jobs yet — pick a profile and Start Scan.", `Open Profiles`. | "Select a job." only when rows exist; with none, the pane is empty ground. |
| Queued | Indeterminate small ring, "Queued · standard", target, "waiting to start". | Header "Queued · 127.0.0.1:8117"; card: "Waiting for the engine to start this job." Cancel Scan enabled. |
| Running | Determinate ring (progress), "Auditing · standard" / target / "4 low" · elapsed; 4 pt progress rule. | Header "Auditing 127.0.0.1:8117", subtitle "standard · started 11:32 by this app · 1:04". Card: progress % + "3,236 of 6,468 checks", rule, **Now** line ("xss-reflected and 3 more"), tiles Probes / Points / Issues. Attention lines only when non-zero. |
| Crawling / Passive / Reporting | Ring: pages ÷ (pages + queued) while crawling; indeterminate for passive; full for reporting. | Card progress line reads "46 pages, 12 queued" / "Passive checks over captured traffic" / "Writing results". |
| Cancelling | Ring frozen at its value, "Cancelling · standard". | Header "Cancelling 127.0.0.1:8117"; Cancel Scan disabled and titled "Cancelling…". |
| Done | No ring; "Done · standard" / target / "4 low" · "1:09". | Card becomes the end sentence: "Done in 1:09 · 1,020 points · 6,468 checks." plus the stopped-reason sentence when present. Buttons: Scan Again · Show Issues · Show Site Map. |
| Cancelled | "Cancelled · standard" / target / "4 low" · "1:55". | "Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays." Scan Again. |
| Failed | "Failed · standard" / target · elapsed. | "Failed after 0:12." then the engine's error text verbatim in `Tok.Status.serverError`, selectable. Scan Again. |
| Done with stopped reason | as Done | budget: "Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further." · time: "Stopped early: the time budget ran out." · session_lost: "Stopped early: the session was lost and the profile says stop when that happens." · errors: "Stopped early: too many errors from the target. 7 checks could not run ▸" · policy: "Stopped early: the agent policy changed to paused or read-only." · guard_refused: "Stopped early: the L4 guard refused a target mid-run." · failed: the error text. |
| Check errors (any state) | nothing | Attention line "7 checks could not run ▸" opening the first 8 `(check, detail)` samples in the data face; "3 checks were skipped ▸" likewise for `skipped_samples`. |
| Crawl trouble | nothing | "The crawl fetched 1 page and hit 1 error ▸" with `last_error` as words: connect_refused "the target refused the connection", tls "TLS handshake failed", timeout "the target did not answer in time", h2_not_negotiated "the target does not speak HTTP/2", transport/other "the connection failed". |
| Notices | nothing | "Clamped budget.probes 50,000 → 20,000" and "Skipped WebSocket: lane not available on this build" as one list under **Notices**, shown only when non-empty. |
| Many jobs | Caption above the rows "4 jobs · 1 running"; rows newest first; the list scrolls; a row's long target middle-truncates with the full list in a tooltip. | unchanged |
| Bus disconnected | Banner above the caption: "Bus disconnected · showing values from 0:42 ago · reconnecting…"; rows keep their last values; hover Cancel hidden. | Cancel Scan and Scan Again disabled; values kept. |
| List read failed | Keep the inline error (D11) with the core's text and the last-good time. | unchanged |

Progress fraction (derived, named as such in the tooltip): queued → none;
crawling → `pages / (pages + queued)` when the sum is > 0; passive → none;
auditing → `checks.done / checks.scheduled` when scheduled > 0; reporting →
1; terminal → the last fraction, dimmed. `scheduled` grows while points are
found, so the fraction can fall; the rule eases to the new value and never
snaps.

### Words (step 5)

- Buttons: `Start Scan`, `Cancel Scan`, `Cancelling…` (disabled), `Scan
  Again`, `Show Issues`, `Show Site Map`, `Copy Job ID`, `Open Profiles`.
  Title case, verbs first, ellipsis only on the in-flight Cancelling.
- Header: `<Phase or state word> <target host[:port]>`; two targets join with
  ", "; three or more read "<first> and 2 more" with the full list in the
  tooltip and the **Target** line.
- Subtitle: `<profile> · started <h:mm> by <this app | the CLI | an agent |
  <client label>> · <elapsed>`; after the end: `… · finished <h:mm> · <duration>`.
- Card progress: `48 %` (data face xl, tabular) and `3,236 of 6,468 checks`;
  `Now` line: `Now: xss-reflected` / `Now: xss-reflected and 3 more` / absent
  when `checks.running` is empty.
- Tiles: `Probes 287 of 2,000` · `Points 97 of 1,020 audited` · `Issues 4`
  with `4 low` beneath in severity ink; `no issues yet` while running, `no
  issues` after.
- Sentence case for labels and all messages. Errors name what happened and
  the fix: "Unable to list jobs: <core text>. Retrying every 2 s." Never
  "something went wrong".
- Every number uses grouping separators and tabular figures.

### Hover help (step 6)

Every icon-only or ambiguous control: Cancel Scan "Stop this job; the issues
and site map it found stay (⌥⌘.)"; Scan Again "Start a new job with this
job's profile and target"; Show Issues "Open the Issues tab filtered to this
job"; Show Site Map "Open the Site map tab for this job"; the progress ring
and rule "<done> of <total> checks (derived from the engine's counters)"; the
Issues tile "<n> issues: 1 high, 3 low"; the truncated target "<all targets>".
Hover reveals the row's Cancel in the elapsed slot so nothing shifts; the
same verb is in the context menu and on ⌥⌘..

### Accessibility (step 7)

- Tab order: Scan tabs → list → inspector header buttons → disclosures.
- ↑↓ move the selection (no animation); Return or → focuses the inspector;
  Escape returns to the list; ⌥⌘. cancels the selected job.
- Each row is one accessibility element whose label is a sentence:
  "Auditing, standard, 127.0.0.1:8117, 48 percent, 3,236 of 6,468 checks, 4
  issues: 4 low, 1 minute 4 seconds." Rows must be present in the AX tree (C10).
- The inspector header is a heading; the progress rule has value "48 percent";
  the ring is hidden (the row label carries it); tiles read label then value.
- When the selected job reaches an end state, VoiceOver gets one announcement:
  "Scan of 127.0.0.1:8117 done: 4 issues." (occasional, state indication).
- Meaning never by colour alone: severity text carries the word; state words
  are text; the Failed error is text.
- Text ≥ 11 pt; Increase Contrast keeps the token pairs (≥ 4.5:1).
- Reduce Motion: progress eases become instant, the end-sentence swap is an
  opacity fade only, the indeterminate ring is the system `ProgressView`
  (which honours the setting).

### Look and motion (Matt, 2026-11-02: "amazing design, animations, styles, colours matching our palette")

Palette and type, all from `tokens.json`: list and inspector on
`Ground.surface`; the summary card on `Ground.raised` with `radius.panel`
(8 pt), no shadow; progress rule and ring in `Ink.primary` on `Ground.raised`;
labels `Ink.secondary` xs caps tracked (existing `ScanSectionTitle`); values
in the data face with tabular figures; the big percent in data xl 500; the
header in UI xl 500; the end sentence in UI md `Ink.primary`; stopped-reason
in UI md `Ink.secondary`; error text in `Status.serverError`; severity words
in `Severity.<level>.fg`; everything else monochrome. Selected row
`Ground.active`, hover `Ground.hover`, rule `Line.rule`.

Motion, per the `animate` gate (frequency → purpose → tool → properties →
curve/duration → interruption → reduce motion):

| Change | Frequency | Purpose | Motion | Reduce Motion |
| --- | --- | --- | --- | --- |
| Counter ticks (every 1 s) | tens per minute | prevent a jarring change | `contentTransition(.numericText())`, 150 ms `easeOut`; opacity/translate of digits only | instant swap |
| Progress rule / ring value | every 1 s | prevent a jarring change | width/trim eases 250 ms `easeOut`; never snaps back | instant |
| State word change (Running → Cancelling → Cancelled) | occasional | state indication | header word crossfades 160 ms `easeOut` (opacity) | same (opacity only) |
| Card swap progress → end sentence | once per job | prevent a jarring change | 220 ms `easeOut`, opacity 0→1 and 2 pt rise | opacity only |
| New row (a job started) | occasional | spatial consistency | 160 ms opacity fade; no travel (tokens: `rowArrive` is for flows, jobs arrive rarely) | same |
| Row hover Cancel | tens per day | feedback | 100 ms opacity in the fixed slot | same |
| Button press | — | feedback | existing press 120 ms scale 0.97 | existing |
| Indeterminate phases | — | state indication | system `ProgressView` small circular | system |
| Selection by keyboard, tab switch | 100+/day | — | **none** | none |

No entrance for the inspector, no pulse on anything, no colour animation.
Durations and curves are tokens (`Tok.Motion.easeOut(…)`); the Kit gets a
`ScanMotion` namespace so views carry no literals.

### UX block (step 8)

```markdown
UX:
- Flow: Start Scan (⌘⏎) / Map Only / a start elsewhere -> Jobs tab, job selected, card live -> ↑↓ rows, Return focuses detail -> Cancel Scan (⌥⌘., header, row hover, context menu) -> Cancelling… -> Done | Cancelled | Failed: one sentence + Scan Again · Show Issues · Show Site Map
- Surface: list rows (at a glance) + inspector (inspect and act); cancel inline, no dialog; errors and notices as inline disclosures; disconnected as an inline banner
- States: empty "No jobs yet — pick a profile and Start Scan." + Open Profiles; queued "Waiting for the engine to start this job."; running card = % + "3,236 of 6,468 checks" + rule + "Now: xss-reflected and 3 more" + Probes/Points/Issues tiles; cancelling button "Cancelling…" disabled; done "Done in 1:09 · 1,020 points · 6,468 checks."; cancelled "Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays."; failed "Failed after 0:12." + error; stopped reasons as sentences (budget/time/session_lost/errors/policy/guard_refused); check errors "7 checks could not run ▸"; crawl "fetched 1 page and hit 1 error ▸ the target refused the connection"; many "4 jobs · 1 running"; disconnected "Bus disconnected · showing values from 0:42 ago · reconnecting…"
- Words: Cancel Scan, Cancelling…, Scan Again, Show Issues, Show Site Map, Copy Job ID, Open Profiles; header "<Phase> <host>"; subtitle "<profile> · started 11:32 by this app · 1:04"
- Help: Cancel Scan "Stop this job; the issues and site map it found stay (⌥⌘.)"; Scan Again "Start a new job with this job's profile and target"; rule "<done> of <total> checks (derived)"
- Access: ↑↓ rows, Return/→ detail, Esc back, ⌥⌘. cancel; row label is a sentence; header is a heading; rule value "48 percent"; one announcement at an end state; rows present in the AX tree
- Look: tokens only; card on Ground.raised radius.panel; hue only on severity words and the Failed error; counters numericText 150 ms, rule 250 ms easeOut, state crossfade 160 ms, card swap 220 ms; keyboard moves never animate; Reduce Motion keeps opacity, drops travel
```

### Fixes the design requires in the live wiring (mac)

- F1 (C1, C2): a selected job is re-read when its stored status is missing
  or non-terminal, and once more whenever the list's state for it differs
  from the stored status's state; a terminal status is final. Status reads
  of unselected terminal jobs happen once (as today) but *after* the list
  called them terminal, so the stored status is the final one.
- F2 (C6): the Kit decodes `checks.errors`, `checks.error_samples`,
  `checks.skipped`, `checks.skipped_samples`, `crawl.errors`,
  `crawl.forms_skipped`, `crawl.last_error` with zero / empty / nil defaults.
- F3 (C8): a job that appears in the list while nothing is selected becomes
  the selection; an existing selection is never stolen.
- F4 (C10): rows are real accessibility elements (verify with the AX dump
  and VoiceOver on the real app).
- F5 (C12): the surface records `jobsLoadedAt` and reads the bus state from
  the session so the banner and the disabled verbs are driven by facts.

### Parity (web, TUI)

Same words, state table, progress definition, stopped-reason sentences and
hover help. Web: `JobsView.tsx` row = ring + two lines + rule; detail card
first, sections as `<details>`; `JobStrip.tsx` shows the same progress
fraction and the Now line; tokens via the existing CSS variables; motion via
CSS transitions on `transform`/`opacity` with `prefers-reduced-motion`. TUI:
the row's probe bar becomes the progress bar (box-drawing, `━`/`─`), the
detail's first lines are the sentence, the progress line and the Now line;
severity by `Theme::severity`, everything else bold/dim.

## Design

*(Stage 2, architect: turn the UX section into decided types, module
boundaries and data flow; mark Architect's calls.)*

## Acceptance criteria

*(Stage 2, architect. Each observable on the real app with a real core and
real traffic; cite the state table rows.)*

## Left to the builder

- Exact point sizes within the token scale; the ring's stroke width.
- Whether the tiles are a three-column `HStack` or a `Grid`.
- The disclosure groups' default open/closed state per section.

## Open questions

- **Scan Again** starts `scan.start { profile_name, overrides: { target } }`
  from the finished job's `profile_name` and `targets`. A saved profile that
  was edited or deleted since makes the engine refuse with `invalid_profile`;
  the view shows the refusal inline. Acceptable, or should Scan Again be
  dropped from this spec? (Default: keep; the refusal is a real state with a
  real sentence.)
