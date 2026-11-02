# Scanner Jobs view UX design

**Status:** approved (2026-11-02, self-approved by the scan-jobs-ux session under Matt's autonomous-approve mode; Matt may correct any **(Architect's call)** at review). Coordinator rulings of 2026-11-02 folded in: Scan Again decided (D13), two mac PRs (Part A, Part B), checks-done as the primary bar (D8, D11), stopped-reason words everywhere with the raw token only in the inspector (D4). The two motion tokens of D12 are approved.
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
- Card progress: `50 %` (data face xl, tabular) and `3,236 of 6,468 checks`
  (architect, 2026-11-02: the draft read `48 %` beside these counters; 3,236 / 6,468 is 50 %);
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
  "Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236 of 6,468 checks, 4
  issues: 4 low, 1 minute 4 seconds." Rows must be present in the AX tree (C10).
- The inspector header is a heading; the progress rule has value "50 percent";
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
- Access: ↑↓ rows, Return/→ detail, Esc back, ⌥⌘. cancel; row label is a sentence; header is a heading; rule value "50 percent"; one announcement at an end state; rows present in the AX tree
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

The UX section above is the research; this section turns it into decided
types, module boundaries and data flow. Every decision below is final unless
marked **(Architect's call)**, which Matt may correct at approval. Nothing
here adds a bus verb or changes the engine (non-goal); every value on screen
is a `scan.list` / `scan.status` / `scan.cancel` / `scan.start` value or a
derived number named as such (progress, percent, elapsed words).

**Supersession.** This spec supersedes mac spec D5's Jobs row and detail
layout (the severity bar as the row's second datum, the eleven flat sections,
the probe rule as the one bar) and the parent spec D10's "issues by severity
as a stacked bar" *for the Jobs list only*. The Issues tab is untouched. Mac
spec D8 (polling, push as trigger), D9 (confirm handshake), D11 (errors stay
inline, values never blank), D12 (words) and D13 (keyboard, VoiceOver) stand
and are extended here.

**Two mac PRs** (coordinator ruling, 2026-11-02). PR 1 is correctness and
lands first: it closes C1, C2, C6 (decoding and words), C10 and C12 inside the
*current* layout. PR 2 is the redesign: the row, the inspector, the derived
progress, motion, Scan Again, the announcement and the banner. Decisions D1 to
D7 are PR 1; D8 to D17 are PR 2; D18 to D20 cover web, TUI and testing and
name their own two steps. The acceptance criteria carry the same prefixes.

### Part A: PR 1, correctness in the current layout (mac)

#### D1. The Kit decodes every status field the design reads (F2, C6)

`ScanModel.swift` gains, with zero / empty / nil defaults so an older core
still parses:

- `ScanCheckCounters` gains `errors: Int` (`"errors"`, default 0),
  `errorSamples: [ScanCheckErrorSample]` (`"error_samples"`, default `[]`),
  `skipped: Int` (`"skipped"`, default 0), `skippedSamples: [ScanCheckErrorSample]`
  (`"skipped_samples"`, default `[]`).
- New `public struct ScanCheckErrorSample: Hashable, Sendable { public var check: String; public var point: String; public var detail: String }`
  with `init(json:)`; a missing key reads `""` (the engine's `#[serde(default)]`).
- `ScanCrawlCounters` gains `errors: Int` (`"errors"`, 0), `formsSkipped: Int`
  (`"forms_skipped"`, 0), `lastError: ScanCrawlErrorKind?` (`"last_error"`, nil).
- New `public enum ScanCrawlErrorKind: ScanVocabulary { case h2NotNegotiated, connectRefused, tls, timeout, transport, other; case unknown(String) }`
  following the `ScanVocabulary` pattern (`init?(rawValue:)` never nil,
  `rawValue` round-trips; the protocol's `static func other(_:)` witness
  returns `.unknown(raw)`). The engine's own token `other` is a known case;
  the escape hatch is spelled `unknown` so the two never collide
  **(Architect's call)**.
- The existing `ScanWire` helpers are reused; no new decoding helper is
  needed. `ScanJobStatus.summary` is unchanged (the summary carries none of
  these fields, matching the engine's `JobStatus::summary`).

Reason: C6 showed a `done` job with 7 check errors and a connect-refused crawl
rendered as "Done" and nothing else. The words of D4 and D9 need these fields.

#### D2. One truth per job: the merged facts, the re-read rule, cancel gating (F1, C1, C2)

**The merged view.** `ScanSurface.swift` gains a pure value the row and the
detail both read, so they can never disagree (anti-goal: a stale detail):

```swift
public struct ScanJobFacts: Equatable, Sendable {
    public var job: String
    public var summary: ScanJobSummary      // the counters both wire shapes carry
    public var status: ScanJobStatus?       // the detail-only fields, when read
    public static func make(summary: ScanJobSummary, status: ScanJobStatus?) -> ScanJobFacts
}
```

`make` picks the *newer* of the two for the shared counters (state, phase,
elapsed, probes, points, issues): the status's summary when the status is
terminal or `status.elapsedMs >= summary.elapsedMs`; the list summary
otherwise (the list said terminal while the stored status is still running,
or the list is simply later). The detail-only fields (profile, targets,
started by, crawl, checks, lanes, clamped, session, l4, stopped reason,
error) always come from `status` and are nil / `—` until it arrives.
`ScanSurfaceModel.facts(for job: String) -> ScanJobFacts?` is the one accessor
the views use; `ScanJobRow` and `ScanJobDetail` stop reading
`surface.statuses[...]` directly.

**The re-read rule.** A pure predicate in the Kit drives the poll:

```swift
public static func needsStatusRead(summary: ScanJobSummary, stored: ScanJobStatus?) -> Bool
// true when stored == nil, or when summary.state.isTerminal && !stored.state.isTerminal
```

`ScanPanelState.pollStatuses` changes to:

1. The selected job is read every status beat while
   `statuses[job] == nil || !statuses[job]!.state.isTerminal` (not, as today,
   while the *list* summary is non-terminal). A terminal stored status is
   final and is never read again (D11's "values never blank" holds: a
   terminal status carries every field).
2. Every other listed job is read when `needsStatusRead` is true and no read
   for it is in flight. `statusRequested` becomes a set of
   `(job, summaryIsTerminal)` pairs so a job read once while running is read
   once more after the list calls it terminal, and then never again.
3. Push flags (`refreshNeeded`) keep their precedence; nothing else in
   `pollTick` changes.

Reason: C1 and C2 are the same bug, a stored status frozen at its first read.
Rule 1 fixes the selected job (C1), rule 2 fixes a finished job selected
later (C2); `ScanJobFacts.make` hides the one-beat gap between the list
turning terminal and the final status landing.

**Cancel gating.** `ScanPanelState.cancel(job:)` sends nothing when
`facts(for: job)?.summary.state` is `.cancelling` or terminal (idempotent
twice over: the engine's cancel already is). `cancelTarget` returns nil for a
cancelling job. The header's Cancel Scan button is disabled and titled
`Cancelling…` while the merged state is `.cancelling`; the row's hover Cancel
and the context-menu item are hidden for cancelling and terminal rows. The
`scan.cancel` reply (`cancelling`) is still applied through `applyStatus` so
the switch is immediate; the poll then carries the job to `cancelled`.

#### D3. Selection follows the list (F3, C8)

`ScanSurfaceModel.applyList` ends with: if `selectedJob == nil` and `jobs` is
non-empty, `selectedJob = jobs[0].job` (the newest); if `selectedJob` names a
job the list no longer carries and this app is not waiting on it
(`locallyStarted`), `selectedJob = jobs.first?.job`. An existing selection is
never replaced by a newer job (the web store has the same rule; the TUI
lands a started job at the cursor only for jobs it started). `applyStart`
keeps selecting the job this app started.

#### D4. Stopped reasons and crawl errors as words, raw token in the data face (C6)

A pure sentence model lives in `ScanSurface.swift` and is shared by PR 1 (in
the existing *Stopped* section) and PR 2 (in the end-state card):

```swift
public enum ScanEndText {
    /// The one sentence for a terminal job; nil while the job is live.
    public static func sentence(_ facts: ScanJobFacts) -> String?
    /// The stopped-reason sentence; nil for a reason the state sentence already says.
    public static func stoppedReason(_ reason: ScanStoppedReason, state: ScanJobState,
                                     probesBudget: Int, error: String?) -> String?
    /// "The crawl fetched 1 page and hit 1 error"; nil when crawl.errors == 0.
    public static func crawlTrouble(_ crawl: ScanCrawlCounters) -> String?
    /// The words for a `crawl.last_error` token.
    public static func crawlErrorWords(_ kind: ScanCrawlErrorKind) -> String
    /// "stopped_reason: errors" — the raw token, for the data-face line.
    public static func rawReasonLine(_ reason: ScanStoppedReason) -> String
}
```

The strings, identical on all three surfaces (web `helpers.ts`, TUI
`scan/jobs.rs`); `<elapsed>` is `ScanFormat.elapsed`, numbers use grouping
separators (D11):

| Input | Sentence |
| --- | --- |
| `done`, no reason | `Done in 1:09 · 1,020 points · 6,468 checks.` |
| `cancelled` | `Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays.` |
| `failed` | `Failed after 0:12.` (the `error` text follows on its own line, verbatim) |
| reason `budget` | `Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further.` |
| reason `time` | `Stopped early: the time budget ran out.` |
| reason `cancelled` | nil when `state == cancelled` (the state sentence says it); else `Stopped early: the job was cancelled.` |
| reason `session_lost` | `Stopped early: the session was lost and the profile says stop when that happens.` |
| reason `errors` | `Stopped early: too many errors from the target.` (the check-error attention line of D9 follows) |
| reason `policy` | `Stopped early: the agent policy changed to paused or read-only.` |
| reason `guard_refused` | `Stopped early: the L4 guard refused a target mid-run.` |
| reason `failed` | nil when `error` is present (the error is shown); else `Stopped early: an error ended the job.` |
| reason `.other(raw)` | `Stopped early for a reason this app does not know.` (the raw line shows the token) |
| crawl `errors > 0` | `The crawl fetched 1 page and hit 1 error` / `fetched 46 pages and hit 2 errors` |
| `last_error` words | `connect_refused` → `the target refused the connection` · `tls` → `TLS handshake failed` · `timeout` → `the target did not answer in time` · `h2_not_negotiated` → `the target does not speak HTTP/2` · `transport`, `other`, unknown → `the connection failed` |
| raw line | `stopped_reason: errors` · `crawl.last_error: connect_refused` |

In PR 1 the existing *Stopped* section renders `stoppedReason(...)` as its
text (UI md, `Tok.Ink.secondary`), then `crawlTrouble` + " — " +
`crawlErrorWords` when the crawl had errors, then the error verbatim in
`Tok.Status.serverError`, and last the raw lines in the data face at
`Tok.Typography.Size.xs`, `Tok.Ink.tertiary`, selectable. The raw token never
appears anywhere else (glossary rule; coordinator ruling 3). Singulars:
`1 page`, `1 error`, `1 check`, `1 point` via `ScanFormat.plural`.

#### D5. Rows are accessibility elements (F4, C10)

Each `ScanJobRow` is one accessibility element: `.accessibilityElement(children: .ignore)`
stays, plus `.accessibilityAddTraits(.isButton)`, `.accessibilityAddTraits(.isSelected)`
when selected, `.accessibilityAction(named: "Select")` (the default action)
that selects the job, and `.accessibilityIdentifier("scan-job-\(id)")`. The
label is `ScanFormat.jobAccessibilityLabel` (PR 2 rewrites its words, D15).
The list container keeps `.accessibilityElement(children: .contain)` and
`.accessibilityLabel("Jobs")`. If the dump still lists no row element after
these modifiers, the builder replaces `ScrollView` + `LazyVStack` with a
`List` whose rows carry the same modifiers; the acceptance criterion is the
dump, not the modifier **(Architect's call on the first mechanism)**.

#### D6. Link facts and the verb gate (F5, C12)

`ScanSurfaceModel` gains two facts and one derived value:

- `jobsLoadedAt: Int?` (epoch ms), set by `applyList(_:now:)` from its new
  `now` parameter; `ScanPanelState.refreshList` passes the wall clock in
  epoch milliseconds, tests pass a literal.
- `listFailedAt: Int?`, set by `ScanPanelState.refreshList`'s failure path
  (new `noteListFailure(now:)`), cleared by `applyList`. A failed *cancel* or
  *status* read still sets `jobsError` but not `listFailedAt`.

```swift
public struct ScanJobsLink: Equatable, Sendable {
    public enum Kind: Equatable, Sendable { case live, reconnecting, disconnected, unanswered }
    public var kind: Kind
    public var valuesAgeMs: Int?      // now - jobsLoadedAt, nil before the first list
    public var bannerText: String?    // nil while live (D16 renders it)
    public var verbsEnabled: Bool     // kind == .live
    public static func make(bus: BusState, listFailedAt: Int?, jobsLoadedAt: Int?, now: Int) -> ScanJobsLink
}
```

Rules: `bus` is `.connecting` → `.reconnecting`; `.disconnected` or
`.failed` → `.disconnected`; `.connected` with `listFailedAt != nil` →
`.unanswered`; else `.live`. `ScanPanelState.link` computes it from
`session.bus` each render. In PR 1 the gate alone ships: Cancel Scan, the
hover Cancel and the context-menu Cancel are disabled while
`!link.verbsEnabled`; the existing inline list error keeps its text and gains
the last-good clause: `Unable to list jobs: <core text>. Showing values from
0:42 ago; retrying every 2 s.` (`ScanFormat.listErrorText(core:ageMs:)`).
`BusState` already lives in the Kit (`ConnectionSummary.swift`), so the
function is unit-testable.

Reason: C12 showed Cancel enabled against a frozen core for 30 s with no
word about the values' age.

#### D7. What PR 1 does not touch

PR 1 keeps `ScanJobRow`'s two lines and severity bar, the detail's sections,
the probe rule and every existing string except the *Stopped* section's. It
adds no motion, no new layout and no Scan Again. It is reviewable as a
behaviour fix plus a decoder extension, and it is the base PR 2 is cut from.

### Part B: PR 2, the redesign (mac)

#### D8. The derived progress model

A pure Kit type computed from `ScanJobFacts`:

```swift
public struct ScanJobProgress: Equatable, Sendable {
    public enum Ring: Equatable, Sendable { case none, indeterminate, determinate(Double), finished(Double?) }
    public var ring: Ring
    public var fraction: Double?       // the determinate value, 0…1; nil otherwise
    public var percentText: String?    // "50 %"; nil when fraction is nil
    public var phaseLine: String       // the card's progress line
    public var nowLine: String?        // "Now: xss-reflected and 3 more"; nil when checks.running is empty
    public var helpText: String        // "3,236 of 6,468 checks (derived from the engine's counters)"
    public init(_ facts: ScanJobFacts)
}
```

Rules (the UX section's, made total):

| state / phase | ring | fraction | phaseLine |
| --- | --- | --- | --- |
| `queued` (any phase) | `.indeterminate` | nil | `Waiting for the engine to start this job.` |
| `running` / `crawling` | `pages + queued > 0` → `.determinate(pages / (pages + queued))`, else `.indeterminate` | as ring | `46 pages, 12 queued` (`1 page, 0 queued`) |
| `running` / `passive` | `.indeterminate` | nil | `Passive checks over captured traffic` |
| `running` / `auditing` | `scheduled > 0` → `.determinate(done / scheduled)`, else `.indeterminate` | as ring | `3,236 of 6,468 checks` / `Scheduling checks` |
| `running` / `reporting` | `.determinate(1)` | 1 | `Writing results` |
| `cancelling` (any phase) | the running rule for its phase, frozen by the view | as ring | the running line |
| `running` without a status yet | `.indeterminate` | nil | the phase word |
| terminal | `.finished(f)` where `f` is the auditing rule over the final counters (`scheduled > 0`), else the crawling rule, else nil | nil | `""` (the card is the end sentence, D9) |

`percentText` is `Int((fraction * 100).rounded(.down))` + ` %` with a
non-breaking space; it never reads `100 %` for a running job unless
`done == scheduled`. `nowLine` is `Now: <first id>` for one running check,
`Now: <first id> and <n> more` for more (`checks.running` is already capped at
8 by the engine). The fraction may fall when `scheduled` grows; the model
reports the new value and D12's motion eases to it.

Web: `jobProgress(j: JobSummary | JobStatus): JobProgress` in `helpers.ts`,
same fields (`ring: 'none' | 'indeterminate' | { determinate: number } | { finished: number | null }`,
`fraction`, `percentText`, `phaseLine`, `nowLine`, `helpText`). TUI:
`pub fn progress(summary: &JobSummary, full: Option<&JobStatus>) -> JobProgress`
in `scan/jobs.rs` with `ring: Ring`, `fraction: Option<f64>`,
`phase_line: String`, `now_line: Option<String>`, and
`pub fn progress_bar(fraction: Option<f64>, cells: usize) -> String` reusing
`BAR_FILLED` / `BAR_EMPTY` (an indeterminate bar is all `BAR_EMPTY`; a
finished bar keeps its fill). The three implementations are pinned by the
same table of inputs and outputs (D20).

#### D9. The end-state card and the attention lines

`ScanEndText` (D4) is the sentence model; PR 2 adds the attention and notice
lists:

```swift
public struct ScanAttentionLine: Equatable, Sendable {
    public var text: String                   // "7 checks could not run"
    public var samples: [ScanCheckErrorSample] // the disclosure's rows; empty for none
}
public enum ScanEndText {
    public static func attention(_ facts: ScanJobFacts) -> [ScanAttentionLine]
    public static func notices(_ status: ScanJobStatus, launchNotices: [String]) -> [String]
}
```

`attention` returns, in this order and only when non-zero: `<n> checks could
not run` with `errorSamples`; `<n> checks were skipped` with
`skippedSamples`; the crawl trouble sentence with no samples, shown as
`The crawl fetched 1 page and hit 1 error — the target refused the connection`
when `lastError` is set. `notices` is today's `clampedLines` plus
`skippedLaneText` rows, under one **Notices** title. Both render in every
state (a running job with check errors already shows them).

The inspector's summary card swaps once per job from the progress card to
the end-state card (D11, D12): the sentence (UI md, `Tok.Ink.primary`), the
stopped-reason sentence beneath (UI md, `Tok.Ink.secondary`), the error
verbatim (data md, `Tok.Status.serverError`, selectable, wrapping), then the
raw-token line (data xs, `Tok.Ink.tertiary`). No buttons live in the card:
the verbs are the header's (D11) **(Architect's call: the UX table lists
Scan Again · Show Issues · Show Site Map beside the sentence; putting them in
the header keeps one stable home for every verb across live and finished
jobs and avoids the same button twice on one pane)**.

#### D10. The row

`ScanJobRow` becomes: a 16 pt leading slot, two text lines, a 4 pt progress
rule at the bottom edge of the text block, and the row separator.

- **Leading slot** (16 pt, always present so text aligns): the ring from
  `ScanJobProgress.ring`: `.determinate` → a `Circle` trimmed to `fraction`,
  stroke 2 pt (builder may pick 1.5 to 2.5) in `Tok.Ink.primary` over a full
  circle in `Tok.Ground.raised`; `.indeterminate` → `ProgressView()
  .controlSize(.small)` (the system spinner honours Reduce Motion);
  `.none` and `.finished` → empty slot (the state word carries the state).
- **Line 1** (UI md 500, `Tok.Ink.primary`): `<Phase or state word> ·
  <profile>` (`ScanFormat.jobRowLine1` rewritten; `—` for a missing profile
  as today). Trailing, right-aligned in the same line, the **elapsed** (data
  sm, tabular, `Tok.Ink.secondary`); on hover of a live row the elapsed slot
  shows the `FlatButton("Cancel")` instead, so nothing shifts (the slot is
  `Tok.Size.control` high as today).
- **Line 2** (data sm, `Tok.Ink.secondary`): the target `host[:port]`
  list, middle-truncated, full list in `.help`. Trailing, right-aligned: the
  issues in words from `ScanFormat.severityWords(by:running:)`: `4 low` /
  `1 high, 3 low` with each count-word in its severity ink
  (`Tok.Severity.<level>.fg`), or `no issues yet` (live) / `no issues`
  (terminal) in `Tok.Ink.tertiary`. No severity bar (C4).
- **Progress rule** (4 pt): a `ScanProgressRule(fraction:)` in
  `Tok.Ink.primary` on `Tok.Ground.raised`, drawn only while the ring is
  `.determinate`; absent (no track) otherwise.
- Backgrounds: selected `Tok.Ground.active`, hover `Tok.Ground.hover`, the
  separator `Rule(color: Tok.Line.rule)`; padding `Space.md` horizontal,
  `Space.sm` vertical; row pitch is whatever two lines plus the rule give on
  the 4 pt grid (builder's call).
- **Caption** above the rows when `jobs.count > 1`: `4 jobs · 1 running`
  (`ScanFormat.jobsCaption(total:running:)`; `· 2 running`; no running clause
  when none), UI xs caps tracked (`ScanSectionTitle`), `Tok.Ink.secondary`.
- **Context menu**: Cancel Scan (live, not cancelling), Scan Again
  (terminal), Show Issues, Show Site Map, divider, Copy Job ID.
- The `ScanSeverityBar` view and `ScanSurfaceModel.severityBarSegments`
  leave the Jobs view; they are deleted when no other view uses them (the
  builder greps), otherwise they stay untouched.

#### D11. The inspector

Top to bottom, on `Tok.Ground.surface`, content padded `Space.md`:

1. **Header** (`Tok.Size.inspectorHeader`, 40 pt): the heading
   `<Phase or state word> <hosts>` (`ScanFormat.jobHeading(facts)`; two
   hosts join with `, `; three or more read `<first> and 2 more` with the
   full list in `.help`), UI xl 500, `Tok.Ink.primary`, one line,
   `.accessibilityAddTraits(.isHeader)`. Right: the **verb slot** holding
   `PrimaryButton("Cancel Scan")` while live (disabled + `Cancelling…` while
   cancelling, D2) or `PrimaryButton("Scan Again")` when terminal (D13);
   then `FlatButton("Show Issues")`, `FlatButton("Show Site Map")`. The
   whole slot is disabled while `!link.verbsEnabled` (D6, D16).
2. **Subtitle** line (UI sm, `Tok.Ink.secondary`):
   `ScanFormat.jobSubtitle(facts, now:)`: `standard · started 11:32 by this
   app · 1:04` while live; `standard · started 11:32 by this app · finished
   11:33 · 1:09` when terminal. Started-by words: `client_label == "aitm-mac"`
   → `this app`; `frontend == "cli"` → `the CLI`; `frontend == "mcp"` → `an
   agent`; `frontend == "operator"` with another label → the label (bounded
   to 40 characters, control characters stripped); otherwise `the operator`.
   Clock text is the local time, hours and minutes, via
   `ScanFormat.clock(ms:timeZone:)` (tests pass a fixed zone).
3. **Summary card**: `Tok.Ground.raised`, `Tok.Radius.panel` (8 pt), no
   shadow, padded `Space.md`. Live: the percent (data xl 500, tabular,
   `Tok.Ink.primary`; absent for an indeterminate phase) beside the
   `phaseLine` (UI md, `Tok.Ink.primary`), the 4 pt `ScanProgressRule` (or
   the small `ProgressView` when indeterminate), the `nowLine` (data sm,
   `Tok.Ink.secondary`, absent when nil), then the three tiles. Terminal: the
   end-state card (D9) and, beneath a `Rule`, the same three tiles with their
   final values. The card's `.help` is `helpText`.
4. **Tiles** (an `HStack` or `Grid`, builder's call), each a `ScanStat`-style
   label over value: `Probes` → `287 of 2,000` (data base 500, tabular) with
   a 2 pt secondary rule beneath in `Tok.Ink.tertiary` on `Tok.Ground.surface`
   filled `sent / budget` (the probe budget is the *secondary* bar;
   coordinator ruling 3); `Points` → `97 of 1,020 audited`; `Issues` → `4`
   with `4 low` beneath in severity ink, or `no issues yet` / `no issues`.
   Tile help: Issues `4 issues: 1 high, 3 low`; Probes `287 of 2,000 probes
   sent (the probe budget, not progress)`.
5. **Attention lines** (D9), each a `DisclosureGroup` whose label is the
   text (UI md, `Tok.Ink.primary`) and whose content lists `(check, detail)`
   samples in data sm, `Tok.Ink.secondary`, selectable; a line with no
   samples is plain text.
6. **Notices** (D9) under a `ScanSectionTitle("Notices")`, only when non-empty.
7. **Details** as `DisclosureGroup`s, collapsed by default (builder may open
   the first): **Crawl** (pages, queued, depth, forms submitted, forms not
   submitted, errors), **Points** (found, waiting for audit, audited, and the
   skips in words: `722 skipped as repetitive`, `6 skipped by rule`, `0
   skipped at the per-request cap`), **Checks** (scheduled, done, errors,
   skipped), **Probes** (sent, budget, errors, timeouts, rate waits, by
   lane), **Lanes** (requested, run, skipped with reasons), **Session** (only
   when `status.session != nil`: reused, lost, canary, browser partial),
   **L4** (only when present). Every label is sentence case; every number is
   tabular with grouping separators. `Points ▸ Queued` is renamed `waiting
   for audit` and `Skipped frequent` becomes `skipped as repetitive` (C9).

Tokens, exhaustively: grounds `Tok.Ground.surface / raised / active / hover`;
lines `Tok.Line.rule`; inks `Tok.Ink.primary / secondary / tertiary`; error
`Tok.Status.serverError`; severity `Tok.Severity.<level>.fg`; faces
`Tok.Face.ui(...)` / `Tok.Face.data(...)` at `Tok.Typography.Size.xs / sm /
md / base / xl` and weights `.medium` / `.regular`; radius
`Tok.Radius.panel`; sizes `Tok.Size.inspectorHeader`, `Tok.Size.control`;
spacing `Space.*`. No literal colour, radius or duration in
`ScanPanel+Jobs.swift`; `grid-lint` and a grep for `Color(` / `.cornerRadius(`
/ `.animation(.easeOut` in that file are the check.

#### D12. Motion

`ScanMotion` lives in the app target (`apps/mac/Sources/Aitmproxy/UI/ScanMotion.swift`,
beside `Tokens.swift`), because `Tok.*` is app-only and the Kit has no
SwiftUI; every constant is a `Tok.Motion` token, so the file carries no
numeric literal:

```swift
enum ScanMotion {
    static let counter = Tok.Motion.counter        // 150 ms, digit ticks (new token)
    static let progress = Tok.Motion.progress      // 250 ms, rule / ring value (new token)
    static let stateWord = Tok.Motion.popover      // 160 ms, heading word crossfade
    static let cardSwap = Tok.Motion.sheet         // 220 ms, progress card → end sentence
    static let rowArrive = Tok.Motion.popover      // 160 ms, new row opacity
    static let hoverReveal = Tok.Motion.hover      // 100 ms, the row's Cancel
    static func ease(_ duration: Double) -> Animation { Tok.Motion.easeOut(duration) }
}
```

`tokens.json` gains two durations, `motion.counter` (`150ms`, "Live counter
digit ticks; opacity/translate of the digits only") and `motion.progress`
(`250ms`, "A progress rule or ring easing to a new value; never snaps"), and
the three generators (`apps/mac/tools/gen-tokens.swift`,
`apps/web/scripts/gen-tokens.mjs`, `crates/aitm-tui/build.rs`) are re-run so
`Tok.Motion.counter` / `Tok.Motion.progress`, `--motion-counter` /
`--motion-progress` exist **(Architect's call: the UX table names 150 and 250 ms, which
are not tokens today; adding them is the documented way to get a new token,
and it keeps "views carry no literals" true)**.

| Change | Mechanism (mac) | Reduce Motion |
| --- | --- | --- |
| Counter ticks | `.contentTransition(.numericText())` on each number `Text`, under `.animation(Tok.Motion.easeOut(ScanMotion.counter), value: <the number>)` | `.contentTransition(.identity)` |
| Progress rule / ring | the rule's width and the ring's `trim(to:)` under `.animation(Tok.Motion.easeOut(ScanMotion.progress), value: fraction)`; the view never clamps a falling value to the old one | `.animation(nil)` |
| State word | `.contentTransition(.opacity)` on the heading and line-1 `Text`, `.animation(Tok.Motion.easeOut(ScanMotion.stateWord), value: stateWord)` | same (opacity only) |
| Card swap | `.transition(.opacity.combined(with: .offset(y: 2)))` on the two card bodies inside a `ZStack`, `withAnimation(Tok.Motion.easeOut(ScanMotion.cardSwap))` when `facts.summary.state.isTerminal` flips | `.transition(.opacity)` |
| New row | `.transition(.opacity)` with `.animation(Tok.Motion.easeOut(ScanMotion.rowArrive), value: jobs.map(\.job))` on the `ForEach`; no travel | same |
| Hover Cancel | `.opacity(hovered ? 1 : 0)` with `.animation(Tok.Motion.easeOut(ScanMotion.hoverReveal), value: hovered)` in the fixed slot | same |
| Button press | the existing `FlatButton` / `PrimaryButton` press style | existing |
| Indeterminate | `ProgressView().controlSize(.small)` | system |
| Keyboard selection, tab switch | no animation: `moveSelection` is called inside `withTransaction(Transaction(animation: nil))` | none |

`@Environment(\.accessibilityReduceMotion) private var reduceMotion` is read
in `ScanJobsTab` and passed down; each row of the table picks its right-hand
column when it is true. No colour animates; nothing pulses; the inspector has
no entrance. Web: CSS `transition` on `transform` / `opacity` / the rule's
`width` with `var(--motion-ease-out)` and the new `--motion-counter` /
`--motion-progress`; the existing global `prefers-reduced-motion` rule in
`base.css` already zeroes durations. TUI: none.

#### D13. Scan Again (decided; coordinator ruling 1)

Client-side only. `ScanSurfaceModel` gains:

```swift
/// nil when Scan Again may be sent; else why not (the same gate as Start Scan).
public func scanAgainRefusal(for job: String, scopeHosts: [String], tools: [ToolDescriptor]) -> String?
/// scan.start { profile_name, overrides: { target: { origins } } } from the job's status.
public func scanAgainArguments(for job: String) -> (tool: String, args: [String: JSONValue])?
/// "Start a new job with profile standard against 127.0.0.1:8117"
public static func scanAgainHelp(_ status: ScanJobStatus) -> String
```

- **Arguments**: `profile_name: status.profileName`, `overrides: { target:
  { origins: status.targets } }`. The engine resolves `profile_name` then
  merges the override (`Profiles::resolve`), so a builtin or saved profile
  runs again against the same origins. A job launched from an *edited*
  builtin cannot be reproduced exactly (the status carries no profile body);
  the help text names the profile so the operator knows what will run.
- **Gate**: identical to Start Scan. `scanAgainRefusal` returns `"scan.start
  is not on this bus"` when the tool is absent; `ScanFormat.outOfScopeText`
  for the first target host not in `scopeHosts`; `scanL4Hint` when
  `status.lanes.requested` has an L4 lane and `l4InjectScopeKnown != true`;
  `"Select a finished job."` when the status is missing or non-terminal.
  The button is additionally disabled while `!link.verbsEnabled`,
  `launchInFlight`, or `confirm != nil`; its `.help` is the refusal when
  there is one, else `scanAgainHelp`.
- **Send path**: `ScanPanelState.scanAgain(job:)` reuses `send(tool:args:)`,
  so a `needs_confirmation` answer opens the existing confirm sheet, the
  confirmed call re-sends the identical arguments plus `_confirm`, and a
  `ScanStartResult` runs through `applyStart` (the new job goes first, is
  selected, Jobs tab stays). `ScanConfirm` gains `summaryLine: String`
  (`Profile standard · 127.0.0.1:8117`, derived from `arguments`: the
  inline `profile.name` + its `target.origins`, or `profile_name` + the
  override's origins) and `ScanConfirmSheet` shows it under the title for
  Start Scan and Scan Again alike.
- **Refusal path**: a thrown error (`invalid_profile`, `busy`,
  `out_of_scope`, `refused_agent`, `lane_unavailable`, …) is shown inline
  where the start was pressed: `ScanSurfaceModel.scanAgainError: ScanLaunchError?`
  rendered under the header as `Unable to scan again: <display>` (UI sm,
  `Tok.Status.serverError`, selectable), cleared by the next successful
  start, by selecting another job, or by Escape. The Profiles footer's
  `statusLine` is not touched (that is Start Scan's home).
- **Homes**: the header verb slot (terminal jobs) and the row context menu
  (terminal rows). No keyboard shortcut and no menu-bar item in this spec
  (the menu bar's Start Scan… ⌃⌘⏎ remains the way to start from a profile)
  **(Architect's call: an unbound verb is better than a shortcut that
  collides with the command map owned by another spec)**.

#### D14. Accessibility

- **Rows**: one element each (D5); label `ScanFormat.jobAccessibilityLabel`
  rewritten to the sentence `Auditing, standard, 127.0.0.1:8117, 50 percent,
  3,236 of 6,468 checks, 4 issues: 4 low, 1 minute 4 seconds.` (percent and
  the checks clause only when the progress is determinate; `no issues yet`
  / `no issues`; `ScanFormat.elapsedWords(ms:)` → `1 minute 4 seconds`,
  `42 seconds`, `1 hour 2 minutes 3 seconds`). Trait `.isButton`,
  `.isSelected` when selected; the ring is `.accessibilityHidden(true)`.
- **Inspector**: the heading has `.isHeader`; the progress rule exposes
  `.accessibilityLabel("Progress")` and `.accessibilityValue("50 percent")`
  (hidden when indeterminate); tiles are `.accessibilityElement(children:
  .combine)` reading label then value (`Probes, 287 of 2,000`); the verb
  buttons carry their help text as `.accessibilityHint`; the end-state
  card's sentence is one static text; disclosure groups are system
  `DisclosureGroup`s (expanded/collapsed is announced by the system).
- **Announcement**: when the selected job's merged state goes from
  non-terminal to terminal, `ScanPanelState` posts one
  `NSAccessibility.post(element: NSApp, notification: .announcementRequested,
  userInfo: [.announcement: text, .priority: NSAccessibilityPriorityLevel.medium.rawValue])`
  with `text = ScanFormat.endAnnouncement(facts)`: `Scan of 127.0.0.1:8117
  done: 4 issues.` / `… cancelled: 4 issues.` / `… failed.` / `… done: no
  issues.` Once per job (a `Set<String>` of announced ids).
- **Keyboard**: Tab order Scan tabs → list → header verbs → disclosures.
  In the list: ↑↓ move the selection (no animation), Return or → calls
  `inspectorFocus = true` (`@FocusState` on the header's first enabled
  button), Escape from the inspector returns focus to the list, ⌥⌘. is
  Cancel Scan (existing). The context menu is reachable with the keyboard
  through the system's menu key / ⌃-click as today.
- Text is never below `Tok.Typography.Size.xs` (11 pt); every colour pair is
  a token pair, so Increase Contrast keeps ≥ 4.5:1.

#### D15. Bus-disconnected banner (F5, C12)

`ScanJobsLink.bannerText` (D6) is rendered in PR 2 above the caption as an
inline banner (`ScanInlineError`'s shape, but in `Tok.Ink.secondary` on
`Tok.Ground.raised`, not the error ink: nothing failed, the bus is away):

| kind | text |
| --- | --- |
| `.reconnecting` | `Bus disconnected · showing values from 0:42 ago · reconnecting…` |
| `.disconnected` | `Bus disconnected · showing values from 0:42 ago · Proxy ▸ Reconnect Bus (⌃⌘R) to retry` |
| `.unanswered` | `The core is not answering · showing values from 0:42 ago · retrying every 2 s` |

The age clause is `ScanFormat.elapsed(ms: valuesAgeMs)` and is omitted while
`jobsLoadedAt` is nil. The `now` that drives it is the poll tick's clock
(the view has no timer). Rows keep their last values; the hover Cancel is
hidden; the header's verb slot, Scan Again and the context-menu Cancel are
disabled (D6). The inline list error (D11) keeps rendering when
`jobsError != nil`, under the banner.

#### D16. Performance and render budget

The detail re-renders when `facts(for:)` changes: once per status beat (1 s)
for a live selected job, once per list beat (2 s) for the rows. No view owns
a `Timer`; the banner age and the subtitle's elapsed come from the facts and
the poll tick's `now`. `ScanJobProgress` and `ScanEndText` are value
computations on a struct with at most a few hundred bytes; the builder does
not memoise them.

#### D17. Words added by this spec (D12 of the mac spec extended)

Every string lives in `ScanSurface.swift` (`ScanFormat` or `ScanEndText`).
New buttons: `Scan Again`, `Cancelling…`. New sentences: D4's table, D8's
phase lines, D9's attention lines, D15's banners, the help strings of the UX
section verbatim, `Unable to scan again: <reason>`, `Select a finished job.`,
`<n> jobs · <n> running`, `started <h:mm> by <who>`, `finished <h:mm>`,
`waiting for audit`, `skipped as repetitive`, `skipped by rule`, `skipped at
the per-request cap`, `forms not submitted`. Glossary terms only; `stop`,
`abort`, `finding`, `run`, `task` do not appear (a grep over
`ScanSurface.swift` strings is the check).

### Part C: parity

#### D18. Web (`apps/web/src/panels/scanner/`)

Two steps, mirroring the mac PRs.

**W1, correctness.** `model.ts`: `CheckCounters` gains `errors`,
`error_samples: CheckErrorSample[]`, `skipped`, `skipped_samples`;
`CrawlCounters` gains `last_error: CrawlErrorKind | null`; new
`CRAWL_ERROR_KINDS` token list; `parseJobStatus` reads them with 0 / `[]` /
`null` defaults. `live.ts`: `refreshJobs` applies the re-read rule: for every
listed job where `needsStatusRead(summary, status(job))` (new in
`helpers.ts`: `stored === null || (isTerminal(summary.state) && !isTerminal(stored.state))`)
it calls `refreshStatus(job)` once (the web's C1/C2 shape: without a push
line the 1 Hz poll stops the moment the list turns terminal, leaving the
held status at its last running read; with push the terminal line already
triggers a read, so this is the fallback). `helpers.ts`: `stoppedReasonText`
is re-pointed to D4's sentences (the current `stopped: probe budget reached`
strings go), `crawlTroubleText`, `crawlErrorWords`, `endSentence`,
`rawReasonLine` are added with the mac strings byte for byte; `stateWords`
returns the glossary words (`Auditing`, `Done`), capitalised, with the
phase word alone while running. `JobsView.tsx` renders the Overview's
`stopped` fact with the sentence and a `data-field="stopped-raw"` mono line
`stopped_reason: errors`; Cancel is disabled while the merged state is
`cancelling` (`jobOf` already merges held status over the summary; it gains
the terminal-wins rule of D2).

**W2, redesign.** `JobsView.tsx` row = ring (`<svg>` circle with
`stroke-dasharray` driven by `fraction`, `role="presentation"`) + line 1
`<Phase> · <profile>` with elapsed trailing + line 2 host with the severity
words trailing (`.sevWord[data-severity]` coloured by
`--color-severity-<level>-fg`) + a 4 px rule (`width: calc(fraction *
100%)`, `transition: width var(--motion-progress) var(--motion-ease-out)`).
The detail: heading `<h2>` `<Phase> <host>`, the subtitle, the summary card
(`background: var(--color-ground-raised); border-radius: var(--radius-panel)`)
with `percentText` in `font: var(--font-weight-medium) var(--font-size-xl)
var(--font-data)` and `font-variant-numeric: tabular-nums`, the rule, the
Now line, the three tiles, attention lines as `<details>`, Notices, then
the detail sections as `<details>` collapsed. End state: the sentence block
replaces the card body (`transition: opacity var(--motion-sheet)`), the
error in `color: var(--color-status-server-error)`, the raw line in
`--font-size-xs` `--color-text-tertiary`. `JobStrip.tsx` shows the ring,
`stateWords`, `percentText`, `phaseLine`, the `nowLine`, the severity words
and elapsed; its Cancel follows the same gate. Scan Again: `store.ts` gains
`scanAgain(job)` building `{ profile_name, overrides: { target: { origins } } }`
and reusing the launch path's confirm handling (`launch.ts`'s
`needs_confirmation` branch); the button sits beside Cancel in the detail
head, `aria-label="Scan again <job>"`, `title` = the help text; a refusal is
reported through `report('launch', …)` beside the head. The list head keeps
`Jobs · 4` and gains `· 1 running`. Rows stay `role="option"` with
`aria-label` = the sentence of D14; the detail region gets
`aria-live="polite"` on the end sentence only (one announcement). The
existing `ReconnectNote` becomes the banner text of D15 with the age from
`jobsLoadedAt`.

#### D19. TUI (`crates/aitm-tui/src/scan/jobs.rs`, `ui/scan/jobs.rs`)

**T1, correctness.** `JobsState::fold_list` returns as follow-ups, besides
the jobs with no `full` entry, every listed job whose summary is terminal
while `full[job].state` is not (the TUI's C1/C2 shape: `live()` stops polling
a job the moment the list calls it terminal, so `full` keeps the last running
read and the Detail pane's checks line is stale). `stopped_text` is
re-worded to D4's sentences; `detail_lines` adds a `stopped_reason: errors`
raw line (label `wire`, tertiary) under the `stopped` line, a `crawl` line
clause `· errors 1 (the target refused the connection)` when `errors > 0`,
and a `checks` clause `· errors 7 · skipped 3` when non-zero; `bound_status`
cuts each `error_samples[].detail` / `skipped_samples[].detail` to
`DETAIL_VALUE_MAX` and both lists to `DETAIL_LIST_MAX` (hostile-core bounds,
D6 of the TUI spec). `scan_cancel` stays as is (the engine's cancel is
idempotent; `already <state>` covers terminal).

**T2, redesign.** The row's probe bar becomes the progress bar:
`JobRow.probe_fill` is replaced by `progress_fill: usize` from
`progress(summary, full)` and the `probes` column reads `checks done/total`
while auditing (`pages/known` while crawling, `...` for indeterminate); a
new `budget` column `sent/budget` without a bar keeps the probe budget
visible as a number only. The header reads `job  profile  targets  state
progress  budget  points  issues  el.`. The severity bar stays in the TUI
row (the terminal has no hue budget problem: it is a 6-cell glyph run, not a
full-width bar, so it cannot read as progress). The Detail pane's first
lines become: the end sentence (terminal) or the `phase_line` with the
percent (live), then `now <ids>` when any, then the attention lines (`7
checks could not run`, with up to `DETAIL_LIST_MAX` samples as `check:
detail` lines), then the existing label-value lines. `state_text` keeps the
lowercase wire word (the TUI's typographic rule is bold/dim, not case;
Architect's call) but `state_phase_text` reads the short phase word alone
while `running` (`auditing`), the state word alone for `queued`,
`cancelling` and the terminal states, matching the other surfaces' "phase
word while running, state word otherwise". Hue only
through `Theme::severity` and the existing `state_style`. Omitted for width:
the subtitle (started by, started at, finished at stay as detail lines), the
tiles (the counters are detail lines), the ring (the bar is the ring), the
banner (the Jobs error banner already carries the last error; it gains the
age clause `showing values from 42s ago`), Scan Again (no key is added; the
`s` start key from Profiles is the way; a follow-up may bind `a`).

### Part D: testing

#### D20. Tests per surface and the live proof

- **mac, unit** (`apps/mac/Tests/AitmproxyKitTests/`): `ScanModelTests`
  gains the decoder cases of D1 against hand-written JSON (the fixture pack
  does not carry the additive fields; a `scan.status.json` sibling with them
  is added to the test target, not to the fixture crate). `ScanSurfaceTests`
  gains: `needsStatusRead`, `ScanJobFacts.make`, `applyList` selection
  (D3), `ScanJobsLink.make`, `ScanEndText.*`, `ScanJobProgress`,
  `ScanFormat.jobRowLine1/2`, `jobHeading`, `jobSubtitle`,
  `jobAccessibilityLabel`, `elapsedWords`, `severityWords`, `jobsCaption`,
  `scanAgainArguments`, `scanAgainRefusal`, `scanAgainHelp`,
  `ScanConfirm.summaryLine`, `endAnnouncement`. Each pins literal strings
  from the tables above. `swift test --scratch-path
  ~/Library/Developer/Aitmproxy/test-build` in the Terminal.
- **mac, gate**: `tools/grid-lint.sh`, the three tripwires, `swift build`
  warning-free, and the no-literal grep of D11.
- **web, unit** (vitest): `helpers.test.ts` pins `jobProgress`,
  `endSentence`, `stoppedReasonText`, `crawlTroubleText`, `crawlErrorWords`,
  `stateWords`, `needsStatusRead` with the same inputs and outputs as the
  mac tests; `live.test.ts` pins the W1 re-read (a list that turns a job
  terminal while the held status is running issues one `scan.status`);
  `JobsView.test.tsx` pins the row text, the stopped sentence plus raw line,
  the disabled Cancel while cancelling, Scan Again's arguments; `styles.test.ts`
  pins that `scanner.module.css` uses only `var(--…)` colours, radii and
  durations.
- **TUI, unit** (`cargo test -p aitm-tui`): `scan/jobs.rs` tests pin
  `progress`, `progress_bar`, `end_sentence`, `stopped_text`,
  `crawl_error_words`, `fold_list` follow-ups for a terminal-vs-stale job,
  `bound_status` on the sample lists; `ui/scan/jobs.rs` pins the header and
  a row's cells. The Rust gate (`cargo fmt --check && cargo clippy
  --all-targets -- -D warnings && cargo test`) in the Terminal.
- **Parity pin**: one table of inputs and expected strings is written in
  the plan and copied into all three test suites (the Swift, TypeScript and
  Rust tests assert the identical literals for: `done` 1:09 / 1,020 / 6,468;
  `cancelled` 1:55 with 3,236 of 6,468; `budget` 2,000; `errors` with 7
  check errors; `connect_refused` crawl with 1 page / 1 error; progress
  3,236 / 6,468 → `50 %` fraction 0.5003; crawling 46 / 12 → 0.7931).
- **Live proof** (the evidence rule; mac first, then web and TUI with the
  same core): build the core from the branch, start
  `aitm-testtarget-serve --latency-ms 400` and a second target that is not
  listening (dead port) for the connect-refused case; `DEV_TAG=jobsux2
  CORE_DIR=<dir> tools/snap-dev.sh`; add the targets to scope; capture
  `swift tools/winshot.swift <pid> …` plus the AX dump
  (`tools/axdump.swift`) and the concurrent `scan.status` JSON for each
  state: empty; queued (start `thorough` and `standard` back to back, the
  second queues or is refused `busy`: capture whichever the engine gives);
  running crawling; running auditing with the Now line; cancelling (frame
  within 1 s of Cancel Scan); cancelled; done (`light-http`); done with
  `stopped_reason: errors` (dead target) showing the check-error disclosure
  open; failed (if reachable: a profile naming an unavailable lane, else
  recorded as not reproducible); many jobs (≥ 4 rows with the caption);
  bus disconnected (`kill -STOP` the core for 35 s, frame at 10 s and 35 s;
  then `kill -CONT` and a frame showing recovery); a job started from the
  another bus client (a `tools/call` script or an MCP agent; the CLI's
  one-shot verb table has no `scan.start`) appearing selected with nothing
  else selected;
  VoiceOver reading one row (a screen recording or the AX dump's label).
  Web: the same states through `apps/web/scripts/shot.mjs --url <operator
  URL> --out <png>` (headless Chrome against the real core; the T8 proof's
  `scan-live.mjs` lived in a scratch worktree and is not in the repo). TUI:
  a pty recording of the Jobs tab through the same job. The frames go to
  `docs/design/evidence/jobs-view-<date>/` in the PR.

## Acceptance criteria

Each criterion is either a unit test of a pure function with a literal
expected value, or an observation on the real app with a real core and real
traffic (`aitm-testtarget-serve --latency-ms 400`, a dead port for the
connect-refused case). Prefixes: **P1** = mac PR 1, **P2** = mac PR 2,
**W** = web, **T** = TUI. Each cites the finding (C1–C12) or the state-table
row it closes.

### PR 1 (mac, correctness)

1. **AC1 (P1, D1, C6; unit).** Decoding a `scan.status` object whose
   `checks` is `{"scheduled":4,"done":3,"running":[],"errors":7,"error_samples":[{"check":"http.xss","point":"p1","detail":"Connection refused (os error 61)"}],"skipped":3,"skipped_samples":[{"check":"fake.point","point":"p2","detail":"the lane hosts nothing"}]}`
   gives `checks.errors == 7`, `checks.errorSamples.count == 1`,
   `checks.errorSamples[0].detail == "Connection refused (os error 61)"`,
   `checks.skipped == 3`, `checks.skippedSamples[0].check == "fake.point"`;
   the fixture pack's `scan.status.json` (no such keys) gives `0`, `[]`,
   `0`, `[]`.
2. **AC2 (P1, D1, C6; unit).** `crawl: {"pages":1,"queued":0,"depth":0,"forms_submitted":0,"errors":1,"forms_skipped":2,"last_error":"connect_refused"}`
   decodes to `errors == 1`, `formsSkipped == 2`, `lastError == .connectRefused`;
   `"last_error":"weird"` decodes to `.unknown("weird")` whose `rawValue` is
   `"weird"`; an absent `last_error` is `nil`.
3. **AC3 (P1, D2, C1, C2; unit).** `needsStatusRead(summary:stored:)` is
   `true` for `(running, nil)`, `true` for `(done, stored running)`,
   `false` for `(running, stored running)`, `false` for `(done, stored
   done)`, `false` for `(cancelled, stored cancelled)`.
4. **AC4 (P1, D2; unit).** `ScanJobFacts.make(summary: done/elapsed 69_000,
   status: running/elapsed 65_000)` yields `summary.state == .done` and
   `summary.elapsedMs == 69_000` while `status?.profileName` is the status's;
   `make(summary: running/65_000, status: running/66_000)` yields
   `elapsedMs == 66_000`; `make(summary: running/70_000, status:
   cancelled/69_500)` yields `.cancelled` (terminal wins).
5. **AC5 (P1, D2, C1; live).** Start `standard`, select it, press Cancel
   Scan: within 1 s the header reads `Cancelling…` (button disabled); within
   5 s both the row and the header read `Cancelled`, the button is gone,
   `Running: <id>` is absent, and the frame taken 60 s later is identical in
   those fields. A concurrent `scan.status` read shows `state: cancelled`.
6. **AC6 (P1, D2, C2; live).** Let `light-http` finish while another job is
   selected; select it afterwards: the detail reads `Done`, its probes and
   checks counters equal the concurrent `scan.status` (`checks.done ==
   checks.scheduled`, non-zero), and Cancel Scan is not shown.
7. **AC7 (P1, D2; unit + live).** With the merged state `.cancelling`,
   `ScanPanelState.cancelTarget == nil` and `cancel(job:)` sends nothing
   (the command recorder logs no second `scan.cancel`); live: pressing ⌥⌘.
   twice within a second produces one `scan.cancel` in the core's audit log.
8. **AC8 (P1, D3, C8; unit + live).** `applyList` on an empty model with two
   jobs selects `jobs[0].job`; `applyList` with `selectedJob = "scan-aaaa"`
   still listed keeps it. Live: with nothing selected, a `scan.start` sent by another bus
   client (a `tools/call` script as operator, or an MCP agent) makes the row
   appear and the detail show it (header host + subtitle `by the operator`
   or `by an agent`) with no click.
9. **AC9 (P1, D4, C6; unit).** `stoppedReason(.errors, state: .done,
   probesBudget: 2000, error: nil) == "Stopped early: too many errors from
   the target."`; `(.budget, .done, 2000, nil) == "Stopped early: the probe
   budget of 2,000 was spent. Raise it in the profile to go further."`;
   `(.cancelled, .cancelled, …) == nil`; `(.failed, .failed, …, "boom") ==
   nil`; `(.other("paused"), …) == "Stopped early for a reason this app does
   not know."`; `rawReasonLine(.errors) == "stopped_reason: errors"`;
   `crawlTrouble(pages 1, errors 1) == "The crawl fetched 1 page and hit 1
   error"`; `crawlTrouble(pages 46, errors 2) == "The crawl fetched 46 pages
   and hit 2 errors"`; `crawlTrouble(errors 0) == nil`;
   `crawlErrorWords(.connectRefused) == "the target refused the connection"`,
   `(.unknown("x")) == "the connection failed"`.
10. **AC10 (P1, D4, C6; live).** The dead-target job's detail *Stopped*
    section reads `Stopped early: too many errors from the target.`, then
    `The crawl fetched 1 page and hit 1 error — the target refused the
    connection`, then a data-face line `stopped_reason: errors`; the token
    `errors` appears nowhere else in the pane (AX dump grep).
11. **AC11 (P1, D5, C10; live).** `tools/axdump.swift` on the real window
    with three jobs lists exactly three row elements under the `Jobs`
    container, each with the label `ScanFormat.jobAccessibilityLabel`
    produces (starts with the state or phase word), role button, and the
    selected one carrying the selected attribute.
12. **AC12 (P1, D6, C12; unit + live).** `ScanJobsLink.make(bus:
    .connecting("…"), listFailedAt: nil, jobsLoadedAt: 1_000, now: 43_000)`
    gives `kind == .reconnecting`, `valuesAgeMs == 42_000`, `verbsEnabled ==
    false`; `(.connected("…"), listFailedAt: 5_000, …)` gives `.unanswered`;
    `(.connected, nil, …)` gives `.live`, `verbsEnabled == true`;
    `(.disconnected, …, jobsLoadedAt: nil)` gives `valuesAgeMs == nil`.
    Live: `kill -STOP` the core; at 35 s the inline error reads `Unable to
    list jobs: <core text>. Showing values from 0:3x ago; retrying every 2
    s.`, Cancel Scan and the hover Cancel are disabled, the rows keep their
    values; after `kill -CONT` the error clears within 5 s and Cancel Scan
    is enabled.

### PR 2 (mac, redesign)

13. **AC13 (P2, D8, C3; unit).** `ScanJobProgress` for `running/auditing`,
    `checks 3236 / 6468` gives `fraction == 0.5003 ± 0.0001`, `percentText
    == "50 %"`, `phaseLine == "3,236 of 6,468 checks"`, `ring ==
    .determinate(…)`; `running/crawling`, `pages 46, queued 12` gives
    `fraction == 0.7931 ± 0.0001`, `phaseLine == "46 pages, 12 queued"`;
    `running/passive` gives `.indeterminate`, `percentText == nil`,
    `phaseLine == "Passive checks over captured traffic"`;
    `running/reporting` gives `fraction == 1`, `phaseLine == "Writing
    results"`; `queued` gives `.indeterminate` and `phaseLine == "Waiting
    for the engine to start this job."`; `running/auditing` with `scheduled
    == 0` gives `.indeterminate`, `phaseLine == "Scheduling checks"`;
    `cancelled` with `3236 / 6468` gives `ring == .finished(0.5003…)`,
    `percentText == nil`; `nowLine` is `nil` for `running == []`, `"Now:
    xss-reflected"` for one id, `"Now: xss-reflected and 3 more"` for four.
14. **AC14 (P2, D8, C3; live).** During `standard`'s auditing phase the
    card's large number is the checks percent (frame value within 1 of
    `floor(100 * done / scheduled)` from the concurrent `scan.status`), the
    probe budget appears only in the Probes tile with its 2 pt secondary
    rule, and the row's ring and rule read the same fraction.
15. **AC15 (P2, D9; unit).** `ScanEndText.sentence` for `done`, elapsed
    69_000, points.found 1020, checks.scheduled 6468 is `"Done in 1:09 ·
    1,020 points · 6,468 checks."`; for `cancelled`, 115_000, done 3236,
    scheduled 6468 is `"Cancelled after 1:55; 3,236 of 6,468 checks had run.
    What it found stays."`; for `failed`, 12_000 is `"Failed after 0:12."`;
    for `running` is `nil`. `attention` for `checks.errors 7` with one
    sample gives `[("7 checks could not run", 1 sample)]`; `checks.errors
    1` gives `"1 check could not run"`; `checks.skipped 3` gives `"3 checks
    were skipped"`; `crawl.errors 1, lastError .connectRefused` gives `"The
    crawl fetched 1 page and hit 1 error — the target refused the
    connection"` with no samples; all zero gives `[]`.
16. **AC16 (P2, D9, D11; live).** The dead-target job's inspector shows the
    end-state card with `Done in 0:3x · 0 points · <n> checks.`, beneath it
    `Stopped early: too many errors from the target.`, then the attention
    disclosure `7 checks could not run` which opens to rows whose first
    detail is `Connection refused (os error 61)`, then `The crawl fetched 1
    page and hit 1 error — the target refused the connection`; the raw line
    `stopped_reason: errors` is the only place the token appears.
17. **AC17 (P2, D10, C4, C5; unit).** `jobRowLine1(summary running/auditing,
    status profile "standard") == "Auditing · standard"`; `jobRowLine1(done,
    nil) == "Done · —"`; `severityWords(by: 4 low, running: true) == "4
    low"`; `severityWords(1 high 3 low, false) == "1 high, 3 low"`;
    `severityWords(zero, running: true) == "no issues yet"`,
    `(zero, false) == "no issues"`; `jobsCaption(total: 4, running: 1) == "4
    jobs · 1 running"`, `(1, 0) == "1 job"`, `(3, 0) == "3 jobs"`.
18. **AC18 (P2, D10, C4, C5; live).** At the 360 pt list width a running row
    shows the ring, `Auditing · standard` with `1:04`-style elapsed fully
    visible at the trailing edge, the host on line 2 with `4 low` trailing in
    the low ink, a 4 pt rule beneath; a Done row shows no ring, no rule and
    no bar; no row contains a full-width coloured bar (frame).
19. **AC19 (P2, D10; live).** Hovering a running row shows `Cancel` in the
    elapsed slot without any other row moving (two frames, hover off / on,
    differ only inside that row's trailing slot); the context menu of a Done
    row lists `Scan Again`, `Show Issues`, `Show Site Map`, `Copy Job ID`
    and not `Cancel Scan`.
20. **AC20 (P2, D11; unit).** `jobHeading(facts auditing, targets
    ["http://127.0.0.1:8117"]) == "Auditing 127.0.0.1:8117"`; three targets
    give `"Auditing a.test and 2 more"`; two give `"Auditing a.test,
    b.test"`; `jobSubtitle(live, profile standard, startedAt = 11:32 local,
    startedBy aitm-mac, elapsed 64_000) == "standard · started 11:32 by this
    app · 1:04"`; terminal with finishedAt 11:33 and elapsed 69_000 ==
    `"standard · started 11:32 by this app · finished 11:33 · 1:09"`;
    `frontend cli` → `by the CLI`; `frontend mcp` → `by an agent`;
    `operator` + label `aitm-tui` → `by aitm-tui`.
21. **AC21 (P2, D11, C7, C9, C11; live).** The running inspector shows, in
    order: heading, subtitle with `started <h:mm> by this app`, the card
    with percent + `… of … checks`, the rule, `Now: <id>` (or `… and n
    more`) within 40 pt of the rule, the three tiles; no section titled
    Session or Lanes is open by default; `Points` reads `waiting for audit`
    and `skipped as repetitive`, never `Queued` or `Skipped frequent`.
22. **AC22 (P2, D11; gate).** `grep -nE 'Color\(|\.cornerRadius\(|easeOut\(0\.[0-9]|\.animation\(\.easeOut' apps/mac/Sources/Aitmproxy/Panels/ScanPanel+Jobs.swift`
    prints nothing; `tools/grid-lint.sh` prints PASS.
23. **AC23 (P2, D12; gate).** `docs/design/tokens.json` carries
    `motion.counter` with `$value` `150ms` and `motion.progress` with
    `250ms`; after the generators run, `Tokens.swift` has `static let
    counter: Double = 0.150` and `static let progress: Double = 0.250` under
    `Tok.Motion`, the web `tokens.css` has `--motion-counter: 150ms` and
    `--motion-progress: 250ms`, and `cargo test -p aitm-tui` passes with the
    bumped `$version`; `grep -nE '[0-9]' apps/mac/Sources/Aitmproxy/UI/ScanMotion.swift`
    matches only comment lines (no numeric literal outside `//`).
24. **AC24 (P2, D12; live).** A screen recording (SCStream or the real-run
    motion harness) over 10 s of the auditing phase shows the percent digits
    changing without a layout jump and the rule's width changing
    monotonically between frames except where `scheduled` grew; with Reduce
    Motion on, the same recording shows instant swaps; no element changes
    colour over time (per-frame diff limited to the digit and rule regions).
25. **AC25 (P2, D13; unit).** `scanAgainArguments(for:)` on a `done` job
    with `profileName "standard"`, `targets ["http://127.0.0.1:8117"]`
    returns `("scan.start", ["profile_name": "standard", "overrides":
    ["target": ["origins": ["http://127.0.0.1:8117"]]]])`; on a running job
    it returns `nil`; `scanAgainRefusal` is `nil` with the host in scope and
    `scan.start` listed, `"Out of scope — add 127.0.0.1:8117 to scope to scan
    it"` otherwise, `"scan.start is not on this bus"` without the tool,
    `"Select a finished job."` for a running job; `scanAgainHelp == "Start a
    new job with profile standard against 127.0.0.1:8117"`;
    `ScanConfirm.summaryLine` for those arguments is `"Profile standard ·
    127.0.0.1:8117"`, and for an inline `profile` is `"Profile <name> ·
    <hosts>"`.
26. **AC26 (P2, D13; live).** Scan Again on the Done `light-http` row: the
    audit log shows one `scan.start` with `profile_name` and `overrides`; a
    new row appears first and is selected; a second Scan Again while that
    job runs shows `Unable to scan again: A scan on this origin is already
    running` under the header and sends one refused `scan.start`.
    Deleting a saved profile and pressing Scan Again on its finished job
    shows `Unable to scan again: <invalid_profile text>`; the Profiles
    footer is unchanged.
27. **AC27 (P2, D13; live).** Scan Again on a finished `l4-stream-safe` job
    (with an L4 scope entry) opens the confirm sheet with the engine's
    prompt and the line `Profile l4-stream-safe · <ip:port>`; Cancel sends
    nothing more; Start Scan sends the identical arguments plus `_confirm`
    (audit log).
28. **AC28 (P2, D14; unit).** `jobAccessibilityLabel` for the auditing
    `standard` job with `3236 / 6468`, `4 low`, elapsed 64_000 is
    `"Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236 of 6,468
    checks, 4 issues: 4 low, 1 minute 4 seconds."`; `elapsedWords(42_000)
    == "42 seconds"`, `(3_723_000) == "1 hour 2 minutes 3 seconds"`;
    `endAnnouncement(done, host, 4 issues) == "Scan of 127.0.0.1:8117 done:
    4 issues."`, `(cancelled, 0) == "Scan of 127.0.0.1:8117 cancelled: no
    issues."`, `(failed) == "Scan of 127.0.0.1:8117 failed."`.
29. **AC29 (P2, D14; live).** With VoiceOver on, ↓ in the list reads a row
    as one sentence (recording or the AX label equals AC28's shape); the
    heading is announced as a heading; the progress rule reports `50
    percent`; when the selected job ends, exactly one announcement is heard
    (the command recorder logs one `announcementRequested`); Return moves
    focus to the header's first button and Escape returns it to the list.
30. **AC30 (P2, D15, C12; live).** `kill -STOP` the core: at 10 s the rows
    are unchanged and no banner shows; at 35 s the banner reads `The core is
    not answering · showing values from 0:3x ago · retrying every 2 s`, the
    verb slot and the hover Cancel are disabled; `kill -CONT`: the banner
    leaves within 5 s. Proxy ▸ Reconnect Bus during a stopped core shows
    `Bus disconnected · showing values from … ago · reconnecting…`.
31. **AC31 (P2, D10; live).** With four jobs the caption reads `4 jobs · 1
    running`, rows are newest first (ids match the concurrent `scan.list`
    order), and the list scrolls without the inspector moving.
32. **AC32 (P2, D16, D17; gate).** `grep -nwiE 'stop|abort|finding|task'`
    over the string literals of `ScanSurface.swift`'s Jobs words finds no
    operator-facing string (`"Stop this job; …"` in the help is the one
    allowed verb use, listed in the UX section); no `Timer` or
    `Task.sleep` is added to `ScanPanel+Jobs.swift`.

### Web parity

33. **AC33 (W1, D18; unit).** `parseJobStatus` on AC1's `checks` gives
    `errors === 7`, `error_samples.length === 1`, `skipped === 3`; AC2's
    `crawl` gives `last_error === 'connect_refused'`; `needsStatusRead`
    matches AC3's five cases; `stoppedReasonText('errors') === 'Stopped
    early: too many errors from the target.'`; `stateWords({state:
    'running', phase: 'auditing'}) === 'Auditing'`, `stateWords({state:
    'done', …}) === 'Done'`.
34. **AC34 (W1, D18; unit).** `live.test.ts`: a `scan.list` reply turning
    `scan-1a2b3c4d` to `done` while the held status is `running` issues
    exactly one `scan.status { job: 'scan-1a2b3c4d' }` and none for a job
    whose held status is already `done`.
35. **AC35 (W1, D18; unit).** `JobsView.test.tsx`: the Overview's `stopped`
    fact reads the sentence and a `[data-field="stopped-raw"]` element
    reads `stopped_reason: errors`; the detail Cancel is disabled while the
    merged state is `cancelling`.
36. **AC36 (W2, D18; unit).** `jobProgress` matches AC13's table
    (`percentText === '50 %'`, `phaseLine === '3,236 of 6,468 checks'`,
    crawling fraction `0.7931 ± 0.0001`); `endSentence` matches AC15's three
    sentences byte for byte; `crawlTroubleText` and `crawlErrorWords` match
    AC9.
37. **AC37 (W2, D18; unit + live).** A row renders the ring `<svg>`, `Auditing
    · standard`, the host, `4 low` in `.sevWord[data-severity="low"]`, and a
    rule whose inline width is `50%` for `3236 / 6468`; Scan Again sends
    `scan.start` with `{ profile_name, overrides: { target: { origins } } }`
    (store test); `styles.test.ts` finds no literal colour, radius or `ms`
    duration in `scanner.module.css`. Live: `scripts/shot.mjs` captures of
    running, cancelled and the dead-target done states show the same
    sentences as AC16.
38. **AC38 (W2, D18; unit).** The `ReconnectNote` text with `jobsLoadedAt`
    42 s old reads `Bus disconnected · showing values from 0:42 ago ·
    reconnecting…`; every control in the Jobs view is disabled while the bus
    is not open (existing test extended to Scan Again).

### TUI parity

39. **AC39 (T1, D19; unit).** `fold_list` with a list that turns
    `scan-1a2b3c4d` `done` while `full["scan-1a2b3c4d"].state == Running`
    returns `["scan-1a2b3c4d"]` as follow-ups; with `full` already `Done` it
    returns `[]`; a job with no `full` entry is still returned.
40. **AC40 (T1, D19; unit).** `stopped_text(StoppedReason::Errors) ==
    "Stopped early: too many errors from the target."`,
    `stopped_text(Budget)` carries `the probe budget of` (the budget number
    is formatted by the caller), `crawl_error_words(ConnectRefused) == "the
    target refused the connection"`; `detail_lines` for a status with
    `stopped_reason: errors`, `crawl.errors 1`, `last_error connect_refused`,
    `checks.errors 7` contains `("stopped", "Stopped early: too many errors
    from the target.")`, `("wire", "stopped_reason: errors")`, a `crawl`
    line ending `· errors 1 (the target refused the connection)` and a
    `checks` line containing `· errors 7`; `bound_status` cuts a 1,000-cell
    `error_samples[0].detail` to `DETAIL_VALUE_MAX` and nine samples to
    `DETAIL_LIST_MAX`.
41. **AC41 (T2, D19; unit).** `progress(summary running/auditing 3236/6468,
    Some(full))` gives `fraction ≈ 0.5003`, `phase_line == "3,236 of 6,468
    checks"`; `progress_bar(Some(0.5), 6) == "━━━───"`, `progress_bar(None,
    6) == "──────"`, `progress_bar(Some(1.0), 6) == "━━━━━━"`;
    `end_sentence(done, 69_000, 1020, 6468) == "Done in 1:09 · 1,020 points
    · 6,468 checks."`; `state_phase_text(Running, Auditing) == "auditing"`, `(Cancelling, Auditing) == "cancelling"`,
    `(Done, Done) == "done"`.
42. **AC42 (T2, D19; unit).** The header line reads `job  profile  targets
    state  progress  budget  points  issues  el.` in the full layout; a row
    for the auditing fixture shows `3236/6468` beside a 6-cell bar with 3
    filled cells and `418/2000` in the budget column with no bar; the Detail
    pane's first lines for a cancelled job are the end sentence, then the
    label-value lines.
43. **AC43 (T2, D19; live).** A pty recording of `aitm tui` on the Jobs tab
    through a `standard` job shows the progress column rising, the detail's
    `now` line, `x` producing `cancelling` then `cancelled`, and the
    detail's first line `Cancelled after …; … of … checks had run. What it
    found stays.`; the Jobs banner after `kill -STOP` carries `showing values
    from 4xs ago`.

## Left to the builder

- Exact point sizes within the token scale; the ring's stroke width.
- Whether the tiles are a three-column `HStack` or a `Grid`.
- The disclosure groups' default open/closed state per section.

## Open questions

None. The two motion tokens of D12 (`motion.counter` 150 ms,
`motion.progress` 250 ms) were approved at the spec's approval: the UX
motion table names those durations, "no literal durations in views" must
hold, and adding a token to `tokens.json` is the documented way (the three
generators re-run in the same task). Matt may still rule to map the two
rows onto `popover` and `sheet` instead; that is a one-line change in D12
and in `ScanMotion`.
