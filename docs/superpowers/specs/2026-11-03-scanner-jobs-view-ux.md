# Scanner Jobs view UX design

**Status:** approved (2026-11-02, self-approved by the scan-jobs-ux session under Matt's autonomous-approve mode; Matt may correct any **(Architect's call)** at review). Coordinator rulings of 2026-11-02 folded in: Scan Again decided (D13), two mac PRs (Part A, Part B), checks-done as the primary bar (D8, D11), stopped-reason words everywhere with the raw token only in the inspector (D4). The two motion tokens of D12 are approved.
**Research inputs:** this document's *Current state* section (real-app frames in `docs/design/evidence/jobs-view-2026-11-02/`), the locked comp `docs/design/mockup/scan-jobs/` (`committed.html`, `committed-1440.jpg`, `NOTES.md`, `direction.json`; `quiet.html` rejected), `docs/design/operator-ui-foundation.md` (§2.2 palette, §2.3 type, §2.8 interaction rules), `docs/design/tokens.json`, `docs/design/GLOSSARY.md`, `docs/superpowers/specs/2026-10-31-scanner-v2-mac-scan-surface-design.md` (D5, D11, D13), the engine's `JobStatus` in `crates/aitm-scan-model/src/job.rs`
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
- The view uses the palette, type scale, depth and motion tokens in
  `docs/design/tokens.json`; every hue has exactly one job (D11's palette
  jobs: accent = progress and selection, severity inks on issues only, teal =
  agent-originated, intercept = not finished, success = done, danger =
  failed, neutral = cancelled) and nothing else carries hue.
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

- Decoration: gradients, glass, charts, hue on chrome for its own sake. The
  locked comp (UX, *Locked comp*) is bold on purpose, with a raised card, real
  depth, a KPI strip and a state chip, but every tone and shadow is a token
  and every hue has exactly one job (D11). Matt rejected two quieter rounds
  before locking it; "restrained" is not the brief any more.
- Motion that performs for no reason: bounces, pulses on counters, repeated
  entrances. D12 allows one orchestrated entrance when a job becomes selected
  and breathing on exactly two dots; everything else bridges a change the
  operator would otherwise see jump.
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
  they reach the screen (mac: at decode, `ScanWire.boundedString`, D1
  amendment); the mac Kit's existing decoders keep their defaults
  for missing fields.
- **Palette and type** from `tokens.json`: UI face / data face, six sizes,
  tabular figures on every number; `Tok.*` on mac, CSS variables on web,
  theme tokens on TUI. No hard-coded colours, radii or durations in views.
- **Motion tokens**: `easeOut` `(0.23, 1, 0.32, 1)`, `easeInOut`
  `(0.77, 0, 0.175, 1)`, `pulse` `(0.42, 0, 0.58, 1)`, press 120 ms, hover
  100 ms, popover 160 ms, sheet 220 ms, `interceptPulse` 1200 ms; D12 adds
  `counter` 150 ms, `progress` 250 ms and `stagger` 60 ms. Keyboard-initiated
  actions never animate. Reduce Motion drops travel and keeps opacity.
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

- **Job card + jobs table + wells**, one column, top to bottom (the locked
  comp). The selected job's raised **card** at the top is the inspect-and-act
  surface (title row with the verbs, the scan lane, the issue ledger, the
  probe budget gauge, the KPI strip); the **table** beneath is the
  at-a-glance surface for every job; two **wells** at the bottom hold what the
  job did (Crawl and points) and what it found (Issues by severity and
  confidence). There is no side-by-side inspector any more.
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

| State | Table row | Job card (when selected) |
| --- | --- | --- |
| Empty | Keep: glyph, "No jobs yet — pick a profile and Start Scan.", `Open Profiles`. No table header, no card, no wells. | none |
| Queued | Small indeterminate spinner in the State column, "Queued"; profile; target; progress "—"; probes `0 of 2,000`; "no issues yet"; elapsed. | Chip "Queued" (neutral pair), heading = the target host, finding line "no issues so far · standard · started 11:32 by this app". Lane empty with the phase line "Waiting for the engine to start this job." inside the track; no now mark; scale row started · elapsed; no estimate. KPI Progress "—". Cancel Scan enabled. |
| Running | 18 pt ring in accent at the progress fraction (6 pt teal dot beside it when agent-started), "Auditing"; "standard"; host in the data face; `50 % · 3,236 of 6,468`; `287 of 2,000`; `97 of 1,020`; "4 low" in the low ink; `1:04`; Cancel at the trailing edge on hover. | Chip "Auditing" (accent pair), heading host, finding line "4 low issues so far · xss-reflected and 3 more checks running now · standard · started 11:32 by this app". Lane: crawl cap (accent.deep, "crawl" / "46 pages"), audit fill (accent, "audit" / "3,236 checks done") at the true checks fraction, "3,232 checks to go" at the right, the now mark with its breathing dot at the fill's edge, "now · xss-reflected and 3 more" under it; scale row "started 11:32 · elapsed 1:04 · at this pace, about 1:04 to go". Ledger: four low marks + "4 low". Gauge 14 % grey, "287 of 2,000". KPI strip: Progress 50 % (accent) · Checks 3,236 of 6,468 · Probes 287 of 2,000 · Points audited 97 of 1,020 · Issues 4, "4 low". Verbs: Show Site Map · Show Issues · **Cancel Scan**. Attention lines only when non-zero. |
| Crawling / Passive / Reporting | Ring: pages ÷ (pages + queued) while crawling; indeterminate spinner for passive; full ring for reporting. Progress text "46 pages, 12 queued" / "Passive checks over captured traffic" / "Writing results". | Lane while crawling: one crawl segment at pages ÷ (pages + queued) with "crawl" / "46 pages, 12 queued", no now mark, no estimate; passive: empty track with the phase line inside, no estimate; reporting: full fill, "Writing results" in the now tag's place. KPI Progress "—" / "—" / "100 %". |
| Cancelling | 6 pt intercept dot breathing, "Cancelling"; the ring is gone; values frozen at their last read. | Chip "Cancelling" (intercept pair), the card's left edge intercept; lane frozen at its value, the now mark's dot stops breathing and the mark fades; primary verb disabled and titled "Cancelling…". |
| Done | 6 pt success dot, "Done"; when a stopped reason exists, its sentence on a second 12 pt line under the word, tail-truncated with the full sentence in the tooltip. Progress "6,468 of 6,468" (checks). | Chip "Done" (success pair), left edge success. Finding line "standard · started 11:32 by this app · finished 11:33" (preceded by the stopped-reason sentence when present). Lane frozen; the now tag is replaced by the end sentence "Done in 1:09 · 1,020 points · 6,468 checks."; no estimate. Verbs: Show Site Map · Show Issues · **Scan Again**. |
| Cancelled | 6 pt neutral dot, "Cancelled"; progress "3,236 of 6,468". | Chip "Cancelled" (neutral pair), left edge neutral; the lane's end sentence "Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays." Scan Again. |
| Failed | 6 pt danger dot, "Failed"; the error's first line as the 12 pt sub-line. | Chip "Failed" (danger pair), left edge danger; end sentence "Failed after 0:12."; the engine's error text verbatim in `Tok.Status.serverError`, selectable, in the attention block. Scan Again. |
| Done with stopped reason | as Done, with the sub-line | The finding line opens with the reason sentence: budget: "Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further." · time: "Stopped early: the time budget ran out." · session_lost: "Stopped early: the session was lost and the profile says stop when that happens." · errors: "Stopped early: too many errors from the target." (the attention line "7 checks could not run ▸" follows in the attention block) · policy: "Stopped early: the agent policy changed to paused or read-only." · guard_refused: "Stopped early: the L4 guard refused a target mid-run." · failed: the error text. The gauge is amber (intercept) when > 80 % of the budget was spent. |
| Check errors (any state) | nothing | Attention block under the KPI strip: "7 checks could not run ▸" opening the first 8 `(check, detail)` samples in the data face; "3 checks were skipped ▸" likewise for `skipped_samples`. |
| Crawl trouble | nothing | Attention block: "The crawl fetched 1 page and hit 1 error" with ` — <last_error words>` when the engine sets `last_error`: connect_refused "the target refused the connection", tls "TLS handshake failed", timeout "the target did not answer in time", h2_not_negotiated "the target does not speak HTTP/2", transport/other "the connection failed". |
| Notices | nothing | "Clamped budget.probes 50,000 → 20,000" and "Skipped WebSocket: lane not available on this build" as one list under **Notices** at the end of the attention block, shown only when non-empty. |
| Many jobs | Rows newest first on a 44 pt pitch; the table scrolls with the page; a row's long target middle-truncates with the full list in a tooltip; the table's accessibility label is "4 jobs · 1 running". | unchanged (the card is the selected job) |
| Bus disconnected | Banner above the card: "Bus disconnected · showing values from 0:42 ago · reconnecting…"; rows keep their last values; hover Cancel hidden; the now mark's dot stops breathing. | Verb slot disabled; values kept. |
| List read failed | Keep the inline error (D6) with the core's text and the last-good time, under the banner. | unchanged |

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
- Chip: the phase word while running (`Crawling`, `Passive`, `Auditing`,
  `Reporting`), else the state word (`Queued`, `Cancelling`, `Done`,
  `Cancelled`, `Failed`).
- Heading: the target `host[:port]` in the data face; two targets join with
  ", "; three or more read "<first> and 2 more" with the full list in the
  tooltip.
- Finding line (under the heading), clauses joined by ` · `: live `<issues so
  far> · <now clause> · <profile> · started <h:mm> by <this app | the CLI | an
  agent | <client label>>`; terminal `[<stopped-reason sentence> · ]<profile>
  · started <h:mm> by <who> · finished <h:mm>`. Issues so far: `no issues so
  far` / `4 low issues so far` / `1 high issue so far` / `5 issues so far: 1
  high, 4 low`. Now clause: `xss-reflected running now` / `xss-reflected and
  3 more checks running now` / absent when `checks.running` is empty.
- Lane: segment labels `crawl` / `46 pages` and `audit` / `3,236 checks done`
  (architect, 2026-11-02: the draft read `48 %` beside these counters; 3,236
  / 6,468 is 50 %); right label `3,232 checks to go` (`1 check to go`); now
  tag `now · xss-reflected` / `now · xss-reflected and 3 more`; scale row
  `started 11:32` · `elapsed 1:04` · `at this pace, about 1:04 to go` (absent
  while crawling or passive, when the rate is 0, and after the end); the end
  sentence replaces the now tag when the job ends.
- Ledger: one mark per issue grouped by severity, each group followed by its
  count word `4 low` in the severity ink; `no issues yet` / `no issues` in
  the tertiary ink when empty.
- Gauge: `probe budget` left, `287 of 2,000` right.
- KPI strip labels: `Progress` · `Checks` · `Probes` · `Points audited` ·
  `Issues`; values `50 %` · `3,236` + `of 6,468` · `287` + `of 2,000` · `97`
  + `of 1,020` · `4` + `4 low` (`no issues yet` / `no issues`); `—` for an
  unknown progress.
- Table header, sentence case: `State` · `Profile` · `Target` · `Progress` ·
  `Probes` · `Points` · `Issues` · `Elapsed`; progress cell `50 % · 3,236 of
  6,468` while auditing, the phase line while crawling or passive, `3,236 of
  6,468` when terminal.
- Sentence case for labels and all messages. Errors name what happened and
  the fix: "Unable to list jobs: <core text>. Retrying every 2 s." Never
  "something went wrong".
- Every number uses grouping separators and tabular figures.

### Hover help (step 6)

Every icon-only or ambiguous control: Cancel Scan "Stop this job; the issues
and site map it found stay (⌥⌘.)"; Scan Again "Start a new job with this
job's profile and target"; Show Issues "Open the Issues tab filtered to this
job"; Show Site Map "Open the Site map tab for this job"; the lane and the
table's ring "<done> of <total> checks (derived from the engine's counters)";
the estimate "Derived from the counters: 3,236 checks done in 1:04, about 51
checks per second, 3,232 to go."; the gauge "287 of 2,000 probes sent (the
probe budget, not progress)"; the Issues KPI cell and the ledger "<n>
issues: 1 high, 3 low"; the truncated target "<all targets>". Hover reveals
the row's Cancel in the trailing column so nothing shifts; the same verb is
in the context menu and on ⌥⌘..

### Accessibility (step 7)

- Tab order: Scan tabs → the card's verbs → the table → the attention
  disclosures and wells.
- ↑↓ in the table move the selection (no animation, no entrance); Return or
  → focuses the card's first enabled verb; Escape returns to the table; ⌥⌘.
  cancels the selected job.
- Each row is one accessibility element whose label is a sentence:
  "Auditing, standard, 127.0.0.1:8117, 50 percent, 3,236 of 6,468 checks, 4
  issues: 4 low, 1 minute 4 seconds." Rows must be present in the AX tree (C10).
- The card's heading is a heading; the lane is one element labelled
  "Progress" with value "50 percent"; the ring, the dots, the ledger marks and
  the now mark are hidden (the row label and the count words carry them); KPI
  cells read label then value; the estimate reads its derived help.
- When the selected job reaches an end state, VoiceOver gets one announcement:
  "Scan of 127.0.0.1:8117 done: 4 issues." (occasional, state indication).
- Meaning never by colour alone: severity text carries the word; state words
  are text; the Failed error is text.
- Text ≥ 11 pt; Increase Contrast keeps the token pairs (≥ 4.5:1).
- Reduce Motion: progress eases become instant, the end-sentence swap is an
  opacity fade only, the indeterminate ring is the system `ProgressView`
  (which honours the setting).

### Look and motion (Matt, 2026-11-02: "push bolder, better animations and colors … 10x more polished with better colors, shadows, animations")

**Locked comp (2026-11-02).** After two rejected rounds (the restrained
`docs/design/mockup/scan-jobs/quiet.html`, kept for contrast only), Matt
locked the HTML comp `docs/design/mockup/scan-jobs/committed.html` (1440×900,
with its motion demo script) and its render
`docs/design/mockup/scan-jobs/committed-1440.jpg`. The comp's CSS and markup
are the source of truth for layout, tokens, sizes and motion; the design
notes are `docs/design/mockup/scan-jobs/NOTES.md` (inventory, the screen's
one question "Is this scan still finding things, and how much of it is
left?", the signature element, the grid arithmetic) and the dealt app style is
`docs/design/mockup/scan-jobs/direction.json` (tasteskill `data-terminal`,
seed 1164699010, palette and type kept from `tokens.json`). Every colour in
the comp is a token value; three values are new tokens (D11: `color.ground.card`,
`shadow.float`, `shadow.rest`). Where this document and the comp differ, the
comp wins; where the comp is silent (light mode, the cancelled and queued
tones, the ledger cap), the decision is marked **(Architect's call)**.

**Composition** (top to bottom, one column on `Ground.surface`): the bus
banner when the link is away (D15); the selected job's **job card**; the
**jobs table**; two **wells**. Grid at 1440 pt: sidebar 240, content 1200,
page padding 24 → 1152 usable; KPI strip five equal cells split by 1 pt
dividers; wells 568 + 16 + 568.

**The job card** (D11): `Ground.card` tone, 1 pt `Line.border`, `Radius.floating`
(10 pt), the `Shadow.float` depth, padding 20/24, a 3 pt left edge in the
state's tone (accent while running, success when done, intercept while
cancelling, danger when failed, neutral when cancelled). Inside, top to
bottom: the **title row** (state chip in the palette's pill pair + the target
host in the data face at 24 pt 600 as the heading + the finding line in UI
base `Ink.secondary` with numbers in `Ink.primary` and the agent words in
`Agent.base`; the verbs Show Site Map · Show Issues · Cancel Scan / Scan
Again at the right, 32 pt tall); the **scan lane** (a 64 pt track on
`Ground.raised`, `Radius.panel`; the crawl cap in `Accent.deep` then the audit
fill in `Accent.base` at the true checks fraction; labels inside the segments
in `Ink.onAccent`; "N checks to go" at the right in `Ink.tertiary`; a 2 pt
now mark in `Ink.primary` overshooting the track by 10 pt with a 3 pt halo at
12 % and a 10 pt breathing dot on top; the now tag under it; a scale row
started · elapsed · estimate in `Ink.tertiary` 12 pt); the **issue ledger**
(one 8×16 pt mark per issue in its severity ink, grouped by severity with the
count word); the **probe budget gauge** (3 pt, `Ink.tertiary` fill on
`Ground.raised`, `Intercept.base` when more than 80 % is spent); the **KPI
strip** (one container on `Ground.surface` with a 1 pt border, `Radius.panel`,
split by 1 pt dividers into Progress · Checks · Probes · Points audited ·
Issues; labels UI md `Ink.secondary`; numerals data face 28 pt regular
tabular; the Progress numeral in `Accent.base` as the lead figure; the unit
suffix UI md `Ink.secondary`; the Issues severity word in its ink); then the
attention block (D9) only when non-empty.

**The jobs table** (D10): header 32 pt, labels 12 pt `Ink.tertiary` sentence
case, no fill; rows on a 44 pt pitch (the comp's 46 on the 4 pt grid) with
1 pt `Line.rule` separators; the State column holds an 18 pt ring in
`Accent.base` over a `Line.control` track for live jobs (a 6 pt `Agent.base`
dot with an `Agent.tint` halo beside it when agent-started), a 6 pt
`Intercept.base` dot breathing while cancelling, a 6 pt `State.success.fg`
dot when done, `State.neutral.fg` when cancelled, `State.danger.fg` when
failed; Profile; Target in the data face; Progress text; Probes · Points ·
Issues · Elapsed right-aligned tabular with the unit muted (`of 2,000` in
`Ink.secondary`); a trailing 84 pt column with a `Cancel` text action shown on
hover of a live row; the selected row on `Ground.active` with a 3 pt
`Accent.base` left edge; hover `Ground.hover`.

**The wells**: `Ground.card`, 1 pt border, `Radius.floating`, `Shadow.rest`,
padding 16/20; title UI base 500 with a 12 pt `Ink.tertiary` subtitle at the
right ("what the job found to test" / "by severity and confidence"); 28 pt
key-value rows split by `Line.rule`, keys `Ink.secondary`, values in the data
face `Ink.primary`.

**Palette jobs** (the whole hue budget): `Accent` = progress (lane fill, ring
arcs, the Progress numeral, the selection edge, the active tab's 2 pt
underline); severity inks on issues only (ledger marks, count words, the
Issues cells); `Agent` teal = agent-originated (the row dot, the finding
line's "an agent"); `Intercept` amber = not finished (cancelling, the budget
warning); `State.success` = done; `State.danger` = failed; `State.neutral` =
cancelled; `Status.serverError` for the Failed error text. Nothing else
carries hue.

**Motion**, per the `animate` gate (frequency → purpose → tool → properties →
curve/duration → interruption → reduce motion); every duration and curve is
a token (D12):

| Change | Frequency | Purpose | Motion | Reduce Motion |
| --- | --- | --- | --- | --- |
| A job becomes selected (click, a start, the first list) | a few per session | orientation | one orchestrated entrance: title row, lane, KPI strip, table, wells rise 8 pt and fade in, 60 ms apart, 220 ms `easeOut` | opacity only, same stagger |
| Lane fill, now mark, ring arc (every 1 s) | tens per minute | prevent a jarring change | width / offset / trim ease 250 ms `easeOut`; never snaps back | instant |
| Counter ticks (every 1 s) | tens per minute | prevent a jarring change | digits tick 150 ms `easeOut` (`numericText`; the web's CSS: translate 3 pt + opacity to .35) | instant swap |
| An issue arrives | occasional | state indication | the new ledger mark rises 3 pt from 60 % height and fades in, 220 ms `easeOut` | opacity only |
| State change (Running → Cancelling → Done) | once per job | state indication | chip crossfade 160 ms; the card's left edge and the chip's pair recolour 160 ms `easeOut` | same (opacity and colour, no travel) |
| The job ends | once per job | prevent a jarring change | the lane's now tag swaps for the end sentence, the primary verb swaps for Scan Again, the now mark fades: 220 ms `easeOut`, opacity + 2 pt rise | opacity only |
| Row hover Cancel | tens per day | feedback | 100 ms opacity in the fixed trailing column | same |
| Button press | — | feedback | existing press 120 ms scale 0.97 | existing |
| Breathing | continuous | "alive" | 1200 ms alternate on the `pulse` curve, opacity 1 → 0.4, on exactly two dots: the now mark's dot and the cancelling dot | removed |
| Selection by keyboard, tab switch | 100+/day | — | **none** (no entrance either) | none |

No `TimelineView`, no timer in a view: every counter and the breathing's
start come from the poll and the state; the breathing itself is a
`repeatForever` opacity animation the system drives.

### UX block (step 8)

```markdown
UX:
- Flow: Start Scan (⌘⏎) / Map Only / a start elsewhere -> Jobs tab, job selected, card live -> ↑↓ rows, Return focuses detail -> Cancel Scan (⌥⌘., header, row hover, context menu) -> Cancelling… -> Done | Cancelled | Failed: one sentence + Scan Again · Show Issues · Show Site Map
- Surface: one column: job card (inspect and act: chip + host heading + finding line + verbs, scan lane, issue ledger, probe gauge, KPI strip) → jobs table (at a glance) → two wells; cancel inline, no dialog; errors and notices as inline disclosures in the card's attention block; disconnected as an inline banner above the card
- States: empty "No jobs yet — pick a profile and Start Scan." + Open Profiles; queued "Waiting for the engine to start this job."; running card = chip "Auditing" + host + "4 low issues so far · xss-reflected and 3 more checks running now · standard · started 11:32 by this app" + lane (crawl 46 pages | audit 3,236 checks done | 3,232 checks to go, now · xss-reflected and 3 more, started · elapsed · at this pace, about 1:04 to go) + ledger + gauge + KPI strip; cancelling button "Cancelling…" disabled; done "Done in 1:09 · 1,020 points · 6,468 checks."; cancelled "Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays."; failed "Failed after 0:12." + error; stopped reasons as sentences (budget/time/session_lost/errors/policy/guard_refused); check errors "7 checks could not run ▸"; crawl "fetched 1 page and hit 1 error ▸ the target refused the connection"; many "4 jobs · 1 running"; disconnected "Bus disconnected · showing values from 0:42 ago · reconnecting…"
- Words: Cancel Scan, Cancelling…, Scan Again, Show Issues, Show Site Map, Copy Job ID, Open Profiles; chip "<Phase or state>"; heading "<host>"; finding line "<issues so far> · <now clause> · <profile> · started 11:32 by this app"; KPI labels Progress · Checks · Probes · Points audited · Issues
- Help: Cancel Scan "Stop this job; the issues and site map it found stay (⌥⌘.)"; Scan Again "Start a new job with this job's profile and target"; lane "<done> of <total> checks (derived)"; estimate "Derived from the counters: … about 51 checks per second, 3,232 to go."
- Access: ↑↓ rows, Return/→ the card's verbs, Esc back, ⌥⌘. cancel; row label is a sentence; the host heading is a heading; lane value "50 percent"; one announcement at an end state; rows present in the AX tree
- Look: the locked comp; tokens only; card on Ground.card, Radius.floating, Shadow.float, a 3 pt state-toned left edge; palette jobs (accent = progress, severity on issues, teal = agent, intercept = not finished, success/danger/neutral = done/failed/cancelled); one staggered entrance 220/60 ms on selection, lane/ring 250 ms, counters 150 ms, chip/edge 160 ms, breathing 1200 ms on two dots; keyboard moves never animate; Reduce Motion keeps opacity, drops travel and breathing
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
hover help. Web: the locked comp is itself HTML and CSS, so W2 reproduces its
composition (card, lane, ledger, gauge, KPI strip, table, wells) with the
tokens as CSS variables and its motion as CSS transitions on
`transform`/`opacity`/`width` under `prefers-reduced-motion`; D18's W2 row
layout is re-cut to the comp before Part 3 opens (D18 amendment). TUI:
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
and are extended here. **The locked comp (UX, *Locked comp*, 2026-11-02)
supersedes, for the Jobs tab only, the list + inspector split of the mac
spec: the selected job is a card above the table, not a pane beside it.**

**Two mac PRs** (coordinator ruling, 2026-11-02). PR 1 is correctness and
lands first: it closes C1, C2, C6 (decoding and words), C10 and C12 inside the
*current* layout. PR 2 is the redesign: the job card, the table, the wells,
the derived progress, motion, Scan Again, the announcement and the banner. Decisions D1 to
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

**Amendment (2026-11-02, PR 1 panel).** The Kit bounds every core string at
decode, mirroring the TUI's `bound_status` (Constraints, hostile-core bounds):
`ScanWire.boundedString(_ key: String, max: Int) throws -> String?` drops the
Unicode scalars whose general category is control, format, line separator or
paragraph separator, then cuts to `max` Unicode scalars. `profile_name` is cut to
64; `error`, each `ScanCheckErrorSample` field (`check`, `point`, `detail`),
`clamped[].field`, `lanes.skipped[].reason` and each `checks.running[]` to
400; each `targets[]` to 200; the lists `error_samples`, `skipped_samples`,
`checks.running` and `targets` keep their first 8 (the engine's own cap; how
many were dropped is not recorded in PR 1). The escape hatches
`ScanCrawlErrorKind.unknown(raw)`, `ScanStoppedReason.other(raw)`,
`ScanJobState.other(raw)` and `ScanPhase.other(raw)` clean and cut the raw
token to 64 in `init?(rawValue:)`, so no view can print an unbounded token.
AC1b pins it.

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
2. Every other listed job is read when `needsStatusRead` is true and no
   read for it is in flight. The bookkeeping is the Kit's
   `ScanStatusReadLedger`, held as `statusReads` on `ScanPanelState`: a job
   is *claimed* when a read is owed and issued; `settle(afterList:stored:)`
   runs after each successful list, prunes jobs the list no longer carries
   and re-arms any job that still owes a read (`needsStatusRead` true
   against its stored status), so a job read once while running is read
   once more after the list calls it terminal, and then never again. A read's
   own outcome never re-arms it: a failing status read is retried after the
   next list lands, not at 1 Hz.
3. Push flags (`refreshNeeded`) keep their precedence; nothing else in
   `pollTick` changes.

Reason: C1 and C2 are the same bug, a stored status frozen at its first read.
Rule 1 fixes the selected job (C1), rule 2 fixes a finished job selected
later (C2); `ScanJobFacts.make` hides the one-beat gap between the list
turning terminal and the final status landing.

**Cancel gating.** `ScanPanelState.cancel(job:)` sends nothing when
`facts(for: job)?.summary.state` is `.cancelling` or terminal (idempotent
twice over: the engine's cancel already is). `cancelTarget` returns nil for a
cancelling job. **Amendment (2026-11-02, tester finding):** the "only running
job" fallback applies only when *no* job is selected; with a selected job
that is cancelling or terminal, ⌥⌘. and Scan ▸ Cancel Scan do nothing rather
than cancel a different job the operator is not looking at. The header's Cancel Scan button is disabled and titled
`Cancelling…` while the merged state is `.cancelling`; the row's hover Cancel
and the context-menu item are hidden for cancelling and terminal rows. The
`scan.cancel` reply (`cancelling`) is still applied through `applyStatus` so
the switch is immediate; the poll then carries the job to `cancelled`.

**Amendment (2026-11-02, PR 1 panel).** A cancel in flight counts as
cancelling. `ScanPanelState` keeps a `cancelsInFlight: Set<String>` of the
jobs whose `scan.cancel` has been sent and not yet answered; `cancel(job:)`
sends nothing while a cancel for that job is in flight (two presses within
one round trip send one `scan.cancel`, AC7), and `cancelInFlight(_ job:)
-> Bool` is exposed for the view, whose header verb reads `Cancelling…`
disabled from the press, not from the reply. The `cancelling` reply then
keeps the header in that state through `applyStatus` as before.

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
    /// `crawlTrouble` joined with " — " + `crawlErrorWords(lastError)` when `last_error` is present; nil when crawl.errors == 0.
    public static func crawlTroubleLine(_ crawl: ScanCrawlCounters) -> String?
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
text (UI md, `Tok.Ink.secondary`), then `crawlTroubleLine` when the crawl
had errors, then the error verbatim in
`Tok.Status.serverError`, and last the raw lines in the data face at
`Tok.Typography.Size.xs`, `Tok.Ink.tertiary`, selectable. The raw token never
appears anywhere else (glossary rule; coordinator ruling 3). Singulars:
`1 page`, `1 error`, `1 check`, `1 point` via `ScanFormat.plural`.

**Amendment (2026-11-02, PR 1 panel).** Three facts the panel pinned down:

- *The suffix follows the engine.* Today's engine sets `crawl.last_error`
  only when the crawl made at least one request and every one failed
  (`errors > 0 && pages == 0`, `crates/aitm-scan-model/src/job.rs`), so a
  crawl that fetched a page never carries it. That is an engine gap, logged
  as scanner amendment 89 for T1b's follow-up: the engine will set
  `crawl.last_error` to the latest closed token whenever `crawl.errors > 0`.
  The UI rule is the same on either core: the crawl-error count sentence
  (`crawlTrouble`) always shows when `errors > 0`, and the ` — <last_error
  words>` suffix shows only when the engine provides `last_error`. The
  dead-target job of today's live proof fetched 1 page, so its line is `The
  crawl fetched 1 page and hit 1 error` with no suffix; the suffix form,
  `The crawl fetched 0 pages and hit 1 error — the target refused the
  connection`, is the shape it takes and lands with amendment 89 (engine);
  it is not proven on today's core and is not a PR 1 acceptance.
  `ScanEndText.crawlTroubleLine(_:)` is the joined line the views render
  (PR 1's Stopped section, PR 2's attention list); no view spells the
  ` — ` join itself.
- *`sentence` needs a terminal status.* `ScanEndText.sentence` is nil unless
  the stored status is itself terminal: during the one-beat gap in which the
  list says terminal and the stored status is still live (plan gap 8), a
  stale non-terminal status yields nil rather than the live read's numbers.
- *The Stopped section is a terminal-job section.* In PR 1 it shows only
  for a job whose merged state is terminal and that has a stopped reason, an
  error, or crawl errors; a live job with crawl errors shows nothing there
  (PR 2's attention lines, D9, cover live jobs).

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
- `readFailure: ScanReadFailure?`, the one stored failure fact
  (`public struct ScanReadFailure: Equatable, Sendable { public var text: String; public var at: Int }`,
  a struct so `Equatable`/`Sendable` are synthesised), set by
  `noteReadFailure(text:now:)` from the list, status and cancel failure
  paths of `ScanPanelState`, cleared by `applyList`. `jobsError` is a
  computed alias of `readFailure?.text` and `readFailedAt` is computed from
  `readFailure?.at`; neither is stored.

```swift
public struct ScanJobsLink: Equatable, Sendable {
    public enum Kind: Equatable, Sendable { case live, reconnecting, disconnected, unanswered }
    public var kind: Kind
    public var valuesAgeMs: Int?      // max(0, now - jobsLoadedAt), nil before the first list
    public var bannerText: String?    // nil while live (D16 renders it)
    public var verbsEnabled: Bool     // kind == .live
    public static func make(bus: BusState, readFailedAt: Int?, jobsLoadedAt: Int?, now: Int) -> ScanJobsLink
}
```

Rules: `bus` is `.connecting` → `.reconnecting`; `.disconnected` or
`.failed` → `.disconnected`; `.connected` with `readFailedAt != nil` →
`.unanswered`; else `.live`. `ScanPanelState.link` computes it from
`session.bus` each render. In PR 1 the gate alone ships: Cancel Scan, the
hover Cancel and the context-menu Cancel are disabled while
`!link.verbsEnabled`; the existing inline list error keeps its text and gains
the last-good clause: `Unable to list jobs: <core text>. Showing values from
0:42 ago; retrying every 2 s.` (`ScanSurfaceModel.inlineJobsError(ageMs:)`,
the views' one entry point; the age clause is internal to the Kit).
`BusState` already lives in the Kit (`ConnectionSummary.swift`), so the
function is unit-testable.

Reason: C12 showed Cancel enabled against a frozen core for 30 s with no
word about the values' age.

**Amendment (2026-11-02, from the PR 1 live proof).** The Jobs poll is
sequential, so against a frozen core whichever read the freeze lands on
times out first (in the proof the selected job's *status* read: at ~30 s the
inline error read `Unable to read job scan-…: the bus did not reply in time`)
while the list read has not even been attempted; with `.unanswered` tied to
the list alone, Cancel stayed enabled. So: **any failed Jobs read** (list,
status, cancel) marks the link. `listFailedAt` is renamed `readFailedAt`, and
`readFailure: ScanReadFailure?` records the failed read's own wording
(`Unable to list jobs: …` / `Unable to read job <id>: …` / `Unable to cancel
job <id>: …`) with its time; `noteReadFailure(text:now:)` replaces
`noteListFailure`; `applyList` clears it (a list that lands is the proof the
core answers). `inlineJobsError(ageMs:)` returns `<text>. Showing values from
0:42 ago; retrying every 2 s.` for whichever read failed (the list beat is
what brings the values back), else nil. `ScanJobsLink.make(bus:readFailedAt:…)`
keeps its kind rules with the renamed input. AC12's live literal therefore
starts with whichever read failed first.

**Amendment (2026-11-02, PR 1 panel).** The shipped shape, which the
paragraphs above now use: one stored failure record,
`readFailure: ScanReadFailure?` (`ScanReadFailure { text: String; at: Int }`,
a struct, not a tuple, so `Equatable`/`Sendable` are synthesised; no `core`
field, it had no consumer); `jobsError` is a computed alias of
`readFailure?.text` and `readFailedAt` of `readFailure?.at`, so the three can
never disagree. `noteReadFailure(text:now:)` is called by the list, status
and cancel failure paths; `applyList` clears the record; a successful status
read clears nothing (a status answering is not proof the list answers).
`inlineJobsError(ageMs:)` is the one entry point the views read
(`readFailure.map { $0.text + <age clause> }`); the age clause is internal
to the Kit and there is no `ScanFormat.listErrorText`. Which read fails first
against a frozen core depends on where the freeze lands in the tick: on a
tick the list beat precedes the status beat, so the inline text starts with
whichever read failed first (`Unable to list jobs: …` or `Unable to read job
<id>: …`). The age clock is an independent 1 s task on `ScanPanelState`
(`clockTask`, started and cancelled with `poll()`), not the poll tick: the
poll loop is sequential and a read hung for the client's 30 s timeout must
not stall the clause (the proof read `from 0:02 ago` over values 36 s old).
D16 still holds: no view owns a timer; `nowMs` is the state's. `valuesAgeMs`
is clamped at 0 (`max(0, now - jobsLoadedAt)`: two stamps of the wall clock
within one tick can otherwise read negative for a beat).

#### D7. What PR 1 does not touch

PR 1 keeps `ScanJobRow`'s two lines and severity bar, the detail's sections,
the probe rule and every existing string except the *Stopped* section's. It
adds no motion, no new layout and no Scan Again. It is reviewable as a
behaviour fix plus a decoder extension, and it is the base PR 2 is cut from.

**Amendment (2026-11-02, PR 1 panel).** The Cancel help text stays PR 1's
words, `Stop this job; its issues stay (⌥⌘.)`, now one Kit constant
(`ScanFormat.cancelHelpText`); the hover-help wording of the UX section is
PR 2's (D11). The Stopped section shows only for a terminal job (D4
amendment); a live job with crawl errors shows nothing there in PR 1.

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

**Amendment (2026-11-02, locked comp).** `ScanJobProgress` gains four derived
values, each named as derived in its help text:

```swift
public struct ScanPace: Equatable, Sendable { public var secondsToGo: Int; public var checksPerSecond: Double }
extension ScanFormat {
    /// checks.done over elapsed_ms; nil unless running/auditing with scheduled > 0, done in 1…scheduled-1, elapsed > 0.
    public static func paceEstimate(done: Int, scheduled: Int, elapsedMs: Int) -> ScanPace?
    /// "3,232 checks to go" / "1 check to go"; nil when scheduled == 0 or done >= scheduled.
    public static func checksToGo(done: Int, scheduled: Int) -> String?
}
extension ScanJobProgress {
    public var checksToGoText: String?   // while auditing or reporting with scheduled > 0; nil otherwise and when terminal
    public var nowTag: String?           // "now · xss-reflected" / "now · xss-reflected and 3 more"; nil when nowLine is nil
    public var estimateText: String?     // "at this pace, about 1:04 to go"
    public var estimateHelp: String?     // "Derived from the counters: 3,236 checks done in 1:04, about 51 checks per second, 3,232 to go."
}
```

`paceEstimate`: `checksPerSecond = done / (elapsedMs / 1000)`;
`secondsToGo = ceil((scheduled - done) / checksPerSecond)`; nil while
crawling, passive, reporting, queued, cancelling or terminal, when
`elapsedMs == 0`, `done == 0` (rate 0), `scheduled == 0` or `done >=
scheduled`. The elapsed time includes the crawl, so the estimate is
conservative; it is an estimate from two bus counters and says so in its
help. `estimateText` formats `secondsToGo` with `ScanFormat.elapsed(ms:)`;
the help's rate is `Int(checksPerSecond.rounded())` with `ScanFormat.plural`
(`about 51 checks per second`, `about 1 check per second`), or `fewer than 1
check per second` when the rate rounds to 0. `nowLine` (`Now: …`) stays as
the parity string for the web and the TUI; `nowTag` is the lane's form
**(Architect's call: one derivation, two spellings, so P22 and the TUI's
`now` line do not move)**.

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
`skippedSamples`; the crawl trouble line (`crawlTroubleLine`, D4) with no
samples, shown as `The crawl fetched 0 pages and hit 1 error — the target
refused the connection` when `lastError` is set (today's engine sets it only
when the crawl fetched no page; scanner amendment 89 widens it, D4
amendment). `notices` is today's `clampedLines` plus
`skippedLaneText` rows, under one **Notices** title. Both render in every
state (a running job with check errors already shows them).

**Where the end state is shown (amended 2026-11-02, locked comp).** When
the selected job ends, the job card (D11) changes in three places, once per
job (D12's end swap): the lane's now tag is replaced by the end sentence
(`ScanEndText.sentence`, UI md, `Tok.Ink.primary`); the finding line's
reason line shows the stopped-reason sentence (UI base, `Tok.Ink.secondary`)
when there is one; the primary verb becomes Scan Again. The error verbatim
(data md, `Tok.Status.serverError`, selectable, wrapping), the attention
lines, the raw-token lines (data xs, `Tok.Ink.tertiary`: `stopped_reason:
errors`, `crawl.last_error: connect_refused`) and the Notices live in the
card's **attention block** under the KPI strip, rendered only when non-empty.
The verbs have one home, the title row, across live and finished jobs
**(Architect's call kept from the first draft: no button twice on one
card)**.

#### D10. The jobs table and its row (locked comp)

The Jobs tab is one scrolling column: banner (D15) → job card (D11) → jobs
table → wells (D11). The table is `ScanJobsTable` in `ScanPanel+Jobs.swift`:
a header row and one `ScanJobRow` per job, newest first, both laid out by one
`ScanJobsColumns` definition so cells align (builder's call: a SwiftUI `Grid`
or an `HStack` of fixed frames). Columns: **State** (flexible, min 148 pt),
**Profile** (120), **Target** (flexible, min 220, data face), **Progress**
(flexible, min 220, data face), **Probes** · **Points** · **Issues** ·
**Elapsed** (120 · 120 · 124 · 80, right-aligned, tabular), and a trailing
84 pt action column. Header: 32 pt, labels UI sm `Tok.Ink.tertiary` sentence
case (`ScanFormat.tableHeaders`: `State`, `Profile`, `Target`, `Progress`,
`Probes`, `Points`, `Issues`, `Elapsed`), no fill, no rule under it. Rows:
44 pt pitch (the comp's 46 on the 4 pt grid; a row with a sub-line grows to
60), `Rule(color: Tok.Line.rule)` between rows, padding `Space.sm` horizontal
per cell.

- **State cell**: an 18 pt leading slot (`Tok.Size.badge`), always present:
  `ScanProgressRing(ring:)` for a live job (`.determinate` → a `Circle`
  trimmed to `fraction`, stroke 2.5 pt, `Tok.Accent.base` over a full circle
  in `Tok.Line.control`, rotated −90°; `.indeterminate` →
  `ProgressView().controlSize(.small)`), or `ScanStateDot(tone:)` (6 pt) for
  cancelling (`Tok.Intercept.base`, breathing), done (`Tok.State.success.fg`),
  cancelled (`Tok.State.neutral.fg`), failed (`Tok.State.danger.fg`). When
  the job is agent-originated (`ScanFormat.agentOriginated(startedBy)`:
  `frontend` is `mcp` or `agent`) a 6 pt `Tok.Agent.base` dot with a 3 pt
  `Tok.Agent.tint` halo follows the slot (`.help("started by an agent")`).
  Then the word `ScanFormat.stateWord(facts)` (UI md 500, `Tok.Ink.primary`,
  `.contentTransition(.opacity)`): the phase word while running, the state
  word otherwise. A terminal row whose status has a stopped-reason sentence
  (D4) or an error shows it as a second line (UI sm, `Tok.Ink.secondary`,
  `.lineLimit(1)`, tail-truncated, `.help` the full text) **(Architect's
  call: the comp's `Stopped early: too many errors` is the D4 sentence cut by
  the column, not a second vocabulary)**.
- **Profile**: `ScanFormat.profileText(facts)` (`standard`; `—` until the
  status lands), UI md `Tok.Ink.primary`.
- **Target**: `ScanFormat.hostsText(facts)` (`127.0.0.1:8117`; `a.test,
  b.test`; `—`), data md `Tok.Ink.primary`, middle-truncated, `.help` the
  full list.
- **Progress**: `ScanFormat.rowProgressText(facts, progress)`, data md:
  `50 % · 3,236 of 6,468` while auditing with `scheduled > 0`; `46 pages, 12
  queued` while crawling; `Passive checks` while passive; `Scheduling checks`
  while auditing with `scheduled == 0`; `Writing results` while reporting;
  `—` while queued; `3,236 of 6,468` (checks) when terminal (`0 of 0` is the
  bus truth and is shown as such).
- **Probes**: `287` + ` of 2,000` with the unit in `Tok.Ink.secondary`
  (`ScanFormat.ofText(budget)`); **Points**: `97 of 1,020`; **Issues**:
  `ScanFormat.severityWordParts(by:)` each in `Tok.Severity.<level>.fg`
  (unknown level → info ink), or `no issues yet` (live) / `no issues`
  (terminal) in `Tok.Ink.tertiary`; **Elapsed**: `ScanFormat.elapsed(ms:)`,
  data sm tabular, `numericText` under D12's counter tick.
- **Action column**: a `Cancel` text button (`FlatButton("Cancel")`,
  `Tok.Ink.secondary`) shown on hover of a live row while `mayCancel &&
  link.verbsEnabled`, else empty; the column is always laid out so nothing
  shifts.
- **Backgrounds**: selected → `Tok.Ground.active` with a 3 pt `Tok.Accent.base`
  left edge (an overlay at the leading edge); hover → `Tok.Ground.hover`.
- **Caption**: no visible caption line (the comp has none; the tab's label
  carries the count). `ScanFormat.jobsCaption(total:running:)` (`4 jobs · 1
  running`) becomes the table container's `.accessibilityLabel`, replacing
  PR 1's `Jobs` **(Architect's call)**. The Scan page's Jobs tab label
  already reads `Jobs 5` (`ScanSurfaceModel.tabTitle`), as the comp shows;
  nothing changes there.
- **Context menu**: Cancel Scan (live, not cancelling), Scan Again
  (terminal), Show Issues, Show Site Map, divider, Copy Job ID.
- The `ScanSeverityBar` view and `ScanSurfaceModel.severityBarSegments`
  leave the Jobs view; they are deleted when no other view uses them (the
  builder greps), otherwise they stay untouched.

#### D11. The job card and the wells (locked comp)

The job card replaces the inspector. `ScanJobCard(facts:progress:link:…)` in
`ScanJobCard.swift` is composed of small views: `ScanJobTitleRow`, `ScanLane`,
`ScanIssueLedger`, `ScanProbeGauge`, `ScanKPIStrip`, `ScanAttentionBlock`;
the wells are `ScanJobWells` in `ScanJobWells.swift`. The card's **tone** is
a Kit value, `ScanFormat.tone(facts) -> ScanJobTone` (`.progress` while
queued or running, `.pending` while cancelling, `.success` when done,
`.danger` when failed, `.neutral` when cancelled), mapped to tokens once in
the app (`ScanToneColors` in `ScanProgressViews.swift`): edge and chip
foreground / chip background = `Tok.Accent.base` / `Tok.Accent.tint`;
`Tok.Intercept.base` / `Tok.Intercept.tint`; `Tok.State.success.fg` / `.bg`;
`Tok.State.danger.fg` / `.bg`; `Tok.State.neutral.fg` / `.bg` **(Architect's
call for queued → progress pair and cancelled → neutral, which the comp does
not show)**.

**Card chrome**: `Tok.Ground.card` (new token), 1 pt `Tok.Line.border`,
`Tok.Radius.floating` (10 pt; no new radius token, Architect's call),
`Tok.Shadow.float` (new), padding `Space.xl` vertical / `Space.xxl`
horizontal, a 3 pt left edge in the tone's colour clipped to the radius,
`Space.xl` below it before the table.

1. **Title row** (`ScanJobTitleRow`): the **chip** (`ScanStateChip`: 22 pt
   pill, `Tok.Radius.pill`, padding 9 pt, UI sm 500, the tone pair, a 6 pt
   dot in the foreground colour before the word, static), the **heading**
   `ScanFormat.jobHeading(facts)` = the hosts (`127.0.0.1:8117`; `a.test,
   b.test`; `a.test and 2 more` with `.help(jobHeadingHelp)`; the chip, not
   the heading, carries the state now), data face `Tok.Typography.Size.xxl`
   (24, new) semibold, `Tok.Ink.primary`, one line,
   `.accessibilityAddTraits(.isHeader)`; under them the **finding line**
   `ScanFormat.findingLine(facts, timeZone:) -> ScanFindingLine`:

   ```swift
   public struct ScanFindingLine: Equatable, Sendable {
       public enum Role: Equatable, Sendable { case plain, figure, checkId, agent }
       public var reason: String?                      // the stopped-reason sentence, terminal only
       public var parts: [(text: String, role: Role)]  // joined, they are `text`
       public var text: String
       public var agentOriginated: Bool
   }
   ```

   Live: `<issuesSoFar> · <nowClause> · <profile> · started <h:mm> by <who>`
   with `ScanFormat.issuesSoFar(by:)` (`no issues so far` / `4 low issues so
   far` / `1 high issue so far` / `5 issues so far: 1 high, 4 low`),
   `ScanFormat.nowClause(running:)` (`xss-reflected running now` /
   `xss-reflected and 3 more checks running now` / nil → clause omitted),
   D11's former subtitle words for `<profile>` and `started <h:mm> by <this
   app | the CLI | an agent | <label> | the operator>`. Terminal: `reason` =
   `ScanEndText.stoppedReason(...)` (nil when none), `text` = `<profile> ·
   started <h:mm> by <who> · finished <h:mm>`. Rendering: UI base
   `Tok.Ink.secondary`; `.figure` parts (the counts) and `.checkId` parts in
   `Tok.Ink.primary`, check ids in the data face; the `.agent` part (`an
   agent`) in `Tok.Agent.base`; the reason line above the text in the same
   style. Right of the title: the **verbs**, 32 pt (`Tok.Size.controlLg`):
   `FlatButton("Show Site Map")`, `FlatButton("Show Issues")`, then the
   primary: `PrimaryButton("Cancel Scan")` while live (disabled and titled
   `Cancelling…` while cancelling or a cancel is in flight, D2) or
   `PrimaryButton("Scan Again")` when terminal (D13). The slot is disabled
   while `!link.verbsEnabled` (D6, D15); the first enabled button takes
   `.focused(inspectorFocused)`; `.onExitCommand` returns focus to the table
   and clears `scanAgainError`. `Unable to scan again: <display>` renders
   under the title row (D13).
2. **Scan lane** (`ScanLane(progress:facts:reduceMotion:)`): a 64 pt track
   (`Tok.Size.Row.card`) on `Tok.Ground.raised`, `Tok.Radius.panel`, with a
   1 pt top highlight at 3 % of `Tok.Ink.primary`. While auditing, reporting
   or terminal with `scheduled > 0`: a **crawl cap** in `Tok.Accent.deep` as
   wide as its labels (`CardMetrics.crawlCapWidth`, about 80 pt: the bus
   carries no crawl duration, so the cap is layout, not a proportion;
   labels `crawl` / `46 pages`), then the **audit fill** in `Tok.Accent.base`
   whose width is `fraction × (track − cap)` (labels `audit` / `3,236 checks
   done`; `ScanFormat.laneChecksDone(done:)`), then the empty track with
   `progress.checksToGoText` (`3,232 checks to go`) at the top right in
   `Tok.Ink.tertiary` (hidden when the empty part is narrower than it;
   builder's call). Segment labels sit at 10 pt from the top and bottom, 12
   pt from the left, UI sm 500 / UI sm at 75 % in `Tok.Ink.onAccent`, and
   hide when the segment is narrower than they are. The **now mark**: 2 pt
   wide, `Tok.Ink.primary`, overshooting the track by 10 pt above and below,
   a 3 pt halo of `Tok.Ink.primary` at 12 % opacity, a 10 pt dot of
   `Tok.Ink.primary` on its top end that breathes (D12); it sits at the
   fill's trailing edge and eases with it. The **now tag** `progress.nowTag`
   (`now · xss-reflected and 3 more`; the ids in the data face) is centred
   under the mark, clamped inside the track's width, UI sm
   `Tok.Ink.secondary`; absent when nil. The **scale row** 40 pt below the
   track: `started 11:32` (`ScanFormat.scaleStarted(clock)`) · `elapsed
   1:04` (`scaleElapsed`) · `progress.estimateText` (`at this pace, about
   1:04 to go`, with `.help(progress.estimateHelp)`; its slot is empty when
   nil), UI sm `Tok.Ink.tertiary`, numbers data face. Other phases: crawling
   → one crawl segment at the crawling fraction (`crawl` / `46 pages, 12
   queued`), no mark, no right label, no estimate; passive or queued → an
   empty track with the phase line centred inside in `Tok.Ink.secondary`,
   no mark; auditing with `scheduled == 0` → the cap and `Scheduling checks`
   inside the empty track; reporting → a full fill with `Writing results` as
   the now tag; cancelling → frozen at its value, the dot stops breathing;
   terminal → frozen at `.finished(f)`, the mark and the right label gone,
   the now tag replaced by `ScanEndText.sentence(facts)` (UI md,
   `Tok.Ink.primary`, left-aligned under the track; empty for the beat in
   which the terminal status has not landed). Accessibility: the lane is one
   element (`children: .ignore`) labelled `Progress` with value
   `ScanFormat.progressAccessibilityValue(progress)` (`50 percent`) or the
   phase line when indeterminate; `.help(progress.helpText)`.
3. **Issue ledger** (`ScanIssueLedger(groups:running:)`):
   `ScanFormat.ledgerGroups(by:) -> [ScanLedgerGroup]` (`severity`, `count`,
   `marks = min(count, 12)`, `word` = `4 low`), ordered critical → info,
   zero counts omitted; each mark 8 × 16 pt, 2 pt radius, in
   `Tok.Severity.<level>.fg`, 3 pt apart; the count word UI sm 500 in the
   same ink 6 pt after the marks; groups 16 pt apart; 14 pt below the scale
   row; min height 20 pt so nothing shifts; empty → `no issues yet` / `no
   issues` in `Tok.Ink.tertiary`. The cap of 12 marks per group keeps a
   200-low job readable; the word carries the true count **(Architect's
   call)**. One accessibility element: `ScanFormat.issuesTileHelp(by:)` (`4
   issues: 4 low`).
4. **Probe budget gauge** (`ScanProbeGauge(sent:budget:)`): label `probe
   budget` (`ScanFormat.gaugeLabel`, UI sm `Tok.Ink.secondary`), a 3 pt
   track on `Tok.Ground.raised`, fill `Tok.Ink.tertiary` at `sent / budget`,
   `Tok.Intercept.base` when `ScanFormat.budgetWarning(sent:budget:)` (`sent
   > 0.8 × budget`, `budget > 0`); text `ScanFormat.probeBudgetText(sent:budget:)`
   (`287 of 2,000`; `287 probes` with the track hidden when `budget == 0`,
   Architect's call) in the data face, `Tok.Ink.secondary`, `numericText`.
   One accessibility element `Probe budget, 287 of 2,000`;
   `.help(ScanFormat.probesTileHelp(sent:budget:))`.
5. **KPI strip** (`ScanKPIStrip(facts:progress:)`): one container on
   `Tok.Ground.surface`, 1 pt `Tok.Line.border`, `Tok.Radius.panel`, 20 pt
   below the gauge, split into five equal `ScanKPICell`s by 1 pt
   `Tok.Line.border` dividers, padding 14/16: **Progress** →
   `progress.percentText` or `—` (`ScanFormat.missingValue`) in
   `Tok.Accent.base` (the lead figure); **Checks** → `grouped(done)` +
   `of 6,468`; **Probes** → `grouped(sent)` + `of 2,000`; **Points audited**
   → `grouped(audited)` + `of 1,020`; **Issues** → `grouped(total)` +
   `severityWords` in the severity ink (`no issues yet` / `no issues` in
   `Tok.Ink.tertiary`). Labels `ScanFormat.kpiLabels` UI md
   `Tok.Ink.secondary`; numerals data face `Tok.Typography.Size.display` (28,
   new) regular tabular `Tok.Ink.primary`, `numericText` under D12's counter
   tick; units UI md `Tok.Ink.secondary` 8 pt after. Cell hover
   `Tok.Ground.hover`. Each cell `.accessibilityElement(children: .combine)`
   (`Progress, 50 percent`; `Probes, 287 of 2,000`); Progress
   `.help(progress.helpText)`, Probes `.help(probesTileHelp)`, Issues
   `.help(issuesTileHelp)`.
6. **Attention block** (`ScanAttentionBlock(facts:launchNotices:)`, D9),
   `Space.lg` below the strip, only when non-empty: `DisclosureGroup`s for
   `ScanEndText.attention(facts)` rows with samples (label UI md
   `Tok.Ink.primary`; content `(check, detail)` in data sm,
   `Tok.Ink.secondary`, selectable), plain text for a row without samples;
   the Failed error verbatim (data md, `Tok.Status.serverError`, selectable,
   wrapping); the raw lines `rawReasonLine` / `rawCrawlErrorLine` (data xs,
   `Tok.Ink.tertiary`, selectable); `ScanSectionTitle("Notices")` +
   `ScanEndText.notices(status, launchNotices:)` when non-empty.

**Wells** (`ScanJobWells(facts:)`): two `ScanWell(title:subtitle:rows:)`
side by side, 16 pt apart, 28 pt below the table: `Tok.Ground.card`, 1 pt
`Tok.Line.border`, `Tok.Radius.floating`, `Tok.Shadow.rest` (new), padding
16/20; title UI base 500 `Tok.Ink.primary` with the subtitle UI sm
`Tok.Ink.tertiary` at the right; rows 28 pt split by `Tok.Line.rule`, keys UI
md `Tok.Ink.secondary`, values data md tabular `Tok.Ink.primary` (`—` until
the status lands). **Crawl and points** ("what the job found to test"):
Pages fetched · Pages waiting · Depth · Forms submitted · Forms not submitted
· Crawl errors (only when > 0) · Points found · Waiting for audit · Audited ·
one row per `pointSkipWords` entry (`722 skipped as repetitive`, `6 skipped
by rule`, `0 skipped at the per-request cap`) · Lanes (`HTTP, WebSocket`;
skipped lanes with reasons as further rows) · Probes by lane (`HTTP 240 ·
WebSocket 47`) · Session (only when `status.session != nil`: `reused · lost ·
canary · browser partial` as `no · no · ok · no`) · L4 rows (only when
present). **Issues** ("by severity and confidence"): `Critical · High ·
Medium` → `0 · 0 · 0` (each count in its severity ink when > 0,
`Tok.Ink.tertiary` when 0) · `Low` · `Info` · `Certain · Firm · Tentative` →
`1 · 2 · 1` · `Probe errors · timeouts · rate waits` → `0 · 0 · 0` · `Checks
scheduled · done · errors · skipped` → `6,468 · 3,236 · 7 · 3`. Every key is a
`ScanFormat` constant (`wellKeys`); `Points ▸ Queued` is `Waiting for audit`
and `Skipped frequent` is `skipped as repetitive` (C9). The Session and Lanes
sections of the old inspector are gone as sections (C9); their facts survive
as the rows above **(Architect's call)**.

**Tokens, exhaustively**: grounds `Tok.Ground.surface / card / raised /
active / hover`; lines `Tok.Line.border / rule / control`; inks
`Tok.Ink.primary / secondary / tertiary / onAccent`; accent `Tok.Accent.base
/ deep / tint`; `Tok.Agent.base / tint`; `Tok.Intercept.base / tint`;
`Tok.State.success / danger / neutral` pairs; `Tok.Status.serverError`;
`Tok.Severity.<level>.fg`; faces `Tok.Face.ui(...)` / `Tok.Face.data(...)`
at `Tok.Typography.Size.xs / sm / md / base / xxl / display`; radii
`Tok.Radius.panel / floating / pill`; shadows `Tok.Shadow.float / rest`;
sizes `Tok.Size.badge / controlLg / Row.card`; spacing `Space.*`. The comp's
geometric constants that are not tokens (edge 3, now mark 2, overshoot 10,
dot 10 and 6, halo 3, gauge 3, mark 8 × 16 radius 2, ring stroke 2.5, crawl
cap 80, row pitch 44, header 32, action column 84, halo opacity 0.12,
breathing floor 0.4) live once in `private enum CardMetrics` in
`ScanJobCard.swift` with a comment naming the comp's CSS rule; no colour,
radius or duration literal appears in `ScanPanel+Jobs.swift`,
`ScanJobCard.swift`, `ScanJobWells.swift` or `ScanProgressViews.swift`
(AC22's grep and `grid-lint` are the check).

#### D12. Motion (locked comp)

`ScanMotion` lives in the app target (`apps/mac/Sources/Aitmproxy/UI/ScanMotion.swift`,
beside `Tokens.swift`), because `Tok.*` is app-only and the Kit has no
SwiftUI; every constant is a `Tok.Motion` token, so the file carries no
numeric literal:

```swift
enum ScanMotion {
    static let counter = Tok.Motion.counter          // 150 ms, digit ticks (new token)
    static let progress = Tok.Motion.progress        // 250 ms, lane fill / now mark / ring (new token)
    static let state = Tok.Motion.popover            // 160 ms, chip crossfade and edge recolour
    static let entrance = Tok.Motion.sheet           // 220 ms, the card's blocks rise and fade in
    static let stagger = Tok.Motion.stagger          // 60 ms between blocks (new token)
    static let endSwap = Tok.Motion.sheet            // 220 ms, now tag → end sentence, verb swap
    static let hoverReveal = Tok.Motion.hover        // 100 ms, the row's Cancel
    static let breath = Tok.Motion.interceptPulse    // 1200 ms, one breath
    static func ease(_ duration: Double) -> Animation { Tok.Motion.easeOut(duration) }
    static func breathe() -> Animation { Tok.Motion.pulse(breath).repeatForever(autoreverses: true) }
}
```

`tokens.json` gains (Task 2.1; generators re-run): `motion.counter` `150ms`
("Live counter digit ticks; opacity/translate of the digits only"),
`motion.progress` `250ms` ("A progress fill, mark or ring easing to a new
value; never snaps"), `motion.stagger` `60ms` ("The delay between the Jobs
card's blocks in its one entrance"); `color.ground.card` light `#FFFFFF`,
dark `#232326` ("The raised job card and the wells: one tone above surface
and below raised in dark; white with a border and a shadow in light");
`shadow.float` light `0 12px 32px rgba(17,24,39,0.10), 0 1px 2px
rgba(17,24,39,0.06)`, dark `0 12px 32px rgba(0,0,0,0.42), 0 1px 0
rgba(255,255,255,0.04) inset` ("The selected job's card"); `shadow.rest`
light `0 4px 14px rgba(17,24,39,0.08)`, dark `0 4px 14px rgba(0,0,0,0.28)`
("A resting card: the Jobs wells"); `typography.size.xxl` `24px` ("The job
card's heading") and `typography.size.display` `28px` ("KPI numerals"). The
light values, the two type sizes and the stagger token are **(Architect's
call)**; the mac generator emits the first shadow layer only (its
`FloatingShadow` shape), so the inset highlight is web-only. The
`shadow.$description` becomes "Shadows on what floats and on the Jobs tab's
raised cards (float: the selected job's card; rest: the wells); other
resting panels get none." and `motion.$description` names the one entrance:
"Feedback only, plus one named entrance: the Jobs card's staggered rise when
a job becomes selected (Jobs view spec D12). Keyboard-initiated actions never
animate. Reduced-motion drops travel, keeps opacity." `$version` bumps to
`0.2.0`.

| Change | Mechanism (mac) | Reduce Motion |
| --- | --- | --- |
| Entrance | `ScanPanelState.entranceGeneration: Int` increments when the selection changes by pointer, by a start this app or another client made, or by the first list; never by keyboard (`moveSelection` runs inside `withTransaction(Transaction(animation: nil))` and does not bump it) and never by a status beat. The card's title row, lane (with ledger and gauge), KPI strip, and the wells carry `.id(generation)` with `.transition(.opacity.combined(with: .offset(y: 8)))` and `.animation(ScanMotion.ease(ScanMotion.entrance).delay(Double(index) * ScanMotion.stagger), value: generation)` for block index 0…3; the table takes part only on the first generation (the tab's first selected job): on a row click the operator is pointing at the table, which must not move **(Architect's call)** | `.transition(.opacity)` with the same delays |
| Lane fill, now mark, ring | frame widths / offsets / `trim(to:)` under `.animation(ScanMotion.ease(ScanMotion.progress), value: fraction)`; a falling value (scheduled grew) eases down, never clamps | `.animation(nil)` |
| Counter ticks | `.contentTransition(.numericText())` on every number `Text` (KPI numerals, lane labels, row cells, elapsed) under `.animation(ScanMotion.ease(ScanMotion.counter), value: <the number>)` | `.contentTransition(.identity)` |
| Ledger mark arrival | marks in a `ForEach` keyed by group and index with `.transition(.opacity.combined(with: .offset(y: 3)).combined(with: .scale(scale: 0.6, anchor: .bottom)))` under `.animation(ScanMotion.ease(ScanMotion.entrance), value: groups)` | `.transition(.opacity)` |
| Chip and edge | `.contentTransition(.opacity)` on the chip's word; the chip's pair and the card edge's colour under `.animation(ScanMotion.ease(ScanMotion.state), value: tone)` (the one place a colour animates) | same |
| End swap | a `ZStack` holding the now tag or the end sentence, and the primary verb slot, each `.transition(.opacity.combined(with: .offset(y: 2)))`; the now mark `.opacity(live ? 1 : 0)`; all inside `withAnimation(ScanMotion.ease(ScanMotion.endSwap))` when `facts.summary.state.isTerminal` flips | `.transition(.opacity)` |
| Hover Cancel | `.opacity(hovered ? 1 : 0)` with `.animation(ScanMotion.ease(ScanMotion.hoverReveal), value: hovered)` in the fixed action column | same |
| Button press | the existing `FlatButton` / `PrimaryButton` press style (120 ms, scale 0.97) | existing |
| Breathing | `Breathing()` modifier in `ScanProgressViews.swift`: `.opacity(on ? 1 : CardMetrics.breathFloor)` toggled once in `.onAppear` inside `withAnimation(ScanMotion.breathe())`; applied to exactly two dots: the now mark's dot while the job is live and not cancelling, and the cancelling dot (the row's and the chip's); nowhere else, and not on the chip's running dot **(the comp breathes it; the brief limits breathing to two dots, kept here)** | opacity 1, no animation |
| Indeterminate | `ProgressView().controlSize(.small)` | system |
| Keyboard selection, tab switch | none (no entrance, no eases) | none |

`@Environment(\.accessibilityReduceMotion) private var reduceMotion` is read
in `ScanJobsTab` and passed down; each row of the table picks its right-hand
column when it is true. `TimelineView` is not allowed anywhere in the Jobs
views: every counter comes from the poll, the entrance from the state's
generation, the breathing from a system-driven repeating animation; no view
owns a `Timer` or sleeps (AC32). Web: CSS `transition` on `transform` /
`opacity` / `width` with `var(--motion-ease-out)` and the new
`--motion-counter` / `--motion-progress` / `--motion-stagger`; the comp's
stylesheet is the reference; the existing global `prefers-reduced-motion`
rule in `base.css` already zeroes durations. TUI: none.

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
  rendered under the card's title row as `Unable to scan again: <display>` (UI sm,
  `Tok.Status.serverError`, selectable), cleared by the next successful
  start, by selecting another job, or by Escape. The Profiles footer's
  `statusLine` is not touched (that is Start Scan's home).
- **Homes**: the card's verb slot (terminal jobs) and the row context menu
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
- **Card**: the host heading has `.isHeader`; the lane is one element with
  `.accessibilityLabel("Progress")` and `.accessibilityValue("50 percent")`
  (the phase line as its value when indeterminate); the ring, the dots, the
  now mark and the ledger marks are `.accessibilityHidden(true)`; the
  ledger and the gauge are one element each (`4 issues: 4 low`; `Probe
  budget, 287 of 2,000`); KPI cells are `.accessibilityElement(children:
  .combine)` reading label then value (`Probes, 287 of 2,000`); the estimate
  carries its derived help; the verb buttons carry their help text as
  `.accessibilityHint`; the end sentence is one static text; disclosure
  groups are system `DisclosureGroup`s (expanded/collapsed is announced by
  the system); the chip's word is read as part of the title row.
- **Announcement**: when the selected job's merged state goes from
  non-terminal to terminal, `ScanPanelState` posts one
  `NSAccessibility.post(element: NSApp, notification: .announcementRequested,
  userInfo: [.announcement: text, .priority: NSAccessibilityPriorityLevel.medium.rawValue])`
  with `text = ScanFormat.endAnnouncement(facts)`: `Scan of 127.0.0.1:8117
  done: 4 issues.` / `… cancelled: 4 issues.` / `… failed.` / `… done: no
  issues.` Once per job (a `Set<String>` of announced ids).
- **Keyboard**: Tab order Scan tabs → the card's verbs → the table →
  disclosures and wells. In the table: ↑↓ move the selection (no animation,
  no entrance), Return or → calls `inspectorFocused = true` (`@FocusState`
  on the card's first enabled verb), Escape from the card returns focus to
  the table, ⌥⌘. is Cancel Scan (existing). The context menu is reachable with the keyboard
  through the system's menu key / ⌃-click as today.
- Text is never below `Tok.Typography.Size.xs` (11 pt); every colour pair is
  a token pair, so Increase Contrast keeps ≥ 4.5:1.

#### D15. Bus-disconnected banner (F5, C12)

`ScanJobsLink.bannerText` (D6) is rendered in PR 2 above the job card as an
inline banner (`ScanInlineError`'s shape, but in `Tok.Ink.secondary` on
`Tok.Ground.raised`, not the error ink: nothing failed, the bus is away):

| kind | text |
| --- | --- |
| `.reconnecting` | `Bus disconnected · showing values from 0:42 ago · reconnecting…` |
| `.disconnected` | `Bus disconnected · showing values from 0:42 ago · Proxy ▸ Reconnect Bus (⌃⌘R) to retry` |
| `.unanswered` | `The core is not answering · showing values from 0:42 ago · retrying every 2 s` |

The age clause is `ScanFormat.elapsed(ms: valuesAgeMs)` and is omitted while
`jobsLoadedAt` is nil. The `now` that drives it is `ScanPanelState.nowMs`,
the state's 1 s clock task (D6 amendment; the view has no timer). Rows keep their last values; the hover Cancel is
hidden; the card's verb slot, Scan Again and the context-menu Cancel are
disabled (D6); the now mark's dot stops breathing (the values are stale). The
inline list error (D6) keeps rendering when `jobsError != nil`, under the
banner.

#### D16. Performance and render budget

The card re-renders when `facts(for:)` changes: once per status beat (1 s)
for a live selected job, once per list beat (2 s) for the rows. No view owns
a `Timer` or a `TimelineView`; the banner age and the scale row's elapsed
come from the facts and the state's 1 s clock (`nowMs`, D6 amendment); the
entrance is driven by `entranceGeneration` (D12), the breathing by a
system-driven repeating animation. `ScanJobProgress` and `ScanEndText` are value
computations on a struct with at most a few hundred bytes; the builder does
not memoise them.

#### D17. Words added by this spec (D12 of the mac spec extended)

Every string lives in `ScanSurface.swift` (`ScanFormat` or `ScanEndText`).
New buttons: `Scan Again`, `Cancelling…`. New sentences: D4's table, D8's
phase lines and derived texts (`3,232 checks to go`, `now · …`, `at this
pace, about 1:04 to go` and its help), D9's attention lines, D15's banners,
the help strings of the UX section verbatim, `Unable to scan again:
<reason>`, `Select a finished job.`, `<n> jobs · <n> running`, the finding
line's clauses (`no issues so far`, `4 low issues so far`, `5 issues so far:
1 high, 4 low`, `xss-reflected and 3 more checks running now`, `started
<h:mm> by <who>`, `finished <h:mm>`), the chip words, the table headers, the
lane labels (`crawl`, `audit`, `46 pages`, `3,236 checks done`, `started
11:32`, `elapsed 1:04`), `probe budget`, `287 of 2,000`, `287 probes`, the
KPI labels (`Progress`, `Checks`, `Probes`, `Points audited`, `Issues`), `—`,
the well titles and subtitles (`Crawl and points` / `what the job found to
test`; `Issues` / `by severity and confidence`) and keys (`Pages fetched`,
`Pages waiting`, `Depth`, `Forms submitted`, `Forms not submitted`, `Crawl
errors`, `Points found`, `Waiting for audit`, `Audited`, `Lanes`, `Probes by
lane`, `Session`, `Critical · High · Medium`, `Low`, `Info`, `Certain · Firm
· Tentative`, `Probe errors · timeouts · rate waits`, `Checks scheduled ·
done · errors · skipped`), `skipped as repetitive`, `skipped by rule`,
`skipped at the per-request cap`, `started by an agent`. Glossary terms only; `stop`,
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

**Amendment (2026-11-02, locked comp).** W2 above describes the first
draft's row + inspector layout. The locked comp is HTML and CSS
(`docs/design/mockup/scan-jobs/committed.html`), so W2 reproduces the comp's
composition (card, lane, ledger, gauge, KPI strip, table, wells) with the
tokens as CSS variables (`--color-ground-card`, `--shadow-float`,
`--shadow-rest`, `--motion-counter`, `--motion-progress`, `--motion-stagger`)
and the same derived values (`jobProgress` gains `checksToGoText`, `nowTag`,
`estimateText`, `estimateHelp`; `findingLine`, `ledgerGroups`,
`budgetWarning` are added to `helpers.ts` with the mac literals). The W2
paragraph and Tasks 3.5, 3.7 and 3.8 are re-cut to the comp by a spec and
plan amendment before Part 3 opens; W1 is unchanged.

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
  `ScanFormat.stateWord`, `profileText`, `hostsText`, `rowProgressText`,
  `jobHeading`, `findingLine`, `issuesSoFar`, `nowClause`, `tone`,
  `ledgerGroups`, `budgetWarning`, `probeBudgetText`, `paceEstimate`,
  `checksToGo`, `jobAccessibilityLabel`, `elapsedWords`, `severityWords`,
  `jobsCaption`,
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
  recorded as not reproducible); many jobs (≥ 4 rows, the tab label `Jobs
  4`);
  bus disconnected (`kill -STOP` the core for 35 s, frame at 10 s and 35 s;
  then `kill -CONT` and a frame showing recovery); the gauge amber and the
  budget sentence (a saved profile `tiny-budget` with a probe budget of 50:
  the gauge turns intercept past 40 probes and the job ends `stopped_reason:
  budget`); the ledger with two severities (`light-http` on the test target
  ends `1 high, 2 low`); the entrance (a recording of a row click, and of a
  ↓ key press that must show none); a job started from
  another bus client (a `tools/call` script or an MCP agent; the CLI's
  one-shot verb table has no `scan.start`) appearing selected with nothing
  else selected;
  VoiceOver reading one row (a screen recording or the AX dump's label).
  Web: the same states through `apps/web/scripts/scan-live.mjs` (real web
  app + real core + headless Chrome; merged in #293 and wrapped by the e2e
  cell `test_t8_web_live`), extended with steps for the Jobs view states;
  `scripts/shot.mjs` only for stills. Its step 03c races at phase
  boundaries, so a new step polls the terminal *state*, never the word. TUI:
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
1b. **AC1b (P1, D1 amendment; unit).** A `scan.status` object whose
   `checks.error_samples[0].detail` is 1,000 characters containing U+202E
   and `\n` decodes to a `detail` of exactly 400 Unicode scalars with neither
   scalar present; `error_samples` of nine objects decodes to
   `errorSamples.count == 8`; a `crawl.last_error` of 200 characters
   containing a control character decodes to `.unknown(raw)` whose
   `rawValue` is 64 clean characters.
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
   Scan: within 1 s the header reads `Cancelling…` (button disabled; the
   frame comes from a frame loop started before the press and is shot within
   1 s of it); within
   5 s both the row and the header read `Cancelled`, the button is gone,
   `Running: <id>` is absent, and the frame taken 60 s later is identical in
   those fields. A concurrent `scan.status` read shows `state: cancelled`.
6. **AC6 (P1, D2, C2; live).** Let `light-http` finish while another job is
   selected; select it afterwards: the detail reads `Done`, its probes and
   checks counters equal the concurrent `scan.status` (`checks.done ==
   checks.scheduled`, non-zero), and Cancel Scan is not shown.
7. **AC7 (P1, D2; unit + live).** With the merged state `.cancelling`,
   `ScanPanelState.cancelTarget == nil` and `cancel(job:)` sends nothing
   (the command recorder logs no second `scan.cancel`); live: the proof
   sends ⌥⌘. twice within a second through a key tool (two real key events,
   not an AX press of a button that may already be gone) and the core's
   audit log shows exactly one `scan.cancel`.
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
    `The crawl fetched 1 page and hit 1 error` (no ` — ` suffix: the job
    fetched 1 page, so today's engine sets no `crawl.last_error`, D4
    amendment), then a data-face line `stopped_reason: errors`; the token
    `errors` appears nowhere else in the pane (AX dump grep). The suffix
    form `The crawl fetched 0 pages and hit 1 error — the target refused
    the connection` lands with amendment 89 (engine); it is not proven on
    today's core and is not a PR 1 acceptance. Its shape is pinned at unit
    level: `crawlTroubleLine(pages 0, errors 1, lastError .connectRefused)
    == "The crawl fetched 0 pages and hit 1 error — the target refused the
    connection"`, `crawlTroubleLine(pages 1, errors 1, lastError nil) ==
    "The crawl fetched 1 page and hit 1 error"`, `crawlTroubleLine(errors 0)
    == nil`.
11. **AC11 (P1, D5, C10; live).** `tools/axdump.swift` on the real window
    with three jobs lists exactly three row elements under the `Jobs`
    container, each with the label `ScanFormat.jobAccessibilityLabel`
    produces (starts with the state or phase word), role button, and the
    selected one carrying the selected attribute (`AXSelected` true in the
    dump, which prints `AXSelected`/`AXFocused` per row; the others nil or
    false, since an unselected row carries no `.isSelected` trait).
12. **AC12 (P1, D6, C12; unit + live).** `ScanJobsLink.make(bus:
    .connecting("…"), readFailedAt: nil, jobsLoadedAt: 1_000, now: 43_000)`
    gives `kind == .reconnecting`, `valuesAgeMs == 42_000`, `verbsEnabled ==
    false`; `(.connected("…"), readFailedAt: 5_000, …)` gives `.unanswered`;
    `(.connected, nil, …)` gives `.live`, `verbsEnabled == true`;
    `(.disconnected, …, jobsLoadedAt: nil)` gives `valuesAgeMs == nil`.
    Live: `kill -STOP` the core with a running job selected; at 35 s the
    inline error reads `Unable to read job <id>: <core text>. Showing values
    from 0:3x ago; retrying every 2 s.` or `Unable to list jobs: …` with the
    same clause (which read fails first depends on where the freeze lands in
    the tick, D6 amendment; the proof asserts the inline text literal, and
    the age in the clause advances between two frames taken after the 30 s
    client timeout, about 36 s and 47 s), Cancel
    Scan is disabled and the hover Cancel hidden, the rows keep their
    values; after `kill -CONT` the error clears within 5 s of the next list
    and Cancel Scan is enabled. The `ScanJobsLink.make` unit cases use
    `readFailedAt:`; `valuesAgeMs` is clamped at 0 (`jobsLoadedAt` later
    than `now` gives `0`, never a negative).

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
14. **AC14 (P2, D8, D11, C3; live).** During `standard`'s auditing phase
    the card's lane shows the audit fill at the checks fraction (fill width ÷
    (track − crawl cap) within 0.02 of `done / scheduled` from the concurrent
    `scan.status`), the KPI Progress numeral is within 1 of `floor(100 *
    done / scheduled)`, the probe budget appears only in the gauge, the
    Probes KPI cell and the Probes column (never as the lane or a full-width
    bar), and the table row's ring and progress text read the same fraction
    and percent.
15. **AC15 (P2, D9; unit).** `ScanEndText.sentence` for `done`, elapsed
    69_000, points.found 1020, checks.scheduled 6468 is `"Done in 1:09 ·
    1,020 points · 6,468 checks."`; for `cancelled`, 115_000, done 3236,
    scheduled 6468 is `"Cancelled after 1:55; 3,236 of 6,468 checks had run.
    What it found stays."`; for `failed`, 12_000 is `"Failed after 0:12."`;
    for `running` is `nil`. `attention` for `checks.errors 7` with one
    sample gives `[("7 checks could not run", 1 sample)]`; `checks.errors
    1` gives `"1 check could not run"`; `checks.skipped 3` gives `"3 checks
    were skipped"`; `crawl.pages 0, errors 1, lastError .connectRefused`
    gives `"The crawl fetched 0 pages and hit 1 error — the target refused
    the connection"` with no samples (`crawlTroubleLine`, D4 amendment);
    `crawl.pages 1, errors 1, lastError nil` gives `"The crawl fetched 1
    page and hit 1 error"`; all zero gives `[]`.
16. **AC16 (P2, D9, D11; live).** The dead-target job's card shows the chip
    `Done`, the finding line's reason `Stopped early: too many errors from
    the target.` above `standard · started <h:mm> by this app · finished
    <h:mm>`, the lane's end sentence `Done in 0:3x · 0 points · <n> checks.`
    where the now tag was, then in the attention block the disclosure `7
    checks could not run` which opens to rows whose first detail is
    `Connection refused (os error 61)`, then `The crawl fetched 1
    page and hit 1 error` (no suffix on today's core: the job fetched a
    page, so the engine sets no `last_error`; the suffix form `… — the
    target refused the connection` lands with amendment 89 (engine) and is
    not a PR 2 acceptance on today's core, D4 amendment); the raw line
    `stopped_reason: errors` is the only place the token appears.
17. **AC17 (P2, D10, C4, C5; unit).** `stateWord(facts running/auditing) ==
    "Auditing"`, `(cancelling) == "Cancelling"`, `(done) == "Done"`;
    `profileText(status profile "standard") == "standard"`, `(status nil) ==
    "—"`; `rowProgressText(auditing 3236/6468) == "50 % · 3,236 of 6,468"`,
    `(crawling 46 pages, 12 queued) == "46 pages, 12 queued"`, `(passive) ==
    "Passive checks"`, `(queued) == "—"`, `(done 6468/6468) == "6,468 of
    6,468"`; `severityWords(by: 4 low, running: true) == "4 low"`;
    `severityWords(1 high 3 low, false) == "1 high, 3 low"`;
    `severityWords(zero, running: true) == "no issues yet"`, `(zero, false)
    == "no issues"`; `jobsCaption(total: 4, running: 1) == "4 jobs · 1
    running"`, `(1, 0) == "1 job"`, `(3, 0) == "3 jobs"`;
    `ScanFormat.tableHeaders == ["State", "Profile", "Target", "Progress",
    "Probes", "Points", "Issues", "Elapsed"]`.
18. **AC18 (P2, D10, C4, C5; live).** In the table at the 1440 pt window a
    running row shows the 18 pt accent ring, `Auditing`, `standard`, the host
    in the data face, `5x % · 3,xxx of 6,468`, `2xx of 2,000` and `97 of
    1,020` right-aligned, `4 low` in the low ink and `1:0x` fully visible; a
    Done row shows a success dot, no ring, and its stopped-reason sentence as
    a second line when it has one; a Cancelling row shows an amber dot; the
    selected row carries the 3 pt accent left edge on the active tint; no
    row contains a full-width coloured bar (frame).
19. **AC19 (P2, D10; live).** Hovering a running row shows `Cancel` in the
    trailing action column without any other row moving (two frames, hover
    off / on, differ only inside that row's action column); the context menu
    of a Done row lists `Scan Again`, `Show Issues`, `Show Site Map`, `Copy
    Job ID` and not `Cancel Scan`.
20. **AC20 (P2, D11; unit).** `jobHeading(facts, targets
    ["http://127.0.0.1:8117"]) == "127.0.0.1:8117"`; three targets give
    `"a.test and 2 more"`; two give `"a.test, b.test"`;
    `findingLine(live auditing, 4 low, running ["xss-reflected", +3],
    profile standard, startedAt = 11:32 local, startedBy aitm-mac).text ==
    "4 low issues so far · xss-reflected and 3 more checks running now ·
    standard · started 11:32 by this app"` with `reason == nil` and
    `agentOriginated == false`; the same with `frontend mcp` ends `by an
    agent`, has `agentOriginated == true` and a part `("an agent", .agent)`;
    zero issues, one running id, `frontend cli` gives `"no issues so far ·
    xss-reflected running now · standard · started 11:32 by the CLI"`;
    terminal `done` with reason `errors`, finishedAt 11:33 gives `reason ==
    "Stopped early: too many errors from the target."` and `text ==
    "standard · started 11:32 by this app · finished 11:33"`; `done` with no
    reason gives `reason == nil`; `issuesSoFar(1 high, 4 low) == "5 issues so
    far: 1 high, 4 low"`, `(1 high) == "1 high issue so far"`, `(zero) == "no
    issues so far"`; `startedByWords`: `operator` + label `aitm-tui` → `by
    aitm-tui`.
21. **AC21 (P2, D11, C7, C9, C11; live).** The running card shows, top to
    bottom: the chip `Auditing` beside the host heading, the finding line
    with `started <h:mm> by this app`, the verbs Show Site Map · Show Issues
    · Cancel Scan at the right; the lane with the `crawl` and `audit` labels
    inside the segments, `N checks to go` at the right, the now mark with
    its dot and `now · <id>` (or `… and n more`) under it, the scale row
    `started <h:mm>` · `elapsed m:ss` · `at this pace, about m:ss to go`; the
    ledger; the gauge with `probe budget` and `N of 2,000`; the KPI strip
    with the labels `Progress`, `Checks`, `Probes`, `Points audited`,
    `Issues`; then the table and the two wells titled `Crawl and points` and
    `Issues`. No section titled Session or Lanes exists; the Crawl well reads
    `Waiting for audit` and `skipped as repetitive`, never `Queued` or
    `Skipped frequent`.
22. **AC22 (P2, D11; gate).** `grep -nE 'Color\(|\.cornerRadius\(|easeOut\(0\.[0-9]|\.animation\(\.easeOut|Animation\.(easeOut|easeIn|easeInOut|linear|spring)|TimelineView' apps/mac/Sources/Aitmproxy/Panels/ScanPanel+Jobs.swift apps/mac/Sources/Aitmproxy/Panels/ScanJobCard.swift apps/mac/Sources/Aitmproxy/Panels/ScanJobWells.swift apps/mac/Sources/Aitmproxy/Panels/ScanProgressViews.swift`
    prints nothing; `grep -nE ': CGFloat = [0-9]|: Double = [0-9]'` over the
    same four files matches only lines inside `enum CardMetrics`;
    `tools/grid-lint.sh` prints PASS.
23. **AC23 (P2, D12; gate).** `docs/design/tokens.json` carries
    `motion.counter` `150ms`, `motion.progress` `250ms`, `motion.stagger`
    `60ms`, `color.ground.card` `{ light: #FFFFFF, dark: #232326 }`,
    `shadow.float`, `shadow.rest`, `typography.size.xxl` `24px`,
    `typography.size.display` `28px` and `$version` `0.2.0`; after the
    generators run, `Tokens.swift` has `static let counter: Double = 0.150`,
    `static let progress: Double = 0.250`, `static let stagger: Double =
    0.060` under `Tok.Motion`, `static let card = DynamicColor(light:
    0xFFFFFF, dark: 0x232326)` under `Tok.Ground`, `static let float` and
    `static let rest` under `Tok.Shadow`, `static let xxl: CGFloat = 24` and
    `static let display: CGFloat = 28` under `Tok.Typography.Size`; the web
    `tokens.css` has `--motion-counter: 150ms`, `--motion-progress: 250ms`,
    `--motion-stagger: 60ms`, `--color-ground-card`, `--shadow-float` and
    `--shadow-rest` in both modes; `cargo test -p aitm-tui` passes with the
    bumped `$version`; `grep -nE '[0-9]' apps/mac/Sources/Aitmproxy/UI/ScanMotion.swift`
    matches only comment lines.
24. **AC24 (P2, D12; live).** A screen recording (SCStream or the real-run
    motion harness) over 10 s of the auditing phase shows the KPI digits
    changing without a layout jump, the lane's fill width and the now mark's
    position changing monotonically between frames except where `scheduled`
    grew, and the now mark's dot's opacity oscillating with a period of
    about 1.2 s; the per-frame diff outside the digit, fill, mark, dot and
    elapsed regions is empty (no other element changes colour over time).
    With Reduce Motion on, the same recording shows instant swaps and a dot
    of constant opacity.
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
29. **AC29 (P2, D14; live).** With VoiceOver on, ↓ in the table reads a row
    as one sentence (recording or the AX label equals AC28's shape); the
    host heading is announced as a heading; the lane reports `Progress, 50
    percent`; when the selected job ends, exactly one announcement is heard
    (one `announce:` line in the unified log); Return moves focus to the
    card's first enabled verb and Escape returns it to the table.
30. **AC30 (P2, D15, C12; live).** `kill -STOP` the core: at 10 s the rows
    are unchanged and no banner shows; at 35 s the banner above the card
    reads `The core is not answering · showing values from 0:3x ago ·
    retrying every 2 s`, the verb slot and the hover Cancel are disabled;
    `kill -CONT`: the banner leaves within 5 s. Proxy ▸ Reconnect Bus during
    a stopped core shows `Bus disconnected · showing values from … ago ·
    reconnecting…`.
31. **AC31 (P2, D10; live).** With four jobs the table container's
    accessibility label reads `4 jobs · 1 running` (AX dump), the Jobs tab
    label reads `Jobs 4`, rows are newest first (ids match the concurrent
    `scan.list` order), and the page scrolls as one column (the card scrolls
    with the table).
32. **AC32 (P2, D16, D17; gate).** `grep -nwiE 'stop|abort|finding|task'`
    over the string literals of `ScanSurface.swift`'s Jobs words finds no
    operator-facing string (`"Stop this job; …"` in the help is the one
    allowed verb use, listed in the UX section); `grep -n 'Timer\|Task.sleep\|TimelineView'`
    over `ScanPanel+Jobs.swift`, `ScanJobCard.swift`, `ScanJobWells.swift`
    and `ScanProgressViews.swift` prints nothing.

Locked-comp additions (numbered after the existing 43 so no reference moves):

44. **AC44 (P2, D8 amendment; unit).** `paceEstimate(done: 3236, scheduled:
    6468, elapsedMs: 64_000)` gives `secondsToGo == 64` and `checksPerSecond
    == 50.5625 ± 0.001`; `ScanJobProgress(auditing 3236/6468, elapsed
    64_000).estimateText == "at this pace, about 1:04 to go"` and
    `.estimateHelp == "Derived from the counters: 3,236 checks done in 1:04,
    about 51 checks per second, 3,232 to go."`; `paceEstimate(0, 6468,
    10_000) == nil`, `(3236, 6468, 0) == nil`, `(6468, 6468, 90_000) == nil`,
    `(3236, 0, 64_000) == nil`; `estimateText` is nil for crawling, passive,
    reporting, queued, cancelling and `cancelled`; `checksToGo(done: 3236,
    scheduled: 6468) == "3,232 checks to go"`, `(6467, 6468) == "1 check to
    go"`, `(6468, 6468) == nil`, `(0, 0) == nil`; `checksToGoText` is nil for
    a terminal job and while crawling; `nowTag` is nil for `running == []`,
    `"now · xss-reflected"` for one id, `"now · xss-reflected and 3 more"`
    for four, while `nowLine` keeps P22's `Now: …` form.
45. **AC45 (P2, D10, D11; unit).** `ledgerGroups(by: 4 low)` is one group
    `(low, count 4, marks 4, word "4 low")`; `(1 high, 4 low)` is `[high,
    low]` in that order; `(30 low)` has `marks == 12` and `word == "30
    low"`; `(zero)` is `[]`; `tone(facts running) == .progress`, `(queued) ==
    .progress`, `(cancelling) == .pending`, `(done) == .success`, `(failed)
    == .danger`, `(cancelled) == .neutral`; `budgetWarning(sent: 1601,
    budget: 2000) == true`, `(1600, 2000) == false`, `(5, 0) == false`;
    `probeBudgetText(287, 2000) == "287 of 2,000"`, `(287, 0) == "287
    probes"`; `agentOriginated(frontend "mcp") == true`, `("cli") == false`;
    `ScanFormat.kpiLabels == ["Progress", "Checks", "Probes", "Points
    audited", "Issues"]`; `ofText(6468) == "of 6,468"`;
    `laneChecksDone(3236) == "3,236 checks done"`; `lanePages(46) == "46
    pages"`, `(1) == "1 page"`.
46. **AC46 (P2, D11; live).** Four frames of the card, one per state
    (running, cancelling, done, cancelled), show the chip word `Auditing` /
    `Cancelling` / `Done` / `Cancelled` and the card's 3 pt left edge in the
    tone's dark value (`#60A5FA` / `#F5A524` / `#86EFAC` / `#B4B4B8`, each
    channel within 4 of the token) with the chip's background in the pair's
    tint; the failed state's `#FCA5A5` edge is recorded when a failed job is
    reachable, else noted as not reproducible.
47. **AC47 (P2, D11; live).** The auditing card's lane frame shows the crawl
    cap in `#3B82F6` with `crawl` / `N pages` inside, the audit fill in
    `#60A5FA` with `audit` / `N checks done` inside, `N checks to go` at the
    right, the now mark with its dot at the fill's edge, `now · <id>` under
    it and the scale row with the estimate; after the job ends (frame within
    3 s of the terminal state) the now mark and the right label are gone and
    the end sentence `Done in m:ss · N points · N checks.` stands where the
    now tag was; the concurrent `scan.status` confirms the state.
48. **AC48 (P2, D11; live).** After `light-http` finishes on the test target
    (it ends `1 high, 2 low` on today's target) its card's ledger shows one
    high-ink mark + `1 high` followed by two low-ink marks + `2 low`, the KPI
    Issues cell reads `3` with `1 high, 2 low`, the row's Issues column reads
    the same words; the `standard` job's ledger at `4 low` shows four low
    marks and `4 low`.
49. **AC49 (P2, D11; live).** A saved profile `tiny-budget` (the `standard`
    builtin with a probe budget of 50) run against the test target: a frame
    past 40 probes shows the gauge fill in `#F5A524` with `4x of 50`; the
    job ends with `stopped_reason: budget`; the card's finding line then
    opens with `Stopped early: the probe budget of 50 was spent. Raise it in
    the profile to go further.`, the chip reads `Done`, the edge is the
    success tone, and the raw line `stopped_reason: budget` appears only in
    the attention block.
50. **AC50 (P2, D12; live).** A recording of a row click shows the card's
    title row, lane, KPI strip and the wells reaching full opacity in that
    order over about 0.5 s with an upward travel (frames at 0, 100, 200, 300
    and 400 ms after the click), the table unchanged; a recording of a ↓ key
    press shows the new job's card fully opaque in the first frame after the
    key (no entrance); with Reduce Motion on the click recording shows the
    same order with no vertical travel.

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
    duration in `scanner.module.css`. Live: `scripts/scan-live.mjs` (with
    Jobs-view steps added) captures running, cancelled and the dead-target
    done states showing the same sentences as AC16.
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

- The table layout mechanism (`Grid` or fixed-frame `HStack`) and the exact
  flexible widths; the thresholds at which lane labels and the right label
  hide.
- The exact SwiftUI incantation for the staggered entrance (`.id` +
  `.transition` + delayed animation, or a per-block `onChange`), as long as
  AC50 holds and keyboard selection shows none.
- The attention disclosures' default open/closed state.
- Whether the chip draws its 6 pt dot (the comp does; it is static).

## Open questions

None blocking. The two motion tokens of D12 (`motion.counter` 150 ms,
`motion.progress` 250 ms) were approved at the spec's approval. The
locked-comp amendment (2026-11-02) added these calls, decided under
autonomous mode; Matt may overrule any of them at the PR 2 review:

1. No visible caption line; `4 jobs · 1 running` becomes the table's
   accessibility label (D10).
2. The entrance plays on a pointer selection, a start and the first list;
   the table takes part only in the first one; keyboard selection never
   animates (D12).
3. Breathing on two dots only (the now mark's and the cancelling dot); the
   comp also breathes the chip's running dot, which this spec keeps static
   (D12).
4. New tokens beyond the brief's list: `motion.stagger` 60 ms,
   `typography.size.xxl` 24 and `typography.size.display` 28 (D12);
   `radius.card` is not added (the card reuses `radius.floating`).
5. The lane's crawl cap is a fixed-width label segment (about 80 pt), not a
   time proportion: the bus carries no crawl duration (D11).
6. "Scan lane" is the design's name for the signature element (Matt's word
   in the comp notes); it collides with the glossary's *Lane* (a protocol a
   job scans over). The word never appears on screen (the element's
   accessibility label is `Progress`; its segments read `crawl` / `audit`),
   so the glossary is untouched; the view type is `ScanLane`.
7. Web W2 is re-cut to the comp before Part 3 opens (D18 amendment); the
   TUI keeps its own layout and gains only the derived words.
