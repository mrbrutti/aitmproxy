# Scan ▸ Jobs — design notes (tasteskill app-screen run)

## Inventory (data and jobs)
- Objects: jobs (`scan-<8 hex>`), 1–~10 per session, newest first; each with state (queued, running, cancelling, done, cancelled, failed), phase (crawling, passive, auditing, reporting), profile name, targets (host:port), elapsed (m:ss), probes sent of budget (≈2 probes/s at 400 ms latency against a 2,000 budget), checks done of scheduled (hundreds to ~6,500), points audited of found, issues by severity (critical/high/medium/low/info) and confidence, crawl pages/queued/errors, check errors with up to 8 samples, stopped reason, started by (this app, the CLI, an agent).
- Magnitudes today (live runs 2026-11-02): standard on 8117: 3,236 of 6,468 checks at 1:04, 287 of 2,000 probes, 97 of 1,020 points, 4 low; thorough on 8119 crawling: 46 pages, 12 queued, 11 probes, 0:05; dead target 8121: done after 0:30, stopped early (errors), 49 of 135 checks, 7 could not run, 1 probe; cancelled standard 8117 at 0:21, 46 probes; light-http on 8120: done in 1:35, 171 of 171 checks, 143 probes, 36 of 36 points, 1 high 2 low.
- People: one operator, a glance every few minutes during a long scan, or an eight-hour session on a Mac; the same operator supervising an agent's scans.
- Jobs: watch; cancel; open the issues; open the site map; scan again when finished.
- The product's own things: the mark `›•‹ aitmproxy`, the Scan page's tabs, the in-scope targets, the profile names, the check ids (`xss-reflected`, `header-reflection`), the glossary words.

## The screen's one question
"Is this scan still finding things, and how much of it is left?"
- Biggest block: the selected job's **scan lane** (progress of checks as one wide lane with the phase boundary and the now mark) with the checks figure and the issues by severity beside it.
- Finding line (under the title): "4 low issues so far · xss-reflected running now" for a live job; "Stopped early: too many errors from the target." for the dead-target job.
- Most frequent job one click away: Cancel Scan in the title row (the one primary); Show Issues beside it.
- Blocks, as answers: (1) which jobs exist and which are running → the table; (2) how far is the selected one → the lane + KPI strip; (3) what did it find → issues by severity; (4) what did it do → crawl / points / checks wells; (5) why did it stop → the stopped sentence in the finding line and the raw token well.

## Style, face, signature
- Style: `data-terminal` (seed 1164699010), kept palette and type from docs/design/tokens.json.
- Face: every figure in the data face (JetBrains Mono here, SF Mono in the app), text in the UI face; the one accent line is the brand blue `#60A5FA` and marks only the selection (active tab, selected row).
- Signature element: **the scan lane** — the job drawn as one horizontal lane at the true proportion of checks done to scheduled, the crawl portion first, the now mark as a 1 px ink line with the running check id, severity ticks at the lane's end sized by count. Only this product has it (Burp shows a table, Proxyman has no scanner).
- Shell: the app's own labelled sidebar stays (outside the Jobs tab's scope); redraw of the dealt icon rail not applied: reason, the shell exists and is shared by every page.

## Grid arithmetic (1440×900)
Sidebar 240; content 1200; canvas padding 24 → 1152 usable. Table columns: state 148 · profile 120 · target 220 · progress 300 · probes 120 · points 120 · issues 124 → 1152. KPI strip: 5 cells × 230.4 (grid, 1 px dividers). Two wells: 568 + 16 + 568 = 1152.
