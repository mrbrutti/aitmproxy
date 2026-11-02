# Jobs view, mac PR 1 (correctness): live-proof evidence

Real app (dev bundle `Aitmproxy-jobsux` built from the branch), a core built from the branch, `aitm-testtarget-serve --mode vulnerable --latency-ms 400` on 127.0.0.1:8117–8120, a dead port 8121 in scope. Frames are window captures (`tools/winshot.swift`, downscaled to 1862 px wide); AX dumps are `tools/axdump.swift` output; `proof.log` is the driver's log across passes 1–6. Pass → code: pass 1–2 = 88cad442, pass 3 = c4d6de70, pass 4 = dffdadc5, pass 5/5c/6 = 35a3148f (the merge candidate's code; later commits are docs and the mechanical 1.5g minors).

| AC | Evidence | Pass |
| --- | --- | --- |
| AC5 Cancel: `Cancelling…` within 1 s, `Cancelled` within 5 s, identical at +60 s, status `cancelled` | `ac5-frames/f03.png` (before the press), `f04.png` (header `Cancelling · Crawling · 0:15`, button `Cancelling…` disabled), `f05.png`/`f06.png` (Cancelled); `42-ac5-cancelled-5s.png` and `43-ac5-cancelled-65s.png` (identical cancelled row and header; `proof.log` AC5 pass 5 note); `ac5-frames-6/` and `50-ac5-cancelled.png` + `50-ac5-status.json` at the merge candidate | 4, 5, 6 |
| AC6 Finished while unselected, selected afterwards reads Done with the bus's counters, no Cancel Scan | `46-ac6-light-http-done.png` (`Done · Done · 8:12`, row label 320 of 320 points, 5 issues) + `45-ac6-status.json` (done, 1521 of 1521 checks); earlier `24-ac6-light-http-done.png` (pass 3) and `08-ac10-dead-target-detail.png` (dead-target job, pass 2) | 5c, 3, 2 |
| AC7 Two presses within a round trip send one `scan.cancel` | `audit-grep.txt` (the durable audit log's lines for the job); `proof.log` "AC7 audit scan.cancel … before=0 after=1" (pass 4 and pass 6: one AX press + two ⌥⌘. real key events) | 4, 6 |
| AC8 A job started by another bus client is selected with no click | `41-ac8-autoselected.png` (from the empty list `40-empty`; detail `Running · Crawling · 0:04`); earlier `01-ac8-autoselected.png` | 5, 1 |
| AC10 Dead-target job: sentence, crawl line, raw token once | `32-ac10-dead-target.png` + `32-ax-dump.tsv` lines 109–111 (`Stopped early: too many errors from the target.` / `The crawl fetched 1 page and hit 1 error` / `stopped_reason: errors`; bare token nowhere else); the `— the target refused the connection` suffix lands with engine amendment 89 | 4 |
| AC11 Rows are AX buttons with the state word first; the selected row carries `AXSelected` | `51-ax-selected.txt` (three `scan-job-` rows, `selected=true` on the selected one, nil on the others); `08-ax-dump.tsv` (three `AXButton` rows with `scan-job-` identifiers) | 6, 2 |
| AC12 Frozen core: inline error with the age clause advancing, Cancel disabled, recovery | `33-ac12-36s.png` + `33-ax-dump.tsv` (`Unable to read job …: the bus did not reply in time. Showing values from 0:36 ago; retrying every 2 s.`, `Cancel Scan` enabled=false), `34-ax-dump.tsv` (`0:47 ago`), `35-ac12-recovered.png` (error gone, Cancel enabled); earlier `22-ac12-36s.png`/`23-ac12-recovered.png` (pass 3) and `17-core-frozen.png` (the C12 defect before the fix) | 4, 3, 1 |
| C1/C2 defects before the fix | `../09-cancelled.png`, `../10-cancelled-later.png`, `../13-first-row-detail.png` (the stale detail) | 0 |

Unit criteria AC1–AC4, AC1b, AC9 and the unit halves of AC7/AC8/AC12 are Swift Testing cases named in the spec's requirement-to-evidence table; the Terminal gate logs are `/tmp/claude/jobsux-gate-w*-{build,test}.log` (w7 on 35a3148f: 877 Kit + 37 bus tests, 0 errors, the three pre-existing `Text +` warnings).

## Merged head (passes 7 and 7b, 2026-11-02): PR 1 + origin/main (#308), bundle tree + #310

After mac-review's CPU fix (#308) landed first, PR 1 merged `origin/main` (4529ea6b; docs ad822f45) and re-ran the proof. The dev bundle was built from `tmp/jobsux-bundle` b7f603f7 = the merged head + #310's branch (`claude/serene-villani-38530e`, still open at the time) so the embedded core writes its audit log under the isolated store. Evidence in `merged/`; `merged/proof.log` is the driver's log for both passes. The bundle was quit after each pass.

| Check | Evidence | Pass |
| --- | --- | --- |
| #310: the generated config carries the audit log under the store; Matt's real `audit.jsonl` untouched | `70-config-audit-lines.txt` (`audit_log: "/tmp/Aitmproxy-dev-state-jobsux/audit.jsonl"`); `proof.log` "real audit log before/after: mtime=1793660731 size=92013" both times, "#310 PASS" twice | 7 |
| AC8 bus-started job selected with no click | `61-ac8-autoselected.png` + `61-ax-dump.tsv` (`Running · Crawling · 0:04`, Cancel Scan enabled) | 7 |
| AC5 `Cancelling…` → `Cancelled` within 5 s, identical at +60 s | `ac5-frames-7/f02–f08` (frame loop across the press), `62-ac5-running.png`, `63-ac5-cancelled-5s.png` + `63-ax-dump.tsv` (`Cancelled · Done · 0:14`), `63-ac5-status.json` (cancelled at 14,653 ms), `65-ac5-cancelled-65s.png` + `65-ax-dump.tsv` (same header and row) | 7 |
| AC7 one AX press + two ⌥⌘. → one `scan.cancel` | `audit-grep.txt` (one line for the job, from the store's audit log); `proof.log` "before=0 after=1" | 7 |
| AC10 dead target: sentence, crawl line, raw token once | `64-ac10-dead-target.png` + `64-ax-dump.tsv` lines 88–90 | 7 |
| AC11 three rows, one `selected=true` | `66-ax-selected.txt` | 7 |
| AC12 frozen core: inline error with the age advancing, Cancel disabled, recovery | pass 7: `68-ac12-36s.png` (`Unable to list jobs: the bus did not reply in time. Showing values from 0:37 ago; retrying every 2 s.`, Cancel disabled), `69-ac12-recovered.png`; pass 7b unfiltered dumps `71-ax-dump.tsv` (`0:39 ago`, `Cancel Scan false`), `72-ax-dump.tsv` (`0:50 ago`), `72b-ax-dump.tsv` (error gone, `Cancel Scan true`), frames `71-ac12-36s.png`, `72-ac12-recovered.png`. The inline error is an `AXUnknown` element, which pass 7's role-filtered dumps dropped; the frames and the unfiltered dumps carry it | 7, 7b |
| AC6 finished while unselected, then selected: Done with the bus's counters, no Cancel Scan | pass 7b: `70-ac6-thorough-selected.png` (the thorough job selected while light-http runs), `73-ac6-before-select.png`, `73-ac6-status.json` (done, 940 of 940 checks, 5 issues, 351,252 ms), `74-ac6-light-http-done.png` + `74-ax-dump.tsv` (`Done · Done · 5:51`, no Cancel Scan). Pass 7's frame 67 is not an AC6 proof: its 400 s wait ended with the job still running (1523/1538) | 7b |

Gate on the merged head: w9 (`swift build` 0 errors, 886 Kit + 37 bus tests, grid-lint and six tripwires PASS; `/tmp/claude/jobsux-gate-w9-*.log`).
