# Live proof, TUI Part 4 (Task 4.6, AC43, AC61 live half)

Run 4 of `proof.sh` (this folder), 2026-11-02 22:26–22:27, Terminal. Real `aitm` server (`--config <run dir>/aitm.yaml`: `mcp.audit_log` and `ca.audit_log` under the run dir, `config-audit-lines.txt`; `mcp.operator_token`) and the real `aitm-tui --bus … --token-file <operator token> --expect-role operator` in tmux 200×50, both built from this branch's tip; `aitm-testtarget-serve --latency-ms 400` on 8117; jobs started over the bus as operator. Matt's real `audit.jsonl`, `audit.agent.jsonl`, `ca-audit.jsonl` identical before and after (`real-audit-diff.txt`); the run dir's own `audit.jsonl` holds the one `scan.cancel` (`run-dir-audit.txt`). Text stills are `tmux capture-pane -p`; the `.json` beside a still is the concurrent `scan.status`.

| Moment (AC43) | Still | What it reads |
| --- | --- | --- |
| `:scan` then `2`: the Jobs tab, header | `pane-5.txt` | `job  profile  targets  state  progress  budget  points  issues  el.` |
| the row with the phase word, progress indeterminate while crawling | `01-jobs-running.txt`, `02-jobs-running-12s.txt` | `crawling  ...  ──────  0/2000` (`01-status.json`, `02-status.json`) |
| the detail's `now` line while auditing | `03-detail-now.txt` | `now xss-reflected` (`03-status.json`) |
| the progress column rising while auditing | `03b-auditing-row-a.txt` → `03c-auditing-row-b.txt` (6 s apart) | `auditing  463/1072 ━━────  36/2000  5/154` → `auditing  469/1072 ━━────  50/2000  6/154` (`03-progress-rise.txt` recorded the bar cell by mistake, the script's field index is corrected; the rows above are the evidence) |
| `x` → the reply's state, then `cancelled`; the detail's first line | `05-cancelled-sentence.txt`, `05-status.json` | row `cancelled  470/1072 ━━────  51/2000`; detail `Cancelled after 0:NN; 470 of 1,072 checks had run. What it found stays.` then `wire stopped_reason: cancelled` |
| `cancelling` | not observable | the engine answers `scan.cancel` with the job already `cancelled` within one tick when the probe queue is idle (50 ms sampling, four runs); gap 73 |
| `kill -STOP` the core: the hung-core banner (Task 4.5a) | `06-banner-age.txt`, `06-banner-timing.txt` | `scan.list: the bus did not reply in time · showing values from 30s ago`, first seen 21 s after SIGSTOP (27 s in runs 2 and 3) |
| five seconds later | `06b-banner-age-plus5.txt` | `… showing values from 35s ago` |
| `x` while unanswered | `06c-x-refused.txt` | toast `scan.cancel not sent: the bus did not reply in time` |
| `kill -CONT`: the clause clears on the next fold | `07-recovered.txt` | banner `idle` |

Steps 1–7 and 10–14 of `run4.log` pass; step 8 is the mis-read field (rows above), step 9 is gap 73.

## The acceptance cell (AC61 live half)
`cell-run.sh`: `tests/e2e/tui/test_tui_scan_live.py` (Task 4.5b's re-pin) run directly against this branch's release `aitm` and `aitm-tui` with the harness self-boot (latency 300 ms), twice (`cell-run2-summary.txt`): every T7-16 Jobs step `ok` (the row for the job, the state cell changing, `sent` bracketed by `scan.status`, `x` → `cancelled`, the push lines), 52 ok, 1 noted, 3 failed. The three failures (T7-17 `⏎` on the first probe flow opening the inspector; T7-17 `f` marking `false_positive`; T7-18 `y` re-issuing the L4 launch and its wording) reproduce identically with main's own cell and main's binaries (`cell-baseline-main-summary.txt`, abbc6102), so they are pre-existing and belong to the acceptance lane (plan gap 75).
