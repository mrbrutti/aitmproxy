# Jobs view, TUI (Part 4): re-check on the merged head

`feat/scan-jobs-view-kit` 6af86865 (= Kit + TUI + `origin/main` v0.5.17 bacb4377), binaries built `--release` from this tree. The same `proof.sh` as the recorded run (`../`), pointed at this tree; `aitm --config <run dir>/aitm.yaml` with `mcp.audit_log` and `ca.audit_log` under the run dir (`config-audit-lines.txt`), `aitm-tui --bus` in tmux 200 × 50, a real `standard` job against `aitm-testtarget-serve --latency-ms 400`, keystrokes only.

| Step | Result |
| --- | --- |
| 1–3 TUI up, Scan view, Jobs tab | ok |
| 4 the row appears with a running phase word | ok (`01-jobs-running.txt`) |
| 5 the Jobs header shows the progress and budget columns | ok |
| 6 the progress column moved between two captures | ok (`02-jobs-running-12s.txt`) |
| 7 the detail carries the `now` line while auditing | ok (`03-detail-now.txt`) |
| 8 the progress cell rises while auditing | ok (`03-progress-rise.txt`) |
| 9 `x` shows `cancelling` at once (50 ms samples) | FAIL, as in the recorded run: the engine answers `cancelled` within a tick when idle (gap 73) |
| 10 then `cancelled`; 11 the detail opens with D4's sentence | ok (`05-cancelled-sentence.txt`, `05-status.json`) |
| 12 the Jobs banner names the hung core within 31 s (Task 4.5a) | ok (`06-banner-age.txt`, `06-banner-timing.txt`) |
| 13 `x` while unanswered is refused with the toast | ok (`06c-x-refused.txt`) |
| 14 the clause clears once the core answers again | ok (`07-recovered.txt`) |

Matt's real `audit.jsonl`, `audit.agent.jsonl`, `ca-audit.jsonl`: `real-audit-diff.txt` reads `REAL FILES UNCHANGED` (size, mtime and sha256 before and after). The run directory's own audit files are listed in `run-dir-audit.txt` / `server-open-audit-files.txt`.
