# Live proof, web Part 3: the Jobs view (W2) against a real core

Run 8 (the merged head: `origin/main` 565daff6 = #320 in, base `main`; runs 2–7 are in plan gap 80) of `proof.sh` (this folder; it lived at `/tmp/claude/web-proof.sh`), on `feat/scan-jobs-view-web` fac356d1, in the Terminal outside the sandbox.

**What ran.** `apps/web` built from the tree (`npm run build`), `aitm` and `aitm-testtarget-serve` built `--release` from the same tree, then `node scripts/scan-live.mjs` (Task 3.11's driver): a fresh run directory under `$TMPDIR`, `aitm` on random loopback ports with the operator bridge, `aitm-testtarget-serve --latency-ms 400` as the target, headless Chrome driven over CDP with real pointer and keyboard input (`scripts/cua-driver.mjs`), the witness being the driver's own bus connection (`scan.list` / `scan.status` / `scan.start` with the operator token). Steps 01–08 are the scanner driver that already existed (gap 56 matcher updates); 09–12 are the Jobs-view steps this PR adds. Viewport 1440 × 900 for the stills.

**Launch guard (#310, the rule for every proof).** Both audit logs of the written harness config sit under the run directory, read from the file the core was started with, at startup and again after the 08b restart; the run aborts otherwise. Matt's real logs are digested before and after:

```
# at startup: /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-gN4s8a/config.yaml
run dir: /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-gN4s8a
mcp:   audit_log: "/var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-gN4s8a/audit.jsonl"
ca:   audit_log: "/var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-gN4s8a/ca-audit.jsonl"
verdict: both inside the run dir

# after the 08b restart: /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-W5gY0M/config.yaml
run dir: /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-W5gY0M
mcp:   audit_log: "/var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-W5gY0M/audit.jsonl"
ca:   audit_log: "/var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-live-W5gY0M/ca-audit.jsonl"
verdict: both inside the run dir
```

```
operator store: /Users/matt/Library/Application Support/aitmproxy
before 2026-11-03T17:48:22.785Z
  audit.jsonl size=100387 sha256=d77844b13c4cd861267e504a4581960c9bfd346e521de4602d4cfe40e7e08a8f
  ca-audit.jsonl size=20889 sha256=ed14b58f15856db8a3d0dbef3a5da3f51d3e028bb205158b5c924a23ec1c42c8
after 2026-11-03T17:58:52.785Z
  audit.jsonl size=100387 sha256=d77844b13c4cd861267e504a4581960c9bfd346e521de4602d4cfe40e7e08a8f
  ca-audit.jsonl size=20889 sha256=ed14b58f15856db8a3d0dbef3a5da3f51d3e028bb205158b5c924a23ec1c42c8
verdict: UNCHANGED
```

## Jobs-view steps 09–12 (23 PASS, 0 FAIL, 0 GAP, 5 NOTE)

00 audit-log preflight at startup — mcp "<run dir>/audit.jsonl" · ca "<run dir>/ca-audit.jsonl" (inside <run dir>)

| Result | Step |
| --- | --- |
| NOTE | 09 lower region — aitm.split.h null -> "0.85" (ArrowUp on the separator) |
| NOTE | 09 origins — the standard draft lost its origin (Origins reads "No origins yet."); re-adding it |
| PASS | 09a the card chip reads Auditing while the witness reads running · auditing |
| PASS | 09a the row state word reads Auditing |
| PASS | 09b the now tag names a check the witness had running (the union of three reads) |
| PASS | 09b the now tag reads `now · <id>` |
| NOTE | 09b now tag vs running[0] — "crlf" equals a witness running[0] of the three reads (["xss-reflected","xss-reflected","crlf"]) |
| PASS | 09c the lane data-fraction is within 0.02 of the witness done / scheduled |
| PASS | 09d the KPI Progress numeral is within 1 of floor(100 · done / scheduled) |
| PASS | 09e the row progress reads `<n> % · <done> of <scheduled>` with U+00A0 before % |
| PASS | 09e the row percent equals the KPI percent |
| PASS | 09e the row done / scheduled are the witness counts (bracket) |
| PASS | 09f the KPI Checks numeral is the witness checks.done, grouped (bracket) |
| PASS | 09g the row probes cell reads `<sent> of <budget>` inside the witness bracket |
| NOTE | 10 witness — cancelled 1 ms after the press |
| PASS | 10a the card chip reads Cancelled after the witness read cancelled |
| PASS | 10a the row state word reads Cancelled |
| PASS | 10b the end sentence is `Cancelled after m:ss; N of M checks had run. What it found stays.` with the witness numbers |
| PASS | 10b the end sentence elapsed is the witness elapsed_ms (±1 s) |
| PASS | 10c no [data-field=stopped] line for a cancelled job (D4) |
| PASS | 10d the run directory audit log holds exactly one scan.cancel for the job |
| NOTE | 11 start — standard against http://127.0.0.1:53354 (port 53354, never listened on) over the witness: scan-f6c95499 |
| PASS | 11a [data-field=stopped] reads the D4 sentence for stopped_reason errors |
| PASS | 11c the attention line reads `<n> checks could not run` with n = the witness checks.errors |
| PASS | 11c the attention details opens on a real click |
| PASS | 11e the row sub-line carries the D4 sentence (title = the full sentence) |
| PASS | 11f the row and the chip read Done |
| PASS | 12 Matt's real audit.jsonl and ca-audit.jsonl are unchanged by the run (size and sha256) |

## AC58 (a): running · auditing with the now mark (`status-09.json`, `09-jobs-auditing.png`)

Job `scan-9b98b419`, profile `standard`. Each capture followed a poll of the witness's `scan.status` *state* (`running · auditing`), never the rendered word; the bracket is a witness read before and one after the DOM read, with a third read 2 s earlier for the now tag.

| Block | Rendered | Witness (before → after) |
| --- | --- | --- |
| chip / row state | `Auditing` / `Auditing` | `running · auditing` → `running · auditing` |
| now tag | `now · crlf` (id `crlf`) | `checks.running` early / before / after: `xss-reflected` / `xss-reflected` / `crlf` |
| lane `data-fraction` | `0.4338` | done / scheduled 463 / 1072 = 0.4319 → 465 / 1072 = 0.4338 |
| KPI Progress | `43 %` | floor(100 · done / scheduled) 43 → 43 |
| KPI Checks | `465` | `checks.done` 463 → 465 |
| row progress | `43 % · 465 of 1,072` | the same percent and counts |
| row probes | `40 of 2,000` | `probes.sent` 36 → 40 of 2,000 |

## AC58 (b): cancelled by one press (`status-10.json`, `10-jobs-cancelled.png`)

Job `scan-9b98b419`: one real click on the card's `Cancel scan scan-9b98b419`; the witness's first read after the press (`cancelled` in `status-10.json`) already read `cancelled` (the `10 witness` NOTE above gives the delay).

| Block | Rendered | Witness `scan.status` (final) |
| --- | --- | --- |
| chip / row state | `Cancelled` / `Cancelled` | `cancelled` |
| end sentence | `Cancelled after 0:18; 467 of 1,072 checks had run. What it found stays.` | elapsed_ms 18034 (0:18); checks.done 467 of scheduled 1072 |
| `[data-field=stopped]` | absent | `stopped_reason` `cancelled` (D4: no Stopped line for a cancel) |
| row progress | `467 of 1,072` | |
| run-dir audit log | exactly one `scan.cancel` for the job (10d) | |

## AC58 (c): dead target, done + `stopped_reason: errors` (`status-11.json`, `11-jobs-dead.png`, `11-jobs-dead-attention.png`)

Job `scan-f6c95499`, `standard` against a port nothing listens on (asserted distinct from the proxy, web and target ports and refused by a connect; step 00's NOTE), started over the witness bus because the editor's origin picker is a native `<select>` headless Chrome cannot drive.

| Block | Rendered | Witness |
| --- | --- | --- |
| chip / row state | `Done` / `Done` | `done`, `stopped_reason` `errors` |
| `[data-field=stopped]` | `Stopped early: too many errors from the target.` | D4's sentence |
| `[data-field="stopped-raw"]` | `stopped_reason: errors` | the raw token line |
| attention line | `3 checks could not run` (opened on a real click: yes) | `checks.errors` 3 |
| row sub-line / title | `Stopped early: too many errors from the target.` / `Stopped early: too many errors from the target.` | |
| `errors` tokens | `stopped_reason: errors` is the only `errors` token outside D4's sentence and the crawl-trouble clause (11d; the card read as laid-out text) | |

## AC59: the stills against `docs/design/mockup/scan-jobs/committed-1440.jpg`

The lower region was grown to the Shell's keyboard maximum first (ArrowUp on the `Resize inspector` separator, 0.02 a press, clamped at 0.85; the driver's `09 lower region` NOTE), so the card fills the viewport the way the comp fills the window; the flow table above it is the real app's and is not in the comp. Each state has a still from the card's top (`<state>.png`) and one with the table scrolled to the top of the region and the wells below it (`<state>-table.png`); the dead job also has its attention block open (`11-jobs-dead-attention.png`).

| Block (comp, top to bottom) | `committed-1440.jpg` | Web stills (run 7) | Match |
| --- | --- | --- | --- |
| Card chrome and edge | panel with a 3 px accent edge on the left, rounded, one level above the page | `09-jobs-auditing.png`: the card with the accent edge at x 241, the same surface step | yes |
| State chip | `● Auditing` pill, tinted, the dot in the state's ink | `● Auditing` pill at the card's top left (`10-…`: `● Cancelled` grey; `11-…`: `● Done` green) | yes |
| Heading and finding line | host in the data face, 28 px; `4 low issues so far · xss-reflected and 3 more checks running now · standard · started 11:32 by the agent` | `127.0.0.1:57594` in the data face; `4 low issues so far · crlf running now · standard · started 00:49 by web-bridge` (one check running on this core; the starter is the bridge's real label); cancelled: `standard · started 00:49 by web-bridge · finished 00:49`; dead: D4's `Stopped early: too many errors from the target.` on its own line | yes |
| Verbs | `Show Site Map` `Show Issues` and the primary `Cancel Scan` at the right | the same three, `Cancel Scan` primary while running, `Scan Again` primary once terminal | yes |
| Lane | crawl segment (`46 pages`), audit fill (`3,335 checks done`), `3,133 checks to go`, the now mark with `now · xss-reflected and 3 more` | crawl `33 pages`, audit `465 checks done`, `607 checks to go`, the now mark at the fill's end with `now · crlf`; cancelled: the fill frozen, no mark; dead: `0 pages`, `7 checks done`, no mark | yes |
| Under the lane | `started 11:32` · `elapsed 1:06` · `at this pace, about 1:05 to go` | `started 00:49` · `elapsed 0:17` · `at this pace, about 0:23 to go`; cancelled: the end sentence `Cancelled after 0:18; 467 of 1,072 checks had run. What it found stays.` above `started · elapsed`; dead: `Done in 0:00 · 0 points · 9 checks.` | yes |
| Ledger | `▮▮▮▮ 4 low` `▮ 1 high`, squares and words in the severity inks | `▮▮▮▮ 4 low` in the low ink (this run found no high); dead: `no issues` muted | yes (one severity present) |
| Gauge | `probe budget ——— 291 of 2,000` | `probe budget ——— 40 of 2,000` (cancelled `44 of 2,000`, dead `0 of 2,000`) | yes |
| KPI strip | Progress `50 %` · Checks `3,285 of 6,468` · Probes `289 of 2,000` · Points audited `97 of 1,020` · Issues `4` `4 low` | Progress `43 %` · Checks `465 of 1,072` · Probes `40 of 2,000` · Points audited `6 of 154` · Issues `4` `4 low`; cancelled and dead show `—` for Progress (no live fraction) | yes |
| Table | State (spinner + dot + word, a `Stopped early: too many errors` sub-line on the dead row), Profile, Target, Progress `51 % · 3,335 of 6,468`, Probes `291 of 2,000`, Points `97 of 1,020`, Issues `4 low` in ink, Elapsed; the hovered row shows `Cancel` | `09-jobs-auditing-table.png`: the same columns, `43 % · 465 of 1,072`, `40 of 2,000`, `6 of 154`, `4 low` in the low ink, `0:17`; the dead row's `Done` with the `Stopped early: too m…` sub-line (title = the full sentence, 11e); the hover Cancel is pointer-only and no pointer rests on a row in a still | yes |
| Wells | `Crawl and points · what the job found to test` and `Issues · by severity and confidence`, two columns under the table | the same two wells with the same captions and row sets (`Pages fetched 33`, `Points found 154`, … / `Critical · High · Medium 0 · 0 · 0`, `Low 4`, `Certain · Firm · Tentative 1 · 2 · 1`, …); dead: `Crawl errors 1`, `Probe errors 10`, `Checks scheduled · done · errors · skipped 9 · 7 · 3 · 0` | yes |
| Attention block (dead job; D4) | not in the comp's frame | `11-jobs-dead-attention.png`: `▸ 3 checks could not run` (opened on a real click, 11c), `The crawl fetched 0 pages and hit 1 error — the target refused the connection`, `stopped_reason: errors`, `crawl.last_error: connect_refused` | spec D4 |

Not in the comp and present in the stills: the app's sidebar, toolbar and flow table above the Scan panel (the Shell's chrome; the comp is the Jobs view alone). The lower region is at the Shell's keyboard maximum (0.85); at the default split the card is cut at the KPI strip (run 3's stills).

## The pre-existing steps 01–08 (26 PASS, 0 FAIL, 1 GAP, 10 NOTE)

| Result | Step |
| --- | --- |
| NOTE | 00 audit-log preflight at startup — mcp "<run dir>/audit.jsonl" · ca "<run dir>/ca-audit.jsonl" (inside <run dir>) |
| NOTE | 00 dead port at startup — 53354 is none of {"proxy":53357,"web":53359,"target":53356} nor of the config's [53357,53358], and a connect is refused |
| NOTE | 03c transient phases — seen by the witness for under 1000 ms, not judged: passive (1 ms) |
| NOTE | 03 job state after the phase track — running · auditing (94 probes) |
| NOTE | 04 issue pick — no hinted-class row (listed: security-header, reflection, cookie-flag, headers); first row |
| GAP | 04d PoC ref — security-header (security-header, firm) carries no poc_ref and no hinted-class issue was listed |
| NOTE | 05 first job — terminal 555384 ms after step 4 ended |
| NOTE | 07 panel left for the inspector — the Scan panel unmounted |
| NOTE | 00 audit-log preflight after the 08b restart — mcp "<run dir>/audit.jsonl" · ca "<run dir>/ca-audit.jsonl" (inside <run dir>) |
| NOTE | 00 dead port after the 08b restart — 53354 is none of {"proxy":56106,"web":56108,"target":53356} nor of the config's [56106,56107], and a connect is refused |
| NOTE | 08b witness scan.start — status "needs_confirmation" |

The full log is `scan-live.log` (run directories replaced by `<run dir>`; the token lines dropped).

## Files

- `09-jobs-auditing.png`, `09-jobs-auditing-table.png`, `status-09.json` (AC58 (a))
- `10-jobs-cancelled.png`, `10-jobs-cancelled-table.png`, `status-10.json` (AC58 (b))
- `11-jobs-dead.png`, `11-jobs-dead-attention.png`, `11-jobs-dead-table.png`, `status-11.json` (AC58 (c))
- `config-audit-lines.txt`, `audit-before-after.txt`, `real-before.txt`, `real-after.txt`, `real-audit-diff.txt` (the #310 guard and AC59's last two clauses)
- `scan-live.log`, `proof.sh`

