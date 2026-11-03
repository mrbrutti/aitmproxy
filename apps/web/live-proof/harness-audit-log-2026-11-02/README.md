# Live proof: web harness audit-log isolation (AC7)

Spec `docs/superpowers/specs/2026-11-02-web-harness-audit-log-isolation.md`, plan Task 4. Run 2026-11-02 20:30–20:35
from the Terminal with `proof.sh` (this folder), branch `fix/web-harness-audit-log` at 58f45ede (code) + 2fd0af33 (tester),
release binaries built from this worktree (`npm run build` then `cargo build --release -p aitm -p aitm-testtarget`),
`AITM_AUDIT_LOG` unset (`env -u`).

| Check | Evidence | Result |
| --- | --- | --- |
| `scan-live.mjs` itself | `scan-live.log` (token redacted on the `aitm up` line) | `{"pass":27,"fail":0,"gap":0}`, exit 0 |
| Real `audit.jsonl`, `audit.agent.jsonl`, `ca-audit.jsonl`, `system-proxy-state.json` | `real-before.txt` vs `real-after.txt` | identical (size, mtime, sha256) |
| Real `audit.reads.jsonl` | `run-dirs.txt` + `reads-writers.txt` | grew 7,978,037 → 8,258,225 bytes. The harness cores are excluded as writers by construction: each run dir's config names its own `audit_log` paths and each holds its own populated `audit.reads.jsonl` (119,827 and 3,931 bytes). The post-run `lsof` corroborates: the one process holding the real file is the installed app's core (pid 11561, started 14:50, hours before the run). AC7 amendment |
| Run dir 1 (`aitm-live-OPyeZz`, the startup core) | `run-dirs.txt` | config lines 14/17 name its own `ca-audit.jsonl` / `audit.jsonl`; `audit.jsonl` 2,055 bytes, `audit.agent.jsonl` 97, `audit.reads.jsonl` 119,827; `scan.cancel` lines: 1 (step 05 PASS) |
| Run dir 2 (`aitm-live-E1UMKQ`, the step 08b restart) | `run-dirs.txt` | config lines 14/17 name its own paths; `audit.jsonl` 859 bytes, reads 3,931; no cancel (none pressed) |
| Secrets in the evidence | `grep -rE 'opsecret-\|live-[a-z0-9]{12,}\|#t='` over the folder (the plan's grep) | one hit: the redaction marker `#t=<redacted>` on the `aitm up` line of `scan-live.log`; the 64-hex strings in `real-*.txt` are sha256 digests, not tokens |

`proof.sh` is the plan's script verbatim. `config.yaml` of a run dir is never copied here (it holds the operator secret and the
bridge token); `run-dirs.txt` holds only its `audit_log` lines and the directory listing.
