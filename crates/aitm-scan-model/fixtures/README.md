# Scanner v2 fixture pack

One JSON example of **every** scanner bus verb result and **every** job push
line, as defined by the D3 verb contract in the scanner v2 design
(`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`).

## What this is for

The UI tracks — T7 (TUI), T8 (web) and T9 (macOS) — and the test harness build
against the scanner's wire shapes **before** the engine (T1b) lands. This pack is
the contract drop they develop against: each file is a complete, realistic
example of the exact type that verb or push line carries, so a frontend can parse
it, render it, and pin its own expectations without a running core.

Every value here is **invented**. The whole pack describes one imagined job,
`scan-1a2b3c4d`, run against `http://127.0.0.1:8080`. Nothing in it came from a
real target, a real session, or a real credential.

## What this is NOT

**A fixture run is never acceptance evidence.** The spec's Verification section is
explicit: the scanner is proven only by runs against real targets. A green parse
of this pack says the wire shapes are internally consistent and nothing more. No
UI, no reviewer, and no release gate may treat "the fixtures parse" as proof that
the scanner found, reported, or reproduced anything. Acceptance comes from the
T10 end-to-end cells against live services, not from here.

## Safety

No file carries a secret-looking value. Session material never reaches the wire
(spec D7): `scan.session.preview.json` lists cookie and header **names only**
(`sid`, `authorization`), never a value, and the sitemap's cookie example is
`<redacted>`. The test `no_fixture_carries_a_secret_value` enforces this by
rejecting any file that contains `Bearer `, `sid=`, `Set-Cookie`, `"Cookie":` or
`"Authorization":`.

## Files

| File | Type | Verb / push |
|---|---|---|
| `scan.start.json` | `StartResult` | `scan.start` |
| `scan.map.json` | `StartResult` | `scan.map` |
| `scan.status.json` | `JobStatus` | `scan.status` |
| `scan.list.json` | `ListResult` | `scan.list` |
| `scan.cancel.json` | `JobStatus` | `scan.cancel` |
| `scan.issues.json` | `IssuesResult` | `scan.issues` |
| `scan.issue.json` | `Issue` | `scan.issue` |
| `scan.issue.update.json` | `Issue` | `scan.issue.update` |
| `scan.sitemap.json` | `SitemapResult` | `scan.sitemap` |
| `scan.checks.json` | `ChecksResult` | `scan.checks` |
| `scan.profile.list.json` | `ProfileListResult` | `scan.profile.list` |
| `scan.profile.get.json` | `ScanProfile` | `scan.profile.get` |
| `scan.profile.save.json` | `ProfileSaveResult` | `scan.profile.save` |
| `scan.profile.delete.json` | `ProfileDeleteResult` | `scan.profile.delete` |
| `scan.session.preview.json` | `SessionProfile` | `scan.session.preview` |
| `job.started.json` | `JobNotification` | push `started` (`seq` 1) |
| `job.phase.json` | `JobNotification` | push `phase` (`seq` 2) |
| `job.progress.json` | `JobNotification` | push `progress` (`seq` 3) |
| `job.issue.json` | `JobNotification` | push `issue` (`seq` 4, carries the issue) |
| `job.finished.json` | `JobNotification` | push `finished` (`seq` 5, `state: done`) |
| `job.cancelled.json` | `JobNotification` | push `cancelled` (`seq` 6, `state: cancelled`) |
| `job.failed.json` | `JobNotification` | push `failed` (`seq` 7, `state: failed`) |

The push method is `notifications/aitm/job` (`JOB_NOTIFICATION_METHOD`) with
`kind: "scan"` (`JOB_KIND_SCAN`).

## How they are kept honest

`crates/aitm-scan-model/tests/fixtures.rs` parses every file back into its model
type, pins its key literals, checks the set of files is exactly this contract
surface (no stray, no missing), checks the push `seq` values run `1..=7`, and runs
the secret scan above. The files are hand-authored to match the serialised shape;
`tests/fixtures.rs` keeps them in sync.

Note that `dry_run` appears in `scan.start` results only for profiles with an L4
lane; `scan.start.json` is an HTTP-lane job, so it carries no `dry_run` key.
