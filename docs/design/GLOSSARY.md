# Glossary

Every thing the operator surfaces (macOS app, web UI, TUI) show has exactly one
name, and the name lives here. A word in the **Not** column never appears on
screen for that idea. Buttons, menus, titles, tooltips, errors and VoiceOver
labels all use the **Term** column. Apple's words are used for system actions
(Settings, Quit, Close, Undo, Copy).

Wire tokens (the snake_case words the bus carries) are listed under each term
so a reader can map a screen word back to the protocol; they never appear on
screen except in a monospace id or path.

## Scanner

| Term | Means | Not |
| --- | --- | --- |
| Scan | The feature: probing in-scope targets for issues. "Scan" is the page, "Start Scan" the verb. | audit, test, run, assessment |
| Job | One scan the engine accepted, running or finished, with an id `scan-<8 hex>`. The Jobs tab lists them, newest first. | run, task, scan job, scan run |
| Profile | The saved settings a job starts from: target, lanes, intensity, speed, accuracy, checks, budget, session. Built-in or saved. | preset, config, template, policy |
| Target | The origin or origins a job scans (`https://app.example`). Shown as `host[:port]`. Wire: `targets`, `target.origins`. | host, site, URL, origin (wire word only) |
| Phase | What a running job is doing now: Crawling, Passive checks, Auditing, Reporting. Wire: `phase`. | stage, step, mode |
| Crawl | The phase that finds pages and forms on the target. Wire: `crawl`. | spider, discovery |
| Passive checks | Checks that only read captured traffic and send nothing. Wire: `passive`. | passive scan |
| Auditing | The phase that sends probes to insertion points. Wire: `auditing`. | active scan, attack, fuzzing (HTTP) |
| Probe | One request a job sends to the target. Wire: `probes.sent`. | request, hit, payload |
| Probe budget | The most probes a job may send; spending it ends the job. Wire: `probes.budget`, `stopped_reason: budget`. | limit, cap, quota, max requests |
| Time budget | The longest a job may run. Wire: `budget.time`, `stopped_reason: time`. | timeout, deadline |
| Point | A place in a request where a check can inject: a parameter, header, cookie, path segment. Wire: `points`. | parameter, insertion point, injection point, param |
| Check | One test applied to one point, by id (`xss-reflected`). Wire: `checks`, `check`. | rule, test, plugin, scanner, module |
| Check error | A check run that could not say whether the point is vulnerable. Wire: `checks.errors`, `error_samples`. | failure, exception |
| Issue | What a check found. Shown on the Issues tab. Wire: `issues`. | finding (the proxy's own Findings page), vulnerability, alert, hit |
| Severity | How bad an issue is: Critical, High, Medium, Low, Info. The one datum drawn in colour. | priority, level, risk |
| Confidence | How sure the check is: Certain, Firm, Tentative. | certainty, score |
| Lane | A protocol a job scans over: HTTP, WebSocket, L4 packet, L4 stream. Wire: `lanes`, `lane`. | channel, protocol, mode, track |
| Site map | The pages and points a job found, by origin and path. | sitemap, tree, discovery results |
| Session | A logged-in state the job keeps or observes while it probes. Wire: `session`. | login, auth, cookie jar |
| Budget | The probe budget and the time budget together. | limits, caps |

## Job states

| Term | Means | Not |
| --- | --- | --- |
| Queued | The engine accepted the job and has not started it. Wire: `queued`. | pending, waiting, scheduled |
| Running | The job is working; the phase word says what it is doing. Wire: `running`. | active, in progress, live |
| Cancelling | Cancel Scan was sent; the engine is winding the job down. Wire: `cancelling`. | stopping, aborting |
| Done | The job finished on its own. Wire: `done`. | finished, complete, completed, success |
| Cancelled | The operator stopped the job. What it found stays. Wire: `cancelled`. | stopped, aborted, killed |
| Failed | An error ended the job; the error text says what. Wire: `failed`. | error, crashed, broken |
| Stopped reason | Why a job ended early, as a sentence: the probe budget was spent, the time budget ran out, cancelled, the session was lost, too many errors, the agent policy changed, the L4 guard refused a target, an error. Wire: `stopped_reason`. | exit reason, exit code, status |

## Job actions

| Term | Means | Not |
| --- | --- | --- |
| Start Scan | Start a job from the profile in the editor (⌘⏎). The job appears selected on the Jobs tab. | run, launch, go, execute |
| Map Only | Start a job that crawls and fills the Site map without probing. | discover, spider, crawl only |
| Cancel Scan | Ask the engine to stop the selected job (⌥⌘.). Issues and the site map stay. No confirmation: nothing is lost that cannot be re-run. | stop, abort, kill, terminate |
| Scan Again | Start a new job with a finished job's profile and target. | retry, rerun, restart, repeat |
| Show Issues | Open the Issues tab filtered to this job. | view findings, open issues |
| Show Site Map | Open the Site map tab for this job. | view map |
| Copy Job ID | Put the job's id on the clipboard. | copy id |
| Open Profiles | Go to the Profiles tab (the empty Jobs tab's one action). | go to profiles |

## Progress words

| Term | Means | Not |
| --- | --- | --- |
| Progress | How far the job is through its work, as a fraction and a bar: pages fetched of pages known while crawling, checks done of checks scheduled while auditing. Not the probe budget. | completion, percent done, ETA |
| Elapsed | Wall time since the job started, `m:ss` or `h:mm:ss`. Wire: `elapsed_ms`. | duration, runtime, uptime |
| Now | The checks running at this moment, by id. Wire: `checks.running`. | current, active checks, in flight |
| Started | When and by whom the job started: this app, the CLI, an agent. Wire: `started_at`, `started_by`. | created, launched |
| Finished | When the job reached its end state. Wire: `finished_at`. | ended, completed at |
