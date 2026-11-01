# 12 - Burp-style scanner architecture (Burp Pro, ZAP active scan, nuclei)

Sources read 2026-10-31 through a fetch tool that returns model-written
summaries (`curl` was sandbox-blocked). Unseen items are marked UNVERIFIED.

## 1. Question

How do Burp Suite Professional's scanner (crawl and audit), OWASP ZAP's active
scanner, and nuclei structure a web vulnerability scan, so aitmproxy can design
a Burp-Pro-like scanner engine?

## 2. Short answer

All three separate target discovery, a per-request-location attack unit, and a
reporting model. Burp and ZAP both attack one "insertion point" or "variant
parameter" at a time, tune cost with an intensity or strength knob, repeat blind
tests to cut false positives, and rate each finding on severity plus
confidence. Burp adds a queue with priority scoring, consolidation of passive
issues, and resource pools. nuclei is template-first, with rate limits, a time-delay
analyzer ported from ZAP, and Interactsh for out-of-band (OOB).

## 3. Findings

### 3.1 Burp crawl

- Uses Burp's embedded Chromium by default and builds "a map of the application
  in the form of a directed graph". Locations are identified "based on their
  contents, not the URL". Breadth-first, link fingerprints, "configurable
  cutoffs". Requests are built from the previous response, so CSRF tokens in
  URLs or fields are handled. It runs scripts, so JS-built forms and
  event-handler clickables work. Volatile content is recorded as
  non-deterministic edges. (https://portswigger.net/burp/documentation/scanner/crawling)
- Discovery logic settings: Submit forms; Request robots file; Request site map
  (max items); Follow hidden links in comments and JavaScript (max items); Click
  all pointer clickable elements; "Application uses fragments for routing"
  (a fragment containing `/ \ ? = &` counts as routing by default).
  (https://portswigger.net/burp/documentation/scanner/scan-configurations/crawl-settings)
- Strategy: Crawl strategy with five named levels (Fastest, Faster, default,
  More complete, Most complete). Faster levels suit stable URLs and no state;
  more complete levels suit volatile URLs or complex state. Separate
  "Maximum crawl depth" (chained link clicks and form submissions). (crawl-settings)
- Limits: time elapsed, unique locations discovered, HTTP requests made.
  Timeout handling: consecutive timed-out requests, overall percentage of
  timed-out requests (each pauses the task), follow-up retry passes. Blank
  disables each. (crawl-settings)
- Login: username/password pairs or recorded login sequences, one per scan. Phases: unauthenticated crawl (may self-register), optional invalid-username failures, then an authenticated crawl per credential set. The crawler handles session mechanisms without macros or session-handling rules. Logins apply only to crawling. (crawling page; https://portswigger.net/burp/documentation/scanner/authenticated-scanning, via search summary)
- "Crawl using my session" as a named feature: NOT FOUND in the docs I read.
  UNVERIFIED that it exists under that name.

### 3.2 Burp audit

- Three phases: passive (no new requests), active (modified requests) and
  JavaScript analysis (static AST taint tracking plus dynamic headless-browser
  analysis; static findings get lower confidence). Active has intensities
  Light (few requests, unlikely to look malicious), Medium (may trigger alerts or
  log users out), Intrusive (may damage data).
  (https://portswigger.net/burp/documentation/scanner/auditing)
- Scheduling: each audit item has a priority score, "weighted 80/20 in favor of
  attack surface exposure over interest level". Exposure = how many new
  insertion points the item adds versus those already queued or audited.
  Interest = action type (POST/PUT rank higher), content type (HTML/JSON/XML
  higher), requires authentication (higher). (auditing page) Each phase runs for all items before the next (blog/multi-phase-scanning).
- Insertion point types (audit settings): URL parameter values, body parameter values, cookie values, parameter name, HTTP headers, entire body, URL path filename, URL path folders. Options: ignore points (skip server-side injection tests or all, match name/value by literal or regex, path folders by 1-based position), frequent-point lighter audit (reverts to full if server-side processing is seen), nested points (Base64 containing JSON), per-request point limit with a skipped count, and payload relocation (URL, body, cookie in each direction). (https://portswigger.net/burp/documentation/scanner/scan-configurations/audit-settings)
- Extender API enum is finer: URL/body/cookie/XML/XML-attr/multipart-attr/JSON/AMF values, header, URL path folder (REST alias deprecated), filename, added URL or body parameter name, entire body, user-provided, extension-provided, unknown. A point exposes name, base value, `buildRequest(raw payload)` (it handles encoding and Content-Length), payload offsets and type. (https://portswigger.net/burp/extender/api/burp/iscannerinsertionpoint.html)
- Check contract: `doPassiveScan` runs once per base request/response with no
  new requests; `doActiveScan` runs once per insertion point.
  (https://portswigger.net/burp/extender/api/burp/iscannercheck.html)
- Audit optimization: Audit speed Fast/Normal/Thorough (Fast makes fewer
  requests, checks fewer derivations); Audit accuracy "Minimize false
  negatives / Normal / Minimize false positives" controls "how many times Burp
  retries blind-technique tests"; "Skip checks unlikely to be effective" (for
  example no path traversal on values that do not look like filenames);
  "Allow crawl and audit phases to run in parallel"; total scan time in minutes
  (scan pauses when reached); "Issue noise reduction" consolidates frequent
  passive issues such as Clickjacking. (audit-settings)
- Audit error handling: ladder of consecutive failures (check, insertion point, item) then pause, plus follow-up retry passes; defaults not stated. (audit-settings)
- Passive consolidation: Burp "consolidates these identical issues and reports a
  single instance at the most relevant level" (auditing page).
- Throttling: resource pools (shared by Intruder and Scanner) set maximum concurrent requests, delay (fixed, random, incremental) and automatic throttling on status codes such as 429 and 503 (https://portswigger.net/burp/documentation/desktop/settings/project/tasks, via search summary). A pool is "a group of tasks that share a quota of network resources" (full-crawl-and-audit page).

### 3.3 Burp issues, configurations, task model

- Every issue has severity (High, Medium, Low, Information) and confidence
  (Certain, Firm, Tentative). Confidence "reflects the inherent reliability of
  the technique", so blind SQLi drops it. Users can reassign either or mark a
  false positive. (https://portswigger.net/burp/documentation/desktop/running-scans/results/issues, search summary)
  Tentative = high chance of false positive; Firm = probably present; Certain =
  definitely present (https://portswigger.net/burp/extensibility/dast/graphql-api/confidence.html).
- Issue definition fields: description, remediation, references, classifications (external links), typical severity, hexadecimal type index. (https://portswigger.net/burp/documentation/desktop/tools/target/issue-definitions)
- Issue instance fields in the table: time, source task, issue type, host, path,
  insertion point type, severity, confidence, comment; detail tabs Advisory,
  Request, Response, Path to issue. "Each issue is only recorded the first time
  it is found." (issues page above)
- Extender dedupe: when a check reports more than one issue for the same URL
  path, Burp calls `consolidateDuplicateIssues`; the check returns -1 (keep
  existing), 0 (keep both), 1 (keep new). (iscannercheck page)
  `IScanIssue` splits generic background/remediation from per-instance
  detail/remediation. (iscanissue API page)
- Configurations: preset modes plus named custom ones from a library (scan-configurations page). Built-ins include "Crawl strategy - faster/fastest", "Crawl limit - 10, 30, or 60 minutes", "Audit checks - light active / medium active / all except JavaScript analysis" (performance page), "all except time-based detection methods", "critical issues only", "Minimize false positives/negatives" (burp-scanner-built-in-configs, via search summary).
- Live tasks: "live audit" scans each request; "live passive crawl" adds site map items from traffic; options are tools monitored, URL scope, dedupe; "isolated scan" keeps results out of the site map. (https://portswigger.net/blog/burp-2-0-where-is-live-scanning, via search summary)
- Progress: Professional results views are Summary, Audit items (with insertion
  points), Issues, Event log, Audit log (search summary of the docs nav).
  Burp DAST shows requests made, discovered URLs, audited URLs with/without
  errors (search summary). The exact Professional counters and pause/resume/cancel
  semantics: UNVERIFIED.

### 3.4 ZAP active scan

- Scan policy chooses which rules run and "how likely potential issues are to be
  flagged". Per rule: Threshold (Off, Low, Medium, High; Low raises more, High
  raises fewer) and Attack Strength (Low, Medium, High, Insane). Policies can be
  locked so new rules do not run by accident. Many policies allowed.
  (https://www.zaproxy.org/docs/desktop/ui/dialogs/scanpolicy/; https://www.zaproxy.org/docs/desktop/start/features/scanpolicy/)
- Strength is a payload budget. In `SqlInjectionScanRule` error-based max is
  4/8/16/100 payloads at Low/Medium/High/Insane, boolean 0/6/20/100, UNION
  0/5/10/100; command injection payloads per OS are 3/7/13/all.
  (zap-extensions ascanrules)
- Scheduling (`HostProcess`): thread pool of `threadPerHost`; `plugin.targets(techSet)` skips rules for absent technology; skip reasons: no nodes, max rule duration, max alerts per rule, dependency; requests counted per plugin. Options: concurrent hosts, threads per host, max rule and scan duration, max alerts per rule, anti-CSRF handling. (HostProcess.java; https://www.zaproxy.org/docs/desktop/ui/dialogs/options/ascan/)
- Input vectors: URL query string, POST data, plain body, URL path, headers (option: all requests), cookies; handlers for multipart, XML, JSON, GWT, OData; script vectors; "Add URL Query Parameter" for GET requests with none; ignored parameters (https://www.zaproxy.org/docs/desktop/ui/dialogs/options/ascaninput/). `AbstractAppParamPlugin` builds variants, iterates each variant's parameters, skips excluded params and anti-CSRF tokens, and records the variant as the alert's input vector.
- Progress: per host, running rules, elapsed time, requests per rule, skip button (scanprogress page). API `ascan`: start (contextId, recurse, inScopeOnly, scanPolicyName, method, postData) returns a scan id; status gives a percentage; pause, resume, stop, per-scanner strength and threshold exist (https://www.zaproxy.org/docs/api/; only status/start were described, other names inferred).
- Alert model: risk 0-3 (Informational, Low, Medium, High); confidence 0-4 (False
  Positive, Low, Medium, High, Confirmed). Fields: pluginId, alertRef, name,
  uri, method, param, attack, evidence, inputVector, otherInfo, description,
  solution, reference, cweId, wascId. `equals` is true for the same alertId, else
  requires equal risk, confidence, pluginId, alertRef, name, method, node/uri,
  param, otherInfo, evidence, attack, inputVector. (Alert.java)
  The alert tree drops an alert it already holds, and a per-host "systemic" limit
  caps alerts. (ExtensionAlert.java; the tree-model matching code was not seen.)

### 3.5 nuclei

- Scheduling: `-rl` 150 req/s (takes precedence over `-c` and `-bs`), `-c` 25
  templates in parallel, `-bs` 25 targets in parallel, `-pc` 25 payloads per
  template, `-timeout` 10 s, `-retries` 1, `-mhe` 30 errors before a host is
  dropped, `-nmhe` disables that. Strategies: `template-spray` (one template
  across many targets, lighter per-target load, more memory), `host-spray`
  (all templates per target, no resume); `auto` is currently template-spray.
  (https://docs.projectdiscovery.io/opensource/nuclei/running; .../mass-scanning-cli)
- DAST fuzz rule: `part` (query default, path, header, cookie, body, request),
  `parts`, `type` (replace, prefix, postfix, infix, replace-regex), `mode`
  (multiple, single), `keys`, `keys-regex`, `values`, `fuzz`. JSON, XML, form and
  multipart bodies are exposed as key-value pairs; other bodies become one pair
  `value`. `pre-condition` gates fuzzing (v3.2.4).
  (https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview)
- No Burp-style confidence on nuclei findings. ResultEvent fields: template-id, matcher-name, extracted-results, matched-at, type, curl-command, timestamp, interaction; severity lives in the template info block (output.go; templates/structure; severity value set UNVERIFIED).
- Dedupe: output.go has no hash dedupe; it only avoids duplicate Interactsh
  events (`InteractshMatched`) and suppresses "honeypot" hosts. In `-dast` mode,
  input is deduplicated, and parameters found uninteresting repeatedly are
  skipped (`-fuzz-param-frequency`; the log line is "as found uninteresting 10
  times"), per PR #5139 and DeepWiki via search summary. Flag name and default
  UNVERIFIED against source. `-dast-proxy` (PR #7725) mirrors in-scope proxy
  traffic into the fuzz queue.
- OOB: `{{interactsh-url}}` placeholder; matchers read `interactsh_protocol`,
  `interactsh_request`, `interactsh_response`; "Nuclei will handle correlation of
  the interaction to the template & the request it was generated from"
  (https://docs.projectdiscovery.io/templates/reference/oob-testing). Interactsh
  payload = 20-char correlation id plus 13-char nonce as a subdomain; client polls
  every 5 s by default; nuclei defaults: cache 5000, eviction 60 s, cooldown 5 s.
  (https://raw.githubusercontent.com/projectdiscovery/interactsh/main/README.md; running page)

### 3.6 Blind, timing and OOB patterns

- Boolean differential (ZAP): resend the original as a control; AND-true must
  match the original, AND-false must differ; OR-true variant if AND-false matches;
  an OR-true response over 1.2x the original length is confirmed with an AND-false
  request; ORDER BY confirmed with DESC. Control requests are not counted toward
  limits, and the original is re-sent because payloads "may have actually
  succeeded in modifying the database". Compared bodies are stripped of the
  injected values. Error checks use a control value and require the error absent
  from the original response. (SqlInjectionScanRule.java)
- Time delay (ZAP/nuclei): request sleep values alternate between large and
  small, a linear regression of requested versus observed delay must correlate.
  ZAP MySQL timing: sleep 5 s, at most 4 requests per template, correlation error
  range 0.15, slope error range 0.30; confidence Medium.
  (SqlInjectionMySqlTimingScanRule.java; https://github.com/zaproxy/zaproxy/issues/8112).
  The nuclei `time_delay` analyzer ports this: `sleep_duration` 5, `requests_limit`
  4, same ranges; docs and pkg.go.dev disagree on the sleep default (docs 5,
  pkg.go.dev 7), and PR #5878 reportedly dropped the slope check.
  (https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview;
  https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/time)
- Burp: repeats blind tests when it first infers an issue (count set by Audit accuracy); confidence drops for blind techniques. Collaborator "can identify the exact Burp Scanner payload behind each interaction" and reports deferred interactions, so second-order flaws are found (https://portswigger.net/burp/documentation/collaborator/uses, via search summary).
- ZAP's command-injection rule read is feedback-based only (no timing or OAST).
  ZAP SSRF/OAST: not researched.

## 4. Candidate directions (not decisions)

Existing scanner: `enumerate`/`InjectionPoint`/`Location`, a crawl, passive
checks and a guarded active client (the two scanner specs, Intent/Goals only).

**Insertion point enum** (union of Burp settings and API, and ZAP vectors):
UrlParamValue, BodyParamValue, CookieValue, HeaderValue, UrlPathFolder,
UrlPathFilename, ParamNameUrl, ParamNameBody, EntireBody, JsonValue, XmlValue,
XmlAttr, MultipartValue, MultipartFilename, UserProvided. Trade-off: each format
needs a parser; Burp's settings page lists only eight. Copy Burp's rule that the
insertion point, not the check, owns encoding and Content-Length.

**Issue taxonomy:** severity High/Medium/Low/Information x confidence
Certain/Firm/Tentative, confidence set by technique (OOB or reflected marker =
Certain; boolean or timing differential = Firm or Tentative). A separate
`status` (open, false_positive, confirmed) keeps the two ratings immutable. A
per-type definition record: id, name, typical severity, description,
remediation, references, CWE.

**Scan profile fields:** crawl {strategy fastest..most_complete, max_depth,
max_time, max_locations, max_requests, submit_forms, robots, sitemap,
hidden_links, click_pointer, fragment_routing, auth_only}; audit {phases
passive/light/medium/intrusive/js, speed, accuracy, skip_unlikely,
insertion_point_types, ignore_rules, point_limit, relocation,
parallel_with_crawl, max_time}; errors {consecutive-failure ladder, pause
percentage, follow-up passes}; throttle {max_concurrent, delay, 429/503 backoff,
per-host error cap}; optional per-check threshold and strength (ZAP). Trade-off:
Burp has three orthogonal axes (intensity = target risk, speed = request count,
accuracy = retry count); ZAP folds count into one strength knob. Burp's axes
fit aitmproxy's deny-by-default, Sensitive-gated model because intensity is a
safety property.

**Progress counters:** requests, errors, timeouts, locations, audit items
total/done, insertion points queued/audited/skipped (reason: limit, ignored,
frequent-uninteresting), issues by severity, per-check requests and elapsed
(ZAP), phase, status (queued, running, paused, cancelled, failed, done),
elapsed. Verbs: pause, resume, cancel, skip-check.

**Dedupe key:** active: (issue_type, host, method, normalised path,
insertion_point_type, insertion_point_name), raising confidence on repeat (ZAP's
key adds evidence, attack and input vector, so it dedupes exact repeats only).
Passive: Burp-style consolidation on (issue_type, host, evidence signature),
reported once at the most relevant level. Also dedupe work: skip insertion
points already audited (Burp exposure score, nuclei param-frequency skip).

**Scheduler:** priority = 0.8 x exposure + 0.2 x interest (method, content type,
auth); each phase across all items before the next; per-host error counters
(nuclei 30, Burp failure ladder).

**Blind template:** stable control, payload and false-payload pair, N repeats set
by accuracy. Timing: alternating sleep plus correlation (constants above). OOB:
unique per-request token, listener, correlate and poll; needs an explicit
deny-by-default decision on external services (nuclei defaults to public
Interactsh servers; a self-hosted one is possible).

## 5. Open questions

- Burp "crawl using my session" and live-proxy cookie reuse: not found.
- Burp Professional progress counters and pause/cancel semantics.
- Burp's five active sub-phases (names not retrieved) and issue type ids.
- ZAP `AlertTreeModel` dedupe, `TimingUtils` source, ZAP OAST add-on.
- nuclei `-fuzz-param-frequency` default and the dedupe source path; interactsh
  correlation internals.

## 6. Sources

- Burp, under https://portswigger.net/burp/: `documentation/scanner/` (crawling, auditing, scan-configurations and its crawl-settings, audit-settings, burp-scanner-built-in-configs pages, authenticated-scanning), `documentation/desktop/` (running-scans full-crawl-and-audit and results/issues, tools/target/issue-definitions, troubleshooting/performance, settings/project/tasks), `documentation/collaborator/uses`, `extender/api/burp/` (iscannerinsertionpoint, iscannercheck, iscanissue), `extensibility/dast/graphql-api/confidence.html`; blog multi-phase-scanning and burp-2-0-where-is-live-scanning.
- ZAP: https://www.zaproxy.org/docs/ (scanpolicy, options/ascan, options/ascaninput, scanprogress, api); github.com/zaproxy/zaproxy (Alert, AbstractAppParamPlugin, HostProcess, ExtensionAlert, issue 8112); github.com/zaproxy/zap-extensions (ascanrules SqlInjectionScanRule, SqlInjectionMySqlTimingScanRule, CommandInjectionScanRule).
- nuclei: https://docs.projectdiscovery.io/ (running, mass-scanning-cli, fuzzing-overview, oob-testing, templates/structure); github.com/projectdiscovery/nuclei (output.go; PRs 5139, 5878, 7725); github.com/projectdiscovery/interactsh README; pkg.go.dev nuclei fuzz/analyzers/time.
- Repo: `docs/research/02-nuclei.md`; the two scanner specs.
