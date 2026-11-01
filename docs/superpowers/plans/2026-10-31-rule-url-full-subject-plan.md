# Rule `url` clause matches the full request URL implementation plan

**Status:** approved (2026-10-31, autonomous mode on Matt's standing instruction)
**Spec:** `docs/superpowers/specs/2026-10-31-rule-url-full-subject-design.md`
**Branch / worktree:** `claude/distracted-poincare-6d5777` at `/Users/matt/Security/aitmproxy/.claude/worktrees/distracted-poincare-6d5777` (base `0f000174` on `main`)

## Overview

Task 1 changes the one matcher and lands the shared case table; it runs first and
alone. Tasks 2, 3 and 4 then fan out in parallel on disjoint files: Task 2 is
the Rust contract (plugin schema text, plugin-level and MCP-level tests), Task 3
is the macOS Kit preview pinned to the case table, Task 4 is the real-core e2e
cell plus the operator docs. The Rust gate runs after every task; the Swift
tests and the e2e cell run in the Terminal panel (SwiftPM and port binding are
not available in the sandbox). Coders do not commit: four writers share one
worktree, so the orchestrating session commits each task's files when its
report is in.

## Tasks

### Task 1: `aitm-rules` matches the full URL and the path

- **Satisfies:** AC1–AC11 (Rust side), AC15 (module docs)
- **Depends on:** none
- **Files:** `crates/aitm-rules/src/lib.rs` (modify), `crates/aitm-rules/Cargo.toml` (modify: add `serde_json = "1"` under a new `[dev-dependencies]` section), `Cargo.lock` (the one-line consequence of that dev-dependency; declared 2026-10-31 after panel 3), `crates/aitm-rules/tests/matches.rs` (modify), `crates/aitm-rules/tests/cases/url-match-cases.json` (create), `crates/aitm-rules/tests/url_match_cases.rs` (create)
- **Change:**
  - Module docs: replace the "URL match subject" section with the spec's
    subject, wildcard and regex rules (full URL `scheme://authority path`,
    path alone, either matches; `*` any run, other chars literal, anchored
    when a `*` is present, substring otherwise, case-insensitive; regex
    searched, case-insensitive by default, `(?-i)` opts out).
  - `fn wildcard_to_regex(pattern: &str) -> String`: anchor with `^…$` only
    when `pattern.contains('*')`; `?` stays escaped (literal).
  - `fn compile_pattern(regex_src, pattern)`: gains a `case_insensitive: bool`
    argument (or a sibling builder) so the `url` wildcard and `url` regex
    compile with `RegexBuilder::case_insensitive(true)` under the same
    `REGEX_SIZE_LIMIT`. Host wildcards keep their lowercase-both approach
    unchanged.
  - `CompiledRule::matches`: for the `url` clause build
    `format!("{}://{}{}", req.scheme, req.authority, req.path)` once and match
    `url.is_match(&full) || url.is_match(&req.path)`. No `aitm-core` change.
  - Case table `url-match-cases.json` (literal matcher cases, not sample data):
    ```json
    { "about": "One case per line. Read by crates/aitm-rules/tests/url_match_cases.rs and apps/mac/Tests/AitmproxyKitTests/BreakpointRuleCasesTests.swift; both must agree.",
      "cases": [
        { "ac": "AC1", "kind": "wildcard", "pattern": "*httpbin.org*", "scheme": "http",  "authority": "httpbin.org",     "path": "/get",      "expect": true },
        { "ac": "AC1", "kind": "wildcard", "pattern": "*httpbin.org*", "scheme": "https", "authority": "httpbin.org:443", "path": "/anything", "query": "x=1", "expect": true },
        { "ac": "AC1", "kind": "wildcard", "pattern": "*httpbin.org*", "scheme": "http",  "authority": "example.com",     "path": "/get",      "expect": false },
        { "ac": "AC2", "kind": "wildcard", "pattern": "https://api.*/v1/*", "scheme": "https", "authority": "api.example.com", "path": "/v1/users", "expect": true },
        { "ac": "AC2", "kind": "wildcard", "pattern": "https://api.*/v1/*", "scheme": "https", "authority": "www.example.com", "path": "/v1/users", "expect": false },
        { "ac": "AC2", "kind": "wildcard", "pattern": "https://api.*/v1/*", "scheme": "http",  "authority": "api.example.com", "path": "/v1/users", "expect": false },
        { "ac": "AC3", "kind": "wildcard", "pattern": "*/login", "scheme": "https", "authority": "h.test", "path": "/api/login", "expect": true },
        { "ac": "AC3", "kind": "wildcard", "pattern": "/api/*",  "scheme": "https", "authority": "h.test", "path": "/api/x",     "expect": true },
        { "ac": "AC3", "kind": "regex",    "pattern": "^/v[0-9]+/users$", "scheme": "https", "authority": "h.test", "path": "/v2/users",   "expect": true },
        { "ac": "AC3", "kind": "regex",    "pattern": "^/v[0-9]+/users$", "scheme": "https", "authority": "h.test", "path": "/v2/users/1", "expect": false },
        { "ac": "AC4", "kind": "regex",    "pattern": "^https://api\\.", "scheme": "https", "authority": "api.example.com", "path": "/x", "expect": true },
        { "ac": "AC4", "kind": "regex",    "pattern": "^https://api\\.", "scheme": "http",  "authority": "api.example.com", "path": "/x", "expect": false },
        { "ac": "AC5", "kind": "wildcard", "pattern": "*HTTPBIN.ORG*",       "scheme": "http", "authority": "httpbin.org", "path": "/get", "expect": true },
        { "ac": "AC5", "kind": "regex",    "pattern": "httpbin\\.ORG",       "scheme": "http", "authority": "httpbin.org", "path": "/get", "expect": true },
        { "ac": "AC5", "kind": "regex",    "pattern": "(?-i)httpbin\\.ORG",  "scheme": "http", "authority": "httpbin.org", "path": "/get", "expect": false },
        { "ac": "AC6", "kind": "wildcard", "pattern": "httpbin.org", "scheme": "http",  "authority": "httpbin.org",           "path": "/get",        "expect": true },
        { "ac": "AC6", "kind": "wildcard", "pattern": "api/orders",  "scheme": "https", "authority": "api.shop-staging.test", "path": "/api/orders", "query": "page=3", "expect": true },
        { "ac": "AC6", "kind": "wildcard", "pattern": "/get",        "scheme": "http",  "authority": "httpbin.org",           "path": "/anything",   "expect": false },
        { "ac": "AC7", "kind": "wildcard", "pattern": "*/search?q=*", "scheme": "https", "authority": "h.test", "path": "/search",   "query": "q=1", "expect": true },
        { "ac": "AC7", "kind": "wildcard", "pattern": "*/search?q=*", "scheme": "https", "authority": "h.test", "path": "/searchXq=1",               "expect": false },
        { "ac": "AC8", "kind": "wildcard", "pattern": "*h.test:443*", "scheme": "https", "authority": "h.test:443", "path": "", "expect": true },
        { "ac": "AC8", "kind": "wildcard", "pattern": "*/",           "scheme": "https", "authority": "h.test:443", "path": "", "expect": false }
      ] }
    ```
    `path` is the path alone; an optional `query` (no `?`) is joined as
    `path?query` into `HttpRequest.path` on the Rust side and passed as
    `FlowRow.query` on the Swift side.
  - `tests/url_match_cases.rs`: read the case table with `serde_json`
    (`include_str!("cases/url-match-cases.json")`), build a `GET` HTTP flow
    per case, `compile` a request-phase rule with the `url` clause, and
    assert `matches(..) == expect` for every case, reporting the failing case's
    `ac`, `pattern` and URL in the panic message. Fail if `cases` is empty.
  - `tests/matches.rs`: keep every existing test (they must still pass), fix
    the header comment that says "path subject", and add AC9
    (`host_and_url_clauses_combine`: `{host: Exact("httpbin.org"), url: Wildcard("*/get")}`
    matches `GET http://httpbin.org/get`, not `/post`) and AC10's size-cap
    check under case-insensitivity (the existing `oversized_regex_rejected`
    stays and must still reject).
- **Test:** `cargo test -p aitm-rules` → `url_match_cases::every_case_agrees_with_the_core` fails on the current matcher at the first AC1 case and passes after the change; the 15 existing tests stay green.
- **Done when:** both test files pass and the full gate passes.

### Task 2: `flow.intercept` contract — schema text, plugin-level and MCP-level tests

- **Satisfies:** AC12, AC13, AC15 (schema description)
- **Depends on:** Task 1
- **Files:** `crates/aitm-plugins/src/intercept.rs` (modify: the `url` entry of `rule_param_fields` only), `crates/aitm-plugins/tests/intercept_rules.rs` (modify), `crates/aitm/tests/intercept_url_rules_mcp.rs` (create), `crates/aitm-plugin-wsctl/src/lib.rs` (modify: the one-line `url` field description in the `ws.intercept` rule schema only), `crates/aitm-plugin-maprules/src/lib.rs` (modify: the `condition` param description of `map.add` only, which today says "Matches the request target path and authority" and is now wrong)
- **Change:**
  - `rule_param_fields()` `url` description becomes, in substance: "URL
    match against the full request URL (scheme://host[:port]/path?query) and
    against the path alone; either may match. A wildcard string (* = any run,
    other characters literal, case-insensitive; without * it matches as a
    substring), or {wildcard} / {regex} (regex is searched, case-insensitive
    by default, (?-i) restores case)." The `frontends.rs` operator schema
    snapshot does not cover `flow.intercept`, so no snapshot update is due;
    confirm by running `cargo test -p aitm frontends`.
  - `intercept_rules.rs`: add `host_bearing_rule_parks_matching_host`
    (AC12): arm `{url:"*ex.test*", phase:"request"}`; a flow
    `GET http://ex.test/anything` parks and is `Intercepted`; a flow with
    authority `other.test` and the same path is not parked. Give the file's
    `http_flow` helper an authority parameter (or add `http_flow_at(authority, path)`).
  - `intercept_url_rules_mcp.rs` (AC13), modelled on
    `crates/aitm/tests/l4_acceptance_mcp.rs` and `frontends.rs`: build the
    proxy with `build_proxy(&cfg)` (temp CA dir as `frontends.rs` does),
    `McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(store, client, guard, None)`;
    call `tools/call flow.intercept {enabled:true, rules:[{url:"*ex.test*", phase:"request"}]}`
    through `handle_on(&ConnCtx::new(Frontend::Operator), ..)` (arming is
    sensitive; the operator role is the one that may do it) and assert
    `isError == false` and `structuredContent.rules[0].url.wildcard == "*ex.test*"`;
    insert two flows (`http://ex.test/anything`, `http://other.test/anything`),
    dispatch `Event::Request(id)` for each through the registry's plugins over
    a `FlowCtx` the way `intercept_rules.rs::dispatch_request` does, persist
    the flow, then `tools/call flow.get {id}` as the operator and assert
    `structuredContent.intercept == "intercepted"` for `ex.test` and
    `"observed"` for `other.test`. If a plugin in the assembled chain cannot
    run `on_event(Request)` in a unit context, dispatch to the plugin named
    `intercept` only and say so in a comment.
- **Test:** the two new tests fail before Task 1's matcher (the `*ex.test*` rule never parks) and pass after; `cargo test -p aitm-plugins --test intercept_rules` and `cargo test -p aitm --test intercept_url_rules_mcp` green.
- **Done when:** both pass and the full gate passes.

### Task 3: macOS Kit preview agrees with the core

- **Satisfies:** AC11 (Swift side), AC7 and AC6 as the preview sees them
- **Depends on:** Task 1 (the case table)
- **Files:** `apps/mac/Sources/AitmproxyKit/BreakpointRules.swift` (modify: `matches(_:)` and `wildcardMatches(pattern:text:)` and their doc comments only; `validationError` and the types stay as they are; `arguments`' wildcard arm changed at the merge with #202, see the Review log), `apps/mac/Tests/AitmproxyKitTests/BreakpointRulesTests.swift` (modify), `apps/mac/Tests/AitmproxyKitTests/BreakpointRuleCasesTests.swift` (create)
- **Change:**
  - `matches(_ row: FlowRow)`: subjects are `row.url` and
    `row.path + (row.query.map { "?" + $0 } ?? "")`; the rule matches when
    the wildcard or regex matches either subject. Method check unchanged.
  - `wildcardMatches(pattern:text:)`: lowercase both; a pattern with no `*`
    is a substring test; otherwise `*` → `.*`, every other character
    (including `?`) escaped, anchored `^…$`. Doc comment: "`*` any run; every
    other character is literal (`?` starts a query); a pattern without `*`
    matches as a substring. Mirrors `crates/aitm-rules` (the core is
    authoritative; `url-match-cases.json` pins both)."
  - Regex branch keeps `.caseInsensitive`.
  - `BreakpointRuleCasesTests.swift`: locate the case table from `#filePath`
    (five `deletingLastPathComponent()` to the repo root, then
    `crates/aitm-rules/tests/cases/url-match-cases.json`), decode
    `{cases: [{ac, kind, pattern, scheme, authority, path, query?, expect}]}`,
    build a `FlowRow(id: FlowID("case-N"), seq: N, method: .get, scheme:, authority:, path:, query:)`
    per case, a `BreakpointRule(url: pattern, matching: kind == "regex" ? .regex : .wildcard)`,
    and `#expect(rule.matches(row) == expect, "\(ac) \(kind) \(pattern) vs \(row.url)")`.
    Fail (do not skip) when the file is missing or `cases` is empty.
  - `BreakpointRulesTests.swift`: the `?` assertion flips to pin the literal
    rule (`wildcardMatches(pattern: "https://?pi.*", text: "https://api.x")`
    is now `false`; add `wildcardMatches(pattern: "*/search?q=*", text: "https://h/search?q=1")` is `true`);
    every other expectation stays (login `[50]`, substring `[45, 46]`, posts
    `[44, 50]`, regex `[51, 53]`, `*shop-staging*` count `13`).
- **Test:** in the Terminal panel, `cd apps/mac && swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build --filter BreakpointRule` → `BreakpointRuleCasesTests` fails on the current `matches` (the `/api/*` and `^/v[0-9]+/users$` path-anchored cases and the AC7 `*/search?q=*` negative, where `?` matched the `X`) and passes after; `BreakpointRulesTests` green.
- **Done when:** both Swift suites pass in the Terminal (the sandbox cannot run SwiftPM; the coder writes the code and the orchestrating session runs the tests and feeds back any failure).

### Task 4: real-core e2e cell and operator docs

- **Satisfies:** AC14, AC15 (SKILL.md, site)
- **Depends on:** Task 1 (to pass; it can be written in parallel)
- **Files:** `tests/e2e/proxy/test_intercept_url_rules.py` (create), `tests/e2e/proxy/README.md` (modify: one catalogue entry, added 2026-10-31 after panel 1), `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md` (modify: the `url` sentence under "Arm interception"), `site/docs.html` (modify: the one sentence at the "To hold only some traffic" paragraph)
- **Change:**
  - The cell follows `tests/e2e/proxy/test_intercept_replay.py` exactly
    (`# e2e: tier=T1 surface=proxy needs=curl`, `ProxyConfig` with free
    ports and the upstream authority in scope, `Aitm.server`, `BusClient.operator`,
    `_clients.curl`/`find_flow`/`wait_for`, `Upstream().received`). Four
    positive rounds, each: arm `flow.intercept {enabled:true, rules:[rule]}`,
    `curl -x` the proxy for a distinct path, poll `flow.get` until
    `intercept == "intercepted"` and the path matches, `flow.resume`, join
    curl, assert the upstream recorded the path, disarm. Rules:
    `{"url": f"*127.0.0.1:{up.port}*"}` (host-bearing wildcard, path `/hostrule`),
    `{"url": f"http://127.0.0.1:{up.port}/scheme*"}` (scheme-bearing wildcard, `/schemerule`),
    `{"url": {"regex": f"^http://127\\.0\\.0\\.1:{up.port}/re"}}` (anchored regex, `/rerule`),
    `{"url": f"127.0.0.1:{up.port}/sub"}` (star-less substring, `/substr`).
    One negative round: arm `{"url": "*nomatch.invalid*"}`, curl `/negative`
    with a 15 s timeout, assert it returned `200` and that `flow.get` for
    that flow is not `intercepted`. Always disarm in `finally`.
  - SKILL.md: after the `url` field sentence add "matched against the full
    URL (`scheme://host[:port]/path?query`) and against the path alone;
    wildcards are case-insensitive and a pattern without `*` matches as a
    substring; a regex is searched case-insensitively (`(?-i)` opts out)".
  - `site/docs.html`: extend the sentence "a method, a host, a URL pattern
    and a phase" so the URL pattern is described as matched against the
    full URL and the path (one clause; keep the markup).
- **Test:** in the Terminal panel, `cargo build -p aitm && python3 tests/e2e/proxy/test_intercept_url_rules.py` exits 0 with five `[ok]` sections; before Task 1 the first round times out waiting for the park.
- **Done when:** the cell passes in the Terminal and the gate passes (the cell is not part of `cargo test`).

### Fix task A (after panel 1, 2026-10-31): findings F1–F7

- **Satisfies:** AC15 (anchoring clause), AC17, AC18, AC19; quality M2/M3/M6.
- **Depends on:** Tasks 1–4, Tester.
- **Files:** `crates/aitm-rules/src/lib.rs`, `crates/aitm-rules/tests/matches.rs`, `crates/aitm-rules/tests/cases/url-match-cases.json`, `crates/aitm-plugins/src/intercept.rs` (the `url` description and `compile_rules`), `crates/aitm-plugins/tests/intercept_rules.rs`, `crates/aitm-plugin-wsctl/src/lib.rs` (the `ws.intercept` rules parser's count cap only), `crates/aitm/tests/intercept_url_rules_mcp.rs`, `apps/mac/Sources/AitmproxyKit/BreakpointRules.swift` (`matches` only), `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md`, `site/docs.html` (the same sentence as Task 4).
- **Change:** the findings report `rule-url-panel-1-findings.md` in the shared notes folder is the input: F1 leading-`/` wildcard is path-only (AC17 rows in the case table), F2 pattern length cap 4096 and 256-rule cap (AC18), F3 empty pattern rejected (AC19), F4 `Case { Fold, Exact }` instead of a positional bool, F5 drop `// Tester:` prefixes, F6 drop the `path alone` phrase pin, F7 state "with a `*` the pattern must match the whole URL or the whole path" in the schema text, SKILL.md and the site sentence and pin the phrase `whole URL` in both docs tests.
- **Test:** the new AC17 rows fail on the current matcher, then pass; `PatternTooLong`/`EmptyPattern` tests; `rule_schemas_state_the_full_url_subject` and `operator_docs_state_the_full_url_subject` pin `whole URL`.
- **Done when:** the crate-scoped tests pass and the Terminal gate, Swift suite, e2e cell and live proof are re-run green.

### Fix task B (after panel 2, 2026-10-31): findings B1–B6

- **Satisfies:** AC19 (Kit test), AC15 (`rules` param text), quality readability.
- **Depends on:** Fix task A.
- **Files:** `apps/mac/Tests/AitmproxyKitTests/BreakpointRulesTests.swift`, `crates/aitm-rules/src/lib.rs`, `crates/aitm-plugins/src/intercept.rs` (the `rules` ParamDef description only), `crates/aitm-plugins/tests/intercept_rules.rs`, `crates/aitm-plugin-wsctl/src/lib.rs` (the `rules` description and the cap unit test's assertion only), `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md`.
- **Change:** the findings report `rule-url-panel-2-findings.md` in the shared notes folder is the input: B1 Swift test for the empty pattern on a literal row, B2 `compile_url` + `UrlSubject::for_wildcard`, B3 `RuleError` doc line, B4 plugin tests pin a fragment of the cap message, B5 SKILL.md sub-bullets, B6 `rules` param descriptions name the caps.
- **Test:** `swift test --filter BreakpointRule` (Terminal) gains `emptyPatternMatchesNoRow`; every Rust test stays green.
- **Done when:** crate-scoped tests pass and the Terminal gate, Swift suite, e2e cell and live proof are re-run green.

## Review log

Kept by the orchestrating session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| whole branch | tester | Minor | `oversized_regex_rejected` could not tell cap from syntax error | fixed in fab0d7c4 (asserts the `size limit` message) |
| whole branch | tester | Minor | AC15 docs (SKILL.md, site) had no test | fixed in fab0d7c4 (`operator_docs_state_the_full_url_subject`) |
| whole branch | tester | Minor | empty `url` pattern matches every flow; surfaces differ | FIX (Fix task A, F3: rejected at compile; AC19) |
| whole branch | tester | Minor | `*httpbin.org` (star only in front) never matches a URL with a path; docs should say | FIX (Fix task A, F7: anchoring clause in every operator text) |
| whole branch | security | Minor | path-intended patterns (`/admin`, `*/login*`) also match at the `//` of `scheme://`; Map rules act on it | FIX (Fix task A, F1: leading-`/` wildcard is path-only; `//` boundary documented and pinned; AC17) |
| whole branch | security | Minor | pattern length unbounded before the compiled-size cap (263 ms per MiB with case folding); `rules[]` count unbounded | FIX (Fix task A, F2: 4096-byte pattern cap, 256-rule cap; AC18) |
| whole branch | security | Minor | empty `url` pattern accepted and matches every flow | FIX (Fix task A, F3) |
| whole branch | quality | Minor | size-cap tests assert on the regex crate's error wording | accepted (autonomous mode, 2026-10-31): the string is `regex`'s Display; a bump that rewords it fails with an obvious message (two tests depend on it after F2: `oversized_regex_rejected` and the at-cap case of `oversized_wildcards_rejected_under_size_cap`) |
| whole branch | quality | Minor | `compile_pattern` takes a positional `bool` beside the `Anchor` enum | FIX (Fix task A, F4: `Case { Fold, Exact }`) |
| whole branch | quality | Minor | `// Tester:` role prefixes in test comments | FIX (Fix task A, F5) |
| whole branch | quality | Minor | Swift path subject re-joins `path?query` that `FlowRow.url` also joins | accepted (autonomous mode, 2026-10-31): the spec confines the Kit change to `matches`/`wildcardMatches`; a `FlowRow.target` helper belongs with the sibling Kit PR |
| whole branch | quality | Minor | `curl_bg`/`park` copied from the sibling e2e cell | accepted (autonomous mode, 2026-10-31): the plan directed the copy; `_clients.py` is a shared file other sessions edit |
| whole branch | quality | Minor | operator-docs pin fails on a harmless rewording of "path alone" | FIX (Fix task A, F6) |
| whole branch | spec | Important | AC15: the starred-pattern anchoring rule is missing from the schema text, SKILL.md and the site | FIX (Fix task A, F7) |
| whole branch | spec | Important | Task 4 touched the undeclared `tests/e2e/proxy/README.md` | fixed in the plan (Task 4 Files line amended 2026-10-31; the hunk stays) |
| whole branch | spec | Minor | spec silent on the empty `url` pattern | FIX (spec amended: rejected at compile, AC19; Fix task A, F3) |
| Fix task A | security | Minor | `rules` param text names the regex rejection but not the 256-rule / 4096-byte caps | FIX (Fix task B, B6) |
| Fix task A | quality | Minor | `compile`'s url arm carries three rules inline; a `compile_url` helper would read better | FIX (Fix task B, B2) |
| Fix task A | quality | Minor | `RuleError` doc says "why `compile` rejected a rule" but `TooManyRules` comes from `check_rule_count` | FIX (Fix task B, B3) |
| Fix task A | quality | Minor | the `TooManyRules` sentence is pinned verbatim in three crates | FIX (Fix task B, B4) |
| Fix task A | quality | Minor | SKILL.md `url` rule is one ~95-word sentence | FIX (Fix task B, B5) |
| Fix task A | spec | Important | AC19's Kit clause (empty pattern matches no row) has no Swift test | FIX (Fix task B, B1) |
| Fix task A | spec | Minor | site omits the leading-`/` rule and the `//` boundary | accepted (autonomous mode, 2026-10-31): the site sentence is the overview; module docs, schema text and SKILL.md carry the rule |
| Fix task A | spec | Minor | spec did not say which patterns the 4096-byte cap covers | fixed in the spec (Bounded input now names url wildcard, url regex and host wildcard; exact host uncapped) |
| Fix task B | security | — | no findings (panel-2 Minor closed by B6) | — |
| Fix task B | quality | Minor | SKILL.md fourth `url` sub-bullet unlabelled and mixes "omit `url`" with the limits | fixed by the orchestrating session (docs: `Limits:` label; "omit `url`" moved to the Subject bullet) |
| Fix task B | tester | Minor | the Kit empty-pattern guard is defence-in-depth (Foundation's `contains("")` and an empty `NSRegularExpression` already yield false); the test pins the spec'd behaviour | accepted (autonomous mode, 2026-10-31): the behaviour, not the mutation, is what AC19 requires |
| Fix task B | tester | Minor | the two `rules` param texts had no pin | fixed by the tester (`rules_param_text_names_every_rejection_cause` in `aitm-plugins` and `aitm-plugin-wsctl`) |
| Fix task B | spec | Minor | `Cargo.lock` was a branch-only file no task declared | fixed in the plan (Task 1 Files line) |
| Fix task B | spec | Minor | the caps' documentation home had no spec anchor and no pin | fixed in the spec (Bounded input names the `rules` param text and SKILL.md) and by the tester's pins |
| merge d593fd4a | security | — | no findings: the resolution is confined to the two Kit files; an as-typed wildcard reaches the core's escaping and caps instead of an app-built regex | — |
| merge d593fd4a | quality | Minor | `apps/mac/docs/FIXLOG.md` still described #202's `{regex}` wire form | fixed in this docs PR (dated supersession line) |
| merge d593fd4a | quality | Minor | two preview-matcher assertions sit in `noticeAndWireForm` | accepted (autonomous mode, 2026-10-31): cosmetic; the metacharacter cases are also in the case table |
| merge d593fd4a | spec | Important | `arguments` was reconciled with #202 but the spec's Non-goals/Constraints and this plan's Task 3 said the wire form was untouched | fixed in this docs PR (spec Non-goals and Constraints notes, Task 3 Files line) |
| merge d593fd4a | spec | Minor | FIXLOG stale (same as quality's) | fixed in this docs PR |
| merge d593fd4a | spec | Minor | no post-merge run of the app's own live self-test (`tools/selftest-live.sh`) on the merged build; the Python live proof and the Kit tests cover the wire form | routed to the improve-loop session with the preview live-check follow-up (the orchestrator) |

## Shipped

Filled at stage 7.
