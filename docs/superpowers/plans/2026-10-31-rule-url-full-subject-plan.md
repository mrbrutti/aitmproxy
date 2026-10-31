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
- **Files:** `crates/aitm-rules/src/lib.rs` (modify), `crates/aitm-rules/Cargo.toml` (modify: add `serde_json = "1"` under a new `[dev-dependencies]` section), `crates/aitm-rules/tests/matches.rs` (modify), `crates/aitm-rules/tests/cases/url-match-cases.json` (create), `crates/aitm-rules/tests/url_match_cases.rs` (create)
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
- **Files:** `apps/mac/Sources/AitmproxyKit/BreakpointRules.swift` (modify: `matches(_:)` and `wildcardMatches(pattern:text:)` and their doc comments only; `arguments`, `validationError` and the types stay as they are), `apps/mac/Tests/AitmproxyKitTests/BreakpointRulesTests.swift` (modify), `apps/mac/Tests/AitmproxyKitTests/BreakpointRuleCasesTests.swift` (create)
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
- **Files:** `tests/e2e/proxy/test_intercept_url_rules.py` (create), `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md` (modify: the `url` sentence under "Arm interception"), `site/docs.html` (modify: the one sentence at the "To hold only some traffic" paragraph)
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

## Review log

Kept by the orchestrating session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
