# Rule `url` clause matches the full request URL design

**Status:** approved (2026-10-31, autonomous mode on Matt's standing instruction; the orchestrator session "aitmproxy: Rust MITM platform design" dispatched this fix)
**Research inputs:** `crates/aitm-rules/src/lib.rs` (the matcher and its 2026-10-28 reconciliation note), `crates/aitm-plugins/src/intercept.rs` (`flow.intercept` and its `rules[]` schema), `docs/superpowers/specs/2026-10-28-aitmproxy-m6-parity-design.md` §0 and AC-R1/AC-R2, `apps/mac/Sources/AitmproxyKit/BreakpointRules.swift` (the macOS "Test Against List" preview), `apps/web/src/shell/InterceptBar.tsx` and `crates/aitm-tui/src/app.rs` (no rule preview on either), `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md` and `site/docs.html` (operator docs of the verb), macOS improve-loop story S-041 (2026-10-31): breakpoint rules have never armed on a live core.

## Intent

A breakpoint rule's `url` pattern is compared against `HttpRequest.path` only,
so every pattern that names a host or a scheme (`*example.com*`,
`https://api.*/v1/*`) silently never fires. The M6 spec prose promised a match
against `scheme://authority/path?query`; the plan's path-anchored regex test
(`^/v[0-9]+/users$`) made the builder run the clause against the path instead,
and the macOS preview kept matching the full URL. Operators write host-bearing
patterns, the preview says they match, and the core never pauses the flow. This
spec makes the core match the full URL while keeping every path-only pattern
working, and pins the preview to the core's answers.

## Goals

- A `url` wildcard or regex that names a scheme or host pauses the matching
  flow on a real core (`flow.intercept {rules:[{url:"*httpbin.org*"}]}` parks
  `GET http://httpbin.org/get`).
- Every pattern that fires today still fires: `*/login`, `/api/*`,
  `^/v[0-9]+/users$`.
- The matched string and the match rules are written once (the verb's schema
  description) and every operator surface that previews a rule gives the
  core's answer for the same pattern and flow.
- Map Local/Remote and WebSocket rules, which share the matcher, get the same
  semantics without their own code changing.

## Non-goals

- A rule-preview verb on the bus. The macOS Kit keeps its own Swift matcher; a
  shared case table pins it to the core instead.
- A web or TUI rule editor. The web "Rules…" button stays disabled and the TUI
  sends only `{enabled}`; neither previews a rule today, so there is nothing
  to align there. Both were checked.
- Fixing the macOS app's wire form (`match`, `flag`, `phase: both`, regex sent
  as a bare string). That is the sibling Kit PR from story S-041.
  Amended 2026-10-31 at the merge: #202 (S-041) landed first and sent every
  wildcard as the `(?i)` regex its `wildcardRegex` built, on the premise that
  the core's wildcard was anchored, case-sensitive and `?`-less. This spec
  removed that premise, and keeping the translation would have re-created the
  `?` (AC7) and `//` (AC17) disagreements the case table forbids, so the merge
  resolution sends `{wildcard: <as typed>}` and deletes `wildcardRegex`; `id`,
  `phase request|response|any`, `method`, `name`, `JSONValue` and the
  no-`match`/`flag` discipline stay #202's.
- Normalising the authority (dropping a default `:443`/`:80`, IDNA, percent
  decoding). The subject is what the client sent.
- `?` as a single-character wildcard. In a URL `?` starts the query, so it is a
  literal.

## Anti-goals

- A second matcher. Intercept, Map and WS rules must keep answering the one
  `CompiledRule::matches` question.
- A rule that matches in a preview and not in the core, or the reverse, for
  any case in the shared case table.
- A path-only pattern that stops matching after the change.

## Constraints

- `aitm-rules` keeps its single `regex` dependency and the 1 MiB
  compiled-size cap; agent-supplied patterns must still be rejected, never
  panic, and never balloon.
- No change to `aitm-core` types. `HttpRequest` already carries
  `scheme`, `authority` and `path` (path includes the query).
- The bus shape of a rule (`url` as a bare string, `{wildcard}` or `{regex}`)
  does not change. Existing e2e cells and tests that arm `*/orig*`-style rules
  keep passing.
- The macOS change is confined to `apps/mac/Sources/AitmproxyKit/` and
  `apps/mac/Tests/AitmproxyKitTests/`; `apps/mac/Sources/Aitmproxy/**` is not
  touched (the sibling Kit PR owns the wire form in the same Swift file; this
  change edits only `matches` and `wildcardMatches` and the tests; at the
  merge with #202, `arguments`' wildcard arm was the one further edit, see
  Non-goals).

## Design

### The subject

For an HTTP flow the `url` clause is evaluated against two strings, and the
clause matches when the pattern matches **either**:

1. `url` = `{scheme}://{authority}{path}`, each field exactly as recorded on
   `HttpRequest`: scheme as the core set it (`http`, or `https` after TLS
   MITM), authority as the client sent it (`host` or `host:port`), path as
   sent including the query. An empty path gives `scheme://authority` with
   no synthesised slash.
2. `path` = `HttpRequest.path` as recorded.

Reason for the second subject: a pattern anchored at the start of the path
(`/api/*`, `^/v1/`) can never match a string that starts with a scheme. Running
the clause against the path too is a strict superset of today's behaviour, and
for every other pattern shape the path match is implied by the URL match (the
path is a suffix of the URL and the URL regex search is unanchored), so no
URL-intended pattern gains a false match. **(Architect's call)**

A CONNECT tunnel is not a flow; the requests inside it are, with the tunnel's
scheme `https`. WebSocket flows carry no request, so `url`, `method` and `host`
clauses never match them (unchanged). L4 flows do not pass through
`aitm-rules`; `l4.intercept.*` has its own gating (documented, out of scope).

### Wildcard semantics

- `*` matches any run of characters, including an empty one.
- Every other character is literal, `?` included.
- A pattern containing at least one `*` is anchored to the whole subject.
- A pattern with no `*` matches as a **substring** of the subject. This is
  Proxyman's rule and the macOS preview's documented behaviour; it lets an
  operator type `httpbin.org` and get the rule they meant. It is a superset of
  today's exact match, so nothing that fires today stops firing.
  **(Architect's call)**
- Matching is case-insensitive. Scheme and host are case-insensitive by RFC
  3986 and now lead the subject; the preview already lowercases; a breakpoint
  that also fires on `/Admin` when the operator typed `/admin` is the safe
  direction for a testing proxy. **(Architect's call)**

### Regex semantics

- `regex` crate syntax, compiled once at `compile` time under the existing
  size cap; an invalid pattern is still `RuleError::BadRegex`.
- Searched (unanchored) in each subject; the operator anchors with `^`/`$`.
- Case-insensitive by default (`RegexBuilder::case_insensitive(true)`); an
  inline `(?-i)` restores case sensitivity. The macOS preview already compiles
  its regex case-insensitively. **(Architect's call)**

### Where the contract lives

- `crates/aitm-rules/src/lib.rs` module docs state the subject and the rules
  above, replacing the 2026-10-28 reconciliation note.
- `flow.intercept`'s `rules[].url` schema description (the MCP tool schema
  every agent and surface reads) states the subject and the rules in one
  sentence each, including that a starred pattern must cover the whole URL or
  the whole path. `ws.intercept`'s `rules[].url` and `map.add`'s `condition`
  descriptions carry a one-line pointer to the same subject (added 2026-10-31,
  panel 1), not a second copy of the rules.
- `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md` and
  `site/docs.html` say the pattern is matched against the full URL and the
  path.
- One case table (literal matcher cases, not sample data), `crates/aitm-rules/tests/cases/url-match-cases.json`, lists
  `(kind, pattern, scheme, authority, path, query?, expect)` cases. The Rust
  test `crates/aitm-rules/tests/url_match_cases.rs` and the Swift test
  `apps/mac/Tests/AitmproxyKitTests/BreakpointRuleCasesTests.swift` both read
  it and assert every case. A preview that disagrees with the core fails a
  test on its own side.

### macOS Kit preview

`BreakpointRule.matches(_ row:)` evaluates the two subjects (`row.url`, and
`row.path` plus `?query` when present). `wildcardMatches` drops `?` as a
wildcard and keeps the substring rule for a star-less pattern and the
lowercase comparison. The regex branch keeps `.caseInsensitive`. The ICU and
Rust regex dialects differ at the edges (lookaround, named classes); the core
is authoritative and the shared case table uses only syntax both accept.

### What does not change

`host`, `method`, `phase`, `ws_dir` and `enabled` keep their semantics (the
4096-byte cap on a `host` wildcard, added after panel 1, is the one addition).
`bus.rs` parse and echo are untouched. Map Local/Remote and `ws.intercept`
inherit the new `url` semantics through `CompiledRule::matches`.

### Amendment (2026-10-31, after panel 1)

The security reviewer showed that a path-intended pattern also matches at the
`//` of `scheme://` when the host starts with that segment: `/admin` matched
`https://admin.example.com/transfer`, and Map Local/Remote act on such a match.
Three decisions, all **(Architect's call)**:

- **Leading `/` means the path.** A `url` *wildcard* whose first character is
  `/` is evaluated against the path subject only (a URL never starts with `/`).
  Every other wildcard, and every regex, keeps the two-subject rule, so the
  `//` boundary remains a legitimate match for `*/seg*` and for an unanchored
  regex (`*/login*` matches `https://login.example.com/x`). The docs say so and
  recommend a `host` clause, or a `^/` anchor, when only the path is meant.
- **Bounded input.** A wildcard or regex pattern, `url` or `host`, longer than
  4096 bytes is rejected before any regex is built
  (`RuleError::PatternTooLong`); an exact `host` is a string compare, not a
  pattern, and is not capped; `flow.intercept` and
  `ws.intercept` reject more than 256 rules in one call. A rejected call leaves
  the active rules unchanged. The `rules` param description of `flow.intercept`
  and `ws.intercept`, and the intercept SKILL.md, name the three rejections and
  the unchanged active set (pinned by `rules_param_text_names_every_rejection_cause`
  in both plugins). (The compiled-size cap only applies after the
  parser has walked the whole pattern; with case folding a 1 MiB literal took
  263 ms to reject.)
- **No empty pattern.** An empty `url` wildcard or regex is rejected at compile
  (`RuleError::EmptyPattern`); omit `url` to match any URL. The macOS form
  already refuses an empty pattern; the core now agrees instead of arming a
  match-everything rule.

## Acceptance criteria

1. **AC1 host wildcard.** A rule `{url:"*httpbin.org*"}` matches a flow
   `GET http://httpbin.org/get` and `GET https://httpbin.org:443/anything?x=1`,
   and does not match `GET http://example.com/get`.
2. **AC2 scheme + host wildcard.** `{url:"https://api.*/v1/*"}` matches
   `https://api.example.com/v1/users`; it does not match
   `https://www.example.com/v1/users` nor `http://api.example.com/v1/users`.
3. **AC3 path patterns keep working.** `*/login` matches
   `https://h.test/api/login`; `/api/*` matches `https://h.test/api/x`;
   regex `^/v[0-9]+/users$` matches `https://h.test/v2/users` and not
   `https://h.test/v2/users/1`.
4. **AC4 scheme-anchored regex.** `^https://api\.` matches
   `https://api.example.com/x` and not `http://api.example.com/x`.
5. **AC5 case.** Wildcard `*HTTPBIN.ORG*` and regex `httpbin\.ORG` match
   `http://httpbin.org/get`; regex `(?-i)httpbin\.ORG` does not.
6. **AC6 substring.** Wildcard `httpbin.org` (no `*`) matches
   `http://httpbin.org/get`; wildcard `api/orders` matches
   `https://api.shop-staging.test/api/orders?page=3`; wildcard `/get` does
   not match `http://httpbin.org/anything`.
7. **AC7 literal `?`.** Wildcard `*/search?q=*` matches
   `https://h.test/search?q=1` and not `https://h.test/searchXq=1`.
8. **AC8 empty path.** A flow with scheme `https`, authority `h.test:443` and
   an empty path has subject `https://h.test:443`; wildcard `*h.test:443*`
   matches it and wildcard `*/` does not.
9. **AC9 combined clauses.** `{host:{exact:"httpbin.org"}, url:"*/get"}`
   matches `http://httpbin.org/get` and not `http://httpbin.org/post`.
10. **AC10 invalid regex still rejected.** `compile` of `{regex:"[bad"}`
    returns `RuleError::BadRegex`; `a{1000}{1000}{100}` is still rejected
    under the size cap with case-insensitivity on.
11. **AC11 shared case table.** `url-match-cases.json` holds every AC1–AC8 case
    (`url`-clause only; AC9 needs a `host` clause the Kit rule has no field
    for, so it is Rust-only); the Rust and Swift tests both read the file and
    every case passes on both sides.
12. **AC12 plugin level.** Through `InterceptPlugin` with
    `flow.intercept {enabled:true, rules:[{url:"*ex.test*"}]}`, a request to
    `http://ex.test/anything` parks (`InterceptState::Intercepted`) and a
    request to `http://other.test/anything` does not.
13. **AC13 MCP level.** Over `McpServer` (`tools/call flow.intercept` with a
    host-bearing rule, then the request event dispatched through the
    assembled plugin chain), `tools/call flow.get` reports
    `intercept: "intercepted"` for the matching flow and not for a
    non-matching one; the `flow.intercept` result echoes the rule.
14. **AC14 real core.** The e2e cell `tests/e2e/proxy/test_intercept_url_rules.py`
    boots a real `aitm`, arms a host-bearing wildcard, a scheme-bearing
    wildcard, a `^http://`-anchored regex and a star-less substring rule in
    turn, sends a real `curl` through the proxy for each, sees each flow
    `intercepted`, resumes it, and reads the upstream's own record; a rule
    naming another host does not pause a request.
15. **AC15 docs.** The `rules[].url` schema description, the `aitm-rules`
    module docs, the intercept SKILL.md and `site/docs.html` all state that
    the pattern is matched against the full URL and the path, with the
    wildcard and regex rules above.
16. **AC16 live proof.** On a real core on this machine, `*httpbin.org*` armed
    over the bus pauses `curl -x <proxy> http://httpbin.org/get`;
    `flow.get` shows `intercepted`; `flow.resume` lets curl finish with 200.
    The transcript is in the PR body.

17. **AC17 leading `/`.** Wildcard `/admin` matches `https://h.test/admin` and
    `https://h.test/v1/admin` and does not match
    `https://admin.example.com/transfer`; wildcard `/api/*` does not match
    `https://api.example.com/other`; wildcard `*/login*` matches
    `https://login.example.com/x` (documented boundary); regex `/admin`
    matches `https://admin.example.com/transfer` and regex `^/admin` does not.
    All are rows of the shared case table, so the Kit preview agrees.
18. **AC18 bounded input.** A 4096-byte pattern compiles; a 4097-byte one is
    `RuleError::PatternTooLong` naming the length and the cap, with no regex
    built; `flow.intercept` with 257 rules errors and leaves the previously
    armed rules active.
19. **AC19 empty pattern.** `compile` of `{wildcard:""}` or `{regex:""}` is
    `RuleError::EmptyPattern`; in the Kit preview a rule with an empty pattern
    matches no row.

## Left to the builder

- How the two subjects are represented inside `CompiledRule::matches` (a
  small struct built once per call, or two `is_match` calls), as long as each
  compiled regex runs at most twice per flow.
- Whether the wildcard builder sets `dot_matches_new_line`; subjects never
  contain a newline either way.
- The exact wording of the schema description, within the sentence budget
  above.
- The e2e cell's path names and how it confirms a negative (a completed 200
  within a bounded wait is enough).

## Open questions

None.
