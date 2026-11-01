# Scanner v2 track T2 (HTTP lane) implementation plan

**Status:** Approved (T2 session, on Matt's autonomous-approval mandate, 2026-10-31; A1-A19 confirmed as proposed, A2 accepted: crawl traffic is discovery bounded by `max_pages`; one amendment: the `wire.rs` one-literal re-pin moves from Task 22 to Task 20 so the full gate is green at every commit, as T1a's call A23 allows)
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved), sections D1, D2, D5 (budget, record policy, crawl marks), D7, D8.1, D12 (row T2 and "Integration-shared files"), Verification, ACs T2-1..T2-6.
**Research:** `docs/research/17-burp-style-scanner-architecture.md` (§3.1 crawl settings, §3.2 insertion point types and scheduling), `docs/research/20-scanner-v2-current-state.md` (§3.5 insertion points and sessions, §3.10 bugs v2 must not inherit). The spec's "research note 12 and 15" are these two notes, renumbered.
**Branch / worktree:** `claude/competent-rubin-4ae816` in `/Users/matt/Security/aitmproxy/.claude/worktrees/competent-rubin-4ae816` (the app-pinned worktree branch stands in for the spec's `feat/scanner-v2-t2`); PR target `main`. Branch head at planning time `dfd43241` = `origin/feat/scanner-v2-t1a` e0464e0e (T1a contract drop + `main` v0.5.8).
**Sibling plan (shape copied):** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t1a-plan.md`.
**Size:** one PR; twenty-two tasks in seven waves; two to three days with parallel coders.

## Overview

T2 fills the skeleton crate `crates/aitm-scan-http` with the real HTTP lane: (1) pure parsers
(URL normalisation, HTML link/form extraction, form/cookie/JSON walking, an offset-recording XML
tokenizer, an offset-recording multipart parser, path templates and value traits, one redaction
indirection); (2) insertion points v2 (`enumerate_v2`), the site map builder, the single mutation
function `build_request`, session application and the `SessionMonitor` canary; (3) crawler v2
behind one `Crawler` trait with a browser engine and a client engine over a shared frontier; (4)
the lane's `ProbeHost`; (5) `HttpLane` implementing `Lane`, and the flip of `lane()` from `None`
to `Some`. It ships **no check and no verb** (`HttpLane::checks()` is empty; T3's checks crate and
the Rhai catalogue supply HTTP detection), so no integration-shared contract list changes. The
lane feeds the engine's scheduler through the model's existing fields only (`SiteNode.params`,
`SiteNode.points`, `SiteNode.method`, `SiteNode.auth`, `PointTrait::Json`); it adds no type for that.

Every task edits only `crates/aitm-scan-http/**`. The sole exceptions are confined to Task 22
(integration): the one-line re-pin in `crates/aitm/src/wire.rs` (T1a call A23), the deletion of
the legacy `aitm-plugin-scanner` modules after T1b is on `main`, and the redaction flip once PR
#199 is on `main`. No task edits the root `Cargo.toml`, `aitm-scan-model`, `aitm-core`,
`aitm-plugin-rhai`, `crates/aitm/**` (beyond the re-pin) or `tests/e2e/**` (T10 owns the cells).

Waves (tasks inside a wave touch disjoint files and fan out to parallel coders):

| Wave | Tasks | Depends on |
|---|---|---|
| 0 | Task 1 (crate scaffold: manifest, module tree with placeholder files, `limits.rs`, `hash.rs`) | none |
| 1 | Task 2 `redact.rs`, Task 3 `url_norm.rs`, Task 4 `crawl/extract.rs`, Task 5 `params.rs`, Task 6 `xml.rs`, Task 7 `multipart.rs`, Task 8 `template.rs`, Task 9 `testutil.rs` | Task 1 |
| 2 | Task 10 `points.rs`, Task 11 `mutate.rs`, Task 12 `sitemap.rs`, Task 13 `session.rs`, Task 14 `crawl/values.rs`, Task 15 `crawl/seeds.rs`, Task 16 `crawl/frontier.rs` | wave 1 (per-task list below) |
| 3 | Task 17 `crawl/client.rs`, Task 18 `crawl/browser.rs`, Task 19 `host.rs` | wave 2 |
| 4 | Task 20 `lane.rs` + `lib.rs` flip | wave 3 |
| 5 | Task 21 Tester whole-branch + live proof | Task 20 |
| 6 | Task 22 integration (merge `origin/main`, redaction flip, legacy deletion, `wire.rs` re-pin, gate, PR) | Task 21 |

### Shared facts for every coder

- **TDD per task.** Write the named tests first, run `cargo test -p aitm-scan-http --offline`
  and quote the red run (a compile error on a symbol that does not exist yet counts as red),
  implement, quote the green run. Commit after each task.
- **Shared worktree discipline (added 2026-11-01 after two incidents).** Coders run in parallel in
  one worktree with one git index: commit with a pathspec, `git commit -m <msg> -- <your file>`
  (never `git add <file> && git commit`, which commits whatever a sibling has staged); format only
  your own file with `rustfmt --edition 2021 <your file>` (never `cargo fmt` / `cargo fmt -p` in
  write mode); never `git add -A`/`-u`/`commit -a`. Commit `2cb26e26` (Task 15) carries an
  intermediate `crawl/browser.rs` for this reason; Task 18's own commit holds the final file.
- **Sandbox vs Terminal.** `cargo test -p aitm-scan-http --offline`, `cargo clippy -p aitm-scan-http
  --all-targets --offline -- -D warnings` and `cargo fmt --check` work in the sandbox (offline
  registry cache: `url 2.5.x`, `regex 1.13.x`, `serde_json`, `tokio` are cached; `blake3` is **not**,
  see call A1). Anything binding a port or running obscura is Terminal-only (Task 21). Full gate from
  the worktree root before handing back: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- **Module tree is fixed in Task 1.** Every later task fills a file that already exists as a
  placeholder; no task adds or removes a `mod` line except Task 20 (which only edits `lane()` in
  `lib.rs`) and Task 22 (legacy deletion in another crate). This is what makes the waves disjoint.
- **Crate rules.** `#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used, clippy::expect_used)]`
  at the crate root (tests opt out with `#[allow(clippy::unwrap_used, clippy::expect_used)]` on
  their `mod tests`); every async seam is `BoxFuture`; no `unwrap`/`expect`/indexing panics on
  network or user input; every limit is a named constant in `limits.rs`; every await on the
  network or the browser is bounded by `min(job.deadline() - now, MAX_AWAIT)`; every loop polls
  `job.cancelled()`.
- **Redaction rules (D8.1, AC T2-6).** Every `InsertionPoint.example` goes through
  `redact::example`; every `cookie`-kind example and every `session`-trait example is the literal
  `<redacted>` regardless of name; every URL that reaches a `tracing::*` line or an `anyhow!`/`bail!`
  message goes through `redact::safe_url`; no log line, error or `Debug` output ever carries a
  header value, cookie value or body. The model's `SessionMaterial`, `Payload`, `RawProbe` and
  `ProbeResponse` already have redacting `Debug` impls; never add a type that prints a value.
- **Marks.** Job mark = `format!("scan:{}", job.job_id())`; crawl mark = the literal `crawl`.
- **`session.mode: none` means unauthenticated (orchestrator amendment 2026-11-01).** A captured
  source request may itself carry the operator's session (`Cookie`, `Authorization`, any
  `is_secret_name` header). Under `mode: none` the `ProbeHost` strips those from the source request
  before building the baseline and every probe (fixed in bfe7b789); the `session`-trait points of such a
  request are skipped by the default `audit.ignore` rule `{ trait: session }` (a point named after a
  session cookie or secret-named header carries the trait regardless of mode), so no further
  `points.rs` change is needed; under `mode: observed` the material is merged as D7 says. Otherwise AC T2-4's
  "with `session.mode: none` it is not reached" cannot hold for a seed captured while logged in.
- **The session-lost token.** `session::SESSION_LOST_PREFIX = "scan: session_lost: "`. After a
  canary loss with `on_lost: stop`, every `probe`/`baseline`/`probe_raw` of every host of that job
  returns `Err` whose message starts with that literal. T1b's engine maps it to
  `stopped_reason: session_lost` and `session.lost: true` (cross-track seam S1, below).
- **Budget seam (D5).** HTTP probes, baselines, raw probes, client-crawler GETs and form
  submissions go through `job.client().send_opts(req, opts)` and are charged by the engine's
  `JobClient`; the lane never calls `job.charge()` for them. The lane **does** call `job.charge(1)`
  before every browser navigation, click and form submission and stops crawling when it returns
  `false`.
- **Test doubles are the inner loop, not proof.** `src/testutil.rs` (Task 9) holds a `FakeJob`
  (`JobCtx`), a `ScriptedClient` (`ProxyClient`) and a `FakeBrowser` (`BrowserDriver`). They make
  the unit tests hermetic; the acceptance evidence for T2-1..T2-6 is the real e2e run of Task 21
  (spec Verification; Matt's rule that fixture/snapshot/mock runs are never evidence).

### Module layout (fixed by Task 1)

```
crates/aitm-scan-http/
  Cargo.toml
  src/lib.rs            crate doc, mod tree, pub fn lane()
  src/limits.rs         every named constant
  src/hash.rs           fnv1a64 (page fingerprints, node ids)
  src/redact.rs         scrub, is_secret_name, example, safe_url, REDACTED
  src/url_norm.rs       parse_absolute, resolve, origin_key, guard_authority, same_origin, request_url
  src/params.rs         form/cookie pairs, JSON leaves + set, body format, split_path
  src/xml.rs            offset-recording tokenizer, escape, splice
  src/multipart.rs      offset-recording part parser, splice, escape_filename
  src/template.rs       path_template, looks_like_filename, traits_for
  src/points.rs         enumerate_v2, EnumerateOptions, CompiledIgnore, Enumerated
  src/mutate.rs         build_request, apply_mode
  src/sitemap.rs        SiteMapBuilder, node_id, is_authenticated
  src/session.rs        apply_session, browser cookie statements, pick_canary, SessionMonitor, SESSION_LOST_PREFIX
  src/host.rs           HttpProbeHost (ProbeHost), SessionMonitors
  src/lane.rs           HttpLane (Lane), discover orchestration
  src/testutil.rs       #[cfg(test)] doubles
  src/crawl/mod.rs      pub mod lines only
  src/crawl/frontier.rs Crawler trait, Frontier, Limits, limits_for, fingerprint, CrawlReport
  src/crawl/extract.rs  HTML extractor
  src/crawl/values.rs   inert form values
  src/crawl/seeds.rs    robots.txt / sitemap.xml
  src/crawl/client.rs   ClientCrawler
  src/crawl/browser.rs  BrowserCrawler, prime_session, StoreDiff
```

## Tasks

### Task 1: crate scaffold: manifest, module tree, `limits.rs`, `hash.rs`

- **Satisfies:** spec D1 ("a lane track edits only its own crate"), Constraints "Rust gate"
  (`forbid(unsafe_code)`), the orchestrator's dependency decision (3); groundwork for every AC.
- **Depends on:** none.
- **Files:** `crates/aitm-scan-http/Cargo.toml` (modify), `crates/aitm-scan-http/src/lib.rs`
  (modify), `crates/aitm-scan-http/src/{limits.rs, hash.rs, redact.rs, url_norm.rs, params.rs,
  xml.rs, multipart.rs, template.rs, points.rs, mutate.rs, sitemap.rs, session.rs, host.rs,
  lane.rs, testutil.rs}` (create), `crates/aitm-scan-http/src/crawl/{mod.rs, frontier.rs,
  extract.rs, values.rs, seeds.rs, client.rs, browser.rs}` (create).
- **Change:**
  1. `Cargo.toml` `[dependencies]`, all `workspace = true`: `aitm-core`, `aitm-scan-model`,
     `anyhow`, `futures`, `tokio` (features `["time", "sync"]`), `tracing`, `serde_json`, `url`,
     `regex`. `[dev-dependencies]`: `tokio` (features `["macros", "rt", "rt-multi-thread"]`).
     No `blake3` (call A1). `[lints] workspace = true` stays.
  2. `lib.rs`: crate doc (owning track, spec section), `#![forbid(unsafe_code)]`,
     `#![deny(clippy::unwrap_used, clippy::expect_used)]`, the `mod` tree above (`pub(crate)` for
     everything except `pub mod` is not needed: the crate's public surface stays `lane()` only),
     `#[cfg(test)] mod testutil;`, and `pub fn lane() -> Option<Arc<dyn Lane>>` still returning
     `None` with its existing test `skeleton_returns_none` kept.
  3. Each placeholder file holds one `//!` doc line naming its task; `crawl/mod.rs` holds the
     seven `pub(crate) mod` lines.
  4. `limits.rs` (every `pub(crate) const`, with a one-line doc each):
     `MAX_LINKS_PER_PAGE: usize = 512`, `MAX_FORMS_PER_PAGE: usize = 64`,
     `MAX_FIELDS_PER_FORM: usize = 256`, `MAX_OPTIONS_PER_SELECT: usize = 128`,
     `MAX_FRONTIER: usize = 4096`, `MAX_DOM_BYTES: usize = 2 * 1024 * 1024`,
     `MAX_BODY_PARSE_BYTES: usize = 2 * 1024 * 1024`, `MAX_SEED_URLS: usize = 256`,
     `MAX_SITEMAP_URLS: usize = 1024`, `MAX_SITEMAPS_FOLLOWED: usize = 4`,
     `MAX_CLICKABLES_LISTED: usize = 32`, `CLICKS_PER_PAGE_NORMAL: u32 = 8`,
     `CLICKS_PER_PAGE_THOROUGH: u32 = 32`, `FORMS_PER_PAGE_NORMAL: u32 = 8`,
     `FORMS_PER_PAGE_THOROUGH: u32 = 32`, `SETTLE_POLL_MS: u64 = 200`, `SETTLE_MAX_MS: u64 = 3000`,
     `MAX_PAIRS: usize = 4096`, `MAX_JSON_DEPTH: usize = 32`, `MAX_XML_SLOTS: usize = 1024`,
     `MAX_XML_DEPTH: usize = 64`, `MAX_MULTIPART_PARTS: usize = 256`,
     `MAX_EXAMPLE_CHARS: usize = 64`, `MAX_SAFE_URL_CHARS: usize = 256`,
     `MAX_HELD_FLOWS: usize = 16`, `MAX_AWAIT: Duration = Duration::from_secs(30)`,
     `CANARY_EVERY: u32 = 25`, `MAX_SESSION_MONITORS: usize = 16`,
     `MAX_HELD_CRAWL_BODY: usize = 64 * 1024`, `MARK_CRAWL: &str = "crawl"`; added later:
     `USER_AGENT: &str = "aitm-scan"` (Task 20 hoist), `JOB_MARK_PREFIX`/`job_mark()` and
     `MAX_STORED_FLOWS: usize = 2048` (panel fix round).
  5. `hash.rs`: `pub(crate) fn fnv1a64(bytes: &[u8]) -> u64` (FNV-1a, 64-bit, offset basis
     `0xcbf2_9ce4_8422_2325`, prime `0x0000_0100_0000_01b3`).
- **Test:** `hash::tests::fnv1a64_known_vectors`: `fnv1a64(b"") == 0xcbf2_9ce4_8422_2325`,
  `fnv1a64(b"a") == 0xaf63_dc4c_8601_ec8c`, `fnv1a64(b"foobar") == 0x85944171f73967e8`.
  `limits::tests::limits_match_the_plan`: `MAX_LINKS_PER_PAGE == 512`, `MAX_FRONTIER == 4096`,
  `MAX_DOM_BYTES == 2_097_152`, `MAX_HELD_FLOWS == 16`, `CANARY_EVERY == 25`,
  `MAX_AWAIT == Duration::from_secs(30)`. `skeleton_returns_none` still passes.
  `cargo metadata --offline --format-version 1 >/dev/null; echo $?` prints `0`.
- **Done when:** the tests pass, `cargo clippy -p aitm-scan-http --all-targets --offline -- -D warnings`
  is clean with the placeholder tree (expect `dead_code` allowances only via `#![allow(dead_code)]`
  on placeholder modules, removed by the task that fills each), full gate passes.

### Task 2: `redact.rs`: the one redaction indirection and `safe_url`

- **Satisfies:** AC T2-2 (cookie examples are `<redacted>`), AC T2-6 (no secret in any result or
  log), D8.1 "Redaction", the coordinator's T1a follow-up (probe URLs scrubbed before any log or
  error).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/redact.rs`.
- **Change:**
  - `pub(crate) const REDACTED: &str = "<redacted>";`
  - `pub(crate) fn scrub(text: &str) -> String` → `aitm_core::redact::scrub_text` (Task 22 flips
    to `scrub_text_wide` once `origin/main` has PR #199).
  - `pub(crate) fn is_secret_name(name: &str) -> bool` → `aitm_core::redact::is_secret_key`
    (Task 22 flips to `is_secret_key_wide`).
  - `pub(crate) fn example(kind: InsertionKind, name: &str, value: &str) -> String`: `REDACTED`
    when `kind == InsertionKind::Cookie` or `is_secret_name(name)`; otherwise `scrub(value)` cut to
    at most `MAX_EXAMPLE_CHARS` chars on a char boundary (no ellipsis).
  - `pub(crate) fn safe_url(url: &str) -> String`: parse with `url::Url`; on success strip
    userinfo, drop the fragment, and rebuild the query by hand as `key=value` pairs joined by `&`
    (raw text kept as it appeared, no re-encoding) where every pair whose key `is_secret_name`
    gets the value `<redacted>`; on parse failure strip anything up to and including the last `@`
    of the authority-looking head and then `scrub` the rest. Either branch is bounded to
    `MAX_SAFE_URL_CHARS` chars on a char boundary.
  - `pub(crate) fn safe_request_url(req: &HttpRequest) -> String` =
    `safe_url(&format!("{}://{}{}", req.scheme, req.authority, req.path))`.
  - A lint-style test (below) that reads the five network-facing source files with
    `include_str!` so the redaction rule for log sites is checked on every `cargo test`.
- **Test:**
  `example_rules`: `example(Query, "q", "hello") == "hello"`;
  `example(Cookie, "theme", "dark") == "<redacted>"`;
  `example(Header, "Authorization", "Bearer abc") == "<redacted>"`;
  `example(Query, "next", "/cb?sid=abc") == "/cb?sid=[redacted]"` (core's `scrub_text` token);
  `example(Query, "q", &"a".repeat(100)).chars().count() == 64`;
  `example(Query, "q", &"é".repeat(100)).chars().count() == 64`.
  `safe_url_pins`: `safe_url("http://t/x?sid=abc&q=1") == "http://t/x?sid=<redacted>&q=1"`;
  `safe_url("http://u:p@t/x#frag") == "http://t/x"`;
  `safe_url("https://t:8443/a?token=abc&b=2&Authorization=xyz") == "https://t:8443/a?token=<redacted>&b=2&Authorization=<redacted>"`;
  `safe_url("nope://u:hunter2@h/?password=hunter2")` does not contain `hunter2`;
  `safe_url(&format!("http://t/{}", "a".repeat(400))).chars().count() == 256`.
  `log_sites_route_urls_through_safe_url`: for each of `include_str!("host.rs")`,
  `include_str!("crawl/browser.rs")`, `include_str!("crawl/client.rs")`,
  `include_str!("session.rs")`, `include_str!("lane.rs")`: every macro invocation whose text
  (the line containing `tracing::`, `warn!(`, `info!(`, `debug!(`, `trace!(`, `error!(`,
  `anyhow!(` or `bail!(`, plus the following lines up to the one ending the invocation with `);`,
  at most 8 lines) mentions the identifier `url` (as a whole word, case-insensitive) also contains
  `safe_url(` or `safe_request_url(`; the assertion message names the file and line. Trivially
  green on the placeholders; red if a later task logs a raw URL.
- **Done when:** tests pass; `grep -n 'scrub_text\|is_secret_key' crates/aitm-scan-http/src` shows
  exactly two call sites, both in `redact.rs` (Task 22's flip edits only those); full gate passes.

### Task 3: `url_norm.rs`: URL normalisation, origin and scope keys

- **Satisfies:** AC T2-1 (crawler scope and dedupe), D8.1 fragment routing rule, research 20 §3.10
  (backslash-host scope bypass stays rejected).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/url_norm.rs`.
- **Change:**
  - `pub(crate) fn parse_absolute(s: &str) -> Option<Url>`: trim; `http`/`https` only; non-empty
    host; no userinfo; fragment handled by `route_fragment`.
  - `pub(crate) fn resolve(base: &Url, href: &str) -> Option<Url>`: `base.join(href)` then the same
    normalisation; non-http schemes (`javascript:`, `mailto:`, `data:`, `tel:`) → `None`.
  - `pub(crate) fn route_fragment(url: &mut Url)`: a fragment containing any of `/ \ ? = &` is
    kept verbatim; any other fragment is dropped (Burp's "fragments for routing" default).
  - `pub(crate) fn origin_key(url: &Url) -> String` = `scheme://host[:port]`, port only when
    not the scheme default.
  - `pub(crate) fn guard_authority(url: &Url) -> String` = `host:port` with the known default
    filled in (the string `ScopeRateGuard::in_scope` / `check_active` take; same as legacy
    `guard_authority`).
  - `pub(crate) fn same_origin(a: &Url, b: &Url) -> bool` via `Url::origin()`.
  - `pub(crate) fn request_url(req: &HttpRequest) -> Option<Url>` from scheme, authority, path
    (path already carries the query).
  - `pub(crate) fn page_key(url: &Url) -> String` = the normalised `as_str()` (visited-set key).
- **Test:** `resolve_pins` with `base = "http://t/a/"`: `resolve(.., "b#top")` → `"http://t/a/b"`;
  `"b#/route?x=1"` → `"http://t/a/b#/route?x=1"`; `"javascript:void(0)"` → `None`;
  `"mailto:a@b"` → `None`; `"//evil.test/x"` → `Some("http://evil.test/x")` and
  `same_origin(base, that) == false`; `"HTTP://T:80/x"` → `"http://t/x"`;
  `"http://u:p@t/x"` → `None`; `"\\\\evil.test\\x"` → the url crate maps it to
  `"http://evil.test/x"` and `same_origin` is false (bypass stays rejected).
  `keys`: `guard_authority("https://t/x") == "t:443"`, `guard_authority("http://t:8080/") == "t:8080"`,
  `origin_key("http://t:8080/x?y") == "http://t:8080"`, `origin_key("https://t/") == "https://t"`.
  `request_url_builds_from_parts`: an `HttpRequest { scheme: "http", authority: "t:8080", path: "/a?b=1" }`
  → `"http://t:8080/a?b=1"`.
- **Done when:** tests pass; full gate passes.

### Task 4: `crawl/extract.rs`: HTML link and form extractor

- **Satisfies:** AC T2-1 (client crawler reaches every link/form route; browser crawler's link
  harvest), D8.1 client engine "HTML link/form extractor".
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/crawl/extract.rs`.
- **Change:** a tag-aware tokenizer (skip `<!-- -->`, `<script>` and `<style>` bodies, decode
  `&amp; &lt; &gt; &quot; &#39; &#NN;` in attribute values), mined from legacy
  `crawl.rs::harvest_links`/`tag_attribute`, extended to forms:
  ```
  pub(crate) struct Extracted { pub base: Option<String>, pub links: Vec<String>, pub resources: Vec<String>, pub forms: Vec<FormSpec> }
  pub(crate) struct FormSpec { pub index: usize, pub action: Option<String>, pub method: String, pub enctype: Option<String>, pub fields: Vec<FieldSpec> }
  pub(crate) struct FieldSpec { pub name: String, pub kind: FieldKind, pub value: Option<String>, pub options: Vec<String>, pub checked: bool }
  pub(crate) enum FieldKind { Text, Email, Number, Url, Password, Tel, Date, Checkbox, Radio, Select, Textarea, Hidden, File, Other(String) }
  pub(crate) fn extract(html: &str) -> Extracted
  ```
  Links: `a[href]`, `area[href]`, `iframe[src]`, `frame[src]`, `meta[http-equiv=refresh]`'s
  `content="N;url=..."` target, `button[formaction]` (as a plain link, call A6). Resources:
  `link[href]`, `script[src]`. Forms: `form[action][method]` (method upper-cased, default `GET`),
  `input`/`select`/`textarea` descendants until `</form>`; nameless controls and
  `input[type=submit|button|image|reset]` are not fields; `select` collects `option[value]` (or the
  option text when no `value`) in order; `input[type=checkbox|radio]` records `value` (default
  `on`) and `checked`. `base` = `<base href>` when present. Caps: `MAX_LINKS_PER_PAGE`,
  `MAX_FORMS_PER_PAGE`, `MAX_FIELDS_PER_FORM`, `MAX_OPTIONS_PER_SELECT`; the caller truncates the
  input to `MAX_DOM_BYTES` on a char boundary first.
- **Test:** `extract_pins` on the literal page
  `<base href="/app/"><a href="/one">1</a><!-- <a href="/hidden">h</a> --><script>var s="<a href='/js'>";</script><form action="/search" method="get"><input name="q"><select name="s"><option value="a">A</option><option value="b">B</option></select><input type="hidden" name="h" value="1"><input type="radio" name="r" value="x" checked><input type="radio" name="r" value="y"><input type="submit"></form><meta http-equiv="refresh" content="0;url=/next"><iframe src="/frame"></iframe><link href="/s.css" rel="stylesheet"><script src="/app.js"></script><button formaction="/alt">b</button><a href="/amp?a=1&amp;b=2">x</a>`:
  `base == Some("/app/")`; `links == ["/one", "/next", "/frame", "/alt", "/amp?a=1&b=2"]`;
  `resources == ["/s.css", "/app.js"]`; `forms.len() == 1`; `forms[0].method == "GET"`,
  `forms[0].action == Some("/search")`; field names `["q", "s", "h", "r", "r"]`; kinds
  `[Text, Select, Hidden, Radio, Radio]`; `fields[1].options == ["a", "b"]`;
  `fields[2].value == Some("1")`; `fields[3].checked == true`, `fields[4].checked == false`.
  `extract_caps_links`: 600 anchors → `links.len() == 512`. `extract_survives_garbage`:
  `"<a href=<<<>>>><form><input"` returns without panic.
- **Done when:** tests pass; full gate passes.

### Task 5: `params.rs`: form, cookie and JSON walking, body format

- **Satisfies:** AC T2-2 (`json_value` nested path `profile.address.city`), D8.1 typed JSON
  replacement, research 20 §3.10 (4) (JSON mutation always yielded a string).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/params.rs`.
- **Change:**
  ```
  pub(crate) fn form_pairs(input: &str) -> Vec<(String, String)>            // form_urlencoded; empty names dropped; cap MAX_PAIRS
  pub(crate) fn serialize_form(pairs: &[(String, String)]) -> String
  pub(crate) fn cookie_pairs(header: &str) -> Vec<(String, String)>         // split ';', first '=' splits, trims; cap MAX_PAIRS
  pub(crate) fn serialize_cookies(pairs: &[(String, String)]) -> String     // "a=1; b=2"
  pub(crate) struct JsonLeaf { pub path: String, pub value: serde_json::Value }
  pub(crate) fn json_leaves(root: &serde_json::Value) -> Vec<JsonLeaf>      // leaves = string|number|bool|null; dotted keys, [i] indexes; a key containing '.' '[' ']' or '"' is rendered ["key"]; depth cap MAX_JSON_DEPTH; cap MAX_PAIRS
  pub(crate) enum JsonStep { Key(String), Index(usize) }
  pub(crate) fn parse_json_path(path: &str) -> anyhow::Result<Vec<JsonStep>>
  pub(crate) fn json_get<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value>
  pub(crate) fn json_set(root: &mut serde_json::Value, path: &str, new: serde_json::Value) -> anyhow::Result<()>   // Err names the path
  pub(crate) fn json_rename_top(root: &mut serde_json::Value, key: &str, new_key: &str) -> anyhow::Result<()>
  pub(crate) fn typed_replacement(original: &serde_json::Value, text: &str) -> serde_json::Value
  pub(crate) struct SplitPath<'a> { pub path: &'a str, pub query: Option<&'a str> }
  pub(crate) fn split_path(raw: &str) -> SplitPath<'_>
  pub(crate) fn body_bytes(body: &Body) -> Option<&[u8]>                     // Bytes → Some, Empty → Some(&[]), Streamed → None
  pub(crate) enum BodyFormat { None, Form, Json, Xml, Multipart { boundary: String }, Other, Unavailable }
  pub(crate) fn body_format(req: &HttpRequest) -> BodyFormat
  ```
  `typed_replacement`: a Number original with `text` parsing as `i64`/`u64`/`f64` (finite) stays a
  Number; a Bool original with `true`/`false` stays a Bool; everything else becomes a String.
  `body_format`: `application/x-www-form-urlencoded` → Form; `application/json` or a `+json`
  suffix → Json; `application/xml`, `text/xml` or a `+xml` suffix → Xml; `multipart/form-data`
  with a `boundary=` parameter (quotes stripped) → Multipart; `Body::Empty` → None;
  `Body::Streamed` → Unavailable; a non-empty body of any other type → Other.
- **Test:** `json_leaves_pins` on
  `{"profile":{"address":{"city":"Lisbon"}},"items":[{"name":"a"}],"n":3,"ok":true,"z":null,"e":{},"arr":[]}`:
  the set of paths is exactly `{"profile.address.city", "items[0].name", "n", "ok", "z"}`
  (compare as sorted vectors) and the first path is `"profile.address.city"` (wire order: the
  workspace's `serde_json` has `preserve_order` unified through `aitm-poc`).
  `json_set_and_get`: `json_set(.., "profile.address.city", "X")` then
  `json_get(.., "profile.address.city") == Some("X")`; `json_set(.., "items[0].name", 7)` works;
  `json_set(.., "items[5].name", ..)` is `Err` whose message contains `items[5].name`;
  `json_set` on a key with a dot via `["a.b"]` works.
  `typed_replacement_pins`: `(json!(3), "7") == json!(7)`; `(json!(3), "7'") == json!("7'")`;
  `(json!(1.5), "2.5") == json!(2.5)`; `(json!(true), "false") == json!(false)`;
  `(json!("x"), "5") == json!("5")`; `(json!(null), "5") == json!("5")`.
  `cookie_pairs_pins`: `cookie_pairs("a=1; b=2=3; ;c") == [("a","1"), ("b","2=3")]`;
  `serialize_cookies(&that) == "a=1; b=2=3"`.
  `form_round_trip`: `serialize_form(&form_pairs("a=1&b=x+y&=z")) == "a=1&b=x+y"`.
  `body_format_pins`: `application/json; charset=utf-8` → `Json`;
  `multipart/form-data; boundary="XyZ"` → `Multipart { boundary: "XyZ" }`; `text/xml` → `Xml`;
  `application/soap+xml` → `Xml`; `Body::Empty` → `None`; a `Streamed` body → `Unavailable`;
  `text/plain` with bytes → `Other`.
  `split_path_pins`: `split_path("/a/b?x=1&y")` → `path "/a/b"`, `query Some("x=1&y")`;
  `split_path("/a")` → `query None`.
- **Done when:** tests pass; full gate passes.

### Task 6: `xml.rs`: offset-recording XML tokenizer, escape, splice

- **Satisfies:** AC T2-2 (`xml_value` points), D8.1 `xml_value`/`xml_attr` kinds and
  re-serialisation; orchestrator decision 3 (hand-rolled, offset-based, never a full re-serialiser).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/xml.rs`.
- **Change:**
  ```
  pub(crate) enum XmlSlotKind { Text, Attr }
  pub(crate) struct XmlSlot { pub kind: XmlSlotKind, pub path: String, pub name: String, pub span: Range<usize>, pub value: String, pub cdata: bool }
  pub(crate) fn scan(bytes: &[u8]) -> anyhow::Result<Vec<XmlSlot>>
  pub(crate) fn escape(text: &str) -> String                                  // & < > " ' → &amp; &lt; &gt; &quot; &apos;
  pub(crate) fn splice(bytes: &[u8], span: Range<usize>, replacement: &[u8]) -> Vec<u8>
  ```
  `scan` is a single forward pass over the bytes (must be valid UTF-8, else `Err`): skips the XML
  declaration, processing instructions, comments and `DOCTYPE` (no entity expansion, ever);
  records an `Attr` slot per attribute (span = the bytes between the quotes, value entity-decoded
  for the five XML entities and `&#NN;`), a `Text` slot for every element whose content is text
  only (no child elements) and not all whitespace (span = the raw text bytes), and a `Text` slot
  with `cdata: true` for a `<![CDATA[...]]>` child (span = the bytes between `[` and `]]`). Path =
  dotted element names from the root (`order.item`); an attribute's path is `order.item@sku`;
  `name` = the element or attribute local name (prefix stripped). Depth cap `MAX_XML_DEPTH`,
  slot cap `MAX_XML_SLOTS`. Unbalanced or unterminated markup → `Err` naming the byte offset.
- **Test:** `scan_pins` on
  `<?xml version="1.0"?><order id="7"><item sku="A1">Widget</item><note><![CDATA[x<y]]></note><empty/></order>`:
  slots in order `[(Attr, "order@id", "id", "7"), (Attr, "order.item@sku", "sku", "A1"), (Text, "order.item", "item", "Widget"), (Text, "order.note", "note", "x<y" with cdata)]`;
  `&bytes[slots[2].span.clone()] == b"Widget"`; `&bytes[slots[0].span.clone()] == b"7"`.
  `splice_escapes`: `splice(bytes, slots[2].span, escape("<b>&\"").as_bytes())` equals the document
  with `Widget` replaced by `&lt;b&gt;&amp;&quot;`; splicing the `sku` attribute with
  `escape("a\"b")` yields `sku="a&quot;b"`. `scan_errors_name_offset`: `<a><b>` → `Err` whose
  message contains `offset`; `scan_skips_doctype_entities`:
  `<!DOCTYPE x [<!ENTITY e "boom">]><a>&e;</a>` → one Text slot with value `&e;` left undecoded (no
  expansion). `scan_caps`: 2000 attributes → `slots.len() == 1024`.
- **Done when:** tests pass; full gate passes.

### Task 7: `multipart.rs`: offset-recording multipart parser, splice

- **Satisfies:** AC T2-2 (`multipart_value` points), D8.1 `multipart_value`/`multipart_filename`
  kinds; orchestrator decision 3.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/multipart.rs`.
- **Change:**
  ```
  pub(crate) struct Part { pub name: Option<String>, pub filename: Option<String>, pub filename_span: Option<Range<usize>>, pub content_type: Option<String>, pub value_span: Range<usize> }
  pub(crate) fn boundary_of(content_type: &str) -> Option<String>
  pub(crate) fn parse(bytes: &[u8], boundary: &str) -> anyhow::Result<Vec<Part>>
  pub(crate) fn splice(bytes: &[u8], span: Range<usize>, replacement: &[u8]) -> Vec<u8>
  pub(crate) fn escape_filename(text: &str) -> String                     // '"' → %22, CR → %0D, LF → %0A, '\\' → %5C
  ```
  `parse` walks `--boundary\r\n` delimited parts (CRLF per RFC 2046; an LF-only body is `Err`,
  call A7), reads `Content-Disposition` (`name=`, `filename=`, quoted or bare) and
  `Content-Type`, records `value_span` as the bytes between the blank line and the `\r\n` before
  the next delimiter, and `filename_span` as the bytes between the filename quotes. A missing
  closing `--boundary--` is `Err`. Cap `MAX_MULTIPART_PARTS`.
- **Test:** `parse_pins` on the literal body (boundary `XyZ`)
  `--XyZ\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name="doc"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nfile-bytes\r\n--XyZ--\r\n`:
  `parts.len() == 2`; `parts[0].name == Some("title")`, `&bytes[parts[0].value_span] == b"hello"`;
  `parts[1].filename == Some("a.txt")`, `&bytes[parts[1].filename_span] == b"a.txt"`,
  `parts[1].content_type == Some("text/plain")`, `&bytes[parts[1].value_span] == b"file-bytes"`.
  `splice_value`: splicing `parts[0].value_span` with `b"<x>"` yields a body whose first part
  content is `<x>` and which still ends with `--XyZ--\r\n`; a re-`parse` of the result gives
  `parts[0]` value `b"<x>"`. `splice_filename`: `escape_filename("../x\"y.txt") == "../x%22y.txt"`
  and splicing it keeps the quotes balanced (re-parse gives `filename == Some("../x%22y.txt")`).
  `boundary_pins`: `boundary_of("multipart/form-data; boundary=\"XyZ\"") == Some("XyZ")`,
  `boundary_of("multipart/form-data; boundary=XyZ; charset=utf-8") == Some("XyZ")`,
  `boundary_of("application/json") == None`. `parse_errors`: body without the closing delimiter →
  `Err`; LF-only body → `Err`.
- **Done when:** tests pass; full gate passes.

### Task 8: `template.rs`: path templates and value traits

- **Satisfies:** AC T2-1 (site map shows `/account/{id}`), AC T2-2 (`path_segment` non-numeric,
  `path_filename`), D8.1 `SiteNode.path_template` and point traits.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/template.rs`.
- **Change:**
  - `pub(crate) fn path_template(path: &str) -> String`: query dropped; per segment: all ASCII
    digits → `{id}`; UUID (`8-4-4-4-12` hex, any case) → `{uuid}`; exactly 24 hex → `{oid}`; else
    unchanged; empty path → `/`; trailing slash kept.
  - `pub(crate) fn looks_like_filename(segment: &str) -> bool`: not all digits, contains a `.`
    that is not first or last, and the text after the last `.` is 1..=8 ASCII alphanumerics.
  - `pub(crate) fn is_id_like(value: &str) -> bool`: all digits (1..=20), UUID, or 24 hex.
  - `pub(crate) fn traits_for(value: &str) -> Vec<PointTrait>` in the enum's order
    `[Url, Filename, Number, Email, Base64, Json, Id]` (never `Session`; `points.rs` adds that):
    `Url` when the value starts with `http://`, `https://` or `//`, or starts with `/` and has
    length > 1 and no whitespace; `Filename` when `looks_like_filename` holds for the last `/`
    segment of a value with no whitespace **and the value is not email-shaped** (orchestrator
    amendment 2026-11-01: every email ends in `.tld`, so without this tie-break `a@b.co` would carry
    `[Filename, Email]`; the pinned test `[Email]` is authoritative, and `wants_traits: filename`
    checks must not probe email fields); `Number` when it parses as `i64` or finite `f64`;
    `Email` when it has exactly one `@` with a `.` after it and no whitespace; `Base64` when
    length >= 16, length % 4 == 0, charset `[A-Za-z0-9+/]` with `=` padding only at the end and
    not all digits; `Json` when it starts with `{` or `[` and `serde_json::from_str` succeeds;
    `Id` when `is_id_like`.
- **Test:** `path_template_pins`: `"/account/42/notes"` → `"/account/{id}/notes"`;
  `"/u/550e8400-e29b-41d4-a716-446655440000/"` → `"/u/{uuid}/"`;
  `"/o/507f1f77bcf86cd799439011"` → `"/o/{oid}"`; `"/files/reports/summary.pdf?x=1"` →
  `"/files/reports/summary.pdf"`; `""` → `"/"`; `"/v1.2/x"` unchanged.
  `filename_pins`: `looks_like_filename("summary.pdf") == true`, `("reports") == false`,
  `("7") == false`, `(".htaccess") == false`, `("a.") == false`, `("v1.2") == true`.
  `traits_pins`: `traits_for("https://e.test/x") == [Url]`; `traits_for("/cb") == [Url]`;
  `traits_for("42") == [Number, Id]`; `traits_for("a@b.co") == [Email]`;
  `traits_for("{\"a\":1}") == [Json]`; `traits_for("summary.pdf") == [Filename]`;
  `traits_for("QUJDREVGR0hJSktMTU5PUA==") == [Base64]`;
  `traits_for("550e8400-e29b-41d4-a716-446655440000") == [Id]`; `traits_for("hello") == []`.
- **Done when:** tests pass; full gate passes.

### Task 9: `testutil.rs`: in-process test doubles (inner loop only)

- **Satisfies:** none directly; enables hermetic unit tests for Tasks 13, 15, 17, 18, 19, 20
  (spec Constraints: default `cargo test` stays hermetic). Not acceptance evidence.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-http/src/testutil.rs` (`#[cfg(test)]`).
- **Change:**
  ```
  pub(crate) const JOB_ID: &str = "scan-1a2b3c4d";  pub(crate) const MARKER: &str = "aitm7f3a";
  pub(crate) fn conn() -> ConnInfo
  pub(crate) fn request(method: &str, url: &str, headers: &[(&str, &str)], body: Option<(&str, &[u8])>) -> HttpRequest   // body = (content-type, bytes); sets content-length
  pub(crate) fn captured_flow(req: HttpRequest, status: u16, resp_headers: &[(&str, &str)], resp_body: &[u8]) -> HttpFlow   // is_replay false
  pub(crate) struct ScriptedClient { pub sent: Mutex<Vec<(HttpRequest, SendOptions)>>, store: Option<Arc<dyn FlowStore>>, script: Box<dyn Fn(&HttpRequest) -> anyhow::Result<HttpResponse> + Send + Sync>, pub delay: Option<Duration> }
  impl ScriptedClient { pub fn new(script) -> Self; pub fn recording_into(self, store: Arc<dyn FlowStore>) -> Self; pub fn sent_paths(&self) -> Vec<String> }
  impl ProxyClient for ScriptedClient   // send → send_opts(default); send_opts records (req, opts), builds an HttpFlow with is_replay true and marks = opts.marks, inserts into the store only when record == Always
  pub(crate) struct PageScript { pub html: String, pub status: u16, pub final_url: Option<String>, pub clickables: Vec<(String, String)> /* (selector, lands_on_url) */, pub captures: Vec<HttpRequest> /* inserted into the store as captured flows on navigate, simulating the proxy */ }
  pub(crate) struct FakeBrowser { pages: HashMap<String, PageScript>, pub log: Mutex<Vec<String>>, current: Mutex<String>, cookies: Mutex<String>, store: Option<Arc<dyn FlowStore>> }
  impl BrowserDriver for FakeBrowser   // navigate: logs "navigate <url>", sets current (final_url if given), inserts captures; click(Selector): logs "click <sel>", sets current to the clickable's landing URL, inserts that page's captures; type_text: logs; eval: `document.cookie = "..."` appends to cookies; `document.cookie` returns them; `location.href` returns current; `document.readyState` returns "complete"; an expr containing the marker comment `/*aitm-clickables*/` returns Value::Array of Value::Object{selector,text} for the current page; an expr containing `requestSubmit` or `.submit()` navigates to the form's action recorded in the page (the test sets it via PageScript.html forms resolved by the browser double using crawl::extract); get_dom returns html; screenshot returns empty
  pub(crate) struct FakeJob { pub profile: ScanProfile, pub client: Arc<ScriptedClient>, pub store: Arc<MemFlowStore>, pub guard: Arc<StdGuard>, pub browser: Option<Arc<FakeBrowser>>, pub session: Option<Arc<SessionMaterial>>, pub budget: AtomicU32, pub charges: AtomicU32, pub cancelled: AtomicBool, pub deadline: Instant }
  impl FakeJob { pub fn new(profile: ScanProfile, client: Arc<ScriptedClient>) -> Self /* guard with ScopeEntry host "t:8080" and "127.0.0.1:8080"; budget 1000; deadline now+60s */ }
  impl JobCtx for FakeJob   // charge: decrements budget, counts charges, false at zero; marker MARKER; job_id JOB_ID
  pub(crate) fn site(pages: &[(&str, &str)]) -> ScriptedClient   // a tiny static site: path → html (200, text/html), unknown → 404; "302:<location>" html prefix answers a redirect
  ```
- **Test:** `scripted_client_records_only_on_always`: `send_opts` with `Never` → store count 0,
  `sent.len() == 1`; with `Always` and marks `["scan:scan-1a2b3c4d", "crawl"]` → count 1 and the
  stored flow's marks equal that. `fake_browser_cookie_round_trip`: `eval("document.cookie = \"sid=S3; path=/\"")`
  then `eval("document.cookie")` → `Value::Str("sid=S3")`. `fake_job_charges`: budget 2 →
  `charge(1)`, `charge(1)` true, third false, `charges == 2`.
- **Done when:** tests pass; `cargo clippy --all-targets` clean; full gate passes.

### Task 10: `points.rs`: `enumerate_v2`, kinds/ignore rules, per-request cap

- **Satisfies:** AC T2-2 (every listed kind with the listed shapes; cookie examples `<redacted>`),
  AC T2-6 (examples redacted), D8.1 "Insertion points v2", D7 (session-trait points), orchestrator
  decision 6 (iii)-(iv).
- **Depends on:** Tasks 2, 3, 5, 6, 7, 8.
- **Files:** `crates/aitm-scan-http/src/points.rs`.
- **Change:**
  ```
  pub(crate) struct CompiledIgnore { rules: Vec<CompiledRule> }   // CompiledRule { kind: Option<InsertionKind>, name: Option<Regex>, point_trait: Option<PointTrait> }
  impl CompiledIgnore { pub fn compile(rules: &[IgnoreRule]) -> anyhow::Result<Self>; pub fn matches(&self, kind: InsertionKind, name: &str, traits: &[PointTrait]) -> bool }
  pub(crate) struct EnumerateOptions<'a> { pub intensity: Intensity, pub kinds: &'a [InsertionKind], pub ignore: &'a CompiledIgnore, pub max_points: u32, pub session: Option<&'a SessionMaterial> }
  impl<'a> EnumerateOptions<'a> { pub fn from_profile(profile: &'a ScanProfile, ignore: &'a CompiledIgnore, session: Option<&'a SessionMaterial>) -> Self }
  pub(crate) struct Enumerated { pub points: Vec<InsertionPoint>, pub seen: Vec<ParamRef>, pub overflow: u32, pub ignored: u32, pub kind_filtered: u32 }
  pub(crate) fn enumerate_v2(flow: &HttpFlow, opts: &EnumerateOptions<'_>) -> Enumerated
  pub(crate) fn kind_token(kind: InsertionKind) -> &'static str              // the snake_case wire token
  ```
  Candidate order (what survives the cap): query values; path segments and filename; body
  (by `body_format`: Form → `body_param`; Json → `json_value` per leaf with `path`; Xml →
  `xml_value`/`xml_attr` per slot with `path`; Multipart → `multipart_value` per named part and
  `multipart_filename` per part with a filename; Other → one `entire_body` named `body`; None /
  Unavailable / body over `MAX_BODY_PARSE_BYTES` → no body points, a `tracing::debug` line);
  headers; cookies; then, only at `intensity >= Medium`, `param_name_query` per query key and
  `param_name_body` per form key or top-level JSON key. Dedupe on `(kind, name, path)`.
  Excluded headers (case-insensitive): `host`, `content-length`, `transfer-encoding`,
  `connection`, `cookie`, `content-type` (call A8), `keep-alive`, `proxy-connection`, `te`,
  `trailer`, `upgrade`, `expect`, and any name starting with `:`. Path points: every non-empty
  segment is `path_segment` (name = the segment text, `path` = its 1-based index as a string)
  except the last when `looks_like_filename` (then `path_filename`). Traits: `traits_for(value)`
  plus `Json` on every `json_value` point (decision 10) plus `Session` when the name equals a
  session cookie name (cookie kind) or a session header name (header kind, case-insensitive) in
  `opts.session`, or `is_secret_name(name)`. `example` = `redact::example(kind, name, value)`;
  for `param_name_*` the example is the key itself; for `entire_body` the first 64 chars scrubbed.
  `url` = `scheme://authority/path?query` as captured, passed through `redact::safe_url`
  (secret-keyed query values `<redacted>`, other values scrubbed, userinfo/fragment dropped,
  bounded to `MAX_SAFE_URL_CHARS`; amended 2026-11-01 under the anti-goal "no result carries a
  value", fix 21243e44); `method` = the request's; `flow` =
  `Some(FlowRef(flow.id))`; `site_node = None`; `frequency = 1`; `id =
  format!("{}:{}:{}", flow.id, kind_token(kind), ordinal)` (call A9). After collecting, drop
  kinds not in `opts.kinds` (count `kind_filtered`), drop points matching `ignore` (count
  `ignored`), keep the first `max_points` (count `overflow`). `seen` lists every deduped
  `(kind, name)` candidate before filtering, for the site map's `params`.
- **Test:** `enumerate_pins` on a captured
  `POST http://t:8080/files/reports/summary.pdf?q=1&next=https://e.test/` with headers
  `X-Client: abc`, `Cookie: sid=S3; theme=dark`, `Authorization: Bearer tok`,
  `Content-Type: application/json` and body `{"profile":{"address":{"city":"Lisbon"}},"n":3}`,
  options from `ScanProfile::default()` (Medium, all kinds, default ignore `[{trait: session}]`,
  max 64) with session material cookies `[("sid","S3")]`, headers `[]`:
  the `(kind, name, path)` set contains `(Query,"q",None)`, `(Query,"next",None)` with
  `traits == [Url]`, `(PathSegment,"files",Some("1"))`, `(PathSegment,"reports",Some("2"))`,
  `(PathFilename,"summary.pdf",Some("3"))` with `traits == [Filename]`,
  `(JsonValue,"city",Some("profile.address.city"))` with `traits == [Json]` and
  `example == Some("Lisbon")`, `(JsonValue,"n",Some("n"))` with `traits == [Number, Json, Id]`,
  `(Header,"X-Client",None)` with `example == Some("abc")`, `(Cookie,"theme",None)` with
  `example == Some("<redacted>")`, `(ParamNameQuery,"q",None)`, `(ParamNameQuery,"next",None)`,
  `(ParamNameBody,"profile",None)`, `(ParamNameBody,"n",None)`; it does **not** contain
  `(Cookie,"sid",_)`, `(Header,"Authorization",_)`, `(Header,"Host",_)`,
  `(Header,"Content-Type",_)`, `(Header,"Content-Length",_)` or any `EntireBody`;
  `ignored == 2`; `seen` contains `ParamRef { kind: Cookie, name: "sid" }` and
  `ParamRef { kind: Header, name: "Authorization" }`; every point has `method == Some("POST")`,
  `url == Some("http://t:8080/files/reports/summary.pdf?q=1&next=https://e.test/")`,
  `flow == Some(..)`, `frequency == 1`; ids are pairwise distinct.
  `light_has_no_param_names`: `intensity: Light` → no `ParamName*` point.
  `cap_counts_overflow`: `max_points: 3` → `points.len() == 3` and `overflow == total - 3`.
  `kinds_filter`: `kinds: &[Query]` → every point is `Query`, `kind_filtered > 0`.
  `ignore_regex`: rule `{ kind: Some(Header), name_regex: Some("(?i)^x-") }` drops `X-Client`.
  `ignore_compile_errors`: `compile(&[IgnoreRule::default()])` is `Err` (no key);
  `name_regex: Some("(")` is `Err` whose message contains `(`.
  `xml_and_multipart_kinds`: a `text/xml` body `<order id="7"><item>W</item></order>` yields
  `(XmlAttr,"id",Some("order@id"))` and `(XmlValue,"item",Some("order.item"))`; the Task 7
  multipart body yields `(MultipartValue,"title",None)` with `example == Some("hello")`,
  `(MultipartValue,"doc",None)` and `(MultipartFilename,"doc",None)` with `traits == [Filename]`
  and `example == Some("a.txt")`.
  `entire_body_only_for_unrecognised`: `text/plain` body `hello` → one `(EntireBody,"body",None)`;
  the JSON flow above yields none. `streamed_and_huge_bodies_skip`: a `Streamed` body and a
  3 MiB `Other` body yield no body points and no panic. `session_header_name_marks_trait`:
  material headers `[("X-Api-Key","k")]` → `(Header,"X-Api-Key")` carries `Session` and is
  ignored by the default rule; with `ignore: []` it is returned with `example == Some("<redacted>")`.
- **Done when:** tests pass; full gate passes.

### Task 11: `mutate.rs`: `build_request`, the single mutation function

- **Satisfies:** AC T2-3 (header and cookie points are mutable), D8.1 `build_request`,
  research 20 §3.10 (4), orchestrator decision 8.
- **Depends on:** Tasks 3, 5, 6, 7.
- **Files:** `crates/aitm-scan-http/src/mutate.rs`.
- **Change:**
  ```
  pub(crate) fn apply_mode(original: &str, payload: &Payload) -> String           // Replace → value; Prefix → value + original; Suffix → original + value
  pub(crate) fn build_request(original: &HttpRequest, point: &InsertionPoint, payload: &Payload) -> anyhow::Result<HttpRequest>
  ```
  Per kind: `query` → re-serialise the query with `form_urlencoded` replacing the first pair of
  that name; `body_param` → same on the form body; `json_value` → `json_set(path,
  typed_replacement(original_leaf, text))`; `xml_value`/`xml_attr` → re-`scan`, find the slot by
  `path`, `splice` with `escape(text)` (or `payload.bytes` raw when set); `multipart_value` →
  re-`parse`, splice the named part's `value_span` with the text bytes (or raw `bytes`);
  `multipart_filename` → splice `filename_span` with `escape_filename(text)`; `header` →
  `headers.remove(name)` then `try_set(name, text)` (`HeaderMap::set` appends, so remove first;
  an invalid value is `Err`); `cookie` → rebuild the `Cookie` header from `cookie_pairs` with the
  named value replaced (`;`, CR, LF percent-encoded), order preserved; `path_segment`/
  `path_filename` → replace the segment at the 1-based index in `path` with the text
  percent-encoded (RFC 3986 path segment set) unless the text already contains `%`, keeping the
  query; `param_name_query`/`param_name_body` → rename the key (form) or `json_rename_top`;
  `entire_body` → body = `bytes` when set else the text. In every case the original value is
  passed through `apply_mode` first (for `param_name_*` the key is; for `entire_body` the body
  text is). After the change: when the body is `Body::Bytes`, set `content-length` to its length
  (remove then set) and remove `transfer-encoding`; never touch `host`. A point whose request no
  longer parses to its kind (param missing, body format changed, slot gone) → `Err` whose message
  contains `kind_token(point.kind)` and the point id. WS/L4 kinds → `Err`.
- **Test:** (helpers build points by hand with the given kind/name/path)
  `query_pins`: `/search?q=hello&x=1`, point `q`, payload `<s>` Replace → path
  `"/search?q=%3Cs%3E&x=1"`; Suffix → `"/search?q=hello%3Cs%3E&x=1"`; Prefix → `"/search?q=%3Cs%3Ehello&x=1"`.
  `form_pins`: body `a=1&b=2`, point `b`, payload `x y` → body `b"a=1&b=x+y"`, `content-length` `"9"` (corrected 2026-11-01: the recomputed length of the new body; `7` was the original body's).
  `json_typed`: `{"n":3,"s":"a"}` point path `n` payload `7` → body `{"n":7,"s":"a"}`; payload
  `7'` → `{"n":"7'","s":"a"}`; nested `profile.address.city` replaced in place; path `missing` →
  `Err` containing `json_value`.
  `xml_pins`: `<a><b>v</b></a>` point `xml_value` path `a.b` payload `<x>&"` → body
  `<a><b>&lt;x&gt;&amp;&quot;</b></a>`; `<a id="1"/>` point `xml_attr` path `a@id` payload `"` →
  `<a id="&quot;"/>`; `Payload { bytes: Some(b"<raw/>") }` on `a.b` → `<a><b><raw/></b></a>`.
  `multipart_pins`: the Task 7 body, point `multipart_value` `title` payload `<x>` → re-parse gives
  part 0 value `b"<x>"` and `content-length` equals the new body length; point `multipart_filename`
  `doc` payload `../x"y.txt` → re-parse gives `filename == Some("../x%22y.txt")`.
  `header_and_cookie_pins`: header `X-Client` payload `zz` → exactly one `X-Client` header with
  value `zz`; payload `"a\r\nb"` → `Err`; cookie `theme` on `Cookie: sid=S3; theme=dark` payload
  `<p>` → `Cookie: sid=S3; theme=<p>`; payload `a;b` → `theme=a%3Bb`.
  `path_pins`: `/files/reports/summary.pdf?x=1`, point `path_segment` `reports` (path `2`)
  payload `..%2f` → `/files/..%2f/summary.pdf?x=1`; payload `a b` → `/files/a%20b/summary.pdf?x=1`;
  point `path_filename` payload `x.txt` → `/files/reports/x.txt?x=1`.
  `param_name_pins`: `param_name_query` `q` payload `qq` → `/search?qq=hello&x=1`;
  `param_name_body` on form `a=1&b=2` key `b` → `a=1&bb=2` (payload `bb`); on JSON `{"n":3}` →
  `{"nn":3}`.
  `entire_body_pins`: text `X` → body `b"X"`, content-type unchanged, `content-length` `"1"`;
  `bytes: Some(vec![0,1,2])` → body exactly those bytes.
  `host_untouched_and_te_removed`: every case above leaves `host` equal to the original; a request
  with `Transfer-Encoding: chunked` and a form body loses it after mutation.
  `stale_point_errors`: query point `missing` → `Err` containing `query`; form point on a JSON body
  → `Err` containing `body_param`.
- **Done when:** tests pass; full gate passes.

### Task 12: `sitemap.rs`: `SiteMapBuilder`, node ids, frequency, auth

- **Satisfies:** AC T2-1 (`path_template` `/account/{id}`), AC T2-2 (sitemap points), D8.1 "Site
  map", orchestrator decision 6 (v) and decision 10 (scheduler inputs through existing fields).
- **Depends on:** Tasks 3, 8 (and Task 10's `Enumerated` type).
- **Files:** `crates/aitm-scan-http/src/sitemap.rs`.
- **Change:**
  ```
  pub(crate) fn node_id(method: &str, scheme: &str, host: &str, port: u16, path_template: &str) -> NodeId   // "n-" + 16 lowercase hex of fnv1a64 over "METHOD scheme host port template"
  pub(crate) fn is_authenticated(req: &HttpRequest, session: Option<&SessionMaterial>) -> bool    // Cookie or Authorization present, or any session header name present
  pub(crate) struct SiteMapBuilder { .. }
  impl SiteMapBuilder {
    pub fn new() -> Self;
    pub fn add(&mut self, flow_id: FlowId, req: &HttpRequest, enumerated: Enumerated, auth: bool) -> Option<NodeId>;   // None when request_url fails; merges into the node keyed (method, scheme, host, port, path_template): pushes the flow, unions params (seen), ORs auth, sets site_node on every point, adds points.len() to node.points
    pub fn finish(self) -> Discovery;   // frequency per (kind, name) = number of distinct nodes whose params carry it; nodes sorted by (host, path_template, method); points in insertion order
  }
  ```
- **Test:** `template_merges_numeric_ids`: `GET /account/1?tab=x` and `GET /account/2` → one node
  with `path_template == "/account/{id}"`, `flows.len() == 2`, `params` contains
  `ParamRef { Query, "tab" }` exactly once, `method == "GET"`, `port == 8080`, `scheme == "http"`,
  `host == "t"`. `frequency_counts_nodes`: three nodes each with a `theme` cookie point → every
  `theme` point has `frequency == 3`, a `q` point present on one node has `frequency == 1`.
  `node_id_is_stable`: two builders over the same input produce equal `id`s; `node_id("GET","http","t",8080,"/a") == node_id("GET","http","t",8080,"/a")` and differs for `POST`.
  `auth_flag`: a request with `Cookie` → `is_authenticated == true`; with only `X-Api-Key` and
  session headers `[("X-Api-Key", ..)]` → true; plain → false. `points_count`: node `points` equals
  the number of points attached and every point's `site_node == Some(node.id)`.
- **Done when:** tests pass; full gate passes.

### Task 13: `session.rs`: session application, browser cookies, canary monitor

- **Satisfies:** AC T2-4 (session material applied to probes and crawler), AC T2-5 (session lost
  → the lane's token), AC T2-6 (no value in logs), D7, orchestrator decision 5.
- **Depends on:** Tasks 2, 3, 9.
- **Files:** `crates/aitm-scan-http/src/session.rs`.
- **Change:**
  ```
  pub(crate) const SESSION_LOST_PREFIX: &str = "scan: session_lost: ";
  pub(crate) fn apply_session(req: &mut HttpRequest, material: &SessionMaterial)     // headers: add each session header only when the request lacks that name (request-specific wins); cookies: parse the request's Cookie, append session cookies whose name is absent, keep order, rewrite the header; no Cookie header + cookies → create one
  pub(crate) fn browser_cookie_statements(material: &SessionMaterial) -> Vec<String>   // one `document.cookie = "name=value; path=/"` per cookie; value with ';' '"' '\\' CR LF percent-encoded; a name that is not an RFC 6265 token is skipped
  pub(crate) fn browser_partial(material: &SessionMaterial, document_cookie: &str) -> Vec<String>   // cookie names not present in the read-back
  pub(crate) struct CanaryRequest { pub request: HttpRequest, pub method: CanaryMethod, pub path: String, pub expected_status: u16 }
  pub(crate) fn pick_canary(store: &dyn FlowStore, origin: &Url, material: &SessionMaterial, from_flow: Option<FlowId>) -> Option<CanaryRequest>
  pub(crate) enum CanaryOutcome { Unarmed, Ok, Lost { before: u16, after: u16 } }
  pub(crate) struct SessionMonitor { canary: Option<CanaryRequest>, on_lost: OnLost, every: u32, ticks: AtomicU32, lost: AtomicBool, logged: AtomicBool }
  impl SessionMonitor {
    pub fn new(canary: Option<CanaryRequest>, on_lost: OnLost, every: u32) -> Self;
    pub fn unarmed(on_lost: OnLost) -> Self;
    pub fn tick(&self) -> bool;                                   // increments; true when armed and ticks % every == 0
    pub fn is_lost(&self) -> bool;  pub fn should_stop(&self) -> bool;   // lost && Stop
    pub fn canary(&self) -> Canary;                               // the model's status shape, for logging
    pub async fn check(&self, client: &dyn ProxyClient, opts: SendOptions, timeout: Duration) -> CanaryOutcome;   // sends the canary with its headers unchanged, Body::Empty; before = expected_status, after = the reply status (0 on transport error, counted as lost only if before was 2xx); lost when before/100 == 2 and after/100 != 2; on loss sets `lost` and logs once at warn (path through safe_url, never a value)
    pub fn lost_error(&self, context: &str) -> anyhow::Error;   // anyhow!("{SESSION_LOST_PREFIX}{context}")
  }
  ```
  `pick_canary`: when `from_flow` names an HTTP flow that is `GET`/`HEAD`, captured (not replay),
  to `origin`, carrying at least one of the material's cookie or header names → it; otherwise
  (and when `from_flow` was given but ineligible, logged at info as a substitution) the newest
  captured `GET`/`HEAD` HTTP flow to `origin` carrying any material name, with a response; the
  request's body is forced to `Body::Empty`; `expected_status` = that flow's response status.
  `None` when nothing qualifies.
- **Test:** `apply_session_merge`: request `Cookie: theme=dark; sid=old`, `X-Api-Key: mine`;
  material cookies `[("sid","NEW"),("lang","en")]`, headers `[("Authorization","Bearer T"),("X-Api-Key","K")]`
  → `Cookie == "theme=dark; sid=old; lang=en"`, `Authorization == "Bearer T"`,
  `X-Api-Key == "mine"`, exactly one of each header. No-cookie request → `Cookie == "sid=NEW; lang=en"`.
  `browser_statements`: material `[("sid","S3"),("bad name","x"),("v","a;b")]` →
  `["document.cookie = \"sid=S3; path=/\"", "document.cookie = \"v=a%3Bb; path=/\""]`;
  `browser_partial(material_with(sid, hs), "sid=S3") == ["hs"]`.
  `pick_canary_rules`: store with (oldest→newest) `GET /public` (no cookie), `GET /account`
  (`Cookie: sid=S3`, 200), `POST /login` (`Cookie: sid=S3`, 302), a replay `GET /account` →
  picks `GET /account` with `expected_status == 200` and `path == "/account"`; `from_flow` = the
  POST → the same GET; material names absent from every flow → `None`; the returned request has
  `Body::Empty` and method `GET`.
  `monitor_ticks_and_lost`: `every = 2`, ScriptedClient answering 200 then 302: `tick()` is false,
  true, false, true; first `check` → `Ok`, second → `Lost { before: 200, after: 302 }`;
  `is_lost()`, `should_stop()` (Stop) true; with `Continue` `should_stop()` false;
  `lost_error("probe").to_string().starts_with("scan: session_lost: ")`; the canary request the
  client saw has `Body::Empty` and method `GET`. `unarmed_never_ticks_true`: `unarmed(Stop).tick()`
  false 30 times; `check` → `Unarmed`. The test module asserts no value appears in the monitor's
  log line by checking `canary()` renders `Canary::Flow { method: GET, path: "/account", expected_status: Some(200) }`.
- **Done when:** tests pass; full gate passes.

### Task 14: `crawl/values.rs`: inert generated form values

- **Satisfies:** AC T2-1 (form submission reaches the seeded route), D8.1 "type+submit on forms
  with inert values".
- **Depends on:** Tasks 3, 4.
- **Files:** `crates/aitm-scan-http/src/crawl/values.rs`.
- **Change:**
  ```
  pub(crate) fn value_for(field: &FieldSpec, marker: &str, origin: &str) -> Option<String>
  pub(crate) fn form_pairs_for(form: &FormSpec, marker: &str, origin: &str) -> Vec<(String, String)>   // hidden values kept; first checkbox/radio per name (the checked one if any, else the first); select → first option; None values skipped
  pub(crate) fn form_action(form: &FormSpec, page: &Url, origin: &Url, base: Option<&str>) -> Option<Url>   // action resolved against <base href> or the page; None (not submittable) unless method is GET or POST and the action is same-origin
  ```
  Values: Text/Textarea/Other → `aitm-<marker>`; Email → `aitm-<marker>@example.invalid`;
  Number/Tel → `1`; Url → `origin`; Password → `Aitm-<marker>!1`; Date → `2026-01-01`;
  Checkbox/Radio → the field's `value`; Select → first option (None when no options); Hidden →
  the existing value (None when absent); File → None as a pair (the client engine adds an inert
  file part instead when the form is multipart, call A18 as amended).
- **Test:** `value_pins` with marker `7f3a`, origin `http://t:8080`: Text `q` → `Some("aitm-7f3a")`;
  Email → `Some("aitm-7f3a@example.invalid")`; Password → `Some("Aitm-7f3a!1")`; Number → `Some("1")`;
  Url → `Some("http://t:8080")`; Select `["a","b"]` → `Some("a")`; Hidden value `"1"` → `Some("1")`;
  Hidden without value → `None`; File → `None`.
  `form_pairs_pins`: the Task 4 form (`q` text, `s` select, `h` hidden `1`, radios `r` x(checked)/y)
  → `[("q","aitm-7f3a"), ("s","a"), ("h","1"), ("r","x")]`. `form_action_rules`: `action
  Some("/search")`, GET, page `http://t:8080/` → `Some("http://t:8080/search")`; `action
  Some("https://evil.test/x")` → `None`; method `PUT` → `None`; `action None` → the page URL;
  `base Some("/app/")` with action `"go"` → `http://t:8080/app/go`.
- **Done when:** tests pass; full gate passes.

### Task 15: `crawl/seeds.rs`: `robots.txt` and `sitemap.xml` seeds

- **Satisfies:** AC T2-1 (crawler coverage), D8.1 "both honour `robots` and `sitemap` options".
- **Depends on:** Tasks 3, 9.
- **Files:** `crates/aitm-scan-http/src/crawl/seeds.rs`.
- **Change:**
  ```
  pub(crate) struct RobotsSeeds { pub paths: Vec<String>, pub sitemaps: Vec<String> }
  pub(crate) fn parse_robots(text: &str) -> RobotsSeeds           // Allow:/Disallow: values (case-insensitive keys), trimmed, cut at the first '*' or '$', non-empty and not exactly "/"; Sitemap: URLs
  pub(crate) fn parse_sitemap(xml: &str) -> Vec<String>           // every <loc>…</loc> text trimmed (urlset and sitemapindex), cap MAX_SITEMAP_URLS; a plain scan, not xml::scan
  pub(crate) async fn fetch_seeds(client: &dyn ProxyClient, origin: &Url, opts: &CrawlOptions, session: Option<&SessionMaterial>, send: SendOptions, deadline: Instant) -> Vec<Url>
  ```
  `fetch_seeds`: when `opts.robots` GET `/robots.txt`; when `opts.sitemap` GET `/sitemap.xml` and
  up to `MAX_SITEMAPS_FOLLOWED` robots-listed same-origin sitemaps; each GET has the session
  applied, goes through `send_opts(send.clone())`, is bounded by `min(deadline - now, MAX_AWAIT)`,
  and reads at most `MAX_BODY_PARSE_BYTES`; results resolved against `origin`, same-origin only,
  deduped, capped at `MAX_SEED_URLS`. Failures are logged at debug through `safe_url` and skipped.
- **Test:** `robots_pins`: `User-agent: *\nDisallow: /admin/\nAllow: /public\ndisallow: /tmp/*\nSitemap: http://t/sm.xml\nDisallow: /\nDisallow:\n`
  → `paths == ["/admin/", "/public", "/tmp/"]`, `sitemaps == ["http://t/sm.xml"]`.
  `sitemap_pins`: `<urlset><url><loc>http://t/a</loc></url><url><loc> http://t/b </loc></url></urlset>`
  → `["http://t/a", "http://t/b"]`; a `sitemapindex` with two `<loc>` → both.
  `fetch_seeds_requests`: ScriptedClient serving the robots text above at `/robots.txt` **with its
  `Sitemap:` line pointing at `http://t:8080/sm.xml`** (corrected 2026-11-01: the `robots_pins` text
  names port 80, which is not same-origin with the test origin; following a cross-origin sitemap
  would be a scope escape, so the served fixture changes, not the rule) and a urlset at
  `/sitemap.xml` and `/sm.xml`; `robots: true, sitemap: true` → `sent_paths() ==
  ["/robots.txt", "/sitemap.xml", "/sm.xml"]`, every `SendOptions.marks == ["scan:scan-1a2b3c4d", "crawl"]`,
  result contains `http://t:8080/admin/`, `http://t:8080/public`, `http://t:8080/a`; with
  `robots: false, sitemap: false` → `sent.len() == 0`; a session cookie `sid=S3` appears on every
  request's `Cookie`.
- **Done when:** tests pass; full gate passes.

### Task 16: `crawl/frontier.rs`: `Crawler` trait, frontier, limits, fingerprint

- **Satisfies:** AC T2-1 (crawler scope and termination), D8.1 "fingerprint pages by normalised
  DOM/body hash", `strategy` limits, research 20 §3.10 (2) limits kept as named constants.
- **Depends on:** Tasks 1, 3.
- **Files:** `crates/aitm-scan-http/src/crawl/frontier.rs`.
- **Change:**
  ```
  pub(crate) struct Limits { pub max_depth: u32, pub max_pages: u32, pub clicks_per_page: u32, pub forms_per_page: u32, pub follow_resources: bool, pub submit_forms: bool, pub click_handlers: bool }
  pub(crate) fn limits_for(opts: &CrawlOptions) -> Limits
  pub(crate) struct Frontier { queue: VecDeque<(Url, u32)>, visited: HashSet<String>, fingerprints: HashSet<u64>, pub attempts: u32, pub depth_hit: bool, pub dropped_full: u32 }
  impl Frontier { pub fn new() -> Self; pub fn push(&mut self, url: Url, depth: u32, limits: &Limits) -> bool; pub fn pop(&mut self) -> Option<(Url, u32)>; pub fn mark_visited(&mut self, url: &Url) -> bool; pub fn is_visited(&self, url: &Url) -> bool; pub fn note_fingerprint(&mut self, fp: u64) -> bool; pub fn len(&self) -> usize }
  pub(crate) fn fingerprint(body: &str) -> u64        // drop <script>/<style>/<!-- --> bodies, collapse whitespace runs to one space, replace every digit run with "0", lowercase; fnv1a64
  pub(crate) struct CrawlReport { pub pages: u32, pub attempts: u32, pub forms_submitted: u32, pub clicks: u32, pub flows: Vec<HttpFlow>, pub stopped_reason: Option<&'static str>, pub depth_reached: u32 }
  pub(crate) trait Crawler: Send + Sync { fn crawl<'a>(&'a self, origin: &'a Url, seeds: Vec<Url>, job: &'a dyn JobCtx, limits: &'a Limits) -> BoxFuture<'a, anyhow::Result<CrawlReport>>; }
  pub(crate) fn remaining(job: &dyn JobCtx) -> Option<Duration>     // deadline - now bounded by MAX_AWAIT; None when past
  ```
  `limits_for`: `Fast` → `max_depth = min(opts.max_depth, 1)`, clicks 0, forms 0,
  `follow_resources false`; `Normal` → profile depth/pages, clicks `CLICKS_PER_PAGE_NORMAL`,
  forms `FORMS_PER_PAGE_NORMAL`; `Thorough` → clicks/forms `*_THOROUGH`, `follow_resources true`;
  `submit_forms`/`click_handlers` from the options (and forced false by `Fast`). `push` refuses
  (returns false) a visited URL, a depth above `max_depth` (sets `depth_hit`), or a full frontier
  (`MAX_FRONTIER`, counts `dropped_full`); it marks the URL visited on acceptance. Stop reasons
  used by both engines: `"max_pages"`, `"max_depth"`, `"time"`, `"budget"`, `"cancelled"`,
  `"left_scope"`, `"navigation_failed"`, `"guard_refused"`, `"no_browser"`.
- **Test:** `limits_pins`: `CrawlOptions::default()` → `Limits { max_depth: 3, max_pages: 200,
  clicks_per_page: 8, forms_per_page: 8, follow_resources: false, submit_forms: true, click_handlers: true }`;
  `strategy: Fast` → `max_depth 1`, clicks 0, forms 0, `submit_forms false`; `Thorough` → 32/32,
  `follow_resources true`. `frontier_rules`: push `http://t/a` depth 0 → true; again → false;
  depth 4 with max 3 → false and `depth_hit`; 4096 distinct URLs accepted, the 4097th refused
  with `dropped_full == 1`; `pop` is FIFO. `fingerprint_pins`:
  `fingerprint("<p>Time 12:30</p>") == fingerprint("<p>time  09:15</p>")`;
  `fingerprint("<p>a</p><script>x=1</script>") == fingerprint("<p>a</p><script>y=2</script>")`;
  `fingerprint("<p>a</p>") != fingerprint("<p>b</p>")`.
- **Done when:** tests pass; full gate passes.

### Task 17: `crawl/client.rs`: the client crawler engine

- **Satisfies:** AC T2-1 (`use_browser: never` reaches every link/form route), AC T2-4 (session
  on crawler requests), D5 "client-crawler GETs through `send_opts` with the `crawl` mark", D8.1
  client engine.
- **Depends on:** Tasks 2, 3, 4, 5, 9, 13, 14, 15, 16.
- **Files:** `crates/aitm-scan-http/src/crawl/client.rs`.
- **Change:** `pub(crate) struct ClientCrawler;` implementing `Crawler`. Loop over the frontier
  (seeded with `seeds`, the first being the origin root): stop on `job.cancelled()` (`"cancelled"`),
  `remaining(job) == None` (`"time"`), `frontier.attempts >= limits.max_pages` (`"max_pages"`);
  `attempts += 1`; skip a URL whose `guard_authority` is not `guard.in_scope` or not same-origin;
  build `GET` with `Accept: text/html,application/xhtml+xml,*/*;q=0.8` and
  `User-Agent: aitm-scan`; `apply_session`; `send_opts(req, SendOptions { record: Always,
  marks: [job mark, "crawl"], version: profile.http.version.into() })` (call A2) bounded by
  `remaining`; `Err` → count a failure and continue (the engine's `JobClient` already charges the
  error ladder); `3xx` with `Location` → `resolve` and `push(depth + 1)`; an HTML response (by
  `content-type`) with a body ≤ `MAX_DOM_BYTES` → `fingerprint`; if new → `extract`, push every
  resolved same-origin in-scope link at `depth + 1`, resources too when `follow_resources`; forms
  (when `limits.submit_forms`, first `forms_per_page` with a `form_action`) → `form_pairs_for`,
  then a `GET` with the pairs as the query or a `POST` `application/x-www-form-urlencoded` body,
  sent the same way, `forms_submitted += 1`, response processed like a page at `depth + 1`. Every
  returned `HttpFlow` goes into `report.flows` with the response body truncated to
  `MAX_HELD_CRAWL_BODY`; `pages` counts `2xx`/`3xx` responses. `stopped_reason` falls back to
  `"max_depth"` when `depth_hit`, `"navigation_failed"` when no page loaded and failures > 0.
- **Test:** (FakeJob with `use_browser: Never`; `site()` pages: `/` → links `/a`, `/b#top`,
  `/ext` as `https://evil.test/x`, and the Task 4 form (`action /search`, GET, field `q`); `/a` →
  link `/c?x=1` and `/account/1`, `/account/2`; `/c` → `302:/d`; `/d`, `/b`, `/account/1`,
  `/account/2`, `/search` → plain pages)
  `client_crawl_reaches_links_and_forms`: `sent_paths()` as a set equals
  `{"/", "/a", "/b", "/c?x=1", "/d", "/account/1", "/account/2", "/search?q=aitm-aitm7f3a"}`
  (no `evil.test` request), `report.pages == 8`, `forms_submitted == 1`, every `SendOptions` has
  `record == Always` and `marks == ["scan:scan-1a2b3c4d", "crawl"]`, `report.flows.len() == 8`,
  `store.count() == 8` (ScriptedClient recording into the job store), `stopped_reason == None`.
  `max_pages_is_attempts`: `max_pages: 2` → `attempts == 2`, `stopped_reason == Some("max_pages")`.
  `fast_limits_stop_at_depth_one`: `strategy: Fast` → `/c?x=1` never requested,
  `forms_submitted == 0`, `stopped_reason == Some("max_depth")`.
  `cancelled_stops`: `cancelled` set before the crawl → `sent.len() == 0`,
  `stopped_reason == Some("cancelled")`. `session_on_every_request`: material `[("sid","S3")]` →
  every sent request's `Cookie` contains `sid=S3`. `volatile_pages_are_not_reextracted`: `/p1` and
  `/p2` with the same text differing only in digits, both linking `/only-from-p2` from `/p2` →
  `/only-from-p2` is **not** requested. `redirect_off_origin_not_followed`: `/c` → `302:https://evil.test/`
  → no request to `evil.test`.
- **Done when:** tests pass; Task 2's `log_sites_route_urls_through_safe_url` still passes; full
  gate passes.

### Task 18: `crawl/browser.rs`: the browser crawler engine, session priming, store diff

- **Satisfies:** AC T2-1 (real obscura reaches a form submission and a click-only link), AC T2-4
  (browser cookies), D5 "crawl flows are different" (store diff + marks), D8.1 browser engine,
  orchestrator decisions 4, 5, 7.
- **Depends on:** Tasks 2, 3, 4, 9, 13, 14, 16.
- **Files:** `crates/aitm-scan-http/src/crawl/browser.rs`.
- **Change:**
  ```
  pub(crate) struct BrowserCrawler;                       // implements Crawler; Err("scan: no browser") when job.browser() is None
  pub(crate) struct StoreDiff { before: HashSet<FlowId> }
  impl StoreDiff { pub fn snapshot(store: &dyn FlowStore) -> Self; pub fn mark_new(&self, store: &dyn FlowStore, origin: &Url, marks: &[String]) -> Vec<HttpFlow> }   // HTTP flows added since the snapshot whose request is to `origin`: store.update sets metadata.marks ∪ marks; returns the updated flows
  pub(crate) async fn prime_session(browser: &dyn BrowserDriver, origin: &Url, material: &SessionMaterial, job: &dyn JobCtx) -> anyhow::Result<Vec<String>>   // charge(1), navigate(origin root), eval each browser_cookie_statement, eval "document.cookie", return browser_partial names (caller logs at warn: names only)
  pub(crate) const CLICKABLES_JS: &str   // one expression, marked `/*aitm-clickables*/`, returning up to MAX_CLICKABLES_LISTED objects {selector, text} for `a[href^="javascript:"], [onclick], button:not([type=submit]), [role=button], [data-href]`, each selector a unique tag:nth-child chain from <body>; no network, no mutation
  pub(crate) fn tag_form_js(index: usize) -> String       // sets data-aitm-form="<index>" on document.forms[index]
  pub(crate) fn submit_form_js(index: usize) -> String    // document.forms[index].requestSubmit ? requestSubmit() : submit()
  pub(crate) fn field_selector(form_index: usize, name: &str) -> String   // form[data-aitm-form="i"] [name="<escaped>"]
  ```
  Per page: cancel/time/`max_pages` checks as in Task 17; `attempts += 1`; `permit =
  guard.check_active(authority)` (an `Err` on the first page is returned; later ones count
  `guard_refused` and skip); `if !job.charge(1) { stop "budget" }`; `StoreDiff::snapshot`;
  `navigate(url)` bounded by `remaining` (failure → `guard.record_error`, continue); drop the
  permit after `get_dom`; `final_url` parsed with `parse_absolute`: off-origin or out-of-scope →
  stop `"left_scope"`; `pages += 1`; `get_dom` truncated to `MAX_DOM_BYTES`; `mark_new` with
  `[job mark, "crawl"]` → extend `report.flows`; `fingerprint` (skip extraction when seen); extract
  and push links (and resources when `follow_resources`). Then forms (when `limits.submit_forms`,
  first `forms_per_page` with a `form_action`): `eval(tag_form_js(i))`, for each field with a value
  → `type_text(field_selector, value)` for text-like kinds, `eval` setting `value`/`checked` for
  select/checkbox/radio; `if !job.charge(1) { stop "budget" }`; snapshot; `eval(submit_form_js(i))`;
  settle (poll `location.href` + `document.readyState` every `SETTLE_POLL_MS` up to
  `SETTLE_MAX_MS`); `forms_submitted += 1`; `get_dom` → `mark_new`, extract, push links; record
  the landing URL as visited. Then clicks (when `limits.click_handlers`): `eval(CLICKABLES_JS)` →
  up to `clicks_per_page`; before each click: if the current URL is no longer the page (a prior
  submit or click navigated away), `charge(1)` + `navigate(page)` back (call A3); `charge(1)`;
  snapshot; `click(ClickTarget::Selector(sel))` bounded; settle; `clicks += 1`; `mark_new`;
  `location.href` → if changed and same-origin/in-scope: record as a visited page, extract its DOM;
  if off-origin: stop `"left_scope"`; else if the DOM fingerprint changed: extract links from the
  new DOM. Processing order per page is links, forms, clicks (fixed so the charge counts below are
  deterministic). `report.flows` are the marked flows read back from the store.
- **Test:** (FakeJob with a FakeBrowser whose pages carry `captures` so each navigate/click/submit
  inserts a captured flow to the origin; site: `/` has links `/a`, the Task 4 form to `/search`
  (GET, `q`), and a clickable `button[onclick]` (selector `body > button:nth-child(3)`) landing on
  `/clicked`; `/a`, `/clicked`, `/search?q=aitm-aitm7f3a` plain)
  `browser_crawl_pins`: browser log (filtered to `navigate`/`click`/`type_text`) equals
  `["navigate http://t:8080/", "type_text form[data-aitm-form=\"0\"] [name=\"q\"] aitm-aitm7f3a", "navigate http://t:8080/", "click body > button:nth-child(3)", "navigate http://t:8080/a"]`
  (the second `navigate /` is the return before the click because the submit navigated away);
  `job.charges == 5`; `report.pages == 4`; `forms_submitted == 1`; `clicks == 1`; every flow in
  the store has marks containing both `scan:scan-1a2b3c4d` and `crawl`; a flow inserted into the
  store **before** the crawl keeps empty marks; `report.flows.len() == store.count() - 1`.
  `fast_limits_skip_forms_and_clicks`: `strategy: Fast` → log is
  `["navigate http://t:8080/", "navigate http://t:8080/a"]`, `charges == 2`.
  `budget_stops_crawl`: `budget: 1` → `charges == 1`, `stopped_reason == Some("budget")`,
  `attempts == 2`. `left_scope_stops`: `/a`'s `final_url = "https://evil.test/"` →
  `stopped_reason == Some("left_scope")`, no further navigate. `no_browser_errors`:
  `browser: None` → `Err` containing `no browser`. `prime_session_pins`: material
  `[("sid","S3"),("hs","H")]`, FakeBrowser read-back returning only `sid=S3` → returns `["hs"]`,
  eval log contains `document.cookie = "sid=S3; path=/"`, and `charges == 1`.
  `store_diff_marks_only_new_origin_flows`: a pre-existing flow and a new flow to another host stay
  unmarked; the new origin flow gets both marks.
- **Done when:** tests pass; Task 2's log-site test still passes; full gate passes.

### Task 19: `host.rs`: `HttpProbeHost` and the per-job `SessionMonitors`

- **Satisfies:** AC T2-3 (mutable header/cookie probes reach the target), AC T2-4 (session on every
  probe), AC T2-5 (session-lost token on every later probe), AC T2-6 (bounded, redacted), D8.1
  "The lane's `ProbeHost`", D5 record policy, orchestrator decisions 4, 5, 9.
- **Depends on:** Tasks 2, 3, 9, 11, 13.
- **Files:** `crates/aitm-scan-http/src/host.rs`.
- **Change:**
  ```
  pub(crate) struct HttpProbeHost { source: HttpRequest, point: InsertionPoint, origin: Url, job: Arc<dyn JobCtx>, profile: ScanProfile, monitor: Arc<SessionMonitor>, baseline: tokio::sync::OnceCell<ProbeResponse>, held: Mutex<VecDeque<Flow>> }
  impl HttpProbeHost {
    pub fn new(point: &InsertionPoint, job: Arc<dyn JobCtx>, monitor: Arc<SessionMonitor>) -> anyhow::Result<Self>;   // point.flow None → Err "scan: point <id> has no source flow"; store.get → not Http or absent → Err "scan: source flow <id> is gone"; apply_session(source) once here; origin = request_url(source)
    fn send_options(&self) -> SendOptions;      // record: IssuesOnly → Never, All → Always; marks [job mark]; version profile.http.version.into()
    async fn send_bounded(&self, req: HttpRequest, what: &str) -> anyhow::Result<ProbeResponse>;   // 1) if monitor.should_stop() → Err(lost_error(what)); 2) if monitor.tick() → monitor.check(client, send_options, bound).await; if it reports Lost and should_stop → Err(lost_error) (Continue → go on); 3) bound = min(deadline() - now, MAX_AWAIT); 4) measure elapsed_ms around send_opts; 5) push Flow::Http(flow) into held (pop_front past MAX_HELD_FLOWS); 6) ProbeResponse { status, headers, body truncated to MAX_MATCH_BODY, elapsed_ms, flow: Some(FlowRef(id)) when the store has it or when record == Always, else None, ws_frames None, l4 None }
  }
  impl ProbeHost for HttpProbeHost {
    baseline → OnceCell::get_or_try_init(send_bounded(source.clone(), "baseline")); cached clone
    probe(payload) → build_request(&source, &point, payload)? then send_bounded(.., "probe")
    probe_raw(raw) → parse raw.url; same scheme+authority as origin else Err("scan: probe_raw: {safe_url} is not on the point's origin"); build HttpRequest (method, path+query, headers via try_set, body), apply_session, send_bounded(.., "probe_raw")
    marker → job.marker(); budget_left → job.budget_left(); deadline → min(job.deadline(), now + profile.budget.check_timeout_s); profile → &self.profile; cancelled → job.cancelled(); held_flows → held.clone() as Vec
  }
  pub(crate) struct SessionMonitors { inner: Mutex<(VecDeque<String>, HashMap<String, Arc<SessionMonitor>>)> }
  impl SessionMonitors { pub fn new() -> Self; pub fn for_job(&self, job: &dyn JobCtx, origin: &Url) -> Arc<SessionMonitor>; pub fn len(&self) -> usize }   // absent → build: session None or mode None → unarmed(on_lost); else pick_canary(store, origin, material, from_flow) → SessionMonitor::new(canary, on_lost, CANARY_EVERY); insert, evict the oldest beyond MAX_SESSION_MONITORS
  ```
- **Test:** (FakeJob + ScriptedClient; a captured `GET http://t:8080/search?q=hello&x=1` with
  `Cookie: theme=dark` in the store; session material `[("sid","S3")]`; point `query` `q`)
  `baseline_is_cached`: two `baseline()` → `sent.len() == 1`, the sent request has
  `Cookie == "theme=dark; sid=S3"`, `marks == ["scan:scan-1a2b3c4d"]`, `record == Never`.
  `probe_mutates_only_the_point`: payload `<s>` → sent path `"/search?q=%3Cs%3E&x=1"`,
  `Cookie` unchanged, `response.status == Some(200)`, `response.flow == None` under `IssuesOnly`;
  with `record_probes: All` → `record == Always` and `response.flow.is_some()`.
  `held_flows_bounded`: 20 probes → `held_flows().len() == 16` and the last held flow's request
  path matches the 20th payload. `probe_raw_same_origin_only`: `RawProbe { url: "http://evil.test/?token=abc" }`
  → `Err` whose message contains `not on the point's origin` and does **not** contain `abc`;
  `sent.len() == 0`; `RawProbe { url: "http://t:8080/raw", method: "HEAD" }` → sent with method
  `HEAD` and `Cookie` containing `sid=S3`. `elapsed_is_measured`: `ScriptedClient.delay = 50 ms`
  → `elapsed_ms >= 50`. `body_is_bounded`: a 2 MiB body → `response.body.len() == MAX_MATCH_BODY`.
  `session_lost_stops_every_probe`: monitor `every = 2`, canary 200 then 302, `on_lost: Stop`:
  probe 1 `Ok`; probe 2 `Err` starting with `scan: session_lost: `; `baseline()` and `probe_raw`
  afterwards `Err` with the same prefix; `sent.len() == 2` (one probe, one canary). With
  `Continue`: three probes all `Ok`, `sent.len() == 4`. `source_gone_errors`: empty store → `Err`
  containing `gone`; `point.flow = None` → `Err` containing `no source flow`.
  `deadline_is_the_min`: FakeJob deadline in 10 s, `check_timeout_s 60` → `deadline() <= now + 10 s`;
  deadline in 120 s → `deadline() <= now + 60 s`. `monitors_bounded_and_shared`: 17 distinct job
  ids → `len() == 16`; two `for_job` calls for one job return `Arc::ptr_eq` monitors; a FakeJob with
  `session: None` → an unarmed monitor (`tick()` never true).
- **Done when:** tests pass; Task 2's log-site test passes; full gate passes.

### Task 20: `lane.rs`: `HttpLane`, discover orchestration, flip `lane()` to `Some`

- **Satisfies:** AC T2-1, T2-2, T2-4 at the lane level (unit-level only; proof is Task 21), D1
  (the binary prefers a lane crate's lane once `lane()` is `Some`), D8.1, orchestrator decisions
  6, 10, 11.
- **Depends on:** Tasks 10, 12, 13, 15, 16, 17, 18, 19.
- **Files:** `crates/aitm-scan-http/src/lane.rs` (fill), `crates/aitm-scan-http/src/lib.rs`
  (modify: `lane()` body and its test only), `crates/aitm/src/wire.rs` (modify: the one test
  literal in `skeleton_lane_slots_are_empty_today`, renamed `lane_slots_hold_the_http_lane`:
  `collect_lanes(None).len()` and `collect_lanes(Some(&shared)).len()` become `1`;
  `collect_native_checks().len()` stays as pinned; T1a call A23 allows exactly this edit).
- **Change:**
  ```
  pub(crate) struct HttpLane { monitors: SessionMonitors }
  impl HttpLane { pub fn new() -> Self }   impl Default for HttpLane
  impl Lane for HttpLane {
    fn lane(&self) -> LaneKind { LaneKind::Http }
    fn discover(target, job) → for each origin string in target.origins: parse_absolute (invalid → warn through safe_url, skip); guard.in_scope(guard_authority) else skip (the engine refused earlier; belt and braces);
      (i) stored: store.query(&FlowQuery { kind: Some(FlowKind::Http), is_replay: Some(false), ..Default::default() }) → get → keep flows whose request_url is same_origin and not already crawl-marked by another job of this run; cap MAX_SEED_URLS of their URLs as extra seeds (GET only);
      (ii) crawl: skip when profile.crawl.max_pages == 0; engine = browser when job.browser().is_some() && use_browser != Never, else client when use_browser != Always, else skip with warn "use_browser: always but no browser"; limits = limits_for(&profile.crawl); seeds = [origin root] + fetch_seeds(..) + stored GET URLs; for the browser engine with session material: prime_session first and warn with the partial names; run crawler.crawl(..); on Err → warn and continue with what the store has;
      (iii) enumerate_v2 over every stored flow and every report flow with EnumerateOptions::from_profile(profile, &CompiledIgnore::compile(&profile.audit.ignore)?, session.as_deref());
      (iv)/(v) SiteMapBuilder::add(flow id, request, enumerated, is_authenticated(req, session)); totals of overflow/ignored/kind_filtered logged once per origin at info with the job id;
      return builder.finish() (merged across origins). Every step polls job.cancelled() and stops early with what it has.
    fn probe_host_for(point, job) → point.lane == Http else Err("scan: point <id> is not an http point"); origin = parse_absolute(point.url) else Err; Ok(Box::new(HttpProbeHost::new(point, job.clone(), self.monitors.for_job(job.as_ref(), &origin))?))
    fn checks(&self) → Vec::new()
  }
  ```
  Also in this task: collapse `mutate::kind_token` (derived from the serde token) and `points::kind_token`
  into one callable (orchestrator note 2026-11-01), and sweep every placeholder `#![allow(dead_code)]`.
  `lib.rs`: `pub fn lane() -> Option<Arc<dyn Lane>> { Some(Arc::new(lane::HttpLane::new())) }`;
  rename the test to `lane_slot_is_populated` asserting `is_some()`, `.lane() == LaneKind::Http`,
  `.checks().is_empty()`. Remove every placeholder `#![allow(dead_code)]`.
- **Test:** (FakeJob; origin `http://t:8080`)
  `discover_seeds_from_captured_flows_without_crawl`: `crawl.max_pages 0`; store holds captured
  `GET /search?q=1`, `GET /account/7` (`Cookie: sid=S3`), one flow to `http://other:9/x`, one
  replay to the origin → `nodes.len() == 2`, templates `{"/search", "/account/{id}"}`, the
  `/account/{id}` node has `auth == true`, `client.sent.len() == 0`, every point's `flow` id is in
  the store. `discover_client_crawl_builds_sitemap`: the Task 17 site, `use_browser: Never`,
  `robots/sitemap false` → node templates include `/account/{id}` with `flows.len() == 2` and
  `/search` with `params` containing `(Query, "q")`; every point has `site_node.is_some()`;
  `(Query,"q")` points have `frequency == 1`; `store.count() == 8`.
  `discover_prefers_browser_when_available`: FakeBrowser present, `use_browser: Auto`,
  `robots/sitemap true` → browser log contains `navigate http://t:8080/` and
  `client.sent_paths() == ["/robots.txt", "/sitemap.xml"]`. `always_without_browser_skips_crawl`:
  `use_browser: Always`, no browser → `client.sent.len() == 0`, nodes from the store only.
  `kinds_and_ignore_apply`: `audit.kinds = [Query]` → every point is `Query`.
  `session_reaches_crawl_and_browser`: material `[("sid","S3")]` → every client request's `Cookie`
  contains `sid=S3`; with the FakeBrowser, its eval log contains `document.cookie = "sid=S3; path=/"`.
  `invalid_origin_is_skipped_not_fatal`: `origins = ["nope", "http://t:8080"]` → `Ok` with the
  second origin's nodes. `cancelled_returns_early`: `cancelled` set → `Ok` with `nodes.is_empty()`
  and `client.sent.len() == 0`. `probe_host_for_rejects_foreign_lane`: a `LaneKind::Ws` point →
  `Err` containing `not an http point`. `lane_slot_is_populated` (in `lib.rs`).
- **Done when:** tests pass; the `wire.rs` pin is red before the flip-and-re-pin commit and
  green after it (quote both runs of `cargo test -p aitm --offline --lib wire`); the full workspace
  gate is green.

### Task 21: Tester whole-branch run and live proof (T2-1..T2-6)

- **Satisfies:** AC T2-1, T2-2, T2-3, T2-4, T2-5, T2-6 (the only acceptance evidence), spec
  Verification.
- **Depends on:** Task 20.
- **Files:** none in the repo. A proof script lives **outside** the repo at
  `/Users/matt/Library/Application Support/Claude-3p/side-session-notes/local_64454d84-e818-4030-b0ab-db14000cd754/t2-proof/`
  only when T10's cells are not yet available (below).
- **Change / steps** (Terminal panel for everything that binds a port or runs obscura):
  1. Tester whole-branch: every AC maps to a test (unit for the inner loop, the cell/script for
     proof); strengthen weak tests; run the full gate from the worktree root and quote the final
     `test result:` lines and `echo $?` (gate on the exit status, never a grep).
  2. Build: `cargo build -p aitm -p aitm-testtarget`. Fetch obscura if absent
     (`scripts/fetch-obscura-dev.sh`, or `AITM_OBSCURA_BIN`).
  3. **Preferred proof**: a throwaway local branch `proof/t2-live` = this branch + `origin/<T10
     seeds branch>` + `origin/<T1b branch>` if not yet on `main` (never pushed, never merged into
     the PR), then `AITM_OBSCURA=1 python3 tests/e2e/run.py scan --jobs 1` and quote each
     `test_t2_*.py` PASS line and the runner exit code. Observers per AC:
     - T2-1 `test_t2_crawl.py`: target request log shows every seeded route incl. the form route
       and the click-only route; `scan.sitemap` node with `path_template == "/account/{id}"`;
       second run with `use_browser: never` reaches every link/form route.
     - T2-2 `test_t2_points.py`: `scan.sitemap` points include kinds `json_value` (path
       `profile.address.city`), `xml_value`, `multipart_value`, `header`, `cookie`,
       `path_segment` non-numeric, `path_filename`; every `cookie` point's `example == "<redacted>"`.
     - T2-3 `test_t2_mutable_points.py`: issues with `location.kind == "header"` and `"cookie"`
       on V, none on P (detection by T3's or the interim lane's reflected check; T2 guarantees the
       mutation reached the target: the request log shows the payload in the header/cookie).
     - T2-4 `test_t2_session_reuse.py`: login through the proxy, then `scan.start`; request log
       shows `/account` requests carrying a cookie; the authenticated-only issue is present on V;
       with `session.mode: none` the log shows no cookie on scanner requests and no such issue.
     - T2-5 `test_t2_session_lost.py`: `/logout-after` armed; `scan.status` ends with
       `stopped_reason == "session_lost"`, `session.lost == true`; the request log shows the canary
       `GET`/`HEAD` every 25 probes and no probes after the loss.
     - T2-6 `test_t2_no_secret_leak.py`: grep over the harness bus transcript, push lines, issue
       and PoC files for the `sid` value and the `Authorization` value → zero hits; `scan.sitemap`
       and `scan.session.preview` results contain names only.
  4. **Fallback proof** when T10's cells or seeds do not exist at proof time: a Python script in
     the notes folder above using `tests/e2e/aitm_e2e` (`Aitm.server(CoreConfig(scope_entries=[target.authority], findings_dir=...))`,
     `BusClient.operator(core)`, `Target("vulnerable")`/`Target("patched")`), driving the real bus
     with `scan.map`/`scan.start` against the routes the current test target has (`/search?q=`,
     `/comments` form, `/account/{n}`, `/profile/{n}`, `/redirect?next=`), polling `scan.status` to a
     terminal state, and asserting every AC the current seeds allow (T2-1 client half and the
     `{id}` template; T2-2 `query`, `body_param`, `header`, `cookie` with `<redacted>`,
     `path_segment` for `/account/1` as `{id}`; T2-6 over the transcript). The PR body then lists
     the ACs still pending T10 **by name** (expected: T2-1 browser half, T2-2 `json_value`/
     `xml_value`/`multipart_value`/`path_filename`, T2-3, T2-4, T2-5) and the exact cell that will
     prove each. Record in this plan's Shipped section which proof applied.
  5. Live-run hygiene: `AITM_OBSCURA=1` for the browser half; cells SKIP 77 loudly without it, and
     a SKIP on a cell this task relies on is a failure of the proof, not a pass; no `pkill -f obscura`;
     redirect logs to `/tmp/claude/`.
- **Test:** the commands above; the proof is their quoted output.
- **Done when:** the gate exits 0 and either every `test_t2_*.py` cell passes, or the fallback
  script passes for the ACs the seeds allow and the pending ACs are listed by name in the Tester's
  report and the PR body.

### Task 22: integration: merge `origin/main`, redaction flip, legacy deletion, `wire.rs` re-pin, gate, PR

- **Satisfies:** spec D12 "Integration-shared files" and row T2 ("its final integration task
  deletes the legacy modules"), Constraints "Sequencing pins (a)" (PR #199 vocabulary), T1a call A23.
- **Depends on:** Task 21.
- **Files:** `crates/aitm-scan-http/src/redact.rs` (two call sites), `crates/aitm-plugin-scanner/src/{crawl.rs,
  discover.rs, inject.rs, checks.rs}` + the interim lane module + their `mod`/`pub use` lines in
  `crates/aitm-plugin-scanner/src/lib.rs` (delete, conditional), `Cargo.lock` (derived).
- **Change / steps** (Terminal for fetch/merge/push; sandbox git for local ops):
  1. `git fetch origin && git merge origin/main` (merge, not rebase; the branch carries the plan
     commit). Expect the five conflict sites the T1b note lists if they recur
     (`side-session-notes/.../t1b-merge-t1a-over-main-conflicts.md`); resolve exactly as there.
  2. **Redaction flip**: if `origin/main` has `aitm_core::redact::scrub_text_wide` and
     `is_secret_key_wide` (PR #199), change the two call sites in `redact.rs` to them; re-run Task 2's
     tests (the `[redacted]` literals hold: the wide scrub uses the same token). Otherwise leave the
     indirection and note it in the PR body as a follow-up.
  3. **Legacy deletion**, only if T1b is on `main`: `grep -rn 'crawl::\|discover::\|inject::\|checks::\|aitm_plugin_scanner::{crawl\|enumerate\|inject\|CheckDefinition' crates/ --include=*.rs`
     and delete `crawl.rs`, `discover.rs`, `inject.rs`, `checks.rs` and the interim lane module
     (named in T1b's plan) plus their `mod`/`pub use` lines **only if nothing outside those files
     references them**. Anything still referenced (expected candidates: `commands.rs`, `reproduce.rs`,
     `passive.rs`) is reported to the coordinator by file and symbol, not refactored. If T1b is not
     on `main`, skip and say so in the PR body.
  3b. **Session-lost hook**: if `aitm_scan_model::JobCtx` on `origin/main` has
     `report_session_lost(&self)`, call it from the lane's loss path (`host.rs`/`session.rs`) and
     add a `FakeJob` assertion that it was called once; otherwise note the pending hook in the PR body.
  4. **`wire.rs` pin check**: Task 20 already re-pinned `lane_slots_hold_the_http_lane` to `1`;
     after the merge confirm the literal survived and `collect_native_checks().len()` is whatever
     `main` pins (T3 may have flipped it).
  5. Contract check, no re-pin expected: `cargo test -p aitm --test frontends` passes with
     `EXPECTED_TOOLS` untouched (T2 adds no verb); `cargo test -p aitm --test bundled_startup` and
     `cargo test -p aitm-plugin-rhai --test bundled_scripts` pass (T2 adds no check). Quote them.
  6. Full gate; quote the final `test result:` lines and `echo $?`.
  7. Real boot proof (Terminal): `cargo build -p aitm -p aitm-testtarget` then
     `python3 tests/e2e/run.py smoke mcp --jobs 2`; quote the PASS lines and exit code. Then
     `cargo tree -p aitm -e normal | grep aitm-scan-http` quoted.
  8. `git push origin claude/competent-rubin-4ae816` (explicit refspec) and open the PR against
     `main` (verify `baseRefName == main`) with: the plan path, the gate output, the Task 21 proof
     output (or the fallback report with the named pending ACs), the stage-6 panel comment
     (security/quality/spec with dispositions), and the attribution line.
- **Test:** the commands above; the proof is their quoted output.
- **Done when:** gate exits 0, `frontends`/`bundled_startup`/`bundled_scripts` pass without
  edits, `run.py smoke mcp` exits 0, the tree shows `aitm-scan-http`, the panel review has no open
  findings, and the PR body carries the panel comment and the live proof.

## File ownership matrix (disjointness check)

| Task | Files |
|---|---|
| 1 | `crates/aitm-scan-http/Cargo.toml`, `src/lib.rs`, `src/limits.rs`, `src/hash.rs`, every placeholder listed in Task 1, `Cargo.lock` (derived) |
| 2 | `src/redact.rs` |
| 3 | `src/url_norm.rs` |
| 4 | `src/crawl/extract.rs` |
| 5 | `src/params.rs` |
| 6 | `src/xml.rs` |
| 7 | `src/multipart.rs` |
| 8 | `src/template.rs` |
| 9 | `src/testutil.rs` |
| 10 | `src/points.rs` |
| 11 | `src/mutate.rs` |
| 12 | `src/sitemap.rs` |
| 13 | `src/session.rs` |
| 14 | `src/crawl/values.rs` |
| 15 | `src/crawl/seeds.rs` |
| 16 | `src/crawl/frontier.rs` |
| 17 | `src/crawl/client.rs` |
| 18 | `src/crawl/browser.rs` |
| 19 | `src/host.rs` |
| 20 | `src/lane.rs`, `src/lib.rs` (`lane()` body + its test; placeholder `allow` removals), `crates/aitm/src/wire.rs` (one test literal, T1a call A23) |
| 21 | none in the repo (proof script outside the repo) |
| 22 | `src/redact.rs` (two call sites), `crates/aitm-plugin-scanner/src/{crawl.rs, discover.rs, inject.rs, checks.rs, <interim lane>, lib.rs}` (deletion only, conditional), `Cargo.lock` |

All paths under `src/` are `crates/aitm-scan-http/src/`. Within a wave no two tasks share a file.
`lib.rs` is edited by Task 1 (wave 0) and Task 20 (wave 4), sequentially. `crates/aitm/src/wire.rs`
is touched by Task 20 alone (the one literal), so every commit on the branch keeps the gate green.

## Cross-track seams (verified by Task 22 against what is on `main`)

- **S1 session-lost token.** `session::SESSION_LOST_PREFIX = "scan: session_lost: "` is what
  every `probe`/`baseline`/`probe_raw` error starts with after a canary loss under `on_lost: stop`.
  T1b's engine must map an `Err` with that prefix to `stopped_reason: session_lost`,
  `session.lost: true`. The T2 session already left this in
  `side-session-notes/.../t2-http-lane-seed-needs.md` ("Open coordination point"); Task 22 greps
  T1b's engine for the literal and reports a mismatch to the coordinator rather than changing it.
  Coordinator decision 2026-10-31: the lane drives the canary exactly so; T1b additionally adds a
  default-bodied `JobCtx::report_session_lost(&self)` and maps either signal to
  `stopped_reason: session_lost` + `session.lost: true`. Task 22 step 3b: once `origin/main`'s
  `aitm-scan-model` has that method, `SessionMonitor::check` (via `host.rs`) calls
  `job.report_session_lost()` on loss, keeping the `Err` token regardless; absent the method, the
  token alone is the contract.
- **S2 lane preference.** The moment `aitm_scan_http::lane()` returns `Some`, `collect_lanes` hands
  it to the engine, which prefers a lane crate's lane over the interim one (D1). Task 20 flips the
  body last and re-pins the one `wire.rs` literal in the same commit (T1a call A23).
- **S3 seeds.** The shapes the lane's enumerator and crawler expect from T10's seeds are in
  `side-session-notes/.../t2-http-lane-seed-needs.md`; Task 21 reads T10's branch before the proof.
- **S4 redaction vocabulary.** `redact.rs` is the only file calling `aitm_core::redact`; Task 22
  flips to the `_wide` pair when PR #199 is on `main`.
- **S5 record policy of crawl GETs.** Call A2 below records client-crawl GETs and form submissions
  with `RecordPolicy::Always` (marked `scan:<job>`, `crawl`); T1b's AC T1-9 cell counts them as
  job-marked flows, which holds.
- **S6 engine re-recording.** `held_flows()` returns at most 16 in-memory `Flow`s per host; the
  engine re-records them with `issue:<id>` on a `vulnerable` verdict (D5). The lane never inserts
  a probe flow itself.

## Architect's calls in this plan (for the orchestrator/Matt to approve or correct)

- **A1** No `blake3`: the offline registry cache does not hold it (verified 2026-10-31), and page
  fingerprints and node ids need only in-process stability, so `hash::fnv1a64` (FNV-1a, 64-bit,
  hand-rolled, two known-vector tests) serves both. `[workspace.dependencies].blake3` stays for T1b.
- **A2** Client-crawler GETs and form submissions are sent with `RecordPolicy::Always` and marks
  `scan:<job>`, `crawl` regardless of `http.record_probes`. D5 says they are "recorded under the
  same policy with the `crawl` mark"; under `issues_only` that would leave the client crawl's
  points without a stored source flow, so `probe_host_for` (decision 9: the source request is
  fetched from the store) could never probe them and the UI's "node → flows" view (D10) would be
  empty for a client crawl. Crawl traffic is discovery, bounded by `max_pages` (200), not by the
  probe budget; browser-crawl captures land in the store anyway. This is a deviation from one
  D5 phrase; the orchestrator can confirm or ask for the in-memory alternative (a per-job source
  request cache keyed by a synthetic id), which keeps the store clean but loses the flow link.
- **A3** Browser engine order per page is links, forms, clicks; after a submit or click that
  navigated away, the lane navigates back to the page only when another form or click remains on
  it, and that return navigation is charged (`job.charge(1)`) like any navigation (D5).
- **A4** Forms are submitted in the browser with `eval(form.requestSubmit() || form.submit())`
  on `document.forms[i]` (tagged with `data-aitm-form`), not by clicking a submit control: it is
  deterministic across layouts and fires the page's submit handlers. Field values go through
  `type_text` for text-like inputs and an `eval` for select/checkbox/radio.
- **A5** The canary origin for a job is the origin of the first point for which
  `probe_host_for` is called; `SessionMonitors` holds one monitor per job (bounded 16); a job with
  `session.mode: none` or no material gets an unarmed monitor so `tick()` is a no-op.
- **A6** `button[formaction]` is extracted as a plain link (a `GET` to that URL) rather than a
  second form submission; `<base href>` is honoured for resolution.
- **A7** Multipart bodies must use CRLF delimiters (RFC 2046); LF-only bodies are an `Err`, so the
  enumerator produces no multipart points for them (logged at debug). Browsers and HTTP clients
  emit CRLF.
- **A8** `content-type` is excluded from `header` points (alongside the hop-by-hop set): mutating
  it changes which body kinds the same request parses to, and `build_request` rejects a point
  whose request no longer parses to its kind.
- **A9** Point id = `"<flow uuid>:<kind wire token>:<ordinal within the flow>"`; `path_segment`
  points carry the 1-based segment index in `path` so `build_request` replaces the right segment
  even when two segments share a text.
- **A10** `param_name_body` points come from form keys and top-level JSON keys only (nested JSON
  keys are not renamed); `entire_body` is named `body`.
- **A11** `json_value` leaves are strings, numbers, booleans and nulls; empty objects/arrays
  produce no point; a key containing `.`, `[`, `]` or `"` is rendered `["key"]` in the path.
- **A12** Traits are emitted in the enum's order (`Url, Filename, Number, Email, Base64, Json, Id,
  Session`); `Json` is added to every `json_value` point (the scheduler's content-type signal,
  decision 10); `Id` for all-digit, UUID and 24-hex values.
- **A13** Client crawler requests carry `Accept: text/html,application/xhtml+xml,*/*;q=0.8` and
  `User-Agent: aitm-scan`; a `3xx` to another origin is not followed and does not stop the client
  crawl (the browser engine keeps the legacy `left_scope` stop because a navigation that landed
  off-origin means the browser is now there).
- **A14** `stopped_reason` strings shared by both engines: `max_pages`, `max_depth`, `time`,
  `budget`, `cancelled`, `left_scope`, `navigation_failed`, `guard_refused`, `no_browser`; they are
  logged with the job id and are not on the wire (the engine's `JobStatus.crawl` has no reason field).
- **A15** Per-request point overflow, ignored and kind-filtered counts are logged once per origin
  at `info` with the job id; `Discovery` has no skipped field and the engine owns
  `points.skipped.*`.
- **A16** `#![deny(clippy::unwrap_used, clippy::expect_used)]` at the crate root enforces the
  "no unwrap/expect in library paths" rule mechanically; tests opt out per module.
- **A17** The log-site redaction rule is enforced by a `cargo test`-time lint in `redact.rs`
  (`include_str!` over the five network-facing files) in addition to the review item, so a later
  edit that logs a raw URL fails the gate.
- **A18** Form field grouping: for checkbox/radio groups the checked field wins, else the first.
  Amended 2026-11-01 (orchestrator, fix N2 in 171c8689): a form whose `enctype` is
  `multipart/form-data` is submitted by the client engine as multipart (boundary derived from the
  job marker), one part per generated pair plus one inert `text/plain` part named
  `aitm-<marker>.txt` with body `aitm-<marker>` per `<input type="file">`; the upload of that inert
  file is an accepted stimulus (same origin, bounded by `max_pages`). Other forms stay urlencoded.
  The browser engine submits whatever the page does.
- **A19** The stored-flow seeding (decision 6 (i)) also feeds up to 256 captured `GET` URLs into
  the crawl frontier as seeds, so proxied traffic widens the crawl and not only the site map.

## Questions for Matt

None. Every open point was either fixed by the orchestrator's decisions or made as a labelled
call above (A2 is the one call that bends a spec phrase; the orchestrator can rule on it without
Matt).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 8 | Coder (stage 4) | Minor | `traits_for` prose rule tags every email as `Filename`; pinned test says `[Email]` | accepted by the orchestrator (autonomous mandate) 2026-11-01: `Filename` suppressed for email-shaped values; plan amended |
| 10 | Coder (stage 4) | Minor | Prefixed `xmlns:ns` declarations become `xml_attr` points (`XmlSlot` keeps only the local name); default `xmlns` is skipped | accepted (orchestrator, 2026-11-01): one wasted probe slot per prefixed declaration; `XmlSlot.is_namespace` is a follow-up in `xml.rs` |
| 11 | Coder (stage 4) | Minor | Plan literal `content-length "7"` was the original body's length; mutated body is 9 bytes | fixed in the plan (4b81060b); code pins `"9"` |
| 15 | Coder (stage 4) | Minor | Plan fixture named a cross-origin sitemap (`http://t/sm.xml` vs origin `:8080`) the same-origin rule can never follow | fixed in the plan (3d04ea61): served fixture is same-origin; rule unchanged |
| 15 / 18 | Coder (stage 4) | Minor | Shared-index race: commit 2cb26e26 (task 15) carries task 18's final `crawl/browser.rs`; 0dfbe5a5 is task 18's empty provenance commit | accepted (orchestrator): history not rewritten with live writers; discipline rule added to the plan |
| 17 | Coder (stage 4) | Minor | Form submissions counted as `attempts` (bounded by `max_pages`), wider than the plan's "per page" | accepted (orchestrator, 2026-11-01): keeps crawl traffic bounded, which justified call A2 |
| 18 | Coder (stage 4) | Minor | `browser_crawl_pins` log token is `type <sel> = <text>` (the double's spelling); `prime_session_pins` uses a test-local scripted browser for the HttpOnly read-back; `budget_stops_crawl` uses a plain two-page site | accepted (orchestrator): same assertions, counts and order as the plan |
| 19 | Coder (stage 4) | Minor | Sender errors scrubbed before they become `anyhow` messages; `probe_raw` keeps the capture's authority as `Host` | accepted (orchestrator): strengthens T2-6 |
| 20 | Coder (stage 4) | Minor | `SessionMonitor::canary()` unreachable across the track boundary (no `JobCtx` seam) | T1b added `JobCtx::report_session_canary` / `report_session_browser_partial` on its branch (26b2a6a4); wired in Task 22 once on `main` |
| whole branch | Tester (stage 5) | Important | F1: browser-driver and crawler error texts logged verbatim (`crawl/browser.rs`, `lane.rs`) could echo a URL with a token or a `document.cookie` statement | fixed in 8c922891 (`redact::scrub_error`, applied in `bounded()` and the lane's warn sites; call-site tests with tracing capture) |
| whole branch | Tester (stage 5) | Important (ruling) | F2: `InsertionPoint.url` "as captured" carried query credentials into `scan.sitemap` results | fixed in 21243e44: `url` passes through `safe_url` (orchestrator ruling under the anti-goal "no result carries a value"); bounded to 256 chars; origin/path parseable |
| whole branch | Tester (stage 5) | Minor | F3: `xml::scan`/`multipart::parse` error names logged verbatim | fixed in 9dbccbf8 |
| whole branch | Tester (stage 5) | Important | F4: `apply_session` merged only the first `Cookie` header, dropping cookies from a second one | fixed in 23d0042d |
| 20 | Coder (stage 4) | Minor | R1: log-site lint false positive on `use tracing::` import lines | fixed in 139e7834 |
| 20 | Coder (stage 4) | Minor | R2: duplicate boundary parsers; the stricter one was dead | fixed in dc9e6cae (`body_format` delegates to `multipart::boundary_of`) |
| 20 | Coder (stage 4) | Minor | R3: a crawl that failed mid-way lost the captures it had already produced | fixed in 1f753ce1 (store re-queried on `Err`; `Crawlers` injection seam for the test) |
| 21 prep | Tester (stage 5) | Important | N1: `session.mode: none` still replayed a captured flow's own `Cookie`/`Authorization`, so AC T2-4's `none` half could not hold for a seed captured while logged in | fixed in bfe7b789 (strip at host construction and on `probe_raw`); plan amended (d1f5d359, 292e0d9d) |
| 21 prep | Tester (stage 5) | Minor | N2: client crawler posted `multipart/form-data` forms as urlencoded (A18) | fixed in 171c8689 (multipart body with an inert file part) |
| whole branch | Security + Quality (stage 6) | Critical | C1: `extract.rs::refresh_target` slices a byte index inside a multibyte char (`content="0;éé"`), panicking the discovery future | fix round A (pending SHA) |
| whole branch | Security (stage 6) | Important | S-I1: JSON/XML secret detection reads the leaf name, not the path (`session.id`, `auth.value` leak an example and are mutated) | fix round B (pending SHA) |
| whole branch | Security (stage 6) | Important | S-I2: browser form submission trusts the extractor's form index against a re-navigated live page; a JS-mounted third-party form could be posted off-origin before `left_scope` | fix round A: live form attributes verified before fill/submit; raw-text elements in the extractor |
| whole branch | Security (stage 6) | Important | S-I3: browser crawl report holds every produced flow with full bodies (client engine truncates) | fix round A: shared held-copy truncation |
| whole branch | Security (stage 6) | Minor | S-M1 path-segment `%` passthrough of SP/CR/LF; `probe_raw` method unvalidated | fix round B |
| whole branch | Security (stage 6) | Minor | S-M2 path-borne tokens exposed as point name/example | fix round B: placeholder names for id-like segments, redacted examples for uuid/oid/hex/base64 |
| whole branch | Security (stage 6) | Minor | S-M3 derived `Debug` on `JsonLeaf`, `SplitPath`, `Frontier` could print values/URLs | fix rounds A+B |
| whole branch | Security (stage 6) | Minor | S-M4 `safe_query` matches keys before percent-decoding | fix round B |
| whole branch | Security + Quality (stage 6) | Minor | S-M5 `SessionMonitors` eviction forgets a live job's lost state (>16 jobs) | fix round B: bounded lost-job set, rebuilt monitors start lost |
| whole branch | Security (stage 6) | Minor | S-M6 `StoreDiff::snapshot` is O(store) per browser action | fix round A: one snapshot per page, running set |
| whole branch | Security (stage 6) | Minor | S-M7 `stored_flows` uncapped clone with bodies | fix round A: `MAX_STORED_FLOWS` newest-first, bodies cleared |
| whole branch | Quality (stage 6) | Minor | Q: job mark formatted in four places; stop reasons as literals; duplicate crawl request builders (+ seed sends ignoring `http.version`, Spec Minor); `attempts` counted in two places; `in_scope(&str)`; permit comment lie; checkbox rule twice; test-only `len/is_empty`; profile clone per host; hand-rolled `scrub_error`; visibility nits | fix rounds A+B |
| whole branch | Quality (stage 6) | Minor | Three byte-search helpers and two `splice`s with different bad-span semantics; `visit`/`landed_page` repetition; constants pinned twice in tests | accepted by the orchestrator (autonomous mandate) 2026-11-01: `mutate.rs` guards every span before splicing (`checked_span`) so no runtime defect; a cross-parser helper refactor is out of proportion for this PR; `limits_match_the_plan` is the plan's own pin |
| whole branch | Spec (stage 6) | Minor | `expect` missing from `EXCLUDED_HEADERS`; seed fetches ignore `http.version`; A18/Task 14 vs N2; Task 10 `url` wording; `Cargo.lock` under Task 1; `USER_AGENT` not in the constant list | code items in fix rounds A/B; plan items fixed in this commit |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7. Record here which Task 21 proof applied
(T10 cells or the fallback script) and which ACs, if any, were still pending T10 at merge time.
