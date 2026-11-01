# Scanner v2 track T3 (HTTP/2 sender + HTTP checks) implementation plan

**Status:** Approved (T3 session, on Matt's autonomous-approval mandate, 2026-10-31)
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved) — Constraints, D1, D2, D4, D5 (record policy), D6, **D8.2**, D9.1, D9.3, D12 (row T3 and "Integration-shared files"), Verification, AC **T3-1..T3-5**, "Left to the builder", Architect's calls 10, 21, 22, 23.
**Research:** `docs/research/19-ws-and-h2-active-scanning.md` (§4 h2 client, §5 h2 checks, §6 version choice), `docs/research/17-burp-style-scanner-architecture.md` (§3.6 blind/timing), `docs/research/20-scanner-v2-current-state.md`.
**Prior plan imitated:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t1a-plan.md`.
**Branch / worktree:** `claude/scanner-v2-t3-4c0d76` in `/Users/matt/Security/aitmproxy/.claude/worktrees/scanner-v2-t3-4c0d76`, cut from `feat/scanner-v2-t1a` (T1a contract drop).
**Size:** one PR; eighteen tasks in eight waves. Waves 1-5 are unblocked today; waves 6-8 wait for T1b on `main`.

## Overview

T3 is three bodies of work that share no file: (1) `HttpSender` in `aitm-proto-http`
— ALPN-negotiated h2 with a per-authority cache, a forced-version policy and a dial
seam so the whole negotiate/cache/dispatch path is unit-testable over
`tokio::io::duplex`; (2) a hand-rolled raw-h2 frame writer/reader
(`raw_h2.rs`) that can emit the malformed HEADERS blocks the `h2`/`http` crates
refuse by construction; (3) the `aitm-scan-checks-http` catalogue — five native
`Check` impls plus five observe-only h2 checks, a dependency-free `TimingOracle`,
and the conversion of the bundled `active/*.rhai` scripts to the D4
`reg.add_check(meta, |point| ...)` form.

Waves 1-5 (tasks 1-10) touch only `crates/aitm-proto-http/src/**` and
`crates/aitm-scan-checks-http/**` and are green against today's tree. Waves 6-7
(tasks 11-16) edit `scripts/bundled/active/**` and **cannot be green until T1b's
`add_check` bridge is on `main`** (see "The T1b landing gate" below). Wave 8 is
the live proof and the integration/PR task.

### Session calls (fixed before this plan; do not re-open)

- **S1 Version oracle.** The spec's "evidence flows show `version: h2`" (T3-1/T3-2)
  is satisfied by `flow.detail`'s `response.version == "HTTP/2"` (resp.
  `"HTTP/1.1"`). The sender sets `HttpResponse.version` from the negotiated
  protocol and leaves `HttpRequest` untouched. D8.2's sentence
  "`HttpRequest.version` stays what the sender observed" is read as applying to
  the **response**; recorded here as a spec wording correction for the
  orchestrator (`T1b::PipelineClient::send_opts` stores the caller's request
  unchanged, so the request field cannot carry the observation).
- **S2 `h2_not_negotiated` surface.** A forced-`H2` send fails with an error whose
  `Display` starts with `h2_not_negotiated:` in **every** case where h2 is not
  negotiated: handshake completes with ALPN absent; handshake completes with ALPN
  `http/1.1`; the server aborts with a `no_application_protocol` alert; the origin
  is `http://` (plaintext cannot negotiate — the detail says "use h2c"). `H2c`
  applies to `http://` origins (prior-knowledge h2 over plain TCP); on an
  `https://` origin `H2c` behaves as `H2`.
- **S3 Check ids.** Native ids literally as D8.2: `sqli-boolean`, `sqli-time`,
  `cmdi-time`, `xss-reflected`, `open-redirect`, `h2-pseudo-header-validation`,
  `h2-header-crlf-tolerance`, `h2-cl-te-downgrade-indicator`,
  `h2-rapid-reset-mitigation`, `h2-settings-observe`. Converted Rhai ids keep the
  shipped verb suffixes so `check.<id>` reproduces today's manual verbs verbatim:
  `sqli` (error technique only; boolean moved to native), `ssti`, `cmdi` (echo
  marker; timing is native), `path_traversal`, `xxe`, `ssrf`, `crlf`, `nosqli`,
  `ldapi`, `cors`, `headers`, `methods`, `paths`; new `nosqli-json` (kinds
  `[json_value]`) and `header-reflection` (kinds `[header, cookie]`). `class`
  carries the taxonomy token, so native `sqli-boolean`/`sqli-time` and Rhai `sqli`
  share class `sqli` and dedupe into one issue (D6).
- **S4 Retired scripts.** `check-xss.rhai` and `check-open-redirect.rhai` are
  deleted (D8.2 makes `xss-reflected`/`open-redirect` native; a technique is
  single-sourced). Their manual verbs become `check.xss-reflected` /
  `check.open-redirect` through the engine's uniform bridge; the README says so;
  the command pins change with the switchover (Task 11).
- **S5 Rhai probe API shape.** `probe.send(payload)` takes a string (replace) or
  `#{ value, mode: "replace"|"prefix"|"suffix" }`; the `point` map keys are exactly
  D4 (`kind`, `name`, `path`, `url`, `method`, `example`, `traits`); the verdict map
  keys are exactly the `Verdict` wire names;
  `poc_hint: #{ matchers: [...], control: #{ payload, matchers } }` uses the PoC
  YAML matcher vocabulary. The six D6 classes implemented in Rhai (`sqli`, `ssti`,
  `cmdi`, `path_traversal`, `crlf`, `xxe`) MUST return a `poc_hint`.
- **S6 Raw h2 scope gate.** An observe-only h2 check calls `host.baseline()` first
  (guarded job client; fails out-of-scope before any raw byte) and only on success
  opens its single raw connection to the same authority; <= 8 streams per
  connection; no retry loop.

### Verified facts on this branch (do not re-derive)

1. **PR #195** (`ConnInfo` with `source_app`, `3fe92f66`) **is an ancestor of
   `HEAD`**, so spec Constraints sequencing pin (b) — "T3 rebases onto PR #195's
   `ConnInfo` change in `crates/aitm-proto-http/src/module.rs` before touching
   `aitm-proto-http`" — is already satisfied. `origin/main` at `v0.5.8` is merged
   into the base (`crates/aitm-sysproxy` is a workspace member), so the only
   substantial merge left is T1b.
2. In `crates/aitm-proto-http/src/h2.rs`, `MAX_HEADER_LIST_SIZE` (64 KiB),
   `HEADER_TABLE_SIZE` (4 KiB) and `send_body` are **private**, and `h2.rs` is
   **not a T3 file**: `h2_sender.rs` carries its own copies (same values, with a
   comment naming `h2.rs` as the source).
3. `crate::translate::{h2_request_from, response_from_h2}` are `pub(crate)` and
   reusable from `h2_sender.rs`; `response_from_h2` already sets
   `version: HttpVersion::H2`.
4. `crate::module::accept_any_verifier` is `pub(crate)` and
   `Http1Sender::client_config` already uses it; that config hard-codes ALPN
   `http/1.1` today.
5. `module.rs` tests carry a `server_config(alpn: &[&[u8]])` helper (rcgen
   self-signed `origin.test` leaf over `tokio::io::duplex`): the pattern for the
   sender's ALPN tests. It is in a `#[cfg(test)]` module of a non-T3 file, so T3
   writes its own copy in its own test module.
6. `PipelineClient::send_opts` (T1b-owned) stores the caller's request unchanged,
   so only `HttpResponse.version` can reflect what the wire negotiated; on the bus
   `flow.detail` renders it as `"HTTP/2"` / `"HTTP/1.1"` under `response.version`.
7. `aitm_core` already exposes `SendOptions`, `RecordPolicy`, `VersionPolicy` and
   `RequestSender::send_with(req, version)` (T1a, verified in
   `crates/aitm-core/src/{client.rs, ctx.rs, lib.rs}`).
8. `aitm_poc::Assertion` deserialises from a YAML/JSON matcher map through its
   hand-written `Deserialize` (`crates/aitm-poc/src/model.rs`): keys `type`
   (`status|word|regex|dsl|browser-eval`), `word`/`regex`/`dsl`/`status`, `part`
   (`body|header|all`), `negative`, and the `all`/`any`/`not` combinators. That is
   the vocabulary a `poc_hint` matcher map must use.
9. `crates/aitm-plugin-rhai/Cargo.toml` pins `rhai = { version = "1.27", features
   = ["sync"] }` (dev-dep adds `"metadata"`). The test-only harness pins the same.

### The T1b landing gate (read before scheduling waves 6-8)

T1b owns `reg.add_check`, the `probe.*` host fns and the uniform `check.<id>`
registration. None of them is on this branch. Two shipped tests load the bundled
catalogue through the **real** engine:

- `crates/aitm/tests/bundled_startup.rs` runs every script's `load(reg)` and pins
  `EXPECTED_COMMANDS`;
- `crates/aitm-plugin-rhai/tests/bundled_scripts.rs::command_scripts_register_their_commands`
  asserts every `active/` script registers at least one **command**.

The moment a script switches from `reg.add_command` to `reg.add_check`, both go
red and stay red until T1b's bridge exists. Therefore:

- **Tasks 11-16 are blocked** until T1b is merged to `main`. Task 11 begins by
  merging `origin/main` (carrying T1b) into this branch; if T1b has not merged, the
  wave waits and the track ships waves 1-5 + the live-proof/integration tasks for
  the native half only, with the Rhai conversion as a follow-up PR (see the
  question at the end).
- **Task 11 is designated "integration, part 1"** and is the one non-final task
  permitted to touch the integration-shared files, because the pin edit and the
  verb-name delta must be one commit for the gate to stay green. Task 18
  (integration, part 2) re-pins again from live `tools/list` after the final merge.
  Every other task touches none of them.


**Amendment A1 (T3 session, 2026-11-01, from the Task 5 report).** The check tasks'
named tests live in `crates/aitm-scan-checks-http/tests/`, a separate crate that can
reach only `pub` items; and a `pub(crate)` constructor with no caller before Task 10
is `dead_code` under `-D warnings`. Therefore: (1) `lib.rs` declares
`pub mod blind_timing; pub mod h2_observe; pub mod redirect; pub mod sqli_boolean;
pub mod xss;` — applied once by the orchestrator in commit "A1" so no check task
edits `lib.rs`; (2) every check constructor named in Tasks 5, 7, 8 and 9 is `pub fn`
(the text below is updated accordingly); (3) Task 10 still owns `catalogue.rs` and
`lib.rs` doc comments only.


**Amendment A2 (T3 session, 2026-11-01, from the Task 5 report).** The open-redirect
`PocHint` regex is `(?im)^location:\s*.*aitm-redirect\.invalid` (multi-line flag added):
`aitm_poc`'s `MatchPart::Header` is every header joined with `\n`, so the plan's
`(?i)` form would match only when `Location` is the first header and the finding
record would silently never be written. `.` does not cross `\n`, so the match stays
on the `Location` line (test `the_location_matcher_is_multiline_and_line_bounded`).
The hint also carries `control: Some(ControlHint { payload: "/", expect: [Not(<canary regex>)] })`.


**Amendment A3 (T3 session, 2026-11-01, from the Task 9 report).** The Task 6 driver
sends one header block per connection, but `h2-pseudo-header-validation` (3 variants),
`h2-header-crlf-tolerance` (2) and `h2-cl-te-downgrade-indicator` (2) need a distinct
block per stream on ONE connection (D8.2, AC T3-3). Task 9 therefore also edits
`crates/aitm-proto-http/src/raw_h2.rs` to add `RawH2Mode::Blocks(Vec<Vec<RawHeader>>)`:
one stream per block, written in order, each awaited to its `StreamOutcome` before the
next is opened (so answered-vs-reset is observable per variant), count = `blocks.len()`,
refused above `MAX_RAW_STREAMS` before the dial, every block subject to the same
session-header and size refusals as `headers`; `SingleRequest` keeps using `headers`.
Driver tests for the mode live in `raw_h2.rs`'s `driver_tests`. Further Task 9
decisions: the `OncePerAuthority` TTL guard is per check instance, not shared; every
runner `Err` (including "did not negotiate ALPN h2") maps to `Outcome::Inconclusive`
with `detail` "origin does not negotiate h2 (or the raw probe failed)"; the AC T3-3
expected set on a conforming server is enumerated for all five ids:
`h2-settings-observe` info, `h2-rapid-reset-mitigation` info ("no reset-rate mitigation
observed in 8 reset pairs" is the normal reading of a conforming server), and
`h2-pseudo-header-validation`, `h2-header-crlf-tolerance`, `h2-cl-te-downgrade-indicator`
clean; forwarded to the coordinator as an AC wording item.


**Amendment A4 (T3 session, 2026-11-01).** Tasks 12-16's script conversions and the
Task 11 test-only harness are drafted OUT OF TREE first, under
`/tmp/claude/t3-rhai/` (a scratch cargo crate holding the fake `reg.add_check` /
`probe.*` harness and the converted `*.rhai` files), because any converted script
committed under `scripts/bundled/active/` turns `crates/aitm/tests/bundled_startup.rs`
red until T1b's bridge is on `main`. Task 11 moves the drafts into the tree in the
same commit as the T1b merge and the pin re-point; Tasks 12-16 then become
verification against the real engine rather than authoring from scratch. The
`probe.*` shape the drafts assume is S5 unless T1b's bridge says otherwise.


**Amendment A5 (coordinator, 2026-11-01): two plan-level acceptance criteria for the
raw-h2 checks, implemented after the T1b merge (Task 11, since the hooks
`ProbeHost::charge(units) -> bool` and `ProbeHost::baseline_peer_addr() ->
Option<SocketAddr>` arrive with T1b):**
- **T3-6** Every raw-h2 check calls `host.charge(plan.streams.max(1))` before dialling
  and returns `Inconclusive` ("budget refused the raw probe") when it is `false`; the
  live cell shows `scan.status.probes.sent` growing by the stream count (0/8/3/2/2) per
  authority. Unit: a host whose `charge` returns false -> `runner.calls() == 0`; a
  counting host records exactly the stream count.
- **T3-7** The raw probe dials `host.baseline_peer_addr()`: the driver gains
  `RawH2Target.addr: Option<SocketAddr>` (pre-validated address; when `Some` the
  resolver is not consulted and the SSRF gate still checks that address); the check
  returns `Inconclusive` ("baseline peer address unknown") when the hook returns `None`
  and refuses when the address differs from the one the baseline reported. Unit: a host
  returning `Some(addr)` -> the dialer is called with exactly `addr`; `None` -> no dial.
Until the merge, F3 implements the `budget_left() >= streams` pre-check (SEC-C2) and
the normalised profile-origin match (C6/SEC-C3) as the interim.

### Waves

Tasks inside a wave touch disjoint files and fan out to parallel coders.

| Wave | Tasks | Depends on | Blocked? |
|---|---|---|---|
| 1 | **1** `HttpSender` front-end (dial seam, ALPN negotiate + cache, `SendError`), **2** checks-http scaffold + `TimingOracle` | none | no |
| 2 | **3** h2 dispatch + per-authority connection reuse, **4** raw-h2 frame + HPACK codec, **5** `xss-reflected` + `open-redirect` | 1 (3, 4); 2 (5) | no |
| 3 | **6** raw-h2 connection driver, **7** `sqli-boolean`, **8** `sqli-time` + `cmdi-time` | 4 (6); 2 (7, 8) | no |
| 4 | **9** the five observe-only h2 checks | 6 | no |
| 5 | **10** `checks()` full list + catalogue agreement test | 5, 7, 8, 9 | no |
| 6 | **11** Rhai switchover: harness, two new scripts, two retirements, pin re-point | 10; **T1b on `main`** | yes |
| 7 | **12** convert `sqli`/`ssti`/`cmdi`, **13** convert `path_traversal`/`xxe`/`ssrf`, **14** convert `crlf`/`nosqli`/`ldapi`, **15** convert `cors`/`headers`/`methods`/`paths` | 11 | yes |
| 8 | **16** README + catalogue sweep test, **17** live proof, **18** integration + PR | 15 (16); 16 (17); 17 (18) | yes |

### Shared facts for every coder

- **Authorized context.** aitmproxy is a first-party, open-source intercepting
  proxy for **authorized** security testing. Every probe in this plan is exercised
  only against the project's own seeded loopback target
  (`crates/aitm-testtarget`, Vulnerable vs Patched) and is a benign
  detection-grade differential: a single quote, `1=1` vs `1=2`, an arithmetic
  marker, a bounded delay payload, a single malformed HTTP/2 header frame, at most
  eight streams. Nothing here exploits, exfiltrates or denies service, and the
  spec's anti-goals forbid it. If a task seems to ask you to exceed that, stop and
  report instead of improvising.
- **TDD per task.** Write the named test first, run it and quote the red run (a
  compile error on a type that does not exist yet counts as red), implement, quote
  the green run. One commit per task.
- **Sandbox vs Terminal.** `cargo test -p <crate> --offline`, `cargo clippy
  --offline` and `cargo fmt --check` work in the sandbox. Anything that binds a
  port runs in the Terminal panel; such a test is `#[ignore]`d with the doc line
  `// runs in the Terminal panel (binds a port)`. Full gate from the worktree root
  before handing back: `cargo fmt --check && cargo clippy --all-targets -- -D
  warnings && cargo test` (add `--offline` in the sandbox).
- **No port binding in a default test.** Every sender and raw-h2 test runs over
  `tokio::io::duplex`, as `sender.rs`'s existing tests do; the far end is a rustls
  server over the duplex (rcgen leaf for `origin.test`) and, for h2, `h2::server`
  or a hand-written frame script.
- **Error hygiene.** No `unwrap`/`expect` on a network or user-input path. Crate
  roots already carry `#![forbid(unsafe_code)]` and `[lints] workspace = true`.
- **Redaction.** No cookie, `Authorization`, token or session value may appear in a
  `detail`, an `Evidence` field, a `Debug` impl or a log line. Bodies are matched
  bounded at `aitm_scan_model::MAX_MATCH_BODY` (1 MiB) and excerpts go through
  `aitm_scan_model::Evidence::excerpt` (256 bytes). A raw-h2 probe sends **no**
  `Cookie`, `Authorization` or any session header — only the pseudo-headers plus
  the one malformed field under test.
- **File ownership is exclusive** (spec D12 row T3). A task edits only the files its
  row names. No task edits the root `Cargo.toml`, `aitm-core`, `aitm-mcp`,
  `aitm-plugin-rhai` (src), `crates/aitm/src/**`, `h2.rs`, `module.rs` or
  `translate.rs`. `crates/aitm-scan-checks-http/Cargo.toml` may add only
  `workspace = true` deps that already exist in `[workspace.dependencies]`
  (`anyhow`, `futures`, `tokio`, `serde`, `serde_json`, `regex`, `tracing`,
  `bytes`, `aitm-core`, `aitm-poc`, `aitm-proto-http`, `aitm-scan-model`); the only
  per-crate pin is dev-only `rhai = { version = "1.27", features = ["sync"] }`.
- **Contract lists are off-limits** except in Tasks 11 and 18:
  `crates/aitm/tests/frontends.rs`, `crates/aitm-tui/src/lib.rs` `CORE_TOOLS`,
  `crates/aitm-tui/fixtures/bus-fixture.json`, `crates/aitm/tests/bundled_startup.rs`,
  `crates/aitm-plugin-rhai/tests/bundled_scripts.rs`.
- **Fixtures are never acceptance evidence** (Matt's rule). The unit tests in this
  plan are the inner loop; Task 17 is the proof.

## Tasks

### Task 1: `HttpSender` front-end — dial seam, ALPN negotiation, per-authority cache, `SendError`

- **Satisfies:** AC T3-1 (version oracle groundwork), AC T3-2 (`h2_not_negotiated`),
  spec D8.2, D9.1, Architect's calls 10 and 21; session calls S1, S2.
- **Depends on:** none.
- **Files:** `crates/aitm-proto-http/src/sender.rs` (modify),
  `crates/aitm-proto-http/src/lib.rs` (modify: exports + two `mod` lines),
  `crates/aitm-proto-http/src/h2_sender.rs` (create: `//!` doc only, a placeholder
  Task 3 fills), `crates/aitm-proto-http/src/raw_h2.rs` (create: `//!` doc only, a
  placeholder Task 4 fills).
- **Change:**
  1. `pub struct HttpSender` replaces the body of `Http1Sender`; `pub type
     Http1Sender = HttpSender;` keeps `crates/aitm/src/wire.rs` untouched. Keep
     every existing builder (`new`, `with_insecure`, `with_ssrf`, `with_resolver`,
     `with_response_timeout`), the SSRF gate, the resolver seam, `CONNECT_TIMEOUT`,
     `READ_TIMEOUT`, `RESPONSE_TIMEOUT` (60 s) and `MAX_RESPONSE_BYTES` (16 MiB).
  2. New dial seam:
     `pub trait ProbeStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}`
     with a blanket impl, and
     `pub trait Dialer: Send + Sync { fn dial(&self, addr: std::net::SocketAddr) -> BoxFuture<'static, anyhow::Result<Box<dyn ProbeStream>>>; }`.
     `struct TcpDialer;` is the default (`TcpStream::connect` under
     `CONNECT_TIMEOUT`). Builder: `pub fn with_dialer(self, dialer: Arc<dyn Dialer>) -> Self`.
  3. ALPN cache: `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Negotiated { H1, H2 }`
     and a `moka::sync::Cache<String, Negotiated>` field built with
     `.time_to_live(ALPN_CACHE_TTL)` (`const ALPN_CACHE_TTL: Duration =
     Duration::from_secs(600)`) and `.max_capacity(1024)`. `moka` is already a
     dependency of this crate. Test accessor `pub fn negotiated_for(&self, scheme: &str, authority: &str) -> Option<Negotiated>`.
  4. `fn client_config(&self, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>>` takes the
     ALPN list (the body is today's, with `cfg.alpn_protocols` from the argument).
     Offers: `Auto` on a cached-miss `https` origin -> `[b"h2", b"http/1.1"]`;
     `Auto` on a cache hit -> the cached protocol's single entry; `H1` ->
     `[b"http/1.1"]`; `H2`/`H2c` on `https` -> `[b"h2"]`.
  5. `impl RequestSender for HttpSender` overrides
     `fn send_with<'a>(&'a self, req: &'a HttpRequest, version: VersionPolicy) -> BoxFuture<'a, Result<HttpResponse>>`
     and `fn send` delegates to `send_with(req, VersionPolicy::Auto)`. The flow:
     resolve -> SSRF gate (unchanged) -> dial -> for `https`, TLS-connect and read
     `tls.get_ref().1.alpn_protocol()`; cache the result keyed by
     `host:port`; dispatch to the existing `drive` (h1) or, from Task 3, to
     `crate::h2_sender::exchange` (h2). Until Task 3 lands, the h2 arm returns
     `SendError::H2NotNegotiated { detail: "h2 dispatch not yet wired" }` so this
     task is independently green and Task 3 is a pure substitution.
  6. `prepare()` is split: `Connection: close` is added **only** on the h1 arm
     (`fn prepare_h1`); the h2 arm uses `fn prepare_common` (Host normalisation
     only) and lets `translate::h2_request_from` strip hop-by-hop names.
  7. `#[derive(Debug)] pub enum SendError { H2NotNegotiated { authority: String, detail: String } }`
     with `impl std::fmt::Display` producing exactly
     `h2_not_negotiated: <authority>: <detail>` and `impl std::error::Error`. It
     converts into `anyhow::Error` with the prefix preserved; never wrap it in a
     `.context()` that would hide the prefix from `to_string()`.
     `pub fn is_h2_not_negotiated(err: &anyhow::Error) -> bool` returns true when any
     link of `err.chain()` downcasts to `SendError::H2NotNegotiated` **or** its
     `to_string()` starts with `h2_not_negotiated:` (so the error survives a bus
     round trip as a string).
  8. A `no_application_protocol` TLS alert maps to the same error: when the
     handshake fails, walk the `io::Error` -> `rustls::Error` chain
     (`e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>())`) and, on
     `rustls::Error::AlertReceived(AlertDescription::NoApplicationProtocol)`,
     return `SendError::H2NotNegotiated { detail: "server refused ALPN h2 (no_application_protocol)" }`.
  9. Forced `H2` on an `http://` origin returns
     `SendError::H2NotNegotiated { detail: "plaintext origin cannot negotiate ALPN; use h2c" }`
     **before** dialling.
  10. `lib.rs`: `mod h2_sender; pub mod raw_h2;` and
      `pub use sender::{is_h2_not_negotiated, Dialer, HostResolver, Http1Sender, HttpSender, Negotiated, ProbeStream, SendError};`
- **Test** (`sender.rs` `#[cfg(test)] mod tests`, `#[tokio::test]`; a `DuplexDialer`
  handing out a pre-made `tokio::io::duplex` client half, a `FixedResolver`
  returning `127.0.0.1`, and a local `server_config(alpn)` copied from
  `module.rs`'s test helper):
  - `auto_offers_both_protocols_and_caches_h2`: server ALPN `[b"h2", b"http/1.1"]`;
    after the send, `sender.negotiated_for("https", "origin.test:443") == Some(Negotiated::H2)`
    and the ALPN list the server saw is `["h2", "http/1.1"]`.
  - `auto_falls_back_to_h1_when_the_server_picks_http11`: server ALPN
    `[b"http/1.1"]`; the exchange returns `status == 200`,
    `resp.version == aitm_core::HttpVersion::Http11`, and
    `negotiated_for("https", ..) == Some(Negotiated::H1)`.
  - `the_second_send_offers_only_the_cached_protocol`: two sends to one authority;
    the recorded offered lists are exactly
    `vec![vec!["h2".to_string(), "http/1.1".to_string()], vec!["http/1.1".to_string()]]`
    for an h1 origin.
  - `forced_h2_on_an_h1_only_origin_is_h2_not_negotiated`: `VersionPolicy::H2`
    against a server whose ALPN is `[b"http/1.1"]`; the error's `to_string()`
    **starts with** `"h2_not_negotiated:"`, contains `origin.test:443`, and
    `is_h2_not_negotiated(&err)` is `true`.
  - `forced_h2_on_a_server_without_alpn_is_h2_not_negotiated`: server ALPN `[]`;
    same two assertions.
  - `forced_h2_on_a_plaintext_origin_says_use_h2c`: scheme `http`; the error string
    contains `"use h2c"`, `is_h2_not_negotiated(&err)` is `true`, and the dialer's
    call count is `0`.
  - `is_h2_not_negotiated_recognises_a_round_tripped_string`:
    `is_h2_not_negotiated(&anyhow::anyhow!("h2_not_negotiated: ex.test:443: nope")) == true`
    and `is_h2_not_negotiated(&anyhow::anyhow!("connect refused")) == false`.
  - `h1_still_sends_connection_close`: the h1 request bytes the origin read contain
    `"Connection: close\r\n"` (characterisation of today's behaviour).
  - `send_defaults_to_auto`: `send(&req)` against an h1 origin succeeds and caches
    `Negotiated::H1`.
- **Done when:** `cargo test -p aitm-proto-http --offline` passes and the full gate
  passes. Note in the report that `Http1Sender` is now an alias and that `send`
  offers h2 by default (a deliberate behaviour change, call **B1**).

### Task 2: `aitm-scan-checks-http` scaffold, `TimingOracle`, bounded matching helpers

- **Satisfies:** spec D4 ("the native `TimingOracle` ... is the same algorithm
  `probe.timing_fit` exposes"), D8.2, AC T3-4 (the oracle half).
- **Depends on:** none.
- **Files:** `crates/aitm-scan-checks-http/Cargo.toml` (modify),
  `crates/aitm-scan-checks-http/src/lib.rs` (modify),
  `crates/aitm-scan-checks-http/src/timing.rs` (create),
  `crates/aitm-scan-checks-http/src/matching.rs` (create), and **placeholder**
  module files containing only a `//!` doc line so later tasks own one file each
  and `lib.rs` is never edited again except by Task 10:
  `src/xss.rs`, `src/redirect.rs`, `src/sqli_boolean.rs`, `src/blind_timing.rs`,
  `src/h2_observe.rs`, `src/catalogue.rs` (create, all).
- **Change:**
  1. `Cargo.toml`: add `aitm-core`, `aitm-poc`, `aitm-proto-http`, `anyhow`,
     `futures`, `regex`, `tracing` (all `workspace = true`); dev-deps `tokio`
     (`workspace = true`, features `["macros", "rt-multi-thread", "time",
     "test-util"]`), `serde_json`, `serde_yaml` (`workspace = true`). `rhai` is added
     by Task 11, not here.
  2. `lib.rs`: `pub mod timing; pub mod matching; mod xss; mod redirect; mod
     sqli_boolean; mod blind_timing; mod h2_observe; mod catalogue;` and
     `pub use catalogue::checks;`. The `checks()` body stays empty here (it moves to
     `catalogue.rs` returning `Vec::new()`), so the T1a skeleton test still passes.
  3. `timing.rs`, dependency-free apart from `aitm_scan_model`:
     - `pub const CORRELATION_ERROR_RANGE: f32 = 0.15;` and
       `pub const SLOPE_ERROR_RANGE: f32 = 0.30;` (ZAP, research 17 §3.6).
     - `pub struct TimingOracle;`
     - `pub fn fit(requested_s: &[f32], observed_ms: &[u32], baseline_ms: &[u32]) -> aitm_scan_model::Timing`
       — least-squares of `(observed_ms - median(baseline_ms))` in **milliseconds**
       against `requested_s` in seconds, so `Timing.slope` is milliseconds per
       second (the model's doc: "near 1000 ms/s when correlated") and `Timing.r` is
       the Pearson coefficient. Total on degenerate input: fewer than two points,
       zero variance or a non-finite result yields `slope: 0.0, r: 0.0`.
     - `pub fn correlated(t: &aitm_scan_model::Timing) -> bool` =
       `(1.0 - t.r).abs() <= CORRELATION_ERROR_RANGE && (1.0 - t.slope / 1000.0).abs() <= SLOPE_ERROR_RANGE`.
     Both are `pub` so T1b's `probe.timing_fit` reuses them verbatim.
  4. `matching.rs`: `pub fn body_text(resp: &ProbeResponse) -> std::borrow::Cow<'_, str>`
     (lossy UTF-8, truncated at `aitm_scan_model::MAX_MATCH_BODY`),
     `pub fn header(resp: &ProbeResponse, name: &str) -> Option<&str>` (ASCII
     case-insensitive, first match), `pub fn is_html(resp: &ProbeResponse) -> bool`
     (`content-type` contains `html`, case-insensitive),
     `pub fn length_differs(a: usize, b: usize, baseline: usize) -> bool` using the
     shipped threshold `max(baseline / 20, 40)`, and
     `pub fn excerpt_around(hay: &str, needle: &str) -> String` returning an
     `Evidence::excerpt`-bounded window.
- **Test** (`#[cfg(test)]` in each new file):
  - `fit_reports_a_correlated_alternating_delay`: `requested_s = [1.0, 3.0, 1.0, 3.0]`,
    `observed_ms = [1040, 3060, 1030, 3090]`, `baseline_ms = [38, 41, 39, 40]` ->
    `t.r >= 0.99`, `950.0 <= t.slope && t.slope <= 1050.0`, `correlated(&t) == true`.
  - `fit_rejects_a_flat_response_set`: same `requested_s`,
    `observed_ms = [1040, 1050, 1030, 1060]` -> `correlated(&t) == false`.
  - `fit_rejects_an_anticorrelated_set`: `observed_ms = [3000, 1000, 3000, 1000]` ->
    `t.r <= -0.9` and `correlated(&t) == false`.
  - `fit_is_total_on_degenerate_input`: empty slices and a one-point set both give
    `t.slope == 0.0`, `t.r == 0.0`, `t.r.is_finite()`, `correlated(&t) == false`.
  - `body_text_is_capped_at_max_match_body`: a 2 MiB body yields
    `body_text(&resp).len() == aitm_scan_model::MAX_MATCH_BODY`.
  - `length_differs_uses_the_shipped_threshold`: `length_differs(600, 600, 600) == false`,
    `length_differs(600, 120, 600) == true`, `length_differs(100, 130, 100) == false`
    (threshold 40), `length_differs(100, 180, 100) == true`.
  - `is_html_matches_a_charset_suffix`: `text/html; charset=utf-8` -> `true`;
    `application/json` -> `false`.
- **Done when:** `cargo test -p aitm-scan-checks-http --offline` passes,
  `cargo metadata --offline --format-version 1 >/dev/null` exits 0 after the
  manifest edit (quote the exit code), and the full gate passes.

### Task 3: h2 dispatch, per-authority connection reuse, h2c

- **Satisfies:** AC T3-1, AC T3-2, spec D8.2, Architect's call 10.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-proto-http/src/h2_sender.rs` (modify: fill the placeholder),
  `crates/aitm-proto-http/src/sender.rs` (modify: substitute the h2 arm — Task 1 left
  one `todo`-shaped branch; **no other sender edit**).
- **Change:**
  1. Local copies, with a comment naming `h2.rs` as the source:
     `const MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;`, `const HEADER_TABLE_SIZE: u32 = 4 * 1024;`,
     `const H2_WIRE_TIMEOUT: Duration = Duration::from_secs(30);`.
  2. `pub(crate) struct H2Pool { conns: Mutex<HashMap<String, h2::client::SendRequest<Bytes>>> }`
     with `pub(crate) const MAX_POOLED_AUTHORITIES: usize = 8;`. `fn take(&self, authority: &str) -> Option<SendRequest<Bytes>>`
     returns a clone only when `SendRequest::poll_ready` is ready and the handle is
     not errored; any error removes the entry. One connection per authority, reused
     while idle, dropped on error. No retry loop: a failed reused connection removes
     the entry and the **same** send returns the error (the engine's probe-error
     ladder owns retries).
  3. `pub(crate) async fn exchange(pool: &H2Pool, stream: Box<dyn ProbeStream>, authority: &str, req: &HttpRequest, response_timeout: Duration) -> Result<HttpResponse>`:
     handshake with `h2::client::Builder::new().enable_push(false)
     .max_header_list_size(MAX_HEADER_LIST_SIZE).header_table_size(HEADER_TABLE_SIZE)
     .handshake::<_, Bytes>(stream)` exactly as `h2.rs::Upstreams::open` does; spawn
     the connection future with a `tracing::warn!` on error; build the head with
     `crate::translate::h2_request_from(req)`; send the body with a local
     `send_body` copy honouring flow control; read the response head with
     `crate::translate::response_from_h2` (which sets `version: HttpVersion::H2`);
     accumulate data frames up to `MAX_RESPONSE_BYTES` (16 MiB), releasing flow-control
     capacity per chunk; collect trailers into `HttpResponse.trailers`. Every wire
     await is bounded by `H2_WIRE_TIMEOUT` and the whole exchange by the sender's
     `response_timeout` (60 s default).
  4. `sender.rs`: the `https` arm dispatches on the negotiated protocol; the `H2c`
     policy on an `http://` origin skips TLS and hands the raw stream to `exchange`
     (prior-knowledge h2); `H2c` on `https` behaves as `H2`.
  5. **(Amendment from the Task 1 report, T3 session 2026-11-01.)** `sender.rs`: the
     ALPN cache is written only by a `VersionPolicy::Auto` exchange. A forced `H1`
     or `H2` send never records `Negotiated` for the authority, so a later `Auto`
     send still offers both protocols. This is the one further `sender.rs` edit
     Task 3 may make.
- **Test** (`h2_sender.rs` `#[cfg(test)]`, `#[tokio::test]`, far end = `h2::server::handshake`
  over `tokio::io::duplex`; plus two cases in `sender.rs`'s module reusing its TLS helper):
  - `an_h2_exchange_round_trips_over_a_duplex_server`: server answers `200` with body
    `b"hi"` -> `resp.status == 200`, `resp.version == aitm_core::HttpVersion::H2`,
    `resp.body == Body::Bytes(b"hi".to_vec())`, and the server saw `:method == "GET"`,
    `:path == "/x"` and **no** `connection` header.
  - `the_pool_reuses_one_connection_per_authority`: two sends to `origin.test:443`
    leave the dialer's call count at `1`.
  - `a_failed_connection_is_dropped_and_the_next_send_redials`: the server sends
    `GOAWAY` after the first stream; the second send's dialer call count is `2`.
  - `an_h2_response_body_is_capped_at_16_mib`: a server streaming 17 MiB yields
    `resp.body.len() == 16 * 1024 * 1024`.
  - `h2c_speaks_prior_knowledge_h2_over_plaintext`: scheme `http`,
    `VersionPolicy::H2c`, plain duplex h2 server -> `status == 200`,
    `version == HttpVersion::H2`, and no TLS handshake was attempted.
  - `an_h2_exchange_times_out_within_the_response_timeout`
    (`#[tokio::test(start_paused = true)]`, `with_response_timeout(Duration::from_secs(5))`):
    a server that never answers yields an error whose string contains `"timed out"`.
  - `h2_requests_carry_no_connection_close`: the server's received header map has no
    `connection` key (S1/D8.2: `Connection: close` is h1-only).
  - `a_forced_h1_send_does_not_pollute_the_alpn_cache` (`sender.rs` tests): a
    `VersionPolicy::H1` send to an h2-capable origin leaves
    `negotiated_for("https", "origin.test:443") == None`, and the following `Auto` send offers
    `["h2", "http/1.1"]` and caches `Some(Negotiated::H2)`.
- **Done when:** `cargo test -p aitm-proto-http --offline` passes and the full gate passes.

### Task 4: raw h2 — frame codec and HPACK literal encoder (pure)

- **Satisfies:** spec D8.2 ("a tiny frame writer/reader ... hand-encoded HPACK
  literals"), "Left to the builder" ("the HPACK literal encoding details ... no
  dynamic table; literal-without-indexing is enough"), AC T3-3.
- **Depends on:** Task 1 (the placeholder file).
- **Files:** `crates/aitm-proto-http/src/raw_h2.rs` (modify: fill with the pure half
  only; Task 6 adds the driver).
- **Change:** pure, I/O-free, all `pub` within the crate and re-exported:
  - `pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum FrameType { Data = 0x0, Headers = 0x1, RstStream = 0x3, Settings = 0x4, Ping = 0x6, GoAway = 0x7, WindowUpdate = 0x8 }`
    with `pub fn from_u8(v: u8) -> Option<FrameType>`.
  - `pub mod flags { pub const END_STREAM: u8 = 0x1; pub const END_HEADERS: u8 = 0x4; pub const ACK: u8 = 0x1; }`
  - `pub fn frame_header(len: u32, kind: FrameType, flags: u8, stream: u32) -> [u8; 9]`
    (24-bit length, 8-bit type, 8-bit flags, 31-bit stream id with the reserved bit
    cleared).
  - `pub struct Frame { pub kind: u8, pub flags: u8, pub stream: u32, pub payload: Vec<u8> }`
    and `pub fn parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>>` returning
    `Ok(None)` when the buffer holds less than one whole frame and `Err` when a
    declared length exceeds `MAX_FRAME_BYTES`.
  - `pub const MAX_FRAME_BYTES: usize = 16 * 1024;`
  - `pub struct RawHeader { pub name: Vec<u8>, pub value: Vec<u8> }` with
    `pub fn new(name: &str, value: &str) -> Self` and
    `pub fn raw(name: &[u8], value: &[u8]) -> Self` (the latter is how a check sends
    a name or value containing `\r\n`, which `http::HeaderName`/`HeaderValue` refuse
    by construction).
  - `pub fn encode_block(headers: &[RawHeader]) -> Vec<u8>` — HPACK **literal header
    field without indexing, new name** (`0x00` prefix byte) for every field, 7-bit
    prefix string lengths, **no Huffman**, **no dynamic-table insert**, no validation
    of the name or value bytes. `pub fn encode_integer(value: usize, prefix_bits: u8, first_byte: u8) -> Vec<u8>`
    is the shared primitive.
  - Parsers: `pub fn parse_settings(payload: &[u8]) -> Vec<(u16, u32)>`,
    `pub fn parse_rst_stream(payload: &[u8]) -> Option<u32>`,
    `pub fn parse_goaway(payload: &[u8]) -> Option<(u32, u32)>` (last-stream-id,
    error code). A decoder for response HEADERS is **not** written: the driver
    (Task 6) records "HEADERS received, N bytes" and the `:status` only when the
    server used a static-table index (`parse_status_indexed`), because the observe
    checks' oracle is reset-vs-answer, not the response body.
  - `pub fn parse_status_indexed(block: &[u8]) -> Option<u16>` — maps the static
    table's indexed `:status` entries (`0x88` -> 200, `0x89` -> 204, `0x8a` -> 206,
    `0x8b` -> 304, `0x8c` -> 400, `0x8d` -> 404, `0x8e` -> 500) and returns `None`
    for anything else.
- **Test** (`raw_h2.rs` `#[cfg(test)]`, no async):
  - `the_preface_is_the_rfc_string`: `PREFACE == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`
    and `PREFACE.len() == 24`.
  - `frame_header_encodes_length_type_flags_and_stream`:
    `frame_header(1, FrameType::Headers, flags::END_HEADERS | flags::END_STREAM, 1)
    == [0x00, 0x00, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01]`.
  - `a_literal_without_indexing_encodes_a_pseudo_header`:
    `encode_block(&[RawHeader::new(":path", "/x")])
    == vec![0x00, 0x05, b':', b'p', b'a', b't', b'h', 0x02, b'/', b'x']`.
  - `the_encoder_accepts_a_crlf_in_a_name_and_in_a_value`:
    `encode_block(&[RawHeader::raw(b"x-a\r\nx-b", b"1")])` contains the subsequence
    `[0x0d, 0x0a]` and starts with `[0x00, 0x08]`; the same for a value.
  - `encode_integer_uses_the_continuation_form`: `encode_integer(1337, 5, 0x20)
    == vec![0x3f, 0x9a, 0x0a]` (RFC 7541 §5.1 worked example).
  - `parse_settings_reads_each_pair`: payload
    `[0x00, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff]`
    -> `vec![(3u16, 128u32), (4u16, 65535u32)]`.
  - `parse_frame_needs_a_whole_frame`: a 5-byte buffer -> `Ok(None)`; a complete
    SETTINGS frame -> `Ok(Some((frame, 9 + payload_len)))` with `frame.kind == 0x04`.
  - `parse_frame_refuses_an_oversized_declared_length`: a header declaring
    `MAX_FRAME_BYTES + 1` -> `Err` whose string contains `"frame too large"`.
  - `parse_rst_stream_reads_the_error_code`:
    `parse_rst_stream(&[0x00, 0x00, 0x00, 0x01]) == Some(1)`.
  - `parse_status_indexed_maps_the_static_table`:
    `parse_status_indexed(&[0x88]) == Some(200)`, `parse_status_indexed(&[0x8c]) == Some(400)`,
    `parse_status_indexed(&[0x00]) == None`.
- **Done when:** `cargo test -p aitm-proto-http --offline` passes and the full gate passes.

### Task 5: native `xss-reflected` and `open-redirect`

- **Satisfies:** AC T3-1 (the XSS half over h2), AC T3-5 (`check.xss-reflected` /
  `check.open-redirect` exist as native ids), spec D8.2, D6 (both MUST supply a
  `PocHint`), Architect's call 23; session calls S3, S4.
- **Depends on:** Task 2.
- **Files:** `crates/aitm-scan-checks-http/src/xss.rs` (modify),
  `crates/aitm-scan-checks-http/src/redirect.rs` (modify),
  `crates/aitm-scan-checks-http/tests/support/mod.rs` (create: the scripted
  `ProbeHost` every check test reuses),
  `crates/aitm-scan-checks-http/tests/native_reflection.rs` (create).
- **Change:**
  1. `tests/support/mod.rs`: `pub struct ScriptedHost { ... }` implementing
     `aitm_scan_model::ProbeHost` from a caller-supplied table
     `Vec<(payload_substring, ProbeResponse)>` plus a baseline, recording every
     `Payload` sent in order (`pub fn sent(&self) -> Vec<String>`), with configurable
     `budget_left`, `deadline`, `cancelled` and a `baseline_fails: bool` switch.
     `pub fn point(kind: InsertionKind, name: &str, url: &str) -> InsertionPoint`.
  2. `xss.rs`: `pub fn check() -> Arc<dyn Check>` over
     `struct XssReflected { meta: CheckMeta }`. Meta: `id "xss-reflected"`, `class "xss"`,
     `lanes [Http]`, `kinds [query, body_param, json_value, xml_value, multipart_value,
     header, path_segment, param_name_query]`, `intensity Light`, `cost Light`,
     `technique Reflected`, `severity High`, `confidence_max Certain`,
     `needs_baseline false`, `wants_traits None`, `cwe Some(79)`, `origin Native`.
     Algorithm: marker `aitm` + the host's marker, three context probes
     (`<MARKER>x</MARKER>`, `"><MARKER>`, `';MARKER//`), at most 3 probes; a hit is
     the probe string surviving **verbatim** in a response whose content-type is
     HTML. Verdict `Vulnerable`/`Certain` with
     `Evidence { payload, matched: excerpt_around(...), probe_flows }` and a
     `PocHint { assertions: vec![Assertion::Status(status), Assertion::Word { word: marker_probe, part: MatchPart::Body }], control: Some(ControlHint { payload: marker.clone(), expect: vec![Assertion::Not(Box::new(Assertion::Word { word: marker_probe, part: MatchPart::Body }))] }) }`.
  3. `redirect.rs`: `pub fn check() -> Arc<dyn Check>` over
     `struct OpenRedirect { meta: CheckMeta }`. Meta: `id "open-redirect"`,
     `class "open-redirect"`, `kinds [query, body_param, json_value, header]`,
     `intensity Light`, `cost Light`, `technique Reflected`, `severity Medium`,
     `confidence_max Certain`, `wants_traits Some(vec![PointTrait::Url])`,
     `cwe Some(601)`. The canary target is the constant
     `pub(crate) const REDIRECT_CANARY: &str = "https://aitm-redirect.invalid/";`
     (RFC 2606 `.invalid`, so a following client resolves nothing); three payload
     forms (absolute, scheme-relative `//aitm-redirect.invalid/`, and a backslash
     variant), at most 3 probes. A hit is a 3xx whose `Location` host is
     `aitm-redirect.invalid`. `PocHint` asserts the status and
     `Assertion::Regex { regex: "(?i)^location:\\s*.*aitm-redirect\\.invalid", part: MatchPart::Header }`.
     The check **never** sends a request to the canary.
- **Test** (`tests/native_reflection.rs`):
  - `xss_reflected_is_certain_when_the_marker_survives_in_html`: host returns
    `content-type: text/html; charset=utf-8` and a body embedding the first probe ->
    `outcome == Outcome::Vulnerable`, `confidence == Confidence::Certain`,
    `verdict.poc_hint.is_some()`, and the hint's first assertion is
    `Assertion::Status(200)`.
  - `xss_reflected_is_clean_when_the_marker_is_entity_encoded`: body contains
    `&lt;aitmabcd&gt;` only -> `outcome == Outcome::Clean` and `poc_hint.is_none()`.
  - `xss_reflected_is_clean_on_a_json_content_type`: verbatim reflection but
    `application/json` -> `Outcome::Clean`.
  - `xss_reflected_sends_at_most_three_probes`: a clean host ->
    `host.sent().len() == 3`.
  - `open_redirect_is_certain_on_a_302_to_the_canary`: status `302`,
    `location: https://aitm-redirect.invalid/` -> `Vulnerable`/`Certain`,
    `evidence.payload == Some("https://aitm-redirect.invalid/".to_string())`.
  - `open_redirect_is_clean_when_location_stays_on_the_origin`: `location: /home` ->
    `Outcome::Clean`.
  - `open_redirect_wants_the_url_trait`:
    `check().meta().wants_traits == Some(vec![PointTrait::Url])`.
  - `neither_check_sends_a_request_to_the_canary_host`: every recorded payload is a
    value placed at the point; `host.sent()` contains no entry whose target
    authority is `aitm-redirect.invalid` (the host records the point's URL, which
    stays the target's).
- **Done when:** `cargo test -p aitm-scan-checks-http --offline` passes and the full
  gate passes.

### Task 6: raw h2 — the connection driver

- **Satisfies:** AC T3-3 (one connection per check, <= 8 streams), spec D8.2,
  session call S6.
- **Depends on:** Task 4 (same file; strictly sequential).
- **Files:** `crates/aitm-proto-http/src/raw_h2.rs` (modify: add the async driver).
- **Change:**
  - `pub struct RawH2Target { pub scheme: String, pub authority: String }`
  - `pub enum RawH2Mode { SingleRequest, RapidReset { pairs: u8 }, SettingsOnly }`
  - `pub struct RawH2Plan { pub target: RawH2Target, pub headers: Vec<RawHeader>, pub mode: RawH2Mode, pub streams: u8 }`
  - `pub enum StreamOutcome { Headers { status: Option<u16> }, Reset { error_code: u32 }, Refused, Timeout }`
  - `pub struct RawH2Observation { pub settings: Vec<(u16, u32)>, pub streams: Vec<StreamOutcome>, pub goaway: Option<(u32, u32)>, pub connection_closed: bool, pub elapsed_ms: u32 }`
  - Caps, all non-overridable: `pub const MAX_RAW_STREAMS: u8 = 8;`,
    `const RAW_READ_BUDGET: usize = 256 * 1024;`,
    `const RAW_READ_TIMEOUT: Duration = Duration::from_secs(5);`,
    `const RAW_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);`.
  - `pub struct RawH2Client { tls: TlsVerify, dialer: Arc<dyn Dialer>, resolver: Arc<dyn HostResolver> }`
    with `pub enum TlsVerify { WebPki, AcceptAny }`,
    `pub fn new(verify: TlsVerify) -> Self`, `pub fn with_dialer(..)`,
    `pub fn with_resolver(..)`, and
    `pub async fn probe(&self, plan: &RawH2Plan) -> Result<RawH2Observation>`.
  - `probe` refuses before any byte when `plan.streams > MAX_RAW_STREAMS` or
    `RapidReset { pairs }` exceeds it (`Err` naming "at most 8 streams"), then: dial
    once -> TLS with ALPN `[b"h2"]` (an `https` target; a plaintext target skips TLS)
    -> write `PREFACE` + an empty SETTINGS frame -> read frames until the peer's
    SETTINGS arrives, ACK it -> per mode, write the HEADERS block(s)
    (`END_HEADERS | END_STREAM`, odd stream ids 1, 3, 5, ...; `RapidReset` follows
    each HEADERS with `RST_STREAM(CANCEL=0x8)`) -> read until every stream has an
    outcome, a `GOAWAY` arrives, the connection closes, the read budget is spent or
    `RAW_TOTAL_TIMEOUT` expires -> close the connection. Exactly **one** connection
    per call and **no** retry.
  - The driver never writes a `cookie`, `authorization`, `proxy-authorization` or
    `set-cookie` field: `probe` returns `Err` naming the header if `plan.headers`
    contains one (a belt-and-braces guard, since the checks build the list).
- **Test** (`raw_h2.rs` `#[cfg(test)]`, `#[tokio::test]`, a `ScriptedServer` over
  `tokio::io::duplex` that reads the preface and replays a fixed frame script):
  - `probe_reads_the_servers_settings_and_closes`: the script sends
    `SETTINGS(3=128, 4=65535)` -> `obs.settings == vec![(3, 128), (4, 65535)]`, the
    dialer's call count is `1`, and the server observed the 24-byte preface first.
  - `a_reset_stream_is_recorded_with_its_error_code`: the script answers
    `RST_STREAM(error 1)` on stream 1 ->
    `obs.streams == vec![StreamOutcome::Reset { error_code: 1 }]`.
  - `an_answered_stream_records_its_status`: the script answers HEADERS `0x88` ->
    `obs.streams == vec![StreamOutcome::Headers { status: Some(200) }]`.
  - `the_plan_refuses_more_than_eight_streams`: `streams: 9` -> `Err` whose string
    contains `"at most 8 streams"` and the dialer's call count is `0`.
  - `rapid_reset_opens_exactly_the_requested_pairs`: `RapidReset { pairs: 8 }` ->
    the server counted `8` HEADERS frames and `8` RST_STREAM frames on stream ids
    `1, 3, 5, 7, 9, 11, 13, 15`.
  - `a_goaway_ends_the_probe`: the script sends `GOAWAY(last 1, error 11)` ->
    `obs.goaway == Some((1, 11))` and `obs.streams.len() <= 8`.
  - `a_silent_server_times_out_bounded` (`#[tokio::test(start_paused = true)]`): no
    reply -> every stream is `StreamOutcome::Timeout` and the call returns within
    `RAW_TOTAL_TIMEOUT`.
  - `the_driver_refuses_a_cookie_header`: a plan carrying `RawHeader::new("cookie", "a=b")`
    -> `Err` whose string contains `"cookie"`, dialer call count `0`.
  - `the_read_budget_is_enforced`: a server that streams unbounded SETTINGS frames ->
    the probe ends with `obs.connection_closed == true` after at most
    `RAW_READ_BUDGET` bytes.
- **Done when:** `cargo test -p aitm-proto-http --offline` passes and the full gate passes.

### Task 7: native `sqli-boolean`

- **Satisfies:** AC T3-4 (the boolean half), spec D8.2, D2 (`Speed`/`Accuracy`
  mappings), research 17 §3.6 (the ZAP rule).
- **Depends on:** Task 2 (and Task 5 for `tests/support/mod.rs`; if Task 5 has not
  landed, create the support module here instead and tell the orchestrator).
- **Files:** `crates/aitm-scan-checks-http/src/sqli_boolean.rs` (modify),
  `crates/aitm-scan-checks-http/tests/native_sqli_boolean.rs` (create).
- **Change:** `pub fn check() -> Arc<dyn Check>` over
  `struct SqliBoolean { meta: CheckMeta }`. Meta: `id "sqli-boolean"`, `class "sqli"`,
  `kinds [query, body_param, json_value, xml_value, multipart_value, header, cookie,
  path_segment]`, `intensity Medium`, `cost Medium`, `technique Boolean`,
  `severity Critical`, `confidence_max Firm`, `needs_baseline true`,
  `cwe Some(89)`, `origin Native`. No `PocHint` (D6's must-hint list names the Rhai
  `sqli-error` technique, not the blind one; a blind differential has no stable
  response assertion), so a boolean issue never produces a `FindingRecord`.
  Algorithm, in order:
  1. `host.baseline()` (cached by the lane, 1 probe).
  2. **Control re-send** of the point's own `example` value; if it does not match the
     baseline within `matching::length_differs`, return `Outcome::Inconclusive`
     ("the page is not stable enough for a boolean differential") without probing
     further — ZAP's rule that the original is re-sent because a payload may have
     changed state.
  3. Pairs, in order, limited by `Speed` (`fast` 2, `normal` 4, `thorough` 8 — D2):
     `(" AND 1=1", " AND 1=2")`, `("' AND '1'='1", "' AND '1'='2")`,
     `("\" AND \"1\"=\"1", "\" AND \"1\"=\"2")`, `(" OR 1=1", " OR 1=2")`,
     then the same four with a leading `)`.
  4. A pair hits when the true arm matches the baseline and the false arm differs
     from both. Repeat a hit `Accuracy` times (`fewer_false_negatives` 1, `normal` 2,
     `fewer_false_positives` 3); every repeat must agree.
  5. Hard cap `const MAX_BOOLEAN_PROBES: u32 = 12;` per point, plus
     `host.budget_left()`, `host.deadline()` and `host.cancelled()` checks between
     probes.
  Verdict on a hit: `Vulnerable`/`Firm` with
  `Evidence { payload, diff: Some(Diff { baseline_len, true_len, false_len }), probe_flows, baseline_flow }`
  and a `detail` naming the pair and the three lengths.
- **Test** (`tests/native_sqli_boolean.rs`, scripted host; bodies are generated
  `"x".repeat(n)` so lengths are exact):
  - `a_true_matching_and_false_diverging_pair_is_firm`: baseline 600 B, control 600 B,
    `" AND 1=1"` 600 B, `" AND 1=2"` 120 B, repeats agreeing ->
    `outcome == Outcome::Vulnerable`, `confidence == Confidence::Firm`,
    `evidence.diff == Some(Diff { baseline_len: 600, true_len: 600, false_len: 120 })`,
    `verdict.poc_hint.is_none()`.
  - `an_unstable_page_is_inconclusive`: control 300 B against a 600 B baseline ->
    `outcome == Outcome::Inconclusive` and `host.sent().len() == 2` (baseline +
    control only).
  - `a_pair_that_does_not_diverge_is_clean`: every arm 600 B ->
    `outcome == Outcome::Clean`.
  - `accuracy_normal_repeats_the_hit_once`: with `Accuracy::Normal` the hit is probed
    twice -> `host.sent().iter().filter(|p| p.contains("1=2")).count() == 2`.
  - `the_check_never_exceeds_twelve_probes`: a host that always differs ->
    `host.sent().len() <= 12`.
  - `the_check_stops_when_the_budget_is_gone`: `budget_left == 1` ->
    `host.sent().len() <= 1` and `outcome == Outcome::Inconclusive`.
- **Done when:** `cargo test -p aitm-scan-checks-http --offline` passes and the full
  gate passes.

### Task 8: native `sqli-time` and `cmdi-time`

- **Satisfies:** AC T3-4 (the timing half, including "<= 8 probes per point" and
  "never sleeps"), spec D4 ("Timing without `sleep`"), D8.2.
- **Depends on:** Task 2.
- **Files:** `crates/aitm-scan-checks-http/src/blind_timing.rs` (modify),
  `crates/aitm-scan-checks-http/tests/native_timing.rs` (create).
- **Change:** one generic `struct TimingCheck { meta: CheckMeta, families: Vec<Family> }`
  with `struct Family { name: &'static str, template: fn(f32) -> String }`, exposed as
  `pub fn sqli_time() -> Arc<dyn Check>` and `pub fn cmdi_time() -> Arc<dyn Check>`.
  - `sqli-time`: `class "sqli"`, `technique Timing`, `severity Critical`,
    `confidence_max Firm`, `intensity Medium`, `cost Medium`, `needs_baseline true`,
    `cwe Some(89)`, kinds as `sqli-boolean`. Families in order: `mysql`
    (`"' AND SLEEP({n})-- "` and the numeric form), `postgres` (`"'||pg_sleep({n})--"`),
    `mssql` (`"'; WAITFOR DELAY '0:0:{n}'--"`).
  - `cmdi-time`: `class "cmdi"`, `cwe Some(78)`, same axes. Families: `sh`
    (`"; sleep {n}"`), `sh_subshell` (`"$(sleep {n})"`), `windows`
    (`"& timeout /T {n}"`).
  - Delay schedule (research 17 §3.6, alternating long/short):
    `[1.0, 3.0, 1.0, 3.0]` at `Speed::Fast|Normal`, `[2.0, 5.0, 2.0, 5.0]` at
    `Speed::Thorough`. **At most 4 probes per family** and
    `const MAX_TIMING_PROBES_PER_POINT: u32 = 8;` across families, so at most two
    families are tried per point.
  - The check **never sleeps**: it sends the payload and reads
    `ProbeResponse.elapsed_ms`. `tokio::time::sleep` and `std::thread::sleep` must
    not appear in the file.
  - Verdict on `timing::correlated(&fit)` being true: `Vulnerable`/`Firm`,
    `Evidence { payload, timing: Some(fit), probe_flows, baseline_flow }`, and a
    `detail` of the form
    `"<family>: observed delay tracks the requested delay (r=<r:.2>, slope=<slope:.0> ms/s)"`
    — the derived `correlated` statement AC T3-4 reads (see spec gap **G2**).
    No `PocHint` (a timing differential has no response assertion).
- **Test** (`tests/native_timing.rs`, scripted host whose table maps a payload
  substring to an `elapsed_ms`):
  - `sqli_time_is_firm_when_the_delays_correlate`: baseline 40 ms; `SLEEP(1)` ->
    1040 ms, `SLEEP(3)` -> 3060 ms, repeats 1030/3090 ->
    `outcome == Outcome::Vulnerable`, `confidence == Confidence::Firm`,
    `evidence.timing.as_ref().unwrap().r >= 0.85`, slope in `950.0..=1050.0`,
    `host.sent().len() == 4`.
  - `sqli_time_is_clean_on_a_flat_target`: every probe 45 ms -> `Outcome::Clean` and
    `host.sent().len() <= 8`.
  - `cmdi_time_is_firm_on_the_sh_family`: `sleep 1` -> 1050 ms, `sleep 3` -> 3070 ms
    -> `Vulnerable`/`Firm` with `detail` containing `"sh:"`.
  - `the_check_never_exceeds_eight_probes_per_point`: a host where no family
    correlates -> `host.sent().len() == 8` (two families x 4).
  - `the_check_never_sleeps`: wrap the run in `std::time::Instant::now()` with a host
    that returns instantly but reports `elapsed_ms: 3000`; assert the measured wall
    time is `< Duration::from_millis(250)`.
  - `no_sleep_call_in_the_source`:
    `assert!(!include_str!("../src/blind_timing.rs").contains("sleep("))` — a literal
    source pin mirroring AC T3-4's "the scripts never call `sleep`".
  - `a_cancelled_job_stops_after_the_current_probe`: `cancelled == true` ->
    `host.sent().len() <= 1` and `outcome == Outcome::Inconclusive`.
- **Done when:** `cargo test -p aitm-scan-checks-http --offline` passes and the full
  gate passes.

### Task 9: the five observe-only h2 checks

- **Satisfies:** AC T3-3, spec D8.2 (the five ids), session call S6, anti-goal "no
  DoS confirmation".
- **Depends on:** Task 6.
- **Files:** `crates/aitm-scan-checks-http/src/h2_observe.rs` (modify),
  `crates/aitm-scan-checks-http/tests/native_h2_observe.rs` (create).
- **Change:**
  1. Test seam: `pub trait RawH2Runner: Send + Sync { fn run<'a>(&'a self, plan: RawH2Plan) -> BoxFuture<'a, anyhow::Result<RawH2Observation>>; }`
     and `pub struct RealRawH2Runner { client: aitm_proto_http::raw_h2::RawH2Client }`.
     `pub fn h2_checks(runner: Arc<dyn RawH2Runner>) -> Vec<Arc<dyn Check>>`;
     `catalogue.rs` passes the real one.
  2. `struct OncePerAuthority { seen: Mutex<HashMap<String, Instant>> }` with a
     10-minute TTL: the first point of an authority runs the probe; later points
     return `Outcome::Inconclusive` with `detail: "already observed for this authority"`
     and send nothing. This is what makes "each check opened <= 1 connection"
     (AC T3-3) true under a scheduler that schedules per insertion point (spec gap
     **G1**).
  3. Every check: call `host.baseline()` **first**; on error return
     `Outcome::Inconclusive` ("baseline refused; not probing") **without** touching
     the runner (S6). Derive the authority from the point's `url`.
  4. The five checks. All are `lanes [Http]`, `intensity Medium` (never `Intrusive`),
     `technique Observe` (`Malformed` for the two malformed-header ones),
     `kinds [query, body_param, header, cookie, path_segment]`, `origin Native`,
     `needs_baseline true`:

     | id | class | severity | confidence_max | cwe | plan | reports |
     |---|---|---|---|---|---|---|
     | `h2-settings-observe` | `h2-settings` | Info | Firm | None | `SettingsOnly`, 0 streams | `Vulnerable` + Info with the advertised pairs in `detail`; `Clean` when the peer sent no SETTINGS |
     | `h2-pseudo-header-validation` | `h2-pseudo-header` | Medium | Firm | Some(444) | 3 streams: missing `:path`; duplicate `:method`; a pseudo-header after a regular header | `Clean` when every stream is `Reset`/`Refused`/4xx; `Vulnerable` when any answers 2xx/3xx |
     | `h2-header-crlf-tolerance` | `h2-header-crlf` | Medium | Firm | Some(113) | 2 streams: a CRLF in a header **value**; a CRLF in a header **name** | same rule |
     | `h2-cl-te-downgrade-indicator` | `h2-smuggling-indicator` | Info | Tentative | Some(444) | 1 stream carrying `content-length: <real+1>` and 1 carrying `transfer-encoding: chunked`; **detect only, never a second request** | `Vulnerable` + Info/Tentative when a stream is answered rather than reset; `Clean` otherwise |
     | `h2-rapid-reset-mitigation` | `h2-rapid-reset` | Info | Firm | Some(400) | `RapidReset { pairs: 8 }` | `Clean` when the peer sends `GOAWAY` or closes; `Vulnerable` + Info "no reset-rate mitigation observed in 8 reset pairs" when it does not |

     An observe check reports by returning `Outcome::Vulnerable` with a `CheckMeta.severity`
     of `Info`, because the engine creates an issue from a vulnerable verdict and the
     issue's severity comes from the meta (call **B7**).
  5. No check supplies a `PocHint` (none is in D6's must-hint list; a raw-frame probe
     is not expressible as a PoC HTTP step).
  6. When the authority does not speak h2 (the runner's dial/ALPN fails), every check
     returns `Outcome::Inconclusive` with `detail: "origin does not negotiate h2"` —
     never an error, never a job failure.
- **Test** (`tests/native_h2_observe.rs`, a `FakeRunner` recording plans and
  returning scripted observations):
  - `settings_observe_reports_the_advertised_values`: observation
    `settings == vec![(3, 128), (4, 65535)]` -> `Outcome::Vulnerable`,
    `meta().severity == aitm_poc::Severity::Info`, and `detail` contains
    `"max_concurrent_streams=128"` and `"initial_window_size=65535"`.
  - `pseudo_header_validation_is_clean_when_every_stream_is_reset`: three
    `StreamOutcome::Reset { error_code: 1 }` -> `Outcome::Clean`, and the plan the
    runner saw had `streams == 3`.
  - `pseudo_header_validation_is_vulnerable_when_a_malformed_stream_is_answered`:
    one `Headers { status: Some(200) }` -> `Outcome::Vulnerable`,
    `confidence == Confidence::Firm`.
  - `crlf_tolerance_sends_one_name_and_one_value_probe`: the plan's headers contain
    exactly one field whose **value** bytes contain `\r\n` and one whose **name**
    bytes do; `streams == 2`.
  - `rapid_reset_is_clean_when_the_peer_sends_goaway`: `goaway == Some((15, 11))` ->
    `Outcome::Clean`; with `goaway == None` -> `Outcome::Vulnerable` and `detail`
    contains `"no reset-rate mitigation observed"`.
  - `rapid_reset_never_opens_more_than_eight_pairs`: the recorded plan is
    `RawH2Mode::RapidReset { pairs: 8 }` and `plan.streams == 8`.
  - `every_h2_check_calls_baseline_before_it_dials`: a host whose `baseline()` errors
    -> every check returns `Outcome::Inconclusive` and `runner.calls() == 0`.
  - `an_h2_check_runs_once_per_authority`: the same check run on two points of
    `origin.test:443` -> `runner.calls() == 1` and the second verdict is
    `Outcome::Inconclusive` with `detail == "already observed for this authority"`.
  - `no_h2_check_is_intrusive`: every meta has `intensity == Intensity::Medium`.
  - `no_h2_check_supplies_a_poc_hint`: every verdict's `poc_hint` is `None`.
- **Done when:** `cargo test -p aitm-scan-checks-http --offline` passes and the full
  gate passes.

### Task 10: `checks()` returns the full native list

- **Satisfies:** spec D1 ("`checks()` ... empty in the T1a skeleton; T3 fills it"),
  D12 row T3, AC T3-3/T3-4/T3-5 (the catalogue half).
- **Depends on:** Tasks 5, 7, 8, 9.
- **Files:** `crates/aitm-scan-checks-http/src/catalogue.rs` (modify),
  `crates/aitm-scan-checks-http/src/lib.rs` (modify: doc only, the `pub use` already
  exists), `crates/aitm-scan-checks-http/tests/catalogue.rs` (create).
- **Change:** `pub fn checks() -> Vec<Arc<dyn Check>>` returns, in id order, the ten
  native checks: `cmdi-time`, `h2-cl-te-downgrade-indicator`, `h2-header-crlf-tolerance`,
  `h2-pseudo-header-validation`, `h2-rapid-reset-mitigation`, `h2-settings-observe`,
  `open-redirect`, `sqli-boolean`, `sqli-time`, `xss-reflected`. The h2 checks are
  built with `RealRawH2Runner` (`TlsVerify::AcceptAny`, see call **B5**). Replace the
  T1a skeleton test in `lib.rs`.
- **Test** (`tests/catalogue.rs`):
  - `checks_returns_every_native_id`: the sorted ids are exactly
    `["cmdi-time", "h2-cl-te-downgrade-indicator", "h2-header-crlf-tolerance",
      "h2-pseudo-header-validation", "h2-rapid-reset-mitigation", "h2-settings-observe",
      "open-redirect", "sqli-boolean", "sqli-time", "xss-reflected"]`
    and `checks().len() == 10`.
  - `every_meta_is_well_formed`: for each — `origin == CheckOrigin::Native`,
    `lanes == vec![LaneKind::Http]`, `!kinds.is_empty()`, `!description.is_empty()`,
    `!class.is_empty()`, `intensity <= Intensity::Medium`.
  - `every_class_is_unique_per_h2_check`: the five h2 classes are
    `["h2-cl-te-downgrade-indicator" -> "h2-smuggling-indicator", ...]`, i.e. the five
    class tokens are pairwise distinct (so D6's dedupe never merges two different h2
    observations).
  - `the_shared_classes_match_the_taxonomy`: `sqli-boolean` and `sqli-time` both have
    `class == "sqli"`; `xss-reflected` has `class == "xss"`; `open-redirect` has
    `class == "open-redirect"`.
  - `ids_are_verb_safe`: every id matches `^[a-z0-9][a-z0-9-]*$` (so `check.<id>` is a
    legal verb).
- **Done when:** `cargo test -p aitm-scan-checks-http --offline` passes,
  `cargo test -p aitm --lib --offline wire` still passes (the binary's slot count
  changes from `0`; if `crates/aitm/src/wire.rs`'s T1a test pins the literal `0`,
  **do not edit it** — report it to the orchestrator as the one line Task 18 re-pins,
  since `crates/aitm/src/**` is not a T3 file), and the full gate passes.

### Task 11: Rhai switchover — harness, two new scripts, two retirements, pin re-point

> **Blocked until T1b is on `main`.** Designated "integration, part 1": the only
> non-final task permitted to edit integration-shared files, because the verb-name
> delta and the pin edit must be one commit (see "The T1b landing gate").

- **Satisfies:** AC T3-5, spec D4 (the `add_check` contract), D8.2 (new
  `check-nosqli-json`, `check-header-reflection`; retire the two native-ised
  scripts), D12 "Integration-shared files"; session calls S3, S4, S5.
- **Depends on:** Task 10; **T1b merged to `main`**.
- **Files:** `git merge origin/main` (resolve per the sibling note, below);
  `scripts/bundled/active/check-xss.rhai` (**delete**),
  `scripts/bundled/active/check-open-redirect.rhai` (**delete**),
  `scripts/bundled/active/check-nosqli-json.rhai` (create),
  `scripts/bundled/active/check-header-reflection.rhai` (create),
  `crates/aitm-scan-checks-http/Cargo.toml` (modify: dev-dep `rhai`),
  `crates/aitm-scan-checks-http/tests/rhai_harness/mod.rs` (create),
  `crates/aitm-scan-checks-http/tests/rhai_new_scripts.rs` (create),
  and the integration-shared pins: `crates/aitm/tests/bundled_startup.rs`,
  `crates/aitm-plugin-rhai/tests/bundled_scripts.rs`.
- **Change:**
  1. Merge `origin/main`. The five known conflicts and their resolutions are in the
     sibling note
     `/Users/matt/Library/Application Support/Claude-3p/side-session-notes/local_64454d84-e818-4030-b0ab-db14000cd754/t1b-merge-t1a-over-main-conflicts.md`
     (root `Cargo.toml` members, `Cargo.lock`, `crates/aitm/src/wire.rs` tests,
     `crates/aitm-proto-l4/src/capture.rs` tests, `crates/aitm-proto-l4/src/commands/mod.rs`
     imports). If T1a has already merged to `main` as a squash, those conflicts are
     absent; say which applied.
  2. **Test-only Rhai harness** (`tests/rhai_harness/mod.rs`), pinned
     `rhai = { version = "1.27", features = ["sync"] }` as a dev-dependency (the same
     pin as `crates/aitm-plugin-rhai/Cargo.toml`). It is **not** the real bridge:
     - `pub struct Harness { ... }` with `pub fn load(path: &Path) -> anyhow::Result<Declared>`:
       builds an engine, registers a `reg` type with
       `add_check(meta: rhai::Map, body: rhai::FnPtr)` recording the pair, registers a
       `probe` namespace backed by a caller-supplied response table
       (`pub struct FakeResponses { pub table: Vec<(String, FakeResponse)>, pub baseline: FakeResponse }`
       keyed by payload substring, each entry giving `status`, `headers`, `body`,
       `elapsed_ms`), plus `probe.marker()`, `probe.budget_left()`,
       `probe.timing_fit(..)` (delegating to `aitm_scan_checks_http::timing`),
       `probe.levenshtein_ratio(a, b)` and the shipped free functions the scripts use
       (`url_encode`, `regex_match`, `contains_ci`, `rand_text_alpha`), then runs
       `load(reg)`.
     - `pub struct Declared { pub meta: rhai::Map, pub body: rhai::FnPtr }` with
       `pub fn meta_as_check_meta(&self) -> anyhow::Result<aitm_scan_model::CheckMeta>`
       (rhai `Map` -> `serde_json::Value` -> `CheckMeta`) and
       `pub fn run(&self, point: rhai::Map, responses: &FakeResponses) -> anyhow::Result<aitm_scan_model::Verdict>`
       (closure result map -> `serde_json::Value` -> `Verdict`, with a plain string
       read as `inconclusive`, per D4).
     - `pub fn matchers_parse(verdict_map: &rhai::Map) -> anyhow::Result<Vec<aitm_poc::Assertion>>`:
       serialises each `poc_hint.matchers` entry to YAML and parses
       `aitm_poc::Assertion` from it (fact 8).
     - A `//!` paragraph states plainly: **this harness is the inner loop only.** The
       real `add_check` bridge and `probe.*` host fns are T1b's; live proof runs
       through the real engine (Task 17), and before T1b merged, the manual
       `check.<id>` verb over the real bus was the only live path.
  3. `check-nosqli-json.rhai`: id `nosqli-json`, class `nosqli`, `kinds
     [json_value]`, `intensity medium`, `cost light`, `technique boolean`,
     `severity critical`, `confidence_max firm`, `cwe 943`, one declaration map and
     one closure, prose comments, `probe.send` only (no hand-built `?param=`). It
     sends the typed operator payloads (`{"$ne": null}`, `{"$gt": ""}`) and a
     control, and reports a result-set/length differential.
  4. `check-header-reflection.rhai`: id `header-reflection`, class `xss` (S3's class
     list has no header-reflection token; call **B8**), `kinds [header, cookie]`,
     `technique reflected`, `severity medium`, `confidence_max certain`, `cwe 79`. It
     places `probe.marker()` in the header and reports when the marker comes back
     unencoded in the body of an HTML response or verbatim in a response header.
  5. Delete `check-xss.rhai` and `check-open-redirect.rhai` (S4). The README row
     change is Task 16.
  6. Pin re-point, read from the tree (not guessed):
     - `crates/aitm/tests/bundled_startup.rs` `EXPECTED_COMMANDS` becomes the fifteen
       script ids as `check.<id>` plus the three `l4.*` entries:
       `check.cmdi`, `check.cors`, `check.crlf`, `check.header-reflection`,
       `check.headers`, `check.ldapi`, `check.methods`, `check.nosqli`,
       `check.nosqli-json`, `check.path_traversal`, `check.paths`, `check.sqli`,
       `check.ssrf`, `check.ssti`, `check.xxe`, `l4.recon`, `l4.tcp_probe`,
       `l4.udp_probe`. (`check.xss` and `check.open_redirect` are gone; the native
       `check.xss-reflected` / `check.open-redirect` are registered by the engine's
       bridge from `native_checks`, which that test does not load — note it in the
       test's doc comment.)
     - `crates/aitm-plugin-rhai/tests/bundled_scripts.rs::command_scripts_register_their_commands`
       becomes `..._register_their_checks`: an `active/*.rhai` script registers at
       least one **check**; the `l4/*.rhai` scripts keep the command assertion.
- **Test:**
  - `the_two_new_scripts_declare_one_check_each_with_valid_meta`: for each file,
    `Harness::load` yields exactly one `Declared`, and `meta_as_check_meta()` gives
    `id == "nosqli-json"` (resp. `"header-reflection"`) with
    `kinds == vec![InsertionKind::JsonValue]` (resp.
    `vec![InsertionKind::Header, InsertionKind::Cookie]`).
  - `a_meta_missing_kinds_fails_naming_kinds`: a fixture script in the test file whose
    meta omits `kinds` -> the error string contains `"kinds"`.
  - `the_new_scripts_find_their_vulnerable_shape_and_clear_the_patched_one`:
    `nosqli-json` against a response table where `{"$ne": null}` returns a 900-byte
    body and the control returns 120 bytes -> `outcome == Outcome::Vulnerable`;
    against a table where both return 120 bytes -> `outcome == Outcome::Clean`. Same
    two-way assertion for `header-reflection` (marker echoed in an HTML body vs
    entity-encoded).
  - `a_plain_string_return_is_read_as_inconclusive`: a fixture closure returning
    `"nothing found"` -> `Verdict { outcome: Outcome::Inconclusive, detail: "nothing found", .. }`.
  - `the_retired_scripts_are_gone`: `check-xss.rhai` and `check-open-redirect.rhai`
    do not exist.
  - `cargo test -p aitm --test bundled_startup` passes with the eighteen pinned names
    (quote the output).
- **Done when:** the merge is clean, every test above passes, `cargo test -p aitm
  --test bundled_startup` and `cargo test -p aitm-plugin-rhai --test bundled_scripts`
  pass, and the full gate passes **in the Terminal** (the `aitm` integration tests
  bind ports).

### Tasks 12-15: convert the thirteen shipped `active/*.rhai` scripts

> Blocked on Task 11. The four tasks touch disjoint script files and disjoint test
> files, so they fan out to four parallel coders.

Every converted script follows the same shape (spec Constraints "Rhai
human-readability", D4, session call S5):

- one `const META = #{ ... }` declaration map with exactly the `CheckMeta` wire keys;
- one `reg.add_check(META, |point| { ... })` closure taking the D4 point map
  (`kind`, `name`, `path`, `url`, `method`, `example`, `traits`);
- probes through `probe.send(payload)` / `probe.baseline()` / `probe.marker()` —
  **never** a hand-built `?param=` URL and never `http.send` with a crafted query;
- a verdict map with the `Verdict` wire keys (`outcome`, `confidence`,
  `evidence: #{ payload, matched }`, `detail`, and `poc_hint` where required);
- prose comments, no JSON-in-strings, no `sleep(`;
- the detection logic and payload sets of the shipped script are preserved except
  where this plan says otherwise.

| Task | Scripts | Ids / classes | poc_hint |
|---|---|---|---|
| **12** | `check-sqli.rhai`, `check-ssti.rhai`, `check-command-injection.rhai` | `sqli`/`sqli` (**error technique only** — the boolean half moves to native `sqli-boolean`, S3), `ssti`/`ssti`, `cmdi`/`cmdi` (**echo marker only** — timing is native `cmdi-time`) | all three **required** |
| **13** | `check-path-traversal.rhai`, `check-xxe.rhai`, `check-ssrf.rhai` | `path_traversal`/`path-traversal` (`wants_traits [filename]`), `xxe`/`xxe` (`kinds [entire_body]`), `ssrf`/`ssrf` (`wants_traits [url]`) | traversal + xxe **required**; ssrf none |
| **14** | `check-crlf-injection.rhai`, `check-nosql-injection.rhai`, `check-ldap-injection.rhai` | `crlf`/`crlf`, `nosqli`/`nosqli`, `ldapi`/`ldapi` | crlf **required** |
| **15** | `check-cors.rhai`, `check-security-headers.rhai`, `check-http-methods.rhai`, `check-sensitive-paths.rhai` | `cors`/`cors`, `headers`/`security-headers`, `methods`/`http-methods`, `paths`/`sensitive-paths` | none |

- **Satisfies (all four):** AC T3-5, spec D4, D6 (the must-hint classes), D8.2,
  session calls S3 and S5.
- **Files (per task):** the named `scripts/bundled/active/*.rhai` files (modify) and
  one new test file each:
  `crates/aitm-scan-checks-http/tests/rhai_injection.rs` (12),
  `crates/aitm-scan-checks-http/tests/rhai_file_and_xml.rs` (13),
  `crates/aitm-scan-checks-http/tests/rhai_crlf_and_nosql.rs` (14),
  `crates/aitm-scan-checks-http/tests/rhai_site_level.rs` (15).
- **Change notes:**
  - Task 12: `check.sqli`'s boolean block is **removed** (native `sqli-boolean`
    owns it); the error-signature block keeps the shipped `SQL_ERR` regex and becomes
    the whole check, `technique: "error"`, `confidence_max: "firm"`.
    `check.cmdi`'s timing block is removed; the split-`echo` marker stays,
    `technique: "reflected"`, `confidence_max: "certain"`.
  - Task 15: the four site-level checks have no natural insertion kind. They declare
    `kinds: ["query", "body_param", "header", "cookie", "path_segment"]` and
    `cost: "light"` so the scheduler attaches them to whatever the node has; D6's
    dedupe collapses the repeats into one issue per origin. This is spec gap **G1**;
    the manual `check.<id>` verb stays the precise way to run them.
  - Every required `poc_hint` uses the PoC matcher vocabulary of fact 8, e.g.
    `poc_hint: #{ matchers: [ #{ type: "word", word: "root:x:0:0", part: "body" } ],
    control: #{ payload: "1", matchers: [ #{ type: "word", word: "root:x:0:0",
    part: "body", negative: true } ] } }`.
- **Test (per task, through the Task 11 harness):** for **each** script,
  - `<id>_declares_one_check_with_valid_meta`: exactly one `Declared`;
    `meta_as_check_meta()` succeeds; `meta.id` and `meta.class` equal the literals in
    the table above; `meta.origin` deserialises as `CheckOrigin::Bundled { path }`
    whose `path` ends with the file name.
  - `<id>_is_vulnerable_against_its_vulnerable_shape`: a response table carrying the
    class's signature (for `sqli`: a body containing
    `"You have an error in your SQL syntax"`; for `ssti`: a body containing `"5767"`;
    for `cmdi`: a body containing the reassembled marker; for `path_traversal`: a body
    containing `"root:x:0:0"`; for `xxe`: the same; for `crlf`: a response header
    `x-aitm-canary`; for `nosqli`/`ldapi`: the operator differential; for `cors`: an
    `access-control-allow-origin` echoing the canary with
    `access-control-allow-credentials: true`; for `headers`: a response missing HSTS
    and CSP; for `methods`: an `allow: GET, PUT, DELETE, TRACE`; for `paths`: a 200 on
    `/.git/HEAD`) -> `outcome == Outcome::Vulnerable`.
  - `<id>_is_clean_against_its_patched_shape`: the negated table -> `Outcome::Clean`.
  - `<id>_supplies_a_parsable_poc_hint` (the required ones only): every matcher in
    `poc_hint.matchers` and in `poc_hint.control.matchers` parses into an
    `aitm_poc::Assertion`, and the list is non-empty.
  - `<id>_never_calls_sleep`: the script source contains no `"sleep("`.
  - `<id>_uses_probe_send_not_a_handbuilt_query`: the source contains
    `"probe.send"` and does **not** contain `"http.send"` or `"url_encode(param)"`.
- **Done when (per task):** `cargo test -p aitm-scan-checks-http --offline` passes,
  `cargo test -p aitm --test bundled_startup` still passes (the verb names are
  unchanged by Tasks 12-15), and the full gate passes.

### Task 16: `scripts/bundled/README.md` and the catalogue sweep test

- **Satisfies:** spec D8.2 ("`scripts/bundled/README.md` is corrected (`script.findings`,
  the catalogue section, the `add_check` shape)"), AC T3-5, session calls S3-S5.
- **Depends on:** Task 15.
- **Files:** `scripts/bundled/README.md` (modify),
  `crates/aitm-scan-checks-http/tests/rhai_catalogue_sweep.rs` (create).
- **Change:**
  1. README corrections: replace the stale `findings.list` sentence with
     `script.findings`; rewrite the "HTTP — active" section as a **catalogue table**
     with one row per check giving `id | class | kinds | intensity | technique |
     confirms`, covering the fifteen Rhai checks **and** the ten native ones (marked
     `native`); add an "Writing a check" subsection with **one** full `add_check`
     example (declaration map + closure + verdict map + `poc_hint`) and the rule that
     a check is scheduled automatically over matching insertion points and is also
     invocable by hand as `check.<id>`; state that `check-xss.rhai` and
     `check-open-redirect.rhai` were retired because `xss-reflected` and
     `open-redirect` are native (a class is single-sourced) and that their manual
     verbs are now `check.xss-reflected` and `check.open-redirect`.
  2. The sweep test, which is the one place the whole directory is asserted.
- **Test** (`tests/rhai_catalogue_sweep.rs`):
  - `every_active_script_declares_exactly_one_check`: every `*.rhai` under
    `scripts/bundled/active/` loads through the harness and yields exactly one
    `Declared`; the count of files is `15`.
  - `every_declared_meta_deserialises_into_check_meta`: all fifteen succeed, and the
    sorted id list is exactly
    `["cmdi", "cors", "crlf", "header-reflection", "headers", "ldapi", "methods",
      "nosqli", "nosqli-json", "path_traversal", "paths", "sqli", "ssrf", "ssti", "xxe"]`.
  - `the_six_poc_classes_supply_a_hint`: the scripts whose class is one of
    `sqli`, `ssti`, `cmdi`, `path-traversal`, `crlf`, `xxe` return a `poc_hint` whose
    matchers all parse as `aitm_poc::Assertion`.
  - `no_active_script_calls_sleep`: no file's source contains `"sleep("`.
  - `no_active_script_registers_a_command`: no file's source contains
    `"add_command"`.
  - `the_readme_table_lists_every_check`: the ids parsed out of the README's
    catalogue table equal the fifteen declared ids plus the ten native ids
    (`checks()`), with no extra and none missing.
- **Done when:** `cargo test -p aitm-scan-checks-http --offline` passes and the full
  gate passes.

### Task 17: live proof over the real bus (no fixtures)

- **Satisfies:** AC T3-1, T3-2, T3-3, T3-4, T3-5; spec Verification ("Acceptance
  evidence is a real scan, over the real bus, against a real target, observed
  independently"); Matt's rule that a fixture/snapshot/mock run is never acceptance
  evidence.
- **Depends on:** Task 16. Needs from other tracks: **T10** (the test target's TLS
  listener with ALPN `h2` + `http/1.1` **and** a per-connection request counter in
  its request log; an h1-only TLS listener; seeds for boolean SQLi, time SQLi, time
  cmdi, SSTI, cmdi echo, traversal, CRLF, XXE, NoSQLi-JSON, LDAPi, header
  reflection) and **T1b** (the job model, the catalogue bridge and the uniform
  `check.<id>` verbs). What each criterion needs is tabulated below.
- **Files:** none (the report is the artifact). The commands run in the **Terminal
  panel**; `git`, port binding and any real core live there.
- **Change / steps:**
  1. Build: `cargo build -p aitm -p aitm-testtarget` (quote the exit code).
  2. Start the target twice, once per mode, on fixed ports:
     `./target/debug/aitm-testtarget-serve --mode vulnerable --port 8099` and
     `--mode patched --port 8098`; note the TLS listener's port from its startup line.
  3. Start a real core with the target's origins in HTTP scope, `findings.dir` set,
     and the bundled catalogue loaded; take the operator token from the 0600 config
     (never print it).
  4. **T3-1** — `scan.start { target: "https://127.0.0.1:<tls-port>", overrides: { http: { version: "auto" } } }`
     on V; poll `scan.status` to `done`; `scan.issues` shows `xss-reflected` and the
     Rhai `sqli` (error) issues; for one issue, `scan.issue { id }` -> take a
     `evidence.probe_flows[0]` -> `flow.detail { id }` and assert
     `response.version == "HTTP/2"` (session call S1); `scan.status.probes.by_lane.http > 0`.
     Re-run on P: neither issue appears.
  5. **T3-2** — the same scan with `http.version: "h1"` -> the evidence flows'
     `response.version == "HTTP/1.1"`. Then `http.version: "h2"` against the target's
     **h1-only** TLS listener -> the job reaches `state: done` with
     `stopped_reason: "errors"`, `probes.errors > 0`, `error` containing
     `h2_not_negotiated`, and the target's request log shows TLS handshakes but **no
     HTTP request**.
  6. **T3-3** — the observe-only set on the hyper listener: `scan.issues
     { class: "h2-settings" }` yields one `info` issue; no `h2-header-crlf` and no
     `h2-pseudo-header` issue exists. From the target's **per-connection request
     counter**, assert each h2 check opened at most one connection and that no
     connection the checks opened carried more than 8 streams.
  7. **T3-4** — on V, `scan.issues { class: "sqli" }` includes a `sqli-boolean` issue
     at `confidence: "firm"`; the time-based issues carry
     `evidence.timing.r >= 0.85` and a slope within 1000 +/- 300 ms/s (the derived
     `correlated` statement, spec gap **G2**); the target's request log shows at most
     8 timing probes per point; `grep -R "sleep(" scripts/bundled/active` is empty.
     None of these on P.
  8. **T3-5** — `scan.checks` lists all twenty-five ids with full `CheckMeta`; the
     manual verbs still work: `check.sqli { url, param }` returns a verdict map, and
     so do `check.xss-reflected` and `check.open-redirect` (the native ids that
     replaced the retired scripts). The scheduled catalogue finds the seeded
     SQLi-error, SSTI, cmdi, traversal, CRLF, XXE, NoSQLi-JSON, LDAPi and
     open-redirect vulns on V and none on P.
  9. **Pre-T1b fallback** (if this task runs before T1b merged, for the native half
     only): drive each native check by hand through the shipped manual verb path and
     read the target's request log for the probe sequence; record plainly in the
     report that the scheduled-catalogue criteria (T3-4's "whole timing check took
     <= 8 probes per point" as scheduled, T3-5) are **not yet proven** and which cell
     will prove them.
  10. A second subscribed `BusClient` records the push lines for the run, as
      independent observation.
- **AC -> dependency map:**

  | AC | Needs from T10 | Needs from T1b |
  |---|---|---|
  | T3-1 | TLS listener with ALPN `h2`; XSS + SQLi-error seeds | job model, `scan.issue`, catalogue bridge |
  | T3-2 | h1-only TLS listener; request log | `probes.errors`, the per-host error ladder, `stopped_reason` |
  | T3-3 | per-connection request counter in the request log | scheduling of the five h2 checks |
  | T3-4 | boolean-SQLi, time-SQLi and time-cmdi seeds; a delayed endpoint | `Accuracy`/`Speed` plumbed into the profile |
  | T3-5 | seeds for all nine classes | `add_check` bridge + uniform `check.<id>` |

- **Test:** the commands above; the proof is their quoted output plus the target's
  request log. A SKIP is a failure of this task, not a pass.
- **Done when:** every step's output is quoted in the report, each criterion is
  marked proven / blocked-on-<track>, and no step was satisfied by a fixture,
  snapshot or in-process model.

### Task 18: integration — merge, re-pin from live `tools/list`, gate, PR

- **Satisfies:** spec D12 "Integration-shared files", Constraints "Contract lists are
  integration-shared", spec Verification.
- **Depends on:** Task 17.
- **Files:** none new. On a merge conflict, only the conflicting hunks; plus the
  integration-shared files if live `tools/list` moved:
  `crates/aitm/tests/frontends.rs` (`EXPECTED_TOOLS`),
  `crates/aitm-tui/src/lib.rs` (`CORE_TOOLS` constant only),
  `crates/aitm-tui/fixtures/bus-fixture.json`,
  `crates/aitm/tests/bundled_startup.rs`,
  `crates/aitm-plugin-rhai/tests/bundled_scripts.rs`; and the one `wire.rs` native-
  check count line if Task 10 reported it.
- **Change / steps** (Terminal for `git` and anything binding a port):
  1. `git fetch origin && git merge origin/main` (merge, not rebase). Verify
     `baseRefName == main` before any merge request (the stacked-PR trap). Note which
     of the sibling note's five conflicts applied.
  2. **Re-pin from live, never from this document**: boot the freshly built core, read
     `tools/list`, and reconcile `EXPECTED_TOOLS`, `CORE_TOOLS` and
     `bus-fixture.json` with it. T3 adds twenty-five `check.<id>` verbs (ten native,
     fifteen bundled) and removes `check.xss` / `check.open_redirect`. No tool-count
     assertion is hard-coded.
  3. Full gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
     cargo test`; quote the final `test result:` lines and `echo $?` (never a grep).
  4. Re-run Task 17's T3-1 and T3-5 steps against the merged tree and quote the
     output, so the proof is of what ships.
  5. `git push origin claude/scanner-v2-t3-4c0d76` (explicit refspec) and open the PR
     **against `main`** with: the plan path, the panel verdicts, the gate output and
     the live proof in the body, plus the stage-6 panel comment on the PR
     (security/quality/spec + dispositions) — a PR without it is not ready.
- **Test:** the commands above.
- **Done when:** the gate exits 0, live `tools/list` equals the contract lists, the
  live proof is re-quoted on the merged tree, and the panel review has no open
  findings.

## File ownership matrix (disjointness check)

| Task | Files |
|---|---|
| 1 | `crates/aitm-proto-http/src/{sender.rs, lib.rs, h2_sender.rs (placeholder), raw_h2.rs (placeholder)}` |
| 2 | `crates/aitm-scan-checks-http/{Cargo.toml, src/lib.rs, src/timing.rs, src/matching.rs, src/{xss,redirect,sqli_boolean,blind_timing,h2_observe,catalogue}.rs (placeholders)}` |
| 3 | `crates/aitm-proto-http/src/h2_sender.rs`, `crates/aitm-proto-http/src/sender.rs` (the one h2 arm) |
| 4 | `crates/aitm-proto-http/src/raw_h2.rs` |
| 5 | `crates/aitm-scan-checks-http/src/{xss.rs, redirect.rs}`, `crates/aitm-scan-checks-http/tests/{support/mod.rs, native_reflection.rs}` |
| 6 | `crates/aitm-proto-http/src/raw_h2.rs` |
| 7 | `crates/aitm-scan-checks-http/src/sqli_boolean.rs`, `crates/aitm-scan-checks-http/tests/native_sqli_boolean.rs` |
| 8 | `crates/aitm-scan-checks-http/src/blind_timing.rs`, `crates/aitm-scan-checks-http/tests/native_timing.rs` |
| 9 | `crates/aitm-scan-checks-http/src/h2_observe.rs`, `crates/aitm-scan-checks-http/tests/native_h2_observe.rs` |
| 10 | `crates/aitm-scan-checks-http/src/{catalogue.rs, lib.rs}`, `crates/aitm-scan-checks-http/tests/catalogue.rs` |
| 11 | `scripts/bundled/active/{check-xss.rhai (del), check-open-redirect.rhai (del), check-nosqli-json.rhai, check-header-reflection.rhai}`, `crates/aitm-scan-checks-http/Cargo.toml`, `crates/aitm-scan-checks-http/tests/{rhai_harness/mod.rs, rhai_new_scripts.rs}`, **integration-shared:** `crates/aitm/tests/bundled_startup.rs`, `crates/aitm-plugin-rhai/tests/bundled_scripts.rs`; plus the merge |
| 12 | `scripts/bundled/active/{check-sqli, check-ssti, check-command-injection}.rhai`, `crates/aitm-scan-checks-http/tests/rhai_injection.rs` |
| 13 | `scripts/bundled/active/{check-path-traversal, check-xxe, check-ssrf}.rhai`, `crates/aitm-scan-checks-http/tests/rhai_file_and_xml.rs` |
| 14 | `scripts/bundled/active/{check-crlf-injection, check-nosql-injection, check-ldap-injection}.rhai`, `crates/aitm-scan-checks-http/tests/rhai_crlf_and_nosql.rs` |
| 15 | `scripts/bundled/active/{check-cors, check-security-headers, check-http-methods, check-sensitive-paths}.rhai`, `crates/aitm-scan-checks-http/tests/rhai_site_level.rs` |
| 16 | `scripts/bundled/README.md`, `crates/aitm-scan-checks-http/tests/rhai_catalogue_sweep.rs` |
| 17 | none (live proof) |
| 18 | none new; the five integration-shared files if live `tools/list` moved; `Cargo.lock` after the merge |

Within a wave no two tasks share a file. `crates/aitm-proto-http/src/sender.rs` is
edited by Task 1 (wave 1) and Task 3 (wave 2), sequentially;
`crates/aitm-proto-http/src/raw_h2.rs` by Tasks 1, 4 and 6, sequentially;
`crates/aitm-scan-checks-http/src/lib.rs` by Tasks 2 and 10, sequentially.
`Cargo.lock` is derived: Tasks 2 and 11 regenerate it as a consequence of their
manifest edits, and Task 18 after the merge.

## Architect's calls in this plan (for the orchestrator/Matt to approve or correct)

- **B1** `HttpSender::send` (the no-policy path used by `flow.replay`, `request.send`
  and the scripts' `http.send`) now offers ALPN `[h2, http/1.1]` and will therefore
  reissue over h2 against an h2 origin, where it was h1-only before. Spec D8.2 says
  `HttpSender` "replaces `Http1Sender`'s behaviour behind the same construction
  site"; `VersionPolicy::Auto` is the default. The visible change is
  `flow.detail`'s `response.version` on a replay. Reverting to h1-by-default would
  mean a replay never exercises the h2 path.
- **B2** The dial seam is a `Dialer` trait returning `Box<dyn ProbeStream>` (rather
  than a boxed stream factory closure), so the duplex-based tests drive the real
  negotiate/cache/dispatch code and the raw-h2 driver reuses the same seam.
- **B3** The ALPN cache is `moka::sync::Cache` with a 10-minute TTL and a 1024-entry
  cap, because `moka` is already a dependency of `aitm-proto-http`; no new crate.
- **B4** `SendError` is an enum with one variant today (`H2NotNegotiated`), so T4/T5
  can add variants without changing the `is_h2_not_negotiated` contract.
  `is_h2_not_negotiated` also matches the `Display` prefix, so the error is still
  recognisable after a bus round trip turns it into a string.
- **B5** A raw-h2 probe does **not** verify the server certificate
  (`TlsVerify::AcceptAny`). Justification: the destination was already authorised
  and reached through the guarded job client (S6), the probe sends **no** cookie,
  `Authorization` or session header, and a self-signed lab target would otherwise be
  unobservable. The alternative — threading the core's `ssl_insecure` posture into
  the checks crate — is an `aitm-core`/T1b change T3 may not make. `TlsVerify` is a
  parameter, so T1b can wire the real posture later. **Flagged for Matt.**
- **B6** The raw-h2 reader decodes only the SETTINGS/RST_STREAM/GOAWAY payloads and
  a statically-indexed `:status`; it does not implement an HPACK **decoder**. The
  observe checks' oracle is reset-versus-answer, so a full decoder would be dead
  weight ("Left to the builder" allows this).
- **B7** An observe-only check reports by returning `Outcome::Vulnerable` with
  `CheckMeta.severity == Info`, because the engine creates an issue from a vulnerable
  verdict and the issue's severity comes from the meta. `Clean` means "observed
  nothing worth reporting". If T1b decides otherwise, the five h2 checks are the
  only consumers.
- **B8** The five h2 checks get five **distinct** class tokens (`h2-settings`,
  `h2-pseudo-header`, `h2-header-crlf`, `h2-smuggling-indicator`, `h2-rapid-reset`)
  rather than one `h2-protocol` class, so D6's class-based dedupe never merges two
  different observations into one issue. The new Rhai `header-reflection` check takes
  class `xss` because S3's taxonomy list is closed and has no header-reflection token.
- **B9** `sqli-boolean`, `sqli-time`, `cmdi-time` and the five h2 checks supply **no**
  `PocHint`, so they yield issues and never `FindingRecord`s: D6's must-hint list
  names the reflected/error techniques, and a blind differential has no stable
  response assertion. `xss-reflected` and `open-redirect` do supply one.
- **B10** The open-redirect canary is `https://aitm-redirect.invalid/` (RFC 2606
  `.invalid`), and the check only reads the `Location` header — it never sends a
  request to the canary, so no stimulus can leave the operator's scope.
- **B11** Probe caps, all constants in the checks crate and none profile-overridable:
  `MAX_BOOLEAN_PROBES = 12` per point, `MAX_TIMING_PROBES_PER_POINT = 8` with at most
  4 per DB/shell family, 3 probes each for `xss-reflected` and `open-redirect`,
  `MAX_RAW_STREAMS = 8`, one raw connection per check per authority per 10 minutes.
- **B12** The `TimingOracle` lives in `aitm-scan-checks-http::timing` as two free
  `pub` functions (`fit`, `correlated`) plus the two ZAP error-range constants, with
  no dependency beyond `aitm-scan-model`, so T1b's `probe.timing_fit` can call it
  without pulling in the checks.
- **B13** Task 11 is "integration, part 1" and is the only non-final task that edits
  integration-shared files. Without it, the gate is red from the first script
  conversion until the final task. **Flagged for Matt** (see the question below).
- **B14** `tests/support/mod.rs`'s `ScriptedHost` is the single fake `ProbeHost` for
  every native-check test, so a `ProbeHost` trait change touches one file.

## Spec gaps found (could not be resolved inside this plan)

- **G1 — no site-level scheduling unit.** Spec D4 says: "**Scheduling.** For each
  insertion point the scheduler selects catalogue entries whose `lanes` contain the
  point's lane, whose `kinds` contain the point's kind, ..." There is no per-node or
  per-origin scheduling unit, yet five native h2 checks and four Rhai checks
  (`cors`, `headers`, `methods`, `paths`) are properties of an **origin**, not of an
  insertion point. The plan's interim answer: those checks declare the kinds any node
  carries, the h2 ones add a once-per-authority TTL guard (so AC T3-3's "<= 1
  connection per check" holds), and D6's dedupe collapses the Rhai repeats. A
  `kinds: []`-means-site-level rule, or a `scope: point | node | origin` field on
  `CheckMeta`, belongs in T1b's model and would be cleaner.
- **G2 — `evidence.timing.correlated` does not exist.** AC T3-4 says the seeded
  timing vulns are "found on V with `evidence.timing.correlated` and `r >= 0.85`",
  but `aitm_scan_model::Timing` (T1a, shipped) is
  `{ requested_s, observed_ms, baseline_ms, slope, r }` — there is no `correlated`
  field, and the model crate is not a T3 file. The plan asserts the derived rule
  (`r >= 0.85` and slope within 1000 +/- 300 ms/s) and puts the statement in the
  verdict's `detail`. Either T1b adds `correlated: bool` to `Timing` or T10's cell
  asserts the derived rule; the AC's wording should follow whichever is chosen.
- **G3 — D8.2's version sentence.** "`HttpRequest.version` stays what the sender
  observed on the wire" cannot hold: `PipelineClient::send_opts` stores the caller's
  request unchanged. Session call S1 reads it as applying to the **response**; the
  spec sentence should be corrected.

## Session decisions on the Architect's questions (T3 session, 2026-10-31)

Taken under Matt's autonomous-approval mandate; the two spec-wording items are
forwarded to the coordinator for the spec file.

| # | Question | Decision |
|---|---|---|
| Q1 | T1b landing gate / Task 11 pin edit | **Approved as planned.** Task 11 is "integration, part 1": it merges `origin/main` carrying T1b and re-points the two script pins in the same commit; Task 18 re-pins from live `tools/list`. One PR. If T1b is not on `main` when waves 1-5 are reviewed, the native half is still panel-reviewed and the PR waits for T1b rather than splitting. |
| Q2 | B5 raw-h2 probe accepts any server certificate | **Accepted, flagged for Matt.** The raw connection is opened only after `host.baseline()` succeeded through the guarded client to the same authority (S6), carries no cookie/auth/session header, and its result is an observation of the server's h2 behaviour, not a trust decision; the sender's own `ssl_insecure` posture is unreachable from the checks crate without an `aitm-core`/T1b change. Recorded for the security reviewer; a follow-up may thread the posture through `ProbeHost`. |
| Q3 | G1 site-level checks have no scheduling unit | **Interim answer accepted** (once-per-authority TTL guard for the h2 checks, D6 dedupe for the Rhai origin checks). A `scope: point \| node \| origin` field on `CheckMeta` is proposed to the coordinator as a T1b/model follow-up, not required for T3. |
| Q4 | G2 `evidence.timing.correlated` absent from the model | **Derived rule.** AC T3-4's `correlated` is satisfied by `timing::correlated(&evidence.timing)`: `r >= 0.85` and slope within `1000 ± 300` ms/s; the live-proof cell computes it from `evidence.timing`. Forwarded to the coordinator as an AC wording note. |
| Q5 | G3/S1 spec wording (`HttpRequest.version`) | **Confirmed**: the sentence applies to the response. Forwarded to the coordinator as a spec wording correction. |
| Q6 | B1 replay over h2 by default | **Confirmed.** `VersionPolicy::Auto` is the spec's default (D9.1) and D8.2 says `HttpSender` replaces `Http1Sender`'s behaviour; `flow.replay`/`request.send`/`http.send` reissue over h2 against an h2 origin, visible in `flow.detail` `response.version`. |


**Coordinator decisions received (2026-10-31, after the table above):** (1) D8.2 will say `HttpResponse.version`; the T3-1/T3-2 oracle is `flow.detail` `response.version`. (2) T1b adds `Timing.correlated: bool` (default `false`) to the model: Task 8 builds `Timing` with the fields that exist on this branch, and Task 11 (the T1b merge) adds `correlated: timing::correlated(&t)` at the single construction site in `blind_timing.rs`, so the T10 cell reads it from `evidence.timing`. (3) `CheckMeta.scope: point | node | origin` arrives via T1b; the per-authority TTL guard stays until then. (4) Raw-h2 accept-any TLS is allowed only under S6's conditions (same authority, after `host.baseline()` passed the guarded client, no session headers, observe-only); Task 6 states them in the `raw_h2` doc comment and Task 18 repeats them in the PR body for the security reviewer's explicit sign-off. (5) Check ids as chosen.


**Coordinator decision on the raw-h2 gate (2026-11-01, option A).** `aitm-scan-checks-http`
exports `checks_with(SsrfPolicy, Arc<dyn ScopeRateGuard>)`; `checks()` returns only the
gate-free checks (the five h2 checks excluded); T3's integration commit (Task 18) swaps
the one call in `crates/aitm/src/wire.rs` to `checks_with(features.ssrf_policy, guard)`,
authorised as an integration-shared exception. The interim (seam present, unwired) is
accepted in writing by the orchestrator for this branch only, provided the PR body
states it and the `wire.rs` edit is in the same PR; if T3 must merge without it, the h2
checks ship disabled. T1b adds `ProbeHost::baseline_peer_addr() -> Option<SocketAddr>`
(default `None`) as a follow-up; the checks use it when present. PR #213 merged as
`1f1cec4`; `origin/main` is merged into this branch before the checks-crate fix round.

**T1b bridge contract received (2026-11-01), corrections to S5:** `origin` is supplied by
the host (a script declaring it is a load error); `scope: point|node|origin` is an
optional meta key; `headers` in every probe response map is a MAP name -> value (not
pairs); `poc_hint` matchers use the PoC loader's own item vocabulary
(`#{ type: "status"|"word"|"regex"|..., ...fields }`, parsed as `Assertion::All`,
negation via a `not` combinator, no `negative` flag); `confidence` defaults to
`tentative`; `probe.*` outside a check closure is an error; a Rhai check's id is used
verbatim for `check.<id>`, so `id: "sqli"` keeps `check.sqli`. Tasks 11-16 follow this.


**Class vocabulary alignment (2026-11-01, with T1b and T10).** The reflected-XSS class
is `reflected-xss` (D6 spelling; the interim lane emits it, and D6 dedupes by class), for
native `xss-reflected` and the `header-reflection` script; S3's `xss` token is
superseded. SQL injection stays one class `sqli` across `sqli-boolean`, `sqli-time` and
the Rhai error-based `sqli` so boolean + error hits on one parameter dedupe into one
issue (T1-7); D6's `sqli-error` is read as the check id. Full list: reflected-xss,
open-redirect, sqli, cmdi, ssti, path-traversal, xxe, crlf, nosqli, ldapi, ssrf, cors,
missing-security-headers (`headers`), risky-http-methods (`methods`), exposed-path (`paths`; one verdict per origin listing every exposed path in `evidence.matched` until the bridge accepts a per-finding location); coordinator pin 2026-11-01, `information-disclosure` reserved for generic leaks, h2-settings, h2-pseudo-header,
h2-header-crlf, h2-smuggling-indicator, h2-rapid-reset. Applied in F3 (`xss.rs`) and in
the Rhai drafts.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1 | Coder (Task 1 report) | Important | A forced `H1`/`H2` send wrote the ALPN cache, so a later `Auto` send offered only the forced protocol for the TTL | Fixed by plan amendment: Task 3 item 5 narrows cache writes to `Auto` exchanges, test `a_forced_h1_send_does_not_pollute_the_alpn_cache` |
| 2 | Coder (Task 2 report) | Minor | Plan wording implied the median-baseline correction affects the timing verdict; subtracting a constant moves only the intercept, which `Timing` does not carry | Accepted (T3 session 2026-11-01): behaviour as specified; `fit` doc states it; tests pin slope/r invariance and the median itself |
| 5 | Coder (Task 5 report) | Important | Plan's open-redirect PoC regex lacked the multi-line flag; against `aitm_poc`'s joined header block the reproduction would fail and no `FindingRecord` would be written | Fixed in d329c3de (`(?im)`); recorded as amendment A2 |
| 5 | Coder (Task 5 report) | Minor | XSS tag is `"aitm" + host.marker()`; T1b's marker fixtures already start with `aitm`, so the live canary may read `aitmaitm7f3a` | Accepted (T3 session 2026-11-01): cosmetic, still unique; revisit when T1b's marker format is final |
| 5 | Coder (Task 5 report) | Minor | `may_send` (cancel/budget/deadline gate) duplicated in `xss.rs` and `redirect.rs`; Tasks 7-9 will want it too | Open: fold into a shared helper in the fix round after Tasks 7-9 land |
| 1,3 | Tester (Tasks 1 and 3) | Important | A timed-out h2 exchange leaves the stalled connection pooled: the outer `send_impl` timeout drops the inner future before `pool.remove` runs, so later sends to that authority burn the full timeout (test `a_timed_out_exchange_drops_the_still_open_connection_from_the_pool`, `#[ignore]`d) | Fixed in eb5b1f40 (F1.1): `PoolEviction` drop guard in `exchange_pooled`, cancellation-safe; test un-ignored |
| 1,3 | Tester (Tasks 1 and 3) | Minor | ALPN cache TTL (10 min) is untestable without a seam | Fixed in eb5b1f40 (F1.3): `with_alpn_cache_ttl(Duration)`; test `an_expired_alpn_cache_entry_makes_the_next_send_offer_both_again` |
| 6 | Coder (Task 6 report) | Minor | Plan left open whether `RawH2Plan.streams` or the mode decides the stream count | Accepted (T3 session 2026-11-01): the mode decides, `streams` is a declared cap, both refused above 8 before the dial; nothing truncated silently |
| 6 | Coder (Task 6 report) | Minor | `raw_h2.rs` duplicates `sender.rs`'s private `TcpDialer`/`SystemResolver`/`split_authority`/`ALPN_H2` | Open for the panel: tidy by making the sender's versions `pub(crate)` in the fix round |
| 4,6 | Coder (Task 6 report) | Important (process) | Shared `target/` served a stale test binary that silently omitted the new `driver_tests` module while reporting ok; only `cargo clean -p` fixed it | Process rule: every review gate runs `cargo clean -p` on the changed crates and counts tests; recorded in memory |
| 9 | Coder (Task 9 report) | Important (process) | Fable's safety layer halted twice on writing the raw-h2 `Blocks` driver arm and the malformed-header check bodies; no code written | The T3 session wrote the driver arm itself (ecfdfa1d, six driver tests); the check layer was re-dispatched on Sonnet with the frame work already done (Task 9b) |
| 8 | Coder (Task 8 report) | Minor | The plan's source pin `!contains("sleep(")` is falsified by the canonical `pg_sleep(n)` payload; the coder split the payload into a constant to keep both true | Open for the fix round: write the payload inline and narrow the pin to `tokio::time::sleep(` / `thread::sleep(` (the AC's intent: the check never waits) |
| 8 | Coder (Task 8 report) | Minor | mysql "numeric form" named in the plan but not implemented; with the 8-probe cap only two families run per point (`mssql`, `windows` never run) | Accepted (T3 session 2026-11-01): the quoted mysql + postgres pair is the right first two under the cap; family order may become profile-driven later |
| 8 | Coder (Task 8 report) | Minor | A partial family series (fewer than 4 measurements) is dropped, not fitted; a failed baseline does not stop the timing check (differs from `sqli-boolean`) | Accepted (T3 session 2026-11-01): a 2-point fit is always perfect, and the baseline moves neither slope nor r; both pinned by tests |
| 8 | Coder (Task 8 report) | Minor | `Speed::Fast` still schedules the timing technique (plan gives Fast the Normal schedule) | Accepted: whether `fast` skips timing checks is the scheduler's (T1b) decision; noted for the coordinator |
| 9 | Coder (Task 9b report) | Minor | `h2-pseudo-header-validation` and `h2-header-crlf-tolerance` shipped with severity Info / `confidence_max` Tentative (dispatch wording) where the plan table said Medium / Firm | Decided (T3 session 2026-11-01): pseudo-header stays Info/Tentative (a conformance observation); `h2-header-crlf-tolerance` becomes severity Medium, `confidence_max` Tentative (a CRLF-tolerant front end is a downgrade-smuggling precondition, research 19 §5); two meta fields + one assertion in the fix round |
| 9 | Coder (Task 9b report) | Minor | `h2-settings-observe` `confidence_max` raised to Certain so the verdict does not exceed it; rapid-reset `Clean` on GOAWAY or any `Refused` (not on `connection_closed`, which the driver also sets on its own timeout); a timed-out malformed stream is `Inconclusive`, not `Clean` | Accepted (T3 session 2026-11-01) |
| 7 | Coder (Task 7 report) | Minor | Plan text drift: `an_unstable_page_is_inconclusive` said `host.sent().len() == 2` but the scripted host records `baseline()` separately; `the_check_never_exceeds_twelve_probes` wording "a host that always differs" would trip the control gate | Accepted (T3 session 2026-11-01): asserted as `baseline_calls() == 1` and `sent() == ["seed"]`; the cap test scripts a stable control with diverging arms |
| 7 | Coder (Task 7 report) | Minor | The "every repeat must agree" branch (a hit that does not reproduce) is untestable with the stateless `ScriptedHost` | Open for the fix round: add `on_nth(needle, n, resp)` to `tests/support/mod.rs` and the test |
| 7 | Coder (Task 7 report) | Minor | `cost: Medium` ("at most ten probes") versus a boolean probe cap of 12 | Decided (T3 session 2026-11-01): lower the cap to 10 in the fix round so the meta is honest (ZAP's medium strength is 6 payloads); common-case hit costs 3/5/7 |
| 7 | Coder (Task 7 report) | Minor | `Evidence.payload` carries the false arm; a point without `example` sends an empty control | Accepted |
| 1,3,4,6,9a,F1 | Spec reviewer (sender panel) | Minor | `pub const FRAME_HEADER_LEN` in `raw_h2.rs` is public API the plan did not list | Fixed in 4c609549 (F2 S1): `FRAME_HEADER_LEN` is `pub(crate)` |
| 1,3,4,6,9a,F1 | Spec reviewer (sender panel) | Minor | Plan Task 1 still showed `negotiated_for(&self, authority)`; F1.2 changed it to `(scheme, authority)`; `with_alpn_cache_ttl` authorised only by the F1.3 row | Fixed in the plan text (this commit): Task 1 item 3 and its test descriptions now carry the shipped signature; F1.3's builder recorded here as an accepted addition |
| 1,3,4,6,9a,F1 | Spec reviewer (sender panel) | Minor | The coder fact sheet claimed 212 lib tests; a post-`cargo clean -p` run shows 206 (the pre-9a baseline was 200, not 206) | Fixed: fact sheet corrected to 206; the whole-branch tester quotes a post-clean count |
| 1,3,4,6,9a,F1 | Spec reviewer (sender panel) | Minor | No AC evidence exists in this range by design (duplex-only tests) | Agreed: ACs T3-1..T3-3 stay open until Task 17's real-bus cells are quoted; this panel accepts the range against its plan tasks only |
| 1,3,4,6,9a,F1 | Spec reviewer (sender panel) | — | Verdict PASS: scope exactly the four T3 files, every D8.2/D9.1 behaviour mapped to a literal test, alias intact, caps retained | Recorded |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | **Important** | Raw h2 driver resolves the name itself and dials with no SSRF/scope gate (DNS-rebinding window after `host.baseline()`); resolve outside `RAW_TOTAL_TIMEOUT` | Fixed in 3e9bcf8f (F2 SEC-1): `RawH2Client::with_ssrf(SsrfPolicy, Arc<dyn ScopeRateGuard>)`, `ssrf_check` on every resolved IP before the dial, resolve inside `RAW_TOTAL_TIMEOUT`; tests refuse 169.254.169.254 and 10.0.0.5 with 0 dials, an in-scope IP literal lifts it, a hanging resolver is bounded. Live wiring = coordinator option A: `checks_with(policy, guard)` (F3 C7) + the `wire.rs` swap in Task 18 |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | Minor | `handshake_error` maps `no_application_protocol` to `h2_not_negotiated` for every version | Fixed in ca7829a5 (F2 SEC-2): mapped by the ALPN offer (`[h2]` only), so forced `H1` and a first `Auto` send get the plain TLS error while forced `H2`/`H2c` and a cache-narrowed `Auto` still map; three tests |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | Minor | `parse_status_indexed` ignores HEADERS PADDED/PRIORITY flags | Fixed in ca7829a5 (F2 SEC-4): PADDED/PRIORITY skipped before the status; a lying pad byte is `status: None` |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | Minor | `Blocks` mode advances on a slot count, so an RST for an unopened id opens the next block early | Fixed in ca7829a5 (F2 SEC-5): `Blocks` waits on its own slot; a reset for an unopened id fills nothing and opens no block |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | Minor | `RawHeader`/`RawH2Plan` derive a value-printing `Debug` | Fixed in ca7829a5 (F2 SEC-6): `RawHeader` Debug is `name=<N bytes>` |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | Minor | h2 connection task logs peer GOAWAY debug data at `warn` | Fixed in ca7829a5 (F2 SEC-7): `debug!` with `go_away`/`reset`/`reason` fields, no Display; test captures the log |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | Minor | Pooled h2 reuse validates the fresh DNS answer, not the pooled peer address | Fixed in 6a912e22 (F2 SEC-8): pooled entries carry their validated address and are re-checked before reuse |
| 1,3,4,6,9a,F1 | Security reviewer (sender panel) | — | Clean: gate ordering on every sender path, cert failures never classified as `h2_not_negotiated`, TLS posture, parsing bounds, resource caps, secrets, no `unsafe` (forbid), no dependency change | Recorded |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Stale pooled h2 connection fails an interactive `flow.replay` with no redial (B1 consequence) | Fixed in 6a912e22 (F2 Q1): one redial for a pooled connection that failed before any response byte; a freshly dialled one is never retried |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Pool eviction is keyed, not identity-keyed | Fixed in 6a912e22 (F2 Q2): generation-tagged pool entries, eviction only on a matching generation |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Two overlapping deadlines for one h2 exchange | Fixed in 6a912e22 (F2 Q3): `exchange`/`exchange_pooled` take the caller's `Instant` deadline |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Duplicated private helpers and a duplicated `MAX_RESPONSE_BYTES` | Fixed in 4c609549 (F2 Q4): `TcpDialer::new(timeout)`, `SystemResolver`, `split_authority`, `ALPN_H2`, `MAX_RESPONSE_BYTES` shared `pub(crate)`; raw copies deleted; raw connect timeout stays 10 s (pinned) |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Doc comment of `split_authority` landed on `alpn_cache`; stale test-module doc | Fixed in 4c609549 (F2 Q5) |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Needless request/body clones on the send path | Fixed in 6a912e22 (F2 Q6, two of three parts): one whole-request clone per send; one body copy per attempt remains so the Q1 redial can resend the body (carrying `Bytes` end to end is a follow-up if wanted) |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Oversized raw block refused after the dial (also SEC-3) | Fixed in 4c609549 (F2 Q7/SEC-3): blocks encoded and size-checked in `validate`, 0 dials for an oversized block |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Test helpers (resolver, counting dialer, `server_config`) copied three times | Accepted (T3 session for Matt, 2026-11-01): test-only duplication of small helpers |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Three weak assertions (vacuous `<= 8`, OR-ed error messages, expected bytes computed with the encoder under test) | Fixed in 4c609549 (F2 Q9): GOAWAY test asserts the GOAWAY and all-Timeout streams; ALPN test split in two; `Blocks` tests assert literal content |
| 1,3,4,6,9a,F1 | Quality reviewer (sender panel) | Minor | Three tests synchronise with real-time sleeps | Fixed in 4c609549 (F2 Q10): yield-loop on `negotiated_for`; the two race sleeps became unnecessary with the Q1 redial |
| 10 | Coder (Task 10 report) | Minor | `crates/aitm/src/wire.rs:1020` `skeleton_lane_slots_are_empty_today` now fails (native checks 10, not 0); the test's doc says the landing track re-pins it | Task 18 (integration): re-pin to 10 and rename the test; the workspace `cargo test` is red on this one assertion until then, by design |
| 10 | Coder (Task 10 report) | Minor | The five h2 checks declare point kinds (query, body_param, header, cookie, path_segment) although they are per-authority observations guarded once per authority | Accepted (T3 session 2026-11-01): the `OncePerAuthority` guard makes the extra scheduling free; the clean fix is the coordinator's `CheckMeta.scope: origin` (decision 3) |
| 17 (pre) | T3 session (dry run) | — | Sender half of T3-1/T3-2 (ALPN auto negotiation) ran over the REAL bus on 2026-11-01 against T10's `aitm-testtarget-serve` (branch `feat/scanner-v2-t10-seeds` @ 23d09aba): `request.send` to the ALPN h2+http/1.1 listener -> `flow.detail` `response.version == "HTTP/2"`, to the h1-only TLS listener -> `"HTTP/1.1"`; the target's `/log/conns` shows `alpn: "h2"` / `"http/1.1"` per connection and `/log/http` shows `version: "h2"` / `"h1"` with `conn_req_index: 1`; no cookie on any probe. Script `/tmp/claude/t3-live-h2.py`, log `/tmp/claude/t3-live-h2-dryrun.log`, binary built before fix round F2 | Dry run; re-run green on the post-F2 binary (4c609549) 2026-11-01, log `/tmp/claude/t3-live-h2-postF2.log`, 10 checks ok, exit 0; Task 17 records the final run on the finished branch in the PR |
| 2,5,7,8,9b,10 | Quality reviewer (checks panel) | **Important** | A refused probe during `sqli-boolean`'s confirmation repeat is swallowed and the run can end `Clean` | Fix round F3 Q-I1 (Inconclusive + detail; stateful host test) |
| 2,5,7,8,9b,10 | Quality reviewer (checks panel) | **Important** | A refused timing probe drops a whole family unfitted and the run still ends `Clean` with a misstating detail | F3 Q-I2 |
| 2,5,7,8,9b,10 | Quality reviewer (checks panel) | **Important** | The crate documents excerpt redaction it never performs; `evidence.matched` can carry session material from the response | F3 Q-I3: `scrub_text_wide` at every evidence construction site + a test on `evidence.matched`/`payload` |
| 2,5,7,8,9b,10 | Quality reviewer (checks panel) | Minor | `no_finding` x4 and the verdict epilogue x3 duplicated; epilogue reports `Error` when the job was cancelled after one refused probe; two URL parsers; empty control on `example: None`; unused `TimingOracle` marker; dependency comments claim uses that do not exist; nine-field tuple in `Kind::meta`; allocation in `setting_name`; a 250 ms wall-clock assertion | F3 Q-M1..Q-M9 (all fixed; `gate.rs` for the fold) |
| 2,5,7,8,9b,10 | Quality reviewer (checks panel) | — | Clean: `timing.rs` total and pinned, no `unwrap`/`expect` on data paths, literal test values, `OncePerAuthority` justified, accept-any conditions documented | Recorded |
| 2,5,7,8,9b,10 | Security reviewer (checks panel) | **Important** | `Evidence.matched` carries unredacted response text (same defect as the quality Important): `excerpt_around` bounds but never scrubs; the crate's own test body shows `SESSIONID=super-secret-value` reaching `matched` | F3 SEC-C1 / Q-I3: scrub inside the helper and at the Location excerpt, test on `matched` |
| 2,5,7,8,9b,10 | Security reviewer (checks panel) | Minor | Raw-h2 probes spend no budget, are not paced and are invisible to the probe counters | F3 SEC-C2: refuse below `budget_left() >= streams`; charging/pacing the raw connection needs an engine hook, raised with the coordinator as a T1b follow-up |
| 2,5,7,8,9b,10 | Security reviewer (checks panel) | Minor | Once-per-authority guard key not port-normalised (`origin.test` vs `origin.test:443` probed twice) | F3 SEC-C3, folded into C6 (one canonical authority for pseudo-header, guard key and profile-origin match) |
| 2,5,7,8,9b,10 | Security reviewer (checks panel) | Minor | Empty control on `example: None`; dependency hygiene | F3 Q-M4 / Q-M6 |
| 2,5,7,8,9b,10 | Security reviewer (checks panel) | — | Clean: payload safety (read-only conditions, 5 s max delay, inert canaries, detect-only cl-te), ceilings, canary never a destination, `point.url` parsing (userinfo, IP literal, odd schemes), baseline-first with claim after baseline, bounded bodies/excerpts, no logging of values, no `unsafe` (forbid), no new crates | Recorded |
| 2,5,7,8,9b,10 | Spec reviewer (checks panel) | Minor | `h2-settings-observe` emits `Certain` on an Observe technique (D2 ceiling sentence) | F3 SP-1: `Firm` |
| 2,5,7,8,9b,10 | Spec reviewer (checks panel) | Minor | `h2-rapid-reset-mitigation` `cost: Light` with 8 streams; `confidence_max: Firm` never emitted | F3 SP-2 (`Medium`), SP-3 (emit `Firm` for the complete 8-pair observation) |
| 2,5,7,8,9b,10 | Spec reviewer (checks panel) | Minor | Two Task 9 test names differ from the plan | F3 SP-4: renamed/added |
| 2,5,7,8,9b,10 | Spec reviewer (checks panel) | — | Verdict PASS: every D8.2 native check present with plan meta, `PocHint` exactly on `xss-reflected`/`open-redirect`, caps pinned, no `sleep`, no unrequested public API, declared files only; ACs T3-3..T3-5 stay open until Task 17 | Recorded |
| 2,5,7,8,9b,10 | Tester (checks crate, 63101171) | **Important** | `Evidence.matched` never scrubbed (same as the panel's Important); pinned by `#[ignore]`d `evidence_excerpts_are_scrubbed_with_the_core_vocabulary` | F3 (un-ignore with the fix) |
| 2,5,7,8,9b,10 | Tester (checks crate, 63101171) | Minor | Timing checks take a baseline before the stop gate (cancelled/expired/zero-budget jobs still get one request); pinned by `#[ignore]`d `a_stopped_timing_check_does_not_even_take_a_baseline` | F3 T-B1 |
| 2,5,7,8,9b,10 | Tester (checks crate, 63101171) | Minor (test gap, fixed) | The third clause of `sqli-boolean`'s `is_hit` was never exercised (mutant survived) | Fixed in 63101171: strengthened unit test + end-to-end `a_false_arm_that_tracks_the_true_arm_is_not_a_hit` |
| 2,5,7,8,9b,10 | Tester (checks crate, 63101171) | — | PASS: 29 tests added (`check_hardening.rs`: bounds, redaction, budget ledger, deadline, mid-run cancel, malformed input, decision edges for all five value checks and the five h2 checks); 12 of 13 mutations caught, 1 equivalent; 150 tests post-clean | Recorded |
| 3 | Coder (Task 3 report) | Minor | ALPN cache and h2 pool are keyed by `host:port` without scheme; one sender driving `http://h:p` (h2c) and `https://h:p` would collide on one key | Fixed in eb5b1f40 (F1.2): `conn_key(scheme, authority)` for cache and pool; `negotiated_for(scheme, authority)`; two tests |
| 1,2,4 | Coder (Tasks 2 and 4 reports) | Important (process) | Parallel coders share one git index; a `git add <path>` + bare `git commit` swept a sibling's staged files into commit 25a42279 | Fixed by the Task 4 coder (rebuilt as 013a338e, single file); every later brief requires `git commit -- <paths>`; orchestrator audits each commit's stat |


## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
