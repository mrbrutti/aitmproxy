# Scanner v2 track T1a (contract drop) implementation plan

**Status:** Approved (orchestrator, on Matt's autonomous-approval mandate, 2026-10-31; A4 and A5 confirmed as proposed)
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved), sections D1, D2, D9.1, D9.5, D12 (row T1a and "Integration-shared files"), Constraints "Dependencies", AC T1a-1; plus the 2026-10-31 amendment (`aitm-scan-checks-http` exposes `checks()`, five lane crates).
**Research:** `docs/research/20-scanner-v2-current-state.md` (in-repo survey), `docs/research/17-burp-style-scanner-architecture.md`, `docs/research/18-protocol-fuzzing.md` (§3.6 dependency versions), `docs/research/19-ws-and-h2-active-scanning.md` (the spec's "12-15" citations are these renumbered notes).
**Branch / worktree:** `feat/scanner-v2-t1a` in `/Users/matt/Security/aitmproxy/.claude/worktrees/scanner-v2-docs`
**Size:** one PR; twelve tasks in six waves; roughly one day with parallel coders.

## Overview

T1a is the contract every other scanner v2 track compiles against, so it is the smallest
shippable PR and lands first. It adds (1) the pure-types crate `aitm-scan-model` with every
D2 type, the built-in profiles, the `Check`/`ProbeHost`/`Lane`/`JobCtx` traits and a JSON
fixture pack; (2) five skeleton lane crates whose `lane()` returns `None`, registered in the
workspace and wired into the binary through `crates/aitm/src/wire.rs`/`main.rs` so that no
lane track ever edits `crates/aitm/**`; (3) every new external dependency in
`[workspace.dependencies]`; (4) the generic D9.1 `SendOptions`/`send_opts` addition to
`aitm-core`; (5) the D9.5 L4 guard `interface: "*"` wildcard. It adds **no verb and no
check**, so `tools/list` is unchanged and no integration-shared file needs a re-pin.

Waves (tasks inside a wave touch disjoint files and fan out to parallel coders):

| Wave | Tasks | Depends on |
|---|---|---|
| 1 | Task 1 (workspace deps + model scaffold + vocabulary), Task 2 (D9.1 core `send_opts`), Task 3 (D9.5 guard wildcard) | none |
| 2 | Task 4 (`profile.rs` + built-ins), Task 5 (`point.rs`, `check.rs`), Task 6 (`job.rs`, `issue.rs`, `session.rs`) | Task 1 (Task 4 also Task 2) |
| 3 | Task 7 (`traits.rs`), Task 8 (`results.rs`) | Tasks 4, 5, 6 |
| 4 | Task 9 (fixture pack), Task 10 (five skeleton lane crates) | Task 8 (Task 9); Task 7 (Task 10) |
| 5 | Task 11 (binary wiring + `ScannerPlugin` setters) | Task 10 |
| 6 | Task 12 (integration: merge `origin/main`, gate, real boot proof) | Task 11 |

Shared facts for every coder:

- **TDD per task.** Write the named test first, run it and quote the red run (a compile
  error on a type that does not exist yet counts as red), implement, quote the green run.
- **Sandbox vs Terminal.** `cargo test -p <crate> --offline`, `cargo clippy --offline` and
  `cargo fmt --check` work in the sandbox (offline registry cache). Anything that binds a
  port (the `aitm` integration tests, the e2e harness) runs in the Terminal panel. Full gate
  from the worktree root before handing back:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- **Dependencies offline.** After any `Cargo.toml` edit run
  `cargo metadata --offline --format-version 1 >/dev/null` and quote the exit code. The
  registry cache (verified 2026-10-31) holds `serde_yaml 0.9.34`, `tokio-tungstenite 0.28.0`,
  `tokio-util 0.7.19`; it does **not** hold `blake3`, `hickory-proto`, `rand 0.9`,
  `rand_chacha 0.9`. A `[workspace.dependencies]` entry that no member inherits is not
  resolved and does not enter `Cargo.lock`, so declaring those four is safe offline. If
  `cargo metadata --offline` nevertheless fails on one of them, comment that single line out
  with `# T1a: not in the offline cache; enable in the Terminal (cargo fetch) before a lane
  track inherits it` and report it; never leave the build broken.
- **No new verbs, no new checks.** `crates/aitm/tests/frontends.rs`, `crates/aitm-tui/src/lib.rs`
  `CORE_TOOLS`, `crates/aitm-tui/fixtures/bus-fixture.json`, `crates/aitm/tests/bundled_startup.rs`
  and `crates/aitm-plugin-rhai/tests/bundled_scripts.rs` are integration-shared (spec
  Constraints) and are **not edited** by any task here; Task 12 only re-runs them.
- **Every new crate**: `#![forbid(unsafe_code)]` at the crate root **and** `[lints] workspace = true`
  (the workspace already forbids `unsafe_code`); `version/edition/license/rust-version` via
  `.workspace = true`; a one-paragraph crate doc naming the owning track and spec section.
- **Wire conventions** (spec D2): every wire type derives `Debug, Clone, PartialEq, Serialize,
  Deserialize`; every enum and struct is `#[serde(rename_all = "snake_case")]`; result types
  (UI-consumed) tolerate unknown keys and treat absent optional keys as `None`/empty
  (`#[serde(default)]`); the profile tree (operator-authored) is `#[serde(default,
  deny_unknown_fields)]` so a typo is `invalid_profile`, never silently ignored. Timestamps on
  the wire are epoch milliseconds (`u64`), matching the push line's `ts_ms`.
- **Ownership note.** Task 11 touches `crates/aitm-plugin-scanner/src/plugin.rs` and its
  `Cargo.toml` (a T1b-owned crate per D12) with two additive setters, on the orchestrator's
  instruction; T1a lands before T1b branches, so there is no concurrent writer.

## Tasks

### Task 1: workspace dependencies, `aitm-scan-model` scaffold, wire vocabulary

- **Satisfies:** spec Constraints "Dependencies" (T1a declares every new external dependency),
  D2 enum wire tokens, D12 row T1a (`Cargo.toml`, `crates/aitm-scan-model/**`), Architect's
  call 26.
- **Depends on:** none.
- **Files:** `Cargo.toml` (modify: `members`, `[workspace.dependencies]`),
  `crates/aitm-scan-model/Cargo.toml` (create), `crates/aitm-scan-model/src/lib.rs` (create),
  `crates/aitm-scan-model/src/ids.rs` (create), `crates/aitm-scan-model/src/vocab.rs` (create),
  and **placeholder** module files containing only a `//!` doc line so later tasks own one
  file each and `lib.rs` is never edited again: `src/profile.rs`, `src/point.rs`,
  `src/check.rs`, `src/job.rs`, `src/issue.rs`, `src/session.rs`, `src/traits.rs`,
  `src/results.rs` (create, all).
- **Change:**
  1. Root `Cargo.toml`: add member `crates/aitm-scan-model`; add the internal path entry
     `aitm-scan-model = { path = "crates/aitm-scan-model" }`; add external entries
     `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`,
     `serde_yaml = "0.9"`, `tokio-tungstenite = "0.28"` (promoted from per-crate; the
     per-crate `"0.28"` literals in `aitm-proto-ws`/`aitm-plugin-wsctl` dev-deps are left as
     they are, they resolve to the same lock entry), `tokio-util = { version = "0.7",
     features = ["rt"] }`, `rand = "0.9"`, `rand_chacha = "0.9"`, `blake3 = "1"`,
     `hickory-proto = "0.26"` (`docs/research/18-protocol-fuzzing.md` §3.6: 0.26.3), `url = "2"`, `regex = "1"`,
     `bytes = "1"`. Each new line gets a short comment naming the track that inherits it
     (T1b: blake3, tokio-util; T2: url, regex; T4: tokio-tungstenite, bytes; T6: hickory-proto,
     rand, rand_chacha; model: serde, serde_json, serde_yaml).
  2. `crates/aitm-scan-model/Cargo.toml`: deps `aitm-core`, `aitm-poc`, `anyhow`, `futures`,
     `serde`, `serde_json` (all `workspace = true`); dev-dep `serde_yaml` (`workspace = true`).
     Description: "Scanner v2 shared data model: wire types, built-in profiles, lane/check
     traits. No I/O." The manifest is final after this task (Tasks 4-9 add no dependency).
  3. `lib.rs`: `#![forbid(unsafe_code)]`, crate doc, `pub mod ids; pub mod vocab; pub mod profile;
     pub mod point; pub mod check; pub mod job; pub mod issue; pub mod session; pub mod traits;
     pub mod results;` and `pub use` glob re-exports of each module (`pub use ids::*;` etc.) so
     consumers write `aitm_scan_model::Lane`, `aitm_scan_model::ScanProfile`.
  4. `ids.rs`: `pub struct FlowRef(pub aitm_core::FlowId)` with `Serialize`/`Deserialize` as the
     UUID string (via `FlowId`'s `Display`/`FromStr`; `aitm-core` has no serde and is not
     edited for this), `From<FlowId>`, `Display`, `Debug, Clone, Copy, PartialEq, Eq, Hash`;
     `pub type NodeId = String; pub type JobId = String; pub type IssueId = String;`.
  5. `vocab.rs`, every enum `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`,
     snake_case tokens exactly as spec D2:
     `LaneKind { Http, Ws, L4Packet, L4Stream }` (derives `PartialOrd, Ord` too, so it can key `ProbeCounters.by_lane`; tokens `http|ws|l4_packet|l4_stream`; the
     **enum** is `LaneKind` because `Lane` is the trait, Architect's call A1);
     `Intensity { Passive, Light, Medium, Intrusive }` plus `PartialOrd, Ord` in that order;
     `Speed { Fast, Normal, Thorough }`; `Accuracy { FewerFalseNegatives, Normal, FewerFalsePositives }`;
     `InsertionKind` with the 20 D2 variants and `pub const ALL: [InsertionKind; 20]`;
     `PointTrait { Url, Filename, Number, Email, Base64, Json, Id, Session }`;
     `Confidence { Tentative, Firm, Certain }` plus `PartialOrd, Ord` (ascending strength);
     `CheckCost { Light, Medium, Heavy }`;
     `Technique { Reflected, Error, Boolean, Timing, Handshake, Malformed, Observe, Passive }`;
     `Outcome { Vulnerable, Clean, Inconclusive, Error }`;
     `CheckOrigin { Native, Bundled { path: String }, Custom { path: String } }` with
     `#[serde(tag = "kind", rename_all = "snake_case")]` (wire `{"kind":"bundled","path":...}`,
     call A2);
     `HttpVersionPolicy { Auto, H1, H2, H2c }`; `RecordProbes { IssuesOnly, All }`;
     `IssueStatus { Open, Confirmed, FalsePositive }`; `L4Transport { Tcp, Udp }`;
     `CrawlStrategy { Fast, Normal, Thorough }`; `UseBrowser { Auto, Always, Never }`;
     `SessionMode { Observed, None }`; `OnLost { Stop, Continue }`;
     `PayloadMode { Replace, Prefix, Suffix }`;
     `ScanErrorCode` with exactly the eleven D3 codes (`NotFound, Busy, OutOfScope, RefusedAgent,
     RefusedL4, LaneUnavailable, InvalidProfile, UnknownCheck, ConfirmRequired, Cancelled,
     Clamped`; `h2_not_negotiated` is a sender error, not a verb error code, and is not here),
     `pub fn as_str(&self) -> &'static str`, `impl FromStr`, and
     `pub fn parse_message(msg: &str) -> Option<(ScanErrorCode, &str)>` for the
     `scan: <code>: <message>` form.
- **Test** (`vocab.rs`/`ids.rs` `#[cfg(test)]`):
  `lane_kind_wire_tokens`: `serde_json::to_string(&LaneKind::L4Packet).unwrap() == "\"l4_packet\""`
  and `serde_json::from_str::<LaneKind>("\"l4_stream\"").unwrap() == LaneKind::L4Stream`;
  `intensity_is_ordered`: `Intensity::Passive < Intensity::Light`, `Intensity::Light < Intensity::Medium`,
  `Intensity::Medium < Intensity::Intrusive`;
  `confidence_is_ordered`: `Confidence::Tentative < Confidence::Firm`, `Confidence::Firm < Confidence::Certain`;
  `insertion_kind_all_round_trips`: `InsertionKind::ALL.len() == 20`, every variant round-trips
  through JSON, and `to_string(&InsertionKind::WsHandshakeHeader) == "\"ws_handshake_header\""`;
  `check_origin_is_kind_tagged`: `to_string(&CheckOrigin::Bundled { path: "a.rhai".into() })
  == r#"{"kind":"bundled","path":"a.rhai"}"#` and `Native` is `{"kind":"native"}`;
  `error_code_parse_message`: `ScanErrorCode::parse_message("scan: lane_unavailable: ws not built")
  == Some((ScanErrorCode::LaneUnavailable, "ws not built"))` and `parse_message("boom") == None`;
  `flow_ref_round_trips_uuid_string`: the JSON of a `FlowRef` built from
  `"550e8400-e29b-41d4-a716-446655440000".parse::<FlowId>()` is that string quoted, and it parses back equal.
- **Done when:** the tests pass with `cargo test -p aitm-scan-model --offline`,
  `cargo metadata --offline` exits 0 after the root manifest edit (quoted), and the full gate passes.

### Task 2: D9.1 `SendOptions` / `ProxyClient::send_opts` in `aitm-core`

- **Satisfies:** AC T1a-1 (the `cargo test -p aitm-core` half: an existing `ProxyClient` impl
  compiles untouched against the new default), spec D9.1, Architect's calls 5 and 21.
- **Depends on:** none.
- **Files:** `crates/aitm-core/src/client.rs` (modify), `crates/aitm-core/src/ctx.rs` (modify:
  the `ProxyClient` trait), `crates/aitm-core/src/lib.rs` (modify: re-exports only).
- **Change:**
  1. `client.rs` gains `pub enum RecordPolicy { Always, Never }` (`Default` = `Always`),
     `pub enum VersionPolicy { Auto, H1, H2, H2c }` (`Default` = `Auto`), and
     `pub struct SendOptions { pub record: RecordPolicy, pub marks: Vec<String>, pub version: VersionPolicy }`
     with `Default`; all `Debug, Clone, PartialEq, Eq` (no serde: core has none).
  2. `RequestSender` gains
     `fn send_with<'a>(&'a self, req: &'a HttpRequest, version: VersionPolicy) -> BoxFuture<'a, anyhow::Result<HttpResponse>>`
     with a default body that ignores `version` and calls `self.send(req)` (so `Http1Sender`
     and every test sender compile unchanged; T3's `HttpSender` overrides it).
  3. `ProxyClient` (`ctx.rs`) gains
     `fn send_opts(&self, req: HttpRequest, opts: SendOptions) -> BoxFuture<'_, anyhow::Result<HttpFlow>>`
     with a default body returning `self.send(req)` (documented: an impl that cannot honour the
     options falls back to plain `send`, which records).
  4. `PipelineClient` implements `send_opts` for real: `guard.check_active(&req.authority)?`
     first (held for the send), then `sender.send_with(&req, opts.version)`, the existing
     `record_error` rules, then builds the `HttpFlow` with `metadata.is_replay = true` and
     `metadata.marks = opts.marks`, inserts into the store **only when** `opts.record ==
     RecordPolicy::Always`, and returns the flow. `PipelineClient::send` becomes
     `self.send_opts(req, SendOptions::default())` so there is one code path and the shipped
     behaviour (record, no marks) is unchanged.
  5. `lib.rs`: `pub use client::{PipelineClient, RecordPolicy, RequestSender, SendOptions, VersionPolicy};`.
- **Test** (`client.rs` `#[cfg(test)] mod tests`, `#[tokio::test]`, using the `EchoSender`
  pattern from `crates/aitm-plugins/tests/scope_rate.rs`: a stub `RequestSender` that answers
  200, counts calls in an `AtomicUsize`, and records the last `VersionPolicy` in a `Mutex`;
  `MemFlowStore::new()`; `StdGuard::default()` with `add_scope(ScopeEntry { host: "ex.test".into() })`;
  a request to authority `ex.test`, path `/x`):
  `send_opts_never_does_not_insert`: `record: Never, marks: ["scan:job1"]` returns `Ok`, the
  flow has `metadata.is_replay == true` and `metadata.marks == vec!["scan:job1"]`, and
  `store.count() == 0`;
  `send_opts_always_inserts_with_marks`: `record: Always, marks: ["scan:job1", "crawl"]` gives
  `store.count() == 1` and the stored flow's `marks == vec!["scan:job1", "crawl"]`;
  `send_keeps_shipped_behaviour`: `send(req)` gives `store.count() == 1`, `marks.is_empty()`,
  `is_replay == true`;
  `send_opts_passes_version_to_sender`: `version: H2` leaves the stub's recorded policy
  `== Some(VersionPolicy::H2)`; the stub also proves the `send_with` default by implementing
  only `send` in a second stub whose recorded policy stays `None`;
  `send_opts_out_of_scope_sends_nothing`: authority `other.test` (not in scope) returns `Err`,
  stub call count `== 0`, `store.count() == 0`;
  `default_send_opts_delegates_to_send` (AC T1a-1): a `struct Legacy; impl ProxyClient for Legacy`
  that implements **only** `send` (returning a fixed `HttpFlow` with path `/legacy`) compiles,
  and `Legacy.send_opts(req, SendOptions::default()).await.unwrap().request.path == "/legacy"`;
  `send_options_default`: `SendOptions::default() == SendOptions { record: RecordPolicy::Always,
  marks: vec![], version: VersionPolicy::Auto }`.
- **Done when:** `cargo test -p aitm-core --offline` passes, `cargo check --workspace --offline`
  passes (every existing `ProxyClient`/`RequestSender` impl untouched), full gate passes.

### Task 3: D9.5 L4 guard `interface: "*"` wildcard

- **Satisfies:** AC T1a-1 (the `cargo test -p aitm-proto-l4` half), spec D9.5, Architect's call 20.
- **Depends on:** none.
- **Files:** `crates/aitm-proto-l4/src/guard.rs` (modify: `entry_matches_location`, its doc,
  the module doc line "interface + direction + CIDR + port", tests),
  `crates/aitm-proto-l4/src/types.rs` (modify: doc comment on `L4ScopeEntry.interface` only),
  `crates/aitm-proto-l4/src/config.rs` (modify: the `scope` field doc comment only).
- **Change:** in `entry_matches_location`, the interface clause becomes: the entry matches when
  `entry.interface == "*"` **or** `entry.interface == target.interface`; the wildcard is
  **entry-side only** (a target whose `interface` is literally `"*"` matches no literal entry).
  Direction, CIDR, port and capability matching are untouched. `pub const ANY_INTERFACE: &str = "*"`
  is added to `guard.rs` and used by the clause. Doc comments: `L4ScopeEntry.interface`
  ("The interface name the entry covers, or `"*"` for any interface: an unprivileged socket
  client cannot know its egress interface before connecting, so the operator authorises a
  destination, not a NIC. Direction, CIDR, ports and capability still apply."), the
  `L4Config.scope` doc (one sentence pointing at the wildcard), the `guard.rs` module doc.
- **Test** (`guard.rs` tests module, using the existing `entry(...)`/`target(...)` helpers,
  CIDR `("10.0.0.0", 8)`, dst `10.1.2.3`, port `6379`, capability `Inject`, rate `(100, 100)`):
  `wildcard_interface_matches_any_interface`: entry `"*"`/`Outbound`; `g.check(L4Action::Inject,
  &target("lo0", Outbound, "10.1.2.3", 6379)).is_ok()` and the same for `"en0"`;
  `literal_interface_still_refuses_other_interface`: entry `"lo0"`; `check(... "en0" ...)` is
  `Err(L4GuardError::OutOfL4Scope("10.1.2.3".into()))`;
  `wildcard_does_not_widen_direction`: entry `"*"`/`Outbound`; a `target("en0", L4Direction::Inbound, ...)`
  is `Err(OutOfL4Scope(_))`;
  `wildcard_does_not_widen_cidr_or_port`: entry `"*"`/`Outbound`/`10.0.0.0/8`/ports `6379..=6379`
  (build the entry then set `ports`); dst `192.168.1.1` is refused and port `6380` is refused;
  `wildcard_is_entry_side_only`: entry `"lo0"`; `target("*", Outbound, "10.1.2.3", 6379)` is
  `Err(OutOfL4Scope(_))`.
- **Done when:** `cargo test -p aitm-proto-l4 --offline guard` passes with the five new tests
  and every existing guard test, and the full gate passes.

### Task 4: `profile.rs`: `ScanProfile`, sub-blocks, defaults, built-in profiles

- **Satisfies:** spec D2 `ScanProfile` and built-in profiles, D11 (profiles are human-readable
  YAML), Architect's call 15 (ceilings live in config, so no ceiling here).
- **Depends on:** Task 1, Task 2 (for the `VersionPolicy` conversion).
- **Files:** `crates/aitm-scan-model/src/profile.rs` (replace placeholder),
  `crates/aitm-scan-model/tests/builtin_profiles.rs` (create).
- **Change:** all structs `#[serde(default, deny_unknown_fields, rename_all = "snake_case")]`
  with `Default` impls carrying the spec's numbers:
  `ScanProfile { name: String (default ""), target: ProfileTarget, lanes: Vec<LaneKind> (default [http]),
  intensity (default medium), speed (default normal), accuracy (default normal), checks: CheckSelection,
  crawl: CrawlOptions, audit: AuditOptions, session: SessionOptions, budget: Budget, http: HttpOptions,
  ws: WsOptions, l4: L4Options }`;
  `ProfileTarget { origins: Vec<String>, l4: Vec<L4TargetSpec> }`;
  `L4TargetSpec { ip: String, port: u16, proto: L4Transport, grammar: Option<String> }`;
  `CheckSelection { include: Vec<String>, exclude: Vec<String> }` (selectors `id | class | lane:*`,
  parsed by the engine);
  `CrawlOptions { strategy: CrawlStrategy (normal), max_depth: u32 (3), max_pages: u32 (200),
  submit_forms: bool (true), click_handlers: bool (true), robots: bool (true), sitemap: bool (true),
  use_browser: UseBrowser (auto) }` (depth/pages are today's `ScannerConfig` defaults, call A3);
  `AuditOptions { kinds: Vec<InsertionKind> (default = InsertionKind::ALL.to_vec()),
  ignore: Vec<IgnoreRule> (default [IgnoreRule { trait: Some(Session), .. }]),
  max_points_per_request: u32 (64), frequent_point_threshold: u32 (8) }`;
  `IgnoreRule { kind: Option<InsertionKind>, name_regex: Option<String>,
  #[serde(rename = "trait")] point_trait: Option<PointTrait> }` with
  `pub fn is_valid(&self) -> bool` (at least one key present);
  `SessionOptions { mode: SessionMode (observed), from_flow: Option<FlowRef>, on_lost: OnLost (stop) }`;
  `Budget { probes: u32 (2000), time_s: u64 (600), max_issues: u32 (1024), check_timeout_s: u64 (60),
  per_host_errors: PerHostErrors }` (`check_timeout_s` is D4's "profile's `check_timeout`", call A4);
  `PerHostErrors { consecutive: u32 (10), ratio: f32 (0.5) }`;
  `HttpOptions { version: HttpVersionPolicy (auto), record_probes: RecordProbes (issues_only) }`;
  `WsOptions { reply_window_ms: u32 (1500), max_frame_bytes: u32 (1_048_576) }`;
  `L4Options { cases: u32 (500), reproduce_count: u32 (3), liveness_every: u32 (25),
  consecutive_timeouts: u32 (20), max_bytes_per_s: u32 (65_536), seeds: Vec<L4Seed>, dry_run: bool (false) }`;
  `L4Seed` `#[serde(untagged)] { Flow { flow: FlowRef }, Hex { hex: String }, Base64 { base64: String } }`;
  `impl From<HttpVersionPolicy> for aitm_core::VersionPolicy` (variant-for-variant);
  `pub const BUILTIN_PROFILE_NAMES: [&str; 7] = ["passive-only", "map-only", "light-http", "standard",
  "thorough", "l4-stream-safe", "l4-full"]`, `pub fn builtin_profiles() -> Vec<ScanProfile>`,
  `pub fn builtin(name: &str) -> Option<ScanProfile>`, `pub fn is_builtin_name(name: &str) -> bool`.
  Built-in shapes (every other field default; `target` empty, filled by `scan.start`):
  `passive-only` lanes `[http]`, intensity `passive`, `crawl.max_pages 0`, `use_browser never`
  (passive checks over already-captured in-scope flows only, call A5);
  `map-only` `[http]`, `passive`, crawl default (crawl + passive, no probes);
  `light-http` `[http]`, `light`, speed `fast`;
  `standard` `[http, ws]`, `medium`, `normal`, `normal`;
  `thorough` `[http, ws]`, `medium`, speed `thorough`, accuracy `fewer_false_negatives`, crawl strategy `thorough`;
  `l4-stream-safe` `[l4_stream]`, `medium`, `l4.cases 200`, `dry_run false`;
  `l4-full` `[l4_packet, l4_stream]`, `medium`, `l4.cases 500`.
- **Test** (`tests/builtin_profiles.rs` plus unit tests in `profile.rs`):
  `every_builtin_round_trips_yaml_and_json`: for each of the 7, `serde_yaml::to_string` then
  `from_str` equals the original, same through `serde_json`; the set of names equals
  `BUILTIN_PROFILE_NAMES` and `builtin("nope").is_none()`;
  `standard_yaml_reads_as_prose`: the YAML of `standard` contains the lines `name: standard`,
  `intensity: medium`, and `- ws` (block style, one key per line), and contains no
  flow-style map (`!yaml.contains("{\"")` and `!yaml.contains("{ ")`);
  `minimal_yaml_fills_every_default`: parsing
  `name: mini\ntarget:\n  origins: ["http://127.0.0.1:8080"]\n` yields `budget.probes == 2000`,
  `budget.time_s == 600`, `audit.max_points_per_request == 64`, `audit.frequent_point_threshold == 8`,
  `audit.ignore == vec![IgnoreRule { point_trait: Some(PointTrait::Session), ..Default::default() }]`,
  `ws.reply_window_ms == 1500`, `l4.cases == 500`, `l4.max_bytes_per_s == 65536`, `http.version == Auto`;
  `unknown_key_is_rejected`: parsing `name: typo\nbudgte:\n  probes: 5\n` is `Err` and the error
  text contains `budgte`;
  `l4_seed_untagged_forms`: `{"hex":"0001"}`, `{"base64":"AAE="}`, `{"flow":"<uuid>"}` each parse
  to the matching variant;
  `version_policy_maps_onto_core`: `aitm_core::VersionPolicy::from(HttpVersionPolicy::H2c) == aitm_core::VersionPolicy::H2c`.
- **Done when:** `cargo test -p aitm-scan-model --offline` passes and the full gate passes.

### Task 5: `point.rs` and `check.rs`: insertion points, site nodes, probe I/O, check metadata, verdict, evidence, `PocHint`

- **Satisfies:** spec D2 `InsertionPoint`, `CheckMeta`, `Verdict`, `PocHint`/`ControlHint`,
  `Evidence`, `L4Evidence`, `ProbeResponse`; D8.1 `SiteNode`; Architect's call 23 (`poc_hint`
  is `#[serde(skip)]`).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-model/src/point.rs`, `crates/aitm-scan-model/src/check.rs`
  (replace placeholders).
- **Change (`point.rs`):**
  `InsertionPoint { id: String, lane: LaneKind, kind: InsertionKind, name: String, path: Option<String>,
  example: Option<String> (already redacted by the lane), flow: Option<FlowRef>, site_node: Option<NodeId>,
  traits: Vec<PointTrait>, frequency: u32, method: Option<String>, url: Option<String> }` (`method`/`url`
  are the D4 point-map keys the Rhai bridge reads, call A6);
  `SiteNode { id: NodeId, method: String, scheme: String, host: String, port: u16, path_template: String,
  flows: Vec<FlowRef>, params: Vec<ParamRef>, auth: bool, points: u32, audited: bool }` with
  `ParamRef { kind: InsertionKind, name: String }` (the union of D3's sitemap node and D8.1's
  `SiteNode`, call A7);
  in-process (non-wire, `Debug + Clone` only, call A8): `Payload { value: String, mode: PayloadMode,
  bytes: Option<Vec<u8>> }`, `RawProbe { method: String, url: String, headers: Vec<(String, String)>,
  body: Vec<u8> }`, `ProbeResponse { status: Option<u16>, headers: Vec<(String, String)>, body: Vec<u8>,
  elapsed_ms: u32, flow: Option<FlowRef>, ws_frames: Option<Vec<Frame>>, l4: Option<L4Reply> }`,
  `Frame { kind: FrameKind, payload: Vec<u8> }`, `FrameKind { Text, Binary, Ping, Pong, Close }`,
  `L4Reply { bytes: Vec<u8>, oracle: L4Oracle, elapsed_ms: u32 }`; `pub const MAX_MATCH_BODY: usize = 1 << 20`.
- **Change (`check.rs`):**
  `CheckMeta { id: String, name: String, class: String, lanes: Vec<LaneKind>, kinds: Vec<InsertionKind>,
  intensity: Intensity, cost: CheckCost, technique: Technique, severity: aitm_poc::Severity,
  confidence_max: Confidence, needs_baseline: bool, wants_traits: Option<Vec<PointTrait>>,
  #[serde(default)] targets_session: bool, cwe: Option<u32>, description: String, remediation: Option<String>,
  origin: CheckOrigin }`;
  `Verdict { outcome: Outcome, confidence: Confidence, evidence: Evidence, detail: String,
  #[serde(skip)] poc_hint: Option<PocHint> }`;
  `PocHint { assertions: Vec<aitm_poc::Assertion>, control: Option<ControlHint> }` and
  `ControlHint { payload: String, expect: Vec<aitm_poc::Assertion> }` (`Debug, Clone, PartialEq`, no serde);
  `Evidence { payload: Option<String>, matched: Option<String>, probe_flows: Vec<FlowRef>,
  baseline_flow: Option<FlowRef>, timing: Option<Timing>, diff: Option<Diff>, l4: Option<L4Evidence> }` with `Default`
  and `pub fn excerpt(text: &str) -> String` (<= 256 bytes, cut on a char boundary; the caller
  scrubs first); `pub const MAX_EXCERPT_BYTES: usize = 256`;
  `Timing { requested_s: Vec<f32>, observed_ms: Vec<u32>, baseline_ms: Vec<u32>, slope: f32, r: f32 }`;
  `Diff { baseline_len: u32, true_len: u32, false_len: u32 }`;
  `L4Evidence { sent_hex: String, seed_id: String, rng_seed: u64, mutation_chain: Vec<String>,
  prior_messages: u32, oracle: L4Oracle, liveness_before: bool, liveness_after: bool,
  reproduced: (u32, u32), scope_entry: String }` (`reproduced` serializes as `[k, n]`, call A9);
  `L4Oracle` `#[serde(tag = "kind", rename_all = "snake_case")]`
  `{ ProtocolError, Reset, Icmp { #[serde(rename = "type")] icmp_type: u8, code: u8 }, Silence,
  LivenessFailed, LatencyOutlier }` (call A10).
- **Test** (`#[cfg(test)]` in each file):
  `insertion_point_round_trips`: a point with `kind: JsonValue`, `path: Some("profile.address.city")`,
  `traits: [Json]`, `frequency: 3` round-trips through JSON and the JSON contains `"kind":"json_value"`;
  `site_node_tolerates_missing_optional_keys`: parsing `{"id":"n1","method":"GET","scheme":"http",
  "host":"127.0.0.1","port":8080,"path_template":"/account/{id}","flows":[]}` yields `params.is_empty()`,
  `auth == false`, `points == 0`, `audited == false`;
  `verdict_never_emits_poc_hint`: a `Verdict` with `poc_hint: Some(PocHint { assertions:
  vec![aitm_poc::Assertion::Status(200)], control: None })` serializes to JSON that does **not**
  contain the substring `poc_hint`, and the parsed value has `poc_hint == None` while
  `outcome == Vulnerable`;
  `check_meta_round_trips_with_bundled_origin`: `origin: Bundled { path: "scripts/bundled/active/sqli.rhai" }`,
  `severity: Severity::High`, `cwe: Some(89)` round-trips and the JSON contains `"severity":"high"`;
  `evidence_excerpt_is_bounded`: `Evidence::excerpt(&"a".repeat(300)).len() == 256` and
  `Evidence::excerpt("héllo").len() == 6`;
  `l4_oracle_icmp_wire_shape`: `to_string(&L4Oracle::Icmp { icmp_type: 3, code: 3 }) ==
  r#"{"kind":"icmp","type":3,"code":3}"#` and `Silence` is `{"kind":"silence"}`;
  `l4_evidence_reproduced_is_pair`: JSON of an `L4Evidence` with `reproduced: (3, 3)` contains `"reproduced":[3,3]`.
- **Done when:** the tests pass under `cargo test -p aitm-scan-model --offline` and the full gate passes.

### Task 6: `job.rs`, `issue.rs`, `session.rs`: job status, issues, session profile and material

- **Satisfies:** spec D5 `JobStatus`, D6 `Issue`/`IssueSummary`, D7 `SessionProfile`,
  D1/D3 `lanes { requested, run, skipped }` and `clamped`; anti-goal "no result carries session
  material" (via `SessionMaterial`).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-scan-model/src/job.rs`, `crates/aitm-scan-model/src/issue.rs`,
  `crates/aitm-scan-model/src/session.rs` (replace placeholders).
- **Change (`job.rs`):**
  `JobState { Queued, Running, Cancelling, Done, Cancelled, Failed }` with `pub fn is_terminal(&self) -> bool`;
  `Phase { Queued, Crawling, Passive, Auditing, Reporting, Done }`;
  `StoppedReason { Budget, Time, Cancelled, SessionLost, Errors, Policy, GuardRefused, Failed }`;
  `StartedBy { frontend: String (the lowercase `aitm_core::Frontend` name: cli|mcp|operator), client_label: Option<String> }`;
  `ProbeCounters { sent: u64, budget: u64, errors: u64, timeouts: u64, rate_waits: u64, by_lane: BTreeMap<LaneKind, u64> }`;
  `CrawlCounters { pages: u64, queued: u64, depth: u32, forms_submitted: u64 }`;
  `PointCounters { found: u64, queued: u64, audited: u64, skipped: SkippedPoints }`,
  `SkippedPoints { ignored: u64, frequent: u64, limit: u64 }`;
  `CheckCounters { scheduled: u64, done: u64, running: Vec<String> }`;
  `IssueCounters { total: u64, by_severity: BySeverity, by_confidence: ByConfidence }`;
  `L4Counters { cases: u64, crashes: u64, liveness_failures: u64, retired_elements: u64 }`;
  `SessionStatus { reused: bool, lost: bool, canary: Canary, browser_partial: bool }`;
  `LaneReport { requested: Vec<LaneKind>, run: Vec<LaneKind>, skipped: Vec<SkippedLane> }`,
  `SkippedLane { lane: LaneKind, reason: String }`;
  `Clamped { field: String, requested: u64, applied: u64 }`;
  `JobStatus { job: JobId, state, phase, profile_name: String, targets: Vec<String>, started_by: StartedBy,
  started_at: u64, finished_at: Option<u64>, elapsed_ms: u64, stopped_reason: Option<StoppedReason>,
  probes: ProbeCounters, crawl: CrawlCounters, points: PointCounters, checks: CheckCounters,
  issues: IssueCounters, l4: Option<L4Counters>, session: Option<SessionStatus>, lanes: LaneReport,
  clamped: Vec<Clamped>, error: Option<String> }` with `Default` and
  `pub fn summary(&self) -> JobSummary`;
  `JobSummary { job, state, phase, elapsed_ms, probes: ProbeCounters, points: PointCounters, issues: IssueCounters }`
  (the "summary fields" of D3's push line and `scan.list`; whole counter structs rather than
  trimmed copies, call A11). All counters are `Default`.
- **Change (`issue.rs`):**
  `BySeverity { critical: u64, high: u64, medium: u64, low: u64, info: u64 }` with
  `pub fn bump(&mut self, s: aitm_poc::Severity)`; `ByConfidence { certain, firm, tentative }` with `bump`;
  `IssueTarget { scheme: String, host: String, port: u16 }`;
  `L4Location { ip: String, port: u16, proto: L4Transport, grammar: Option<String>, field_path: Option<String>, mutation: Option<String> }`;
  `IssueLocation { method: Option<String>, path: String, path_template: String, kind: InsertionKind, name: String,
  field_path: Option<String>, ws_path: Option<String>, l4: Option<L4Location> }`;
  `Issue { id: IssueId, job: JobId, check_id: String, class: String, name: String, severity: aitm_poc::Severity,
  confidence: Confidence, status: IssueStatus, lane: LaneKind, target: IssueTarget, location: IssueLocation,
  evidence: Evidence, first_seen: u64, last_seen: u64, occurrences: u32, poc_ref: Option<String>,
  finding_id: Option<String>, description: String, remediation: Option<String>, note: Option<String> }`
  with `pub fn summary(&self) -> IssueSummary`;
  `IssueSummary` = the same fields minus `evidence`, `description`, `remediation`, `note` (call A12).
- **Change (`session.rs`):**
  `CanaryMethod { Get, Head }` with `#[serde(rename_all = "UPPERCASE")]` (tokens `GET`/`HEAD`);
  `Canary` `#[serde(tag = "kind", rename_all = "snake_case")] { None, Flow { method: CanaryMethod, path: String,
  #[serde(default)] expected_status: Option<u16> } }` (call A13; one type serves D5 and D7);
  `SessionProfile { origin: String, cookies: Vec<String>, headers: Vec<String>, source_flow: Option<FlowRef>,
  observed_at: u64, canary: Canary }` (names only, never a value);
  `SessionMaterial { pub cookies: Vec<(String, String)>, pub headers: Vec<(String, String)> }`:
  **no** `Serialize`/`Deserialize`, a hand-written `Debug` that prints names and `<redacted>` for
  every value, `Clone`, and `pub fn names(&self, origin: &str, source_flow: Option<FlowRef>, observed_at: u64, canary: Canary) -> SessionProfile`
  (the only way material becomes a wire type is by dropping its values). Doc comment: the
  engine holds this only in the worker's memory (D7).
- **Test:**
  `job_status_default_round_trips` and `by_lane_keys_are_lane_tokens`: a `JobStatus` whose
  `probes.by_lane` is `{Http: 400, Ws: 18}` round-trips and its JSON contains `"by_lane":{"http":400,"ws":18}`;
  `summary_drops_crawl_and_keeps_counters`: `status.probes.sent = 42`; `status.summary().probes.sent == 42`
  and the summary's JSON has no `crawl` key and no `started_by` key;
  `terminal_states`: `Done`, `Cancelled`, `Failed` are terminal; `Queued`, `Running`, `Cancelling` are not;
  `issue_summary_has_no_evidence`: `issue.summary()` JSON has no `evidence` and no `description` key
  and `id == "issue-9f8e7d6c"`;
  `by_severity_bump`: bumping `High` twice and `Info` once gives `high == 2, info == 1, critical == 0`;
  `canary_wire_shapes`: `Canary::None` is `{"kind":"none"}`; `Canary::Flow { method: Get, path: "/account", expected_status: None }`
  is `{"kind":"flow","method":"GET","path":"/account","expected_status":null}` (or without the
  key when `skip_serializing_if` is used; the test asserts the parsed value, and that the string
  contains `"method":"GET"`);
  `session_material_debug_redacts_values`: `format!("{:?}", SessionMaterial { cookies: vec![("sid".into(), "s3cr3t".into())], headers: vec![("authorization".into(), "Bearer abc".into())] })`
  contains `sid`, `authorization` and `<redacted>` and contains neither `s3cr3t` nor `Bearer abc`;
  `session_material_names_only`: `.names("http://t", None, 0, Canary::None).cookies == vec!["sid"]` and
  the `SessionProfile` JSON does not contain `s3cr3t`.
- **Done when:** the tests pass under `cargo test -p aitm-scan-model --offline` and the full gate passes.

### Task 7: `traits.rs`: `Check`, `ProbeHost`, `Lane`, `JobCtx`

- **Satisfies:** spec D2 traits, D1 "Registration without shared files" (the `Arc<dyn Lane>`
  slot type), D5 "Where a probe goes" (lanes get the job's client through `JobCtx`).
- **Depends on:** Tasks 4, 5, 6.
- **Files:** `crates/aitm-scan-model/src/traits.rs` (replace placeholder).
- **Change:** all traits object-safe, `Send + Sync`, `futures::future::BoxFuture` for async:
  - `pub trait Check: Send + Sync { fn meta(&self) -> &CheckMeta;
    fn run<'a>(&'a self, point: &'a InsertionPoint, host: &'a dyn ProbeHost) -> BoxFuture<'a, Verdict>; }`
  - `pub trait ProbeHost: Send + Sync {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>>;
    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>>;
    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>>;
    fn marker(&self) -> String; fn budget_left(&self) -> u32; fn deadline(&self) -> std::time::Instant;
    fn profile(&self) -> &ScanProfile; fn cancelled(&self) -> bool;
    fn held_flows(&self) -> Vec<aitm_core::Flow>; }`
    (`held_flows`: the probe/baseline flows the host kept in memory under `issues_only`, at
    most 16 per point, for the engine's issue re-recording of D5; call A14).
  - `pub trait JobCtx: Send + Sync { fn job_id(&self) -> &str; fn profile(&self) -> &ScanProfile;
    fn client(&self) -> Arc<dyn aitm_core::ProxyClient>; fn store(&self) -> Arc<dyn aitm_core::FlowStore>;
    fn guard(&self) -> Arc<dyn aitm_core::ScopeRateGuard>; fn browser(&self) -> Option<Arc<dyn aitm_core::BrowserDriver>>;
    fn session(&self) -> Option<Arc<SessionMaterial>>; fn charge(&self, units: u32) -> bool;
    fn budget_left(&self) -> u32; fn deadline(&self) -> std::time::Instant; fn cancelled(&self) -> bool;
    fn marker(&self) -> String; }`
    (the engine-owned per-job surface a lane consumes; `client()` is the job's budgeted
    `JobClient` as a `ProxyClient`; `charge` meters non-HTTP stimuli (WS frames, L4 cases) against
    the one job budget and returns `false` when exhausted; call A15).
  - `pub struct Discovery { pub points: Vec<InsertionPoint>, pub nodes: Vec<SiteNode> }` (`Default`).
  - `pub trait Lane: Send + Sync { fn lane(&self) -> LaneKind;
    fn discover<'a>(&'a self, target: &'a ProfileTarget, job: &'a dyn JobCtx) -> BoxFuture<'a, anyhow::Result<Discovery>>;
    fn probe_host_for(&self, point: &InsertionPoint, job: Arc<dyn JobCtx>) -> anyhow::Result<Box<dyn ProbeHost>>;
    fn checks(&self) -> Vec<Arc<dyn Check>>; }`
  - Module doc states the extension rule: after T1a, T1b may add methods to these traits
    **only with default bodies**, so a lane track in flight keeps compiling.
- **Test** (`#[cfg(test)]`): `traits_are_object_safe`: a function taking `&dyn Check`, `&dyn ProbeHost`,
  `&dyn Lane`, `&dyn JobCtx` compiles (compile-time proof) and is called with a test `NullLane`
  (`lane() == LaneKind::Http`, `discover` returns `Ok(Discovery::default())`, `probe_host_for`
  returns `Err`, `checks()` empty) stored as `Arc<dyn Lane>`: `lanes.len() == 1`,
  `lanes[0].lane() == LaneKind::Http`, `lanes[0].checks().is_empty()`;
  `discovery_default_is_empty`: `Discovery::default().points.is_empty() && nodes.is_empty()`.
- **Done when:** `cargo test -p aitm-scan-model --offline` passes; `cargo doc -p aitm-scan-model --no-deps --offline`
  builds without warnings; full gate passes.

### Task 8: `results.rs`: verb result types, job notification, method constant

- **Satisfies:** spec D3 (every verb result is a model type; the `notifications/aitm/job` params shape).
- **Depends on:** Tasks 4, 5, 6.
- **Files:** `crates/aitm-scan-model/src/results.rs` (replace placeholder).
- **Change:** result types (`#[serde(default)]` where a field is optional; tolerant of unknown keys):
  `StartResult { job: JobId, status: JobStatus, clamped: Vec<Clamped>, lanes: LaneReport }` (`scan.start`, `scan.map`);
  `ListResult { jobs: Vec<JobSummary> }`; `IssuesResult { issues: Vec<IssueSummary>, next_cursor: Option<String>, by_severity: BySeverity }`;
  `SitemapResult { nodes: Vec<SiteNode>, points: Vec<InsertionPoint>, next_cursor: Option<String> }`;
  `ChecksResult { checks: Vec<CheckMeta> }`;
  `ProfileListResult { profiles: Vec<ProfileListEntry> }`, `ProfileListEntry { name: String, builtin: bool, summary: ProfileSummary }`,
  `ProfileSummary { lanes: Vec<LaneKind>, intensity: Intensity, speed: Speed }` with `impl From<&ScanProfile> for ProfileSummary`;
  `ProfileSaveResult { saved: String, path: String }`; `ProfileDeleteResult { deleted: bool }`;
  `scan.status`/`scan.cancel` return `JobStatus`, `scan.issue`/`scan.issue.update` return `Issue`,
  `scan.profile.get` returns `ScanProfile`, `scan.session.preview` returns `SessionProfile` (documented, no new type);
  `JobEvent { Started, Phase, Progress, Issue, Finished, Cancelled, Failed }`;
  `JobNotification { job: JobId, kind: String, event: JobEvent, seq: u64, ts_ms: u64, status: JobSummary, issue: Option<IssueSummary> }`;
  `pub const JOB_NOTIFICATION_METHOD: &str = "notifications/aitm/job"; pub const JOB_KIND_SCAN: &str = "scan";
  pub const MAX_PROGRESS_LINES_PER_SECOND: u32 = 4;`.
- **Test:** `start_result_round_trips_with_skipped_lane`: a `StartResult` with
  `lanes.skipped == [SkippedLane { lane: Ws, reason: "lane not available on this build" }]` round-trips
  and its JSON contains `"skipped":[{"lane":"ws","reason":"lane not available on this build"}]`;
  `job_event_tokens`: `to_string(&JobEvent::Progress) == "\"progress\""`, `Finished` is `"finished"`;
  `notification_round_trips`: a `JobNotification` with `event: Issue`, `seq: 7`, `issue: Some(..)` round-trips
  and `JOB_NOTIFICATION_METHOD == "notifications/aitm/job"`;
  `profile_summary_from_standard`: `ProfileSummary::from(&builtin("standard").unwrap()) == ProfileSummary { lanes: vec![Http, Ws], intensity: Medium, speed: Normal }`;
  `issues_result_tolerates_missing_cursor`: parsing `{"issues":[],"by_severity":{}}` yields `next_cursor == None` and `by_severity == BySeverity::default()`.
- **Done when:** `cargo test -p aitm-scan-model --offline` passes and the full gate passes.

### Task 9: fixture pack and its parse test

- **Satisfies:** spec D12 ("a JSON/YAML fixture pack under `crates/aitm-scan-model/fixtures/`
  carrying one example of every verb result and push line"); spec Verification (fixtures are a
  development aid, never evidence).
- **Depends on:** Task 8.
- **Files:** `crates/aitm-scan-model/fixtures/README.md` (create),
  `crates/aitm-scan-model/fixtures/*.json` (create, 22 files below),
  `crates/aitm-scan-model/tests/fixtures.rs` (create).
- **Change:** one file per verb result and per push event, each a complete, realistic example
  whose values are consistent with one imagined job `scan-1a2b3c4d` against
  `http://127.0.0.1:8080`, with these pinned literals (the test asserts them):

  | File | Parses as | Pinned literal |
  |---|---|---|
  | `scan.start.json` | `StartResult` | `job == "scan-1a2b3c4d"`, `status.state == Queued`, `lanes.skipped == [{ws, "lane not available on this build"}]`, `clamped == [{ "budget.probes", 50000, 20000 }]` |
  | `scan.map.json` | `StartResult` | `lanes.run == [Http]`, `status.phase == Crawling` |
  | `scan.status.json` | `JobStatus` | `state == Running`, `phase == Auditing`, `probes.sent == 418`, `probes.budget == 2000`, `issues.total == 3`, `session.is_some()` |
  | `scan.list.json` | `ListResult` | `jobs.len() == 2`, `jobs[0].job == "scan-1a2b3c4d"` |
  | `scan.cancel.json` | `JobStatus` | `state == Cancelling` |
  | `scan.issues.json` | `IssuesResult` | `issues.len() == 2`, `by_severity.high == 1`, `next_cursor == None` |
  | `scan.issue.json` | `Issue` | `id == "issue-9f8e7d6c"`, `class == "reflected-xss"`, `severity == High`, `confidence == Certain`, `evidence.matched.is_some()`, `poc_ref.is_some()`, `finding_id.is_some()` |
  | `scan.issue.update.json` | `Issue` | `status == FalsePositive`, `note == Some("intended behaviour")` |
  | `scan.sitemap.json` | `SitemapResult` | a node with `path_template == "/account/{id}"`; a point with `kind == JsonValue` and `path == Some("profile.address.city")`; a point with `kind == Cookie` and `example == Some("<redacted>")` |
  | `scan.checks.json` | `ChecksResult` | `checks.len() == 3`; origins `Native`, `Bundled{..}`, `Custom{..}` each present |
  | `scan.profile.list.json` | `ProfileListResult` | `profiles.len() == 7`, every `builtin == true`, names == `BUILTIN_PROFILE_NAMES` |
  | `scan.profile.get.json` | `ScanProfile` | `== builtin("standard").unwrap()` (exact equality: the fixture is the constant) |
  | `scan.profile.save.json` | `ProfileSaveResult` | `saved == "my-api"`, `path` ends with `scan/profiles/my-api.yaml` |
  | `scan.profile.delete.json` | `ProfileDeleteResult` | `deleted == true` |
  | `scan.session.preview.json` | `SessionProfile` | `cookies == ["sid"]`, `headers == ["authorization"]`, `canary == Flow { Get, "/account", Some(200) }` |
  | `job.started.json` .. `job.failed.json` (7 files: `started`, `phase`, `progress`, `issue`, `finished`, `cancelled`, `failed`) | `JobNotification` | `kind == "scan"`, `event` matches the file name, `seq` strictly increasing 1..=7 in that order, `job.issue.json` has `issue.is_some()`, every other has `issue.is_none()`, `job.finished.json` `status.state == Done`, `job.failed.json` `status.state == Failed` |

  `fixtures/README.md`: what the pack is (the D3 contract as examples for T7/T8/T9 to develop
  against), the rule from the spec's Verification section verbatim in spirit ("no fixture run
  counts as acceptance evidence"), and that every value is invented and secret-free.
- **Test** (`tests/fixtures.rs`): `every_fixture_parses_into_its_model_type`: a table of
  `(file, parser closure)` covering all 22 files with the pinned assertions above (a missing file
  fails the test by name); `fixture_pack_is_complete`: the set of `*.json` files in the directory
  equals the 22 expected names (no stray, no missing); `no_fixture_carries_a_secret_value`: no
  file's text contains `Bearer `, `sid=`, `Set-Cookie`, `"Cookie":`, `"Authorization":` (the
  session preview carries names only; the sitemap cookie example is `<redacted>`);
  `push_sequence_is_monotonic`: the seven `job.*.json` `seq` values are `[1,2,3,4,5,6,7]`.
- **Done when:** `cargo test -p aitm-scan-model --offline --test fixtures` passes and the full gate passes.

### Task 10: five skeleton lane crates

- **Satisfies:** spec D1 "Registration without shared files" (skeleton `lane()`/`language()`
  slots), D12 row T1a ("skeleton `Cargo.toml`+`lib.rs` of the lane crates, handed over at T1a's
  merge"), Architect's call 1.
- **Depends on:** Task 7 (the `Lane`/`Check` traits).
- **Files:** `Cargo.toml` (modify: five members + five path entries),
  `crates/aitm-scan-http/{Cargo.toml,src/lib.rs}`, `crates/aitm-scan-checks-http/{Cargo.toml,src/lib.rs}`,
  `crates/aitm-scan-ws/{Cargo.toml,src/lib.rs}`, `crates/aitm-scan-l4-packet/{Cargo.toml,src/lib.rs}`,
  `crates/aitm-scan-l4-stream/{Cargo.toml,src/lib.rs}` (create, all).
- **Change:** each crate: `#![forbid(unsafe_code)]`, `[lints] workspace = true`, a crate doc
  naming its track (T2/T3/T4/T5/T6) and spec section (D8.1/D8.2/D8.3/D8.4/D8.5), and the
  **final** slot signature (a lane track flips the body, never the signature, because
  `crates/aitm/src/wire.rs` is frozen after T1a):
  - `aitm-scan-http` (deps `aitm-scan-model`): `pub fn lane() -> Option<std::sync::Arc<dyn aitm_scan_model::Lane>> { None }`.
  - `aitm-scan-checks-http` (deps `aitm-scan-model`): `pub fn checks() -> Vec<std::sync::Arc<dyn aitm_scan_model::Check>> { Vec::new() }`
    (this crate contributes native checks to the HTTP lane's catalogue, not a second `http` lane,
    so its slot is `checks()`; spec amendment of 2026-10-31, recorded as A16).
  - `aitm-scan-ws` (deps `aitm-scan-model`, `aitm-core`, `aitm-plugin`):
    `pub fn lane() -> Option<Arc<dyn Lane>> { None }` and
    `pub fn language(guard: Arc<dyn aitm_core::ScopeRateGuard>) -> Option<Box<dyn aitm_plugin::language::ProtocolLanguage>> { None }`
    (the `ws.*` host fns are `Guarded` through the scope guard, D8.3; `main.rs` passes its
    `LateHandles`, call A17).
  - `aitm-scan-l4-packet` and `aitm-scan-l4-stream` (deps `aitm-scan-model`, `aitm-proto-l4`):
    `pub fn lane(guard: Option<Arc<aitm_proto_l4::guard::L4Guard>>, store: Option<Arc<dyn aitm_proto_l4::flow::L4FlowStore>>) -> Option<Arc<dyn Lane>> { None }`
    (`wire.rs` passes `Features::l4_shared`; `None` when L4 is disabled. A landed L4 lane
    returns `Some` even when the handles are `None`, so that `scan.start` refuses with
    `refused_l4`, not `lane_unavailable`, when `l4.enabled` is false (D3 order); call A18).
  - Root `Cargo.toml`: members `crates/aitm-scan-http`, `crates/aitm-scan-checks-http`,
    `crates/aitm-scan-ws`, `crates/aitm-scan-l4-packet`, `crates/aitm-scan-l4-stream`; path
    entries `aitm-scan-http = { path = ... }` etc.
- **Test:** in each `lib.rs`, `skeleton_returns_none` (or `skeleton_returns_no_checks`):
  `aitm_scan_http::lane().is_none()`; `aitm_scan_checks_http::checks().is_empty()`;
  `aitm_scan_ws::lane().is_none()` and `aitm_scan_ws::language(Arc::new(aitm_core::StdGuard::default())).is_none()`;
  `aitm_scan_l4_packet::lane(None, None).is_none()`; `aitm_scan_l4_stream::lane(None, None).is_none()`.
- **Done when:** `cargo test --offline -p aitm-scan-http -p aitm-scan-checks-http -p aitm-scan-ws -p aitm-scan-l4-packet -p aitm-scan-l4-stream`
  passes, `cargo metadata --offline` exits 0, and the full gate passes.

### Task 11: wire the slots into the binary and the plugin

- **Satisfies:** spec D1 ("adds them to the workspace and to `crates/aitm/Cargo.toml`, and wires
  the calls in `crates/aitm/src/wire.rs` and `main.rs` up front"), D12 ("Only T1a and T1b touch
  `crates/aitm/src/**`").
- **Depends on:** Task 10.
- **Files:** `crates/aitm/Cargo.toml` (modify), `crates/aitm/src/wire.rs` (modify),
  `crates/aitm/src/main.rs` (modify), `crates/aitm-plugin-scanner/Cargo.toml` (modify: add
  `aitm-scan-model.workspace = true`), `crates/aitm-plugin-scanner/src/plugin.rs` (modify).
- **Change:**
  1. `crates/aitm/Cargo.toml`: `aitm-scan-model`, `aitm-scan-http`, `aitm-scan-checks-http`,
     `aitm-scan-ws`, `aitm-scan-l4-packet`, `aitm-scan-l4-stream` (all `.workspace = true`), with
     a comment: "scanner v2 lane slots (spec D1); each returns `None` until its track lands".
     Also switch this crate's `tokio-tungstenite = "0.28"` to `tokio-tungstenite.workspace = true`.
  2. `plugin.rs`: `ScannerPlugin` gains fields `lanes: Vec<Arc<dyn aitm_scan_model::Lane>>` and
     `native_checks: Vec<Arc<dyn aitm_scan_model::Check>>` (both empty in `new`), builder-style
     setters `pub fn with_lanes(mut self, lanes: Vec<Arc<dyn Lane>>) -> Self` and
     `pub fn with_native_checks(mut self, checks: Vec<Arc<dyn Check>>) -> Self`, and readers
     `pub fn lanes(&self) -> &[Arc<dyn Lane>]`, `pub fn native_checks(&self) -> &[Arc<dyn Check>]`.
     The shipped `load` ignores them (T1b consumes them); a doc comment says so.
  3. `wire.rs`: `pub fn collect_lanes(l4: Option<&L4Shared>) -> Vec<Arc<dyn aitm_scan_model::Lane>>`
     calling, in order, `aitm_scan_http::lane()`, `aitm_scan_ws::lane()`,
     `aitm_scan_l4_packet::lane(guard, store)`, `aitm_scan_l4_stream::lane(guard, store)` (guard/store
     cloned from `l4` when `Some`) and keeping the `Some`s; `pub fn collect_native_checks() -> Vec<Arc<dyn aitm_scan_model::Check>>`
     returning `aitm_scan_checks_http::checks()`. The `ScannerPlugin::new(ScannerConfig::default())`
     registration in `assemble_with_scripts` becomes
     `ScannerPlugin::new(..).with_lanes(collect_lanes(features.l4_shared.as_ref())).with_native_checks(collect_native_checks())`
     (the comment above it updated: "scanner v2 lane slots, spec D1").
  4. `main.rs`: before `languages` is built, `let ws_language = aitm_scan_ws::language(handles.clone());`
     (`handles` is the `Arc<LateHandles>` already used as the script tier's `ScopeRateGuard`);
     push `lang.as_ref()` into `languages` when `Some`; after the tier is built, register its
     `poc_step()` into `poc_step_handlers` when present (mirroring the `l4_language` block); drop it
     with the other borrows. `aitm tui` goes through `wire::assemble`, so its lanes are wired by
     step 3; it builds no Rhai languages today, so nothing changes there.
- **Test:** `wire.rs` tests module `skeleton_lane_slots_are_empty_today`:
  `collect_lanes(None).len() == 0` and `collect_native_checks().len() == 0` (the literal `0` is
  what T1a ships; a lane track's landing flips it and that track re-pins this test in its own
  integration task, which is allowed because `crates/aitm/src/**` is T1-owned and the lane
  tracks' plans declare the one-line re-pin); and the existing `assemble` tests still pass
  (`assembled_ingress_dispatches_or_refuses_tcp`, `l4_guard_tracks_l4_enabled`).
  `plugin.rs` test `with_lanes_keeps_the_handles`: a test `Lane` impl (`lane() == LaneKind::Http`)
  passed via `with_lanes(vec![Arc::new(TestLane)])` gives `plugin.lanes().len() == 1`,
  `plugin.lanes()[0].lane() == LaneKind::Http`, `plugin.native_checks().is_empty()`; and the three
  existing plugin tests still pass unchanged (the registry still exposes exactly `scan.discover`,
  `scan.passive`, `scan.report`).
- **Done when:** `cargo test -p aitm --lib --offline wire` and `cargo test -p aitm-plugin-scanner --offline`
  pass in the sandbox; `cargo tree -p aitm --offline -e normal --depth 1 | grep -c 'aitm-scan-'` prints `6` (without `--depth 1` it prints 12, because each lane crate re-lists the model crate)
  (quoted); the full gate passes in the Terminal (port-binding tests).

### Task 12: integration: merge `origin/main`, gate, real boot proof

- **Satisfies:** spec D12 "Integration-shared files" (every track's plan ends with an integration
  task), spec Verification (a real core, never a fixture), AC T1a-1 (whole-branch run).
- **Depends on:** Task 11 (and every earlier task merged into `feat/scanner-v2-t1a`).
- **Files:** none new. If the merge conflicts, only the conflicting hunks; if `tools/list`
  moved on `main` the integration-shared files are **not** edited by this task (T1a adds no
  verb), only re-run.
- **Change / steps** (Terminal for `git fetch`/merge/push and for anything binding a port):
  1. `git fetch origin && git merge origin/main` on `feat/scanner-v2-t1a` (merge, not rebase:
     the branch already carries the spec/plan commits; a stacked-PR check: `baseRefName == main`).
     If PR #199 (redaction consolidation) is on `main`, nothing in T1a overlaps it; note which
     applied.
  2. Full gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`;
     quote the final `test result:` lines and the exit code (`echo $?`), never a grep.
  3. Contract check without a re-pin: `cargo test -p aitm --test frontends` passes with
     `EXPECTED_TOOLS` untouched (T1a adds no verb); quote the output.
  4. **Real boot proof** (Terminal): `cargo build -p aitm -p aitm-testtarget` then
     `python3 tests/e2e/run.py smoke mcp --jobs 2`. The `mcp/test_tool_list_complete.py` cell
     boots a real core from the freshly built binary, asserts the live `tools/list` equals
     `EXPECTED_TOOLS` (so the contract is unchanged with the model crate and the five lane crates linked in) and
     drives one real request through the proxy, asserting `flow.list` returns the captured id;
     the `smoke/test_http1_capture.py` and `smoke/test_lib_additions.py` cells drive real HTTP
     through the real proxy to a real upstream and read the capture over the bus. Quote the
     runner's per-suite PASS lines and its exit code. A SKIP (77) in any of these cells is a
     failure of this task's proof, not a pass.
  5. `cargo tree -p aitm -e normal | grep 'aitm-scan-'` quoted: the model crate and the five
     lane crates are linked into the binary that just served the e2e traffic.
  6. Push with an explicit refspec (`git push origin feat/scanner-v2-t1a`) and open the PR with
     the plan path, the gate output and the e2e output in the description.
- **Test:** the commands above; the proof is their quoted output.
- **Done when:** the gate exits 0, `run.py smoke mcp` exits 0 with every cell PASS, the tree
  shows the model crate plus the five lane crates, and the panel review (stage 6) has no open findings.

## File ownership matrix (disjointness check)

| Task | Files |
|---|---|
| 1 | `Cargo.toml` (root), `crates/aitm-scan-model/{Cargo.toml, src/lib.rs, src/ids.rs, src/vocab.rs}`, placeholders `src/{profile,point,check,job,issue,session,traits,results}.rs` |
| 2 | `crates/aitm-core/src/{client.rs, ctx.rs, lib.rs}` |
| 3 | `crates/aitm-proto-l4/src/{guard.rs, types.rs (doc), config.rs (doc)}` |
| 4 | `crates/aitm-scan-model/src/profile.rs`, `crates/aitm-scan-model/tests/builtin_profiles.rs` |
| 5 | `crates/aitm-scan-model/src/{point.rs, check.rs}` |
| 6 | `crates/aitm-scan-model/src/{job.rs, issue.rs, session.rs}` |
| 7 | `crates/aitm-scan-model/src/traits.rs` |
| 8 | `crates/aitm-scan-model/src/results.rs` |
| 9 | `crates/aitm-scan-model/fixtures/**`, `crates/aitm-scan-model/tests/fixtures.rs` |
| 10 | `Cargo.toml` (root, after Task 1), `crates/aitm-scan-{http,checks-http,ws,l4-packet,l4-stream}/**` |
| 11 | `crates/aitm/{Cargo.toml, src/wire.rs, src/main.rs}`, `crates/aitm-plugin-scanner/{Cargo.toml, src/plugin.rs}` |
| 12 | none (merge + proof) |

Within a wave no two tasks share a file. The root `Cargo.toml` is edited by Task 1 (wave 1)
and Task 10 (wave 4), sequentially.

## Architect's calls in this plan (for the orchestrator/Matt to approve or correct)

- **A1** The D2 enum `Lane` is named `LaneKind` in code because `Lane` is the trait every
  lane crate implements (`Arc<dyn Lane>` is the slot type the spec and the task brief use).
  Wire tokens and the `lane` field names are unchanged.
- **A2** `CheckOrigin` is kind-tagged on the wire: `{"kind":"native"}`,
  `{"kind":"bundled","path":...}`, `{"kind":"custom","path":...}`.
- **A3** Crawl defaults `max_depth 3`, `max_pages 200` (today's `ScannerConfig`), forms/clicks/
  robots/sitemap on, `use_browser: auto`.
- **A4** `budget.check_timeout_s` (default 60) lives in the profile's budget block, which is
  what D4's "profile's `check_timeout`" names; `scanner.check_timeout_s` in config (D11) stays
  the ceiling.
- **A5** `passive-only` = `[http]`, `passive`, `crawl.max_pages 0`, `use_browser never`
  (passive checks over already-captured in-scope flows); `map-only` crawls.
- **A6** `InsertionPoint` carries `method` and `url` (both `Option`) because the D4 Rhai
  point map exposes them.
- **A7** One `SiteNode` type is the union of D3's sitemap node and D8.1's `SiteNode`
  (`params`, `auth`, `points`, `audited` all `#[serde(default)]`).
- **A8** `Payload`, `RawProbe`, `ProbeResponse`, `Frame`, `L4Reply` are in-process types
  without serde; `SessionMaterial` has no serde by design and a redacting `Debug`.
- **A9** `L4Evidence.reproduced` is a `(u32, u32)` pair, `[k, n]` on the wire.
- **A10** `L4Oracle` is kind-tagged; `icmp` carries `type` and `code`.
- **A11** `JobSummary` (push line, `scan.list`) carries the whole `probes`/`points`/`issues`
  counter structs rather than trimmed copies; it drops `crawl`, `checks`, `l4`, `session`,
  `started_by`, `clamped`, `lanes`, `error`, timestamps.
- **A12** `IssueSummary` = `Issue` minus `evidence`, `description`, `remediation`, `note`.
- **A13** `Canary` is kind-tagged (`{"kind":"none"}` / `{"kind":"flow",...}`) and serves both
  D5's status and D7's session profile; `expected_status` is optional.
- **A14** `ProbeHost::held_flows()` exposes the in-memory probe/baseline flows so the engine
  can re-record them when a verdict is `vulnerable` (D5 record policy).
- **A15** `JobCtx` is the model-crate trait through which a lane reaches the job's client,
  store, guard, browser, session material, budget (`charge`), deadline and cancellation; it
  names only `aitm-core` types, so the model crate's dependency set stays as D1 says.
- **A16** (decided by the spec amendment of 2026-10-31, not a call) `aitm-scan-checks-http`
  is not a lane: it exposes `checks() -> Vec<Arc<dyn Check>>`, `wire.rs` collects that list,
  and `ScannerPlugin` takes it as `native_checks` beside the lanes (Tasks 10 and 11). D1's
  "five lane crates" is the correct count; the model crate makes six scan crates in the binary.
- **A17** `aitm_scan_ws::language` takes the scope guard (`Arc<dyn ScopeRateGuard>`) so the
  `ws.*` host fns can be `Guarded` at build time; `main.rs` passes its `LateHandles`.
- **A18** The L4 lane slots take `Option<Arc<L4Guard>>` and `Option<Arc<dyn L4FlowStore>>` from
  `Features::l4_shared`; a landed lane returns `Some` even with `None` handles so the
  `refused_l4`-before-`lane_unavailable` order of D3 holds.
- **A19** Workspace dependencies declared beyond the spec's list: `rand_chacha` (a seedable
  RNG whose stream is stable across `rand` versions, so an L4 case replays from its
  `rng_seed`), `url`, `regex`, `bytes`, `serde`, `serde_json` (the lane tracks need them and
  may not edit the root manifest). `tokio-tungstenite`'s per-crate dev-dep literals in
  `aitm-proto-ws`/`aitm-plugin-wsctl` are left as they are (same lock entry; not T1a files).
- **A20** Wire timestamps are epoch milliseconds (`u64`), the push line's `ts_ms` convention.
- **A21** The profile tree is `deny_unknown_fields`; result types are tolerant.
- **A22** `RequestSender::send_with(req, version)` with a default delegating to `send` is the
  additive core seam that lets `PipelineClient::send_opts` hand the version policy to T3's
  `HttpSender` without changing `HttpRequest.version` (D8.2: it "stays what the sender observed").
- **A23** Task 11's `collect_lanes`/`collect_native_checks` test pins the literal `0`; each lane
  track's integration task re-pins that one line when it flips its slot to `Some`.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
