# T7 fix round A: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows marked "fix round A").
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D3, D5, D7, D10, D11, D12, D13 as amended 2026-11-01).
**Range reviewed:** `6a95f777..f157d987` (Tasks 1 to 4) plus Task 5 once it lands. Each finding names the file; the fix Coder may touch only those files plus the test file that reproduces each finding.

For each finding: write a test that reproduces it and fails, fix it, watch it pass. Commit as `fix(tui-scan): <finding title>`. Do not fix anything not listed here.

## Important

A1. **Contract-mismatch wording repeats the verb.** `crates/aitm-tui/src/scan/mod.rs` `parse_result`: the detail must be `reply did not match the contract (<serde error>)` with no verb; `wording()` adds the `<verb>: ` prefix once. Test (`tests/scan_v2_parse.rs` `a_malformed_reply_is_a_contract_error`): replace the computed assertion with the literal `err.wording().starts_with("scan.status: reply did not match the contract (")` and `!err.wording().contains("scan.status: scan.status")`.

A2. **Site map pane-to-list choice is made twice and the copies disagree.** `crates/aitm-tui/src/scan/mod.rs` (`cursor_mut`), `crates/aitm-tui/src/scan/sitemap.rs`, `crates/aitm-tui/src/app.rs` (`Action::Enter` for `ScanTab::SiteMap`). One decision keyed on the bus, not on list emptiness: `pub enum MapSource { Legacy, V2 }` with `SitemapState::source(offer: ScanOffer) -> MapSource` (`V2` only when `offer == ScanOffer::V2`); `ScanState::cursor_mut(&mut self, offer: ScanOffer)` and a new `ScanState::sitemap_selected_flow(&self, offer: ScanOffer) -> Option<String>` both read it; the `Enter` arm becomes one call. Test (`tests/scan_v2_matrix.rs`): on a V2 app with `sitemap.nodes` filled from `scan.sitemap.json` and legacy lists empty, `Down` then `Enter` selects the v2 node's first flow (after a `Flows` event carrying that id) and never a legacy row; on a legacy app the existing `scan_surface.rs` tests keep passing.

A3. **Banner reads `idle` on a degraded tab.** `crates/aitm-tui/src/ui/scan/mod.rs` `banner()`: under `ScanOffer::Legacy` the Profiles and Issues banners read the D2 degraded text (`profiles need scan.profile.list (scanner v2)`, `issues need scan.issues (scanner v2)`); under `V2` with the tab's verb missing, `<verb> is not on this bus`; the pane body no longer repeats it (D13: exactly one state on screen). Test (`tests/scan_v2_matrix.rs` `legacy_bus_opens_on_jobs_...`): the strip row of the Profiles tab ends with the degraded literal, not `idle`.

## Minor

A4. `scan_host` mis-parses a bare IPv6 literal (`crates/aitm-tui/src/scan/mod.rs`): strip a port only when the text after the last colon is all digits and the remainder holds at most one colon, or when the host is bracketed. Test: `scan_host("::1") == "::1"`, `scan_host("[::1]:8080") == "::1"`, `scan_host("host:8080") == "host"`, `scan_host("fe80::1") == "fe80::1"`. Also drop the unreachable `unwrap_or` fallback (`split` always yields one item).

A5. Confirm overlay survives a `Disconnected` (`crates/aitm-tui/src/app.rs` `BusEvent::Disconnected`): when `mode == Mode::WireConfirm`, clear `wire_confirm`, set `mode = wire_confirm_from`, toast `<call> confirmation dropped: bus disconnected`. Test in `tests/scan_v2_confirm.rs`.

A6. Remove the unused `pub type L4Confirm` alias and its false doc comment (`crates/aitm-tui/src/l4.rs`); `grep -rn L4Confirm crates/aitm-tui/src` must find nothing.

A7. Two `tests/scan_v2_confirm.rs` assertions pass with the behaviour broken: use a distinctive prompt literal (`"Prompt-7Q verbatim"`) and assert `text.contains(...)`; in the cancel test set `app.wire_confirm_from = Mode::Scan` before cancelling and assert `app.mode == Mode::Scan` literally.

A8. `_confirm` spelled in three places: one `pub const CONFIRM_KEY: &str = "_confirm";` in `crates/aitm-tui/src/action.rs`, used by `bus.rs` (`prune`), `scan/launch.rs` (`confirmed_args`) and `fixture.rs`.

A9. Transport-vs-refusal split written three times in `crates/aitm-tui/src/bus.rs` (`subscribe`, `perform`, `call_failed`): one `fn refusal(e: BusError) -> Result<String, Outcome>` used by all three.

A10. `parse_result` clones every reply (`crates/aitm-tui/src/scan/mod.rs`): deserialize from `&Value` (`T::deserialize(value)` with `serde::Deserialize` in scope).

A11. Overlay call-name line uses `theme.l4()` for `scan.*` calls (`crates/aitm-tui/src/ui/scan/confirm.rs`): `accent()` for a `scan.` call, `l4()` for an `l4.` call (D13: hue only on data).

A12. `panes()`/`pane_rule()` (`crates/aitm-tui/src/ui/scan/mod.rs`): one helper returning `{ list, detail, rule: Option<Rect> }`, arithmetic in `u32`; test: renders at `Rect::new(0, 0, 1500, 60)` without panic and the list width is `1500 * 45 / 100`.

A13. Legacy `scan.discover` failure reason is stored but never drawn (`crates/aitm-tui/src/ui/scan/mod.rs` `tab_error`): under `ScanOffer::Legacy` the Jobs tab's error is `legacy.error` wrapped as `ScanError::from_message("scan.discover", e)`. Test (`tests/scan_surface.rs` or `scan_v2_matrix.rs`): after a `CallFailed { name: "scan.discover", message: "out of scope" }` the Jobs tab screen contains `scan.discover: out of scope`.

A14. `SCAN_CHROME_ROWS` doc comment (`crates/aitm-tui/src/app.rs`): make it true (three bars, two box edges, the strip-and-banner row, a heading row, a rule, a detail line, one spare footer row), drop the repeated `= 10` in the `navigate()` prose. Constant and test literal unchanged.

A15. `step` wrap helper duplicated (`crates/aitm-tui/src/scan/mod.rs`, `crates/aitm-tui/src/app.rs`): one `pub(crate) fn step<T: PartialEq + Copy>(all: &[T], cur: T, forward: bool) -> T` in `scan/mod.rs`, used by both.

A16. No-scanner sentence as a const and as a toast literal: `pub const NO_SCANNER` moves to `crate::scan` (`scan/mod.rs`); `ui/scan/mod.rs` and the `app.rs` toast use it.

A17. Sidebar computes "newest non-terminal job" inline (`crates/aitm-tui/src/ui/sidebar.rs`): `impl JobsState { pub fn newest_active(&self) -> Option<&JobSummary> }` in `crates/aitm-tui/src/scan/jobs.rs`; the sidebar calls it.

A18. `legacy_app` helper and the 15-verb list duplicated in `tests/scan_surface.rs` and `tests/scan_v2_matrix.rs`: one `legacy_app(cols, rows)` in `tests/common/mod.rs` that retains `scan.discover` and every non-`scan.` tool, then asserts `app.scan_offer() == ScanOffer::Legacy`; both files use it.

A19. Tab strip hygiene (`crates/aitm-tui/src/ui/scan/mod.rs`): `enumerate()` instead of `tab.index() + 1`; one `const GAP: usize = 4` for the strip gap; the per-file `pub const DEGRADED` become private `const`.

A20. First `Esc` on the legacy Site map flips Points to Nodes instead of leaving (`crates/aitm-tui/src/scan/mod.rs` `close_pane`, `crates/aitm-tui/src/app.rs` `Back`): under `ScanOffer::Legacy`, `Back` leaves to `Mode::Flows` at once (D12 "nothing changes in behaviour"). Test in `tests/scan_surface.rs`: `open_site_map`, `Back` gives `Mode::Flows`.

## Not in this round (dispositioned elsewhere)

The `IssueFilters.severity_min` type and its doc comment (Task 7); the two `format!("http://{host}/")` sites (Task 9); the Profiles list placeholder arm (Task 11); the legacy Jobs hint line (Task 14).
