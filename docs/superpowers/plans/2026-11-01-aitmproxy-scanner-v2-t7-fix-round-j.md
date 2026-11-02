# T7 fix round J: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows for the second Task 17 merge `0063a726`: security PASS with one Minor, quality PASS with seven Minor, spec PASS with four Minor).
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D3 `WireConfirm`, D7 wire confirm, D11 help).
**Range reviewed:** merge `0063a726` (main `a2ab31c3`, #263 L4 parity (b) beside the Scan surface). The fix Coder may touch only the files each finding names plus the test file that reproduces it.

J1 changes behaviour: write the reproducing test first. Commit as `fix(tui-scan): J1 ...` and `refactor(tui-scan): J2-J6 ...`, each by path. Do not fix anything not listed here.

## Behaviour

J1. **`l4.pending` survives a bus disconnect** (`crates/aitm-tui/src/app.rs` `BusEvent::Disconnected` arm ~4198-4220 and `forget_inflight()` ~2769; security Minor). Every other in-flight confirm state is dropped there (`wire_confirm`, `scan.launch.pending`, `scan.inflight`, `issues.pending_read`) but not `App::l4.pending`, so after a reconnect the same L4 control stays refused by `l4_in_flight` ("already waiting for the core") until an unrelated reply of that name arrives, and a later palette-typed call of the same name would bind its handshake to the stale args. Fix: clear `self.l4.pending = None` inside `forget_inflight()` (both `Disconnected` and `Connected` call it). Test (`tests/l4_parity.rs` or `tests/scan_v2_confirm.rs`, whichever has the L4 scaffolding): set `app.l4.pending = Some(("l4.inject".into(), json!({"flow": "f1"})))`, fold `BusEvent::Disconnected("x".into())`, assert `app.l4.pending.is_none()`; then after a `Connected` and an available in-scope craft flow, `Action::L4Inject` yields exactly one `BusRequest::Call { name: "l4.inject", .. }` and no "already waiting" toast.

## Structure

J2. `PROMPT_FRAME_ROWS = 5` overstates the trailer when the footnote is `None` (`crates/aitm-tui/src/ui/scan/confirm.rs:68-70, 94-99`; quality Minor): bind the footnote once and derive the frame from it, `let footnote = family.footnote(&c.call); let frame = 4 + usize::from(footnote.is_some());`, pass `frame` to `wrap`; delete `PROMPT_FRAME_ROWS` or re-doc it as the no-footnote frame; fix the "three trailer rows" comment. Guard: `tests/l4_parity.rs::chips_filters_confirm_footer_only_for_inject` and `tests/scan_v2_confirm.rs` overlay tests.

J3. Two dead writes to `wire_confirm_from` (`crates/aitm-tui/src/app.rs:2198` in `l4_inject`, `:2324` in `l4_intercept_verb`): delete both; `open_wire_confirm(confirm, from)` is the single writer (the L4 `CallOk` arm chooses `from` by name).

J4. `help_scope_add_l4` is a private one-user wrapper the reducer spells differently (`crates/aitm-tui/src/ui/overlays.rs:226, 259-260, 284`; `crates/aitm-tui/src/app.rs:3257`): drop the wrapper and call `crate::l4::supports_operator_scope_add(&app.tools)` directly in `help()`, or make it `pub` and use it from the reducer's clamp too; fix the `help_scroll_max` doc that links a pub fn's parameter to a private fn.

J5. Test name no longer describes its assertion (`crates/aitm-tui/tests/l4_parity.rs:3419` `help_footer_counts_exactly_the_hidden_lines_and_only_when_some_are`): rename to `help_more_marker_shows_exactly_when_lines_are_hidden_and_end_reaches_the_closing_hint`. Also (spec Minor 4, optional) retitle `quality_toast_text_renders_inert` (~3720) to say the toast is cleaned at store time and inert on render; no behaviour change.

J6. Two doc comments describe dropped or narrowed behaviour: `crates/aitm-tui/src/ui/l4.rs:1` becomes "The L4 operator surface's inspector and the L4 panel (the wire-confirm overlay is `ui::scan::confirm`)"; `crates/aitm-tui/src/l4.rs:897` `pending` doc becomes "A pending guarded call (`l4.inject`, `l4.scope.add`, an intercept verdict) awaiting its `needs_confirmation` reply."

## Not in this round (dispositions)

- The two `unavailable — <reason>` pane strings in `ui/l4.rs:56, 448` are pinned outside this crate (`crates/aitm/tests/l4_cua_tui.rs:737, 795, 800`, `tests/e2e/l4/test_l4_tui_live.py:459-467`, L4 parity plan B6); per H19's rule they stay and are reported: follow-up for the L4 parity owner (change both strings to `unavailable: {reason}` with their pins together, the H40 pattern).
- One `WireConfirm`, two reply idioms (`classify` on the L4 arm, `from_reply` on the scan arm): accepted; D7's scan fall-through to the `StartResult` parse surfaces a malformed handshake as a `ScanError`, nothing swallowed.
- Spec D3 (`ConfirmReply`/`classify`), D7 and Task 3 (footnote for `l4.inject` only per L4 parity B7; `l4.scope.add` returns to `Mode::Scope`): orchestrator doc amendments, this round.
- The two test-precondition hunks the merge added (`scan_v2_confirm.rs` `L4Availability` before `L4Inject`; `scan_v2_launch.rs` `app.l4.pending` before the `l4.inject` handshake): ratified as semantic-merge necessities (B10 honest availability; name-bound pending) in the Review log.
