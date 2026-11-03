#!/bin/bash
# Task 4.6 / AC61: the canonical TUI acceptance cell against the real core (self-boot), binaries from the TUI branch tip.
TWT=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/scan-jobs-view-tui
HWT=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/web-harness-audit-log
cd "$TWT" || exit 90
git log --oneline -1
mkdir -p /tmp/claude/tui-cell
AITM_BIN=$TWT/target/release/aitm AITM_TESTTARGET_BIN=$HWT/target/release/aitm-testtarget-serve AITM_TUI_BIN=$TWT/target/release/aitm-tui AITM_E2E_ARTIFACTS=/tmp/claude/tui-cell python3 -I tests/e2e/tui/test_tui_scan_live.py
echo "TUI-CELL-DONE exit $?"
