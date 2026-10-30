#!/usr/bin/env bash
# e2e: surface=ne tier=auto
# The capture-capability state machine, the tunnel reconcile policy and the transient-
# failure classifier, asserted by the real Swift unit tests
# (apps/mac/Tests/AitmproxyKitTests/CaptureCapabilityTests). No signed build or running
# core needed.
set -u
source "$(dirname "$0")/../lib/contract.sh"
repo="$(cd "$(dirname "$0")/../../.." && pwd)"

command -v swift >/dev/null 2>&1 || e2e_skip "swift not available"
[ "$(uname -s)" = "Darwin" ] || e2e_skip "macOS app only builds on macOS"
cd "$repo/apps/mac" || e2e_fail "apps/mac not found under $repo"

swift test --scratch-path "$HOME/Library/Developer/Aitmproxy/test-build" --filter CaptureCapabilityTests
e2e_check $? "CaptureCapability state machine + TunnelReconcilePolicy + TunnelFailure"
e2e_pass "NE Swift capability tests verified"
