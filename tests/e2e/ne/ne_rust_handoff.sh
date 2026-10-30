#!/usr/bin/env bash
# e2e: surface=ne tier=auto
# The macOS Network Extension provider<->core handoff, loop-avoidance and capability
# seam, asserted by the real Rust integration tests (crates/aitm/tests/macos_capture_*).
# These bind Unix domain sockets, so they run here (unsandboxed) rather than in CI's
# restricted sandbox. No signed build and no running core needed — pure Rust.
set -u
source "$(dirname "$0")/../lib/contract.sh"
repo="$(cd "$(dirname "$0")/../../.." && pwd)"

command -v cargo >/dev/null 2>&1 || e2e_skip "cargo not available"
[ "$(uname -s)" = "Darwin" ] || e2e_skip "macOS capture seam only builds on macOS"
cd "$repo" || e2e_fail "repo root not found: $repo"

# The six macos_capture integration targets: adapter -> CaptureIngress, availability,
# capability, the activation gate (deny-by-default), the UDS listener round-trip, and
# the no-CA-key handoff. Naming the targets runs every test in each, regardless of fn name.
cargo test -p aitm \
  --test macos_capture_adapter \
  --test macos_capture_availability \
  --test macos_capture_capability \
  --test macos_capture_gate \
  --test macos_capture_listener \
  --test macos_capture_no_key
e2e_check $? "macos_capture provider<->core handoff + loop-avoidance + capability + no-key"
e2e_pass "NE Rust seam verified"
