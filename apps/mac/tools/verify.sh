#!/bin/zsh
# The whole check after a build: unit tests, the in-app self-test, the main-screen
# snapshots (light + dark) and the parts gallery. Prints one line per step.
# Usage: tools/verify.sh [pages]     default pages: apps
set -u
here=${0:A:h:h}
pages=${1:-apps}
cd "$here" || exit 1
echo "== unit tests"
swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build 2>&1 | grep -E 'Test run|failed|error:' | tail -6
echo "== self-test"
tools/selftest.sh 2>&1 | grep -E 'FAIL|SELFTEST' | grep -v '^PASS' || echo 'SELFTEST: no output'
echo "== snapshots ($pages)"
APP_SNAPSHOT_PAGES=$pages tools/snap.sh 2>&1 | grep -E 'SNAPSHOT done|error|fallback'
echo "== parts gallery"
rm -rf /tmp/Aitmproxy-gallery /tmp/Aitmproxy-gallery-state
mkdir -p /tmp/Aitmproxy-gallery-state
APP_KIT_GALLERY=1 APP_STORE=/tmp/Aitmproxy-gallery-state APP_SNAPSHOT=/tmp/Aitmproxy-gallery \
  ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy 2>&1 | grep -E 'SNAPSHOT done|error|fallback'
echo "== grid"
tools/grid-lint.sh | tail -1
echo "== capture guards"
# The two capture tripwires are real gates, not informational lines like the grep-filtered
# steps above: a failing one prints its own output (the offending file:line) and makes
# verify.sh exit non-zero. `tool >/dev/null && echo PASS || echo FAIL` printed FAIL but
# threw the exit status away, so a red tripwire still read as a green verify.
guards_failed=0
capture_guard() { # capture_guard <label> <tool>
  local label=$1 tool=$2 out
  if out=$("$tool" 2>&1); then
    echo "$label: PASS"
  else
    printf '%s\n' "$out" | sed 's/^/    /'
    echo "$label: FAIL"
    guards_failed=1
  fi
}
capture_guard "operator-only" tools/check-capture-operator-only.sh
capture_guard "toggle wiring" tools/check-capture-toggle.sh
exit "$guards_failed"
