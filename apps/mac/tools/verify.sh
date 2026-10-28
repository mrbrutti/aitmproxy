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
tools/selftest.sh 2>&1 | grep -E 'FAIL|SELFTEST'
echo "== snapshots ($pages)"
APP_SNAPSHOT_PAGES=$pages tools/snap.sh 2>&1 | grep -E 'SNAPSHOT done|error|fallback'
echo "== parts gallery"
rm -rf /tmp/Aitmproxy-gallery /tmp/Aitmproxy-gallery-state
mkdir -p /tmp/Aitmproxy-gallery-state
APP_KIT_GALLERY=1 APP_STORE=/tmp/Aitmproxy-gallery-state APP_SNAPSHOT=/tmp/Aitmproxy-gallery \
  ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy 2>&1 | grep -E 'SNAPSHOT done|error|fallback'
echo "== grid"
tools/grid-lint.sh | tail -1
