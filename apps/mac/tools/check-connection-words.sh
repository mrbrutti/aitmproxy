#!/usr/bin/env bash
# ST-AC5 tripwire (spec 2026-10-31-macos-status-page-and-first-run-design): every connection
# indicator — sidebar brand row, toolbar pill, status bar, Status page, Core Log header,
# Settings rows — draws its core/bus/capture state words from `ConnectionSummary`. No view may
# spell a lane word itself, so two surfaces can never disagree about the same state.
#
# Greps the APP target (views) for the lane words as quoted string literals. The Kit models that
# define them (ConnectionSummary, CaptureAdvice, CaptureCapability) are outside the scan root.
# Exit 0 + PASS on a clean tree; exit 1 listing each offending file:line otherwise.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
words='"(running|not running|starting…|restarting…|stopped|failed|external|connected|connecting…|offline|bus failed|capture on|capture off|capture degraded|waiting for approval|on, nothing in scope|no extension|Capturing|Approved|Awaiting approval|core running|core failed)"'
# Skipped: comments, the self-test (it ASSERTS the words), and filter values (`FilterRow(.state, …, "failed")`
# is a flow-state query, not a connection word).
hits=$(grep -rnE --include='*.swift' -e "$words" Sources/Aitmproxy | grep -vE ':[0-9]+:[[:space:]]*///?' | grep -v 'SelfTest' | grep -v 'FilterRow(' || true)
if [ -n "$hits" ]; then
  printf '%s\n' "$hits"
  echo "FAIL check-connection-words: a view spells a connection state word; read it from ConnectionSummary instead"
  exit 1
fi
echo "PASS check-connection-words"
