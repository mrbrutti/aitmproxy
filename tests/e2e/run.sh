#!/usr/bin/env bash
# Stopgap aggregate runner until tests/e2e/run.py (the e2e-framework runner, PR #110)
# lands on main. Runs tests/e2e/<surface>/test_*.py and classifies each by exit code,
# per the settled contract: 0 = PASS, 77 = SKIP, anything else = FAIL. Exits non-zero
# iff any suite FAILs; skips are loud, never green.
#
#   tests/e2e/run.sh              # all surfaces
#   tests/e2e/run.sh ca poc       # only these surfaces
#
# Binaries: $AITM_BIN / $AITM_TESTTARGET_BIN, else target/{debug,release}.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
py="${PYTHON:-python3}"
surfaces=("$@")
[ "$#" -eq 0 ] && surfaces=(ca poc findings scripting)

fail=0
for s in "${surfaces[@]}"; do
  for t in "$here/$s"/test_*.py; do
    [ -e "$t" ] || continue
    echo ""
    echo "########## $s/$(basename "$t") ##########"
    "$py" "$t"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      :
    elif [ "$rc" -eq 77 ]; then
      echo "(suite skipped)"
    else
      fail=1
    fi
  done
done

echo ""
[ "$fail" -ne 0 ] && echo "E2E GATE: FAIL" || echo "E2E GATE: PASS"
exit "$fail"
