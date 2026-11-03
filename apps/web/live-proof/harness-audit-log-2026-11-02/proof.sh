#!/bin/bash
# Live proof AC7 of docs/superpowers/specs/2026-11-02-web-harness-audit-log-isolation.md; copied from the plan's Task 4.
set -u
WT=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/web-harness-audit-log
EV="$WT/apps/web/live-proof/harness-audit-log-2026-11-02"
REAL="$HOME/Library/Application Support/aitmproxy"
snap() {
  for f in audit.jsonl audit.agent.jsonl audit.reads.jsonl ca-audit.jsonl system-proxy-state.json; do
    if [ -e "$REAL/$f" ]; then
      echo "$f $(stat -f '%z %m' "$REAL/$f") $(shasum -a 256 "$REAL/$f" | cut -d' ' -f1)"
    else
      echo "$f absent"
    fi
  done
}
snap > "$EV/real-before.txt"
touch "$EV/.marker"
cd "$WT/apps/web"
env -u AITM_AUDIT_LOG AITM_BIN="$WT/target/release/aitm" \
  AITM_TESTTARGET_BIN="$WT/target/release/aitm-testtarget-serve" \
  node scripts/scan-live.mjs > "$EV/scan-live.log" 2>&1
echo "scan-live exit $?" >> "$EV/scan-live.log"
snap > "$EV/real-after.txt"
diff "$EV/real-before.txt" "$EV/real-after.txt" && echo "REAL FILES UNCHANGED" || echo "REAL FILES CHANGED"
: > "$EV/run-dirs.txt"
for d in $(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'aitm-live-*' -newer "$EV/.marker"); do
  {
    echo "== $d"
    grep -n 'audit_log' "$d/config.yaml"
    ls -la "$d"
    echo "audit.jsonl bytes: $(stat -f '%z' "$d/audit.jsonl")"
    echo "scan.cancel lines: $(grep -c 'scan.cancel' "$d/audit.jsonl")"
  } >> "$EV/run-dirs.txt"
done
rm -f "$EV/.marker"
