#!/bin/bash
# Web live proof (plan Task 3.11, AC58/AC59): final UI + release core from the web branch tip, scan-live.mjs with the
# Jobs-view steps; evidence copied into the branch's docs/design/evidence/jobs-view-2026-11-02/web/.
set -u
WT=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/scan-jobs-view-web
EV=$WT/docs/design/evidence/jobs-view-2026-11-02/web
REAL="$HOME/Library/Application Support/aitmproxy"
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
snap() { for f in audit.jsonl audit.agent.jsonl ca-audit.jsonl; do [ -e "$REAL/$f" ] && echo "$f $(stat -f '%z %m' "$REAL/$f") $(shasum -a 256 "$REAL/$f" | cut -d' ' -f1)" || echo "$f absent"; done; }
cd "$WT" || exit 90
log "== web proof on $(git log --oneline -1)"
[ -z "${AITM_AUDIT_LOG+x}" ] || { echo "AITM_AUDIT_LOG is set; unset it"; exit 91; }
mkdir -p "$EV"
(cd apps/web && npm run build > /tmp/claude/web-proof-ui.log 2>&1); log "ui build exit $?"
cargo build --release -p aitm -p aitm-testtarget > /tmp/claude/web-proof-core.log 2>&1; log "core build exit $?"
snap > "$EV/real-before.txt"
cd apps/web
rm -rf .cua-shots/scan
AITM_BIN=$WT/target/release/aitm AITM_TESTTARGET_BIN=$WT/target/release/aitm-testtarget-serve node scripts/scan-live.mjs > /tmp/claude/web-proof-run.log 2>&1
rc=$?; log "scan-live exit $rc"
snap > "$EV/real-after.txt"
diff "$EV/real-before.txt" "$EV/real-after.txt" > "$EV/real-audit-diff.txt" && echo "REAL FILES UNCHANGED" >> "$EV/real-audit-diff.txt" || echo "REAL FILES CHANGED" >> "$EV/real-audit-diff.txt"
cp .cua-shots/scan/09-*.png .cua-shots/scan/10-*.png .cua-shots/scan/11-*.png "$EV/" 2>/dev/null
cp .cua-shots/scan/status-*.json .cua-shots/scan/audit-before-after.txt .cua-shots/scan/config-audit-lines.txt "$EV/" 2>/dev/null
grep -vE 'opsecret-|#t=|token' /tmp/claude/web-proof-run.log | sed -E 's#/var/folders/[^ ]*aitm-live-[A-Za-z0-9]+#<run dir>#g' > "$EV/scan-live.log"
cp "$0" "$EV/proof.sh"
log "== done; evidence $EV"
echo "WEB-PROOF-DONE rc=$rc"
