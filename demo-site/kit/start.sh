#!/bin/zsh
# Bring up the recording scenario: benign sample site + aitmproxy (proxy + web UI + bus).
# Run from anywhere. Ctrl-C does NOT stop the servers; run stop.sh to tear down.
set -e
ROOT=/Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf
KIT=$ROOT/demo-site/kit
AITM=$ROOT/target/release/aitm
WWW=$ROOT/demo-site/www
LOG=$KIT/logs
mkdir -p $LOG

echo "[kit] stopping any previous kit instances…"
pkill -f 'http.server 19000' 2>/dev/null || true
pkill -f 'release/aitm --config .*kit-config.yaml' 2>/dev/null || true
sleep 1

echo "[kit] starting benign sample site on http://127.0.0.1:19000 …"
(python3 -m http.server 19000 --bind 127.0.0.1 --directory "$WWW" >"$LOG/site.log" 2>&1 &)

echo "[kit] starting aitmproxy (proxy 127.0.0.1:18080, web UI 127.0.0.1:18082) …"
(AITM_WEB_TOKEN=aitmdemo-web "$AITM" --config "$KIT/kit-config.yaml" web --listen 127.0.0.1:18082 --no-open >"$LOG/aitm.log" 2>&1 &)

echo "[kit] waiting for startup…"
for i in $(seq 1 20); do
  if grep -q "web UI listening" "$LOG/aitm.log" 2>/dev/null; then break; fi
  sleep 1
done

echo ""
echo "=================== aitmproxy recording kit is UP ==================="
echo "Sample site (benign):   http://127.0.0.1:19000"
echo "Proxy (point here):     127.0.0.1:18080"
echo ""
echo "WEB UI — open in a browser (operator, full powers):"
grep "web UI (operator)" "$LOG/aitm.log" | tail -1 | sed 's/.*web UI/   web UI/'
grep "web UI (agent)"    "$LOG/aitm.log" | tail -1 | sed 's/.*web UI/   web UI/'
echo ""
echo "TUI — run in a terminal you want to film:"
echo "   $ROOT/target/release/aitm-tui --bus 127.0.0.1:18090 --token aitmdemo-operator --expect-role operator --poll 100"
echo ""
echo "TRAFFIC — in another terminal, start the live stream:"
echo "   zsh $KIT/traffic.sh"
echo ""
echo "STOP everything when done:"
echo "   zsh $KIT/stop.sh"
echo "===================================================================="
