#!/bin/bash
# Control run: turn Capture OFF through the app's own Proxy menu (operator path), repeat the
# IP_DONTFRAG and Chrome forced-QUIC tests with no transparent proxy active, then turn it back ON.
D=/tmp/claude/ne-survey; out=$D/capture-control.out
exec > >(tee "$out") 2>&1
to() { perl -e 'alarm shift; exec @ARGV' "$@"; }
se() { osascript -e "tell application \"System Events\" to tell process \"Aitmproxy\" to $1" 2>&1; }
flows_last() { log show --last "$1" --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep -c 'New flow: NEFlow'; }
echo "== $(date) =="
echo "-- before: provider flows in last 30s: $(flows_last 30s)"
se 'set frontmost to true'; sleep 0.7
echo "-- clicking Proxy > Disable Capture"; se 'click menu item "Disable Capture" of menu "Proxy" of menu bar 1'
sleep 8
echo "-- provider log after disable:"; log show --last 30s --style compact --predicate 'subsystem == "com.mrbrutti.aitmproxy.ne" AND category == "provider"' 2>/dev/null | tail -3 | cut -c1-160
dig @1.1.1.1 example.net +short +time=2 +tries=1 >/dev/null; sleep 2
echo "-- provider flows in the 12 s after disable (expect 0): $(flows_last 12s)"
echo "== IP_DONTFRAG with capture OFF =="; python3 -I "$D/dontfrag-core.py"
echo "== Chrome forced QUIC with capture OFF =="
CH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; P=$D/chrome-prof-ctl; rm -rf "$P"
to 45 "$CH" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$P" --origin-to-force-quic-on=cloudflare-quic.com:443 --dump-dom https://cloudflare-quic.com/ > "$D/chrome-cfquic-forced-ctl.html" 2>"$D/chrome-cfquic-forced-ctl.err"
echo "-- exit=$? bytes=$(wc -c < "$D/chrome-cfquic-forced-ctl.html")"; grep -o 'Page load failed: [A-Za-z_:]*' "$D/chrome-cfquic-forced-ctl.err" | head -2
python3 -I -c 'import re,sys; t=re.sub(r"<script.*?</script>|<style.*?</style>","",open(sys.argv[1]).read(),flags=re.S); t=re.sub(r"<[^>]+>"," ",t); t=re.sub(r"\s+"," ",t); i=t.lower().find("your browser used"); print(t[i:i+120] if i>=0 else t[:200])' "$D/chrome-cfquic-forced-ctl.html"
to 45 "$CH" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$P" --origin-to-force-quic-on=quic.nginx.org:443 --dump-dom https://quic.nginx.org/ > "$D/chrome-nginx-forced-ctl.html" 2>"$D/chrome-nginx-forced-ctl.err"
echo "-- nginx exit=$? bytes=$(wc -c < "$D/chrome-nginx-forced-ctl.html")"; grep -o 'Page load failed: [A-Za-z_:]*' "$D/chrome-nginx-forced-ctl.err" | head -2
python3 -I -c 'import re,sys; t=re.sub(r"<script.*?</script>|<style.*?</style>","",open(sys.argv[1]).read(),flags=re.S); t=re.sub(r"<[^>]+>"," ",t); t=re.sub(r"\s+"," ",t); print(t[:200])' "$D/chrome-nginx-forced-ctl.html"
echo "== turning capture back ON =="
se 'set frontmost to true'; sleep 0.7
se 'click menu item "Enable Capture" of menu "Proxy" of menu bar 1'
sleep 10
dig @1.1.1.1 example.org +short +time=2 +tries=1 >/dev/null; sleep 3
echo "-- provider log after enable:"; log show --last 20s --style compact --predicate 'subsystem == "com.mrbrutti.aitmproxy.ne"' 2>/dev/null | grep -E 'startProxy|SURVEY-START|SURVEY k=' | tail -3 | cut -c1-200
echo "-- provider flows in last 15 s (expect >0): $(flows_last 15s)"
systemextensionsctl list 2>&1 | grep -E 'aitmproxy.ne.*activated'
echo "== IP_DONTFRAG with capture back ON (expect ECONNRESET again) =="; python3 -I "$D/dontfrag-core.py" | head -4
echo "CONTROL DONE $(date)"
