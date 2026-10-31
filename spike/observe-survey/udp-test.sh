#!/bin/bash
# Item 8: UDP under the active provider returning false for every UDP flow.
# usage: udp-test.sh <tag>      output /tmp/claude/ne-survey/udp-<tag>.out (+ dom/png files)
tag=${1:-run}
D=/tmp/claude/ne-survey
out=$D/udp-$tag.out
exec > >(tee "$out") 2>&1
to() { perl -e 'alarm shift; exec @ARGV' "$@"; }   # macOS has no coreutils timeout
echo "== $(date) tag=$tag =="
systemextensionsctl list 2>&1 | grep -E 'aitmproxy.ne.*activated'
echo "== DNS over UDP from user processes =="
for s in 1.1.1.1 8.8.8.8 ""; do dig ${s:+@$s} quic.nginx.org A +time=3 +tries=1 +noall +answer +stats 2>&1 | grep -E 'IN|Query time|SERVER|connection|timed out' | tr '\n' ' '; echo; done
echo "== system resolver =="; dscacheutil -q host -a name cloudflare-quic.com | head -2; python3 -I -c 'import socket; print("getaddrinfo", socket.getaddrinfo("quic.nginx.org",443,proto=6)[0][4])'
echo "== curl resolver loop: 30 connect-by-name HTTPS fetches (curl does its own UDP DNS) =="
fails=0; slow=0
for h in example.com example.org example.net cloudflare.com apple.com google.com github.com wikipedia.org mozilla.org debian.org python.org rust-lang.org kernel.org nginx.org letsencrypt.org ietf.org w3.org archive.org gnu.org opensource.org ubuntu.com fedoraproject.org gentoo.org freebsd.org openbsd.org netbsd.org haskell.org golang.org nodejs.org php.net; do
  r=$(curl -sS --max-time 6 -o /dev/null -w '%{http_code} %{time_namelookup}' "https://$h/" 2>&1 | tail -1)
  case "$r" in *"Could not resolve"*|*"timed out"*|*"000 "*) fails=$((fails+1)); echo "  FAIL $h: $r";; esac
  t=${r##* }; awk -v t="$t" 'BEGIN{exit !(t+0 > 2)}' && { slow=$((slow+1)); echo "  SLOW $h: namelookup ${t}s"; }
done
echo "-- curl loop: 30 names, failures=$fails, namelookup>2s=$slow"
echo "== NTP (sntp, UDP 123) =="; to 8 sntp -t 3 time.apple.com 2>&1 | tail -1
echo "== Chrome: QUIC forced (no TCP fallback), fresh profile =="
CH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
P=$D/chrome-prof-$tag; rm -rf "$P"
to 45 "$CH" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$P" --origin-to-force-quic-on=cloudflare-quic.com:443 --dump-dom https://cloudflare-quic.com/ > "$D/chrome-cfquic-forced-$tag.html" 2>"$D/chrome-cfquic-forced-$tag.err"
echo "-- exit=$? bytes=$(wc -c < "$D/chrome-cfquic-forced-$tag.html")"; python3 -I -c 'import re,sys; t=re.sub(r"<script.*?</script>|<style.*?</style>","",open(sys.argv[1]).read(),flags=re.S); t=re.sub(r"<[^>]+>"," ",t); t=re.sub(r"\s+"," ",t); print(t[:400])' "$D/chrome-cfquic-forced-$tag.html"
to 45 "$CH" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$P" --origin-to-force-quic-on=quic.nginx.org:443 --dump-dom https://quic.nginx.org/ > "$D/chrome-nginx-forced-$tag.html" 2>/dev/null
echo "-- exit=$? bytes=$(wc -c < "$D/chrome-nginx-forced-$tag.html")"; python3 -I -c 'import re,sys; t=re.sub(r"<script.*?</script>|<style.*?</style>","",open(sys.argv[1]).read(),flags=re.S); t=re.sub(r"<[^>]+>"," ",t); t=re.sub(r"\s+"," ",t); print(t[:300])' "$D/chrome-nginx-forced-$tag.html"
echo "== Chrome: netlog of a normal load pair (Alt-Svc discovery then h3) =="
NL=$D/chrome-netlog-$tag.json; rm -f "$NL"
to 45 "$CH" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$P" --dump-dom https://cloudflare-quic.com/ > "$D/chrome-cfquic-2nd-$tag.html" 2>/dev/null
echo "-- 2nd load exit=$?"; python3 -I -c 'import re,sys; t=re.sub(r"<script.*?</script>|<style.*?</style>","",open(sys.argv[1]).read(),flags=re.S); t=re.sub(r"<[^>]+>"," ",t); t=re.sub(r"\s+"," ",t); print(t[:300])' "$D/chrome-cfquic-2nd-$tag.html"
to 45 "$CH" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$P" --log-net-log="$NL" --net-log-capture-mode=Default --dump-dom https://cloudflare-quic.com/ > /dev/null 2>&1
echo "-- netlog exit=$? size=$(wc -c < "$NL" 2>/dev/null)"
python3 -I - "$NL" <<'PY'
import json,sys,re,collections
raw=open(sys.argv[1],errors="replace").read()
if not raw.rstrip().endswith("]}"): raw=raw.rstrip().rstrip(",")+"]}"
try: d=json.loads(raw)
except Exception as e: print("netlog parse failed:",e); sys.exit(0)
types={v:k for k,v in d["constants"]["logEventTypes"].items()}
c=collections.Counter(types.get(e["type"],e["type"]) for e in d["events"])
print("QUIC_SESSION events:",sum(n for t,n in c.items() if str(t).startswith("QUIC_SESSION")))
for t in ["QUIC_SESSION","QUIC_SESSION_CLOSE_ON_ERROR","QUIC_SESSION_CONNECTION_CLOSE_FRAME_RECEIVED","QUIC_SESSION_CLOSED","HTTP2_SESSION","HTTP_TRANSACTION_READ_RESPONSE_HEADERS","UDP_CONNECT","UDP_SOCKET_ERROR","SOCKET_ERROR"]:
    if c.get(t): print(f"  {t}: {c[t]}")
protos=collections.Counter()
for e in d["events"]:
    p=e.get("params",{})
    for k in ("next_proto","protocol","alpn","negotiated_protocol"):
        if k in p: protos[(k,p[k])]+=1
print("protocols seen:",dict(protos))
errs=[e["params"] for e in d["events"] if types.get(e["type"])in("QUIC_SESSION_CLOSE_ON_ERROR","UDP_SOCKET_ERROR","SOCKET_ERROR") and e.get("params")]
print("errors:",errs[:4])
PY
echo "== Firefox: two loads, persistent temp profile, screenshots =="
FF="/Applications/Firefox.app/Contents/MacOS/firefox"
FP=$D/ff-prof-$tag; rm -rf "$FP"; mkdir -p "$FP"
printf 'user_pref("network.http.http3.enable", true);\nuser_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\n' > "$FP/user.js"
to 60 "$FF" --headless --no-remote --profile "$FP" --window-size=1000,700 --screenshot "$D/ff-quic1-$tag.png" https://cloudflare-quic.com/ 2>&1 | tail -1
to 60 "$FF" --headless --no-remote --profile "$FP" --window-size=1000,700 --screenshot "$D/ff-quic2-$tag.png" https://cloudflare-quic.com/ 2>&1 | tail -1
ls -la "$D"/ff-quic*-$tag.png 2>&1
echo "== UDP flows the provider saw in this run (framework log, last 5 min) =="
log show --last 5m --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | grep 'New flow: NEFlow type = datagram' | sed -E 's/.*app = ([^,]*), name = ([^,]*), [^ ]+ <-> ([^,]+).*/\1 -> \3/' | sort | uniq -c | sort -rn | head -14
echo "== UDP TEST DONE =="
