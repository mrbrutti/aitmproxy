#!/bin/bash
# Item 8 baseline: UDP under the ACTIVE provider that returns false for every flow.
# Runs in Matt's shell (outside the sandbox). Writes /tmp/claude/ne-survey/udp-<tag>.out
tag=${1:-baseline}
out=/tmp/claude/ne-survey/udp-$tag.out
exec > >(tee "$out") 2>&1
echo "== $(date) tag=$tag =="
echo "== sysex state =="; systemextensionsctl list 2>&1 | grep -E 'aitmproxy|littlesnitch'
echo "== rendezvous present? =="; ls -la /private/tmp/aitmproxy-capture.rendezvous 2>&1
echo "== DNS: dig UDP to 1.1.1.1 =="; time dig @1.1.1.1 example.com A +time=3 +tries=1 +noall +answer +stats 2>&1 | grep -E 'IN|Query time|SERVER|connection|timed out'
echo "== DNS: dig UDP to 8.8.8.8 =="; dig @8.8.8.8 cloudflare-quic.com A +time=3 +tries=1 +noall +answer +stats 2>&1 | grep -E 'IN|Query time|connection|timed out'
echo "== DNS: dig TCP control =="; dig @1.1.1.1 example.com A +tcp +time=3 +tries=1 +noall +answer +stats 2>&1 | grep -E 'IN|Query time|connection|timed out'
echo "== DNS: system resolver (mDNSResponder) =="; dscacheutil -q host -a name www.apple.com 2>&1 | head -3; time nslookup quic.nginx.org 2>&1 | grep -E 'Address|timed out|SERVFAIL' | head -3
echo "== DNS: dig to the LAN resolver =="; dig example.org A +time=3 +tries=1 +noall +answer +stats 2>&1 | grep -E 'IN|Query time|SERVER|connection|timed out'
echo "== curl TCP sanity =="; curl -sS -o /dev/null -w 'h1 %{http_version} code %{http_code} %{time_total}s\n' https://example.com/ 2>&1
CH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
P=/tmp/claude/ne-survey/chrome-prof-$tag; rm -rf "$P"
echo "== Chrome headless, QUIC forced on cloudflare-quic.com (no TCP fallback) =="
timeout 40 "$CH" --headless=new --disable-gpu --no-first-run --user-data-dir="$P" --origin-to-force-quic-on=cloudflare-quic.com:443 --dump-dom https://cloudflare-quic.com/ 2>/dev/null | tr -d '\n' | grep -o -i -E 'congratulations[^<]{0,80}|not using HTTP/3[^<]{0,40}|HTTP/3[^<]{0,30}|ERR_[A-Z_]+' | head -5
echo "-- exit=$?"
echo "== Chrome headless, QUIC forced on quic.nginx.org =="
timeout 40 "$CH" --headless=new --disable-gpu --no-first-run --user-data-dir="$P" --origin-to-force-quic-on=quic.nginx.org:443 --dump-dom https://quic.nginx.org/ 2>/dev/null | tr -d '\n' | grep -o -i -E 'QUIC is [a-z]+|HTTP/3[^<]{0,30}|ERR_[A-Z_]+|nginx[^<]{0,20}' | head -5
echo "-- exit=$?"
echo "== Chrome headless, normal (Alt-Svc) second load of cloudflare-quic.com =="
timeout 40 "$CH" --headless=new --disable-gpu --no-first-run --user-data-dir="$P" --dump-dom https://cloudflare-quic.com/ 2>/dev/null | tr -d '\n' | grep -o -i -E 'congratulations[^<]{0,80}|not using HTTP/3[^<]{0,40}|ERR_[A-Z_]+' | head -3
echo "-- exit=$?"
echo "== Chrome netlog: protocol used for cloudflare-quic.com =="
NL=/tmp/claude/ne-survey/chrome-netlog-$tag.json; rm -f "$NL"
timeout 40 "$CH" --headless=new --disable-gpu --no-first-run --user-data-dir="$P" --log-net-log="$NL" --net-log-capture-mode=Default https://cloudflare-quic.com/ >/dev/null 2>&1
grep -o '"next_proto":"[a-z0-9/.-]*"\|"protocol":"[a-z0-9/.-]*"\|"alpn":"[a-z0-9/.-]*"' "$NL" 2>/dev/null | sort | uniq -c | sort -rn | head -8
grep -c 'QUIC_SESSION' "$NL" 2>/dev/null | sed 's/^/QUIC_SESSION events: /'
grep -o 'QUIC_SESSION_CLOSE_ON_ERROR[^}]*' "$NL" 2>/dev/null | head -3
FF="/Applications/Firefox.app/Contents/MacOS/firefox"
FP=/tmp/claude/ne-survey/ff-prof-$tag; rm -rf "$FP"; mkdir -p "$FP"
echo "== Firefox headless screenshot of cloudflare-quic.com (two loads, persistent temp profile) =="
timeout 60 "$FF" --headless --no-remote --profile "$FP" --screenshot /tmp/claude/ne-survey/ff-quic1-$tag.png https://cloudflare-quic.com/ 2>&1 | tail -2
timeout 60 "$FF" --headless --no-remote --profile "$FP" --screenshot /tmp/claude/ne-survey/ff-quic2-$tag.png https://cloudflare-quic.com/ 2>&1 | tail -2
ls -la /tmp/claude/ne-survey/ff-quic*-$tag.png 2>&1
echo "== UDP datagram flows the provider saw during this run (framework log, last 4 min) =="
log show --last 4m --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | grep 'Calling handleNewUDPFlow\|type = datagram' | sed -E 's/.*(app = [^,]*|UDP [^[]*).*(remote: [^ ]*|<-> [^,]*).*/\1 \2/' | sort | uniq -c | sort -rn | head -15
echo "== UDP BASELINE DONE =="
