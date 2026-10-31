#!/bin/bash
# Why did curl fail to resolve while dig/dscacheutil worked? Read-only probes.
out=/tmp/claude/ne-survey/dns-curl-probe.out
exec > >(tee "$out") 2>&1
echo "== $(date) =="
echo "== which curl =="; which -a curl; curl --version | head -2
echo "== curl -v example.com (10s max) =="; curl -sv --max-time 10 -o /dev/null https://example.com/ 2>&1 | grep -E 'Could not|Trying|Connected|HTTP/|resolve|timed out|error' | head -8
echo "== curl by IP (bypass DNS) =="; curl -sS --max-time 10 -o /dev/null -w 'code %{http_code} %{time_total}s\n' --resolve example.com:443:104.20.23.154 https://example.com/ 2>&1
echo "== curl http://1.1.1.1/ =="; curl -sS --max-time 10 -o /dev/null -w 'code %{http_code} %{time_total}s\n' http://1.1.1.1/ 2>&1
echo "== getaddrinfo via python =="; time python3 -I -c 'import socket,time; print(socket.getaddrinfo("example.com",443,proto=socket.IPPROTO_TCP)[0][4])' 2>&1
echo "== host / dscacheutil =="; host -W 5 example.com 2>&1 | head -2; dscacheutil -q host -a name example.com 2>&1 | head -3
echo "== ping (resolver via mDNSResponder) =="; ping -c 1 -t 5 example.com 2>&1 | head -2
echo "== scutil --dns (resolvers) =="; scutil --dns 2>&1 | grep -E 'nameserver|resolver #|if_index|flags' | head -12
echo "== curl again =="; curl -sS --max-time 10 -o /dev/null -w 'code %{http_code} %{time_total}s\n' https://example.com/ 2>&1
echo "== provider flows for curl/mDNSResponder, last 20 min =="
log show --last 20m --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | grep 'New flow' | grep -E 'app = (com.apple.curl|curl|com.apple.mDNSResponder|com.apple.dig|com.apple.dscacheutil|com.apple.nslookup|com.apple.ping)' | sed -E 's/^[^ ]+ ([0-9:.]+) .*type = ([a-z]+), app = ([^,]*), name = ([^,]*), ([^ ]+) <-> ([^,]+).*/\1 \2 \3 name=\4 \6/' | tail -40
echo "== mDNSResponder log mentioning example.com, last 20 min =="
log show --last 20m --style compact --predicate 'process == "mDNSResponder"' 2>&1 | grep -i 'example' | sed -E 's/^[^ ]+ ([0-9:.]+) .*/\1 &/' | cut -c1-260 | tail -20
echo "== Little Snitch denies, last 20 min (if logged) =="
log show --last 20m --style compact --predicate 'subsystem BEGINSWITH "at.obdev"' 2>&1 | grep -i -E 'deny|denied|curl' | cut -c1-220 | tail -10
echo "== PROBE DONE =="
