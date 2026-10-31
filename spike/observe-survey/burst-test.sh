#!/bin/bash
# Controlled bursts for item 7: a heavy page load in headless Chrome (no GUI impact) and one in Safari.
D=/tmp/claude/ne-survey; exec > >(tee "$D/burst.out") 2>&1
to() { perl -e 'alarm shift; exec @ARGV' "$@"; }
window() { # $1 = app grep, $2 = start 'YYYY-MM-DD HH:MM:SS', $3 = seconds
  log show --start "$2" --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep 'New flow: NEFlow' | grep -E "$1" | awk '{print $2}' | cut -c1-8 | sort | uniq -c | sort -k2 | head -$3
}
CH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
for site in https://www.theverge.com/ https://www.cnn.com/ https://www.nytimes.com/; do
  P=$D/chrome-burst; rm -rf "$P"
  start=$(date '+%Y-%m-%d %H:%M:%S'); echo "== Chrome headless $site at $start =="
  to 40 "$CH" --headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$P" --dump-dom "$site" > /dev/null 2>&1
  sleep 12
  echo "-- Chrome.helper new flows per second (first 20 s):"; window 'com.google.Chrome' "$start" 20
  total=$(log show --start "$start" --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep 'New flow: NEFlow' | grep -c 'com.google.Chrome'); echo "-- total Chrome flows in window: $total"
done
start=$(date '+%Y-%m-%d %H:%M:%S'); echo "== Safari https://www.theverge.com/ at $start =="
open -a Safari https://www.theverge.com/; sleep 20
echo "-- Safari/WebKit new flows per second:"; window 'com.apple.Safari|WebKit|nsurlsessiond' "$start" 20
echo "-- all apps, flows per second in that window:"; log show --start "$start" --style compact --predicate 'process == "AitmproxyNE"' 2>/dev/null | grep 'New flow: NEFlow' | awk '{print $2}' | cut -c1-8 | sort | uniq -c | sort -rn | head -5
echo "-- provider SURVEY-RATE lines since the bursts:"; log show --start "$start" --style compact --predicate 'subsystem == "com.mrbrutti.aitmproxy.ne" AND category == "survey"' 2>/dev/null | grep 'SURVEY-RATE' | tail -2 | cut -c1-260
echo "BURST DONE $(date)"
