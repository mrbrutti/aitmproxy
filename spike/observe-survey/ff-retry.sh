#!/bin/bash
# Firefox headless HTTP/3 check with a longer alarm; two loads on one temp profile.
tag=${1:-run}; D=/tmp/claude/ne-survey
to() { perl -e 'alarm shift; exec @ARGV' "$@"; }
FF="/Applications/Firefox.app/Contents/MacOS/firefox"
FP=$D/ff-prof-$tag; rm -rf "$FP"; mkdir -p "$FP"
printf 'user_pref("network.http.http3.enable", true);\nuser_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\nuser_pref("toolkit.telemetry.enabled", false);\n' > "$FP/user.js"
for i in 1 2 3; do
  echo "-- load $i $(date +%T)"; time to 150 env MOZ_HEADLESS=1 "$FF" --headless --no-remote --profile "$FP" --screenshot "$D/ff-quic$i-$tag.png" https://cloudflare-quic.com/ 2>&1 | grep -v -i 'console\|JavaScript\|^$' | tail -2
done
ls -la "$D"/ff-quic*-$tag.png 2>&1
echo "FF DONE"
