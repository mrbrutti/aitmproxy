#!/bin/bash
echo "== $(date) =="
systemextensionsctl list 2>&1 | grep -E 'aitmproxy'
pgrep -fl 'Aitmproxy$|AitmproxyNE|Resources/core/aitm ' 2>&1 | cut -c1-120
echo "-- app build: $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' /Applications/Aitmproxy.app/Contents/Info.plist 2>&1)"
echo "-- rendezvous: $(ls /private/tmp/aitmproxy-capture.rendezvous 2>&1)"
echo "-- last provider lines:"
log show --last 10m --style compact --predicate 'subsystem == "com.mrbrutti.aitmproxy.ne"' 2>&1 | grep -v 'SURVEY k=' | tail -6 | cut -c1-230
echo "-- SURVEY lines in last 10 min: $(log show --last 10m --style compact --predicate 'subsystem == "com.mrbrutti.aitmproxy.ne" AND category == "survey"' 2>&1 | grep -c 'SURVEY k=')"
log show --last 10m --style compact --predicate 'subsystem == "com.mrbrutti.aitmproxy.ne" AND category == "survey"' 2>&1 | grep 'SURVEY k=' | tail -3 | cut -c1-260
echo "-- sysextd decisions, last 10 min:"
log show --last 10m --style compact --predicate 'process == "sysextd"' 2>&1 | grep -i -E 'aitmproxy|replac|approv|activat|error' | tail -8 | cut -c1-220
echo "STATUS DONE"
