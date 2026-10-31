#!/bin/bash
# Pull the variant's SURVEY lines (and the framework per-flow lines) for the last N minutes.
# usage: survey-pull.sh <minutes> [tag]
mins=${1:-60}; tag=${2:-$(date +%H%M)}
D=/tmp/claude/ne-survey
log show --last "${mins}m" --style compact --predicate 'subsystem == "com.mrbrutti.aitmproxy.ne"' 2>&1 | grep -E 'SURVEY|startProxy|stopProxy|attached to core|detached from core|scope updated' > "$D/survey-$tag.log"
log show --last "${mins}m" --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | grep -E 'New flow: NEFlow|Calling handleNew|provider rejected' > "$D/framework-$tag.log"
echo "survey lines: $(grep -c 'SURVEY k=' "$D/survey-$tag.log")  rate lines: $(grep -c 'SURVEY-RATE' "$D/survey-$tag.log")  framework new-flow lines: $(grep -c 'New flow' "$D/framework-$tag.log")"
echo "first: $(grep -m1 'SURVEY' "$D/survey-$tag.log" | cut -c1-23)  last: $(grep 'SURVEY' "$D/survey-$tag.log" | tail -1 | cut -c1-23)"
grep -m3 'SURVEY-START\|startProxy' "$D/survey-$tag.log" | cut -c1-200
echo "PULL DONE $tag"
