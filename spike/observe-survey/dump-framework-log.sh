#!/bin/bash
# Dump the NE framework's per-flow lines for the provider process over the last N hours.
hours=${1:-24}
out=/tmp/claude/ne-survey/framework-${hours}h.log
log show --last "${hours}h" --style compact --predicate 'process == "AitmproxyNE"' 2>&1 | grep -E 'New flow: NEFlow|Calling handleNew|provider rejected|startProxy|stopProxy|attached to core|detached from core|scope updated' > "$out"
wc -l "$out"
echo "first: $(head -1 "$out" | cut -c1-23)  last: $(tail -1 "$out" | cut -c1-23)"
echo "DUMP DONE"
