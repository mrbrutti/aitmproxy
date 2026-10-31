#!/bin/bash
log show --start '2026-10-31 13:34:40' --end '2026-10-31 13:35:30' --style compact --predicate 'process == "sysextd"' 2>&1 | grep -v -E 'nonRemovable|returning cdhash|xpc:connection|activating connection|invalidated' | cut -c1-260 | head -60
echo "SYSEXTD2 DONE"
