#!/usr/bin/env bash
# Structural tripwire for the macOS app's live L4 path (spec
# docs/superpowers/specs/2026-10-31-l4-parity-fixes-design.md, L4PAR-AC25; plan
# docs/superpowers/plans/2026-10-31-l4-parity-fixes-plan.md, unit (d) task M4b and the
# tasks that append to it).
#
# Why this exists: the L4 rows the flow list shows come from `l4.flow.list` + `l4.flow.get`
# polled in `BusService.pollLoop`, which lives in the app target (no unit-test target). Before
# the l4-parity fixes the app only ever showed L4 flows from a fixture mode selected by the
# `APP_L4_EMBEDDED` switch, so a live core never produced an L4 row. This script reads Swift
# source only: it cannot prove the rows appear (the live check against the rig does that),
# but it pins what a regression would have to undo and fails closed when the code it reads
# moves. Later tasks add checks here (`inspector-parked-id`, `verbs-gated`, `scope-add-gated`).
#
# Usage: tools/check-l4-live.sh
#   MAC_ROOT=<dir>   the apps/mac tree to check (default: the apps/mac that holds this script),
#                    so it can be pointed at an exported origin/main tree as the red run.
# Exit 0 and exactly "check-l4-live: ok" when every check holds; otherwise one
# "check-l4-live: FAIL <check>: <file>" line per broken check and exit 1.
#
# Exceptions (plan unit (d) amendment 5): `APP_L4_EMBEDDED` is listed in
# Sources/AitmproxyKit/RemovedModes.swift (and its test) as a removed switch a launch must
# refuse, so that file and this script are the only places the token may appear. The grep
# covers Sources and tools; Tests/ is not in its scope.
# When a check says a file was not found, the code was renamed or moved: re-read it and
# update this script in the same commit. Do not delete the check.
set -u
set -o pipefail
export LC_ALL=C

self_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=${MAC_ROOT:-$(cd "$self_dir/.." && pwd)}
cd "$root" || { echo "check-l4-live: FAIL root: $root"; exit 1; }
[ -d Sources ] || { echo "check-l4-live: FAIL root: $root/Sources"; exit 1; }

failures=0
fail() {
    echo "check-l4-live: FAIL $1: $2"
    failures=$((failures + 1))
}

# live-path: BusService polls both L4 verbs (the list, then the per-flow fields).
check_live_path() {
    local f=Sources/Aitmproxy/Bus/BusService.swift
    [ -f "$f" ] || { fail live-path "$f"; return; }
    if ! grep -q 'l4\.flow\.list' "$f" || ! grep -q 'l4\.flow\.get' "$f"; then
        fail live-path "$f"
    fi
}

# no-embedded-switch: the fixture-era switch appears nowhere but the removed-modes refusal list.
check_no_embedded_switch() {
    local hits
    hits=$(grep -rl 'APP_L4_EMBEDDED' Sources tools 2>/dev/null \
        | grep -v -e '^Sources/AitmproxyKit/RemovedModes\.swift$' -e '^tools/check-l4-live\.sh$')
    local h
    for h in $hits; do
        fail no-embedded-switch "$h"
    done
}

# verbs-gated: Session's verb items pass through the L4 gate (AC29, task M6), so an L4 row
# offers no HTTP verb from the context menu, the Flow menu, the keyboard or the palette.
check_verbs_gated() {
    local f=Sources/Aitmproxy/Session+Verbs.swift
    [ -f "$f" ] || { fail verbs-gated "$f"; return; }
    grep -q 'L4RowVerbs\.gate' "$f" || fail verbs-gated "$f"
}

# scope-add-gated: the Scope page's operator scope-add form renders only when `tools/list`
# shows `l4.scope.add` confirmable (spec §3 last rule, AC30, task M7) AND the bus session
# resolved as the operator (plan amendment 7: `tools/list` says confirmable to an agent too,
# and an agent's add can only be refused, AC33). Any mention of the add verb in
# ScopePanel.swift must sit beside the `l4CanAddScope` gate, the role read `session.isOperator`
# (fix A2: `Session.isOperator` wraps the `resolvedRole` the server echoed; the word
# `resolvedRole` itself now appears here only in a doc comment, so it is not what we pin), AND
# the gate expression itself, `if l4IsOperator` (tester finding F1: a role read that is merely
# defined, while the form renders unconditionally, must not pass). The page offers no remove
# action at all (Decision 6).
check_scope_add_gated() {
    local f=Sources/Aitmproxy/Panels/ScopePanel.swift
    [ -f "$f" ] || { fail scope-add-gated "$f"; return; }
    if grep -q 'l4\.scope\.add' "$f" \
        && { ! grep -q 'l4CanAddScope' "$f" || ! grep -q 'session\.isOperator' "$f" || ! grep -q 'if l4IsOperator' "$f"; }; then
        fail scope-add-gated "$f"
        return
    fi
    grep -q 'l4\.scope\.remove' "$f" && fail scope-add-gated "$f"
}

# inspector-parked-id: the L4 inspector starts the craft editor from Kit's accepted sample (AC27,
# task M5; the old `sampleSpec` with `sport`/`dport` is gone) and its Forward/Drop verdicts send the
# parked id through `L4Verdict.args` (AC28), never the flow id.
check_inspector_parked_id() {
    local f=Sources/Aitmproxy/Inspector/L4Inspector.swift
    [ -f "$f" ] || { fail inspector-parked-id "$f"; return; }
    if grep -q 'sampleSpec' "$f" || ! grep -q 'L4Verdict\.args' "$f"; then
        fail inspector-parked-id "$f"
    fi
}

checks="live_path no_embedded_switch verbs_gated scope_add_gated inspector_parked_id"
for c in $checks; do
    "check_$c"
done

if [ "$failures" -eq 0 ]; then
    echo "check-l4-live: ok"
    exit 0
fi
exit 1
