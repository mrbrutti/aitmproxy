# Shell contract helpers for non-Python e2e suites (source this).
#   source "$(dirname "$0")/../lib/contract.sh"
# A suite signals its result by EXIT CODE: 0 = PASS, 77 = SKIP, else = FAIL.
# Use these so shell/cargo/codesign checks obey the same contract as Python ones.

E2E_SKIP_EXIT=77

e2e_pass() { echo "  [ok] ${1:-pass}"; exit 0; }
e2e_skip() { echo "  [SKIP] ${1:-skipped}"; exit "$E2E_SKIP_EXIT"; }
e2e_fail() { echo "  [FAIL] ${1:-failed}"; exit 1; }

# e2e_check <cond-exit-status> <message>: pass-through helper for inline asserts.
#   some_command; e2e_check $? "some_command succeeded"
e2e_check() {
    if [ "$1" -eq 0 ]; then
        echo "  [ok] $2"
    else
        echo "  [FAIL] $2"
        exit 1
    fi
}

# e2e_pause <instruction>: a manual step. SKIPs the whole suite unless the runner
# was invoked with --manual (AITM_E2E_MANUAL=1); otherwise waits for the operator.
e2e_pause() {
    if [ "${AITM_E2E_MANUAL:-}" != "1" ]; then
        e2e_skip "manual step requires --manual: $1"
    fi
    echo ">>> MANUAL: $1"
    echo ">>> press Enter when done ..."
    read -r _
}
