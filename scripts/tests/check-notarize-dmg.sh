#!/usr/bin/env bash
# Structural tripwire for scripts/notarize-dmg.sh — Part 1 of the spec
# docs/superpowers/specs/2026-10-30-macos-ne-ship-and-toggle-design.md (SH-AC1..SH-AC8).
#
# bash + grep only. It never signs, notarizes, or touches a keychain, so it runs
# anywhere (including the sandbox). It cannot prove the signatures are real — that
# is the manual Terminal-panel run — but it pins what a regression would have to
# undo: the sign recipe, its inside-out order, the fail-closed verify block that
# runs before notarytool, the non-NE path, and that nothing masks codesign's exit
# status (a `codesign … | grep … || true` would turn a failed restricted-entitlement
# sign into a "successful" release). The stage-6 review fixes are pinned too: both bundles
# are asserted to carry the team the entitlement files hard-code (#8), `--entitlements -`
# replaces the deprecated `:-` (#8), and the nested-code `find` status is checked (#10).
#
# Usage: scripts/tests/check-notarize-dmg.sh      exit 0 = recipe intact, 1 = drift
#
# The patterns below are regular expressions that deliberately contain literal
# `$name` text, so they are single-quoted on purpose.
# shellcheck disable=SC2016
set -u

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
# NOTARIZE_DMG_SCRIPT lets the tripwire be pointed at a mutated copy (to prove it bites).
script=${NOTARIZE_DMG_SCRIPT:-$repo_root/scripts/notarize-dmg.sh}
if [ ! -f "$script" ]; then
    echo "check-notarize-dmg.sh: missing $script" >&2
    exit 1
fi

failures=0
pass() { echo "ok:   $1"; }
fail() {
    echo "FAIL: $1"
    failures=$((failures + 1))
}

# The script with comment-only lines blanked (line numbers preserved), so a
# comment that merely mentions "codesign" or "notarytool submit" cannot satisfy or
# trip an assertion.
code=$(sed -e 's/^[[:space:]]*#.*$//' "$script")

# first_line <ERE>: line number of the first match, empty if none.
first_line() { grep -n -E -- "$1" <<<"$code" | head -n 1 | cut -d: -f1; }
# count_lines <ERE>: number of matching lines.
count_lines() { grep -c -E -- "$1" <<<"$code"; }
# line_text <line number>: that line of the comment-blanked script (empty if no number).
line_text() {
    if [ -n "$1" ]; then sed -n "${1}p" <<<"$code"; fi
}

present() { # present <label> <line-number-or-empty>
    if [ -n "$2" ]; then pass "$1"; else fail "$1 (not found)"; fi
}
before() { # before <label> <line A> <line B>: both exist and A comes first
    if [ -n "$2" ] && [ -n "$3" ] && [ "$2" -lt "$3" ]; then
        pass "$1 (line $2 before line $3)"
    else
        fail "$1 (line '${2:-missing}' must come before line '${3:-missing}')"
    fi
}
has_fixed() { # has_fixed <label> <haystack> <literal>
    if grep -q -F -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (missing: $3)"; fi
}
equals() { # equals <label> <actual> <expected>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected $3, got '$2')"; fi
}

# --- SH-AC8: the script stays valid ------------------------------------------
if bash -n "$script"; then pass "SH-AC8 bash -n notarize-dmg.sh"; else fail "SH-AC8 bash -n notarize-dmg.sh"; fi
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck "$script"; then
        pass "SH-AC8 shellcheck notarize-dmg.sh"
    else
        fail "SH-AC8 shellcheck notarize-dmg.sh"
    fi
else
    fail "SH-AC8 shellcheck is not installed (it is part of the contract)"
fi

# --- cs(): abort on a real codesign failure, never masked ---------------------
present "cs() helper is defined" "$(first_line '^cs\(\)[[:space:]]*\{')"
cs_body=$(awk '/^cs\(\)[[:space:]]*\{/ {f=1} f {print} f && /^\}/ {exit}' <<<"$code")
has_fixed "cs() runs codesign with its own arguments" "$cs_body" 'codesign "$@"'
has_fixed "cs() aborts the script on failure" "$cs_body" 'exit 1'
has_fixed "cs() hides only the benign 'replacing existing signature' line" "$cs_body" 'replacing existing signature'
# The capture must be checked bare: `$(codesign "$@" 2>&1 || true)` would hand `if !` a success
# whatever codesign did, and a failed restricted-entitlement sign would reach notarytool.
has_fixed "cs() tests codesign's own exit status (nothing masks it inside the capture)" \
    "$cs_body" 'if ! out=$(codesign "$@" 2>&1); then'
equals "set -euo pipefail is in force" "$(count_lines '^set -euo pipefail$')" "1"
present "runtime_opts = hardened runtime + secure timestamp" \
    "$(first_line '^runtime_opts=\(--options runtime --timestamp\)$')"

# Every --sign call except the DMG's own goes through cs.
bare_sign=$(grep -n -E -- '--sign' <<<"$code" | grep -v -E '^[0-9]+:[[:space:]]*cs ' | grep -v -E '"\$dmg"')
equals "no bare codesign --sign outside cs() (except the DMG)" "$bare_sign" ""
# Nothing pipes codesign into something that would replace its exit status ...
piped=$(grep -n -E 'codesign[^|]*\|([^|]|$)' <<<"$code")
equals "codesign is never piped" "$piped" ""
# ... or swallows it with `|| true` / `|| :` (also inside a larger expression: `... || true)`).
swallowed=$(grep -n -E 'codesign.*\|\|[[:space:]]*(true|:)([^[:alnum:]_]|$)' <<<"$code")
equals "codesign is never followed by || true" "$swallowed" ""
# The helpers abort with `exit`, which only ends the script when they run in it: not piped, not
# inside $(...), and not given an `|| true` that a refactor to `return` would turn into a pass.
helper_masked=$(grep -n -E '^[[:space:]]*(cs|assert_contains)[[:space:]].*\|\|[[:space:]]*(true|:)([^[:alnum:]_]|$)|^[[:space:]]*(cs|assert_contains)[[:space:]][^|]*[^|]\|[^|]|\$\((cs|assert_contains)[[:space:]]' <<<"$code")
equals "cs and assert_contains are never swallowed, piped or run in a subshell" "$helper_masked" ""
# A captured codesign (for the verify greps) must check codesign's own status.
unchecked=$(grep -n -E '\$\(codesign' <<<"$code" | grep -v -E '\|\||if !')
equals "every captured codesign checks its exit status" "$unchecked" ""

# --- SH-AC6: the NE work is guarded; the non-NE path stays reachable ----------
l_guard=$(first_line '^[[:space:]]*if \[ -n "\$sysex_bundle" \]; then')
present "SH-AC6 NE work is guarded by a sysex-presence test" "$l_guard"
l_detect=$(first_line 'SystemExtensions/\*\.systemextension')
present "SH-AC1 sysex is detected under Contents/Library/SystemExtensions" "$l_detect"
before "SH-AC6 detection precedes the guard" "$l_detect" "$l_guard"

# --- SH-AC1: sysex signed inside-out, before the app --------------------------
equals "profile presence is checked for the app and the sysex (not re-copied)" \
    "$(count_lines '^[[:space:]]*\[ -f "\$(app|sysex_bundle)/Contents/embedded\.provisionprofile" \] \|\|.*exit 1')" "2"
equals "provisioning profiles are never copied by this script" \
    "$(count_lines '^[[:space:]]*(cp|ditto|rsync|install|mv)[[:space:]].*provisionprofile')" "0"
l_nested_find=$(first_line 'find "\$sysex_bundle/Contents" -depth ')
present "SH-AC1 nested code under the sysex is found depth-first" "$l_nested_find"
l_nested=$(first_line '^[[:space:]]*cs .*"\$nested"[[:space:]]*$')
present "SH-AC1 nested code is signed through cs" "$l_nested"
l_sysex=$(first_line '^[[:space:]]*cs .*apps/mac/Extension/Aitmproxy-Extension\.entitlements.*"\$sysex_bundle"[[:space:]]*$')
present "SH-AC1 the .systemextension is signed with Aitmproxy-Extension.entitlements" "$l_sysex"
equals "the sysex is signed exactly once" \
    "$(count_lines '^[[:space:]]*cs .*"\$sysex_bundle"[[:space:]]*$')" "1"
has_fixed "the sysex sign uses hardened runtime + timestamp" \
    "$(line_text "$l_sysex")" '"${runtime_opts[@]}"'
has_fixed "the sysex sign uses the Developer ID identity" \
    "$(line_text "$l_sysex")" '--sign "$dev_id"'
l_obscura=$(first_line '^[[:space:]]*cs .*--entitlements "\$obscura_ent".*"\$core/obscura"[[:space:]]*$')
present "obscura keeps its JIT entitlements" "$l_obscura"
l_aitm=$(first_line '^[[:space:]]*cs .*"\$core/aitm"[[:space:]]*$')
present "aitm is signed through cs" "$l_aitm"
# (the find feeds the while loop, so it is textually the loop's last line)
before "SH-AC1 the nested-code pass precedes the sysex bundle sign" "$l_nested_find" "$l_sysex"
before "SH-AC1 nested code is signed before the sysex bundle" "$l_nested" "$l_sysex"

# --- SH-AC2: the app is signed WITH the NE entitlements, last -----------------
l_app_ne=$(first_line '^[[:space:]]*cs .*apps/mac/Aitmproxy\.entitlements.*"\$app"[[:space:]]*$')
present "SH-AC2 the app is signed with Aitmproxy.entitlements" "$l_app_ne"
has_fixed "the NE app sign uses hardened runtime + timestamp" \
    "$(line_text "$l_app_ne")" '"${runtime_opts[@]}"'
before "SH-AC1/SH-AC2 the sysex is signed before the app" "$l_sysex" "$l_app_ne"
before "the sysex is signed before obscura/aitm (inside-out order)" "$l_sysex" "$l_obscura"
before "obscura is signed before the app" "$l_obscura" "$l_app_ne"
before "aitm is signed before the app" "$l_aitm" "$l_app_ne"

# --- SH-AC6: non-NE build keeps the plain, entitlement-less app sign ----------
plain_app=$(grep -n -E '^[[:space:]]*cs .*"\$app"[[:space:]]*$' <<<"$code" | grep -v -- '--entitlements' | cut -d: -f1)
equals "SH-AC6 exactly one entitlement-less app sign (the non-NE branch)" "$(grep -c . <<<"$plain_app")" "1"
present "SH-AC6 the plain app sign exists" "$plain_app"
if [ -n "$l_app_ne" ] && [ -n "$plain_app" ] && [ "$l_app_ne" -lt "$plain_app" ] \
    && sed -n "${l_app_ne},${plain_app}p" <<<"$code" | grep -q -E '^[[:space:]]*else[[:space:]]*$'; then
    pass "SH-AC6 the plain app sign sits in the else of the NE app sign"
else
    fail "SH-AC6 the plain app sign must sit in the else of the NE app sign"
fi

# --- SH-AC3/SH-AC4: verify-or-fail BEFORE the DMG and notarytool --------------
l_make_dmg=$(first_line 'scripts/make-dmg\.sh')
l_notary=$(first_line 'notarytool submit')
present "make-dmg.sh is still called" "$l_make_dmg"
present "notarytool submit is still called" "$l_notary"
present "assert_contains() is defined" "$(first_line '^assert_contains\(\)[[:space:]]*\{')"
assert_body=$(awk '/^assert_contains\(\)[[:space:]]*\{/ {f=1} f {print} f && /^\}/ {exit}' <<<"$code")
has_fixed "assert_contains() exits non-zero on a missing needle" "$assert_body" 'exit 1'

l_verify_deep=$(first_line '^[[:space:]]*codesign --verify --deep --strict --verbose=2 "\$app"[[:space:]]*$')
present "codesign --verify --deep --strict stays" "$l_verify_deep"
l_dv=$(first_line 'codesign -dv --verbose=4 "\$sysex_bundle"')
present "SH-AC3 codesign -dv --verbose=4 on the nested sysex" "$l_dv"
# The app's own signature is read too, so its TeamIdentifier can be asserted (review #8).
l_app_dv=$(first_line 'codesign -dv --verbose=4 "\$app"')
present "review #8 codesign -dv --verbose=4 on the app" "$l_app_dv"
# `--entitlements -` is the supported form; `:-` is deprecated and, on current macOS, reports an
# invalid entitlements blob instead of the dump the assertions grep (review #8).
l_app_ents=$(first_line 'codesign -d --entitlements - "\$app"')
present "SH-AC2/SH-AC4 entitlement dump of the app (--entitlements -)" "$l_app_ents"
l_sysex_ents=$(first_line 'codesign -d --entitlements - "\$sysex_bundle"')
present "SH-AC4 entitlement dump of the sysex (--entitlements -)" "$l_sysex_ents"
equals "the deprecated ':-' entitlements form is not used anywhere" "$(count_lines 'entitlements :-')" "0"
l_spctl=$(first_line 'spctl -a -t exec -vvv "\$app"')
present "SH-AC3 spctl -a -t exec -vvv on the app (advisory)" "$l_spctl"

l_as_dev_id=$(first_line '^[[:space:]]*assert_contains .*"\$sysex_sig" .*Authority=Developer ID Application')
present "SH-AC3 asserts the sysex is signed by a Developer ID identity" "$l_as_dev_id"
l_as_runtime=$(first_line '^[[:space:]]*assert_contains .*"\$sysex_sig" .*flags=.*runtime')
present "SH-AC3 asserts the sysex carries the hardened-runtime flag" "$l_as_runtime"
l_as_app_ne=$(first_line '^[[:space:]]*assert_contains .*"\$app_ents" .*app-proxy-provider-systemextension')
present "SH-AC2 asserts the app has app-proxy-provider-systemextension" "$l_as_app_ne"
l_as_app_inst=$(first_line '^[[:space:]]*assert_contains .*"\$app_ents" .*com.apple.developer.system-extension.install')
present "SH-AC2 asserts the app has system-extension.install" "$l_as_app_inst"
l_as_sysex_ne=$(first_line '^[[:space:]]*assert_contains .*"\$sysex_ents" .*app-proxy-provider-systemextension')
present "SH-AC4 asserts the sysex has app-proxy-provider-systemextension" "$l_as_sysex_ne"
# review #8: both bundles must carry the team the entitlement files hard-code. The pattern is
# anchored so a longer id that merely starts with it, or `not set`, cannot pass.
l_as_sysex_team=$(first_line '^[[:space:]]*assert_contains .*"\$sysex_sig" .*\^TeamIdentifier=995PCLM9KH\$')
present "review #8 asserts the sysex TeamIdentifier is 995PCLM9KH (anchored)" "$l_as_sysex_team"
l_as_app_team=$(first_line '^[[:space:]]*assert_contains .*"\$app_sig" .*\^TeamIdentifier=995PCLM9KH\$')
present "review #8 asserts the app TeamIdentifier is 995PCLM9KH (anchored)" "$l_as_app_team"

# All of the NE verification runs inside the guard, after the app is signed, and
# before both the DMG is built and notarytool is called.
before "verify starts after the NE app sign" "$l_app_ne" "$l_dv"
before "app signature inspection starts after the NE app sign" "$l_app_ne" "$l_app_dv"
verify_before_dmg_and_notary() { # <label> <line>
    before "SH-AC4 $1 runs before make-dmg.sh" "$2" "$l_make_dmg"
    before "SH-AC4 $1 runs before notarytool submit" "$2" "$l_notary"
}
verify_before_dmg_and_notary "codesign --verify --deep --strict" "$l_verify_deep"
verify_before_dmg_and_notary "sysex codesign -dv" "$l_dv"
verify_before_dmg_and_notary "app entitlement dump" "$l_app_ents"
verify_before_dmg_and_notary "sysex entitlement dump" "$l_sysex_ents"
verify_before_dmg_and_notary "spctl pre-check" "$l_spctl"
verify_before_dmg_and_notary "Developer ID assertion" "$l_as_dev_id"
verify_before_dmg_and_notary "hardened-runtime assertion" "$l_as_runtime"
verify_before_dmg_and_notary "app NE-provider assertion" "$l_as_app_ne"
verify_before_dmg_and_notary "app system-extension.install assertion" "$l_as_app_inst"
verify_before_dmg_and_notary "sysex NE-provider assertion" "$l_as_sysex_ne"
verify_before_dmg_and_notary "app codesign -dv" "$l_app_dv"
verify_before_dmg_and_notary "sysex TeamIdentifier assertion" "$l_as_sysex_team"
verify_before_dmg_and_notary "app TeamIdentifier assertion" "$l_as_app_team"
before "SH-AC4 the verify guard follows the NE sign guard" "$l_guard" "$l_dv"

# Ordering alone does not prove containment. Every NE sign and verify line must sit inside an
# `if [ -n "$sysex_bundle" ]` block: a verify block that lost its guard fails every non-NE
# build (SH-AC6), and an NE sign outside it would sign a bundle that is not there. The nearest
# column-0 `if`/`fi` above the line must be the sysex-presence guard (nested `if`s are indented).
inside_guard() { # <label> <line>
    local opener
    if [ -z "$2" ]; then fail "$1 sits inside the sysex-presence guard (line not found)"; return; fi
    opener=$(awk -v n="$2" 'NR <= n && /^(if |fi$)/ { last = $0 } END { print last }' <<<"$code")
    equals "$1 sits inside the sysex-presence guard" "$opener" 'if [ -n "$sysex_bundle" ]; then'
}
inside_guard "SH-AC1 nested-code sign" "$l_nested"
inside_guard "SH-AC1 sysex bundle sign" "$l_sysex"
inside_guard "SH-AC2 NE app sign" "$l_app_ne"
inside_guard "SH-AC3 sysex codesign -dv" "$l_dv"
inside_guard "SH-AC2 app entitlement dump" "$l_app_ents"
inside_guard "SH-AC4 sysex entitlement dump" "$l_sysex_ents"
inside_guard "SH-AC3 spctl pre-check" "$l_spctl"
inside_guard "SH-AC3 Developer ID assertion" "$l_as_dev_id"
inside_guard "SH-AC3 hardened-runtime assertion" "$l_as_runtime"
inside_guard "SH-AC2 app NE-provider assertion" "$l_as_app_ne"
inside_guard "SH-AC2 app system-extension.install assertion" "$l_as_app_inst"
inside_guard "SH-AC4 sysex NE-provider assertion" "$l_as_sysex_ne"
inside_guard "review #8 app codesign -dv" "$l_app_dv"
inside_guard "review #8 sysex TeamIdentifier assertion" "$l_as_sysex_team"
inside_guard "review #8 app TeamIdentifier assertion" "$l_as_app_team"
inside_guard "review #10 nested-code find" "$l_nested_find"

# --- review #10: an errored find must abort the release -----------------------
# `while ... done < <(find ...)` discards find's exit status (a process substitution escapes
# set -e and pipefail), so a find that errored half way would leave nested code unsigned and
# the release would carry on. The list is written to a file first and find's status checked.
equals "no process substitution (< <(...)) feeds a loop" "$(count_lines '<[[:space:]]*<\(')" "0"
l_find_checked=$(first_line 'find "\$sysex_bundle/Contents" -depth .*-print0 >"\$nested_list" \|\| \{.*exit 1')
present "review #10 find writes its list to a file and aborts on a non-zero status" "$l_find_checked"
l_find_loop=$(first_line '^[[:space:]]*done <"\$nested_list"[[:space:]]*$')
present "review #10 the nested-sign loop reads the list file" "$l_find_loop"
before "review #10 find (and its status check) precede the nested sign loop" "$l_find_checked" "$l_nested"
before "review #10 the nested sign precedes the end of the loop that reads the list" "$l_nested" "$l_find_loop"
inside_guard "review #10 the nested-sign loop" "$l_find_loop"

# --- the entitlement files the script signs with ------------------------------
# A wrong path, or a file that no longer carries what the verify block demands, would only show
# up on Matt's Mac after the sign, as a failed release. Fail it here instead (SH-AC2/SH-AC4).
ent_paths=$(grep -o -E 'apps/mac/[A-Za-z/._-]*[.]entitlements' <<<"$code" | sort -u)
equals "the script signs with exactly three entitlement files (app, extension, obscura)" \
    "$(grep -c . <<<"$ent_paths")" "3"
while IFS= read -r ent_path; do
    [ -n "$ent_path" ] || continue
    if [ -f "$repo_root/$ent_path" ]; then pass "entitlement file exists: $ent_path"; else fail "entitlement file missing: $ent_path"; fi
done <<<"$ent_paths"
app_ents_text=$(cat "$repo_root/apps/mac/Aitmproxy.entitlements" 2>/dev/null)
sysex_ents_text=$(cat "$repo_root/apps/mac/Extension/Aitmproxy-Extension.entitlements" 2>/dev/null)
has_fixed "SH-AC2 Aitmproxy.entitlements carries app-proxy-provider-systemextension" \
    "$app_ents_text" 'app-proxy-provider-systemextension'
has_fixed "SH-AC2 Aitmproxy.entitlements carries com.apple.developer.system-extension.install" \
    "$app_ents_text" 'com.apple.developer.system-extension.install'
has_fixed "SH-AC4 Aitmproxy-Extension.entitlements carries app-proxy-provider-systemextension" \
    "$sysex_ents_text" 'app-proxy-provider-systemextension'

# review #8: the team the verify block demands is the team the entitlement files hard-code. If
# the team ever changes in one place and not the other, fail here, not on Matt's Mac after a
# full sign. ent_team prints the <string> after the com.apple.developer.team-identifier key.
ent_team() { # <file>
    awk '/<key>com\.apple\.developer\.team-identifier<\/key>/ { f = 1; next }
         f && /<string>/ { gsub(/.*<string>|<\/string>.*/, ""); print; exit }' "$1"
}
script_team=$(grep -o -E 'TeamIdentifier=[A-Z0-9]+' <<<"$code" | sort -u | sed 's/^TeamIdentifier=//')
equals "the script asserts exactly one team id" "$(grep -c . <<<"$script_team")" "1"
equals "review #8 the asserted team is the app entitlements' team" \
    "$(ent_team "$repo_root/apps/mac/Aitmproxy.entitlements")" "$script_team"
equals "review #8 the asserted team is the extension entitlements' team" \
    "$(ent_team "$repo_root/apps/mac/Extension/Aitmproxy-Extension.entitlements")" "$script_team"

# --- SH-AC7: the header documents the credentialed manual step ----------------
header=$(sed -n '1,/^set -euo pipefail/p' "$script")
has_fixed "SH-AC7 header names the ASC key id" "$header" 'G638JVUND7'
has_fixed "SH-AC7 header names the team id" "$header" '995PCLM9KH'
has_fixed "SH-AC7 header gives the NE release APP location" "$header" 'APP=/Applications/Aitmproxy.app'
has_fixed "SH-AC7 header says it runs in the Terminal panel" "$header" 'Terminal panel'
if grep -q -i -F 'no secret' <<<"$header"; then
    pass "SH-AC7 header says no secret is automated"
else
    fail "SH-AC7 header must say no secret is stored or automated"
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "check-notarize-dmg.sh: PASS"
    exit 0
fi
echo "check-notarize-dmg.sh: $failures check(s) FAILED" >&2
exit 1
