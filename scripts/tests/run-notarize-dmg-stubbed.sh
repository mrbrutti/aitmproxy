#!/usr/bin/env bash
# Behavioural test for scripts/notarize-dmg.sh — Part 1 of the spec
# docs/superpowers/specs/2026-10-30-macos-ne-ship-and-toggle-design.md
# (SH-AC1, SH-AC2, SH-AC4, SH-AC6 and the "silent codesign success" anti-goal), plus the
# stage-6 review fixes in docs/superpowers/plans/2026-10-30-macos-ne-ship-and-toggle-plan.md:
# #8 (the app and the sysex must both carry TeamIdentifier 995PCLM9KH; cases 3g-3j) and
# #10 (an errored find over the nested code aborts before anything is signed; case 4d), and
# the bundled detection catalogue guard (the 0.5.4 DMG shipped without core/share/aitm/scripts):
# an app whose catalogue is missing, empty, or carries a symlink is refused before anything is
# signed (cases 5f-5h), and an errored find over the catalogue says so instead of dying silently
# (case 4e).
#
# check-notarize-dmg.sh reads the script's text. This one RUNS it. It builds a scratch copy
# of the repo layout around the real notarize-dmg.sh, a fake Aitmproxy.app, and puts shims
# for codesign, spctl and xcrun first on PATH. The shims log every call and answer from
# environment switches, so each case can make a signature, an entitlement or a sign step go
# wrong and the test can check what the script did about it. make-dmg.sh is a stub that exits
# 42: reaching it means "verification passed and the DMG would be built next".
#
# It signs nothing, touches no keychain and no network, and runs anywhere (the sandbox
# included). What it cannot show is that real signatures are right: that is the manual
# Terminal-panel run in the plan.
#
# Usage: scripts/tests/run-notarize-dmg-stubbed.sh     exit 0 = every case behaved, 1 = a case did not
# NOTARIZE_DMG_SCRIPT=<path> runs the cases against another copy (to prove the test bites).
#
# The shim bodies are single-quoted heredocs and the fixtures hold literal $-text on
# purpose (SC2016). The assertion helpers are called through expect/expect_not, an
# indirection the linter cannot follow (SC2329).
# shellcheck disable=SC2016,SC2329
set -u

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
script=${NOTARIZE_DMG_SCRIPT:-$repo_root/scripts/notarize-dmg.sh}
[ -f "$script" ] || {
    echo "run-notarize-dmg-stubbed.sh: missing $script" >&2
    exit 1
}
for f in Aitmproxy.entitlements EmbeddedObscura.entitlements Extension/Aitmproxy-Extension.entitlements; do
    [ -f "$repo_root/apps/mac/$f" ] || {
        echo "run-notarize-dmg-stubbed.sh: missing apps/mac/$f" >&2
        exit 1
    }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/notarize-stub.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
stub=$work/stub
mkdir -p "$stub/bin"

failures=0
pass() { echo "ok:   $1"; }
fail() {
    echo "FAIL: $1"
    failures=$((failures + 1))
}

# ---- shims ------------------------------------------------------------------
cat >"$stub/bin/codesign" <<'EOF'
#!/usr/bin/env bash
# Logs the call, then answers like codesign would for the mode it was asked in.
echo "codesign $*" >>"$FAKE_LOG"
for last; do :; done
mode=sign
for a in "$@"; do
    case $a in
    --verify) mode=verify ;;
    -dv) mode=dv ;;
    -d) mode=d ;;
    esac
done
case $mode in
verify) exit 0 ;;
dv)
    [ -e "$last" ] || { echo "$last: No such file or directory" >&2; exit 1; }
    # The team each bundle is signed by; the real value is the one the entitlement files
    # hard-code. FAKE_SYSEX_TEAM / FAKE_APP_TEAM override it per bundle.
    case $last in
    *.systemextension) team=${FAKE_SYSEX_TEAM-995PCLM9KH} ;;
    *) team=${FAKE_APP_TEAM-995PCLM9KH} ;;
    esac
    echo "Executable=$last/Contents/MacOS/x" >&2
    echo "CodeDirectory v=20500 size=1 flags=${FAKE_FLAGS-0x10000(runtime)} hashes=1+1 location=embedded" >&2
    echo "Authority=${FAKE_AUTHORITY-Developer ID Application: Test (TEAM123456)}" >&2
    echo "TeamIdentifier=$team" >&2
    exit 0
    ;;
d)
    [ -e "$last" ] || { echo "$last: No such file or directory" >&2; exit 1; }
    case $last in
    *.systemextension) ents=${FAKE_SYSEX_ENTS-app-proxy-provider-systemextension} ;;
    *) ents=${FAKE_APP_ENTS-app-proxy-provider-systemextension com.apple.developer.system-extension.install} ;;
    esac
    echo "<?xml version=\"1.0\"?><plist><dict><key>ents</key><string>$ents</string></dict></plist>"
    exit 0
    ;;
sign)
    if [ -n "${FAKE_FAIL_SIGN-}" ] && [ "$last" = "$FAKE_FAIL_SIGN" ]; then
        echo "$last: errSecInternalComponent" >&2
        exit 1
    fi
    echo "$last: replacing existing signature" >&2
    exit 0
    ;;
esac
EOF
# Before notarization a Developer ID app is "Unnotarized": spctl rejects it. Advisory only.
cat >"$stub/bin/spctl" <<'EOF'
#!/usr/bin/env bash
echo "spctl $*" >>"$FAKE_LOG"
echo "rejected (the code is valid but does not seem to be an app)" >&2
exit 3
EOF
# notarytool / stapler must never be reached by a case that is meant to stop earlier.
cat >"$stub/bin/xcrun" <<'EOF'
#!/usr/bin/env bash
echo "xcrun $*" >>"$FAKE_LOG"
exit 99
EOF
# The real find, then (FAKE_FIND_FAIL=<path>, for a find rooted at or under that path) a non-zero
# status like find has after a read error. It still lists everything it could read, so a script
# that ignores the status carries on with a partial list and leaves the rest of the nested code
# unsigned. Scoped by root, like FAKE_FAIL_SIGN is by path: the script runs several finds (the
# catalogue count, then the nested code), and failing them all would stop it at the first one,
# whichever a case meant to test.
cat >"$stub/bin/find" <<'EOF'
#!/usr/bin/env bash
/usr/bin/find "$@"
rc=$?
if [ -n "${FAKE_FIND_FAIL-}" ]; then
    case $1 in
    "$FAKE_FIND_FAIL" | "$FAKE_FIND_FAIL"/*)
        echo "find: simulated read error while listing $1" >&2
        exit 1
        ;;
    esac
fi
exit $rc
EOF
chmod +x "$stub/bin/codesign" "$stub/bin/spctl" "$stub/bin/xcrun" "$stub/bin/find"

# ---- fixtures ---------------------------------------------------------------
sysex_name=com.mrbrutti.aitmproxy.ne.systemextension

# mk_case <name> <ne|plain>: a scratch repo around the script under test plus a fake app.
# Sets case_dir, app, catalogue, sysex, log.
mk_case() {
    case_dir=$work/$1
    mkdir -p "$case_dir/repo/scripts" "$case_dir/repo/apps/mac/Extension"
    cp "$script" "$case_dir/repo/scripts/notarize-dmg.sh"
    printf '#!/usr/bin/env bash\necho reached >>"$FAKE_LOG.dmg"\nexit 42\n' >"$case_dir/repo/scripts/make-dmg.sh"
    for f in Aitmproxy.entitlements EmbeddedObscura.entitlements Extension/Aitmproxy-Extension.entitlements; do
        cp "$repo_root/apps/mac/$f" "$case_dir/repo/apps/mac/$f"
    done
    app=$case_dir/Aitmproxy.app
    mkdir -p "$app/Contents/Resources/core"
    : >"$app/Contents/Resources/core/aitm"
    : >"$app/Contents/Resources/core/obscura"
    # The bundled detection catalogue, beside the core, where build.sh stages it.
    catalogue=$app/Contents/Resources/core/share/aitm/scripts
    mkdir -p "$catalogue/http"
    echo 'fn on_response(flow) { }' >"$catalogue/http/fixture.rhai"
    sysex=$app/Contents/Library/SystemExtensions/$sysex_name
    if [ "$2" = ne ]; then
        mkdir -p "$sysex/Contents/MacOS" "$sysex/Contents/Frameworks/Nested.framework"
        : >"$sysex/Contents/MacOS/AitmproxyNE"
        : >"$sysex/Contents/Frameworks/libhelper.dylib"
        : >"$app/Contents/embedded.provisionprofile"
        : >"$sysex/Contents/embedded.provisionprofile"
    fi
    : >"$case_dir/AuthKey_TESTKEY.p8"
    log=$case_dir/calls.log
    : >"$log"
}

# run_case [VAR=value ...]: runs the scratch script; sets rc and out (its combined output).
rc=0
out=
run_case() {
    out=$case_dir/out.txt
    env PATH="$stub/bin:$PATH" FAKE_LOG="$log" APP="$app" DEV_ID=TESTID \
        ASC_KEY="$case_dir/AuthKey_TESTKEY.p8" ASC_KEY_ID=TESTKEY ASC_ISSUER_ID=issuer \
        "$@" bash "$case_dir/repo/scripts/notarize-dmg.sh" >"$out" 2>&1
    rc=$?
}

# ---- assertions -------------------------------------------------------------
reached_dmg() { [ -s "$log.dmg" ]; }
called() { grep -q -F -- "$1" "$log"; } # called <fixed text>
# called_line <whole call>: a call that is exactly this line. `called` matches a substring, and a
# call on the app (`... $app`) is a prefix of the same call on the sysex (`... $app/Contents/...`).
called_line() { grep -q -x -F -- "$1" "$log"; }
first_ln() { grep -n -F -- "$1" "$log" | head -n 1 | cut -d: -f1; }
sign_ln() { first_ln "--sign TESTID $1"; } # the line of the sign call for that path
# signed <path>: a sign call whose LAST argument is exactly <path> (so the app is not confused
# with the files under it). signed_without_entitlements is the same but only for calls that
# carry no --entitlements.
signed() { awk -v p="$1" 'index($0, "--sign TESTID ") && substr($0, length($0) - length(p)) == " " p { f = 1 } END { exit !f }' "$log"; }
signed_without_entitlements() {
    awk -v p="$1" 'index($0, "--sign TESTID ") && !index($0, "--entitlements") && substr($0, length($0) - length(p)) == " " p { f = 1 } END { exit !f }' "$log"
}
expect() { # expect <label> <command...>: pass if the command succeeds
    local label=$1
    shift
    if "$@"; then pass "$label"; else fail "$label"; fi
}
expect_not() {
    local label=$1
    shift
    if "$@"; then fail "$label"; else pass "$label"; fi
}
before() { # before <label> <line A> <line B>
    if [ -n "$2" ] && [ -n "$3" ] && [ "$2" -lt "$3" ]; then
        pass "$1 (call $2 before call $3)"
    else
        fail "$1 (call '${2:-missing}' must come before call '${3:-missing}')"
    fi
}
rc_is() { # rc_is <label> <expected>
    if [ "$rc" -eq "$2" ]; then pass "$1 (exit $rc)"; else fail "$1 (expected exit $2, got $rc; output in $out)"; sed 's/^/        | /' "$out" | tail -n 12; fi
}
rc_nonzero_not_dmg() { # an abort: failed, and never got as far as building the DMG
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 42 ]; then pass "$1 aborts (exit $rc)"; else fail "$1 must abort, got exit $rc"; fi
    expect_not "$1 never builds the DMG" reached_dmg
    expect_not "$1 never reaches notarytool or stapler" called "xcrun "
}
said() {
    if grep -q -F -- "$2" "$out"; then pass "$1"; else fail "$1 (output lacks: $2)"; fi
}

# ============ Case 1: NE build, everything correct (SH-AC1, SH-AC2, SH-AC3) ================
echo "--- case 1: NE build, all correct"
mk_case ne-ok ne
run_case
rc_is "NE build with correct signatures reaches the DMG step" 42
expect "the DMG step was reached" reached_dmg
expect_not "notarytool is not reached before the DMG step" called "xcrun "
ext_ent=$case_dir/repo/apps/mac/Extension/Aitmproxy-Extension.entitlements
app_ent=$case_dir/repo/apps/mac/Aitmproxy.entitlements
obs_ent=$case_dir/repo/apps/mac/EmbeddedObscura.entitlements
l_framework=$(sign_ln "$sysex/Contents/Frameworks/Nested.framework")
l_dylib=$(sign_ln "$sysex/Contents/Frameworks/libhelper.dylib")
l_sysex=$(first_ln "--entitlements $ext_ent --sign TESTID $sysex")
l_obscura=$(first_ln "--entitlements $obs_ent --sign TESTID $app/Contents/Resources/core/obscura")
l_aitm=$(sign_ln "$app/Contents/Resources/core/aitm")
l_app=$(first_ln "--entitlements $app_ent --sign TESTID $app")
expect "nested framework in the sysex is signed" test -n "$l_framework"
expect "nested dylib in the sysex is signed" test -n "$l_dylib"
before "nested framework is signed before the sysex bundle" "$l_framework" "$l_sysex"
before "nested dylib is signed before the sysex bundle" "$l_dylib" "$l_sysex"
before "the sysex is signed before obscura" "$l_sysex" "$l_obscura"
before "the sysex is signed before aitm" "$l_sysex" "$l_aitm"
before "obscura is signed before the app" "$l_obscura" "$l_app"
before "aitm is signed before the app" "$l_aitm" "$l_app"
expect "the sysex is signed with its own entitlements" test -n "$l_sysex"
expect "the app is signed WITH the NE entitlements (the v0.5.1 fix)" test -n "$l_app"
expect "the sysex sign uses hardened runtime and a timestamp" called "--force --options runtime --timestamp --entitlements $ext_ent --sign TESTID $sysex"
expect "the app sign uses hardened runtime and a timestamp" called "--force --options runtime --timestamp --entitlements $app_ent --sign TESTID $app"
expect "the app sign call is the NE one" signed "$app"
expect_not "the app is never signed without entitlements in an NE build" signed_without_entitlements "$app"
l_verify=$(first_ln "--verify --deep --strict --verbose=2 $app")
l_dv=$(first_ln "-dv --verbose=4 $sysex")
l_app_dv=$(grep -n -x -F -- "codesign -dv --verbose=4 $app" "$log" | head -n 1 | cut -d: -f1)
before "verification follows the app sign" "$l_app" "$l_verify"
before "the sysex signature is inspected after the app is signed" "$l_app" "$l_dv"
before "the app signature is inspected after the app is signed" "$l_app" "$l_app_dv"
expect "the app's signature is inspected too (for its TeamIdentifier)" called_line "codesign -dv --verbose=4 $app"
# `--entitlements -` is the supported form; the deprecated `:-` reports an invalid blob on current macOS.
expect "the app's entitlements are dumped with --entitlements -" called_line "codesign -d --entitlements - $app"
expect "the sysex's entitlements are dumped with --entitlements -" called_line "codesign -d --entitlements - $sysex"
expect_not "the deprecated ':-' entitlements form is never used" called "entitlements :-"
expect "the Gatekeeper pre-check ran and its rejection was advisory" called "spctl -a -t exec -vvv $app"
expect_not "the benign 'replacing existing signature' chatter is filtered" grep -q -F 'replacing existing signature' "$out"

# ============ Case 2: non-NE build is unchanged (SH-AC6) ===================================
echo "--- case 2: non-NE build"
mk_case plain plain
run_case
rc_is "a build with no sysex reaches the DMG step" 42
expect "the DMG step was reached" reached_dmg
expect "aitm is signed" test -n "$(sign_ln "$app/Contents/Resources/core/aitm")"
expect "obscura is signed with its JIT entitlements" called "--entitlements $case_dir/repo/apps/mac/EmbeddedObscura.entitlements --sign TESTID $app/Contents/Resources/core/obscura"
expect "the app is signed plainly: hardened runtime, timestamp, NO entitlements" \
    called "codesign --force --options runtime --timestamp --sign TESTID $app"
expect_not "no NE entitlements are used anywhere" called "Aitmproxy.entitlements"
expect_not "no extension entitlements are used anywhere" called "Aitmproxy-Extension.entitlements"
expect_not "no sysex is signed" called ".systemextension"
expect_not "no NE verification runs (no -dv)" called " -dv "
expect_not "no entitlement dumps run" called "-d --entitlements"
expect_not "no NE spctl pre-check runs" called "spctl "
expect "codesign --verify --deep --strict still runs" called "--verify --deep --strict --verbose=2 $app"

# ============ Case 3: verification failures abort before the DMG (SH-AC3, SH-AC4) ==========
echo "--- case 3a: the app lost system-extension.install"
mk_case ne-no-install ne
run_case FAKE_APP_ENTS="app-proxy-provider-systemextension"
rc_nonzero_not_dmg "an app without system-extension.install"
said "the failure names the missing entitlement" "com.apple.developer.system-extension.install"

echo "--- case 3b: the app lost the NE provider entitlement"
mk_case ne-no-provider ne
run_case FAKE_APP_ENTS="com.apple.developer.system-extension.install"
rc_nonzero_not_dmg "an app without app-proxy-provider-systemextension"
said "the failure names the missing entitlement" "app-proxy-provider-systemextension"

echo "--- case 3c: the app has no entitlements at all (the v0.5.1 regression)"
mk_case ne-stripped ne
run_case FAKE_APP_ENTS=""
rc_nonzero_not_dmg "an entitlement-stripped app"

echo "--- case 3d: the sysex lost its NE entitlement"
mk_case ne-sysex-no-ents ne
run_case FAKE_SYSEX_ENTS=""
rc_nonzero_not_dmg "a sysex without app-proxy-provider-systemextension"

echo "--- case 3e: the sysex has no hardened runtime"
mk_case ne-no-hardening ne
run_case FAKE_FLAGS="0x0(none)"
rc_nonzero_not_dmg "a sysex signed without the hardened runtime"
said "the failure names the hardened runtime" "hardened runtime"

echo "--- case 3f: the sysex is not Developer ID signed"
mk_case ne-wrong-authority ne
run_case FAKE_AUTHORITY="Apple Development: someone (ABCDE12345)"
rc_nonzero_not_dmg "a sysex signed by a non-Developer-ID identity"
said "the failure names Developer ID" "Developer ID"

# The entitlement files hard-code team 995PCLM9KH, so a bundle signed by any other team
# notarizes fine and then fails AMFI on the user's Mac. Each bundle is checked on its own.
echo "--- case 3g: the sysex is signed by another team"
mk_case ne-sysex-wrong-team ne
run_case FAKE_SYSEX_TEAM=ZZZZZZZZZZ
rc_nonzero_not_dmg "a sysex signed by another team"
said "the failure names the sysex" "the nested system extension is signed by team 995PCLM9KH"
said "the failure shows the TeamIdentifier it wanted" "TeamIdentifier=995PCLM9KH"

echo "--- case 3h: the app is signed by another team"
mk_case ne-app-wrong-team ne
run_case FAKE_APP_TEAM=ZZZZZZZZZZ
rc_nonzero_not_dmg "an app signed by another team"
said "the failure names the app" "the app is signed by team 995PCLM9KH"

echo "--- case 3i: the app has no team at all (ad-hoc signature)"
mk_case ne-app-no-team ne
run_case "FAKE_APP_TEAM=not set"
rc_nonzero_not_dmg "an app with TeamIdentifier=not set"
said "the failure names the app" "the app is signed by team 995PCLM9KH"

echo "--- case 3j: a team id that only starts with the right one"
mk_case ne-sysex-team-prefix ne
run_case FAKE_SYSEX_TEAM=995PCLM9KHZ
rc_nonzero_not_dmg "a sysex whose team id merely starts with 995PCLM9KH"
said "the failure names the sysex" "the nested system extension is signed by team 995PCLM9KH"

# ============ Case 4: a failed sign is never masked (anti-goal: silent codesign success) ===
echo "--- case 4a: codesign fails signing the sysex"
mk_case ne-sign-fails-sysex ne
run_case FAKE_FAIL_SIGN="$sysex"
rc_nonzero_not_dmg "a failed sysex sign"
said "the failure says which codesign call failed" "codesign failed"
expect_not "nothing is signed after the failed sysex sign (obscura)" signed "$app/Contents/Resources/core/obscura"
expect_not "nothing is signed after the failed sysex sign (aitm)" signed "$app/Contents/Resources/core/aitm"
expect_not "nothing is signed after the failed sysex sign (app)" signed "$app"

echo "--- case 4b: codesign fails signing the app with its NE entitlements"
mk_case ne-sign-fails-app ne
run_case FAKE_FAIL_SIGN="$app"
rc_nonzero_not_dmg "a failed app sign"
expect_not "no verification runs after a failed app sign" called "-dv --verbose=4"

echo "--- case 4c: codesign fails signing aitm in a non-NE build"
mk_case plain-sign-fails plain
run_case FAKE_FAIL_SIGN="$app/Contents/Resources/core/aitm"
rc_nonzero_not_dmg "a failed aitm sign"
expect_not "the app is not signed after a failed aitm sign" signed "$app"

# find listing the code nested in the sysex errors out. A `done < <(find ...)` loop discards that
# status and signs whatever was listed; the release must stop before anything is signed.
echo "--- case 4d: find fails while listing the code nested in the sysex"
mk_case ne-find-fails ne
run_case FAKE_FIND_FAIL="$sysex"
rc_nonzero_not_dmg "an errored nested-code find"
said "the failure says the nested-code listing failed" "listing the code nested in"
expect_not "nothing is signed after the errored find" called "--sign"

# The catalogue count is a `find | wc -l` under pipefail: an errored find there must stop the
# release with its own message (cause and fix), not a silent set -e exit.
echo "--- case 4e: find fails while listing the detection catalogue"
mk_case ne-catalogue-find-fails ne
run_case FAKE_FIND_FAIL="$catalogue"
rc_nonzero_not_dmg "an errored catalogue find"
said "the failure says the catalogue listing failed" "listing the detection catalogue"
expect_not "nothing is signed after the errored catalogue find" called "--sign"

# ============ Case 5: a bundle that cannot carry the entitlements is refused ===============
echo "--- case 5a: no app provisioning profile"
mk_case ne-no-app-profile ne
rm -f "$app/Contents/embedded.provisionprofile"
run_case
rc_nonzero_not_dmg "an NE app with no embedded provisioning profile"
said "the failure names the profile" "embedded.provisionprofile"
expect_not "nothing is signed before the profile check" called "--sign"

echo "--- case 5b: no sysex provisioning profile"
mk_case ne-no-sysex-profile ne
rm -f "$sysex/Contents/embedded.provisionprofile"
run_case
rc_nonzero_not_dmg "an NE sysex with no embedded provisioning profile"
said "the failure names the profile" "embedded.provisionprofile"
expect_not "nothing is signed before the profile check" called "--sign"

echo "--- case 5c: two system extensions"
mk_case ne-two-sysex ne
mkdir -p "$app/Contents/Library/SystemExtensions/com.example.other.systemextension/Contents"
run_case
rc_nonzero_not_dmg "an app embedding two extensions"
said "the failure says exactly one is expected" "exactly one"

echo "--- case 5d: no embedded core"
mk_case plain-no-core plain
rm -f "$app/Contents/Resources/core/obscura"
run_case
rc_nonzero_not_dmg "an app with no embedded obscura"
expect_not "nothing is signed for a core-less app" called "--sign"

# The 0.5.4 DMG shipped with core/ holding only aitm + obscura and no share/aitm/scripts, so
# the embedded core loaded zero default detections. Refused here, before anything is signed.
echo "--- case 5f: no bundled catalogue"
mk_case plain-no-catalogue plain
rm -rf "$app/Contents/Resources/core/share"
run_case
rc_nonzero_not_dmg "an app with no bundled catalogue"
expect_not "nothing is signed for a catalogue-less app" called "--sign"
said "the failure names the catalogue" "detection catalogue"

# The guard counts *.rhai, not the directory: a catalogue holding only its README is as empty.
echo "--- case 5g: a catalogue directory with no scripts in it"
mk_case plain-empty-catalogue plain
rm -rf "$catalogue/http"
echo '# bundled detection catalogue' >"$catalogue/README.md"
run_case
rc_nonzero_not_dmg "an app whose catalogue holds no *.rhai"
expect_not "nothing is signed for an app with an empty catalogue" called "--sign"
said "the failure names the catalogue" "detection catalogue"
said "the failure says the catalogue holds no scripts" "holds no *.rhai"

# Only regular files ship in the sealed bundle: a symlink in the catalogue is refused, so what
# the signature seals is exactly what the core reads.
echo "--- case 5h: a symlink inside the catalogue"
mk_case plain-symlink-catalogue plain
ln -s fixture.rhai "$catalogue/http/link.rhai"
run_case
rc_nonzero_not_dmg "an app whose catalogue contains a symlink"
expect_not "nothing is signed for an app with a symlink in its catalogue" called "--sign"
said "the failure names symlinks/special files" "symlink"

echo "--- case 5e: no app"
mk_case no-app plain
rm -rf "$app"
run_case
rc_nonzero_not_dmg "a missing app"
said "the failure says run build.sh first" "build.sh"

echo
if [ "$failures" -eq 0 ]; then
    echo "run-notarize-dmg-stubbed.sh: PASS"
    exit 0
fi
echo "run-notarize-dmg-stubbed.sh: $failures check(s) FAILED" >&2
exit 1
