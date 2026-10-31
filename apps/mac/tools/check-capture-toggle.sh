#!/usr/bin/env bash
# Structural tripwire for the macOS capture toggle (spec
# docs/superpowers/specs/2026-10-30-macos-ne-ship-and-toggle-design.md):
# TG-AC3 spawn reads the choice fresh, TG-AC4 first run OFF asks nothing, TG-AC5 ON,
# TG-AC6 OFF, TG-AC8 persisted OFF default and idempotent, TG-AC10 menu + shortcut,
# TG-AC11 the four snapshot states.
#
# Why this exists: the toggle's glue (CaptureSwitch, ExtensionController start/enable/disable,
# EmbeddedCore.spawn) lives in the app target, which has no unit-test target, and the
# plan's per-task grep checks were run once and never committed. This script keeps them.
# It reads Swift source only: it cannot prove the toggle works on a Mac (the manual steps
# in the plan do that), but it pins what a regression would have to undo, and fails
# closed when the code it reads moves. The sibling check-capture-operator-only.sh covers
# TG-AC9 (who may call any of this); this one covers what the calls do.
#
# Usage: tools/check-capture-toggle.sh [mac-dir]   (default: the apps/mac that holds this script)
# Exit 0 and "PASS" when every check holds; exit 1 and a "FAIL:" line per broken check.
#
# Function bodies are cut out by brace counting with comments removed, so a comment that
# merely mentions saveToPreferences or deactivationRequest cannot satisfy or trip a check.
# When a check says a function was not found, the code was renamed or moved: re-read it
# and update this script in the same commit. Do not delete the check.
set -u
set -o pipefail
export LC_ALL=C

mac_dir=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
cd "$mac_dir" || { echo "FAIL: cannot enter $mac_dir"; exit 1; }
[ -d Sources ] || { echo "FAIL: $mac_dir/Sources is not a directory"; exit 1; }

ext=Sources/Aitmproxy/Bus/ExtensionController.swift
core=Sources/Aitmproxy/Bus/EmbeddedCore.swift
core_ctl=Sources/Aitmproxy/Bus/EmbeddedCoreController.swift
health=Sources/Aitmproxy/Bus/CoreHealthState.swift
settings=Sources/Aitmproxy/SettingsView.swift
app=Sources/Aitmproxy/App.swift
shell=Sources/Aitmproxy/Shell/ShellView.swift
snap=Sources/Aitmproxy/Snapshot.swift
scenes=Sources/Aitmproxy/SnapshotScenes.swift
for f in "$ext" "$core" "$core_ctl" "$health" "$settings" "$app" "$shell" "$snap" "$scenes"; do
    [ -f "$f" ] || { echo "FAIL: $f not found; update this script"; exit 1; }
done

failures=0
pass() { echo "ok:   $1"; }
fail() {
    echo "FAIL: $1"
    failures=$((failures + 1))
}

# body_of FILE SIGNATURE_ERE: the function's lines as "lineno:code", from its signature line
# to its closing brace, trailing // comments removed. Empty when the signature is not found.
# (Signatures use [(] not \( so awk -v does not eat the backslash.)
body_of() {
    awk -v sig="$2" '
        !started && $0 ~ sig { started = 1 }
        started {
            code = $0
            sub(/\/\/.*/, "", code)
            opens = gsub(/\{/, "{", code)
            closes = gsub(/\}/, "}", code)
            print NR ":" code
            depth += opens - closes
            if (opens > 0) seen = 1
            if (seen && depth <= 0) exit
        }
    ' "$1"
}
# line_of BODY ERE: the source line number of the first body line matching ERE (empty if none).
line_of() { grep -E -- "$2" <<<"$1" | head -n 1 | cut -d: -f1; }
# between BODY A B: the body lines strictly between source lines A and B.
between() { awk -F: -v a="$2" -v b="$3" '$1 > a && $1 < b' <<<"$1"; }
# after BODY A: the body lines after source line A.
after() { awk -F: -v a="$2" '$1 > a' <<<"$1"; }

found() { # found <label> <body>: a function body must exist, or every check on it is meaningless
    if [ -n "$2" ]; then pass "$1 found"; else fail "$1 not found (renamed or moved; update this script)"; fi
}
has() { # has <label> <text> <fixed string>
    if [ -n "$2" ] && grep -q -F -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (missing: $3)"; fi
}
hasnt() { # hasnt <label> <text> <ERE>: text must exist and must not match
    local hits
    if [ -z "$2" ]; then fail "$1 (nothing to check: function not found)"; return; fi
    hits=$(grep -n -E -- "$3" <<<"$2" | head -n 1)
    if [ -z "$hits" ]; then pass "$1"; else fail "$1 (found: $hits)"; fi
}
equals() { # equals <label> <actual> <expected>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$3', got '$2')"; fi
}
ordered() { # ordered <label> <line A> <line B>: both exist and A comes first
    if [ -n "$2" ] && [ -n "$3" ] && [ "$2" -lt "$3" ]; then
        pass "$1 (line $2 before line $3)"
    else
        fail "$1 (line '${2:-missing}' must come before line '${3:-missing}')"
    fi
}
# only_in LABEL FILE ERE SIGNATURE_ERE...: every non-comment match of ERE in FILE lies inside
# one of the named functions, and there is at least one match (so the rule cannot go blind).
only_in() {
    local label=$1 file=$2 re=$3 sig body ranges="" first last hit n r ok outside="" hits=0
    shift 3
    for sig in "$@"; do
        body=$(body_of "$file" "$sig")
        if [ -z "$body" ]; then fail "$label (function '$sig' not found in $file)"; return; fi
        first=$(head -n 1 <<<"$body" | cut -d: -f1)
        last=$(tail -n 1 <<<"$body" | cut -d: -f1)
        ranges="$ranges $first-$last"
    done
    while IFS= read -r hit; do
        n=${hit%%:*}
        hits=$((hits + 1))
        ok=0
        for r in $ranges; do
            if [ "$n" -ge "${r%-*}" ] && [ "$n" -le "${r#*-}" ]; then ok=1; fi
        done
        if [ "$ok" -eq 0 ]; then outside="$outside $n"; fi
    done < <(grep -n -E -- "$re" "$file" | grep -v -E '^[0-9]+:[[:space:]]*//')
    if [ "$hits" -eq 0 ]; then
        fail "$label (no longer matches anywhere in $file; this check has gone blind)"
    elif [ -z "$outside" ]; then
        pass "$label"
    else
        fail "$label (outside the allowed functions, at $file lines:$outside)"
    fi
}
# code_lines FILE: the file's non-comment lines (comment-only lines dropped).
code_lines() { grep -v -E '^[[:space:]]*//' "$1"; }

# ============================ TG-AC3: spawn reads the choice fresh =====================
spawn=$(body_of "$core" '^[[:space:]]*(private )?func spawn[(][)]')
found "TG-AC3 EmbeddedCore.spawn()" "$spawn"
has "TG-AC3 spawn() reads capture.enabled from UserDefaults" "$spawn" 'forKey: "capture.enabled"'
spawn_read=$(grep -F 'forKey: "capture.enabled"' <<<"$spawn" | head -n 1)
has "TG-AC3/TG-AC8 the spawn read is false when the key is absent or not a Bool" "$spawn_read" 'as? Bool ?? false'
has "TG-AC3 spawn() threads the choice into the core Config" "$spawn" 'captureEnabled: captureEnabled'
equals "TG-AC3 capture.enabled is read only inside spawn(), never cached across spawns" \
    "$(code_lines "$core" | grep -c -F 'capture.enabled')" "$(grep -c -F 'capture.enabled' <<<"$spawn")"
core_start=$(body_of "$core" '^[[:space:]]*func start[(][)] async')
found "TG-AC3 EmbeddedCore.start()" "$core_start"
has "TG-AC3 start() spawns (so a restart re-reads the choice)" "$core_start" 'await spawn()'
restart=$(body_of "$core_ctl" '^[[:space:]]*func restart[(][)]')
found "TG-AC3 EmbeddedCoreController.restart()" "$restart"
ordered "TG-AC3 restart() stops the core, then starts a fresh one" \
    "$(line_of "$restart" 'core[.]stop[(][)]')" "$(line_of "$restart" 'core[.]start[(][)]')"
has "TG-AC3 ShellView maps restartCoreTick to the embedded-core restart" \
    "$(code_lines "$shell")" 'onChange(of: session.restartCoreTick) { embeddedCore?.restart() }'

# ============================ TG-AC4: first run OFF asks nothing =======================
# The prompts are: the activation request (Network Extensions) and the first save of a new
# NETransparentProxyManager (Add Proxy Configurations). Neither may be reachable from start().
prompting='submitRequest|activationRequest|OSSystemExtensionManager|saveToPreferences|startVPNTunnel|NETransparentProxyManager[(][)]|removeFromPreferences'
start=$(body_of "$ext" '^[[:space:]]*func start[(][)] [{]')
found "TG-AC4 ExtensionController.start()" "$start"
hasnt "TG-AC4 start() itself submits no request and saves no configuration" "$start" "$prompting"
equals "TG-AC4 start() calls enable() exactly once" "$(grep -c -E '^[0-9]+:[[:space:]]*enable[(][)]' <<<"$start")" "1"
start_enable=$(line_of "$start" '^[0-9]+:[[:space:]]*enable[(][)]')
if [ -n "$start_enable" ]; then
    guard_line=$(sed -n "$((start_enable - 1))p" "$ext")
    if grep -q -E 'capture\.enabled.*\?\? false[[:space:]]*\{' <<<"$guard_line"; then
        pass "TG-AC4 enable() runs only inside 'if <capture.enabled> ?? false {'"
    else
        fail "TG-AC4 enable() in start() must sit directly under 'if ... capture.enabled ... ?? false {' (found: $guard_line)"
    fi
else
    fail "TG-AC4 no enable() call found in start()"
fi
detect=$(body_of "$ext" '^[[:space:]]*(private )?func detectInactiveExtension[(][)]')
found "TG-AC4 detectInactiveExtension()" "$detect"
has "TG-AC4 the off-at-launch detection only reads saved configurations" "$detect" 'loadAllFromPreferences'
hasnt "TG-AC4 the off-at-launch detection submits and saves nothing" "$detect" "$prompting"
only_in "TG-AC4 the activation request is built only in enable()" "$ext" '[.]activationRequest[[:space:]]*[(]' \
    '^[[:space:]]*func enable[(][)] [{]'
only_in "TG-AC4 submitRequest is called only in enable() and deactivate()" "$ext" 'submitRequest[[:space:]]*[(]' \
    '^[[:space:]]*func enable[(][)] [{]' '^[[:space:]]*(private )?func deactivate[(][)]'
only_in "TG-AC4 a new proxy configuration (the second prompt) is created only in the reconcile" "$ext" \
    'NETransparentProxyManager[(][)]' '^[[:space:]]*(private )?func enableAndStartTunnel[(][)]'
only_in "TG-AC4 configurations are saved only by the reconcile and by disable()" "$ext" 'saveToPreferences' \
    '^[[:space:]]*(private )?func enableAndStartTunnel[(][)]' '^[[:space:]]*func disable[(][)] async'
only_in "TG-AC4 the tunnel is started only by the reconcile" "$ext" 'startVPNTunnel' \
    '^[[:space:]]*(private )?func enableAndStartTunnel[(][)]'

# ============================ TG-AC5 / TG-AC6: the operator's ON and OFF ===============
sw=$(body_of "$settings" '^[[:space:]]*static func set[(]_ on: Bool')
found "TG-AC5/6 CaptureSwitch.set" "$sw"
l_if=$(line_of "$sw" '^[0-9]+:[[:space:]]*if on [{]$')
l_else=$(line_of "$sw" '^[0-9]+:[[:space:]]*[}] else [{]$')
if [ -n "$l_if" ] && [ -n "$l_else" ]; then
    on_block=$(between "$sw" "$l_if" "$l_else")
    off_block=$(after "$sw" "$l_else")
else
    fail "TG-AC5/6 CaptureSwitch.set has no 'if on { ... } else { ... }' to read; update this script"
    on_block=""
    off_block=""
fi
has "TG-AC5 ON persists capture.enabled = true" "$on_block" 'set(true, forKey: "capture.enabled")'
has "TG-AC5 ON activates the extension" "$on_block" 'extensionController?.enable()'
has "TG-AC5 ON restarts the core so the feeder gate opens" "$on_block" 'restartCoreTick += 1'
hasnt "TG-AC5 ON never calls disable()" "$on_block" '[.]disable[[:space:]]*[(]'
ordered "TG-AC5 ON writes the choice before the restart reads it" \
    "$(line_of "$on_block" 'set[(]true, forKey: "capture[.]enabled"[)]')" "$(line_of "$on_block" 'restartCoreTick')"
has "TG-AC6 OFF stops the tunnel through disable()" "$off_block" 'extensionController?.disable()'
has "TG-AC6 OFF persists capture.enabled = false" "$off_block" 'set(false, forKey: "capture.enabled")'
has "TG-AC6 OFF restarts the core so the feeder gate closes" "$off_block" 'restartCoreTick += 1'
hasnt "TG-AC6 OFF never calls enable()" "$off_block" '[.]enable[[:space:]]*[(]'
l_disable=$(line_of "$off_block" 'disable[(][)]')
l_off_set=$(line_of "$off_block" 'set[(]false, forKey: "capture[.]enabled"[)]')
l_off_tick=$(line_of "$off_block" 'restartCoreTick')
ordered "TG-AC6 OFF stops the tunnel before it clears the choice" "$l_disable" "$l_off_set"
ordered "TG-AC6 OFF clears the choice before the restart reads it" "$l_off_set" "$l_off_tick"
has "TG-AC6 OFF waits for disable() to finish (await)" "$(grep -F 'disable()' <<<"$off_block")" 'await'

disable=$(body_of "$ext" '^[[:space:]]*func disable[(][)] async')
found "TG-AC6 ExtensionController.disable()" "$disable"
has "TG-AC6 disable() stops the tunnel" "$disable" 'stopVPNTunnel()'
has "TG-AC6 disable() switches the saved configuration off so the system cannot restart it" "$disable" 'isEnabled = false'
has "TG-AC6 disable() cancels the reconcile so a late save cannot restart the tunnel" "$disable" 'reconcileTask?.cancel()'
has "TG-AC6 disable() records that capture is no longer wanted" "$disable" 'captureWanted = false'
hasnt "TG-AC6 disable() removes nothing and submits no deactivation (the sysex stays installed)" "$disable" \
    'deactivationRequest|deactivate[(]|removeFromPreferences|removeSavedConfiguration|submitRequest|activationRequest'
# The last statement of the body (the line before the closing brace) is the state change.
has "TG-AC6 disable() ends in apply(.disabled)" "$(tail -n 2 <<<"$disable" | head -n 1)" 'apply(.disabled)'
enable=$(body_of "$ext" '^[[:space:]]*func enable[(][)] [{]')
found "TG-AC5 ExtensionController.enable()" "$enable"
has "TG-AC5 enable() records that capture is wanted (so a late approval brings the tunnel up)" "$enable" 'captureWanted = true'
has "TG-AC5 enable() submits the request" "$enable" 'submitRequest('
has "TG-AC6 a request that completes after an OFF leaves the tunnel down" "$(code_lines "$ext")" 'guard captureWanted else'
uninstall=$(body_of "$ext" '^[[:space:]]*func uninstall[(][)] async')
found "TG-AC6 ExtensionController.uninstall()" "$uninstall"
has "TG-AC6 uninstall() still removes the saved configuration" "$uninstall" 'removeSavedConfiguration()'
has "TG-AC6 uninstall() still deactivates the extension" "$uninstall" 'deactivate()'
has "TG-AC6 uninstall() still ends at not-installed" "$uninstall" 'apply(.uninstalled)'
remove_cfg=$(body_of "$ext" '^[[:space:]]*(private )?func removeSavedConfiguration[(][)]')
has "TG-AC6 removeSavedConfiguration() removes the configuration" "$remove_cfg" 'removeFromPreferences()'
deactivate=$(body_of "$ext" '^[[:space:]]*(private )?func deactivate[(][)]')
has "TG-AC6 deactivate() submits the deactivation request" "$deactivate" 'deactivationRequest('

# ============================ TG-AC8: persisted OFF default, idempotent ================
# Every way the choice is read must default to off. A `?? true`, a registered default or an
# @AppStorage default of true would arm capture on a fresh install.
equals "TG-AC8 no capture.enabled read defaults to true or registers a default" \
    "$(grep -rn -E --include='*.swift' 'capture\.enabled.*(\?\? true|register)|register.*capture\.enabled' Sources | grep -v -E ':[0-9]+:[[:space:]]*//' | head -n 1)" ""
storage=$(grep -rn -F --include='*.swift' '@AppStorage("capture.enabled")' Sources | grep -v -E ':[0-9]+:[[:space:]]*//')
if [ "$(grep -c . <<<"$storage")" -ge 2 ]; then
    pass "TG-AC8 the Settings toggle and the menu label both bind @AppStorage(\"capture.enabled\")"
else
    fail "TG-AC8 expected @AppStorage(\"capture.enabled\") in SettingsView and App (found: ${storage:-none})"
fi
equals "TG-AC8 every @AppStorage(\"capture.enabled\") defaults to false" \
    "$(grep -v -E '= false[[:space:]]*$' <<<"$storage")" ""
has "TG-AC8 start() reads the choice as false-by-default" "$start" 'as? Bool ?? false'
# Idempotence: a toggle to the value already in force, or while another action runs, does nothing.
# The guard statement spans the lines from `guard` to its `else { return }`.
l_guard=$(line_of "$sw" '^[0-9]+:[[:space:]]*guard ')
l_return=$(line_of "$sw" 'else [{] return [}]')
if [ -n "$l_guard" ] && [ -n "$l_return" ]; then
    sw_guard=$(between "$sw" "$((l_guard - 1))" "$((l_return + 1))")
else
    fail "TG-AC8 CaptureSwitch.set has no 'guard ... else { return }' to read; update this script"
    sw_guard=""
fi
ordered "TG-AC8 the guard is the first thing set() does (before the busy flag is raised)" \
    "$l_return" "$(line_of "$sw" 'captureBusy = true')"
has "TG-AC8 set() ignores a request made while another capture action runs" "$sw_guard" '!health.captureBusy'
has "TG-AC8 set() ignores a request for the state already in force" "$sw_guard" 'on != UserDefaults.standard.bool(forKey: "capture.enabled")'
has "TG-AC8 enable() submits no second request while one is outstanding or capture is on" "$enable" \
    'guard pendingActivity == nil, !health.captureCapability.isCaptureOn'
has "TG-AC8 enable() refuses while a disable() or uninstall() runs" "$enable" '!uninstalling, !disabling'
has "TG-AC8 disable() refuses a second concurrent disable" "$disable" '!disabling'
has "TG-AC8 start() runs once" "$start" 'guard !started'

# ============================ visibility: a dev build shows no dead toggle =============
launch=$(body_of "$health" '^[[:space:]]*(private )?static func launchSupportsCapture[(][)]')
found "visibility CoreHealthState.launchSupportsCapture()" "$launch"
has "visibility captureSupported comes from the launch guards, not a constant" \
    "$(code_lines "$health")" 'var captureSupported: Bool = CoreHealthState.launchSupportsCapture()'
has "visibility fixtures are never capture-capable" "$launch" 'Store.usesFixtures'
has "visibility self-test runs are never capture-capable" "$launch" 'SelfTest.requested'
has "visibility snapshot runs are never capture-capable" "$launch" 'APP_SNAPSHOT'
has "visibility only a build that embeds the extension is capture-capable" "$launch" 'CaptureExtension.isEmbedded(inApp: Bundle.main.bundleURL)'
cs_body=$(body_of "$settings" '^struct CaptureSettings')
found "visibility CaptureSettings view" "$cs_body"
l_avail=$(line_of "$cs_body" 'if health[.]captureControlsAvailable [{]')
l_toggle=$(line_of "$cs_body" 'Toggle[(]"Capture L4 traffic"')
l_note=$(line_of "$cs_body" 'Not available in this build')
ordered "visibility the live Toggle sits inside the captureControlsAvailable branch" "$l_avail" "$l_toggle"
ordered "visibility the 'Not available in this build' note follows the live Toggle (else branch)" "$l_toggle" "$l_note"
hasnt "TG-AC5 the Settings status line never hard-codes 'Capturing' (it shows CaptureCapability.title)" \
    "$cs_body" '"Capturing"'
has "TG-AC5 the Settings status line shows CaptureCapability.title" "$cs_body" 'Text(capability.title)'
has "TG-AC5 a running action reads Working, never Capturing" "$cs_body" 'Text("Working…")'

# ============================ TG-AC10: menu command + non-colliding shortcut ===========
proxy_menu_start=$(grep -n -F 'CommandMenu("Proxy")' "$app" | head -n 1 | cut -d: -f1)
next_menu=$(awk -v a="${proxy_menu_start:-0}" 'NR > a && /CommandMenu[(]/ { print NR; exit }' "$app")
menu_item=$(grep -n -E 'Button[(].*"Disable Capture" : "Enable Capture"|Button[(].*"Enable Capture" : "Disable Capture"' "$app" | head -n 1 | cut -d: -f1)
if [ -n "$menu_item" ]; then
    pass "TG-AC10 App.swift has the Enable/Disable Capture menu command (line $menu_item)"
else
    fail "TG-AC10 App.swift has no 'Enable Capture' / 'Disable Capture' menu Button"
fi
if [ -n "$proxy_menu_start" ] && [ -n "$next_menu" ] && [ -n "$menu_item" ] \
    && [ "$menu_item" -gt "$proxy_menu_start" ] && [ "$menu_item" -lt "$next_menu" ]; then
    pass "TG-AC10 the command is in the Proxy menu"
else
    fail "TG-AC10 the capture command must sit inside CommandMenu(\"Proxy\") (menu $proxy_menu_start, next $next_menu, item $menu_item)"
fi
if [ -n "$menu_item" ]; then
    item_text=$(sed -n "${menu_item},$((menu_item + 8))p" "$app")
    shortcut_line=$(grep -F '.keyboardShortcut(' <<<"$item_text" | head -n 1)
    has "TG-AC10 the command runs the same glue as the toggle" "$item_text" 'CaptureSwitch.set('
    has "TG-AC10 the command stands down in a build with no extension and while an action runs" "$item_text" \
        'captureControlsAvailable'
    has "TG-AC10 the command stands down while an action runs" "$item_text" 'captureBusy'
else
    shortcut_line=""
fi

# chord_of <text after ".keyboardShortcut(">: "key|sorted modifiers". SwiftUI's default modifier is
# .command when none is given.
chord_of() {
    local rest=$1 key mods
    if [[ $rest == *"modifiers:"* ]]; then
        key=${rest%%, modifiers:*}
        mods=${rest#*modifiers:}
        mods=${mods%%]*}
        mods=${mods%%)*}
    else
        key=${rest%%)*}
        mods=".command"
    fi
    key=${key// /}
    echo "$key|$(grep -o -E '[.][a-zA-Z]+' <<<"$mods" | sort -u | paste -s -d + -)"
}
if [ -n "${shortcut_line:-}" ]; then
    mine=$(chord_of "${shortcut_line#*.keyboardShortcut(}")
    pass "TG-AC10 the command has a keyboard shortcut ($mine)"
    clashes=0
    while IFS= read -r hit; do
        text=${hit#*:}
        text=${text#*:}
        other=$(chord_of "${text#*.keyboardShortcut(}")
        if [ "$other" = "$mine" ]; then clashes=$((clashes + 1)); fi
    done < <(grep -rn -F --include='*.swift' '.keyboardShortcut(' Sources | grep -v -E ':[0-9]+:[[:space:]]*//')
    equals "TG-AC10 no other shortcut in Sources uses $mine" "$clashes" "1"
    case "$mine" in
    'c|.command' | 'v|.command' | 'x|.command' | 'z|.command' | 'a|.command' | 'q|.command' | 'w|.command' | 'h|.command' | 'm|.command' | '","|.command')
        fail "TG-AC10 $mine is a standard system shortcut" ;;
    *) pass "TG-AC10 $mine is not a standard system shortcut" ;;
    esac
else
    fail "TG-AC10 the capture command has no .keyboardShortcut within its Button"
fi

# ============================ TG-AC11: the four snapshot states ========================
has "TG-AC11 the snapshot states are off, awaiting, active and failed" "$(code_lines "$scenes")" 'case off, awaiting, active, failed'
for seeded in '.inactive' '.pendingApproval' '.capturing' '.degraded('; do
    has "TG-AC11 a snapshot state seeds $seeded" "$(code_lines "$scenes")" "captureCapability = $seeded"
done
has "TG-AC11 every state is captured" "$(code_lines "$snap")" 'for state in CaptureSnapshotState.allCases'
has "TG-AC11 each capture is written as settings-capture-<state>-<mode>.png" "$(code_lines "$snap")" \
    'settings-capture-\(state.rawValue)-\(mode).png'
has "TG-AC11 the capture loop runs in light and dark" "$(code_lines "$snap")" 'for mode in ["light", "dark"]'

echo
if [ "$failures" -eq 0 ]; then
    echo "PASS check-capture-toggle"
    exit 0
fi
echo "FAIL check-capture-toggle: $failures check(s) failed. The capture toggle's behaviour has drifted from the spec."
exit 1
