#!/usr/bin/env bash
# The operator-only tripwire for macOS capture (spec 2026-10-30-macos-ne-ship-and-toggle,
# TG-AC4 and TG-AC9).
#
# Capture is the operator's choice: Settings > Capture or Proxy > Enable/Disable Capture,
# and nowhere else. No bus/MCP verb, Session action or command-palette entry may reach the
# toggle, enable()/disable(), the system-extension activation/deactivation request, or the
# persisted capture.enabled choice. This script reads the Swift source and fails closed.
# Core-side twin: crates/aitm/tests/macos_capture_gate.rs (agent_cannot_trigger_sysex_install).
#
# Usage: tools/check-capture-operator-only.sh [mac-dir]   (default: the apps/mac that holds this script)
# Exit 0 and "PASS" on a clean tree. Exit 1 on any violation, printing each offending
# "file:line" (relative to apps/mac) with its text.
#
# A match counts anywhere in a file, comments included: a surface with no business knowing
# about capture should not mention it either. To add a legitimate operator surface, add it
# to the allow-list below in the same commit, and say why. Every allow-list entry must
# still match (an `expect` line), so the list stays exactly the set that legitimately
# does and cannot quietly widen when code moves.
#
# The five rules, as built:
#   1. The activation/deactivation request and submitRequest live in ExtensionController.swift only.
#   2. Dotted .enable()/.disable() calls appear only in SettingsView.swift (the CaptureSwitch
#      glue) and ExtensionController.swift. App.swift calls CaptureSwitch.set, never these.
#      Same for the published controller handle (extensionController) and CaptureSwitch itself.
#   3. The "capture.enabled" key appears only in EmbeddedCore.swift (spawn reads it),
#      ExtensionController.swift (start() reads it), SettingsView.swift (the toggle + CaptureSwitch)
#      and App.swift (the menu label).
#   4. The agent-reachable surfaces reference none of the above.
#   5. ShellView.swift constructs the ExtensionController once and calls start() on it once.
#      (It also has `bus?.start()`, so this counts by receiver, not every .start().)
set -u
set -o pipefail
export LC_ALL=C

mac_dir=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
cd "$mac_dir" || { echo "FAIL check-capture-operator-only: cannot enter $mac_dir"; exit 1; }

# Product code only. Tests are not an agent-reachable surface.
scan_roots=(Sources Extension)
for root in "${scan_roots[@]}"; do
  [ -d "$root" ] || { echo "FAIL check-capture-operator-only: $mac_dir/$root is not a directory"; exit 1; }
done

ext_controller=Sources/Aitmproxy/Bus/ExtensionController.swift
embedded_core=Sources/Aitmproxy/Bus/EmbeddedCore.swift
core_health=Sources/Aitmproxy/Bus/CoreHealthState.swift
settings_view=Sources/Aitmproxy/SettingsView.swift
app_swift=Sources/Aitmproxy/App.swift
shell_view=Sources/Aitmproxy/Shell/ShellView.swift

violations=0
checked=0

# The UserDefaults key. The leading boundary keeps out `macos_capture.enabled`, the core's
# own YAML path (EmbeddedCoreLaunch.swift documents it), which is a different key.
key_re='(^|[^A-Za-z0-9_])capture\.enabled'

flag() { # rule, "file:line:text" or a message
  printf 'VIOLATION [%s] %s\n' "$1" "$2"
  violations=$((violations + 1))
}

# scan RULE REGEX ALLOWED_FILE...
# Every match of REGEX under the scan roots, in a file not named in ALLOWED_FILE..., is a violation.
scan() {
  local rule=$1 regex=$2 hit file rest line text allowed ok
  shift 2
  while IFS= read -r hit; do
    file=${hit%%:*}
    rest=${hit#*:}
    line=${rest%%:*}
    text=${rest#*:}
    text=${text#"${text%%[![:space:]]*}"}
    ok=0
    for allowed in "$@"; do
      if [ "$file" = "$allowed" ]; then ok=1; break; fi
    done
    if [ "$ok" -eq 0 ]; then flag "$rule" "$file:$line: $text"; fi
  done < <(grep -rnE --include='*.swift' -e "$regex" "${scan_roots[@]}")
}

# expect RULE FILE REGEX WHAT
# FILE must still match REGEX. Keeps an allow-list entry honest and stops a rename from
# turning a rule into a check that finds nothing.
expect() {
  if [ ! -f "$2" ]; then
    flag "$1" "$2: not found, but the allow-list names it"
    return
  fi
  if ! grep -qE -e "$3" "$2"; then
    flag "$1" "$2: no longer contains $4; the allow-list is stale or this tripwire has gone blind. Re-read the code and update this script"
  fi
}

# deny REGEX FILE...
# None of the agent-reachable FILEs may match REGEX. A file that does not exist is noted and skipped.
deny() {
  local regex=$1 f hit line text
  shift
  for f in "$@"; do
    if [ ! -f "$f" ]; then
      echo "NOTE: agent-reachable surface not present, skipped: $f" >&2
      continue
    fi
    checked=$((checked + 1))
    while IFS= read -r hit; do
      line=${hit%%:*}
      text=${hit#*:}
      text=${text#"${text%%[![:space:]]*}"}
      flag "4 agent-reachable surface" "$f:$line: $text"
    done < <(grep -nE -e "$regex" "$f")
  done
}

# ---- 1. the activation/deactivation request: ExtensionController only ----------------
scan "1 system-extension request" \
  '(activation|deactivation)Request[[:space:]]*\(|submitRequest[[:space:]]*\(' \
  "$ext_controller"
expect "1 system-extension request" "$ext_controller" 'activationRequest[[:space:]]*\(' 'the activation request'
expect "1 system-extension request" "$ext_controller" 'deactivationRequest[[:space:]]*\(' 'the deactivation request'

# ---- 2. enable()/disable(), the controller handle, CaptureSwitch ---------------------
scan "2 enable()/disable() call" '\.(enable|disable)[[:space:]]*\(' "$settings_view" "$ext_controller"
expect "2 enable()/disable() call" "$settings_view" '\.enable[[:space:]]*\(' 'a .enable() call (CaptureSwitch)'
expect "2 enable()/disable() call" "$settings_view" '\.disable[[:space:]]*\(' 'a .disable() call (CaptureSwitch)'

# The handle other code would need to reach the controller (CoreHealthState publishes it).
scan "2 controller handle" 'extensionController' "$core_health" "$settings_view" "$ext_controller"
expect "2 controller handle" "$core_health" 'extensionController' 'the published handle'
expect "2 controller handle" "$settings_view" 'extensionController' 'the handle CaptureSwitch uses'
expect "2 controller handle" "$ext_controller" 'extensionController' 'the handle it publishes'

# The one glue type behind the Settings toggle and the menu command.
scan "2 toggle glue" 'CaptureSwitch' "$settings_view" "$app_swift"
expect "2 toggle glue" "$settings_view" 'CaptureSwitch' 'CaptureSwitch'
expect "2 toggle glue" "$app_swift" 'CaptureSwitch' 'the menu command calling CaptureSwitch'

# ---- 3. the persisted choice ---------------------------------------------------------
scan "3 capture.enabled key" "$key_re" \
  "$embedded_core" "$ext_controller" "$settings_view" "$app_swift"
for f in "$embedded_core" "$ext_controller" "$settings_view" "$app_swift"; do
  expect "3 capture.enabled key" "$f" "$key_re" 'the capture.enabled key'
done

# ---- 4. the agent-reachable surfaces reference none of it ----------------------------
deny "$key_re|captureEnabled|CaptureSwitch|ExtensionController|extensionController|OSSystemExtension|(activation|deactivation)Request|submitRequest|\.(enable|disable)[[:space:]]*\(" \
  Sources/Aitmproxy/Bus/BusService.swift \
  Sources/AitmproxyKit/CommandMap.swift \
  Sources/Aitmproxy/Shell/CommandPalette.swift \
  Sources/Aitmproxy/Session+Palette.swift \
  Sources/Aitmproxy/Session+Verbs.swift \
  Sources/Aitmproxy/Panels/AgentPanel.swift \
  Sources/AitmproxyKit/Fixtures+Agent.swift \
  Sources/AitmproxyKit/Fixtures+Tools.swift

# ---- 5. ShellView: one ExtensionController, one start() on it ------------------------
shell_rule="5 ShellView single call site"
if [ ! -f "$shell_view" ]; then
  flag "$shell_rule" "$shell_view: not found"
else
  ctors=$(grep -cE -e 'ExtensionController[[:space:]]*\(' "$shell_view")
  if [ "$ctors" -ne 1 ]; then
    flag "$shell_rule" "$shell_view: expected exactly 1 ExtensionController( construction, found $ctors"
  fi
  # The receivers a .start() could be called on: the local bound to the constructor, the
  # @State holder, and the published handle.
  local_name=$(grep -E -e '(let|var)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*ExtensionController[[:space:]]*\(' "$shell_view" |
    sed -E 's/.*(let|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*/\2/' | head -n 1)
  holder_name=$(grep -E -e '(let|var)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:[[:space:]]*ExtensionController' "$shell_view" |
    sed -E 's/.*(let|var)[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*:.*/\2/' | head -n 1)
  if [ -z "$local_name" ]; then
    flag "$shell_rule" "$shell_view: no 'let <name> = ExtensionController(' to name the receiver; update this script"
  else
    receivers="extensionController|$local_name"
    [ -n "$holder_name" ] && receivers="$receivers|$holder_name"
    starts=$(grep -nE -e "(^|[^A-Za-z0-9_])($receivers)[?!]?[[:space:]]*\.start[[:space:]]*\(" "$shell_view")
    start_count=$(printf '%s\n' "$starts" | grep -c .)
    if [ "$start_count" -ne 1 ]; then
      flag "$shell_rule" "$shell_view: expected exactly 1 .start() on the ExtensionController ($receivers), found $start_count"
      printf '%s\n' "$starts" | while IFS= read -r l; do [ -n "$l" ] && printf '    %s:%s\n' "$shell_view" "$l"; done
    fi
  fi
fi

if [ "$violations" -ne 0 ]; then
  echo "FAIL check-capture-operator-only: $violations violation(s). Capture must stay operator-only."
  exit 1
fi
echo "PASS check-capture-operator-only ($checked agent-reachable surfaces checked)"
