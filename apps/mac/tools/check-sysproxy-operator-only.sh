#!/usr/bin/env bash
# The operator-only tripwire for the system proxy in the macOS app (spec
# 2026-10-31-system-proxy-automation-design §D13 "Tripwire", SP-AC24).
#
# Setting the system proxy rewrites the Mac's network settings. The app does it through ONE
# path, `Session.setSystemProxy()` / `restoreSystemProxy()` in
# Sources/Aitmproxy/Session+SystemProxy.swift — the only file that spells the bus verbs
# "proxy.system.set" / "proxy.system.unset" — reached from the operator's surfaces only:
# Settings ▸ Proxy's live toggle, the Status page's row, the first-run sheet, the Flows route
# banner / empty state, and the Proxy menu. "Set system proxy at launch" is a preference the
# operator writes in Settings or on the sheet and the embedded-core spawn reads; no agent
# surface can flip either. This script reads the Swift source and fails closed.
#
# Usage: tools/check-sysproxy-operator-only.sh [mac-dir]   (default: the apps/mac that holds this script)
#        tools/check-sysproxy-operator-only.sh --self-check   plants one violation per rule (two for rule 2)
#                                                             in a copy and expects each rule's tag on its file
# Exit 0 and "PASS" on a clean tree. Exit 1 on any violation, printing each offending
# "file:line" (relative to apps/mac) with its text.
#
# A match counts anywhere in a file, comments included. To add a legitimate operator
# surface, add it to the allow-list below in the same commit, and say why. Every
# allow-list entry must still match (an `expect` line), so the list stays exactly the set
# that legitimately does and cannot quietly widen when code moves. A file a rule names
# that is not there is a violation, never a skip: a surface that moved takes its rule along.
#
# This tripwire greps TOKENS. It guards honest changes (a refactor that moves a call into
# the wrong file, a surface that copies a neighbour's code), not deliberately obfuscated
# code: a verb assembled from pieces, a call reached by reflection. That is review's job.
#
# The four rules, as built:
#   1. The quoted literals "proxy.system.set" and "proxy.system.unset" appear in
#      Session+SystemProxy.swift only. "proxy.system.status" is a read and is not ruled on.
#      Session.swift's doc comments name the verbs in backticks, unquoted, which the regex
#      does not match.
#   2. `.setSystemProxy(` / `.restoreSystemProxy(` are called from SettingsView.swift,
#      Panels/StatusPanel.swift, Shell/SetupSheet.swift, Shell/RouteBanner.swift and App.swift
#      only (each with an expect pinned to the call shape `session.setSystemProxy()`, which the
#      surfaces' doc comments — `Session.setSystemProxy()` — do not satisfy). Shell/ShellView.swift's
#      empty state routes through the shared RouteBanner model and makes no call of its own, so it
#      is not listed. An UNDOTTED
#      `setSystemProxy(` / `restoreSystemProxy(` (a call from inside an `extension Session`, or
#      a second definition) may appear in those five files and in Session+SystemProxy.swift only,
#      where the undotted matches are exactly the two `func` definitions (pinned by count). A BARE
#      member reference — `session.setSystemProxy`, `self.restoreSystemProxy`,
#      `Session.setSystemProxy` with no `(` after it, the method handed on as a value — may appear
#      in those six files only. The receiver is required because `.setSystemProxy` is also the
#      `ConnectionAction` case every surface names (ConnectionSummary.swift, Session+Connection.swift,
#      StatusPanel, RouteBanner, SetupSheet, App).
#   3. The agent-reachable surfaces of check-capture-operator-only.sh's rule 4 plus the self-tests
#      match none of: the quoted verbs, `session.`/`Session.`/`self.` + the method, or an undotted
#      method call. BusService.swift parses the STATUS sub-object (fine); CommandMap.swift carries
#      the menu TITLES "Set as System Proxy" / "Restore System Proxy" only; Session+Palette.swift
#      calls `Session.isSystemProxyVerb(` (the palette's guard), which the pattern does not match.
#   4. The launch preference `SystemProxyPreferences.autoKey` ("Set system proxy at launch") is
#      WRITTEN in SettingsView.swift (@AppStorage) and Shell/SetupSheet.swift (the sheet's button)
#      and READ in Bus/EmbeddedCore.swift (spawn), Bus/EmbeddedCoreController.swift (the applied
#      snapshot for the Apply dirty-check) and Session+CATrust.swift (`setupSheetDue`: the sheet is
#      not due when the launch toggle is on). The token appears in those five files only, plus one
#      `///` doc-comment mention in AitmproxyKit/CoreConnection.swift (pinned to exactly one line
#      and to a comment). The raw literal "systemProxy.auto" appears in
#      AitmproxyKit/SystemProxyPreferences.swift only, as the key's definition.
set -u
set -o pipefail
export LC_ALL=C

self=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")

if [ "${1:-}" = "--self-check" ]; then
  src=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  work=$(mktemp -d "${TMPDIR:-/tmp}/check-sysproxy-operator-only.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  cp -R "$src/Sources" "$work/Sources"
  [ -d "$src/Extension" ] && cp -R "$src/Extension" "$work/Extension"
  if ! bash "$self" "$work" >/dev/null; then
    echo "SELF-CHECK FAIL: the clean copy does not pass; fix the tree first"
    exit 1
  fi
  # One plant per rule, two for rule 2: a quoted verb (rule 1), an undotted call from inside an
  # extension Session outside the allow-list and a bare member reference outside it (rule 2),
  # a receiver-dotted call on an agent-reachable surface (rule 3), the raw preference key
  # outside its definition (rule 4).
  printf '\nlet _ = "proxy.system.set"\n' >> "$work/Sources/Aitmproxy/Session+Verbs.swift"
  printf '\nextension Session {\n    func plantedSet() async { await setSystemProxy() }\n}\n' >> "$work/Sources/Aitmproxy/Session+Connection.swift"
  printf '\nextension Session {\n    var plantedSetRef: () async -> Void { self.setSystemProxy }\n}\n' >> "$work/Sources/Aitmproxy/Panels/ConfigPanel.swift"
  printf '\n// planted: session.setSystemProxy()\n' >> "$work/Sources/Aitmproxy/Panels/AgentPanel.swift"
  printf '\nlet _ = "systemProxy.auto"\n' >> "$work/Sources/Aitmproxy/Session+Verbs.swift"
  # The two shapes the security panel found unguarded (2026-11-01): an undotted member reference
  # with no `(` inside an extension Session in a shared file, and a receiver that is neither
  # `session` nor `self`.
  printf '\nextension Session {\n    var plantedBareRef: () async -> Void { setSystemProxy }\n}\n' >> "$work/Sources/Aitmproxy/Panels/ScopePanel.swift"
  printf '\nfunc plantedOtherReceiver(_ s: Session) -> () async -> Void { s.restoreSystemProxy }\n' >> "$work/Sources/Aitmproxy/Panels/ScriptsPanel.swift"
  out=$(bash "$self" "$work" 2>&1); rc=$?
  printf '%s\n' "$out"
  ok=1
  if [ "$rc" -ne 1 ]; then echo "SELF-CHECK FAIL: expected exit 1, got exit $rc"; ok=0; fi
  grep -qE '^VIOLATION \[1 [^]]*\] Sources/Aitmproxy/Session\+Verbs\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 1 did not name the planted \"proxy.system.set\" in Session+Verbs.swift"; ok=0; }
  grep -qE '^VIOLATION \[2 [^]]*\] Sources/Aitmproxy/Session\+Connection\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 2 did not name the planted undotted setSystemProxy() in Session+Connection.swift"; ok=0; }
  grep -qE '^VIOLATION \[2 [^]]*\] Sources/Aitmproxy/Panels/ConfigPanel\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 2 did not name the planted bare self.setSystemProxy reference in Panels/ConfigPanel.swift"; ok=0; }
  grep -qE '^VIOLATION \[3 [^]]*\] Sources/Aitmproxy/Panels/AgentPanel\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 3 did not name the planted session.setSystemProxy() in Panels/AgentPanel.swift"; ok=0; }
  grep -qE '^VIOLATION \[4 [^]]*\] Sources/Aitmproxy/Session\+Verbs\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 4 did not name the planted \"systemProxy.auto\" in Session+Verbs.swift"; ok=0; }
  grep -qE '^VIOLATION \[2 [^]]*\] Sources/Aitmproxy/Panels/ScopePanel\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 2 did not name the planted bare undotted setSystemProxy reference in Panels/ScopePanel.swift"; ok=0; }
  grep -qE '^VIOLATION \[2 [^]]*\] Sources/Aitmproxy/Panels/ScriptsPanel\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 2 did not name the planted s.restoreSystemProxy reference in Panels/ScriptsPanel.swift"; ok=0; }
  if [ "$ok" -eq 1 ]; then
    echo "SELF-CHECK PASS: rules 1–4 each caught their planted violation"
    exit 0
  fi
  exit 1
fi

mac_dir=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
cd "$mac_dir" || { echo "FAIL check-sysproxy-operator-only: cannot enter $mac_dir"; exit 1; }

# Product code only. Tests are not an agent-reachable surface.
scan_roots=(Sources)
[ -d Extension ] && scan_roots+=(Extension)
for root in "${scan_roots[@]}"; do
  [ -d "$root" ] || { echo "FAIL check-sysproxy-operator-only: $mac_dir/$root is not a directory"; exit 1; }
done

sysproxy=Sources/Aitmproxy/Session+SystemProxy.swift
connection_summary=Sources/AitmproxyKit/ConnectionSummary.swift
settings_view=Sources/Aitmproxy/SettingsView.swift
status_panel=Sources/Aitmproxy/Panels/StatusPanel.swift
setup_sheet=Sources/Aitmproxy/Shell/SetupSheet.swift
# The Flows route banner / empty-state button (traffic-route spec D4/D5): routes the shared
# model's .setSystemProxy / .unsetSystemProxy actions to the two Session calls and nothing else.
route_banner=Sources/Aitmproxy/Shell/RouteBanner.swift
app_swift=Sources/Aitmproxy/App.swift
# Rule 4: the launch preference's writers, readers and definition.
prefs=Sources/AitmproxyKit/SystemProxyPreferences.swift
embedded_core=Sources/Aitmproxy/Bus/EmbeddedCore.swift
embedded_core_controller=Sources/Aitmproxy/Bus/EmbeddedCoreController.swift
ca_trust=Sources/Aitmproxy/Session+CATrust.swift

violations=0
checked=0

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
  # Code only: a `//` comment must not keep an allow-list entry alive.
  if ! sed -E 's#//.*$##' "$2" | grep -qE -e "$3"; then
    flag "$1" "$2: no longer contains $4; the allow-list is stale or this tripwire has gone blind. Re-read the code and update this script"
  fi
}

# expect_count RULE FILE REGEX N WHAT
# FILE must match REGEX on exactly N lines.
expect_count() {
  local found
  if [ ! -f "$2" ]; then
    flag "$1" "$2: not found, but the allow-list names it"
    return
  fi
  found=$(grep -cE -e "$3" "$2" || true)
  if [ "${found:-0}" -ne "$4" ]; then
    flag "$1" "$2: expected exactly $4 line(s) matching $5, found ${found:-0}"
  fi
}

# deny RULE REGEX FILE...
# None of the FILEs may match REGEX. A file that does not exist is a violation.
deny() {
  local rule=$1 regex=$2 f hit line text
  shift 2
  for f in "$@"; do
    if [ ! -f "$f" ]; then
      flag "$rule" "$f: not found; the surface moved, so move its rule to the file that replaced it"
      continue
    fi
    checked=$((checked + 1))
    while IFS= read -r hit; do
      line=${hit%%:*}
      text=${hit#*:}
      text=${text#"${text%%[![:space:]]*}"}
      flag "$rule" "$f:$line: $text"
    done < <(grep -nE -e "$regex" "$f")
  done
}

# ---- 1. the verbs' quoted literals: Session+SystemProxy.swift only -------------------
verb_re='"proxy\.system\.(set|unset)"'
scan "1 proxy.system.set/unset literal" "$verb_re" "$sysproxy"
expect "1 proxy.system.set/unset literal" "$sysproxy" '"proxy\.system\.set"' 'the "proxy.system.set" literal'
expect "1 proxy.system.set/unset literal" "$sysproxy" '"proxy\.system\.unset"' 'the "proxy.system.unset" literal'

# ---- 2. setSystemProxy()/restoreSystemProxy() calls: the operator surfaces only -----
rule2="2 setSystemProxy()/restoreSystemProxy() call"
call_re='\.(setSystemProxy|restoreSystemProxy)[[:space:]]*\('
scan "$rule2" "$call_re" "$settings_view" "$status_panel" "$setup_sheet" "$route_banner" "$app_swift"
# The expects pin the CALL shape (`session.setSystemProxy()`), not the token: every surface's doc
# comment also names `Session.setSystemProxy()`, and a comment must not keep an entry alive.
expect "$rule2" "$settings_view" 'session\.setSystemProxy\(\)' 'the live toggle'"'"'s session.setSystemProxy() call'
expect "$rule2" "$settings_view" 'session\.restoreSystemProxy\(\)' 'the live toggle'"'"'s session.restoreSystemProxy() call'
expect "$rule2" "$status_panel" 'session\.setSystemProxy\(\)' 'the Status page'"'"'s .setSystemProxy action'"'"'s session.setSystemProxy() call'
expect "$rule2" "$status_panel" 'session\.restoreSystemProxy\(\)' 'the Status page'"'"'s .unsetSystemProxy action'"'"'s session.restoreSystemProxy() call'
expect "$rule2" "$setup_sheet" 'session\.setSystemProxy\(\)' 'the sheet'"'"'s Set as System Proxy button'"'"'s session.setSystemProxy() call'
expect "$rule2" "$route_banner" 'session\.setSystemProxy\(\)' 'the Flows route banner / empty-state session.setSystemProxy() call'
expect "$rule2" "$route_banner" 'session\.restoreSystemProxy\(\)' 'the Flows route banner session.restoreSystemProxy() call'
expect "$rule2" "$app_swift" 'session\.setSystemProxy\(\)' 'the Proxy menu item'"'"'s session.setSystemProxy() call'
expect "$rule2" "$app_swift" 'session\.restoreSystemProxy\(\)' 'the Proxy menu item'"'"'s session.restoreSystemProxy() call'
# Undotted: a call from inside an `extension Session` (self is implicit) or a second definition.
undotted_re='(^|[^A-Za-z0-9_.])(setSystemProxy|restoreSystemProxy)[[:space:]]*\('
scan "$rule2" "$undotted_re" "$settings_view" "$status_panel" "$setup_sheet" "$route_banner" "$app_swift" "$sysproxy"
# The definitions live in the one file, and they are its only undotted matches.
expect "$rule2" "$sysproxy" 'func setSystemProxy\(\)' 'func setSystemProxy()'
expect "$rule2" "$sysproxy" 'func restoreSystemProxy\(\)' 'func restoreSystemProxy()'
expect_count "$rule2" "$sysproxy" "$undotted_re" 2 'an undotted setSystemProxy(/restoreSystemProxy( (the two func definitions)'
# Bare: the method as a value, `session.setSystemProxy` / `self.restoreSystemProxy` /
# `Session.setSystemProxy` with no `(` after it. The receiver is required: `.setSystemProxy`
# alone is also the ConnectionAction case.
# Any lowercase receiver (a variable: `session`, `self`, `s`) or the type `Session`; type-named
# receivers such as `ConnectionAction.setSystemProxy` (the action case) are not member references.
bare_re='(^|[^A-Za-z0-9_.])(Session|[a-z][A-Za-z0-9_]*)\.(setSystemProxy|restoreSystemProxy)([^A-Za-z0-9_(]|$)'
scan "$rule2" "$bare_re" "$settings_view" "$status_panel" "$setup_sheet" "$route_banner" "$app_swift" "$sysproxy"
# Bare undotted: the method handed on as a value from inside an `extension Session`
# (`{ setSystemProxy }`). The leading-dot form is the ConnectionAction case and is excluded;
# the Kit's `case setSystemProxy, unsetSystemProxy` declaration is the one allowed undotted match
# outside the call path.
bare_undotted_re='(^|[^A-Za-z0-9_.])(setSystemProxy|restoreSystemProxy)([^A-Za-z0-9_(]|$)'
scan "$rule2" "$bare_undotted_re" "$settings_view" "$status_panel" "$setup_sheet" "$route_banner" "$app_swift" "$sysproxy" "$connection_summary"
expect_count "$rule2" "$connection_summary" "$bare_undotted_re" 1 'the ConnectionAction case declaration'

# ---- 3. the agent-reachable surfaces reference none of it ----------------------------
# The self-tests drive Session without an operator, so they are held to the same rule as
# BusService.swift. The pattern needs a receiver or a call so the ConnectionAction case name
# (`.setSystemProxy`) and the palette's `Session.isSystemProxyVerb(` stay legal.
deny "3 agent-reachable surface" \
  '"proxy\.system\.(set|unset)"|[Ss]ession\.(setSystemProxy|restoreSystemProxy)|self\.(setSystemProxy|restoreSystemProxy)|[^.A-Za-z0-9_](setSystemProxy|restoreSystemProxy)[[:space:]]*\(' \
  Sources/Aitmproxy/Bus/BusService.swift \
  Sources/AitmproxyKit/CommandMap.swift \
  Sources/Aitmproxy/Shell/CommandPalette.swift \
  Sources/Aitmproxy/Session+Palette.swift \
  Sources/Aitmproxy/Session+Verbs.swift \
  Sources/Aitmproxy/Panels/AgentPanel.swift \
  Sources/Aitmproxy/SelfTest.swift \
  Sources/Aitmproxy/SelfTest+Live.swift

expect "3 agent-reachable surface" Sources/Aitmproxy/Panels/AgentPanel.swift 'Session\.isSystemProxyVerb\(' 'the Approve guard Session.isSystemProxyVerb('
expect "3 agent-reachable surface" Sources/Aitmproxy/Session+Palette.swift 'isSystemProxyVerb\(' 'the palette filter isSystemProxyVerb('

# ---- 4. the launch preference: operator-written, spawn-read ---------------------------
rule4="4 systemProxy.auto preference"
autokey_re='SystemProxyPreferences\.autoKey'
scan "$rule4" "$autokey_re" "$settings_view" "$setup_sheet" "$embedded_core" "$embedded_core_controller" "$ca_trust"
expect "$rule4" "$settings_view" '@AppStorage\([[:space:]]*SystemProxyPreferences\.autoKey' 'the "Set system proxy at launch" @AppStorage binding'
expect "$rule4" "$setup_sheet" '\.set\(true,[[:space:]]*forKey:[[:space:]]*SystemProxyPreferences\.autoKey\)' 'the sheet'"'"'s set(true, forKey: autoKey) write'
expect "$rule4" "$embedded_core" 'forKey:[[:space:]]*SystemProxyPreferences\.autoKey' 'the spawn'"'"'s autoKey read'
expect "$rule4" "$embedded_core_controller" 'forKey:[[:space:]]*SystemProxyPreferences\.autoKey' 'the applied-snapshot autoKey read'
expect "$rule4" "$ca_trust" 'bool\(forKey:[[:space:]]*SystemProxyPreferences\.autoKey\)' 'setupSheetDue'"'"'s autoKey read'
# CoreConnection.swift documents `appliedSystemProxyAuto` by naming the key; it neither reads
# nor writes it. Pinned to exactly one line, and that line a `///` comment.
# The raw key is spelled once, where it is defined.
scan "$rule4" '"systemProxy\.auto"' "$prefs"
expect "$rule4" "$prefs" 'static let autoKey = "systemProxy\.auto"' 'the autoKey definition'

if [ "$violations" -ne 0 ]; then
  echo "FAIL check-sysproxy-operator-only: $violations violation(s). The system proxy has one call path, reached by the operator only."
  exit 1
fi
echo "PASS check-sysproxy-operator-only ($checked agent-reachable surfaces checked)"
