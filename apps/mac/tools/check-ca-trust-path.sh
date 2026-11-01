#!/usr/bin/env bash
# The one-call-path tripwire for CA trust in the macOS app (spec
# 2026-10-31-system-proxy-automation-design §D17.10 and D17.1, SP-AC34).
#
# Trusting the CA changes the OS trust store. The app does it through ONE path,
# `Session.trustCA()` / `untrustCA()` in Sources/Aitmproxy/Session+CATrust.swift — the
# only file that spells the bus verbs "ca.install" / "ca.uninstall" — reached from the
# operator's surfaces only: the CA panel, the first-run sheet, the Status page's CA row and
# step, and the Proxy menu. The scope is always the user store (`.string("user")`, rendered
# in the Kit's CATrustFacts.scopeArgs); the literal "system" never enters the call path, so
# the app can never ask for /Library/Keychains/System.keychain. This script reads the Swift
# source and fails closed.
#
# Usage: tools/check-ca-trust-path.sh [mac-dir]   (default: the apps/mac that holds this script)
#        tools/check-ca-trust-path.sh --self-check   plants one violation per rule (two for rule 2)
#                                                    in a copy and expects each rule's tag on its file
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
#   1. The quoted literals "ca.install" and "ca.uninstall" appear in Session+CATrust.swift
#      only. The fixture tool list (AitmproxyKit/Fixtures+Tools.swift) and the fixture
#      activity log (AitmproxyKit/Fixtures+Agent.swift) still name `ca.install` as DATA
#      (a tool descriptor, a pending agent entry); both are allowed by file, without an
#      expect, until the fake-data-removal PR deletes them.
#   2. `.trustCA(` / `.untrustCA(` are called from Panels/CAPanel.swift,
#      Shell/SetupSheet.swift, Panels/StatusPanel.swift and App.swift only (each with an
#      expect). An UNDOTTED `trustCA(` / `untrustCA(` (a call from inside an `extension
#      Session`, or a second definition) may appear in those four files and in
#      Session+CATrust.swift only, where the undotted matches are exactly the two `func`
#      definitions (pinned by count). A BARE member reference — `session.trustCA`,
#      `self.untrustCA`, `Session.trustCA` with no `(` after it, the method handed on as a
#      value — may appear in those five files only. The receiver is required because
#      `.trustCA` is also the `ConnectionAction` case every surface names.
#   3. The scope: AitmproxyKit/CATrustFacts.swift renders `.string("user")` (expect);
#      Session+CATrust.swift calls `scopeArgs(platform:` (expect) and never spells "system"
#      (deny); no file under the scan roots spells `.string("system")`.
#      (SP-AC34 words rule 3 as `.string("user")` in Session+CATrust.swift; the CA-trust
#      plan record moved the scope rendering into the Kit's CATrustFacts.scopeArgs so the
#      Kit test can pin it, and this rule follows the literal to its one home.)
#   4. The agent-reachable surfaces of check-capture-operator-only.sh's rule 4, plus the
#      self-test, the snapshot scenes and the fixture session, match none of
#      ca.install | ca.uninstall | trustCA | untrustCA. CommandMap.swift carries the menu
#      TITLE "Trust the aitmproxy CA" only, which the pattern does not match;
#      `Session.isCATrustVerb` (the palette's and the Agent log's guard) does not match it
#      either. The two fixture files of rule 1 are allowed here for the same reason, by
#      file, and skipped once deleted.
set -u
set -o pipefail
export LC_ALL=C

self=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")

if [ "${1:-}" = "--self-check" ]; then
  src=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  work=$(mktemp -d "${TMPDIR:-/tmp}/check-ca-trust-path.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  cp -R "$src/Sources" "$work/Sources"
  [ -d "$src/Extension" ] && cp -R "$src/Extension" "$work/Extension"
  if ! bash "$self" "$work" >/dev/null; then
    echo "SELF-CHECK FAIL: the clean copy does not pass; fix the tree first"
    exit 1
  fi
  # One plant per rule, two for rule 2: a quoted verb (rule 1), an undotted call from inside an
  # extension Session outside the allow-list and a bare member reference outside it (rule 2),
  # the "system" scope literal in the call path (rule 3), a bare token on an agent-reachable
  # surface (rule 4).
  printf '\nlet _ = "ca.install"\n' >> "$work/Sources/Aitmproxy/Session+Verbs.swift"
  printf '\nextension Session {\n    func plantedTrust() async { await trustCA() }\n}\n' >> "$work/Sources/Aitmproxy/Session+Connection.swift"
  printf '\nextension Session {\n    var plantedTrustRef: () async -> Void { self.trustCA }\n}\n' >> "$work/Sources/Aitmproxy/Panels/ConfigPanel.swift"
  printf '\nlet _ = JSONValue.string("system")\n' >> "$work/Sources/Aitmproxy/Session+CATrust.swift"
  printf '\n// planted: trustCA\n' >> "$work/Sources/Aitmproxy/Panels/AgentPanel.swift"
  out=$(bash "$self" "$work" 2>&1); rc=$?
  printf '%s\n' "$out"
  ok=1
  if [ "$rc" -ne 1 ]; then echo "SELF-CHECK FAIL: expected exit 1, got exit $rc"; ok=0; fi
  grep -qE '^VIOLATION \[1 [^]]*\] Sources/Aitmproxy/Session\+Verbs\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 1 did not name the planted \"ca.install\" in Session+Verbs.swift"; ok=0; }
  grep -qE '^VIOLATION \[2 [^]]*\] Sources/Aitmproxy/Session\+Connection\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 2 did not name the planted undotted trustCA() in Session+Connection.swift"; ok=0; }
  grep -qE '^VIOLATION \[2 [^]]*\] Sources/Aitmproxy/Panels/ConfigPanel\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 2 did not name the planted bare self.trustCA reference in Panels/ConfigPanel.swift"; ok=0; }
  grep -qE '^VIOLATION \[3 [^]]*\] Sources/Aitmproxy/Session\+CATrust\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 3 did not name the planted .string(\"system\") in Session+CATrust.swift"; ok=0; }
  grep -qE '^VIOLATION \[4 [^]]*\] Sources/Aitmproxy/Panels/AgentPanel\.swift:' <<<"$out" \
    || { echo "SELF-CHECK FAIL: rule 4 did not name the planted trustCA token in Panels/AgentPanel.swift"; ok=0; }
  if [ "$ok" -eq 1 ]; then
    echo "SELF-CHECK PASS: rules 1–4 each caught their planted violation"
    exit 0
  fi
  exit 1
fi

mac_dir=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
cd "$mac_dir" || { echo "FAIL check-ca-trust-path: cannot enter $mac_dir"; exit 1; }

# Product code only. Tests are not an agent-reachable surface.
scan_roots=(Sources)
[ -d Extension ] && scan_roots+=(Extension)
for root in "${scan_roots[@]}"; do
  [ -d "$root" ] || { echo "FAIL check-ca-trust-path: $mac_dir/$root is not a directory"; exit 1; }
done

ca_trust=Sources/Aitmproxy/Session+CATrust.swift
ca_facts=Sources/AitmproxyKit/CATrustFacts.swift
ca_panel=Sources/Aitmproxy/Panels/CAPanel.swift
setup_sheet=Sources/Aitmproxy/Shell/SetupSheet.swift
status_panel=Sources/Aitmproxy/Panels/StatusPanel.swift
app_swift=Sources/Aitmproxy/App.swift
# Fixture DATA that still names the verbs (rule 1 note); deleted by the fake-data-removal PR.
fixture_tools=Sources/AitmproxyKit/Fixtures+Tools.swift
fixture_agent=Sources/AitmproxyKit/Fixtures+Agent.swift

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
  if ! grep -qE -e "$3" "$2"; then
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

# deny_present RULE REGEX FILE...
# `deny` for fixture DATA scheduled for deletion: a missing file is skipped with a note.
deny_present() {
  local rule=$1 regex=$2 f present=()
  shift 2
  for f in "$@"; do
    if [ -f "$f" ]; then present+=("$f"); else echo "NOTE: fixture file gone, skipped: $f" >&2; fi
  done
  [ "${#present[@]}" -gt 0 ] && deny "$rule" "$regex" "${present[@]}"
}

# ---- 1. the verbs' quoted literals: Session+CATrust.swift only -----------------------
verb_re='"ca\.(install|uninstall)"'
scan "1 ca.install/ca.uninstall literal" "$verb_re" "$ca_trust" "$fixture_tools" "$fixture_agent"
expect "1 ca.install/ca.uninstall literal" "$ca_trust" '"ca\.install"' 'the "ca.install" literal'
expect "1 ca.install/ca.uninstall literal" "$ca_trust" '"ca\.uninstall"' 'the "ca.uninstall" literal'

# ---- 2. trustCA()/untrustCA() calls: the operator surfaces only ----------------------
call_re='\.(un)?trustCA[[:space:]]*\('
scan "2 trustCA()/untrustCA() call" "$call_re" "$ca_panel" "$setup_sheet" "$status_panel" "$app_swift"
expect "2 trustCA()/untrustCA() call" "$ca_panel" '\.trustCA[[:space:]]*\(' 'the Install… call to session.trustCA()'
expect "2 trustCA()/untrustCA() call" "$ca_panel" '\.untrustCA[[:space:]]*\(' 'the Uninstall… call to session.untrustCA()'
expect "2 trustCA()/untrustCA() call" "$setup_sheet" '\.trustCA[[:space:]]*\(' 'the sheet'"'"'s Trust the aitmproxy CA button'
expect "2 trustCA()/untrustCA() call" "$status_panel" '\.trustCA[[:space:]]*\(' 'the Status page'"'"'s .trustCA action'
expect "2 trustCA()/untrustCA() call" "$app_swift" '\.trustCA[[:space:]]*\(' 'the Proxy menu item'
# Undotted: a call from inside an `extension Session` (self is implicit) or a second definition.
undotted_re='(^|[^A-Za-z0-9_.])(un)?trustCA[[:space:]]*\('
scan "2 trustCA()/untrustCA() call" "$undotted_re" "$ca_panel" "$setup_sheet" "$status_panel" "$app_swift" "$ca_trust"
# The definitions live in the one file, and they are its only undotted matches.
expect "2 trustCA()/untrustCA() call" "$ca_trust" 'func trustCA\(\)' 'func trustCA()'
expect "2 trustCA()/untrustCA() call" "$ca_trust" 'func untrustCA\(\)' 'func untrustCA()'
expect_count "2 trustCA()/untrustCA() call" "$ca_trust" "$undotted_re" 2 'an undotted trustCA(/untrustCA( (the two func definitions)'
# Bare: the method as a value, `session.trustCA` / `self.untrustCA` / `Session.trustCA` with no
# `(` after it. The receiver is required: `.trustCA` alone is also the ConnectionAction case.
bare_re='([Ss]ession|self)\.(un)?trustCA([^A-Za-z0-9_(]|$)'
scan "2 trustCA()/untrustCA() call" "$bare_re" "$ca_panel" "$setup_sheet" "$status_panel" "$app_swift" "$ca_trust"

# ---- 3. the scope is the user store, never "system" ----------------------------------
expect "3 user scope" "$ca_facts" '\.string\("user"\)' 'the .string("user") scope'
expect "3 user scope" "$ca_trust" 'scopeArgs\(platform:' 'the scopeArgs(platform:) call'
deny "3 user scope" '"system"' "$ca_trust"
scan "3 user scope" '\.string\("system"\)'

# ---- 4. the agent-reachable surfaces reference none of it ----------------------------
# FixtureBus.swift is the bus's stand-in in fixture, snapshot and self-test runs (the test
# adapter behind Session.commandRunner), so it is held to the same rule as BusService.swift;
# the self-test, the snapshot scenes and the fixture session drive Session without an operator.
deny "4 agent-reachable surface" 'ca\.install|ca\.uninstall|trustCA|untrustCA' \
  Sources/Aitmproxy/Bus/BusService.swift \
  Sources/Aitmproxy/Bus/FixtureBus.swift \
  Sources/AitmproxyKit/CommandMap.swift \
  Sources/Aitmproxy/Shell/CommandPalette.swift \
  Sources/Aitmproxy/Session+Palette.swift \
  Sources/Aitmproxy/Session+Verbs.swift \
  Sources/Aitmproxy/Panels/AgentPanel.swift \
  Sources/Aitmproxy/SelfTest.swift \
  Sources/Aitmproxy/SelfTest+Live.swift \
  Sources/Aitmproxy/SnapshotScenes.swift \
  Sources/Aitmproxy/Session+Fixtures.swift
# The two fixture DATA files of rule 1: not a call path, but they must not grow one either.
deny_present "4 agent-reachable surface" 'trustCA|untrustCA|runCommand|commandRunner' "$fixture_tools" "$fixture_agent"

if [ "$violations" -ne 0 ]; then
  echo "FAIL check-ca-trust-path: $violations violation(s). CA trust has one call path and one scope."
  exit 1
fi
echo "PASS check-ca-trust-path ($checked agent-reachable surfaces checked)"
