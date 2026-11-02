#!/bin/zsh
# The live half of the L4 parity gate for the macOS app (spec
# docs/superpowers/specs/2026-10-31-l4-parity-fixes-design.md §6, L4PAR-AC25–AC31, AC33; plan
# docs/superpowers/plans/2026-10-31-l4-parity-fixes-plan.md, unit (d) task M9 and amendments 3, 7, 8).
#
# The rule: no fixture, snapshot, self-test or seeded-store run counts as evidence. This script
# drives the REAL dev bundle, connected to a REAL core (the unit (d) rig under $RIG, bus 31431)
# carrying REAL proxied HTTP traffic, with real menu clicks, key strokes and mouse clicks, and
# reads the result back three ways: screenshots of the live window (tools/winshot.swift), the
# window's accessibility tree (tools/axdump.swift, native AX, one TSV line per element), and the
# rig core's own audit ring over a second operator bus connection (tools/l4-rig-bus.py). There is
# no fixture mode and none may be added; the tripwire half of the gate is tools/check-l4-live.sh.
#
# Usage: tools/cua-l4-live.sh [--dark] [--add | --agent]
#   --dark   launch with -AppleInterfaceStyle Dark (default: -NSRequiresAquaSystemAppearance 1)
#   --add    also run the AC30 operator add through the real form and confirm sheet (needs a
#            core with the operator-confirmed l4.scope.add, unit (a')); removed over the bus after
#   --agent  launch WITHOUT the operator token (the bundle connects as the agent), open the Scope
#            page and assert by AX that the operator-only hint is shown and no add form or L4 Add
#            button exists (AC33, plan amendment 7); skips the Flows, add and Pinned steps
#   DRY_RUN=1  print every command it would run (the token is never shown) and exit 0
# Inputs by environment (defaults in parentheses):
#   BUNDLE  the snap-dev bundle            (/tmp/Aitmproxy-dev-l4par.app; executable from CFBundleExecutable)
#   RIG     the rig directory              (/tmp/claude/l4d: config.yaml, op.token 0600) — must exist
#   BUS     the rig core's bus host:port   (127.0.0.1:31431)
#   PROXY   the rig core's proxy           (127.0.0.1:31180)
#   TARGET  the real HTTP target behind it (http://127.0.0.1:9199/)
#   WATCH   seconds of polling to count    (60)
#   TAG     this run's tag, [A-Za-z0-9._-] (cua-<timestamp>; also the kept defaults suite's suffix)
#   OUT     evidence directory             ($RIG/evidence/$TAG)
# The app runs with APP_LIVE=1, APP_LIVE_OPERATOR_TOKEN read from $RIG/op.token into the
# environment (never printed: no set -x, no echo of the environment), a fresh APP_STORE (mode
# 700) under $RIG and a fresh APP_DEFAULTS_SUITE, against the rig as its external core
# (AITM_CONFIG). Only the pid this script launched is stopped at the end; never a pkill.
# Controls are located by accessibility (identifier, label, placeholder) and clicked at their
# centre. Known AX shapes of this app: sidebar rows are single AXButtons described
# "<title>, <count>" (no child texts); Scope rows are one combined element each (label
# "<cidr> <ports> <if> <dir> <cap>", value the source). The pixel points of the --add walk
# ((336,401), (472,401), (1811,436) in the 1848×1126
# window the dev bundle opens at) are the fallback when a label is not found, and the script
# warns when the window size differs. Runs from any cwd; cannot run inside the Claude sandbox
# (no Apple Events, no AX, no loopback connects): run it from the Terminal.
set -u
umask 077
unsetopt bg_nice
zmodload zsh/datetime
export LANG=${LANG:-en_US.UTF-8}
here=${0:A:h:h}

DARK=0; ADD=0; AGENT=0
for a in "$@"; do
  case $a in
    --dark) DARK=1 ;;
    --add) ADD=1 ;;
    --agent) AGENT=1 ;;
    -h|--help) sed -n '2,42p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a (usage: cua-l4-live.sh [--dark] [--add | --agent])"; exit 2 ;;
  esac
done
(( ADD && AGENT )) && { echo "--add needs the operator; it cannot be combined with --agent"; exit 2; }
role=operator; (( AGENT )) && role=agent

DRY=${DRY_RUN:-0}
BUNDLE=${BUNDLE:-/tmp/Aitmproxy-dev-l4par.app}
RIG=${RIG:-/tmp/claude/l4d}
BUS=${BUS:-127.0.0.1:31431}
PROXY=${PROXY:-127.0.0.1:31180}
TARGET=${TARGET:-http://127.0.0.1:9199/}
WATCH=${WATCH:-60}
TAG=${TAG:-cua-$(date +%Y%m%d-%H%M%S)}
# TAG names a directory we rm -rf and a defaults suite; RIG is where that rm -rf happens.
[[ $TAG =~ '^[A-Za-z0-9._-]+$' ]] || { echo "TAG must match [A-Za-z0-9._-]+ (got '$TAG')"; exit 2; }
[[ -d $RIG && -f $RIG/config.yaml ]] || { echo "RIG must be an existing directory holding config.yaml (got '$RIG')"; exit 2; }
OUT=${OUT:-$RIG/evidence/$TAG}
store=$RIG/store-$TAG
suite=com.mrbrutti.aitmproxy.$TAG
mode=light; style_args=(-NSRequiresAquaSystemAppearance 1)
(( DARK )) && { mode=dark; style_args=(-AppleInterfaceStyle Dark); }
busctl=("$here/tools/l4-rig-bus.py")

# The executable name comes from the bundle's own Info.plist (a tagged dev build is Aitmproxy-<tag>).
exe_name=""
[[ -f $BUNDLE/Contents/Info.plist ]] && exe_name=$(plutil -extract CFBundleExecutable raw "$BUNDLE/Contents/Info.plist" 2>/dev/null)
if [[ -z $exe_name ]]; then
  (( DRY )) || { echo "no bundle at $BUNDLE (build it: DEV_TAG=l4par apps/mac/tools/snap-dev.sh)"; exit 1; }
  exe_name="Aitmproxy-l4par"; echo "dry: no bundle at $BUNDLE, assuming executable $exe_name"
fi
exe=$BUNDLE/Contents/MacOS/$exe_name
if (( ! DRY )); then
  [[ -x $exe ]] || { echo "no executable at $exe"; exit 1; }
  [[ -r $RIG/op.token ]] || { echo "no operator token at $RIG/op.token (rig down? see $RIG/up.sh)"; exit 1; }
  [[ -f $here/tools/axdump.swift && -f $here/tools/winshot.swift && -f $here/tools/cgclick.swift && -f ${busctl[1]} ]] \
    || { echo "tools missing under $here/tools (axdump.swift, winshot.swift, cgclick.swift, l4-rig-bus.py)"; exit 1; }
fi

# ---- helpers ---------------------------------------------------------------------------------
results=()        # the summary lines
nfail=0
# The L4 add form's shape on the Scope page: set by scope_page, read by agent_ac33.
form_fields=0; add_en=0; add_all=0; hdr_y=none
ok()   { results+=("$1"); echo "$1"; }
fail() { results+=("$1"); echo "$1"; nfail=$(( nfail + 1 )); }
skip() { results+=("$1"); echo "$1"; }
# run <cmd...>: print and skip in a dry run, else execute.
run() { if (( DRY )); then print -r -- "+ $*"; else "$@"; fi }
# bus <subcommand...>: the in-repo rig bus helper, pointed at this rig.
bus() { run env L4_RIG="$RIG" L4_BUS="$BUS" python3 "${busctl[@]}" "$@"; }
# ax: AppleScript on stdin to osascript; a dry run prints the script (to stderr, so a captured
# result stays empty) and returns nothing. Used only for frontmost, the menu click and keystrokes.
ax() {
  local script; script=$(cat)
  if (( DRY )); then
    { print -r -- "+ osascript <<'AppleScript'"; print -r -- "$script" | sed 's/^/    /'; print -r -- "  AppleScript"; } >&2
    return 0
  fi
  osascript <<< "$script" 2>&1
}
# with_app <statements...>: the statements inside the System Events preamble that targets our pid
# (as `p`) and brings it frontmost first.
with_app() {
  ax <<AS
tell application "System Events"
  set p to first process whose unix id is $pid
  set frontmost of p to true
  delay 0.3
  $*
end tell
AS
}
focus()  { with_app ""; run sleep 0.4; }
typeit() { with_app "keystroke \"$1\""; run sleep 0.4; }
shot()   { run swift "$here/tools/winshot.swift" "$pid" "$OUT/$1.png" && echo "shot: $OUT/$1.png"; }
# click_xy <dx> <dy>: a real click at a window-relative point, twice 0.9 s apart (the page opens
# calm; the first click only focuses the field). The pixel fallback of the --add walk.
click_xy() {
  focus
  run swift "$here/tools/cgclick.swift" $(( wx + $1 )) $(( wy + $2 )); run sleep 0.9
  run swift "$here/tools/cgclick.swift" $(( wx + $1 )) $(( wy + $2 )); run sleep 0.5
}
# ax_dump <name> [--sheet]: the native AX tree of our window (or its sheet) into $OUT/ax-<name>.txt
# — ROLE TITLE VALUE DESC PLACEHOLDER ENABLED X Y W H IDENTIFIER, tab-separated — and sets
# $dumpfile to it. Prints the element count and the dump's elapsed seconds.
dumpfile=/dev/null
ax_dump() {
  local name=$1; shift
  if (( DRY )); then run swift "$here/tools/axdump.swift" "$pid" "$@"; dumpfile=/dev/null; return 0; fi
  local t_start=$EPOCHREALTIME
  dumpfile=$OUT/ax-$name.txt
  swift "$here/tools/axdump.swift" "$pid" "$@" > "$dumpfile" 2> "$OUT/ax-$name.err" || { echo "axdump failed: $(<"$OUT/ax-$name.err")"; : > "$dumpfile"; }
  printf 'ax-%s.txt: %d elements in %.1f s · %s\n' "$name" "$(grep -c . "$dumpfile")" $(( EPOCHREALTIME - t_start )) "$(grep '^window:' "$OUT/ax-$name.err" || echo 'window: not reported')"
}
# mouse_away: park the pointer over the empty lower part of the flow list (window-relative), so
# no tooltip is up when the tree is read; a bare move, no click.
mouse_away() {
  run swift -e "import Cocoa; CGWarpMouseCursorPosition(CGPoint(x: $(( wx + ww / 2 )), y: $(( wy + wh - 120 ))))"
  run sleep 1.2
}
# Column helpers over a dump (fields: 1 role 2 title 3 value 4 desc 5 placeholder 6 enabled 7 x 8 y 9 w 10 h 11 id).
# centre_of <label>: "cx cy" of the first element whose identifier, title, value, description or
# placeholder is exactly <label>.
centre_of() {
  awk -F'\t' -v L="$1" '($11 == L || $2 == L || $3 == L || $4 == L || $5 == L) && $9 != "" { printf "%d %d\n", $7 + $9 / 2, $8 + $10 / 2; exit }' "$dumpfile"
}
# click_label <label> [twice]: locate by AX, click by position — a real click at the element's
# centre (global points, the space cgclick posts in). Returns 1 when nothing carries the label.
click_label() {
  local c; c=$(centre_of "$1")
  if [[ -z $c ]]; then
    (( DRY )) && { print -r -- "+ swift $here/tools/cgclick.swift <centre of the element labelled '$1'>"; run sleep 1.5; return 0; }
    echo "no element labelled '$1' in $dumpfile"; return 1
  fi
  focus
  run swift "$here/tools/cgclick.swift" ${=c}
  if [[ ${2:-} == twice ]]; then run sleep 0.9; run swift "$here/tools/cgclick.swift" ${=c}; fi
  echo "clicked '$1' at $c"
  run sleep 1.5
}
# The static texts with the L4 availability lines.
l4_lines() { awk -F'\t' '$1 == "AXStaticText" && ($3 ~ /unavailable/ || $3 ~ /Reading L4/) { print $3 }' "$dumpfile"; }
# The sidebar's rows are single AXButtons described "<title>, <count>" ("Pinned, 0", "Flows, 72")
# with no child texts (seen live in ax-scope.txt). pinned_label prints that exact description,
# the handle click_label needs; pinned_count the count after the comma.
pinned_label() { awk -F'\t' '$1 == "AXButton" && $4 ~ /^Pinned(, |$)/ { print $4; exit }' "$dumpfile"; }
pinned_count() { pinned_label | awk '{ sub(/^Pinned, ?/, ""); print }'; }
# The L4 add form's fields (placeholder `cidr`, label "CIDR to add to L4 scope", or any field
# named cidr) and the "Add…" buttons whose centre sits below the "L4 SCOPE" header (the HTTP Add
# sits above it) — the two shapes the operator-only gate removes. Live shapes (ax-scope.txt):
# the header is an AXHeading whose text is its description; buttons carry "Add" / "Add, ⌘⏎" in
# their description with an empty title; the L4 Add is identified l4-scope-add.
l4_form_fields() {
  awk -F'\t' '$5 == "cidr" || $4 == "CIDR to add to L4 scope" || $2 == "cidr" || $3 == "cidr" { n++ } END { print n + 0 }' "$dumpfile"
}
l4_add_buttons() {  # prints "<enabled below header> <all below header> <header y|none>"
  awk -F'\t' '
    { n++; line[n] = $0 }
    ($1 == "AXHeading" || $1 == "AXStaticText") && ($3 == "L4 SCOPE" || $4 == "L4 SCOPE") && !found { hy = $8 + $10 / 2; found = 1 }
    END {
      if (!found) { print "0 0 none"; exit }
      en = 0; all = 0
      for (i = 1; i <= n; i++) {
        split(line[i], f, "\t")
        if (f[1] != "AXButton" || (f[2] !~ /^Add/ && f[4] !~ /^Add/ && f[11] != "l4-scope-add")) continue
        cy = f[8] + f[10] / 2
        if (cy > hy) { all++; if (f[6] == "true") en++ }
      }
      print en, all, hy
    }' "$dumpfile"
}
count_in() { awk -v n="$2" '$1 == n { print $2; exit }' "$1" | grep . || echo 0; }
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
stopped=0
stop_app() {
  (( stopped )) && return; stopped=1
  if (( DRY )); then print -r -- "+ kill \$pid"; return; fi
  if [[ -n ${pid:-} ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid"; sleep 1
    kill -0 "$pid" 2>/dev/null && echo "pid $pid still running after SIGTERM" || echo "stopped $pid"
  fi
}
trap stop_app EXIT INT TERM

# ---- steps -----------------------------------------------------------------------------------
launch_app() {
  echo "cua-l4-live · $mode · role $role · bundle $exe · rig $RIG · bus $BUS · tag $TAG"
  echo "evidence → $OUT · store $store · suite $suite"
  if (( ! DRY )); then
    mkdir -p "$OUT"; rm -rf "$store"; mkdir -m 700 "$store"
  fi
  t0=$(now_ms)
  echo "t0 (ms, before launch): $t0"
  # The operator token reaches the app only through its environment; --agent leaves it out, so
  # the bundle connects with the config's agent token (the harness suite is fresh and carries none).
  local token_env="APP_LIVE_OPERATOR_TOKEN=<read from $RIG/op.token, not shown>"
  (( AGENT )) && token_env="(no APP_LIVE_OPERATOR_TOKEN: agent role)"
  if (( DRY )); then
    print -r -- "+ APP_LIVE=1 $token_env APP_STORE=$store APP_DEFAULTS_SUITE=$suite AITM_CONFIG=$RIG/config.yaml $exe $style_args > $OUT/app.log 2>&1 &"
    pid=0; wx=0; wy=0; ww=1848; wh=1126
  elif (( AGENT )); then
    APP_LIVE=1 APP_STORE="$store" APP_DEFAULTS_SUITE="$suite" AITM_CONFIG="$RIG/config.yaml" \
      "$exe" "${style_args[@]}" > "$OUT/app.log" 2>&1 &
    pid=$!
    echo "launched pid $pid (agent: no operator token in the environment)"
  else
    APP_LIVE=1 APP_LIVE_OPERATOR_TOKEN="$(<"$RIG/op.token")" APP_STORE="$store" APP_DEFAULTS_SUITE="$suite" AITM_CONFIG="$RIG/config.yaml" \
      "$exe" "${style_args[@]}" > "$OUT/app.log" 2>&1 &
    pid=$!
    echo "launched pid $pid"
  fi
  run sleep 9
  for i in 1 2 3; do run curl -s -o /dev/null -x "http://$PROXY" "$TARGET"; done
  echo "sent 3 requests through $PROXY to $TARGET"
  run sleep 2
  # Window geometry: the window is the first line of its own AX dump.
  ax_dump launch
  if (( ! DRY )); then
    read -r wx wy ww wh <<< "$(awk -F'\t' 'NR == 1 { print $7, $8, $9, $10 }' "$dumpfile")"
    [[ $wx == <-> || $wx == -<-> ]] || { echo "could not read the window geometry from $dumpfile"; exit 1; }
  fi
  echo "window origin $wx,$wy size ${ww}x${wh}"
  [[ $ww == 1848 && $wh == 1126 ]] || echo "WARNING: window is not 1848x1126; the --add pixel fallbacks assume that size"
}

flows_and_ac25_ac27() {
  echo "== watching $WATCH s of polling on the Flows page"
  run sleep $(( WATCH > 11 ? WATCH - 11 : 1 ))
  shot flows
  ax_dump flows
  local chips="" c
  for c in TCP UDP L4; do [[ -n $(centre_of "$c") ]] && chips+="$c "; done
  echo "chips located by AX: ${chips:-none}"
  # Locate by AX, click by position: one click on the L4 chip, park the mouse (a chip tooltip
  # would otherwise be up), read the footer, shoot, back to All.
  click_label L4
  mouse_away
  ax_dump flows-l4
  local rows_l4; rows_l4=$(awk -F'\t' '$1 == "AXStaticText" && $3 ~ /rows/ { print $3; exit }' "$dumpfile")
  echo "row readout under the L4 chip: ${rows_l4:-not read}"
  shot flows-l4
  click_label All
  mouse_away
  if (( DRY )); then
    echo "dry: AC29 needs TCP, UDP and L4 located by AX and a readout ending in '/ 0 rows' under L4 (flows-l4.png)"
  elif [[ $chips == *TCP* && $chips == *UDP* && $chips == *L4* && $rows_l4 == *"/ 0 rows" ]]; then
    ok "AC29 ok: chips $chips located; under L4 the footer reads '$rows_l4' (flows-l4.png)"
  else
    fail "AC29 FAIL: chips located '${chips:-none}' (need TCP UDP L4); readout under L4 '${rows_l4:-none}' (need '… / 0 rows'); see flows-l4.png"
  fi

  echo "== bus calls by aitm-mac since t0 (the rig core's audit ring)"
  if (( DRY )); then
    bus activity "$t0" aitm-mac
    echo "dry: AC25 needs l4.flow.list >= 1, l4.capture.status >= 1, l4.intercept.list == 0"
  else
    bus activity "$t0" aitm-mac | tee "$OUT/activity.txt"
    local n_list n_cap n_int elapsed
    n_list=$(count_in "$OUT/activity.txt" l4.flow.list)
    n_cap=$(count_in "$OUT/activity.txt" l4.capture.status)
    n_int=$(count_in "$OUT/activity.txt" l4.intercept.list)
    elapsed=$(( $(now_ms) - t0 ))
    echo "window ${elapsed} ms: l4.flow.list $n_list · l4.capture.status $n_cap · l4.intercept.list $n_int"
    if (( n_list >= 1 && n_cap >= 1 && n_int == 0 )); then
      ok "AC25 ok: l4.flow.list $n_list, l4.capture.status $n_cap, l4.intercept.list $n_int over ${elapsed} ms"
    else
      fail "AC25 FAIL: l4.flow.list $n_list, l4.capture.status $n_cap, l4.intercept.list $n_int"
    fi
  fi

  echo "== l4.craft with PacketSpecDraft.sample parsed"
  if (( DRY )); then
    bus craft
    echo "dry: AC27 needs 'l4.craft length: 36'"
  else
    bus craft | tee "$OUT/craft.txt"
    if grep -q 'l4.craft length: 36' "$OUT/craft.txt"; then ok "AC27 ok: l4.craft length 36"; else fail "AC27 FAIL: see $OUT/craft.txt"; fi
  fi
}

scope_page() {
  echo "== Proxy ▸ Scope…"
  with_app 'click menu item "Scope…" of menu "Proxy" of menu bar 1 of p'
  run sleep 2.5
  local scope_shot=scope; (( AGENT )) && scope_shot=scope-agent
  shot $scope_shot
  ax_dump scope
  local l4 n_l4=0 l
  l4=$(l4_lines)
  if [[ -n $l4 ]]; then
    while IFS= read -r l; do echo "L4 line: $l"; n_l4=$(( n_l4 + 1 )); done <<< "$l4"
  fi
  # Scope rows are one combined element each: label "<cidr> <ports> <if> <dir> <cap>", value the source.
  local rows_cfg rows_rt bare_cfg bare_rt cfg
  rows_cfg=$(awk -F'\t' 'tolower($3) == "config" && ($2 ~ /127\.0\.0\.1/ || $4 ~ /127\.0\.0\.1/) { n++ } END { print n + 0 }' "$dumpfile")
  rows_rt=$(awk -F'\t' 'tolower($3) == "runtime" && ($2 ~ /127\.0\.0\.1/ || $4 ~ /127\.0\.0\.1/) { n++ } END { print n + 0 }' "$dumpfile")
  bare_cfg=$(awk -F'\t' 'tolower($3) == "config" { n++ } END { print n + 0 }' "$dumpfile")
  bare_rt=$(awk -F'\t' 'tolower($3) == "runtime" { n++ } END { print n + 0 }' "$dumpfile")
  echo "scope rows by AX: config $rows_cfg (bare value matches $bare_cfg) · runtime $rows_rt (bare $bare_rt)"
  if (( DRY )); then
    echo "dry: AC26 needs a 'Capture and inject unavailable: <reason>' line; AC28 an 'In-path intercept unavailable: <reason>' line; AC30 three config rows"
  else
    (( n_l4 > 0 )) && ok "AC26 lines: $n_l4" || fail "AC26 lines: 0 (no availability line read; see $scope_shot.png)"
    if print -r -- "$l4" | grep -q '^Capture and inject unavailable: .'; then
      ok "AC26 ok: capture line carries the core's reason"
    else
      fail "AC26 FAIL: no 'Capture and inject unavailable: <reason>' line"
    fi
    if print -r -- "$l4" | grep -q '^In-path intercept unavailable: .'; then
      ok "AC28 line present: intercept line carries the core's reason"
    else
      fail "AC28 FAIL: no 'In-path intercept unavailable: <reason>' line"
    fi
    cfg=$rows_cfg; (( cfg == 0 )) && cfg=$bare_cfg
    (( cfg == 3 )) && ok "AC30 config entries: 3" || fail "AC30 FAIL: config entries read $cfg (need 3)"
  fi
  # The add form's shape on this page, both roles: fields with the cidr placeholder/label, and
  # "Add…" buttons below the L4 SCOPE header (enabled, all, header y).
  form_fields=$(l4_form_fields)
  read -r add_en add_all hdr_y <<< "$(l4_add_buttons)"
  echo "L4 add form by AX: cidr fields $form_fields · Add buttons below the L4 SCOPE header: $add_all (enabled $add_en; header y ${hdr_y:-none})"
}

agent_ac33() {
  # AC33 (plan amendment 7): as the agent the page says the operator token is needed and offers
  # no add control — nothing here can only fail.
  local op_hint
  op_hint=$(awk -F'\t' '$1 == "AXStaticText" && $3 == "Adding L4 scope needs the operator token (Settings ▸ Bus)" { print $3; exit }' "$dumpfile")
  echo "operator-only hint: ${op_hint:-not read}"
  if (( DRY )); then
    echo "dry: AC33 agent needs the hint 'Adding L4 scope needs the operator token (Settings ▸ Bus)', zero cidr fields and zero Add buttons below the L4 SCOPE header"
  elif [[ -n $op_hint ]] && (( form_fields == 0 && add_all == 0 )); then
    ok "AC33 agent: ok — hint shown, no cidr field, no Add below the L4 SCOPE header (scope-agent.png)"
  else
    fail "AC33 agent: FAIL — hint '${op_hint:-none}', cidr fields $form_fields, Add buttons below header $add_all (enabled $add_en); see scope-agent.png"
  fi
}

add_ac30() {
  echo "== AC30 add: 127.0.0.1/32 9100-9199 lo0 inbound capture through the form"
  (( DRY )) || { echo "scope.list before:"; bus scope-list; }
  # Fields by their accessibility labels (ScopePanel.l4Field), the pixel points as the fallback.
  click_label "CIDR to add to L4 scope" twice || click_xy 336 401
  typeit "127.0.0.1/32"
  click_label "Ports (empty for all)" twice || click_xy 472 401
  typeit "9100-9199"
  run sleep 0.5
  shot scope-typed
  ax_dump scope-typed
  # The form's Add: its identifier first, then the pixel point (twice, as the proven walk did).
  click_label l4-scope-add twice || click_xy 1811 436
  run sleep 2.5
  ax_dump sheet --sheet
  awk -F'\t' '$1 == "AXStaticText" && $3 != "" { print "sheet: " $3 }' "$dumpfile"
  local sgeo; sgeo=$(awk -F'\t' 'NR == 1 { print $7, $8, $9, $10 }' "$dumpfile")
  echo "sheet geometry (x y w h): ${sgeo:-not read}"
  shot scope-confirm
  # The sheet's Add: its identifier, else the prominent button's proven place at the sheet's
  # bottom-right (39 pt in from the right edge, 27 pt up from the bottom).
  if ! click_label l4-scope-confirm; then
    local sx sy sw shh
    read -r sx sy sw shh <<< "$sgeo"
    if [[ $sx == <-> || $sx == -<-> ]]; then
      swift "$here/tools/cgclick.swift" $(( sx + sw - 39 )) $(( sy + shh - 27 )); echo "clicked the sheet's Add by position"
    else
      echo "no confirm sheet read; nothing clicked"
    fi
  fi
  run sleep 3
  shot scope-added
  if (( DRY )); then
    bus scope-list
    bus scope-remove '<runtime id>'
    echo "dry: AC30 needs a 'runtime <id> 127.0.0.1/32 9100-9199 …' line, then its removal"
  else
    echo "scope.list after:"; bus scope-list | tee "$OUT/scope-list-after.txt"
    local rid; rid=$(awk '$1 == "runtime" && $3 == "127.0.0.1/32" && $4 == "9100-9199" { print $2; exit }' "$OUT/scope-list-after.txt")
    if [[ -n $rid ]]; then
      ok "AC30 ok: runtime entry $rid 127.0.0.1/32 9100-9199 added through the confirm"
      echo "remove $rid over the bus:"; bus scope-remove "$rid"
    else
      fail "AC30 FAIL: no runtime 127.0.0.1/32 9100-9199 entry after the add; see scope-added.png"
    fi
  fi
  run sleep 6
  shot scope-final
}

pinned_ac31() {
  echo "== Pinned page"
  # No View menu item opens Pinned: locate the sidebar row by AX (the Scope-page dump carries the
  # sidebar; the row is one AXButton described "Pinned, <count>") and click its centre. The count
  # in that description is AC31 evidence too.
  local plabel pcount nav=ok hint
  plabel=$(pinned_label); pcount=$(pinned_count)
  echo "sidebar Pinned row: '${plabel:-not read}' → count ${pcount:-not read}"
  click_label "${plabel:-Pinned}" || nav=fail
  mouse_away
  shot pinned
  ax_dump pinned
  hint=$(awk -F'\t' '$1 == "AXStaticText" && $3 ~ /Nothing pinned/ { print $3; exit }' "$dumpfile")
  echo "pinned hint: ${hint:-not read}"
  echo "store listing:"; run ls -la "$store"
  if (( DRY )); then
    echo "dry: AC31 needs a sidebar Pinned count of 0 (or the 'Nothing pinned' hint) and no pins.json (or one with empty hosts and apps)"
    return
  fi
  local pins_ok=1 pins_note="no pins.json" npins
  if [[ -f $store/pins.json ]]; then
    npins=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get("hosts",[]))+len(d.get("apps",[])))' "$store/pins.json" 2>/dev/null || echo unreadable)
    pins_note="pins.json with $npins pinned"
    [[ $npins == 0 ]] || pins_ok=0
  fi
  if (( pins_ok )) && { [[ $pcount == 0 ]] || [[ -n $hint ]]; }; then
    ok "AC31 ok: sidebar Pinned count '${pcount:-not read}', page hint '${hint:-not read}', $pins_note, nav $nav (pinned.png)"
  else
    fail "AC31 FAIL: sidebar Pinned count '${pcount:-not read}', page hint '${hint:-not read}', $pins_note, nav $nav (see pinned.png)"
  fi
}

# ---- the walk --------------------------------------------------------------------------------
launch_app
if (( AGENT )); then
  echo "agent run: Flows, AC25, AC27 skipped (operator evidence); on to the Scope page"
  run sleep 3
else
  flows_and_ac25_ac27
fi
scope_page
if (( AGENT )); then
  agent_ac33
  skip "AC30 add: skipped (--agent)"
  skip "AC31: skipped (--agent)"
else
  if (( ADD )); then add_ac30; else skip "AC30 add: skipped (no --add)"; fi
  pinned_ac31
fi

# ---- stop, summary ---------------------------------------------------------------------------
if (( ! DRY )); then echo "app log tail:"; tail -3 "$OUT/app.log"; fi
stop_app
echo
echo "==== cua-l4-live summary ($mode, role $role, tag $TAG) ===="
for r in "${results[@]}"; do echo "  $r"; done
if (( AGENT )); then
  echo "  shots: scope-agent (.png)"
else
  echo "  shots: flows flows-l4 scope$( (( ADD )) && echo ' scope-typed scope-confirm scope-added scope-final') pinned (.png)"
fi
echo "  evidence: $OUT"
if (( DRY )); then echo "  dry run: nothing launched, nothing asserted"; exit 0; fi
echo "  stop: kill $pid (done)"
(( nfail == 0 )) && { echo "  result: ok"; exit 0; } || { echo "  result: $nfail FAILED"; exit 1; }
