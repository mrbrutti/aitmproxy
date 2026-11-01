#!/bin/zsh
# The bus-reconnect live regression check on the EMBEDDED path (issue #192, spec D6, BR-AC7).
#
# What it proves: after each of the three ways `BusService.start()` is triggered in the real
# app, the FIRST operator action through the app still works. The triggers go through the
# real menu bar (System Events), never a direct bus call:
#   T1 reconnect-bus   Proxy ▸ Reconnect Bus      (core stays up; child pid unchanged)
#   T2 restart-core    Proxy ▸ Restart Core       (new child: new pid, new --config, new bus.endpoint)
#   T3 crash-respawn   kill -KILL the child       (`bus failed` within 5 s, then the respawn)
# After each: the toolbar pill's tooltip must read `bus: connected` within 20 s of the trigger
# (T1: never `bus failed` in between), then ONE View ▸ Pause Proxy click must flip
# `proxy.status.capturing` to false within 10 s and ONE Resume Proxy click must flip it back.
# The action travels menu → Session → BusService.live(); only the OBSERVATION is a bus read.
# Before each click the script waits (MENU_BOUND) for the item's title to settle: the View menu
# flips Pause Proxy ⇄ Resume Proxy only after the app has handled its own proxy.pause/resume
# reply, which can land after the separate observation connection already reads the new state.
# That wait never clicks; each action is still exactly one click.
# The pre-fix build fails at T1's pause: the superseded run's cleanup has nulled the client the
# new run owns, `live()` throws "the bus connection closed", and capturing stays true.
#
# Why a snap-dev bundle and not the installed app: `/tmp/Aitmproxy-dev-<tag>.app` runs as the
# process `Aitmproxy-<tag>`, so System Events, pgrep and kill target it unambiguously even with
# the operator's day-to-day app open; nothing is installed, the operator's real store is never
# read or written (APP_STORE points at a fresh scratch store), and a rebuild takes seconds.
#
# Usage: DEV_TAG=<tag> [CORE_DIR=<dir with aitm>] tools/selftest-live-reconnect.sh
#   DEV_TAG defaults to `reconnect`. CORE_DIR defaults to the repo's target/release when it
#   holds an executable `aitm`; otherwise snap-dev borrows the installed app's bundled core.
#
# Bounds (every wait is bounded by one of these; the script cannot hang):
#   CONNECT_BOUND 20 s   trigger → `bus: connected` (T2/T3's respawn wait shares this deadline)
#   FAILED_BOUND   5 s   T3: kill -KILL → `bus failed`
#   ACTION_BOUND  10 s   one menu click → `capturing` flips (measured from the click)
#   MENU_BOUND     5 s   a menu item's title settles (Pause/Resume Proxy) before its one click
#   QUIT_BOUND    15 s   quit menu click → app gone
#   QUIT_SLEEP   0.2 s   between app-gone checks, and once before the post-quit core check
#
# Hygiene (BR-AC8): nothing is written to the defaults domain; no path under the operator's
# install or store directories appears here; the operator token is read from the 0600 config
# into a variable, handed to python3 as an argv item and never printed; the only process reap
# is by this bundle's own core path; a SIGTERM to the app would skip its AppKit teardown, so the
# app is quit by clicking the Quit item of its own app menu through System Events, scoped to the
# dev bundle's process (the bundle id is shared with the installed app, which is usually running,
# so a `quit` Apple Event could reach that one instead; no ⌘Q is typed at whatever happens to be
# frontmost on the operator's desktop) and the reap is the fallback.
#
# Output: one `reconnect-live: <trigger>: <what was observed>` line per step (build, launch,
# reconnect-bus, restart-core, crash-respawn, teardown); the last line is
#   RECONNECT LIVE SELFTEST PASS (reconnect-bus, restart-core, crash-respawn: an operator action through the app succeeded after each)
# and exit 0, or `RECONNECT LIVE SELFTEST FAIL: <trigger> <step> <detail>` and exit 1 at the
# first unmet bound, or `RECONNECT LIVE SELFTEST FAIL: setup <detail>` and exit 2 on a rig
# problem (build, no core bundled, DEV_TAG/CORE_DIR validation, store refusal, no Accessibility,
# stale core, winshot), so a broken rig is distinguishable from the bug. The launch-time "no
# embedded core within 20 s" stays exit 1: the embedded path failing to spawn is a product failure.
set -u
zmodload zsh/datetime

here=${0:A:h:h}                 # apps/mac
repo_root=${here:h:h}           # repo root
tag=${DEV_TAG:-reconnect}
name=Aitmproxy
exe="$name-$tag"
dev="/tmp/$name-dev-$tag.app"
store="/tmp/$name-dev-state-$tag"
bin="$dev/Contents/MacOS/$exe"
core_pattern="$dev/Contents/Resources/core/aitm --config"
shots=/tmp/claude
CORE_DIR=${CORE_DIR:-}

# Bounds, in seconds (spec D6).
CONNECT_BOUND=20   # trigger → `bus: connected`; T2/T3's respawn wait shares this one deadline
FAILED_BOUND=5     # T3: kill -KILL → `bus failed`
ACTION_BOUND=10    # one menu click → `capturing` flips
MENU_BOUND=5       # a menu item's title settles (View ▸ Pause/Resume Proxy re-renders after the app handles its reply)
QUIT_BOUND=15      # quit menu click → app gone
QUIT_SLEEP=0.2     # between app-gone checks, and once before the post-quit core check
AX_SLEEP=0.1       # between AX reads; an osascript read itself takes ~100 ms, so reads land ≤ 250 ms apart
BUS_SLEEP=0.5      # between proxy.status polls
MENU_SLEEP=0.2     # between menu-item existence checks
T1_MIN_SETTLE=1    # after Reconnect Bus the label may still read the OLD `bus: connected`; keep polling at least this long

# The toolbar connection pill (ShellToolbar → ListeningPill) as System Events exposes it: its
# `help` is ConnectionSummary.tooltip (`Core: … \nBus: connected — operator · 127.0.0.1:<port>\n…`);
# the SwiftUI accessibility label is not exposed, and the window is addressed by NAME because the
# process also owns an unnamed AXUnknown window that can be `window 1`. A toolbar change is a
# one-line fix here.
AX_PILL='help of button 1 of group 1 of toolbar 1 of window "aitmproxy"'

# Script state. The token variable is assigned in discover_child and read only by bus_json.
app_pid=""; child_pid=""; core_cfg=""; bus_addr=""
t0=$EPOCHREALTIME
labels_seen=""; forbidden_seen=""; capturing_elapsed=""; quit_clean=""

note() { print -r -- "reconnect-live: $*" }
fail() { print -r -- "RECONNECT LIVE SELFTEST FAIL: $*"; exit 1 }
setup_fail() { print -r -- "RECONNECT LIVE SELFTEST FAIL: setup $*"; exit 2 }
elapsed() { printf '%.1f' $(( EPOCHREALTIME - t0 )) }

# One System Events statement against the dev bundle's process; osascript's status is returned
# unchanged so a missing menu item fails loudly instead of being swallowed.
se() { osascript -e "tell application \"System Events\" to tell process \"$exe\" to $1" }

# menu_click <item> <menu>: the menu is the LAST menu bar item with that name, because the bar
# holds two items named "View" (the system one, "Enter Full Screen", and the app's CommandMenu("View")).
menu_click() {
  local item=$1 menu=$2
  se 'set frontmost to true' >/dev/null || return 1
  se "click menu item \"$item\" of menu 1 of (item -1 of (menu bar items of menu bar 1 whose name is \"$menu\"))" >/dev/null
}

# wait_menu_item <item> <menu> <bound_s>: poll every MENU_SLEEP until the menu has an item named
# <item> (same last-menu-bar-item addressing as menu_click); 0 when present, 1 at the bound. A
# title-settle, never a retry: it only reads, it never clicks. An osascript error counts as
# not-there-yet and is polled again until the bound.
wait_menu_item() {
  local item=$1 menu=$2 bound=$3 start=$EPOCHREALTIME got
  while true; do  # bounded: gives up at start + bound (MENU_BOUND)
    got=$(se "exists menu item \"$item\" of menu 1 of (item -1 of (menu bar items of menu bar 1 whose name is \"$menu\"))" \
      2>/dev/null) || got=""
    [[ $got == true ]] && return 0
    (( EPOCHREALTIME - start >= bound )) && return 1
    sleep $MENU_SLEEP
  done
}

# The pill's tooltip text; empty on any error (no window yet, no Accessibility grant, app gone).
ax_label() {
  local out
  out=$(se "get $AX_PILL" 2>/dev/null) || out=""
  print -r -- "$out"
}

# wait_label <needle> <bound_s> <min_s> [forbidden]: poll ax_label every AX_SLEEP until
# elapsed ≥ min_s AND the label contains needle (case-insensitive); give up at t0 + bound_s.
# Records each distinct consecutive Bus lane line in labels_seen and sets forbidden_seen=1 if
# any read contains the forbidden needle. Returns 0 on success, 1 at the bound.
wait_label() {
  local needle=${1:l} bound=$2 min=$3 forbidden=${4:-}
  forbidden=${forbidden:l}
  local deadline=$(( t0 + bound )) label lane last=""
  labels_seen=""; forbidden_seen=""
  while true; do  # bounded: gives up at t0 + bound (CONNECT_BOUND or FAILED_BOUND)
    label=$(ax_label)
    lane=${(M)${(f)label}:#Bus:*}
    [[ -n $lane ]] || lane=${label//$'\n'/ · }
    [[ -n $lane ]] || lane="<empty>"
    if [[ $lane != "$last" ]]; then labels_seen+="${labels_seen:+ → }$lane"; last=$lane; fi
    [[ -n $forbidden && ${label:l} == *"$forbidden"* ]] && forbidden_seen=1
    if (( EPOCHREALTIME - t0 >= min )) && [[ ${label:l} == *"$needle"* ]]; then return 0; fi
    (( EPOCHREALTIME >= deadline )) && return 1
    sleep $AX_SLEEP
  done
}

# discover_child <old_pid> <old_cfg> <trigger>: until t0 + CONNECT_BOUND, find the embedded child
# by its own command line (never "the newest config.yaml"): a pid other than old_pid whose
# --config path differs from old_cfg, whose config exists and whose bus.endpoint beside it is
# non-empty. Sets child_pid, core_cfg, bus_addr and the operator token (a variable only — never
# echoed, never in a note, never in a file name). Re-run after every respawn: each spawn mints a
# new config, new tokens and a new bus.endpoint. <trigger> names the step in its FAIL lines.
discover_child() {
  local old_pid=$1 old_cfg=$2 trig=$3 pid cfg step=spawn
  [[ -n $old_pid ]] && step=respawn
  local deadline=$(( t0 + CONNECT_BOUND ))
  child_pid=""; core_cfg=""; bus_addr=""
  while true; do  # bounded: gives up at t0 + CONNECT_BOUND
    for pid in $(pgrep -f "$core_pattern"); do
      [[ $pid == "$old_pid" ]] && continue
      cfg=$(ps -o command= -p "$pid" 2>/dev/null | sed -n 's/.*--config \(.*config\.yaml\).*/\1/p')
      [[ -n $cfg && $cfg != "$old_cfg" && -s $cfg && -s "${cfg:h}/bus.endpoint" ]] || continue
      child_pid=$pid; core_cfg=$cfg
      bus_addr=$(head -1 "${core_cfg:h}/bus.endpoint" | tr -d '[:space:]')
      op_token=$(sed -n 's/^[[:space:]]*operator_token: "\(.*\)"/\1/p' "$core_cfg" | head -1)
      [[ -n "$op_token" ]] || fail "$trig $step the new core's config carries no mcp.operator_token"
      [[ -n $bus_addr ]] || fail "$trig $step bus.endpoint beside $core_cfg is empty"
      return 0
    done
    (( EPOCHREALTIME >= deadline )) && fail "$trig $step no embedded core under $dev" \
      "(pid other than '${old_pid:-none}', new --config, non-empty bus.endpoint) within ${CONNECT_BOUND} s"
    sleep $BUS_SLEEP
  done
}

# bus_json <tool>: one tools/call over the embedded core's loopback bus as the operator
# (observation only — never the action under test). Newline-delimited JSON-RPC: token line,
# initialize, tools/call with empty arguments. Prints the result's structuredContent as JSON
# when present, else the first content[].text; exits 1 on an RPC error or isError. The token
# travels as an argv item and is never printed. Serves the proxy.status reads (generic in the tool name).
bus_json() {
  python3 - "$bus_addr" "$op_token" "$1" <<'PY'
import json, socket, sys
bus, token, tool = sys.argv[1], sys.argv[2], sys.argv[3]
host, port = bus.rsplit(":", 1)
host = host.strip("[]")  # bracketed IPv6 literal, if the core ever prints one
s = socket.create_connection((host, int(port)), timeout=10)  # the 10 s timeout bounds every read below
f = s.makefile("rwb")
f.write((json.dumps({"token": token}) + "\n").encode()); f.flush()
n = [0]
def rpc(method, params=None):
    n[0] += 1
    f.write((json.dumps({"jsonrpc": "2.0", "id": n[0], "method": method,
                         "params": params or {}}) + "\n").encode()); f.flush()
    while True:  # bounded by the socket timeout
        line = f.readline()
        if not line:
            raise SystemExit("bus closed before reply")
        r = json.loads(line)
        if r.get("id") == n[0]:
            if "error" in r:
                raise SystemExit("rpc error: " + json.dumps(r["error"]))
            return r["result"]
rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "reconnect-live-check", "version": "0"}})
r = rpc("tools/call", {"name": tool, "arguments": {}})
f.close(); s.close()
text = (r.get("content") or [{}])[0].get("text", "")
if r.get("isError"):
    raise SystemExit("tool error: " + text[:200])
if "structuredContent" in r:
    print(json.dumps(r["structuredContent"]))
else:
    print(text)
PY
}

# Prints `true`/`false` from proxy.status, or `unknown` (and returns 1) when the bus read fails.
bus_capturing() {
  local reply_json
  reply_json=$(bus_json proxy.status) || { print -r -- unknown; return 1 }
  print -r -- "$reply_json" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["capturing"]).lower())' 2>/dev/null \
    || { print -r -- unknown; return 1 }
}

# wait_capturing <true|false> <bound_s>: poll bus_capturing every BUS_SLEEP from NOW (the
# click); 0 on match, 1 at the bound. capturing_elapsed holds the seconds taken, one decimal.
wait_capturing() {
  local want=$1 bound=$2 start=$EPOCHREALTIME got
  capturing_elapsed=""
  while true; do  # bounded: gives up at start + bound (ACTION_BOUND)
    got=$(bus_capturing)
    capturing_elapsed=$(printf '%.1f' $(( EPOCHREALTIME - start )))
    [[ $got == "$want" ]] && return 0
    (( EPOCHREALTIME - start >= bound )) && return 1
    sleep $BUS_SLEEP
  done
}

# operator_action <trigger>: the thing under test. Baseline capturing=true (resume first if the
# View menu already reads Resume Proxy), then ONE Pause Proxy click, then ONE Resume Proxy click,
# each observed over the bus within ACTION_BOUND. No retry of either click: the label said
# connected, so live() must succeed at once.
operator_action() {
  local trig=$1 base pause_s
  base=$(bus_capturing)
  [[ $base != unknown ]] || fail "$trig baseline proxy.status over the bus at $bus_addr failed"
  if [[ $base != true ]]; then
    wait_menu_item "Resume Proxy" View $MENU_BOUND || fail "$trig baseline the View menu did not show Resume Proxy within ${MENU_BOUND} s"
    menu_click "Resume Proxy" View || fail "$trig baseline click on Resume Proxy failed"
    wait_capturing true $ACTION_BOUND || fail "$trig baseline capturing stayed false for ${ACTION_BOUND} s after one Resume Proxy click"
  fi
  wait_menu_item "Pause Proxy" View $MENU_BOUND || fail "$trig pause the View menu did not show Pause Proxy within ${MENU_BOUND} s"
  menu_click "Pause Proxy" View || fail "$trig pause click on Pause Proxy failed"
  wait_capturing false $ACTION_BOUND || fail "$trig pause capturing stayed true for ${ACTION_BOUND} s after one Pause Proxy click"
  pause_s=$capturing_elapsed
  wait_menu_item "Resume Proxy" View $MENU_BOUND || fail "$trig resume the View menu did not show Resume Proxy within ${MENU_BOUND} s"
  menu_click "Resume Proxy" View || fail "$trig resume click on Resume Proxy failed"
  wait_capturing true $ACTION_BOUND || fail "$trig resume capturing stayed false for ${ACTION_BOUND} s after one Resume Proxy click"
  note "$trig: Pause Proxy → proxy.status.capturing=false in ${pause_s} s; Resume Proxy → capturing=true in ${capturing_elapsed} s"
}

# shot <trigger>: the attached evidence, by pid (a tagged bundle keeps the display name Aitmproxy).
# No PNG written is a rig problem (a screen-recording grant, `swift`), not the app's: exit 2, with
# the trigger kept in the message. The trigger's own steps have already passed over the bus.
shot() {
  local png="$shots/reconnect-$tag-$1.png"
  swift "$here/tools/winshot.swift" "$app_pid" "$png" >/dev/null 2>&1 && [[ -s $png ]] \
    || setup_fail "$1 shot winshot wrote no PNG at $png (a screen-recording grant or swift problem)"
}

# after_trigger <trigger> [forbidden]: the sub-procedure after each trigger (spec D6).
after_trigger() {
  local trig=$1 forbidden=${2:-} min=0
  [[ $trig == reconnect-bus ]] && min=$T1_MIN_SETTLE
  wait_label "bus: connected" $CONNECT_BOUND $min "$forbidden" \
    || fail "$trig connect bus label never read 'bus: connected' within ${CONNECT_BOUND} s (saw: $labels_seen)"
  if [[ -n $forbidden ]]; then
    [[ -z $forbidden_seen ]] || fail "$trig flicker bus label read '$forbidden' during Reconnect Bus (saw: $labels_seen)"
  fi
  note "$trig: bus: connected after $(elapsed) s (labels: $labels_seen)"
  operator_action "$trig"
  shot "$trig"
}

# quit_app: click "Quit Aitmproxy" in the app menu (menu bar item 2 of menu bar 1) through the
# process-scoped `se` helper, so only this dev bundle's process is addressed. That is the normal
# terminate path, so willTerminate reaps the child. A `quit` Apple Event is not used: the bundle id
# is shared with the operator's installed app, which is usually running, so Launch Services may
# resolve the event to that instance. The click needs no focus and types nothing at whatever is
# frontmost on the operator's desktop. Then a bounded wait, then kill + a reap by this bundle's own
# core path as the fallback. quit_clean=1 when the app left on its own and no core remained under
# the bundle path before the fallback ran.
quit_app() {
  [[ -n $app_pid ]] || return 0
  local start=$EPOCHREALTIME
  quit_clean=""
  if se 'click menu item "Quit Aitmproxy" of menu 1 of menu bar item 2 of menu bar 1' >/dev/null 2>&1; then
    while kill -0 "$app_pid" 2>/dev/null; do  # bounded: gives up at start + QUIT_BOUND
      (( EPOCHREALTIME - start >= QUIT_BOUND )) && break
      sleep $QUIT_SLEEP
    done
  fi
  if kill -0 "$app_pid" 2>/dev/null; then
    kill "$app_pid" 2>/dev/null
  else
    sleep $QUIT_SLEEP
    pgrep -f "$core_pattern" >/dev/null || quit_clean=1
  fi
  pkill -f "$dev/Contents/Resources/core/" 2>/dev/null  # the only reap: this bundle's own core path
  app_pid=""
}

cleanup() { [[ -n $app_pid ]] && quit_app; return 0 }
trap cleanup EXIT

# 1. Build and assemble the dev bundle (snap-dev's bundle, scratch dir and staleness check).
[[ $tag =~ ^[A-Za-z0-9_-]+$ ]] || setup_fail "DEV_TAG must match [A-Za-z0-9_-]+"
mkdir -p "$shots"
if [[ -n $CORE_DIR ]]; then
  [[ -x "$CORE_DIR/aitm" ]] || setup_fail "CORE_DIR=$CORE_DIR holds no executable aitm"
  core_from="CORE_DIR=$CORE_DIR"
elif [[ -x "$repo_root/target/release/aitm" ]]; then
  CORE_DIR="$repo_root/target/release"
  core_from="the repo's target/release"
else
  core_from="the installed app's bundled core (borrowed by snap-dev)"
fi
env NO_LAUNCH=1 DEV_TAG=$tag ${CORE_DIR:+CORE_DIR=$CORE_DIR} "$here/tools/snap-dev.sh" || setup_fail "snap-dev.sh failed"
[[ -x "$bin" ]] || setup_fail "no binary at $bin"
[[ -x "$dev/Contents/Resources/core/aitm" ]] || setup_fail "no core bundled; set CORE_DIR"
note "build: bundle $dev (core from $core_from)"

# 1b. Tester — a core already running under THIS bundle path (an earlier run of the same DEV_TAG
#     killed before its EXIT trap, or a snap-dev launch left open: NO_LAUNCH=1 reaps nothing) is
#     the one discover_child would find at the rendezvous and its bus the one every observation
#     would read, so the run would measure some other app. A rig problem: refuse (exit 2) and
#     reap nothing — the only reap in this script stays quit_app's, of the app this run launched.
stale=$(pgrep -f "$core_pattern" || true)
[[ -z $stale ]] || setup_fail "a core already runs under $dev (pid ${stale//$'\n'/ }); quit that app first or use another DEV_TAG"

# 2. Launch the bundle on a fresh, isolated store (the harness defaults suite is wiped under
#    APP_STORE and defaults to the embedded core, so nothing is written to the defaults domain).
#    The bundle id's saved window state goes exactly as snap-dev does on a launch (window state,
#    not the operator's store).
rm -rf "$HOME/Library/Saved Application State/com.mrbrutti.aitmproxy.savedState" "$store"
mkdir "$store" || setup_fail "something appeared at $store between its removal and the mkdir (snap-dev's race guard); refusing to launch"
[[ ! -L $store && -O $store && -d $store ]] || setup_fail "store $store is not a directory we own; refusing to launch"
unsetopt bg_nice
t0=$EPOCHREALTIME
APP_STORE="$store" "$bin" >"$shots/reconnect-$tag-app.log" 2>&1 &
app_pid=$!

# 3. Rendezvous: the embedded child, then `bus: connected` on the pill, both within CONNECT_BOUND
#    of the launch.
discover_child "" "" launch
if ! wait_label "bus: connected" $CONNECT_BOUND 0; then
  [[ -n "$(ax_label)" ]] || setup_fail "System Events could not read the toolbar label (is Accessibility granted to the terminal app?)"
  fail "launch connect bus label never read 'bus: connected' within ${CONNECT_BOUND} s (saw: $labels_seen)"
fi
note "launch: app pid $app_pid; embedded core pid $child_pid; bus: connected after $(elapsed) s"

# 4. T1 reconnect-bus: Proxy ▸ Reconnect Bus; the core stays up, so the child pid must not change
#    and the label must never read `bus failed` on the way back to `bus: connected` (BR-AC5).
old_pid=$child_pid
t0=$EPOCHREALTIME
menu_click "Reconnect Bus" Proxy || fail "reconnect-bus click the Proxy menu has no Reconnect Bus item"
after_trigger reconnect-bus "bus failed"
now_pid=$(pgrep -f "$core_pattern" | head -1)
[[ $now_pid == "$old_pid" ]] || fail "reconnect-bus child the embedded core pid changed (was $old_pid, now ${now_pid:-none})"
note "reconnect-bus: child pid unchanged ($old_pid)"

# 5. T2 restart-core: Proxy ▸ Restart Core; a new child (new pid, new --config, non-empty
#    bus.endpoint; token and address re-read), then the sub-procedure.
old_pid=$child_pid; old_cfg=$core_cfg
t0=$EPOCHREALTIME
menu_click "Restart Core" Proxy || fail "restart-core click the Proxy menu has no Restart Core item"
discover_child "$old_pid" "$old_cfg" restart-core
note "restart-core: new core pid $child_pid after $(elapsed) s"
after_trigger restart-core

# 6. T3 crash-respawn: kill -KILL the child; the owner must report the real loss (`bus failed`
#    within FAILED_BOUND, BR-AC4), then the supervisor respawns and the sub-procedure runs.
old_pid=$child_pid; old_cfg=$core_cfg
t0=$EPOCHREALTIME
kill -KILL "$old_pid" || fail "crash-respawn kill kill -KILL $old_pid failed"
wait_label "bus failed" $FAILED_BOUND 0 \
  || fail "crash-respawn failed-report bus label never read 'bus failed' within ${FAILED_BOUND} s of kill -KILL (saw: $labels_seen)"
note "crash-respawn: bus failed seen $(elapsed) s after kill -KILL $old_pid"
discover_child "$old_pid" "$old_cfg" crash-respawn
after_trigger crash-respawn

# 7. Teardown: the normal quit path, then the verdict.
quit_app
if [[ -n $quit_clean ]]; then
  note "teardown: app quit on the app menu's Quit click (process-scoped); no core left under the bundle path"
else
  note "teardown: app did not leave cleanly within ${QUIT_BOUND} s of the app menu's Quit click (or a core remained);" \
    "killed and reaped by the bundle path"
fi
print -r -- "RECONNECT LIVE SELFTEST PASS (reconnect-bus, restart-core, crash-respawn:" \
  "an operator action through the app succeeded after each)"
exit 0
