#!/usr/bin/env bash
# Live proof of the R14 one-shot verbs on a running core: every surface serves
# a loopback operator bus by default, mints the operator token into the `0600`
# config on its first run and publishes a `run/cores/<pid>.json` pointer; a
# one-shot verb finds that core, acts on it and renders the core's answer, or
# refuses with the spec's panel when none is reachable.
#
# Spec: docs/superpowers/specs/2026-11-01-cli-oneshot-live-core-design.md
# Plan: docs/superpowers/plans/2026-11-01-cli-oneshot-live-core-plan.md
#       (Task 11; the section numbers below are the plan's)
#
# Boots the REAL `aitm` binary (no mocks, no fixtures). Every section runs in
# its own isolated HOME under a temp dir, so it never touches your real
# ~/Library/Application Support/aitmproxy, never writes the system proxy or a
# keychain (`system_proxy.auto` stays unset) and never installs a CA.
#
# A "default core" is bare `aitm` with no flags and no config file (spec
# §Acceptance criteria), so sections 1-10, 13 and 14 need 127.0.0.1:8080 and
# :8081 free; a section whose default ports are taken FAILs its setup with
# the port named. Sections 5, 7, 11 and 12 pick free ports for their own
# configs.
#
# Usage:
#   tests/e2e/cli/oneshot-live-core.sh
#
# Environment:
#   AITM_BIN             the aitm binary under test
#                        (default: <repo>/target/debug/aitm, else target/release/aitm)
#   AITM_TERM_SECTIONS   comma list of the sections to run, by number or name
#                        (default: all). Names: card oneshot restart refusals
#                        configport stale twocores rotated gate explicit optout
#                        shared surfaces rundir w1pins docs
#
# Needs `python3` on PATH (free ports, port holders, the bus client, the
# pointer and lock checks, sha256); without it the script exits 2 at once.
#
# A check whose precondition is missing SKIPs with a reason and never FAILs:
#   - the `lsof` checks (section 1's bound port, section 12's listener count)
#     need `lsof` on PATH;
#   - section 13's `aitm tui` half needs stdout to be a terminal (`[ -t 1 ]`)
#     and a pty `script` can allocate; the `aitm web` half runs anywhere.
#
# Readiness is the card's `Log: ` row (W1 D13). A default core serves MCP on
# stdio and exits on stdin EOF (W1 Open question 3; section 3 proves exactly
# that), so every core that must stay up reads its stdin from a pipe this
# script holds open for the whole run (fd 8); one-shots get /dev/null.
#
# Token hygiene (plan C13): the minted operator token is read from the `0600`
# config with `sed` into a shell variable and only ever (a) used as a
# `grep -c -F` needle whose count must be 0, (b) written by the `printf`
# builtin into a `0600` token file for `--token-file`, or (c) exported as
# `AITM_BUS_TOKEN` from the variable for one child. It is never echoed, never
# logged, never on a command line `ps` could show; the python bus client reads
# it from the file in-process. No token-bearing file is ever `cat`ed or shown
# in a failure dump (dumps redact `#t=` URL fragments too). No global `pkill`:
# every spawned core, port holder and feeder is tracked by PID and killed by
# the exit trap.
#
# Exit status is non-zero if any assertion fails.
# shellcheck disable=SC2016  # the single-quoted `…` below are literal texts the binary prints
set -uo pipefail
umask 077

# ---------------------------------------------------------------------------
# Locate the binary under test.
# ---------------------------------------------------------------------------
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../../.." && pwd)"
OS="$(uname -s)"

if [ -z "${AITM_BIN:-}" ]; then
  if [ -x "$repo_root/target/debug/aitm" ]; then
    AITM_BIN="$repo_root/target/debug/aitm"
  elif [ -x "$repo_root/target/release/aitm" ]; then
    AITM_BIN="$repo_root/target/release/aitm"
  else
    echo "FATAL: no aitm binary found; build one (cargo build -p aitm) or set AITM_BIN" >&2
    exit 2
  fi
fi
if [ ! -x "$AITM_BIN" ]; then
  echo "FATAL: AITM_BIN=$AITM_BIN is not an executable file; build one (cargo build -p aitm) or set AITM_BIN" >&2
  exit 2
fi
command -v python3 >/dev/null || { echo "FATAL: python3 is required (ports, the bus client, the pointer and lock checks)" >&2; exit 2; }
AITM_BIN="$(cd "$(dirname "$AITM_BIN")" && pwd)/$(basename "$AITM_BIN")"
SECTIONS="${AITM_TERM_SECTIONS:-all}"
HAVE_LSOF=0; command -v lsof >/dev/null 2>&1 && HAVE_LSOF=1

# The runner's own settings must not leak into the binary under test: every
# section states the variables it needs on the command line.
unset RUST_LOG NO_COLOR CLICOLOR_FORCE AITM_TERM CI AITM_LOG_FILE AITM_OBSCURA_BIN AITM_TUI_LOG AITM_CONFIG XDG_CONFIG_HOME
unset AITM_RUN_DIR AITM_BUS AITM_BUS_TOKEN
# The piped expectations use the rich separator (`·`), which a pipe gets
# whenever any of LC_ALL/LC_CTYPE/LANG names UTF-8 (W1 spec T1).
case "${LC_ALL:-}${LC_CTYPE:-}${LANG:-}" in
  *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) ;;
  *) export LANG=en_US.UTF-8 ;;
esac
REC_TERM="${TERM:-xterm-256color}"
[ "$REC_TERM" = dumb ] && REC_TERM=xterm-256color

echo "aitm under test:  $AITM_BIN"
echo "platform:         $OS"
[ "$HAVE_LSOF" = 1 ] && echo "lsof:             $(command -v lsof)" || echo "lsof:             (absent; the bound-port checks will be skipped)"
[ -t 1 ] && echo "stdout:           a TTY (the aitm tui half of section 13 can run)" || echo "stdout:           not a TTY (the aitm tui half of section 13 will be skipped)"
echo "sections:         $SECTIONS"
echo

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aitm-oneshot-XXXXXX")"
if [ -z "$ROOT" ] || [ ! -d "$ROOT" ]; then
  echo "FATAL: could not create a scratch directory under ${TMPDIR:-/tmp}" >&2
  exit 2
fi
PASS=0; FAIL=0; SKIP=0
SERVER_PID=""; SERVER_RC=""; RC=""; SCRIPT_PID=""; REC_PID=""; FEEDER_PID=""; FEEDER_FD=""; SECTION_FAIL0=0
KEEPALIVE_PID=""; TRACKED=""
HOME_DIR=""; CFG=""; TOKEN=""; PTR=""; BUSPORT=""; CORE_ERR=""; CORE_OUT=""

cleanup() {
  local p
  # shellcheck disable=SC2086  # TRACKED is a space-separated pid list
  for p in $(jobs -p) ${SERVER_PID:-} ${REC_PID:-} ${SCRIPT_PID:-} ${FEEDER_PID:-} ${KEEPALIVE_PID:-} $TRACKED; do kill "$p" 2>/dev/null; done
  sleep 0.3
  # shellcheck disable=SC2086
  for p in $(jobs -p) $TRACKED; do kill -9 "$p" 2>/dev/null; done
  chmod -R u+rwX "$ROOT" 2>/dev/null
  rm -rf "$ROOT"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }
note() { echo "  note: $1"; }

# want <number> <name>: is this section selected by AITM_TERM_SECTIONS?
want() {
  case ",$SECTIONS," in *,all,*|*,"$1",*|*,"$2",*) return 0 ;; esac
  return 1
}

# check "<description>" <command...>: PASS when the command succeeds.
check() { local desc="$1"; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }
starts_with() { case "$1" in "$2"*) return 0 ;; esac; return 1; }
# bytes_equal <file> <text>: the file's bytes are exactly <text>.
bytes_equal() { printf '%s' "$2" | cmp -s - "$1"; }

# Line counts (0 when the file is missing). `count_re` takes an ERE,
# `count_fx` a fixed string (the form every token comparison uses).
count_re() { local n; n="$(grep -a -c -E -- "$1" "$2" 2>/dev/null)"; printf '%s\n' "${n:-0}"; }
count_fx() { local n; n="$(grep -a -c -F -- "$1" "$2" 2>/dev/null)"; printf '%s\n' "${n:-0}"; }

redact() { sed -E 's/#t=[^&[:space:]]+/#t=<redacted>/g'; }

begin_section() { echo; echo "### $1 ###"; SECTION_FAIL0=$FAIL; }
# end_section <text files...>: when the section failed, show the files' heads.
# Never pass a token-bearing file (a config, a token file) here.
end_section() {
  [ "$FAIL" -gt "$SECTION_FAIL0" ] || return 0
  local f
  for f in "$@"; do
    [ -s "$f" ] || continue
    echo "  --- $(basename "$f") (first 30 lines, URL tokens redacted) ---"
    head -30 "$f" | redact | sed 's/^/  | /'
  done
}

fmode() { if [ "$OS" = Darwin ]; then stat -f %Lp "$1"; else stat -c %a "$1"; fi; }
fsize() { if [ "$OS" = Darwin ]; then stat -f %z "$1"; else stat -c %s "$1"; fi; }
fmtime() { if [ "$OS" = Darwin ]; then stat -f %m "$1"; else stat -c %Y "$1"; fi; }
sha256_of() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
now_s() { python3 -c 'import time; print("%.2f" % time.time())'; }
gen_secret() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }

# The per-HOME paths aitm derives (W1 D7; R14 D4): the aitmproxy directory,
# the default config, the log, the durable audit log and the pointer dir.
aitm_dir_for() {
  if [ "$OS" = Darwin ]; then printf '%s/Library/Application Support/aitmproxy' "$1"
  else printf '%s/.config/aitmproxy' "$1"; fi
}
cfg_path_for()   { printf '%s/config.yaml' "$(aitm_dir_for "$1")"; }
log_path_for()   { printf '%s/logs/aitm.log' "$(aitm_dir_for "$1")"; }
audit_path_for() { printf '%s/audit.jsonl' "$(aitm_dir_for "$1")"; }
default_run_dir_for() { printf '%s/run/cores' "$(aitm_dir_for "$1")"; }
# run_dir_for <home>: where this HOME's cores publish pointers — the
# AITM_RUN_DIR override when the script exported one (section 14), else the
# default.
run_dir_for() {
  if [ -n "${AITM_RUN_DIR:-}" ]; then printf '%s' "$AITM_RUN_DIR"; else default_run_dir_for "$1"; fi
}
# pointer_count <home> / pointers_in <dir>
pointers_in() { find "$1" -mindepth 1 -maxdepth 1 -name '*.json' 2>/dev/null; }
pointer_count() { pointers_in "$(run_dir_for "$1")" | wc -l | tr -d ' '; }
# wait_pointer <dir> <secs>: until a `*.json` appears there.
wait_pointer() {
  local dir="$1" secs="$2" i=0
  while [ "$i" -lt "$((secs*4))" ]; do
    [ -n "$(pointers_in "$dir")" ] && return 0
    sleep 0.25; i=$((i+1))
  done
  [ -n "$(pointers_in "$dir")" ]
}
# wait_gone <path> <secs>: until the path no longer exists (polled at 0.1 s).
wait_gone() {
  local p="$1" secs="$2" i=0
  while [ "$i" -lt "$((secs*10))" ]; do
    [ -e "$p" ] || return 0
    sleep 0.1; i=$((i+1))
  done
  [ ! -e "$p" ]
}
# flock_state <pointer>: `held` when a shared non-blocking flock fails with
# BlockingIOError (the writer holds its exclusive lock), `free` otherwise.
flock_state() {
  python3 - "$1" <<'PY'
import fcntl, sys
f = open(sys.argv[1], 'rb')
try:
    fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
except BlockingIOError:
    print('held'); sys.exit(0)
print('free')
PY
}
# token_in <config>: the `mcp.operator_token` value, for `TOKEN="$(token_in …)"`
# ONLY. Never call it outside a command substitution (that would print it).
token_in() { sed -n 's/^  operator_token: //p' "$1" | head -1; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null; }
port_listening() { python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(("127.0.0.1",int(sys.argv[1])))==0 else 1)' "$1" 2>/dev/null; }

# Hold a port until the returned PID is killed (stdout/stderr detached so the
# `$(hold_port …)` substitution returns at once). Tracked for the trap.
hold_port() {
  python3 -c "import socket,time,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen()
time.sleep(600)" "$1" >/dev/null 2>&1 &
  TRACKED="$TRACKED $!"; echo $!
}
# A listener that accepts and never writes (AC-R14-25's R10 case).
hold_silent() {
  python3 -c "import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen()
held=[]
while True:
    c,_=s.accept(); held.append(c)" "$1" >/dev/null 2>&1 &
  TRACKED="$TRACKED $!"; echo $!
}
# A listener that accepts and closes at once (AC-R14-25's R2' case).
hold_closing() {
  python3 -c "import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen()
while True:
    c,_=s.accept(); c.close()" "$1" >/dev/null 2>&1 &
  TRACKED="$TRACKED $!"; echo $!
}

wait_port_listening() {
  local port="$1" secs="$2" i=0
  while [ "$i" -lt "$((secs*4))" ]; do
    port_listening "$port" && return 0
    sleep 0.25; i=$((i+1))
  done
  return 1
}

# default_ports_free: a default core listens on 127.0.0.1:8080 (proxy) and
# :8081 (browser proxy); a section that starts one FAILs its setup, naming the
# port, when either is taken (another aitm, or another proxy, holds it).
default_ports_free() {
  local p
  for p in 8080 8081; do
    if port_listening "$p"; then
      fail "setup: 127.0.0.1:$p is in use, and a default core (no config file) listens there; stop whatever holds it (another aitm?)"
      return 1
    fi
  done
  return 0
}

# new_home <name>: a fresh isolated HOME. Sets HOME_DIR and clears the
# per-core state.
new_home() {
  HOME_DIR="$ROOT/$1/home"; mkdir -p "$HOME_DIR"
  CFG="$(cfg_path_for "$HOME_DIR")"; TOKEN=""; PTR=""; BUSPORT=""; CORE_ERR=""; CORE_OUT=""
}
# main_home: the HOME sections 1-4 share (the default core of section 1, the
# one-shots of 2, the restarts of 3, the refusals of 4).
main_home() {
  HOME_DIR="$ROOT/main/home"; mkdir -p "$HOME_DIR"
  CFG="$(cfg_path_for "$HOME_DIR")"
}

# The keep-alive stdin: an anonymous pipe whose writer (`sleep`) never writes,
# held on fd 8 for the whole run, so a default core's stdio MCP transport
# never sees EOF. The process substitution's PID is `$!` right after the
# `exec` (bash 3.2 and 5.x); the trap ends it.
exec 8< <(exec sleep 100000)
KEEPALIVE_PID=$!

# start_core <stdout-file> <stderr-file> <cmd...>: a serving aitm in the
# background with stdin on the keep-alive pipe, HOME isolated. Sets SERVER_PID.
start_core() {
  local out="$1" err="$2"; shift 2
  HOME="$HOME_DIR" "$@" >"$out" 2>"$err" <&8 &
  SERVER_PID=$!; TRACKED="$TRACKED $SERVER_PID"
}

# wait_for <file> <ERE> <secs>: until the pattern appears (0), the server
# exits (its final output is checked once more) or the bound passes (1).
wait_for() {
  local f="$1" re="$2" secs="$3" i=0
  while [ "$i" -lt "$((secs*4))" ]; do
    grep -a -q -E -- "$re" "$f" 2>/dev/null && return 0
    if [ -n "$SERVER_PID" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
      grep -a -q -E -- "$re" "$f" 2>/dev/null; return $?
    fi
    sleep 0.25; i=$((i+1))
  done
  return 1
}

# stop_server [pid]: SIGTERM, bounded escalation to SIGKILL. Sets SERVER_RC.
stop_server() {
  local pid="${1:-$SERVER_PID}" i=0
  [ -n "$pid" ] || { SERVER_RC=""; return; }
  kill -TERM "$pid" 2>/dev/null
  while kill -0 "$pid" 2>/dev/null; do
    [ "$i" -ge 40 ] && { kill -9 "$pid" 2>/dev/null; break; }
    sleep 0.25; i=$((i+1))
  done
  wait "$pid" 2>/dev/null; SERVER_RC=$?
  [ "$pid" = "${SERVER_PID:-}" ] && SERVER_PID=""
}

# run_bounded <stdout-file> <stderr-file> <secs> <cmd...>: a command that must
# exit on its own (stdin /dev/null). Sets RC (124 when it had to be killed).
run_bounded() {
  local out="$1" err="$2" secs="$3"; shift 3
  HOME="$HOME_DIR" "$@" >"$out" 2>"$err" </dev/null &
  local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    [ "$i" -ge "$((secs*4))" ] && { kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; RC=124; return; }
    sleep 0.25; i=$((i+1))
  done
  wait "$pid" 2>/dev/null; RC=$?
}

# oneshot <tag> <aitm args...>: a one-shot in HOME_DIR, bounded to 60 s, its
# streams at $ROOT/<tag>.out and $ROOT/<tag>.err. Sets RC.
oneshot() { local tag="$1"; shift; run_bounded "$ROOT/$tag.out" "$ROOT/$tag.err" 60 "$AITM_BIN" "$@"; }

# median_of <n> <cmd...>: the median `real` of n `/usr/bin/time -p` runs.
median_of() {
  local n="$1"; shift
  local i=0 t list=""
  while [ "$i" -lt "$n" ]; do
    HOME="$HOME_DIR" /usr/bin/time -p "$@" >/dev/null 2>"$ROOT/time.err" </dev/null
    t="$(awk '/^real/ {print $2}' "$ROOT/time.err" | tail -1)"
    list="$list ${t:-99}"; i=$((i+1))
  done
  # shellcheck disable=SC2086
  printf '%s\n' $list | sort -n | sed -n "$((n/2 + 1))p"
}

# start_default_core <tag> [command prefix...]: bare `aitm` (no flags, no
# config file) in HOME_DIR, optionally behind a prefix such as
# `env RUST_LOG=info`, waited for up to its `Log:` row. Sets CORE_OUT CORE_ERR
# CFG TOKEN PTR BUSPORT (TOKEN is read from the 0600 config with `sed`, never
# printed). Returns 1, after a FAIL, when the core did not come up.
start_default_core() {
  local tag="$1"; shift
  CORE_OUT="$ROOT/$tag.out"; CORE_ERR="$ROOT/$tag.err"
  start_core "$CORE_OUT" "$CORE_ERR" "$@" "$AITM_BIN"
  if ! wait_for "$CORE_ERR" '^Log: ' 30; then
    fail "setup: the default core's ready card never appeared in $(basename "$CORE_ERR") (the server exited, or 30 s passed)"
    stop_server; return 1
  fi
  CFG="$(cfg_path_for "$HOME_DIR")"
  TOKEN="$(token_in "$CFG" 2>/dev/null)"
  if [ -z "$TOKEN" ]; then
    fail "setup: no '  operator_token:' line in $CFG after the default core came up"
    stop_server; return 1
  fi
  BUSPORT="$(sed -n -E 's/^Operator bus: 127\.0\.0\.1:([0-9]+)$/\1/p' "$CORE_ERR" | head -1)"
  if [ -z "$BUSPORT" ]; then
    fail "setup: no 'Operator bus: 127.0.0.1:<port>' row on the default core's card"
    stop_server; return 1
  fi
  local dir; dir="$(run_dir_for "$HOME_DIR")"
  wait_pointer "$dir" 5 || true
  PTR="$(pointers_in "$dir" | head -1)"
  if [ -z "$PTR" ]; then
    fail "setup: no pointer under $dir while the default core runs"
    stop_server; return 1
  fi
  return 0
}

# need_default_core <tag>: sections 2 and 3 want the main HOME's core up;
# start one when section 1 did not run (or was stopped).
need_default_core() {
  main_home
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null && [ -n "$PTR" ] && [ -e "$PTR" ]; then
    return 0
  fi
  SERVER_PID=""
  default_ports_free || return 1
  start_default_core "$1"
}

# token_absent "<label>" <needle> <files...>: the needle occurs 0 times across
# the files that exist (AC-R14-28). An empty needle is a setup failure, never
# a vacuous pass.
token_absent() {
  local label="$1" needle="$2"; shift 2
  [ -n "$needle" ] || { fail "$label: no operator token to look for (setup)"; return; }
  local f n hits=0 seen=0
  for f in "$@"; do
    [ -e "$f" ] || continue
    n="$(count_fx "$needle" "$f")"; hits=$((hits + n)); seen=$((seen + 1))
  done
  check "$label: the operator token occurs 0 times across $seen files ($hits)" [ "$hits" = 0 ]
}

# ---------------------------------------------------------------------------
# TTY recording through `script` (section 13's `aitm tui`), as in
# term-reporting.sh §14: a pipe-fed `script`, the aitm child found through
# `pgrep -P`, a PID-tracked stdin feeder, never a FIFO (BSD `script` refuses
# one) and never a global pkill.
# ---------------------------------------------------------------------------
stripped() {
  LC_ALL=C sed -e $'s/\x1b\\[[0-9;?<=>!]*[@-~]//g' -e $'s/\x1b[()][0-9A-Za-z]//g' -e $'s/\x1b[=>78]//g' -e $'s/\r//g' "$1"
}

start_recording() {
  local cast="$1"; shift
  local wrap="$ROOT/rec.$RANDOM$RANDOM.sh"
  { printf 'stty rows 40 cols 120 2>/dev/null\nexec'; printf ' %q' "$@"; printf '\n'; } > "$wrap"
  : > "$cast"
  if [ -z "$FEEDER_FD" ]; then
    note "recording: no feeder pipe open (start_feeder first)"; SCRIPT_PID=""; REC_PID=""; return 1
  fi
  if [ "$OS" = Darwin ]; then
    HOME="$HOME_DIR" script -q -t 0 "$cast" /bin/sh "$wrap" <&"$FEEDER_FD" 7<&- 8<&- >/dev/null 2>"$cast.script.err" &
  else
    HOME="$HOME_DIR" script -q -f -c "/bin/sh '$wrap'" "$cast" <&"$FEEDER_FD" 7<&- 8<&- >/dev/null 2>"$cast.script.err" &
  fi
  SCRIPT_PID=$!
  REC_PID=""
  local i=0 p q c
  while [ "$i" -lt 40 ] && [ -z "$REC_PID" ] && kill -0 "$SCRIPT_PID" 2>/dev/null; do
    for p in $(pgrep -P "$SCRIPT_PID" 2>/dev/null); do
      for q in "$p" $(pgrep -P "$p" 2>/dev/null); do
        c="$(ps -o comm= -p "$q" 2>/dev/null)"
        case "$c" in *aitm) REC_PID="$q"; break 2 ;; esac
      done
    done
    [ -n "$REC_PID" ] || { sleep 0.25; i=$((i+1)); }
  done
}

end_recording() {
  local sig="${1:-INT}" i=0 p
  [ -n "$REC_PID" ] && kill "-$sig" "$REC_PID" 2>/dev/null
  while kill -0 "$SCRIPT_PID" 2>/dev/null; do
    if [ "$i" -eq 40 ]; then
      [ -n "$REC_PID" ] && kill -TERM "$REC_PID" 2>/dev/null
      for p in $(pgrep -P "$SCRIPT_PID" 2>/dev/null); do kill -TERM "$p" 2>/dev/null; done
    fi
    if [ "$i" -ge 60 ]; then
      [ -n "$REC_PID" ] && kill -9 "$REC_PID" 2>/dev/null
      kill -9 "$SCRIPT_PID" 2>/dev/null; break
    fi
    sleep 0.25; i=$((i+1))
  done
  wait "$SCRIPT_PID" 2>/dev/null
  reap_feeder
}

start_feeder() {
  FEEDER_PID=""; FEEDER_FD=""
  exec 7< <("$@")
  FEEDER_PID=$!
  [ -n "$FEEDER_PID" ] || { exec 7<&-; return 1; }
  FEEDER_FD=7
}

reap_feeder() {
  if [ -n "$FEEDER_PID" ]; then
    kill "$FEEDER_PID" 2>/dev/null
    wait "$FEEDER_PID" 2>/dev/null
  fi
  [ -n "$FEEDER_FD" ] && exec 7<&-
  FEEDER_PID=""; FEEDER_FD=""
}

recording_diag() {
  local cast="$1" serr="$1.script.err" text=""
  [ -s "$serr" ] && text="$(tr '\n' ' ' <"$serr" | head -c 300)"
  note "recording: $(basename "$cast") is $(fsize "$cast" 2>/dev/null || echo 0) bytes; script stderr: [${text:-<empty>}]"
}

pty_probe() {
  if [ "$OS" = Darwin ]; then script -q /dev/null true </dev/null >/dev/null 2>&1
  else script -q -c true /dev/null </dev/null >/dev/null 2>&1; fi
}

# The stdin feeder for the `aitm tui` recording: once the alternate screen has
# been entered AND the flag file exists (the main script touches it after its
# one-shot ran), press `q`, then keep the pipe open.
tui_quit_feeder() {
  local cast="$1" flag="$2" i=0
  while [ "$i" -lt 480 ]; do
    if grep -a -q -F $'\x1b[?1049h' "$cast" 2>/dev/null && [ -e "$flag" ]; then break; fi
    sleep 0.25; i=$((i+1))
  done
  sleep 0.5
  printf 'q'
  exec sleep 60
}

# ===========================================================================
section_card() {
  begin_section "1. default core and its card (AC-R14-1, AC-R14-3, AC-R14-10)"
  main_home
  default_ports_free || { end_section; return; }
  start_default_core plain || { end_section "$ROOT/plain.err"; return; }
  local err="$CORE_ERR" run_dir; run_dir="$(run_dir_for "$HOME_DIR")"
  check "card row 'Bus: stdio (MCP)'" grep -q -x -E 'Bus: stdio \(MCP\)' "$err"
  check "card row 'Operator bus: 127.0.0.1:<port>' (port $BUSPORT)" grep -q -x -E 'Operator bus: 127\.0\.0\.1:[0-9]+' "$err"
  check "the operator bus port is not 0" [ "$BUSPORT" != 0 ]
  check "card row 'Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>'" \
    grep -q -x -F 'Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>' "$err"
  check "checklist: exactly one 'operator token written · <path>' line ($(count_re '^operator token written · ' "$err"))" \
    [ "$(count_re '^operator token written · ' "$err")" = 1 ]
  check "that line names the config path: 'operator token written · $CFG'" grep -q -x -F "operator token written · $CFG" "$err"
  check "config.yaml exists ($CFG)" [ -f "$CFG" ]
  check "config.yaml mode 600" [ "$(fmode "$CFG" 2>/dev/null)" = 600 ]
  check "config.yaml has an 'mcp:' line" grep -q -x -F 'mcp:' "$CFG"
  check "config.yaml has exactly one '  operator_token: <64 hex>' line" [ "$(count_re '^  operator_token: [0-9a-f]{64}$' "$CFG")" = 1 ]
  check "exactly one pointer under $run_dir" [ "$(pointer_count "$HOME_DIR")" = 1 ]
  check "pointer name is <pid>.json for the core's pid $SERVER_PID" [ "$(basename "$PTR")" = "$SERVER_PID.json" ]
  check "pointer mode 600" [ "$(fmode "$PTR" 2>/dev/null)" = 600 ]
  check "run/cores mode 700" [ "$(fmode "$run_dir" 2>/dev/null)" = 700 ]
  check "run mode 700" [ "$(fmode "$(dirname "$run_dir")" 2>/dev/null)" = 700 ]
  local verdict
  verdict="$(python3 - "$PTR" "$SERVER_PID" "127.0.0.1:$BUSPORT" "$CFG" <<'PY'
import json, os, sys
path, pid, bus, cfg = sys.argv[1:5]
raw = open(path, 'rb').read()
problems = []
if not raw.endswith(b'\n') or raw.count(b'\n') != 1:
    problems.append('not one line with a trailing newline')
try:
    obj = json.loads(raw)
except Exception as e:
    print('FAIL: not JSON: %s' % e); sys.exit(1)
want = {'v', 'pid', 'bus', 'operator', 'config', 'started_unix', 'version'}
if set(obj) != want:
    problems.append('keys %s' % sorted(obj))
if obj.get('v') != 1:
    problems.append('v=%r' % obj.get('v'))
if obj.get('pid') != int(pid):
    problems.append('pid=%r (core pid %s)' % (obj.get('pid'), pid))
if obj.get('operator') is not True:
    problems.append('operator=%r' % obj.get('operator'))
if obj.get('bus') != bus:
    problems.append('bus=%r (card says %s)' % (obj.get('bus'), bus))
c = obj.get('config')
if not (isinstance(c, str) and os.path.isabs(c) and os.path.realpath(c) == os.path.realpath(cfg)):
    problems.append('config=%r (want %s)' % (c, cfg))
if not isinstance(obj.get('started_unix'), int):
    problems.append('started_unix=%r' % obj.get('started_unix'))
if not isinstance(obj.get('version'), str):
    problems.append('version=%r' % obj.get('version'))
if problems:
    print('FAIL: ' + '; '.join(problems)); sys.exit(1)
print('OK: keys {v,pid,bus,operator,config,started_unix,version}, v=1, pid=%s, operator=true, bus=%s, config=the default path, version=%s' % (pid, bus, obj['version']))
PY
)"
  local vrc=$?
  note "pointer: $verdict"
  check "pointer content (one JSON line; keys, v, pid, bus, operator, config)" [ "$vrc" = 0 ]
  check "pointer carries no substring of the operator token" [ "$(count_fx "$TOKEN" "$PTR")" = 0 ]
  check "pointer lock is held while the core runs (flock LOCK_SH|LOCK_NB → BlockingIOError)" [ "$(flock_state "$PTR")" = held ]
  if [ "$HAVE_LSOF" = 1 ]; then
    lsof -nP -p "$SERVER_PID" -iTCP -sTCP:LISTEN > "$ROOT/plain.lsof" 2>/dev/null
    check "lsof: the operator bus port $BUSPORT is bound ($(count_fx ":$BUSPORT (LISTEN)" "$ROOT/plain.lsof") LISTEN line)" \
      [ "$(count_fx ":$BUSPORT (LISTEN)" "$ROOT/plain.lsof")" -ge 1 ]
    local off_lo; off_lo="$(grep -a -F ":$BUSPORT (LISTEN)" "$ROOT/plain.lsof" | grep -v -c -F "127.0.0.1:$BUSPORT (LISTEN)")"
    check "lsof: no LISTEN line for port $BUSPORT off 127.0.0.1 ($off_lo)" [ "${off_lo:-0}" = 0 ]
  else
    skip "lsof: the operator bus port is bound on 127.0.0.1 only (lsof not on PATH)"
    skip "lsof: no LISTEN line for the operator bus port off 127.0.0.1 (lsof not on PATH)"
  fi
  end_section "$err" "$CORE_OUT"
}

# ===========================================================================
section_oneshot() {
  begin_section "2. the one-shot acts on it (AC-R14-13, AC-R14-22, AC-R14-26, AC-R14-28)"
  need_default_core plain2 || { end_section "$ROOT/plain2.err"; return; }
  local log audit; log="$(log_path_for "$HOME_DIR")"; audit="$(audit_path_for "$HOME_DIR")"
  oneshot add scope add --host example.com
  check "aitm scope add --host example.com → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "scope add: stdout is exactly 'example.com\\n'" bytes_equal "$ROOT/add.out" $'example.com\n'
  check "scope add: stderr is empty" [ ! -s "$ROOT/add.err" ]
  oneshot list scope list
  check "aitm scope list → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "scope list: stdout is exactly '[\\n  \"example.com\"\\n]\\n'" bytes_equal "$ROOT/list.out" $'[\n  "example.com"\n]\n'
  check "scope list: stderr is empty" [ ! -s "$ROOT/list.err" ]
  # A python operator client: the address from the pointer, the token from the
  # 0600 config (read in-process, never printed), the token line, `initialize`,
  # `tools/call scope.list`.
  local bus_verdict
  bus_verdict="$(python3 - "$PTR" "$CFG" <<'PY'
import json, re, socket, sys
ptr = json.load(open(sys.argv[1]))
m = re.search(r'^  operator_token: (\S+)$', open(sys.argv[2]).read(), re.M)
if not m:
    print('FAIL: no operator_token line in the config'); sys.exit(1)
host, port = ptr['bus'].rsplit(':', 1)
s = socket.create_connection((host, int(port)), timeout=10)
rf = s.makefile('rb')
def send(obj):
    s.sendall((json.dumps(obj) + '\n').encode())
def recv(i):
    while True:
        line = rf.readline()
        if not line:
            print('FAIL: the bus closed the connection before answering id %d' % i); sys.exit(1)
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get('id') == i:
            return msg
send({'token': m.group(1)})
send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
    'protocolVersion': '2025-06-18', 'capabilities': {},
    'clientInfo': {'name': 'oneshot-live-core.sh', 'version': '0'}}})
init = recv(1)
if 'error' in init:
    print('FAIL: initialize error code %s' % init['error'].get('code')); sys.exit(1)
role = init.get('result', {}).get('role')
send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
send({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'scope.list', 'arguments': {}}})
res = recv(2)
if 'error' in res:
    print('FAIL: tools/call error code %s' % res['error'].get('code')); sys.exit(1)
result = res.get('result', {})
if result.get('isError'):
    print('FAIL: tools/call isError'); sys.exit(1)
structured = result.get('structuredContent')
ok = role == 'operator' and structured == ['example.com']
print('%s: role=%s structuredContent=%s' % ('OK' if ok else 'FAIL', role, json.dumps(structured)))
sys.exit(0 if ok else 1)
PY
)"
  local brc=$?
  note "bus client: $bus_verdict"
  check "tools/call scope.list over the operator bus → role operator, [\"example.com\"]" [ "$brc" = 0 ]
  # The core's durable audit log records the one-shot (research F24b).
  local i=0
  while [ "$i" -lt 20 ] && ! grep -a -q -F '"client_label":"aitm-cli"' "$audit" 2>/dev/null; do sleep 0.25; i=$((i+1)); done
  check "audit.jsonl has ≥ 1 line with '\"client_label\":\"aitm-cli\"' ($(count_fx '"client_label":"aitm-cli"' "$audit"))" \
    [ "$(count_fx '"client_label":"aitm-cli"' "$audit")" -ge 1 ]
  local audit_line; audit_line="$(grep -a -F '"client_label":"aitm-cli"' "$audit" 2>/dev/null | grep -a -F '"command":"scope.add"' | head -1)"
  check "that line has '\"command\":\"scope.add\"' and '\"origin\":\"operator\"'" \
    sh -c 'printf "%s" "$1" | grep -q -F "\"origin\":\"operator\""' _ "$audit_line"
  oneshot castatus ca status
  check "aitm ca status → exit 0 (a local verb; rc=$RC)" [ "$RC" = 0 ]
  local med_live med_local
  med_live="$(median_of 11 "$AITM_BIN" scope list)"
  med_local="$(median_of 11 "$AITM_BIN" ca status)"
  note "medians of 11 runs: aitm scope list=${med_live}s · aitm ca status=${med_local}s"
  check "aitm scope list median ($med_live s) <= 2 × aitm ca status median ($med_local s)" \
    awk -v l="$med_live" -v c="$med_local" 'BEGIN { exit !(l <= 2 * c) }'
  token_absent "sections 1-2" "$TOKEN" "$CORE_ERR" "$CORE_OUT" "$ROOT/add.out" "$ROOT/add.err" "$ROOT/list.out" "$ROOT/list.err" \
    "$ROOT/castatus.out" "$ROOT/castatus.err" "$log" "$PTR" "$audit"
  end_section "$ROOT/add.err" "$ROOT/list.err" "$ROOT/castatus.err"
}

# ===========================================================================
section_restart() {
  begin_section "3. second start is quiet; shutdown removes the pointer (AC-R14-3, AC-R14-10, AC-R14-28)"
  need_default_core plain3 || { end_section "$ROOT/plain3.err"; return; }
  local log ptr sum0 mtime0; log="$(log_path_for "$HOME_DIR")"
  # (a) SIGTERM.
  ptr="$PTR"
  kill -TERM "$SERVER_PID" 2>/dev/null
  check "SIGTERM: the pointer is gone within 1 s" wait_gone "$ptr" 1
  stop_server
  check "SIGTERM: exit 0 (rc=$SERVER_RC)" [ "$SERVER_RC" = 0 ]
  sum0="$(sha256_of "$CFG")"; mtime0="$(fmtime "$CFG")"
  # (b) The second start: no minting, the file untouched.
  start_default_core second || { end_section "$ROOT/second.err"; return; }
  check "second start: zero 'operator token written' lines" [ "$(count_fx 'operator token written' "$CORE_ERR")" = 0 ]
  check "second start: the card still has its Operator bus row" grep -q -x -E 'Operator bus: 127\.0\.0\.1:[0-9]+' "$CORE_ERR"
  check "second start: config.yaml bytes unchanged (sha256)" [ "$(sha256_of "$CFG")" = "$sum0" ]
  check "second start: config.yaml mtime unchanged" [ "$(fmtime "$CFG")" = "$mtime0" ]
  check "second start: config.yaml still mode 600" [ "$(fmode "$CFG" 2>/dev/null)" = 600 ]
  check "second start: a pointer exists again ($(basename "$PTR"))" [ -f "$PTR" ]
  ptr="$PTR"
  kill -TERM "$SERVER_PID" 2>/dev/null
  check "second start, SIGTERM: the pointer is gone within 1 s" wait_gone "$ptr" 1
  stop_server
  # (c) Ctrl-C, with the raw tracing stream on (AC-R14-28's RUST_LOG=info run).
  start_default_core third env RUST_LOG=info || { end_section "$ROOT/third.err"; return; }
  check "RUST_LOG=info: the raw stream is on ('INFO aitm_core::proxy: proxy listening')" grep -q -F 'INFO aitm_core::proxy: proxy listening' "$CORE_ERR"
  ptr="$PTR"
  kill -INT "$SERVER_PID" 2>/dev/null
  check "Ctrl-C (SIGINT): the pointer is gone within 1 s" wait_gone "$ptr" 1
  stop_server
  check "Ctrl-C: exit 0 (rc=$SERVER_RC)" [ "$SERVER_RC" = 0 ]
  grep -a -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' "$CORE_ERR" > "$ROOT/third.trace" 2>/dev/null
  token_absent "RUST_LOG=info run ($(wc -l <"$ROOT/third.trace" | tr -d ' ') tracing records)" "$TOKEN" "$CORE_ERR" "$CORE_OUT" "$ROOT/third.trace" "$log"
  # (d) stdin EOF: a default core on /dev/null ends on its own.
  HOME="$HOME_DIR" "$AITM_BIN" >"$ROOT/eof.out" 2>"$ROOT/eof.err" </dev/null &
  local pid=$! i=0 exited=0 erc=""
  TRACKED="$TRACKED $pid"
  while [ "$i" -lt 120 ]; do
    kill -0 "$pid" 2>/dev/null || { exited=1; break; }
    sleep 0.25; i=$((i+1))
  done
  if [ "$exited" = 1 ]; then
    wait "$pid" 2>/dev/null; erc=$?
    pass "stdin EOF: a default core on </dev/null exits on its own (exit $erc)"
  else
    kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; fail "stdin EOF: a default core on </dev/null did not exit within 30 s"
  fi
  check "stdin EOF: the last stderr line is 'stdin closed · stdio MCP transport ended'" [ "$(tail -1 "$ROOT/eof.err")" = 'stdin closed · stdio MCP transport ended' ]
  check "stdin EOF: no pointer remains under run/cores" [ "$(pointer_count "$HOME_DIR")" = 0 ]
  SERVER_PID=""; PTR=""
  end_section "$ROOT/second.err" "$ROOT/eof.err"
}

# ===========================================================================
section_refusals() {
  begin_section "4. refusals with no core (AC-R14-15, AC-R14-18, AC-R14-22)"
  main_home
  [ -n "$SERVER_PID" ] && stop_server
  SERVER_PID=""
  local run_dir; run_dir="$(run_dir_for "$HOME_DIR")"
  check "setup: no core and no pointer in the main HOME ($(pointer_count "$HOME_DIR") pointers)" [ "$(pointer_count "$HOME_DIR")" = 0 ]
  oneshot r1 scope add --host example.com
  check "R1: aitm scope add --host example.com → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "R1: stdout is empty" [ ! -s "$ROOT/r1.out" ]
  check "R1: line 1 is 'error: no running core found'" [ "$(head -1 "$ROOT/r1.err")" = 'error: no running core found' ]
  check "R1: the why line names the config, the run dir and the verb, ending 'Nothing was changed.'" \
    grep -q -x -F "  Looked for a core started from $CFG and for any core published under $run_dir; none is running, so scope add has nothing to change. Nothing was changed." "$ROOT/r1.err"
  check "R1: the fix sentence 'Start aitm, or use the app's Scope page.'" grep -q -x -F "  Start aitm, or use the app's Scope page." "$ROOT/r1.err"
  check "R1: a line exactly '  fix: aitm'" grep -q -x -F '  fix: aitm' "$ROOT/r1.err"
  check "R1: a line starting '  log: '" grep -q -E '^  log: ' "$ROOT/r1.err"
  oneshot r1b proxy status
  check "aitm proxy status with no core → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "aitm proxy status: line 1 is 'error: no running core found'" [ "$(head -1 "$ROOT/r1b.err")" = 'error: no running core found' ]
  oneshot ca4 ca status
  check "aitm ca status with no core → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  local cfg_off="$ROOT/main/off.yaml"
  printf 'mcp:\n  operator_bus:\n    enabled: false\n' > "$cfg_off"
  oneshot r5 --config "$cfg_off" scope list
  check "R5: aitm --config off.yaml scope list → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "R5: line 1 is 'error: this config serves MCP over stdio and no operator bus, which a second client cannot reach'" \
    [ "$(head -1 "$ROOT/r5.err")" = 'error: this config serves MCP over stdio and no operator bus, which a second client cannot reach' ]
  check "R5: the why line names the key, ending 'Nothing was changed.'" \
    grep -q -x -F "  $cfg_off sets mcp.operator_bus.enabled: false, so a core started from it has no address a one-shot can dial. Nothing was changed." "$ROOT/r5.err"
  check "R5: no 'fix:' line" [ "$(count_re '^  fix: ' "$ROOT/r5.err")" = 0 ]
  check "R5: stdout is empty" [ ! -s "$ROOT/r5.out" ]
  end_section "$ROOT/r1.err" "$ROOT/r1b.err" "$ROOT/ca4.err" "$ROOT/r5.err"
}

# ===========================================================================
section_configport() {
  begin_section "5. configured port, nothing there; another core elsewhere (AC-R14-16)"
  new_home configport
  local p cfg_port="$ROOT/configport/port.yaml"
  p="$(free_port)"
  [ -n "$p" ] || { fail "setup: cannot bind a loopback port here (a sandbox?); this section needs real sockets"; end_section; return; }
  printf 'mcp:\n  operator_token: %s\n  transport:\n    loopback_tcp:\n      port: %s\n      token: %s\n' "$(gen_secret)" "$p" "$(gen_secret)" > "$cfg_port"
  oneshot r2 --config "$cfg_port" scope list
  check "R2: aitm --config port.yaml scope list → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "R2: stdout is empty" [ ! -s "$ROOT/r2.out" ]
  check "R2: line 1 is 'error: no running core at 127.0.0.1:$p'" [ "$(head -1 "$ROOT/r2.err")" = "error: no running core at 127.0.0.1:$p" ]
  check "R2: the why line names the config and the port, ending 'Nothing was changed.'" \
    grep -q -x -F "  $cfg_port sets mcp.transport.loopback_tcp.port $p, but nothing is listening there, so scope list has nothing to change. Nothing was changed." "$ROOT/r2.err"
  check "R2: no 'A different core' line while nothing else runs" [ "$(count_fx 'A different core is running at' "$ROOT/r2.err")" = 0 ]
  check "R2: a line exactly '  fix: aitm --config $cfg_port'" grep -q -x -F "  fix: aitm --config $cfg_port" "$ROOT/r2.err"
  default_ports_free || { end_section "$ROOT/r2.err"; return; }
  start_default_core r2core || { end_section "$ROOT/r2core.err"; return; }
  oneshot r2b --config "$cfg_port" scope list
  check "R2 with a default core up: still exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "R2 with a default core up: line 1 is 'error: no running core at 127.0.0.1:$p'" [ "$(head -1 "$ROOT/r2b.err")" = "error: no running core at 127.0.0.1:$p" ]
  check "R2 with a default core up: the body contains 'A different core is running at 127.0.0.1:'" grep -q -F 'A different core is running at 127.0.0.1:' "$ROOT/r2b.err"
  check "R2 with a default core up: that line names the default core's bus port $BUSPORT and pid $SERVER_PID, and ends 'pass --bus 127.0.0.1:$BUSPORT to use it.'" \
    grep -q -E "^  A different core is running at 127\.0\.0\.1:$BUSPORT \(pid $SERVER_PID, started (just now|[0-9]+ (min|h|d) ago), config $(printf '%s' "$CFG" | sed 's/[][\.*^$\/]/\\&/g')\); pass --bus 127\.0\.0\.1:$BUSPORT to use it\.$" "$ROOT/r2b.err"
  stop_server
  token_absent "section 5" "$TOKEN" "$CORE_ERR" "$CORE_OUT" "$ROOT/r2b.out" "$ROOT/r2b.err"
  end_section "$ROOT/r2.err" "$ROOT/r2b.err"
}

# ===========================================================================
section_stale() {
  begin_section "6. stale pointer after SIGKILL (AC-R14-10, AC-R14-17)"
  new_home stale
  default_ports_free || { end_section; return; }
  start_default_core stale || { end_section "$ROOT/stale.err"; return; }
  local ptr="$PTR"
  kill -KILL "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
  sleep 0.5
  check "the pointer survives SIGKILL" [ -f "$ptr" ]
  check "its lock is released (flock LOCK_SH|LOCK_NB succeeds)" [ "$(flock_state "$ptr")" = free ]
  oneshot r1k scope list
  check "aitm scope list → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "line 1 is 'error: no running core found' (R1, not R4)" [ "$(head -1 "$ROOT/r1k.err")" = 'error: no running core found' ]
  check "'no running core at' appears nowhere (nothing was dialed)" [ "$(count_fx 'no running core at' "$ROOT/r1k.err")" = 0 ]
  check "stdout is empty" [ ! -s "$ROOT/r1k.out" ]
  check "the stale pointer was deleted by the one-shot" [ ! -e "$ptr" ]
  end_section "$ROOT/r1k.err"
}

# ===========================================================================
section_twocores() {
  begin_section "7. two cores (AC-R14-19, plan C14)"
  new_home two
  default_ports_free || { end_section; return; }
  start_default_core a || { end_section "$ROOT/a.err"; return; }
  local a_pid="$SERVER_PID" a_port="$BUSPORT" a_token="$TOKEN"
  local lb bb lc cfg_b="$ROOT/two/b.yaml" cfg_c="$ROOT/two/c.yaml"
  lb="$(free_port)"; bb="$(free_port)"; lc="$(free_port)"
  printf 'listen: 127.0.0.1:%s\nbrowser:\n  proxy_addr: 127.0.0.1:%s\n' "$lb" "$bb" > "$cfg_b"
  printf 'listen: 127.0.0.1:%s\n' "$lc" > "$cfg_c"
  start_core "$ROOT/b.out" "$ROOT/b.err" "$AITM_BIN" --config "$cfg_b"
  local b_pid="$SERVER_PID"
  wait_for "$ROOT/b.err" '^Log: ' 30 || note "core B's ready card not seen (the server exited, or 30 s passed)"
  check "core B minted its own token into b.yaml" [ "$(count_re '^  operator_token: [0-9a-f]{64}$' "$cfg_b")" = 1 ]
  check "two pointers under run/cores ($(pointer_count "$HOME_DIR"))" [ "$(pointer_count "$HOME_DIR")" = 2 ]
  oneshot r11 --config "$cfg_c" scope list
  check "R11: aitm --config c.yaml scope list → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "R11: stdout is empty" [ ! -s "$ROOT/r11.out" ]
  check "R11: line 1 is 'error: two running cores found'" [ "$(head -1 "$ROOT/r11.err")" = 'error: two running cores found' ]
  check "R11: two lines '  127.0.0.1:<port> · pid <pid> · started <age> · <config>' ($(count_re '^  127\.0\.0\.1:[0-9]+ · pid [0-9]+ · started (just now|[0-9]+ (min|h|d) ago) · /' "$ROOT/r11.err"))" \
    [ "$(count_re '^  127\.0\.0\.1:[0-9]+ · pid [0-9]+ · started (just now|[0-9]+ (min|h|d) ago) · /' "$ROOT/r11.err")" = 2 ]
  check "R11: core A's line names its port, pid and the default config" grep -q -E "^  127\.0\.0\.1:$a_port · pid $a_pid · started (just now|[0-9]+ (min|h|d) ago) · $(printf '%s' "$CFG" | sed 's/[][\.*^$\/]/\\&/g')$" "$ROOT/r11.err"
  check "R11: core B's line names its pid and b.yaml" grep -q -E "^  127\.0\.0\.1:[0-9]+ · pid $b_pid · started (just now|[0-9]+ (min|h|d) ago) · $(printf '%s' "$cfg_b" | sed 's/[][\.*^$\/]/\\&/g')$" "$ROOT/r11.err"
  check "R11: 'Neither was started from <c.yaml>, so aitm cannot tell which one scope list means. Nothing was changed.'" \
    grep -q -x -F "  Neither was started from $cfg_c, so aitm cannot tell which one scope list means. Nothing was changed." "$ROOT/r11.err"
  check "R11: a line exactly '  fix: aitm --bus <addr> scope list'" grep -q -x -F '  fix: aitm --bus <addr> scope list' "$ROOT/r11.err"
  # The explicit override: core A's token copied (by the printf builtin, under
  # umask 077) into a 0600 file.
  local tokfile="$ROOT/two/a.token"
  printf '%s\n' "$a_token" > "$tokfile"
  check "the token file is mode 600" [ "$(fmode "$tokfile" 2>/dev/null)" = 600 ]
  oneshot r11b --bus "127.0.0.1:$a_port" --token-file "$tokfile" scope list
  check "aitm --bus 127.0.0.1:$a_port --token-file <file> scope list → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly '[]\\n' (core A's empty Scope)" bytes_equal "$ROOT/r11b.out" $'[]\n'
  check "…stderr is empty" [ ! -s "$ROOT/r11b.err" ]
  stop_server "$b_pid"; stop_server "$a_pid"; SERVER_PID=""
  check "both pointers are gone after SIGTERM ($(pointer_count "$HOME_DIR"))" [ "$(pointer_count "$HOME_DIR")" = 0 ]
  local b_token; b_token="$(token_in "$cfg_b")"
  token_absent "section 7 (core A's token)" "$a_token" "$ROOT/a.err" "$ROOT/a.out" "$ROOT/b.err" "$ROOT/b.out" "$ROOT/r11.err" "$ROOT/r11.out" "$ROOT/r11b.err" "$ROOT/r11b.out" "$(log_path_for "$HOME_DIR")"
  token_absent "section 7 (core B's token)" "$b_token" "$ROOT/a.err" "$ROOT/a.out" "$ROOT/b.err" "$ROOT/b.out" "$ROOT/r11.err" "$ROOT/r11.out" "$ROOT/r11b.err" "$ROOT/r11b.out" "$(log_path_for "$HOME_DIR")"
  end_section "$ROOT/r11.err" "$ROOT/r11b.err" "$ROOT/b.err"
}

# ===========================================================================
section_rotated() {
  begin_section "8. rotated token (AC-R14-4, AC-R14-20)"
  new_home rotated
  default_ports_free || { end_section; return; }
  start_default_core rot || { end_section "$ROOT/rot.err"; return; }
  local old_token="$TOKEN"
  HOME="$HOME_DIR" "$AITM_BIN" operator-token generate --force >"$ROOT/rot-gen.out" 2>"$ROOT/rot-gen.err" </dev/null; local grc=$?
  check "aitm operator-token generate --force → exit 0 (rc=$grc)" [ "$grc" = 0 ]
  check "…stdout contains 'operator access enabled'" grep -q -F 'operator access enabled' "$ROOT/rot-gen.out"
  check "…config.yaml stays mode 600" [ "$(fmode "$CFG" 2>/dev/null)" = 600 ]
  check "…still exactly one '  operator_token: <64 hex>' line" [ "$(count_re '^  operator_token: [0-9a-f]{64}$' "$CFG")" = 1 ]
  TOKEN="$(token_in "$CFG")"
  check "…config.yaml still holds a token" [ -n "$TOKEN" ]
  check "…the token value changed" [ "$TOKEN" != "$old_token" ]
  oneshot r7 scope list
  check "R7: aitm scope list → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "R7: stdout is empty" [ ! -s "$ROOT/r7.out" ]
  check "R7: line 1 is 'error: the core at 127.0.0.1:$BUSPORT refused the operator token in $CFG'" \
    [ "$(head -1 "$ROOT/r7.err")" = "error: the core at 127.0.0.1:$BUSPORT refused the operator token in $CFG" ]
  check "R7: the why line 'The config changed after that core started; a rotated token only takes effect on restart. Nothing was changed.'" \
    grep -q -x -F '  The config changed after that core started; a rotated token only takes effect on restart. Nothing was changed.' "$ROOT/r7.err"
  check "R7: the fix sentence 'Restart the core, or pass --config for the config it was started with.'" \
    grep -q -x -F '  Restart the core, or pass --config for the config it was started with.' "$ROOT/r7.err"
  check "R7: no 'fix:' command line" [ "$(count_re '^  fix: ' "$ROOT/r7.err")" = 0 ]
  stop_server
  start_default_core rot2 || { end_section "$ROOT/rot2.err"; return; }
  check "the restarted core prints no 'operator token written' line" [ "$(count_fx 'operator token written' "$CORE_ERR")" = 0 ]
  oneshot r7b scope list
  check "after the restart: aitm scope list → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly '[]\\n'" bytes_equal "$ROOT/r7b.out" $'[]\n'
  stop_server
  token_absent "section 8 (the rotated token)" "$TOKEN" "$ROOT/rot.err" "$ROOT/rot.out" "$ROOT/rot-gen.out" "$ROOT/rot-gen.err" "$ROOT/r7.err" "$ROOT/r7.out" "$ROOT/rot2.err" "$ROOT/rot2.out" "$ROOT/r7b.err" "$ROOT/r7b.out" "$(log_path_for "$HOME_DIR")"
  token_absent "section 8 (the old token)" "$old_token" "$ROOT/rot.err" "$ROOT/rot.out" "$ROOT/rot-gen.out" "$ROOT/rot-gen.err" "$ROOT/r7.err" "$ROOT/r7.out" "$(log_path_for "$HOME_DIR")"
  end_section "$ROOT/rot-gen.err" "$ROOT/r7.err" "$ROOT/r7b.err"
}

# ===========================================================================
section_gate() {
  begin_section "9. Cli-only gate (AC-R14-21)"
  new_home gate
  default_ports_free || { end_section; return; }
  start_default_core gate || { end_section "$ROOT/gate.err"; return; }
  oneshot r9 tls passthrough add --host example.com
  check "R9: aitm tls passthrough add --host example.com → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "R9: stdout is empty" [ ! -s "$ROOT/r9.out" ]
  check "R9: line 1 starts 'error: tls.passthrough.add refused:'" starts_with "$(head -1 "$ROOT/r9.err")" 'error: tls.passthrough.add refused:'
  check "R9: the body names the core's address ('This one-shot reached the core at 127.0.0.1:$BUSPORT as an operator')" \
    grep -q -F "This one-shot reached the core at 127.0.0.1:$BUSPORT as an operator" "$ROOT/r9.err"
  check "R9: the body says 'The app and the TUI are refused by the same gate.'" grep -q -F 'The app and the TUI are refused by the same gate.' "$ROOT/r9.err"
  check "R9: the body ends 'Nothing was changed.'" grep -q -F 'Nothing was changed.' "$ROOT/r9.err"
  check "R9: no 'fix:' line" [ "$(count_re '^  fix: ' "$ROOT/r9.err")" = 0 ]
  oneshot r9b tls passthrough list
  check "aitm tls passthrough list → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly '[]\\n' (the add did not happen)" bytes_equal "$ROOT/r9b.out" $'[]\n'
  stop_server
  end_section "$ROOT/r9.err" "$ROOT/r9b.err"
}

# ===========================================================================
section_explicit() {
  begin_section "10. explicit override and usage errors (AC-R14-23, AC-R14-25)"
  new_home explicit
  default_ports_free || { end_section; return; }
  start_default_core explicit || { end_section "$ROOT/explicit.err"; return; }
  local tokfile="$ROOT/explicit/bus.token"
  printf '%s\n' "$TOKEN" > "$tokfile"
  oneshot x1 --bus "127.0.0.1:$BUSPORT" --token-file "$tokfile" scope list
  check "aitm --bus 127.0.0.1:$BUSPORT --token-file <0600 file> scope list → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly '[]\\n'" bytes_equal "$ROOT/x1.out" $'[]\n'
  # The env form: the token goes from the shell variable into the child's
  # environment (a bash prefix assignment, not `env`, so no argv shows it).
  export AITM_BUS="127.0.0.1:$BUSPORT" AITM_BUS_TOKEN="$TOKEN"
  oneshot x2 scope list
  unset AITM_BUS AITM_BUS_TOKEN
  check "AITM_BUS=127.0.0.1:$BUSPORT AITM_BUS_TOKEN=… aitm scope list → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly '[]\\n'" bytes_equal "$ROOT/x2.out" $'[]\n'
  oneshot x3 --bus 10.0.0.5:9090 --token-file x scope list
  check "aitm --bus 10.0.0.5:9090 --token-file x scope list → exit 2 (rc=$RC)" [ "$RC" = 2 ]
  check "…stderr has 'error: --bus 10.0.0.5:9090 is not a loopback address'" grep -q -F 'error: --bus 10.0.0.5:9090 is not a loopback address' "$ROOT/x3.err"
  check "…and 'The operator bus is loopback-only; a core elsewhere needs a local tunnel.'" grep -q -F 'The operator bus is loopback-only; a core elsewhere needs a local tunnel.' "$ROOT/x3.err"
  oneshot x4 --bus 127.0.0.1:1 scope list
  check "aitm --bus 127.0.0.1:1 scope list (no token) → exit 2 (rc=$RC)" [ "$RC" = 2 ]
  check "…stderr has '--bus needs --token-file <path> or AITM_BUS_TOKEN'" grep -q -F -- '--bus needs --token-file <path> or AITM_BUS_TOKEN' "$ROOT/x4.err"
  oneshot x5 --bus 127.0.0.1:1 --token-file x ca status
  check "aitm --bus 127.0.0.1:1 --token-file x ca status → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stderr has exactly one line 'warning: --bus ignored · ca status runs on this machine, not on a core' ($(count_re '^warning: --bus ignored · ca status runs on this machine, not on a core$' "$ROOT/x5.err"))" \
    [ "$(count_re '^warning: --bus ignored · ca status runs on this machine, not on a core$' "$ROOT/x5.err")" = 1 ]
  # R10: a listener that accepts and never answers.
  local hp hang t0 t1 took
  hp="$(free_port)"; hang="$(hold_silent "$hp")"
  if wait_port_listening "$hp" 10; then
    export AITM_BUS="127.0.0.1:$hp" AITM_BUS_TOKEN=x
    t0="$(now_s)"; oneshot x6 scope list; t1="$(now_s)"
    unset AITM_BUS AITM_BUS_TOKEN
    took="$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }')"
    check "R10: AITM_BUS at a silent listener: aitm scope list → exit 1 (rc=$RC)" [ "$RC" = 1 ]
    check "R10: …within 4 s (took ${took}s)" awk -v t="$took" 'BEGIN { exit !(t <= 4.0) }'
    check "R10: line 1 is 'error: the core at 127.0.0.1:$hp accepted the connection but did not answer within 2 s'" \
      [ "$(head -1 "$ROOT/x6.err")" = "error: the core at 127.0.0.1:$hp accepted the connection but did not answer within 2 s" ]
    check "R10: exactly one 'did not answer within 2 s' ($(count_fx 'did not answer within 2 s' "$ROOT/x6.err"))" [ "$(count_fx 'did not answer within 2 s' "$ROOT/x6.err")" = 1 ]
    check "R10: the why line 'The call may still be running there. Whether anything changed is unknown.'" \
      grep -q -x -F '  The call may still be running there. Whether anything changed is unknown.' "$ROOT/x6.err"
  else
    fail "setup: the silent listener never listened on $hp"
  fi
  kill "$hang" 2>/dev/null
  # R2': a listener that accepts and closes at once.
  local cp closer
  cp="$(free_port)"; closer="$(hold_closing "$cp")"
  if wait_port_listening "$cp" 10; then
    export AITM_BUS="127.0.0.1:$cp" AITM_BUS_TOKEN=x
    oneshot x7 scope list
    unset AITM_BUS AITM_BUS_TOKEN
    check "R2': AITM_BUS at a listener that closes at once: aitm scope list → exit 1 (rc=$RC)" [ "$RC" = 1 ]
    check "R2': line 1 is 'error: no running core at 127.0.0.1:$cp'" [ "$(head -1 "$ROOT/x7.err")" = "error: no running core at 127.0.0.1:$cp" ]
    check "R2': the why line 'Nothing is listening at the address AITM_BUS named, so scope list has nothing to change. Nothing was changed.'" \
      grep -q -x -F '  Nothing is listening at the address AITM_BUS named, so scope list has nothing to change. Nothing was changed.' "$ROOT/x7.err"
    check "R2': a line exactly '  fix: aitm'" grep -q -x -F '  fix: aitm' "$ROOT/x7.err"
  else
    fail "setup: the closing listener never listened on $cp"
  fi
  kill "$closer" 2>/dev/null
  stop_server
  token_absent "section 10" "$TOKEN" "$CORE_ERR" "$CORE_OUT" "$ROOT/x1.out" "$ROOT/x1.err" "$ROOT/x2.out" "$ROOT/x2.err" "$ROOT/x3.err" "$ROOT/x4.err" "$ROOT/x5.err" "$ROOT/x6.err" "$ROOT/x7.err" "$(log_path_for "$HOME_DIR")"
  end_section "$ROOT/x3.err" "$ROOT/x4.err" "$ROOT/x5.err" "$ROOT/x6.err" "$ROOT/x7.err"
}

# ===========================================================================
section_optout() {
  begin_section "11. opt-out and fixed port on the card (AC-R14-5, AC-R14-8, AC-R14-9)"
  new_home optout
  default_ports_free || { end_section; return; }
  local cfg_off="$ROOT/optout/off.yaml" cfg_fixed="$ROOT/optout/fixed.yaml" fp
  printf 'mcp:\n  operator_bus:\n    enabled: false\n' > "$cfg_off"
  start_core "$ROOT/off.out" "$ROOT/off.err" "$AITM_BIN" --config "$cfg_off"
  wait_for "$ROOT/off.err" '^Log: ' 30 || note "opt-out core's ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "opt-out: card row 'Operator bus: off · mcp.operator_bus.enabled: false'" grep -q -x -F 'Operator bus: off · mcp.operator_bus.enabled: false' "$ROOT/off.err"
  check "opt-out: the Scope row is exactly 'Scope: Nothing is decrypted until a host is in Scope.' (no next step)" \
    grep -q -x -F 'Scope: Nothing is decrypted until a host is in Scope.' "$ROOT/off.err"
  check "opt-out: no token written into off.yaml" [ "$(count_fx operator_token "$cfg_off")" = 0 ]
  check "opt-out: no 'operator token written' line" [ "$(count_fx 'operator token written' "$ROOT/off.err")" = 0 ]
  check "opt-out: no pointer published (no bus to point at)" [ "$(pointer_count "$HOME_DIR")" = 0 ]
  check "opt-out: exit 0 after SIGTERM (rc=$SERVER_RC)" [ "$SERVER_RC" = 0 ]
  fp="$(free_port)"
  [ -n "$fp" ] || { fail "setup: cannot bind a loopback port here"; end_section; return; }
  printf 'mcp:\n  operator_bus:\n    port: %s\n' "$fp" > "$cfg_fixed"
  start_core "$ROOT/fixed.out" "$ROOT/fixed.err" "$AITM_BIN" --config "$cfg_fixed"
  wait_for "$ROOT/fixed.err" '^Log: ' 30 || note "fixed-port core's ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "fixed port: card row 'Operator bus: 127.0.0.1:$fp'" grep -q -x -F "Operator bus: 127.0.0.1:$fp" "$ROOT/fixed.err"
  check "fixed port: the first run minted a token into fixed.yaml" [ "$(count_re '^  operator_token: [0-9a-f]{64}$' "$cfg_fixed")" = 1 ]
  local holder; holder="$(hold_port "$fp")"
  if wait_port_listening "$fp" 10; then
    run_bounded "$ROOT/held.out" "$ROOT/held.err" 20 "$AITM_BIN" --config "$cfg_fixed"
    check "held operator bus port: exit 1 (rc=$RC)" [ "$RC" = 1 ]
    check "held operator bus port: headline 'error: cannot start: the operator bus port 127.0.0.1:$fp is already in use'" \
      grep -q -x -F "error: cannot start: the operator bus port 127.0.0.1:$fp is already in use" "$ROOT/held.err"
    check "held operator bus port: the remedy names mcp.operator_bus.port" grep -q -F 'mcp.operator_bus.port' "$ROOT/held.err"
    check "held operator bus port: the remedy is 'Free it, or set mcp.operator_bus.port to another port in $cfg_fixed.'" \
      grep -q -F "Free it, or set mcp.operator_bus.port to another port in $cfg_fixed." "$ROOT/held.err"
    check "held operator bus port: stdout is empty" [ ! -s "$ROOT/held.out" ]
    check "held operator bus port: no 'Log:' card row (never ready)" [ "$(count_re '^Log: ' "$ROOT/held.err")" = 0 ]
  else
    fail "setup: the port holder never listened on $fp"
  fi
  kill "$holder" 2>/dev/null
  end_section "$ROOT/off.err" "$ROOT/fixed.err" "$ROOT/held.err"
}

# ===========================================================================
section_shared() {
  begin_section "12. shared bus (AC-R14-6)"
  new_home shared
  local lp bp sp cfg_shared="$ROOT/shared/shared.yaml"
  lp="$(free_port)"; bp="$(free_port)"; sp="$(free_port)"
  if [ -z "$lp" ] || [ -z "$bp" ] || [ -z "$sp" ]; then
    fail "setup: cannot bind a loopback port here (a sandbox?); this section needs real sockets"; end_section; return
  fi
  printf 'listen: 127.0.0.1:%s\nbrowser:\n  proxy_addr: 127.0.0.1:%s\nmcp:\n  transport:\n    loopback_tcp:\n      port: %s\n      token: %s\n' "$lp" "$bp" "$sp" "$(gen_secret)" > "$cfg_shared"
  start_core "$ROOT/shared.out" "$ROOT/shared.err" "$AITM_BIN" --config "$cfg_shared"
  wait_for "$ROOT/shared.err" '^Log: ' 30 || note "shared-bus core's ready card not seen (the server exited, or 30 s passed)"
  local token; token="$(token_in "$cfg_shared")"
  check "the first run minted a token: 'operator token written · $cfg_shared'" grep -q -x -F "operator token written · $cfg_shared" "$ROOT/shared.err"
  check "shared.yaml has exactly one '  operator_token: <64 hex>' line" [ "$(count_re '^  operator_token: [0-9a-f]{64}$' "$cfg_shared")" = 1 ]
  check "shared.yaml is mode 600 afterwards" [ "$(fmode "$cfg_shared" 2>/dev/null)" = 600 ]
  check "the agent token line is still there" grep -q -E '^      token: [0-9a-f]{32}$' "$cfg_shared"
  check "card row 'Bus: loopback 127.0.0.1:$sp · operator'" grep -q -x -F "Bus: loopback 127.0.0.1:$sp · operator" "$ROOT/shared.err"
  check "no 'Operator bus:' row" [ "$(count_re '^Operator bus: ' "$ROOT/shared.err")" = 0 ]
  check "the Scope row carries the next step" grep -q -x -F 'Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>' "$ROOT/shared.err"
  wait_pointer "$(run_dir_for "$HOME_DIR")" 5 || true
  local ptr; ptr="$(pointers_in "$(run_dir_for "$HOME_DIR")" | head -1)"
  check "one pointer, and it names the shared bus 127.0.0.1:$sp with operator true" \
    sh -c '[ -n "$1" ] && grep -q -F "\"bus\":\"127.0.0.1:$2\",\"operator\":true" "$1"' _ "$ptr" "$sp"
  if [ "$HAVE_LSOF" = 1 ]; then
    lsof -nP -p "$SERVER_PID" -iTCP -sTCP:LISTEN > "$ROOT/shared.lsof" 2>/dev/null
    local others; others="$(grep -a -F '(LISTEN)' "$ROOT/shared.lsof" | grep -v -F ":$lp (LISTEN)" | grep -v -F ":$bp (LISTEN)" | grep -c -F '(LISTEN)')"
    check "lsof: exactly one bus listener besides the proxy ($lp) and browser ($bp) ports ($others)" [ "${others:-0}" = 1 ]
    check "lsof: that listener is 127.0.0.1:$sp" grep -q -F "127.0.0.1:$sp (LISTEN)" "$ROOT/shared.lsof"
  else
    skip "lsof: the process holds exactly one bus listener (lsof not on PATH)"
  fi
  oneshot sadd --config "$cfg_shared" scope add --host example.com
  check "aitm --config shared.yaml scope add --host example.com → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly 'example.com\\n'" bytes_equal "$ROOT/sadd.out" $'example.com\n'
  check "…stderr is empty" [ ! -s "$ROOT/sadd.err" ]
  stop_server
  check "exit 0 after SIGTERM (rc=$SERVER_RC)" [ "$SERVER_RC" = 0 ]
  check "the pointer is gone" [ "$(pointer_count "$HOME_DIR")" = 0 ]
  token_absent "section 12" "$token" "$ROOT/shared.err" "$ROOT/shared.out" "$ROOT/sadd.out" "$ROOT/sadd.err" "$(log_path_for "$HOME_DIR")"
  end_section "$ROOT/shared.err" "$ROOT/sadd.err"
}

# ===========================================================================
section_surfaces() {
  begin_section "13. aitm web and aitm tui (AC-R14-2, AC-R14-14)"
  new_home surfaces
  default_ports_free || { end_section; return; }
  local wp; wp="$(free_port)"
  [ -n "$wp" ] || { fail "setup: cannot bind a loopback port here"; end_section; return; }
  start_core "$ROOT/web.out" "$ROOT/web.err" "$AITM_BIN" web --no-open --listen "127.0.0.1:$wp"
  wait_for "$ROOT/web.err" '^Log: ' 30 || note "aitm web's ready card not seen (the server exited, or 30 s passed)"
  check "aitm web: card row 'Operator bus: 127.0.0.1:<port>'" grep -q -x -E 'Operator bus: 127\.0\.0\.1:[0-9]+' "$ROOT/web.err"
  check "aitm web: card row 'Operator: http://127.0.0.1:$wp/#t=…&expect=operator'" grep -q -E "^Operator: http://127\.0\.0\.1:$wp/#t=[^&[:space:]]+&expect=operator$" "$ROOT/web.err"
  check "aitm web: a pointer exists" [ "$(pointer_count "$HOME_DIR")" = 1 ]
  oneshot wadd scope add --host example.com
  check "against aitm web: aitm scope add --host example.com → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly 'example.com\\n'" bytes_equal "$ROOT/wadd.out" $'example.com\n'
  oneshot wlist scope list
  check "against aitm web: aitm scope list → exit 0 with the two-line array (rc=$RC)" sh -c '[ "$1" = 0 ] && printf "%s" "$2" | cmp -s - "$3"' _ "$RC" $'[\n  "example.com"\n]\n' "$ROOT/wlist.out"
  stop_server
  check "aitm web: exit 0 after SIGTERM (rc=$SERVER_RC)" [ "$SERVER_RC" = 0 ]
  check "aitm web: the pointer is gone" [ "$(pointer_count "$HOME_DIR")" = 0 ]
  local tok; tok="$(token_in "$CFG")"
  token_absent "section 13 (aitm web)" "$tok" "$ROOT/web.err" "$ROOT/web.out" "$ROOT/wadd.out" "$ROOT/wadd.err" "$ROOT/wlist.out" "$ROOT/wlist.err" "$(log_path_for "$HOME_DIR")"

  local no_tty=""
  if [ ! -t 1 ]; then
    no_tty="stdout is not a TTY: run the script directly in a terminal, not through a pipe"
  elif ! pty_probe; then
    no_tty="script cannot allocate a pty here"
  fi
  if [ -n "$no_tty" ]; then
    skip "aitm tui: pointer while it runs, a one-shot reaches it, gone after q ($no_tty)"
    end_section "$ROOT/web.err" "$ROOT/wadd.err"
    return
  fi
  local cast="$ROOT/tui.cast" flag="$ROOT/surfaces/tui-oneshot-done" run_dir i=0
  run_dir="$(run_dir_for "$HOME_DIR")"
  if start_feeder tui_quit_feeder "$cast" "$flag"; then
    start_recording "$cast" env TERM="$REC_TERM" "$AITM_BIN" tui
    [ -n "$REC_PID" ] || { note "aitm tui recording: aitm child of script(${SCRIPT_PID:-none}) not found"; recording_diag "$cast"; }
    if wait_pointer "$run_dir" 15; then
      pass "aitm tui: a pointer exists under run/cores while it runs"
    else
      fail "aitm tui: no pointer appeared under run/cores within 15 s"; recording_diag "$cast"
    fi
    oneshot tadd scope add --host example.com
    check "against aitm tui: aitm scope add --host example.com → exit 0 (rc=$RC)" [ "$RC" = 0 ]
    check "…stdout is exactly 'example.com\\n'" bytes_equal "$ROOT/tadd.out" $'example.com\n'
    : > "$flag"
    while kill -0 "$SCRIPT_PID" 2>/dev/null && [ "$i" -lt 200 ]; do sleep 0.25; i=$((i+1)); done
    if kill -0 "$SCRIPT_PID" 2>/dev/null; then
      fail "aitm tui did not exit on 'q' within 50 s; sending Ctrl-C"
    else
      pass "aitm tui exited on 'q'"
    fi
    end_recording INT
    check "aitm tui: the pointer is gone after q" [ "$(pointer_count "$HOME_DIR")" = 0 ]
    check "aitm tui: the alternate screen was entered (ESC[?1049h in the cast)" grep -a -q -F $'\x1b[?1049h' "$cast"
  else
    fail "aitm tui recording: cannot open a feeder pipe"
  fi
  end_section "$ROOT/web.err" "$ROOT/wadd.err" "$ROOT/tadd.err"
}

# ===========================================================================
section_rundir() {
  begin_section "14. AITM_RUN_DIR (AC-R14-11)"
  new_home rundir
  default_ports_free || { end_section; return; }
  local rd="$ROOT/rundir/run" default_dir
  default_dir="$(default_run_dir_for "$HOME_DIR")"
  export AITM_RUN_DIR="$rd"
  if ! start_default_core rundir; then unset AITM_RUN_DIR; end_section "$ROOT/rundir.err"; return; fi
  check "the pointer is under \$AITM_RUN_DIR ($rd)" [ "$(pointers_in "$rd" | wc -l | tr -d ' ')" = 1 ]
  check "\$AITM_RUN_DIR is mode 700" [ "$(fmode "$rd" 2>/dev/null)" = 700 ]
  check "nothing was written under the default run dir ($default_dir)" sh -c '[ ! -e "$1" ] || [ -z "$(ls -A "$1")" ]' _ "$default_dir"
  oneshot rl scope list
  check "with AITM_RUN_DIR: aitm scope list → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  check "…stdout is exactly '[]\\n'" bytes_equal "$ROOT/rl.out" $'[]\n'
  oneshot radd scope add --host example.com
  check "with AITM_RUN_DIR: aitm scope add --host example.com → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  stop_server
  check "the pointer under \$AITM_RUN_DIR is gone after SIGTERM" [ "$(pointers_in "$rd" | wc -l | tr -d ' ')" = 0 ]
  check "still nothing under the default run dir" sh -c '[ ! -e "$1" ] || [ -z "$(ls -A "$1")" ]' _ "$default_dir"
  unset AITM_RUN_DIR
  end_section "$ROOT/rundir.err" "$ROOT/rl.err" "$ROOT/radd.err"
}

# ===========================================================================
section_w1pins() {
  begin_section "15. W1 pins: cli-startup.sh and term-reporting.sh (AC-R14-27)"
  local log="$ROOT/cli-startup.log" rc res
  if [ -x "$here/cli-startup.sh" ]; then
    note "running cli-startup.sh (a few minutes)…"
    AITM_BIN="$AITM_BIN" "$here/cli-startup.sh" >"$log" 2>&1; rc=$?
    res="$(grep -a '^RESULT:' "$log" | tail -1)"
    note "cli-startup.sh: ${res:-<no RESULT line>} (exit $rc)"
    if [ "$rc" = 0 ] && printf '%s\n' "$res" | grep -q ', 0 failed,'; then
      pass "cli-startup.sh → $res"
    else
      fail "cli-startup.sh: exit $rc, ${res:-no RESULT line}"
      grep -a -E '^  FAIL' "$log" | head -10 | sed 's/^/  | /'
    fi
  else
    fail "$here/cli-startup.sh is missing or not executable"
  fi
  local log2="$ROOT/term-reporting.log"
  if [ -x "$here/term-reporting.sh" ]; then
    # Its own section selector must not inherit ours: `all`, explicitly.
    if [ -t 1 ] && pty_probe; then
      note "running term-reporting.sh under script -q so its §14 recordings run (several minutes; it runs cli-startup.sh again in its §11)…"
      if [ "$OS" = Darwin ]; then
        AITM_BIN="$AITM_BIN" AITM_TERM_SECTIONS=all script -q -t 0 "$log2" "$here/term-reporting.sh"; rc=$?
      else
        AITM_BIN="$AITM_BIN" AITM_TERM_SECTIONS=all script -q -e -f -c "'$here/term-reporting.sh'" "$log2"; rc=$?
      fi
      res="$(tr -d '\r' <"$log2" | grep -a '^RESULT:' | tail -1)"
      note "term-reporting.sh: ${res:-<no RESULT line>} (script exit $rc)"
      # Under `script` the RESULT line is the verdict (BSD `script` does not
      # relay the child's exit status).
      if [ -n "$res" ] && printf '%s\n' "$res" | grep -q ', 0 failed,'; then
        pass "term-reporting.sh → $res"
      else
        fail "term-reporting.sh: ${res:-no RESULT line} (script exit $rc)"
        tr -d '\r' <"$log2" | grep -a -E '^  FAIL' | head -10 | redact | sed 's/^/  | /'
      fi
    else
      note "running term-reporting.sh directly (no TTY: its §14 SKIPs; several minutes)…"
      AITM_BIN="$AITM_BIN" AITM_TERM_SECTIONS=all "$here/term-reporting.sh" >"$log2" 2>&1; rc=$?
      res="$(grep -a '^RESULT:' "$log2" | tail -1)"
      note "term-reporting.sh: ${res:-<no RESULT line>} (exit $rc)"
      if [ "$rc" = 0 ] && printf '%s\n' "$res" | grep -q ', 0 failed,'; then
        pass "term-reporting.sh → $res"
      else
        fail "term-reporting.sh: exit $rc, ${res:-no RESULT line}"
        grep -a -E '^  FAIL' "$log2" | head -10 | redact | sed 's/^/  | /'
      fi
    fi
  else
    fail "$here/term-reporting.sh is missing or not executable"
  fi
  end_section
}

# ===========================================================================
# doc_grep <file> <fixed needle> <expected count>
doc_grep() {
  local f="$1" needle="$2" want="$3" n
  n="$(count_fx "$needle" "$repo_root/$f")"
  check "grep -c '$needle' $f → $want ($n)" [ "$n" = "$want" ]
}

section_docs() {
  begin_section "16. docs (AC-R14-30)"
  doc_grep README.md 'does not steer a proxy that is already running' 0
  doc_grep site/docs.html 'The CLI is one-shot' 0
  doc_grep docs/scanner.md 'one-shot, in-process' 0
  doc_grep README.md 'No `cli` line is written today' 0
  doc_grep site/docs.html 'The CLI talks to the running core' 1
  doc_grep INSTALL.md 'mints `mcp.operator_token`' 1
  # The D13 addendum (the site items as whole elements; spec AC-R14-30 gains).
  doc_grep site/features.html 'runs its own core' 0
  doc_grep site/features.html 'has no browser' 0
  doc_grep site/poc.html 'has no browser' 0
  doc_grep docs/scanner.md 'not the one-shot CLI' 0
  doc_grep site/poc.html 'poc_path pocs/reflected-xss-search-q.yaml' 1
  doc_grep site/index.html 'does not steer a proxy that is already running' 0
  doc_grep site/index.html 'the self-contained ones also run one-shot' 0
  doc_grep site/features.html 'the self-contained ones also run one-shot' 0
  end_section
}

# ===========================================================================
want 1  card       && section_card
want 2  oneshot    && section_oneshot
want 3  restart    && section_restart
want 4  refusals   && section_refusals
want 5  configport && section_configport
want 6  stale      && section_stale
want 7  twocores   && section_twocores
want 8  rotated    && section_rotated
want 9  gate       && section_gate
want 10 explicit   && section_explicit
want 11 optout     && section_optout
want 12 shared     && section_shared
want 13 surfaces   && section_surfaces
want 14 rundir     && section_rundir
want 15 w1pins     && section_w1pins
want 16 docs       && section_docs

# Sections 1-3 may leave the main HOME's core up for the next one; end it.
[ -n "$SERVER_PID" ] && stop_server

echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
