#!/usr/bin/env bash
# Live proof of the wave-1 terminal reporting: the header, the in-place
# checklist, the ready card, error panels, exit codes, the 0600 log file, the
# raw `-v` / `RUST_LOG` stream, token hygiene and the TTY recordings.
#
# Spec: docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md
# Plan: docs/superpowers/plans/2026-11-01-cli-terminal-reporting-wave1-plan.md
#       (Task 14; the section numbers below are the plan's)
#
# Boots the REAL `aitm` binary (no mocks, no fixtures). Every section runs in
# its own isolated HOME under a temp dir with its own free ports, so it never
# touches your real ~/Library/Application Support/aitmproxy, never writes the
# system proxy or a keychain (`system_proxy.auto` stays unset), and never
# needs 8080/8081/8082 to be free. Repeatable.
#
# Usage:
#   tests/e2e/cli/term-reporting.sh
#
# Environment:
#   AITM_BIN             the aitm binary under test
#                        (default: <repo>/target/debug/aitm, else target/release/aitm)
#   AITM_OLD_BIN         the previous release for the section-13 timing and
#                        thread-count comparison (default: /opt/homebrew/bin/aitm
#                        when it exists; the comparison SKIPs otherwise)
#   AITM_EXPECT_VERSION  the version `aitm --version` must print
#                        (default: the workspace Cargo.toml `version`)
#   AITM_TERM_SECTIONS   comma list of the sections to run, by number or name
#                        (default: all). Names: preboot piped portinuse
#                        exitcodes log warnings unwritable raw stdout tokens
#                        clistartup liveenv perf tty
#
# Needs `python3` on PATH (free ports, port holders, byte counts, secrets);
# without it the script exits 2 at once instead of mis-reporting every
# section as a sandbox that cannot bind a port.
#
# A section whose precondition is missing SKIPs with a reason and never FAILs:
#   - section 14 (TTY recordings) needs stdout to be a terminal (`[ -t 1 ]`)
#     and a pty `script` can allocate;
#   - section 13 needs AITM_OLD_BIN (executable);
#   - section 12 needs apps/web/node_modules and `node`;
#   - the `obscura probed` check and the AC-W1-33 "the log records the
#     browser's teardown error" check need `obscura` beside AITM_BIN;
#   - the `aitm-tui --help` check needs `aitm-tui` beside AITM_BIN.
#
# Section 6's browser-unavailable run executes a hard copy of AITM_BIN from a
# scratch dir under the temp dir that holds no `obscura`, with
# `PATH=/usr/bin:/bin` (~130 MB for a debug build; removed with the scratch
# dir). Engine discovery falls through a missing `AITM_OBSCURA_BIN` to the
# engine beside the real binary and ends with a PATH lookup, so the env
# override cannot stand in for that (live dry-run finding D3).
#
# Tokens are generated into 0600 files, read into variables and only ever
# compared with `grep -c -F`; nothing here prints one. Failure-context dumps
# redact `#t=` URL fragments. The script never uses a global `pkill`: the
# aitm child of a `script` recording is found through `pgrep -P`, and the
# recordings' stdin feeders write into anonymous pipes (never FIFOs: BSD
# `script` refuses a FIFO stdin, dry-run D5) and are tracked by PID, so no
# `sleep` outlives the run.
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
command -v python3 >/dev/null || { echo "FATAL: python3 is required (ports, byte counts, secrets)" >&2; exit 2; }
AITM_BIN="$(cd "$(dirname "$AITM_BIN")" && pwd)/$(basename "$AITM_BIN")"
OBSCURA="$(dirname "$AITM_BIN")/obscura"
TUI_BIN="$(dirname "$AITM_BIN")/aitm-tui"
if [ -z "${AITM_OLD_BIN:-}" ] && [ -x /opt/homebrew/bin/aitm ]; then
  AITM_OLD_BIN=/opt/homebrew/bin/aitm
fi
AITM_OLD_BIN="${AITM_OLD_BIN:-}"
EXPECT_VERSION="${AITM_EXPECT_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/Cargo.toml" | head -1)}"
SECTIONS="${AITM_TERM_SECTIONS:-all}"

# The runner's own terminal settings must not leak into the binary under
# test: every section states the variables it needs on the command line.
unset RUST_LOG NO_COLOR CLICOLOR_FORCE AITM_TERM CI AITM_LOG_FILE AITM_OBSCURA_BIN AITM_TUI_LOG AITM_CONFIG XDG_CONFIG_HOME
# The piped expectations use the rich separator (`·`), which a pipe gets
# whenever any of LC_ALL/LC_CTYPE/LANG names UTF-8 (spec T1).
case "${LC_ALL:-}${LC_CTYPE:-}${LANG:-}" in
  *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) ;;
  *) export LANG=en_US.UTF-8 ;;
esac
# The TTY recordings need a real, non-dumb TERM (the dumb-terminal cases set
# their own).
REC_TERM="${TERM:-xterm-256color}"
[ "$REC_TERM" = dumb ] && REC_TERM=xterm-256color

echo "aitm under test:  $AITM_BIN"
echo "expected version: $EXPECT_VERSION"
echo "old binary:       ${AITM_OLD_BIN:-(none; section 13 comparison will be skipped)}"
[ -x "$OBSCURA" ] && echo "obscura engine:   $OBSCURA" || echo "obscura engine:   (absent; the 'obscura probed' check will be skipped)"
[ -x "$TUI_BIN" ] && echo "aitm-tui:         $TUI_BIN" || echo "aitm-tui:         (absent; the 'aitm-tui --help' check will be skipped)"
echo "platform:         $OS"
echo "sections:         $SECTIONS"
echo

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aitm-term-XXXXXX")"
if [ -z "$ROOT" ] || [ ! -d "$ROOT" ]; then
  echo "FATAL: could not create a scratch directory under ${TMPDIR:-/tmp}" >&2
  exit 2
fi
PASS=0; FAIL=0; SKIP=0
SERVER_PID=""; SERVER_RC=""; RC=""; SCRIPT_PID=""; REC_PID=""; FEEDER_PID=""; FEEDER_FD=""; SECTION_FAIL0=0
HOME_DIR=""; CFG=""; CFG_STDIO=""; PROXY_PORT=""; BROWSER_PORT=""; WEB_PORT=""; BUS_PORT=""

cleanup() {
  local p
  for p in $(jobs -p) ${SERVER_PID:-} ${REC_PID:-} ${SCRIPT_PID:-} ${FEEDER_PID:-}; do kill "$p" 2>/dev/null; done
  sleep 0.3
  for p in $(jobs -p); do kill -9 "$p" 2>/dev/null; done
  chmod -R u+rwX "$ROOT" 2>/dev/null
  rm -rf "$ROOT"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }
note() { echo "  note: $1"; }
have_obscura() { [ -x "$OBSCURA" ]; }

# want <number> <name>: is this section selected by AITM_TERM_SECTIONS?
want() {
  case ",$SECTIONS," in *,all,*|*,"$1",*|*,"$2",*) return 0 ;; esac
  return 1
}

# check "<description>" <command...>: PASS when the command succeeds.
check() { local desc="$1"; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }
starts_with() { case "$1" in "$2"*) return 0 ;; esac; return 1; }

# Line counts (0 when the file is missing). `count_re` takes an ERE,
# `count_fx` a fixed string (the form every token comparison uses).
count_re() { local n; n="$(grep -a -c -E -- "$1" "$2" 2>/dev/null)"; printf '%s\n' "${n:-0}"; }
count_fx() { local n; n="$(grep -a -c -F -- "$1" "$2" 2>/dev/null)"; printf '%s\n' "${n:-0}"; }

# bytecount <file> <python bytes regex> [path-prefix]: how many times the
# byte pattern occurs (locale-independent; for the `script` casts). With a
# third argument, every run of non-blank bytes that starts with that literal
# path is removed first (the scratch paths a cast echoes); the prefix is
# escaped, so a TMPDIR with `|`, `+`, `.` or `[` in it cannot break the
# expression (an unescaped sed would error out and leave an empty file,
# turning the assertion into a false PASS).
bytecount() {
  python3 - "$1" "$2" "${3:-}" <<'PY'
import os, re, sys
data = open(sys.argv[1], 'rb').read()
if sys.argv[3]:
    data = re.sub(re.escape(os.fsencode(sys.argv[3])) + rb'[^\s]*', b'', data)
print(len(re.findall(sys.argv[2].encode('latin-1'), data)))
PY
}

# The SGR/CSI-stripped, CR-free text of a cast (spec: `sed $'s/\x1b\[[0-9;?]*[A-Za-z]//g'`,
# widened to every CSI final byte and the charset/keypad escapes ratatui emits).
stripped() {
  LC_ALL=C sed -e $'s/\x1b\\[[0-9;?<=>!]*[@-~]//g' -e $'s/\x1b[()][0-9A-Za-z]//g' -e $'s/\x1b[=>78]//g' -e $'s/\r//g' "$1"
}

redact() { sed -E 's/#t=[^&[:space:]]+/#t=<redacted>/g'; }

begin_section() { echo; echo "### $1 ###"; SECTION_FAIL0=$FAIL; }
# end_section <text files...>: when the section failed, show the files' heads.
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
# The log file aitm derives for a HOME (spec D7, amendment B).
log_path_for() {
  if [ "$OS" = Darwin ]; then printf '%s/Library/Application Support/aitmproxy/logs/aitm.log' "$1"
  else printf '%s/.config/aitmproxy/logs/aitm.log' "$1"; fi
}
thread_count() {
  if [ "$OS" = Darwin ]; then ps -M -p "$1" | awk 'NR > 1' | wc -l | tr -d ' '
  else find "/proc/$1/task" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' '; fi
}
# thread_names <pid> <out-file>: one OS thread name per line (unnamed threads
# as `<unnamed>`), from `sample <pid> 1 -mayDie` on macOS — its call-graph
# headers `Thread_<n>: <name>` / `Thread_<n>   DispatchQueue_<k>: <name>
# (serial)`; the raw report is kept at <out-file>.sample, and the sampling is
# bounded to 60 s (symbolication of a debug binary is slow) — or from
# `/proc/<pid>/task/*/comm` on Linux. Returns 1 when neither source is
# available or `sample` fails (a hardened-runtime target, say): the caller
# SKIPs instead of asserting on nothing.
thread_names() {
  local pid="$1" out="$2"
  if [ "$OS" = Darwin ]; then
    command -v sample >/dev/null 2>&1 || return 1
    sample "$pid" 1 -mayDie -file "$out.sample" >/dev/null 2>&1 &
    local sp=$! i=0
    while kill -0 "$sp" 2>/dev/null; do
      [ "$i" -ge 240 ] && { kill -9 "$sp" 2>/dev/null; wait "$sp" 2>/dev/null; return 1; }
      sleep 0.25; i=$((i+1))
    done
    wait "$sp" 2>/dev/null || return 1
    sed -n -E 's/^ *[0-9]+ Thread_[0-9]+(: | +DispatchQueue_[0-9]+: )?//p' "$out.sample" \
      | sed -E -e 's/ +\(serial\)$//' -e 's/^$/<unnamed>/' > "$out"
  else
    [ -d "/proc/$pid/task" ] || return 1
    cat /proc/"$pid"/task/*/comm > "$out" 2>/dev/null
  fi
  [ -s "$out" ]
}
grow_file() { python3 -c 'import sys; f = open(sys.argv[1], "ab"); f.truncate(int(sys.argv[2])); f.close()' "$1" "$2"; }
gen_secret() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null; }

# Hold a port until the returned PID is killed (stdout/stderr detached so the
# `$(hold_port …)` substitution returns at once).
hold_port() {
  python3 -c "import socket,time,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen()
time.sleep(120)" "$1" >/dev/null 2>&1 &
  echo $!
}

wait_port_listening() {
  local port="$1" secs="$2" i=0
  while [ "$i" -lt "$((secs*4))" ]; do
    python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(("127.0.0.1",int(sys.argv[1])))==0 else 1)' "$port" 2>/dev/null && return 0
    sleep 0.25; i=$((i+1))
  done
  return 1
}

# new_home <name>: a fresh isolated HOME. Sets HOME_DIR.
new_home() { HOME_DIR="$ROOT/$1/home"; mkdir -p "$HOME_DIR"; }

# new_env <name> [operator-secret-file]: a fresh HOME plus two configs on free
# ports. CFG serves the MCP bus over loopback TCP with a random token that
# lives in a 0600 file (never printed); CFG_STDIO is the same proxy on the
# stdio transport. Sets HOME_DIR CFG CFG_STDIO PROXY_PORT BROWSER_PORT
# WEB_PORT BUS_PORT.
new_env() {
  local name="$1" secret_file="${2:-}"
  new_home "$name"
  CFG="$ROOT/$name/config.yaml"; CFG_STDIO="$ROOT/$name/config-stdio.yaml"
  PROXY_PORT="$(free_port)"; BROWSER_PORT="$(free_port)"; WEB_PORT="$(free_port)"; BUS_PORT="$(free_port)"
  if [ -z "$PROXY_PORT" ] || [ -z "$BROWSER_PORT" ] || [ -z "$WEB_PORT" ] || [ -z "$BUS_PORT" ]; then
    fail "setup: cannot bind a loopback port here (a sandbox?); this section needs real sockets"
    return 1
  fi
  local token_file="$ROOT/$name/bus.token"
  gen_secret > "$token_file"
  {
    printf 'listen: 127.0.0.1:%s\n' "$PROXY_PORT"
    printf 'browser:\n  proxy_addr: 127.0.0.1:%s\n' "$BROWSER_PORT"
  } > "$CFG_STDIO"
  {
    cat "$CFG_STDIO"
    printf 'mcp:\n'
    [ -n "$secret_file" ] && printf '  operator_token: %s\n' "$(cat "$secret_file")"
    printf '  transport:\n    loopback_tcp:\n      port: %s\n      token: %s\n' "$BUS_PORT" "$(cat "$token_file")"
  } > "$CFG"
}

# start_server <stdout-file> <stderr-file> <cmd...>: in the background, stdin
# /dev/null, HOME isolated. Sets SERVER_PID.
start_server() {
  local out="$1" err="$2"; shift 2
  HOME="$HOME_DIR" "$@" >"$out" 2>"$err" </dev/null &
  SERVER_PID=$!
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
  kill -TERM "$pid" 2>/dev/null
  while kill -0 "$pid" 2>/dev/null; do
    [ "$i" -ge 40 ] && { kill -9 "$pid" 2>/dev/null; break; }
    sleep 0.25; i=$((i+1))
  done
  wait "$pid" 2>/dev/null; SERVER_RC=$?
}

# run_bounded <stdout-file> <stderr-file> <secs> <cmd...>: a command that must
# exit on its own. Sets RC (124 when it had to be killed).
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

# ---------------------------------------------------------------------------
# TTY recordings through `script` (section 14).
# ---------------------------------------------------------------------------

# start_recording <cast> <cmd...>: run the command inside a pty recorded to
# <cast>, its stdin the feeder pipe `start_feeder` opened (FEEDER_FD). The
# pty is sized 40x120 by `stty` inside the wrapper (a pipe-fed `script`
# would otherwise hand the child a 0x0 window) and the wrapper `exec`s the
# command, so the aitm process is `script`'s direct child; it is found
# through `pgrep -P` (never a global pkill). `script`'s own stderr goes to
# <cast>.script.err for `recording_diag`. Sets SCRIPT_PID and REC_PID (empty
# when the child was not found in 10 s).
start_recording() {
  local cast="$1"; shift
  local wrap="$ROOT/rec.$RANDOM$RANDOM.sh"
  { printf 'stty rows 40 cols 120 2>/dev/null\nexec'; printf ' %q' "$@"; printf '\n'; } > "$wrap"
  : > "$cast"
  if [ -z "$FEEDER_FD" ]; then
    note "recording: no feeder pipe open (start_feeder first)"; SCRIPT_PID=""; REC_PID=""; return 1
  fi
  if [ "$OS" = Darwin ]; then
    HOME="$HOME_DIR" script -q -t 0 "$cast" /bin/sh "$wrap" <&"$FEEDER_FD" 7<&- >/dev/null 2>"$cast.script.err" &
  else
    HOME="$HOME_DIR" script -q -f -c "/bin/sh '$wrap'" "$cast" <&"$FEEDER_FD" 7<&- >/dev/null 2>"$cast.script.err" &
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

# wait_cast <cast> <ERE over the stripped text> <secs>
wait_cast() {
  local cast="$1" re="$2" secs="$3" i=0
  while [ "$i" -lt "$((secs*4))" ]; do
    stripped "$cast" | grep -q -E -- "$re" && return 0
    kill -0 "$SCRIPT_PID" 2>/dev/null || { stripped "$cast" | grep -q -E -- "$re"; return $?; }
    sleep 0.25; i=$((i+1))
  done
  return 1
}

# end_recording [signal]: signal the aitm child (default INT, i.e. Ctrl-C),
# wait for `script` to finish, escalate when it does not.
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

# start_feeder <cmd...>: run <cmd> in the background with its stdout on an
# anonymous pipe whose read end this shell holds on fd 7, as a recording's
# stdin. Sets FEEDER_FD and FEEDER_PID; end_recording (and cleanup) reap the
# writer. Not a FIFO: macOS implements FIFOs over sockets and BSD `script`
# does `tcgetattr`/`ioctl(TIOCGWINSZ)` on its stdin, which a pipe answers
# with ENOTTY (tolerated) and a FIFO with EOPNOTSUPP — so a FIFO-fed `script`
# exits at once with `tcgetattr/ioctl: Operation not supported on socket`
# and records nothing (live dry-run D5). The process substitution's PID is
# `$!` right after the `exec` (bash 3.2 and 5.x), so the writer is tracked
# without a FIFO and no `sleep` outlives the run. One recording at a time,
# hence the fixed fd.
start_feeder() {
  FEEDER_PID=""; FEEDER_FD=""
  exec 7< <("$@")
  FEEDER_PID=$!
  [ -n "$FEEDER_PID" ] || { exec 7<&-; return 1; }
  FEEDER_FD=7
}

# reap_feeder: end the recording's stdin writer and close the pipe.
reap_feeder() {
  if [ -n "$FEEDER_PID" ]; then
    kill "$FEEDER_PID" 2>/dev/null
    wait "$FEEDER_PID" 2>/dev/null
  fi
  [ -n "$FEEDER_FD" ] && exec 7<&-
  FEEDER_PID=""; FEEDER_FD=""
}

# recording_diag <cast>: why a recording has no aitm child or no text —
# `script`'s own stderr and the cast's size, so an environment failure
# (dry-run D5: `script: tcgetattr/ioctl: Operation not supported on socket`)
# is visible in the run's output instead of silent.
recording_diag() {
  local cast="$1" serr="$1.script.err" text=""
  [ -s "$serr" ] && text="$(tr '\n' ' ' <"$serr" | head -c 300)"
  note "recording: $(basename "$cast") is $(fsize "$cast" 2>/dev/null || echo 0) bytes; script stderr: [${text:-<empty>}]"
}

# record_server <cast> <cmd...>: a serving aitm in a pty, run until its ready
# card is drawn (rich `  Log  ~/…` or plain `Log: …`), then Ctrl-C.
# Returns 1 when the card never appeared.
record_server() {
  local cast="$1"; shift
  if ! start_feeder sleep 90; then
    note "recording: cannot open a feeder pipe"; return 1
  fi
  start_recording "$cast" "$@"
  local ok=0
  if [ -z "$REC_PID" ]; then
    note "recording: aitm child of script(${SCRIPT_PID:-none}) not found"; recording_diag "$cast"
  elif wait_cast "$cast" '^(  Log +~?/|Log: )' 30; then
    ok=1
  else
    note "recording: the ready card never appeared in $(basename "$cast")"; recording_diag "$cast"
  fi
  end_recording INT
  [ "$ok" -eq 1 ]
}

# Can `script` allocate a pty here at all? (The Claude sandbox cannot.)
pty_probe() {
  if [ "$OS" = Darwin ]; then script -q /dev/null true </dev/null >/dev/null 2>&1
  else script -q -c true /dev/null </dev/null >/dev/null 2>&1; fi
}

# The stdin feeder for the `aitm tui` recording: once the alternate screen
# has been entered, press `q`, then keep the pipe open.
tui_feeder() {
  local cast="$1" i=0
  while [ "$i" -lt 120 ]; do
    grep -a -q -F $'\x1b[?1049h' "$cast" 2>/dev/null && break
    sleep 0.25; i=$((i+1))
  done
  sleep 1.5
  printf 'q'
  # Keep the pipe open; `exec` so the tracked FEEDER_PID is this sleeper and
  # reap_feeder ends it (a killed subshell would leave its `sleep` behind).
  exec sleep 60
}

# ===========================================================================
# pb_version "<label>" <args...>: the pre-boot version line (AC-W1-1): stdout
# is exactly `aitm <version>`, stderr empty, exit 0.
pb_version() {
  local label="$1"; shift
  HOME="$HOME_DIR" "$AITM_BIN" "$@" >"$ROOT/pb.out" 2>"$ROOT/pb.err" </dev/null; local rc=$?
  if [ "$rc" -eq 0 ] && [ "$(cat "$ROOT/pb.out")" = "aitm $EXPECT_VERSION" ] && [ ! -s "$ROOT/pb.err" ]; then
    pass "$label → stdout 'aitm $EXPECT_VERSION', stderr empty, exit 0"
  else
    fail "$label: rc=$rc stdout=[$(head -c 120 "$ROOT/pb.out" | tr '\n' ' ')] stderr=[$(head -c 120 "$ROOT/pb.err" | tr '\n' ' ')]"
  fi
}

# pb_help "<label>" <args...>: the pre-boot synopsis (AC-W1-1, AC-W1-2) on
# stdout, exit 0.
pb_help() {
  local label="$1"; shift
  HOME="$HOME_DIR" "$AITM_BIN" "$@" >"$ROOT/pb.out" 2>"$ROOT/pb.err" </dev/null; local rc=$?
  local first; first="$(head -1 "$ROOT/pb.out")"
  if [ "$rc" -eq 0 ] && starts_with "$first" "aitm $EXPECT_VERSION — intercepting proxy" \
     && grep -q '^Groups:' "$ROOT/pb.out" && grep -q -F 'aitm scope add --host <host>' "$ROOT/pb.out"; then
    pass "$label → synopsis on stdout ('$first'; Groups:; scope add), exit 0"
  else
    fail "$label: rc=$rc first line=[$first]"
  fi
}

section_preboot() {
  begin_section "1. pre-boot --version / --help (AC-W1-1, AC-W1-2)"
  new_home preboot
  touch "$ROOT/marker"; sleep 1
  local a
  for a in --version -V version; do pb_version "aitm $a" "$a"; done
  for a in --help -h help; do pb_help "aitm $a" "$a"; done
  # Amended AC-W1-1 (spec D8): leading global flags are stepped over before
  # anything boots. The `--config` path is never read, so it need not exist
  # (and must not be created: the `find` below sees it).
  pb_version "aitm -v --version" -v --version
  pb_version 'aitm --config $HOME/does-not-exist.yaml --version' --config "$HOME_DIR/does-not-exist.yaml" --version
  pb_help "aitm --color never -h" --color never -h
  local created; created="$(find "$HOME_DIR" -mindepth 1 -newer "$ROOT/marker" | wc -l | tr -d ' ')"
  check "pre-boot created nothing under a fresh HOME ($created entries)" [ "$created" = 0 ]
  local med; med="$(median_of 5 "$AITM_BIN" --version)"
  note "aitm --version median real of 5 runs: ${med}s"
  check "aitm --version median wall < 0.100 s" awk -v m="$med" 'BEGIN { exit !(m < 0.100) }'
  end_section "$ROOT/pb.err"
}

# ===========================================================================
section_piped() {
  begin_section "2. piped startup is plain lines (AC-W1-5, AC-W1-7, AC-W1-8, AC-W1-9, AC-W1-23, AC-W1-33)"
  new_env piped || return
  local out="$ROOT/plain.out" err="$ROOT/plain.err" log; log="$(log_path_for "$HOME_DIR")"
  start_server "$out" "$err" "$AITM_BIN" --config "$CFG"
  # The card's last row; `proxy listening` precedes the obscura and CA-trust
  # phases, so the rows below are only there once `Log:` is.
  wait_for "$err" '^Log: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "zero ESC bytes in stderr" [ "$(count_fx $'\x1b' "$err")" = 0 ]
  check "zero CR bytes in stderr" [ "$(count_fx $'\r' "$err")" = 0 ]
  check "stdout is empty" [ ! -s "$out" ]
  check "line 1 is 'aitmproxy $EXPECT_VERSION'" [ "$(head -1 "$err")" = "aitmproxy $EXPECT_VERSION" ]
  check "phase line: config" grep -q -E '^config ' "$err"
  check "phase line: N detections ready" grep -q -E '^[0-9]+ detections ready$' "$err"
  check "phase line: CA created|loaded · path" grep -q -E '^CA (created|loaded) · ' "$err"
  check "phase line: proxy listening 127.0.0.1:$PROXY_PORT · browser proxy" grep -q -E "^proxy listening 127\.0\.0\.1:$PROXY_PORT · browser proxy " "$err"
  check "card row: Bus: loopback 127.0.0.1:" grep -q -E '^Bus: loopback 127\.0\.0\.1:' "$err"
  check "card row: Scope advice · scope add" grep -q -E '^Scope: Nothing is decrypted until a host is in Scope\. · aitm scope add --host <host>$' "$err"
  # A fresh HOME mints a CA no store can hold yet (login keychain absent →
  # unknown, System keychain → no; any `no` reduces to untrusted, spec T7),
  # so the untrusted path is deterministic here. The trusted path is the
  # recipe's run on the operator's own HOME (AC-W1-7).
  check "card row: CA: untrusted · aitm ca install (fresh HOME, AC-W1-7)" grep -q -E '^CA: untrusted · aitm ca install$' "$err"
  check "card row: System proxy: <state> (AC-W1-8)" grep -q -E '^System proxy: ' "$err"
  check "card row: Log:" grep -q -E '^Log: ' "$err"
  check "no INFO line on stderr" [ "$(count_fx INFO "$err")" = 0 ]
  check "exit 0 after SIGTERM" [ "$SERVER_RC" = 0 ]
  # AC-W1-33 (dry-run D1): closing the embedded browser's CDP socket logs
  # `WS Connection error: Ws(Protocol(ResetWithoutClosingHandshake))` at
  # ERROR during teardown. The reporter is quiesced after the serving loop,
  # so the line never reaches the view (the card row stays last) while the
  # log file still records it. The stderr checks hold with or without an
  # engine; the log check needs one (no browser, nothing to quiesce).
  check "AC-W1-33: no 'WS Connection error' line on stderr after SIGTERM" [ "$(count_fx 'WS Connection error' "$err")" = 0 ]
  check "AC-W1-33: the last stderr line is the 'Log:' card row" starts_with "$(tail -1 "$err")" 'Log: '
  if have_obscura; then
    check "AC-W1-33: the log file records the browser's teardown 'WS Connection error' ($(count_fx 'WS Connection error' "$log") records)" \
      [ "$(count_fx 'WS Connection error' "$log")" -ge 1 ]
  else
    skip "AC-W1-33: the log records the browser's teardown error (no obscura beside AITM_BIN: no browser to close)"
  fi
  end_section "$err" "$out"
}

# ===========================================================================
assert_port_panel() {  # <who> <stdout-file> <stderr-file> <rc>
  local who="$1" out="$2" err="$3" rc="$4"
  check "$who: exit 1" [ "$rc" = 1 ]
  check "$who: 'error: binding ports' phase line" grep -q -x -F 'error: binding ports' "$err"
  check "$who: headline 'error: cannot start: the proxy port 127.0.0.1:$PROXY_PORT is already in use'" \
    grep -q -x -F "error: cannot start: the proxy port 127.0.0.1:$PROXY_PORT is already in use" "$err"
  check "$who: held-by sentence" grep -q -F 'It is most likely held by another running `aitm`' "$err"
  check "$who: remedy names the config path" grep -q -F "Free it, or set \`listen:\` to another address in $CFG" "$err"
  local fixes; fixes="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$err" | grep -c -x -F "fix: lsof -nP -iTCP:$PROXY_PORT -sTCP:LISTEN")"
  check "$who: trimmed line 'fix: lsof -nP -iTCP:$PROXY_PORT -sTCP:LISTEN'" [ "$fixes" = 1 ]
  check "$who: '  log: ' footer" grep -q -E '^  log: ' "$err"
  check "$who: 'os error 48' absent" [ "$(count_fx 'os error 48' "$err")" = 0 ]
  check "$who: 'web UI (agent):' absent" [ "$(count_fx 'web UI (agent):' "$err")" = 0 ]
  check "$who: stdout empty" [ ! -s "$out" ]
}

section_portinuse() {
  begin_section "3. port in use, plain panel (AC-W1-3, AC-W1-13)"
  new_env port || return
  local holder; holder="$(hold_port "$PROXY_PORT")"
  if wait_port_listening "$PROXY_PORT" 10; then
    run_bounded "$ROOT/port-bare.out" "$ROOT/port-bare.err" 20 "$AITM_BIN" --config "$CFG"
    assert_port_panel "bare aitm" "$ROOT/port-bare.out" "$ROOT/port-bare.err" "$RC"
    run_bounded "$ROOT/port-web.out" "$ROOT/port-web.err" 20 "$AITM_BIN" --config "$CFG" web --no-open --listen "127.0.0.1:$WEB_PORT"
    assert_port_panel "aitm web" "$ROOT/port-web.out" "$ROOT/port-web.err" "$RC"
  else
    fail "setup: the port holder never listened on $PROXY_PORT"
  fi
  kill "$holder" 2>/dev/null
  end_section "$ROOT/port-bare.err" "$ROOT/port-web.err"
}

# ===========================================================================
# ec "<label>" <expected rc> "<stderr must contain>" "<and this>" -- <cmd...>
ec() {
  local label="$1" want="$2" s1="$3" s2="$4"; shift 4
  [ "${1:-}" = -- ] && shift
  HOME="$HOME_DIR" "$@" >"$ROOT/ec.out" 2>"$ROOT/ec.err" </dev/null; local rc=$? ok=1 why=""
  [ "$rc" = "$want" ] || { ok=0; why="rc=$rc (want $want)"; }
  [ -z "$s1" ] || grep -q -F -- "$s1" "$ROOT/ec.err" || { ok=0; why="$why; stderr lacks '$s1'"; }
  [ -z "$s2" ] || grep -q -F -- "$s2" "$ROOT/ec.err" || { ok=0; why="$why; stderr lacks '$s2'"; }
  [ ! -s "$ROOT/ec.out" ] || { ok=0; why="$why; stdout not empty"; }
  if [ "$ok" = 1 ]; then
    pass "$label → exit $rc${s1:+, stderr has '$s1'}${s2:+ and '$s2'}, stdout empty"
  else
    fail "$label: $why"; head -6 "$ROOT/ec.err" | redact | sed 's/^/  | /'
  fi
}

section_exitcodes() {
  begin_section "4. exit codes and usage panels (AC-W1-13, AC-W1-14, AC-W1-26, AC-W1-27)"
  new_home exitcodes
  ec "aitm tui extra"                         2 'usage: aitm [--config <path>] tui' ''                -- "$AITM_BIN" tui extra
  ec "aitm operator-token"                    2 'usage: aitm [--config <path>] operator-token' ''     -- "$AITM_BIN" operator-token
  ec "aitm nonsense"                          2 'unknown command `nonsense`' 'fix: aitm --help'      -- "$AITM_BIN" nonsense
  ec "aitm flow list --bogus 1"               2 'error: unknown flag --bogus' 'fix: aitm --help'     -- "$AITM_BIN" flow list --bogus 1
  ec "aitm --flag-first"                      2 'error: expected a command before flags, got `--flag-first`' 'fix: aitm --help' -- "$AITM_BIN" --flag-first
  ec "aitm --config (no value)"               2 'error: --config requires a path' 'fix: aitm --help'    -- "$AITM_BIN" --config
  ec "aitm -v -q"                             2 '`-v` and `-q` cannot be combined' ''                -- "$AITM_BIN" -v -q
  ec "aitm --config /nonexistent.yaml flow list" 1 'in config file /nonexistent.yaml' 'Create it, or run without --config' -- "$AITM_BIN" --config /nonexistent.yaml flow list
  ec "aitm findings get --id nope"            1 'error: findings.get: ' '  log: '                     -- "$AITM_BIN" findings get --id nope
  ec "aitm sysproxy-watchdog"                 2 'usage: aitm sysproxy-watchdog' ''                    -- "$AITM_BIN" sysproxy-watchdog
  if [ -x "$TUI_BIN" ]; then
    HOME="$HOME_DIR" "$TUI_BIN" --help >"$ROOT/tui-help.log" 2>&1 </dev/null; local rc=$?
    if [ "$rc" = 2 ] && grep -q -F 'usage: aitm-tui' "$ROOT/tui-help.log"; then
      pass "aitm-tui --help 2>&1 → exit 2, text has 'usage: aitm-tui'"
    else
      fail "aitm-tui --help: rc=$rc"; head -4 "$ROOT/tui-help.log" | sed 's/^/  | /'
    fi
  else
    skip "aitm-tui --help (no aitm-tui beside AITM_BIN; cargo build -p aitm-tui)"
  fi
  HOME="$HOME_DIR" "$AITM_BIN" web --help >"$ROOT/web-help.out" 2>"$ROOT/web-help.err" </dev/null; local wrc=$?
  if [ "$wrc" = 0 ] && grep -q -F 'web operator UI' "$ROOT/web-help.out"; then
    pass "aitm web --help → exit 0, stdout has 'web operator UI'"
  else
    fail "aitm web --help: rc=$wrc"; head -4 "$ROOT/web-help.out" "$ROOT/web-help.err" | sed 's/^/  | /'
  fi
  end_section
}

# ===========================================================================
section_log() {
  begin_section "5. the log file (AC-W1-15, AC-W1-16, AC-W1-18)"
  new_env log || return
  local log; log="$(log_path_for "$HOME_DIR")"
  start_server "$ROOT/log.out" "$ROOT/log.err" "$AITM_BIN" --config "$CFG"
  wait_for "$ROOT/log.err" '^Log: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "log file exists ($log)" [ -f "$log" ]
  check "log file mode 600" [ "$(fmode "$log" 2>/dev/null)" = 600 ]
  check "log has 'proxy listening'" grep -q -F 'proxy listening' "$log"
  check "log has no 'loaded script' at the default level" [ "$(count_fx 'loaded script' "$log")" = 0 ]
  check "log has zero ESC bytes" [ "$(count_fx $'\x1b' "$log")" = 0 ]
  HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG" -vv scope list >"$ROOT/vv.out" 2>"$ROOT/vv.err" </dev/null
  check "-vv one-shot: log gains ≥ 49 'loaded script' records ($(count_fx 'loaded script' "$log"))" [ "$(count_fx 'loaded script' "$log")" -ge 49 ]
  start_server "$ROOT/logweb.out" "$ROOT/logweb.err" "$AITM_BIN" --config "$CFG" web --no-open --listen "127.0.0.1:$WEB_PORT"
  wait_for "$ROOT/logweb.err" '^Log: ' 30 || note "web ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "aitm web: log has 'web UI listening'" grep -q -F 'web UI listening' "$log"
  grow_file "$log" $((11*1024*1024))
  HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG" scope list >/dev/null 2>"$ROOT/rot.err" </dev/null
  check "rotation: aitm.log.1 exists after opening an 11 MiB log" [ -f "$log.1" ]
  check "rotation: aitm.log.1 > 10 MiB" [ "$(fsize "$log.1" 2>/dev/null || echo 0)" -gt $((10*1024*1024)) ]
  check "rotation: fresh aitm.log < 1 MiB" [ "$(fsize "$log" 2>/dev/null || echo 99999999)" -lt $((1024*1024)) ]
  start_server "$ROOT/x.out" "$ROOT/x.err" env AITM_LOG_FILE="$ROOT/x.log" "$AITM_BIN" --config "$CFG"
  wait_for "$ROOT/x.err" '^Log: ' 30 || note "AITM_LOG_FILE run: ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "AITM_LOG_FILE: the file exists" [ -f "$ROOT/x.log" ]
  check "AITM_LOG_FILE: mode 600" [ "$(fmode "$ROOT/x.log" 2>/dev/null)" = 600 ]
  check "AITM_LOG_FILE: card row 'Log: $ROOT/x.log'" grep -q -x -F "Log: $ROOT/x.log" "$ROOT/x.err"
  end_section "$ROOT/log.err" "$ROOT/logweb.err" "$ROOT/x.err"
}

# ===========================================================================
section_warnings() {
  begin_section "6. warnings and the browser line (AC-W1-19, AC-W1-33)"
  new_env warn || return
  local log; log="$(log_path_for "$HOME_DIR")"
  # The "unavailable" run needs an aitm that finds no engine. Discovery
  # (crates/aitm-browser/src/obscura.rs `discover_binary`) tries, in order,
  # `browser.obscura.binary`, `AITM_OBSCURA_BIN`, `<exe_dir>/obscura`,
  # `<exe_dir>/../libexec/obscura` and a PATH lookup, and a candidate that
  # does not exist falls through to the next — so `AITM_OBSCURA_BIN=/nonexistent`
  # still found the engine beside AITM_BIN (dry-run D3). Instead run a hard
  # COPY of AITM_BIN from a scratch dir with no `obscura` in it or in a
  # sibling libexec (a symlink would canonicalize back to the real dir), with
  # `PATH=/usr/bin:/bin` so the PATH lookup finds none either (the trust read
  # and the system-proxy probe use absolute paths; the row values are not
  # asserted here). The copy (~130 MB on a debug build) lives under $ROOT, so
  # the exit trap removes it even if the early `rm` below never runs; it
  # loads no bundled detection catalogue (found beside the real binary),
  # which this section does not assert on.
  local copy="$ROOT/nobrowser/aitm"
  mkdir -p "$ROOT/nobrowser"
  if cp "$AITM_BIN" "$copy" && [ -x "$copy" ]; then
    start_server "$ROOT/warn.out" "$ROOT/warn.err" env PATH=/usr/bin:/bin "$copy" --config "$CFG"
    wait_for "$ROOT/warn.err" '^Log: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
    stop_server
    check "exactly one 'warning: embedded browser unavailable; browser.* commands will error' line on stderr" \
      [ "$(count_re '^warning: embedded browser unavailable; browser\.\* commands will error' "$ROOT/warn.err")" = 1 ]
    check "the warning is in the log exactly once" [ "$(count_fx 'embedded browser unavailable; browser.* commands will error' "$log")" = 1 ]
    check "stdout empty" [ ! -s "$ROOT/warn.out" ]
    check "phase line 'browser unavailable'" grep -q -x -F 'browser unavailable' "$ROOT/warn.err"
  else
    fail "setup: could not copy $AITM_BIN to $copy (disk space?); the browser-unavailable run did not happen"
  fi
  rm -f "$copy"
  if have_obscura; then
    new_env warn2 || return
    start_server "$ROOT/warn2.out" "$ROOT/warn2.err" "$AITM_BIN" --config "$CFG"
    wait_for "$ROOT/warn2.err" '^Log: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
    stop_server
    # The engine word is stripped from the probe's raw `obscura aitm-v1`, so
    # the line is `obscura probed aitm-v1` — one word after `probed`, never
    # `obscura probed obscura …` (dry-run D4). The line found is printed on
    # failure so a wording drift is diagnosable from the run's output.
    local probed; probed="$(grep -a -E '^obscura probed' "$ROOT/warn2.err" | head -1)"
    if printf '%s\n' "$probed" | grep -q -E '^obscura probed [^ ]+$'; then
      pass "normal run: phase line 'obscura probed <version>' ('$probed')"
    else
      fail "normal run: phase line 'obscura probed <version>' (one word after 'probed', e.g. 'obscura probed aitm-v1'): found [${probed:-<no 'obscura probed' line>}]"
    fi
    check "AC-W1-33: normal run: no 'WS Connection error' line on stderr after SIGTERM" [ "$(count_fx 'WS Connection error' "$ROOT/warn2.err")" = 0 ]
  else
    skip "'obscura probed <version>' line (no obscura beside AITM_BIN; scripts/fetch-obscura-dev.sh)"
  fi
  end_section "$ROOT/warn.err" "$ROOT/warn2.err"
}

# ===========================================================================
section_unwritable() {
  begin_section "7. unwritable log directory (AC-W1-17)"
  new_env unwritable || return
  local dir; dir="$(dirname "$(log_path_for "$HOME_DIR")")"
  mkdir -p "$dir"; chmod 500 "$dir"
  if [ "$(id -u)" = 0 ]; then
    chmod 700 "$dir"
    skip "unwritable log dir (running as root: chmod 500 is not enforced)"
    return
  fi
  start_server "$ROOT/unw.out" "$ROOT/unw.err" "$AITM_BIN" --config "$CFG"
  wait_for "$ROOT/unw.err" '^Scope: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
  stop_server
  chmod 700 "$dir"
  check "one 'warning: log file unavailable:' line" [ "$(count_re '^warning: log file unavailable:' "$ROOT/unw.err")" = 1 ]
  check "no 'Log:' card row" [ "$(count_re '^Log: ' "$ROOT/unw.err")" = 0 ]
  check "startup continued to 'proxy listening'" grep -q -E '^proxy listening ' "$ROOT/unw.err"
  check "exit 0 after SIGTERM" [ "$SERVER_RC" = 0 ]
  end_section "$ROOT/unw.err"
}

# ===========================================================================
section_raw() {
  begin_section "8. raw stream: RUST_LOG, -v, -q (AC-W1-20, AC-W1-12)"
  new_env raw || return
  start_server "$ROOT/raw.out" "$ROOT/raw.err" env RUST_LOG=info "$AITM_BIN" --config "$CFG"
  wait_for "$ROOT/raw.err" '^Log: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "RUST_LOG=info: raw 'INFO aitm_core::proxy: proxy listening' on stderr" grep -q -F 'INFO aitm_core::proxy: proxy listening' "$ROOT/raw.err"
  check "RUST_LOG=info: zero cursor-up sequences" [ "$(count_re $'\x1b\\[[0-9]*A' "$ROOT/raw.err")" = 0 ]
  check "RUST_LOG=info: stdout empty" [ ! -s "$ROOT/raw.out" ]
  new_env rawv || return
  start_server "$ROOT/rawv.out" "$ROOT/rawv.err" "$AITM_BIN" -v --config "$CFG"
  wait_for "$ROOT/rawv.err" '^Log: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "-v: raw INFO stream present" grep -q -F 'INFO aitm_core::proxy: proxy listening' "$ROOT/rawv.err"
  check "-v: plain phase line '^proxy listening'" grep -q -E '^proxy listening ' "$ROOT/rawv.err"
  check "-v: zero cursor-up sequences" [ "$(count_re $'\x1b\\[[0-9]*A' "$ROOT/rawv.err")" = 0 ]
  new_env rawq || return
  local holder; holder="$(hold_port "$PROXY_PORT")"
  if wait_port_listening "$PROXY_PORT" 10; then
    run_bounded "$ROOT/rawq.out" "$ROOT/rawq.err" 20 "$AITM_BIN" -q --config "$CFG"
    check "-q with the port held: exit 1" [ "$RC" = 1 ]
    check "-q: the panel is present" grep -q -E '^error: cannot start: the proxy port ' "$ROOT/rawq.err"
    check "-q: the header 'aitmproxy $EXPECT_VERSION' is absent" [ "$(count_fx "aitmproxy $EXPECT_VERSION" "$ROOT/rawq.err")" = 0 ]
  else
    fail "setup: the port holder never listened on $PROXY_PORT"
  fi
  kill "$holder" 2>/dev/null
  end_section "$ROOT/raw.err" "$ROOT/rawv.err" "$ROOT/rawq.err"
}

# ===========================================================================
section_stdout() {
  begin_section "9. stdout silence on the stdio transport (AC-W1-21, AC-W1-32, AC-W1-33; spec Open question 3 default)"
  new_env stdio || return
  HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG_STDIO" >"$ROOT/stdio.out" 2>"$ROOT/stdio.err" </dev/null &
  local pid=$! i=0 exited=0
  while [ "$i" -lt 80 ]; do
    kill -0 "$pid" 2>/dev/null || { exited=1; break; }
    sleep 0.25; i=$((i+1))
  done
  if [ "$exited" = 1 ]; then
    wait "$pid" 2>/dev/null; pass "stdio transport exits on its own after stdin EOF (exit $?)"
  else
    kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; fail "stdio transport did not exit within 20 s of stdin EOF"
  fi
  check "stdout received 0 bytes" [ "$(wc -c <"$ROOT/stdio.out" | tr -d ' ')" = 0 ]
  # Spec Open question 3 (default in force): when the stdio MCP arm ends on
  # stdin EOF the reporter says so once, as its last line on stderr; a UTF-8
  # pipe is plain mode, so the note carries the `·` separator and no glyph.
  local eof_notes; eof_notes="$(count_re '^stdin closed · stdio MCP transport ended$' "$ROOT/stdio.err")"
  check "spec Open question 3 default: stderr has exactly one 'stdin closed · stdio MCP transport ended' line ($eof_notes)" [ "$eof_notes" = 1 ]
  check "AC-W1-32: the note is the last stderr line" [ "$(tail -1 "$ROOT/stdio.err")" = 'stdin closed · stdio MCP transport ended' ]
  # AC-W1-33 (dry-run D1): the browser's CDP-socket teardown ERROR after the
  # stdin-EOF exit is dropped by the quiesced reporter (it stays in the log).
  check "AC-W1-33: no 'WS Connection error' line on stderr after the stdin-EOF exit" [ "$(count_fx 'WS Connection error' "$ROOT/stdio.err")" = 0 ]
  # AC-W1-32 names `aitm web` too: the same stdio config, bounded like the
  # bare run, nothing on stdout, the note exactly once and last.
  run_bounded "$ROOT/stdio-web.out" "$ROOT/stdio-web.err" 20 "$AITM_BIN" --config "$CFG_STDIO" web --no-open --listen "127.0.0.1:$WEB_PORT"
  if [ "$RC" = 124 ]; then
    fail "aitm web on the stdio transport did not exit within 20 s of stdin EOF"
  else
    pass "aitm web on the stdio transport exits on its own after stdin EOF (exit $RC)"
  fi
  check "aitm web: stdout received 0 bytes" [ "$(wc -c <"$ROOT/stdio-web.out" | tr -d ' ')" = 0 ]
  eof_notes="$(count_re '^stdin closed · stdio MCP transport ended$' "$ROOT/stdio-web.err")"
  check "aitm web: stderr has exactly one 'stdin closed · stdio MCP transport ended' line ($eof_notes)" [ "$eof_notes" = 1 ]
  check "aitm web: the note is the last stderr line" [ "$(tail -1 "$ROOT/stdio-web.err")" = 'stdin closed · stdio MCP transport ended' ]
  check "AC-W1-33: aitm web: no 'WS Connection error' line on stderr after the stdin-EOF exit" [ "$(count_fx 'WS Connection error' "$ROOT/stdio-web.err")" = 0 ]
  end_section "$ROOT/stdio.err" "$ROOT/stdio-web.err"
}

# ===========================================================================
section_tokens() {
  begin_section "10. no token in any stream or file (AC-W1-22)"
  mkdir -p "$ROOT/tokens"
  gen_secret > "$ROOT/tokens/op.secret"; gen_secret > "$ROOT/tokens/web.token"
  new_env tokens "$ROOT/tokens/op.secret" || return
  local opsecret t log; opsecret="$(cat "$ROOT/tokens/op.secret")"; t="$(cat "$ROOT/tokens/web.token")"
  log="$(log_path_for "$HOME_DIR")"
  start_server "$ROOT/web.out" "$ROOT/web.err" "$AITM_BIN" --config "$CFG" web --no-open --listen "127.0.0.1:$WEB_PORT" --token "$t"
  wait_for "$ROOT/web.err" '^Log: ' 30 || note "web ready card not seen (the server exited, or 30 s passed)"
  stop_server
  check "web: the bridge token appears exactly once on stderr" [ "$(count_fx "$t" "$ROOT/web.err")" = 1 ]
  check "web: that line is the 'Web UI: http://127.0.0.1:$WEB_PORT/#t=…' row" grep -q -E "^Web UI: http://127\.0\.0\.1:$WEB_PORT/#t=[^&[:space:]]+$" "$ROOT/web.err"
  local hits=$(( $(count_fx "$opsecret" "$ROOT/web.err") + $(count_fx "$opsecret" "$ROOT/web.out") + $(count_fx "$opsecret" "$log") ))
  check "web: mcp.operator_token appears in neither stderr, stdout nor the log" [ "$hits" = 0 ]
  local opb; opb="$(sed -n -E "s|^Operator: http://127\.0\.0\.1:$WEB_PORT/#t=([^&[:space:]]+)&expect=operator$|\1|p" "$ROOT/web.err" | head -1)"
  if [ -n "$opb" ]; then
    check "web: the operator bridge token appears exactly once on stderr" [ "$(count_fx "$opb" "$ROOT/web.err")" = 1 ]
    check "web: the operator bridge token is not in the log" [ "$(count_fx "$opb" "$log")" = 0 ]
    check "web: the operator bridge token differs from the secret and the bridge token" [ "$opb" != "$opsecret" -a "$opb" != "$t" ]
  else
    fail "web: no 'Operator: …#t=<token>&expect=operator' row on stderr"
  fi
  check "web: stdout empty" [ ! -s "$ROOT/web.out" ]
  check "web: the bridge token is not in the log" [ "$(count_fx "$t" "$log")" = 0 ]
  start_server "$ROOT/webraw.out" "$ROOT/webraw.err" env RUST_LOG=info "$AITM_BIN" --config "$CFG" web --no-open --listen "127.0.0.1:$WEB_PORT" --token "$t"
  wait_for "$ROOT/webraw.err" '^Log: ' 30 || note "RUST_LOG=info web run: ready card not seen (the server exited, or 30 s passed)"
  stop_server
  grep -a -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' "$ROOT/webraw.err" > "$ROOT/webraw.trace" 2>/dev/null
  check "RUST_LOG=info: the raw tracing stream has $(wc -l <"$ROOT/webraw.trace" | tr -d ' ') records and none carries the bridge token" [ "$(count_fx "$t" "$ROOT/webraw.trace")" = 0 ]
  check "RUST_LOG=info: no tracing record carries mcp.operator_token" [ "$(count_fx "$opsecret" "$ROOT/webraw.trace")" = 0 ]
  check "RUST_LOG=info: the bridge token still appears exactly once (the card row)" [ "$(count_fx "$t" "$ROOT/webraw.err")" = 1 ]
  end_section
}

# ===========================================================================
section_clistartup() {
  begin_section "11. tests/e2e/cli/cli-startup.sh passes unchanged (AC-W1-23)"
  local log="$ROOT/cli-startup.log"
  if [ -x "$here/cli-startup.sh" ]; then
    note "running cli-startup.sh (a few minutes)…"
    AITM_BIN="$AITM_BIN" "$here/cli-startup.sh" >"$log" 2>&1; local rc=$?
    local res; res="$(grep '^RESULT:' "$log" | tail -1)"
    note "cli-startup.sh: ${res:-<no RESULT line>} (exit $rc)"
    if [ "$rc" = 0 ] && printf '%s\n' "$res" | grep -q ', 0 failed,'; then
      pass "cli-startup.sh → $res"
    else
      fail "cli-startup.sh: exit $rc, ${res:-no RESULT line}"
      grep -E '^  FAIL' "$log" | head -10 | sed 's/^/  | /'
    fi
  else
    fail "$here/cli-startup.sh is missing or not executable"
  fi
  end_section
}

# ===========================================================================
section_liveenv() {
  begin_section "12. apps/web/scripts/live-env.mjs reaches readiness (AC-W1-24)"
  if [ ! -d "$repo_root/apps/web/node_modules" ]; then
    skip "live-env.mjs (apps/web/node_modules missing; cd apps/web && npm ci)"; return
  fi
  if ! command -v node >/dev/null 2>&1; then
    skip "live-env.mjs (node not on PATH)"; return
  fi
  new_home liveenv
  local out="$ROOT/liveenv.log"
  (
    cd "$repo_root" && HOME="$HOME_DIR" AITM_BIN="$AITM_BIN" node -e \
      "import('./apps/web/scripts/live-env.mjs').then(async m => { const a = await m.startAitm({}); if (!a.operatorUiUrl) throw new Error('no operator url'); await a.stop(); })"
  ) >"$out" 2>&1 </dev/null &
  local pid=$! i=0 rc=124
  while kill -0 "$pid" 2>/dev/null; do
    [ "$i" -ge 240 ] && { kill -9 "$pid" 2>/dev/null; break; }
    sleep 0.25; i=$((i+1))
  done
  wait "$pid" 2>/dev/null; rc=$?
  if [ "$rc" = 0 ]; then
    pass "live-env.mjs startAitm({}) captured the operator URL and stopped (exit 0)"
  else
    fail "live-env.mjs startAitm({}) exit $rc"; tail -15 "$out" | redact | sed 's/^/  | /'
  fi
  end_section
}

# ===========================================================================
section_perf() {
  begin_section "13. performance against the previous release (AC-W1-30)"
  # The thread-COUNT comparison against 0.5.10 ("new == old") was retired
  # (live dry-run D6): the W1 binary carries three named threads 0.5.10 does
  # not — `aitm-audit-reads`, `aitm-audit-control`, `aitm-audit-agent`, main's
  # durable audit log (#259), not this branch — so equality is wrong by
  # construction. What AC-W1-30 guards is that no `aitm-term` thread outlives
  # the ready card: that is the pass/fail below (SKIP when thread names cannot
  # be read); both counts and the names present in the new binary but not in
  # the old are printed as notes so a reviewer sees the audit threads explained.
  if [ -z "$AITM_OLD_BIN" ] || [ ! -x "$AITM_OLD_BIN" ]; then
    skip "one-shot timing vs the old binary (AITM_OLD_BIN unset or not executable)"
    skip "no aitm-term thread after the ready card (same)"
    return
  fi
  new_env perf || return
  # Warm-up: both binaries mint/load the CA in the shared isolated HOME.
  HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG" scope list >/dev/null 2>&1 </dev/null; local rn=$?
  HOME="$HOME_DIR" "$AITM_OLD_BIN" --config "$CFG" scope list >/dev/null 2>&1 </dev/null; local ro=$?
  if [ "$rn" != 0 ] || [ "$ro" != 0 ]; then
    skip "one-shot timing (warm-up failed: new exit $rn, old exit $ro — the old binary may not read this config)"
    skip "no aitm-term thread after the ready card (same)"
    return
  fi
  local med_new med_old
  med_new="$(median_of 11 "$AITM_BIN" --config "$CFG" scope list)"
  med_old="$(median_of 11 "$AITM_OLD_BIN" --config "$CFG" scope list)"
  note "aitm scope list median real of 11 runs: new=${med_new}s old=${med_old}s"
  check "one-shot median: new ($med_new) <= old ($med_old) + 0.005" awk -v n="$med_new" -v o="$med_old" 'BEGIN { exit !(n <= o + 0.005) }'
  start_server "$ROOT/thr-new.out" "$ROOT/thr-new.err" "$AITM_BIN" --config "$CFG"
  wait_for "$ROOT/thr-new.err" '^Log: ' 30 || note "new binary: ready card not seen (the server exited, or 30 s passed)"
  sleep 1
  local tn tnames="$ROOT/thr-new.names" onames="$ROOT/thr-old.names" have_new=0 have_old=0
  tn="$(thread_count "$SERVER_PID")"
  thread_names "$SERVER_PID" "$tnames" && have_new=1
  stop_server
  if [ "$have_new" = 1 ]; then
    check "no thread named aitm-term after the ready card ($(wc -l <"$tnames" | tr -d ' ') thread names read, $(count_fx aitm-term "$tnames") aitm-term)" \
      [ "$(count_fx aitm-term "$tnames")" = 0 ]
  else
    skip "no aitm-term thread after the ready card (thread names unavailable: \`sample\` missing, failed or over 60 s; or no /proc)"
  fi
  start_server "$ROOT/thr-old.out" "$ROOT/thr-old.err" "$AITM_OLD_BIN" --config "$CFG"
  # 0.5.10 logs INFO on stdout.
  wait_for "$ROOT/thr-old.out" 'proxy listening' 30 || wait_for "$ROOT/thr-old.err" 'proxy listening' 5 || note "old binary: 'proxy listening' did not appear"
  sleep 1
  local to; to="$(thread_count "$SERVER_PID")"
  thread_names "$SERVER_PID" "$onames" && have_old=1
  stop_server
  # Informational since D6 (see the heading comment): the counts and the names.
  note "threads after readiness: new=$tn old=$to (informational; the count comparison was retired, dry-run D6)"
  if [ "$have_new" = 1 ] && [ "$have_old" = 1 ]; then
    local extra; extra="$(comm -23 <(sort -u "$tnames") <(sort -u "$onames") | tr '\n' ' ')"
    note "thread names in new not in old: ${extra:-(none)}"
    note "new binary's threads: $(sort "$tnames" | uniq -c | awk '{ c=$1; $1=""; sub(/^ /, ""); printf "%s%s× %s", (n++ ? ", " : ""), c, $0 }')"
  else
    note "thread names: new $([ "$have_new" = 1 ] && echo read || echo unavailable), old $([ "$have_old" = 1 ] && echo read || echo unavailable)"
  fi
  end_section "$ROOT/thr-new.err"
}

# ===========================================================================
section_tty() {
  begin_section "14. TTY recordings (AC-W1-4, 7, 8, 9, 10, 11, 25) and the forced-colour pipe"
  # The recordings' precondition, decided first so it is reported even when
  # the pipe run below cannot set up.
  local no_tty=""
  if [ ! -t 1 ]; then
    no_tty="stdout is not a TTY: run the script directly in a terminal, not through a pipe"
  elif ! pty_probe; then
    no_tty="script cannot allocate a pty here"
  fi

  # The pipe form needs no terminal: CLICOLOR_FORCE never puts an escape byte
  # into a non-TTY stream (spec D2 rule 7, amended AC-W1-11).
  if new_env ttypipe; then
    start_server "$ROOT/forced.out" "$ROOT/forced.err" env CLICOLOR_FORCE=1 "$AITM_BIN" --config "$CFG"
    wait_for "$ROOT/forced.err" '^Log: ' 30 || note "ready card not seen (the server exited, or 30 s passed)"
    stop_server
    check "CLICOLOR_FORCE=1 aitm 2>forced.err: the run reached its ready card" grep -q -E '^Log: ' "$ROOT/forced.err"
    check "CLICOLOR_FORCE=1 aitm 2>forced.err: zero ESC bytes" [ "$(count_fx $'\x1b' "$ROOT/forced.err")" = 0 ]
  fi

  if [ -n "$no_tty" ]; then
    skip "TTY recordings ($no_tty)"
    return
  fi

  new_env tty || return
  local cast txt tail14 cursor_up clear_line
  # (a) UTF-8 terminal: in-place drawing, braille spinner, the M1 final screen.
  cast="$ROOT/tty.cast"; txt="$cast.txt"; tail14="$cast.tail"
  record_server "$cast" env TERM="$REC_TERM" "$AITM_BIN" --config "$CFG" || note "see the assertions below"
  stripped "$cast" > "$txt"; tail -14 "$txt" > "$tail14"
  cursor_up="$(bytecount "$cast" '\x1b\[[0-9]*A')"; clear_line="$(bytecount "$cast" '\x1b\[2K')"
  check "tty: ≥ 1 cursor-up sequence ($cursor_up)" [ "$cursor_up" -ge 1 ]
  check "tty: ≥ 1 clear-line sequence ($clear_line)" [ "$clear_line" -ge 1 ]
  check "tty: header '›•‹ aitmproxy'" grep -q -F '›•‹ aitmproxy' "$txt"
  check "tty: at least one braille spinner frame (U+2800–U+283F)" [ "$(bytecount "$cast" '\xe2\xa0[\x80-\xbf]')" -ge 1 ]
  check "tty: pill '● aitmproxy · listening 127.0.0.1:$PROXY_PORT'" grep -q -F "● aitmproxy · listening 127.0.0.1:$PROXY_PORT" "$tail14"
  check "tty: Bus row" grep -q -F "$(printf '  %-14s%s' Bus 'loopback 127.0.0.1:')" "$tail14"
  check "tty: Scope row" grep -q -F "$(printf '  %-14s%s' Scope 'Nothing is decrypted until a host is in Scope.')" "$tail14"
  check "tty: Scope fix line" grep -q -F "$(printf '  %-14s%s' '' '▸ aitm scope add --host <host>')" "$tail14"
  # Fresh HOME ⇒ untrusted CA (see section 2): the pill word, the CA next
  # step, and the System proxy row (two-space indent, label padded to 14).
  check "tty: pill says '· CA untrusted' (fresh HOME, AC-W1-7)" grep -q -F '· CA untrusted' "$tail14"
  check "tty: CA fix line '▸ aitm ca install' (AC-W1-7)" grep -q -F '▸ aitm ca install' "$tail14"
  check "tty: System proxy row (AC-W1-8)" grep -q -E '^  System proxy  ' "$tail14"
  # shellcheck disable=SC2088  # the literal `~/` is what the card prints
  check "tty: Log row shortened to ~/" grep -q -F "$(printf '  %-14s%s' Log '~/')" "$tail14"
  echo "  --- SGR-stripped final screen (last 14 lines of tty.cast) ---"
  sed 's/^/  | /' "$tail14"

  # (b) C locale: ASCII glyphs only.
  cast="$ROOT/tty-ascii.cast"; txt="$cast.txt"
  record_server "$cast" env TERM="$REC_TERM" LC_ALL=C LC_CTYPE=C LANG=C "$AITM_BIN" --config "$CFG" || note "see the assertions below"
  stripped "$cast" > "$txt"
  check "LC_ALL=C: no byte ≥ 0x80 in the recording (outside the scratch paths)" [ "$(bytecount "$cast" '[\x80-\xff]' "$ROOT")" = 0 ]
  check "LC_ALL=C: done glyph is '+' ('  + N detections ready')" grep -q -E '^  \+ [0-9]+ detections ready' "$txt"
  check "LC_ALL=C: pill is '* aitmproxy - listening'" grep -q -F "* aitmproxy - listening 127.0.0.1:$PROXY_PORT" "$txt"

  # (c) NO_COLOR: no SGR, animation kept.
  cast="$ROOT/tty-nocolor.cast"
  record_server "$cast" env TERM="$REC_TERM" NO_COLOR=1 "$AITM_BIN" --config "$CFG" || note "see the assertions below"
  check "NO_COLOR=1: zero SGR sequences" [ "$(bytecount "$cast" '\x1b\[[0-9;]*m')" = 0 ]
  check "NO_COLOR=1: cursor-up sequences still present" [ "$(bytecount "$cast" '\x1b\[[0-9]*A')" -ge 1 ]

  # (d) CI: plain lines on a TTY.
  cast="$ROOT/tty-ci.cast"
  record_server "$cast" env TERM="$REC_TERM" CI=1 "$AITM_BIN" --config "$CFG" || note "see the assertions below"
  check "CI=1: zero cursor-up sequences" [ "$(bytecount "$cast" '\x1b\[[0-9]*A')" = 0 ]

  # (e)–(h) colour forcing is TTY-only and ordered: flag > NO_COLOR > CLICOLOR_FORCE > TERM.
  cast="$ROOT/tty-force.cast"
  record_server "$cast" env TERM=dumb CLICOLOR_FORCE=1 "$AITM_BIN" --config "$CFG" || note "see the assertions below"
  check "TERM=dumb CLICOLOR_FORCE=1: SGR colour present (ESC[3Xm)" [ "$(bytecount "$cast" '\x1b\[3[0-9]m')" -ge 1 ]
  check "TERM=dumb CLICOLOR_FORCE=1: zero cursor-up sequences (no animation on a dumb TTY)" [ "$(bytecount "$cast" '\x1b\[[0-9]*A')" = 0 ]
  cast="$ROOT/tty-dumb.cast"
  record_server "$cast" env TERM=dumb "$AITM_BIN" --config "$CFG" || note "see the assertions below"
  check "TERM=dumb alone: zero SGR colour sequences" [ "$(bytecount "$cast" '\x1b\[3[0-9]m')" = 0 ]
  cast="$ROOT/tty-never.cast"
  record_server "$cast" env TERM=dumb CLICOLOR_FORCE=1 "$AITM_BIN" --color=never --config "$CFG" || note "see the assertions below"
  check "TERM=dumb CLICOLOR_FORCE=1 --color=never: zero SGR colour sequences" [ "$(bytecount "$cast" '\x1b\[3[0-9]m')" = 0 ]
  cast="$ROOT/tty-always.cast"
  record_server "$cast" env TERM="$REC_TERM" NO_COLOR=1 "$AITM_BIN" --color=always --config "$CFG" || note "see the assertions below"
  check "NO_COLOR=1 --color=always: SGR colour present" [ "$(bytecount "$cast" '\x1b\[3[0-9]m')" -ge 1 ]

  # (i) aitm tui: phases, the clear, the alternate screen; `q` leaves only the header.
  cast="$ROOT/tui.cast"
  if start_feeder tui_feeder "$cast"; then
    start_recording "$cast" env TERM="$REC_TERM" "$AITM_BIN" --config "$CFG" tui
    [ -n "$REC_PID" ] || { note "aitm tui recording: aitm child of script(${SCRIPT_PID:-none}) not found"; recording_diag "$cast"; }
    local i=0
    while kill -0 "$SCRIPT_PID" 2>/dev/null && [ "$i" -lt 200 ]; do sleep 0.25; i=$((i+1)); done
    kill -0 "$SCRIPT_PID" 2>/dev/null && note "aitm tui did not exit on 'q' within 50 s; sending Ctrl-C"
    end_recording INT
  else
    note "aitm tui recording: cannot open a feeder pipe"
  fi
  local verdict
  verdict="$(python3 - "$cast" "›•‹ aitmproxy $EXPECT_VERSION" <<'PY'
import re, sys
data = open(sys.argv[1], 'rb').read()
header = sys.argv[2].encode()
esc = re.compile(rb'\x1b\[[0-9;?<=>!]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78cDEHM]')
strip = lambda b: esc.sub(b'', b).replace(b'\r', b'')
i = data.find(b'\x1b[?1049h')
if i < 0:
    print('FAIL: no alternate-screen enter (ESC[?1049h) in the cast'); sys.exit(1)
pre = data[:i]
if b'\x1b[2K' not in pre:
    print('FAIL: no clear-line (ESC[2K) before the alternate screen'); sys.exit(1)
if header not in strip(pre):
    print('FAIL: header %r not drawn before the alternate screen' % header.decode()); sys.exit(1)
j = data.rfind(b'\x1b[?1049l')
if j < 0:
    print('FAIL: no alternate-screen leave (ESC[?1049l) in the cast'); sys.exit(1)
tail = strip(data[j + len(b'\x1b[?1049l'):]).strip()
if tail in (b'', header):
    print('OK: %d clear-line sequences before ESC[?1049h; text after the last ESC[?1049l: %r' % (pre.count(b'\x1b[2K'), tail.decode('utf-8', 'replace'))); sys.exit(0)
print('FAIL: text after the last ESC[?1049l is %r' % tail[:200].decode('utf-8', 'replace')); sys.exit(1)
PY
)"
  local vrc=$?
  note "aitm tui recording: $verdict"
  check "aitm tui: phases → clear-line → ESC[?1049h; after ESC[?1049l only the header remains" [ "$vrc" = 0 ]
  end_section "$ROOT/tty.cast.txt"
}

# ===========================================================================
want 1  preboot    && section_preboot
want 2  piped      && section_piped
want 3  portinuse  && section_portinuse
want 4  exitcodes  && section_exitcodes
want 5  log        && section_log
want 6  warnings   && section_warnings
want 7  unwritable && section_unwritable
want 8  raw        && section_raw
want 9  stdout     && section_stdout
want 10 tokens     && section_tokens
want 11 clistartup && section_clistartup
want 12 liveenv    && section_liveenv
want 13 perf       && section_perf
want 14 tty        && section_tty

echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
