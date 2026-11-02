#!/usr/bin/env bash
# Live proof of the wave-2 help product: the grouped top page, the group and
# verb pages, did-you-mean, dotted names never in prose, the `Usage:`-form
# mode errors, the structured `[y/N]` prompt, the sibling scripts and the
# rich TTY rendering.
#
# Spec: docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md
#       (AC-W2-1 … AC-W2-10)
# Plan: docs/superpowers/plans/2026-11-01-cli-terminal-reporting-wave2-plan.md
#       (Task 16; the section numbers below are the plan's)
#
# Runs the REAL `aitm` binary (no mocks, no fixtures). No ports, no server:
# help is pre-boot, so sections 1–3 also prove that nothing is created and
# nothing is booted; sections 4–5 run the one-shot CLI's usage errors (those
# boot and write the log); section 6 declines the `ca install` prompt with
# `n`, so no keychain is written (`--yes` is never passed, memory
# `aitmproxy-live-proof-needs-matts-yes`). Every section runs in its own
# fresh HOME under a temp dir, so it never touches your real
# ~/Library/Application Support/aitmproxy. Repeatable.
#
# Usage:
#   tests/e2e/cli/help.sh
#
# Environment:
#   AITM_BIN             the aitm binary under test
#                        (default: <repo>/target/debug/aitm, else target/release/aitm)
#   AITM_EXPECT_VERSION  the version the top page's first line must carry
#                        (default: the workspace Cargo.toml `version`)
#   AITM_HELP_SECTIONS   comma list of the sections to run, by number or name
#                        (default: all). Names: top groups verbs dym usage
#                        prompt siblings tty
#
# Needs `python3` on PATH (the binary's real path for the catalogue lookup,
# byte counts in the `script` casts); without it the script exits 2 at once,
# as its sibling term-reporting.sh does.
#
# A section whose precondition is missing SKIPs with a reason and never FAILs:
#   - sections 6 and 8 (the prompt and the TTY rendering) need stdout to be a
#     terminal (`[ -t 1 ]`) and a pty `script` can allocate;
#   - the `aitm-tui --help` pin needs `aitm-tui` beside AITM_BIN;
#   - the Cargo.lock check needs `git` and one of its two base refs;
#   - with no bundled catalogue discoverable beside AITM_BIN the top page
#     still lists 19 groups (`l4` is built in since p1b #267; the catalogue adds verbs, not a group).
#
# The recordings' stdin feeders write into anonymous pipes (never FIFOs: BSD
# `script` refuses a FIFO stdin, dry-run D5) and are tracked by PID, so no
# `sleep` outlives the run; the aitm child of a `script` recording is found
# through `pgrep -P`, never a global pkill. Nothing here prints a token: no
# section serves a bus or reads a config, and the failure-context dumps
# redact `#t=` URL fragments anyway.
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
command -v python3 >/dev/null || { echo "FATAL: python3 is required (real paths, byte counts)" >&2; exit 2; }
AITM_BIN="$(cd "$(dirname "$AITM_BIN")" && pwd)/$(basename "$AITM_BIN")"
TUI_BIN="$(dirname "$AITM_BIN")/aitm-tui"
EXPECT_VERSION="${AITM_EXPECT_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/Cargo.toml" | head -1)}"
SECTIONS="${AITM_HELP_SECTIONS:-all}"
# Decided once, at top level: `tty_reason` is read through `$(...)`, whose
# stdout is a pipe, so `[ -t 1 ]` inside it would always say "not a TTY".
if [ -t 1 ]; then STDOUT_IS_TTY=1; else STDOUT_IS_TTY=0; fi

# The runner's own settings must not leak into the binary under test: every
# section states the variables it needs on the command line. The three
# script variables decide the group count (plan C30), so they go too.
unset RUST_LOG NO_COLOR CLICOLOR_FORCE AITM_TERM CI AITM_LOG_FILE AITM_CONFIG XDG_CONFIG_HOME AITM_NO_BUNDLED_SCRIPTS AITM_BUNDLED_SCRIPTS AITM_SCRIPTS
# The pages use the rich separator (`—`, `·`), which a pipe gets whenever any
# of LC_ALL/LC_CTYPE/LANG names UTF-8 (spec T1).
case "${LC_ALL:-}${LC_CTYPE:-}${LANG:-}" in
  *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) ;;
  *) export LANG=en_US.UTF-8 ;;
esac
# The TTY recordings need a real, non-dumb TERM.
REC_TERM="${TERM:-xterm-256color}"
[ "$REC_TERM" = dumb ] && REC_TERM=xterm-256color
# The pty size the recordings' wrapper sets (section 8 narrows it to 80
# columns, the width a pipe is assumed to have, so its line-for-line
# comparison with the piped page is exact).
REC_ROWS=40; REC_COLS=120

# The bundled catalogue the binary will find: crates/aitm/src/bundled.rs
# `candidates`, in its order, over the binary's real path (symlinks
# resolved, as `std::fs::canonicalize` does). Empty when none is a
# directory. Since p1b #267 the top page lists 19 groups either way (`l4` is
# built in); the directory is reported for the record.
catalogue_dir() {
  local real dir c
  real="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$AITM_BIN")"
  dir="$(dirname "$real")"
  for c in "$dir/share/aitm/scripts" "$dir/../share/aitm/scripts" "$dir/../../share/aitm/scripts" "$dir/../../scripts/bundled"; do
    if [ -d "$c" ]; then (cd "$c" && pwd); return 0; fi
  done
  return 1
}
CATALOGUE_DIR="$(catalogue_dir || true)"

echo "aitm under test:  $AITM_BIN"
echo "expected version: $EXPECT_VERSION"
[ -x "$TUI_BIN" ] && echo "aitm-tui:         $TUI_BIN" || echo "aitm-tui:         (absent; the 'aitm-tui --help' pin will be skipped)"
[ -n "$CATALOGUE_DIR" ] && echo "catalogue:        $CATALOGUE_DIR" || echo "catalogue:        (none beside the binary; the bundled check/l4 scripts are absent)"
echo "platform:         $OS"
echo "sections:         $SECTIONS"
echo

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aitm-help-XXXXXX")"
if [ -z "$ROOT" ] || [ ! -d "$ROOT" ]; then
  echo "FATAL: could not create a scratch directory under ${TMPDIR:-/tmp}" >&2
  exit 2
fi
PASS=0; FAIL=0; SKIP=0
RC=""; SCRIPT_PID=""; REC_PID=""; FEEDER_PID=""; FEEDER_FD=""; SECTION_FAIL0=0
HOME_DIR=""; ERR_ACC=""

cleanup() {
  local p
  for p in $(jobs -p) ${REC_PID:-} ${SCRIPT_PID:-} ${FEEDER_PID:-}; do kill "$p" 2>/dev/null; done
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

# want <number> <name>: is this section selected by AITM_HELP_SECTIONS?
want() {
  case ",$SECTIONS," in *,all,*|*,"$1",*|*,"$2",*) return 0 ;; esac
  return 1
}

# check "<description>" <command...>: PASS when the command succeeds.
check() { local desc="$1"; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }
starts_with() { case "$1" in "$2"*) return 0 ;; esac; return 1; }
# same_bytes <file> <file...>: every file is byte-identical to the first.
same_bytes() { local first="$1" f; shift; for f in "$@"; do cmp -s "$first" "$f" || return 1; done; }

# Line counts (0 when the file is missing). `count_re` takes an ERE,
# `count_fx` a fixed string.
count_re() { local n; n="$(grep -a -c -E -- "$1" "$2" 2>/dev/null)"; printf '%s\n' "${n:-0}"; }
count_fx() { local n; n="$(grep -a -c -F -- "$1" "$2" 2>/dev/null)"; printf '%s\n' "${n:-0}"; }

# bytecount <file> <python bytes regex> [path-prefix]: how many times the
# byte pattern occurs (locale-independent; for the `script` casts). With a
# third argument, every run of non-blank bytes that starts with that literal
# path is removed first (the scratch paths a cast echoes); the prefix is
# escaped, so a TMPDIR with `|`, `+`, `.` or `[` in it cannot break the
# expression.
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
# widened to every CSI final byte and the charset/keypad escapes).
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

fsize() { if [ "$OS" = Darwin ]; then stat -f %z "$1"; else stat -c %s "$1"; fi; }
# The log file aitm derives for a HOME (spec D7, amendment B).
log_path_for() {
  if [ "$OS" = Darwin ]; then printf '%s/Library/Application Support/aitmproxy/logs/aitm.log' "$1"
  else printf '%s/.config/aitmproxy/logs/aitm.log' "$1"; fi
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

# new_home <name>: a fresh isolated HOME. Sets HOME_DIR.
new_home() { HOME_DIR="$ROOT/$1/home"; mkdir -p "$HOME_DIR"; }

# ---------------------------------------------------------------------------
# Page helpers.
# ---------------------------------------------------------------------------

# run_page <name> <args...>: `aitm <args>` in HOME_DIR with stdin closed;
# stdout to $ROOT/<name>.out, stderr to $ROOT/<name>.err. Sets RC.
run_page() {
  local name="$1"; shift
  HOME="$HOME_DIR" "$AITM_BIN" "$@" >"$ROOT/$name.out" 2>"$ROOT/$name.err" </dev/null; RC=$?
}

# block_lines <file> <heading>: the lines between the line that is exactly
# <heading> and the next blank line.
block_lines() { awk -v h="$2" '$0 == h { f = 1; next } f && /^$/ { exit } f { print }' "$1"; }

# rows <file> <heading>: the block's rows — two-space indent then a
# non-space. A description's continuation line starts at column 28 (plan
# C40) and is dropped.
rows() { block_lines "$1" "$2" | grep -E '^  [^ ]'; }

# left_cells <file> <heading>: each row's left cell — the text after the
# indent up to the two-space gap before its description. A left cell wider
# than 24 columns stands alone on its row (its description follows on the
# next line) and is taken whole.
left_cells() { rows "$1" "$2" | sed -E -e 's/^  //' -e 's/  .*$//' -e 's/ *$//'; }

# verb_words <left cell>: the verb's words — everything before the first
# ` --flag`, ` <placeholder>` or ` [optional]` token: `add` from
# `add --host <host>`, `passthrough add` from `passthrough add --host <host>`
# (a three-segment name's verb is two words; pages.rs `verb_row`).
verb_words() { printf '%s\n' "$1" | sed -E 's/ +(--|<|\[).*$//'; }

# created_since <marker>: how many entries under HOME_DIR are newer than it.
created_since() { find "$HOME_DIR" -mindepth 1 -newer "$1" | wc -l | tr -d ' '; }

# dotted_count <file>: lines carrying a dotted command-like token
# (`scope.add`) once the `log:` footer lines are dropped (AC-W2-4).
dotted_count() { local n; n="$(grep -v -E '^ *log: ' "$1" | grep -c -E '[a-z_]+\.[a-z_]+')"; printf '%s\n' "${n:-0}"; }

# err_case <label> <want-rc> [<stderr literal>...] -- <cmd...>: the command
# exits <want-rc>, its stderr has every literal, its stdout is empty. The
# stderr is kept at $ROOT/ec.err and appended to $ERR_ACC when that is set.
err_case() {
  local label="$1" want="$2"; shift 2
  local lits=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do lits+=("$1"); shift; done
  [ "${1:-}" = -- ] && shift
  HOME="$HOME_DIR" "$@" >"$ROOT/ec.out" 2>"$ROOT/ec.err" </dev/null; local rc=$? ok=1 why="" l
  [ "$rc" = "$want" ] || { ok=0; why="rc=$rc (want $want)"; }
  for l in ${lits[@]+"${lits[@]}"}; do
    grep -q -F -- "$l" "$ROOT/ec.err" || { ok=0; why="$why; stderr lacks '$l'"; }
  done
  [ ! -s "$ROOT/ec.out" ] || { ok=0; why="$why; stdout not empty"; }
  [ -n "$ERR_ACC" ] && cat "$ROOT/ec.err" >> "$ERR_ACC"
  if [ "$ok" = 1 ]; then
    pass "$label → exit $rc, stderr has $(printf "'%s' " ${lits[@]+"${lits[@]}"})stdout empty"
  else
    fail "$label: ${why#; }"; head -6 "$ROOT/ec.err" | redact | sed 's/^/  | /'
  fi
}

# mode_help <label> <args...> -- <stdout ERE>...: `aitm <args>` exits 0 and
# its stdout has every ERE.
mode_help() {
  local label="$1"; shift
  local args=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do args+=("$1"); shift; done
  [ "${1:-}" = -- ] && shift
  run_page mode-help ${args[@]+"${args[@]}"}
  local ok=1 why="" re
  [ "$RC" -eq 0 ] || { ok=0; why="rc=$RC"; }
  for re in "$@"; do
    grep -q -E -- "$re" "$ROOT/mode-help.out" || { ok=0; why="$why; stdout lacks /$re/"; }
  done
  if [ "$ok" = 1 ]; then
    pass "$label → exit 0, stdout has $(printf '/%s/ ' "$@")"
  else
    fail "$label: ${why#; }"; head -6 "$ROOT/mode-help.out" "$ROOT/mode-help.err" | sed 's/^/  | /'
  fi
}

# ---------------------------------------------------------------------------
# TTY recordings through `script` (sections 6 and 8; the wave-1 helpers).
# ---------------------------------------------------------------------------

# start_recording <cast> <cmd...>: run the command inside a pty recorded to
# <cast>, its stdin the feeder pipe `start_feeder` opened (FEEDER_FD). The
# pty is sized REC_ROWS x REC_COLS by `stty` inside the wrapper (a pipe-fed
# `script` would otherwise hand the child a 0x0 window) and the wrapper
# `exec`s the command, so the aitm process is `script`'s direct child; it is
# found through `pgrep -P` (never a global pkill). `script`'s own stderr goes
# to <cast>.script.err for `recording_diag`. Sets SCRIPT_PID and REC_PID
# (empty when the child was not found before `script` exited or in 10 s).
start_recording() {
  local cast="$1"; shift
  local wrap="$ROOT/rec.$RANDOM$RANDOM.sh"
  { printf 'stty rows %s cols %s 2>/dev/null\nexec' "$REC_ROWS" "$REC_COLS"; printf ' %q' "$@"; printf '\n'; } > "$wrap"
  : > "$cast"
  if [ -z "$FEEDER_FD" ]; then
    note "recording: no feeder pipe open (start_feeder first)"; SCRIPT_PID=""; REC_PID=""; return 1
  fi
  if [ "$OS" = Darwin ]; then
    # BSD `script` exits with the child's status.
    HOME="$HOME_DIR" script -q -t 0 "$cast" /bin/sh "$wrap" <&"$FEEDER_FD" 7<&- >/dev/null 2>"$cast.script.err" &
  else
    # util-linux `script` needs -e to return the child's status.
    HOME="$HOME_DIR" script -q -e -f -c "/bin/sh '$wrap'" "$cast" <&"$FEEDER_FD" 7<&- >/dev/null 2>"$cast.script.err" &
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

# finish_recording <secs>: wait for the recorded command to exit on its own
# (bounded), then reap the feeder. Sets RC to `script`'s exit status — the
# child's — or 124 when the bound passed and the recording had to be ended.
finish_recording() {
  local secs="$1" i=0
  while kill -0 "$SCRIPT_PID" 2>/dev/null; do
    if [ "$i" -ge "$((secs*4))" ]; then
      note "recording: still running after ${secs}s; sending Ctrl-C"
      end_recording INT; RC=124; return
    fi
    sleep 0.25; i=$((i+1))
  done
  wait "$SCRIPT_PID" 2>/dev/null; RC=$?
  reap_feeder
}

# start_feeder <cmd...>: run <cmd> in the background with its stdout on an
# anonymous pipe whose read end this shell holds on fd 7, as a recording's
# stdin. Sets FEEDER_FD and FEEDER_PID; finish_recording/end_recording (and
# cleanup) reap the writer. Not a FIFO: macOS implements FIFOs over sockets
# and BSD `script` does `tcgetattr`/`ioctl(TIOCGWINSZ)` on its stdin, which
# a pipe answers with ENOTTY (tolerated) and a FIFO with EOPNOTSUPP — so a
# FIFO-fed `script` exits at once with `tcgetattr/ioctl: Operation not
# supported on socket` and records nothing (live dry-run D5). The process
# substitution's PID is `$!` right after the `exec` (bash 3.2 and 5.x), so
# the writer is tracked without a FIFO and no `sleep` outlives the run. One
# recording at a time, hence the fixed fd.
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
# (dry-run D5) is visible in the run's output instead of silent.
recording_diag() {
  local cast="$1" serr="$1.script.err" text=""
  [ -s "$serr" ] && text="$(tr '\n' ' ' <"$serr" | head -c 300)"
  note "recording: $(basename "$cast") is $(fsize "$cast" 2>/dev/null || echo 0) bytes; script stderr: [${text:-<empty>}]"
}

# record_oneshot <cast> <cmd...>: a command that exits on its own, run in a
# pty recorded to <cast> with an open, silent stdin. Sets RC (its exit
# status; 124 when it had to be ended after 30 s; 125 with no feeder pipe).
record_oneshot() {
  local cast="$1"; shift
  if ! start_feeder sleep 90; then
    note "recording: cannot open a feeder pipe"; RC=125; return 1
  fi
  start_recording "$cast" "$@"
  finish_recording 30
}

# Can `script` allocate a pty here at all? (The Claude sandbox cannot.)
pty_probe() {
  if [ "$OS" = Darwin ]; then script -q /dev/null true </dev/null >/dev/null 2>&1
  else script -q -c true /dev/null </dev/null >/dev/null 2>&1; fi
}

# tty_reason: empty when the recordings can run here; else why not.
tty_reason() {
  if [ "$STDOUT_IS_TTY" != 1 ]; then
    printf '%s' "stdout is not a TTY: run the script directly in a terminal, not through a pipe"
  elif ! pty_probe; then
    printf '%s' "script cannot allocate a pty here"
  fi
}

# The stdin feeder for the `ca install` recording: answer `n` once the
# prompt is on screen (2 s), then keep the pipe open. `exec` so the tracked
# FEEDER_PID is this sleeper and reap_feeder ends it.
prompt_feeder() {
  sleep 2
  printf 'n\n'
  exec sleep 60
}

# ===========================================================================
section_top() {
  begin_section "1. the top page (AC-W2-1, AC-W2-7, AC-W2-10)"
  new_home top
  touch "$ROOT/marker-top"; sleep 1
  local i=0 a out="$ROOT/top1.out"
  for a in --help -h help; do
    i=$((i+1)); run_page "top$i" "$a"
    if [ "$RC" -eq 0 ] && [ ! -s "$ROOT/top$i.err" ]; then
      pass "aitm $a → exit 0, stderr empty"
    else
      fail "aitm $a: rc=$RC stderr=[$(head -c 160 "$ROOT/top$i.err" | tr '\n' ' ')]"
    fi
  done
  check "aitm --help, aitm -h, aitm help: stdout byte-identical (cmp) (AC-W2-7)" same_bytes "$ROOT/top1.out" "$ROOT/top2.out" "$ROOT/top3.out"
  local first; first="$(head -1 "$out")"
  check "first line is 'aitm $EXPECT_VERSION — intercepting proxy for authorized security testing' (got '$first')" \
    [ "$first" = "aitm $EXPECT_VERSION — intercepting proxy for authorized security testing" ]
  check "has a 'Groups:' heading" grep -q -E '^Groups:$' "$out"
  check "has an 'Options:' heading" grep -q -E '^Options:$' "$out"
  check "has an 'Examples:' heading" grep -q -E '^Examples:$' "$out"
  check "has a 'Learn more:' heading" grep -q -E '^Learn more:$' "$out"
  check "has the row '  scope …which hosts are decrypted'" grep -q -E '^  scope +which hosts are decrypted$' "$out"
  check "has the literal 'aitm scope add --host <host>'" grep -q -F 'aitm scope add --host <host>' "$out"
  local lines want_lines
  lines="$(block_lines "$out" "Groups:" | wc -l | tr -d ' ')"
  # 19 with or without the catalogue since p1b #267 (`l4.privilege` registers on every core).
  want_lines=19
  [ -n "$CATALOGUE_DIR" ] || note "no bundled catalogue beside $AITM_BIN (the group list is unchanged: 19)"
  check "Groups: block is $want_lines lines (got $lines)" [ "$lines" = "$want_lines" ]
  HOME="$HOME_DIR" AITM_NO_BUNDLED_SCRIPTS=1 "$AITM_BIN" --help >"$ROOT/top-nocat.out" 2>"$ROOT/top-nocat.err" </dev/null
  local nocat; nocat="$(block_lines "$ROOT/top-nocat.out" "Groups:" | wc -l | tr -d ' ')"
  check "AITM_NO_BUNDLED_SCRIPTS=1 aitm --help: Groups: block is exactly 19 lines (got $nocat)" [ "$nocat" = 19 ]
  check "piped: zero ESC bytes (AC-W2-1)" [ "$(count_fx $'\x1b' "$out")" = 0 ]
  local created; created="$(created_since "$ROOT/marker-top")"
  check "help created nothing under a fresh HOME ($created entries)" [ "$created" = 0 ]
  check "no log file exists ($(log_path_for "$HOME_DIR"))" [ ! -e "$(log_path_for "$HOME_DIR")" ]
  local med; med="$(median_of 5 "$AITM_BIN" --help)"
  note "aitm --help median real of 5 runs: ${med}s"
  check "aitm --help median wall < 0.100 s" awk -v m="$med" 'BEGIN { exit !(m < 0.100) }'
  # AC-W2-10: no new package in Cargo.lock since the wave-1 tip.
  if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local base=""
    base="$(git -C "$repo_root" merge-base HEAD claude/cli-ux-terminal-reporting-64b09b 2>/dev/null)" \
      || base="$(git -C "$repo_root" merge-base HEAD origin/main 2>/dev/null)"
    if [ -n "$base" ]; then
      local added; added="$(git -C "$repo_root" diff "$base" -- Cargo.lock | grep -c '^+name = ')"
      check "Cargo.lock: no new package since $(git -C "$repo_root" rev-parse --short "$base") (+name lines: ${added:-0}) (AC-W2-10)" [ "${added:-0}" = 0 ]
    else
      skip "Cargo.lock check: neither claude/cli-ux-terminal-reporting-64b09b nor origin/main is a known ref here"
    fi
  else
    skip "Cargo.lock check: git unavailable, or $repo_root is not a git work tree"
  fi
  end_section "$ROOT/top1.err" "$ROOT/top-nocat.err"
}

# ===========================================================================
section_groups() {
  begin_section "2. group pages (AC-W2-2, AC-W2-3, AC-W2-7)"
  new_home groups
  run_page groups-top --help
  if [ "$RC" -ne 0 ]; then
    fail "aitm --help: rc=$RC (cannot read the group list)"; end_section "$ROOT/groups-top.err"; return
  fi
  local names; names="$(rows "$ROOT/groups-top.out" "Groups:" | awk '{ print $1 }')"
  [ -n "$names" ] || fail "no Groups: rows on the top page"
  local g first ok why
  while IFS= read -r g; do
    [ -n "$g" ] || continue
    ok=1; why=""
    run_page "grp-$g" "$g"
    [ "$RC" -eq 0 ] || { ok=0; why="$why; rc=$RC"; }
    [ ! -s "$ROOT/grp-$g.err" ] || { ok=0; why="$why; stderr not empty"; }
    first="$(head -1 "$ROOT/grp-$g.out")"
    starts_with "$first" "aitm $g — " || { ok=0; why="$why; first line [$first]"; }
    grep -q -E '^Usage:$' "$ROOT/grp-$g.out" || { ok=0; why="$why; no Usage:"; }
    grep -q -E '^Verbs:$' "$ROOT/grp-$g.out" || { ok=0; why="$why; no Verbs:"; }
    run_page "grp-$g-help" help "$g"
    cmp -s "$ROOT/grp-$g.out" "$ROOT/grp-$g-help.out" || { ok=0; why="$why; aitm help $g differs"; }
    run_page "grp-$g-flag" "$g" --help
    cmp -s "$ROOT/grp-$g.out" "$ROOT/grp-$g-flag.out" || { ok=0; why="$why; aitm $g --help differs"; }
    if [ "$ok" = 1 ]; then
      pass "aitm $g → exit 0, stderr empty, 'aitm $g — …', Usage:, Verbs:; = aitm help $g = aitm $g --help"
    else
      fail "aitm $g: ${why#; }"; head -4 "$ROOT/grp-$g.err" | redact | sed 's/^/  | /'
    fi
  done <<EOF
$names
EOF
  if [ -s "$ROOT/grp-scope.out" ]; then
    local last; last="$(tail -1 "$ROOT/grp-scope.out")"
    check "aitm scope: last line is 'Nothing is decrypted until a host is in Scope.' (got '$last')" \
      [ "$last" = "Nothing is decrypted until a host is in Scope." ]
    local cells; cells="$(left_cells "$ROOT/grp-scope.out" "Verbs:")"
    check "aitm scope: Verbs: rows are exactly 'add --host <host>', 'remove --host <host>', 'list'" \
      [ "$cells" = "$(printf 'add --host <host>\nremove --host <host>\nlist')" ]
    [ "$cells" = "$(printf 'add --host <host>\nremove --host <host>\nlist')" ] || printf '%s\n' "$cells" | sed 's/^/  | /'
  else
    fail "aitm scope printed no page (scope missing from the Groups: rows?)"
  fi
  run_page grp-scan-again scan
  check "aitm scan → exit 0 (AC-W2-3's group case; rc=$RC)" [ "$RC" -eq 0 ]
  end_section "$ROOT/groups-top.err"
}

# ===========================================================================
# verb_page_ok <group> <verb words...>: `aitm <g> <v> --help` is a verb page:
# exit 0, stderr empty, `Usage:`, a `  aitm <g> <v>` usage line, `Examples:`
# and at least one `  $ aitm <g> <v>` example. One FAIL line and 1 when any
# expectation misses.
verb_page_ok() {
  local g="$1"; shift
  local v="$*" name why=""
  name="vp-$g-${v// /-}"
  run_page "$name" "$g" "$@" --help
  [ "$RC" -eq 0 ] || why="$why; rc=$RC"
  [ ! -s "$ROOT/$name.err" ] || why="$why; stderr not empty"
  grep -q -E '^Usage:$' "$ROOT/$name.out" || why="$why; no Usage:"
  grep -q -E "^  aitm $g $v" "$ROOT/$name.out" || why="$why; no '  aitm $g $v' usage line"
  grep -q -E '^Examples:$' "$ROOT/$name.out" || why="$why; no Examples:"
  grep -q -E "^  \\\$ aitm $g $v" "$ROOT/$name.out" || why="$why; no '  \$ aitm $g $v' example"
  [ -z "$why" ] && return 0
  fail "aitm $g $v --help: ${why#; }"; head -4 "$ROOT/$name.err" | redact | sed 's/^/  | /'
  return 1
}

section_verbs() {
  begin_section "3. verb pages (AC-W2-2)"
  new_home verbs
  touch "$ROOT/marker-verbs"; sleep 1
  run_page verbs-top --help
  if [ "$RC" -ne 0 ]; then
    fail "aitm --help: rc=$RC (cannot read the group list)"; end_section "$ROOT/verbs-top.err"; return
  fi
  local g cell v words pages bad total=0
  while IFS= read -r g; do
    [ -n "$g" ] || continue
    run_page "vg-$g" "$g"
    if [ "$RC" -ne 0 ]; then fail "aitm $g: rc=$RC (cannot read its Verbs: rows)"; continue; fi
    pages=0; bad=0
    while IFS= read -r cell; do
      [ -n "$cell" ] || continue
      v="$(verb_words "$cell")"
      if [ -z "$v" ]; then fail "aitm $g: no verb in the Verbs: row '$cell'"; bad=$((bad+1)); continue; fi
      pages=$((pages+1))
      read -r -a words <<<"$v"
      verb_page_ok "$g" "${words[@]}" || bad=$((bad+1))
    done <<EOF
$(left_cells "$ROOT/vg-$g.out" "Verbs:")
EOF
    total=$((total+pages))
    if [ "$pages" -eq 0 ]; then
      fail "aitm $g: no Verbs: rows"
    elif [ "$bad" -eq 0 ]; then
      pass "aitm $g: $pages verb pages → exit 0, stderr empty, Usage:, '  aitm $g <verb>', Examples:, '  \$ aitm $g <verb>'"
    fi
  done <<EOF
$(rows "$ROOT/verbs-top.out" "Groups:" | awk '{ print $1 }')
EOF
  note "$total verb pages rendered"
  run_page vp-scope-add scope add --help
  check "aitm scope add --help: has '--host <string>'" grep -q -F -- '--host <string>' "$ROOT/vp-scope-add.out"
  check "aitm scope add --help: has '[required]'" grep -q -F -- '[required]' "$ROOT/vp-scope-add.out"
  local first; first="$(head -1 "$ROOT/vp-scope-add.out")"
  check "aitm scope add --help: first line is the description's first line (got '$first')" \
    [ "$first" = "Add a host, host:port, or *.wildcard to Scope. New connections to it are" ]
  run_page vp-flow-detail flow detail --help
  check "aitm flow detail --help: has '(default inline)' (C46)" grep -q -F '(default inline)' "$ROOT/vp-flow-detail.out"
  run_page vp-help-scope-add help scope add
  check "aitm help scope add is byte-identical to aitm scope add --help (AC-W2-7)" same_bytes "$ROOT/vp-scope-add.out" "$ROOT/vp-help-scope-add.out"
  local created; created="$(created_since "$ROOT/marker-verbs")"
  check "the whole loop created nothing under a fresh HOME ($created entries)" [ "$created" = 0 ]
  check "no log file exists after the loop (nothing booted, no record written)" [ ! -e "$(log_path_for "$HOME_DIR")" ]
  end_section "$ROOT/verbs-top.err"
}

# ===========================================================================
section_dym() {
  begin_section "4. did-you-mean and dotted names (AC-W2-3, AC-W2-4)"
  new_home dym
  touch "$ROOT/marker-dym"; sleep 1
  ERR_ACC="$ROOT/dym.errs"; : > "$ERR_ACC"
  # The explicit, pre-boot case first, before anything in this HOME boots:
  # its "nothing created" check needs a HOME no earlier case has written.
  err_case "aitm help scpe" 2 'unknown command `scpe`' 'did you mean: scope' 'fix: aitm --help' -- "$AITM_BIN" help scpe
  check "aitm help scpe: no 'log:' line (pre-boot)" [ "$(count_re '^ *log: ' "$ROOT/ec.err")" = 0 ]
  check "aitm help scpe: created nothing under a fresh HOME ($(created_since "$ROOT/marker-dym") entries)" [ "$(created_since "$ROOT/marker-dym")" = 0 ]
  err_case "aitm scpe add --host x"   2 'unknown command `scpe`' 'did you mean: scope' 'fix: aitm --help' -- "$AITM_BIN" scpe add --host x
  err_case "aitm scope ad"            2 'unknown command `scope ad`' 'did you mean: scope add' 'fix: aitm scope' -- "$AITM_BIN" scope ad
  err_case "aitm flow tabel"          2 'did you mean: flow table' -- "$AITM_BIN" flow tabel
  err_case "aitm flow list --bogus 1" 2 'unknown flag --bogus for `flow list`' 'Usage: aitm flow list' 'fix: aitm flow list --help' -- "$AITM_BIN" flow list --bogus 1
  err_case "aitm scope add"           2 'missing required flag --host for `scope add`' -- "$AITM_BIN" scope add
  local dotted; dotted="$(dotted_count "$ERR_ACC")"
  check "no dotted command name in any of the six stderrs, log: lines dropped ($dotted hits) (AC-W2-4)" [ "$dotted" = 0 ]
  [ "$dotted" = 0 ] || grep -v -E '^ *log: ' "$ERR_ACC" | grep -E '[a-z_]+\.[a-z_]+' | head -6 | redact | sed 's/^/  | /'
  ERR_ACC=""
  end_section
}

# ===========================================================================
section_usage() {
  begin_section "5. Usage:-form errors and the formula pins (AC-W2-5, AC-W2-9)"
  new_home usage
  err_case "aitm tui --bad"      2 'tui takes no further arguments' 'Usage: aitm [--config <path>] tui' -- "$AITM_BIN" tui --bad
  err_case "aitm operator-token" 2 'operator-token needs a verb' 'Usage: aitm [--config <path>] operator-token generate [--force]' -- "$AITM_BIN" operator-token
  err_case "aitm web --bad"      2 'unknown argument to `aitm web`: --bad' 'Usage: aitm [--config <path>] web' 'fix: aitm web --help' -- "$AITM_BIN" web --bad
  err_case "aitm --bad"          2 'expected a command before flags, got `--bad`' 'Usage: aitm <group> <verb> [--flag <value>]...' -- "$AITM_BIN" --bad
  mode_help "aitm web --help"            web --help            -- 'web operator UI' '^Usage:$'
  mode_help "aitm tui --help"            tui --help            -- '^Usage:$' '^  aitm \[--config <path>\] tui$'
  mode_help "aitm operator-token --help" operator-token --help -- '^  aitm \[--config <path>\] operator-token generate \[--force\]$'
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
  end_section
}

# ===========================================================================
section_prompt() {
  begin_section "6. the [y/N] prompt, declined (AC-W2-8)"
  local no_tty; no_tty="$(tty_reason)"
  if [ -n "$no_tty" ]; then
    skip "ca install prompt recording ($no_tty)"; return
  fi
  new_home prompt
  # Mint the CA once: the prompt loads it to print its fingerprint.
  HOME="$HOME_DIR" "$AITM_BIN" scope list >"$ROOT/prompt-mint.out" 2>"$ROOT/prompt-mint.err" </dev/null; local mrc=$?
  check "aitm scope list (mints the CA in the fresh HOME) → exit 0 (rc=$mrc)" [ "$mrc" -eq 0 ]
  # The operator's login keychain, read before and after (never written: the
  # answer is `n`, and `--yes` is never passed).
  local keychain="$HOME/Library/Keychains/login.keychain-db" before="" after=""
  if [ "$OS" = Darwin ] && command -v security >/dev/null 2>&1 && [ -f "$keychain" ]; then
    before="$(security find-certificate -a -c aitmproxy "$keychain" 2>&1 | grep -c '^keychain:')"
  fi
  local cast="$ROOT/prompt.cast" txt="$ROOT/prompt.cast.txt"
  if ! start_feeder prompt_feeder; then
    fail "ca install prompt: cannot open a feeder pipe for the recording"; return
  fi
  start_recording "$cast" env TERM="$REC_TERM" "$AITM_BIN" ca install
  [ -n "$REC_PID" ] || { note "recording: aitm child of script(${SCRIPT_PID:-none}) not found"; recording_diag "$cast"; }
  finish_recording 30
  stripped "$cast" > "$txt"
  check "aitm ca install, answered n → exit 1 (rc=$RC)" [ "$RC" = 1 ]
  check "prompt: the fingerprint on its own line '  SHA-256 XX:…:XX' (32 bytes)" grep -q -E '^  SHA-256 ([0-9A-F]{2}:){31}[0-9A-F]{2}$' "$txt"
  check "prompt: a line 'Install it? [y/N]'" grep -q -E '^Install it\? \[y/N\]' "$txt"
  check "prompt: 'aborted: ca install not run'" grep -q -F 'aborted: ca install not run' "$txt"
  local dotted; dotted="$(grep -v '/' "$txt" | grep -c -E '[a-z_]+\.[a-z_]+')"
  check "prompt: no dotted command name outside the path-bearing lines (${dotted:-0} hits)" [ "${dotted:-0}" = 0 ]
  if [ -n "$before" ]; then
    after="$(security find-certificate -a -c aitmproxy "$keychain" 2>&1 | grep -c '^keychain:')"
    check "login keychain unchanged: ${before:-0} aitmproxy certificate(s) before, ${after:-0} after" [ "${before:-0}" = "${after:-0}" ]
  else
    note "no keychain comparison here (not macOS, no security(1), or no login keychain); the answer was n and --yes was never passed"
  fi
  echo "  --- SGR-stripped prompt recording (first 12 lines) ---"
  head -12 "$txt" | sed 's/^/  | /'
  end_section "$cast.script.err" "$ROOT/prompt-mint.err"
}

# ===========================================================================
# sibling <label> <log> <script> [VAR=value...]: a sibling e2e script passes
# (`RESULT: … 0 failed …`, exit 0) against the same binary.
sibling() {
  local label="$1" log="$2" script="$3"; shift 3
  if [ ! -x "$script" ]; then
    fail "$label: $script is missing or not executable"; return
  fi
  note "running $label (minutes)…"
  env "$@" AITM_BIN="$AITM_BIN" AITM_EXPECT_VERSION="$EXPECT_VERSION" "$script" >"$log" 2>&1; local rc=$?
  local res; res="$(grep '^RESULT:' "$log" | tail -1)"
  note "$label: ${res:-<no RESULT line>} (exit $rc)"
  if [ "$rc" = 0 ] && printf '%s\n' "$res" | grep -q ', 0 failed,'; then
    pass "$label → $res"
  else
    fail "$label: exit $rc, ${res:-no RESULT line}"
    grep -E '^  FAIL' "$log" | head -10 | redact | sed 's/^/  | /'
  fi
}

section_siblings() {
  begin_section "7. sibling scripts (AC-W2-9)"
  sibling "cli-startup.sh" "$ROOT/cli-startup.log" "$here/cli-startup.sh"
  sibling "term-reporting.sh §1 preboot + §4 exitcodes" "$ROOT/term-reporting.log" "$here/term-reporting.sh" AITM_TERM_SECTIONS=preboot,exitcodes
  end_section
}

# ===========================================================================
section_tty() {
  begin_section "8. TTY rendering (AC-W2-1, the rich half)"
  local no_tty; no_tty="$(tty_reason)"
  if [ -n "$no_tty" ]; then
    skip "TTY help recordings ($no_tty)"; return
  fi
  new_home tty
  # The piped page to compare with: section 1's when it ran, else one now.
  local piped="$ROOT/top1.out"
  if [ ! -s "$piped" ]; then
    run_page tty-piped --help; piped="$ROOT/tty-piped.out"
    note "section 1 did not run; the piped page for the comparison was taken now"
  fi
  REC_COLS=80
  local cast="$ROOT/tty-help.cast" txt="$ROOT/tty-help.cast.txt"
  record_oneshot "$cast" env TERM="$REC_TERM" "$AITM_BIN" --help
  check "tty: aitm --help → exit 0 (rc=$RC)" [ "$RC" = 0 ]
  local dim bold up
  dim="$(LC_ALL=C grep -a -c -F -- $'\x1b[2m' "$cast")"; bold="$(LC_ALL=C grep -a -c -F -- $'\x1b[1m' "$cast")"
  up="$(bytecount "$cast" '\x1b\[[0-9]*A')"
  check "tty: ≥ 19 lines with a dim SGR (ESC[2m: ${dim:-0})" [ "${dim:-0}" -ge 19 ]
  check "tty: ≥ 5 lines with a bold SGR (ESC[1m: ${bold:-0})" [ "${bold:-0}" -ge 5 ]
  check "tty: zero cursor-movement sequences (ESC[<n>A: $up)" [ "$up" = 0 ]
  stripped "$cast" > "$txt"
  # Trailing newlines normalised to one on both sides; nothing else.
  printf '%s\n' "$(cat "$txt")" > "$txt.norm"
  printf '%s\n' "$(cat "$piped")" > "$ROOT/piped.norm"
  if cmp -s "$ROOT/piped.norm" "$txt.norm"; then
    pass "tty: the SGR-stripped recording equals the piped page line for line ($(wc -l <"$txt.norm" | tr -d ' ') lines)"
  else
    fail "tty: the SGR-stripped recording differs from the piped page"
    diff "$ROOT/piped.norm" "$txt.norm" | head -12 | sed 's/^/  | /'
  fi
  cast="$ROOT/tty-help-nocolor.cast"
  record_oneshot "$cast" env TERM="$REC_TERM" NO_COLOR=1 "$AITM_BIN" --help
  local sgr; sgr="$(bytecount "$cast" '\x1b\[[0-9;]*m')"
  check "tty NO_COLOR=1: zero SGR sequences ($sgr)" [ "$sgr" = 0 ]
  REC_COLS=120
  end_section "$ROOT/tty-help.cast.script.err"
}

# ===========================================================================
want 1 top      && section_top
want 2 groups   && section_groups
want 3 verbs    && section_verbs
want 4 dym      && section_dym
want 5 usage    && section_usage
want 6 prompt   && section_prompt
want 7 siblings && section_siblings
want 8 tty      && section_tty

echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
