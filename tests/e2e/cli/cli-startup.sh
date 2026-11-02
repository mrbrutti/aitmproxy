#!/usr/bin/env bash
# Real functional tests for the `aitm` CLI's DEFAULT first-run experience.
#
# These boot the REAL `aitm` binary (no mocks) and assert the behaviour an
# operator sees on a fresh machine: the embedded `obscura` browser engine is
# discovered from a package layout, `aitm web` starts cleanly and the web UI is
# reachable, a taken port fails with ONE clear error (never a cryptic os-error
# after a success line), and the one-shot verbs / operator-token / config paths
# behave. This is the class of bug that green unit tests kept missing.
#
# Repeatable: run it as often as you like. Every test uses an isolated HOME and
# its own free ports, so it never touches your real config/CA and never needs
# the default 8080/8081/8082 to be free.
#
# Usage:
#   tests/e2e/cli/cli-startup.sh
#
# Environment:
#   AITM_BIN   path to the aitm binary under test
#              (default: <repo>/target/debug/aitm, else target/release/aitm)
#   OBSCURA    path to the obscura engine to stage in the package-layout tests
#              (default: the obscura beside AITM_BIN)
#
# Exit status is non-zero if any assertion fails.
set -uo pipefail

# ---------------------------------------------------------------------------
# Locate the binary under test.
# ---------------------------------------------------------------------------
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../../.." && pwd)"

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
AITM_BIN="$(cd "$(dirname "$AITM_BIN")" && pwd)/$(basename "$AITM_BIN")"
export AITM_AUDIT_LOG="${AITM_AUDIT_LOG:-off}"
OBSCURA="${OBSCURA:-$(dirname "$AITM_BIN")/obscura}"

echo "aitm under test: $AITM_BIN"
[ -x "$OBSCURA" ] && echo "obscura engine:  $OBSCURA" || echo "obscura engine:  (absent; obscura-discovery tests will be skipped)"
echo

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
PASS=0; FAIL=0; SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }
have_obscura() { [ -x "$OBSCURA" ]; }

# A free loopback TCP port (bind :0, read it back, release).
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

# Hold a port until the returned PID is killed. The holder's stdout/stderr are
# redirected away from this function's own stdout so the `$(hold_port ...)`
# command substitution gets EOF and returns immediately (it must not wait for
# the 120s-sleeping holder to exit).
hold_port() {
  python3 -c "import socket,time,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',int(sys.argv[1]))); s.listen()
time.sleep(120)" "$1" >/dev/null 2>&1 &
  echo $!
}

# Write an isolated config for one test into $1, with three free ports.
# Globals set: PROXY_PORT BROWSER_PORT WEB_PORT CFG HOME_DIR
new_env() {
  local name="$1"
  HOME_DIR="$ROOT/$name/home"; mkdir -p "$HOME_DIR"
  CFG="$ROOT/$name/config.yaml"
  PROXY_PORT="$(free_port)"; BROWSER_PORT="$(free_port)"; WEB_PORT="$(free_port)"
  cat > "$CFG" <<YAML
listen: 127.0.0.1:$PROXY_PORT
ca:
  dir: $ROOT/$name/ca
browser:
  proxy_addr: 127.0.0.1:$BROWSER_PORT
YAML
}

# Start aitm in the background with stdin held open (a long sleep). `aitm` /
# `aitm web` / `aitm tui` also run the stdio MCP transport, which ends the whole
# process when its stdin reaches EOF; a terminal operator keeps stdin open (the
# TTY blocks), so holding it open reproduces that documented flow deterministically
# whether or not the test runs under a TTY. Sets SERVER_PID.
start_server() {
  local log="$1"; shift
  HOME="$HOME_DIR" "$@" >"$log" 2>&1 < <(sleep 300) &
  SERVER_PID=$!
}

# Wait up to $2 seconds for the server logging to $1 to come up (a "listening"
# line) or to exit on its own.
wait_ready() {
  local log="$1" secs="$2" i=0
  while kill -0 "$SERVER_PID" 2>/dev/null; do
    grep -qE "web UI \(agent\):|proxy listening" "$log" 2>/dev/null && break
    [ "$i" -ge "$((secs*4))" ] && break
    sleep 0.25; i=$((i+1))
  done
}

# Stop a server: SIGTERM first so aitm reaps its obscura child, then a bounded
# escalation to SIGKILL. Never blocks on `wait` (a pipe-fed stdio server can be
# slow to act on SIGTERM).
stop_server() {
  local pid="${1:-$SERVER_PID}" i=0
  kill "$pid" 2>/dev/null
  while kill -0 "$pid" 2>/dev/null; do
    [ "$i" -ge 32 ] && { kill -9 "$pid" 2>/dev/null; break; }
    sleep 0.25; i=$((i+1))
  done
}

# Start, wait for ready, then stop — for tests that only assert startup lines.
run_server() { local log="$1" secs="$2"; shift 2; start_server "$log" "$@"; wait_ready "$log" "$secs"; stop_server; }

# Wait up to $2 seconds until something is actually accepting on 127.0.0.1:$1.
wait_port_listening() {
  local port="$1" secs="$2" i=0
  while [ "$i" -lt "$((secs*4))" ]; do
    python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(("127.0.0.1",int(sys.argv[1])))==0 else 1)' "$port" 2>/dev/null && return 0
    sleep 0.25; i=$((i+1))
  done
  return 1
}

# Run a command expected to EXIT on its own (e.g. fail fast on a port conflict),
# bounded by $2 seconds so a lost race or a regression is a FAIL, never a hang.
# Sets RC to the exit status, or 124 if it had to be killed for exceeding $2.
run_bounded() {
  local log="$1" secs="$2"; shift 2
  HOME="$HOME_DIR" "$@" >"$log" 2>&1 </dev/null &
  local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    [ "$i" -ge "$((secs*4))" ] && { kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; RC=124; return; }
    sleep 0.25; i=$((i+1))
  done
  wait "$pid" 2>/dev/null; RC=$?
}

in_log()  { grep -qiE "$2" "$1"; }

# ===========================================================================
echo "### obscura discovery ###"

# 1) Dev layout: obscura sits beside the aitm binary.
if have_obscura && [ "$(dirname "$AITM_BIN")/obscura" = "$OBSCURA" ]; then
  new_env disc_dev
  run_server "$ROOT/disc_dev.log" 12 "$AITM_BIN" --config "$CFG" web --no-open --listen 127.0.0.1:"$WEB_PORT"
  if in_log "$ROOT/disc_dev.log" "obscura probed" && ! in_log "$ROOT/disc_dev.log" "embedded browser unavailable"; then
    pass "obscura discovered beside the binary (dev layout)"
  else
    fail "obscura NOT discovered in dev layout"; sed -n '1,20p' "$ROOT/disc_dev.log"
  fi
else
  skip "dev-layout discovery (obscura not beside AITM_BIN)"
fi

# 2) Homebrew layout: bin/aitm is a SYMLINK into libexec, obscura in libexec.
#    Reproduces Matt's "/opt/homebrew/bin/obscura" miss; the fix canonicalizes
#    current_exe() so exe_dir lands on the real libexec.
if have_obscura; then
  pfx="$ROOT/brew/prefix"; mkdir -p "$pfx/bin" "$pfx/libexec"
  cp "$AITM_BIN" "$pfx/libexec/aitm"; cp "$OBSCURA" "$pfx/libexec/obscura"
  ln -s "../libexec/aitm" "$pfx/bin/aitm"
  new_env brew
  run_server "$ROOT/brew.log" 12 "$pfx/bin/aitm" --config "$CFG" web --no-open --listen 127.0.0.1:"$WEB_PORT"
  if in_log "$ROOT/brew.log" "obscura probed" && ! in_log "$ROOT/brew.log" "embedded browser unavailable"; then
    pass "obscura discovered via Homebrew-style bin symlink (canonicalized)"
  else
    fail "obscura NOT discovered via bin symlink"; grep -iE "obscura|unavailable|Looked in" "$ROOT/brew.log" | head
  fi

  # 2b) Exact Homebrew shape: a DOUBLE symlink
  #     /opt/homebrew/bin/aitm -> Cellar/<v>/bin/aitm -> Cellar/<v>/libexec/aitm,
  #     obscura in Cellar/<v>/libexec. canonicalize() must resolve the whole chain.
  cell="$ROOT/brew2/Cellar/aitm/0.5.0"; opt="$ROOT/brew2/opt"
  mkdir -p "$cell/bin" "$cell/libexec" "$opt"
  cp "$AITM_BIN" "$cell/libexec/aitm"; cp "$OBSCURA" "$cell/libexec/obscura"
  ln -s "../libexec/aitm" "$cell/bin/aitm"
  ln -s "../Cellar/aitm/0.5.0/bin/aitm" "$opt/aitm"
  new_env brew2
  run_server "$ROOT/brew2.log" 12 "$opt/aitm" --config "$CFG" web --no-open --listen 127.0.0.1:"$WEB_PORT"
  if in_log "$ROOT/brew2.log" "obscura probed" && ! in_log "$ROOT/brew2.log" "embedded browser unavailable"; then
    pass "obscura discovered via Homebrew-exact double symlink"
  else
    fail "obscura NOT discovered via double symlink"; grep -iE "obscura|unavailable|Looked in" "$ROOT/brew2.log" | head
  fi

  # 3) aitm is a REAL file in bin/, obscura only in a sibling libexec/.
  #    Canonicalize cannot help here; the libexec-sibling candidate must.
  pfx2="$ROOT/lib/prefix"; mkdir -p "$pfx2/bin" "$pfx2/libexec"
  cp "$AITM_BIN" "$pfx2/bin/aitm"; cp "$OBSCURA" "$pfx2/libexec/obscura"
  new_env libx
  run_server "$ROOT/libx.log" 12 "$pfx2/bin/aitm" --config "$CFG" web --no-open --listen 127.0.0.1:"$WEB_PORT"
  if in_log "$ROOT/libx.log" "obscura probed" && ! in_log "$ROOT/libx.log" "embedded browser unavailable"; then
    pass "obscura discovered in sibling libexec (aitm real file in bin)"
  else
    fail "obscura NOT discovered in sibling libexec"; grep -iE "obscura|unavailable|Looked in" "$ROOT/libx.log" | head
  fi
else
  skip "Homebrew/libexec discovery (no obscura to stage)"
fi

# ===========================================================================
echo "### aitm web starts clean and is reachable ###"
new_env web
run_server "$ROOT/web.log" 12 "$AITM_BIN" --config "$CFG" web --no-open --listen 127.0.0.1:"$WEB_PORT"
agent_url="$(grep -oE 'http://127.0.0.1:[0-9]+/#t=[0-9a-f]+' "$ROOT/web.log" | head -1)"
if [ -n "$agent_url" ]; then
  pass "web printed the one-time agent URL with a token"
else
  fail "web did not print the agent URL"; sed -n '1,25p' "$ROOT/web.log"
fi
# Reachable: the UI HTML is served at the root (token lives client-side). Use a
# fresh env/ports so this never races the first run's teardown.
new_env web2
start_server "$ROOT/web2.log" "$AITM_BIN" --config "$CFG" web --no-open --listen 127.0.0.1:"$WEB_PORT"
wait_ready "$ROOT/web2.log" 12
# Proxy port must also be listening (the whole point of the fix).
if in_log "$ROOT/web2.log" "proxy listening"; then pass "proxy port bound alongside the web UI"; else fail "proxy port not listening"; fi
# Poll the HTTP root a few times; serve() may begin accepting a beat after bind.
code=000
for i in $(seq 1 20); do
  code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$WEB_PORT/" 2>/dev/null)" || code=000
  [ "$code" = "200" ] && break
  sleep 0.25
done
stop_server
if [ "$code" = "200" ]; then pass "web UI reachable over HTTP (200)"; else fail "web UI not reachable (HTTP $code)"; fi

# ===========================================================================
echo "### port conflict is graceful (one clear error, no success-then-crash) ###"

# web: hold the proxy port (wait until it is really listening), then start aitm web.
new_env conf_web
holder="$(hold_port "$PROXY_PORT")"
if wait_port_listening "$PROXY_PORT" 10; then
  run_bounded "$ROOT/conf_web.log" 20 "$AITM_BIN" --config "$CFG" web --no-open --listen 127.0.0.1:"$WEB_PORT"
  if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ] \
     && in_log "$ROOT/conf_web.log" "already in use" \
     && in_log "$ROOT/conf_web.log" "$PROXY_PORT" \
     && ! in_log "$ROOT/conf_web.log" "os error 48" \
     && ! in_log "$ROOT/conf_web.log" "web UI \(agent\):"; then
    pass "aitm web: one clear port error, no success line, no raw os-error, non-zero exit"
  else
    fail "aitm web port conflict not graceful (RC=$RC)"; sed -n '1,25p' "$ROOT/conf_web.log"
  fi
else
  fail "test setup: holder never listened on $PROXY_PORT"
fi
kill "$holder" 2>/dev/null

# bare aitm (stdio MCP server): same pre-bind guard.
new_env conf_bare
holder="$(hold_port "$PROXY_PORT")"
if wait_port_listening "$PROXY_PORT" 10; then
  run_bounded "$ROOT/conf_bare.log" 20 "$AITM_BIN" --config "$CFG"
  if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ] && in_log "$ROOT/conf_bare.log" "already in use" && ! in_log "$ROOT/conf_bare.log" "os error 48"; then
    pass "bare aitm: clear port error, non-zero exit"
  else
    fail "bare aitm port conflict not graceful (RC=$RC)"; sed -n '1,25p' "$ROOT/conf_bare.log"
  fi
else
  fail "test setup: holder never listened on $PROXY_PORT"
fi
kill "$holder" 2>/dev/null

# ===========================================================================
echo "### one-shot verbs and operator-token ###"

new_env oneshot
if HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG" flow list >"$ROOT/flow.log" 2>&1; then
  pass "one-shot 'aitm flow list' exits 0"
else
  fail "'aitm flow list' failed"; cat "$ROOT/flow.log"
fi

new_env optoken
if HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG" operator-token generate >"$ROOT/optoken.log" 2>&1 \
   && grep -qiE "operator" "$ROOT/optoken.log" \
   && grep -qiE "operator_token" "$CFG"; then
  pass "'operator-token generate' writes the config and confirms"
else
  fail "'operator-token generate' did not behave"; cat "$ROOT/optoken.log"
fi
# Re-running without --force must refuse rather than clobber; --force succeeds.
HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG" operator-token generate >"$ROOT/optoken2.log" 2>&1; rc2=$?
HOME="$HOME_DIR" "$AITM_BIN" --config "$CFG" operator-token generate --force >"$ROOT/optoken3.log" 2>&1; rc3=$?
if [ "$rc2" -ne 0 ] && [ "$rc3" -eq 0 ]; then
  pass "'operator-token generate' refuses to overwrite without --force"
else
  fail "operator-token overwrite guard wrong (rc2=$rc2 rc3=$rc3)"; cat "$ROOT/optoken2.log"
fi

# ===========================================================================
echo "### bad config is a clear error, not a panic ###"
badcfg="$ROOT/bad.yaml"; printf 'listen: 127.0.0.1:9\nnot_a_real_key: 1\n' > "$badcfg"
HOME="$ROOT/badhome" "$AITM_BIN" --config "$badcfg" flow list >"$ROOT/bad.log" 2>&1; rc=$?
if [ "$rc" -ne 0 ] && in_log "$ROOT/bad.log" "config file" && ! in_log "$ROOT/bad.log" "panicked"; then
  pass "malformed config: clear error naming the file, no panic"
else
  fail "malformed config not handled gracefully (rc=$rc)"; cat "$ROOT/bad.log"
fi

# ===========================================================================
echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
