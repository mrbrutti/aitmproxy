#!/usr/bin/env bash
# tui-live-check — drive the real TUI by keystrokes (tmux) against a real core
# with real traffic, the way an operator would: capture → arm intercept →
# paused request → review → edit the request in the raw editor → Apply & Resume
# → inspect the real response body (F5) → build and run a PoC → disarm.
#
# Two modes:
#   scripts/tui-live-check.sh embed   # `aitm tui`: core + TUI in one process (default)
#   scripts/tui-live-check.sh bus     # `aitm` server + `aitm-tui --bus … --token …`
#
# Needs: tmux, curl, python3 (a local echo server stands in for the upstream so
# the check is deterministic and offline). Must run in a real shell (binds ports).
# Exit status is the number of failed steps; the pane text of each step is kept
# under $WORK for reading.

set -uo pipefail

MODE=${1:-embed}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${PORT:-18080}
BPORT=${BPORT:-18081}
MCP=${MCP:-19090}
ECHO=${ECHO:-18888}
TOKEN=tui-live-check-token
S=tuilive
WORK=$(mktemp -d -t tui-live-check)
POC="$WORK/pocs"
mkdir -p "$POC/out"
FAILS=0
STEP=0

say() { printf '\n== %s\n' "$*"; }
pane() { tmux capture-pane -p -t "$S" -S -60 2>/dev/null; }

# expect_pane <seconds> <needle>… — wait until every needle is on screen.
expect_pane() {
  local secs=$1; shift
  local deadline=$((SECONDS + secs))
  while :; do
    local text; text=$(pane)
    local ok=1
    for n in "$@"; do grep -qF -- "$n" <<<"$text" || ok=0; done
    if [ "$ok" = 1 ]; then return 0; fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      printf '%s\n' "$text" > "$WORK/step-$STEP-fail.txt"
      return 1
    fi
    sleep 0.3
  done
}

step() {
  STEP=$((STEP + 1))
  local name=$1; shift
  if "$@"; then
    printf 'ok   %2d  %s\n' "$STEP" "$name"
    pane > "$WORK/step-$STEP-ok.txt"
  else
    printf 'FAIL %2d  %s   (pane: %s)\n' "$STEP" "$name" "$WORK/step-$STEP-fail.txt"
    FAILS=$((FAILS + 1))
  fi
}

keys() { tmux send-keys -t "$S" "$@"; sleep 0.4; }
type_text() { tmux send-keys -t "$S" -l -- "$1"; sleep 0.3; }

cleanup() {
  tmux send-keys -t "$S" q 2>/dev/null || true
  sleep 0.5
  tmux kill-session -t "$S" 2>/dev/null || true
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "${ECHO_PID:-}" ] && kill "$ECHO_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ---- upstream: a local echo server that returns the request's headers as JSON.
cat > "$WORK/echo.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_any(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        out = json.dumps({"method": self.command, "path": self.path,
                          "headers": {k.lower(): v for k, v in self.headers.items()},
                          "body": body}, indent=2).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_any
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/echo.py" "$ECHO" &
ECHO_PID=$!

# ---- config: free ports, scope = the echo host, PoC dirs.
cat > "$WORK/aitm.yaml" <<EOF
listen: 127.0.0.1:$PORT
browser:
  proxy_addr: 127.0.0.1:$BPORT
mcp:
  transport:
    loopback_tcp:
      port: $MCP
      token: $TOKEN
scope:
  entries: ["127.0.0.1:$ECHO"]
poc:
  dir: $POC
  out_dir: $POC/out
EOF

say "building aitm + aitm-tui"
(cd "$ROOT" && cargo build -q -p aitm -p aitm-tui) || { echo "build failed"; exit 99; }
AITM="$ROOT/target/debug/aitm"
TUI="$ROOT/target/debug/aitm-tui"

tmux kill-session -t "$S" 2>/dev/null || true
case "$MODE" in
  embed)
    say "starting: aitm tui (embedded) in tmux $S"
    tmux new-session -d -s "$S" -x 200 -y 50 "RUST_LOG=info $AITM --config $WORK/aitm.yaml tui"
    ;;
  bus)
    say "starting: aitm server + aitm-tui over the bus"
    "$AITM" --config "$WORK/aitm.yaml" > "$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1.5
    tmux new-session -d -s "$S" -x 200 -y 50 "$TUI --bus 127.0.0.1:$MCP --token $TOKEN --poc-dir $POC"
    ;;
  *) echo "usage: $0 [embed|bus]"; exit 2 ;;
esac

PROXY="http://127.0.0.1:$PORT"
UP="http://127.0.0.1:$ECHO"

step "TUI is up and shows the listening address" \
  expect_pane 10 "aitmproxy" "127.0.0.1:$PORT"

curl -s -x "$PROXY" "$UP/first" -o "$WORK/first.json"
step "a real request through the proxy appears in the list with its status" \
  expect_pane 6 "/first" "200"

keys End; keys Enter
step "Enter opens the inspector with real F5 headers and body" \
  expect_pane 6 "Request" "Response" "user-agent" "\"method\": \"GET\""
keys Escape

keys i
step "i arms intercept (bar says so)" \
  expect_pane 4 "Intercept armed"

curl -s -x "$PROXY" -H "x-live: before" "$UP/paused" -o "$WORK/paused.json" &
CURL_PID=$!
step "the next request pauses in the bar" \
  expect_pane 8 "1 paused" "/paused"

keys End; keys Enter
step "review: the paused request's headers are on screen" \
  expect_pane 6 "x-live" "before"

keys e
step "e opens the raw editor on the paused request" \
  expect_pane 4 "editing"
# Line 0 is the request line; go down to the first header, to its end, open a
# new line and type a header the upstream will echo back.
keys Down; keys End; keys Enter
type_text "x-edited-by: tui-live-check"
step "the editor shows the typed header as an edit" \
  expect_pane 4 "x-edited-by: tui-live-check" "edits pending"

keys C-s
step "Ctrl-S applies the edit and resumes (toasts)" \
  expect_pane 8 "Resumed"
wait "$CURL_PID" 2>/dev/null || true
step "the client received a response carrying the edited header (upstream echo)" \
  grep -q '"x-edited-by": "tui-live-check"' "$WORK/paused.json"

keys Escape; keys End; keys Enter; keys Tab
step "the response body (F5) shows the edited header echoed by the upstream" \
  expect_pane 8 "x-edited-by"
keys Escape

keys P
step "P asks for the PoC name" \
  expect_pane 4 "poc name"
type_text "live-check"
keys Enter
step "then the parameter" \
  expect_pane 4 "param"
keys Enter
step "poc.build wrote a PoC" \
  expect_pane 8 "PoC written"
POC_FILE=$(ls "$POC"/*.y*ml 2>/dev/null | head -1)
step "the PoC file exists under poc.dir" \
  test -n "$POC_FILE"

keys ":"
type_text "poc run $POC_FILE $UP"
keys Enter
step "poc.run completes and reports a verdict" \
  expect_pane 15 "PoC"

keys F
step "F opens the findings panel with the run" \
  expect_pane 6 "Findings" "live-check"
keys Escape

keys i
step "i disarms intercept" \
  expect_pane 4 "Intercept disarmed"

keys ":"
type_text "config"
keys Enter
step ":config shows the redacted configuration (F7)" \
  expect_pane 6 "listen" "127.0.0.1:$PORT"
keys Escape

pane > "$WORK/final.txt"
say "done: $FAILS failed step(s); pane captures under $WORK"
exit "$FAILS"
