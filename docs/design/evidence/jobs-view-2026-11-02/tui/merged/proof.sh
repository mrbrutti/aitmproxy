#!/bin/bash
# Live proof, Jobs view Part 4 (plan Task 4.6, AC43): the real `aitm` server + `aitm-tui --bus` in tmux,
# a real `standard` job against aitm-testtarget-serve --latency-ms 400, driven by keystrokes.
# Audit-log rule: the server's config carries mcp.audit_log and ca.audit_log under the run dir; abort otherwise.
set -u
TWT=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/scan-jobs-view-kit
HWT=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/scan-jobs-view-kit
AITM=$TWT/target/release/aitm
TUI=$TWT/target/release/aitm-tui
TT=$HWT/target/release/aitm-testtarget-serve
BUSPY=/tmp/claude/busfull.py
EV=$TWT/docs/design/evidence/jobs-view-2026-11-02/tui/merged
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tui-proof-XXXXXX")
PORT=18180; BPORT=18181; MCP=19190; TPORT=8117
S=tuiproof
REAL="$HOME/Library/Application Support/aitmproxy"
FAILS=0; STEP=0
say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
pane() { tmux capture-pane -p -t "$S" 2>/dev/null; }
snap_real() { for f in audit.jsonl audit.agent.jsonl ca-audit.jsonl; do if [ -e "$REAL/$f" ]; then echo "$f $(stat -f '%z %m' "$REAL/$f") $(shasum -a 256 "$REAL/$f" | cut -d' ' -f1)"; else echo "$f absent"; fi; done; }
expect_pane() { local secs=$1; shift; local deadline=$((SECONDS + secs)); while :; do local text; text=$(pane); local ok=1; for n in "$@"; do grep -qF -- "$n" <<<"$text" || ok=0; done; [ "$ok" = 1 ] && return 0; [ "$SECONDS" -ge "$deadline" ] && { printf '%s\n' "$text" > "$WORK/fail-$STEP.txt"; return 1; }; sleep 0.4; done; }
step() { STEP=$((STEP + 1)); local name=$1; shift; if "$@"; then say "ok   $STEP  $name"; pane > "$WORK/pane-$STEP.txt"; else say "FAIL $STEP  $name"; FAILS=$((FAILS + 1)); fi; }
keys() { tmux send-keys -t "$S" "$@"; sleep 0.5; }
type_text() { tmux send-keys -t "$S" -l -- "$1"; sleep 0.3; }
bus() { python3 -I "$BUSPY" "127.0.0.1:$MCP" "$WORK/op.token" "$@"; }
cleanup() { tmux send-keys -t "$S" q 2>/dev/null; sleep 0.5; tmux kill-session -t "$S" 2>/dev/null; [ -n "${SERVER_PID:-}" ] && kill -CONT "$SERVER_PID" 2>/dev/null; [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null; [ -n "${TT_PID:-}" ] && kill "$TT_PID" 2>/dev/null; }
trap cleanup EXIT

for b in "$AITM" "$TUI" "$TT"; do [ -x "$b" ] || { echo "missing $b"; exit 90; }; done
[ -z "${AITM_AUDIT_LOG+x}" ] || { echo "AITM_AUDIT_LOG is set in this shell; unset it"; exit 91; }
mkdir -p "$EV" "$WORK/poc/out"
snap_real > "$WORK/real-before.txt"
OPTOK="op-$(openssl rand -hex 16)"; printf '%s\n' "$OPTOK" > "$WORK/op.token"; chmod 600 "$WORK/op.token"
AGTOK="ag-$(openssl rand -hex 16)"
cat > "$WORK/aitm.yaml" <<YAML
listen: 127.0.0.1:$PORT
browser:
  proxy_addr: 127.0.0.1:$BPORT
scope:
  entries: ["127.0.0.1:$TPORT", "127.0.0.1:8121"]
poc:
  dir: $WORK/poc
  out_dir: $WORK/poc/out
ca:
  audit_log: "$WORK/ca-audit.jsonl"
mcp:
  operator_token: $OPTOK
  audit_log: "$WORK/audit.jsonl"
  transport:
    loopback_tcp:
      port: $MCP
      token: $AGTOK
YAML
grep -q "^  audit_log: \"$WORK/audit.jsonl\"" "$WORK/aitm.yaml" && grep -q "^  audit_log: \"$WORK/ca-audit.jsonl\"" "$WORK/aitm.yaml" || { echo "config lacks the audit_log lines under $WORK"; exit 92; }
grep -n 'audit_log' "$WORK/aitm.yaml" > "$WORK/config-audit-lines.txt"

say "== target on $TPORT (latency 400 ms)"
nohup "$TT" --mode vulnerable --port $TPORT --latency-ms 400 > "$WORK/target.log" 2>&1 &
TT_PID=$!
say "== server"
RUST_LOG=info nohup "$AITM" --config "$WORK/aitm.yaml" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 40); do nc -z 127.0.0.1 $MCP 2>/dev/null && break; sleep 0.25; done
nc -z 127.0.0.1 $MCP || { echo "bus never came up"; tail -5 "$WORK/server.log"; exit 93; }
echo "server pid $SERVER_PID" > "$WORK/server.txt"
lsof -p "$SERVER_PID" 2>/dev/null | grep -i 'audit' | awk '{print $NF}' > "$WORK/server-open-audit-files.txt"

say "== TUI in tmux"
tmux kill-session -t "$S" 2>/dev/null
tmux new-session -d -s "$S" -x 200 -y 50 "$TUI --bus 127.0.0.1:$MCP --token-file $WORK/op.token --expect-role operator --poc-dir $WORK/poc"
step "TUI is up" expect_pane 15 "aitmproxy"
keys ":"; type_text "scan"; keys Enter
step "the Scan view opens" expect_pane 8 "Profiles" "Jobs"
keys 2
step "the Jobs tab opens (empty until a job exists)" expect_pane 8 "2 Jobs"

say "== start a standard job over the bus (operator)"
START=$(bus scan.start '{"profile_name":"standard","overrides":{"target":{"origins":["http://127.0.0.1:'$TPORT'"]}}}')
printf '%s\n' "$START" > "$WORK/start.json"
JOB=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("job") or d.get("result",{}).get("job",""))' "$WORK/start.json")
echo "job $JOB" > "$WORK/job.txt"
[ -n "$JOB" ] || { echo "no job id"; cat "$WORK/start.json"; exit 94; }
step "the row appears with a running phase word" expect_pane 25 "$JOB"
step "the Jobs header shows the progress and budget columns" expect_pane 5 "progress" "budget" "points" "issues"
sleep 1
pane > "$EV/01-jobs-running.txt"; bus scan.status "{\"job\":\"$JOB\"}" > "$EV/01-status.json"
sleep 12
pane > "$EV/02-jobs-running-12s.txt"; bus scan.status "{\"job\":\"$JOB\"}" > "$EV/02-status.json"
row1=$(grep -F "$JOB" "$EV/01-jobs-running.txt" | head -1); row2=$(grep -F "$JOB" "$EV/02-jobs-running-12s.txt" | head -1)
step "the progress column moved between the two captures" test "$row1" != "$row2"
step "the detail carries the now line while auditing" expect_pane 90 "now"
pane > "$EV/03-detail-now.txt"; bus scan.status "{\"job\":\"$JOB\"}" > "$EV/03-status.json"
for i in $(seq 1 60); do ph=$(bus scan.status "{\"job\":\"$JOB\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("phase",""))'); [ "$ph" = auditing ] && break; sleep 1; done
rowcell() { pane | grep -F "$JOB" | head -1 | sed -E 's/ +/ /g' | awk '{print $5}'; }
cellA=$(rowcell); pane > "$EV/03b-auditing-row-a.txt"; sleep 6; cellB=$(rowcell); pane > "$EV/03c-auditing-row-b.txt"
echo "progress cell $cellA -> $cellB over 6 s while auditing" > "$EV/03-progress-rise.txt"
step "the progress cell rises while auditing (n/m to a larger n/m)" bash -c '[[ "'"$cellA"'" =~ ^[0-9]+/[0-9]+$ && "'"$cellB"'" =~ ^[0-9]+/[0-9]+$ && "'"$cellA"'" != "'"$cellB"'" ]]'

say "== cancel with x"
tmux send-keys -t "$S" x
got=1; for i in $(seq 1 80); do pane > "$WORK/cancelling-probe.txt"; if grep -q "cancelling" "$WORK/cancelling-probe.txt"; then got=0; cp "$WORK/cancelling-probe.txt" "$EV/04-cancelling.txt"; break; fi; sleep 0.05; done
step "x shows cancelling at once (sampled every 50 ms)" test "$got" = 0
step "then cancelled" expect_pane 20 "cancelled"
step "the detail opens with the Cancelled sentence" expect_pane 10 "Cancelled after" "had run. What it found stays."
pane > "$EV/05-cancelled-sentence.txt"; bus scan.status "{\"job\":\"$JOB\"}" > "$EV/05-status.json"

say "== freeze the core for the banner age clause"
kill -STOP "$SERVER_PID"; t_stop=$SECONDS
step "the Jobs banner names the hung core within 31 s (Task 4.5a: an overdue scan.list)" expect_pane 31 "scan.list: the bus did not reply in time" "showing values from"
pane > "$EV/06-banner-age.txt"; echo "banner first seen $((SECONDS - t_stop)) s after SIGSTOP" > "$EV/06-banner-timing.txt"
sleep 5; pane > "$EV/06b-banner-age-plus5.txt"
tmux send-keys -t "$S" x; sleep 0.6; pane > "$EV/06c-x-refused.txt"
step "x while unanswered is refused with the toast" grep -q "scan.cancel not sent: the bus did not reply in time" "$EV/06c-x-refused.txt"
kill -CONT "$SERVER_PID"
step "the clause clears once the core answers again" bash -c 'for i in $(seq 1 40); do tmux capture-pane -p -t '"$S"' | grep -q "showing values from" || exit 0; sleep 0.5; done; exit 1'
pane > "$EV/07-recovered.txt"

say "== shutdown"
keys q; sleep 0.5; tmux kill-session -t "$S" 2>/dev/null
kill "$SERVER_PID" 2>/dev/null; sleep 1
kill "$TT_PID" 2>/dev/null
snap_real > "$WORK/real-after.txt"
diff "$WORK/real-before.txt" "$WORK/real-after.txt" > "$EV/real-audit-diff.txt" && echo "REAL FILES UNCHANGED" >> "$EV/real-audit-diff.txt" || echo "REAL FILES CHANGED" >> "$EV/real-audit-diff.txt"
cp "$WORK/config-audit-lines.txt" "$WORK/server-open-audit-files.txt" "$WORK/job.txt" "$EV/"
{ echo "run dir audit.jsonl bytes: $(stat -f '%z' "$WORK/audit.jsonl" 2>/dev/null || echo absent)"; echo "scan.cancel lines: $(grep -c 'scan.cancel' "$WORK/audit.jsonl" 2>/dev/null || echo 0)"; echo "ca-audit.jsonl: $(stat -f '%z' "$WORK/ca-audit.jsonl" 2>/dev/null || echo absent)"; } > "$EV/run-dir-audit.txt"
cp "$0" "$EV/proof.sh"
for f in "$WORK"/pane-*.txt "$WORK"/fail-*.txt; do [ -e "$f" ] && cp "$f" "$EV/"; done
sed -i '' -E "s#$WORK#<run dir>#g" "$EV"/*.txt 2>/dev/null
say "== done: $FAILS failed step(s); work $WORK; evidence $EV"
echo "TUI-PROOF-DONE fails=$FAILS"
exit $FAILS
