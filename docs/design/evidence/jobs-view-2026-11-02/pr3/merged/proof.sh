#!/bin/zsh
# PR 3 live check (plan Task 3.0L, AC57 live half): real app + core from the kit3-bundle tree (kit tip + #310),
# aitm-testtarget-serve --latency-ms 400 on 8117 (standard), 100 on 8120 (light-http), dead 8121.
# Frames: running standard job's wells + lane now tag; dead-target row sub-line; finished light-http row + card issue words.
set -u
L=/tmp/claude/jobsux-live.sh
out=/tmp/claude/jobsux-proof
wt=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be
kit=$wt/.claude/worktrees/scan-jobs-view-kit
bt=/Users/matt/Security/aitmproxy/.claude/worktrees/scan-jobs-ux-9202be/.claude/worktrees/scan-jobs-view-kit
ev=$kit/docs/design/evidence/jobs-view-2026-11-02/pr3/merged
export MAC_DIR=$bt/apps/mac CORE_DIR=$bt/target/release
real="$HOME/Library/Application Support/aitmproxy"
mkdir -p $ev $out/pr3m
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $out/pr3m/proof.log }
snap() { for f in audit.jsonl audit.agent.jsonl ca-audit.jsonl; do [[ -e "$real/$f" ]] && echo "$f $(stat -f '%z %m' "$real/$f") $(shasum -a 256 "$real/$f" | cut -d' ' -f1)" || echo "$f absent"; done }
startjob() { TARGET_PORT=$2 $L start $1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("job") or d)' }
jfield() { $L status $1 | python3 -c "import json,sys; d=json.load(sys.stdin); print($2)" }
nosheet() { for i in {1..4}; do r=$($L press AXButton "Not Now" 2>&1); [[ "$r" == pressed* ]] || return 0; log "dismissed the setup sheet: $r"; sleep 0.8; done }
waitfor() { for i in {1..$3}; do [[ $(jfield $1 "$2") == $4 ]] && return 0; sleep 1; done; return 1 }
log "== PR 3 live check: bundle tree $(git -C $bt rev-parse --short HEAD) = kit $(git -C $kit rev-parse --short HEAD) code 6972acd4 + #310"
snap > $out/pr3m/real-before.txt
for p in 8120; do pkill -f "aitm-testtarget-serve --mode vulnerable --port $p" 2>/dev/null; nohup $CORE_DIR/aitm-testtarget-serve --mode vulnerable --port $p --latency-ms 100 > $out/target-$p.log 2>&1 & done
$L up 400 2>&1 | tail -4 | tee -a $out/pr3m/proof.log
sleep 3
corepid=$(awk '{print $3}' $out/core.txt); cfg=$(ps -o command= -p $corepid | sed -E 's/.*--config //'); audit=$(grep -E "audit_log:" "$cfg" | head -1 | sed -E 's/.*audit_log: "?([^"]+)"?.*/\1/')
grep -nE 'audit_log:' "$cfg" | sed -E 's/(token|secret)[^ ]*/<redacted>/g' > $out/pr3m/config-audit-lines.txt
case "$audit" in /tmp/Aitmproxy-dev-state-jobsux/*) log "#310 PASS: audit log under the isolated store ($audit)";; *) log "#310 FAIL ($audit) - ABORTING"; $L down; exit 3;; esac
for i in {1..20}; do r=$($L press AXButton "Not Now" 2>&1); [[ "$r" == pressed* ]] && { log "setup sheet dismissed: $r"; break; }; sleep 1; done
$L bus scope.add '{"host":"127.0.0.1:8120"}' > /dev/null; $L bus scope.add '{"host":"127.0.0.1:8121"}' > /dev/null
$L resize 1440 900 | tee -a $out/pr3m/proof.log; $L nav | tee -a $out/pr3m/proof.log; sleep 2
jd=$(startjob light-http 8121); log "dead-target job $jd (8121), alone (gap 40: a concurrent crawl collapses)"
waitfor $jd "d['state']" 90 done && log "dead job done: $(jfield $jd "d.get('stopped_reason')")" || log "dead job not done in 90 s"
nosheet; $L rowclick $jd | tee -a $out/pr3m/proof.log; sleep 1.5
nosheet; $L shot pr3-03-dead-subline > /dev/null; $L status $jd > $out/pr3m/03-status-dead.json; log "frame 03 dead-target row + card"
jl=$(startjob light-http 8120); log "light-http job $jl (8120, latency 100), alone"
js=""
waitfor $jl "d['state']" 420 done && log "light-http done: issues $(jfield $jl "d['issues']['by_severity']") checks $(jfield $jl "d['checks']['done']")" || log "light-http not done in 420 s"
nosheet; $L rowclick $jl | tee -a $out/pr3m/proof.log; sleep 1.5
nosheet; $L shot pr3-02-light-done-card > /dev/null; $L status $jl > $out/pr3m/02-status-light.json; log "frame 02 finished light-http row + card"
js=$(startjob standard 8117); log "standard job $js (8117)"
for i in {1..120}; do [[ $(jfield $js "d['phase']") == auditing && $(jfield $js "len(d.get('checks',{}).get('running',[]))") -gt 0 ]] && break; sleep 1; done
log "standard phase $(jfield $js "d['phase']") running $(jfield $js "d.get('checks',{}).get('running',[])")"
nosheet; $L rowclick $js | tee -a $out/pr3m/proof.log; sleep 1.5
nosheet; $L status $js > $out/pr3m/01-status-standard.json; $L shot pr3-01-wells-running > /dev/null; $L status $js > $out/pr3m/01b-status-standard-after.json; log "frame 01 standard running: wells + lane now tag"
swift $MAC_DIR/tools/axdump.swift $(cut -d' ' -f3 $out/app.pid) 2>/dev/null > $out/pr3m/ax-dump-final.tsv
[[ -n "$js" ]] && $L cancel $js > /dev/null; sleep 2
log "== quitting the bundle (quit-when-idle rule)"
$L down | tee -a $out/pr3m/proof.log
for p in 8120 8121; do pkill -f "aitm-testtarget-serve --mode vulnerable --port $p" 2>/dev/null; done
snap > $out/pr3m/real-after.txt
diff $out/pr3m/real-before.txt $out/pr3m/real-after.txt > $out/pr3m/real-audit-diff.txt && echo "REAL FILES UNCHANGED" >> $out/pr3m/real-audit-diff.txt || echo "REAL FILES CHANGED" >> $out/pr3m/real-audit-diff.txt
for f in pr3-01-wells-running pr3-02-light-done-card pr3-03-dead-subline; do sips -Z 1440 $out/$f.png --out $ev/$f.png > /dev/null 2>&1; done
cp $out/pr3m/*.json $out/pr3m/*.txt $out/pr3m/proof.log $ev/ 2>/dev/null
sed -i '' -E 's/"(token|operator_token|secret)": *"[^"]*"/"\1": "<redacted>"/g' $ev/*.json
log "== done; evidence $ev"
echo PR3-PROOF-DONE
