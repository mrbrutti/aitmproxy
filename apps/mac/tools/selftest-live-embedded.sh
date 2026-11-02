#!/bin/zsh
# The EMBEDDED-path live self-test (spec AC6/AC7, Task 9).
#
# tools/selftest-live.sh drives an EXTERNAL `aitm` the operator started; this one
# proves the app's OWN embedded core end to end: it bundles a core into the app,
# launches the app with NO external `aitm` and NO external config, lets the app
# spawn and supervise the child itself, pushes a real flow THROUGH the embedded
# proxy, then quits the app the normal way and checks nothing was orphaned.
#
# Why not reuse SelfTest+Live (runLive)? `--selftest` quits via `exit(code)` in
# applicationWillTerminate, which hard-exits and bypasses the embedded-core
# teardown. AC7 is about the NORMAL quit path (the willTerminate teardown that S1
# fixes), so we quit the app for real.
#
# Scope posture (embedded-core-scope, Task 12): the generated embedded config now
# emits `mcp.operator_token` alongside the agent token, and the app connects with
# the OPERATOR token, so it is classified `Frontend::Operator` — a present human.
# Startup scope stays deny-by-default/empty (no `scope:` block). A runtime
# `scope.add` over the operator connection (what the app's Scope panel does) now
# SUCCEEDS against the embedded core, while an agent-token connection is still
# refused (scope.allow_agent_widen OFF). Both are asserted below (step 7b). This
# needs the core half (operator-may-widen-scope) in the bundled `aitm`.
#
# What it exercises:
#   AC6  the app discovers the bundled core, spawns it, it publishes its bus
#        rendezvous, binds its proxy, and a real HTTP request routed THROUGH that
#        embedded proxy reaches the upstream and comes back 200.
#   AC14 a runtime scope.add over the OPERATOR connection succeeds against the
#        embedded core; the same call over the AGENT connection is still refused.
#   AC7  on a normal quit (osascript 'quit'), the willTerminate teardown reaps the
#        child: no bundled `aitm` survives and no per-launch workDir is left behind.
#
# What it does NOT exercise (documented, not faked):
#   - obscura spawn/teardown. `obscura` is a separate Chromium engine fetched at
#     packaging time (scripts/package.sh, via gh); it is not built from this repo.
#     A PLACEHOLDER obscura (a copy of `aitm`) is bundled only so build.sh's
#     inside-out signing runs its real path; no browser flow is driven, so it never
#     executes. The obscura side of AC7 (no orphaned browser) needs a full
#     scripts/package.sh core on a machine with `gh` access.
#
# Usage: tools/selftest-live-embedded.sh [upstream host:port]   (default 127.0.0.1:8099)
set -u
here=${0:A:h:h}                 # apps/mac
repo_root=${here:h:h}           # repo root
app="$HOME/Applications/Aitmproxy.app"
bundle_core="$app/Contents/Resources/core"
app_bin="$app/Contents/MacOS/Aitmproxy"
upstream=${1:-127.0.0.1:8099}
up_host=${upstream%%:*}; up_port=${upstream##*:}

note() { print -r -- "embedded-live: $*" }

upstream_pid=""; app_pid=""
cleanup() {
  [[ -n "$app_pid" ]] && kill "$app_pid" 2>/dev/null
  [[ -n "$upstream_pid" ]] && kill "$upstream_pid" 2>/dev/null
}
trap cleanup EXIT
fail() { print -r -- "EMBEDDED LIVE SELFTEST FAIL: $*"; exit 1 }

# 1. Build the real core (aitm). obscura is not in this repo; a placeholder stands
#    in so build.sh bundles+signs both via its normal AITM_CORE_DIR path.
note "building release aitm"
( cd "$repo_root" && cargo build --release -p aitm ) || fail "cargo build -p aitm failed"
real_aitm="$repo_root/target/release/aitm"
[[ -x "$real_aitm" ]] || fail "no built aitm at $real_aitm"

coredir=$(mktemp -d)
cp "$real_aitm" "$coredir/aitm"
cp "$real_aitm" "$coredir/obscura"          # placeholder, never executed (see header)
chmod 755 "$coredir/aitm" "$coredir/obscura"

# 2. Build + install the app WITH the core bundled in (real inside-out signing).
note "installing the app with the bundled core"
( cd "$here" && AITM_CORE_DIR="$coredir" ./build.sh ) || fail "build.sh failed"
[[ -x "$bundle_core/aitm" ]] || fail "core was not bundled at $bundle_core/aitm"

# 3. Pin the embedded choice (it is the default; a prior persisted 'external' must
#    not select an external core here).
defaults write com.mrbrutti.aitmproxy bus.activeKind embedded >/dev/null 2>&1 || true

# 4. Upstream the embedded proxy forwards to.
python3 -m http.server "$up_port" --bind "$up_host" >/dev/null 2>&1 &
upstream_pid=$!
sleep 0.5

# 5. Launch the app the NORMAL way (no --selftest, no APP_LIVE): APP_STORE keeps it
#    off the real database; the app runs its live embedded path (there is no fixture mode).
rm -rf ~/Library/Saved\ Application\ State/com.mrbrutti.aitmproxy.savedState
store=/tmp/Aitmproxy-live-embedded-state
rm -rf "$store"; mkdir -p "$store"
note "launching the app (embedded, no external core)"
AITM_AUDIT_LOG="${AITM_AUDIT_LOG:-off}" APP_STORE="$store" "$app_bin" &
app_pid=$!

# 6. Wait for the embedded core to come up: its process, its rendezvous file, and
#    the proxy port it bound (read from the per-launch config it was handed).
tmproot=$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null)
core_cfg=""; proxy=""
for i in {1..40}; do
  core_cfg=$(find "$tmproot" "$HOME/Library/Containers/com.mrbrutti.aitmproxy/Data/tmp" \
               -maxdepth 4 -path '*aitm-embedded-core*/config.yaml' 2>/dev/null | head -1)
  if [[ -n "$core_cfg" ]]; then
    proxy=$(sed -n 's/^listen: "\(.*\)"/\1/p' "$core_cfg" | head -1)
    [[ -n "$proxy" ]] && break
  fi
  sleep 0.5
done
[[ -n "$proxy" ]] || fail "AC6: the embedded core never wrote a per-launch config (core did not spawn)"
note "AC6: embedded core spawned; proxy bound at $proxy; config $core_cfg"

core_pids=$(pgrep -f "Aitmproxy.app/Contents/Resources/core/aitm" || true)
[[ -n "$core_pids" ]] || fail "AC6: no embedded aitm process found after launch"
# The rendezvous file the core publishes its bus address to (Task 3).
rendezvous=$(find "${core_cfg:h}" -name 'bus.endpoint' 2>/dev/null | head -1)
[[ -s "$rendezvous" ]] || note "AC6: (rendezvous file not found at ${core_cfg:h}/bus.endpoint — continuing on proxy check)"

# 7. AC6: a real HTTP request routed THROUGH the embedded proxy reaches the upstream.
#    (No agent scope widening needed — this is the proxy's forward path, not an
#    agent FlowActions call.) Retry briefly while the proxy finishes binding.
ok=""
for i in {1..20}; do
  if curl -sf -o /dev/null --max-time 5 -x "http://$proxy" "http://$upstream/"; then ok=1; break; fi
  sleep 0.5
done
[[ -n "$ok" ]] || fail "AC6: a request through the embedded proxy ($proxy -> $upstream) did not succeed"
note "AC6: a live HTTP flow went through the embedded proxy to the upstream (200)"

# 7b. AC14 (embedded-core-scope): a runtime scope.add over the OPERATOR connection
#     succeeds against the embedded core (what the app's Scope panel does), while
#     the same call over the AGENT connection is still refused. Reads both tokens
#     from this run's 0600 config and the bus address from the rendezvous file,
#     then drives the MCP loopback bus directly (newline-delimited JSON-RPC, token
#     line first — the same protocol the app and scripts/bus-agent-check.py use).
#     Needs the core half (operator-may-widen-scope) in the bundled aitm.
bus_addr=""
[[ -s "$rendezvous" ]] && bus_addr=$(head -1 "$rendezvous" | tr -d '[:space:]')
[[ -n "$bus_addr" ]] || fail "AC14: no bus rendezvous address at $rendezvous (cannot reach the embedded bus)"
agent_token=$(sed -n 's/^[[:space:]]*token: "\(.*\)"/\1/p' "$core_cfg" | head -1)
op_token=$(sed -n 's/^[[:space:]]*operator_token: "\(.*\)"/\1/p' "$core_cfg" | head -1)
[[ -n "$op_token" ]] || fail "AC14: the generated config carries no mcp.operator_token"
[[ -n "$agent_token" && "$agent_token" != "$op_token" ]] || fail "AC14: agent/operator tokens missing or identical (must be distinct)"

python3 - "$bus_addr" "$op_token" "$agent_token" <<'PY' || fail "AC14: operator scope.add did not succeed, or agent gating is broken, against the embedded core (is the core half present?)"
import json, socket, sys
bus, op_token, agent_token = sys.argv[1], sys.argv[2], sys.argv[3]
host, port = bus.rsplit(":", 1)
host = host.strip("[]")  # bracketed IPv6 literal, if the core ever prints one

def scope_add(token, entry):
    s = socket.create_connection((host, int(port)), timeout=10)
    f = s.makefile("rwb")
    f.write((json.dumps({"token": token}) + "\n").encode()); f.flush()
    n = [0]
    def rpc(method, params=None):
        n[0] += 1
        f.write((json.dumps({"jsonrpc": "2.0", "id": n[0], "method": method,
                             "params": params or {}}) + "\n").encode()); f.flush()
        while True:
            line = f.readline()
            if not line:
                raise SystemExit("bus closed before reply")
            r = json.loads(line)
            if r.get("id") == n[0]:
                if "error" in r:
                    raise SystemExit("rpc error: " + json.dumps(r["error"]))
                return r["result"]
    rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "embedded-scope-check", "version": "0"}})
    r = rpc("tools/call", {"name": "scope.add", "arguments": {"host": entry}})
    f.close(); s.close()
    text = (r.get("content") or [{}])[0].get("text", "")
    return (not r.get("isError")), text

ok_op, msg_op = scope_add(op_token, "operator-added.test")
print("embedded-live: AC14 operator scope.add ->", "OK" if ok_op else "REFUSED", "--", msg_op[:120])
ok_agent, msg_agent = scope_add(agent_token, "agent-added.test")
print("embedded-live: AC14 agent scope.add ->", "OK" if ok_agent else "REFUSED", "--", msg_agent[:120])

if not ok_op:
    print("FAIL: operator scope.add was refused — the embedded core does not accept operator widening (core half missing?)")
    sys.exit(1)
if ok_agent:
    print("FAIL: agent scope.add SUCCEEDED — agents must stay gated (scope.allow_agent_widen off)")
    sys.exit(1)
print("embedded-live: AC14 PASS: a present operator may widen embedded scope; an agent still cannot")
PY
note "AC14: operator scope.add succeeds against the embedded core; agent is still gated"

# 8. AC7: quit the app the normal way so the willTerminate teardown (S1) runs, then
#    assert no orphaned core and no leftover per-launch workDir.
note "quitting the app (normal terminate -> willTerminate teardown)"
osascript -e 'quit app "Aitmproxy"' >/dev/null 2>&1 || kill -TERM "$app_pid" 2>/dev/null
# Bounded wait: the teardown budget is stopGrace (5s) + margin; give it room.
for i in {1..20}; do
  kill -0 "$app_pid" 2>/dev/null || { app_pid=""; break; }
  sleep 0.5
done
sleep 1

# The exact core process this run spawned must be gone (be precise, so an
# unrelated stale instance elsewhere can't mask or fake this run's result).
for pid in ${=core_pids}; do
  kill -0 "$pid" 2>/dev/null && fail "AC7: the embedded core (pid $pid) survived the quit"
done
note "AC7: the embedded core this run spawned did not survive the quit"

# This run's per-launch workDir (config + rendezvous) must be gone — the teardown
# deletes it. Check THIS run's dir specifically, not a global scan.
workdir="${core_cfg:h}"
[[ ! -e "$workdir" ]] || fail "AC7: this run's per-launch workDir was left behind: $workdir"
note "AC7: this run's per-launch config/rendezvous workDir was removed"

cleanup
print -r -- "EMBEDDED LIVE SELFTEST PASS (AC6 embedded spawn+rendezvous+live proxy flow; AC14 operator may widen scope, agent gated; AC7 clean teardown, no orphan/leftover)"
exit 0
