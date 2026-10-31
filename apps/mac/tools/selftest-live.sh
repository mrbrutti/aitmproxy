#!/bin/zsh
# The live self-test: every FlowActions call over the real bus (SelfTest+Live.swift).
# Needs a running aitm whose config is at $AITM_CONFIG and an HTTP upstream to send to.
# The app connects as operator with the config's `mcp.operator_token` (read from the file, or
# given as APP_LIVE_OPERATOR_TOKEN): an agent connection is refused flow.intercept, a sensitive
# command, under the default `auto` policy, and the policy cannot be set from the CLI.
# Usage: AITM_CONFIG=/path/config.yaml tools/selftest-live.sh [upstream host:port]
#   e.g. python3 -m http.server 8099 --bind 127.0.0.1   (the default upstream)
#   APP_BIN=/tmp/Aitmproxy-dev-<tag>.app/Contents/MacOS/Aitmproxy-<tag>  runs a snap-dev bundle
#
# The app reads its connection settings from an isolated defaults suite in this mode
# (SettingsDomain: APP_LIVE=1 selects it and wipes it), so Settings > Bus residue in the
# real defaults (a pasted operator token, an embedded-core choice) never reaches the test
# and the test never writes there. Two live runs at once: give each its own
# APP_DEFAULTS_SUITE=<name>.
set -u
: ${AITM_CONFIG:?set AITM_CONFIG to the config.yaml of the running aitm}
rm -rf ~/Library/Saved\ Application\ State/com.mrbrutti.aitmproxy.savedState
store=/tmp/Aitmproxy-live-state
rm -rf $store
mkdir -p $store
bin=${APP_BIN:-$HOME/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy}
[[ -x $bin ]] || { echo "no app binary at $bin (run ./build.sh --debug, or set APP_BIN)"; exit 1; }
operator_token=${APP_LIVE_OPERATOR_TOKEN:-$(sed -n 's/^ *operator_token: *"\{0,1\}\([^"#]*\)"\{0,1\}.*/\1/p' "$AITM_CONFIG" | head -1)}
role=operator; [[ -n $operator_token ]] || role="agent (no mcp.operator_token in the config: flow.intercept will be refused)"
echo "LIVE self-test · app $bin · defaults suite ${APP_DEFAULTS_SUITE:-com.mrbrutti.aitmproxy.harness} · role $role"
APP_STORE=$store APP_LIVE=1 APP_LIVE_UPSTREAM=${1:-127.0.0.1:8099} APP_LIVE_OPERATOR_TOKEN=$operator_token "$bin" --selftest
