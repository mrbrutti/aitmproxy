#!/bin/zsh
# The live self-test: every FlowActions call over the real bus (SelfTest+Live.swift).
# Needs a running aitm whose config is at $AITM_CONFIG and an HTTP upstream to send to.
# The config's `mcp.policy` must be `all`: the app connects as an agent and flow.intercept is
# a sensitive command, refused under the default `auto` policy.
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
echo "LIVE self-test · app $bin · defaults suite ${APP_DEFAULTS_SUITE:-com.mrbrutti.aitmproxy.harness}"
APP_STORE=$store APP_LIVE=1 APP_LIVE_UPSTREAM=${1:-127.0.0.1:8099} "$bin" --selftest
