#!/bin/zsh
# The live self-test: every FlowActions call over the real bus (SelfTest+Live.swift).
# Needs a running aitm whose config is at $AITM_CONFIG and an HTTP upstream to send to.
# Usage: AITM_CONFIG=/path/config.yaml tools/selftest-live.sh [upstream host:port]
#   e.g. python3 -m http.server 8099 --bind 127.0.0.1   (the default upstream)
set -u
: ${AITM_CONFIG:?set AITM_CONFIG to the config.yaml of the running aitm}
rm -rf ~/Library/Saved\ Application\ State/com.mrbrutti.aitmproxy.savedState
store=/tmp/Aitmproxy-live-state
rm -rf $store
mkdir -p $store
APP_STORE=$store APP_LIVE=1 APP_LIVE_UPSTREAM=${1:-127.0.0.1:8099} \
  ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy --selftest
