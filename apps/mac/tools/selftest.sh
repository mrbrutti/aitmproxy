#!/bin/zsh
# Runs the in-app self-test on the fixture session with local state in /tmp. Exit 0 when every check passed.
# APP_BIN=/tmp/Aitmproxy-dev-<tag>.app/Contents/MacOS/Aitmproxy-<tag> runs a snap-dev bundle instead.
set -u
rm -rf ~/Library/Saved\ Application\ State/com.mrbrutti.aitmproxy.savedState
store=/tmp/Aitmproxy-self-state
rm -rf $store
mkdir -p $store
bin=${APP_BIN:-$HOME/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy}
[[ -x $bin ]] || { echo "no app binary at $bin (run ./build.sh --debug, or set APP_BIN)"; exit 1; }
APP_STORE=$store "$bin" --selftest
