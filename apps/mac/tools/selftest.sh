#!/bin/zsh
# Runs the in-app self-test on the fixture session with local state in /tmp. Exit 0 when every check passed.
set -u
rm -rf ~/Library/Saved\ Application\ State/com.mrbrutti.aitmproxy.savedState
store=/tmp/Aitmproxy-self-state
rm -rf $store
mkdir -p $store
APP_STORE=$store ~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy --selftest
