#!/bin/zsh
# Snapshots of every page in light and dark, on the fixture session, with local state in /tmp.
# Usage: tools/snap.sh            all pages
#        APP_SNAPSHOT_PAGES=apps,settings tools/snap.sh
set -u
app=~/Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy
store=/tmp/Aitmproxy-test-state
shots=/tmp/Aitmproxy-shots
# A crashed run leaves saved window state, and the next launch would wait on a "reopen windows?" alert.
rm -rf ~/Library/Saved\ Application\ State/com.mrbrutti.aitmproxy.savedState
rm -rf $store $shots
mkdir -p $store
APP_STORE=$store APP_FIXTURES=1 APP_SNAPSHOT=$shots $app
