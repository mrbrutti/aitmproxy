#!/bin/zsh
# Tear down everything start.sh launched.
echo "[kit] stopping sample site, aitmproxy, and any kit TUI…"
pkill -f 'http.server 19000' 2>/dev/null || true
pkill -f 'release/aitm --config .*kit-config.yaml' 2>/dev/null || true
pkill -f 'aitm-tui --bus 127.0.0.1:18090' 2>/dev/null || true
sleep 1
echo "[kit] done. Nothing of the kit should be running now."
