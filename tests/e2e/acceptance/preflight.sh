#!/usr/bin/env bash
# e2e: tier=manual surface=acceptance
# Release acceptance, step D2: read the operator's REAL starting state, read-only.
#
# Writes every reading to $1 (default /tmp/claude/acceptance/state-<timestamp>.txt) and
# prints it. Runs from a real shell (the Terminal panel): the sandbox sees an empty
# `scutil --proxy` dictionary and cannot `pgrep`. Changes nothing. Never prints a token.
#
# Spec: docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md §D2
set -uo pipefail
out="${1:-/tmp/claude/acceptance/state-$(date +%Y%m%d-%H%M%S).txt}"
mkdir -p "$(dirname "$out")"
exec > >(tee "$out") 2>&1

section() { printf '\n== %s\n' "$1"; }
app=/Applications/Aitmproxy.app
data="$HOME/Library/Application Support/aitmproxy"

section "when / host"
date -u +%Y-%m-%dT%H:%M:%SZ; sw_vers 2>/dev/null | tr '\n' ' '; echo

section "installed versions"
printf 'app  CFBundleShortVersionString: '; defaults read "$app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "(no app bundle)"
printf 'app  bundled core: '; ls -la "$app/Contents/Resources/core/aitm" 2>/dev/null | awk '{print $5, $6, $7, $8}' || echo "(none)"
printf 'cli  which aitm: '; command -v aitm || echo "(none)"
brew list --versions aitm aitmproxy 2>/dev/null || echo "(brew list failed)"

section "processes (app, embedded core, terminal cores, obscura, extension)"
pgrep -fl 'Aitmproxy.app/Contents/MacOS' || echo "app: not running"
pgrep -fl 'Aitmproxy.app/Contents/Resources/core/aitm' || echo "embedded core: not running"
pgrep -fl '/opt/homebrew/(bin|Cellar)/aitm' || echo "terminal aitm: none"
pgrep -fl 'obscura' | grep -v pgrep || echo "obscura: none"
pgrep -fl 'AitmproxyNE' || echo "extension process: none"

section "listeners on the default ports"
lsof -nP -iTCP:8080 -iTCP:8081 -iTCP:8082 -iTCP:9090 -sTCP:LISTEN 2>/dev/null || echo "(none)"

section "system proxy: scutil --proxy (effective)"
scutil --proxy
section "system proxy: per service"
for svc in "Wi-Fi" "Display Ethernet"; do
  echo "-- $svc"
  networksetup -getwebproxy "$svc" 2>&1 | sed 's/^/   http  /'
  networksetup -getsecurewebproxy "$svc" 2>&1 | sed 's/^/   https /'
done

section "CA trust (login + System keychains)"
for kc in "$HOME/Library/Keychains/login.keychain-db" "/Library/Keychains/System.keychain"; do
  echo "-- $kc"
  security find-certificate -a -c aitmproxy -Z "$kc" 2>/dev/null | grep -E 'SHA-1|"labl"' || echo "   (no aitmproxy certificate)"
done

section "network extension"
systemextensionsctl list 2>/dev/null | grep -E 'aitmproxy|enabled|---' || echo "(systemextensionsctl gave nothing)"

section "data dir: $data"
ls -la "$data" 2>/dev/null || echo "(absent)"
echo "-- config.yaml: listen / scope / mcp keys (values of tokens are NOT shown)"
if [ -f "$data/config.yaml" ]; then
  grep -nE '^(listen|scope|mcp|system_proxy|macos_capture|ca):' "$data/config.yaml"
  awk '/^scope:/{f=1;next} /^[^ ]/{f=0} f' "$data/config.yaml" | head -20
  grep -nE 'operator_token|token:' "$data/config.yaml" | sed -E 's/(token:?\s*).*/\1<redacted, present>/'
else
  echo "(no config.yaml)"
fi
echo "-- system-proxy-state.json"
[ -f "$data/system-proxy-state.json" ] && sed -E 's/"[a-f0-9]{32,}"/"<redacted>"/g' "$data/system-proxy-state.json" || echo "(absent)"
echo "-- audit.jsonl tail (last 5 control entries)"
[ -f "$data/audit.jsonl" ] && tail -n 5 "$data/audit.jsonl" | cut -c1-300 || echo "(absent)"

section "app defaults (com.mrbrutti.aitmproxy) - connection and capture keys, tokens redacted"
defaults read com.mrbrutti.aitmproxy 2>/dev/null | grep -viE 'token' | grep -iE 'capture|proxy|firstRun|setup|core|bus' || echo "(no relevant keys)"

section "embedded core per-launch dirs (aitm-embedded-core)"
tmp="$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null)"
ls -la "$tmp/aitm-embedded-core" 2>/dev/null || echo "(none)"
for d in "$tmp"/aitm-embedded-core/*/; do
  [ -d "$d" ] || continue
  printf '%s  bus.endpoint=%s  listen=%s\n' "$d" "$(cat "$d/bus.endpoint" 2>/dev/null || echo none)" "$(grep -E '^listen:' "$d/config.yaml" 2>/dev/null | awk '{print $2}')"
done

section "done"
echo "written to $out"
