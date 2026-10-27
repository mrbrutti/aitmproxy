#!/bin/sh
# A stand-in for the aitmproxy obscura fork that passes the probe but dies
# during startup (a bad flag, a port in use): `serve` writes to stderr and
# exits 7 without ever listening. `start` must report the status and the
# stderr tail at once, not wait out `start_timeout`.
case "$1" in
  --help|-h|help)
    cat <<'EOF'
Headless browser engine for agents

Usage: obscura [OPTIONS] <COMMAND>

Commands:
  serve   Start the CDP server
  render  Render a page once
  help    Print this message or the help of the given subcommand(s)

Options:
      --proxy <URL>              Route all traffic through this HTTP proxy
      --ca-cert <PATH>           Trust the certificate(s) in PATH as additional root CAs, added to the built-in roots. Repeatable. PEM bundle or DER.
      --allow-private-network    Permit requests to loopback and private ranges
  -h, --help                     Print help
  -V, --version                  Print version
EOF
    exit 0
    ;;
  --version|-V)
    echo "obscura 0.2.5-aitm.test"
    exit 0
    ;;
  serve)
    echo "boom" >&2
    exit 7
    ;;
  *)
    echo "error: unrecognized subcommand '$1'" >&2
    exit 2
    ;;
esac
