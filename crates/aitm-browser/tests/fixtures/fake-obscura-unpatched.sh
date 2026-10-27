#!/bin/sh
# A stand-in for *upstream* obscura: its help lists no `--ca-cert`, so the
# probe must refuse it. Exits 0 like the real binary does on `--help`.
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
      --allow-private-network    Permit requests to loopback and private ranges
  -h, --help                     Print help
  -V, --version                  Print version
EOF
    exit 0
    ;;
  --version|-V)
    echo "obscura 0.2.5"
    exit 0
    ;;
  serve)
    sleep 30
    ;;
  *)
    echo "error: unrecognized subcommand '$1'" >&2
    exit 2
    ;;
esac
