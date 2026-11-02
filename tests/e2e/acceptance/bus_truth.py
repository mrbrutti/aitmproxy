#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Read the six bus truths of a RUNNING core, read-only, token never printed.

Usage:
  bus_truth.py --embedded            # the installed app's embedded core (by its own cmdline)
  bus_truth.py --config <config.yaml>  # any core whose per-launch config holds operator_token
  bus_truth.py --bus host:port --token-file <file>

Prints: scope.list, proxy.status, capture.status, proxy.system.status, flow.table (count +
last 10 rows), ca.status (trust summary), agent.activity tail, and the durable audit tail.
Spec: docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md §D1.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e.bus import BusClient, ToolError  # noqa: E402

APP_CORE = "Aitmproxy.app/Contents/Resources/core/aitm"
DATA = os.path.expanduser("~/Library/Application Support/aitmproxy")


def embedded_config() -> str:
    out = subprocess.run(["pgrep", "-fl", APP_CORE], capture_output=True, text=True).stdout
    m = re.search(r"--config (\S+)", out)
    if not m:
        print("[SKIP] the installed app's embedded core is not running", flush=True)
        sys.exit(77)
    return m.group(1)


def read_config(path: str) -> tuple[str, str]:
    token = ""
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s.startswith("operator_token:"):
                token = s.split(":", 1)[1].strip().strip('"').strip("'")
    ep_file = os.path.join(os.path.dirname(path), "bus.endpoint")
    with open(ep_file, encoding="utf-8") as f:
        ep = f.read().strip()
    if not token:
        print("[SKIP] no operator_token in that config", flush=True)
        sys.exit(77)
    return ep, token


def redact(obj, token: str):
    s = json.dumps(obj, indent=1, sort_keys=True)
    if token:
        s = s.replace(token, "<redacted>")
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--embedded", action="store_true")
    ap.add_argument("--config")
    ap.add_argument("--bus")
    ap.add_argument("--token-file")
    a = ap.parse_args()
    if a.embedded:
        a.config = embedded_config()
        print(f"embedded core config: {a.config}")
    if a.config:
        ep, token = read_config(a.config)
    elif a.bus and a.token_file:
        ep = a.bus
        with open(a.token_file, encoding="utf-8") as f:
            token = f.read().strip()
    else:
        ap.error("--embedded, --config or --bus + --token-file")
    host, port = ep.rsplit(":", 1)
    print(f"bus: {ep}")
    bus = BusClient(host, int(port), token)
    bus.connect()
    print(f"role: {getattr(bus, 'role', '?')}")

    def show(name: str, args=None, trim=None):
        print(f"\n== {name}")
        try:
            r = bus.call(name, args or {})
        except ToolError as e:
            print(f"ERROR {e}")
            return None
        if trim:
            r = trim(r)
        print(redact(r, token))
        return r

    show("scope.list")
    show("proxy.status")
    show("capture.status")
    show("proxy.system.status")

    def trim_table(r):
        flows = r.get("flows", []) if isinstance(r, dict) else r
        return {"count": len(flows), "last": flows[-10:]}

    show("flow.table", trim=trim_table)

    def trim_ca(r):
        return {k: r.get(k) for k in ("exists", "fingerprint_sha1", "stores")} if isinstance(r, dict) else r

    show("ca.status", trim=trim_ca)
    show("agent.activity", {"limit": 10})

    print("\n== durable audit tail (control stream)")
    p = os.path.join(DATA, "audit.jsonl")
    if os.path.exists(p):
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f.readlines()[-8:]:
                print(line.rstrip()[:300].replace(token, "<redacted>"))
    else:
        print("(absent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
