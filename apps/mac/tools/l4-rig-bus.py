#!/usr/bin/env python3
"""Operator bus reads for the macOS L4 live walk (tools/cua-l4-live.sh; spec
docs/superpowers/specs/2026-10-31-l4-parity-fixes-design.md §6, plan unit (d) task M9).

A second operator connection to the rig core, beside the app's own: it reads the core's audit
ring to count what the app put on the bus (AC25), crafts the sample packet the app's editor
starts from (AC27), and lists / removes L4 scope entries around the AC30 add. The core is the
real `aitm web` of the rig; nothing here is a fixture. Never prints a token.

usage: l4-rig-bus.py probe
       l4-rig-bus.py activity <since_ms> <client_label>   l4.* calls by that connection: "name count"
                                                         lines, a "total N" line and a "labels" line
       l4-rig-bus.py craft                                l4.craft with the parsed sample: "l4.craft length: N"
       l4-rig-bus.py scope-list                           "source id cidr ports interface direction capability" per entry
       l4-rig-bus.py scope-remove <id>
env:   L4_RIG   rig directory holding op.token (0600)      default /tmp/claude/l4d
       L4_BUS   the rig core's loopback bus host:port       default 127.0.0.1:31431
"""
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]  # tools → mac → apps → repo root
E2E = REPO / "tests" / "e2e"
if not (E2E / "aitm_e2e" / "bus.py").is_file():
    sys.exit(f"l4-rig-bus: no bus client at {E2E}/aitm_e2e/bus.py (is this script still under apps/mac/tools?)")
sys.path.insert(0, str(E2E))
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402

RIG = Path(os.environ.get("L4_RIG", "/tmp/claude/l4d"))
BUS = os.environ.get("L4_BUS", "127.0.0.1:31431")

# What PacketSpecDraft.sample parses to (Kit test testSampleSpecIsWhatTheCoreAccepts): integers,
# never floats, for the raw bytes — the core rejects a float byte list.
SAMPLE = {
    "layers": [
        {"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}},
        {"udp": {"src_port": 40000, "dst_port": 9}},
        {"raw": [104, 101, 108, 108, 111, 45, 108, 52]},
    ]
}


def operator_client() -> BusClient:
    """The operator connection; every failure is one stderr line, never a traceback or the token."""
    token_file = RIG / "op.token"
    try:
        token = token_file.read_text().strip()
    except OSError as e:
        sys.exit(f"l4-rig-bus: cannot read the operator token file {token_file}: {e.strerror}")
    host, _, port = BUS.rpartition(":")
    try:
        return BusClient(host or "127.0.0.1", int(port), token, client_name="l4-rig-bus").connect()
    except (OSError, ValueError, BusError, ToolError) as e:
        sys.exit(f"l4-rig-bus: cannot connect to the rig bus at {BUS} as the operator: {type(e).__name__}: {e}")


def l4_entries(client: BusClient, since_ms: int, label: str | None):
    act = client.call("agent.activity", {"since": since_ms})
    entries = act if isinstance(act, list) else act.get("entries", act)
    hits = []
    for e in entries:
        cmd = e.get("command") or e.get("tool") or ""
        if cmd.startswith("l4.") and (label is None or e.get("client_label") == label):
            hits.append(e)
    return entries, hits


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 0 if len(argv) >= 2 else 2
    cmd = argv[1]
    client = operator_client()
    try:
        if cmd == "probe":
            tools = client.tools()
            l4 = sorted(t["name"] for t in tools if t["name"].startswith("l4."))
            print("tools", len(tools), "l4", len(l4))
            add = next((t for t in tools if t["name"] == "l4.scope.add"), None)
            print("l4.scope.add confirmable:", add.get("confirmable") if add else "absent")
            get = next((t for t in tools if t["name"] == "l4.flow.get"), None)
            props = sorted(((get or {}).get("inputSchema") or {}).get("properties", {}).keys())
            print("l4.flow.get props:", props)
            print("capture.status:", json.dumps(client.call("l4.capture.status")))
            print("intercept.status:", json.dumps(client.call("l4.intercept.status")))
            print("scope.list:", json.dumps(client.call("l4.scope.list")))
            print("flow.list:", json.dumps(client.call("l4.flow.list")))
            entries, _ = l4_entries(client, int(time.time() * 1000) - 60_000, None)
            print("activity entries last 60s:", len(entries))
        elif cmd == "activity":
            if len(argv) != 4:
                sys.exit("usage: l4-rig-bus.py activity <since_ms> <client_label>")
            since, label = int(argv[2]), argv[3]
            entries, hits = l4_entries(client, since, label)
            for name, n in sorted(Counter(e.get("command") for e in hits).items()):
                print(name, n)
            print("total", len(hits))
            labels = Counter(e.get("client_label") for e in entries)
            print("labels", " ".join(f"{k}={v}" for k, v in sorted(labels.items(), key=lambda kv: str(kv[0]))))
        elif cmd == "craft":
            r = client.call("l4.craft", {"spec": SAMPLE})
            length = r.get("length") if isinstance(r, dict) else None
            print("l4.craft length:", length, "summary:", json.dumps(r.get("summary") if isinstance(r, dict) else r))
        elif cmd == "scope-list":
            for e in client.call("l4.scope.list"):
                print(e.get("source"), e.get("id"), e.get("cidr"), e.get("ports"), e.get("interface"),
                      e.get("direction"), e.get("capability"))
        elif cmd == "scope-remove":
            if len(argv) != 3:
                sys.exit("usage: l4-rig-bus.py scope-remove <id>")
            print(json.dumps(client.call("l4.scope.remove", {"id": argv[2]})))
        else:
            sys.exit(f"l4-rig-bus: unknown subcommand {cmd!r} (probe | activity | craft | scope-list | scope-remove)")
    except (ToolError, BusError, OSError) as e:
        print(f"l4-rig-bus: {cmd}: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
