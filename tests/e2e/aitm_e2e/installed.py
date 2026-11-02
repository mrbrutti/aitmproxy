"""aitm_e2e.installed — find the OPERATOR'S installed aitmproxy and read its bus truth.

Release acceptance (spec 2026-11-01-release-acceptance-operator-journeys §D1/§D9) attaches to
what Matt actually runs: the macOS app's embedded core, found by its OWN command line (never
"the newest config in the temp dir": sibling sessions' dev bundles spawn cores there too), and
the Homebrew `aitm`. Read-only; the operator token is returned to the caller and must never be
printed or logged (use `redact`).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass

from .bus import BusClient, ToolError

APP_BUNDLE = "/Applications/Aitmproxy.app"
APP_CORE_CMDLINE = "/Applications/Aitmproxy.app/Contents/Resources/core/aitm"
INSTALLED_CLI = "/opt/homebrew/bin/aitm"
DATA_DIR = os.path.expanduser("~/Library/Application Support/aitmproxy")

TRUTH_VERBS = ("scope.list", "proxy.status", "capture.status", "proxy.system.status", "flow.table", "ca.status")


@dataclass
class EmbeddedCore:
    pid: int
    config_path: str
    bus_addr: str
    operator_token: str

    @property
    def launch_dir(self) -> str:
        return os.path.dirname(self.config_path)


def find_embedded_core() -> EmbeddedCore | None:
    """The installed app's embedded core, or None when the app is not running."""
    out = subprocess.run(["pgrep", "-fl", APP_CORE_CMDLINE], capture_output=True, text=True).stdout
    # Anchored to the INSTALLED bundle: sibling sessions run dev bundles under /tmp with the same
    # relative layout. The config path is the last argument (per-launch dir under the user temp root).
    hits = [m for m in re.finditer(r"^(\d+) /Applications/Aitmproxy\.app/Contents/Resources/core/aitm --config (.+?)/config\.yaml\s*$", out, re.M)]
    if not hits:
        return None
    if len(hits) > 1:
        raise RuntimeError(f"{len(hits)} installed-bundle cores are running; refusing to pick one")
    m = hits[0]
    pid, cfg = int(m.group(1)), m.group(2) + "/config.yaml"
    token = ""
    with open(cfg, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s.startswith("operator_token:"):
                token = s.split(":", 1)[1].strip().strip('"').strip("'")
    ep_path = os.path.join(os.path.dirname(cfg), "bus.endpoint")
    with open(ep_path, encoding="utf-8") as f:
        addr = f.read().strip()
    return EmbeddedCore(pid=pid, config_path=cfg, bus_addr=addr, operator_token=token)


def connect(core: EmbeddedCore, client_name: str = "aitm-acceptance") -> BusClient:
    host, port = core.bus_addr.rsplit(":", 1)
    return BusClient(host, int(port), core.operator_token, client_name=client_name).connect()


def bus_truth(bus: BusClient) -> dict:
    """The six readings of §D1 (plus ca.status), as one dict; errors kept as strings."""
    out: dict = {}
    for verb in TRUTH_VERBS:
        try:
            out[verb] = bus.call(verb, {})
        except ToolError as e:
            out[verb] = {"error": str(e)}
    return out


def audit_tail(n: int = 20, stream: str = "audit.jsonl") -> list[dict]:
    """Last n lines of the durable audit. The file is SHARED by every core on the default data
    dir (sibling dev cores included): callers filter by pid/connection_id, never trust the tail."""
    p = os.path.join(DATA_DIR, stream)
    if not os.path.exists(p):
        return []
    rows = []
    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f.readlines()[-n:]:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line.rstrip()[:200]})
    return rows


def redact(text: str, *secrets: str) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "<redacted>")
    return text


def app_version() -> str | None:
    r = subprocess.run(
        ["defaults", "read", os.path.join(APP_BUNDLE, "Contents/Info.plist"), "CFBundleShortVersionString"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() or None


def port_holder(port: int) -> str | None:
    """`COMMAND pid` of the LISTEN holder of a loopback TCP port, or None."""
    r = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True)
    lines = r.stdout.splitlines()
    if len(lines) < 2:
        return None
    parts = lines[1].split()
    return f"{parts[0]} pid {parts[1]}"
