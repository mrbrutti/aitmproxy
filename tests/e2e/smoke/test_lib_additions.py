#!/usr/bin/env python3
# e2e: tier=T1 surface=smoke
"""Validate the lib additions that let surface sessions drop their own harnesses:
rhai_scripts_dir (+ Aitm scripts=), the per-run ca_dir, and aitm_e2e.tls.

Ground truth: a real .rhai dropped in rhai_scripts_dir is auto-loaded by a real
core (script.list shows it over the bus); aitm writes its MITM CA to the per-run
ca_dir (aitm_e2e.tls.ca_cert locates it); curl is wired for the TLS cells.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e import tls  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

TAGGER_RHAI = '''// e2e tagger — registers a liveness command + a request hook.
const NAME = "tagger";
const API  = "1";

fn load(reg) {
    reg.add_option("tag", "seen-by-aitm", "value for the X-Aitm header");
    reg.add_command("tagger.ping", "liveness check", |args| "pong");
}

fn on_request(flow) {
    flow.request.headers.set("X-Aitm", option("tag"));
}
'''


def main() -> int:
    scripts_dir = tempfile.mkdtemp(prefix="aitm-e2e-scripts-")
    with open(os.path.join(scripts_dir, "tagger.rhai"), "w", encoding="utf-8") as f:
        f.write(TAGGER_RHAI)

    cfg = CoreConfig(proxy_port=free_port(), rhai_scripts_dir=scripts_dir)
    core = None
    bus = None
    try:
        section("boot a real core with rhai_scripts_dir auto-load (core-features' unblock)")
        core = Aitm.server(cfg)
        bus = BusClient.agent(core)
        scripts = bus.call("script.list")
        dump = json.dumps(scripts)
        check("tagger" in dump, f"script.list shows the auto-loaded tagger script ({dump[:160]})")

        section("per-run ca_dir: aitm wrote its MITM CA where tls.ca_cert expects it")
        cert = tls.ca_cert(core)
        check(os.path.exists(cert), f"CA cert present at {cert}")
        check(bool(cfg.ca_dir) and cfg.ca_dir not in ("", None),
              f"ca_dir is a per-run isolated dir ({cfg.ca_dir})")

        section("tls helper is wired for the TLS-MITM cells")
        check(tls.have("curl"), "curl is available for the TLS/ALPN cells")
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
