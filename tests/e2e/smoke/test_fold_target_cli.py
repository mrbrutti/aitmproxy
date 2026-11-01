#!/usr/bin/env python3
# e2e: tier=T1 surface=smoke
"""Validate the folded helpers so the surface sessions can drop lib/seeded.py:
aitm_e2e.target.Target (seeded vuln origin, vulnerable vs patched), aitm_e2e.core.cli
(one-shot `aitm <cmd>`), and aitm_e2e.tls.curl_code (curl + HTTP status).

Ground truth: the real seeded target reflects a marker RAW when vulnerable and
ESCAPED when patched; a real curl through the real proxy returns the real status +
body; the one-shot CLI answers ca.status.
"""

import http.client
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e import tls  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm, cli  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402

MARK = "<e2e-fold-xss>"


def direct_search(authority: str) -> str:
    conn = http.client.HTTPConnection(authority, timeout=10)
    try:
        conn.request("GET", "/search?q=" + MARK.replace("<", "%3C").replace(">", "%3E"))
        return conn.getresponse().read().decode("utf-8", "replace")
    finally:
        conn.close()


def main() -> int:
    if not tls.have("curl"):
        from aitm_e2e import skip
        skip("curl not available")

    section("aitm_e2e.target.Target: vulnerable reflects raw, patched escapes (seeded origin)")
    with Target("vulnerable") as vuln:
        vbody = direct_search(vuln.authority)
        check(MARK in vbody, f"vulnerable /search reflects the marker RAW ({MARK!r} present)")
    with Target("patched") as patched:
        pbody = direct_search(patched.authority)
        check(MARK not in pbody, "patched /search does NOT reflect the marker raw (escaped)")

    section("boot a core + seeded target; curl_code through the proxy; one-shot cli")
    up = Target("vulnerable")
    core = None
    try:
        cfg = CoreConfig(proxy_port=free_port(), scope_entries=[up.authority, "127.0.0.1"])
        core = Aitm.server(cfg)

        section("aitm_e2e.tls.curl_code: real status through the real proxy")
        rc, code, body = tls.curl_code(
            ["-x", f"http://127.0.0.1:{cfg.proxy_port}", f"{up.base}/search?q=ok"])
        check(rc == 0 and code == 200, f"curl_code through the proxy -> rc {rc}, status {code}")

        section("aitm_e2e.core.cli: one-shot `aitm ca status` answers")
        crc, cout, cerr = cli(core, "ca", "status")
        check(crc == 0, f"cli(core, 'ca', 'status') exit 0 (rc {crc}; stderr {cerr[:120]!r})")
        check("ca" in (cout + cerr).lower() or cout.strip() != "",
              "cli ca status produced output")
    finally:
        if core:
            core.stop()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
