#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""The exact failure Matt hit: `aitm web` must start CLEANLY and be reachable.

Ground truth: a real `aitm web` process that binds its web port, serves /healthz
and the static UI over real HTTP, logs readiness, and (when obscura is expected)
has a discoverable obscura binary. No fixtures.
"""

import http.client
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, repo_root, section  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402


def http_get(port: int, path: str, timeout: float = 10.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def obscura_discoverable() -> str | None:
    env = os.environ.get("AITM_OBSCURA_BIN")
    if env and os.path.exists(env):
        return env
    beside = os.path.join(repo_root(), "target", "debug", "obscura")
    if os.path.exists(beside):
        return beside
    return shutil.which("obscura")


def main() -> int:
    cfg = CoreConfig(proxy_port=free_port())

    section("boot: aitm web starts cleanly and binds")
    core = Aitm.web(cfg)  # raises (with aitm stderr) if it does not bind in time
    try:
        ok(f"aitm web bound 127.0.0.1:{core.web_port} and stayed up")

        section("web UI is reachable over real HTTP")
        status, _ = http_get(core.web_port, "/healthz")
        check(status == 200, f"GET /healthz -> {status} (expected 200)")
        status, body = http_get(core.web_port, "/")
        check(status == 200, f"GET / -> {status} (expected 200, static UI served)")
        check(len(body) > 0, f"GET / returned a non-empty body ({len(body)} bytes)")

        section("startup printed the web UI address; the operator SECRET never leaks")
        logs = core.stdout_text() + core.stderr_text()
        check("web UI" in logs, "startup logged the web UI address (clean startup)")
        # aitm mints a fresh per-run operator BRIDGE token for the URL; the real
        # mcp.operator_token SECRET must never appear in any log.
        check(
            cfg.operator_token not in logs,
            "the operator-token SECRET never appears in the logs (hygiene)",
        )

        section("obscura discoverability")
        found = obscura_discoverable()
        if os.environ.get("AITM_OBSCURA") == "1":
            check(found is not None, f"obscura binary discoverable ({found})")
        elif found:
            ok(f"obscura binary present ({found}) [not required without AITM_OBSCURA=1]")
        else:
            ok("obscura not present (fine without AITM_OBSCURA=1; browser cells will SKIP)")
    finally:
        core.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — surface boot failures as a FAIL with context
        fail(f"{type(e).__name__}: {e}")
