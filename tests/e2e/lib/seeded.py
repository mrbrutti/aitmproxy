"""Local helpers for the two things aitm_e2e does not wrap yet: the seeded
vulnerable testtarget (`aitm-testtarget-serve`) and the one-shot `aitm <cmd>` CLI.

Both are candidates to fold into aitm_e2e (a `Target` module + a `cli()` helper);
until then these keep the surface tests on the shared `aitm_e2e` core/bus/config/tls
rather than a second harness. Binary discovery matches aitm_e2e (AITM_* env, else
target/{debug}).
"""
from __future__ import annotations

import os
import subprocess
import time

from aitm_e2e import repo_root
from aitm_e2e import tls
from aitm_e2e.core import _aitm_bin


def _testtarget_bin() -> str:
    env = os.environ.get("AITM_TESTTARGET_BIN")
    if env:
        return env
    return os.path.join(repo_root(), "target", "debug", "aitm-testtarget-serve")


class TestTarget:
    """The hermetic seeded origin (crates/aitm-testtarget). `vulnerable` serves the
    planted vulns raw (reflected XSS at /search?q=, /admin trusts X-Role, ...);
    `patched` serves them fixed. Binds an ephemeral loopback port."""

    def __init__(self, mode: str = "vulnerable"):
        self.proc = subprocess.Popen(
            [_testtarget_bin(), "--mode", mode, "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.base_url = None
        deadline = time.time() + 15
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                if self.proc.poll() is not None:
                    break
                continue
            if "listening " in line:
                self.base_url = line.split("listening ", 1)[1].strip()
                break
        if not self.base_url:
            self.stop()
            raise RuntimeError("aitm-testtarget-serve did not report a listen URL")

    def host(self) -> str:
        return self.base_url.split("://", 1)[1]

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()


def aitm_cli(core, *args, timeout: float = 90):
    """Run a one-shot `aitm --config <core's config> <args...>` (its own in-process
    core, nothing bound). Returns (rc, stdout, stderr)."""
    cfg = os.path.join(core.workdir, "config.yaml")
    p = subprocess.run(
        [_aitm_bin(), "--config", cfg, *args],
        capture_output=True, text=True, timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def curl_code(args, timeout: float = 20):
    """tls.curl plus the HTTP status: returns (rc, http_code:int, body:str)."""
    rc, out, _ = tls.curl([*args, "-o", "-", "-w", "\n__CODE__%{http_code}"], timeout=timeout)
    body = out.decode("utf-8", "replace")
    code = 0
    if "__CODE__" in body:
        body, _, c = body.rpartition("__CODE__")
        try:
            code = int(c.strip())
        except ValueError:
            code = 0
    return rc, code, body
