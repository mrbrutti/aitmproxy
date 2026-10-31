"""Target: the hermetic seeded-vuln origin (crates/aitm-testtarget / aitm-testtarget-serve).

`Target("vulnerable")` serves the planted vulns raw (reflected XSS at /search?q=,
/admin trusts X-Role, /redirect?next= open redirect, ...); `Target("patched")` serves
the fixed controls. Binds an ephemeral loopback port and prints `listening http://...`.
Discovery: AITM_TESTTARGET_BIN, else <repo>/target/debug/aitm-testtarget-serve.

Folded in from the surface sessions' lib/seeded.py so every surface shares one origin
wrapper (poc / scripting / scanner / proto cells). `TestTarget` is a compat alias.
"""

from __future__ import annotations

import os
import subprocess
import time

from . import repo_root


def testtarget_bin() -> str:
    return (os.environ.get("AITM_TESTTARGET_BIN")
            or os.path.join(repo_root(), "target", "debug", "aitm-testtarget-serve"))


class Target:
    def __init__(self, mode: str = "vulnerable", start_timeout: float = 15.0):
        bin_ = testtarget_bin()
        if not os.path.exists(bin_):
            raise FileNotFoundError(
                f"aitm-testtarget-serve not found at {bin_} "
                "(build it: cargo build -p aitm-testtarget, or set AITM_TESTTARGET_BIN)")
        self.mode = mode
        self.proc = subprocess.Popen(
            [bin_, "--mode", mode, "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.base_url: str | None = None
        deadline = time.time() + start_timeout
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

    @property
    def base(self) -> str:
        return self.base_url

    def host(self) -> str:
        return self.base_url.split("://", 1)[1]

    @property
    def authority(self) -> str:
        return self.host()

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


TestTarget = Target  # compat alias for the surface sessions' existing imports
