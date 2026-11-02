"""Boot and supervise a REAL `aitm` core for one scenario.

Two entry points:
  - Aitm.server(...)  -> bare `aitm` (proxy + loopback-TCP MCP bus), the agent entry point
  - Aitm.web(...)     -> `aitm web` (proxy + embedded web UI + /bus bridge)

Lifecycle is scoped to THIS process's own child PID: stop() signals only the
child it spawned (never a machine-wide pkill), so concurrent sessions are safe.
The core supervises obscura as its own child and reaps it on SIGINT, so stopping
the core cleans up the browser too — we never `pkill -f obscura`.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time

from . import free_port, repo_root
from .config import CoreConfig, write_config


def _aitm_bin() -> str:
    env = os.environ.get("AITM_BIN")
    if env:
        return env
    return os.path.join(repo_root(), "target", "debug", "aitm")


def _wait_port(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class Aitm:
    def __init__(self, cfg: CoreConfig, workdir: str, mode: str, web_port: int | None = None):
        self.cfg = cfg
        self.workdir = workdir
        self.mode = mode
        self.web_port = web_port
        self.proc: subprocess.Popen | None = None
        self.bus_addr: tuple[str, int] | None = None
        self._endpoint_file = os.path.join(workdir, "bus.addr")
        self._stderr_path = os.path.join(workdir, "aitm.stderr.log")
        self._stdout_path = os.path.join(workdir, "aitm.stdout.log")
        self._stderr_file = None
        self._stdout_file = None

    # ---- construction ----------------------------------------------------

    @classmethod
    def _prep(cls, cfg: CoreConfig) -> tuple[str, str]:
        workdir = tempfile.mkdtemp(prefix="aitm-e2e-")
        cfg.poc_dir = cfg.poc_dir or os.path.join(workdir, "poc")
        cfg.poc_out_dir = cfg.poc_out_dir or os.path.join(workdir, "poc-out")
        # Per-run CA dir isolates the MITM CA from the operator's real store.
        cfg.ca_dir = cfg.ca_dir or os.path.join(workdir, "ca")
        dirs = [cfg.poc_dir, cfg.poc_out_dir, cfg.ca_dir]
        if cfg.findings_dir:
            dirs.append(cfg.findings_dir)
        if cfg.rhai_scripts_dir:
            dirs.append(cfg.rhai_scripts_dir)
        for d in dirs:
            os.makedirs(d, exist_ok=True)
        cfg_path = write_config(os.path.join(workdir, "config.yaml"), cfg)
        return workdir, cfg_path

    @classmethod
    def server(cls, cfg: CoreConfig, start_timeout: float = 30.0,
               scripts: list[str] | None = None) -> "Aitm":
        """Bare `aitm`: proxy on cfg.proxy_port + loopback-TCP MCP bus (ephemeral,
        learned from --bus-endpoint-file). `scripts` passes `--script <path>` per
        entry (loaded in order, after any rhai.scripts_dir auto-load)."""
        bin_ = _aitm_bin()
        if not os.path.exists(bin_):
            raise FileNotFoundError(
                f"aitm binary not found at {bin_} (build it: cargo build -p aitm, "
                f"or set AITM_BIN)"
            )
        workdir, cfg_path = cls._prep(cfg)
        self = cls(cfg, workdir, mode="server")
        argv = [bin_, "--config", cfg_path, "--bus-endpoint-file", self._endpoint_file]
        for s in scripts or []:
            argv += ["--script", s]
        self._spawn(argv)
        if not self._wait_endpoint_file(start_timeout):
            self._die("the bus endpoint file was never written")
        if not _wait_port(cfg.proxy_port, start_timeout):
            self._die(f"the proxy never bound 127.0.0.1:{cfg.proxy_port}")
        return self

    @classmethod
    def web(cls, cfg: CoreConfig, start_timeout: float = 30.0,
            scripts: list[str] | None = None) -> "Aitm":
        """`aitm web`: proxy + embedded web UI + /bus bridge on a free web port.
        `scripts` passes `--script <path>` per entry (global flags, before `web`)."""
        bin_ = _aitm_bin()
        if not os.path.exists(bin_):
            raise FileNotFoundError(
                f"aitm binary not found at {bin_} (build it: cargo build -p aitm, "
                f"or set AITM_BIN)"
            )
        workdir, cfg_path = cls._prep(cfg)
        web_port = free_port()
        self = cls(cfg, workdir, mode="web", web_port=web_port)
        argv = [bin_, "--config", cfg_path]
        for s in scripts or []:
            argv += ["--script", s]
        argv += ["web", "--listen", f"127.0.0.1:{web_port}", "--token", cfg.agent_token, "--no-open"]
        self._spawn(argv)
        if not _wait_port(web_port, start_timeout):
            self._die(f"the web UI never bound 127.0.0.1:{web_port}")
        return self

    # ---- process plumbing ------------------------------------------------

    def _spawn(self, argv: list[str]) -> None:
        self._stderr_file = open(self._stderr_path, "wb")
        self._stdout_file = open(self._stdout_path, "wb")
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "info")
        # The core finds its bundled Rhai catalogue through `AITM_BUNDLED_SCRIPTS`,
        # a `share/aitm/scripts` beside the executable, or a dev-checkout fallback
        # relative to the executable. A binary built into /tmp (the private-target
        # pattern) has none of those, so every e2e core would silently run with NO
        # bundled scripts (umbrella amendment 60). Point it at the checkout unless
        # the caller set the variable (`AITM_NO_BUNDLED_SCRIPTS` still wins inside
        # the core: it is checked before the directory).
        env.setdefault("AITM_BUNDLED_SCRIPTS", os.path.join(repo_root(), "scripts", "bundled"))
        # Audit is on by default: this sends the default file into the workdir so a run never touches the operator's own (a path, not `off`, so the cells still exercise the real writer).
        env["AITM_AUDIT_LOG"] = os.environ.get("AITM_E2E_AUDIT_LOG") or os.path.join(self.workdir, "audit.jsonl")
        self.proc = subprocess.Popen(
            argv, stdout=self._stdout_file, stderr=self._stderr_file,
            stdin=subprocess.DEVNULL, env=env,
        )

    def _wait_endpoint_file(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                return False
            if os.path.exists(self._endpoint_file):
                try:
                    txt = open(self._endpoint_file, encoding="utf-8").read().strip()
                    host, port = txt.rsplit(":", 1)
                    self.bus_addr = (host, int(port))
                    return True
                except (OSError, ValueError):
                    pass
            time.sleep(0.1)
        return False

    def stderr_text(self) -> str:
        try:
            return open(self._stderr_path, encoding="utf-8", errors="replace").read()
        except OSError:
            return ""

    def stdout_text(self) -> str:
        try:
            return open(self._stdout_path, encoding="utf-8", errors="replace").read()
        except OSError:
            return ""

    def _die(self, why: str) -> None:
        err = self.stderr_text()
        self.stop()
        raise RuntimeError(f"aitm did not start: {why}\n--- aitm stderr ---\n{err}")

    def stop(self) -> None:
        """Signal only our own child; give it a moment to reap obscura, then kill."""
        p = self.proc
        if p and p.poll() is None:
            try:
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
            except ProcessLookupError:
                pass
        for fh in (self._stderr_file, self._stdout_file):
            if fh:
                try:
                    fh.close()
                except OSError:
                    pass
        # AITM_E2E_KEEP_WORKDIR=1 keeps the core's workdir (bus.addr, aitm.stderr.log,
        # aitm.stdout.log) after the run, for reading the core's own log on a rig
        # where a cell failed inside the engine (T5 live proof, 2026-11-02).
        if os.environ.get("AITM_E2E_KEEP_WORKDIR") == "1":
            print(f"  note: kept core workdir {self.workdir}", flush=True)
            return
        shutil.rmtree(self.workdir, ignore_errors=True)

    def __enter__(self) -> "Aitm":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def cli(core: "Aitm", *args: str, timeout: float = 90):
    """Run a one-shot `aitm --config <core's config> <args...>` — its own in-process
    core, nothing bound (so it can't see the running core's live flows; use it for
    ca export/status/dry-run, poc run, and other self-contained verbs). Returns
    (returncode, stdout, stderr). Folded in from the surface sessions' lib/seeded.py."""
    cfg = os.path.join(core.workdir, "config.yaml")
    p = subprocess.run(
        [_aitm_bin(), "--config", cfg, *args],
        capture_output=True, text=True, timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr
