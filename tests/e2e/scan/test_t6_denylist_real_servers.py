#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=redis
"""scan/t6_denylist_real_servers -- AC T6-3 (capstone tier): a RESP job against
a REAL `redis-server` and a memcached job against a REAL `memcached` send no
destructive command, complete bounded, and leave both servers running.

The denylist of parent D8.5 is on by construction and cannot be lifted by a
profile, a config key or a confirmation in v2: Redis `FLUSHALL / FLUSHDB /
SHUTDOWN / CONFIG / DEBUG / SAVE` and memcached `flush_all` are never
generated and never sent. This cell proves that against the real servers'
OWN counters, not against the scanner's account of itself:

  * `INFO commandstats` over a raw RESP socket lists one `cmdstat_<cmd>` line
    per command the server has actually executed since it started; none of the
    six denylisted names may appear;
  * memcached's `stats` lists `cmd_flush`, the count of `flush_all` commands
    it has served; it must still be `0`;
  * both server processes are alive when the jobs are done (nothing crashed
    them, nothing shut them down), and this cell kills only the PIDs it
    spawned itself -- never a `pkill`.

Each server is spawned on its own free loopback port (`--bind 127.0.0.1` /
`-l 127.0.0.1`, memcached with UDP off), with persistence disabled so the run
touches no file of the operator's.

Observer: `redis-server`'s and `memcached`'s own counters.

SKIPs 77 (never a FAIL), naming the missing thing:
  * `redis-server` or `memcached` is not on PATH (this is the capstone tier;
    AC T6-4 proves every grammar without them in `test_t6_grammars_live.py`);
  * the core does not advertise the `scan.*` verbs this cell calls;
  * `scan.checks` lists no check for the `l4_stream` lane.

Exit 0 pass / 1 fail / 77 skip. Never prints a token.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig, l4_inject_entry  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)

VERBS = ("scan.start", "scan.status", "scan.issues", "scan.checks")
# A bounded job that must be REFUSED or stay local; 300 s is generous.
JOB_TIMEOUT = 300.0
CASES = 200
# The RESP commands of parent D8.5 the lane may never generate, as redis
# spells them in `INFO commandstats` (`cmdstat_<lowercase name>:...`).
DENYLISTED_CMDSTATS = (
    "cmdstat_flushall",
    "cmdstat_flushdb",
    "cmdstat_config",
    "cmdstat_debug",
    "cmdstat_save",
    "cmdstat_shutdown",
)


class Server:
    """One real server process on a free loopback port, with its output in a
    temp file so a startup failure is reportable."""

    def __init__(self, name: str, argv_for_port, start_timeout: float = 15.0):
        self.name = name
        self.port = free_port()
        self.argv = argv_for_port(self.port)
        self._log = tempfile.NamedTemporaryFile(  # noqa: SIM115  (closed in stop())
            prefix=f"aitm-e2e-{name}-", suffix=".log", delete=False)
        self.proc = subprocess.Popen(
            self.argv, stdout=self._log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + start_timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"{name} exited with {self.proc.returncode} before binding "
                    f"127.0.0.1:{self.port}; output:\n{self.output()}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        self.stop()
        raise RuntimeError(f"{name} never bound 127.0.0.1:{self.port} within {start_timeout}s")

    def alive(self) -> bool:
        return self.proc.poll() is None

    def output(self) -> str:
        try:
            with open(self._log.name, encoding="utf-8", errors="replace") as fh:
                return fh.read()[-2000:]
        except OSError:
            return ""

    def stop(self) -> None:
        """Kill only this process (by its own PID), then drop its log file."""
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        try:
            self._log.close()
        except OSError:
            pass
        try:
            os.unlink(self._log.name)
        except OSError:
            pass


def ask(port: int, payload: bytes, terminator: bytes | None, timeout: float = 5.0) -> str:
    """Send `payload` on a fresh loopback TCP connection and read the reply until
    `terminator` is seen (or EOF when it is None). Text, errors replaced."""
    chunks: list[bytes] = []
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(payload)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                buf = s.recv(65536)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
            if terminator is not None and terminator in b"".join(chunks):
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def run_job(op: BusClient, port: int, grammar: str) -> dict:
    """One stream job against a real server on `port`, mutating `grammar`."""
    started = start_job(
        op, "operator",
        profile_name="l4-stream-safe",
        overrides={
            "target": {"l4": [{"ip": "127.0.0.1", "port": port, "proto": "tcp", "grammar": grammar}]},
            "l4": {"cases": CASES},
        },
        confirm=True,
    )
    job = started.get("job")
    check(isinstance(job, str) and job != "", f"scan.start returned a job id (got {job!r})")
    return wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)


def main() -> int:
    missing = [b for b in ("redis-server", "memcached") if shutil.which(b) is None]
    if missing:
        skip("capstone tier needs a real " + " and a real ".join(missing)
             + " on PATH (not found)")

    redis = memcached = core = op = None
    try:
        section("1. two real servers on free loopback ports, and an L4-inject core")
        redis = Server("redis", lambda p: [
            "redis-server", "--port", str(p), "--bind", "127.0.0.1",
            "--save", "", "--appendonly", "no"])
        memcached = Server("memcached", lambda p: [
            "memcached", "-p", str(p), "-l", "127.0.0.1", "-U", "0"])
        ok(f"redis-server on 127.0.0.1:{redis.port} (pid {redis.proc.pid}), "
           f"memcached on 127.0.0.1:{memcached.port} (pid {memcached.proc.pid})")

        cfg = CoreConfig(
            proxy_port=free_port(),
            l4_enabled=True,
            l4_scope_entries=[l4_inject_entry()],  # 127.0.0.1/32, ports 1-65535, inject
        )
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, *VERBS)
        require_lane(op, "l4_stream")
        ok("the core advertises the scan verbs and an l4_stream check")

        section("2. a RESP job against the real redis-server")
        status = run_job(op, redis.port, "resp")
        check(status.get("state") == "done",
              f"the RESP job finished `done` (got {status.get('state')!r}, "
              f"stopped_reason={status.get('stopped_reason')!r}, error={status.get('error')!r})")
        total = (status.get("issues") or {}).get("total")
        check(total == 0, f"the RESP job against a real redis filed no issues (got {total!r})")

        section("3. redis's own counters: no denylisted command was executed")
        info = ask(redis.port, b"INFO commandstats\r\nQUIT\r\n", None)
        check("cmdstat_" in info or "# Commandstats" in info,
              f"INFO commandstats answered with a commandstats section ({len(info)} bytes)")
        seen = sorted(line.split(":", 1)[0].strip()
                      for line in info.splitlines() if line.startswith("cmdstat_"))
        # `name not in seen` over an EMPTY `seen` would prove nothing: a RESP job of
        # 200 cases must have made redis execute at least one (benign) command.
        check(len(seen) >= 1,
              f"redis's own commandstats show the RESP job executed at least one command ({len(seen)} cmdstat row(s))")
        for name in DENYLISTED_CMDSTATS:
            check(name not in seen, f"redis never executed {name[len('cmdstat_'):].upper()}")
        ok(f"redis executed only: {seen}")

        section("4. a memcached job against the real memcached")
        m_status = run_job(op, memcached.port, "memcached")
        check(m_status.get("state") == "done",
              f"the memcached job finished `done` (got {m_status.get('state')!r}, "
              f"stopped_reason={m_status.get('stopped_reason')!r}, error={m_status.get('error')!r})")

        section("5. memcached's own counters: cmd_flush is still 0")
        stats = ask(memcached.port, b"stats\r\n", b"END\r\n")
        flush = [line for line in stats.splitlines() if line.startswith("STAT cmd_flush ")]
        check(len(flush) == 1, f"memcached `stats` reports one cmd_flush line (got {flush})")
        check(flush[0].strip() == "STAT cmd_flush 0",
              f"memcached served zero flush_all commands (got {flush[0].strip()!r})")

        section("6. both servers survived")
        check(redis.alive(), f"redis-server (pid {redis.proc.pid}) is still running")
        check(memcached.alive(), f"memcached (pid {memcached.proc.pid}) is still running")
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        for s in (redis, memcached):
            if s:
                s.stop()

    ok("T6-3: RESP and memcached jobs ran bounded against real servers, denylist never fired")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
