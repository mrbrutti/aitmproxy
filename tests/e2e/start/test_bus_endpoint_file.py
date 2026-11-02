#!/usr/bin/env python3
# e2e: tier=T1 surface=start
"""`--bus-endpoint-file`: the rendezvous file holds the REAL bound bus address and
nothing secret, and a client that knows ONLY that file (plus its own token) lands on
THIS core -- proven on a dedicated core across its whole lifecycle, and cross-checked
on the runner's core.

What the file IS (crates/aitm-mcp/src/transport.rs `write_endpoint_file`, and
crates/aitm/src/main.rs `--bus-endpoint-file`): once the loopback-TCP bus has bound,
the core writes exactly one line `127.0.0.1:<port>\\n` to the path, mode 0600,
truncating any stale leftover, and NEVER the token (the token stays in the config;
the file only removes the need to parse stdout for the ephemeral port). It is removed
when the listener is dropped (clean exit). It is how the e2e harness itself, the macOS
app and any parent process find the bus.

Ground truth, never fixtures:

  A. the RUNNER's core (env AITM_BUS_ADDR / AITM_BUS_TOKEN; its file at
     AITM_BUS_ENDPOINT_FILE, or `bus.addr` under AITM_E2E_WORKDIR): the file is a
     regular 0600 file holding exactly the advertised address and no token byte; a
     RAW socket client told nothing but that file + the token completes the MCP
     handshake (`serverInfo.name == aitmproxy`), and `proxy.status` on that
     connection reports the runner's own proxy listener (AITM_PROXY_ADDR); a wrong
     token at that address is answered `-32001 unauthorized` and closed.
  B. a DEDICATED core booted here with `port: 0` (ephemeral: the port is knowable
     ONLY through the file) and random per-run tokens:
     B1 fresh boot -- the file appears after bind (its port accepts a TCP connection
        on the FIRST try the instant the file parses), holds exactly one
        `127.0.0.1:<port>\\n` line, is a regular 0600 file owned by us, carries
        neither token; the raw handshake and the harness BusClient reach THIS child
        (`proxy.status.address` is the proxy port only this test chose); the agent
        token gets the Mcp role (Sensitive `proxy.pause` refused, capture state
        untouched) and the operator token the Operator role (pause really flips
        `capturing`, resume restores it); a bogus token, and the correct token
        smuggling an extra key, are both `-32001` + close; neither token reaches the
        core's stdout/stderr even at RUST_LOG=debug; SIGINT exits 0, the file is
        GONE and the bus port refuses connections.
     B2 stale leftover -- a pre-planted junk file (as after a crash) is truncated to
        the new real address (exercises the `--bus-endpoint-file=<path>` spelling).
     B3 misuse -- over a stdio transport the flag is refused naming the fix and no
        file is created; the flag without a path is refused.

Why this test boots a core: the flag is a BOOT-time contract (write-after-bind,
truncate, remove-on-exit) that an already-running runner core can only witness in
steady state. Leg A attaches to the runner's core and boots nothing; leg B owns its
own child PID (stopped by SIGINT to that PID only, never a pkill) on dedicated free
ports, a private 0700 workdir and a private CA dir, so it never touches the
operator's running app or real CA. Without the aitm binary leg B cannot run and the
test SKIPs loudly rather than pass on leg A alone. Tokens are never printed.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, repo_root, section, skip  # noqa: E402
from aitm_e2e.bus import PROTOCOL_VERSION, BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402

# Exactly one `127.0.0.1:<port>` line with ONE trailing newline (transport.rs writeln!).
ENDPOINT_RE = re.compile(r"\A127\.0\.0\.1:([1-9][0-9]{0,4})\n\Z")
HOST = "127.0.0.1"
UNAUTHORIZED = -32001  # aitm_mcp::server::UNAUTHORIZED
SERVER_NAME = "aitmproxy"  # initialize.result.serverInfo.name
STDIO_REFUSAL = "needs the loopback-TCP bus"  # main.rs apply_bus_endpoint_file
NO_PATH = "requires a path"  # main.rs split_bus_endpoint_file_arg
START_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# a soft-assertion battery: every failed expectation is printed, the run continues
# (and cleans up), and the exit code is 1 iff anything failed.

_failures: list[str] = []
_secrets: list[str] = []  # every token this run knows, scrubbed from anything printed


def scrub(text: object) -> str:
    s = str(text)
    for t in _secrets:
        if t:
            s = s.replace(t, "<token>")
    return s


def expect(cond: object, msg: str, detail: object = "") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {scrub(detail)[:600]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


# ---------------------------------------------------------------------------
# small ground-truth probes (stdlib only, no harness in the way)


def aitm_binary() -> str | None:
    p = os.environ.get("AITM_BIN") or os.path.join(repo_root(), "target", "debug", "aitm")
    return p if os.path.isfile(p) and os.access(p, os.X_OK) else None


def hostport(s: str) -> tuple[str, int]:
    host, _, port = s.strip().rpartition(":")
    return (host.strip("[]") or HOST, int(port))


def read_text(path: str) -> str:
    # newline="" keeps the bytes verbatim so "\n" vs "\r\n" vs nothing is visible.
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def file_facts(path: str) -> dict:
    st = os.lstat(path)
    return {
        "regular": stat.S_ISREG(st.st_mode),
        "symlink": stat.S_ISLNK(st.st_mode),
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "size": st.st_size,
    }


def connect_once(port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=timeout):
            return True
    except OSError:
        return False


def refused(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=2.0):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False  # a timeout or anything else is not a clean refusal


def wait_port(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if connect_once(port, timeout=0.5):
            return True
        time.sleep(0.05)
    return False


class RawLine:
    """A bare newline-delimited JSON client: nothing but a socket and the file's
    address, so the handshake is proven at the wire, not through the harness."""

    def __init__(self, port: int, timeout: float = 10.0):
        self.sock = socket.create_connection((HOST, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.rfile = self.sock.makefile("rb")

    def send(self, obj: dict) -> None:
        self.sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    def recv(self):
        """The next line as JSON; None at EOF; 'silent' if the server said nothing."""
        try:
            line = self.rfile.readline()
        except (socket.timeout, TimeoutError):
            return "silent"
        if not line:
            return None
        return json.loads(line)

    def close(self) -> None:
        for c in (self.rfile, self.sock):
            try:
                c.close()
            except OSError:
                pass

    def __enter__(self) -> "RawLine":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def raw_initialize(port: int, token: str, label: str):
    """Connect to the file's address, present the token, send `initialize`; the reply."""
    with RawLine(port) as c:
        c.send({"token": token})
        c.send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": label, "version": "0"}},
        })
        return c.recv()


def raw_auth_outcome(port: int, token_line: dict) -> tuple[object, object]:
    """Send ONE auth line; return (first reply, what follows). A refusal is an error
    line then EOF (None); an accepted token is silence (the server replies to
    nothing until a request arrives)."""
    with RawLine(port, timeout=4.0) as c:
        c.send(token_line)
        first = c.recv()
        second = c.recv() if isinstance(first, dict) else "n/a"
        return first, second


def is_unauthorized(reply: object) -> bool:
    return (isinstance(reply, dict) and isinstance(reply.get("error"), dict)
            and reply["error"].get("code") == UNAUTHORIZED)


def server_name(reply: object):
    return reply.get("result", {}).get("serverInfo", {}).get("name") if isinstance(reply, dict) else None


def shim(port: int, agent_token: str, operator_token: str | None) -> SimpleNamespace:
    """What BusClient.agent()/operator() need: the address FROM THE FILE + tokens."""
    return SimpleNamespace(bus_addr=(HOST, port),
                           cfg=SimpleNamespace(agent_token=agent_token, operator_token=operator_token))


# ---------------------------------------------------------------------------
# the dedicated child core (leg B): our own PID, dedicated ports, private dirs


def child_env(level: str) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "AITM_CONFIG"}
    env["RUST_LOG"] = level
    env.setdefault("AITM_AUDIT_LOG", "off")
    return env


class Child:
    """One `aitm` process we spawned; stopped by SIGINT to ITS pid only."""

    def __init__(self, argv: list[str], work: str, tag: str):
        self.out_path = os.path.join(work, f"{tag}.stdout.log")
        self.err_path = os.path.join(work, f"{tag}.stderr.log")
        self._out = open(self.out_path, "wb")
        self._err = open(self.err_path, "wb")
        # debug is the loudest the core gets: a token in there would be a leak.
        self.proc = subprocess.Popen(argv, stdout=self._out, stderr=self._err,
                                     stdin=subprocess.DEVNULL, env=child_env("debug"))

    def alive(self) -> bool:
        return self.proc.poll() is None

    def logs(self) -> tuple[str, str]:
        def rd(p: str) -> str:
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    return f.read()
            except OSError:
                return ""
        return rd(self.out_path), rd(self.err_path)

    def stop(self, timeout: float = 10.0):
        """SIGINT our child; its exit code, or None if it had to be killed."""
        killed = False
        if self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGINT)
                try:
                    self.proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    killed = True
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            except ProcessLookupError:
                pass
        for fh in (self._out, self._err):
            try:
                fh.close()
            except OSError:
                pass
        return None if killed else self.proc.returncode


def make_config(work: str, tag: str) -> tuple[CoreConfig, str]:
    """A per-boot config: dedicated free ports, bus port 0 (ephemeral), random
    tokens, and every on-disk dir (poc, CA) under our private workdir."""
    base = os.path.join(work, tag)
    cfg = CoreConfig(
        proxy_port=free_port(),
        browser_proxy_port=free_port(),
        bus_port=0,
        agent_token=secrets.token_hex(24),
        operator_token=secrets.token_hex(24),
        poc_dir=os.path.join(base, "poc"),
        poc_out_dir=os.path.join(base, "poc-out"),
    )
    os.makedirs(cfg.poc_dir)
    os.makedirs(cfg.poc_out_dir)
    _secrets.extend([cfg.agent_token, cfg.operator_token])
    yaml = cfg.to_yaml() + (
        "ca:\n"
        f"  dir: {json.dumps(os.path.join(base, 'ca'))}\n"
        f"  audit_log: {json.dumps(os.path.join(base, 'ca-audit.jsonl'))}\n"
    )
    path = os.path.join(work, f"{tag}.yaml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(yaml)
    os.chmod(path, 0o600)
    return cfg, path


def wait_endpoint(path: str, child: Child, timeout: float):
    """Poll until the file holds a COMPLETE `127.0.0.1:<port>\\n` line (a partial
    write is not accepted); (text, port), or None if the core died / timed out."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not child.alive():
            return None
        try:
            text = read_text(path)
        except OSError:
            text = ""
        m = ENDPOINT_RE.match(text)
        if m:
            return text, int(m.group(1))
        time.sleep(0.02)
    return None


def die_with_logs(child: Child, why: str) -> None:
    _out, err = child.logs()
    child.stop()
    fail(f"{why}; core alive: {child.alive()}; stderr tail: {scrub(err[-900:])!r}")


# ---------------------------------------------------------------------------
# leg A: the runner's core, attached, nothing booted


def leg_runner_core() -> bool:
    addr = os.environ.get("AITM_BUS_ADDR", "").strip()
    token = os.environ.get("AITM_BUS_TOKEN", "")
    if not (addr and token):
        print("  [note] no runner core in env (AITM_BUS_ADDR / AITM_BUS_TOKEN): leg A not run", flush=True)
        return False
    _secrets.append(token)
    op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None
    if op_token:
        _secrets.append(op_token)
    path = os.environ.get("AITM_BUS_ENDPOINT_FILE") or ""
    if not path:
        work = os.environ.get("AITM_E2E_WORKDIR") or ""
        cand = os.path.join(work, "bus.addr") if work else ""  # aitm_e2e.core.Aitm's name
        path = cand if cand and os.path.lexists(cand) else ""
    if not path:
        print("  [note] the runner did not expose its endpoint file (AITM_BUS_ENDPOINT_FILE, or "
              "bus.addr under AITM_E2E_WORKDIR): leg A not run", flush=True)
        return False

    section("A. the runner's core: its endpoint file is the real, secret-free rendezvous")
    ok(f"endpoint file: {path}")
    if not expect(os.path.lexists(path), "the endpoint file exists while the core runs"):
        return True
    facts = file_facts(path)
    expect(facts["regular"] and not facts["symlink"], "a regular file, not a symlink", facts)
    expect(facts["mode"] == 0o600, f"mode is exactly 0600 (got {facts['mode']:04o})")
    expect(facts["uid"] == os.getuid(), "owned by this user")
    text = read_text(path)
    m = ENDPOINT_RE.match(text)
    if not expect(m is not None, "content is exactly one `127.0.0.1:<port>` line with one newline", repr(text[:80])):
        return True
    port = int(m.group(1))
    _host, env_port = hostport(addr)
    expect(port == env_port, f"the file's port {port} is the advertised AITM_BUS_ADDR port {env_port}")
    expect(token not in text and (not op_token or op_token not in text), "neither token appears in the file")

    reply = raw_initialize(port, token, "aitm-e2e-busfile-raw")
    expect(server_name(reply) == SERVER_NAME,
           f"a raw socket client knowing ONLY the file + token completed initialize (serverInfo.name={server_name(reply)!r})", reply)
    bus = BusClient(HOST, port, token, client_name="aitm-e2e-busfile-agent").connect()
    try:
        status = bus.call("proxy.status")
        expect(isinstance(status, dict) and status.get("listening") is True,
               "proxy.status over the file-found bus: the proxy is listening", status)
        proxy = os.environ.get("AITM_PROXY_ADDR", "")
        if proxy and isinstance(status, dict):
            try:
                same = hostport(str(status.get("address")))[1] == hostport(proxy)[1]
            except ValueError:
                same = False
            expect(same, f"...and it is the RUNNER's proxy ({proxy}): the file points at that core, not another", status)
        else:
            ok("AITM_PROXY_ADDR not set: proxy-identity cross-check not run")
        names = bus.tool_names()
        expect(len(names) > 0, f"tools/list is non-empty ({len(names)} tools)")
    finally:
        bus.close()
    first, second = raw_auth_outcome(port, {"token": "not-the-token-" + secrets.token_hex(8)})
    expect(is_unauthorized(first), f"a wrong token at the file's address is answered {UNAUTHORIZED} unauthorized", first)
    expect(second is None, "...and the connection is closed (EOF)", second)
    return True


# ---------------------------------------------------------------------------
# leg B: a dedicated core, the whole lifecycle


def leg_dedicated_core(binary: str) -> None:
    # mkdtemp is 0700: the private parent dir the transport's symlink note requires.
    work = tempfile.mkdtemp(prefix="aitm-e2e-busfile-")
    child: Child | None = None
    try:
        # ---------------------------------------------------------------
        section("B1. fresh boot: write-after-bind, exact content, 0600, no token; connect via the file; roles; clean exit")
        ep = os.path.join(work, "bus.addr")
        cfg, cfg_path = make_config(work, "fresh")
        expect(not os.path.lexists(ep), "no endpoint file before the core starts")
        child = Child([binary, "--config", cfg_path, "--bus-endpoint-file", ep], work, "fresh")
        got = wait_endpoint(ep, child, START_TIMEOUT)
        if got is None:
            die_with_logs(child, f"the endpoint file never held a complete `127.0.0.1:<port>` line within {START_TIMEOUT}s")
        text, port = got
        expect(connect_once(port),
               f"the instant the file parsed, 127.0.0.1:{port} accepted a TCP connection on the FIRST try: bound before written")
        expect(port not in (cfg.proxy_port, cfg.browser_proxy_port),
               "the port is the bus's own (not the proxy's, not the browser listener's)")
        facts = file_facts(ep)
        expect(facts["regular"] and not facts["symlink"], "a regular file, not a symlink", facts)
        expect(facts["mode"] == 0o600, f"created mode is exactly 0600 (got {facts['mode']:04o})")
        expect(facts["uid"] == os.getuid(), "owned by this user")
        expect(facts["size"] == len(text.encode("utf-8")), "not one byte beyond the single line", facts)
        expect(cfg.agent_token not in text and cfg.operator_token not in text,
               "neither the agent nor the operator token is in the file")
        expect(wait_port(cfg.proxy_port, START_TIMEOUT), f"the whole core is up: proxy bound 127.0.0.1:{cfg.proxy_port}")
        expect(read_text(ep) == text, "the file is unchanged once startup completes (written once)")

        reply = raw_initialize(port, cfg.agent_token, "aitm-e2e-busfile-raw")
        expect(server_name(reply) == SERVER_NAME,
               f"raw handshake via the file's address: serverInfo.name == {SERVER_NAME!r}", reply)
        pv = reply.get("result", {}).get("protocolVersion") if isinstance(reply, dict) else None
        expect(bool(pv), f"...with a protocolVersion ({pv!r})")

        core = shim(port, cfg.agent_token, cfg.operator_token)
        agent = BusClient.agent(core)
        op = BusClient.operator(core)
        try:
            status = agent.call("proxy.status")
            expect(isinstance(status, dict) and status.get("listening") is True,
                   "harness BusClient (agent) via the file: proxy.status.listening", status)
            expect(isinstance(status, dict) and status.get("address") == f"127.0.0.1:{cfg.proxy_port}",
                   f"proxy.status.address is the proxy port only THIS test chose ({cfg.proxy_port}): the file names THIS child's bus",
                   status)
            baseline = status.get("capturing") if isinstance(status, dict) else None
            names = agent.tool_names()
            expect("proxy.pause" in names and "proxy.resume" in names,
                   f"tools/list ({len(names)} tools) includes proxy.pause / proxy.resume")

            st, msg = agent.try_call("proxy.pause")
            expect(st == "error", "AGENT token -> Mcp role: Sensitive proxy.pause is refused", msg)
            expect(agent.call("proxy.status").get("capturing") == baseline,
                   f"...and the refusal was real: capturing is unchanged ({baseline})")
            r = op.confirm("proxy.pause")
            expect(isinstance(r, dict) and r.get("capturing") is False,
                   "OPERATOR token -> Operator role: proxy.pause ran (capturing false)", r)
            expect(agent.call("proxy.status").get("capturing") is False,
                   "...ground truth on the OTHER connection: proxy.status.capturing is off")
            r = op.call("proxy.resume")
            expect(isinstance(r, dict) and r.get("capturing") is True, "operator proxy.resume restored capture", r)
            expect(agent.call("proxy.status").get("capturing") is True, "...and the agent sees capturing on again")
        finally:
            agent.close()
            op.close()

        first, second = raw_auth_outcome(port, {"token": "not-the-token-" + secrets.token_hex(8)})
        expect(is_unauthorized(first) and first["error"].get("message") == "unauthorized",
               f"a wrong token -> {UNAUTHORIZED} unauthorized", first)
        expect(second is None, "...then EOF: the connection is closed", second)
        first, second = raw_auth_outcome(port, {"token": cfg.agent_token, "extra": 1})
        expect(is_unauthorized(first) and second is None,
               "the correct token cannot smuggle an extra key on the auth line (refused + closed)", first)

        rc = child.stop()
        expect(rc == 0, f"SIGINT -> clean exit code 0 (got {rc})")
        expect(not os.path.lexists(ep), "the endpoint file is REMOVED on clean exit")
        expect(refused(port), f"127.0.0.1:{port} now refuses connections: the listener is gone with the file")
        out, err = child.logs()
        for name, tok in (("agent", cfg.agent_token), ("operator", cfg.operator_token)):
            expect(tok not in out and tok not in err,
                   f"the {name} token never reached stdout/stderr ({len(out)}+{len(err)} bytes at RUST_LOG=debug)")
        child = None

        # ---------------------------------------------------------------
        section("B2. stale leftover: a crash-era junk file is truncated to the new real address (`=` spelling)")
        junk = "127.0.0.1:1\nSTALE " + "x" * 400 + "\n"
        with open(ep, "w", encoding="utf-8") as f:
            f.write(junk)
        os.chmod(ep, 0o600)
        cfg2, cfg2_path = make_config(work, "stale")
        child = Child([binary, "--config", cfg2_path, f"--bus-endpoint-file={ep}"], work, "stale")
        got = wait_endpoint(ep, child, START_TIMEOUT)
        if got is None:
            die_with_logs(child, f"the pre-planted file was never rewritten to a `127.0.0.1:<port>` line within {START_TIMEOUT}s"
                                 f" (now {scrub(read_text(ep)[:60]) if os.path.exists(ep) else 'absent'!r})")
        text2, port2 = got
        expect(port2 != 1 and "STALE" not in text2 and file_facts(ep)["size"] == len(text2.encode("utf-8")),
               f"the junk was truncated away: exactly `127.0.0.1:{port2}` + newline remains", repr(text2[:60]))
        expect(cfg2.agent_token not in text2 and cfg2.operator_token not in text2, "still no token in the file")
        reply = raw_initialize(port2, cfg2.agent_token, "aitm-e2e-busfile-raw")
        expect(server_name(reply) == SERVER_NAME, "the rewritten address is live: raw handshake completes", reply)
        rc = child.stop()
        expect(rc == 0, f"SIGINT -> clean exit code 0 (got {rc})")
        expect(not os.path.lexists(ep), "...and the file is removed again")
        child = None

        # ---------------------------------------------------------------
        section("B3. misuse is refused before anything binds")
        ep3 = os.path.join(work, "never.addr")
        stdio_cfg = os.path.join(work, "stdio.yaml")
        with open(stdio_cfg, "w", encoding="utf-8") as f:
            f.write(f"listen: 127.0.0.1:{free_port()}\nbrowser:\n  proxy_addr: 127.0.0.1:0\n"
                    "mcp:\n  transport:\n    stdio: {}\n")
        try:
            run = subprocess.run([binary, "--config", stdio_cfg, "--bus-endpoint-file", ep3],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
                                 env=child_env("warn"))
            expect(run.returncode != 0 and STDIO_REFUSAL in run.stderr,
                   f"over a stdio transport the flag is refused (exit {run.returncode}) naming the fix", run.stderr[-300:])
        except subprocess.TimeoutExpired:
            expect(False, "over a stdio transport the flag is refused up front (the core kept running instead)")
        expect(not os.path.lexists(ep3), "...and no endpoint file was created")
        try:
            run = subprocess.run([binary, "--config", cfg_path, "--bus-endpoint-file"],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
                                 env=child_env("warn"))
            expect(run.returncode != 0 and NO_PATH in run.stderr,
                   f"the flag without a path is refused (exit {run.returncode})", run.stderr[-300:])
        except subprocess.TimeoutExpired:
            expect(False, "the flag without a path is refused up front (the core kept running instead)")
    finally:
        if child is not None:
            child.stop()
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------


def main() -> int:
    ran_a = leg_runner_core()
    binary = aitm_binary()
    if binary is None:
        if _failures:
            fail(f"{len(_failures)} expectation(s) failed on the runner's core: " + "; ".join(_failures[:8]))
        skip("the boot-time contract (leg B) needs the aitm binary: set AITM_BIN or `cargo build -p aitm`"
             + (" (leg A on the runner's core passed, but is not the whole claim)" if ran_a else ""))
    ok(f"aitm binary: {binary}")
    leg_dedicated_core(binary)
    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:8]))
    ok("PASS: --bus-endpoint-file publishes exactly the bound bus address (0600, no token), truncates a stale "
       "leftover, is removed on clean exit, and a client knowing only the file + its token reaches this core "
       "in the right role" + (" (also verified on the runner's core)" if ran_a else ""))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 -- surface boot/bus failures as a FAIL with context
        fail(f"{type(e).__name__}: {scrub(e)}")
