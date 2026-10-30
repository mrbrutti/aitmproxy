"""Shared harness for aitmproxy REAL end-to-end scenarios.

Boots a real `aitm` proxy (dedicated ports, throwaway per-run dirs, throwaway CA),
a real seeded `aitm-testtarget-serve`, and (on demand) a loopback TLS origin, then
drives them through real clients (curl, the loopback-TCP MCP transport) and asserts
on INDEPENDENT observers (curl exit/status, findings-on-disk, an upstream echo) --
never the proxy's own view.

Conventions (aligned with the e2e-test-framework design, PR #110):
  * exit-code gate: non-zero iff any REQUIRED cell FAILs; SKIPs are loud and never
    read as green;
  * per-run dirs and dedicated ports; the token is never printed;
  * obscura / browser children are cleaned up via the aitm process group only
    (never a machine-wide pkill).

Binary discovery: $AITM_BIN / $AITM_TESTTARGET_BIN, else <repo>/target/debug/<bin>,
else <repo>/target/release/<bin>.
"""

from __future__ import annotations

import itertools
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

_TLS_ORIGIN_SRC = '''\
import http.server, ssl, sys
port, certfile, keyfile = int(sys.argv[1]), sys.argv[2], sys.argv[3]
BODY = b"aitm-e2e-origin-ok\\n"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", str(len(BODY)))
        self.end_headers(); self.wfile.write(BODY)
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(certfile, keyfile)
httpd = http.server.HTTPServer(("127.0.0.1", port), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print(f"tls-origin listening https://127.0.0.1:{port}", flush=True)
httpd.serve_forever()
'''


# --------------------------------------------------------------------------- #
# Reporting: PASS / SKIP / FAIL with an exit-code gate.
# --------------------------------------------------------------------------- #
class Reporter:
    def __init__(self, suite: str):
        self.suite = suite
        self.failed = 0
        self.passed = 0
        self.skipped = 0

    def ok(self, cell: str, detail: str = ""):
        self.passed += 1
        print(f"PASS: {cell}" + (f" -- {detail}" if detail else ""), flush=True)

    def skip(self, cell: str, tier: str, reason: str):
        self.skipped += 1
        print(f"SKIP(tier={tier}): {cell} -- {reason}", flush=True)

    def fail(self, cell: str, detail: str):
        self.failed += 1
        print(f"FAIL: {cell} -- {detail}", flush=True)

    def check(self, cell: str, cond: bool, detail: str = ""):
        # `detail` explains a failure, so it is shown only when the cell FAILs.
        if cond:
            self.ok(cell)
        else:
            self.fail(cell, detail or "assertion false")
        return cond

    def finish(self) -> int:
        print(
            f"\n== {self.suite}: {self.passed} passed, "
            f"{self.skipped} skipped, {self.failed} failed ==",
            flush=True,
        )
        # Optional machine-readable summary for the runner.
        result_file = os.environ.get("AITM_E2E_RESULT")
        if result_file:
            try:
                with open(result_file, "a") as f:
                    f.write(json.dumps({"suite": self.suite, "passed": self.passed,
                                        "skipped": self.skipped, "failed": self.failed}) + "\n")
            except OSError:
                pass
        # Runner contract: 0=PASS, 77=SKIP (nothing ran but skips), else=FAIL.
        if self.failed:
            return 1
        if self.passed == 0 and self.skipped:
            return 77
        return 0


def die(msg: str) -> "NoReturn":  # noqa: F821
    print(f"FATAL: {msg}", file=sys.stderr, flush=True)
    sys.exit(2)


# --------------------------------------------------------------------------- #
# Binaries, ports, tokens.
# --------------------------------------------------------------------------- #
def find_bin(env: str, name: str) -> str:
    override = os.environ.get(env)
    if override:
        if not Path(override).exists():
            die(f"${env}={override} does not exist")
        return override
    for profile in ("debug", "release"):
        cand = REPO_ROOT / "target" / profile / name
        if cand.exists():
            return str(cand)
    die(f"{name} not found (set ${env} or build it under target/debug)")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _hex_token() -> str:
    return os.urandom(32).hex()


# --------------------------------------------------------------------------- #
# Child processes (own process group, killed as a group -> obscura too).
# --------------------------------------------------------------------------- #
class Proc:
    def __init__(self, argv, log_path: Path, env=None):
        self.log_path = log_path
        self.log = open(log_path, "wb")
        self.popen = subprocess.Popen(
            argv,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # own process group
            env=env,
        )

    def alive(self) -> bool:
        return self.popen.poll() is None

    def read_log(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except OSError:
            return ""

    def stop(self):
        if self.popen.poll() is None:
            try:
                os.killpg(os.getpgid(self.popen.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.popen.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.popen.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            self.log.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# The harness: a per-run temp root, config, and the processes it owns.
# --------------------------------------------------------------------------- #
class Harness:
    def __init__(self, suite: str, *, scope_hosts=None, obscura: bool = False,
                 ca_allow_agent_install=False, poc_allow_agent_run=False,
                 rhai_allow_agent_authoring=False, scripts=None,
                 extra_config: str = ""):
        self.suite = suite
        self.root = Path(tempfile.mkdtemp(prefix=f"aitm-e2e-{suite}-"))
        self.procs: list[Proc] = []
        self.aitm_bin = find_bin("AITM_BIN", "aitm")
        self.testtarget_bin = find_bin("AITM_TESTTARGET_BIN", "aitm-testtarget-serve")

        self.proxy_port = free_port()
        self.browser_port = free_port()
        self.mcp_port = free_port()
        self.agent_token = _hex_token()
        self.operator_token = _hex_token()

        self.ca_dir = self.root / "ca"
        self.findings_dir = self.root / "findings"
        self.poc_dir = self.root / "poc"
        self.poc_out = self.root / "poc-out"
        self.scripts_dir = self.root / "scripts"
        self.bus_file = self.root / "bus.json"
        for d in (self.poc_dir, self.poc_out, self.scripts_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.scope_hosts = list(scope_hosts or [])
        self.obscura = obscura
        self._cfg_opts = dict(
            ca_allow_agent_install=ca_allow_agent_install,
            poc_allow_agent_run=poc_allow_agent_run,
            rhai_allow_agent_authoring=rhai_allow_agent_authoring,
        )
        self._scripts = scripts or {}  # {name: source}
        self._extra_config = extra_config
        self.config_path = self.root / "config.yaml"

    # --- lifecycle ------------------------------------------------------- #
    def write_config(self):
        scope = "\n".join(f'    - "{h}"' for h in self.scope_hosts) or "    []"
        if self.scope_hosts:
            scope_block = "scope:\n  entries:\n" + scope + "\n"
        else:
            scope_block = ""
        cfg = f"""listen: 127.0.0.1:{self.proxy_port}
ssl_insecure: true
ca:
  dir: {self.ca_dir}
  allow_agent_install: {str(self._cfg_opts['ca_allow_agent_install']).lower()}
browser:
  proxy_addr: 127.0.0.1:{self.browser_port}
mcp:
  transport:
    loopback_tcp:
      port: {self.mcp_port}
      token: "{self.agent_token}"
      endpoint_file: {self.bus_file}
  operator_token: "{self.operator_token}"
poc:
  dir: {self.poc_dir}
  out_dir: {self.poc_out}
  allow_agent_run: {str(self._cfg_opts['poc_allow_agent_run']).lower()}
findings:
  dir: {self.findings_dir}
rhai:
  scripts_dir: {self.scripts_dir}
  allow_agent_authoring: {str(self._cfg_opts['rhai_allow_agent_authoring']).lower()}
{scope_block}{self._extra_config}"""
        self.config_path.write_text(cfg)

    def install_scripts(self):
        for name, src in self._scripts.items():
            (self.scripts_dir / name).write_text(src)

    def start_testtarget(self, mode="vulnerable") -> str:
        log = self.root / "testtarget.log"
        p = Proc([self.testtarget_bin, "--mode", mode, "--port", "0"], log)
        self.procs.append(p)
        base = self._wait_line(p, "listening ", timeout=15)
        if not base:
            die(f"testtarget did not report a listen URL\n{p.read_log()}")
        return base.split("listening ", 1)[1].strip()

    def start_aitm(self):
        self.write_config()
        self.install_scripts()
        env = dict(os.environ, AITM_CONFIG=str(self.config_path))
        if not self.obscura:
            # Point obscura discovery at nothing so a non-browser suite boots fast
            # and spawns no engine; aitm logs a warning and serves without it.
            env["AITM_OBSCURA_BIN"] = str(self.root / "no-obscura")
        log = self.root / "aitm.log"
        p = Proc([self.aitm_bin, "--bus-endpoint-file", str(self.bus_file)], log, env=env)
        self.procs.append(p)
        # readiness: proxy listening + CA minted + MCP port accepting.
        deadline = time.time() + 25
        ca_crt = self.ca_dir / "ca.crt"
        while time.time() < deadline:
            if not p.alive():
                die(f"aitm exited during boot\n{p.read_log()}")
            if ca_crt.exists() and _port_open(self.mcp_port) and "proxy listening" in p.read_log():
                return
            time.sleep(0.1)
        die(f"aitm not ready within 25s\n{p.read_log()}")

    def run_cli(self, *args, timeout=40):
        """Run a one-shot `aitm --config <cfg> <args...>` (its own in-process core,
        nothing bound). Returns (rc, stdout, stderr)."""
        argv = [self.aitm_bin, "--config", str(self.config_path), *args]
        res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr

    def start_tls_origin(self):
        """A hermetic loopback HTTPS origin (self-signed) the proxy MITMs. Returns
        its base URL; the proxy accepts its cert via ssl_insecure."""
        crt = self.root / "origin.crt"
        key = self.root / "origin.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(crt), "-days", "2",
             "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            capture_output=True, check=True,
        )
        port = free_port()
        src = self.root / "tls_origin.py"
        src.write_text(_TLS_ORIGIN_SRC)
        log = self.root / "tls_origin.log"
        p = Proc([sys.executable, str(src), str(port), str(crt), str(key)], log)
        self.procs.append(p)
        if not self._wait_line(p, "tls-origin listening", timeout=10):
            die(f"tls origin did not start\n{p.read_log()}")
        return f"https://127.0.0.1:{port}"

    def mcp(self, role="agent") -> "Mcp":
        token = self.operator_token if role == "operator" else self.agent_token
        return Mcp(self.mcp_port, token)

    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.proxy_port}"

    def cleanup(self):
        for p in reversed(self.procs):
            p.stop()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
        return False


def _port_open(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _wait_line_impl(proc: Proc, needle: str, timeout: float):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for line in proc.read_log().splitlines():
            if needle in line:
                return line
        if not proc.alive():
            return None
        time.sleep(0.1)
    return None


# attach as method
Harness._wait_line = lambda self, proc, needle, timeout=15: _wait_line_impl(proc, needle, timeout)


# --------------------------------------------------------------------------- #
# curl: the independent TLS client.
# --------------------------------------------------------------------------- #
def curl(url, *, proxy=None, cacert=None, insecure=False, extra=None, timeout=20):
    """Return (exit_code, http_code:int, body:str). exit 60 == TLS trust failure."""
    argv = ["curl", "-sS", "-o", "-", "-w", "\n__HTTP__%{http_code}", "--max-time", str(timeout)]
    if proxy:
        argv += ["-x", proxy]
    if cacert:
        argv += ["--cacert", cacert]
    if insecure:
        argv += ["-k"]
    if extra:
        argv += extra
    argv.append(url)
    res = subprocess.run(argv, capture_output=True, text=True)
    out = res.stdout
    http_code = 0
    body = out
    if "__HTTP__" in out:
        body, _, code = out.rpartition("__HTTP__")
        try:
            http_code = int(code.strip())
        except ValueError:
            http_code = 0
    return res.returncode, http_code, body


# --------------------------------------------------------------------------- #
# Loopback-TCP MCP client (framing/roles per crates/aitm-mcp/src/transport.rs).
# --------------------------------------------------------------------------- #
class McpError(RuntimeError):
    pass


class Mcp:
    def __init__(self, port, token, host="127.0.0.1", timeout=30):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.rf = self.sock.makefile("r", encoding="utf-8", newline="\n")
        self._ids = itertools.count(1)
        self._send({"token": token})  # auth line: one-key JSON + newline

    def _send(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def _rpc(self, method, params=None):
        rid = next(self._ids)
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        for line in self.rf:
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if str(msg.get("method", "")).startswith("notifications/"):
                continue
            if msg.get("id") == rid:
                if "error" in msg:
                    raise McpError(msg["error"])
                return msg["result"]
        raise McpError("connection closed before reply (bad token?)")

    def initialize(self):
        r = self._rpc("initialize", {"protocolVersion": "2025-06-18",
                                     "clientInfo": {"name": "e2e", "version": "0"}})
        return r

    def tools(self) -> set:
        r = self._rpc("tools/list")
        return {t["name"] for t in r.get("tools", [])}

    def call(self, name, arguments=None, *, confirm=True):
        """Standard MCP tools/call. Returns (structuredContent, is_error, text).
        Auto-handles the operator _confirm two-step for confirm-prompt commands."""
        args = dict(arguments or {})
        res = self._rpc("tools/call", {"name": name, "arguments": args})
        sc = res.get("structuredContent")
        if confirm and isinstance(sc, dict) and sc.get("status") == "needs_confirmation":
            args["_confirm"] = sc["confirm_token"]
            res = self._rpc("tools/call", {"name": name, "arguments": args})
            sc = res.get("structuredContent")
        text = ""
        content = res.get("content") or []
        if content and isinstance(content[0], dict):
            text = content[0].get("text", "")
        return sc, bool(res.get("isError")), text

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
