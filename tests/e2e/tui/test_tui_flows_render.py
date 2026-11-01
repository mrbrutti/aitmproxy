#!/usr/bin/env python3
# e2e: tier=T1 surface=tui timeout=180 needs=aitm-tui
"""tui/tui_flows_render -- the REAL aitm-tui paints live flows from the running core, and
its filter grammar narrows the list.

aitm-tui --bus host:port --token-file p (crates/aitm-tui/src/main.rs) is the terminal
operator UI, a CLIENT of a running core. It is started here inside a pseudo-terminal and
what it paints is read back through a small VT100 screen model. Ground truth, in order:
  1. the status bar names the bus address and the role the core echoed at initialize;
  2. two REAL GETs through the proxy (/search?q=<m>a -> 200 reflected; /<m>b -> 404) are
     rows on the bus AND both URLs are painted in the flow list, unprompted (live render);
  3. `/` opens the filter; `~u <m> & ~s 4xx` leaves exactly the 404; the bus agrees;
  4. Esc clears the filter and the list widens again;
  5. an unknown atom `~zz` is refused by the grammar; `q` ends the process with exit 0.

Capability gate (headless vs live rig): the aitm-tui binary must exist (AITM_TUI_BIN, a
build output, or PATH) -> SKIP (77) naming the dep when absent. Converted from the dead
_lib/mcp draft harness onto aitm_e2e: it attaches to a runner-provided core
(AITM_BUS_ADDR + AITM_BUS_TOKEN [+ AITM_PROXY_ADDR / AITM_TARGET_URL]) or, when none is
given, self-boots its own core + seeded Target. Uses a real pty (pty.openpty), so it runs
from a real shell/rig, not the sandbox. Exit 0 PASS / 1 FAIL / 77 SKIP.
"""
from __future__ import annotations

import codecs
import fcntl
import os
import pty
import re
import secrets
import shutil
import signal
import ssl
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)

from aitm_e2e import free_port, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(E2E))
COLS, ROWS = 320, 50
CONNECT_TIMEOUT = 60.0
TOAST_LIFETIME = 4.0
ROWS_RE = re.compile(r"(\d+|\S) / (\d+) rows")
TOKEN = re.compile(
    r"\x1b\[([0-?]*)[ -/]*([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][@-~]|\x1b[@-Z\\-_]|[\r\n\x08]|[^\x1b\r\n\x08]+"
)


class Fatal(Exception):
    """The scenario cannot go on (recorded as a failed check)."""


def hostport(addr):
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), int(port)


def find_tui():
    """AITM_TUI_BIN, else the usual build outputs, else PATH; None if absent."""
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(ROOT, "target")
    cands = [os.environ.get("AITM_TUI_BIN"), os.path.join(target, "debug", "aitm-tui"),
             os.path.join(target, "release", "aitm-tui"), shutil.which("aitm-tui")]
    return next((c for c in cands if c and os.path.isfile(c)), None)


def poll(pred, timeout, interval=0.2):
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def via_proxy(url, proxy, timeout=30):
    """One real GET through the proxy: (status, body). A 4xx is an answer, not an error."""
    handlers = [urllib.request.ProxyHandler({"http": f"http://{proxy}", "https": f"http://{proxy}"}),
                urllib.request.HTTPSHandler(context=ssl._create_unverified_context())]  # noqa: SLF001
    req = urllib.request.Request(url, headers={"Connection": "close"})
    try:
        with urllib.request.build_opener(*handlers).open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def tool(bus, name, args=None):
    """One tools/call via the shared aitm_e2e BusClient (unwraps structuredContent, raises on isError)."""
    return bus.call(name, args or {})


def marked_rows(bus, marker):
    return [r for r in tool(bus, "flow.table").get("flows", []) if marker in (r.get("path") or "")]


class Screen:
    """Just enough VT100 to know what is on the terminal NOW: cursor moves and erases are
    applied to a grid; colours and private modes are ignored."""

    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.x = self.y = 0
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._pending = ""

    def feed(self, data):
        text = self._pending + self._dec.decode(data)
        self._pending = ""
        pos = 0
        while pos < len(text):
            m = TOKEN.match(text, pos)
            if m is None:
                if text[pos] == "\x1b" and len(text) - pos < 64:
                    self._pending = text[pos:]
                    return
                pos += 1
                continue
            tok, pos = m.group(0), m.end()
            if tok[0] == "\x1b":
                if tok[1] == "[":
                    self._csi(m.group(1) or "", m.group(2))
            elif tok == "\r":
                self.x = 0
            elif tok == "\n":
                self.y = min(self.y + 1, self.rows - 1)
            elif tok == "\x08":
                self.x = max(self.x - 1, 0)
            else:
                row = self.grid[self.y]
                for ch in tok:
                    if ch >= " " and ch != "\x7f" and self.x < self.cols:
                        row[self.x] = ch
                        self.x += 1

    def _csi(self, params, final):
        if params.startswith("?") or final == "m":
            return
        p = [int(v) if v.isdigit() else 0 for v in params.split(";")] if params else []
        n = (p[0] if p else 0) or 1
        if final in "Hf":
            self.y = min(max(p[0] if p else 1, 1) - 1, self.rows - 1)
            self.x = min(max(p[1] if len(p) > 1 else 1, 1) - 1, self.cols - 1)
        elif final == "A":
            self.y = max(self.y - n, 0)
        elif final == "B":
            self.y = min(self.y + n, self.rows - 1)
        elif final == "C":
            self.x = min(self.x + n, self.cols - 1)
        elif final == "D":
            self.x = max(self.x - n, 0)
        elif final == "G":
            self.x = min(n - 1, self.cols - 1)
        elif final == "d":
            self.y = min(n - 1, self.rows - 1)
        elif final == "J":
            mode = p[0] if p else 0
            for yy in range(self.rows):
                if mode >= 2 or (mode == 0 and yy > self.y) or (mode == 1 and yy < self.y):
                    self.grid[yy] = [" "] * self.cols
            if mode < 2:
                self._erase_line(mode)
        elif final == "K":
            self._erase_line(p[0] if p else 0)

    def _erase_line(self, mode):
        lo, hi = {0: (self.x, self.cols), 1: (0, self.x + 1)}.get(mode, (0, self.cols))
        for i in range(lo, min(hi, self.cols)):
            self.grid[self.y][i] = " "

    def text(self):
        return "\n".join("".join(r).rstrip() for r in self.grid)


class Terminal:
    """aitm-tui on a pty: the screen as it is now (text), keys (press)."""

    def __init__(self, argv, env):
        self.screen = Screen(COLS, ROWS)
        self._lock = threading.Lock()
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                                     start_new_session=True)
        os.close(slave)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            with self._lock:
                self.screen.feed(chunk)

    def text(self):
        with self._lock:
            return self.screen.text()

    def wait_for(self, pattern, timeout):
        rx = re.compile(pattern)
        poll(lambda: rx.search(self.text()) is not None or self.proc.poll() is not None, timeout)
        return rx.search(self.text()) is not None

    def press(self, keys):
        os.write(self.master, keys.encode("utf-8"))

    def wait_exit(self, timeout):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self):
        if self.proc.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.proc.pid, sig)
                except ProcessLookupError:
                    break
                if self.wait_exit(8) is not None:
                    break
        try:
            os.close(self.master)
        except OSError:
            pass


class Checks:
    def __init__(self):
        self.results = []

    def check(self, name, ok, detail=""):
        ok = bool(ok)
        self.results.append((name, ok))
        print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  -- {str(detail)[:700]}"), flush=True)
        return ok

    def fatal(self, name, detail=""):
        self.check(name, False, detail)
        raise Fatal(name)

    def failed(self):
        return [n for n, ok in self.results if not ok]


def scenario(c, term, bus, tui_bus, proxy, target):
    """The five steps; returns (role, filter expression) for the summary line."""

    def screen():
        return f"screen: {term.text()[-1500:]!r}"

    def rows_count():
        m = ROWS_RE.search(term.text())
        return int(m.group(2)) if m else None

    role_rx = r"bus " + re.escape(tui_bus) + r" · (agent|operator)"
    if not term.wait_for(role_rx, CONNECT_TIMEOUT):
        c.fatal(f"the TUI never showed 'bus {tui_bus} · <role>' (exit {term.proc.poll()})", screen())
    role = re.search(role_rx, term.text()).group(1)
    c.check(f"ui: status bar shows 'bus {tui_bus} · {role}' (initialize echoed the role)", True)
    term.press("t")

    marker = "tf" + secrets.token_hex(5)
    url_a = f"{target}/search?q={marker}a"
    url_b = f"{target}/{marker}b"
    status_a, body_a = via_proxy(url_a, proxy)
    status_b, _ = via_proxy(url_b, proxy)
    c.check("proxy: GET /search answered 200 and reflected the marker", status_a == 200 and f"{marker}a" in body_a, status_a)
    c.check(f"proxy: GET /{marker}b answered 404", status_b == 404, status_b)

    def settled():
        return {("a" if f"{marker}a" in r["path"] else "b"): r
                for r in marked_rows(bus, marker) if r.get("status") is not None}

    if not poll(lambda: len(settled()) == 2, 20):
        c.fatal("bus: both flows never settled on the core (flow.table)", marked_rows(bus, marker))
    rows = settled()
    row_a, row_b = rows["a"], rows["b"]
    c.check("bus: both flows captured at the target (GET 200, GET 404)",
            (row_a["method"], row_a["status"], row_b["method"], row_b["status"]) == ("GET", 200, "GET", 404), (row_a, row_b))
    painted_a = f"{row_a['authority']}{row_a['path']}"
    painted_b = f"{row_b['authority']}{row_b['path']}"
    c.check("ui: the flow list painted both URLs, unprompted (live render)",
            poll(lambda: painted_a in term.text() and painted_b in term.text(), 15), screen())
    c.check("ui: status bar counts at least our two rows", poll(lambda: (rows_count() or 0) >= 2, 10), screen())

    expr = f"~u {marker} & ~s 4xx"
    term.press("/")
    c.check("ui: `/` opens the filter prompt", term.wait_for(r"filter: editing", 5), screen())
    term.press(expr)
    c.check("ui: the prompt echoes the typed expression", term.wait_for(re.escape(expr), 5), screen())
    term.press("\r")
    c.check("ui: Enter applies it -- the chip shows the expression and `Esc clears`",
            term.wait_for(re.escape(expr) + r"\s+Esc clears", 5), screen())
    term.press("G")
    narrowed = poll(lambda: rows_count() == 1 and painted_b in term.text() and painted_a not in term.text(), 10)
    c.check("ui: exactly one row remains -- the 404 is listed, the 200 is gone", narrowed, screen())
    mine = marked_rows(bus, marker)
    mine_4xx = [r for r in mine if (r.get("status") or 0) // 100 == 4]
    c.check("bus agrees: two flows carry the marker, exactly one is 4xx, and it is the one shown",
            len(mine) == 2 and len(mine_4xx) == 1 and mine_4xx[0]["path"] == f"/{marker}b", mine)

    term.press("\x1b")
    c.check("ui: Esc clears the filter (chip back to `/ filter`)", term.wait_for(r"/ filter", 5), screen())
    c.check("ui: the list widens again", poll(lambda: (rows_count() or 0) >= 2, 10), screen())

    term.press("/")
    term.wait_for(r"filter: editing", 5)
    term.press("~zz\r")
    c.check("ui: unknown atom `~zz` is refused -- the prompt stays open with its line cleared",
            poll(lambda: "filter: editing" in term.text() and "~zz" not in term.text(), 5), screen())
    term.press("\x1b")
    c.check("ui: Esc closes the prompt and the status bar names the error (`unknown filter ~zz`)",
            term.wait_for(r"unknown filter `~zz`", TOAST_LIFETIME) and "filter: editing" not in term.text(), screen())
    term.press("q")
    code = term.wait_exit(15)
    c.check("process: `q` ended aitm-tui with exit 0", code == 0, f"exit {code}; {screen()}")
    return role, expr


def main():
    tui = find_tui()
    if not tui:
        skip("no aitm-tui binary found (set AITM_TUI_BIN or `cargo build -p aitm-tui`)")

    booted = None
    tgt = None
    bus = None
    try:
        if os.environ.get("AITM_BUS_ADDR"):
            bus_addr = os.environ["AITM_BUS_ADDR"].strip()
            token = os.environ.get("AITM_BUS_TOKEN", "").strip()
            proxy = os.environ.get("AITM_PROXY_ADDR", "").strip()
            target = os.environ.get("AITM_TARGET_URL", "").strip().rstrip("/")
            if not (token and proxy and target):
                skip("a runner core was named by AITM_BUS_ADDR but AITM_BUS_TOKEN / AITM_PROXY_ADDR / "
                     "AITM_TARGET_URL are incomplete")
        else:
            tgt = Target("vulnerable")
            cfg = CoreConfig(proxy_port=free_port(), bus_port=free_port(),
                             scope_entries=[tgt.authority, "127.0.0.1"])
            booted = Aitm.server(cfg)
            h, p = booted.bus_addr
            bus_addr, token = f"{h}:{p}", cfg.agent_token
            proxy, target = f"127.0.0.1:{cfg.proxy_port}", tgt.base.rstrip("/")

        host, port = hostport(bus_addr)
        host = "127.0.0.1" if host in ("", "localhost") else host
        tui_bus = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        bus = BusClient(host, port, token, client_name="aitm-e2e-tui-witness").connect()

        c = Checks()
        role, expr = "?", "?"
        with tempfile.TemporaryDirectory(prefix="aitm-tui-e2e-") as work:
            token_file = os.path.join(work, "bus.token")
            with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
                f.write(token)
            child_env = {k: v for k, v in os.environ.items()
                         if not k.startswith("AITM_") and k not in ("RUST_LOG", "COLUMNS", "LINES")}
            child_env.update({"TERM": "xterm-256color", "HOME": work, "XDG_CONFIG_HOME": work})
            term = Terminal([tui, "--bus", tui_bus, "--token-file", token_file, "--ansi", "--poll", "200"], child_env)
            try:
                role, expr = scenario(c, term, bus, tui_bus, proxy, target)
            except Fatal:
                pass
            finally:
                term.stop()

        failed = c.failed()
        passed = len(c.results) - len(failed)
        print(("PASS" if not failed else "FAIL") + f": aitm-tui ({role}) on bus {tui_bus} painted 2 live flows; "
              f"`{expr}` narrowed the list to 1 row ({passed}/{len(c.results)} checks)"
              + ("" if not failed else f"; failed: {failed}"), flush=True)
        return 0 if not failed else 1
    finally:
        if bus is not None:
            bus.close()
        if booted is not None:
            booted.stop()
        if tgt is not None:
            tgt.stop()


if __name__ == "__main__":
    sys.exit(main())
