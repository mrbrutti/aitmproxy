#!/usr/bin/env python3
# e2e: tier=T1 surface=tui serial timeout=240 needs=aitm-tui
"""tui/tui_intercept -- the REAL aitm-tui holds, edits and resumes a live request.

aitm-tui --bus host:port --token-file p (crates/aitm-tui/src/main.rs) is started in a
pseudo-terminal against a running core, the way an operator attaches it, and driven by
KEYSTROKES only. Every claim is read from OUTSIDE the TUI -- a separate bus connection, the
blocked client, the upstream's own answer -- never from what the TUI says about itself:
  1. `i` arms interception: proxy.status.intercept_armed flips to true.
  2. a REAL GET /search?q=<tag> parks: flow.table state=intercepted, no status, client blocked.
  3. `/ ~u <tag>` narrows to it, `g` selects, `e` opens the raw editor; End/Backspace/typing
     swap the marker in the request line; ^S is Apply & Resume (flow.mutate then flow.resume).
  4. GROUND TRUTH: the blocked client gets the testtarget's 200 reflecting the EDITED marker
     and not the original; the stored flow ends state=resumed, edited=true, edited path+body.
  5. `i` disarms; `q` ends the process with exit 0.

Capability gate (headless vs live rig): the aitm-tui binary must exist (AITM_TUI_BIN / a build
output / PATH) -> SKIP (77) naming the dep when absent; and flow.intercept is Sensitive so it
needs the operator token (own-core provides it; an env rig must supply AITM_BUS_OPERATOR_TOKEN).
Converted from the dead _lib/mcp draft harness onto aitm_e2e: attaches to a runner core or
self-boots its own core + seeded Target; uses a real pty (runs from a real shell/rig, not the
sandbox). serial: `i` is a GLOBAL arm. Exit 0 PASS / 1 FAIL / 77 SKIP.
"""
from __future__ import annotations

import base64
import codecs
import fcntl
import os
import pty
import re
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import urllib.parse

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)

from aitm_e2e import free_port, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(E2E))
COLS, ROWS = 320, 50
HOLD_GRACE_S = 1.0
ENTER, ESC, BACKSPACE, END, CTRL_S = "\r", "\x1b", "\x7f", "\x1b[F", "\x13"
TOKEN = re.compile(
    r"\x1b\[([0-?]*)[ -/]*([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][@-~]|\x1b[@-Z\\-_]|[\r\n\x08]|[^\x1b\r\n\x08]+"
)

_failures: list[str] = []


class Fatal(Exception):
    """The scenario cannot go on (recorded as a failed check)."""


def check(cond, msg, detail="") -> bool:
    ok = bool(cond)
    _failures.append(msg) if not ok else None
    print(("ok   " if ok else "FAIL ") + msg + ("" if ok or not detail else f"  -- {str(detail)[:700]}"), flush=True)
    return ok


def fatal(msg, detail=""):
    check(False, msg, detail)
    raise Fatal(msg)


def confirm_call(bus, name, args):
    try:
        return True, bus.confirm(name, args)
    except (ToolError, BusError) as e:
        return False, str(e)


def find_binary(env_name, name):
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(ROOT, "target")
    cands = [os.environ.get(env_name), os.path.join(target, "debug", name),
             os.path.join(target, "release", name), shutil.which(name)]
    return next((c for c in cands if c and os.path.isfile(c)), None)


def poll(pred, timeout, interval=0.2):
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def hostport(addr):
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), int(port)


def scope_covers(scope, authority):
    host = authority.rsplit(":", 1)[0]
    for e in scope:
        if not isinstance(e, str):
            continue
        if e.startswith("*.") and (host == e[2:] or host.endswith("." + e[2:])):
            return True
        if e == (authority if ":" in e else host):
            return True
    return False


def wait_for_flow(bus, pred, timeout=30, completed=True):
    deadline = time.monotonic() + timeout
    while True:
        for r in bus.call("flow.table").get("flows", []):
            if pred(r) and (not completed or r.get("status") is not None):
                return r
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.2)


def decode_body(msg) -> bytes:
    raw = (msg or {}).get("body")
    return base64.b64decode(raw) if isinstance(raw, str) and raw else b""


class Screen:
    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.x = self.y = 0
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._pending = ""

    def feed(self, data):
        text, self._pending = self._pending + self._dec.decode(data), ""
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
    def __init__(self, argv, env):
        self.screen = Screen(COLS, ROWS)
        self._lock = threading.Lock()
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

        def controlling_tty():
            try:
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            except OSError:
                pass

        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                                     start_new_session=True, preexec_fn=controlling_tty)
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
        poll(lambda: rx.search(self.text()) is not None or self.proc.poll() is not None, timeout, 0.1)
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


def scenario(term, bus, ctl, proxy_port, target, tui_bus, authority, state):
    def screen():
        return f"screen: {term.text()[-1500:]!r}"

    role_rx = r"bus " + re.escape(tui_bus) + r" · (agent|operator)"
    if not term.wait_for(role_rx, 60):
        fatal(f"the TUI never showed 'bus {tui_bus} · <role>' (exit {term.proc.poll()})", screen())
    tui_role = re.search(role_rx, term.text()).group(1)
    check(True, f"ui: connected as {tui_role} (status bar shows 'bus {tui_bus} · {tui_role}')")

    term.press("i")
    armed = poll(lambda: bus.call("proxy.status").get("intercept_armed") is True, 10)
    if not armed and tui_role == "agent":
        skip("`i` (flow.intercept, Sensitive) did not arm with the agent token; provide the operator token")
    check(armed, "ui: `i` armed intercept (proxy.status.intercept_armed is true)", screen())
    if not armed:
        fatal("nothing to hold without an armed intercept")
    check(term.wait_for(r"intercept armed", 5), "ui: the toolbar pill says 'intercept armed'", screen())

    tag, edited = "hold" + secrets.token_hex(5), "edit" + secrets.token_hex(5)
    url = f"{target}/search?q={tag}"
    box: list = []

    def client_get():
        try:
            box.append(via_proxy(proxy_port, "GET", url, timeout=90))
        except Exception as e:  # noqa: BLE001
            box.append(e)

    client = threading.Thread(target=client_get, daemon=True)
    client.start()
    row = wait_for_flow(bus, lambda f: f"q={tag}" in (f.get("path") or "") and f.get("state") == "intercepted",
                        timeout=30, completed=False)
    if row is None:
        fatal("the marked GET never parked (flow.table never showed state=intercepted)", screen())
    fid = state["fid"] = row["id"]
    check(row.get("status") is None, "bus: the flow is parked (state=intercepted, no status yet)", row)
    time.sleep(HOLD_GRACE_S)
    check(client.is_alive() and not box, f"client: still blocked {HOLD_GRACE_S}s later (nothing forwarded)", box)
    check(term.wait_for(r"[1-9]\d* paused", 10), "ui: the status bar counts the paused flow", screen())

    term.press("/")
    term.wait_for(r"filter: editing", 5)
    term.press(f"~u {tag}" + ENTER)
    check(term.wait_for(re.escape(f"/search?q={tag}"), 10), "ui: `~u <tag>` lists our parked row", screen())
    term.press("g")
    opened = False
    for _ in range(8):
        term.press("e")
        if term.wait_for(r"no edits yet", 1.5):
            opened = True
            break
    if not opened:
        fatal("`e` never opened the raw request editor", screen())
    req_line = f"GET /search?q={tag} HTTP/1.1"
    shown = term.wait_for(re.escape(req_line), 5)
    check(shown, "ui: the editor shows OUR parked request line", screen())
    if not shown:
        term.press(ESC)
        fatal("not editing someone else's flow")

    term.press(END)
    time.sleep(0.2)
    term.press(BACKSPACE * (len(tag) + len(" HTTP/1.1")))
    time.sleep(0.2)
    term.press(f"{edited} HTTP/1.1")
    changed = term.wait_for(r"~ GET /search\?q=" + edited + r" HTTP/1\.1", 5)
    check(changed, "ui: request line edited in place (the gutter marks the changed line)", screen())
    check("edits pending" in term.text(), "ui: the hint says 'edits pending' (^S Apply & Resume)", screen())
    if not changed:
        term.press(ESC)
        fatal("not applying an edit the editor does not show")
    term.press(CTRL_S)

    client.join(30)
    resp = box[0] if box else None
    got = resp is not None and not isinstance(resp, Exception)
    check(got and resp.status == 200, "client: the held request completed after ^S with 200", resp)
    if got:
        check(edited in resp.text, "upstream answered the EDITED request (its body reflects the new marker)", resp.text[:200])
        check(tag not in resp.text, "upstream never saw the original marker", resp.text[:200])
    done = wait_for_flow(bus, lambda f: f.get("id") == fid, timeout=15)
    check(done is not None and done.get("state") == "resumed" and done.get("status") == 200,
          "bus: the flow ends state=resumed with status 200", done)
    d = bus.call("flow.detail", {"id": fid})
    check(d.get("edited") is True, "bus: flow.detail records edited=true", d.get("edited"))
    stored_path = (d.get("request") or {}).get("path")
    check(stored_path == f"/search?q={edited}", "bus: the stored request path carries the edit", stored_path)
    body = decode_body(d.get("response"))
    check(edited.encode() in body and tag.encode() not in body,
          "bus: the captured response body reflects only the edited marker", body[:200])

    term.press("i")
    check(poll(lambda: bus.call("proxy.status").get("intercept_armed") is False, 10),
          "ui: `i` disarmed intercept (proxy.status.intercept_armed is false)", screen())
    term.press("q")
    code = term.wait_exit(15)
    check(code == 0, "process: `q` ended aitm-tui with exit 0", f"exit {code}; {screen()}")
    return tui_role, tag, edited


def main():
    tui = find_binary("AITM_TUI_BIN", "aitm-tui")
    if not tui:
        skip("aitm-tui binary not found (set AITM_TUI_BIN or `cargo build -p aitm-tui`)")

    booted = tgt = bus = ctl = term = None
    state = {"fid": None}
    added_scope = None
    try:
        if os.environ.get("AITM_BUS_ADDR"):
            bus_addr = os.environ["AITM_BUS_ADDR"].strip()
            agent_token = os.environ.get("AITM_BUS_TOKEN", "").strip()
            op_tok = os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None
            proxy = os.environ.get("AITM_PROXY_ADDR", "").strip()
            target = (os.environ.get("AITM_TARGET_URL") or "").strip().rstrip("/")
            if not (agent_token and proxy and target):
                skip("a runner core was named by AITM_BUS_ADDR but AITM_BUS_TOKEN / AITM_PROXY_ADDR / "
                     "AITM_TARGET_URL are incomplete")
            h, p = hostport(bus_addr)
            proxy_port = int(proxy.rsplit(":", 1)[1])
        else:
            tgt = Target("vulnerable")
            cfg = CoreConfig(proxy_port=free_port(), bus_port=free_port(),
                             scope_entries=[tgt.authority, "127.0.0.1"])
            booted = Aitm.server(cfg)
            h, p = booted.bus_addr
            agent_token, op_tok = cfg.agent_token, cfg.operator_token
            proxy_port, target = cfg.proxy_port, tgt.base.rstrip("/")

        bus = BusClient(h, p, agent_token, client_name="aitm-e2e-tui-witness").connect()
        ctl = BusClient(h, p, op_tok, client_name="aitm-e2e-tui-op").connect() if op_tok else bus
        role = "operator" if op_tok else "agent"
        names = set(bus.tool_names())
        missing = [tl for tl in ("flow.intercept", "flow.mutate", "flow.resume", "flow.table", "flow.detail", "proxy.status", "scope.list") if tl not in names]
        if missing:
            skip(f"the core is missing {missing}")
        if not op_tok:
            st, status = bus.try_call("agent.status")
            if st == "ok" and isinstance(status, dict) and status.get("policy") == "ask":
                skip("agent policy is `ask` (the TUI's flow.intercept would park); provide the operator token")

        th = "127.0.0.1" if h in ("", "localhost") else h
        tui_bus = f"[{th}]:{p}" if ":" in th else f"{th}:{p}"
        tgt_u = urllib.parse.urlsplit(target)
        authority = f"{tgt_u.hostname}:{tgt_u.port or 80}"

        if not scope_covers(bus.call("scope.list"), authority):
            ok_s, msg = confirm_call(ctl, "scope.add", {"host": tgt_u.hostname})
            if not ok_s:
                skip(f"testtarget {authority} is not in scope and the {role} cannot scope.add it ({str(msg)[:120]}); "
                     "the TUI refuses `e` out of scope -- provide the operator token")
            added_scope = tgt_u.hostname

        ctl.try_call("flow.intercept", {"enabled": False, "rules": []})
        if bus.call("proxy.status").get("intercept_armed") is not False:
            skip(f"intercept is already armed on this core and the {role} token cannot disarm it")

        work = tempfile.mkdtemp(prefix="aitm-tui-e2e-")
        token_file = os.path.join(work, "bus.token")
        with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(op_tok or agent_token)
        child_env = {k: v for k, v in os.environ.items()
                     if not k.startswith("AITM_") and k not in ("COLUMNS", "LINES", "RUST_LOG")}
        child_env["TERM"] = "xterm-256color"
        term = Terminal([tui, "--bus", tui_bus, "--token-file", token_file, "--ansi", "--poll", "200"], child_env)

        tui_role, tag, edited = "?", "?", "?"
        try:
            tui_role, tag, edited = scenario(term, bus, ctl, proxy_port, target, tui_bus, authority, state)
        except Fatal:
            pass

        failed = list(_failures)
        total = "?"  # checks aren't individually counted here; summary is enough
        print(("PASS" if not failed else "FAIL") + f": aitm-tui held + edited + resumed a flow on bus {tui_bus}"
              + ("" if not failed else f"; failed: {failed}"), flush=True)
        return 0 if not failed else 1
    except SystemExit:
        raise
    finally:
        if ctl is not None:
            try:
                ctl.try_call("flow.intercept", {"enabled": False, "rules": []})
            except Exception:  # noqa: BLE001
                pass
        if state["fid"] is not None and bus is not None:
            try:
                mine = [r for r in bus.call("flow.table").get("flows", []) if r.get("id") == state["fid"]]
                if mine and mine[0].get("state") == "intercepted":
                    (ctl or bus).try_call("flow.kill", {"id": state["fid"]})
            except Exception:  # noqa: BLE001
                pass
        if added_scope and ctl is not None:
            try:
                confirm_call(ctl, "scope.remove", {"host": added_scope})
            except Exception:  # noqa: BLE001
                pass
        if term is not None:
            term.stop()
        if ctl is not None and ctl is not bus:
            ctl.close()
        if bus is not None:
            bus.close()
        if booted is not None:
            booted.stop()
        if tgt is not None:
            tgt.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  {type(e).__name__}: {e}", flush=True)
        sys.exit(1)
