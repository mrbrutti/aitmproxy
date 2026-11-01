#!/usr/bin/env python3
# e2e: tier=T1 surface=l4 serial timeout=300 needs=aitm-tui
"""l4/l4_tui_live -- the REAL aitm-tui against the L4 rig core (L4 parity plan task B9).

The worktree's `aitm-tui` binary runs in a pseudo-terminal (160x44) against the rig core
named by AITM_BUS_ADDR, exactly as an operator attaches it (`--bus host:port --token-file p
--expect-role operator`), and is driven by KEYSTROKES only. Every claim is read from OUTSIDE
the TUI -- a separate operator bus connection reading the core's audit ring
(`agent.activity`), `l4.scope.list`, `scope.list`, `flow.table` -- or from the TUI's rendered
screen text, compared against what the core itself reported over the bus a moment earlier.
No fixture, snapshot or self-test counts (Matt, 2026-10-31): the rows are real GETs through
the proxy, the reasons are the core's, the ring is the core's.

  AC17  the Agent overlay's first line is `policy: <label> · N actions in the last minute ·
        N client(s)` for the policy `agent.status` reports; no stale "core follow-up F1" line.
  AC15  the L4 panel (`L`) shows `capture unavailable — <reason>` with the exact
        `l4.capture.status.reason`; `:l4 capture lo0` toasts `capture unavailable: <reason>`
        and the ring holds NO `l4.capture.start` from `aitm-tui` since t0.
  AC11  the L4 panel's intercept line shows the exact `l4.intercept.status.reason`; the
        Forward/Drop/Mutate/Revert keys (a d m u) put NO `l4.intercept.*` on the ring. On
        this rig no L4 row can exist (capture needs privilege, intercept is unsupported on
        macOS), so the keys are pressed in the inspector of a real HTTP row, where the L4
        verbs are no-ops and the HTTP verbs find nothing paused; the live verdict on a parked
        packet is [Linux].
  B10   the craft pane's `s` (inject) is refused locally while `l4.capture.status` says
        unavailable: NO `l4.inject` from `aitm-tui` on the ring after the key; the toast
        `inject unavailable: <l4.capture.status.reason>` needs the craft pane of an L4 row,
        which this rig cannot have, so that half is reported [skipped] (unit: `--test
        l4_parity inject_gate`; the real-core key walk is crates/aitm/tests/l4_cua_tui.rs).
  AC14  with real HTTP rows: the chip bar shows `TCP UDP L4`, help (`?`) and the filter hint
        list `~l4 ~tcp ~udp ~icmp`, `/~l4` leaves `0 rows` (the tagged row is gone from the
        screen), Esc brings it back.
  AC13  the scope panel (`S`) has an "L4 scope" section with the three config entries
        (lo0 127.0.0.1/32 9000-9999 capture/inject/intercept, `config`); `:scope add l4
        127.0.0.1/32 9100-9199 lo0 inbound capture` opens the confirm overlay with the
        core's prompt (naming the cidr), `y` adds it and it appears as `runtime` within one
        slow poll; it is then removed over the bus (`l4.scope.remove`). `:scope add
        127.0.0.1:9100` still adds HTTP scope (`scope.list`), removed over the bus after.
        The rig core carries unit (a') (operator confirm, main #218); the plan's "without
        (a')" branch is kept as the else-path and is not exercised here.
  AC33  after every control above, no `aitm-tui` entry on the ring carries `L4 unavailable`.
  Finally `q` exits 0.

Env model (like the sibling l4 cells): AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN (+ AITM_BUS_TOKEN),
AITM_PROXY_ADDR, AITM_TARGET_URL, AITM_TUI_BIN. Never boots its own core. Tokens are never
printed. Soft-assertion battery; exit 0 pass / 1 fail / 77 skip. serial: it adds and removes
scope entries on the shared core and reads the shared audit ring.
"""
from __future__ import annotations

import codecs
import fcntl
import json
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
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
COLS, ROWS = 160, 44
ENTER, ESC = "\r", "\x1b"
TUI_LABEL = "aitm-tui"  # crates/aitm-tui/src/bus.rs CLIENT_NAME, the ring's client_label
UNAVAILABLE = "L4 unavailable"
# The TUI's own literals (crates/aitm-tui/src/ui/{l4,overlays,bars}.rs, app.rs), quoted.
L4_PANEL_HINT = ":l4 capture <iface> [inbound|outbound]"
HELP_TITLE = "aitm-tui · keys and commands"
HELP_ATOMS = "~l4 ~tcp ~udp ~icmp"
AGENT_TITLE = "Agent (MCP) — policy and activity"
SCOPE_TITLE = "Scope — the authorised hosts"
L4_SCOPE_HEADING = "L4 scope"
CONFIRM_TITLE = "Confirm over the wire — guarded L4 action"
INJECT_FOOTER = "This reaches the wire only through l4.inject"
NOT_CONFIRMABLE_TOAST = "this core cannot confirm an operator L4 scope add"
NOTHING_PAUSED = "Nothing paused."
STALE_F1 = re.compile(r"core follow-up F1(?!\d)|Agent · n/a \(F1\)")
# `AgentPolicy::label()` in crates/aitm-tui/src/model.rs, by the wire word `agent.status` reports.
POLICY_LABELS = {"all": "all tools", "auto": "auto", "ask": "ask", "readonly": "read-only", "paused": "paused"}
# The chip bar (`ui::bars::chips`): label then its digit, `TCP UDP L4` after WebSocket.
CHIP_GROUP = re.compile(r"TCP5\s+UDP6\s+L47")
# The slow poll re-reads both status verbs every pass (spec §1): the one `l4.intercept.*`
# call the TUI legitimately makes; every other one is a verdict or a list the bar must not send.
INTERCEPT_POLL = "l4.intercept.status"


def list_row_rx(tag: str):
    """A flow-LIST row carrying `tag` (`ui::flows::row_line`): the record dot, the sequence
    number, then the URL. The inspector pane's header (`GET  404 Not Found  http://…`) and
    the filter text never match it, so this counts rows, not mentions."""
    return re.compile(r"●\s*\d+\S?\s+http://\S*" + re.escape(tag))
AGENT_LINE = re.compile(r"policy: (.+?) · (\d+) actions in the last minute · (\d+) client\(s\)")
# The AC5 entry (spec L4PAR-AC5 / AC13).
AC5_WORDS = ("127.0.0.1/32", "9100-9199", "lo0", "inbound", "capture")
AC5_LINE = ":scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture"
HTTP_SCOPE_HOST = "127.0.0.1:9100"
TOKEN = re.compile(
    r"\x1b\[([0-?]*)[ -/]*([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][@-~]|\x1b[@-Z\\-_]|[\r\n\x08]|[^\x1b\r\n\x08]+"
)

_failures: list[str] = []
_skipped: list[str] = []


class Fatal(Exception):
    """The scenario cannot go on (already recorded as a failed check)."""


def expect(cond, msg: str, detail="") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        text = str(detail)
        # A screen dump is the evidence: keep it whole (160x44 is at most ~7 KB).
        line += "   -- " + (text if text.startswith("screen: ") else text[:700])
    print(line, flush=True)
    _failures.append(msg)
    return False


def fatal(msg: str, detail="") -> None:
    expect(False, msg, detail)
    raise Fatal(msg)


def skipped_check(msg: str, why: str) -> None:
    print(f"  [skipped] {msg}   -- {why}", flush=True)
    _skipped.append(msg)


def show(label: str, value) -> None:
    print(f"note: {label} = {json.dumps(value, default=str, sort_keys=True)[:700]}", flush=True)


def poll(pred, timeout, interval=0.2):
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def find_binary(env_name, name):
    target = os.environ.get("CARGO_TARGET_DIR") or str(ROOT / "target")
    cands = [os.environ.get(env_name), os.path.join(target, "debug", name),
             os.path.join(target, "release", name), shutil.which(name)]
    return next((c for c in cands if c and os.path.isfile(c)), None)


def hostport(addr):
    host, _, port = addr.rpartition(":")
    return host.strip("[]") or "127.0.0.1", int(port)


def now_ms() -> int:
    return int(time.time() * 1000)


# ---- pure helpers (no bus, no exit) -----------------------------------------------------

def tui_entries(entries, since_ms: int) -> list[dict]:
    """The ring entries the TUI's connection made after `since_ms` (display label `aitm-tui`)."""
    return [e for e in entries if isinstance(e, dict) and e.get("client_label") == TUI_LABEL
            and isinstance(e.get("at"), int) and e["at"] > since_ms]


def commands_matching(entries, prefix: str) -> list[str]:
    return [str(e.get("command")) for e in entries if str(e.get("command", "")).startswith(prefix)]


def unavailable_results(entries) -> list[dict]:
    """Entries whose result is an error carrying `L4 unavailable` (AC33's forbidden outcome)."""
    out = []
    for e in entries:
        r = e.get("result")
        if isinstance(r, dict) and UNAVAILABLE in str(r.get("error", "")):
            out.append(e)
    return out


def histogram(entries) -> dict[str, int]:
    h: dict[str, int] = {}
    for e in entries:
        c = str(e.get("command"))
        h[c] = h.get(c, 0) + 1
    return dict(sorted(h.items()))


def scope_line_rx(cidr: str, ports: str, iface: str, direction: str, capability: str, source: str):
    """The scope panel's L4 row (`ui::overlays::scope`): iface cidr ports direction capability source."""
    return re.compile(
        rf"{re.escape(iface)}\s+{re.escape(cidr)}\s+{re.escape(ports)}\s+{direction}\s+{capability}\s+{source}\b"
    )


def ports_text(entry: dict) -> str:
    return str(entry.get("ports", ""))


# ---- the pty terminal (the pattern of tests/e2e/tui/test_tui_intercept.py) ---------------

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
        rx = pattern if isinstance(pattern, re.Pattern) else re.compile(pattern)
        poll(lambda: rx.search(self.text()) is not None or self.proc.poll() is not None, timeout, 0.1)
        return rx.search(self.text()) is not None

    def wait_gone(self, pattern, timeout):
        rx = pattern if isinstance(pattern, re.Pattern) else re.compile(pattern)
        poll(lambda: rx.search(self.text()) is None or self.proc.poll() is not None, timeout, 0.1)
        return rx.search(self.text()) is None

    def press(self, keys):
        os.write(self.master, keys.encode("utf-8"))

    def esc(self, gone=None, timeout=5) -> bool:
        """Press a BARE Esc: written alone, then a pause so the next key never lands in
        the same pty read (crossterm would parse `ESC @` as Alt+@ and drop the Esc, or
        process the Esc late -- the second live run's failure mode). When `gone` is given,
        wait until that pattern has left the screen, so the mode change is confirmed."""
        self.press(ESC)
        time.sleep(0.3)
        if gone is None:
            return True
        return self.wait_gone(gone, timeout)

    def reveal(self, pattern, timeout) -> bool:
        """Wait for `pattern`; when the list is longer than the screen, jump to its end
        (`G`) and then its start (`g`) before giving up -- the row exists, the viewport
        may just not hold it."""
        if self.wait_for(pattern, timeout):
            return True
        for key in ("G", "g"):
            self.press(key)
            if self.wait_for(pattern, 3):
                return True
        return False

    def command(self, line: str):
        """Type `:<line>` into the palette and run it (Enter runs the typed line, or the
        single completion the typed line is)."""
        self.press(":")
        time.sleep(0.15)
        self.press(line)
        time.sleep(0.25)
        self.press(ENTER)

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


# ---- the live drive ----------------------------------------------------------------------

def get_via_proxy(proxy_addr: str, url: str, timeout=15.0) -> int:
    """One real GET through the proxy (urllib ProxyHandler, as the sibling cells do)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://{proxy_addr}"}))
    try:
        with opener.open(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def ring(op, since_ms: int) -> list[dict]:
    entries = op.call("agent.activity", {"since": since_ms})
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


def flows_with(op, needle: str) -> list[dict]:
    table = op.call("flow.table")
    rows = table.get("flows", []) if isinstance(table, dict) else []
    return [r for r in rows if needle in str(r.get("path") or "") or needle in str(r.get("url") or "")]


def scenario(term: Terminal, op, state: dict, facts: SimpleNamespace) -> None:
    def screen():
        return f"screen: {term.text()!r}"

    t0 = state["t0"]
    tui_bus = facts.tui_bus

    section("(0) the real aitm-tui connects as operator")
    role_rx = re.compile(r"bus " + re.escape(tui_bus) + r" · operator")
    if not term.wait_for(role_rx, 60):
        fatal(f"the TUI never showed 'bus {tui_bus} · operator' (exit {term.proc.poll()})", screen())
    ok(f"ui: status bar shows 'bus {tui_bus} · operator'")
    # The first slow poll must land before the panels say anything about L4.
    term.press("L")
    landed = term.wait_for(re.escape("capture unavailable — ") if not facts.capture["available"]
                           else r"capture: available", 20)
    expect(landed, "ui: `L` opens the L4 panel and the first status poll has landed", screen())
    expect(L4_PANEL_HINT in term.text(), f"ui: the L4 panel offers `{L4_PANEL_HINT}`", screen())
    expect(term.esc(re.escape(L4_PANEL_HINT)), "ui: Esc closes the L4 panel before the next section", screen())

    section("(1) AC17: the Agent overlay's first line is the core's policy")
    term.press("@")
    expect(term.wait_for(re.escape(AGENT_TITLE), 10), f"ui: `@` opens '{AGENT_TITLE}'", screen())
    expect(term.wait_for(AGENT_LINE, 10), "ui: the overlay's first line reads `policy: … · … actions in the last minute · … client(s)`", screen())
    m = AGENT_LINE.search(term.text())
    shown = m.group(1) if m else None
    want = POLICY_LABELS.get(facts.policy)
    print(f"note: agent.status policy = {facts.policy!r}; overlay label = {shown!r}", flush=True)
    expect(shown == want, f"ui: the overlay labels the policy `{want}` (agent.status says `{facts.policy}`)", shown)
    expect(STALE_F1.search(term.text()) is None, "ui: no stale `core follow-up F1` / `n/a (F1)` line anywhere on screen", screen())
    expect(term.esc(re.escape(AGENT_TITLE)), "ui: Esc closes the Agent overlay", screen())

    section("(2) AC15: the L4 panel shows the core's capture reason; `:l4 capture lo0` sends nothing")
    cap_reason = facts.capture.get("reason")
    int_reason = facts.intercept.get("reason")
    term.press("L")
    expect(term.wait_for(re.escape(L4_PANEL_HINT), 10), "ui: `L` opens the L4 panel", screen())
    if facts.capture["available"]:
        skipped_check("AC15 capture-unavailable line", "this core says capture is available; the start/stop walk is [D0]'s")
    else:
        line = f"capture unavailable — {cap_reason}"
        expect(line in term.text(), "ui: the panel line is exactly `capture unavailable — <l4.capture.status.reason>`",
               {"want": line, "screen": term.text()[:1200]})
        expect("no running capture" in term.text(), "ui: the panel says `no running capture` (captures == [])", screen())
    if facts.intercept["available"]:
        skipped_check("AC11 intercept-unavailable line", "this core says intercept is available; the parked walk is [Linux]")
    else:
        line = f"intercept unavailable — {int_reason}"
        expect(line in term.text(), "ui: the panel line is exactly `intercept unavailable — <l4.intercept.status.reason>` (AC11)",
               {"want": line, "screen": term.text()[:1200]})
    expect("Reading L4 availability…" not in term.text(), "ui: the pending literal is gone once the core answered", screen())
    before = ring(op, t0)
    term.command("l4 capture lo0")
    if facts.capture["available"]:
        skipped_check("`:l4 capture lo0` local refusal", "capture is available here; a real start would run")
    else:
        prefix = "capture unavailable: " + str(cap_reason)[:24]
        expect(term.wait_for(re.escape(prefix), 10),
               "ui: the toast reads `capture unavailable: <reason>` (clipped to the status bar)", screen())
    time.sleep(1.0)
    after = tui_entries(ring(op, t0), t0)
    show("ring: aitm-tui commands since t0", histogram(after))
    expect(len(after) > 0, "ring: the TUI's connection is attributed as `aitm-tui` (its polls are on the ring)", len(before))
    expect(commands_matching(after, "l4.capture.start") == [],
           "ring: NO `l4.capture.start` from aitm-tui since t0", commands_matching(after, "l4.capture.start"))
    expect(term.esc(re.escape(L4_PANEL_HINT)), "ui: Esc closes the L4 panel", screen())

    section("(3) AC14: real HTTP rows, the L4 chip, help, `/~l4`")
    tag = "l4tui" + secrets.token_hex(4)
    url = f"{facts.target}/{tag}"
    statuses = [get_via_proxy(facts.proxy, url) for _ in range(3)]
    print(f"note: 3 real GETs through {facts.proxy} to {url}: statuses {statuses}", flush=True)
    expect(all(isinstance(s, int) for s in statuses), "proxy: three real GETs went through the proxy", statuses)
    expect(poll(lambda: len(flows_with(op, tag)) >= 3, 20), "bus: flow.table lists the three tagged rows", flows_with(op, tag))
    state["tag"] = tag
    expect(term.reveal(re.escape(tag), 20), "ui: the tagged HTTP row is on the screen", screen())
    expect(CHIP_GROUP.search(term.text()) is not None, "ui: the chip bar shows `TCP UDP L4` (keys 5 6 7) after WebSocket", screen())
    term.press("?")
    expect(term.wait_for(re.escape(HELP_TITLE), 10), f"ui: `?` opens '{HELP_TITLE}'", screen())
    expect(HELP_ATOMS in term.text(), f"ui: help lists `{HELP_ATOMS}`", screen())
    if facts.confirmable:
        expect(":scope add l4" in term.text(), "ui: help offers `:scope add l4 …` (the core can confirm it)", screen())
    expect(term.esc(re.escape(HELP_TITLE)), "ui: any key closes help", screen())
    term.press("/")
    expect(term.wait_for(r"filter: editing", 5), "ui: `/` opens the filter prompt", screen())
    expect(HELP_ATOMS in term.text(), f"ui: the filter hint lists `{HELP_ATOMS}`", screen())
    rows_before = len(list_row_rx(tag).findall(term.text()))
    expect(rows_before >= 1, "ui: the tagged rows are list rows (dot, seq, URL) before the filter", rows_before)
    term.press("~l4" + ENTER)
    gone = term.wait_gone(list_row_rx(tag), 10)
    expect(gone, "ui: `/~l4` hides every tagged HTTP list row (the inspector pane may still show the selection)", screen())
    expect(term.wait_for(r"/ 0 rows", 10), "ui: `/~l4` leaves `0 rows` (zero HTTP rows; L4 rows need D0)", screen())
    expect("~l4" in term.text() and "Esc clears" in term.text(), "ui: the chip bar shows the active filter `~l4  Esc clears`", screen())
    term.esc()
    expect(term.reveal(list_row_rx(tag), 10), "ui: Esc clears the filter and the tagged list row is back", screen())

    section("(4) AC11: Forward/Drop/Mutate/Revert keys put no `l4.intercept.*` on the ring")
    l4_rows = op.call("l4.flow.list")
    show("l4.flow.list", l4_rows)
    if isinstance(l4_rows, list) and l4_rows:
        skipped_check("AC11 keys on an L4 row", f"this rig has {len(l4_rows)} L4 flow(s); the parked walk is [Linux] -- "
                      "the keys below are pressed on the HTTP row instead")
    else:
        print("note: no L4 row can exist on this rig (capture unavailable, intercept unsupported); "
              "the keys are pressed in the inspector of the real HTTP row, where the L4 verbs are no-ops", flush=True)
    term.press("/")
    term.wait_for(r"filter: editing", 5)
    term.press(f"~u {tag}" + ENTER)
    term.press("g")
    term.press(ENTER)
    expect(term.wait_for(r"Tab\s+pane", 10), "ui: Enter opens the inspector of the tagged row", screen())
    paused = op.call("proxy.status").get("paused")
    print(f"note: proxy.status.paused = {paused!r} before pressing a/d", flush=True)
    t_keys = now_ms()
    term.press("m")
    time.sleep(0.3)
    term.press("u")
    time.sleep(0.3)
    # B10: the inject key. On an L4 row's craft pane it is refused locally with the
    # core's `l4.capture.status.reason`; on this rig (no L4 row) it is a no-op in the
    # HTTP inspector and, either way, nothing named `l4.inject` may reach the ring.
    term.press("s")
    time.sleep(0.3)
    if paused in (0, None):
        term.press("a")
        expect(term.wait_for(re.escape(NOTHING_PAUSED), 5), "ui: `a` (Forward on L4 / Resume on HTTP) finds nothing paused", screen())
        term.press("d")
        time.sleep(0.5)
        expect(NOTHING_PAUSED in term.text(), "ui: `d` (Drop on L4 / Kill on HTTP) finds nothing paused", screen())
    else:
        skipped_check("`a`/`d` keys", f"{paused} flow(s) are paused on this shared core; not resuming or killing someone else's")
    time.sleep(1.0)
    since_keys = tui_entries(ring(op, t0), t_keys - 1)
    show("ring: aitm-tui commands since the keys", histogram(since_keys))
    verdicts = [c for c in commands_matching(since_keys, "l4.intercept.") if c != INTERCEPT_POLL]
    expect(verdicts == [], f"ring: NO `l4.intercept.*` other than the §1 `{INTERCEPT_POLL}` poll from aitm-tui after a/d/m/u", verdicts)
    injects = commands_matching(since_keys, "l4.inject")
    expect(injects == [], "ring: NO `l4.inject` from aitm-tui after `s` (B10: refused locally while capture/inject is unavailable)", injects)
    if facts.capture["available"]:
        skipped_check("B10 `s` toast `inject unavailable: <reason>`", "capture is available here; the inject walk is [D0]'s")
    elif isinstance(l4_rows, list) and l4_rows:
        skipped_check("B10 `s` toast `inject unavailable: <reason>`",
                      "an L4 row exists but the keys were pressed on the HTTP row; the L4 craft walk is crates/aitm/tests/l4_cua_tui.rs STEP 4")
    else:
        skipped_check("B10 `s` toast `inject unavailable: <reason>`",
                      f"the craft pane needs an L4 row and this rig cannot have one (l4.capture.status: {facts.capture.get('code')!r}); "
                      "the real-core key walk is crates/aitm/tests/l4_cua_tui.rs STEP 4")
    expect(not [c for c in commands_matching(since_keys, "flow.") if c in ("flow.kill", "flow.resume", "flow.mutate")],
           "ring: no flow.kill/resume/mutate from aitm-tui either (the HTTP verbs found nothing paused)")
    rows_after = flows_with(op, tag)
    expect(rows_after and all(r.get("state") != "killed" for r in rows_after), "bus: the tagged rows are untouched", rows_after)
    expect(term.esc(r"Tab\s+pane"), "ui: Esc leaves the inspector", screen())
    expect(term.esc(re.escape(f"~u {tag}")), "ui: Esc clears the `~u` filter", screen())

    section("(5) AC13: the scope panel's L4 scope section; the operator L4 scope add; HTTP scope add")
    term.press("S")
    expect(term.wait_for(re.escape(SCOPE_TITLE), 10), f"ui: `S` opens '{SCOPE_TITLE}'", screen())
    expect(L4_SCOPE_HEADING in term.text(), f"ui: the panel has an `{L4_SCOPE_HEADING}` section", screen())
    for cap in ("capture", "inject", "intercept"):
        rx = scope_line_rx("127.0.0.1/32", "9000-9999", "lo0", "inbound", cap, "config")
        expect(rx.search(term.text()) is not None, f"ui: the config entry lo0 127.0.0.1/32 9000-9999 inbound {cap} config is listed", screen())
    if facts.confirmable:
        expect(":scope add l4" in term.text(), "ui: the section offers `:scope add l4 …` with `(the core asks you to confirm)`", screen())
        t_add = now_ms()
        term.command(AC5_LINE[1:])
        opened = term.wait_for(re.escape(CONFIRM_TITLE), 15)
        expect(opened, f"ui: the core's handshake opens '{CONFIRM_TITLE}'", screen())
        if opened:
            ov = term.text()
            expect(" l4.scope.add" in ov, "ui: the overlay names the call `l4.scope.add`", screen())
            missing = [w for w in AC5_WORDS if w not in ov]
            expect(not missing, "ui: the core's prompt names the cidr, ports, interface, direction, capability", missing)
            expect(INJECT_FOOTER not in ov, "ui: no `l4.inject` footer on a scope-add confirm", screen())
            term.press("y")
            rx = scope_line_rx("127.0.0.1/32", "9100-9199", "lo0", "inbound", "capture", "runtime")
            expect(term.wait_for(rx, 15), "ui: after `y` the new entry appears in the L4 scope section as `runtime` (within one slow poll)", screen())
        time.sleep(0.5)
        listed = op.call("l4.scope.list")
        mine = [e for e in listed if isinstance(e, dict) and ports_text(e) == "9100-9199" and e.get("source") == "runtime"]
        show("l4.scope.list runtime 9100-9199 entries", mine)
        expect(len(mine) == 1, "bus: l4.scope.list shows exactly one runtime entry for 9100-9199", mine)
        if mine:
            state["l4_scope_id"] = mine[0].get("id")
        widen = op.call("l4.agent.status").get("widen")
        expect(widen is False, "bus: l4.agent.status still reads widen: false (the operator path never opened the agent gate)", widen)
        adds = [e for e in tui_entries(ring(op, t0), t_add - 1) if e.get("command") == "l4.scope.add"]
        show("ring: aitm-tui l4.scope.add entries", adds)
        expect(len(adds) == 1 and adds[0].get("result") == "ok",
               "ring: exactly one confirmed `l4.scope.add` from aitm-tui, result ok (the handshake step is not audited)", adds)
        if state.get("l4_scope_id"):
            removed = op.confirm("l4.scope.remove", {"id": state["l4_scope_id"]})
            expect(removed is True, "bus: l4.scope.remove removes it (true)", removed)
            state["l4_scope_id"] = None
        ids_now = sorted(str(e.get("id")) for e in op.call("l4.scope.list") if isinstance(e, dict))
        expect(ids_now == facts.scope_ids, "bus: the L4 scope list is back to its starting ids", {"now": ids_now, "before": facts.scope_ids})
    else:
        # The plan's "without (a')" branch: refused locally, nothing on the bus.
        t_add = now_ms()
        term.command(AC5_LINE[1:])
        expect(term.wait_for(re.escape(NOT_CONFIRMABLE_TOAST), 10), f"ui: `{NOT_CONFIRMABLE_TOAST}`", screen())
        time.sleep(1.0)
        adds = commands_matching(tui_entries(ring(op, t0), t_add - 1), "l4.scope.add")
        expect(adds == [], "ring: no `l4.scope.add` from aitm-tui (refused locally)", adds)

    term.command(f"scope add {HTTP_SCOPE_HOST}")
    expect(term.wait_for(re.escape(f"Scope + {HTTP_SCOPE_HOST}"), 10), f"ui: `:scope add {HTTP_SCOPE_HOST}` toasts `Scope + {HTTP_SCOPE_HOST}`", screen())
    state["http_scope"] = HTTP_SCOPE_HOST
    expect(poll(lambda: HTTP_SCOPE_HOST in op.call("scope.list"), 10), f"bus: scope.list carries {HTTP_SCOPE_HOST}", op.call("scope.list"))
    expect(term.wait_for(re.escape(HTTP_SCOPE_HOST), 10), "ui: the scope panel lists the HTTP host", screen())
    removed = op.confirm("scope.remove", {"host": HTTP_SCOPE_HOST})
    expect(removed is True, "bus: scope.remove removes the HTTP host (true)", removed)
    state["http_scope"] = None
    expect(HTTP_SCOPE_HOST not in op.call("scope.list"), "bus: scope.list no longer carries it")
    expect(term.esc(re.escape(SCOPE_TITLE)), "ui: Esc closes the scope panel", screen())

    section("(6) AC33: nothing the TUI did returned `L4 unavailable`")
    time.sleep(0.5)
    all_tui = tui_entries(ring(op, t0), t0)
    show("ring: every aitm-tui command since t0", histogram(all_tui))
    bad = unavailable_results(all_tui)
    expect(not bad, "ring: no aitm-tui entry carries an `L4 unavailable` result", bad)
    errs = [e for e in all_tui if isinstance(e.get("result"), dict)]
    show("ring: aitm-tui entries with an error result (any)", errs)

    section("(7) `q` exits 0")
    term.esc()
    term.press("q")
    code = term.wait_exit(15)
    expect(code == 0, "process: `q` ended aitm-tui with exit 0", f"exit {code}; {screen()}")


def main() -> int:
    bus_addr = os.environ.get("AITM_BUS_ADDR")
    op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN")
    if not (bus_addr and op_token):
        skip("no runner-provided L4 core: set AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN (+ AITM_BUS_TOKEN), "
             "AITM_PROXY_ADDR, AITM_TARGET_URL and AITM_TUI_BIN from the L4 rig (/tmp/claude/l4-rig/run-cells.sh)")
    proxy = (os.environ.get("AITM_PROXY_ADDR") or "").strip()
    target = (os.environ.get("AITM_TARGET_URL") or "").strip().rstrip("/")
    if not (proxy and target):
        skip("AITM_PROXY_ADDR / AITM_TARGET_URL are not set: AC14 needs real HTTP rows through the proxy")
    tui = find_binary("AITM_TUI_BIN", "aitm-tui")
    if not tui:
        skip("aitm-tui binary not found (set AITM_TUI_BIN or `cargo build -p aitm-tui`)")
    print(f"note: aitm-tui = {tui}", flush=True)

    h, p = hostport(bus_addr.strip())
    tui_bus = f"[{h}]:{p}" if ":" in h else f"{h}:{p}"
    op = term = None
    state: dict = {"t0": 0, "l4_scope_id": None, "http_scope": None, "tag": None}
    work = None
    try:
        op = BusClient(h, p, op_token, client_name="aitm-e2e-l4-tui-witness").connect()
        tools = op.tools()
        names = {t.get("name") for t in tools}
        needed = ("l4.capture.status", "l4.intercept.status", "l4.scope.list", "l4.scope.remove", "l4.agent.status",
                  "agent.activity", "agent.status", "scope.list", "scope.remove", "flow.table", "proxy.status")
        missing = [n for n in needed if n not in names]
        if missing:
            skip(f"the core is missing {missing}; run this against the L4 rig (l4.enabled)")
        confirmable = any(t.get("name") == "l4.scope.add" and t.get("confirmable") is True for t in tools)

        section("facts read over the bus before the TUI starts (the expectations below)")
        policy = op.call("agent.status").get("policy")
        capture = op.call("l4.capture.status")
        intercept = op.call("l4.intercept.status")
        scope = op.call("l4.scope.list")
        show("agent.status.policy", policy)
        show("l4.capture.status", capture)
        show("l4.intercept.status", intercept)
        show("l4.scope.list ids/sources", [(e.get("id"), e.get("source"), e.get("capability")) for e in scope])
        show("l4.scope.add confirmable", confirmable)
        if not isinstance(capture, dict) or "available" not in capture or not isinstance(intercept, dict):
            fail("this core's status verbs are not the spec §1 objects; the rig must carry unit (a)")
        if policy not in POLICY_LABELS:
            fail(f"agent.status.policy {policy!r} is not one the TUI labels {sorted(POLICY_LABELS)}")
        facts = SimpleNamespace(
            tui_bus=tui_bus, proxy=proxy, target=target, policy=policy, capture=capture, intercept=intercept,
            confirmable=confirmable,
            scope_ids=sorted(str(e.get("id")) for e in scope if isinstance(e, dict)),
        )
        if not confirmable:
            print("note: tools/list shows l4.scope.add confirmable=false: this core lacks unit (a'); "
                  "AC13's add takes the plan's refused path", flush=True)

        work = tempfile.mkdtemp(prefix="aitm-l4-tui-e2e-")
        token_file = os.path.join(work, "bus.token")
        with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(op_token)
        child_env = {k: v for k, v in os.environ.items()
                     if not k.startswith("AITM_") and k not in ("COLUMNS", "LINES", "RUST_LOG")}
        child_env["TERM"] = "xterm-256color"
        state["t0"] = now_ms()
        term = Terminal([tui, "--bus", tui_bus, "--token-file", token_file, "--expect-role", "operator",
                         "--ansi", "--poll", "200"], child_env)
        print(f"note: aitm-tui pid {term.proc.pid} in a {COLS}x{ROWS} pty; t0 = {state['t0']}", flush=True)
        try:
            scenario(term, op, state, facts)
        except Fatal:
            pass
    finally:
        if op is not None:
            if state.get("l4_scope_id"):
                try:
                    op.confirm("l4.scope.remove", {"id": state["l4_scope_id"]})
                except (ToolError, BusError) as e:  # pragma: no cover - rig hygiene
                    print(f"  [warn] could not remove the L4 scope entry: {e}", flush=True)
            if state.get("http_scope"):
                try:
                    op.confirm("scope.remove", {"host": state["http_scope"]})
                except (ToolError, BusError) as e:  # pragma: no cover - rig hygiene
                    print(f"  [warn] could not remove the HTTP scope host: {e}", flush=True)
        if term is not None:
            term.stop()
        if work:
            shutil.rmtree(work, ignore_errors=True)
        if op is not None:
            op.close()

    if _skipped:
        print(f"note: {len(_skipped)} check(s) reported as skipped on this core (see [skipped] lines)", flush=True)
    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:8]))
    ok("PASS: the real aitm-tui against the rig core proves AC11/AC13/AC14/AC15/AC17/AC33 (TUI half)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
