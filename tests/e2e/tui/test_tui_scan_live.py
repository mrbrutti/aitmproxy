#!/usr/bin/env python3
# e2e: tier=T1 surface=scan timeout=600 needs=aitm-tui
"""tui/tui_scan_live -- the REAL aitm-tui drives a REAL scan job against a REAL core.

aitm-tui --bus host:port --token-file p (crates/aitm-tui/src/main.rs) is started inside a
pseudo-terminal as the OPERATOR and driven by KEYSTROKES only. Every claim is read from
OUTSIDE the TUI: the harness's own operator BusClient (scan.list / scan.status /
scan.issues / scan.issue / scan.sitemap / l4.scope.list / flow.get), a SECOND BusClient
that holds a flow.subscribe subscription and counts notifications/aitm/job lines, and the
seeded test target itself. This cell is the only acceptance evidence for the TUI Scan
surface (spec ACs T7-16 .. T7-20, umbrella UI-1, UI-2, UI-3, UI-5).

  T7-16 (UI-1) :scan, 1, cursor to `standard`, Enter, o <origin>, Enter, s -> a Jobs row
        with the id scan.list reports; three or more screen samples whose on-screen
        `sent/budget` is non-decreasing and inside a scan.status bracket taken around the
        sample; the state/phase cell changes at least once; x yields `cancelled` on screen
        and in scan.status; the second client saw a `progress` and a `cancelled` line.
  T7-17 (UI-2) a second `standard` job: while scan.status still says `running`, the Issues
        tab shows a reflected-xss issue (else one carrying a payload and a probe flow)
        under its severity header, the detail shows the evidence payload scan.issue
        reports, Tab + Enter opens the first probe flow in the inspector (Request and
        Response panes, the flow's method and path, the Scan strip gone), f ->
        false_positive, u -> open (screen AND scan.issue), P opens Findings on the PoC
        or records the toast.
  T7-18 (UI-3) `l4-stream-safe` + t 127.0.0.1:<port>/tcp: the D7 gate text is on screen and
        s starts nothing (scan.list unchanged for 3 s); after the harness adds an inject
        L4 scope entry (removed again at the end of the run), s shows the confirm overlay
        containing "may disrupt the target", y is answered by what the harness's own
        scan.start answers for the same profile (a Jobs row for a job, the D9 wording for
        `refused_l4` or `lane_unavailable`), and n on a fresh prompt shows `scan.start
        cancelled` with no new job. A core without the `l4-stream-safe` profile FAILS
        the step; only an l4.scope.add the core refuses skips its cleared-gate sub-steps.
  T7-19 (UI-5) a `map-only` job that reached `done`: every host, `METHOD path_template` and
        point name of the harness's live scan.sitemap read is in the rendered text (never
        a fixture); Enter on the node under the cursor opens its first flow in the
        inspector.
  T7-20 hygiene: the seeded Cookie and Authorization values (and their first 12 hex
        chars) never appear in any screen sample taken on the Scan surface (every sample
        is kept, tagged with its surface, and grepped), and q ends the process with exit 0.

Capability gates -> exit 77 (SKIP), nothing claimed:
  * no aitm-tui binary (AITM_TUI_BIN, a build output, or PATH);
  * no aitm-testtarget-serve / no aitm binary when self-booting;
  * a runner core named by AITM_BUS_ADDR with an incomplete operator environment;
  * `scan.start` absent from tools/list (the scanner v2 engine is not on this core).
A v2 core lacking scan.sitemap / scan.issues / scan.issue FAILS the step that reads it.

Attaches to a runner core (AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN + AITM_PROXY_ADDR +
AITM_TARGET_URL) or self-boots Target("vulnerable") + Aitm.server(CoreConfig(..)). Uses a
real pty and real ports, so it runs from a real shell or rig, NEVER from the sandbox
(which denies socket binds). Evidence (screen captures, status brackets, push counts,
summary) is written to $AITM_E2E_ARTIFACTS, else to a temp dir named on stdout; the
seeded secrets are redacted from everything written or printed, and are never printed.
Results are three-state: `ok`, `FAIL`, and `note` (a sub-step the core could not offer,
recorded and tallied apart, never a pass). The per-run work dir (the TUI's HOME, the
0600 token file, the self-booted core's findings store with the seeded session values)
is removed with the run; the L4 scope entry the cell adds is removed by its id.

Exit 0 PASS / 1 FAIL / 77 SKIP.
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
import urllib.parse

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)

from aitm_e2e import free_port  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.target import Target, testtarget_bin  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(E2E))
SKIP_EXIT = 77
COLS, ROWS = 200, 50
# The Scan tabs split side by side at 100 columns or more: the list pane takes the left
# 45 % (crates/aitm-tui/src/ui/scan/mod.rs `panes`), the detail the rest.
LIST_SPAN = int(COLS * 45 / 100)

# Timings. The TUI polls scan.status about once a second (spec D6), so every
# screen claim is polled, never read once.
CONNECT_TIMEOUT = 60.0
UI_SETTLE = 0.35
JOB_APPEAR_S = 30.0
ROW_APPEAR_S = 20.0
SAMPLE_GAP_S = 1.5
SAMPLES_MIN, SAMPLES_MAX = 3, 6
CATCHUP_S = 8.0
CANCEL_S = 25.0
ISSUE_WAIT_S = 150.0
MAP_WAIT_S = 150.0
QUIET_WINDOW_S = 3.0
L4_SCOPE_S = 5.0
GATE_CLEAR_S = 25.0
OVERLAY_S = 20.0
EXIT_S = 15.0
# The first hex chars of a seeded secret that a truncated pane cell must still betray.
SECRET_PREFIX = 12

REDACTED = "<seeded-secret-redacted>"
JOB_ID_RE = re.compile(r"scan-[0-9a-f]{8}")
STATE_RE = re.compile(
    r"\b(queued|running|cancelling|done|cancelled|failed)(?:/(queued|crawl|passive|audit|report|done))?\b"
)
PROBES_RE = re.compile(r"(\d+)/(\d+)")
CURSOR_ROW_RE = re.compile(r"(?:^|\n)>")
# The held editor's header (`crates/aitm-tui/src/ui/scan/profiles.rs` `header`): ` profile `
# then the name. The D7 gate's `open the profile (⏎)` does not match (no `(` in a name).
EDITOR_HEAD_RE = re.compile(r"\bprofile [A-Za-z0-9_.-]+")
# The core's scan error text (`aitm_scan_model::ScanErrorCode::parse_message`): `scan: <code>`.
SCAN_CODE_RE = re.compile(r"scan: ([a-z_]+)")
TOKEN = re.compile(
    r"\x1b\[([0-?]*)[ -/]*([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][@-~]|\x1b[@-Z\\-_]|[\r\n\x08]|[^\x1b\r\n\x08]+"
)

ENTER, ESC = "\r", "\x1b"
SCAN_STRIP = "1 Profiles"
# A text each tab alone draws (crates/aitm-tui/src/ui/scan/{profiles,jobs,sitemap,issues}.rs):
# the Profiles list header, the Jobs footer, the v2 Nodes pane's summary head, the Issues
# footer. The tab strip is on every tab and proves nothing about which one drew.
TAB_MARKERS = {
    "1": r"name\s+lanes\s+intensity",
    "2": r"x cancel · ⏎ issues of this job",
    "3": r"\d+ nodes",
    "4": r"S severity · C confidence",
}
# Spec D9 wordings a refused launch can show instead of a Jobs row (T7-18), by the
# core's error code (crates/aitm-tui/src/scan/mod.rs `code_wording`).
REFUSAL_WORDINGS = {
    "refused_l4": "L4 refused",
    "lane_unavailable": "No requested lane can run on this core",
    "out_of_scope": "Out of scope",
    "busy": "Scanner busy",
    "refused_agent": "Refused for the agent role",
}
CONFIRM_TITLE = "Confirm over the wire: scan launch"
NO_L4_ID = "no id"


class Fatal(Exception):
    """The scenario cannot go on (recorded as a failed check)."""


def skip77(line: str) -> None:
    """Exit 77 with the one skip line the plan names (loud, never green)."""
    print(f"SKIP: {line}", flush=True)
    sys.exit(SKIP_EXIT)


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


def wait_field(read, key, want, timeout, interval=0.4):
    """Poll `read()` (a dict-returning bus read) until its `key` is `want`; the last
    dict read, so the caller can print what the core said instead."""
    last = {}

    def hit():
        nonlocal last
        got = read()
        if isinstance(got, dict):
            last = got
        return last.get(key) == want

    poll(hit, timeout, interval)
    return last


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


class Evidence:
    """Every screen sample is kept RAW in memory (T7-20 greps the raw samples), tagged
    with the surface it was taken on (`scan`: the four tabs and their overlays;
    `inspector`: a flow detail; `other`: Flows, Findings, the exit), and written
    REDACTED to the artifacts dir, so no file and no printed line can carry a seeded
    secret. A secret is matched whole and by its first SECRET_PREFIX hex chars, so a
    pane that truncates the value is still caught."""

    def __init__(self, secret_values):
        self.secrets = [s for s in secret_values if s]
        self.needles = []
        for s in self.secrets:
            self.needles.append(s)
            if len(s) > SECRET_PREFIX:
                self.needles.append(s[:SECRET_PREFIX])
        self.samples = []  # (step, tag, raw text)
        self._dir = os.environ.get("AITM_E2E_ARTIFACTS") or None

    @property
    def dir(self):
        """The artifacts dir, created on first use so a skip leaves nothing behind."""
        if self._dir is None:
            self._dir = tempfile.mkdtemp(prefix="aitm-tui-scan-")
            print(f"evidence dir: {self._dir}", flush=True)
        else:
            os.makedirs(self._dir, exist_ok=True)
        return self._dir

    def redact(self, text):
        out = str(text)
        for s in self.needles:  # whole values first, then their prefixes
            out = out.replace(s, REDACTED)
        return out

    def sample(self, step, text, tag):
        """Record one screen sample under `step` on surface `tag` and return it (raw)."""
        self.samples.append((step, tag, text))
        return text

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.redact(text))
        return path

    def write_json(self, name, obj):
        return self.write(name, json.dumps(obj, indent=2, sort_keys=True, default=str))

    def leaks(self, tag):
        """(index, tag, step) of every sample on surface `tag` carrying a seeded secret
        or its prefix (T7-20)."""
        return [(i, t, step) for i, (step, t, text) in enumerate(self.samples)
                if t == tag and any(n in text for n in self.needles)]

    def tagged(self, tag):
        return sum(1 for _, t, _ in self.samples if t == tag)


class Checks:
    """Three-state results: `ok`, `FAIL`, `note` (a sub-step the core could not offer,
    recorded and tallied apart; never a pass, never a failure)."""

    def __init__(self, redact=str):
        self.results = []  # (name, state)
        self._redact = redact

    def check(self, name, ok, detail=""):
        ok = bool(ok)
        self.results.append((name, "ok" if ok else "FAIL"))
        tail = "" if ok or not detail else f"  -- {self._redact(detail)[:700]}"
        print(("ok   " if ok else "FAIL ") + name + tail, flush=True)
        return ok

    def note(self, name, detail=""):
        self.results.append((name, "note"))
        tail = f"  -- {self._redact(detail)[:300]}" if detail else ""
        print("note " + name + tail, flush=True)

    def fatal(self, name, detail=""):
        self.check(name, False, detail)
        raise Fatal(name)

    def failed(self):
        return [n for n, state in self.results if state == "FAIL"]

    def tally(self):
        """(ok, noted, failed) counts."""
        states = [s for _, s in self.results]
        return states.count("ok"), states.count("note"), states.count("FAIL")

    def lines(self):
        return [f"{state:<5}{n}" for n, state in self.results]


class Pushes:
    """The second bus client: holds a flow.subscribe subscription and tallies
    notifications/aitm/job lines by job and params.event (spec D3 push kind). Only
    the counts are kept; the client's own stash is cleared after each drain."""

    def __init__(self, client):
        self.client = client
        self.counts = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                msgs = self.client.drain_notifications(0.5)
            except (BusError, OSError, ValueError):
                return
            for m in msgs:
                if (m.get("method") or "") != "notifications/aitm/job":
                    continue
                params = m.get("params") or {}
                job = str(params.get("job"))
                event = str(params.get("event"))
                with self._lock:
                    per = self.counts.setdefault(job, {})
                    per[event] = per.get(event, 0) + 1
            self.client.notifications.clear()

    def of(self, job):
        with self._lock:
            return dict(self.counts.get(job, {}))

    def snapshot(self):
        with self._lock:
            return {j: dict(ev) for j, ev in self.counts.items()}

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)


# ----------------------------------------------------------------- bus reads


def job_ids(bus):
    try:
        res = bus.call("scan.list", {})
    except (ToolError, BusError):
        return set()
    return {j.get("job") for j in (res.get("jobs") or []) if isinstance(j, dict) and j.get("job")}


def wait_new_job(bus, before, timeout):
    found = {}

    def seen():
        new = job_ids(bus) - before
        if new:
            found["id"] = sorted(new)[0]
            return True
        return False

    poll(seen, timeout, 0.4)
    return found.get("id")


def status_of(bus, job):
    try:
        return bus.call("scan.status", {"job": job})
    except (ToolError, BusError) as e:
        return {"error": str(e)}


def sent_of(status):
    try:
        return int((status.get("probes") or {}).get("sent"))
    except (TypeError, ValueError):
        return None


def issue_of(bus, issue_id):
    try:
        res = bus.call("scan.issue", {"id": issue_id})
    except (ToolError, BusError):
        return {}
    return res if isinstance(res, dict) else {}


def cancel_quietly(bus, job):
    if not job:
        return
    try:
        bus.call("scan.cancel", {"job": job})
    except (ToolError, BusError):
        pass


# -------------------------------------------------------------- screen reads


def line_with(text, needle):
    for line in text.split("\n"):
        if needle in line:
            return line
    return None


def row_tail(text, job):
    """The job row's text after its id (profile, targets, state/phase, counters)."""
    line = line_with(text, job)
    return line.split(job, 1)[1] if line else None


def row_probes(text, job):
    tail = row_tail(text, job)
    if tail is None:
        return None
    m = PROBES_RE.search(tail)
    return (int(m.group(1)), int(m.group(2))) if m else None


def row_state(text, job):
    tail = row_tail(text, job)
    if tail is None:
        return None
    m = STATE_RE.search(tail)
    return m.group(0) if m else None


def on_cursor(text, needle):
    """True when a row carrying `needle` is the one the cursor marks (`>` then at most a
    few glyph cells, then the text): the Scan list panes all draw the cursor that way."""
    return re.search(r">[^\n]{0,8}" + re.escape(needle), text) is not None


def cursor_row(text):
    """The text of the row the `>` cursor marks (after the mark), or None."""
    m = re.search(r"(?:^|\n)>([^\n]*)", text)
    return m.group(1) if m else None


def group_of(text, needle, headers):
    """The severity header (of `headers`) the LIST row carrying `needle` sits under, or
    None. Only the list pane's columns are read: the detail head on the right shares its
    row with the filter line and would otherwise claim the needle first."""
    lines = [ln[:LIST_SPAN] for ln in text.split("\n")]
    idx = next((i for i, ln in enumerate(lines) if needle in ln), None)
    if idx is None:
        return None
    seen = None
    for i in range(idx):
        for h in headers:
            if re.search(r"\b" + re.escape(h) + r"\s+\d+", lines[i]):
                seen = h
    return seen


def host_label(node):
    """The Site map's group key: `host[:port]`, the port only when it is not the
    scheme's default (crates/aitm-tui/src/scan/sitemap.rs)."""
    default = 443 if node.get("scheme") == "https" else 80
    port = node.get("port") or default
    return node.get("host", "") if port == default else f"{node.get('host', '')}:{port}"


def node_needle(node):
    """`METHOD path_template` as the Nodes pane writes it (`{:<4} {}`), cut so a long
    template cannot fail the match on the pane's own truncation."""
    return "{:<4} {}".format(node.get("method", ""), node.get("path_template", ""))[:40]


def inspector_open(text, method, path):
    """The flow inspector, and nothing else: its Request and Response pane titles
    (crates/aitm-tui/src/ui/inspector.rs), the flow's method then its path on the header
    row, and the Scan tab strip gone. `path` alone is everywhere (`/`)."""
    return (bool(method) and bool(path)
            and re.search(r"Request\s+Headers", text) is not None
            and re.search(r"Response\s+Headers", text) is not None
            and re.search(r"\b" + re.escape(method) + r"\b[^\n]*" + re.escape(path), text) is not None
            and SCAN_STRIP not in text)


def wordings_on(text):
    """The D9 refusal codes whose wording is on screen."""
    return sorted(code for code, w in REFUSAL_WORDINGS.items() if w in text)


# ------------------------------------------------------------------- driving


class Ctx:
    """Everything a step needs; built once in main()."""

    def __init__(self, c, term, bus, pushes, ev, proxy_port, target, origin, target_port, names):
        self.c = c
        self.term = term
        self.bus = bus
        self.pushes = pushes
        self.ev = ev
        self.proxy_port = proxy_port
        self.target = target
        self.origin = origin
        self.target_port = target_port
        self.names = names
        self.marker = ""
        self.cookie_secret = ""
        self.auth_secret = ""
        self.jobs = {}
        self.l4_entry_id = None

    def snap(self, step, tag="scan"):
        """One screen sample on surface `tag`: recorded for the T7-20 grep, returned raw."""
        return self.ev.sample(step, self.term.text(), tag)

    def screen(self, step="detail", tag="scan"):
        """The screen as a failure detail: redacted and cut."""
        return f"screen: {self.ev.redact(self.snap(step, tag))[-1400:]!r}"


def open_scan(ctx):
    """`:scan` opens the Scan view (the palette's first match is the `:scan` command) on
    the tab it was left on."""
    term = ctx.term
    term.press(":")
    if not term.wait_for(r"command or tool", 10):
        return False
    term.press("scan")
    time.sleep(UI_SETTLE)
    term.press(ENTER)
    return term.wait_for(re.escape(SCAN_STRIP), 10)


def tab(ctx, key, timeout=10):
    """Press a tab key and wait for the text that tab alone draws."""
    ctx.term.press(key)
    return ctx.term.wait_for(TAB_MARKERS[key], timeout)


def focus_profiles_list(ctx):
    """The Profiles List pane focused before a cursor walk (G99): while an editor is held
    its Fields pane owns the cursor keys, so one `Esc` (`close_pane`: pane = List, draft
    kept) comes first whenever the editor header `profile <name>` is on screen. The `>`
    row is drawn whichever pane is focused, so a List that was already focused is told
    by the strip leaving on that `Esc`, and `:scan` brings the view back on this tab."""
    term = ctx.term
    if EDITOR_HEAD_RE.search(term.text()):
        term.press(ESC)
        time.sleep(UI_SETTLE)
        if SCAN_STRIP not in term.text() and not open_scan(ctx):
            return False
    return poll(lambda: CURSOR_ROW_RE.search(term.text()) is not None, 5)


def cursor_to(ctx, needle, tries=64):
    """Walk the focused list pane from its top until the cursor marks the row carrying
    `needle`. On Profiles call `focus_profiles_list` first (G99)."""
    ctx.term.press("g")
    time.sleep(UI_SETTLE)
    for _ in range(tries):
        if on_cursor(ctx.term.text(), needle):
            return True
        ctx.term.press("j")
        time.sleep(0.15)
    return on_cursor(ctx.term.text(), needle)


def open_profile(ctx, name):
    """Profiles tab, List pane, cursor to `name`, Enter: the editor over scan.profile.get."""
    if not tab(ctx, "1"):
        return False
    if not focus_profiles_list(ctx) or not cursor_to(ctx, name):
        return False
    ctx.term.press(ENTER)
    return ctx.term.wait_for(r"profile " + re.escape(name), 15)


def ensure_editor(ctx, name, origin):
    """The Profiles tab with `name`'s editor held over a draft carrying `origin`. A
    launch does not close the editor, so a second launch reuses the same draft; only a
    closed editor is re-opened (re-opening re-reads the profile and drops a typed
    origin, spec D11). The launch keys read the held editor whichever pane is focused."""
    if not tab(ctx, "1"):
        return False
    time.sleep(UI_SETTLE)
    text = ctx.term.text()
    if f"profile {name}" in text and origin in text:
        return True
    if not open_profile(ctx, name):
        return False
    return type_origin(ctx, origin)


def type_origin(ctx, origin):
    """`o` (PromptKind::ScanOrigin), the origin, Enter."""
    ctx.term.press("o")
    if not ctx.term.wait_for(r"origin:", 8):
        return False
    ctx.term.press(origin)
    time.sleep(UI_SETTLE)
    ctx.term.press(ENTER)
    return poll(lambda: origin in ctx.term.text(), 10)


def type_l4_target(ctx, spec):
    """`t` (PromptKind::ScanL4Target), `ip:port[/tcp|udp]`, Enter."""
    ctx.term.press("t")
    if not ctx.term.wait_for(r"l4 target:", 8):
        return False
    ctx.term.press(spec)
    time.sleep(UI_SETTLE)
    ctx.term.press(ENTER)
    return poll(lambda: spec.split("/")[0] in ctx.term.text(), 10)


def launch(ctx, key, timeout=JOB_APPEAR_S):
    """Press a launch key and return the job id scan.list gained (None when none)."""
    before = job_ids(ctx.bus)
    ctx.term.press(key)
    return wait_new_job(ctx.bus, before, timeout)


def back_to_scan_list(ctx, step):
    """After the inspector: `:scan` restores the Scan view with the pane it was left on.
    The flow was opened from a Detail pane (Tab, then Enter), so that pane is focused
    and one `Esc` returns to the list (`close_pane`); should the list already be
    focused, that `Esc` leaves the view and `:scan` brings it back."""
    if not open_scan(ctx):
        return False
    ctx.term.press(ESC)
    time.sleep(UI_SETTLE)
    if SCAN_STRIP not in ctx.term.text():
        ctx.c.note(f"{step}: the list pane was already focused on re-entry (Esc left the view; reopened)")
        return open_scan(ctx)
    return True


def phases_of(samples):
    """The state/phase cells the samples carry (the empty ones dropped)."""
    return [s["screen_state_phase"] for s in samples if s["screen_state_phase"]]


# --------------------------------------------------------------------- steps


def step_seed(ctx):
    """One real GET through the proxy carrying session material: the flow the scanner
    reuses, the /search node the crawl finds, and the T7-20 secrets."""
    c = ctx.c
    url = f"{ctx.target}/search?q={ctx.marker}"
    headers = {"Cookie": f"sid={ctx.cookie_secret}",
               "Authorization": f"Bearer {ctx.auth_secret}",
               "Connection": "close"}
    try:
        resp = via_proxy(ctx.proxy_port, "GET", url, headers=headers)
    except OSError as e:
        c.fatal("seed: the GET through the proxy failed", str(e))
    body = resp.body.decode("utf-8", "replace")
    c.check("seed: GET /search answered 200 and reflected the marker",
            resp.status == 200 and ctx.marker in body, f"status {resp.status}")

    def row():
        try:
            rows = ctx.bus.call("flow.table").get("flows", [])
        except (ToolError, BusError):
            return None
        return next((r for r in rows if ctx.marker in (r.get("path") or "")), None)

    c.check("seed: the core captured the seeded flow (flow.table)",
            poll(lambda: row() is not None, 20), "no row carries the marker")
    c.check("seed: the TUI painted the seeded flow", poll(lambda: ctx.marker in ctx.term.text(), 20),
            ctx.screen("seed", "other"))


def step_t7_16(ctx):
    """T7-16 (UI-1): launch from the editor, watch the counters, cancel."""
    c, term = ctx.c, ctx.term
    if not open_scan(ctx):
        c.fatal("T7-16: `:scan` never opened the Scan view", ctx.screen("t7-16"))
    if not open_profile(ctx, "standard"):
        c.fatal("T7-16: the `standard` profile editor never opened (1, cursor, Enter)",
                ctx.screen("t7-16"))
    c.check("T7-16: `o` accepted the target origin into the editor", type_origin(ctx, ctx.origin),
            ctx.screen("t7-16"))

    job = launch(ctx, "s")
    if not job:
        c.fatal("T7-16: `s` started no job (scan.list gained no id)", ctx.screen("t7-16"))
    ctx.jobs["standard"] = job
    c.check("T7-16: scan.list reports a job id in the engine's form", bool(JOB_ID_RE.fullmatch(job)), job)
    c.check(f"T7-16: the Jobs row for {job} is on screen",
            poll(lambda: row_tail(term.text(), job) is not None, ROW_APPEAR_S), ctx.screen("t7-16"))

    samples = []
    for n in range(SAMPLES_MAX):
        before = status_of(ctx.bus, job)
        b_sent = sent_of(before)
        # The TUI polls scan.status about once a second: wait for its paint to carry a
        # value at least as fresh as the `before` read, so the bracket is a real bracket
        # (a frozen or invented number can never satisfy it; an over-large one fails the
        # upper bound below).
        caught_up = poll(lambda: (row_probes(term.text(), job) or (-1, 0))[0] >= (b_sent or 0),
                         CATCHUP_S, 0.2)
        text = ctx.snap(f"t7-16-{n}")
        after = status_of(ctx.bus, job)
        probes = row_probes(text, job)
        state = row_state(text, job)
        samples.append({"n": n, "screen_sent": None if probes is None else probes[0],
                        "screen_budget": None if probes is None else probes[1],
                        "screen_state_phase": state, "caught_up": caught_up,
                        "status_before_sent": b_sent, "status_after_sent": sent_of(after),
                        "status_before_state": before.get("state"),
                        "status_after_state": after.get("state")})
        ctx.ev.write(f"screen-T7-16-{n}.txt", text)
        if len(samples) >= SAMPLES_MIN and len(set(phases_of(samples))) > 1:
            break
        if (after.get("state") or "") in ("done", "cancelled", "failed"):
            break
        time.sleep(SAMPLE_GAP_S)
    ctx.ev.write_json("status-pairs.json", samples)

    c.check(f"T7-16: at least {SAMPLES_MIN} screen samples carry the row's probes cell",
            len([s for s in samples if s["screen_sent"] is not None]) >= SAMPLES_MIN, samples)
    seen = [s["screen_sent"] for s in samples if s["screen_sent"] is not None]
    c.check("T7-16: the on-screen `sent` is non-decreasing across the samples",
            all(a <= b for a, b in zip(seen, seen[1:])), seen)
    bracketed = [s for s in samples if s["screen_sent"] is not None
                 and s["status_before_sent"] is not None and s["status_after_sent"] is not None]
    c.check("T7-16: every sample's on-screen `sent` lies inside the scan.status bracket "
            "taken just before and just after it",
            bool(bracketed) and all(s["status_before_sent"] <= s["screen_sent"] <= s["status_after_sent"]
                                    for s in bracketed), samples)
    phases = phases_of(samples)
    c.check("T7-16: the row's state/phase text changed at least once", len(set(phases)) > 1, phases)

    term.press("x")
    cancelled = poll(lambda: "cancelled" in (row_state(term.text(), job) or ""), CANCEL_S, 0.3)
    text = ctx.snap("t7-16-cancel")
    ctx.ev.write("screen-T7-16-cancel.txt", text)
    c.check("T7-16: `x` left the row reading `cancelled`", cancelled, ctx.screen("t7-16"))
    final = wait_field(lambda: status_of(ctx.bus, job), "state", "cancelled", CANCEL_S)
    c.check("T7-16: scan.status agrees the job is `cancelled`", final.get("state") == "cancelled",
            final.get("state"))

    counts = ctx.pushes.of(job)
    c.check("T7-16: the second bus client saw a `progress` and a `cancelled` job line",
            counts.get("progress", 0) >= 1 and counts.get("cancelled", 0) >= 1, counts)


def pick_issue(ctx, job, found):
    """One poll tick of T7-17's issue search: a reflected-xss issue of `job`, else one
    whose scan.issue read carries both an evidence payload and a probe flow. Fills
    `found` (summary, full) and returns True; False while there is none yet."""
    try:
        res = ctx.bus.call("scan.issues", {"job": job, "limit": 64})
    except (ToolError, BusError) as e:
        found["error"] = str(e)
        return False
    issues = [i for i in (res.get("issues") or []) if isinstance(i, dict)]
    found["seen"] = len(issues)
    if not issues:
        return False
    xss = [i for i in issues if "reflected-xss" in f"{i.get('check_id') or ''} {i.get('class') or ''}"]
    for summary in xss + [i for i in issues if i not in xss][:8]:
        full = issue_of(ctx.bus, summary.get("id"))
        evidence = full.get("evidence") or {}
        if summary in xss or (evidence.get("payload") and evidence.get("probe_flows")):
            found["summary"], found["full"] = summary, full
            return True
    return False


def step_t7_17(ctx):
    """T7-17 (UI-2): a live issue, its evidence, a probe flow, the status round trip."""
    c, term = ctx.c, ctx.term
    for verb in ("scan.issues", "scan.issue"):
        if verb not in ctx.names:
            c.check(f"T7-17: the core offers {verb} (the ground truth this step reads)", False,
                    "absent from tools/list")
            return
    if not ensure_editor(ctx, "standard", ctx.origin):
        c.check("T7-17: the `standard` editor with the target origin was available", False,
                ctx.screen("t7-17"))
        return
    job = launch(ctx, "s")
    if not job:
        c.check("T7-17: the second `s` started a job", False, ctx.screen("t7-17"))
        return
    ctx.jobs["issues"] = job

    found = {}

    def picked():
        if pick_issue(ctx, job, found):
            return True
        # Stop early once the job has left `running`: the comparison needs a live job.
        return (status_of(ctx.bus, job).get("state") or "running") not in ("queued", "running")

    poll(picked, ISSUE_WAIT_S, 1.0)
    if "summary" not in found:
        c.check("T7-17: the running job produced a reflected-xss issue (else one with an "
                "evidence payload and a probe flow) that scan.issues reports", False,
                f"job {job} status {status_of(ctx.bus, job).get('state')}; "
                f"{found.get('seen', 0)} issues seen; {found.get('error', '')}")
        return
    summary, full = found["summary"], found["full"]
    issue_id, name = summary.get("id"), str(summary.get("name") or "")
    severity = str(summary.get("severity") or "").upper()
    # The list cuts the name column to fit the pane, so the needle is a prefix.
    needle = name[:20]

    if not tab(ctx, "4"):
        c.check("T7-17: the Issues tab drew", False, ctx.screen("t7-17"))
        return
    # `J` pins the filter to the Jobs cursor's job (D11), so the row under the cursor is
    # this job's issue and not a same-named one from the cancelled job.
    term.press("J")
    if not poll(lambda: f"job {job}" in term.text(), 10):
        c.note("T7-17: `J` did not pin the Issues filter to this job (the list may hold "
               "other jobs' issues)", job)
    shown = poll(lambda: needle in term.text(), 30)
    text = ctx.snap("t7-17-list")
    running = (status_of(ctx.bus, job) or {}).get("state")
    c.check("T7-17: the issue is on the Issues tab while scan.status still says `running`",
            shown and running == "running", f"state {running}; {ctx.ev.redact(text)[-900:]!r}")
    headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    c.check(f"T7-17: the issue sits under its `{severity}` severity header",
            group_of(text, needle, headers) == severity,
            f"group {group_of(text, needle, headers)}; {ctx.ev.redact(text)[-900:]!r}")

    c.check("T7-17: the cursor lands on the issue row", cursor_to(ctx, needle), ctx.screen("t7-17"))
    evidence = full.get("evidence") or {}
    payload = str(evidence.get("payload") or "")
    if c.check("T7-17: scan.issue reports an evidence.payload for the issue", bool(payload),
               f"class {full.get('class')!r} evidence keys {sorted(evidence)}"):
        # The detail draws the payload on one row: match its first whitespace-free run,
        # which no wrap, pad or truncation can break.
        pay_needle = next((w for w in payload.split() if w), payload)[:20]
        c.check("T7-17: the detail shows the `payload` scan.issue reports",
                poll(lambda: pay_needle in term.text(), 20),
                f"payload head {pay_needle!r}; {ctx.screen('t7-17')}")

    flows = [str(f) for f in (evidence.get("probe_flows") or [])]
    if c.check("T7-17: scan.issue reports a probe flow for the issue", bool(flows), issue_id):
        try:
            first = ctx.bus.call("flow.get", {"id": flows[0]})
        except (ToolError, BusError) as e:
            first = {}
            c.check("T7-17: flow.get read the first probe flow", False, str(e))
        method, path = str(first.get("method") or ""), str(first.get("path") or "")
        term.press("\t")
        time.sleep(UI_SETTLE)
        term.press(ENTER)
        opened = poll(lambda: inspector_open(term.text(), method, path), 15)
        ctx.ev.write("screen-T7-17-inspector.txt", ctx.snap("t7-17-inspector", "inspector"))
        c.check("T7-17: `⏎` on the first probe flow opened the inspector (Request/Response panes, "
                "the flow's method and path, the Scan strip gone)",
                opened, f"{method} {path!r}; {ctx.screen('t7-17', 'inspector')}")
        if not back_to_scan_list(ctx, "T7-17"):
            c.check("T7-17: the Scan view came back after the inspector", False, ctx.screen("t7-17"))
            return

    term.press("f")
    on_screen = poll(lambda: "false_positive" in term.text(), 20)
    after_f = wait_field(lambda: issue_of(ctx.bus, issue_id), "status", "false_positive", 20)
    ctx.ev.write("screen-T7-17.txt", ctx.snap("t7-17-false-positive"))
    c.check("T7-17: `f` marked the issue `false_positive` on screen and in scan.issue",
            on_screen and after_f.get("status") == "false_positive",
            f"scan.issue status {after_f.get('status')}; {ctx.screen('t7-17')}")

    term.press("u")
    after_u = wait_field(lambda: issue_of(ctx.bus, issue_id), "status", "open", 20)
    c.check("T7-17: `u` cleared `false_positive` from the screen and scan.issue reads `open`",
            poll(lambda: "false_positive" not in term.text(), 15) and after_u.get("status") == "open",
            f"scan.issue status {after_u.get('status')}; {ctx.screen('t7-17')}")

    poc_ref = str(full.get("poc_ref") or "").strip()
    stem = os.path.splitext(os.path.basename(poc_ref))[0] if poc_ref else ""
    term.press("P")
    answered = poll(lambda: "PoCs and runs" in term.text() or "is not in the Findings list" in term.text()
                    or "this issue has no PoC" in term.text(), 10, 0.2)
    opened = "PoCs and runs" in term.text()
    text = ctx.snap("t7-17-poc", "other" if opened else "scan")
    ctx.ev.write("screen-T7-17-poc.txt", text)
    if poc_ref:
        toast = "is not in the Findings list" in text
        c.check("T7-17: `P` opened the Findings surface on the issue's PoC",
                opened, f"poc_ref {poc_ref!r} toast {toast} answered {answered}; "
                        f"{ctx.ev.redact(text)[-900:]!r}")
        if opened:
            # The Findings list marks its selection by highlight only (ui/overlays.rs), so
            # the selected finding is read from the detail pane: its `poc <path>` line
            # names the PoC file, and its head repeats the title the list row carries.
            poc_line = re.search(r"\bpoc\s+(\S+)", text)
            selected = ((poc_line is not None and (stem in poc_line.group(1) or poc_ref in poc_line.group(1)))
                        or (bool(needle) and text.count(needle) >= 2))
            c.check("T7-17: the Findings selection is the issue's PoC (its file stem on the "
                    "detail's `poc` line, or the issue name on both list and detail)",
                    selected, f"stem {stem!r} name {needle!r}; {ctx.ev.redact(text)[-900:]!r}")
            term.press(ESC)
            time.sleep(UI_SETTLE)
            open_scan(ctx)
    else:
        c.note("T7-17: no PoC for this issue (the TUI toasted it; nothing to open)",
               "this issue has no PoC" if "no PoC" in text else text[-200:])

    cancel_quietly(ctx.bus, job)


def l4_add_args(bus, cidr, ports):
    """The l4.scope.add arguments, built from the names tools/list declares."""
    wanted = {"interface": "*", "direction": "outbound", "capability": "inject",
              "cidr": cidr, "ports": ports}
    declared = None
    try:
        tools = bus.tools()
    except (ToolError, BusError):
        tools = []
    for t in tools:
        if t.get("name") == "l4.scope.add":
            schema = t.get("inputSchema") or {}
            props = schema.get("properties") or {}
            declared = set(props.keys())
    if not declared:
        return wanted, []
    unknown = sorted(k for k in wanted if k not in declared)
    return {k: v for k, v in wanted.items() if k in declared}, unknown


def l4_entry_by_id(bus, entry_id):
    """The l4.scope.list entry carrying `entry_id`, or None (never matched by cidr)."""
    try:
        entries = bus.call("l4.scope.list", {})
    except (ToolError, BusError):
        return None
    rows = entries if isinstance(entries, list) else (entries.get("entries") or [])
    return next((e for e in rows if isinstance(e, dict) and str(e.get("id")) == entry_id), None)


def l4_remove_quietly(bus, entry_id):
    """Best-effort `l4.scope.remove` of the entry the cell added (run from `finally`)."""
    if not entry_id or entry_id == NO_L4_ID:
        return
    try:
        bus.call("l4.scope.remove", {"id": entry_id})
    except (ToolError, BusError, OSError):
        pass


def harness_scan_start(ctx):
    """What the core answers the harness for the L4 profile and target the TUI launched:
    ("job", id) or ("code", scan error code) or ("error", text)."""
    try:
        profile = ctx.bus.call("scan.profile.get", {"name": "l4-stream-safe"})
        target = profile.setdefault("target", {})
        target["l4"] = [{"ip": "127.0.0.1", "port": ctx.target_port, "proto": "tcp"}]
        res = ctx.bus.confirm("scan.start", {"profile": profile})
        job = res.get("job") if isinstance(res, dict) else None
        return ("job", job) if job else ("error", f"scan.start answered {str(res)[:120]!r} without a job")
    except (ToolError, BusError, AttributeError, TypeError) as e:
        m = SCAN_CODE_RE.search(str(e))
        return ("code", m.group(1)) if m else ("error", f"{type(e).__name__}: {e}")


def step_t7_18(ctx):
    """T7-18 (UI-3): the L4 gate, the confirm overlay, y and n."""
    c, term = ctx.c, ctx.term
    if not tab(ctx, "1"):
        c.check("T7-18: the Profiles tab drew for the L4 profile", False, ctx.screen("t7-18"))
        return
    if not focus_profiles_list(ctx) or not cursor_to(ctx, "l4-stream-safe"):
        try:
            names = [p.get("name") for p in (ctx.bus.call("scan.profile.list", {}).get("profiles") or [])]
        except (ToolError, BusError) as e:
            names = str(e)
        c.check("T7-18: the Profiles list carries l4-stream-safe", False,
                f"profiles {names}; {ctx.screen('t7-18')}")
        return
    term.press(ENTER)
    if not term.wait_for(r"profile l4-stream-safe", 15):
        c.check("T7-18: the `l4-stream-safe` editor opened", False, ctx.screen("t7-18"))
        return

    spec = f"127.0.0.1:{ctx.target_port}/tcp"
    c.check("T7-18: `t` accepted the L4 target into the editor", type_l4_target(ctx, spec),
            ctx.screen("t7-18"))
    gated = poll(lambda: "capability inject" in term.text() and "l4.scope.add" in term.text(), 20)
    ctx.ev.write("screen-T7-18-gate.txt", ctx.snap("t7-18-gate"))
    c.check("T7-18: the editor shows the D7 reason (`capability inject`, `l4.scope.add`)",
            gated, ctx.screen("t7-18"))

    before = job_ids(ctx.bus)
    term.press("s")
    time.sleep(QUIET_WINDOW_S)
    c.check(f"T7-18: `s` under the gate started nothing (scan.list unchanged for {QUIET_WINDOW_S:.0f} s)",
            job_ids(ctx.bus) == before, sorted(job_ids(ctx.bus) - before))

    args, unknown = l4_add_args(ctx.bus, "127.0.0.1/32", str(ctx.target_port))
    answer = ""
    try:
        answer = str(ctx.bus.confirm("l4.scope.add", args) or "")
    except (ToolError, BusError) as e:
        answer = f"{type(e).__name__}: {e}"
        ctx.l4_entry_id = NO_L4_ID
    else:
        ctx.l4_entry_id = answer.strip() or NO_L4_ID

    if ctx.l4_entry_id == NO_L4_ID or not poll(
            lambda: l4_entry_by_id(ctx.bus, ctx.l4_entry_id) is not None, L4_SCOPE_S, 0.4):
        c.note("T7-18: the core refused the operator-confirmed inject L4 scope entry, so the "
               "cleared-gate sub-steps (overlay, y, n) are skipped. The operator confirm "
               "path skips the agent widen gate, so a refusal here is a core bug to report",
               f"l4.scope.add answered {answer[:200]!r}; unknown args {unknown}")
        return

    cleared = poll(lambda: "L4 launch disabled" not in term.text(), GATE_CLEAR_S, 0.5)
    c.check("T7-18: the TUI's l4.scope.list pass cleared the gate", cleared, ctx.screen("t7-18"))

    before = job_ids(ctx.bus)
    term.press("s")
    overlay = poll(lambda: CONFIRM_TITLE in term.text() and "may disrupt the target" in term.text(),
                   OVERLAY_S, 0.3)
    ctx.ev.write("screen-T7-18-overlay.txt", ctx.snap("t7-18-overlay"))
    c.check("T7-18: `s` opened the wire-confirm overlay containing \"may disrupt the target\"",
            overlay, ctx.screen("t7-18"))

    # A wording already on screen before `y` does not count as its answer.
    pre_codes = set(wordings_on(term.text()))
    term.press("y")
    new_job = wait_new_job(ctx.bus, before, OVERLAY_S)
    row_shown = bool(new_job) and poll(lambda: row_tail(term.text(), new_job) is not None, ROW_APPEAR_S)
    if not new_job:
        poll(lambda: set(wordings_on(term.text())) - pre_codes, OVERLAY_S, 0.3)
    tui_codes = sorted(set(wordings_on(term.text())) - pre_codes)
    ctx.ev.write("screen-T7-18.txt", ctx.snap("t7-18-after-y"))

    # The harness asks the core the same question after `y`. The TUI's own job is
    # cancelled first so the comparison is not refused `busy` by it (one running job per
    # origin): that would be the cell's doing, not the core's answer.
    if new_job:
        cancel_quietly(ctx.bus, new_job)
        wait_field(lambda: status_of(ctx.bus, new_job), "state", "cancelled", CANCEL_S)
    kind, value = harness_scan_start(ctx)
    harness_job = value if kind == "job" else None
    if kind == "job":
        expected, agrees = "a Jobs row", row_shown
    elif kind == "code" and value in ("refused_l4", "lane_unavailable"):
        expected, agrees = f"the D9 `{REFUSAL_WORDINGS[value]}` wording", value in tui_codes
    else:
        expected, agrees = "(no sanctioned branch)", False
    c.check("T7-18: `y` re-issued the launch and the screen answered as the harness's own "
            "scan.start did (a Jobs row for a job; the D9 wording for refused_l4 / lane_unavailable)",
            agrees, f"tui job {new_job} row {row_shown} wordings {tui_codes} (pre-existing "
                    f"{sorted(pre_codes)}); harness scan.start: {kind} {value}; expected "
                    f"{expected}; {ctx.screen('t7-18')}")
    cancel_quietly(ctx.bus, harness_job)

    if not tab(ctx, "1"):
        c.check("T7-18: the Profiles tab came back for the `n` sub-step", False, ctx.screen("t7-18"))
        return
    before = job_ids(ctx.bus)
    term.press("s")
    if not poll(lambda: CONFIRM_TITLE in term.text(), OVERLAY_S, 0.3):
        c.check("T7-18: a fresh confirm prompt opened for the `n` sub-step", False, ctx.screen("t7-18"))
        return
    term.press("n")
    said = poll(lambda: "scan.start cancelled" in term.text(), 10, 0.2)
    ctx.ev.write("screen-T7-18-cancelled.txt", ctx.snap("t7-18-n"))
    time.sleep(QUIET_WINDOW_S)
    c.check("T7-18: `n` cancelled the launch (`scan.start cancelled`) and no job appeared",
            said and job_ids(ctx.bus) == before,
            f"new ids {sorted(job_ids(ctx.bus) - before)}; {ctx.screen('t7-18')}")


def step_t7_19(ctx):
    """T7-19 (UI-5): the Site map against a live scan.sitemap read."""
    c, term = ctx.c, ctx.term
    if "scan.sitemap" not in ctx.names:
        c.check("T7-19: the core offers scan.sitemap (the ground truth this step reads)", False,
                "absent from tools/list")
        return
    if not open_profile(ctx, "map-only"):
        c.check("T7-19: the `map-only` profile editor never opened", False, ctx.screen("t7-19"))
        return
    if not type_origin(ctx, ctx.origin):
        c.check("T7-19: `o` never accepted the origin for the map job", False, ctx.screen("t7-19"))
        return
    job = launch(ctx, "m")
    if not job:
        c.check("T7-19: `m` started no map job", False, ctx.screen("t7-19"))
        return
    ctx.jobs["map"] = job
    done = wait_field(lambda: status_of(ctx.bus, job), "state", "done", MAP_WAIT_S, 1.0)
    reached = done.get("state") == "done"
    c.check("T7-19: the map job reached `done`", reached, done.get("state"))
    if not reached:
        return

    try:
        live = ctx.bus.call("scan.sitemap", {"job": job})
    except (ToolError, BusError) as e:
        c.check("T7-19: scan.sitemap read the live map the screen is compared against", False, str(e))
        return
    nodes = [n for n in (live.get("nodes") or []) if isinstance(n, dict)]
    points = [p for p in (live.get("points") or []) if isinstance(p, dict)]

    if not tab(ctx, "3"):
        c.check("T7-19: the Site map tab never drew", False, ctx.screen("t7-19"))
        return
    term.press("J")  # follow the Jobs cursor's job, the one the harness reads
    c.check(f"T7-19: the Nodes pane head counts the live read's {len(nodes)} nodes",
            poll(lambda: f"{len(nodes)} nodes" in term.text(), 15), ctx.screen("t7-19"))

    # Walk the Nodes pane from the top, one row per `j`, polling for the cursor to move.
    seen_text = []
    term.press("g")
    poll(lambda: cursor_row(term.text()) is not None, 5)
    for _ in range(min(len(nodes), 60)):
        was = cursor_row(term.text())
        seen_text.append(ctx.snap("t7-19-walk"))
        term.press("j")
        poll(lambda: cursor_row(term.text()) != was, 2.0, 0.1)
    seen_text.append(ctx.snap("t7-19-walk"))
    walked = "\n".join(seen_text)
    ctx.ev.write("screen-T7-19.txt", walked[-60000:])

    missing_hosts = sorted({host_label(n) for n in nodes if host_label(n) not in walked})
    c.check("T7-19: every host of the live scan.sitemap is rendered", not missing_hosts, missing_hosts)
    missing_nodes = sorted({node_needle(n) for n in nodes if node_needle(n) not in walked})
    c.check("T7-19: every `METHOD path_template` of the live scan.sitemap is rendered",
            bool(nodes) and not missing_nodes, f"{missing_nodes}; {len(nodes)} nodes")
    # Every point of the live read, attached to a listed node or not (fix round G, G20
    # keeps the orphans on the page).
    missing_points = sorted({str(p.get("name")) for p in points if str(p.get("name"))[:16] not in walked})
    c.check("T7-19: every point name of the live scan.sitemap is rendered",
            not missing_points, f"missing {missing_points}; {len(points)} points in the live read")

    # `⏎` on the node under the cursor after `g` (the pane renders in host-group order,
    # so the first row is not necessarily the reply's first node).
    term.press("g")
    poll(lambda: cursor_row(term.text()) is not None, 5)
    under = (cursor_row(term.text()) or "").strip()
    node = next((n for n in nodes if under.startswith(node_needle(n).rstrip())), None)
    if not c.check("T7-19: the row under the cursor after `g` is a node of the live read",
                   node is not None, f"row {under!r}; {ctx.screen('t7-19')}"):
        return
    first_flows = [str(f) for f in (node.get("flows") or [])]
    if not c.check("T7-19: the node under the cursor carries a flow to open", bool(first_flows),
                   f"node {node.get('id')}"):
        return
    try:
        flow = ctx.bus.call("flow.get", {"id": first_flows[0]})
    except (ToolError, BusError) as e:
        c.check("T7-19: flow.get read the node's first flow", False, str(e))
        return
    method, path = str(flow.get("method") or ""), str(flow.get("path") or "")
    term.press(ENTER)
    opened = poll(lambda: inspector_open(term.text(), method, path), 15)
    ctx.ev.write("screen-T7-19-inspector.txt", ctx.snap("t7-19-inspector", "inspector"))
    c.check("T7-19: `⏎` on the node under the cursor opened its first flow in the inspector "
            "(Request/Response panes, the flow's method and path, the Scan strip gone)",
            opened, f"{method} {path!r}; {ctx.screen('t7-19', 'inspector')}")
    open_scan(ctx)


def step_t7_20(ctx):
    """T7-20: no seeded secret on any Scan-surface screen sample; `q` exits 0."""
    c, term = ctx.c, ctx.term
    leaks = ctx.ev.leaks("scan")
    c.check("T7-20: no Scan-surface screen sample carried the seeded Cookie or Authorization "
            f"value (whole or its first {SECRET_PREFIX} hex chars)",
            not leaks, f"{len(leaks)} of {ctx.ev.tagged('scan')} scan samples (index, tag, step): "
                       f"{leaks[:8]}; {len(ctx.ev.samples)} samples in all")
    for _ in range(4):
        term.press(ESC)
        time.sleep(0.25)
    term.press("q")
    code = term.wait_exit(EXIT_S)
    c.check("T7-20: `q` ended aitm-tui with exit 0", code == 0, f"exit {code}; {ctx.screen('t7-20', 'other')}")


def scenario(ctx):
    """The steps in order. T7-20 (no secret on screen, exit 0) runs even when an earlier
    step gave up, so the hygiene claim covers every sample taken."""
    try:
        step_seed(ctx)
        step_t7_16(ctx)
        step_t7_17(ctx)
        step_t7_18(ctx)
        step_t7_19(ctx)
    except Fatal:
        pass
    step_t7_20(ctx)


# ---------------------------------------------------------------------- main


def main():
    tui = find_tui()
    if not tui:
        skip77("no aitm-tui binary found (set AITM_TUI_BIN or `cargo build -p aitm-tui`)")

    # The secrets and the redactor exist before anything can fail, so the top-level
    # handler can redact whatever an exception carries.
    marker = "ts" + secrets.token_hex(4)
    cookie_secret = secrets.token_hex(16)
    auth_secret = secrets.token_hex(16)
    ev = Evidence([cookie_secret, auth_secret])
    try:
        return run(tui, ev, marker, cookie_secret, auth_secret)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  {type(e).__name__}: {ev.redact(str(e))}", flush=True)
        return 1


def run(tui, ev, marker, cookie_secret, auth_secret):
    booted = tgt = bus = push_client = pushes = term = ctx = None
    work = token_file = None
    try:
        if os.environ.get("AITM_BUS_ADDR"):
            bus_addr = os.environ["AITM_BUS_ADDR"].strip()
            token = (os.environ.get("AITM_BUS_OPERATOR_TOKEN") or "").strip()
            proxy = (os.environ.get("AITM_PROXY_ADDR") or "").strip()
            target = (os.environ.get("AITM_TARGET_URL") or "").strip().rstrip("/")
            if not (token and proxy and target):
                skip77("a runner core was named by AITM_BUS_ADDR but AITM_BUS_OPERATOR_TOKEN / "
                       "AITM_PROXY_ADDR / AITM_TARGET_URL are incomplete (the Scan surface is "
                       "operator-only)")
            host, port = hostport(bus_addr)
            proxy_port = int(proxy.rsplit(":", 1)[1])
        else:
            if not os.path.exists(testtarget_bin()):
                skip77("no aitm-testtarget-serve binary (build it: cargo build -p aitm-testtarget, "
                       "or set AITM_TESTTARGET_BIN)")
            work = tempfile.mkdtemp(prefix="aitm-tui-scan-run-")
            tgt = Target("vulnerable")
            # l4_enabled only: the operator confirm path skips the agent widen gate, so no
            # agent-widen flag is needed for the cell's own l4.scope.add.
            cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                             bus_port=free_port(),
                             scope_entries=[tgt.authority, "127.0.0.1"],
                             findings_dir=os.path.join(work, "findings"),
                             l4_enabled=True)
            try:
                booted = Aitm.server(cfg)
            except FileNotFoundError as e:
                skip77(f"no aitm binary to self-boot a core ({e})")
            host, port = booted.bus_addr
            token = cfg.operator_token
            proxy_port, target = cfg.proxy_port, tgt.base.rstrip("/")

        host = "127.0.0.1" if host in ("", "localhost") else host
        tui_bus = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        bus = BusClient(host, port, token, client_name="aitm-e2e-scan-witness").connect()
        names = set(bus.tool_names())
        if "scan.start" not in names:
            skip77("built, awaiting engine for live proof (scan.start is not in tools/list)")

        push_client = BusClient(host, port, token, client_name="aitm-e2e-scan-pushes").connect()
        subscribed = ""
        if "flow.subscribe" in names:
            try:
                push_client.call("flow.subscribe", {})
            except (ToolError, BusError) as e:
                subscribed = str(e)
        else:
            subscribed = "this bus has no flow.subscribe"
        pushes = Pushes(push_client)

        u = urllib.parse.urlsplit(target)
        target_port = u.port or (443 if u.scheme == "https" else 80)
        origin = f"{u.scheme}://{u.hostname}:{target_port}"

        c = Checks(ev.redact)

        work = work or tempfile.mkdtemp(prefix="aitm-tui-scan-run-")
        token_file = os.path.join(work, "bus.token")
        with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(token)
        child_env = {k: v for k, v in os.environ.items()
                     if not k.startswith("AITM_") and k not in ("RUST_LOG", "COLUMNS", "LINES")}
        child_env.update({"TERM": "xterm-256color", "HOME": work, "XDG_CONFIG_HOME": work})
        term = Terminal([tui, "--bus", tui_bus, "--token-file", token_file,
                         "--expect-role", "operator", "--ansi", "--poll", "200"], child_env)

        ctx = Ctx(c, term, bus, pushes, ev, proxy_port, target, origin, target_port, names)
        ctx.marker, ctx.cookie_secret, ctx.auth_secret = marker, cookie_secret, auth_secret

        if subscribed:
            c.note("push: the second bus client holds no flow.subscribe subscription "
                   "(the T7-16 push counts will be empty)", subscribed)
        role_rx = r"bus " + re.escape(tui_bus) + r" · (agent|operator)"
        attached = term.wait_for(role_rx, CONNECT_TIMEOUT)
        role = re.search(role_rx, term.text()).group(1) if attached else None
        c.check(f"ui: the TUI attached to bus {tui_bus} as the operator", role == "operator",
                f"role {role}; exit {term.proc.poll()}; {ev.redact(term.text())[-900:]!r}")

        scenario(ctx)

        ev.write_json("push-counts.json", pushes.snapshot())
        failed = c.failed()
        n_ok, n_noted, n_failed = c.tally()
        head = (("PASS" if not failed else "FAIL")
                + f": {n_ok} ok, {n_noted} noted, {n_failed} failed"
                + f"; aitm-tui Scan surface on bus {tui_bus}: jobs {sorted(ctx.jobs.values())}"
                + ("" if not failed else f"; failed: {failed}"))
        ev.write("summary.txt", "\n".join(c.lines() + ["", head, f"evidence dir: {ev.dir}"]) + "\n")
        print(head, flush=True)
        return 0 if not failed else 1
    finally:
        if pushes is not None:
            pushes.stop()
        if term is not None:
            term.stop()
        if token_file:
            # The operator token never outlives the run (it is never printed either).
            try:
                os.unlink(token_file)
            except OSError:
                pass
        if bus is not None and ctx is not None:
            # The L4 scope widening the cell added leaves with it (matched by its id).
            l4_remove_quietly(bus, ctx.l4_entry_id)
        if push_client is not None:
            push_client.close()
        if bus is not None:
            bus.close()
        if booted is not None:
            booted.stop()
        if tgt is not None:
            tgt.stop()
        if work:
            # The run's HOME, token file and (self-booted) findings store, which holds
            # the seeded session values raw, go with the run.
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
