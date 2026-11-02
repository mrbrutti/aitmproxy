"""aitm_e2e.tui_pty — drive a real terminal UI through a pty and read the screen as a grid.

Extracted from tests/e2e/tui/test_tui_flows_render.py for the release acceptance. A forked
pty has a 0×0 window, so ratatui draws nothing until TIOCSWINSZ is set: `Terminal` sets it
before the child starts. ratatui writes cell diffs with cursor moves between runs, so a naive
ANSI strip garbles words; `Screen` replays the stream into a rows×cols grid instead.
"""
from __future__ import annotations

import codecs
import fcntl
import os
import pty
import re
import signal
import struct
import subprocess
import termios
import threading
import time

TOKEN = re.compile(
    r"\x1b\[([0-?]*)[ -/]*([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][@-~]|\x1b[@-Z\\-_]|[\r\n\x08]|[^\x1b\r\n\x08]+"
)


def poll(pred, timeout: float, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


class Screen:
    """Just enough VT100 to know what is on the terminal NOW: cursor moves and erases are
    applied to a grid; colours and private modes are ignored."""

    def __init__(self, cols: int, rows: int):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.x = self.y = 0
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._pending = ""

    def feed(self, data: bytes) -> None:
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

    def _csi(self, params: str, final: str) -> None:
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

    def _erase_line(self, mode: int) -> None:
        lo, hi = {0: (self.x, self.cols), 1: (0, self.x + 1)}.get(mode, (0, self.cols))
        for i in range(lo, min(hi, self.cols)):
            self.grid[self.y][i] = " "

    def text(self) -> str:
        return "\n".join("".join(r).rstrip() for r in self.grid)

    def row(self, y: int) -> str:
        return "".join(self.grid[y]).rstrip()


class Terminal:
    """A TUI on a pty: the screen as it is now (text), keys (press), exit."""

    def __init__(self, argv: list[str], env: dict, cols: int = 180, rows: int = 45, cwd: str | None = None):
        self.screen = Screen(cols, rows)
        self._lock = threading.Lock()
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                                     start_new_session=True, cwd=cwd)
        os.close(slave)
        self.raw = bytearray()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            with self._lock:
                self.raw += chunk
                self.screen.feed(chunk)

    def text(self) -> str:
        with self._lock:
            return self.screen.text()

    def wait_for(self, pattern: str, timeout: float) -> bool:
        rx = re.compile(pattern)
        poll(lambda: rx.search(self.text()) is not None or self.proc.poll() is not None, timeout)
        return rx.search(self.text()) is not None

    def press(self, keys: str, settle: float = 0.0) -> None:
        """Write keys. A bare Esc must be written alone and followed by a pause (crossterm reads
        `ESC x` in one read as Alt+x)."""
        os.write(self.master, keys.encode("utf-8"))
        if settle:
            time.sleep(settle)

    def wait_exit(self, timeout: float):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.wait_exit(5)
        try:
            os.close(self.master)
        except OSError:
            pass
