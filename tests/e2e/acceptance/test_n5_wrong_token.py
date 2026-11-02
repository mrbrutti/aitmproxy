#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, negative N5 (spec §D7): a wrong operator token against the installed
app's embedded core, from the installed `aitm-tui --bus … --token-file <wrong>`.

Required words: `bus refused the token: it matched neither the agent nor the operator token
(check the token you supplied)` and the TUI stops retrying. Read-only: a refused connection
changes nothing. SKIP when the app's core is not running.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e.installed import find_embedded_core  # noqa: E402
from aitm_e2e.tui_pty import Terminal  # noqa: E402

OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/n5")
os.makedirs(OUT, exist_ok=True)
TUI = os.environ.get("AITM_TUI", "/opt/homebrew/bin/aitm-tui")
REFUSAL = "bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)"


def step(sid, result, observed="", truth="", explains=""):
    print(f"{sid:7s} {result:7s} {observed[:160]}", flush=True)
    with open(os.path.join(OUT, "negatives-steps.tsv"), "a", encoding="utf-8") as f:
        f.write("\t".join([sid, result, observed, truth, explains]) + "\n")


def main() -> int:
    core = find_embedded_core()
    if core is None:
        step("N5-TUI", "SKIP", "the app's embedded core is not running")
        return 77
    if not os.path.isfile(TUI):
        step("N5-TUI", "SKIP", f"installed aitm-tui not found at {TUI}")
        return 77
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".tok") as f:
        f.write("not-the-token\n")
        wrong = f.name
    env = dict(os.environ)
    env.setdefault("LANG", "en_US.UTF-8")
    term = Terminal([TUI, "--bus", core.bus_addr, "--token-file", wrong], env)
    try:
        seen = term.wait_for("bus refused the token", 15)
        screen = term.text()
        exact = REFUSAL in screen or REFUSAL in bytes(term.raw).decode("utf-8", "replace")
        time.sleep(2)
        still = term.proc.poll() is None
        with open(os.path.join(OUT, "N5-TUI.txt"), "w", encoding="utf-8") as fh:
            fh.write(screen)
        if seen and exact:
            step("N5-TUI", "PASS", "exact refusal sentence shown; " + ("TUI stays open with the message" if still else f"process exited {term.proc.returncode}"), f"core {core.bus_addr} refused the token line (unauthorized)")
            return 0
        step("N5-TUI", "FAIL", f"refusal seen {seen}, exact {exact}; screen head: {screen.splitlines()[0][:100] if screen else ''}")
        return 1
    finally:
        term.stop()
        os.unlink(wrong)


if __name__ == "__main__":
    sys.exit(main())
