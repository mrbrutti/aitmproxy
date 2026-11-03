#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, negatives N4 and N5 (spec §D7) while the installed app's embedded core
holds the default ports.

N5-TUI: the installed `aitm-tui --bus <app bus> --token-file <wrong>` must show
`bus refused the token: it matched neither the agent nor the operator token (check the token you
supplied)` and stop retrying. N4-TUI / N4-WEB: `aitm tui` / `aitm web` started for at most 5 s
while 8080 is held must print `cannot start: the proxy port 127.0.0.1:8080 is already in use`
(wave 1's M2 panel, `N4_PANEL`) before any screen and exit by themselves (read-only: a refused
start changes nothing; the only process touched is the child this cell started). N5-WEB is
judged by the web cell when `aitm web` runs (it owns the agent URL; spec D7 places it there), so
this cell writes no N5-WEB row. N5-CLI is CLI-6's one-shot refusal: `N/A` here (spec D1). SKIP
when the app's core is not running.
Steps → negatives-steps.tsv.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e.installed import INSTALLED_CLI, StepWriter, exit_on_term, find_embedded_core, port_holder, port_holder_pid  # noqa: E402
from aitm_e2e.tui_pty import Terminal  # noqa: E402

OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/n5")
os.makedirs(OUT, exist_ok=True)
TUI = os.environ.get("AITM_TUI", "/opt/homebrew/bin/aitm-tui")
AITM = os.environ.get("AITM", INSTALLED_CLI)
REFUSAL = "bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)"
# Wave 1's M2 panel (spec 2026-11-01-cli-terminal-reporting-design, M2 "after"): the headline has no
# trailing period, the two why sentences follow, and the holder command is the panel's `fix:` line
# on a pipe / `▸` on a TTY (0.5.10 said "in use." and "Find the holder with:"). The TTY form wraps
# the why lines at the terminal's width (80 in the spec's M2 drawing), so `N4_CHECKS` matches the
# words across any whitespace.
N4_PANEL = "cannot start: the proxy port 127.0.0.1:8080 is already in use"
N4_HOLDER_LINE = "It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program."
N4_FREE_LINE = "Free it, or set `listen:` to another address in"
N4_LSOF = "lsof -nP -iTCP:8080 -sTCP:LISTEN"
EXPECTED_STEPS = ("N5-TUI", "N5-CLI", "N4-TUI", "N4-WEB")

w = StepWriter(os.path.join(OUT, "negatives-steps.tsv"), EXPECTED_STEPS)
step = w.step


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", s)


def _words(phrase: str) -> str:
    """Regex for `phrase` with any run of whitespace between its words (the TTY form wraps)."""
    return r"\s+".join(re.escape(w) for w in phrase.split())


# The two marks that tell wave 1's panel from 0.5.10's are pinned: the headline is not followed by
# a period, and the holder command stands on the fix line (`fix: lsof …` piped, `▸ lsof …` on a TTY).
N4_CHECKS = (
    ("headline without a trailing period", re.compile(_words(N4_PANEL) + r"(?!\.)")),
    ("holder sentence", re.compile(_words(N4_HOLDER_LINE))),
    ("free-it sentence", re.compile(_words(N4_FREE_LINE))),
    ("fix line (`fix:` or `▸` + lsof)", re.compile(r"(?:fix:|▸)[ \t]+" + _words(N4_LSOF))),
)


def n4_words(text: str) -> tuple[bool, list[str]]:
    """Wave 1's port-in-use panel: the headline (no trailing period) decides; the why sentences
    and the `fix:`/`▸ lsof` line are reported when missing."""
    miss = [name for name, rx in N4_CHECKS if not rx.search(text)]
    return N4_CHECKS[0][0] not in miss, miss


def n5_tui(core) -> None:
    if not os.path.isfile(TUI):
        step("N5-TUI", "SKIP", f"installed aitm-tui not found at {TUI}")
        return
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
        else:
            step("N5-TUI", "FAIL", f"refusal seen {seen}, exact {exact}; screen head: {screen.splitlines()[0][:100] if screen else ''}")
    finally:
        term.stop()
        os.unlink(wrong)


def installed_core_holds_8080() -> tuple[bool, str, object]:
    """(True, holder text, core) only when the LISTEN holder of 8080 is the installed app's embedded
    core, by pid identity (lsof truncates COMMAND, so names are never compared). Right after MAC-13's
    Restart Core the port is free for a few seconds; an `aitm tui`/`aitm web` started then binds it
    itself, publishes a pointer naming the operator's real config and leaves the restarted core on an
    ephemeral port (0.5.18 run A: N4-TUI entered its alternate screen, N4-WEB held 8080-8082)."""
    try:
        core = find_embedded_core()
    except RuntimeError:
        core = None
    holder_pid = port_holder_pid(8080)
    holder = port_holder(8080) or "nobody"
    return (core is not None and holder_pid == core.pid), holder, core


def n4_tui() -> None:
    ok, holder, core = installed_core_holds_8080()
    if not ok:
        step("N4-TUI", "SKIP", f"8080 is not held by the installed app's core (holder: {holder}; core pid {core.pid if core else None}); not starting aitm tui against a free port")
        return
    env = dict(os.environ)
    env.setdefault("LANG", "en_US.UTF-8")
    term = Terminal([AITM, "tui"], env)
    try:
        term.wait_for(re.escape(N4_PANEL), 5)
        rc = term.wait_exit(5)
        raw = strip_ansi(bytes(term.raw).decode("utf-8", "replace"))
        with open(os.path.join(OUT, "N4-TUI.txt"), "w", encoding="utf-8") as fh:
            fh.write(raw)
        panel, miss = n4_words(raw)
        alt_screen = "\x1b[?1049h" in bytes(term.raw).decode("utf-8", "replace")
        if panel and rc not in (None, 0) and not alt_screen:
            step("N4-TUI", "PASS", f"panel before any screen, exit {rc}" + (f"; missing follow-up lines {miss}" if miss else ""), f"8080 held by {port_holder(8080)}")
        else:
            step("N4-TUI", "FAIL", f"panel {panel}; exit {rc} (None = still running after 5 s, stopped by the cell); alternate screen entered {alt_screen}; missing {miss}")
    finally:
        term.stop()


def n4_web() -> None:
    # Precondition (2026-11-03): 8080 must be held by the INSTALLED app's core. Right after MAC-13's
    # Restart Core the port is free for a few seconds; an `aitm web` started then binds 8080-8082
    # itself, publishes a pointer naming the operator's real config, and the restarted embedded core
    # falls back to an ephemeral port (0.5.18 run A). Refuse to start one against a free port.
    ok, holder, core = installed_core_holds_8080()
    if not ok:
        step("N4-WEB", "SKIP", f"8080 is not held by the installed app's core (holder: {holder}; core pid {core.pid if core else None}); not starting aitm web against a free port")
        return
    env = dict(os.environ, LANG=os.environ.get("LANG", "en_US.UTF-8"))
    proc = subprocess.Popen([AITM, "web"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        out, err = proc.communicate(timeout=5)
        rc = proc.returncode
        child_dead = True
    except subprocess.TimeoutExpired:
        # Still serving after the cap: it bound the ports. End it for certain — `aitm web` ignored
        # SIGTERM for 10 s on 0.5.18 — and never leave it holding 8080 behind the operator's app.
        proc.kill()
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        rc = None
        child_dead = proc.poll() is not None
    text = strip_ansi((out or "") + "\n" + (err or ""))
    with open(os.path.join(OUT, "N4-WEB.txt"), "w", encoding="utf-8") as fh:
        fh.write(text)
    panel, miss = n4_words(text)
    # The card is on stderr since wave 1 (G1/D13), `Web UI: http…` on a pipe: look in both streams.
    card = re.search(r"Web UI:?\s+http", text) is not None
    after_pid = port_holder_pid(8080)
    after = port_holder(8080) or "nobody"
    left_ours = after_pid is not None and after_pid != core.pid   # the child (or a survivor of it) kept the port
    if panel and rc not in (None, 0) and not card and not left_ours:
        step("N4-WEB", "PASS", f"panel, exit {rc}, no card first" + (f"; missing follow-up lines {miss}" if miss else ""), f"8080 before {holder}; after {after}")
    else:
        step("N4-WEB", "FAIL", f"panel {panel}; exit {rc} (None = still running after 5 s, killed by the cell); card printed {card}; missing {miss}; 8080 before {holder}; after {after}" + ("; a process of ours still holds 8080" if left_ours else "") + ("" if child_dead else "; the aitm web child did not die after SIGKILL"))


def main() -> int:
    exit_on_term()
    step("N5-CLI", "N/A", "the one-shot refusal is CLI-6's row (no separate step on this surface)")
    try:
        core = find_embedded_core()
    except RuntimeError as e:
        for sid in ("N5-TUI", "N4-TUI", "N4-WEB"):
            step(sid, "SKIP", str(e))
        w.finish()
        return w.exit_code()
    if core is None:
        for sid in ("N5-TUI", "N4-TUI", "N4-WEB"):
            step(sid, "SKIP", "the app's embedded core is not running (8080 not held by it)")
        w.finish()
        return w.exit_code()
    n5_tui(core)
    if not os.path.isfile(AITM):
        for sid in ("N4-TUI", "N4-WEB"):
            step(sid, "SKIP", f"installed aitm not found at {AITM}")
    else:
        n4_tui()
        n4_web()
    w.finish()
    return w.exit_code()


if __name__ == "__main__":
    sys.exit(main())
