#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey TUI (spec §D4, negatives §D7, amended 2026-11-03): the INSTALLED
`aitm tui` on the operator's real HOME, driven by keystrokes in a pty, observed through the screen
grid, the real client and the loopback operator bus `aitm tui` serves since cli-oneshot-live-core:
the one-shot CLI on the operator's default config (`aitm scope list`, `aitm proxy status`) is the
bus truth while the TUI runs. The TUI's in-process operator server is unaudited by design
(durable-audit spec, named follow-up), so audit.jsonl is read only for the system-proxy verbs.

Preconditions: the default ports are free (the app quit) — else SKIP naming the holder.
`yes` steps (TUI-3 set, TUI-7 restore the system proxy) run only when ACCEPT_YES lists them and
the bypass precondition holds (config.yaml system_proxy.bypass carries the operator's tooling);
after the flip the cell asserts `scutil --proxy` ExceptionsList carries them or restores at once.
A restore trap replays the recorded per-service state. `hand` steps (TUI-4 Safari) pause only with
AITM_E2E_MANUAL=1. The host TUI-2 adds is removed before quitting through the TUI's own
`:scope rm <host>` (the same path the Scope panel's `d` takes, but it names the host, so it can
never remove the operator's own entry) unless ACCEPT_KEEP_SCOPE=1; leftovers.txt lists it. A host
is PRE-EXISTING (never removed) when the operator's config.yaml `scope:` block lists it OR the
Scope panel shows it before the add (a late render alone must not decide). Steps that do not
exist on this surface (TUI-9/10, N1-TUI) are `N/A` (spec D1). Every screen saved beside the steps
goes through the writer's redaction. Exit 0 = all performed PASS (N/A counts as such), 77 = any
SKIP/BLOCKED, 1 = any FAIL. Steps → $ACCEPT_OUT/tui-steps.tsv.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e import is_manual, pause  # noqa: E402
from aitm_e2e.installed import (  # noqa: E402
    INSTALLED_CLI,
    StepWriter,
    append_leftover,
    audit_tail,
    bypass_applied,
    config_bypass,
    config_scope_entries,
    exit_on_term,
    keep_scope,
    port_holder,
    replay,
    scutil,
    service_state,
    sh,
    tooling_mentioned,
    yes_set,
)
from aitm_e2e.tui_pty import Terminal  # noqa: E402

OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/tui")
os.makedirs(OUT, exist_ok=True)
YES = yes_set()
AITM = os.environ.get("AITM", INSTALLED_CLI)
HOST = "example.com"
EXPECTED_STEPS = ("TUI-1", "TUI-2", "TUI-3", "TUI-4", "TUI-5a", "TUI-5b", "TUI-6", "TUI-7", "TUI-8", "TUI-9", "TUI-10", "N1-TUI", "N2-TUI", "N3-TUI")
NO_FLOWS = "No flows yet: point a client at 127.0.0.1:8080 or open the browser."
NO_FLOWS_GENERIC = "No flows yet: point a client at the proxy or open the browser."
# crates/aitm/src/tui.rs TuiLog: the startup toast's three shapes (plan Literals table).
TOAST_LOG = ("embedded proxy · log: ", "embedded proxy · log location not reported", "embedded proxy · logging disabled: could not open ")
TOAST_LOG_RX = "|".join(re.escape(t) for t in TOAST_LOG)
SUBSCRIBE_REGRESSION = "flow.subscribe failed"  # #255: the in-process transport must never call flow.subscribe
ANSI_RX = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")  # CSI sequences: a style change mid-toast must not split a substring
SCOPE_HINT = "host · host:port · *.wildcard (a human action)"
SCOPE_EMPTY = "Scope is empty: every flow is dimmed and read-only. Press a to add a host."
SIDEBAR_SCOPE_RX = re.compile(r"^\s*Scope\s+(\d+)", re.M)  # the host count; the status bar's ` · N in scope` counts flows
ARMED_BAR_RX = r"Intercept armed: every request pauses here"
ARMED_PILL = " · intercept armed"  # the toolbar pill's word while armed (`… · CA trusted · intercept armed`)
CA_HINT = "y runs it · n / Esc cancels"
PAUSE_HINT = "[a Resume] [A Resume all] [d Kill · abort mode: reset (429/503 need F3)] [e Edit] [i Disarm]"

w = StepWriter(os.path.join(OUT, "tui-steps.tsv"), EXPECTED_STEPS)
step = w.step


def pgrep_lines(pattern: str) -> str:
    """`pgrep -fl` matches for a literal command line: "" when there are none (exit 1), the
    matches on exit 0, and a `[pgrep error …]` marker on any other exit so a tool failure is
    never read as "nothing left"."""
    r = subprocess.run(["pgrep", "-fl", re.escape(pattern)], capture_output=True, text=True, check=False)
    if r.returncode == 0:
        return r.stdout.strip()
    if r.returncode == 1:
        return ""
    return f"[pgrep error {r.returncode}: {r.stderr.strip()[:80]}]"


def plain_raw(term: Terminal) -> str:
    """Everything the TUI ever wrote, CSI styling stripped: a substring search here catches a toast
    even after it cleared, and even when a style change was emitted in the middle of its words."""
    return ANSI_RX.sub("", bytes(term.raw).decode("utf-8", "replace"))


def armed_flag(st: object) -> bool | None:
    """`intercept_armed` from an `aitm proxy status` object; None when the verb gave no object."""
    return st.get("intercept_armed") if isinstance(st, dict) else None


def audit_since(t0_ms: int) -> list[dict]:
    return [r for r in audit_tail(400) if r.get("at", 0) >= t0_ms]


def oneshot_json(*args: str) -> tuple[object | None, str]:
    """`aitm <args>` as a one-shot verb on the operator's default config while `aitm tui` serves the
    loopback bus: (parsed stdout JSON, note). The value is None on a non-zero exit, a timeout or
    unparsable stdout; the note carries the exit and the first 120 chars of stderr (never stdout,
    which could carry a token) so the step detail says why."""
    try:
        r = subprocess.run([AITM, *args], capture_output=True, text=True, timeout=40, check=False)
    except subprocess.TimeoutExpired:
        return None, f"aitm {' '.join(args)}: timeout 40s"
    err = r.stderr.strip().replace("\n", " ")[:120]
    if r.returncode != 0:
        return None, f"aitm {' '.join(args)}: exit {r.returncode} {err}".strip()
    try:
        return json.loads(r.stdout), f"aitm {' '.join(args)}: exit 0"
    except ValueError:
        return None, f"aitm {' '.join(args)}: exit 0, stdout not JSON ({len(r.stdout)} bytes) {err}".strip()


def save(name: str, text: str) -> None:
    """A screen beside the steps, through the writer's redaction (no secret value, no `#t=`)."""
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(w.redact(text))


def na_rows() -> None:
    step("TUI-9", "N/A", "no All Apps control on this surface", "", "UIs pending (per-host decryption decision)")
    step("TUI-10", "N/A", "no Apps view on this surface on 0.5.10")
    step("N1-TUI", "N/A", "aitm tui owns its core on 0.5.10; the app's restart is seen only from aitm-tui --bus")
    step("N3-TUI", "SKIP", "CA stays trusted (un-trusting is Matt's yes; words read from source)")


def main() -> int:  # noqa: C901 — one journey, in the operator's order
    exit_on_term()
    if not os.path.isfile(AITM):
        step("TUI-1", "SKIP", f"installed aitm not found at {AITM}")
        na_rows()
        w.finish()
        return w.exit_code()
    for port in (8080, 8081, 8082):
        h = port_holder(port)
        if h:
            for sid in ("TUI-1", "TUI-2", "TUI-3", "TUI-4", "TUI-5a", "TUI-5b", "TUI-6", "TUI-7", "TUI-8", "N2-TUI"):
                step(sid, "SKIP", f"port {port} held by {h}; aitm tui needs the default ports (quit the app first)")
            na_rows()
            w.finish()
            return w.exit_code()

    before_scutil, before_svc = scutil(), service_state()
    config_scope = config_scope_entries()  # his persisted hosts: pre-existing whatever the panel has rendered so far
    t0 = int(time.time() * 1000)
    env = dict(os.environ)
    env.pop("AITM_AUDIT_LOG", None)
    env.setdefault("LANG", "en_US.UTF-8")
    term = Terminal([AITM, "tui"], env)
    armed_set = False
    added = False
    pre_existing = False
    cleaned = False

    def remove_added_host() -> None:
        nonlocal cleaned
        if cleaned or not added:
            return
        cleaned = True
        if keep_scope():
            append_leftover(OUT, HOST, "kept", "tui")
            return
        term.press(":", 0.3)
        term.press(f"scope rm {HOST}\r", 0.6)
        gone = term.wait_for(r"removed " + re.escape(HOST), 5)
        append_leftover(OUT, HOST, "removed" if gone else "failed", "tui")

    try:
        # TUI-1 — the screen, the pill, the status bar, the toast, the empty state (verbatim).
        # The startup checklist card prints `aitmproxy` 0.26 s in, before ratatui draws: wait
        # for the frame (the flows pane's empty state), then the status bar, then the toast.
        ok = term.wait_for(r"No flows yet", 30)
        busbar = term.wait_for(r"bus \S.*? · operator", 5)
        toast = term.wait_for(TOAST_LOG_RX, 6)
        screen = term.text()
        regression = SUBSCRIBE_REGRESSION in plain_raw(term)
        pill = next((ln for ln in screen.splitlines() if "aitmproxy" in ln and ("listening" in ln or "bus" in ln)), "")
        # The toolbar pills (`sys-proxy …`, `CA trusted`) are drawn on the first bus tick, after the
        # frame and the status bar; wait for them instead of reading the first screen (0.5.18 run B).
        for pill_word in ("sys-proxy", "CA trusted"):
            term.wait_for(re.escape(pill_word), 5)
        screen = term.text()
        want = ["listening 127.0.0.1:8080", "sys-proxy", "CA trusted"]
        miss = [x for x in want if x not in screen]
        exact = NO_FLOWS in screen
        generic = NO_FLOWS_GENERIC in screen
        save("TUI-1.txt", screen)
        if ok and not miss and exact and busbar and toast and not regression:
            step("TUI-1", "PASS", f"pill: {pill.strip()[:120]}; empty state verbatim; status bar `bus … · operator`; startup toast present; no `{SUBSCRIBE_REGRESSION}`", "bus truth: one-shot CLI (TUI-2, TUI-5a read it)", "claude/cli-oneshot-live-core")
        else:
            obs_line = next((ln.strip() for ln in screen.splitlines() if "No flows yet" in ln), "(no 'No flows yet' line)")
            step("TUI-1", "FAIL", f"frame {ok}; missing {miss}; no-flows line exact {exact}" + (f" — TUI prints the generic sentence: `{obs_line}` (spec AC2 gap)" if generic else f" — observed `{obs_line[:120]}`") + f"; status bar `bus … · operator` {busbar}; startup toast {toast}" + (f"; `{SUBSCRIBE_REGRESSION}` drawn: the in-process transport called flow.subscribe (#255 regression, plan 2026-11-03 Task 1)" if regression else "") + f"; screen head: {screen.splitlines()[0][:100] if screen else '(blank: 0x0 pty?)'}")

        # TUI-2 — Scope add (words, toast, sidebar count, one-shot `aitm scope list`).
        term.press("S", 0.5)
        panel = term.text()
        scope_empty = SCOPE_EMPTY in panel
        on_panel = re.search(r"(^|\s)" + re.escape(HOST) + r"(\s|$)", panel, re.M) is not None
        pre_existing = HOST in config_scope or on_panel   # config OR surface: never remove his own host
        term.press("a", 0.3)
        prompt = term.wait_for(r"scope add:", 3)
        hint = SCOPE_HINT in term.text()
        term.press(HOST + "\r", 0.8)
        toast = term.wait_for(r"Scope \+ " + re.escape(HOST), 5)
        added = toast and not pre_existing
        listed = re.search(r"(^|\s)" + re.escape(HOST) + r"(\s|$)", term.text(), re.M) is not None
        save("TUI-2.txt", term.text())
        # No audit grep: the TUI's in-process operator server is unaudited by design (durable-audit
        # spec, "stays unaudited (Architect's call)", named follow-up); the one-shot CLI is the truth.
        scope_list, scope_note = oneshot_json("scope", "list")
        on_bus = isinstance(scope_list, list) and HOST in scope_list
        # The status bar's ` · N in scope` counts flows, not hosts; it is hidden under the toast for
        # ~4 s and only recorded. The host count is the sidebar's `Scope N` row.
        term.press("\x1b", 0.4)
        term.wait_for(r" · \d+ in scope", 8)
        after = term.text()
        count = re.search(r" · (\d+) in scope", after)
        side = SIDEBAR_SCOPE_RX.search(after)
        side_n = int(side.group(1)) if side else 0
        # A fresh scope reads `Scope 1`; a pre-existing host (his own entry) legitimately raises it.
        side_ok = side_n == 1 or (pre_existing and side_n >= 1)
        if prompt and hint and toast and listed and on_bus and side_ok:
            step("TUI-2", "PASS", f"prompt + hint shown, toast `Scope + {HOST}`, panel lists it, sidebar `Scope {side_n}`, status bar ` · {count.group(1) if count else '?'} in scope` (flows; recorded); Scope-empty words before: {scope_empty}" + (f"; the host was ALREADY in Scope before the run (config.yaml {HOST in config_scope}, panel {on_panel}; not removed at the end)" if pre_existing else ""), f"aitm scope list contains {HOST} ({len(scope_list)} hosts); bus truth: one-shot CLI")
        else:
            step("TUI-2", "FAIL", f"prompt {prompt}, hint {hint}, toast {toast}, listed {listed}, sidebar `Scope {side_n}` (row {side.group(0).strip() if side else None}; want 1, or >= 1 for a pre-existing host), status bar {count.group(0) if count else None}, aitm scope list has host {on_bus}", scope_note[:200])
        term.press("\x1b", 0.4)

        # N2 — a host in Scope, no route: the pill word and the empty pane are what is judged.
        screen = term.text()
        if "sys-proxy off" in screen and (NO_FLOWS in screen or NO_FLOWS_GENERIC in screen):
            step("N2-TUI", "PASS", "pill `· sys-proxy off`; flows pane empty state while a host is in Scope (zero rows is correct here)", "bus truth: one-shot CLI (TUI-2's aitm scope list)")
        elif "sys-proxy off" not in screen:
            pill_word = re.search(r"sys-proxy [^·\n]*", screen)
            step("N2-TUI", "SKIP", f"not the N2 state: pill shows `{pill_word.group(0).strip() if pill_word else '(no sys-proxy word)'}`")
        else:
            step("N2-TUI", "FAIL", "pill `· sys-proxy off` but the flows pane does not show the empty-state sentence")

        # TUI-3 — set the system proxy (yes).
        if "TUI-3" not in YES:
            step("TUI-3", "SKIP", "needs Matt's yes (ACCEPT_YES=TUI-3)")
        else:
            byp = config_bypass()
            if not tooling_mentioned(byp):
                step("TUI-3", "SKIP", f"bypass list absent in config.yaml system_proxy.bypass ({byp or 'none'}); add it through the surface's Settings first")
            else:
                print(f"== window TUI-3 start {time.strftime('%H:%M:%S')}", flush=True)
                term.press("s", 0.5)
                setting = term.wait_for(r"sys-proxy (setting…|→ us)", 5)
                us = term.wait_for(r"sys-proxy → us", 15)
                armed_set = True
                sc = scutil()
                applied = bypass_applied(sc)
                n_set = len([r for r in audit_since(t0) if r.get("command") == "proxy.system.set"])
                if us and "HTTPEnable : 1" in sc and "HTTPPort : 8080" in sc and applied:
                    step("TUI-3", "PASS", f"pill → `sys-proxy → us` (setting… seen: {setting})", f"scutil: HTTPEnable 1, 8080, ExceptionsList carries the tooling; audit proxy.system.set {n_set}; bus truth: audit only")
                elif not applied:
                    term.press("s", 0.5)
                    off = term.wait_for(r"sys-proxy (off|→ 127\.0\.0\.1:\d+)", 15)
                    armed_set = scutil() != before_scutil
                    step("TUI-3", "FAIL", f"bypass not applied: ExceptionsList lacks the tooling hosts after the flip; restored at once (pill off {off}, scutil identical {not armed_set})", sc[:200])
                else:
                    step("TUI-3", "FAIL", f"us={us} scutil has 8080: {'HTTPPort : 8080' in sc}", sc[:200])
                print(f"== window TUI-3 end {time.strftime('%H:%M:%S')}", flush=True)

        # TUI-4 — real browser rows (hand).
        if w.results.get("TUI-3") != "PASS":
            step("TUI-4", "BLOCKED", "TUI-3 did not set the route")
        elif not is_manual():
            step("TUI-4", "SKIP", "needs a hand: Safari visits http://example.com/ and https://httpbin.org/get (--manual)")
        else:
            pause(f"In Safari open http://{HOST}/ then https://httpbin.org/get, then press Enter here")
            seen = term.wait_for(r"GET\s+" + re.escape(HOST), 15)
            httpbin_get = term.wait_for(r"GET\s+httpbin\.org", 15)
            save("TUI-4.txt", term.text())
            step("TUI-4", "PASS" if seen and httpbin_get else "FAIL", f"rows: example {seen}, httpbin GET {httpbin_get} (a CONNECT-only row = passthrough)", "real client loaded the pages; audit no error; bus truth: audit only")

        # TUI-5a — arm / disarm; TUI-5b — park / resume (needs a route and a hand).
        term.press("i", 0.5)
        armed = term.wait_for(ARMED_BAR_RX, 5)
        pill_armed = ARMED_PILL in term.text()
        save("TUI-5a-armed.txt", term.text())
        st_armed, note_armed = oneshot_json("proxy", "status")
        bus_armed = armed_flag(st_armed) is True
        if w.results.get("TUI-4") == "PASS" and is_manual():
            pause("Reload http://example.com/ in Safari, then press Enter here")
            parked = term.wait_for(r"1 paused\s+GET http://example\.com/", 15)
            hint_ok = PAUSE_HINT in term.text()
            save("TUI-5b.txt", term.text())
            term.press("a", 0.5)
            resumed = term.wait_for(r"Resumed", 5)
            step("TUI-5b", "PASS" if parked and hint_ok and resumed else "FAIL", f"parked `1 paused  GET http://example.com/` {parked}; hint {hint_ok}; toast Resumed {resumed}", "bus truth: audit only")
        else:
            step("TUI-5b", "BLOCKED", "TUI-3" if w.results.get("TUI-3") != "PASS" else "TUI-4", "no route / no hand: park and resume cannot be judged")
        term.press("i", 0.5)
        disarmed = term.wait_for(r"Intercept disarmed", 5)
        st_off, note_off = oneshot_json("proxy", "status")
        bus_disarmed = armed_flag(st_off) is False
        ok_5a = armed and pill_armed and disarmed and bus_armed and bus_disarmed
        detail_5a = (
            f"armed bar {armed}; pill `{ARMED_PILL.strip()}` {pill_armed}; toast `Intercept disarmed` {disarmed}; "
            f"aitm proxy status intercept_armed after arm {armed_flag(st_armed)}, after disarm {armed_flag(st_off)}"
        )
        step("TUI-5a", "PASS" if ok_5a else "FAIL", detail_5a, f"bus truth: one-shot CLI ({note_armed}; {note_off})")

        # TUI-6 — local confirm: CA panel, i, then n.
        term.press(":", 0.3)
        term.press("ca\r", 0.6)
        term.press("i", 0.5)
        prompt = term.wait_for(r"confirm: ca\.install", 5)
        # The hint is observed, not asserted: ca.install's long description pushes `[y/N]` and the
        # hint off a 180-column prompt row (bars.rs::prompt drops the hint when it does not fit).
        hint = CA_HINT in term.text()
        term.press("n", 0.5)
        # The local `n` toasts `<call> cancelled` (app.rs answer_confirm); `CA trust cancelled` is
        # the toast for a `ca.install cancelled` error from the OS dialog (system-proxy spec D17.11).
        cancelled = term.wait_for(r"ca\.install cancelled", 5)
        ca_rows = [r for r in audit_tail(50, "ca-audit.jsonl") if r.get("at", 0) >= t0 and "install" in json.dumps(r)]
        if prompt and cancelled and not ca_rows:
            step("TUI-6", "PASS", f"confirm prompt `confirm: ca.install` shown; hint `{CA_HINT}` visible {hint} (not required: clipped at 180 cols); n → `ca.install cancelled`", "ca-audit.jsonl: no ca.install from this run", "PR #263 (over-the-wire _confirm) not pinned here")
        else:
            step("TUI-6", "FAIL", f"prompt {prompt}, hint {hint} (not required), cancelled {cancelled}, ca-audit rows {len(ca_rows)}")
        term.press("\x1b", 0.4)
        term.press("\x1b", 0.4)

        # TUI-7 — restore (yes; only if TUI-3 set it) — mirrors MAC-15.
        if not armed_set:
            step("TUI-7", "SKIP", "nothing to restore (TUI-3 did not set it)")
        elif "TUI-7" not in YES:
            step("TUI-7", "SKIP", "needs Matt's yes (ACCEPT_YES=TUI-7) — the trap will restore")
        else:
            term.press("s", 0.5)
            off = term.wait_for(r"sys-proxy (off|→ 127\.0\.0\.1:\d+)", 15)
            after = scutil()
            n_unset = len([r for r in audit_since(t0) if r.get("command") == "proxy.system.unset"])
            if off and after == before_scutil:
                step("TUI-7", "PASS", "pill back to the before word; scutil identical", f"audit proxy.system.unset {n_unset}; bus truth: audit only")
                armed_set = False
            else:
                step("TUI-7", "FAIL", f"pill off {off}; scutil identical {after == before_scutil}")

        # Scope cleanup through the TUI itself, then TUI-8 — quit.
        remove_added_host()
        term.press("q")
        rc = term.wait_exit(10)
        after = scutil()
        # `pgrep` exits 1 with nothing on either stream when no process matches; `sh()` would
        # render that exit as a `[stderr]` marker and fail the step with nothing left behind.
        # The pattern is the literal command line (`re.escape`); a pgrep error is reported, not
        # folded into "nothing left".
        left = pgrep_lines(f"{AITM} tui")
        if rc == 0 and after == before_scutil and not left:
            step("TUI-8", "PASS", "exit 0, no child left, scutil unchanged", "audit: last entries from this pid")
        else:
            step("TUI-8", "FAIL", f"exit {rc}, leftover `{left[:60]}`, scutil identical {after == before_scutil}")
        na_rows()
    finally:
        if added and not cleaned and term.proc.poll() is None:
            try:
                remove_added_host()
            except Exception:  # noqa: BLE001
                append_leftover(OUT, HOST, "failed", "tui")
        elif added and not cleaned:
            append_leftover(OUT, HOST, "failed (tui exited first)", "tui")
        term.stop()
        if armed_set:
            print("== restore trap: TUI-3 set the system proxy and TUI-7 did not restore it; replaying the recorded per-service state", flush=True)
            errs = replay(before_svc)
            same = scutil() == before_scutil
            step("RESTORE", "PASS" if same and not errs else "FAIL", f"replayed recorded state; identical {same}; errors {errs}")
        elif scutil() != before_scutil:
            step("DRIFT", "FAIL", "the system proxy changed during the run by another actor; the harness set nothing and touched nothing — left as is", scutil()[:200])
        save("tui-raw.txt", bytes(term.raw).decode("utf-8", "replace"))
        w.finish()
    return w.exit_code()


if __name__ == "__main__":
    sys.exit(main())
