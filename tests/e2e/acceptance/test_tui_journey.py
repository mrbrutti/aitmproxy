#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey TUI (spec §D4, negatives §D7): the INSTALLED `aitm tui` on the
operator's real HOME, driven by keystrokes in a pty, observed through the screen grid, the real
client and the durable audit (aitm tui serves no loopback bus on 0.5.10: results read
"bus truth: audit only").

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
import sys
import subprocess
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


def pgrep_lines(pattern: str) -> str:
    """`pgrep -fl` matches, or "" when there are none (exit 1 is not an error here)."""
    r = subprocess.run(["pgrep", "-fl", pattern], capture_output=True, text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""

OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/tui")
os.makedirs(OUT, exist_ok=True)
YES = yes_set()
AITM = os.environ.get("AITM", INSTALLED_CLI)
HOST = "example.com"
EXPECTED_STEPS = ("TUI-1", "TUI-2", "TUI-3", "TUI-4", "TUI-5a", "TUI-5b", "TUI-6", "TUI-7", "TUI-8", "TUI-9", "TUI-10", "N1-TUI", "N2-TUI", "N3-TUI")
NO_FLOWS = "No flows yet — point a client at 127.0.0.1:8080 or open the browser."
NO_FLOWS_GENERIC = "No flows yet — point a client at the proxy or open the browser."
TOAST_LOG = ("embedded proxy · set RUST_LOG to write a log file", "embedded proxy · log: ")
PAUSE_HINT = "[a Resume] [A Resume all] [d Kill · abort mode: reset (429/503 need F3)] [e Edit] [i Disarm]"

w = StepWriter(os.path.join(OUT, "tui-steps.tsv"), EXPECTED_STEPS)
step = w.step


def audit_since(t0_ms: int) -> list[dict]:
    return [r for r in audit_tail(400) if r.get("at", 0) >= t0_ms]


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
        ok = term.wait_for(r"aitmproxy", 30)
        screen = term.text()
        pill = next((ln for ln in screen.splitlines() if "aitmproxy" in ln and ("listening" in ln or "bus" in ln)), "")
        want = ["listening 127.0.0.1:8080", "sys-proxy", "CA trusted"]
        miss = [x for x in want if x not in screen]
        exact = NO_FLOWS in screen
        generic = NO_FLOWS_GENERIC in screen
        busbar = re.search(r"bus \S.*? · operator", screen) is not None
        toast = any(t in screen for t in TOAST_LOG)
        save("TUI-1.txt", screen)
        if ok and not miss and exact and busbar and toast:
            step("TUI-1", "PASS", f"pill: {pill.strip()[:120]}; empty state verbatim; status bar `bus … · operator`; startup toast present", "bus truth: audit only; proxy.status SKIP (no loopback bus on 0.5.10)", "claude/cli-oneshot-live-core")
        else:
            obs_line = next((ln.strip() for ln in screen.splitlines() if "No flows yet" in ln), "(no 'No flows yet' line)")
            step("TUI-1", "FAIL", f"missing {miss}; no-flows line exact {exact}" + (f" — TUI prints the generic sentence: `{obs_line}` (spec AC2 gap)" if generic else f" — observed `{obs_line[:120]}`") + f"; status bar `bus … · operator` {busbar}; startup toast {toast}; screen head: {screen.splitlines()[0][:100] if screen else '(blank: 0x0 pty?)'}")

        # TUI-2 — Scope add (words, toast, count, audit).
        term.press("S", 0.5)
        panel = term.text()
        scope_empty = "Scope is empty — every flow is dimmed and read-only. Press a to add a host." in panel
        on_panel = re.search(r"(^|\s)" + re.escape(HOST) + r"(\s|$)", panel, re.M) is not None
        pre_existing = HOST in config_scope or on_panel   # config OR surface: never remove his own host
        term.press("a", 0.3)
        prompt = term.wait_for(r"scope add:", 3)
        hint = "host · host:port · *.wildcard — a human action" in term.text()
        term.press(HOST + "\r", 0.8)
        toast = term.wait_for(r"Scope \+ " + re.escape(HOST), 5)
        added = toast and not pre_existing
        count = re.search(r" · (\d+) in scope", term.text())
        rows = audit_since(t0)
        ok_rows = [r for r in rows if r.get("command") == "scope.add" and HOST in json.dumps(r.get("args", "")) and r.get("result") == "ok"]
        listed = re.search(r"(^|\s)" + re.escape(HOST) + r"(\s|$)", term.text(), re.M) is not None
        save("TUI-2.txt", term.text())
        if prompt and hint and toast and ok_rows and listed and count:
            step("TUI-2", "PASS", f"prompt + hint shown, toast `Scope + {HOST}`, panel lists it, status bar ` · {count.group(1)} in scope`; Scope-empty words before: {scope_empty}" + (f"; the host was ALREADY in Scope before the run (config.yaml {HOST in config_scope}, panel {on_panel}; not removed at the end)" if pre_existing else ""), f"audit scope.add ok at {ok_rows[-1]['at']} (origin {ok_rows[-1].get('origin')}); bus truth: audit only")
        else:
            step("TUI-2", "FAIL", f"prompt {prompt}, hint {hint}, toast {toast}, listed {listed}, in-scope count {count.group(0) if count else None}, audit scope.add ok {len(ok_rows)}", json.dumps(rows[-3:])[:200])
        term.press("\x1b", 0.4)
        term.press("\x1b", 0.4)

        # N2 — a host in Scope, no route: the pill word and the empty pane are what is judged.
        screen = term.text()
        if "sys-proxy off" in screen and (NO_FLOWS in screen or NO_FLOWS_GENERIC in screen):
            step("N2-TUI", "PASS", "pill `· sys-proxy off`; flows pane empty state while a host is in Scope (zero rows is correct here)", "bus truth: audit only")
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
        armed = term.wait_for(r"Intercept armed — every request pauses here", 5)
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
        step("TUI-5a", "PASS" if armed and disarmed else "FAIL", f"armed bar {armed}; toast `Intercept disarmed` {disarmed}", "bus truth: audit only")

        # TUI-6 — local confirm: CA panel, i, then n.
        term.press(":", 0.3)
        term.press("ca\r", 0.6)
        term.press("i", 0.5)
        prompt = term.wait_for(r"confirm: ca\.install", 5)
        hint = "y runs it · n / Esc cancels" in term.text()
        term.press("n", 0.5)
        cancelled = term.wait_for(r"CA trust cancelled", 5)
        ca_rows = [r for r in audit_tail(50, "ca-audit.jsonl") if r.get("at", 0) >= t0 and "install" in json.dumps(r)]
        if prompt and hint and cancelled and not ca_rows:
            step("TUI-6", "PASS", "confirm prompt + hint shown; n → `CA trust cancelled`", "ca-audit.jsonl: no ca.install from this run", "PR #263 (over-the-wire _confirm) not pinned here")
        else:
            step("TUI-6", "FAIL", f"prompt {prompt}, hint {hint}, cancelled {cancelled}, ca-audit rows {len(ca_rows)}")
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
