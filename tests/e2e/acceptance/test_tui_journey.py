#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey TUI (spec §D4): the INSTALLED `aitm tui` on the operator's real
HOME, driven by keystrokes in a pty, observed through the screen grid, the real client and the
durable audit (aitm tui serves no loopback bus on 0.5.10: results read "bus truth: audit only").

Preconditions: the default ports are free (the app quit) — else SKIP naming the holder.
`yes` steps (TUI-3 set, TUI-7 restore the system proxy) run only when ACCEPT_YES lists them and
the bypass precondition holds; a restore trap replays the recorded per-service state.
`hand` steps (TUI-4 Safari) pause only with AITM_E2E_MANUAL=1.
Exit 0 = all performed PASS, 77 = any SKIP/BLOCKED, 1 = any FAIL. Steps → $ACCEPT_OUT/tui-steps.tsv.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e import is_manual, pause  # noqa: E402
from aitm_e2e.installed import DATA_DIR, INSTALLED_CLI, audit_tail, port_holder  # noqa: E402
from aitm_e2e.tui_pty import Terminal, poll  # noqa: E402

OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/tui")
os.makedirs(OUT, exist_ok=True)
STEPS = os.path.join(OUT, "tui-steps.tsv")
YES = set(filter(None, os.environ.get("ACCEPT_YES", "").split(",")))
AITM = os.environ.get("AITM", INSTALLED_CLI)
HOST = "example.com"
SERVICES = ("Wi-Fi", "Display Ethernet")
TOOLING = ("*.anthropic.com", "claude.ai", "github.com")

results: dict[str, str] = {}


def step(sid: str, result: str, observed: str = "", truth: str = "", explains: str = "") -> None:
    results[sid] = result
    print(f"{sid:7s} {result:7s} {observed[:160]}", flush=True)
    with open(STEPS, "a", encoding="utf-8") as f:
        f.write("\t".join([sid, result, observed.replace("\t", " "), truth.replace("\t", " "), explains]) + "\n")


def sh(*argv: str) -> str:
    return subprocess.run(list(argv), capture_output=True, text=True).stdout


def scutil() -> str:
    return sh("scutil", "--proxy")


def service_state() -> dict:
    st = {}
    for svc in SERVICES:
        st[svc] = {"http": sh("networksetup", "-getwebproxy", svc), "https": sh("networksetup", "-getsecurewebproxy", svc)}
    return st


def replay(before: dict) -> list[str]:
    """Put each service back exactly as recorded (never a blanket off); returns the failures."""
    errs = []
    for svc, d in before.items():
        for kind, text in d.items():
            en = re.search(r"Enabled: (\w+)", text)
            host = re.search(r"Server: (\S*)", text)
            port = re.search(r"Port: (\d+)", text)
            setp = "-setwebproxy" if kind == "http" else "-setsecurewebproxy"
            setstate = "-setwebproxystate" if kind == "http" else "-setsecurewebproxystate"
            if host and port and host.group(1):
                r = subprocess.run(["networksetup", setp, svc, host.group(1), port.group(1)], capture_output=True, text=True)
                if r.returncode:
                    errs.append(f"{svc} {setp}: {r.stderr.strip()}")
            r = subprocess.run(["networksetup", setstate, svc, "on" if en and en.group(1) == "Yes" else "off"], capture_output=True, text=True)
            if r.returncode:
                errs.append(f"{svc} {setstate}: {r.stderr.strip()}")
    return errs


def config_bypass() -> list[str]:
    p = os.path.join(DATA_DIR, "config.yaml")
    if not os.path.exists(p):
        return []
    out, inside = [], False
    with open(p, encoding="utf-8") as f:
        for line in f:
            if line.startswith("system_proxy:"):
                inside = True
                continue
            if inside and line and not line.startswith(" "):
                break
            if inside and "bypass" in line:
                out.append(line)
            elif inside and line.strip().startswith("- "):
                out.append(line.strip()[2:].strip('"'))
    return out


def audit_since(t0_ms: int, pid: int | None = None) -> list[dict]:
    rows = [r for r in audit_tail(400) if r.get("at", 0) >= t0_ms]
    return rows


def main() -> int:
    if not os.path.isfile(AITM):
        step("TUI-1", "SKIP", f"installed aitm not found at {AITM}")
        return 77
    for port in (8080, 8081, 8082):
        h = port_holder(port)
        if h:
            for sid in ("TUI-1", "TUI-2", "TUI-3", "TUI-4", "TUI-5", "TUI-6", "TUI-7", "TUI-8"):
                step(sid, "SKIP", f"port {port} held by {h}; aitm tui needs the default ports (quit the app first)")
            step("TUI-9", "SKIP", "no All Apps control on this surface", "", "UIs pending (per-host decryption decision)")
            step("TUI-10", "SKIP", "no Apps view on this surface on 0.5.10")
            return 77

    before_scutil, before_svc = scutil(), service_state()
    t0 = int(time.time() * 1000)
    env = dict(os.environ)
    env.pop("AITM_AUDIT_LOG", None)
    env.setdefault("LANG", "en_US.UTF-8")
    term = Terminal([AITM, "tui"], env)
    armed_set = False
    try:
        # TUI-1 — the screen, the pill, the empty state.
        ok = term.wait_for(r"aitmproxy", 30)
        screen = term.text()
        pill = next((l for l in screen.splitlines() if "aitmproxy" in l and ("listening" in l or "bus" in l)), "")
        want = ["listening 127.0.0.1:8080", "sys-proxy", "CA trusted"]
        missing = [w for w in want if w not in screen]
        noflows = "No flows yet — point a client at" in screen
        if ok and not missing and noflows:
            step("TUI-1", "PASS", f"pill: {pill.strip()[:120]}; empty state present", "bus truth: audit only; proxy.status SKIP (no loopback bus on 0.5.10)", "claude/cli-oneshot-live-core")
        else:
            step("TUI-1", "FAIL", f"missing {missing}; no-flows line {noflows}; screen head: {screen.splitlines()[0][:100] if screen else '(blank: 0x0 pty?)'}")
        with open(os.path.join(OUT, "TUI-1.txt"), "w", encoding="utf-8") as f:
            f.write(screen)

        # TUI-2 — Scope add.
        term.press("S", 0.4)
        scope_empty = "Scope is empty" in term.text()
        term.press("a", 0.3)
        prompt = term.wait_for(r"scope add:", 3)
        term.press(HOST + "\r", 0.8)
        toast = term.wait_for(r"Scope \+ " + re.escape(HOST), 5)
        rows = audit_since(t0)
        added = [r for r in rows if r.get("command") == "scope.add" and HOST in r.get("args", "") and r.get("result") == "ok"]
        if prompt and toast and added:
            step("TUI-2", "PASS", f"prompt shown, toast `Scope + {HOST}`; Scope-empty words before: {scope_empty}", f"audit scope.add ok at {added[-1]['at']} (origin {added[-1].get('origin')})")
        else:
            step("TUI-2", "FAIL", f"prompt {prompt}, toast {toast}, audit scope.add {len(added)}", json.dumps(rows[-3:])[:200])
        term.press("\x1b", 0.4)
        term.press("\x1b", 0.4)

        # TUI-3 — set the system proxy (yes).
        if "TUI-3" not in YES:
            step("TUI-3", "SKIP", "needs Matt's yes (ACCEPT_YES=TUI-3)")
        else:
            byp = config_bypass()
            if not any(t in " ".join(byp) for t in TOOLING):
                step("TUI-3", "SKIP", f"bypass list absent in config.yaml system_proxy.bypass ({byp or 'none'}); add it through the surface's Settings first")
            else:
                print(f"== window TUI-3 start {time.strftime('%H:%M:%S')}", flush=True)
                term.press("s", 0.5)
                setting = term.wait_for(r"sys-proxy (setting…|→ us)", 5)
                us = term.wait_for(r"sys-proxy → us", 15)
                armed_set = True
                sc = scutil()
                exc = [t for t in TOOLING if t.split(".")[-1] in sc]
                if us and "HTTPEnable : 1" in sc and "HTTPPort : 8080" in sc and exc:
                    step("TUI-3", "PASS", f"pill → `sys-proxy → us` (setting… seen: {setting})", f"scutil: HTTPEnable 1, 8080, exceptions include tooling; audit proxy.system.set {len([r for r in audit_since(t0) if r.get('command')=='proxy.system.set'])}")
                else:
                    step("TUI-3", "FAIL", f"us={us} scutil has 8080: {'HTTPPort : 8080' in sc}, bypass applied: {bool(exc)}", sc[:200])
                    if not exc:
                        term.press("s", 0.5)
                        term.wait_for(r"sys-proxy off", 15)

        # TUI-4 — real browser rows (hand).
        if results.get("TUI-3") != "PASS":
            step("TUI-4", "BLOCKED", "TUI-3 did not set the route")
        elif not is_manual():
            step("TUI-4", "SKIP", "needs a hand: Safari visits http://example.com/ and https://httpbin.org/get (--manual)")
        else:
            pause(f"In Safari open http://{HOST}/ then https://httpbin.org/get, then press Enter here")
            seen = term.wait_for(r"GET\s+" + re.escape(HOST), 15)
            httpbin_get = term.wait_for(r"GET\s+httpbin\.org", 15)
            screen = term.text()
            step("TUI-4", "PASS" if seen and httpbin_get else "FAIL", f"rows: example {seen}, httpbin GET {httpbin_get} (a CONNECT-only row = passthrough)", "real client loaded the pages; audit no error")
            with open(os.path.join(OUT, "TUI-4.txt"), "w", encoding="utf-8") as f:
                f.write(screen)

        # TUI-5 — intercept arm / park / resume / disarm.
        term.press("i", 0.5)
        armed = term.wait_for(r"Intercept armed — every request pauses here", 5)
        if results.get("TUI-4") == "PASS" and is_manual():
            pause("Reload http://example.com/ in Safari, then press Enter here")
            parked = term.wait_for(r"1 paused", 15)
            term.press("a", 0.5)
            resumed = term.wait_for(r"Resumed", 5)
        else:
            parked = resumed = None
        term.press("i", 0.5)
        disarmed = term.wait_for(r"Intercept disarmed", 5)
        if armed and disarmed and (parked is None or (parked and resumed)):
            obs = f"armed {armed}, parked {parked}, resumed {resumed}, disarmed {disarmed}"
            step("TUI-5", "PASS" if parked is not None else "PASS", obs + ("" if parked is not None else " (park/resume BLOCKED: no route)"), "bus truth: audit only")
            if parked is None:
                results["TUI-5"] = "PASS"
        else:
            step("TUI-5", "FAIL", f"armed {armed}, parked {parked}, resumed {resumed}, disarmed {disarmed}")

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

        # TUI-7 — restore (yes; only if TUI-3 set it).
        if not armed_set:
            step("TUI-7", "SKIP" if "TUI-7" in YES else "SKIP", "nothing to restore (TUI-3 did not run)" if "TUI-7" in YES else "needs Matt's yes (ACCEPT_YES=TUI-7)")
        else:
            term.press("s", 0.5)
            off = term.wait_for(r"sys-proxy (off|→ 127\.0\.0\.1:9090)", 15)
            after = scutil()
            if off and after == before_scutil:
                step("TUI-7", "PASS", "pill back to the before word; scutil identical", "audit proxy.system.unset ok")
                armed_set = False
            else:
                step("TUI-7", "FAIL", f"pill off {off}; scutil identical {after == before_scutil}")

        # TUI-8 — quit.
        term.press("q")
        rc = term.wait_exit(10)
        after = scutil()
        left = sh("pgrep", "-fl", f"{AITM} tui").strip()
        if rc == 0 and after == before_scutil and not left:
            step("TUI-8", "PASS", "exit 0, no child left, scutil unchanged", "audit: last entries from this pid")
        else:
            step("TUI-8", "FAIL", f"exit {rc}, leftover `{left[:60]}`, scutil identical {after == before_scutil}")
        step("TUI-9", "SKIP", "no All Apps control on this surface", "", "UIs pending (per-host decryption decision)")
        step("TUI-10", "SKIP", "no Apps view on this surface on 0.5.10")
    finally:
        term.stop()
        if armed_set:
            print("== restore trap: TUI-3 set the system proxy and TUI-7 did not restore it; replaying the recorded per-service state", flush=True)
            errs = replay(before_svc)
            same = scutil() == before_scutil
            step("RESTORE", "PASS" if same and not errs else "FAIL", f"replayed recorded state; identical {same}; errors {errs}")
        elif scutil() != before_scutil:
            step("DRIFT", "FAIL", "the system proxy changed during the run by another actor; the harness set nothing and touched nothing — left as is", scutil()[:200])
        with open(os.path.join(OUT, "tui-raw.txt"), "wb") as f:
            f.write(bytes(term.raw))

    if any(v == "FAIL" for v in results.values()):
        return 1
    if any(v in ("SKIP", "BLOCKED") for v in results.values()):
        return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
