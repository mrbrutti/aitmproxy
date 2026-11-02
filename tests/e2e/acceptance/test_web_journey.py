#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey WEB (spec §D5, negatives §D7): the INSTALLED `aitm web` on the
operator's real HOME, its ready card (WEB-1), then a REAL Google Chrome over CDP
(lib/web_journey.mjs) for the page words (WEB-2/3/6, N2-WEB, N5-WEB), the system-proxy flips
only with Matt's yes (WEB-4/7) and the bypass precondition, a second browser's traffic as a hand
step (WEB-5, --manual; judged from the page by the mjs, the web cell has no bus client), and the
shutdown (WEB-8). Bus truth here is `scutil` for the route, the durable audit for scope.add, and
the page state; the wrapper answers the mjs's `CHECK WEB-4` with the ExceptionsList assertion and
replays the recorded per-service state in its trap if the surface did not restore.

Preconditions: 8080/8081/8082 free (the app quit) — else SKIP naming the holder; Google Chrome
installed — else WEB-2…7 SKIP. The host WEB-3 adds is removed by the mjs through its row's own
button (unless ACCEPT_KEEP_SCOPE=1) and listed in leftovers.txt.
Exit 0 = all performed PASS, 77 = any SKIP/BLOCKED, 1 = any FAIL. Steps → $ACCEPT_OUT/web-steps.tsv.
"""
from __future__ import annotations

import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e import is_manual, pause  # noqa: E402
from aitm_e2e.installed import (  # noqa: E402
    DATA_DIR,
    INSTALLED_CLI,
    StepWriter,
    append_leftover,
    audit_tail,
    bypass_applied,
    config_bypass,
    port_holder,
    replay,
    scutil,
    service_state,
    yes_set,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/web")
os.makedirs(OUT, exist_ok=True)
YES = yes_set()
AITM = os.environ.get("AITM", INSTALLED_CLI)
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
BROWSER_STEPS = ("WEB-2", "WEB-3", "WEB-4", "WEB-5", "WEB-6a", "WEB-6b", "WEB-6c", "WEB-6d", "WEB-7", "N2-WEB", "N5-WEB")
EXPECTED_STEPS = ("WEB-1",) + BROWSER_STEPS + ("WEB-8", "WEB-9", "WEB-10", "N1-WEB", "N3-WEB")
CARD_WANT = {
    "title line `aitm web`": r"^\s*aitm web\s*$",
    "Web UI line": r"Web UI\s+http://127\.0\.0\.1:8082/#t=",
    "Proxy line": r"Proxy\s+127\.0\.0\.1:8080",
    "Browser line (SSRF-filtered)": r"Browser\s+127\.0\.0\.1:8081\s+\(SSRF-filtered\)",
    "Bus ready": r"Bus\s+ready",
}
SCOPE_LINE = "Scope      Nothing is decrypted until a host is in Scope."

w = StepWriter(os.path.join(OUT, "web-steps.tsv"), EXPECTED_STEPS)
step = w.step


def na_rows() -> None:
    step("WEB-9", "SKIP", "no All Apps control on this surface", "", "UIs pending (per-host decryption decision)")
    step("WEB-10", "SKIP", "no Apps view on this surface on 0.5.10")
    step("N1-WEB", "SKIP", "aitm web owns its core: a core restart under an open tab is not performable here (words pinned in D7)")
    step("N3-WEB", "SKIP", "CA stays trusted (un-trusting is Matt's yes; words read from source)")


def config_scope_empty() -> bool | None:
    """True/False from the `scope:` block of the operator's config.yaml (only that block is read);
    None when there is no config."""
    p = os.path.join(DATA_DIR, "config.yaml")
    if not os.path.exists(p):
        return None
    inside, entries = False, 0
    with open(p, encoding="utf-8") as f:
        for line in f:
            if line.startswith("scope:"):
                inside = True
                if "[" in line and line.split(":", 1)[1].strip() not in ("[]", ""):
                    entries += 1
                continue
            if inside and line.strip() and not line.startswith(" "):
                break
            if inside and line.strip().startswith("- "):
                entries += 1
    return entries == 0


def read_card(proc: subprocess.Popen, deadline_s: float) -> tuple[list[str], str | None, str | None]:
    """The ready card from stdout, read in a thread so a silent `aitm web` cannot hang the cell:
    stops at the SECOND rule line (`────`), at EOF, or at the deadline."""
    q: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        for line in proc.stdout:
            q.put(line)
        q.put(None)

    threading.Thread(target=pump, daemon=True).start()
    card: list[str] = []
    op_url = agent_url = None
    rules = 0
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            line = q.get(timeout=max(0.05, end - time.time()))
        except queue.Empty:
            break
        if line is None:
            break
        card.append(line.rstrip("\n"))
        m = re.match(r"\s*Operator\s+(https?://\S+)", line)
        if m:
            op_url = m.group(1)
        m = re.match(r"\s*Web UI\s+(https?://\S+)", line)
        if m:
            agent_url = m.group(1)
        if "────" in line:
            rules += 1
            if rules >= 2:
                break
    return card, op_url, agent_url


def main() -> int:  # noqa: C901 — one journey, in the operator's order
    if not os.path.isfile(AITM):
        step("WEB-1", "SKIP", f"installed aitm not found at {AITM}")
        na_rows()
        w.finish()
        return w.exit_code()
    for port in (8080, 8081, 8082):
        h = port_holder(port)
        if h:
            for sid in ("WEB-1",) + BROWSER_STEPS + ("WEB-8",):
                step(sid, "SKIP", f"port {port} held by {h}; aitm web needs the default ports (quit the app first)")
            na_rows()
            w.finish()
            return w.exit_code()
    chrome_ok = os.path.isfile(CHROME)

    before, before_svc = scutil(), service_state()
    t0 = int(time.time() * 1000)
    env = dict(os.environ)
    env.pop("AITM_AUDIT_LOG", None)
    env.setdefault("LANG", "en_US.UTF-8")
    set_by_us = False
    with open(os.path.join(OUT, "aitm-web.log"), "w", encoding="utf-8") as log:
        proc = subprocess.Popen([AITM, "web"], stdout=subprocess.PIPE, stderr=log, text=True, env=env, start_new_session=True)
        try:
            # WEB-1 — the ready card.
            card, op_url, agent_url = read_card(proc, 20)
            for u in (op_url, agent_url):
                if u and "#t=" in u:
                    w.add_secret(u.split("#t=", 1)[1].split("&", 1)[0])
            shown = "\n".join(card)
            with open(os.path.join(OUT, "WEB-1.txt"), "w", encoding="utf-8") as f:
                f.write(w.redact(shown))
            loader = sum(1 for ln in card if "loaded script" in ln or "script loaded into the host" in ln)
            have = {label: bool(re.search(rx, shown, re.M)) for label, rx in CARD_WANT.items()}
            rules = sum(1 for ln in card if "────" in ln)
            have["two rules"] = rules == 2
            scope_empty = config_scope_empty()
            if scope_empty:
                have["Scope line (Scope empty)"] = SCOPE_LINE in shown
            healthz = ""
            try:
                healthz = urllib.request.urlopen("http://127.0.0.1:8082/healthz", timeout=5).read().decode()
            except Exception as e:  # noqa: BLE001
                healthz = f"error {e}"
            obs = f"card lines {len(card)} ({loader} loader lines); " + ", ".join(f"{k}: {v}" for k, v in have.items()) + f"; Operator line {'present' if op_url else 'ABSENT'}; config scope empty {scope_empty}; /healthz {healthz.strip()}"
            if all(have.values()) and loader == 0 and healthz.strip() == '{"ok":true}':
                step("WEB-1", "PASS", obs)
            else:
                step("WEB-1", "FAIL", obs, "", "log noise / card shape: PR #271" if loader or not have["two rules"] else "")
            if not op_url:
                for sid in BROWSER_STEPS:
                    step(sid, "BLOCKED", "no Operator line: mcp.operator_token is not set in the operator's config (`aitm operator-token generate` is a manual step on 0.5.10)")
            elif not chrome_ok:
                for sid in BROWSER_STEPS:
                    step(sid, "SKIP", f"Google Chrome not found at {CHROME}; the page words need a real browser")
            else:
                yes = sorted(YES & {"WEB-4", "WEB-7"})
                byp = config_bypass()
                if "WEB-4" in yes and not any(t.lstrip("*.") in " ".join(byp) for t in ("*.anthropic.com", "claude.ai", "github.com")):
                    step("WEB-4", "SKIP", f"bypass list absent in config.yaml system_proxy.bypass ({byp or 'none'}); add it through Settings first")
                    yes = [x for x in yes if x not in ("WEB-4", "WEB-7")]
                env2 = dict(env, ACCEPT_ROUTE_OPEN="1" if "WEB-4" in yes else "0", ACCEPT_OP_URL=op_url, ACCEPT_AGENT_URL=agent_url or "")
                with open(os.path.join(OUT, "web_journey.mjs.log"), "w", encoding="utf-8") as mlog:
                    p = subprocess.Popen(["node", os.path.join(HERE, "lib", "web_journey.mjs"), OUT, ",".join(yes), "manual" if is_manual() else ""],
                                         stdout=subprocess.PIPE, stderr=mlog, stdin=subprocess.PIPE, text=True, env=env2, start_new_session=True)
                    for line in p.stdout:
                        line = line.rstrip("\n")
                        kind, _, rest = line.partition("\t")
                        if kind == "PAUSE":
                            pause(rest)
                            p.stdin.write("\n")
                            p.stdin.flush()
                        elif kind == "CHECK":
                            set_by_us = True
                            ok = bypass_applied(scutil())
                            p.stdin.write("ok\n" if ok else "bad\n")
                            p.stdin.flush()
                        elif kind == "LEFTOVER":
                            host, _, state = rest.partition("\t")
                            append_leftover(OUT, host, state, "web")
                        elif kind == "STEP":
                            sid, res, obs2 = (rest.split("\t") + ["", ""])[:3]
                            truth = ""
                            if sid == "WEB-3":
                                rows = [r for r in audit_tail(200) if r.get("at", 0) >= t0 and r.get("command") == "scope.add"]
                                truth = f"audit scope.add entries since start: {len(rows)}"
                            elif sid == "WEB-5":
                                truth = "judged from the page (grid rows) by the mjs; the web cell has no bus client"
                            elif sid in ("WEB-4", "WEB-7"):
                                now = scutil()
                                if sid == "WEB-7" and res == "PASS" and now == before:
                                    set_by_us = False
                                if sid == "WEB-4" and res == "FAIL":
                                    set_by_us = now != before
                                truth = "scutil: " + ("points at 8080" if "HTTPPort : 8080" in now else "not 8080") + f"; ExceptionsList carries the tooling {bypass_applied(now)}; identical to before: {now == before}"
                            step(sid, res, obs2, truth)
                    try:
                        p.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGTERM)
            # WEB-8 — stop.
            os.killpg(proc.pid, signal.SIGINT)
            try:
                rc = proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGTERM)
                rc = proc.wait(timeout=5)
            time.sleep(0.5)
            free = all(port_holder(pt) is None for pt in (8080, 8081, 8082))
            same = scutil() == before
            pointers = os.path.join(DATA_DIR, "run", "cores")
            left = sorted(os.listdir(pointers)) if os.path.isdir(pointers) else []
            step("WEB-8", "PASS" if free and same else "FAIL", f"exit {rc}; ports free {free}; scutil identical {same}; run/cores pointers left {left}", "audit: no proxy.system.set left unmatched" if same else "")
            na_rows()
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
            if set_by_us:
                print("== restore trap: WEB-4 set the system proxy and WEB-7 did not restore it; replaying the recorded per-service state", flush=True)
                errs = replay(before_svc)
                same = scutil() == before
                step("RESTORE", "PASS" if same and not errs else "FAIL", f"replayed recorded state; identical {same}; errors {errs}")
            elif scutil() != before:
                step("DRIFT", "FAIL", "the system proxy changed during the run by another actor; the harness set nothing and touched nothing — left as is", scutil()[:200])
            w.finish()
    return w.exit_code()


if __name__ == "__main__":
    sys.exit(main())
