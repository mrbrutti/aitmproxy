#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey WEB (spec §D5): the INSTALLED `aitm web` on the operator's real
HOME, its ready card (WEB-1), then a REAL Google Chrome over CDP (lib/web_journey.mjs) for the
page words (WEB-2/3/6), the system-proxy flips only with Matt's yes (WEB-4/7) and the bypass
precondition, a second browser's traffic as a hand step (WEB-5, --manual), and the shutdown (WEB-8).
Bus truth for every step is read over the web `/bus` as operator through the Python harness
(BusClient speaks the same token-line protocol only to the loopback bus; the web bridge is a
WebSocket, so here the truth comes from the OPERATOR URL's page state plus the durable audit, and
from `scutil` for the route).

Preconditions: 8080/8081/8082 free (the app quit) — else SKIP naming the holder; Google Chrome
installed. Exit 0 = all performed PASS, 77 = any SKIP/BLOCKED, 1 = any FAIL. Steps → web-steps.tsv.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
import urllib.request

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e import is_manual, pause  # noqa: E402
from aitm_e2e.installed import DATA_DIR, INSTALLED_CLI, audit_tail, port_holder  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/web")
os.makedirs(OUT, exist_ok=True)
STEPS = os.path.join(OUT, "web-steps.tsv")
YES = set(filter(None, os.environ.get("ACCEPT_YES", "").split(",")))
AITM = os.environ.get("AITM", INSTALLED_CLI)
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
TOOLING = ("*.anthropic.com", "claude.ai", "github.com")
results: dict[str, str] = {}


def step(sid, result, observed="", truth="", explains=""):
    results[sid] = result
    print(f"{sid:7s} {result:7s} {observed[:160]}", flush=True)
    with open(STEPS, "a", encoding="utf-8") as f:
        f.write("\t".join([sid, result, observed.replace("\t", " "), truth.replace("\t", " "), explains]) + "\n")


def scutil() -> str:
    return subprocess.run(["scutil", "--proxy"], capture_output=True, text=True).stdout


def redact(s: str) -> str:
    return re.sub(r"#t=[^&\s]+", "#t=<redacted>", s)


def config_has_bypass() -> bool:
    p = os.path.join(DATA_DIR, "config.yaml")
    if not os.path.exists(p):
        return False
    txt = open(p, encoding="utf-8").read()
    m = re.search(r"^system_proxy:(.*?)(?=^\S|\Z)", txt, re.S | re.M)
    return bool(m and any(t in m.group(1) for t in TOOLING))


def main() -> int:
    if not os.path.isfile(AITM):
        step("WEB-1", "SKIP", f"installed aitm not found at {AITM}")
        return 77
    for port in (8080, 8081, 8082):
        h = port_holder(port)
        if h:
            for sid in ("WEB-1", "WEB-2", "WEB-3", "WEB-4", "WEB-5", "WEB-6a", "WEB-6b", "WEB-6c", "WEB-6d", "WEB-7", "WEB-8"):
                step(sid, "SKIP", f"port {port} held by {h}; aitm web needs the default ports (quit the app first)")
            step("WEB-9", "SKIP", "no All Apps control on this surface", "", "UIs pending (per-host decryption decision)")
            step("WEB-10", "SKIP", "no Apps view on this surface on 0.5.10")
            return 77
    if not os.path.isfile(CHROME):
        step("WEB-2", "SKIP", f"Google Chrome not found at {CHROME}")

    before = scutil()
    t0 = int(time.time() * 1000)
    env = dict(os.environ)
    env.pop("AITM_AUDIT_LOG", None)
    env.setdefault("LANG", "en_US.UTF-8")
    log = open(os.path.join(OUT, "aitm-web.log"), "w", encoding="utf-8")
    proc = subprocess.Popen([AITM, "web"], stdout=subprocess.PIPE, stderr=log, text=True, env=env, start_new_session=True)
    card, op_url = [], None
    try:
        # WEB-1 — the ready card.
        deadline = time.time() + 20
        while time.time() < deadline and proc.poll() is None:
            line = proc.stdout.readline()
            if not line:
                break
            card.append(line.rstrip("\n"))
            m = re.match(r"\s*Operator\s+(https?://\S+)", line)
            if m:
                op_url = m.group(1)
            if "Scope" in line or (len(card) > 12 and "────" in line):
                break
        shown = "\n".join(card)
        with open(os.path.join(OUT, "WEB-1.txt"), "w", encoding="utf-8") as f:
            f.write(redact(shown))
        loader = sum(1 for l in card if "loaded script" in l or "script loaded into the host" in l)
        have = {k: bool(re.search(k, shown)) for k in (r"^\s*aitm web$", r"Web UI\s+http://127\.0\.0\.1:8082/#t=", r"Proxy\s+127\.0\.0\.1:8080", r"Browser\s+127\.0\.0\.1:8081\s+\(SSRF-filtered\)", r"Bus\s+ready")}
        healthz = ""
        try:
            healthz = urllib.request.urlopen("http://127.0.0.1:8082/healthz", timeout=5).read().decode()
        except Exception as e:  # noqa: BLE001
            healthz = f"error {e}"
        obs = f"card lines {len(card)} ({loader} loader lines); " + ", ".join(f"{k.split(chr(92))[0].strip('^s*')}: {v}" for k, v in have.items()) + f"; Operator line {'present' if op_url else 'ABSENT'}; /healthz {healthz.strip()}"
        if all(have.values()) and loader == 0 and healthz.strip() == '{"ok":true}':
            step("WEB-1", "PASS", redact(obs))
        else:
            step("WEB-1", "FAIL", redact(obs), "", "log noise / card shape: PR #271" if loader else "")
        if not op_url:
            for sid in ("WEB-2", "WEB-3", "WEB-4", "WEB-5", "WEB-6a", "WEB-6b", "WEB-6c", "WEB-6d", "WEB-7"):
                step(sid, "BLOCKED", "no Operator line: mcp.operator_token is not set in the operator's config (run `aitm operator-token generate` is a manual step on 0.5.10)")
        elif results.get("WEB-2") != "SKIP":
            yes = ",".join(sorted(YES & {"WEB-4", "WEB-7"}))
            if "WEB-4" in YES and not config_has_bypass():
                step("WEB-4", "SKIP", "bypass list absent in config.yaml system_proxy.bypass; add it through Settings first")
                yes = ",".join(x for x in yes.split(",") if x not in ("WEB-4", "WEB-7"))
            manual = "manual" if is_manual() else ""
            env2 = dict(env, ACCEPT_ROUTE_OPEN="1" if "WEB-4" in yes else "0")
            with open(os.path.join(OUT, "web_journey.mjs.log"), "w", encoding="utf-8") as mlog:
                p = subprocess.Popen(["node", os.path.join(HERE, "lib", "web_journey.mjs"), op_url, OUT, yes, manual], stdout=subprocess.PIPE, stderr=mlog, stdin=subprocess.PIPE, text=True, env=env2)
                for line in p.stdout:
                    line = line.rstrip("\n")
                    if line.startswith("PAUSE\t"):
                        pause(line.split("\t", 1)[1])
                        p.stdin.write("\n")
                        p.stdin.flush()
                    elif line.startswith("STEP\t"):
                        _, sid, res, obs2 = (line.split("\t") + [""])[:4]
                        truth = ""
                        if sid == "WEB-3":
                            rows = [r for r in audit_tail(200) if r.get("at", 0) >= t0 and r.get("command") == "scope.add"]
                            truth = f"audit scope.add entries since start: {len(rows)}"
                        if sid in ("WEB-4", "WEB-7"):
                            truth = "scutil: " + ("points at 8080" if "HTTPPort : 8080" in scutil() else "not 8080") + f"; identical to before: {scutil() == before}"
                        step(sid, res, redact(obs2), truth)
                p.wait(timeout=60)
            if "WEB-4" not in YES or results.get("WEB-4") != "PASS":
                step("WEB-5", "BLOCKED", "WEB-4 did not set the route")
            elif not is_manual():
                step("WEB-5", "SKIP", "needs a hand: Safari visits http://example.com/ and https://httpbin.org/get (--manual)")
        # WEB-8 — stop.
        os.killpg(proc.pid, signal.SIGINT)
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            rc = proc.wait(timeout=5)
        time.sleep(0.5)
        free = all(port_holder(p) is None for p in (8080, 8081, 8082))
        same = scutil() == before
        step("WEB-8", "PASS" if free and same else "FAIL", f"exit {rc}; ports free {free}; scutil identical {same}", "audit: no proxy.system.set left unmatched" if same else "")
        step("WEB-9", "SKIP", "no All Apps control on this surface", "", "UIs pending (per-host decryption decision)")
        step("WEB-10", "SKIP", "no Apps view on this surface on 0.5.10")
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
        log.close()
        if scutil() != before:
            print("== restore trap: scutil differs from before; `aitm proxy system unset` is NOT run by the harness (one-shot restores nothing on 0.5.10) — restoring per service", flush=True)
            for svc in ("Wi-Fi", "Display Ethernet"):
                subprocess.run(["networksetup", "-setwebproxystate", svc, "off"], capture_output=True)
                subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"], capture_output=True)
            print("== scutil identical after restore:", scutil() == before, flush=True)
    if any(v == "FAIL" for v in results.values()):
        return 1
    if any(v in ("SKIP", "BLOCKED") for v in results.values()):
        return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
