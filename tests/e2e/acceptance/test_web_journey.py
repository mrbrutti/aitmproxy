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
SERVICES = ("Wi-Fi", "Display Ethernet")
results: dict[str, str] = {}
set_by_us = False


def step(sid, result, observed="", truth="", explains=""):
    results[sid] = result
    print(f"{sid:7s} {result:7s} {observed[:160]}", flush=True)
    with open(STEPS, "a", encoding="utf-8") as f:
        f.write("\t".join([sid, result, observed.replace("\t", " "), truth.replace("\t", " "), explains]) + "\n")


def scutil() -> str:
    return subprocess.run(["scutil", "--proxy"], capture_output=True, text=True).stdout


def service_state() -> dict:
    return {svc: {"http": subprocess.run(["networksetup", "-getwebproxy", svc], capture_output=True, text=True).stdout,
                  "https": subprocess.run(["networksetup", "-getsecurewebproxy", svc], capture_output=True, text=True).stdout} for svc in SERVICES}


def replay(before: dict) -> list[str]:
    """Put each service back exactly as recorded; returns the networksetup failures."""
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

    global set_by_us
    before, before_svc = scutil(), service_state()
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
            env2 = dict(env, ACCEPT_ROUTE_OPEN="1" if "WEB-4" in yes else "0", ACCEPT_OP_URL=op_url)
            with open(os.path.join(OUT, "web_journey.mjs.log"), "w", encoding="utf-8") as mlog:
                p = subprocess.Popen(["node", os.path.join(HERE, "lib", "web_journey.mjs"), OUT, yes, manual], stdout=subprocess.PIPE, stderr=mlog, stdin=subprocess.PIPE, text=True, env=env2, start_new_session=True)
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
                            if sid == "WEB-4":
                                set_by_us = True
                            if sid == "WEB-7" and res == "PASS" and scutil() == before:
                                set_by_us = False
                            truth = "scutil: " + ("points at 8080" if "HTTPPort : 8080" in scutil() else "not 8080") + f"; identical to before: {scutil() == before}"
                        step(sid, res, redact(obs2), truth)
                try:
                    p.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGTERM)
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
        if set_by_us:
            print("== restore trap: WEB-4 set the system proxy and WEB-7 did not restore it; replaying the recorded per-service state", flush=True)
            errs = replay(before_svc)
            same = scutil() == before
            step("RESTORE", "PASS" if same and not errs else "FAIL", f"replayed recorded state; identical {same}; errors {errs}")
        elif scutil() != before:
            step("DRIFT", "FAIL", "the system proxy changed during the run by another actor; the harness set nothing and touched nothing — left as is", scutil()[:200])
    if any(v == "FAIL" for v in results.values()):
        return 1
    if any(v in ("SKIP", "BLOCKED") for v in results.values()):
        return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
