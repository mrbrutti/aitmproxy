#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey MAC (spec §D3): Matt's INSTALLED /Applications/Aitmproxy.app.

What runs without a window (always): MAC-1 (process + bus truth from the embedded core found by
its own command line), a read-only accessibility dump of whatever page the window shows, and
MAC-9a/9b judged from `flow.table` (source_app per row). Everything that presses a menu, types,
or changes the Mac needs the orchestrator's display-lock window (ACCEPT_WINDOW=1) and, for the
`yes` steps (MAC-6/7/14/15), their ids in ACCEPT_YES; MAC-5/8/10-12 additionally need
AITM_E2E_MANUAL=1 because a hand reloads Safari. Without them every such step is SKIP with the
reason. The `yes` steps record `scutil`/per-service state first and replay it in a trap.

Exit 0 = all performed PASS, 77 = any SKIP/BLOCKED, 1 = any FAIL. Steps → mac-steps.tsv.
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
from aitm_e2e.bus import ToolError  # noqa: E402
from aitm_e2e.installed import app_version, audit_tail, bus_truth, connect, find_embedded_core, redact  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "lib")
OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/mac")
os.makedirs(OUT, exist_ok=True)
STEPS = os.path.join(OUT, "mac-steps.tsv")
YES = set(filter(None, os.environ.get("ACCEPT_YES", "").split(",")))
WINDOW = os.environ.get("ACCEPT_WINDOW") == "1"
HOSTS = ("example.com:80", "httpbin.org:443")
SERVICES = ("Wi-Fi", "Display Ethernet")
TOOLING = ("anthropic.com", "claude.ai", "github.com")
results: dict[str, str] = {}
secret = ""


def step(sid, result, observed="", truth="", explains=""):
    results[sid] = result
    print(f"{sid:7s} {result:7s} {redact(observed, secret)[:160]}", flush=True)
    with open(STEPS, "a", encoding="utf-8") as f:
        f.write("\t".join([sid, result, redact(observed, secret).replace("\t", " "), redact(truth, secret).replace("\t", " "), explains]) + "\n")


def sh(*argv, timeout=30) -> str:
    r = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    return r.stdout + (("\n[stderr] " + r.stderr.strip()) if r.returncode else "")


def scutil() -> str:
    return sh("scutil", "--proxy")


def service_state() -> dict:
    return {svc: {"http": sh("networksetup", "-getwebproxy", svc), "https": sh("networksetup", "-getsecurewebproxy", svc)} for svc in SERVICES}


def replay(before: dict) -> None:
    for svc, d in before.items():
        for kind, text in d.items():
            en = re.search(r"Enabled: (\w+)", text)
            host = re.search(r"Server: (\S*)", text)
            port = re.search(r"Port: (\d+)", text)
            setp = "-setwebproxy" if kind == "http" else "-setsecurewebproxy"
            setstate = "-setwebproxystate" if kind == "http" else "-setsecurewebproxystate"
            if host and port and host.group(1):
                subprocess.run(["networksetup", setp, svc, host.group(1), port.group(1)], capture_output=True)
            subprocess.run(["networksetup", setstate, svc, "on" if en and en.group(1) == "Yes" else "off"], capture_output=True)


def ax() -> str:
    return sh("bash", os.path.join(LIB, "ax_texts.sh"))


def menu(m, item) -> str:
    return sh("bash", os.path.join(LIB, "menu.sh"), m, item)


def has(text: str, *needles: str) -> list[str]:
    return [n for n in needles if n not in text]


def mac_bypass_ok() -> bool:
    d = sh("defaults", "read", "com.mrbrutti.aitmproxy")
    return any(t in d for t in TOOLING)


def main() -> int:
    global secret
    core = find_embedded_core()
    ver = app_version()
    if core is None:
        step("MAC-1", "SKIP" if not WINDOW else "FAIL", f"the app is not running (bundle {ver}); launching it is a hand/yes step (open -a Aitmproxy) — not done without the window")
        return 77
    secret = core.operator_token
    bus = connect(core)
    truth0 = bus_truth(bus)
    ps = truth0.get("proxy.status", {})
    with open(os.path.join(OUT, "mac-bus-truth-start.json"), "w", encoding="utf-8") as f:
        f.write(redact(json.dumps(truth0, indent=1, sort_keys=True), secret))
    ok1 = ps.get("listening") is True and bool(ps.get("version"))
    step("MAC-1", "PASS" if ok1 else "FAIL",
         f"app running (bundle {ver}); embedded core pid {core.pid} listening {ps.get('address')} version {ps.get('version')}" + ("" if ver == ps.get("version") else f" — bundle plist {ver} differs from the running core {ps.get('version')}"),
         f"proxy.status.listening {ps.get('listening')}, version {ps.get('version')}; start marker in audit: {any(r.get('marker') == 'start' and r.get('pid') == core.pid for r in audit_tail(400))}")

    # Read-only AX dump of whatever the window shows, for the report (no press).
    dump = ax()
    with open(os.path.join(OUT, "MAC-ax-initial.txt"), "w", encoding="utf-8") as f:
        f.write(dump)
    sc = truth0.get("scope.list", [])
    cap = truth0.get("capture.status", {})
    sp = truth0.get("proxy.system.status", {})
    expected_status = []
    if sp.get("state") == "off":
        expected_status.append("system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.")
    elif sp.get("state") == "points_at_us":
        expected_status.append(f"system proxy on · {sp.get('ours', {}).get('host')}:{sp.get('ours', {}).get('port')}")
    if cap.get("enabled") and cap.get("provider", {}).get("state") == "attached":
        expected_status.append("All Apps is on")
    elif not cap.get("enabled"):
        expected_status.append("All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)")
    if not sc:
        expected_status.append("Add a host to Scope (for now as example.com:443)")
    if not WINDOW:
        for sid in ("MAC-2", "MAC-3", "MAC-4"):
            step(sid, "SKIP", "needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: " + " | ".join(expected_status),
                 f"scope.list {sc}; capture enabled {cap.get('enabled')} provider {cap.get('provider', {}).get('state')}; system proxy {sp.get('state')}")
    else:
        menu("Proxy", "Status")
        time.sleep(1.2)
        dump = ax()
        with open(os.path.join(OUT, "MAC-3-ax.txt"), "w", encoding="utf-8") as f:
            f.write(dump)
        sheet = "Set up aitmproxy on this Mac" in dump
        if sheet:
            ca_row = "CA trusted (user keychain)" if truth0.get("ca.status", {}).get("stores", {}).get("user", {}).get("trusted") == "yes" else "HTTPS is not captured until the CA is trusted"
            miss = has(dump, "Set aitmproxy as the system proxy", "Trust the aitmproxy CA", ca_row, "Nothing is decrypted until a host is in Scope")
            step("MAC-2", "PASS" if not miss else "FAIL", f"first-run sheet shown; missing {miss}", f"ca.status user trusted {truth0.get('ca.status', {}).get('stores', {}).get('user', {}).get('trusted')}")
            menu("Proxy", "Status")  # the sheet's Not Now is a hand step; leave it and read behind it if possible
        else:
            step("MAC-2", "PASS", "first-run sheet not shown (already dismissed or every row done); recorded as such")
        miss = has(dump, *expected_status)
        step("MAC-3", "PASS" if not miss else "FAIL", f"Status page words present: {[w for w in expected_status if w not in miss]}; missing: {miss}", f"scope.list {sc}; capture {cap.get('enabled')}/{cap.get('provider', {}).get('state')}; system proxy {sp.get('state')}")
        flows = truth0.get("flow.table", {}).get("flows", [])
        step("MAC-4", "PASS" if (flows or "No flows yet" in dump) else "FAIL", "rows exist: banner case applies" if flows else f"'No flows yet' present {'No flows yet' in dump}", f"flow.table rows {len(flows)}")

    # MAC-5 — add the hosts on the Scope page (hand + window: types into his app).
    if not (WINDOW and is_manual()):
        step("MAC-5", "SKIP", "needs the window and a hand (types into the Edit Scope sheet); hosts example.com:80, httpbin.org:443")
    else:
        pause("On the Scope page add example.com:80 and httpbin.org:443 with the Add button; press Enter here when both are listed")
        time.sleep(2)
        sc2 = bus.call("scope.list", {})
        rows = [r for r in audit_tail(200) if r.get("command") == "scope.add" and r.get("result") == "ok"]
        step("MAC-5", "PASS" if all(h in sc2 for h in HOSTS) else "FAIL", f"scope.list now {sc2}", f"audit scope.add ok entries: {len(rows)}")

    before_sc, before_svc = scutil(), service_state()
    set_by_us = False
    cap_by_us = False
    try:
        # MAC-6 — Set as System Proxy (yes).
        if "MAC-6" not in YES or not WINDOW:
            step("MAC-6", "SKIP", "needs Matt's yes (ACCEPT_YES=MAC-6) and the window")
        elif not mac_bypass_ok():
            step("MAC-6", "SKIP", "bypass list absent in the app's Settings ▸ Proxy Bypass hosts; add the operator's tooling there first")
        else:
            print(f"== window MAC-6 start {time.strftime('%H:%M:%S')}", flush=True)
            pressed = menu("Proxy", "Set as System Proxy")
            set_by_us = True
            time.sleep(3)
            sp2 = bus.call("proxy.system.status", {})
            sc_now = scutil()
            items = sh("bash", os.path.join(LIB, "ax_texts.sh"), "menu", "Proxy")
            ok = sp2.get("state") == "points_at_us" and sp2.get("managed_by_us") is True and "HTTPPort : 8080" in sc_now and any(t in sc_now for t in TOOLING) and "Restore System Proxy" in items
            step("MAC-6", "PASS" if ok else "FAIL", f"{pressed.strip()}; menu now has Restore System Proxy: {'Restore System Proxy' in items}; scutil 8080: {'HTTPPort : 8080' in sc_now}; bypass applied: {any(t in sc_now for t in TOOLING)}", f"proxy.system.status {sp2.get('state')} managed_by_us {sp2.get('managed_by_us')}")
            if not any(t in sc_now for t in TOOLING):
                menu("Proxy", "Restore System Proxy")
                set_by_us = False

        # MAC-7 — Capture All Apps (yes); already on → verify words only.
        if cap.get("enabled"):
            step("MAC-7", "PASS" if cap.get("provider", {}).get("state") == "attached" else "FAIL", f"All Apps already on at start (capability {cap.get('capability')}, provider {cap.get('provider', {}).get('state')}); Status word expected 'All Apps is on'" + (", lane 'on, nothing in scope'" if not sc else ""), f"capture.status enabled {cap.get('enabled')} feeder {cap.get('feeder', {}).get('state')} handed off {cap.get('flows_handed_off')}")
        elif "MAC-7" not in YES or not WINDOW:
            step("MAC-7", "SKIP", "needs Matt's yes (ACCEPT_YES=MAC-7) and the window")
        else:
            pressed = menu("Proxy", "Capture All Apps")
            cap_by_us = True
            time.sleep(4)
            cap2 = bus.call("capture.status", {})
            step("MAC-7", "PASS" if cap2.get("enabled") and cap2.get("feeder", {}).get("state") == "listening" else "FAIL", pressed.strip(), f"capture.status {json.dumps({k: cap2.get(k) for k in ('enabled', 'capability', 'feeder', 'provider')})}")

        # MAC-8 — real browser rows (hand).
        route = results.get("MAC-6") == "PASS" or results.get("MAC-7") == "PASS"
        if results.get("MAC-5") != "PASS" or not route:
            step("MAC-8", "BLOCKED", "needs MAC-5 and a route (MAC-6 or MAC-7)")
        elif not is_manual():
            step("MAC-8", "SKIP", "needs a hand: Safari visits http://example.com/ and https://httpbin.org/get")
        else:
            pause("In Safari open http://example.com/ then https://httpbin.org/get; press Enter here")
            time.sleep(3)
            flows = bus.call("flow.table", {}).get("flows", [])
            ex = [r for r in flows if (r.get("authority") or "").startswith("example.com")]
            hb = [r for r in flows if (r.get("authority") or "").startswith("httpbin.org") and r.get("method") == "GET"]
            dec = [r for r in hb if r.get("tunnel") == "decrypted"]
            step("MAC-8", "PASS" if ex and dec else "FAIL", f"example rows {len(ex)}, httpbin GET rows {len(hb)} decrypted {len(dec)}", json.dumps([{k: r.get(k) for k in ('method', 'authority', 'status', 'tunnel', 'tunnel_reason', 'source_app', 'capture_interface')} for r in (ex + hb)[:4]]))

        # MAC-9a / MAC-9b from the bus.
        flows = bus.call("flow.table", {}).get("flows", [])
        ne = [r for r in flows if r.get("capture_interface") == "macos-ne"]
        proxied = [r for r in flows if r.get("capture_interface") is None]
        if ne:
            step("MAC-9a", "PASS" if all(r.get("source_app") for r in ne) else "FAIL", f"{len(ne)} extension rows, source_app set on {sum(1 for r in ne if r.get('source_app'))}; group name per spec: WebKit Networking vs Safari (two Kit tables)", f"source_apps {sorted({r.get('source_app') for r in ne})}")
        else:
            step("MAC-9a", "BLOCKED" if not results.get("MAC-8") == "PASS" else "FAIL", "no extension-captured rows (All Apps on but Scope empty → the extension claims nothing)" if cap.get("enabled") else "All Apps off", f"capture.status flows_handed_off {cap.get('flows_handed_off')}")
        if proxied:
            attributed = sum(1 for r in proxied if r.get("source_app"))
            step("MAC-9b", "PASS" if attributed == len(proxied) else "FAIL", f"{len(proxied)} proxied rows, {attributed} carry a source_app → Apps sidebar shows {'them' if attributed else 'NOTHING for them'}", f"flow.table source_app null ×{len(proxied) - attributed}", "" if attributed else "missing feature: attribution for proxied flows (session core-name-the-client-app)")
        else:
            step("MAC-9b", "BLOCKED", "no proxied rows to judge")

        # MAC-10/11/12 — intercept (window + hand).
        if not (WINDOW and is_manual() and results.get("MAC-8") == "PASS"):
            for sid in ("MAC-10", "MAC-11", "MAC-12"):
                step(sid, "BLOCKED" if results.get("MAC-8") != "PASS" else "SKIP", "needs MAC-8 rows, the window and a hand (reload in Safari)")
        else:
            menu("Flow", "Arm Intercept")
            time.sleep(1)
            armed = bus.call("proxy.status", {}).get("intercept_armed")
            dump = ax()
            step("MAC-10", "PASS" if armed and "Intercept armed — every request pauses here" in dump else "FAIL", f"bar words present {'Intercept armed — every request pauses here' in dump}", f"intercept_armed {armed}")
            pause("Reload http://example.com/ in Safari (it should spin); press Enter here")
            time.sleep(1)
            parked = [r for r in bus.call("flow.table", {}).get("flows", []) if r.get("state") == "intercepted"]
            menu("Flow", "Resume")
            time.sleep(2)
            resumed = [r for r in bus.call("flow.table", {}).get("flows", []) if r.get("state") == "resumed"]
            step("MAC-11", "PASS" if parked and resumed else "FAIL", f"parked {len(parked)} → resumed {len(resumed)}", f"paused before resume {len(parked)}")
            menu("Flow", "Disarm Intercept")
            time.sleep(1)
            step("MAC-12", "PASS" if bus.call("proxy.status", {}).get("intercept_armed") is False else "FAIL", "disarmed", "intercept_armed false")

        # MAC-13 — Restart Core (window; changes nothing on the Mac but restarts his core).
        if not WINDOW or "MAC-13" not in YES:
            step("MAC-13", "SKIP", "needs the window and ACCEPT_YES=MAC-13 (restarts his core; Scope must survive)")
        else:
            sc_before = bus.call("scope.list", {})
            menu("Proxy", "Restart Core")
            time.sleep(6)
            core2 = find_embedded_core()
            bus2 = connect(core2) if core2 else None
            ok = bus2 is not None and bus2.call("proxy.status", {}).get("listening") is True and bus2.call("scope.list", {}) == sc_before
            dump = ax()
            step("MAC-13", "PASS" if ok and "Embedded core failed" not in dump else "FAIL", f"new core pid {core2.pid if core2 else None}; stale failed banner present {'Embedded core failed' in dump}", f"scope.list before {sc_before} after {bus2.call('scope.list', {}) if bus2 else None}")
            if bus2:
                bus = bus2
                secret = core2.operator_token

        # MAC-14 — Stop Capturing (yes; only if we turned it on).
        if not cap_by_us:
            step("MAC-14", "SKIP", "All Apps was already on at start (operator's state) — not turned off by the run" if cap.get("enabled") else "MAC-7 did not run")
        elif "MAC-14" not in YES:
            step("MAC-14", "SKIP", "needs Matt's yes (ACCEPT_YES=MAC-14)")
        else:
            menu("Proxy", "Stop Capturing All Apps")
            time.sleep(3)
            cap3 = bus.call("capture.status", {})
            step("MAC-14", "PASS" if cap3.get("enabled") is False else "FAIL", "pressed Stop Capturing All Apps", f"capture.status enabled {cap3.get('enabled')} feeder {cap3.get('feeder', {}).get('state')}")
            cap_by_us = False

        # MAC-15 — Restore System Proxy (yes; only if we set it).
        if not set_by_us:
            step("MAC-15", "SKIP", "nothing to restore (MAC-6 did not set it)")
        elif "MAC-15" not in YES:
            step("MAC-15", "SKIP", "needs Matt's yes (ACCEPT_YES=MAC-15) — the trap will restore")
        else:
            menu("Proxy", "Restore System Proxy")
            time.sleep(3)
            sp3 = bus.call("proxy.system.status", {})
            same = scutil() == before_sc
            items = sh("bash", os.path.join(LIB, "ax_texts.sh"), "menu", "Proxy")
            step("MAC-15", "PASS" if same and sp3.get("managed_by_us") is False and "Set as System Proxy" in items else "FAIL", f"scutil identical to before {same}; menu back to Set as System Proxy {'Set as System Proxy' in items}", f"proxy.system.status {sp3.get('state')} managed_by_us {sp3.get('managed_by_us')}")
            if same:
                set_by_us = False
        step("MAC-16", "SKIP", "the app was already running at start; not quit by the run (Matt's app)")
    finally:
        if set_by_us or scutil() != before_sc:
            print("== restore trap: replaying the recorded per-service system proxy state", flush=True)
            try:
                menu("Proxy", "Restore System Proxy")
                time.sleep(3)
            except Exception:  # noqa: BLE001
                pass
            if scutil() != before_sc:
                replay(before_svc)
            print("== scutil identical after restore:", scutil() == before_sc, flush=True)
        if cap_by_us:
            print("== restore trap: All Apps was turned on by the run and not turned off — leftover for the report", flush=True)
    if any(v == "FAIL" for v in results.values()):
        return 1
    if any(v in ("SKIP", "BLOCKED") for v in results.values()):
        return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
