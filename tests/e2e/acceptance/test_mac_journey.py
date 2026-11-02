#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey MAC (spec §D3, negatives §D7): Matt's INSTALLED /Applications/Aitmproxy.app.

What runs without a window (always): MAC-1 (process + bus truth from the embedded core found by
its own command line), a read-only accessibility dump of whatever page the window shows, and
MAC-9b judged from `flow.table` (source_app per row). Everything that presses a menu, types, or
reads a page needs the orchestrator's display-lock window (ACCEPT_WINDOW=1): MAC-2/3/4 (Status
page words), MAC-5 (the Edit Scope sheet, typed through lib/type.sh), MAC-7 "already on" and
MAC-9a (words inside the window), MAC-13 (Restart Core). The `yes` steps (MAC-6/7/14/15) need
their ids in ACCEPT_YES as well, and every yes press first checks that the holder of 8080 is this
app's core. MAC-8/10-12 and N1-MAC additionally need AITM_E2E_MANUAL=1 (a hand drives Safari).
Without them every such step is SKIP with the reason. The `yes` steps record `scutil`/per-service
state first and replay it in a trap. Scope hosts the run adds are removed at the end through the
Scope page's own "Remove <host> from Scope" button (unless ACCEPT_KEEP_SCOPE=1) and listed in
leftovers.txt; hosts that were in Scope before (bus `scope.list` read before typing) are never
touched. When that button is not found the row's context menu is NOT attempted: the host is listed
`failed (…)` for Matt's hand. Every accessibility dump written beside the steps goes through the
writer's redaction (the embedded core's token values are added to it first). `set_by_us` is armed
BEFORE the Set as System Proxy press, so a crash mid-press still restores.

Exit 0 = all performed PASS, 77 = any SKIP/BLOCKED, 1 = any FAIL. Steps → $ACCEPT_OUT/mac-steps.tsv.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e import is_manual, pause  # noqa: E402
from aitm_e2e.installed import (  # noqa: E402
    StepWriter,
    field_center,
    app_version,
    append_leftover,
    audit_tail,
    bus_truth,
    bypass_applied,
    connect,
    embedded_secret_lines,
    exit_on_term,
    find_embedded_core,
    keep_scope,
    port_holder,
    port_holder_pid,
    replay,
    scutil,
    service_state,
    sh,
    tooling_mentioned,
    window_open,
    yes_set,
)

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "lib")
OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/mac")
os.makedirs(OUT, exist_ok=True)
YES = yes_set()
WINDOW = window_open()
HOSTS = ("example.com:80", "httpbin.org:443")
N1_HOST = "acceptance-n1.invalid:443"
EXPECTED_STEPS = (
    "MAC-0", "MAC-1", "MAC-2", "MAC-3", "MAC-4", "MAC-5", "MAC-6", "MAC-7", "MAC-8", "MAC-9a", "MAC-9b",
    "MAC-10", "MAC-11", "MAC-12", "MAC-13", "MAC-14", "MAC-15", "MAC-16",
    "N1-MAC", "N2-MAC", "N3-MAC", "N4-MAC", "N5-MAC",
)
# `ClientInfo.name` for the ids the dry runs saw (spec D11); anything else is shown by its last component.
CLIENT_NAMES = {"com.apple.Safari": "Safari", "com.apple.WebKit.Networking": "WebKit Networking", "com.google.Chrome": "Google Chrome", "com.apple.curl": "curl"}
PENDING_WORDS = ("sending…", "queued — added when the core is back", "not added —")
STATUS_ROUTE_OFF = "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core."
STATUS_ALLAPPS_OFF = "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"

w = StepWriter(os.path.join(OUT, "mac-steps.tsv"), EXPECTED_STEPS)
step = w.step


def ax() -> str:
    return sh("bash", os.path.join(LIB, "ax_texts.sh"))


def ax_menu(m: str) -> str:
    return sh("bash", os.path.join(LIB, "ax_texts.sh"), "menu", m)


def menu(m: str, item: str) -> str:
    return sh("bash", os.path.join(LIB, "menu.sh"), m, item)


def press(label: str, prefix: bool = False) -> tuple[int, str]:
    """(exit code, output) of ax_press.sh; 4 = no such button (nothing pressed)."""
    argv = ["bash", os.path.join(LIB, "ax_press.sh")] + (["--prefix"] if prefix else []) + [label]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + (("\n[stderr] " + r.stderr.strip()) if r.returncode else "")


def type_text(text: str, enter: bool = True) -> str:
    argv = ["bash", os.path.join(LIB, "type.sh")] + ([] if enter else ["--no-return"]) + [text]
    return sh(*argv)


def save_dump(name: str, text: str) -> None:
    """An accessibility dump beside the steps, through the writer's redaction."""
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(w.redact(text))


def missing(text: str, *needles: str) -> list[str]:
    return [n for n in needles if n not in text]


BYPASS_KEY = "systemProxy.bypass"  # SystemProxyPreferences.bypassKey (apps/mac/Sources/AitmproxyKit/SystemProxyPreferences.swift)


def mac_bypass_field() -> str:
    """The Settings ▸ Proxy "Bypass hosts" field as stored (the ONE key, not the whole defaults
    domain); empty when the key has never been written (the app then shows its recommended
    default, but the D2 reading is the stored key)."""
    r = subprocess.run(["defaults", "read", "com.mrbrutti.aitmproxy", BYPASS_KEY], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def mac_bypass_ok() -> bool:
    """The app passes its Settings ▸ Proxy "Bypass hosts" field: a tooling host must be in it."""
    return tooling_mentioned(mac_bypass_field())


def core_holds_8080(core) -> str | None:
    """None when the app's embedded core is the LISTEN holder of 8080; else the reason to SKIP."""
    pid = port_holder_pid(8080)
    if pid == core.pid:
        return None
    return f"8080 holder is {port_holder(8080) or 'nobody'}, not this app's core pid {core.pid}; a yes press would act on the wrong core"


def open_scope_sheet() -> bool:
    """Proxy ▸ Scope… navigates to the page first; a second press opens the Edit Scope sheet."""
    for _ in range(2):
        menu("Proxy", "Scope…")
        time.sleep(1.0)
        if "Host to add to scope" in ax():
            return True
    return False


SCOPE_FIELD_DESC = "Host to add to scope"
SCOPE_FIELD_ID = "scope-add-host"   # the identifier the mac fix adds; the description is the fallback


def click_scope_field() -> bool:
    """Give the Edit Scope sheet's field the focus by clicking its centre (a real click through
    System Events), located by accessibility identifier when present, else by description. The
    sheet does not focus the field itself when Scope already has hosts (run 5, MAC-5)."""
    centre = field_center(ax(), SCOPE_FIELD_DESC, SCOPE_FIELD_ID)
    if centre is None:
        return False
    out = sh("bash", os.path.join(LIB, "click.sh"), str(centre[0]), str(centre[1]))
    time.sleep(0.4)
    return "clicked" in out


def field_focused() -> bool:
    """Type one harmless digit, read it back from the text field, clear it. When the digit is NOT
    read back the focus is somewhere unknown: nothing more is sent there (no ⌘A/Delete either)."""
    sh("bash", os.path.join(LIB, "type.sh"), "--probe")
    time.sleep(0.3)
    dump = ax()
    ok = any(r.startswith("AXTextField") and "\t1\t" in r for r in dump.splitlines())
    if ok:
        sh("bash", os.path.join(LIB, "type.sh"), "--clear")
    return ok


def capture_loop(stop: threading.Event, folder: str, bounds: str) -> None:
    """~4 fps `screencapture -R <window bounds>` into folder until stop (N1's transient state)."""
    os.makedirs(folder, exist_ok=True)
    i = 0
    while not stop.is_set():
        subprocess.run(["screencapture", "-x", "-o", "-R", bounds, os.path.join(folder, f"{i:03d}.png")], capture_output=True)
        i += 1
        time.sleep(0.25)


def main() -> int:  # noqa: C901 — one journey, in the operator's order
    exit_on_term()
    step("MAC-0", "SKIP", "release run only; brew upgrade is Matt's")
    step("N3-MAC", "SKIP", "CA stays trusted (un-trusting is Matt's yes; words read from source)")
    step("N4-MAC", "SKIP", "needs a plain 8080 listener before launch — yes (it blocks his app's core)")
    step("N5-MAC", "SKIP", "hand: Settings ▸ Bus field")
    ver = app_version()
    try:
        core = find_embedded_core()
    except RuntimeError as e:
        step("MAC-1", "SKIP", str(e))
        w.finish()
        return w.exit_code()
    if core is None:
        step("MAC-1", "SKIP", f"the app is not running (bundle {ver}); launch is a hand step (open -a Aitmproxy)" + (" — the window is open but the harness never launches his app" if WINDOW else ""))
        w.finish()
        return w.exit_code()
    w.add_secret(core.operator_token)
    for sec in embedded_secret_lines(core):
        w.add_secret(sec)
    bus = connect(core)
    truth0 = bus_truth(bus)
    ps = truth0.get("proxy.status", {})
    with open(os.path.join(OUT, "mac-bus-truth-start.json"), "w", encoding="utf-8") as f:
        f.write(w.redact(json.dumps(truth0, indent=1, sort_keys=True)))
    t0 = int(time.time() * 1000)

    # Read-only AX dump of whatever the window shows, for the report (no press).
    dump = ax()
    save_dump("MAC-ax-initial.txt", dump)
    sc = truth0.get("scope.list", [])
    cap = truth0.get("capture.status", {})
    sp = truth0.get("proxy.system.status", {})
    expected_status = []
    if sp.get("state") == "off":
        expected_status.append(STATUS_ROUTE_OFF)
    elif sp.get("state") == "points_at_us":
        expected_status.append(f"system proxy on · {sp.get('ours', {}).get('host')}:{sp.get('ours', {}).get('port')}")
    if cap.get("enabled") and cap.get("provider", {}).get("state") == "attached":
        expected_status.append("All Apps is on")
    elif not cap.get("enabled"):
        expected_status.append(STATUS_ALLAPPS_OFF)
    if not sc:
        expected_status.append("Add a host to Scope (for now as example.com:443)")

    lanes = ""
    if WINDOW:
        menu("Proxy", "Status")
        time.sleep(1.2)
        dump = ax()
        save_dump("MAC-3-ax.txt", dump)
        lanes = "; lane words: " + ", ".join(f"'{wd}' {wd in dump}" for wd in ("running", "connected", "operator ·"))
        if "Paste the operator token in Settings ▸ Bus" in dump:
            lanes += "; ROLE-WARNING lane present (connected as <role>)"
    ok1 = ps.get("listening") is True and bool(ps.get("version")) and "Paste the operator token in Settings ▸ Bus" not in dump
    step("MAC-1", "PASS" if ok1 else "FAIL",
         f"app running (bundle {ver}); embedded core pid {core.pid} listening {ps.get('address')} version {ps.get('version')}" + ("" if ver == ps.get("version") else f" — bundle plist {ver} differs from the running core {ps.get('version')}") + lanes,
         f"proxy.status.listening {ps.get('listening')}, version {ps.get('version')}; start marker in audit: {any(r.get('marker') == 'start' and r.get('pid') == core.pid for r in audit_tail(400))}")

    if not WINDOW:
        for sid in ("MAC-2", "MAC-3", "MAC-4"):
            step(sid, "SKIP", "needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: " + " | ".join(expected_status),
                 f"scope.list {sc}; capture enabled {cap.get('enabled')} provider {cap.get('provider', {}).get('state')}; system proxy {sp.get('state')}")
        step("N2-MAC", "SKIP", "needs the window (judged from the MAC-3 read)")
    else:
        sheet = "Set up aitmproxy on this Mac" in dump
        if sheet:
            ca_row = "CA trusted (user keychain)" if truth0.get("ca.status", {}).get("stores", {}).get("user", {}).get("trusted") == "yes" else "HTTPS is not captured until the CA is trusted"
            miss = missing(dump, "Set aitmproxy as the system proxy", "Trust the aitmproxy CA", ca_row, "Nothing is decrypted until a host is in Scope")
            step("MAC-2", "PASS" if not miss else "FAIL", f"first-run sheet shown; missing {miss}", f"ca.status user trusted {truth0.get('ca.status', {}).get('stores', {}).get('user', {}).get('trusted')}")
            menu("Proxy", "Status")  # the sheet's Not Now is a hand step; leave it and read behind it if possible
        else:
            step("MAC-2", "PASS", "first-run sheet not shown (already dismissed or every row done); recorded as such")
        miss = missing(dump, *expected_status)
        step("MAC-3", "PASS" if not miss else "FAIL", f"Status page words present: {[x for x in expected_status if x not in miss]}; missing: {miss}", f"scope.list {sc}; capture {cap.get('enabled')}/{cap.get('provider', {}).get('state')}; system proxy {sp.get('state')}")
        flows = truth0.get("flow.table", {}).get("flows", [])
        step("MAC-4", "PASS" if (flows or "No flows yet" in dump) else "FAIL", "rows exist: banner case applies" if flows else f"'No flows yet' present {'No flows yet' in dump}", f"flow.table rows {len(flows)}")
        # N2 — no route with a host in Scope: the words are what is judged (zero rows is correct).
        if sc and sp.get("state") == "off" and not cap.get("enabled"):
            miss = missing(dump, STATUS_ROUTE_OFF, "All Apps off — turn it on")
            step("N2-MAC", "PASS" if not miss else "FAIL", f"Scope has {len(sc)} host(s), no route; closed-route words present, missing {miss}", f"scope.list {sc}; proxy.system.status off; capture enabled false")
        else:
            step("N2-MAC", "SKIP", f"not the N2 state: scope {len(sc)} host(s), system proxy {sp.get('state')}, All Apps {cap.get('enabled')}")

    # MAC-5 — add the hosts on the Scope page through the Edit Scope sheet (window; auto).
    scope_before = list(sc) if isinstance(sc, list) else []
    added: list[str] = []
    targets = [h for h in HOSTS if h not in scope_before]
    pre = [h for h in HOSTS if h in scope_before]
    if not WINDOW:
        step("MAC-5", "SKIP", f"needs the window (ACCEPT_WINDOW=1): types into the Edit Scope sheet; hosts {HOSTS}" + (f"; already in Scope before the run: {pre}" if pre else ""))
    elif not targets:
        step("MAC-5", "PASS", f"both hosts were already in Scope before the run ({pre}); nothing typed, nothing to remove later", f"scope.list {sc}")
    elif not open_scope_sheet():
        step("MAC-5", "FAIL", "Proxy ▸ Scope… (twice) did not show the Edit Scope sheet's field 'Host to add to scope'; nothing typed")
    elif not (click_scope_field() and field_focused()):
        step("MAC-5", "FAIL", "the sheet's field did not take the focus probe (typed '1' not read back); refusing to type into an unknown target")
    else:
        for h in targets:
            type_text(h)
            added.append(h)
            time.sleep(2.0)
        sc2 = bus.call("scope.list", {})
        dump = ax()
        save_dump("MAC-5-ax.txt", dump)
        listed = [h for h in targets if h in sc2]
        shown = [h for h in targets if h in dump]
        pend = [x for x in PENDING_WORDS if x in dump]
        err = "add to scope:" in dump
        rows = [r for r in audit_tail(200) if r.get("command") == "scope.add" and r.get("result") == "ok" and r.get("at", 0) >= t0]
        ok5 = len(listed) == len(targets) and len(shown) == len(targets) and not pend and not err
        step("MAC-5", "PASS" if ok5 else "FAIL", f"typed {targets}" + (f" (already in Scope before: {pre})" if pre else "") + f"; rows shown {shown}; pending words {pend}; status-bar error {err}", f"scope.list now {sc2}; audit scope.add ok since start: {len(rows)}")

    before_sc, before_svc = scutil(), service_state()
    set_by_us = False
    cap_by_us = False
    try:
        # MAC-6 — Set as System Proxy (yes).
        hold = core_holds_8080(core)
        if "MAC-6" not in YES or not WINDOW:
            step("MAC-6", "SKIP", "needs Matt's yes (ACCEPT_YES=MAC-6) and the window")
        elif not mac_bypass_ok():
            fld = mac_bypass_field()
            step("MAC-6", "SKIP", "bypass list absent in the app's Settings ▸ Proxy Bypass hosts" + (f" (defaults key {BYPASS_KEY} = {fld[:80]!r})" if fld else f" (defaults key {BYPASS_KEY} never written: the field shows the app's recommended default, but the D2 reading is the stored key — save the field once in Settings)") + "; add the operator's tooling there first")
        elif hold:
            step("MAC-6", "SKIP", hold)
        else:
            print(f"== window MAC-6 start {time.strftime('%H:%M:%S')}", flush=True)
            set_by_us = True  # armed BEFORE the press: a crash mid-press still reaches the restore trap
            pressed = menu("Proxy", "Set as System Proxy")
            time.sleep(3)
            sp2 = bus.call("proxy.system.status", {})
            sc_now = scutil()
            items = ax_menu("Proxy")
            applied = bypass_applied(sc_now)
            ok = sp2.get("state") == "points_at_us" and sp2.get("managed_by_us") is True and "HTTPPort : 8080" in sc_now and applied and "Restore System Proxy" in items
            if not applied:
                menu("Proxy", "Restore System Proxy")
                time.sleep(3)
                set_by_us = scutil() != before_sc
                step("MAC-6", "FAIL", f"bypass not applied: ExceptionsList lacks the tooling hosts after the flip; restored at once (scutil identical {not set_by_us})", f"proxy.system.status {sp2.get('state')} managed_by_us {sp2.get('managed_by_us')}")
            else:
                step("MAC-6", "PASS" if ok else "FAIL", f"{pressed.strip()}; menu now has Restore System Proxy: {'Restore System Proxy' in items}; scutil 8080: {'HTTPPort : 8080' in sc_now}; bypass applied: True", f"proxy.system.status {sp2.get('state')} managed_by_us {sp2.get('managed_by_us')}")
            print(f"== window MAC-6 end {time.strftime('%H:%M:%S')}", flush=True)

        # MAC-7 — Capture All Apps (yes); already on → the words come from the window.
        if cap.get("enabled"):
            tr = f"capture.status enabled {cap.get('enabled')} feeder {cap.get('feeder', {}).get('state')} provider {cap.get('provider', {}).get('state')} handed off {cap.get('flows_handed_off')}"
            if not WINDOW:
                step("MAC-7", "SKIP", "All Apps already on at start; needs the window to read 'All Apps is on' on the Status page", tr)
            else:
                menu("Proxy", "Status")
                time.sleep(1.2)
                dump = ax()
                on = "All Apps is on" in dump
                step("MAC-7", "PASS" if on and cap.get("provider", {}).get("state") == "attached" else "FAIL", f"All Apps already on at start; Status page shows 'All Apps is on': {on}", tr)
        elif "MAC-7" not in YES or not WINDOW:
            step("MAC-7", "SKIP", "needs Matt's yes (ACCEPT_YES=MAC-7) and the window")
        elif hold:
            step("MAC-7", "SKIP", hold)
        else:
            pressed = menu("Proxy", "Capture All Apps")
            cap_by_us = True
            time.sleep(4)
            cap2 = bus.call("capture.status", {})
            menu("Proxy", "Status")
            time.sleep(1.2)
            dump = ax()
            word = "All Apps is on" in dump or "All Apps waiting for approval" in dump
            step("MAC-7", "PASS" if cap2.get("enabled") and cap2.get("feeder", {}).get("state") == "listening" and word else "FAIL", f"{pressed.strip()}; Status word present {word}", f"capture.status {json.dumps({k: cap2.get(k) for k in ('enabled', 'capability', 'feeder', 'provider')})}")

        # MAC-8 — real browser rows (hand).
        route = w.results.get("MAC-6") == "PASS" or w.results.get("MAC-7") == "PASS"
        if w.results.get("MAC-5") != "PASS" or not route:
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

        # MAC-9a — Apps sidebar words from the window; MAC-9b from the bus.
        flows = bus.call("flow.table", {}).get("flows", [])
        ne = [r for r in flows if r.get("capture_interface") == "macos-ne"]
        proxied = [r for r in flows if r.get("capture_interface") is None]
        apps = sorted({r.get("source_app") for r in ne if r.get("source_app")})
        tr9 = f"flow.table: {len(ne)} macos-ne rows, source_app set on {sum(1 for r in ne if r.get('source_app'))}: {apps}"
        if not ne:
            step("MAC-9a", "BLOCKED" if w.results.get("MAC-8") != "PASS" else "FAIL", "no extension-captured rows (All Apps on but Scope empty → the extension claims nothing)" if cap.get("enabled") else "All Apps off", f"capture.status flows_handed_off {cap.get('flows_handed_off')}")
        elif not WINDOW:
            step("MAC-9a", "SKIP", f"needs the window to read the Apps sidebar; expected group names {[CLIENT_NAMES.get(a, a.rsplit('.', 1)[-1]) for a in apps]}", tr9)
        else:
            prc, pout = press("Apps", prefix=True)  # the sidebar title may carry a count ("Apps 3")
            time.sleep(1.2)
            dump = ax()
            save_dump("MAC-9a-ax.txt", dump)
            names = [CLIENT_NAMES.get(a, a.rsplit(".", 1)[-1]) for a in apps]
            rows_seen = {n: any(n in ln and any(ch.isdigit() for ch in ln) for ln in dump.splitlines()) for n in names}
            step("MAC-9a", "PASS" if prc == 0 and names and all(rows_seen.values()) and all(r.get("source_app") for r in ne) else "FAIL", f"sidebar press: {pout.strip()[:80] if prc == 0 else f'no Apps button (exit {prc})'}; Apps rows with a count: {rows_seen}; chevrons present {('Expand ' in dump) or ('Collapse ' in dump)}", tr9, "" if all(rows_seen.values()) else "#272 Apps tree (in 0.5.11) / mac-app-icons-and-names spec decides WebKit Networking vs Safari")
        if proxied:
            attributed = sum(1 for r in proxied if r.get("source_app"))
            step("MAC-9b", "PASS" if attributed == len(proxied) else "FAIL", f"{len(proxied)} proxied rows, {attributed} carry a source_app → Apps sidebar shows {'them' if attributed else 'NOTHING for them'}", f"flow.table source_app null ×{len(proxied) - attributed}", "" if attributed else "missing feature: attribution for proxied flows (session core-name-the-client-app)")
        else:
            step("MAC-9b", "BLOCKED", "no proxied rows to judge")

        # MAC-10/11/12 — intercept (window + hand).
        if not (WINDOW and is_manual() and w.results.get("MAC-8") == "PASS"):
            for sid in ("MAC-10", "MAC-11", "MAC-12"):
                step(sid, "BLOCKED" if w.results.get("MAC-8") != "PASS" else "SKIP", "needs MAC-8 rows, the window and a hand (reload in Safari)")
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

        # MAC-13 — Restart Core (window only: it restarts his core, changes nothing on the Mac);
        # N1-MAC rides the same restart when a hand is present (add within ~1 s after a focus re-probe, frames captured).
        if not WINDOW:
            step("MAC-13", "SKIP", "needs the window (ACCEPT_WINDOW=1): Proxy ▸ Restart Core; Scope must survive")
            step("N1-MAC", "SKIP", "needs the window and --manual (Restart Core, then an add within ~1 s after a focus re-probe)")
        else:
            sc_before = bus.call("scope.list", {})
            n1 = is_manual() and open_scope_sheet() and click_scope_field() and field_focused()
            stop = threading.Event()
            if n1:
                bounds = sh("bash", os.path.join(LIB, "ax_texts.sh"), "bounds").strip()
                threading.Thread(target=capture_loop, args=(stop, os.path.join(OUT, "N1-frames"), bounds), daemon=True).start()
                time.sleep(0.5)
            menu("Proxy", "Restart Core")
            n1_focus = None
            if n1:
                # Re-probe the focus AFTER the restart press (one digit + AX read): the restart may have moved
                # it. Seen → paste + Return (the add lands while the core is still coming back); not seen →
                # send NOTHING more (a blind paste could land in a persisting field such as Settings' bypass).
                n1_focus = click_scope_field() and field_focused()
                if n1_focus:
                    type_text(N1_HOST, enter=True)
            time.sleep(6)
            stop.set()
            core2 = None
            try:
                core2 = find_embedded_core()
            except RuntimeError:
                pass
            bus2 = connect(core2) if core2 else None
            sc_after = bus2.call("scope.list", {}) if bus2 else None
            dump = ax()
            save_dump("MAC-13-ax.txt", dump)
            kept = sc_after is not None and all(h in sc_after for h in sc_before)
            ok = bus2 is not None and bus2.call("proxy.status", {}).get("listening") is True and kept
            step("MAC-13", "PASS" if ok and "Embedded core failed" not in dump else "FAIL", f"new core pid {core2.pid if core2 else None}; Scope rows kept {kept}; stale failed banner present {'Embedded core failed' in dump}", f"scope.list before {sc_before} after {sc_after}")
            if not is_manual():
                step("N1-MAC", "SKIP", "needs --manual (a hand watches the restart) — the restart itself ran as MAC-13")
            elif not n1:
                step("N1-MAC", "SKIP", "the Edit Scope sheet did not open / take focus before the restart; no add attempted")
            elif not n1_focus:
                step("N1-MAC", "SKIP", f"the focus probe after Restart Core was not seen in the sheet's field; nothing was pasted — only the probe digit `1` went to the then-focused field: clear it by hand if it is visible; frames in N1-frames/", f"scope.list after restart {sc_after}")
            else:
                landed = bool(sc_after) and N1_HOST in sc_after
                if landed:
                    added.append(N1_HOST)
                named = "add to scope:" in dump or "not added —" in dump
                pend = [x for x in PENDING_WORDS if x in dump and x != "not added —"]
                if landed and not pend:
                    step("N1-MAC", "PASS", f"the add during the restart landed on the new core ({N1_HOST} listed, no pending row); frames in N1-frames/", f"scope.list after restart contains {N1_HOST}")
                elif named and N1_HOST not in dump:
                    step("N1-MAC", "PASS", "the add failed and an error names it; the row is removed", f"scope.list after restart {sc_after}")
                else:
                    step("N1-MAC", "FAIL", f"after the restart: host listed on the core {landed}; row still shown {N1_HOST in dump}; pending words {pend}; error named {named}", f"scope.list after restart {sc_after}", "#274 merged after the tag, unreleased" if ver == "0.5.11" else "S-081 / PR #274")
            if bus2 and core2:
                bus = bus2
                core = core2
                w.add_secret(core2.operator_token)
                for sec in embedded_secret_lines(core2):
                    w.add_secret(sec)

        # MAC-14 — Stop Capturing (yes; only if we turned it on).
        hold = core_holds_8080(core)
        if not cap_by_us:
            step("MAC-14", "SKIP", "All Apps was already on at start (operator's state) — not turned off by the run" if cap.get("enabled") else "MAC-7 did not run")
        elif "MAC-14" not in YES:
            step("MAC-14", "SKIP", "needs Matt's yes (ACCEPT_YES=MAC-14)")
        elif hold:
            step("MAC-14", "SKIP", hold)
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
        elif hold:
            step("MAC-15", "SKIP", hold + " — the trap will restore")
        else:
            menu("Proxy", "Restore System Proxy")
            time.sleep(3)
            sp3 = bus.call("proxy.system.status", {})
            same = scutil() == before_sc
            items = ax_menu("Proxy")
            step("MAC-15", "PASS" if same and sp3.get("managed_by_us") is False and "Set as System Proxy" in items else "FAIL", f"scutil identical to before {same}; menu back to Set as System Proxy {'Set as System Proxy' in items}", f"proxy.system.status {sp3.get('state')} managed_by_us {sp3.get('managed_by_us')}")
            if same:
                set_by_us = False
        step("MAC-16", "SKIP", "the app was already running at start; not quit by the run (Matt's app)")
    finally:
        # Scope cleanup: exactly the hosts this run added, through the Scope page's own button.
        if added:
            if keep_scope():
                for h in added:
                    append_leftover(OUT, h, "kept", "mac")
            else:
                done: set[str] = set()
                try:
                    menu("Proxy", "Scope…")  # the page; the row's context menu is never attempted (a hand's job)
                    time.sleep(1.0)
                    for h in added:
                        if h in scope_before:
                            done.add(h)
                            continue
                        prc, pout = press(f"Remove {h} from Scope")
                        if prc != 0:
                            append_leftover(OUT, h, f"failed (no 'Remove {h} from Scope' button on the Scope page: {pout.strip().splitlines()[-1][:80] if pout.strip() else f'exit {prc}'}; remove by hand)", "mac")
                            done.add(h)
                            continue
                        time.sleep(1.5)
                        now = bus.call("scope.list", {})
                        append_leftover(OUT, h, "removed" if h not in now else "failed (pressed, still in scope.list)", "mac")
                        done.add(h)
                except Exception as e:  # noqa: BLE001 — the report lists what is left
                    for h in added:
                        if h not in done:
                            append_leftover(OUT, h, f"failed ({type(e).__name__}: {str(e)[:60]})", "mac")
        if set_by_us:
            print("== restore trap: MAC-6 set the system proxy and MAC-15 did not restore it; Restore via the app, then replay the recorded state", flush=True)
            try:
                menu("Proxy", "Restore System Proxy")
                time.sleep(3)
            except Exception:  # noqa: BLE001
                pass
            errs = replay(before_svc) if scutil() != before_sc else []
            same = scutil() == before_sc
            step("RESTORE", "PASS" if same and not errs else "FAIL", f"restored; scutil identical {same}; errors {errs}")
        elif scutil() != before_sc:
            step("DRIFT", "FAIL", "the system proxy changed during the run by another actor; the harness set nothing and touched nothing — left as is", scutil()[:200])
        if cap_by_us:
            print("== restore trap: All Apps was turned on by the run and not turned off — leftover for the report", flush=True)
        w.finish()
    return w.exit_code()


if __name__ == "__main__":
    sys.exit(main())
