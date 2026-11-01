#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=ws
"""The bundled passive catalogue still fires on real proxied traffic, Vulnerable
vs Patched (T10 spec S10; parent AC T10-3) — with NO scanner engine and NO
`scan.*` call at all. The observer is the core's own `script.findings` after real
MITM'd HTTPS and real cleartext `ws://` traffic through the proxy.

  - A real `curl --cacert <core CA> -x <proxy> https://<V tls>/` (the MITM path;
    `missing-hsts` only fires on `https://`) plus a real cleartext `ws://<V>/ws`
    echo conversation through the proxy make the three bundled passive scripts
    `missing-hsts`, `missing-csp`, `ws-cleartext-transport` each record a finding
    on V's host.
  - The same two actions against the PATCHED target add NONE of the three for P's
    host (P sends HSTS + CSP, so the header scripts stay silent; its `/ws` requires
    a session so no cleartext WebSocket flow is established). Two assertions close
    the attribution hole: no finding from the three scripts attributes to a P host,
    AND every finding from them that arrived after the V phase attributes to V (a
    P finding whose flow cannot be resolved and whose detail lacks the host would
    otherwise slip through as "not P").

Before polling, the cell asserts on the core's OWN flow store that the ws://
conversation went through it (the 101 handshake flow to V's plain listener and the
websocket-kind flow spawned from it), so a missing script finding is attributable
to the script, never to the traffic; on a miss it prints the script's
`script.list` row (`enabled`, `hooks`, `last_error`) and every finding `source`
seen before failing.

This cell imports `ScanTarget` from `aitm_e2e.scan` only; it calls no `scan.*`
verb, so its ledger file is `calls: []`. `script.findings` / `flow.get` /
`script.list` are plain bus reads, not scan verbs.

SKIPs 77 when the bundled catalogue is not loaded (no `script.findings` /
`script.list`, or the three scripts are absent) or `curl` is missing. Do NOT set
`AITM_NO_BUNDLED_SCRIPTS`. Binds loopback ports: run from a real shell, not the
Claude sandbox. Exit 0 pass / 1 fail / 77 skip. Never prints a token.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e import tls  # noqa: E402
from aitm_e2e.bus import BusClient, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import ScanTarget  # noqa: E402
from aitm_e2e.ws import WsClient  # noqa: E402

SCRIPT_IDS = ("missing-hsts", "missing-csp", "ws-cleartext-transport")
POLL_V_S = 10.0     # poll window for V's findings (spec S10)
SETTLE_P_S = 3.0    # let any P finding land before asserting none did


def findings_now(op: BusClient) -> list[dict]:
    r = op.call("script.findings", {})
    return r.get("findings", []) if isinstance(r, dict) else []


def flow_authority(op: BusClient, fid: str, cache: dict) -> str | None:
    if fid not in cache:
        try:
            s = op.call("flow.get", {"id": fid})
        except ToolError:
            s = None
        cache[fid] = s.get("authority") if isinstance(s, dict) else None
    return cache[fid]


def on_host(op: BusClient, finding: dict, host: str, cache: dict) -> bool:
    """True when a finding belongs to `host`: either the finding's flow authority
    equals it (HTTP findings), or the host appears in the finding detail (the
    `ws://host/..` URL the cleartext-transport script records; a WebSocket flow's
    own authority is null)."""
    fid = finding.get("flow_id")
    if fid and flow_authority(op, fid, cache) == host:
        return True
    return host in (finding.get("detail") or "")


def fired_for(op: BusClient, sid: str, hosts: tuple[str, ...], findings: list[dict], cache: dict) -> list[dict]:
    return [f for f in findings
            if f.get("source") == sid and any(on_host(op, f, h, cache) for h in hosts)]


def flow_ids(result) -> list:
    if isinstance(result, dict):
        for k in ("flows", "ids", "items"):
            if k in result:
                result = result[k]
                break
    if isinstance(result, list):
        return [i.get("id", i) if isinstance(i, dict) else i for i in result]
    return []


def wait_ws_capture(op: BusClient, authority: str, timeout: float) -> tuple[dict | None, dict | None]:
    """The core's own record that the ws:// conversation went through it: the
    101 handshake flow to `authority` `/ws` and, when present, the websocket-kind
    flow spawned from it (its `handshake` field, via flow.get or flow.detail)."""
    deadline = time.monotonic() + timeout
    seen: dict = {}
    while time.monotonic() < deadline:
        for fid in reversed(flow_ids(op.call("flow.list"))):
            s = seen.get(fid)
            if s is None or (s.get("kind") == "http" and s.get("status") is None):
                try:
                    s = op.call("flow.get", {"id": fid})
                except ToolError:
                    continue
                if not isinstance(s, dict):
                    continue
                seen[fid] = s
            if (s.get("kind") == "http" and s.get("authority") == authority
                    and (s.get("path") or "").startswith("/ws") and s.get("status") == 101):
                ws = None
                for cand in seen.values():
                    if cand.get("kind") == "websocket" and cand.get("handshake") == s.get("id", fid):
                        ws = cand
                if ws is None:
                    for cand_id, cand in seen.items():
                        if cand.get("kind") != "websocket":
                            continue
                        try:
                            d = op.call("flow.detail", {"id": cand_id})
                        except ToolError:
                            continue
                        if isinstance(d, dict) and d.get("handshake") == s.get("id", fid):
                            ws = dict(cand, handshake=d.get("handshake"))
                            break
                return s, ws
        time.sleep(0.2)
    return None, None


def script_row(op: BusClient, name: str) -> dict:
    for s in op.call("script.list") or []:
        if isinstance(s, dict) and s.get("name") == name:
            return s
    return {}


def drive_https(proxy: str, ca: str, authority: str, label: str) -> None:
    rc, code, _ = tls.curl_code(["-x", proxy, "--cacert", ca, f"https://{authority}/"])
    check(rc == 0 and code == 200,
          f"{label}: curl --cacert through the proxy to https://{authority}/ = 200 (rc={rc} http={code})")


def drive_ws(proxy_host: str, proxy_port: int, authority: str, label: str, *, expect_upgrade: bool) -> None:
    """One cleartext ws:// echo conversation through the proxy. On V the upgrade
    succeeds (any Origin, no session); on P it is refused (no session), which is
    the point — no cleartext WebSocket flow is established for P."""
    host, _, port = authority.rpartition(":")
    try:
        client = WsClient(proxy_host, proxy_port, host, int(port), path="/ws")
    except Exception as e:  # noqa: BLE001  (P refuses the upgrade; that is expected)
        if expect_upgrade:
            fail(f"{label}: the cleartext ws:// upgrade through the proxy failed: {e}")
        else:
            ok(f"{label}: the cleartext ws:// upgrade was refused (no session) as expected ({e})")
        return
    try:
        client.send_text(json.dumps({"type": "echo", "msg": "hi"}))
        client.recv(timeout=5)
        ok(f"{label}: cleartext ws:// echo conversation through the proxy established")
    finally:
        client.close()


def main() -> int:
    if not tls.have("curl"):
        skip("curl not found: the MITM HTTPS path needs curl --cacert")
    try:
        v = ScanTarget("vulnerable", tls=True, control=True)
        p = ScanTarget("patched", tls=True, control=True)
    except FileNotFoundError as e:
        skip(str(e))
        return 77

    core = op = None
    try:
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[v.tls_authority, v.authority, p.tls_authority, p.authority],
            ssl_insecure=True,
        )
        core = Aitm.server(cfg)
        op = BusClient.operator(core)

        section("the bundled passive catalogue is loaded")
        tools = set(op.tool_names())
        if "script.findings" not in tools or "script.list" not in tools:
            skip("bundled catalogue not loaded: no script.findings / script.list on this core")
        listed = {s.get("name") for s in (op.call("script.list") or []) if isinstance(s, dict)}
        missing = [n for n in SCRIPT_IDS if n not in listed]
        if missing:
            skip(f"bundled catalogue not loaded: missing scripts {missing}")
        ok(f"script.findings + the three bundled scripts are present ({', '.join(SCRIPT_IDS)})")

        proxy = f"http://127.0.0.1:{cfg.proxy_port}"
        ca = tls.ca_cert(core)
        v_hosts = (v.tls_authority, v.authority)
        p_hosts = (p.tls_authority, p.authority)

        section("drive real MITM'd HTTPS + cleartext ws:// against the VULNERABLE target")
        drive_https(proxy, ca, v.tls_authority, "V")
        drive_ws("127.0.0.1", cfg.proxy_port, v.authority, "V", expect_upgrade=True)

        section("the core's own flow store holds the ws:// conversation (so a miss below is the script's, not the traffic's)")
        hs, wsf = wait_ws_capture(op, v.authority, POLL_V_S)
        check(hs is not None,
              f"V: the core captured the 101 handshake flow to {v.authority}/ws "
              f"(id {(hs or {}).get('id')!r})")
        if wsf is not None:
            ok(f"V: a websocket-kind flow {wsf.get('id')!r} was spawned from that handshake "
               f"(flow.get authority={wsf.get('authority')!r})")
        else:
            print("note: no websocket-kind flow linked to the handshake was visible via flow.get/flow.detail",
                  flush=True)

        section("poll script.findings: all three bundled scripts fire on V's host")
        present: set[str] = set()
        fs: list[dict] = []
        deadline = time.monotonic() + POLL_V_S
        while time.monotonic() < deadline:
            cache: dict = {}
            fs = findings_now(op)
            present = {sid for sid in SCRIPT_IDS if fired_for(op, sid, v_hosts, fs, cache)}
            if present == set(SCRIPT_IDS):
                break
            time.sleep(0.3)
        for sid in SCRIPT_IDS:
            if sid in present:
                ok(f"V: bundled `{sid}` recorded a finding on V's host")
                continue
            # Diagnostics before the FAIL: is the script loaded and error-free, and
            # did ANY finding from it exist (an attribution miss) or none at all (the
            # hook never produced one)?
            row = script_row(op, sid)
            print(f"diag: script.list[{sid}] enabled={row.get('enabled')!r} hooks={row.get('hooks')!r} "
                  f"last_error={row.get('last_error')!r}", flush=True)
            same_source = [f for f in fs if f.get("source") == sid]
            print(f"diag: findings with source == {sid!r}: {len(same_source)} "
                  f"(details: {[f.get('detail') for f in same_source][:3]!r}); "
                  f"all sources seen: {sorted({str(f.get('source')) for f in fs})}", flush=True)
            if sid == "ws-cleartext-transport" and not same_source:
                print("diag: ws-cleartext-transport guards on `flow.request.url.starts_with(\"ws://\")` in "
                      "on_ws_start, but a WebSocket flow has no request in the Rhai flow API "
                      "(crates/aitm-plugin-rhai/src/flow_api.rs NO_REQUEST: reads return \"\"), so the "
                      "guard cannot be true on a live WS flow -- a bundled-script/engine gap, not a traffic gap",
                      flush=True)
            check(False, f"V: bundled `{sid}` recorded a finding on V's host")

        section("the same two actions against the PATCHED target add none of the three")
        # Snapshot BEFORE the P traffic: `script.findings` is oldest-first, so every
        # finding past this index arrived during (or after) the P phase.
        n_before_p = len(findings_now(op))
        drive_https(proxy, ca, p.tls_authority, "P")
        drive_ws("127.0.0.1", cfg.proxy_port, p.authority, "P", expect_upgrade=False)
        time.sleep(SETTLE_P_S)
        cache = {}
        fs = findings_now(op)
        for sid in SCRIPT_IDS:
            hits = fired_for(op, sid, p_hosts, fs, cache)
            check(hits == [], f"P: bundled `{sid}` fired zero times on P's host (got {len(hits)})")
        new_three = [f for f in fs[n_before_p:] if f.get("source") in SCRIPT_IDS]
        stray = [(f.get("source"), f.get("flow_id"), (f.get("detail") or "")[:60]) for f in new_three
                 if not any(on_host(op, f, h, cache) for h in v_hosts)]
        check(not stray,
              f"P: every finding from the three scripts that arrived after the V phase attributes to V "
              f"({len(new_three)} new; unattributed: {stray or 'none'})")
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        p.stop()
        v.stop()

    ok("T10-3: the bundled passive catalogue fires on V and stays silent on P, via real proxied traffic")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
