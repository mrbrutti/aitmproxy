#!/usr/bin/env python3
# e2e: tier=T1 surface=flow
"""source_app / capture_interface on the wire for a PROXIED flow: `capture_interface`
is null, `source_app` is null or a real client name, and the three read surfaces agree
(spec 2026-10-31-ne-source-app-on-the-wire SA-AC1 + SA-AC2 as amended by spec
2026-11-01-proxied-client-attribution D7/D8; plan Task 8).

Until proxied client attribution this cell asserted BOTH keys null on a proxied flow.
The core now names the loopback client of an explicit-proxy connection itself (spec
D7: `source_app` set + `capture_interface` null means "the core named the client";
both null means it could not: non-loopback peer, other user, budget missed,
rate-limited, unsupported OS). So the honest statement for a proxied flow is:

 1. `flow.get` carries BOTH keys, each PRESENT (never absent): `capture_interface` is
    `null` (no capture backend delivered the connection), `source_app` is either
    `null` or a non-empty string that is not a placeholder ("unknown", "proxy", "");
 2. the `flow.table` row for the same flow carries the same two keys with the SAME
    values as `flow.get`;
 3. the `flow.subscribe` push (`notifications/aitm/flow`, event=created) for that flow
    carries the same two keys in `params.summary` with the same values — the push
    summary, the row and `flow.get` agree key for key;
 4. every row `flow.table` returns has both keys (the keys are kind-independent), no
    row shows a placeholder string for either, and `capture_interface` is null on
    every one of them (nothing here came through a capture backend);
 5. `tools/list` declares the two fields on the `flow.get` and `flow.table` result
    schemas and still says what a proxied flow reports (the word "proxied") when the
    server publishes output schemas (skipped with a note if it does not).

The positive proof that `source_app` IS the client's name (`curl`, `python3.x`,
`com.apple.python3`) on a proxied flow lives in
`tests/e2e/proxy/test_client_attribution.py` (AC10-AC13). The captured (NE) half,
`"source_app": "com.apple.Safari"` + `"capture_interface": "macos-ne"`, is SA-AC6,
verified manually on the v0.5.4 DMG; it cannot be driven here (no Network Extension
in a test process).

Core: attaches to the core the runner provides via env (AITM_BUS_ADDR,
AITM_BUS_TOKEN, AITM_PROXY_ADDR); without that contract it boots its own
dedicated core on free ports like every aitm_e2e suite.
"""

import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

FLOW_NOTE = "notifications/aitm/flow"
KEYS = ("source_app", "capture_interface")
PLACEHOLDERS = {"", "unknown", "proxy", "none", "null"}
ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_OP_TOKEN, ENV_PROXY_ADDR = (
    "AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_BUS_OPERATOR_TOKEN", "AITM_PROXY_ADDR",
)


def env_core():
    """The core the runner already booted, if it described one in the environment."""
    addr, tok, proxy = (os.environ.get(k) for k in (ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_PROXY_ADDR))
    if not (addr and tok and proxy):
        return None
    host, port = addr.rsplit(":", 1)
    _, pport = proxy.rsplit(":", 1)
    cfg = SimpleNamespace(agent_token=tok, operator_token=os.environ.get(ENV_OP_TOKEN) or None,
                          proxy_port=int(pport))
    return SimpleNamespace(bus_addr=(host.strip("[]"), int(port)), cfg=cfg, stop=lambda: None)


def table(bus):
    return bus.call("flow.table")["flows"]


def wait_flow(bus, method, marker, timeout=10.0):
    """The id of the completed flow with this method whose path carries `marker`."""
    deadline = time.time() + timeout
    while True:
        for row in table(bus):
            if row.get("method") == method and marker in (row.get("path") or "") and row.get("status") is not None:
                return row["id"]
        if time.time() > deadline:
            seen = [f"{r.get('method')} {r.get('authority')}{r.get('path')} -> {r.get('status')}" for r in table(bus)[-8:]]
            fail(f"no completed {method} flow with {marker!r} in its path within {timeout}s; last rows: {seen}")
        time.sleep(0.1)


def collect_until(bus, pred, timeout=15.0):
    """params of the flow notifications on `bus` until one satisfies `pred`
    (included) or `timeout` elapses. Returns (params, found)."""
    out = []
    pending = [m for m in bus.notifications if m.get("id") is None]
    bus.notifications.clear()
    deadline = time.time() + timeout
    while True:
        while pending:
            m = pending.pop(0)
            if m.get("method") != FLOW_NOTE:
                continue
            p = m.get("params") or {}
            out.append(p)
            if pred(p):
                return out, True
        left = deadline - time.time()
        if left <= 0:
            return out, False
        bus._set_read_timeout(max(0.05, left))
        try:
            pending.append(bus._recv())
        except (socket.timeout, TimeoutError):
            return out, False
        finally:
            bus._restore_read_timeout()


def capture_null_and_source_consistent(obj, what):
    """Both keys PRESENT on `obj` (a flow.get result, a table row, a push summary):
    `capture_interface` null (no capture backend on the explicit-proxy path);
    `source_app` null or a non-placeholder string (the core's own naming of the
    loopback client, spec D7). Returns the (source_app, capture_interface) pair so
    callers can assert the three surfaces agree."""
    for k in KEYS:
        check(k in obj, f"{what}: the `{k}` key is present (keys: {sorted(obj)[:16]})")
    ci = obj.get("capture_interface")
    check(ci is None, f"{what}: `capture_interface` is null for a proxied flow (got {ci!r})")
    sa = obj.get("source_app")
    if sa is None:
        ok(f"{what}: `source_app` is null (the core could not name the client; allowed, never a placeholder)")
    else:
        check(isinstance(sa, str) and sa.strip() != "" and sa.strip().lower() not in PLACEHOLDERS,
              f"{what}: `source_app` is a non-placeholder client name (got {sa!r})")
    return (sa, ci)


def main() -> int:
    up = Upstream().start()
    core = env_core()
    booted = core is None
    bus = sub = None
    try:
        section("arrange: an echo-record upstream + a real aitm core + a live flow.subscribe")
        if booted:
            cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                             scope_entries=[up.authority, "127.0.0.1"])
            core = Aitm.server(cfg)
            ok(f"booted a dedicated core: proxy :{cfg.proxy_port}, bus {core.bus_addr}")
        else:
            ok(f"attached to the runner's core at {core.bus_addr}")
        pp = core.cfg.proxy_port
        bus = BusClient.agent(core)
        names = set(bus.tool_names())
        for need in ("flow.table", "flow.get", "flow.subscribe"):
            check(need in names, f"the core exposes {need}")
        sub = BusClient.agent(core)
        sub.call("flow.subscribe", {})
        ok("a second agent connection subscribed to every flow")

        section("act: one real request through the explicit proxy (curl -x equivalent)")
        tag = f"sa-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        path = f"/proxied?t={tag}"
        r = via_proxy(pp, "GET", up.base + path, headers={"X-E2E": tag})
        check(r.status == 200 and "aitm-e2e-upstream" in r.text,
              f"GET through the proxy: {r.status}, the upstream's body round-tripped")
        check([(q["method"], q["path"]) for q in up.received][-1:] == [("GET", path)],
              "ground truth: the upstream recorded exactly our GET")
        fid = wait_flow(bus, "GET", path)

        section("SA-AC1 (as amended by D7/D8): flow.get and the flow.table row carry both keys; "
                "capture_interface null, source_app null or a real client name")
        s = bus.call("flow.get", {"id": fid})
        check(s.get("kind") == "http" and s.get("path") == path, f"flow.get is our flow ({s.get('kind')} {s.get('path')})")
        got_get = capture_null_and_source_consistent(s, "flow.get")
        row = next((row for row in table(bus) if row.get("id") == fid), None)
        check(row is not None, "flow.table has our row")
        got_row = capture_null_and_source_consistent(row or {}, "flow.table row")
        check(got_row == got_get,
              f"flow.table row and flow.get agree on source_app / capture_interface "
              f"(row={got_row!r}, get={got_get!r})")

        section("SA-AC2: the flow.subscribe push summary carries the same two keys with the same values")
        got, found = collect_until(sub, lambda p: p.get("id") == fid and p.get("event") == "created")
        check(found, f"a created push for our flow arrived ({[(p.get('event'), p.get('id')) for p in got][-6:]})")
        pushed = next((p.get("summary") or {} for p in got if p.get("id") == fid and p.get("event") == "created"), {})
        got_push = capture_null_and_source_consistent(pushed, "push summary (event=created)")
        check(got_push == got_get,
              f"push summary and flow.get agree on source_app / capture_interface "
              f"(push={got_push!r}, get={got_get!r})")
        # Any later event for the same flow (response) carries them too.
        later = [p.get("summary") or {} for p in got if p.get("id") == fid and p.get("event") != "created"]
        for summ in later:
            got_later = capture_null_and_source_consistent(summ, "push summary (later event)")
            check(got_later == got_get,
                  f"a later push for the same flow carries the same two values "
                  f"(later={got_later!r}, get={got_get!r})")

        section("every flow.table row has both keys, none shows a placeholder, capture_interface null on all")
        rows = table(bus)
        check(rows and all(all(k in row for k in KEYS) for row in rows),
              f"all {len(rows)} rows carry both keys (kind-independent)")
        captured = [(row.get("id"), row.get("capture_interface")) for row in rows
                    if row.get("capture_interface") is not None]
        check(not captured,
              f"no row reports a capture_interface: nothing here came through a capture backend (bad: {captured[:3]})")
        bad = [(row.get("id"), k, row.get(k)) for row in rows for k in KEYS
               if isinstance(row.get(k), str) and row.get(k).strip().lower() in PLACEHOLDERS]
        check(not bad, f"no row shows a placeholder string for either key (bad: {bad[:3]})")

        section("tools/list: the result schemas declare the two fields and still say what a proxied flow reports")
        tools = {t.get("name"): t for t in bus.tools()}
        declared = 0
        for name in ("flow.get", "flow.table"):
            t = tools.get(name) or {}
            schema = t.get("outputSchema") or t.get("output_schema")
            if not schema:
                ok(f"{name}: no output schema published on the wire; schema check is the Rust test's (schemas_declare_source_app_and_capture_interface)")
                continue
            text = json.dumps(schema)
            check(all(k in text for k in KEYS), f"{name}: output schema names source_app and capture_interface")
            check("proxied" in text, f"{name}: the descriptions say what a proxied flow reports")
            declared += 1
        if declared:
            ok(f"{declared} output schema(s) declare the fields")
    finally:
        for c in (bus, sub):
            if c:
                c.close()
        if core:
            core.stop()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
