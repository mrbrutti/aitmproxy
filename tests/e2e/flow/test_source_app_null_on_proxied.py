#!/usr/bin/env python3
# e2e: tier=T1 surface=flow
"""source_app / capture_interface on the wire for a PROXIED flow (spec
2026-10-31-ne-source-app-on-the-wire, SA-AC1 + SA-AC2; the plan's stage-5
"end-to-end check the Tester can run without the NE").

Against a REAL `aitm` core, a real request through the explicit proxy listener and
the echo-record upstream as the independent observer, this proves:

 1. `flow.get` for the proxied flow carries BOTH keys, each present and `null`
    (never absent, never a placeholder such as "unknown" or "");
 2. the `flow.table` row for the same flow carries the same two null keys;
 3. the `flow.subscribe` push (`notifications/aitm/flow`, event=created) for that
    flow carries the same two null keys in `params.summary` — the push summary and
    `flow.get` agree key for key on the two fields;
 4. every row `flow.table` returns has both keys (the keys are kind-independent),
    and no row shows a placeholder string for either;
 5. `tools/list` declares the two fields on the `flow.get` and `flow.table` result
    schemas when the server publishes output schemas (skipped with a note if it
    does not).

The captured (NE) half — `"source_app": "com.apple.Safari"`,
`"capture_interface": "macos-ne"` — is SA-AC6, verified manually on the v0.5.4
DMG; it cannot be driven here (no Network Extension in a test process).

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


def both_null(obj, what):
    """Both keys PRESENT and null on `obj` (a flow.get result, a table row, a push summary)."""
    for k in KEYS:
        check(k in obj, f"{what}: the `{k}` key is present (keys: {sorted(obj)[:16]})")
        check(obj.get(k) is None, f"{what}: `{k}` is null for a proxied flow (got {obj.get(k)!r})")


def main() -> int:
    up = Upstream().start()
    core = env_core()
    booted = core is None
    bus = sub = None
    try:
        section("arrange: an echo-record upstream + a real aitm core + a live flow.subscribe")
        if booted:
            cfg = CoreConfig(proxy_port=free_port(), scope_entries=[up.authority, "127.0.0.1"])
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

        section("SA-AC1: flow.get and the flow.table row carry both keys, null")
        s = bus.call("flow.get", {"id": fid})
        check(s.get("kind") == "http" and s.get("path") == path, f"flow.get is our flow ({s.get('kind')} {s.get('path')})")
        both_null(s, "flow.get")
        row = next((row for row in table(bus) if row.get("id") == fid), None)
        check(row is not None, "flow.table has our row")
        both_null(row or {}, "flow.table row")

        section("SA-AC2: the flow.subscribe push summary carries the same two null keys")
        got, found = collect_until(sub, lambda p: p.get("id") == fid and p.get("event") == "created")
        check(found, f"a created push for our flow arrived ({[(p.get('event'), p.get('id')) for p in got][-6:]})")
        pushed = next((p.get("summary") or {} for p in got if p.get("id") == fid and p.get("event") == "created"), {})
        both_null(pushed, "push summary (event=created)")
        check({k: pushed.get(k) for k in KEYS} == {k: s.get(k) for k in KEYS},
              "push summary and flow.get agree on source_app / capture_interface")
        # Any later event for the same flow (response) carries them too.
        later = [p.get("summary") or {} for p in got if p.get("id") == fid and p.get("event") != "created"]
        for summ in later:
            both_null(summ, "push summary (later event)")

        section("every flow.table row has both keys and none shows a placeholder")
        rows = table(bus)
        check(rows and all(all(k in row for k in KEYS) for row in rows),
              f"all {len(rows)} rows carry both keys (kind-independent)")
        bad = [(row.get("id"), k, row.get(k)) for row in rows for k in KEYS
               if isinstance(row.get(k), str) and row.get(k).strip().lower() in PLACEHOLDERS]
        check(not bad, f"no row shows a placeholder string for either key (bad: {bad[:3]})")

        section("tools/list: the result schemas declare the two fields")
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
