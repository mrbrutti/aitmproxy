#!/usr/bin/env python3
# e2e: tier=T1 surface=flow
"""flow.list returns the flows the proxy REALLY captured, oldest first, and the
bus's flow query narrows them correctly.

What "the filter" is, read from the code rather than assumed: `flow.list` and
`flow.table` take NO parameters (crates/aitm-plugins/src/capture.rs,
`params: vec![]`). The one server-side narrowing of the flow store over the bus is
the subscription filter `flow.subscribe {filter: {host?, method?}, since?}`
(crates/aitm-mcp/src/server.rs `FlowFilter`): `since` replays the matching stored
flows through `FlowStore::query` (crates/aitm-core/src/store.rs `FlowQuery` /
`matches`); live events are matched by `FlowFilter::matches`. Against a real core
this proves:

 1. flow.list lists exactly the flows this script pushed through the proxy, in
    capture order, consistent with flow.table, flow.get and proxy.status, and
    flow.get agrees with the request the client really sent;
 2. an unknown `filter` argument on flow.list / flow.table is REFUSED (JSON-RPC
    -32602), never silently ignored: no client can believe it filtered when it
    did not;
 3. filter.host = a full authority replays EXACTLY the flows to that upstream
    (equality, not a subset) and `since` is exclusive;
 4. filter.host = a bare host matches by host portion, any port;
 5. filter.method = POST keeps the POSTs, drops the GETs, every yielded flow is a
    POST;
 6. a `since` outside the filtered set replays the whole filtered set (the
    documented fallback), a filter nothing matches replays nothing;
 7. live narrowing: with a method=POST subscription open, a GET sent BEFORE the
    POST never reaches the subscriber, the POST's created/response events do;
 8. live and replay agree on a lowercase method filter. Candidate bug, asserted
    LAST so all other evidence prints first: live `FlowFilter::matches` is
    eq_ignore_ascii_case, replay `store::matches` compares the method exactly,
    so a `post` subscriber gets live POSTs but an empty catch-up on reconnect.

Ground truth: the requests this script sent and the responses it got through the
proxy listener, and what the two echo-record upstreams RECORDED server-side (the
independent observers). No fixtures, no frozen expectations.

Core: attaches to the core the runner provides via env (AITM_BUS_ADDR,
AITM_BUS_TOKEN, AITM_PROXY_ADDR, optional AITM_BUS_OPERATOR_TOKEN); without that
contract it boots its own dedicated core (free ports) like every aitm_e2e suite,
in which case the store is private and every list assertion is an EQUALITY.
Markers are unique per run, the upstreams' random ports give this run
authorities nobody else uses, and no global core state is touched.
"""

import os
import socket
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient, BusError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

FLOW_NOTE = "notifications/aitm/flow"
FORM = {"Content-Type": "application/x-www-form-urlencoded"}
ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_OP_TOKEN, ENV_PROXY_ADDR = (
    "AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_BUS_OPERATOR_TOKEN", "AITM_PROXY_ADDR",
)


# ---- the core: provided by the runner (env) or booted here ---------------------

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


# ---- bus helpers on top of BusClient -------------------------------------------

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


def _take_stashed(bus):
    out = [m for m in bus.notifications if m.get("id") is None]
    bus.notifications.clear()
    return out


def collect_until(bus, pred, timeout=15.0):
    """params of the notifications/aitm/flow lines on `bus` until one satisfies
    `pred` (included) or `timeout` elapses. Returns (params, found)."""
    out, pending = [], _take_stashed(bus)
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


def collect_quiet(bus, quiet=1.0):
    """params of the flow notifications on `bus` until `quiet` seconds pass with none."""
    out = [m.get("params") or {} for m in _take_stashed(bus) if m.get("method") == FLOW_NOTE]
    while True:
        bus._set_read_timeout(quiet)
        try:
            m = bus._recv()
        except (socket.timeout, TimeoutError):
            return out
        finally:
            bus._restore_read_timeout()
        if m.get("id") is None and m.get("method") == FLOW_NOTE:
            out.append(m.get("params") or {})


def replay(core, since, *, host=None, method=None, until_id=None, quiet=None, timeout=15.0):
    """On a fresh agent connection: flow.subscribe with this filter and `since`,
    collect what the server replays. With `until_id`: until that id shows (then
    `quiet` more seconds if given). Without: a `quiet` window. Returns (params, found)."""
    bus = BusClient.agent(core)
    try:
        args = {"since": since}
        flt = {k: v for k, v in (("host", host), ("method", method)) if v}
        if flt:
            args["filter"] = flt
        bus.call("flow.subscribe", args)
        if until_id is not None:
            got, found = collect_until(bus, lambda p: p.get("id") == until_id, timeout)
            if quiet:
                got += collect_quiet(bus, quiet)
            return got, found
        return collect_quiet(bus, quiet or 1.0), None
    finally:
        bus.close()


def ids_of(params):
    return [p.get("id") for p in params]


def summaries(params):
    return [p.get("summary") or {} for p in params]


def in_order(ids, want):
    """`ids` deduplicated (first occurrence) and restricted to `want`."""
    seen, out = set(), []
    for i in ids:
        if i in want and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def host_of(authority):
    return str(authority or "").rsplit(":", 1)[0]


def main() -> int:
    up = Upstream().start()       # authority 127.0.0.1:<random>: ours alone
    other = Upstream().start()    # a second authority, ours alone
    core = env_core()
    booted = core is None
    bus = op = None
    try:
        section("arrange: two echo-record upstreams + a real aitm core")
        if booted:
            cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                             scope_entries=[up.authority, other.authority, "127.0.0.1"])
            core = Aitm.server(cfg)
            ok(f"booted a dedicated core: proxy :{cfg.proxy_port}, bus {core.bus_addr} (private store: list assertions are equalities)")
        else:
            ok(f"attached to the runner's core at {core.bus_addr} (shared store: list assertions are subset+order)")
        ok(f"upstreams {up.authority} and {other.authority}")
        pp = core.cfg.proxy_port
        bus = BusClient.agent(core)
        names = set(bus.tool_names())
        for need in ("flow.list", "flow.table", "flow.get", "flow.subscribe", "proxy.status"):
            check(need in names, f"the core exposes {need}")
        tag = f"fl-{os.getpid()}-{uuid.uuid4().hex[:8]}"

        def exact_or_ordered(name, got, want):
            """Booted here: `got` is exactly `want`. Shared core: `want` is inside `got`, in order."""
            if booted:
                check(got == want, f"{name}: exactly {want} (got {got})")
            else:
                check(in_order(got, set(want)) == want, f"{name}: contains {want} in order (got {got[-12:]})")

        # ---- 0. the anchor: a POST to `up`. It is `since` for every replay; it is a
        # POST on `up`, so it sits inside the lists we query and its absence from
        # each replay proves `since` is exclusive.
        section("act: real traffic through the proxy (anchor, 3 GETs, 2 POSTs over two authorities)")
        anchor_path = f"/anchor?t={tag}"
        r = via_proxy(pp, "POST", up.base + anchor_path, headers=FORM, body=f"anchor={tag}".encode())
        check(r.status == 200 and "aitm-e2e-upstream" in r.text, f"anchor POST through the proxy: {r.status}, upstream body round-tripped")
        anchor_id = wait_flow(bus, "POST", anchor_path)

        g_path, p_path, c_path, e_path, tail_path = (f"/{n}?t={n}-{tag}" for n in ("g", "p", "c", "e", "tail"))
        sent = [  # (method, upstream, path) in capture order -- the ground truth
            ("GET", up, g_path),
            ("POST", other, p_path),
            ("GET", other, c_path),
            ("GET", up, e_path),
            ("POST", up, tail_path),
        ]
        for method, origin, path in sent:
            r = via_proxy(pp, method, origin.base + path, headers=FORM if method == "POST" else {"X-E2E": tag},
                          body=f"{method.lower()}={tag}".encode() if method == "POST" else None)
            check(r.status == 200, f"{method} {origin.authority}{path.split('?')[0]} through the proxy: {r.status}")
        g_id, p_id, c_id, e_id, tail_id = (wait_flow(bus, m, p) for m, _, p in sent)
        later = [g_id, p_id, c_id, e_id, tail_id]
        ours = [anchor_id] + later
        check(len(set(ours)) == 6, f"six distinct flow ids for our six flows ({ours})")

        section("ground truth A: the upstreams RECORDED exactly what we sent, in order")
        check([(q["method"], q["path"]) for q in up.received] == [("POST", anchor_path), ("GET", g_path), ("GET", e_path), ("POST", tail_path)],
              f"upstream {up.authority} recorded anchor, g, e, tail in order (got {[(q['method'], q['path']) for q in up.received]})")
        check([(q["method"], q["path"]) for q in other.received] == [("POST", p_path), ("GET", c_path)],
              f"upstream {other.authority} recorded p, c in order (got {[(q['method'], q['path']) for q in other.received]})")
        check(all("x-e2e" in q["headers"] and q["headers"]["x-e2e"] == tag for q in up.received if q["method"] == "GET"),
              "the GETs' X-E2E marker header reached the upstream intact")

        section("flow.list: our flows, oldest first, consistent with flow.table / flow.get / proxy.status")
        listed = bus.call("flow.list")
        check(isinstance(listed, list) and all(isinstance(i, str) for i in listed), f"flow.list is a bare list of string ids ({len(listed)})")
        check(len(set(listed)) == len(listed), "flow.list has no duplicate ids")
        exact_or_ordered("flow.list is oldest first", listed, ours)
        rows = table(bus)
        table_ids = [row["id"] for row in rows]
        check(set(listed) <= set(table_ids), f"flow.table has a row for every id flow.list returned (missing {sorted(set(listed) - set(table_ids))[:5]})")
        common = set(listed) & set(table_ids)
        check([i for i in listed if i in common] == [i for i in table_ids if i in common], "flow.list and flow.table order their common ids identically")
        if booted:
            st = bus.call("proxy.status")
            check(st.get("flows") == len(listed) == 6, f"proxy.status.flows == len(flow.list) == 6 (got {st.get('flows')}, {len(listed)})")

        expect = {anchor_id: ("POST", up.authority, anchor_path)}
        expect.update({fid: (m, o.authority, p) for fid, (m, o, p) in zip(later, sent)})
        by_id = {row["id"]: row for row in rows}
        for fid, (method, authority, path) in expect.items():
            s = bus.call("flow.get", {"id": fid})
            got = (s.get("method"), s.get("authority"), s.get("path"))
            check(got == (method, authority, path) and s.get("status") == 200 and s.get("kind") == "http",
                  f"flow.get {method} {path.split('?')[0]} == the request we sent, status 200 (got {got}, {s.get('status')})")
            row = by_id.get(fid, {})
            check((row.get("method"), row.get("authority"), row.get("path"), row.get("status")) == (method, authority, path, 200),
                  f"flow.table row agrees for {path.split('?')[0]}")
        bad = []
        for fid in listed[-500:]:
            st, val = bus.try_call("flow.get", {"id": fid})
            if st != "ok" or not isinstance(val, dict) or val.get("id") != fid:
                bad.append((fid, str(val)[:60]))
        check(not bad, f"every id flow.list returned resolves through flow.get ({min(len(listed), 500)} checked; bad: {bad[:3]})")

        op_token = getattr(core.cfg, "operator_token", None)
        if op_token:
            op = BusClient.operator(core)
            op_listed = op.call("flow.list")
            check(op_listed == listed if booted else set(listed) <= set(op_listed),
                  "operator and agent see the same flow.list (no per-role hiding of captured flows)")
        else:
            ok("no operator token in the env contract; operator parity not asserted")

        section("flow.list / flow.table have no filter parameter: an attempt is refused loudly")
        for tool in ("flow.list", "flow.table"):
            try:
                val = bus.call(tool, {"filter": {"method": "POST"}})
                fail(f"{tool} silently ACCEPTED an unknown `filter` argument and returned {str(val)[:60]}")
            except BusError as e:
                check("-32602" in str(e) and "filter" in str(e), f"{tool} refuses an unknown `filter` argument with JSON-RPC -32602 naming it ({str(e)[:100]})")

        section("the query narrows the store: flow.subscribe replay since the anchor, one filter at a time")
        # a full authority: exactly the later flows to `up` (g, e, tail), never p/c (other) nor the anchor
        got, found = replay(core, anchor_id, host=up.authority, until_id=tail_id, quiet=1.0)
        ids = ids_of(got)
        check(ids == [g_id, e_id, tail_id], f"filter.host={up.authority}: EXACTLY our three later flows to it, anchor excluded by since (got {ids})")
        check(all(p.get("event") == "created" for p in got), "replayed flows arrive as event=created")
        s = next((p["summary"] for p in got if p.get("id") == e_id and p.get("summary")), {})
        check((s.get("method"), s.get("authority"), s.get("path"), s.get("status")) == ("GET", up.authority, e_path, 200),
              f"the replayed summary of our GET e == what we sent and got (got {s})")

        # the other authority with a `since` that is not in its list: the whole list
        got, found = replay(core, anchor_id, host=other.authority, until_id=c_id, quiet=1.0)
        ids = ids_of(got)
        check(ids == [p_id, c_id], f"filter.host={other.authority}: exactly its two flows (since outside the filtered set => full filtered replay) (got {ids})")

        # a bare host: host portion, any port
        got, found = replay(core, anchor_id, host="127.0.0.1", until_id=tail_id)
        ids = ids_of(got)
        exact_or_ordered("filter.host=127.0.0.1 replays our flows on every 127.0.0.1 port", ids, later)
        check(anchor_id not in ids, "filter.host=127.0.0.1: since is exclusive (anchor not replayed)")
        check(all(s.get("kind") == "http" and host_of(s.get("authority")) == "127.0.0.1" for s in summaries(got)),
              "filter.host=127.0.0.1: every yielded flow is an HTTP flow whose host is 127.0.0.1")

        # method=POST
        got, found = replay(core, anchor_id, method="POST", until_id=tail_id)
        ids = ids_of(got)
        exact_or_ordered("filter.method=POST replays our POSTs", ids, [p_id, tail_id])
        check(not any(i in ids for i in (g_id, c_id, e_id)), f"filter.method=POST: drops our GETs (got {ids})")
        check(anchor_id not in ids, "filter.method=POST: since is exclusive (anchor POST not replayed)")
        check(all(s.get("method") == "POST" for s in summaries(got)), "filter.method=POST: every yielded flow is a POST")

        # host AND method together
        got, found = replay(core, anchor_id, host=up.authority, method="GET", until_id=e_id, quiet=1.0)
        ids = ids_of(got)
        check(ids == [g_id, e_id], f"filter.host={up.authority}+method=GET: exactly our two GETs to it (got {ids})")

        # no filter
        got, found = replay(core, anchor_id, until_id=tail_id)
        ids = ids_of(got)
        exact_or_ordered("no filter: everything after the anchor, in capture order", ids, later)
        check(anchor_id not in ids, "no filter: since is exclusive (anchor not replayed)")

        # a filter nothing matches
        got, _ = replay(core, anchor_id, host=f"{tag}.invalid", quiet=1.5)
        check(got == [], f"filter.host that matches nothing replays nothing (got {ids_of(got)})")

        section("live narrowing: a method=POST subscriber never sees a GET sent before the POST")
        live = BusClient.agent(core)
        live.call("flow.subscribe", {"filter": {"method": "POST"}})
        lower = BusClient.agent(core)
        lower.call("flow.subscribe", {"filter": {"method": "post"}})
        lg_path, lp_path = f"/lg?t=lg-{tag}", f"/lp?t=lp-{tag}"
        r = via_proxy(pp, "GET", up.base + lg_path)
        check(r.status == 200, f"live GET through the proxy: {r.status}")
        r = via_proxy(pp, "POST", up.base + lp_path, headers=FORM, body=b"live=1")
        check(r.status == 200, f"live POST through the proxy: {r.status}")
        lg_id = wait_flow(bus, "GET", lg_path)
        lp_id = wait_flow(bus, "POST", lp_path)
        got, found = collect_until(live, lambda p: p.get("id") == lp_id and p.get("event") == "response")
        ids = ids_of(got)
        check(found and any(p.get("event") == "created" and p.get("id") == lp_id for p in got),
              f"live filter.method=POST: the POST's created and response events reached the subscriber ({[(p.get('event'), p.get('id')) for p in got][-6:]})")
        check(lg_id not in ids, f"live filter.method=POST: the GET sent before the POST never reached the subscriber (got {ids})")
        check(all(s.get("method") == "POST" for s in summaries(got)), "live filter.method=POST: every pushed summary is a POST")
        got, found = collect_until(lower, lambda p: p.get("id") == lp_id)
        check(found, f"live filter.method=post (lowercase): matches the POST case-insensitively (got {ids_of(got)[-6:]})")
        check(lg_id not in ids_of(got), "live filter.method=post: the GET never reached the subscriber")
        live.close()
        lower.close()
        check([(q["method"], q["path"]) for q in up.received][-2:] == [("GET", lg_path), ("POST", lp_path)],
              "ground truth: the upstream recorded the live GET then the live POST")

        section("replay must agree with live on the lowercase filter (asserted last)")
        got, found = replay(core, anchor_id, method="post", until_id=lp_id, timeout=6.0)
        ids = ids_of(got)
        check(found and p_id in ids and tail_id in ids,
              "replay filter.method=post (lowercase) yields the POSTs the live filter did "
              f"(got {ids}; candidate bug: aitm-core store::matches compares the method exactly while "
              "aitm-mcp FlowFilter::matches ignores case, so a `post` subscriber gets live POSTs but an empty catch-up)")
    finally:
        for c in (bus, op):
            if c:
                c.close()
        if core:
            core.stop()
        up.stop()
        other.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
