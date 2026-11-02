#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy needs=openssl
"""Proxied client attribution on a real core: the core names the loopback client.

Spec `docs/superpowers/specs/2026-11-01-proxied-client-attribution-design.md` (D1, D5,
D7; AC10, AC11, AC12, AC13), plan Task 8. One real `aitm` core booted with an EMPTY
Scope, the plain HTTP echo-record `Upstream` (the independent observer for "the
request reached the origin"), a loopback TLS echo origin, real `curl` and this very
Python process as the two clients, read back over the operator bus. Four proofs:

  1. curl, plain HTTP (AC10): after `curl -sS -m 15 -x http://127.0.0.1:<proxy>
     <up>/attr-<uuid>` the `flow.table` row for that path has `source_app` a string
     whose lower-case contains `curl`, `capture_interface` null (no capture backend
     delivered it: this is the explicit proxy), and `flow.detail {id}` has
     `client_conn.process` equal to that same string.
  2. python, plain HTTP (AC11): a `via_proxy` GET from THIS process yields a row whose
     `source_app` lower-case contains `python`, `capture_interface` null, detail
     agreeing.
  3. curl, HTTPS/CONNECT (AC12): with `scope.add 127.0.0.1` and the TLS echo origin,
     `curl --cacert <aitm ca> -x … https://127.0.0.1:<tls>/attr-<uuid>` produces a
     `CONNECT` row (tunnel `decrypted`) and a `GET` row for that authority; both carry
     `curl` in `source_app`, `capture_interface` null, detail agreeing.
  4. latency (AC13): 20 sequential plain `via_proxy` GETs through the same core; the
     median wall time is printed (`median_ms=<value>`) and must be under 100 ms (an
     absolute bound: the 25 ms attribution budget is the most a connection can pay).

Identity vocabulary (spec D5), stated honestly so the assertions are not tied to one
machine: a BUNDLED executable is named by its bundle identifier, a bare one by its
executable basename. On macOS Apple's `/usr/bin/curl` is a bare executable, so it is
`curl`; `/usr/bin/python3` runs inside `Python.app` and is `com.apple.python3`, while
a Homebrew or nix python is `python3.14` (its basename) and a framework build may be
`org.python.python`. On Linux both are basenames (`curl`, `python3.14`). Hence the
checks are CONTAINS, lower-cased: `curl` in `source_app`, `python` in `source_app`,
never an equality against one spelling. The same string must come back from
`flow.detail` `client_conn.process` (the TUI/web Client column source).

Every check names what was observed. Exit 0 pass, 77 skip (no curl / openssl, or an
OS where the resolver is `None` by design), anything else fail. Ports are dedicated
free ports; the bus token is never printed.
"""
from __future__ import annotations

import os
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.tls import ca_cert, curl_code, have, start_https_echo, upstream_cert  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

import _clients as c  # noqa: E402

HOST = "127.0.0.1"
KEYS = ("source_app", "capture_interface")
LATENCY_SAMPLES = 20
LATENCY_BOUND_MS = 100.0


# ---------------------------------------------------------------------------
# flow.table ground truth over the operator bus
# ---------------------------------------------------------------------------
def rows(bus) -> list:
    res = bus.call("flow.table")
    return (res.get("flows") or []) if isinstance(res, dict) else []


def rows_for(bus, authority: str) -> list:
    return [r for r in rows(bus) if r.get("authority") == authority]


def wait_rows(bus, authority: str, pred, timeout: float = 5.0, delay: float = 0.05) -> list:
    """Poll `flow.table` for `authority` until `pred(rows)` holds or `timeout`
    elapses; return the last rows seen (capture lands a beat after the client exits)."""
    deadline = time.time() + timeout
    rs = rows_for(bus, authority)
    while not pred(rs) and time.time() < deadline:
        time.sleep(delay)
        rs = rows_for(bus, authority)
    return rs


def by_path(rs: list, method: str, path: str) -> list:
    return [r for r in rs if r.get("method") == method and r.get("path") == path]


def connects(rs: list) -> list:
    return [r for r in rs if r.get("method") == "CONNECT"]


def done(r: dict) -> bool:
    return r.get("status") is not None


def brief(r: dict) -> dict:
    keys = ("id", "method", "path", "status", "tunnel", "source_app", "capture_interface")
    return {k: r.get(k) for k in keys}


def wait_one(bus, authority: str, method: str, path: str) -> dict:
    """The single completed `method path` row for `authority`, or fail with what was seen."""
    rs = wait_rows(bus, authority, lambda rs: any(done(r) for r in by_path(rs, method, path)))
    mine = [r for r in by_path(rs, method, path) if done(r)]
    check(len(mine) == 1,
          f"flow.table holds exactly one completed {method} {path} row for {authority} "
          f"(got {len(mine)}: {[brief(r) for r in rs][-6:]})")
    return mine[0] if mine else {}


# ---------------------------------------------------------------------------
# the attribution assertions (spec D5 vocabulary, D7 meaning)
# ---------------------------------------------------------------------------
def check_attributed(bus, row: dict, needle: str, what: str) -> str:
    """`source_app` is a string whose lower-case contains `needle`; `capture_interface`
    is present and null; `flow.detail` agrees via `client_conn.process`. Returns the name."""
    for k in KEYS:
        check(k in row, f"{what}: the `{k}` key is present on the row (keys: {sorted(row)[:20]})")
    name = row.get("source_app")
    check(isinstance(name, str) and needle in name.lower(),
          f"{what}: source_app is a string containing {needle!r} (got {name!r})")
    check(row.get("capture_interface") is None,
          f"{what}: capture_interface is null on the explicit-proxy path "
          f"(got {row.get('capture_interface')!r})")
    d = bus.call("flow.detail", {"id": row.get("id"), "body": "none"})
    cc = d.get("client_conn") if isinstance(d, dict) else None
    check(isinstance(cc, dict) and "process" in cc,
          f"{what}: flow.detail carries client_conn.process (client_conn={cc!r})")
    proc = (cc or {}).get("process")
    check(proc == name,
          f"{what}: flow.detail client_conn.process equals the row's source_app "
          f"(detail={proc!r}, row={name!r})")
    return name if isinstance(name, str) else ""


def scope_add(bus, host: str) -> None:
    added = bus.call("scope.add", {"host": host})
    listed = bus.call("scope.list")
    check(added == host and host in listed,
          f"scope.add {host} over the operator bus (returned {added!r}; scope.list={listed})")


def wait_file(path: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    if sys.platform not in ("darwin", "linux"):
        skip(f"the peer resolver is None by design on {sys.platform} (spec D2); nothing to attribute")
    if not have("curl"):
        skip("curl is required for the client")
    if not have("openssl"):
        skip("openssl is required to mint the TLS origin certificate")

    work = tempfile.mkdtemp(prefix="aitm-e2e-attr-")
    crt, key = upstream_cert(work)
    tls_srv, tls_port = start_https_echo(crt, key)
    tls_auth = f"{HOST}:{tls_port}"
    up = Upstream().start()

    core = None
    bus = None
    try:
        section("boot: real aitm with an EMPTY Scope + plain HTTP upstream + TLS echo origin")
        cfg = c.ProxyConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[],
        )
        core = Aitm.server(cfg)
        bus = BusClient.operator(core)
        ca = ca_cert(core)
        if not wait_file(ca):
            fail("aitm did not write its CA cert; curl --cacert has nothing to trust")
        proxy = ["-x", f"http://127.0.0.1:{cfg.proxy_port}", "-m", "15"]
        listed = bus.call("scope.list")
        check(listed == [], f"the core booted with an empty Scope (scope.list={listed})")
        ok(f"proxy 127.0.0.1:{cfg.proxy_port}, plain origin {up.authority}, tls origin {tls_auth}; "
           f"client python is {sys.executable}")

        # ------------------------------------------------------------------ 1
        section("1. AC10: curl over plain HTTP is named `curl` on the flow.table row and in flow.detail")
        p1 = f"/attr-{uuid.uuid4().hex[:12]}"
        rc, code, body = curl_code(proxy + [f"{up.base}{p1}"])
        check(rc == 0 and code == 200, f"curl -x GET {p1} returned 200 (rc={rc}, code={code})")
        check("aitm-e2e-upstream" in body, f"the body is the UPSTREAM's own echo (body={body[:80]!r})")
        check([(q["method"], q["path"]) for q in up.received if q["path"] == p1] == [("GET", p1)],
              f"ground truth: the upstream recorded exactly our GET {p1}")
        r1 = wait_one(bus, up.authority, "GET", p1)
        curl_name = check_attributed(bus, r1, "curl", "curl plain-HTTP row")
        ok(f"curl is named {curl_name!r} (spec D5: bare executable -> basename)")

        # ------------------------------------------------------------------ 2
        section("2. AC11: a via_proxy GET from THIS python process is named `python…`")
        p2 = f"/py-{uuid.uuid4().hex[:12]}"
        resp = via_proxy(cfg.proxy_port, "GET", f"{up.base}{p2}")
        check(resp.status == 200 and "aitm-e2e-upstream" in resp.text,
              f"via_proxy GET {p2}: {resp.status}, the upstream's body round-tripped")
        check([(q["method"], q["path"]) for q in up.received if q["path"] == p2] == [("GET", p2)],
              f"ground truth: the upstream recorded exactly our GET {p2}")
        r2 = wait_one(bus, up.authority, "GET", p2)
        py_name = check_attributed(bus, r2, "python", "python plain-HTTP row")
        ok(f"this process ({os.path.basename(sys.executable)}, pid {os.getpid()}) is named {py_name!r} "
           f"(com.apple.python3 when bundled, python3.x when a bare Homebrew/nix binary)")
        check(py_name != curl_name,
              f"two different clients get two different names (curl={curl_name!r}, python={py_name!r})")

        # ------------------------------------------------------------------ 3
        section("3. AC12: curl over HTTPS in Scope: the CONNECT row AND the decrypted GET row are `curl`")
        scope_add(bus, HOST)
        p3 = f"/attr-{uuid.uuid4().hex[:12]}"
        rc, code, body = curl_code(proxy + ["--cacert", ca, f"https://{tls_auth}{p3}"])
        check(rc == 0 and code == 200,
              f"curl --cacert <aitm ca> -x GET https://{tls_auth}{p3} returned 200: an aitm leaf was served "
              f"(rc={rc}, code={code})")
        check(f'"path": "{p3}"' in body, f"the body is the TLS ORIGIN's own echo of GET {p3} (body={body[:100]!r})")
        rs = wait_rows(bus, tls_auth,
                       lambda rs: connects(rs) and all(done(r) for r in connects(rs))
                       and any(done(r) for r in by_path(rs, "GET", p3)))
        cn = connects(rs)
        check(len(cn) == 1, f"exactly one CONNECT row for {tls_auth} (got {[brief(r) for r in cn]})")
        crow = cn[0] if cn else {}
        check(crow.get("tunnel") == "decrypted" and crow.get("status") == 200,
              f"the CONNECT row is a decrypted tunnel with status 200 "
              f"(tunnel={crow.get('tunnel')!r} status={crow.get('status')!r})")
        c_name = check_attributed(bus, crow, "curl", "CONNECT row")
        g = [r for r in by_path(rs, "GET", p3) if done(r)]
        check(len(g) == 1 and g[0].get("status") == 200,
              f"exactly one decrypted GET {p3} row with status 200 (got {[brief(r) for r in g]})")
        g_name = check_attributed(bus, g[0] if g else {}, "curl", "decrypted GET row")
        check(c_name == g_name == curl_name,
              f"the same client string on the tunnel, its inner request and the plain-HTTP row "
              f"(connect={c_name!r} get={g_name!r} plain={curl_name!r})")

        # ------------------------------------------------------------------ 4
        section(f"4. AC13: {LATENCY_SAMPLES} sequential via_proxy GETs; median wall time < {LATENCY_BOUND_MS:g} ms")
        samples_ms: list[float] = []
        tag = uuid.uuid4().hex[:8]
        for i in range(LATENCY_SAMPLES):
            path = f"/lat-{tag}-{i}"
            t0 = time.perf_counter()
            resp = via_proxy(cfg.proxy_port, "GET", f"{up.base}{path}")
            samples_ms.append((time.perf_counter() - t0) * 1000.0)
            if resp.status != 200:
                fail(f"latency sample {i}: GET {path} returned {resp.status}, not 200")
        median = statistics.median(samples_ms)
        print(f"  median_ms={median:.2f} min_ms={min(samples_ms):.2f} max_ms={max(samples_ms):.2f} "
              f"n={len(samples_ms)}", flush=True)
        check(len([q for q in up.received if q["path"].startswith(f"/lat-{tag}-")]) == LATENCY_SAMPLES,
              f"ground truth: the upstream recorded all {LATENCY_SAMPLES} latency GETs")
        check(median < LATENCY_BOUND_MS,
              f"median wall time per proxied GET is {median:.2f} ms, under {LATENCY_BOUND_MS:g} ms "
              f"(attribution adds at most its 25 ms budget per connection)")
        lat_rows = [r for r in rows_for(bus, up.authority) if (r.get("path") or "").startswith(f"/lat-{tag}-")]
        named = [r for r in lat_rows if isinstance(r.get("source_app"), str) and "python" in r["source_app"].lower()]
        ok(f"{len(named)}/{len(lat_rows)} latency rows carry a python source_app so far "
           f"(informational: a budget miss is a null, never a placeholder)")
        placeholders = [brief(r) for r in lat_rows
                        if isinstance(r.get("source_app"), str) and "python" not in r["source_app"].lower()]
        check(not placeholders, f"no latency row carries a non-python string as source_app (bad={placeholders[:3]})")
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
        tls_srv.shutdown()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
