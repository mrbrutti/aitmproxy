#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy needs=openssl
"""Per-host decryption on a real core: Scope is the decryption list.

Spec `docs/superpowers/specs/2026-10-31-per-host-decryption-design.md` (D1, D4, D5,
D7, D8; AC1, AC2, AC3, AC5, AC9, AC13, AC18), plan Task 11. One real `aitm` core
booted with an EMPTY Scope, a loopback TLS echo origin presenting its OWN
self-signed cert (the independent observer for "the proxy never terminated TLS")
and a plain HTTP echo-record `Upstream` (the independent observer for "the request
reached the origin"), driven by real `curl` and read back over the operator bus:

  1. passthrough: with nothing in Scope an HTTPS request is tunnelled, not
     decrypted. `curl --cacert <aitm ca>` fails to verify (rc 60: the client saw the
     ORIGIN's cert, not an aitm leaf), `curl -k` gets the origin's echo. `flow.table`
     holds a `CONNECT` row per tunnel — `tunnel == "passthrough"`,
     `tunnel_reason == "out_of_scope"`, status 200, `bytes_up`/`bytes_down` > 0,
     `duration_ms` set once the client closed, `passive == false` — and NO `GET` row
     for that authority (nothing was decrypted). A `flow.subscribe` on an
     operator-token connection receives that row as `created` then `response`, both
     carrying `tunnel == "passthrough"` in the summary.
  2. scope.add flips live: `scope.add 127.0.0.1` makes the NEXT connection decrypted
     (`curl --cacert` → 200; a `CONNECT` row `tunnel == "decrypted"`, status 200, plus
     a `GET /b` row with `passive == false`); the step-1 rows are untouched.
  3. scope.remove flips back: `curl --cacert` fails again, a new `passthrough` row,
     no new `GET` row, no new `decrypted` row.
  4. CA refused: in Scope, a client that trusts neither the aitm CA nor `-k` fails
     (rc 60) and the row says why — `tunnel == "failed"`,
     `tunnel_reason == "client_rejected_certificate"`, status null, `duration_ms` set.
  5. plain HTTP out of Scope is passive: with an armed breakpoint rule naming the
     plain origin, `GET /p` returns 200 at once (the UPSTREAM record has it, nothing
     parked, `proxy.status.paused == 0`) and its row has `passive == true`; after
     `scope.add` the same request IS parked until `flow.resume` and its row has
     `passive == false`.
  6. status: `proxy.status.decrypt` is `{scope_hosts: 0, decrypting: false, advice:
     "Nothing is decrypted until a host is in Scope."}` on the empty Scope and
     `{scope_hosts: 1, decrypting: true, advice: null}` after `scope.add`.

Every check names what was observed. Exit 0 pass, 77 skip (no curl / openssl),
anything else fail. Ports are dedicated free ports; the bus token is never printed.
"""
from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.tls import ca_cert, curl, curl_code, have, start_https_echo, upstream_cert  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

import _clients as c  # noqa: E402

FLOW_NOTE = "notifications/aitm/flow"
ADVICE = "Nothing is decrypted until a host is in Scope."
HOST = "127.0.0.1"
CURL_VERIFY_FAILED = 60  # CURLE_PEER_FAILED_VERIFICATION


# ---------------------------------------------------------------------------
# flow.table ground truth over the operator bus
# ---------------------------------------------------------------------------
def rows(bus) -> list:
    res = bus.call("flow.table")
    return (res.get("flows") or []) if isinstance(res, dict) else []


def rows_for(bus, authority: str) -> list:
    return [r for r in rows(bus) if r.get("authority") == authority]


def connects(rs: list, tunnel=None) -> list:
    out = [r for r in rs if r.get("method") == "CONNECT"]
    if tunnel is not None:
        out = [r for r in out if r.get("tunnel") == tunnel]
    return out


def gets(rs: list) -> list:
    return [r for r in rs if r.get("method") == "GET"]


def wait_rows(bus, authority: str, pred, timeout: float = 3.0, delay: float = 0.05) -> list:
    """Poll `flow.table` for `authority` until `pred(rows)` holds or `timeout`
    elapses; return the last rows seen (capture lands a beat after curl exits)."""
    deadline = time.time() + timeout
    rs = rows_for(bus, authority)
    while not pred(rs) and time.time() < deadline:
        time.sleep(delay)
        rs = rows_for(bus, authority)
    return rs


def brief(r: dict) -> dict:
    keys = ("id", "method", "path", "status", "tunnel", "tunnel_reason", "bytes_up",
            "bytes_down", "duration_ms", "passive", "state")
    return {k: r.get(k) for k in keys}


def check_passthrough_row(r: dict, what: str) -> None:
    check(r.get("method") == "CONNECT", f"{what}: method is CONNECT (got {r.get('method')!r})")
    check(r.get("tunnel") == "passthrough", f"{what}: tunnel == passthrough (got {r.get('tunnel')!r})")
    check(r.get("tunnel_reason") == "out_of_scope",
          f"{what}: tunnel_reason == out_of_scope (got {r.get('tunnel_reason')!r})")
    check(r.get("status") == 200, f"{what}: status == 200, the tunnel was established (got {r.get('status')!r})")
    check(isinstance(r.get("bytes_up"), int) and r["bytes_up"] > 0,
          f"{what}: bytes_up > 0, the ClientHello crossed the relay (got {r.get('bytes_up')!r})")
    check(isinstance(r.get("bytes_down"), int) and r["bytes_down"] > 0,
          f"{what}: bytes_down > 0, the origin's ServerHello/cert came back (got {r.get('bytes_down')!r})")
    check(r.get("duration_ms") is not None,
          f"{what}: duration_ms set after the client closed (got {r.get('duration_ms')!r})")
    check(r.get("passive") is False, f"{what}: passive is false on a tunnel row (got {r.get('passive')!r})")
    check(r.get("state") == "observed", f"{what}: interception state is observed (got {r.get('state')!r})")


def scope_add(bus, host: str) -> None:
    added = bus.call("scope.add", {"host": host})
    listed = bus.call("scope.list")
    check(added == host and host in listed,
          f"scope.add {host} over the operator bus (returned {added!r}; scope.list={listed})")


def scope_remove(bus, host: str) -> None:
    removed = bus.call("scope.remove", {"host": host})
    listed = bus.call("scope.list")
    check(removed is True and host not in listed,
          f"scope.remove {host} over the operator bus (returned {removed!r}; scope.list={listed})")


def decrypt_status(bus) -> dict:
    st = bus.call("proxy.status")
    d = st.get("decrypt") if isinstance(st, dict) else None
    check(isinstance(d, dict), f"proxy.status carries a decrypt object (got {d!r})")
    return d


def check_decrypt(d: dict, hosts: int, decrypting: bool, advice) -> None:
    check(d.get("scope_hosts") == hosts, f"decrypt.scope_hosts == {hosts} (got {d.get('scope_hosts')!r})")
    check(d.get("decrypting") is decrypting, f"decrypt.decrypting is {decrypting} (got {d.get('decrypting')!r})")
    check(d.get("advice") == advice, f"decrypt.advice == {advice!r} (got {d.get('advice')!r})")


# ---------------------------------------------------------------------------
# flow.subscribe pushes (a second operator-token connection)
# ---------------------------------------------------------------------------
def collect_until(sub, pred, timeout: float = 10.0) -> tuple[list, bool]:
    """params of the `notifications/aitm/flow` lines on `sub` until one satisfies
    `pred` (included) or `timeout` elapses. Returns (params, found)."""
    out: list = []
    pending = [m for m in sub.notifications if m.get("id") is None]
    sub.notifications.clear()
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
        sub._set_read_timeout(max(0.05, left))
        try:
            pending.append(sub._recv())
        except (socket.timeout, TimeoutError, OSError):
            return out, False
        finally:
            sub._restore_read_timeout()


# ---------------------------------------------------------------------------
# curl in the background (for the parked request of step 5)
# ---------------------------------------------------------------------------
def curl_bg(args, timeout: float = 30):
    res: dict = {}

    def run():
        res["rc"], res["out"], res["err"] = curl(args, timeout=timeout)

    t = threading.Thread(target=run)
    t.start()
    return t, res


def parked(bus, path: str):
    """The id of the flow for `path` once it is parked, polling up to ~15 s."""
    return c.find_flow(
        bus, pred=lambda s: s.get("intercept") == "intercepted" and s.get("path") == path,
        tries=150, delay=0.1)


def wait_file(path: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    if not have("curl"):
        skip("curl is required for the client")
    if not have("openssl"):
        skip("openssl is required to mint the TLS origin certificate")

    work = tempfile.mkdtemp(prefix="aitm-e2e-phd-")
    crt, key = upstream_cert(work)
    tls_srv, tls_port = start_https_echo(crt, key)
    plain = Upstream().start()
    tls_auth = f"{HOST}:{tls_port}"
    tls_base = f"https://{tls_auth}"

    core = None
    bus = None
    sub = None
    try:
        section("boot: real aitm with an EMPTY Scope + TLS echo origin + plain HTTP upstream")
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
        via = ["-x", f"http://127.0.0.1:{cfg.proxy_port}"]
        proxy = via + ["-m", "15"]  # every foreground curl is bounded; it must never hang
        listed = bus.call("scope.list")
        check(listed == [], f"the core booted with an empty Scope (scope.list={listed})")
        ok(f"proxy 127.0.0.1:{cfg.proxy_port}, tls origin {tls_auth}, plain origin {plain.authority}")

        sub = BusClient.operator(core)
        sub_id = sub.call("flow.subscribe", {})
        ok(f"flow.subscribe on a second operator-token connection (sub_id={sub_id!r})")

        section("6a. status: proxy.status.decrypt on the empty Scope says nothing is decrypted")
        check_decrypt(decrypt_status(bus), hosts=0, decrypting=False, advice=ADVICE)

        # ------------------------------------------------------------------ 1
        section("1. passthrough: out-of-Scope HTTPS is tunnelled, not decrypted")
        rc, _out, err = curl(proxy + ["--cacert", ca, "-o", "/dev/null", f"{tls_base}/a"])
        check(rc == CURL_VERIFY_FAILED,
              f"curl --cacert <aitm ca> fails to verify: the client saw the ORIGIN's own cert, "
              f"not an aitm leaf (rc={rc}, stderr={err.strip()[-160:]!r})")
        rs = wait_rows(bus, tls_auth, lambda rs: len(rs) >= 1 and rs[0].get("duration_ms") is not None)
        check(len(rs) == 1, f"flow.table holds exactly one row for {tls_auth} after one CONNECT "
                            f"(got {len(rs)}: {[brief(r) for r in rs]})")
        first = rs[0]
        check_passthrough_row(first, "row 1 (curl --cacert)")
        check(not gets(rs), f"no GET row for {tls_auth}: nothing was decrypted (rows={[brief(r) for r in rs]})")

        rc, code, body = curl_code(proxy + ["-k", f"{tls_base}/a"])
        check(rc == 0 and code == 200, f"curl -k through the tunnel gets the origin's 200 (rc={rc}, code={code})")
        check('"path": "/a"' in body and '"method": "GET"' in body,
              f"the body is the ORIGIN's own echo of GET /a (body={body[:120]!r})")
        rs = wait_rows(bus, tls_auth,
                       lambda rs: len(rs) >= 2 and all(r.get("duration_ms") is not None for r in rs))
        check(len(rs) == 2 and len(connects(rs, "passthrough")) == 2,
              f"two CONNECTs → exactly two rows for {tls_auth}, both passthrough "
              f"(got {[brief(r) for r in rs]})")
        second = next((r for r in rs if r.get("id") != first.get("id")), {})
        check_passthrough_row(second, "row 2 (curl -k)")
        check(not gets(rs), f"still no GET row for {tls_auth}: the 200 came through an opaque tunnel")
        step1 = {r["id"]: dict(r) for r in rs}

        section("1. push: flow.subscribe delivered the passthrough row as created then response")
        got, found = collect_until(
            sub, lambda p: p.get("id") == first["id"] and p.get("event") == "response")
        check(found, f"a response push for the first passthrough row arrived "
                     f"(events seen: {[(p.get('event'), p.get('id')) for p in got][-8:]})")
        mine = [p for p in got if p.get("id") == first["id"]]
        events = [p.get("event") for p in mine]
        check(events[:1] == ["created"] and "response" in events,
              f"the row was pushed as created first, then response (events={events})")
        for p in mine:
            s = p.get("summary") or {}
            check(s.get("tunnel") == "passthrough" and s.get("tunnel_reason") == "out_of_scope"
                  and s.get("method") == "CONNECT",
                  f"push {p.get('event')}: summary carries tunnel=passthrough/out_of_scope on a CONNECT "
                  f"(got tunnel={s.get('tunnel')!r} reason={s.get('tunnel_reason')!r} method={s.get('method')!r})")
        resp = next((p.get("summary") or {} for p in mine if p.get("event") == "response"), {})
        check(resp.get("status") == 200 and resp.get("duration_ms") is not None
              and (resp.get("bytes_up") or 0) > 0 and (resp.get("bytes_down") or 0) > 0,
              f"the response push carries the closed tunnel's status/duration/bytes "
              f"(status={resp.get('status')!r} duration_ms={resp.get('duration_ms')!r} "
              f"bytes_up={resp.get('bytes_up')!r} bytes_down={resp.get('bytes_down')!r})")

        # ------------------------------------------------------------------ 2
        section("2. scope.add flips the NEXT connection to decrypted, live")
        scope_add(bus, HOST)
        section("6b. status: proxy.status.decrypt after scope.add says decrypting, no advice")
        check_decrypt(decrypt_status(bus), hosts=1, decrypting=True, advice=None)

        rc, code, body = curl_code(proxy + ["--cacert", ca, f"{tls_base}/b"])
        check(rc == 0 and code == 200,
              f"curl --cacert <aitm ca> now verifies: an aitm leaf was served (rc={rc}, code={code})")
        check('"path": "/b"' in body, f"the decrypted request reached the origin end to end (body={body[:120]!r})")
        rs = wait_rows(bus, tls_auth,
                       lambda rs: connects(rs, "decrypted") and gets(rs)
                       and all(r.get("status") is not None for r in gets(rs)))
        dec = connects(rs, "decrypted")
        check(len(dec) == 1, f"flow.table gained one CONNECT row with tunnel == decrypted (got {[brief(r) for r in dec]})")
        d = dec[0] if dec else {}
        check(d.get("status") == 200, f"the decrypted CONNECT row has status 200 (got {d.get('status')!r})")
        check(d.get("tunnel_reason") is None and d.get("passive") is False,
              f"the decrypted row has no reason and is not passive "
              f"(reason={d.get('tunnel_reason')!r} passive={d.get('passive')!r})")
        g = gets(rs)
        check(len(g) == 1 and g[0].get("path") == "/b",
              f"exactly one GET row for {tls_auth}, GET /b, the decrypted inner request (got {[brief(r) for r in g]})")
        gb = g[0] if g else {}
        check(gb.get("passive") is False and gb.get("tunnel") is None and gb.get("status") == 200,
              f"GET /b: passive false, tunnel null, status 200 "
              f"(passive={gb.get('passive')!r} tunnel={gb.get('tunnel')!r} status={gb.get('status')!r})")
        now1 = {r["id"]: dict(r) for r in rs if r["id"] in step1}
        check(now1 == step1,
              "the step-1 passthrough rows are unchanged (same ids, same fields) — existing tunnels are left alone"
              + ("" if now1 == step1 else f" (before={list(step1.values())}, after={list(now1.values())})"))

        # ------------------------------------------------------------------ 3
        section("3. scope.remove flips the NEXT connection back to passthrough")
        scope_remove(bus, HOST)
        rc, _out, err = curl(proxy + ["--cacert", ca, "-o", "/dev/null", f"{tls_base}/a"])
        check(rc == CURL_VERIFY_FAILED,
              f"curl --cacert <aitm ca> fails to verify again: the origin's cert is back "
              f"(rc={rc}, stderr={err.strip()[-160:]!r})")
        rs = wait_rows(bus, tls_auth,
                       lambda rs: len(connects(rs, "passthrough")) >= 3
                       and all(r.get("duration_ms") is not None for r in connects(rs, "passthrough")))
        pt = connects(rs, "passthrough")
        check(len(pt) == 3, f"a new passthrough row appeared (passthrough rows: {len(pt)})")
        newest = next((r for r in pt if r["id"] not in step1), {})
        check_passthrough_row(newest, "row 3 (after scope.remove)")
        check(len(gets(rs)) == 1, f"no new GET row: still only GET /b (GET rows={[brief(r) for r in gets(rs)]})")
        check(len(connects(rs, "decrypted")) == 1,
              f"no new decrypted row: still only the step-2 one (decrypted rows={len(connects(rs, 'decrypted'))})")

        # ------------------------------------------------------------------ 4
        section("4. CA refused: an in-Scope client that distrusts the aitm CA is a failed row that says so")
        scope_add(bus, HOST)
        rc, _out, err = curl(proxy + ["-o", "/dev/null", f"{tls_base}/c"])
        check(rc == CURL_VERIFY_FAILED,
              f"curl with neither --cacert nor -k rejects the aitm leaf (rc={rc}, stderr={err.strip()[-160:]!r})")
        rs = wait_rows(bus, tls_auth,
                       lambda rs: connects(rs, "failed")
                       and all(r.get("duration_ms") is not None for r in connects(rs, "failed")))
        failed = connects(rs, "failed")
        check(len(failed) == 1, f"flow.table gained one CONNECT row with tunnel == failed (got {[brief(r) for r in failed]})")
        f = failed[0] if failed else {}
        check(f.get("tunnel_reason") == "client_rejected_certificate",
              f"tunnel_reason == client_rejected_certificate (got {f.get('tunnel_reason')!r})")
        check(f.get("status") is None, f"a failed tunnel never reports 200: status is null (got {f.get('status')!r})")
        check(f.get("duration_ms") is not None, f"duration_ms is set on the failed row (got {f.get('duration_ms')!r})")
        check(not [r for r in gets(rs) if r.get("path") == "/c"], "no GET /c row: the request never left the client")

        # ------------------------------------------------------------------ 5
        section("5. plain HTTP to an out-of-Scope host is passive: captured, never parked")
        scope_remove(bus, HOST)
        rule = {"url": f"*127.0.0.1:{plain.port}*"}
        bus.call("flow.intercept", {"enabled": True, "rules": [rule]})
        ok(f"breakpoint rule armed: {rule}")
        rc, code, body = curl_code(proxy + [f"{plain.base}/p"])
        check(rc == 0 and code == 200,
              f"GET /p through the proxy returned 200 at once, it did not park (rc={rc}, code={code})")
        check("aitm-e2e-upstream" in body, f"the body is the UPSTREAM's own echo (body={body[:100]!r})")
        rec = [r for r in plain.received if r["path"] == "/p"]
        check(len(rec) == 1 and rec[0]["method"] == "GET",
              f"the UPSTREAM's own record already has GET /p (rec={rec[:1]})")
        prs = wait_rows(bus, plain.authority,
                        lambda rs: [r for r in rs if r.get("path") == "/p" and r.get("status") is not None])
        prow = next((r for r in prs if r.get("path") == "/p"), {})
        check(prow.get("passive") is True, f"the /p row has passive == true (row={brief(prow)})")
        check(prow.get("state") == "observed", f"the /p row was never intercepted: state == observed (got {prow.get('state')!r})")
        check(prow.get("tunnel") is None, f"the /p row is not a tunnel row (tunnel={prow.get('tunnel')!r})")
        paused = bus.call("proxy.status").get("paused")
        check(paused == 0, f"proxy.status.paused == 0: nothing is parked (got {paused!r})")

        section("5. after scope.add the same request IS parked by the same rule")
        scope_add(bus, HOST)
        # No -m here: this request is MEANT to park until flow.resume (as in
        # test_intercept_url_rules.py); the subprocess timeout bounds it instead.
        t, res = curl_bg(via + ["-o", "/dev/null", "-w", "%{http_code}", f"{plain.base}/q"])
        pid = parked(bus, "/q")
        check(pid is not None, "GET /q parks under the rule now that its host is in Scope (intercept == intercepted)")
        check(not [r for r in plain.received if r["path"] == "/q"],
              "the UPSTREAM has not seen GET /q while it is parked")
        qrow = next((r for r in rows_for(bus, plain.authority) if r.get("id") == pid), {})
        check(qrow.get("passive") is False, f"the parked /q row has passive == false (row={brief(qrow)})")
        paused = bus.call("proxy.status").get("paused")
        check(paused == 1, f"proxy.status.paused == 1 while /q is parked (got {paused!r})")
        bus.call("flow.resume", {"id": pid})
        t.join(timeout=20)
        code = res.get("out", b"").decode("utf-8", "replace").strip()
        check(code == "200", f"flow.resume lets curl finish with 200 (code={code!r} rc={res.get('rc')})")
        rec = [r for r in plain.received if r["path"] == "/q"]
        check(len(rec) == 1 and rec[0]["method"] == "GET",
              f"the UPSTREAM's own record has GET /q after the resume (rec={rec[:1]})")
        bus.call("flow.intercept", {"enabled": False, "rules": []})
        ok("breakpoint disarmed")

        # ------------------------------------------------------------------ 6
        section("6. status: decrypt read-back follows Scope both ways")
        check_decrypt(decrypt_status(bus), hosts=1, decrypting=True, advice=None)
        scope_remove(bus, HOST)
        check_decrypt(decrypt_status(bus), hosts=0, decrypting=False, advice=ADVICE)
    finally:
        if bus:
            bus.try_call("flow.intercept", {"enabled": False, "rules": []})
            bus.close()
        if sub:
            sub.close()
        if core:
            core.stop()
        tls_srv.shutdown()
        plain.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
