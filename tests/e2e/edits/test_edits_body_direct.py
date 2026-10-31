#!/usr/bin/env python3
# e2e: tier=T1 surface=edits serial
"""edits/test_edits_body_direct -- the `edits` body op mutates a HELD request body,
and the ORIGIN receives the MUTATED body, not the original.

This exercises aitmproxy's OWN edit path (flow.mutate's `edits.body`) against its
OWN seeded loopback target (crates/aitm-testtarget's POST /comments store) -- first
-party authorized testing, no third party involved. The origin is booted by this
test on a random loopback port (aitm_e2e.target.Target, like the query/header
siblings boot their own Upstream); the shared proxy's loopback scope already
covers it, so no AITM_TARGET_URL is needed.

Ground truth (never fixtures, never the proxy's own view):
  * a REAL HTTP/1.1 POST /comments with body `comment=<ORIG>` sent THROUGH the proxy
    is parked by a breakpoint rule scoped to this run's marker: flow.table shows the
    row state=intercepted with no status, and flow.detail (body inline, base64 off
    the bus) shows the parked request body is byte-for-byte the ORIGINAL -- and no
    response / no server_conn, so nothing has gone upstream yet;
  * flow.mutate {id, edits:{body:"comment=<MUT>"}} replaces the held body IN PLACE:
    flow.detail now returns the MUTATED bytes (a DIFFERENT length than the original),
    body_size matches the new length, edited=true, and the flow is STILL parked
    (intercept=intercepted, still no response, still nothing upstream) -- the edit
    landed on the held request before any byte left for the origin;
  * flow.resume {id} releases it; the blocked client's POST completes (the origin's
    302 redirect to /comments), proving the mutated, Content-Length-reframed request
    was actually forwarded;
  * the ORIGIN (aitm-testtarget, read DIRECTLY -- not through the proxy) lists the
    MUTATED comment and NEVER the original: the edit op changed what upstream stored;
  * a control comment POSTed through the proxy unmutated DOES appear, so the
    "original absent" check is live, not vacuous (the store faithfully records what
    upstream receives; the original's absence means upstream truly never got it).

Roles: flow.intercept is Sensitive (the default agent policy may refuse it), so
arming tries the agent first and falls back to the operator token (skips without
one). flow.mutate and flow.resume are Write tier and are driven by the AGENT.

Runner contract (environment; this test boots its own origin but never its own core):
  AITM_BUS_ADDR   host:port of the loopback MCP bus
  AITM_BUS_TOKEN  the agent token (never printed)
  AITM_PROXY_ADDR host:port of the proxy listener
  AITM_BUS_OPERATOR_TOKEN  optional: the operator token (needed to arm interception
                           when the agent policy refuses it)
The seeded origin is this test's own aitm-testtarget (aitm_e2e.target.Target) on a
random loopback port; no AITM_TARGET_URL is consulted.
flow.intercept arms a GLOBAL mode and replaces the GLOBAL rule set: run this alone.
"""

from __future__ import annotations

import base64
import http.client
import os
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Callable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402

CLIENT_TIMEOUT_S = 40.0  # the held client's OWN socket timeout; resume must beat it by far
PARK_WAIT_S = 15.0  # how long the parked row may take to appear in flow.table
HOLD_GRACE_S = 1.0  # how long we watch the parked client stay blocked before editing
RESUME_COMPLETE_S = 15.0  # the released POST must complete within this after flow.resume
FORM = "application/x-www-form-urlencoded"
DEFAULT_POLICIES = ("auto", "all", "ask")  # policies under which a Write call must be allowed


# --- the runner-provided core -------------------------------------------------


def _hostport(addr: str) -> Tuple[str, int]:
    host, sep, port = addr.strip().rpartition(":")
    if not sep or not port.isdigit():
        fail(f"malformed host:port {addr!r}")
    return (host.strip("[]") or "127.0.0.1"), int(port)


class _Cfg:
    def __init__(self, agent_token: str, operator_token: Optional[str]):
        self.agent_token = agent_token
        self.operator_token = operator_token


class EnvCore:
    """The core the runner already booted, shaped like aitm_e2e.core.Aitm (bus_addr +
    cfg.agent_token / cfg.operator_token) so BusClient.agent(core) and
    BusClient.operator(core) work unchanged."""

    REQUIRED = ("AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_PROXY_ADDR")

    def __init__(self) -> None:
        missing = [k for k in self.REQUIRED if not os.environ.get(k)]
        if missing:
            skip(f"no runner-provided core: {' '.join(missing)} unset (see tests/e2e/README.md)")
        self.bus_addr = _hostport(os.environ["AITM_BUS_ADDR"])
        self.cfg = _Cfg(os.environ["AITM_BUS_TOKEN"], os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None)
        self.proxy_host, self.proxy_port = _hostport(os.environ["AITM_PROXY_ADDR"])

    @property
    def has_operator(self) -> bool:
        return bool(self.cfg.operator_token)


# --- the real client whose request is parked, then released -------------------


class ProxyPoster(threading.Thread):
    """One REAL HTTP/1.1 POST sent THROUGH the proxy (absolute-form, as a browser
    configured with aitm as its HTTP proxy would send it). The call blocks inside the
    proxy while the flow is parked and returns only once flow.resume forwards it; the
    thread records the response (or error) the client actually observed."""

    def __init__(self, core: EnvCore, url: str, body: bytes) -> None:
        super().__init__(daemon=True, name="edits-body-poster")
        self.core = core
        self.url = url
        self.body = body
        self.resp = None
        self.error: Optional[BaseException] = None
        self.started: float = 0.0
        self.finished: Optional[float] = None

    def run(self) -> None:
        self.started = time.monotonic()
        try:
            self.resp = via_proxy(
                self.core.proxy_port,
                "POST",
                self.url,
                headers={"Content-Type": FORM},
                body=self.body,
                timeout=CLIENT_TIMEOUT_S,
            )
        except BaseException as e:  # noqa: BLE001 -- record whatever the client saw
            self.error = e
        finally:
            self.finished = time.monotonic()


# --- bus helpers --------------------------------------------------------------


def table_rows(bus: BusClient) -> List[dict]:
    t = bus.call("flow.table")
    rows = t.get("flows", []) if isinstance(t, dict) else (t or [])
    return [r for r in rows if isinstance(r, dict)]


def wait_for_row(bus: BusClient, pred: Callable[[dict], bool], timeout: float) -> Optional[dict]:
    deadline = time.monotonic() + timeout
    while True:
        for r in table_rows(bus):
            try:
                if pred(r):
                    return r
            except Exception:  # noqa: BLE001 -- a matcher tripping on a non-HTTP row
                pass
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.1)


def agent_policy(bus: BusClient) -> Optional[str]:
    st, status = bus.try_call("agent.status")
    return status.get("policy") if st == "ok" and isinstance(status, dict) else None


def arm(core: EnvCore, agent: BusClient, rule: dict) -> Tuple[BusClient, dict]:
    """Arm `rule` on whichever connection may: the agent when its policy answers a
    Sensitive call at once, else the operator. Returns (controlling bus, result)."""
    policy = agent_policy(agent)
    if policy != "ask":  # under `ask` the agent's call would PARK for approval, not answer
        st, res = agent.try_call("flow.intercept", {"enabled": True, "rules": [rule]})
        if st == "ok":
            ok(f"agent (policy={policy}) armed flow.intercept itself")
            return agent, res
        ok(f"agent (policy={policy}) is refused flow.intercept (Sensitive), as expected: {str(res)[:100]}")
    else:
        ok("agent policy is `ask` (its flow.intercept call would park for approval); arming as operator")
    if not core.has_operator:
        skip("arming flow.intercept needs the operator here and AITM_BUS_OPERATOR_TOKEN is unset")
    op = BusClient.operator(core)
    return op, op.call("flow.intercept", {"enabled": True, "rules": [rule]})


def write_call(agent: BusClient, tool: str, args: dict):
    """Drive a Write-tier command as the AGENT; skip (not fail) if the agent's policy
    refuses Write entirely (a non-default policy), so the suite stays honest about
    which core it was handed. Returns the tool result."""
    st, res = agent.try_call(tool, args)
    if st == "ok":
        return res
    policy = agent_policy(agent)
    if policy not in DEFAULT_POLICIES:
        skip(f"agent policy is {policy!r}: {tool} (Write) is refused by design; run the core with its default policy")
    fail(f"agent is REFUSED {tool} (Write tier) under policy={policy!r}: {res}")


def held_request(bus: BusClient, fid) -> Tuple[dict, dict, str, int]:
    """flow.detail (body inline) for a flow, with the request body decoded from the
    base64 the bus carries `Value::Bytes` as. Returns (detail, request, body, size)."""
    d = bus.call("flow.detail", {"id": fid, "body": "inline"})
    req = d.get("request") or {}
    raw = req.get("body")
    body = base64.b64decode(raw).decode("utf-8", "replace") if isinstance(raw, str) and raw else ""
    size = int(req.get("body_size") or 0)
    return d, req, body, size


def origin_get(target: Target, path: str) -> Tuple[int, str]:
    """Read the seeded origin DIRECTLY (no proxy): the independent observer."""
    thost, tport = target.host().split(":")
    conn = http.client.HTTPConnection(thost, int(tport), timeout=10)
    try:
        conn.request("GET", path, headers={"Host": target.authority})
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


# --- the scenario -------------------------------------------------------------


def main() -> int:
    core = EnvCore()
    run = f"edit{uuid.uuid4().hex[:10]}"
    orig_marker = f"{run}-ORIGINAL"
    # Deliberately a DIFFERENT length than the original, so a correct result proves
    # the body was truly replaced AND the egress re-framed Content-Length to the new
    # length (a stale length would desync the origin's form parse).
    mut_marker = f"{run}-MUTATED-replaced-by-edits-op"
    ctl_marker = f"{run}-CONTROL-unmutated"
    orig_body = urllib.parse.urlencode({"comment": orig_marker}).encode()
    mut_body = urllib.parse.urlencode({"comment": mut_marker}).encode()
    # Anchored wildcard over the request target (path + query): only this run's POST
    # matches, so everything else keeps flowing while we hold ours.
    rule = {"id": run, "name": "e2e edits_body_direct", "phase": "request", "method": "POST", "url": f"*e2e={run}*"}

    # The origin is this test's OWN seeded aitm-testtarget (crates/aitm-testtarget),
    # booted here on a random loopback port exactly as the query/header siblings boot
    # their own Upstream — the shared proxy's loopback scope already covers it. We need
    # the seeded `/comments` store (POST -> 302 + append, GET -> <li> list) that a plain
    # echo origin does not have, so this cell owns its origin instead of reading
    # AITM_TARGET_URL (whatever the runner put there).
    target = Target("vulnerable")
    agent = BusClient.agent(core)
    ctl: Optional[BusClient] = None
    poster: Optional[ProxyPoster] = None
    fid = None
    resumed = False
    try:
        section("preflight: the runner's core exposes the commands under test")
        names = set(agent.tool_names())
        need = ["flow.intercept", "flow.mutate", "flow.resume", "flow.table", "flow.detail", "proxy.status"]
        missing = [n for n in need if n not in names]
        check(not missing, f"live tools/list registers {need} (missing: {missing or 'none'})")
        ok(f"core has {len(names)} tools; proxy {core.proxy_host}:{core.proxy_port}; origin {target.base}; marker {run}")
        check(len(orig_body) != len(mut_body), f"original ({len(orig_body)}B) and mutated ({len(mut_body)}B) bodies differ in length")

        section("arrange: arm a breakpoint rule that matches ONLY this run's POST")
        ctl, armed = arm(core, agent, rule)
        check(isinstance(armed, dict) and armed.get("enabled") is True, f"flow.intercept reports enabled=true ({armed!r})")
        rule_ids = [r.get("id") for r in (armed.get("rules") or []) if isinstance(r, dict)]
        check(rule_ids == [run], f"the active rule set is exactly our rule ({rule_ids})")
        st = agent.call("proxy.status")
        check(st.get("intercept_armed") is True, f"proxy.status reports intercept_armed=true ({st.get('intercept_armed')!r})")

        section("act 1: a REAL POST (body=comment=<ORIGINAL>) through the proxy is parked")
        poster = ProxyPoster(core, f"{target.base}/comments?e2e={run}", orig_body)
        poster.start()
        row = wait_for_row(
            agent,
            lambda r: run in (r.get("path") or "") and r.get("state") == "intercepted",
            PARK_WAIT_S,
        )
        if row is None:
            fail(
                f"no flow.table row for {run} in state=intercepted within {PARK_WAIT_S}s "
                f"(poster finished={poster.finished is not None}, error={poster.error!r})"
            )
        fid = row["id"]
        ok(f"flow {fid} parked: {row.get('method')} {row.get('authority')}{row.get('path')}")
        check(row.get("status") is None, f"parked row has no response status yet ({row.get('status')!r})")

        section("ground truth A: the HELD request body is the ORIGINAL, nothing upstream yet")
        d, _req, body, size = held_request(agent, fid)
        check(d.get("intercept") == "intercepted", f"flow.detail intercept={d.get('intercept')!r} (expected intercepted)")
        check(body == orig_body.decode(), f"held request body is the ORIGINAL ({body!r})")
        check(size == len(orig_body), f"held body_size {size} == original length {len(orig_body)}")
        check(d.get("edited") is False, f"flow.detail edited=false before any mutation ({d.get('edited')!r})")
        check(d.get("response") is None, f"no response while parked ({d.get('response')!r})")
        check(d.get("server_conn") is None, f"no server_conn: nothing went upstream ({d.get('server_conn')!r})")
        time.sleep(HOLD_GRACE_S)
        check(poster.is_alive() and poster.resp is None, "client still blocked in the proxy (POST has not returned)")

        section("act 2: the edits body op mutates the HELD request in place (flow.mutate as AGENT)")
        res = write_call(agent, "flow.mutate", {"id": fid, "edits": {"body": mut_body.decode()}})
        check(str(res) == str(fid), f"flow.mutate returned the edited flow id ({res!r})")
        d2, _req2, body2, size2 = held_request(agent, fid)
        check(body2 == mut_body.decode(), f"held request body is now the MUTATED value ({body2!r})")
        check(size2 == len(mut_body), f"mutated body_size {size2} == mutated length {len(mut_body)} (replaced, not appended)")
        check(d2.get("edited") is True, f"flow.detail edited=true after the mutation ({d2.get('edited')!r})")
        check(d2.get("intercept") == "intercepted", f"flow is STILL parked after the edit ({d2.get('intercept')!r})")
        check(d2.get("response") is None and d2.get("server_conn") is None, "still nothing upstream after the edit (not forwarded yet)")
        check(poster.is_alive(), "client still blocked after the edit (the edit alone does not release it)")

        section("act 3: flow.resume (AGENT, Write) forwards the MUTATED request")
        t_resume = time.monotonic()
        res = write_call(agent, "flow.resume", {"id": fid})
        resumed = True
        check(res == "resumed", f"flow.resume answered {res!r} (expected 'resumed')")
        poster.join(RESUME_COMPLETE_S + 5)
        released_after = (poster.finished or time.monotonic()) - t_resume
        check(not poster.is_alive(), f"client POST returned after the resume ({released_after:.3f}s after the call)")
        if poster.error is not None:
            fail(f"client POST errored instead of completing: {poster.error!r}")
        check(poster.resp is not None, "client received a response from the origin (via the proxy)")
        check(
            poster.resp is not None and poster.resp.status // 100 == 3,
            f"origin answered the forwarded POST with its 302 redirect (got {getattr(poster.resp, 'status', None)})",
        )

        section("ground truth B: the ORIGIN stored the MUTATED comment, never the original (read DIRECTLY)")
        status, html = origin_get(target, "/comments")
        check(status == 200, f"origin GET /comments (direct, no proxy) answered {status}")
        check(f"<li>{mut_marker}</li>" in html, "origin lists the MUTATED comment -- the edit op reached upstream")
        check(f"<li>{orig_marker}</li>" not in html, "origin NEVER stored the original comment -- it was truly replaced")
        check(orig_marker not in html, "the original marker appears nowhere in the origin's state")

        section("liveness: a control POST (unmutated, after disarm) DOES appear -- the negative check is live")
        off = ctl.call("flow.intercept", {"enabled": False, "rules": []})
        check(off.get("enabled") is False and off.get("rules") == [], f"disarmed with an empty rule set ({off!r})")
        check(agent.call("proxy.status").get("intercept_armed") is False, "proxy.status reports intercept_armed=false")
        rc = via_proxy(
            core.proxy_port,
            "POST",
            f"{target.base}/comments?e2e={run}-ctl",
            headers={"Content-Type": FORM},
            body=urllib.parse.urlencode({"comment": ctl_marker}).encode(),
        )
        check(rc.status // 100 == 3, f"control POST after disarm reached the origin through the proxy (redirect, got {rc.status})")
        _st, html2 = origin_get(target, "/comments")
        check(f"<li>{ctl_marker}</li>" in html2, "origin lists the control comment -- the store faithfully records what upstream receives")
        check(f"<li>{orig_marker}</li>" not in html2, "still no original comment after the control write (the edit's replacement holds)")
        ok(f"edits body op on held flow {fid}: {orig_marker!r} -> {mut_marker!r} reached the origin, original never did")
    finally:
        if fid is not None and not resumed:
            # Never leave a parked flow (and a blocked client thread) behind.
            (ctl or agent).try_call("flow.kill", {"id": fid})
        if ctl is not None:
            ctl.try_call("flow.intercept", {"enabled": False, "rules": []})  # never leave the global arm behind
        if poster is not None and poster.is_alive():
            poster.join(5)
        if ctl is not None and ctl is not agent:
            ctl.close()
        agent.close()
        target.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
