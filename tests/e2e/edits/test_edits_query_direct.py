#!/usr/bin/env python3
# e2e: tier=T1 surface=edits serial
"""edits/test_edits_query_direct -- the `edits` query op on flow.mutate rewrites the
query string of a PARKED request, and the resumed request reaches the ORIGIN with
the mutated query -- proven on the origin's OWN record, never the proxy's view.

What "the query edit op" is, read from the code rather than assumed: flow.mutate
{id, edits} (crates/aitm-plugins/src/mutate.rs) applies an `edits` object to the
stored request; its keys are method / scheme / authority / path / headers / body
(+ status for a parked response). The request target's query lives in `path`
("Request path and query"), so the query edit is `edits.path = "/p?q=<new>&..."`.
Unknown keys are refused and leave the flow unchanged. The HTTP/1 module forwards
`flow.request` RE-READ from the store after the Request event returns
(crates/aitm-proto-http/src/module.rs), so an edit made while the flow is parked is
exactly what goes upstream on flow.resume.

Ground truth (never fixtures):
  * a REAL GET through the REAL proxy to a REAL loopback echo-record origin
    (aitm_e2e.upstream.Upstream, the independent observer) is parked by a
    breakpoint rule scoped to this run's marker: flow.table shows the row
    state=intercepted with no status, flow.detail has no response / no server_conn,
    and the origin has recorded NOTHING for the marker -- nothing went upstream
    before the edit;
  * flow.mutate {id, edits: {path: <same path, q=<new>, other params untouched>}}
    as the AGENT (Write tier) answers the flow id; the store now shows the new
    target (flow.detail request.path, flow.table path), edited=true, the method and
    headers untouched, and the flow STILL parked (a mutate does not release);
  * flow.resume {id} as the AGENT answers "resumed", and the blocked client gets the
    origin's real 200 whose echo names the MUTATED target;
  * THE PROOF: the origin's own record holds exactly ONE request for this run's
    marker, its request-target is the mutated one (q == <new>, the untouched
    parameter still present, the User-Agent this client sent), and the ORIGINAL
    q value appears in NO request the origin ever received;
  * the store agrees afterwards: intercept=resumed, request.path mutated,
    edited=true, response.status 200, a real server_conn; flow.table state=resumed;
  * control (after disarm): the same path with the ORIGINAL q sent through the
    proxy reaches the origin VERBATIM -- the proxy forwards queries untouched, so
    the rewrite above was the edit op, not a side-effect of proxying.

Roles: flow.intercept is Sensitive (the default agent policy refuses it), so arming
tries the agent first and falls back to the operator token (skips without one).
flow.mutate and flow.resume are Write tier and MUST succeed as the agent.

Runner contract (environment; this test never boots a core of its own):
  AITM_BUS_ADDR   host:port of the loopback MCP bus
  AITM_BUS_TOKEN  the agent token (never printed)
  AITM_PROXY_ADDR host:port of the proxy listener
  AITM_BUS_OPERATOR_TOKEN  optional: the operator token (needed to arm interception
                           when the agent policy refuses it)
The origin is this script's own echo-record Upstream on a random loopback port
(the passive connector relays freely; no AITM_TARGET_URL needed).
flow.intercept arms a GLOBAL mode and replaces the GLOBAL rule set: run this alone.
"""

from __future__ import annotations

import json
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
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.proxyutil import ProxyResponse, via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

CLIENT_TIMEOUT_S = 60.0  # the held client's OWN socket timeout; the resume must beat it by far
PARK_WAIT_S = 15.0  # how long the parked row may take to appear in flow.table
RESUME_RELEASE_S = 10.0  # the client must have its response this soon after flow.resume
HOLD_GRACE_S = 0.5  # how long we watch a parked client stay blocked after the mutate
UA = "aitm-e2e/edits_query_direct"
ECHO_MARKER = "aitm-e2e-upstream"  # the echo-record origin's own response signature
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


# --- the real client whose request is parked, edited, then forwarded -----------


class HeldClient(threading.Thread):
    """One REAL GET sent through the proxy (absolute-form, as a browser configured
    with aitm as its HTTP proxy would send it); it then blocks waiting for the
    response. Records exactly what the client got: the response, or the error."""

    def __init__(self, core: EnvCore, url: str) -> None:
        super().__init__(daemon=True, name="held-client")
        self.core = core
        self.url = url
        self.response: Optional[ProxyResponse] = None
        self.error: Optional[BaseException] = None
        self.started: float = 0.0
        self.finished: Optional[float] = None

    def run(self) -> None:
        self.started = time.monotonic()
        try:
            self.response = via_proxy(
                self.core.proxy_port, "GET", self.url, headers={"User-Agent": UA}, timeout=CLIENT_TIMEOUT_S
            )
        except BaseException as e:  # noqa: BLE001 -- record whatever the client experienced
            self.error = e
        finally:
            self.finished = time.monotonic()

    def blocked(self) -> bool:
        return self.is_alive() and self.response is None and self.error is None


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


def row_by_id(bus: BusClient, fid) -> Optional[dict]:
    return next((r for r in table_rows(bus) if str(r.get("id")) == str(fid)), None)


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
    """A Write-tier call that MUST succeed as the agent under a default policy."""
    st, res = agent.try_call(tool, args)
    if st != "ok":
        policy = agent_policy(agent)
        if policy not in DEFAULT_POLICIES:
            skip(f"agent policy is {policy!r}: {tool} (Write) is refused by design; run the core with its default policy")
        fail(f"agent is REFUSED {tool} (Write tier) under policy={policy!r}: {res}")
    return res


def refused(bus: BusClient, tool: str, args: dict) -> Tuple[bool, str]:
    """True when the core refused the call -- a ToolError (isError) OR a JSON-RPC
    error for a malformed argument. Either way the edit did NOT happen."""
    try:
        res = bus.call(tool, args)
    except (ToolError, BusError) as e:
        return True, str(e)
    return False, repr(res)


# --- the origin's record ------------------------------------------------------


def target_of(recorded_path: str) -> str:
    """The request-target the origin saw, normalised to origin-form (path?query) in
    case a proxy ever forwarded absolute-form."""
    if recorded_path.startswith(("http://", "https://")):
        u = urllib.parse.urlparse(recorded_path)
        return u.path + (f"?{u.query}" if u.query else "")
    return recorded_path


def hits(origin: Upstream, marker: str) -> List[dict]:
    """The requests the origin REALLY received whose target carries `marker`."""
    return [r for r in origin.received if marker in target_of(r["path"])]


def qs(target: str) -> dict:
    return urllib.parse.parse_qs(urllib.parse.urlparse(target).query, keep_blank_values=True)


# --- the scenario -------------------------------------------------------------


def main() -> int:
    core = EnvCore()
    run = f"qedit{uuid.uuid4().hex[:10]}"
    held_marker, ctl_marker = f"e2e={run}-held", f"e2e={run}-ctl"
    base_path = f"/edits-{run}"
    orig_q, new_q, keep = f"orig-{run}", f"mutated-{run}", f"keep-{run}"
    # The ORIGINAL target the client sends, and the target the edit op must make of
    # it: ONLY `q` changes; `keep` and the run marker stay exactly where they were.
    orig_target = f"{base_path}?q={orig_q}&keep={keep}&{held_marker}"
    new_target = f"{base_path}?q={new_q}&keep={keep}&{held_marker}"
    ctl_target = f"{base_path}?q={orig_q}&keep={keep}&{ctl_marker}"
    # `url` is an anchored wildcard over the request target (path + query): only
    # this run's held GET matches; everything else keeps flowing.
    rule = {"id": run, "name": "e2e edits_query_direct", "phase": "request", "method": "GET", "url": f"*{held_marker}*"}

    origin = Upstream().start()
    agent = BusClient.agent(core)
    ctl: Optional[BusClient] = None
    held: Optional[HeldClient] = None
    fid = None
    try:
        section("preflight: the runner's core exposes the commands under test")
        names = set(agent.tool_names())
        need = ["flow.intercept", "flow.mutate", "flow.resume", "flow.table", "flow.detail", "proxy.status"]
        missing = [n for n in need if n not in names]
        check(not missing, f"live tools/list registers {need} (missing: {missing or 'none'})")
        schema = next((t for t in agent.tools() if t.get("name") == "flow.mutate"), {}).get("inputSchema") or {}
        edit_keys = sorted(((schema.get("properties") or {}).get("edits") or {}).get("properties") or {})
        check("path" in edit_keys, f"flow.mutate's live `edits` schema carries `path` (request path AND query): {edit_keys}")
        ok(f"core has {len(names)} tools; proxy {core.proxy_host}:{core.proxy_port}; origin {origin.base}; marker {run}")

        section("arrange: arm a breakpoint rule that matches ONLY this run's held GET")
        ctl, armed = arm(core, agent, rule)
        check(isinstance(armed, dict) and armed.get("enabled") is True, f"flow.intercept reports enabled=true ({armed!r})")
        rule_ids = [r.get("id") for r in (armed.get("rules") or []) if isinstance(r, dict)]
        check(rule_ids == [run], f"the active rule set is exactly our rule ({rule_ids})")
        check(agent.call("proxy.status").get("intercept_armed") is True, "proxy.status reports intercept_armed=true")

        section("act 1: a REAL GET through the proxy is parked before anything goes upstream")
        held = HeldClient(core, f"{origin.base}{orig_target}")
        held.start()
        row = wait_for_row(
            agent,
            lambda r: held_marker in (r.get("path") or "") and r.get("state") == "intercepted",
            PARK_WAIT_S,
        )
        if row is None:
            fail(
                f"no flow.table row for {held_marker} in state=intercepted within {PARK_WAIT_S}s "
                f"(client response={held.response and held.response.status!r}, error={held.error!r})"
            )
        fid = row["id"]
        ok(f"flow {fid} parked: {row.get('method')} {row.get('authority')}{row.get('path')}")
        check(row.get("path") == orig_target, f"parked row carries the ORIGINAL target ({row.get('path')!r})")
        check(row.get("status") is None, f"parked row has no response status yet ({row.get('status')!r})")
        d0 = agent.call("flow.detail", {"id": fid, "body": "none"})
        req0 = d0.get("request") or {}
        check(d0.get("intercept") == "intercepted", f"flow.detail intercept={d0.get('intercept')!r} (expected intercepted)")
        check(req0.get("path") == orig_target, f"flow.detail request.path is the original target ({req0.get('path')!r})")
        check(req0.get("authority") == origin.authority, f"flow.detail request.authority is the origin ({req0.get('authority')!r})")
        check(d0.get("edited") is False, f"flow.detail edited={d0.get('edited')!r} before any mutate (expected false)")
        check(d0.get("response") is None, f"flow.detail has no response while parked ({d0.get('response')!r})")
        check(d0.get("server_conn") is None, f"flow.detail has no server_conn: nothing went upstream ({d0.get('server_conn')!r})")
        check(len(hits(origin, held_marker)) == 0, "origin has recorded NOTHING for the held marker: the request is truly parked")
        headers_before = {k.lower(): v for k, v in (req0.get("headers") or {}).items()} if isinstance(req0.get("headers"), dict) else req0.get("headers")

        section("act 2: flow.mutate edits.path rewrites q=<orig> -> q=<new> as the AGENT (Write tier)")
        res = write_call(agent, "flow.mutate", {"id": fid, "edits": {"path": new_target}})
        check(str(res).strip('"') == str(fid), f"flow.mutate answered the flow id ({res!r})")
        d1 = agent.call("flow.detail", {"id": fid, "body": "none"})
        req1 = d1.get("request") or {}
        check(req1.get("path") == new_target, f"flow.detail request.path is now the MUTATED target ({req1.get('path')!r})")
        check(qs(req1.get("path") or "").get("q") == [new_q], f"the stored query has q={new_q!r}")
        check(qs(req1.get("path") or "").get("keep") == [keep], f"the untouched parameter keep={keep!r} survived the edit")
        check(d1.get("edited") is True, f"flow.detail edited={d1.get('edited')!r} after the mutate (expected true)")
        check(req1.get("method") == "GET" and req1.get("authority") == origin.authority, "method and authority untouched by the query edit")
        headers_after = {k.lower(): v for k, v in (req1.get("headers") or {}).items()} if isinstance(req1.get("headers"), dict) else req1.get("headers")
        check(headers_after == headers_before, "request headers untouched by the query edit")
        check(d1.get("intercept") == "intercepted", f"the flow is STILL parked after the mutate (intercept={d1.get('intercept')!r})")
        check(d1.get("response") is None and d1.get("server_conn") is None, "still no response / server_conn: the mutate did not forward anything")
        row1 = row_by_id(agent, fid)
        check(row1 is not None and row1.get("path") == new_target, f"flow.table row shows the mutated target ({row1 and row1.get('path')!r})")
        time.sleep(HOLD_GRACE_S)
        check(held.blocked(), f"client still blocked {HOLD_GRACE_S}s after the mutate (response={held.response!r}, error={held.error!r})")
        check(len(hits(origin, held_marker)) == 0, "origin STILL has nothing for the held marker: the edit happened before forwarding")

        section("act 3: flow.resume as the AGENT forwards the EDITED request")
        t_resume = time.monotonic()
        res = write_call(agent, "flow.resume", {"id": fid})
        check(res == "resumed", f"flow.resume answered {res!r} (expected 'resumed')")
        held.join(RESUME_RELEASE_S + 5)
        released_after = (held.finished or time.monotonic()) - t_resume
        check(not held.is_alive(), f"client thread returned after the resume ({released_after:.3f}s after the call)")
        check(released_after < RESUME_RELEASE_S, f"client answered {released_after:.3f}s after flow.resume (< {RESUME_RELEASE_S}s), not by its own timeout")
        if held.error is not None:
            fail(f"client got no response: {type(held.error).__name__}: {held.error}")
        resp = held.response
        check(resp is not None and resp.status == 200, f"client got the origin's real 200 through the proxy (was {resp and resp.status})")
        try:
            echo = json.loads(resp.text)
        except json.JSONDecodeError:
            echo = {}
        check(echo.get("observed_by") == ECHO_MARKER, f"the body is the echo-record origin's own answer ({str(resp.text)[:100]!r})")
        check(target_of(echo.get("path") or "") == new_target, f"the origin's echo names the MUTATED target ({echo.get('path')!r})")

        section("GROUND TRUTH: the origin's own record holds exactly the mutated request, never the original")
        got = hits(origin, held_marker)
        check(len(got) == 1, f"origin recorded exactly ONE request for the held marker ({len(got)})")
        rec = got[0] if got else {"path": "", "method": None, "headers": {}}
        target = target_of(rec["path"])
        check(target == new_target, f"origin received the MUTATED request-target ({target!r})")
        check(qs(target).get("q") == [new_q], f"origin saw q={new_q!r}")
        check(qs(target).get("keep") == [keep], f"origin saw the untouched parameter keep={keep!r}")
        check(orig_q not in target, f"the ORIGINAL q value {orig_q!r} is not in what the origin received")
        check(rec["method"] == "GET", f"origin saw the method unchanged (GET; was {rec['method']!r})")
        check(rec["headers"].get("user-agent") == UA, f"the record is THIS client's request (user-agent {rec['headers'].get('user-agent')!r})")
        leaked = [target_of(r["path"]) for r in origin.received if orig_q in target_of(r["path"])]
        check(leaked == [], f"the original q value reached the origin in NO request ever ({leaked})")

        section("the store agrees: resumed, mutated, edited, answered 200 over a real upstream connection")
        d2 = agent.call("flow.detail", {"id": fid, "body": "none"})
        req2, resp2 = d2.get("request") or {}, d2.get("response") or {}
        check(d2.get("intercept") == "resumed", f"flow.detail intercept={d2.get('intercept')!r} (expected resumed)")
        check(req2.get("path") == new_target, f"flow.detail request.path stays the mutated target ({req2.get('path')!r})")
        check(d2.get("edited") is True, f"flow.detail edited={d2.get('edited')!r} (expected true)")
        check(isinstance(resp2, dict) and resp2.get("status") == 200, f"flow.detail response.status={resp2.get('status') if isinstance(resp2, dict) else resp2!r}")
        check(d2.get("server_conn") is not None, f"flow.detail has a real server_conn now ({d2.get('server_conn')!r})")
        row2 = row_by_id(agent, fid)
        check(
            row2 is not None and row2.get("state") == "resumed" and row2.get("status") == 200 and row2.get("path") == new_target,
            f"flow.table row is state=resumed status=200 with the mutated path ({row2!r})",
        )

        section("the edit op is atomic: a bad edit on the (now released) flow is refused and changes nothing")
        was_refused, msg = refused(agent, "flow.mutate", {"id": fid, "edits": {"path": f"{base_path}?q=never", "no_such_key": 1}})
        check(was_refused, f"flow.mutate with an unknown edit key is refused: {msg[:120]}")
        d3 = agent.call("flow.detail", {"id": fid, "body": "none"})
        check((d3.get("request") or {}).get("path") == new_target, "the refused edit left request.path unchanged")

        section("control (after disarm): the ORIGINAL query reaches the origin VERBATIM -- the proxy did not rewrite it")
        off = ctl.call("flow.intercept", {"enabled": False, "rules": []})
        check(off.get("enabled") is False and off.get("rules") == [], f"disarmed with an empty rule set ({off!r})")
        check(agent.call("proxy.status").get("intercept_armed") is False, "proxy.status reports intercept_armed=false")
        rc = via_proxy(core.proxy_port, "GET", f"{origin.base}{ctl_target}", headers={"User-Agent": UA})
        check(rc.status == 200, f"control GET through the proxy got the origin's 200 (was {rc.status})")
        ctl_hits = hits(origin, ctl_marker)
        check(len(ctl_hits) == 1, f"origin recorded exactly ONE control request ({len(ctl_hits)})")
        ctl_t = target_of(ctl_hits[0]["path"]) if ctl_hits else ""
        check(ctl_t == ctl_target, f"the unedited control arrived VERBATIM ({ctl_t!r})")
        check(qs(ctl_t).get("q") == [orig_q], f"control carried the original q={orig_q!r}: the earlier rewrite was the edit op, not the proxy")
        ctl_row = wait_for_row(agent, lambda r: ctl_marker in (r.get("path") or "") and r.get("status") is not None, PARK_WAIT_S)
        check(
            ctl_row is not None and ctl_row.get("state") == "observed" and ctl_row.get("path") == ctl_target,
            f"the control flow completed unparked, state=observed, path unedited ({ctl_row!r})",
        )
        ok(f"flow.mutate edits.path on parked flow {fid}: origin received q={new_q!r} (never {orig_q!r}); released {released_after:.3f}s after resume")
    finally:
        if ctl is not None:
            ctl.try_call("flow.intercept", {"enabled": False, "rules": []})  # never leave the global arm behind
        if fid is not None and held is not None and held.is_alive():
            (ctl or agent).try_call("flow.kill", {"id": fid})  # never leave a parked flow behind
        if ctl is not None and ctl is not agent:
            ctl.close()
        agent.close()
        origin.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
