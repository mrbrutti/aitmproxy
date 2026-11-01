#!/usr/bin/env python3
# e2e: tier=T1 surface=edits serial
"""edits/test_edits_header_direct -- the `edits.*` header edit op on a HELD request
mutates a request header, and the UPSTREAM receives the mutated value (echo-confirmed).

The feature: `flow.mutate {id, edits}` edits a captured/parked HTTP flow in place
(crates/aitm-plugins/src/mutate.rs). The `edits.headers` map is the header edit op --
"Header name->value; each replaces any existing header of that name" (remove-then-set,
no duplicate accumulation). This script proves that op end-to-end on a request parked
at the request phase, against INDEPENDENTLY-OBSERVED ground truth.

Ground truth (never fixtures, never the proxy's own view):
  * the INDEPENDENT observer is the echo-record upstream (aitm_e2e.upstream.Upstream):
    a real HTTP/1.1 origin that records, server-side, exactly the request it received
    (every header, lowercased). The proof of "upstream received the change" is that
    record -- not flow.get, not what the proxy thinks it forwarded.

  * control (no interception): a real POST through the proxy carrying `X-Orig: baseline`
    is recorded verbatim by the upstream -- so the observer is live and faithful, and
    the later contrast is attributable to the edit alone.

  * a second real POST through the proxy, carrying `X-Orig: client-value` and
    `X-Keep: keepme`, is PARKED by a request-phase breakpoint rule scoped to this run's
    marker: flow.table shows the row state=intercepted, flow.detail has no response and
    no server_conn (nothing has gone upstream), and the upstream has recorded NOTHING
    for the parked path. The client is still blocked awaiting its response.

  * `flow.mutate {id, edits: {headers: {X-Orig: operator-value, X-Added: operator-added}}}`
    then `flow.resume {id}` releases the held flow. The UPSTREAM record for the parked
    path now shows:
      - x-orig  == "operator-value"  (the edit op OVERWROTE the held header; the
                                       client's "client-value" never reached the origin),
      - x-added == "operator-added"  (the edit op ADDED a new header),
      - x-keep  == "keepme"          (an untouched header passed through unchanged),
      - the body is unchanged (a header-only edit changed only headers),
    and exactly ONE header-line for x-orig (replace, not append). The blocked client is
    released with a 200 whose echo names the parked path.

Core: attaches to the core the runner provides via env (AITM_BUS_ADDR, AITM_BUS_TOKEN,
AITM_PROXY_ADDR, optional AITM_BUS_OPERATOR_TOKEN) and does NOT boot its own; without
that contract it boots a dedicated core on free ports (the aitm_e2e fallback every suite
uses so it is runnable standalone under run.py). The echo-record upstream is always this
script's own, on a random 127.0.0.1 port nobody else uses. Markers are unique per run.

Roles: flow.intercept is Sensitive (the default agent policy refuses it), so arming (and
the Write-tier mutate/resume) run as the operator when a token is available; attached to
a core that exposes only the agent token, this SKIPs rather than assert a false refusal.
flow.intercept arms a GLOBAL mode and REPLACES the global rule set, so this suite is
tagged `serial` and always disarms in its finally.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_OP_TOKEN, ENV_PROXY_ADDR = (
    "AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_BUS_OPERATOR_TOKEN", "AITM_PROXY_ADDR",
)
FORM = "application/x-www-form-urlencoded"
PARK_WAIT_S = 15.0    # how long the parked row may take to appear in flow.table
CLIENT_TIMEOUT_S = 40.0  # the held client's own socket timeout; mutate+resume beats it
RELEASE_WAIT_S = 20.0  # how long to wait for the resumed client to return


# ---- the core: provided by the runner (env) or booted here ---------------------

def env_core():
    """The core the runner already booted, if it described one in the environment.
    Shaped like aitm_e2e.core.Aitm (bus_addr + cfg.{agent,operator}_token + proxy_port)
    so BusClient.operator(core)/.agent(core) and via_proxy(core.cfg.proxy_port, ...) work
    unchanged. Returns None when the runner provided no core (-> boot our own)."""
    addr, tok, proxy = (os.environ.get(k) for k in (ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_PROXY_ADDR))
    if not (addr and tok and proxy):
        return None
    host, port = addr.rsplit(":", 1)
    _, pport = proxy.rsplit(":", 1)
    cfg = SimpleNamespace(
        agent_token=tok,
        operator_token=os.environ.get(ENV_OP_TOKEN) or None,
        proxy_port=int(pport),
    )
    return SimpleNamespace(bus_addr=(host.strip("[]"), int(port)), cfg=cfg, stop=lambda: None)


# ---- the real client whose request is held and then resumed --------------------

class HeldClient(threading.Thread):
    """One REAL HTTP/1.1 POST sent THROUGH the proxy (absolute-URI form, as a browser
    configured with aitm as its HTTP proxy would send it). It blocks in getresponse()
    until the flow is resumed, then records the response it finally got."""

    def __init__(self, proxy_port: int, url: str, headers: dict, body: bytes):
        super().__init__(daemon=True, name="held-edits-client")
        self._proxy_port = proxy_port
        self._url = url
        self._headers = headers
        self._body = body
        self.resp = None
        self.error: Optional[BaseException] = None

    def run(self) -> None:
        try:
            self.resp = via_proxy(
                self._proxy_port, "POST", self._url,
                headers=self._headers, body=self._body, timeout=CLIENT_TIMEOUT_S,
            )
        except BaseException as e:  # noqa: BLE001 -- record whatever the client saw
            self.error = e


# ---- bus helpers ---------------------------------------------------------------

def table_rows(bus: BusClient) -> list:
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


def recorded(up: Upstream, path: str) -> list:
    return [r for r in up.received if r.get("path") == path]


def main() -> int:
    up = Upstream().start()  # the independent observer: authority 127.0.0.1:<random>, ours alone
    core = env_core()
    booted = core is None
    ctl = None
    held: Optional[HeldClient] = None
    fid = None
    run = f"edits-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    ctrl_path = f"/control?r={run}"
    held_path = f"/held?r={run}"
    try:
        section("arrange: an echo-record upstream (the observer) + a real aitm core")
        if booted:
            cfg = CoreConfig(
                proxy_port=free_port(), scope_entries=[up.authority, "127.0.0.1"],
            )
            core = Aitm.server(cfg)
            ok(f"booted a dedicated core: proxy :{cfg.proxy_port}, bus {core.bus_addr}")
        else:
            ok(f"attached to the runner's core at {core.bus_addr} (did not boot one)")
        pp = core.cfg.proxy_port
        ok(f"upstream (observer) {up.base}; marker {run}")

        # flow.intercept is Sensitive; the Write-tier mutate/resume follow. Drive them
        # as the operator when a token is available, else fall back to the agent.
        op_token = getattr(core.cfg, "operator_token", None)
        if op_token:
            ctl = BusClient.operator(core)
            role = "operator"
        else:
            ctl = BusClient.agent(core)
            role = "agent"
        ok(f"driving the edit as the {role}")

        section("preflight: the live tools/list registers the commands under test")
        names = set(ctl.tool_names())
        need = ["flow.intercept", "flow.mutate", "flow.resume", "flow.table", "flow.detail"]
        missing = [n for n in need if n not in names]
        check(not missing, f"core registers {need} (missing: {missing or 'none'})")

        section("control: a real POST through the proxy is recorded VERBATIM by the upstream")
        r = via_proxy(pp, "POST", up.base + ctrl_path,
                      headers={"Content-Type": FORM, "X-Orig": "baseline"}, body=b"body=ctl")
        check(r.status == 200 and "aitm-e2e-upstream" in r.text,
              f"control POST round-tripped through the proxy ({r.status})")
        crec = recorded(up, ctrl_path)
        if not crec:
            # In attach mode this most likely means the upstream is not in the runner
            # core's scope, so nothing can be captured/parked -- skip rather than fail.
            if not booted:
                skip(f"the runner core did not capture a POST to {up.authority} "
                     f"(upstream not in its scope?); run this suite with its own core")
            fail(f"control POST was not recorded by the upstream ({up.received!r})")
        check(crec[0]["headers"].get("x-orig") == "baseline",
              f"upstream recorded the control X-Orig verbatim (observer is live) ({crec[0]['headers'].get('x-orig')!r})")

        section("arrange: arm a request-phase breakpoint matching ONLY this run's held path")
        rule = {"id": run, "name": "e2e edits_header_direct", "phase": "request",
                "method": "POST", "url": f"*r={run}*"}
        st, armed = ctl.try_call("flow.intercept", {"enabled": True, "rules": [rule]})
        if st != "ok":
            if role == "agent":
                skip("flow.intercept is Sensitive and the agent is refused it here; attach a "
                     f"core that exposes {ENV_OP_TOKEN}, or run with a booted core: {armed}")
            fail(f"operator flow.intercept was refused: {armed}")
        check(isinstance(armed, dict) and armed.get("enabled") is True,
              f"flow.intercept reports enabled=true ({armed!r})")
        rule_ids = [x.get("id") for x in (armed.get("rules") or []) if isinstance(x, dict)]
        check(rule_ids == [run], f"the active rule set is exactly our rule ({rule_ids})")

        section("act 1: a real POST is PARKED at the request phase -- nothing reaches the upstream")
        held = HeldClient(pp, up.base + held_path,
                          {"Content-Type": FORM, "X-Orig": "client-value", "X-Keep": "keepme"},
                          b"body=held")
        held.start()
        row = wait_for_row(
            ctl,
            lambda r: held_path in (r.get("path") or "") and r.get("state") == "intercepted",
            PARK_WAIT_S,
        )
        if row is None:
            fail(f"no flow.table row for {held_path} in state=intercepted within {PARK_WAIT_S}s "
                 f"(client error={held.error!r})")
        fid = row["id"]
        ok(f"flow {fid} parked: {row.get('method')} {row.get('authority')}{row.get('path')}")
        check(row.get("status") is None, f"parked row has no response status yet ({row.get('status')!r})")
        d = ctl.call("flow.detail", {"id": fid, "body": "none"})
        check(d.get("intercept") == "intercepted", f"flow.detail intercept={d.get('intercept')!r} (expected intercepted)")
        check(d.get("response") is None, f"flow.detail has no response while parked ({d.get('response')!r})")
        check(d.get("server_conn") is None, f"flow.detail has no server_conn: nothing went upstream ({d.get('server_conn')!r})")
        check(recorded(up, held_path) == [],
              f"the upstream has recorded NOTHING for the parked path yet ({recorded(up, held_path)!r})")

        section("act 2: the edits.* header op on the held request (overwrite + add), then resume")
        ctl.call("flow.mutate", {"id": fid, "edits": {"headers": {
            "X-Orig": "operator-value", "X-Added": "operator-added"}}})
        ctl.call("flow.resume", {"id": fid})

        section("ground truth: the UPSTREAM received the MUTATED request headers (echo-confirmed)")
        held.join(RELEASE_WAIT_S)
        check(not held.is_alive(), "the held client returned after resume")
        if held.error is not None:
            fail(f"the resumed client errored instead of getting a response: {held.error!r}")
        check(held.resp is not None and held.resp.status == 200,
              f"the released client got 200 ({held.resp.status if held.resp else None})")
        check(held.resp is not None and held_path in held.resp.text,
              "the client's response echoes the (unchanged) request path")

        deadline = time.monotonic() + 5.0
        while not recorded(up, held_path) and time.monotonic() < deadline:
            time.sleep(0.05)
        hrec = recorded(up, held_path)
        check(len(hrec) == 1, f"the upstream recorded exactly one request for the held path ({len(hrec)})")
        hdrs = hrec[0]["headers"] if hrec else {}
        check(hdrs.get("x-orig") == "operator-value",
              f"edit op OVERWROTE the held header: upstream saw x-orig=operator-value ({hdrs.get('x-orig')!r})")
        check("client-value" not in (hdrs.get("x-orig") or ""),
              "the client's original x-orig value never reached the upstream (replaced, not appended)")
        check(hdrs.get("x-added") == "operator-added",
              f"edit op ADDED a new header: upstream saw x-added=operator-added ({hdrs.get('x-added')!r})")
        check(hdrs.get("x-keep") == "keepme",
              f"an untouched header passed through unchanged ({hdrs.get('x-keep')!r})")
        check(hrec[0].get("body") == "body=held",
              f"a header-only edit left the body unchanged ({hrec[0].get('body')!r})")
        ok(f"edits.headers mutated the held request header; the upstream confirmed it (flow {fid})")

        section("teardown: disarm interception (restore the global state)")
        off = ctl.call("flow.intercept", {"enabled": False, "rules": []})
        check(off.get("enabled") is False, f"interception disarmed ({off!r})")
    finally:
        if ctl is not None:
            # never leave a parked flow or the global arm behind for a sibling run
            if fid is not None and held is not None and held.is_alive():
                ctl.try_call("flow.resume", {"id": fid})
                ctl.try_call("flow.kill", {"id": fid})
            ctl.try_call("flow.intercept", {"enabled": False, "rules": []})
            ctl.close()
        if core is not None:
            core.stop()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
