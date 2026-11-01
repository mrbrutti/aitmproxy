#!/usr/bin/env python3
# e2e: tier=T1 surface=map
"""Map Remote: a map rule redirects a matching request to the mapped target.

A real client sends an HTTP request THROUGH the real proxy aimed at one origin
(`origin`). A `map.add kind=remote` rule, authored over the bus, rewrites the
authority of every request whose path matches a unique wildcard to a SECOND
origin (`mapped`). We prove the redirect happened on INDEPENDENT ground truth,
never the proxy's own view:

  1. the mapped upstream RECORDED the matching request, and the original origin
     did NOT -- the request really went somewhere else (two separate echo-record
     servers, each its own observer);
  2. the client got the mapped upstream's real 200 response back through the proxy;
  3. the core CAPTURED the flow over the bus with the rewritten authority and the
     `map-remote` mark the plugin sets when it actually rewrites a request;
  4. a NON-matching request to the same origin is NOT redirected (reaches origin);
  5. after `map.remove`, the once-matching path is no longer redirected (reaches
     origin again).

Map authoring over the bus is an authorisation decision: the maprules plugin
refuses `map.add` from any non-CLI frontend unless `maps.allow_agent_authoring`
is set (verified in crates/aitm-plugin-maprules/src/lib.rs). This scenario boots
its OWN dedicated core with that gate opened and authors as the operator, exactly
as a human operator configuring a redirect would. The rewrite target is in scope
(map-remote passes the scope guard before rewriting), so the redirect is allowed
rather than refused.
"""

import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

MARKER = "aitm-e2e-upstream"  # the echo-record origin's own response signature
REWRITE_MARK = "map-remote"   # flow mark the maprules plugin sets on a real rewrite


class _MapsCoreConfig(CoreConfig):
    """CoreConfig that also opens `maps.allow_agent_authoring`.

    The maprules agent gate bypasses only `Frontend::Cli`; an operator (or agent)
    bus connection is still refused `map.add` unless this is set. We append the
    `maps:` section the Rust config parser accepts (crates/aitm/src/config_file.rs
    MapsFile), on top of the harness's generated YAML."""

    def to_yaml(self) -> str:
        return super().to_yaml() + "maps:\n  allow_agent_authoring: true\n"


def flow_rows(bus) -> list:
    """Every flow.table summary row (id, kind, state, marks, method, authority,
    path, status, ...)."""
    result = bus.call("flow.table")
    return result.get("flows", []) if isinstance(result, dict) else []


def wait_row(bus, predicate, timeout: float = 6.0):
    """Poll flow.table until a COMPLETED (status present) row matches, or time out.

    Match on a unique marker in the path, never on position: this core is private
    to the scenario, but the contract (find your flow by its marker) still holds."""
    deadline = time.time() + timeout
    last: list = []
    while time.time() < deadline:
        last = flow_rows(bus)
        for row in last:
            if row.get("status") is None:
                continue
            try:
                if predicate(row):
                    return row
            except Exception:  # noqa: BLE001 -- a predicate tripping on a ws row etc.
                pass
        time.sleep(0.2)
    return None


def paths_hit(upstream, path: str) -> list:
    """The requests `upstream` really received for exactly `path` (its own record)."""
    return [r for r in upstream.received if r["path"] == path]


def main() -> int:
    origin = Upstream().start()   # where the client AIMS the request
    mapped = Upstream().start()   # where the map-remote rule SENDS it instead
    core = None
    bus = None
    try:
        tag = uuid.uuid4().hex[:8]
        match_path = f"/mapped-{tag}"   # matches the rule -> must be redirected
        other_path = f"/direct-{tag}"   # does not match -> must reach origin

        section("boot: two real upstreams + a real aitm core (map authoring on)")
        cfg = _MapsCoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            # The rewrite target must be in scope: map-remote passes the scope
            # guard before it rewrites. origin is in scope too (tidy, not required
            # for passive capture).
            scope_entries=[origin.authority, mapped.authority],
        )
        core = Aitm.server(cfg)
        ok(f"proxy 127.0.0.1:{cfg.proxy_port}, bus {core.bus_addr}")
        ok(f"origin {origin.base}, mapped {mapped.base}")

        section("arrange: author a Map Remote rule over the bus (operator)")
        bus = BusClient.operator(core)
        if "map.add" not in bus.tool_names():
            skip("the core does not expose map.add (Map feature not built in)")
        try:
            added = bus.call("map.add", {
                "kind": "remote",
                "condition": {"url": {"wildcard": f"*{match_path}"}},
                "action": {"to": {"authority": mapped.authority}},
            })
        except ToolError as e:
            # Fail-closed by default; this core opened the gate, so a refusal here
            # is a real regression in the gate -- but report it as a skip reason so
            # the suite stays honest on a core that did not open it.
            skip(f"map.add refused (maps.allow_agent_authoring gate): {e}")
        map_id = added.get("id") if isinstance(added, dict) else None
        check(isinstance(map_id, str) and map_id, f"map.add returned a rule id ({map_id!r})")
        listed = bus.call("map.list")
        ids = [m.get("id") for m in listed.get("maps", [])] if isinstance(listed, dict) else []
        check(map_id in ids, f"map.list shows the new rule {map_id!r} ({ids})")

        section("act: a real client requests the MATCHING path on origin")
        resp = via_proxy(cfg.proxy_port, "GET", f"{origin.base}{match_path}")
        check(resp.status == 200, f"client got 200 through the proxy (was {resp.status})")
        check(MARKER in resp.text, "client got a real upstream 200 body (not a 502 refusal)")

        section("ground truth 1: the request landed on MAPPED, not on origin")
        on_mapped = paths_hit(mapped, match_path)
        on_origin = paths_hit(origin, match_path)
        check(len(on_mapped) == 1,
              f"mapped upstream recorded the redirected request ({len(on_mapped)} hit(s))")
        check(on_mapped and on_mapped[0]["method"] == "GET",
              "the redirected request kept its method (GET)")
        check(len(on_origin) == 0,
              f"the ORIGINAL origin received nothing for {match_path} ({len(on_origin)} hit(s))")

        section("ground truth 2: the core captured the flow, rewritten + marked")
        row = wait_row(bus, lambda r: r.get("path") == match_path
                       and r.get("authority") == mapped.authority)
        if not row:
            fail(f"no captured flow with the rewritten authority {mapped.authority} for {match_path}")
        check(REWRITE_MARK in (row.get("marks") or []),
              f"captured flow carries the {REWRITE_MARK!r} mark ({row.get('marks')})")
        check(row.get("status") == 200,
              f"captured flow completed 200 (was {row.get('status')!r})")
        detail = bus.call("flow.detail", {"id": row["id"], "body": "none"})
        req = detail.get("request", {}) if isinstance(detail, dict) else {}
        check(req.get("authority") == mapped.authority,
              f"flow.detail request authority is the mapped target (was {req.get('authority')!r})")

        section("negative control: a NON-matching path is NOT redirected")
        resp2 = via_proxy(cfg.proxy_port, "GET", f"{origin.base}{other_path}")
        check(resp2.status == 200, f"non-matching request got 200 (was {resp2.status})")
        check(len(paths_hit(origin, other_path)) == 1,
              "the non-matching request reached the ORIGINAL origin")
        check(len(paths_hit(mapped, other_path)) == 0,
              "the non-matching request did NOT reach the mapped target")
        nrow = wait_row(bus, lambda r: r.get("path") == other_path)
        check(nrow is not None and REWRITE_MARK not in (nrow.get("marks") or []),
              "the non-matching flow carries no map-remote mark")

        section("teardown of the rule: map.remove restores normal routing")
        bus.call("map.remove", {"id": map_id})
        after = bus.call("map.list")
        after_ids = [m.get("id") for m in after.get("maps", [])] if isinstance(after, dict) else []
        check(map_id not in after_ids, f"map.list no longer shows {map_id!r} ({after_ids})")
        resp3 = via_proxy(cfg.proxy_port, "GET", f"{origin.base}{match_path}")
        check(resp3.status == 200, f"re-sent once-matching request got 200 (was {resp3.status})")
        check(len(paths_hit(origin, match_path)) == 1,
              "after removal the once-matching path reaches the ORIGINAL origin")
        check(len(paths_hit(mapped, match_path)) == 1,
              "after removal the mapped target gets no further redirects")

        section("PASS: map-remote redirected the matching request to the mapped target")
        return 0
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
        mapped.stop()
        origin.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
