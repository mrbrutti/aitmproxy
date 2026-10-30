#!/usr/bin/env python3
# e2e: tier=T1 surface=scope
# e2e: serial
"""scope.remove / scope.clear take effect, and confinement follows the live scope.

Scope is the deny-by-default allowlist for what aitm itself may *emit*: the active
commands (`request.send`, `flow.replay`, ...) are refused for any authority not in
scope, and the SSRF-filtered browser-facing listener only dials a loopback/private
upstream whose exact address is in scope. This test proves that narrowing scope at
runtime re-confines both paths immediately, per entry, and that emptying the scope
confines everything -- including entries the rig pre-configured.

Ground truth, never fixtures:
  * two real HTTP upstreams THIS test runs (A and B, 127.0.0.1:<random port>) that
    record every request they really receive: a refused action must leave nothing
    there, an allowed one exactly the request we crafted;
  * the refusal text the core returns over the bus (`host <authority> is out of
    scope`, naming the exact authority);
  * the flow store read back over the bus (flow.table / flow.detail: authority,
    path, status, is_replay);
  * the command audit ring (agent.activity) recording each refusal;
  * the browser-facing (SSRF-confined) listener: a request through it reaches the
    upstream only while the upstream's exact authority is in scope.

`scope.clear` is not a product command today. The test derives that from the live
tool surface AND the Rust EXPECTED_TOOLS contract (they must agree), uses the real
command if one ever appears, and otherwise clears by removing every entry -- the
only way an operator can empty the scope now -- and asserts the same outcome.

Core: the one the runner provides via env (AITM_BUS_ADDR, AITM_BUS_TOKEN,
AITM_PROXY_ADDR, AITM_BUS_OPERATOR_TOKEN; optional AITM_BROWSER_PROXY_ADDR and
AITM_TARGET_URL). It changes GLOBAL scope (serial), snapshots the scope first and
restores it exactly at exit. Without a runner core it boots a dedicated one.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, repo_root, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

OUT_OF_SCOPE = "is out of scope"  # GuardError::OutOfScope: "host <authority> is out of scope"
UPSTREAM_MARK = "aitm-e2e-upstream"  # the echo-record upstream's own body marker
CONTRACT = Path(repo_root()) / "crates" / "aitm" / "tests" / "frontends.rs"
SETTLE = 0.4  # grace after a refusal: a refuse-but-send-anyway bug lands in this window


# ---------------------------------------------------------------------------
# the core: the runner's (env) or, failing that, a dedicated one
# ---------------------------------------------------------------------------


class EnvCore:
    """Adapter so BusClient.operator/agent(core) work against a runner-provided core."""

    def __init__(self, env):
        host, port = env["AITM_BUS_ADDR"].rsplit(":", 1)
        self.bus_addr = (host, int(port))
        browser = env.get("AITM_BROWSER_PROXY_ADDR") or ""
        self.cfg = SimpleNamespace(
            agent_token=env["AITM_BUS_TOKEN"],
            operator_token=env.get("AITM_BUS_OPERATOR_TOKEN") or None,
            proxy_port=int(env["AITM_PROXY_ADDR"].rsplit(":", 1)[1]),
            browser_proxy_port=int(browser.rsplit(":", 1)[1]) if browser else None,
        )
        self.provided = True

    def stop(self) -> None:  # never ours to stop
        pass


def attach_or_boot():
    env = os.environ
    if all(env.get(k) for k in ("AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_PROXY_ADDR")):
        core = EnvCore(env)
        ok(
            f"attached to the runner's core: bus {core.bus_addr[0]}:{core.bus_addr[1]}, "
            f"proxy :{core.cfg.proxy_port}, browser listener "
            f"{':%d' % core.cfg.browser_proxy_port if core.cfg.browser_proxy_port else 'not provided'}"
        )
        return core
    cfg = CoreConfig(
        proxy_port=free_port(),
        browser_proxy_port=free_port(),
        allow_agent_widen=False,  # the shipped fail-closed posture
    )
    core = Aitm.server(cfg)
    core.provided = False
    ok(
        f"no runner core in env (AITM_BUS_ADDR/AITM_BUS_TOKEN/AITM_PROXY_ADDR); booted a "
        f"dedicated core: proxy :{cfg.proxy_port}, browser listener :{cfg.browser_proxy_port}, "
        f"bus {core.bus_addr}"
    )
    return core


def pick_widener(core, agent):
    """The connection allowed to widen scope: the operator, or the agent when the
    rig opted into scope.allow_agent_widen. Skips (77) when neither can."""
    if core.cfg.operator_token:
        return BusClient.operator(core), "operator"
    probe = "e2e-widen-probe.invalid"
    st, msg = agent.try_call("scope.add", {"host": probe})
    if st == "ok":
        agent.call("scope.remove", {"host": probe})
        ok("rig allows agent widening (scope.allow_agent_widen); the agent will widen")
        return agent, "agent"
    skip(
        "widening scope needs the operator role: set AITM_BUS_OPERATOR_TOKEN "
        f"(agent scope.add was refused: {str(msg)[:80]})"
    )
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# helpers over the real surfaces
# ---------------------------------------------------------------------------


def unique(prefix: str) -> str:
    return f"{prefix}-{os.getpid()}-{secrets.token_hex(4)}"


def active(bus, tool: str, args: dict):
    """Run an active command as `bus`: (True, flow_id) or (False, refusal text).
    The shared 127.0.0.1 rate bucket can throttle transiently; that is retried so a
    throttle is never mistaken for a scope verdict."""
    st, val = "error", "not attempted"
    for _ in range(8):
        st, val = bus.try_call(tool, args)
        if st == "ok" or "rate limited" not in str(val):
            break
        time.sleep(0.3)
    return st == "ok", val


def refused_out_of_scope(okflag: bool, msg, authority: str) -> bool:
    return (not okflag) and OUT_OF_SCOPE in str(msg) and authority in str(msg)


def hits(up: Upstream, tag: str) -> list:
    """Requests upstream `up` REALLY received carrying `tag` in the path."""
    return [r for r in up.received if tag in r["path"]]


def rows_with(bus, tag: str) -> list:
    return [r for r in bus.call("flow.table")["flows"] if tag in (r.get("path") or "")]


def wait_completed(bus, tag: str, timeout: float = 6.0) -> list:
    """Rows for `tag` once at least one carries a response status."""
    deadline = time.time() + timeout
    rows = rows_with(bus, tag)
    while not any(r.get("status") is not None for r in rows) and time.time() < deadline:
        time.sleep(0.15)
        rows = rows_with(bus, tag)
    return rows


def detail(bus, fid: str) -> dict:
    return bus.call("flow.detail", {"id": fid, "body": "inline"})


def body_text(msg: dict) -> str:
    b = (msg or {}).get("body")
    if isinstance(b, dict):
        b = b.get("base64") or b.get("data") or ""
    if not isinstance(b, str) or not b:
        return ""
    try:
        return base64.b64decode(b).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return b


def through(port: int, url: str):
    """A real client request through listener `port`: (status, None) or
    (None, error). The SSRF connector refusing the dial drops the client socket
    without a response, which is exactly a refusal from the client's seat."""
    try:
        r = via_proxy(port, "GET", url, timeout=10)
        return r.status, None
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def entry_covers(entry: str, authority: str) -> bool:
    """Python mirror of Authority::matches_scope_entry plus the SSRF `localhost`
    lift, for the precondition that nothing ELSE in scope covers our upstreams."""
    e = entry.strip().lower()
    host, port = authority.rsplit(":", 1)
    if e == "localhost":
        return True
    if e.startswith("*."):
        suffix = e[2:]
        return host == suffix or host.endswith("." + suffix)
    if ":" in e:
        eh, ep = e.rsplit(":", 1)
        return eh == host and ep == port
    return e == host


def audited_refusals(bus, since_ms: int, command: str, needle: str) -> list:
    entries = bus.call("agent.activity", {"since": since_ms})
    out = []
    for e in entries if isinstance(entries, list) else []:
        res = e.get("result")
        if (
            e.get("command") == command
            and needle in (e.get("args") or "")
            and isinstance(res, dict)
            and OUT_OF_SCOPE in str(res.get("error", ""))
        ):
            out.append(e)
    return out


def contract_names() -> set:
    """The Rust EXPECTED_TOOLS contract (crates/aitm/tests/frontends.rs), the single
    source of truth the coders maintain -- never a hard-coded list here."""
    if not CONTRACT.exists():
        return set()
    text = CONTRACT.read_text(encoding="utf-8")
    m = re.search(r"EXPECTED_TOOLS[^=]*=\s*\[(.*?)\];", text, re.S)
    if not m:
        return set()
    body = re.sub(r"//[^\n]*", "", m.group(1))
    return set(re.findall(r'"([^"]+)"', body))


def restore_scope(op, snapshot: list) -> list:
    """Make the live scope exactly `snapshot` again (order included): remove
    everything, then re-add the snapshot in order."""
    for e in list(op.call("scope.list")):
        op.try_call("scope.remove", {"host": e})
    for e in snapshot:
        op.confirm("scope.add", {"host": e})
    return list(op.call("scope.list"))


# ---------------------------------------------------------------------------
# the scenario
# ---------------------------------------------------------------------------


def main() -> int:
    section("arrange: the core, two real upstreams this test owns, a scope snapshot")
    core = attach_or_boot()
    a = Upstream().start()
    b = Upstream().start()
    A, B = a.authority, b.authority
    agent = op = None
    snapshot = None
    state = {"restored": None}
    try:
        agent = BusClient.agent(core)
        op, widener = pick_widener(core, agent)
        snapshot = list(op.call("scope.list"))
        ok(f"upstream A {A}, upstream B {B}; widening as {widener}; scope has {len(snapshot)} entries")

        covering = [e for e in snapshot if entry_covers(e, A) or entry_covers(e, B)]
        if covering:
            # A bare 127.0.0.1 / localhost / wildcard entry would keep lifting the
            # block for every loopback port and mask every refusal we assert on.
            # They are in the snapshot, so they come back at exit.
            for e in covering:
                check(op.call("scope.remove", {"host": e}) is True,
                      f"precondition: parked rig entry {e!r} that covers our upstreams (restored at exit)")
        live = op.call("scope.list")
        check(not any(entry_covers(e, A) or entry_covers(e, B) for e in live),
              f"precondition: nothing in scope covers {A} or {B} (scope: {live})")

        tools_live = set(agent.tool_names())
        for name in ("scope.add", "scope.remove", "scope.list", "request.send", "flow.replay",
                     "flow.table", "flow.detail", "agent.activity"):
            check(name in tools_live, f"live tool surface has {name}")

        browser_port = core.cfg.browser_proxy_port
        tag = unique("scoperm")

        # ------------------------------------------------------------------
        section("baseline: unscoped A and B are refused on every active path")
        okflag, msg = active(agent, "request.send", {"authority": A, "path": f"/pre-a?t={tag}"})
        check(refused_out_of_scope(okflag, msg, A), f"request.send to unscoped A refused out of scope ({str(msg)[:90]})")
        okflag, msg = active(agent, "request.send", {"authority": B, "path": f"/pre-b?t={tag}"})
        check(refused_out_of_scope(okflag, msg, B), f"request.send to unscoped B refused out of scope ({str(msg)[:90]})")
        time.sleep(SETTLE)
        check(hits(a, tag) == [] and hits(b, tag) == [], "neither upstream received a refused request")
        if browser_port:
            st, err = through(browser_port, f"{a.base}/pre-browser?t={tag}")
            check(st != 200, f"browser-facing listener refuses the unscoped loopback upstream A (client saw {st or err})")
            time.sleep(SETTLE)
            check(hits(a, tag) == [], "A received nothing via the browser-facing listener while unscoped")

        # ------------------------------------------------------------------
        section("scope.add A and B: both become reachable, exactly as crafted")
        for h in (A, B):
            added = op.confirm("scope.add", {"host": h})
            check(added == h, f"scope.add echoes the entry ({added!r})")
        live = op.call("scope.list")
        check(A in live and B in live, f"scope.list shows A and B ({live})")

        path_a = f"/active-a?t={tag}"
        okflag, fid_a = active(agent, "request.send",
                               {"authority": A, "path": path_a, "headers": {"X-E2E-Tag": tag}})
        check(okflag and isinstance(fid_a, str) and fid_a, f"request.send to scoped A returns a flow id ({fid_a!r})")
        got = hits(a, tag)
        check(len(got) == 1 and got[0]["path"] == path_a and got[0]["headers"].get("x-e2e-tag") == tag,
              f"A really received exactly our crafted request ({[(g['method'], g['path']) for g in got]})")
        d = detail(agent, fid_a)
        check(d["request"]["authority"] == A and d["request"]["path"] == path_a,
              "stored flow: authority A, path kept")
        check((d.get("response") or {}).get("status") == 200 and UPSTREAM_MARK in body_text(d["response"])
              and path_a in body_text(d["response"]),
              "stored flow: 200 and the body is A's own echo of our path (not a fixture)")
        check(d["meta"]["is_replay"] is True, "stored flow is marked is_replay (emitted by the core itself)")

        path_b = f"/active-b?t={tag}"
        okflag, fid_b = active(agent, "request.send", {"authority": B, "path": path_b})
        check(okflag and isinstance(fid_b, str) and fid_b, f"request.send to scoped B returns a flow id ({fid_b!r})")
        check([g["path"] for g in hits(b, tag)] == [path_b], "B really received exactly our request")

        if browser_port:
            st, err = through(browser_port, f"{a.base}/browser-a?t={tag}")
            check(st == 200, f"browser-facing listener now dials scoped loopback A (client saw {st or err})")
            check(any(g["path"] == f"/browser-a?t={tag}" for g in hits(a, tag)),
                  "A received the browser-listener request while in scope")
            rows = wait_completed(agent, f"browser-a?t={tag}")
            check(any(r.get("authority") == A and r.get("status") == 200 for r in rows),
                  f"browser-listener flow captured against A with status 200 ({[(r.get('authority'), r.get('status')) for r in rows]})")

        # ------------------------------------------------------------------
        section("scope.remove A: A is re-confined on every path; B is untouched")
        a_hits_before = len(hits(a, tag))
        removed = op.call("scope.remove", {"host": A})
        check(removed is True, f"scope.remove A returns true ({removed!r})")
        live = op.call("scope.list")
        check(A not in live and B in live, f"scope.list drops A and keeps B ({live})")

        t_remove = int(time.time() * 1000) - 1
        okflag, msg = active(agent, "request.send", {"authority": A, "path": f"/post-remove-a?t={tag}"})
        check(refused_out_of_scope(okflag, msg, A), f"request.send to A refused out of scope after removal ({str(msg)[:90]})")
        okflag, msg = active(agent, "flow.replay", {"id": fid_a})
        check(refused_out_of_scope(okflag, msg, A), f"flow.replay of the earlier A flow refused out of scope ({str(msg)[:90]})")
        time.sleep(SETTLE)
        check(len(hits(a, tag)) == a_hits_before, f"A received nothing after removal (still {a_hits_before} hit(s))")
        check(rows_with(agent, f"post-remove-a?t={tag}") == [], "no flow stored for the refused request.send")

        okflag, fid_b2 = active(agent, "request.send", {"authority": B, "path": f"/still-b?t={tag}"})
        check(okflag and isinstance(fid_b2, str), f"request.send to B still runs: removal is per entry ({fid_b2!r})")
        check(any(g["path"] == f"/still-b?t={tag}" for g in hits(b, tag)), "B really received the post-removal request")
        okflag, rid = active(agent, "flow.replay", {"id": fid_b})
        check(okflag and isinstance(rid, str) and rid != fid_b, f"flow.replay of the B flow runs and yields a new flow ({rid!r})")
        check([g["path"] for g in hits(b, tag)].count(path_b) == 2, "B received the replay as a second identical request")

        if browser_port:
            st, err = through(browser_port, f"{a.base}/browser-a-removed?t={tag}")
            check(st != 200, f"browser-facing listener refuses A again after removal (client saw {st or err})")
            time.sleep(SETTLE)
            check(len(hits(a, tag)) == a_hits_before, "A received nothing via the browser-facing listener after removal")
            rows = rows_with(agent, f"browser-a-removed?t={tag}")
            check(all(r.get("status") is None for r in rows),
                  f"any stored row for the refused browser attempt has no response ({[(r.get('authority'), r.get('status')) for r in rows]})")
            st, err = through(browser_port, f"{b.base}/browser-b?t={tag}")
            check(st == 200, f"browser-facing listener still dials B (client saw {st or err})")

        # capture is observation, not authorisation: the main listener still relays
        # A, and that captured flow cannot be replayed into the removed host.
        st, err = through(core.cfg.proxy_port, f"{a.base}/passive-a?t={tag}")
        check(st == 200, f"main listener still relays passive traffic to removed A (client saw {st or err})")
        check(any(g["path"] == f"/passive-a?t={tag}" for g in hits(a, tag)), "A received the passive request")
        a_hits_before = len(hits(a, tag))
        rows = wait_completed(agent, f"passive-a?t={tag}")
        prow = next((r for r in rows if r.get("authority") == A), None)
        check(prow is not None and prow.get("status") == 200,
              f"passive A flow captured with status 200 ({(prow or {}).get('id')}, state {(prow or {}).get('state')!r})")
        pmeta = detail(agent, prow["id"]).get("meta") or {}
        check(pmeta.get("is_replay") is False, f"passive A flow is not a replay (meta.is_replay={pmeta.get('is_replay')!r})")
        okflag, msg = active(agent, "flow.replay", {"id": prow["id"]})
        check(refused_out_of_scope(okflag, msg, A), f"flow.replay of the passive A flow refused out of scope ({str(msg)[:90]})")
        time.sleep(SETTLE)
        check(len(hits(a, tag)) == a_hits_before, "A saw no replay")

        removed_again = op.call("scope.remove", {"host": A})
        check(removed_again is False, f"scope.remove of an absent entry returns false ({removed_again!r})")
        check(op.call("scope.list") == live, "scope.list unchanged by the no-op removal")

        audit = audited_refusals(agent, t_remove, "request.send", f"post-remove-a?t={tag}")
        check(len(audit) >= 1 and all(e.get("origin") == "mcp" for e in audit),
              f"audit ring records the agent's refused request.send to A ({len(audit)} entr{'y' if len(audit) == 1 else 'ies'})")

        # scope.remove carries the fail-closed default Sensitivity::Sensitive (the plugin
        # never overrides it; the Rust contract lists it among the operator-command
        # tools), so whether the AGENT may narrow follows the LIVE agent policy:
        # refused under auto/readonly/paused, runs under all, parks under ask.
        status = agent.call("agent.status") if "agent.status" in tools_live else {}
        policy = str((status or {}).get("policy", "")) if isinstance(status, dict) else ""
        extra = f"e2e-narrow-{secrets.token_hex(3)}.invalid"
        check(op.confirm("scope.add", {"host": extra}) == extra, f"operator adds a throwaway entry {extra}")
        if policy == "ask":
            ok("agent policy is `ask`: an agent scope.remove would park for approval; not driven")
        else:
            st_, val = agent.try_call("scope.remove", {"host": extra})
            if policy == "all":
                check(st_ == "ok" and val is True, f"agent policy `all`: agent scope.remove runs ({st_}: {val!r})")
                check(extra not in op.call("scope.list"), "agent's removal took effect")
            else:
                check(st_ == "error" and "refused" in str(val),
                      f"agent policy `{policy or 'default'}`: agent scope.remove is refused as Sensitive ({str(val)[:100]})")
                check(extra in op.call("scope.list"), "the refused agent removal left the entry in scope")
        if extra in op.call("scope.list"):
            check(op.call("scope.remove", {"host": extra}) is True, "operator removes the throwaway entry")
        check(extra not in op.call("scope.list"), "throwaway entry gone")

        # ------------------------------------------------------------------
        section("scope.clear: emptying the scope confines everything, pre-configured entries included")
        contract = contract_names()
        live_has_clear = "scope.clear" in tools_live
        if contract:
            check(live_has_clear == ("scope.clear" in contract),
                  f"live surface and the Rust EXPECTED_TOOLS contract agree about scope.clear "
                  f"(live={live_has_clear}, contract={'scope.clear' in contract})")
        else:
            ok("Rust contract not found beside this checkout; live surface alone decides scope.clear")

        target_url = os.environ.get("AITM_TARGET_URL") or ""
        target = urlsplit(target_url).netloc if target_url else ""
        target_in_scope = bool(target) and target in op.call("scope.list")
        if target_in_scope:
            okflag, tfid = active(agent, "request.send", {"authority": target, "path": f"/search?q={tag}"})
            check(okflag and isinstance(tfid, str), f"control: seeded target {target} is reachable before the clear ({tfid!r})")

        before_clear = list(op.call("scope.list"))
        t_clear = int(time.time() * 1000) - 1
        if live_has_clear:
            op.confirm("scope.clear", {})
            ok("cleared with the real scope.clear command")
        else:
            ok(f"scope.clear is not a product command; clearing by removing all {len(before_clear)} entries")
            for e in before_clear:
                check(op.call("scope.remove", {"host": e}) is True, f"removed {e}")
        live = op.call("scope.list")
        check(live == [], f"scope.list is empty ({live})")

        b_hits_before = len(hits(b, tag))
        okflag, msg = active(agent, "request.send", {"authority": B, "path": f"/post-clear-b?t={tag}"})
        check(refused_out_of_scope(okflag, msg, B), f"request.send to B refused out of scope after the clear ({str(msg)[:90]})")
        okflag, msg = active(agent, "flow.replay", {"id": fid_b})
        check(refused_out_of_scope(okflag, msg, B), f"flow.replay of the B flow refused after the clear ({str(msg)[:90]})")
        if target_in_scope:
            okflag, msg = active(agent, "request.send", {"authority": target, "path": f"/search?q={tag}-cleared"})
            check(refused_out_of_scope(okflag, msg, target),
                  f"the rig's pre-configured target {target} is refused too ({str(msg)[:90]})")
        time.sleep(SETTLE)
        check(len(hits(b, tag)) == b_hits_before, f"B received nothing after the clear (still {b_hits_before} hit(s))")
        if browser_port:
            st, err = through(browser_port, f"{b.base}/browser-b-cleared?t={tag}")
            check(st != 200, f"browser-facing listener refuses B after the clear (client saw {st or err})")
            time.sleep(SETTLE)
            check(len(hits(b, tag)) == b_hits_before, "B received nothing via the browser-facing listener after the clear")
        audit = audited_refusals(agent, t_clear, "request.send", f"post-clear-b?t={tag}")
        check(len(audit) >= 1, f"audit ring records the refused post-clear request.send ({len(audit)})")

        # ------------------------------------------------------------------
        section("restore: the rig's scope is exactly what it was, and live again")
        after = restore_scope(op, snapshot)
        state["restored"] = after
        check(after == snapshot, f"scope restored exactly (now {after}, was {snapshot})")
        if target_in_scope:
            okflag, tfid = active(agent, "request.send", {"authority": target, "path": f"/search?q={tag}-restored"})
            check(okflag and isinstance(tfid, str), f"seeded target reachable again after restore ({tfid!r})")
        okflag, msg = active(agent, "request.send", {"authority": A, "path": f"/post-restore-a?t={tag}"})
        check(refused_out_of_scope(okflag, msg, A), "our A is not in the restored scope: still refused")

        print(
            f"\nPASS: scope.remove re-confined {A} (active + browser-listener) while {B} stayed open; "
            f"clearing the scope refused everything; scope restored to {len(snapshot)} entries",
            flush=True,
        )
        return 0
    finally:
        if op is not None and snapshot is not None and state["restored"] != snapshot:
            try:
                restore_scope(op, snapshot)
            except Exception as e:  # noqa: BLE001
                print(f"  [warn] could not restore scope: {type(e).__name__}: {e}", flush=True)
        for c in (agent, op):
            if c is not None:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass
        for up in (a, b):
            try:
                up.stop()
            except Exception:  # noqa: BLE001
                pass
        core.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
