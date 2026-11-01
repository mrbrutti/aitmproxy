#!/usr/bin/env python3
# e2e: tier=T1 surface=neg
"""The agent-vs-operator gate on a Sensitive command, proven on ground truth.

A real `aitm` core applies a role gate: a connection presenting the AGENT token
(`Frontend::Mcp`) is refused the Sensitive `poc.run` command by default, while a
connection presenting the OPERATOR token runs it. This is a *preventive* control,
so a fixture-free proof has to show two things no fixture controls:

  1. the refused agent call ran NOTHING — an independent upstream echo-record
     origin never saw the request the PoC would have sent; and
  2. the allowed operator call really ran — that same upstream recorded the real
     request, the tool reports `passed: true`, and a durable finding lands on disk
     (`findings.get` reads it back).

Ground truth (never the tool's own say-so):
  * `Upstream.received` — the origin's server-side record of what actually reached
    it (empty after the agent's refusal, holding the operator's GET after its run);
  * the on-disk findings store (`findings.get <recorded_id>`).

Why `poc.run`: of the task's candidates (`poc.run` / `ca.install` / `scan.inject`),
`scan.inject` is not a registered tool and `ca.install` mutates the real OS trust
store, so `poc.run` is the one whose allowed side we can drive to real, reversible
ground truth. The live `poc.run` is Sensitive (the registered `ScriptedPocRunCommand`
inherits the `Command` trait's default `Sensitivity::Sensitive`), so under the
default `auto` agent policy the server's role gate (`crates/aitm-mcp/src/server.rs`
`policy_decision`) refuses it for an `Frontend::Mcp` agent and allows it for the
operator — exactly the asymmetry under test.

Parallel/isolation: the core runs on DEDICATED free ports with its own temp
poc/findings dirs; the upstream is a random loopback port this test alone uses; no
global core state is touched. Cleanup signals only our own child PID.
"""

import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

GATED_TOOL = "poc.run"

# A minimal HTTP-only PoC (no browser step, so no obscura needed). Its single HTTP
# step hits the echo upstream; `success` passes iff the unique marker is reflected
# in the response body — which the echo origin always does (it echoes the request
# path), so a real run against a reachable, in-scope upstream passes deterministically.
POC_YAML = """\
id: e2e-agent-gate-probe
info:
  name: E2E agent-gate operator probe
  severity: info
  description: Minimal HTTP-only PoC the agent-gate e2e test runs through the real core.
  cwe: CWE-200
  tags: [e2e, gate]
variables:
  - name: target
    required: true
  - name: marker
    required: true
steps:
  - http:
      method: GET
      url: "{{target}}/echo?probe={{marker}}"
success:
  all:
    - type: word
      part: body
      word: "{{marker}}"
"""


def marker(prefix: str) -> str:
    """A unique, URL-safe, alphanumeric marker that survives verbatim in a path."""
    return f"{prefix}{secrets.token_hex(8)}"


def saw_marker(up: Upstream, mark: str) -> bool:
    return any(mark in r["path"] for r in up.received if r["path"].startswith("/echo"))


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="aitm-e2e-neg-gate-"))
    poc_dir = work / "poc"
    poc_dir.mkdir()
    poc_path = poc_dir / "probe.yaml"
    poc_path.write_text(POC_YAML, encoding="utf-8")

    up = Upstream().start()
    core = None
    agent = None
    op = None
    try:
        section("boot: a real aitm core (dedicated ports) with the upstream in scope")
        cfg = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[up.authority],
            poc_dir=str(poc_dir),
            poc_out_dir=str(work / "poc-out"),
            findings_dir=str(work / "findings"),
        )
        core = Aitm.server(cfg)
        ok(f"core up: bus {core.bus_addr}, upstream {up.base}, gated tool {GATED_TOOL!r}")

        # Connect both roles to the SAME core; the role is decided purely by which
        # token each presents, so the only variable between them is the gate. The
        # bare `aitm` server always wires the operator token into the loopback bus
        # (crates/aitm/src/main.rs `with_mcp_roles`), so a failure here is a real
        # regression in the operator role, not a missing dependency — fail, don't skip.
        try:
            op = BusClient.operator(core)
        except BusError as e:
            fail(f"operator role refused on the loopback bus — the role gate is broken: {e}")

        if GATED_TOOL not in op.tool_names():
            skip(f"{GATED_TOOL} is not registered on this build; nothing to gate")
        ok(f"{GATED_TOOL} is registered and visible on the live tool surface")

        agent = BusClient.agent(core)
        args_op = {"poc_path": str(poc_path), "target": up.base, "vars": {"marker": marker("e2eop")}}
        args_agent = {"poc_path": str(poc_path), "target": up.base, "vars": {"marker": marker("e2eag")}}
        agent_mark = args_agent["vars"]["marker"]
        op_mark = args_op["vars"]["marker"]

        section("the agent connection is HEALTHY for non-gated commands (rules out a dead socket)")
        st, val = agent.try_call("flow.list")
        check(st == "ok", f"agent may run the Read command flow.list (got {st}: {str(val)[:80]})")

        section(f"gate CLOSED: the agent is REFUSED {GATED_TOOL}")
        st, msg = agent.try_call(GATED_TOOL, args_agent)
        check(st == "error", f"agent {GATED_TOOL} is refused, not allowed (got {st})")
        lo = (msg or "").lower()
        check("refused" in lo, f"the refusal says so (message: {msg[:200]!r})")
        # The live poc.run is Sensitive (the registered ScriptedPocRunCommand inherits
        # the Command trait's default Sensitivity::Sensitive), so the default `auto`
        # agent policy refuses it as a sensitive action — a role/sensitivity gate, not
        # an unrelated failure (bad args / missing file would never say "sensitive").
        check(
            "sensitive" in lo,
            f"the refusal is the agent sensitivity gate, not an unrelated error (message: {msg[:200]!r})",
        )

        section("ground truth A: the refused agent call RAN NOTHING (upstream saw no traffic)")
        check(
            not saw_marker(up, agent_mark),
            f"the upstream never received the agent PoC's request ({len(up.received)} total hit(s))",
        )

        section(f"gate OPEN: the operator is ALLOWED {GATED_TOOL} and it really runs")
        result = op.call(GATED_TOOL, args_op)
        check(isinstance(result, dict), f"{GATED_TOOL} returned a structured result (got {type(result).__name__})")
        check(result.get("passed") is True, f"the operator's PoC passed against the real upstream (result: {result})")

        section("ground truth B: the operator's PoC request REALLY reached the upstream")
        deadline = time.time() + 5
        while not saw_marker(up, op_mark) and time.time() < deadline:
            time.sleep(0.1)
        check(saw_marker(up, op_mark), f"the upstream recorded the operator PoC's GET /echo?probe={op_mark}")
        check(not saw_marker(up, agent_mark), "the upstream still shows NOTHING from the refused agent (asymmetry holds)")

        section("ground truth C: the operator's passing run left a durable finding on disk")
        recorded_id = result.get("recorded_id")
        check(bool(recorded_id), f"the passing poc.run recorded a finding id (result keys: {sorted(result)})")
        if recorded_id:
            st, got = op.try_call("findings.get", {"id": recorded_id})
            check(st == "ok" and isinstance(got, dict),
                  f"findings.get reads the recorded finding back from disk (got {st}: {str(got)[:80]})")
    finally:
        for c in (agent, op):
            if c:
                c.close()
        if core:
            core.stop()
        up.stop()
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
