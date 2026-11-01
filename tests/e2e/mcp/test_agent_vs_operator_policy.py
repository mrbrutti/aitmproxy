#!/usr/bin/env python3
# e2e: tier=T1 surface=mcp
"""Agent vs operator: the role policy refuses the AGENT both Sensitive commands
(`poc.run` and `ca.install`) while the OPERATOR runs them — proven on ground truth.

aitmproxy's central safety property is that a (possibly confused or compromised)
agent on the MCP bus cannot take Sensitive actions on its own, while the human
operator can. The role is decided purely by which token a connection presents on
the loopback bus (`crates/aitm-mcp/src/transport.rs`: operator token ->
`Frontend::Operator`, agent token -> `Frontend::Mcp`), so one real core, driven at
both roles, exposes the asymmetry with nothing but the token changed between them.

Both commands are Sensitive on the live binary:
  * `ca.install` declares `Sensitivity::Sensitive` (it touches the OS trust store).
  * `poc.run` is served by `ScriptedPocRunCommand` (the binary always wires the Rhai
    executor, `crates/aitm/src/main.rs`), which inherits the `Command` trait's
    fail-closed default `Sensitivity::Sensitive`.
Under the default `auto` agent policy the server's role gate
(`crates/aitm-mcp/src/server.rs::policy_decision`) REFUSES a Sensitive command for a
`Frontend::Mcp` agent ("...the agent policy is `auto`... permits no sensitive
actions") and ALLOWS it for the operator (role != Mcp -> bypasses the gate).

Ground truth asserted (never the tool's own say-so, never a fixture):
  1. the agent call for EACH command is REFUSED with the sensitivity gate's reason;
  2. the refused agent `poc.run` RAN NOTHING — an independent upstream echo-record
     origin never saw the request the PoC would have sent;
  3. the OPERATOR `ca.install` really executed (its REAL dry-run: `dry_run:true`,
     `changed` a would-change boolean, and the actual OS commands it inspected) —
     dry-run only, so NOTHING in the real trust store changes;
  4. the OPERATOR `poc.run` really ran: the same upstream RECORDED its request, the
     tool reports `passed:true`, and the durable finding is read back off disk
     (`findings.get`), while the upstream STILL shows nothing from the agent.

Why `ca.install` is driven with `dry_run:true`: the allowed side must be real and
repeatable without mutating the host. Dry-run skips every mutating command
(`crates/aitm-ca/src/exec.rs::DryRunExecutor`) but still runs the read-only trust
queries and reports the plan, so "the operator is allowed" is proven on the real
command's real output with zero side effects. The agent is refused at the policy
gate BEFORE invoke regardless of `dry_run`, so the asymmetry is exact.

Modes. By default this boots its OWN real core on dedicated free ports with its own
poc/findings dirs and a private loopback upstream (the `aitm_e2e` convention; this
is the only mode the suite runner exercises, and it touches no global state). If a
runner instead exports `AITM_BUS_ADDR` (`host:port`) plus `AITM_BUS_TOKEN` (agent)
and `AITM_OPERATOR_TOKEN`, the test ATTACHES to that already-running core and drives
the operator `poc.run` against `AITM_TARGET_URL`; without an independent upstream it
leans on the on-disk finding for ground truth. Either way the shared MCP client is
`aitm_e2e.bus.BusClient` and the result is signalled by exit code (0/1/77).

Parallel/isolation & cleanup: dedicated free ports, per-run temp dirs, a random
loopback upstream; `ca.install` is dry-run only. Cleanup signals only our own child
PID (the core reaps obscura) — never a machine-wide `pkill`.
"""

import os
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

POC_RUN = "poc.run"
CA_INSTALL = "ca.install"

# A minimal HTTP-only PoC (no browser step -> no obscura). Its single step GETs the
# target with a unique marker in the path; `success` passes iff that marker is
# reflected in the response body, which the echo-record upstream always does (it
# echoes the request path in its JSON body). So a real run against a reachable,
# in-scope upstream passes deterministically and is observable upstream-side.
POC_YAML = """\
id: e2e-agent-operator-policy-probe
info:
  name: E2E agent/operator policy operator probe
  severity: info
  description: Minimal HTTP-only PoC the agent-vs-operator policy e2e test runs through the real core.
  cwe: CWE-200
  tags: [e2e, policy, gate]
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


def saw_marker(observer, mark: str) -> bool:
    """True iff the independent upstream's OWN record shows a /echo request carrying
    `mark`. Returns False when there is no upstream (attach mode)."""
    if observer is None:
        return False
    return any(mark in r["path"] for r in observer.received if r["path"].startswith("/echo"))


def prove(agent, op, *, target_base, observer, poc_path, findings_required) -> None:
    """The role asymmetry on both Sensitive commands, asserted on ground truth.

    `observer` is the independent upstream (boot mode) or None (attach mode). All
    checks use the real core's real decisions; `check(...)` fails the run (exit 1)
    on the first falsified claim.
    """
    section("the live tool surface registers BOTH Sensitive commands")
    names = op.tool_names()
    for tool in (POC_RUN, CA_INSTALL):
        if tool not in names:
            skip(f"{tool} is not registered on this build; nothing to gate")
    ok(f"{POC_RUN} and {CA_INSTALL} are both registered and visible on the live surface")

    section("sanity: the AGENT socket is healthy for a Read command (rules out a dead connection)")
    st, val = agent.try_call("flow.list")
    check(st == "ok", f"agent may run the Read command flow.list (got {st}: {str(val)[:80]})")

    op_mark = marker("e2eop")
    ag_mark = marker("e2eag")
    poc_args_op = {"poc_path": poc_path, "target": target_base, "vars": {"marker": op_mark}}
    poc_args_ag = {"poc_path": poc_path, "target": target_base, "vars": {"marker": ag_mark}}
    ca_args = {"dry_run": True}  # dry-run: no real trust-store change, same policy decision

    section("gate CLOSED: the AGENT is REFUSED both Sensitive commands")
    for tool, args in ((POC_RUN, poc_args_ag), (CA_INSTALL, ca_args)):
        st, msg = agent.try_call(tool, args)
        lo = (msg or "").lower()
        check(st == "error", f"agent {tool} is REFUSED, not allowed (got {st}: {str(msg)[:120]})")
        check("refused" in lo, f"agent {tool} refusal states it is refused (msg: {msg[:180]!r})")
        # Auto + Sensitive -> the sensitivity reason; a bad-args or missing-file error
        # would never mention "sensitive", so this pins it to the role/policy gate.
        check("sensitive" in lo,
              f"agent {tool} refusal is the role/sensitivity gate, not an unrelated error (msg: {msg[:180]!r})")

    if observer is not None:
        section("ground truth A: the refused agent poc.run RAN NOTHING (the independent upstream saw no request)")
        check(not saw_marker(observer, ag_mark),
              f"the upstream never received the agent PoC's request ({len(observer.received)} hit(s) total)")

    section(f"gate OPEN: the OPERATOR is ALLOWED {CA_INSTALL} (REAL dry-run — no trust-store change)")
    st, res = op.try_call(CA_INSTALL, ca_args)
    check(st == "ok",
          f"operator {CA_INSTALL} is NOT policy-refused; it runs (got {st}: {str(res)[:180]})")
    check(isinstance(res, dict) and res.get("dry_run") is True,
          f"operator {CA_INSTALL} executed the real dry-run (dry_run echoed true): {str(res)[:220]}")
    check(isinstance(res.get("changed"), bool),
          f"the dry-run reports a boolean would-change plan, making no actual change: {str(res)[:220]}")
    check(isinstance(res.get("commands"), list) and len(res["commands"]) > 0,
          f"the dry-run reports the real OS trust commands it inspected/would run: {res.get('commands')}")

    section(f"gate OPEN: the OPERATOR is ALLOWED {POC_RUN}")
    st, result = op.try_call(POC_RUN, poc_args_op)
    if observer is None and st == "error":
        # Attach mode without a controlled upstream/poc dir: the only hard claim is
        # that the operator is NOT refused by the ROLE policy (ca.install above
        # already proved the allowed side on ground truth). An environment failure
        # (unknown poc dir, unreachable target) is noted, not a policy regression.
        lo = (result or "").lower()
        check("sensitive" not in lo and "agent policy" not in lo,
              f"operator {POC_RUN} is NOT policy-refused; any failure is environment, not the role gate ({result[:180]})")
        ok(f"operator {POC_RUN} cleared the role gate but did not complete here ({result[:120]}); "
           "the operator-allowed side is already proven by ca.install on ground truth")
        print("PASS: agent refused poc.run & ca.install (sensitive); operator ran ca.install (dry-run); "
              "operator cleared the poc.run role gate — asymmetry holds.")
        return

    check(st == "ok", f"operator {POC_RUN} is NOT policy-refused; it runs (got {st}: {str(result)[:180]})")
    check(isinstance(result, dict) and "passed" in result,
          f"{POC_RUN} returned a structured PoC result (got {type(result).__name__})")

    if observer is not None:
        check(result.get("passed") is True,
              f"the operator's PoC PASSED against the real upstream (result: {result})")
        section("ground truth B: the operator's PoC request REALLY reached the upstream; the agent's still did not")
        deadline = time.time() + 5
        while not saw_marker(observer, op_mark) and time.time() < deadline:
            time.sleep(0.1)
        check(saw_marker(observer, op_mark),
              f"the upstream RECORDED the operator PoC's GET /echo?probe={op_mark}")
        check(not saw_marker(observer, ag_mark),
              "the upstream STILL shows nothing from the refused agent (asymmetry holds at the network boundary)")
    else:
        ok(f"operator {POC_RUN} ran (passed={result.get('passed')}); no independent upstream in attach mode")

    section("ground truth C: the operator's run left a durable finding the store reads back off disk")
    recorded_id = result.get("recorded_id") if isinstance(result, dict) else None
    if recorded_id:
        st, got = op.try_call("findings.get", {"id": recorded_id})
        check(st == "ok" and isinstance(got, dict),
              f"findings.get reads the recorded finding back from disk (got {st}: {str(got)[:80]})")
    elif findings_required:
        fail(f"the passing poc.run recorded no finding id (result keys: {sorted(result)})")
    else:
        ok("no finding id returned (the attached core configured no findings dir); skipping the disk read-back")

    print("PASS: the agent is REFUSED poc.run & ca.install (sensitive); the operator RUNS both — "
          "ground truth verified (dry-run only; no real trust-store change).")


def main_boot() -> int:
    """Default: boot a real core on dedicated ports with a private upstream in scope."""
    work = Path(tempfile.mkdtemp(prefix="aitm-e2e-mcp-policy-"))
    poc_dir = work / "poc"
    poc_dir.mkdir()
    poc_path = poc_dir / "probe.yaml"
    poc_path.write_text(POC_YAML, encoding="utf-8")

    up = Upstream().start()
    core = agent = op = None
    try:
        section("boot: a real aitm core on dedicated free ports, the upstream in scope")
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[up.authority],
            poc_dir=str(poc_dir),
            poc_out_dir=str(work / "poc-out"),
            findings_dir=str(work / "findings"),
        )
        core = Aitm.server(cfg)
        ok(f"core up: bus {core.bus_addr}, upstream {up.base}")

        # The bare `aitm` server always wires the operator token into the loopback
        # bus, so a failure to connect as operator is a real role-gate regression,
        # not a missing dependency — fail, do not skip.
        try:
            op = BusClient.operator(core)
        except BusError as e:
            fail(f"operator role refused on the loopback bus — the role gate is broken: {e}")
        agent = BusClient.agent(core)

        prove(agent, op, target_base=up.base, observer=up,
              poc_path=str(poc_path), findings_required=True)
    finally:
        for c in (agent, op):
            if c:
                c.close()
        if core:
            core.stop()
        up.stop()
        shutil.rmtree(work, ignore_errors=True)
    return 0


def main_attach(addr: str) -> int:
    """Attach to an externally-run core named by AITM_BUS_ADDR (the runner model)."""
    try:
        host, port_s = addr.rsplit(":", 1)
        port = int(port_s)
    except ValueError:
        fail(f"AITM_BUS_ADDR must be host:port (got {addr!r})")

    agent_tok = os.environ.get("AITM_BUS_TOKEN") or os.environ.get("AITM_AGENT_TOKEN")
    op_tok = os.environ.get("AITM_OPERATOR_TOKEN") or os.environ.get("AITM_BUS_OPERATOR_TOKEN")
    target_base = os.environ.get("AITM_TARGET_URL")
    if not agent_tok:
        skip("attach mode (AITM_BUS_ADDR set) needs AITM_BUS_TOKEN (the agent token)")
    if not op_tok:
        skip("attach mode needs AITM_OPERATOR_TOKEN to exercise the operator role")
    if not target_base:
        skip("attach mode needs AITM_TARGET_URL (a real, in-scope target) for the operator poc.run leg")

    work = Path(tempfile.mkdtemp(prefix="aitm-e2e-mcp-policy-"))
    poc_dir = Path(os.environ.get("AITM_POC_DIR") or work)
    poc_dir.mkdir(parents=True, exist_ok=True)
    poc_path = poc_dir / "e2e_agent_vs_operator_probe.yaml"
    poc_path.write_text(POC_YAML, encoding="utf-8")

    agent = op = None
    try:
        section(f"attach: connect BOTH roles to the running core at {host}:{port}")
        op = BusClient(host, port, op_tok, client_name="aitm-e2e-operator").connect()
        agent = BusClient(host, port, agent_tok, client_name="aitm-e2e-agent").connect()
        ok("both roles connected (operator token -> Operator, agent token -> Mcp)")
        prove(agent, op, target_base=target_base, observer=None,
              poc_path=str(poc_path), findings_required=False)
    finally:
        for c in (agent, op):
            if c:
                c.close()
        shutil.rmtree(work, ignore_errors=True)
    return 0


def main() -> int:
    addr = os.environ.get("AITM_BUS_ADDR")
    return main_attach(addr) if addr else main_boot()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
