#!/usr/bin/env python3
# e2e: tier=T1 surface=l4 serial needs=l4
"""l4/l4_parity_core -- the L4 parity contract on an UNPRIVILEGED core (plan tasks A9, A6).

Everything here is provable on a core that cannot capture (this Mac: /dev/bpf* is
root-only), so it is the "[now]" half of the L4 parity spec, driven over the real MCP bus
as operator AND as agent and asserted on the core's verbatim replies -- never a fixture:

  * AC2 (live): `tools/list` has every verb the L4 module registers, and `l4.flow.get`'s
    inputSchema lists `offset` and `limit`, neither required.
  * AC3: `l4.capture.status` answers operator and agent alike, with no error, the object
    `{available, code, reason, captures}`; when unavailable `code == "needs_privilege"`,
    `captures == []`, and `l4.capture.start` still errors with `L4 unavailable: ` followed
    by exactly that `reason`. On macOS the literal reason is quoted and asserted (R_CAP).
  * AC4: the same for `l4.intercept.status` (`{available, code, reason, sessions}`,
    `code == "unsupported_platform"` and R_INT on macOS) and `l4.intercept.start`.
  * AC5 (half): every `l4.scope.list` entry carries `source: "config" | "runtime"`, and the
    rig's three config entries are there.
  * AC5 (1b): `tools/list` shows `l4.scope.add` with `confirmable: true` (unit (a'), plan A6):
    the operator-confirmed scope add is on this core; a core without it FAILS here.
  * AC5 operator add (unit (a')): with `widen: false`, an operator `l4.scope.add` returns
    `needs_confirmation` with a `confirm_token` and a prompt naming the cidr, ports,
    interface, direction and capability; re-issuing with `_confirm` returns the id; the list
    shows it `source: "runtime"` beside the three `config` entries; `widen` is still false;
    `l4.scope.remove` returns true and the list is back to its starting ids.
  * AC6: with the agent policy `all` and widen off, an agent `l4.scope.add` is refused with
    the widen text, is offered no confirmation, and leaves the list unchanged; under `auto`
    it is refused by policy. The original policy is restored.
  * AC34 (self-exclusion) needs a privileged capture: reported as skipped here, proven by
    the sibling `test_l4_parity_priv.py`.

Env model (like the sibling l4 cells): attaches to the runner's l4 core via AITM_BUS_ADDR +
AITM_BUS_OPERATOR_TOKEN + AITM_BUS_TOKEN (the agent half); never boots its own core. Tokens
are never printed. Soft-assertion battery; exit 0 pass / 1 fail / 77 skip. serial: it flips
the agent policy on the shared core for the AC6 checks.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402

# The 22 verbs the L4 module registers (plan A9 (1), spec AC32). Bundled-catalogue
# scripts may add more `l4.*` names; this cell asserts the module's, not a total.
L4_MODULE_TOOLS = (
    "l4.agent.set", "l4.agent.status",
    "l4.capture.start", "l4.capture.status", "l4.capture.stop",
    "l4.craft", "l4.flow.get", "l4.flow.list", "l4.inject",
    "l4.intercept.drop", "l4.intercept.forward", "l4.intercept.list", "l4.intercept.mutate",
    "l4.intercept.revert", "l4.intercept.start", "l4.intercept.status", "l4.intercept.stop",
    "l4.interfaces", "l4.scope.add", "l4.scope.list", "l4.scope.remove", "l4.send_recv",
)

# The unprivileged-rig reasons, verbatim (plan "The rig"; they change when D0 lands and
# only this cell asserts them literally, spec §1 / plan decision 1).
R_CAP = ("no read+write access to any /dev/bpf* device (capture/inject needs it; install "
         "ChmodBPF or run with privilege)")
R_INT = "in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)"
R_WIDEN = ("runtime L4 scope widening is disabled; declare scope in the `l4.scope` config "
           "block or set `l4.allow_agent_widen`")
WIDEN_TEXT = "runtime L4 scope widening is disabled"
UNAVAILABLE_PREFIX = "L4 unavailable: "

STATUS_CODES = ("available", "needs_privilege", "unsupported_platform", "not_configured")

# The AC5 entry (spec L4PAR-AC5).
AC5_ENTRY = {"cidr": "127.0.0.1/32", "ports": "9100-9199", "interface": "lo0",
             "direction": "inbound", "capability": "capture"}
AC5_PROMPT_WORDS = ("127.0.0.1/32", "9100-9199", "lo0", "inbound", "capture")

_failures: list[str] = []
_skipped: list[str] = []


def expect(cond, msg: str, detail="") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:300]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def skipped_check(msg: str, why: str) -> None:
    """One check of the battery that this core cannot prove; loud, not green, not a FAIL."""
    print(f"  [skipped] {msg}   -- {why}", flush=True)
    _skipped.append(msg)


def show(label: str, value) -> None:
    print(f"note: {label} = {json.dumps(value, default=str, sort_keys=True)[:600]}", flush=True)


# ---- pure helpers (no bus, no exit; exercised with literal inputs) --------------------

def status_shape_errors(reply, payload_key: str) -> list[str]:
    """Why `reply` is NOT a spec-§1 availability object `{available, code, reason,
    <payload_key>}`; `[]` when it is. `reason` must be a string exactly when
    `available` is false and null when true; `code` must be from the vocabulary and
    agree with `available`; the payload must be a list, empty when unavailable."""
    if not isinstance(reply, dict):
        return [f"reply is {type(reply).__name__}, not an object"]
    errs: list[str] = []
    missing = [k for k in ("available", "code", "reason", payload_key) if k not in reply]
    if missing:
        errs.append(f"missing keys {missing}")
    available = reply.get("available")
    code = reply.get("code")
    reason = reply.get("reason")
    payload = reply.get(payload_key)
    if not isinstance(available, bool):
        errs.append(f"available is {available!r}, not a bool")
    if code not in STATUS_CODES:
        errs.append(f"code {code!r} is not one of {STATUS_CODES}")
    if available is True:
        if code != "available":
            errs.append(f"available: true but code {code!r}")
        if reason is not None:
            errs.append(f"available: true but reason {reason!r} (must be null)")
    elif available is False:
        if code == "available":
            errs.append("available: false but code \"available\"")
        if not (isinstance(reason, str) and reason):
            errs.append(f"available: false but reason {reason!r} (must be a non-empty string)")
        if payload != []:
            errs.append(f"available: false but {payload_key} {payload!r} (must be [])")
    if not isinstance(payload, list):
        errs.append(f"{payload_key} is {type(payload).__name__}, not a list")
    return errs


def unavailable_error_matches(error_text: str, reason) -> bool:
    """True iff a gated verb's error text ends with `L4 unavailable: ` + exactly `reason`
    (the ToolError text is `<tool>: <message>`; nothing may follow the reason)."""
    return isinstance(reason, str) and bool(reason) and error_text.endswith(UNAVAILABLE_PREFIX + reason)


def optional_params(input_schema: dict, names) -> list[str]:
    """Those of `names` the JSON-Schema `input_schema` declares as properties and does
    NOT list under `required`."""
    props = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or [])
    return [n for n in names if n in props and n not in required]


def required_params(input_schema: dict) -> list[str]:
    return sorted(input_schema.get("required") or [])


def tool_by_name(tools: list[dict], name: str):
    for t in tools:
        if t.get("name") == name:
            return t
    return None


def scope_add_confirmable(tools: list[dict]) -> bool:
    """True iff tools/list has `l4.scope.add` with `confirmable: true` (spec §3: the UIs
    render their add control, and this cell runs AC5, only then)."""
    t = tool_by_name(tools, "l4.scope.add")
    return bool(t) and t.get("confirmable") is True


def l4_names(tools: list[dict]) -> list[str]:
    return sorted({t.get("name", "") for t in tools if str(t.get("name", "")).startswith("l4.")})


def scope_source_errors(entries) -> list[str]:
    """Every `l4.scope.list` entry must carry `source` as `config` or `runtime`."""
    if not isinstance(entries, list):
        return [f"l4.scope.list returned {type(entries).__name__}, not a list"]
    errs = []
    for i, e in enumerate(entries):
        src = e.get("source") if isinstance(e, dict) else None
        if src not in ("config", "runtime"):
            errs.append(f"entry {i} ({e.get('id') if isinstance(e, dict) else e!r}) source={src!r}")
    return errs


def config_loopback_capabilities(entries) -> set[str]:
    """The capabilities granted by CONFIG entries on a 127.x cidr."""
    return {e.get("capability") for e in entries
            if isinstance(e, dict) and e.get("source") == "config"
            and str(e.get("cidr", "")).startswith("127.")}


def scope_ids(entries) -> list[str]:
    return sorted(str(e.get("id")) for e in entries if isinstance(e, dict))


def is_needs_confirmation(reply) -> bool:
    return isinstance(reply, dict) and reply.get("status") == "needs_confirmation"


def expected_literal_reason(code: str):
    """The verbatim reason this cell asserts on macOS for an unavailable code; None where
    no literal is pinned (Linux rigs, or after D0 rewrites the probe strings)."""
    if sys.platform != "darwin":
        return None
    return {"needs_privilege": R_CAP, "unsupported_platform": R_INT}.get(code)


def default_loopback_interface() -> str:
    return "lo0" if sys.platform == "darwin" else "lo"


# ---- the live checks ------------------------------------------------------------------

def check_status_verb(op, agent, verb: str, start_verb: str, payload_key: str,
                      unavailable_codes: tuple, iface: str):
    """AC3 / AC4: the status verb answers both roles with the same honest object; the start
    verb still refuses with exactly the status reason. Returns the operator's reply."""
    st_op, rep_op = op.try_call(verb)
    st_ag, rep_ag = agent.try_call(verb)
    show(f"{verb} (operator)", rep_op)
    show(f"{verb} (agent)", rep_ag)
    expect(st_op == "ok", f"{verb} answers the operator without error", rep_op)
    expect(st_ag == "ok", f"{verb} answers the agent without error (not L4 unavailable, not policy)", rep_ag)
    if st_op != "ok":
        return None
    errs = status_shape_errors(rep_op, payload_key)
    expect(not errs, f"{verb} is the spec §1 object {{available, code, reason, {payload_key}}}", errs)
    if st_ag == "ok":
        expect(rep_ag == rep_op, f"{verb}: the agent reads the same object as the operator",
               {"operator": rep_op, "agent": rep_ag})
    if errs:
        return rep_op
    reason = rep_op["reason"]
    if rep_op["available"] is False:
        expect(rep_op["code"] in unavailable_codes,
               f"{verb}: code is one of {unavailable_codes} on this unprivileged rig", rep_op["code"])
        literal = expected_literal_reason(rep_op["code"])
        if literal is not None:
            print(f"note: {verb} reason, verbatim: {reason!r}", flush=True)
            expect(reason == literal, f"{verb}: the reason is the rig's verbatim literal", reason)
        st, err = op.try_call(start_verb, {"interface": iface})
        show(f"{start_verb} {{interface: {iface!r}}} (operator)", err)
        expect(st == "error", f"{start_verb} is still refused while unavailable", err)
        expect(st == "error" and unavailable_error_matches(str(err), reason),
               f"{start_verb} errors with `{UNAVAILABLE_PREFIX}` + exactly the status reason",
               {"error": str(err)[-220:], "reason": reason})
    else:
        expect(rep_op["code"] == "available" and reason is None,
               f"{verb}: available on this core (code \"available\", reason null)", rep_op)
        skipped_check(f"{start_verb} refusal text", f"{verb} says available here; the start/stop "
                      "walk is the sibling test_l4_parity_priv.py's")
    return rep_op


def run_operator_scope_add(op, before_ids: list[str]) -> None:
    """AC5 on a core with unit (a'): confirm handshake, add, list provenance, widen off, remove."""
    widen0 = op.call("l4.agent.status").get("widen")
    expect(widen0 is False, "l4.agent.status reads widen: false before the operator add", widen0)
    asked = op.call("l4.scope.add", dict(AC5_ENTRY))
    show("operator l4.scope.add (first call)", asked)
    expect(is_needs_confirmation(asked), "operator l4.scope.add returns needs_confirmation", asked)
    token = asked.get("confirm_token") if isinstance(asked, dict) else None
    prompt = str(asked.get("prompt", "")) if isinstance(asked, dict) else ""
    expect(bool(token), "the handshake carries a confirm_token", asked)
    missing = [w for w in AC5_PROMPT_WORDS if w not in prompt]
    expect(not missing, "the confirm prompt names cidr, ports, interface, direction, capability",
           {"missing": missing, "prompt": prompt})
    if not token:
        return
    added = op.call("l4.scope.add", dict(AC5_ENTRY, _confirm=token))
    show("operator l4.scope.add (_confirm)", added)
    expect(isinstance(added, str) and bool(added), "re-issuing with _confirm returns the new entry id", added)
    new_id = added if isinstance(added, str) else None
    try:
        listed = op.call("l4.scope.list")
        mine = [e for e in listed if e.get("id") == new_id]
        expect(len(mine) == 1 and mine[0].get("source") == "runtime",
               "l4.scope.list shows the added entry with source: \"runtime\"", mine)
        cfg = [e for e in listed if e.get("source") == "config"]
        expect(len(cfg) == 3, "the three config entries still read source: \"config\"", [e.get("id") for e in cfg])
        widen1 = op.call("l4.agent.status").get("widen")
        expect(widen1 is False, "l4.agent.status still reads widen: false after the operator add", widen1)
    finally:
        if new_id:
            removed = op.confirm("l4.scope.remove", {"id": new_id})
            expect(removed is True, "l4.scope.remove removes the entry (true)", removed)
    expect(scope_ids(op.call("l4.scope.list")) == before_ids, "the scope list is back to its starting ids")


def run_agent_scope_add(op, agent, before_ids: list[str]) -> None:
    """AC6: agents are unchanged. Policy `all` + widen off -> the widen text, no handshake,
    list unchanged; policy `auto` -> refused by policy. Restores the original policy."""
    original = op.call("agent.status").get("policy")
    print(f"note: agent policy before = {original!r}", flush=True)
    try:
        op.confirm("agent.set", {"policy": "all"})
        st, rep = agent.try_call("l4.scope.add", dict(AC5_ENTRY))
        show("agent l4.scope.add under policy all", rep)
        expect(st == "error", "agent l4.scope.add is refused under policy all (widen off)", rep)
        expect(st == "error" and WIDEN_TEXT in str(rep),
               "the refusal is the widen text (\"runtime L4 scope widening is disabled\")", str(rep)[-240:])
        expect(st == "error" and R_WIDEN in str(rep), "the widen refusal is the verbatim R_WIDEN literal", str(rep)[-240:])
        expect(not is_needs_confirmation(rep), "no confirmation handshake is offered to the agent", rep)
        expect(scope_ids(op.call("l4.scope.list")) == before_ids, "the scope list is unchanged after the agent attempt")

        op.confirm("agent.set", {"policy": "auto"})
        st2, rep2 = agent.try_call("l4.scope.add", dict(AC5_ENTRY))
        show("agent l4.scope.add under policy auto", rep2)
        expect(st2 == "error" and "refused" in str(rep2) and "policy" in str(rep2),
               "under policy auto the agent l4.scope.add is refused by policy", str(rep2)[-240:])
        expect(scope_ids(op.call("l4.scope.list")) == before_ids, "the scope list is still unchanged")
    finally:
        if isinstance(original, str) and original:
            try:
                op.confirm("agent.set", {"policy": original})
            except (ToolError, BusError) as e:  # pragma: no cover - rig hygiene
                print(f"  [warn] could not restore agent policy {original!r}: {e}", flush=True)
    restored = op.call("agent.status").get("policy")
    expect(restored == original, "the agent policy is restored", {"before": original, "after": restored})


def main() -> int:
    bus_addr = os.environ.get("AITM_BUS_ADDR")
    op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN")
    agent_token = os.environ.get("AITM_BUS_TOKEN")
    if not (bus_addr and op_token):
        skip("no runner-provided L4 core: set AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN (+ AITM_BUS_TOKEN) "
             "from an l4-enabled rig (run.py --shared-core l4, or the L4 rig)")
    if not agent_token:
        skip("AITM_BUS_TOKEN (the agent token) is not set: AC3/AC4/AC6 assert the agent role too")
    bh, _, bp = bus_addr.rpartition(":")
    core = SimpleNamespace(bus_addr=(bh or "127.0.0.1", int(bp)),
                           cfg=SimpleNamespace(agent_token=agent_token, operator_token=op_token))
    iface = default_loopback_interface()

    op = agent = None
    try:
        op = BusClient.operator(core)
        agent = BusClient.agent(core)
        tools = op.tools()
        names = l4_names(tools)
        if "l4.capture.status" not in names:
            skip(f"the L4 module is not enabled on this core (l4.* tools: {names}); l4.enabled is opt-in "
                 "+ feature-compiled -- run this in the L4 rig")

        section("(1) tools/list: the l4.* family and the l4.flow.get window params (AC2 live)")
        print(f"note: {len(names)} l4.* tools: {names}", flush=True)
        missing_mod = [n for n in L4_MODULE_TOOLS if n not in names]
        expect(not missing_mod, "every L4 module verb is in tools/list", missing_mod)
        print(f"note: l4.* names beyond the module's 22: {sorted(set(names) - set(L4_MODULE_TOOLS))}", flush=True)
        fg = tool_by_name(tools, "l4.flow.get") or {}
        schema = fg.get("inputSchema") or {}
        show("l4.flow.get inputSchema", schema)
        expect(optional_params(schema, ("offset", "limit")) == ["offset", "limit"],
               "l4.flow.get inputSchema lists offset and limit, neither required",
               {"properties": sorted((schema.get("properties") or {}).keys()), "required": required_params(schema)})
        expect(required_params(schema) == ["id"], "l4.flow.get requires only id", required_params(schema))
        agent_names = l4_names(agent.tools())
        expect(agent_names == names, "the agent's tools/list carries the same l4.* names", agent_names)

        section("(1b) tools/list: l4.scope.add is confirmable (unit (a'): operator confirm-over-the-wire)")
        show("l4.scope.add tool", {k: v for k, v in (tool_by_name(tools, "l4.scope.add") or {}).items()
                                   if k != "inputSchema"})
        expect(scope_add_confirmable(tools),
               "tools/list shows l4.scope.add with confirmable: true (the UIs render their add control on it)",
               tool_by_name(tools, "l4.scope.add"))
        agent_tools = agent.tools()
        expect(scope_add_confirmable(agent_tools),
               "the agent's tools/list shows the same confirmable: true (static per tool, never per role)",
               tool_by_name(agent_tools, "l4.scope.add"))

        section("(2) AC3: l4.capture.status is honest for operator and agent; capture.start still refuses")
        check_status_verb(op, agent, "l4.capture.status", "l4.capture.start", "captures", ("needs_privilege",), iface)

        section("(3) AC4: l4.intercept.status is honest for operator and agent; intercept.start still refuses")
        # macOS: no in-path backend. Linux: no CAP_NET_ADMIN, or no `l4.intercept` config block.
        check_status_verb(op, agent, "l4.intercept.status", "l4.intercept.start", "sessions",
                          ("unsupported_platform",) if sys.platform == "darwin" else ("needs_privilege", "not_configured"),
                          iface)

        section("(4) AC5 provenance: every l4.scope.list entry carries source")
        scope = op.call("l4.scope.list")
        show("l4.scope.list", scope)
        src_errs = scope_source_errors(scope)
        expect(not src_errs, "every scope entry has source: \"config\" | \"runtime\"", src_errs)
        caps = config_loopback_capabilities(scope)
        expect(caps == {"capture", "inject", "intercept"},
               "the rig's three config loopback entries (capture, inject, intercept) are listed as config", caps)
        agent_scope = agent.call("l4.scope.list")
        expect(agent_scope == scope, "the agent reads the same scope list (read verb)", agent_scope)
        before_ids = scope_ids(scope)

        section("(5) AC5 operator scope add through confirm-over-the-wire (unit (a'))")
        if scope_add_confirmable(tools):
            run_operator_scope_add(op, before_ids)
        else:
            # (1b) already failed the cell for this; do not also send an un-confirmable add,
            # and do not count the same defect twice.
            print("note: (5) not run: tools/list shows l4.scope.add confirmable=false (this core lacks "
                  "unit (a'), fix/l4-parity-core-scope task A6) -- already a FAIL at (1b)", flush=True)

        section("(6) AC6 agents unchanged: the widen gate, not a handshake")
        run_agent_scope_add(op, agent, before_ids)

        section("(7) AC34 self-exclusion of the core's own listeners")
        skipped_check("AC34 live: a lo0 capture holds no packet on the bus port",
                      "needs a privileged capture; proven by tests/e2e/l4/test_l4_parity_priv.py "
                      "(blocked: needs D0 on this Mac)")
    finally:
        for c in (agent, op):
            if c is not None:
                c.close()

    if _skipped:
        print(f"note: {len(_skipped)} check(s) reported as skipped on this core (see [skipped] lines)", flush=True)
    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:8]))
    ok("PASS: L4 parity core contract holds for operator and agent on this core")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
