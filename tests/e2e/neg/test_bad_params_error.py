#!/usr/bin/env python3
# e2e: tier=T1 surface=neg
"""neg/test_bad_params_error -- a tool called with MISSING or INVALID params answers a
STRUCTURED error, never a crash, a dropped connection, a silent "ok", or a hang.

The expectation is DERIVED, never hard-coded: every tool in the live ``tools/list``
publishes an ``inputSchema`` (``required``, per-param ``type`` / ``format: uuid`` /
``contentEncoding: base64``, ``additionalProperties: false``). That published schema
IS the contract (crates/aitm-mcp/src/schema.rs), so for EVERY live tool this cell
sends, one defect at a time:

  B1  ``{}``                        when the schema lists required params  -> missing
  B2  valid required args + one undeclared key                             -> unknown key
  B3  each declared param (required or optional) with a wrong-typed value  -> wrong type
  B4  a ``format: uuid`` param with a non-uuid, a base64 param with junk   -> wrong format

and asserts each answer is a structured error -- the MCP ``-32602`` INVALID_PARAMS
envelope (the command never ran; crates/aitm-mcp/src/json.rs ``params_from_json``),
or, for a server-handled verb, an ``isError`` tool result naming the param -- that
arrives within HANG_S on the SAME connection. Protocol-level junk (no tool ``name``,
non-object ``params``/``arguments``, an unknown tool, an unknown method, a malformed
JSON line, a non-object request, a request with no method) gets the same treatment.
Then the well-formed-but-wrong class (a flow id nobody has, a ``body`` mode that
does not exist on a REAL captured flow, scope entries that are not hosts, approving
a request nobody parked) must come back ``isError`` with the command's own reason.

Ground truth, not fixtures:
  * the server's own JSON-RPC replies (code, message, id) to each probe, and that the
    SAME connection keeps answering afterwards (ping, an unchanged tools/list,
    proxy.status listening=true) -- no drop, no hang;
  * the audit ring (``agent.activity``): every command that RUNS or is REFUSED by
    policy is audited under the caller's client label, a protocol-level refusal is
    not -- so after the storm, no tool that only ever received bad params has an
    entry under this run's unique label: a refused call is a call that did not run;
  * state the bad calls could have mutated: the junk scope entries are absent from
    ``scope.list``; the tool surface is unchanged;
  * after the storm the core still FORWARDS real traffic: a GET sent THROUGH the
    proxy is answered 200 by the seeded aitm-testtarget (AITM_TARGET_URL) or
    recorded by an independent echo-record upstream, and appears in ``flow.table``
    carrying this run's unique marker; a fresh connection still initializes.

Roles: the storm runs as the OPERATOR (the policy gate is bypassed, so the argument
validator is reached for every tool) when AITM_BUS_OPERATOR_TOKEN is given;
otherwise as the agent, where a Sensitive tool's policy refusal (also structured) is
accepted and validation itself is asserted on the Read/Write tools. Under the
``ask`` policy an agent's Sensitive call may be PARKED up to the approval timeout,
which this cell cannot tell from a hang, so the agent-only fallback SKIPs there.

Core: the one the runner provides through the environment -- AITM_BUS_ADDR,
AITM_BUS_TOKEN (agent token), AITM_PROXY_ADDR, optional AITM_BUS_OPERATOR_TOKEN and
AITM_TARGET_URL. This cell never boots a core (exit 77 without AITM_BUS_ADDR).
Parallel-safe on a shared core: nothing it sends can run, every assertion on shared
state is scoped to this run's own client label / marker, and the only widening it
may do (adding its loopback observer to scope when no AITM_TARGET_URL is given) is
undone in ``finally``. Never prints a token.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

ENV_BUS_ADDR = "AITM_BUS_ADDR"
ENV_BUS_TOKEN = "AITM_BUS_TOKEN"
ENV_OP_TOKEN = "AITM_BUS_OPERATOR_TOKEN"
ENV_PROXY_ADDR = "AITM_PROXY_ADDR"
ENV_TARGET_URL = "AITM_TARGET_URL"

# JSON-RPC 2.0 codes as the server emits them (crates/aitm-mcp/src/server.rs).
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

HANG_S = 5.0  # a loopback validation refusal is milliseconds; past this it hung
BOGUS_KEY = "__e2e_bogus_param__"
WRONG = {  # a JSON value of the WRONG type for each JSON Schema `type`
    "string": 12345,
    "integer": "twelve",
    "number": "pi",
    "boolean": "yes",
    "array": {"not": "an array"},
    "object": ["not", "an object"],
}
# Verbs the server answers itself in `run_tool`, BEFORE the shared validator
# (`params_from_json`): they parse their own arguments, so a violation here is
# attributed to them by name rather than to the registry path.
SERVER_HANDLED = frozenset({"flow.subscribe", "flow.unsubscribe", "agent.approve"})

_failures: list[str] = []


def expect(cond: object, msg: str, detail: object = "") -> bool:
    """A soft assertion: print, collect, keep going (one bad tool must not hide the
    rest). The run exits 1 iff anything was collected. Preconditions use check()."""
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:400]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def note(msg: str) -> None:
    print(f"  [note] {msg}", flush=True)


class Hang(RuntimeError):
    """No id-matched reply within HANG_S: the very failure this cell exists for."""


# --- the core: provided by the runner through the environment -------------------


def _hostport(addr: str, what: str) -> tuple[str, int]:
    host, sep, port = addr.strip().rpartition(":")
    if not sep or not port.isdigit():
        fail(f"{what} must be host:port, got {addr!r}")
    return (host.strip("[]") or "127.0.0.1"), int(port)


class EnvCore:
    """The runner's core, shaped like aitm_e2e.core.Aitm (bus_addr + cfg tokens) so
    BusClient works unchanged. Boots nothing; there is nothing to stop."""

    def __init__(self) -> None:
        addr = os.environ.get(ENV_BUS_ADDR)
        if not addr:
            skip(f"no runner-provided core: {ENV_BUS_ADDR} is unset (this cell never boots its "
                 f"own core; the runner exports {ENV_BUS_ADDR}, {ENV_BUS_TOKEN}, {ENV_PROXY_ADDR})")
        token = os.environ.get(ENV_BUS_TOKEN)
        if not token:
            fail(f"{ENV_BUS_ADDR} is set but {ENV_BUS_TOKEN} (the agent token) is not")
        self.bus_addr = _hostport(addr, ENV_BUS_ADDR)
        self.agent_token = token
        self.operator_token = os.environ.get(ENV_OP_TOKEN) or None
        proxy = os.environ.get(ENV_PROXY_ADDR)
        self.proxy_addr = _hostport(proxy, ENV_PROXY_ADDR) if proxy else None
        self.target_url = (os.environ.get(ENV_TARGET_URL) or "").rstrip("/") or None


# --- the probe client: raw envelopes, bounded waits ---------------------------------


class ProbeBus(BusClient):
    """BusClient plus raw envelope access with a per-request read bound. BusClient.rpc
    hides the envelope (it raises on `error`); this cell asserts ON the envelope."""

    def rpc_raw(self, method: str, params, timeout: float = HANG_S) -> tuple[dict, float]:
        self._id += 1
        mid = self._id
        self._set_read_timeout(timeout)
        t0 = time.monotonic()
        try:
            self._send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
            while True:
                msg = self._recv()
                if msg.get("id") == mid:
                    return msg, time.monotonic() - t0
                self.notifications.append(msg)  # a server push; not ours to judge here
        except (socket.timeout, TimeoutError) as e:
            raise Hang(f"{method}: no id-matched reply within {timeout:.1f}s") from e
        finally:
            self._restore_read_timeout()

    def raw_line(self, line: str, want_id=None, timeout: float = HANG_S) -> tuple[dict, float]:
        """Send one raw wire line (possibly malformed) and wait for the server's reply:
        the one with `want_id`, or, when None, the first id-less error envelope."""
        self._set_read_timeout(timeout)
        t0 = time.monotonic()
        try:
            self._write_line(line)
            while True:
                msg = self._recv()
                if want_id is None:
                    if msg.get("id") is None and "error" in msg:
                        return msg, time.monotonic() - t0
                elif msg.get("id") == want_id:
                    return msg, time.monotonic() - t0
                self.notifications.append(msg)
        except (socket.timeout, TimeoutError) as e:
            raise Hang(f"raw line {line[:40]!r}: no reply within {timeout:.1f}s") from e
        finally:
            self._restore_read_timeout()


def connect(core: EnvCore, token: str, label: str) -> ProbeBus:
    host, port = core.bus_addr
    return ProbeBus(host, port, token, client_name=label).connect()


def classify(env: dict) -> tuple[str, int | None, str]:
    """One reply envelope -> (kind, code, text) with kind in
    rpc_error | tool_error | pending | ok."""
    if "error" in env:
        err = env.get("error") or {}
        return "rpc_error", err.get("code"), str(err.get("message", ""))
    res = env.get("result")
    if isinstance(res, dict):
        if res.get("isError"):
            content = res.get("content") or []
            text = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
            return "tool_error", None, text or "error"
        sc = res.get("structuredContent")
        if isinstance(sc, dict) and sc.get("status") == "needs_confirmation":
            return "pending", None, "needs_confirmation"
    return "ok", None, json.dumps(res)[:160]


class Prober:
    """Sends probes on ONE connection; a hang or a drop is recorded as such and the
    connection is re-established so the storm can go on and report everything."""

    def __init__(self, core: EnvCore, token: str, label: str):
        self.core, self.token, self.label = core, token, label
        self.bus = connect(core, token, label)
        self.reconnects = 0
        self.max_dt = 0.0

    def _reconnect(self) -> None:
        try:
            self.bus.close()
        except Exception:  # noqa: BLE001
            pass
        self.reconnects += 1
        self.bus = connect(self.core, self.token, self.label)

    def rpc(self, method: str, params) -> tuple[str, int | None, str, float]:
        """-> (kind, code, text, seconds); kind adds hang | closed to classify()'s."""
        t0 = time.monotonic()
        try:
            env, dt = self.bus.rpc_raw(method, params)
        except Hang as e:
            self._reconnect()
            return "hang", None, str(e), time.monotonic() - t0
        except BusError as e:
            self._reconnect()
            return "closed", None, str(e), time.monotonic() - t0
        self.max_dt = max(self.max_dt, dt)
        kind, code, text = classify(env)
        return kind, code, text, dt

    def call(self, name: str, args) -> tuple[str, int | None, str, float]:
        return self.rpc("tools/call", {"name": name, "arguments": args})

    def raw(self, line: str, want_id=None) -> tuple[dict | None, str, float]:
        """-> (envelope | None, failure, seconds)."""
        t0 = time.monotonic()
        try:
            env, dt = self.bus.raw_line(line, want_id)
            self.max_dt = max(self.max_dt, dt)
            return env, "", dt
        except Hang as e:
            self._reconnect()
            return None, f"hang: {e}", time.monotonic() - t0
        except BusError as e:
            self._reconnect()
            return None, f"closed: {e}", time.monotonic() - t0


# --- schema-derived values ----------------------------------------------------------


def valid_value(prop: dict):
    """A value satisfying one inputSchema property, recursing into the required
    members of a nested object, so a probe carries exactly ONE defect."""
    t = prop.get("type")
    if t == "string":
        if prop.get("format") == "uuid":
            return str(uuid.uuid4())
        if prop.get("contentEncoding") == "base64":
            return base64.b64encode(b"aitm-e2e").decode()
        return "aitm-e2e"
    if t == "integer":
        return 0
    if t == "number":
        return 0.0
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        props = prop.get("properties")
        if props is None:
            return {}  # a Map<_>: an empty object is valid
        return {k: valid_value(props[k]) for k in prop.get("required", []) if k in props}
    return None  # `{}` = Any: everything is valid, null included


def valid_args(schema: dict) -> dict:
    props = schema.get("properties") or {}
    return {k: valid_value(props[k]) for k in schema.get("required", []) if k in props}


def names_param(text: str, param: str) -> bool:
    return f"`{param}`" in text or f"'{param}'" in text or f'"{param}"' in text


def is_policy_refusal(role: str, kind: str, text: str) -> bool:
    """An agent's Sensitive call is refused by the policy gate BEFORE validation; that
    is structured too, so for the agent role it is an acceptable answer."""
    return role == "agent" and kind == "tool_error" and "refused" in text


def scope_covers(entries, authority: str) -> bool:
    """Whether a scope.list answer provably covers `authority` (exact authority, exact
    host, or a *.wildcard over the host) -- the proxy's own in-scope rule shape."""
    host = authority.rsplit(":", 1)[0]
    for e in entries if isinstance(entries, list) else []:
        e = str(e)
        if e in (authority, host):
            return True
        if e.startswith("*.") and host.endswith(e[1:]):
            return True
    return False


def main() -> int:
    core = EnvCore()
    run = secrets.token_hex(6)
    label = f"aitm-e2e-neg-badparams-{run}"
    role = "operator" if core.operator_token else "agent"
    token = core.operator_token or core.agent_token
    t0_ms = int(time.time() * 1000) - 5000
    pb: Prober | None = None
    fresh: BusClient | None = None
    up: Upstream | None = None
    scope_added: str | None = None
    try:
        # ---------------------------------------------------------------------------
        section(f"attach: the runner's core at {core.bus_addr[0]}:{core.bus_addr[1]}, probing as the {role}")
        pb = Prober(core, token, label)
        init = pb.bus.initialize()
        check(init.get("role") == role, f"the connection's resolved role is {init.get('role')!r} (wanted {role})")
        tools_before = pb.bus.tools()
        by_name = {t["name"]: t for t in tools_before}
        check(len(by_name) > 0, f"tools/list answered with {len(by_name)} tools (the derived contract)")
        bad_schema = [n for n, t in by_name.items() if not isinstance(t.get("inputSchema"), dict)]
        check(not bad_schema, f"every tool publishes an inputSchema object (bad: {bad_schema})")
        no_addl = [n for n, t in by_name.items() if t["inputSchema"].get("additionalProperties") is not False]
        check(not no_addl, f"every tool publishes additionalProperties:false (missing on: {no_addl[:5]})")

        policy = None
        if "agent.status" in by_name:
            st, res = pb.bus.try_call("agent.status", {})
            policy = (res or {}).get("policy") if st == "ok" and isinstance(res, dict) else None
        if role == "agent":
            if policy == "paused":
                skip("agent-only probing under the `paused` policy: every agent call is refused "
                     f"before validation; provide {ENV_OP_TOKEN}")
            if policy == "ask":
                skip("agent-only probing under the `ask` policy: a Sensitive agent call may be PARKED "
                     f"for operator approval (up to the approval timeout), indistinguishable from a "
                     f"hang here; provide {ENV_OP_TOKEN}")
            note(f"no {ENV_OP_TOKEN}: Sensitive tools are refused by policy ({policy!r}) before "
                 f"validation -- accepted as structured; validation is asserted on the rest")
        ok(f"agent policy {policy!r}; probe label {label}")
        pick = "flow.get" if "flow.get" in by_name else next(
            (n for n, t in sorted(by_name.items()) if t["inputSchema"].get("required")), None)
        check(pick is not None, f"a live tool with a required param to aim the shape probes at ({pick})")

        # ---------------------------------------------------------------------------
        section("A. protocol-level junk -> the JSON-RPC error envelope, promptly, no drop")
        proto = [
            ("tools/call without a tool `name`", "tools/call", {"arguments": {}}, INVALID_PARAMS, "name"),
            ("tools/call with a non-string `name`", "tools/call", {"name": 42, "arguments": {}}, INVALID_PARAMS, "name"),
            ("tools/call whose params are not an object", "tools/call", 5, INVALID_PARAMS, "name"),
            ("`arguments` as an array", "tools/call", {"name": pick, "arguments": []}, INVALID_PARAMS, "arguments"),
            ("`arguments` as a string", "tools/call", {"name": pick, "arguments": "id=1"}, INVALID_PARAMS, "arguments"),
            (f"`arguments` null on {pick} (has required params)", "tools/call",
             {"name": pick, "arguments": None}, INVALID_PARAMS, "missing required param"),
            ("an unknown tool", "tools/call", {"name": f"no.such.tool_{run}", "arguments": {}}, INVALID_PARAMS, "unknown tool"),
            ("an unknown method", f"tools/frobnicate_{run}", {}, METHOD_NOT_FOUND, "unknown method"),
        ]
        for what, method, params, want_code, want_text in proto:
            kind, code, text, dt = pb.rpc(method, params)
            good = kind == "rpc_error" and code == want_code and want_text in text and dt < HANG_S
            if role == "agent" and not good:
                good = is_policy_refusal(role, kind, text)  # only `arguments: null` can reach the gate
            expect(good, f"{what}: {kind} {code} {text[:70]!r} in {dt * 1000:.0f}ms (want {want_code} mentioning {want_text!r})")

        # Malformed wire lines: a parse error (id null), a non-object request (id null),
        # a request with no method (its own id). Each must be ANSWERED, connection kept.
        for what, line, want_id, want_code in [
            ("a malformed JSON line", '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {', None, PARSE_ERROR),
            ("a request that is not an object", "[1, 2, 3]", None, INVALID_REQUEST),
            ("a request with no method", '{"jsonrpc": "2.0", "id": 424242}', 424242, INVALID_REQUEST),
        ]:
            env, failure, dt = pb.raw(line, want_id)
            if env is None:
                expect(False, f"{what}: no structured reply ({failure[:80]})")
                continue
            err = env.get("error") or {}
            expect(err.get("code") == want_code and "result" not in env and dt < HANG_S,
                   f"{what}: error {err.get('code')} {str(err.get('message'))[:60]!r} in {dt * 1000:.0f}ms (want {want_code})")
        kind, _, _, dt = pb.rpc("ping", {})
        expect(kind == "ok" and pb.reconnects == 0,
               f"the SAME connection answers ping after the junk ({kind}, {dt * 1000:.0f}ms, {pb.reconnects} reconnects)")

        # ---------------------------------------------------------------------------
        section("B. derived from the live inputSchema: every tool, every param, one defect at a time")
        counts = {"missing": 0, "unknown": 0, "type": 0, "format": 0}
        # a violation is (where, kind, line): where = "<tool> {}" | "<tool> +<key>" | "<tool>.<param>:<type>"
        viol: dict[str, list[tuple[str, str, str]]] = {"missing": [], "unknown": [], "type": [], "format": []}
        drops: list[str] = []
        sent_bad: set[str] = set()

        def judge(cat: str, name: str, where: str, args, kind, code, text, dt, want_params) -> None:
            sent_bad.add(name)
            if kind in ("hang", "closed"):
                drops.append(f"{where}: {kind} after {dt:.1f}s")
                viol[cat].append((where, kind, f"{where} -> {kind}"))
                return
            if cat == "missing":
                good = (kind == "rpc_error" and code == INVALID_PARAMS and "missing required param" in text)
            elif cat == "unknown":
                good = (kind == "rpc_error" and code == INVALID_PARAMS and "unknown param" in text and BOGUS_KEY in text)
            else:
                good = kind in ("rpc_error", "tool_error") and (code in (None, INVALID_PARAMS)) \
                    and any(names_param(text, p) for p in want_params)
            if cat != "unknown" and not good and kind == "tool_error" and any(names_param(text, p) for p in want_params):
                good = True  # a server-handled verb's own structured refusal naming the param
            if not good and is_policy_refusal(role, kind, text):
                good = True
            if not good:
                viol[cat].append((where, kind, f"{where} <- {json.dumps(args)[:60]} -> {kind} {code} {text[:80]!r}"))

        for name in sorted(by_name):
            schema = by_name[name]["inputSchema"]
            props: dict = schema.get("properties") or {}
            required = [r for r in (schema.get("required") or []) if r in props]
            base = valid_args(schema)
            if required:
                counts["missing"] += 1
                k, c, t, dt = pb.call(name, {})
                judge("missing", name, f"{name} {{}}", {}, k, c, t, dt, required)
            counts["unknown"] += 1
            args = dict(base, **{BOGUS_KEY: True})
            k, c, t, dt = pb.call(name, args)
            judge("unknown", name, f"{name} +{BOGUS_KEY}", args, k, c, t, dt, [BOGUS_KEY])
            for pname, prop in props.items():
                ptype = prop.get("type")
                if ptype not in WRONG:
                    continue  # `{}` = Any accepts everything by contract
                counts["type"] += 1
                args = dict(base, **{pname: WRONG[ptype]})
                k, c, t, dt = pb.call(name, args)
                judge("type", name, f"{name}.{pname}:{ptype}", args, k, c, t, dt, [pname])
                bad_fmt = None
                if prop.get("format") == "uuid":
                    bad_fmt = ("uuid", "not-a-flow-id")
                elif prop.get("contentEncoding") == "base64":
                    bad_fmt = ("base64", "%%% not base64 %%%")
                if bad_fmt:
                    counts["format"] += 1
                    args = dict(base, **{pname: bad_fmt[1]})
                    k, c, t, dt = pb.call(name, args)
                    judge("format", name, f"{name}.{pname}:{bad_fmt[0]}", args, k, c, t, dt, [pname])

        total = sum(counts.values())
        ok(f"sent {total} schema-derived bad calls across {len(by_name)} tools "
           f"(missing {counts['missing']}, unknown-key {counts['unknown']}, wrong-type {counts['type']}, "
           f"wrong-format {counts['format']}); slowest answer {pb.max_dt * 1000:.0f}ms")
        expect(not drops, f"no bad call hung or dropped the connection ({len(drops)} did)", drops[:4])
        expect(pb.max_dt < HANG_S, f"every answered bad call came back within {HANG_S:.0f}s (max {pb.max_dt * 1000:.0f}ms)")
        all_viol = [v for vs in viol.values() for v in vs]
        for _, _, line in all_viol:
            print(f"      violation: {line}", flush=True)

        def is_sh(where: str) -> bool:
            return any(where.startswith(s + " ") or where.startswith(s + ".") for s in SERVER_HANDLED)

        # Registry tools go through the one shared validator: judged per defect class.
        reg = {cat: [v for v in vs if not is_sh(v[0])] for cat, vs in viol.items()}
        expect(not reg["missing"], f"registry tools: missing required param -> -32602 `missing required param` ({len(reg['missing'])} violation(s))")
        expect(not reg["unknown"], f"registry tools: an undeclared key -> -32602 `unknown param` naming it, before anything runs ({len(reg['unknown'])} violation(s))")
        expect(not reg["type"], f"registry tools: a wrong-typed value -> -32602 naming the param ({len(reg['type'])} violation(s))")
        expect(not reg["format"], f"registry tools: a non-uuid flow id / non-base64 bytes -> -32602 naming the param ({len(reg['format'])} violation(s))")
        # The server-handled verbs are held to the same published contract, each defect
        # counted ONCE, by severity: a silent `ok` (the caller believes its invalid call
        # took effect) vs. a structured error that is not the validator's (the undeclared
        # key was ignored and the verb ran anyway).
        sh_live = sorted(SERVER_HANDLED & set(by_name))
        if sh_live:
            sh_silent = [v[2] for v in all_viol if is_sh(v[0]) and v[1] == "ok"]
            sh_ran = [v[2] for v in all_viol if is_sh(v[0]) and v[1] != "ok"]
            where_fixed = " -- server.rs run_tool answers them before params_from_json"
            expect(not sh_silent, f"server-handled verbs {sh_live}: no invalid call is silently accepted as `ok` "
                                  f"({len(sh_silent)} were{where_fixed if sh_silent else ''})", sh_silent[:5])
            expect(not sh_ran, f"server-handled verbs {sh_live}: an undeclared key is refused before the verb runs, as their "
                               f"published additionalProperties:false says ({len(sh_ran)} ran instead{where_fixed if sh_ran else ''})", sh_ran[:5])

        # ---------------------------------------------------------------------------
        section("C. liveness: the storm left the core answering, unchanged, and forwarding real traffic")
        kind, _, text, dt = pb.rpc("ping", {})
        expect(kind == "ok" and dt < HANG_S, f"the SAME connection still answers ping after the storm ({kind}, {dt * 1000:.0f}ms)")
        tools_after = pb.bus.tools()
        expect(tools_after == tools_before, f"tools/list is byte-identical after the storm ({len(tools_after)} tools)")
        st, status = pb.bus.try_call("proxy.status", {})
        if st == "ok":
            expect(isinstance(status, dict) and status.get("listening") is True,
                   f"proxy.status on the same connection: the data plane is listening ({json.dumps(status)[:100]})")
        else:
            note(f"proxy.status not readable as the {role} ({str(status)[:70]}); liveness shown by ping + tools/list")
        fresh = BusClient(core.bus_addr[0], core.bus_addr[1], core.agent_token,
                          client_name=f"{label}-fresh").connect()
        expect(len(fresh.tools()) == len(tools_before), "a FRESH connection initializes and lists the same tools")

        tag = f"e2e-neg-{run}"
        real_flow_id = None
        if core.proxy_addr is None:
            note(f"{ENV_PROXY_ADDR} unset: forwarding through the proxy not asserted")
        else:
            proxy_port = core.proxy_addr[1]
            scope_now = pb.bus.call("scope.list") if "scope.list" in by_name else []
            capture_url = None
            if core.target_url:
                url = f"{core.target_url}/?probe={tag}"
                resp = via_proxy(proxy_port, "GET", url)
                expect(resp.status == 200, f"a real GET through the proxy to the seeded testtarget is answered 200 after the storm (got {resp.status})")
                authority = url.split("//", 1)[1].split("/", 1)[0]
                if scope_covers(scope_now, authority):
                    capture_url = url
                else:
                    note(f"{authority} is not provably in scope ({scope_now}); capture in flow.table not asserted")
            else:
                try:
                    up = Upstream().start()
                except (PermissionError, OSError) as e:
                    up = None
                    note(f"no {ENV_TARGET_URL} and this process may not bind an observer ({e}); forwarding asserted as 'the proxy answers'")
                if up is not None:
                    k, _, t, _ = pb.call("scope.add", {"host": up.authority})
                    scope_added = up.authority if k == "ok" else None
                    url = f"{up.base}/echo?probe={tag}"
                    resp = via_proxy(proxy_port, "GET", url)
                    hits = [r for r in up.received if tag in r["path"]]
                    # The origin's OWN record is the proof of forwarding, whatever the scope.
                    expect(resp.status == 200 and len(hits) == 1,
                           f"the independent echo-record upstream RECORDED the post-storm GET (status {resp.status}, {len(hits)} hit): the proxy still forwards")
                    if scope_added or scope_covers(scope_now, up.authority):
                        capture_url = url
                    else:
                        note(f"could not widen scope to the observer ({t[:60]!r}) and it is not provably in scope; "
                             f"capture in flow.table not asserted")
                else:
                    try:
                        resp = via_proxy(proxy_port, "GET", f"http://aitm-e2e-neg.invalid/?probe={tag}")
                        expect(resp.status > 0, f"the proxy still answers a real client after the storm (status {resp.status})")
                    except OSError as e:
                        expect(False, f"the proxy did not answer a real client after the storm: {e}")
            if capture_url and "flow.table" in by_name:
                found = None
                deadline = time.time() + 5
                while time.time() < deadline and found is None:
                    rows = (pb.bus.call("flow.table") or {}).get("flows") or []
                    found = next((r for r in rows if tag in json.dumps(r)), None)
                    if found is None:
                        time.sleep(0.2)
                expect(found is not None, f"flow.table shows the post-storm request captured, carrying marker {tag}")
                if isinstance(found, dict):
                    real_flow_id = found.get("id")

        # ---------------------------------------------------------------------------
        section("D. well-formed but wrong -> the command RUNS and answers isError with its own reason")
        ghost = str(uuid.uuid4())

        def semantic(name: str, args: dict, what: str, want: str = "") -> None:
            if name not in by_name:
                return
            if role == "operator" and by_name[name].get("confirmable"):
                note(f"{name} is confirmable (an operator handshake precedes the run); not probed semantically")
                return
            kind, code, text, dt = pb.call(name, args)
            want_ok = (want in text) if (want and role == "operator") else True
            expect(kind == "tool_error" and want_ok and dt < HANG_S,
                   f"{what} -> {kind} {text[:72]!r} in {dt * 1000:.0f}ms (want isError{' mentioning ' + repr(want) if want else ''})")

        semantic("flow.get", {"id": ghost}, "flow.get on a flow id nobody has", "no flow")
        semantic("flow.detail", {"id": ghost, "body": "inline"}, "flow.detail on a flow id nobody has", "no flow")
        semantic("flow.replay", {"id": ghost}, "flow.replay on a flow id nobody has", "no flow")
        if real_flow_id:
            semantic("flow.detail", {"id": real_flow_id, "body": "bogus-mode"},
                     "flow.detail with a body mode that does not exist, on a REAL captured flow", "none|inline|range")
        else:
            note("no captured flow id of our own: the body-mode probe needs a real flow and was not run")
        semantic("agent.approve", {"request_id": f"e2e-ghost-{run}", "allow": False},
                 "agent.approve on a request nobody parked", "no parked request")
        junk_entries = ["", "not a host!!", "bad/host"]
        for entry in junk_entries:
            semantic("scope.add", {"host": entry}, f"scope.add {entry!r}", "is not a host")

        # ---------------------------------------------------------------------------
        section("E. nothing ran: scope has no junk, and the audit ring has no entry for a storm-only tool under our label")
        if "scope.list" in by_name:
            scope_after = pb.bus.call("scope.list")
            leaked = [e for e in junk_entries if e in (scope_after if isinstance(scope_after, list) else [])]
            expect(not leaked, f"none of the rejected scope entries reached scope.list ({len(scope_after) if isinstance(scope_after, list) else '?'} entries)", leaked)
        if "agent.activity" in by_name:
            try:
                entries = pb.bus.call("agent.activity", {"since": t0_ms})
            except ToolError as e:
                entries = None
                note(f"agent.activity not readable here ({str(e)[:80]}); audit leg not run")
            if entries is not None:
                check(isinstance(entries, list), f"agent.activity answers a list ({type(entries).__name__})")
                ours = [e for e in entries if isinstance(e, dict) and e.get("client_label") == label]
                intentional = {"scope.list", "agent.status", "flow.table", "proxy.status", "agent.activity",
                               "scope.add", "scope.remove", "flow.get", "flow.detail", "flow.replay"}
                storm_only = (sent_bad - intentional) - SERVER_HANDLED

                def is_refusal(e: dict) -> bool:
                    r = e.get("result")
                    return isinstance(r, dict) and "refused" in str(r.get("error", ""))

                ran = [e for e in ours if e.get("command") in storm_only and not (role == "agent" and is_refusal(e))]
                expect(any(e.get("command") in intentional for e in ours),
                       f"the ring is live: our own intentional calls are audited under {label} ({len(ours)} entries)")
                expect(not ran, f"no tool that only ever received bad params was audited as run/refused under our label "
                                f"({len(storm_only)} such tools; {len(ran)} entries say otherwise)",
                       [(e.get("command"), e.get("result")) for e in ran[:4]])
    finally:
        if scope_added and pb is not None:
            try:
                pb.bus.call("scope.remove", {"host": scope_added})
            except Exception:  # noqa: BLE001
                pass
        for b in (fresh, pb.bus if pb else None):
            if b:
                b.close()
        if up is not None:
            up.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + " | ".join(f[:110] for f in _failures[:6]))
    ok("PASS: bad params -> structured error on every live tool; protocol junk -> JSON-RPC envelope; "
       "no hang, no drop, nothing ran, the core still forwards")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except (socket.timeout, TimeoutError) as e:
        fail(f"HANG: the core did not answer within the read timeout ({type(e).__name__}: {e})")
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
