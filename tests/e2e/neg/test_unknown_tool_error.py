#!/usr/bin/env python3
# e2e: tier=T1 surface=neg
"""Negative path: calling an UNKNOWN tool is answered with a proper JSON-RPC
protocol error -- promptly, on the same connection, with no side effect -- never
a hang, a dropped connection, a tool-result masquerade, or an internal error.

Everything is asserted on ground truth from the live core, never a fixture:

  DERIVE   the "unknown" names are proven unknown against the LIVE `tools/list`
           of the very core under test (a random name, near-misses of a real
           tool, case/whitespace/unicode variants, empty, 64 KiB, NUL, shell and
           traversal junk, JSON-RPC method names used as tool names, typos of the
           server-handled verbs) -- a name the core actually registers is dropped
           from the battery, so the expectation can never be stale.
  ERROR    every `tools/call` with such a name is answered by a JSON-RPC ERROR
           envelope -- `jsonrpc: "2.0"`, the request's own `id`, an `error` object
           and NO `result` -- whose code is the MCP "unknown tool" protocol code
           (-32602 Invalid params; -32601 Method not found is also accepted) and
           whose message names the rejected tool verbatim. Not `isError: true`
           (that is a tool result for a tool that RAN), not -32603 internal.
  METHOD   the literal method-not-found case: an unknown JSON-RPC METHOD (not a
           tool) is -32601 and names the method; the two cases stay distinct.
  SHAPE    a `tools/call` with no `name`, a non-string `name`, or non-object
           `arguments` is the same -32602 envelope -- the command never ran.
  NO HANG  each reply arrives within HANG_BUDGET seconds (a read timeout IS the
           hang verdict, exit 1); 32 unknown calls PIPELINED back-to-back on one
           connection each get their own id-matched error naming their own tool
           (no head-of-line stall, no cross-wired replies).
  ALIVE    the SAME connection then answers `ping`, an unchanged `tools/list` (the
           junk registered nothing) and `proxy.status` listening=true; a fresh
           connection can still initialize; a dedicated core's process is alive
           with no panic in its stderr.
  ROLES    agent and operator receive the identical code + message (an unknown
           tool is rejected before any policy gate; it is not a refusal).
  AUDIT    a protocol-level failure is not a command invocation: `agent.activity`
           holds no entry for any unknown name under this test's client label,
           and every entry it does hold for us names a REAL live tool.

Core: the one the runner provides through the environment (`AITM_BUS_ADDR`,
`AITM_BUS_TOKEN` = agent token, optional `AITM_BUS_OPERATOR_TOKEN`); nothing is
booted in that case. Without `AITM_BUS_ADDR` a dedicated core is booted on free
ports (so the suite is runnable standalone) and stopped again. Touches no global
state: only reads, protocol errors, and a per-run client label.
"""

from __future__ import annotations

import os
import secrets
import socket
import sys
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

# JSON-RPC 2.0 / MCP protocol-error codes (crates/aitm-mcp/src/server.rs).
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# MCP 2025-06-18 "Tool errors": an unknown tool in tools/call is a protocol error
# with -32602 (the spec's own example); -32601 is the JSON-RPC method-not-found
# family and is accepted too. Anything else (internal, parse, invalid request,
# or a tool result) is wrong.
UNKNOWN_TOOL_CODES = (INVALID_PARAMS, METHOD_NOT_FOUND)
HANG_BUDGET = 5.0  # seconds per reply; a read timeout here is the hang verdict
PIPELINE_N = 32
MAX_MESSAGE_BYTES = 16 * 1024 * 1024  # transport line cap; probes stay far below it


# ---------------------------------------------------------------------------
# a soft-assertion battery: every failed expectation is printed, the run goes on
# (and cleans up), exit code 1 iff anything failed. Preconditions use check().

_failures: list[str] = []


def expect(cond: object, msg: str, detail: object = "") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:600]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def show(s: str, n: int = 48) -> str:
    """A printable, length-capped rendering of a probe name for log lines."""
    r = repr(s)
    return r if len(r) <= n else f"{r[: n - 12]}...({len(s)} chars)"


class Hang(RuntimeError):
    """No id-matched reply within HANG_BUDGET: the very failure this test exists for."""


# ---------------------------------------------------------------------------
# the shared BusClient, extended with RAW envelope access: BusClient.rpc() hides
# the envelope (it raises on `error`), and this test asserts on the envelope.


class RawBus(BusClient):
    def rpc_raw(self, method: str, params, timeout: float = HANG_BUDGET) -> tuple[dict, float, int]:
        """Send one request; return (the full id-matched reply envelope, seconds, the id).
        Raises Hang on a read timeout, BusError if the core closes the connection."""
        self._id += 1
        mid = self._id
        self._set_read_timeout(timeout)
        t0 = time.monotonic()
        try:
            self._send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
            while True:
                msg = self._recv()
                if msg.get("id") == mid:
                    return msg, time.monotonic() - t0, mid
                self.notifications.append(msg)  # a server push; not ours to judge here
        except (socket.timeout, TimeoutError) as e:
            raise Hang(f"{method}: no id-matched reply within {timeout:.1f}s "
                       f"(elapsed {time.monotonic() - t0:.1f}s)") from e
        finally:
            self._restore_read_timeout()

    def pipelined_calls(self, names: list[str], timeout: float = HANG_BUDGET) -> tuple[dict, dict, float]:
        """Fire tools/call for every name WITHOUT waiting, then collect every
        id-matched reply. Returns (id -> name, id -> envelope, seconds)."""
        ids: dict[int, str] = {}
        for name in names:
            self._id += 1
            ids[self._id] = name
        t0 = time.monotonic()
        for mid, name in ids.items():
            self._send({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                        "params": {"name": name, "arguments": {}}})
        got: dict[int, dict] = {}
        deadline = t0 + timeout
        try:
            while len(got) < len(ids):
                self._set_read_timeout(max(0.1, deadline - time.monotonic()))
                msg = self._recv()
                if msg.get("id") in ids:
                    got[msg["id"]] = msg
                else:
                    self.notifications.append(msg)
        except (socket.timeout, TimeoutError) as e:
            raise Hang(f"pipelined tools/call: {len(got)}/{len(ids)} replies within {timeout:.1f}s") from e
        finally:
            self._restore_read_timeout()
        return ids, got, time.monotonic() - t0


# ---------------------------------------------------------------------------
# the core: the runner's (via env) or, failing that, a dedicated one


class EnvCore:
    """The runner's core, shaped like `aitm_e2e.core.Aitm` for RawBus/BusClient.
    Boots nothing; stop() is a no-op (it is not ours to stop)."""

    owned = False

    def __init__(self, addr: str, agent_token: str, operator_token: str | None):
        host, sep, port = addr.strip().rpartition(":")
        if not sep or not port.isdigit():
            fail(f"AITM_BUS_ADDR must be host:port, got {addr!r}")
        self.bus_addr = (host.strip("[]") or "127.0.0.1", int(port))
        self.cfg = types.SimpleNamespace(agent_token=agent_token, operator_token=operator_token)

    def stop(self) -> None:
        pass


def acquire_core():
    addr = os.environ.get("AITM_BUS_ADDR")
    if addr:
        agent_token = os.environ.get("AITM_BUS_TOKEN")
        if not agent_token:
            fail("AITM_BUS_ADDR is set but AITM_BUS_TOKEN (the agent token) is not")
        core = EnvCore(addr, agent_token, os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None)
        return core, f"runner-provided core at {addr} (nothing booted)"
    cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port())
    core = Aitm.server(cfg)
    core.owned = True  # type: ignore[attr-defined]
    return core, f"dedicated core (no AITM_BUS_ADDR in env): bus {core.bus_addr}, proxy 127.0.0.1:{cfg.proxy_port}"


def connect(core, token: str, label: str) -> RawBus:
    host, port = core.bus_addr
    return RawBus(host, port, token, client_name=label).connect()


# ---------------------------------------------------------------------------
# the battery of names that must be unknown (each proven absent from the live list)


def unknown_name_battery(real: str, run: str) -> list[tuple[str, str]]:
    half = max(1, len(real) // 2)
    return [
        ("random", f"e2e.unknown_{run}"),
        ("near-miss: suffix", real + "x"),
        ("near-miss: prefix", "x" + real),
        ("near-miss: dropped char", real[:-1]),
        ("case-folded", real.upper()),
        ("whitespace-padded", f" {real} "),
        ("trailing newline", real + "\n"),
        ("embedded NUL", real + "\x00"),
        ("zero-width space", real[:half] + "\u200b" + real[half:]),
        ("cyrillic homoglyph", real.replace("o", "\u043e", 1) if "o" in real else real + "\u043e"),
        ("empty", ""),
        ("rpc method as tool", "tools/list"),
        ("rpc method as tool", "initialize"),
        ("rpc method as tool", "notifications/initialized"),
        ("server-handled verb typo", "flow.subscribe_"),
        ("server-handled verb typo", "flow.unsubscribed"),
        ("server-handled verb typo", "agent.approve."),
        ("reserved confirm key", "_confirm"),
        ("path traversal", "../" + real),
        ("shell metachars", real + "; id"),
        ("json-shaped", '{"name":"' + real + '"}'),
        ("64-deep dotted", ".".join(["x"] * 64)),
        ("4 KiB", "a" * 4096),
        ("64 KiB", "n" * 65536),
    ]


def judge_unknown_tool(label: str, name: str, resp: dict, elapsed: float, want_id) -> None:
    """The one assertion set for 'an unknown tool `name` was answered by `resp`'."""
    tag = f"{label} {show(name)}"
    err = resp.get("error")
    if not expect(isinstance(err, dict) and "result" not in resp,
                  f"{tag}: a JSON-RPC ERROR envelope, no `result` ({elapsed * 1000:.0f} ms)",
                  str(resp)[:300]):
        return
    expect(resp.get("jsonrpc") == "2.0" and resp.get("id") == want_id,
           f"{tag}: jsonrpc 2.0 with the request's id", (resp.get("jsonrpc"), resp.get("id")))
    code, message = err.get("code"), err.get("message")
    expect(isinstance(code, int) and code in UNKNOWN_TOOL_CODES,
           f"{tag}: code {code} is an unknown-tool protocol code {UNKNOWN_TOOL_CODES}", err)
    expect(code != INTERNAL_ERROR, f"{tag}: not an internal error", err)
    expect(isinstance(message, str) and bool(message.strip()), f"{tag}: non-empty message", err)
    if isinstance(message, str):
        low = message.lower()
        expect(any(w in low for w in ("unknown", "not found", "no such")),
               f"{tag}: the message says the tool is unknown", message[:160])
        expect(name in message, f"{tag}: the message names the rejected tool verbatim",
               f"{len(message)}-char message: {message[:120]!r}")
    expect(elapsed < HANG_BUDGET, f"{tag}: answered in {elapsed:.3f}s < {HANG_BUDGET}s", elapsed)


# ---------------------------------------------------------------------------


def main() -> int:
    core, how = acquire_core()
    run = secrets.token_hex(6)
    ag_label = f"aitm-e2e-neg-unknown-agent-{run}"
    op_label = f"aitm-e2e-neg-unknown-operator-{run}"
    ag = op = probe = None
    sent_unknown: list[str] = []
    try:
        section(f"arrange: {how}")
        t0_ms = int(time.time() * 1000) - 5000
        ag = connect(core, core.cfg.agent_token, ag_label)
        tools_before = ag.tool_names()
        live = set(tools_before)
        check(len(live) > 0, f"the live core registers {len(live)} tools (tools/list)")
        real = "flow.list" if "flow.list" in live else sorted(live)[0]
        ok(f"deriving near-misses from the REAL live tool {real!r}")

        # ---------------------------------------------------------------
        section("derive: every probe name is proven ABSENT from the live tools/list")
        battery = []
        for label, name in unknown_name_battery(real, run):
            if name in live:
                ok(f"{label} {show(name)} is a REAL tool on this core; dropped from the battery")
                continue
            battery.append((label, name))
        check(len(battery) >= 12, f"{len(battery)} probe names, none registered live")
        for _, name in battery:
            check(len(name.encode("utf-8")) + 128 < MAX_MESSAGE_BYTES,
                  f"probe {show(name)} is far below the {MAX_MESSAGE_BYTES}-byte line cap (a reply is owed)")

        # ---------------------------------------------------------------
        section(f"act: tools/call each unknown name as the AGENT; a reply is owed within {HANG_BUDGET}s")
        slowest = 0.0
        for label, name in battery:
            try:
                resp, dt, mid = ag.rpc_raw("tools/call", {"name": name, "arguments": {}})
            except Hang as e:
                fail(f"HANG: unknown tool {label} {show(name)}: {e}")
            except BusError as e:
                fail(f"the core DROPPED the connection on unknown tool {label} {show(name)}: {e}")
            sent_unknown.append(name)
            slowest = max(slowest, dt)
            judge_unknown_tool(label, name, resp, dt, mid)
        ok(f"{len(battery)} unknown-tool calls answered; slowest reply {slowest * 1000:.0f} ms")

        # ---------------------------------------------------------------
        section("method: an unknown JSON-RPC METHOD is -32601 Method not found (distinct from unknown tool)")
        for method in (f"e2e/unknown_{run}", "tools/cal", "tools/call ", "tools/call/extra", "TOOLS/CALL"):
            try:
                resp, dt, mid = ag.rpc_raw(method, {"name": real, "arguments": {}})
            except Hang as e:
                fail(f"HANG: unknown method {method!r}: {e}")
            err = resp.get("error") or {}
            expect(isinstance(err, dict) and "result" not in resp and err.get("code") == METHOD_NOT_FOUND,
                   f"method {method!r}: -32601 error envelope ({dt * 1000:.0f} ms)", str(resp)[:300])
            expect(method in str(err.get("message", "")), f"method {method!r}: the message names the method", err)
            expect(resp.get("id") == mid, f"method {method!r}: id matches", resp.get("id"))

        # ---------------------------------------------------------------
        section("shape: tools/call without a usable `name` / with non-object `arguments` is -32602, nothing ran")
        shapes = [
            ("no name", {"arguments": {}}),
            ("null name", {"name": None, "arguments": {}}),
            ("numeric name", {"name": 42, "arguments": {}}),
            ("array name", {"name": [real], "arguments": {}}),
            ("array arguments", {"name": real, "arguments": []}),
            ("string arguments", {"name": real, "arguments": "x"}),
            ("numeric arguments", {"name": real, "arguments": 7}),
            ("params is an array", [real]),
            ("params is a string", real),
        ]
        for label, params in shapes:
            try:
                resp, dt, _ = ag.rpc_raw("tools/call", params)
            except Hang as e:
                fail(f"HANG: malformed tools/call ({label}): {e}")
            except BusError as e:
                fail(f"the core DROPPED the connection on malformed tools/call ({label}): {e}")
            err = resp.get("error") or {}
            expect(isinstance(err, dict) and "result" not in resp and err.get("code") == INVALID_PARAMS,
                   f"{label}: -32602 Invalid params envelope ({dt * 1000:.0f} ms)", str(resp)[:300])
            expect(isinstance(err.get("message"), str) and err.get("message"), f"{label}: non-empty message", err)

        # ---------------------------------------------------------------
        section(f"pipeline: {PIPELINE_N} unknown calls back-to-back on ONE connection, each gets ITS OWN error")
        names = [f"e2e.pipe_{run}_{i:02d}" for i in range(PIPELINE_N)]
        check(not (set(names) & live), "the pipelined names are not registered live")
        try:
            ids, got, dt = ag.pipelined_calls(names)
        except Hang as e:
            fail(f"HANG: {e}")
        sent_unknown.extend(names)
        expect(set(got) == set(ids), f"all {PIPELINE_N} replies arrived, ids match exactly ({dt * 1000:.0f} ms total)",
               sorted(set(ids) - set(got)))
        wired = 0
        for mid, resp in got.items():
            err = resp.get("error") or {}
            if (isinstance(err, dict) and "result" not in resp and err.get("code") in UNKNOWN_TOOL_CODES
                    and ids[mid] in str(err.get("message", ""))):
                wired += 1
        expect(wired == len(ids), f"every reply is an unknown-tool error naming ITS request's tool ({wired}/{len(ids)})")
        expect(dt < HANG_BUDGET, f"the whole pipeline answered in {dt:.3f}s < {HANG_BUDGET}s", dt)

        # ---------------------------------------------------------------
        section("alive: the SAME connection still works and nothing was registered or taken down")
        resp, dt, _ = ag.rpc_raw("ping", {})
        expect(resp.get("result") == {} and "error" not in resp, f"ping on the same connection -> {{}} ({dt * 1000:.0f} ms)", resp)
        tools_after = ag.tool_names()
        expect(tools_after == tools_before,
               f"tools/list is unchanged after {len(sent_unknown)} unknown calls ({len(tools_after)} tools)",
               (sorted(set(tools_after) ^ set(tools_before))))
        expect(not (set(sent_unknown) & set(tools_after)), "no probe name became a registered tool")
        st, status = ag.try_call("proxy.status", {})
        if st == "ok":
            expect(isinstance(status, dict) and status.get("listening") is True,
                   f"proxy.status (same connection): the data plane is listening ({status})")
        else:
            ok(f"proxy.status not readable as the agent here ({str(status)[:80]}); liveness shown by ping + tools/list")
        probe = connect(core, core.cfg.agent_token, f"aitm-e2e-neg-unknown-fresh-{run}")
        expect(probe.tool_names() == tools_before, "a FRESH connection initializes and lists the same tools")
        probe.close()
        probe = None
        if getattr(core, "owned", False):
            alive = core.proc is not None and core.proc.poll() is None
            expect(alive, "the dedicated core process is still running", core.proc.poll() if core.proc else None)
            err_log = core.stderr_text()
            expect("panicked at" not in err_log and "thread '" not in err_log,
                   "no panic in the core's stderr", err_log[-400:])

        # ---------------------------------------------------------------
        section("roles: the OPERATOR gets the identical code + message (rejected before any policy gate)")
        name = f"e2e.unknown_{run}"
        ag_resp, _, _ = ag.rpc_raw("tools/call", {"name": name, "arguments": {}})
        if core.cfg.operator_token:
            op = connect(core, core.cfg.operator_token, op_label)
            try:
                op_resp, dt, mid = op.rpc_raw("tools/call", {"name": name, "arguments": {}})
            except Hang as e:
                fail(f"HANG (operator): {e}")
            judge_unknown_tool("operator", name, op_resp, dt, mid)
            expect(op_resp.get("error") == ag_resp.get("error"),
                   "operator error == agent error (code and message)", (op_resp.get("error"), ag_resp.get("error")))
            init_role = op.initialize().get("role")
            expect(init_role == "operator", f"the operator connection really is the operator role ({init_role!r})")
        else:
            ok("no AITM_BUS_OPERATOR_TOKEN from the runner: operator leg not run")

        # ---------------------------------------------------------------
        section("audit: a protocol-level failure is NOT a command invocation (agent.activity)")
        reader = op or ag
        try:
            entries = reader.call("agent.activity", {"since": t0_ms})
        except ToolError as e:
            entries = None
            ok(f"agent.activity not readable here ({str(e)[:100]}); audit leg not run")
        if entries is not None:
            check(isinstance(entries, list), f"agent.activity answers a list ({type(entries).__name__})")
            ours = [e for e in entries if e.get("client_label") in (ag_label, op_label)]
            junk = [e for e in ours if e.get("command") in set(sent_unknown + [name])]
            expect(not junk, f"no audit entry for any of the {len(set(sent_unknown))} unknown names", junk[:3])
            unreal = [e.get("command") for e in ours if e.get("command") not in live]
            expect(not unreal, f"every audited command under our labels is a REAL live tool ({len(ours)} entries)", unreal)
            expect(any(e.get("client_label") == ag_label for e in ours),
                   "the sweep saw our own label (the real reads we made were audited, so the ring is live)",
                   sorted({e.get("client_label") for e in entries})[:5])

    finally:
        for b in (probe, op, ag):
            if b:
                b.close()
        core.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: unknown tool -> prompt JSON-RPC protocol error; distinct from unknown method; "
       "no hang, no drop, no registration, no audit entry; both roles agree")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except (socket.timeout, TimeoutError) as e:
        # A read timeout anywhere (connect/initialize included) IS the hang this
        # test exists to catch: the core accepted the connection and never answered.
        fail(f"HANG: the core did not answer within the read timeout ({type(e).__name__}: {e})")
    except Exception as e:  # noqa: BLE001 -- surface boot/bus failures as a FAIL with context
        fail(f"{type(e).__name__}: {e}")
