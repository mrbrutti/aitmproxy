#!/usr/bin/env python3
# e2e: tier=T1 surface=neg
"""neg/test_nonexistent_flow_error -- operating on a flow id that does not exist
returns a CLEAN error, from EVERY id-taking command, and changes NOTHING.

What "clean" means here, asserted on a real core (never fixtures):
  * a well-formed id with no flow behind it is an `isError` TOOL RESULT (the
    command ran and refused), whose text is one line, names the EXACT id, reads
    `no flow with id <id>` (crates/aitm-plugins/src/{capture,detail,replay,meta,
    intercept,mutate}.rs, aitm-plugin-wsctl, aitm-plugin-sessionio, aitm-poc), and
    carries no panic/backtrace/source-location noise;
  * a MALFORMED id (not a UUID, wrong type, missing) never reaches the command:
    the bus rejects it as the JSON-RPC `-32602` INVALID_PARAMS envelope
    (crates/aitm-mcp/src/json.rs `TypeDesc::FlowId`), and -- because the command
    never ran -- the audit ring records nothing for it;
  * the error is deterministic (same id -> byte-identical text, twice), identical
    for the operator and the agent, and the near-miss of a REAL id (one hex digit
    flipped) is a miss: lookup is exact, not prefix/fuzzy;
  * NOTHING happened as a side effect: the ORIGIN (an echo-record upstream this
    test owns, or the seeded aitm-testtarget read directly) received exactly the
    one control request and nothing from `flow.replay` of a missing id; the one
    REAL flow this test captured is byte-identical before/after apart from
    `meta.marks` (no comment, no mutation landed on it); marks get their own checks:
      - the REAL flow's marks may only GROW: every earlier mark survives (the
        bundled passive detectors add marks to a live flow at any moment, so marks
        are checked on their own);
      - BARRAGE_MARK (the barrage's own label) appears on no listed flow in the
        store -- flows captured during a capture pause (and not parked) are not
        listed by flow.table.
    Also: no flow was lost (proxy.status still counts the control flow) and the
    missing ids were not created; proxy.status's `paused` / `capturing` fields are
    NOT asserted equal -- on a shared runner core a concurrent suite may
    legitimately park a flow or pause the proxy;
  * the core and the connection survive a barrage: hostile ids (path traversal,
    SQLi, 10 KB, unicode, non-string types) and a flood of FLOOD_N distinct missing
    ids on ONE connection all answer cleanly, fast, with the socket still open and
    the real flow still readable afterwards;
  * every refused (ran-and-failed) call is in agent.activity with the command, the
    role, and the same error text -- the independent audit observer agrees.

Non-vacuous: the test first pushes a REAL request through the REAL proxy, finds
its flow, and proves flow.get on that id WORKS -- the id shape and the lookup are
live before any "not found" is believed.

Roles (crates/aitm-mcp/src/server.rs policy gate): flow.get/detail are Read,
flow.replay/mark/comment/resume/kill/mutate and poc.build are Write (the agent runs
them under the default `auto`); flow.export and ws.frame/ws.send carry the
fail-closed default Sensitivity::Sensitive, so they are driven as the OPERATOR
(AITM_BUS_OPERATOR_TOKEN) and reported-but-not-failed when no operator token is
given. Under `ask` a Sensitive agent call would PARK, so the agent never sends one.

Runner contract (environment; this test never boots a core of its own):
  AITM_BUS_ADDR            host:port of the loopback MCP bus        (required)
  AITM_BUS_TOKEN           the agent token (never printed)          (required)
  AITM_PROXY_ADDR          host:port of the proxy listener          (required)
  AITM_BUS_OPERATOR_TOKEN  the operator token                       (optional)
  AITM_TARGET_URL          base URL of the seeded aitm-testtarget   (optional;
                           the origin observer when this process may not bind)
Touches no global state; the only write is one captured control flow.
"""

from __future__ import annotations

import copy
import http.client
import json
import os
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

NO_FLOW = "no flow with id"  # the one refusal text every store lookup uses
NOT_VALID = "not a valid flow id"  # json.rs TypeDesc::FlowId coercion failure
INVALID_PARAMS = -32602  # JSON-RPC: the command never ran
NIL_UUID = "00000000-0000-0000-0000-000000000000"
MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
BARRAGE_MARK = "e2e-missing"  # flow.mark's label in the barrage; reserved: the store-wide scan fails on any listed flow carrying it, so no other suite may use it
MAX_ERROR_CHARS = 400  # a clean refusal is short; a dump is not
NOISE = (  # none of this belongs in an error shown to an agent or operator
    "panicked", "RUST_BACKTRACE", "stack backtrace", "unwrap()", "called `Option",
    "called `Result", "thread '", ".rs:", "src/", "/Users/", "Traceback",
)
ROW_WAIT_S = 10.0  # for the control flow to appear in flow.table
SETTLE_S = 0.5  # grace for any hypothetical async leak to land at the origin
FLOOD_N = 100
FLOOD_MAX_RTT_S = 2.0
DEFAULT_WRITE_POLICIES = ("auto", "all", "ask")  # Write runs for the agent
READ_POLICIES = DEFAULT_WRITE_POLICIES + ("readonly",)


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
    """The core the runner already booted, shaped like aitm_e2e.core.Aitm so
    BusClient.agent(core) / BusClient.operator(core) work unchanged."""

    REQUIRED = ("AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_PROXY_ADDR")

    def __init__(self) -> None:
        missing = [k for k in self.REQUIRED if not os.environ.get(k)]
        if missing:
            skip(f"no runner-provided core: {' '.join(missing)} unset (see tests/e2e/README.md)")
        self.bus_addr = _hostport(os.environ["AITM_BUS_ADDR"])
        self.cfg = _Cfg(os.environ["AITM_BUS_TOKEN"], os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None)
        self.proxy_host, self.proxy_port = _hostport(os.environ["AITM_PROXY_ADDR"])
        self.target_url = (os.environ.get("AITM_TARGET_URL") or "").rstrip("/") or None

    @property
    def has_operator(self) -> bool:
        return bool(self.cfg.operator_token)


# --- the origin: the independent observer ---------------------------------------


class OwnUpstream:
    """An echo-record origin THIS test runs: its own record of what arrived."""

    name = "own echo-record upstream"

    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.up = Upstream().start()
        self.path = f"/nonexistent-ctl?e2e={tag}"
        self.url = f"{self.up.base}{self.path}"

    def control(self, core: EnvCore) -> int:
        return via_proxy(core.proxy_port, "GET", self.url).status

    def control_ok(self, status: int) -> bool:
        return status == 200

    def hits(self) -> int:
        return sum(1 for r in self.up.received if self.tag in r["path"])

    def stop(self) -> None:
        self.up.stop()


class TargetComments:
    """The seeded aitm-testtarget's comment board, read DIRECTLY (not via the
    proxy): a replay of our POST would list the marker a second time."""

    name = "aitm-testtarget /comments (read directly)"

    def __init__(self, core: EnvCore, tag: str) -> None:
        assert core.target_url
        self.tag = tag
        self.base = core.target_url
        netloc = urllib.parse.urlparse(self.base).netloc
        self.host, self.port = _hostport(netloc if ":" in netloc else netloc + ":80")
        self.path = f"/comments?e2e={tag}"
        self.url = f"{self.base}{self.path}"

    def control(self, core: EnvCore) -> int:
        return via_proxy(
            core.proxy_port, "POST", self.url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urllib.parse.urlencode({"comment": self.tag}).encode(),
        ).status

    def control_ok(self, status: int) -> bool:
        return status // 100 in (2, 3)

    def hits(self) -> int:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            conn.request("GET", "/comments", headers={"Host": f"{self.host}:{self.port}"})
            r = conn.getresponse()
            html = r.read().decode("utf-8", "replace")
        finally:
            conn.close()
        return html.count(f"<li>{self.tag}</li>")

    def stop(self) -> None:
        pass


def make_observer(core: EnvCore, tag: str):
    try:
        return OwnUpstream(tag)
    except PermissionError as e:
        if core.target_url:
            ok(f"cannot bind a loopback port here ({e}); using the seeded target as the origin observer")
            return TargetComments(core, tag)
        skip(f"cannot bind an upstream ({e}) and AITM_TARGET_URL is unset: no origin to observe")
        raise AssertionError("unreachable")


# --- outcome classification -----------------------------------------------------


class Outcome:
    """What ONE tools/call did, from the client's seat."""

    def __init__(self, kind: str, text: str = "", code: Optional[int] = None, result: Any = None):
        self.kind = kind  # ok | tool_error | rpc_error | closed
        self.text = text
        self.code = code
        self.result = result

    def __repr__(self) -> str:
        if self.kind == "rpc_error":
            return f"rpc_error({self.code}: {self.text[:120]!r})"
        if self.kind == "ok":
            return f"ok({str(self.result)[:120]!r})"
        return f"{self.kind}({self.text[:120]!r})"


def invoke(bus: BusClient, name: str, args: Dict[str, Any]) -> Outcome:
    """Call `name`; classify. Follows the operator confirm handshake if offered
    (confirming a call on a flow that does not exist cannot do anything)."""
    try:
        res = bus.call(name, args)
        if isinstance(res, dict) and res.get("status") == "needs_confirmation" and res.get("confirm_token"):
            res = bus.call(name, {**args, "_confirm": res["confirm_token"]})
        return Outcome("ok", result=res)
    except ToolError as e:
        text = str(e)
        prefix = f"{name}: "
        return Outcome("tool_error", text[len(prefix):] if text.startswith(prefix) else text)
    except BusError as e:
        text = str(e)
        prefix = "rpc tools/call: "
        if text.startswith(prefix):
            try:
                err = json.loads(text[len(prefix):])
                return Outcome("rpc_error", str(err.get("message", "")), code=err.get("code"))
            except json.JSONDecodeError:
                pass
        return Outcome("closed", text)


def noise_in(text: str) -> List[str]:
    return [n for n in NOISE if n in text]


def canonical(raw: str) -> str:
    """The lowercase-hyphenated form the core prints for any UUID spelling."""
    return str(uuid.UUID(raw))


def explain_missing(o: Outcome, shown_id: str) -> Tuple[bool, str]:
    """Is `o` the clean missing-flow refusal naming `shown_id`? (verdict, why)."""
    if o.kind != "tool_error":
        return False, f"expected an isError tool result, got {o!r}"
    t = o.text
    problems = []
    if NO_FLOW not in t:
        problems.append(f"text lacks {NO_FLOW!r}")
    if shown_id.lower() not in t.lower():
        problems.append(f"text does not name the id {shown_id}")
    if "\n" in t.strip():
        problems.append("text is multi-line")
    if len(t) > MAX_ERROR_CHARS:
        problems.append(f"text is {len(t)} chars (> {MAX_ERROR_CHARS})")
    if noise_in(t):
        problems.append(f"text carries internals {noise_in(t)}")
    return (not problems), ("; ".join(problems) if problems else t)


def explain_invalid(o: Outcome, needle: str) -> Tuple[bool, str]:
    """Is `o` the clean INVALID_PARAMS protocol rejection mentioning `needle`?"""
    if o.kind != "rpc_error":
        return False, f"expected a JSON-RPC error, got {o!r}"
    problems = []
    if o.code != INVALID_PARAMS:
        problems.append(f"code {o.code} (want {INVALID_PARAMS})")
    if needle not in o.text:
        problems.append(f"message lacks {needle!r}")
    if noise_in(o.text):
        problems.append(f"message carries internals {noise_in(o.text)}")
    if len(o.text) > MAX_ERROR_CHARS:
        problems.append(f"message is {len(o.text)} chars (> {MAX_ERROR_CHARS})")
    return (not problems), ("; ".join(problems) if problems else o.text)


# --- bus helpers ----------------------------------------------------------------


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


def activity_since(bus: BusClient, since_ms: int) -> List[dict]:
    entries = bus.call("agent.activity", {"since": since_ms})
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


def audited(entries: List[dict], command: str, needle: str) -> List[dict]:
    """Audit entries for `command` whose recorded error names `needle`."""
    out = []
    for e in entries:
        res = e.get("result")
        if e.get("command") == command and isinstance(res, dict) and needle.lower() in str(res.get("error", "")).lower():
            out.append(e)
    return out


def flip_last_hex(fid: str) -> str:
    """The same UUID with its final hex digit changed: a near-miss, never equal."""
    last = fid[-1].lower()
    repl = "1" if last == "0" else "0"
    return fid[:-1] + repl


def marks_of(detail: Any) -> List[str]:
    """`flow.detail`'s `meta.marks`. Fails loudly if the shape moved, so a renamed
    field cannot turn without_marks() below into a silent no-op."""
    meta = detail.get("meta") if isinstance(detail, dict) else None
    marks = meta.get("marks") if isinstance(meta, dict) else None
    if not isinstance(marks, list) or not all(isinstance(m, str) for m in marks):
        fail(f"flow.detail has no meta.marks list of strings: {str(detail)[:200]}")
    return marks


def without_marks(detail: Dict[str, Any]) -> Dict[str, Any]:
    """A deep copy of `detail` with ONLY `meta.marks` removed; never mutates its argument."""
    out = copy.deepcopy(detail)
    meta = out.get("meta")
    if isinstance(meta, dict):
        meta.pop("marks", None)
    return out


_ABSENT = object()


def differing_keys(a: Dict[str, Any], b: Dict[str, Any]) -> List[str]:
    """Names of what differs between two flow.detail dicts: the top-level keys,
    and for `meta` the individual `meta.<key>`s. Only for failure messages."""
    names: List[str] = []
    for k in sorted(set(a) | set(b)):
        va, vb = a.get(k, _ABSENT), b.get(k, _ABSENT)
        if va == vb:
            continue
        if k == "meta" and isinstance(va, dict) and isinstance(vb, dict):
            names += [f"meta.{m}" for m in sorted(set(va) | set(vb)) if va.get(m, _ABSENT) != vb.get(m, _ABSENT)]
        else:
            names.append(k)
    return names


def barrage_carriers(rows: List[dict]) -> List[Any]:
    """Ids of the flow.table rows whose `marks` carry BARRAGE_MARK."""
    return [r.get("id") for r in rows if BARRAGE_MARK in (r.get("marks") or [])]


# --- the id-taking commands -------------------------------------------------------

# (tool, args-for-id, need) -- `need` is the role class that may run it:
#   read      -> the agent unless policy is `paused`
#   write     -> the agent under auto/all/ask (else the operator)
#   sensitive -> the operator only (the agent is refused, or PARKED under `ask`)
MISSING_ID_CALLS: List[Tuple[str, Callable[[str], Dict[str, Any]], str]] = [
    ("flow.get", lambda i: {"id": i}, "read"),
    ("flow.detail", lambda i: {"id": i, "body": "inline"}, "read"),
    ("flow.replay", lambda i: {"id": i}, "write"),
    ("flow.mark", lambda i: {"id": i, "marks": [BARRAGE_MARK]}, "write"),
    ("flow.comment", lambda i: {"id": i, "text": "e2e missing-flow probe"}, "write"),
    ("flow.resume", lambda i: {"id": i}, "write"),
    ("flow.kill", lambda i: {"id": i}, "write"),
    ("flow.kill", lambda i: {"id": i, "mode": "503"}, "write"),
    ("flow.mutate", lambda i: {"id": i, "edits": {"path": "/e2e-missing"}}, "write"),
    ("poc.build", lambda i: {"flow_id": i}, "write"),
    ("flow.export", lambda i: {"ids": [i]}, "sensitive"),
    ("ws.frame", lambda i: {"id": i, "index": 0, "action": "forward"}, "sensitive"),
    ("ws.send", lambda i: {"id": i, "dir": "c2s", "opcode": "text", "data": "ZTJl"}, "sensitive"),
]

# Malformed spellings: each must be rejected as INVALID_PARAMS naming `param `id``.
MALFORMED_IDS: List[Tuple[str, Any]] = [
    ("empty string", ""),
    ("plain word", "not-a-flow-id"),
    ("short digits", "1234"),
    ("path traversal", "../../../etc/passwd"),
    ("sql injection", "' OR 1=1 --"),
    ("html", "<script>alert(1)</script>"),
    ("10 KB string", "x" * 10_000),
    ("unicode", "flow-ид-\U0001f525"),
    ("json null literal", "null"),
]
NON_STRING_IDS: List[Tuple[str, Any]] = [
    ("integer", 123),
    ("null", None),
    ("object", {}),
    ("array", []),
    ("boolean", True),
]


# --- the scenario -----------------------------------------------------------------


def main() -> int:
    core = EnvCore()
    tag = f"nxf{uuid.uuid4().hex[:10]}"
    agent = BusClient.agent(core)
    op: Optional[BusClient] = None
    observer = None
    try:
        section("preflight: the runner's core exposes the commands under test")
        names = set(agent.tool_names())
        need = sorted({n for n, _, _ in MISSING_ID_CALLS} | {"flow.table", "flow.list", "proxy.status", "agent.activity"})
        missing_tools = [n for n in need if n not in names]
        check(not missing_tools, f"live tools/list registers every id-taking command ({len(need)}; missing: {missing_tools or 'none'})")
        policy = agent_policy(agent)
        ok(f"core has {len(names)} tools; proxy {core.proxy_host}:{core.proxy_port}; agent policy {policy!r}; marker {tag}")
        if core.has_operator:
            op = BusClient.operator(core)
            ok("operator connection open (AITM_BUS_OPERATOR_TOKEN): Sensitive commands and role parity are covered")
        else:
            ok("no AITM_BUS_OPERATOR_TOKEN: Sensitive commands (flow.export, ws.*) and role parity are reported, not asserted")

        def pick(need_role: str) -> Optional[Tuple[str, BusClient]]:
            if need_role == "read" and policy in READ_POLICIES:
                return "agent", agent
            if need_role == "write" and policy in DEFAULT_WRITE_POLICIES:
                return "agent", agent
            if op is not None:
                return "operator", op
            return None

        reader = pick("read")
        if reader is None:
            skip(f"agent policy {policy!r} refuses even Read and no operator token was given")
        rd_label, rd = reader

        section("arrange: a REAL request through the REAL proxy -> one real flow (the control)")
        observer = make_observer(core, tag)
        ok(f"origin observer: {observer.name}")
        status = observer.control(core)
        check(observer.control_ok(status), f"control request reached the origin through the proxy (HTTP {status})")
        check(observer.hits() == 1, f"origin's OWN record shows exactly the control request ({observer.hits()})")
        row = wait_for_row(rd, lambda r: tag in (r.get("path") or "") and r.get("status") is not None, ROW_WAIT_S)
        if row is None:
            fail(f"the control flow for {tag} never appeared completed in flow.table within {ROW_WAIT_S}s")
        real_id = row["id"]
        check(uuid.UUID(real_id).version is not None and real_id == canonical(real_id),
              f"flow ids are canonical lowercase-hyphenated UUIDs ({real_id})")
        summary_before = rd.call("flow.get", {"id": real_id})
        check(summary_before.get("id") == real_id and summary_before.get("path") == observer.path,
              f"flow.get on the REAL id works and is the control request ({summary_before.get('method')} {summary_before.get('path')})")
        detail_before = rd.call("flow.detail", {"id": real_id, "body": "inline"})
        check(isinstance(detail_before, dict) and (detail_before.get("response") or {}).get("status") == status,
              f"flow.detail on the REAL id carries the origin's response ({(detail_before.get('response') or {}).get('status')})")
        # Not asserted empty: bundled passive detectors may add marks at any moment. So the 'marks only
        # grew' check below only binds when marks existed before the barrage; it is a tripwire for future
        # barrage entries. docs/superpowers/specs/2026-10-31-neg-nonexistent-flow-marks-design.md AC3
        # (fault injection F2) proves that it binds.
        marks_before = marks_of(detail_before)
        status_before = rd.call("proxy.status")
        flows_before = int(status_before.get("flows") or 0)
        check(flows_before >= 1, f"proxy.status counts the store ({flows_before} flows, control included)")
        list_before = set(rd.call("flow.list"))
        check(real_id in list_before, f"flow.list holds the control flow ({len(list_before)} flows in the store)")

        section("arrange: ids that provably do NOT exist (checked against flow.list, the store's own index)")
        fresh = str(uuid.uuid4())
        while fresh in list_before:  # astronomically unlikely; keep the precondition honest
            fresh = str(uuid.uuid4())
        near = flip_last_hex(real_id)
        missing_ids = [("fresh uuid4", fresh), ("nil uuid", NIL_UUID), ("max uuid", MAX_UUID), ("near-miss of the real id", near)]
        for label, mid in missing_ids:
            check(mid not in list_before, f"{label} {mid} is not in the store")
        check(near != real_id and near[:-1] == real_id[:-1], f"near-miss differs from the real id in its last hex digit only")

        section("act: every id-taking command on a missing id -> one clean `no flow with id` refusal each")
        t0_ms = int(time.time() * 1000) - 1
        first_text: Dict[str, str] = {}
        ran: List[Tuple[str, str, str]] = []  # (tool, role, id) that RAN and refused (audited)
        not_run: List[str] = []
        for tool, mk, need_role in MISSING_ID_CALLS:
            who = pick(need_role)
            if who is None:
                not_run.append(tool)
                ok(f"{tool}: needs the {'operator' if need_role == 'sensitive' else 'operator (agent policy ' + repr(policy) + ')'}; not available here -- skipped, not asserted")
                continue
            role, bus = who
            for label, mid in missing_ids:
                o = invoke(bus, tool, mk(mid))
                good, why = explain_missing(o, mid)
                check(good, f"[{role}] {tool} on {label}: {why}")
                ran.append((tool, role, mid))
                first_text.setdefault(f"{tool}|{json.dumps(mk(mid), sort_keys=True)}", o.text)
            # deterministic: the same call again yields byte-identical text
            key = f"{tool}|{json.dumps(mk(fresh), sort_keys=True)}"
            again = invoke(bus, tool, mk(fresh))
            check(again.kind == "tool_error" and again.text == first_text[key],
                  f"[{role}] {tool} repeated on the same missing id answers byte-identically")
            ran.append((tool, role, fresh))

        section("act: flow.export with a REAL id and a missing one is all-or-nothing")
        who = pick("sensitive")
        if who is None:
            ok("flow.export needs the operator; skipped")
        else:
            role, bus = who
            o = invoke(bus, "flow.export", {"ids": [real_id, fresh]})
            good, why = explain_missing(o, fresh)
            check(good, f"[{role}] flow.export [real, missing] refuses naming the missing id, no partial export: {why}")
            ran.append(("flow.export", role, fresh))

        section("act: alternative UUID spellings of the same missing id are refused cleanly, naming the canonical id")
        for label, raw in [("UPPERCASE", fresh.upper()), ("braced", "{" + fresh + "}"),
                           ("urn:uuid:", "urn:uuid:" + fresh), ("32-hex simple", fresh.replace("-", ""))]:
            o = invoke(rd, "flow.get", {"id": raw})
            as_missing, why_m = explain_missing(o, canonical(fresh))
            as_invalid, why_i = explain_invalid(o, NOT_VALID)
            check(as_missing or as_invalid,
                  f"[{rd_label}] flow.get on {label} id -> {'missing-flow refusal naming ' + fresh if as_missing else ('INVALID_PARAMS: ' + why_i if as_invalid else why_m)}")
            if as_missing:
                ran.append(("flow.get", rd_label, fresh))

        section("act: MALFORMED ids never reach a command -- JSON-RPC -32602, naming the param; the socket stays open")
        for label, raw in MALFORMED_IDS:
            o = invoke(rd, "flow.get", {"id": raw})
            good, why = explain_invalid(o, NOT_VALID)
            check(good and "param `id`" in o.text, f"[{rd_label}] flow.get id={label}: {why[:160]}")
        for label, raw in NON_STRING_IDS:
            o = invoke(rd, "flow.get", {"id": raw})
            good, why = explain_invalid(o, "expected a flow id string")
            check(good and "param `id`" in o.text, f"[{rd_label}] flow.get id={label}: {why[:160]}")
        o = invoke(rd, "flow.get", {})
        good, why = explain_invalid(o, "missing required param `id`")
        check(good, f"[{rd_label}] flow.get with no id at all: {why[:160]}")
        # the same envelope on the Write/Sensitive commands, BEFORE any side effect.
        # The malformed id carries this run's marker so the audit probe below is
        # attributable to THIS test even on a core other suites share.
        bogus = f"not-a-flow-id-{tag}"
        for tool, mk, need_role in MISSING_ID_CALLS:
            who = pick(need_role)
            if who is None or tool in ("flow.get",):
                continue
            role, bus = who
            args = mk(bogus)
            o = invoke(bus, tool, args)
            good, why = explain_invalid(o, NOT_VALID)
            pname = "flow_id" if tool == "poc.build" else ("ids" if tool == "flow.export" else "id")
            check(good and f"param `{pname}`" in o.text, f"[{role}] {tool} with a malformed id is INVALID_PARAMS before running: {why[:140]}")
        check(rd.call("flow.get", {"id": real_id}) == summary_before,
              f"[{rd_label}] the SAME connection still answers flow.get on the real id identically after the malformed barrage")

        section("ground truth: the ORIGIN saw nothing but the control; the real flow and the store are untouched")
        time.sleep(SETTLE_S)
        hits = observer.hits()
        check(hits == 1, f"origin's OWN record still shows exactly 1 request for {tag} (got {hits}) -- no replay leaked")
        detail_after = rd.call("flow.detail", {"id": real_id, "body": "inline"})
        marks_after = marks_of(detail_after)
        marks_delta = f"(marks {marks_before!r} -> {marks_after!r})"
        # Detectors add marks after the response is stored, so compare everything else strictly.
        rest_before, rest_after = without_marks(detail_before), without_marks(detail_after)
        differs = ", ".join(differing_keys(rest_before, rest_after))
        check(rest_after == rest_before,
              "flow.detail of the REAL flow is byte-identical apart from meta.marks -- no comment or mutation landed on it"
              + (f" (differs in: {differs})" if differs else ""))
        check(BARRAGE_MARK not in marks_after,
              f"the barrage's mark label {BARRAGE_MARK!r} is absent from the REAL flow's marks -- no flow.mark landed on it {marks_delta}")
        check(set(marks_before) <= set(marks_after),
              f"marks only grew: every mark present before the barrage is still present -- none was replaced or wiped {marks_delta}"
              + (" -- vacuous: no marks before the barrage, so only the label checks and the rest-of-detail comparison bound"
                 if not marks_before else ""))
        rows = table_rows(rd)
        tagged = [r for r in rows if tag in (r.get("path") or "")]
        check(len(tagged) == 1 and tagged[0]["id"] == real_id, f"flow.table holds exactly the one control flow for {tag} ({len(tagged)})")
        if not isinstance(tagged[0].get("marks"), list):  # a renamed field must not turn the scan below into a no-op
            fail(f"flow.table row of the REAL flow has no marks list: {str(tagged[0])[:200]}")
        carriers = barrage_carriers(rows)
        check(not carriers,
              f"no flow in the store carries the barrage's mark label {BARRAGE_MARK!r} -- no flow.mark landed on any listed flow "
              f"(scanned {len(rows)} flows; carriers: {carriers})")
        list_after = set(rd.call("flow.list"))
        for _, mid in missing_ids:
            check(mid not in list_after, f"{mid} still does not exist: refusing did not create it")
        status_after = rd.call("proxy.status")
        check(int(status_after.get("flows") or 0) >= flows_before,
              f"proxy.status: the store lost no flow ({flows_before} -> {status_after.get('flows')}); "
              f"paused {status_after.get('paused')!r}, capturing {status_after.get('capturing')!r} (reported, shared-core safe)")

        section("ground truth: the audit ring recorded every refusal that RAN, and nothing for what never ran")
        # An agent-role reader no longer receives trusted-control (operator) entries (spec D3), so read as the operator when there is one.
        entries = activity_since(op or rd, t0_ms)
        check(len(entries) >= len(ran), f"agent.activity has >= {len(ran)} entries since the barrage began ({len(entries)})")
        origin_of = {"agent": "mcp", "operator": "operator"}
        for tool, role, mid in ran:
            hits_a = [e for e in audited(entries, tool, mid) if e.get("origin") == origin_of[role]]
            check(bool(hits_a), f"audit: {tool} by {role} on {mid[:8]}... recorded with the `{NO_FLOW}` reason")
        leaked_ids = [e for e in audited(entries, "flow.get", NO_FLOW) if real_id in str(e.get("result"))]
        check(not leaked_ids, "audit: no `no flow` entry names the REAL id (it was never refused)")
        never_ran = [e for e in entries if bogus in str(e.get("args", "")) or bogus in str(e.get("result", ""))]
        check(not never_ran, f"audit: the malformed-id calls were protocol rejections and left no audit entry ({len(never_ran)})")
        sample = audited(entries, "flow.get", fresh)
        if sample:
            check(sample[0]["result"]["error"] == first_text[f"flow.get|{json.dumps({'id': fresh}, sort_keys=True)}"],
                  "audit: the recorded reason is the very text the caller saw")

        if op is not None and policy in READ_POLICIES:
            section("role parity: the operator and the agent get the identical refusal")
            for tool, args in [("flow.get", {"id": fresh}), ("flow.replay", {"id": fresh}), ("flow.kill", {"id": fresh})]:
                a = invoke(agent, tool, args)
                b = invoke(op, tool, args)
                if a.kind == "tool_error" and NO_FLOW not in a.text:
                    ok(f"{tool}: agent policy {policy!r} refuses it ({a.text[:80]}); parity not applicable")
                    continue
                check(a.kind == b.kind == "tool_error" and a.text == b.text,
                      f"{tool}: agent and operator see the same text ({a.text[:80]!r})")

        section(f"survival: {FLOOD_N} distinct missing ids on ONE connection, all clean, all fast")
        rtts: List[float] = []
        bad: List[str] = []
        for _ in range(FLOOD_N):
            mid = str(uuid.uuid4())
            t = time.monotonic()
            o = invoke(rd, "flow.get", {"id": mid})
            rtts.append(time.monotonic() - t)
            good, why = explain_missing(o, mid)
            if not good:
                bad.append(why)
        check(not bad, f"all {FLOOD_N} answered with the clean refusal ({len(bad)} bad: {bad[:2]})")
        check(max(rtts) < FLOOD_MAX_RTT_S,
              f"slowest refusal {max(rtts) * 1000:.1f} ms (< {FLOOD_MAX_RTT_S:.0f}s); median {sorted(rtts)[len(rtts) // 2] * 1000:.1f} ms")
        check(rd.call("flow.get", {"id": real_id}) == summary_before, "after the flood the real flow reads back identically on the same socket")
        check(len(rd.tool_names()) == len(names), "after the flood tools/list is unchanged on the same socket")
        hits = observer.hits()
        check(hits == 1, f"origin's OWN record is still exactly 1 request after everything ({hits})")

        ok(f"nonexistent flow id -> clean `{NO_FLOW}` from {len({t for t, _, _ in ran})} commands "
           f"({len(ran)} refusals, {len(not_run)} commands skipped for lack of a role), nothing changed")
    finally:
        if observer is not None:
            try:
                observer.stop()
            except Exception:  # noqa: BLE001
                pass
        for c in (op, agent):
            if c is not None:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
