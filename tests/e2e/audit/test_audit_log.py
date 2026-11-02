#!/usr/bin/env python3
# e2e: tier=T1 surface=audit
"""The F2 command-invocation audit log records a sensitive command with its
redacted args summary, and never a secret, on a REAL running core.

What is proven, each against something the audit code does not control:

1. A Sensitive command (`scope.add`) from the AGENT is refused by the agent
   policy, and the refusal itself lands in the audit ring: command, origin `mcp`,
   the connection's client label, `args` = the arguments, `result.error` = the
   very text the agent was shown.
2. The OPERATOR runs the same Sensitive command; `scope.list` (ground truth)
   shows the scope really widened, and the entry says origin `operator`, `ok`.
3. `request.send` carrying FIVE secrets (an `Authorization: Bearer`, an
   `X-Api-Key`, a `Cookie`, an `access_token=` in the query string and a
   `password=` in the form body) runs for real: an independent echo-record
   upstream (`aitm_e2e.upstream.Upstream`) RECEIVED every secret verbatim, and
   `flow.detail` shows them captured in clear -- so the secrets were on the wire.
4. The audit entry for that call keeps the non-secret arguments (authority,
   method, a marker header, `q=`/`page=`/`user=` fields) and redacts every secret:
   secret-named keys become `"<redacted>"`, secrets inside non-secret strings
   become `[redacted]`, and not one secret byte appears anywhere in the whole
   `agent.activity` response.
5. The identical entry was PUSHED live as `notifications/aitm/agent` to a
   subscribed connection, with the same redacted `args`.
6. `agent.activity` `since` bounds (at-1 includes, at+1 excludes, at returns
   nothing older), `limit` caps, entries are oldest-first and timestamps monotonic.
7. A protocol-level failure (unknown argument, JSON-RPC -32602) is NOT an entry.

Connects to the core the runner provides through the environment
(`AITM_BUS_ADDR`, `AITM_BUS_TOKEN`, optional `AITM_BUS_OPERATOR_TOKEN`,
`AITM_TARGET_URL`); it never boots its own. Every entry of ours is found by a
per-connection client label and a unique marker, so it runs in parallel with the
rest of the suite against one shared core. Global state it touches: it widens the
scope by one unique `127.0.0.1:<free port>` entry (operator) and removes it again.
Works under every agent policy: the agent's refusals are themselves the audited
evidence; audit reads go through the operator connection when one is provided
(under `paused` the agent cannot even read the log).
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

ARGS_SUMMARY_CAP = 512  # aitm_core::DEFAULT_ARGS_SUMMARY_CAP (bytes of the JSON rendering)
KEY_REDACTED = "<redacted>"  # a secret-NAMED key's value (aitm-mcp redact_value)
TEXT_REDACTED = "[redacted]"  # a secret INSIDE a string (aitm_core::redact::scrub_text)
AGENT_NOTE = "notifications/aitm/agent"


# ---------------------------------------------------------------------------
# a soft-assertion battery: every failed expectation is printed, the test still
# runs to the end (and cleans up), and the exit code is 1 iff anything failed.

_failures: list[str] = []


def expect(cond: object, msg: str, detail: object = "") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:700]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# the runner-provided core (env contract; see tests/e2e/README.md)


def env_core() -> SimpleNamespace:
    addr = os.environ.get("AITM_BUS_ADDR", "").strip()
    agent_token = os.environ.get("AITM_BUS_TOKEN", "")
    if not addr or not agent_token:
        skip("no runner-provided core: export AITM_BUS_ADDR=host:port and AITM_BUS_TOKEN "
             "(this test never boots its own core)")
    host, sep, port = addr.rpartition(":")
    if not sep or not port.isdigit():
        fail(f"AITM_BUS_ADDR must be host:port, got {addr!r}")
    return SimpleNamespace(
        bus_addr=(host.strip("[]") or "127.0.0.1", int(port)),
        cfg=SimpleNamespace(
            agent_token=agent_token,
            operator_token=os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None,
        ),
    )


def connect(core: SimpleNamespace, token: str, label: str) -> BusClient:
    """The shared BusClient, with OUR client label: it becomes the audit entry's
    `client_label` (initialize.clientInfo.name), which is how this test finds its
    own entries in a ring shared with every parallel test."""
    host, port = core.bus_addr
    return BusClient(host, port, token, client_name=label).connect()


def activity(bus: BusClient, since: int, **kw) -> list[dict]:
    params = {"since": since}
    params.update(kw)
    res = bus.call("agent.activity", params)
    if not isinstance(res, list):
        fail(f"agent.activity must answer an array of entries, got {type(res).__name__}: {str(res)[:200]}")
    return res


def mine(entries: list[dict], label: str, command: str, contains: str = "") -> list[dict]:
    return [
        e for e in entries
        if e.get("client_label") == label and e.get("command") == command
        and contains in (e.get("args") or "")
    ]


def tool_error_text(msg: str, name: str) -> str:
    """BusClient.ToolError renders `f"{name}: {text}"`; recover the tool's text."""
    prefix = f"{name}: "
    return msg[len(prefix):] if msg.startswith(prefix) else msg


def wait_agent_note(sub: BusClient, pred, timeout: float) -> dict | None:
    """The first pushed `notifications/aitm/agent` line whose params satisfy `pred`."""
    deadline = time.time() + timeout
    while True:
        for m in sub.notifications:
            if m.get("method") == AGENT_NOTE and pred(m.get("params") or {}):
                return m
        if time.time() >= deadline:
            return None
        sub.drain_notifications(timeout=min(1.0, max(0.1, deadline - time.time())))


def header(headers: list, name: str) -> str | None:
    """A header value from flow.detail's `[[name, value], ...]`."""
    want = name.lower()
    for pair in headers or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and str(pair[0]).lower() == want:
            return str(pair[1])
    return None


# ---------------------------------------------------------------------------


def main() -> int:
    core = env_core()
    run = secrets.token_hex(4)
    marker = f"e2e-audit-{os.getpid()}-{run}"
    ag_label = f"aitm-e2e-audit-agent-{run}"
    op_label = f"aitm-e2e-audit-operator-{run}"
    sub_label = f"aitm-e2e-audit-subscriber-{run}"
    # Pure hex: distinctive, and can never contain a redaction needle itself.
    secret = {
        "bearer": secrets.token_hex(16),
        "api_key": secrets.token_hex(16),
        "cookie": secrets.token_hex(16),
        "query_token": secrets.token_hex(16),
        "password": secrets.token_hex(16),
    }

    ag = op = sub = None
    up: Upstream | None = None
    target = ""
    widened_by: list[BusClient] = []
    try:
        section("arrange: three labelled connections to the runner's core, a live subscriber, secrets")
        ag = connect(core, core.cfg.agent_token, ag_label)
        if core.cfg.operator_token:
            op = connect(core, core.cfg.operator_token, op_label)
        # The audit READER. agent.status/agent.activity are Read commands any role
        # answers -- except under `paused`, which refuses every agent call before it
        # runs; the operator bypasses the policy gate, so prefer it when present.
        rd = op or ag
        st, status = rd.try_call("agent.status")
        if st != "ok":
            skip(f"cannot read the agent policy from this core: {str(status)[:160]}")
        policy = status.get("policy") if isinstance(status, dict) else None
        check(policy in ("all", "auto", "ask", "readonly", "paused"), f"agent policy is {policy!r}")
        # The live subscriber. The agent stream is fanned to EVERY subscribed
        # connection (not operators only), so an agent-token subscriber is the
        # stronger proof; under `paused` its flow.subscribe is itself refused, so
        # fall back to an operator subscriber when there is one.
        sub = connect(core, core.cfg.agent_token, sub_label)
        st, sub_id = sub.try_call("flow.subscribe", {})
        if st != "ok" and op:
            sub.close()
            sub = connect(core, core.cfg.operator_token, sub_label)
            st, sub_id = sub.try_call("flow.subscribe", {})
        check(st == "ok" and isinstance(sub_id, dict) and "sub_id" in sub_id,
              f"subscriber connection subscribed ({sub_id})")
        t0 = now_ms() - 5000  # the ring is shared; `since` + our labels isolate this run

        if op:
            up = Upstream().start()
            target = up.authority
            ok(f"independent echo-record upstream on {target} (operator will scope it)")
        else:
            url = os.environ.get("AITM_TARGET_URL", "")
            if not url:
                skip("neither AITM_BUS_OPERATOR_TOKEN nor AITM_TARGET_URL provided: no in-scope target")
            target = urlsplit(url).netloc
            ok(f"no operator token: operator-side audit not exercised; target is the scoped testtarget {target}")

        # ---------------------------------------------------------------
        section("1. a Sensitive command from the AGENT is refused by policy, and the REFUSAL is audited")
        if policy == "ask":
            ok("policy is `ask`: the agent's scope.add would park for approval; agent-side step skipped")
        else:
            st, res = ag.try_call("scope.add", {"host": target})
            if policy == "auto":
                expect(st == "error", f"under `auto` the agent is refused scope.add (got {st})", res)
                expect("refused" in str(res), "the refusal names itself a refusal", res)
            es = mine(activity(rd, t0), ag_label, "scope.add", target)
            expect(len(es) == 1, f"exactly one scope.add entry carries our label + host (found {len(es)})", es)
            if es:
                e = es[0]
                expect(e.get("origin") == "mcp", f"origin is `mcp` for the agent token (got {e.get('origin')!r})")
                expect(e.get("client_label") == ag_label, "client_label is our initialize.clientInfo.name", e)
                try:
                    parsed = json.loads(e.get("args") or "")
                except ValueError:
                    parsed = None
                expect(parsed == {"host": target}, f"args summary is the JSON of the arguments (got {e.get('args')!r})")
                if st == "error":
                    want = tool_error_text(str(res), "scope.add")
                    got = e.get("result")
                    expect(isinstance(got, dict) and got.get("error") == want,
                           "result.error is the exact refusal text the agent received", got)
                else:
                    expect(e.get("result") == "ok", "the agent's scope.add ran: result is `ok`", e.get("result"))
                    widened_by.append(ag)

        # ---------------------------------------------------------------
        section("2. the OPERATOR runs the same Sensitive command: scope really widens, entry says operator/ok")
        if op:
            r = op.confirm("scope.add", {"host": target})
            expect(r == target, f"operator scope.add answered the entry (got {r!r})")
            widened_by.append(op)
            listed = op.call("scope.list")
            expect(isinstance(listed, list) and target in listed, "scope.list (ground truth) now holds the host", listed)
            es = mine(activity(op, t0), op_label, "scope.add", target)
            expect(len(es) == 1, f"exactly one scope.add entry carries the operator label + host (found {len(es)})", es)
            if es:
                e = es[0]
                expect(e.get("origin") == "operator", f"origin is `operator` (got {e.get('origin')!r})")
                expect(e.get("result") == "ok", "result is `ok`", e.get("result"))
                expect(json.loads(e.get("args") or "null") == {"host": target}, "args summary is the arguments", e.get("args"))

        # ---------------------------------------------------------------
        section("3. request.send with five secrets runs for real; the upstream SAW them (so redaction is not vacuous)")
        send_args = {
            "method": "POST",
            "authority": target,
            "path": f"/search?q={marker}&access_token={secret['query_token']}&page=2",
            "headers": {
                "Authorization": f"Bearer {secret['bearer']}",
                "X-Api-Key": secret["api_key"],
                "Cookie": f"session={secret['cookie']}",
                "X-Audit-Marker": marker,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": f"user={marker}&password={secret['password']}",
        }
        st, res = ag.try_call("request.send", send_args)
        write_allowed = policy in ("all", "auto", "ask")
        if write_allowed:
            expect(st == "ok", f"the agent may request.send (Write) under `{policy}` (got {st})", res)
        else:
            expect(st == "error", f"the agent is refused request.send under `{policy}` (got {st})", res)
        flow_id = str(res) if st == "ok" else None

        if flow_id:
            if up:
                deadline = time.time() + 5
                hits: list[dict] = []
                while time.time() < deadline and not hits:
                    hits = [r for r in up.received if marker in r.get("path", "")]
                    if not hits:
                        time.sleep(0.05)
                expect(len(hits) == 1, f"the upstream recorded exactly our request ({len(hits)} hit(s))")
                if hits:
                    h = hits[0]
                    hh = h["headers"]
                    expect(h["method"] == "POST", "upstream saw POST", h["method"])
                    expect(hh.get("authorization") == f"Bearer {secret['bearer']}",
                           "upstream received the real Authorization bearer", hh.get("authorization"))
                    expect(hh.get("x-api-key") == secret["api_key"], "upstream received the real X-Api-Key")
                    expect(secret["cookie"] in (hh.get("cookie") or ""), "upstream received the real Cookie")
                    expect(hh.get("x-audit-marker") == marker, "upstream received the marker header")
                    expect(secret["query_token"] in h["path"], "upstream received the real access_token in the query")
                    expect(secret["password"] in h["body"], "upstream received the real password in the body")
            d = ag.call("flow.detail", {"id": flow_id, "body": "inline"})
            req = d.get("request", {}) if isinstance(d, dict) else {}
            expect(marker in (req.get("path") or ""), "flow.detail: the captured flow is ours (marker in path)", req.get("path"))
            expect(header(req.get("headers"), "authorization") == f"Bearer {secret['bearer']}",
                   "flow.detail keeps the raw Authorization in the capture store (redaction is the audit log's job)")
            expect(secret["query_token"] in (req.get("path") or ""), "flow.detail keeps the raw query token")
            if not up:
                ok("no upstream observer here; the capture store is the wire evidence")

        # ---------------------------------------------------------------
        section("4. the audit entry for request.send: non-secret args intact, every secret redacted")
        all_entries = activity(rd, t0)
        es = mine(all_entries, ag_label, "request.send", marker)
        expect(len(es) == 1, f"exactly one request.send entry carries our label + marker (found {len(es)})",
               [e.get("args") for e in all_entries if e.get("client_label") == ag_label])
        entry = es[0] if es else {}
        args_s = entry.get("args")
        expect(isinstance(args_s, str), "args is a string rendering", type(args_s).__name__)
        args_s = args_s if isinstance(args_s, str) else ""
        expect(entry.get("origin") == "mcp" and entry.get("client_label") == ag_label,
               "origin `mcp` + our client label", (entry.get("origin"), entry.get("client_label")))
        if flow_id:
            expect(entry.get("result") == "ok", "result is `ok` for the call that ran", entry.get("result"))
        else:
            got = entry.get("result")
            expect(isinstance(got, dict) and got.get("error") == tool_error_text(str(res), "request.send"),
                   "result.error is the refusal the agent received", got)
        expect(not args_s.endswith("…") and len(args_s.encode("utf-8")) <= ARGS_SUMMARY_CAP,
               f"args summary is complete (not truncated) and within {ARGS_SUMMARY_CAP} bytes", len(args_s.encode()))
        try:
            a = json.loads(args_s)
        except ValueError:
            a = None
        expect(isinstance(a, dict), "args summary parses as a JSON object", args_s)
        a = a if isinstance(a, dict) else {}
        hdrs = a.get("headers") if isinstance(a.get("headers"), dict) else {}
        expect(a.get("authority") == target, "authority survives verbatim", a.get("authority"))
        expect(a.get("method") == "POST", "method survives verbatim", a.get("method"))
        expect(hdrs.get("X-Audit-Marker") == KEY_REDACTED,
               f"non-benign header X-Audit-Marker has its value hidden as {KEY_REDACTED} (rule D)", hdrs)
        expect("X-Audit-Marker" in hdrs, "the name X-Audit-Marker is still present", hdrs)
        expect(hdrs.get("Content-Type") == "application/x-www-form-urlencoded", "Content-Type survives verbatim", hdrs)
        for key in ("Authorization", "X-Api-Key", "Cookie"):
            expect(hdrs.get(key) == KEY_REDACTED, f"secret-named header {key} is {KEY_REDACTED}", hdrs.get(key))
        path = a.get("path") or ""
        expect(f"q={marker}" in path and "page=2" in path, "non-secret query fields survive", path)
        expect(f"access_token={TEXT_REDACTED}" in path, f"access_token= in the path is {TEXT_REDACTED} (content scrub)", path)
        body = a.get("body") or ""
        expect(f"user={marker}" in body, "non-secret body field survives", body)
        expect(f"password={TEXT_REDACTED}" in body, f"password= in the body is {TEXT_REDACTED} (content scrub)", body)
        blob = json.dumps(entry)
        for name, val in secret.items():
            expect(val not in blob, f"secret `{name}` is absent from the request.send entry")
        everything = json.dumps(all_entries)
        for name, val in secret.items():
            expect(val not in everything, f"secret `{name}` is absent from the WHOLE agent.activity response")
        expect(any(e.get("client_label") == ag_label for e in all_entries),
               "the sweep covered our own entries (client label present)")

        # ---------------------------------------------------------------
        section("5. the same entry was PUSHED live as notifications/aitm/agent, identically redacted")
        note = wait_agent_note(
            sub,
            lambda p: p.get("command") == "request.send" and p.get("client_label") == ag_label
            and marker in (p.get("args") or ""),
            timeout=8.0,
        )
        expect(note is not None, "a subscribed connection received our request.send audit line within 8s",
               [m.get("method") for m in sub.notifications][-10:])
        if note:
            p = note.get("params") or {}
            expect(p.get("args") == args_s, "the pushed args rendering is byte-identical to agent.activity's", p.get("args"))
            expect(p.get("origin") == "mcp" and p.get("result") == entry.get("result"),
                   "pushed origin/result match the ring entry", (p.get("origin"), p.get("result")))
            expect(p.get("at") == entry.get("at"), "pushed `at` matches the ring entry", (p.get("at"), entry.get("at")))
            line = json.dumps(note)
            for name, val in secret.items():
                expect(val not in line, f"secret `{name}` is absent from the pushed line")

        # ---------------------------------------------------------------
        section("6. agent.activity since/limit semantics, oldest-first order, monotonic timestamps")
        at = entry.get("at")
        if isinstance(at, int):
            # `at` is ms-truncated while the ring compares the full SystemTime, so
            # since=<at> can still return this very entry (its sub-ms tail is
            # "strictly after" the whole millisecond). The unambiguous bounds are
            # at-1 (included) and at+1 (excluded); since=<at> must never return
            # anything OLDER than the entry.
            after = mine(activity(rd, at + 1), ag_label, "request.send", marker)
            expect(not after, "since=<entry.at + 1> excludes the entry", after)
            incl = mine(activity(rd, at - 1), ag_label, "request.send", marker)
            expect(len(incl) == 1, "since=<entry.at - 1> includes the entry", len(incl))
            older = [e for e in activity(rd, at) if isinstance(e.get("at"), int) and e["at"] < at]
            expect(not older, "since=<entry.at> returns nothing older than the entry", older[:3])
        capped = rd.call("agent.activity", {"limit": 1})
        expect(isinstance(capped, list) and len(capped) == 1, "limit=1 answers exactly one entry", capped)
        ours = [e for e in activity(rd, t0) if e.get("client_label") in (ag_label, op_label)]
        ats = [e.get("at") for e in ours]
        expect(all(isinstance(x, int) for x in ats) and ats == sorted(ats), "our entries are oldest-first with monotonic `at`", ats)
        cmds = [e.get("command") for e in ours]
        if "scope.add" in cmds and "request.send" in cmds:
            expect(cmds.index("scope.add") < cmds.index("request.send"),
                   "the earlier scope.add precedes the later request.send", cmds)

        # ---------------------------------------------------------------
        section("7. a protocol-level failure (unknown argument) is a JSON-RPC error, NOT an audit entry")
        # The policy gate runs BEFORE argument validation: under `paused` an agent
        # probe is refused (and audited) before the bad argument is ever seen, so
        # probe as the operator when there is one (it bypasses the gate).
        probe = op or ag
        bogus = f"bogus_{run}"
        if probe is ag and policy == "paused":
            ok("policy is `paused` and no operator token: the agent never reaches argument validation; step skipped")
        else:
            try:
                probe.rpc("tools/call", {"name": "flow.get", "arguments": {"id": "0", bogus: 1}})
                expect(False, "an unknown argument must be rejected with a JSON-RPC error")
            except BusError as e:
                expect("-32602" in str(e), "the rejection is INVALID_PARAMS (-32602)", str(e)[:200])
            leaked = [e for e in activity(rd, t0) if bogus in (e.get("args") or "")]
            expect(not leaked, "no audit entry was recorded for the call that never ran", leaked)

    finally:
        section("cleanup: narrow the scope back, close connections, stop the upstream")
        if op and target:
            for _ in range(3):
                try:
                    listed = op.call("scope.list")
                except (BusError, ToolError, OSError):
                    break
                if target not in listed:
                    break
                op.try_call("scope.remove", {"host": target})
            try:
                expect(target not in op.call("scope.list"), "operator removed the scope entry again")
            except (BusError, ToolError, OSError) as e:  # noqa: BLE001
                print(f"  [warn] could not verify scope cleanup: {e}", flush=True)
        for b in (sub, op, ag):
            if b:
                b.close()
        if up:
            up.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("audit log: sensitive command recorded, args summarised, all secrets redacted, pushed live")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
