"""Scanner v2 harness helper (T10 spec D7): every `scan.*` verb a cell calls goes
through here, so the run can prove which verb was exercised at which role.

Pieces:
  - the verb contract: `expected_scan_verbs()` parsed from the maintained Rust
    EXPECTED_TOOLS list (never a literal here); `ContractDrift` when a live core
    disagrees; `require_verbs` / `require_lane` SKIP 77 with the missing thing named
  - the only call paths: `scan_call` / `scan_try`, which record
    (verb, role, outcome, code) in the per-cell ledger that `ledger_flush()` writes
    to `$AITM_E2E_LEDGER_DIR/<cell>.json` at exit (run.py prints the roll-up)
  - job helpers: `start_job`, `map_job`, `cancel`, `wait_terminal`, `subscribe`,
    `collect_push`, `issues`, `issue`
  - `ScanTarget`: the seeded origin (`aitm-testtarget-serve`) with its TLS, TLS-h1,
    control and L4 listeners; `TargetLogs`: its control-origin logs (D2), the
    independent observer every cell asserts on; `Canary`: an out-of-scope loopback
    listener a cell plants a link to, to prove the crawler never left scope.

Pure stdlib. Never prints a token. Wire names below are pinned by the T1a fixture
pack (`crates/aitm-scan-model/fixtures/*.json`) and the T10 spec D1/D2.
"""

from __future__ import annotations

import atexit
import base64
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import fail, free_port, ok, repo_root, skip
from .bus import BusError, ToolError
from .proxyutil import via_proxy
from .target import testtarget_bin
from .ws import WsClient

__all__ = [
    "ROLES",
    "SCAN_VERBS_D3",
    "REFLECTED_XSS_CLASSES",
    "WS_CSWSH_CLASS",
    "WS_REFLECTION_CLASS",
    "WS_OVERSIZE_CLASS",
    "WS_OVERSIZE_CHECK_ID",
    "JOB_NOTIFICATION_METHOD",
    "TERMINAL_STATES",
    "TERMINAL_EVENTS",
    "ContractDrift",
    "expected_scan_verbs",
    "scan_tools",
    "require_verbs",
    "require_lane",
    "require_checks",
    "scan_call",
    "scan_try",
    "scan_error_code",
    "start_job",
    "map_job",
    "cancel",
    "wait_terminal",
    "run_to_terminal",
    "subscribe",
    "collect_push",
    "issues",
    "issue",
    "brief",
    "sitemap",
    "PACKET_LANE_VIA",
    "PACKET_PERMISSION_PENDING",
    "packet_lane_gate",
    "read_capture_packets",
    "ScanTarget",
    "boot_target",
    "split_addr",
    "l4_endpoint",
    "login",
    "login_via_proxy",
    "post_form_direct",
    "until",
    "Expectations",
    "TargetLogs",
    "Canary",
    "WsClientWithHeaders",
    "ledger_flush",
]

# The 18 verbs of the parent spec D3. `test_t1_contract` uses this tuple for
# CONTRACT COMPLETENESS only -- "the maintained EXPECTED_TOOLS list still names every
# verb the spec promises". The expectation asserted against a LIVE core is always
# `expected_scan_verbs()`, parsed from the Rust contract, never this tuple.
SCAN_VERBS_D3: tuple[str, ...] = (
    "scan.start",
    "scan.map",
    "scan.status",
    "scan.list",
    "scan.cancel",
    "scan.issues",
    "scan.issue",
    "scan.issue.update",
    "scan.sitemap",
    "scan.checks",
    "scan.profile.list",
    "scan.profile.get",
    "scan.profile.save",
    "scan.profile.delete",
    "scan.session.preview",
    "scan.discover",
    "scan.passive",
    "scan.report",
)

# Push line (parent D3 "Progress push"; fixtures job.*.json): method + the params
# `event` values that end a job. `JobStatus.state` terminal values (parent D5).
JOB_NOTIFICATION_METHOD = "notifications/aitm/job"
TERMINAL_EVENTS = frozenset({"finished", "cancelled", "failed"})
TERMINAL_STATES = frozenset({"done", "cancelled", "failed"})

ROLES = ("operator", "agent")

# Issue-class vocabulary pinned by the coordinator (2026-11-01), D6. A cell selects
# reflection issues CLIENT-SIDE with `i["class"] in REFLECTED_XSS_CLASSES` rather than
# passing `class=` to `scan.issues`, so adding an alias stays a one-line change here.
# The token is settled: `reflected-xss` is the only member today.
REFLECTED_XSS_CLASSES: tuple[str, ...] = ("reflected-xss",)

# Integration-shared edit, sanctioned by the coordinator (2026-11-01): T4's SHIPPED
# class names are the WebSocket vocabulary, and `ws-cswsh` / `ws-injection` are retired.
# The classes T4's checks declare (`crates/aitm-scan-ws/src/checks/*.rs`) are `cswsh`,
# `ws-auth-bypass`, `ws-input-reflection`, `ws-oversize-frame` and `ws-subprotocol`;
# injection over frames reports the family tokens `sqli` / `ssti` / `cmdi`.
# Check ids are still a separate vocabulary and differ from the class for CSWSH
# (id `cswsh`, class `cswsh`) and subprotocol (id `ws-subprotocol-observe`,
# class `ws-subprotocol`); for oversize the id and the class are both
# `ws-oversize-frame`, so both constants are spelled out below.
WS_CSWSH_CLASS = "cswsh"
WS_REFLECTION_CLASS = "ws-input-reflection"
WS_OVERSIZE_CLASS = "ws-oversize-frame"
WS_OVERSIZE_CHECK_ID = "ws-oversize-frame"

_CONTRACT = Path(repo_root()) / "crates" / "aitm" / "tests" / "frontends.rs"
_ERROR_CODE_RE = re.compile(r"scan: ([a-z0-9_]+):")
_HTTP_TIMEOUT = 5.0


class ContractDrift(RuntimeError):
    """The live `scan.*` tool set differs from the maintained EXPECTED_TOOLS contract."""


# ---------------------------------------------------------------------------
# verb contract
# ---------------------------------------------------------------------------


def _parse_expected_tools(path: Path) -> list[str]:
    """The tool names of the Rust EXPECTED_TOOLS contract (the regex of
    mcp/test_tool_list_complete.py, reused verbatim so both derive the same list)."""
    text = path.read_text(encoding="utf-8")
    strict = re.search(r"EXPECTED_TOOLS\s*:\s*\[\s*&str\s*;\s*(\d+)\s*\]\s*=\s*\[(.*?)\];", text, re.S)
    if strict:
        body = strict.group(2)
    else:
        loose = re.search(r"EXPECTED_TOOLS[^=]*=\s*\[(.*?)\];", text, re.S)
        if not loose:
            raise RuntimeError(f"EXPECTED_TOOLS not found in {path}")
        body = loose.group(1)
    body = re.sub(r"//[^\n]*", "", body)  # drop line comments before harvesting literals
    return re.findall(r'"([^"]+)"', body)


def expected_scan_verbs(client=None) -> list[str]:
    """The `scan.*` names of `crates/aitm/tests/frontends.rs` EXPECTED_TOOLS, in
    contract order. With `client`, raise ContractDrift unless that set equals the
    live `scan_tools(client)`."""
    if not _CONTRACT.exists():
        raise FileNotFoundError(f"EXPECTED_TOOLS contract not found: {_CONTRACT}")
    verbs = [n for n in _parse_expected_tools(_CONTRACT) if n.startswith("scan.")]
    if client is not None:
        live = scan_tools(client)
        if live != set(verbs):
            raise ContractDrift(
                "live scan.* tools differ from EXPECTED_TOOLS: "
                f"missing live={sorted(set(verbs) - live)} extra live={sorted(live - set(verbs))}")
    return verbs


def scan_tools(client) -> set[str]:
    """The live tools/list names starting `scan.`."""
    return {n for n in client.tool_names() if isinstance(n, str) and n.startswith("scan.")}


def require_verbs(client, *verbs: str) -> None:
    """SKIP 77 unless the live core advertises every verb; the reason names the
    missing one(s) (`missing verb scan.start`)."""
    live = set(client.tool_names())
    missing = [v for v in verbs if v not in live]
    if missing:
        skip("missing verb " + ", ".join(missing))


def require_lane(client, lane: str, role: str = "operator") -> None:
    """SKIP 77 unless `scan.checks` lists at least one check for `lane`
    (`http | ws | l4_stream | l4_packet`). Goes through `scan_call`, so the
    ledger records the `scan.checks` call at `role`."""
    require_verbs(client, "scan.checks")
    checks = _catalogue(client, role)
    if not any(lane in (c.get("lanes") or []) for c in checks):
        skip(f"lane {lane} has no scan.checks entry on this build")


def require_checks(client, *ids: str, role: str = "operator", needs: str | None = None) -> None:
    """SKIP 77 naming every check id of `ids` the live `scan.checks` catalogue lacks
    (a check that has not landed on this build is a loud SKIP, never a silent pass).
    `needs` names the track that lands them (appended to the reason). Goes through
    `scan_call`, so the ledger records the call at `role`."""
    require_verbs(client, "scan.checks")
    live = {c.get("id") for c in _catalogue(client, role)}
    missing = [i for i in ids if i not in live]
    if missing:
        reason = "missing check id " + ", ".join(missing) + " in scan.checks (not on this build)"
        skip(reason + (f"; {needs}" if needs else ""))


def lane_source(client, lane: str, role: str = "operator") -> str | None:
    """`scan.checks`' `lanes[].source` for `lane`: `"crate"` (a lane crate's lane),
    `"interim"` (the engine's own HTTP lane, which stands in until `aitm-scan-http`
    lands) or None when the core does not list the lane at all or predates the
    key (T1b, 2026-11-01: additive, so an older core simply reports None)."""
    require_verbs(client, "scan.checks")
    result = scan_call(client, role, "scan.checks", {})
    rows = result.get("lanes", []) if isinstance(result, dict) else []
    for row in rows:
        if isinstance(row, dict) and row.get("lane") == lane:
            return str(row.get("source", "crate"))
    return None


def require_crate_lane(client, lane: str, needs: str, role: str = "operator") -> None:
    """SKIP 77 while `lane` is served by the engine's interim lane rather than a
    lane crate; `needs` names the track that lands the crate. A core that does not
    report lane sources is left alone (the cell then asserts on real behaviour)."""
    if lane_source(client, lane, role) == "interim":
        skip(f"{lane} lane is the interim lane; {needs}")


def _catalogue(client, role: str) -> list[dict]:
    """The `checks` rows of one live `scan.checks` call, ledgered at `role`."""
    result = scan_call(client, role, "scan.checks", {})
    rows = result.get("checks", []) if isinstance(result, dict) else []
    return [c for c in rows if isinstance(c, dict)]


# ---------------------------------------------------------------------------
# call paths + ledger
# ---------------------------------------------------------------------------

_LEDGER: list[dict] = []
_LEDGER_LOCK = threading.Lock()
_NOTED_NO_DIR = False


def _cell_name() -> str:
    return Path(sys.argv[0]).stem


def _record(verb: str, role: str, outcome: str, code: str | None) -> None:
    with _LEDGER_LOCK:
        _LEDGER.append({"verb": verb, "role": role, "outcome": outcome, "code": code})


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}, got {role!r}")


def scan_error_code(msg: str) -> str | None:
    """The `<code>` of a `scan: <code>: <message>` error text (as surfaced through
    ToolError, e.g. `scan.status: scan: not_found: no job x` -> `not_found`), or
    None when the text is not in that form."""
    m = _ERROR_CODE_RE.search(msg or "")
    return m.group(1) if m else None


def _invoke(client, role: str, verb: str, args: dict | None, confirm: bool) -> Any:
    """The one call path behind `scan_call` and `scan_try`: check the role, call the
    verb (`client.confirm` two-phase handshake when `confirm`, else `client.call`),
    and record the outcome in the ledger. Raises ToolError on a refusal."""
    _check_role(role)
    args = args or {}
    try:
        result = client.confirm(verb, args) if confirm else client.call(verb, args)
    except ToolError as e:
        _record(verb, role, "error", scan_error_code(str(e)))
        raise
    _record(verb, role, "ok", None)
    return result


def scan_call(client, role: str, verb: str, args: dict | None = None, *, confirm: bool = False) -> Any:
    """Call a scan verb at `role`; record it in the ledger; raise ToolError on a
    refusal (the ledger row then carries the parsed code). `confirm=True` runs the
    operator two-phase `client.confirm` handshake instead of a plain call."""
    return _invoke(client, role, verb, args, confirm)


def scan_try(client, role: str, verb: str, args: dict | None = None, *,
             confirm: bool = False) -> tuple[str, Any]:
    """Like scan_call but returns ('ok', result) | ('error', message) -- for asserting
    that a verb is REFUSED for a role. Recorded in the ledger. `confirm=True` answers
    the operator confirm prompt first, so a refusal has to survive the confirmation
    instead of hiding behind it. A BusError (a prompt with no `confirm_token`) is a
    broken core, not a refusal, and propagates."""
    try:
        return ("ok", _invoke(client, role, verb, args, confirm))
    except ToolError as e:
        return ("error", str(e))


def ledger_flush() -> None:
    """Write `$AITM_E2E_LEDGER_DIR/<cell>.json` = {"cell", "calls": [...]}; with the
    dir unset (a cell run by hand) print one note and write nothing. Registered
    with atexit at import; safe to call again (rewrites the same file).

    No calls recorded AND no dir set means there is nothing to report: stay silent,
    so an importer that is not a cell (run.py, reading the roll-up) prints no note.
    With the dir set the file is written even when `calls` is empty -- "this cell
    called no scan verb" is a fact the roll-up should see."""
    global _NOTED_NO_DIR
    with _LEDGER_LOCK:
        calls = list(_LEDGER)
    ledger_dir = os.environ.get("AITM_E2E_LEDGER_DIR")
    if not ledger_dir:
        if calls and not _NOTED_NO_DIR:
            _NOTED_NO_DIR = True
            print(f"note: AITM_E2E_LEDGER_DIR unset; {len(calls)} scan call(s) not recorded "
                  "(run via tests/e2e/run.py for the verb ledger)", flush=True)
        return
    os.makedirs(ledger_dir, exist_ok=True)
    path = os.path.join(ledger_dir, f"{_cell_name()}.json")
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"cell": _cell_name(), "calls": calls}, fh, indent=1)
        fh.write("\n")
    os.replace(tmp, path)


atexit.register(ledger_flush)


# ---------------------------------------------------------------------------
# job helpers
# ---------------------------------------------------------------------------


def _sets_use_browser(d) -> bool:
    """Whether a profile or overrides dict pins `crawl.use_browser` itself."""
    return isinstance(d, dict) and isinstance(d.get("crawl"), dict) and "use_browser" in d["crawl"]


def _job_args(profile, profile_name, target, overrides) -> dict:
    given = [k for k, v in (("profile", profile), ("profile_name", profile_name), ("target", target)) if v is not None]
    if len(given) != 1:
        raise ValueError(f"scan.start takes exactly one of profile/profile_name/target, got {given}")
    args: dict = {}
    if profile is not None:
        args["profile"] = profile
    if profile_name is not None:
        args["profile_name"] = profile_name
    if target is not None:
        args["target"] = target
    # Sanctioned default (coordinator, 2026-11-01): a cell that does not ask for
    # the browser runs the client crawl. On a rig with obscura present the
    # engine's `use_browser: auto` would pick the browser, and a browser proxy
    # port shared with another session's core makes every navigation time out.
    # A cell that sets `crawl.use_browser` itself (profile or overrides) is
    # left alone (test_t2_crawl needs the real browser).
    if not _sets_use_browser(profile) and not _sets_use_browser(overrides):
        overrides = dict(overrides or {})
        crawl = dict(overrides.get("crawl") or {})
        crawl["use_browser"] = "never"
        overrides["crawl"] = crawl
    if overrides is not None:
        args["overrides"] = overrides
    return args


def start_job(client, role: str, *, profile: dict | None = None, profile_name: str | None = None,
              target: str | None = None, overrides: dict | None = None, confirm: bool = False) -> dict:
    """`scan.start` -> {job, status, clamped, lanes, dry_run?} (fixture scan.start.json).
    `confirm=True` runs `client.confirm` (L4 lanes / `intensity: intrusive`)."""
    return scan_call(client, role, "scan.start", _job_args(profile, profile_name, target, overrides), confirm=confirm)


def map_job(client, role: str, *, profile: dict | None = None, profile_name: str | None = None,
            target: str | None = None, overrides: dict | None = None, confirm: bool = False) -> dict:
    """`scan.map`: same params and result shape as `scan.start` (fixture scan.map.json)."""
    return scan_call(client, role, "scan.map", _job_args(profile, profile_name, target, overrides), confirm=confirm)


def cancel(client, role: str, job: str) -> dict:
    """`scan.cancel {job}` -> JobStatus with `state` cancelling | cancelled."""
    return scan_call(client, role, "scan.cancel", {"job": job})


def wait_terminal(client, role: str, job: str, timeout: float = 600.0, poll: float = 0.5) -> dict:
    """Poll `scan.status {job}` until `state` in {done, cancelled, failed}; return
    that JobStatus. TimeoutError (naming the last state/phase) otherwise."""
    deadline = time.monotonic() + timeout
    last: dict = {}
    while True:
        last = scan_call(client, role, "scan.status", {"job": job})
        if isinstance(last, dict) and last.get("state") in TERMINAL_STATES:
            return last
        if time.monotonic() >= deadline:
            state = last.get("state") if isinstance(last, dict) else last
            phase = last.get("phase") if isinstance(last, dict) else None
            raise TimeoutError(f"job {job} not terminal after {timeout}s (state={state!r}, phase={phase!r})")
        time.sleep(poll)


def run_to_terminal(client, role: str, *, timeout: float = 600.0, **start_kwargs) -> tuple[str, dict]:
    """`start_job(client, role, **start_kwargs)` then `wait_terminal`: the (job id,
    terminal JobStatus) pair. RuntimeError when `scan.start` answered without a job
    id (including an unanswered confirm prompt), so a cell never polls `None`."""
    started = start_job(client, role, **start_kwargs)
    job = started.get("job") if isinstance(started, dict) else None
    if not isinstance(job, str) or not job:
        raise RuntimeError(f"scan.start did not return a job id: {str(started)[:200]}")
    return job, wait_terminal(client, role, job, timeout=timeout)


def subscribe(client):
    """`flow.subscribe {}` on `client` (job lines fan out to every connection that
    holds a flow subscription; parent D3). Returns the client, now a subscriber for
    `collect_push`. Not a scan verb: not in the ledger."""
    client.call("flow.subscribe", {})
    return client


def _take_stashed_job_lines(subscriber) -> list[dict]:
    """Remove and return every stashed `notifications/aitm/job` message, in order."""
    stash = getattr(subscriber, "notifications", None)
    if not stash:
        return []
    taken = [m for m in stash if JOB_NOTIFICATION_METHOD in (m.get("method") or "")]
    if taken:
        stash[:] = [m for m in stash if JOB_NOTIFICATION_METHOD not in (m.get("method") or "")]
    return taken


def collect_push(subscriber, job: str, *, until_terminal: bool = True, timeout: float = 600.0) -> list[dict]:
    """Drain `notifications/aitm/job` lines for `job` from a subscribed client, in
    arrival order, as their `params` dicts ({job, kind, event, seq, ts_ms, status,
    issue?}; fixtures job.*.json). Stops at the first `event` in
    {finished, cancelled, failed} (when `until_terminal`) or at the timeout. Lines
    for OTHER jobs are re-stashed on `subscriber.notifications` before this returns,
    so a later `collect_push` for those jobs still sees them; notifications that are
    not job lines are never taken off the stash at all."""
    got: list[dict] = []
    others: list[dict] = []
    deadline = time.monotonic() + timeout

    def accept(msg) -> bool:
        params = msg.get("params") if isinstance(msg, dict) else None
        if not isinstance(params, dict) or params.get("job") != job:
            others.append(msg)  # another job's line: put it back before returning
            return False
        got.append(params)
        return until_terminal and params.get("event") in TERMINAL_EVENTS

    try:
        for m in _take_stashed_job_lines(subscriber):
            if accept(m):
                return got
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return got
            m = subscriber.wait_notification(JOB_NOTIFICATION_METHOD, timeout=max(0.05, remaining))
            if m is None:
                return got
            if accept(m):
                return got
            # a job line for another job: keep draining; also sweep anything the
            # client stashed meanwhile (wait_notification stashes non-matching lines)
            for s in _take_stashed_job_lines(subscriber):
                if accept(s):
                    return got
    finally:
        stash = getattr(subscriber, "notifications", None)
        if stash is not None and others:
            stash.extend(others)


def issues(client, role: str, **filters) -> list[dict]:
    """`scan.issues {filters}` walking `next_cursor` until it is null; the
    concatenated `issues` (IssueSummary dicts; fixture scan.issues.json)."""
    out: list[dict] = []
    args = {k: v for k, v in filters.items() if v is not None}
    seen_cursors: set[str] = set()
    while True:
        page = scan_call(client, role, "scan.issues", args)
        if not isinstance(page, dict):
            raise RuntimeError(f"scan.issues: expected an object, got {type(page).__name__}")
        out.extend(page.get("issues") or [])
        cursor = page.get("next_cursor")
        if not cursor or cursor in seen_cursors:
            return out
        seen_cursors.add(cursor)
        args = dict(args, cursor=cursor)


def issue(client, role: str, id: str) -> dict:  # noqa: A002  (the wire name is `id`)
    """`scan.issue {id}` -> the full Issue (fixture scan.issue.json)."""
    return scan_call(client, role, "scan.issue", {"id": id})


def brief(issue_rows, limit: int = 12) -> str:
    """A one-line digest of issue summaries for a diagnostic print:
    `N kind(s): <class>/<check_id>@<path>, ...` over the DISTINCT triples, `...`
    when more than `limit` of them. Carries no evidence, so no secret."""
    rows = sorted({(i.get("class"), i.get("check_id"), (i.get("location") or {}).get("path"))
                   for i in issue_rows if isinstance(i, dict)},
                  key=lambda r: tuple("" if x is None else str(x) for x in r))
    shown = ", ".join(f"{c}/{cid}@{path}" for c, cid, path in rows[:limit])
    return f"{len(rows)} kind(s): {shown}{' ...' if len(rows) > limit else ''}"


def sitemap(client, role: str, job: str, *, limit: int = 1024) -> tuple[list[dict], list[dict]]:
    """`scan.sitemap {job, limit}` walking `next_cursor` until it is null (like
    `issues()`): (nodes, points). Nodes are de-duplicated on `id` (falling back to
    `<method> <path_template>`); points are concatenated in page order."""
    nodes: dict[str, dict] = {}
    points: list[dict] = []
    cursor: str | None = None
    seen: set[str] = set()
    while True:
        args: dict = {"job": job, "limit": limit}
        if cursor:
            args["cursor"] = cursor
        page = scan_call(client, role, "scan.sitemap", args)
        if not isinstance(page, dict):
            raise RuntimeError(f"scan.sitemap: expected an object, got {type(page).__name__}")
        for n in page.get("nodes") or []:
            nodes[n.get("id") or f"{n.get('method')} {n.get('path_template')}"] = n
        points.extend(page.get("points") or [])
        cursor = page.get("next_cursor")
        if not cursor or cursor in seen:
            return list(nodes.values()), points
        seen.add(cursor)


# The privilege route the packet-lane proof accepts today (l4-capture-privilege spec
# §2.2 `l4.privilege`: a capability's `via` is `process` or `helper`). A tuple so the
# helper route is a one-line widening once that route is proven (T5 live proof, 2026-11-01).
PACKET_LANE_VIA: tuple[str, ...] = ("process",)

# The per-platform SKIP reason when packet capture is not granted to the core process.
# It names the PRODUCT's own privilege path (macOS: the Aitmproxy app's packet-capture
# helper, `aitm-l4-helper`; Linux: the packet-capture helper, or CAP_NET_RAW held by the
# core process on a test rig) -- never a third-party daemon and never a line to type.
PACKET_PERMISSION_PENDING: dict[str, str] = {
    "darwin": "packet-capture permission not granted (aitm-l4-helper phase 1 pending)",
    "linux": "packet-capture permission not granted (the core process has no CAP_NET_RAW; "
             "the packet-capture helper of spec 2026-10-31-l4-capture-privilege-design.md is pending)",
}
_PACKET_PERMISSION_PENDING_OTHER = (
    "packet-capture permission not granted (no packet-capture privilege path is defined for "
    "this platform by spec 2026-10-31-l4-capture-privilege-design.md)")


def _packet_permission_pending() -> str:
    return PACKET_PERMISSION_PENDING.get(sys.platform, _PACKET_PERMISSION_PENDING_OTHER)


def _privilege_gate(privilege: dict) -> None:
    """SKIP 77 unless the `l4.privilege` report says `capture` AND `inject` are
    `available` via a route in `PACKET_LANE_VIA`. Anything else is a SKIP with the
    report's own reason, never a FAIL: a core serving through the helper, or one still
    waiting for approval, is not broken."""
    caps = privilege.get("capabilities") if isinstance(privilege.get("capabilities"), dict) else {}
    for name in ("capture", "inject"):
        cap = caps.get(name) if isinstance(caps.get(name), dict) else {}
        if cap.get("state") != "available":
            reason = cap.get("reason") or f"l4.privilege reports {name} {cap.get('state')!r}"
            skip(f"{_packet_permission_pending()}; core says: {reason}")
    for name in ("capture", "inject"):
        via = caps[name].get("via")
        if via not in PACKET_LANE_VIA:
            skip(f"the packet-lane proof expects capture via process on this PR; the core reports "
                 f"via {via} (widen PACKET_LANE_VIA when that route is proven)")


def packet_lane_gate(client, *verbs: str, role: str = "operator") -> dict:
    """SKIP 77 unless this core can really run the L4 PACKET lane: every verb of
    `verbs` live, an `l4_packet` lane in `scan.checks`, the L4 module compiled in and
    enabled, and packet-capture privilege held by the core process.

    Privilege is read from `l4.privilege` (l4-capture-privilege spec §2.2) when the core
    advertises it: `capabilities.capture` and `capabilities.inject` must both be
    `{"state": "available", "via": <one of PACKET_LANE_VIA>}`. On a pre-p1b core without
    the verb it falls back to `l4.capture.status.available`. Either way a missing grant
    SKIPs with `PACKET_PERMISSION_PENDING[platform]; core says: <reason>`.

    Returns the `l4.capture.status` reply plus `"privilege"`: the `l4.privilege` reply,
    or None on a core without the verb. Neither holds a token."""
    if verbs:
        require_verbs(client, *verbs)
    require_lane(client, "l4_packet", role)
    tools = set(client.tool_names())
    if "l4.capture.status" not in tools:
        skip("the L4 module is not enabled on this core (no l4.capture.status): the packet lane "
             "needs l4.enabled and the feature-compiled l4 module")
    status, reply = client.try_call("l4.capture.status")
    if status != "ok" or not isinstance(reply, dict):
        skip(f"l4.capture.status did not answer with an availability object: {str(reply)[:200]}")
    privilege: dict | None = None
    if "l4.privilege" in tools:
        p_status, privilege = client.try_call("l4.privilege")
        if p_status != "ok" or not isinstance(privilege, dict):
            skip(f"l4.privilege did not answer with a privilege report: {str(privilege)[:200]}")
        _privilege_gate(privilege)
    elif reply.get("available") is not True:
        skip(f"{_packet_permission_pending()}; core says: {reply.get('reason')}")
    return {**reply, "privilege": privilege}


def read_capture_packets(client, flow_id: str, page: int = 500) -> list[dict]:
    """Every packet of an L4 capture flow, walking `l4.flow.get {offset, limit}`
    while the reply says `truncated`. Not a scan verb: not in the ledger."""
    out: list[dict] = []
    offset = 0
    while True:
        doc = client.call("l4.flow.get", {"id": flow_id, "offset": offset, "limit": page})
        if not isinstance(doc, dict):
            raise RuntimeError(f"l4.flow.get: expected an object, got {type(doc).__name__}")
        got = doc.get("packets") or []
        out.extend(got)
        nxt = doc.get("next_offset")
        if not doc.get("truncated") or not isinstance(nxt, int) or nxt <= offset or not got:
            return out
        offset = nxt


# ---------------------------------------------------------------------------
# the seeded target + its control-origin logs
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow nothing: a 3xx surfaces as an HTTPError the caller has to handle."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Control-origin, /services and canary traffic is loopback-only and must stay that
# way: an empty ProxyHandler makes urllib ignore `http_proxy` / `HTTPS_PROXY` /
# `ALL_PROXY` in the environment, so an observer read can never be routed off the
# machine -- or, worse, through the aitm proxy this suite is testing.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def post_form_direct(url: str, fields: dict) -> int:
    """`POST` a form to a target origin DIRECTLY (loopback, no proxy env, no redirect
    followed) and return the status the target answered (a 3xx is an answer)."""
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with _OPENER.open(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310  (loopback only)
            resp.read()
            return resp.status
    except urllib.error.HTTPError as e:
        e.read()
        e.close()
        return e.code


def _http_json(method: str, url: str, body: bytes | None = None) -> Any:
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with _OPENER.open(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310  (loopback only)
        raw = resp.read()
    return json.loads(raw.decode("utf-8")) if raw else None


# The seeded login of the test target (T10 spec D3 `/login`): these credentials are
# fixtures of the target, not a secret. The SESSION ID they return is never printed.
_LOGIN_FORM = b"user=alice&pass=wonderland"
_SET_COOKIE_RE = re.compile(r"session=([0-9a-f]{32}); HttpOnly; Path=/$")


def _session_from_set_cookie(set_cookie: str) -> str:
    """The 32-hex session id of `Set-Cookie: session=<32 hex>; HttpOnly; Path=/`.
    RuntimeError -- naming the SHAPE, never the header value -- when it differs."""
    m = _SET_COOKIE_RE.match(set_cookie or "")
    if not m:
        raise RuntimeError("login did not answer with `Set-Cookie: session=<32 hex>; HttpOnly; Path=/`")
    return m.group(1)


def login(base: str) -> str:
    """`POST /login` DIRECTLY to the target origin with the seeded credentials; the
    32-hex session id. Use when the login itself must NOT become a captured flow
    (`login_via_proxy` is the other half). Never prints the id or the cookie."""
    req = urllib.request.Request(base.rstrip("/") + "/login", data=_LOGIN_FORM, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with _OPENER.open(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310  (loopback only)
            status, headers = resp.status, resp.headers
            resp.read()
    except urllib.error.HTTPError as e:  # the seeded /login answers 302; we follow none
        status, headers = e.code, e.headers
        e.read()
        e.close()
    if status != 302:
        raise RuntimeError(f"POST /login -> 302 expected, got {status}")
    return _session_from_set_cookie(headers.get("Set-Cookie") or "")


def login_via_proxy(proxy_port: int, base: str) -> str:
    """`POST /login` THROUGH the aitm proxy (so the login is a captured flow the
    scanner can learn the session from); the 32-hex session id. Never printed."""
    r = via_proxy(proxy_port, "POST", base.rstrip("/") + "/login",
                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                  body=_LOGIN_FORM)
    if r.status != 302:
        raise RuntimeError(f"POST /login through the proxy -> 302 expected, got {r.status}")
    headers = {k.lower(): v for k, v in r.headers.items()}
    return _session_from_set_cookie(headers.get("set-cookie") or "")


def _authority(url: str | None) -> str | None:
    if not url:
        return None
    return urllib.parse.urlsplit(url).netloc


class TargetLogs:
    """The target's control origin (T10 spec D2): request / WS / L4 / connection
    logs with redacted headers, the observer every cell asserts on. Every getter is
    one GET with a 5 s timeout; `reset()` is the POST that clears the rings."""

    def __init__(self, control_url: str):
        self.control = control_url.rstrip("/")

    def _get(self, path: str) -> Any:
        return _http_json("GET", self.control + path)

    def http(self) -> list[dict]:
        """`/log/http` entries: kind `request` | `tls_handshake` (seq, ts_ms, conn_id, listener, ...)."""
        return (self._get("/log/http") or {}).get("entries", [])

    def ws(self) -> list[dict]:
        """`/log/ws` entries: kind `handshake` | `frame`."""
        return (self._get("/log/ws") or {}).get("entries", [])

    def l4(self, service: str | None = None) -> dict:
        """`/log/l4`: without `service` the whole `services` map
        (name -> {accepts, messages, closes, downtime}); with it, that service's
        entry (empty lists when the service has logged nothing)."""
        if service is None:
            return (self._get("/log/l4") or {}).get("services", {})
        doc = self._get("/log/l4?service=" + urllib.parse.quote(service, safe="")) or {}
        entry = (doc.get("services") or {}).get(service) or {}
        return {
            "accepts": entry.get("accepts", []),
            "messages": entry.get("messages", []),
            "closes": entry.get("closes", []),
            "downtime": entry.get("downtime", []),
        }

    def conns(self) -> list[dict]:
        """`/log/conns` entries: {conn_id, listener, alpn, peer, opened_ms, closed_ms, requests}."""
        return (self._get("/log/conns") or {}).get("entries", [])

    def reset(self) -> int:
        """`POST /reset`: clears every log; returns the last `seq` issued before the
        reset (pass it to `scanner_requests`)."""
        doc = _http_json("POST", self.control + "/reset", b"{}") or {}
        return int(doc.get("seq", 0))

    def last_seq(self) -> int:
        """The highest `seq` across the HTTP, WS and L4 logs right now (0 when empty)."""
        seqs = [0]
        seqs += [int(e.get("seq", 0)) for e in self.http()]
        seqs += [int(e.get("seq", 0)) for e in self.ws()]
        for entry in self.l4().values():
            for key in ("accepts", "messages", "closes", "downtime"):
                seqs += [int(e.get("seq", 0)) for e in (entry.get(key) or [])]
        return max(seqs)

    def scanner_requests(self, since_seq: int) -> list[dict]:
        """Request entries with `seq > since_seq`: probes carry no job marker, so
        "since the reset" is the discriminator (Architect's call C8)."""
        return [e for e in self.http() if e.get("kind") == "request" and int(e.get("seq", 0)) > since_seq]

    def handshakes(self, listener: str | None = None) -> list[dict]:
        """`tls_handshake` entries ({listener, alpn}), optionally for one listener (`tls` | `tls_h1`)."""
        return [e for e in self.http() if e.get("kind") == "tls_handshake"
                and (listener is None or e.get("listener") == listener)]

    def downtime(self, service: str) -> list[dict]:
        """The crash windows of one L4 service: [{seq, service, conn_id, down_at_ms, up_at_ms, trigger_sha256}]."""
        return self.l4(service)["downtime"]

    def messages(self, service: str, dir: str | None = None) -> list[dict]:  # noqa: A002  (wire name)
        """The L4 messages of one service ({dir in|out, len, sha256, verb, classified}), optionally one direction."""
        return [m for m in self.l4(service)["messages"] if dir is None or m.get("dir") == dir]


class ScanTarget:
    """`aitm-testtarget-serve --mode <mode> --port 0 [--tls-port 0 --tls-h1-port 0]
    [--control-port 0] [--l4] [--latency-ms N]` (T10 spec D1). Parses the stdout block
    `listening http://..`, `tls https://..`, `tls_h1 https://..`, `control http://..`,
    `ready`; L4 addresses come from `GET /services` on the control origin."""

    def __init__(self, mode: str = "vulnerable", *, tls: bool = True, control: bool = True,
                 l4: bool = False, start_timeout: float = 15.0,
                 latency_ms: int | None = None):
        if l4 and not control:
            raise ValueError("ScanTarget: l4=True needs control=True (--l4 needs --control-port)")
        bin_ = testtarget_bin()
        if not os.path.exists(bin_):
            raise FileNotFoundError(
                f"aitm-testtarget-serve not found at {bin_} "
                "(build it: cargo build -p aitm-testtarget, or set AITM_TESTTARGET_BIN)")
        self.mode = mode
        self.base: str | None = None
        self.tls_base: str | None = None
        self.tls_h1_base: str | None = None
        self.control: str | None = None
        self.logs: TargetLogs | None = None
        argv = [bin_, "--mode", mode, "--port", "0"]
        if tls:
            argv += ["--tls-port", "0", "--tls-h1-port", "0"]
        if control:
            argv += ["--control-port", "0"]
        if l4:
            argv.append("--l4")
        if latency_ms:
            # `--latency-ms N`: every HTTP response and WS frame waits N ms (not the
            # L4 speakers), so a UI can be observed while a scan is still running.
            argv += ["--latency-ms", str(int(latency_ms))]
        self.argv = argv
        self.proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True)
        self._lines: queue.Queue = queue.Queue()
        self._recent: deque[str] = deque(maxlen=200)
        # Keep the child's stdout pipe open and drained for its whole life, so it
        # never sees a broken pipe / a full pipe buffer after `ready`.
        self._reader = threading.Thread(target=self._drain, name="scan-target-stdout", daemon=True)
        self._reader.start()
        seen: list[str] = []
        deadline = time.monotonic() + start_timeout
        ready = False
        while not ready:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = self._lines.get(timeout=min(0.5, remaining))
            except queue.Empty:
                if self.proc.poll() is not None and self._lines.empty():
                    break
                continue
            if line is None:  # EOF: the child exited
                break
            seen.append(line)
            ready = self._parse_line(line)
        if not ready:
            self.stop()
            rc = self.proc.poll()
            raise RuntimeError(
                "aitm-testtarget-serve did not print `ready` within "
                f"{start_timeout}s (exit={rc}); lines seen:\n" + "\n".join(seen))
        if self.control:
            self.logs = TargetLogs(self.control)

    def _drain(self) -> None:
        out = self.proc.stdout
        try:
            for line in iter(out.readline, ""):
                text = line.rstrip("\n")
                self._recent.append(text)
                self._lines.put(text)
        except (OSError, ValueError):
            pass
        finally:
            self._lines.put(None)

    def _parse_line(self, line: str) -> bool:
        """Apply one stdout line; True on `ready`."""
        text = line.strip()
        if text == "ready":
            return True
        for prefix, attr in (("listening ", "base"), ("tls_h1 ", "tls_h1_base"),
                             ("tls ", "tls_base"), ("control ", "control")):
            if text.startswith(prefix):
                setattr(self, attr, text[len(prefix):].strip().rstrip("/"))
                return False
        return False

    # ---- addresses -----------------------------------------------------------

    @property
    def authority(self) -> str | None:
        return _authority(self.base)

    @property
    def tls_authority(self) -> str | None:
        return _authority(self.tls_base)

    @property
    def tls_h1_authority(self) -> str | None:
        return _authority(self.tls_h1_base)

    def recent_output(self) -> list[str]:
        """The last stdout/stderr lines the child printed (diagnostics)."""
        return list(self._recent)

    # ---- control origin --------------------------------------------------------

    def services(self) -> list[dict]:
        """`GET /services` on the control origin: [{name, proto, addr, role, alpn?, grammar?}]."""
        if not self.control:
            raise RuntimeError("ScanTarget started without a control origin (control=False)")
        return (_http_json("GET", self.control + "/services") or {}).get("services", [])

    def service(self, name: str) -> dict:
        """One `/services` row by name (KeyError naming the known services otherwise)."""
        rows = self.services()
        for s in rows:
            if s.get("name") == name:
                return s
        raise KeyError(f"no service {name!r}; known: {[s.get('name') for s in rows]}")

    # ---- lifecycle -----------------------------------------------------------

    def stop(self) -> None:
        p = self.proc
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        self._reader.join(timeout=2)

    def __enter__(self) -> "ScanTarget":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def until(pred, timeout: float, interval: float = 0.05) -> bool:
    """Poll `pred()` until it is truthy or `timeout` seconds pass; return the last
    result. A deadline poll replaces fixed sleeps so cells wait exactly as long as
    the condition needs."""
    deadline = time.monotonic() + timeout
    while True:
        result = pred()
        if result:
            return result
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval)


def boot_target(mode: str = "vulnerable", **kw) -> "ScanTarget":
    """`ScanTarget(mode, **kw)`, except a missing serve binary is one consistent
    loud SKIP (exit 77) instead of a traceback or a per-cell except block."""
    try:
        return ScanTarget(mode, **kw)
    except FileNotFoundError as e:
        skip(str(e))  # exits the process (77); nothing after this line runs


def split_addr(addr: str) -> tuple[str, int]:
    """`127.0.0.1:54321` -> ("127.0.0.1", 54321); `[::1]:54321` -> ("::1", 54321).
    `urlsplit("//" + addr)` does the IPv6 bracket handling, so nothing in the suite
    splits on the last colon -- which would cut an IPv6 address in half."""
    parts = urllib.parse.urlsplit("//" + str(addr))
    host, port = parts.hostname, parts.port
    if not host or port is None:
        raise ValueError(f"not a host:port address: {addr!r}")
    return host, port


def l4_endpoint(target: "ScanTarget", service: str, grammar: str | None = None) -> dict:
    """The `{ip, port, proto[, grammar]}` endpoint of one `/services` L4 row, ready
    for `scan.start` `overrides.target.l4`. `grammar` overrides the row's own; with
    neither, the endpoint carries no `grammar` key."""
    row = target.service(service)
    host, port = split_addr(row["addr"])
    endpoint = {"ip": host, "port": port, "proto": row.get("proto")}
    chosen = grammar if grammar is not None else row.get("grammar")
    if chosen:
        endpoint["grammar"] = chosen
    return endpoint


class Expectations:
    """A soft-assert collector for a long table-driven cell: one failing row must
    not hide the rest of the table. `expect` prints `[ok]` / `[FAIL]` and records the
    failures, `note` prints a diagnostic, `finish` ends the cell with ONE `fail()`
    naming them (and returns silently when every expectation held)."""

    def __init__(self, what: str = "expectation"):
        self.what = what
        self.failures: list[str] = []

    def expect(self, cond, msg: str, detail: Any = "") -> bool:
        """Record and keep going: True when `cond` held."""
        if cond:
            ok(msg)
            return True
        line = f"  [FAIL] {msg}"
        if detail != "":
            line += f"   -- {str(detail)[:300]}"
        print(line, flush=True)
        self.failures.append(msg)
        return False

    def note(self, label: str, value: Any) -> None:
        """One `note: <label> = <value>` diagnostic line (truncated at 400 chars)."""
        print(f"note: {label} = {str(value)[:400]}", flush=True)

    def finish(self, limit: int = 8) -> None:
        """`fail()` (exit 1) naming the first `limit` failures; a no-op when none."""
        if self.failures:
            fail(f"{len(self.failures)} {self.what}(s) failed: " + "; ".join(self.failures[:limit]))


# ---------------------------------------------------------------------------
# the out-of-scope canary
# ---------------------------------------------------------------------------


# At most this much request body is read off a canary hit: the body is never
# asserted on, only the fact of the hit, so there is no reason to buffer more.
_CANARY_MAX_BODY = 1024 * 1024


class Canary:
    """An out-of-scope loopback HTTP listener. A cell plants `link_html(path)` on the
    target (e.g. POST /comments on V) and then asserts `hits == []`: the crawler never
    followed a link outside the scope. Every hit is recorded as {method, path, headers}
    and answered 200 `canary`."""

    def __init__(self):
        self.port = free_port()
        self.hits: list[dict] = []
        self._lock = threading.Lock()
        canary = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _hit(self):
                # Record FIRST, read second: the hit is the whole point of this
                # listener, and it must survive a malformed Content-Length, a body
                # that never arrives, or a body too large to want in memory.
                with canary._lock:
                    canary.hits.append({
                        "method": self.command,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                    })
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                if length > 0:
                    self.rfile.read(min(length, _CANARY_MAX_BODY))
                body = b"canary"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = _hit

            def log_message(self, *args):  # quiet
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), _Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="canary", daemon=True)
        self._thread.start()

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def base(self) -> str:
        return f"http://{self.authority}"

    def link_html(self, path: str) -> str:
        """The `<a>` a cell posts into the target: `<a href="http://127.0.0.1:PORT{path}">leak</a>`."""
        return f'<a href="{self.base}{path}">leak</a>'

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "Canary":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# a WebSocket client that can carry extra upgrade headers
# ---------------------------------------------------------------------------


class WsClientWithHeaders(WsClient):
    """`aitm_e2e.ws.WsClient` plus two things the scanner cells need: arbitrary
    `extra_headers` on the proxied upgrade (`Origin`, `Cookie`, ...) and the
    `Sec-WebSocket-Key` it sent, kept as `.key` -- so a cell can prove a scanner lane
    re-dialled with a key of its OWN rather than replaying the cell's handshake.

    A header value of None is dropped, so `extra_headers={"Cookie": cookie}` with no
    cookie yields an anonymous upgrade. Cookie values are never printed here."""

    def __init__(self, proxy_host, proxy_port, origin_host, origin_port, path="/",
                 *, extra_headers: dict | None = None):
        self.key = base64.b64encode(os.urandom(16)).decode()
        self.sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
        self.rd = self.sock.makefile("rb")
        target = f"http://{origin_host}:{origin_port}{path}"
        lines = [
            f"GET {target} HTTP/1.1",
            f"Host: {origin_host}:{origin_port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {self.key}",
            "Sec-WebSocket-Version: 13",
        ]
        lines += [f"{name}: {value}" for name, value in (extra_headers or {}).items() if value is not None]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        status = self.rd.readline().decode().strip()
        if "101" not in status:
            raise BusError(f"ws upgrade failed: {status!r} {self.rd.read(400)!r}")
        while True:
            line = self.rd.readline()
            if line in (b"\r\n", b"\n", b""):
                break
