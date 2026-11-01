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
import json
import os
import queue
import re
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

from . import free_port, repo_root, skip
from .bus import ToolError
from .target import testtarget_bin

__all__ = [
    "SCAN_VERBS_D3",
    "REFLECTED_XSS_CLASSES",
    "WS_CSWSH_CLASS",
    "WS_INJECTION_CLASS",
    "WS_AUTH_BYPASS_CLASS",
    "JOB_NOTIFICATION_METHOD",
    "TERMINAL_STATES",
    "TERMINAL_EVENTS",
    "ContractDrift",
    "expected_scan_verbs",
    "scan_tools",
    "require_verbs",
    "require_lane",
    "scan_call",
    "scan_try",
    "scan_error_code",
    "start_job",
    "map_job",
    "cancel",
    "wait_terminal",
    "subscribe",
    "collect_push",
    "issues",
    "issue",
    "ScanTarget",
    "TargetLogs",
    "Canary",
    "ledger_flush",
]

# The 18 verbs of the parent spec D3, for documentation and cross-checks only. The
# expectation a cell or run.py uses is `expected_scan_verbs()`, parsed from the
# maintained Rust contract, never this tuple.
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

# The WebSocket issue families (D3 manifest rows `ws-cswsh` / `ws-input-reflection`,
# whose classes are these). Check ids are a separate vocabulary: `ws-oversize-frame`
# is a check id, not a class.
WS_CSWSH_CLASS = "ws-cswsh"
WS_INJECTION_CLASS = "ws-injection"
WS_AUTH_BYPASS_CLASS = "ws-auth-bypass"

_CONTRACT = Path(repo_root()) / "crates" / "aitm" / "tests" / "frontends.rs"
_ERROR_CODE_RE = re.compile(r"scan: ([a-z_]+):")
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
            return []
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
    if "scan.checks" not in set(client.tool_names()):
        skip("missing verb scan.checks")
    result = scan_call(client, role, "scan.checks", {})
    checks = result.get("checks", []) if isinstance(result, dict) else []
    if not any(lane in (c.get("lanes") or []) for c in checks if isinstance(c, dict)):
        skip(f"lane {lane} has no scan.checks entry on this build")


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


def scan_call(client, role: str, verb: str, args: dict | None = None, *, confirm: bool = False) -> Any:
    """Call a scan verb at `role`; record it in the ledger; raise ToolError on a
    refusal (the ledger row then carries the parsed code). `confirm=True` runs the
    operator two-phase `client.confirm` handshake instead of a plain call."""
    _check_role(role)
    args = args or {}
    try:
        result = client.confirm(verb, args) if confirm else client.call(verb, args)
    except ToolError as e:
        _record(verb, role, "error", scan_error_code(str(e)))
        raise
    _record(verb, role, "ok", None)
    return result


def scan_try(client, role: str, verb: str, args: dict | None = None) -> tuple[str, Any]:
    """Like scan_call but returns ('ok', result) | ('error', message) -- for
    asserting that a verb is REFUSED for a role. Recorded in the ledger."""
    _check_role(role)
    status, payload = client.try_call(verb, args or {})
    if status == "ok":
        _record(verb, role, "ok", None)
    else:
        _record(verb, role, "error", scan_error_code(str(payload)))
    return status, payload


def ledger_flush() -> None:
    """Write `$AITM_E2E_LEDGER_DIR/<cell>.json` = {"cell", "calls": [...]}; with the
    dir unset (a cell run by hand) print one note and write nothing. Registered
    with atexit at import; safe to call again (rewrites the same file)."""
    global _NOTED_NO_DIR
    with _LEDGER_LOCK:
        calls = list(_LEDGER)
    ledger_dir = os.environ.get("AITM_E2E_LEDGER_DIR")
    if not ledger_dir:
        if not _NOTED_NO_DIR:
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
    for other jobs and other notification kinds are left alone / stashed."""
    got: list[dict] = []
    deadline = time.monotonic() + timeout

    def accept(msg) -> bool:
        params = msg.get("params") if isinstance(msg, dict) else None
        if not isinstance(params, dict) or params.get("job") != job:
            return False
        got.append(params)
        return until_terminal and params.get("event") in TERMINAL_EVENTS

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


def issues(client, role: str, **filters) -> list[dict]:
    """`scan.issues {filters}` walking `next_cursor` until it is null; the
    concatenated `issues` (IssueSummary dicts; fixture scan.issues.json)."""
    out: list[dict] = []
    args = {k: v for k, v in filters.items() if v is not None}
    seen_cursors: set[str] = set()
    while True:
        page = scan_call(client, role, "scan.issues", args)
        if not isinstance(page, dict):
            raise ToolError(f"scan.issues: expected an object, got {type(page).__name__}")
        out.extend(page.get("issues") or [])
        cursor = page.get("next_cursor")
        if not cursor or cursor in seen_cursors:
            return out
        seen_cursors.add(cursor)
        args = dict(args, cursor=cursor)


def issue(client, role: str, id: str) -> dict:  # noqa: A002  (the wire name is `id`)
    """`scan.issue {id}` -> the full Issue (fixture scan.issue.json)."""
    return scan_call(client, role, "scan.issue", {"id": id})


# ---------------------------------------------------------------------------
# the seeded target + its control-origin logs
# ---------------------------------------------------------------------------


def _http_json(method: str, url: str, body: bytes | None = None) -> Any:
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310  (loopback only)
        raw = resp.read()
    return json.loads(raw.decode("utf-8")) if raw else None


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
    [--control-port 0] [--l4]` (T10 spec D1). Parses the stdout block
    `listening http://..`, `tls https://..`, `tls_h1 https://..`, `control http://..`,
    `ready`; L4 addresses come from `GET /services` on the control origin."""

    def __init__(self, mode: str = "vulnerable", *, tls: bool = True, control: bool = True,
                 l4: bool = False, start_timeout: float = 15.0):
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


# ---------------------------------------------------------------------------
# the out-of-scope canary
# ---------------------------------------------------------------------------


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
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                with canary._lock:
                    canary.hits.append({
                        "method": self.command,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                    })
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
