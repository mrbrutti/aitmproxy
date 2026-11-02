"""aitm_e2e.installed — find the OPERATOR'S installed aitmproxy, read its bus truth, and the
shared pieces every release-acceptance cell uses.

Release acceptance (spec 2026-11-01-release-acceptance-operator-journeys §D1/§D9) attaches to
what Matt actually runs: the macOS app's embedded core, found by its OWN command line (never
"the newest config in the temp dir": sibling sessions' dev bundles spawn cores there too), and
the Homebrew `aitm`. Read-only unless a cell calls `replay` (its restore trap). The operator
token is returned to the caller and must never be printed or logged (use `redact` or a
`StepWriter` with `secrets=`).

Shared across the cells (quality-I2):
  SERVICES, TOOLING, scutil(), service_state(), replay(before, run=), config_bypass(),
  config_scope_entries(), tooling_mentioned(), bypass_applied(scutil_text),
  StepWriter(path, expected_steps), port_holder()/port_holder_pid(), yes_set()/window_open(),
  append_leftover(), exit_on_term().
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Iterable

from .bus import BusClient, ToolError

APP_BUNDLE = "/Applications/Aitmproxy.app"
APP_CORE_CMDLINE = "/Applications/Aitmproxy.app/Contents/Resources/core/aitm"
INSTALLED_CLI = "/opt/homebrew/bin/aitm"
DATA_DIR = os.path.expanduser("~/Library/Application Support/aitmproxy")

TRUTH_VERBS = ("scope.list", "proxy.status", "capture.status", "proxy.system.status", "flow.table", "ca.status")

# The operator's two network services (spec D2) and the tooling hosts the bypass list must carry
# before any `yes` flip (spec Constraints, "Bypass is a precondition, not a promise").
SERVICES = ("Wi-Fi", "Display Ethernet")
TOOLING = ("*.anthropic.com", "api.anthropic.com", "claude.ai", "*.claude.ai", "github.com", "*.githubusercontent.com")

# Spec D1: `N/A` marks a step that does not exist on that surface or build; it is listed, never
# performed, and never holds the verdict (counted like PASS by exit_code / report.verdict).
RESULTS = ("PASS", "FAIL", "SKIP", "BLOCKED", "ERROR", "N/A")

# `^(\d+) /Applications/Aitmproxy.app/.../aitm --config <dir>/config.yaml` — anchored to the
# INSTALLED bundle so a `/tmp/claude/.../Aitmproxy.app` dev bundle never matches; `.+?` keeps a
# config dir with spaces whole.
_CORE_LINE = re.compile(r"^(\d+) /Applications/Aitmproxy\.app/Contents/Resources/core/aitm --config (.+?/config\.yaml)\s*$", re.M)


@dataclass
class EmbeddedCore:
    pid: int
    config_path: str
    bus_addr: str
    operator_token: str

    @property
    def launch_dir(self) -> str:
        return os.path.dirname(self.config_path)


def parse_core_lines(pgrep_out: str) -> list[tuple[int, str]]:
    """(pid, config path) for every INSTALLED-bundle core line in `pgrep -fl` output."""
    return [(int(m.group(1)), m.group(2)) for m in _CORE_LINE.finditer(pgrep_out)]


def read_core_config(pid: int, cfg: str) -> EmbeddedCore:
    """The per-launch config + bus.endpoint of one embedded core. A file that cannot be read (the
    core exited between pgrep and here, a permission change) is a RuntimeError naming the pid,
    never a bare OSError out of a cell."""
    token = ""
    ep_path = os.path.join(os.path.dirname(cfg), "bus.endpoint")
    try:
        with open(cfg, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("operator_token:"):
                    token = s.split(":", 1)[1].strip().strip('"').strip("'")
        with open(ep_path, encoding="utf-8") as f:
            addr = f.read().strip()
    except OSError as e:
        raise RuntimeError(f"embedded core {pid} config unreadable: {e}") from e
    return EmbeddedCore(pid=pid, config_path=cfg, bus_addr=addr, operator_token=token)


def find_embedded_core() -> EmbeddedCore | None:
    """The installed app's embedded core, or None when the app is not running."""
    out = subprocess.run(["pgrep", "-fl", APP_CORE_CMDLINE], capture_output=True, text=True).stdout
    hits = parse_core_lines(out)
    if not hits:
        return None
    if len(hits) > 1:
        raise RuntimeError(f"{len(hits)} installed-bundle cores are running; refusing to pick one")
    pid, cfg = hits[0]
    return read_core_config(pid, cfg)


def embedded_secret_lines(core: EmbeddedCore) -> list[str]:
    """The secret VALUES of the embedded core's per-launch config (operator + agent token), for
    the runner's leak grep. Returned, never printed by this module."""
    out = []
    with open(core.config_path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if re.match(r"^(operator_token|token):", s):
                v = s.split(":", 1)[1].strip().strip('"').strip("'")
                if v:
                    out.append(v)
    return out


def connect(core: EmbeddedCore, client_name: str = "aitm-acceptance") -> BusClient:
    host, port = core.bus_addr.rsplit(":", 1)
    return BusClient(host, int(port), core.operator_token, client_name=client_name).connect()


def bus_truth(bus: BusClient) -> dict:
    """The six readings of §D1 (plus ca.status), as one dict; errors kept as strings."""
    out: dict = {}
    for verb in TRUTH_VERBS:
        try:
            out[verb] = bus.call(verb, {})
        except ToolError as e:
            out[verb] = {"error": str(e)}
    return out


def audit_tail(n: int = 20, stream: str = "audit.jsonl") -> list[dict]:
    """Last n lines of the durable audit. The file is SHARED by every core on the default data
    dir (sibling dev cores included): callers filter by pid/connection_id, never trust the tail."""
    p = os.path.join(DATA_DIR, stream)
    if not os.path.exists(p):
        return []
    rows = []
    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f.readlines()[-n:]:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line.rstrip()[:200]})
    return rows


def redact(text: str, *secrets: str) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "<redacted>")
    return re.sub(r"#t=[^&\s\"']+", "#t=<redacted>", text)


def app_version() -> str | None:
    r = subprocess.run(
        ["defaults", "read", os.path.join(APP_BUNDLE, "Contents/Info.plist"), "CFBundleShortVersionString"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() or None


def port_holder(port: int) -> str | None:
    """`COMMAND pid N` of the LISTEN holder of a loopback TCP port, or None."""
    r = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True)
    lines = r.stdout.splitlines()
    if len(lines) < 2:
        return None
    parts = lines[1].split()
    return f"{parts[0]} pid {parts[1]}"


def port_holder_pid(port: int) -> int | None:
    h = port_holder(port)
    if not h:
        return None
    try:
        return int(h.rsplit(" ", 1)[1])
    except ValueError:
        return None


# ----------------------------------------------------------------------------- system proxy

def sh(*argv: str, timeout: float = 30) -> str:
    r = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    return r.stdout + (("\n[stderr] " + r.stderr.strip()) if r.returncode else "")


def scutil() -> str:
    return sh("scutil", "--proxy")


def service_state() -> dict:
    """Per-service before-state, exactly what `replay` puts back."""
    return {svc: {"http": sh("networksetup", "-getwebproxy", svc), "https": sh("networksetup", "-getsecurewebproxy", svc)} for svc in SERVICES}


def replay(before: dict, run: Callable = subprocess.run) -> list[str]:
    """Put each service back exactly as recorded (never a blanket off); returns the failures.
    `run` is subprocess.run or a scripted stand-in (tests)."""
    errs: list[str] = []
    for svc, d in before.items():
        for kind, text in d.items():
            en = re.search(r"Enabled: (\w+)", text)
            host = re.search(r"Server: ([^\s]*)", text)
            port = re.search(r"Port: (\d+)", text)
            setp = "-setwebproxy" if kind == "http" else "-setsecurewebproxy"
            setstate = "-setwebproxystate" if kind == "http" else "-setsecurewebproxystate"
            if host and port and host.group(1):
                r = run(["networksetup", setp, svc, host.group(1), port.group(1)], capture_output=True, text=True)
                if r.returncode:
                    errs.append(f"{svc} {setp}: {r.stderr.strip()}")
            r = run(["networksetup", setstate, svc, "on" if en and en.group(1) == "Yes" else "off"], capture_output=True, text=True)
            if r.returncode:
                errs.append(f"{svc} {setstate}: {r.stderr.strip()}")
    return errs


def record_state_file(path: str) -> None:
    """scutil + per-service state to a JSON file (for a bash cell's EXIT trap)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"scutil": scutil(), "services": service_state()}, f)


def replay_file(path: str) -> int:
    """Replay the state recorded by record_state_file iff `scutil --proxy` differs now. 0 = identical
    (nothing done or restored), 1 = replayed but still different / a networksetup error."""
    with open(path, encoding="utf-8") as f:
        rec = json.load(f)
    if scutil() == rec["scutil"]:
        return 0
    errs = replay(rec["services"])
    return 0 if not errs and scutil() == rec["scutil"] else 1


def _inline_list(rest: str) -> list[str]:
    return [x.strip().strip("\"'") for x in rest.strip("[]").split(",") if x.strip()]


def config_bypass(path: str | None = None) -> list[str]:
    """The operator's `system_proxy.bypass` entries from config.yaml (the TUI/web precondition).
    Reads only that block; never copies the file."""
    p = path or os.path.join(DATA_DIR, "config.yaml")
    if not os.path.exists(p):
        return []
    out: list[str] = []
    inside = sub = False
    with open(p, encoding="utf-8") as f:
        for line in f:
            if line.startswith("system_proxy:"):
                inside = True
                continue
            if inside and line.strip() and not line.startswith(" "):
                break
            if not inside:
                continue
            s = line.strip()
            if s.startswith("bypass:"):
                sub = True
                rest = s.split(":", 1)[1].strip()
                if rest.startswith("["):
                    out += _inline_list(rest)
                continue
            if sub and s.startswith("- "):
                out.append(s[2:].strip().strip("\"'"))
            elif sub and s and not s.startswith("- "):
                sub = False
    return out


def config_scope_entries(path: str | None = None) -> list[str]:
    """The `scope:` block of the operator's config.yaml as exact strings (quotes stripped), for
    the pre-existing-host decision (security S2: a host persisted in his config is HIS even when
    the surface has not rendered it yet, so it is never removed). Reads only that block."""
    p = path or os.path.join(DATA_DIR, "config.yaml")
    if not os.path.exists(p):
        return []
    out: list[str] = []
    inside = False
    with open(p, encoding="utf-8") as f:
        for line in f:
            if line.startswith("scope:"):
                inside = True
                rest = line.split(":", 1)[1].strip()
                if rest.startswith("["):
                    out += _inline_list(rest)
                continue
            if inside and line.strip() and not line.startswith(" "):
                break
            if inside and line.strip().startswith("- "):
                out.append(line.strip()[2:].strip().strip("\"'"))
    return out


def tooling_mentioned(reading: str | Iterable[str]) -> bool:
    """True iff the bypass READING (a config list, the app's Settings field, any text) names at
    least one TOOLING host as a whole entry — the precondition every `yes` flip checks before
    writing (spec Constraints, "Bypass is a precondition, not a promise")."""
    if isinstance(reading, str):
        entries = {x.strip().strip("\"'") for x in re.split(r"[,\s]+", reading) if x.strip()}
    else:
        entries = {str(x).strip().strip("\"'") for x in reading}
    return any(t in entries for t in TOOLING)


def bypass_applied(scutil_text: str, hosts: Iterable[str] = TOOLING) -> bool:
    """True iff `scutil --proxy`'s ExceptionsList carries at least one of `hosts`, compared as
    whole entries (`*.anthropic.com` is matched by `*.anthropic.com`, never by the TLD `com`
    and never by a mention outside the ExceptionsList block)."""
    m = re.search(r"ExceptionsList : <array> \{(.*?)\n\s*\}", scutil_text, re.S)
    if not m:
        return False
    entries = {ln.split(":", 1)[1].strip() for ln in m.group(1).splitlines() if ":" in ln}
    return any(h in entries for h in hosts)


# ----------------------------------------------------------------------------- cells

def yes_set() -> set[str]:
    return set(filter(None, os.environ.get("ACCEPT_YES", "").split(",")))


def window_open() -> bool:
    return os.environ.get("ACCEPT_WINDOW") == "1"


def keep_scope() -> bool:
    return os.environ.get("ACCEPT_KEEP_SCOPE") == "1"


def exit_on_term() -> None:
    """Turn SIGTERM (the runner's watchdog, a Ctrl-C'd run.sh's TERM) into SystemExit(2) so a
    cell's `finally` (restore trap, Scope cleanup, step file) still runs. Every cell calls this
    first thing in main(). Default SIGTERM disposition kills the interpreter outright."""
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(2))


def append_leftover(out_dir: str, host: str, state: str, cell: str) -> None:
    """One line per host the run added: `<host>\t<removed|kept|failed>\t<cell>` (D8 §6)."""
    with open(os.path.join(out_dir, "leftovers.txt"), "a", encoding="utf-8") as f:
        f.write(f"{host}\t{state}\t{cell}\n")


class StepWriter:
    """The per-cell step log: `<id>\t<result>\t<observed>\t<bus truth>\t<explains>` rows to a
    FRESH file, tabs escaped, secrets redacted, one row per expected id at the end (`SKIP not
    reached` for anything the cell never got to), and the contract exit code (0 / 77 / 1)."""

    def __init__(self, path: str, expected_steps: Iterable[str], secrets: Iterable[str] = ()):
        self.path = path
        self.expected = tuple(expected_steps)
        self.secrets = [s for s in secrets if s]
        self.results: dict[str, str] = {}
        self._finished = False
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8"):
            pass

    def add_secret(self, s: str) -> None:
        if s and s not in self.secrets:
            self.secrets.append(s)

    def clean(self, s: str) -> str:
        """Redact every known secret (and any `#t=` value), flatten tabs/newlines."""
        return redact(str(s), *self.secrets).replace("\t", " ").replace("\n", " ")

    def redact(self, s: str) -> str:
        """Redact only (keeps newlines): for files written beside the steps."""
        return redact(str(s), *self.secrets)

    def step(self, sid: str, result: str, observed: str = "", truth: str = "", explains: str = "") -> None:
        if result not in RESULTS:
            raise ValueError(f"{sid}: unknown result {result!r} (one of {RESULTS})")
        self.results[sid] = result
        obs = self.clean(observed)
        print(f"{sid:8s} {result:7s} {obs[:160]}", flush=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("\t".join([sid, result, obs, self.clean(truth), self.clean(explains)]) + "\n")

    def finish(self) -> None:
        if self._finished:
            return
        self._finished = True
        for sid in self.expected:
            if sid not in self.results:
                self.step(sid, "SKIP", "not reached")

    def exit_code(self) -> int:
        """ERROR (2) > FAIL (1) > SKIP/BLOCKED (77) > PASS = N/A (0), the same order run.sh and
        report.py rank the run."""
        vals = set(self.results.values())
        if "ERROR" in vals:
            return 2
        if "FAIL" in vals:
            return 1
        if vals & {"SKIP", "BLOCKED"}:
            return 77
        return 0
