#!/usr/bin/env python3
"""The aitmproxy end-to-end test runner.

Discovers suites under tests/e2e/<surface>/ and runs each as a subprocess,
classifying by EXIT CODE: 0 = PASS, 77 = SKIP, anything else = FAIL. Exits
non-zero iff a required (non-skipped) suite FAILs. SKIPs are LOUD (reason + why)
and never read as green. After a run that includes the `scan` surface it prints the
per-verb scan ledger (which cells called each scan.* verb, at which role).

A suite is any file named test_*.py (run with python3) or *.sh (run with bash)
under a surface directory. A suite may tag itself in its first ~20 lines:

    # e2e: tier=manual        -> skipped unless --manual (needs a human present)
    # e2e: needs=obscura      -> informational (the suite itself SKIPs 77 if absent)

Usage:
    python3 tests/e2e/run.py [SURFACE ...] [--jobs N] [--build] [--manual] [--list]

  SURFACE   limit to these surface dirs (e.g. `web proxy`); default: all
  --jobs N  run up to N suites at once (default 4, capped at 6). Each suite picks
            its own free ports so parallel runs don't collide. --manual forces 1.
  --build   cargo build -p aitm -p aitm-testtarget first (preflight). Without it,
            a missing aitm is fatal and a missing aitm-testtarget-serve warns.
  --shared-core  boot ONE core + a seeded aitm-testtarget and export AITM_BUS_ADDR /
            AITM_BUS_TOKEN / AITM_BUS_OPERATOR_TOKEN / AITM_PROXY_ADDR /
            AITM_TARGET_URL so cells that connect to a runner-provided core (and
            otherwise skip) run against it. Cells isolate via per-connection labels.
  --manual  include tier=manual suites and let them prompt the operator
  --list    list discovered suites and exit
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

E2E_DIR = os.path.dirname(os.path.abspath(__file__))
SKIP_EXIT = 77
EXCLUDE_DIRS = {"lib", "aitm_e2e", "__pycache__"}


def parse_tags(path: str) -> dict:
    tags: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                i = line.find("# e2e:")
                if i >= 0:
                    for part in line[i + len("# e2e:"):].strip().split():
                        if "=" in part:
                            k, v = part.split("=", 1)
                            tags[k.strip()] = v.strip()
    except OSError:
        pass
    return tags


def discover(surfaces: list[str]) -> list[dict]:
    suites: list[dict] = []
    for surface in sorted(os.listdir(E2E_DIR)):
        sdir = os.path.join(E2E_DIR, surface)
        if not os.path.isdir(sdir) or surface in EXCLUDE_DIRS:
            continue
        if surfaces and surface not in surfaces:
            continue
        for name in sorted(os.listdir(sdir)):
            path = os.path.join(sdir, name)
            if not os.path.isfile(path):
                continue
            if name.startswith("test_") and name.endswith(".py"):
                runner = [sys.executable, path]
            elif name.endswith(".sh"):
                runner = ["bash", path]
            else:
                continue
            suites.append({
                "surface": surface,
                "name": name,
                "path": path,
                "runner": runner,
                "tags": parse_tags(path),
            })
    return suites


def run_suite(suite: dict, child_env: dict) -> tuple:
    """Run one suite as a subprocess; classify by exit code. Thread-safe (no shared
    state): safe to call concurrently from the --jobs pool."""
    label = f"{suite['surface']}/{suite['name']}"
    t0 = time.time()
    proc = subprocess.run(
        suite["runner"], cwd=E2E_DIR, env=child_env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    dt = time.time() - t0
    code = proc.returncode
    if code == 0:
        return ("pass", label, "", dt, proc.stdout)
    if code == SKIP_EXIT:
        return ("skip", label, _last_line(proc.stdout, "[SKIP]"), dt, proc.stdout)
    return ("fail", label, f"exit {code}", dt, proc.stdout)


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(E2E_DIR))


def preflight(build: bool) -> None:
    """Ensure the binaries the suites need exist. `aitm` is required by every
    suite; `aitm-testtarget-serve` only by ca/poc/findings/scripting/scan, so a
    miss there is a loud warning, not a hard stop. `--build` builds both first."""
    repo = _repo_root()
    aitm = os.environ.get("AITM_BIN") or os.path.join(repo, "target", "debug", "aitm")
    tgt = (os.environ.get("AITM_TESTTARGET_BIN")
           or os.path.join(repo, "target", "debug", "aitm-testtarget-serve"))
    if build:
        print("preflight: cargo build -p aitm -p aitm-testtarget ...", flush=True)
        if subprocess.run(["cargo", "build", "-p", "aitm", "-p", "aitm-testtarget"],
                          cwd=repo).returncode != 0:
            print("FATAL: cargo build failed", flush=True)
            sys.exit(1)
    if not os.path.exists(aitm):
        print(f"FATAL: aitm binary missing: {aitm}\n"
              "  build it: cargo build -p aitm  (or pass --build, or set AITM_BIN)", flush=True)
        sys.exit(1)
    if not os.path.exists(tgt):
        print(f"WARNING: aitm-testtarget-serve missing: {tgt}\n"
              "  ca/poc/findings/scripting/scan will FAIL without it — "
              "build: cargo build -p aitm-testtarget  (or --build, or set AITM_TESTTARGET_BIN)",
              flush=True)


def _boot_shared_core(child_env: dict):
    """Boot ONE real core + a seeded aitm-testtarget and export the AITM_BUS_* /
    AITM_PROXY_ADDR / AITM_TARGET_URL env the shared-core cells read (they never boot
    their own core; they isolate via per-connection labels + unique markers). Returns
    an object with .stop(). Scope is loopback-wide with agent-widen so cells reach
    their own upstreams.

    AITM_TARGET_URL is a real seeded aitm-testtarget (what every cell's runner
    contract documents it as), not a bare echo: cells that exercise real routes
    (POST /comments -> 302, GET /comments listing, /search reflection) need it, and
    echo-only cells boot their own aitm_e2e.upstream.Upstream regardless."""
    sys.path.insert(0, E2E_DIR)
    sys.path.insert(0, os.path.join(E2E_DIR, "lib"))
    from aitm_e2e import free_port  # noqa: E402
    from aitm_e2e.config import CoreConfig  # noqa: E402
    from aitm_e2e.core import Aitm  # noqa: E402
    from seeded import TestTarget  # noqa: E402

    target = TestTarget("vulnerable")
    cfg = CoreConfig(proxy_port=free_port(), scope_entries=["127.0.0.1", target.host()],
                     allow_agent_widen=True, ssl_insecure=True)
    core = Aitm.server(cfg)
    host, port = core.bus_addr
    child_env["AITM_BUS_ADDR"] = f"{host}:{port}"
    child_env["AITM_BUS_TOKEN"] = cfg.agent_token
    child_env["AITM_BUS_OPERATOR_TOKEN"] = cfg.operator_token
    child_env["AITM_PROXY_ADDR"] = f"127.0.0.1:{cfg.proxy_port}"
    child_env["AITM_TARGET_URL"] = target.base_url
    print(f"shared-core: bus {host}:{port}, proxy 127.0.0.1:{cfg.proxy_port}, "
          f"target {target.base_url} (seeded aitm-testtarget)", flush=True)

    class _Shared:
        def stop(self):
            core.stop()
            target.stop()

    return _Shared()


def main() -> int:
    args = sys.argv[1:]
    manual = "--manual" in args
    do_list = "--list" in args
    build = "--build" in args
    shared_core = "--shared-core" in args
    jobs = 4
    surfaces: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--jobs":
            i += 1
            if i < len(args):
                try:
                    jobs = int(args[i])
                except ValueError:
                    pass
        elif a.startswith("--jobs="):
            try:
                jobs = int(a.split("=", 1)[1])
            except ValueError:
                pass
        elif not a.startswith("--"):
            surfaces.append(a)
        i += 1
    jobs = 1 if manual else max(1, min(jobs, 6))

    suites = discover(surfaces)
    if do_list:
        for s in suites:
            tag = f"  [{','.join(f'{k}={v}' for k, v in s['tags'].items())}]" if s["tags"] else ""
            print(f"{s['surface']}/{s['name']}{tag}")
        return 0

    if not suites:
        print("no e2e suites found (looked for test_*.py / *.sh under tests/e2e/<surface>/)")
        return 1

    preflight(build)

    child_env = dict(os.environ)
    child_env["PYTHONPATH"] = E2E_DIR + os.pathsep + child_env.get("PYTHONPATH", "")
    if manual:
        child_env["AITM_E2E_MANUAL"] = "1"
    ledger_dir = tempfile.mkdtemp(prefix="aitm-e2e-ledger-")
    child_env["AITM_E2E_LEDGER_DIR"] = ledger_dir

    shared = _boot_shared_core(child_env) if shared_core else None
    nfail = 0
    try:
        results: list[tuple] = []
        to_run = []
        for s in suites:
            label = f"{s['surface']}/{s['name']}"
            if s["tags"].get("tier") == "manual" and not manual:
                print(f"SKIP  {label}  (tier=manual; re-run with --manual)")
                results.append(("skip", label, "tier=manual"))
            else:
                to_run.append(s)

        def emit(r: tuple) -> None:
            kind, label, why, dt, out = r
            if kind == "pass":
                print(f"PASS  {label}  ({dt:.1f}s)", flush=True)
            elif kind == "skip":
                print(f"SKIP  {label}  ({why})", flush=True)
            else:
                print(f"FAIL  {label}  (exit after {dt:.1f}s)", flush=True)
                print(_indent(out), flush=True)
            results.append((kind, label, why))

        if jobs == 1:
            for s in to_run:
                print(f"RUN   {s['surface']}/{s['name']} ...", flush=True)
                emit(run_suite(s, child_env))
        else:
            print(f"running {len(to_run)} suites, up to {jobs} at once ...", flush=True)
            with ThreadPoolExecutor(max_workers=jobs) as ex:
                futures = [ex.submit(run_suite, s, child_env) for s in to_run]
                for fut in as_completed(futures):
                    emit(fut.result())

        npass = sum(1 for r in results if r[0] == "pass")
        nskip = sum(1 for r in results if r[0] == "skip")
        nfail = sum(1 for r in results if r[0] == "fail")
        print("\n" + "=" * 60)
        print(f"e2e summary: {npass} pass, {nskip} skip, {nfail} fail")
        for kind, label, why in results:
            if kind == "fail":
                print(f"  FAIL {label} ({why})")
            elif kind == "skip":
                print(f"  skip {label} ({why})")
        if any(s["surface"] == "scan" for s in to_run):
            print_ledger(ledger_dir)
    finally:
        if shared:
            shared.stop()
        shutil.rmtree(ledger_dir, ignore_errors=True)
    return 1 if nfail else 0


def print_ledger(ledger_dir: str) -> None:
    """The per-verb scan ledger (T10 spec D7 / parent Verification "Ledger"): one
    line per `scan.*` verb of the EXPECTED_TOOLS contract naming the cells that
    called it and at which role, `UNCALLED` otherwise, then `called/total`. Cells
    write `$AITM_E2E_LEDGER_DIR/<cell>.json` via aitm_e2e.scan.ledger_flush(). A
    called verb that is NOT in the contract is still listed, flagged, so a call the
    contract does not know about is never hidden (it does not count toward total).

    The roll-up is a REPORT, not a gate: anything that goes wrong reading it prints
    one line and leaves the run's own pass/skip/fail summary standing."""
    try:
        _print_ledger(ledger_dir)
    except Exception as e:  # noqa: BLE001  (never let a report break the run)
        print(f"ledger: could not print ({e})", flush=True)


def _print_ledger(ledger_dir: str) -> None:
    if E2E_DIR not in sys.path:
        sys.path.insert(0, E2E_DIR)
    # The runner is not a cell: it records no scan call, and aitm_e2e.scan's atexit
    # flush is silent with nothing recorded, so importing it here changes no output.
    from aitm_e2e.scan import ROLES, expected_scan_verbs  # noqa: E402

    expected = expected_scan_verbs()
    calls: dict[str, dict[str, list[str]]] = {}
    for name in sorted(os.listdir(ledger_dir)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(ledger_dir, name), encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"ledger: unreadable {name}: {e}", flush=True)
            continue
        cell = doc.get("cell") or name[: -len(".json")]
        for c in doc.get("calls") or []:
            verb, role = c.get("verb"), c.get("role")
            if not isinstance(verb, str) or not isinstance(role, str):
                continue
            cells = calls.setdefault(verb, {}).setdefault(role, [])
            if cell not in cells:
                cells.append(cell)

    def line(verb: str) -> str:
        roles = calls.get(verb)
        if not roles:
            return f"  {verb:<26}UNCALLED"
        order = [r for r in ROLES if r in roles] + sorted(r for r in roles if r not in ROLES)
        return f"  {verb:<26}" + " | ".join(f"{role}: {', '.join(roles[role])}" for role in order)

    print("\nscan verb ledger (spec D3):")
    for verb in expected:
        print(line(verb))
    for verb in sorted(set(calls) - set(expected)):
        print(line(verb) + "  (not in EXPECTED_TOOLS)")
    called = sum(1 for v in expected if v in calls)
    print(f"ledger: {called}/{len(expected)} scan verbs called by at least one cell", flush=True)


def _last_line(text: str, marker: str) -> str:
    for line in reversed(text.splitlines()):
        if marker in line:
            return line.split(marker, 1)[1].strip()
    return "skipped"


def _indent(text: str) -> str:
    return "\n".join("    " + ln for ln in text.splitlines())


if __name__ == "__main__":
    sys.exit(main())
