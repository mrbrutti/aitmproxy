#!/usr/bin/env python3
"""The aitmproxy end-to-end test runner.

Discovers suites under tests/e2e/<surface>/ and runs each as a subprocess,
classifying by EXIT CODE: 0 = PASS, 77 = SKIP, anything else = FAIL. Exits
non-zero iff a required (non-skipped) suite FAILs. SKIPs are LOUD (reason + why)
and never read as green.

A suite is any file named test_*.py (run with python3) or *.sh (run with bash)
under a surface directory. A suite may tag itself in its first ~20 lines:

    # e2e: tier=manual        -> skipped unless --manual (needs a human present)
    # e2e: needs=obscura      -> informational (the suite itself SKIPs 77 if absent)

Usage:
    python3 tests/e2e/run.py [SURFACE ...] [--manual] [--list]

  SURFACE   limit to these surface dirs (e.g. `web proxy`); default: all
  --manual  include tier=manual suites and let them prompt the operator
  --list    list discovered suites and exit
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

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


def main() -> int:
    args = sys.argv[1:]
    manual = "--manual" in args
    do_list = "--list" in args
    surfaces = [a for a in args if not a.startswith("--")]

    suites = discover(surfaces)
    if do_list:
        for s in suites:
            tag = f"  [{','.join(f'{k}={v}' for k, v in s['tags'].items())}]" if s["tags"] else ""
            print(f"{s['surface']}/{s['name']}{tag}")
        return 0

    if not suites:
        print("no e2e suites found (looked for test_*.py / *.sh under tests/e2e/<surface>/)")
        return 1

    child_env = dict(os.environ)
    child_env["PYTHONPATH"] = E2E_DIR + os.pathsep + child_env.get("PYTHONPATH", "")
    if manual:
        child_env["AITM_E2E_MANUAL"] = "1"

    results = []
    for s in suites:
        label = f"{s['surface']}/{s['name']}"
        if s["tags"].get("tier") == "manual" and not manual:
            print(f"SKIP  {label}  (tier=manual; re-run with --manual)")
            results.append(("skip", label, "tier=manual"))
            continue
        print(f"RUN   {label} ...", flush=True)
        t0 = time.time()
        proc = subprocess.run(
            s["runner"], cwd=E2E_DIR, env=child_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        dt = time.time() - t0
        code = proc.returncode
        if code == 0:
            print(f"PASS  {label}  ({dt:.1f}s)")
            results.append(("pass", label, ""))
        elif code == SKIP_EXIT:
            reason = _last_line(proc.stdout, "[SKIP]")
            print(f"SKIP  {label}  ({reason})")
            results.append(("skip", label, reason))
        else:
            print(f"FAIL  {label}  (exit {code}, {dt:.1f}s)")
            print(_indent(proc.stdout))
            results.append(("fail", label, f"exit {code}"))

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
    return 1 if nfail else 0


def _last_line(text: str, marker: str) -> str:
    for line in reversed(text.splitlines()):
        if marker in line:
            return line.split(marker, 1)[1].strip()
    return "skipped"


def _indent(text: str) -> str:
    return "\n".join("    " + ln for ln in text.splitlines())


if __name__ == "__main__":
    sys.exit(main())
