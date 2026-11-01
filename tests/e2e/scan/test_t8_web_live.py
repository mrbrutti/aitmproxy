#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=web
"""The web Scan surface works end to end on a REAL run (umbrella UI-1/2/3/5; T8 child
spec): this cell wraps T8's `apps/web/scripts/scan-live.mjs --json`, which spawns a
real `aitm web` on a real core with `aitm-testtarget-serve` (vulnerable) as the target,
drives the real web UI in headless Chrome with real input events over the real `/bus`
bridge, keeps a second "witness" bus connection, and prints per-step results.

What this cell asserts, from the script's own result JSON (the LAST stdout line):
  - the process exited 0 and `fail == 0`;
  - every step is PASS, except that a GAP is tolerated only for the step-8 L4 rows
    (T8's note: a core built without an L4 lane cannot run the L4 confirm flow);
  - the run covered the surface: at least 20 recorded results and the step groups
    01..08 all appear.

SKIPs 77, naming what is missing: the script (T8's PR not on this build), `node`
below 22, Chrome (`$CHROME` or `/Applications/Google Chrome.app`), the `aitm` or
`aitm-testtarget-serve` binary, the built web app (`apps/web/dist/index.html`; the
core embeds it at build time), or a core without the scanner engine (`scan.start`
absent from `tools/list`, probed on a throwaway core before the run).

This cell calls no `scan.*` verb itself (its ledger file is `calls: []`): the web UI
and the script's witness do, over their own bus connections. Never prints a token:
operator URLs carry `#t=<token>`, which is redacted from everything echoed here.
Binds loopback ports: run from a real shell, not the Claude sandbox.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, repo_root, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import require_verbs  # noqa: E402
from aitm_e2e.target import testtarget_bin  # noqa: E402

SCRIPT = Path("apps/web/scripts/scan-live.mjs")
WEB_DIST = Path("apps/web/dist/index.html")
DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
MIN_NODE_MAJOR = 22
# The script runs one standard scan, a second job for the cancel, and the L4 flow;
# 15 min is generous for a debug-build core on a loaded machine.
RUN_TIMEOUT_S = 900.0
# The engine verbs the Scan panel drives (T8 child spec, D-T8.x); their absence is
# the pre-T1b build, a loud SKIP rather than a red step 01.
ENGINE_VERBS = ("scan.start", "scan.status", "scan.cancel", "scan.issues", "scan.issue",
                "scan.sitemap", "scan.profile.list")
MIN_RESULTS = 20
STEP_GROUPS = ("01", "02", "03", "04", "05", "06", "07", "08")
# GAP is tolerated for the L4 rows only (step 8), per T8's note for this cell.
GAP_ALLOWED_PREFIX = "08"
TOKEN_RE = re.compile(r"(#t=|token=)[A-Za-z0-9._~-]+")


def redact(text: str) -> str:
    return TOKEN_RE.sub(r"\1<redacted>", text)


def node_major() -> int | None:
    node = shutil.which("node")
    if not node:
        return None
    try:
        out = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.match(r"v(\d+)", out.strip())
    return int(m.group(1)) if m else None


def aitm_bin() -> str:
    return os.environ.get("AITM_BIN") or os.path.join(repo_root(), "target", "debug", "aitm")


def preflight() -> dict:
    """Every SKIP reason, checked before anything is spawned; returns the run env."""
    root = Path(repo_root())
    if not (root / SCRIPT).exists():
        skip(f"{SCRIPT} is not on this build (T8's web Scan surface PR not merged)")
    major = node_major()
    if major is None:
        skip("node not found: the live web run needs Node >= 22")
    if major < MIN_NODE_MAJOR:
        skip(f"node v{major} is too old: the live web run needs Node >= {MIN_NODE_MAJOR}")
    chrome = os.environ.get("CHROME") or DEFAULT_CHROME
    if not Path(chrome).exists():
        skip(f"Chrome not found at {chrome} (set CHROME): the live web run drives headless Chrome")
    if not Path(aitm_bin()).exists():
        skip(f"aitm binary not found at {aitm_bin()} (set AITM_BIN or cargo build -p aitm)")
    if not Path(testtarget_bin()).exists():
        skip(f"aitm-testtarget-serve not found at {testtarget_bin()} (cargo build -p aitm-testtarget)")
    if not (root / WEB_DIST).exists():
        skip(f"{WEB_DIST} is missing: the web app is not built (npm run build in apps/web, then rebuild aitm)")
    return {**os.environ, "AITM_BIN": aitm_bin(), "AITM_TESTTARGET_BIN": testtarget_bin(), "CHROME": chrome}


def probe_engine() -> None:
    """A throwaway core: SKIP 77 unless the Scan panel's engine verbs are on the build."""
    cfg = CoreConfig(proxy_port=free_port())
    core = Aitm.server(cfg)
    op = None
    try:
        op = BusClient.operator(core)
        require_verbs(op, *ENGINE_VERBS)
        ok(f"the core offers the engine verbs the Scan panel drives ({len(ENGINE_VERBS)} probed)")
    finally:
        if op:
            op.close()
        core.stop()


def run_script(env: dict) -> tuple[int, dict, str]:
    """`node apps/web/scripts/scan-live.mjs --json` from the repo root; (exit, summary, stderr tail)."""
    proc = subprocess.run(
        [shutil.which("node") or "node", str(SCRIPT), "--json"],
        cwd=repo_root(), env=env, capture_output=True, text=True, timeout=RUN_TIMEOUT_S,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    summary: dict = {}
    if lines:
        try:
            summary = json.loads(lines[-1])
        except json.JSONDecodeError:
            summary = {}
    tail = "\n".join(proc.stderr.splitlines()[-40:])
    return proc.returncode, summary, tail


def main() -> int:
    section("preflight: script, node, Chrome, binaries, built web app")
    env = preflight()
    ok("script, node >= 22, Chrome, aitm, aitm-testtarget-serve and the built web app are present")

    section("probe: does this core offer the scanner engine")
    probe_engine()

    section("act: the real web Scan surface, driven in headless Chrome by T8's script")
    try:
        code, summary, tail = run_script(env)
    except subprocess.TimeoutExpired:
        fail(f"scan-live.mjs did not finish within {RUN_TIMEOUT_S:.0f} s")
        return 1
    results = summary.get("results") or []
    for r in results:
        detail = redact(str(r.get("detail") or ""))
        print(f"  {str(r.get('status')).ljust(4)} {r.get('step')}" + (f" -- {detail[:160]}" if detail else ""),
              flush=True)
    if not summary or code != 0 or summary.get("fail", 1):
        print("  --- script log tail ---", flush=True)
        print(redact(tail), flush=True)

    section("assert: zero FAIL, GAP only on the L4 rows, the surface covered")
    check(isinstance(summary.get("fail"), int), f"the last stdout line is the result JSON (got {sorted(summary)})")
    check(code == 0, f"scan-live.mjs exited 0 (got {code})")
    check(summary.get("fail") == 0,
          f"no FAIL step (fail={summary.get('fail')}, pass={summary.get('pass')}, gap={summary.get('gap')})")
    gaps = [r.get("step") for r in results if r.get("status") == "GAP"]
    check(all(str(s).startswith(GAP_ALLOWED_PREFIX) for s in gaps),
          f"a GAP is tolerated only on the step-{GAP_ALLOWED_PREFIX} L4 rows (gaps: {gaps})")
    check(len(results) >= MIN_RESULTS, f"at least {MIN_RESULTS} recorded results (got {len(results)})")
    seen_groups = {str(r.get("step"))[:2] for r in results}
    missing = [g for g in STEP_GROUPS if g not in seen_groups]
    check(not missing, f"every step group 01..08 appears (missing {missing})")
    passed = sum(1 for r in results if r.get("status") == "PASS")
    ok(f"web Scan surface live: {passed} PASS, {len(gaps)} GAP (L4 rows), 0 FAIL over {len(results)} steps; "
       f"screenshots in {summary.get('shots')}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
