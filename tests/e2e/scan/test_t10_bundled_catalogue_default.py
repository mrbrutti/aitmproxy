#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""The default build loads the bundled Rhai catalogue (umbrella amendment 60).

T3's 2b live run found that a core built into a private `/tmp` target dir finds no
`scripts/bundled` (the core discovers the catalogue through `AITM_BUNDLED_SCRIPTS`,
a `share/aitm/scripts` beside the executable, or a dev-checkout fallback relative
to the executable), so every e2e core ran with no bundled scripts and three cells
SKIPped as if the catalogue were absent. The harness now points every spawned
core at `<repo>/scripts/bundled` unless the caller overrides it; this cell is the
regression detector: on a plain `CoreConfig` core,

  - `script.list` names the three passive scripts (`missing-hsts`, `missing-csp`,
    `ws-cleartext-transport`) and at least a dozen scripts in all, none with a
    load error;
  - `scan.checks` lists at least one check whose `origin.kind` is `bundled` (the
    converted active scripts), beside the native ones.

SKIPs 77 only when `script.list` or `scan.checks` is absent from `tools/list` (a
core without the Rhai plugin or without the scanner engine). Calls `scan.checks`
(ledgered at `operator`) and no other scan verb. No token is printed.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, free_port, ok, repo_root, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import require_verbs, scan_call  # noqa: E402

PASSIVE = ("missing-hsts", "missing-csp", "ws-cleartext-transport")
MIN_SCRIPTS = 12


def main() -> int:
    work = tempfile.mkdtemp(prefix="aitm-e2e-bundled-default-")
    core = op = None
    try:
        section("a plain CoreConfig core (no rhai.scripts_dir, no env override)")
        bundled_dir = os.path.join(repo_root(), "scripts", "bundled")
        check(os.path.isdir(bundled_dir), f"the checkout carries scripts/bundled ({bundled_dir})")
        cfg = CoreConfig(proxy_port=free_port(), findings_dir=os.path.join(work, "findings"))
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, "script.list", "scan.checks")

        section("script.list: the bundled passive scripts are loaded")
        scripts = op.call("script.list") or []
        names = sorted(str(s.get("name") or s.get("id") or "") for s in scripts)
        missing = [p for p in PASSIVE if p not in names]
        check(not missing, f"script.list names {list(PASSIVE)} (missing {missing}; {len(names)} scripts loaded)")
        check(len(names) >= MIN_SCRIPTS, f"at least {MIN_SCRIPTS} bundled scripts loaded (got {len(names)})")
        errors = [(s.get("name") or s.get("id"), s.get("last_error")) for s in scripts if s.get("last_error")]
        check(not errors, f"no bundled script reports a load error ({errors[:3]})")

        section("scan.checks: at least one bundled-origin check beside the natives")
        checks = scan_call(op, "operator", "scan.checks", {})["checks"]
        origins = sorted({str((c.get("origin") or {}).get("kind")) for c in checks})
        bundled = [c.get("id") for c in checks if (c.get("origin") or {}).get("kind") == "bundled"]
        check(bool(bundled), f"scan.checks lists a bundled-origin check (origins seen: {origins}; "
                             f"bundled ids: {bundled[:6]})")
        ok(f"default build: {len(names)} bundled scripts, {len(bundled)} bundled checks of {len(checks)}")
        return 0
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
