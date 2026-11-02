#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""T1-6: `scan.checks` is the real catalogue.

  - Core A (stock): every entry carries full `CheckMeta` (the D2/D3 wire keys),
    the interim HTTP lane's two native classes are present, and -- only once T3
    has converted the bundled active scripts to `reg.add_check` -- at least one
    entry declares `origin.kind` bundled.
  - Core B: an operator-authored `e2e-custom.rhai` dropped in `rhai.scripts_dir`
    registers through `load(reg)` / `reg.add_check(...)` and appears in
    `scan.checks` after the core boots.
  - Core C: the same script MINUS the required `kinds` key fails to load — the
    check is absent from `scan.checks` and the core's stderr names `kinds`
    (parent spec D4: "Missing or invalid meta is a load error naming the key").

Observers: the live `scan.checks` result, `script.list` (what is actually
loaded), the bundled active scripts on disk, and the core's own stderr.

SKIPs 77 when the live core lacks `scan.checks`. The bundled `origin.kind`
sub-assertion alone is noted and skipped when no bundled active script declares
`reg.add_check` (T3's conversion is not on this build); every other assertion,
including the custom `add_check` half of T1-6, still runs.
"""
# Integration-shared edit: this cell is re-pinned only by the track's integration
# task (plan 2026-10-31-aitmproxy-scanner-v2-t1b, Task 19), never by a build task.
import os
import shutil
import sys
import tempfile
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, repo_root, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    require_verbs,
    scan_call,
)

# The CheckMeta keys every catalogue entry must carry (plan task B5).
REQUIRED_META_KEYS = (
    "id", "name", "class", "lanes", "kinds", "intensity", "cost",
    "technique", "severity", "confidence_max", "origin",
)
# The interim HTTP lane's two native payload classes (parent spec D5/D6). The
# catalogue is asserted as a SUPERSET of these: a build with more lanes or more
# converted scripts adds ids, and that is not a regression.
NATIVE_IDS = {"xss-reflected", "open-redirect"}
# Where the bundled active scripts live; a script only reaches the catalogue once
# it declares `reg.add_check` (T3's conversion), so the cell reads the files on
# disk rather than assuming the conversion has landed.
ACTIVE_DIR = Path(repo_root()) / "scripts" / "bundled" / "active"


def bundled_scripts_declaring_add_check() -> list[str]:
    """Names of `scripts/bundled/active/*.rhai` that declare `reg.add_check`."""
    return [f.name for f in sorted(ACTIVE_DIR.glob("*.rhai"))
            if "reg.add_check" in f.read_text(encoding="utf-8", errors="replace")]

# A human-readable operator check (Matt's rule: Rhai scripts are for people to
# read). It never probes — the closure reports `clean` for every point — so the
# cell asserts on the CATALOGUE without changing what a scan does.
SCRIPT_HEADER = """\
// {name}.rhai — a minimal operator-authored catalogue entry used by
// tests/e2e/scan/test_t1_catalogue.py (AC T1-6). It registers one check through
// `load(reg)` and never sends a probe: every insertion point comes back `clean`.
const NAME = "{name}";
const API  = "1";

fn load(reg) {{
    reg.add_check(#{{
        id: "{name}",
        name: "{title}",
        class: "e2e",
        lanes: ["http"],
{kinds_line}\
        intensity: "light",
        cost: "light",
        technique: "reflected",
        severity: "info",
        confidence_max: "tentative",
        needs_baseline: false,
        description: "e2e",
    }}, |point| #{{
        outcome: "clean",
        confidence: "tentative",
        evidence: #{{}},
        detail: "ok",
    }});
}}
"""
KINDS_LINE = '        kinds: ["query"],\n'


def write_script(dirpath: str, name: str, title: str, with_kinds: bool) -> str:
    body = SCRIPT_HEADER.format(
        name=name, title=title, kinds_line=KINDS_LINE if with_kinds else "")
    path = os.path.join(dirpath, f"{name}.rhai")
    Path(path).write_text(body, encoding="utf-8")
    return path


def checks_of(client) -> list[dict]:
    result = scan_call(client, "operator", "scan.checks", {})
    return (result or {}).get("checks", []) if isinstance(result, dict) else []


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-scan-t1-cat-")
    try:
        with boot_target("vulnerable") as v:
            # --- core A: stock catalogue -------------------------------------
            cfg_a = CoreConfig(
                proxy_port=free_port(),
                scope_entries=[v.authority],
                findings_dir=os.path.join(work, "core-a-findings"),
            )
            with Aitm.server(cfg_a) as core_a:
                op = BusClient.operator(core_a)
                require_verbs(op, "scan.checks")

                section("core A: every scan.checks entry carries full CheckMeta")
                checks = checks_of(op)
                check(len(checks) > 0, f"scan.checks listed {len(checks)} entr(y/ies)")
                missing = {}
                for c in checks:
                    absent = [k for k in REQUIRED_META_KEYS if k not in c]
                    if absent:
                        missing[c.get("id", "<no id>")] = absent
                check(not missing,
                      f"every entry has {list(REQUIRED_META_KEYS)} (offenders: {missing})")

                ids = {c.get("id") for c in checks}
                check(NATIVE_IDS.issubset(ids),
                      f"the interim lane's native checks {sorted(NATIVE_IDS)} are in the "
                      f"catalogue (missing {sorted(NATIVE_IDS - ids)})")

                section("core A: bundled active scripts appear with origin.kind bundled")
                status, loaded = op.try_call("script.list", {})
                bundled_active = []
                if status == "ok":
                    bundled_active = [row for row in (loaded or [])
                                      if isinstance(row, dict)
                                      and "bundled" in str(row.get("path", ""))
                                      and "active" in str(row.get("path", ""))]
                registering = bundled_scripts_declaring_add_check()
                if bundled_active and registering:
                    origins = [c.get("origin", {}).get("kind") for c in checks]
                    check("bundled" in origins,
                          f"{len(bundled_active)} bundled active script(s) loaded and "
                          f"{len(registering)} declare reg.add_check, so at least one check "
                          f"has origin.kind == bundled "
                          f"(origins seen: {sorted(set(origins))})")
                elif bundled_active:
                    ok(f"note: {len(bundled_active)} bundled active script(s) are loaded but "
                       f"none of the {len(list(ACTIVE_DIR.glob('*.rhai')))} scripts in "
                       f"{ACTIVE_DIR.name}/ declares reg.add_check, so none can reach the "
                       "catalogue; T3's add_check conversion is not on this build and the "
                       "origin.kind == bundled assertion is skipped")
                else:
                    ok(f"note: script.list ({status}) shows no bundled active scripts on "
                       "this build; the origin.kind == bundled assertion is not applicable")
                op.close()

            # --- core B: an operator script registers a check -----------------
            scripts_b = os.path.join(work, "core-b-scripts")
            os.makedirs(scripts_b, exist_ok=True)
            write_script(scripts_b, "e2e-custom", "E2E custom", with_kinds=True)
            cfg_b = CoreConfig(
                proxy_port=free_port(),
                scope_entries=[v.authority],
                findings_dir=os.path.join(work, "core-b-findings"),
                rhai_scripts_dir=scripts_b,
            )
            with Aitm.server(cfg_b) as core_b:
                op2 = BusClient.operator(core_b)
                section("core B: e2e-custom.rhai is in scan.checks after boot")
                entries = {c.get("id"): c for c in checks_of(op2)}
                check("e2e-custom" in entries,
                      f"e2e-custom is in the catalogue (ids: {sorted(entries)[:12]}...)")
                custom = entries.get("e2e-custom") or {}
                if custom:
                    check(custom.get("class") == "e2e",
                          f"e2e-custom class is e2e, got {custom.get('class')!r}")
                    check(custom.get("lanes") == ["http"],
                          f"e2e-custom lanes are ['http'], got {custom.get('lanes')!r}")
                    check(custom.get("kinds") == ["query"],
                          f"e2e-custom kinds are ['query'], got {custom.get('kinds')!r}")
                    check((custom.get("origin") or {}).get("kind") == "custom",
                          f"e2e-custom origin.kind is custom, got "
                          f"{(custom.get('origin') or {}).get('kind')!r}")
                op2.close()

            # --- core C: a script missing `kinds` fails to load ---------------
            scripts_c = os.path.join(work, "core-c-scripts")
            os.makedirs(scripts_c, exist_ok=True)
            write_script(scripts_c, "e2e-broken", "E2E broken", with_kinds=False)
            cfg_c = CoreConfig(
                proxy_port=free_port(),
                scope_entries=[v.authority],
                findings_dir=os.path.join(work, "core-c-findings"),
                rhai_scripts_dir=scripts_c,
            )
            section("core C: a check missing `kinds` is a load error naming `kinds`")
            try:
                core_c = Aitm.server(cfg_c)
            except RuntimeError as e:
                # The core refused to boot on the bad script: the error itself must
                # name the missing key, and no catalogue can hold e2e-broken.
                check("kinds" in str(e),
                      f"the core's refusal to boot names `kinds`: {str(e)[-400:]!r}")
                return
            with core_c:
                op3 = BusClient.operator(core_c)
                ids_c = {c.get("id") for c in checks_of(op3)}
                check("e2e-broken" not in ids_c,
                      f"e2e-broken is absent from the catalogue (ids: {sorted(ids_c)[:12]}...)")
                err = core_c.stderr_text()
                check("kinds" in err,
                      f"the core's stderr names the missing key `kinds` "
                      f"(tail: {err[-400:]!r})")
                op3.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
