#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http serial
"""The harness config emitters reach a real core (T10 spec S8, S9; parent AC
T10-2), observed on the config file on disk, the profile file on disk,
`l4.scope.list`, and the target's own request log.

Three real observers, in this order (the L4 half runs on any build with the L4
module, so it is exercised before the scanner SKIP):

  1. Pure emitter literals (no core): `ScannerSection(...).to_yaml()` contains the
     exact S8 `scanner:` block, and `l4_inject_entry()` yields the exact S9
     `l4:` / `scope:` block.
  2. Core B, `CoreConfig(l4_enabled=True, l4_scope_entries=[l4_inject_entry()])`:
     the core parses the `l4:` block and `l4.scope.list` reports one entry with
     `interface == "*"`, `direction == "outbound"`, `capability == "inject"`.
  3. A probe core WITHOUT `scanner=` runs `require_verbs` (SKIP 77 on a pre-T1b
     build), then core A `CoreConfig(scanner=ScannerSection(ceilings={probes:10},
     default_profile="standard", max_jobs=1), scope_entries=[V])`: its written
     config carries the `scanner:` section, `scan.start {target: V}` reports
     `clamped` naming `budget.probes` applied `10`, the job is listed, the builtin
     `standard` profile lists with `builtin: true`, a cloned `e2e-tiny` profile is
     saved to / read from / deleted off disk, and the job's probe ceiling holds at
     the origin (`V.logs.scanner_requests` count <= 10 + a crawl allowance).

`scanner:` is an unknown top-level key to a pre-T1b core (`deny_unknown_fields`
in `crates/aitm/src/config_file.rs`): such a core FAILS TO BOOT rather than
ignoring it. The probe core (no `scanner:`) carries the `require_verbs` SKIP, so
core A (which has the section) is booted only once the verbs are known to exist.

`serial`: boots several cores in sequence and writes a profile file. Binds
loopback ports: run from a real shell, not the Claude sandbox. Exit 0 pass / 1
fail / 77 skip. Never prints a token.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig, ScannerSection, l4_inject_entry  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)

PROFILE_VERBS = (
    "scan.start", "scan.status", "scan.list",
    "scan.profile.list", "scan.profile.get", "scan.profile.save", "scan.profile.delete",
)
CEILING = 10
# `probes.sent <= 10` is the exact clamp proof; the at-origin assertion
# corroborates it by bounding TOTAL requests at `10 probes + the crawl`. The crawl
# is a separate phase the probe ceiling does not cap: it fetches up to the profile's
# `crawl.max_pages` pages plus form submissions / per-origin baselines. We derive
# the crawl bound from the live `standard` profile's own `crawl.max_pages` (never a
# guessed constant, so the assertion cannot flake if the profile changes) and add a
# margin for forms + baselines.
CRAWL_MARGIN = 40
JOB_TIMEOUT = 600.0

# The exact S8 / S9 literal blocks (spec acceptance criteria 8, 9).
S8_BLOCK = (
    "scanner:\n"
    "  allow_agent_active: true\n"
    "  max_jobs: 1\n"
    "  default_profile: standard\n"
    "  ceilings:\n"
    "    probes: 10\n"
)
S9_BLOCK = (
    "l4:\n"
    "  enabled: true\n"
    "  scope:\n"
    "    - cidr:\n"
    "        addr: 127.0.0.1\n"
    "        prefix: 32\n"
    "      ports:\n"
    "        lo: 1\n"
    "        hi: 65535\n"
    '      interface: "*"\n'
    "      direction: outbound\n"
    "      capability: inject\n"
    "      inject_rate:\n"
    "        pps: 200\n"
    "        burst: 400\n"
)


def check_emitter_literals() -> None:
    cfg8 = CoreConfig(
        proxy_port=1,
        scanner=ScannerSection(allow_agent_active=True, ceilings={"probes": 10},
                               default_profile="standard", max_jobs=1),
    )
    check(S8_BLOCK in cfg8.to_yaml(), "S8: ScannerSection.to_yaml() contains the exact scanner: block")
    check("scanner:" not in CoreConfig(proxy_port=1).to_yaml(),
          "a CoreConfig with no scanner section emits no scanner: key")
    cfg9 = CoreConfig(proxy_port=1, l4_enabled=True, l4_scope_entries=[l4_inject_entry()])
    check(S9_BLOCK in cfg9.to_yaml(), "S9: l4_inject_entry() emits the exact l4:/scope: block")


def check_core_b_l4_scope() -> None:
    cfg_b = CoreConfig(
        proxy_port=free_port(),
        browser_proxy_port=free_port(),
        l4_enabled=True,
        l4_scope_entries=[l4_inject_entry()],
    )
    try:
        core_b = Aitm.server(cfg_b)
    except RuntimeError as e:
        skip(f"core with l4_enabled did not boot (L4 is feature-compiled + opt-in): {e}")
        return
    try:
        op = BusClient.operator(core_b)
        if "l4.scope.list" not in set(op.tool_names()):
            op.close()
            skip("the L4 module is not enabled on this build (no l4.scope.list); l4 is opt-in")
        scope = op.call("l4.scope.list")
        entries = scope if isinstance(scope, list) else (scope or {}).get("entries") or []
        check(len(entries) == 1, f"l4.scope.list reports exactly one entry (got {len(entries)})")
        e = entries[0] if entries else {}
        check(e.get("interface") == "*", f"the entry's interface is \"*\" (got {e.get('interface')!r})")
        check(e.get("direction") == "outbound", f"direction is outbound (got {e.get('direction')!r})")
        check(e.get("capability") == "inject", f"capability is inject (got {e.get('capability')!r})")
        op.close()
    finally:
        core_b.stop()


def check_core_a_scanner(v: ScanTarget) -> None:
    # The probe core has no `scanner:` section, so a pre-T1b core boots and
    # require_verbs can SKIP cleanly; only then is core A (with the section) booted.
    probe_cfg = CoreConfig(
        proxy_port=free_port(),
        browser_proxy_port=free_port(),
        scope_entries=[v.authority],
    )
    with Aitm.server(probe_cfg) as probe:
        pop = BusClient.operator(probe)
        require_verbs(pop, *PROFILE_VERBS)
        pop.close()

    findings_dir = tempfile.mkdtemp(prefix="aitm-e2e-scan-t10-cfg-")
    cfg_a = CoreConfig(
        proxy_port=free_port(),
        browser_proxy_port=free_port(),
        scanner=ScannerSection(ceilings={"probes": CEILING}, default_profile="standard", max_jobs=1),
        scope_entries=[v.authority],
        findings_dir=findings_dir,
    )
    with Aitm.server(cfg_a) as core_a:
        op = BusClient.operator(core_a)

        section("observer: the scanner: section reached the core's config file on disk")
        written = Path(core_a.workdir, "config.yaml").read_text(encoding="utf-8")
        for line in ("scanner:", "  max_jobs: 1", "  default_profile: standard", "  ceilings:", "    probes: 10"):
            check(line in written, f"the written config carries `{line.strip()}`")

        section("scan.start clamps budget.probes to the config ceiling and reports it")
        seq0 = v.logs.reset()
        started = start_job(op, "operator", target=v.base)
        job = started.get("job")
        check(isinstance(job, str) and job, f"scan.start returned a job id (got {job!r})")
        clamped = started.get("clamped") or []
        hit = [c for c in clamped if c.get("field") == "budget.probes"]
        check(len(hit) == 1 and hit[0].get("applied") == CEILING,
              f"clamped names budget.probes applied {CEILING} (got {clamped})")

        section("scan.status / scan.list see the job")
        status = scan_call(op, "operator", "scan.status", {"job": job})
        check(status.get("job") == job, f"scan.status returns this job (got {status.get('job')!r})")
        listing = scan_call(op, "operator", "scan.list", {})
        jobs = listing.get("jobs") or []
        check(any(j.get("job") == job for j in jobs),
              f"scan.list lists the job (ids {[j.get('job') for j in jobs]})")

        section("scan.profile.list/get/save/delete round-trips through the on-disk profile store")
        profiles = (scan_call(op, "operator", "scan.profile.list", {}).get("profiles")) or []
        std = [p for p in profiles if p.get("name") == "standard"]
        check(len(std) == 1 and std[0].get("builtin") is True,
              f"scan.profile.list has `standard` with builtin: true (got {std})")
        std_prof = scan_call(op, "operator", "scan.profile.get", {"name": "standard"})
        check(std_prof.get("name") == "standard", f"scan.profile.get standard round-trips (got {std_prof.get('name')!r})")
        base = scan_call(op, "operator", "scan.profile.get", {"name": "light-http"})
        check(base.get("name") == "light-http", f"scan.profile.get light-http (got {base.get('name')!r})")

        clone = dict(base)
        clone["name"] = "e2e-tiny"
        clone["budget"] = dict(clone.get("budget") or {}, probes=5)
        saved = scan_call(op, "operator", "scan.profile.save", {"profile": clone})
        check(saved.get("saved") == "e2e-tiny", f"scan.profile.save returns saved: e2e-tiny (got {saved})")
        prof_path = os.path.join(findings_dir, "scan", "profiles", "e2e-tiny.yaml")
        check(os.path.exists(prof_path), f"the profile file was written to disk ({prof_path})")
        roundtrip = scan_call(op, "operator", "scan.profile.get", {"name": "e2e-tiny"})
        check((roundtrip.get("budget") or {}).get("probes") == 5,
              f"scan.profile.get e2e-tiny round-trips budget.probes == 5 (got {roundtrip.get('budget')})")
        deleted = scan_call(op, "operator", "scan.profile.delete", {"name": "e2e-tiny"})
        check(deleted.get("deleted") is True, f"scan.profile.delete reports deleted: true (got {deleted})")
        check(not os.path.exists(prof_path), "the profile file is gone from disk after delete")

        section("observer: the probe ceiling held at the origin")
        final = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
        check(final.get("state") == "done",
              f"the job finished `done` (got {final.get('state')!r}, stopped_reason={final.get('stopped_reason')!r})")
        sent = (final.get("probes") or {}).get("sent")
        check(isinstance(sent, int) and sent <= CEILING,
              f"probes.sent ({sent!r}) <= the clamped ceiling {CEILING}")
        crawl_cap = (std_prof.get("crawl") or {}).get("max_pages") or 200
        bound = CEILING + int(crawl_cap) + CRAWL_MARGIN
        reqs = v.logs.scanner_requests(seq0)
        check(len(reqs) <= bound,
              f"the target logged {len(reqs)} request(s) for the job "
              f"(<= {CEILING} probes + {crawl_cap} crawl pages + {CRAWL_MARGIN} margin = {bound})")
        op.close()


def main() -> int:
    section("1. the config emitters produce the exact S8 / S9 literals (no core)")
    check_emitter_literals()

    section("2. core B: the l4: block parses and l4.scope.list reports the inject entry")
    check_core_b_l4_scope()

    section("3. probe verbs, then core A: the scanner: section and the profile store")
    try:
        v = ScanTarget("vulnerable")
    except FileNotFoundError as e:
        skip(str(e))
        return 77
    try:
        check_core_a_scanner(v)
    finally:
        v.stop()
    ok("T10-2: the scanner: + l4: emitters reach a real core; clamp, listing and profiles all round-trip")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
