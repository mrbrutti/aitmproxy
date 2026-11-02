#!/usr/bin/env python3
"""Write the D8 report skeleton from a run directory: results.tsv + per-journey step files.

Usage: report.py <version> <outdir>  (stdout = README.md body)
Each journey cell may write <outdir>/<journey>-steps.tsv with lines
  <step-id>\t<PASS|FAIL|SKIP|BLOCKED>\t<observed>\t<bus truth>\t<explains>
which are rendered as the spec's tables. Missing files render as "not run".
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

JOURNEYS = ("cli", "mac", "tui", "web", "negatives")


def rows(path: str) -> list[list[str]]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            out.append((parts + [""] * 5)[:5])
    return out


def main() -> int:
    ver, out = sys.argv[1], sys.argv[2]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    print(f"# Release acceptance — {ver} on the installed build ({now})\n")
    print("Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.")
    print(f"Raw outputs: `{out}` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).\n")
    yes = os.environ.get("ACCEPT_YES", "")
    print(f"**Yes-list for this run:** `{yes or '(none)'}`  ·  **manual:** {os.environ.get('AITM_E2E_MANUAL', '0')}\n")
    counts = {}
    for j in JOURNEYS:
        r = rows(os.path.join(out, f"{j}-steps.tsv"))
        print(f"## Journey {j.upper()}\n")
        if not r:
            print("not run\n")
            continue
        print("| # | Result | Observed | Bus truth | Explains |\n|---|---|---|---|---|")
        c = counts.setdefault(j, {"PASS": 0, "FAIL": 0, "SKIP": 0, "BLOCKED": 0})
        for sid, res, obs, truth, expl in r:
            c[res] = c.get(res, 0) + 1
            print(f"| {sid} | {res} | {obs} | {truth} | {expl} |")
        print()
    print("## Restore proof\n")
    d = os.path.join(out, "state-diff.txt")
    if os.path.exists(d) and os.path.getsize(d) == 0:
        print("`state-before.txt` == `state-after.txt` (timestamps/pids excluded): identical.\n")
    elif os.path.exists(d):
        print("```\n" + open(d, encoding="utf-8").read() + "```\n")
    else:
        print("not taken\n")
    print("## Summary\n\n| Journey | PASS | FAIL | SKIP | BLOCKED |\n|---|---|---|---|---|")
    for j, c in counts.items():
        print(f"| {j.upper()} | {c.get('PASS', 0)} | {c.get('FAIL', 0)} | {c.get('SKIP', 0)} | {c.get('BLOCKED', 0)} |")
    total_fail = sum(c.get("FAIL", 0) for c in counts.values())
    print()
    print("**Verdict:** " + ("blocks the tap bump until every FAIL has an owner in a shipped release or Matt's written acceptance." if total_fail else "no performed step failed; SKIPs listed above are not green."))
    print("\n## Leftovers\n\n(fill in: Scope hosts added by the run, files left on the Mac)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
