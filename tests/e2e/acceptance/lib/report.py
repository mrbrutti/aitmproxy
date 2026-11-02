#!/usr/bin/env python3
"""Write the D8 report skeleton from a run directory: per-journey step files, the restore diff,
the leftovers and the D1 verdict word.

Usage: report.py <version> <outdir>  (stdout = README.md body)
Each journey cell writes <outdir>/<journey>-steps.tsv with lines
  <step-id>\t<PASS|FAIL|SKIP|BLOCKED|ERROR|N/A>\t<observed>\t<bus truth>\t<explains>
rendered as the spec's tables; an unknown result string is a hard error (a cell wrote something the
contract does not know). Missing files render as "not run". <outdir>/leftovers.txt
(`<host>\t<removed|kept|failed>\t<cell>`) renders as the Leftovers section.

Filled in BY HAND afterwards (the harness cannot know them): the D2 starting-state table in prose,
the yes-list as Matt approved it verbatim, and the Explains STATE column (open / merged, unreleased /
missing feature with its card) — the cells only name the owner.

Verdict word (D1): `pass` (every step PASS or N/A, at least one PASS), `fail` (a performed step
FAILed), `incomplete` (no FAIL but a SKIP/BLOCKED), `error` when a cell was killed or wrote an ERROR
row. `N/A` (a step that does not exist on that surface or build) is listed and never holds the verdict.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

JOURNEYS = ("cli", "mac", "negatives", "tui", "web")
RESULTS = ("PASS", "FAIL", "SKIP", "BLOCKED", "ERROR", "N/A")


def rows(path: str) -> list[list[str]]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            parts = (line.rstrip("\n").split("\t") + [""] * 5)[:5]
            if parts[1] not in RESULTS:
                raise SystemExit(f"{path}:{n}: unknown result {parts[1]!r} for step {parts[0]!r} (expected one of {RESULTS})")
            out.append(parts)
    return out


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def verdict(counts: dict[str, dict[str, int]]) -> str:
    total = {k: sum(c.get(k, 0) for c in counts.values()) for k in RESULTS}
    if total["ERROR"]:
        return "error"
    if total["FAIL"]:
        return "fail"
    if total["SKIP"] or total["BLOCKED"]:
        return "incomplete"
    return "pass" if total["PASS"] else "incomplete"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: report.py <version> <outdir>", file=sys.stderr)
        return 2
    ver, out = sys.argv[1], sys.argv[2]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    print(f"# Release acceptance — {ver} on the installed build ({now})\n")
    print("Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.")
    print(f"Raw outputs: `{out}` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).\n")
    yes = os.environ.get("ACCEPT_YES", "")
    print(f"**Yes-list for this run (as given to the runner; quote Matt's words by hand):** `{yes or '(none)'}`  ·  **manual:** {os.environ.get('AITM_E2E_MANUAL', '0')}  ·  **window:** {os.environ.get('ACCEPT_WINDOW', '0')}\n")
    print("_Starting state (D2): fill in from `state-before.txt` by hand._\n")
    counts: dict[str, dict[str, int]] = {}
    for j in JOURNEYS:
        r = rows(os.path.join(out, f"{j}-steps.tsv"))
        print(f"## Journey {j.upper()}\n")
        if not r:
            print("not run\n")
            continue
        print("| # | Result | Observed | Bus truth | Explains |\n|---|---|---|---|---|")
        c = counts.setdefault(j, {k: 0 for k in RESULTS})
        for sid, res, obs, truth, expl in r:
            c[res] += 1
            print(f"| {sid} | {'**' + res + '**' if res in ('FAIL', 'ERROR') else res} | {obs} | {truth} | {expl} |")
        print()
    print("## Restore proof\n")
    d = os.path.join(out, "state-diff.txt")
    if os.path.exists(d) and os.path.getsize(d) == 0:
        print("`state-before.txt` == `state-after.txt` (timestamps/pids excluded): identical.\n")
    elif os.path.exists(d):
        print("```\n" + read(d) + "```\n")
    else:
        print("not taken\n")
    print("## Summary\n\n| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |\n|---|---|---|---|---|---|---|")
    for j, c in counts.items():
        print(f"| {j.upper()} | {c['PASS']} | {c['FAIL']} | {c['SKIP']} | {c['BLOCKED']} | {c['ERROR']} | {c['N/A']} |")
    v = verdict(counts)
    print()
    words = {
        "pass": "every performed step PASSed (N/A rows are steps that do not exist on that surface) — clears the tap bump.",
        "fail": "a performed step FAILed — blocks the tap bump until every FAIL has an owner in a shipped release or Matt's written acceptance.",
        "incomplete": "no FAIL, but SKIP/BLOCKED steps remain (a yes, a hand or a free port was missing) — not green; run them or Matt accepts the gap in writing.",
        "error": "a cell was killed or exited 2 — no verdict for the release; fix the runner and re-run.",
    }
    print(f"**Verdict:** `{v}` — {words[v]}")
    print("\n_Explains state (open / merged, unreleased / missing feature with its card): fill in by hand per FAIL._")
    print("\n## Leftovers\n")
    lp = os.path.join(out, "leftovers.txt")
    if os.path.exists(lp) and os.path.getsize(lp):
        print("| Host | State | Cell |\n|---|---|---|")
        for line in read(lp).splitlines():
            host, state, cell = (line.split("\t") + ["", ""])[:3]
            print(f"| {host} | {state} | {cell} |")
        print("\n`kept` and `failed` rows are for Matt to remove by hand; `removed` rows were taken out through the same surface that added them.")
    else:
        print("No Scope host was added by the run (or none is recorded). Log files stay under the run folder.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
