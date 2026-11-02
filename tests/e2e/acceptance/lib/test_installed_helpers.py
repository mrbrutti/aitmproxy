#!/usr/bin/env python3
"""Pure-function tests for aitm_e2e.installed (the release-acceptance shared code).

Plain `python3 tests/e2e/acceptance/lib/test_installed_helpers.py`; exit 0 = every check held,
1 = a failure (printed). Nothing here touches the Mac: `replay` runs against a ScriptedRunner
that records argv, `find_embedded_core` is exercised through `parse_core_lines` on canned
`pgrep -fl` output, and StepWriter writes into a temp dir. Lives under lib/ so run.py never
discovers it (AC10).
"""
from __future__ import annotations

import os
import sys
import tempfile

E2E = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, E2E)
from aitm_e2e.installed import (  # noqa: E402
    SERVICES,
    TOOLING,
    StepWriter,
    bypass_applied,
    parse_core_lines,
    replay,
)

failures: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("  ok    " if cond else "  FAIL  ") + what)
    if not cond:
        failures.append(what)


class ScriptedRunner:
    """Stands in for subprocess.run: records argv, answers with a canned returncode."""

    def __init__(self, fail_on: tuple[str, ...] = ()):
        self.calls: list[list[str]] = []
        self.fail_on = fail_on

    def __call__(self, argv, **_):
        self.calls.append(list(argv))

        class R:
            returncode = 1 if any(f in argv for f in self.fail_on) else 0
            stderr = "scripted failure" if returncode else ""
            stdout = ""

        return R()


SCUTIL_OFF = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
}
"""

SCUTIL_US_WITH_BYPASS = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
    2 : *.anthropic.com
    3 : claude.ai
    4 : github.com
  }
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 8080
  HTTPSProxy : 127.0.0.1
}
"""

# The TLD trap: "com" and an unrelated host appear, no tooling host does.
SCUTIL_US_TLD_ONLY = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : example.com
    2 : com
  }
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : 127.0.0.1
}
"""

# A tooling host mentioned OUTSIDE the ExceptionsList block must not count as applied.
SCUTIL_HOST_OUTSIDE_LIST = """<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : github.com
}
"""


def test_bypass_applied() -> None:
    print("bypass_applied")
    check(bypass_applied(SCUTIL_US_WITH_BYPASS) is True, "tooling hosts inside ExceptionsList -> True")
    check(bypass_applied(SCUTIL_OFF) is False, "no tooling host -> False")
    check(bypass_applied(SCUTIL_US_TLD_ONLY) is False, "only the TLD 'com' / example.com -> False (never the TLD)")
    check(bypass_applied(SCUTIL_HOST_OUTSIDE_LIST) is False, "tooling host outside the ExceptionsList block -> False")
    check(bypass_applied("") is False, "empty text -> False")
    check(bypass_applied(SCUTIL_US_WITH_BYPASS, ("*.githubusercontent.com",)) is False, "a host not in the list -> False")
    check(bypass_applied("ExceptionsList : <array> {\n 0 : api.anthropic.com\n}", ("*.anthropic.com",)) is False,
          "the wildcard *.anthropic.com is not satisfied by api.anthropic.com alone (entries compared whole)")
    check(bypass_applied("ExceptionsList : <array> {\n 0 : api.anthropic.com\n}", ("api.anthropic.com",)) is True,
          "an exact host entry matches")
    check("*.anthropic.com" in TOOLING and "github.com" in TOOLING, "TOOLING carries the operator's tooling hosts")


def test_replay_argv() -> None:
    print("replay")
    before = {
        "Wi-Fi": {
            "http": "Enabled: No\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n",
            "https": "Enabled: No\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n",
        },
        "Display Ethernet": {
            "http": "Enabled: Yes\nServer: proxy.corp.example\nPort: 3128\nAuthenticated Proxy Enabled: 0\n",
            "https": "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n",
        },
    }
    r = ScriptedRunner()
    errs = replay(before, run=r)
    check(errs == [], f"no errors from a clean replay (got {errs})")
    check(["networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "9090"] in r.calls, "Wi-Fi http server+port re-set as recorded")
    check(["networksetup", "-setwebproxystate", "Wi-Fi", "off"] in r.calls, "Wi-Fi http state off (Enabled: No)")
    check(["networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "9090"] in r.calls, "Wi-Fi https server+port re-set")
    check(["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"] in r.calls, "Wi-Fi https state off")
    check(["networksetup", "-setwebproxy", "Display Ethernet", "proxy.corp.example", "3128"] in r.calls, "Ethernet http server re-set")
    check(["networksetup", "-setwebproxystate", "Display Ethernet", "on"] in r.calls, "Ethernet http state ON (Enabled: Yes) — never a blanket off")
    check(not any(c[1] == "-setsecurewebproxy" and c[2] == "Display Ethernet" for c in r.calls),
          "an empty recorded Server is not re-set (no `networksetup -setsecurewebproxy <svc> '' 0`)")
    check(["networksetup", "-setsecurewebproxystate", "Display Ethernet", "off"] in r.calls, "Ethernet https state off")
    check(len(r.calls) == 7, f"exactly 7 networksetup calls (got {len(r.calls)})")
    order = [c[1] for c in r.calls if c[2] == "Wi-Fi"]
    check(order.index("-setwebproxy") < order.index("-setwebproxystate"), "server set before state (state last wins)")
    bad = ScriptedRunner(fail_on=("-setwebproxystate",))
    errs = replay(before, run=bad)
    check(len(errs) == 2 and all("scripted failure" in e for e in errs), f"failures are returned, one per failing call (got {errs})")
    check(SERVICES == ("Wi-Fi", "Display Ethernet"), "SERVICES are the operator's two services")


PGREP_SAMPLE = """\
4242 /Applications/Aitmproxy.app/Contents/Resources/core/aitm --config /var/folders/ab/T/aitm-embedded-core/9F1C0A2B-1111-2222-3333-444455556666/config.yaml
5151 /tmp/claude/dev-bundle/Aitmproxy.app/Contents/Resources/core/aitm --config /var/folders/ab/T/aitm-embedded-core/AAAA/config.yaml
6161 /Applications/Aitmproxy.app/Contents/MacOS/Aitmproxy
7171 pgrep -fl /Applications/Aitmproxy.app/Contents/Resources/core/aitm
"""

PGREP_SPACES = "8282 /Applications/Aitmproxy.app/Contents/Resources/core/aitm --config /Users/m/Library/Application Support/x y/aitm-embedded-core/ID/config.yaml\n"


def test_parse_core_lines() -> None:
    print("parse_core_lines (find_embedded_core's regex)")
    hits = parse_core_lines(PGREP_SAMPLE)
    check(len(hits) == 1, f"exactly one installed-bundle core in the sample (got {hits})")
    check(hits and hits[0][0] == 4242, "its pid is read")
    check(hits and hits[0][1].endswith("9F1C0A2B-1111-2222-3333-444455556666/config.yaml"), "its config path is read")
    check(not any(p == 5151 for p, _ in hits), "a /tmp/claude/...Aitmproxy.app dev bundle does NOT match")
    check(not any(p == 6161 for p, _ in hits), "the app process itself does not match")
    check(not any(p == 7171 for p, _ in hits), "the pgrep line itself does not match")
    sp = parse_core_lines(PGREP_SPACES)
    check(sp == [(8282, "/Users/m/Library/Application Support/x y/aitm-embedded-core/ID/config.yaml")], f"a config path with spaces is kept whole (got {sp})")
    check(parse_core_lines("") == [], "empty pgrep output -> []")
    check(parse_core_lines(PGREP_SAMPLE + PGREP_SPACES) == [hits[0], sp[0]], "two installed cores -> two hits (the caller refuses to pick)")


def test_step_writer() -> None:
    print("StepWriter")
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x-steps.tsv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("STALE\tPASS\tfrom a previous run\t\t\n")
        w = StepWriter(p, ("A-1", "A-2", "A-3", "A-4"), secrets=["s3cr3t-token-value"])
        w.step("A-1", "PASS", "words\twith\ttabs and s3cr3t-token-value", "truth s3cr3t-token-value", "")
        w.step("A-2", "SKIP", "needs Matt's yes")
        w.finish()
        with open(p, encoding="utf-8") as f:
            lines = f.read().splitlines()
        check(not any(line.startswith("STALE") for line in lines), "the file is created fresh (no stale rows)")
        check(len(lines) == 4, f"four rows: two written, two `not reached` (got {len(lines)}: {lines})")
        check(lines[0].split("\t") == ["A-1", "PASS", "words with tabs and <redacted>", "truth <redacted>", ""], f"tabs escaped, secret redacted in observed and truth (got {lines[0]!r})")
        check(lines[2] == "A-3\tSKIP\tnot reached\t\t" and lines[3] == "A-4\tSKIP\tnot reached\t\t", f"unwritten ids get `SKIP not reached` in order (got {lines[2:]})")
        check(w.results == {"A-1": "PASS", "A-2": "SKIP", "A-3": "SKIP", "A-4": "SKIP"}, "results dict includes the not-reached rows")
        check(w.exit_code() == 77, f"a SKIP -> 77 (got {w.exit_code()})")

        w2 = StepWriter(os.path.join(d, "y.tsv"), ("B-1",))
        w2.step("B-1", "PASS")
        w2.finish()
        check(w2.exit_code() == 0, "all PASS -> 0")

        w3 = StepWriter(os.path.join(d, "z.tsv"), ("C-1", "C-2"))
        w3.step("C-1", "FAIL", "x")
        w3.step("C-2", "SKIP", "y")
        check(w3.exit_code() == 1, "a FAIL wins over a SKIP -> 1")

        w4 = StepWriter(os.path.join(d, "b.tsv"), ("D-1",))
        w4.step("D-1", "BLOCKED", "D-0")
        check(w4.exit_code() == 77, "BLOCKED is never green -> 77")

        w5 = StepWriter(os.path.join(d, "e.tsv"), ("E-1",))
        try:
            w5.step("E-1", "OK", "x")
            check(False, "an unknown result string is rejected")
        except ValueError:
            check(True, "an unknown result string is rejected (ValueError)")

        w6 = StepWriter(os.path.join(d, "f.tsv"), ("F-1",))
        w6.finish()
        w6.finish()
        with open(os.path.join(d, "f.tsv"), encoding="utf-8") as f:
            check(len(f.read().splitlines()) == 1, "finish() is idempotent (one not-reached row, not two)")


def main() -> int:
    test_bypass_applied()
    test_replay_argv()
    test_parse_core_lines()
    test_step_writer()
    print()
    if failures:
        print(f"{len(failures)} FAILED:")
        for f in failures:
            print("  - " + f)
        return 1
    print("all checks held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
