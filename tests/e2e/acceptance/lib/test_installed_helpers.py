#!/usr/bin/env python3
"""Pure-function tests for aitm_e2e.installed (the release-acceptance shared code).

Plain `python3 tests/e2e/acceptance/lib/test_installed_helpers.py`; exit 0 = every check held,
1 = a failure (printed). Nothing here touches the Mac: `replay` runs against a ScriptedRunner
that records argv, `find_embedded_core` is exercised through `parse_core_lines` on canned
`pgrep -fl` output, and StepWriter writes into a temp dir. It also exercises the TUI cell's
one-shot helpers (`test_tui_journey.oneshot_json`, `pgrep_lines`) against a scripted `aitm` and
a scripted `pgrep` in a temp dir. Lives under lib/ so run.py never discovers it (AC10).
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import tempfile
import time

E2E = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, E2E)
from aitm_e2e.installed import (  # noqa: E402
    field_center,
    SERVICES,
    TOOLING,
    StepWriter,
    bypass_applied,
    config_scope_entries,
    parse_core_lines,
    read_core_config,
    replay,
    tooling_mentioned,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402

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

        # Spec D1: `N/A` is a sixth result; it is listed, never performed, and never holds the verdict.
        w7 = StepWriter(os.path.join(d, "g.tsv"), ("G-1", "G-2"))
        w7.step("G-1", "PASS", "x")
        w7.step("G-2", "N/A", "no such control on this surface")
        w7.finish()
        check(w7.exit_code() == 0, f"PASS + N/A -> 0 (N/A does not block `pass`; got {w7.exit_code()})")
        with open(os.path.join(d, "g.tsv"), encoding="utf-8") as f:
            check(f.read().splitlines()[1] == "G-2\tN/A\tno such control on this surface\t\t", "the N/A row is written as `N/A`")
        w8 = StepWriter(os.path.join(d, "h.tsv"), ("H-1",))
        w8.step("H-1", "N/A", "x")
        check(w8.exit_code() == 0, "only N/A rows -> 0")

        # Precedence ERROR (2) > FAIL (1) > SKIP/BLOCKED (77) > N/A = PASS (0), matching run.sh and report.py.
        w9 = StepWriter(os.path.join(d, "i.tsv"), ("I-1", "I-2", "I-3", "I-4"))
        w9.step("I-1", "PASS")
        w9.step("I-2", "N/A")
        w9.step("I-3", "SKIP", "x")
        check(w9.exit_code() == 77, "SKIP wins over PASS/N/A -> 77")
        w9.step("I-4", "FAIL", "x")
        check(w9.exit_code() == 1, "FAIL wins over SKIP -> 1")
        w9.step("I-1", "ERROR", "x")
        check(w9.exit_code() == 2, f"ERROR wins over FAIL -> 2 (got {w9.exit_code()})")
        w10 = StepWriter(os.path.join(d, "j.tsv"), ("J-1", "J-2"))
        w10.step("J-1", "ERROR", "x")
        w10.step("J-2", "SKIP", "x")
        check(w10.exit_code() == 2, "ERROR wins over SKIP -> 2")


def test_report_verdict() -> None:
    print("report.verdict / report.rows (N/A)")
    check(report.verdict({"tui": {"PASS": 3, "N/A": 2}}) == "pass", "PASS + N/A -> `pass`")
    check(report.verdict({"tui": {"PASS": 3, "N/A": 2, "SKIP": 1}}) == "incomplete", "a SKIP beside N/A -> `incomplete`")
    check(report.verdict({"tui": {"N/A": 2}}) == "incomplete", "only N/A rows (nothing performed) -> `incomplete`, never `pass`")
    check(report.verdict({"a": {"FAIL": 1}, "b": {"ERROR": 1}}) == "error", "ERROR wins over FAIL")
    check(report.verdict({"a": {"FAIL": 1, "SKIP": 4}}) == "fail", "FAIL wins over SKIP")
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x-steps.tsv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("X-1\tN/A\tnot on this surface\t\t\n")
        r = report.rows(p)
        check(r == [["X-1", "N/A", "not on this surface", "", ""]], f"report.rows accepts an N/A row (got {r})")
        check("N/A" in report.RESULTS, "report.RESULTS lists N/A")


def test_exit_on_term() -> None:
    print("exit_on_term (SIGTERM -> SystemExit(2), finally runs)")
    child = (
        "import os, sys, time\n"
        f"sys.path.insert(0, {E2E!r})\n"
        "from aitm_e2e.installed import exit_on_term\n"
        "exit_on_term()\n"
        "print('armed', flush=True)\n"
        "try:\n"
        "    time.sleep(30)\n"
        "finally:\n"
        "    print('finally ran', flush=True)\n"
    )
    p = subprocess.Popen([sys.executable, "-c", child], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    first = p.stdout.readline()
    check(first.strip() == "armed", f"child armed the handler (got {first!r})")
    p.send_signal(signal.SIGTERM)
    try:
        out, err = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        check(False, "the child did not exit within 10 s of SIGTERM")
    check(p.returncode == 2, f"exit code 2 after SIGTERM (got {p.returncode}; stderr {err.strip()[:120]!r})")
    check("finally ran" in out, f"the `finally` block ran (stdout {out!r})")
    # SIGINT: even when the child was started with SIGINT ignored (a bash background job), the helper
    # restores KeyboardInterrupt so the watchdog's first signal reaches `finally` too.
    child_int = (
        "import signal, sys, time\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        f"sys.path.insert(0, {E2E!r})\n"
        "from aitm_e2e.installed import exit_on_term\n"
        "exit_on_term()\n"
        "print('armed', flush=True)\n"
        "try:\n"
        "    time.sleep(30)\n"
        "except KeyboardInterrupt:\n"
        "    print('interrupted', flush=True)\n"
        "finally:\n"
        "    print('finally ran', flush=True)\n"
    )
    pi = subprocess.Popen([sys.executable, "-c", child_int], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pi.stdout.readline()
    t_int = time.time()
    pi.send_signal(signal.SIGINT)
    try:
        out_i, _ = pi.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        pi.kill()
        out_i, _ = pi.communicate()
    check("interrupted" in out_i and "finally ran" in out_i and time.time() - t_int < 5, f"SIGINT -> KeyboardInterrupt -> finally within 5 s even with SIGINT inherited as ignored (stdout {out_i!r})")
    # A plain child without the handler dies with -SIGTERM and never reaches `finally` (the bug the helper closes).
    plain = subprocess.Popen([sys.executable, "-c", "import time\nprint('up', flush=True)\ntry:\n    time.sleep(30)\nfinally:\n    print('finally ran', flush=True)\n"], stdout=subprocess.PIPE, text=True)
    plain.stdout.readline()
    plain.send_signal(signal.SIGTERM)
    out2, _ = plain.communicate(timeout=10)
    check(plain.returncode == -signal.SIGTERM and "finally ran" not in out2, "control: without the handler SIGTERM skips `finally` (so the test proves the helper)")


SAMPLE_CONFIG = """\
listen: 127.0.0.1:8080
scope:
  entries:
    - example.com
    - "httpbin.org:443"
    - '*.corp.example'
  allow_agent_widen: true
system_proxy:
  bypass:
    - "*.anthropic.com"
    - do-not-read-me.local
mcp:
  operator_token: "not-a-scope-entry"
"""
SAMPLE_CONFIG_INLINE = "scope:\n  entries: [a.example, \"b.example:80\"]\n  allow_agent_widen: false\nsystem_proxy:\n  bypass: []\n"
SAMPLE_CONFIG_EMPTY = "scope:\n  entries: []\nsystem_proxy:\n  bypass: []\n"


def test_config_scope_entries() -> None:
    print("config_scope_entries")
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "config.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SAMPLE_CONFIG)
        got = config_scope_entries(p)
        check(got == ["example.com", "httpbin.org:443", "*.corp.example"], f"the scope: block's entries, exact strings, quotes stripped (got {got})")
        check("do-not-read-me" not in " ".join(got) and "*.anthropic.com" not in got, "nothing outside the scope: block is read (no bypass entry, no token)")
        check("true" not in got and not any("allow_agent_widen" in g for g in got), "allow_agent_widen is a sibling key, not an entry")
        from aitm_e2e.installed import config_bypass as _cb
        check(_cb(p) == ["*.anthropic.com", "do-not-read-me.local"], f"config_bypass reads system_proxy.bypass through the same walker (got {_cb(p)})")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SAMPLE_CONFIG_INLINE)
        got = config_scope_entries(p)
        check(got == ["a.example", "b.example:80"], f"an inline list is read (got {got})")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SAMPLE_CONFIG_EMPTY)
        check(config_scope_entries(p) == [], "scope: [] -> []")
        check(config_scope_entries(os.path.join(d, "absent.yaml")) == [], "no config -> []")


def test_field_center() -> None:
    print("field_center")
    dump = "\n".join([
        "AXStaticText\t\tEdit Scope\ttext",
        "AXTextField\t\t\ttext field\tsidebar-filter\t10,20\t100,20",
        "AXTextField\t\t\tHost to add to scope\t\t300,400\t200,24",
        "AXButton\t\t\tbutton",
        "AXTextField\t\t\tHost to add to scope\tscope-add-host\t500,600\t200,24",
        "AXTextField\t\t\tHost to add to scope\t\t0,0\t0,0",
    ])
    check(field_center(dump, "Host to add to scope", "scope-add-host") == (600, 612), "the identifier row wins over an earlier description match")
    check(field_center(dump, "Host to add to scope", "no-such-id") == (400, 412), "falls back to the first description match with a real size")
    check(field_center(dump, "Host to add to scope") == (400, 412), "no identifier asked: first description match")
    check(field_center(dump, "nothing like it") is None, "unknown description -> None")
    check(field_center("AXTextField\t\t\tHost to add to scope", "Host to add to scope") is None, "a row without position/size columns (older dump) -> None")
    check(field_center("AXTextField\t\t\tHost to add to scope\t\t0,0\t0,0", "Host to add to scope") is None, "the only match has zero size -> None (never a click at 0,0)")
    check(field_center("AXTextField\t\t\tHost to add to scope\t\t300.5,400.0\t200.0,24.0", "Host to add to scope") == (400, 412), "float coordinates are accepted")
    check(field_center("AXTextField\t\t\tHost to add to scope\t\tabc,1\t200,24", "Host to add to scope") is None, "a garbage position -> None")
    check(field_center("AXTextField\t\t\tsome other field\tscope-add-host\t500,600\t200,24", "Host to add to scope", "scope-add-host") is None, "the identifier on a field with another description does not win")


def test_tooling_mentioned() -> None:
    print("tooling_mentioned")
    check(tooling_mentioned("*.anthropic.com, api.anthropic.com, claude.ai") is True, "the recommended list -> True")
    check(tooling_mentioned(["github.com", "*.local"]) is True, "a list with github.com -> True")
    check(tooling_mentioned("") is False, "empty -> False")
    check(tooling_mentioned([]) is False, "[] -> False")
    check(tooling_mentioned("example.com, com") is False, "an unrelated host and the bare TLD -> False")
    check(tooling_mentioned("*.githubusercontent.com") is True, "any one TOOLING host suffices")


def test_read_core_config_oserror() -> None:
    print("read_core_config (find_embedded_core's file reads)")
    with tempfile.TemporaryDirectory() as d:
        try:
            read_core_config(4242, os.path.join(d, "gone", "config.yaml"))
            check(False, "an unreadable per-launch config raises RuntimeError")
        except RuntimeError as e:
            check("embedded core 4242 config unreadable" in str(e), f"RuntimeError names the pid and the cause (got {e})")
        except OSError as e:
            check(False, f"OSError leaked instead of RuntimeError ({e})")
        cfg = os.path.join(d, "config.yaml")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write("listen: 127.0.0.1:8080\nmcp:\n  operator_token: \"tok-value\"\n  token: agent-value\n")
        try:
            read_core_config(4242, cfg)
            check(False, "a missing bus.endpoint beside the config raises RuntimeError")
        except RuntimeError as e:
            check("bus.endpoint" in str(e) or "unreadable" in str(e), f"RuntimeError for the missing endpoint file (got {e})")
        with open(os.path.join(d, "bus.endpoint"), "w", encoding="utf-8") as f:
            f.write("127.0.0.1:9100\n")
        core = read_core_config(4242, cfg)
        check((core.pid, core.bus_addr, core.operator_token) == (4242, "127.0.0.1:9100", "tok-value"), "pid, endpoint and operator token are read")


def _import_cell(tmpdir: str):
    """The TUI journey cell as a module. Importing it writes its fresh steps file, so ACCEPT_OUT
    points at `tmpdir` first; the caller pops ACCEPT_OUT in a `finally`."""
    os.environ["ACCEPT_OUT"] = tmpdir
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import test_tui_journey as cell  # noqa: E402

    return cell


def test_tui_oneshot_json() -> None:
    """test_tui_journey.oneshot_json (tester, plan 2026-11-03 Task 2): the one-shot CLI is the TUI
    cells' bus truth, so its four outcomes are pinned against a scripted `aitm` on PATH-less argv:
    JSON on exit 0 is parsed; a non-zero exit, non-JSON stdout and a timeout are None with a note
    that carries the exit and stderr but never stdout (which could hold a token)."""
    print("test_tui_journey.oneshot_json")
    fresh = "test_tui_journey" not in sys.modules
    with tempfile.TemporaryDirectory() as d:
        try:
            fake = os.path.join(d, "aitm")
            with open(fake, "w", encoding="utf-8") as f:
                f.write(
                    "#!/bin/sh\n"
                    'case "$1 $2" in\n'
                    '  "scope list") printf \'["example.com","a.test"]\\n\' ;;\n'
                    '  "proxy status") printf \'{"intercept_armed":true}\\n\' ;;\n'
                    '  "scope fail") echo "stdout-tok3n"; echo "boom: refused" >&2; exit 3 ;;\n'
                    '  "scope text") echo "not json tok3n"; echo "warned" >&2 ;;\n'
                    "esac\n"
                )
            os.chmod(fake, 0o755)
            cell = _import_cell(d)
            check(not fresh or os.path.isfile(os.path.join(d, "tui-steps.tsv")), "importing the cell writes its steps file under ACCEPT_OUT only")
            cell.AITM = fake
            v, note = cell.oneshot_json("scope", "list")
            check(v == ["example.com", "a.test"], f"scope list: stdout JSON array parsed (got {v!r})")
            check(note == "aitm scope list: exit 0", f"scope list note (got {note!r})")
            v, note = cell.oneshot_json("proxy", "status")
            check(isinstance(v, dict) and v.get("intercept_armed") is True, f"proxy status: object parsed (got {v!r})")
            v, note = cell.oneshot_json("scope", "fail")
            check(v is None, "non-zero exit -> None")
            check(note.startswith("aitm scope fail: exit 3") and "boom: refused" in note, f"note carries the exit and stderr (got {note!r})")
            check("tok3n" not in note, "note never carries stdout (a token could be there)")
            v, note = cell.oneshot_json("scope", "text")
            check(v is None, "exit 0 with non-JSON stdout -> None")
            check("stdout not JSON" in note and "warned" in note, f"note says stdout was not JSON and carries stderr (got {note!r})")
            check("tok3n" not in note, "non-JSON stdout is not echoed into the note")
            v, note = cell.oneshot_json("scope", "missing-verb")
            check(v is None and "stdout not JSON (0 bytes)" in note, f"empty stdout on exit 0 -> None, note says 0 bytes (got {note!r})")

            class TimingOut:
                TimeoutExpired = subprocess.TimeoutExpired

                @staticmethod
                def run(argv, **kw):
                    raise subprocess.TimeoutExpired(argv, kw.get("timeout", 0))

            real = cell.subprocess
            cell.subprocess = TimingOut
            try:
                v, note = cell.oneshot_json("proxy", "status")
            finally:
                cell.subprocess = real
            check(v is None and note == "aitm proxy status: timeout 40s", f"timeout -> None with the 40 s note (got {note!r})")
        finally:
            os.environ.pop("ACCEPT_OUT", None)


def test_tui_pgrep_lines() -> None:
    """test_tui_journey.pgrep_lines: exit 1 is "" (nothing left), exit 0 is the matches, any other
    exit is a marker (a tool failure is never read as "nothing left"); the command line is passed
    as a literal (`re.escape`). Scripted: the sandbox's pgrep has no sysmond."""
    print("test_tui_journey.pgrep_lines")
    with tempfile.TemporaryDirectory() as d:
        try:
            cell = _import_cell(d)

            class Pgrep:
                def __init__(self, rc: int, out: str = "", err: str = ""):
                    self.rc, self.out, self.err = rc, out, err

                def run(self, argv, **_):
                    self.argv = argv

                    class R:
                        returncode, stdout, stderr = self.rc, self.out, self.err

                    return R()

            real = cell.subprocess
            for rc, out, err, want in (
                (1, "", "", ""),
                (0, "4242 /opt/homebrew/bin/aitm tui\n", "", "4242 /opt/homebrew/bin/aitm tui"),
                (3, "", "sysmon request failed", "[pgrep error 3: sysmon request failed]"),
            ):
                stub = Pgrep(rc, out, err)
                cell.subprocess = stub
                try:
                    got = cell.pgrep_lines("/opt/homebrew/bin/aitm tui")
                finally:
                    cell.subprocess = real
                check(got == want, f"pgrep_lines exit {rc} -> {want!r} (got {got!r})")
            check(stub.argv[:2] == ["pgrep", "-fl"] and stub.argv[2] == re.escape("/opt/homebrew/bin/aitm tui"), f"pgrep_lines escapes the command line as a literal (argv {stub.argv})")
        finally:
            os.environ.pop("ACCEPT_OUT", None)


def main() -> int:
    test_bypass_applied()
    test_replay_argv()
    test_parse_core_lines()
    test_step_writer()
    test_report_verdict()
    test_exit_on_term()
    test_config_scope_entries()
    test_field_center()
    test_tooling_mentioned()
    test_read_core_config_oserror()
    test_tui_oneshot_json()
    test_tui_pgrep_lines()
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
