#!/usr/bin/env python3
# e2e: tier=manual surface=acceptance
"""Release acceptance, journey WEB (spec §D5, negatives §D7): the INSTALLED `aitm web` on the
operator's real HOME, its ready card (WEB-1, read from stderr: wave 1 G1/D13), then a REAL Google Chrome over CDP
(lib/web_journey.mjs) for the page words (WEB-2/3/6, N2-WEB, N5-WEB), the system-proxy flips
only with Matt's yes (WEB-4/7) and the bypass precondition, a second browser's traffic as a hand
step (WEB-5, --manual; judged from the page by the mjs, the web cell has no bus client), and the
shutdown (WEB-8). Bus truth here is `scutil` for the route, the durable audit for scope.add, and
the page state; the wrapper answers the mjs's `CHECK WEB-4` with the ExceptionsList assertion and
replays the recorded per-service state in its trap if the surface did not restore.

Preconditions: 8080/8081/8082 free (the app quit) — else SKIP naming the holder; Google Chrome
installed — else WEB-2…7 SKIP. The host WEB-3 adds is removed by the mjs through its row's own
button (unless ACCEPT_KEEP_SCOPE=1) and listed in leftovers.txt; a host the operator's config.yaml
`scope:` block lists (ACCEPT_PRE_SCOPE to the mjs) or the page already shows is pre-existing and
never removed. Secrets: the card's `#t=` bearer values are added to the writer, appended to
$ACCEPT_OUT/.secrets (0600, one per line) for run.sh's leak grep, and `aitm web`'s stderr reaches
aitm-web.log through a redacting pump (post-processed once more at exit). WEB-9/10 and N1-WEB do
not exist on this surface: `N/A` (spec D1). Exit 0 = all performed PASS (N/A counts as such),
77 = any SKIP/BLOCKED, 1 = any FAIL. Steps → $ACCEPT_OUT/web-steps.tsv.
"""
from __future__ import annotations

import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)
from aitm_e2e import is_manual, pause  # noqa: E402
from aitm_e2e.installed import (  # noqa: E402
    DATA_DIR,
    INSTALLED_CLI,
    StepWriter,
    append_leftover,
    audit_tail,
    bypass_applied,
    config_bypass,
    config_scope_entries,
    exit_on_term,
    port_holder,
    replay,
    scutil,
    service_state,
    tooling_mentioned,
    yes_set,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("ACCEPT_OUT", "/tmp/claude/acceptance/web")
os.makedirs(OUT, exist_ok=True)
YES = yes_set()
AITM = os.environ.get("AITM", INSTALLED_CLI)
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
BROWSER_STEPS = ("WEB-2", "WEB-3", "WEB-4", "WEB-5", "WEB-6a", "WEB-6b", "WEB-6c", "WEB-6d", "WEB-7", "N2-WEB", "N5-WEB")
EXPECTED_STEPS = ("WEB-1",) + BROWSER_STEPS + ("WEB-8", "WEB-9", "WEB-10", "N1-WEB", "N3-WEB")
# Wave 1 (spec 2026-11-01-cli-terminal-reporting, G1/D13): the ready card is a human line, so it is
# on STDERR; stdout stays free (JSON-RPC for the stdio transport, the answer for a one-shot). On the
# cell's pipe it arrives in the plain form — `Label: value · command` rows, no pill line, no rules;
# the rules and the `aitm web` pill exist only on a TTY — so the rows are matched with an optional
# colon and any spacing.
CARD_WANT = {
    "Web UI line": r"^\s*Web UI:?\s+http://127\.0\.0\.1:8082/#t=",
    "Proxy line": r"^\s*Proxy:?\s+127\.0\.0\.1:8080",
    "Browser line (SSRF-filtered)": r"^\s*Browser:?\s+127\.0\.0\.1:8081\s+\(SSRF-filtered\)",
    "Bus ready": r"^\s*Bus:?\s+ready",
}
SCOPE_LINE = re.compile(r"^\s*Scope:?\s+Nothing is decrypted until a host is in Scope\.", re.M)

w = StepWriter(os.path.join(OUT, "web-steps.tsv"), EXPECTED_STEPS)
step = w.step


def na_rows() -> None:
    step("WEB-9", "N/A", "no All Apps control on this surface", "", "UIs pending (per-host decryption decision)")
    step("WEB-10", "N/A", "no Apps view on this surface on 0.5.10")
    step("N1-WEB", "N/A", "aitm web owns its core: a core restart under an open tab is not performable here (words pinned in D7)")
    step("N3-WEB", "SKIP", "CA stays trusted (un-trusting is Matt's yes; words read from source)")


def note_secret(value: str) -> None:
    """A web bearer value: redacted by the writer from now on and appended to $ACCEPT_OUT/.secrets
    (created 0600, one per line) so run.sh's leak grep knows it; run.sh deletes the file as soon as
    this cell returns. Written only under run.sh (ACCEPT_OUT set): a standalone run keeps the values
    in memory and never puts a bearer on disk."""
    if not value:
        return
    w.add_secret(value)
    if not os.environ.get("ACCEPT_OUT"):
        return
    fd = os.open(os.path.join(OUT, ".secrets"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(value + "\n")


def pump_redacted(src, dst) -> None:
    """Copy `aitm web`'s stderr to the log file line by line through the writer's redaction."""
    for line in src:
        try:
            dst.write(w.redact(line))
            dst.flush()
        except ValueError:  # the log was closed at the end of the cell while a last line arrived
            return


def read_card(proc: subprocess.Popen, deadline_s: float, log) -> tuple[list[str], str | None, str | None]:
    """The ready card from STDERR (wave 1 G1/D13), read in a thread so a silent `aitm web` cannot
    hang the cell: stops at the `Log` row (the plain form's last row), at the SECOND rule line
    (`────`, the TTY form), at EOF, or at the deadline. Every stderr line, card or not, also goes to
    the log through the writer's redaction, and once the card is in a drain thread keeps doing that
    for the rest of the run."""
    q: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        for line in proc.stderr:
            q.put(line)
        q.put(None)

    def to_log(line: str) -> None:
        try:
            log.write(w.redact(line))
            log.flush()
        except ValueError:  # the log was closed at the end of the cell while a last line arrived
            pass

    def drain() -> None:
        while True:
            line = q.get()
            if line is None:
                return
            to_log(line)

    threading.Thread(target=pump, daemon=True).start()
    card: list[str] = []
    op_url = agent_url = None
    rules = 0
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            line = q.get(timeout=max(0.05, end - time.time()))
        except queue.Empty:
            break
        if line is None:
            break
        to_log(line)
        card.append(line.rstrip("\n"))
        m = re.match(r"\s*Operator:?\s+(https?://\S+)", line)
        if m:
            op_url = m.group(1)
        m = re.match(r"\s*Web UI:?\s+(https?://\S+)", line)
        if m:
            agent_url = m.group(1)
        if "────" in line:
            rules += 1
            if rules >= 2:
                break
        if re.match(r"\s*Log:?\s+\S", line):
            break
    threading.Thread(target=drain, daemon=True).start()
    return card, op_url, agent_url


def main() -> int:  # noqa: C901 — one journey, in the operator's order
    exit_on_term()
    if not os.path.isfile(AITM):
        step("WEB-1", "SKIP", f"installed aitm not found at {AITM}")
        na_rows()
        w.finish()
        return w.exit_code()
    for port in (8080, 8081, 8082):
        h = port_holder(port)
        if h:
            for sid in ("WEB-1",) + BROWSER_STEPS + ("WEB-8",):
                step(sid, "SKIP", f"port {port} held by {h}; aitm web needs the default ports (quit the app first)")
            na_rows()
            w.finish()
            return w.exit_code()
    chrome_ok = os.path.isfile(CHROME)

    before, before_svc = scutil(), service_state()
    t0 = int(time.time() * 1000)
    env = dict(os.environ)
    env.pop("AITM_AUDIT_LOG", None)
    env.setdefault("LANG", "en_US.UTF-8")
    set_by_us = False
    pre_scope = config_scope_entries()  # his persisted hosts: pre-existing whatever the page shows
    p: subprocess.Popen | None = None  # the node child, killed in the OUTER finally if it is still there
    log_path = os.path.join(OUT, "aitm-web.log")
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.Popen([AITM, "web"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
        # stdout carries nothing for `aitm web` (wave 1 G1); whatever arrives is logged, redacted.
        threading.Thread(target=pump_redacted, args=(proc.stdout, log), daemon=True).start()
        try:
            # WEB-1 — the ready card.
            card, op_url, agent_url = read_card(proc, 20, log)
            for u in (op_url, agent_url):
                if u and "#t=" in u:
                    note_secret(u.split("#t=", 1)[1].split("&", 1)[0])
            shown = "\n".join(card)
            with open(os.path.join(OUT, "WEB-1.txt"), "w", encoding="utf-8") as f:
                f.write(w.redact(shown))
            loader = sum(1 for ln in card if "loaded script" in ln or "script loaded into the host" in ln)
            have = {label: bool(re.search(rx, shown, re.M)) for label, rx in CARD_WANT.items()}
            # The two 60-char rules frame the card only on a TTY; on this pipe the plain form has
            # none (wave 1 D13), so they are reported, not required.
            rules = sum(1 for ln in card if "────" in ln)
            scope_empty = not pre_scope
            if scope_empty:
                have["Scope line (Scope empty)"] = bool(SCOPE_LINE.search(shown))
            healthz = ""
            try:
                healthz = urllib.request.urlopen("http://127.0.0.1:8082/healthz", timeout=5).read().decode()
            except Exception as e:  # noqa: BLE001
                healthz = f"error {e}"
            obs = f"card lines {len(card)} on stderr ({loader} loader lines, {rules} rules); " + ", ".join(f"{k}: {v}" for k, v in have.items()) + f"; Operator line {'present' if op_url else 'ABSENT'}; config scope empty {scope_empty}; /healthz {healthz.strip()}"
            if all(have.values()) and loader == 0 and healthz.strip() == '{"ok":true}':
                step("WEB-1", "PASS", obs)
            else:
                step("WEB-1", "FAIL", obs, "", "log noise: PR #271" if loader else "")
            if not op_url:
                for sid in BROWSER_STEPS:
                    step(sid, "BLOCKED", "no Operator line: mcp.operator_token is not set in the operator's config (`aitm operator-token generate` is a manual step on 0.5.10)")
            elif not chrome_ok:
                for sid in BROWSER_STEPS:
                    step(sid, "SKIP", f"Google Chrome not found at {CHROME}; the page words need a real browser")
            else:
                yes = sorted(YES & {"WEB-4", "WEB-7"})
                byp = config_bypass()
                if "WEB-4" in yes and not tooling_mentioned(byp):
                    step("WEB-4", "SKIP", f"bypass list absent in config.yaml system_proxy.bypass ({byp or 'none'}); add it through Settings first")
                    yes = [x for x in yes if x not in ("WEB-4", "WEB-7")]
                env2 = dict(env, ACCEPT_ROUTE_OPEN="1" if "WEB-4" in yes else "0", ACCEPT_OP_URL=op_url, ACCEPT_AGENT_URL=agent_url or "", ACCEPT_PRE_SCOPE=",".join(pre_scope))
                with open(os.path.join(OUT, "web_journey.mjs.log"), "w", encoding="utf-8") as mlog:
                    p = subprocess.Popen(["node", os.path.join(HERE, "lib", "web_journey.mjs"), OUT, ",".join(yes), "manual" if is_manual() else ""],
                                         stdout=subprocess.PIPE, stderr=mlog, stdin=subprocess.PIPE, text=True, env=env2, start_new_session=True)
                    for line in p.stdout:
                        line = line.rstrip("\n")
                        kind, _, rest = line.partition("\t")
                        if kind == "PAUSE":
                            pause(rest)
                            p.stdin.write("\n")
                            p.stdin.flush()
                        elif kind == "SET":
                            set_by_us = True  # armed BEFORE the mjs clicks: a crash mid-click still restores
                        elif kind == "CHECK":
                            ok = bypass_applied(scutil())
                            p.stdin.write("ok\n" if ok else "bad\n")
                            p.stdin.flush()
                        elif kind == "LEFTOVER":
                            host, _, state = rest.partition("\t")
                            append_leftover(OUT, host, state, "web")
                        elif kind == "STEP":
                            sid, res, obs2 = (rest.split("\t") + ["", ""])[:3]
                            truth = ""
                            if sid == "WEB-3":
                                rows = [r for r in audit_tail(200) if r.get("at", 0) >= t0 and r.get("command") == "scope.add"]
                                truth = f"audit scope.add entries since start: {len(rows)}"
                            elif sid == "WEB-5":
                                truth = "judged from the page (grid rows) by the mjs; the web cell has no bus client"
                            elif sid in ("WEB-4", "WEB-7"):
                                now = scutil()
                                if sid == "WEB-7" and res == "PASS" and now == before:
                                    set_by_us = False
                                if sid == "WEB-4" and res == "FAIL":
                                    set_by_us = now != before
                                truth = "scutil: " + ("points at 8080" if "HTTPPort : 8080" in now else "not 8080") + f"; ExceptionsList carries the tooling {bypass_applied(now)}; identical to before: {now == before}"
                            step(sid, res, obs2, truth)
                    try:
                        p.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGTERM)
            # WEB-8 — stop.
            os.killpg(proc.pid, signal.SIGINT)
            try:
                rc = proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGTERM)
                rc = proc.wait(timeout=5)
            time.sleep(0.5)
            free = all(port_holder(pt) is None for pt in (8080, 8081, 8082))
            same = scutil() == before
            pointers = os.path.join(DATA_DIR, "run", "cores")
            left = sorted(os.listdir(pointers)) if os.path.isdir(pointers) else []
            step("WEB-8", "PASS" if free and same else "FAIL", f"exit {rc}; ports free {free}; scutil identical {same}; run/cores pointers left {left}", "audit: no proxy.system.set left unmatched" if same else "")
            na_rows()
        finally:
            if p is not None and p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)  # the node child (and its Chrome) on ANY exit path, not only the 60 s timeout
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
            if set_by_us:
                print("== restore trap: WEB-4 set the system proxy and WEB-7 did not restore it; replaying the recorded per-service state", flush=True)
                errs = replay(before_svc)
                same = scutil() == before
                step("RESTORE", "PASS" if same and not errs else "FAIL", f"replayed recorded state; identical {same}; errors {errs}")
            elif scutil() != before:
                step("DRIFT", "FAIL", "the system proxy changed during the run by another actor; the harness set nothing and touched nothing — left as is", scutil()[:200])
            w.finish()
    # The pump redacted with the secrets known at the time of each line; one more pass with every value learned since.
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(w.redact(text))
    except OSError as e:
        print(f"aitm-web.log post-redaction failed: {e}", flush=True)
    return w.exit_code()


if __name__ == "__main__":
    sys.exit(main())
