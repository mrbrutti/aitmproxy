#!/usr/bin/env python3
# e2e: tier=T1 surface=l4 needs=l4
"""l4/privilege_core -- the packet-capture privilege contract on a LIVE, unprivileged core
(spec 2026-10-31-l4-capture-privilege-design, plan task P1b.17).

Every check here drives the rig's real core over the MCP bus as operator AND as agent and
asserts on the core's verbatim replies -- never a fixture (plan Rule 1):

  * AC1: `l4.privilege` answers both roles within 500 ms: `enabled: true`, `platform` in
    {macos, linux}, `capabilities.capture.state == "needs_approval"` (or, on a privileged
    host, `available` -- reported as skipped, not green), an integer `checked_at`; on macOS
    `intercept.state == "unsupported"`. `how.kind` is `"package"` on this rig (the config
    points `l4.privilege.macos_app_path` at a missing bundle); `AITM_E2E_PRIV_EXPECT_HOW`
    overrides the expected kind for the signed Mac (P3.13, `app_action`). The `package` action
    is the download URL, never a shell command.
  * AC2: a second, L4-off core (`AITM_BUS_ADDR_L4OFF`) answers `enabled: false` with three
    `unsupported`; without that core a skip-line is printed (the cell still runs).
  * AC4: `l4.capture.status` is `{available: false, code: "needs_privilege", captures: [],
    privilege}` and its `reason` is `packet capture is not allowed yet (<how.label>)`;
    `l4.intercept.status` carries `privilege` with code `unsupported_platform` (macOS) or
    `needs_privilege` (Linux).
  * AC10 (macOS) / AC20+AC23 (Linux): the operator's `l4.privilege.request` goes through the
    confirm handshake and returns `outcome: "cannot_prompt"`; its message names no shell
    command; `l4.privilege.request` then records progress; no `open -a` (macOS) or `pkexec`
    (Linux) process the script did not start appears; Aitmproxy is not launched.
  * AC24: the rig core's log (`AITM_CORE_LOG`) has exactly one `L4 enabled; packet capture
    needs approval: ` line, matching neither the AC3 command regex nor the operator token.
  * AC5: the agent's `l4.privilege.request` is refused under the current policy and never
    parked. The full `ask`/`auto`/`all` battery runs only with `AITM_E2E_P7=1` AND the verb
    visible in the agent's tools/list (p7's `is_operator_only`); it flips and restores the
    policy. Otherwise the reduced, true-today check runs and the policy is never touched.
  * Linux only: the one-shot `aitm l4.privilege.request` (under `setsid`, no DISPLAY) refuses
    with the spec §2.4 text and spawns no pkexec (`AITM_BIN` names the binary).

Env model (like the sibling l4 cells): attaches to the runner's l4 core via AITM_BUS_ADDR +
AITM_BUS_OPERATOR_TOKEN + AITM_BUS_TOKEN (the agent half); never boots its own core. Tokens
are read into variables and never printed. Soft-assertion battery; exit 0 pass / 1 fail / 77
only when no core is provided.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402

# ---- the contract literals (spec §2.2-§2.4) --------------------------------------------

READ_VERB = "l4.privilege"
REQUEST_VERB = "l4.privilege.request"
DOWNLOAD_URL = "https://mrbrutti.github.io/aitmproxy/download.html"
UNAVAILABLE_PREFIX = "L4 unavailable: "
REASON_PREFIX = "packet capture is not allowed yet ("
MAC_INTERCEPT_REASON = "in-path interception is Linux only"
STARTUP_MARKER = "L4 enabled; packet capture needs approval: "
LINUX_ONESHOT_TEXT = ("a one-shot command exits before the helper could serve it; set "
                      "l4.privilege.request: at_start or use Allow in the TUI or web UI")
# The agent refusal under p7 (spec AC5): `auto` names the policy; `all` names the operator.
AGENT_REFUSED_PREFIX = "`l4.privilege.request` refused: "
AGENT_REFUSED_POLICY_PREFIX = "`l4.privilege.request` refused: the agent policy is "

# Spec AC3 / plan Rule 2: no reply, label, message or log line names a command.
COMMAND_WORDS = re.compile(r"\b(sudo|setcap|chmod|chgrp|chown|dseditgroup|launchctl|pkexec)\b")
# Spec §5.5 pins the `failed` progress text for a pkexec child that died generically:
# "The packet-capture helper did not start (pkexec exit <n>)" / "(killed by signal <n>)".
# That literal names `pkexec` by design, so the command-word scan of a *progress message*
# (`request.message`, and the request reply's `message` when it is the same text) exempts
# exactly those literals (panel 2: the whole message, anchored, not a prefix). The third
# form is `linux.rs`'s `watch_step` row for a failed wait (`waitpid: <ERRNO>`); it names
# no command, so it would pass the full scan anyway. Reasons, labels, prompts, start-up
# lines and one-shot output keep the full scan (`names_a_command`).
PINNED_FAILED_MESSAGE = re.compile(
    r"^The packet-capture helper did not start \((pkexec exit -?\d+|killed by signal \d+|waitpid: [A-Z]+)\)$"
)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

CAPABILITY_STATES = ("available", "needs_approval", "unsupported")
HOW_KINDS = ("app_action", "os_dialog", "package", "pkexec")
HELPER_KINDS = ("macos_bpf_permissions", "linux_pkexec_helper", "linux_cap_helper", "none")
HELPER_STATUSES = ("not_installed", "installed", "applied", "running", "version_mismatch", "unknown")
REQUEST_STATES = ("pending", "handed_to_app", "approved", "dismissed", "failed")
OUTCOMES = ("already_available", "pending", "handed_to_app", "cannot_prompt")
PLATFORMS = ("macos", "linux")

READ_BUDGET_S = 0.5
# A parked (not refused) agent call blocks until an operator answers; bound the wait so
# the cell reports the parking as a FAIL instead of hanging for the 120 s approval timeout.
AGENT_PARK_PROBE_S = 5.0

IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

_failures: list[str] = []
_skipped: list[str] = []


def expect(cond, msg: str, detail="") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:300]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def skipped_check(msg: str, why: str) -> None:
    """One check this run cannot prove; loud, not green, not a FAIL (a skip-line)."""
    print(f"  [skipped] {msg}   -- {why}", flush=True)
    _skipped.append(msg)


def show(label: str, value) -> None:
    print(f"note: {label} = {json.dumps(value, default=str, sort_keys=True)[:700]}", flush=True)


# ---- pure helpers (no bus, no exit) ----------------------------------------------------

def report_shape_errors(rep) -> list[str]:
    """Why `rep` is NOT a spec-§2.2 `PrivilegeReport`; `[]` when it is."""
    if not isinstance(rep, dict):
        return [f"reply is {type(rep).__name__}, not an object"]
    errs: list[str] = []
    for k in ("enabled", "platform", "capabilities", "helper", "request", "checked_at"):
        if k not in rep:
            errs.append(f"missing key {k!r}")
    if not isinstance(rep.get("enabled"), bool):
        errs.append(f"enabled is {rep.get('enabled')!r}, not a bool")
    if rep.get("platform") not in PLATFORMS + ("other",):
        errs.append(f"platform {rep.get('platform')!r} is not macos|linux|other")
    ca = rep.get("checked_at")
    if not (isinstance(ca, int) and not isinstance(ca, bool)):
        errs.append(f"checked_at is {ca!r}, not an integer")
    caps = rep.get("capabilities")
    if not isinstance(caps, dict):
        errs.append("capabilities is not an object")
    else:
        for name in ("capture", "inject", "intercept"):
            errs.extend(f"capabilities.{name}: {e}" for e in capability_errors(caps.get(name)))
    helper = rep.get("helper")
    if not isinstance(helper, dict):
        errs.append("helper is not an object")
    else:
        if helper.get("kind") not in HELPER_KINDS:
            errs.append(f"helper.kind {helper.get('kind')!r} not in {HELPER_KINDS}")
        if helper.get("status") not in HELPER_STATUSES:
            errs.append(f"helper.status {helper.get('status')!r} not in {HELPER_STATUSES}")
        for k in ("version", "detail"):
            if k in helper and helper[k] is not None and not isinstance(helper[k], str):
                errs.append(f"helper.{k} is neither null nor a string")
    req = rep.get("request")
    if req is not None:
        errs.extend(request_errors(req))
    return errs


def capability_errors(cap) -> list[str]:
    if not isinstance(cap, dict):
        return [f"is {type(cap).__name__}, not an object"]
    state = cap.get("state")
    if state not in CAPABILITY_STATES:
        return [f"state {state!r} not in {CAPABILITY_STATES}"]
    errs: list[str] = []
    if state == "available":
        if cap.get("via") not in ("process", "helper"):
            errs.append(f"available but via {cap.get('via')!r}")
    else:
        if not (isinstance(cap.get("reason"), str) and cap.get("reason")):
            errs.append(f"{state} but reason {cap.get('reason')!r}")
        elif COMMAND_WORDS.search(cap["reason"]):
            errs.append(f"reason names a command: {cap['reason']!r}")
    if state == "needs_approval":
        how = cap.get("how")
        if not isinstance(how, dict):
            errs.append("needs_approval but no how object")
        else:
            if how.get("kind") not in HOW_KINDS:
                errs.append(f"how.kind {how.get('kind')!r} not in {HOW_KINDS}")
            label = how.get("label")
            if not (isinstance(label, str) and label):
                errs.append(f"how.label {label!r}")
            elif COMMAND_WORDS.search(label):
                errs.append(f"how.label names a command: {label!r}")
            errs.extend(f"how.action: {e}" for e in action_errors(how.get("action")))
    return errs


def action_errors(action) -> list[str]:
    if not isinstance(action, dict):
        return [f"is {type(action).__name__}, not an object"]
    t = action.get("type")
    if t == "bus_verb":
        return [] if action.get("verb") == REQUEST_VERB else [f"bus_verb verb {action.get('verb')!r}"]
    if t == "open_url":
        url = action.get("url")
        return [] if url == DOWNLOAD_URL else [f"open_url url {url!r} != {DOWNLOAD_URL!r}"]
    return [f"type {t!r} is neither bus_verb nor open_url"]


def request_errors(req) -> list[str]:
    if not isinstance(req, dict):
        return [f"request is {type(req).__name__}, not an object or null"]
    errs = []
    if req.get("state") not in REQUEST_STATES:
        errs.append(f"request.state {req.get('state')!r} not in {REQUEST_STATES}")
    at = req.get("at")
    if not (isinstance(at, int) and not isinstance(at, bool)):
        errs.append(f"request.at {at!r} is not an integer")
    msg = req.get("message")
    if not isinstance(msg, str):
        errs.append(f"request.message {msg!r} is not a string")
    elif progress_message_names_a_command(msg):
        errs.append(f"request.message names a command: {msg!r}")
    return errs


def capture_how(rep) -> dict:
    cap = (rep.get("capabilities") or {}).get("capture") if isinstance(rep, dict) else None
    how = cap.get("how") if isinstance(cap, dict) else None
    return how if isinstance(how, dict) else {}


def capture_state(rep):
    cap = (rep.get("capabilities") or {}).get("capture") if isinstance(rep, dict) else None
    return cap.get("state") if isinstance(cap, dict) else None


def expected_reason(rep) -> str | None:
    """`packet capture is not allowed yet (<how.label>)` from the report, or None."""
    label = capture_how(rep).get("label")
    return f"{REASON_PREFIX}{label})" if isinstance(label, str) and label else None


def strip_volatile(rep):
    """A report minus `checked_at` (the probe re-runs after 1 s, so two back-to-back reads
    may carry different stamps while meaning the same thing)."""
    if not isinstance(rep, dict):
        return rep
    return {k: v for k, v in rep.items() if k != "checked_at"}


def is_needs_confirmation(reply) -> bool:
    return isinstance(reply, dict) and reply.get("status") == "needs_confirmation"


def names_a_command(text) -> bool:
    return isinstance(text, str) and COMMAND_WORDS.search(text) is not None


def progress_message_names_a_command(text) -> bool:
    """`names_a_command` for a request progress message: the spec-§5.5 pinned failure texts
    "The packet-capture helper did not start (pkexec exit <n> | killed by signal <n> |
    waitpid: <ERRNO>)" are exempt, whole and anchored (the first names pkexec by spec);
    anything else, a longer message with that prefix included, is scanned in full."""
    if isinstance(text, str) and PINNED_FAILED_MESSAGE.fullmatch(text):
        return False
    return names_a_command(text)


def startup_lines(log_text: str) -> list[str]:
    """The log lines carrying the AC24 marker, ANSI stripped, from the marker on."""
    out = []
    for raw in log_text.splitlines():
        line = ANSI.sub("", raw)
        i = line.find(STARTUP_MARKER)
        if i >= 0:
            out.append(line[i:])
    return out


def pgrep(*args: str) -> list[str]:
    """`pgrep` lines (a non-zero exit, i.e. no match, is `[]`; a missing pgrep is `[]`)."""
    try:
        r = subprocess.run(["pgrep", *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [ln for ln in r.stdout.splitlines() if ln.strip()] if r.returncode == 0 else []


def new_pids(before: list[str], after: list[str]) -> list[str]:
    """Lines of `after` whose leading pid is not in `before` (pgrep -l output)."""
    seen = {ln.split()[0] for ln in before}
    return [ln for ln in after if ln.split()[0] not in seen]


def parse_bus_addr(addr: str) -> tuple[str, int]:
    bh, _, bp = addr.rpartition(":")
    return (bh or "127.0.0.1", int(bp))


def make_core(addr: str, op_token: str, agent_token: str):
    return SimpleNamespace(bus_addr=parse_bus_addr(addr),
                           cfg=SimpleNamespace(agent_token=agent_token, operator_token=op_token))


# ---- the live checks ------------------------------------------------------------------

def timed_call(bus, verb: str, args=None):
    t0 = time.perf_counter()
    st, rep = bus.try_call(verb, args)
    return st, rep, time.perf_counter() - t0


def check_ac1(op, agent, expect_how: str) -> dict | None:
    section(f"(1) AC1: {READ_VERB} answers operator and agent within 500 ms, honestly")
    st_op, rep_op, dt_op = timed_call(op, READ_VERB)
    st_ag, rep_ag, dt_ag = timed_call(agent, READ_VERB)
    show(f"{READ_VERB} (operator)", rep_op)
    show(f"{READ_VERB} (agent)", rep_ag)
    print(f"note: {READ_VERB} took operator {dt_op * 1000:.0f} ms, agent {dt_ag * 1000:.0f} ms", flush=True)
    expect(st_op == "ok", f"{READ_VERB} answers the operator without error", rep_op)
    expect(st_ag == "ok", f"{READ_VERB} answers the agent without error (a Read verb)", rep_ag)
    expect(dt_op < READ_BUDGET_S, f"operator {READ_VERB} answered within 500 ms", f"{dt_op * 1000:.0f} ms")
    expect(dt_ag < READ_BUDGET_S, f"agent {READ_VERB} answered within 500 ms", f"{dt_ag * 1000:.0f} ms")
    if st_op != "ok":
        return None
    errs = report_shape_errors(rep_op)
    expect(not errs, f"{READ_VERB} is the spec §2.2 PrivilegeReport (shape, vocabularies, no command words)", errs)
    if st_ag == "ok":
        expect(strip_volatile(rep_ag) == strip_volatile(rep_op),
               "the agent reads the same report as the operator (checked_at aside)",
               {"operator": strip_volatile(rep_op), "agent": strip_volatile(rep_ag)})
    if errs:
        return rep_op
    expect(rep_op["enabled"] is True, "enabled is true on the privilege rig", rep_op["enabled"])
    expect(rep_op["platform"] in PLATFORMS, "platform is macos or linux", rep_op["platform"])
    expect(rep_op["platform"] == ("macos" if IS_MAC else "linux"),
           "platform matches the OS this cell runs on", rep_op["platform"])
    caps = rep_op["capabilities"]
    state = caps["capture"]["state"]
    if state == "available":
        skipped_check("capture.state == needs_approval", "this host is privileged (capture available: "
                      f"via {caps['capture'].get('via')!r}); the needs_approval half cannot be proven here")
    else:
        expect(state == "needs_approval", "capabilities.capture.state is needs_approval on the unprivileged rig", state)
        expect(caps["inject"]["state"] == "needs_approval",
               "capabilities.inject.state is needs_approval too (same /dev/bpf* or CAP_NET_RAW gate)",
               caps["inject"])
        how = capture_how(rep_op)
        print(f"note: capture.how.kind = {how.get('kind')!r}, label = {how.get('label')!r}", flush=True)
        expect(how.get("kind") == expect_how, f"capture.how.kind is {expect_how!r} on this rig", how.get("kind"))
        if expect_how == "package":
            expect(how.get("action") == {"type": "open_url", "url": DOWNLOAD_URL},
                   "the package remedy is the download URL (open_url), never a shell command", how.get("action"))
        elif expect_how in ("app_action", "pkexec", "os_dialog"):
            expect(how.get("action") == {"type": "bus_verb", "verb": REQUEST_VERB},
                   f"the {expect_how} remedy is the bus verb {REQUEST_VERB}", how.get("action"))
    if IS_MAC:
        expect(caps["intercept"]["state"] == "unsupported", "macOS: capabilities.intercept.state is unsupported",
               caps["intercept"])
        expect(caps["intercept"].get("reason") == MAC_INTERCEPT_REASON,
               f"macOS: the intercept reason is {MAC_INTERCEPT_REASON!r}", caps["intercept"].get("reason"))
    else:
        expect(caps["intercept"]["state"] in ("unsupported", "available"),
               "Linux: capabilities.intercept.state is unsupported (no CAP_NET_ADMIN) or available",
               caps["intercept"])
    return rep_op


def check_ac2(op_token: str, agent_token: str) -> None:
    section(f"(2) AC2: an L4-off core answers {READ_VERB} with enabled: false and three unsupported")
    addr = os.environ.get("AITM_BUS_ADDR_L4OFF")
    if not addr:
        skipped_check("AC2 L4-off core", "AITM_BUS_ADDR_L4OFF (+ _L4OFF tokens, or the same tokens) is not set; "
                      "the orchestrator provides the second core with l4.enabled: false")
        return
    core = make_core(addr, os.environ.get("AITM_BUS_OPERATOR_TOKEN_L4OFF") or op_token,
                     os.environ.get("AITM_BUS_TOKEN_L4OFF") or agent_token)
    op2 = ag2 = None
    try:
        op2 = BusClient.operator(core)
        ag2 = BusClient.agent(core)
        names = sorted(n for n in op2.tool_names() if n.startswith("l4."))
        print(f"note: L4-off core l4.* tools: {names}", flush=True)
        expect(READ_VERB in names and REQUEST_VERB in names,
               f"the L4-off core still lists {READ_VERB} and {REQUEST_VERB} (always registered)", names)
        expect("l4.capture.status" not in names, "the L4-off core does not list the L4 module's verbs", names)
        for role, bus in (("operator", op2), ("agent", ag2)):
            st, rep, dt = timed_call(bus, READ_VERB)
            show(f"L4-off {READ_VERB} ({role})", rep)
            expect(st == "ok", f"L4-off: {READ_VERB} answers the {role} without error", rep)
            if st != "ok":
                continue
            expect(dt < READ_BUDGET_S, f"L4-off: the {role} read answered within 500 ms", f"{dt * 1000:.0f} ms")
            errs = report_shape_errors(rep)
            expect(not errs, f"L4-off: the {role} report has the §2.2 shape", errs)
            if errs:
                continue
            expect(rep["enabled"] is False, f"L4-off: enabled is false ({role})", rep["enabled"])
            states = {k: v.get("state") for k, v in rep["capabilities"].items()}
            expect(states == {"capture": "unsupported", "inject": "unsupported", "intercept": "unsupported"},
                   f"L4-off: all three capabilities are unsupported ({role})", states)
    except (OSError, BusError) as e:
        expect(False, "the L4-off core is reachable with the given address and tokens", f"{type(e).__name__}: {e}")
    finally:
        for c in (ag2, op2):
            if c is not None:
                c.close()


def check_ac4(op, agent, report: dict | None) -> dict | None:
    section("(3) AC4: l4.capture.status / l4.intercept.status carry code + privilege; the reason is the label")
    st, cap = op.try_call("l4.capture.status")
    st_ag, cap_ag = agent.try_call("l4.capture.status")
    show("l4.capture.status (operator)", cap)
    expect(st == "ok", "l4.capture.status answers the operator without error", cap)
    expect(st_ag == "ok", "l4.capture.status answers the agent without error", cap_ag)
    if st == "ok" and st_ag == "ok":
        norm = lambda r: {**r, "privilege": strip_volatile(r.get("privilege"))} if isinstance(r, dict) else r  # noqa: E731
        expect(norm(cap_ag) == norm(cap), "the agent reads the same capture status (checked_at aside)",
               {"operator": cap, "agent": cap_ag})
    if st != "ok" or not isinstance(cap, dict):
        return None
    priv = cap.get("privilege")
    expect(isinstance(priv, dict), "l4.capture.status carries a privilege object", cap.keys())
    if isinstance(priv, dict):
        errs = report_shape_errors(priv)
        expect(not errs, "the embedded privilege report has the §2.2 shape", errs)
        if report is not None:
            expect(strip_volatile(priv) == strip_volatile(report),
                   f"the embedded report equals {READ_VERB}'s (checked_at aside)")
    if cap.get("available") is True:
        skipped_check("l4.capture.status needs_privilege row", "capture is available on this host")
    else:
        expect(cap.get("available") is False, "l4.capture.status available is false", cap.get("available"))
        expect(cap.get("code") == "needs_privilege", "l4.capture.status code is needs_privilege", cap.get("code"))
        expect(cap.get("captures") == [], "l4.capture.status captures is []", cap.get("captures"))
        expect(isinstance(priv, dict) and capture_state(priv) == "needs_approval",
               "privilege.capabilities.capture.state is needs_approval", capture_state(priv))
        want = expected_reason(priv) if isinstance(priv, dict) else None
        reason = cap.get("reason")
        print(f"note: l4.capture.status reason, verbatim: {reason!r}", flush=True)
        expect(want is not None and reason == want,
               "reason == \"packet capture is not allowed yet (\" + how.label + \")\"",
               {"reason": reason, "expected": want})
        expect(not names_a_command(reason), "the reason names no shell command", reason)
        iface = "lo0" if IS_MAC else "lo"
        st_s, err = op.try_call("l4.capture.start", {"interface": iface})
        show(f"l4.capture.start {{interface: {iface!r}}} (operator)", err)
        expect(st_s == "error", "l4.capture.start is still refused while capture needs approval", err)
        expect(st_s == "error" and str(err) == f"l4.capture.start: {UNAVAILABLE_PREFIX}{reason}",
               "l4.capture.start errors with exactly \"L4 unavailable: \" + reason",
               {"error": str(err)[-240:], "reason": reason})

    st_i, inter = op.try_call("l4.intercept.status")
    st_i_ag, inter_ag = agent.try_call("l4.intercept.status")
    show("l4.intercept.status (operator)", inter)
    expect(st_i == "ok", "l4.intercept.status answers the operator without error", inter)
    expect(st_i_ag == "ok", "l4.intercept.status answers the agent without error", inter_ag)
    if st_i == "ok" and isinstance(inter, dict):
        expect(isinstance(inter.get("privilege"), dict), "l4.intercept.status carries a privilege object", inter.keys())
        if IS_MAC:
            expect(inter.get("code") == "unsupported_platform", "macOS: l4.intercept.status code is unsupported_platform",
                   inter.get("code"))
            expect(inter.get("reason") == MAC_INTERCEPT_REASON,
                   f"macOS: l4.intercept.status reason is {MAC_INTERCEPT_REASON!r}", inter.get("reason"))
        elif inter.get("available") is True:
            skipped_check("Linux l4.intercept.status needs_privilege", "intercept is available on this host")
        else:
            expect(inter.get("code") == "needs_privilege", "Linux: l4.intercept.status code is needs_privilege",
                   inter.get("code"))
        expect(inter.get("sessions") == [] or inter.get("available") is True,
               "l4.intercept.status sessions is [] while unavailable", inter.get("sessions"))
    return cap


def operator_request(op) -> tuple[str, object]:
    """The operator's confirm handshake, asserted step by step. Returns (status, final reply)."""
    first = op.call(REQUEST_VERB)
    show(f"operator {REQUEST_VERB} (first call)", first)
    expect(is_needs_confirmation(first), f"operator {REQUEST_VERB} first returns needs_confirmation", first)
    if not is_needs_confirmation(first):
        return ("ok", first)
    prompt = str(first.get("prompt", ""))
    expect(bool(prompt) and not names_a_command(prompt), "the confirm prompt is present and names no command", prompt)
    token = first.get("confirm_token")
    expect(bool(token), "the handshake carries a confirm_token", first)
    if not token:
        return ("error", "no confirm_token")
    return op.try_call(REQUEST_VERB, {"_confirm": token})


def check_request(op, report: dict | None) -> None:
    tag = "AC10" if IS_MAC else "AC20/AC23"
    section(f"(4) {tag}: the operator's {REQUEST_VERB} is cannot_prompt on this rig; nothing is launched")
    if report is not None and capture_state(report) == "available":
        skipped_check(f"{tag} cannot_prompt", "capture is available on this host; the request would be "
                      "already_available and prove nothing about the prompt path")
        return
    open_before = pgrep("-fl", "open -a") if IS_MAC else []
    pkexec_before = pgrep("-x", "pkexec") if IS_LINUX else []
    app_before = pgrep("-x", "Aitmproxy") if IS_MAC else []
    try:
        st, rep = operator_request(op)
    except (ToolError, BusError) as e:
        st, rep = "error", str(e)
    show(f"operator {REQUEST_VERB} (_confirm)", rep)
    expect(st == "ok", f"operator {REQUEST_VERB} answers without error after confirm", rep)
    if st == "ok" and isinstance(rep, dict):
        outcome = rep.get("outcome")
        expect(outcome in OUTCOMES, "outcome is one of the §2.3 outcomes", outcome)
        expect(outcome == "cannot_prompt", "outcome is cannot_prompt (no valid app / no prompt path on this rig)", outcome)
        msg = rep.get("message")
        print(f"note: request message, verbatim: {msg!r}", flush=True)
        expect(isinstance(msg, str) and bool(msg), "the message is a non-empty string", msg)
        expect(not progress_message_names_a_command(msg),
               "the message names no shell command (sudo/setcap/chmod/.../pkexec; spec §5.5 pinned text exempt)", msg)
        if IS_LINUX and not os.environ.get("AITM_E2E_PRIV_DOC_ACCEPTED"):
            expect("packet-capture.md" not in str(msg), "AC23: the message names no doc (none accepted yet)", msg)
        priv = rep.get("privilege")
        errs = report_shape_errors(priv)
        expect(not errs, "the reply's privilege report has the §2.2 shape", errs)
        if isinstance(priv, dict):
            req = priv.get("request")
            expect(isinstance(req, dict) and req.get("state") in ("failed", "pending", "handed_to_app"),
                   "privilege.request records progress (state failed | pending | handed_to_app)", req)
            expect(isinstance(req, dict) and req.get("state") == "failed",
                   "cannot_prompt is recorded as failed progress", req)
    time.sleep(2.0)
    st2, after = op.try_call(READ_VERB)
    show(f"{READ_VERB} after the request", after if st2 == "ok" else str(after))
    if st2 == "ok" and isinstance(after, dict):
        req = after.get("request")
        expect(isinstance(req, dict) and req.get("state") in ("failed", "pending", "handed_to_app"),
               f"{READ_VERB}.request is a dict with state in {{failed, pending, handed_to_app}}", req)
        if isinstance(req, dict):
            expect(not progress_message_names_a_command(req.get("message")),
                   "the recorded progress message names no command (spec §5.5 pinned text exempt)",
                   req.get("message"))
    if IS_MAC:
        open_after = pgrep("-fl", "open -a")
        expect(not new_pids(open_before, open_after), "macOS: no new `open -a` process appeared (open was not run)",
               new_pids(open_before, open_after))
        app_after = pgrep("-x", "Aitmproxy")
        expect(len(app_after) == len(app_before), "macOS: the Aitmproxy process count is unchanged",
               {"before": len(app_before), "after": len(app_after)})
    if IS_LINUX:
        pkexec_after = pgrep("-x", "pkexec")
        expect(not new_pids(pkexec_before, pkexec_after), "Linux: no pkexec process appeared within 2 s",
               pkexec_after)


def check_ac24(op_token: str) -> None:
    section("(5) AC24: the rig core's log has exactly one start-up privilege line, honest and token-free")
    path = os.environ.get("AITM_CORE_LOG")
    if not path:
        skipped_check("AC24 core log", "AITM_CORE_LOG is not set; the orchestrator passes the rig core's log path")
        return
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        expect(False, "the core log at AITM_CORE_LOG is readable", f"{type(e).__name__}: {e}")
        return
    lines = startup_lines(text)
    expect(len(lines) == 1, f"exactly one log line carries {STARTUP_MARKER!r}", f"{len(lines)} line(s)")
    for line in lines:
        has_token = bool(op_token) and op_token in line
        # Never echo a line that carries the token.
        print(f"note: start-up line, verbatim: {'<withheld: carries the operator token>' if has_token else line!r}",
              flush=True)
        expect(not has_token, "the start-up line does not carry the operator token")
        expect(not names_a_command(line), "the start-up line matches none of the AC3 command words", line)
        expect(len(line) > len(STARTUP_MARKER), "the start-up line carries a label after the marker", line)


def pending_requests(op) -> list | None:
    """The parked agent requests as the operator sees them, or None when this core has no
    verb for them (the plan names `agent.pending`; a core may expose them on agent.status)."""
    names = set(op.tool_names())
    if "agent.pending" in names:
        st, rep = op.try_call("agent.pending")
        if st == "ok" and isinstance(rep, list):
            return rep
        if st == "ok" and isinstance(rep, dict):
            return rep.get("pending", rep.get("requests", []))
        return None
    st, rep = op.try_call("agent.status")
    if st == "ok" and isinstance(rep, dict):
        for key in ("pending", "parked", "pending_requests", "approvals"):
            if isinstance(rep.get(key), list):
                return rep[key]
    return None


def agent_request_bounded(agent, core):
    """The agent's request with a bounded wait. Returns (status, text, replacement agent client):
    status is 'error' (refused), 'ok' (ran!), or 'parked' (no answer within the probe window,
    i.e. the call was parked for approval; the stuck connection is dropped and a fresh one
    is handed back)."""
    agent._set_read_timeout(AGENT_PARK_PROBE_S)  # noqa: SLF001 - bounded probe, then restore
    try:
        st, rep = agent.try_call(REQUEST_VERB)
        agent._restore_read_timeout()  # noqa: SLF001
        return st, rep, agent
    except (socket.timeout, TimeoutError, OSError, BusError):
        try:
            agent.close()
        except Exception:  # noqa: BLE001
            pass
        return "parked", f"no reply within {AGENT_PARK_PROBE_S:.0f} s (parked for approval)", BusClient.agent(core)


def check_ac5(op, agent, core):
    section(f"(6) AC5: the agent's {REQUEST_VERB} is refused, never parked, and launches nothing")
    agent_tools = set(agent.tool_names())
    listed = REQUEST_VERB in agent_tools
    print(f"note: {REQUEST_VERB} in the agent's tools/list: {listed}", flush=True)
    policy = op.call("agent.status").get("policy")
    print(f"note: agent policy now = {policy!r}", flush=True)
    full = bool(os.environ.get("AITM_E2E_P7")) and listed
    app_before = pgrep("-x", "Aitmproxy") if IS_MAC else []
    pkexec_before = pgrep("-x", "pkexec") if IS_LINUX else []
    t_since = int(time.time() * 1000) - 1

    if not full:
        skipped_check("AC5 full ask/auto/all battery", "runs only with AITM_E2E_P7=1 and the verb in the agent's "
                      "tools/list (p7's is_operator_only); the reduced, true-today check runs instead")
        before = pending_requests(op)
        st, rep, agent = agent_request_bounded(agent, core)
        print(f"note: agent {REQUEST_VERB} under policy {policy!r}: status={st}, text={str(rep)[:400]!r}", flush=True)
        expect(st == "error", f"the agent's {REQUEST_VERB} is refused (error) under the current policy {policy!r}", rep)
        after = pending_requests(op)
        if before is None or after is None:
            skipped_check("agent.pending stays empty", "this core exposes no pending-requests verb "
                          "(no agent.pending; agent.status has no pending list)")
            expect(st == "error" and "operator" in str(rep),
                   "the refusal text names the operator (the only role that may ask)", str(rep)[:300])
        else:
            expect(after == before and not [p for p in after if REQUEST_VERB in json.dumps(p)],
                   "no request was parked for approval", after)
    else:
        original = policy
        try:
            for pol in ("ask", "auto", "all"):
                op.confirm("agent.set", {"policy": pol})
                before = pending_requests(op)
                st, rep, agent = agent_request_bounded(agent, core)
                text = str(rep)
                print(f"note: agent {REQUEST_VERB} under {pol!r}: status={st}, text={text[:400]!r}", flush=True)
                expect(st == "error", f"under {pol!r} the agent's {REQUEST_VERB} is refused at once", rep)
                body = text.split(": ", 1)[1] if text.startswith(REQUEST_VERB + ": ") else text
                if pol == "ask":
                    after = pending_requests(op)
                    if before is None or after is None:
                        skipped_check("ask: agent.pending stays empty", "no pending-requests verb on this core")
                    else:
                        expect(after == before, "ask: agent.pending stays empty (never parked)", after)
                elif pol == "auto":
                    expect(body.startswith(AGENT_REFUSED_POLICY_PREFIX),
                           f"auto: the text starts with {AGENT_REFUSED_POLICY_PREFIX!r}", body[:200])
                else:
                    expect(body.startswith(AGENT_REFUSED_PREFIX) and "operator" in body,
                           f"all: the text starts with {AGENT_REFUSED_PREFIX!r} and contains 'operator'", body[:200])
        finally:
            if isinstance(original, str) and original:
                try:
                    op.confirm("agent.set", {"policy": original})
                except (ToolError, BusError) as e:  # pragma: no cover - rig hygiene
                    print(f"  [warn] could not restore agent policy {original!r}: {e}", flush=True)
        restored = op.call("agent.status").get("policy")
        expect(restored == original, "the agent policy is restored", {"before": original, "after": restored})
        st_a, acts = op.try_call("agent.activity", {"since": t_since, "limit": 200})
        mine = [a for a in acts if isinstance(a, dict) and REQUEST_VERB in json.dumps(a)] if st_a == "ok" else []
        show("agent.activity entries for the request", mine[:3])
        expect(bool(mine) and all(str(a.get("origin", a.get("role", ""))).lower() not in ("operator", "cli")
                                  for a in mine),
               "agent.activity records the agent caller for the refused request", mine[:2])

    time.sleep(2.0)
    if IS_MAC:
        app_after = pgrep("-x", "Aitmproxy")
        expect(len(app_after) == len(app_before), "macOS: pgrep -x Aitmproxy count is unchanged across the agent call",
               {"before": len(app_before), "after": len(app_after)})
    if IS_LINUX:
        pkexec_after = pgrep("-x", "pkexec")
        expect(not new_pids(pkexec_before, pkexec_after), "Linux: no pkexec appeared within 2 s of the agent call",
               pkexec_after)
    return agent


def check_linux_oneshot() -> None:
    section(f"(7) Linux AC20/AC23: the one-shot `aitm {REQUEST_VERB}` under setsid refuses and spawns nothing")
    if not IS_LINUX:
        skipped_check("Linux one-shot refusal", "macOS host; AC20/AC23 run in the [linux-ci] container")
        return
    aitm_bin = os.environ.get("AITM_BIN")
    if not aitm_bin:
        skipped_check("Linux one-shot refusal", "AITM_BIN is not set (the rig's aitm binary)")
        return
    env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    cfg = os.environ.get("AITM_E2E_RIG_CONFIG")
    if cfg:
        env["AITM_CONFIG"] = cfg
    pkexec_before = pgrep("-x", "pkexec")
    try:
        r = subprocess.run(["setsid", "-w", aitm_bin, REQUEST_VERB], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        expect(False, "the one-shot ran under setsid", f"{type(e).__name__}: {e}")
        return
    out = ANSI.sub("", r.stdout + "\n" + r.stderr)
    print(f"note: one-shot exit={r.returncode}, output tail={out[-500:]!r}", flush=True)
    expect(LINUX_ONESHOT_TEXT in out, "the one-shot refuses with the spec §2.4 text", out[-300:])
    expect(not names_a_command(out), "the one-shot output names no shell command", out[-300:])
    time.sleep(2.0)
    pkexec_after = pgrep("-x", "pkexec")
    expect(not new_pids(pkexec_before, pkexec_after), "no pkexec appeared after the one-shot", pkexec_after)


def main() -> int:
    bus_addr = os.environ.get("AITM_BUS_ADDR")
    op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN")
    agent_token = os.environ.get("AITM_BUS_TOKEN")
    if not (bus_addr and op_token):
        skip("no runner-provided core: set AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN (+ AITM_BUS_TOKEN) from the "
             "privilege rig (l4.enabled: true; l4.privilege.macos_app_path: /nonexistent.app on a Mac)")
    if not agent_token:
        skip("AITM_BUS_TOKEN (the agent token) is not set: every check here runs as operator AND as agent")
    expect_how = os.environ.get("AITM_E2E_PRIV_EXPECT_HOW") or "package"
    if expect_how not in HOW_KINDS:
        fail(f"AITM_E2E_PRIV_EXPECT_HOW={expect_how!r} is not one of {HOW_KINDS}")
    core = make_core(bus_addr, op_token, agent_token)

    op = agent = None
    try:
        op = BusClient.operator(core)
        agent = BusClient.agent(core)
        names = sorted(n for n in op.tool_names() if n.startswith("l4."))
        print(f"note: {len(names)} l4.* tools on this core: {names}", flush=True)
        if not expect(READ_VERB in names and REQUEST_VERB in names,
                      f"tools/list carries {READ_VERB} and {REQUEST_VERB} (a core built from main lacks them)", names):
            fail(f"this core has no {READ_VERB}; the checks need a core built from the l4priv branch")
        if "l4.capture.status" not in names:
            skip(f"the L4 module is not enabled on this core (l4.* tools: {names}); the privilege rig sets "
                 "l4.enabled: true. Use AITM_BUS_ADDR_L4OFF for the AC2 core")

        report = check_ac1(op, agent, expect_how)
        check_ac2(op_token, agent_token)
        check_ac4(op, agent, report)
        check_request(op, report)
        check_ac24(op_token)
        agent = check_ac5(op, agent, core)
        check_linux_oneshot()
    finally:
        for c in (agent, op):
            if c is not None:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass

    if _skipped:
        print(f"note: {len(_skipped)} check(s) reported as skipped on this run (see [skipped] lines)", flush=True)
    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:8]))
    ok("PASS: the packet-capture privilege contract holds for operator and agent on this core")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
