#!/usr/bin/env python3
# e2e: tier=T1 surface=scan timeout=600 needs=aitm-tui
"""tui/tui_scan_live -- the REAL aitm-tui drives a REAL scan job against a REAL core.

aitm-tui --bus host:port --token-file p (crates/aitm-tui/src/main.rs) is started inside a
pseudo-terminal as the OPERATOR and driven by KEYSTROKES only. Every claim is read from
OUTSIDE the TUI: the harness's own operator BusClient (scan.list / scan.status /
scan.issues / scan.issue / scan.sitemap / l4.scope.list / flow.get), a SECOND BusClient
that holds a flow.subscribe subscription and counts notifications/aitm/job lines, and the
seeded test target itself. This cell is the only acceptance evidence for the TUI Scan
surface (spec ACs T7-16 .. T7-20, umbrella UI-1, UI-2, UI-3, UI-5).

  The steps run T7-17, T7-16, T7-18, T7-19 (H65): the engine dedupes issues across jobs
  by class and location, and the FIRST job that finds an issue owns it (`issue.job`); a
  later job that re-finds it emits an `issue` push line, but `scan.issues {job}` and
  `scan.status.issues` for that later job show nothing (T1b, 2026-11-01; `Issue.jobs`
  membership lands on a later head). So T7-17's job is the fresh core's first finder,
  and T7-16's sampled and cancelled jobs follow it, their issue counts irrelevant.

  T7-17 (UI-2) :scan, 1, cursor to `standard`, Enter, o <origin>, Enter, the crawl
        `browser` field set to `never` and the `speed` field to `thorough` with e (H42,
        H62/H65; the Fields walk every HTTP launch below repeats), s: while scan.status
        still says `running`, the Issues tab (J pinned to this job) shows a reflected-xss
        issue (else one carrying a payload and a probe flow) under its severity header,
        the detail shows the evidence payload scan.issue reports, Tab + Enter opens the
        first probe flow in the inspector (Request and Response panes, the flow's method
        and path, the Scan strip gone), f -> false_positive, u -> open (screen AND
        scan.issue; after each the cursor is watched for CURSOR_HOLD_S and must stay on
        the marked issue's row, H76), P opens Findings on the PoC, or the `PoC <ref> is not
        in the Findings list` toast names the issue's poc_ref (the spec's fallback, its own
        check; the self-booted core's `poc_dir` is the engine's `findings/scan/pocs`, H78).
  T7-16 (UI-1) the held `standard` editor re-entered (never assumed fresh), `browser
        never`, `speed thorough` and `intensity intrusive` asserted on their Fields lines
        (H62, H70), s -> the engine's `needs_confirmation` overlay for the intrusive
        launch (`Confirm over the wire: scan launch`, recorded as a check and answered
        with y by `launch`, H77; the prompt is read across the box's line wrap, H79) -> a
        Jobs row with the id scan.list reports, sampled as soon as it is on screen at 0.5 s
        spacing: three or more screen samples (on until the state/phase cell changes or
        SAMPLES_MAX, H80) whose on-screen `sent/budget` is non-decreasing and inside a
        scan.status bracket taken around the sample; x right after the last sample yields
        `cancelled` on screen and in scan.status (on a fresh `thorough` `intrusive` job
        cancelled in its first second when the sampled one finished before x, H37), and the
        state/phase cell changes at least once across the samples and that `cancelled` row;
        the second client saw a `progress` and a `cancelled` line for the cancelled job.
        Every launch (s, m, the confirm's y) returns only once its start reply has landed
        on the Jobs tab with the new row, since that reply switches the tab and undoes a
        tab key pressed before it (H72).
  T7-18 (UI-3) `l4-stream-safe` + t 127.0.0.1:<port>/tcp: the D7 gate text is on screen and
        s starts nothing (scan.list unchanged for 3 s); after the harness adds an inject
        L4 scope entry (removed again at the end of the run), s shows the confirm overlay
        containing "may disrupt the target", y is answered by what the harness's own
        scan.start answers for the same profile (a Jobs row for a job, the D9 wording for
        `refused_l4` or `lane_unavailable`), and n on a fresh prompt shows `scan.start
        cancelled` with no new job. A core without the `l4-stream-safe` profile FAILS
        the step; only an l4.scope.add the core refuses skips its cleared-gate sub-steps.
  T7-19 (UI-5) a `map-only` job that reached `done`: every host, `METHOD path_template` and
        point name of the harness's live scan.sitemap read is in the rendered text (never
        a fixture); Enter on the node under the cursor opens its first flow in the
        inspector, the cursor read only once the `g` after the walk has visibly put it
        back on the walk's first row (`press_home`, H74). The wait after `3`/`J` is
        head-first (H63): the job's `{n} nodes` head
        alone ends it, for the whole SITEMAP_HEAD_S (an engine refusing the tab-entry
        `scan.sitemap {}` request changes the strip banner a moment before `J`'s head
        lands); a head that never draws is reported with the banner, read as an error
        only when it CHANGED since the snapshot taken before the keys (a wording already
        on the strip is stale, H54), the Jobs cursor's job and the harness's own node
        counts (H39).
  T7-20 hygiene: the seeded Cookie value (and its first 12 hex chars) never appears in
        any screen sample taken on the Scan surface (every sample is kept, tagged with
        its surface, and grepped), and q ends the process with exit 0. The cookie is
        seeded on `GET /` (the session-bearing flow the engine's session reuse reads);
        the reflected `GET /search?q=<marker>` goes without it. No Authorization header
        is seeded: session reuse replays it on every probe and aitm-testtarget answers a
        fabricated bearer as unauthenticated, so nothing reflects (H55 as amended by T1b).

Capability gates -> exit 77 (SKIP), nothing claimed:
  * no aitm-tui binary (AITM_TUI_BIN, a build output, or PATH);
  * no aitm-testtarget-serve / no aitm binary when self-booting;
  * a runner core named by AITM_BUS_ADDR with an incomplete operator environment;
  * `scan.start` absent from tools/list (the scanner v2 engine is not on this core).
A v2 core lacking scan.sitemap / scan.issues / scan.issue FAILS the step that reads it.

Attaches to a runner core (AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN + AITM_PROXY_ADDR +
AITM_TARGET_URL) or self-boots the seeded `vulnerable` origin + Aitm.server(CoreConfig(..)):
through `aitm_e2e.scan.ScanTarget(latency_ms=300)` when the harness offers it (H81; the
engine probes about four at a time, so 40 ms gave about 100 probes/s and a job that
finished inside one 0.5 s status sample; 300 ms gives about 13 probes/s and an intrusive
job of about 20 s, so the "while running" checks never race a fast job, H82; the summary
head names the latency), else `Target("vulnerable")` at full speed with a `note`. Uses a
real pty and real ports, so it runs from a real shell or rig, NEVER from the sandbox
(which denies socket binds). Evidence (screen captures, status brackets, push counts,
summary) is written to $AITM_E2E_ARTIFACTS, else to a temp dir named on stdout; the
seeded secrets are redacted from everything written or printed, and are never printed.
Results are three-state: `ok`, `FAIL`, and `note` (a sub-step the core could not offer,
recorded and tallied apart, never a pass); a failing check keeps its whole redacted
screen as `fail-<n>-<step>.txt` and the summary lists those files (H38). The per-run
work dir (the TUI's HOME, the
0600 token file, the self-booted core's findings store with the seeded session values)
is removed with the run; the L4 scope entry the cell adds is removed by its id.

Exit 0 PASS / 1 FAIL / 77 SKIP.

`python3 -I tests/e2e/tui/test_tui_scan_live.py --selftest` runs the screen readers
(cursor row, severity group, editor header, surface tag, inspector, Findings head, the
Site map node and marker, the wire-confirm overlay and its wrapped prompt (H79), the `P`
fallback toast's ref (H78), the crawl `browser` line, the strip banner, the Site map settle
rule (H54) and head-first wait (H63), the T7-16 sampling rule (H80), the prompt bar and the
Fields `origins`/`l4`/`speed`/`intensity` lines), the failure-screen writer, the self-boot
`CoreConfig` (H78), the target booter (the `ScanTarget` lever, its argv and the fallback,
H81), the L4 scope read and add arguments (H59), the prompt, `browser`, `speed`
and `intensity` key helpers
against a scripted terminal (H49, H44, H62, H70), the launch's landing wait against
scripted screens and a scripted scan.list (H72), the tab markers against footers painted
from the Rust key tables and read back from the Rust sources (H71), and the push-counting
thread against a scripted bus client with the harness's blocking per-line read (H46, H57,
H64), against frames painted with the TUI's real geometry (the boxed Scan view, its pane
rule, a sidebar offset), with no core and no pty, one line per assertion; exit 0 when all
hold.
"""
from __future__ import annotations

import codecs
import fcntl
import inspect
import io
import json
import os
import pty
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import types
import urllib.parse

E2E = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, E2E)

from aitm_e2e import free_port  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.target import Target, testtarget_bin  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(E2E))
SKIP_EXIT = 77
COLS, ROWS = 200, 50

# Timings. The TUI polls scan.status about once a second (spec D6), so every
# screen claim is polled, never read once.
CONNECT_TIMEOUT = 60.0
UI_SETTLE = 0.35
JOB_APPEAR_S = 30.0
ROW_APPEAR_S = 20.0
# Between two T7-16 samples: the `standard` job finishes its 182 probes in about a second
# with the client crawl (the fourth live run) and its 278 `thorough` probes in about 2 s
# (the fifth: one `done` sample), so the sampled job runs `thorough` AND `intrusive` and
# is sampled at this spacing, the first sample as soon as its row is on screen (H62, H70).
SAMPLE_GAP_S = 0.5
# Never fewer than SAMPLES_MIN samples; the sampling goes on past them until the row's
# state/phase cell changes or SAMPLES_MAX samples exist (the seventh live run's three all
# read `running/audit`: the crawl phase had passed before the row appeared, H80).
SAMPLES_MIN, SAMPLES_MAX = 3, 8
CATCHUP_S = 8.0
CANCEL_S = 25.0
ISSUE_WAIT_S = 150.0
MAP_WAIT_S = 150.0
# The whole wait for the pinned job's `{n} nodes` head after `3`/`J` (H63).
SITEMAP_HEAD_S = 15.0
QUIET_WINDOW_S = 3.0
L4_SCOPE_S = 5.0
GATE_CLEAR_S = 25.0
OVERLAY_S = 20.0
# How long the Issues cursor is watched after `f` and after `u` (H76). The update reply
# replaces the row in place, so `false_positive` is on screen before the running job's
# pushes refetch the page (`app.rs` `request_issues`), and the sixth live run's refetch
# then moved the rows under a cursor that kept its index (H75): one read right after the
# `f` check could pass by luck, so the cell holds the cursor under watch for this long
# and fails the moment its name cell reads another issue.
CURSOR_HOLD_S = 2.0
EXIT_S = 15.0
# The first hex chars of a seeded secret that a truncated pane cell must still betray.
SECRET_PREFIX = 12

REDACTED = "<seeded-secret-redacted>"
JOB_ID_RE = re.compile(r"scan-[0-9a-f]{8}")
STATE_RE = re.compile(
    r"\b(queued|running|cancelling|done|cancelled|failed)(?:/(queued|crawl|passive|audit|report|done))?\b"
)
PROBES_RE = re.compile(r"(\d+)/(\d+)")
# The Scan view is drawn inside a box (`boxed(theme, "Scan", ..)`, crates/aitm-tui/src/ui/
# scan/mod.rs), so every screen row starts with the box's left border `│` and the list
# pane of each tab (Profiles, Jobs, the Site map's Nodes, Issues) sits at the box's inner
# edge: its cursor row reads `│>...` wherever the box starts (column 0 in Scan mode, which
# draws no sidebar; after one should a layout ever keep it). The capture runs to the pane
# rule (the next `│`, `panes`) or the row's end. The detail sides' own `>` marks (the
# editor's Origins pane, the Site map's Points pane, the Issues detail's flow list) follow
# the rule further right and are never the list's (fix round H, H9/H7).
CURSOR_ROW_RE = re.compile(r"│>([^│\n]*)")
# The held editor's header (`crates/aitm-tui/src/ui/scan/profiles.rs` `header`): ` profile `
# then the name, drawn at the detail pane's first cell, so the pane rule `│` stands right
# before it. The no-editor hint `⏎ opens the profile under the cursor · N new profile` and
# the D7 gate's `open the profile (⏎)` carry `profile` mid-sentence and never match (H4).
EDITOR_HEAD_RE = re.compile(r"│ profile (?!under\b)([A-Za-z0-9_.-]+)")
# The flow inspector's pane rows (`crates/aitm-tui/src/ui/inspector.rs`): ` Request  Headers ..`.
INSPECTOR_PANE_RE = re.compile(r"Request\s+Headers")
# The Findings overlay's detail head (`crates/aitm-tui/src/ui/overlays.rs` `findings`):
# ` {title}  {severity}` and nothing after it; a list row puts the severity first and
# ends with the title, so it never matches (H10).
FINDING_HEAD_RE = re.compile(r"^ (.+?)  (critical|high|medium|low|info)\s*$")
# The Issues list's name column never shrinks below this many cells
# (`crates/aitm-tui/src/ui/scan/issues.rs` `COLUMN_MIN`), so the first ISSUE_NAME_MIN chars
# of a name are always rendered (H6).
ISSUE_NAME_MIN = 8
# The core's scan error text (`aitm_scan_model::ScanErrorCode::parse_message`): `scan: <code>`.
SCAN_CODE_RE = re.compile(r"scan: ([a-z_]+)")
TOKEN = re.compile(
    r"\x1b\[([0-?]*)[ -/]*([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][@-~]|\x1b[@-Z\\-_]|[\r\n\x08]|[^\x1b\r\n\x08]+"
)

ENTER, ESC = "\r", "\x1b"
SCAN_STRIP = "1 Profiles"
# The Scan key tables as `crates/aitm-tui/src/ui/scan/mod.rs` spells them (`key_table!`
# and the `ISSUES_FILTER_KEYS` const; a `Hint` is `(key, what)`), mirrored here so the
# self-test frames paint their footers from the same tuples the TUI does and the tab
# markers below are checked against them; `rust_hints` reads the tables back from the
# Rust source in the self-test, so a renamed key fails there with no core (H71). The
# status bar's `Esc back` is the bar's own, never in a footer.
PROFILES_KEYS = (("s", "start"), ("m", "map"), ("w", "save as"), ("e", "edit"), ("Space", "toggle"))
JOBS_KEYS = (("x", "cancel"), ("⏎", "issues of this job"), ("s", "start"), ("m", "map"))
SITEMAP_KEYS = (("⏎", "open flow"), ("n", "next page"), ("J", "job filter"))
ISSUES_KEYS = (("c", "confirm"), ("f", "false positive"), ("u", "reopen"), ("⏎", "open flow"), ("P", "PoC"))
ISSUES_FILTER_KEYS = (("S", "severity"), ("C", "confidence"), ("L", "lane"), ("T", "status"), ("J", "job"),
                      ("R", "reset"))
# The Profiles list header's column names, in the order `ui/scan/profiles.rs` formats them
# (` {name}   {GAP}{lanes}{GAP}{intensity}{GAP}speed`, each `fit` to its column).
PROFILES_HEADER = ("name", "lanes", "intensity", "speed")
RUST_KEY_TABLES = os.path.join(ROOT, "crates", "aitm-tui", "src", "ui", "scan", "mod.rs")
RUST_PROFILES_VIEW = os.path.join(ROOT, "crates", "aitm-tui", "src", "ui", "scan", "profiles.rs")


def key_text(groups):
    """`key what · key what ...`: the hint groups joined the way `ui/scan/mod.rs`
    `key_text` spells a footer (H71)."""
    return " · ".join(f"{k} {w}" for g in groups for k, w in g)


RUST_HINT_RE = re.compile(r'\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)')


def rust_hints(path, table):
    """The `(key, what)` tuples the Rust key table `table` lists in the source at `path`
    (`key_table!(NAME, BAR[, MORE]: hints);` or `const NAME: &[Hint] = &[hints];`), a
    bare const hint (`RESET`, `OPEN_FLOW`) resolved from its own `const X: Hint = (..);`
    line; () when the file or the table is not there (H71)."""
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        return ()
    consts = {m.group(1): (m.group(2), m.group(3)) for m in
              re.finditer(r'const\s+([A-Z_]+)\s*:\s*Hint\s*=\s*\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)', src)}
    m = (re.search(r"key_table!\(\s*" + re.escape(table) + r"\s*,[^:]*:(.*?)\);", src, re.S)
         or re.search(r"const\s+" + re.escape(table) + r"\s*:\s*&\[Hint\]\s*=\s*&\[(.*?)\];", src, re.S))
    if m is None:
        return ()
    out = []
    for tok in re.finditer(r'\(\s*"(?:[^"\\]|\\.)*"\s*,\s*"(?:[^"\\]|\\.)*"\s*\)|\b([A-Z][A-Z_]+)\b', m.group(1)):
        if tok.group(1):
            if tok.group(1) in consts:
                out.append(consts[tok.group(1)])
        else:
            pair = RUST_HINT_RE.match(tok.group(0))
            out.append((pair.group(1), pair.group(2)))
    return tuple(out)


def rust_profiles_header(path):
    """The column names the Profiles list header formats, in order, read from the
    `format!(" {}   {GAP_TEXT}{}..", fit("name", ..), fit("lanes", ..), fit("intensity",
    ..), "speed")` call in `ui/scan/profiles.rs`; () when not found (H71)."""
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        return ()
    m = re.search(r'format!\(\s*" \{\}   \{GAP_TEXT\}\{\}\{GAP_TEXT\}\{\}\{GAP_TEXT\}\{\}",(.*?)\)\s*,\s*theme',
                  src, re.S)
    if m is None:
        return ()
    return tuple(re.findall(r'"([a-z]+)"', m.group(1)))


# A text each tab alone draws (crates/aitm-tui/src/ui/scan/{profiles,jobs,issues}.rs): the
# Profiles list header, the Jobs footer (`key_text(&[JOBS_KEYS])`), the Issues list pane's
# filter line (`key_text(&[ISSUES_FILTER_KEYS])`: `S severity · C confidence · L lane · T
# status · J job · R reset`, the Issues detail pane's footer being `key_text(&[ISSUES_KEYS])`),
# each checked in the self-test against the table it is drawn from (H71). The tab strip is
# on every tab and proves nothing about which one drew. The Site map's marker is the
# summary head's node count of the job under test (`sitemap.rs` `summary`: `N nodes · ..`),
# which T7-19 waits for after pinning the job with `J` (H11); a bare `\d+ nodes` would be
# the job-less query's answer. The head is drawn by `hint` (ui/scan/mod.rs): a pad cell,
# then the summary, so the marker keeps that pad and `3 nodes` cannot match the job-less
# answer's `13 nodes` (H12).
TAB_MARKERS = {
    "1": r"name\s+lanes\s+intensity",
    "2": r"x cancel · ⏎ issues of this job",
    "4": r"S severity · C confidence",
}
SITEMAP_MARKER = " {n} nodes"
# Spec D9 wordings a refused launch can show instead of a Jobs row (T7-18), by the
# core's error code (crates/aitm-tui/src/scan/mod.rs `code_wording`).
REFUSAL_WORDINGS = {
    "refused_l4": "L4 refused",
    "lane_unavailable": "No requested lane can run on this core",
    "out_of_scope": "Out of scope",
    "busy": "Scanner busy",
    "refused_agent": "Refused for the agent role",
}
CONFIRM_TITLE = "Confirm over the wire: scan launch"
# The Issues `P` fallback toast (`app.rs` `scan_open_poc`): `PoC <ref> is not in the
# Findings list`, the ref cut by `truncate` to POC_TOAST_MAX cells (`w - 1` chars and `…`)
# when the Findings panel lists no finding whose PoC file stem or name is the issue's
# `poc_ref` (or whose title is its name); the spec's fallback, so it passes as its own
# check when the ref it carries is the issue's (H78).
POC_TOAST_RE = re.compile(r"PoC (\S+) is not in the Findings list")
POC_TOAST_MAX = 80
NO_L4_ID = "no id"
# A job's terminal states (`aitm_scan_model::JobState`): after one of them `x` is inert
# (the banner reads `already <state>`), so T7-16 cancels a fresh job instead (H37).
TERMINAL_STATES = ("done", "cancelled", "failed")
# The editor's Fields pane walks these in this order (`crates/aitm-tui/src/scan/profiles.rs`
# `EDITOR_FIELDS`, spec D3); the cursor is a highlight, not a glyph, so the cell counts
# its `j` presses from `g` (the first field) to `use_browser` instead of reading it.
EDITOR_FIELDS = ("name", "origins", "l4_targets", "lane_http", "lane_ws", "lane_l4_packet",
                 "lane_l4_stream", "intensity", "speed", "accuracy", "checks", "crawl_strategy",
                 "use_browser", "max_depth", "max_pages", "submit_forms", "session_mode", "on_lost",
                 "budget_probes", "budget_time_s", "budget_max_issues", "http_version",
                 "record_probes")
# The crawl Fields line (`ui/scan/profiles.rs` `field_lines`, the `crawl` row:
# `<strategy> · browser <value> · depth ..`); `e` on the field cycles the ring auto, always,
# never (`crates/aitm-scan-model/src/vocab.rs` `UseBrowser`, `scan/profiles.rs` `BROWSERS`).
# A `standard` job under `auto` with no reachable browser burns its probes without finding
# a point (the first live run: 182 probes, zero issues), so every HTTP launch from the held
# editor sets `never` first and asserts the line (H42).
BROWSER_FIELD_RE = re.compile(r"· browser (auto|always|never) ·")
BROWSER_RING = ("auto", "always", "never")
# The `intensity` Fields line (`field_lines`: `<intensity>   speed <v>   accuracy <v>`); `e`
# on the `speed` field cycles the ring fast, normal, thorough (`crates/aitm-scan-model/src/
# vocab.rs` `Speed`, `scan/profiles.rs` `SPEEDS`). With the client crawl a `standard` job
# finishes its 182 probes in about a second (the fourth live run), too fast for T7-16's
# three samples and its `x`, so the sampled job and the fresh cancel job run `thorough`
# (H62), and so does T7-17's first-finder job (H65). The Profiles list header's bare
# `speed` is followed by a pad or the pane rule, never a ring word, so it never reads.
SPEED_FIELD_RE = re.compile(r"\bspeed (fast|normal|thorough)\b")
SPEED_RING = ("fast", "normal", "thorough")
# The same Fields line's first value (`│ intensity <v>   speed ..`, the label padded to
# LABEL_W at the detail pane's first cell); `e` on the `intensity` field cycles the ring
# passive, light, medium, intrusive (`crates/aitm-scan-model/src/vocab.rs` `Intensity`,
# `scan/profiles.rs` `INTENSITIES`). `thorough` alone still finished the `standard` job in
# about 2 s (the fifth live run: 278 probes, one `done` sample), so T7-16's sampled job and
# its fresh cancel job run `intrusive` too (H70); T7-17's first finder keeps `thorough`
# alone. The list header's `intensity` is followed by a pad then `speed`, and the list
# rows' intensity cells stand without the label, so neither reads.
INTENSITY_FIELD_RE = re.compile(r"│ intensity +(passive|light|medium|intrusive)\b")
INTENSITY_RING = ("passive", "light", "medium", "intrusive")
# The Scan prompts' bar (`ui/bars.rs` `prompt`): while `Mode::Prompt` is up the status
# row (the screen's last) reads ` <label> <typed>` with the label one of `origin:` (o),
# `l4 target:` (t), `profile name:` (w) or `value:` (e on a text or number field).
# `submit_retrying` (app.rs) closes the prompt on Ok and keeps it up with the line
# cleared on a refusal; Enter is processed after the bar has echoed the typed value, so
# a helper that returned on the echo let the next keys type into the open prompt and
# an Esc discard the value (H43): every prompt helper waits for the bar to leave AND
# the value to land on its Fields line (H49), and `e` is checked for a stray `value:`
# prompt (H44).
PROMPT_BAR_RE = re.compile(r"^ (origin|l4 target|profile name|value):(?=\s|$)")
# A held editor's Fields line (`ui/scan/profiles.rs` `fields`): ` <label padded to
# LABEL_W> <segments>` at the detail pane's first cell, right after the pane rule; the
# `origins` and `l4` values are `text_of`'s (`none` when empty, else comma-joined).
FIELD_LINE_RE = r"│ {label} {{2,}}(\S[^│]*?)\s*(?:│|$)"
# The strip banner's quiet states (`ui/scan/mod.rs` `banner`): `idle`, a refresh in flight,
# the `already <state>` notice a key left. Anything else on the strip row is the tab's
# last error wording (D9) or its degraded text (D2), which T7-19 waits for as the other
# way the Site map can settle (H39).
BANNER_QUIET_RE = re.compile(r"^(idle|refreshing \S+\.\.\.|already [a-z]+)$")


class Fatal(Exception):
    """The scenario cannot go on (recorded as a failed check)."""


def skip77(line: str) -> None:
    """Exit 77 with the one skip line the plan names (loud, never green)."""
    print(f"SKIP: {line}", flush=True)
    sys.exit(SKIP_EXIT)


def hostport(addr):
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), int(port)


def find_tui():
    """AITM_TUI_BIN, else the usual build outputs, else PATH; None if absent."""
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(ROOT, "target")
    cands = [os.environ.get("AITM_TUI_BIN"), os.path.join(target, "debug", "aitm-tui"),
             os.path.join(target, "release", "aitm-tui"), shutil.which("aitm-tui")]
    return next((c for c in cands if c and os.path.isfile(c)), None)


def poll(pred, timeout, interval=0.2):
    deadline = time.monotonic() + timeout
    while True:
        if pred():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def wait_field(read, key, want, timeout, interval=0.4):
    """Poll `read()` (a dict-returning bus read) until its `key` is `want`; the last
    dict read, so the caller can print what the core said instead."""
    last = {}

    def hit():
        nonlocal last
        got = read()
        if isinstance(got, dict):
            last = got
        return last.get(key) == want

    poll(hit, timeout, interval)
    return last


class Screen:
    """Just enough VT100 to know what is on the terminal NOW: cursor moves and erases are
    applied to a grid; colours and private modes are ignored."""

    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.x = self.y = 0
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._pending = ""

    def feed(self, data):
        text = self._pending + self._dec.decode(data)
        self._pending = ""
        pos = 0
        while pos < len(text):
            m = TOKEN.match(text, pos)
            if m is None:
                if text[pos] == "\x1b" and len(text) - pos < 64:
                    self._pending = text[pos:]
                    return
                pos += 1
                continue
            tok, pos = m.group(0), m.end()
            if tok[0] == "\x1b":
                if tok[1] == "[":
                    self._csi(m.group(1) or "", m.group(2))
            elif tok == "\r":
                self.x = 0
            elif tok == "\n":
                self.y = min(self.y + 1, self.rows - 1)
            elif tok == "\x08":
                self.x = max(self.x - 1, 0)
            else:
                row = self.grid[self.y]
                for ch in tok:
                    if ch >= " " and ch != "\x7f" and self.x < self.cols:
                        row[self.x] = ch
                        self.x += 1

    def _csi(self, params, final):
        if params.startswith("?") or final == "m":
            return
        p = [int(v) if v.isdigit() else 0 for v in params.split(";")] if params else []
        n = (p[0] if p else 0) or 1
        if final in "Hf":
            self.y = min(max(p[0] if p else 1, 1) - 1, self.rows - 1)
            self.x = min(max(p[1] if len(p) > 1 else 1, 1) - 1, self.cols - 1)
        elif final == "A":
            self.y = max(self.y - n, 0)
        elif final == "B":
            self.y = min(self.y + n, self.rows - 1)
        elif final == "C":
            self.x = min(self.x + n, self.cols - 1)
        elif final == "D":
            self.x = max(self.x - n, 0)
        elif final == "G":
            self.x = min(n - 1, self.cols - 1)
        elif final == "d":
            self.y = min(n - 1, self.rows - 1)
        elif final == "J":
            mode = p[0] if p else 0
            for yy in range(self.rows):
                if mode >= 2 or (mode == 0 and yy > self.y) or (mode == 1 and yy < self.y):
                    self.grid[yy] = [" "] * self.cols
            if mode < 2:
                self._erase_line(mode)
        elif final == "K":
            self._erase_line(p[0] if p else 0)

    def _erase_line(self, mode):
        lo, hi = {0: (self.x, self.cols), 1: (0, self.x + 1)}.get(mode, (0, self.cols))
        for i in range(lo, min(hi, self.cols)):
            self.grid[self.y][i] = " "

    def text(self):
        return "\n".join("".join(r).rstrip() for r in self.grid)


class Terminal:
    """aitm-tui on a pty: the screen as it is now (text), keys (press)."""

    def __init__(self, argv, env):
        self.screen = Screen(COLS, ROWS)
        self._lock = threading.Lock()
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                                     start_new_session=True)
        os.close(slave)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            with self._lock:
                self.screen.feed(chunk)

    def text(self):
        with self._lock:
            return self.screen.text()

    def wait_for(self, pattern, timeout):
        rx = re.compile(pattern)
        poll(lambda: rx.search(self.text()) is not None or self.proc.poll() is not None, timeout)
        return rx.search(self.text()) is not None

    def press(self, keys):
        os.write(self.master, keys.encode("utf-8"))

    def wait_exit(self, timeout):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self):
        if self.proc.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.proc.pid, sig)
                except ProcessLookupError:
                    break
                if self.wait_exit(8) is not None:
                    break
        try:
            os.close(self.master)
        except OSError:
            pass


class Evidence:
    """Every screen sample is kept RAW in memory (T7-20 greps the raw samples), tagged
    with the surface its text shows (`surface_of`: `scan`, the four tabs; `inspector`, a
    flow detail; `other`, Flows, Findings, the exit), and written REDACTED to the
    artifacts dir, so no file and no printed line can carry a seeded secret. An overlay
    is tagged by the body under it, which is the view the launch came from (`ui/mod.rs`
    `render` draws the body of `wire_confirm_from` under `Mode::WireConfirm`, H18): a
    Scan launch's wire confirm tags `scan` and is in the T7-20 grep; an L4 confirm from
    Flows tags `other` or `inspector` (H15). A secret is matched whole and by its first
    SECRET_PREFIX hex chars, so a pane that truncates the value is still caught."""

    def __init__(self, secret_values, directory=None):
        self.secrets = [s for s in secret_values if s]
        self.needles = []
        for s in self.secrets:
            self.needles.append(s)
            if len(s) > SECRET_PREFIX:
                self.needles.append(s[:SECRET_PREFIX])
        self.samples = []  # (step, tag, raw text)
        self._dir = directory or os.environ.get("AITM_E2E_ARTIFACTS") or None

    @property
    def dir(self):
        """The artifacts dir, created on first use so a skip leaves nothing behind."""
        if self._dir is None:
            self._dir = tempfile.mkdtemp(prefix="aitm-tui-scan-")
            print(f"evidence dir: {self._dir}", flush=True)
        else:
            os.makedirs(self._dir, exist_ok=True)
        return self._dir

    def redact(self, text):
        out = str(text)
        for s in self.needles:  # whole values first, then their prefixes
            out = out.replace(s, REDACTED)
        return out

    def sample(self, step, text, tag):
        """Record one screen sample under `step` on surface `tag` and return it (raw)."""
        self.samples.append((step, tag, text))
        return text

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.redact(text))
        return path

    def write_json(self, name, obj):
        return self.write(name, json.dumps(obj, indent=2, sort_keys=True, default=str))

    def leaks(self, tag):
        """(index, tag, step) of every sample on surface `tag` carrying a seeded secret
        or its prefix (T7-20)."""
        return [(i, t, step) for i, (step, t, text) in enumerate(self.samples)
                if t == tag and any(n in text for n in self.needles)]

    def tagged(self, tag):
        return sum(1 for _, t, _ in self.samples if t == tag)


def step_slug(name):
    """The step a check belongs to, from its name's prefix (`T7-16: ..` -> `t7-16`,
    `seed: ..` -> `seed`), as a file-name part."""
    return re.sub(r"[^a-z0-9]+", "-", name.split(":", 1)[0].lower()).strip("-") or "check"


class Checks:
    """Three-state results: `ok`, `FAIL`, `note` (a sub-step the core could not offer,
    recorded and tallied apart; never a pass, never a failure). A failing check keeps
    the whole screen as evidence (H38): when `screen` (the raw screen text) and `write`
    (the Evidence writer, which redacts) are given, the screen goes to
    `fail-<n>-<step>.txt` (`n` the failure's ordinal), the check's line names the file
    and `files` lists them for the summary; the detail's 700-character cut stays for
    the stdout reader."""

    def __init__(self, redact=str, screen=None, write=None, out=None):
        self.results = []  # (name, state)
        self.files = []  # the failure screens written (H38)
        self._redact = redact
        self._screen = screen
        self._write = write
        self._out = out

    def _say(self, line):
        print(line, file=self._out if self._out is not None else sys.stdout, flush=True)

    def _keep_screen(self, name):
        """Write the failing screen; the path, or what stopped the write (never raises:
        a check must record its failure whatever the terminal is doing)."""
        if self._screen is None or self._write is None:
            return ""
        try:
            path = self._write(f"fail-{len(self.failed())}-{step_slug(name)}.txt", self._screen())
        except Exception as e:  # noqa: BLE001
            return f"  -- screen not kept: {type(e).__name__}"
        self.files.append(path)
        return f"  -- screen: {path}"

    def check(self, name, ok, detail=""):
        ok = bool(ok)
        self.results.append((name, "ok" if ok else "FAIL"))
        tail = "" if ok or not detail else f"  -- {self._redact(detail)[:700]}"
        if not ok:
            tail += self._keep_screen(name)
        self._say(("ok   " if ok else "FAIL ") + name + tail)
        return ok

    def note(self, name, detail=""):
        self.results.append((name, "note"))
        tail = f"  -- {self._redact(detail)[:300]}" if detail else ""
        self._say("note " + name + tail)

    def fatal(self, name, detail=""):
        self.check(name, False, detail)
        raise Fatal(name)

    def failed(self):
        return [n for n, state in self.results if state == "FAIL"]

    def tally(self):
        """(ok, noted, failed) counts."""
        states = [s for _, s in self.results]
        return states.count("ok"), states.count("note"), states.count("FAIL")

    def lines(self):
        return [f"{state:<5}{n}" for n, state in self.results]


JOB_PUSH = "notifications/aitm/job"
PUSH_SAMPLES = 3
# One socket read of the push thread: `BusClient.wait_notification(JOB_PUSH, PUSH_READ_S)`,
# the per-line read T1b's `tests/e2e/scan/test_t1_push.py` receives the job lines with
# (`aitm_e2e/scan.py` `collect_push`, which passes the REMAINING budget as the timeout,
# so it never times out mid-read). The harness's `_read_line` is `_rfile.readline()` on
# a buffered file over the socket, and after ONE read timeout that reader is broken:
# `OSError: cannot read from timed out object` at once on every later read, which
# `wait_notification` swallows into an instant None. The fourth live run's thread read
# with a 1.0 s timeout and spun 32 million instant `None`s, seeing no job line. So the
# read blocks for the cell's own budget, the thread never reads again after a None (a
# timeout, or that swallowed error), and `stop()` wakes the blocked read by shutting the
# client's socket down (`shutdown(SHUT_RDWR)`: the readline returns "" and `_read_line`
# raises `BusError`) before joining the thread. `close()` alone would not: the buffered
# reader's lock is held through the read, so `_rfile.close()` waits for it, and
# `socket.close()` under an open `makefile` does not close the fd (H64). The third live
# run's thread read with `drain_notifications(0.5)`, which returns only after 0.5 s of
# silence on the socket: the TUI's polling fans a `notifications/aitm/agent` audit line
# out to the subscriber every ~150 ms (2342 lines in that run), so the drain never
# returned while the TUI lived and all 2518 lines landed in one batch after `q` (H57).
PUSH_READ_S = 600.0
# A None back sooner than this never waited on the socket: the broken reader (H64).
PUSH_WAITED_S = 0.5
PUSH_READ = (f"BusClient.wait_notification({JOB_PUSH!r}, {PUSH_READ_S:.0f} s) per line, blocking, the "
             "client's stash folded around each read (T1b collect_push); never read again after a "
             "None; stop() shuts the socket down under the read")


class Pushes:
    """The second bus client: holds a flow.subscribe subscription and tallies
    notifications/aitm/job lines by job and params.event (spec D3 push kind; the
    engine fans `{job, kind, event, seq, status, issue?}` out to every connection
    holding any flow.subscribe, no replay). It subscribes as T1b's cell does (one
    `flow.subscribe {}` on a second operator `BusClient`) and reads as T1b's
    `collect_push` does: one `wait_notification(JOB_PUSH, read_s)` per job line, the
    read BLOCKING for the cell's budget (PUSH_READ_S; the harness's reader is broken
    after one timeout, H64), the lines it stashes meanwhile (replies, flow and agent
    lines) folded from the client's stash around each read and once more when the
    thread ends, never a drain that waits for a quiet socket (H57; `read` in the
    snapshot names the mechanism, `idle_reads` counts a read that waited and returned
    nothing). A read that returns None is the last: `stopped_by` says whether it timed
    out or ended at once (the broken reader, a swallowed socket error). The TUI's own
    connection is no observer: it polls and holds no subscription, so it sees no push.
    Its own state is visible (H46): every line counted by method, the first
    PUSH_SAMPLES raw job params kept, the flow.subscribe reply, the lines the client
    could not parse and the messages the fold rejected (each counted and read past,
    never fatal), and why the thread stopped: `stop()` (which shuts the socket down
    under the blocked read), the None, or `<Type>: <text>` when an exception ended
    `_run` (the socket closed by the core is a `BusError`). The first live run
    recorded `{}` with none of this, so an empty count could not be told from a dead
    thread."""

    def __init__(self, client, subscribe_reply=None, read_s=PUSH_READ_S):
        self.client = client
        self.subscribe_reply = subscribe_reply
        self.read_s = read_s
        self.counts = {}  # job -> event -> n
        self.by_method = {}  # method (or `<reply>`) -> lines
        self.lines = 0
        self.idle_reads = 0
        self.bad_lines = 0
        self.bad_messages = 0
        self.last_error = ""
        self.samples = []  # the first PUSH_SAMPLES job params, raw (redacted on write)
        self.stopped_by = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            while not self._stop.is_set():
                # The stash first: `wait_notification` answers a stashed job line without
                # removing it, so the stash must hold no job line when it is called.
                self._fold_stash()
                started = time.monotonic()
                try:
                    m = self.client.wait_notification(JOB_PUSH, timeout=self.read_s)
                except (ValueError, AttributeError) as e:
                    # One line `_recv` could not parse, or parsed to no object: the socket
                    # is intact and the line consumed; read on.
                    self._error("bad_lines", e)
                    continue
                if m is None:
                    self._none(time.monotonic() - started)
                    return
                self._fold_one(m)
                self._fold_stash()
        except Exception as e:  # noqa: BLE001  the socket died or the client is gone
            # `stop()` shuts the socket down under the read: that `BusError` is the stop.
            self._end("stop()" if self._stop.is_set() else f"{type(e).__name__}: {e}")
            return
        finally:
            # Whatever the client read past while blocking (agent and flow lines) counts.
            self._fold_stash()
        self._end("stop()")

    def _none(self, waited):
        """A read that returned None ends the thread; it never reads again (H64). After
        `stop()` it is the shut-down socket; one that waited counts as the idle read
        and, at the whole timeout, is the timeout; one back at once is the harness's
        reader broken by an earlier timeout, or a socket error it swallowed."""
        if self._stop.is_set():
            self._end("stop()")
            return
        if waited >= PUSH_WAITED_S:
            with self._lock:
                self.idle_reads += 1
        if waited >= self.read_s * 0.9:
            self._end(f"read timeout: no job line in {waited:.1f} s; the thread never reads again "
                      "after a None (H64)")
        else:
            self._end(f"read ended with None after {waited:.3f} s (the harness reader swallowed a socket "
                      "error, or is broken by an earlier timeout); the thread never reads again (H64)")

    def _fold_stash(self):
        """Fold and empty the client's stash (what `wait_notification` read past)."""
        stash = self.client.notifications
        msgs, stash[:] = list(stash), []
        for m in msgs:
            self._fold_one(m)

    def _fold_one(self, m):
        try:
            self._fold(m)
        except Exception as e:  # noqa: BLE001  one bad message, never the thread
            self._error("bad_messages", e)

    def _fold(self, m):
        if not isinstance(m, dict):
            raise TypeError(f"message is not an object: {type(m).__name__}")
        method = m.get("method")
        key = str(method) if method else ("<reply>" if "id" in m else "<no method>")
        with self._lock:
            self.lines += 1
            self.by_method[key] = self.by_method.get(key, 0) + 1
        if method != JOB_PUSH:
            return
        params = m.get("params")
        if not isinstance(params, dict):
            raise TypeError(f"{JOB_PUSH} params are not an object: {type(params).__name__}")
        job, event = str(params.get("job")), str(params.get("event"))
        with self._lock:
            per = self.counts.setdefault(job, {})
            per[event] = per.get(event, 0) + 1
            if len(self.samples) < PUSH_SAMPLES:
                self.samples.append(params)

    def _error(self, counter, e):
        with self._lock:
            setattr(self, counter, getattr(self, counter) + 1)
            self.last_error = f"{type(e).__name__}: {e}"[:300]

    def _end(self, reason):
        with self._lock:
            if self.stopped_by is None:
                self.stopped_by = reason

    def alive(self):
        """True while the drain thread runs (it stops only on `stop()` or a dead socket)."""
        return self._thread.is_alive() and self.stopped_by is None

    def of(self, job):
        with self._lock:
            return dict(self.counts.get(job, {}))

    def snapshot(self):
        """Everything `push-counts.json` records (H46)."""
        with self._lock:
            return {"by_job": {j: dict(ev) for j, ev in self.counts.items()},
                    "by_method": dict(self.by_method), "lines": self.lines,
                    "idle_reads": self.idle_reads, "read": PUSH_READ,
                    "bad_lines": self.bad_lines, "bad_messages": self.bad_messages,
                    "last_error": self.last_error, "stopped_by": self.stopped_by,
                    "subscribe_reply": self.subscribe_reply,
                    "first_job_params": list(self.samples)}

    def describe(self):
        """The state as one failure detail (redacted by the check that prints it)."""
        s = self.snapshot()
        return (f"push thread stopped_by: {s['stopped_by'] or 'running'}; {s['lines']} lines by method "
                f"{s['by_method']}; {s['idle_reads']} idle reads of {s['read']}; bad lines "
                f"{s['bad_lines']}, bad messages {s['bad_messages']}, last "
                f"error {s['last_error']!r}; flow.subscribe reply {s['subscribe_reply']!r}; first "
                f"{JOB_PUSH} params {s['first_job_params']}")

    def stop(self):
        """End the thread: the stop flagged, then the client's socket (the harness's
        `_sock`, the one its `close()` would close) shut down so the blocked read
        returns at once with a `BusError`, then the join. The client itself is closed
        by the run's cleanup once the thread is gone (its `close()` would otherwise
        wait for the read, see PUSH_READ_S; H64)."""
        self._stop.set()
        sock = getattr(self.client, "_sock", None)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._thread.join(timeout=3)


# ----------------------------------------------------------------- bus reads


def job_ids(bus):
    try:
        res = bus.call("scan.list", {})
    except (ToolError, BusError):
        return set()
    return {j.get("job") for j in (res.get("jobs") or []) if isinstance(j, dict) and j.get("job")}


def wait_new_job(bus, before, timeout):
    found = {}

    def seen():
        new = job_ids(bus) - before
        if new:
            found["id"] = sorted(new)[0]
            return True
        return False

    poll(seen, timeout, 0.4)
    return found.get("id")


def status_of(bus, job):
    try:
        return bus.call("scan.status", {"job": job})
    except (ToolError, BusError) as e:
        return {"error": str(e)}


def sent_of(status):
    try:
        return int((status.get("probes") or {}).get("sent"))
    except (TypeError, ValueError):
        return None


def issue_of(bus, issue_id):
    try:
        res = bus.call("scan.issue", {"id": issue_id})
    except (ToolError, BusError):
        return {}
    return res if isinstance(res, dict) else {}


def cancel_quietly(bus, job):
    if not job:
        return
    try:
        bus.call("scan.cancel", {"job": job})
    except (ToolError, BusError):
        pass


# -------------------------------------------------------------- screen reads


def line_with(text, needle):
    for line in text.split("\n"):
        if needle in line:
            return line
    return None


def row_tail(text, job):
    """The job row's text after its id (profile, targets, state/phase, counters)."""
    line = line_with(text, job)
    return line.split(job, 1)[1] if line else None


def row_probes(text, job):
    tail = row_tail(text, job)
    if tail is None:
        return None
    m = PROBES_RE.search(tail)
    return (int(m.group(1)), int(m.group(2))) if m else None


def row_state(text, job):
    tail = row_tail(text, job)
    if tail is None:
        return None
    m = STATE_RE.search(tail)
    return m.group(0) if m else None


def box_left(text):
    """The column of the Scan box's left border: the `│` right before the tab strip
    (`tab_strip` draws ` 1 Profiles ..` at the box's inner edge). None off the view."""
    for line in text.split("\n"):
        i = line.find(" " + SCAN_STRIP)
        if i > 0 and line[i - 1] == "│":
            return i - 1
    return None


def cursor_row(text):
    """The text of the row the list pane's `>` cursor marks (after the mark, to the pane
    rule, the pad before the rule dropped), or None: the `│>` at the box's left border
    (H9); off the view, the leftmost `│>` of the first row carrying one."""
    left = box_left(text)
    for line in text.split("\n"):
        for m in CURSOR_ROW_RE.finditer(line):
            if left is None or m.start() == left:
                return m.group(1).rstrip()
    return None


def on_cursor(text, needle):
    """True when the list pane's cursor row carries `needle` after at most a few glyph
    cells (`>` then the two confidence glyphs on Issues, a pad cell on the Site map)."""
    row = cursor_row(text)
    return row is not None and re.match(r"[^\n]{0,8}" + re.escape(needle), row) is not None


def list_span(text):
    """Each screen row cut to the list pane: from the box's inner edge to the pane rule
    (the next `│`), so the detail side can never be read as a list row."""
    left = box_left(text)
    start = 0 if left is None else left + 1
    out = []
    for line in text.split("\n"):
        seg = line[start:]
        cut = seg.find("│")
        out.append(seg if cut < 0 else seg[:cut])
    return out


def issue_row_name(row):
    """The name cell of an Issues cursor row (`>` then the two glyphs, a space, the name)
    cut to ISSUE_NAME_MIN chars, or None when the row has not that shape (H6)."""
    m = re.match(r"\S\S (.*)$", row or "")
    return m.group(1)[:ISSUE_NAME_MIN].rstrip() if m else None


def name_cell_matches(cell, needle):
    """True when the rendered name cell (`issue_row_name`) reads as the needle: equal,
    or cut by `fit` (`text.rs`: `w - 1` chars and `…`) to a prefix of it. At exactly
    COLUMN_MIN the cell is 7 chars and `…`, one short of the ISSUE_NAME_MIN needle
    (H17)."""
    if cell is None:
        return False
    want = needle.rstrip()
    if cell == want:
        return True
    return cell.endswith("…") and len(cell) > 1 and want.startswith(cell[:-1])


def cursor_holds(term, needle, hold_s):
    """Watch the Issues cursor row for `hold_s`: `(True, cell)` when its name cell read
    as `needle` on every read, `(False, cell)` the moment it read as anything else,
    `cell` the last name cell read (the row the cursor is on, for the failure detail).
    A refetched page that moves the rows under a cursor keeping its index is caught
    while it lands instead of being missed by one lucky read (H75, H76)."""
    last = {}

    def drifted():
        last["cell"] = issue_row_name(cursor_row(term.text()))
        return not name_cell_matches(last["cell"], needle)

    moved = poll(drifted, hold_s, 0.2)
    return not moved, last.get("cell")


def surface_of(text):
    """The surface a screen sample was taken on, read from the text itself (H3): `scan`
    while the Scan tab strip is drawn (the four tabs; an overlay counts by the body it
    leaves visible, H15), `inspector` while the flow inspector's pane row is, else
    `other`."""
    if SCAN_STRIP in text:
        return "scan"
    if INSPECTOR_PANE_RE.search(text):
        return "inspector"
    return "other"


def findings_head_title(text):
    """The title of the Findings overlay's selected finding, read from its detail head
    (` {title}  {severity}`, right of the list's rule) and nowhere else, or None (H10)."""
    for line in text.split("\n"):
        for seg in line.split("│"):
            m = FINDING_HEAD_RE.match(seg)
            if m:
                return m.group(1)
    return None


def group_of(text, needle, headers):
    """The severity header (of `headers`) the LIST row carrying `needle` sits under, or
    None. Only the list pane's span is read (`list_span`): the detail head on the right
    shares its row with the filter line and would otherwise claim the needle first."""
    lines = list_span(text)
    idx = next((i for i, ln in enumerate(lines) if needle in ln), None)
    if idx is None:
        return None
    seen = None
    for i in range(idx):
        for h in headers:
            if re.search(r"\b" + re.escape(h) + r"\s+\d+", lines[i]):
                seen = h
    return seen


def host_label(node):
    """The Site map's group key: `host[:port]`, the port only when it is not the
    scheme's default (crates/aitm-tui/src/scan/sitemap.rs)."""
    default = 443 if node.get("scheme") == "https" else 80
    port = node.get("port") or default
    return node.get("host", "") if port == default else f"{node.get('host', '')}:{port}"


def node_needle(node):
    """`METHOD path_template` as the Nodes pane writes it (`{:<4} {}`), cut so a long
    template cannot fail the match on the pane's own truncation."""
    return "{:<4} {}".format(node.get("method", ""), node.get("path_template", ""))[:40]


def node_row_head(node):
    """The Nodes pane's row text up to its flow count (`sitemap.rs` `node_text`:
    `METHOD path_template  flows n · pts n`), uncut: the whole node, so `GET  /` cannot
    claim the `GET  /search` row (H13)."""
    return "{:<4} {}  flows".format(node.get("method", ""), node.get("path_template", ""))


def node_at_cursor(under, nodes):
    """The node of the live read whose WHOLE row head (`node_row_head`) the Nodes cursor
    row `under` carries, or None (H13)."""
    return next((n for n in nodes if under.startswith(node_row_head(n))), None)


def inspector_open(text, method, path):
    """The flow inspector, and nothing else: its Request and Response pane titles
    (crates/aitm-tui/src/ui/inspector.rs), the flow's method then its WHOLE path on the
    header row (followed by whitespace, a `?` or the end: `/` is a prefix of every path,
    H13), and the Scan tab strip gone."""
    return (bool(method) and bool(path)
            and INSPECTOR_PANE_RE.search(text) is not None
            and re.search(r"Response\s+Headers", text) is not None
            and re.search(r"\b" + re.escape(method) + r"\b[^\n]*" + re.escape(path) + r"(?=\s|\?|$)",
                          text) is not None
            and SCAN_STRIP not in text)


def wordings_on(text):
    """The D9 refusal codes whose wording is on screen."""
    return sorted(code for code, w in REFUSAL_WORDINGS.items() if w in text)


def confirm_text(text):
    """The wire-confirm overlay's inner rows joined with single spaces, or None without
    the overlay (H79). The box (`ui/scan/confirm.rs` `render`: `centered`, then `boxed`
    with CONFIRM_TITLE on its top border) wraps the engine's prompt to its width
    (`wrap`), and the live prompt names the origin (`.. traffic to http://127.0.0.1:50795
    and may disrupt the target. Continue?`), so `may disrupt the` ends one row and
    `target. Continue?` starts the next (the seventh live run's `fail-2-t7-16.txt`): a
    substring search over the raw screen misses the phrase. The rows are cut between the
    box's left border (the `┌` before the title) and its right border (the `┐` on the
    title row), so nothing of the body beside the box is read, and end at the first row
    whose cell under the `┌` is not the border `│` (the bottom `└`)."""
    lines = text.split("\n")
    top = next((i for i, ln in enumerate(lines) if CONFIRM_TITLE in ln), None)
    if top is None:
        return None
    head = lines[top]
    left = head.rfind("┌", 0, head.find(CONFIRM_TITLE))
    if left < 0:
        return None
    right = head.find("┐", left)
    right = right if right > left else None
    rows = []
    for ln in lines[top + 1:]:
        if len(ln) <= left or ln[left] != "│":
            break
        rows.append(ln[left + 1:right].strip(" │"))
    return " ".join(r for r in rows if r)


def confirm_says(text, phrase):
    """True when the wire-confirm overlay is up and its prompt carries `phrase` across
    the box's line wrap (`confirm_text`, H79): what `launch` and T7-18 poll for."""
    return phrase in (confirm_text(text) or "")


def poc_toast_ref(text):
    """The ref the `PoC <ref> is not in the Findings list` toast carries, as the status
    row shows it (cut to POC_TOAST_MAX cells by `truncate`), or None without the toast
    (H78)."""
    m = POC_TOAST_RE.search(text)
    return m.group(1) if m else None


def ref_shown_is(shown, poc_ref):
    """True when the toast's ref `shown` names the issue's `poc_ref`: equal, or cut by
    `truncate` (`text.rs`: `w - 1` chars and `…`) to a prefix of it (H78)."""
    if not shown or not poc_ref:
        return False
    if shown == poc_ref:
        return True
    return shown.endswith("…") and len(shown) > 1 and poc_ref.startswith(shown[:-1])


def browser_value(text):
    """The held editor's crawl `browser` value as the Fields line reads it (`auto`,
    `always`, `never`), or None without an editor on screen (H42)."""
    m = BROWSER_FIELD_RE.search(text)
    return m.group(1) if m else None


def speed_value(text):
    """The held editor's `speed` value as its `intensity` Fields line reads it (`fast`,
    `normal`, `thorough`), or None without an editor on screen (H62)."""
    m = SPEED_FIELD_RE.search(text)
    return m.group(1) if m else None


def intensity_value(text):
    """The held editor's `intensity` value as its Fields line reads it (`passive`, `light`,
    `medium`, `intrusive`), or None without an editor on screen (H70)."""
    m = INTENSITY_FIELD_RE.search(text)
    return m.group(1) if m else None


def landed_on_jobs(text, job):
    """True when the start reply has landed: the Jobs footer (`fold_start_result`, app.rs,
    sets `scan.tab = ScanTab::Jobs`) AND `job`'s row are on screen. The start toast
    carries the id too, so the id alone proves nothing (H72, H5)."""
    return re.search(TAB_MARKERS["2"], text) is not None and row_tail(text, job) is not None


def prompt_open(text):
    """The label of the Scan prompt the status row carries (`origin:`, `l4 target:`,
    `profile name:`, `value:`), or None when no Scan prompt is up (H49, H44). The bar
    is the screen's last row (`ui/bars.rs` `prompt` draws into the status area)."""
    m = PROMPT_BAR_RE.match(text.rsplit("\n", 1)[-1])
    return m.group(1) + ":" if m else None


def field_line(text, label):
    """The held editor's Fields line labelled `label` (`origins`, `l4`, ..): the value
    text after the padded label, to the next pane rule or the row's end; None without
    one. The first match top-down is the Fields block's (the Origins pane's own head
    sits under it)."""
    m = re.search(FIELD_LINE_RE.format(label=re.escape(label)), text, re.M)
    return m.group(1) if m else None


def prompt_settled(text, landed):
    """True once no Scan prompt is up and `landed(text)` holds: the one predicate every
    prompt helper waits on after Enter (H49). A bar still up is a refusal keeping the
    prompt open or an Enter not yet processed; either way the value is not in the
    draft and no key may follow."""
    return prompt_open(text) is None and bool(landed(text))


def banner_of(text):
    """The Scan strip row's state banner (`ui/scan/mod.rs` `banner`): the text after
    the last tab label, to the box's right border; None off the view (H39)."""
    line = line_with(text, SCAN_STRIP)
    if line is None or "4 Issues" not in line:
        return None
    return line.split("4 Issues", 1)[1].split("│", 1)[0].strip()


def banner_is_error(banner):
    """True for a banner that is neither `idle`, a refresh in flight nor the `already
    <state>` notice: the tab's last error wording or its degraded text (H39)."""
    return bool(banner) and BANNER_QUIET_RE.match(banner) is None


def sitemap_settled(text, marker, banner_before):
    """How the Site map tab reads after `3`/`J` and the head wait (H54, H63): `head` when
    the job's `{n} nodes` marker is on the screen; `error` when the strip banner is an
    error wording (`banner_is_error`) AND differs from `banner_before`, the banner
    snapshotted before the keys; None otherwise. A wording that was already on the
    strip is stale (the third live run: the T7-18 L4 launch's `lane_unavailable` text,
    shown on every tab by the `last_error` fallback the Rust item H56 removed) and reads
    as nothing; so does a quiet banner. The wait itself is `wait_sitemap_head`; this
    names the outcome in the failure detail once the head never came."""
    if marker in text:
        return "head"
    now = banner_of(text)
    if now != banner_before and banner_is_error(now):
        return "error"
    return None


def wait_sitemap_head(term, marker, timeout):
    """Poll the Site map tab for the pinned job's `{n} nodes` head for the whole
    `timeout`; True once it is on screen (H63). The head alone ends the wait, never the
    strip banner: an engine that refuses the tab-entry `scan.sitemap {}` request (the
    fourth live run: `give either job or target`) changes the banner a moment before
    `J`'s own request lands its head, so a wait that also settled on a changed error
    banner raced the head and lost. The banner is read only after the head never came
    (`sitemap_settled`, in the failure detail)."""
    return poll(lambda: marker in term.text(), timeout)


def sitemap_node_count(bus, args):
    """The node count of the harness's own `scan.sitemap` read with `args`, or the
    error text (H39)."""
    try:
        live = bus.call("scan.sitemap", args)
    except (ToolError, BusError, OSError) as e:
        return f"{type(e).__name__}: {e}"
    nodes = live.get("nodes") if isinstance(live, dict) else None
    return len(nodes) if isinstance(nodes, list) else f"no nodes list in {str(live)[:80]!r}"


# ------------------------------------------------------------------- driving


class Ctx:
    """Everything a step needs; built once in main()."""

    def __init__(self, c, term, bus, pushes, ev, proxy_port, target, origin, target_port, names):
        self.c = c
        self.term = term
        self.bus = bus
        self.pushes = pushes
        self.ev = ev
        self.proxy_port = proxy_port
        self.target = target
        self.origin = origin
        self.target_port = target_port
        self.names = names
        self.marker = ""
        self.cookie_secret = ""
        self.jobs = {}
        # job id -> whether its start reply landed on the Jobs tab with its row inside the
        # launch's wait (`launch`, H72).
        self.landed = {}
        self.l4_entry_id = None

    def snap(self, step):
        """One screen sample, tagged with the surface its own text shows (`surface_of`,
        H3: never the caller's expectation), recorded for the T7-20 grep, returned raw."""
        text = self.term.text()
        return self.ev.sample(step, text, surface_of(text))

    def screen(self, step="detail"):
        """The screen as a failure detail: redacted and cut."""
        return f"screen: {self.ev.redact(self.snap(step))[-1400:]!r}"


def open_scan(ctx):
    """`:scan` opens the Scan view (the palette's first match is the `:scan` command) on
    the tab it was left on."""
    term = ctx.term
    term.press(":")
    if not term.wait_for(r"command or tool", 10):
        return False
    term.press("scan")
    time.sleep(UI_SETTLE)
    term.press(ENTER)
    return term.wait_for(re.escape(SCAN_STRIP), 10)


def tab(ctx, key, timeout=10):
    """Press a tab key and wait for the text that tab alone draws."""
    ctx.term.press(key)
    return ctx.term.wait_for(TAB_MARKERS[key], timeout)


def focus_profiles_list(ctx):
    """The Profiles List pane focused before a cursor walk (G99): while an editor is held
    its Fields pane owns the cursor keys, so one `Esc` (`close_pane`: pane = List, draft
    kept) comes first whenever the held editor's header `│ profile <name>` is on screen
    (EDITOR_HEAD_RE; the no-editor hint is not one, H4, so a plain Profiles visit presses
    nothing). The `>` row is drawn whichever pane is focused, so a List that was already
    focused is told by the strip leaving on that `Esc`, and `:scan` brings the view back
    on this tab. While a Scan prompt is still up nothing is pressed and the answer is
    False: after H43 that `Esc` would discard the typed value (H49)."""
    term = ctx.term
    if prompt_open(term.text()) is not None:
        return False
    if EDITOR_HEAD_RE.search(term.text()):
        term.press(ESC)
        time.sleep(UI_SETTLE)
        if SCAN_STRIP not in term.text() and not open_scan(ctx):
            return False
    return poll(lambda: cursor_row(term.text()) is not None, 5)


def cursor_to(ctx, needle, tries=64):
    """Walk the focused list pane from its top until the cursor marks the row carrying
    `needle`. On Profiles call `focus_profiles_list` first (G99)."""
    ctx.term.press("g")
    time.sleep(UI_SETTLE)
    for _ in range(tries):
        if on_cursor(ctx.term.text(), needle):
            return True
        ctx.term.press("j")
        time.sleep(0.15)
    return on_cursor(ctx.term.text(), needle)


def press_home(term, first_row, timeout=5.0):
    """`g` (Home) on the focused list pane, then wait until the cursor row reads
    `first_row` (the row the pane's walk started from, `cursor_row` of its first frame);
    True once it does, False after `timeout`. A read that only asked for some `>` row
    was satisfied at once by the stale screen with the cursor still on the LAST row,
    while the TUI homed and opened the first node's flow (the fifth live run's T7-19
    inspector showed `GET /` for a `POST /login` row, H74). With one row the walk's
    first row is the last and the wait ends at once, rightly."""
    term.press("g")
    return poll(lambda: (cursor_row(term.text()) or "").rstrip() == first_row.rstrip(), timeout, 0.1)


def open_profile(ctx, name):
    """Profiles tab, List pane, cursor to `name`, Enter: the editor over scan.profile.get."""
    if not tab(ctx, "1"):
        return False
    if not focus_profiles_list(ctx) or not cursor_to(ctx, name):
        return False
    ctx.term.press(ENTER)
    return ctx.term.wait_for(r"profile " + re.escape(name), 15)


def ensure_editor(ctx, name, origin):
    """The Profiles tab with `name`'s editor held over a draft carrying `origin`. A
    launch does not close the editor, so a second launch reuses the same draft; only a
    closed editor is re-opened (re-opening re-reads the profile and drops a typed
    origin, spec D11). The launch keys read the held editor whichever pane is focused."""
    if not tab(ctx, "1"):
        return False
    time.sleep(UI_SETTLE)
    text = ctx.term.text()
    if f"profile {name}" in text and origin in text:
        return True
    if not open_profile(ctx, name):
        return False
    return type_origin(ctx, origin)


def submit_prompt(ctx, key, label, value, landed, timeout):
    """Press `key`, wait for the `label` prompt bar, type `value`, Enter, and return
    True only once the prompt CLOSED and `landed(text)` holds (`prompt_settled`, H49).
    False when a Scan prompt was already up, the bar never came, or it is still up
    after `timeout` (a refused value keeps it open, `submit_retrying`): then nothing
    more is pressed here, since a key would type into the prompt and an Esc would
    discard the value (H43); the caller's check fails with the screen."""
    term = ctx.term
    if prompt_open(term.text()) is not None:
        return False
    term.press(key)
    if not poll(lambda: prompt_open(term.text()) == label, 8, 0.1):
        return False
    term.press(value)
    time.sleep(UI_SETTLE)
    term.press(ENTER)
    return poll(lambda: prompt_settled(term.text(), landed), timeout, 0.1)


def type_origin(ctx, origin, timeout=10):
    """`o` (PromptKind::ScanOrigin), the origin, Enter; True once the prompt closed and
    the origin is on the Fields `origins` line (H49)."""
    return submit_prompt(ctx, "o", "origin:", origin,
                         lambda t: origin in (field_line(t, "origins") or ""), timeout)


def type_l4_target(ctx, spec, timeout=10):
    """`t` (PromptKind::ScanL4Target), `ip:port[/tcp|udp]`, Enter; True once the prompt
    closed and the target's `ip:port` is on the Fields `l4` line (H49)."""
    return submit_prompt(ctx, "t", "l4 target:", spec,
                         lambda t: spec.split("/")[0] in (field_line(t, "l4") or ""), timeout)


def set_ring_field(ctx, step, field, want, ring, value_of, label, tag, what="the editor"):
    """The held editor's ring field `field` (an EDITOR_FIELDS name) set to `want` with
    `e`, recorded as the check `<step>: <what>'s <label> field reads `<want>` before the
    launch (<tag>)`; the answer is whether it passed. The Fields pane is focused by
    construction, not read (focus is a style): one `Esc` to the List pane
    (`focus_profiles_list`, draft kept; nothing while a prompt is up, H49), then one
    Tab (`step_pane`: List, Fields, Origins, Checks); `g` puts the field cursor on the
    first field and `j` walks it to `field` (EDITOR_FIELDS, counted, since the cursor
    is a highlight); then `e` round `ring` until `value_of(text)` (the field's value
    off its Fields line) reads `want`, each press checked to have moved the value. An
    `e` that opens a prompt instead (`value:`: the cursor was on a text or number
    field, not `field`) is answered by one Esc and no more keys; the check fails naming
    the prompt and the prompt screen is kept as `screen-<step>-stray-prompt.txt` (H44;
    the second live run typed `s` into that prompt)."""
    c, term = ctx.c, ctx.term
    name = f"{step}: {what}'s {label} field reads `{want}` before the launch ({tag})"
    if not focus_profiles_list(ctx):
        return c.check(name, False, f"the Profiles List pane never took focus (prompt up: "
                                    f"{prompt_open(term.text())!r}); {ctx.screen(step.lower())}")
    term.press("\t")
    time.sleep(UI_SETTLE)
    term.press("g")
    time.sleep(UI_SETTLE)
    term.press("j" * EDITOR_FIELDS.index(field))
    time.sleep(UI_SETTLE)
    for _ in range(len(ring)):
        was = value_of(term.text())
        if was is None or was == want:
            break
        term.press("e")
        poll(lambda: value_of(term.text()) not in (None, was) or prompt_open(term.text()) is not None,
             5, 0.1)
        prompt = prompt_open(term.text())
        if prompt is not None:
            stray = ctx.snap(f"{step.lower()}-stray-prompt")
            bar = stray.rsplit("\n", 1)[-1].strip()
            kept = ctx.ev.write(f"screen-{step}-stray-prompt.txt", stray)
            term.press(ESC)
            return c.check(name, False, f"`e` opened the `{prompt}` prompt (bar {bar!r}): the Fields "
                                        f"cursor was not on `{field}` (H44); Esc pressed, no more "
                                        f"keys; the prompt screen is {kept}")
        if value_of(term.text()) in (None, was):
            break
    value = value_of(term.text())
    return c.check(name, value == want, f"the Fields line reads {label} {value!r}; {ctx.screen(step.lower())}")


def set_browser_never(ctx, step, what="the editor"):
    """The held editor's crawl `use_browser` set to `never` (`set_ring_field`): the ring
    auto, always, never read off the crawl line (H42)."""
    return set_ring_field(ctx, step, "use_browser", "never", BROWSER_RING, browser_value,
                          "crawl `browser`", "H42", what)


def set_speed_thorough(ctx, step, what="the editor"):
    """The held editor's `speed` set to `thorough` (`set_ring_field`): the ring fast,
    normal, thorough read off the `intensity` line, so the job outlives T7-16's three
    samples and its `x` (H62) and T7-17's job is observed while running (H65)."""
    return set_ring_field(ctx, step, "speed", "thorough", SPEED_RING, speed_value, "`speed`", "H62", what)


def set_intensity_intrusive(ctx, step, what="the editor"):
    """The held editor's `intensity` set to `intrusive` (`set_ring_field`): the ring
    passive, light, medium, intrusive read off the same Fields line as `speed`, so the
    T7-16 sampled job outlives its three 0.5 s samples and its `x` where `thorough` alone
    did not (H70)."""
    return set_ring_field(ctx, step, "intensity", "intrusive", INTENSITY_RING, intensity_value,
                          "`intensity`", "H70", what)


def wait_landed(ctx, job, timeout=ROW_APPEAR_S):
    """Poll until the start reply for `job` has landed (`landed_on_jobs`: the Jobs footer
    and the job's row); True once it has, False after `timeout` (H72)."""
    return poll(lambda: landed_on_jobs(ctx.term.text(), job), timeout, 0.1)


def launch(ctx, key, timeout=JOB_APPEAR_S, land_s=ROW_APPEAR_S, step="launch"):
    """Press a launch key and return the job id scan.list gained (None when none), only
    once its start reply has landed on screen or `land_s` ran out. The `StartResult`
    switches the Scan tab to Jobs (`fold_start_result`, spec D7) whenever it arrives, so a
    tab key pressed before it lands is undone (the fifth live run: T7-17's `4` was followed
    by the Jobs tab); every launch therefore waits for the Jobs footer and the new row
    before any caller presses another key (H72). Whether the landing came in time is kept
    in `ctx.landed[job]` for the step's own check.

    An `intrusive` launch starts nothing at first: the engine answers `needs_confirmation`
    and the TUI draws the wire-confirm overlay (`CONFIRM_TITLE`, the prompt "may disrupt
    the target"; the sixth live run's `fail-3-t7-16.txt`). The key is followed by a watch
    for either the overlay or a new id; the overlay is recorded as `step`'s own check,
    answered with `y` (never `n` here: that is T7-18's sub-step), and the id and the
    landing are then waited for as for any launch (H77)."""
    before = job_ids(ctx.bus)
    ctx.term.press(key)
    answer = {}

    def answered():
        if CONFIRM_TITLE in ctx.term.text():
            answer["confirm"] = True
            return True
        new = job_ids(ctx.bus) - before
        if new:
            answer["job"] = sorted(new)[0]
            return True
        return False

    poll(answered, timeout, 0.2)
    job = answer.get("job")
    if answer.get("confirm"):
        text = ctx.snap(f"{step_slug(step)}-confirm")
        # The phrase is read across the box's line wrap (`confirm_says`, H79).
        ctx.c.check(f"{step}: the engine asked to confirm the intrusive launch (the `{CONFIRM_TITLE}` "
                    f"overlay after `{key}` carries \"may disrupt the target\"); `y` answers it (H77)",
                    confirm_says(text, "may disrupt the target"),
                    f"overlay text {confirm_text(text)!r}; {ctx.ev.redact(text)[-900:]!r}")
        ctx.term.press("y")
        job = wait_new_job(ctx.bus, before, timeout)
    if job:
        ctx.landed[job] = wait_landed(ctx, job, land_s)
    return job


def back_to_scan_list(ctx, step):
    """After the inspector: `:scan` restores the Scan view with the pane it was left on.
    The flow was opened from a Detail pane (Tab, then Enter), so that pane is focused
    and one `Esc` returns to the list (`close_pane`); should the list already be
    focused, that `Esc` leaves the view and `:scan` brings it back."""
    if not open_scan(ctx):
        return False
    ctx.term.press(ESC)
    time.sleep(UI_SETTLE)
    if SCAN_STRIP not in ctx.term.text():
        ctx.c.note(f"{step}: the list pane was already focused on re-entry (Esc left the view; reopened)")
        return open_scan(ctx)
    return True


def phases_of(samples):
    """The state/phase cells the samples carry (the empty ones dropped)."""
    return [s["screen_state_phase"] for s in samples if s["screen_state_phase"]]


def more_samples(samples):
    """True while T7-16 keeps sampling the job's row (H80): fewer than SAMPLES_MIN samples
    yet, or SAMPLES_MIN or more whose state/phase cells have not changed and fewer than
    SAMPLES_MAX. The seventh live run's three samples at 0.5 s all read `running/audit`
    (the crawl phase had passed before the row appeared), so a fixed three could never
    see a change; a job that leaves `running` ends the sampling from the caller (H37)."""
    if len(samples) < SAMPLES_MIN:
        return True
    if len(samples) >= SAMPLES_MAX:
        return False
    return len(set(phases_of(samples))) <= 1


def sample_of(n, text, job, before, after, caught_up):
    """One T7-16 sample of `job`'s row on the screen `text`, bracketed by the scan.status
    reads `before` and `after` (`status-pairs.json`): the on-screen `sent/budget` and
    state/phase cells, the bracket's `sent` and `state`. `n` is the sample's ordinal, or
    `cancel` for the post-`x` row that ends the phase-change assertion (H80)."""
    probes = row_probes(text, job)
    return {"n": n, "job": job, "screen_sent": None if probes is None else probes[0],
            "screen_budget": None if probes is None else probes[1],
            "screen_state_phase": row_state(text, job), "caught_up": caught_up,
            "status_before_sent": sent_of(before), "status_after_sent": sent_of(after),
            "status_before_state": before.get("state"), "status_after_state": after.get("state")}


# --------------------------------------------------------------------- steps


def step_seed(ctx):
    """Two real GETs through the proxy. First `GET /` carrying the session cookie
    (`Cookie: sid=..`, and nothing else): the flow the engine's session reuse reads,
    and the source of the T7-20 secret. Then `GET /search?q=<marker>` WITHOUT the
    cookie: the /search node the crawl finds and the one reflected-xss point the audit
    attacks. The third live run seeded a `Cookie` and an `Authorization: Bearer
    <fabricated>` on /search itself and raised nothing: T1b (the engine owner) ruled
    that the canary is never excluded from the audit; session reuse replays the seeded
    Authorization on every probe and aitm-testtarget answers an invalid bearer as
    unauthenticated, with no reflection. So no Authorization header is seeded at all
    (H55 as amended)."""
    c = ctx.c
    session_headers = {"Cookie": f"sid={ctx.cookie_secret}", "Connection": "close"}
    try:
        session = via_proxy(ctx.proxy_port, "GET", f"{ctx.target}/", headers=session_headers)
    except OSError as e:
        c.fatal("seed: the session-bearing GET / through the proxy failed", str(e))
    c.check("seed: GET / with the session cookie only (no Authorization header) answered 200 (H55)",
            session.status == 200, f"status {session.status}")
    url = f"{ctx.target}/search?q={ctx.marker}"
    try:
        resp = via_proxy(ctx.proxy_port, "GET", url, headers={"Connection": "close"})
    except OSError as e:
        c.fatal("seed: the GET through the proxy failed", str(e))
    body = resp.body.decode("utf-8", "replace")
    c.check("seed: GET /search (no session headers, H55) answered 200 and reflected the marker",
            resp.status == 200 and ctx.marker in body, f"status {resp.status}")

    def flows():
        try:
            return ctx.bus.call("flow.table").get("flows", [])
        except (ToolError, BusError):
            return []

    def row():
        return next((r for r in flows() if ctx.marker in (r.get("path") or "")), None)

    def session_row():
        return next((r for r in flows() if (r.get("path") or "") == "/" and r.get("method") == "GET"), None)

    c.check("seed: the core captured the seeded flow (flow.table)",
            poll(lambda: row() is not None, 20), "no row carries the marker")
    c.check("seed: the core captured the session-bearing GET / (flow.table; the T7-20 source, H55)",
            poll(lambda: session_row() is not None, 20), "no GET / row")
    c.check("seed: the TUI painted the seeded flow", poll(lambda: ctx.marker in ctx.term.text(), 20),
            ctx.screen("seed"))


def step_t7_16(ctx):
    """T7-16 (UI-1): launch from the held editor, watch the counters, cancel. It runs
    after T7-17 (H65), so the editor is re-entered (`ensure_editor`, as T7-17 did
    before) and never assumed fresh; the sampled job and the fresh cancel job run
    `thorough` and `intrusive`, since a `standard` job with the client crawl is `done`
    in about a second (H62) and a `thorough` one in about 2 s (H70). The launch returns
    once its start reply landed on the Jobs tab with the row (`launch`, H72), and the
    samples then come every SAMPLE_GAP_S (0.5 s) with `x` right after the third."""
    c, term = ctx.c, ctx.term
    if not open_scan(ctx):
        c.fatal("T7-16: `:scan` never opened the Scan view", ctx.screen("t7-16"))
    if not ensure_editor(ctx, "standard", ctx.origin):
        c.fatal("T7-16: the held `standard` editor with the target origin was not available "
                "(1, cursor, Enter, `o` <origin>, Enter)", ctx.screen("t7-16"))
    c.check("T7-16: the held `standard` editor carries the target origin on its `origins` line",
            ctx.origin in (field_line(term.text(), "origins") or ""), ctx.screen("t7-16"))
    set_browser_never(ctx, "T7-16")
    set_speed_thorough(ctx, "T7-16")
    set_intensity_intrusive(ctx, "T7-16")

    job = launch(ctx, "s", step="T7-16")
    if not job:
        c.fatal("T7-16: `s` started no job (scan.list gained no id)", ctx.screen("t7-16"))
    ctx.jobs["standard"] = job
    c.check("T7-16: scan.list reports a job id in the engine's form", bool(JOB_ID_RE.fullmatch(job)), job)

    samples = []
    for n in range(SAMPLES_MAX):
        before = status_of(ctx.bus, job)
        b_sent = sent_of(before)

        def fresh_enough():
            # The TUI polls scan.status about once a second: the paint must carry a value
            # at least as fresh as the `before` read, so the bracket is a real bracket (a
            # frozen or invented number can never satisfy it; an over-large one fails the
            # upper bound below).
            return (row_probes(term.text(), job) or (-1, 0))[0] >= (b_sent or 0)

        if n == 0:
            # A launch lands on the Jobs tab (app.rs `fold_start_result`: `scan.tab =
            # ScanTab::Jobs` on the start reply); its footer is the tab's own text, so the
            # row is read on the Jobs tab (H5). `launch` already waited for that landing
            # (H72); the first sample is taken as soon as the row's paint has caught up
            # with the bracket's first read, nothing between (H62, H70).
            caught_up = poll(lambda: landed_on_jobs(term.text(), job) and fresh_enough(), ROW_APPEAR_S, 0.1)
        else:
            caught_up = poll(fresh_enough, CATCHUP_S, 0.2)
        text = ctx.snap(f"t7-16-{n}")
        after = status_of(ctx.bus, job)
        if n == 0:
            on_jobs = re.search(TAB_MARKERS["2"], text) is not None
            c.check(f"T7-16: the Jobs tab drew and carries the row for {job}",
                    on_jobs and row_tail(text, job) is not None, f"jobs tab {on_jobs}; {ctx.screen('t7-16')}")
        samples.append(sample_of(n, text, job, before, after, caught_up))
        ctx.ev.write(f"screen-T7-16-{n}.txt", text)
        # The sampling goes on at SAMPLE_GAP_S until the state/phase cell changes or
        # SAMPLES_MAX samples exist, never fewer than SAMPLES_MIN (`more_samples`, H80: the
        # seventh live run's three all read `running/audit`); a job already out of
        # `running` ends it too, since a wait for its phase to change could only watch it
        # finish (H37).
        if not more_samples(samples):
            break
        if (after.get("state") or "") in TERMINAL_STATES:
            break
        time.sleep(SAMPLE_GAP_S)

    # `x` cancels the job under the Jobs cursor, and it goes RIGHT after the last sample
    # (H62): the bracketing read and the key come before the sample checks below. Against
    # the small target a `standard` job can finish inside the sampling window (the first
    # live run: 182 probes in about 6 s; the fourth: in about a second), and `x` on a
    # terminal job is inert (`already <state>`). So when the bracketing read taken before
    # `x` already shows a terminal state, a fresh job is launched from the held editor
    # (`thorough` too) and `x` goes within its first second, as soon as its row is drawn
    # (the launch lands on the Jobs tab with the new job under the cursor, `land_started`);
    # the cancel checks and the push counts then name that job (H37).
    cancel_job = job
    pre_x = status_of(ctx.bus, job)
    sampled_terminal = (pre_x.get("state") or "") in TERMINAL_STATES
    if not sampled_terminal:
        term.press("x")
    ctx.ev.write_json("status-pairs.json", samples)

    c.check(f"T7-16: at least {SAMPLES_MIN} screen samples carry the row's probes cell",
            len([s for s in samples if s["screen_sent"] is not None]) >= SAMPLES_MIN, samples)
    seen = [s["screen_sent"] for s in samples if s["screen_sent"] is not None]
    c.check("T7-16: the on-screen `sent` is non-decreasing across the samples",
            all(a <= b for a, b in zip(seen, seen[1:])), seen)
    bracketed = [s for s in samples if s["screen_sent"] is not None
                 and s["status_before_sent"] is not None and s["status_after_sent"] is not None]
    c.check("T7-16: every sample's on-screen `sent` lies inside the scan.status bracket "
            "taken just before and just after it",
            bool(bracketed) and all(s["status_before_sent"] <= s["screen_sent"] <= s["status_after_sent"]
                                    for s in bracketed), samples)
    # The phase-change assertion comes after `x`: the `cancelled` row is its last sample (H80).

    if sampled_terminal:
        c.note(f"T7-16: {job} read `{pre_x.get('state')}` before `x`; a fresh `standard` job is "
               "cancelled in its place (H37)", f"probes {sent_of(pre_x)}")
        if not ensure_editor(ctx, "standard", ctx.origin):
            c.check("T7-16: the held `standard` editor was available for the fresh job", False,
                    ctx.screen("t7-16"))
            return
        set_browser_never(ctx, "T7-16", "the fresh job's editor")
        set_speed_thorough(ctx, "T7-16", "the fresh job's editor")
        set_intensity_intrusive(ctx, "T7-16", "the fresh job's editor")
        fresh = launch(ctx, "s", step="T7-16")
        if not fresh:
            c.check("T7-16: `s` started the fresh job for the cancel (scan.list gained an id)", False,
                    ctx.screen("t7-16"))
            return
        ctx.jobs["cancel"] = cancel_job = fresh
        # `launch` returned once the start reply landed on the Jobs tab with the row (H72).
        on_row = ctx.landed.get(fresh, False)
        c.check(f"T7-16: the Jobs tab drew the fresh job {fresh} under the cursor",
                on_row and on_cursor(term.text(), fresh), f"landed {on_row}; {ctx.screen('t7-16')}")
        term.press("x")
    cancelled = poll(lambda: "cancelled" in (row_state(term.text(), cancel_job) or ""), CANCEL_S, 0.3)
    # The `cancelled` row is bracketed by status reads like every sample and, when it is
    # the sampled job's own row, folds in as the last sample of the phase-change
    # assertion (H80); a fresh job's row (H37) is another row and proves nothing about the
    # sampled one's phases, so it stays out of it.
    before_cancel = status_of(ctx.bus, cancel_job)
    text = ctx.snap("t7-16-cancel")
    after_cancel = status_of(ctx.bus, cancel_job)
    ctx.ev.write("screen-T7-16-cancel.txt", text)
    if cancel_job == job:
        samples.append(sample_of("cancel", text, job, before_cancel, after_cancel, cancelled))
        ctx.ev.write_json("status-pairs.json", samples)
    c.check(f"T7-16: `x` left the row of {cancel_job} reading `cancelled`", cancelled,
            f"pre-x state {pre_x.get('state')}; banner {banner_of(text)!r}; {ctx.screen('t7-16')}")
    phases = phases_of(samples)
    c.check("T7-16: the row's state/phase text changed at least once across the samples and the "
            "post-`x` `cancelled` row (H80)", len(set(phases)) > 1, phases)
    final = wait_field(lambda: status_of(ctx.bus, cancel_job), "state", "cancelled", CANCEL_S)
    c.check(f"T7-16: scan.status agrees {cancel_job} is `cancelled`", final.get("state") == "cancelled",
            final.get("state"))

    # The push counts, with the second client's own state in the failure detail: what it
    # drained by method, why its thread stopped (if it did), what flow.subscribe answered
    # and the first job lines it saw (H46); its socket must still be alive here.
    counts = ctx.pushes.of(cancel_job)
    c.check(f"T7-16: the second bus client saw a `progress` and a `cancelled` line for {cancel_job}",
            counts.get("progress", 0) >= 1 and counts.get("cancelled", 0) >= 1,
            f"counts for {cancel_job} {counts}; {ctx.pushes.describe()}")
    c.check("T7-16: the second bus client's subscription socket is still alive (its drain thread "
            "runs; it stops only on `stop()` or a dead socket)", ctx.pushes.alive(), ctx.pushes.describe())


def pick_issue(ctx, job, found):
    """One poll tick of T7-17's issue search: a reflected-xss issue of `job`, else one
    whose scan.issue read carries both an evidence payload and a probe flow. Fills
    `found` (summary, full) and returns True; False while there is none yet."""
    try:
        res = ctx.bus.call("scan.issues", {"job": job, "limit": 64})
    except (ToolError, BusError) as e:
        found["error"] = str(e)
        return False
    issues = [i for i in (res.get("issues") or []) if isinstance(i, dict)]
    found["seen"] = len(issues)
    if not issues:
        return False
    xss = [i for i in issues if "reflected-xss" in f"{i.get('check_id') or ''} {i.get('class') or ''}"]
    for summary in xss + [i for i in issues if i not in xss][:8]:
        full = issue_of(ctx.bus, summary.get("id"))
        evidence = full.get("evidence") or {}
        if summary in xss or (evidence.get("payload") and evidence.get("probe_flows")):
            found["summary"], found["full"] = summary, full
            return True
    return False


def step_t7_17(ctx):
    """T7-17 (UI-2): a live issue, its evidence, a probe flow, the status round trip. It
    is the first launch of the run (H65: the engine dedupes issues across jobs and the
    first finder owns them, so a job launched after T7-16's could never own one), so it
    opens the Scan view and the editor itself; its job runs `thorough` so it is still
    running when the Issues tab is read (H62/H65)."""
    c, term = ctx.c, ctx.term
    for verb in ("scan.issues", "scan.issue"):
        if verb not in ctx.names:
            c.check(f"T7-17: the core offers {verb} (the ground truth this step reads)", False,
                    "absent from tools/list")
            return
    if not open_scan(ctx):
        c.check("T7-17: `:scan` opened the Scan view", False, ctx.screen("t7-17"))
        return
    if not ensure_editor(ctx, "standard", ctx.origin):
        c.check("T7-17: the `standard` editor with the target origin was available (1, cursor, "
                "Enter, `o` <origin>, Enter)", False, ctx.screen("t7-17"))
        return
    set_browser_never(ctx, "T7-17")
    set_speed_thorough(ctx, "T7-17")
    job = launch(ctx, "s", step="T7-17")
    if not job:
        c.check("T7-17: the second `s` started a job", False, ctx.screen("t7-17"))
        return
    ctx.jobs["issues"] = job
    # The start reply switches the tab to Jobs when it lands (D7); `4` pressed before it
    # was undone in the fifth live run, so `launch` waited for the landing (H72).
    c.check(f"T7-17: the start reply for {job} landed on the Jobs tab with its row before any "
            "tab key (H72)", ctx.landed.get(job, False), ctx.screen("t7-17"))

    found = {}

    def picked():
        if pick_issue(ctx, job, found):
            return True
        # Stop early once the job has left `running`: the comparison needs a live job.
        return (status_of(ctx.bus, job).get("state") or "running") not in ("queued", "running")

    poll(picked, ISSUE_WAIT_S, 1.0)
    if "summary" not in found:
        c.check("T7-17: the running job produced a reflected-xss issue (else one with an "
                "evidence payload and a probe flow) that scan.issues reports", False,
                f"job {job} status {status_of(ctx.bus, job).get('state')}; "
                f"{found.get('seen', 0)} issues seen; {found.get('error', '')}")
        return
    summary, full = found["summary"], found["full"]
    issue_id, name = summary.get("id"), str(summary.get("name") or "")
    severity = str(summary.get("severity") or "").upper()
    # The list's name column is at least ISSUE_NAME_MIN cells however the pane is cut
    # (`COLUMN_MIN`); the `J` pin (checked below) keeps the cancelled job's twin issue off
    # the list, so this prefix names one row (H6). At 200 columns the box's inner width
    # is 198 and the list pane 89 (`panes`, 45 %); a row takes 4 + name + 2 + location +
    # 2 + point + 2 + status cells (`Columns::total`), so with every column at its cap
    # (40, 32, 24, 14) the name column is 40 - (120 - 89) = 9: the needle is rendered
    # whole here, and `fit` cuts a longer name to 8 chars and `…`. Only at COLUMN_MIN
    # itself (a narrower terminal) would the cell be 7 chars and `…`, which the
    # comparison below tolerates (H17).
    needle = name[:ISSUE_NAME_MIN]

    if not tab(ctx, "4"):
        c.check("T7-17: the Issues tab drew", False, ctx.screen("t7-17"))
        return
    # `J` pins the filter to the Jobs cursor's job (D11), so the row under the cursor is
    # this job's issue and not a same-named one from the cancelled job.
    term.press("J")
    c.check("T7-17: `J` pinned the Issues filter to this job (its id on the filter line)",
            poll(lambda: f"job {job}" in term.text(), 10), f"{job}; {ctx.screen('t7-17')}")
    shown = poll(lambda: needle in term.text(), 30)
    text = ctx.snap("t7-17-list")
    running = (status_of(ctx.bus, job) or {}).get("state")
    c.check("T7-17: the issue is on the Issues tab while scan.status still says `running`",
            shown and running == "running", f"state {running}; {ctx.ev.redact(text)[-900:]!r}")
    headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    c.check(f"T7-17: the issue sits under its `{severity}` severity header",
            group_of(text, needle, headers) == severity,
            f"group {group_of(text, needle, headers)}; {ctx.ev.redact(text)[-900:]!r}")

    landed = cursor_to(ctx, needle)
    row_name = issue_row_name(cursor_row(term.text()))
    c.check("T7-17: the cursor lands on the issue row (its name cell, after the glyphs, reads "
            "the issue's name)", landed and name_cell_matches(row_name, needle),
            f"row name {row_name!r} wanted {needle!r}; {ctx.screen('t7-17')}")
    evidence = full.get("evidence") or {}
    payload = str(evidence.get("payload") or "")
    if c.check("T7-17: scan.issue reports an evidence.payload for the issue", bool(payload),
               f"class {full.get('class')!r} evidence keys {sorted(evidence)}"):
        # The detail draws the payload on one row: match its first whitespace-free run,
        # which no wrap, pad or truncation can break.
        pay_needle = next((w for w in payload.split() if w), payload)[:20]
        c.check("T7-17: the detail shows the `payload` scan.issue reports",
                poll(lambda: pay_needle in term.text(), 20),
                f"payload head {pay_needle!r}; {ctx.screen('t7-17')}")

    flows = [str(f) for f in (evidence.get("probe_flows") or [])]
    if c.check("T7-17: scan.issue reports a probe flow for the issue", bool(flows), issue_id):
        try:
            first = ctx.bus.call("flow.get", {"id": flows[0]})
        except (ToolError, BusError) as e:
            first = {}
            c.check("T7-17: flow.get read the first probe flow", False, str(e))
        method, path = str(first.get("method") or ""), str(first.get("path") or "")
        term.press("\t")
        time.sleep(UI_SETTLE)
        term.press(ENTER)
        opened = poll(lambda: inspector_open(term.text(), method, path), 15)
        ctx.ev.write("screen-T7-17-inspector.txt", ctx.snap("t7-17-inspector"))
        c.check("T7-17: `⏎` on the first probe flow opened the inspector (Request/Response panes, "
                "the flow's method and path, the Scan strip gone)",
                opened, f"{method} {path!r}; {ctx.screen('t7-17')}")
        if not back_to_scan_list(ctx, "T7-17"):
            c.check("T7-17: the Scan view came back after the inspector", False, ctx.screen("t7-17"))
            return

    term.press("f")
    on_screen = poll(lambda: "false_positive" in term.text(), 20)
    after_f = wait_field(lambda: issue_of(ctx.bus, issue_id), "status", "false_positive", 20)
    ctx.ev.write("screen-T7-17.txt", ctx.snap("t7-17-false-positive"))
    c.check("T7-17: `f` marked the issue `false_positive` on screen and in scan.issue",
            on_screen and after_f.get("status") == "false_positive",
            f"scan.issue status {after_f.get('status')}; {ctx.screen('t7-17')}")
    # The next key acts on the row under the cursor (`scan_issue_status` reads
    # `cursor_issue()`), so the cursor must still be on the marked issue: the sixth live
    # run's refetch moved the rows and `u` and `P` acted on another issue (H75); the cursor
    # is held under watch for CURSOR_HOLD_S and the detail names the row it is on (H76).
    held_f, row_after_f = cursor_holds(term, needle, CURSOR_HOLD_S)
    c.check(f"T7-17: after `f` the cursor stays on the marked issue's row for {CURSOR_HOLD_S:.0f} s "
            "(its name cell reads the issue's name; the issues list refetch keeps the id, H75/H76)",
            held_f, f"cursor row {row_after_f!r} wanted {needle!r}; {ctx.screen('t7-17')}")

    term.press("u")
    after_u = wait_field(lambda: issue_of(ctx.bus, issue_id), "status", "open", 20)
    c.check("T7-17: `u` cleared `false_positive` from the screen and scan.issue reads `open`",
            poll(lambda: "false_positive" not in term.text(), 15) and after_u.get("status") == "open",
            f"scan.issue status {after_u.get('status')}; {ctx.screen('t7-17')}")
    held_u, row_after_u = cursor_holds(term, needle, CURSOR_HOLD_S)
    c.check(f"T7-17: after `u` the cursor stays on the reopened issue's row for {CURSOR_HOLD_S:.0f} s "
            "before `P` (its name cell reads the issue's name, H76)",
            held_u, f"cursor row {row_after_u!r} wanted {needle!r}; {ctx.screen('t7-17')}")

    poc_ref = str(full.get("poc_ref") or "").strip()
    stem = os.path.splitext(os.path.basename(poc_ref))[0] if poc_ref else ""
    term.press("P")
    answered = poll(lambda: "PoCs and runs" in term.text() or "is not in the Findings list" in term.text()
                    or "this issue has no PoC" in term.text(), 10, 0.2)
    opened = "PoCs and runs" in term.text()
    text = ctx.snap("t7-17-poc")
    ctx.ev.write("screen-T7-17-poc.txt", text)
    if poc_ref:
        # Two sanctioned answers (spec D11, coordinator note 3): the Findings surface open
        # on the PoC (the strong branch, checked below as before), or the fallback toast
        # `PoC <ref> is not in the Findings list` naming this issue's `poc_ref` when the
        # Findings panel (`poc.list` over the core's `poc.dir`) lists no finding for it,
        # which passes as its own check (H78). Any other screen fails the strong check.
        shown = poc_toast_ref(text)
        if not opened and shown is not None:
            c.check("T7-17: `P` reported the PoC path the Findings panel does not list (the `PoC <ref> "
                    "is not in the Findings list` toast names the issue's `poc_ref`, whole or cut to "
                    f"{POC_TOAST_MAX} cells; the spec's fallback, H78)",
                    ref_shown_is(shown, poc_ref), f"toast ref {shown!r} poc_ref {poc_ref!r}; "
                                                  f"{ctx.ev.redact(text)[-900:]!r}")
        else:
            c.check("T7-17: `P` opened the Findings surface on the issue's PoC",
                    opened, f"poc_ref {poc_ref!r} toast ref {shown!r} answered {answered}; "
                            f"{ctx.ev.redact(text)[-900:]!r}")
        if opened:
            # The Findings list marks its selection by highlight only (ui/overlays.rs), so
            # the selected finding is read from the detail pane alone: its `poc <path>`
            # line names the PoC file, else its head (` {title}  {severity}`) carries the
            # issue's name as the title `scan_open_poc` matched on (H10; a count of the
            # name anywhere on the screen would pass on the list rows alone).
            poc_line = re.search(r"\bpoc\s+(\S+)", text)
            head_title = findings_head_title(text)
            selected = ((poc_line is not None and (stem in poc_line.group(1) or poc_ref in poc_line.group(1)))
                        or (bool(name) and head_title == name))
            c.check("T7-17: the Findings selection is the issue's PoC (its file stem on the "
                    "detail's `poc` line, or the issue name as the detail head's title)",
                    selected, f"stem {stem!r} name {name!r} head {head_title!r}; "
                              f"{ctx.ev.redact(text)[-900:]!r}")
            term.press(ESC)
            time.sleep(UI_SETTLE)
            open_scan(ctx)
    else:
        c.note("T7-17: no PoC for this issue (the TUI toasted it; nothing to open)",
               "this issue has no PoC" if "no PoC" in text else text[-200:])

    cancel_quietly(ctx.bus, job)


# The injection rate the cell's inject entry carries (`l4.scope.add` `inject_rate_pps`,
# crates/aitm-proto-l4/src/commands/scope.rs: "0 => refuse. Default 0"): the engine's
# default is the fail-closed value and the guard's refusal does not yet name the field,
# so an entry added without it clears the D7 gate but can never inject (H59).
L4_INJECT_RATE_PPS = 10


def l4_args_for(declared, cidr, ports):
    """The l4.scope.add arguments for a schema declaring the property names `declared`
    (None or empty when tools/list could not be read or does not list the verb): the
    five tuple fields (`interface`, `direction`, `capability`, `cidr`, `ports`), cut to
    the declared names when known, plus `inject_rate_pps: L4_INJECT_RATE_PPS` only when
    the schema declares it (H59). Also the tuple fields the schema lacks (`unknown`)."""
    wanted = {"interface": "*", "direction": "outbound", "capability": "inject",
              "cidr": cidr, "ports": ports}
    if not declared:
        return wanted, []
    unknown = sorted(k for k in wanted if k not in declared)
    args = {k: v for k, v in wanted.items() if k in declared}
    if "inject_rate_pps" in declared:
        args["inject_rate_pps"] = L4_INJECT_RATE_PPS
    return args, unknown


def l4_add_args(bus, cidr, ports):
    """The l4.scope.add arguments, built from the names tools/list declares (`l4_args_for`)."""
    declared = None
    try:
        tools = bus.tools()
    except (ToolError, BusError):
        tools = []
    for t in tools:
        if t.get("name") == "l4.scope.add":
            schema = t.get("inputSchema") or {}
            props = schema.get("properties") or {}
            declared = set(props.keys())
    return l4_args_for(declared, cidr, ports)


L4_TUPLE_KEYS = ("cidr", "ports", "interface", "direction", "capability")


def echoed_pps(entry):
    """The injection rate an l4.scope.list entry echoes, as an int: `inject_rate.pps`
    (the core's shape, crates/aitm-proto-l4/src/commands/mod.rs) or a flat
    `inject_rate_pps`; None when the entry echoes neither or it is not a number (H59)."""
    rate = entry.get("inject_rate")
    raw = rate.get("pps") if isinstance(rate, dict) else entry.get("inject_rate_pps")
    try:
        return int(raw) if raw is not None and not isinstance(raw, bool) else None
    except (TypeError, ValueError):
        return None


def l4_entries(bus):
    """The l4.scope.list entries (dicts), or [] when the list cannot be read (a refusal,
    a closed bus, or a socket timeout: `OSError`, H16)."""
    try:
        entries = bus.call("l4.scope.list", {})
    except (ToolError, BusError, OSError):
        return []
    rows = entries if isinstance(entries, list) else (entries.get("entries") or [])
    return [e for e in rows if isinstance(e, dict)]


def l4_entry_by_id(bus, entry_id):
    """The l4.scope.list entry carrying `entry_id`, or None (never matched by cidr)."""
    return next((e for e in l4_entries(bus) if str(e.get("id")) == entry_id), None)


def l4_entry_matching(bus, args):
    """The id of the l4.scope.list entry whose WHOLE tuple is the one the cell sent
    (`cidr`, `ports` as the core echoes them, `lo-hi`, `interface`, `direction`,
    `capability`) and whose `source` is `runtime` (added over the bus), or None: the
    exact match H2 allows for a lost `l4.scope.add` reply, never the loose one G97
    ruled out. None too when any tuple key was not sent. When `inject_rate_pps` was
    sent and the entry echoes a rate (`echoed_pps`), the rate is part of the tuple,
    compared as integers (H59)."""
    if any(k not in args for k in L4_TUPLE_KEYS):
        return None
    ports = str(args["ports"])
    if "-" not in ports:
        ports = f"{ports}-{ports}"
    want = (str(args["cidr"]), ports, str(args["interface"]), str(args["direction"]),
            str(args["capability"]), "runtime")
    sent_pps = args.get("inject_rate_pps")
    for e in l4_entries(bus):
        got = tuple(str(e.get(k, "")) for k in L4_TUPLE_KEYS + ("source",))
        if got != want or not e.get("id"):
            continue
        pps = echoed_pps(e)
        if sent_pps is not None and pps is not None and pps != int(sent_pps):
            continue
        return str(e["id"])
    return None


def l4_remove_quietly(bus, entry_id):
    """Best-effort `l4.scope.remove` of the entry the cell added (run from `finally`)."""
    if not entry_id or entry_id == NO_L4_ID:
        return
    try:
        bus.call("l4.scope.remove", {"id": entry_id})
    except (ToolError, BusError, OSError):
        pass


def harness_scan_start(ctx):
    """What the core answers the harness for the L4 profile and target the TUI launched:
    ("job", id) or ("code", scan error code) or ("error", text)."""
    def answer_of(e):
        m = SCAN_CODE_RE.search(str(e))
        return ("code", m.group(1)) if m else ("error", f"{type(e).__name__}: {e}")

    try:
        profile = ctx.bus.call("scan.profile.get", {"name": "l4-stream-safe"})
    except (ToolError, BusError) as e:
        return answer_of(e)
    if not isinstance(profile, dict):
        return ("error", f"scan.profile.get answered {str(profile)[:120]!r}, not a profile object")
    target = profile.get("target")
    if not isinstance(target, dict):
        target = {}
        profile["target"] = target
    target["l4"] = [{"ip": "127.0.0.1", "port": ctx.target_port, "proto": "tcp"}]
    # The same crawl browser setting the TUI's launches carry (H42; `CrawlOptions` is
    # `deny_unknown_fields`, so the key goes on the profile's own `crawl` object).
    crawl = profile.get("crawl")
    if not isinstance(crawl, dict):
        crawl = {}
        profile["crawl"] = crawl
    crawl["use_browser"] = "never"
    try:
        res = ctx.bus.confirm("scan.start", {"profile": profile})
    except (ToolError, BusError) as e:
        return answer_of(e)
    job = res.get("job") if isinstance(res, dict) else None
    return ("job", job) if job else ("error", f"scan.start answered {str(res)[:120]!r} without a job")


def step_t7_18(ctx):
    """T7-18 (UI-3): the L4 gate, the confirm overlay, y and n."""
    c, term = ctx.c, ctx.term
    if not tab(ctx, "1"):
        c.check("T7-18: the Profiles tab drew for the L4 profile", False, ctx.screen("t7-18"))
        return
    if not focus_profiles_list(ctx) or not cursor_to(ctx, "l4-stream-safe"):
        try:
            names = [p.get("name") for p in (ctx.bus.call("scan.profile.list", {}).get("profiles") or [])]
        except (ToolError, BusError) as e:
            names = str(e)
        c.check("T7-18: the Profiles list carries l4-stream-safe", False,
                f"profiles {names}; {ctx.screen('t7-18')}")
        return
    term.press(ENTER)
    if not term.wait_for(r"profile l4-stream-safe", 15):
        c.check("T7-18: the `l4-stream-safe` editor opened", False, ctx.screen("t7-18"))
        return

    spec = f"127.0.0.1:{ctx.target_port}/tcp"
    c.check("T7-18: `t` accepted the L4 target into the editor", type_l4_target(ctx, spec),
            ctx.screen("t7-18"))
    gated = poll(lambda: "capability inject" in term.text() and "l4.scope.add" in term.text(), 20)
    ctx.ev.write("screen-T7-18-gate.txt", ctx.snap("t7-18-gate"))
    c.check("T7-18: the editor shows the D7 reason (`capability inject`, `l4.scope.add`)",
            gated, ctx.screen("t7-18"))

    before = job_ids(ctx.bus)
    term.press("s")
    time.sleep(QUIET_WINDOW_S)
    c.check(f"T7-18: `s` under the gate started nothing (scan.list unchanged for {QUIET_WINDOW_S:.0f} s)",
            job_ids(ctx.bus) == before, sorted(job_ids(ctx.bus) - before))

    args, unknown = l4_add_args(ctx.bus, "127.0.0.1/32", str(ctx.target_port))
    answer = ""
    try:
        answer = str(ctx.bus.confirm("l4.scope.add", args) or "")
    except ToolError as e:
        # The core refused: nothing was added.
        answer = f"{type(e).__name__}: {e}"
        ctx.l4_entry_id = NO_L4_ID
    except (BusError, OSError) as e:
        # The reply was lost, not refused (the bus closed, or the socket timed out:
        # `socket.timeout` is an OSError, H16): the entry may stand on the core. Its id
        # is found by the cell's own whole tuple (H2) so the run's `finally` removes it
        # by id like any other; the step then goes on with that id. No match, nothing
        # to remove.
        answer = f"{type(e).__name__}: {e}"
        ctx.l4_entry_id = l4_entry_matching(ctx.bus, args) or NO_L4_ID
    else:
        ctx.l4_entry_id = answer.strip() or NO_L4_ID

    if ctx.l4_entry_id == NO_L4_ID or not poll(
            lambda: l4_entry_by_id(ctx.bus, ctx.l4_entry_id) is not None, L4_SCOPE_S, 0.4):
        c.note("T7-18: the core refused the operator-confirmed inject L4 scope entry, so the "
               "cleared-gate sub-steps (overlay, y, n) are skipped. The operator confirm "
               "path skips the agent widen gate, so a refusal here is a core bug to report",
               f"l4.scope.add answered {answer[:200]!r}; unknown args {unknown}")
        return

    cleared = poll(lambda: "L4 launch disabled" not in term.text(), GATE_CLEAR_S, 0.5)
    c.check("T7-18: the TUI's l4.scope.list pass cleared the gate", cleared, ctx.screen("t7-18"))

    before = job_ids(ctx.bus)
    term.press("s")
    # The phrase is read across the box's line wrap (`confirm_says`, H79).
    overlay = poll(lambda: confirm_says(term.text(), "may disrupt the target"), OVERLAY_S, 0.3)
    ctx.ev.write("screen-T7-18-overlay.txt", ctx.snap("t7-18-overlay"))
    c.check("T7-18: `s` opened the wire-confirm overlay containing \"may disrupt the target\"",
            overlay, f"overlay text {confirm_text(term.text())!r}; {ctx.screen('t7-18')}")

    # A wording already on screen before `y` does not count as its answer.
    pre_codes = set(wordings_on(term.text()))
    term.press("y")
    new_job = wait_new_job(ctx.bus, before, OVERLAY_S)
    # The start toast carries the id too, so the row is read on the Jobs tab only: its
    # footer and the row together (`wait_landed`, H14, H5 parity, H72); `y` is a launch
    # too, so no key follows before that landing.
    row_shown = bool(new_job) and wait_landed(ctx, new_job)
    if not new_job:
        poll(lambda: set(wordings_on(term.text())) - pre_codes, OVERLAY_S, 0.3)
    tui_codes = sorted(set(wordings_on(term.text())) - pre_codes)
    ctx.ev.write("screen-T7-18.txt", ctx.snap("t7-18-after-y"))

    # The harness asks the core the same question after `y`. The TUI's own job is
    # cancelled first so the comparison is not refused `busy` by it (one running job per
    # origin): that would be the cell's doing, not the core's answer.
    if new_job:
        cancel_quietly(ctx.bus, new_job)
        wait_field(lambda: status_of(ctx.bus, new_job), "state", "cancelled", CANCEL_S)
    kind, value = harness_scan_start(ctx)
    harness_job = value if kind == "job" else None
    if kind == "job":
        expected, agrees = "a Jobs row", row_shown
    elif kind == "code" and value in ("refused_l4", "lane_unavailable"):
        expected, agrees = f"the D9 `{REFUSAL_WORDINGS[value]}` wording", value in tui_codes
    else:
        expected, agrees = "(no sanctioned branch)", False
    c.check("T7-18: `y` re-issued the launch and the screen answered as the harness's own "
            "scan.start did (a Jobs row for a job; the D9 wording for refused_l4 / lane_unavailable)",
            agrees, f"tui job {new_job} row {row_shown} wordings {tui_codes} (pre-existing "
                    f"{sorted(pre_codes)}); harness scan.start: {kind} {value}; expected "
                    f"{expected}; {ctx.screen('t7-18')}")
    cancel_quietly(ctx.bus, harness_job)

    if not tab(ctx, "1"):
        c.check("T7-18: the Profiles tab came back for the `n` sub-step", False, ctx.screen("t7-18"))
        return
    before = job_ids(ctx.bus)
    term.press("s")
    if not poll(lambda: CONFIRM_TITLE in term.text(), OVERLAY_S, 0.3):
        c.check("T7-18: a fresh confirm prompt opened for the `n` sub-step", False, ctx.screen("t7-18"))
        return
    term.press("n")
    said = poll(lambda: "scan.start cancelled" in term.text(), 10, 0.2)
    ctx.ev.write("screen-T7-18-cancelled.txt", ctx.snap("t7-18-n"))
    time.sleep(QUIET_WINDOW_S)
    c.check("T7-18: `n` cancelled the launch (`scan.start cancelled`) and no job appeared",
            said and job_ids(ctx.bus) == before,
            f"new ids {sorted(job_ids(ctx.bus) - before)}; {ctx.screen('t7-18')}")


def step_t7_19(ctx):
    """T7-19 (UI-5): the Site map against a live scan.sitemap read."""
    c, term = ctx.c, ctx.term
    if "scan.sitemap" not in ctx.names:
        c.check("T7-19: the core offers scan.sitemap (the ground truth this step reads)", False,
                "absent from tools/list")
        return
    if not open_profile(ctx, "map-only"):
        c.check("T7-19: the `map-only` profile editor never opened", False, ctx.screen("t7-19"))
        return
    if not type_origin(ctx, ctx.origin):
        c.check("T7-19: `o` never accepted the origin for the map job", False, ctx.screen("t7-19"))
        return
    set_browser_never(ctx, "T7-19")
    job = launch(ctx, "m", step="T7-19")
    if not job:
        c.check("T7-19: `m` started no map job", False, ctx.screen("t7-19"))
        return
    ctx.jobs["map"] = job
    done = wait_field(lambda: status_of(ctx.bus, job), "state", "done", MAP_WAIT_S, 1.0)
    reached = done.get("state") == "done"
    c.check("T7-19: the map job reached `done`", reached, done.get("state"))
    if not reached:
        return

    try:
        live = ctx.bus.call("scan.sitemap", {"job": job})
    except (ToolError, BusError) as e:
        c.check("T7-19: scan.sitemap read the live map the screen is compared against", False, str(e))
        return
    nodes = [n for n in (live.get("nodes") or []) if isinstance(n, dict)]
    points = [p for p in (live.get("points") or []) if isinstance(p, dict)]

    # The strip banner as it reads BEFORE the keys: a wording already there (the T7-18
    # launch's refusal, in the third live run) is stale and must not end the wait (H54).
    banner_before = banner_of(term.text())
    # `3`, then `J` (follow the Jobs cursor's job, the one the harness read), then the
    # job's own node count as the tab's marker: a wait on a bare `N nodes` before the pin
    # would ride on the job-less `scan.sitemap {}` answer (H11).
    term.press("3")
    term.press("J")
    marker = SITEMAP_MARKER.format(n=len(nodes))
    # The wait is head-first (`wait_sitemap_head`, H63): the head alone ends it, for the
    # whole SITEMAP_HEAD_S. Only once it never came does the failure read the strip
    # (`sitemap_settled`: a banner that changed to an error wording, where a
    # `scan.sitemap` failure lands, D9/D13), with the banner before and after, the strip
    # row, whether the body still reads `no site map yet`, the Jobs cursor's job as the
    # Jobs tab shows it (the job `J` pinned) and the harness's own node counts for
    # `scan.sitemap {}` and `{job}` (H39).
    drew = wait_sitemap_head(term, marker, SITEMAP_HEAD_S)
    text = ctx.snap("t7-19-sitemap")
    drew = drew and marker in text
    detail = ""
    if not drew:
        ctx.ev.write("screen-T7-19-sitemap.txt", text)
        all_count = sitemap_node_count(ctx.bus, {})
        jobs_cursor = None
        if tab(ctx, "2", 5):
            jobs_cursor = (cursor_row(term.text()) or "").split(" ", 1)[0] or None
        ctx.ev.write("screen-T7-19-jobs.txt", ctx.snap("t7-19-jobs"))
        detail = (f"settled: {sitemap_settled(text, marker, banner_before)!r}; banner before `3`/`J` "
                  f"{banner_before!r}, after {banner_of(text)!r} (error wording: "
                  f"{banner_is_error(banner_of(text))}); body reads `no site map yet`: "
                  f"{'no site map yet' in text}; Jobs cursor job {jobs_cursor!r} (map job {job}); "
                  f"harness scan.sitemap {{}} {all_count} nodes, {{job}} {len(nodes)} nodes; strip row "
                  f"{(line_with(text, SCAN_STRIP) or '').strip()!r}")
    if not c.check(f"T7-19: the Site map tab drew the live read's {len(nodes)} nodes for this job "
                   f"(`{marker}` on the Nodes pane head after `J`)", drew, detail):
        return

    # Walk the Nodes pane from the top, one row per `j`, polling for the cursor to move.
    # The first `g` is a no-op on a fresh tab (the Nodes cursor starts at the top), so its
    # wait is a bounded change-wait: a cursor that was elsewhere is seen moving, one that
    # was at the top costs the bound (H74).
    seen_text = []
    was_before_home = cursor_row(term.text())
    term.press("g")
    poll(lambda: cursor_row(term.text()) not in (None, was_before_home), 1.0, 0.1)
    for _ in range(min(len(nodes), 60)):
        was = cursor_row(term.text())
        seen_text.append(ctx.snap("t7-19-walk"))
        term.press("j")
        poll(lambda: cursor_row(term.text()) != was, 2.0, 0.1)
    seen_text.append(ctx.snap("t7-19-walk"))
    walked = "\n".join(seen_text)
    ctx.ev.write("screen-T7-19.txt", walked[-60000:])

    missing_hosts = sorted({host_label(n) for n in nodes if host_label(n) not in walked})
    c.check("T7-19: every host of the live scan.sitemap is rendered", not missing_hosts, missing_hosts)
    missing_nodes = sorted({node_needle(n) for n in nodes if node_needle(n) not in walked})
    c.check("T7-19: every `METHOD path_template` of the live scan.sitemap is rendered",
            bool(nodes) and not missing_nodes, f"{missing_nodes}; {len(nodes)} nodes")
    # Every point of the live read, attached to a listed node or not (fix round G, G20
    # keeps the orphans on the page).
    missing_points = sorted({str(p.get("name")) for p in points if str(p.get("name"))[:16] not in walked})
    c.check("T7-19: every point name of the live scan.sitemap is rendered",
            not missing_points, f"missing {missing_points}; {len(points)} points in the live read")

    # `⏎` on the node under the cursor after `g` (the pane renders in host-group order,
    # so the first row is not necessarily the reply's first node). The walk left the
    # cursor on the last row, so the read after `g` waits for the cursor row to read the
    # walk's first row again (`press_home`): the stale screen must not name the row the
    # TUI is no longer on (H74).
    first_row = cursor_row(seen_text[0]) or ""
    homed = press_home(term, first_row)
    under = (cursor_row(term.text()) or "").strip()
    node = node_at_cursor(under, nodes)
    if not c.check("T7-19: `g` put the cursor back on the walk's first row and the row under it is a "
                   "node of the live read (H74)", homed and node is not None,
                   f"homed {homed}; row {under!r}; the walk's first row {first_row!r}; {ctx.screen('t7-19')}"):
        return
    first_flows = [str(f) for f in (node.get("flows") or [])]
    if not c.check("T7-19: the node under the cursor carries a flow to open", bool(first_flows),
                   f"node {node.get('id')}"):
        return
    try:
        flow = ctx.bus.call("flow.get", {"id": first_flows[0]})
    except (ToolError, BusError) as e:
        c.check("T7-19: flow.get read the node's first flow", False, str(e))
        return
    method, path = str(flow.get("method") or ""), str(flow.get("path") or "")
    term.press(ENTER)
    opened = poll(lambda: inspector_open(term.text(), method, path), 15)
    ctx.ev.write("screen-T7-19-inspector.txt", ctx.snap("t7-19-inspector"))
    c.check("T7-19: `⏎` on the node under the cursor opened its first flow in the inspector "
            "(Request/Response panes, the flow's method and path, the Scan strip gone)",
            opened, f"{method} {path!r}; {ctx.screen('t7-19')}")
    open_scan(ctx)


def step_t7_20(ctx):
    """T7-20: no seeded secret on any Scan-surface screen sample; `q` exits 0."""
    c, term = ctx.c, ctx.term
    leaks = ctx.ev.leaks("scan")
    c.check("T7-20: no Scan-surface screen sample carried the seeded Cookie value "
            f"(whole or its first {SECRET_PREFIX} hex chars)",
            not leaks, f"{len(leaks)} of {ctx.ev.tagged('scan')} scan samples (index, tag, step): "
                       f"{leaks[:8]}; {len(ctx.ev.samples)} samples in all")
    for _ in range(4):
        term.press(ESC)
        time.sleep(0.25)
    term.press("q")
    code = term.wait_exit(EXIT_S)
    c.check("T7-20: `q` ended aitm-tui with exit 0", code == 0, f"exit {code}; {ctx.screen('t7-20')}")


def scenario(ctx):
    """The steps in order: T7-17 before T7-16, so its job is the fresh core's first finder
    and owns the issues it finds (the engine's cross-job dedupe, H65). T7-20 (no secret
    on screen, exit 0) runs even when an earlier step gave up, so the hygiene claim
    covers every sample taken."""
    try:
        step_seed(ctx)
        step_t7_17(ctx)
        step_t7_16(ctx)
        step_t7_18(ctx)
        step_t7_19(ctx)
    except Fatal:
        pass
    step_t7_20(ctx)


# ---------------------------------------------------------------------- main


def main():
    tui = find_tui()
    if not tui:
        skip77("no aitm-tui binary found (set AITM_TUI_BIN or `cargo build -p aitm-tui`)")

    # The secrets and the redactor exist before anything can fail, so the top-level
    # handler can redact whatever an exception carries.
    marker = "ts" + secrets.token_hex(4)
    cookie_secret = secrets.token_hex(16)
    ev = Evidence([cookie_secret])
    try:
        return run(tui, ev, marker, cookie_secret)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  {type(e).__name__}: {ev.redact(str(e))}", flush=True)
        return 1


def quietly(step):
    """Run one cleanup step; whatever it raises is swallowed so the next step runs."""
    try:
        step()
    except Exception:  # noqa: BLE001
        pass


# H81: the eighth live run's target answered a thorough intrusive scan in about two
# seconds, so the T7-16/T7-17 "while running" observations raced the job under load. No
# cell-side timing trick is reliable; the lever is a slower target: T10's
# `aitm-testtarget-serve --latency-ms N` (a per-response sleep on the HTTP and WS
# listeners), reached through `aitm_e2e.scan.ScanTarget(mode, latency_ms=)`. The tenth
# live run showed 40 ms is not enough: the engine probes about four at a time, so 40 ms a
# response gave about 100 probes/s and the intrusive job still finished inside one 0.5 s
# status sample (`status-pairs.json`: 228 to 278 probes inside the window). 300 ms gives
# about 13 probes/s, an intrusive job of about 20 s and a thorough one of about 14 s,
# inside the 600 s budget (H82). Every literal that spells the latency (the argv, the `ok`
# record, the summary head, the self-test) derives from this one constant. The harness
# copy under test may predate the flag (today's main has no `aitm_e2e.scan`), so the cell
# boots with the lever when it exists and falls back to `Target("vulnerable")` at full
# speed with a note.
TARGET_LATENCY_MS = 300
TARGET_FAST_NOTE = ("target boots at full speed: this harness has no ScanTarget(latency_ms=), so the "
                    "T7-16 and T7-17 while-running checks may race a fast job (H81)")


def slow_target_class(module=None):
    """`(ScanTarget, "")` when the harness module (`aitm_e2e.scan` unless one is given)
    has a `ScanTarget` whose constructor takes `latency_ms`; else `(None, why)`."""
    if module is None:
        try:
            from aitm_e2e import scan as module  # noqa: PLC0415  (the lever lands with T10)
        except Exception as e:  # noqa: BLE001  (an older harness, or one half landed)
            return None, f"aitm_e2e.scan is not importable: {type(e).__name__}: {e}"
    cls = getattr(module, "ScanTarget", None)
    if cls is None:
        return None, "the harness has no ScanTarget"
    try:
        params = inspect.signature(cls).parameters
    except (TypeError, ValueError) as e:
        return None, f"ScanTarget's signature is unreadable: {e}"
    if "latency_ms" not in params:
        return None, "ScanTarget takes no latency_ms"
    return cls, ""


def boot_seeded_target(slow_cls, fallback=Target, mode="vulnerable"):
    """Boot the seeded origin: `(target, latency_ms)`. With `slow_cls` (the harness's
    `ScanTarget`, H81) it serves `mode` over plain HTTP only (no TLS pair, no control
    origin: the cell reads nothing from them, as with `Target` today) with
    `--latency-ms TARGET_LATENCY_MS`; without it, `fallback(mode)` at full speed and 0.
    Both expose `base` and `authority`, which is all the cell reads."""
    if slow_cls is not None:
        return slow_cls(mode, tls=False, control=False, latency_ms=TARGET_LATENCY_MS), TARGET_LATENCY_MS
    return fallback(mode), 0


def latency_words(latency_ms):
    """The summary head's target-latency segment: the cell's own target with the lever,
    without it (0), or a runner's target the cell did not boot (None)."""
    if latency_ms is None:
        return "target latency unknown (runner core)"
    if not latency_ms:
        return "target latency none (full speed)"
    return f"target latency {latency_ms} ms"


def record_target_latency(c, latency_ms, why):
    """One `ok` line when the target boots with the lever (a record, not a probe: the
    flag is on the argv the harness built), the `TARGET_FAST_NOTE` with `why` when it
    boots at full speed, nothing for a runner core's target (H81)."""
    if latency_ms is None:
        return
    if latency_ms:
        c.check(f"target boots with {latency_ms} ms per response (H81)", True)
    else:
        c.note(TARGET_FAST_NOTE, why)


def self_boot_config(work, authority, ports):
    """The self-booted core's `CoreConfig`: the three ports (proxy, browser proxy, bus),
    the target's authority and loopback in scope, the findings store under `work`, the
    L4 lane on (`l4_enabled` only: the operator confirm path skips the agent widen gate,
    so no agent-widen flag is needed for the cell's own l4.scope.add), and `poc_dir`
    pointed at the engine's PoC store `<work>/findings/scan/pocs` (where the seventh live
    run's `poc_ref` lay), so the Findings panel (`poc.list`) lists the scan PoCs it can
    and T7-17's `P` may open on one (H78)."""
    proxy_port, browser_port, bus_port = ports
    findings = os.path.join(work, "findings")
    return CoreConfig(proxy_port=proxy_port, browser_proxy_port=browser_port, bus_port=bus_port,
                      scope_entries=[authority, "127.0.0.1"],
                      poc_dir=os.path.join(findings, "scan", "pocs"),
                      findings_dir=findings, l4_enabled=True)


def run(tui, ev, marker, cookie_secret):
    booted = tgt = bus = push_client = pushes = term = ctx = None
    work = token_file = None
    latency_ms, lever_why = None, ""  # the runner core's target is not the cell's to slow
    try:
        if os.environ.get("AITM_BUS_ADDR"):
            bus_addr = os.environ["AITM_BUS_ADDR"].strip()
            token = (os.environ.get("AITM_BUS_OPERATOR_TOKEN") or "").strip()
            proxy = (os.environ.get("AITM_PROXY_ADDR") or "").strip()
            target = (os.environ.get("AITM_TARGET_URL") or "").strip().rstrip("/")
            if not (token and proxy and target):
                skip77("a runner core was named by AITM_BUS_ADDR but AITM_BUS_OPERATOR_TOKEN / "
                       "AITM_PROXY_ADDR / AITM_TARGET_URL are incomplete (the Scan surface is "
                       "operator-only)")
            host, port = hostport(bus_addr)
            proxy_port = int(proxy.rsplit(":", 1)[1])
        else:
            if not os.path.exists(testtarget_bin()):
                skip77("no aitm-testtarget-serve binary (build it: cargo build -p aitm-testtarget, "
                       "or set AITM_TESTTARGET_BIN)")
            work = tempfile.mkdtemp(prefix="aitm-tui-scan-run-")
            slow_cls, lever_why = slow_target_class()
            tgt, latency_ms = boot_seeded_target(slow_cls)
            cfg = self_boot_config(work, tgt.authority, (free_port(), free_port(), free_port()))
            try:
                booted = Aitm.server(cfg)
            except FileNotFoundError as e:
                skip77(f"no aitm binary to self-boot a core ({e})")
            host, port = booted.bus_addr
            token = cfg.operator_token
            proxy_port, target = cfg.proxy_port, tgt.base.rstrip("/")

        host = "127.0.0.1" if host in ("", "localhost") else host
        tui_bus = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        bus = BusClient(host, port, token, client_name="aitm-e2e-scan-witness").connect()
        names = set(bus.tool_names())
        if "scan.start" not in names:
            skip77("built, awaiting engine for live proof (scan.start is not in tools/list)")

        push_client = BusClient(host, port, token, client_name="aitm-e2e-scan-pushes").connect()
        subscribed = ""
        if "flow.subscribe" in names:
            try:
                reply = push_client.call("flow.subscribe", {})
            except (ToolError, BusError) as e:
                subscribed = str(e)
                reply = f"{type(e).__name__}: {e}"
        else:
            subscribed = reply = "this bus has no flow.subscribe"
        # The reply goes into push-counts.json beside the counts (H46).
        pushes = Pushes(push_client, reply)

        u = urllib.parse.urlsplit(target)
        target_port = u.port or (443 if u.scheme == "https" else 80)
        origin = f"{u.scheme}://{u.hostname}:{target_port}"

        work = work or tempfile.mkdtemp(prefix="aitm-tui-scan-run-")
        token_file = os.path.join(work, "bus.token")
        with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(token)
        child_env = {k: v for k, v in os.environ.items()
                     if not k.startswith("AITM_") and k not in ("RUST_LOG", "COLUMNS", "LINES")}
        child_env.update({"TERM": "xterm-256color", "HOME": work, "XDG_CONFIG_HOME": work})
        term = Terminal([tui, "--bus", tui_bus, "--token-file", token_file,
                         "--expect-role", "operator", "--ansi", "--poll", "200"], child_env)

        def failing_screen():
            # The screen a failing check keeps (H38), a sample too: taken on the Scan
            # surface it is in the T7-20 grep like any other (tagged from its text, H3).
            text = term.text()
            return ev.sample("fail", text, surface_of(text))

        c = Checks(ev.redact, screen=failing_screen, write=ev.write)
        ctx = Ctx(c, term, bus, pushes, ev, proxy_port, target, origin, target_port, names)
        ctx.marker, ctx.cookie_secret = marker, cookie_secret

        record_target_latency(c, latency_ms, lever_why)
        if subscribed:
            c.note("push: the second bus client holds no flow.subscribe subscription "
                   "(the T7-16 push counts will be empty)", subscribed)
        role_rx = r"bus " + re.escape(tui_bus) + r" · (agent|operator)"
        attached = term.wait_for(role_rx, CONNECT_TIMEOUT)
        role = re.search(role_rx, term.text()).group(1) if attached else None
        c.check(f"ui: the TUI attached to bus {tui_bus} as the operator", role == "operator",
                f"role {role}; exit {term.proc.poll()}; {ev.redact(term.text())[-900:]!r}")

        scenario(ctx)

        # The drain thread is stopped first so the file carries its exit reason:
        # `stop()` here, or the exception that ended it earlier (H46).
        pushes.stop()
        ev.write_json("push-counts.json", pushes.snapshot())
        failed = c.failed()
        n_ok, n_noted, n_failed = c.tally()
        head = (("PASS" if not failed else "FAIL")
                + f": {n_ok} ok, {n_noted} noted, {n_failed} failed"
                + f"; aitm-tui Scan surface on bus {tui_bus}: jobs {sorted(ctx.jobs.values())}"
                + f"; {latency_words(latency_ms)}"
                + ("" if not failed else f"; failed: {failed}")
                + ("" if not c.files else f"; failure screens: {c.files}"))
        ev.write("summary.txt", "\n".join(c.lines() + ["", head]
                                          + [f"failure screen: {p}" for p in c.files]
                                          + [f"evidence dir: {ev.dir}"]) + "\n")
        print(head, flush=True)
        return 0 if not failed else 1
    finally:
        # Each cleanup step on its own, so one that raises cannot skip those after it;
        # the L4 scope entry goes first, before a hung TUI's kill can delay it (H1).
        if bus is not None and ctx is not None:
            # The L4 scope widening the cell added leaves with it (matched by its id).
            quietly(lambda: l4_remove_quietly(bus, ctx.l4_entry_id))
        if pushes is not None:
            quietly(pushes.stop)
        if term is not None:
            quietly(term.stop)
        if token_file:
            # The operator token never outlives the run (it is never printed either).
            quietly(lambda: os.unlink(token_file))
        if push_client is not None:
            quietly(push_client.close)
        if bus is not None:
            quietly(bus.close)
        if booted is not None:
            quietly(booted.stop)
        if tgt is not None:
            quietly(tgt.stop)
        if work:
            # The run's HOME, token file and (self-booted) findings store, which holds
            # the seeded session values raw, go with the run.
            quietly(lambda: shutil.rmtree(work, ignore_errors=True))


# -------------------------------------------------------- offline self-test


class Frame:
    """A COLS x ROWS screen painted cell by cell the way the TUI's buffer is
    (`buf.set_string(x, y, ..)`), so a self-test frame carries the renderer's geometry:
    the Scan box (`boxed`, ui/scan/mod.rs), its tab strip, the 45/55 pane split with its
    rule (`panes`), the list panes' `>` cursor rows and the detail sides. A hand-typed
    200-column literal cannot be kept honest; the painted one is checked against the
    Rust sources named at each painter."""

    def __init__(self, cols=COLS, rows=ROWS):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]

    def put(self, x, y, text):
        for i, ch in enumerate(text):
            if 0 <= x + i < self.cols and 0 <= y < self.rows:
                self.grid[y][x + i] = ch

    def text(self):
        return "\n".join("".join(r).rstrip() for r in self.grid)

    @classmethod
    def from_text(cls, text):
        """A frame re-painted from a painter's text, so an overlay can be drawn over it."""
        f = cls()
        for y, line in enumerate(text.split("\n")):
            f.put(0, y, line)
        return f

    def blank(self, x, y, w, h):
        """`Clear` over a rect (what `boxed` does before it draws)."""
        for yy in range(y, y + h):
            self.put(x, yy, " " * w)


# The whole-screen rows (ui/mod.rs `render`): toolbar, chip bar, body, status bar.
BODY_Y, BODY_H = 2, ROWS - 3
GAP_TEXT = "  "


def chrome(f):
    """The bars outside the body (ui/bars.rs): never read by a Scan check."""
    f.put(0, 0, " ›•‹ aitmproxy  ● rec   Flows  Scan  Findings")
    f.put(0, 1, " All  HTTP  HTTPS  WebSocket  h1  h2  JSON")
    f.put(0, ROWS - 1, " bus 127.0.0.1:9001 · operator")
    f.put(COLS - 60, ROWS - 1, "0 B   1 2 3 4 tabs · Tab/BackTab pane · Esc back")


def box(f, x, y, w, h, title):
    """`boxed`: a bordered block with ` title ` on the top border; its inner rect."""
    f.put(x, y, "┌" + "─" * (w - 2) + "┐")
    f.put(x + 1, y, f" {title} ")
    for yy in range(y + 1, y + h - 1):
        f.put(x, yy, "│")
        f.put(x + w - 1, yy, "│")
    f.put(x, y + h - 1, "└" + "─" * (w - 2) + "┘")
    return x + 1, y + 1, w - 2, h - 2


def scan_box(f, tab, offset=0, banner="idle"):
    """The Scan box over the body from `offset` (0 in Scan mode, which draws no
    sidebar; 28 should a layout ever keep one), its strip with `tab` active, and the
    side-by-side panes: (list x, body y, list width, rule x, detail x, detail width,
    body height)."""
    if offset:
        for yy in range(BODY_Y, BODY_Y + BODY_H):
            f.put(offset - 1, yy, "│")
        f.put(1, BODY_Y + 1, "Pinned")
        f.put(1, BODY_Y + 2, "Saved")
        f.put(1, BODY_Y + 3, "All flows")
        f.put(1, BODY_Y + 4, "Scan")
    ix, iy, iw, ih = box(f, offset, BODY_Y, COLS - offset, BODY_H, "Scan")
    strip = "".join(f" {k} {label} " for k, label in
                    ((1, "Profiles"), (2, "Jobs"), (3, "Site map"), (4, "Issues")))
    f.put(ix, iy, strip + "    " + banner)
    body_y, body_h = iy + 1, ih - 1
    left = iw * 45 // 100
    rule_x = ix + left
    for yy in range(body_y, body_y + body_h):
        f.put(rule_x, yy, "│")
    return ix, body_y, left, rule_x, rule_x + 1, iw - left - 1, body_h


ORIGIN = "http://127.0.0.1:8080"


def profiles_header_text():
    """The Profiles list header as `ui/scan/profiles.rs` formats it from PROFILES_HEADER:
    ` {name}   {GAP}{lanes}{GAP}{intensity}{GAP}speed`, the first three `fit` to their
    columns (the name column 14 and the lanes column 9 wide here, `INTENSITY_W` 9) (H71)."""
    name, lanes, intensity, speed = PROFILES_HEADER
    return f" {name:<14}   {GAP_TEXT}{lanes:<9}{GAP_TEXT}{intensity:<9}{GAP_TEXT}{speed}"


def profiles_frame(editor, offset=0, browser="auto", origins=ORIGIN, l4="none", speed="normal",
                   intensity="medium", banner="idle"):
    """Profiles (ui/scan/profiles.rs): the column header (`profiles_header_text`), three
    rows with `standard` under the cursor (their intensity and speed cells the builtins'
    wire tokens, as the fifth live run's screen read them), and on the detail side
    either the no-editor hint over the D7 gate text and the key footer
    (`key_text(&[PROFILES_KEYS])`, H71), or the held editor's header and Fields block
    (its `origins` and `l4` rows as `text_of` writes them, `none` when empty, H49; its
    `crawl` row carrying `browser` as `field_lines` writes it, H42; its `intensity` row
    carrying `intensity`, `speed` and `accuracy` the same way, H62, H70). `banner` is the
    strip's state text (a start toast's text in the H72 rows)."""
    f = Frame()
    chrome(f)
    lx, y, lw, rule_x, dx, dw, bh = scan_box(f, 1, offset, banner=banner)
    f.put(lx, y, profiles_header_text())
    rows = [("standard", "http ws", "medium", "normal"),
            ("map-only", "http", "passive", "normal"),
            ("l4-stream-safe", "l4_stream", "medium", "normal")]
    for k, (name, lanes, inten, row_speed) in enumerate(rows):
        mark = ">" if k == 0 else " "
        editing = "*" if editor and k == 0 else " "
        f.put(lx, y + 1 + k, f"{mark}{name:<14} {editing}·{GAP_TEXT}{lanes:<9}{GAP_TEXT}{inten:<9}{GAP_TEXT}{row_speed:<8}")
    if editor:
        f.put(dx, y, " profile standard (builtin)")
        f.put(dx + dw - 6, y, "dirty")
        f.put(dx, y + 1, f" {'origins':<9} {origins}")
        f.put(dx, y + 2, f" {'l4':<9} {l4}")
        f.put(dx, y + 3, f" {'lanes':<9} [x] http  [x] ws  [ ] l4_packet  [ ] l4_stream")
        f.put(dx, y + 4, f" {'intensity':<9} {intensity}   speed {speed}   accuracy normal")
        f.put(dx, y + 5, f" {'checks':<9} all (12)")
        f.put(dx, y + 6, f" {'crawl':<9} normal · browser {browser} · depth 3 · pages 200 · forms on")
    else:
        f.put(dx, y, " ⏎ opens the profile under the cursor · N new profile")
        f.put(dx, y + bh - 2, " L4 launch disabled: open the profile (⏎) to check its L4 target and scope")
    f.put(dx, y + bh - 1, " " + key_text([PROFILES_KEYS]))
    return f.text()


JOB = "scan-1a2b3c4d"


def jobs_frame():
    """Jobs (ui/scan/jobs.rs): the table stacked over its detail (full width, one
    horizontal rule), the one row under the cursor, the Jobs footer."""
    f = Frame()
    chrome(f)
    lx, y, lw, rule_x, dx, dw, bh = scan_box(f, 2)
    # The Jobs tab stacks: no vertical rule, the table spans the inner width.
    for yy in range(y, y + bh):
        f.put(rule_x, yy, " ")
    target = "http://127.0.0.1:8080"
    f.put(lx, y, f" {'job':<13}{GAP_TEXT}{'profile':<8}{GAP_TEXT}{'targets':<21}{GAP_TEXT}{'state/phase':<13}"
                 f"{GAP_TEXT}{'probes':<13}{GAP_TEXT}{'points':<6}{GAP_TEXT}{'issues':<6}{GAP_TEXT}{'el.':>3}")
    f.put(lx, y + 1, f">{JOB:<13}{GAP_TEXT}{'standard':<8}{GAP_TEXT}{target:<21}{GAP_TEXT}{'running/crawl':<13}"
                     f"{GAP_TEXT}{'12/400':<6} ━━────{GAP_TEXT}{'3/9':<6}{GAP_TEXT}──────{GAP_TEXT}{'12s':>3}")
    f.put(lx, y + 2, "─" * (COLS - 2))
    f.put(lx, y + 3, f" {JOB}")
    f.put(lx, y + 4, " state running · phase crawl")
    f.put(lx, y + 5, f" targets {target}")
    f.put(lx, y + bh - 1, " " + key_text([JOBS_KEYS]))
    return f.text()


ISSUE_NAME = "Reflected XSS in q"
# The row the sixth live run's cursor drifted to after `f` (H76).
DRIFT_NAME = "Cookie without Secure or HttpOnly"


def fit_cell(s, w):
    """`text.rs` `fit`: `s` padded to `w` cells, or cut to `w - 1` chars plus `…`."""
    return s + " " * (w - len(s)) if len(s) <= w else s[:w - 1] + "…"


def issues_frame(name_w=18, drifted=False):
    """Issues (ui/scan/issues.rs): the filter line, the five severity headers with
    the one row under HIGH and the cursor, the Detail pane whose head repeats the
    name on the filter line's row (the G100e trap), its flow list with its own `>`.
    `name_w` is the measured name column (`fit` cuts the name to it, H17). With
    `drifted` the frame is the sixth live run's `fail-1-t7-17.txt` in miniature: the
    marked issue reads `false_positive` and has lost the cursor, which sits on another
    row (`DRIFT_NAME`, under LOW) after a refetched page moved the rows (H75, H76)."""
    f = Frame()
    chrome(f)
    lx, y, lw, rule_x, dx, dw, bh = scan_box(f, 4)
    f.put(lx, y, f" job {JOB} · S none · C none · L none · T none")
    f.put(lx, y + 1, " CRITICAL 0")
    f.put(lx, y + 2, " HIGH 1")
    mark, status = (" ", "false_positive") if drifted else (">", "open")
    f.put(lx, y + 3, f"{mark}●● {fit_cell(ISSUE_NAME, name_w)}{GAP_TEXT}{'GET /search':<11}{GAP_TEXT}{'query:q':<7}{GAP_TEXT}{status}")
    f.put(lx, y + 4, " MEDIUM 0")
    if drifted:
        f.put(lx, y + 5, " LOW 1")
        f.put(lx, y + 6, f">●○ {fit_cell(DRIFT_NAME, name_w)}{GAP_TEXT}{'GET /lang':<11}{GAP_TEXT}{'query:set':<9}{GAP_TEXT}{'open':<4}")
        f.put(lx, y + 7, " INFO 0")
    else:
        f.put(lx, y + 5, " LOW 0")
        f.put(lx, y + 6, " INFO 0")
    f.put(lx, y + bh - 1, " " + key_text([ISSUES_FILTER_KEYS]))
    f.put(dx, y, f" {ISSUE_NAME}   high · certain · open")
    f.put(dx, y + 1, f" {'class':<9} reflected-xss")
    f.put(dx, y + 2, f" {'payload':<9} <svg/onload=alert(1)>")
    f.put(dx, y + 3, f" {'flows':<9}")
    f.put(dx, y + 4, "> 0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b  probe")
    f.put(dx, y + bh - 1, " " + key_text([ISSUES_KEYS]))
    return f.text()


SITEMAP_NODES = [{"method": "GET", "path_template": "/search", "scheme": "http", "host": "127.0.0.1",
                  "port": 8080, "flows": ["f-1"]},
                 {"method": "GET", "path_template": "/", "scheme": "http", "host": "127.0.0.1",
                  "port": 8080, "flows": ["f-2"]},
                 {"method": "POST", "path_template": "/login", "scheme": "http", "host": "127.0.0.1",
                  "port": 8080, "flows": ["f-3"]}]


def sitemap_frame(cursor=0, count=None, nodes=SITEMAP_NODES, banner="idle"):
    """Site map (ui/scan/sitemap.rs): the summary head (`hint`: a pad cell, then
    `summary`'s `N nodes · ..`; `count` overrides N), a host header, the node rows
    (`node_text`: `METHOD path_template  flows n · pts n`) with the cursor on row
    `cursor`, and the Points pane whose cursor row sits one row ABOVE the Nodes cursor
    row, right after the pane rule (the H9 trap); `banner` is the strip's state text
    (H39)."""
    f = Frame()
    chrome(f)
    lx, y, lw, rule_x, dx, dw, bh = scan_box(f, 3, banner=banner)
    f.put(lx, y, f" {len(nodes) if count is None else count} nodes · 2 points of n-1")
    f.put(lx, y + 1, f" {host_label(nodes[0])}")
    for k, n in enumerate(nodes):
        mark = ">" if k == cursor else " "
        f.put(lx, y + 2 + k, f"{mark} {node_needle(n)}  flows {len(n['flows'])} · pts {2 if k != 1 else 0}")
    f.put(dx, y, f" {'kind':<12} {'name':<14} {'path':<24} {'traits':<8} example")
    f.put(dx, y + 1, f"> {'query':<12} {'q':<14} {'/search':<24} {'-':<8} ts12ab34cd")
    f.put(dx, y + 2, f"  {'header':<12} {'user-agent':<14} {'/search':<24} {'-':<8} curl/8.4")
    f.put(dx, y + bh - 1, " " + key_text([SITEMAP_KEYS]))
    return f.text()


FLOW_PATH = "/search?q=ts12ab34cd"


def flows_frame(path=FLOW_PATH):
    """The Flows list with the sidebar and no flow selected (ui/mod.rs `main_region`,
    the body every mode without its own arm falls to): no Scan strip, no inspector."""
    f = Frame()
    chrome(f)
    for yy in range(BODY_Y, BODY_Y + BODY_H):
        f.put(27, yy, "│")
    for k, item in enumerate(("Pinned", "Saved", "All flows", "Scan", "Findings")):
        f.put(1, BODY_Y + 1 + k, item)
    f.put(28, BODY_Y, f" {'#':>3}  {'method':<6}  {'host':<20}  {'path':<40}  status")
    f.put(28, BODY_Y + 1, f" {1:>3}  {'GET':<6}  {'127.0.0.1:8080':<20}  {path:<40}  200")
    return f.text()


def inspector_frame(secret, path=FLOW_PATH):
    """The flow inspector (ui/inspector.rs) under the Flows list with the sidebar
    (main_region): no Scan strip, the summary row with the flow's method and path,
    the Request and Response pane rows, and the captured Cookie header verbatim."""
    f = Frame.from_text(flows_frame(path))
    insp_y = BODY_Y + BODY_H // 2
    f.put(28, insp_y + 1, f" GET http://127.0.0.1:8080{path}  200 OK · 1.2 KB · 12 ms")
    panes_y = insp_y + 2
    mid = 28 + (COLS - 28) // 2
    for yy in range(panes_y, BODY_Y + BODY_H):
        f.put(mid - 1, yy, "│")
    f.put(28, panes_y, " Request  Headers  Query  Cookies  Body")
    f.put(mid, panes_y, " Response  Headers  Set-Cookie  Body  JSON")
    f.put(28, panes_y + 1, " Host: 127.0.0.1:8080")
    f.put(28, panes_y + 2, f" Cookie: sid={secret}")
    f.put(mid, panes_y + 1, " Content-Type: text/html")
    return f.text()


POC_PATH = "/work/findings/pocs/reflected-xss-q.yaml"


CONFIRM_PROMPT = "This scan sends malformed traffic and may disrupt the target. Continue?"
# The prompt the engine sent in the seventh live run (`fail-2-t7-16.txt`): with the origin
# it is 97 cells, over the box's 86 text cells, so the TUI wraps it after `may disrupt the`.
LIVE_CONFIRM_PROMPT = "This scan sends malformed traffic to http://127.0.0.1:50795 and may disrupt the target. Continue?"
# The `poc_ref` the seventh live run's issue carried (`fail-1-t7-17.txt`): the engine's
# PoC under the findings store's `scan/pocs`, longer than the toast's 80 cells.
LIVE_POC_REF = ("/var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-tui-scan-run-0i4i8gks/findings/scan/pocs/"
                "aitm-poc-open-redirect-67108-0-1793557916878198000/open-redirect.poc.yaml")


def wrap_prompt(text, w):
    """`ui/scan/mod.rs` `wrap` for the self-test frames: the text cut after every `,` `.`
    `:` or `;` that whitespace or the end follows (`clauses`), a clause wider than `w`
    split into words, the units packed greedily into rows of at most `w` cells (one
    space between units); `max_rows` is never reached by the prompts painted here."""
    units = []
    for clause in re.split(r"(?<=[,.:;])\s+", text.strip()):
        clause = clause.strip()
        if not clause:
            continue
        units.extend([clause] if len(clause) <= w else clause.split())
    rows, row = [], ""
    for unit in units:
        if not row:
            row = unit[:w]
        elif len(row) + 1 + len(unit) <= w:
            row = f"{row} {unit}"
        else:
            rows.append(row)
            row = unit[:w]
    if row:
        rows.append(row)
    return rows


def truncate_cells(s, w):
    """`text.rs` `truncate` for ASCII: `s` whole when it fits `w` cells, else its first
    `w - 1` chars and `…`."""
    return s if len(s) <= w else s[:w - 1] + "…"


def wire_confirm_over(body_text, prompt=CONFIRM_PROMPT):
    """The wire-confirm overlay (ui/scan/confirm.rs `render`) over `body_text`:
    `centered(screen, 90, 16)` at 200x50 (x 55, y 17), `boxed` (cleared, the title on
    the top border), then the call line, the prompt wrapped to the inner width less two
    (`wrap`, each row drawn after one pad cell, H79), the footnote and the key line.
    `ui/mod.rs` `render` draws it last over the body of the view the launch came from
    (`wire_confirm_from`, H18): the Scan view for a Scan launch, `main_region` for an
    L4 confirm from Flows (H15)."""
    f = Frame.from_text(body_text)
    w, h = min(COLS - 10, 90), min(ROWS - 8, 16)
    x, y = (COLS - w) // 2, (ROWS - h) // 2
    f.blank(x, y, w, h)
    ix, iy, iw, ih = box(f, x, y, w, h, CONFIRM_TITLE)
    lines = ([" scan.start", ""] + [f" {chunk}" for chunk in wrap_prompt(prompt, iw - 2)]
             + ["", " Confirming starts the job now; x in Jobs cancels it at any time.",
                " y confirm (re-issues with _confirm) · n / Esc cancel"])
    for k, line in enumerate(lines[:ih]):
        f.put(ix, iy + k, line[:iw])
    return f.text()


def poc_toast_frame(poc_ref):
    """The Issues frame with the `P` fallback toast on the status row, as `app.rs`
    `scan_open_poc` toasts it (`PoC <ref cut to POC_TOAST_MAX> is not in the Findings
    list`) and the seventh live run's `fail-1-t7-17.txt` showed it after the Issues
    footer's first hints (H78)."""
    f = Frame.from_text(issues_frame())
    f.put(0, ROWS - 1, " " * COLS)
    f.put(0, ROWS - 1, f" c confirm  f false positive   PoC {truncate_cells(poc_ref, POC_TOAST_MAX)} is not in "
                       "the Findings list   6.2 KB (F4)  ● bus 127.0.0.1:50798 · operator")
    return f.text()


def findings_frame():
    """The Findings overlay (ui/overlays.rs `findings`): the list rows put the
    severity before the title, the detail head puts the title before the severity."""
    f = Frame()
    chrome(f)
    ix, iy, iw, ih = box(f, 0, BODY_Y, COLS, BODY_H, FINDINGS_TITLE)
    list_w = iw * 45 // 100
    for yy in range(iy, iy + ih):
        f.put(ix + list_w - 1, yy, "│")
    f.put(ix, iy, f" ·  high  {ISSUE_NAME}")
    f.put(ix, iy + 1, "       · not run · r to run")
    f.put(ix, iy + 2, f" ·  low  Other finding")
    dx = ix + list_w
    f.put(dx, iy, f" {ISSUE_NAME}  high")
    f.put(dx, iy + 1, f" poc     {POC_PATH}")
    return f.text()


# The Findings overlay's box title (`ui/overlays.rs` `findings`; the middle dot is the
# TUI's separator everywhere, H40); the live `P` poll matches its tail (H41).
FINDINGS_TITLE = "Findings · PoCs and runs"

# The Scan prompts' right-hand hints (`ui/bars.rs` `prompt`), by label.
PROMPT_HINTS = {"origin:": "scheme://host[:port] · ⏎ add", "value:": "⏎ set · Esc",
                "profile name:": "a-z 0-9 . _ - lowercase · ⏎ save as",
                "l4 target:": "ip:port[/tcp|udp][ grammar] · ⏎ add"}


def prompt_over(body_text, label, typed):
    """The prompt bar (`ui/bars.rs` `prompt`) over `body_text`: the status row reads
    ` <label> <typed>` then the cursor cell, the hint right-aligned (`put_sides`). After
    H43 the body under it is the view the prompt was opened from, so over the held
    editor the Fields lines stay on screen while the bar is up (H49)."""
    f = Frame.from_text(body_text)
    f.blank(0, ROWS - 1, COLS, 1)
    f.put(0, ROWS - 1, f" {label} {typed} ")
    hint = PROMPT_HINTS[label] + " "
    f.put(COLS - len(hint), ROWS - 1, hint)
    return f.text()


class ScriptedTerm:
    """A `Terminal` stand-in for the key helpers (no pty): `text()` is the held
    `standard` editor's frame with whatever prompt is up painted over it, `press`
    records every key and moves the state the way `app.rs` does. `o` opens the
    `origin:` prompt and `t` the `l4 target:` one; typed keys go into an open prompt;
    Enter closes it and lands the value on its Fields line only after `lag` further
    `text()` reads (the TUI processes Enter after the bar echoed the typed value, the
    live H49 failure) unless `refuse` (`submit_retrying` keeps the bar up with the line
    cleared); Esc closes it and drops the value (H43). The Fields cursor is tracked the
    way `app.rs` moves it: `g` to the first field, each `j` one field down
    (EDITOR_FIELDS); `e` acts on the field under it when `on_field`: the crawl
    `browser` ring on `use_browser`, the `speed` ring on `speed` (H62), the `intensity`
    ring on `intensity` (H70), the `value:` prompt prefilled with the name on any
    other. With `on_field` False the cursor never left `name`, so `e` opens that
    prompt (the live H44 failure)."""

    def __init__(self, on_field=True, refuse=False, lag=2):
        self.keys = []
        self.on_field, self.refuse, self.lag = on_field, refuse, lag
        self.origins, self.l4, self.browser, self.speed = "none", "none", "auto", "normal"
        self.intensity = "medium"  # the builtin `standard`'s, as the live screen reads it
        self.field = 0  # the Fields cursor: an EDITOR_FIELDS index
        self.prompt = None  # (label, typed)
        self._pending = None  # (label, typed, reads left) after Enter

    def _frame(self):
        return profiles_frame(editor=True, browser=self.browser, origins=self.origins, l4=self.l4,
                              speed=self.speed, intensity=self.intensity)

    def text(self):
        if self._pending is not None:
            label, typed, left = self._pending
            if left > 0:
                self._pending = (label, typed, left - 1)
            else:
                self._pending, self.prompt = None, None
                if label == "origin:":
                    self.origins = typed
                elif label == "l4 target:":
                    self.l4 = typed
        if self.prompt is None:
            return self._frame()
        return prompt_over(self._frame(), *self.prompt)

    def wait_for(self, pattern, timeout):
        return poll(lambda: re.search(pattern, self.text()) is not None, timeout, 0.05)

    def press(self, keys):
        self.keys.append(keys)
        if self.prompt is not None:
            label, typed = self.prompt
            if keys == ESC:
                self.prompt = None
            elif keys == ENTER:
                if self.refuse:
                    self.prompt = (label, "")
                else:
                    self._pending = (label, typed, self.lag)
            else:
                self.prompt = (label, typed + keys)
            return
        if keys == "o":
            self.prompt = ("origin:", "")
        elif keys == "t":
            self.prompt = ("l4 target:", "")
        elif keys == "g":
            self.field = 0
        elif keys and set(keys) == {"j"}:
            self.field = min(self.field + len(keys), len(EDITOR_FIELDS) - 1)
        elif keys == "e":
            under = EDITOR_FIELDS[self.field] if self.on_field else "name"
            if under == "use_browser":
                self.browser = BROWSER_RING[(BROWSER_RING.index(self.browser) + 1) % len(BROWSER_RING)]
            elif under == "speed":
                self.speed = SPEED_RING[(SPEED_RING.index(self.speed) + 1) % len(SPEED_RING)]
            elif under == "intensity":
                self.intensity = INTENSITY_RING[(INTENSITY_RING.index(self.intensity) + 1) % len(INTENSITY_RING)]
            else:
                self.prompt = ("value:", "standard")


class ScriptedScreens:
    """A `Terminal` stand-in for `wait_sitemap_head` (H63) and `wait_landed`/`launch`
    (H72): `text()` serves the scripted frames in order, one per read, and repeats the
    last; `press` records the keys and moves nothing (the frames are the script)."""

    def __init__(self, frames):
        self.frames = list(frames)
        self.reads = 0
        self.keys = []

    def text(self):
        self.reads += 1
        return self.frames[min(self.reads, len(self.frames)) - 1]

    def press(self, keys):
        self.keys.append(keys)


class ScriptedListBus:
    """A bus stand-in for `launch` (H72): `scan.list` answers no job on its first read
    (the `before` set) and `job` on every later one, so the launch sees the new id at
    once and the landing wait alone decides when `launch` returns. With `armed` (a
    callable) the job is listed only while it answers True: the engine that starts
    nothing until the confirm overlay's `y` re-issued the launch (H77)."""

    def __init__(self, job, armed=None):
        self.job = job
        self.armed = armed
        self.calls = 0

    def call(self, name, _args=None):
        assert name == "scan.list", name
        self.calls += 1
        if self.calls == 1 or (self.armed is not None and not self.armed()):
            return {"jobs": []}
        return {"jobs": [{"job": self.job}]}


class ScriptedSocket:
    """The `_sock` the harness's `BusClient` holds, as far as `Pushes.stop()` touches it:
    `shutdown` wakes the blocked read (on the real socket the readline returns "" and
    `_read_line` raises `BusError`, H64)."""

    def __init__(self):
        self.closed = threading.Event()
        self.shutdowns = 0

    def shutdown(self, how):
        self.shutdowns += 1
        self.closed.set()


class ScriptedPushClient:
    """A bus client stand-in for `Pushes` with the harness's `wait_notification` shape
    (`aitm_e2e/bus.py`), the read T1b's `collect_push` relies on (H57): each call reads
    the scripted lines one by one, stashes every line that is not a `method_contains`
    notification on `notifications` (a reply, a flow or agent line) and returns the
    first that is; a scripted exception is raised in its turn (a `ValueError` is one
    line `_recv` could not parse, a `BusError` the socket closed by the core; a parsed
    line that is not an object fails `m.get`, as it would there), except an `OSError`,
    which `wait_notification` swallows into a None the way the harness does, and from
    which its reader is broken: every later read is an instant None (the fourth live
    run's `cannot read from timed out object`, H64). The script exhausted, the read
    BLOCKS like a quiet socket: until `_sock.shutdown` (a `BusError`, the socket closed
    under the read) or the timeout (a None, and the reader broken from then on, as the
    harness's buffered reader is after one timeout). It has no `drain_notifications`: a
    thread that still called it would die at once."""

    def __init__(self, script):
        self.script = list(script)
        self.pending = []
        self.notifications = []
        self.reads = 0
        self.broken = False
        self._sock = ScriptedSocket()

    def wait_notification(self, method_contains, timeout=6.0):
        self.reads += 1
        if self.broken:
            return None
        while True:
            if not self.pending:
                if self._sock.closed.is_set():
                    raise BusError("bus connection closed by the core")
                if not self.script:
                    if self._sock.closed.wait(timeout):
                        raise BusError("bus connection closed by the core")
                    self.broken = True
                    return None
                item = self.script.pop(0)
                if isinstance(item, OSError):
                    self.broken = True
                    return None
                if isinstance(item, BaseException):
                    raise item
                self.pending.extend(item)
                continue
            m = self.pending.pop(0)
            # The harness's own test, verbatim (bus.py `wait_notification`).
            if m.get("id") is None and method_contains in (m.get("method") or ""):
                return m
            self.notifications.append(m)


def selftest():
    """H9: the screen readers against frames painted with the TUI's real geometry, with
    no core and no pty. One line per assertion; exit 0 when every one holds."""
    c = Checks()
    headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    plain, held = profiles_frame(editor=False), profiles_frame(editor=True)
    shifted = profiles_frame(editor=False, offset=28)

    def row_of(text, needle):
        return line_with(text, needle) or ""

    c.check("selftest: a line-anchored `>` reader finds nothing on the boxed frame (the H9 regression)",
            re.search(r"(?:^|\n)>", plain) is None, row_of(plain, "standard"))
    c.check("selftest: Profiles: cursor_row reads the `standard` row through the box border",
            (cursor_row(plain) or "").startswith("standard"), repr(cursor_row(plain)))
    c.check("selftest: Profiles: on_cursor sees `standard` and not `map-only`",
            on_cursor(plain, "standard") and not on_cursor(plain, "map-only"), row_of(plain, "standard"))
    c.check("selftest: Profiles: the no-editor hint and the D7 gate text are not an editor header (H4)",
            EDITOR_HEAD_RE.search(plain) is None,
            repr(EDITOR_HEAD_RE.search(plain) and EDITOR_HEAD_RE.search(plain).group(0)))
    m = EDITOR_HEAD_RE.search(held)
    c.check("selftest: Profiles: the held editor's header names `standard`",
            m is not None and m.group(1) == "standard", repr(m and m.group(0)))
    c.check("selftest: Profiles: the tab marker is the Profiles header and no other tab's",
            re.search(TAB_MARKERS["1"], plain) is not None
            and all(re.search(TAB_MARKERS[k], plain) is None for k in ("2", "4")), row_of(plain, "lanes"))
    c.check("selftest: Profiles: the Scan view is not the inspector",
            not inspector_open(plain, "GET", "/search") and surface_of(plain) == "scan", surface_of(plain))
    c.check("selftest: Profiles behind a 28-column sidebar: the same cursor row (box-relative, H9)",
            box_left(shifted) == 28 and cursor_row(shifted) == cursor_row(plain) and on_cursor(shifted, "standard"),
            repr(cursor_row(shifted)))

    jobs = jobs_frame()
    c.check("selftest: Jobs: the cursor row is the job and its cells read back",
            (cursor_row(jobs) or "").startswith(JOB) and row_probes(jobs, JOB) == (12, 400)
            and row_state(jobs, JOB) == "running/crawl", repr(cursor_row(jobs)))
    c.check("selftest: Jobs: the Jobs footer is the tab's marker (H5)",
            re.search(TAB_MARKERS["2"], jobs) is not None and re.search(TAB_MARKERS["1"], jobs) is None,
            row_of(jobs, "cancel"))

    issues = issues_frame()
    needle = ISSUE_NAME[:ISSUE_NAME_MIN]
    c.check("selftest: Issues: the issue sits under HIGH although the detail head repeats its "
            "name on the filter row (G100e)", group_of(issues, needle, headers) == "HIGH",
            repr(group_of(issues, needle, headers)))
    c.check("selftest: Issues: the detail head's row carries the needle first when rows are read whole",
            line_with(issues, needle) == line_with(issues, "job " + JOB), repr(line_with(issues, needle)))
    c.check("selftest: Issues: the cursor row's name cell is the issue's first COLUMN_MIN chars (H6)",
            on_cursor(issues, needle) and issue_row_name(cursor_row(issues)) == needle,
            repr(cursor_row(issues)))
    c.check("selftest: Issues: the detail's flow list `>` is never the list cursor",
            not (cursor_row(issues) or "").startswith(" 0192"), repr(cursor_row(issues)))
    # Cell item from the sixth live smoke run: H76. After `f` the running job's refetch
    # moved the rows and the cursor kept its index (`fail-1-t7-17.txt`): `cursor_holds`
    # watches the cursor row's name cell for the whole hold and answers False the moment
    # it reads another issue, naming that row; the still frame holds for the whole window.
    drifted = issues_frame(drifted=True)
    drift_screens = ScriptedScreens([issues, issues, drifted])
    held_screens = ScriptedScreens([issues])
    drift_ok, drift_row = cursor_holds(drift_screens, needle, 1.0)
    hold_ok, hold_row = cursor_holds(held_screens, needle, 0.5)
    c.check("selftest: Issues: cursor_holds reads False as soon as the cursor row's name cell is "
            "another issue's (the third frame, the row named in the answer) and True when the "
            "cell reads the issue for the whole hold (H76)",
            drift_ok is False and drift_row == DRIFT_NAME[:ISSUE_NAME_MIN] and drift_screens.reads == 3
            and hold_ok is True and hold_row == needle and held_screens.reads >= 2
            and "false_positive" in drifted and not on_cursor(drifted, needle),
            f"drift {drift_ok} {drift_row!r} after {drift_screens.reads} reads; hold {hold_ok} {hold_row!r} "
            f"after {held_screens.reads} reads; drifted cursor {cursor_row(drifted)!r}")
    c.check("selftest: Issues: the tab marker is the Issues footer and the J pin is on the filter line",
            re.search(TAB_MARKERS["4"], issues) is not None and f"job {JOB}" in issues, row_of(issues, "job "))

    sitemap = sitemap_frame()
    under = (cursor_row(sitemap) or "").strip()
    node = node_at_cursor(under, SITEMAP_NODES)
    c.check("selftest: Site map: the Nodes cursor row is read, not the Points pane's `>` one row above (H9)",
            node is SITEMAP_NODES[0] and not under.startswith("query"), repr(cursor_row(sitemap)))
    c.check("selftest: Site map: the job's node count is the tab's marker (H11)",
            SITEMAP_MARKER.format(n=len(SITEMAP_NODES)) in sitemap and SITEMAP_MARKER.format(n=4) not in sitemap,
            row_of(sitemap, "nodes"))

    secret = "f00dbabe0123456789abcdef00000000"
    insp = inspector_frame(secret)
    c.check("selftest: inspector: Request/Response panes, the flow's method and path, no Scan strip",
            inspector_open(insp, "GET", FLOW_PATH) and not inspector_open(insp, "POST", FLOW_PATH)
            and not inspector_open(plain, "GET", FLOW_PATH), row_of(insp, "GET http"))
    ev = Evidence([secret])
    ev.sample("selftest-insp", insp, surface_of(insp))
    ev.sample("selftest-scan", issues, surface_of(issues))
    c.check("selftest: surfaces are read from the text: inspector, scan, other (H3)",
            surface_of(insp) == "inspector" and surface_of(issues) == "scan"
            and surface_of(findings_frame()) == "other",
            f"{surface_of(insp)} {surface_of(issues)} {surface_of(findings_frame())}")
    c.check("selftest: the T7-20 grep covers the scan samples only; the inspector sample carries the secret",
            ev.leaks("scan") == [] and [i for i, _, _ in ev.leaks("inspector")] == [0], repr(ev.leaks("inspector")))

    findings = findings_frame()
    c.check("selftest: Findings: the detail head's title is read, never the list row's severity-first text (H10)",
            findings_head_title(findings) == ISSUE_NAME, repr(findings_head_title(findings)))
    poc = re.search(r"\bpoc\s+(\S+)", findings)
    c.check("selftest: Findings: the detail's `poc` line names the PoC file",
            poc is not None and poc.group(1) == POC_PATH, repr(poc and poc.group(1)))

    # Cell item from the seventh live smoke run: H78. `P` on an issue whose `poc_ref` the
    # Findings panel does not list toasts `PoC <ref> is not in the Findings list` with the
    # ref cut to POC_TOAST_MAX cells (`fail-1-t7-17.txt`); the toast's ref is read off the
    # status row and compared with the issue's `poc_ref` as a whole or as its cut prefix
    # (all the cut toast gives: a ref of another run's store differs inside it, one of a
    # sibling PoC in the same store only beyond it).
    issues_only = issues_frame()
    shown_long = poc_toast_ref(poc_toast_frame(LIVE_POC_REF))
    shown_short = poc_toast_ref(poc_toast_frame(POC_PATH))
    c.check("selftest: `P` fallback toast: the ref is read off the status row (cut to 80 cells and `…` "
            "as `truncate` does) and names the issue's `poc_ref` by prefix, not another store's; no "
            "toast, no ref (H78)",
            shown_long is not None and shown_long.endswith("…") and len(shown_long) == POC_TOAST_MAX
            and ref_shown_is(shown_long, LIVE_POC_REF)
            and not ref_shown_is(shown_long, LIVE_POC_REF.replace("run-0i4i8gks", "run-9z9z9z9z"))
            and shown_short == POC_PATH and ref_shown_is(shown_short, POC_PATH)
            and not ref_shown_is(shown_short, POC_PATH + ".bak") and poc_toast_ref(issues_only) is None
            and not ref_shown_is(None, POC_PATH) and not ref_shown_is(shown_short, ""),
            f"long {shown_long!r} short {shown_short!r}")
    boot_cfg = self_boot_config("/work/run", "127.0.0.1:8080", (18080, 18081, 19001))
    c.check("selftest: the self-booted core's CoreConfig points `poc_dir` at the engine's PoC store "
            "under the findings dir (`<work>/findings/scan/pocs`), with the findings dir, the L4 "
            "lane and the scope entries as before (H78)",
            boot_cfg.poc_dir == "/work/run/findings/scan/pocs"
            and boot_cfg.findings_dir == "/work/run/findings" and boot_cfg.l4_enabled is True
            and boot_cfg.scope_entries == ["127.0.0.1:8080", "127.0.0.1"]
            and (boot_cfg.proxy_port, boot_cfg.browser_proxy_port, boot_cfg.bus_port) == (18080, 18081, 19001)
            and 'dir: "/work/run/findings/scan/pocs"' in boot_cfg.to_yaml(),
            f"poc_dir {boot_cfg.poc_dir!r} findings_dir {boot_cfg.findings_dir!r}")

    # Cell item H81, the "sampling races a fast job" class: the eighth live run's target
    # answered a thorough intrusive scan in about two seconds, so every "while running"
    # observation raced the job. The lever is T10's `aitm-testtarget-serve --latency-ms N`
    # behind `aitm_e2e.scan.ScanTarget(mode, latency_ms=)`; the cell boots with it when
    # the harness offers it and falls back to `Target("vulnerable")` with a note when not.
    # The latency is TARGET_LATENCY_MS (300 ms since H82: 40 ms still finished the job
    # inside one status sample); every literal below spells the constant, never a number.
    class SlowStandIn:
        """`aitm_e2e.scan.ScanTarget` as T10 ships it: its own argv assembly (`--port 0`,
        the TLS pair and the control port on request, `--latency-ms N` when asked)."""

        booted = []

        def __init__(self, mode="vulnerable", *, tls=True, control=True, l4=False,
                     start_timeout=15.0, latency_ms=None):
            argv = ["aitm-testtarget-serve", "--mode", mode, "--port", "0"]
            if tls:
                argv += ["--tls-port", "0", "--tls-h1-port", "0"]
            if control:
                argv += ["--control-port", "0"]
            if l4:
                argv.append("--l4")
            if latency_ms:
                argv += ["--latency-ms", str(int(latency_ms))]
            self.argv, self.base = argv, "http://127.0.0.1:50795"
            SlowStandIn.booted.append(self)

        @property
        def authority(self):
            return "127.0.0.1:50795"

    class OldStandIn:
        """A `ScanTarget` from before the flag: no `latency_ms` keyword."""

        def __init__(self, mode="vulnerable", *, tls=True, control=True):
            self.mode = mode

    class FastStandIn:
        """`aitm_e2e.target.Target`: `(mode, start_timeout)`, `base_url`, `base`, `authority`."""

        booted = []

        def __init__(self, mode="vulnerable", start_timeout=15.0):
            self.mode, self.base_url = mode, "http://127.0.0.1:50796/"
            FastStandIn.booted.append(self)

        @property
        def base(self):
            return self.base_url

        @property
        def authority(self):
            return "127.0.0.1:50796"

    picked, why = slow_target_class(types.SimpleNamespace(ScanTarget=SlowStandIn))
    old, why_old = slow_target_class(types.SimpleNamespace(ScanTarget=OldStandIn))
    none, why_none = slow_target_class(types.SimpleNamespace())
    c.check("selftest: H81: the harness's ScanTarget is the booter only when it takes `latency_ms`; "
            "one without the keyword, or a harness without the class, names why it is not",
            picked is SlowStandIn and why == "" and old is None and "latency_ms" in why_old
            and none is None and "ScanTarget" in why_none,
            f"picked {picked!r} {why!r}; old {old!r} {why_old!r}; none {none!r} {why_none!r}")
    slow, slow_ms = boot_seeded_target(SlowStandIn, fallback=FastStandIn)
    c.check("selftest: H81: with the lever the target boots `vulnerable` over plain HTTP, no TLS or "
            f"control listener, with `--latency-ms {TARGET_LATENCY_MS}`, and the cell reads the same "
            "`base` and `authority` it reads from Target",
            slow_ms == TARGET_LATENCY_MS and isinstance(slow, SlowStandIn)
            and slow.argv == ["aitm-testtarget-serve", "--mode", "vulnerable", "--port", "0",
                              "--latency-ms", str(TARGET_LATENCY_MS)]
            and slow.base.rstrip("/") == "http://127.0.0.1:50795" and slow.authority == "127.0.0.1:50795"
            and FastStandIn.booted == [],
            f"latency {slow_ms!r}; argv {getattr(slow, 'argv', None)!r}")
    fast, fast_ms = boot_seeded_target(None, fallback=FastStandIn)
    c.check("selftest: H81: without the lever (today's main) the fallback `Target(\"vulnerable\")` "
            "boots at full speed, and the cell reads `base` and `authority` from it as before",
            fast_ms == 0 and isinstance(fast, FastStandIn) and fast.mode == "vulnerable"
            and fast.base.rstrip("/") == "http://127.0.0.1:50796" and fast.authority == "127.0.0.1:50796"
            and len(SlowStandIn.booted) == 1,
            f"latency {fast_ms!r}; {fast!r}")
    rec = Checks(out=io.StringIO())
    record_target_latency(rec, TARGET_LATENCY_MS, "")
    record_target_latency(rec, 0, "aitm_e2e.scan has no ScanTarget")
    record_target_latency(rec, None, "")
    c.check(f"selftest: H81: the record is the `ok` line `target boots with {TARGET_LATENCY_MS} ms per "
            "response (H81)` with the lever, a `note` that the timing checks may race a fast job "
            "without it, nothing for a runner core; the summary head names the latency in each case",
            rec.results == [(f"target boots with {TARGET_LATENCY_MS} ms per response (H81)", "ok"),
                            (TARGET_FAST_NOTE, "note")]
            and "may race a fast job" in TARGET_FAST_NOTE and "(H81)" in TARGET_FAST_NOTE
            and latency_words(TARGET_LATENCY_MS) == f"target latency {TARGET_LATENCY_MS} ms"
            and latency_words(0) == "target latency none (full speed)"
            and latency_words(None) == "target latency unknown (runner core)",
            f"results {rec.results!r}; words {latency_words(TARGET_LATENCY_MS)!r} {latency_words(0)!r} "
            f"{latency_words(None)!r}")

    # Cell item H82: the tenth live run's target, at 40 ms per response, still finished
    # its intrusive job inside one 0.5 s status sample (`status-pairs.json`: 228 to 278
    # probes inside the window; the engine probes about four at a time, about 100
    # probes/s). The latency is 300 ms (about 13 probes/s, an intrusive job of about 20 s),
    # and every literal that spells it (the argv, the `ok` record, the summary head) is
    # derived from TARGET_LATENCY_MS, so the self-test cannot drift from the constant.
    c.check("selftest: H82: TARGET_LATENCY_MS is 300 and the booted argv, the `ok` record and the "
            "summary head all spell that one constant",
            TARGET_LATENCY_MS == 300
            and slow.argv[-2:] == ["--latency-ms", str(TARGET_LATENCY_MS)]
            and rec.results[0] == (f"target boots with {TARGET_LATENCY_MS} ms per response (H81)", "ok")
            and latency_words(TARGET_LATENCY_MS) == f"target latency {TARGET_LATENCY_MS} ms",
            f"TARGET_LATENCY_MS {TARGET_LATENCY_MS!r}; argv {slow.argv!r}; record {rec.results[:1]!r}")

    # Cell item from the seventh live smoke run: H79. The engine's prompt names the origin
    # (`.. traffic to http://127.0.0.1:50795 and may disrupt the target. Continue?`), longer
    # than the box's 86 text cells, so `ui/scan/confirm.rs` wraps it: `.. and may disrupt
    # the` on one row, `target. Continue?` on the next (`fail-2-t7-16.txt` line 21), and a
    # substring search over the raw screen misses `may disrupt the target`. `confirm_text`
    # joins the box's inner rows with single spaces; `confirm_says` is what `launch` and
    # T7-18 poll.
    wrapped = wire_confirm_over(held, LIVE_CONFIRM_PROMPT)
    disrupt_row = line_with(wrapped, "may disrupt the") or ""
    joined = confirm_text(wrapped) or ""
    c.check("selftest: wire confirm: the live prompt wraps in the box after `may disrupt the` (the "
            "run 7 screen) so the raw text lacks `may disrupt the target`; the joined inner rows "
            "carry it, the call line and the key line, and nothing of the body beside the box (H79)",
            "may disrupt the target" not in wrapped and "target" not in disrupt_row
            and line_with(wrapped, "target. Continue?") is not None
            and confirm_says(wrapped, "may disrupt the target")
            and joined.startswith("scan.start This scan sends malformed traffic to http://127.0.0.1:50795")
            and "n / Esc cancel" in joined and "s start" not in joined and "profile standard" not in joined
            and confirm_says(wire_confirm_over(held), "may disrupt the target")
            and confirm_text(held) is None and not confirm_says(held, "may disrupt the target")
            and not confirm_says(wrapped, "may unsettle the target"),
            f"row {disrupt_row.strip()!r}; joined {joined[:200]!r}")

    # Fix round H re-review residuals, H12 to H17.
    thirteen = sitemap_frame(count=13)
    c.check("selftest: Site map: the `3 nodes` marker does not match a `13 nodes` head (the "
            "job-less answer's count, H12)",
            SITEMAP_MARKER.format(n=len(SITEMAP_NODES)) not in thirteen
            and SITEMAP_MARKER.format(n=13) in thirteen, row_of(thirteen, "nodes"))
    root_first = [SITEMAP_NODES[1], SITEMAP_NODES[0], SITEMAP_NODES[2]]
    on_search = (cursor_row(sitemap_frame(cursor=1, nodes=root_first)) or "").strip()
    on_root = (cursor_row(sitemap_frame(cursor=0, nodes=root_first)) or "").strip()
    c.check("selftest: Site map: the node under the cursor is matched whole: the root `GET  /` "
            "listed first does not claim the `GET  /search` row, and claims its own (H13)",
            node_at_cursor(on_search, root_first) is SITEMAP_NODES[0]
            and node_at_cursor(on_root, root_first) is SITEMAP_NODES[1],
            f"{on_search!r} -> {(node_at_cursor(on_search, root_first) or {}).get('path_template')!r}")
    insp_root = inspector_frame(secret, path="/")
    c.check("selftest: inspector: the path is matched whole: `/` is not open on the /search "
            "inspector and is open on the root one (H13)",
            not inspector_open(insp, "GET", "/") and inspector_open(insp_root, "GET", "/"),
            f"on /search {inspector_open(insp, 'GET', '/')}; on / {inspector_open(insp_root, 'GET', '/')}")

    over_insp, over_flows, over_scan = (wire_confirm_over(t) for t in (insp, flows_frame(), plain))
    c.check("selftest: wire confirm: the overlay carries the title and the prompt the live "
            "T7-18 polls for, whatever body it is drawn over",
            all(CONFIRM_TITLE in t and "may disrupt the target" in t
                for t in (over_insp, over_flows, over_scan)), row_of(over_insp, "disrupt"))
    c.check("selftest: wire confirm over main_region (an L4 confirm from Flows, H18): the sample "
            "tags the body under the box, `inspector` or `other` and never `scan`, and the "
            "inspector's secret prefix shows beside the box (H15)",
            surface_of(over_insp) == "inspector" and surface_of(over_flows) == "other"
            and secret[:SECRET_PREFIX] in over_insp,
            f"{surface_of(over_insp)} {surface_of(over_flows)}")
    c.check("selftest: wire confirm over the Scan view (a Scan launch's body since H18): the "
            "sample tags `scan` and the T7-20 grep covers it (H15)",
            surface_of(over_scan) == "scan", surface_of(over_scan))

    class DownBus:
        """A bus whose reads time out (`socket.timeout` is an OSError)."""

        def call(self, *_args, **_kwargs):
            raise TimeoutError("timed out")

    try:
        quiet = l4_entries(DownBus()) == [] and l4_entry_by_id(DownBus(), "x") is None
        why = ""
    except OSError as e:
        quiet, why = False, f"{type(e).__name__}: {e}"
    c.check("selftest: L4: a scope read whose socket times out (OSError) reads as no entries, "
            "never a crash (H16)", quiet, why)

    narrow = issues_frame(name_w=ISSUE_NAME_MIN)
    cell = issue_row_name(cursor_row(narrow))
    c.check("selftest: Issues at COLUMN_MIN: the name cell is 7 chars and `…` and still reads "
            "as the issue's needle; a different name does not (H17)",
            cell == ISSUE_NAME[:ISSUE_NAME_MIN - 1] + "…" and name_cell_matches(cell, needle)
            and not name_cell_matches(cell, "Reflecxx") and name_cell_matches(needle, needle),
            repr(cell))
    # Cell items from the first live smoke run, H37 to H39, and H42.
    fail_dir = tempfile.mkdtemp(prefix="aitm-tui-scan-selftest-")
    try:
        fail_ev = Evidence([secret], directory=fail_dir)
        captured = io.StringIO()
        inner = Checks(fail_ev.redact, screen=lambda: f"│ Cookie: sid={secret}", write=fail_ev.write,
                       out=captured)
        inner.check("T7-16: a check that fails", False, "the detail")
        inner.check("T7-16: a check that passes", True)
        written = inner.files[0] if inner.files else ""
        body = open(written, encoding="utf-8").read() if written and os.path.isfile(written) else ""
        c.check("selftest: a failing check writes the full redacted screen to `fail-<n>-<step>.txt`, "
                "names the file in its line, and a passing one writes nothing (H38)",
                len(inner.files) == 1 and os.path.basename(written) == "fail-1-t7-16.txt"
                and REDACTED in body and secret not in body and secret[:SECRET_PREFIX] not in body
                and written in captured.getvalue() and secret not in captured.getvalue(),
                f"files {inner.files}; printed {captured.getvalue()[:160]!r}")
    finally:
        shutil.rmtree(fail_dir, ignore_errors=True)

    never, auto = profiles_frame(editor=True, browser="never"), profiles_frame(editor=True)
    c.check("selftest: Profiles: the crawl Fields line reads `browser never` on the never frame "
            "and `browser auto` on the builtin one, never both (H42)",
            browser_value(never) == "never" and browser_value(auto) == "auto"
            and "browser never" not in auto and browser_value(plain) is None,
            f"{browser_value(never)!r} {browser_value(auto)!r} {browser_value(plain)!r}")

    erred = sitemap_frame(banner="scan.sitemap: reply did not match the contract (missing field `nodes`)")
    noticed = sitemap_frame(banner="already done")
    c.check("selftest: Site map: the strip banner is read off the strip row; `idle` and the "
            "`already <state>` notice are quiet, an error wording is not (H39)",
            banner_of(sitemap) == "idle" and not banner_is_error(banner_of(sitemap))
            and banner_of(noticed) == "already done" and not banner_is_error(banner_of(noticed))
            and banner_is_error(banner_of(erred)) and banner_of(erred).startswith("scan.sitemap: ")
            and banner_of(insp) is None,
            f"{banner_of(sitemap)!r} {banner_of(noticed)!r} {banner_of(erred)!r}")

    # Cell item from the third live smoke run: H54. The T7-18 L4 launch's refusal wording
    # sat on the strip when `3` was pressed; the old wait took it for the Site map's own
    # error and returned before the TUI had drawn anything.
    stale = REFUSAL_WORDINGS["lane_unavailable"] + "; pick other lanes or a build that has them"
    marker3 = SITEMAP_MARKER.format(n=len(SITEMAP_NODES))
    pending = sitemap_frame(count=0, banner=stale)
    # No head drawn yet (count 0) and the Site map's own failure on the strip.
    failed = sitemap_frame(count=0, banner="scan.sitemap: reply did not match the contract (missing field `nodes`)")
    c.check("selftest: Site map settle: the banner snapshotted before `3`/`J` still on the strip "
            "does not settle the wait, nor does a quiet banner; a banner that CHANGED to an "
            "error wording settles it as `error`; the job's `{n} nodes` head settles it as "
            "`head` whatever the banner (H54)",
            sitemap_settled(pending, marker3, stale) is None
            and sitemap_settled(sitemap_frame(count=0, banner="idle"), marker3, stale) is None
            and sitemap_settled(sitemap_frame(count=0, banner="refreshing scan.sitemap..."), marker3, "idle") is None
            and sitemap_settled(failed, marker3, stale) == "error"
            and sitemap_settled(failed, marker3, None) == "error"
            and sitemap_settled(failed, marker3, banner_of(failed)) is None
            and sitemap_settled(sitemap, marker3, stale) == "head"
            and sitemap_settled(sitemap_frame(banner=stale), marker3, stale) == "head"
            and sitemap_settled(erred, marker3, stale) == "head"
            and sitemap_settled(sitemap_frame(count=13), marker3, "idle") is None,
            f"{sitemap_settled(pending, marker3, stale)!r} {sitemap_settled(failed, marker3, stale)!r} "
            f"{sitemap_settled(failed, marker3, banner_of(failed))!r} {sitemap_settled(sitemap, marker3, stale)!r}")
    # Cell item from the fourth live smoke run: H63. The engine's refusal of the
    # tab-entry `scan.sitemap {}` request changed the banner a moment before `J`'s head
    # landed, so a wait that settled on the changed banner lost the race.
    raced = ScriptedScreens([pending, failed, failed, failed, sitemap])
    late = ScriptedScreens([pending, failed])
    raced_head = wait_sitemap_head(raced, marker3, 3.0)
    late_head = wait_sitemap_head(late, marker3, 0.5)
    c.check("selftest: wait_sitemap_head is head-first: a banner that changed to an error wording "
            "before the `{n} nodes` head does not end the wait, the head three reads later does; "
            "a head that never comes runs the whole timeout and the detail then reads the "
            "changed banner as `error` (H63)",
            raced_head is True and raced.reads == 5 and late_head is False and late.reads >= 3
            and sitemap_settled(late.text(), marker3, stale) == "error",
            f"raced {raced_head} after {raced.reads} reads; late {late_head} after {late.reads} reads")

    # Cell item H59: the inject L4 scope entry carries `inject_rate_pps` (the engine's
    # default 0 is the fail-closed value) when the schema declares it, and the exact
    # match of a lost reply compares it as an integer when the entry echoes it.
    five = {"cidr", "ports", "interface", "direction", "capability"}
    with_rate, unknown_with = l4_args_for(five | {"inject_rate_pps", "inject_rate_burst"}, "127.0.0.1/32", "8080")
    without, unknown_without = l4_args_for(five, "127.0.0.1/32", "8080")
    unread, unknown_unread = l4_args_for(None, "127.0.0.1/32", "8080")
    c.check("selftest: L4: `l4_add_args` carries `inject_rate_pps: 10` when `tools/list` declares "
            "it for l4.scope.add and omits it otherwise (an unreadable schema too); the five "
            "tuple fields are sent as before (H59)",
            with_rate == {"interface": "*", "direction": "outbound", "capability": "inject",
                          "cidr": "127.0.0.1/32", "ports": "8080", "inject_rate_pps": L4_INJECT_RATE_PPS}
            and L4_INJECT_RATE_PPS == 10 and unknown_with == []
            and without == {"interface": "*", "direction": "outbound", "capability": "inject",
                            "cidr": "127.0.0.1/32", "ports": "8080"} and unknown_without == []
            and unread == without and unknown_unread == []
            and l4_args_for({"cidr", "ports", "inject_rate_pps"}, "10.0.0.0/8", "1-2")
            == ({"cidr": "10.0.0.0/8", "ports": "1-2", "inject_rate_pps": 10}, ["capability", "direction", "interface"]),
            f"{with_rate} {without} {unread}")

    class ScopeBus:
        """A bus whose l4.scope.list answers the given entries."""

        def __init__(self, entries):
            self.entries = entries

        def call(self, name, _args=None):
            assert name == "l4.scope.list", name
            return {"entries": self.entries}

    def entry(entry_id, **extra):
        e = {"id": entry_id, "cidr": "127.0.0.1/32", "ports": "8080-8080", "interface": "*",
             "direction": "outbound", "capability": "inject", "source": "runtime"}
        e.update(extra)
        return e

    echo_ok = ScopeBus([entry("e-zero", inject_rate={"pps": 0, "burst": 0}),
                        entry("e-ten", inject_rate={"pps": 10, "burst": 10})])
    echo_flat = ScopeBus([entry("e-flat", inject_rate_pps=10)])
    echo_none = ScopeBus([entry("e-plain")])
    c.check("selftest: L4: `l4_entry_matching` includes the echoed rate in the tuple, compared as "
            "an integer (`inject_rate.pps` or a flat `inject_rate_pps`): the entry echoing 10 "
            "matches, the one echoing 0 does not; an entry that echoes no rate matches on the "
            "five; without the field sent the rate is not compared (H59)",
            l4_entry_matching(echo_ok, with_rate) == "e-ten"
            and l4_entry_matching(echo_flat, with_rate) == "e-flat"
            and l4_entry_matching(echo_none, with_rate) == "e-plain"
            and l4_entry_matching(ScopeBus([entry("e-zero", inject_rate={"pps": 0, "burst": 0})]), with_rate) is None
            and l4_entry_matching(echo_ok, without) == "e-zero"
            and l4_entry_matching(ScopeBus([entry("e-cfg", source="config", inject_rate={"pps": 10})]), with_rate) is None,
            f"{l4_entry_matching(echo_ok, with_rate)!r} {l4_entry_matching(echo_flat, with_rate)!r} "
            f"{l4_entry_matching(echo_none, with_rate)!r} {l4_entry_matching(echo_ok, without)!r}")

    # Cell items from the second live smoke run: H41, H44, H46, H49.
    c.check("selftest: Findings: the box title is `Findings · PoCs and runs` (H40) and the live "
            "`P` poll's `PoCs and runs` still matches it (H41)",
            FINDINGS_TITLE in findings and "PoCs and runs" in findings and "\u2014" not in findings
            and surface_of(findings) == "other", row_of(findings, "PoCs"))

    origin_up = prompt_over(held, "origin:", ORIGIN)
    value_up = prompt_over(held, "value:", "standard")
    empty_up = prompt_over(held, "l4 target:", "")
    c.check("selftest: prompt bar: the Scan prompt's label is read off the status row while it is "
            "up (`origin:` with a value, `value:`, an empty `l4 target:`), None once it closed, "
            "and the view under it stays `scan` (H43, H49, H44)",
            prompt_open(origin_up) == "origin:" and prompt_open(value_up) == "value:"
            and prompt_open(empty_up) == "l4 target:" and prompt_open(held) is None
            and prompt_open(plain) is None and surface_of(origin_up) == "scan",
            f"{prompt_open(origin_up)!r} {prompt_open(value_up)!r} {prompt_open(empty_up)!r} "
            f"{prompt_open(held)!r}")
    pending = prompt_over(profiles_frame(editor=True, origins="none"), "origin:", ORIGIN)
    with_l4 = profiles_frame(editor=True, l4="127.0.0.1:8080/tcp")
    on_origins = lambda t: ORIGIN in (field_line(t, "origins") or "")  # noqa: E731
    c.check("selftest: Fields: the `origins` and `l4` lines are read by label (`none` when empty); "
            "a frame with the origin on the prompt bar and the bar still up is NOT closed although "
            "the origin is on screen (the H49 regression), nor is one with the origin on the "
            "`origins` line under a bar still up; the held frame is",
            field_line(held, "origins") == ORIGIN and field_line(held, "l4") == "none"
            and field_line(with_l4, "l4") == "127.0.0.1:8080/tcp" and field_line(plain, "origins") is None
            and ORIGIN in pending and not prompt_settled(pending, on_origins)
            and on_origins(origin_up) and not prompt_settled(origin_up, on_origins)
            and prompt_settled(held, on_origins),
            f"origins {field_line(held, 'origins')!r} l4 {field_line(held, 'l4')!r} "
            f"pending {field_line(pending, 'origins')!r} bar up {prompt_open(origin_up)!r}")

    script_dir = tempfile.mkdtemp(prefix="aitm-tui-scan-selftest-")
    try:
        s_ev = Evidence([secret], directory=script_dir)
        s_out = io.StringIO()

        def scripted(**kw):
            term = ScriptedTerm(**kw)
            checks = Checks(s_ev.redact, screen=term.text, write=s_ev.write, out=s_out)
            return term, checks, Ctx(checks, term, None, None, s_ev, 0, "", ORIGIN, 8080, set())

        lagged, _, lag_ctx = scripted(lag=3)
        typed_ok = type_origin(lag_ctx, ORIGIN, timeout=3)
        c.check("selftest: type_origin returns only once the prompt bar left and the origin is on the "
                "`origins` line: True on a TUI that processes Enter late, no key after Enter (H49)",
                typed_ok is True and lagged.prompt is None and lagged.origins == ORIGIN
                and lagged.keys[-1] == ENTER and lagged.keys[0] == "o",
                f"{typed_ok} keys {lagged.keys!r} origins {lagged.origins!r}")
        refused, _, ref_ctx = scripted(refuse=True)
        typed_no = type_origin(ref_ctx, ORIGIN, timeout=0.6)
        c.check("selftest: type_origin is False while the bar stays up (a refused value, "
                "`submit_retrying`) and presses nothing more: no Esc into the open prompt (H49, H43)",
                typed_no is False and refused.prompt == ("origin:", "") and refused.keys[-1] == ENTER,
                f"{typed_no} keys {refused.keys!r} prompt {refused.prompt!r}")
        l4term, _, l4_ctx = scripted(lag=1)
        l4_ok = type_l4_target(l4_ctx, "127.0.0.1:8080/tcp", timeout=3)
        c.check("selftest: type_l4_target waits the same way: the target on the `l4` line, the bar gone (H49)",
                l4_ok is True and l4term.l4 == "127.0.0.1:8080/tcp" and l4term.prompt is None,
                f"{l4_ok} l4 {l4term.l4!r} keys {l4term.keys!r}")
        stuck, _, stuck_ctx = scripted(refuse=True)
        stuck.press("o")
        c.check("selftest: focus_profiles_list presses nothing while a Scan prompt is up (an Esc "
                "would discard the typed value after H43) and returns False (H49)",
                focus_profiles_list(stuck_ctx) is False and stuck.keys == ["o"],
                f"keys {stuck.keys!r}")

        stray, stray_checks, stray_ctx = scripted(on_field=False)
        stray_ok = set_browser_never(stray_ctx, "T7-16")
        after_e = stray.keys[stray.keys.index("e") + 1:] if "e" in stray.keys else None
        stray_files = sorted(n for n in os.listdir(script_dir) if "stray-prompt" in n)
        c.check("selftest: set_browser_never: an `e` that opens the `value:` prompt gets one Esc and "
                "nothing more, the H42 check FAILS naming the prompt, and the prompt screen is kept "
                "as `screen-T7-16-stray-prompt.txt` (H44)",
                stray_ok is False and stray.keys.count("e") == 1 and after_e == [ESC]
                and stray.prompt is None and len(stray_checks.failed()) == 1
                and "`value:` prompt" in s_out.getvalue() and stray_files == ["screen-T7-16-stray-prompt.txt"],
                f"{stray_ok} keys {stray.keys!r} files {stray_files} printed {s_out.getvalue()[-300:]!r}")
        walked, walk_checks, walk_ctx = scripted(on_field=True)
        walk_ok = set_browser_never(walk_ctx, "T7-17")
        c.check("selftest: set_browser_never: on the `use_browser` field two `e` presses walk the ring "
                "auto, always, never and the H42 check passes (H42, H44)",
                walk_ok is True and walked.browser == "never" and walked.keys.count("e") == 2
                and walk_checks.tally() == (1, 0, 0)
                and walked.keys[:3] == [ESC, "\t", "g"] and walked.keys[3] == "j" * EDITOR_FIELDS.index("use_browser"),
                f"{walk_ok} browser {walked.browser!r} keys {walked.keys!r}")

        # Cell item from the fourth live smoke run: H62. The `standard` job finished its 182
        # probes in about a second, so the sampled job runs `thorough`, set through the
        # same Fields walk as `browser never`.
        c.check("selftest: speed_value reads the held editor's `speed` from its `intensity` Fields "
                "row (`normal`, `thorough`) and nothing from the list header's bare `speed` (H62)",
                speed_value(held) == "normal" and speed_value(profiles_frame(editor=True, speed="thorough")) == "thorough"
                and speed_value(plain) is None,
                f"{speed_value(held)!r} {speed_value(plain)!r}")
        sped, sped_checks, sped_ctx = scripted(on_field=True)
        sped_ok = set_speed_thorough(sped_ctx, "T7-16")
        c.check("selftest: set_speed_thorough: Esc, Tab, `g`, then EDITOR_FIELDS.index('speed') `j`s land "
                "on `speed`; one `e` turns `normal` into `thorough`, the H62 check passes and the "
                "crawl `browser` line is untouched (H62)",
                sped_ok is True and sped.speed == "thorough" and sped.browser == "auto"
                and sped.keys.count("e") == 1 and sped_checks.tally() == (1, 0, 0)
                and sped.keys[:3] == [ESC, "\t", "g"] and sped.keys[3] == "j" * EDITOR_FIELDS.index("speed")
                and speed_value(sped.text()) == "thorough",
                f"{sped_ok} speed {sped.speed!r} browser {sped.browser!r} keys {sped.keys!r}")
        both, both_checks, both_ctx = scripted(on_field=True)
        both_ok = set_browser_never(both_ctx, "T7-16") and set_speed_thorough(both_ctx, "T7-16")
        c.check("selftest: the T7-16 launch sequence, `browser never` then `speed thorough` on one "
                "held editor, leaves both on the Fields lines with three `e` presses and two passed "
                "checks; a second pass presses no `e` and both checks pass again (H62)",
                both_ok is True and both.browser == "never" and both.speed == "thorough"
                and both.keys.count("e") == 3 and both_checks.tally() == (2, 0, 0)
                and set_browser_never(both_ctx, "T7-16", "the fresh job's editor") is True
                and set_speed_thorough(both_ctx, "T7-16", "the fresh job's editor") is True
                and both.keys.count("e") == 3 and both_checks.tally() == (4, 0, 0),
                f"{both_ok} browser {both.browser!r} speed {both.speed!r} keys {both.keys!r}")

        # Cell item from the fifth live smoke run: H70. `thorough` alone still finished the
        # `standard` job in about 2 s (278 probes, one `done` sample), so the sampled job
        # and the fresh cancel job also cycle `intensity` to `intrusive`, read off the same
        # Fields line as `speed`, and the samples come every 0.5 s.
        intrusive = profiles_frame(editor=True, intensity="intrusive")
        c.check("selftest: intensity_value reads the held editor's `intensity` from its Fields row "
                "(`medium` on the builtin, `intrusive`) and nothing from the list header's bare "
                "`intensity` or the list rows' `medium` cells (H70)",
                intensity_value(held) == "medium" and intensity_value(intrusive) == "intrusive"
                and intensity_value(plain) is None and "medium" in plain
                and INTENSITY_RING == ("passive", "light", "medium", "intrusive"),
                f"{intensity_value(held)!r} {intensity_value(intrusive)!r} {intensity_value(plain)!r}")
        harder, harder_checks, harder_ctx = scripted(on_field=True)
        harder_ok = set_intensity_intrusive(harder_ctx, "T7-16")
        c.check("selftest: set_intensity_intrusive: Esc, Tab, `g`, then EDITOR_FIELDS.index('intensity') "
                "`j`s land on `intensity`; one `e` turns `medium` into `intrusive`, the H70 check passes "
                "and the `speed` and crawl `browser` values are untouched (H70)",
                harder_ok is True and harder.intensity == "intrusive" and harder.speed == "normal"
                and harder.browser == "auto" and harder.keys.count("e") == 1
                and harder_checks.tally() == (1, 0, 0)
                and harder.keys[:3] == [ESC, "\t", "g"]
                and harder.keys[3] == "j" * EDITOR_FIELDS.index("intensity")
                and intensity_value(harder.text()) == "intrusive" and speed_value(harder.text()) == "normal",
                f"{harder_ok} intensity {harder.intensity!r} speed {harder.speed!r} keys {harder.keys!r}")
        three, three_checks, three_ctx = scripted(on_field=True)
        three_ok = (set_browser_never(three_ctx, "T7-16") and set_speed_thorough(three_ctx, "T7-16")
                    and set_intensity_intrusive(three_ctx, "T7-16"))
        c.check("selftest: the T7-16 launch sequence, `browser never`, `speed thorough`, `intensity "
                "intrusive` on one held editor, leaves all three on the Fields lines with four `e` "
                "presses and three passed checks; a second pass presses no `e`; the samples come "
                f"every 0.5 s, three at least (H70)",
                three_ok is True and three.browser == "never" and three.speed == "thorough"
                and three.intensity == "intrusive" and three.keys.count("e") == 4
                and three_checks.tally() == (3, 0, 0)
                and set_intensity_intrusive(three_ctx, "T7-16", "the fresh job's editor") is True
                and three.keys.count("e") == 4 and three_checks.tally() == (4, 0, 0)
                and SAMPLE_GAP_S == 0.5 and SAMPLES_MIN == 3,
                f"{three_ok} browser {three.browser!r} speed {three.speed!r} intensity "
                f"{three.intensity!r} keys {three.keys!r}; gap {SAMPLE_GAP_S}")

        # Cell item from the seventh live smoke run: H80. Three samples at 0.5 s all read
        # `running/audit` (`status-pairs.json`: the crawl phase had passed before the row
        # appeared), so the sampling goes on until the state/phase cell changes or SAMPLES_MAX
        # (8) samples exist, never fewer than SAMPLES_MIN, and the post-`x` `cancelled` row
        # is the last sample of the phase-change assertion.
        audit = {"screen_state_phase": "running/audit", "screen_sent": 1}
        report = {"screen_state_phase": "running/report", "screen_sent": 2}
        cancel_row = sample_of("cancel", "│>" + JOB + "  standard  http://127.0.0.1:8080  cancelled"
                               "      220/2000", JOB, {"probes": {"sent": 220}, "state": "cancelled"},
                               {"probes": {"sent": 220}, "state": "cancelled"}, True)
        c.check("selftest: T7-16 sampling: three identical samples keep sampling (the run 7 case), a "
                "fourth with a changed phase ends it, eight identical end it, two with a change go on to "
                "the third; the `cancelled` row folds as a bracketed sample whose phase differs (H80)",
                SAMPLES_MAX == 8 and more_samples([]) and more_samples([audit, audit])
                and more_samples([audit, audit, audit]) and not more_samples([audit, audit, audit, report])
                and more_samples([audit] * 7) and not more_samples([audit] * 8)
                and more_samples([audit, report]) and not more_samples([audit, report, report])
                and len(set(phases_of([audit, audit, audit]))) == 1
                and phases_of([audit, audit, audit, cancel_row]) == ["running/audit"] * 3 + ["cancelled"]
                and cancel_row["n"] == "cancel" and cancel_row["job"] == JOB
                and cancel_row["screen_sent"] == 220 and cancel_row["screen_budget"] == 2000
                and cancel_row["status_before_sent"] == 220 and cancel_row["status_after_state"] == "cancelled"
                and cancel_row["caught_up"] is True,
                f"cancel sample {cancel_row}")

        # Cell item from the fifth live smoke run: H72. The start reply switches the Scan tab
        # to Jobs (`fold_start_result`), so a `4` pressed before it lands is undone: `launch`
        # returns only once the Jobs footer and the new row are on screen (or the wait ran
        # out, recorded in `ctx.landed`).
        landing = ScriptedScreens([held, held, jobs_frame()])
        landed_ok = wait_landed(Ctx(Checks(out=io.StringIO()), landing, None, None, s_ev, 0, "", ORIGIN,
                                    8080, set()), JOB, 3.0)
        toasted = profiles_frame(editor=True, banner=f"started {JOB}")
        toast_only = ScriptedScreens([toasted])
        toast_ok = wait_landed(Ctx(Checks(out=io.StringIO()), toast_only, None, None, s_ev, 0, "", ORIGIN,
                                   8080, set()), JOB, 0.4)
        c.check("selftest: wait_landed ends on the Jobs footer AND the job's row (the third read), "
                "not on the job id alone: the Profiles tab with the start toast's id on the strip "
                "runs the whole wait and answers False (H72)",
                landed_ok is True and landing.reads == 3 and toast_ok is False and JOB in toasted
                and toast_only.reads >= 3 and landed_on_jobs(jobs_frame(), JOB)
                and not landed_on_jobs(toasted, JOB) and not landed_on_jobs(jobs_frame(), "scan-ffffffff"),
                f"landed {landed_ok} after {landing.reads} reads; toast {toast_ok} after {toast_only.reads}")
        lands = ScriptedScreens([held, held, held, jobs_frame()])
        lands_bus = ScriptedListBus(JOB)
        lands_ctx = Ctx(Checks(out=io.StringIO()), lands, lands_bus, None, s_ev, 0, "", ORIGIN, 8080, set())
        got = launch(lands_ctx, "s", timeout=3.0, land_s=3.0)
        never = ScriptedScreens([held])
        never_ctx = Ctx(Checks(out=io.StringIO()), never, ScriptedListBus(JOB), None, s_ev, 0, "", ORIGIN,
                        8080, set())
        got_never = launch(never_ctx, "m", timeout=3.0, land_s=0.4)
        c.check("selftest: launch presses the key, reads the new id off scan.list and returns it only "
                "once the start reply landed on the Jobs tab (`ctx.landed[job]` True after the Jobs "
                "frame); on a screen that never lands it returns the id after the bounded wait with "
                "`landed` False, so the step's check names it (H72)",
                got == JOB and lands_ctx.landed == {JOB: True} and lands.reads == 4 and lands.keys == ["s"]
                and got_never == JOB and never_ctx.landed == {JOB: False} and never.keys == ["m"],
                f"got {got!r} landed {lands_ctx.landed} reads {lands.reads}; never {got_never!r} "
                f"{never_ctx.landed} reads {never.reads}")

        # Cell item from the sixth live smoke run: H77. An `intrusive` launch raises the
        # engine's `needs_confirmation` overlay (`fail-3-t7-16.txt`): `launch` reads the
        # title after the key, records the check, presses `y`, and only then reads the new
        # id and waits for the landing. The scripted bus lists the job only once `y` was
        # pressed, so a launch that never answered the overlay could not pass here. The
        # overlay carries the engine's live prompt, wrapped in the box as run 7 drew it (H79).
        over_held = wire_confirm_over(held, LIVE_CONFIRM_PROMPT)
        asked = ScriptedScreens([over_held, over_held, jobs_frame()])
        asked_checks = Checks(out=io.StringIO())
        asked_ctx = Ctx(asked_checks, asked, ScriptedListBus(JOB, armed=lambda: "y" in asked.keys), None,
                        s_ev, 0, "", ORIGIN, 8080, set())
        got_asked = launch(asked_ctx, "s", timeout=3.0, land_s=3.0, step="T7-16")
        asked_names = [n for n, _ in asked_checks.results]
        c.check("selftest: launch on the wire-confirm overlay: the title after `s` is recorded as the "
                "step's own ok check (`asked to confirm the intrusive launch`), `y` is pressed, the id "
                "is read only after it and the landing wait runs as before; a launch the engine "
                "started outright records no such check (H77)",
                got_asked == JOB and asked.keys == ["s", "y"] and asked_ctx.landed == {JOB: True}
                and len(asked_names) == 1 and asked_names[0].startswith("T7-16: ")
                and "asked to confirm the intrusive launch" in asked_names[0]
                and asked_checks.results[0][1] == "ok" and lands_ctx.c.results == []
                and never_ctx.c.results == [],
                f"got {got_asked!r} keys {asked.keys} landed {asked_ctx.landed} checks {asked_checks.results}; "
                f"outright {lands_ctx.c.results} {never_ctx.c.results}")
        # An overlay whose prompt is not the engine's "may disrupt the target" wording still
        # gets its `y` (the launch must go on) but the check reads FAIL and names the screen
        # (the wrap splits the phrase, so the first row's `may disrupt the` is what changes).
        odd = Frame.from_text(over_held)
        odd_text = odd.text().replace("may disrupt the", "may unsettle the")
        odd_screens = ScriptedScreens([odd_text, jobs_frame()])
        odd_checks = Checks(out=io.StringIO())
        odd_ctx = Ctx(odd_checks, odd_screens, ScriptedListBus(JOB, armed=lambda: "y" in odd_screens.keys),
                      None, s_ev, 0, "", ORIGIN, 8080, set())
        got_odd = launch(odd_ctx, "m", timeout=3.0, land_s=3.0, step="T7-19")
        c.check("selftest: launch on a confirm overlay without the engine's `may disrupt the target` "
                "prompt still answers `y` and lands, and the recorded check is FAIL (H77)",
                got_odd == JOB and odd_screens.keys == ["m", "y"] and odd_checks.results
                and odd_checks.results[0][1] == "FAIL" and odd_checks.results[0][0].startswith("T7-19: "),
                f"got {got_odd!r} keys {odd_screens.keys} checks {odd_checks.results}")
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)

    # Cell item from the fifth live smoke run: H71. The tab markers are checked against the
    # footer literals the Rust key tables spell (`ui/scan/mod.rs` `key_text(&[JOBS_KEYS])`,
    # `key_text(&[ISSUES_FILTER_KEYS])`; the Profiles list header in `ui/scan/profiles.rs`):
    # the frames paint their footers from the same tuples, one row per marker, and the
    # tuples are read back from the Rust sources so a renamed key fails here, with no core.
    profiles_header = profiles_header_text()
    jobs_footer, issues_filter, issues_detail = (key_text([JOBS_KEYS]), key_text([ISSUES_FILTER_KEYS]),
                                                 key_text([ISSUES_KEYS]))
    others = {"1": [jobs_footer, issues_filter, issues_detail, key_text([SITEMAP_KEYS]), key_text([PROFILES_KEYS])],
              "2": [profiles_header, issues_filter, issues_detail, key_text([SITEMAP_KEYS]), key_text([PROFILES_KEYS])],
              "4": [profiles_header, jobs_footer, issues_detail, key_text([SITEMAP_KEYS]), key_text([PROFILES_KEYS])]}
    c.check("selftest: marker `1` matches the Profiles list header painted from its column names "
            "(`name  lanes  intensity  speed`) and no tab's key footer (H71)",
            re.search(TAB_MARKERS["1"], profiles_header) is not None
            and all(re.search(TAB_MARKERS["1"], t) is None for t in others["1"])
            and re.search(TAB_MARKERS["1"], profiles_frame(editor=False)) is not None,
            repr(profiles_header))
    c.check("selftest: marker `2` matches the Jobs footer `key_text(&[JOBS_KEYS])` painted from the "
            "table (`x cancel · ⏎ issues of this job · s start · m map`) and no other footer (H71)",
            re.search(TAB_MARKERS["2"], jobs_footer) is not None
            and jobs_footer == "x cancel · ⏎ issues of this job · s start · m map"
            and all(re.search(TAB_MARKERS["2"], t) is None for t in others["2"])
            and line_with(jobs_frame(), "x cancel").strip("│ ") == jobs_footer,
            repr(jobs_footer))
    c.check("selftest: marker `4` matches the Issues filter line `key_text(&[ISSUES_FILTER_KEYS])` "
            "painted from the table (`S severity · C confidence · L lane · T status · J job · R reset`) "
            "and neither the Issues detail footer nor any other tab's (H71)",
            re.search(TAB_MARKERS["4"], issues_filter) is not None
            and issues_filter == "S severity · C confidence · L lane · T status · J job · R reset"
            and all(re.search(TAB_MARKERS["4"], t) is None for t in others["4"])
            and line_with(issues_frame(), "S severity").split("│")[1].strip() == issues_filter
            and issues_detail == "c confirm · f false positive · u reopen · ⏎ open flow · P PoC",
            repr(issues_filter))
    # Cell item from the fifth live smoke run: H74. After the Nodes walk the cursor sat on
    # the last row; `g` was pressed and the next read, satisfied by the stale screen, took
    # the last row (`POST /login`) for the row under the cursor while the TUI homed and
    # opened the first node's flow (`GET /`).
    first_row = cursor_row(sitemap_frame(cursor=0))
    last_frame = sitemap_frame(cursor=2)
    homing = ScriptedScreens([last_frame, last_frame, sitemap_frame(cursor=0)])
    homed = press_home(homing, first_row, timeout=3.0)
    stuck = ScriptedScreens([last_frame])
    stuck_home = press_home(stuck, first_row, timeout=0.4)
    c.check("selftest: press_home presses `g` and waits for the cursor row to read the walk's first "
            "row: the stale screen with the `>` still on the last row (`POST /login`, which the old "
            "`is not None` read took at once) does not end the wait, the homed frame two reads later "
            "does; a screen that never homes runs the whole wait and answers False (H74)",
            homed is True and homing.reads == 3 and homing.keys == ["g"]
            and (cursor_row(last_frame) or "").strip().startswith("POST /login")
            and cursor_row(last_frame) is not None and first_row.strip().startswith("GET  /search")
            and stuck_home is False and stuck.reads >= 3
            and node_at_cursor((cursor_row(last_frame) or "").strip(), SITEMAP_NODES) is SITEMAP_NODES[2],
            f"homed {homed} after {homing.reads} reads keys {homing.keys}; stuck {stuck_home} after "
            f"{stuck.reads}; last row {cursor_row(last_frame)!r} first {first_row!r}")

    rust = {name: rust_hints(RUST_KEY_TABLES, name) for name in
            ("PROFILES_KEYS", "JOBS_KEYS", "SITEMAP_KEYS", "ISSUES_KEYS", "ISSUES_FILTER_KEYS")}
    c.check("selftest: the key tuples the frames paint from are the Rust key tables' "
            "(`crates/aitm-tui/src/ui/scan/mod.rs`, read back; a const hint such as `RESET` or "
            "`OPEN_FLOW` resolved), and the Profiles header's four column names stand in that "
            "order in `ui/scan/profiles.rs` (H71)",
            rust["PROFILES_KEYS"] == PROFILES_KEYS and rust["JOBS_KEYS"] == JOBS_KEYS
            and rust["SITEMAP_KEYS"] == SITEMAP_KEYS and rust["ISSUES_KEYS"] == ISSUES_KEYS
            and rust["ISSUES_FILTER_KEYS"] == ISSUES_FILTER_KEYS
            and rust_profiles_header(RUST_PROFILES_VIEW) == PROFILES_HEADER,
            f"rust {rust}; header {rust_profiles_header(RUST_PROFILES_VIEW)}")

    def job_line(job, event, **extra):
        params = {"job": job, "kind": "scan", "event": event, "seq": 1, "status": {"state": "running"}}
        params.update(extra)
        return {"jsonrpc": "2.0", "method": "notifications/aitm/job", "params": params}

    # Eight reads: the first job line; a flow line stashed then a non-object line (a bad
    # line, consumed); the reply stashed then the scripted ValueError (a bad line); the
    # `cancelled` line; a job line whose params are not an object (counted by method,
    # then a bad message); two `progress` lines of the second job; the dead socket.
    dead = ScriptedPushClient([
        [job_line("scan-00000001", "progress"), {"jsonrpc": "2.0", "method": "notifications/aitm/flow"},
         "not an object", {"jsonrpc": "2.0", "id": 7, "result": {}}],
        ValueError("Expecting value: line 1 column 1 (char 0)"),
        [job_line("scan-00000001", "cancelled", issue={"name": "x"}),
         {"jsonrpc": "2.0", "method": JOB_PUSH, "params": "x"},
         job_line("scan-00000002", "progress"), job_line("scan-00000002", "progress")],
        BusError("bus connection closed by the core"),
    ])
    dead_pushes = Pushes(dead, {"subscribed": True})
    dead_pushes._thread.join(5)
    snap = dead_pushes.snapshot()
    c.check("selftest: Pushes: two bad lines and a bad message are counted and read past; the "
            "dead socket ends the thread with `stopped_by: BusError: ..`; counts, by_method, the "
            "subscribe reply and the first three job params are in the snapshot (H46, H57)",
            not dead_pushes.alive() and (snap["stopped_by"] or "").startswith("BusError: bus connection closed")
            and dead_pushes.of("scan-00000001") == {"progress": 1, "cancelled": 1}
            and dead_pushes.of("scan-00000002") == {"progress": 2}
            and snap["by_method"] == {"notifications/aitm/job": 5, "notifications/aitm/flow": 1, "<reply>": 1}
            and snap["lines"] == 7 and snap["bad_lines"] == 2 and snap["bad_messages"] == 1
            and snap["subscribe_reply"] == {"subscribed": True}
            and [p["job"] for p in snap["first_job_params"]] == ["scan-00000001", "scan-00000001", "scan-00000002"]
            and dead.reads == 8 and "stopped_by: BusError" in dead_pushes.describe()
            and "'<reply>': 1" in dead_pushes.describe(),
            f"reads {dead.reads}; {json.dumps(snap, default=str)[:600]}")
    # The fourth live run's thread spun 32 million instant `None` reads: the harness's
    # buffered reader is broken after one read timeout (H64). The read now blocks for the
    # cell's budget, so a quiet socket holds the thread in ONE read, with nothing idle
    # counted, until `stop()` shuts the socket down under it.
    quiet = ScriptedPushClient([])
    quiet_pushes = Pushes(quiet, "this bus has no flow.subscribe")
    time.sleep(0.4)
    blocked = quiet_pushes.alive() and quiet.reads == 1 and quiet_pushes.snapshot()["idle_reads"] == 0
    quiet_pushes.stop()
    c.check("selftest: Pushes: a quiet socket holds the thread in one blocking read (alive, one read, "
            "no idle read after 0.4 s); `stop()` shuts the socket down under it and the thread ends "
            "at once with `stopped_by: stop()` and nothing counted; `read` names the blocking "
            "mechanism (H64, H46)",
            blocked and not quiet_pushes.alive() and quiet_pushes.snapshot()["stopped_by"] == "stop()"
            and quiet._sock.shutdowns == 1 and quiet.reads == 1
            and quiet_pushes.snapshot()["by_method"] == {} and quiet_pushes.snapshot()["lines"] == 0
            and quiet_pushes.snapshot()["read"] == PUSH_READ and "blocking" in PUSH_READ,
            f"blocked {blocked} reads {quiet.reads} shutdowns {quiet._sock.shutdowns}; "
            f"{json.dumps(quiet_pushes.snapshot(), default=str)}")
    broken = ScriptedPushClient([[job_line("scan-00000004", "progress")], OSError(9, "Bad file descriptor")])
    broken_pushes = Pushes(broken, {"sub_id": 1})
    broken_pushes._thread.join(3)
    b_snap = broken_pushes.snapshot()
    c.check("selftest: Pushes: a read the harness reader swallowed into an instant None (a socket "
            "error, or the reader broken by an earlier timeout) marks the thread dead with its "
            "reason, after exactly that one more read and no idle read, instead of spinning (H64)",
            not broken_pushes.alive() and (b_snap["stopped_by"] or "").startswith("read ended with None")
            and broken.reads == 2 and b_snap["idle_reads"] == 0
            and broken_pushes.of("scan-00000004") == {"progress": 1},
            f"reads {broken.reads}; {json.dumps(b_snap, default=str)[:400]}")
    slow = ScriptedPushClient([])
    slow_pushes = Pushes(slow, None, read_s=0.6)
    slow_pushes._thread.join(3)
    s_snap = slow_pushes.snapshot()
    c.check("selftest: Pushes: a read that waited its whole timeout counts the one idle read and "
            "ends the thread with `stopped_by: read timeout ..`; the thread never reads again "
            "after a None (H64)",
            not slow_pushes.alive() and (s_snap["stopped_by"] or "").startswith("read timeout")
            and s_snap["idle_reads"] == 1 and slow.reads == 1,
            f"reads {slow.reads}; {json.dumps(s_snap, default=str)[:400]}")
    # The third live run's socket: the TUI's polling fans an agent audit line out every
    # ~150 ms (2342 in the run), so a drain that returns only after 0.5 s of silence never
    # returned and the T7-16 check read zero lines (H57). Per-line reads count the job
    # line as soon as it is read; the agent lines the client read past while blocking
    # are folded from its stash when the thread ends (H64).
    agent = {"jsonrpc": "2.0", "method": "notifications/aitm/agent", "params": {"verb": "scan.status"}}
    busy = ScriptedPushClient([[agent] * 100 + [job_line("scan-00000003", "progress")] + [agent] * 100])
    busy_pushes = Pushes(busy, {"sub_id": 1})
    counted = poll(lambda: busy_pushes.of("scan-00000003") == {"progress": 1}, 3, 0.05)
    time.sleep(0.2)
    still = busy_pushes.alive() and busy.reads == 2
    busy_pushes.stop()
    c.check("selftest: Pushes: a socket that is never quiet (100 agent lines, one job line, 100 "
            "more) has the job line counted without waiting for a silence and the thread still "
            "blocked in its second read; after `stop()` every agent line is counted by method "
            "(200) and `lines` is 201 (H57, H64)",
            counted and still and busy_pushes.snapshot()["lines"] == 201
            and busy_pushes.snapshot()["by_method"].get("notifications/aitm/agent") == 200
            and busy_pushes.snapshot()["read"] == PUSH_READ and "wait_notification" in PUSH_READ
            and busy_pushes.snapshot()["stopped_by"] == "stop()",
            f"still {still} reads {busy.reads}; {json.dumps(busy_pushes.snapshot(), default=str)[:400]}")

    n_ok, n_noted, n_failed = c.tally()
    print(f"{'PASS' if not n_failed else 'FAIL'}: selftest {n_ok} ok, {n_failed} failed", flush=True)
    return 0 if not n_failed else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(main())
