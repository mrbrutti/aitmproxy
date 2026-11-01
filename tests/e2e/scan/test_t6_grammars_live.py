#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=l4
"""scan/t6_grammars_live -- AC T6-4: EVERY one of the eight stream grammars,
against its REAL seeded speaker, in both modes, with the bytes/s pacer proven
from the speaker's own message timestamps.

For each grammar of parent D8.5 (TLV, RESP, memcached text, DNS UDP,
Modbus/TCP, MQTT, SMTP, FTP) and its child-spec-D5 speaker:

  * on VULNERABLE, one job (`l4-stream-safe`, `overrides.l4.max_bytes_per_s =
    16384`, `cases = 200`) files EXACTLY ONE issue whose
    `location.l4.grammar` is that grammar and whose class is `l4-crash` or
    `l4-parser-fault`;
  * the generated messages really are well formed: some inbound message in
    the speaker's own `/log/l4` is classified `ok`;
  * the speaker's own `downtime` ring is non-empty (its parse bug made it
    close and fail liveness for its bounded window);
  * the pacer holds on the speaker's own clock: over every sliding 1 000 ms
    window of the inbound `messages`, the summed `len` is at most
    `16384 * 1.1` bytes (10 % slack for window alignment);
  * on PATCHED the same job files zero issues and the `downtime` ring stays
    empty.

`raw` (the speaker `l4-udp-payload-crash`) is the PACKET lane's grammar and is
covered by AC T5-2b in `test_t5_crash_oracle.py`; it is not run here. That is
why this cell iterates eight grammars, not nine.

Partial skips. The lane ships three GENERIC checks for every grammar
(`l4-crash`, `l4-parser-fault`, `l4-latency-outlier`, kind `l4_field`; T6 child
spec S6.3): a check id never names a grammar, the grammar lives in
`Issue.location.l4.grammar` and the site node's `path_template`. So "landed" is
one question for the whole lane (at least one `l4_stream` check of kind `l4_field`
in `scan.checks`),
and the per-grammar question is answered by `scan.start`: an unknown grammar is
refused with `invalid_profile: unknown grammar '<x>'; known: ...`, printed as
`[SKIP-PART] <grammar>` and the cell moves on -- but if EVERY grammar skips that
way the cell FAILS, so a half-landed lane is visible while a missing lane is a
normal whole-cell SKIP 77.

Observer: the seeded speakers' control-origin L4 logs (classification,
downtime, and the message timestamps the pacer bound is computed from).

SKIPs 77: missing `scan.*` verbs; no `l4_stream` check at all in `scan.checks`.
Soft-assertion battery: every grammar runs even after one of them fails, and
the failures are listed together at the end.

Budget: 16 jobs of up to 200 cases with 5 s crash windows; allow several
minutes of wall time.

Exit 0 pass / 1 fail / 77 skip. Never prints a token.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig, l4_inject_entry  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    Expectations,
    ScanTarget,
    boot_target,
    issues,
    l4_endpoint,
    require_lane,
    require_verbs,
    scan_call,
    scan_error_code,
    start_job,
    wait_terminal,
)

# (grammar, the child spec D5 speaker that speaks it). `raw` is the packet
# lane's and is deliberately absent (AC T5-2b covers it).
GRAMMARS: tuple[tuple[str, str], ...] = (
    ("tlv", "l4-tlv-crash"),
    ("resp", "l4-resp"),
    ("memcached", "l4-memcached"),
    ("dns", "l4-dns-fault"),
    ("modbus", "l4-modbus"),
    ("mqtt", "l4-mqtt"),
    ("smtp", "l4-smtp"),
    ("ftp", "l4-ftp"),
)
# `tlv` is the one grammar with no generator of its own: a named `tlv` with an empty
# corpus has nothing to infer from (parent spec D8.5 Corpus (c); T6 child spec S5.2 (c)),
# so the row passes the
# same three well-formed frames `test_t6_tlv_crash.py` uses (u16 BE length + payload,
# three distinct lengths so the S4 length inference succeeds). Every other grammar
# generates its own seeds.
TLV_SEEDS = [{"hex": "000161"}, {"hex": "00026162"}, {"hex": "0003616263"}]
FAULT_CLASSES = {"l4-crash", "l4-parser-fault"}
VERBS = ("scan.start", "scan.status", "scan.issues", "scan.checks")
MAX_BYTES_PER_S = 16384
PACER_LIMIT = MAX_BYTES_PER_S * 1.1
WINDOW_MS = 1000
CASES = 200
# One bounded L4 job per grammar against a local speaker; 300 s each.
JOB_TIMEOUT = 300.0

# One soft-assert collector: one grammar's failure must not hide the other eight.
EXPECT = Expectations("grammar assertion")
expect = EXPECT.expect


def lane_landed(checks: list[dict]) -> bool:
    """Has the stream lane landed at all: at least one `scan.checks` entry of the
    `l4_stream` lane with the `l4_field` insertion kind, whatever its id (the
    three generic checks carry no grammar name; T6 child spec S6.3). The packet
    lane's checks carry `l4_field` too, hence the lane filter. Per-grammar
    support is decided by `scan.start`, never by the catalogue."""
    return any("l4_field" in (c.get("kinds") or []) and "l4_stream" in (c.get("lanes") or [])
               for c in checks)


def worst_window(messages: list[dict]) -> tuple[int, int]:
    """(worst summed `len` over any sliding 1 000 ms window of `messages`,
    total bytes). The window is half-open [t, t + 1000) anchored on each
    message's own `ts_ms`, so every burst the speaker saw is covered."""
    pairs = sorted((int(m.get("ts_ms", 0)), int(m.get("len", 0))) for m in messages)
    worst = 0
    total = sum(n for _, n in pairs)
    end = 0
    running = 0
    for start in range(len(pairs)):
        if end < start:
            end, running = start, 0
        while end < len(pairs) and pairs[end][0] < pairs[start][0] + WINDOW_MS:
            running += pairs[end][1]
            end += 1
        worst = max(worst, running)
        running -= pairs[start][1]
    return worst, total


def start_stream_job(op: BusClient, target: ScanTarget, service: str, grammar: str) -> str | None:
    """Start the job; return its id, or None when the lane refused the grammar
    with `invalid_profile` (a partial skip). Any other refusal is raised."""
    try:
        started = start_job(
            op, "operator",
            profile_name="l4-stream-safe",
            overrides={
                "target": {"l4": [l4_endpoint(target, service, grammar)]},
                "l4": {"cases": CASES, "max_bytes_per_s": MAX_BYTES_PER_S,
                       **({"seeds": TLV_SEEDS} if grammar == "tlv" else {})},
            },
            confirm=True,
        )
    except ToolError as e:
        msg = str(e)
        if scan_error_code(msg) == "invalid_profile" and grammar in msg:
            return None
        raise
    return started.get("job")


def check_grammar(op: BusClient, vuln: ScanTarget, patched: ScanTarget,
                  grammar: str, service: str, checks: list[dict]) -> bool:
    """Run both halves for one grammar. True when it ran, False when it was
    skipped as not landed."""
    section(f"grammar {grammar} -- speaker {service}")
    if not lane_landed(checks):
        print(f"  [SKIP-PART] {grammar}: scan.checks has no `l4_stream` check of kind `l4_field` "
              "(lane not landed)", flush=True)
        return False

    vuln.logs.reset()
    job = start_stream_job(op, vuln, service, grammar)
    if job is None:
        print(f"  [SKIP-PART] {grammar}: scan.start refused it with invalid_profile", flush=True)
        return False
    status = wait_terminal(op, "operator", job, timeout=JOB_TIMEOUT)
    expect(status.get("state") == "done",
           f"{grammar}: the vulnerable job finished `done` (got {status.get('state')!r}, "
           f"stopped_reason={status.get('stopped_reason')!r}, error={status.get('error')!r})")

    found = issues(op, "operator", job=job)
    mine = [i for i in found
            if ((i.get("location") or {}).get("l4") or {}).get("grammar") == grammar
            and i.get("class") in FAULT_CLASSES]
    expect(len(mine) == 1,
           f"{grammar}: exactly one {sorted(FAULT_CLASSES)} issue naming the grammar "
           f"(got {len(mine)} of {len(found)}: "
           f"{[(i.get('class'), ((i.get('location') or {}).get('l4') or {}).get('grammar')) for i in found]})")

    inbound = vuln.logs.messages(service, dir="in")
    expect(any(m.get("classified") == "ok" for m in inbound),
           f"{grammar}: some generated message parsed (classified `ok`); seen "
           f"{sorted({m.get('classified') for m in inbound})} over {len(inbound)} messages")

    downtime = vuln.logs.downtime(service)
    expect(len(downtime) >= 1,
           f"{grammar}: the speaker logged a crash window (got {len(downtime)})")

    worst, total = worst_window(inbound)
    expect(worst <= PACER_LIMIT,
           f"{grammar}: the pacer held -- worst 1 s window {worst} bytes <= {PACER_LIMIT:.0f} "
           f"({total} bytes over {len(inbound)} messages)")

    patched.logs.reset()
    p_job = start_stream_job(op, patched, service, grammar)
    if p_job is None:
        expect(False, f"{grammar}: the patched job was refused after the vulnerable one ran")
        return True
    p_status = wait_terminal(op, "operator", p_job, timeout=JOB_TIMEOUT)
    expect(p_status.get("state") == "done",
           f"{grammar}: the patched job finished `done` (got {p_status.get('state')!r})")
    p_total = (p_status.get("issues") or {}).get("total")
    expect(p_total == 0, f"{grammar}: the patched job filed no issues (got {p_total!r})")
    p_downtime = patched.logs.downtime(service)
    expect(p_downtime == [],
           f"{grammar}: the patched speaker logged no downtime (got {p_downtime})")
    return True


def main() -> int:
    vuln = patched = core = op = None
    ran: list[str] = []
    skipped: list[str] = []
    try:
        section("1. the nine seeded speakers in both modes, and a core with the L4 inject scope")
        vuln = boot_target("vulnerable", l4=True)
        patched = boot_target("patched", l4=True)
        names = {s.get("name") for s in vuln.services()}
        ok(f"/services lists {len(names)} services on the vulnerable target")

        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            l4_enabled=True,
            l4_scope_entries=[l4_inject_entry()],
        )
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        require_verbs(op, *VERBS)
        require_lane(op, "l4_stream")
        checks = (scan_call(op, "operator", "scan.checks", {}) or {}).get("checks") or []
        ok(f"the core advertises an l4_stream check ({len(checks)} checks in the catalogue)")

        section("2. every grammar, vulnerable then patched")
        for grammar, service in GRAMMARS:
            if service not in names:
                print(f"  [SKIP-PART] {grammar}: the target has no {service} service", flush=True)
                skipped.append(grammar)
                continue
            if check_grammar(op, vuln, patched, grammar, service, checks):
                ran.append(grammar)
            else:
                skipped.append(grammar)
    finally:
        if op:
            op.close()
        if core:
            core.stop()
        for t in (vuln, patched):
            if t:
                t.stop()

    section("3. coverage")
    print(f"  ran: {ran or '-'}", flush=True)
    print(f"  skipped: {skipped or '-'}", flush=True)
    if not ran:
        fail(f"every one of the {len(GRAMMARS)} grammars skipped as not landed ({skipped}); "
             "a half-landed lane must not pass as green")
    EXPECT.finish()
    ok(f"T6-4: {len(ran)}/{len(GRAMMARS)} grammars proven live on V and clean on P "
       f"(skipped as not landed: {skipped or '-'})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
