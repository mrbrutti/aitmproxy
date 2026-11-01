#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=l4 serial
"""scan/t5_crash_oracle -- AC T5-2: the L4 packet lane's oracle, proven twice against real
reactions (scanner v2 design AC 27 / D8.4; T10 plan task B10).

The target's kernel drops malformed IP/TCP/UDP headers before any userland service sees
them, so one positive proof is not enough. This cell runs both halves:

  (a) KERNEL oracle (T5-2a). A packet-lane job of 10 cases on `udp.length` against a real
      CLOSED UDP port yields ICMP port-unreachable, classified `{kind: icmp, type: 3,
      code: 3}`; 10 cases on `tcp.flags` against a real CLOSED TCP port yield `{kind:
      reset}`. Both are recorded as `info` `l4-protocol-reaction` issues, and neither job
      invents an `l4-crash`.
  (b) CRASH oracle (T5-2b). Against the VULNERABLE target's userland `l4-udp-payload-crash`
      service (child spec D5: a UDP echo that drops every datagram for a 5 s window when a
      payload starts `DE AD BE EF` and is at least 8 bytes long), a job fuzzing the `raw`
      layer from the seed `deadbeef0000` reaches that trigger through the lane's
      deterministic `grow:8` case and records exactly one `l4-crash` issue, `critical`
      / `firm`, `oracle.kind == "liveness_failed"`, `reproduced == [3, 3]`,
      `liveness_before: true`, `liveness_after: false`; the element is then RETIRED
      (`status.l4.retired_elements == 1`) and never sent again.
      The same profile against the PATCHED target (which echoes the trigger) yields zero
      issues and no downtime.

Observers -- the TARGET's own control-origin L4 log (`/log/l4`), never the scanner's word:
`downtime` (one entry per real crash window: `down_at_ms`, `up_at_ms`, `trigger_sha256`)
must hold 4 entries (the find plus three confirmation replays), and no `messages` entry
logged after the last window's `up_at_ms` may carry the trigger payload's sha256 -- that is
what "the element is retired and the lane stopped hammering it" means on the wire.
The kernel's ICMP/RST reactions are the second, independent observer for (a).
No fixture: a real `aitm` core, a real `aitm-testtarget-serve`, real packets.

SKIP (77) conditions, each naming the missing thing:
  * the serve binary or the `aitm` binary is absent;
  * the core does not advertise the `scan.*` verbs this cell calls (pre-T1b core);
  * `scan.checks` lists no check for the `l4_packet` lane (the T5 lane is not on this build);
  * the L4 module is not enabled on the core (no `l4.capture.status`);
  * `l4.privilege` (or, on a pre-p1b core, `l4.capture.status`) says packet capture is not
    available: the cell SKIPs with `packet-capture permission not granted (...)` naming the
    product's own path (macOS: the Aitmproxy app's packet-capture helper; Linux: the
    packet-capture helper, or the core process holding CAP_NET_RAW on a test rig), followed
    by the core's own reason. A core that holds the capability through the helper rather
    than its own process SKIPs too, naming that route (the proof is per-process today);
  * the core accepted a job but reported the `l4_packet` lane as skipped (its reason).

serial: it crashes a real service four times and fuzzes real ports. Exit 0 / 1 / 77.
Never prints a token.
"""
from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.config import CoreConfig, l4_capture_entry, l4_inject_entry  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    Expectations,
    boot_target,
    issue,
    issues,
    packet_lane_gate,
    split_addr,
    start_job,
    wait_terminal,
)

SERVICE = "l4-udp-payload-crash"
# Child spec D5: the V trigger is a payload starting DE AD BE EF with len >= 8. The seed is
# 6 bytes (benign: it is echoed), so only the lane's deterministic `grow:8` case reaches
# the trigger -- a 4-byte magic is unreachable from `616263` by random mutation.
# T5 committed the chain element as `grow:8` (the layer is not part of the token).
SEED_HEX = "deadbeef0000"
GROW_MUTATION = "grow:8"
TRIGGER_PAYLOAD = bytes.fromhex("deadbeef00000000")
KERNEL_CASES = 10
CRASH_CASES = 100
REPRODUCE_COUNT = 3
LIVENESS_EVERY = 25
# the find plus `reproduce_count` confirmation replays, one crash window each
EXPECTED_DOWNTIME = 1 + REPRODUCE_COUNT
VERBS = ("scan.start", "scan.status", "scan.issues", "scan.issue", "scan.checks")

# One soft-assert collector for the whole cell: a failing expectation records itself
# and the run continues, so one bad row never hides the rest of the evidence.
EXPECT = Expectations()
expect, note = EXPECT.expect, EXPECT.note


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def packet_profile(ip: str, port: int, proto: str, l4_opts: dict) -> dict:
    return {
        "lanes": ["l4_packet"],
        "target": {"origins": [], "l4": [{"ip": ip, "port": port, "proto": proto}]},
        "l4": dict(l4_opts),
    }


def run_job(op, profile: dict, label: str, timeout: float = 600.0) -> tuple[dict, dict, list[dict]]:
    """Start a confirmed packet-lane job, wait for its terminal status, and read its issues.
    SKIPs when the core reports the lane as skipped for this job."""
    started = start_job(op, "operator", profile=profile, confirm=True)
    note(f"scan.start ({label})", started)
    for entry in (started.get("lanes") or {}).get("skipped") or []:
        if entry.get("lane") == "l4_packet":
            skip(f"the core skipped the l4_packet lane for the {label} job: {entry.get('reason')}")
    job = started.get("job")
    if not isinstance(job, str):
        fail(f"scan.start ({label}) returned no job id: {started!r}")
    final = wait_terminal(op, "operator", job, timeout=timeout)
    note(f"scan.status ({label}, terminal)",
         {k: final.get(k) for k in ("state", "phase", "stopped_reason", "l4", "issues")})
    return started, final, issues(op, "operator", job=job)


def oracles_of(op, summaries: list[dict], want_class: str) -> list[dict]:
    """The `evidence.l4.oracle` object of every issue of `want_class` (full `scan.issue`
    reads: a summary carries no evidence)."""
    out = []
    for s in summaries:
        if s.get("class") != want_class:
            continue
        full = issue(op, "operator", s["id"])
        l4 = ((full.get("evidence") or {}).get("l4")) or {}
        out.append(l4.get("oracle"))
    return out


def check_kernel_reaction(op, ip: str, port: int, proto: str, field: str, want_oracle: dict, label: str) -> None:
    """(a) A real closed port's own kernel reaction, read back through the lane's evidence."""
    profile = packet_profile(ip, port, proto, {"cases": KERNEL_CASES, "fields": [field]})
    _, final, found = run_job(op, profile, label)
    expect(final.get("state") == "done", f"the {label} job finished `done`", final.get("state"))
    classes = sorted({str(i.get("class")) for i in found})
    note(f"{label} issue classes", classes)
    expect("l4-crash" not in classes, f"the {label} job invented no l4-crash issue", classes)
    reactions = [i for i in found if i.get("class") == "l4-protocol-reaction"]
    expect(len(reactions) >= 1,
           f"the {label} job recorded at least one l4-protocol-reaction issue", len(reactions))
    severities = sorted({str(i.get("severity")) for i in reactions})
    expect(severities in ([], ["info"]), f"every {label} protocol reaction is severity info", severities)
    oracles = oracles_of(op, found, "l4-protocol-reaction")
    note(f"{label} oracles", oracles)
    expect(want_oracle in oracles,
           f"the {label} reaction is classified {want_oracle} by the lane's oracle", oracles)


def wait_past(ts_ms: int, cap_s: float = 12.0) -> None:
    """Sleep until the wall clock is past `ts_ms` (bounded): a crash window that is still
    open would hide traffic the target could not log."""
    deadline = time.monotonic() + cap_s
    while time.time() * 1000 <= ts_ms and time.monotonic() < deadline:
        time.sleep(0.25)


def main() -> int:
    vuln = patched = core = op = None
    try:
        section("arrange: the vulnerable and patched targets with their L4 speakers, and an L4 core")
        vuln = boot_target("vulnerable", l4=True)
        patched = boot_target("patched", l4=True)
        v_svc = vuln.service(SERVICE)
        p_svc = patched.service(SERVICE)
        v_ip, v_port = split_addr(v_svc["addr"])
        p_ip, p_port = split_addr(p_svc["addr"])
        note(f"V /services[{SERVICE}]", v_svc)
        note(f"P /services[{SERVICE}]", p_svc)
        expect(v_svc.get("proto") == "udp", f"{SERVICE} is a udp service on V", v_svc.get("proto"))

        cfg = CoreConfig(
            proxy_port=free_port(),
            l4_enabled=True,
            l4_flags={},
            l4_scope_entries=[l4_inject_entry(), l4_capture_entry()],
        )
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        status = packet_lane_gate(op, *VERBS)
        note("l4.privilege (None on a core without the verb)", status.get("privilege"))

        section("(a) T5-2a: a real CLOSED UDP port answers ICMP 3/3, a real CLOSED TCP port answers RST")
        closed_udp = free_port()
        closed_tcp = free_port()
        note("closed ports (nothing is bound here)", {"udp": closed_udp, "tcp": closed_tcp})
        check_kernel_reaction(op, "127.0.0.1", closed_udp, "udp", "udp.length",
                              {"kind": "icmp", "type": 3, "code": 3}, "closed-udp")
        check_kernel_reaction(op, "127.0.0.1", closed_tcp, "tcp", "tcp.flags",
                              {"kind": "reset"}, "closed-tcp")

        section("(b) T5-2b: the userland crash oracle on V -- one l4-crash, confirmed and retired")
        vuln.logs.reset()
        crash_profile = packet_profile(v_ip, v_port, "udp", {
            "cases": CRASH_CASES,
            "reproduce_count": REPRODUCE_COUNT,
            "liveness_every": LIVENESS_EVERY,
            "fields": ["raw"],
            "seeds": [{"hex": SEED_HEX}],
        })
        _, final, found = run_job(op, crash_profile, "V-crash")
        expect(final.get("state") == "done", "the V crash job finished `done`", final.get("state"))
        crashes = [i for i in found if i.get("class") == "l4-crash"]
        note("V issue classes", sorted({str(i.get("class")) for i in found}))
        expect(len(crashes) == 1, "exactly one l4-crash issue", [i.get("class") for i in found])
        if crashes:
            full = issue(op, "operator", crashes[0]["id"])
            ev = ((full.get("evidence") or {}).get("l4")) or {}
            loc = ((full.get("location") or {}).get("l4")) or {}
            note("l4-crash evidence.l4", {k: v for k, v in ev.items() if k != "sent_hex"})
            note("l4-crash evidence.l4.sent_hex", ev.get("sent_hex"))
            expect(full.get("severity") == "critical", "the l4-crash issue is `critical`", full.get("severity"))
            expect(full.get("confidence") == "firm", "the l4-crash issue is `firm`", full.get("confidence"))
            expect(full.get("lane") == "l4_packet", "the issue's lane is l4_packet", full.get("lane"))
            expect(loc.get("ip") == v_ip and loc.get("port") == v_port and loc.get("proto") == "udp",
                   "the issue points at the fuzzed udp endpoint", loc)
            expect((ev.get("oracle") or {}).get("kind") == "liveness_failed",
                   'evidence.l4.oracle.kind == "liveness_failed"', ev.get("oracle"))
            expect(ev.get("reproduced") == [REPRODUCE_COUNT, REPRODUCE_COUNT],
                   f"evidence.l4.reproduced == [{REPRODUCE_COUNT}, {REPRODUCE_COUNT}]", ev.get("reproduced"))
            expect(ev.get("liveness_before") is True, "liveness_before is true", ev.get("liveness_before"))
            expect(ev.get("liveness_after") is False, "liveness_after is false", ev.get("liveness_after"))
            expect(GROW_MUTATION in (ev.get("mutation_chain") or []),
                   f'"{GROW_MUTATION}" is in evidence.l4.mutation_chain', ev.get("mutation_chain"))
            expect("deadbeef" in str(ev.get("sent_hex", "")).lower(),
                   "the bytes the lane sent carry the DE AD BE EF trigger magic", ev.get("sent_hex"))
            expect(ev.get("seed_id"), "the evidence names the seed the case was mutated from", ev.get("seed_id"))
        l4 = final.get("l4") or {}
        expect(l4.get("retired_elements") == 1, "status.l4.retired_elements == 1", l4.get("retired_elements"))
        expect(l4.get("crashes", 0) >= 1, "status.l4.crashes counted the crash", l4.get("crashes"))

        section("observer: the target's own downtime log, and the retirement proof on the wire")
        down = vuln.logs.downtime(SERVICE)
        note(f"/log/l4 {SERVICE} downtime", down)
        expect(len(down) == EXPECTED_DOWNTIME,
               f"the target logged {EXPECTED_DOWNTIME} crash windows (the find plus {REPRODUCE_COUNT} replays)",
               len(down))
        if down:
            last_up = max(int(d.get("up_at_ms", 0)) for d in down)
            wait_past(last_up + 500)
            trigger_hashes = {str(d.get("trigger_sha256")) for d in down}
            literal = sha256_hex(TRIGGER_PAYLOAD)
            note("sha256(DE AD BE EF 00 00 00 00)", literal)
            note("the target's own trigger_sha256 set", sorted(trigger_hashes))
            late = [m for m in vuln.logs.messages(SERVICE, dir="in") if int(m.get("ts_ms", 0)) > last_up]
            note("messages logged after the last crash window closed", len(late))
            repeats = [m for m in late if str(m.get("sha256")) in trigger_hashes]
            expect(not repeats,
                   "after the element was retired the trigger payload was never sent again "
                   "(no message past the last up_at_ms carries a logged trigger sha256)", repeats[:3])
            literal_repeats = [m for m in late if str(m.get("sha256")) == literal]
            expect(not literal_repeats,
                   "no message past the last up_at_ms carries the DE AD BE EF 00 00 00 00 payload",
                   literal_repeats[:3])

        section("(c) the same profile on P: a service that answers the trigger yields nothing")
        patched.logs.reset()
        p_profile = packet_profile(p_ip, p_port, "udp", {
            "cases": CRASH_CASES,
            "reproduce_count": REPRODUCE_COUNT,
            "liveness_every": LIVENESS_EVERY,
            "fields": ["raw"],
            "seeds": [{"hex": SEED_HEX}],
        })
        _, p_final, p_found = run_job(op, p_profile, "P-clean")
        expect(p_final.get("state") == "done", "the P job finished `done`", p_final.get("state"))
        expect((p_final.get("issues") or {}).get("total") == 0,
               "zero issues against the patched service", (p_final.get("issues") or {}).get("total"))
        expect([i.get("class") for i in p_found] == [], "scan.issues lists nothing for the P job", p_found)
        expect(patched.logs.downtime(SERVICE) == [],
               "the patched service logged no downtime window", patched.logs.downtime(SERVICE))
    finally:
        if op is not None:
            op.close()
        if core is not None:
            core.stop()
        for t in (patched, vuln):
            if t is not None:
                t.stop()

    EXPECT.finish()
    ok("PASS: the kernel reactions are classified, the userland crash is found, confirmed and retired, "
       "and the patched service stays clean")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
