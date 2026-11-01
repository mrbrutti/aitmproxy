#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=l4 serial
"""scan/t5_bounded_clean -- AC T5-1: the L4 PACKET lane is bounded and clean on a healthy
target (scanner v2 design AC 26 / D8.4; T10 plan task B10).

A packet-lane job with `cases: 100` and `liveness_every: 25` against the PATCHED target's
`l4-udp-payload-crash` service (which echoes every datagram and never faults) must:
send exactly its budget and nothing beyond it, never address a host it was not pinned to,
finish `done` with zero issues, and report `l4.liveness_failures == 0`.

Observers -- two, both outside the scanner:
  1. the KERNEL, through the core's own packet capture (`l4.capture.start` on the loopback
     interface, then `l4.flow.list` / `l4.flow.get`): every frame the lane actually put on
     the wire, read back from the capture the operator started. Ground truth for "100 cases
     + 1 baseline + 4 scheduled liveness probes = 105 frames" and for "every frame's `dst`
     is 127.0.0.1 on the pinned port".
  2. the TARGET's own control-origin L4 log (`/log/l4`): `downtime == []` for the fuzzed
     service and for `l4-tlv-crash` -- a healthy P target never went down.
No fixture: a real `aitm` core, a real `aitm-testtarget-serve`, real packets, real kernel.

SKIP (77) conditions, each naming the missing thing:
  * the serve binary or the `aitm` binary is absent (FileNotFoundError from the harness);
  * the core does not advertise the `scan.*` verbs this cell calls (pre-T1b core);
  * `scan.checks` lists no check for the `l4_packet` lane (the T5 lane is not on this build);
  * the L4 module is not enabled on the core (no `l4.capture.status`);
  * `l4.capture.status` says `available: false` -- the packet lane needs raw pcap privilege
    (macOS: read+write on /dev/bpf*, e.g. ChmodBPF; Linux: CAP_NET_RAW). On Matt's Mac
    /dev/bpf* is root-only, so this cell SKIPs there with the core's own `reason` until BPF
    is granted or a Linux rig runs it;
  * the core accepted the job but reported the `l4_packet` lane as skipped (its reason).

serial: it runs a privileged loopback capture and a packet fuzz run. Exit 0 / 1 / 77.
Never prints a token.

NOTE for the plan owner (reported, not redesigned): plan task B10 describes this cell as
"service `l4-udp-payload-crash` addr (udp; ...)" and in the same sentence pins the profile
to "`target: {l4: [{ip, port, proto: "tcp"}]}`". Those two cannot both hold: a TCP packet
to that UDP service's port reaches a CLOSED TCP port, whose RST is an `l4-protocol-reaction`
issue (that is exactly what test_t5_crash_oracle.py asserts), contradicting this cell's own
pinned `issues.total == 0`. This cell therefore sends `proto` as the service's own declared
transport from `/services` (asserted to be literally `udp`), which is the only reading under
which the pinned assertions can hold.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig, l4_capture_entry, l4_inject_entry  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import ScanTarget, start_job, require_lane, require_verbs, wait_terminal  # noqa: E402

SERVICE = "l4-udp-payload-crash"
CASES = 100
LIVENESS_EVERY = 25
# 100 cases + 1 baseline + 4 scheduled liveness probes (cases 25, 50, 75, 100).
EXPECTED_FRAMES = CASES + 1 + CASES // LIVENESS_EVERY
VERBS = ("scan.start", "scan.status", "scan.issues", "scan.checks")

_failures: list[str] = []


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


def note(label: str, value) -> None:
    print(f"note: {label} = {str(value)[:400]}", flush=True)


def loopback_interface() -> str:
    return "lo0" if sys.platform == "darwin" else "lo"


def split_addr(addr: str) -> tuple[str, int]:
    """`127.0.0.1:54321` -> ("127.0.0.1", 54321)."""
    host, _, port = str(addr).rpartition(":")
    return host, int(port)


def gate(op) -> dict:
    """SKIP 77 unless this core can run the packet lane: the scan verbs, a live
    `l4_packet` lane in `scan.checks`, the L4 module, and raw capture privilege.
    Returns the `l4.capture.status` reply."""
    require_verbs(op, *VERBS)
    require_lane(op, "l4_packet")
    if "l4.capture.status" not in set(op.tool_names()):
        skip("the L4 module is not enabled on this core (no l4.capture.status): the packet lane "
             "needs l4.enabled and the feature-compiled l4 module")
    status, reply = op.try_call("l4.capture.status")
    if status != "ok" or not isinstance(reply, dict):
        skip(f"l4.capture.status did not answer with an availability object: {str(reply)[:200]}")
    if reply.get("available") is not True:
        skip(f"the L4 packet lane needs raw pcap privilege, and this core has none: {reply.get('reason')} "
             "(macOS: read+write on /dev/bpf*, e.g. ChmodBPF; Linux: CAP_NET_RAW)")
    return reply


def skip_if_lane_skipped(started: dict) -> None:
    """The core took the job but could not run the lane: that is a SKIP with its reason,
    never a FAIL (a half-landed lane must be visible, not green)."""
    lanes = started.get("lanes") or {}
    for entry in lanes.get("skipped") or []:
        if entry.get("lane") == "l4_packet":
            skip(f"the core skipped the l4_packet lane for this job: {entry.get('reason')}")


def read_packets(op, flow_id: str, page: int = 500) -> list[dict]:
    """Every packet of a capture flow, walking `l4.flow.get {offset, limit}` while the
    reply says `truncated`."""
    out: list[dict] = []
    offset = 0
    while True:
        doc = op.call("l4.flow.get", {"id": flow_id, "offset": offset, "limit": page})
        if not isinstance(doc, dict):
            raise ToolError(f"l4.flow.get: expected an object, got {type(doc).__name__}")
        got = doc.get("packets") or []
        out.extend(got)
        nxt = doc.get("next_offset")
        if not doc.get("truncated") or not isinstance(nxt, int) or nxt <= offset or not got:
            return out
        offset = nxt


def main() -> int:
    iface = loopback_interface()
    target = core = op = None
    cap_id = None
    try:
        section("arrange: the PATCHED target with its L4 speakers, and an L4-enabled core")
        target = ScanTarget("patched", l4=True)
        svc = target.service(SERVICE)
        ip, port = split_addr(svc["addr"])
        note(f"/services[{SERVICE}]", svc)
        expect(svc.get("proto") == "udp", f"{SERVICE} is the udp service the packet lane fuzzes", svc.get("proto"))
        expect(ip == "127.0.0.1", f"{SERVICE} listens on 127.0.0.1", ip)
        proto = str(svc.get("proto"))

        cfg = CoreConfig(
            proxy_port=free_port(),
            l4_enabled=True,
            l4_flags={},
            l4_scope_entries=[l4_inject_entry(), l4_capture_entry()],
        )
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        status = gate(op)
        note("l4.capture.status", {k: v for k, v in status.items() if k != "reason"})

        section("observer 1: start the operator's own loopback capture before a single case is sent")
        started_cap = op.confirm("l4.capture.start", {"interface": iface, "direction": "inbound"})
        cap_id = started_cap.get("flow_id") if isinstance(started_cap, dict) else None
        if not cap_id:
            fail(f"l4.capture.start returned no flow id: {started_cap!r}")
        expect(cap_id in (op.call("l4.flow.list") or []), "the capture flow is listed by l4.flow.list", cap_id)

        section("observer 2: clear the target's own L4 log")
        target.logs.reset()

        section(f"act: a bounded packet-lane job -- {CASES} cases, liveness every {LIVENESS_EVERY}")
        profile = {
            "lanes": ["l4_packet"],
            "target": {"origins": [], "l4": [{"ip": ip, "port": port, "proto": proto}]},
            "l4": {"cases": CASES, "liveness_every": LIVENESS_EVERY},
        }
        started = start_job(op, "operator", profile=profile, confirm=True)
        note("scan.start", started)
        skip_if_lane_skipped(started)
        job = started.get("job")
        expect(isinstance(job, str) and job.startswith("scan-"), "scan.start returned a job id", job)
        expect(started.get("dry_run") is False,
               "scan.start reports dry_run: false for this L4 job (design D3/D8.4)", started.get("dry_run"))
        expect("l4_packet" in ((started.get("lanes") or {}).get("run") or []),
               "the l4_packet lane is in lanes.run", started.get("lanes"))

        final = wait_terminal(op, "operator", job, timeout=600)
        note("scan.status (terminal)", {k: final.get(k) for k in ("state", "phase", "stopped_reason", "l4", "issues")})

        section("assert: the job finished done, clean, and inside its budget")
        expect(final.get("state") == "done", "the job finished `done`", final.get("state"))
        expect((final.get("issues") or {}).get("total") == 0,
               "zero issues on a healthy target", (final.get("issues") or {}).get("total"))
        l4 = final.get("l4") or {}
        expect(l4.get("cases") == CASES, f"status.l4.cases == {CASES}", l4.get("cases"))
        expect(l4.get("liveness_failures") == 0, "status.l4.liveness_failures == 0", l4.get("liveness_failures"))
        expect(l4.get("crashes") == 0, "status.l4.crashes == 0", l4.get("crashes"))
        expect(l4.get("retired_elements") == 0, "status.l4.retired_elements == 0", l4.get("retired_elements"))

        section("assert (observer 1): the kernel saw exactly the budgeted frames, all pinned to 127.0.0.1")
        note("l4.capture.stop", op.confirm("l4.capture.stop", {"id": cap_id}))
        running = (op.call("l4.capture.status") or {}).get("captures") or []
        expect(cap_id not in running, "the capture is no longer running after l4.capture.stop", running)
        cap_id_done, cap_id = cap_id, None
        packets = read_packets(op, cap_id_done)
        to_port = [p for p in packets if p.get("dst_port") == port]
        injected = [p for p in packets if p.get("injected") is True]
        note("capture", f"{len(packets)} packets total, {len(to_port)} to port {port}, "
                        f"{len(injected)} flagged injected")
        expect(len(to_port) >= CASES,
               f"the capture holds at least the {CASES} cases addressed to port {port}", len(to_port))
        expect(len(to_port) == EXPECTED_FRAMES,
               f"the capture holds exactly {EXPECTED_FRAMES} frames to port {port} "
               f"({CASES} cases + 1 baseline + {CASES // LIVENESS_EVERY} scheduled liveness probes)",
               len(to_port))
        stray_dst = sorted({str(p.get("dst")) for p in to_port if p.get("dst") != "127.0.0.1"})
        expect(not stray_dst, "every frame to the pinned port has dst 127.0.0.1", stray_dst)
        stray_injected = [{"dst": p.get("dst"), "dst_port": p.get("dst_port")} for p in injected
                          if p.get("dst") != "127.0.0.1" or p.get("dst_port") != port]
        expect(not stray_injected,
               "no injected frame addressed anything but the pinned 127.0.0.1:<port>", stray_injected[:5])

        section("assert (observer 2): the patched target never went down")
        log = target.logs.l4(SERVICE)
        note(f"/log/l4 {SERVICE}", {k: len(v) for k, v in log.items()})
        expect(log["downtime"] == [], f"{SERVICE} logged no downtime window", log["downtime"])
        expect(target.logs.downtime("l4-tlv-crash") == [],
               "l4-tlv-crash logged no downtime window either", target.logs.downtime("l4-tlv-crash"))
        note("messages the service parsed from the lane's frames (informational: header-field cases "
             "are dropped by the kernel before userland)", len(target.logs.messages(SERVICE, dir="in")))
    finally:
        if cap_id and op is not None:
            try:
                op.confirm("l4.capture.stop", {"id": cap_id})
            except (ToolError, BusError) as e:  # pragma: no cover - rig hygiene
                print(f"  [warn] could not stop the capture {cap_id}: {e}", flush=True)
        if op is not None:
            op.close()
        if core is not None:
            core.stop()
        if target is not None:
            target.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:8]))
    ok("PASS: the packet lane stayed inside its case budget, on its pinned destination, and left P healthy")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except FileNotFoundError as e:
        skip(f"a real binary this cell needs is missing: {e}")
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
