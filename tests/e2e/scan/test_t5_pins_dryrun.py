#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=l4 serial
"""scan/t5_pins_dryrun -- AC T5-3: the packet lane's non-fuzzable pins, and a dry run that
sends nothing (scanner v2 design AC 28 / D8.4; T10 plan task B10).

Two guarantees, both asserted against what really happened on the wire:

  * PINS. `dst`, `dst_port`, `interface`, `ether.src/dst`, `ipv4.src` / `ipv6.src` are
    non-fuzzable by construction (scapy's rule; source spoofing is refused). A profile
    naming `ipv4.src` or `dst` as a fuzz field is refused with the error code
    `invalid_profile` -- and no job is created, so nothing is sent.
  * DRY RUN. `l4.dry_run: true` renders cases and sends nothing: `scan.start` reports
    `dry_run: true`, the job still finishes `done`, and the two observers below see
    exactly zero traffic.

Observers -- both independent of the scanner:
  1. the KERNEL, through the operator's own capture started BEFORE any job runs
     (`l4.capture.start` on the loopback interface, read back with `l4.flow.get`): zero
     packets addressed to the target port.
  2. the TARGET's own control-origin L4 log (`/log/l4`): `messages == []` and
     `downtime == []` for the service -- it never heard a datagram.
No fixture: a real `aitm` core, a real `aitm-testtarget-serve`, a real capture.

SKIP (77) conditions, each naming the missing thing:
  * the serve binary or the `aitm` binary is absent;
  * the core does not advertise the `scan.*` verbs this cell calls (pre-T1b core);
  * `scan.checks` lists no check for the `l4_packet` lane (the T5 lane is not on this build);
  * the L4 module is not enabled on the core (no `l4.capture.status`);
  * `l4.capture.status` says `available: false` -- the packet lane needs raw pcap privilege
    (macOS: read+write on /dev/bpf*, e.g. ChmodBPF; Linux: CAP_NET_RAW). On Matt's Mac
    /dev/bpf* is root-only, so this cell SKIPs there with the core's own `reason`;
  * the core accepted the dry-run job but reported the `l4_packet` lane as skipped.

serial: it runs a privileged loopback capture. Exit 0 / 1 / 77. Never prints a token.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig, l4_capture_entry, l4_inject_entry  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (ScanTarget, require_lane, require_verbs, scan_error_code,  # noqa: E402
                           scan_try, start_job, wait_terminal)

SERVICE = "l4-udp-payload-crash"
PINNED_FIELDS = ("ipv4.src", "dst")
DRY_RUN_CASES = 50
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
    `l4_packet` lane in `scan.checks`, the L4 module, and raw capture privilege."""
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


def packet_profile(ip: str, port: int, l4_opts: dict) -> dict:
    return {
        "lanes": ["l4_packet"],
        "target": {"origins": [], "l4": [{"ip": ip, "port": port, "proto": "udp"}]},
        "l4": dict(l4_opts),
    }


def try_start(op, profile: dict) -> tuple[str, object]:
    """`scan.start` at operator through `scan_try` (so the refusal lands in the verb
    ledger), following the operator `_confirm` handshake when the core offers one: an L4
    profile is confirmable, and the refusal must survive the confirmation, not hide behind
    it. Returns ('ok', result) | ('error', message)."""
    args = {"profile": profile}
    status, payload = scan_try(op, "operator", "scan.start", args)
    if status == "ok" and isinstance(payload, dict) and payload.get("status") == "needs_confirmation":
        token = payload.get("confirm_token")
        if not token:
            fail(f"scan.start asked for confirmation without a confirm_token: {payload!r}")
        status, payload = scan_try(op, "operator", "scan.start", dict(args, _confirm=token))
    return status, payload


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
        section("arrange: the vulnerable target with its L4 speakers, and an L4-enabled core")
        target = ScanTarget("vulnerable", l4=True)
        svc = target.service(SERVICE)
        ip, port = split_addr(svc["addr"])
        note(f"/services[{SERVICE}]", svc)

        cfg = CoreConfig(
            proxy_port=free_port(),
            l4_enabled=True,
            l4_flags={},
            l4_scope_entries=[l4_inject_entry(), l4_capture_entry()],
        )
        core = Aitm.server(cfg)
        op = BusClient.operator(core)
        gate(op)

        section("observer 1: a capture that is running before any job is started")
        started_cap = op.confirm("l4.capture.start", {"interface": iface, "direction": "inbound"})
        cap_id = started_cap.get("flow_id") if isinstance(started_cap, dict) else None
        if not cap_id:
            fail(f"l4.capture.start returned no flow id: {started_cap!r}")

        section("observer 2: clear the target's own L4 log")
        target.logs.reset()

        section("T5-3 pins: a profile naming a non-fuzzable field is refused with invalid_profile")
        for field in PINNED_FIELDS:
            profile = packet_profile(ip, port, {"cases": 10, "fields": [field]})
            status, payload = try_start(op, profile)
            note(f"scan.start with fields: [{field!r}]", payload)
            expect(status == "error", f"a profile fuzzing `{field}` is refused", payload)
            code = scan_error_code(str(payload)) if status == "error" else None
            expect(code == "invalid_profile",
                   f"the refusal of `{field}` carries the error code invalid_profile", code)
            if status == "error":
                expect(field in str(payload), f"the refusal names the offending field `{field}`", payload)

        section("T5-3 dry run: scan.start reports dry_run: true and the job sends nothing")
        dry = packet_profile(ip, port, {"dry_run": True, "cases": DRY_RUN_CASES})
        started = start_job(op, "operator", profile=dry, confirm=True)
        note("scan.start (dry run)", started)
        for entry in (started.get("lanes") or {}).get("skipped") or []:
            if entry.get("lane") == "l4_packet":
                skip(f"the core skipped the l4_packet lane for the dry-run job: {entry.get('reason')}")
        job = started.get("job")
        expect(started.get("dry_run") is True, "scan.start reports dry_run: true", started.get("dry_run"))
        if not isinstance(job, str):
            fail(f"scan.start (dry run) returned no job id: {started!r}")

        final = wait_terminal(op, "operator", job, timeout=600)
        note("scan.status (dry run, terminal)",
             {k: final.get(k) for k in ("state", "phase", "stopped_reason", "l4", "issues")})
        expect(final.get("state") == "done", "the dry-run job finished `done`", final.get("state"))
        expect((final.get("issues") or {}).get("total") == 0,
               "a dry run reports no issues", (final.get("issues") or {}).get("total"))
        note("status.l4 after the dry run (cases rendered, not sent)", final.get("l4"))

        section("assert (observer 1): the kernel saw not one packet to the target port")
        note("l4.capture.stop", op.confirm("l4.capture.stop", {"id": cap_id}))
        running = (op.call("l4.capture.status") or {}).get("captures") or []
        expect(cap_id not in running, "the capture is no longer running after l4.capture.stop", running)
        cap_id_done, cap_id = cap_id, None
        packets = read_packets(op, cap_id_done)
        to_port = [p for p in packets if p.get("dst_port") == port]
        note("capture", f"{len(packets)} packets total, {len(to_port)} to port {port}")
        expect(len(to_port) == 0,
               f"the capture holds 0 packets addressed to port {port} (pins refused, dry run sent nothing)",
               [{"dst": p.get("dst"), "dst_port": p.get("dst_port"), "proto": p.get("proto")}
                for p in to_port[:5]])

        section("assert (observer 2): the target never heard a datagram")
        log = target.logs.l4(SERVICE)
        note(f"/log/l4 {SERVICE}", {k: len(v) for k, v in log.items()})
        expect(log["messages"] == [], f"{SERVICE} logged no message", log["messages"][:3])
        expect(log["downtime"] == [], f"{SERVICE} logged no downtime window", log["downtime"])
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
    ok("PASS: the non-fuzzable pins are refused with invalid_profile and a dry run puts nothing on the wire")
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
