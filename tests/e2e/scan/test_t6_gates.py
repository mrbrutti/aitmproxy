#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=l4
"""scan/t6_gates -- AC T6-5: every L4 stream gate refuses BEFORE a socket is
opened, and the fully authorised configuration starts.

Five sub-cases, each on its own REAL core, all pointed at the same REAL seeded
speaker `l4-tlv-crash` (`aitm-testtarget-serve --l4`), and each asserted on the
parent-spec-D3 error code (`scan: <code>: <message>`, parsed by
`scan_error_code`):

  (a) `l4.enabled: false`                                     -> `refused_l4`
  (b) `l4.enabled: true`, no `Inject` scope entry             -> `out_of_scope`
  (c) an AGENT with `scanner.allow_agent_l4_fuzz` but without
      `l4.allow_agent_inject`, and the mirror                 -> `refused_l4`
  (d) a profile naming only a lane whose crate returns `None` -> `lane_unavailable`
  (e) `l4.enabled: true` + an entry `interface: "*"`, `direction: outbound`,
      the target CIDR/port and `Inject`, with both agent flags set: the same
      job STARTS (`dry_run == False`) and is then cancelled.

The INDEPENDENT observer is the speaker's own accept log: after (a) to (d),
`/log/l4` for `l4-tlv-crash` must still show `accepts == []` and
`messages == []` -- the refusals happened in the engine, not after a connect.

`scanner:` is a `deny_unknown_fields` section: a core that predates it FAILS
TO BOOT with it, so the verb probe runs on a core WITHOUT the section first
(plan note, 2026-11-01), and `require_lane` runs on the `l4.enabled: true`
core so a disabled L4 layer cannot be mistaken for a missing lane.

SKIPs 77: missing `scan.*` verbs; no `l4_stream` check in `scan.checks`.
Sub-case (d) prints a note and continues when every candidate lane is live on
the build (the skip cannot be provoked there).

Exit 0 pass / 1 fail / 77 skip. Never prints a token.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig, ScannerSection, l4_inject_entry  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    cancel,
    require_lane,
    require_verbs,
    scan_call,
    scan_error_code,
    scan_try,
    start_job,
    wait_terminal,
)

SERVICE = "l4-tlv-crash"
GRAMMAR = "tlv"
VERBS = ("scan.start", "scan.status", "scan.cancel", "scan.checks")
DEAD_LANE_CANDIDATES = ("l4_packet", "ws")


def boot(**kw) -> Aitm:
    """One core on free ports with the given L4 / scanner configuration."""
    return Aitm.server(CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(), **kw))


def endpoint(target: ScanTarget) -> dict:
    row = target.service(SERVICE)
    host, _, port = str(row["addr"]).rpartition(":")
    return {"ip": host, "port": int(port), "proto": row["proto"], "grammar": GRAMMAR}


def stream_args(target: ScanTarget, lanes: list[str] | None = None) -> dict:
    """`scan.start` arguments for the stream job every sub-case tries."""
    overrides: dict = {"target": {"l4": [endpoint(target)]}}
    if lanes is not None:
        overrides["lanes"] = lanes
    return {"profile_name": "l4-stream-safe", "overrides": overrides}


def refusal_code(client: BusClient, role: str, args: dict) -> tuple[str, object]:
    """`scan.start` through `scan_try`, answering the operator confirm prompt if
    one comes back first, and returning (code, payload). `code` is the parsed
    `scan: <code>:` token, `"ok"` when the call succeeded, or `"?"` when the
    error text is not in the `scan:` form."""
    status, payload = scan_try(client, role, "scan.start", args)
    if status == "ok" and isinstance(payload, dict) and payload.get("status") == "needs_confirmation":
        token = payload.get("confirm_token")
        if not token:
            return ("?", "needs_confirmation without a confirm_token")
        status, payload = scan_try(client, role, "scan.start", dict(args, _confirm=token))
    if status == "ok":
        return ("ok", payload)
    return (scan_error_code(str(payload)) or "?", payload)


def dead_lane(checks: list[dict]) -> str | None:
    """The first of `l4_packet`, `ws` that no check in the catalogue lists."""
    live = {lane for c in checks for lane in (c.get("lanes") or [])}
    return next((lane for lane in DEAD_LANE_CANDIDATES if lane not in live), None)


def main() -> int:
    vuln = core = op = ag = None
    try:
        section("1. the seeded TLV speaker (the observer for every sub-case)")
        vuln = ScanTarget("vulnerable", l4=True)
        ep = endpoint(vuln)
        ok(f"{SERVICE} on {ep['ip']}:{ep['port']} ({ep['proto']}), grammar {GRAMMAR}")
        vuln.logs.reset()

        # ---------------------------------------------------------------
        section("2. (a) l4.enabled: false -> refused_l4")
        # Also the verb probe: this core carries no `scanner:` section, so it
        # boots on a build that predates it.
        core = boot(l4_enabled=False)
        op = BusClient.operator(core)
        require_verbs(op, *VERBS)
        code, payload = refusal_code(op, "operator", stream_args(vuln))
        check(code == "refused_l4",
              f"(a) a stream job on a core with l4.enabled false is `refused_l4` "
              f"(got {code!r}: {payload!r})")
        op.close()
        op = None
        core.stop()
        core = None

        # ---------------------------------------------------------------
        section("3. (b) l4.enabled: true with no Inject scope entry -> out_of_scope")
        core = boot(l4_enabled=True)
        op = BusClient.operator(core)
        # The lane probe runs here: the L4 layer is on, so an absent
        # `l4_stream` check means the lane itself has not landed.
        require_lane(op, "l4_stream")
        ok("the core advertises an l4_stream check")
        code, payload = refusal_code(op, "operator", stream_args(vuln))
        check(code == "out_of_scope",
              f"(b) a stream job with no Inject entry covering the target is `out_of_scope` "
              f"(got {code!r}: {payload!r})")

        # ---------------------------------------------------------------
        section("4. (d) a lane with no scan.checks entries -> lane_unavailable")
        checks = (scan_call(op, "operator", "scan.checks", {}) or {}).get("checks") or []
        lane = dead_lane(checks)
        if lane is None:
            print(f"  [note] every candidate lane {list(DEAD_LANE_CANDIDATES)} is live on this "
                  "build; the lane_unavailable sub-case cannot be provoked", flush=True)
        else:
            code, payload = refusal_code(op, "operator", stream_args(vuln, lanes=[lane]))
            check(code == "lane_unavailable",
                  f"(d) a profile naming only the unavailable lane {lane!r} is "
                  f"`lane_unavailable` (got {code!r}: {payload!r})")
        op.close()
        op = None
        core.stop()
        core = None

        # ---------------------------------------------------------------
        section("5. (c) the agent flags, both halves -> refused_l4")
        for label, flags, fuzz in (
            ("scanner.allow_agent_l4_fuzz without l4.allow_agent_inject", {}, True),
            ("l4.allow_agent_inject without scanner.allow_agent_l4_fuzz",
             {"allow_agent_inject": True}, False),
        ):
            core = boot(
                l4_enabled=True,
                l4_flags=flags,
                l4_scope_entries=[l4_inject_entry()],
                scanner=ScannerSection(allow_agent_active=True, allow_agent_l4_fuzz=fuzz),
            )
            op = BusClient.operator(core)
            op.confirm("agent.set", {"policy": "all"})
            ag = BusClient.agent(core)
            code, payload = refusal_code(ag, "agent", stream_args(vuln))
            check(code == "refused_l4",
                  f"(c) an agent with {label} is `refused_l4` (got {code!r}: {payload!r})")
            ag.close()
            ag = None
            op.close()
            op = None
            core.stop()
            core = None

        # ---------------------------------------------------------------
        section("6. the observer: the speaker saw nothing at all during (a) to (d)")
        entry = vuln.logs.l4(SERVICE)
        check(entry["accepts"] == [],
              f"{SERVICE} accepted no connection during the refused sub-cases "
              f"(got {len(entry['accepts'])})")
        check(entry["messages"] == [],
              f"{SERVICE} received no message during the refused sub-cases "
              f"(got {len(entry['messages'])})")

        # ---------------------------------------------------------------
        section("7. (e) the fully authorised configuration starts the same job")
        core = boot(
            l4_enabled=True,
            l4_flags={"allow_agent_inject": True},
            l4_scope_entries=[l4_inject_entry()],  # interface "*", outbound, inject
            scanner=ScannerSection(allow_agent_active=True, allow_agent_l4_fuzz=True),
        )
        op = BusClient.operator(core)
        started = start_job(
            op, "operator",
            profile_name="l4-stream-safe",
            overrides={"target": {"l4": [endpoint(vuln)]}},
            confirm=True,
        )
        job = started.get("job")
        check(isinstance(job, str) and job != "",
              f"(e) scan.start returned a job id (got {job!r})")
        check(started.get("dry_run") is False,
              f"(e) the started L4 job reports dry_run false (got {started.get('dry_run')!r})")
        check((started.get("lanes") or {}).get("run") == ["l4_stream"],
              f"(e) the job runs the l4_stream lane (got {(started.get('lanes') or {}).get('run')!r})")
        cancelled = cancel(op, "operator", job)
        check(cancelled.get("state") in {"cancelling", "cancelled"},
              f"(e) scan.cancel moved the job to cancelling/cancelled "
              f"(got {cancelled.get('state')!r})")
        final = wait_terminal(op, "operator", job, timeout=60.0)
        check(final.get("state") == "cancelled",
              f"(e) the job settled as `cancelled` (got {final.get('state')!r})")
    finally:
        for c in (ag, op):
            if c:
                c.close()
        if core:
            core.stop()
        if vuln:
            vuln.stop()

    ok("T6-5: refused_l4, out_of_scope, agent flags, lane_unavailable -- no socket opened; "
       "the authorised job started and cancelled")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
