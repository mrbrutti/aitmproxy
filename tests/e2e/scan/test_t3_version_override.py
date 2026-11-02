#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""AC T3-2: `http.version` forces the wire protocol, and a forced `h2` against an
h1-only listener errors every probe instead of failing the job.

Arrange: a real `aitm-testtarget-serve` V with both TLS listeners (T10 child spec
D1: `tls` offers ALPN `h2, http/1.1`; `tls_h1` offers `http/1.1` only), a real core
with `ssl_insecure: true` and the target's authorities in scope.

Act + assert, two jobs:
  1. `scan.start { target: <tls base>, overrides: { http: { version: "h1" } } }`
     -> every `request` entry the target logged since the reset has
     `version == "h1"` and every `tls_handshake` since has `alpn == "http/1.1"`:
     the override beat the listener's h2 offer.
  2. `scan.start { target: <tls_h1 base>, overrides: { http: { version: "h2" },
     crawl: { use_browser: "never" } } }` -> `wait_terminal` ends `state: "done"`
     (never `failed`), `stopped_reason == "errors"`, `"h2_not_negotiated"` in
     `status["error"]`, `probes.errors > 0`, and the target logged only
     `tls_handshake` entries (all `alpn == "http/1.1"`) and zero HTTP requests.

Observer, independent of the scanner: the target's control origin `GET /log/http`
(`version`, `alpn`, and the absence of `request` entries). No fixture.

SKIP 77 when: no `scan.*` verbs, no `http` lane in `scan.checks`, or the target
started no TLS listener. The reason names the missing thing.
"""

import sys
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    boot_target,
    require_checks,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)

JOB_TIMEOUT = 600.0


def since(entries, seq: int) -> list:
    return [e for e in entries if int(e.get("seq", 0)) > seq]


def main() -> None:
    with boot_target("vulnerable") as v:
        if not v.tls_base or not v.tls_h1_base:
            skip("the test target started no tls / tls_h1 listener (needs --tls-port and "
                 "--tls-h1-port; T10 child spec D1)")
        cfg = CoreConfig(
            proxy_port=free_port(),
            ssl_insecure=True,
            scope_entries=[v.tls_authority, v.tls_h1_authority, v.authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status")
            require_lane(op, "http")
            # The override is observable only through T3's HttpSender, which lands
            # with its native checks (sqli-boolean is one of them): skip until then.
            require_checks(op, "sqli-boolean", needs="needs T3 PR 2 (HttpSender wiring)")

            section("http.version: h1 forces h1 on a listener that offers h2")
            seq0 = v.logs.reset()
            job1 = start_job(op, "operator", target=v.tls_base,
                             overrides={"http": {"version": "h1"}})["job"]
            st1 = wait_terminal(op, "operator", job1, timeout=JOB_TIMEOUT)
            ok(f"job 1 ended state={st1.get('state')!r} stopped_reason={st1.get('stopped_reason')!r}")

            entries1 = since(v.logs.http(), seq0)
            reqs1 = [e for e in entries1 if e.get("kind") == "request"]
            hs1 = [e for e in entries1 if e.get("kind") == "tls_handshake"]
            versions1 = sorted({e.get("version") for e in reqs1})
            alpns1 = sorted({e.get("alpn") for e in hs1})
            check(len(reqs1) > 0, f"the forced-h1 job reached the target ({len(reqs1)} requests logged)")
            check(versions1 == ["h1"],
                  f"every logged request is version h1 (observed versions {versions1})")
            check(len(hs1) > 0 and alpns1 == ["http/1.1"],
                  f"every TLS handshake negotiated http/1.1 (observed alpns {alpns1}, "
                  f"{len(hs1)} handshakes)")

            section("http.version: h2 against the h1-only listener errors every probe")
            seq1 = v.logs.reset()
            job2 = start_job(op, "operator", target=v.tls_h1_base,
                             overrides={"http": {"version": "h2"},
                                        "crawl": {"use_browser": "never"}})["job"]
            st2 = wait_terminal(op, "operator", job2, timeout=JOB_TIMEOUT)
            error_text = st2.get("error") or ""
            probes2 = st2.get("probes") or {}
            check(st2.get("state") == "done",
                  f"the job ended state 'done', not a job failure (state={st2.get('state')!r})")
            check(st2.get("stopped_reason") == "errors",
                  f"stopped_reason is 'errors' (observed {st2.get('stopped_reason')!r})")
            check("h2_not_negotiated" in error_text,
                  f"status.error names h2_not_negotiated (observed {error_text[:120]!r})")
            check(probes2.get("errors", 0) > 0,
                  f"probes.errors counted the sender errors (observed {probes2.get('errors')!r})")

            entries2 = since(v.logs.http(), seq1)
            reqs2 = [e for e in entries2 if e.get("kind") == "request"]
            hs2 = [e for e in entries2 if e.get("kind") == "tls_handshake"]
            alpns2 = sorted({e.get("alpn") for e in hs2})
            kinds2 = sorted({e.get("kind") for e in entries2})
            check(len(hs2) > 0, f"the target saw TLS handshakes ({len(hs2)})")
            check(kinds2 == ["tls_handshake"],
                  f"the target logged only tls_handshake entries (kinds {kinds2})")
            check(alpns2 == ["http/1.1"],
                  f"every handshake negotiated http/1.1 (observed {alpns2})")
            check(len(reqs2) == 0,
                  f"the target served zero HTTP requests under forced h2 (observed {len(reqs2)})")

            ok("T3-2: h1 is forced on an h2 listener; forced h2 on an h1-only listener "
               "errors every probe and ends the job done/errors")


if __name__ == "__main__":
    main()
