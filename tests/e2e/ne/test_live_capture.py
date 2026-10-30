#!/usr/bin/env python3
# e2e: surface=ne tier=manual
"""The macOS Network Extension LIVE capture gate (Task 18, NE-AC16/AC17/AC5).

Proves a real in-scope flow is captured by the signed system extension and shown in
ALL THREE UIs reading the same core (macOS app + `aitm web` + `aitm tui`), with the
only manual step being the two unavoidable System Settings approval clicks (Apple
requires a human). `tier=manual`: the runner skips this unless invoked with --manual.

Prerequisites (HELD until Task 18): a signed + notarized NE build installed in
/Applications, and the core-side rendezvous writer + scope-spec emitter. Until those
exist the suite SKIPs loudly with the exact reason — a SKIP stays green, never red.
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, pause, section, skip  # noqa: E402

APP = "/Applications/Aitmproxy.app"
SYSEX_ID = "com.mrbrutti.aitmproxy.ne"


def sysex_row() -> str:
    """The `systemextensionsctl list` line for our sysex, or '' if absent."""
    try:
        out = subprocess.run(
            ["systemextensionsctl", "list"], capture_output=True, text=True, check=False
        ).stdout
    except OSError:
        return ""
    return next((ln for ln in out.splitlines() if SYSEX_ID in ln), "")


def main() -> int:
    section("prerequisites (Task 18): a signed NE build must be installed")
    if sys.platform != "darwin":
        skip("macOS-only")
    if not os.path.isdir(APP):
        skip(f"no signed NE build installed at {APP} (build.sh is Task 18)")
    if not os.path.isdir(os.path.join(APP, "Contents/Library/SystemExtensions", f"{SYSEX_ID}.systemextension")):
        skip("app installed but no embedded sysex (not an NE build)")

    section("the two unavoidable System Settings approvals (human required)")
    pause(
        "In System Settings -> General -> Login Items & Extensions -> Network Extensions (i), "
        "enable 'AitmproxyNE' and authenticate; then on the 'Aitmproxy would like to Add Proxy "
        "Configurations' prompt, click Allow."
    )
    check("activated enabled" in sysex_row(),
          f"systemextensionsctl shows the sysex [activated enabled] (row: {sysex_row()!r})")

    # --- Task-18 live cross-UI capture (wire up when the core-side rendezvous writer +
    #     scope-spec emitter land; see the plan Task 18 pass conditions 1-5):
    #       core = Aitm.web(CoreConfig(proxy_port=..., scope_entries=[target],
    #                                  l4_enabled=True, l4_flags={...}))   # aitm_e2e.core / .config
    #       drive a real in-scope HTTPS flow + a UDP flow through an independent observer
    #       assert the flow appears over the bus (BusClient.agent + .operator), in `aitm web`,
    #         and in `aitm tui` — the same core, all three UIs
    #       assert out-of-scope traffic is NOT captured
    #       assert core stopped -> ordinary browsing is unaffected (fail-open, NE-AC5)
    #       assert the extension process holds NO CA key (codesign / memory inspection)
    skip(
        "live cross-UI capture not yet wired: needs the core-side rendezvous writer + "
        "scope-spec emitter (Task 18 deps). The sysex is approved; the capture + cross-UI "
        "assertions are the remaining Task-18 work."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
