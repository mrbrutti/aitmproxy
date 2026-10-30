"""aitm_e2e — the shared harness for aitmproxy's real end-to-end test suite.

Every scenario boots a REAL `aitm` core, drives REAL traffic, and asserts on an
INDEPENDENT observer (the upstream echo-record server, a real client, the bound
socket) — never a fixture, and never a frozen expectation. See tests/e2e/README.md.

A scenario is a plain Python script that imports from here, does arrange -> act ->
assert, and signals its result by EXIT CODE:

    0   PASS
    77  SKIP  (print a one-line reason first; e.g. a missing real dependency)
    any other  FAIL

The helpers below (`ok`, `fail`, `skip`, `section`, `check`) wrap that contract.
"""

from __future__ import annotations

import os
import socket
import sys
from contextlib import closing

SKIP_EXIT = 77

__all__ = [
    "SKIP_EXIT",
    "free_port",
    "section",
    "ok",
    "fail",
    "skip",
    "check",
    "is_manual",
    "pause",
    "repo_root",
]


def repo_root() -> str:
    """Absolute path to the repository root (tests/e2e/aitm_e2e/ -> repo)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def free_port() -> int:
    """A currently-free loopback TCP port. Small TOCTOU window; fine for tests."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def section(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


def ok(msg: str) -> None:
    print(f"  [ok] {msg}", flush=True)


def fail(msg: str) -> "None":
    """Print a FAIL line and exit non-zero (the runner reads the exit code)."""
    print(f"  [FAIL] {msg}", flush=True)
    sys.exit(1)


def skip(reason: str) -> "None":
    """Print a one-line reason and exit 77 (a loud, non-green SKIP)."""
    print(f"  [SKIP] {reason}", flush=True)
    sys.exit(SKIP_EXIT)


def check(cond: bool, msg: str) -> None:
    """Assert on a real outcome: ok(msg) if true, else fail(msg)."""
    if cond:
        ok(msg)
    else:
        fail(msg)


def is_manual() -> bool:
    """True when the runner was invoked with --manual (operator present)."""
    return os.environ.get("AITM_E2E_MANUAL") == "1"


def pause(instruction: str) -> None:
    """A manual step: show `instruction` and wait for the operator to press Enter.

    Only valid under --manual (is_manual()); a scenario that needs a human must
    tag itself `# e2e: tier=manual` and the runner skips it unless --manual.
    """
    if not is_manual():
        skip(f"manual step requires --manual: {instruction}")
    print(f"\n  >>> MANUAL: {instruction}\n  >>> press Enter when done ...", flush=True)
    try:
        input()
    except EOFError:
        fail("manual step needs an interactive operator but stdin is closed")
