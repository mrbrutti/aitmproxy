"""Proxy-surface helpers layered on the shared aitm_e2e lib.

The TLS-MITM curl client and the raw RFC6455 WebSocket client were folded from
this file into aitm_e2e.tls / aitm_e2e.ws; they are re-exported below so this
surface's scenarios keep a single import and there is one definition to maintain.
What stays here is what the shared lib does not carry: the node HTTP/2 upstream
(needs h2_upstream.mjs beside this file), a ProxyConfig that defaults ssl_insecure
on for the self-signed TLS echo origins, and the bus ground-truth helpers the
proxy assertions read.
"""

from __future__ import annotations

import base64
import dataclasses
import os
import subprocess
import time

from aitm_e2e.config import CoreConfig
from aitm_e2e.tls import (  # noqa: F401  re-exported for this surface's scenarios
    ca_cert,
    curl,
    curl_http_version,
    have,
    new_ca_dir,
    start_https_echo,
    upstream_cert,
)
from aitm_e2e.ws import (  # noqa: F401  re-exported for this surface's scenarios
    WsClient,
    WsEchoServer,
    ws_accept,
    ws_encode,
    ws_read_frame,
)

PROXY_DIR = os.path.dirname(os.path.abspath(__file__))
H2_UPSTREAM_JS = os.path.join(PROXY_DIR, "h2_upstream.mjs")


@dataclasses.dataclass
class ProxyConfig(CoreConfig):
    # ssl_insecure + ca_dir live on CoreConfig and are emitted by its to_yaml; this
    # surface only flips the ssl_insecure default on (its upstreams are self-signed).
    ssl_insecure: bool = True


# ---------------------------------------------------------------------------
# node HTTP/2 + HTTP/1.1 upstream (node ships a real http2 server; stdlib doesn't)
# ---------------------------------------------------------------------------
def start_h2_upstream(crt: str, key: str, port: int):
    proc = subprocess.Popen(["node", H2_UPSTREAM_JS, crt, key, str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(100):
        line = proc.stdout.readline()
        if b"listening" in line:
            return proc
        if proc.poll() is not None:
            raise RuntimeError("h2 upstream exited: " + line.decode("utf-8", "replace"))
    raise RuntimeError("h2 upstream did not come up")


# ---------------------------------------------------------------------------
# bus ground-truth helpers (over aitm_e2e BusClient)
# ---------------------------------------------------------------------------
def _flow_ids(result) -> list:
    if isinstance(result, dict):
        for key in ("flows", "ids", "items"):
            if key in result:
                result = result[key]
                break
    if isinstance(result, list):
        return [i.get("id", i) if isinstance(i, dict) else i for i in result]
    return []


def find_flow(bus, path=None, kind=None, pred=None, tries=120, delay=0.05):
    """Poll flow.list/flow.get until a flow matching the criteria appears; return
    its id. Capture lands a beat after the client sees the body, so ground-truth
    lookups must poll rather than read once."""
    for _ in range(tries):
        ok, ids = bus.try_call("flow.list")
        if ok:
            for fid in reversed(_flow_ids(ids)):
                ok2, s = bus.try_call("flow.get", {"id": fid})
                if not ok2 or not isinstance(s, dict):
                    continue
                if path is not None and s.get("path") != path:
                    continue
                if kind is not None and s.get("kind") != kind:
                    continue
                if pred is not None and not pred(s):
                    continue
                return fid
        time.sleep(delay)
    return None


def detail(bus, fid, body="inline"):
    ok, d = bus.try_call("flow.detail", {"id": fid, "body": body})
    return d if ok and isinstance(d, dict) else None


def req_headers(d) -> dict:
    return {k.lower(): v for k, v in d.get("request", {}).get("headers", [])}


def resp_headers(d) -> dict:
    return {k.lower(): v for k, v in d.get("response", {}).get("headers", [])}


def _b64(v) -> bytes:
    return base64.b64decode(v) if v else b""


def resp_body(d) -> bytes:
    return _b64(d.get("response", {}).get("body"))


def req_body(d) -> bytes:
    return _b64(d.get("request", {}).get("body"))


def wait_for(fn, tries=80, delay=0.1):
    for _ in range(tries):
        v = fn()
        if v:
            return v
        time.sleep(delay)
    return None
