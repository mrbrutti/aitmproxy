"""Send a real HTTP/1.1 request THROUGH the aitm proxy (absolute-URI form).

This is a real external client hitting the proxy's listen port, exactly as a
browser configured with aitm as its HTTP proxy would — so the request lands in
the flow store as a captured flow. (HTTPS MITM via CONNECT + --cacert is a later
scenario; this is the basic HTTP capture path.)
"""

from __future__ import annotations

import http.client
from urllib.parse import urlparse


class ProxyResponse:
    def __init__(self, status: int, headers: dict, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def via_proxy(proxy_port: int, method: str, url: str,
              headers: dict | None = None, body: bytes | None = None,
              timeout: float = 15.0) -> ProxyResponse:
    u = urlparse(url)
    authority = u.netloc
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=timeout)
    # The request-target is the absolute URI (proxy form); Host names the upstream.
    hdrs = {"Host": authority}
    if headers:
        hdrs.update(headers)
    try:
        conn.request(method, url, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return ProxyResponse(resp.status, dict(resp.getheaders()), data)
    finally:
        conn.close()
