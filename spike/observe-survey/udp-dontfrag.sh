#!/bin/bash
# Research 12 §3.2.7 / DevForums 770707 mechanism check: does setsockopt(IP_DONTFRAG) (and a send)
# on a CONNECTED UDP socket fail with ECONNRESET while the transparent proxy is active?
tag=${1:-run}
out=/tmp/claude/ne-survey/dontfrag-$tag.out
exec > >(tee "$out") 2>&1
echo "== $(date) tag=$tag =="
systemextensionsctl list 2>&1 | grep -E 'aitmproxy.ne.*activated'
python3 -I - <<'PY'
import socket, errno, time
IP_DONTFRAG = 28          # <netinet/in.h> on macOS
IPV6_DONTFRAG = 62
def trial(label, family, addr, dontfrag=True, send=True):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    res = []
    try:
        s.connect(addr); res.append("connect ok")
    except OSError as e:
        res.append(f"connect {errno.errorcode.get(e.errno, e.errno)}")
    if dontfrag:
        try:
            if family == socket.AF_INET: s.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG, 1)
            else: s.setsockopt(socket.IPPROTO_IPV6, IPV6_DONTFRAG, 1)
            res.append("setsockopt(DONTFRAG) ok")
        except OSError as e:
            res.append(f"setsockopt(DONTFRAG) {errno.errorcode.get(e.errno, e.errno)}")
    if send:
        try:
            s.send(b"\x00" * 64); res.append("send ok")
        except OSError as e:
            res.append(f"send {errno.errorcode.get(e.errno, e.errno)}")
        try:
            s.send(b"\x00" * 64); res.append("send2 ok")
        except OSError as e:
            res.append(f"send2 {errno.errorcode.get(e.errno, e.errno)}")
    s.close()
    print(f"  {label:34s} {' | '.join(res)}")
print("-- IPv4, connected UDP sockets --")
trial("cloudflare-quic 104.18.27.14:443", socket.AF_INET, ("104.18.27.14", 443))
trial("same, no DONTFRAG", socket.AF_INET, ("104.18.27.14", 443), dontfrag=False)
trial("google quic 142.250.73.110:443", socket.AF_INET, ("142.250.73.110", 443))
trial("1.1.1.1:53 (DNS)", socket.AF_INET, ("1.1.1.1", 53))
trial("LAN resolver 10.9.10.1:53", socket.AF_INET, ("10.9.10.1", 53))
trial("time.apple.com 17.253.16.125:123", socket.AF_INET, ("17.253.16.125", 123))
trial("loopback 127.0.0.1:443", socket.AF_INET, ("127.0.0.1", 443))
print("-- IPv6 --")
try: trial("cloudflare v6 [2606:4700::6812:1b0e]:443", socket.AF_INET6, ("2606:4700::6812:1b0e", 443))
except Exception as e: print("  v6 trial error", e)
print("-- real DNS query over a CONNECTED UDP socket WITH DONTFRAG (does a reply arrive?) --")
import struct, random
def dnsq(name):
    tid = random.randrange(65536)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."): q += bytes([len(part)]) + part.encode()
    return q + b"\x00\x00\x01\x00\x01"
for server in ("1.1.1.1", "10.9.10.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.connect((server, 53))
    try: s.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG, 1); df = "DONTFRAG set"
    except OSError as e: df = f"DONTFRAG {errno.errorcode.get(e.errno, e.errno)}"
    t0 = time.time()
    try:
        s.send(dnsq("example.com")); r = s.recv(512); print(f"  {server}: {df}; reply {len(r)} bytes in {1000*(time.time()-t0):.0f} ms")
    except OSError as e: print(f"  {server}: {df}; {errno.errorcode.get(e.errno, e.errno) if e.errno else e}")
    s.close()
PY
echo "DONTFRAG DONE"
