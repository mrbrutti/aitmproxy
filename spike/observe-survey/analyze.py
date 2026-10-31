#!/usr/bin/env python3 -I
"""Analyse NE framework per-flow log lines and SURVEY lines from the observe-survey variant.

usage: analyze.py framework <dump.log>     per-hour/min/sec rates, field survey from the framework's own lines
       analyze.py survey    <dump.log>     SURVEY k=.. lines: field survey + timing percentiles
"""
import re
import sys
from collections import Counter, defaultdict

TS = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})")
NEWFLOW = re.compile(
    r"New flow: NEFlow type = (\w+), app = ([^,]*), name = ([^,]*), (\S+) <-> (\S+), filter_id = ([^,]*), interface = (\S*)"
)
CALLING = re.compile(r"Calling (handleNew\w+) with (TCP|UDP) (\S*?)\[\{length = (\d+)")
REJECT = re.compile(r"provider rejected new flow (TCP|UDP)")
SURVEY = re.compile(r"SURVEY k=(\S+) why=(\S+) ep=(\S+) hn=(-?\d+) sid=(\d) tok=(\d) euid=(\d+) pid=(\d+) ffid=(\d) if=(\S+) self_ns=(\d+) pp_ns=(\d+) pp_len=(-?\d+) claim_ns=(\d+) total_ns=(\d+)")
RATE = re.compile(r"SURVEY-RATE (.*)$")


def pct(values, p):
    if not values:
        return 0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100 * (len(s) - 1)))))
    return s[k]


def rates(seconds):
    """seconds: Counter of 'YYYY-MM-DD HH:MM:SS' -> count. Prints hour/min/sec stats."""
    hours = Counter()
    minutes = Counter()
    for sec, n in seconds.items():
        hours[sec[:13]] += n
        minutes[sec[:16]] += n
    total = sum(seconds.values())
    if not seconds:
        print("  no flows")
        return
    first, last = min(seconds), max(seconds)
    print(f"  window: {first} .. {last}  flows: {total}")
    print("  per hour:")
    for h in sorted(hours):
        print(f"    {h}:00  {hours[h]:6d}  ({hours[h] / 3600:.2f}/s avg)")
    busy_min = minutes.most_common(5)
    print("  busiest minutes:", ", ".join(f"{m} = {n} ({n / 60:.1f}/s)" for m, n in busy_min))
    busy_sec = seconds.most_common(8)
    print("  busiest seconds:", ", ".join(f"{s[11:]} = {n}" for s, n in busy_sec))
    vals = list(seconds.values())
    print(f"  per-second (over seconds that had >=1 flow, n={len(vals)}): p50={pct(vals, 50)} p90={pct(vals, 90)} p99={pct(vals, 99)} max={max(vals)}")
    # sliding 10 s windows
    import datetime as dt
    keys = sorted(seconds)
    best10 = 0
    best10_at = ""
    for i, k in enumerate(keys):
        t0 = dt.datetime.strptime(k, "%Y-%m-%d %H:%M:%S")
        acc = 0
        j = i
        while j < len(keys):
            tj = dt.datetime.strptime(keys[j], "%Y-%m-%d %H:%M:%S")
            if (tj - t0).total_seconds() >= 10:
                break
            acc += seconds[keys[j]]
            j += 1
        if acc > best10:
            best10, best10_at = acc, k
    print(f"  busiest 10 s window: {best10} flows starting {best10_at} ({best10 / 10:.1f}/s)")


def framework(path):
    seconds = Counter()
    by_type = Counter()
    name_set = Counter()
    app_empty = Counter()
    filter_nil = Counter()
    ifaces = Counter()
    ports = Counter()
    apps = Counter()
    udp_ports = Counter()
    calling = Counter()
    rejected = Counter()
    token_len = Counter()
    remote_zero_port = 0
    n_newflow = 0
    with open(path, errors="replace") as f:
        for line in f:
            m = TS.match(line)
            if not m:
                continue
            sec = f"{m.group(1)} {m.group(2)}:{m.group(3)}:{m.group(4)}"
            nf = NEWFLOW.search(line)
            if nf:
                n_newflow += 1
                typ, app, name, local, remote, fid, iface = nf.groups()
                seconds[sec] += 1
                by_type[typ] += 1
                name_set[(typ, bool(name.strip()))] += 1
                app_empty[(typ, app.strip() == "")] += 1
                filter_nil[(typ, fid.strip() in ("", "(null)", "00000000-0000-0000-0000-000000000000"))] += 1
                ifaces[iface] += 1
                apps[app.strip() or "<empty>"] += 1
                port = remote.rsplit(":", 1)[-1]
                ports[(typ, port)] += 1
                if typ == "datagram":
                    udp_ports[port] += 1
                if remote.endswith(":0"):
                    remote_zero_port += 1
                continue
            c = CALLING.search(line)
            if c:
                calling[(c.group(1), c.group(2))] += 1
                token_len[c.group(4)] += 1
                continue
            r = REJECT.search(line)
            if r:
                rejected[r.group(1)] += 1
    print(f"framework per-flow lines: New flow={n_newflow}  Calling={dict(calling)}  rejected={dict(rejected)}")
    print("by type:", dict(by_type))
    print("remote hostname set (framework 'name ='):", {f"{t}:{'set' if s else 'unset'}": n for (t, s), n in sorted(name_set.items())})
    print("app signing id empty:", {f"{t}:{'empty' if e else 'set'}": n for (t, e), n in sorted(app_empty.items())})
    print("filter_id nil:", {f"{t}:{'nil' if e else 'set'}": n for (t, e), n in sorted(filter_nil.items())})
    print("interfaces:", dict(ifaces.most_common(8)))
    print("remote with port 0:", remote_zero_port)
    print("unique-identifier byte length in 'Calling' lines:", dict(token_len))
    print("top remote ports (type, port):", [(f"{t}:{p}", n) for (t, p), n in ports.most_common(12)])
    print("UDP remote ports:", dict(udp_ports.most_common(10)))
    print("top apps:", apps.most_common(15))
    print("rates:")
    rates(seconds)


def survey(path):
    seconds = Counter()
    rows = []
    rate_lines = []
    with open(path, errors="replace") as f:
        for line in f:
            m = TS.match(line)
            s = SURVEY.search(line)
            if m and s:
                sec = f"{m.group(1)} {m.group(2)}:{m.group(3)}:{m.group(4)}"
                seconds[sec] += 1
                k, why, ep, hn, sid, tok, euid, pid, ffid, iface, self_ns, pp_ns, pp_len, claim_ns, total_ns = s.groups()
                rows.append(dict(k=k, why=why, ep=ep, hn=int(hn), sid=int(sid), tok=int(tok), euid=int(euid),
                                 pid=int(pid), ffid=int(ffid), iface=iface, self_ns=int(self_ns), pp_ns=int(pp_ns),
                                 pp_len=int(pp_len), claim_ns=int(claim_ns), total_ns=int(total_ns)))
                continue
            r = RATE.search(line)
            if r and m:
                rate_lines.append((f"{m.group(1)} {m.group(2)}:{m.group(3)}:{m.group(4)}", r.group(1)))
    n = len(rows)
    print(f"SURVEY lines: {n}")
    if not n:
        return

    def frac(cnt):
        return f"{cnt} ({100.0 * cnt / n:.1f}%)"

    def ep_class(ep):
        if ep == "nil":
            return "nil"
        if ep.startswith("name:"):
            return "hostname-typed"
        if ep in ("service", "url", "unix", "opaque", "unknown"):
            return ep
        return "ip:port"

    print("kind:", dict(Counter(r["k"] for r in rows)))
    print("why:", dict(Counter(r["why"] for r in rows)))
    print("endpoint class:", dict(Counter(ep_class(r["ep"]) for r in rows)))
    print("remoteHostname: nil", frac(sum(1 for r in rows if r["hn"] < 0)), " set", frac(sum(1 for r in rows if r["hn"] > 0)),
          " empty-string", frac(sum(1 for r in rows if r["hn"] == 0)))
    for k in ("T", "U"):
        sub = [r for r in rows if r["k"] == k]
        if sub:
            print(f"  {k}: hostname set {sum(1 for r in sub if r['hn'] > 0)}/{len(sub)}")
    print("sourceAppSigningIdentifier empty:", frac(sum(1 for r in rows if r["sid"] == 0)))
    print("sourceAppAuditToken: nil", frac(sum(1 for r in rows if r["tok"] == 0)), " present", frac(sum(1 for r in rows if r["tok"] == 1)),
          " wrong-size", frac(sum(1 for r in rows if r["tok"] == 2)))
    print("filterFlowIdentifier nil:", frac(sum(1 for r in rows if r["ffid"] == 0)))
    print("interface:", dict(Counter(r["iface"] for r in rows).most_common(8)))
    euids = Counter(r["euid"] for r in rows if r["tok"] == 1)
    print("euid distribution (token present):", dict(euids.most_common(10)))
    print("sid empty by euid:", dict(Counter(r["euid"] for r in rows if r["sid"] == 0 and r["tok"] == 1).most_common(6)))
    print("pp_len==0 (proc_pidpath_audittoken failed):", frac(sum(1 for r in rows if r["tok"] == 1 and r["pp_len"] <= 0)),
          "of token-present rows", sum(1 for r in rows if r["tok"] == 1))
    print("distinct pids:", len(set(r["pid"] for r in rows if r["tok"] == 1)))
    ports = Counter(r["ep"].rsplit(":", 1)[-1] for r in rows if ep_class(r["ep"]) in ("ip:port", "hostname-typed"))
    print("top remote ports:", dict(ports.most_common(12)))
    udp_ports = Counter(r["ep"].rsplit(":", 1)[-1] for r in rows if r["k"] == "U")
    print("UDP remote ports:", dict(udp_ports.most_common(10)))

    def timing(label, vals):
        vals = [v for v in vals if v > 0]
        if not vals:
            print(f"  {label}: no samples")
            return
        print(f"  {label} (us): n={len(vals)} p50={pct(vals, 50) / 1000:.1f} p90={pct(vals, 90) / 1000:.1f} p99={pct(vals, 99) / 1000:.1f} max={max(vals) / 1000:.1f} mean={sum(vals) / len(vals) / 1000:.1f}")

    print("timings:")
    timing("isSelf", [r["self_ns"] for r in rows])
    timing("isSelf (token present)", [r["self_ns"] for r in rows if r["tok"] == 1])
    timing("isSelf (token nil)", [r["self_ns"] for r in rows if r["tok"] == 0])
    timing("proc_pidpath_audittoken", [r["pp_ns"] for r in rows])
    timing("claim path (handleTCP/handleUDP)", [r["claim_ns"] for r in rows if r["why"] == "unclaimed"])
    timing("total handleNewFlow to log", [r["total_ns"] for r in rows])
    print("rates:")
    rates(seconds)
    if rate_lines:
        print("SURVEY-RATE lines (in-process counters):")
        for ts, body in rate_lines[-12:]:
            print(f"  {ts}  {body}")
        peak = 0
        for _, body in rate_lines:
            m = re.search(r"max_1s=(\d+)", body)
            if m:
                peak = max(peak, int(m.group(1)))
        print(f"  in-process max flows in one second: {peak}")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("framework", "survey"):
        print(__doc__)
        sys.exit(2)
    (framework if sys.argv[1] == "framework" else survey)(sys.argv[2])
