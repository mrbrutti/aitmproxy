# aitmproxy — Blind Agentic Penetration Test: bWAPP

**Engagement:** Authorized blind assessment of a local, deliberately‑vulnerable
web application, driven **100% over aitmproxy's MCP bus** by an autonomous agent
with **no prior knowledge** of the target.
**Date:** 2026-10-30
**Target (in scope, only host reachable):** `http://127.0.0.1:8088` (bWAPP, security level *low*)
**Proxy posture:** deny‑by‑default; scope locked to the single target host throughout.
**Result:** **7 distinct vulnerabilities confirmed**, each proven with live
tool‑observed evidence and a reproducible PoC that `poc.run` executed to PASS.

Video of the full run: `bwapp-blind-pentest.mp4` (terminal capture of the
discovery → exploit → PoC → findings flow).

---

## 1. How this was done (methodology)

Everything below was performed by an agent calling aitmproxy tools over the
loopback MCP bus — no direct access to the app, no memorized vulnerabilities.

1. **Posture / scope.** `agent.status` (policy `auto`) and `scope.list` confirm
   the proxy is deny‑by‑default and locked to `127.0.0.1:8088` only.
2. **Discovery.** The agent authenticated **through the proxy** (`request.send`
   → `flow.detail`), fingerprinting the stack from observed response headers,
   then crawled the authenticated portal and enumerated the attack surface
   (276 menu entries) and the real page/parameter names.
3. **Exploitation.** For each candidate, the agent sent a crafted payload with
   `request.send` and read the captured flow (`flow.detail`), confirming the
   vulnerability **only from what the tool observed** in the response.
4. **Proof‑of‑concept.** A human‑readable PoC (nuclei‑style YAML) was written
   for each class and executed with `poc.run`. `poc.run` is a *Sensitive*
   action: under policy `auto` the agent is refused, so the **operator**
   (human‑in‑the‑loop) authorized and ran each reproduction — exactly the
   deny‑by‑default design. Every PoC returned **PASSED**.
5. **Findings.** Each confirmed issue was recorded with `findings.record`
   (persisted by `aitm-findings` as one YAML per finding + `runs.jsonl`) and
   appears in `findings.list`.

### Environment fingerprint (observed live)
From the login response headers captured through the proxy:
- `Server: Apache/2.4.7 (Ubuntu)`
- `X-Powered-By: PHP/5.5.9-1ubuntu4.14`  ← end‑of‑life runtime (OWASP A9)
- Database (via SQLi UNION): **MySQL `5.5.47-0ubuntu0.14.04.1`**

---

## 2. Findings summary

| # | Severity | Vulnerability | Endpoint | Parameter | PoC |
|---|----------|---------------|----------|-----------|-----|
| 1 | Medium   | HTML Injection (Reflected, GET) | `/htmli_get.php` | `firstname` | `01-html-injection.yaml` |
| 2 | **Critical** | SQL Injection (UNION exfiltration) | `/sqli_1.php` | `title` | `02-sqli-get-search.yaml` |
| 3 | **Critical** | OS Command Injection (RCE) | `/commandi.php` | `target` | `03-os-command-injection.yaml` |
| 4 | High     | Cross‑Site Scripting (Reflected, GET) | `/xss_get.php` | `firstname` | `04-xss-reflected-get.yaml` |
| 5 | **Critical** | PHP Code Injection (RCE) | `/phpi.php` | `message` | `05-php-code-injection.yaml` |
| 6 | High     | Directory / Path Traversal | `/directory_traversal_1.php` | `page` | `06-directory-traversal.yaml` |
| 7 | High     | Local File Inclusion (RFI/LFI) | `/rlfi.php` | `language` | `07-local-file-inclusion.yaml` |

All 7 PoCs executed by `poc.run` → **PASSED**. All 7 persisted in `findings.list`.

---

## 3. Findings detail

Each finding lists the live payload the agent sent and the **exact evidence
observed in the response through aitmproxy**.

### 1. HTML Injection — Reflected (GET)  ·  Medium  ·  CWE‑79
- **Endpoint:** `GET /htmli_get.php?firstname=<payload>&lastname=x`
- **Payload:** `<h1>AITM-PROOF</h1>`
- **Observed evidence:** response body contained `Welcome <h1>AITM-PROOF</h1> x`
  — the parameter is reflected into HTML with no output encoding.
- **Impact:** arbitrary markup injection / content spoofing; precursor to XSS.
- **Remediation:** context‑aware output encoding (e.g. `htmlspecialchars`).

### 2. SQL Injection (GET/Search) — UNION data exfiltration  ·  Critical  ·  CWE‑89
- **Endpoint:** `GET /sqli_1.php?title=<payload>&action=search`
- **Payloads:** `'` (error) and
  `zz' UNION SELECT 1,concat('AITMSQLi-',version()),3,4,5,6,7-- -`
- **Observed evidence:** a lone quote returned *“You have an error in your SQL
  syntax”*; the UNION injected an attacker row rendered as
  `AITMSQLi-5.5.47-0ubuntu0.14.04.1` — proving arbitrary read access and
  exfiltration of the live DB version.
- **Impact:** full read of the application database (credentials, data).
- **Remediation:** parameterized queries / prepared statements; least‑priv DB user.

### 3. OS Command Injection (RCE)  ·  Critical  ·  CWE‑78
- **Endpoint:** `POST /commandi.php` body `target=<payload>&form=submit`
- **Payload:** `www.nsa.gov; id`
- **Observed evidence:** response contained
  `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — the shell
  metacharacter executed `id` on the server.
- **Impact:** remote command execution as `www-data`; full host compromise path.
- **Remediation:** avoid shelling out; if unavoidable, use argument arrays with
  strict allow‑listing, never string concatenation.

### 4. Cross‑Site Scripting — Reflected (GET)  ·  High  ·  CWE‑79
- **Endpoint:** `GET /xss_get.php?firstname=<payload>&lastname=x`
- **Payload:** `<script>window.__aitm='PROOF'</script>`
- **Observed evidence:** the `<script>…</script>` element was returned verbatim
  inside the page — it executes in the victim's browser.
- **Impact:** session/credential theft, action on behalf of the victim.
- **Remediation:** output‑encode untrusted data; Content‑Security‑Policy.

### 5. PHP Code Injection (RCE)  ·  Critical  ·  CWE‑94
- **Endpoint:** `GET /phpi.php?message=<payload>`
- **Payload:** `system('id')`
- **Observed evidence:** response contained
  `uid=33(www-data) gid=33(www-data) …` — the `message` value reached a PHP
  `eval()`‑style sink and executed server‑side code.
- **Impact:** arbitrary PHP / OS command execution.
- **Remediation:** never pass user input to `eval`/dynamic code; redesign the sink.

### 6. Directory / Path Traversal  ·  High  ·  CWE‑22
- **Endpoint:** `GET /directory_traversal_1.php?page=<payload>`
- **Payload:** `../../../../../../etc/passwd`
- **Observed evidence:** response contained `root:x:0:0:root:/root:/bin/bash …`
  — traversal escaped the intended directory and disclosed `/etc/passwd`.
- **Impact:** disclosure of arbitrary server files (source, config, secrets).
- **Remediation:** canonicalize and confine paths to an allow‑listed base dir.

### 7. Local File Inclusion (RFI/LFI)  ·  High  ·  CWE‑98
- **Endpoint:** `GET /rlfi.php?language=<payload>&action=go`
- **Payload:** `../../../../../../etc/passwd`
- **Observed evidence:** response contained `root:x:0:0:root:/root:/bin/bash …`
  — the `language` parameter is used as a file path in an include/read sink.
- **Impact:** local file disclosure; with the same sink, remote file inclusion → RCE.
- **Remediation:** allow‑list permitted values; never build include paths from input.

---

## 4. Reproducing the findings

Against a running aitm core scoped to the target, with an authenticated bWAPP
session cookie supplied as the `cookie` variable:

```
poc.run { poc_path: "<pocs>/02-sqli-get-search.yaml",
          target:   "http://127.0.0.1:8088",
          vars:     { cookie: "PHPSESSID=<id>; security_level=0" } }
```

The PoCs are in `bwapp-assessment/pocs/` (`01`–`07`). Each PoC sends the attack
request(s) and asserts the evidence above; all return PASSED. Persisted findings
are in `bwapp-assessment/findings/` (one YAML per finding + `runs.jsonl`).

## 5. Tooling note

The assessment was driven by a small MCP client (`mcpcli.py` / `run-assessment.py`)
over aitmproxy's token‑gated loopback bus. aitmproxy provided: the intercepting
proxy + flow store (`request.send`, `flow.detail`), the embedded obscura browser
engine behind the same scope/SSRF gating, the nuclei‑style PoC engine
(`poc.run`), and the persistent findings store (`findings.record` / `findings.list`).
Scope stayed locked to `http://127.0.0.1:8088` for the entire engagement.
