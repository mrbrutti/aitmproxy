# aitmproxy bundled detection catalogue

First-party Rhai scripts that ship with aitmproxy and load by default. They give
a fresh install a working passive scanner plus a set of operator-invoked active
and L4 checks, covering the OWASP Top 10 and other common weaknesses across
HTTP, HTTPS, WebSocket, and L4.

All scripts are for **authorised security testing only**: they act on traffic
inside the engagement scope you have configured.

## How they load

`aitm` discovers this catalogue beside the binary (`<exe_dir>/share/aitm/scripts`,
with `bin/`+`share/` one- and two-level-up variants, installed there by the
packagers) or, in a dev checkout, at `scripts/bundled/`. Every `*.rhai` under the
tree is loaded as an enabled script at startup, after anything you declared in
`scripts:`, via `AITM_SCRIPTS`, or with `--script` — a declared entry with the
same path wins (the bundled copy is skipped), so you can re-point one with custom
options or disable it.

- `AITM_NO_BUNDLED_SCRIPTS=1` — load none of them.
- `AITM_BUNDLED_SCRIPTS=/path` — load from a directory you choose instead. Every
  `*.rhai` under it is compiled and run at startup, so point it at a dir you trust.

## Posture

- **Passive detectors (`http/`, `ws/`)** run automatically on in-scope flows.
  They are observe-only: they read the flow, mark it, and record findings. They
  send no traffic and change no request or response, so loading them by default
  does not weaken deny-by-default. Read findings with `findings.list`.
- **Active checks (`active/`)** register `check.*` commands that do nothing until
  you invoke them. Each sends one or a few requests through the proxy's own
  client, which is scope- and rate-gated. Probes are benign: a unique canary
  marker, a cross-origin `Origin`, a single quote for error-based SQLi, an
  `OPTIONS` request. They detect a weakness; they do not exploit it.
- **L4 checks (`l4/`)** register `l4.*` commands that require the L4 layer to be
  enabled and the target in the L4 scope, and are gated by the L4 Inject/Capture
  capability. They send a single crafted packet.

## Catalogue

### HTTP / HTTPS — passive (`http/`)

| Script | Detects | OWASP |
|---|---|---|
| missing-hsts | HTTPS without Strict-Transport-Security | A05 / A02 |
| missing-csp | HTML without Content-Security-Policy | A05 |
| missing-nosniff | No X-Content-Type-Options: nosniff | A05 |
| missing-frame-protection | No X-Frame-Options / frame-ancestors (clickjacking) | A05 |
| missing-referrer-policy | No Referrer-Policy | A05 |
| missing-permissions-policy | No Permissions-Policy | A05 |
| insecure-cookies | Set-Cookie without Secure / HttpOnly / SameSite | A05 / A07 |
| cors-misconfiguration | Wildcard, reflected-origin-with-credentials, or null ACAO | A05 / A01 |
| server-banner-disclosure | Version banners (Server, X-Powered-By, …) | A05 |
| verbose-error-disclosure | Stack traces / framework error pages in body | A05 / A04 |
| sql-error-indicator | Database error strings in response | A03 |
| secret-in-response | Cloud keys, tokens, private keys in a response | A02 / A05 |
| secret-in-url | Credentials/tokens in the query string | A09 / A02 |
| basic-auth-cleartext | Basic/Digest credentials over plaintext HTTP | A02 |
| jwt-weakness | JWT with alg=none | A02 / A07 |
| open-redirect-reflection | Redirect Location echoes a request parameter | A01 |
| directory-listing | Auto-generated directory index | A05 |
| sensitive-path-exposed | Reachable VCS metadata / dotfiles / debug endpoints | A05 / A01 |
| reflected-input-indicator | Request value reflected unencoded into HTML | A03 (XSS) |
| host-header-reflection | X-Forwarded-Host reflected into the response | A03 |
| mixed-content | HTTPS page referencing http:// sub-resources | A02 |
| graphql-introspection | GraphQL introspection enabled | A05 |
| csrf-token-missing | Cookie-authenticated state change without a CSRF token | A01 |
| request-smuggling-indicator | Both Content-Length and Transfer-Encoding | A05 |
| cacheable-sensitive-response | Authenticated response cacheable | A05 |
| private-address-disclosure | Internal RFC1918 address leaked | A05 |
| dangerous-http-methods | TRACE enabled / risky methods advertised | A05 |

### WebSocket — passive (`ws/`)

| Script | Detects | OWASP |
|---|---|---|
| ws-cleartext-transport | WebSocket over ws:// instead of wss:// | A02 |
| ws-cross-site-hijack-indicator | Cookie-authenticated handshake (CSWSH precondition) | A01 |
| ws-secret-in-frame | Credential/token inside a text frame | A02 / A09 |
| ws-pii-in-frame | Email / card-like number inside a text frame | A02 |

### HTTP — active vulnerability detection, operator/agent-invoked (`active/`)

These confirm **real, exploitable** issues by probing a parameter and verifying
the server's behaviour (error signature, boolean/length differential, evaluated
marker, or reflected content). Payloads are detection-grade and benign: an
arithmetic marker, a split `echo` marker, a single quote, an always-true/false
condition, a read of a universal marker file. They confirm a bug; they do not
weaponise it. Each sends a few scope- and rate-gated requests and only when you
invoke it. A cyber model drives them per parameter over MCP.

| Command | Confirms | Technique | OWASP |
|---|---|---|---|
| `check.sqli { url, param, value? }` | SQL injection | Error signature + boolean (1=1 vs 1=2) length differential | A03 |
| `check.xss { url, param }` | Reflected XSS | Unique markup canary reflected unencoded in an HTML context | A03 |
| `check.ssti { url, param }` | Template injection (→RCE) | Arithmetic marker (73×79) evaluated to its product | A03 |
| `check.cmdi { url, param, value? }` | OS command injection (RCE) | Split `echo` marker reassembled only by shell execution | A03 |
| `check.path_traversal { url, param }` | Path traversal / LFI | Reads `/etc/passwd` / `win.ini` and matches its signature | A01 / A03 |
| `check.xxe { url }` | XML External Entity (→file read/SSRF) | In-band entity resolves a local file; signature matched | A05 |
| `check.ssrf { url, param }` | Server-Side Request Forgery | Points the param at cloud-metadata/internal targets; matches their replies | A10 |
| `check.crlf { url, param }` | CRLF / response-header injection | Injects a canary response header and confirms it appears | A03 |
| `check.nosqli { url, param, value? }` | NoSQL (Mongo) injection | `$ne`/`$gt` operator error + result-set differential | A03 |
| `check.ldapi { url, param, value? }` | LDAP injection | Filter-metacharacter error + always-true filter differential | A03 |
| `check.open_redirect { url, param }` | Open redirect | Canary target reflected in the Location of a 3xx | A01 |
| `check.cors { url }` | CORS trust misconfig | Canary Origin reflected (with credentials) | A05 |
| `check.headers { url }` | Missing security headers | Active fetch and header audit | A05 |
| `check.methods { url }` | Risky HTTP methods | OPTIONS; reports and flags the Allow set | A05 |
| `check.paths { base }` | Exposed sensitive paths | Probes well-known VCS/dotfile/debug paths | A05 / A01 |

Recommended battery for one query parameter: `check.sqli`, `check.xss`,
`check.ssti`, `check.cmdi`, `check.path_traversal`, `check.crlf`,
`check.nosqli`, `check.ldapi`, `check.ssrf`, then `check.open_redirect`; and
`check.xxe` against any XML endpoint.

### L4 — operator-invoked (`l4/`)

| Command | Does |
|---|---|
| `l4.recon` | List capture interfaces and the current L4 scope (read-only) |
| `l4.tcp_probe { dst, port, interface }` | One TCP SYN → open / closed / filtered |
| `l4.udp_probe { dst, port, interface }` | One UDP datagram → reply / no reply |

## Writing your own

Each file is plain Rhai using the host API in `docs/design/languages/rhai.api.json`.
Passive detectors use the `on_request` / `on_response` / `on_ws_*` hooks and
`finding(#{ … })`. Active/L4 scripts register a command in `load(reg)` and call
the scope-gated `http.send` / `l4.*` verbs. The compile-and-run test in
`crates/aitm-plugin-rhai/tests/bundled_scripts.rs` validates every file here,
and `crates/aitm/tests/bundled_startup.rs` loads the whole catalogue the way
the binary does at startup (every `load(reg)` included), with and without the
L4 layer.

Two Rhai rules every script here follows. A top-level `const` with a literal
value (`const SQL_ERR = "(?i)…"`, `const PATHS = [...]`) may be read inside
hooks and inside `load(reg)` command closures: the engine resolves such names
inside functions from the script's constants. A constant computed by a call is
not visible in functions; a parameter or `let` of the same name shadows the
constant; and the constant is read-only there, so mutate a copy (`let p =
PATHS; p.push(x)`). Second, a closure captures every outer name when it is *created*, so a
command closure that names an optional namespace (`l4` with the L4 layer off)
fails at load before its `try` can catch anything; the `l4/` scripts call `l4`
from a named function and keep the `try` in the closure.
