# aitmproxy bundled detection catalogue

First-party Rhai scripts that ship with aitmproxy and load by default. They give
a fresh install a working passive scanner plus a set of active checks the
scanner schedules and the operator can invoke by hand, covering the OWASP Top 10
and other common weaknesses across HTTP, HTTPS, WebSocket, and L4.

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

### What a loaded file registers

- A **passive detector** (`http/`, `ws/`) registers hooks — `on_request`,
  `on_response`, `on_ws_*` — and records what it sees with `finding(#{ … })`.
  Those script-emitted findings are read back with **`script.findings`**.
  (`findings.list` is a different surface: the persistent findings store, which
  holds a record only once a PoC reproduction has run and passed.)
- An **active check** (`active/`) registers a *check*, not a command:
  `reg.add_check(META, |point| { … })`. A check is a function of one insertion
  point, and registering it buys two ways to run:
  1. **The scanner schedules it.** When you start a job with `scan.start`, the
     HTTP lane enumerates insertion points over the site map and the scheduler
     selects every catalogue entry whose `lanes` contain the point's lane, whose
     `kinds` contain the point's kind, whose `intensity` is within the profile's
     intensity, that passes the profile's include/exclude lists, and — when the
     check declares `wants_traits` — whose traits the point carries. You name no
     checks and no parameters; the catalogue is matched to the points.
  2. **You invoke it by hand.** Every catalogue entry, Rhai *or* native, also
     gets a manual verb `check.<id> { url, param, value? }` (`Sensitive`),
     registered uniformly by the engine's catalogue bridge. The verb synthesises
     a single `query` point and runs the same check body, so a hand-run and a
     scheduled run are the same code.
- An **L4 script** (`l4/`) still registers a plain command (`reg.add_command`);
  the L4 lane has no insertion-point catalogue.

## Posture

- **Passive detectors (`http/`, `ws/`)** run automatically on in-scope flows.
  They are observe-only: they read the flow, mark it, and record findings. They
  send no traffic and change no request or response, so loading them by default
  does not weaken deny-by-default. Read findings with `script.findings`.
- **Active checks (`active/`)** send nothing until either you invoke
  `check.<id>` or a scan job you started reaches them. Each sends one or a few
  requests through the proxy's own client, which is scope-, budget- and
  rate-gated. Probes are benign: a unique canary marker, a cross-origin
  `Origin`, a single quote for error-based SQLi, an arithmetic marker, an
  `OPTIONS` request. They detect a weakness; they do not exploit it. The manual
  verb stays `Sensitive`; inside a job the gate is the job's — `scan.start` is
  itself `Sensitive` and its agent gate was passed at start, so the catalogue
  runs without a second per-call decision.
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

### HTTP — active checks, scheduled and operator-invoked (`active/`)

These confirm **real, exploitable** issues by probing an insertion point and
verifying the server's behaviour (error signature, boolean/length differential,
evaluated marker, or reflected content). Payloads are detection-grade and
benign: an arithmetic marker, a split `echo` marker, a single quote, an
always-true/false condition, a read of a universal marker file. They confirm a
bug; they do not weaponise it. Each sends a few scope-, budget- and rate-gated
requests, and only inside a job you started or a `check.<id>` you invoked.

One row per script; the manual verb is `check.<id>`.

| id | class | kinds | intensity | technique | severity | PoC hint | Confirms |
|---|---|---|---|---|---|---|---|
| `cmdi` | cmdi | query, body_param, json_value | medium | reflected | critical | yes | Split `echo` marker reassembled only by a shell |
| `cors` | cors | query (origin-scoped) | light | reflected | medium | no | Canary `Origin` echoed, with or without credentials |
| `crlf` | crlf | query, body_param, header | medium | reflected | high | yes | Injected canary appears as a response header |
| `header-reflection` | reflected-xss | header, cookie | light | reflected | medium | yes | A markup-significant header/cookie marker echoed verbatim into HTML, or into a response header |
| `headers` | missing-security-headers | query (origin-scoped) | passive | passive | low | no | Which of HSTS, CSP, nosniff, frame, referrer are absent |
| `ldapi` | ldapi | query, body_param | medium | boolean | high | no | Always-true filter differential (directory error refines it) |
| `methods` | risky-http-methods | query (origin-scoped) | light | observe | info | no | `Allow` advertises a write or debug method |
| `nosqli` | nosqli | query, body_param | medium | boolean | high | no | `$ne`/`$gt` operator changes the result set |
| `nosqli-json` | nosqli | json_value | medium | boolean | critical | no | A JSON string value replaced by an operator document |
| `path_traversal` | path-traversal | query, body_param, json_value, path_filename, multipart_filename | medium | reflected | critical | yes | A well-known system file comes back |
| `paths` | exposed-path | query (origin-scoped) | light | observe | medium | no | Well-known VCS/config/debug paths answering 200 |
| `sqli` | sqli | query, body_param, json_value, cookie | medium | error | critical | yes | A database error signature after a single quote |
| `ssrf` | ssrf | query, body_param, json_value | medium | reflected | critical | no | Cloud-metadata / loopback reply returned in-band |
| `ssti` | ssti | query, body_param, json_value | medium | reflected | critical | yes | `73*79` returned as its product |
| `xxe` | xxe | entire_body | medium | reflected | critical | yes | A declared external entity resolved to a file |

Aiming hints: `path_traversal` declares `wants_traits: ["filename"]` and `ssrf`
declares `wants_traits: ["url"]`, so the scheduler skips them on points that
cannot plausibly be effective. The four origin-level audits (`cors`, `headers`,
`methods`, `paths`) declare `kinds: ["query"]` and `scope: "origin"`: the point
is only a carrier and the audit is of the origin. Three of them run once per
origin and return one verdict; `paths` returns one verdict per exposed path.
All four return `inconclusive` when the point carries no URL at all: there is
then no origin to audit, and concluding nothing is the honest answer.

Three behaviours are deliberately narrower than their class suggests, and all
are noted here rather than hidden:

- `paths` returns **one verdict per exposed path**: an array of verdict maps,
  which the bridge reads as a root verdict plus `Verdict.more` siblings, each
  carrying `location: #{ path }` so `/.git/HEAD` and `/.env` dedupe as two
  issues. A clean origin is a single `clean` verdict with no location.
- `header-reflection` sends a **markup-significant** payload — a quote and an
  angle bracket in front of the marker — and counts only a verbatim echo. The
  payload back in an **HTML body** is `vulnerable` at `certain`; the payload
  back in a **response header** is `vulnerable` at `firm`. A JSON or plain-text
  body that echoes it, and a page that returns the marker's letters with the
  punctuation encoded, are both `clean`: the output was escaped, or it never
  reaches a browser as markup.
- `methods` returns `inconclusive` when the `OPTIONS` reply carries no `Allow`
  header: the origin advertised nothing, which is not the same as advertising
  nothing risky.

### HTTP — native checks (`crates/aitm-scan-checks-http`)

Compiled Rust checks, contributed by
`aitm_scan_checks_http::checks_with(ssrf_policy, scope_guard)` — the slot
`crates/aitm/src/wire.rs` calls once at startup with the operator's SSRF policy
and the proxy's scope guard, because five of the ten dial raw HTTP/2 and every
such dial is gated. They sit in the same catalogue as the scripts above, are
scheduled by the same rules, and get the same manual verb:
`check.sqli-boolean`, `check.sqli-time`, `check.cmdi-time`,
`check.xss-reflected`, `check.open-redirect`,
`check.h2-settings-observe`, `check.h2-pseudo-header-validation`,
`check.h2-header-crlf-tolerance`, `check.h2-cl-te-downgrade-indicator`,
`check.h2-rapid-reset-mitigation`.

"the eight injectable kinds" below means `query, body_param, json_value,
xml_value, multipart_value, header, cookie, path_segment`.

| id | class | kinds | intensity | technique | severity | PoC hint | Confirms |
|---|---|---|---|---|---|---|---|
| `cmdi-time` | cmdi | the eight injectable kinds | medium | timing | critical | no | Response time tracks a requested shell delay |
| `h2-cl-te-downgrade-indicator` | h2-smuggling-indicator | query, body_param, header, cookie, path_segment | medium | observe | info | no | An h2 request with a disagreeing `content-length`, or a `transfer-encoding`, is answered rather than rejected |
| `h2-header-crlf-tolerance` | h2-header-crlf | query, body_param, header, cookie, path_segment | medium | malformed | medium | no | CR LF inside an h2 header name or value is tolerated |
| `h2-pseudo-header-validation` | h2-pseudo-header | query, body_param, header, cookie, path_segment | medium | malformed | info | no | A malformed pseudo-header set is answered rather than reset |
| `h2-rapid-reset-mitigation` | h2-rapid-reset | query, body_param, header, cookie, path_segment | medium | observe | info | no | Whether eight open/reset pairs provoke any reset-rate mitigation |
| `h2-settings-observe` | h2-settings | query, body_param, header, cookie, path_segment | medium | observe | info | no | The SETTINGS the server advertises |
| `open-redirect` | open-redirect | query, body_param, json_value, header | light | reflected | medium | yes | A 3xx whose `Location` authority is the canary host |
| `sqli-boolean` | sqli | the eight injectable kinds | medium | boolean | critical | no | True arm reproduces the baseline, false arm diverges |
| `sqli-time` | sqli | the eight injectable kinds | medium | timing | critical | no | Response time tracks a requested database delay |
| `xss-reflected` | reflected-xss | query, body_param, json_value, xml_value, multipart_value, header, cookie, path_segment, param_name_query | light | reflected | high | yes | A markup canary reflected with brackets and quotes intact into HTML |

`open-redirect` declares `wants_traits: ["url"]`. The five `h2-*` checks observe
one HTTP/2 connection each, open at most eight streams, and send no `Cookie`,
`Authorization` or any session header; they are `medium` intensity and never
`intrusive`. They also declare `scope: "origin"` — like the four Rhai origin
audits, the point only carries the origin and the verdict is about the server,
so each runs once per origin rather than once per parameter.

Two scripts were **retired** when these landed: `check-xss.rhai` and
`check-open-redirect.rhai` are gone, because `xss-reflected` and `open-redirect`
are native now and a technique is single-sourced — one class is implemented in
one place, never twice. Their manual verbs changed with them: `check.xss` is now
**`check.xss-reflected`** and `check.open_redirect` is now
**`check.open-redirect`**.

Where a class is covered by more than one check — `sqli` by the Rhai `sqli`
(error signature), native `sqli-boolean` and native `sqli-time`; `cmdi` by the
Rhai `cmdi` (echo marker) and native `cmdi-time` — the checks are different
techniques for the same weakness, and hits on one point collapse into a single
issue: the dedupe key carries the class, not the check id.

A battery for one parameter by hand, now that the scheduler does this for you in
a job: `check.sqli`, `check.sqli-boolean`, `check.sqli-time`, `check.ssti`,
`check.cmdi`, `check.cmdi-time`, `check.path_traversal`, `check.crlf`,
`check.nosqli`, `check.ldapi`, `check.ssrf`, `check.xss-reflected`,
`check.open-redirect`; and `check.xxe` against any XML endpoint.

### L4 — operator-invoked (`l4/`)

| Command | Does |
|---|---|
| `l4.recon` | List capture interfaces and the current L4 scope (read-only) |
| `l4.tcp_probe { dst, port, interface }` | One TCP SYN → open / closed / filtered |
| `l4.udp_probe { dst, port, interface }` | One UDP datagram → reply / no reply |

## Ids and classes

They are two different things and the tables above keep them apart.

- The **id** names the check and nothing else. It is used verbatim for the
  manual verb, so an id keeps the spelling its shipped verb already had,
  underscores included: `path_traversal` gives `check.path_traversal`.
- The **class** is the taxonomy token. It is what an issue is filed under and
  what the dedupe key hashes, so two checks of the same class on the same point
  produce one issue. Classes are hyphenated: `path-traversal`.

So `path_traversal` (id) has class `path-traversal`, and native `xss-reflected`
(id) has class `reflected-xss`.

The class vocabulary is **pinned** — a new check picks a token from this list or
the list is extended deliberately:

`reflected-xss`, `open-redirect`, `sqli`, `cmdi`, `ssti`, `path-traversal`,
`xxe`, `crlf`, `nosqli`, `ldapi`, `ssrf`, `cors`, `missing-security-headers`,
`risky-http-methods`, `exposed-path`, and the five HTTP/2 tokens `h2-settings`,
`h2-pseudo-header`, `h2-header-crlf`, `h2-smuggling-indicator`,
`h2-rapid-reset`. `information-disclosure` is reserved for generic leaks.

## Writing a check

A check is a declaration map plus one closure. Here is a whole shipped one,
`active/check-ssti.rhai`, unabridged:

```rhai
// check-ssti.rhai — catalogue check `ssti`, class `ssti`.
//
// A template engine that renders request data evaluates expressions written in
// its own syntax. The probe asks it to multiply two primes: if `73*79` comes
// back as 5767 next to a per-run tag, the value was evaluated, not echoed. The
// product is a detection marker, not a code-execution payload — nothing is
// read, written or executed beyond the arithmetic.
//
// Four syntaxes cover the common engines: Jinja/Twig, FreeMarker/JSP-EL,
// Ruby/Thymeleaf and ERB. OWASP A03 Injection. CWE-1336.
const NAME = "check-ssti";
const API  = "1";

const META = #{
    id: "ssti",
    name: "Server-side template injection",
    class: "ssti",
    lanes: ["http"],
    kinds: ["query", "body_param", "json_value"],
    intensity: "medium",
    cost: "medium",
    technique: "reflected",
    severity: "critical",
    confidence_max: "certain",
    needs_baseline: false,
    cwe: 1336,
    description: "Sends an arithmetic marker in the major template syntaxes and reports when the server returns the evaluated product.",
    remediation: "Never build a template from request data; pass it as a bound variable to a fixed template, and sandbox the engine.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        // Two primes, so the product is unlikely to appear by chance, and the
        // job's own marker as the tag, so the match is this probe's and nobody
        // else's. The marker rather than random letters: the oracle has to
        // recognise the tag coming back, and the marker is the one token the
        // engine, the evidence and a later PoC all agree on.
        let tag = probe.marker();
        let want = tag + `${73 * 79}`;
        // The second payload is assembled rather than interpolated: a literal
        // dollar-brace would be read by Rhai's own string interpolation.
        let payloads = [
            `${tag}{{73*79}}`,
            tag + "${" + "73*79" + "}",
            `${tag}#{73*79}`,
            `${tag}<%= 73*79 %>`,
        ];

        for payload in payloads {
            let reply = probe.send(payload);
            if reply.body.contains(want) {
                return #{
                    outcome: "vulnerable",
                    confidence: "certain",
                    evidence: #{ payload: payload, matched: want },
                    detail: `"${point.name}" evaluated a template expression: 73*79 came back rendered as ${want}. Template injection usually reaches remote code execution.`,
                    // The tag alone is the control: it must come back unchanged
                    // and without the product.
                    poc_hint: #{
                        matchers: [ #{ type: "word", word: want, part: "body" } ],
                        control: #{
                            payload: tag,
                            matchers: [ #{ not: #{ type: "word", word: want, part: "body" } } ],
                        },
                    },
                };
            }
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: payloads[0], matched: () },
            detail: "No template syntax was evaluated: the arithmetic marker never came back as its product.",
        }
    });
}
```

### The declaration map

**Required.** `id`, `name`, `class`, `lanes`, `kinds`, `intensity`, `cost`,
`technique`, `severity`, `confidence_max`, `description`.

**Optional.** `needs_baseline`, `wants_traits`, `targets_session`, `cwe`,
`remediation`, `scope`.

**Host-owned.** `origin` — the host fills it in (bundled scripts get the path
they were loaded from). A script that declares `origin` is a load error.

A missing or invalid key is a **load error naming the key**: the catalogue
refuses to schedule what it cannot classify, and failing at load beats
discovering at audit time that a check never ran.

The values:

| Key | Values |
|---|---|
| `id` | the check's name; becomes `check.<id>` verbatim |
| `class` | one token from the pinned list above |
| `lanes` | `["http"]` for everything in `active/` |
| `kinds` | the insertion kinds this check understands: `query`, `body_param`, `json_value`, `xml_value`, `xml_attr`, `multipart_value`, `multipart_filename`, `header`, `cookie`, `path_segment`, `path_filename`, `param_name_query`, `param_name_body`, `entire_body` |
| `intensity` | `passive`, `light`, `medium`, `intrusive` — the scheduler runs a check only when the profile's intensity reaches it |
| `cost` | `light` (≤3 probes per point), `medium` (≤10), `heavy` |
| `technique` | `reflected`, `error`, `boolean`, `timing`, `handshake`, `malformed`, `observe`, `passive` |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |
| `confidence_max` | `tentative`, `firm`, `certain` — the ceiling a verdict from this check may claim |
| `needs_baseline` | whether the check compares against `probe.baseline()` |
| `wants_traits` | aim the check: e.g. `["url"]`, `["filename"]`; the scheduler skips points without the trait |
| `scope` | `point` (default), `node`, or `origin` — what the verdict is about |
| `cwe` | the CWE number, as an integer |

### The point

The closure takes one argument, a map describing where the check may inject:

| Key | What |
|---|---|
| `kind` | the insertion kind, one of the `kinds` tokens |
| `name` | the parameter, header, cookie or field name |
| `path` | the request path |
| `url` | the full request URL |
| `method` | the request method |
| `example` | the value the captured request carried at this point, if any |
| `traits` | the traits the lane inferred (`url`, `filename`, `session`, …) |

### The probes

`probe.*` is available **only inside a check closure**; calling it anywhere else
is an error.

| Call | Returns |
|---|---|
| `probe.send(payload)` | the response map, having placed `payload` at the point. `payload` is a string (replace), or `#{ value, mode }` with `mode` one of `"replace"`, `"prefix"`, `"suffix"` |
| `probe.baseline()` | the response map for the point's unmodified request; cached per point, so asking twice costs one probe |
| `probe.raw(#{ method, url, headers, body })` | the response map for a request you compose yourself. **Same origin only** — for handshake-, header- and path-level work such as `OPTIONS` or a fixed path list |
| `probe.marker()` | the job's collision-resistant canary token: a fresh string on every call, so take it **once** into a variable and reuse it — a check whose oracle has to recognise its own canary (`ssti`, `cmdi`, `crlf`, `xxe`, `cors`, `header-reflection`) builds it from here rather than from `rand_text_alpha`, so evidence, hint and a later PoC all name the same token |
| `probe.budget_left()` | how many probes the job will still pay for |
| `probe.timing_fit(#{ requested_s: [..], observed_ms: [..] })` | `#{ correlated, slope, r }` |
| `probe.levenshtein_ratio(a, b)` | similarity of two strings, 0.0 to 1.0 |

Every response map is `#{ status, headers, body, elapsed_ms, flow_id }`.
`headers` is a **map of lower-case header name to value**, so
`reply.headers["content-type"]` is how you read one; a header the response did
not carry is absent, so check the type before using it.

Encoding is not your problem. `probe.send` hands the payload to the lane, which
re-serialises the form, JSON, XML or multipart body, re-encodes the query or
path, and recomputes `Content-Length`. Never build a `?param=` URL by hand and
never reach for `http.send`: a hand-built URL only ever tests query points, and
the same check then cannot run against a JSON field or a cookie.

### The verdict

Return a map:

| Key | Values |
|---|---|
| `outcome` | `vulnerable`, `clean`, `inconclusive`, `error` — required |
| `confidence` | `tentative` (the default when you omit it), `firm`, `certain` |
| `evidence` | `#{ payload, matched }` — what you sent and what matched. `matched: ()` when nothing did |
| `detail` | one or two plain sentences an operator can act on |
| `poc_hint` | optional, below |
| `location` | optional `#{ path, name }` — what inside the target this verdict is about, so an origin-scoped audit that finds several things dedupes them apart (`paths` uses it) |

Those six are the whole vocabulary: any other key turns the run into an `error`
verdict naming it. `more` is **not** one of them — a check with several
findings returns an **array** of verdict maps, and the bridge reads the first
as the verdict and the rest as its `more` siblings.

Returning a **plain string** instead of a map is read as `inconclusive` with the
string as `detail`. That keeps an old or half-finished script from breaking a
run; it is not a shape to write new checks in.

`inconclusive` is a real answer and is worth using: a refused probe, a throttled
origin, an unstable page or a missing `Allow` header is not a clean bill of
health.

### The PoC hint

A `vulnerable` verdict at `firm` or better that supplies a `poc_hint` is what
turns an issue into a **reproduced** finding: the engine builds a PoC from the
probe request with your matchers, runs it once, and writes a finding record only
if the reproduction passes. No hint, or a reproduction that does not pass, means
an issue and no finding record.

```rhai
poc_hint: #{
    matchers: [ #{ type: "word", word: want, part: "body" } ],
    control: #{
        payload: tag,
        matchers: [ #{ not: #{ type: "word", word: want, part: "body" } } ],
    },
},
```

The matcher vocabulary is the PoC loader's own, so a hint is a PoC assertion
already: `type` is `status`, `word`, `regex`, `dsl` or `browser-eval`, with the
matching field beside it (`status`, `word`, `regex`, `dsl`, or `expr` plus
`equals`), and `part` one of `body`, `header`, `all` for the `word` and `regex`
forms. `matchers` is required and is a **list**, which the loader reads as an
implicit `all`. Combine explicitly with `all` and `any`; negate either with
**`not:`** wrapping a matcher or with `negative: true` beside it — the scripts
here use `not:`, because it reads as what it is when the matcher is nested.
The optional `control` re-runs with a harmless payload and must *not* match,
which is what separates a real finding from a page that always contains your
word.

The classes that **must** supply a hint are `sqli`, `ssti`, `cmdi`,
`path-traversal`, `crlf` and `xxe` — the ones whose issues are worth nothing
without a reproduction.

### Budget and timing

A check never waits. There is no `sleep` in this directory and there must not
be: the host runs the probe and hands you `elapsed_ms`, and a check that sleeps
burns the job's wall budget for every point it visits. For a timing technique,
send the delay payloads, collect the `elapsed_ms` values, and give the pairs to
`probe.timing_fit`, which applies the alternating long/short correlation rule
rather than trusting one slow response.

The host enforces the limits around you: a per-check wall budget (the profile's
`check_timeout`, 60 s by default), a per-probe timeout, and the job's probe
budget — `probe.budget_left()` tells you what is left, and a probe beyond it is
refused rather than silently dropped. Keep a check inside the `cost` it
declares.

### Two Rhai rules every script here follows

A top-level `const` with a literal value (`const SQL_ERR = "(?i)…"`, `const PATHS
= [...]`) may be read inside hooks and inside the `load(reg)` closures: the
engine resolves such names inside functions from the script's constants. A
constant computed by a call is not visible in functions; a parameter or `let` of
the same name shadows the constant; and the constant is read-only there, so
mutate a copy (`let p = PATHS; p.push(x)`).

Second, a closure captures every outer name when it is *created*, so a closure
that names an optional namespace (`l4` with the L4 layer off) fails at load
before its `try` can catch anything; the `l4/` scripts call `l4` from a named
function and keep the `try` in the closure.

## Writing your own

Each file is plain Rhai using the host API in `docs/design/languages/rhai.api.json`.
Passive detectors use the `on_request` / `on_response` / `on_ws_*` hooks and
`finding(#{ … })`; active checks use `reg.add_check` and `probe.*` as above; L4
scripts register a command in `load(reg)` and call the scope-gated `l4.*` verbs.

Three tests hold the catalogue to this contract. The compile-and-run test in
`crates/aitm-plugin-rhai/tests/bundled_scripts.rs` validates every file here and
asserts that each `active/` script registers at least one **check** (and each
`l4/` script a command). `crates/aitm/tests/bundled_startup.rs` loads the whole
catalogue the way the binary does at startup, with and without the L4 layer, and
pins the registered verb names. `crates/aitm-scan-checks-http/tests/rhai_catalogue_sweep.rs`
sweeps the `active/` directory: one check per file, meta that deserialises, a
parsable hint for every must-hint class, no `sleep(`, no `add_command`, and the
tables above listing exactly the ids the catalogue declares — this README is
part of the contract, so a new check that is not in its table fails the build.
