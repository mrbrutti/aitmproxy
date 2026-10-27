# aitmproxy PoC language design

**Status:** approved (2026-10-27 by Matt)
**Research inputs:** `docs/research/02-nuclei.md`, `docs/research/01-mitmproxy.md`, `docs/research/05-synthesis.md`
**Companion specs:** platform — `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md`; plugin system — `docs/superpowers/specs/2026-10-27-aitmproxy-plugin-system-design.md`

## Intent

The PoC artifact is aitmproxy's key differentiator: a **self-contained,
declarative document** that reproduces a known finding deterministically, runnable
with **only aitmproxy** (no agent). Following Matt's principle — agent-first but
human-readable, human-usable, and flexible — and mirroring nuclei's own evolution
(declarative YAML that grew a JS `flow` escape hatch for real control flow), the
PoC language is **declarative-first, flexible via a scripting escape hatch**:

- a readable YAML document with `id` / `info` / `variables` / ordered `steps` and
  a **matcher/extractor DSL** for assertions, that a person can hand-author and an
  agent can generate; plus
- an optional **`script` step (Rhai)** for genuine control flow, reusing the exact
  scripting API defined in the plugin-system spec so a person learns one surface.

This spec defines the complete on-disk language (schema, templating, DSL, step
types, assertion model, grammar) and how it maps onto the platform spec's
`aitm-poc` Rust model. The declarative subset is **Milestone 1** (it satisfies the
platform's AC13–AC15/AC18); the `script` step lands with the **Rhai runtime in
Milestone 2** (shape decided now).

## Goals

- **Human-readable and hand-authorable**: a security tester can read and write a
  PoC by hand.
- **Agent-generatable**: `poc.build` turns a captured flow + chosen variables and
  assertion into this document.
- **Deterministic**: given the same variables and target, a run's pass/fail is
  reproducible.
- **Runnable with only aitmproxy**: `poc.run` executes every step via the proxy's
  own client and the embedded browser; no agent, no external service, no original
  captured flow required.
- **Flexible**: anything the declarative layer cannot express is reachable via a
  `script` step using the shared Rhai API (M2).
- **Designed for signing/validation later** (supply-chain safety, nuclei
  precedent): the document is a stable, serializable artifact a signature can
  cover.

## Non-goals

- **Not a scanner/discovery language.** The PoC reproduces a *known* finding; it
  does not crawl, enumerate injection points, or hunt for unknown bugs. (The
  matcher/extractor vocabulary is deliberately reusable by a future scanner
  plugin — platform spec — but this language is reproduction.)
- **No remediation/fix prose** in the artifact (platform Non-goal); `info` carries
  identification metadata only.
- The **`script` step is not executed in M1** — only its grammar is fixed. M1
  `poc.run` executes the declarative subset (http/browser/extract + matchers).
- This spec does not redefine the `aitm-poc` Rust types (`Poc`, `Step`,
  `Assertion`, `ExtractSource`, `PocRunResult`, builder/runner) — it defines the
  **on-disk language** that serializes to/from them, and references them.
- No signing implementation now (deferred, designed-for).

## Anti-goals

- A format only an agent can read, or only a machine can write. If a human cannot
  comfortably read and edit a PoC, the readability principle has failed.
- A PoC that needs the agent, the network, or the original flow to replay
  (platform anti-goal). Non-self-contained or non-deterministic PoCs are failures.
- A DSL that quietly becomes a general programming language. Real control flow
  belongs in the explicit `script` step, not smuggled into matchers.
- Two different scripting surfaces (one for plugins, one for PoCs). The `script`
  step **must** reuse the plugin-system Rhai API verbatim.
- Matcher/extractor semantics that drift from nuclei's familiar vocabulary without
  reason — ecosystem familiarity is a feature.

## Constraints

- **Format: YAML (decided by Matt).** YAML is the on-disk format — human-friendly,
  diffable, and familiar from the nuclei/mitmproxy ecosystem (the reason Matt
  chose it). This is a settled decision, not a tentative default. **It supersedes
  the platform spec's earlier TOML call** (reconciled there).
- **Serde round-trip:** the YAML must deserialize into the `aitm-poc` `Poc` model
  and re-serialize equal (platform AC13), so the language and the Rust model stay
  in lockstep.
- **Determinism:** no implicit time/randomness in the declarative core; any
  randomness is via explicit DSL helpers seeded for reproducibility, or confined
  to a `script` step.
- **Security/scale:** every active step (http/browser) runs through the platform
  scope, rate-limit, and SSRF guards; a `script` step runs sandboxed under the
  plugin-system Rhai sandbox.
- **Scripting surface:** the `script` step uses the **plugin-system Rhai API**
  (hook-less body form; same host functions `log`/`http`/`browser`/`store`/`scope`
  and DSL helpers). Cross-referenced, not duplicated.
- **Workflow:** every change travels the seven stages in `docs/superpowers/WORKFLOW.md`.

## Design

### Document structure (mirrors nuclei)

A PoC is one YAML file. Top level:

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | string (no spaces) | yes | unique PoC identifier |
| `info` | map | yes | identification metadata (below) |
| `variables` | list of var defs | no | reusable `{{placeholders}}`, with defaults |
| `steps` | ordered list | yes | http / browser / extract / script steps |
| `success` | assertion | yes | what "triggered" means (the pass condition) |

`info` block:

| Key | Type | Meaning |
|---|---|---|
| `name` | string | human title |
| `author` | string | optional |
| `severity` | enum `info\|low\|medium\|high\|critical` | maps to `Severity` |
| `description` | string | what the finding is (no fix prose) |
| `reference` | list of string | URLs/CVE/CWE refs |
| `tags` | list of string | selection/reporting |
| `cwe` | string | optional |
| `metadata` | map | arbitrary `key: value` |

Maps to `aitm-poc::Poc { id, info: PocInfo, variables, steps, success }`.

### Variables and templating

- A `variables` entry: `name` (string), `default` (scalar, optional),
  `description` (string), `required` (bool, default false). Maps to
  `aitm-poc::Variable`.
- **Placeholders `{{name}}`** interpolate anywhere in step strings (urls, headers,
  bodies, selectors, expressions). Resolution order: caller-supplied `VarBindings`
  (e.g. `poc.run --var payload=...`) override `variables` defaults.
- **Runtime placeholders** (nuclei-style, computed from the target at run time):
  `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}`, `{{Host}}`, `{{Port}}`,
  `{{Path}}`, `{{Scheme}}`.
- **DSL-evaluated variables:** a variable `default` may be a DSL expression
  wrapped in `{{ }}` (e.g. `{{rand_text_alpha(8)}}`), evaluated once at run start.
- **Extracted variables:** an `extract` with a `name` binds a variable for later
  steps (dynamic values like CSRF tokens, sessions); `internal: true` keeps it out
  of output (nuclei semantics).

Templating maps to the `aitm-poc::Template` trait (`render(input, vars)`).

### Step types

`steps` is an ordered list; each entry has exactly one of the step keys. Maps to
`aitm-poc::Step` (`Http` / `Browser` / `Extract`; `Script` is the M2 addition).

**`http` step** → `HttpStep`:

| Field | Type | Meaning |
|---|---|---|
| `method` | string | GET/POST/… |
| `url` or `path` | string | templated; `path` is relative to `{{BaseURL}}` |
| `headers` | map | templated |
| `body` | string | templated (use `raw` for full control) |
| `raw` | string | full raw HTTP text with placeholders (nuclei RAW mode) |
| `extract` | list | post-response extractors (below) |
| `matchers` | list | per-step matchers (below) |
| `matchers-condition` | `and\|or` | combine this step's matchers |

**`browser` step** → `BrowserStep` with one `action`:

| Action | Fields | Meaning |
|---|---|---|
| `navigate` | `url` | load a page (SSRF-guarded) |
| `click` | `target` (selector or `x,y`) | click |
| `type` | `selector`, `text` | type text |
| `eval` | `expr` | run JS, bind/assert its value |
| `screenshot` | `label` | capture PNG (the "vuln triggering" artifact) |

**`extract` step** → standalone `ExtractStep` (also usable inline in `http`):

| Field | Type | Meaning |
|---|---|---|
| `name` | string | binds a variable for later steps |
| `type` | `regex\|json\|kval\|dsl\|browser-eval` | extractor kind (`ExtractSource`) |
| `from` | `body\|header\|all` | `part` to extract from (http) |
| `regex` / `group` | string / int | for `regex` |
| `json` | string (JSONPath/jq) | for `json` |
| `kval` | string | header/cookie key (dashes→underscores) |
| `expr` | string | for `dsl` or `browser-eval` |
| `internal` | bool | pass between steps without printing |

**`script` step** → `ScriptStep` (**Milestone 2**, grammar decided now):

| Field | Type | Meaning |
|---|---|---|
| `script` | string (Rhai) | body using the plugin-system Rhai API |
| `name` | string | optional label |

The body runs sandboxed (plugin-system sandbox) with the shared host functions
(`log`, `http.send`, `browser.*`, `store.*`, `scope.*`) and DSL helpers, plus
read/write access to PoC variables via `vars.get(name)` / `vars.set(name, value)`.
It may `return pass`/`return fail` to contribute to `success`, or bind variables
for later steps. It cannot touch the filesystem/OS or bypass the guards.

### Matcher / extractor DSL (assertions)

Reuses nuclei's operator vocabulary, scoped to reproduction (and deliberately
reusable by a future scanner plugin — platform spec). Maps to `aitm-poc::Assertion`.

**Matcher types:**

| `type` | Payload | `Assertion` variant |
|---|---|---|
| `status` | int | `Status(u16)` |
| `word` | string(s), `encoding: hex?`, `part` | `Word { word, part }` |
| `regex` | pattern(s), `part` | `Regex { regex, part }` |
| `size` | int (content length) | via `Dsl` |
| `binary` | hex byte signature | via `Dsl`/`Word` hex |
| `dsl` | expression(s) over `status_code`, `body`, `all_headers`, `content_length`, extracted vars | `Dsl(String)` |
| `browser-eval` | `expr`, `equals` | `BrowserEval { expr, equals }` |

Matcher modifiers (nuclei semantics): `part` (`body` default / `header` / `all`),
`condition: and\|or` (within a matcher's values), `negative: true` (→ `Not`),
`internal: true` (precondition, not printed), `name` (labels the matcher).

**Extractor types:** `regex` (+`group`), `json` (jq/JSONPath), `kval`
(header/cookie), `dsl`, `browser-eval`. A `name`d extractor becomes a variable;
`internal: true` passes it between steps without printing.

**DSL helpers** (shared with the plugin-system Rhai API — one vocabulary): string
ops (`concat`, `contains`, `replace`, `to_lower`, `len`), encoding (`base64`,
`hex_encode`, `url_encode`, `html_escape`), hashing (`md5`, `sha256`, `hmac`),
regex (`regex`, `replace_regex`), random (`rand_text_alpha`, `rand_int`),
comparison (`equals_any`, `compare_versions`), `resolve`. Operators: comparison,
`=~` regex, logical, arithmetic, `in`, ternary. Values are strings; `to_number`
for math. (Grounded in `02-nuclei.md` §4.)

### Success / assertion model

- Top-level **`success`** is an assertion tree evaluated after all steps run; the
  PoC **passes iff `success` is true**. It composes matchers with `all` / `any` /
  `not` (→ `Assertion::All/Any/Not`). A bare matcher is allowed.
- Per-step `matchers` + `matchers-condition` evaluate within a step; a named step
  matcher can be referenced from `success` (nuclei matcher-name semantics), which
  is how multi-step PoCs reason across responses.
- For browser-triggered findings (XSS), `success` is typically a `browser-eval`
  asserting a marker is present in the page after the triggering navigation.
- A `script` step may contribute `pass`/`fail` that `success` references by the
  step's `name`.

### Mapping to the `aitm-poc` Rust model (no duplication)

| Language construct | `aitm-poc` type (platform spec) |
|---|---|
| document | `Poc` |
| `info` | `PocInfo` + `Severity` |
| `variables[]` | `Variable` |
| `steps[] http/browser/extract` | `Step::Http/Browser/Extract`, `HttpStep`/`BrowserStep`/`ExtractStep` |
| `steps[] script` (M2) | `Step::Script(ScriptStep)` — additive enum variant in M2 |
| matcher / `success` | `Assertion` (+ `BrowserEval`, `All/Any/Not`) |
| extractor `type` | `ExtractSource::Regex/JsonPath/Header/BrowserEval` |
| run result | `PocRunResult { passed, finding_capture, poc_path, screenshot_path, evaluated }` |

`poc.build` emits this YAML from a captured flow; `poc.run` deserializes it,
resolves variables, executes steps through the guards + proxy client + browser,
evaluates `success`, and writes the **three artifacts** (finding capture, the PoC
file, the screenshot). See platform data-flow 5 and 6.

### On-disk grammar

Every step/field above has a complete, copyable YAML form in the dedicated
**"Worked examples (normative reference shapes)"** section below — four full PoCs
covering the declarative reflected-XSS case, a multi-step extractor chain, an
HTTP-only matcher-based check, and the Rhai `script` escape hatch.

### Reproducibility and signing (deferred)

The YAML + its `aitm-poc` model are a stable, serializable artifact a detached
signature can cover (nuclei `-sign` precedent; platform spec defers the mechanism).
`poc.run` does not require signing in M1/M2; a future milestone adds
verify-on-load with a policy to refuse unsigned PoCs.

## Worked examples (normative reference shapes)

These four PoCs are **normative reference shapes**: implementers match them, the
serde model round-trips them (AC-L1), and humans can copy them as starting points.
They also **seed M1's functional tests and the bundled vulnerable/patched test
target** — Example 1 is the M1 end-to-end PoC (platform AC14/AC18); the target app
must expose the `/search` (reflected) and, for later milestones, `/login`+`/notes`
(stored) endpoints these examples assume. Each example ends with a one-line note
on what it demonstrates.

### Example 1 — reflected XSS, fully declarative (M1)

```yaml
id: reflected-xss-search-q
info:
  name: Reflected XSS in search 'q' parameter
  severity: high
  description: The 'q' parameter is reflected unescaped into the HTML response.
  reference:
    - https://owasp.org/www-community/attacks/xss/
  cwe: CWE-79
  tags: [xss, reflected]

variables:
  - name: target
    description: Base URL of the vulnerable app
    required: true
  - name: param
    default: q
    description: Reflected query parameter
  - name: marker
    default: "{{rand_text_alpha(8)}}"
    description: Unique marker to confirm script execution
  - name: payload
    default: "<script>window.__aitm='{{marker}}'</script>"
    description: XSS payload carrying the marker

steps:
  # 1. Send the injection and confirm the payload is reflected in the HTML.
  - http:
      method: GET
      url: "{{target}}/search?{{param}}={{url_encode(payload)}}"
      matchers-condition: and
      matchers:
        - type: status
          status: 200
        - type: word
          part: body
          word: "window.__aitm='{{marker}}'"

  # 2. Drive the browser to the same URL and confirm the script actually executed.
  - browser:
      action: navigate
      url: "{{target}}/search?{{param}}={{url_encode(payload)}}"
  - browser:
      action: screenshot
      label: xss-triggered

success:
  all:
    - type: word
      part: body
      word: "window.__aitm='{{marker}}'"
    - type: browser-eval
      expr: "window.__aitm"
      equals: "{{marker}}"     # marker observed in the live page == script ran
```

Demonstrates: variables + `{{placeholders}}`, an http matcher step and a browser
navigate/screenshot step, and a `browser-eval` success assertion — true against
the vulnerable target, false against the patched one (deterministic pass-vs-patch).

### Example 2 — multi-step with an extractor (CSRF/session chaining, M1)

```yaml
id: authed-profile-email-change
info:
  name: CSRF-token-chained profile update
  severity: medium
  description: Logs in, carries the session + CSRF token forward, and changes the email.
  tags: [auth, csrf, chaining]

variables:
  - name: target
    required: true
  - name: user
    default: tester
  - name: pass
    default: testpass
  - name: new_email
    default: "pwned+{{rand_text_alpha(6)}}@example.com"

steps:
  # 1. GET the login page; extract the CSRF token (internal: not printed).
  - http:
      method: GET
      url: "{{target}}/login"
      extract:
        - name: csrf
          type: regex
          from: body
          regex: 'name="csrf" value="([a-f0-9]+)"'
          group: 1
          internal: true

  # 2. POST credentials + the extracted token; extract the session cookie.
  - http:
      method: POST
      url: "{{target}}/login"
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: "user={{user}}&pass={{pass}}&csrf={{csrf}}"
      extract:
        - name: session
          type: kval
          kval: set_cookie     # Set-Cookie -> set_cookie (kval normalization)
          internal: true

  # 3. Use both carried values to perform the authenticated action.
  - http:
      method: POST
      url: "{{target}}/profile"
      headers:
        Content-Type: application/x-www-form-urlencoded
        Cookie: "session={{session}}"
      body: "email={{url_encode(new_email)}}&csrf={{csrf}}"
      matchers:
        - type: status
          status: 200

success:
  all:
    - type: word
      part: body
      word: "Email updated"
    - type: dsl
      dsl: "contains(body, new_email)"
```

Demonstrates: named `regex` and `kval` extractors with `internal: true`, and
`{{var}}` chaining of a CSRF token and session cookie across three sequential
http steps — the declarative multi-step/stateful pattern, no browser, no script.

### Example 3 — HTTP-only, matcher-based (matcher DSL surface, M1)

```yaml
id: exposed-actuator-env
info:
  name: Spring Boot actuator /env exposed
  severity: high
  description: The actuator env endpoint is reachable and leaks configuration.
  tags: [exposure, actuator, misconfig]

variables:
  - name: target
    required: true

steps:
  - http:
      method: GET
      url: "{{target}}/actuator/env"
      matchers-condition: and
      matchers:
        - type: status                 # status matcher
          status: 200
        - type: word                   # literal word matcher
          part: header
          word: "application/vnd.spring-boot.actuator"
        - type: regex                  # regex matcher
          part: body
          regex: '"activeProfiles"\s*:\s*\['
        - type: dsl                    # dsl matcher over response context
          dsl: "contains(body, 'propertySources') && status_code == 200"
        - type: word                   # negative matcher: must NOT look patched
          part: body
          word: "Whitelabel Error Page"
          negative: true

success:
  # all step matchers must hold (status + word + regex + dsl + negative word)
  - dsl: 'step("exposed-actuator-env") == "matched"'
```

Demonstrates: the full matcher DSL surface — `status`, `word` (header + body),
`regex`, `dsl`, and a `negative` matcher — combined with `matchers-condition: and`,
with no browser or script step.

### Example 4 — Rhai `script` escape hatch (real control flow, M2)

```yaml
id: stored-note-xss-authed
info:
  name: Authenticated stored XSS in notes
  severity: high
  tags: [xss, stored, authed]

variables:
  - name: target
    required: true
  - name: user
    default: tester
  - name: pass
    default: testpass
  - name: marker
    default: "{{rand_text_alpha(10)}}"

steps:
  # Declarative login, extracting the CSRF token for the script step.
  - http:
      method: GET
      url: "{{target}}/login"
      extract:
        - name: csrf
          type: regex
          from: body
          regex: 'name="csrf" value="([a-f0-9]+)"'
          group: 1
          internal: true

  # Script step: real control flow — only proceed if we got a token, then
  # authenticate, store the payload, and confirm it renders on a second visit.
  - script:
      name: post-and-confirm
      script: |
        if vars.get("csrf") == () {
          log.error("no CSRF token extracted");
          return fail;
        }
        // authenticate + store the payload (http.send is scope/rate-gated)
        http.send(#{
          method: "POST",
          url: vars.get("target") + "/login",
          headers: #{ "Content-Type": "application/x-www-form-urlencoded" },
          body: "user=" + vars.get("user") + "&pass=" + vars.get("pass")
               + "&csrf=" + vars.get("csrf")
        });
        let m = vars.get("marker");
        http.send(#{
          method: "POST",
          url: vars.get("target") + "/notes",
          headers: #{ "Content-Type": "application/x-www-form-urlencoded" },
          body: "note=<script>window.__aitm='" + m + "'</script>"
        });
        // visit the notes page in the browser and confirm execution (SSRF-gated)
        browser.navigate(vars.get("target") + "/notes");
        browser.screenshot();                 // artifact
        if browser.eval("window.__aitm") == m { return pass; }
        return fail;

success:
  # reference the script step's verdict by name
  - dsl: 'step("post-and-confirm") == "pass"'
```

Demonstrates: the `script` step using the **plugin-system Rhai API verbatim**
(`vars.get`, `log`, `http.send`, `browser.*`) for a conditional, stateful flow the
declarative layer can't express — the escape hatch, with the same scripting
surface a person learns once for plugins.

## Acceptance criteria

Observable via `cargo test` (integration tests stand up the bundled vulnerable +
patched reflected-XSS target from the platform spec). **AC-L1–AC-L7 are Milestone
1 (declarative subset). AC-L8 is Milestone 2 (script step).** These align with the
platform spec's AC13–AC15/AC18.

1. **AC-L1 — YAML round-trips (M1):** The example-1 reflected-XSS PoC deserializes
   from YAML into the `aitm-poc::Poc` model and re-serializes equal, and passes
   schema validation (platform AC13, now YAML).
2. **AC-L2 — Deterministic pass-vs-patched run (M1):** `poc.run` on example 1
   returns **pass** against the bundled vulnerable target and **fail** against the
   patched variant (platform AC14).
3. **AC-L3 — Three artifacts (M1):** A passing `poc.run` writes the finding
   capture, the YAML PoC file, and a valid-PNG screenshot (platform AC15).
4. **AC-L4 — Templating (M1):** `{{var}}` and runtime placeholders
   (`{{BaseURL}}`, `{{Hostname}}`) substitute correctly; a caller `--var` override
   beats the `variables` default (asserted on the rendered request).
5. **AC-L5 — Matcher DSL (M1):** `status`, `word`, `regex`, and `browser-eval`
   matchers evaluate to the expected boolean on known inputs; `negative`,
   `condition: and|or`, and `matchers-condition` combine as specified.
6. **AC-L6 — Extractor binds a later variable (M1):** A named `regex`/`json`
   extractor binds a variable that a subsequent step consumes (asserted by the
   later request carrying the extracted value); `internal: true` keeps it out of
   output.
7. **AC-L7 — Schema validation rejects malformed PoC (M1):** A PoC missing a
   required field (e.g. `id`) or with an unknown step type is rejected with a clear
   error, not a silent partial parse.
8. **AC-L8 — Script escape hatch runs sandboxed (M2):** The example-2 `script`
   step executes via the plugin-system Rhai runtime, can read/set variables and
   call guarded `http`/`browser`, contributes `pass`/`fail` to `success`, and
   cannot touch the filesystem or bypass the scope/SSRF guards (parity with
   plugin-system AC-P9/AC-P11).

## Left to the builder

- The precise JSON/YAML schema file (`poc-schema`) used for AC-L1/AC-L7 validation,
  and which nuclei DSL helpers from the shared vocabulary ship first (enough to
  satisfy AC-L5).
- JSONPath vs jq semantics for the `json` extractor, and the exact `kval`
  normalization rules.
- How `success` references a named step matcher / script verdict internally
  (`step(...)` / matcher-name resolution).
- The YAML↔`Poc` serde attribute mapping (tag names, enum representations).
- Error messages and line/column reporting for malformed PoCs.

## Open questions

*(None. The `script` step engine is **Rhai**, confirmed by Matt on 2026-10-27
(plugin-system spec). Format is **YAML, decided by Matt**. No questions remain.)*
