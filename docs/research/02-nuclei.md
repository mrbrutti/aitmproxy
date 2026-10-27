# nuclei — declarative check engine reference

Sources: github.com/projectdiscovery/nuclei README + docs.projectdiscovery.io/templates
(structure, matchers, extractors, http basic/payloads, workflows, helper-functions).
Repo key files: `SYNTAX-REFERENCE.md`, `DESIGN.md`, `FUZZING.md`, `nuclei-jsonschema.json`;
packages under `pkg/` (protocols, operators), `internal/`, `lib/`.

## 1. Template model

- A template is a single YAML file. Top level: `id` (unique, no spaces), `info`
  block (`name`, `author`, `severity`, `description`, `reference`, `tags`,
  `metadata` incl. search-engine queries like `shodan-query`, plus arbitrary
  `key:value`), then one or more protocol request blocks.
- Protocols: `http`, `headless` (browser), `dns`, `tcp`, `ssl`, `websocket`,
  `whois`, `file`, `code`, `javascript`. A file can hold multiple requests run in
  order.
- `variables` block defines reusable values (often DSL-evaluated) injected into
  requests. Runtime placeholders: `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}`,
  `{{Host}}`, `{{Port}}`, `{{Path}}`, `{{Scheme}}`, etc.

## 2. Matchers / extractors

- **Matcher types:** `status` (int), `size` (content length), `word` (literal,
  supports `encoding: hex`), `regex`, `binary` (hex byte sigs / magic bytes),
  `dsl` (expressions over `status_code`, `body`, `all_headers`, `content_length`…),
  `xpath`.
- `part` selects target (`body` default, `header`, `all`). Within one matcher,
  `condition: and|or`. Across matchers in a request, `matchers-condition: and|or`.
  `negative: true` inverts. `internal: true` makes a matcher/extractor a
  precondition that is not printed. `name` labels matchers (output
  `[template:name]`, and drives workflow branching).
- **Extractor types:** `regex` (+`group`), `kval` (header/cookie key:value,
  dashes→underscores), `json` (jq via gojq), `xpath` (+`attribute`), `dsl`. A
  `name`d extractor becomes a variable; `internal: true` passes dynamic values
  (CSRF tokens, sessions) between requests without printing. Since v3.1.4 an
  extracted value is usable by later extractors in the same request.

## 3. Request flow

- HTTP requests: `method`, `path` (list), `headers`, `body`. Also RAW request
  mode (full raw HTTP text with placeholders) — required for using named
  extractors as dynamic variables. Cookies reused across requests by default
  (`disable-cookie` to stop); redirects off by default (`redirects: true`,
  `max-redirects`, per-template not per-request).
- Multi-step: requests run sequentially; **req-condition** / numeric suffixes
  (`status_code_1`, `body_2`) let matchers reason across responses (all prior
  responses held in memory).
- Payloads/fuzzing: `payloads` (inline lists or wordlist files) with `{{name}}`
  placeholders; `attack` types `batteringram` (default, same value all
  positions), `pitchfork` (parallel sets), `clusterbomb` (full cross product).
  DAST mode (`-dast`, fuzz rules with part/type/mode/keys/values, sniper) fuzzes
  live traffic for unknown bugs; out-of-band via Interactsh.

## 4. DSL / helpers

- Rich expression language usable in matchers, extractors, variables, payloads,
  inside `{{ }}`. Categories: string ops (`concat`, `contains`, `replace`,
  `to_lower`, `len`…), encoding (`base64`, `hex_encode`, `url_encode`,
  `html_escape`), compression (`gzip`, `zlib`), hashing (`md5`, `sha256`, `mmh3`,
  `hmac`), regex (`regex`, `replace_regex`), random generators (`rand_text_alpha`,
  `rand_int`, `rand_ip`), date/time (`unix_time`), math/base conversion,
  comparison (`equals_any`, `compare_versions`), plus `generate_jwt`, AES-GCM,
  `resolve` (DNS). Operators: comparison, `=~` regex, logical, arithmetic, `in`,
  ternary. Values are strings — convert with `to_number` for math.

## 5. Execution at scale

- Engine defaults: global rate limit 150 req/s (`-rl`); 25 templates in parallel
  (`-c`); 25 hosts/template batch (`-bs`); headless 10/10; JS runtimes 120.
  Per-host rate limiting + back-off; host skipped after 30 errors (`-mhe`); 10s
  timeout, 1 retry. Template matching by path/tag/id/author/severity/protocol.
  Templates can be `-validate`-d and `-sign`-ed (unsigned can be disabled) — a
  trust/reproducibility mechanism. Output: text/JSON/JSONL/Markdown/SARIF/PDF.

## 6. Workflows & chaining

- `workflows:` chains separate template files/tags. Conditional execution:
  `subtemplates` run only if the base `template` matched, or only when a specific
  named matcher fired (matcher-name based), and can nest multi-level. Workflow
  templates share a cookie jar and key-value store, so a named extractor from one
  template feeds a later one. (This is cross-template; within one template,
  sequential requests + the JS-based `flow` keyword orchestrate steps and
  multi-protocol logic programmatically.)

## 7. Reproducibility / automation — and limits

- **Strengths for our use case:** fully declarative single-file checks (easy to
  version, diff, share, sign); protocol-agnostic structure with a uniform
  matcher/extractor/condition vocabulary; deterministic placeholders +
  named/internal extractors give reproducible request chaining; tags/severity/
  metadata make selection and reporting automatable; already has a `headless`
  (browser) protocol and DAST fuzzing + Interactsh, which maps well to driving a
  proxy/browser.
- **Limitations to design around:** YAML + an ad-hoc DSL gets awkward for real
  control flow (hence the bolted-on JS `flow` keyword and `code`/`javascript`
  protocols — consider a first-class scripting/flow layer from the start);
  req-condition keeps all prior responses in memory (costly); redirects/session
  configured per-template not per-request; matcher expressiveness is bounded by
  the DSL; stateful multi-step auth flows are clunky; signing exists precisely
  because free-form templates are a supply-chain risk.

## Design takeaways for aitmproxy

- Keep the declarative template + separated matchers/extractors/conditions core.
- Model protocols as pluggable executors sharing one operator vocabulary.
- Make dynamic-variable passing and a real flow/orchestration layer first-class
  rather than bolt-on.
- Add a **proxy-capture mode** (turn observed requests into reproducible
  templates) and a browser executor alongside HTTP.
- Build in rate-limit/concurrency/per-host back-off and signing/validation early.
