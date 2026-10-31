# Bundled security-detection script catalogue design

**Status:** Approved — 2026-10-30 (self-approved under autonomous-operation mandate)
**Research inputs:** `docs/research/05-synthesis.md`, `docs/design/languages/rhai.api.json`, existing addon examples `crates/aitm/examples/addons/`
**Implementation under review:** branch `feat/bundled-detection-catalogue` (retroactive spec; the code already exists and this document describes it)

## Intent

A fresh aitmproxy install starts with no detection logic, so it observes traffic
but flags nothing until an operator writes or imports Rhai scripts. This feature
ships a first-party catalogue of detection scripts that load by default, giving a
clean install a working passive scanner for in-scope traffic plus a set of
operator/agent-invoked active and L4 confirmation checks. The catalogue covers
the OWASP Top 10 and other common weaknesses across HTTP/HTTPS, WebSocket, and
L4. It must do this without weakening aitmproxy's deny-by-default posture: nothing
that auto-loads may emit traffic or mutate a flow on its own.

## Goals

- A fresh install flags common findings on in-scope traffic with zero setup.
- The catalogue lives in-tree at `scripts/bundled/` and installs beside the
  binary at `share/aitm/scripts` for every packaged target.
- Passive HTTP/HTTPS and WebSocket detectors (observe-only) load and run
  automatically on in-scope flows.
- Active HTTP checks and L4 checks ship too, but register operator/agent-invoked
  commands only; loading them arms no automatic behaviour.
- An operator can disable the whole catalogue, point it at a custom directory, or
  override an individual bundled script with a declared `scripts:` entry.
- Every shipped script is guarded against shipping broken by an automated test.

## Non-goals

- No new host-API verbs, hooks, or engine capabilities: the scripts use only the
  existing Rhai host API documented in `docs/design/languages/rhai.api.json`.
- No scanning orchestration, scheduling, or UI surface for the catalogue beyond
  the existing script-loading, findings, and command mechanisms.
- No change to scope, rate-limiting, capability, or trust gates; the catalogue
  rides on the gates that already exist.
- No weaponising/exploitation payloads: active checks confirm a bug, they do not
  exploit it.
- No per-protocol expansion of the sandbox/capability model here (tracked
  separately for new MITM protocols and L4).

## Anti-goals

- Auto-loading anything that sends outbound traffic or mutates a request/response
  without explicit operator/agent invocation. This would silently weaken
  deny-by-default and is the single outcome that makes the feature a failure even
  if every detector works.
- Time-based blind detection (anything that depends on `sleep` or a wall clock),
  which the hardened engine does not and must not expose.
- Shipping a script that fails to compile under the real hardened engine, or a
  passive detector that raises a runtime error on a normal flow.
- Loading the catalogue in a way the operator cannot turn off or redirect.

## Constraints

- **Deny-by-default is inviolable.** Auto-loaded scripts must be observe-only.
- **Hardened engine only.** Scripts run under the production Rhai engine with its
  limits; no clock, no `sleep`, no filesystem, no network except the scope- and
  rate-gated host verbs.
- **Scope / rate / capability gates.** Active checks send only through the
  proxy's scope- and rate-gated `http.send`; L4 checks go through `l4.*`, which
  require the L4 layer enabled, the target in L4 scope, and the L4
  Inject/Capture capability.
- **Discovery must be relocatable.** The binary and its catalogue move together;
  discovery is relative to the executable, mirroring the obscura engine's
  sibling-binary discovery, with a dev-checkout fallback.
- **Human-authorable.** Each script is plain, readable Rhai a person can edit,
  consistent with the project's human-friendly scripting requirement.
- **Packaging parity.** The macOS tarball (`scripts/package.sh`) and the Linux
  packages (`scripts/package-linux.sh` + `scripts/nfpm.yaml`) must both install
  the catalogue to the discovered location.

## Design

### Catalogue layout (`scripts/bundled/`)

Four subdirectories, loaded recursively:

- `http/` — 27 passive HTTP/HTTPS detectors. Each is observe-only: it implements
  `on_request` / `on_response`, reads the flow, calls `flow.mark(...)` and
  `finding(#{ ... })`. No `http.send`, no mutation of request/response.
- `ws/` — 4 passive WebSocket detectors using `on_ws_start` / `on_ws_message`,
  same observe-only posture.
- `active/` — 15 active HTTP checks. Each registers a `check.*` command in
  `load(reg)` via `reg.add_command(...)`. The command body runs only when
  invoked, sends a few requests through `http.send`, and confirms a bug with
  benign, detection-grade payloads, then records a `finding` and returns a
  human-readable verdict string.
- `l4/` — 3 L4 checks (`l4.recon`, `l4.tcp_probe`, `l4.udp_probe`) that register
  `l4.*` commands and use `l4.*` host verbs (e.g. `l4.send_recv`).

A `scripts/bundled/README.md` documents the posture and carries per-script tables
(script → detects → OWASP mapping) for all four groups.

### Posture decisions (the load-by-default safety argument)

1. **Passive detectors are observe-only, therefore safe to auto-enable.** They
   send no outbound traffic and mutate no request or response; they only read,
   `mark`, and `finding`. Auto-loading them does not change deny-by-default, which
   is why they ship enabled. *(This is the core rationale the whole feature rests
   on.)*
2. **Active and L4 scripts auto-load but arm nothing.** Loading one only
   registers its command; the probing code runs solely on explicit invocation and
   remains scope-/rate-/capability-gated. Because loading arms no behaviour, they
   can also ship by default without weakening posture.
3. **No time-based blind detection.** The sandboxed engine exposes no clock and
   blocks `sleep`, so active checks confirm bugs by error signature, boolean/
   length differential, evaluated marker, or reflected/returned content instead
   of timing. Payloads are benign detection conditions (e.g. a single quote,
   `1=1`/`1=2`, an arithmetic marker, a split `echo` marker, reading a universal
   marker file); they confirm, they do not weaponise.
4. **Discovery mirrors the obscura sibling-binary pattern.** The install location
   is `share/aitm/scripts` beside the executable.
5. **Operator control.** `AITM_NO_BUNDLED_SCRIPTS` disables the catalogue;
   `AITM_BUNDLED_SCRIPTS` points discovery at a custom directory; a declared
   `scripts:` entry overrides a bundled file of the same canonical path.

### Loader module (`crates/aitm/src/bundled.rs`)

New module exported from `crates/aitm/src/lib.rs` (`pub mod bundled;`). Public
surface:

- `pub const BUNDLED_DIR: &str = "AITM_BUNDLED_SCRIPTS";` — custom directory
  override.
- `pub const NO_BUNDLED: &str = "AITM_NO_BUNDLED_SCRIPTS";` — opt-out; truthy
  values are `1` / `true` / `yes` (trimmed, case-insensitive).
- `pub fn discover_dir(exe: Option<&Path>, lookup: impl Fn(&str) -> Option<String>) -> Option<PathBuf>`
  — resolution order:
  1. If `NO_BUNDLED` is truthy, return `None` (opt-out wins even if an override is
     set).
  2. If `BUNDLED_DIR` is set, use it when it is a directory, else `None`.
  3. Otherwise probe candidates relative to the executable's directory and return
     the first that is a directory.
- `pub fn append(cfg: &mut RhaiConfig, dir: &Path)` — walk `dir` recursively,
  collect every `*.rhai`, name-sort, and push each as an enabled `ScriptEntry`,
  skipping any path a declared entry already names (compared after
  `canonicalize`, so the operator's entry and its options win). Non-`.rhai` files
  are ignored; a missing/unreadable directory appends nothing.
- `pub fn apply(cfg: &mut RhaiConfig, lookup: impl Fn(&str) -> Option<String>)` —
  resolve the current executable (canonicalized where possible), call
  `discover_dir`, and `append` when a directory is found.

The candidate list (relative to the executable directory), in order:

1. `<exe_dir>/share/aitm/scripts` — beside the binary (macOS tarball; Linux lib
   dir).
2. `<exe_dir>/../share/aitm/scripts` — `bin/` + `share/` sibling layout.
3. `<exe_dir>/../../share/aitm/scripts` — e.g. `/usr/lib/aitmproxy/aitm` →
   `/usr/share/aitm/scripts`.
4. `<exe_dir>/../../scripts/bundled` — dev-checkout fallback
   (`target/<profile>/aitm` → repo `scripts/bundled`).

The `lookup` closure is injected so unit tests never touch the real process
environment.

### Startup wiring (`crates/aitm/src/main.rs`)

Inside `run()`, immediately after `env::apply_rhai(&mut rhai_cfg, ...)`, call
`aitm::bundled::apply(&mut rhai_cfg, |k| std::env::var(k).ok());`. Ordering is
load-bearing: config-file and `AITM_SCRIPTS`-declared entries are already in
`rhai_cfg.scripts`, so the bundled catalogue is appended after them and the
declared-wins dedup in `append` lets an operator override or disable any single
bundled script.

### Packaging

- `scripts/package.sh` (macOS tarball): stage `scripts/bundled/` into
  `$stage/share/aitm/scripts` and add `share` to the `tar` payload so the
  catalogue ships beside `aitm`.
- `scripts/package-linux.sh`: copy `scripts/bundled/` into
  `$libdir/share/aitm/scripts` (exe_dir = `/usr/lib/aitmproxy`) and set shipped
  files to mode 644.
- `scripts/nfpm.yaml`: add a `contents` entry mapping the staged
  `share/aitm/scripts` tree to `/usr/lib/aitmproxy/share/aitm/scripts`.

### Test guard (`crates/aitm-plugin-rhai/tests/bundled_scripts.rs`)

Three integration tests over the real engine and loader:

- `every_bundled_script_compiles` — every `*.rhai` under `scripts/bundled/`
  validates (compiles) under the real hardened engine; asserts a floor of at
  least 20 scripts found.
- `passive_scripts_run_without_error_and_record_findings` — loads each `http/`
  and `ws/` detector, dispatches `Request`/`Response` (over both an `http` and an
  `https` flow) and `WsStart`/`WsMessage` against deliberately vulnerable flows;
  asserts no runtime error from any detector and at least 10 findings recorded in
  aggregate.
- `command_scripts_register_their_commands` — every `active/` and `l4/` script
  validates with registers and registers at least one command.

## Acceptance criteria

1. **AC1 — Catalogue exists and is grouped.** `scripts/bundled/` contains a
   `README.md` and four subdirectories: `http/` (27 passive detectors), `ws/` (4
   passive detectors), `active/` (15 `check.*` scripts), `l4/` (3 `l4.*`
   scripts). Observable by listing the tree.
2. **AC2 — Everything compiles under the hardened engine.** The
   `every_bundled_script_compiles` test passes: every bundled `*.rhai` validates
   under the real engine, with at least 20 files found.
3. **AC3 — Passive detectors never mutate a flow or emit traffic.** No script in
   `http/` or `ws/` calls `http.send`/`l4.*` or mutates the request/response; it
   only reads, `mark`s, and records `finding`s. The
   `passive_scripts_run_without_error_and_record_findings` test runs every passive
   detector over vulnerable `http`, `https`, and WebSocket flows with zero runtime
   errors.
4. **AC4 — Passive detectors actually detect.** The same test records at least 10
   findings in aggregate over the vulnerable flows.
5. **AC5 — Loads by default.** With no env override and the catalogue present at a
   discovered location, `bundled::apply` appends every bundled `*.rhai` as an
   enabled `ScriptEntry` onto `rhai_cfg.scripts` at startup, after config-file and
   `AITM_SCRIPTS` entries.
6. **AC6 — Opt-out works.** `AITM_NO_BUNDLED_SCRIPTS=1` (or `true`/`yes`) makes
   `discover_dir` return `None` and the catalogue loads nothing, even when
   `AITM_BUNDLED_SCRIPTS` is also set. Covered by
   `discover_honours_override_and_opt_out`.
7. **AC7 — Custom directory override works.** `AITM_BUNDLED_SCRIPTS=/path` makes
   discovery load from that directory when it exists, bypassing the probed
   candidates. Covered by `discover_honours_override_and_opt_out`.
8. **AC8 — Declared entries win.** A `scripts:` entry naming the same canonical
   path as a bundled file is not duplicated; the declared entry (and its options)
   is kept. Covered by `append_walks_recursively_and_dedups_declared`.
9. **AC9 — Recursive, `.rhai`-only discovery.** `append` walks subdirectories
   recursively and ignores non-`.rhai` files. Covered by
   `append_walks_recursively_and_dedups_declared`.
10. **AC10 — Active checks are invoke-only and register a command.** Every
    `active/` script registers at least one `check.*` command in `load(reg)` and
    performs no work until invoked. Covered by
    `command_scripts_register_their_commands`.
11. **AC11 — Active checks probe through the gated client only.** Active checks
    send exclusively via `http.send` (scope- and rate-gated) and use benign
    detection-grade payloads (error/boolean/marker/content), never time-based
    blind techniques.
12. **AC12 — L4 checks register a command and are capability-gated.** Every `l4/`
    script registers an `l4.*` command, acts only when invoked, and uses `l4.*`
    host verbs that require the L4 layer enabled, the target in L4 scope, and the
    L4 Inject/Capture capability. Registration is covered by
    `command_scripts_register_their_commands`.
13. **AC13 — Discovery mirrors sibling-binary layout.** `discover_dir` probes, in
    order, `share/aitm/scripts` beside the executable, one level up, two levels
    up, then the dev-checkout `scripts/bundled` fallback, returning the first
    directory that exists.
14. **AC14 — Packaging installs the catalogue.** `scripts/package.sh`,
    `scripts/package-linux.sh`, and `scripts/nfpm.yaml` each place the catalogue
    at `share/aitm/scripts` beside the installed binary so default discovery finds
    it.
15. **AC15 — README documents the posture and the catalogue.**
    `scripts/bundled/README.md` states the observe-only posture of passives, the
    invoke-only/gated posture of active and L4 checks, the opt-out/override env
    vars, and per-script tables with OWASP mappings.
16. **AC16 — The Rust gate passes.** `cargo fmt --check`, `cargo clippy
    --all-targets -- -D warnings`, and `cargo test` all pass on the branch.

## Left to the builder

This is a retroactive spec, so the implementation is fixed; for any future
revision the following are the builder's call without returning to Matt:

- The exact set, names, and severity/tag choices of individual detectors, as long
  as the posture and OWASP coverage hold.
- The precise regexes, thresholds (e.g. the SQLi boolean length threshold), and
  verdict strings inside each script.
- The exact numeric floors in the test guards (currently ≥20 scripts, ≥10
  findings), provided they remain meaningful non-trivial lower bounds.

## Open questions

1. **Directory traverse bits in the Linux package.** `scripts/nfpm.yaml` maps the
   `share/aitm/scripts` tree with `file_info.mode: 0o644`. Confirm nfpm still
   gives the intermediate directories a traversable (executable) mode in the
   installed `.deb`/`.rpm`; if 644 is applied to directories, discovery could fail
   on installed Linux packages. (`package-linux.sh` itself chmods only `-type f`,
   so the staging side is fine — this is specifically about the nfpm entry.) Flag,
   not a blocker for the spec.
