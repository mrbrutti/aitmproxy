# aitmproxy Milestone 2 — embedded obscura browser + CA management design

**Status:** draft
**Research inputs:** `docs/research/06-obscura-embedding.md`,
`docs/research/experiments/2026-10-27-obscura-ca-mitm.md`,
`docs/research/07-ca-install.md` (CA install/uninstall per platform; on branch
`claude/ca-commands-d9b1bc`, to be cherry-picked to `main` with this spec),
the obscura `--ca-cert` flag design note from the spike session (side-session
note `obscura-ca-cert-flag-DESIGN.md`, folded into §D2), and the approved
platform spec `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md`
(the architecture baseline; this spec amends its browser section, see §D12).
**Supersedes:** the draft `2026-10-27-ca-commands-design.md` on branch
`claude/ca-commands-d9b1bc`, whose content is folded into §D8–§D9 here. That
branch is retired and will not merge; this spec is the single design of
record for the browser swap **and** the `ca.*` command family.
**Code this changes:** `crates/aitm-browser/src/{driver.rs,config.rs}` (+ new
`obscura.rs`), `crates/aitm-proto-http/src/ca.rs` (one accessor),
`crates/aitm-core/src/{config.rs,ctx.rs,registry.rs}` (additive),
`crates/aitm/src/{main.rs,wire.rs}` (+ new `config_file.rs`, `env.rs`,
`render.rs`), `crates/aitm-cli/src/dispatch.rs`, `crates/aitm-mcp/src/server.rs`,
new crate `crates/aitm-ca`, `crates/aitm-browser/tests/*`,
`crates/aitm/tests/{frontends.rs,e2e_reflected_xss.rs}`, and a fork of obscura.

## Intent

Milestone 1 drives a **system-installed Google Chrome** over CDP. That makes
aitmproxy depend on a ~200 MB external browser the operator must install, and
it trusts the MITM CA only through CDP `Security.setIgnoreCertificateErrors`.
Milestone 2 replaces Chrome with an **embedded obscura engine** — a pure-Rust
headless browser (V8 via `deno_core`, its own HTTP stack, a CDP server) that we
ship with aitmproxy — behind the **same `BrowserDriver`, the same six
`browser.*` commands, and the same MCP tools**, so the agent interface does not
change and the tool becomes self-contained and lighter. The research note
found the one blocker: obscura's HTTP clients verify TLS against bundled
webpki roots only, with no documented way to trust a private CA. The spike
proved trust *can* be granted through the undocumented `SSL_CERT_FILE`
environment variable, and Matt **rejected** that path (and the OS trust store,
which obscura ignores). M2 therefore **forks obscura and adds a first-class
`--ca-cert` flag**, runs the forked binary as a managed child process, and
keeps the Chrome driver as a selectable fallback.

Because the embedded engine trusts the CA one way and native browsers another,
M2 is explicit about **two trust paths**. Path 2 is `--ca-cert`, for the
embedded engine. Path 1 is the OS trust store, for native Chrome/Safari/curl
and any other client the operator points at the proxy — and nothing trusts
aitmproxy's root until the user puts it there, which the platform spec names
as "the single biggest adoption-friction point in mitmproxy". M2 therefore
adds one command family, `ca.*`, registered once in the shared `Registry` so
`aitm ca …` on the CLI and the `ca.*` MCP tools are the same code: export the
root certificate, report its fingerprint and whether it is installed, and
install or remove it from the OS trust store by shelling out to the
platform's own tools. Installing a root CA is also what malware does (MITRE
T1553.004), so the family keeps a human in the loop: the OS authorization
prompt is never bypassed, the CLI asks before acting, an agent over MCP is
refused by default, and every CA operation — including a refused one — is
written to an audit log with the certificate's fingerprint.

## Goals

Browser (Path 2):

- `aitm` starts with **no browser installed on the machine** and
  `browser.navigate` / `click` / `type` / `screenshot` / `eval` / `get_dom`
  work against the embedded obscura engine; the MCP tool names and schemas of
  the six `browser.*` tools are byte-for-byte unchanged.
- HTTPS pages loaded by obscura are **decrypted and captured** by aitmproxy —
  the navigation, **and** every sub-resource: page-JS `fetch()`, XHR, images,
  scripts. Nothing obscura fetches while rendering bypasses the proxy.
- obscura trusts aitmproxy's root CA **only** through the forked binary's
  `--ca-cert <path>` flag — not `SSL_CERT_FILE`/`SSL_CERT_DIR`, not the OS
  store — and the fork keeps strict verification otherwise (built-in roots
  retained, hostname/SAN checked, no "accept invalid certs").
- An **unpatched upstream obscura** is refused at startup with a clear error,
  never discovered mid-run as `UnknownIssuer`.
- The forked obscura is a **managed child**: spawned by aitmproxy with exactly
  the flags and environment aitmproxy chose, health-checked at start, torn
  down on shutdown, never orphaned by an orderly exit or a signal.
- **Hybrid fallback:** `browser.engine = obscura | chrome` selects the driver;
  `obscura` is the default; the Chrome path keeps its M1 behavior.
- The reflected-XSS end-to-end (platform AC18) runs over obscura.
- The `--ca-cert` patch is **upstreamable**: one PR to `h4ckf0r0day/obscura`
  plus two companion issues (undocumented `SSL_CERT_FILE`/`SSL_CERT_DIR`;
  `SSL_CERT_DIR` panics on a private-key file). M2 does not wait for it.
- Lower resident memory than Chrome for the same page (vendor claim ~30 MB vs
  200+ MB, unverified). Measured and reported by the plan, **not** gated.

CA management (Path 1):

- `aitm ca export [--format pem|der] [--out <path>]` / `ca.export`: the root
  **certificate only**, its SHA-256 fingerprint and the CA directory path.
- `aitm ca status` / `ca.status`: does a CA exist, its fingerprint and path,
  and, per platform and scope, whether the certificate with that fingerprint
  is present in the OS trust store and whether that presence means trust.
- `aitm ca install [--scope user|system]` / `ca.install` and
  `aitm ca uninstall …` / `ca.uninstall`: put the root in, or take it out of,
  the OS trust store with the platform tool; idempotent; identify the
  certificate by fingerprint; report the fingerprint.
- One implementation, two frontends: the four commands appear in MCP
  `tools/list` and as CLI subcommands with no frontend-specific code paths
  beyond the policy gate and the CLI confirmation.
- `ca.install` / `ca.uninstall` over **MCP are refused unless the operator set
  `ca.allow_agent_install`** (default **off** — decided, §D8); the **CLI** is
  the human path and is not gated; the OS's own authorization prompt is left
  standing.
- Every `ca.export` / `ca.install` / `ca.uninstall` attempt — successful,
  failed, refused, or dry-run — appends one record to a **durable audit log**,
  or the operation does not run.
- Every platform's command lines and output parsers are unit-tested on every
  host without executing anything, through an executor trait; one
  `#[ignore]`d test per platform exercises the real OS by hand.
- A clear, actionable error when the OS cannot grant trust in this session
  (headless macOS, unelevated Windows, non-root Linux).
- Operators can tell which path a given client is on: `ca.status` and
  `ca.install` help text say the OS store does not affect the embedded
  (obscura) engine and point at `--ca-cert`.

## Non-goals

Browser:

- No in-process linking of the `obscura` library crate (Candidate B of the
  research note). The crate's facade lacks `screenshot` and key input and
  trusts via a process-global env var; the CDP server covers all six
  primitives today. Linking is a later option behind the same `BrowserDriver`.
- No stealth build. aitmproxy ships the `render` build. The fork's flag still
  reaches the stealth (`wreq`/BoringSSL) client so the patch is complete
  upstream, but aitmproxy does not build, ship, or test with `--stealth`.
- No automatic download of the obscura binary by `aitm` at runtime. It is
  bundled with aitmproxy's release (or pointed at by config/env). Runtime
  network fetches of an executable are a supply-chain surface this tool
  should not have.
- No per-context (per-page) CA trust or proxy inside obscura: process-global,
  like `SSL_CERT_FILE` and `OBSCURA_ALLOW_PRIVATE_NETWORK` are today.
- No automatic restart of a crashed obscura child in M2. A dead child makes
  `browser.*` fail with a clear error until `aitm` restarts.
- No silent fallback from obscura to Chrome. If the configured engine cannot
  start, `browser.*` is unavailable and the log says why; the operator chooses
  `engine = chrome` explicitly.
- No release pipeline, code signing, or brew formula in M2 beyond the minimal
  packaging in §D3 (Open question 2).

CA management (all future work unless noted):

- Firefox/NSS profile stores (any OS, including Chrome's `~/.pki/nssdb` on
  Linux), Java keystores (`keytool`), Android, iOS. `ca.export` plus the
  application's own import is the path for those, and the `ca.install`
  result/help says so.
- Serving the certificate over a magic hostname through the proxy
  (mitmproxy's `mitm.it`).
- Arch/openSUSE/Alpine-specific paths (`trust anchor`,
  `/etc/ca-certificates/trust-source/anchors`, `/usr/share/pki/trust/anchors`).
  Alpine happens to use the Debian tool and directory and so works through the
  Debian family; it is not separately tested.
- Verifying macOS **trust settings** (as opposed to keychain presence); see
  Status semantics. Recorded as future work with the `verify-cert` /
  `trust-settings-export` candidates from research 07 §3.1.
- Finding and removing stale aitmproxy roots whose fingerprint we no longer
  know (a regenerated CA). Only the Linux anchor file, which is ours by name,
  is removed regardless of fingerprint.
- A PowerShell path on Windows; a direct crypt32 / Security.framework path
  (ruled out by `unsafe_code = "forbid"`). The Windows `TrustStore` impl is
  designed and unit-tested like the others (it is host-independent code) but
  aitmproxy's M2 binary ships for macOS and Linux only; its real-OS test is
  not run in M2.
- Generating the CA. The commands never create `ca.key`/`ca.crt`; the proxy
  does that on start (`CertAuthority::load_or_generate` runs in `build_proxy`
  before any CLI dispatch, so in the real binary the CA always exists by the
  time a `ca.*` command runs).
- A `ca.audit` command; the operator reads the audit file.

Both:

- No scanner, no L4 module, no Rhai runtime (that is **M3**, §D12), no GUI,
  no config hot-reload.
- No change to the `BrowserDriver` trait, any existing method of the
  `Command`/`Plugin` traits, or any M1 tool's name or schema
  (external-authoring stability). Additions are defaulted trait methods and
  new members only.

## Anti-goals

Browser:

- Trust granted to the embedded engine by **anything other than the flag**:
  an inherited `SSL_CERT_FILE`, an operator's `OBSCURA_CA_CERT`, the OS store,
  or a CDP call the engine accepts and ignores. If the driver can believe trust
  was granted when it was not, the design has failed.
- **Replacing** obscura's built-in roots with ours. The flag adds one issuer;
  public sites keep verifying; a wrong-host leaf is still rejected.
- Any obscura network path that **bypasses the proxy**. A bypassing image
  loader is both a MITM gap and an SSRF hole (it would skip aitmproxy's
  SSRF-filtered browser listener). One such path makes M2 a failure even if
  navigations are captured.
- Running the obscura child with the CA **directory** or the CA **private
  key** reachable through its arguments. It gets the certificate file path
  only.
- A `browser.*` surface that drifts between engines (a tool that works on
  Chrome and errors on obscura, or vice versa, for the same input).

CA management:

- `ca.key` read, copied, moved, exported, or named on any command line by any
  `ca.*` command. The commands open exactly one file in the CA directory:
  `ca.crt` (the audit log lives outside it, §D8).
- A directory-scanning option (`SSL_CERT_DIR`, `--localcertsdir`, a glob)
  pointed at the CA directory. The obscura experiment showed what happens
  (`ca.key` parsed as a certificate; panic).
- An export layout that bundles key and certificate (mitmproxy's
  `mitmproxy-ca.pem`). `ca.export` emits the certificate and nothing else.
- `ca.export --out` writing into the CA directory (it could clobber `ca.crt`
  with DER, or `ca.key`).
- An agent installing a root silently: no gate, no audit record, or a refusal
  message that does not say which setting would allow it. Equally: an operator
  who cannot do it from the CLI because the agent gate got in the way.
- A CA operation with no record. An unwritable audit log means the operation
  does not run.
- A false "installed": reporting presence as trust where the platform does
  not equate them (macOS), or reporting "installed" from an exit code that
  cannot distinguish absent from present (`find-certificate -a` exits 0 on no
  match; `certutil -addstore` succeeds on a duplicate).
- Bypassing or suppressing the OS authorization prompt (for example loosening
  `com.apple.trust-settings.admin` in the authorization database, or
  `certutil -f`). The prompt is the user's consent; a headless failure is
  reported, not worked around.
- Secrets on argv or in logs: no passwords, no key material, no PEM bodies in
  log lines or audit records.
- A `ca.*` command writing to stdout or stderr. MCP's stdio transport owns
  them; frontends print.

## Constraints

- **Rust gate** for aitmproxy: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  before any review; `unsafe_code = "forbid"` stays (no FFI into crypt32,
  Security.framework, or `libc::geteuid`). The default `cargo test` must
  remain hermetic: no obscura binary, no Chrome, no network, no OS trust
  store. Engine-backed tests are **gated**: `AITM_CHROME=1` (M1 pattern) and
  the new `AITM_OBSCURA=1`; real-OS trust-store tests are `#[ignore]`d and
  additionally gated on `AITM_REAL_OS_TESTS=1`.
- **Fork gate** (the obscura repository is a different Cargo workspace with
  its own conventions): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
  as configured upstream, and `cargo nextest run` for the crates the patch
  touches (`obscura-net`, `obscura-js`, `obscura-cli`); obscura's tests need
  nextest (one V8 isolate per process). The `stealth` feature test runs only
  where CMake/Clang/libclang exist and is reported as such.
- **Fork prerequisites (plan tasks, not assumptions):** `github.com/mrbrutti/obscura`
  does not exist yet and must be created (`gh repo fork h4ckf0r0day/obscura`);
  the only local clone (`~/tmp/obscura-spike/obscura`) is shallow and cannot be
  branched from — the fork is cloned fresh to a sibling directory
  (`/Users/matt/Security/obscura`, **Architect's call**) and fork tasks run in
  worktrees of that clone; `cargo nextest` is not installed and is required
  for the fork gate (`cargo install cargo-nextest --locked`).
- **Platforms:** macOS (arm64, x86_64) and Linux (x86_64, aarch64, glibc ≥
  2.35) — the obscura release targets. Windows is out for the shipped binary.
- **Binary weight:** the `render` build is ~73 MiB prebuilt (109 MiB from a
  local release build). Accepted; `obscura-worker` is **not** shipped
  (`scrape` only).
- **Dependencies.** aitmproxy keeps `chromiumoxide 0.9` (`Browser::connect`),
  adds `tokio::process` + `tokio::signal` for the child, and uses
  `serde`/`serde_yaml`/`serde_json` (already in the tree) for the config file
  and audit records. The new `aitm-ca` crate may depend on **(Architect's call
  C1)**: `aitm-core`, `anyhow`, `tracing`, `serde`/`serde_json`, `dirs = "5"`
  (already a dependency of `aitm-core`), `ring = "0.17"` for SHA-256
  (`ring::digest::SHA256`) and SHA-1 (`ring::digest::SHA1_FOR_LEGACY_USE_ONLY`,
  used only to produce the Windows thumbprint and the macOS SHA-1 fallback),
  `x509-parser = "0.18"` for PEM to DER (`pem::parse_x509_pem`) and iterating
  PEM bundles (`pem::Pem::iter_from_buffer`), and `time` for RFC 3339. All are
  already resolved in `Cargo.lock`. Not allowed: `sha2`, the `sha1` crate,
  `rcgen` (the commands never mint anything), `security-framework`,
  `windows`/`windows-sys`/`winapi`, `rustls-platform-verifier`,
  `rustls-native-certs`, `openssl`, `tempfile`. Dev-dependencies may add
  `tracing-subscriber = "0.3"` (already resolved). No new TLS stack. The fork
  adds `webpki-root-certs` as an optional dependency under `stealth` only.
- **Frontend neutrality.** `aitm-mcp` and `aitm-cli` must not learn command
  names. The gate and the confirmation are expressed through `CommandHost`
  and the `Command` trait (additive, defaulted), not through name lists.
- **Public trait surface is semver-stable** (platform spec). Additions are a
  defaulted trait method and new `CommandHost`/`CaConfig`/`BrowserConfig`
  members; no existing signature changes.
- **Every subprocess is bounded.** A GUI prompt that never appears, a `sudo`
  waiting for a password nobody can type, or an obscura child that never
  listens must not hang the MCP server forever.
- **Security posture (platform spec, unchanged):** the SSRF-filtered browser
  listener (`Proxy::run_browser`) and `browser.navigate`'s guard stay the
  authoritative SSRF control; the embedded engine's own guard is **not** relied
  on. Deny-by-default for every new active capability. The CA key stays `0600`
  in a `0700` directory and is never passed to, read by, or exported by any new
  code path.
- **Research facts that bound the CA design** (`07-ca-install.md`): macOS
  `find-certificate -a` exits 0 on no match (parse stdout); macOS 27 prints
  SHA-256 and SHA-1 with `-Z`, older releases SHA-1 only; `delete-certificate
  -Z` exits 1 for absent and malformed alike; `remove-trusted-cert` leaves
  the certificate in the keychain; `add-trusted-cert` into System needs root
  and a GUI session (`no user interaction was possible` otherwise, with the
  cert landing untrusted); Debian requires `.crt` in
  `/usr/local/share/ca-certificates`; `update-ca-certificates` re-run is a
  no-op and only cleans orphans when counts are non-zero; Fedora anchors in
  `/etc/pki/ca-trust/source/anchors` and `update-ca-trust extract`; Windows
  `certutil` keys on the SHA-1 thumbprint and succeeds on duplicate
  `-addstore`; `-user` shows a Security Warning dialog, the machine store
  needs an elevated process.
- **Performance:** `browser.*` latency and proxy throughput are not regressed:
  the engine swap touches only the browser crate and wiring, not the proxy
  data path (platform AC20 soak stays green).
- **Workflow:** seven stages per `docs/superpowers/WORKFLOW.md`. Fork tasks run
  in a worktree of the fork repository; each is one Coder task with the fork
  gate above.

## Design

### D1. Shape of the change

```
                    aitm (binary)                       obscura fork (child process)
   ┌──────────────────────────────────────┐    spawn     ┌──────────────────────────────┐
   │ wire::assemble(cfg) ─► Proxy + Arc<CA>│ ───────────► │ obscura serve                │
   │                                      │              │   --host 127.0.0.1 --port P  │
   │ aitm_browser::launch(&cfg.browser,   │   CDP ws://  │   --proxy http://127.0.0.1:B │
   │     ca.cert_path())                  │ ◄──────────► │   --ca-cert <ca.crt>         │
   │   ├─ engine=obscura → ObscuraDriver  │              │   --allow-private-network    │
   │   └─ engine=chrome  → ChromeDriver   │              └──────────────┬───────────────┘
   │                                      │                             │ all HTTP(S), via proxy
   │ Proxy::run_browser(B)  ◄─────────────┼─────────────────────────────┘
   │   (SSRF-filtered listener, MITM with │
   │    leaves signed by CA)              │
   │                                      │
   │ CaPlugin(CaConfig, Executor, AuditLog)│  ca.status / ca.export / ca.install / ca.uninstall
   │ McpServer → CommandHost{frontend=Mcp}│    → security / update-ca-certificates / certutil
   │ Cli       → CommandHost{frontend=Cli}│    → <config_dir>/aitmproxy/ca-audit.jsonl
   └──────────────────────────────────────┘
```

Two independent pieces, one shared fact: both read the **certificate** and
never the key. The obscura launcher gets the certificate **path** from the
`Arc<CertAuthority>` wiring already builds (§D7); the `ca.*` commands read
`<ca.dir>/ca.crt` themselves (§D8) so they work even when the key is
unreadable.

### D2. The obscura fork and the `--ca-cert` flag (decided; cites the spike)

**Fork.** `github.com/mrbrutti/obscura`, forked from `h4ckf0r0day/obscura`.
Work branch `aitm/ca-cert`, based on upstream commit **`034a147`** (upstream
`main` on 2026-10-27, the tree every patch site below was mapped against;
**Architect's call** — not the `v0.2.5` tag, which is ten days older, has a
workspace version of `0.1.0` unrelated to the tag, and was only the *binary*
the spike ran; M2-AC10 re-proves MITM against the fork's own build). Release
tags `aitm-v1`, `aitm-v2`, … **(Architect's call)**. The fork's release
workflow builds the `render` binary for the four platforms above.

**Flag contract** — this is what aitmproxy depends on, so it is normative:

- `obscura --ca-cert <PATH> ... serve|fetch|scrape|mcp`: a clap arg with
  `global = true` next to `--proxy`, **repeatable**; each `PATH` is a PEM
  bundle (one or more certificates) or a single DER certificate, parsed by the
  same parser the env path uses (`from_pem_bundle`, fallback `from_der`).
- Env fallback `OBSCURA_CA_CERT=<path>[:<path>...]` (platform path-list
  separator, `std::env::split_paths`). It exists because `scrape` and
  `serve --workers N` pass `--proxy` to worker processes as `OBSCURA_PROXY`;
  the CLI mirrors `--ca-cert` into `OBSCURA_CA_CERT` at the two worker-spawn
  sites the same way. **aitmproxy never sets this variable**; it passes the
  flag.
- **Add, never replace.** Effective roots = built-in webpki roots ∪
  (`SSL_CERT_FILE`/`SSL_CERT_DIR` certs, if set) ∪ `--ca-cert` certs.
  `danger_accept_invalid_certs` stays `false`; hostname/SAN verification
  stays on (aitmproxy's forged leaf carries the host as CN and SAN, so it
  passes). Help text reads: `Trust the certificate(s) in PATH as additional
  root CAs, added to the built-in roots. Repeatable. PEM bundle or DER.`
- **Fail fast.** An unreadable or unparseable `--ca-cert` file is a startup
  error: non-zero exit, message naming the path, before any listener binds.
  (The env path today warns and skips; that is right for an ambient variable
  and wrong for an explicit flag.)
- **All three client-construction sites honor it**, so the root reaches every
  transport — navigation, sub-resources, page-JS `fetch()`/XHR, the ES-module
  loader, stealth:

  | Site | Today | Change |
  |---|---|---|
  | `obscura-net/src/client.rs` `ObscuraHttpClient::get_client` (reqwest) | adds `configured_root_certificates()` only if `SSL_CERT_FILE\|\|SSL_CERT_DIR` set | fold flag certs into `configured_root_certificates()`; condition becomes "env set ∨ extra roots set" |
  | `obscura-net/src/wreq_client.rs` `StealthHttpClient::with_proxy` (wreq/BoringSSL) | if env set, `CertStore::builder().set_default_paths()` — **replaces** webpki | store = webpki (`webpki-root-certs`) ∪ default paths (if env set) ∪ flag certs — fixes the replace-roots bug for the env path too |
  | `obscura-js/src/ops.rs` `build_request_client` (reqwest, page `fetch()`/XHR, proxied) + `module_loader.rs` `standalone_client` | proxy yes, **no configured roots**. These are the *fallback* clients: `op_fetch_url` prefers the page's shared pool (which does add roots) and falls back to this one; whether the fallback is ever on the hot path during a `serve` session is unconfirmed | add `configured_root_certificates()` to both (make the fn `pub`) so no client lacks the roots whichever path a request takes; M2-AC11 verifies end to end |

- Patch shape: `client.rs` (`OnceLock<Vec<reqwest::Certificate>>` extra roots,
  `pub fn set_extra_root_certificates(paths: &[PathBuf]) -> Result<usize, ObscuraNetError>`,
  `pub fn extra_root_pem() -> &[u8]` for wreq), `wreq_client.rs` + `Cargo.toml`,
  `ops.rs` + `module_loader.rs`, `obscura-cli/src/main.rs` (clap arg; merge
  with env at startup next to the `--allow-private-network` env mirror; exit on
  error; set `OBSCURA_CA_CERT` on worker spawns), three docs pages, tests
  reusing `https_fixture_with_private_ca()`. ≈85 lines of code, ≈60 of tests,
  ≈25 of docs, 6 files, **no signature changes** in `obscura-cdp`,
  `obscura-mcp`, `obscura-browser`, or the `obscura` library crate.
- **Image loader.** `obscura-render/src/paint.rs` has a static `ureq` image
  agent with no proxy support. Whether it is on the hot path (the comment says
  resources are prefetched through the browser's proxy-aware pool before
  layout) is **unknown**. M2-AC11/AC12 decide it empirically; if any HTTPS image
  or other sub-resource is fetched outside the proxy, the fork patch **extends
  to `obscura-render`** so every fetch goes through the proxied client with
  the configured roots (or the direct path is disabled). This is in scope for
  the fork, not optional.
- **Upstream.** After the fork's gate is green and M2-AC10/11 pass, open one PR
  (`--ca-cert`: add private roots without `SSL_CERT_FILE`; make the stealth
  client add rather than replace) and file two issues (env vars undocumented;
  `SSL_CERT_DIR` + private key panics). URLs recorded in the plan's Shipped
  section. M2 does not block on upstream acceptance.

### D3. Shipping and finding the binary

- aitmproxy has no release artifact today (no CI, no formula). M2 adds the
  **minimum that makes "next to `aitm`" real (Architect's call, Open question
  2):** a `scripts/package.sh` that builds `aitm --release`, downloads the
  fork's GitHub Release asset for the host platform (checksum-verified against
  the release's published `SHA256SUMS`), strips macOS quarantine, and writes
  `dist/aitm-<version>-<target>.tar.gz` containing `aitm` and `obscura` side by
  side. No signing, no brew formula, no multi-target CI in M2.
- **Discovery order (Architect's call):** `browser.obscura.binary` from config
  → `AITM_OBSCURA_BIN` env → `obscura` in the same directory as the running
  `aitm` executable (`std::env::current_exe()`) → `obscura` on `PATH`. The
  first candidate that exists is **the** candidate; it is not skipped if it
  then fails the probe — a wrong binary is an error to report, not to route
  around.
- **Probe (decided):** before spawning the server, run `<binary> --help` and
  require the output to contain `--ca-cert`. Failure → `launch` returns an
  error naming the path and saying the binary is not the aitmproxy fork
  (example text left to the builder) and **no CDP connection is attempted**.
  Also run `<binary> --version` and log it at `info` **(Architect's call:**
  informational, not a pin; a newer fork build must not be refused**)**. The
  required-flag probe is the gate because it tests the exact capability we
  need rather than a version string.
- macOS Gatekeeper quarantine (`com.apple.quarantine`) on a downloaded binary
  is handled by `package.sh`; a binary the operator fetched by hand may still
  carry it, and the driver reports that spawn error as-is with a hint naming
  `xattr -d com.apple.quarantine`.

### D4. The managed child process

`aitm-browser` gains `obscura.rs` with:

```rust
/// How to find and start the forked obscura; lives in aitm-core next to BrowserConfig.
pub struct ObscuraConfig {
    pub binary: Option<PathBuf>,        // None → discovery order in D3
    pub start_timeout: Duration,        // default 15 s: spawn → CDP connected
    pub stop_timeout: Duration,         // default 5 s: graceful → SIGKILL
}

/// A running `obscura serve` owned by one driver.
pub struct ObscuraProcess { /* tokio::process::Child, port, ready-file path */ }

impl ObscuraProcess {
    /// The exact Command that would be spawned (argv + env), for tests and logging.
    pub fn command(config: &BrowserConfig, binary: &Path, ca_cert: &Path, cdp_port: u16, ready_file: &Path) -> tokio::process::Command;
    /// Probe (D3), spawn, wait for readiness, return the WebSocket URL to connect to.
    pub async fn start(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<(Self, String /* ws url */)>;
    /// Graceful stop, then kill after `stop_timeout`.
    pub async fn stop(self) -> anyhow::Result<()>;
}
```

**Argv (decided, from the spike):**
`serve --host 127.0.0.1 --port <P> --proxy http://127.0.0.1:<browser_listener> --ca-cert <ca.crt> --allow-private-network --ready-file <tmp>`

- `<P>` is a free loopback port aitmproxy picks (bind-and-release) **(Architect's
  call)**; readiness = the ready-file appears **or** TCP connect to `<P>`
  succeeds, whichever first, bounded by `start_timeout`; the child exiting
  early is an immediate error carrying its exit status and the tail of its
  stderr.
- `--proxy` is `BrowserConfig.proxy_addr` — the SSRF-filtered browser listener,
  as for Chrome. obscura ignores `HTTP_PROXY`/`NO_PROXY` and has no bypass
  list, so loopback targets go through the proxy too — the equivalent of
  Chrome's `--proxy-bypass-list=<-loopback>` comes for free.
- `--ca-cert` is `CertAuthority::cert_path()` — the **file**, never the
  directory (the directory holds `ca.key`; the spike showed obscura reads
  every file in a cert dir and panics on the key).
- `--allow-private-network` is passed **always** when the engine is obscura
  **(Architect's call)**. Reason: obscura's own guard blocks loopback/private
  *targets* before the proxy sees them and cannot know aitmproxy's scope, so
  it would turn the decided escape hatch (platform AC12: a scoped loopback
  host is permitted) into obscura's error instead of ours. Every request still
  traverses the SSRF-filtered browser listener, which enforces aitmproxy's
  policy and scope on every upstream connection, sub-resources included; the
  spike confirmed the loopback **proxy** itself needs no allowance. M2-AC12
  proves no request escapes that listener.
- `headless` is meaningless for obscura (no head exists); `headless = false`
  with `engine = obscura` logs a warning and is ignored **(Architect's call)**.

**Environment (decided — the "programmatic, not env" principle made
concrete):** the child inherits the parent environment **minus**
`SSL_CERT_FILE`, `SSL_CERT_DIR`, `OBSCURA_CA_CERT`, `OBSCURA_PROXY`,
`OBSCURA_ALLOW_PRIVATE_NETWORK`, `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` (and
lowercase forms), so the child's trust and routing are exactly what aitmproxy
passed as flags, whatever the operator's shell carries. `OBSCURA_CDP_TOKEN` is
set to a per-launch random token when the fork's `serve` accepts it in a form
`chromiumoxide::Browser::connect` can present (see Left to the builder).

**Lifecycle:** `kill_on_drop(true)` on the child so a Rust panic/unwind in
`aitm` does not orphan it; stdout/stderr piped into `tracing` at `debug` (the
last ~50 stderr lines are retained for error reports). `stop()`: close the CDP
connection, send SIGTERM, wait `stop_timeout`, then SIGKILL. A child that
exits while `aitm` runs is detected on the next `browser.*` call, which fails
with `"embedded browser (obscura) exited with <status>"`; no restart
(Non-goal). `kill_on_drop` does **not** cover `aitm` being killed by a signal
— destructors do not run — so §D6 adds signal handling in `main`; a SIGKILL
of `aitm` is the one case M2 accepts as unrecoverable (no `unsafe`, so no
`PR_SET_PDEATHSIG`), and the next `aitm` start logs any stale ready-file it
finds.

### D5. Driver: one CDP session, two launchers

`driver.rs` keeps the six primitives exactly as implemented today (the spike
ran every one of them unchanged against obscura) and splits the launch:

```rust
/// Engine selection; lives in aitm-core next to BrowserConfig.
pub enum BrowserEngine { Obscura, Chrome }        // Default: Obscura

pub struct BrowserConfig {
    pub engine: BrowserEngine,                     // NEW, default Obscura
    pub obscura: ObscuraConfig,                    // NEW
    pub proxy_addr: SocketAddr,
    pub headless: bool,                            // Chrome only
    pub ignore_cert_errors: bool,                  // Chrome only (CDP Security.setIgnoreCertificateErrors)
    pub nav_timeout: Duration,
    pub ssrf: SsrfPolicy,
}

// aitm-browser
pub(crate) struct CdpSession { /* Browser, Page, nav_timeout, handler JoinHandle */ }  // the six primitives live here
pub struct ChromeDriver { /* CdpSession */ }                 // M1 behavior, unchanged surface
pub struct ObscuraDriver { /* CdpSession, ObscuraProcess */ }
impl ObscuraDriver {
    pub async fn launch(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<Self>;
    pub async fn close(self) -> anyhow::Result<()>;
}
/// The one entry point the binary calls; selects by `config.engine`.
pub async fn launch(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<Arc<dyn BrowserDriver>>;
```

- `ObscuraDriver::launch` = `ObscuraProcess::start` → `Browser::connect(ws_url)`
  → spawn the handler task → `new_page("about:blank")`. It **does not** call
  `Security.setIgnoreCertificateErrors`: obscura accepts and ignores it, and
  a driver that believes a no-op granted trust is the anti-goal.
- `ChromeDriver::launch` is unchanged (flags, `ignore_cert_errors`).
- `Drop for ObscuraDriver` aborts the handler and lets `kill_on_drop` reap the
  child; `close()` is the graceful path and is what `main` calls on shutdown.
- `BrowserDriver` is **not** changed. `NavOutcome.status` stays `None` (the
  captured flow carries it) for both engines.
- The `browser.*` commands, `BrowserPlugin`, and the SSRF guard are untouched.

### D6. Wiring in `main.rs`

- Server path: `aitm_browser::launch(&cfg.browser, assembled.ca.cert_path())`.
  On error: the existing `warn!` ("embedded browser unavailable …") now names
  the engine and the error; `browser.*` tools error until restart. No fallback
  to the other engine (Non-goal).
- Shutdown: `main` gains a fourth `select!` arm on `tokio::signal` (SIGINT and
  SIGTERM on Unix). Whichever arm completes first — a listener or the MCP
  transport ending, or a signal — `main` then calls the driver's `close()`
  (bounded by `stop_timeout`) before returning, so the child is reaped on
  every orderly exit path (today Chrome is only dropped, and a signal ends the
  process without running destructors).
- The CLI one-shot path still passes `None` for the browser. It applies the
  env bridge (§D10), builds the `CommandHost` as `Frontend::Cli`, and prints
  results through `render_cli_value` (§D9) instead of `{value:?}`.

### D7. Sharing the CA with the launcher

`wire.rs` today builds `CertAuthority` and moves it into `HttpModule` with no
way back out. Additive change **(Architect's call)**:

```rust
// aitm::wire
pub struct Assembled { pub proxy: Proxy, pub ca: Arc<CertAuthority> }
pub fn assemble(cfg: &Config) -> anyhow::Result<Assembled>;                    // NEW
pub fn assemble_with(cfg: &Config, features: &Features) -> anyhow::Result<Assembled>;
pub fn build_proxy(cfg: &Config) -> anyhow::Result<Proxy>;                     // unchanged: assemble(cfg)?.proxy
pub fn build_proxy_with(cfg: &Config, features: &Features) -> anyhow::Result<Proxy>;
```

`assemble_with` also registers `CaPlugin` (§D8) after `PocCommands`, so every
`build_proxy` caller (all existing tests) sees the four `ca.*` commands.
`Features` gains `pub ca: Option<CaPlugin>`-style injection for tests
**(Architect's call:** `Features { mutate: bool, ca_plugin: Option<aitm_ca::CaPlugin> }`;
`None` builds `CaPlugin::new(cfg.ca.clone())`, `Some` registers the prebuilt
plugin, which is how integration tests inject a scripted executor and an
in-memory audit log**)**.

`CertAuthority` gains one accessor (additive, `aitm-proto-http/src/ca.rs`):

```rust
impl CertAuthority {
    pub fn cert_path(&self) -> &Path;   // <dir>/ca.crt, as loaded or written by load_or_generate
}
```

`load_or_generate` records the path it used. Nothing here touches the key.
The `ca.*` commands do **not** use `CertAuthority` (next section).

### D8. CA management (Path 1): the `aitm-ca` crate

#### Decided by Matt (2026-10-27) — recorded, not reopened

1. The four commands are registered once in the shared `Registry`; CLI and
   MCP share one implementation (the `PocCommands`/`BrowserPlugin` pattern in
   `crates/aitm/src/wire.rs`).
2. `ca.export`: root certificate (never the key), SHA-256 fingerprint, CA dir
   path. `--format pem|der`, `--out <path>`. Always available.
3. `ca.status`: CA exists?, fingerprint, path, installed-in-OS-store per
   platform. Always available.
4. `ca.install [--scope user|system]` / `ca.uninstall`: macOS `security
   add-trusted-cert` (login keychain for `user`, `-d` + System keychain for
   `system`; the OS prompt stands; headless failure reported clearly); Linux
   Debian/Ubuntu (`/usr/local/share/ca-certificates/<name>.crt` +
   `update-ca-certificates`) and Fedora/RHEL (`update-ca-trust`) with family
   detection; Windows `certutil -addstore Root`. Idempotent; identify by
   fingerprint; never read or move `ca.key`; report the fingerprint; CLI
   confirms unless `--yes`.
5. **Policy gate:** `ca.install`/`ca.uninstall` over MCP are registered and
   discoverable but refused unless `CaConfig.allow_agent_install` (**default
   `false`**) is set; the refusal names the setting. The CLI is not gated.
   Rationale: the OS prompt is absent as root, in containers, and with
   NOPASSWD sudo; MCP-only agents have no shell; the command runs inside the
   process holding the CA key. Exposed at all because an agent with a shell
   would run the CLI anyway and hiding it leaves the MCP surface incomplete.
   Matt reconfirms the OFF default on approval of this spec.
6. Out of scope: Firefox/NSS, Java keystores, magic hostname.
7. Platform shell-outs sit behind a trait; unit tests assert exact command
   lines and parse canned output; a real install test is `#[ignore]`d.
   Research direction A, with D's dry-run.
8. The `ca.*` family ships in **Milestone 2** together with the browser swap,
   in this spec; the separate `ca-commands` draft is retired.

#### Where it lives: crate `aitm-ca` (Architect's call C2)

A new workspace member `crates/aitm-ca`, following the "command provider
crate" pattern (`aitm-browser`, `aitm-poc`). It depends on `aitm-core` only
among workspace crates. Nothing in `aitm-proto-http` changes for it: the
commands read `ca.crt` from disk themselves rather than going through
`CertAuthority`, because `CertAuthority::load_or_generate` opens `ca.key` and
the commands must work when the key is unreadable or absent.

Module layout (the builder may split further; these names are referenced
below):

| Module | Holds |
|---|---|
| `lib.rs` | `CaPlugin`, re-exports |
| `cert.rs` | `CaCert` (load `ca.crt`, DER, fingerprints, PEM/DER rendering) |
| `exec.rs` | `CmdLine`, `CmdOutput`, `Executor`, `RealExecutor`, `DryRunExecutor` |
| `store.rs` | `Scope`, `Platform`, `LinuxFamily`, `Presence`, `Trust`, `StoreStatus`, `Change`, `TrustStore`, `store_for`, `TrustError` |
| `platform/macos.rs`, `platform/linux.rs`, `platform/windows.rs` | one `TrustStore` impl each, compiled on every host |
| `audit.rs` | `AuditRecord`, `AuditLog`, `FileAuditLog` |
| `commands.rs` | the four `Command` impls |
| `testing.rs` | `ScriptedExecutor`, `MemoryAuditLog` (public, so integration tests in `aitm` can use them) |

```rust
pub struct CaPlugin { /* cfg: CaConfig, exec: Arc<dyn Executor>, audit: Arc<dyn AuditLog>, platform: Option<Platform> */ }
impl CaPlugin {
    /// Real executor, file audit log at `cfg.audit_log`, platform detected at each invocation.
    pub fn new(cfg: CaConfig) -> Self;
    /// Injected executor, audit log and fixed platform (tests, and any host that wants to drive a foreign platform's logic).
    pub fn with_backend(cfg: CaConfig, exec: Arc<dyn Executor>, audit: Arc<dyn AuditLog>, platform: Platform) -> Self;
}
impl Plugin for CaPlugin { /* name() == "ca"; load() registers ca.export, ca.status, ca.install, ca.uninstall */ }
```

#### The certificate as the commands see it: `CaCert`

```rust
pub struct CaCert {
    pub path: PathBuf,      // <dir>/ca.crt
    pub pem: String,        // file contents, byte-for-byte
    pub der: Vec<u8>,       // the single CERTIFICATE block, decoded
    pub sha256: [u8; 32],   // over `der`
    pub sha1: [u8; 20],     // over `der`
}
impl CaCert {
    /// Reads only `<dir>/ca.crt`, through the executor (so tests can supply it and record the path).
    /// `Ok(None)` when it does not exist.
    pub fn load(dir: &Path, exec: &dyn Executor) -> anyhow::Result<Option<CaCert>>;
    pub fn fingerprint_sha256(&self) -> String;   // "AB:CD:...:EF", 32 pairs, uppercase
    pub fn fingerprint_sha1(&self) -> String;     // same form, 20 pairs
    pub fn sha256_hex(&self) -> String;           // uppercase, no separators (macOS `-Z`)
    pub fn sha1_hex_lower(&self) -> String;       // lowercase, no separators (certutil thumbprint)
}
pub fn sha256_of(der: &[u8]) -> [u8; 32];
```

`load` fails with a clear error if `ca.crt` is not exactly one PEM
`CERTIFICATE` block. It never looks at `ca.key`, never lists the directory.
Fingerprints are computed once in Rust from the DER and shared by every
command, so `status`, `install`, `uninstall` and the audit log always agree.

Fingerprint display form is colon-separated uppercase hex (what browsers and
`openssl x509 -fingerprint` show) **(Architect's call C3)**. Tool arguments use
the form each tool wants: macOS `-Z` gets uppercase hex without separators
(the form `find-certificate -Z` prints); Windows gets lowercase hex without
separators.

#### Shell-outs behind a trait: `Executor`

Every effect on the OS, and every read of OS state, goes through one trait so
platform logic is pure with respect to the host it runs on.

```rust
pub struct CmdLine {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,   // piped to the child; `None` = /dev/null
    pub mutating: bool,           // true for anything that changes the store
}
impl CmdLine {
    /// `program` and `args` joined by single spaces; an arg containing whitespace is single-quoted.
    /// Stdin is never rendered. This string is what tests assert on and what results report.
    pub fn render(&self) -> String;
}
pub struct CmdOutput { pub code: Option<i32>, pub stdout: String, pub stderr: String }
impl CmdOutput { pub fn success(&self) -> bool; }

pub trait Executor: Send + Sync {
    /// `Err` only when the program could not be started or timed out; a non-zero exit is an `Ok` with its code.
    fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput>;
    /// `Ok(None)` when the file does not exist; `Err` on any other I/O failure (permission denied included).
    fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>>;
    fn dir_exists(&self, path: &Path) -> bool;
    fn home_dir(&self) -> Option<PathBuf>;
    fn is_root(&self) -> bool;
}
```

`RealExecutor` **(Architect's call C4)**: `std::process::Command` with stdin
from `cmd.stdin` or null, stdout/stderr captured and decoded lossily; a
wall-clock timeout of **15 s for non-mutating** and **180 s for mutating**
commands (long enough to type a password or click an OS dialog), after which
the child is killed (`Child::kill`, safe) and `run` returns an error whose
text contains `timed out` and the rendered command line. `home_dir` is
`dirs::home_dir()`. `is_root` on Unix runs `id -u` once through its own `run`
and compares the trimmed stdout to `0`; on Windows it is `false`. (The builder
may substitute any safe-Rust uid source already in `Cargo.lock`; no new crate,
no `unsafe`.) `RealExecutor::new()` uses those timeouts;
`RealExecutor::with_timeouts(query, mutate)` exists for the timeout test.

`DryRunExecutor<'a>` wraps another executor: non-mutating commands and all
reads pass through; a mutating command is recorded and answered with a
synthetic `CmdOutput { code: Some(0), stdout: "", stderr: "" }`. The recorded
list is what `dry_run` reports.

`ScriptedExecutor` (in `testing.rs`) is the test double: canned responses
keyed by rendered command line (with a default for unlisted commands), an
in-memory file map, a set of existing directories, a fixed home, a fixed
`is_root`; it records every `run` call (rendered line plus stdin bytes) and
every `read_file` path, in order, so tests assert exact command sequences and
prove no path ever names `ca.key`. `with_real_fs()` switches `read_file` and
`dir_exists` to the real filesystem while `run` stays scripted, for tests
that need a real directory (the unreadable-key test, CA-AC24).

#### Platform model

```rust
pub enum Scope { User, System }                 // parsed from "user" | "system", exact, lowercase
pub enum LinuxFamily { Debian, Fedora }
pub enum Platform { MacOs, Linux(LinuxFamily), Windows, Unsupported(String) }
impl Platform {
    /// `cfg!(target_os)` picks the OS; on Linux `detect_linux_family` picks the family.
    pub fn detect(exec: &dyn Executor) -> Platform;
    pub fn label(&self) -> &'static str;        // "macos" | "linux-debian" | "linux-fedora" | "windows" | "unsupported"
    pub fn scopes(&self) -> &'static [Scope];   // macOS, Windows: [User, System]; Linux: [System]; Unsupported: []
    pub fn default_scope(&self) -> Option<Scope>; // macOS, Windows: User; Linux: System; Unsupported: None
}
pub fn detect_linux_family(exec: &dyn Executor) -> Option<LinuxFamily>;

pub enum Presence { Present, Absent, Stale, Unknown }   // "present" | "absent" | "stale" | "unknown"
pub enum Trust { Yes, No, Unknown }                      // "yes" | "no" | "unknown"
pub struct StoreStatus { pub scope: Scope, pub location: String, pub installed: Presence, pub trusted: Trust, pub detail: Vec<String> }
pub struct Change { pub changed: bool, pub scope: Scope, pub location: String, pub commands: Vec<String>, pub detail: Vec<String> }

pub trait TrustStore: Send + Sync {
    fn platform(&self) -> &Platform;
    fn status(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor) -> anyhow::Result<StoreStatus>;
    fn install(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor) -> anyhow::Result<Change>;
    fn uninstall(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor) -> anyhow::Result<Change>;
}
pub struct MacOsStore;
pub struct LinuxStore(pub LinuxFamily);
pub struct WindowsStore;
pub struct UnsupportedStore(pub String);
pub fn store_for(platform: &Platform) -> Box<dyn TrustStore>;

pub enum TrustErrorKind { UnsupportedPlatform, UnsupportedScope, NoCertificate, NeedsRoot, HeadlessAuth, ToolMissing, ToolFailed, Timeout, CopiesRemain }
pub struct TrustError { pub kind: TrustErrorKind, pub message: String }   // Display = message; message carries the hint
```

All four store impls and `detect_linux_family` are **compiled on every
host** with no `cfg` attributes; they are plain functions of `(cert, scope,
exec)`. Only `Platform::detect` (`cfg!` macros, which compile everywhere) and
`RealExecutor::is_root` (`#[cfg(unix)]` / `#[cfg(windows)]`) know what the
host is. That is how a macOS developer unit-tests the Linux and Windows
stores: construct `LinuxStore(LinuxFamily::Debian)` and drive it with a
`ScriptedExecutor`.

Default scope **(Architect's call C5)**: the least-privileged scope the
platform has: `user` on macOS and Windows, `system` on Linux (Linux has no
per-user OS store). An explicit `--scope user` on Linux is an
`UnsupportedScope` error: `Linux has no per-user OS trust store; use --scope system`.

#### Linux family detection (Architect's call C6)

Research direction G, resolved as "directory existence first, os-release as
tie-break":

1. `fedora_dir = /etc/pki/ca-trust/source/anchors`,
   `debian_dir = /usr/local/share/ca-certificates`.
2. Exactly one exists: that family.
3. Both exist: read `/etc/os-release` (then `/usr/lib/os-release`); take the
   space-separated tokens of `ID` and `ID_LIKE`, lowercased, quotes stripped.
   Any of `debian`, `ubuntu` → Debian; any of `fedora`, `rhel`, `centos` →
   Fedora; otherwise Fedora (first in mkcert's order).
4. Neither exists: `None`, and `Platform::detect` yields
   `Unsupported("linux")`. `ca.status` then reports `platform:
   "unsupported"` with an empty `stores` and a detail line naming both
   directories; `ca.install` fails with `UnsupportedPlatform`:
   `no supported trust-store directory found (looked for
   /etc/pki/ca-trust/source/anchors and /usr/local/share/ca-certificates);
   install the ca-certificates package, or install <path to ca.crt> by hand`.

#### Privilege model (Architect's call C7)

The aitmproxy process never escalates itself and never prompts for a
password. On Unix, each **individual privileged subprocess** is prefixed with
`sudo --` when `exec.is_root()` is false, exactly as mkcert does; the user's
own `sudo` prompts on the controlling terminal. Which commands are
privileged: every macOS `system`-scope mutation; every Linux mutation.
`user`-scope macOS and Windows commands never use `sudo`; Windows never does.

Why the process does not simply tell the user to run `sudo aitm ca install`:
`CaConfig.dir` defaults to the invoking user's config directory, and under
`sudo` `HOME` usually changes, so the command would not find the CA. The
"no CA" error says so: `no CA certificate at <path>; start the proxy once
(aitm) to generate it. If you ran this under sudo, run it as your own user:
aitm escalates only the trust-store commands.`

Headless behaviour follows from `sudo`'s own: with no terminal it exits
non-zero (`a terminal is required to read the password`), which the store
reports as `NeedsRoot` with the hint `needs root: run aitm ca install from
a shell where sudo can prompt, or start the proxy as root`. The MCP stdio
stream is never handed to a child: child stdin is null unless the command
pipes data (`tee`).

The cost of C7 — the proxy process (including the MCP server) can start a
`sudo` child that waits for a password on the controlling terminal — is
bounded by the 180 s mutating timeout and accepted; the alternative ("never
spawn `sudo`, tell the user to re-run under `sudo`") fails on the `HOME`
problem above. Matt may overturn on approval.

#### Exact command lines

Notation: `K_user = <home>/Library/Keychains/login.keychain-db`,
`K_sys = /Library/Keychains/System.keychain`, `P = <dir>/ca.crt` (the real
path, passed verbatim), `S256 = cert.sha256_hex()`, `S1 =
cert.sha1_hex_lower()`, `[sudo]` = the `sudo --` prefix per the privilege
model. `[-d]` appears only for `system`. Every line below is a `CmdLine`; the
ones under "mutate" have `mutating: true`.

**macOS**

| Op | Steps |
|---|---|
| status (either scope) | 1. query: `security find-certificate -a -Z <K>` (never `sudo`; the System keychain is world-readable). Parse: output is blocks starting `SHA-256 hash: <hex>` and/or `SHA-1 hash: <hex>`; `Present` if any block's SHA-256 equals `S256` **or** its SHA-1 equals `S1` (older macOS prints SHA-1 only); `Absent` if exit 0 and no match (including empty output); `Unknown` if exit non-zero. `trusted: Unknown` always; detail: `macOS: keychain presence is reported; trust settings are not verified. Open Keychain Access to confirm "Always Trust".` |
| install | 1. query `<K>`. `Present` → `changed: false`, stop. 2. mutate: `[sudo] security add-trusted-cert [-d] -r trustRoot -p ssl -p basic -k <K> <P>`. Exit 0 → `changed: true`. Non-zero → classify stderr: matches `no user interaction was possible`, `authorization was denied`, or `User interaction is not allowed` (case-insensitive) → `HeadlessAuth`, else `ToolFailed`; then **rollback**: re-run the query, and if `Present`, mutate `[sudo] security delete-certificate -Z <S256> <K>` (best effort; the cert would otherwise sit untrusted and make `status` say present). Error text includes the stderr tail and, for `HeadlessAuth`: `macOS refused to change trust settings without a GUI session; run aitm ca install from a terminal in a logged-in desktop session`. |
| uninstall | 1. query `<K>`. `Absent` → `changed: false`, stop. 2. mutate: `[sudo] security remove-trusted-cert [-d] <P>` (non-zero tolerated: recorded in `detail`, since a cert without trust settings has nothing to remove). 3. mutate: `[sudo] security delete-certificate -Z <S256> <K>`; non-zero → mutate `[sudo] security delete-certificate -Z <S1> <K>` (older macOS); non-zero again → `ToolFailed`. 4. query again; if still `Present` (duplicate copies, research 07 §3.1) repeat step 3, at most 3 passes in total; still present → `CopiesRemain`. `changed: true`. |

macOS duplicate-add behaviour is unverified (research Q1); the check-first
query makes the design independent of it **(Architect's call C8)**. The
`#[ignore]`d test records what a second direct `add-trusted-cert` does.

**Linux**

| Family | Anchor `A` | Bundle `B` | Refresh after add `R` | Refresh after remove `R_rm` |
|---|---|---|---|---|
| Debian | `/usr/local/share/ca-certificates/aitmproxy-root-ca.crt` | `/etc/ssl/certs/ca-certificates.crt` | `update-ca-certificates` | `update-ca-certificates --fresh` |
| Fedora | `/etc/pki/ca-trust/source/anchors/aitmproxy-root-ca.pem` | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | `update-ca-trust extract` | `update-ca-trust extract` |

Fixed anchor names (research direction F, **Architect's call C9**): a
regenerated CA overwrites rather than accumulates, and the file is
identifiable as ours by name even when the fingerprint has changed.

| Op | Steps (scope `system` only; `user` → `UnsupportedScope`) |
|---|---|
| status | No subprocess. `read_file(A)`: `None` → `Absent`; `Some` and its single PEM block's DER SHA-256 equals ours → `Present`; `Some` otherwise (different cert, unparsable) → `Stale`; `Err` → `Unknown` with detail. `read_file(B)`: `None`/`Err` → `trusted: Unknown` with detail `bundle <B> not readable`; `Some` → iterate every PEM block (`Pem::iter_from_buffer`), `Yes` if any DER SHA-256 equals ours, else `No`. |
| install | `Present` and `Yes` → `changed: false`, no commands. `Present` and not `Yes` (file dropped, never refreshed) → mutate `[sudo] R` only. Otherwise → mutate `[sudo] tee <A>` with `stdin = cert.pem` bytes exactly, then mutate `[sudo] R`. Any non-zero exit → `NeedsRoot` if stderr matches `Permission denied` or `Operation not permitted` or `sudo:`, else `ToolFailed`; a spawn failure of `R` → `ToolMissing` (`<R> not found; install the ca-certificates package`). Detail records `update-ca-certificates: <n> added, <m> removed` when that line is present in stdout. `changed: true`. |
| uninstall | `Absent` → `changed: false`, no commands. Otherwise (`Present` **or** `Stale`: the file is ours by name) → mutate `[sudo] rm -f <A>`, then mutate `[sudo] R_rm`. If it was `Stale`, detail says `removed a stale aitmproxy anchor (fingerprint <its SHA-256>)`. `changed: true`. |

`--fresh` on Debian removal is the defensive choice for research Q6 (a plain
run can leave a dangling `/etc/ssl/certs/<name>.pem` link because orphan
cleanup is gated on non-zero counts) **(Architect's call C10)**; verified by
the `#[ignore]`d Debian test.

**Windows**

`F` = `-user` for scope `user`, nothing for `system`. `P` is the Windows path
of `ca.crt`.

| Op | Steps |
|---|---|
| status | 1. query: `certutil [F] -store Root`. Exit 0: collect every line matching `Cert Hash(sha1): <hex, spaces allowed>` (label match case-insensitive), normalise (strip spaces, lowercase). Any equals `S1` → `Present`; one or more lines and none match → `Absent`; zero lines (localised or changed output) → `Unknown` with detail `could not parse certutil output`. Exit non-zero → `Unknown` with the exit code. `trusted` mirrors `installed` (`Present`→`Yes`, `Absent`→`No`, else `Unknown`): membership of the Root store is trust. |
| install | 1. query. `Present` → `changed: false`. 2. mutate: `certutil [F] -addstore Root <P>` (no `-f`: the check-first query makes it unnecessary and `-f` is the malware signature). Exit 0 → `changed: true`. Non-zero: output matches `0x80070005` or `Access is denied` → `NeedsRoot` (`run from an elevated (Administrator) shell for --scope system`); otherwise `ToolFailed`; for `user` scope the hint adds `the Security Warning dialog must be answered on an interactive desktop`. |
| uninstall | 1. query. `Absent` → `changed: false`. 2. mutate: `certutil [F] -delstore Root <S1>`. Exit 0 → `changed: true`; else `ToolFailed`. |

The thumbprint is the SHA-1 of the DER (research 07 §3.4), passed as 40
lowercase hex characters without separators **(Architect's call C11)**; the
`#[ignore]`d Windows test (not run in M2) confirms `certutil` accepts it and
records whether the store dump also shows `Cert Hash(sha256)`.

**Unsupported platform.** `status` returns no stores and the detail `no OS
trust-store integration for <os>; export the certificate with aitm ca export
and install it by hand`. `install`/`uninstall` fail with
`UnsupportedPlatform` and the same text.

#### Status semantics: what `ca.status` can and cannot assert

`installed` means "a certificate with our fingerprint is in that scope's
store" (`Present`), "not there" (`Absent`), "our anchor file exists but holds
a different certificate" (`Stale`, Linux only), or "could not determine"
(`Unknown`). `trusted` is a separate field because presence and trust differ
by platform:

| Platform | `installed` from | `trusted` |
|---|---|---|
| macOS | `find-certificate -a -Z` per keychain | `unknown` always, with the Keychain Access detail. `verify-cert` and `dump-trust-settings` were inconclusive in research 07 §3.1; asserting trust here would risk a false "installed". |
| Linux | anchor file hash | from the extracted bundle: `yes`/`no`/`unknown` |
| Windows | `certutil -store Root` dump | equals `installed` |

Neither field says anything about the embedded engine: `ca.status`'s `detail`
always carries the line `the embedded browser (obscura) does not use the OS
trust store; it trusts this CA through --ca-cert at launch`.

#### Command surface

Parameter names are snake_case like the rest of the registry (`flow_id`,
`poc_path`), so the CLI flags are `--format`, `--out`, `--scope`,
`--dry_run`. Tool descriptions (MCP-visible) state the gate on
`ca.install`/`ca.uninstall` and the Path 1/Path 2 distinction.

**`ca.export`** — params: `format: Str` optional (`pem` default, or `der`;
anything else → error `format must be pem or der`), `out: Str` optional.
Result (`TypeDesc::Object`):

```
{ format: Str, certificate: Str (PEM text) | Bytes (DER),
  fingerprint_sha256: Str, fingerprint_sha1: Str, dir: Str, path: Str, written_to: Str | Null }
```

`out`: created or truncated, contents exactly the PEM text or the DER bytes.
Refused **(Architect's call C12)** when `out`'s parent directory canonicalises
to the canonical CA dir or anything under it: `refusing to write into the CA
directory <dir>`. Over MCP the DER is base64 (`to_json` does that already).

**`ca.status`** — no params. Result:

```
{ exists: Bool, dir: Str, path: Str,
  fingerprint_sha256: Str | Null, fingerprint_sha1: Str | Null,
  platform: Str,
  stores: Object { "<scope>": Object { installed: Str, trusted: Str, location: Str } },
  detail: Array<Str> }
```

`stores` has one entry per `Platform::scopes()`; it is empty when
`exists` is false (no fingerprint to look for; detail says `no CA certificate
at <path>; start the proxy once (aitm) to generate it`) or the platform is
unsupported. `location` is the keychain path, the anchor path, or
`Root (CurrentUser)` / `Root (LocalMachine)`.

**`ca.install`** and **`ca.uninstall`** — params: `scope: Str` optional
(`user` | `system`; default `Platform::default_scope()`), `dry_run: Bool`
optional (default false). Result:

```
{ changed: Bool, dry_run: Bool, scope: Str, platform: Str, location: Str,
  fingerprint_sha256: Str, commands: Array<Str>, detail: Array<Str> }
```

`commands` is every rendered command line executed, in order, queries
included, so a human (or an EDR analyst) sees exactly what ran. With
`dry_run`, queries run for real and `commands` lists the mutating lines that
would have run; `changed` says whether a change would be made.

Order of work inside `invoke` for install/uninstall: parse args → **open the
audit log for append** (failure ⇒ refuse, below) → policy gate → `CaCert::load`
(absent → `NoCertificate`) → `Platform::detect` (`Unsupported` →
`UnsupportedPlatform`, before any scope handling) → resolve scope (not in
`Platform::scopes()` → `UnsupportedScope`) → `store.install` / `store.uninstall`
(through `DryRunExecutor` when `dry_run`) → **audit record** → `tracing` →
build the `Value`. No subprocess runs before the gate passes. `ca.export`
follows the same shape without the gate and platform steps.

#### Policy gate

**Config.** `CaConfig` gains `pub allow_agent_install: bool`, **default
`false`** (decided). It is set from the config file (§D10) and, as a bridge,
from the environment variable `AITM_CA_ALLOW_AGENT_INSTALL` (`1`, `true`,
`yes`, case-insensitive → `true`; anything else or unset → `false`) via a pure
function `aitm::env::apply(cfg: &mut Config, lookup: impl Fn(&str) ->
Option<String>)` **(Architect's call C13)**; the env bridge overrides the file.

**Mechanism (Architect's call C14): the frontend is known to the command
through `CommandHost`.** `aitm-core` gains:

```rust
#[non_exhaustive]
pub enum Frontend { Cli, Mcp }
impl<'a> CommandHost<'a> {
    pub fn with_frontend(self, frontend: Frontend) -> Self;
    pub fn frontend(&self) -> Frontend;   // default when never set: Frontend::Mcp
}
```

`Cli::dispatch` builds its host `.with_frontend(Frontend::Cli)`;
`McpServer::call_tool` builds its `.with_frontend(Frontend::Mcp)`. The default
is the gated posture: a host that did not declare itself the human CLI is
treated as agent-driven, matching deny-by-default elsewhere. A future TUI or
GUI adds a variant and extends the one `match` in `commands.rs`. This keeps
`aitm-mcp` and `aitm-cli` ignorant of command names and lets the command own
its policy and its config.

**Rule.** In `ca.install`/`ca.uninstall`: if `host.frontend() != Frontend::Cli`
and `!dry_run` and `!cfg.allow_agent_install`, write the audit record
(`outcome: "refused"`), emit the `warn!` below, and return the refusal error.
`dry_run` passes the gate because it changes nothing and gives a shell-less
agent the exact lines to hand to a human **(Architect's call C15**: it is the
same tool name the gate refuses, but it runs read-only queries and writes
nothing, and it is audited as `outcome: "dry_run"`; Matt may overturn on
approval**)**.

**Refusal text** (exact; `<cmd>` is `ca.install` or `ca.uninstall`):

```
<cmd> refused: changing the OS trust store from an agent frontend is disabled. Set ca.allow_agent_install = true in the aitmproxy config (or AITM_CA_ALLOW_AGENT_INSTALL=1 in the environment) to allow it, or run `aitm ca <install|uninstall>` yourself from a shell. <cmd> with dry_run=true is always allowed.
```

Over MCP this arrives as a tool result with `isError: true` (a failing command
is a tool result, not a protocol error, per `server.rs`). `tools/list` always
includes all four `ca.*` tools regardless of the flag.

#### Audit log (net-new; the M2 brief's requirement)

`tracing` output is ephemeral and depends on the operator's `RUST_LOG`; a
root-CA change deserves a record that survives the session.

```rust
pub struct AuditRecord {
    pub ts: String,                 // RFC 3339 UTC, e.g. "2026-10-27T21:03:14Z"
    pub command: &'static str,      // "ca.install" | "ca.uninstall" | "ca.export"
    pub frontend: &'static str,     // "cli" | "mcp"
    pub outcome: &'static str,      // "ok" | "refused" | "error" | "dry_run"
    pub scope: Option<String>,      // install/uninstall only
    pub platform: Option<String>,   // Platform::label(), when detected
    pub fingerprint_sha256: Option<String>,   // colon form; None when no ca.crt
    pub detail: String,             // changed=true/false, written_to, or the error text — never PEM/key material
}
pub trait AuditLog: Send + Sync {
    /// Prove the log is writable before anything else happens. `Err` ⇒ the command refuses to run.
    fn open(&self) -> anyhow::Result<()>;
    /// Append one record (one JSON line).
    fn record(&self, rec: &AuditRecord) -> anyhow::Result<()>;
}
pub struct FileAuditLog { /* path */ }      // O_APPEND; created 0600 (Unix); parent dir created if missing
pub struct MemoryAuditLog { /* Vec<AuditRecord> behind a Mutex */ }   // testing.rs
```

- **Location (Architect's call):** `CaConfig.audit_log: PathBuf`, default
  `<config_dir>/aitmproxy/ca-audit.jsonl` — a **sibling** of the default CA dir
  (`<config_dir>/aitmproxy/ca`), never inside it, so the anti-goal "the
  commands open exactly one file in the CA directory" holds and the `0700` CA
  dir keeps only key and cert. Same fallbacks as `default_ca_dir()`.
- **Format:** JSON Lines (`serde_json`, one object per line, fields exactly as
  above, `null` for absent options). Append-only; aitmproxy never rewrites or
  truncates it.
- **Fail-closed:** `open()` is the first thing `invoke` does after parsing
  arguments — before the gate, before `CaCert::load`, before any subprocess.
  If it fails, the command returns `audit log <path> is not writable (<io
  error>); refusing to change or export the CA until it is` and nothing else
  happens. A write failure in `record()` after the action is reported as the
  command's error (the action has happened; the result still says so in the
  error text).
- **What is recorded:** every `ca.install` / `ca.uninstall` / `ca.export`
  invocation that got past argument parsing — `ok`, `error` (including
  `NoCertificate`, `NeedsRoot`, timeouts), `refused` (the gate), `dry_run`.
  `ca.status` is read-only and not recorded.
- Each record is also emitted as `tracing::info!` (target `aitm_ca::audit`,
  same fields).

#### CLI: arguments, confirmation, output

**Shapes.** `aitm ca export [--format pem|der] [--out <path>]`,
`aitm ca status`, `aitm ca install [--scope user|system] [--dry_run] [--yes]`,
`aitm ca uninstall [--scope user|system] [--dry_run] [--yes]`. All but `--yes`
are ordinary `ParamDef` flags handled by the existing parser (a bare Bool flag
is `true`).

**Confirmation (Architect's call C16).** `Command` gains one defaulted method,
so the CLI can ask without knowing command names:

```rust
pub trait Command: Send + Sync {
    // existing: name, schema, invoke
    /// A yes/no question a human frontend must get "yes" to before `invoke`. `None` = no confirmation.
    fn confirm_prompt(&self, args: &Params) -> Option<String> { None }
}
```

`ca.install` returns `Install the aitmproxy root CA (SHA-256 <fp>) into
<location> (scope <scope>)? Every TLS client that uses that store will then
trust certificates this proxy mints. (The embedded obscura browser is
unaffected; it trusts the CA via --ca-cert.)`; `ca.uninstall` returns
`Remove the aitmproxy root CA (SHA-256 <fp>) from <location> (scope <scope>)?`.
Both return `None` when `dry_run` is true or when there is no `ca.crt`
(invoke will fail with the clear error instead). Computing the prompt reads
`ca.crt` only.

`aitm-cli` gains:

```rust
pub trait Confirmer: Send + Sync { fn confirm(&self, prompt: &str) -> anyhow::Result<bool>; }
pub struct TtyConfirmer { /* interactive: bool */ }
impl TtyConfirmer { pub fn from_stdin() -> Self /* std::io::IsTerminal */; pub fn new(interactive: bool) -> Self; }
impl Cli { pub fn with_confirmer(self, confirmer: Arc<dyn Confirmer>) -> Self; }   // default: TtyConfirmer::from_stdin()
```

`--yes` is a **reserved CLI flag**: `Cli::dispatch` removes a bare `--yes`
token from the flag list before `parse_flags` (so it is not a `ParamDef`, does
not appear in MCP schemas, and is accepted, as a no-op, on every command).
Then: if `--yes` was absent and `cmd.confirm_prompt(&args)` is `Some(p)`,
call `confirmer.confirm(&p)`; `Ok(false)` → error `aborted: <name> not run`
with nothing invoked; `Err` propagates. `TtyConfirmer` with `interactive ==
true` writes `<p> [y/N] ` to stderr, reads one line from stdin, and answers
`true` only for `y`/`yes` (case-insensitive, trimmed); with `interactive ==
false` it returns `Err(<name> needs confirmation but stdin is not a terminal;
pass --yes to confirm non-interactively)`. MCP ignores `confirm_prompt`
entirely; its control is the config flag.

**Output rendering (Architect's call C17).** `main.rs` currently prints
`{value:?}`. A `Value::Object` with a PEM inside is unreadable that way, so
`aitm` gains `pub fn render_cli_value(v: &Value) -> Vec<u8>`: `Str` → the
string plus newline, `Bytes` → the raw bytes, anything else → pretty JSON via
`aitm_mcp::json::to_json`. `main` writes that to stdout. This applies to every
command, which is an improvement, not a regression (nothing asserted on the
Debug form).

#### Logging (`tracing`)

Target `aitm_ca`, structured fields, never PEM or key material:

| When | Level | Fields | Message |
|---|---|---|---|
| install/uninstall completed | `info` | `command`, `fingerprint_sha256` (colon form), `scope`, `platform`, `frontend` (`cli`/`mcp`), `changed`, `dry_run` | `OS trust store updated` / `OS trust store already in the requested state` / `dry run: no changes made` |
| gate refusal | `warn` | `command`, `frontend`, `setting = "ca.allow_agent_install"` | `refused: agent-driven trust-store change is disabled` |
| install/uninstall failed | `warn` | `command`, `fingerprint_sha256`, `scope`, `platform`, `kind` (the `TrustErrorKind`), `error` | `OS trust store change failed` |
| export | `info` | `fingerprint_sha256`, `format`, `written_to` (path or empty) | `root certificate exported` |
| every subprocess | `debug` | `command_line` (rendered), `code` | `ran trust-store command` |
| audit record written | `info` (target `aitm_ca::audit`) | the `AuditRecord` fields | `ca audit` |

### D9. Wiring changes outside `aitm-ca` and `aitm-browser`

- `aitm-core`: `BrowserConfig.{engine, obscura}`, `BrowserEngine`,
  `ObscuraConfig`; `CaConfig.{allow_agent_install, audit_log}`; `Frontend`,
  `CommandHost::{with_frontend, frontend}`; `Command::confirm_prompt`. All
  additive. `Frontend` is re-exported from `lib.rs`.
- `aitm-mcp`: `call_tool` adds `.with_frontend(Frontend::Mcp)`.
- `aitm-cli`: `Frontend::Cli`, `--yes`, `Confirmer`, `TtyConfirmer`,
  `with_confirmer`.
- `aitm`: `Cargo.toml` depends on `aitm-ca`; `wire.rs` gains `assemble` /
  `Assembled` and registers `CaPlugin`; `env.rs` (`env::apply`), `render.rs`
  (`render_cli_value`), `config_file.rs` (§D10); `main.rs` loads the config,
  applies the env, launches the engine, handles signals, uses the renderer;
  `tests/frontends.rs` `EXPECTED_TOOLS` grows from 18 to 22 with `ca.export`,
  `ca.status`, `ca.install`, `ca.uninstall`.
- Workspace `Cargo.toml`: new member and `aitm-ca` path dependency.

### D10. Operator configuration surface

M1 runs on `Config::default()`; no file is read. M2 adds knobs an operator
must be able to set without recompiling (`browser.engine`,
`browser.obscura.binary`, `ca.allow_agent_install`, `ca.audit_log`).
**Recommended (Architect's call, Open question 1):** a YAML config file, the
platform spec's stated intention ("the `aitm` binary parses a YAML file into
them"):

- Path: `aitm --config <path>` (a leading flag the binary strips before CLI
  dispatch) → `AITM_CONFIG` env → `<config_dir>/aitmproxy/config.yaml`
  (sibling of the CA dir). A missing file at the default path means
  `Config::default()`, exactly today's behavior; a missing file at an
  explicit path is an error.
- Format: a serde mirror of `Config` with every field optional and defaults
  applied field by field (so a two-line file is valid). Keys mirror the Rust
  names: `browser.engine: obscura|chrome`, `browser.obscura.binary`,
  `ca.allow_agent_install`, `ca.audit_log`, and the existing fields
  (`listen`, `scope.entries`, `limits.*`, `ca.dir`, `mcp.transport`,
  `browser.*`, `poc.dir`, `ssl_insecure`, `max_flows`, `max_flow_bytes`).
- Lives in the `aitm` crate (`config_file.rs`); `aitm-core::Config` stays a
  plain data type. `env::apply` (C13) runs after the file so
  `AITM_CA_ALLOW_AGENT_INSTALL` still works as a bridge and overrides it.

The alternative is env overrides only (`AITM_BROWSER_ENGINE`,
`AITM_OBSCURA_BIN`, `AITM_CA_ALLOW_AGENT_INSTALL`, `AITM_CA_AUDIT_LOG`) read by
`env::apply`, leaving the file for later. The rest of this spec is unchanged
either way.

### D11. Tests and gating

- Default `cargo test`: hermetic. New hermetic tests cover the spawn
  `Command` (argv + scrubbed env), the `--help` probe refusal (a fake
  `obscura` shell script in `crates/aitm-browser/tests/fixtures/`), engine
  selection, `cert_path`, config parsing, the unchanged `browser.*` schemas,
  the 22-tool AC7 pin, and the whole `ca.*` family against `ScriptedExecutor`
  + `MemoryAuditLog`.
- **CA unit tests, any host:** every `TrustStore` impl against
  `ScriptedExecutor`; assertions are on the exact `Vec<String>` of rendered
  command lines, the `stdin` bytes handed to `tee`, the parsed
  `Presence`/`Trust`, `changed`, error kinds/text, and the audit records.
  Fixed inputs: the fixture `ca.crt` placed in the scripted file map at
  `/ca/ca.crt` (so `P = /ca/ca.crt` in rendered lines), home `/Users/t`.
  Windows tests compare against `cert.path.display()` rather than a literal,
  because `Path` joins render differently per host.
- **Fixture CA:** one checked-in `crates/aitm-ca/tests/fixtures/ca.crt` (a
  self-signed certificate generated once; the plan records its literal
  SHA-256 and SHA-1 so tests compare against constants, not against the code
  under test).
- **Frontends:** `aitm` integration tests build the proxy with
  `assemble_with(cfg, &Features { ca_plugin: Some(CaPlugin::with_backend(cfg.ca, scripted, memory_audit, Platform::MacOs)), .. })`
  and drive `McpServer::handle` and `Cli::dispatch`.
- **Real OS (`#[ignore]`):** `crates/aitm-ca/tests/real_os.rs`, one test per
  platform behind `#[cfg(target_os = ...)]` and `#[ignore]`, additionally
  skipping unless `AITM_REAL_OS_TESTS=1`. Each uses a throwaway CA dir and
  audit path, performs install → status → uninstall → status against the
  host, and prints (not asserts) the observations behind calls C8, C10, C11.
  They modify the machine's trust store and are run by hand, never in CI.
- `AITM_OBSCURA=1` (binary via discovery or `AITM_OBSCURA_BIN`): the
  obscura-backed twins of the M1 Chrome tests — primitives, routes-through-
  proxy, scoped-loopback navigation, HTTPS MITM, sub-resources, no-bypass, and
  the reflected-XSS e2e. Implemented by **parametrizing** the existing tests on
  engine, not duplicating them **(Architect's call)**: each test runs for
  Chrome when `AITM_CHROME` is set and for obscura when `AITM_OBSCURA` is set,
  skipping inertly otherwise.
- The HTTPS fixtures (M2-AC10–12) stand up a local TLS server with a throwaway
  self-signed certificate (rcgen + tokio-rustls, both in the tree) and set
  `cfg.ssl_insecure = true` so the proxy's **upstream** leg accepts it; the
  leg under test is the **client** leg (obscura ↔ proxy), where the proxy
  presents a leaf signed by the aitmproxy CA and obscura must trust it via
  `--ca-cert`. Sub-resource flows may land after `navigate` returns, so the
  tests poll the store for up to 10 s.
- Fork tests live in the fork and run under its gate (Constraints).

### D12. Relationship to the platform spec (amendments at approval)

This spec supersedes, for M2, these parts of the approved platform spec:

- "Embedded headless browser (`aitm-browser`)" — the Architect's call of
  chromiumoxide driving a **system Chrome** becomes: chromiumoxide driving a
  **bundled obscura child** by default, Chrome selectable. CA trust "at runtime
  via CDP `Security.setIgnoreCertificateErrors`" applies to the Chrome engine
  only; the obscura engine trusts via `--ca-cert`.
- The crate table's `aitm-browser` line ("Embedded headless Chromium over
  CDP") → "Embedded headless browser (obscura, Chrome fallback) over CDP";
  add `aitm-ca` ("CA export/status/install/uninstall over the OS trust store").
- `BrowserConfig` gains `engine` and `obscura`; `CaConfig` gains
  `allow_agent_install` and `audit_log`; `CommandHost` gains `frontend`;
  `Command` gains the defaulted `confirm_prompt`.
- The "CA (Architect's call)" bullet under Safety gains: "installed/removed
  via `aitm ca install/uninstall`; agent-initiated changes gated by
  `ca.allow_agent_install` (default off); every CA operation audited".
- **Milestones (decided):** this browser + CA work is **Milestone 2**; the
  roadmap table's Rhai scripting tier, labelled "M2, committed", becomes
  **M3**. The main session edits the table when this spec is approved.
- Platform AC7's "exact expected tool-name set" is 22 names.

The main session applies these edits to the platform spec when this spec is
approved (it owns Status lines and reconciliation notes).

## Acceptance criteria

Each is observable via a test unless marked otherwise. Gates: **[hermetic]**
runs in default `cargo test`; **[obscura]** needs `AITM_OBSCURA=1`;
**[chrome]** needs `AITM_CHROME=1`; **[fork]** runs in the fork's test suite;
**[real-os]** is `#[ignore]`d and gated on `AITM_REAL_OS_TESTS=1`;
**[manual]** is verified by the orchestrator. Browser criteria are `M2-ACn`;
CA criteria are `CA-ACn`. `<FP256>`/`<FP1>` are the fixture's literal
fingerprints recorded in the plan.

### Browser (Path 2)

**Fork and flag**

1. **M2-AC1 — `--ca-cert` grants trust [fork]:** with `--ca-cert <pem>` a
   request to the private-CA HTTPS fixture succeeds; without it the same
   request fails with `UnknownIssuer`. Tested for the reqwest client and
   (where the toolchain exists) the stealth client.
2. **M2-AC2 — Add, not replace; still strict [fork]:** with `--ca-cert` set, a
   leaf from a *different* throwaway CA is still rejected, a leaf whose SAN
   does not match the requested host is still rejected, and the stealth cert
   store built with the flag contains the webpki roots.
3. **M2-AC3 — Fail fast [fork]:** `obscura --ca-cert /nonexistent serve` and
   `--ca-cert <a file holding a private key>` exit non-zero before binding,
   with the path in the message.
4. **M2-AC4 — Every client [fork]:** the page-JS `fetch()`/XHR client and the
   ES-module loader are built with the configured roots (unit test on the
   builder; end-to-end by M2-AC11).
5. **M2-AC5 — Env fallback and workers [fork]:** `OBSCURA_CA_CERT=a:b` without
   the flag yields the same roots as `--ca-cert a --ca-cert b`; the worker
   spawn sites set `OBSCURA_CA_CERT` from the parent's flag (clap/env unit
   tests).

**Driver and child**

6. **M2-AC6 — Unpatched binary refused [hermetic]:** with `browser.obscura.binary`
   pointing at a fake `obscura` whose `--help` lacks `--ca-cert`, `launch`
   returns `Err` whose text contains `--ca-cert` and the binary path, and no
   TCP connection is attempted (a listener on the would-be CDP port sees
   nothing).
7. **M2-AC7 — Spawn contract [hermetic]:** `ObscuraProcess::command(...)`
   yields argv beginning `serve`, containing `--host 127.0.0.1`, `--port <P>`,
   `--proxy http://127.0.0.1:<proxy_addr port>`, `--ca-cert <ca.crt path>`
   (the file, not the dir), `--allow-private-network`, `--ready-file <path>`;
   and an environment with none of `SSL_CERT_FILE`, `SSL_CERT_DIR`,
   `OBSCURA_CA_CERT`, `OBSCURA_PROXY`, `OBSCURA_ALLOW_PRIVATE_NETWORK`,
   `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` even when the parent sets them.
8. **M2-AC8 — Engine toggle [hermetic + chrome + obscura]:**
   `BrowserConfig::default().engine == BrowserEngine::Obscura`;
   `aitm_browser::launch` with `engine = Chrome` produces a driver whose
   primitives pass M2-AC13's checks under `AITM_CHROME=1`, and with
   `engine = Obscura` under `AITM_OBSCURA=1`; the config file's
   `browser.engine: chrome` parses to `Chrome`.
9. **M2-AC9 — Lifecycle [obscura]:** after `launch`, the child's pid is alive
   and CDP is connected within `start_timeout`; after `close()` (and,
   separately, after dropping the driver) the pid is gone within
   `stop_timeout`. Separately, the `aitm` binary itself
   (`env!("CARGO_BIN_EXE_aitm")`, started with a temp CA dir and the engine
   set to obscura) is sent SIGTERM, and then SIGINT in a second run: in both,
   the `obscura` child it spawned is gone within `stop_timeout` of `aitm`
   exiting. No `obscura` process remains after the test.
10. **M2-AC10 — HTTPS MITM over obscura [obscura]:** navigating to the local
    HTTPS fixture through the proxy stores a decrypted `HttpFlow` with
    `scheme == "https"`, `GET /`, status `200`, and the fixture's body
    substring; `browser.navigate`'s `final_url` is the fixture URL.
11. **M2-AC11 — Sub-resources are captured [obscura]:** a fixture page whose
    HTML has `<img src="https://<fixture>/img.png">`, an inline
    `fetch("https://<fixture>/api")`, and an XHR to
    `https://<fixture>/xhr` yields, within 10 s of navigation, decrypted flows
    for `/`, `/img.png`, `/api`, and `/xhr`, each `200`. If `/img.png` is
    missing, the fork's render loader is routed through the proxy (D2) until it
    is present — the criterion does not relax.
12. **M2-AC12 — No bypass path [obscura]:** a fixture page referencing
    `<img src="http://127.0.0.1:<raw>/x.png">` and `fetch("http://127.0.0.1:<raw>/y")`
    where `<raw>` is a plain loopback listener that is **not** the proxy and
    **not** in scope: the raw listener accepts **zero** connections, no flow
    for `/x.png` or `/y` has a response, and a captured `tracing` subscriber
    saw the browser listener's `PrivateAddressBlocked` refusal for that
    authority (the cleartext path inserts a request-only flow before the
    upstream connect is refused; the refusal itself is only in `tracing`).
13. **M2-AC13 — Primitives over obscura [obscura]:** platform AC11's checks
    pass on the obscura driver: `screenshot` is a PNG (magic bytes, non-empty),
    `eval("1+1") == Int(2)`, `get_dom` contains `<html`, `click` and `type`
    change the page state (a fixture with a button and an input, asserted via
    `eval`).
14. **M2-AC14 — Reflected XSS over obscura [obscura]:** `e2e_reflected_xss`
    with `engine = Obscura` returns `passed == true` against the vulnerable
    target with the three artifacts (finding in store, PoC re-parses,
    screenshot is a PNG) and `passed == false` against the patched one.
15. **M2-AC15 — SSRF posture preserved over obscura [obscura]:**
    `browser.navigate` to an unscoped `http://127.0.0.1:<port>/` is refused by
    aitmproxy with `PrivateAddressBlocked` (not by obscura: the driver is never
    called); after `scope.add` of that exact `host:port` the same navigation
    succeeds and its flow is captured.
16. **M2-AC16 — Cert path, no key [hermetic]:** `CertAuthority::cert_path()`
    equals `<ca.dir>/ca.crt` after both a fresh generate and a reload; the
    spawn `Command` (M2-AC7) contains that path and does **not** contain
    `ca.dir` itself or `ca.key`; `ca.key`'s bytes and mode are unchanged by
    `launch`.

**Surface, config, packaging, gate**

17. **M2-AC17 — Surface [hermetic]:** the six `browser.*` tool schemas are
    byte-identical to M1 (snapshot compare); `tools/list` is exactly the 18
    M1 names plus `ca.status`, `ca.export`, `ca.install`, `ca.uninstall` (22).
18. **M2-AC18 — Config file [hermetic]:** a YAML file with `browser.engine: chrome`,
    `browser.obscura.binary: /x/obscura`, `ca.allow_agent_install: true`,
    `ca.audit_log: /x/audit.jsonl` loads into those `Config` fields with every
    other field equal to `Config::default()`; an absent default-path file
    yields `Config::default()`; an absent explicit `--config` path is an
    error. (Shape per Open question 1.)
19. **M2-AC19 — Packaging [manual]:** `scripts/package.sh` on the developer's
    machine produces a tarball containing `aitm` and `obscura` side by side;
    extracting it to a fresh directory with nothing else on `PATH` and running
    `./aitm` starts with the obscura engine (discovery "next to `aitm`") and
    logs the probed version. (Shape per Open question 2.)
20. **M2-AC20 — Memory report [obscura, manual]:** the plan's test run records
    the obscura child's peak RSS during M2-AC14 alongside Chrome's under
    `AITM_CHROME=1`, in the plan's Shipped section. Reported, not asserted.
21. **M2-AC21 — Upstream [manual]:** the fork PR and the two issues exist;
    URLs in the plan's Shipped section.
22. **M2-AC22 — Gate green [hermetic]:** the aitmproxy Rust gate passes with
    0 ignored (the `[real-os]` tests excepted, which are `#[ignore]`d by
    design); the fork gate passes in the fork.

### CA management (Path 1)

All `[hermetic]` unless marked.

1. **CA-AC1 — export PEM.** `ca.export` with no params on a CA dir holding the
   fixture returns `format == "pem"`, `certificate == Value::Str(<exact file
   text>)`, `fingerprint_sha256 == "<FP256>"`, `fingerprint_sha1 == "<FP1>"`,
   `dir`/`path` equal to the dir and `<dir>/ca.crt`, `written_to == Null`.
2. **CA-AC2 — export DER and `--out`.** `format == "der"` returns
   `certificate == Value::Bytes(der)` where `der` begins `0x30 0x82` and
   equals the PEM block decoded independently in the test; with `out` set, the
   file's bytes equal `der` exactly and `written_to` is the path; `format ==
   "pem"` with `out` writes text identical to `ca.crt`.
3. **CA-AC3 — export refusals.** `format == "p12"` fails with a message
   containing `format must be pem or der`; `out` under the CA dir fails with
   `refusing to write into the CA directory`; a CA dir with no `ca.crt` fails
   with a message containing the path and `start the proxy once`.
4. **CA-AC4 — status without a CA.** `exists == false`, both fingerprints
   `Null`, `stores == {}`, `detail` contains the `ca.crt` path.
5. **CA-AC5 — status macOS.** With canned `find-certificate` output (a) a block
   whose `SHA-256 hash:` is `<FP256 without colons>`, (b) blocks with other
   hashes, (c) a SHA-1-only block matching `<FP1>`: `installed` is `present`,
   `absent`, `present`; `trusted == "unknown"` in all three; `detail` contains
   `Keychain Access` and `--ca-cert`; the executed queries are exactly
   `security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db`
   and `security find-certificate -a -Z /Library/Keychains/System.keychain`; a
   canned exit code 1 yields `unknown`.
6. **CA-AC6 — status Linux Debian.** With the scripted file map: anchor equal
   to fixture + bundle containing it → (`present`, `yes`); anchor holding a
   different certificate + bundle without ours → (`stale`, `no`); no anchor →
   (`absent`, `no`); anchor present, bundle missing → (`present`, `unknown`).
   Zero `run` calls in every case; `read_file` paths are exactly `A` and `B`.
7. **CA-AC7 — status Linux Fedora.** Same as CA-AC6 with
   `/etc/pki/ca-trust/source/anchors/aitmproxy-root-ca.pem` and
   `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`.
8. **CA-AC8 — status Windows.** Canned `certutil -user -store Root` output
   containing `Cert Hash(sha1): <FP1 with spaces, mixed case>` → `present`,
   `trusted == "yes"`; output with other hashes → `absent`/`no`; exit 1 → both
   `unknown`; output with no `Cert Hash` lines → `unknown` with detail
   containing `could not parse`; `system` scope issues `certutil -store Root`
   (no `-user`).
9. **CA-AC9 — macOS install, user scope, idempotent.** Absent → commands exactly
   `["security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db",
   "security add-trusted-cert -r trustRoot -p ssl -p basic -k /Users/t/Library/Keychains/login.keychain-db /ca/ca.crt"]`,
   `changed == true`. Present → commands exactly the first line only,
   `changed == false`.
10. **CA-AC10 — macOS install, system scope and sudo.** With `is_root == false`
    the second line is `sudo -- security add-trusted-cert -d -r trustRoot -p
    ssl -p basic -k /Library/Keychains/System.keychain /ca/ca.crt`; with
    `is_root == true` the same line without the `sudo -- ` prefix; the query
    line never has the prefix.
11. **CA-AC11 — macOS headless failure and rollback.** Canned `add-trusted-cert`
    exit 1 with stderr `SecTrustSettingsSetTrustSettings: The authorization was
    denied since no user interaction was possible` → `Err` whose text
    contains `GUI session` and the stderr; when the post-failure query shows
    the cert present, the recorded commands end with `security
    delete-certificate -Z <FP256 hex> /Users/t/Library/Keychains/login.keychain-db`;
    the audit log holds one record with `outcome == "error"`.
12. **CA-AC12 — macOS uninstall.** Present → commands exactly `[query,
    "security remove-trusted-cert /ca/ca.crt", "security delete-certificate -Z
    <FP256 hex> /Users/t/Library/Keychains/login.keychain-db", query]` with
    `changed == true`; absent → `[query]`, `changed == false`; when the
    SHA-256 delete exits 1, the next command is the same with `-Z <FP1 lower>`
    and `changed == true`; `system` scope adds `-d` to `remove-trusted-cert`
    and `sudo -- ` to both mutations.
13. **CA-AC13 — Linux Debian install.** Absent → commands exactly `["sudo -- tee
    /usr/local/share/ca-certificates/aitmproxy-root-ca.crt", "sudo --
    update-ca-certificates"]`, the `tee` stdin equals the fixture PEM bytes,
    `changed == true`, and with canned stdout `1 added, 0 removed; done.`
    `detail` contains `1 added, 0 removed`; present+trusted → `[]`, `changed ==
    false`; present but `trusted == no` → `["sudo -- update-ca-certificates"]`;
    `is_root == true` → no `sudo -- ` prefixes; canned exit 1 with stderr
    `Permission denied` → `Err` containing `needs root`.
14. **CA-AC14 — Linux Debian uninstall.** Present → `["sudo -- rm -f
    /usr/local/share/ca-certificates/aitmproxy-root-ca.crt", "sudo --
    update-ca-certificates --fresh"]`, `changed == true`; absent → `[]`,
    `changed == false`; stale → same two commands and `detail` contains
    `stale`.
15. **CA-AC15 — Linux Fedora install/uninstall.** As CA-AC13/CA-AC14 with the
    `.pem` anchor path and `sudo -- update-ca-trust extract` as both refresh
    commands.
16. **CA-AC16 — Linux scopes.** `scope == "user"` → `Err` containing `no
    per-user OS trust store`; no `scope` → result `scope == "system"`.
17. **CA-AC17 — Linux family detection and unsupported.** Only the Fedora dir
    exists → `Fedora`; only Debian → `Debian`; both + os-release `ID=ubuntu` →
    `Debian`; both + `ID_LIKE="rhel fedora"` → `Fedora`; both + no os-release →
    `Fedora`; neither → `None`. With `Platform::Unsupported("linux")`:
    `ca.status` gives `platform == "unsupported"`, `stores == {}`, detail
    naming both directories; `ca.install` fails with a message naming both
    directories and `/ca/ca.crt`.
18. **CA-AC18 — Windows install/uninstall.** User scope, absent → `["certutil
    -user -store Root", "certutil -user -addstore Root <P>"]` where `<P>` is
    `cert.path.display()`, `changed == true`; present → first line only,
    `changed == false`; system scope → the same without `-user`; uninstall
    present → `["certutil -user -store Root", "certutil -user -delstore Root
    <FP1 lower>"]`; canned `-addstore` exit 1 with `Access is denied.
    0x80070005` → `Err` containing `Administrator`.
19. **CA-AC19 — MCP refusal with the flag off.** With `allow_agent_install ==
    false`, `tools/call ca.install` returns `isError == true` and text
    containing `ca.allow_agent_install` and `AITM_CA_ALLOW_AGENT_INSTALL`; the
    scripted executor recorded zero `run` calls; the audit log holds exactly
    one record with `command == "ca.install"`, `frontend == "mcp"`,
    `outcome == "refused"`, `fingerprint_sha256 == "<FP256>"`; the same for
    `ca.uninstall`; `tools/list` contains `ca.export`, `ca.status`,
    `ca.install`, `ca.uninstall`.
20. **CA-AC20 — MCP success with the flag on.** With `allow_agent_install ==
    true` and a scripted absent store, `tools/call ca.install` returns
    `isError == false` and `structuredContent.changed == true`, the executor
    recorded the CA-AC9 command lines, and the audit log holds one record with
    `outcome == "ok"`, `frontend == "mcp"`, `scope == "user"`,
    `platform == "macos"`.
21. **CA-AC21 — dry run passes the gate and changes nothing.** Flag off,
    `tools/call ca.install {dry_run: true}` → `isError == false`, `dry_run ==
    true`, `changed == true`, `commands` contains the `add-trusted-cert` line,
    the scripted executor recorded only the non-mutating query, and the audit
    record says `outcome == "dry_run"`.
22. **CA-AC22 — CLI unaffected by the flag.** Flag off, `Cli::dispatch(["ca",
    "install", "--yes"])` with the same scripted store → `Ok` with `changed ==
    true` and an audit record with `frontend == "cli"`, `outcome == "ok"`.
23. **CA-AC23 — CLI confirmation.** With a scripted `Confirmer`: `["ca",
    "install"]` calls it once with a prompt containing `<FP256>`, `scope
    user` and `--ca-cert`; answering `false` → `Err` containing `aborted`,
    zero mutating commands recorded, and **no** audit record (nothing was
    invoked); answering `true` → `Ok`; with `--yes` the confirmer is not
    called; with `--dry_run` it is not called; `TtyConfirmer::new(false)` →
    `Err` containing `--yes`; `ca status --yes` succeeds (reserved flag is a
    no-op elsewhere).
24. **CA-AC24 — the key is never touched.** On a real temporary CA dir
    containing the fixture `ca.crt` and (a) no `ca.key`, and (b, Unix only) a
    `ca.key` with mode `0o000`, using `ScriptedExecutor::with_real_fs()` so
    file reads are real and subprocesses are scripted: `ca.export`,
    `ca.status`, `ca.install`, `ca.uninstall` all return `Ok`, and no
    recorded command argument, stdin, `read_file` path, or audit record
    contains `ca.key` or a `PRIVATE KEY` block; the CA dir contains no new
    file afterwards (the audit log is outside it).
25. **CA-AC25 — tracing fields.** With a capturing subscriber, a successful
    `ca.install` emits exactly one `INFO` event with target `aitm_ca` whose
    fields include `command="ca.install"`, `fingerprint_sha256="<FP256>"`,
    `scope="user"`, `platform="macos"`, `frontend="cli"`, `changed=true`, and
    one `INFO` event with target `aitm_ca::audit`; a gate refusal emits a
    `WARN` event with `setting="ca.allow_agent_install"`.
26. **CA-AC26 — executor timeout (Unix only).** `RealExecutor::with_timeouts(_,
    200 ms)` running a mutating `sleep 5` returns `Err` containing `timed out`
    within 2 s.
27. **CA-AC27 — wiring.** `build_proxy(&cfg)` registers exactly the 22 expected
    tools; `Cli::dispatch(["ca", "status"])` on a temp CA dir created by
    `build_proxy` returns `exists == true`; `aitm::env::apply` sets
    `allow_agent_install` to `true` for `AITM_CA_ALLOW_AGENT_INSTALL` in
    `1`/`true`/`YES` and `false` for `0` or unset; `render_cli_value` returns
    the raw string for `Str`, the raw bytes for `Bytes`, and pretty JSON for an
    `Object`; `CaConfig::default().allow_agent_install == false` and
    `CaConfig::default().audit_log` is a sibling of the default CA dir, not
    inside it.
28. **CA-AC28 — audit log file.** With `FileAuditLog` at a temp path: after
    `ca.export`, the file exists with mode `0600` (Unix) and one line that
    parses as JSON with exactly the fields `ts`, `command`, `frontend`,
    `outcome`, `scope`, `platform`, `fingerprint_sha256`, `detail`, `ts`
    parsing as RFC 3339; a second `ca.export` appends a second line and the
    first is unchanged; no line contains `BEGIN CERTIFICATE`. With the audit
    path pointing at an existing **directory**: `ca.install` (flag on, CLI)
    returns `Err` containing `audit log` and the path, the scripted executor
    recorded **zero** `run` calls, and `CaCert::load` was not called (no
    `read_file` recorded); `ca.status` still succeeds.
29. **CA-AC29 — real OS [real-os].** On macOS and Linux: install → status
    `present` → uninstall → status `absent` on a throwaway CA, with four audit
    records written; the macOS test also runs `add-trusted-cert` a second time
    directly and prints its exit code and output (C8); the Debian test asserts
    no dangling `/etc/ssl/certs/aitmproxy-root-ca.pem` remains after uninstall
    (C10). (The Windows test exists for C11 but is not run in M2.)

## Left to the builder

Browser:

- `chromiumoxide::Browser::connect` details (URL form, handler task shape —
  mirror the current `launch` code); whether to prefer the ready-file or the
  port poll first.
- How `OBSCURA_CDP_TOKEN` is presented to `obscura serve` from
  `Browser::connect` (query parameter, header, or not supported). If it can be
  presented, set a per-launch random token; if chromiumoxide cannot present
  it, do not set it, log that the CDP endpoint is loopback-only and
  unauthenticated, and note it in the Coder report for the Security reviewer.
- Exact error strings beyond the fragments the ACs require; stderr tail size.
- Free-port selection helper; ready-file location (`$TMPDIR`), cleanup.
- The fake `obscura` fixture script and how tests find it.
- The HTTPS fixture server (rcgen self-signed + tokio-rustls + a tiny hyper
  handler serving `/`, `/img.png`, `/api`, `/xhr`, the click/type page).
- How the SIGTERM/SIGINT test (M2-AC9) finds the child's pid (parse `aitm`'s
  log line, or `pgrep -P`).
- `package.sh` details (target triple detection, asset naming, checksum file
  format) and the fork's release workflow YAML (which upstream targets to
  keep).
- Internal module layout within `aitm-browser`, test file organization,
  parametrization helper for the engine-twinned tests.

CA management:

- File layout inside `aitm-ca` beyond the module names above; the
  `ScriptedExecutor` API shape (keyed by rendered line vs. ordered script);
  the `TrustError` ↔ `anyhow` conversion.
- The exact regular expressions for parsing `security`, `certutil` and
  `update-ca-certificates` output, as long as the ACs' canned inputs parse as
  stated.
- `CmdLine::render` quoting details for arguments containing whitespace.
- How `is_root` is obtained in `RealExecutor` (the `id -u` route, or a safe
  wrapper already in `Cargo.lock`), with no `unsafe` and no new crate.
- Whether the fixture certificate is generated with `openssl` or with `rcgen`
  as a dev-dependency once and checked in; either way the fingerprints become
  literals in the plan.
- Where the timeout constants live and how `RealExecutor` implements the
  kill-on-timeout (thread + channel, or polling `try_wait`).
- The `usage()` text for the reserved `--yes` flag.
- `FileAuditLog` internals (how `open()` proves writability without leaving an
  empty line; `O_APPEND` + `create` with mode `0600` on Unix).

Config:

- The config-file struct mirror and its defaulting mechanics; how `--config`
  is stripped before `Cli::dispatch`.

## Open questions

Only Matt can answer these. Each has a recommended default so the plan can
proceed if the answer is "as written".

1. **Operator config surface.** Recommended: the **YAML config file** (D10 —
   the platform spec's stated plan, one small module in `aitm`; the
   `AITM_CA_ALLOW_AGENT_INSTALL` env bridge keeps working on top of it).
   Alternative: `AITM_*` env overrides only, leaving the file for later.
2. **Packaging scope.** Recommended: the **minimal `scripts/package.sh`** (D3:
   one tarball for the host platform, fork binary downloaded from the fork's
   GitHub Release and checksum-verified, no signing, no brew, no CI), with a
   full multi-target release pipeline and brew formula deferred to a later
   milestone. Alternative: build that pipeline now (then: is there an Apple
   signing identity?).

### Summary

M2 swaps the system Chrome for a bundled, forked obscura engine run as a
managed child (`obscura serve --proxy … --ca-cert <ca.crt>`), driven by the
unchanged chromiumoxide `BrowserDriver` over `Browser::connect`, so the six
`browser.*` MCP tools do not change. The fork (from upstream `034a147`) adds a
first-class, additive, fail-fast `--ca-cert` flag to all three of obscura's
HTTP clients and is upstreamed. The driver refuses an unpatched binary, scrubs
trust/proxy env from the child, always passes `--allow-private-network`
(aitmproxy's SSRF-filtered listener is the real guard), reaps the child on
signals, and tests prove images, `fetch()` and XHR are MITM'd with no bypass.
Chrome stays behind `browser.engine`. A new `aitm-ca` crate registers
`ca.export/status/install/uninstall` once for CLI and MCP: `ca.crt` only,
`ring` fingerprints, platform tools (`security`, `update-ca-certificates`/
`update-ca-trust`, `certutil`) behind an `Executor` trait so every command line
is unit-tested with canned output; MCP install/uninstall refused unless
`ca.allow_agent_install` (default off); CLI confirms unless `--yes`; every CA
operation lands in a fail-closed JSONL audit log. 22 tools.

### Architect's calls

Each is a default Matt can overturn on approval.

Browser:

1. Fork branch `aitm/ca-cert` from upstream commit `034a147` (not the
   `v0.2.5` tag); release tags `aitm-vN`; `render` build only, four platforms,
   no Windows; fork cloned to `/Users/matt/Security/obscura`, tasks in its
   worktrees; `cargo nextest` installed as a prerequisite.
2. Binary discovery order: config → `AITM_OBSCURA_BIN` → next to `aitm` →
   `PATH`; first existing candidate is final; no runtime download by `aitm`;
   `scripts/package.sh` is the only thing that downloads the binary
   (checksum-verified) and it builds one host-platform tarball.
3. `--help` contains `--ca-cert` is the gate; `--version` is logged, not
   pinned.
4. aitmproxy picks the CDP port (bind-and-release); readiness = ready-file or
   TCP connect; `start_timeout` 15 s, `stop_timeout` 5 s.
5. `--allow-private-network` always passed for the obscura engine (aitmproxy's
   SSRF-filtered listener is authoritative; M2-AC12 proves no bypass).
6. Child env scrubbed of `SSL_CERT_*`, `OBSCURA_*` trust/proxy vars, and
   `*_PROXY`; `headless = false` is ignored with a warning for obscura.
7. No restart of a dead child; no silent engine fallback; `main` handles
   SIGINT/SIGTERM and closes the driver on every orderly exit path; SIGKILL of
   `aitm` is accepted as the one orphaning case (no `unsafe`).
8. Additive `wire::assemble` returning `Assembled { proxy, ca }`; `build_proxy`
   unchanged; `Features.ca_plugin` injects a prebuilt `CaPlugin` for tests.
9. `CertAuthority` gains only `cert_path()`; the `ca.*` commands read `ca.crt`
   directly (C2).
10. Engine-backed tests parametrized on engine under `AITM_CHROME` /
    `AITM_OBSCURA`; memory measured and reported, not asserted.
11. YAML config file at `--config` / `AITM_CONFIG` / `<config_dir>/aitmproxy/config.yaml`
    (Open question 1); minimal `package.sh` (Open question 2).

CA management (C-numbering kept from the folded draft):

- **C1** Dependencies: `ring` (SHA-256, legacy SHA-1), `x509-parser`,
  `dirs`, `serde_json`, `time`; no `sha2`/`sha1`/`rcgen`/platform-crypto
  crates.
- **C2** New crate `crates/aitm-ca` with `CaPlugin`; reads `ca.crt` directly,
  not via `CertAuthority`.
- **C3** Fingerprint display `AB:CD:...` uppercase; tool-specific hex forms
  for `-Z` and `certutil`.
- **C4** `RealExecutor` timeouts 15 s (query) / 180 s (mutate), kill on
  expiry; `is_root` via `id -u`.
- **C5** Default scope `user` on macOS/Windows, `system` on Linux; `user` on
  Linux is an error.
- **C6** Linux family: anchor-directory existence first, `os-release`
  `ID`/`ID_LIKE` as tie-break, Fedora when undecidable, unsupported when no
  directory exists.
- **C7** Privilege: per-subprocess `sudo --` when not root (mkcert's model);
  no self-escalation, no password handling. (Was an open question in the
  folded draft; settled here because the alternative breaks on `HOME` under
  `sudo`.)
- **C8** macOS idempotency by check-first query, independent of
  `add-trusted-cert`'s unverified duplicate behaviour; rollback-delete after a
  failed trust step.
- **C9** Fixed Linux anchor names `aitmproxy-root-ca.crt` / `.pem`; uninstall
  removes a stale anchor too.
- **C10** `update-ca-certificates --fresh` after removal on Debian; plain run
  on install.
- **C11** Windows thumbprint = SHA-1 of DER, lowercase hex; whole-store dump
  parsed rather than `CertId` lookup; no `-f`; Windows impl unit-tested, not
  shipped or real-OS-tested in M2.
- **C12** `ca.export --out` refuses paths inside the CA directory.
- **C13** `AITM_CA_ALLOW_AGENT_INSTALL` environment bridge, applied after the
  config file.
- **C14** Gate mechanism: `Frontend` enum on `CommandHost`, default `Mcp`
  (gated); the command owns the policy.
- **C15** `dry_run` passes the MCP gate and is audited as `dry_run`. (Was an
  open question in the folded draft; settled here: it runs read-only queries
  and writes nothing.)
- **C16** CLI confirmation via a defaulted `Command::confirm_prompt`, a
  `Confirmer` trait, and a reserved `--yes` CLI flag that is not a `ParamDef`.
- **C17** `render_cli_value`: `Str` raw, `Bytes` raw, otherwise pretty JSON,
  replacing the Debug print in `main.rs`.
- **C18 (new)** Audit log: `CaConfig.audit_log`, default
  `<config_dir>/aitmproxy/ca-audit.jsonl` (sibling of the CA dir, never inside
  it), JSON Lines, `0600`, append-only, opened before anything else and
  fail-closed; records `ok` / `error` / `refused` / `dry_run` for
  export/install/uninstall; `ca.status` not recorded.
