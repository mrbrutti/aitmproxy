# aitmproxy Milestone 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** approved (2026-10-27 by Matt)
**Spec:** `docs/superpowers/specs/2026-10-27-aitmproxy-m2-obscura-browser-design.md` (approved 2026-10-27; M2-AC1–AC22, CA-AC1–AC29)
**Branch / worktree:** aitmproxy `feat/aitmproxy-m2`; obscura fork `aitm/ca-cert` in a worktree of `/Users/matt/Security/obscura`

**Goal:** Replace the system Chrome with a bundled, forked obscura engine that trusts the MITM CA through a first-class `--ca-cert` flag, behind the unchanged `BrowserDriver` and `browser.*` tools; add the `ca.*` command family (export/status/install/uninstall, agent-gated, audited); ship a YAML config file and a minimal packaging script — every M2 and CA acceptance criterion green.

**Architecture:** Two streams. **The fork** (a separate Cargo workspace, `mrbrutti/obscura`, branch `aitm/ca-cert` from upstream `034a147`) adds an additive, fail-fast `--ca-cert`/`OBSCURA_CA_CERT` root to all three of obscura's HTTP clients. **aitmproxy** spawns that binary as a managed child (`obscura serve --proxy … --ca-cert <ca.crt> --allow-private-network`), attaches the existing chromiumoxide driver with `Browser::connect`, selects the engine from `BrowserConfig.engine`, and exposes the CA from wiring. A new `aitm-ca` crate drives platform trust-store tools through an `Executor` trait with a `Frontend` gate on `CommandHost` and a fail-closed JSONL audit log. Streams are independent until the obscura-gated tests, which need the fork binary.

**Tech Stack:** Rust; chromiumoxide 0.9 (`Browser::connect`), tokio (`process`, `signal`), serde/serde_yaml/serde_json, ring (digests), x509-parser, time, dirs; obscura fork: reqwest/rustls, wreq/BoringSSL (stealth, not shipped), clap, deno_core; `cargo nextest` for the fork gate.

## Global Constraints

Every task's requirements implicitly include these (verbatim from the spec):

- **aitmproxy gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` before any review; `unsafe_code = "forbid"` stays (no FFI into crypt32, Security.framework, or `libc::geteuid`). Default `cargo test` is hermetic: no obscura binary, no Chrome, no network, no OS trust store. Gated tests: `AITM_CHROME=1`, `AITM_OBSCURA=1`; real-OS trust-store tests are `#[ignore]`d **and** need `AITM_REAL_OS_TESTS=1`.
- **Fork gate:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` as configured upstream, `cargo nextest run -p obscura-net -p obscura-js -p obscura-cli`; stealth tests only where CMake/Clang/libclang exist, reported as such.
- **TDD:** no production code without a failing test first; the Coder's report includes both runs.
- **Declared signatures are authoritative.** Types, fields and method signatures in the spec are copied exactly; bodies and file layout inside a module are the builder's.
- **Public trait surface is semver-stable.** Additions are defaulted trait methods (`Command::confirm_prompt`) and new members (`CommandHost::{with_frontend,frontend}`, `BrowserConfig.{engine,obscura}`, `CaConfig.{allow_agent_install,audit_log}`); no existing signature changes; `BrowserDriver` unchanged.
- **Dependencies (aitm-ca, call C1):** may add `ring = "0.17"`, `x509-parser = "0.18"`, `dirs = "5"`, `serde`/`serde_json`, `time`, `tracing`, `anyhow`; dev `tracing-subscriber = "0.3"`. Not allowed: `sha2`, `sha1`, `rcgen`, `security-framework`, `windows`/`windows-sys`/`winapi`, `rustls-platform-verifier`, `rustls-native-certs`, `openssl`, `tempfile`. aitmproxy adds no new TLS or hashing crate. The fork adds `webpki-root-certs` optional under `stealth` only.
- **Security posture:** the SSRF-filtered browser listener and `browser.navigate`'s guard are the authoritative SSRF control; deny-by-default for every new active capability (`ca.allow_agent_install` default `false`); the CA key stays `0600` in a `0700` dir and is never passed to, read by, or exported by any new code path; the obscura child gets the certificate **file** path only; `ca.*` commands open exactly one file in the CA directory: `ca.crt`.
- **Every subprocess is bounded** (obscura start/stop timeouts; `RealExecutor` 15 s query / 180 s mutate).
- **Platforms:** macOS (arm64, x86_64) and Linux (x86_64, aarch64, glibc ≥ 2.35) for the shipped binary; the Windows `TrustStore` impl is unit-tested only.
- **Frontend neutrality:** `aitm-mcp` and `aitm-cli` never learn command names; gate and confirmation go through `CommandHost` and the `Command` trait.
- **Git/gh run through the Terminal panel** (`run_in_terminal`), never the sandboxed shell (`CLAUDE.md`).

## Review Focus

Input classes the spec implies but no happy-path test exercises; each is pinned to a test in the owning task:

1. **obscura child dies or never listens.** A binary that passes the probe but exits during startup (bad flag, port in use) must surface its exit status and stderr tail, not hang to `start_timeout`. Pinned in Task 20 (`start_reports_early_exit`).
2. **Paths with whitespace.** A CA dir under `~/Library/Application Support/…` puts a space in `ca.crt`'s path; `CmdLine::render` must quote it and `security add-trusted-cert` must receive it as one argument. Pinned in Task 9 (`render_quotes_whitespace`) and Task 13 (`install_with_space_in_cert_path`).
3. **Unknown or misspelled config keys.** `browser.enigne: chrome` must be an error, not a silent default. Pinned in Task 22 (`unknown_key_is_an_error`).
4. **Multi-certificate PEM bundles and DER on `--ca-cert`.** A bundle of two roots must add two; a DER file must add one; a PEM with zero certificates must fail. Pinned in Task 2 (`extra_roots_count_bundle_and_der`, `empty_pem_is_an_error`).
5. **Binary present but not executable (quarantine / mode).** A discovered `obscura` without the exec bit must fail at spawn with the `xattr -d com.apple.quarantine` hint, not a bare `EACCES`. Pinned in Task 20 (`spawn_permission_error_carries_hint`).

---

## Overview

**Stream F — the fork (Tasks 1–6, 27, 29)** lives in `/Users/matt/Security/obscura`, branch `aitm/ca-cert`, and runs under the fork gate. **Stream A — aitmproxy (Tasks 7–26, 28, 30)** lives in the `feat/aitmproxy-m2` worktree. The streams meet at Task 24 (first obscura-gated test needs the fork binary from Task 6).

Phases in Stream A: **core types** (7, 8) → **`aitm-ca`** (9–16) and **frontend gate plumbing** (17, 18) → **browser** (19, 20) → **wiring + config + main** (21–23) → **gated tests** (24–26) → **packaging and exit** (28, 30).

**Parallel groups (disjoint files, after dependencies land):**

| Group | Tasks | Why disjoint |
|---|---|---|
| **P-F/A** | Stream F (1–6) ∥ Stream A (7–23) | different repositories |
| **P-F1** | 3 ∥ 4 (after 2) | `wreq_client.rs` vs `obscura-js/*` |
| **P-A1** | 7 ∥ 8 ∥ 9 | `aitm-core` vs `aitm-proto-http` vs new `aitm-ca` + workspace `Cargo.toml` |
| **P-A2** | 10 ∥ 11 ∥ 12 (after 9) | `cert.rs` vs `exec.rs`+`testing.rs` vs `audit.rs` |
| **P-A3** | 14 ∥ 15 (after 13) | `platform/linux.rs` vs `platform/windows.rs` |
| **P-A4** | 17 ∥ 18 ∥ 19 ∥ 22 (after 7) | `aitm-cli` vs `aitm-mcp` vs `aitm-browser/obscura.rs` vs `aitm/config_file.rs` |
| **P-A5** | 24 ∥ 25 ∥ 26 (after 6, 20, 23) | three new test files |
| **P-A6** | 28 ∥ 29 (after 24, 25) | `scripts/` vs the fork repo |

20 of 30 tasks sit in some parallel group; the longest sequential chain is 7 → 9 → 11 → 13 → 14 → 16 → 21 → 23 → 24 → 30 (10 tasks).

## Tasks

### Stream F — the obscura fork

### Task 1: Fork, clone, branch, fork gate baseline

- **Satisfies:** prerequisite for M2-AC1–AC5; spec Constraints "Fork prerequisites".
- **Depends on:** none. **Independent:** starts Stream F (P-F/A).
- **Files:** none in aitmproxy. Creates `/Users/matt/Security/obscura` (clone of `mrbrutti/obscura`), branch `aitm/ca-cert` at `034a147`, a worktree `/Users/matt/Security/obscura/.worktrees/aitm-ca-cert` for the Coder.
- **Change:** via the Terminal panel: `gh repo fork h4ckf0r0day/obscura --clone=false` (org `mrbrutti`); `git clone https://github.com/mrbrutti/obscura /Users/matt/Security/obscura`; `git remote add upstream https://github.com/h4ckf0r0day/obscura`; `git fetch upstream 034a147`; `git worktree add -b aitm/ca-cert .worktrees/aitm-ca-cert 034a147`; `cargo install cargo-nextest --locked`.
- **Test:** the baseline gate in the worktree: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo nextest run -p obscura-net` → exit 0; the report quotes the nextest summary line (`Summary [ … ] N tests run: N passed`). Also `grep -n "fn https_fixture_with_private_ca" crates/obscura-net/src/client.rs` → one hit (the fixture Tasks 2–4 reuse).
  - [ ] Fork + clone + worktree in the Terminal panel; record the HEAD SHA (`034a147…`).
  - [ ] Install nextest; run the baseline gate; paste output.
  - [ ] Commit nothing (no source change); report the SHA, the fixture line number, and the baseline summary.
- **Done when:** the baseline gate is green on `034a147` and the fixture helper is located.

### Task 2: `obscura-net` — extra root certificates for the reqwest client

- **Satisfies:** M2-AC1 (reqwest), M2-AC2 (strict), M2-AC3 (error on bad file, library half); Review Focus #4.
- **Depends on:** Task 1. **Independent:** no (Tasks 3–5 build on its API).
- **Files:** Modify `crates/obscura-net/src/client.rs` (around `configured_root_paths` `:18-34`, `configured_root_certificates` `:37-62`, `get_client` `:1090-1113`); tests in the same file's `mod tests` next to `configured_roots_trust_a_private_ca_via_ssl_cert_file` (`:2901`).
- **Interfaces — Produces:**
  ```rust
  pub fn set_extra_root_certificates(paths: &[PathBuf]) -> Result<usize, ObscuraNetError>; // parse all, store in a OnceLock; Err names the first bad path; returns certs loaded
  pub fn configured_root_certificates() -> &'static [reqwest::Certificate];              // now pub; env roots ∪ extra roots
  pub fn extra_root_pem() -> &'static [u8];                                                // concatenated PEM of the extra roots, for the wreq store
  ```
- **Change:** `set_extra_root_certificates` reads each path, parses as PEM bundle (`reqwest::Certificate::from_pem_bundle`) falling back to DER (`from_der`); a path that is unreadable, parses to zero certificates, or fails both parsers → `Err(ObscuraNetError::…)` whose `Display` contains the path; stores `Vec<Certificate>` plus the concatenated PEM bytes in `OnceLock`s (a second call after set → `Err` "already configured"; the CLI calls it once). `configured_root_certificates()` chains env-derived certs then extras. `get_client`'s condition becomes "env set **or** extras non-empty"; `danger_accept_invalid_certs(false)` untouched.
- **Test** (all reuse `https_fixture_with_private_ca()`; the fixture CA PEM written to a temp file):
  - `ca_cert_extra_roots_trust_a_private_ca`: `set_extra_root_certificates(&[tmp_pem])` → `Ok(1)`; a GET to the fixture → `Ok` with the fixture body.
  - `private_ca_still_rejected_without_extra_roots`: no env, no extras → the error text contains `UnknownIssuer`.
  - `extra_roots_do_not_relax_hostname_check`: fixture leaf for `localhost`, request to `https://127.0.0.1:<port>/` with extras set → error contains `NotValidForName` (or reqwest's `invalid peer certificate` + name text).
  - `extra_roots_count_bundle_and_der` (RF#4): a file holding two PEM roots → `Ok(2)`; the DER of one root → `Ok(1)`.
  - `empty_pem_is_an_error` (RF#4): a file with a `BEGIN CERTIFICATE` header and no valid cert → `Err` whose text contains the path.
  - `bad_extra_root_path_is_an_error`: `/nonexistent/ca.pem` → `Err` whose text contains `/nonexistent/ca.pem`.
  - [ ] Write tests → `cargo nextest run -p obscura-net ca_cert` → FAIL (fn missing) → implement → PASS → fork gate → commit `feat(net): --ca-cert extra roots, added to built-in and env roots`.
- **Done when:** the six tests pass and the fork gate is green.

### Task 3: `obscura-net` — stealth store adds, never replaces

- **Satisfies:** M2-AC1 (stealth), M2-AC2 (webpki retained).
- **Depends on:** Task 2. **Independent:** yes — **P-F1** with Task 4.
- **Files:** Modify `crates/obscura-net/src/wreq_client.rs` (`StealthHttpClient::with_proxy`, `:222-272`) and `crates/obscura-net/Cargo.toml` (`webpki-root-certs` optional, enabled by `stealth`).
- **Change:** build the store unconditionally as `CertStore::builder().add_der_certs(webpki_root_certs::TLS_SERVER_ROOT_CERTS…)`, then `.set_default_paths()` **only when** `SSL_CERT_FILE`/`SSL_CERT_DIR` is set, then `.add_stack_pem_certs(extra_root_pem())` when non-empty, `.build()` → `tls_cert_store`. The pre-existing env path therefore stops replacing webpki (called out in the commit message as a fix).
- **Test** (`#[cfg(feature = "stealth")]`): `stealth_ca_cert_trusts_private_ca` (fixture GET → `Ok`); `stealth_store_keeps_webpki_roots` (with extras set, the built store's certificate count ≥ `webpki_root_certs::TLS_SERVER_ROOT_CERTS.len()`, or — if `CertStore` exposes no count — a GET to a webpki-trusted local fixture signed by a second fixture CA **fails** while a GET with that CA added via `SSL_CERT_FILE` succeeds, proving env is additive too).
  - [ ] Tests → `cargo nextest run -p obscura-net --features stealth stealth_` → FAIL → implement → PASS (where the BoringSSL toolchain exists; otherwise report "stealth not built here" and the compile check `cargo check -p obscura-net --features stealth` if possible) → fork gate → commit.
- **Done when:** stealth tests pass where buildable; the non-stealth gate is green everywhere.

### Task 4: `obscura-js` — page `fetch()`/XHR and module-loader clients get the roots

- **Satisfies:** M2-AC4.
- **Depends on:** Task 2. **Independent:** yes — **P-F1** with Task 3.
- **Files:** Modify `crates/obscura-js/src/ops.rs` (`build_request_client`, `:3437`) and `crates/obscura-js/src/module_loader.rs` (the standalone client constructor, `with_base_url_and_proxy` or its successor).
- **Change:** after proxy configuration, `for c in obscura_net::configured_root_certificates() { builder = builder.add_root_certificate(c.clone()); }` in both constructors. No other change.
- **Test:** `fallback_fetch_client_trusts_extra_roots`: with `set_extra_root_certificates` pointing at the fixture CA, the client from `build_request_client(Some(proxy_url_to_fixture))` (or a direct fixture URL when the function allows no proxy) GETs the fixture → `Ok`; `module_loader_standalone_client_trusts_extra_roots`: same via the loader's client. (If the fixture helper is private to `obscura-net`, re-create a minimal rcgen fixture in a `tests/support` module of `obscura-js` — builder's choice, noted in the report.)
  - [ ] Tests → FAIL → implement → PASS → fork gate → commit `fix(js): page fetch and module loader honor configured root certificates`.
- **Done when:** both tests pass and the gate is green.

### Task 5: `obscura-cli` — `--ca-cert`, `OBSCURA_CA_CERT`, fail-fast, help, worker propagation

- **Satisfies:** M2-AC3 (startup exit), M2-AC5.
- **Depends on:** Tasks 2, 3, 4. **Independent:** no.
- **Files:** Modify `crates/obscura-cli/src/main.rs` (global args `:30-61`; env mirror site `:440-449`; worker spawn sites `:909-914`, `:2095`); tests in `main.rs` `mod tests` and `crates/obscura-cli/tests/ca_cert_cli.rs` (new).
- **Interfaces — Produces:** CLI contract for aitmproxy: `obscura --ca-cert <PATH> [--ca-cert <PATH>]… serve …`; env `OBSCURA_CA_CERT=<path>[:<path>…]`; help line exactly `Trust the certificate(s) in PATH as additional root CAs, added to the built-in roots. Repeatable. PEM bundle or DER.`
- **Change:** `#[arg(long, global = true, value_name = "PATH", help = "<text above>")] ca_cert: Vec<PathBuf>`; at startup, next to the `--allow-private-network` env mirror: `let mut paths = cli.ca_cert.clone(); if let Some(v) = env::var_os("OBSCURA_CA_CERT") { paths.extend(env::split_paths(&v)); }`; if non-empty → `set_extra_root_certificates(&paths)`, on `Err(e)` print `error: --ca-cert: {e}` to stderr and `std::process::exit(2)` **before** any command runs; at both worker-spawn sites `cmd.env("OBSCURA_CA_CERT", env::join_paths(&paths)?)` when non-empty.
- **Test:**
  - `main.rs::tests::ca_cert_is_repeatable_and_global`: parse `["obscura", "--ca-cert", "a", "serve", "--ca-cert", "b"]` → `ca_cert == [PathBuf::from("a"), PathBuf::from("b")]`.
  - `main.rs::tests::ca_cert_help_text`: `Cli::command().render_long_help().to_string()` contains the exact help line.
  - `main.rs::tests::env_merges_after_flags`: the pure merge fn with flags `[a]` and env `"b:c"` → `[a, b, c]`.
  - `ca_cert_cli.rs::bad_ca_cert_exits_before_serving`: run `env!("CARGO_BIN_EXE_obscura")` with `--ca-cert /nonexistent/x.pem serve --port 0` → exit code `2`, stderr contains `/nonexistent/x.pem`, and a TCP listener on the port that would have been used is never contacted (use a fixed free port and assert no connection within 500 ms).
  - `ca_cert_cli.rs::help_lists_ca_cert`: `obscura --help` stdout contains `--ca-cert` (this is the exact probe aitmproxy runs — Task 19).
  - [ ] Tests → FAIL → implement → PASS → fork gate → commit `feat(cli): --ca-cert / OBSCURA_CA_CERT, fail fast, propagate to workers`.
- **Done when:** the five tests pass and the gate is green.

### Task 6: Fork docs, tag `aitm-v1`, release build

- **Satisfies:** M2-AC3 (documented), prerequisite for M2-AC8–AC15, AC19.
- **Depends on:** Task 5. **Independent:** no.
- **Files (fork):** Modify `docs/CLI-reference.md`, `docs/Configure-stealth-and-proxies.md`, `docs/Environment-variables.md` (document `--ca-cert`, `OBSCURA_CA_CERT`, and the hitherto undocumented `SSL_CERT_FILE`/`SSL_CERT_DIR`, including the "dir with a private key panics" caveat); add `.github/workflows/aitm-release.yml` (on tag `aitm-v*`: build `obscura-cli --release --features render --bins` for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu` (Ubuntu 22.04), `aarch64-unknown-linux-gnu`; upload `obscura-<target>.tar.gz` + `SHA256SUMS`).
- **Change:** docs as above; workflow derived from upstream's release workflow with the targets trimmed and the `obscura-worker` binary omitted.
- **Test:** fork gate green; `cargo build --release -p obscura-cli --bins --features render` locally → `target/release/obscura --help` contains `--ca-cert` and `target/release/obscura --version` prints a version; copy the local binary to `/Users/matt/Security/obscura/dist/obscura` for Stream A tests (`AITM_OBSCURA_BIN`). Tag and push via the Terminal panel: `git tag aitm-v1 && git push origin aitm/ca-cert aitm-v1`; the Actions run is observed with `gh run watch` and its four assets + `SHA256SUMS` are listed with `gh release view aitm-v1`.
  - [ ] Docs → gate → commit `docs: --ca-cert, OBSCURA_CA_CERT, SSL_CERT_FILE/DIR`.
  - [ ] Workflow → commit → tag → push → watch the run → record asset names and the local binary's path and SHA-256 in the report.
- **Done when:** `aitm-v1` release has four tarballs + `SHA256SUMS`, and a local `render` binary whose `--help` contains `--ca-cert` is at a recorded path.

### Stream A — aitmproxy

### Task 7: `aitm-core` additive types: engine, obscura config, CA fields, `Frontend`, `confirm_prompt`

- **Satisfies:** foundation for M2-AC7, AC8, AC18; CA-AC19–23, AC27; spec §D5, §D8 "Policy gate", §D9.
- **Depends on:** none. **Independent:** yes — **P-A1**.
- **Files:** Modify `crates/aitm-core/src/config.rs`, `crates/aitm-core/src/ctx.rs`, `crates/aitm-core/src/command.rs`, `crates/aitm-core/src/lib.rs` (re-exports). Test: `crates/aitm-core/tests/m2_types.rs` (new).
- **Interfaces — Produces** (exactly as spec §D4/§D5/§D8):
  ```rust
  // config.rs
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub enum BrowserEngine { #[default] Obscura, Chrome }
  #[derive(Debug, Clone)] pub struct ObscuraConfig { pub binary: Option<PathBuf>, pub start_timeout: Duration, pub stop_timeout: Duration }  // Default: None, 15 s, 5 s
  pub struct BrowserConfig { pub engine: BrowserEngine, pub obscura: ObscuraConfig, /* existing fields unchanged */ }
  pub struct CaConfig { pub dir: PathBuf, pub key_mode: u32, pub allow_agent_install: bool, pub audit_log: PathBuf }  // defaults: false; default_ca_audit_log()
  fn default_ca_audit_log() -> PathBuf;   // <config_dir>/aitmproxy/ca-audit.jsonl with the same fallbacks as default_ca_dir()
  // ctx.rs
  #[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Frontend { Cli, Mcp }
  impl<'a> CommandHost<'a> { pub fn with_frontend(self, frontend: Frontend) -> Self; pub fn frontend(&self) -> Frontend; }  // default Mcp
  // command.rs
  pub trait Command { /* existing */ fn confirm_prompt(&self, args: &Params) -> Option<String> { None } }
  ```
- **Test:**
  - `m2_types.rs::browser_defaults`: `BrowserConfig::default().engine == BrowserEngine::Obscura`; `.obscura.binary == None`; `.obscura.start_timeout == Duration::from_secs(15)`; `.obscura.stop_timeout == Duration::from_secs(5)`.
  - `m2_types.rs::ca_defaults`: `CaConfig::default().allow_agent_install == false`; `audit_log.file_name() == Some("ca-audit.jsonl")`; `audit_log.parent() == CaConfig::default().dir.parent()` (sibling of the CA dir, not inside it); `!audit_log.starts_with(&dir)`.
  - `m2_types.rs::frontend_defaults_to_mcp`: a `CommandHost::new(...)` over stub services → `frontend() == Frontend::Mcp`; `.with_frontend(Frontend::Cli).frontend() == Frontend::Cli`.
  - `m2_types.rs::confirm_prompt_defaults_to_none`: a test `Command` without an override → `confirm_prompt(&Params::new(BTreeMap::new())) == None`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(core): BrowserEngine/ObscuraConfig, CaConfig gate+audit path, Frontend on CommandHost, Command::confirm_prompt`.
- **Done when:** tests pass; existing tests still compile (struct-update syntax `..Default::default()` keeps them green).

### Task 8: `CertAuthority::cert_path()`

- **Satisfies:** M2-AC16 (first half); spec §D7.
- **Depends on:** none. **Independent:** yes — **P-A1**.
- **Files:** Modify `crates/aitm-proto-http/src/ca.rs`; test `crates/aitm-proto-http/tests/ca.rs` (append).
- **Interfaces — Produces:** `impl CertAuthority { pub fn cert_path(&self) -> &Path; }` — `<dir>/ca.crt` as loaded or written.
- **Change:** store `cert_path: PathBuf` on `CertAuthority` in `load_or_generate` (both branches).
- **Test:** `ca.rs::cert_path_after_generate_and_reload`: fresh temp dir → `load_or_generate(&dir, 0o600)?.cert_path() == dir.join("ca.crt")`; a second `load_or_generate` on the same dir → same path; `ca.key` bytes and mode (`0o600`) unchanged by the accessor.
  - [ ] Test → FAIL → implement → PASS → gate → commit.
- **Done when:** test passes.

### Task 9: `aitm-ca` skeleton: crate, `Executor` types, `AuditLog` trait, fixture CA, research note

- **Satisfies:** foundation for CA-AC1–AC29; Review Focus #2 (render quoting).
- **Depends on:** none. **Independent:** yes — **P-A1**.
- **Files:** Create `crates/aitm-ca/Cargo.toml`, `crates/aitm-ca/src/{lib.rs,cert.rs,exec.rs,audit.rs,store.rs,commands.rs,testing.rs}`, `crates/aitm-ca/src/platform/{mod.rs,macos.rs,linux.rs,windows.rs}` (modules declared; non-skeleton files hold only a doc comment until their task), `crates/aitm-ca/tests/fixtures/ca.crt`, `crates/aitm-ca/tests/exec.rs`. Modify workspace `Cargo.toml` (member + `aitm-ca = { path = "crates/aitm-ca" }`). Cherry-pick `docs/research/07-ca-install.md` from `claude/ca-commands-d9b1bc` (Terminal panel: `git checkout claude/ca-commands-d9b1bc -- docs/research/07-ca-install.md`) and add its index line to `docs/research/README.md`.
- **Interfaces — Produces** (exactly as spec §D8 "Shell-outs behind a trait" / "Audit log"):
  ```rust
  // exec.rs
  pub struct CmdLine { pub program: String, pub args: Vec<String>, pub stdin: Option<Vec<u8>>, pub mutating: bool }
  impl CmdLine { pub fn render(&self) -> String; }
  pub struct CmdOutput { pub code: Option<i32>, pub stdout: String, pub stderr: String }
  impl CmdOutput { pub fn success(&self) -> bool; }
  pub trait Executor: Send + Sync { fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput>; fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>>; fn dir_exists(&self, path: &Path) -> bool; fn home_dir(&self) -> Option<PathBuf>; fn is_root(&self) -> bool; }
  // audit.rs
  #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
  pub struct AuditRecord { pub ts: String, pub command: &'static str, pub frontend: &'static str, pub outcome: &'static str, pub scope: Option<String>, pub platform: Option<String>, pub fingerprint_sha256: Option<String>, pub detail: String }
  pub trait AuditLog: Send + Sync { fn open(&self) -> anyhow::Result<()>; fn record(&self, rec: &AuditRecord) -> anyhow::Result<()>; }
  // testing.rs
  pub const FIXTURE_FP256: &str = "<FP256>";   // recorded below after generation
  pub const FIXTURE_FP1: &str = "<FP1>";
  ```
- **Change:** `Cargo.toml` deps per Global Constraints (C1). Generate the fixture once with `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null -subj "/CN=aitmproxy test fixture CA" -days 3650 -out tests/fixtures/ca.crt` (key discarded; only the cert is checked in); compute `openssl x509 -in tests/fixtures/ca.crt -noout -fingerprint -sha256` and `-sha1`; the Coder's report states both; **the orchestrator records them here:** `<FP256> = ________`, `<FP1> = ________`, and Tasks 10–16 use `FIXTURE_FP256`/`FIXTURE_FP1`.
- **Test:**
  - `exec.rs::render_joins_with_single_spaces`: `CmdLine{program:"security", args:["find-certificate","-a","-Z","/k"]}.render() == "security find-certificate -a -Z /k"`.
  - `exec.rs::render_quotes_whitespace` (RF#2): arg `"/Users/t/Library/Application Support/x/ca.crt"` renders single-quoted; `stdin` never appears in `render()`.
  - `exec.rs::success_is_code_zero`: `code: Some(0)` → `true`; `Some(1)`/`None` → `false`.
  - `exec.rs::audit_record_roundtrips_json`: `serde_json::to_string` of a record then `from_str` → equal; the JSON object has exactly the keys `ts, command, frontend, outcome, scope, platform, fingerprint_sha256, detail`.
  - `exec.rs::fixture_is_one_certificate`: `tests/fixtures/ca.crt` contains exactly one `-----BEGIN CERTIFICATE-----` and no `PRIVATE KEY`.
  - [ ] Tests → FAIL → implement → PASS → gate (`cargo test -p aitm-ca`, whole workspace) → commit `feat(ca): aitm-ca skeleton, Executor/CmdLine, AuditRecord/AuditLog, fixture CA` + `docs(research): 07 CA install`.
- **Done when:** the workspace builds with the new member, five tests pass, fingerprints reported.

### Task 10: `CaCert`

- **Satisfies:** CA-AC1 (fingerprints), CA-AC2 (DER), CA-AC3 (missing/invalid), CA-AC24 (reads only `ca.crt`).
- **Depends on:** Task 9. **Independent:** yes — **P-A2**.
- **Files:** Modify `crates/aitm-ca/src/cert.rs`; test `crates/aitm-ca/tests/cert.rs`.
- **Interfaces — Produces** (spec §D8 "The certificate as the commands see it"): `pub struct CaCert { pub path, pub pem, pub der, pub sha256: [u8;32], pub sha1: [u8;20] }`; `CaCert::load(dir: &Path, exec: &dyn Executor) -> anyhow::Result<Option<CaCert>>`; `fingerprint_sha256()`, `fingerprint_sha1()`, `sha256_hex()`, `sha1_hex_lower()`; `pub fn sha256_of(der: &[u8]) -> [u8; 32]`.
- **Change:** `load` calls `exec.read_file(&dir.join("ca.crt"))` only; parses with `x509_parser::pem::Pem::iter_from_buffer`; exactly one block with label `CERTIFICATE` else `Err` (`ca.crt must hold exactly one PEM CERTIFICATE block, found N`); digests via `ring::digest::{SHA256, SHA1_FOR_LEGACY_USE_ONLY}`.
- **Test** (uses a minimal in-test `Executor` stub with a file map until Task 11's `ScriptedExecutor` lands — or depends on Task 11 if the Coder prefers; builder's call, noted in the report):
  - `cert.rs::fixture_fingerprints`: `fingerprint_sha256() == FIXTURE_FP256`, `fingerprint_sha1() == FIXTURE_FP1`, `sha256_hex() == FIXTURE_FP256.replace(':', "")`, `sha1_hex_lower() == FIXTURE_FP1.replace(':', "").to_lowercase()`, `der[0..2] == [0x30, 0x82]`.
  - `cert.rs::missing_is_none`: empty file map → `Ok(None)`; `read_file` was called with exactly `/ca/ca.crt`.
  - `cert.rs::two_blocks_is_an_error`: the fixture concatenated twice → `Err` containing `exactly one`.
  - `cert.rs::key_is_never_read`: file map also holds `/ca/ca.key`; after `load`, recorded `read_file` paths == `["/ca/ca.crt"]`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** four tests pass.

### Task 11: `RealExecutor`, `DryRunExecutor`, `ScriptedExecutor`, `MemoryAuditLog`

- **Satisfies:** CA-AC26 (timeout), CA-AC21 (dry-run mechanics), test infrastructure for CA-AC5–AC25.
- **Depends on:** Task 9. **Independent:** yes — **P-A2**.
- **Files:** Modify `crates/aitm-ca/src/exec.rs` (add `RealExecutor`, `DryRunExecutor`), `crates/aitm-ca/src/testing.rs` (add `ScriptedExecutor`, `MemoryAuditLog`); test `crates/aitm-ca/tests/executors.rs`.
- **Interfaces — Produces:**
  ```rust
  pub struct RealExecutor { /* query_timeout, mutate_timeout */ }
  impl RealExecutor { pub fn new() -> Self /* 15 s / 180 s */; pub fn with_timeouts(query: Duration, mutate: Duration) -> Self; }
  pub struct DryRunExecutor<'a> { /* inner: &'a dyn Executor, recorded: Mutex<Vec<String>> */ }
  impl<'a> DryRunExecutor<'a> { pub fn new(inner: &'a dyn Executor) -> Self; pub fn recorded(&self) -> Vec<String>; }
  // testing.rs
  pub struct ScriptedExecutor { /* responses keyed by rendered line, default response, files: BTreeMap<PathBuf, Vec<u8>>, dirs, home, is_root, recorded runs (line + stdin), recorded reads */ }
  impl ScriptedExecutor {
      pub fn new() -> Self;  // home "/Users/t", is_root false, default response code 0 empty
      pub fn respond(self, rendered: &str, code: i32, stdout: &str, stderr: &str) -> Self;
      pub fn file(self, path: &str, bytes: &[u8]) -> Self; pub fn dir(self, path: &str) -> Self;
      pub fn root(self, is_root: bool) -> Self; pub fn with_real_fs(self) -> Self;
      pub fn runs(&self) -> Vec<String>; pub fn stdins(&self) -> Vec<Option<Vec<u8>>>; pub fn reads(&self) -> Vec<PathBuf>;
  }
  pub struct MemoryAuditLog { /* Mutex<Vec<AuditRecord>>, fail_open: bool */ }
  impl MemoryAuditLog { pub fn new() -> Self; pub fn failing() -> Self /* open() returns Err */; pub fn records(&self) -> Vec<AuditRecord>; }
  ```
- **Change:** `RealExecutor::run`: `std::process::Command` with stdin piped from `cmd.stdin` or `Stdio::null()`, stdout/stderr piped, wall-clock timeout per `mutating` (thread + `try_wait` polling or channel — builder's), on expiry `Child::kill` and `Err` containing `timed out` and `cmd.render()`; `is_root` via `id -u` through `run` (Unix), `false` (Windows). `DryRunExecutor`: passes through non-mutating `run` and all reads; records mutating lines and returns `CmdOutput{code:Some(0),..}`.
- **Test:**
  - `executors.rs::real_executor_times_out` (CA-AC26, `#[cfg(unix)]`): `with_timeouts(_, 200 ms)` running `CmdLine{program:"sleep", args:["5"], mutating:true}` → `Err` containing `timed out` within 2 s (measure elapsed).
  - `executors.rs::real_executor_captures_output` (`#[cfg(unix)]`): `sh -c 'echo out; echo err >&2; exit 3'` → `code == Some(3)`, `stdout == "out\n"`, `stderr == "err\n"`.
  - `executors.rs::dry_run_records_mutating_only`: scripted inner; one non-mutating + one mutating `run` → inner saw only the first; `recorded() == [mutating.render()]`; the mutating result is `code == Some(0)`.
  - `executors.rs::scripted_records_runs_reads_and_stdin`: a `tee` line with `stdin: Some(b"pem")` → `stdins() == [Some(b"pem")]`; `read_file` of a mapped path returns it and `reads()` lists it; an unmapped path → `Ok(None)`.
  - `executors.rs::memory_audit_failing_open`: `MemoryAuditLog::failing().open()` → `Err`; `new().open()` → `Ok`, `record` appends.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** five tests pass.

### Task 12: `FileAuditLog`

- **Satisfies:** CA-AC28 (file half), spec §D8 "Audit log" (C18).
- **Depends on:** Task 9. **Independent:** yes — **P-A2**.
- **Files:** Modify `crates/aitm-ca/src/audit.rs`; test `crates/aitm-ca/tests/audit.rs`.
- **Interfaces — Produces:** `pub struct FileAuditLog { /* path */ }`; `FileAuditLog::new(path: PathBuf) -> Self`; `impl AuditLog` — `open()` creates the parent directory (`0o700` on Unix) if missing and opens/creates the file with `O_APPEND` and mode `0o600` (Unix), returning `Err` naming the path on failure; `record()` appends `serde_json::to_string(rec)? + "\n"` in one `write_all`; `pub fn now_rfc3339() -> String` (via `time::OffsetDateTime::now_utc().format(&Rfc3339)`, seconds precision).
- **Test:**
  - `audit.rs::creates_0600_and_appends_lines`: temp path with a missing parent → `open()` `Ok`; parent exists; two `record`s → file has two lines; each parses as JSON with exactly the eight keys; mode `& 0o777 == 0o600` (Unix); the first line is byte-identical after the second append.
  - `audit.rs::open_fails_when_path_is_a_directory`: path pointing at an existing directory → `open()` `Err` whose text contains the path.
  - `audit.rs::rfc3339_parses`: `time::OffsetDateTime::parse(&now_rfc3339(), &Rfc3339)` → `Ok`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** three tests pass.

### Task 13: Store model + macOS trust store

- **Satisfies:** CA-AC5, CA-AC9, CA-AC10, CA-AC11, CA-AC12; Review Focus #2.
- **Depends on:** Tasks 10, 11. **Independent:** no (defines the types Tasks 14–16 use).
- **Files:** Modify `crates/aitm-ca/src/store.rs`, `crates/aitm-ca/src/platform/{mod.rs,macos.rs}` (`linux.rs`/`windows.rs` get a `LinuxStore(pub LinuxFamily)` / `WindowsStore` struct whose three methods return `TrustError{kind: UnsupportedPlatform, message: "not implemented"}` until Tasks 14/15); test `crates/aitm-ca/tests/macos.rs`.
- **Interfaces — Produces** (exactly spec §D8 "Platform model"): `Scope`, `LinuxFamily`, `Platform` (+ `detect`, `label`, `scopes`, `default_scope`), `detect_linux_family` (stub `None` until Task 14), `Presence`, `Trust`, `StoreStatus`, `Change`, `TrustStore` trait, `MacOsStore`, `LinuxStore`, `WindowsStore`, `UnsupportedStore`, `store_for`, `TrustErrorKind`, `TrustError` (+ `impl std::error::Error`, `From<TrustError> for anyhow::Error` via `?`). `Scope: FromStr` (`"user"`/`"system"` exact) and `label() -> &'static str`.
- **Change:** `MacOsStore` per the spec's macOS table: keychain paths `K_user = <home>/Library/Keychains/login.keychain-db`, `K_sys = /Library/Keychains/System.keychain`; status parses `SHA-256 hash:`/`SHA-1 hash:` blocks; install = query → `add-trusted-cert [-d] -r trustRoot -p ssl -p basic -k <K> <P>` → classify stderr → rollback delete; uninstall = query → `remove-trusted-cert [-d] <P>` (failure tolerated) → `delete-certificate -Z <S256>` → fallback `-Z <S1>` → re-query, ≤ 3 passes → `CopiesRemain`. `[sudo] = "sudo --"` prefix when `!exec.is_root()` and the scope is `System`.
- **Test** (all with `ScriptedExecutor`, fixture at `/ca/ca.crt`, home `/Users/t`; `Q_user = "security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db"`):
  - `macos.rs::status_present_absent_sha1_only` (CA-AC5): canned outputs (a) block with `SHA-256 hash: <FP256 hex>` → `Present`; (b) other hashes → `Absent`; (c) `SHA-1 hash: <FP1 hex upper>` only → `Present`; `trusted == Trust::Unknown` in all; `detail` contains `Keychain Access`; exit 1 → `Unknown`; both scopes' queries are exactly `Q_user` and `security find-certificate -a -Z /Library/Keychains/System.keychain`.
  - `macos.rs::install_user_idempotent` (CA-AC9): absent → `runs() == [Q_user, "security add-trusted-cert -r trustRoot -p ssl -p basic -k /Users/t/Library/Keychains/login.keychain-db /ca/ca.crt"]`, `changed == true`; present → `runs() == [Q_user]`, `changed == false`.
  - `macos.rs::install_system_sudo` (CA-AC10): `root(false)` → second line `"sudo -- security add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain /ca/ca.crt"`; `root(true)` → same without `sudo -- `; the query line never has the prefix.
  - `macos.rs::install_headless_rolls_back` (CA-AC11): `add-trusted-cert` exit 1, stderr `SecTrustSettingsSetTrustSettings: The authorization was denied since no user interaction was possible` → `Err` text contains `GUI session` and the stderr; with the post-failure query canned `Present`, `runs()` ends with `"security delete-certificate -Z <FP256 hex> /Users/t/Library/Keychains/login.keychain-db"`; `kind == HeadlessAuth`.
  - `macos.rs::uninstall_sequence_and_sha1_fallback` (CA-AC12): present → `runs() == [Q_user, "security remove-trusted-cert /ca/ca.crt", "security delete-certificate -Z <FP256 hex> /Users/t/Library/Keychains/login.keychain-db", Q_user]`, `changed == true`; absent → `[Q_user]`, `changed == false`; SHA-256 delete exit 1 → next line uses `-Z <FP1 lower>`; `system` adds `-d` and `sudo -- `.
  - `macos.rs::install_with_space_in_cert_path` (RF#2): cert at `/Users/t/Application Support/ca/ca.crt` → the `add-trusted-cert` `CmdLine.args` last element equals that path unquoted and `render()` shows it single-quoted.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** six tests pass.

### Task 14: Linux trust store + family detection

- **Satisfies:** CA-AC6, CA-AC7, CA-AC13, CA-AC14, CA-AC15, CA-AC16, CA-AC17.
- **Depends on:** Task 13. **Independent:** yes — **P-A3** with Task 15.
- **Files:** Modify `crates/aitm-ca/src/platform/linux.rs`, `crates/aitm-ca/src/store.rs` (only the `detect_linux_family` body); test `crates/aitm-ca/tests/linux.rs`.
- **Change:** per the spec's Linux tables (anchors `A`, bundles `B`, refresh `R`/`R_rm`; `tee <A>` with `stdin = cert.pem`; `rm -f <A>`; `NeedsRoot` on `Permission denied`/`Operation not permitted`/`sudo:`; `ToolMissing` on spawn failure; `Stale` handling) and the family-detection algorithm (§D8 "Linux family detection", steps 1–4).
- **Test** (`ScriptedExecutor`, `root(false)` unless stated):
  - `linux.rs::debian_status_matrix` (CA-AC6): anchor == fixture + bundle containing it → (`Present`, `Yes`); anchor = other cert + bundle without → (`Stale`, `No`); no anchor → (`Absent`, `No`); anchor present, bundle missing → (`Present`, `Unknown`); `runs() == []` in all; `reads() == [A, B]`.
  - `linux.rs::fedora_status_paths` (CA-AC7): same with `/etc/pki/ca-trust/source/anchors/aitmproxy-root-ca.pem` and `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`.
  - `linux.rs::debian_install` (CA-AC13): absent → `runs() == ["sudo -- tee /usr/local/share/ca-certificates/aitmproxy-root-ca.crt", "sudo -- update-ca-certificates"]`, `stdins()[0] == Some(fixture pem bytes)`, `changed == true`; canned stdout `1 added, 0 removed; done.` → `detail` contains `1 added, 0 removed`; present+`Yes` → `[]`, `changed == false`; present+`No` → `["sudo -- update-ca-certificates"]`; `root(true)` → no prefixes; exit 1 + stderr `Permission denied` → `Err` containing `needs root`.
  - `linux.rs::debian_uninstall` (CA-AC14): present → `["sudo -- rm -f /usr/local/share/ca-certificates/aitmproxy-root-ca.crt", "sudo -- update-ca-certificates --fresh"]`, `changed == true`; absent → `[]`; stale → same two lines and `detail` contains `stale`.
  - `linux.rs::fedora_install_uninstall` (CA-AC15): `.pem` anchor and `sudo -- update-ca-trust extract` as both refreshes.
  - `linux.rs::user_scope_rejected` (CA-AC16): `Scope::User` → `Err` containing `no per-user OS trust store`; `Platform::Linux(_).default_scope() == Some(Scope::System)`.
  - `linux.rs::family_detection` (CA-AC17): only Fedora dir → `Some(Fedora)`; only Debian → `Some(Debian)`; both + `/etc/os-release` `ID=ubuntu` → `Debian`; both + `ID_LIKE="rhel fedora"` → `Fedora`; both + no os-release → `Fedora`; neither → `None` and `Platform::detect` (with `cfg!(target_os="linux")` forced via a `detect_with_os("linux", exec)` test seam) → `Unsupported("linux")`; `UnsupportedStore` install `Err` names both directories and `/ca/ca.crt`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** seven tests pass.

### Task 15: Windows trust store

- **Satisfies:** CA-AC8, CA-AC18 (unit-tested only; not shipped).
- **Depends on:** Task 13. **Independent:** yes — **P-A3** with Task 14.
- **Files:** Modify `crates/aitm-ca/src/platform/windows.rs`; test `crates/aitm-ca/tests/windows.rs`.
- **Change:** per the spec's Windows table: `certutil [-user] -store Root` parse of `Cert Hash(sha1):` lines (spaces stripped, lowercased); `-addstore Root <P>` (no `-f`); `-delstore Root <S1>`; `NeedsRoot` on `0x80070005`/`Access is denied`; `trusted` mirrors `installed`.
- **Test:**
  - `windows.rs::status_parse` (CA-AC8): `Cert Hash(sha1): <FP1 with spaces, mixed case>` → `Present`, `Yes`; other hashes → `Absent`, `No`; exit 1 → `Unknown`/`Unknown`; no `Cert Hash` lines → `Unknown` with detail containing `could not parse`; `system` scope line is `certutil -store Root`.
  - `windows.rs::install_uninstall` (CA-AC18): user, absent → `["certutil -user -store Root", format!("certutil -user -addstore Root {}", cert.path.display())]`, `changed == true`; present → first line only; system → no `-user`; uninstall present → `["certutil -user -store Root", "certutil -user -delstore Root <FP1 lower>"]`; `-addstore` exit 1 with `Access is denied. 0x80070005` → `Err` containing `Administrator`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** both tests pass on macOS/Linux hosts.

### Task 16: The four `ca.*` commands and `CaPlugin`

- **Satisfies:** CA-AC1, AC2, AC3, AC4, AC19–AC21 (command level), AC24, AC25, AC28 (fail-closed half); spec §D8 "Command surface", "Policy gate", "Audit log", "Logging".
- **Depends on:** Tasks 7, 10, 11, 12, 13, 14, 15. **Independent:** no.
- **Files:** Modify `crates/aitm-ca/src/commands.rs`, `crates/aitm-ca/src/lib.rs` (`CaPlugin`, re-exports); test `crates/aitm-ca/tests/commands.rs`; create `crates/aitm-ca/tests/real_os.rs` (CA-AC29, `#[ignore]`). Dev-dep `tracing-subscriber`.
- **Interfaces — Produces** (spec §D8 "Where it lives"):
  ```rust
  #[derive(Clone)]  // all fields are Arc/Clone, so wire::Features can hold one and stay Clone; manual Debug prints the config only
  pub struct CaPlugin { /* cfg: CaConfig, exec: Arc<dyn Executor>, audit: Arc<dyn AuditLog>, platform: Option<Platform> */ }
  impl CaPlugin { pub fn new(cfg: CaConfig) -> Self; pub fn with_backend(cfg: CaConfig, exec: Arc<dyn Executor>, audit: Arc<dyn AuditLog>, platform: Platform) -> Self; }
  impl Plugin for CaPlugin { fn name(&self) -> &str { "ca" } /* load registers ca.export, ca.status, ca.install, ca.uninstall */ }
  ```
  Command names, params, result shapes, descriptions, refusal text, and confirm prompts exactly as spec §D8 "Command surface" / "Policy gate" / "CLI: … confirmation" (the descriptions of `ca.install`/`ca.uninstall` state the gate; `ca.status` detail carries the obscura line).
- **Change:** `invoke` order per spec: parse → `audit.open()` (Err → `audit log <path> is not writable (<e>); refusing to change or export the CA until it is`) → gate (`host.frontend() != Frontend::Cli && !dry_run && !cfg.allow_agent_install` → record `refused`, `warn!`, return refusal) → `CaCert::load` → `Platform::detect`/fixed → scope → store op (via `DryRunExecutor` when `dry_run`) → `audit.record` (`ok`/`error`/`dry_run`) → `tracing` → `Value`. `ca.export` `out` refusal when canonical parent is the canonical CA dir or under it. `confirm_prompt` returns the spec's texts (with the obscura sentence) for install/uninstall, `None` for `dry_run` or no cert.
- **Test** (`CaPlugin::with_backend(cfg, scripted, MemoryAuditLog, Platform::MacOs)`, `CommandHost::new(stubs).with_frontend(...)`, registry built via `Registry::add_plugin`):
  - `commands.rs::export_pem_default` (CA-AC1): result fields `format == "pem"`, `certificate == Value::Str(<fixture text>)`, `fingerprint_sha256 == FIXTURE_FP256`, `fingerprint_sha1 == FIXTURE_FP1`, `dir`, `path == "/ca/ca.crt"`, `written_to == Value::Null`; one audit record `command == "ca.export"`, `outcome == "ok"`.
  - `commands.rs::export_der_and_out` (CA-AC2): `format: "der"` → `Value::Bytes` starting `[0x30, 0x82]` equal to the independently decoded block; `out` (real temp path, `with_real_fs`) → file bytes equal, `written_to == path`; `pem` + `out` → text identical to `ca.crt`.
  - `commands.rs::export_refusals` (CA-AC3): `format: "p12"` → `Err` containing `format must be pem or der`; `out` under the CA dir → `refusing to write into the CA directory`; no `ca.crt` → `Err` containing the path and `start the proxy once`.
  - `commands.rs::status_without_ca` (CA-AC4): `exists == false`, fingerprints `Null`, `stores == {}`, `detail` contains the path **and** `--ca-cert`; no audit record.
  - `commands.rs::gate_refuses_mcp_and_audits` (CA-AC19 command level): flag off, `Frontend::Mcp` → `Err` whose text is exactly the spec's refusal text for `ca.install`; `runs() == []`; audit `[{command:"ca.install", frontend:"mcp", outcome:"refused", fingerprint_sha256: Some(FP256), ..}]`; same for `ca.uninstall`.
  - `commands.rs::gate_allows_with_flag_and_cli` (CA-AC20/22): flag on + Mcp → `changed == true`, audit `outcome == "ok"`, `platform == Some("macos")`, `scope == Some("user")`; flag off + `Frontend::Cli` → `changed == true`, audit `frontend == "cli"`.
  - `commands.rs::dry_run_passes_gate` (CA-AC21): flag off, Mcp, `dry_run: true` → `Ok`, `dry_run == true`, `changed == true`, `commands` contains the `add-trusted-cert` line, `runs()` holds only the query, audit `outcome == "dry_run"`.
  - `commands.rs::key_never_touched` (CA-AC24): real temp dir (`with_real_fs`) with fixture `ca.crt` and (a) no `ca.key`, (b, Unix) `ca.key` mode `0o000`: all four commands `Ok`; no `runs()` arg, `stdins()` byte, `reads()` path, or audit `detail` contains `ca.key` or `PRIVATE KEY`; the CA dir's entry list is unchanged afterwards.
  - `commands.rs::tracing_fields` (CA-AC25): capturing subscriber; successful CLI install emits one `INFO` at target `aitm_ca` with `command="ca.install"`, `fingerprint_sha256=FP256`, `scope="user"`, `platform="macos"`, `frontend="cli"`, `changed=true`, and one `INFO` at `aitm_ca::audit`; a refusal emits `WARN` with `setting="ca.allow_agent_install"`.
  - `commands.rs::audit_fail_closed` (CA-AC28 half): `MemoryAuditLog::failing()`, flag on, Cli → `ca.install` `Err` containing `audit log`; `runs() == []`; `reads() == []`; `ca.status` still `Ok`.
  - `commands.rs::confirm_prompts`: `ca.install` `confirm_prompt` contains `FIXTURE_FP256`, `scope user`, `--ca-cert`; with `dry_run: true` → `None`; without `ca.crt` → `None`; `ca.status` → `None`.
  - `real_os.rs::{macos,linux}_round_trip` (CA-AC29; `#[ignore]`, `#[cfg(target_os = …)]`, returns early unless `AITM_REAL_OS_TESTS=1`): `CaPlugin::new` with a throwaway CA dir (fixture `ca.crt`) and a temp audit path, `Frontend::Cli`: install → status `installed == "present"` → uninstall → status `"absent"`; four audit lines written; macOS additionally runs `security add-trusted-cert` a second time directly and **prints** its exit code/output (C8); Debian asserts no `/etc/ssl/certs/aitmproxy-root-ca.pem` remains (C10). Run by hand in Task 30; never in the default suite.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(ca): ca.export/status/install/uninstall, Frontend gate, fail-closed audit`.
- **Done when:** eleven hermetic tests pass and `real_os.rs` compiles (ignored).

### Task 17: `aitm-cli` — `Frontend::Cli`, reserved `--yes`, `Confirmer`

- **Satisfies:** CA-AC22, CA-AC23 (frontend mechanics); spec §D8 "CLI: arguments, confirmation, output" (C16).
- **Depends on:** Task 7. **Independent:** yes — **P-A4**.
- **Files:** Modify `crates/aitm-cli/src/dispatch.rs`, `crates/aitm-cli/src/lib.rs` (re-exports), create `crates/aitm-cli/src/confirm.rs`; test `crates/aitm-cli/tests/cli.rs` (append).
- **Interfaces — Produces:**
  ```rust
  pub trait Confirmer: Send + Sync { fn confirm(&self, prompt: &str) -> anyhow::Result<bool>; }
  pub struct TtyConfirmer { /* interactive: bool */ }
  impl TtyConfirmer { pub fn from_stdin() -> Self; pub fn new(interactive: bool) -> Self; }
  impl Cli { pub fn with_confirmer(self, confirmer: Arc<dyn Confirmer>) -> Self; }  // default TtyConfirmer::from_stdin()
  ```
- **Change:** `dispatch`: strip a bare `--yes` token from the flag list before `parse_flags`; build the host `.with_frontend(Frontend::Cli)`; if `--yes` absent and `cmd.confirm_prompt(&args)` is `Some(p)` → `confirmer.confirm(&p)`: `Ok(false)` → `Err("aborted: <name> not run")`, `Err` propagates, `Ok(true)` → invoke. `TtyConfirmer`: interactive → write `<p> [y/N] ` to stderr, read a line, `true` only for `y`/`yes` (trimmed, case-insensitive); non-interactive → `Err("<name> needs confirmation but stdin is not a terminal; pass --yes to confirm non-interactively")`. `usage()` mentions `--yes` once.
- **Test** (a test command `demo.confirm` whose `confirm_prompt` returns `Some("Proceed?")` and whose `invoke` returns `Value::Str(host.frontend() label)`):
  - `cli.rs::frontend_is_cli`: `dispatch(["demo","confirm","--yes"])` → `Value::Str("cli")`.
  - `cli.rs::confirmer_gates_invoke`: scripted confirmer answering `false` → `Err` containing `aborted`, invoke count 0; answering `true` → `Ok`, prompt received exactly `"Proceed?"`; with `--yes` the confirmer is not called.
  - `cli.rs::non_interactive_needs_yes`: `TtyConfirmer::new(false)` → `Err` containing `--yes`.
  - `cli.rs::yes_is_a_noop_elsewhere`: a command without a prompt dispatched with `--yes` → `Ok`, and `--yes` is not reported as an unknown flag.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** four tests pass.

### Task 18: `aitm-mcp` — `Frontend::Mcp`

- **Satisfies:** CA-AC19 (frontend mechanics); spec §D8 "Policy gate" (C14).
- **Depends on:** Task 7. **Independent:** yes — **P-A4**.
- **Files:** Modify `crates/aitm-mcp/src/server.rs` (`call_tool`); test `crates/aitm-mcp/tests/mcp.rs` (append).
- **Change:** `.with_frontend(Frontend::Mcp)` on the host built in `call_tool`.
- **Test:** `mcp.rs::frontend_is_mcp`: a registered test command returning the frontend label → `tools/call` `structuredContent == "mcp"`.
  - [ ] Test → FAIL → implement → PASS → gate → commit.
- **Done when:** the test passes.

### Task 19: `aitm-browser` `obscura.rs` — discovery, probe, spawn command (hermetic)

- **Satisfies:** M2-AC6, M2-AC7, M2-AC16 (second half); spec §D3, §D4 argv/env.
- **Depends on:** Task 7. **Independent:** yes — **P-A4**.
- **Files:** Create `crates/aitm-browser/src/obscura.rs`; modify `crates/aitm-browser/src/lib.rs` (`pub mod obscura; pub use obscura::{ObscuraProcess, ProbeInfo}`), `crates/aitm-browser/Cargo.toml` (tokio `process`); create `crates/aitm-browser/tests/fixtures/fake-obscura-unpatched.sh` (prints upstream-like help without `--ca-cert`, exit 0) and `fake-obscura-patched.sh` (help contains `--ca-cert`; `--version` prints `obscura 0.2.5-aitm.test`; `serve` sleeps); test `crates/aitm-browser/tests/obscura_spawn.rs`.
- **Interfaces — Produces:**
  ```rust
  pub struct ProbeInfo { pub version: String }
  pub fn discover_binary(cfg: &ObscuraConfig, env_bin: Option<PathBuf>, exe_dir: Option<&Path>, path_lookup: &dyn Fn(&str) -> Option<PathBuf>) -> anyhow::Result<PathBuf>;
  pub async fn probe(binary: &Path) -> anyhow::Result<ProbeInfo>;   // runs `--help` (must contain "--ca-cert") then `--version`
  pub struct ObscuraProcess { /* Child, cdp_port, ready_file */ }
  impl ObscuraProcess {
      pub fn command(config: &BrowserConfig, binary: &Path, ca_cert: &Path, cdp_port: u16, ready_file: &Path) -> tokio::process::Command;
      // start/stop in Task 20
  }
  pub const SCRUBBED_ENV: [&str; 11] = ["SSL_CERT_FILE","SSL_CERT_DIR","OBSCURA_CA_CERT","OBSCURA_PROXY","OBSCURA_ALLOW_PRIVATE_NETWORK","HTTP_PROXY","HTTPS_PROXY","NO_PROXY","http_proxy","https_proxy","no_proxy"];
  ```
- **Change:** discovery order config → env → `exe_dir/obscura` → `path_lookup("obscura")`, first **existing** candidate is final; probe error text: `"<path> is not the aitmproxy obscura fork: its --help does not list --ca-cert; install the bundled binary or set browser.obscura.binary"`. `command`: `serve --host 127.0.0.1 --port <P> --proxy http://127.0.0.1:<proxy_addr.port()> --ca-cert <ca_cert> --allow-private-network --ready-file <ready_file>`, `env_remove` each `SCRUBBED_ENV`, `kill_on_drop(true)`, stdout/stderr piped.
- **Test:**
  - `obscura_spawn.rs::command_argv_and_env` (M2-AC7, M2-AC16): with the parent env setting all eleven vars, `command(...).as_std()` args equal the exact vector above (`P`/ports/paths substituted), and `.get_envs()` shows each scrubbed var as removed (`None` value); argv contains `<dir>/ca.crt` and neither `<dir>` alone nor `ca.key`.
  - `obscura_spawn.rs::probe_refuses_unpatched` (M2-AC6): `probe(fake-obscura-unpatched.sh)` → `Err` containing `--ca-cert` and the script path; a loopback listener on a chosen port saw no connection.
  - `obscura_spawn.rs::probe_accepts_patched`: `probe(fake-obscura-patched.sh)` → `Ok(ProbeInfo{version})` with `version` containing `0.2.5-aitm.test`.
  - `obscura_spawn.rs::discovery_order`: temp dirs: config path wins over env; env wins over exe_dir; exe_dir wins over PATH; a configured path that does not exist → `Err` containing it (not skipped).
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** four tests pass.

### Task 20: Driver split, `ObscuraDriver`, `launch()`, child lifecycle

- **Satisfies:** M2-AC8 (dispatch), M2-AC9 (driver half), M2-AC13 (obscura twin, run in Task 25); Review Focus #1, #5; spec §D4 lifecycle, §D5.
- **Depends on:** Task 19. **Independent:** no.
- **Files:** Modify `crates/aitm-browser/src/driver.rs` (extract `pub(crate) struct CdpSession` holding `Browser`, `Page`, `nav_timeout`, handler `JoinHandle`, with the six primitives; `ChromeDriver { session }` unchanged in behavior), `crates/aitm-browser/src/obscura.rs` (`start`, `stop`, `ObscuraDriver`), `crates/aitm-browser/src/lib.rs` (`pub async fn launch`); test `crates/aitm-browser/tests/obscura_lifecycle.rs`.
- **Interfaces — Produces** (spec §D5):
  ```rust
  impl ObscuraProcess { pub async fn start(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<(Self, String)>; pub async fn stop(self) -> anyhow::Result<()>; pub fn pid(&self) -> Option<u32>; }
  pub struct ObscuraDriver { /* CdpSession, ObscuraProcess */ }
  impl ObscuraDriver { pub async fn launch(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<Self>; pub async fn close(self) -> anyhow::Result<()>; pub fn pid(&self) -> Option<u32>; }
  impl BrowserDriver for ObscuraDriver { /* delegates to CdpSession */ }
  /// What `main` holds: a shareable driver plus the one owner that can close it.
  pub struct LaunchedBrowser { pub driver: Arc<dyn BrowserDriver>, /* closer */ }
  impl LaunchedBrowser { pub async fn close(self) -> anyhow::Result<()>; }   // Obscura: ObscuraDriver::close; Chrome: ChromeDriver::close
  pub async fn launch_owned(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<LaunchedBrowser>;  // by config.engine
  pub async fn launch(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<Arc<dyn BrowserDriver>>;  // = launch_owned(..)?.driver (tests, poc runner)
  ```
- **Change:** `start`: discover → probe (log version at `info`) → pick a free loopback port (bind-and-release) → spawn `command(...)` → log `tracing::info!(pid, port, "obscura started")` → wait for ready-file **or** TCP connect, polling every 50 ms, bounded by `start_timeout`; if the child exits first → `Err("obscura exited during startup with <status>: <last 50 stderr lines>")`; spawn `EACCES` → `Err` containing `permission denied` and `xattr -d com.apple.quarantine`. `ObscuraDriver::launch`: `start` → `Browser::connect(ws_url)` → handler task → `new_page("about:blank")`; **no** `Security.setIgnoreCertificateErrors`. `OBSCURA_CDP_TOKEN`: the Coder checks whether `serve` accepts the token in a form `Browser::connect` can present (URL query or header); if yes, set a per-launch random token; if not, leave it unset and log `info!("CDP endpoint is loopback-only and unauthenticated")`, and say which in the report (spec "Left to the builder"). `stop`: `browser.close()` over CDP, then on Unix `std::process::Command::new("kill").args(["-TERM", &pid])` (no `libc`/`nix`), poll `try_wait()` up to `stop_timeout`, then `Child::kill()` (SIGKILL); remove the ready-file. `headless == false` with Obscura → `warn!` and ignore. Dead-child detection: each primitive first checks `try_wait()`; `Some(status)` → `Err("embedded browser (obscura) exited with <status>")`.
- **Test:**
  - `obscura_lifecycle.rs::start_reports_early_exit` (RF#1, hermetic): a fake patched script whose `serve` prints `boom` to stderr and exits 7 → `start` `Err` containing `exited during startup`, `7`, and `boom`, within 2 s.
  - `obscura_lifecycle.rs::spawn_permission_error_carries_hint` (RF#5, hermetic, Unix): a fake binary without the exec bit → `Err` containing `xattr -d com.apple.quarantine`.
  - `obscura_lifecycle.rs::headless_false_is_ignored_for_obscura` (hermetic): `command(...)` with `headless: false` has no head flag and `tracing` captured a `WARN` mentioning `headless`.
  - `obscura_lifecycle.rs::launch_close_reaps_child` (M2-AC9 driver half, `[obscura]`): `ObscuraDriver::launch` with the real fork binary and a temp CA → `pid()` alive; `close()` → pid gone within `stop_timeout`; a second launch dropped (not closed) → pid gone within `stop_timeout`; `pgrep -f obscura.*--ready-file` finds nothing.
  - `obscura_lifecycle.rs::dead_child_errors_clearly` (`[obscura]`): launch, `kill -9 <pid>`, then `eval("1")` → `Err` containing `exited`.
  - [ ] Tests → FAIL → implement → PASS (hermetic in default; gated with `AITM_OBSCURA=1 AITM_OBSCURA_BIN=<Task 6 path>`) → gate → commit `feat(browser): ObscuraDriver over a managed obscura child; engine-selecting launch()`.
- **Done when:** three hermetic tests pass in the default suite; the two gated tests pass with the fork binary.

### Task 21: Wiring — `assemble`, `CaPlugin` registration, `env.rs`, `render.rs`, 22-tool pin, CA frontend integration tests

- **Satisfies:** M2-AC17, CA-AC19, AC20, AC21, AC22, AC23, AC27; spec §D7, §D9.
- **Depends on:** Tasks 8, 16, 17, 18. **Independent:** no.
- **Files:** Modify `crates/aitm/src/wire.rs`, `crates/aitm/src/lib.rs` (`pub mod env; pub mod render;`), `crates/aitm/Cargo.toml` (`aitm-ca`), create `crates/aitm/src/env.rs`, `crates/aitm/src/render.rs`; modify `crates/aitm/tests/frontends.rs` (`EXPECTED_TOOLS: [&str; 22]`, snapshot of the six `browser.*` schemas), create `crates/aitm/tests/ca_frontends.rs`, `crates/aitm/tests/wiring_m2.rs`.
- **Interfaces — Produces** (spec §D7):
  ```rust
  #[derive(Clone)] pub struct Features { pub mutate: bool, pub ca_plugin: Option<aitm_ca::CaPlugin> }   // Default: true, None; Debug derive dropped (CaPlugin has a manual Debug if needed)
  pub struct Assembled { pub proxy: Proxy, pub ca: Arc<CertAuthority> }
  pub fn assemble(cfg: &Config) -> anyhow::Result<Assembled>;
  pub fn assemble_with(cfg: &Config, features: &Features) -> anyhow::Result<Assembled>;
  pub fn build_proxy(cfg: &Config) -> anyhow::Result<Proxy>;                             // unchanged
  pub fn build_proxy_with(cfg: &Config, features: &Features) -> anyhow::Result<Proxy>;   // unchanged signature
  // env.rs
  pub fn apply(cfg: &mut Config, lookup: impl Fn(&str) -> Option<String>);  // AITM_CA_ALLOW_AGENT_INSTALL: 1/true/yes (ci) → true; anything else → false; unset → unchanged
  // render.rs
  pub fn render_cli_value(v: &Value) -> Vec<u8>;  // Str → s + "\n"; Bytes → raw; else pretty JSON (aitm_mcp::json::to_json) + "\n"
  ```
- **Change:** `assemble_with` registers `features.ca_plugin.clone().unwrap_or_else(|| CaPlugin::new(cfg.ca.clone()))` after `PocCommands`.
- **Test:**
  - `frontends.rs::ac7_exact_twenty_two_tools` (rename; M2-AC17): sorted names == 18 + `ca.export`, `ca.install`, `ca.status`, `ca.uninstall`; the six `browser.*` `inputSchema`s equal a checked-in JSON snapshot `tests/fixtures/browser-tool-schemas.json`, generated in this task from the registry (no M2 task touches `aitm-browser/src/commands.rs`, so it equals M1's by construction; the snapshot pins it against future drift).
  - `ca_frontends.rs::mcp_refused_then_allowed` (CA-AC19/20): `assemble_with(cfg, Features{ ca_plugin: Some(CaPlugin::with_backend(cfg.ca, scripted, memory_audit, Platform::MacOs)), ..})`; flag off → `isError == true`, text contains `ca.allow_agent_install` and `AITM_CA_ALLOW_AGENT_INSTALL`, zero `runs()`, audit `refused`/`mcp`; flag on → `isError == false`, `structuredContent.changed == true`, `runs()` == the CA-AC9 lines, audit `ok`.
  - `ca_frontends.rs::mcp_dry_run` (CA-AC21) and `ca_frontends.rs::cli_ungated_with_yes` (CA-AC22): as specified.
  - `ca_frontends.rs::cli_confirmation` (CA-AC23): scripted `Confirmer` receives a prompt containing `FP256`, `scope user`, `--ca-cert`; `false` → `aborted`, no mutating runs, no audit record; `true` → `Ok`; `--yes`/`--dry_run` skip it; `ca status --yes` → `Ok`.
  - `wiring_m2.rs::assemble_exposes_ca_and_status_sees_it` (CA-AC27): `assemble(&cfg)?.ca.cert_path()` exists; `Cli::dispatch(["ca","status"])` → `exists == true`; `env::apply` matrix (`1`/`true`/`YES` → `true`; `0` → `false`; unset → unchanged); `render_cli_value(&Value::Str("x"))== b"x\n"`, `Bytes` raw, `Object` pretty JSON parses back.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(aitm): assemble() exposes the CA; register ca.*; env bridge; CLI renderer; 22 tools`.
- **Done when:** all listed tests pass; `tests/wiring.rs` still green.

### Task 22: YAML config file module

- **Satisfies:** M2-AC18; Review Focus #3; spec §D10.
- **Depends on:** Task 7. **Independent:** yes — **P-A4**.
- **Files:** Create `crates/aitm/src/config_file.rs`; modify `crates/aitm/src/lib.rs` (`pub mod config_file;`), `crates/aitm/Cargo.toml` (`serde`, `serde_yaml` as regular deps); test `crates/aitm/tests/config_file.rs`.
- **Interfaces — Produces:**
  ```rust
  pub fn default_config_path() -> PathBuf;                       // <config_dir>/aitmproxy/config.yaml, same fallbacks as default_ca_dir()
  pub fn load(path: Option<&Path>) -> anyhow::Result<Config>;    // None → default path (absent ⇒ Config::default()); Some(p) absent ⇒ Err naming p
  pub fn parse(yaml: &str) -> anyhow::Result<Config>;            // serde mirror with #[serde(deny_unknown_fields)], every field Option, defaults applied per field
  ```
  Keys mirror the Rust names (`browser.engine: obscura|chrome`, `browser.obscura.binary`, `browser.obscura.start_timeout: "15s"` (humantime-free: integer seconds), `ca.allow_agent_install`, `ca.audit_log`, `ca.dir`, `listen`, `scope.entries: ["host:port"]`, `limits.*`, `mcp.transport: {stdio: {}} | {loopback_tcp: {port, token}}`, `poc.dir`, `ssl_insecure`, `max_flows`, `max_flow_bytes`).
- **Test:**
  - `config_file.rs::m2_knobs_load` (M2-AC18): the four-line YAML from the AC → `engine == Chrome`, `obscura.binary == Some("/x/obscura")`, `ca.allow_agent_install == true`, `ca.audit_log == "/x/audit.jsonl"`, and every other field `==` `Config::default()`'s (compare `Debug` strings of the remaining fields).
  - `config_file.rs::absent_default_is_default`: `load(None)` with `AITM_CONFIG`-free env and a default path redirected to a temp dir → equals `Config::default()`.
  - `config_file.rs::absent_explicit_is_error`: `load(Some("/nonexistent/c.yaml"))` → `Err` containing `/nonexistent/c.yaml`.
  - `config_file.rs::unknown_key_is_an_error` (RF#3): `browser:\n  enigne: chrome` → `Err` containing `enigne`.
  - `config_file.rs::two_line_file_is_valid`: `ssl_insecure: true` alone → `Ok` with only that field changed.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** five tests pass.

### Task 23: `main.rs` — config, env bridge, engine launch, signals, renderer

- **Satisfies:** M2-AC9 (binary half, tested in Task 26), M2-AC8 (operator toggle), M2-AC18 (`--config`), CA-AC27 (renderer in use); spec §D6, §D10.
- **Depends on:** Tasks 20, 21, 22. **Independent:** no.
- **Files:** Modify `crates/aitm/src/main.rs`, `crates/aitm/Cargo.toml` (tokio `signal`, `process`).
- **Change:** argv: if `argv[0] == "--config"` take `argv[1]` as the path (also `--config=<path>`) and strip both; else `AITM_CONFIG` env; `let mut cfg = config_file::load(path)?; env::apply(&mut cfg, |k| std::env::var(k).ok());`. `let assembled = wire::assemble(&cfg)?;`. CLI one-shot: unchanged services; print via `render_cli_value` to stdout (`write_all`). Server: `let launched = match aitm_browser::launch_owned(&cfg.browser, assembled.ca.cert_path()).await { Ok(l) => Some(l), Err(e) => { warn!(engine = ?cfg.browser.engine, error = %e, "embedded browser unavailable; browser.* commands will error"); None } }`; the frontends get `launched.as_ref().map(|l| l.driver.clone())`. `select!` gains `_ = shutdown_signal()` (SIGINT via `tokio::signal::ctrl_c`, SIGTERM via `tokio::signal::unix::signal(SignalKind::terminate())`); after the `select!`, `if let Some(b) = launched { let _ = tokio::time::timeout(cfg.browser.obscura.stop_timeout + 1s, b.close()).await; }` then return. Log a stale ready-file if found at startup (`info`).
- **Test:** hermetic unit test in `main.rs` `mod tests` for the argv splitter: `["--config","/c.yaml","flow","list"]` → `(Some("/c.yaml"), ["flow","list"])`; `["--config=/c.yaml"]` → `(Some("/c.yaml"), [])`; `["flow","list"]` → `(None, ["flow","list"])`. The binary-level signal behavior is Task 26.
  - [ ] Test → FAIL → implement → `cargo run -- --config /nonexistent.yaml` prints an error naming the path (manual check in the report) → gate → commit `feat(aitm): config file, env bridge, engine launch, signal-driven shutdown, CLI renderer`.
- **Done when:** the unit test passes, the gate is green, and `cargo run -- ca status` prints pretty JSON with `exists: true` (quoted in the report).

### Task 24: HTTPS fixture + obscura MITM, sub-resource, no-bypass and SSRF tests

- **Satisfies:** M2-AC10, M2-AC11, M2-AC12, M2-AC15; decides Task 27.
- **Depends on:** Tasks 6, 20, 21. **Independent:** yes — **P-A5**.
- **Files:** Create `crates/aitm/tests/support/https_fixture.rs` (rcgen self-signed leaf for `localhost`, tokio-rustls acceptor, hyper handler: `/` HTML with `<img src="https://localhost:<p>/img.png">`, inline `fetch("https://localhost:<p>/api")`, XHR to `/xhr`, optional raw-listener references; `/img.png` a 1×1 PNG; `/api`, `/xhr` JSON), `crates/aitm/tests/obscura_mitm.rs`; `crates/aitm/Cargo.toml` dev-deps `rcgen`, `tokio-rustls`, `rustls` (all in the tree).
- **Change:** tests only. Setup per test: `cfg.ssl_insecure = true`, `cfg.browser.proxy_addr = free_addr()`, `cfg.scope.entries = ["localhost:<p>"]`, `cfg.browser.obscura.binary = AITM_OBSCURA_BIN`; `assemble` → `run_browser` → `aitm_browser::launch` → drive via `BrowserDriver` directly; poll the store up to 10 s.
- **Test** (all `[obscura]`, inert without `AITM_OBSCURA=1`):
  - `obscura_mitm.rs::https_navigation_is_decrypted` (M2-AC10): a stored `HttpFlow` with `request.scheme == "https"`, `method == "GET"`, `path == "/"`, `response.status == Some(200)`, body contains `aitm-fixture`; `final_url == "https://localhost:<p>/"`.
  - `obscura_mitm.rs::subresources_are_captured` (M2-AC11): flows for `/`, `/img.png`, `/api`, `/xhr` each with status 200 within 10 s. **If `/img.png` is absent, the report says so verbatim and Task 27 is triggered; the test stays red until it passes.**
  - `obscura_mitm.rs::no_bypass_path` (M2-AC12): raw loopback listener (not the proxy, not in scope) referenced by `<img>` and `fetch` → `accepted == 0` after 5 s; no flow for `/x.png` or `/y` has a response; a captured `tracing` subscriber saw `PrivateAddressBlocked` for `127.0.0.1:<raw>`.
  - `obscura_mitm.rs::ssrf_posture_preserved` (M2-AC15): `browser.navigate` (through the registered command, `block_on` in `spawn_blocking`) to an unscoped `http://127.0.0.1:<port>/` → `Err` containing `PrivateAddressBlocked`/the host, driver never called (a counting wrapper driver); after `scope.add` of `127.0.0.1:<port>` → `Ok` and a captured flow.
  - [ ] Tests → run gated → record which pass; fix aitmproxy-side failures here; sub-resource gaps go to Task 27 → gate → commit.
- **Done when:** AC10, AC12, AC15 pass; AC11 passes (possibly after Task 27).

### Task 25: Engine-parametrized browser tests and the reflected-XSS e2e over obscura

- **Satisfies:** M2-AC8 (chrome + obscura halves), M2-AC13, M2-AC14.
- **Depends on:** Tasks 6, 20. **Independent:** yes — **P-A5**.
- **Files:** Modify `crates/aitm-browser/tests/browser.rs`, `crates/aitm-browser/tests/ssrf.rs` (the `navigate_permitted_after_scope_reaches_driver` test), `crates/aitm/tests/e2e_reflected_xss.rs`; create `crates/aitm-browser/tests/support/engines.rs` (`pub fn engines() -> Vec<BrowserEngine>`: `Chrome` if `AITM_CHROME`, `Obscura` if `AITM_OBSCURA`; `pub fn config_for(engine, proxy) -> BrowserConfig` setting `obscura.binary` from `AITM_OBSCURA_BIN`).
- **Change:** each test loops over `engines()` and launches via `aitm_browser::launch(&cfg, ca_cert)`; for Chrome `ca_cert` is unused (pass the temp CA path anyway). Add a click/type fixture page (data URL or the Task 24 fixture) for M2-AC13.
- **Test:**
  - `browser.rs::primitives` (M2-AC13): per engine — PNG magic, `eval("1+1") == Int(2)`, `get_dom` contains `<html`; `click("#btn")` then `eval("window.__clicked") == Bool(true)`; `type_text("#in","abc")` then `eval("document.querySelector('#in').value") == Str("abc")`.
  - `browser.rs::navigate_routes_through_proxy` and `ssrf.rs::navigate_permitted_after_scope_reaches_driver`: per engine, unchanged assertions.
  - `e2e_reflected_xss.rs::reflected_xss_over_mcp` (M2-AC14): per engine — `passed == true` vulnerable with the three artifacts, `false` patched.
  - [ ] Parametrize → run `AITM_CHROME=1 cargo test …` and `AITM_OBSCURA=1 AITM_OBSCURA_BIN=… cargo test …` → both PASS → default `cargo test` still 0 ignored → gate → commit.
- **Done when:** both engine runs are green and quoted in the report.

### Task 26: `aitm` shutdown test (signals reap the child)

- **Satisfies:** M2-AC9 (binary half).
- **Depends on:** Tasks 6, 23. **Independent:** yes — **P-A5**.
- **Files:** Create `crates/aitm/tests/shutdown.rs`.
- **Test** (`[obscura]`): spawn `env!("CARGO_BIN_EXE_aitm")` with `--config <temp yaml>` (temp CA dir, `browser.obscura.binary`, free ports, `mcp.transport: loopback_tcp` so stdio is not consumed) and `RUST_LOG=info`; wait for the `obscura started` log line and parse its `pid=<n>` field (Task 20 logs it at `info`; stderr piped); send `SIGTERM` (`kill -TERM`), assert `aitm` exits within 10 s and `kill -0 <n>` fails within `stop_timeout + 1 s`; repeat with `SIGINT`. No `obscura` process with the temp ready-file path remains.
  - [ ] Test → run gated → PASS → gate → commit.
- **Done when:** both signal cases pass.

### Task 27 (conditional): `obscura-render` image fetches go through the proxy

- **Satisfies:** M2-AC11 when Task 24 shows `/img.png` missing; spec §D2 "Image loader".
- **Depends on:** Task 24's result. **Independent:** no (Stream F).
- **Files (fork):** `crates/obscura-render/src/paint.rs` (`image_agent()` `:8161`, the prefetch comment `:336`) and whichever module hands images to layout.
- **Change:** route image loads through the browser's proxied, root-configured client (`ObscuraHttpClient`) instead of the static `ureq` agent, or disable the direct `ureq` path when a proxy is configured — whichever the code structure allows with the smaller diff; the builder reports which.
- **Test:** fork unit test `render_image_fetch_uses_configured_client` (the image fetch hits a proxied fixture, not a direct listener) + re-run Task 24's `subresources_are_captured` → PASS. Rebuild the binary, retag `aitm-v2`, update `AITM_OBSCURA_BIN`.
  - [ ] Test → FAIL → implement → PASS → fork gate → commit → retag → re-run Task 24.
- **Done when:** M2-AC11 is green against the rebuilt binary (or Task 24 proved it green already and this task is marked **not needed** in the Review log).

### Task 28: `scripts/package.sh`

- **Satisfies:** M2-AC19 [manual].
- **Depends on:** Tasks 6, 23. **Independent:** yes — **P-A6**.
- **Files:** Create `scripts/package.sh`, `scripts/README.md` (one paragraph: what the tarball contains, that `obscura` next to `aitm` is discovered automatically).
- **Change:** `set -euo pipefail`; detect host target triple (`rustc -vV | sed -n 's/host: //p'`); `cargo build --release -p aitm`; `gh release download aitm-v<N> --repo mrbrutti/obscura --pattern "obscura-<target>.tar.gz" --pattern SHA256SUMS`; verify with `shasum -a 256 -c` (filtered to the one asset); extract; `xattr -d com.apple.quarantine` on macOS (ignore failure); `tar -czf dist/aitm-<aitm version>-<target>.tar.gz aitm obscura`. `OBSCURA_TAG` env overrides the tag (default `aitm-v1`).
- **Test:** `bash -n scripts/package.sh`; `shellcheck scripts/package.sh` if installed; run it; `tar -tzf dist/*.tar.gz` lists exactly `aitm` and `obscura`; extract to a temp dir, `PATH=/usr/bin:/bin ./aitm --config <temp yaml with mcp loopback>` logs `engine=obscura` and the probed version, then is killed. Output quoted in the report.
  - [ ] Write → run → quote → commit `build: scripts/package.sh bundles aitm with the obscura fork binary`.
- **Done when:** the tarball is produced and the extracted `aitm` starts obscura from the sibling binary.

### Task 29: Upstream PR and two issues

- **Satisfies:** M2-AC21 [manual].
- **Depends on:** Tasks 24, 25 (MITM proven against the fork build). **Independent:** yes — **P-A6**.
- **Change (Terminal panel, `gh`):** open `h4ckf0r0day/obscura` PR from `mrbrutti:aitm/ca-cert` titled `--ca-cert: add private root CAs without SSL_CERT_FILE; make the stealth client add rather than replace` (body: the flag contract from spec §D2, the three client sites, tests; omits the `aitm-release.yml` workflow and any Task 27 render change unless it is generic — rebase a `upstream/ca-cert` branch without those commits if needed); file issue 1 `SSL_CERT_FILE / SSL_CERT_DIR are honored but undocumented` and issue 2 `SSL_CERT_DIR containing a private key panics with InvalidCertificate(BadEncoding)` with the spike's reproduction.
- **Test:** `gh pr view --json url` and `gh issue view` ×2 return URLs; recorded in **Shipped**.
  - [ ] Open PR + issues → record URLs.
- **Done when:** three URLs are in the Shipped section.

### Task 30: M2 exit gate — whole branch, memory report, platform-spec amendments

- **Satisfies:** M2-AC20, M2-AC22; spec §D12.
- **Depends on:** all. **Independent:** no (last).
- **Files:** Modify `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md` (the §D12 amendments: browser section, crate table, config/host/command additions, Safety CA bullet, roadmap Rhai → M3, AC7 = 22) — **main session**, not a Coder; this plan's **Shipped** section.
- **Test:** Tester runs the full gate on the whole branch (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` → 0 failed, 0 ignored except `real_os`), then `AITM_CHROME=1 cargo test` and `AITM_OBSCURA=1 AITM_OBSCURA_BIN=… cargo test` → green; records peak RSS of the obscura child vs Chrome during `e2e_reflected_xss` (`/usr/bin/time -l` on macOS or `ps -o rss` sampling; both numbers in Shipped — M2-AC20); the fork gate on `aitm/ca-cert`; the AC coverage table (every M2-AC/CA-AC → test name → result).
  - [ ] Whole-branch Tester + panel → fixes → Shipped section filled → platform spec amended → integrate.
- **Done when:** every AC is green or accepted in the Review log; Shipped is filled.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

- Fixture fingerprints (Task 9): `<FP256> = ________`, `<FP1> = ________`.
- Fork binary: tag `aitm-vN`, local path, SHA-256.
- Upstream PR / issues (Task 29): ________.
- Memory report (Task 30): obscura peak RSS ________ MB vs Chrome ________ MB during `e2e_reflected_xss`.
