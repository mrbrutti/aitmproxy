# macOS NE core prerequisites — rendezvous writer + scope-spec emitter plan

**Status:** Approved 2026-10-30 (self-approved per Matt's autonomous mandate; C1–C7 confirmed). Execute Task 1 then Task 2.
**Spec:** `docs/superpowers/specs/2026-10-30-macos-ne-core-prereqs-design.md`
**Branch / worktree:** `claude/nervous-feynman-6d408a` (this worktree)

## Overview

Two small, test-driven tasks adding two disjoint new files under
`crates/aitm/src/macos_capture/`. Task 1 is the rendezvous writer
(`rendezvous.rs` + a `CaptureListener::publish_rendezvous` wrapper in
`listener.rs`). Task 2 is the scope-spec emitter (`scope_spec.rs`). The two
production files are disjoint, but **both tasks edit `mod.rs`** (different lines:
one adds `pub mod rendezvous;`, the other `pub mod scope_spec;`), so they are
**not independent** — run Task 1, then Task 2. No `main.rs`/feeder wiring;
`adapter.rs` is untouched (its `pub const CAPTURE_INTERFACE` is reused). No new
dependencies. All tests are pure (no UDS/port bind) and run under `cargo test`
in the sandbox; the full gate runs via the Terminal panel.

## Tasks

### Task 1: Rendezvous writer (`rendezvous.rs` + listener wrapper)

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC6, AC7.
- **Depends on:** none (run before Task 2 only because both edit `mod.rs`).
- **Files:**
  - `crates/aitm/src/macos_capture/rendezvous.rs` (create — module + its
    `#[cfg(test)] mod tests`).
  - `crates/aitm/src/macos_capture/mod.rs` (modify — add `pub mod rendezvous;`).
  - `crates/aitm/src/macos_capture/listener.rs` (modify — add
    `impl CaptureListener { pub fn publish_rendezvous }`; change `const CONTROL_SOCK`
    to `pub(crate) const CONTROL_SOCK`).
- **Change:**
  - `pub const RENDEZVOUS_PATH: &str = "/private/tmp/aitmproxy-capture.rendezvous";`
  - `const SUN_PATH_MAX: usize = 104;` (commented: macOS `sockaddr_un.sun_path`).
  - `pub struct RendezvousFile { path: std::path::PathBuf }` with
    `impl Drop` doing best-effort `fs::remove_file(&self.path)`.
  - `impl RendezvousFile`:
    - `pub fn publish(socket_dir: &std::path::Path, rendezvous_path: impl Into<std::path::PathBuf>) -> std::io::Result<RendezvousFile>`
      — canonicalize `socket_dir`; if
      `abs.as_os_str().len() + 1 + super::listener::CONTROL_SOCK.len() >= SUN_PATH_MAX`
      return `io::Error::new(io::ErrorKind::InvalidInput, …)`; body
      `format!("{}\n", abs.display())`; `let _ = fs::remove_file(&rendezvous_path);`
      then `OpenOptions::new().write(true).create_new(true).mode(0o600).open(&rendezvous_path)?`
      (needs `use std::os::unix::fs::OpenOptionsExt`); `write_all(body.as_bytes())`;
      return the guard.
    - `pub fn path(&self) -> &std::path::Path`.
  - In `listener.rs`, next to `dir()`:
    `pub fn publish_rendezvous(&self) -> std::io::Result<rendezvous::RendezvousFile>`
    delegating to
    `rendezvous::RendezvousFile::publish(self.dir(), rendezvous::RENDEZVOUS_PATH)`
    (add `use crate::macos_capture::rendezvous;` or a path-qualified call), and
    change `const CONTROL_SOCK: &str = "control.sock";` to
    `pub(crate) const CONTROL_SOCK: &str = "control.sock";`.
- **Test** (in `rendezvous.rs`, pure — scratch dirs via
  `std::env::temp_dir().join(format!("aitm-rendezvous-{…}", …))`, unique suffix;
  `use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink}`):
  - `rendezvous_path_matches_swift_constant` — asserts
    `RENDEZVOUS_PATH == "/private/tmp/aitmproxy-capture.rendezvous"` (**AC1**).
  - `publish_writes_absolute_mode_0600_file` — create scratch dir, chmod `0o700`;
    `publish(&dir, &rv)`; read `rv`: assert the trimmed content equals
    `fs::canonicalize(&dir).unwrap().to_string_lossy()`, the raw content ends with
    `"\n"`, `metadata.len()` is in `1..=1024`, and `metadata.permissions().mode() & 0o777 == 0o600`
    (**AC2**).
  - `published_file_passes_swift_acceptance_mirror` — with the same scratch
    dir/file, a local mirror `fn is_acceptable_file(md) -> bool` (regular file:
    `mode & 0o170000 == 0o100000`; no group/other **write**:
    `mode & 0o022 == 0`; `size` in `1..=1024` — citing FlowHandoff.swift:627-631),
    a mirror `fn is_acceptable_directory(md, file_uid) -> bool` (is dir
    `mode & 0o170000 == 0o040000`; no group/other access `mode & 0o077 == 0`;
    `md.uid() == file_uid` — citing :635-639), and a mirror `fn path_fits(dir) -> bool`
    (`dir.starts_with('/')`, no NUL byte,
    `dir.len() + 1 + 12 < 104` — citing :610-614) all return `true` for the
    published file against its `lstat`'d (via `fs::symlink_metadata`) 0700 dir
    (**AC3**).
  - `too_long_dir_path_is_rejected` — build a nested scratch dir whose canonical
    path length makes `abs.len() + 1 + 12 >= 104` (create enough nested
    components under `temp_dir()`), `publish` it, assert
    `err.kind() == io::ErrorKind::InvalidInput` (**AC4**).
  - `publish_replaces_stale_file` — write `rv` with stale bytes
    (`b"/private/tmp/some-old-dir\n"`), `publish(&dir, &rv)`, assert the content
    now trims to `fs::canonicalize(&dir)` (not the stale text) (**AC5**).
  - `publish_does_not_write_through_a_symlink` — create a victim file with known
    content `b"VICTIM"`, `symlink(&victim, &rv)`, `publish(&dir, &rv)`; assert the
    victim still reads `b"VICTIM"`, and `fs::symlink_metadata(&rv)` reports a
    **regular file** (`!file_type().is_symlink()`) whose content trims to
    `fs::canonicalize(&dir)` (**AC5**).
  - `drop_removes_the_file` — in an inner scope `{ let g = publish(&dir, &rv)?; assert!(rv.exists()); }`,
    then assert `!rv.exists()` after the guard drops (**AC6**).
  - **AC7** is satisfied by `publish_rendezvous` compiling and by the gate; add a
    doc/comment in the test module noting it is exercised live at NE plan Task 18
    (no direct unit test — it writes the real `/private/tmp` path and needs a
    bound listener).
- **Done when:** every test above passes and the full gate
  (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`)
  passes.

### Task 2: Scope-spec emitter (`scope_spec.rs`)

- **Satisfies:** AC8, AC9, AC10, AC11, AC12.
- **Depends on:** Task 1 only for the shared `mod.rs` edit (sequential, **not**
  independent). No code dependency on Task 1.
- **Files:**
  - `crates/aitm/src/macos_capture/scope_spec.rs` (create — module + its
    `#[cfg(test)] mod tests`).
  - `crates/aitm/src/macos_capture/mod.rs` (modify — add `pub mod scope_spec;`).
- **Change:**
  - `pub fn provider_scope_spec(l7: &[aitm_core::ScopeEntry], l4: &[aitm_proto_l4::types::L4ScopeEntry]) -> crate::macos_capture::listener::ScopeSpec`
    implementing the token rules from the spec's Design §Piece 2:
    - L7: trim+lowercase `host`; `*.suffix` → emit `suffix` then `*.suffix`
      (skip if suffix empty); else
      `aitm_core::authority::Authority::parse_with_default(raw, 0)` → on `Ok`
      emit `a.host` when `a.port == 0` else `a.to_string()`; on `Err` skip.
    - L4: keep only `capability == L4Capability::Capture && interface == crate::macos_capture::adapter::CAPTURE_INTERFACE && direction == L4Direction::Outbound`;
      require host-prefix CIDR (`V4`/32 or `V6`/128, else skip); any-port
      (`lo==0 && hi==65535`) → bare `addr.to_string()`; single-port (`lo==hi`) →
      `ip:port` with IPv6 bracketed (`[ip]:port`); partial range → skip.
    - Collect tokens L7-then-L4 in input order, de-duplicate preserving first
      appearance, join with `" "`, wrap in `ScopeSpec { spec }`.
  - Private helpers (builder's discretion): e.g. `l7_tokens`, `l4_tokens`, a
    `bracket_ip(addr, port)` formatter.
- **Test** (in `scope_spec.rs`, pure):
  - `emits_byte_exact_spec_for_representative_scopes` — build the pinned fixture
    (spec §"Pinned scope fixture"): L7 `["Example.com", "*.api.example.com", "10.0.0.5:8080", "[2001:db8::1]:443"]`;
    L4 the eight entries listed there. Assert
    `provider_scope_spec(&l7, &l4).spec == "example.com api.example.com *.api.example.com 10.0.0.5:8080 [2001:db8::1]:443 198.51.100.7 203.0.113.9:53 2001:db8::2"`
    (**AC8, AC9, AC11, AC12**).
  - `swift_scope_matcher_mirror_claims_and_rejects` — a local faithful mirror of
    `ScopeMatcher` (`parse` FlowHandoff.swift:543-575 + `matches` :520-535,
    cited in comments; IP tokens/flows compared as `std::net::IpAddr`), built
    from the emitted `spec`, asserts each pinned case:
    - `true`: `(Some("example.com"),"1.1.1.1",443)`,
      `(Some("www.api.example.com"),"1.1.1.1",443)`,
      `(Some("api.example.com"),"1.1.1.1",443)`,
      `(None,"198.51.100.7",9999)`, `(None,"203.0.113.9",53)`,
      `(None,"2001:db8::2",12345)`, `(None,"10.0.0.5",8080)`.
    - `false`: `(Some("evil.com"),"9.9.9.9",1)`,
      `(Some("api.example.com.evil"),"1.1.1.1",443)`,
      `(None,"203.0.113.9",54)`, `(None,"10.0.0.5",9090)`,
      `(None,"192.0.2.1",1500)`, `(None,"10.0.0.1",1)`,
      `(None,"198.51.100.50",1)`
    (**AC9, AC10, AC11, AC12**).
  - (Optional, builder's discretion) a focused `skips_unrepresentable_l4_entries`
    asserting the AC8 string contains none of `192.0.2.1`, `10.0.0.`,
    `198.51.100.5` — a direct restatement of the skip rule (**AC11**).
- **Done when:** every test above passes and the full gate passes.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
