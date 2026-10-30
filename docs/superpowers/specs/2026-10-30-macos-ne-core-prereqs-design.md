# macOS NE core prerequisites — rendezvous writer + scope-spec emitter design

**Status:** Approved 2026-10-30 (self-approved per Matt's autonomous mandate; C1–C7 confirmed). **Amended 2026-10-30** after the Stage-6 security FAIL: §Piece 2 L7 rule now skips IP-valued entries (finding 2) and validates host labels against the provider's `isValidHostname` before emitting (finding 1); pinned fixture + AC8/AC10 updated; AC12 strengthened (IPv6 single-port); AC13/AC14 added. See the plan's Review log.
**Research inputs:** `docs/research/10-macos-network-extension.md`,
`docs/superpowers/specs/2026-10-29-aitmproxy-macos-network-extension-design.md`
(NE-AC5/6/7), and that plan's Review log (Task 11 deferred item: "core-side
rendezvous writer + scope-spec emitter not exercised here — core-side
follow-ups").

## Intent

The macOS Network Extension provider (Swift) is the **client** of the core's
capture handoff; the core (`aitm`) is the listener
(`crates/aitm/src/macos_capture/listener.rs`). Before the Task-9/18 live feeder
can prove a real in-scope flow end to end (NE-AC17), the core needs two small
pieces the NE milestone deferred: (1) a **rendezvous writer** that publishes the
absolute path of the core's 0700 socket directory to the well-known file the
provider reads, and (2) a **scope-spec emitter** that renders the core's two
authorization scopes (L7 host scope and L4 IP scope) into the single
`ScopeSpec` string the provider's `ScopeMatcher` grammar understands. This spec
covers **only** those two pure building blocks. It does not build the feeder,
the control loop, or any `main.rs` wiring — those are owned by another session
(NE plan Task 9/18) and call these blocks.

## Goals

- A `RendezvousFile::publish` that writes the provider-contract rendezvous file
  (byte-exact path, canonical absolute socket-dir content, mode 0600, RAII
  removal) and a thin `CaptureListener::publish_rendezvous()` wrapper.
- A `provider_scope_spec(l7, l4)` that renders the two core scopes into one
  `ScopeSpec` string the provider's `ScopeMatcher` accepts, choosing
  **under-inclusive over over-inclusive** whenever the grammar cannot represent
  a scope entry exactly.
- Every behaviour proven by **pure** unit tests (no UDS bind, no port bind), so
  `cargo test` runs them in the Bash sandbox. The full gate runs via the
  Terminal panel.
- A faithful Rust mirror of the Swift provider's acceptance checks
  (`isAcceptableFile` / `isAcceptableDirectory` / path checks) and of its
  `ScopeMatcher` (parse + match), each citing the Swift source lines, so the two
  halves are proven to agree without a Mac.

## Non-goals

- No live feeder, control loop, `Hello`/`FlowOpen` session handling, or
  `CaptureListener` accept logic (those exist or are owned elsewhere).
- No wiring into `main.rs`, no call site that actually publishes to the real
  `/private/tmp` path or binds the real sockets (that is Task 18's live run).
- No change to `adapter.rs` — its `pub const CAPTURE_INTERFACE` is reused as-is.
- No change to the wire format, the `ScopeSpec` struct, or the provider.
- No re-validation of the socket directory's permissions/ownership in the writer
  (`CaptureListener::bind` already locks the dir to 0700; the provider
  independently re-validates). The writer trusts the dir it is handed.

## Anti-goals

- **Over-inclusive scope.** A spec that makes the provider claim a flow the core
  guard then refuses breaks the user's connection (the provider commits to MITM,
  the core drops it). Emitting a widened token when the grammar cannot represent
  a scope entry exactly is a failure even if every test "passes". When in doubt,
  **skip** the token (the flow then goes direct/uncaptured but works).
- **Writing through a planted symlink or stale file.** Publishing must never
  follow a pre-existing symlink at the rendezvous path to clobber its target, and
  must never leave another process's stale content in place.
- **Tests that need a Mac, a socket bind, or the real `/private/tmp` file.**

## Constraints

- **Platform:** the rendezvous writer is Unix-only (mode bits, `sun_path`); it
  lives in `macos_capture`, which is already a Unix/macOS-oriented module. Tests
  use `std::os::unix::fs` (`PermissionsExt`, `MetadataExt`, `symlink`).
- **No new dependencies.** Tests use `std::env::temp_dir()` with a unique suffix
  (the crate's existing convention — see `operator_token.rs`, `tui.rs`) for
  scratch dirs; no `tempfile`, no `libc`.
- **`sun_path` budget:** macOS `sockaddr_un.sun_path` is **104** bytes. The dir
  path plus `/` plus the longest socket filename (`control.sock`, 12 bytes) must
  fit: `abs.len() + 1 + 12 < 104`. This mirrors `FlowHandoff.swift` lines
  611-614 (`longestSocket = controlSocketName.utf8.count`).
- **Byte-exact provider contract** (`FlowHandoff.swift` lines 36-74, 586-640):
  the path, file shape, and content format are fixed by the Swift side and may
  not drift.
- **Security:** deny-by-default is owned by the core guard below the ingress; the
  provider spec is a coarse pre-filter the core re-checks (`dispatch_tcp` →
  `ScopeRateGuard::in_scope`; `udp_admits`/`dispatch_udp` → `L4Guard::check`).

## Design

### Piece 1 — Rendezvous writer

New module **`crates/aitm/src/macos_capture/rendezvous.rs`**, declared with
`pub mod rendezvous;` in `crates/aitm/src/macos_capture/mod.rs`.

Public surface:

```rust
/// Byte-exact with FlowHandoff.swift `HandoffConfig.rendezvousPath` (line 54).
pub const RENDEZVOUS_PATH: &str = "/private/tmp/aitmproxy-capture.rendezvous";

/// RAII guard: best-effort `fs::remove_file(self.path)` on Drop.
pub struct RendezvousFile { /* path: PathBuf (private) */ }

impl RendezvousFile {
    /// Publish `socket_dir` to `rendezvous_path` and return the removal guard.
    pub fn publish(
        socket_dir: &std::path::Path,
        rendezvous_path: impl Into<std::path::PathBuf>,
    ) -> std::io::Result<RendezvousFile>;

    /// The rendezvous file path this guard will remove.
    pub fn path(&self) -> &std::path::Path;
}
```

`publish` behaviour, in order:

1. `fs::canonicalize(socket_dir)` → an absolute realpath `abs`. Any error
   (e.g. the dir does not exist) propagates unchanged.
2. **`sun_path` length check:** if `abs.as_os_str().len() + 1 + CONTROL_SOCK.len() >= SUN_PATH_MAX`
   return `io::Error::new(io::ErrorKind::InvalidInput, …)`.
   `SUN_PATH_MAX = 104` (a module `const` with a comment citing macOS
   `sockaddr_un`). `CONTROL_SOCK` is the socket filename — see the shared-const
   decision below.
3. Compute the body `format!("{}\n", abs.display())`.
4. **Unlink-first, then create-new:** `let _ = fs::remove_file(&rendezvous_path);`
   then open with
   `OpenOptions::new().write(true).create_new(true).mode(0o600)`. `create_new`
   makes the open fail `AlreadyExists` on any entry (regular file **or**
   symlink) that reappears between the unlink and the create, so publishing never
   follows a planted symlink nor writes through a stale file. Write the body.
5. Return `RendezvousFile { path: rendezvous_path }`.

`Drop` does `let _ = fs::remove_file(&self.path)` (best-effort; a double-remove
or an already-gone file is ignored).

**Shared-const decision (Architect's call):** make `CONTROL_SOCK` in
`listener.rs` `pub(crate)` (a one-word change) and have `rendezvous.rs` use
`super::listener::CONTROL_SOCK` for the length check, so the socket filename has
a single source of truth that matches the Swift `longestSocket`. (The rejected
alternative — hardcoding `"control.sock".len()` with a comment — duplicates the
name.) `DATA_SOCK` (`"data.sock"`, 8 bytes) is shorter, so `control.sock` is the
binding constraint, exactly as the Swift side assumes.

**Listener wrapper**, added in `crates/aitm/src/macos_capture/listener.rs` next
to `dir()`:

```rust
impl CaptureListener {
    /// Publish this listener's socket dir to the well-known rendezvous path.
    pub fn publish_rendezvous(&self) -> std::io::Result<rendezvous::RendezvousFile> {
        rendezvous::RendezvousFile::publish(self.dir(), rendezvous::RENDEZVOUS_PATH)
    }
}
```

This wrapper is a one-line delegation. It is **not** unit-tested directly (it
writes to the real `/private/tmp` constant and presupposes a bound listener,
which needs a UDS bind — EPERM in the sandbox); its correctness rests on the
pure `publish` tests plus the compiler, and its live exercise is NE plan
Task 18. (Architect's call: place the wrapper in `listener.rs` as the task
suggested, not as an inherent impl in `rendezvous.rs`.)

### Piece 2 — Scope-spec emitter

New module **`crates/aitm/src/macos_capture/scope_spec.rs`**, declared with
`pub mod scope_spec;` in `mod.rs`.

Public surface:

```rust
pub fn provider_scope_spec(
    l7: &[aitm_core::ScopeEntry],
    l4: &[aitm_proto_l4::types::L4ScopeEntry],
) -> crate::macos_capture::listener::ScopeSpec;
```

It builds a list of grammar tokens, de-duplicates them **preserving first
appearance**, joins them with a single ASCII space, and returns
`ScopeSpec { spec }`.

**Ordering/dedup rule (so output is deterministic and byte-assertable):** emit L7
tokens in input order (each entry may contribute 1 or 2 tokens — see the `*.`
rule, apex before wildcard), then L4 tokens in input order; drop any token equal
to one already emitted; join with `" "`; no leading/trailing space.

**L7 → tokens** (`aitm_core::ScopeEntry { host: String }`, config.rs:166; core
match semantics `Authority::matches_scope_entry`, authority.rs:83):

A host label is **emittable** only if it is a valid hostname by the provider's own
rule (`FlowHandoff.swift:577-583` `isValidHostname`): non-empty, ≤253 chars, no
leading `.`, no `..`, and every char in `[a-z0-9.\-_]`. This is the crux of the
two security findings below — the provider **splits the whole spec on `,`, `;`, and
whitespace _before_ parsing** (`FlowHandoff.swift:514-517`), so a token that
contains any of those (which `Authority` does **not** reject in a host —
authority.rs:70 blocks only `/ space \t \r \n \0`, **not `,`/`;`**) would fragment
into extra provider entries. So an un-emittable label is **skipped**, never emitted.

- Trim and lowercase the raw `host`.
- **Skip IP-valued entries.** If the host (bare, `host:port`, bracketed IPv6, or the
  `*.`-suffix below) parses as a `std::net::IpAddr`, **skip** it. Reason (security
  finding 2): the provider matches an IP token against the flow's **destination IP**,
  ignoring the hostname (`FlowHandoff.swift:526-527`), but the core L7 gate matches
  the **SNI/host string** (`ingress.rs:183-188` → `authority.rs:89-90`). A flow to
  that IP carrying a different SNI would be claimed by the provider and then refused
  by the core → broken connection (over-inclusive). No provider token can reproduce
  the core's "IP matched as a host string, only when it is the SNI" semantics, so IP
  targets belong in the **L4 scope** (which the provider and `L4Guard` both match by
  IP), not here.
- If it starts with `*.`: strip the prefix to `suffix`. If `suffix` is empty, parses
  as an `IpAddr`, or is not an emittable hostname, **skip**. Otherwise emit **both**
  `suffix` (the apex) **and** `*.suffix` (the wildcard). Rationale: the core's
  `*.suffix` matches the apex **and** subdomains (authority.rs:86 —
  `host == suffix || host.ends_with(".suffix")`), but the provider's `*.x` matches
  **subdomains only** (FlowHandoff.swift:531 — `host.hasSuffix("." + suffix)`), so
  the extra apex token makes the provider claim the apex too.
- Otherwise parse the raw string with
  `aitm_core::authority::Authority::parse_with_default(raw, 0)`:
  - `Err(_)` → **skip** (the core would not treat it as a plain host either).
  - `Ok(a)` whose `a.host` is **not** an emittable hostname → **skip** (security
    finding 1: this is what rejects a `,`/`;`/whitespace-bearing host before it can
    fragment the spec).
  - `Ok(a)` with `a.port == 0` → emit `a.host`. A portless core entry matches any
    port of its host; a bare provider token with no `:port` likewise matches any port.
  - `Ok(a)` with `a.port != 0` → emit `a.host:a.port` (`host:port`). A `host:port`
    core entry matches that port only; the provider token with a port matches that
    port only. (`a.host` is a validated DNS name here — never an IPv6 literal, which
    was skipped above — so no bracketing is needed.)

**L4 → tokens** (`aitm_proto_l4::types::L4ScopeEntry`, types.rs:58; gate
`L4Guard::check(Capture, target)` via `ingress::udp_admits`). The NE UDP path
tags flows `interface = CAPTURE_INTERFACE` (`"macos-ne"`, adapter.rs:49) and
`direction = Outbound` (adapter.rs `udp_target`). So:

- Consider only entries where `capability == L4Capability::Capture`
  **and** `interface == CAPTURE_INTERFACE` **and** `direction == L4Direction::Outbound`.
  Any other entry is **skipped** (it cannot gate an NE-captured flow).
- The entry's `cidr` must be a **host-prefix** CIDR: prefix `32` for a
  `IpAddr::V4` `addr`, or `128` for a `IpAddr::V6` `addr`. A non-host CIDR is
  **skipped** (the provider grammar has no CIDR form; widening to the base
  address, or to the whole block, would be over-inclusive).
- Given a host CIDR, inspect `ports: PortRange { lo, hi }`:
  - any-port (`lo == 0 && hi == 65535`) → emit the bare IP `addr.to_string()`
    (IPv6 **unbracketed**).
  - single-port (`lo == hi`) → emit `ip:port`, IPv6 bracketed as `[ip]:port`
    (use the same bracketing as `Authority`'s `Display`: bracket when the address
    is IPv6).
  - any other (partial) range → **skip** (the grammar is one port or all ports;
    a partial range cannot be represented without widening).

**Rationale to pin (the under-vs-over rule):** the provider is a coarse
pre-filter; the authoritative decision is the core guard, which re-checks every
flow. **Under-inclusive** (we skip a token we cannot represent exactly) means a
flow the core would have captured instead goes direct and uncaptured — the user
is unaffected. **Over-inclusive** (we widen a token) means the provider claims a
flow the core then refuses, and the user's connection breaks. So when the
grammar cannot represent a scope element exactly, **skip, never widen**.

### Why these tests prove agreement

Both pieces are proven against **Rust mirrors of the Swift provider** living in
each module's `#[cfg(test)]`:

- A mirror of `Rendezvous.isAcceptableFile` (FlowHandoff.swift:627-631),
  `isAcceptableDirectory` (635-639), and the path checks (610-615) confirms the
  published file + its 0700 dir would be accepted by the provider.
- A mirror of `ScopeMatcher` parse (FlowHandoff.swift:543-575) + `matches`
  (520-535) confirms the emitted `spec` claims every intended flow and rejects
  every out-of-scope one. (Architect's call: the mirror may compare IP tokens by
  parsing to `std::net::IpAddr` and comparing by value — equivalent to the
  Swift's `IPText.canonical` string compare for valid inputs.)

## Acceptance criteria

Rendezvous:

1. **AC1:** `RENDEZVOUS_PATH == "/private/tmp/aitmproxy-capture.rendezvous"`
   (byte-exact with `FlowHandoff.swift` `HandoffConfig.rendezvousPath`, line 54).
2. **AC2:** `RendezvousFile::publish(dir, p)` for a canonicalizable `dir` writes
   a **regular file** at `p` whose single line trims to `fs::canonicalize(dir)`'s
   string, whose content ends with `"\n"`, whose size is in `1..=1024`, and whose
   mode is `0o600` (no group/other access bit set).
3. **AC3:** a Rust mirror of the Swift `isAcceptableFile` + `isAcceptableDirectory`
   + `sun_path`/absolute/NUL path checks (citing FlowHandoff.swift:610-639)
   **accepts** the published file when its named dir is a non-symlink directory
   with mode `0o700` owned by the same uid.
4. **AC4:** `publish` on a dir whose canonical path is too long to fit
   `abs.len() + 1 + 12 < 104` returns `Err` with
   `kind() == io::ErrorKind::InvalidInput`.
5. **AC5:** when the rendezvous path already holds a **stale regular file**,
   `publish` replaces it with the fresh canonical content; when it holds a
   **symlink** to a victim file, `publish` leaves the victim's content unchanged
   and the rendezvous path is afterwards a regular file holding the canonical
   content (unlink-first + `create_new` do not write through the link).
6. **AC6:** dropping the `RendezvousFile` removes the file from disk (it exists
   while the guard is alive, is gone after it drops).
7. **AC7:** `CaptureListener::publish_rendezvous(&self)` exists with signature
   `-> io::Result<rendezvous::RendezvousFile>` and delegates to
   `RendezvousFile::publish(self.dir(), RENDEZVOUS_PATH)` (compiles; covered
   indirectly by AC2-AC6 and the gate — not unit-tested directly, per Design).

Scope:

8. **AC8:** for the pinned representative fixture (below), `provider_scope_spec`
   returns exactly:
   `"example.com api.example.com *.api.example.com 198.51.100.7 203.0.113.9:53 2001:db8::2 [2001:db8::3]:443"`.
   (The IP-valued L7 entries and the separator-bearing L7 entries are **skipped** —
   security findings 1 and 2 — so no `10.0.0.5`, `2001:db8::1`, comma, or semicolon
   appears.)
9. **AC9:** the `*.suffix` dual-emission is observable: the Swift-`ScopeMatcher`
   mirror, fed the emitted spec, claims **both** the apex `api.example.com`
   **and** a subdomain `www.api.example.com`.
10. **AC10:** the Swift-`ScopeMatcher` mirror (citing FlowHandoff.swift:520-575),
    fed the emitted spec, returns the pinned `true`/`false` for each
    `(hostname, ip, port)` case in the fixture: it **claims** every intended flow
    and **rejects** every out-of-scope flow.
11. **AC11:** L4 filtering holds: an entry with `capability != Capture`,
    `interface != "macos-ne"`, `direction != Outbound`, a **partial** port range,
    or a **non-host** CIDR contributes **no** token (each proven by a flow the
    mirror rejects and by its absence from the AC8 string).
12. **AC12:** L4 any-port emits a bare IP, single-port emits `ip:port`, and an
    IPv6 host address is bare/unbracketed for any-port and `[ip]:port` for
    single-port (covered by the AC8 string's `198.51.100.7`, `203.0.113.9:53`,
    `2001:db8::2`, and the IPv6 **single-port** `[2001:db8::3]:443`, with the mirror
    claiming `(None, "2001:db8::3", 443)` and rejecting `(None, "2001:db8::3", 444)`).
13. **AC13 (security finding 1):** an L7 entry whose host or `*.`-suffix contains a
    provider separator (`,`, `;`, ASCII whitespace) or any char outside
    `isValidHostname`'s `[a-z0-9.\-_]` contributes **no** token — proven by the AC8
    string containing no `,`/`;` and not the injected `b.com`/`d.com`, and by the
    mirror rejecting `(Some("b.com"), "5.5.5.5", 1)`.
14. **AC14 (security finding 2):** an L7 entry whose host parses as an `IpAddr`
    (bare, with port, bracketed IPv6, or as a `*.` suffix) contributes **no** token
    — proven by the AC8 string containing no `10.0.0.5` or `2001:db8::1`, and by the
    mirror rejecting both `(None, "10.0.0.5", 8080)` and, crucially,
    `(Some("unrelated.example"), "10.0.0.5", 8080)` (the over-inclusion that would
    break a connection).

### Pinned scope fixture (for AC8/AC10/AC11/AC12/AC13/AC14)

**L7** (`Vec<ScopeEntry>` by `host`, in order): `"Example.com"` (→ `example.com`),
`"*.api.example.com"` (→ apex + wildcard), `"10.0.0.5:8080"` (IP-valued → **skip**,
AC14), `"[2001:db8::1]:443"` (IP-valued → **skip**, AC14), `"a,b.com"` (comma →
**skip**, AC13), `"*.c;d.com"` (semicolon in suffix → **skip**, AC13).

**L4** (`Vec<L4ScopeEntry>`, in order; all fields except the varied one set to
`capability = Capture`, `interface = "macos-ne"`, `direction = Outbound`):
`198.51.100.7/32` any-port (→ `198.51.100.7`); `203.0.113.9/32` port `53..=53`
(→ `203.0.113.9:53`); `2001:db8::2/128` any-port (→ `2001:db8::2`);
`2001:db8::3/128` port `443..=443` (→ `[2001:db8::3]:443`, the IPv6 single-port case,
AC12); `10.0.0.0/24` any-port (non-host → skip); `192.0.2.1/32` port `1000..=2000`
(partial → skip); `198.51.100.50/32` any-port but `capability = Inject` (skip);
`198.51.100.51/32` any-port but `interface = "en0"` (skip); `198.51.100.52/32`
any-port but `direction = Inbound` (skip).

Mirror match cases (AC10) — `true`: `(Some("example.com"), "1.1.1.1", 443)`,
`(Some("www.api.example.com"), "1.1.1.1", 443)`,
`(Some("api.example.com"), "1.1.1.1", 443)`, `(None, "198.51.100.7", 9999)`,
`(None, "203.0.113.9", 53)`, `(None, "2001:db8::2", 12345)`,
`(None, "2001:db8::3", 443)`. `false`: `(Some("evil.com"), "9.9.9.9", 1)`,
`(Some("api.example.com.evil"), "1.1.1.1", 443)`, `(None, "203.0.113.9", 54)`,
`(None, "2001:db8::3", 444)`, `(None, "10.0.0.5", 8080)` (IP-valued L7 skipped,
AC14), `(Some("unrelated.example"), "10.0.0.5", 8080)` (the over-inclusion AC14
prevents), `(None, "192.0.2.1", 1500)`, `(None, "10.0.0.1", 1)`,
`(None, "198.51.100.50", 1)`, `(Some("b.com"), "5.5.5.5", 1)` (separator L7 skipped,
AC13).

## Left to the builder

- Exact private helper functions inside each module (e.g. an `l7_tokens` /
  `l4_tokens` split), as long as the public signatures above are met.
- The exact text of error messages.
- Whether the Swift mirrors live as free functions or small structs in the test
  module, provided they faithfully reproduce the cited Swift logic and carry the
  citing comments.
- Scratch-dir naming for tests (follow the crate convention:
  `std::env::temp_dir().join(format!("aitm-rendezvous-{…}", …))` with a unique
  suffix; clean up on drop or at test end).

## Open questions

None.

## Summary and Architect's calls

This spec defines two pure, unit-tested core building blocks the macOS NE live
feeder will call: a rendezvous writer (`RendezvousFile::publish` +
`CaptureListener::publish_rendezvous`) that publishes the 0700 socket dir to the
byte-exact provider path with mode-0600, unlink-first + `create_new` safety and
RAII removal; and a scope-spec emitter (`provider_scope_spec`) that renders the
core's L7 host scope and L4 IP scope into the one `ScopeSpec` grammar string the
provider's `ScopeMatcher` reads, skipping (never widening) anything the grammar
cannot represent exactly. Both are proven in the sandbox against Rust mirrors of
the Swift provider's acceptance and matching logic; no feeder, control loop, or
`main.rs` wiring is built, and `adapter.rs` is untouched.

Architect's calls made (please confirm or correct):

- **C1:** Make `CONTROL_SOCK` `pub(crate)` in `listener.rs` and reference it
  from `rendezvous.rs` for the `sun_path` length check (single source of truth)
  rather than hardcoding `"control.sock".len()`.
- **C2:** Place `publish_rendezvous` as an inherent method on `CaptureListener`
  in `listener.rs` (next to `dir()`), not in `rendezvous.rs`.
- **C3:** Do **not** unit-test `publish_rendezvous` directly (it needs the real
  `/private/tmp` path + a bound listener); its live exercise is NE plan Task 18.
- **C4:** Token ordering = L7-then-L4, input order, apex-before-wildcard,
  de-duplicated by first appearance, single-space joined — chosen to make the
  emitted spec deterministic and byte-assertable.
- **C5:** For an L7 `*.` entry with an empty suffix, skip the entry entirely.
- **C6:** The scope mirror compares IP tokens/flows by parsing to
  `std::net::IpAddr` and comparing by value (equivalent to the Swift
  `IPText.canonical` string compare for the fixture's valid inputs).
- **C7:** `SUN_PATH_MAX = 104` hardcoded as a commented module const (macOS
  `sockaddr_un`), matching the Swift side.
