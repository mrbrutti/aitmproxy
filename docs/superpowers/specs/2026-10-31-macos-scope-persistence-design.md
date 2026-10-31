# macOS Scope persistence across embedded-core restarts — design

**Status:** approved — self-approved 2026-10-31 by the owning session (autonomous
mode, memory `aitmproxy-autonomous-approve-merge-mode`; design calls per the
owner's brief, no key account/identity decisions)
**Research inputs:** the owner's design brief
`~/Library/Application Support/Claude-3p/side-session-notes/local_75059306-ee27-4e35-9526-25f7809380be/scope-persistence-BRIEF.md`
(problem, option (a) vs (b), decisions D1–D9); the shipped embedded-core design
(`docs/superpowers/specs/2026-10-30-macos-ne-ship-and-toggle-design.md` for the
per-launch `config.yaml` convention and its byte-exact test style).
**Code read (2026-10-31):** `apps/mac/Sources/AitmproxyKit/EmbeddedCoreLaunch.swift`,
`apps/mac/Sources/AitmproxyKit/Compose.swift` (`enum Scope`),
`apps/mac/Sources/AitmproxyKit/Pins.swift`, `apps/mac/Sources/AitmproxyKit/ActiveConnection.swift`,
`apps/mac/Sources/AitmproxyKit/Panels/ScopeEntry.swift`, `apps/mac/Sources/AitmproxyKit/Fixtures.swift`,
`apps/mac/Sources/Aitmproxy/Session.swift`, `apps/mac/Sources/Aitmproxy/Session+Verbs.swift`,
`apps/mac/Sources/Aitmproxy/App.swift` (`enum Store`), `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`,
`apps/mac/Sources/Aitmproxy/Bus/EmbeddedCore.swift`, `apps/mac/Sources/Aitmproxy/Bus/EmbeddedCoreController.swift`,
`apps/mac/Sources/Aitmproxy/Bus/LiveConnectionDriver.swift`, `apps/mac/Sources/Aitmproxy/Bus/FlowActions.swift`,
`apps/mac/Sources/Aitmproxy/SelfTest.swift`, `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`,
`apps/mac/Sources/Aitmproxy/Panels/ScopePanel.swift`, `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (read only),
`apps/mac/Tests/AitmproxyKitTests/EmbeddedCoreLaunchTests.swift`, `apps/mac/Tests/AitmproxyKitTests/PinsTests.swift`,
`crates/aitm/src/config_file.rs` (`ScopeFile`), `crates/aitm-core/src/config.rs` (`ScopeConfig`, `ScopeEntry`),
`crates/aitm-core/src/guard.rs` (`normalize_scope`, `StdGuard::add_scope`),
`crates/aitm-core/src/proxy.rs` (`ProxyBuilder::build`, guard seeding), `crates/aitm/tests/config_file.rs`,
`crates/aitm/src/macos_capture/feeder.rs` (Scope frame on Hello, `DEFAULT_SCOPE_POLL`).

## Intent

The macOS app's embedded `aitm` core keeps scope only in memory. The app writes
a fresh per-launch `config.yaml` with no `scope:` block, so every quit/relaunch
and every Settings ▸ Proxy "Apply & Restart Core" comes back with an empty
scope: the Scope page is empty, every host is read-only, and the Network
Extension (which claims only in-scope flows, pushed from the core's guard on
Hello) claims nothing. The only hint is the "No scope set" banner. Operators
expect Proxyman-style behaviour: a host added to Scope stays until removed.
This change persists the embedded core's operator scope in the app's own store
(beside `pins.json`), emits it as a `scope:` block in the generated per-launch
config at spawn, and never re-pushes it over the bus — so the core itself stays
stateless across runs for every frontend.

## Goals

- A host added to Scope while the embedded core is active is still in scope
  after quitting and relaunching the app, and after Apply & Restart Core.
- A host removed from Scope stays removed across the same boundaries.
- The Scope page shows the restored scope at launch, before the bus connects,
  and the "No scope set" banner does not appear for a restored, non-empty scope.
- The embedded core receives the restored scope the only way it already accepts
  startup scope: `scope.entries` in its config, parsed by `config_file.rs` and
  seeded into the guard at build through the same `add_scope` normalisation the
  bus verbs use. The NE provider's first Scope frame therefore carries it.
- The external-core path is untouched: nothing is seeded into, written from, or
  displayed for an external core, and the app issues no `scope.add` on connect
  in any mode.
- Fixture, snapshot, and self-test runs never write the operator's store.
- Every acceptance criterion below is pinned by a Swift unit test, a Rust parse
  test, a self-test check, or a listed manual step.

## Non-goals

- No change to the core (`crates/aitm*`) beyond one new test: no `scope.persist`
  knob, no core-side file, no new bus verb.
- No persistence for the external-core connection; its scope is the operator's
  own `config.yaml` plus runtime verbs, exactly as today.
- No persistence of per-host rate limits, L4 scope, breakpoint rules, or any
  other core state; only the L7 host scope (`scope.list`).
- No UI change: `ShellView.swift`, `SettingsView.swift`, `ScopePanel.swift`,
  `Bus/ExtensionController.swift` and `CaptureAdvice.swift` are not edited
  (the first four are owned by a concurrent session; the restored scope must
  make the existing banner condition false by itself).
- No migration or import of scope from an external core's config.
- No "restored from last session" affordance or undo.

## Anti-goals

- **A persisted scope that widens anything the operator did not choose.** The
  file must only ever contain what the embedded core's `scope.list` returned
  after an operator's own add/remove, in a core whose config never enables
  agent widening.
- **Making every `aitm` remember scope.** CLI/TUI/web users must see no
  behaviour change; the core stays stateless across runs.
- **A second source of truth that fights the core.** The app never re-pushes
  `scope.add` on connect; the core's `scope.list` always wins after connect.
- **A corrupt or tampered `scope.json` that wedges the embedded core.** Invalid
  entries are dropped at load, never emitted; a newline-bearing host can never
  reach the YAML.
- **Test runs that dirty `~/Library/Application Support/Aitmproxy/`.**

## Constraints

- **Core compatibility.** `config_file.rs` `ScopeFile { entries: Option<Vec<String>>, allow_agent_widen: Option<bool> }`
  with `deny_unknown_fields`; `entries` map to `ScopeEntry { host }`; the guard
  is seeded in `ProxyBuilder::build` via `guard.add_scope(entry)` which trims,
  ASCII-lowercases and de-duplicates (`normalize_scope`). The emitted block must
  be exactly what that parser accepts and nothing else.
- **Generated-config conventions** (`EmbeddedCoreLaunch.Config.yaml()`): a base
  block with no trailing newline, then optional tails each prefixed with `\n`
  (`ssl_insecure: true\n`, `macos_capture:\n  enabled: true\n`); double-quoted
  scalars escaped by `yamlDoubleQuoted` (`\` and `"`), newline/CR rejected;
  file written `0600` with `O_NOFOLLOW`. Existing byte-exact tests (notably
  `hasSuffix("macos_capture:\n  enabled: true\n")` for scope-less configs and
  `!yaml.contains("scope:")` for the default config) must stay valid.
- **Isolation.** The `Aitmproxy` target compiles with `defaultIsolation(MainActor.self)`;
  `enum Store` is therefore main-actor isolated, and `EmbeddedCore` is an actor.
  Reading `Store.url` from `spawn()` needs an `await` (or the URL injected at
  init); `EmbeddedCore.discoverBundled()` is a static (non-isolated) call.
- **Store contract.** `Store.url` honours `APP_STORE`; snapshots and self-tests
  refuse to run unless `Store.isOverridden` (APP_STORE in /tmp);
  `Store.usesFixtures` is true for `APP_FIXTURES=1`, any `APP_SNAPSHOT`, or
  `--selftest` unless `APP_LIVE=1`.
- **Security posture.** Scope widening stays operator-only; MITM only in-scope
  hosts; the persisted file is the operator's explicit, UI-visible choice; no
  agent can read or write `scope.json` (the bus has no verb for it); the
  generated embedded config never enables `scope.allow_agent_widen` or
  `rhai.allow_scope_add`.
- **Files owned by another concurrent session — do not touch:**
  `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift`,
  `apps/mac/Sources/Aitmproxy/SettingsView.swift`,
  `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`,
  `apps/mac/Sources/Aitmproxy/CaptureAdvice.swift`.
- **Gates.** Rust: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  Swift: `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`
  (Terminal panel), `tools/selftest.sh`, `tools/selftest-live.sh`.

## Design

### The decision: (a) app-side persistence, not (b) a core-side persist file

Chosen by the owner; recorded here with the reasons so a builder does not
reopen it.

| Concern | (a) app store `scope.json` → `scope:` block in the per-launch config (chosen) | (b) core-side `scope.persist` file |
|---|---|---|
| Core state across runs | Unchanged: the core stays stateless; scope = operator config + runtime verbs, for every frontend | Every `aitm` run silently remembers scope — a widening surprise for CLI/TUI/web users |
| New core surface | None. One more operator-authored key in a config the app already writes `0600`/`O_NOFOLLOW` per launch, the same route `listen`, `ssl_insecure` and `macos_capture.enabled` take | A new config knob, a Rust file-permission and atomicity story, a new write path on every scope verb |
| Ownership and visibility | The app operator's: lives in the app's store, shown on the Scope page, never touches an external core | Shared by every frontend, invisible to the app's model |
| Runtime trigger | None: `config.scope.entries` already seeds the guard in `ProxyBuilder::build` through `add_scope` normalisation | New |
| Bus traffic | None. (Re-pushing `scope.add` on connect was considered and rejected: redundant with config seeding, and it races the NE feeder's first Scope frame) | None |
| Tests | Swift unit tests + one Rust parse test | Rust persistence tests + Swift |

### Data flow

```
operator adds/removes host on the Scope page (embedded core active)
  → BusService.addScope/removeScope: scope.add|scope.remove → scope.list (refreshScope)
  → iff preferEmbedded && !Store.usesFixtures: EmbeddedScope(hosts: session.scopeHosts).save(to: session.scopeURL)
                                                              ↓ ~/Library/Application Support/Aitmproxy/scope.json
next spawn (launch, crash-restart, Apply & Restart Core)
  → EmbeddedCore.spawn(): EmbeddedScope.load(from: scopeURL).hosts  (validated, de-duplicated)
  → EmbeddedCoreLaunch.Config(scopeHosts:) → yaml() appends `scope:\n  entries:\n    - "<host>"…`
  → core: config_file.rs ScopeFile.entries → ProxyBuilder::build → guard.add_scope(each)
  → NE feeder: first Scope frame after Hello = guard.list_scope() → provider claims in-scope flows
next launch display
  → Session.init: iff embedded kind && bundled core && !fixtures: scopeHosts = EmbeddedScope.load(...).hosts
  → on connect, refreshScope() replaces it with the core's scope.list (equal when seeding worked)
```

### D1. Model — `EmbeddedScope` (AitmproxyKit, new file `EmbeddedScope.swift`)

The persisted operator scope of the **embedded** core only. JSON
`{"hosts": [...]}`, pretty-printed with sorted keys like `Pins`.

```swift
public struct EmbeddedScope: Codable, Hashable, Sendable {
    public var hosts: [String]
    public init(hosts: [String] = [])

    /// `store/scope.json` — beside `pins.json`.
    public static func url(in store: URL) -> URL

    /// Missing, unreadable, or undecodable → empty. Hosts pass through `sanitized`.
    public static func load(from url: URL) -> EmbeddedScope

    /// Pretty + sortedKeys, creates the directory, writes atomically.
    public func save(to url: URL) throws

    /// Trim, drop what `isPersistable` rejects, drop duplicates keeping the first; order kept.
    public static func sanitized(_ hosts: [String]) -> [String]

    /// `Scope.validate(trimmed) == nil` AND no newline/control character.
    public static func isPersistable(_ host: String) -> Bool

    /// Whether `Session.init` seeds `scopeHosts` from the file (D5).
    public static func seedsAtLaunch(activeKind: ActiveCoreKind, bundledCorePresent: Bool, usesFixtures: Bool) -> Bool
}
```

Load semantics, in order, per host: trim `.whitespacesAndNewlines`; drop if
`Scope.validate(trimmed)` returns a message; drop if the trimmed host contains
any character in `.newlines` or `.controlCharacters`; drop if an earlier kept
host is string-equal. Order is preserved. A missing file, an unreadable file,
non-JSON, or JSON of the wrong shape all yield `EmbeddedScope()`.

**(Architect's call)** The explicit newline/control-character rule exists because
`Scope.validate` (`Compose.swift`) trims `.whitespaces` only and checks for
`://`, `/`, a space, dots at the ends, and the port range — it returns `nil`
(valid) for `"bad\nhost.test"`. Without this rule a tampered or corrupt file
would make `Config.yaml()` throw on every spawn (D2) and wedge the embedded
core in a restart loop. Load is the single validation point; emission's newline
check (D2) is belt-and-braces.

**(Architect's call)** `save(to:)` writes with `Data.WritingOptions.atomic`
(unlike `Pins`, which uses the default). A crash mid-write must not leave a
truncated file that loads as empty and silently wipes scope at the next launch.
Permissions are the default (the file holds host names, the same class as
`pins.json`; it is not a secret).

**(Architect's call)** `sanitized`, `isPersistable` and `seedsAtLaunch` are
public pure functions so the Kit tests pin them with literals; the app passes
in the three facts for `seedsAtLaunch` rather than the Kit reading
`UserDefaults`, `Bundle.main` or `Store`.

Load does not lowercase: the persisted list is the core's `scope.list`, already
normalised; a mixed-case entry from a hand-edited file is still collapsed by
the core's `add_scope` at seed time.

### D2. Config emission — `EmbeddedCoreLaunch.Config`

```swift
public struct Config: Sendable {
    // existing fields …
    /// The embedded core's restored operator scope (D1); emitted as `scope.entries`.
    public var scopeHosts: [String]

    public init(
        obscuraBinary: URL, proxyPort: UInt16, browserProxyPort: UInt16,
        token: String, operatorToken: String, endpointFile: URL,
        sslInsecure: Bool = false, captureEnabled: Bool = false,
        scopeHosts: [String] = []          // new, last, defaulted: every call site compiles
    )
}

public enum ConfigError: Error, Equatable {
    case pathContainsNewline(String)
    case hostContainsNewline(String)       // new
}
```

When `scopeHosts` is non-empty, `yaml()` appends, **after** the `macos_capture`
tail (so every existing `hasSuffix` test on scope-less configs stays valid), a
top-level block that is byte-for-byte:

```
scope:
  entries:
    - "api.example.test"
    - "*.shop.test"
    - "localhost:8099"
```

i.e. `"scope:\n  entries:\n"` followed by one `"    - \"<escaped>\"\n"` line
per host, in array order, where `<escaped>` is the same `\`/`"` escaping
`yamlDoubleQuoted` applies to paths. A host containing `\n` or `\r` makes
`yaml()` throw `ConfigError.hostContainsNewline(host)`. When `scopeHosts` is
empty, no `scope` text of any kind is emitted. `allow_agent_widen` is **never**
emitted (test-pinned for both the default and a scoped config).

**(Architect's call)** The block is appended the way the other tails are —
prefixed with a single `\n` — so when `macos_capture` is on there is one blank
line between the two blocks. YAML is indifferent; the tests assert
`hasSuffix(block)` and "exactly one `scope:` line at column 0", not the
separator.

**(Architect's call)** `yaml()` trusts its hosts beyond the newline check
(no re-validation, de-duplication or lowercasing at emission). Validation has
exactly one home, `EmbeddedScope.load` (D1); the core normalises again at seed.

### D3. Read at spawn — `EmbeddedCore.spawn()`

Alongside the fresh `UserDefaults` reads (`proxy.preferredPort`,
`proxy.verifyUpstreamTLS`, `capture.enabled`), `spawn()` reads
`EmbeddedScope.load(from: EmbeddedScope.url(in: Store.url)).hosts` **fresh on
every spawn** and passes it as `scopeHosts:`. Consequence: Apply & Restart Core
(`EmbeddedCoreController.restart()` → `core.stop()` → `core.start()` → `spawn()`)
and crash-restarts no longer wipe scope. `spawn()` is embedded-only by
construction — nothing on the external path ever calls it.

`Store` is main-actor isolated under the target's default isolation; the read
is `await`ed (or the URL is injected at `EmbeddedCore.init` from
`EmbeddedCoreController` — builder's choice; the contract is "fresh each spawn").

### D4. Write path — `BusService.addScope` / `removeScope`

```swift
@discardableResult private func refreshScope() async -> Bool   // true iff scope.list succeeded and session.scopeHosts was set
private func persistEmbeddedScope() throws                       // iff preferEmbedded && !Store.usesFixtures: save EmbeddedScope(hosts: session.scopeHosts) to session.scopeURL; a failed save throws BusError.tool("Scope change not saved: …") (panel amendment)
```

After the verb **and** the refresh both succeed, persist
`EmbeddedScope(hosts: session.scopeHosts)` to `session.scopeURL` iff
`preferEmbedded && !Store.usesFixtures`. Snapshot semantics: the file is the
embedded core's `scope.list` as of the operator's last Scope action. It is not
written on connect, not on poll, never from a failed verb, and never while the
client is pointed at an external core (`preferEmbedded` is true exactly from
`awaitEmbeddedEndpoint`/`useEmbeddedEndpoint` until `useExternalEndpoint`).
Removing the last host writes `{"hosts": []}`; the app never deletes the file.

Precondition that makes "every persisted entry is an operator's choice" true:
the generated embedded config never enables `scope.allow_agent_widen` or
`rhai.allow_scope_add`, so only operator-token clients can widen the embedded
core, and `scope.list` is therefore the operator's own choice. (Alternative
considered — persist only the app's own add/remove deltas — rejected: it would
diverge from the core's normalisation and rejections and buys nothing while
the precondition holds.)

**(Architect's call)** `refreshScope` returns `Bool` so a succeeded `scope.add`
followed by a failed `scope.list` does not persist a stale list; the next
successful action re-syncs. **(Architect's call, superseded by the panel amendment below)** A failed save
was to be swallowed (`try?`) as `Pins`, `BreakpointRules` and `ColumnLayout` do;
it is now an error of the action. The in-memory scope stays correct either way.

### D5. Launch display — `Session.init`

```swift
var scopeURL: URL { EmbeddedScope.url(in: Store.url) }     // beside pinsURL
```

In `init()`, next to the pins load: when
`EmbeddedScope.seedsAtLaunch(activeKind: UserDefaultsActiveKindPersistence().load() ?? .embedded, bundledCorePresent: EmbeddedCore.discoverBundled() != nil, usesFixtures: Store.usesFixtures)`
is true, set `scopeHosts = EmbeddedScope.load(from: scopeURL).hosts`, so the
Scope page lists them before the bus connects. On connect `refreshScope()`
replaces the list with the core's (equal when seeding worked). `loadFixtures()`
still sets `scopeHosts = Fixtures.scope` in fixture mode, as today.

**(Architect's call)** The seed is additionally gated on a bundled core being
present. `LiveConnectionDriver.activateEmbedded()` falls back to
`useExternalEndpoint()` when `EmbeddedCore.discoverBundled()` is `nil`
(development builds, the live self-test, CLI operators), so with the brief's
two-part gate a dev build would briefly show the embedded scope while actually
connecting to an external core. The three-part predicate is pure and
unit-tested in the Kit.

### D6. External core

Never seeded into it (spawn is embedded-only), never written from it
(`preferEmbedded` false), never shown at launch when the persisted active kind
is external (D5 predicate). The app issues no `scope.add` on connect in any
mode: the only `scope.add` call site in `BusService` remains `addScope`, which
runs only on an operator's Scope action.

### D7. Network Extension

No core change. `feeder.rs` sends the provider a Scope frame after Hello built
from `l7_guard.list_scope()`, which the config seeded in `ProxyBuilder::build`,
so the provider honours the restored scope at once; its re-poll
(`DEFAULT_SCOPE_POLL`, 1 s) covers later operator edits as today.

### D8. Test and fixture isolation

Fixture mode never writes: `FixtureActions.addScope/removeScope` mutate
`session.scopeHosts` directly and never reach `BusService`, and the D4 guard
also refuses while `Store.usesFixtures`. Snapshot and self-test runs refuse to
start unless `APP_STORE` is set, so even `APP_LIVE=1` runs cannot touch the
operator's store. The live self-test connects to an **external** core
(`AITM_CONFIG`) → `preferEmbedded` false → no write.

### D9. Rust

One new test in `crates/aitm/tests/config_file.rs` parses the exact bytes D2
emits for three hosts and asserts the entries and `!allow_agent_widen`. No
production Rust change.

### Security posture (summary for the reviewers)

- Widening stays operator-only: the generated config never enables
  `scope.allow_agent_widen`/`rhai.allow_scope_add`; the persisted snapshot is
  the operator's own `scope.list`.
- `scope.json` is unreachable from the bus (no verb); agents cannot read or
  write it. It is readable by the same local user account that already owns
  `pins.json`, `rules.json` and the app's `UserDefaults` — the trust boundary
  is unchanged.
- Fail-safe load: invalid entries are dropped, never widened or "fixed";
  emission refuses newlines, so no crafted host can inject YAML into the
  token-bearing config.
- The file restores only what the operator authorised in a previous run, is
  shown on the Scope page, and remove persists; no new MITM surface.

### Panel amendments (ratified 2026-10-31 by the owning session after the stage-5/6 reports)

Three behaviours were tightened by the panel fix wave; each supersedes the
corresponding sentence above.

- **D1, `isPersistable`.** In addition to `Scope.validate` and the
  newline/control-character rule, a host is persistable only if every Unicode
  scalar is one libyaml's reader prints (`U+0009`, `U+0020…U+007E`, `U+0085`,
  `U+00A0…U+D7FF`, `U+E000…U+FFFD`, `U+10000…U+10FFFF`). Why: the core's YAML
  reader refuses U+FFFE/U+FFFF, which `Scope.validate`, the core's own
  `scope.add` and the Cc/Cf check all accept, so a persisted host could wedge
  the embedded core in a restart loop (security Important).
- **D1, `load`/`sanitized` caps.** `load` reads only a regular file of at most
  1 MiB (anything else → empty); `sanitized` drops hosts longer than 1 024
  characters and keeps at most 10 000 entries (the first ones, in order). Why:
  the read runs on the main actor at launch and inside the core actor at every
  spawn, and the core seeds the guard with a linear-scan de-dup (security Minor).
- **D2, newline guard.** `yamlDoubleQuoted` rejects a newline or carriage
  return as Unicode scalars, not Characters: Swift treats `"\r\n"` as one
  grapheme, so the Character-based `contains` let a CRLF host through (tester
  F1; SP-AC16 now also covers CRLF).
- **D4, failed save.** A failed `scope.json` save is surfaced as
  `session.lastError` ("Scope change not saved: …") instead of being swallowed:
  a silently failed save after a remove would resurrect the host at the next
  launch (security Minor; supersedes OQ1's default). The in-memory scope is
  unchanged.
- **D4, embedded intent.** `addScope`/`removeScope` snapshot `preferEmbedded`
  before the verb and persist only if it was and still is true after the
  refresh, so a Settings ▸ Bus switch mid-action cannot persist the other
  core's list (quality Minor).

## Acceptance criteria

Prefix `SP-`. Verification kind in brackets: `[kit]` Swift unit test in
`AitmproxyKitTests`, `[rust]` cargo test, `[selftest]` fixture self-test check,
`[live]` live self-test check (external core), `[manual]` owner-run step in the
plan's Manual verification, `[review]` confirmed by diff inspection in the panel.

1. **SP-AC1 Launch display.** With the persisted active kind `embedded`, a
   bundled core present, not in fixture mode, and `scope.json` holding
   `["api.example.test", "*.shop.test"]`, the Scope page lists both hosts
   before the bus connects; after connect the list equals the core's
   `scope.list` (the same two hosts). `[manual]` plus
   `EmbeddedScope.seedsAtLaunch(.embedded, true, false) == true` `[kit]`.
2. **SP-AC2 Add persists.** With the embedded core active, adding
   `api.example.test` on the Scope page results in `scope.json` whose `hosts`
   equal the core's `scope.list` and contain `api.example.test`, written only
   after `scope.add` and `scope.list` both succeeded. `[manual]`, `[review]`.
3. **SP-AC3 Remove persists.** Removing a host rewrites `scope.json` without it;
   removing the last host writes `{"hosts": []}` and the file still exists.
   `[manual]`, `[review]`.
4. **SP-AC4 Byte-exact block.** `Config(… scopeHosts: ["api.example.test", "*.shop.test", "localhost:8099"]).yaml()`
   has the suffix
   `"scope:\n  entries:\n    - \"api.example.test\"\n    - \"*.shop.test\"\n    - \"localhost:8099\"\n"`;
   split on `\n`, the lines contain exactly one `scope:` (column 0), `  entries:`
   directly after it, then the three `    - "…"` lines in order. `[kit]`
5. **SP-AC5 Never `allow_agent_widen`.** Neither the default config's YAML nor a
   scoped config's YAML contains the text `allow_agent_widen`. `[kit]` The Rust
   parse of the SP-AC4 block yields `allow_agent_widen == false`. `[rust]`
6. **SP-AC6 Empty scope emits nothing.** A `Config` built without `scopeHosts:`
   has `scopeHosts == []` and its YAML contains neither `scope:` nor `entries`
   — the existing `!yaml.contains("scope:")` assertion for the default config
   stays green. `[kit]`
7. **SP-AC7 Core parses the exact bytes.** `aitm::config_file::parse` of exactly
   `"scope:\n  entries:\n    - \"api.example.test\"\n    - \"*.shop.test\"\n    - \"localhost:8099\"\n"`
   yields `cfg.scope.entries` hosts `["api.example.test", "*.shop.test", "localhost:8099"]`
   and `!cfg.scope.allow_agent_widen`; `"scope:\n  entries: []\n"` yields empty
   entries; the block prefixed with `"ssl_insecure: true\n"` still parses to
   the same hosts. `[rust]`
8. **SP-AC8 External core untouched.** (a) `seedsAtLaunch(.external, true, false) == false`
   and `seedsAtLaunch(.embedded, false, false) == false` `[kit]`; (b) in the
   live self-test (external core) after `session.addScope(upstream)` lands in
   `scope.list`, no file exists at `session.scopeURL` `[live]`; (c) the
   external path never calls `EmbeddedCore.spawn()` `[review]`.
9. **SP-AC9 No `scope.add` on connect.** In the live self-test, between
   `.connected` and the self-test's own first `addScope`, the activity log
   holds no operator-origin `scope.add` entry `[live]`; `BusService`'s only
   `scope.add` call site is `addScope` `[review]`.
10. **SP-AC10 Test runs never write the operator's store.** In the fixture
    self-test, after `session.addScope("persist-probe.test")` lands in
    `session.scopeHosts`, no file exists at `session.scopeURL` and
    `EmbeddedScope.load(from: session.scopeURL).hosts == []` `[selftest]`;
    `seedsAtLaunch(.embedded, true, true) == false` `[kit]`; snapshot/self-test
    refusal without `APP_STORE` is unchanged `[review]`.
11. **SP-AC11 Banner.** With a restored non-empty scope, once the bus is
    `.connected` the "No scope set — every host is read-only until you add
    one" banner is not shown, with `ShellView.swift` unchanged (`git diff` shows
    no hunk in it). `[manual]`, `[review]`
12. **SP-AC12 NE first Scope frame.** With capture on and a restored scope,
    the extension's first Scope frame after Hello carries the restored hosts
    (provider log / an in-scope flow from a non-curl app is claimed and
    appears in the app without any Scope edit this run). `[manual]`
13. **SP-AC13 Apply & Restart Core keeps scope.** After Settings ▸ Proxy
    "Apply & Restart Core", `scope.list` on the new core equals the list before
    the restart, and the new child's `config.yaml` carries the block. `[manual]`
14. **SP-AC14 Load sanitises.** A file with
    `{"hosts": ["api.example.test", " api.example.test ", "*.shop.test", "", "http://x.test", "a b.test", "api.example.test", "bad\nhost.test", "localhost:8099"]}`
    loads as `["api.example.test", "*.shop.test", "localhost:8099"]`. `[kit]`
15. **SP-AC15 Missing/corrupt loads empty.** A missing path, the bytes
    `{not json`, and `{"hosts": "x"}` each load as `EmbeddedScope()` with
    `hosts == []`. `[kit]`
16. **SP-AC16 Newline rejected at emission.** `Config(… scopeHosts: ["ok.test", "evil.test\nlisten: 0.0.0.0:1"]).yaml()`
    throws `EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\nlisten: 0.0.0.0:1")`;
    a `\r` variant throws. `[kit]`
17. **SP-AC17 Escaping.** `scopeHosts: ["a\"b.test", "c\\d.test"]` emits the
    lines `    - "a\"b.test"` and `    - "c\\d.test"` (one backslash before the
    quote; two backslashes for the backslash). `[kit]`
18. **SP-AC18 Round trip and path.** `EmbeddedScope(hosts: ["api.example.test", "*.shop.test"])`
    saved to a temp file loads equal to itself; `EmbeddedScope.url(in: store).lastPathComponent == "scope.json"`
    and its parent is `store`. `[kit]`
19. **SP-AC19 Persist only after a successful refresh.** `persistEmbeddedScope()`
    is reached only when `refreshScope()` returned `true`; a failed
    `scope.list` after a succeeded verb leaves the file untouched. `[review]`
20. **SP-AC20 Gates and footprint.** Rust gate green; `git diff --stat -- crates/`
    lists only `crates/aitm/tests/config_file.rs`; `swift test` green;
    `tools/selftest.sh` PASS including the new check; `tools/selftest-live.sh`
    PASS including the two new checks; no hunk in any file of the do-not-touch
    list. `[gate]`, `[review]`

## Left to the builder

- Whether `yaml()` pre-checks hosts for `\n`/`\r` before calling
  `yamlDoubleQuoted`, or `yamlDoubleQuoted` is generalised with an error
  factory; the observable contract is the thrown `hostContainsNewline(host)`.
- Whether `EmbeddedCore.spawn()` reads `Store.url` with `await` or receives the
  scope URL at `init` from `EmbeddedCoreController` (the latter touches
  `EmbeddedCoreController.swift`, which is allowed). Contract: read fresh on
  every spawn.
- Exact placement of the seed inside `Session.init()` (beside the pins load),
  of the fixture check inside `SelfTest.swift` (beside the S-014 pins block),
  and of the two live checks around the existing `session.addScope(upstream)`.
- Test helper names and the temp-directory convention (`$TMPDIR` as the
  existing capture tests do).
- Doc-comment wording; the `yaml()` doc comment that says "no `scope:` block is
  emitted" must be updated to "only when `scopeHosts` is non-empty".

## Open questions

Genuine product questions, each with a default so work is not blocked.

- **OQ1 — surface a failed `scope.json` save?** Default **(Architect's call)**:
  no; swallow like `Pins` (the in-memory scope is correct for this run; the
  store directory failing to write is a broader problem the operator sees
  elsewhere).
- **OQ2 — delete the file when the last host is removed?** Default
  **(Architect's call)**: no; write `{"hosts": []}`. Simpler, and the file's
  presence then documents "the operator has used Scope".
- **OQ3 — should an external-core connection ever persist its scope?** Default:
  no (non-goal); the external core's `config.yaml` is the operator's.

## Summary

The embedded core's operator scope is persisted by the app, not the core: every
operator add/remove on the embedded core snapshots `scope.list` to
`~/Library/Application Support/Aitmproxy/scope.json` (atomic, validated on
load), and every spawn of the embedded child renders that list as a byte-exact
`scope.entries` block in the per-launch `config.yaml`, which the core already
parses and seeds into its guard — so the Scope page, the proxy and the Network
Extension all come back with the same scope after relaunch or Apply & Restart
Core. Nothing is re-pushed over the bus, the external core is never seeded,
written or displayed, fixture/snapshot/self-test runs cannot write the
operator's store, and no core production code changes.

**Architect's calls** (approve or correct): (1) load rejects hosts containing a
newline/control character in addition to `Scope.validate`, because
`Scope.validate` accepts them; (2) `save(to:)` writes atomically; (3)
`sanitized`/`isPersistable`/`seedsAtLaunch` are public pure Kit functions;
(4) the launch seed is also gated on a bundled core being present (dev builds
fall back to an external core); (5) the `scope:` block is appended like the
other tails (one `\n` prefix; a blank line may precede it when capture is on);
(6) `yaml()` does not re-validate/de-duplicate hosts — load is the single
validation point; (7) `refreshScope()` returns `Bool` and the save runs only on
`true`; (8) a failed save is swallowed (OQ1); (9) emptying scope writes
`{"hosts": []}` rather than deleting (OQ2); (10) the live self-test gains two
checks (no `scope.add` on connect; no `scope.json` for an external core) in
`SelfTest+Live.swift`, a file not on the do-not-touch list.
