# Per-host decryption and visible tunnels — design

**Status:** approved — self-approved 2026-10-31 by the per-host-decryption session
(autonomous mode; product decision by Matt 2026-10-31, verbatim: "Switch to per-host
decryption like Proxyman: decrypt only hosts in scope, passthrough the rest, with
inline Add to Scope.").
**Research inputs:** `docs/research/10-macos-network-extension.md` (Proxyman's
host-scoped capture model, the NE claim rule), the shipped TLS-passthrough design
`docs/superpowers/specs/2026-10-28-aitmproxy-m6-parity-design.md` (F11), the NE
honest-state spec `docs/superpowers/specs/2026-10-31-ne-no-scope-honest-state-design.md`
("nothing in scope" wording), `docs/superpowers/specs/2026-10-31-flow-finish-and-timing-design.md`
(the one `duration_ms` rule).
**Milestone:** v0.5.8.
**Branch / worktree:** `claude/youthful-kapitsa-c196d6` off `main` 144cdcc8,
`/Users/matt/Security/aitmproxy/.claude/worktrees/youthful-kapitsa-c196d6`.

## Intent

Today the proxy terminates TLS for every host the client trusts; Scope only gates
*actions* (replay, scripts' network, scanner, SSRF). That is the opposite of how an
operator reasons about an engagement: the hosts they are authorised to look inside
are the Scope, everything else should pass untouched. It also produces silence
where the operator most needs a signal: a CONNECT whose TLS handshake fails (a
client that refuses our CA) or that is tunnelled produces **no flow at all**, which
is exactly the "Safari shows zero rows" mystery of v0.5.3–v0.5.5.

This change makes Scope the decryption list: the proxy decrypts **only** hosts in
Scope, tunnels every other CONNECT byte-for-byte, and emits **every** CONNECT as a
visible row with its outcome (`decrypted`, `passthrough`, `failed` + reason). The
flip is live: `scope.add` decrypts the next connection, `scope.remove` tunnels it.
The Network Extension already claims only in-scope hosts, so the capture path and
the explicit-proxy path now agree.

## Goals

- A real core with an empty Scope decrypts nothing: every HTTPS CONNECT is a
  `passthrough` row, the client sees the origin's own certificate, and no decrypted
  request row exists for that host.
- `scope.add <host>` makes the **next** connection to that host decrypted (a
  `decrypted` tunnel row plus its inner request rows), with no restart; `scope.remove`
  reverses it for new connections; connections already open are left alone.
- A client that rejects the proxy's certificate for an in-scope host produces a
  `failed` row whose reason says so. A tunnel that fails for another reason says why.
- Plain HTTP to an out-of-scope host is observed as a flow but nothing acts on it: no
  script, no intercept rule, no mutation, no map rule; the row says it was passive.
- `flow.get`, `flow.table`, the push summary and `flow.detail` all carry the same
  tunnel fields; `proxy.status` tells a frontend whether anything is decrypted and
  the sentence to show when nothing is.
- The agent gate on widening Scope is **unchanged**.

## Non-goals

- Frontend code. The macOS inline "Add `<host>` to Scope (⌥⏎)" is S-073
  (mac-improve-loop); the TUI and web inline actions and passthrough-row rendering
  are separate units. This spec fixes the wire contract they consume (§D9).
- A "decrypt everything" switch. There is no wildcard-all Scope token today and this
  spec adds none; the model is opt-in per host, as Proxyman's is.
- Removing the explicit `tls.passthrough.*` pin list. It keeps its meaning ("never
  decrypt this host, even if it is in Scope") and its agent gate.
- Intercepting or killing a CONNECT itself. A tunnel row is a record, not an
  actionable exchange.
- Gating `ws.send` or other commands on a passive flow (follow-up; today they are
  reachable only for flows that were in scope when captured, see §D4).
- Changing the Network Extension's claim rule (already host-scoped).

## Anti-goals

- Decrypting an out-of-scope host through any path (module order, a missing guard, a
  ClientHello larger than the acceptor's peek). Every path that terminates TLS checks
  Scope itself; a context without a scope guard decrypts nothing (deny-by-default).
- A CONNECT that leaves no trace. Silence was the bug.
- A tunnel row that lies about its status: `200` means the tunnel was established
  end to end; a failed tunnel never reports `200` even if the proxy had already
  written the `200 Connection Established` acknowledgement.
- A hidden regression of the agent gate: `scope.add` keeps `caller_is_trusted_control`
  / `allow_agent_widen` exactly; `scope.remove` keeps its current posture (not gated,
  `Sensitivity::Sensitive` by default, audited).
- Double counting: a decrypted tunnel row shares its authority with its inner request
  rows; a frontend that counts requests must not count the tunnel row as one (§D9).

## Constraints

- No new dependency. The acceptor's peek stays 2048 bytes; the CONNECT line always
  fits in the first segment. SNI-only (raw TLS, no CONNECT) connections are the
  transparent/NE path, which is scope-gated before any module runs.
- `Flow::Http` keeps its shape (93 struct literals in the workspace); new facts live on
  `FlowMeta`, which has `Default` and is the per-flow bookkeeping struct already.
- The one `duration_ms` / `started_at` rule (`FlowMeta::duration_ms`,
  `FlowMeta::started_at_ms`) is reused as is; a tunnel row's `created` is the time
  the CONNECT head was read, its `duration` is set once on close.
- The push summary (`aitm-mcp` `flow_summary`) and `flow.get` (`aitm-plugins`
  `summarize`) are locked together by
  `push_summary_equals_flow_get_for_http_and_websocket_flows`; both gain the same keys.
- Secrets: a tunnel row stores the CONNECT request headers (they are the request);
  `proxy-authorization` is already a secret key under `is_secret_key` (`auth`
  segment), so `flow.detail` redaction covers it. Failure reasons are a fixed code
  set, never free text copied from an error.
- `crates/aitm/src/wire.rs`, `ingress.rs` and the `aitm-mcp` server pins were touched
  today by #214/#215; this change adds no bus verb, so `EXPECTED_TOOLS`/`CORE_TOOLS`/
  `bus-fixture.json` are untouched. Only `proxy.status` gains a sub-object.
- Quiet default logs: nothing new at `warn`; the advice line is printed once in the
  startup summary and served on the bus, not logged repeatedly.

## Design

### D1. The decryption rule

A TLS connection is **decrypted** iff its tunnel authority is in Scope and not on
the `tls.passthrough` pin list. Otherwise it is **passed through** (tunnelled
byte-for-byte to the origin; the client completes TLS against the origin's own
certificate).

- *Tunnel authority* is `host:port` from the `CONNECT host:port` line (port defaults
  to 443 when absent). For a raw TLS connection (no CONNECT) it is the ClientHello
  SNI with the destination port when the connection came from a capture ingress
  (`NextLayerHint::capture_interface.is_some()`, whose `dst` is the original
  destination), else `sni:443`. Authority with no SNI and no CONNECT cannot be
  decrypted today and is unchanged (it fails as before; see D6 for its row).
- *In Scope* is `ScopeRateGuard::in_scope(authority)`, i.e. exactly
  `Authority::matches_scope_entry` over the live entries: a bare `host` entry admits
  every port of that host, `host:port` only that port, `*.suffix` the suffix and its
  subdomains, matched case-insensitively. IP literals match as hosts. This is the
  same predicate the NE ingress gates on, so a host that the extension claims is a
  host the core decrypts.
- The rule is evaluated **per connection, at the moment the CONNECT head (or the
  ClientHello) is read**, against the live guard. `scope.add` therefore takes effect
  on the next connection; `scope.remove` likewise. A connection already decrypted or
  already tunnelled keeps going until it closes ("existing tunnels are left alone").
- Pins win over Scope: a pinned host in Scope is still tunnelled, with
  `tunnel_reason: "pinned"`.
- An upgrade hand-off (`NextLayerHint::from_upgrade`) has **no** tunnel authority: it
  continues a connection whose decision was already made, so neither the passthrough
  module nor the HTTP module re-decides it (added 2026-11-01 from the Task 3 report).

### D2. Where the decision is made (Architect's call)

Two places decide, with the same predicate, so no single miswiring can decrypt an
out-of-scope host:

1. **`PassthroughModule`** (first in module order, as today) claims a connection
   whose tunnel authority is pinned **or not in Scope**. It gains a scope handle:
   `PassthroughModule::new(list).with_scope(Arc<dyn ScopeRateGuard>)`. Without a
   scope handle it claims **every** TLS/CONNECT connection (deny-by-default: no
   guard means nothing is in scope), so a test or embedding that forgets the handle
   fails loudly rather than decrypting. Its `matches` uses the acceptor's peeked
   bytes exactly as today (CONNECT line or SNI); the port rule of D1 is a new helper
   `NextLayerHint::tunnel_authority(&self) -> Option<Authority>` on the core hint so
   both modules compute the same string.
2. **`HttpModule`** re-checks before it terminates TLS. `ModuleCtx` gains
   `with_scope(Arc<dyn ScopeRateGuard>)` and `in_scope(&str) -> bool` (false when no
   guard is attached). On a CONNECT or raw-TLS connection whose authority is **not**
   in scope the HTTP module does not decrypt: it runs the same byte relay the
   passthrough module runs (shared helper, D5) and records a `passthrough` row. This
   path is normally unreachable (the passthrough module claimed the connection
   first); it exists so the invariant holds without relying on module order, and it
   is the path for a raw-TLS ClientHello that did not fit the acceptor's peek.

The acceptor (`aitm_core::Proxy::handle_conn`) and the capture ingress
(`CoreIngress::dispatch_tcp`) attach their guard to every `ModuleCtx`
(`inner.guard` / `sd.guard`). `wire.rs` hands the passthrough module the proxy's
guard through the existing late-bound pattern (`LateGuard`, bound right after
`Proxy::build`, before serving), the same way Map Remote gets it.

### D3. Scope commands

Unchanged in signature, result shape and gate:

- `scope.add {host}` → `Str` (the entry). Refused from an agent frontend unless
  `scope.allow_agent_widen`, exactly as today (`caller_is_trusted_control`). Operator
  surfaces (operator-token connections, the CLI) widen freely, which is what the
  inline "Add to Scope" action calls. Validation unchanged (`host`, `host:port`,
  `*.wildcard`).
- `scope.remove {host}` → `Bool`. Not gated (narrowing). Note for the record: under
  this model removing a host **hides** its traffic (it becomes a passthrough), the
  same effect `tls.passthrough.add` has, which *is* agent-gated. Matt's brief keeps
  the gate unchanged; the command keeps its default `Sensitivity::Sensitive`, so under
  the `ask` agent policy an agent is asked and under `all` it is audited. Flagged in
  §Open questions as a decision for Matt, not changed here.
- `scope.list` → `[Str]`. Unchanged; the honesty fields live on `proxy.status` (D8).

The `scope.add` schema description and `summarize` text say what it now does:
"Add a host … to Scope. From now on new connections to it are decrypted; others are
tunnelled."

### D4. Plain HTTP to an out-of-scope host: observed, passive

Cleartext HTTP cannot be "not decrypted"; the request is on the wire in the clear
and the proxy must relay it. The rule (recommended in the brief, adopted here):

- The request **is captured** as a normal `http` flow (so the operator sees it and
  can add the host to Scope from the row).
- Nothing **acts** on it: no Rhai script hook, no intercept/breakpoint rule, no
  `flow.mutate`, no Map rule, no scanner passive check, no rate accounting. Only
  observers run: the subscription tap (so the row is pushed live).
- The flow is marked **passive**: `FlowMeta.passive = true`, emitted as `passive:
  true` on every surface (D7). A frontend renders it as out of scope / read-only.

Mechanism (Architect's call): the stamp is decided by the module that stores the
flow, the dispatch rule is enforced by the chain.

- `HttpModule` sets `passive = !ctx.in_scope(authority)` when it inserts a cleartext
  flow (per request: a keep-alive connection may carry requests for several hosts).
  Requests inside a tunnel inherit the tunnel's decision (in scope when the tunnel
  was admitted ⇒ `passive = false`), so "existing tunnels are left alone" holds for
  their inner requests too. h2 streams inherit from their connection the same way.
  `WsModule` copies `passive` from the handshake flow, as it already copies the
  capture attribution.
- `Plugin` gains `fn observes_passive_flows(&self) -> bool { false }`.
  `SubscriptionPlugin` returns `true`. Every other plugin keeps the default.
- `Chain::dispatch` looks at the flow it already cloned: if `metadata.passive` or
  `metadata.tunnel.is_some()` it dispatches **only** to plugins that observe passive
  flows and never parks. No extra store read, no guard in the chain.
- Captured (NE) flows are scope-gated before dispatch, so they stamp `passive =
  false` through the same predicate; nothing special-cases them.

Active commands on a passive flow are already refused by the guard where they reach
the network (`flow.replay`, `request.send` → `check_active` → `OutOfScope`).
`flow.mutate` needs an intercepted flow, which a passive flow never becomes. `ws.send`
on a passive WebSocket is left as a follow-up (non-goal).

### D5. Every CONNECT is a row

One shared helper in `aitm-core` (`tunnel` module) records tunnel rows so the two
producers (`PassthroughModule`, `HttpModule`) cannot drift:

```rust
pub enum TunnelMode { Decrypted, Passthrough, Failed }
pub enum TunnelReason {
    // passthrough
    OutOfScope, Pinned,
    // failed
    ClientRejectedCertificate, ClientClosed, ClientTlsError,
    UpstreamUnreachable, UpstreamTlsFailed, ProtocolError,
}
pub struct TunnelInfo {
    pub mode: TunnelMode,
    pub reason: Option<TunnelReason>,   // None for Decrypted
    pub bytes_up: Option<u64>,          // passthrough, set on close
    pub bytes_down: Option<u64>,
}
// FlowMeta gains: pub tunnel: Option<TunnelInfo>, pub passive: bool
```

- **Shape of the row**: `Flow::Http` with `request.method = "CONNECT"`, `scheme =
  "https"`, `authority = host:port` (normalised through `Authority`), `path = ""`,
  the CONNECT request headers, empty body; `kind` stays `http`. `client_conn` is the
  client peer (`tls: true` for a TLS tunnel), `server_conn` the resolved origin when
  one was dialled. `metadata.created` is the time the CONNECT head (or ClientHello)
  was read; `duration` is set exactly once, when the tunnel closes or fails.
- **When the row appears** (Architect's call: at the outcome, so there is no fourth
  "pending" value):
  - `decrypted`: after the client's TLS handshake with the proxy's leaf completes
    (`response = 200 Connection Established`, body empty). Its inner requests are
    their own rows as today. On connection close: `duration` set.
  - `passthrough`: after the origin was dialled and the acknowledgement written
    (`response = 200`). On close: `duration`, `bytes_up` (client→origin),
    `bytes_down` set. Byte counts are kept by a counting wrapper on the client
    stream so they survive a reset mid-relay. `reason` is `out_of_scope` or
    `pinned`.
  - `failed`: at the failure, `response = None` (the `200` the proxy may already
    have written is an acknowledgement, not an exchange outcome; status stays
    null), `duration` set, `reason` one of the failed codes.
  - A cleartext CONNECT (inner bytes not TLS) in scope is a `decrypted` row with
    `client_conn.tls = false`; rare (`curl -p`), documented, not special-cased.
- **Failure classification** is by type, never by message text, in one function
  next to the existing `is_benign_disconnect` logic:
  - `client_rejected_certificate`: the client-facing handshake ended with a received
    TLS alert in the certificate family (`BadCertificate`, `UnsupportedCertificate`,
    `CertificateRevoked`, `CertificateExpired`, `CertificateUnknown`, `UnknownCA`,
    `AccessDenied`, `BadCertificateStatusResponse`, `CertificateRequired`). This is
    the untrusted-CA case (Safari, curl without `--cacert`).
  - `client_closed`: EOF / reset / broken pipe before the tunnel was established
    (speculative pre-connects, a client that gave up).
  - `client_tls_error`: any other alert or TLS protocol error on the client side.
  - `upstream_unreachable`: DNS, refused, timed out, or any I/O failure dialling the
    origin.
  - `upstream_tls_failed`: the origin handshake failed or timed out.
  - `protocol_error`: anything else (malformed CONNECT head, h2-to-h1 mirror
    refusal, an authority the HTTP module cannot decrypt such as TLS without SNI).
- **Events**: the producer emits `Event::RequestHeaders(id)` when it inserts the row
  and `Event::Response(id)` when it closes or fails it. Both go through the chain's
  passive dispatch (D4), so the only consumer is the subscription tap: frontends get
  the row as a `created` push and its final state as a `response` push, with the
  tunnel fields in the summary. No intercept rule can park a CONNECT; no script sees
  it.
- **Terminal rule**: `MemFlowStore::is_terminal` treats a tunnel row as terminal
  iff `metadata.duration.is_some()` (closed or failed). An open tunnel is in flight:
  `flow.clear` keeps it (counted in `skipped_in_flight`), eviction skips it; it
  becomes clearable the moment it closes.
- **Logging**: a failed tunnel logs one `debug` line with the reason code and
  authority; nothing at `warn` (the benign-disconnect classification is unchanged).

### D6. The HTTP module's CONNECT path, step by step

```
read CONNECT head  →  created = now; authority = Authority(host, port|443)
  parse error                     → failed/protocol_error (reply nothing, close)
  !ctx.in_scope(authority)        → relay (D5 passthrough, reason out_of_scope)
  write "200 Connection Established"
  peek first byte
    EOF / reset                   → failed/client_closed
    not TLS                       → serve cleartext inside the tunnel; row decrypted (tls=false)
    TLS: read ClientHello, dial origin
      dial error                  → failed/upstream_unreachable
      origin handshake error      → failed/upstream_tls_failed
      h2 mirror refusal           → failed/protocol_error
      client handshake error      → failed/{client_rejected_certificate|client_closed|client_tls_error}
      ok                          → row decrypted (200); serve; on return: duration
```

Raw TLS (no CONNECT): the authority is `sni` + port rule of D1; `!in_scope` →
relay with the peeked bytes still in the stream (the `Prefixed` reader keeps them);
no SNI → `failed/protocol_error` as today's error, now with a row.

The passthrough module's path is the same list minus the TLS branch: parse →
dial → (dial error → `failed/upstream_unreachable`) → ack → row `passthrough` →
relay → close: bytes + duration.

### D7. Wire contract (every surface, same names)

New keys, all always present:

| key | `flow.table` row | `flow.get` / push summary | `flow.detail` | values |
|---|---|---|---|---|
| `tunnel` | yes | yes | `meta.tunnel.mode` | `"decrypted"` \| `"passthrough"` \| `"failed"` \| `null` (not a tunnel row) |
| `tunnel_reason` | yes | yes | `meta.tunnel.reason` | passthrough: `"out_of_scope"` \| `"pinned"`; failed: the six codes of D5; else `null` |
| `bytes_up` / `bytes_down` | yes | yes | `meta.tunnel.bytes_up/down` | int, passthrough on close; else `null` |
| `passive` | yes | yes | `meta.passive` | bool: observed only, nothing acted on it (D4) |

`flow.detail` renders `meta.tunnel` as an object `{mode, reason, bytes_up,
bytes_down}` or `null`, beside the existing `meta` keys. Existing keys keep their
meaning: `state`/`intercept` is still the interception lifecycle (`observed` for
every tunnel row), `status` is `200` for an established tunnel and `null` while
open-but-not-yet-established never occurs (rows appear at the outcome) or for a
failed one, `duration_ms` is `null` while a tunnel is open.

Schema descriptions (`row_fields`, `summary_fields`) and the plugin tool reference
document the keys. The `tunnelled` **mark** the old passthrough row carried is
retired: a mark is an operator annotation, the structured field is the fact. The two
tests that pinned the mark move to `tunnel == passthrough`.

### D8. Status, migration, release note

- `proxy.status` gains `decrypt`: `{ "scope_hosts": <entries in Scope>,
  "decrypting": <scope_hosts > 0>, "advice": <string|null> }`. `advice` is exactly
  `"Nothing is decrypted until a host is in Scope."` when `scope_hosts == 0`, else
  `null`. One sentence, one place; frontends print it, they do not compose it.
- At launch with an empty Scope the same sentence is said once: `aitm web` adds it
  as a line of its stdout startup summary (`web::startup_summary`); bare `aitm`,
  which prints no summary, logs it once at `info` on the `aitm` target (the curated
  default directive shows `info` for `aitm*` targets). Never repeated, never `warn`.
- **Behaviour change** (release note, verbatim for the release driver):

  > **Per-host decryption.** aitmproxy now decrypts only hosts in Scope, like
  > Proxyman's SSL Proxying list. Every other HTTPS connection is tunnelled
  > untouched, so an empty Scope decrypts nothing: add the hosts you are authorised
  > to inspect with `aitm scope add --host <host>` (or the Scope sheet). Every
  > CONNECT is now a row: `decrypted`, `passthrough` (with bytes and duration), or
  > `failed` with the reason, including "client rejected the proxy certificate",
  > the silent cause of empty captures on an untrusted CA. Plain HTTP to a host
  > outside Scope is still shown, marked passive: no script, breakpoint or map rule
  > touches it. `tls.passthrough` pins still win over Scope.

- Existing configs with `scope.entries` keep decrypting those hosts; configs with no
  entries change behaviour (nothing decrypted) by design. No config migration.
- `docs/design/languages/flow-kinds.json` (`http` descriptor, `list_cells.ssl`) is
  updated to derive the padlock from `tunnel`: open = decrypted or a decrypted
  tunnel's inner row, closed = `passthrough`, warning = `failed`; `passive` dims the
  row. The plugin docs (`aitmproxy-plugin/docs/tool-reference.md`,
  `aitmproxy-plugin/commands/scope.md`, the overview skill) say what Scope now means.

### D9. Frontend contract (TUI, web, mac — separate units)

What a row renderer needs and gets:

- Identify a tunnel row: `method == "CONNECT" && tunnel != null`. Render by `tunnel`:
  `decrypted` (open padlock, status 200), `passthrough` (closed padlock, bytes
  up/down, duration; "open" while `duration_ms == null`), `failed` (warning,
  `tunnel_reason` text).
- Offer **Add `<host>` to Scope** on a row when `tunnel == "passthrough" &&
  tunnel_reason == "out_of_scope"`, or when `passive == true`. `<host>` is the host
  part of `authority` (strip the port; `Authority` form is `host:port`, IPv6 in
  brackets). The action is `scope.add {host}` on the operator connection (trusted
  control, no gate); an agent surface goes through its existing confirm path. After
  it succeeds the surface says: new connections to `<host>` are decrypted; the
  existing tunnel stays as it is (the row does not change).
- Do not offer it when `tunnel_reason == "pinned"` (the host is pinned; the action is
  `tls.passthrough.remove`, agent-gated).
- Counts: a decrypted tunnel row and its inner rows share `authority`. Domain / app
  lists count **distinct hosts** (no double counting arises); request counters
  exclude rows with `tunnel != null`. Failed and passthrough rows are the only rows
  for their host, so they are what a Domains list shows for an undecrypted host.
- Honesty line: show `proxy.status.decrypt.advice` verbatim when non-null (Status
  page, first run, empty states), and `decrypting == false` as "nothing is decrypted".
- Pushes: a tunnel row arrives as `created` then `response`; `passive` rows as a
  normal flow lifecycle. Both carry the new keys in the summary.

## Acceptance criteria

1. **AC1 (empty Scope decrypts nothing).** Real core, empty Scope, `curl --cacert
   <aitm ca> -x <proxy> https://<origin>` fails to verify (the client saw the
   origin's own self-signed cert, not an aitm leaf) and `curl -k` succeeds with the
   origin's body; `flow.table` holds exactly one row for the origin: `method
   CONNECT`, `tunnel "passthrough"`, `tunnel_reason "out_of_scope"`, `status 200`,
   `bytes_up > 0`, `bytes_down > 0`, `duration_ms` not null after the client closed;
   no row for that authority has `tunnel == null`. [e2e + unit]
2. **AC2 (live flip on `scope.add`).** On the same running core, `scope.add
   <origin host>` over the operator bus, then the same `curl --cacert` succeeds
   (aitm leaf) and `flow.table` gains a `CONNECT` row with `tunnel "decrypted"`,
   `status 200`, plus a `GET` row for the path with `passive false`; the earlier
   passthrough row is unchanged. [e2e + unit]
3. **AC3 (live flip on `scope.remove`).** `scope.remove`, then the next connection
   is a `passthrough` row again and no new decrypted row appears. [e2e + unit]
4. **AC4 (existing tunnels are left alone).** A connection decrypted before
   `scope.remove` keeps serving decrypted requests (their rows have `passive false`)
   until it closes; a connection tunnelled before `scope.add` stays a tunnel. [unit,
   proto-http]
5. **AC5 (client rejects our CA).** In-scope host, `curl -x <proxy> https://…` with
   no `--cacert`: curl fails with a certificate error and `flow.table` holds a
   `CONNECT` row with `tunnel "failed"`, `tunnel_reason "client_rejected_certificate"`,
   `status null`, `duration_ms` not null. [e2e + unit]
6. **AC6 (other failures are rows).** Unit tests per code: `client_closed` (CONNECT
   then EOF), `upstream_unreachable` (dial refused), `upstream_tls_failed`,
   `protocol_error` (malformed CONNECT line); passthrough dial failure yields
   `failed/upstream_unreachable`, not a `passthrough` row. [unit]
7. **AC7 (pins win).** A host both in Scope and on `tls.passthrough` is a
   `passthrough` row with `tunnel_reason "pinned"`. [unit, passthrough crate]
8. **AC8 (matching).** Decryption decisions follow `Authority::matches_scope_entry`:
   `host` admits every port, `host:port` only that port, `*.suffix` the suffix and
   subdomains, case-insensitive; an IPv6 literal CONNECT authority is normalised.
   [unit]
9. **AC9 (plain HTTP out of scope is passive).** Real core, empty Scope, a breakpoint
   rule (`intercept.rule.add`) whose `url` names the plain-HTTP origin, intercept
   armed: `curl -x <proxy> http://<origin>/p` returns 200 **without** parking (the
   upstream record has the request immediately), the row has `passive true`,
   `proxy.status.paused == 0`; after `scope.add <origin>` the same request **is**
   parked (`state intercepted`, upstream record empty) until `flow.resume`, and its
   row has `passive false`. [e2e + unit]
10. **AC10 (passive dispatch).** `Chain::dispatch` on a flow with `passive = true` or
    `tunnel.is_some()` calls only plugins whose `observes_passive_flows()` is true,
    never parks, and the subscription tap still receives the event; a flow with
    neither runs every plugin as before. [unit, aitm-core]
11. **AC11 (every surface, same keys).** `flow.table` rows, `flow.get`, the push
    summary and `flow.detail` carry `tunnel`, `tunnel_reason`, `bytes_up`,
    `bytes_down`, `passive` with the values of D7 for a passthrough row, a decrypted
    row, a failed row, a passive row and an ordinary row;
    `push_summary_equals_flow_get_for_http_and_websocket_flows` still passes with
    the new keys; schema `row_fields`/`summary_fields` list them. [unit]
12. **AC12 (terminal rule).** An open passthrough row is kept by `flow.clear`
    (`skipped_in_flight` counts it) and by eviction; once closed or failed it is
    cleared. [unit, store]
13. **AC13 (status + advice).** `proxy.status.decrypt` is `{scope_hosts: 0,
    decrypting: false, advice: "Nothing is decrypted until a host is in Scope."}` on
    an empty Scope and `{scope_hosts: 1, decrypting: true, advice: null}` after
    `scope.add`; `aitm web`'s startup summary prints that sentence iff Scope is
    empty at launch and bare `aitm` logs it once at `info` under the same condition.
    [unit + e2e read-back]
14. **AC14 (deny-by-default seams).** A `ModuleCtx` without a scope guard reports
    `in_scope == false` for every authority; a `PassthroughModule` without a scope
    handle claims every TLS/CONNECT connection; the proxy acceptor and the capture
    ingress attach their guard (wire test + ingress test). [unit]
15. **AC15 (agent gate unchanged).** The existing `scope.add` gate tests
    (`scope_rate.rs`, `frontends.rs`, web/tui governance) pass untouched; no new
    command appears in `tools/list`. [existing tests]
16. **AC16 (no silent decrypt).** With the passthrough module **removed** from the
    module list, an out-of-scope CONNECT through `HttpModule` alone is still a
    `passthrough` row and the client sees the origin's certificate. [unit, proto-http]
17. **AC17 (docs).** `flow-kinds.json` validates (`node --test
    docs/design/languages/validate.test.mjs`); the plugin tool reference and scope
    command doc describe the new fields and model; the e2e proxy README lists the new
    cell. [gate + review]
18. **AC18 (gate).** `cargo fmt --check && cargo clippy --all-targets -- -D warnings
    && cargo test` green; the new e2e cell(s) pass on a real core from the Terminal.

## Left to the builder

- The exact byte-counting wrapper (a small `AsyncRead + AsyncWrite` adapter around
  the client stream) and whether `copy_bidirectional` or two `copy` halves drive the
  relay, as long as counts survive an error.
- Where the failure classifier lives (`aitm-core` next to `is_benign_disconnect` is
  the natural home; it already matches `rustls::Error` by type) and its exact
  signature, as long as it is one function with a unit test per code.
- Whether `NextLayerHint::tunnel_authority` or a free function; the port rule of D1
  is fixed.
- Test fixtures: the loopback TLS origin of `crates/aitm-plugin-passthrough/tests/tunnel.rs`
  may move to a shared test helper; the e2e cell reuses `aitm_e2e.tls` and the
  passthrough cell's origin.

## Open questions

Decided by the brief or the architect; nothing blocks implementation. For Matt, not
blocking: should `scope.remove` now share `tls.passthrough.add`'s agent gate, since
under this model it hides traffic? Kept **unchanged** per the brief ("the agent gate
for scope widening stays exactly as it is"); it remains `Sensitive` and audited.
