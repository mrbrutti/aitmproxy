# Scanner v2 track T6: L4 stream lane design

**Status:** Approved (T6 session, on Matt's autonomous-approval mandate, 2026-10-31; with amendments A1 self-port exclusion, A2 job state reachable by marker, A3 liveness `ok` closure, A4 HEAD e0464e0e, A5 `JobCtx::report_l4`, A6 grammar name `modbus`, A7 parser-fault definition, A8 T10 observers; applied by the Architect before the plan)
**Parent spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (approved; this child spec refines sections D1, D2, D5, D6, D8.4, D8.5, D11, D12 row T6, Verification, ACs T6-1..T6-5 and T10-1, Architect's calls 12, 13, 14, 20, 28; it may not contradict them and does not; one deliberate **refinement** of D8.5's wording is recorded: D8.5 says "a reproducible protocol-error-with-reset becomes `l4-parser-fault`"; T10's P mode and real servers answer a protocol error **and then close** while staying up, so this spec defines the parser fault as a close with **no** protocol-error token in the reply (A7, S6.1/S6.2, call 8), which keeps T6-4's "zero issues on P" satisfiable).
**Research inputs:** `docs/research/18-protocol-fuzzing.md`, `docs/research/20-scanner-v2-current-state.md` (§3.7, §3.9), `docs/research/08-l4-packet-rust.md`.
**Code the lane compiles against (read at worktree `scanner-v2-t6-e91bd9`, HEAD `e0464e0e` (T1a head merged with `main` v0.5.8)):** `crates/aitm-scan-model/src/{traits.rs, check.rs, point.rs, profile.rs, job.rs, issue.rs, vocab.rs, ids.rs}`; `crates/aitm-scan-l4-stream/{Cargo.toml, src/lib.rs}` (the `lane(guard, store) -> Option<Arc<dyn Lane>>` signature is final); `crates/aitm-proto-l4/src/{guard.rs, types.rs, flow.rs, craft.rs (PacketSummary), config.rs}`; `crates/aitm/src/wire.rs` `collect_lanes`; `crates/aitm-testtarget/src/l4.rs`.

## Intent

The umbrella spec gives the scanner an L4 **stream** lane: an unprivileged TCP/UDP socket client that takes messages a target already receives (captured L4 flows, operator seeds, or grammar-generated messages), parses them against a human-readable grammar, mutates them structure-first and byte-second, and watches the target through a liveness oracle so that a crash is found, reproduced a bounded number of times, recorded with everything needed to replay it, and then left alone. This document decides everything a builder would otherwise have to guess: the `MessageSpec` grammar format and its eight grammars, the exact way the lane implements the T1a `Lane`/`ProbeHost`/`Check` contract, the mutators and their naming, the liveness/reproduction/retirement state machine, dry run, the hard ceilings, and how each acceptance criterion is observed on a real run against T10's speakers.

## Goals

- `aitm_scan_l4_stream::lane(guard, store)` returns `Some` for every build; `discover` yields one `l4_field` insertion point per (endpoint, seed, mutable field) and one `SiteNode` per endpoint; `probe_host_for` returns a host that sends exactly one rendered message per `probe`, each authorised by `L4Guard::check` and `L4Permit::authorize_packet`, paced in bytes/s, and charged to the job budget.
- Eight grammars (TLV-inferred, RESP, Memcached text, DNS, Modbus/TCP, MQTT 3.1.1, SMTP, FTP) shipped as YAML files that read as prose, embedded with `include_str!`, each with `parse`, `generate`, `classify_reply`, `liveness_probe`, a rule set in the shared `denylist` and (where needed) a stateful prelude.
- The generic TLV grammar infers its length relation from the seed set and refuses to guess when the set does not pin one down.
- Three native checks (`l4-crash`, `l4-parser-fault`, `l4-latency-outlier`) share one deterministic, seedable mutation campaign per point, so a point is fuzzed once and each class gets its own correctly-classed, correctly-severitied issue.
- A crash is reported only after silence/reset plus two failed liveness probes, reproduced `reproduce_count` times; then the point is retired and never hit again in that job.
- Dry run renders every case and opens no socket.
- Nothing destructive is ever sent: the per-grammar denylist is checked on the rendered bytes of every message, is on for every profile, and has no off switch.
- Acceptance is a real run against T10's speakers over the real bus (ACs T6-1..T6-5), observed through the speakers' own logs.

## Non-goals

- TCP stream reassembly beyond "one captured packet payload = one message" (umbrella D8.5). A message split across segments in a capture is two seeds; the generic TLV inference tolerates that by refusing to infer when lengths do not fit.
- MQTT 5 (properties block), the memcached **binary** protocol, DNS over TCP (the 2-byte length prefix), SMTP `DATA`/`BDAT` bodies, FTP data channels, RESP3 streamed types. Each is a later grammar or grammar extension.
- Connection reuse across cases, pipelining as a transport strategy, or any session-state inference (AFLNet-style). Every case runs on a fresh connection after a constant prelude.
- Coverage feedback, corpus evolution, or minimisation (`afl-tmin`). The schedule is fixed and deterministic.
- Any change outside `crates/aitm-scan-l4-stream/**`. In particular: no `aitm-scan-model` edit (counter reporting to `JobStatus.l4` is requested from T1b in "Left to T1b", below), no `aitm-proto-l4` helper (the frame payload extractor is hand-rolled inside this crate), no root manifest edit.
- Issue `description`/`remediation` text beyond one factual sentence each.

## Anti-goals

- A single byte reaching a destination the L4 guard did not authorise, including the liveness probe, the prelude and the reproduction replays.
- Sending a denylisted command under any configuration: not via a seed, not via a mutation that happens to render one, not via a prelude, not via `baseline()`.
- Replaying or recording credentials seen in captured traffic (RESP `AUTH`, FTP `PASS`, SMTP `AUTH`, MQTT `CONNECT` username/password).
- Hammering a target that stopped answering: after a finding the point is retired; after `consecutive_timeouts` silent cases the host refuses further probes; a liveness failure without a recovery within the recovery window ends the campaign.
- A log line, `Debug` output, push line or issue that carries the bytes of a sent message other than the bounded `sent_hex` in `L4Evidence` and the bounded hex in `InsertionPoint.example`.
- A profile, config key or confirmation that lifts a ceiling or the denylist.
- Fixture-driven acceptance: unit tests against in-process listeners are the inner loop and are labelled so; no AC is satisfied by them.

## Constraints

- `#![forbid(unsafe_code)]`; `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` green; default `cargo test -p aitm-scan-l4-stream` binds **loopback ephemeral ports only** for its in-process listeners and is hermetic (no external host; skipped tests announce themselves when the sandbox refuses to bind).
- **Dependencies** are limited to what `[workspace.dependencies]` already declares: `anyhow`, `futures`, `tokio` (features `net`, `io-util`, `time`, `sync`, `macros`, `rt`), `tracing`, `serde`, `serde_json`, `serde_yaml`, `bytes`, `hickory-proto`, `rand`, `rand_chacha`, `tokio-util`, `uuid`, `aitm-core`, `aitm-proto-l4`, `aitm-scan-model`, `aitm-poc` (`CheckMeta.severity` is an `aitm_poc::Severity`, which the model crate does not re-export). **No** `nom`, `libafl`, `lain`, `hex`, `base64`, `etherparse`, `blake3`. Hex and base64 decoding, FNV-1a hashing, CRC-32 and the IPv4/TCP/UDP header skipper are hand-rolled in this crate.
- **Files** only under `crates/aitm-scan-l4-stream/**` (umbrella D12). Grammars live in `crates/aitm-scan-l4-stream/grammars/<name>.yaml` and are embedded with `include_str!`; the lane never reads grammar files at runtime.
- No `unwrap`/`expect` on any path that touches network bytes, captured flows, seeds or YAML authored outside the crate; `expect` is allowed only on the eight embedded grammars at lane construction (a malformed embedded grammar is a build defect caught by C1) and in tests.
- `Debug` on every in-process type that holds message bytes (`Tree`, `Node`, `Case`, `Campaign`, `StreamHost`, `JobState`) prints lengths, never contents, following `point.rs`'s pattern. No `tracing` line prints message bytes; log lines carry counts, paths, oracle names and durations.
- Every redaction of text excerpts goes through `aitm_core::redact::scrub_text` (the crate's public function at HEAD); field names are tested with `aitm_core::redact::is_secret_key`.
- The lane is one `Arc<dyn Lane>` shared by every job in the process; all per-job state is keyed by `JobCtx::job_id()` and bounded.
- Authorisation vocabulary is the L4 guard's (umbrella call 12): the lane needs `l4.enabled`, an L4 scope entry with the `Inject` capability, `direction: outbound`, `interface: "*"` (the T1a wildcard; a target whose interface is literally `"*"` matches no literal entry, by design), a CIDR and port range covering the target and `inject_rate.pps > 0`. A loopback target (the test target) additionally needs that entry to be **config-declared** and contained within `127.0.0.0/8` (or `dangerous_dst_override`), because loopback is on the guard's dangerous-destination denylist; the config reference wording is T1b's (D11), this spec only states the requirement so the e2e cells configure it.
- **Self-port exclusion (A1).** At `e0464e0e` `L4Guard` carries the core's own listener ports (`set_self_ports`, `add_self_ports`, `self_ports() -> Vec<u16>`; `admit_endpoints` refuses loopback frames touching them, so a capture never records the bus token line). The lane applies the same rule to its own stimuli: a target whose `dst` is a loopback address and whose `dst_port` is in `guard.self_ports()` is refused with `scan: out_of_scope: <ip>:<port> is one of the core's own listener ports`, at discovery and again before every connect (the set grows at runtime as listeners bind), and no socket is opened. A non-loopback `dst` on such a port is not refused by this rule. The other `e0464e0e` guard change the lane must respect is already covered: per-write metering is `L4Permit::authorize_packet(len)` (S5.4); `admit_endpoints` itself is a capture-side predicate and the lane does not call it.

## Design

Section numbers below are this spec's (`S1`..`S9`); umbrella sections are cited as `D8.5` etc.

### S1. Crate layout

**(Architect's call)** Module tree of `crates/aitm-scan-l4-stream/src/`, fixed so plan tasks own disjoint files:

| Module | Owns |
|---|---|
| `lib.rs` | `lane()`, `L4StreamLane` (the `Lane` impl), re-exports |
| `spec.rs` | `MessageSpec`, `FieldSpec`, `FieldKind`, `Relation`, YAML (de)serialisation, validation |
| `tree.rs` | `Tree`, `Node`, `FieldPath`, `parse(spec, bytes)`, `render(tree)`, relation re-satisfaction |
| `grammar.rs` | the `Grammar` trait, `GrammarKind`, `select_grammar`, the registry of eight |
| `grammars/<name>.rs` | one file per grammar: `tlv.rs`, `resp.rs`, `memcached.rs`, `dns.rs`, `modbus.rs`, `mqtt.rs`, `smtp.rs`, `ftp.rs` (each embeds `../../grammars/<name>.yaml`) |
| `infer.rs` | TLV length-relation inference |
| `corpus.rs` | seeds from flows / profile / generation, the credential filter, hex and base64 decoding, point and node construction |
| `frame.rs` | the hand-rolled frame payload extractor over captured `L4Packet.bytes` |
| `mutate/bytes.rs` | the 25 byte-level mutators |
| `mutate/structure.rs` | the structure-aware mutators |
| `mutate/schedule.rs` | `Schedule`, `Case`, chain naming, determinism |
| `denylist.rs` | per-grammar denylist, pure, no configuration input |
| `client.rs` | `StreamClient` trait, `TokioStreamClient`, bounded reads, timeouts |
| `host.rs` | `StreamHost` (`ProbeHost` impl), the probe sequence, liveness, `HostError` |
| `state.rs` | `LaneState` (per-process), `JobState` (per job), pacer, semaphore, latency window, retirement |
| `checks.rs` | the three `Check` impls and the shared `Campaign` |
| `oracle.rs` | `ReplyClass`, oracle decision table, latency outlier rule |
| `tests/` (integration) | in-process speakers (labelled inner loop) |

### S2. The `MessageSpec` grammar format

A grammar is a YAML document that reads top to bottom as a description of one message. It is boofuzz's shape (D8.5): typed fields, and relations that name other fields instead of holding a value.

**YAML keys (fixed).** Top level: `grammar` (name), `transport` (`tcp`|`udp`), `default_ports` (list), `close_on_malformed_is_expected` (bool, default `false`; `true` for MQTT, where the spec mandates closing), `reply` (free prose, ignored by the parser, kept so the file explains itself), `message` (the ordered field list). Each field: `name`; `type`; optional `value` (the generated default; a hex string `0x..`, a quoted string, or an integer), `one_of` (allowed values; the generator picks from it, the type-substitution mutator cycles through it), `range: [lo, hi]` (integers), `terminator` (for `line`/`cstring`: `"\r\n"`, `"\n"`, `"\0"`), `mutable: false` (a field no mutator touches: transaction ids, protocol ids, magic bytes, and an optional separator's `absent` alternative), `secret: true` (its example is `<redacted>` and its bytes never enter `sent_hex`-adjacent excerpts; the whole message is still fuzzable), `len`, `count`, `checksum`, `fields` (children of `group`, `repeat`, `choice`), `count_from` (on a `repeat`: names the **count field** that holds its element count, `count_from: count`, `count_from: qdcount`; that field may sit anywhere declared earlier in the document, inside `header` for instance, and must carry `count: { of: <this repeat> }`, which validation checks; a `repeat` without `count_from` has `until: end` or `until: terminator`).

Types: `bytes` (rest or fixed `size`), `u8`, `u16 be`, `u16 le`, `u32 be`, `u32 le`, `varint` (MQTT 7-bit continuation), `decimal` (ASCII digits, optionally signed: RESP/memcached lengths), `cstring`, `line` (bytes up to the terminator, which belongs to the field), `token` (a word from `one_of`, ASCII, case-insensitive on parse), `delim` (a fixed separator, `value` required), `group`, `repeat`, `choice` (the first child whose parse succeeds).

Relations: `len: { of: [names] | rest, inclusive: bool (default false), adjust: int (default 0) }` (width and endianness come from the field's own type; `of: rest` means every byte after this field), `count: { of: name }` (the number of elements of the named `repeat`), `checksum: { algo: crc32 | internet, over: [names] }` (none of the eight grammars needs one; it exists so the mutator vocabulary is complete and so a later grammar does not change the format).

**Field paths.** A path names a node in the parsed tree: dotted for `group` members and `[i]` for `repeat` elements: `header.length`, `args[1]`, `args[1].data`, `questions[0].name.labels[2].len`. `InsertionPoint.path`, `L4Location.field_path` and every `mutation_chain` entry use exactly this form. The `name` of a point is the last path component (`length`, `data`, `len`).

**Rust sketch (names and fields only):**

```rust
pub struct MessageSpec { pub grammar: String, pub transport: Transport, pub default_ports: Vec<u16>,
    pub close_on_malformed_is_expected: bool, pub reply: Option<String>, pub message: Vec<FieldSpec> }
pub enum Transport { Tcp, Udp }
pub struct FieldSpec { pub name: String, pub kind: FieldKind, pub value: Option<Literal>, pub one_of: Vec<Literal>,
    pub range: Option<(i64, i64)>, pub terminator: Option<Vec<u8>>, pub mutable: bool, pub secret: bool,
    pub relation: Option<Relation>, pub fields: Vec<FieldSpec>, pub count_from: Option<String>, pub until: Option<Until> }
pub enum FieldKind { Bytes { size: Option<usize> }, U8, U16 { endian: Endian }, U32 { endian: Endian }, Varint,
    Decimal, CString, Line, Token, Delim, Group, Repeat, Choice }
pub enum Endian { Be, Le }
pub enum Literal { Int(i64), Text(String), Hex(Vec<u8>) }
pub enum Relation { Len { of: LenOf, inclusive: bool, adjust: i32 }, Count { of: String }, Checksum { algo: ChecksumAlgo, over: Vec<String> } }
pub enum LenOf { Fields(Vec<String>), Rest }
pub enum ChecksumAlgo { Crc32, Internet }
pub enum Until { End, Terminator }

pub struct FieldPath(String);
pub struct Tree { pub grammar: String, pub root: Vec<Node> }
pub struct Node { pub path: FieldPath, pub kind: FieldKind, pub bytes: Vec<u8>, pub children: Vec<Node>,
    pub relation: Option<Relation>, pub mutable: bool, pub secret: bool }
pub fn parse(spec: &MessageSpec, bytes: &[u8]) -> Option<Tree>;
pub fn render(tree: &Tree) -> Vec<u8>;
pub fn resatisfy(tree: &mut Tree, except: Option<&FieldPath>);
```

`parse` is total over the spec: a `len` relation is read, not trusted (the parser slices by the declared length only when it fits the buffer, otherwise the field takes the rest and the tree records `relation_broken: true` on that node so the mutators know the seed was already desynced); `render` concatenates leaf bytes in order; `resatisfy` recomputes every `len`, `count` and `checksum` node from its targets except the one named (the mutation that targets a relation keeps its deliberately wrong value).

**One short example** (`grammars/modbus.yaml`, abridged):

```yaml
grammar: modbus
transport: tcp
default_ports: [502]
reply: >
  The server answers with the same transaction id; a function code with the
  high bit set is an exception and carries one exception-code byte.
message:
  - name: header
    type: group
    fields:
      - { name: transaction_id, type: u16 be, mutable: false }
      - { name: protocol_id, type: u16 be, value: 0 }
      - { name: length, type: u16 be, len: { of: [unit_id, pdu] } }
      - { name: unit_id, type: u8, value: 1 }
  - name: pdu
    type: group
    fields:
      - { name: function, type: u8, value: 3, one_of: [1, 2, 3, 4, 5, 6, 8, 15, 16] }
      - { name: address, type: u16 be, value: 0 }
      - { name: quantity, type: u16 be, range: [1, 125], value: 1 }
```

Points from this seed: `header.protocol_id`, `header.length`, `header.unit_id`, `pdu.function`, `pdu.address`, `pdu.quantity` (not `header.transaction_id`, which is `mutable: false`). `pdu.function`'s `one_of` is the real function-code vocabulary, so `type_subst` is seen to refuse the write codes; `generate` filters the list through the denylist and only ever emits 1-4.

**Validation at load** (`MessageSpec::validate`): unique names per level; every `len.of`/`count.of`/`checksum.over` names a sibling or `rest`; `delim` has a `value`; `token` has `one_of`; `repeat` has `count_from` (naming a declared field that carries `count: { of: <the repeat> }`) or `until`; `decimal`/`varint` carry `len`/`count` only (no checksum); at most 8 nesting levels; a field tree of at most 256 fields. Validation errors name the field.

### S3. The `Grammar` trait, selection, and the eight grammars

```rust
pub trait Grammar: Send + Sync {
    fn kind(&self) -> GrammarKind;
    fn name(&self) -> &'static str;
    fn spec(&self) -> &MessageSpec;
    fn specs(&self) -> Vec<&MessageSpec>;              // default vec![self.spec()]
    fn default_ports(&self) -> &'static [u16];
    fn transport(&self) -> Transport;
    fn parse(&self, bytes: &[u8]) -> Option<Tree>;
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8>;
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass;
    fn reply_complete(&self, buf: &[u8]) -> bool;
    fn liveness_probe(&self) -> Exchange;
    fn prelude(&self) -> Vec<Vec<u8>>;
    fn prelude_for(&self, case: &[u8]) -> Vec<Vec<u8>>; // default self.prelude()
    fn expects_banner(&self) -> bool;                   // default false
    fn is_credential_message(&self, bytes: &[u8]) -> bool;
}
pub enum ReplyClass { Ok, ProtocolError, Unknown }
pub struct Exchange { pub send: Vec<u8>, pub expect: Expect, pub after: Option<Vec<u8>> }
pub enum Expect { Prefix(Vec<u8>), SameIdAt { offset: usize, width: usize }, AnyReply, ReplyOrOpen, DnsSameId }
impl Exchange { pub fn matches(&self, reply: &[u8], ended: Ended) -> bool; }   // `Ended` is client.rs's, re-exported by grammar.rs
pub enum GrammarKind { Tlv, Resp, Memcached, Dns, Modbus, Mqtt, Smtp, Ftp, Raw }
pub fn select_grammar(target: &L4TargetSpec, corpus: &[Seed]) -> Selected;
pub struct Selected { pub grammar: Arc<dyn Grammar>, pub reason: SelectionReason }
pub enum SelectionReason { Named, DefaultPort(u16), Inferred(LenDescriptor), RawFallback(String) }
```

The denylist is not a trait method: it is the free function `denylist::refuses(GrammarKind, &[u8])` ("Denylist semantics", below), so no grammar can carry its own weaker list. `specs()` exists because a grammar file may hold a **second YAML document** after a `---` line for an alternative wire form of the same message; `parse` tries the documents in order (RESP's inline form and memcached's storage form use it). `prelude_for` lets a grammar vary the prelude per case (MQTT: a CONNECT case goes alone), `expects_banner` makes the host read the server's greeting before writing (SMTP, FTP), and `Exchange.after` is a best-effort message written after the liveness reply (MQTT DISCONNECT, a line protocol's `QUIT`). `Ended` is defined in `client.rs` and re-exported by `grammar.rs`. The default-bodied `strip_credentials` and `close_on_malformed_is_expected` (plan Task 7) complete the trait.

**Selection** (D8.5): (1) `L4TargetSpec.grammar` when named (`tlv`, `resp`, `memcached`, `dns`, `modbus` (alias `modbus-tcp` accepted by `select_grammar`, A6), `mqtt`, `smtp`, `ftp`, `raw`; an unknown name makes `discover` fail with `scan: invalid_profile: unknown grammar '<x>'; known: ...`; a grammar whose `transport` disagrees with `L4TargetSpec.proto` fails the same way); naming `tlv` or `raw` names a *family*, not a fixed grammar: a named `tlv` runs step (3) over the corpus and falls to step (4) on a refusal, and a named `raw` is built over the corpus so its liveness probe replays a seed (fix F6; neither is ever refused for its transport); (2) else by default port (`6379` resp, `11211` memcached, `53/udp` dns, `502` modbus, `1883` mqtt, `25`/`587` smtp, `21` ftp); (3) else TLV inference over the corpus (S4); (4) else `raw`: one `bytes` field named `message`, byte-level mutators only. For (2), if **no** seed of the corpus parses under the port's grammar, the lane falls to (3) and records `SelectionReason` in the node's `path_template` suffix (`/resp` becomes `/tlv` or `/raw`) and in every verdict `detail`. **(Architect's call)**: the corpus decides over the port because a port is a convention and a seed is evidence.

**Liveness expectation (A3).** `Exchange::matches` evaluates a stored `Expect` against the reply, so an expectation can refer to the sent bytes without a capturing closure: `Prefix(b"+PONG")` (RESP), `Prefix(b"VERSION ")` (memcached), `Prefix(b"250")`/`Prefix(b"200")` (SMTP/FTP `NOOP`), `SameIdAt { offset: 0, width: 2 }` (Modbus transaction id and MQTT CONNACK are checked by type byte `0x20` via `Prefix`; Modbus compares `reply[0..2] == send[0..2]`), `DnsSameId` (hickory parses the reply and its id equals the query's), `AnyReply` (UDP TLV), `ReplyOrOpen` (TCP TLV: any byte, or `Ended::Silence` with the connection still open at 500 ms). **(Architect's call)**: an enum over stored bytes rather than a boxed closure, so `Exchange` stays `Clone + Debug` (byte lengths only) and testable by value.

**Reply reading** uses `reply_complete` to stop early: line grammars stop at the final line (SMTP/FTP: a line whose fourth byte is a space; RESP: a complete frame by its own length/CRLF rules; memcached: `\r\n` after a complete response, `END\r\n` for retrievals), binary grammars stop at the declared frame length (Modbus MBAP, MQTT remaining length, DNS datagram = one read), TLV/raw stop at the first read. Otherwise the read ends at the 64 KiB bound, EOF, or the 2 s timeout.

**Delivery order** is the umbrella's (call 13): TLV, RESP, Memcached, DNS, Modbus/TCP, MQTT, SMTP, FTP. The table fixes each grammar.

| # | Grammar (`name`, transport, ports) | Wire shape as `MessageSpec` (field names are the paths) | `liveness_probe()` and what is ok | `classify_reply` | Denylist (D8.5 is the floor) | Prelude; data channel |
|---|---|---|---|---|---|---|
| 1 | `tlv`, tcp or udp (the target's), no default port | Built by inference (S4): `length` (`u8`/`u16 be|le`/`u32 be|le`, `len { of: rest | [payload], inclusive, adjust }`) preceded by `prefix` (`bytes`, `size: offset`, `mutable: false`) when `offset > 0`, followed by `payload` (`bytes`) | Send the shortest seed unmutated; ok when any reply byte arrives **or** the connection is still open (no EOF/RST) 500 ms after the send (a TLV service that never replies is still alive). UDP: ok only when a reply arrives | any bytes: `Ok`; nothing: `Unknown` | none (no command vocabulary; stated explicitly) | none; n/a |
| 2 | `resp`, tcp, 6379 | `array` group: `star` delim `*`, `count` decimal `count { of: args }`, `crlf` delim; `args` repeat `count_from: count` of group { `dollar` delim `$`, `len` decimal `len { of: [data] }`, `crlf`, `data` bytes, `crlf` }. Inline commands (no leading `*`) parse as the file's second document: one `inline` line | `PING\r\n`; ok when the reply starts with `+PONG` | first byte `+ $ : * _ # , ( ! = % ~ >`: `Ok`; `-`: `ProtocolError`; else `Unknown` | `FLUSHALL FLUSHDB SHUTDOWN CONFIG DEBUG SAVE BGSAVE BGREWRITEAOF SLAVEOF REPLICAOF MIGRATE RESTORE SCRIPT EVAL EVALSHA FUNCTION FCALL ACL CLUSTER FAILOVER MODULE SYNC PSYNC SWAPDB DEL UNLINK RENAME RENAMENX MONITOR CLIENT KILL` | none; n/a. Credential filter: `AUTH`, `HELLO` with `AUTH` |
| 3 | `memcached`, tcp, 11211 | `line` group: `cmd` token one_of `get gets set add replace append prepend cas incr decr delete touch gat gats stats version verbosity`, `sp` delim, `key` line (terminator CRLF); the storage form (`cmd` from the six storage verbs, `sp`, `key` line with terminator space, then `storage` group { `flags` decimal, `sp1`, `exptime` decimal, `sp2`, `bytes` decimal `len { of: [data] }`, `crlf`, `data` bytes, `crlf2` }) is the file's second document | `version\r\n`; ok when the reply starts with `VERSION ` | `ERROR`, `CLIENT_ERROR`, `SERVER_ERROR`: `ProtocolError`; `STORED NOT_STORED EXISTS NOT_FOUND VALUE END DELETED TOUCHED VERSION OK STAT` or digits: `Ok`; else `Unknown` | `flush_all shutdown slabs lru lru_crawler cache_memlimit watch verbosity misbehave` (and `me`/`mn` meta debug) | none; n/a |
| 4 | `dns`, udp, 53 | `header` group { `id` u16 be `mutable: false`, `flags` u16 be, `qdcount` u16 be `count { of: questions }`, `ancount`, `nscount`, `arcount` u16 be }; `questions` repeat `count_from: qdcount` of group { `name` group: `labels` repeat `until: terminator` of group { `len` u8 `len { of: [text] }`, `text` bytes }, `root` u8 value 0 }, `qtype` u16 be, `qclass` u16 be }; trailing `rest` bytes. The DNS `MessageSpec` produces the tree (hickory has no byte offsets); `hickory_proto::op::Message::from_vec` is the validator for `parse` (a seed hickory refuses is not a DNS seed), the builder for `generate` (a well-formed `A` query for a generated name) and the reader for `classify_reply` (RCODE) | An `A` query for `.` with a fresh id (T10 answers A `127.0.0.1`; a non-A qtype gets NotImp); ok when a reply with the same id arrives (any RCODE) | hickory parses and RCODE is `NoError`/`NXDomain`: `Ok`; `FormErr ServFail NotImp Refused`: `ProtocolError`; parse fails: `Unknown` | opcode `UPDATE` (5) and `NOTIFY` (4); qtype `AXFR` (252) and `IXFR` (251) | none; n/a |
| 5 | `modbus`, tcp, 502 | S2's example | FC 3, address 0, quantity 1, unit 1; ok when a reply with the same transaction id arrives (an exception reply is also alive) | 7+ bytes and FC < 0x80: `Ok`; FC with 0x80 set: `ProtocolError`; shorter: `Unknown` | function codes `5 6 8 15 16 21 22 23` (write single coil/register, diagnostics, write multiple, write file record, mask write, read/write multiple) | none; n/a |
| 6 | `mqtt`, tcp, 1883 | `fixed` group { `type_flags` u8 (type nibble `one_of` 1 3 8 10 12 14; flags nibble), `remaining_length` varint `len { of: rest }` }; `variable` choice by type: CONNECT { `proto_name` group (u16 be len + `MQTT`), `level` u8 value 4, `connect_flags` u8, `keepalive` u16 be, `client_id` group (u16 be `len` + `text`), optional will/user/password groups per flags (`secret: true` on `password`) }, PUBLISH { `topic` group (len + text), `packet_id` u16 be when QoS > 0, `payload` bytes }, SUBSCRIBE { `packet_id`, `topics` repeat of (len + text + qos u8) }, PINGREQ/DISCONNECT (empty) | CONNECT (client id `aitm-scan-<4 hex>`, clean session, keepalive 60, no will, no credentials), expect CONNACK; then DISCONNECT; ok when CONNACK arrives (any return code) | CONNACK rc 0, SUBACK without 0x80, PUBACK, PUBREC, PINGRESP: `Ok`; CONNACK rc 1-5, SUBACK 0x80, **peer close** (`close_on_malformed_is_expected: true`): `ProtocolError`; else `Unknown` | PUBLISH with the retain bit; PUBLISH to a topic starting `$`; CONNECT with will-retain | CONNECT (the liveness CONNECT) unless the case is itself a CONNECT, which goes on a fresh connection alone; n/a. Credential filter: CONNECT with username or password flag (the seed is kept with the flags cleared and the fields removed) |
| 7 | `smtp`, tcp, 25 and 587 | `command` group { `verb` token one_of `EHLO HELO MAIL RCPT NOOP RSET VRFY EXPN HELP QUIT STARTTLS`, `sp` choice { `present`: a mutable `delim " "`; `absent`: an immutable zero-size `bytes` } (paths `command.sp.present`/`command.sp.absent`; `NOOP` has no argument), `arg` line terminator CRLF } | Read the 220 banner; `NOOP\r\n`; ok when `250` comes back; then `QUIT` best-effort | three-digit code 2xx/3xx: `Ok`; 4xx/5xx: `ProtocolError`; else `Unknown`; multi-line replies (`250-`) are read to the final `250 ` line | `DATA BDAT ETRN TURN ATRN`; `RCPT` unless the address's domain is the target's IP as an address literal (`[127.0.0.1]`), `localhost`, or the hostname announced in the 220 banner; `AUTH` (credential filter, and never sent) | read 220, `EHLO aitm.scan.invalid\r\n`, read 250 (two prior messages); DATA is never sent, so no body is ever opened |
| 8 | `ftp`, tcp, 21 | `command` group { `verb` token one_of `USER PASS NOOP SYST FEAT PWD CWD CDUP TYPE MODE STRU STAT HELP QUIT REIN ABOR ALLO REST SIZE MDTM`, `sp` choice (`present`/`absent`, as SMTP), `arg` line CRLF } | Read 220; `NOOP\r\n`; ok on `200`; `QUIT` | as SMTP | `DELE STOR STOU APPE RMD RNFR RNTO MKD SITE PORT EPRT PASV EPSV RETR LIST NLST MLSD MLST`; anything that opens a data channel or makes the server connect out is refused | read 220, `USER anonymous\r\n` (331 or 230), `PASS aitm@scan.invalid\r\n` (230 or 530; a 530 is recorded in `detail` and the campaign runs unauthenticated); the data channel is never opened. Credential filter: captured `USER`/`PASS` lines are dropped from the corpus |

**Denylist semantics (all grammars).** `Denylist::refuses(grammar, rendered: &[u8]) -> Option<&'static str>` is a pure function of the grammar and the rendered bytes of the message about to be written (prelude messages included, each checked). Text grammars match **case-insensitively at token boundaries** over the whole rendered buffer, so a pipelined or element-repeated message with one bad command is refused as a whole; RESP additionally checks the first bulk string of every array. Binary grammars decode the command field (`pdu.function`, `fixed.type_flags`, DNS opcode/qtype) from the rendered bytes, not from the tree, so a byte-level mutation that lands on a denylisted value is caught. Over-blocking (a memcached key containing `flush_all`) is accepted. A refused case is **skipped and counted** (`skipped_denylisted` in `JobState` and in every verdict `detail`), never sent, never retried. There is no field, flag, profile key, config key or confirmation that reaches this function (C4 proves it by construction: its signature has no such parameter and `host.rs` calls it unconditionally before every write).

**Credential filter.** `is_credential_message` drops a seed from the corpus before parsing (RESP `AUTH`/`HELLO ... AUTH`, SMTP `AUTH`, FTP `USER`/`PASS`) or strips it (MQTT CONNECT credentials). Dropped seeds are counted in `discover`'s tracing line as `seeds_dropped_credential: n` and never appear in a point, an example, a `sent_hex` or a log.

### S4. Generic TLV: length-relation inference

```rust
pub struct LenDescriptor { pub offset: usize, pub width: u8 /* 1|2|4 */, pub endian: Endian,
    pub counts: Counts, pub adjust: i32 /* -4..=4 */ }
pub enum Counts { BodyOnly, Inclusive, Whole }
pub fn infer(seeds: &[Vec<u8>]) -> Result<LenDescriptor, InferRefusal>;
pub enum InferRefusal { TooFewSeeds, SameLength, NoCandidateFits, Ambiguous(Vec<LenDescriptor>) }
```

Semantics of `counts`, for a message of `L` bytes with the length field at `offset..offset+width` reading `v`: `BodyOnly`: `v + adjust == L - (offset + width)` (the bytes after the field); `Inclusive`: `v + adjust == L - offset` (the field and everything after it; boofuzz `inclusive`); `Whole`: `v + adjust == L`. (The brief's `header_only` is `Inclusive` here; the name says what it counts.)

Candidates: `offset` in `0..=8`, `width` in `{1, 2, 4}` (`endian` `Be` only for width 1, else both), every `counts`, `adjust` in `-4..=4`, subject to `offset + width <= min seed length`. Keep every candidate that fits **every** seed. Requirements: at least 2 seeds **and** at least 2 distinct lengths (`TooFewSeeds`/`SameLength`), otherwise any constant fits and the lane must not guess. Among fitting candidates choose by, in order: smallest `|adjust|`, `counts` order `BodyOnly < Inclusive < Whole`, `width` order `2 < 4 < 1`, `Be` before `Le`, smallest `offset`. If, after that ordering, two candidates still tie on every key the result is `Ambiguous` (it cannot happen with distinct `(offset, width, endian)`, but the enum exists so the refusal is explicit). On refusal the lane falls to `raw` and names the reason in the node's `path_template` (`/raw`) and in verdict `detail` (`tlv inference refused: same_length`).

The inferred grammar is rendered as a `MessageSpec` (`prefix` when `offset > 0`, `length`, `payload`), so its field paths are `prefix`, `length`, `payload` and the same mutators apply as to a hand-written grammar. C2 pins `{offset 0, width 2, be, body_only, adjust 0}` for the seed set `[00 02 aa bb]`, `[00 05 01 02 03 04 05]`, `[00 01 ff]`, and a refusal for `[00 02 aa bb]`, `[00 09 01 02 03 04 05]` (`NoCandidateFits`; the same-length pair `[00 02 aa bb]`, `[00 09 01 02]` is `SameLength`, refused before any candidate is tried) and for `[00 02 aa bb]` alone (`TooFewSeeds`).

### S5. Lane mechanics against the T1a contract

#### S5.1 `lane()` and the shared state

`lane(guard, store)` always returns `Some(Arc::new(L4StreamLane { guard, store, grammars, state: LaneState }))`. `LaneState { jobs: Mutex<HashMap<JobId, Arc<JobState>>>, by_marker: Mutex<HashMap<String, JobId>> }` (A2), bounded to 16 jobs: on every `probe_host_for` the maps first drop entries whose job is cancelled or past its deadline, then, if still full, the oldest by insertion; both maps are updated together under one lock order (`jobs` then `by_marker`) so they never disagree. `probe_host_for` reads `job.marker()` **once**, inserts `by_marker[marker] = job.job_id()` and hands that same value to the host it builds. `JobCtx::marker()` is a generator in the engine (every call mints a new token), so `by_marker` is many-to-one: a job holds one marker per host built for it, all resolving to the same `Arc<JobState>`, and evicting a job removes every marker pointing at it (fix F7). `JobState.marker` is the first marker seen and is informational only. The three checks hold an `Arc<LaneState>` (handed to them by `L4StreamLane::checks()`), and because `Check::run` receives only `&dyn ProbeHost`, which has `marker()` but no `job_id()`, a check reaches its job's state through `state.job_by_marker(&host.marker()) -> Option<Arc<JobState>>`. A job that never calls `probe_host_for` leaves nothing behind.

```rust
pub struct JobState {
    pub job_id: String,
    pub marker: String,                        // the first marker seen for the job, informational; the key a check has is its host's captured marker (A2, F7)
    pub cases_sent: AtomicU32,                 // every message written that is a case (not prelude, not liveness)
    pub cases_skipped_denylisted: AtomicU32,
    pub cases_skipped_too_large: AtomicU32,
    pub liveness_probes: AtomicU32, pub liveness_failures: AtomicU32,
    pub crashes: AtomicU32, pub parser_faults: AtomicU32, pub retired: Mutex<HashSet<String /* point id */>>,
    pub consecutive_timeouts: AtomicU32,
    pub rate_waits: AtomicU32,                       // InjectionRateExceeded sleeps (S5.4)
    pub connections: Arc<tokio::sync::Semaphore>,   // 4 permits
    pub pacer: Mutex<BytePacer>,                     // sliding one-second window, bytes/s (F2)
    pub latency: Mutex<VecDeque<u32>>,               // last 20 reply times, ms
    pub campaigns: Mutex<HashMap<String /* point id */, Arc<tokio::sync::Mutex<Option<Campaign>>>>>,
    pub points_total: AtomicU32,                     // from discover, for the share
    pub selection: Mutex<HashMap<String /* node id */, SelectionReason>>,
    pub points: Mutex<HashMap<String /* point id */, DiscoveredPoint>>, // the discovery cache probe_host_for reads
    pub grammars: Mutex<HashMap<String /* node id */, Arc<dyn Grammar>>>, // the selected grammar per endpoint
    pub seed_notes: Mutex<HashMap<String /* node id */, Arc<Vec<String>>>>, // S5.2 (b) skip notes (decoded once per job, shared by every node), for the verdict detail
}
impl JobState { pub fn counters(&self) -> aitm_scan_model::L4Counters; }   // cases, crashes, liveness_failures, retired_elements (u64)
```

**Pacer (F2).** `BytePacer` is a sliding one-second window, not a token bucket: no one-second window carries more than `max_bytes_per_s` bytes, so a burst can never exceed the rate; a single message larger than the rate goes alone in an empty window. `wait_for_at(len, now)` returns how long the caller sleeps before writing `len` bytes at `now`.

**Guard `None` (L4 disabled).** `lane()` still returns `Some` (D1, call A18, so the engine's refusal order says `refused_l4`). Defence in depth: `discover` refuses every endpoint through its authorisation preview with `Err(anyhow!("scan: refused_l4: L4 is disabled (l4.enabled: false); the stream lane sends nothing"))` (a target with no L4 endpoints has nothing to refuse and yields an empty discovery) and `probe_host_for` returns the same error; the engine, which has already refused at `scan.start`, never sees either on a correctly configured core. **(Architect's call)**: the lane re-uses the D3 error form so a misordered engine still surfaces the right token.

#### S5.2 `discover(target, job)`

Endpoints are `target.l4` (`ip`, `port`, `proto`, `grammar`); an `ip` that does not parse as an `IpAddr` fails discovery with `scan: invalid_profile: l4 target ip '<x>' is not an IP address`. For each endpoint:

1. **Self-port check**: `ip.is_loopback() && guard.self_ports().contains(&port)` makes `discover` fail with `scan: out_of_scope: <ip>:<port> is one of the core's own listener ports` and opens nothing (C18). Then the **authorisation preview**: `guard.check(L4Action::Inject, &L4Target { interface: "*", direction: Outbound, dst: Some(ip), dst_port: Some(port), proto })`. A refusal makes `discover` fail with `scan: out_of_scope: <guard error Display>` and opens nothing (T6-5 b). The minted permit is dropped unused. The matching scope entry string (S5.4) is computed now and kept on the node.
2. **Corpus** (in this order, de-duplicated by bytes, at most 64 seeds per endpoint):
   (a) captured flows: every `L4Flow` in `store.list()` (when `store` is `Some`), every packet with `dir == L4Direction::Outbound` whose `frame::transport_payload(&pkt.bytes, &pkt.decoded.layers)` yields `dst == ip && dst_port == port && proto matches` and a non-empty payload; one packet payload = one seed, `seed_id = "flow:<L4FlowId>#<packet index>"`. The capture tags every packet with the capture's direction, so the destination match is the real filter and the direction check only excludes captures declared inbound.
   (b) profile seeds `job.profile().l4.seeds`: `hex` (hand-rolled decoder; whitespace and `0x` tolerated; odd length or a non-hex digit fails discovery with `invalid_profile` naming the seed index), `base64` (standard alphabet with padding, hand-rolled; same failure rule), `flow` (an HTTP `FlowRef`, which the stream lane cannot use) is skipped with a note (`seed[i]: flow seeds are not L4 flows`); so is a seed that decodes to no bytes, a seed over the 64 KiB message bound, and the 65th and later seeds of an endpoint. Every note reaches the discovery tracing line (`seeds_skipped=<n>`) and the verdict `detail` (`seed_notes=[...]`, S6.5). `seed_id = "hex:<i>"` / `"base64:<i>"`.
   (c) when (a)+(b) is empty after the credential filter: 8 grammar-generated messages from `generate(&mut ChaCha8Rng::seed_from_u64(fnv1a64(marker + node_id)))` where `marker` is `job.marker()` read once per `discover`, `seed_id = "gen:<i>"`. For `tlv`/`raw` with no corpus there is nothing to infer and nothing to generate: the endpoint yields one node and zero points, and the tracing line says so.
3. **Grammar** per S3; each seed is parsed; a seed the grammar rejects falls to TLV inference together with the other rejected ones, and if that refuses, to `raw`. A seed never disappears for being unparseable.
4. **Points**: one `InsertionPoint` per (seed, mutable leaf node), in seed order then tree order, `repeat` elements beyond index 3 collapsed (only `[0..=3]` yield points). Fields: `id` (S5.3), `lane: L4Stream`, `kind: L4Field`, `name` = last path component, `path` = the full field path, `example` = lowercase hex of the node's bytes bounded to 32 bytes (64 hex chars, `...` appended when cut), or `"<redacted>"` when `secret` or `is_secret_key(name)`; `flow: None` (an `L4FlowId` is not a `FlowId`; the seed id carries the provenance), `site_node` = the endpoint's node id, `traits`: `Number` for integer kinds, else empty, `frequency: 1`, `method: Some("L4")`, `url: Some("<tcp|udp>://<ip>:<port>/<grammar>")`. Cap **256 points per endpoint**; beyond it, points are dropped and counted.
5. **Node**: one `SiteNode` per endpoint: `id = "l4s-<proto>-<ip>-<port>"` (colons in IPv6 replaced by `-`), `method: "L4"`, `scheme: "tcp"|"udp"`, `host: ip`, `port`, `path_template: "/<grammar>"` (the selected grammar's name, so `L4Location.grammar` can be read from it), `flows: []`, `params: [(L4Field, name)]` for every distinct field name, `auth: false`, `points: n`, `audited: false`.

`points_total` on the `JobState` is set to the total across endpoints (the share divisor). Discovery never opens a socket (C8, C9 rely on this), never panics on a hostile frame (C12) and logs one line per endpoint: `l4_stream discover node=<id> grammar=<name> reason=<selection> seeds=<n> seeds_dropped_credential=<n> seeds_skipped=<n> points=<n> points_dropped=<n>`.

#### S5.3 Identifiers and seeds

- Point id: `"l4s-" + hex16(fnv1a64("<node id>|<seed id>|<path>"))`. Stable across runs for the same inputs; C16.
- `rng_seed` for a point's campaign: `fnv1a64(job.marker() + "|" + point.id)`. Recorded in `L4Evidence.rng_seed`; a replay with the recorded seed and the same seed bytes reproduces the schedule (C5).
- FNV-1a 64 is the one hash in the crate (offset basis `0xcbf29ce484222325`, prime `0x100000001b3`); it is a label, not a security primitive.

#### S5.4 Authorisation per connection and per write

Every connect (TCP) or socket creation (UDP) first mints `permit = guard.check(Inject, &L4Target { interface: ANY_INTERFACE, direction: Outbound, dst, dst_port, proto })`. Every write then calls `permit.authorize_packet(len)`. Outcomes:

- `OutOfL4Scope`, `CapabilityNotGranted`, `DangerousDestinationBlocked`: `HostError::Guard(msg)`; the probe fails, the campaign ends with `Outcome::Error` and the engine's `stopped_reason: guard_refused` logic applies.
- `InjectionRateExceeded { retry_after }`: sleep `min(retry_after, 1 s)` and retry, at most 10 times per write; counted as `rate_waits` in the verdict `detail`; then `HostError::Guard`.
- `PacketTooLarge { max }`: the case is **skipped and counted** (`cases_skipped_too_large`), never truncated.
- `CountExceeded`: the permit is spent; drop it and mint a new one (`check` again) for the same connection, once; a second `CountExceeded` on the same write is `HostError::Guard`.

`L4Evidence.scope_entry` is derived at discovery from `guard.list_scope()`: the first entry with `capability == Inject`, `direction == Outbound`, `interface_covers(entry, ANY_INTERFACE)` (true only for a wildcard entry, exactly the guard's own match), whose CIDR contains `dst` and whose port range contains `port`, rendered as `"<addr>/<prefix>:<lo>-<hi> <interface> <direction>"`, e.g. `127.0.0.0/8:9000-9000 * outbound`. If no entry renders (a race with `l4.scope.remove`), the string is `"<entry removed after check>"`. **(Architect's call)**: describe from `list_scope` rather than extend the permit, which is T1a's type.

#### S5.5 `probe_host_for(point, job)`

Looks the point up by `id` in the lane's discovery cache for `job.job_id()` (the cache is written by `discover` into `JobState`; a point not found is `Err("l4_stream: point <id> was not produced by this lane for job <job>")`), and returns `Box::new(StreamHost { point, seed_bytes, tree, grammar, endpoint, scope_entry, job: Arc<dyn JobCtx>, state: Arc<JobState>, client: Arc<dyn StreamClient>, baseline: OnceCell<ProbeResponse> })`. The constructor is synchronous and performs no I/O; the first `probe`/`baseline` connects.

```rust
pub trait StreamClient: Send + Sync {
    fn exchange<'a>(&'a self, ep: &'a Endpoint, permit: &'a mut L4Permit, pacer: &'a Mutex<BytePacer>,
        messages: &'a [Vec<u8>], complete: &'a dyn Fn(&[u8]) -> bool, reply_timeout: Duration, connect_timeout: Duration)
        -> BoxFuture<'a, Result<Vec<ExchangeStep>, ClientError>>;
}
pub struct ExchangeStep { pub sent_len: usize, pub reply: Vec<u8>, pub ended: Ended, pub elapsed_ms: u32 }
pub enum Ended { Replied, Silence, Eof, Reset, IcmpUnreachable }
pub enum ClientError { ConnectTimeout, ConnectRefused, Guard(L4GuardError), Io(String), DryRun }
```

`TokioStreamClient` opens one connection per `exchange` (fresh connection per case; **(Architect's call)** attribution over speed), writes each message after `authorize_packet` and the pacer, reads a bounded reply (64 KiB, `reply_timeout` 2 s, early stop on `complete`), and closes. UDP uses a connected `UdpSocket`; `ECONNREFUSED` on recv maps to `Ended::IcmpUnreachable`, which the oracle reports as `L4Oracle::Icmp { type: 3, code: 3 }` with `detail` noting it was inferred from the socket error. `ECONNRESET`/`EPIPE` map to `Reset`; a clean close to `Eof`.

#### S5.6 The probe sequence (`StreamHost::probe(payload)`)

`payload.bytes` must be `Some(rendered message)`; `payload.value` is ignored (`Err(HostError::NotBytes)` otherwise). In order:

1. `job.cancelled()` → `HostError::Cancelled`; `Instant::now() >= job.deadline()` → `HostError::Deadline`; the point retired → `HostError::Retired`.
2. `state.consecutive_timeouts >= profile.l4.consecutive_timeouts` → `HostError::ConsecutiveTimeouts(n)` (the error names the count, as the brief requires).
3. `profile.l4.dry_run` → `HostError::DryRun` (S7; the campaign never calls `probe` in dry run, this is the backstop).
4. Denylist over the rendered case and every prelude message → `HostError::Denylisted(verb)`; counted; nothing sent.
5. `job.charge(1)` false → `HostError::Budget`.
6. Self-port re-check (the set changes at runtime): a loopback `dst` whose port is now in `guard.self_ports()` → `HostError::Guard("<ip>:<port> is one of the core's own listener ports")`, nothing opened. Then mint the permit (S5.4); acquire a connection permit from the semaphore (4 per job), bounded by `min(deadline, 30 s)` → `HostError::Deadline` on timeout.
7. `client.exchange(prelude ++ [case])`: the pacer waits for `sum(len)` bytes; `prior_messages = prelude.len()`.
8. Classify: the last step's `ended` and `grammar.classify_reply(reply)` feed the oracle (S6.1). Update `latency` (push `elapsed_ms`, keep 20) and `consecutive_timeouts` (reset on any reply byte or `Eof`/`Reset`; +1 on `Silence`).
9. Liveness, when the oracle says `Silence` or `Reset` (and for MQTT `Eof`, which is a protocol reaction there, only when `classify_reply` is not `ProtocolError`): run `liveness_probe()` on a fresh connection (permit, pacer, `job.charge(1)`), and if it fails, again after 500 ms. Both fail → `oracle = LivenessFailed`, `liveness_after = false`, `state.liveness_failures += 1`. Otherwise `liveness_after = true` and the oracle stays `Silence`/`Reset`.
10. Cadence: every `profile.l4.liveness_every` cases (counted on `state.cases_sent`) the host runs a liveness probe before the case; its result is `liveness_before` for that case (otherwise `liveness_before` is the last known value, initially `true` after `baseline()`).
11. Return `Ok(ProbeResponse { status: None, headers: vec![], body: vec![], elapsed_ms, flow: None, ws_frames: None, l4: Some(L4Reply { bytes: reply (bounded), oracle, elapsed_ms }) })`.

`baseline()` sends the unmutated seed through steps 1-8 once and caches it; it also seeds `liveness_before = true` when the baseline got a reply. `probe_raw` is `Err(HostError::Unsupported("probe_raw is not available on the L4 stream lane"))`. `budget_left()`, `deadline()`, `profile()`, `cancelled()` forward to the job; `marker()` returns the marker captured when the host was built (constant for the host's life, because the engine's `JobCtx::marker()` mints a fresh token per call, fix F7); `held_flows()` is empty (the lane holds no `aitm_core::Flow`; `L4Evidence.sent_hex` is the record).

`HostError` is an `enum` wrapped in `anyhow::Error` so the checks can `downcast_ref::<HostError>()`: `Denylisted(&'static str) | TooLarge | NotBytes | Retired | Budget | Deadline | Cancelled | ConsecutiveTimeouts(u32) | Guard(String) | DryRun | Unsupported(&'static str) | Connect(String)`. `Debug`/`Display` carry no message bytes.

#### S5.7 Ceilings the lane enforces itself

Regardless of profile (the engine clamps to D11 ceilings; the lane re-caps so a misconfigured engine cannot overshoot): cases per job <= 5000 (counted on `cases_sent`; the campaign stops at the cap with `detail` `lane cap 5000 reached`); bytes/s <= 1 MiB (`BytePacer::new(min(profile.l4.max_bytes_per_s, 1 << 20))`, applied to every write: prelude, case, liveness, reproduction); connections 4 (the semaphore); reply bound 64 KiB; message bound 64 KiB (a rendered case larger than that is skipped and counted as too large before the guard sees it); per-await `min(remaining to deadline, 30 s)`; reply timeout 2 s; connect timeout 2 s; liveness retry 500 ms; recovery window 15 s (S6.2); reproduction spacing 1 s; prelude depth <= 8 messages; 16 job states; 64 seeds and 256 points per endpoint. These numbers are constants in `state.rs` (`pub const`), named in the verdict `detail` when they bind.

### S6. Checks, the shared campaign, oracles, mutators

#### S6.1 Oracle decision table

`ReplyClass` (grammar) x `Ended` (transport) -> `L4Oracle` on the reply, before liveness:

| `Ended` | `classify_reply` | `L4Oracle` | Note |
|---|---|---|---|
| `Replied` | `Ok` | none (clean case) | latency rule still applies |
| `Replied` | `ProtocolError` | `ProtocolError` | a refusal, expected for malformed input |
| `Replied` | `Unknown` | none, `detail` notes `unknown reply` | |
| `Silence` | - | `Silence` | triggers liveness (S5.6 step 9) |
| `Eof`/`Reset` | `ProtocolError` (the peer answered its error token, then closed) | `ProtocolError` (clean refusal) | T10's P mode and real Redis/memcached do this; never a finding (A7) |
| `Eof`/`Reset` | `Ok` (bytes came back, then the peer closed) | none (clean) | e.g. TLV `ERR` then close; a reply means the parser survived |
| `Eof`/`Reset` | reply empty or `Unknown`, grammar `close_on_malformed_is_expected: false` | `Reset` | triggers liveness; the parser-fault candidate (A7) |
| `Eof` | reply empty, `close_on_malformed_is_expected: true` (MQTT) | `ProtocolError` | the spec-mandated close; liveness still runs every `liveness_every` |
| `Reset` (RST) | reply empty, MQTT | `Reset` | the one MQTT parser-fault candidate |
| `IcmpUnreachable` (UDP) | - | `Icmp { 3, 3 }` | triggers liveness |

**Latency outlier** (F1, F4): with at least 10 samples in the window, a clean reply whose `elapsed_ms > 5 x max(median, 10 ms)` is an outlier candidate; the campaign re-sends that exact case once; if the repeat is also `> 3 x max(median, 10 ms)` the campaign records one `LatencyOutlier` (the first only, per point). The 10 ms floor keeps a sub-millisecond loopback target from making every later reply an outlier. The rule is **not evaluated for frame-incomplete cases** (the point is a `len`/`count` relation node or a `delim`/`varint`, or the chain contains `len_desync`, `count_mismatch`, `delim_remove`, `delim_dup`, `varint_overlong`): a server waiting for the rest of a frame until its idle timeout measures its framing timeout, not a processing anomaly. Such cases are counted as `latency_skipped_framing`. **(Architect's call)**: one confirming repeat keeps a single GC pause from becoming an issue.

#### S6.2 The campaign: liveness -> reproduction -> retirement

A **campaign** is the whole fuzzing of one point: the schedule (S6.4), the oracle readings, the reproduction of interesting cases and the resulting per-class outcomes. `Campaign { point_id, rng_seed, cases_planned, cases_sent, skipped_denylisted, skipped_too_large, crash: Option<Finding>, parser_fault: Option<Finding>, latency: Option<Finding>, stopped: StopReason, dry_run_render: Option<DryRunReport> }`, `Finding { case: Case, evidence: L4Evidence, reply_excerpt: String, timing: Option<(u32, u32)> }` (`timing` is `(elapsed_ms, median_ms)` for a latency finding; `L4Evidence` has no field for either).

The three checks share one campaign per point through `JobState.campaigns`. `Campaign::run_or_read(point, host, state: &LaneState)` first locates the job: `state.job_by_marker(&host.marker())`; a miss (no `probe_host_for` ran for this job, or the state was evicted) returns a verdict `Outcome::Error`, `detail` `l4_stream: no job state for this host`, sending nothing (A2). With the `JobState` in hand, the campaign slot is `campaigns[point.id]`: the first check to run a point takes the point's `tokio::sync::Mutex<Option<Campaign>>`, finds `None`, runs the campaign (through `host.probe`), stores it, and returns its own class's verdict; a check that finds `Some` returns its verdict from the stored campaign **without sending anything**. Two checks racing on one point serialise on that mutex; the engine's running-checks bound (8) means at most that many campaigns run at once across points, under the 4-connection semaphore. **(Architect's call)**: three checks over one campaign rather than one check, because `Issue.class`, `Issue.severity` and the dedupe key come from `CheckMeta` (the engine builds the issue from the check's metadata plus the verdict), so one check could not produce `l4-crash` and `l4-parser-fault` issues with their different severities; and three independent campaigns would triple the traffic for the same information.

**Counter reporting (A5).** After every case that changes a counter (a case sent, a skip, a liveness probe, a finding, a retirement) and once at campaign end, the campaign calls `job.report_l4(state.counters())` where `report_l4` is the default-bodied `JobCtx::report_l4(&self, counters: aitm_scan_model::L4Counters)` T1b adds; the integration task checks `traits.rs` on `origin/main` and wires the call when the method exists, otherwise leaves `L4StreamLane::job_counters(job_id)` as the accessor. The counters are in `JobState` and in every verdict `detail` regardless. The `JobCtx` reaches the campaign through `StreamHost` (which holds the `Arc<dyn JobCtx>`), via a crate-private `StreamHost::job()`; a check that only has `&dyn ProbeHost` cannot call it, so the host, not the check, performs the report inside `probe()` after step 8 and inside the reproduction and liveness paths.

Share of cases per point: `cases_planned = max(1, min(profile.l4.cases, 5000) / max(1, points_total))`, further bounded by `job.budget_left()` at campaign start. The campaign stops at `cases_planned`, `job.budget_left() == 0` (`HostError::Budget`), the deadline, cancellation, `ConsecutiveTimeouts`, a guard refusal, or retirement of the point.

**Crash path.** When a case returns `oracle == LivenessFailed` (silence/reset/ICMP plus two failed liveness probes, S5.6 step 9):
1. `liveness_before` for that case is read from the host (the last cadence probe or the baseline).
2. **Recovery wait**: poll `liveness_probe()` every 1 s for up to **15 s** (constant `RECOVERY_WINDOW`). T10's V-mode speakers come back after 3-5 s. If the target does not recover, the campaign stops (`StopReason::TargetDown`), and the crash finding is recorded with `reproduced: (1, 1)`, `confidence: Tentative`, `detail` `target did not recover within 15 s; reproduction impossible` **(Architect's call)**: a target that stays down after one specific case is a critical signal that must not be reported as inconclusive, but without reproduction it cannot be `firm`.
3. **Reproduction**: `n = profile.l4.reproduce_count` attempts, each: wait for liveness (recovery window), wait 1 s spacing, replay the identical prelude + case bytes on a fresh connection, read the oracle, run the two liveness probes. An attempt **reproduces** when its oracle is again `LivenessFailed`. Each attempt costs `job.charge(1)` plus the liveness charges.
4. Verdict: `k == n` -> `Outcome::Vulnerable`, `Confidence::Firm`; `0 < k < n` -> `Vulnerable`, `Tentative` (a flaky crash is still a crash; `detail` says `reproduced k of n`); `k == 0` -> no crash finding; the campaign records `detail` `one-off liveness failure after case <i>, not reproduced` and continues. `L4Evidence { sent_hex (the case, full, <= 64 KiB), seed_id, rng_seed, mutation_chain, prior_messages, oracle: LivenessFailed, liveness_before, liveness_after: false, reproduced: (k, n), scope_entry }`.
5. **Retirement**: on any crash finding (`k >= 1`, or the target-down case) the point id is added to `JobState.retired` **and the pair `(node id, field path)` to `JobState.retired_paths`**, `crashes += 1`; `host.probe` returns `HostError::Retired` from then on for any point whose id, or whose `(node id, field path)`, is retired, so no later check and no later campaign step touches that field on that endpoint. A point whose path is already retired when its campaign would start yields an empty `Campaign` (`stopped: Retired`, zero cases) without a socket. Retirement is by field path rather than by point because one endpoint yields a point per `(seed, field path)` pair and the umbrella's L4 dedupe key `(class, ip, port, proto, grammar, field_path, mutation_class)` folds those per-seed repeats into one issue; `L4Counters.retired_elements` counts retired paths, one per crash finding (fix F8). A `HostError::Connect` refusal **before a case goes out** (the opening baseline included) is a pre-existing down state, not a reading of that case: the campaign runs the recovery poll once, retries the identical case if the target returns, and only a second refusal, or a window that expires, is `StopReason::TargetDown`; the waits are reported as `connect_waits` (fix F9). After a recovered reproduction round the campaign ends for that point (the finding is the result; no more cases on a point that crashes the target).

**Parser-fault path (A7).** A case whose oracle is `Reset` per S6.1, i.e. the peer closed the connection (`Eof` or RST) with **no protocol-error token in the reply** (reply empty or `Unknown`), **and** whose immediate liveness probe passes, is a parser-fault candidate, for grammars where closing is not the expected reaction (`close_on_malformed_is_expected: false`). A protocol-error reply followed by a close is a clean refusal (T10's P mode; Redis and memcached behave the same) and is never a finding. It is reproduced like a crash (same `n`, 1 s spacing, no recovery wait needed); each attempt reproduces when the oracle is again `Reset` (close without an error token) with liveness passing. `k == n` -> `Vulnerable`, `Firm`; `0 < k < n` -> `Vulnerable`, `Tentative`; `k == 0` -> nothing. `L4Evidence.oracle: Reset`, `liveness_after: true`. One parser-fault finding per point (the first); the point is **not** retired for a parser fault (the service is alive), but the campaign stops re-sending that exact case. For MQTT, where `Eof` is a protocol reaction, a parser fault is instead a `Reset` (RST, not a clean close) with liveness passing.

**Latency path.** S6.1; `L4Evidence.oracle: LatencyOutlier`, `reproduced: (1, 2)` (the confirming repeat), `liveness_before/after: true`.

**Cadence liveness failure** (a scheduled probe fails twice with no case to blame): `liveness_failures += 1`; recovery wait; on recovery the campaign continues; without recovery `StopReason::TargetDown` and every check's verdict is `Inconclusive` with `detail` naming the last case sent.

#### S6.3 The three checks

All three: `lanes: [L4Stream]`, `kinds: [L4Field]`, `technique: Malformed`, `intensity: Medium`, `cost: Heavy`, `needs_baseline: true`, `wants_traits: None`, `targets_session: false`, `origin: Native`.

| `id` = `class` | `name` | `severity` | `confidence_max` | `cwe` | `description` (one sentence) |
|---|---|---|---|---|---|
| `l4-crash` | L4 service crash on malformed message | `Critical` | `Firm` | 400 | A mutated message stopped the service answering, confirmed by failed liveness probes and reproduced. |
| `l4-parser-fault` | L4 parser fault: connection dropped on malformed message | `Medium` | `Firm` | 20 | The service closes the connection on a malformed message instead of answering with its protocol error, reproducibly. |
| `l4-latency-outlier` | L4 latency outlier on malformed message | `Info` | `Tentative` | 400 | One mutated message took more than five times the median reply time, twice. Cases that leave the frame incomplete (a mutated length or count, a removed delimiter, an over-long varint) are excluded, because the delay such a case measures is the peer's framing timeout. (Two sentences: the one place Non-goals' one-sentence rule is relaxed, because the exclusion is what makes the class honest.) |

`remediation`: `Some("Validate declared lengths and counts against the bytes received before allocating or indexing.")` for the first two; `None` for the third.

`run(point, host)` for each: `campaign = Campaign::run_or_read(point, host, state)` then map: the class's `Finding` present -> `Vulnerable` with its confidence, `evidence: Evidence { payload: Some(hex of the mutated field bytes, <= 256 chars), matched: Some(scrub_text(reply excerpt) <= 256 bytes, or the oracle token when the reply was empty), l4: Some(evidence), ..Default }`, `detail` (S6.5), `poc_hint: None` (no PoC for L4 in v2; umbrella D6 builds PoCs from HTTP requests); no finding and the campaign completed -> `Clean`; the campaign stopped early for `Budget`/`Deadline`/`Cancelled`/`ConsecutiveTimeouts`/`TargetDown`/dry run -> `Inconclusive`; `Guard` -> `Error`. `Verdict.confidence` for `Clean`/`Inconclusive` is `Tentative`.

**What the verdict carries so the engine can build `Issue.location.l4`** (a contract for T1b, stated here because the engine cannot guess it): `ip`, `port`, `proto` from the point's `SiteNode` (`host`, `port`, `scheme`); `grammar` from the node's `path_template` without the leading `/`; `field_path` from `InsertionPoint.path`; `mutation` from `Evidence.l4.mutation_chain[0]` up to its first `(` (the mutator name, e.g. `len_desync`), which is also the `mutation_class` of the L4 dedupe key (D6).

#### S6.4 Mutators and the schedule

**Byte-level set** (`mutate/bytes.rs`; the LibAFL names, hand-rolled, pure `fn(&mut Vec<u8>, &mut ChaCha8Rng, ctx: &Corpus) -> Option<MutationNote>` where `None` means "not applicable to this input", e.g. too short): `BitFlip, ByteFlip, ByteInc, ByteDec, ByteNeg, ByteRand, ByteAdd, WordAdd, DwordAdd, QwordAdd, ByteInteresting, WordInteresting, DwordInteresting, BytesDelete, BytesExpand, BytesInsert, BytesRandInsert, BytesSet, BytesRandSet, BytesCopy, BytesInsertCopy, BytesSwap, CrossoverInsert, CrossoverReplace, Splice` (25; the two `Mapped*` variants are not in scope). Interesting values: 8-bit `{-128, -1, 0, 1, 16, 32, 64, 100, 127}`, 16-bit adds `{-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767}`, 32-bit adds `{-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647}` (AFL's tables). `Crossover*`/`Splice` take the other seeds of the same endpoint as the donor set and are skipped when there is none. Growth is bounded: a byte-level mutation that would exceed 64 KiB is rejected (`None`).

**Structure-aware set** (`mutate/structure.rs`, `structure_cases(tree, spec, path, kind)` over the `Tree`; the `MessageSpec` is passed because `one_of` and `range` live on `FieldSpec`, not on the node; each mutator yields a deterministic list of cases for a node of the right kind): `len_desync` on a `len` node: `+1, -1, 0, max (all ones for the width; `2147483647` for a `decimal`), past_buffer (declared = actual + 1000)`; `count_mismatch` on a `count` node: `+1, -1, 0, max` (same `max` rule); `type_subst` on a node with `one_of`: every other allowed value, then the values `0`, `0xff` and, for tokens, a lowercase variant and an unknown token `ZZZZ` (denylisted values are filtered here as well as at send); `delim_remove`, `delim_dup`, `delim_inject` (inject the grammar's own delimiter and `\r\n`/`\0`/space into the preceding `line`/`bytes`/`token` field) on `delim` nodes; `long_string` on `line`/`bytes`/`cstring`/`token`: fill with `A` to 256, 4096, 65535 bytes (bounded by the 64 KiB message cap, so 65535 is skipped when the rest of the message leaves no room); `repeat_element` on a `repeat` element: duplicate it x2, x16, x256; `checksum_invalid` on a `checksum` node: xor 1, zero; `varint_overlong` on a `varint`: 5-byte encoding of the same value, continuation bit never cleared (4 bytes with the high bit set), value `268435456` (one past the MQTT maximum) (chain tokens `5`, `no_terminator`, `268435456`); `int_boundary` on `u8/u16/u32/decimal`: `0`, `1`, `max`, `max-1`, `-1` (decimal), `range.hi + 1` (token `range_hi+1`) when `range` is set.

**Relation-aware rendering.** After any mutation of a node, `resatisfy(tree, except)` recomputes every `len`/`count`/`checksum` **unless** the mutation targeted that relation node itself (`len_desync`, `count_mismatch`, `checksum_invalid`, or a byte-level mutator applied to a relation node), in which case that one node keeps its mutated value and every other relation is recomputed. So `BytesInsert` on `payload` yields a longer message with a correct `length`, while `len_desync(header.length, +1)` yields a correct payload with a wrong length (C6).

**Schedule** (`mutate/schedule.rs`): `Schedule::new(tree, spec, point_path, kind, rng_seed, cases_planned, donors) -> impl Iterator<Item = Case>`, `Case { index: u32, bytes: Vec<u8>, chain: Vec<String>, field_bytes: Vec<u8> }`. Order: every structure-aware case for the point's node in the fixed order above (stage 1), then byte-level cases (stage 2) until `cases_planned`: for each, the rng picks a stack depth `1..=3`, then that many mutators from the byte-level set applied to the node's bytes in turn, re-rendered with relations re-satisfied. The rng is `ChaCha8Rng::seed_from_u64(rng_seed)`, consumed only by stage 2 and by `Crossover*`/`Splice` donor choice, so the same `(tree, path, rng_seed, cases_planned, donors)` yields a byte-identical case list (C5). A case identical to the seed or to an earlier case is dropped (does not count toward the share).

**Chain naming** (`mutation_chain` entries, read by T6-1): `"<mutator>(<path>[,<params>])"`. Structure: `len_desync(header.length,+1)`, `len_desync(header.length,max)`, `len_desync(header.length,past_buffer)`, `count_mismatch(header.qdcount,-1)`, `type_subst(pdu.function,0x08)`, `delim_remove(command.crlf)`, `delim_dup(args[0].crlf)`, `delim_inject(command.arg,"\r\n")`, `long_string(command.arg,4096)`, `repeat_element(args[1],x16)`, `checksum_invalid(trailer.crc,xor1)`, `varint_overlong(fixed.remaining_length,5)`, `varint_overlong(fixed.remaining_length,no_terminator)`, `int_boundary(pdu.quantity,max)`, `int_boundary(pdu.quantity,range_hi+1)`. Byte-level: `BitFlip(payload,@13)`, `BytesInsert(payload,@2,+7)`, `WordInteresting(payload,@0,be,-129)`, `WordAdd(payload,@0,le,+7)`, `Splice(payload,donor=1)`; a multi-byte mutator (`Word*`, `Dword*`, `Qword*`) carries the endianness it read the field with as a `be`/`le` token before the value. The mutator name is everything before the first `(`.

#### S6.5 Verdict `detail`

One line, bounded to 2 KiB except in dry run (S7): `l4_stream <grammar> <ip>:<port>/<proto> point=<path> cases=<sent>/<planned> skipped_denylisted=<n> skipped_too_large=<n> liveness_probes=<n> liveness_failures=<n> rate_waits=<n> connect_waits=<n> latency_skipped_framing=<n> stop=<reason> selection=<reason>` followed by the class-specific clause: `crash reproduced k/n after case #i chain=[...]`, `parser fault reproduced k/n ...`, `latency outlier <ms> vs median <ms>`, `clean`, or the stop clause (`budget exhausted`, `deadline`, `cancelled`, `consecutive timeouts 20`, `target did not recover within 15 s`, `guard refused: <msg>`, `tlv inference refused: <reason>`, `lane cap 5000 reached`), and, when the endpoint had skipped seeds, `seed_notes=[...]` at the end (S5.2 (b)). Never a byte of a message.

### S7. Dry run

With `profile.l4.dry_run: true` the campaign renders every case of the schedule (stage 1 and stage 2, up to `cases_planned`) and opens no socket: `StreamClient` is never called, no permit is minted (`guard.check` is not called either, so a dry run also works for a target the operator has not yet scoped — the engine's `out_of_scope` check at `scan.start` still applies, D3), `job.charge` is not called, and `baseline()` returns `Err(HostError::DryRun)`. Every check returns `Outcome::Inconclusive`, `Confidence::Tentative`, `evidence: Evidence::default()`; the `l4-crash` check's `detail` is the dry-run report, the other two say `dry run: see l4-crash for the rendered cases`. **Report shape (Architect's call)**: `dry run: <total> cases for <path> (<skipped_denylisted> denylisted would be skipped); first 50:` then one entry per case `#<i> <len>B <chain> <hex of the first 64 bytes>[...]`, newline-separated, bounded to 16 KiB in total. The denylist is evaluated in dry run too, so the report shows which cases would have been refused (`#7 12B type_subst(cmd,FLUSHALL) <denylisted>` with no hex). `discover` behaves exactly as live (it never opens a socket anyway). The `StreamClient` trait makes "no socket" testable: a counting test double proves zero `exchange` calls (C8), and the in-process listener's accept count stays 0.

### S8. Frame payload extraction (captured flows)

`L4Packet.bytes` are the raw frame as captured (Ethernet, bare IP, or BSD loopback with a 4-byte address-family word, `craft.rs` `parse_frame`'s three cases); `decoded.layers` tells which. `frame::transport_payload(bytes: &[u8], layers: &[String]) -> Option<FramePayload { dst: IpAddr, dst_port: u16, src_port: u16, proto: L4Proto, payload: &[u8] }>`, hand-rolled: link layer by `layers[0] == "Ethernet"` (14 bytes, ethertype `0x0800`/`0x86DD`) or by the first byte being an AF word (`2`, `24`, `28`, `30` in either byte order, then 4 bytes) or by the first nibble (`4`/`6`); IPv4 header length from IHL (`>= 20`, `<= total length`), protocol 6/17 only; IPv6 fixed 40 bytes, next header 6/17 only (an extension header makes the packet unusable: `None`); TCP data offset `>= 5`; UDP 8 bytes, length honoured when it fits. Every slice is bounds-checked; an inconsistent frame is `None` and a truncated one is `None` or a payload shorter than the original, never a panic (C12). Only TCP and UDP payloads are seeds.

### S9. Logging and `Debug`

One `tracing::info!` per `discover` endpoint (S5.2), one `debug!` per campaign start/stop (`point`, `cases_planned`, `stop`), one `info!` per finding (`class`, `point`, `reproduced`, `chain`), one `warn!` per guard refusal (discovery's `out_of_scope` and `HostError::Guard`) and one per target-down (`StopReason::TargetDown`); the two `warn!` lines are required, not optional. Never bytes, never hex of a sent message (C11). `Debug` for `Tree`, `Node`, `Case`, `Campaign`, `Finding`, `StreamHost`, `JobState`, `ExchangeStep` prints byte fields as `<n bytes>`.

## Acceptance criteria

### Umbrella criteria (cited, not renumbered; real run over the real bus against T10's speakers)

- **T6-1** Against the seeded length-prefixed TCP service in V, the generic TLV grammar infers the 2-byte big-endian length relation from captured flows (issue evidence `mutation_chain` names `len_desync`), the service's own downtime log shows the crash, the lane records one `l4-crash` with `reproduced: (3, 3)`, and on P the same run yields zero issues (`test_t6_tlv_crash.py`).
- **T6-2** Against the seeded UDP DNS-like service, the DNS grammar's label-length mutation triggers the seeded fault on V (`l4-parser-fault` or `l4-crash`) and nothing on P (`test_t6_dns_udp.py`).
- **T6-3** A RESP job against a real `redis-server` (capstone tier, `needs=redis`) sends no denylisted command (server `MONITOR` log), completes bounded, and yields zero issues; the same for memcached `flush_all` (`test_t6_denylist_real_servers.py`, SKIP 77 without the servers).
- **T6-4** For every one of the eight grammars, against T10's seeded minimal speaker: in V the grammar's generated messages are classified `ok`, its parse-bug trigger makes the speaker close and fail liveness for its bounded window, and the lane records exactly one `l4-crash` or `l4-parser-fault` issue naming that grammar; in P the same run yields zero issues; the max bytes/s pacer holds (speaker log timestamps). No grammar is proven only in the capstone tier (`test_t6_grammars_live.py`).
- **T6-5** Gates, each sub-case opening no socket (the speaker's accept log stays empty): (a) `l4.enabled: false` -> `refused_l4`; (b) no `Inject` entry covering `ip:port` -> `out_of_scope`; (c) an agent with one of the two L4 agent flags but not the other -> `refused_l4`; (d) a profile naming only an unavailable lane -> `lane_unavailable`; (e) with `l4.enabled`, an entry `interface: "*"`, `direction: outbound`, the target CIDR/port and `Inject`, the same job starts (`test_t6_gates.py`).
- **T10-1** (T10's) names the speakers this lane is accepted against; T6 does not restate it but depends on it (Verification).

### Child criteria (inner loop: `cargo test -p aitm-scan-l4-stream`; each is a named test; none is acceptance evidence for T6-1..T6-5)

1. **C1 YAML round-trip.** Each of the eight embedded grammar files parses into a `MessageSpec`, validates, serialises back with `serde_yaml` and re-parses to an equal value; the registry has exactly eight names in delivery order `["tlv", "resp", "memcached", "dns", "modbus", "mqtt", "smtp", "ftp"]` plus `raw`; `select_grammar` accepts the alias `modbus-tcp` for `modbus`; a spec with a `len.of` naming a missing field fails validation with an error containing that field name.
2. **C2 TLV inference.** `infer(&[[00 02 aa bb], [00 05 01 02 03 04 05], [00 01 ff]])` returns `LenDescriptor { offset: 0, width: 2, endian: Be, counts: BodyOnly, adjust: 0 }`; `infer(&[[00 02 aa bb], [00 09 01 02 03 04 05]])` returns `Err(NoCandidateFits)`; `infer(&[[00 02 aa bb]])` returns `Err(TooFewSeeds)`; `infer(&[[00 02 aa bb], [00 02 cc dd]])` returns `Err(SameLength)`; a little-endian inclusive set `[03 00 aa], [05 00 aa bb cc]` returns `{0, 2, Le, Inclusive, 0}`.
3. **C3 generate parses.** For each grammar and each of 64 rng seeds, `parse(generate(rng))` is `Some(tree)` and `render(&tree) == generated bytes`; for DNS, `hickory_proto::op::Message::from_vec` also accepts the generated bytes.
4. **C4 denylist.** For every grammar, every listed command (exact case, lowercase, mixed case; inside a RESP array, a RESP inline line, a pipelined pair; Modbus FC bytes; MQTT retain bit and `$` topic; DNS opcode 5 and qtype 252; SMTP `RCPT TO:<a@other.example>` refused while `RCPT TO:<a@[127.0.0.1]>` passes) makes `Denylist::refuses` return `Some(verb)`; through a `StreamHost` built under each of the seven built-in profiles and under a profile with every `l4` field at its maximum and `checks.include: ["lane:l4_stream"]`, probing each denylisted message returns `HostError::Denylisted`, the counting `StreamClient` records zero exchanges and the in-process listener accepted zero connections. `Denylist::refuses` takes no profile, config or flag parameter (asserted by the test calling it with only `(GrammarKind, &[u8])`).
5. **C5 determinism.** Two `Schedule`s built from the same tree, path, `rng_seed`, `cases_planned` and donors yield identical `Vec<(chain, bytes)>`; changing `rng_seed` changes stage 2 and leaves stage 1 identical; stage 1 precedes stage 2; no case equals the seed.
6. **C6 relations.** On the Modbus example, `BytesInsert` of 3 bytes into `pdu.address` re-renders `header.length` as the new PDU length; `len_desync(header.length,+1)` leaves the PDU intact and `length` one too high; on RESP, `long_string(args[1].data,256)` re-renders `args[1].len` as `256` and leaves `count` unchanged; `count_mismatch(count,+1)` leaves every `len` intact; `checksum_invalid` on a synthetic spec with a `crc32` relation changes only that node.
7. **C7 state machine (inner loop only, in-process tokio listeners).** A TLV echo speaker that, on a declared length past the buffer, closes and refuses connections for 1 s: the `l4-crash` campaign yields `Vulnerable`/`Firm`, `reproduced: (3, 3)`, `liveness_before: true`, `liveness_after: false`, `mutation_chain[0]` starts with `len_desync`, the point is in `retired`, a further `probe` returns `HostError::Retired`, and the `l4-parser-fault` check on the same point sends nothing and returns `Clean` (no `Reset` with liveness passing was seen). A speaker that closes on a bad length **without replying** but keeps accepting yields `l4-parser-fault` `Vulnerable`/`Firm` and no crash. A P-mode-shaped speaker that answers the bad length with its protocol-error reply (`00 03 45 52 52` for TLV, `-ERR ...\r\n` for RESP) **and then closes** while staying up yields `Clean` for all three checks (A7). The inner-loop speakers mimic T10's triggers: TLV declared length > 4096 (or > received after 200 ms idle), RESP `$N` > 1 MiB, memcached line > 2048, DNS label length past the datagram end, Modbus MBAP length > 260 or < 2, MQTT varint with a fifth byte, SMTP/FTP line > 1024. A speaker that delays one specific case by 1 s (under `REPLY_TIMEOUT`) yields `l4-latency-outlier` `Vulnerable`/`Tentative` with `reproduced: (1, 2)`. A speaker that never replies yields `HostError::ConsecutiveTimeouts(n)` after exactly `profile.l4.consecutive_timeouts` silent cases and `Inconclusive`. A speaker that dies and never returns yields `Vulnerable`/`Tentative` with `reproduced: (1, 1)` and `detail` containing `did not recover`.
8. **C8 dry run.** With `dry_run: true`, the campaign for a 20-case share yields `Inconclusive`, a `detail` starting `dry run: 20 cases`, listing 20 entries (50 when the share is 100), the counting `StreamClient` records zero exchanges, `guard.check` was not called (a counting guard wrapper is not possible, so the test uses a guard whose scope is emptied after discovery, so any `check` during the campaign would refuse, and asserts no `Guard` error surfaced), and the listener accepted zero connections.
9. **C9 guard refusals open no socket.** `lane(None, store)` -> `discover` errors with a message starting `scan: refused_l4:`; a guard with a scope entry for another CIDR -> `scan: out_of_scope:`; a `Capture`-only entry -> `scan: out_of_scope:` mentioning the capability; in all three the listener accepted zero connections and the client double recorded zero exchanges.
10. **C10 wildcard scope.** A guard with one config-declared entry `{ cidr 127.0.0.0/8, ports 0-65535, interface "*", direction outbound, inject, pps 1000 }` authorises `discover` and a `probe` to `127.0.0.1:<listener port>` (one accepted connection); the same entry with `interface: "lo0"` makes `discover` fail with `out_of_scope` and zero accepts (the lane's target interface is `"*"`, which matches no literal entry).
11. **C11 no bytes in logs or `Debug`.** With a `tracing` subscriber capturing every line during a C7 run whose seed contains the ASCII marker `S3CR3TBYTES`, no captured line contains that marker or its hex; `format!("{:?}", ...)` of a `Tree`, `Case`, `Campaign`, `StreamHost` and `JobState` built from that seed contains neither.
12. **C12 frame extractor.** Ethernet+IPv4+TCP, bare IPv4+UDP, BSD loopback (`02 00 00 00`)+IPv6+TCP frames built by hand yield the right `dst`, `dst_port`, `proto` and payload; an Ethernet+ARP frame and an IPv6 frame with a hop-by-hop header return `None`; the valid frame truncated at every length from 0 to full-1 returns `None` or a payload shorter than the original; 10 000 random byte strings return without panicking.
13. **C13 decoders.** Hex (`"00ff"`, `"00 FF"`, `"0x00ff"`) decodes to `[0, 255]`; `"0f0"` and `"zz"` are errors naming the seed index; base64 `"AAE="` decodes to `[0, 1]`; `"A"` and `"A*=="` are errors; a seed over the 64 KiB message bound is skipped with a note (S5.2 (b)) and yields no point.
14. **C14 credential filter.** Seeds `*2\r\n$4\r\nAUTH\r\n$3\r\nabc\r\n`, `PASS secret\r\n`, `AUTH PLAIN xyz\r\n`, and an MQTT CONNECT with the password flag set produce, respectively, no point, no point, no point, and points whose rendered seed has the user/password flags cleared and no `password` node; the discovery tracing line reports `seeds_dropped_credential=3`; a field named `password` yields `example: "<redacted>"`.
15. **C15 ceilings.** `l4.cases: 999_999` plans at most 5000 cases across points; `max_bytes_per_s: 1_000_000_000` builds a pacer at `1_048_576`; a fifth concurrent `exchange` waits until one of four finishes (observed via the listener's concurrent-connection high-water mark `== 4`); a 70 000-byte rendered case is skipped as too large before the guard.
16. **C16 ids and caps.** Two `discover` runs over the same store and profile produce identical point ids and node ids; an endpoint with 300 candidate fields yields exactly 256 points and a tracing line with `points_dropped=44`; `repeat` elements `[4..]` yield no points.
17. **C17 slot.** `lane(None, None)` is `Some`, `.lane() == LaneKind::L4Stream`, `.checks()` has exactly three checks whose `meta()` match S6.3 (`id`, `class`, `severity`, `confidence_max`, `intensity`, `cost`, `technique`, `lanes`, `kinds`).
18. **C18 self-port exclusion.** A guard with `set_self_ports([p])` where `p` is an in-process listener's port makes `discover` for target `127.0.0.1:p` fail with a message containing `is one of the core's own listener ports` and the listener accepts zero connections; a host whose guard gains `add_self_ports([p])` after discovery fails its next `probe` with `HostError::Guard` naming the same text and the listener's accept count does not grow; the same port on a non-loopback `dst` (`10.0.0.9:p`, with a matching scope entry and the client double) is not refused by this rule (the client double records one exchange).

## Verification (what each umbrella AC's independent observer is, and what T6 needs from T10)

No fixture, snapshot or in-process run counts. Each T6 AC is a cell under `tests/e2e/scan/` (T10 owns the files; T6's plan names the cell and the Tester runs it and quotes its output), driven over the real bus against a real core with `l4.enabled`, a config-declared wildcard `Inject` entry within `127.0.0.0/8` covering the speakers' ports, `scanner.allow_agent_l4_fuzz`/`l4.allow_agent_inject` as the cell needs, and T10's speakers in V and P.

| AC | Independent observer | Assertion |
|---|---|---|
| T6-1 | T10's per-service log `GET /log/l4?service=l4-tlv-crash` (entries with `seq`, `ts_ms`: `accepts`, `messages` with `classified ok|protocol_error|denylisted|trigger` and `verb`, `closes`, `downtime {down_at_ms, up_at_ms, trigger_sha256}`; crash window 5 s) and `scan.issue` over the bus; the speaker's address comes from the target's control origin `GET /services` (`name, proto, addr, grammar`) | Exactly one `l4-crash` issue on V with `evidence.l4.reproduced == [3, 3]`, `mutation_chain[0]` starting `len_desync(`, `location.l4.grammar == "tlv"`; the log shows >= 4 `downtime` entries (first trigger + 3 reproductions), each `down_at_ms` following a `messages` entry classified `trigger`, and `up_at_ms - down_at_ms == 5000`; on P zero issues and an empty downtime log. The corpus is **captured**: the cell first replays >= 3 well-formed TLV messages of distinct lengths through an `l4.capture` session on loopback so the flow store holds them (inference needs distinct lengths, S4); the cell asserts `scan.sitemap` shows `path_template: "/tlv"`. |
| T6-2 | `GET /log/l4?service=l4-dns-fault` (`messages` classified `trigger`/`protocol_error`, `downtime`) | On V one issue of class `l4-crash` or `l4-parser-fault` with `location.l4.grammar == "dns"` and a `mutation_chain` entry on a path under `questions[0].name.labels`; on P zero issues; the datagram log shows the speaker received the case. |
| T6-3 | `redis-cli MONITOR` output and memcached `-vv` log for the run's duration | No line matches any denylisted verb (case-insensitive); `scan.status` reaches `done`; `probes.sent` <= the MONITOR line count + liveness `PING`s; zero issues. SKIP 77 without both servers. |
| T6-4 | Per speaker, `GET /log/l4?service=<name>` for the eight `l4-*` services listed by `GET /services` (grammar names `tlv resp memcached dns modbus mqtt smtp ftp`): `messages[].classified`/`verb`/`dir`/`len`/`ts_ms`, `accepts`, `closes`, `downtime` | For each of the eight: the log shows the lane's generated/baseline messages `classified: ok`; exactly one `l4-crash` or `l4-parser-fault` issue with `location.l4.grammar` equal to the speaker's grammar on V, zero on P; **bytes/s**: the observer sums `messages[].len` of the client->server entries (`dir: in`) per `ts_ms` second (T10's `accepts` carry no byte count), and every one-second sum is `<= profile.l4.max_bytes_per_s` (the cell sets `max_bytes_per_s: 8192` so the bound is observable); no `messages` entry is `classified: denylisted`. |
| T6-5 | `GET /log/l4?service=<name>` `accepts` (empty for a-d) and the verb error string | (a)-(d) error tokens as listed and zero accepts; (e) `scan.start` returns a job and `scan.status` reaches `done`. |
| Interim lane-level live proof (**not acceptance evidence** for T6-1..T6-5) | `crates/aitm-scan-l4-stream/tests/live_t10.rs` driven by `tests/live_t10.sh`: the real lane, real sockets and a real guard against T10's speakers, reading `GET /services` and `GET /log/l4?service=<name>` as the observer, in V and P | Per speaker, from the observer: generated/baseline messages `classified: ok`; on V a crash or parser-fault verdict naming the grammar, on P none; the T6-4 bytes/s rule over `messages[].len` per second; zero `classified: denylisted`. It does not go over the bus and produces no `scan.issue`, so it stands in only until T1b's engine runs the cells above. |

**What T10 provides (its child spec D5, read 2026-10-31) and what T6 still needs.** Provided: eight speakers on `127.0.0.1` ephemeral ports listed by `GET /services` with grammar names matching S3's (A6), `GET /log/l4?service=<name>` as above, a 5 s crash window in V (inside the 15 s recovery window, longer than the 500 ms liveness retry; TCP connects are refused meanwhile, UDP datagrams dropped), P mode answering each trigger with the grammar's protocol-error reply then closing while staying up, denylisted commands answered and logged `denylisted`. Still needed from T10's cells (PR B files `tests/e2e/scan/test_t6_*.py`): for TLV, the e2e cell's ability to pre-populate the L4 flow store with >= 3 captured messages of distinct lengths (an `l4.capture` session on loopback while the cell sends them), or, failing capture privilege, the cell falls back to `l4.seeds` hex seeds and the cell says which path it took. The lane needs nothing else from any track.

## Left to the builder

- Internal error type shapes beyond `HostError`, `ClientError`, `InferRefusal`; module-private helpers; test speaker implementations.
- The exact prose of each grammar YAML's `reply:` paragraph and field comments, as long as the file reads as prose and the key names are S2's.
- The byte-level mutator bodies (names, applicability rules and interesting-value tables are fixed; the bodies are free).
- Whether `reply_complete` for line protocols tolerates bare `\n`.
- How `JobState` eviction picks "oldest" (insertion order via a counter is enough).
- Tracing field order.

## Left to T1b (interface gaps this spec cannot close inside `crates/aitm-scan-l4-stream/**`)

- `JobStatus.l4 { cases, crashes, liveness_failures, retired_elements }` has no path from a lane to the engine today. **Decided (A5, coordinator):** T1b adds a default-bodied `JobCtx::report_l4(&self, counters: aitm_scan_model::L4Counters)`. The lane keeps counters in `JobState` and in every `Verdict.detail` regardless, calls `job.report_l4(state.counters())` after every counter-changing case and at campaign end once the method exists at integration time (the integration task checks `traits.rs` on `origin/main` and wires the call), and until then exposes `pub fn job_counters(&self, job_id: &str) -> Option<L4Counters>` on `L4StreamLane` as the accessor.
- `Issue.location.l4` derivation (S6.3) is a contract T1b's issue builder must implement: grammar from the node's `path_template`, mutation from `mutation_chain[0]`.
- `InsertionPoint.flow` cannot reference an `L4FlowId`; provenance is in `L4Evidence.seed_id`. A later model change could add `l4_flow: Option<String>`.

## Open questions

None for Matt. The remaining two interface gaps above (`Issue.location.l4` derivation, `InsertionPoint.flow`) are for the orchestrator to route to T1b; the counter gap is decided (A5).

## Summary

The L4 stream lane is one `Arc<dyn Lane>` returning `Some` on every build, with all per-job state in a bounded map keyed by job id. `discover` builds a corpus per L4 endpoint from captured outbound packet payloads (through a hand-rolled frame skipper), operator hex/base64 seeds and grammar-generated messages, drops credentials, selects a grammar by name, port or TLV inference (falling to `raw`), parses every seed into a field tree and emits one `l4_field` point per mutable field and one node per endpoint. Three native checks share one deterministic, seedable campaign per point: structure-aware mutations first, LibAFL-named byte mutators second, relations re-satisfied unless targeted; every rendered message is denylist-checked, guard-authorised per connection and per write, paced in bytes/s, charged to the job budget and sent on a fresh connection after a constant prelude. Silence or reset triggers two liveness probes; a confirmed failure waits for recovery, is reproduced `reproduce_count` times, becomes an `l4-crash` and retires the point; a reproducible close with the service alive is an `l4-parser-fault`; a confirmed 5x latency spike is an `info`. Dry run renders without a socket. Acceptance is the real run against T10's speakers, observed through their own logs.

### Architect's calls (for Matt to approve or correct)

1. Three checks (`l4-crash` critical/firm, `l4-parser-fault` medium/firm, `l4-latency-outlier` info/tentative) over **one shared campaign per point**, because class and severity come from `CheckMeta` and three campaigns would triple traffic.
2. A fresh connection per case after a constant prelude; no connection reuse, no session inference.
3. The corpus decides over the default port: a port grammar that parses no seed falls to TLV inference, then `raw`.
4. TLV inference needs >= 2 seeds with >= 2 distinct lengths; `counts` is `body_only | inclusive | whole`; tie-break smallest `|adjust|`, then body_only, width 2, big-endian, smallest offset; any refusal falls to `raw` and is named in the verdict.
5. Captured credential messages (RESP `AUTH`, FTP `USER`/`PASS`, SMTP `AUTH`) are dropped from the corpus; MQTT CONNECT credentials are stripped; secret-named fields show `<redacted>` examples.
6. Denylist is a pure function of (grammar, rendered bytes) checked before every write including preludes, matched at token boundaries case-insensitively for text grammars and decoded from bytes for binary ones; over-blocking accepted; TLV/raw have no denylist. SMTP `RCPT` allowed only to the target's own address literal, `localhost` or its banner hostname; FTP refuses every data-channel and server-connect command; Modbus adds FC 21; RESP and memcached lists extended beyond the umbrella floor (S3 table).
7. Crash reproduction waits for recovery (poll 1 s, window 15 s) before each attempt; `k == n` firm, `0 < k < n` tentative, target never recovering is `Vulnerable`/tentative with `reproduced: (1, 1)`; retirement on any crash finding.
8. (A7, refining D8.5's wording) Parser fault = peer close **without a protocol-error token in the reply** (reply empty or `Unknown`) with liveness passing, reproduced the same `n` times, for grammars where closing is not the mandated reaction (MQTT excluded; there only an RST counts); an error reply followed by a close is clean; no retirement.
9. Latency outlier needs one confirming repeat (`> 3x` median after the `> 5x` trigger), the median floored at 10 ms; frame-incomplete cases are not evaluated; one per point.
10. UDP `ECONNREFUSED` is reported as `Icmp { 3, 3 }` inferred from the socket error, noted in `detail`.
11. `scope_entry` is rendered from `guard.list_scope()` as `<cidr>:<lo>-<hi> <interface> <direction>`.
12. Point id `l4s-<fnv1a64 hex>` of node|seed|path; `rng_seed = fnv1a64(marker|point id)`; FNV-1a is the crate's only hash.
13. Lane ceilings as constants: 5000 cases, 1 MiB/s, 4 connections, 64 KiB reply and message, 2 s reply/connect, 500 ms liveness retry, 15 s recovery, 1 s reproduction spacing, 8 prelude messages, 16 job states, 64 seeds and 256 points per endpoint, repeat elements `[0..=3]`.
14. Dry run opens no socket and mints no permit; the `l4-crash` verdict `detail` carries the first 50 rendered cases (hex of the first 64 bytes each, denylisted ones marked), bounded to 16 KiB.
15. Guard `None`: `lane()` is `Some`; `discover` (per endpoint; an empty `target.l4` discovers nothing) and `probe_host_for` fail with the D3 `scan: refused_l4:` form as defence in depth.
16. Frame payloads are extracted by a hand-rolled IPv4/IPv6/TCP/UDP header skipper (no `etherparse` dependency in this crate), TCP/UDP only, no IPv6 extension headers.
17. `probe_raw` unsupported; `held_flows` empty; `InsertionPoint.flow` is `None` with provenance in `seed_id`; `method: "L4"`, `url: "<proto>://ip:port/<grammar>"` on points for the UIs.
18. The byte-level set is the 25 non-`Mapped` LibAFL names; stage 2 stacks 1..=3 mutators per case; AFL's interesting-value tables.
19. Counter reporting to `JobStatus.l4` goes through T1b's default-bodied `JobCtx::report_l4(L4Counters)` (A5), called by the host after every counter-changing case and at campaign end when the method exists at integration time; counters stay in `JobState` and `detail` regardless, with `L4StreamLane::job_counters` as the interim accessor.
20. (A1) Self-port exclusion: a loopback target on one of `guard.self_ports()` is refused `out_of_scope` at discovery and re-checked before every connect.
21. (A2) Checks hold `Arc<LaneState>` and find their job's state by `host.marker()` through `by_marker`; a miss is `Outcome::Error` with `l4_stream: no job state for this host`.
22. (A3) `Exchange.expect` is an enum (`Prefix`, `SameIdAt`, `DnsSameId`, `AnyReply`, `ReplyOrOpen`) evaluated by `Exchange::matches`, not a boxed closure.
