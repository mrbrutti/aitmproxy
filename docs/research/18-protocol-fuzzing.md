# Protocol fuzzing: framework structure, mutation catalogues, and Rust parser crates

> **Provenance:** AI-generated research summary produced by the Researcher engine
> on **2026-10-31**, reading upstream docs via WebFetch/WebSearch (the sandbox
> denies `curl` to crates.io/docs.rs, so every registry figure is second-hand —
> re-check with `cargo info` on a networked machine) plus the aitmproxy tree
> (read directly). No fetched page carried instructions aimed at this task.
>
> **Scope and posture.** This is tooling-architecture research for a first-party,
> authorized security-testing platform whose primary target is its own seeded
> `crates/aitm-testtarget`. It describes **how fuzzing frameworks are
> structured** and **which Rust crates parse/build the relevant protocols**. It
> deliberately contains no exploit recipes. §3.6 names the technique families we
> should **exclude** because they are volumetric or destructive rather than
> robustness-testing.

## 1. Question

How do boofuzz, AFLNet, grammar fuzzers (Peach/Dharma-style) and scapy's
`fuzz()` structure mutation- and generation-based fuzzing of L4 services and raw
packets, and which Rust crates give aitmproxy parsers/builders for DNS, MQTT,
Modbus/TCP, RESP, Memcached, SMTP, FTP and generic TLV framing — so an L4 fuzzer
lane can be designed over the existing `PacketSpec`/`l4.send_recv` primitives
(raw lane) and plain TCP/UDP sockets (stream lane)?

## 2. Short answer

Every mature framework splits into the same four parts: a **corpus/grammar**
(pure data), a **mutation engine** (pure, seedable), a **transport** behind a
tiny send/recv trait, and an **oracle + monitor** that decides whether the target
misbehaved. boofuzz supplies the generation-based side (typed primitives with
declarative `Size`/`Checksum` relations) and the session bookkeeping; AFLNet the
mutation-based side (pcap-derived seeds, response-code state inference). Rust has
well-maintained parsers for all eight protocols and `libafl`'s 27 named byte
mutators are reusable as a library. aitmproxy's gap is oracles and budgets, not
mutators.

## 3. Findings

All sources read **2026-10-31** unless noted. "Inference" marks my reading.

### 3.1 boofuzz: loop, monitors, crash detection, results

- **Protocol definition is pure data.** A `Request` is a tree of blocks and
  primitives: `Static`, `Simple`, `Delim`, `Group`, `RandomData`, `String`,
  `FromFile`, `Mirror`, `BitField`, `Byte`/`Word`/`DWord`/`QWord`, `Bytes`;
  blocks `Block`, `Size`, `Checksum`, `Repeat`, `Aligned`. Each element yields a
  `mutations` generator of pre-rendered values and keeps a valid `default_value`;
  the page explicitly "does not describe sending".
  (https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html)
- **Length and checksum relations are declarative.** `Size` options: `length`
  (default 4), `inclusive`, `endian`, `fuzzable`, `offset`, `math`. `Checksum`
  algorithms: `crc32`, `crc32c`, `adler32`, `md5`, `sha1`, `ipv4`, `udp`, or a
  custom callable. This is the key structural idea: a length/checksum is a
  *named relation to another block*, not a value — so the engine can either
  satisfy it or deliberately desynchronise it. (same page)
- **Message ordering is a graph.** `session.connect()` links requests;
  prerequisites are replayed before the message under test: "When fuzzing,
  boofuzz will send `user` before fuzzing `passw`, and `user` and `passw` before
  fuzzing `stor` or `retr`."
  (https://boofuzz.readthedocs.io/en/stable/user/quickstart.html)
- **Monitors are the oracle.** `BaseMonitor` interface: `alive`, `pre_send`,
  `post_send`, `post_start_target`, `retrieve_data`, `set_options`,
  `start_target`, `stop_target`, `restart_target`, `get_crash_synopsis`.
  `ProcessMonitor` (RPC daemon on the target host; detects segfaults, restarts
  the process), `NetworkMonitor` (passive pcap attached to the test-case log;
  its `restart_target` always returns `false`), `CallbackMonitor` (runs the
  session's callbacks). A monitor's `post_send` returning `False` means crash:
  "If one Monitor reports a crash, the whole testcase will be marked as
  crashing", after which `get_crash_synopsis` produces a human-readable synopsis
  (e.g. a hexdump).
  (https://boofuzz.readthedocs.io/en/stable/user/monitors.html)
- **Session thresholds** (handed down from the first pass, cited to
  https://boofuzz.readthedocs.io/en/stable/source/Session.html):
  `crash_threshold_request=12`, `crash_threshold_element=3`,
  `restart_threshold`/`restart_timeout` `None` (retry indefinitely),
  `receive_data_after_each_request=True`, `ignore_connection_reset=False`,
  `sleep_time=0`, callbacks `pre_send`/`post_test_case`/`restart`/
  `post_start_target`. **Note: pacing defaults to off, and the element threshold
  of 3 means boofuzz retires an element rather than hammering the same spot.**
- **Results are a per-run SQLite DB.** "The log data of each run will be saved to
  a SQLite database located in the `boofuzz-results` directory"; `boo open`
  reopens the web UI on any of them. (quickstart page) Test cases are addressed
  by index, which is what makes "replay case N" reproducible.

### 3.2 AFLNet: state inference, pcap seeds, liveness

From the README (https://raw.githubusercontent.com/aflnet/aflnet/master/README.md)
and the ICST'20 paper (https://mboehme.github.io/paper/ICST20.AFLNet.pdf):

- **Mutation-based, no grammar.** AFLNet "acts as a client and replays variations
  of the original sequence of messages sent to the server" and keeps variations
  that increase code coverage **or** state-space coverage.
- **Seeds come from captured traffic.** Record with `tcpdump -w rtsp.pcap -i lo
  port 8554`, then in Wireshark "extract only the requests and use the request
  sequence as a seed input". The seed file is the concatenated client-to-server
  bytes; `aflnet-replay` later re-splits stored test cases into messages "based
  on their size". **The README does not specify the pcap→message splitter**, so
  the message-boundary problem is left to the user — relevant to us because we
  *do* have per-flow capture.
- **State inference from response codes.** "To identify the server states that
  are exercised by a message sequence, AFLNet uses the server's response codes";
  the inferred state machine is written to `ipsm.dot`. The follow-up TSE paper
  (https://arxiv.org/html/2412.20324v1) describes the State Machine Learner
  reading the response into a byte buffer, extracting the status code "as
  specified in the protocol", and augmenting the IPSM with new states and
  transitions.
- **Known weakness, well documented.** The README notes RTSP uses "the same
  response code 200 for all successful client requests", needing a patch to split
  it. StateAFL (https://arxiv.org/pdf/2110.06253) argues response codes "are
  often not representative of the current state of the server, but only reflect
  the outcome of the last request", inflating the state machine; APFuzz
  (https://arxiv.org/pdf/2602.21892) adds that codes aren't available in all
  protocols and need manual per-protocol extraction. **Inference: for us,
  response-code state inference is a cheap first oracle for SMTP/FTP/Redis/
  Memcached (all have status tokens) and a poor fit for MQTT/Modbus/DNS, which
  have typed reply codes but little state signal.**
- **Selection strategies:** `-q` state selection and `-s` seed selection, each
  `RANDOM_SELECTION | ROUND_ROBIN | FAVOR`; `-R` enables region-level mutation
  operators; `-x` a dictionary.
- **Liveness / lifecycle options:** `-D usec` wait for server init; `-K` send
  SIGTERM to gracefully terminate the server after consuming all messages
  (without it normal runs are flagged as hangs); `-F` false-negative-reduction
  mode; `-c script` server cleanup so each run starts clean; `-e netnsname` run
  the server in a network namespace. **The README does not describe how a dead
  server is detected or restarted (unverified).** AFLNet's model is
  *local-process*; aitmproxy's targets are remote, so our liveness oracle must be
  a network re-probe (§3.6), not a process signal.

### 3.3 Mutation operator catalogues

- **AFL** (https://raw.githubusercontent.com/google/AFL/master/docs/technical_details.txt)
  names deterministic stages as "Sequential bit flips with varying lengths and
  stepovers", "Sequential addition and subtraction of small integers",
  "Sequential insertion of known interesting integers (0, 1, INT_MAX, etc)"; and
  non-deterministic "stacked bit flips, insertions, deletions, arithmetics, and
  splicing of different test cases". Byte-flip / block-dup are *not* separately
  named in that doc. Trimming: the built-in trimmer "attempts to sequentially
  remove blocks of data with variable length and stepover"; `afl-tmin` zeroes
  large blocks with large stepovers then does alphabet normalisation.
- **LibAFL's `mutators::mutations` module is the best concrete, reusable list**
  (https://docs.rs/libafl/0.16.1/libafl/mutators/mutations/index.html), 27
  structs: `BitFlip`, `ByteFlip`, `ByteInc`, `ByteDec`, `ByteNeg`, `ByteRand`,
  `ByteAdd`, `WordAdd`, `DwordAdd`, `QwordAdd`, `ByteInteresting`,
  `WordInteresting`, `DwordInteresting`, `BytesDelete`, `BytesExpand`,
  `BytesInsert`, `BytesRandInsert`, `BytesSet`, `BytesRandSet`, `BytesCopy`,
  `BytesInsertCopy`, `BytesSwap`, `CrossoverInsert`, `CrossoverReplace`,
  `MappedCrossoverInsert`, `MappedCrossoverReplace`, `Splice` (all `*Mutator`).
  A sibling `havoc_mutations` module is "a collection equivalent to AFL++'s havoc
  mutations"; the parent module page says mutators "can be used standalone or in
  combination with other mutators", but **whether `libafl` can be depended on
  purely as a mutator library without pulling instrumentation machinery is not
  stated on the pages I read (unverified)** — needs a `cargo tree` check.
- **radamsa**: the README FAQ recommends `-m bf,bd,bi,br,bp,bei,bed,ber,sr,sd`
  for ~10x faster output and names a "number mutator, which replaces textual
  numbers with something else" (`2000` → `4294967296`). The full mutator table is
  only behind `radamsa -l`, so **the per-code descriptions remain unverified**.
  (https://gitlab.com/akihe/radamsa/-/raw/develop/README.md , `/doc/radamsa.1`)
- **Structure-aware families that byte mutators miss**, from boofuzz's primitive
  set (§3.1): length-field desync (a `Size` whose `fuzzable=True`), delimiter
  substitution/removal (`Delim`), long/overlong strings (`String`), repetition
  (`Repeat`), alignment padding (`Aligned`), and checksum invalidation
  (`Checksum`). **Inference: these are the high-yield classes for text protocols,
  and byte-level havoc rarely reaches them.**
- **Generation-based grammars**: Dharma (archived,
  https://github.com/MozillaSecurity/dharma; fork posidron/dharma) is a
  "Generation-based, context-free grammar fuzzer" whose `.dg` files declare
  non-terminals (`digit := %range%(0-9)`), reference them with `+name+`, and
  offer extension methods `%range%`, `%repeat%`, `%uri%`, `%block%`, `%choice%`.
  **Takeaway: a grammar fuzzer is a CFG plus a few built-in generators; the hard
  part is the grammar, not the engine.**

### 3.4 Raw-packet header fuzzing: what scapy's `fuzz()` actually does

From https://scapy.readthedocs.io/en/latest/usage.html:

- `fuzz()` "change[s] any default value that is not to be calculated (like
  checksums) ... by an object whose value is random and whose type is adapted to
  the field". So **it randomises unset fields only**, per-field-type.
- **Checksums stay valid**: "The UDP checksum will be correct."
- **Explicitly set fields win**: in `fuzz(UDP()/NTP(version=4))` "the NTP
  version will be forced to be 4"; "All the other ports will be randomized."
- **IP addresses are not randomised**: "If you use `fuzz()` in IP layer, `src`
  and `dst` parameter won't be random so in order to do that use `RandIP()`."
  Good news for us: a scope-safe raw fuzz lane can adopt exactly this rule and
  make `dst` non-fuzzable by construction.
- The page does not say whether length fields are randomised (unverified).

**Oracles available at the raw lane** (from `sendrecv.rs`, §3.7): a correlated
reply (`Response`), a non-correlating reply from the target including TCP RST
(`Other`), and silence (`NoResponse { waited }`). A *liveness re-probe* — a known
well-formed stimulus sent after a suspicious case — is the only way to tell
"this input was rejected" from "the service stopped answering", and **no liveness
probe exists anywhere in the crate today** (verified by reading the module).

**Technique families to exclude, not design for.** Volumetric or
resource-exhaustion shapes (high-rate floods, amplification/reflection via
spoofed source, connection-table or memory exhaustion, fragment-reassembly
flooding) and destructive protocol commands (e.g. Modbus write/coil-force
function codes, Redis `FLUSHALL`/`SHUTDOWN`/`CONFIG SET`, memcached `flush_all`,
FTP `DELE`/`STOR` over existing paths, SMTP mass-relay) are out of scope for a
robustness lane: they prove nothing about memory safety and they damage the
target. The design should put these behind an explicit, per-protocol
**destructive-command denylist** that is on by default, and keep the guard's
existing packets/sec ceiling as the hard anti-flood rail.

### 3.5 Grammar coverage per protocol (wire shape + where a length relation lives)

| Protocol | Framing (source) | Where the fuzz-relevant relations are |
|---|---|---|
| **DNS** | RFC 1035 §4: 12-byte header (ID, flags, QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT), then length-prefixed labels; TCP transport prefixes a 2-byte length (RFC 1035 §4.2.2). Not re-read this pass — **cited from the RFC, treat section numbers as unverified.** | Count fields vs actual record count; label length byte vs label; name compression pointers; TCP 2-byte length prefix |
| **MQTT 3.1.1** | OASIS spec §2 (https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html): fixed header byte 1 = 4-bit type (1 CONNECT … 14 DISCONNECT; 0/15 forbidden) + 4 type-specific flags; invalid reserved flags **must** close the connection (MQTT-2.2.2-2). Remaining Length is a 1–4 byte varint (7 data bits + continuation bit, max 268,435,455); "if the multiplier grows past 128×128×128 before the continuation bit clears, the packet is malformed". 2-byte big-endian Packet Identifier where applicable. | Remaining Length vs real body; varint over-length; reserved flag bits; packet-id zero where forbidden (MQTT-2.3.1-1); UTF-8 string length prefixes |
| **MQTT 5** | Adds a properties block with its own varint length. **Not read this pass — unverified.** | Property-length vs properties |
| **Modbus/TCP** | 7-byte MBAP (2 transaction id, 2 protocol id = 0, 2 length, 1 unit id) then PDU = 1 function code + 0–252 data; length counts unit id + PDU; ADU max 260 bytes; big-endian; port 502. **Secondary sources only** (web-search summaries of the Modbus Org *Modbus Messaging on TCP/IP Implementation Guide V1.0b*, e.g. https://scadaprotocols.com/modbus-tcp-mbap-header/, https://www.prosoft-technology.com/kb/assets/intro_modbustcp.pdf) — re-read the official PDF before specifying. | MBAP length vs real PDU length; non-zero protocol id; reserved unit ids 248–255; byte/word counts inside the PDU vs data |
| **Redis RESP2/3** | https://redis.io/docs/latest/develop/reference/protocol-spec/ : first byte is the type; CRLF "always" separates parts. RESP2 `+ - : $ *`; RESP3 adds `_ # , ( ! = % \| ~ >`. Bulk string `$<len>\r\n<data>\r\n`, default max 512 MB (`proto-max-bulk-len`); nulls `$-1\r\n`/`*-1\r\n`; RESP3 adds streamed forms. Clients send **arrays of bulk strings**; `HELLO <ver>` negotiates (`-NOPROTO`); inline commands also accepted. | `$`/`*` length vs actual bytes/elements; negative and huge lengths; missing final CRLF; deep nesting; streamed chunk terminator |
| **Memcached (text)** | https://raw.githubusercontent.com/memcached/memcached/master/doc/protocol.txt : CRLF-terminated command lines; storage line `<cmd> <key> <flags> <exptime> <bytes> [noreply]` then the payload and CRLF; **the reader uses the announced length, not the trailing CRLF, to find the block end**; keys ≤ 250 chars, no control chars or whitespace. Errors: `ERROR` (unknown command), `CLIENT_ERROR <error>` (malformed line), `SERVER_ERROR <error>` (server-side; connection closed only on unrecoverable errors). The doc does not state whether the binary protocol is deprecated (meta commands "cover most of its features") — **binary protocol shape unverified.** | `<bytes>` vs real payload; over-long/illegal keys; `noreply` desync; negative exptime |
| **SMTP** | RFC 5321: CRLF command lines, `<verb> SP <arg>`, 3-digit reply codes, DATA terminated by `CRLF.CRLF`. **Not re-read this pass — unverified.** | Command/argument length; dot-stuffing; pipelining; reply-code state |
| **FTP** | RFC 959: CRLF command lines, 3-digit reply codes, separate data channel. **Not re-read this pass — unverified.** | Command argument length; PORT/PASV argument shape; reply-code state |
| **Generic TLV / length-prefixed** | Inferable from captured traffic: a candidate descriptor is `{ offset, width, endianness, counts: HeaderOnly\|BodyOnly\|Whole, adjust: i32 }` — precisely boofuzz's `Size(length, endian, inclusive, offset, math)` generalised. | The single relation worth fuzzing is "declared length ≠ delivered length" |

**Inference:** seven of the eight protocols reduce to the same three primitives —
a *typed header*, one or more *count/length relations*, and a *status token in
the reply*. That is what makes one descriptor shape plausible across all of them.

### 3.6 Rust crates (all registry data via crates.io API, read 2026-10-31)

| Need | Crate | Latest / date | Licence | Recent dl | Verdict |
|---|---|---|---|---|---|
| DNS | **`hickory-proto`** | 0.26.3, 2026-09-10 | MIT OR Apache-2.0 | 32.3M | Healthy; "safe and secure low-level DNS library"; the clear pick |
| MQTT codec | `mqttbytes` | 0.6.0, **2021-10-30** | Apache-2.0 | 51.5k | Stale as a standalone crate ("MQTT 4/5 serialization and deserialization") |
| MQTT client | **`rumqttc`** | 0.25.1, 2025-11-21 | Apache-2.0 | 2.36M | Active; same `bytebeamio/rumqtt` repo — **whether its vendored codec is re-exported for raw encode/decode is unverified** |
| MQTT (alt) | `mqtt-protocol` | **not checked this pass** | — | — | Unverified |
| Modbus | **`tokio-modbus`** | 0.17.0, 2025-10-22 | MIT OR Apache-2.0 | 432k | Active, async, client+server |
| Modbus | `rmodbus` | 0.12.2, 2025-09-29 | Apache-2.0 | 41k | Active, `no_std`-friendly server framework; lower-level frame control |
| RESP | **`redis-protocol`** | 6.0.0, 2024-11-15 | MIT | 3.13M | "An implementation of the RESP2 and RESP3 protocols" — exactly the codec, no client baggage; ~1 year since release |
| Memcached | `memcache` | 0.21.0, 2026-08-22 | MIT | 1.0M | Active **client**, not a codec; text protocol is trivial to hand-roll |
| Parser toolkit | **`nom`** | 8.0.0, 2025-01-26 | MIT | 211M | For SMTP/FTP/TLV hand-rolled parsers |
| Structured input | **`arbitrary`** | 1.5.0, 2026-10-06 | MIT OR Apache-2.0 | 52.0M | `rust-fuzz`; "generating structured data from unstructured data" — the natural way to drive a typed grammar from a seed byte string, and it makes a case reproducible from (seed, length) |
| Mutator library | **`libafl`** | 0.16.1, 2026-08-11 | MIT OR Apache-2.0 | 189k | 27 named byte mutators (§3.3); library-only use unverified |
| Mutator library | `lain` | 0.5.5, **2021-05-21**, 55 recent dl, no repo field | MIT | 55 | **Dead — do not use** |

Licences are all MIT and/or Apache-2.0, compatible with aitmproxy's
`MIT OR Apache-2.0`. SMTP and FTP have no obvious "codec crate" worth adopting;
both are CRLF line protocols a few hundred lines of `nom` covers.

### 3.7 What is already in the tree (read directly, 2026-10-31 — verified)

- **`crates/aitm-proto-l4/src/craft.rs`.** `PacketSpec { layers: Vec<Layer> }`,
  `Layer::{Ether,Ipv4,Ipv6,Tcp,Udp,Icmp,Raw}`. Every per-layer field is
  `Option<T>`: `None` auto-completes, `Some(v)` is written **verbatim including a
  deliberately-wrong value** — the module doc states this is "the whole point of
  an L4 fuzzing tool". Verbatim-capable fields confirmed: IPv4 `ihl`,
  `total_length`, `flags`, `fragment_offset`, `checksum`, `protocol`,
  `identification`, `dscp`, `ecn`; IPv6 `payload_length`, `next_header`,
  `traffic_class`, `flow_label`; TCP `data_offset`, `flags`, `checksum`, `seq`,
  `ack`, `window`, `urgent_ptr`; UDP `length`, `checksum`; ICMP `icmp_type`,
  `code`, `checksum`, `rest_of_header`; Ether `ethertype`, `src`, `dst`.
  **Gaps (confirmed):** no IP-options or TCP-options field; `set_version(4)`/
  `set_version(6)` are hard-coded in `build_ipv4`/`build_ipv6`; TCP reserved bits
  not exposed; `MAX_PACKET_BYTES = 65_535` cap; errors are only
  `CraftError::{TooLarge, BadLayerOrder}`. `PacketSpec` is `Serialize +
  Deserialize` — so it already *is* the YAML grammar for the raw lane.
- **`crates/aitm-proto-l4/src/sendrecv.rs`.** `send_recv` mints an `Inject`
  permit against the packet's *real* target (aborting if the crafted dst differs
  from the declared one) and a `Capture` permit before any I/O, and re-checks
  `Capture` on the correlated reply. `SendRecvOutcome` is
  `Response(L4Packet) | Responses(Vec<L4Packet>) | Other(L4Packet) |
  NoResponse { waited: Duration }` (the first pass missed `Responses`).
  `ReplyMatch::{Any, FromHost, FiveTuple}`; under `FiveTuple` a TCP RST from the
  target classifies as `Other`. **An ICMP error from the target is `Other` with
  no type/code extracted** — confirmed; there is no ICMP parsing in `classify`.
  No liveness probe exists.
- **`crates/aitm-proto-l4/src/guard.rs`.** `L4Permit` already carries a bounded
  per-call budget and meters **per-packet** against per-entry and global token
  buckets (`pps`, `burst`), plus `max_packet_bytes` and `max_packets_per_call`;
  errors `OutOfL4Scope`, `DangerousDestinationBlocked`, `InjectionRateExceeded
  { retry_after }`, `PacketTooLarge`, `CountExceeded`. **This is already most of
  a fuzzing budget model.**
- **The M5 non-goal is being superseded.** The spec
  (`docs/superpowers/specs/2026-10-27-aitmproxy-m5-l4-packet-mitm-design.md`,
  lines 111 and 580) states "**No automated fuzzing/crash-triage engine in the
  tool**" and "There is **no** `l4.fuzz` verb and **no in-tool crash-triage
  engine**", with the mutation/triage strategy living in the agent or a Rhai
  script. The operator has decided to supersede this. The Architect must record
  the supersession explicitly and re-justify the tool/agent split, because M5's
  safety argument ("A fuzzing run is many guarded calls — no uncapped path")
  depended on every send being an individually guarded verb call.

### 3.8 Crash triage

Synthesised from §3.1–§3.3; no single source states all of it.

- **Minimisation**: AFL's two-level model — an inline trimmer removing blocks
  "with variable length and stepover" during the run, and `afl-tmin` offline.
- **N-times reproduction**: boofuzz's `crash_threshold_request=12` /
  `crash_threshold_element=3` are the published precedent for "confirm before
  believing, then stop testing that spot".
- **Dedupe**: boofuzz dedupes implicitly by test-case index + synopsis;
  AFLNet by (state, coverage). **Inference:** for a remote, black-box target we
  have no coverage, so the available key is `(target endpoint, protocol,
  message-sequence prefix, mutated field path, mutation class, oracle fired)`.
- **A finding record should carry** (inference, modelled on boofuzz's results DB
  and `get_crash_synopsis`): the exact bytes sent (hex) and the parsed
  grammar-level diff from the seed; the full prior message sequence needed to
  reach it; the seed/PRNG state and mutation chain so it replays deterministically;
  which oracle fired and its evidence (reply bytes, RST, ICMP type/code, or
  `waited` duration); timing; the liveness re-probe result before and after; the
  reproduction count out of N attempts; and the scope entry + permit that
  authorised it.

## 4. Candidate directions (for the Architect — candidates, not decisions)

**C1 — Mutator set.** Adopt LibAFL's 27 names (§3.3) as the vocabulary even if we
implement them ourselves, so findings are comparable to the literature. Split
into *byte-level* (bit/byte flip, inc/dec/neg, add/interesting at 1/2/4/8 bytes,
delete/expand/insert/copy/swap/set, crossover, splice) and *structure-aware*
(length-field desync, checksum invalidation, delimiter substitution, long string,
element repetition, count/element mismatch, type-byte substitution). The second
set is where the yield is, and only it needs a grammar.
*Trade-off:* depending on `libafl` (0.16.1) saves work but its library-only
footprint is unverified (§3.6); hand-rolling ~27 pure functions over `Vec<u8>` is
maybe 400 lines, keeps `forbid(unsafe_code)` and is trivially seedable.

**C2 — Oracle set, ordered cheap→expensive.** (1) well-formed reply; (2) protocol
error token (`-ERR`, `CLIENT_ERROR`, SMTP/FTP 4xx/5xx, MQTT connection close,
Modbus exception FC|0x80, DNS RCODE); (3) connection reset / `Other`; (4) ICMP
error — requires adding type/code extraction to `classify` (§3.7); (5) silence
past timeout; (6) **liveness re-probe** with a known-good stimulus, which is the
only oracle that distinguishes "input rejected" from "service stopped"; (7)
response-time outlier. Only (5)+(6) together should promote a case to a finding.
*Trade-off:* the re-probe doubles traffic and must itself consume guard budget.

**C3 — One grammar descriptor, two lanes.** The raw lane already has its
descriptor: `PacketSpec` is serde-round-trippable, and a fuzz plan over it is a
list of *field paths* plus a mutator per path — with `dst` and the scope-relevant
fields marked non-fuzzable by construction, exactly as scapy's `fuzz()` leaves
`src`/`dst` alone (§3.4). The stream lane wants a sibling `MessageSpec` of typed
fields with explicit relations (`Len { of: FieldPath, width, endian, inclusive,
offset, adjust }`, `Count { of }`, `Checksum { algo, over }`, `Delim`,
`Token { oneof }`), i.e. boofuzz's `Size`/`Checksum` shape in Rust, written as
human-readable YAML per the project's scripting rule.
*Trade-off:* `PacketSpec` is layer-structured and a stream message is
field-structured; two siblings sharing one relation vocabulary may beat forcing
a single type.

**C4 — Seeds from our own capture.** AFLNet's seed story (§3.2) is manual
Wireshark work; aitmproxy already captures flows, so a `seed-from-flow` path is a
differentiator — and it also solves AFLNet's unspecified message-splitting
problem for us, because we know the flow's message boundaries.

**C5 — Budget model, hard caps.** Invert the upstream defaults: boofuzz's
`sleep_time=0` and `restart_threshold=None` are the wrong defaults for a remote
target. Reuse the existing `L4Permit` budget (§3.7) and add, as **non-overridable
ceilings**: total cases per run, wall-clock deadline, bytes/sec as well as
packets/sec, consecutive-timeout abort, an error-rate circuit breaker, a
per-element crash threshold (boofuzz's 3) that retires an element, mandatory
liveness re-probe cadence, and the per-protocol destructive-command denylist of
§3.4. A dry-run mode that renders cases without sending should be the default
first step.

## 5. Open questions

1. Can `libafl` 0.16.1 be used as a pure mutator library (no instrumentation,
   no `libafl_targets`)? Needs `cargo tree -p libafl --no-default-features`.
2. Does `rumqttc` 0.25.1 re-export a public encode/decode API, or is
   `mqttbytes` (2021) the only standalone MQTT codec?
3. MQTT 5 properties block and the memcached **binary** protocol: both
   unverified this pass.
4. Modbus/TCP facts came from secondary sources — re-read the Modbus Org
   *Messaging on TCP/IP Implementation Guide V1.0b* PDF.
5. DNS (RFC 1035), SMTP (RFC 5321), FTP (RFC 959) wire details were cited from
   memory of the RFC, not re-read; confirm before specifying.
6. radamsa's full `-m`/`-p` table (only `radamsa -l` has it).
7. How does AFLNet actually detect a dead server and restart it? Not in the
   README.
8. Does scapy's `fuzz()` randomise length fields? Not stated.
9. Policy: the M5 spec's "no in-tool fuzz engine" non-goal is superseded —
   what replaces its safety argument, now that one verb call can generate
   thousands of sends? (A design/policy call for the Architect and Matt.)
10. Should the stream lane reuse the existing `ScopeRateGuard` (host-string,
    requests/sec) or the L4 guard (CIDR/port, packets/sec)? They are different
    guards with different vocabularies.

## 6. Sources

All read 2026-10-31.

- boofuzz: https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html ,
  /user/quickstart.html , /user/monitors.html , /source/Session.html
- AFLNet: https://raw.githubusercontent.com/aflnet/aflnet/master/README.md ;
  ICST'20 paper https://mboehme.github.io/paper/ICST20.AFLNet.pdf ;
  "AFLNet Five Years Later" https://arxiv.org/html/2412.20324v1 ;
  StateAFL https://arxiv.org/pdf/2110.06253 ; SGFuzz https://arxiv.org/pdf/2204.02545 ;
  APFuzz https://arxiv.org/pdf/2602.21892
- AFL: https://raw.githubusercontent.com/google/AFL/master/docs/technical_details.txt
- radamsa: https://gitlab.com/akihe/radamsa/-/raw/develop/README.md ,
  /-/raw/develop/doc/radamsa.1
- Dharma: https://github.com/MozillaSecurity/dharma
- scapy: https://scapy.readthedocs.io/en/latest/usage.html
- MQTT 3.1.1: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
- RESP: https://redis.io/docs/latest/develop/reference/protocol-spec/
- memcached: https://raw.githubusercontent.com/memcached/memcached/master/doc/protocol.txt
- Modbus (secondary): https://scadaprotocols.com/modbus-tcp-mbap-header/ ,
  https://www.prosoft-technology.com/kb/assets/intro_modbustcp.pdf ,
  https://orangehorsetech.com/open-source/oms-modbus/modbus-tcp-mbap/
- crates.io API (`https://crates.io/api/v1/crates/<name>`): hickory-proto,
  mqttbytes, rumqttc, tokio-modbus, rmodbus, redis-protocol, memcache, nom,
  arbitrary, libafl, lain
- docs.rs: https://docs.rs/libafl/0.16.1/libafl/mutators/index.html ,
  .../libafl/mutators/mutations/index.html
- aitmproxy tree: `crates/aitm-proto-l4/src/{craft.rs,sendrecv.rs,guard.rs}`,
  `docs/superpowers/specs/2026-10-27-aitmproxy-m5-l4-packet-mitm-design.md`,
  `docs/research/08-l4-packet-rust.md`
