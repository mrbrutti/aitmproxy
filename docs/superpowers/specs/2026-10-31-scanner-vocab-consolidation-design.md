# Scanner vocabulary consolidation design

**Status:** approved (2026-10-31, self-approved by the orchestrating session under Matt's autonomous-approve mode); amended after the Stage 6 panel (Amendment 1, 2026-10-31)
**Research inputs:** no `docs/research/` note. This is the follow-up named
"scanner vocabulary consolidation" by `docs/superpowers/specs/2026-10-30-audit-ring-integrity-design.md`
(Non-goals, Design 4, Residual risks 12-14) and its plan (Shipped section). Code read on
`15009b2`: `crates/aitm-core/src/{redact,lib}.rs`,
`crates/aitm-plugin-scanner/src/{discover,reproduce,crawl,commands}.rs` and `Cargo.toml`,
`crates/aitm-poc/src/builder.rs`, `crates/aitm-mcp/src/server.rs` (`redact_value`),
`crates/aitm-plugins/src/{mutate,capture,detail}.rs`. Baseline measured on `15009b2`:
`cargo test -p aitm-plugin-scanner` = 178 passed; `cargo test -p aitm-core --lib redact` = 32 passed.

## Amendment 1 (post-panel), 2026-10-31

The Stage 6 security review failed this spec on one Important finding (F1). It also raised a second
design question (F2, rated Minor) that this spec's own rule settles against leaving it alone: "PoC
output must not get weaker except where this spec lists it." The sections below are edited in place;
this note says what moved and why. Numbers marked (scratch) are the Architect's, from an out-of-tree
probe that links the old core, the old scanner scan, the branch's core and the candidate shapes, driven
by the panel's kept `difftool.py` on the panel's seeds (`svc-aligned`, `svc-full`, `svc-soup`,
20261031). They justify the decisions; they are not the AC24 evidence, which the security reviewer
re-runs on the real tree.

**1. F1: one wide scan swallows a nested standard key (Design 2, 3, 4, 5, 7, 9, 12; AC19, AC24; new
AC25, AC26).** Design 4 made `scrub_text_wide` one scan with the wide key test. A wide-only key
(`authentication`, `author`, `sessions`, `sidebar`, `userSession`) masks its value as one region, and
that region can end between a nested standard-secret key and its value, so the nested key is swallowed
and its value is left in the clear: `authentication:\n  password: hunter2` came out
`authentication:\n  [redacted] hunter2`, `sidebar=sid="C1"` came out `sidebar=[redacted]"C1"`. The old
pipeline masked the nested pair first, because its core scan ran before the scanner's. That is a
counterexample to Design 5 row 8 ("same final bytes"), to the "Direction in one sentence" paragraph, to
I1 and I2 (13,635 and 14,627 failing inputs of 3,000,000 on the aligned alphabet), and to the two doc
passages that said the readings "differ ... in nothing else": the public `scrub_text_wide` left a canary
that `scrub_text` masks in 80,102 of 1,500,000 inputs.
**Decision:** `scrub_text_wide` is the two regexes, then the one private scan with the standard reading,
then the same scan with the wide reading over its output. The first scan is `scrub_text`'s own, so a
nested pair is masked first, exactly as before, and everything `scrub_text` masks stays masked (the
second scan only replaces more values with `[redacted]`). "One pair scanner" stays true: one function,
one value rule, one closing-quote rule, run twice. Cost: about twice the scan time, still linear.
`scrub_text` and `is_secret_key` are not touched, so AC8 and AC10 stand. Rejected: the single wide scan
(the reviewed shape; numbers above and in the table below).

**2. F2 (class D): the second scan must not read across a line break (Design 4, 5, 6, 9, 12; AC5, AC14,
AC15, AC19; new AC27).** Run second, the wide scan reads blanks around a separator as core does (Unicode
whitespace, newlines included), where the old second scan read space and tab. A newline after a
separator then makes the wide scan take the next line's first token as the value; that value ends
mid-pair and swallows a nested wide-only key. `authentication:\n  sessionKey: abc123` (plausible YAML;
the old pipeline masked `abc123`) came out `authentication:\n  [redacted] abc123`.
**Decision (Architect's call, the one real design question):** the wide scan does not skip the three
ASCII characters `\n`, `\r` and `\x0c` beside a separator, before it or after it: a pair is read on one
line, as the old second scan read it. It still skips every other whitespace character (non-ASCII
whitespace, the vertical tab). Consequences: (a) every line-break shape is byte-for-byte what the old
pipeline printed, so the aligned alphabet of Design 7 now allows line breaks at separators and I2 covers
them (scratch: 1,000,000 such inputs, 0 violations); (b) DC2 shrinks to non-ASCII whitespace and the
vertical tab, and `author:\nJohn` is no longer a deliberate change; (c) the reading parameter is
consulted in a third place (Design 4, AC19). What is left of class D is three exotic arms, D1 to D3
(Residual risks 8), accepted as a Minor residual; no test pins a leak.

| Blank rule of the wide scan beside a separator | aligned + line breaks, 1M: I1 inputs / I2 | full alphabet, 1M: inputs that leak more than old | soup, 1M | Verdict |
|---|---|---|---|---|
| one wide scan with no first scan, core's blanks (`bcd9647`) | 7,476 / 16,712 | 39,253 | 12,356 | rejected (F1) |
| standard scan first, then the wide scan with core's blanks (all whitespace) | 1,554 / 12,951 | 3,411 | 10,468 | rejected: the YAML shape above leaks |
| space and tab only (the old second scan's) | not run | 4,673 | 13,623 | rejected: undoes DC2 and leaves a value that starts with a non-ASCII space, which the old pipeline masked |
| all but every line-like character (adds U+0085, U+2028, U+2029, vertical tab) | not run | 3,412 | not run | rejected: leaves a value that starts with one of them (`SIDE:\u{2028}Q`), which the old pipeline masked |
| **all but ASCII `\n`, `\r`, `\x0c`** | **0 / 0** | **2,690** | **10,374** | **chosen** |

Every two-pass shape scores 0 / 0 on the aligned alphabet without line breaks (400,000 to 1,000,000
inputs each); the single scan fails it (1,792 I1 inputs and 1,927 I2 violations per 400,000).
`scrub_text_wide` fails to mask something `scrub_text` masks in 0 of 1,500,000 inputs (single scan:
79,822). Every leaking input of the chosen shape holds one of the four triggers of I3 (0 of 60,803
without one; the single scan leaves 29,535).

**3. Not changed.** `scrub_text`, `is_secret_key`, every signature, the API (two `pub fn`s), the
`is_secret_name` delegate, `scrub_embedded` as the one expression `scrub_text_wide(&strip_userinfo(text))`,
the Design 8 list of edited existing tests, DC1 and DC3 to DC6, and the host:port decision (the wide scan
never exempts). One alternative was measured and not taken: if the wide scan judged only the five words
as substrings, as the old second scan did, needle-only dotted host:port keys would stay exempt and DC3
and arm D3 would vanish; the gain is small (full 1M, leaks no trigger explains: 16 to 14) and the wide
scan's key test would stop being `is_secret_key_wide`, which AC4 and the docs rely on. Matt may take it.

**4. Minor findings.** F3 (DC5, DC6 are Minor): accepted, with the worst shape recorded in Residual risks
1. F4 (nested YAML under a standard-secret parent leaks through `scrub_text`): pre-existing, outside this
change, Residual risks 9. S1: the `safe_target` pin is added (AC28); the `commands.rs` pin is a tests-only
follow-up (Residual risks 10). S2: the `patterns()` doc edit is accurate and doc-only, now Design 9 item
11. S3: closed by I4. Q1 to Q5: Design 9, AC20 and the plan's Fix tasks. Fix tasks may edit tests that
this branch added; no pre-existing test is edited beyond Design 8's list.

## Intent

PR 171 made `aitm-core`'s `redact.rs` the one secret-key vocabulary and rewrote `scrub_text`'s
pair pass as a linear, quote-aware scan, but it left the scanner alone on purpose. The scanner
still carries a copy of the same five words (`EXTRA_SECRET_NEEDLES`), a second `key=value` scan
(`redact_needle_pairs` and its helpers) run over the output of the first, and doc comments that
are now false (`scrub_text` "only knows api_key / token / ..."). The two scans disagree on where
a value ends, so every future fix to the reviewed core scan has to be mirrored by hand or the PoC
path silently diverges, and core's host:port exemption is quietly undone for the PoC path. This
change keeps the scanner's deliberately wider reading of names, moves it into core beside the one
list it is derived from, deletes the scanner's scan, and fixes the comments. It is a refactor with
a security edge: PoC output must not get weaker except where this spec lists it.

## Goals

- The five session/auth words exist as one list in non-test code: core's `SECRET_KEY_SEGMENTS`.
  The scanner holds no word list.
- `mask_secret_pairs` in core is the only `key=value` scanner. The scanner crate has none.
- `scrub_text` and `is_secret_key` return byte-for-byte what they return today, for every input.
- `scrub_embedded` returns what it returns today, except the deliberate changes DC1-DC6 below
  and the exotic class-D residual of Residual risks 8, which nobody asked for and no test pins.
  Every deliberate change is named with the tests it touches (none of the 178 existing assertions).
- `scrub_text_wide` masks everything `scrub_text` masks (it runs the standard scan first), and a
  standard-secret pair nested under a wide-only key is masked as it is today (Amendment 1, F1).
- The scanner's name decisions (`is_secret_name`: injection-point redaction in `enumerate`, PoC
  placeholders in `Scrubber`) are identical by construction, and are now pinned by tests (today
  almost nothing pins them).
- Every stale doc comment that describes the scanner's second vocabulary or second scan is fixed.
- The core API grows by exactly two functions, additively.

## Non-goals

- Changing `scrub_text` or `is_secret_key` behaviour, or the standard vocabulary, or core's rules
  for where a key, value or quote begins and ends under the standard reading. (PR 171
  panel-reviewed them.) The one place the wide scan departs from those rules is the blank rule
  beside a separator (Design 4); the standard scan is untouched.
- Fixing nested YAML under a standard-secret parent (`auth:\n  password: hunter2` leaks through
  plain `scrub_text`, before and after this change; Residual risks 9).
- Changing any caller of plain `scrub_text`: `crawl.rs` (`safe_target`), `commands.rs` (every
  free-text output string), findings, audit, MCP. Their output must not move.
- Moving `strip_userinfo` out of `crawl.rs`. URL userinfo is URL structure, not vocabulary; core's
  scan does not strip it, and `scrub_embedded` must keep stripping it first.
- Making the wide reading exempt host:port, or making the redactor URL-aware. (Residual risk 3.)
- Editing the historical, approved specs and plans that describe the superseded scanner design
  (`2026-10-30-aitmproxy-scanner-active-backend-{design,plan}.md` mention `POC_EXTRA_NEEDLES`, which
  no longer exists in the tree; the audit-ring spec and plan name this follow-up).
- Editing `crates/aitm-poc/tests/builder.rs`, whose comments at ~523, ~646-648 and ~674 still say
  the shared `scrub_text` set "lacks jwt/sid" (stale since PR 171, but that is the PoC builder's
  comment, not the scanner's). Listed for a later docs sweep.
- New dependencies, `unsafe`, config keys, a new struct field, or a changed existing signature.
- Keeping a frozen copy of the old pipeline in the repository (see Equivalence strategy).

## Anti-goals

- A second scan "left in for safety", or a general hook (`scrub_text_with(closure)`) that lets
  every crate grow a private vocabulary again, which is exactly what PR 171 removed.
- `scrub_text`'s output moving for any caller. In particular, `authority=`, `author=`, `side=`,
  `inside=`, `sessions=`, `authenticated=` must stay readable everywhere the standard reading runs.
- A refactor that quietly weakens the PoC path. Anything that can leave more of a value in the
  clear than today is listed and argued: DC5 and DC6, each with a test that pins the new output, and
  the exotic class-D shapes of Residual risks 8, which no test pins (a test must not assert a leak).
- Editing an existing test's expected value to make it pass. Only the edits listed in
  Design 8 are allowed; a red existing test stops the Coder and goes back to the Architect.
- A wide reading that is used for MCP argument keys or human-facing free text.

## Constraints

- Public API of `aitm-core` is additive: two new `pub fn`s in `aitm_core::redact`. No new
  struct field, no changed signature, no `lib.rs` change (verified: `lib.rs` has
  `pub mod redact;` and no re-export of any `redact` item), so dependents need no edit.
- `aitm-plugin-scanner` already depends on `aitm-core` (`Cargo.toml`), has no `regex` and gets
  none; no `Cargo.toml` or `Cargo.lock` change. The workspace forbids `unsafe`.
- Linear time, no per-byte allocation. The vocabulary is consulted once per key run that is
  followed by a separator, per scan, with one lowercase allocation per such candidate, as today;
  `scrub_text_wide` runs two scans, so about twice that work.
- `scrub_embedded` keeps its order: `strip_userinfo` first (so `//auth:pw@host/x` cannot make the
  scan swallow the host), then `scrub_text_wide`. The `{{var}}` and payload handling in `Scrubber`
  is untouched: `scrub_embedded` is still applied per decoded component.
- Rust gate before any review: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  Tests that bind ports (`aitm-mcp`) run in the Terminal panel.

## Design

### 1. What I verified, and where it corrects the brief

1. **One list, two readings.** `EXTRA_SECRET_NEEDLES` is `["sid","jwt","csrf","session","auth"]`
   and core's `SECRET_KEY_SEGMENTS` is `["sid","jwt","csrf","session","auth"]`. Core matches them
   as whole alphanumeric segments; the scanner matches them as ASCII-case-insensitive
   substrings. There is no word to promote; the delta is the matching mode.
2. **Promoting the mode into the default is not safe** (Option A). `"authority"` appears 65 times
   as a string in the tree: it is an argument of `request.send` and `flow.mutate` and an output
   field of `flow.list`, `flow.get`, `flow.table` and `flow.detail`
   (`aitm-plugins/src/{mutate,capture,detail}.rs`), and it is used in the MCP tests. Under
   substring semantics the audit ring's `args_summary` (which drops the value of any secret-named
   key) would drop the target host of every `request.send` and `flow.mutate`. Config key
   `rhai.allow_agent_authoring` contains `auth`; `side`, `inside`, `sidebar`, `sessions` are also
   real names. Core's `is_secret_key_leaves_lookalikes_alone` and
   `scrub_text_leaves_lookalike_pairs_alone` pin the lookalikes as not secret.
3. **The oracle is thinner than 178 suggests on the wide path.** Of the 178 scanner tests, the
   only assertion that separates the wide reading from the standard one is
   `scrub_embedded("subsidiary=acme") == "subsidiary=[redacted]"`. Every other secret name in
   them (`sid`, `jwt`, `csrf`, `session`, `auth`, `x_sid_y`, `X-CSRF-Token`, `PHPSESSID`) is a
   whole-segment or needle match that core's standard reading already catches since PR 171.
   `is_secret_name`'s wide-only decisions (`author`, `sidebar`, ...) are pinned by no test, and no
   scanner test checks that the scanner's scan is linear (core's tests carry that evidence).
   So Task 1 must add pins on the unmodified tree before anything is deleted (Design 7).
4. **The old host:port exemption is defeated for every key containing a segment word.** In the old
   pipeline core's pass exempts `auth.example.com:8443`, then the scanner's pass (no exemption)
   masks it, so `scrub_embedded("https://auth.example.com:8443/login")` is
   `https://auth.example.com:[redacted]` (the path is eaten too: the scanner's unquoted value runs
   to whitespace or a delimiter). The exemption survives only for needle-only dotted keys such as
   `token.example.com:8443`. The right frame is therefore "keys that contain a segment word",
   not "wide-only keys".
5. **Two of the differences also affect the five words themselves** (`sid`, `jwt`, ...), not
   only wide-only keys: a value containing a vertical tab or Unicode whitespace (DC5) and an
   unclosed quote followed by an opener-shaped quote (DC6). The old pipeline masked those
   further for the five words only because the second scan re-masked the first scan's output with
   its own, more generous value rule (the new wide scan shares core's value rule).
6. **Core's `lib.rs` needs no change.** The new functions are reached as
   `aitm_core::redact::{is_secret_key_wide, scrub_text_wide}`, like the existing two.
7. **`is_secret_name` is identical to the new wide predicate** by definition:
   `is_secret_key(name)` or the ASCII-lowercased name contains any of the five words.
   The scanner's `names_a_secret` is the same substring test over the five words alone.

### 2. The decision: C, one list read two ways, in core

Core keeps the one list (`SECRET_KEY_SEGMENTS`) and gains the wide *reading* of it next to the
list: `is_secret_key_wide` (names) and `scrub_text_wide` (the standard scrub, then a second scan of
the same function judging keys by that reading; Design 4). The scanner deletes its list, its
predicate body, and its scan, and calls those two.
The wide reading is derived from `SECRET_KEY_SEGMENTS`, so a word added there widens both readings
and nothing in the scanner can drift from it.

| Option | What it is | Why it loses (or wins) |
|---|---|---|
| A | Promote substring matching of the five words into the shared default | Newly masks `authority` (a real `request.send` / `flow.mutate` argument), `side`, `inside`, `sidebar`, `sessions`, `authenticated`, `rhai.allow_agent_authoring`; changes `scrub_text` output for the audit ring, findings, MCP error text and scanner free text (violates the brief's constraint); contradicts core's two lookalike tests. Rejected. |
| A2 | Make only the pair pass of `scrub_text` wide, keep `is_secret_key` standard | Same output change for every `scrub_text` caller, and the pass would then disagree with `is_secret_key`, which core's `scrub_text_and_is_secret_key_share_one_vocabulary` forbids. It would also mask `?author=3` (WordPress author enumeration) in `scan.discover` endpoint strings, which are keys of `endpoint_flows`. Rejected. |
| B | `scrub_text_with(text, extra: impl Fn(&str) -> bool)` (or `&[&str]` needles) | Works, but the scanner keeps a copy of the five words and its own predicate (drift: a word added to core is not added to the scanner's substring reading), and a public hook invites the private vocabularies PR 171 removed. A needle list cannot express a segment mode at all. Rejected; it is the nearest runner-up. |
| **C** | **Core owns list and both readings; two `pub fn`s** | **Chosen.** The five words live once, the wide reading cannot drift, the scanner shrinks by ~130 lines, API surface is two functions with fixed meanings. |
| D | Scanner drops its widening, uses the standard reading everywhere | Changes an asserted output (`subsidiary=acme`), weakens `enumerate` and PoC placeholder decisions the scanner chose on purpose ("a redacted example costs nothing, a leaked session id does"). Not a refactor. Rejected. |
| E | Keep two scans, export core's `ends_value`/`closing_quote` helpers to the scanner | Two scans remain, the second still runs over the first's output, more public surface, and host:port still diverges. Rejected. |
| F | A public `Reading` enum with `scrub_text_in(text, reading)` | More public surface than the two readings that exist. Revisit only if a third reading appears. Rejected. |
| G | C as first written: `scrub_text_wide` is one scan with the wide key test | Reviewed and rejected by the Stage 6 panel (F1, Amendment 1): a wide-only key's value region swallows a nested standard key and leaves its value (`authentication:\n  password: hunter2`). Replaced inside C by the two-scan seam of Design 4. |

The split of callers stays exactly as it is today: **names and PoC-embedded values use the wide
reading; free text that goes to agents, findings, audit and `scan.*` results uses the standard
reading.** Reason: free text routinely carries `authority=`, `author=3`, `side=left`, and a
`scan.discover` endpoint URL is a map key that must stay equal to the captured flow's URL.

### 3. The API added to core (exact)

In `crates/aitm-core/src/redact.rs`, both `pub`, both documented:

```rust
pub fn is_secret_key_wide(key: &str) -> bool
pub fn scrub_text_wide(text: &str) -> String
```

- `is_secret_key_wide`: true when `is_secret_key(key)` is true, or when the ASCII-lowercased key
  contains any `SECRET_KEY_SEGMENTS` word as a substring (`author`, `authority`, `sidebar`,
  `subsidiary`, `inside`, `sessions`, `userSession` read as secret). One lowercase allocation.
  Doc intent: for decisions where a false positive costs nothing and a miss leaks (a shareable PoC,
  an injection-point example); never for MCP argument keys, audit summaries or text a human reads,
  because `authority` is a real argument key. `is_secret_key(k)` implies `is_secret_key_wide(k)`.
- `scrub_text_wide`: the two regex passes first (`Authorization` line, `Bearer` token), then the
  pair scan with the standard reading (exactly `scrub_text`'s), then the same pair scan again with
  the wide reading over its output (see 4). So it masks everything `scrub_text` masks, and then
  every pair whose key reads as secret under `is_secret_key_wide`. The wide scan has **no host:port
  exemption** and does not skip `\n`, `\r` or `\x0c` beside a separator. Doc intent: over-redacts by
  design; says it is two scans of one function, names the three places the second scan differs from
  the first (key test, host:port exemption, line breaks beside a separator) and says everything else
  (value rule, quotes, nested pairs) is shared; says in one sentence that a non-ASCII letter glued
  into a key, or a non-ASCII space beside a separator, can make the wide scan read a wider pair than
  the standard one and let a wide-only pair nested right after it keep its value (Residual risks 8).
- `is_secret_key` and `scrub_text` keep their signatures and, byte for byte, their behaviour.

### 4. One scan function, two readings, two passes (private seam)

`scrub_text` is the two regex passes, then the private scan `mask_secret_pairs` with the standard
reading. `scrub_text_wide` is the two regex passes, then the same scan with the standard reading,
then the same scan again with the wide reading over its output. (Equivalently, `scrub_text_wide(x)`
is the wide scan applied to `scrub_text(x)`.) Both entry points are thin over private code, and
`scrub_text`'s output is byte for byte what it is today. `mask_secret_pairs` gains one parameter: a
private two-variant `Reading` (`Standard` | `Wide`), or an equivalent such as a predicate pointer
plus flags (builder's call).

**Why two scans (F1, Amendment 1).** A wide-only key masks its value as one region. If that region
ends between a nested standard-secret key and its value, a single wide scan swallows the nested key
and leaves its value (`authentication:\n  password: hunter2`, `sidebar=sid="C1"`). Run first, the
standard scan masks the nested pair before the parent's region can hide it, which is the order the
old pipeline had. Because the second scan only replaces values with `[redacted]`, `scrub_text_wide`
masks everything `scrub_text` masks. A single wide scan was the first design of this spec and failed
that and I1/I2 (Amendment 1).

**The parameter is consulted in exactly three places:**

1. the secret test of a key run: `is_secret_key` (Standard) or `is_secret_key_wide` (Wide);
2. the host:port exemption: applied for Standard, never for Wide;
3. the blank rule beside a separator, in one private helper (`skip_pair_blanks`) used at both skips
   (after the key run and its optional closing quote, and after the separator): Standard skips every
   whitespace character as core does today; Wide skips every whitespace character **except** the
   three ASCII characters `\n`, `\r` and `\x0c`, which it leaves in place (F2, below).

It is not consulted anywhere that decides where a key run, a separator, a value's end or a closing
quote lies; its one effect on where a value starts is the third, which makes the wide scan find no
value after a line break. That is what "one pair scanner" means here: one function, one key-run
rule, one value rule, one closing-quote rule, run twice; the two readings differ in three declared
places and in nothing else. A reviewer checks it by counting the parameter's uses (three).

**The blank rule of the wide scan (F2, Architect's call).** The old second scan read a pair on one
line: its blanks were space and tab, so a newline after a separator left an empty value and the scan
went on to see the next line's key. Core's blanks include newlines (so that `sid:\nabc` is masked).
Run second with core's blanks, the wide scan crosses the line and takes the next line's first token
as the value; that value ends mid-pair and swallows a nested wide-only key
(`authentication:\n  sessionKey: abc123`). Leaving `\n`, `\r` and `\x0c` where they are restores the
old reading exactly for every line-break shape, and it is the smallest rule that does: the other
whitespace characters still skip, so a value that starts with a non-ASCII space or a vertical tab is
still masked, which a rule of "space and tab only" would stop doing. The table in Amendment 1 holds
the numbers for each candidate rule. Standard keys are unaffected: the first scan still reads across a
line break, so `sid:\nabc` is masked.

**Host:port decision (Architect's call).** The wide scan never exempts. Old behaviour: exempt only
for keys with no segment word (`token.example.com:8443`), masked for every key with one
(`auth.example.com:8443`, the common case). The first scan exempts as `scrub_text` does; the second
never does, and it judges needle-only keys too, so a needle-only dotted key before a port
(`token.example.com:8443/x`) is now masked in a PoC-embedded value (DC3), which was the pre-PR-171
behaviour. Never exempting reproduces the common case exactly and is the crisp rule for an
over-redacting reading. Alternatives, if Matt prefers zero change: exempt in the wide scan iff the key
contains no segment word, or have the wide scan judge only the five words as substrings, as the old
second scan did (Amendment 1, item 3); either removes DC3 and arm D3.

### 5. The differences between the old pipeline and the two-scan wide scrub

Old pipeline: P1 = `scrub_text` (two regexes, then core's pair scan with the standard predicate),
then P2 = the scanner's `redact_needle_pairs` over P1's output with the five-word substring
predicate. New: the two regexes, then core's pair scan with the standard predicate (P1 unchanged),
then core's pair scan again with the wide predicate over its output (the new P2). The "old" column
below is derived by reading `15009b2`; **Task 1 records the real outputs by running the old
code**, and a mismatch with this table stops the Coder (spec gap).

| # | Aspect | Old (P1 core, then P2 scanner) | New (standard core scan, then wide core scan) | Direction | Verdict | Example, old to new | Pinned by |
|---|---|---|---|---|---|---|---|
| 1 | Vocabulary | five words as substrings, others as core | `is_secret_key_wide`: same set | none | identical | | AC4, AC13 |
| 2 | Key run | P2: ASCII run only; a non-ASCII char ends it | core: non-ASCII non-whitespace chars continue the run | masks at least as much | accept (DC1) | `xsidéy=v` to `xsidéy=[redacted]` | AC15 |
| 3a | `\n`, `\r` or `\x0c` beside a separator | P2: not a blank, so the pair has no value on its line | wide scan: not a blank either | none | identical | `author:\nJohn` unchanged; `authentication:\n  sessionKey: abc123` to `authentication:\n  sessionKey: [redacted]` | AC14, AC27 |
| 3b | Other whitespace beside a separator (non-ASCII whitespace, vertical tab) | P2: space and tab only | wide scan: skipped as core skips it | masks at least as much (`sidebar\u{a0}:\u{a0}v`), or same exposure with different bytes (`sidebar=\u{b}v`) | accept (DC2) | `sidebar\u{a0}:\u{a0}v` to `sidebar\u{a0}:\u{a0}[redacted]`; `sidebar=\u{b}v` from `sidebar=[redacted]` to `sidebar=\u{b}[redacted]` | AC15, AC5 |
| 4 | End of an unquoted value | P2: `is_ascii_whitespace` (no vertical tab) and delimiters; non-ASCII never ends | core: also vertical tab and Unicode whitespace | **masks less** | accept (DC5) | `sid=abc\u{a0}def` to `sid=[redacted]\u{a0}def` | AC15 |
| 5 | Closing quote, both close | P2: first unescaped quote | core: skips an opener-shaped quote (after `=`/`:`, followed by a value char) | same exposure, different bytes | accept (DC4) | `sidebar='abc def token='S3'` to `sidebar='[redacted]'` | AC15, AC5 |
| 6 | Closing quote, core finds none | P2 closes at the opener-shaped quote | core falls back to the plain unquoted rule and remembers the failed search | **masks less** | accept (DC6) | `sid='abc def token='S3` to `sid='[redacted] def token='[redacted]` | AC15 |
| 7 | host:port | P1 exempts; P2 re-masks it for any key with a segment word | first scan exempts as P1; wide scan never exempts | masks at least as much | five-word keys unchanged (AC14); needle-only keys accept (DC3) | `token.example.com:8443/x` to `token.example.com:[redacted]` | AC6, AC14, AC15 |
| 8 | Pairs nested in a value | P1 masks a nested standard pair, P2 then masks the value | the first scan masks a nested standard pair, the wide scan then masks the value | none | identical (the single-scan first design of this spec was not: F1) | `author=password=S3` to `author=[redacted]`, and `sidebar=sid="C1"` to `sidebar=[redacted]"[redacted]"`, both old and new | AC14, AC25 |
| 9 | Empty value; scan resumption after a non-secret key | resume after the key run | resume after the key run | none | identical | `sid=&password=x` | existing tests, AC14 |

Direction in one sentence: **what can leave more of a value in the clear than today is DC5 and DC6
(malformed or exotic input, accepted) and class D (three exotic arms that need a non-ASCII character
or a needle-named dotted host:port, Residual risks 8); nothing that a well-formed input can do.** Well
formed means the aligned alphabet of Design 7 (ASCII, balanced quotes, no vertical tab, no form feed,
no `key:digits` host:port, line breaks allowed anywhere): there the new output equals the old output
byte for byte (I2). The first wording of this paragraph said that only DC5 and DC6 could leave more
and that I2 held; both were false for the single-scan first design, whose counterexamples were well
formed: `authentication:\n  password: hunter2` and `sidebar=sid="C1"` left `hunter2` and `C1` in the
clear (Amendment 1).

DC5 and DC6 are malformed or exotic input (a credential that itself contains a vertical tab or a
non-ASCII space; a quote that is never closed), where the new output equals what the standard
reading has always done for `password`, `token` and every other needle key (PR 171 Residual risks
12-14). The old pipeline was stronger there only for keys that contain one of the five words (for the
five words themselves because a second scan re-masked the first scan's output, for wide-only keys
because the second scan was the only one that saw them), never for `password`, `token` or any other
needle key, so the PoC path was inconsistent (`sid='abc def ...` masked further than
`password='abc def ...`).

**Fallback, not built:** had the security panel rated DC5 or DC6 Important, the fix was one branch
confined to the wide scan (a lenient unquoted-value end, or a fall-back to the first unescaped quote
when the opener-aware search fails), which reintroduces a second value rule. The panel rated them
Minor (F3), so it stays unbuilt.

### 6. Every deliberate output change

All are in `scrub_embedded` (so in PoC-embedded values: Referer, header values, JSON string
leaves, form values, untyped bodies). None changes a name decision, `scrub_text`, or a `scan.*`
free-text output.

| ID | Change | Affects | Direction | Existing tests touched |
|---|---|---|---|---|
| DC1 | A key run glues across non-ASCII characters, so a secret word inside it counts (`xsidéy=v`); residual arm D1 | wide-only keys | more masked | none (no existing input has a non-ASCII char glued to a key) |
| DC2 | A vertical tab or a non-ASCII whitespace character may sit beside the separator (`sidebar\u{a0}:\u{a0}v`, `sidebar=\u{b}v`). A line break or form feed may not: the wide scan keeps `\n`, `\r`, `\x0c` as a boundary, so `author:\nJohn` is unchanged and is not a change; residual arm D2 | wide-only keys (the five words already behaved so through P1) | `sidebar\u{a0}:\u{a0}v` more masked; `sidebar=\u{b}v` same exposure, different bytes | none |
| DC3 | A needle-only dotted key before a port is masked (`token.example.com:8443/x`); residual arm D3 | needle-only dotted keys | more masked | none |
| DC4 | A quoted value holding an opener-shaped quote closes at the real closer (`sidebar='abc def token='S3'`) | wide-only keys | same exposure, shorter output | none |
| DC5 | An unquoted value ends at a vertical tab or a non-ASCII whitespace char | the five words and wide-only keys | **less masked** | none |
| DC6 | An unclosed quote with only opener-shaped later quotes ends at the plain unquoted rule | the five words and wide-only keys | **less masked** | none |

"None": I read every existing `scrub_embedded` and `build_poc` assertion in `reproduce.rs`. The only
non-ASCII input is `h\u{e9}llo sid=w\u{f6}rld \u{fc}n\u{ef}` (ASCII key, value ends at a plain
space, unchanged); the unclosed-quote input `sid="abc&x=1` has no later quote (unchanged); no input
has a newline before a separator, a dotted key before a port, a vertical tab, or an opener-shaped
quote. AC16 proves it by running them.

### 7. Equivalence strategy

The old pipeline is **not** kept in the repository: it would keep alive the names AC17 deletes,
freeze ~130 lines of code nobody maintains, and its job is one-time evidence. The evidence is data:

1. **Pin before you cut (Task 1, on the unmodified tree at `15009b2`, all green).** Add tests that
   pass on the old code and must still pass on the new: the recorded-output corpora of AC8 and
   AC14, and the name-decision pins of AC11-AC13. Outputs are recorded by running the old code, not
   written by hand, and the Coder pastes the run into its report.
2. **Swap, then flip.** After the swap the same tests must be green unchanged; the DC rows of
   AC15 are written against the old code's recorded outputs (kept in comments) and are red until
   the swap.
3. **Panel differential, out of tree (amended: Amendment 1).** The security reviewer builds the old
   pipeline from `15009b2` and the new pipeline from the head under review, each in a scratch tree, and
   runs `old(scrub_embedded)` against `new(scrub_embedded)` on at least 3,000,000 generated inputs
   (PR 171's panel used 3M), plus the extra runs of I4 and I5, and records counts and results. The
   first run of this differential (on `bcd9647`, the single-scan design) is what found F1; its kept
   scripts are in `/tmp/claude-501/svc-diff-tools/`.
   - **Aligned alphabet (amended)** = ASCII keys from {the five words, needles, wide-only words such as
     `author`, `authority`, `sidebar`, `subsidiary`, `inside`, `userSession`, non-secret words},
     case variants, optional `x-`/`_id`/`.v1` affixes, a dotted key allowed but no `key:digits`
     host:port shape; `=` or `:` with space/tab padding and optional key quotes; values that are
     unique ASCII canaries, bare (no whitespace, no `& ; , " ' }`) or quoted with a matched quote
     and escapes; empty values; pair delimiters `& ; , } { [ ] / ?`, spaces, tabs, `\n`, `\r`; a pair
     nested in a non-secret key's value; **a line break (`\n`, `\r`, `\r\n`) directly before or after a
     separator is now allowed, including an empty value followed by a line break and parent/child pairs
     on separate lines (`parent:\n  child: value`, any mix of standard, needle and wide-only keys)**;
     still no vertical tab, no form feed, no non-ASCII byte, no unmatched or unescaped inner quote, no
     `key:digits` host:port. The kept `difftool.py` excludes a line break at a separator in three
     places (the `[=:][ \t]*[\r\n]` check in `aligned_ok`, and two `last_empty` line-break guards in
     `compose_aligned`); the reviewer lifts them in a scratch copy. (The Architect did, and measured 0
     violations on 1,000,000 inputs for the chosen design, so the invariant is satisfiable.)
   - **I1 (no regression).** On the aligned alphabet, every canary absent from `old(x)` is absent
     from `new(x)`. Zero violations.
   - **I2 (equality).** On the aligned alphabet, `new(x) == old(x)` byte for byte. Zero violations.
     (DC1 to DC6 each need something outside the alphabet.)
   - **I3 (full alphabet).** No panic, no char-boundary error; linear time (on each hostile family,
     the time at 2, 4 and 8 MiB is at most 3.0 times the time at the previous size, and
     `scrub_text_wide` takes at most 4 times what `scrub_text` takes on the same input, about 2
     expected); and every canary that `new` leaves while `old` masked is in an input that holds at
     least one **trigger**: T1 a vertical tab or a non-ASCII whitespace character (DC2, DC5, arm D2);
     T2 a non-ASCII character that is not whitespace, directly beside an ASCII key character (DC1, arm
     D1); T3 an unclosed or unmatched quote, or an opener-shaped quote (DC4, DC6); T4 a dotted key
     directly before `:` and one to five digits (DC3, arm D3). A leak in an input with none of the four
     is a finding. The reviewer also minimizes (deletes characters while some canary still leaks in `new`
     and not in `old`) at least 25 leaking inputs per trigger kind and groups the minimal reproducers;
     every group must be DC5, DC6, D1, D2 or D3, and a group outside them is a finding. (The kept tool's
     trigger test knows only T1 and T3; the reviewer adds T2 and T4.)
   - **I4 (the untouched functions).** `scrub_text` over at least 3,000,000 fresh inputs, and
     `is_secret_key` over at least 1,000,000 keys, equal the old tree's outputs (zero differences);
     `is_secret_name` equals the old scanner predicate over at least 1,000,000 keys. (Closes S3; the
     fix edits the shared scan, so it is re-run.)
   - **I5 (superset).** On at least 1,500,000 inputs of the full alphabet and the nested shapes, every
     canary absent from `scrub_text(x)` is absent from `scrub_text_wide(x)`. Zero violations.
   - Any violation of I1, I2, I4 or I5 is a finding. A counterexample that shows this spec's table
     wrong is a finding against the spec, not the code.
4. **Mutants (Tester).** AC23.

### 8. What the scanner deletes, keeps, and edits

**Deleted:** in `discover.rs`: `EXTRA_SECRET_NEEDLES`, the body of `is_secret_name`. In `reproduce.rs`:
the `EXTRA_SECRET_NEEDLES` import, and `is_key_byte`, `ends_value`, `names_a_secret`,
`redact_needle_pairs`, `closing_quote` (the block at ~383-508).

**Kept, now thin:**
- `discover::is_secret_name(name: &str) -> bool` stays `pub(crate)` as a one-line delegate to
  `is_secret_key_wide`, so its four call sites (`enumerate`, three in `Scrubber`) and the tests that
  name it stay untouched. It holds no list. (Architect's call; deleting it means editing four call
  sites and two tests for no gain.)
- `reproduce::scrub_embedded(text: &str) -> String` stays a private fn whose body is the single
  expression `scrub_text_wide(&strip_userinfo(text))`. `use aitm_core::redact::scrub_text` stays
  (`scrub_url` uses it); `scrub_text_wide` is added to that import.
- `crawl.rs` and `commands.rs` are not edited at all (empty diff).

**Tests edited (the complete list; everything else is untouched):**

| Test | File | Edit | Reason | Replacement assertion |
|---|---|---|---|---|
| `scrub_embedded_covers_every_extra_secret_needle` | `reproduce.rs` | renamed `scrub_embedded_covers_every_segment_word`; body iterates the literal `["sid","jwt","csrf","session","auth"]` instead of `EXTRA_SECRET_NEEDLES` | it names a deleted constant | the same three assertions per word: `is_secret_name(word)`; `scrub_embedded("x_{word}_y=V1&z=2") == "x_{word}_y=[redacted]&z=2"`; `scrub_embedded("{WORD}: V1") == "{WORD}: [redacted]"`. The literal list is deliberate (a dropped word must fail), as core's `is_secret_key_names_every_substring_needle` does. Its doc comment drops "built from the very slice". |
| `build_poc_drops_the_referer_query_and_leaks_no_session_id` | `reproduce.rs` | doc comment only (~1315) | says none of the names "is in `scrub_text`'s", false since PR 171 | reword as history ("before PR 171 none was..."); no assertion changes |
| `build_poc_scrubs_session_ids_embedded_in_a_non_secret_header` | `reproduce.rs` | doc comment only (~1372) | "The needle layer on its own" names a deleted layer | reword to "the embedded-value scrub on its own" |
| `scrub_embedded_masks_every_shared_vocabulary_name` | `reproduce.rs` | one inline comment (~1510) | "one pass, two vocabularies" | reword to one list, read by the wide scrub (Task 3 wrote "one scan, one list"; Amendment 1 corrects it, Design 9 item 8) |
| `enumerate_redacts_common_auth_parameter_names` | `discover.rs` | doc comment only (~537) | "outside the shared vocabulary" is false since PR 171 | reword; no assertion changes |

### 9. Comments and docs to fix (the complete list)

Core, `crates/aitm-core/src/redact.rs`:
1. Delete the two pointer comments: the `//` block above `ends_value` (~191-194) and the one above
   `closing_quote` (~233-236). Their `///` docs stay and need no edit (they do not mention the scanner).
   (Done in Task 2.)
2. Module doc (~1-24): one list, two readings; `scrub_text` and `scrub_text_wide` named;
   `scrub_text_wide` is the standard scan then the wide scan, so it masks everything `scrub_text`
   masks; the wide scan differs from the standard one in three declared places (key test, host:port
   exemption, line breaks beside a separator) and shares everything else. **The Stage 6 panel named
   two false passages, rewritten by this amendment:** the module doc's "a scrubber and its predicate
   cannot diverge, and both readings share one pair scanner, so the two scrubbers differ in that
   predicate and in the host:port exemption, and in nothing else" (~21-24), and the
   `scrub_text_wide` doc's "the only two differences from `scrub_text`" (~156-164). A scrubber judges
   each key *run* by the predicate of its reading; it does not judge every string the predicate
   accepts (`user[sid]` is one string but two key runs, and the pair `user[sid]=v` has no `key=`
   framing), so the docs say "judges a key run by", never
   "cannot diverge" or "cannot disagree" (Q1).
3. `SECRET_KEY_SEGMENTS` doc (~45-49): add that the same words are what the wide reading matches as
   substrings. (Done in Task 2.)
4. `scrub_text` doc: one sentence pointing to `scrub_text_wide` for the over-matching reading; the
   host:port paragraph stays (it describes the standard reading). (Done in Task 2.)
5. `mask_secret_pairs` doc: say the reading parameter is consulted in exactly three places (the
   secret test, the host:port exemption, `skip_pair_blanks`) and nowhere that decides where a key
   run, separator, value end or closing quote lies. The `Reading` enum docs say the variants are the
   readings of the first and the second scan.
5b. `scrub_text_wide` doc: rewritten as Design 3 describes (two scans, superset, three differences,
   linear at about twice `scrub_text`, one sentence on the class-D residual).
5c. Rename two private helpers to the `is_*` / `contains_*` convention (Q5): `holds_secret_word` to
   `is_secret_lower`, `holds_segment_word` to `contains_segment_word`. Three call sites, no test
   names them.

Scanner, `crates/aitm-plugin-scanner/src/`:
6. `reproduce.rs` module doc (~17-22): `scrub_embedded` is "URL userinfo stripped, then
   `aitm_core::redact::scrub_text_wide`", not "`scrub_text` plus the same widened name vocabulary";
   say "a narrower reading", not "a narrower list", and reflow the ragged wrap at lines 22-23 (Q1).
7. `scrub_embedded` doc (~362-373): rewrite. The three-step description and the claim that
   `scrub_text` alone "only knows api_key / token / ..." are false, and so is "the two scrubs cannot
   disagree about which names are secret": say that both judge a key by the same predicate (Q1).
8. The five test comments in Design 8, and more (Q2, Q3, and the "one scan" wording), all on tests
   this branch added or already in the Design 8 list: the inline comment in
   `scrub_embedded_masks_every_shared_vocabulary_name` (~1380) and the doc of
   `scrub_embedded_reads_the_edges_of_the_text` (~1958) say "one scan"; they say "one list, read by
   the wide scrub" and "as the wide scrub reads" instead; `build_poc_drops_the_referer_query_and_leaks_no_session_id` says
   `scrub_text` alone did not know these names until PR 171, so a `Referer` scrubbed by it alone was
   emitted verbatim, and the embedded-value scrub must mask all of them (not that shipped PoCs leaked
   until PR 171: the scanner's second scan landed with that test); the doc of
   `scrub_embedded_deliberate_changes_are_exactly_these` says "one row per change, DC1 to DC6 of the
   spec (`docs/superpowers/specs/2026-10-31-scanner-vocab-consolidation-design.md`); every row of
   `RECORDED_SCRUB_EMBEDDED` is unchanged", drops "the only ones whose output differs" (it is false:
   `sid=abc\u{2028}def` also changes) and says what is pinned, the recorded output of the old two-scan
   pipeline at `15009b2`, instead of "before ..." phrases; the same rewording for the doc of
   `scrub_embedded_matches_the_recorded_pipeline_output` and for the section comment above the first
   pin test ("Pins taken before ...").
9. `discover.rs` module doc (~8-15): "widened locally by `is_secret_name` with the common auth
   parameter names" becomes the wide reading in core. The `EXTRA_SECRET_NEEDLES` doc goes with the
   const. The `is_secret_name` doc is rewritten: a delegate, "so `reproduce`'s PoC scrubber masks
   exactly the names `enumerate` redacts".
10. No comment in the scanner may name a deleted item (`EXTRA_SECRET_NEEDLES`, `redact_needle_pairs`,
    `names_a_secret`, `ends_value`, `closing_quote`, `is_key_byte`); AC17 greps for it.
11. (S2, accepted) the `patterns()` doc in core was edited to name both entry points (commit
    41b91a0 of this branch). The edit is accurate and doc-only, and is part of the list.

Not edited, by decision: the historical specs and plans named in Non-goals, the aitm-poc test
comments, and `docs/research/MEMORY.md` (it has no entry about redaction; grep found none).
`README.md` and `docs/` outside specs and plans have no text about the scanner vocabulary.

### 10. Semantics changes by surface

| Surface | Change |
|---|---|
| PoC from `scan.reproduce` / `build_poc` | Embedded-value text: DC1-DC6. Header, query, form and JSON key names and placeholder decisions: none |
| `scan.discover` examples and endpoints | none (same name decision; endpoint strings still use the standard reading) |
| `scan.passive`, `scan.report`, `scan.*` free text, findings, audit ring, MCP error text | none |
| `aitm-poc` `poc.build`, TUI, web, macOS app | none |
| Rust API | `aitm_core::redact::{is_secret_key_wide, scrub_text_wide}` added |

### 11. Rebase hazards

Files touched: `crates/aitm-core/src/redact.rs`; `crates/aitm-plugin-scanner/src/discover.rs`;
`crates/aitm-plugin-scanner/src/reproduce.rs`. Not touched: core `lib.rs`, `crawl.rs`, `commands.rs`,
any `Cargo.toml` or `Cargo.lock`, and no file outside those crates except this spec and its plan.
I looked for branches that change these three files relative to `15009b2` (`git diff --name-only
HEAD...<branch>` over every local and remote ref): the hits are `competent-cori-43f38a` (PR 171),
`scanner-active-build`, `scanner-plugin-stage1-8a18a1`, `scanner-w2`, `scanner-w3` and three `p67-*`
review branches. By name and history they are merged or finished work, not live sessions, but I did
not verify that branch by branch; the orchestrator should check `git worktree list` before
dispatch. The follow-ups that could
meet this one are "durable audit wiring" (touches `audit.rs`, `server.rs`, not `redact.rs`) and any
session appending tests to `reproduce.rs`'s `mod tests`, which is a plain append conflict. Keep the
window short: one writer per file, and rebase on `main` and re-gate before merge (CI tests the
branch plus current `main`, so a sibling's new `reproduce.rs` test can fail only there).

### 12. Residual risks

1. **DC5 and DC6 are weaker than today for malformed input** (Design 5). Accepted (F3, Minor): they
   equal the standard reading's reviewed behaviour, exposure needs a secret that itself holds a
   vertical tab or non-ASCII space, or a malformed quote; the fallback is named. The panel's worst
   shape is wider than "the tail": an unclosed quote directly followed by a vertical tab or a
   non-ASCII space leaves the whole value (`sid="\u{b}SECRET9` was `sid="[redacted]`, and
   `auth:"\u{a0}SECRET9` likewise), because the plain rule's value is empty there. `password`,
   `token` and `api_key` already behave that way in the old pipeline (`password="\u{b}SECRET9` is
   unchanged by both), so this is a consistency loss for the five words and wide-only keys, not a new
   class.
2. **PR 171 Residual risks 12-14 now also bind the PoC path for the five words and wide-only
   keys:** `password='x password'=S3CR3T` style leaks, a quoted key opener right after an unclosed
   quote, `token="token="S3CR3T`, and `Cookie: sid="S3CR3T"` (the `Cookie` pair's unquoted value
   stops at the quote). The old second scan did not close these either; unchanged.
3. **A dotted key containing a segment word before a port is still masked in PoC-embedded values**
   (`https://auth.example.com:8443/cb` becomes `https://auth.example.com:[redacted]`): unchanged
   readability cost, now also for needle-only dotted keys (DC3, with arm D3 of risk 8). A PoC step
   that embeds such a URL in a body does not replay faithfully. A URL-aware redactor is a separate
   change.
4. **Prose false positives get slightly wider for wide-only keys:** `Author:\u{a0}John` loses
   `John` (DC2). A line break no longer widens anything (`Author:\nJohn` is unchanged), unlike
   `auth:\nnext line`, which the standard scan has always masked for the five words.
5. **The wide reading is public.** Another crate could adopt it for audit keys and mask `authority`.
   The doc says not to; nothing enforces it. Core's own `authority` tests guard the standard reading.
6. **Literal five-word lists in tests do not fail when a word is added to core.** Same as PR 171's
   needle test; accepted. Core's `is_secret_key_wide_names_every_segment_word` is the one that names them.
7. **The panel differential is out of tree** and depends on `15009b2` staying reachable. If the
   branch is squash-merged the SHA is still in history.
8. **Class D: a wider pair can swallow a nested wide-only pair (F2).** Three exotic arms remain after
   the line-break rule. In each, the wide scan masks a region the old pipeline left alone, the region
   ends inside a nested *wide-only* pair, and that pair's value, which is quoted or padded, stays in
   the clear. A nested standard-secret pair is never affected: the first scan masks it first.
   Examples (old to new):
   - D1, a non-ASCII letter glued into a wide-only key (DC1): `authr\u{e9}=QAUTH:"Q7` from
     `authr\u{e9}=QAUTH:"[redacted]` to `authr\u{e9}=[redacted]"Q7`.
   - D2, a non-ASCII space beside a separator (DC2): `NSid\u{2009}:AUTHO:"Q8` from
     `NSid\u{2009}:AUTHO:"[redacted]` to `NSid\u{2009}:[redacted]"Q8`; `jwtv:\u{a0} sessions:\tQ9` from
     `jwtv:[redacted] sessions:\t[redacted]` to `jwtv:\u{a0} [redacted]\tQ9`.
   - D3, a needle-only dotted host:port key (DC3): `token.example.com:8443/x?sessions="Q5"` from
     `token.example.com:8443/x?sessions="[redacted]"` to `token.example.com:[redacted]"Q5"`.

   Exposure: a non-ASCII character (D1, D2) or a needle-named dotted host before a port (D3), and a
   wide-only key right behind it whose value is quoted or padded. Measured (scratch, full alphabet,
   1,000,000 inputs): 16 inputs leak something that no DC5 or DC6 trigger explains (the samples all hold
   a non-ASCII letter glued into a key), against 282 for the unrestricted two-scan shape and 7,283 for
   the single scan; every leaking input holds an I3 trigger. Accepted as Minor: no smaller rule exists
   (D1 and D3 are the key-run and exemption rules of DC1 and DC3, chosen on purpose; D2 is the half of
   DC2 that keeps a value led by a non-ASCII space masked). **No test pins one of these outputs**, since
   a test must not assert a leak; DC1, DC2 and DC3 keep their rows in AC15. The alternative that
   removes D3 is named in Design 4.
9. **Nested YAML under a standard-secret parent leaks through `scrub_text` (F4, pre-existing, outside
   this change).** `auth:\n  password: hunter2` is `auth:\n  [redacted] hunter2` through `scrub_text`,
   `scrub_embedded`, and the old pipeline alike (same for `credentials:`, `secret:`, `token:`,
   `session:`, `cookie:`): core skips a newline after a separator, so the child key is taken as the
   parent's value, and the same holds for `auth:\n  sessionKey: abc123`. Changing core's newline rule
   is a non-goal (Goal 3). Follow-up, recorded in the plan's Shipped section; it affects every plain
   `scrub_text` caller.
10. **The standard reading of scanner free text is pinned for `safe_target` only (S1).** Swapping a
    `commands.rs` free-text call to `scrub_text_wide` goes red nowhere. The pin belongs in
    `commands.rs`'s own test module, which AC18 forbids editing here: a tests-only follow-up, recorded
    in the plan's Shipped section.

## Acceptance criteria

`[red]` = fails on `15009b2` (does not compile or asserts new behaviour) and passes after.
`[guard]` = passes on `15009b2` (and is written and run there first) and must pass after, unedited.
Test names are exact; the Coder may add rows, never remove or weaken one.

Core, `crates/aitm-core/src/redact.rs` `mod tests`:

1. AC1 `[red]` `is_secret_key_wide_reads_the_segment_words_as_substrings`: for each of `author`,
   `authority`, `authenticated`, `inside`, `side`, `sidebar`, `subsidiary`, `sessions`, `Author`,
   `X-Authority`, `rhai.allow_agent_authoring`, `userSession`: `is_secret_key_wide` is true and
   `is_secret_key` is false. For `sid`, `X-CSRF`, `connect.sid`, `PHPSESSID`, `Authorization`: both true.
   For `path`, `host`, `body`, `note`, `method`, `page`, `q`, `username`, `next`, `Content-Type`,
   `Referer`: both false.
2. AC2 `[red]` `is_secret_key_wide_is_a_superset_of_is_secret_key`: over the union of core's existing
   secret-key and lookalike tables and every substring needle, `is_secret_key(k)` implies
   `is_secret_key_wide(k)`.
3. AC3 `[red]` `is_secret_key_wide_names_every_segment_word`: each of `sid`, `jwt`, `csrf`,
   `session`, `auth` spelled out, as the bare word, upper case, `x-{w}-y`, and `my{w}2`: all true.
4. AC4 `[red]` `scrub_text_wide_and_is_secret_key_wide_share_one_vocabulary`: the table of
   `scrub_text_and_is_secret_key_share_one_vocabulary` plus the wide-only keys of AC1: for each
   key, `is_secret_key_wide(key) == (scrub_text_wide("{key}=VALUE9") != "{key}=VALUE9")`.
5. AC5 `[red]` `scrub_text_wide_masks_a_wide_only_pair_as_a_standard_pair`: exact rows (value rule
   is core's, not a lenient one): `author=bob&page=2` to `author=[redacted]&page=2`;
   `{"subsidiary":"a b","n":1}` to `{"subsidiary":"[redacted]","n":1}`;
   `sidebar='x y' z=1` to `sidebar='[redacted]' z=1`; `author:\u{a0}John` to `author:\u{a0}[redacted]`
   (amended: the old row `author:\n  John` to `author:\n  [redacted]` is gone, a line break is a
   boundary, see AC27); `sidebar=abc\u{a0}def` to `sidebar=[redacted]\u{a0}def`;
   `sidebar='abc def token='S3'` to `sidebar='[redacted]'`;
   `{"sidebar":"YWJj=","user":"bob"}` to `{"sidebar":"[redacted]","user":"bob"}`;
   `next=/cb?sidebar=S1` to `next=/cb?sidebar=[redacted]`; `sidebar=&x=1` unchanged.
6. AC6 `[red]` `scrub_text_wide_does_not_exempt_a_host_port`: `auth.example.com:8443` to
   `auth.example.com:[redacted]`; `https://auth.example.com:8443/login` to
   `https://auth.example.com:[redacted]`; `token.example.com:8443/x` to
   `token.example.com:[redacted]`; `sid:12345` to `sid:[redacted]`. The existing
   `scrub_text_does_not_mask_a_host_port` (standard reading still exempts) is the paired `[guard]`.
7. AC7 `[red]` `scrub_text_wide_survives_hostile_inputs_and_stays_linear`: with `assert!` on `==`,
   not `assert_eq!`: `"sidebar=".repeat(1 << 19)` is `sidebar=[redacted]`; `"sidebar=\"x ".repeat(150_000)`
   masks every value; `"sidebar='x sidebar=\"x ".repeat(75_000)` masks every value;
   `"author.x:1 ".repeat(300_000)` is `"author.x:[redacted] ".repeat(300_000)`; a 1 MiB run of `é`
   and of `\u{a0}`, and `"sidébar=x ".repeat(100_000)`, return without panic. The test finishing is the check.
8. AC8 `[guard]` `scrub_text_is_unchanged_on_the_recorded_corpus`: at least 60 rows of
   `(input, output)` recorded by running `scrub_text` at `15009b2`. Families: every wide-only lookalike
   in each framing (`author:\nJohn`, `sidebar\u{a0}:\u{a0}v`, `xsidéy=v`, `subsidiary='a b'`); a
   standard key with a vertical tab and with a no-break space in an unquoted value; the DC4 and
   DC6 shapes with `sid`/`password`; host:port forms; non-ASCII-glued keys; `Authorization` and
   `Bearer` lines; ten short hostile strings. Passes on `15009b2` before any production edit.
9. AC9 `[red]` `scrub_text_wide_agrees_with_scrub_text_when_nothing_wide_applies`: every AC8 row that
   has no wide-only key and no dotted key before `:digit` gives `scrub_text_wide(input) == scrub_text(input)`.
   Proves the second scan changes nothing else on that corpus (a corpus test, not a theorem; the
   two-scan shape satisfies it on every such row).
10. AC10 `[guard]` (core) every one of the 32 existing `redact` tests passes and none is edited:
    `git diff 15009b2 -- crates/aitm-core/src/redact.rs` removes no line at or after the
    `#[cfg(test)]` line. The only `pub` change in that diff is the two added functions
    (`is_secret_key_wide`, `scrub_text_wide`); `is_secret_key` and `scrub_text` signatures are unchanged.

Scanner, `crates/aitm-plugin-scanner/src/`:

11. AC11 `[guard]` `discover::tests::enumerate_redacts_a_wide_only_parameter_name`: a flow
    `/x?subsidiary=acme&author=bob&sidebar=1&page=2` gives examples `<redacted>` for the first
    three and `2` for `page`. Written and green on `15009b2`.
12. AC12 `[guard]` `reproduce::tests::build_poc_placeholders_a_wide_only_parameter`: a GET
    `/search?q=hello&author=ALICE` built through `build_poc` has `author={{author}}` in the step URL,
    declares a required variable `author`, and the serialized PoC does not contain `ALICE`.
13. AC13 `[guard]` `reproduce::tests::scrub_embedded_and_is_secret_name_agree_on_every_key`: over a
    table of at least 40 ASCII keys (the wide-only keys, the five words, every needle,
    whole-segment and non-secret keys): `is_secret_name(k) == (scrub_embedded("{k}=VALUE9") != "{k}=VALUE9")`.
    ASCII only: a key with a non-ASCII character glued to a secret word (`xsidéy`) is DC1, where
    the two disagree today.
14. AC14 `[guard]` `reproduce::tests::scrub_embedded_matches_the_recorded_pipeline_output`: at least
    80 rows of `(input, output)` recorded by running the old `scrub_embedded` at `15009b2`: every
    input of the existing `scrub_embedded_*` and `build_poc_scrubs_*` tests, plus quotes, escapes,
    nested pairs, userinfo, empty values, `Authorization`/`Bearer`, `Referer`-shaped values,
    percent-decoded values, host:port rows for the five words (`auth.example.com:8443` stays masked),
    and malformed families. Rows that DC1-DC6 change are NOT in this test (they are AC15). A row
    whose new output differs and fits none of DC1-DC6 stops the Coder: it is a spec gap, not a row to
    move or drop. **Amended (Amendment 1): the corpus gains the fifteen F1/F2 rows below, recorded by
    running the old `scrub_embedded` in a scratch copy cut from `15009b2` (`git archive`, never the
    branch). All fifteen are `[red]` on `bcd9647` and green after the fix.** Expected old outputs, to
    be confirmed by that run (a difference stops the Coder, spec gap): `authentication:\n  password:
    hunter2` to `authentication:\n  password: [redacted]`; `author:\n  token: abc123` to
    `author:\n  token: [redacted]`; `sessions:\n  jwt: J1` to `sessions:\n  jwt: [redacted]`;
    `sidebar:\n    api_key: K1` to `sidebar:\n    api_key: [redacted]`; `authentication: {password:
    hunter2}` to `authentication: [redacted] [redacted]}`; `sidebar=sid="C1"` to
    `sidebar=[redacted]"[redacted]"`; `author=password='C2'` to `author=[redacted]'[redacted]'`;
    `inside=x?sid\t=\tC9` to `inside=[redacted]\t=\t[redacted]`; `Auths:Pwd: C` to `Auths:[redacted]
    [redacted]`; `authentication:\n  sessionKey: abc123` to `authentication:\n  sessionKey:
    [redacted]`; `side:\nSid2':C` to `side:\nSid2':[redacted]`; `bsid:\rSIDE:'C` to
    `bsid:\rSIDE:'[redacted]`; `author:\nJohn` unchanged; `sidebar\n:v` unchanged; `sidebar=\u{c}v`
    unchanged. The earlier screen that kept a newline at a wide-only separator out of this corpus is
    lifted: the line-break half of DC2 is gone.
15. AC15 `[red]` `reproduce::tests::scrub_embedded_deliberate_changes_are_exactly_these`: one row per
    DC with the new output as the expected value and the old output in a comment:
    DC1 `xsidéy=v` to `xsidéy=[redacted]`; DC2 `sidebar\u{a0}:\u{a0}v` to
    `sidebar\u{a0}:\u{a0}[redacted]` and `sidebar=\u{b}v` to `sidebar=\u{b}[redacted]` (old
    `sidebar=[redacted]`; amended: the row `author:\nJohn` to `author:\n[redacted]` is gone, that
    input is unchanged and is a row of AC14); DC3 `token.example.com:8443/x` to
    `token.example.com:[redacted]`; DC4 `sidebar='abc def token='S3'` to `sidebar='[redacted]'`;
    DC5 `sid=abc\u{a0}def` to `sid=[redacted]\u{a0}def` and `sidebar=abc\u{b}def` to
    `sidebar=[redacted]\u{b}def`; DC6 `sid='abc def token='S3` to
    `sid='[redacted] def token='[redacted]`.
16. AC16 `[guard]` all 178 pre-existing scanner tests pass. The set of their names after the change
    contains every name before it, except the one rename in Design 8
    (`cargo test -p aitm-plugin-scanner -- --list` before and after, diffed). No assertion of an
    existing test changed except in that renamed test, and there only the loop source.
17. AC17 `[red]` structural, one scanner: `grep -rnwE "EXTRA_SECRET_NEEDLES|redact_needle_pairs|names_a_secret|ends_value|closing_quote|is_key_byte" crates/aitm-plugin-scanner/src`
    prints nothing. In `discover.rs` and `reproduce.rs`, `grep -n '"jwt"\|"csrf"\|"session"'` prints
    only lines after the `#[cfg(test)]` line (no word list in non-test scanner code).
    `scrub_embedded`'s body is the one expression `scrub_text_wide(&strip_userinfo(text))`.
18. AC18 `[guard]` `git diff 15009b2 --stat -- crates/aitm-plugin-scanner/src/crawl.rs crates/aitm-plugin-scanner/src/commands.rs`
    is empty, and their tests pass unedited. `git diff 15009b2 -- '*.toml' Cargo.lock` is empty. The
    diff adds no `unsafe`.
19. AC19 (review and grep; reworded by Amendment 1) core's reading parameter is branched on in exactly
    three places in `redact.rs`: the secret test of a key run, the host:port exemption, and the one
    private helper `skip_pair_blanks` (the blank rule beside a separator, used at both skips); no
    other function branches on it (`scrub_text` and `scrub_text_wide` only choose it), and it decides
    nowhere else where a key run, separator, value end or closing quote lies. By reading the diff, and:
    `sed -n '/^fn mask_secret_pairs/,/^}/p' crates/aitm-core/src/redact.rs | grep -n reading` prints
    exactly five lines (the signature, the secret test, the exemption, and the two calls of
    `skip_pair_blanks`); `sed -n '/^fn skip_pair_blanks/,/^}/p' crates/aitm-core/src/redact.rs | grep -c reading`
    prints `2` (the signature and the one branch). The word `reading` appears in no comment inside
    either body. The report names each line.
20. AC20 `[red]` stale docs gone (amended): `grep -rnE "only knows|widened locally|needle layer|two vocabularies|none is in .scrub_text|vocabulary consolidation|stays until|scanner's copy|cannot diverge|cannot disagree|in nothing else|narrower list|only two differences|the only ones whose|one-scan|before the scanner stopped|Pins taken before|before PR 171 none" crates/aitm-core/src/redact.rs crates/aitm-plugin-scanner/src`
    prints nothing, and each item of Design 9 is done (reviewed by reading the diff).
21. AC21 `[guard]` the suites of crates that depend on core's redaction pass unedited:
    `aitm-core`, `aitm-poc`, `aitm-findings`, `aitm-mcp` (port-binding tests in the Terminal
    panel), `aitm-plugins`, `aitm-plugin-scanner`.
22. AC22 `[guard]` the full Rust gate is green.
23. AC23 `[guard]` mutants killed (Tester, in a scratch copy of the head, never the branch, each
    restored from a pristine copy): (a) `is_secret_key_wide` returns `is_secret_key` only: AC1, AC4,
    AC5, AC11, AC12, AC13 go red; (b) the wide scan exempts a host:port: AC6, AC14, AC15 go red; (c) the
    wide reading is used by `scrub_text`: AC8 and the existing lookalike tests go red; (d) one
    segment word is dropped from the substring check: AC3 goes red. **Added by Amendment 1:** (e)
    `scrub_text_wide` runs only the wide scan (the `bcd9647` shape): AC25, AC26, AC27 and the new AC14
    rows go red; (f) the wide scan skips blanks as core does (`skip_pair_blanks` ignores the reading):
    AC27 and the AC14 rows for line breaks go red; (g) the wide scan skips space and tab only: AC5
    (`author:\u{a0}John`) and AC15 (the DC2 rows) go red; (h) `crawl.rs::safe_target` calls
    `scrub_text_wide`: AC28 goes red, as does `scrub_url`'s test; (i) one free-text call in
    `commands.rs` calls `scrub_text_wide`: **expected to survive** (S1: no test pins it; recorded, not
    a finding, with the follow-up of Residual risks 10).
24. AC24 (review; restated by Amendment 1) the security review report records the panel differential
    of Design 7, re-run on the head under review with the kept scripts in
    `/tmp/claude-501/svc-diff-tools/` (guards lifted and triggers added as Design 7 says): the tool and
    scratch layout, the seeds, the input counts per alphabet (at least 3,000,000 in all, 1,000,000 on
    the amended aligned alphabet, 1,000,000 on the full alphabet, 1,500,000 for I5), and **I1 = 0 and
    I2 = 0 on the aligned alphabet**; I3 as amended (no panic, linear with the times at 1, 2, 4, 8 MiB
    and the `scrub_text_wide` to `scrub_text` ratio, every leak in a trigger input, the minimal
    reproducers by family within DC5, DC6, D1, D2, D3); I4 (`scrub_text`, `is_secret_key`,
    `is_secret_name` unchanged: zero differences); I5 (superset: zero violations); the positive
    controls (the `bcd9647` single-scan tree must report I1 and I2 violations on the amended aligned
    alphabet within its first 100,000 inputs, and the mutant (a) tree must report them too); the
    cleanup of the scratch trees; and every violation classified. Zero violations of I1, I2, I4, I5,
    and no unclassified I3 finding.
25. AC25 `[red]` `scrub_text_wide_masks_a_standard_pair_nested_under_a_wide_only_key` (core): exact
    rows, `scrub_text_wide(input)`: `authentication:\n  password: hunter2` to
    `authentication:\n  password: [redacted]`; `author:\n  token: abc123` to
    `author:\n  token: [redacted]`; `sessions:\n  jwt: J1` to `sessions:\n  jwt: [redacted]`;
    `sidebar:\n    api_key: K1` to `sidebar:\n    api_key: [redacted]`; `authentication: {password:
    hunter2}` to `authentication: [redacted] [redacted]}`; `sidebar=sid="C1"` to
    `sidebar=[redacted]"[redacted]"`; `author=password='C2'` to `author=[redacted]'[redacted]'`;
    `inside=x?sid\t=\tC9` to `inside=[redacted]\t=\t[redacted]`; `Auths:Pwd: C` to
    `Auths:[redacted] [redacted]`. (F1 reproducers; each output equals the old pipeline's.)
26. AC26 `[red]` `scrub_text_wide_masks_everything_scrub_text_masks` (core): over every input of
    `RECORDED_SCRUB_TEXT` plus the inputs of AC25 and AC27, every maximal run of ASCII alphanumerics
    of at least two characters that occurs in the input, is not a substring of `redacted`, and does
    not occur in `scrub_text(input)` also does not occur in `scrub_text_wide(input)`. At least 100
    inputs are checked and at least 20 of them have such a masked run (so the test is not vacuous).
    Fails on `bcd9647` on the AC25 inputs (`hunter2` stays in the clear).
27. AC27 `[red]` `scrub_text_wide_keeps_a_line_break_as_a_boundary` (core): exact rows,
    `scrub_text_wide(input)`: `side:\nSid2':C` to `side:\nSid2':[redacted]`;
    `authentication:\n  sessionKey: abc123` to `authentication:\n  sessionKey: [redacted]`;
    `bsid:\rSIDE:'C` to `bsid:\rSIDE:'[redacted]`; `author:\nJohn` unchanged; `sidebar:\r\nv`
    unchanged; `sidebar\n:v` unchanged; `sidebar=\u{c}v` unchanged; and, to show the standard keys
    still read across a line break, `sid:\nabc` to `sid:\n[redacted]`. No row asserts a leaked secret:
    the unchanged rows hold non-secret words or are the old pipeline's output for that shape.
28. AC28 `[guard]` `reproduce::tests::safe_target_reads_a_query_by_the_standard_reading` (scanner,
    in `reproduce.rs`'s `mod tests`, calling `crate::crawl::safe_target`): for the text
    `http://t/x?authority=ex&author=3&side=left`, `safe_target` returns that text unchanged (the
    Coder confirms the literal by running it), and `scrub_embedded` of the same text is
    `http://t/x?authority=[redacted]&author=[redacted]&side=[redacted]`, so the pin discriminates the
    two readings. Green on `bcd9647`; red when `safe_target` is swapped to the wide reading (mutant
    (h)). Closes S1 for `safe_target`.

## Left to the builder

- Whether the private seam is a two-variant enum or a predicate pointer plus flags; helper names
  other than `skip_pair_blanks`, `is_secret_lower` and `contains_segment_word`; whether the second
  scan is `mask_secret_pairs(&scrub_text(x), Wide)` or an equivalent that runs the regexes once;
  whether `contains_segment_word` and the standard test share one lowercase string.
- Where the new functions sit in `redact.rs`, and the wording of docs, provided Design 9 and the
  AC20 grep hold.
- The rows added beyond the minimums in AC8, AC13, AC14, so long as outputs are recorded from the
  old code, never typed by hand.
- Whether to keep `is_secret_name` as the one-line delegate (default) or inline it; if inlined, the
  four call sites and the two tests that name it are edited in the same task and Design 8 is amended.
- The task split in the plan. Suggested shape: (1) pins on the old tree, scanner side and core
  side (independent files); (2) core wide reading and docs; (3) scanner swap, deletions, doc fixes
  (needs 2); (4) Tester mutants, then the panel differential. After the panel, Fix 1 (core) and
  Fix 2 (scanner), in the plan's Fix tasks section.

## Open questions

None that block approval. Calls where I chose the safer default over the cheaper one and Matt may
reverse them: accepting DC5 and DC6 rather than building the fallback (Design 5); the wide scan never
exempting host:port (Design 4), with the named alternative that also removes DC3 and arm D3; and
accepting arms D1 to D3 of class D as a Minor residual rather than building a third rule
(Residual risks 8).

## Summary

The scanner's "extra needles" are core's own five session/auth words read as substrings instead of
whole segments, so there is no word to promote and promoting the substring mode into the default
would mask the real `authority` argument key. The spec moves the wide reading into core beside the
one list (`is_secret_key_wide`, `scrub_text_wide`) and deletes the scanner's list, predicate body,
and entire second scan. `scrub_text_wide` runs core's one pair scan twice, first with the standard
reading (so it masks everything `scrub_text` masks and a nested standard key is never hidden), then
with the wide reading, which differs in three declared places: the key test, no host:port exemption,
and `\n`, `\r`, `\x0c` kept as a boundary beside a separator. The scanner's name decisions are
identical by construction; PoC embedded-value output is byte for byte what it was on the aligned
alphabet (line breaks included) and otherwise changes only in six listed ways, four of which mask at
least as much as before and two (DC5 vertical tab or Unicode space inside an unquoted value, DC6
unclosed quote) mask slightly less, matching the standard reading's reviewed behaviour; three exotic
shapes (D1 to D3) can also leave a nested wide-only value, and are a documented Minor residual that no
test pins. Equivalence is established by corpora recorded from the old code plus an out-of-tree
million-input differential with stated invariants I1 to I5 (the first run of which found the single-scan
flaw this amendment fixes). Stale comments in core, `discover.rs` and `reproduce.rs` are listed and
fixed.

## Architect's calls (for Matt to approve or correct)

1. Option C: core owns the list and both readings; two `pub fn`s, not a generic hook (B) and not a
   promotion (A).
2. `is_secret_name` stays as a one-line delegate in `discover.rs` rather than being deleted.
3. The wide reading differs from the standard one in exactly three places (amended from two): the
   secret test, the host:port exemption, and `\n`, `\r`, `\x0c` kept as a boundary beside a separator
   (call 11); the key-run, value and closing-quote rules are core's.
4. The wide scan never exempts host:port, which makes DC3 (a needle-only dotted key before a port is
   now masked in PoC-embedded values) a deliberate change. Alternatives: exempt iff the key has no
   segment word, or have the wide scan judge only the five words as substrings; either gives zero
   change and removes arm D3 (measured gain small).
5. Accept DC5 and DC6 (less masked on a vertical tab or Unicode space inside a value, and on an
   unclosed quote) instead of building a lenient branch; the fallback is named, not built. The panel
   rated them Minor (F3).
6. Free-text surfaces (`scan.discover` endpoints, findings, audit, `commands.rs`) stay on the
   standard reading; names and PoC-embedded values stay wide.
7. No frozen copy of the old pipeline in the repo; recorded corpora in-tree, the million-input
   differential out of tree with invariants I1-I5.
8. Task 1 adds name-decision pins on the old tree (AC11-AC13), because the existing 178 tests pin
   almost none of the wide behaviour.
9. One test is renamed and four are comment-edited; the aitm-poc test comments and the historical
   specs are left alone.
10. The Status line is set to approved on the orchestrator's instruction; it is the orchestrator's to
    revert if it sends changes.
11. **(Amendment 1, F1)** `scrub_text_wide` is the standard scan followed by the wide scan, one
    function run twice, not a single wide scan. The single scan was reviewed and failed.
12. **(Amendment 1, F2)** The wide scan keeps `\n`, `\r`, `\x0c` as a boundary beside a separator and
    still skips every other whitespace character. This shrinks DC2 (`author:\nJohn` stays as it is) and
    makes the line-break shapes, `authentication:\n  sessionKey: abc123` among them, byte-identical to
    the old pipeline. It costs a third consultation of the reading parameter (AC19 reworded). Dropping
    DC2 outright was allowed and was measured worse (space and tab only).
13. **(Amendment 1, F2)** The three exotic class-D arms D1 to D3 are accepted as a Minor residual with
    no test that asserts a leak; no smaller rule exists without a second key-run, exemption or value
    rule.
14. **(Amendment 1)** The aligned alphabet now allows line breaks at separators (so I2 covers the
    F2 shapes), I3 names four triggers, and I4 (untouched functions) and I5 (superset) are added.
    Fix tasks may edit tests this branch added, never a pre-existing test beyond Design 8.
