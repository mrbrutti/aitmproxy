# Scanner vocabulary consolidation design

**Status:** approved (2026-10-31, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Research inputs:** no `docs/research/` note. This is the follow-up named
"scanner vocabulary consolidation" by `docs/superpowers/specs/2026-10-30-audit-ring-integrity-design.md`
(Non-goals, Design 4, Residual risks 12-14) and its plan (Shipped section). Code read on
`15009b2`: `crates/aitm-core/src/{redact,lib}.rs`,
`crates/aitm-plugin-scanner/src/{discover,reproduce,crawl,commands}.rs` and `Cargo.toml`,
`crates/aitm-poc/src/builder.rs`, `crates/aitm-mcp/src/server.rs` (`redact_value`),
`crates/aitm-plugins/src/{mutate,capture,detail}.rs`. Baseline measured on `15009b2`:
`cargo test -p aitm-plugin-scanner` = 178 passed; `cargo test -p aitm-core --lib redact` = 32 passed.

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
- `scrub_embedded` returns what it returns today, except the deliberate changes DC1-DC6 below.
  Every one of them is named with the tests it touches (none of the 178 existing assertions).
- The scanner's name decisions (`is_secret_name`: injection-point redaction in `enumerate`, PoC
  placeholders in `Scrubber`) are identical by construction, and are now pinned by tests (today
  almost nothing pins them).
- Every stale doc comment that describes the scanner's second vocabulary or second scan is fixed.
- The core API grows by exactly two functions, additively.

## Non-goals

- Changing `scrub_text` or `is_secret_key` behaviour, or the standard vocabulary, or core's rules
  for where a key, value or quote begins and ends. (PR 171 panel-reviewed them.)
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
  clear than today is listed (DC5, DC6), argued, and has a test that pins the new output.
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
  followed by a separator, with one lowercase allocation per such candidate, as today.
- `scrub_embedded` keeps its order: `strip_userinfo` first (so `//auth:pw@host/x` cannot make the
  scan swallow the host), then one scan. The `{{var}}` and payload handling in `Scrubber` is
  untouched: `scrub_embedded` is still applied per decoded component.
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
   further for the five words only because the second scan re-masked the first scan's output.
6. **Core's `lib.rs` needs no change.** The new functions are reached as
   `aitm_core::redact::{is_secret_key_wide, scrub_text_wide}`, like the existing two.
7. **`is_secret_name` is identical to the new wide predicate** by definition:
   `is_secret_key(name)` or the ASCII-lowercased name contains any of the five words.
   The scanner's `names_a_secret` is the same substring test over the five words alone.

### 2. The decision: C, one list read two ways, in core

Core keeps the one list (`SECRET_KEY_SEGMENTS`) and gains the wide *reading* of it next to the
list: `is_secret_key_wide` (names) and `scrub_text_wide` (the same scrub, judging keys by that
reading). The scanner deletes its list, its predicate body, and its scan, and calls those two.
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
- `scrub_text_wide`: `scrub_text` with the pair pass judging keys by `is_secret_key_wide`, and with
  **no host:port exemption** (see 4). Same two regex passes first (`Authorization` line, `Bearer`
  token). Doc intent: over-redacts by design; states the one other difference from `scrub_text`
  and says everything else (value rule, quotes, whitespace, nested pairs) is shared.
- `is_secret_key` and `scrub_text` keep their signatures and, byte for byte, their behaviour.

### 4. One scan, two readings (private seam)

`scrub_text` and `scrub_text_wide` become thin entry points over one private function that runs the
two regex passes and then `mask_secret_pairs`. `mask_secret_pairs` gains one parameter: a private
two-variant `Reading` (`Standard` | `Wide`), or an equivalent such as a predicate pointer plus a
flag (builder's call). **The parameter is consulted in exactly two places:**

1. the secret test of a key run: `is_secret_key` (Standard) or `is_secret_key_wide` (Wide);
2. the host:port exemption: applied for Standard, never for Wide.

It is not consulted anywhere that decides where a key run, a blank, a separator, a value or a
closing quote starts or ends. That is the property that makes "one pair scanner" true: a pair
that both readings call secret is scanned identically by both, host:port aside. A reviewer checks
it by counting the parameter's uses (two).

**Host:port decision (Architect's call).** The wide reading never exempts. Old behaviour: exempt
only for keys with no segment word (`token.example.com:8443`), masked for every key with one
(`auth.example.com:8443`, the common case). Never exempting reproduces the common case exactly and
is the crisp rule for an over-redacting reading; the cost is DC3, a needle-only dotted key before a
port (`token.example.com:8443/x`) is now masked in a PoC-embedded value, which was the pre-PR-171
behaviour. Alternative, if Matt prefers zero change: exempt in the wide reading iff the key
contains no segment word (the helper exists anyway); one expression, but a rule that exists only to
mimic the old pipeline.

### 5. The differences between the old pipeline and one scan

Old pipeline: P1 = `scrub_text` (two regexes, then core's pair scan with the standard predicate),
then P2 = the scanner's `redact_needle_pairs` over P1's output with the five-word substring
predicate. New: the two regexes, then one core scan with the wide predicate. The "old" column
below is derived by reading `15009b2`; **Task 1 records the real outputs by running the old
code**, and a mismatch with this table stops the Coder (spec gap).

| # | Aspect | Old (P1 core, then P2 scanner) | New (one core scan, wide) | Direction | Verdict | Example, old to new | Pinned by |
|---|---|---|---|---|---|---|---|
| 1 | Vocabulary | five words as substrings, others as core | `is_secret_key_wide`: same set | none | identical | | AC4, AC13 |
| 2 | Key run | P2: ASCII run only; a non-ASCII char ends it | core: non-ASCII non-whitespace chars continue the run | masks at least as much | accept (DC1) | `xsidéy=v` to `xsidéy=[redacted]` | AC15 |
| 3 | Blanks around the separator | P2: space and tab | Unicode whitespace, newlines included | masks at least as much | accept (DC2) | `author:\nJohn` to `author:\n[redacted]` | AC15, AC5 |
| 4 | End of an unquoted value | P2: `is_ascii_whitespace` (no vertical tab) and delimiters; non-ASCII never ends | core: also vertical tab and Unicode whitespace | **masks less** | accept (DC5) | `sid=abc\u{a0}def` to `sid=[redacted]\u{a0}def` | AC15 |
| 5 | Closing quote, both close | P2: first unescaped quote | core: skips an opener-shaped quote (after `=`/`:`, followed by a value char) | same exposure, different bytes | accept (DC4) | `sidebar='abc def token='S3'` to `sidebar='[redacted]'` | AC15, AC5 |
| 6 | Closing quote, core finds none | P2 closes at the opener-shaped quote | core falls back to the plain unquoted rule and remembers the failed search | **masks less** | accept (DC6) | `sid='abc def token='S3` to `sid='[redacted] def token='[redacted]` | AC15 |
| 7 | host:port | P1 exempts; P2 re-masks it for any key with a segment word | wide never exempts | masks at least as much | five-word keys unchanged (AC14); needle-only keys accept (DC3) | `token.example.com:8443/x` to `token.example.com:[redacted]` | AC6, AC14, AC15 |
| 8 | Pairs nested in a value | P1 scans inside a wide-only value, P2 then masks the value | the value is masked whole, the scan resumes after it | same final bytes (a nested pair inside a masked value is masked either way) | identical | `author=password=S3` to `author=[redacted]` both | AC14 |
| 9 | Empty value; scan resumption after a non-secret key | resume after the key run | resume after the key run | none | identical | `sid=&password=x` | existing tests, AC14 |

Direction in one sentence: **the only changes that can leave more of a value in the clear than
today are DC5 and DC6**, and both are malformed or exotic input (a credential that itself contains
a vertical tab or a non-ASCII space; a quote that is never closed), where the new output equals what
the standard reading has always done for `password`, `token` and every other needle key
(PR 171 Residual risks 12-14). The old pipeline was stronger there only for keys that contain one of
the five words (for the five words themselves because a second scan re-masked the first scan's
output, for wide-only keys because the second scan was the only one that saw them), never for
`password`, `token` or any other needle key, so the PoC path was inconsistent (`sid='abc def ...`
masked further than `password='abc def ...`). Nothing changes for any value that is well formed:
ASCII, balanced quotes, no vertical tab.

**Fallback, not built now:** if the security panel rates DC5 or DC6 Important, the fix is one
branch confined to the wide reading (a lenient unquoted-value end, or a fall-back to the first
unescaped quote when the opener-aware search fails). It would reintroduce a second value rule, so
this spec does not pre-build it.

### 6. Every deliberate output change

All are in `scrub_embedded` (so in PoC-embedded values: Referer, header values, JSON string
leaves, form values, untyped bodies). None changes a name decision, `scrub_text`, or a `scan.*`
free-text output.

| ID | Change | Affects | Direction | Existing tests touched |
|---|---|---|---|---|
| DC1 | A key run glues across non-ASCII characters, so a secret word inside it counts (`xsidéy=v`) | wide-only keys | more masked | none (no existing input has a non-ASCII char glued to a key) |
| DC2 | Newlines and Unicode whitespace may sit around the separator (`author:\nJohn`, `sidebar\u{a0}:\u{a0}v`) | wide-only keys (the five words already behaved so through P1) | more masked | none |
| DC3 | A needle-only dotted key before a port is masked (`token.example.com:8443/x`) | needle-only dotted keys | more masked | none |
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
3. **Panel differential, out of tree.** The security reviewer builds the old pipeline from
   `15009b2` in a scratch worktree and runs `old(scrub_embedded)` against the new on at least
   3,000,000 generated inputs (PR 171's panel used 3M) and records counts and results. The
   invariants:
   - **Aligned alphabet** = ASCII keys from {the five words, needles, wide-only words such as
     `author`, `authority`, `sidebar`, `subsidiary`, `inside`, `userSession`, non-secret words},
     case variants, optional `x-`/`_id`/`.v1` affixes, a dotted key allowed but no `key:digits`
     host:port shape; `=` or `:` with space/tab padding and optional key quotes; values that are
     unique ASCII canaries, bare (no whitespace, no `& ; , " ' }`) or quoted with a matched quote
     and escapes; empty values; pair delimiters `& ; , } { [ ] / ?`, spaces, tabs, `\n`, `\r`; a pair
     nested in a non-secret key's value; no vertical tab, no non-ASCII byte, no unmatched or
     unescaped inner quote, no newline right at a separator.
   - **I1 (no regression).** On the aligned alphabet, every canary absent from `old(x)` is absent
     from `new(x)`.
   - **I2 (equality).** On the aligned alphabet, `new(x) == old(x)` byte for byte. (DC1-DC4, DC6
     all need something outside it.)
   - **I3 (full alphabet).** No panic, no char-boundary error, linear time (at most 3x the time of
     a 1 MiB baseline per doubling), and every canary that `new` leaves and `old` masked is in an
     input that contains a vertical tab, a non-ASCII whitespace character, or an unclosed or
     unmatched quote (DC5, DC6). Anything else is a finding.
   - Any violation of I1 or I2 is a finding. A counterexample that shows this spec's table is wrong
     is a finding against the spec, not the code.
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
| `scrub_embedded_masks_every_shared_vocabulary_name` | `reproduce.rs` | one inline comment (~1510) | "one pass, two vocabularies" | reword to one scan, one list |
| `enumerate_redacts_common_auth_parameter_names` | `discover.rs` | doc comment only (~537) | "outside the shared vocabulary" is false since PR 171 | reword; no assertion changes |

### 9. Comments and docs to fix (the complete list)

Core, `crates/aitm-core/src/redact.rs`:
1. Delete the two pointer comments: the `//` block above `ends_value` (~191-194) and the one above
   `closing_quote` (~233-236). Their `///` docs stay and need no edit (they do not mention the scanner).
2. Module doc (~1-17): one list, two readings; `scrub_text` and `scrub_text_wide` named; the
   sentence "so the two cannot diverge" extended to cover the wide reading.
3. `SECRET_KEY_SEGMENTS` doc (~45-49): add that the same words are what the wide reading matches
   as substrings.
4. `scrub_text` doc: one sentence pointing to `scrub_text_wide` for the over-matching reading;
   the host:port paragraph stays (it describes the standard reading).
5. `mask_secret_pairs` doc: say the reading parameter is consulted in exactly two places.

Scanner, `crates/aitm-plugin-scanner/src/`:
6. `reproduce.rs` module doc (~17-22): `scrub_embedded` is "URL userinfo stripped, then
   `aitm_core::redact::scrub_text_wide`", not "`scrub_text` plus the same widened name vocabulary".
7. `scrub_embedded` doc (~362-381): rewrite. The three-step description and the claim that
   `scrub_text` alone "only knows api_key / token / ..." are false.
8. The five test comments in Design 8.
9. `discover.rs` module doc (~8-15): "widened locally by `is_secret_name` with the common auth
   parameter names" becomes the wide reading in core. The `EXTRA_SECRET_NEEDLES` doc goes with the
   const. The `is_secret_name` doc is rewritten: a delegate, "so `reproduce`'s PoC scrubber masks
   exactly the names `enumerate` redacts".
10. No comment in the scanner may name a deleted item (`EXTRA_SECRET_NEEDLES`, `redact_needle_pairs`,
    `names_a_secret`, `ends_value`, `closing_quote`, `is_key_byte`); AC17 greps for it.

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

1. **DC5 and DC6 are weaker than today for malformed input** (Design 5). Accepted: they equal the
   standard reading's reviewed behaviour, exposure needs a secret that itself holds a vertical tab or
   non-ASCII space, or a malformed quote; the fallback is named.
2. **PR 171 Residual risks 12-14 now also bind the PoC path for the five words and wide-only
   keys:** `password='x password'=S3CR3T` style leaks, a quoted key opener right after an unclosed
   quote, `token="token="S3CR3T`, and `Cookie: sid="S3CR3T"` (the `Cookie` pair's unquoted value
   stops at the quote). The old second scan did not close these either; unchanged.
3. **A dotted key containing a segment word before a port is still masked in PoC-embedded values**
   (`https://auth.example.com:8443/cb` becomes `https://auth.example.com:[redacted]`): unchanged
   readability cost, now also for needle-only dotted keys (DC3). A PoC step that embeds such a URL in
   a body does not replay faithfully. A URL-aware redactor is a separate change.
4. **Prose false positives get slightly wider for wide-only keys:** `Author:\nJohn` loses `John`
   (DC2), as `auth:\nnext line` always did for the five words.
5. **The wide reading is public.** Another crate could adopt it for audit keys and mask `authority`.
   The doc says not to; nothing enforces it. Core's own `authority` tests guard the standard reading.
6. **Literal five-word lists in tests do not fail when a word is added to core.** Same as PR 171's
   needle test; accepted. Core's `is_secret_key_wide_names_every_segment_word` is the one that names them.
7. **The panel differential is out of tree** and depends on `15009b2` staying reachable. If the
   branch is squash-merged the SHA is still in history.

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
   `sidebar='x y' z=1` to `sidebar='[redacted]' z=1`; `author:\n  John` to `author:\n  [redacted]`;
   `sidebar=abc\u{a0}def` to `sidebar=[redacted]\u{a0}def`;
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
   Proves the reading parameter changes nothing else.
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
    move or drop.
15. AC15 `[red]` `reproduce::tests::scrub_embedded_deliberate_changes_are_exactly_these`: one row per
    DC with the new output as the expected value and the old output in a comment:
    DC1 `xsidéy=v` to `xsidéy=[redacted]`; DC2 `author:\nJohn` to `author:\n[redacted]` and
    `sidebar\u{a0}:\u{a0}v` to `sidebar\u{a0}:\u{a0}[redacted]`; DC3 `token.example.com:8443/x` to
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
19. AC19 (review) core's reading parameter is consulted in exactly two places in `redact.rs`
    (the secret test and the host:port exemption), by reading the diff.
20. AC20 `[red]` stale docs gone: `grep -rnE "only knows|widened locally|needle layer|two vocabularies|none is in .scrub_text|vocabulary consolidation|stays until|scanner's copy" crates/aitm-core/src/redact.rs crates/aitm-plugin-scanner/src`
    prints nothing, and each item of Design 9 is done (reviewed by reading the diff).
21. AC21 `[guard]` the suites of crates that depend on core's redaction pass unedited:
    `aitm-core`, `aitm-poc`, `aitm-findings`, `aitm-mcp` (port-binding tests in the Terminal
    panel), `aitm-plugins`, `aitm-plugin-scanner`.
22. AC22 `[guard]` the full Rust gate is green.
23. AC23 `[guard]` mutants killed (Tester, in the sandbox, each reverted by hand and the revert
    proven by a saved `git diff`): (a) `is_secret_key_wide` returns `is_secret_key` only: AC1, AC4,
    AC5, AC11, AC12, AC13 go red; (b) the wide reading exempts a host:port: AC6, AC14, AC15 go red; (c) the
    wide reading is used by `scrub_text`: AC8 and the existing lookalike tests go red; (d) one
    segment word is dropped from the substring check: AC3 goes red.
24. AC24 (review) the security review report records the panel differential of Design 7 (input
    count, alphabets, I1, I2, I3 results) with zero violations, or each violation classified.

## Left to the builder

- Whether the private seam is a two-variant enum or a predicate pointer plus a flag; helper names;
  whether `names_a_segment_word` and the standard test share one lowercase string.
- Where the new functions sit in `redact.rs`, and the wording of docs, provided Design 9 and the
  AC20 grep hold.
- The rows added beyond the minimums in AC8, AC13, AC14, so long as outputs are recorded from the
  old code, never typed by hand.
- Whether to keep `is_secret_name` as the one-line delegate (default) or inline it; if inlined, the
  four call sites and the two tests that name it are edited in the same task and Design 8 is amended.
- The task split in the plan. Suggested shape: (1) pins on the old tree, scanner side and core
  side (independent files); (2) core wide reading and docs; (3) scanner swap, deletions, doc fixes
  (needs 2); (4) Tester mutants, then the panel differential.

## Open questions

None that block approval. Two calls where I chose the safer default over the cheaper one and Matt
may reverse them: accepting DC5 and DC6 rather than building the fallback (Design 5), and the wide
reading never exempting host:port (Design 4).

## Summary

The scanner's "extra needles" are core's own five session/auth words read as substrings instead of
whole segments, so there is no word to promote and promoting the substring mode into the default
would mask the real `authority` argument key. The spec moves the wide reading into core beside the
one list (`is_secret_key_wide`, `scrub_text_wide`), makes it a two-line variation of the one core
scan (a different secret test, no host:port exemption), and deletes the scanner's list, predicate
body, and entire second scan. The scanner's name decisions are identical by construction; PoC
embedded-value output is unchanged except six listed changes, four of which mask at least as much as
before and two (DC5 vertical tab or Unicode space inside an unquoted value, DC6 unclosed quote)
mask slightly less, matching the standard reading's reviewed behaviour. Equivalence is established
by corpora recorded from the old code on the unmodified tree plus an out-of-tree million-input
differential with stated invariants. Stale comments in core, `discover.rs` and `reproduce.rs` are
listed and fixed.

## Architect's calls (for Matt to approve or correct)

1. Option C: core owns the list and both readings; two `pub fn`s, not a generic hook (B) and not a
   promotion (A).
2. `is_secret_name` stays as a one-line delegate in `discover.rs` rather than being deleted.
3. The wide reading differs from the standard one in exactly two places: the secret test and the
   host:port exemption; value extents are core's.
4. The wide reading never exempts host:port, which makes DC3 (a needle-only dotted key before a
   port is now masked in PoC-embedded values) a deliberate change. Alternative: exempt iff the key
   has no segment word, for zero change.
5. Accept DC5 and DC6 (less masked on a vertical tab or Unicode space inside a value, and on an
   unclosed quote) instead of building a lenient branch; the fallback is named, not built.
6. Free-text surfaces (`scan.discover` endpoints, findings, audit, `commands.rs`) stay on the
   standard reading; names and PoC-embedded values stay wide.
7. No frozen copy of the old pipeline in the repo; recorded corpora in-tree, the million-input
   differential out of tree with invariants I1-I3.
8. Task 1 adds name-decision pins on the old tree (AC11-AC13), because the existing 178 tests pin
   almost none of the wide behaviour.
9. One test is renamed and four are comment-edited; the aitm-poc test comments and the historical
   specs are left alone.
10. The Status line is set to approved on the orchestrator's instruction; it is the orchestrator's to
    revert if it sends changes.
