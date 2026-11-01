# scrub_text nested-pair leak design

**Status:** approved (2026-11-01, self-approved by the orchestrating session under Matt's autonomous-approve mode; the Open questions keep their defaults and are flagged in the PR for Matt); amended after the Stage 6 panel (Amendment 1, 2026-11-01, self-approved the same way)
**Research inputs:** no `docs/research/` note. This is the follow-up the vocabulary-consolidation spec
and plan name (`docs/superpowers/specs/2026-10-31-scanner-vocab-consolidation-design.md`, Residual
risks 9 and 11; its plan, Shipped follow-up 1), found twice by the PR 199 security panel. Code read on
`origin/main` `f2b0dae6` and again on `c3a4fd37` (`redact.rs`, `reproduce.rs`, `discover.rs` and the
`aitm-poc` builder are byte-identical between the two). Numbers marked (scratch) are the Architect's,
from a lab outside the repo, `/tmp/claude-501/nested-scratch/` (variants of `redact.rs` cut from
`f2b0dae6`, a runner, generators, a harness; informational, rebuilt by the reviewer from the head under
review, never committed). They justify the decisions; they are not the Stage 6 evidence (Design 9).

## Amendment 1 (post-panel), 2026-11-01

The Stage 6 panel on head `a2181852` (base `ecbf58ac`) returned spec PASS (P-1 to P-3, Minor), quality PASS (Q-1 to
Q-9, Minor) and security FAIL (S-1 Important and spec-shaped; S-2 to S-4 Minor). Per Fix-task protocol 4 the
spec-shaped finding came to the Architect first. The consolidated findings are in the orchestrator's notes folder
(`F4-panel-round1-findings.md`), the reviewer's differential beside it (`F4-security-differential.md`).
**This amendment changes no behaviour of any function, and no production line.** It restates one invariant, records
the classes and counts this spec missed, and corrects docs (the plan's Fix 1 is comments, docs and tests).
Sections edited in place: Goals (two bullets), Design 4 (the C bullet), 5 (hazard 2), 6 (heading, lead, closing
sentence, new rows 29 and 30), 7 (items 1 and 3), 9 (I1, I5), Residual risks 3 and 4 (and new 10), Open questions
(new 4), Summary (one sentence), Architect's calls (new 13 to 20). The Status line stays the orchestrator's. AC numbers and names are
unchanged and no AC is added (item 6). Outputs below marked (scratch) are mine, from
`/tmp/claude-501/f4-arch-amend/`: the production section of `redact.rs` cut from `ecbf58ac` and from `a2181852`
(`#[cfg(test)]` and what follows removed), both built into one scratch binary outside the worktree. They are the real
outputs of both; they justify the decisions and are not the Stage 6 evidence, which is the reviewer's.

**1. S-1 (Important): "nothing the old output masked is exposed on well-formed input" is false as written (family
G1).** A quoted value whose last token is a key that holds a needle and a separator, closed by its quote
(`"x-pwd:"`), under a secret parent that swallows the child's key. The old scan, with the child's key swallowed,
read the closing quote as the opener of a pair (`pwd:` then `"`) and masked the text after it, often the next line.
The new scan reads the child pair, closes its quote correctly, and the text after it is read by its own keys. No
malformed quote is involved (scratch, real outputs; `scrub_text` and `scrub_text_wide` give the same output on
rows 1 to 4):

| # | Input | Old output | New output | What the new output exposes, and its governing key |
|---|---|---|---|---|
| 1 | `token:\n  apikey: "x-pwd:"\n  note: "hello"` | `token:\n  [redacted] "x-pwd:"[redacted]"` | `token:\n  [redacted] "[redacted]"\n  note: "hello"` | `hello`, governed by `note` (not secret). The nested secret value `x-pwd:` was exposed and is now masked |
| 2 | `jwt:secret:"pwd:"\n:"Qw"` | `jwt:[redacted]"pwd:"[redacted]"` | `jwt:[redacted]"[redacted]"\n:"Qw"` | `Qw`, governed by no key (a separator with no key run before it) |
| 3 | `Auth:secret:'pwd=' :'QZ'` | `Auth:[redacted]'pwd='[redacted]'` | `Auth:[redacted]'[redacted]' :'QZ'` | `QZ`, no key |
| 4 | `pwd=auth="pwd:" x2""` | `pwd=[redacted]"pwd:"[redacted]""` | `pwd=[redacted]"[redacted]" x2""` | `x2`, a bare word, no key |
| 5 | `Session:Autho:"pwd="\n3Z"` | `scrub_text`: `Session:[redacted]"pwd="[redacted]"`; wide: the same | `scrub_text`: unchanged; wide: `Session:[redacted]"[redacted]"\n3Z"` | `3Z`, no key. This is the I5 form: the standard scan still misreads the quote and masks `3Z`, the wide scan reads the nested pair and does not |

The reviewer's counts (his own well-formed generators, which put a hazard value inside quotes, as mine in the first
version of this spec never did): raw I1 799 (`scrub_text`) and 1,049 (wide) of 3,000,000 well-formed inputs, raw I5
374; on his targeted alphabet 7,157, 12,438 and 836 of 400,000; **ownership-aware I1' 0 on all 3.4M and I5' 0 on
re-runs of 500,000 and 200,000**; every one of the 1,185 sampled and minimised violations is G1. My independent
check (scratch, a generator of my own: a secret parent, a quoted child value ending in a needle key and a separator,
a tail pair with a key from `note`, `title`, `id`, `user`, `password`, `token`, `api_key`, `sessionKey`, three
layouts, nine parents; 5,248,800 inputs): raw I1 656,100 (`scrub_text`) and 874,800 (wide), every violation a tail
token governed by a non-secret key under that reading; I1' 0; no token governed by a secret key exposed by either
function; the child's own canary never exposed.

**Decision: no code change; the invariant is restated.** (a) The only code change that restores the old output on
these inputs is to read, inside text the scan has already read as a quoted value, the closing quote that follows a
key and a separator as the opener of a pair. That is the misparse, and by shape it is the same quote as the closing
quote of `token="sid:" tail="x"` (a quote after a key and a separator, then a blank), which guard R2 and AC7 require
the scan not to read as an opener (mutant M2 shows what it costs: `token="[redacted]"[redacted]"`). The old output
masked `hello` only because the child's key sat in plain text. (b) The tokens it newly shows are governed by
non-secret keys or by no key, and a bare credential with no recognisable key is the documented residual of the scrub
(the `scrub_text` doc: it cannot be detected). (c) For the nested value itself the new output is the safer one.

**Restated invariant** (replaces "nothing the old output masked is exposed on well-formed input" wherever it
appears): *no value governed by a secret key becomes visible on well-formed input.* A token is governed by the key
written directly before it: a key run, an optional closing quote, blanks, `=` or `:`, blanks, an optional opening
quote, then the token. A key is secret under a reading when `is_secret_key` (`scrub_text`) or `is_secret_key_wide`
(`scrub_text_wide`, `scrub_embedded`) accepts it. A token with no such key before it (a bare word, text after a
closing quote, a separator with no key run) is governed by no key. "Well-formed" means quotes balanced and escaped,
no value character directly behind a closing quote, no two kinds of quote interleaved: JSON, YAML, logfmt, query
strings, forms, Cookie headers, Python reprs, ini and env files. "The value" is what the scan's value rule reads for
the key (so `[` for an array: item 5). Design 9's I1' and I5' are this invariant's checks; the raw I1 and I5 are
reported, grouped by family, and are not pass criteria.

**2. S-2 (Minor): interleaved quotes (G2) and an unmatched or opener-shaped quote (G3), on malformed input.** The
harness trigger of Design 9 (unmatched, unescaped, opener-shaped) misses G2: two kinds of quote, each with an even
count, opened and closed across one another. Scratch, real outputs: `Token:Jwt:'token="'id"` gives `Token:[redacted]'token="[redacted]"` before
and `Token:[redacted]'[redacted]'id"` after (`id` exposed); `Side=\n'rsession="'QZ"` under the wide scrub gives
`Side=\n'rsession="[redacted]"` before and `Side=\n'[redacted]'QZ"` after (`QZ` exposed; `scrub_text` leaves both
unchanged); G3: `Auth:csrf:'pwd='&4Z'` gives `Auth:[redacted]'pwd='[redacted]'` before and
`Auth:[redacted]'[redacted]'&4Z'` after (`4Z` exposed). Counts: Residual risks 3. Disposition: Minor, accepted
(Architect's call 14); "malformed-quote trigger" in Design 9 now includes interleaved quotes; no test pins any of
them.

**3. S-3 and P-1 (Minor): Design 6 did not list every class.** Two are missing. (a) `token="sid:"x` (and the same
with `\u{e9}` or `\u{1f600}` after the quote) gives `token="[redacted]"[redacted]` where the old output gave
`token="[redacted]"x`; with a blank or a line break behind the quote (`token="sid:" x`, `token="sid:"\nx`) the output
is unchanged (scratch, real outputs, both readings). A quote with a value character behind it is opener-shaped, so
the parent's quoted value does not close there and the nested `sid:` takes the next token. It follows Design 6's own
"when and only when" sentence and only masks more. (b) Wide reading only: `token:\n  author: bob` gives `token:\n
[redacted] [redacted]` and `auth:\n  authority: example.com` gives `auth:\n  [redacted] [redacted]` where the old
output kept `bob` and `example.com` (`scrub_text` keeps them, AC4): row 21's rule for the wide-only keys `author`
and `authority`. Design 6 now says "classes", names the class that goes toward less masking (G1), and has rows 29 and
30. The tester's three rows (`token="sid:"x` with a 1-, 2- and 4-byte character after the quote) in
`scrub_text_reads_the_edges_of_a_nested_pair` stay: they pin a mask and are a char-boundary check, and row 29 is
their basis (Q-8(b), accepted).

**4. P-2 (Minor): counts and a repeat count were stale.** Measured from git and the Tester's runs; the plan's Fix
tasks section carries the same table.

| | base `ecbf58ac` | S7 `85b81815` | head `a2181852` | after the plan's Fix 1 |
|---|---|---|---|---|
| `redact::tests` | 54 | 64 | 69 | 68 |
| `cargo test -p aitm-core --lib redact` | 67 | 77 | 82 | 81 |
| `cargo test -p aitm-plugin-scanner --lib` | 197 | 201 | 203 | 203 |
| `cargo test -p aitm-poc --test builder` | 23 | 24 | 26 | 26 |

The filter row counts the 11 lib tests of `redact_strict` (the durable-audit sibling, merged by `f3c4a9c0`) and 2
`tunnel` tests; at the original cut `61a35571` the base filter was 56 and S7's 66, which is what the plan said. The
spec's 63 and 65 (AC12, the AC list header) are the Architect's scratch file, which merges AC6 and AC6b; read 64 and
66 for the original cut and the table above for the head. The "three scanner expectations" of Open question 1 and
Architect's call 4 are the four values AC19 edits (JSON `note` and `list`, form `note`, untyped body): read four.
**AC8's repeat counts give four families under 1 MiB** (1,000,000, 500,000, 524,306 and 1,000,002 bytes); the 1 MiB
floor of AC8 and "Left to the builder" binds, the counts do not (Architect's call 17).

**5. Pre-existing, unrated: an array or object value** (Residual risks 10). `{"api_keys": ["abc123", "def456"]}`
becomes `{"api_keys": [redacted]"abc123", "def456"]}` on both trees, text and wide (scratch). Named, not fixed.

**6. Tests: no AC25.** The code does not move. The invariant's check is Design 9 (I1', I5'), which AC23 already
requires. The tester's three rows pin row 29. Row 30 follows row 21, which AC10 pins and mutant M3 kills. A pin for
G1's visible token would pin the exposure of a token no secret key governs, and give the next conservative change a
red test for no gain; a pin of the masked nested value alone is AC1 to AC3. The one test edit is the plan's: AC8 is
one test, every family at 1 MiB or more, both scrubs (Q-4).

**7. Docs (Q-1, Q-2, Q-3, Q-9, S-4) and comments (Q-6, Q-7).** The docs are the plan's Fix 1, with exact text: the
module doc and the `scrub_text_wide` doc say the ownership-aware phrase, not "masks everything `scrub_text` masks";
Q-1: the two scans differ in the key test outside a masked value and in the host:port exemption, not in a third
place; Q-2: the risky quote is one that closes a value but reads as an opener (it follows `=` or `:`, a value
character follows, no delimiter does), the timing sentence says "linear" without a number; Q-3 and S-4: the
`scrub_text` doc states the malformed-quote residual and loses its empty sentence; Q-9: the two guards are named in
the code comments and the long linearity paragraph is split. Q-7: the production change (a method on `Reading`, or a
`matches!`) is accepted by the orchestrator, not made; the `Reading` docs get a comment-only sentence. AC14 stands:
no comment in the body of `mask_secret_pairs` says "reading". AC12's "every other existing test passes unedited" is
read as "no assertion, row or input of an existing test changes": Fix 1 edits the doc comment of one pre-existing
test (`scrub_text_wide_stays_linear_when_both_scans_have_work`, Q-6) and nothing else of it.

**8. Statements this amendment supersedes** (the ones marked "edited" are rewritten in place, the others are not and
are read as stated here): Goals bullets 3 and 4 (edited); Design 2, "Why the nested value is masked": "the old output
is never un-masked" is about the parent's token, and "the invariant I1" is I1'; Design 4, the C bullet (edited);
Design 5 hazard 2 (edited); Design 6 heading, lead, closing sentence (edited), and the paragraph "Unchanged (pinned by
AC4, AC5, AC7)", which is true of `scrub_text` and not of the wide reading for `token:\n  author: bob` and
`auth:\n  authority: example.com` (row 30); Design 7 items 1 and 3 (edited); Design 9 I1 and I5 (edited), the
"malformed-quote trigger" (now includes interleaved quotes) and the positive controls (b) to (d), which fire on I1'
as before; Residual risks 3, 4 (edited), 10 (new); Anti-goals bullet 1 ("anything the old output masked" reads "any
value that a secret key governs"); the Summary (one sentence added; its "0 old-masked canaries exposed" is a
measurement on the Architect's alphabets and stands as measured) and Architect's call 2 (same reading); AC12's 63 and 65 and AC8's
repeat counts (item 4); AC19's and Open question 1's "three" (item 4); AC23's "every group within Residual risks 3"
now includes G1 and G2.

**9. Open for Matt:** Open question 4 (read the constraint ownership-aware). Its default stands unless he reverses it.

## Intent

`aitm_core::redact::scrub_text` skips every blank, line breaks included, after a secret-named key and its
separator, and takes the next token as the value. When that token is itself a nested `key:` the parent
swallows it and the nested value is left in the clear: `auth:\n  password: hunter2` comes out
`auth:\n  [redacted] hunter2`. The same holds for `credentials:`, `secret:`, `token:`, `session:`,
`cookie:` and every other secret word as the parent, on one line (`auth: password: hunter2`) or on two.
The wide reading (`scrub_text_wide`, `scrub_embedded`, the PoC path) has the mirror problem: it stops at a
line break on purpose, so a credential on the line after a wide-only key is not masked at all
(`userSession:\n  S3SS10N9`), and a wide-only pair under a standard parent is hidden from it by the
standard scan (`auth:\n  sessionKey: abc123`). The leak is pre-existing, reaches every plain
`scrub_text` caller (audit error reasons, findings text, MCP error text, scanner and WebSocket
evidence) and, through the PoC builders, a shareable artifact on the url, json, form and text surfaces.
Matt's constraint is that the fix may not weaken what `scrub_text` masks today (PR 171 masks
`password:\n  hunter2` on purpose), so the rule has to read the nested pair without un-masking the
parent's token.

## Goals

- `scrub_text` masks the value of a secret pair that begins inside the value masked for another secret
  pair, in every layout of the bug list (Acceptance criteria 1 to 3).
- `scrub_text_wide` and `scrub_embedded` mask a credential on the line after a wide-only key and a
  wide-only pair under a standard parent (AC9, AC10, AC15, AC16).
- No value governed by a secret key becomes visible on well-formed input (ownership-aware, Amendment 1: a
  value is governed by the key written directly before it), and every value that looks like a pair
  (`token:\n  YWJj=`, `password:\n  s3cr:et`, basic-auth `user:pass`) stays masked (AC4 to AC7).
- Every class of `scrub_text` output change is listed (Design 6, Amendment 1); the recorded corpus
  `RECORDED_SCRUB_TEXT` loses no row; the rows of the wide corpora that change are named (AC11, AC15, AC19).
- The scan stays linear, with a hostile test for the new rule (AC8).

## Non-goals

- Changing the vocabulary, `is_secret_key`, `is_secret_key_wide`, the two regex passes, the host:port
  exemption, the closing-quote rule or the value-end rule.
- Masking the values of **non-secret** children of a secret parent (`auth:\n  user: bob` keeps `bob`;
  Architect's call 3). That needs a block or indentation model (approach B below, measured worse).
- Fixing the `Authorization` regex pass, which can eat a key that ends a line and orphan its next-line
  value (pre-existing, Residual risks 8).
- Any caller of `scrub_text` (`commands.rs`, `crawl.rs`, findings, audit, MCP, `aitm-scan-*`): their code
  does not move; their output moves only through `scrub_text`.
- A new dependency, `unsafe`, a public item, a config key.
- Editing the 2026-10-31 specs and plans. This spec supersedes the statements listed in Design 7.

## Anti-goals

- A fix that turns anything the old output masked into something exposed (approach A does; Design 4).
- Editing a pinned row to make it pass, other than the rows named in Design 6 and AC11, AC15, AC19.
- A second scan "for safety", or a rule that needs the key's column, a block model, or a lookahead whose
  cost is not constant per candidate.
- Hiding the churn of the wide reading: every changed wide row is named.

## Constraints

- Linear time, no per-byte allocation, no new public API. The only signatures that change are private: the
  `Reading` enum gains a value, `skip_pair_blanks` is deleted, `mask_secret_pairs(text: &str, reading:
  Reading) -> String` keeps its signature. `scrub_text`, `scrub_text_wide`, `is_secret_key` and
  `is_secret_key_wide` keep theirs.
- Rust gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. Suites that
  bind ports (`aitm-mcp`, the proxy tests of `aitm-core`) run in the Terminal panel; the sandbox cannot
  bind (`proxy::tests::acceptor_attaches_the_scope_guard_to_the_module_ctx` fails there on `main` too).
- Write only the files of Design 12. The PR body cites only completed real runs.

## Design

### 1. What I verified, and where it corrects the brief

1. **The bug, on `f2b0dae6`.** `mask_secret_pairs` skips all whitespace after a secret key and after its
   separator (`skip_blanks`), so the first token after the separator is the value, whatever it is. For
   `auth:\n  password: hunter2` the value is `password:` (an unquoted value runs to a blank or one of
   `& ; , " ' }`), the scan resumes after it, and `hunter2` is a key run with no separator. Old output
   `auth:\n  [redacted] hunter2`, confirmed (scratch) for the eleven parents `auth`, `credentials`,
   `secret`, `token`, `session`, `cookie`, `password`, `sid`, `jwt`, `csrf`, `api_key`.
2. **`auth:\n  password=hunter2` is not a leak.** With `=` and no blank the value token is the whole
   `password=hunter2`, masked as one: `auth:\n  [redacted]`. The leak needs a blank between the separator and
   the nested value, or between the nested key and its separator.
3. **`auth:\n  sessionKey: abc123` is not a leak through plain `scrub_text`.** `sessionKey` is neither a
   needle nor a whole segment, so `sessionKey: abc123` alone is left unchanged by the standard reading
   (`is_secret_key("sessionKey")` is false); the brief's list takes it from the PR 199 spec, where it is a
   *wide-reading* leak. Through `scrub_text_wide` and `scrub_embedded` it is one: old output
   `auth:\n  [redacted] abc123`, because the standard scan swallows the key before the wide scan runs.
4. **The standard scan hides a wide-only key from the wide scan at the top level too.** `jwt:\n\tsidebar :  "Q"`
   comes out `jwt:\n\t[redacted] :  "Q"` through `scrub_text_wide` on `f2b0dae6`: no parent needed.
5. **Callers.** Plain `scrub_text` (all reach the bug): `aitm-core/src/audit.rs:284` (client label);
   `aitm-mcp/src/server.rs:1955` (audit error reason) and `:2468` (`redact_value`, every argument string
   of the audit `args_summary`); `aitm-findings/src/store.rs:87-90` (title, notes, target, client label);
   `aitm-poc/src/builder.rs:273,283,284,289,319` (the builder never uses the wide reading: query values,
   header values, JSON string leaves, form values, and the opaque-body fallback);
   `aitm-plugin-scanner/src/commands.rs:261,282,306,393,492,505` (every free-text string of `scan.*`),
   `crawl.rs:270` (`safe_target`), `reproduce.rs:285,286` (`scrub_url`); `aitm-scan-ws/src/discover.rs:183`,
   `checks/cswsh.rs:141`, `checks/auth_bypass.rs:177` (examples and evidence excerpts);
   `aitm-scan-checks-http/src/matching.rs:111` (evidence). The wide reading has one caller:
   `aitm-plugin-scanner/src/reproduce.rs:376` (`scrub_embedded` = `scrub_text_wide(&strip_userinfo(text))`,
   used per decoded component by `Scrubber` for url, body, header, JSON and form text). The brief's list
   (audit ring, findings, MCP error text, `build_poc`) is incomplete.
6. **`build_poc` is the scanner's function** (`reproduce.rs:118`); `aitm-poc` has `StdPocBuilder::build`,
   which uses `scrub_text` only. The spec tests both with the real builder (AC18, AC19, AC21). Both leak on
   `f2b0dae6` on all four surfaces (scratch, real builders): `build_poc` gave
   `note=auth%3A%0A++%5Bredacted%5D+URLPW1` (url), `"auth:\n  [redacted] JSONPW2"` (json),
   `note=auth%3A%0A++%5Bredacted%5D+FORMPW3&page=2` (form) and `auth:\n  [redacted] RAWPW4` (text);
   `StdPocBuilder` the same shapes.

### 2. The rule (chosen: approach C, with two guards)

`mask_secret_pairs` stays one linear scan over the same primitives (`run_end`, `is_key_byte`,
`skip_blanks`, `closing_quote`, `unquoted_value_end`, `is_host_port`, the `copied` pointer). Four edits and a
cost bound (R2'):

- **R1, resume inside the masked value.** After a pair's value `[value_start, value_end)` is masked
  (`copied = value_end`, as today), the scan resumes at `value_start`, not at `value_end`. A new `masked_to:
  usize`, initially 0, is `value_end + 1` when the value was closed by its quote (`closer.is_some()`) and
  `value_end` otherwise: the first index not covered by the masked text, closing quote included.
  A pair whose key run starts before `copied` is called *nested*.
- **R2, a nested pair is skipped when its value would start inside the masked text.** After the separator
  and the blanks after it (`skip_blanks`), if the index of the first non-blank byte is before `masked_to`,
  the pair is left alone exactly as a pair with a non-secret key is (no value, no closing-quote search, the scan
  goes on after its key run). This is the **exact guard**, run before the quote handling and the closing-quote
  search. Its quote half matters: for `token="sid:" tail="x"` the nested `sid:` would otherwise read the
  parent's own closing quote as the opener of a value and swallow ` tail="x`.
- **R2', the early guard (a cost bound, never a behaviour).** Right after the separator is found, before the
  vocabulary is consulted, a pair whose index just after the separator is before `copied` is skipped. It is
  implied by R2 (inside the masked text the first non-blank byte is before `masked_to`), so it changes no
  output; it only keeps a long masked value full of nested keys from costing one lowercase allocation each.
- **R3, the key test inside a masked value.** `Reading::Standard` and `Reading::Wide` judge every key run by
  `is_secret_key` and `is_secret_key_wide`. A private third value (name left to the builder; call it
  `FirstOfWide` here) judges a key run that starts before `copied` by `is_secret_key_wide` and every other key
  run by `is_secret_key`; its host:port exemption is the standard one.
- **R4, one blank rule.** Both readings skip every whitespace character after a key run and after a
  separator. `skip_pair_blanks` and its Wide arm (the three ASCII line breaks as a boundary) are deleted;
  the two call sites call `skip_blanks`.

`scrub_text` is the two regex passes, then `mask_secret_pairs(.., Standard)`. `scrub_text_wide` is the same
two regex passes (a private helper shared by both, builder's call), then `mask_secret_pairs(.., FirstOfWide)`,
then `mask_secret_pairs(.., Wide)`. So the first scan of the wide scrub is `scrub_text`'s scan except in one
place (R3), and it is no longer literally `scrub_text(text)`.

**Why the nested value is masked and the nested key is masked too.** The parent's token is masked as today
(the old output is never un-masked: that is what keeps hazard 1 and the invariant I1 safe), and the nested
pair, read inside it, masks its own value: `auth:\n  password: hunter2` becomes `auth:\n  [redacted]
[redacted]`. The label `password:` stays masked, as it was.

**Termination and linearity.** The scan index strictly increases (after a masked pair it is `value_start`,
greater than the pair's key end). Key starts strictly increase, and a pair reaches a closing-quote search only
when its value starts at or after `masked_to >= copied`, so searches start at strictly increasing positions and
successful ones never overlap: each starts after the previous masked text. The failed-search memory of
`mask_secret_pairs` is sound for any strictly increasing sequence of starts (a later search considers a subset
of the candidates of an earlier failed one, and a candidate is judged on its neighbouring characters alone),
so its argument is unchanged. A byte is read once to find a value's end and once more when the scan walks the
masked value; masked values are disjoint and increasing, so a byte is in at most one. Blank runs are read by
the lookahead after a key run and by the loop's own steps, as before. The `copied` pointer logic needs
`value_start >= copied` at the slice `text[copied..value_start]`: R2 guarantees `value_start >= masked_to >=
copied`. Without R2 the scan panics on that slice (mutant M1, AC13).

### 3. The wide reading (decision, Architect's call 1)

The wide scan used to stop at `\n`, `\r`, `\x0c` beside a separator (PR 199 Amendment 1) so that a wide-only
parent could not swallow a nested key. R1 reads the nested pair, so crossing a line break is safe, and R4
drops the special case. What changes, all measured (scratch) and all named in Design 6 and AC11, AC15, AC19:

- A credential on the line after a wide-only key is masked: `userSession:\n  S3SS10N9` becomes
  `userSession:\n  [redacted]`, `sidebar:\nS3SS10N9` becomes `sidebar:\n[redacted]`.
- The wide reading over-redacts prose by design: `author:\nJohn` becomes `author:\n[redacted]`.
- A nested pair under a wide-only parent now reads `authentication:\n  [redacted] [redacted]` (it read
  `authentication:\n  password: [redacted]`): the parent takes the child's label as its value, as a standard parent
  does. A PoC text shows `[redacted] [redacted]` where it showed a label.

**Why not keep the boundary.** Keeping it (the shape `y_keep`, scratch: the same rule, `skip_pair_blanks`
left in place) changes one assertion of one existing test (the `sid:\n` row of
`scrub_text_wide_stays_linear_on_line_break_shapes`) and keeps every other fix, and leaves exactly the next-line
leak the brief lists: 11,487 of 300,000 nested inputs (the wide-only parents with a value on the next line) still
leak, against 0 for the chosen design (old: 89,302). It is the named alternative in Open questions 1.

**Why `scrub_text_wide` needs the third reading.** With R1 in a plain standard first scan (`scrub_text` then the
wide scan, the PR 199 shape) the first scan swallows a wide-only key as the value of a nested standard pair and
the wide scan can no longer see it. Measured (scratch, ownership-aware): that shape exposes a canary the
`f2b0dae6` output masked in 1,288 of 400,000 mutated nested inputs and 277 of 100,000 aligned ones
(`Credentials:\n\tjwt:\n\tsidebar :  "Q"` is the minimal kind). One wide scan alone, and a wide scan then a
standard scan, expose fewer (51 and 43 of 400,000 on the malformed alphabet against 15) but lose "masks
everything `scrub_text` masks" (I5: 23 of 400,000 for each, against 0). The chosen shape is the first scan with a wide key
test inside the masked value, then the wide scan: the best of the four on I1 and on I5. The price is that the
superset property is measured, no longer by construction (Residual risks 4).

### 4. The approaches weighed (measured; old output exposes a must-mask canary in 41,598 of 200,000 nested inputs)

All rows are `scrub_text` on 200,000 inputs of the Architect's nested-shape generator (parent, line break,
child pair; chains; every canary a unique alphanumeric token with a known governing key; seed `apr-1`).
`I1` = inputs where a canary the old output masked is exposed by the new one. `leaks` = inputs where a canary
of a secret pair is still exposed. `changed` = inputs whose output differs.

| Approach | What it does | I1 | leaks | changed | Verdict |
|---|---|---|---|---|---|
| A-any | the next-line token followed by a separator is a nested pair: the parent keeps an empty value, the scan resumes at the child | 19,470 | 27,458 | 96,469 | rejected |
| A-secret | same, only if the child key is secret and not a host:port | 6,612 | 17,111 | 58,871 | rejected |
| A-secret, same line too | same, with no line-break condition | 12,112 | 14,869 | 75,080 | rejected |
| B | A-secret and the child line indented deeper than the parent's | 5,619 | 31,819 | 31,043 | rejected |
| E | a value that starts after a line break runs to the end of that line | 2,258 | 15,217 | 74,969 | rejected |
| **C** | **resume inside the masked value, skip a nested value that starts inside it (R1, R2)** | **0** | **0** | 57,965 | **chosen** |

- **A (what it does: the parent keeps an empty value and the scan resumes at the child).** It *un-masks* the
  token the old output masked, so it cannot satisfy I1. On the hazard-1 table (Design 5) A-any exposes 14 of 15
  rows, among them the three the brief names (`token:\n  YWJj=`, `password:\n  s3cr:et`,
  `password:\n  user:pass`); A-secret exposes 5 of 15 (`token:\n  AApwdBB=`, `token:\n  AApwdBB==\n  other: 1`,
  `password:\n  sid:abc`, `password:\n  auth=xyz`, `password:\n  jwt=eyJhbGciOi.eyJzdWIi.sig=`). On 200,000
  random base64 credentials under a secret parent, A-any exposes 94,519 and A-secret 21 (a padded body that
  holds `pwd` before the `=` reads as a secret key and a separator); the chosen rule exposes 0 of 300,000. A
  also moves the swallow one level down: an empty-valued child takes the next sibling's key as its value
  (`COOKIE : \r\nsession= csrf:\tQ1` exposes `Q1`; the old output masked it). It reads better
  (`auth:\n  password: [redacted]`) and I judged that not worth any exposure.
- **B (indentation).** It cannot tell a value from a key: `token:\n  YWJj=` and `auth:\n  password=x` are
  indented the same. It leaves the same-indent sibling (`auth:\npassword: hunter2`) as it was, needs the column of
  the parent's line (a backward scan per candidate, quadratic on a long line without a pointer), and tabs,
  `\r`-only and `\x0c` make "deeper" ambiguous. Strictly weaker than A-secret.
- **E (the whole next line).** Simple and linear, but it masks every following line after any secret label
  (`Session token:\n- found in the cookie jar` loses the line), and it still exposes (I1 2,258): a line end inside the
  swallowed text cuts the masked region where the old scan found a pair (`sid:\x0cSUBSIDIARY: ; SESSION:\x0c'Q1 Q2'`
  was `sid:\x0c[redacted] ; SESSION:\x0c'[redacted]'` and becomes `sid:\x0c[redacted]\x0c'Q1 Q2'`).
- **The old rule with line breaks not skipped** (revert PR 171) contradicts the test
  `scrub_text_masks_a_value_on_the_next_line` (`password:\n  hunter2`, `token=\r\nabc123`) and the recorded row
  `sid\n=\nx`. Not a candidate.
- **C (chosen).** By design the parent's token is masked as today and the nested pair adds masks inside it; the
  only masks it removes are ones the old scan made by misreading a quote (family G1, Residual risks 3), so it never
  un-masks a value that a secret key governs (ownership-aware, Amendment 1). Measured on the Architect's
  well-formed alphabets: I1 0, leaks 0, hazard-1 15 of 15 identical to the old output, 0 of 600,000 random padded
  base64 credentials exposed (top-level parent and nested pair); those alphabets never reached G1, which is why the
  raw reading ("every token the old output masked") was not found false here. It changes the output of 57,965 of
  these 200,000 inputs, all of them inputs where a secret pair begins inside a masked value (Design 6; the input
  regex TRIG of Design 9 matches every one of 234,656 changed inputs of 2.1M). It is not a superset of the old
  output on well-formed input (G1) or on malformed quotes (G2, G3): Residual risks 3.
- **A fifth variant, C with an A-style exception** (a nested pair takes no value when the next token itself
  starts a secret pair, "G3" in the scratch) was built and measured because it changes fewer outputs (no label
  churn in chains, every existing standard row unchanged). With a generator that holds needle-bearing
  credentials (`Qpwd001Z=`, a body that reads as a secret key and a separator) it exposes what the old output
  masked: I1 202 of 300,000 on the wide path and 2 on the standard one, against 0 and 0 for C; 4,266 and 5,805
  inputs still leak, against 0. Rejected on I1 and I2; the label churn it avoids is in Open questions 2.

### 5. The hazards, each run for real

**1. A value that looks like a pair (AC5, guard).** Output of the old and of the chosen rule, identical on all
15 rows (scratch): `token:\n  YWJj=`, `token:\n  YWJj==`, `password:\n  s3cr:et`, `token:\n  dXNlcjpwYXNz`,
`password:\n  user:pass`, `token:\n  AApwdBB=`, `token:\n  AApwdBB==\n  other: 1`, `password:\n  sid:abc`,
`password:\n  auth=xyz`, `secret:\n  a=b`, `auth:\n  user:pass`, `token:\r\n  YWJj=\r\n`,
`session:\n\tQWxhZGRpbjpvcGVuIHNlc2FtZQ==`, `password:\n  jwt=eyJhbGciOi.eyJzdWIi.sig=`, `api_key:\n  Key=AAA=:` all give
`<parent>:<layout>[redacted]` (`token:\n  AApwdBB==\n  other: 1` keeps `\n  other: 1`). Why C holds: the parent's
token is masked first; the token that reads like a pair is *inside* that masked value, and a nested pair whose
value starts inside it is skipped (R2).

**2. No value governed by a secret key is un-masked; the quote-closing search and the `copied` pointer (AC6, AC8,
mutants).** C keeps such a value masked by R2, not by accident (ownership-aware, Amendment 1; the raw reading,
"the old output is never un-masked", fails on family G1, Residual risks 3). Without R2 and the early guard the scan panics
(`text[copied..value_start]` with the start after the end) and 16 tests of the final suite fail (mutant M1). The
closing-quote half of R2 is its own mutant: with `masked_to = value_end` for a quoted value (mutant M2), every
existing test stays green and only AC7 fails (`token="sid:" tail="x"` gives `token="[redacted]"[redacted]"`). The
opener-chain shapes keep their old outputs (`sid:"sid:"sid:"x"` is `sid:"[redacted]"` before and after) and stay
linear (Design 9, I4).

**3. The forms of the brief (AC1 to AC4; chosen output, scratch).** `=` separator: `auth:\n  password=hunter2`
stays `auth:\n  [redacted]` (no leak). Tab, CRLF, `\r`, `\x0c`, four spaces: `auth:\r\n  password: hunter2` gives
`auth:\r\n  [redacted] [redacted]`, likewise `auth:\n\tpassword: hunter2`, `auth:\r  password: hunter2`,
`auth:\x0c  password: hunter2`. Quoted keys: `"auth":\n  "password": "x"` gives `"auth":\n  "[redacted]": "[redacted]"`.
YAML comment between parent and child: `auth:\n  # note\n  password: hunter2` is unchanged
(`auth:\n  [redacted] note\n  password: [redacted]`: the parent masks `#`, the child is a plain pair). List item:
`credentials:\n  - password: hunter2` unchanged (`-` masked, the pair masked). Chains of secret parents:
`auth:\n  token:\n    secret:\n      password: hunter2` leaked `hunter2` and now gives
`auth:\n  [redacted]\n    [redacted]\n      [redacted] [redacted]`; with a non-secret middle
(`auth:\n  creds:\n    password: hunter2`) the old output already masked the value and is unchanged. A secret
parent with a non-secret child: `auth:\n  user: bob` is unchanged (`auth:\n  [redacted] bob`; `bob` stays,
Architect's call 3). An empty value then a line break: `auth:\n` unchanged. A value on the parent's line followed
by a block: `auth: x\n  password: hunter2` unchanged (`auth: [redacted]\n  password: [redacted]`). The same-line
nested pair `auth: password: hunter2` gives `auth: [redacted] [redacted]`.

**4. Linearity (AC8, Design 9 I4).** (scratch, release build, the chosen rule against `f2b0dae6`, best of three, 1,
2, 4, 8 MiB). Every family grows by about 2 per doubling. The largest cost is a quoted value that holds a
megabyte of nested keys (`token="a=a=a=...`: 13 ms to 161 ms at 8 MiB, 12 times; the early guard R2' cuts it from
about 35 times), the opener chain `sid:"sid:"...x"` 5 times (17 ms to 85 ms), one 8 MiB token after `sid:` 2.1
times, a chain of parents 2.4 times; every other family at most about 3 times in the quiet runs, and the blank-run
families the same as before. On a loaded machine the timings jitter by a factor of two or three: the reviewer takes best of three.

**5. The wide reading (AC9, AC10, AC11, AC19; Design 3).** Measured (scratch, all against the `f2b0dae6` wide
output, fresh seeds, 300,000 per alphabet): ownership-aware I1 0 on the unmutated nested alphabet; raw I1 0 on aligned,
dc and nest, 1 on soup, 18 on the malformed `full` alphabet; every canary of a wide-secret pair in the nested
alphabet masked (old leaks 89,302, new 0). Over-redaction is in the table of Design 6.

### 6. The output changes, by class

The rows are the classes of change, each with its inputs; they are not a list of every changed input (Amendment 1,
S-3: two classes were missing, rows 29 and 30). `scrub_text` (standard reading). A change happens when and only when
the scan reads a secret pair that began inside a value it had just masked and whose own value starts after that
masked text. Either that value was exposed (rows 1 to 10), or the "value" is a key label that the nested pair now
takes (rows 11 to 16), or the parent's quoted value ended early at a quote with a value character behind it and the
nested pair takes the next token (row 29); each of these masks a token the old output left visible. One class goes
the other way, family G1 (Amendment 1, S-1; Residual risks 3): when the nested pair is a quoted value that ends in a
key and a separator, the old output read its closing quote as the opener of a pair and masked the text after it; the
new output reads the pair, and a token that no secret key governs, after the closing quote, stays visible. No pinned
row of `RECORDED_SCRUB_TEXT` changes: run on a scratch copy of the
chosen rule, `scrub_text_is_unchanged_on_the_recorded_corpus` passes with all 183 rows unedited (the standard
reading is untouched wherever no pair is nested).

| # | Input | Old output | New output | Touches |
|---|---|---|---|---|
| 1 | `{p}:\n  password: hunter2` (p = auth, credentials, secret, token, session, cookie, password, sid, jwt, csrf, api_key) | `{p}:\n  [redacted] hunter2` | `{p}:\n  [redacted] [redacted]` | AC1 |
| 2 | `auth:\r\n  password: hunter2`, `auth:\n\tpassword: hunter2`, `auth:\r  password: hunter2`, `auth:\x0c  password: hunter2`, `auth:\n    password: hunter2` | the same with `[redacted] hunter2` | the same with `[redacted] [redacted]` | AC1 |
| 3 | `token:\r\n\tsid: S1`, `session:\n  csrf: C9` | `token:\r\n\t[redacted] S1`, `session:\n  [redacted] C9` | `[redacted] [redacted]` in both | AC1 |
| 4 | `"auth":\n  "password": "x"` | `"auth":\n  "[redacted]": "x"` | `"auth":\n  "[redacted]": "[redacted]"` | AC2 |
| 5 | `'auth':\n  'password' : 'x y'` | `'auth':\n  '[redacted]' : 'x y'` | `'auth':\n  '[redacted]' : '[redacted]'` | AC2 |
| 6 | `auth: password: hunter2` | `auth: [redacted] hunter2` | `auth: [redacted] [redacted]` | AC2 |
| 7 | `auth:\n  password :   hunter2` | `auth:\n  [redacted] :   hunter2` | `auth:\n  [redacted] :   [redacted]` | AC2 |
| 8 | `auth:\n  password:\n    hunter2` | `auth:\n  [redacted]\n    hunter2` | `auth:\n  [redacted]\n    [redacted]` | AC2 |
| 9 | `auth:\n  password: 'hunter2'` | `auth:\n  [redacted] 'hunter2'` | `auth:\n  [redacted] '[redacted]'` | AC2 |
| 10 | `auth:\n\n\n\n\n  password: x` | `auth:\n\n\n\n\n  [redacted] x` | `auth:\n\n\n\n\n  [redacted] [redacted]` | AC2 |
| 11 | `token:\n  sid:\n  password: hunter2` | `token:\n  [redacted]\n  password: [redacted]` | `token:\n  [redacted]\n  [redacted] [redacted]` | AC3 |
| 12 | `auth:\n  secret:\n    password: hunter2` | `auth:\n  [redacted]\n    password: [redacted]` | `auth:\n  [redacted]\n    [redacted] [redacted]` | AC3 |
| 13 | `auth:\n  token:\n    secret:\n      password: hunter2` | `auth:\n  [redacted]\n    secret:\n      [redacted] hunter2` | `auth:\n  [redacted]\n    [redacted]\n      [redacted] [redacted]` | AC3 |
| 14 | `auth:\n  password:\n  sid=abc` | `auth:\n  [redacted]\n  sid=[redacted]` | `auth:\n  [redacted]\n  [redacted]` | AC3 |
| 15 | `auth:\n  secret:\n    "password": "x"` | `auth:\n  [redacted]\n    "password": "[redacted]"` | `auth:\n  [redacted]\n    "[redacted]": "[redacted]"` | AC3 |
| 16 | `sid:\nsid:\nsid:\n` | `sid:\n[redacted]\nsid:\n` | `sid:\n[redacted]\n[redacted]\n` | AC3; `scrub_text_wide_stays_linear_on_line_break_shapes` (assertion 4) |

Unchanged (pinned by AC4, AC5, AC7): the hazard-1 rows, `auth:\n  password=hunter2`, `auth:\n  user: bob`,
`token:\n  author: bob`, `auth:\n  authority: example.com`, the comment and list rows, `auth: x\n  password:
hunter2`, `auth:\n  sessionKey: abc123` (standard reading: `auth:\n  [redacted] abc123`),
`Authorization:\n  password: hunter2` (the regex pass), `token="sid: " tail="x"` and its four siblings of AC7.

`scrub_text_wide` and `scrub_embedded` (the wide reading). Rows 1 to 16 hold for the wide reading too, plus:

| # | Input | Old output | New output | Touches |
|---|---|---|---|---|
| 17 | `userSession:\n  S3SS10N9` | unchanged | `userSession:\n  [redacted]` | AC9, AC16 |
| 18 | `sidebar:\nS3SS10N9`, `userSession:\r\n\tS3SS10N9`, `sessionKey:\n  abc123` | unchanged | the next-line token masked (`sidebar:\n[redacted]`, `userSession:\r\n\t[redacted]`, `sessionKey:\n  [redacted]`) | AC9 |
| 19 | `author:\nJohn` | unchanged | `author:\n[redacted]` | AC9, AC11, AC15, AC16 |
| 20 | `sidebar=\x0cv`, `sidebar\n:v`, `sidebar:\r\nv` | unchanged | `sidebar=\x0c[redacted]`, `sidebar\n:[redacted]`, `sidebar:\r\n[redacted]` | AC9, AC11, AC15 |
| 21 | `auth:\n  sessionKey: abc123` | `auth:\n  [redacted] abc123` | `auth:\n  [redacted] [redacted]` | AC10, AC16 |
| 22 | `auth: sessionKey: abc123` | `auth: [redacted] abc123` | `auth: [redacted] [redacted]` | AC10 |
| 23 | `jwt:\n\tsidebar :  "Q"` | `jwt:\n\t[redacted] :  "Q"` | `jwt:\n\t[redacted] :  "[redacted]"` | AC10 |
| 24 | `Credentials:\n\tjwt:\n\tsidebar :  "Q"` | `Credentials:\n\t[redacted]\n\tsidebar :  "[redacted]"` | `Credentials:\n\t[redacted]\n\t[redacted] :  "[redacted]"` | AC10 |
| 25 | `authentication:\n  password: hunter2`, `author:\n  token: abc123`, `sessions:\n  jwt: J1`, `sidebar:\n    api_key: K1` | `authentication:\n  password: [redacted]` and its three siblings (label kept) | `authentication:\n  [redacted] [redacted]` and its three siblings | AC11, AC15, AC19 |
| 26 | `authentication:\n  sessionKey: abc123` | `authentication:\n  sessionKey: [redacted]` | `authentication:\n  [redacted] [redacted]` | AC11, AC15 |
| 27 | `side:\nSid2':C`, `bsid:\rSIDE:'C` | `side:\nSid2':[redacted]`, `bsid:\rSIDE:'[redacted]` | `side:\n[redacted]':[redacted]`, `bsid:\r[redacted]'[redacted]` | AC11, AC15 |
| 28 | the four PR 199 reproducers of arms D1 to D4: `authr\u{e9}=QAUTH:"Q7`, `NSid\u{2009}:AUTHO:"Q8`, `token.example.com:8443/x?sessions="Q5"`, `nsid='='authr'=C1` (and `sidebar="a=":"sessions":"C1"`) | the nested value left (`...:"Q7`, `...:"Q8`, `"Q5"`, `=C1`, `":"C1"`) | the nested value masked | none pinned; Residual risks 7 |

Rows 17 to 28 are the change of the wide reading beyond rows 1 to 16 that follows from dropping the boundary at a
line break (Design 3); rows 29 and 30 below are two classes this list first missed (Amendment 1, S-3). Unchanged wide
rows that the corpora pin and the new rule keeps: `authentication: {password: hunter2}`,
`sidebar=sid="C1"`, `author=password='C2'`, `inside=x?sid\t=\tC9`, `Auths:Pwd: C`, `sid:\nabc`,
`X-Authority: example.com\r\nX-Sid: S1\r\n`.

Rows added by Amendment 1 (S-3; real outputs of `ecbf58ac` and `a2181852`, both readings unless a row says one):

| # | Input | Old output | New output | Touches |
|---|---|---|---|---|
| 29 | `token="sid:"x`, `token="sid:"\u{e9}`, `token="sid:"\u{1f600}` (a value character directly behind the closing quote; both readings) | `token="[redacted]"x`, `token="[redacted]"\u{e9}`, `token="[redacted]"\u{1f600}` | `token="[redacted]"[redacted]` for each | Residual risks 3 (the opener-shaped quote); pinned by the three rows of `scrub_text_reads_the_edges_of_a_nested_pair` (a 1-, 2- and 4-byte character after the quote: a char-boundary check) |
| 30 | `token:\n  author: bob`, `auth:\n  authority: example.com` (wide reading only: `author` and `authority` are wide-only keys nested under a standard parent) | `token:\n  [redacted] bob`, `auth:\n  [redacted] example.com` | `token:\n  [redacted] [redacted]`, `auth:\n  [redacted] [redacted]` | row 21's rule (AC10; mutant M3 kills it); not pinned by a row of its own. `scrub_text` keeps `bob` and `example.com` (AC4) |

Row 29: the quote after `sid:` has a value character behind it, so it is shaped like an opener and the parent's
quoted value does not close there; the parent's value is the plain run `sid:`, the nested `sid:` starts at that
quote and takes the next token. With a blank or a line break behind the quote (`token="sid:" x`, `token="sid:"\nx`)
the output is unchanged. Both rows only mask more.

### 7. Docs and comments to fix (the complete list)

Core, `crates/aitm-core/src/redact.rs`:
1. Module doc (the two paragraphs about `scrub_text_wide`, lines 16 to 35): the first scan of the wide scrub reads
   like `scrub_text`'s except that a key run inside a value it has masked is judged by the wide reading; the
   second is the wide scan; they share every blank rule, value rule and quote rule; the differences are the key
   test outside a masked value and the host:port exemption (Amendment 1, Q-1: inside a masked value both scans
   use the wide key test, so that is no third difference); delete the sentence about `\n`, `\r`, `\x0c` and the
   `author:\nJohn` / `sid:\nabc` pair. State that a pair that begins inside a masked value is read.
2. `scrub_text` doc: add that a secret pair that begins inside a value just masked is read too
   (`auth:\n  password: hunter2` masks `hunter2`), what stays (`auth:\n  user: bob` keeps `bob`, a value that looks
   like a pair stays masked whole), and that an empty value is left alone. Keep the host:port paragraph.
3. `scrub_text_wide` doc: rewrite as Design 2 and 3 say. Remove "does not skip `\n`, `\r` or `\x0c`", "reads a pair
   on one line", the credential-on-the-next-line paragraph, and the four-shape residual sentence (replace it by the
   malformed-quote residual of Residual risks 3). Say that on well-formed input it masks every value that a
   secret key governs under `scrub_text` (the ownership-aware phrase of Amendment 1), not "masks everything
   `scrub_text` masks" and not "by construction", and replace "about twice that of `scrub_text`, except on long
   runs of blank characters" by "linear" with no number: the bound of Design 9 I4 is a Stage 6 check, not a doc
   claim (Amendment 1, Q-2).
4. `Reading` enum docs: three variants and what each reads; delete the line-break description.
5. `skip_pair_blanks`: deleted with its doc; `skip_blanks` doc unchanged.
6. `mask_secret_pairs` doc: `reading` is consulted in exactly two places (the key test, with its in-region
   variant, and the host:port exemption); the scan resumes at a masked value's start; R2 and R2'; the linearity
   paragraph of Design 2 replaces the "successful searches never overlap" paragraph.
7. Tests that name the deleted rule keep or lose their names as AC11 says.

Scanner, `crates/aitm-plugin-scanner/src/reproduce.rs`:
8. `scrub_embedded` doc (the sentence "it runs core's one pair scan twice, first with the standard reading and
   then with the wide one"): the two scans differ in the key test inside a masked value; a pair that begins
   inside a masked value, and a line break beside a separator, are read.
9. The comment above the `(xii)` rows of `RECORDED_SCRUB_EMBEDDED` ("a line break or form feed beside the separator
   of a wide-only key") goes with the ten rows that move (AC15); the doc of
   `scrub_embedded_matches_the_recorded_pipeline_output` keeps saying "the recorded output of the old pipeline at
   `15009b2`", which is true of the rows that stay.

Statements of the 2026-10-31 spec and plan that this spec supersedes (not edited): Amendment 1 item 2 and its
table (the line-break boundary); Amendment 2 item 2; Design 3 (the wide doc sentence on the boundary and the
credential on the next line); Design 4 (the three consultations of `reading`, the blank rule of the wide scan,
`skip_pair_blanks`); Design 5 row 3a; Design 6 DC2's line-break half; Residual risks 8 (arms D1 to D4: the four
named reproducers now mask), 9 (F4: fixed here), 11 (next-line credential under a wide-only key: fixed here);
AC5's `author:\u{a0}John` row, AC14 and AC15's line-break rows, AC19, AC25 to AC27, Architect's calls 3, 12, 13,
16; the plan's Shipped follow-up 1. The aitm-poc test comments that say the shared set "lacks jwt/sid" stay
untouched (still a later docs sweep).

### 8. Callers

See Design 1 item 5. No caller changes. `commands.rs`, `crawl.rs`, `discover.rs`, `server.rs`, `store.rs`,
`audit.rs`, `aitm-scan-*`, `aitm-poc/src` are not edited. Their suites pass unedited on a scratch copy of the
chosen rule: `aitm-findings`, `aitm-scan-checks-http`, `aitm-scan-ws` (192 lib tests), `aitm-plugins`,
`aitm-poc` (`tests/builder.rs`, 23 tests), `aitm-core` (all lib tests except the socket test), and the
`durable-audit-462ca8` sibling's `redact_strict` suite (28 tests) and `audit` lib tests (46) built over the new
`redact.rs`. `aitm-mcp` runs in the Terminal panel.

### 9. Equivalence strategy (Stage 6, the security reviewer)

The old pipeline is not kept in the repository. The reviewer builds, out of tree, the old tree (`f2b0dae6` or the
base SHA of the branch) and the head under review, each in a scratch tree cut with `git archive`, each with a
wrapper runner exposing `scrub_text`, `scrub_text_wide`, `scrub_embedded` and `is_secret_key` (JSON line in, JSON
line out; a panic reported as a value). **Reuse** `/tmp/claude-501/svc-diff-tools-r2/difftool_r2.py` (generators
`aligned`, `full`, `soup`, `dc`, `nest`; its runners are `diffrun.rs` and `diffrun_new.rs` in
`/tmp/claude-501/svc-diff-tools/runner-src/`) and the Architect's scratch
`/tmp/claude-501/nested-scratch/` (`gen2.py`: nested shapes with a known governing key per canary, plus a
mutating variant `gen2m`; `diff3.py`: the harness; `trig.py`: TRIG; `minimize.py`; `timing.py`; `mkvariants.py` and
`runmutants.py`). `/tmp` may be cleared: rebuild from this description, and copy what is reused to a durable
place if the plan asks. Every secret value is a unique alphanumeric canary; the generators avoid the
`Authorization` and `bearer` keys (the regex pass, Residual risks 8). The alphabets: **aligned** (the r2 aligned
alphabet, line breaks at separators and parent/child lines included), **full** (malformed: unbalanced quotes,
non-ASCII, vertical tab), **nested** (`gen2` and `gen2m`; ownership known), and `soup` and `dc` for breadth.

Minimum counts: at least 4,000,000 inputs in all (the brief asks 3,000,000), at least 1,000,000 on each of
aligned, full and nested, and at least 500,000 on each of soup and dc. Seeds (start with these, add more):
`nestfix-aligned-20261101`, `nestfix-full-20261101`, `nestfix-soup-20261101`, `nestfix-dc-20261101`,
`nestfix-nest-20261101`, `nestfix-gen2-20261101`, `nestfix-gen2m-20261101`, `nestfix-b64-20261101`.

- **I1 (no regression; ownership-aware, Amendment 1).** The pass criterion on every alphabet is **ownership-aware
  I1'**: every canary that `old(x)` masks and whose governing key is secret under the reading (`is_secret_key` for
  `scrub_text`, `is_secret_key_wide` for `scrub_text_wide` and `scrub_embedded`; the governing key is the key
  written directly before the canary) is absent from `new(x)`. I1' is 0 on every alphabet whose input is
  well-formed (aligned, dc, nest, unmutated nested, and any well-formed structured-text alphabet, such as the
  Stage 6 reviewer's `wf` and `fa`) and at most 5 per 1,000,000 on the mutated alphabet, each a minimal reproducer
  whose quotes are malformed (unmatched, unescaped, opener-shaped, or two kinds interleaved). **Raw I1** (every
  canary absent from `old(x)` is absent from `new(x)`, governing key or not) is reported and is never a pass
  criterion; its violations are minimised and grouped by family, and each family must be one of Residual risks 3
  (G1 on well-formed input; G2, G3 and the opener-shaped quote on malformed input). Measured by the Architect
  (scratch, 300,000 per alphabet unless noted; alphabets that never put a hazard value inside quotes): raw I1 for
  `scrub_text` 0 on aligned, soup, dc, nest and nested, 5 on full; for `scrub_text_wide` 0 on aligned, dc, nest and
  nested, 1 on soup, 18 on full; ownership-aware 1 per 600,000 mutated for each. Measured by the Stage 6 reviewer on
  head `a2181852` (Amendment 1): raw I1 0, so I1' 0, on aligned (2.4M), dc, nest and soup; I1' 0 on gen2 (2.0M), on
  `wf` (3.0M) and on `fa` (0.4M); on the mutated alphabet (4.0M) I1' 3 for `scrub_text` and 6 for the wide
  functions (0.75 and 1.5 per 1,000,000); raw I1 on `wf` 799 and 1,049, and on `fa` 7,157 and 12,438, every one of
  the 1,185 sampled and minimised being family G1.
- **I2 (completeness).** On the unmutated nested alphabet every canary whose governing key is secret under the
  reading is masked by `new(x)`: zero. Measured 0 leaking inputs of 300,000 for `scrub_text` and for
  `scrub_text_wide` (old: 61,992 and 89,302). The hazard shapes are in the alphabet (`Q...pwd...Z=`,
  `Q...Z==`, `user:Q...Z`, `Q...Z:more`, a secret word then a separator then the canary).
- **I3 (byte equality outside the trigger).** TRIG (necessary condition for any change of `scrub_text`): a
  separator `=` or `:`, then blanks, then a token or a quoted run that ends in a key run, then an optional quote
  and blanks, then a separator (the escape-aware regex of `trig.py`; blanks are the Unicode whitespace of
  `char::is_whitespace`). TRIG-W adds a line break (`\n`, `\r`, `\x0c`) that touches a separator through blanks.
  On every input TRIG does not match, `new == old` for `scrub_text`; on every input TRIG-W does not match,
  `new == old` for `scrub_text_wide` and `scrub_embedded`. At least 1,000,000 such inputs per function, zero
  differences; and **no changed input without a TRIG match**. Measured: of 2,100,000 inputs over seven
  generators, 234,656 changed and all match TRIG; 675,748 non-TRIG inputs and 475,676 non-TRIG-W inputs, zero
  differences.
- **I4 (robustness and linear time).** No panic or char-boundary fault; for each hostile family of AC8 plus
  `author:\n` repeated, `authentication:\n  sessionKey: x\n` repeated and a megabyte newline run after a wide-only
  key, the time at 2, 4 and 8 MiB is at most 3.0 times the time at the previous size (best of three), and the time
  at 8 MiB is at most 20 times the old tree's. Measured worst: 12 times (`token="a=a=a=..."`).
- **I5 (superset; ownership-aware, Amendment 1).** The pass criterion is **I5'**: every canary absent from
  `scrub_text(x)` whose governing key is secret under the standard reading is absent from `scrub_text_wide(x)`:
  zero on every alphabet whose input is well-formed and on unmutated nested; on the malformed alphabets each
  violation is a minimal reproducer whose quotes are malformed. **Raw I5** (any canary) is reported and grouped by
  family, never a pass criterion. Measured by the Architect (scratch): raw 0 on every alphabet but full (3 of
  300,000). Measured by the Stage 6 reviewer on head `a2181852`: raw I5 0 on aligned, nest, dc, soup and gen2; 9 of
  2.4M on full (8 with a quote trigger); 1 of 4.0M on the mutated alphabet (interleaved quotes); 374 of 3.0M on `wf`
  and 836 of 0.4M on `fa` (family G1: the standard scan reads a closing quote as an opener, the wide scan reads the
  pair correctly); I5' 0 on re-runs of 500,000 `wf`, 500,000 mutated and 200,000 `fa`.
- **I6 (hazard 1 at scale).** At least 1,000,000 random base64 credentials (6 to 40 random bytes, standard and
  URL-safe alphabets, padded and not) in `{p}:{layout}<credential>` for p in token, password, secret, session,
  auth, api_key, cookie and layouts `\n  `, `\r\n    `, `=\n\t`, `:\n`: zero left in the clear by `scrub_text`,
  `scrub_text_wide` and `scrub_embedded`; and under a nested pair (`auth:\n  password:\n    <credential>`) zero.
  Measured 0 of 300,000 for each (old: 0 top-level, 299,942 nested).
- **Positive controls (must fire).** (a) The old tree on the nested alphabet reports I2 leaks within the first 1,000
  inputs (measured 41,598 of 200,000). (b) Mutant M4 (the fix reverted, AC13) reports them too. (c)
  The A-secret mutant (the next-line token that starts a secret pair is not the parent's value) reports I1
  violations within the first 100,000 nested inputs (measured 6,612 of 200,000) and fails the hazard-1 rows. (d)
  Mutant M3 (no wide key test inside a masked value) reports wide I1 violations on the aligned and nested alphabets
  (measured 277 of 100,000 aligned and 1,288 of 400,000 mutated nested, as the `scrub_text`-then-wide shape).
  (e) Mutant M5 (the wide boundary restored) reports wide I2 leaks (measured 11,487 of 300,000).
  A control that does not fire invalidates the run.

### 10. Residual risks

1. **A non-secret child keeps its value.** `auth:\n  user: bob` is `auth:\n  [redacted] bob`; `bob` is exposed
   because `user` is not a secret key (Architect's call 3).
2. **Multi-token values** (`password: correct horse`) mask the first token only: the shared value rule, unchanged.
3. **C is not a superset of the old output (amended: Amendment 1).** The nested scan reads the quotes of a pair
   that the old scan left inside a masked value, and pairs them differently. Three families. None exposes a value
   that a secret key governs on well-formed input (the ownership-aware invariant of Amendment 1); the differential
   reports and groups each, and no test pins any of them (a test must not pin a leak).
   - **G1, well-formed: no malformed quote anywhere.** A quoted value whose last token is a key that holds a needle,
     then a separator, then the closing quote (`"x-pwd:"`, `'pwd='`, `"csid="`), nested under a secret parent that
     swallows its key: `token:\n  apikey: "x-pwd:"\n  note: "hello"`. The old scan read that closing quote as the
     opener of a pair and masked the text after it, often the next line (`note: "hello`); the new scan reads the
     nested pair, closes the quote correctly, and the text after it is read by its own keys. The token that becomes
     visible is governed by a non-secret key (`note`) or by no key; the old output hid it only through the misparse,
     and a bare token with no recognisable key is the documented residual of the scrub. The nested value itself,
     `x-pwd:`, which the old output left in the clear, is now masked. Real outputs: Amendment 1, S-1. Not fixed, and
     not fixable without the misparse (Amendment 1). Measured by the Stage 6 reviewer: raw I1 799 (`scrub_text`) and
     1,049 (wide) of 3,000,000 well-formed inputs, 7,157 and 12,438 of 400,000 targeted ones; ownership-aware 0 of
     3.4M. Measured by the Architect on 5,248,800 inputs of a G1 generator of my own (scratch): raw I1 656,100 and
     874,800, every one a token governed by a non-secret key; ownership-aware 0; no token governed by a secret key
     exposed.
   - **G2, interleaved quotes of two kinds** (`Token:Jwt:'token="'id"`, `Side=\n'rsession="'QZ"`): each kind has an
     even count, so a harness trigger for an unmatched or unescaped quote misses it; the two scans pair the quotes
     differently. Measured by the reviewer on `full` (2.4M): raw I1 31 for `scrub_text` and 101 for the wide scrub
     (the harness trigger flagged 30 and 97 of the unminimised originals); minimised, all 31 and 82 of the 101 are
     G2, 18 are G3 and 1 is G1. On the mutated alphabet one ownership-aware violation is a G2 shape that the harness
     trigger did not flag.
   - **G3, an unmatched or opener-shaped quote** (`Auth:csrf:'pwd='&4Z'`): as first written. Measured (scratch, the
     Architect): raw I1 5 of 300,000 on the malformed alphabet for `scrub_text`, 18 for the wide scrub;
     ownership-aware 1 of 600,000 mutated inputs. The one real shape found at design time: `jwt:\x0cAPI_KEY:'   Q1=\n  sid=  '\u{2028}Q2 Q3'` exposes `Q2 Q3`
     and masks `Q1`, which the old output exposed (an unmatched `'` after `API_KEY:` swaps which of the two is read).
   G2 and G3 together, ownership-aware, on the mutated alphabet (4.0M inputs, reviewer): 3 for `scrub_text` and 6 for
   the wide scrub, 0.75 and 1.5 per 1,000,000 (the bound of Design 9 I1 is 5); each minimises to a malformed or
   interleaved-quote reproducer. Rated Minor.
4. **The wide superset is measured, no longer by construction, and it is ownership-aware (amended: Amendment 1).**
   The first scan of the wide scrub is not literally `scrub_text`. Measured I5 (the Architect, scratch): 3 of
   300,000 on the malformed alphabet, 0 elsewhere. The Stage 6 reviewer's raw I5 is non-zero on well-formed text
   too (374 of 3,000,000 on `wf`): family G1, where the standard scan keeps reading a closing quote as an opener and
   masks a token that no secret key governs, and the wide scan reads the pair correctly and does not. Ownership-aware
   I5' is 0 (Design 9 I5). G2 and G3 apply to the wide scrub as in 3.
5. **Label churn (over-redaction, the safe direction).** In a chain of secret keys with no same-line value the
   nested pair takes the next line's token: `sid:\nsid:\nsid:\n` masks the second `sid:`; `auth:\n  secret:\n
   password: hunter2` masks `password:`. The wide reading shows `[redacted] [redacted]` where it showed a label,
   and masks `author:\nJohn`.
6. **Cost.** At most about 12 times the old time on the most adversarial family, linear, 161 ms at 8 MiB.
7. **PR 199 arms D1 to D4.** The four named reproducers now mask (Design 6 row 28); the arms are not re-derived:
   the reviewer's minimisation decides whether any shape is left.
8. **The `Authorization` regex pass** (`authorization\s*[:=]\s*.+`) runs before the scan and can eat a key at
   the end of its line: `Authorization: x; password:\n  Q9` loses `password:` and leaves `Q9`. Pre-existing and
   outside this change. Likewise `Cookie:\r\nHost: example.com` masks `Host:` (an empty secret header takes the
   next header's name), unchanged.
9. **Same-line prose over-redacts a little more.** `token: auth: expired` now masks `expired`. It cannot be
   excluded without a line-break condition that would reopen the same-line leak.
10. **A secret key whose value is an array or an object leaves the elements visible** (Amendment 1; found by the
    Stage 6 security reviewer, unrated; identical in the old and the new output). `{"api_keys": ["abc123", "def456"]}`
    becomes `{"api_keys": [redacted]"abc123", "def456"]}`: the value the scan reads for the key is `[`, because an
    unquoted value ends at a quote. It is the shared value rule, kin to items 1 and 2. Not fixed here; named as a
    next-spec item (bracketed values).

### 11. Rebase hazards (what I checked)

`git worktree list` showed 53 worktrees. `git log origin/main -- crates/aitm-core/src/redact.rs`: last commit
`5f89b2fc` (PR 199); `main` moved from `f2b0dae6` to `c3a4fd37` and `git diff f2b0dae6 origin/main` is empty on
`redact.rs`, `reproduce.rs`, `discover.rs` and `crates/aitm-poc`. Branches whose `redact.rs` differs from `main`:
`claude/competent-cori-43f38a` (PR 171, merged) and `claude/scanner-vocab-7d36bb` (PR 199, merged; empty diff).
`claude/durable-audit-462ca8` (live) adds `crates/aitm-core/src/redact_strict.rs`, which runs `scrub_text` as its
first pass and iterates to a fixed point; its `redact_strict` suite (28 tests), its `redact_strict` lib tests (11)
and its `audit` lib tests (46) pass over the new `redact.rs` in a scratch copy. Its docs say "`scrub_text` itself,
unchanged": still true of the API, no longer of the outputs on nested shapes; it will need a doc touch when it
rebases. The brief's worktree (`heuristic-panini-828774`) was removed from `git worktree list` while this spec was
written; the spec file sits in the plain directory at that path. A sibling session appending tests to
`reproduce.rs`'s `mod tests` is a plain append conflict; keep one writer per file and re-gate after rebasing.

### 12. Files by task (Stage 3 builds disjoint tasks from this)

| Files | Content |
|---|---|
| `crates/aitm-core/src/redact.rs` | R1 to R4, the third `Reading` value, `skip_pair_blanks` deleted, the doc list of Design 7 items 1 to 7, the core tests of AC1 to AC12. One writer. |
| `crates/aitm-plugin-scanner/src/reproduce.rs` | the scanner tests of AC15 to AC20 and the doc and comment edits of Design 7 items 8 and 9. Independent file; its new tests go green after the core change. |
| `crates/aitm-poc/tests/builder.rs` | one test (AC21), appended. Independent file. |

Not touched: every other file, `Cargo.toml`, `Cargo.lock`, `lib.rs`, `crawl.rs`, `commands.rs`, `discover.rs`, the
2026-10-31 spec and plan.

## Acceptance criteria

`[red]` = fails on `f2b0dae6` (measured on a scratch copy with the tests appended) and passes after. `[guard]`
= passes on `f2b0dae6` (written and run there first) and passes after, with its rows unedited. Test names are
exact. Rows are `(input) -> expected output` as the tables above; `\n`, `\r`, `\x0c`, `\t` are the characters.
`assert!` on `==`, not `assert_eq!`, where the text is large.

Core, `crates/aitm-core/src/redact.rs` `mod tests` (HEAD: 54 `redact::tests`; after: 63):

1. AC1 `[red]` `scrub_text_masks_a_credential_nested_under_a_secret_parent`: for each parent in `auth`,
   `credentials`, `secret`, `token`, `session`, `cookie`, `password`, `sid`, `jwt`, `csrf`, `api_key` and each layout
   in `"\n  "`, `"\r\n  "`, `"\n\t"`, `"\r  "`, `"\u{c}  "`, `"\n    "`: `{parent}:{layout}password: hunter2` gives
   `{parent}:{layout}[redacted] [redacted]` (66 rows); and `token:\r\n\tsid: S1` gives
   `token:\r\n\t[redacted] [redacted]`, `session:\n  csrf: C9` gives `session:\n  [redacted] [redacted]`.
2. AC2 `[red]` `scrub_text_masks_a_nested_credential_in_every_separator_and_quote_form`: `"auth":\n  "password": "x"`
   gives `"auth":\n  "[redacted]": "[redacted]"`; `'auth':\n  'password' : 'x y'` gives
   `'auth':\n  '[redacted]' : '[redacted]'`; `auth: password: hunter2` gives `auth: [redacted] [redacted]`;
   `auth:\n  password :   hunter2` gives `auth:\n  [redacted] :   [redacted]`; `auth:\n  password:\n    hunter2` gives
   `auth:\n  [redacted]\n    [redacted]`; `auth:\n  password: 'hunter2'` gives `auth:\n  [redacted] '[redacted]'`;
   `auth:\n\n\n\n\n  password: x` gives `auth:\n\n\n\n\n  [redacted] [redacted]`.
3. AC3 `[red]` `scrub_text_reads_every_pair_of_a_chain_of_secret_keys`: rows 11 to 16 of Design 6 (new outputs).
4. AC4 `[guard]` `scrub_text_keeps_the_output_it_had_when_no_secret_pair_starts_inside_a_masked_value`: 14 rows:
   `auth:\n  password=hunter2` -> `auth:\n  [redacted]`; `auth=\n  password=hunter2` -> `auth=\n  [redacted]`;
   `auth:\n  creds:\n    password: hunter2` -> `auth:\n  [redacted]\n    password: [redacted]`; `auth:\n  user: bob` ->
   `auth:\n  [redacted] bob`; `token:\n  author: bob` -> `token:\n  [redacted] bob`; `auth:\n  authority: example.com`
   -> `auth:\n  [redacted] example.com`; `auth:\n  user: bob\n  password: hunter2` ->
   `auth:\n  [redacted] bob\n  password: [redacted]`; `auth:\n  # note\n  password: hunter2` ->
   `auth:\n  [redacted] note\n  password: [redacted]`; `credentials:\n  - password: hunter2` ->
   `credentials:\n  [redacted] password: [redacted]`; `auth: x\n  password: hunter2` ->
   `auth: [redacted]\n  password: [redacted]`; `auth:\n` -> `auth:\n`; `auth:\n  sessionKey: abc123` ->
   `auth:\n  [redacted] abc123`; `Authorization:\n  password: hunter2` -> `Authorization:\n  [redacted]`;
   `password:\n  hunter2` -> `password:\n  [redacted]`. The `token:\n  author: bob` and `authority` rows kill the
   mutant that reads the wide key test inside a masked value in `scrub_text` (M7).
5. AC5 `[guard]` `scrub_text_masks_a_value_that_looks_like_a_pair_under_a_secret_parent`: the 15 rows of Design 5
   hazard 1, each -> `<parent>:<layout>[redacted]` (`token:\n  AApwdBB==\n  other: 1` -> `token:\n  [redacted]\n  other: 1`).
6. AC6 `[guard]` `scrub_text_masks_a_padded_base64_credential_on_the_next_line`: 5,000 credentials from a seeded
   in-test xorshift (no dependency; 4 to 43 base64 characters, then `=` or `==`) under `token`, `password`,
   `secret`, `session`, `auth`, `api_key` on `{parent}:\n  {credential}`: each -> `{parent}:\n  [redacted]`.
   AC6b `[red]` `scrub_text_masks_a_padded_base64_credential_under_a_nested_pair`: the same credentials as
   `auth:\n  password:\n    {credential}` -> `auth:\n  [redacted]\n    [redacted]`.
7. AC7 `[guard]` `scrub_text_does_not_read_the_closing_quote_of_a_masked_value_as_an_opener`: `token="sid: " tail="x"`,
   `token="sid:" tail="x"`, `token="a sid:" tail="x"` -> `token="[redacted]" tail="x"`; `x=1&token='auth='&y="z"` ->
   `x=1&token='[redacted]'&y="z"`; `x=1&token="sid:\t"\ny=2` -> `x=1&token="[redacted]"\ny=2`.
8. AC8 `[red]` `scrub_text_stays_linear_on_nested_pair_shapes`: `"auth:\n  password: x\n".repeat(50_000)` ->
   `"auth:\n  [redacted] [redacted]\n".repeat(50_000)`; `"sid:\n".repeat(100_000)` ->
   `"sid:\n".to_string() + &"[redacted]\n".repeat(99_999)`; `"password:\n password:\n".repeat(50_000)` ->
   `"password:\n [redacted]\n".to_string() + &"[redacted]\n [redacted]\n".repeat(49_999)`;
   `format!("auth:{}  password: x", "\n".repeat(1 << 19))` -> `format!("auth:{}  [redacted] [redacted]", ...)`;
   `format!("token=\"{}\"", "a=".repeat(1 << 20))` -> `token="[redacted]"`; `format!("{}x\"", "sid:\"".repeat(200_000))` ->
   `sid:"[redacted]"`; `"token=\"sid: \" tail=\"x\" ".repeat(100_000)` -> `"token=\"[redacted]\" tail=\"x\" ".repeat(100_000)`.
   The test finishing is the check (a quadratic scan hangs on the 1 MiB shapes); the builder may shrink a repeat
   count if a debug-build run is slow, keeping every family at 1 MiB or more.
9. AC9 `[red]` `scrub_text_wide_masks_a_next_line_credential_under_a_wide_only_parent` (`scrub_text_wide`):
   `userSession:\n  S3SS10N9` -> `userSession:\n  [redacted]`; `sidebar:\nS3SS10N9` -> `sidebar:\n[redacted]`;
   `author:\nJohn` -> `author:\n[redacted]`; `sessionKey:\n  abc123` -> `sessionKey:\n  [redacted]`;
   `userSession:\r\n\tS3SS10N9` -> `userSession:\r\n\t[redacted]`; `sidebar=\u{c}v` -> `sidebar=\u{c}[redacted]`;
   `sidebar\n:v` -> `sidebar\n:[redacted]`.
10. AC10 `[red]` `scrub_text_wide_masks_a_wide_only_pair_nested_under_a_standard_parent` (`scrub_text_wide`):
    `auth:\n  sessionKey: abc123` -> `auth:\n  [redacted] [redacted]`; `auth: sessionKey: abc123` ->
    `auth: [redacted] [redacted]`; `jwt:\n\tsidebar :  "Q"` -> `jwt:\n\t[redacted] :  "[redacted]"`;
    `Credentials:\n\tjwt:\n\tsidebar :  "Q"` -> `Credentials:\n\t[redacted]\n\t[redacted] :  "[redacted]"`.
11. AC11 `[red]` the existing wide tests that pin the boundary, edited by exactly these rows and no others:
    - `scrub_text_wide_masks_a_standard_pair_nested_under_a_wide_only_key`: rows 1 to 4 of
      `NESTED_UNDER_A_WIDE_ONLY_KEY` (the `\n` ones) get the new outputs of Design 6 row 25; rows 5 to 9 keep theirs.
    - `scrub_text_wide_keeps_a_line_break_as_a_boundary`, **renamed**
      `scrub_text_wide_reads_a_pair_across_a_line_break` (body and const renamed alike): rows 1 to 7 of
      `LINE_BREAK_IS_A_BOUNDARY` get the new outputs of Design 6 rows 18 to 20, 26, 27; row 8 (`sid:\nabc` ->
      `sid:\n[redacted]`) keeps its output.
    - `scrub_text_wide_reads_a_pair_on_one_line_beside_non_ascii_spaces`, **renamed**
      `scrub_text_wide_reads_a_pair_across_a_line_break_beside_non_ascii_spaces`: 6 of its 10 rows change:
      `sidebar:\u{a0}\nJohn` -> `sidebar:\u{a0}\n[redacted]`; `author\u{a0}\n:John` -> `author\u{a0}\n:[redacted]`;
      `author\u{c}=John` -> `author\u{c}=[redacted]`; `sidebar:\n\u{a0}sessionKey: abc123` ->
      `sidebar:\n\u{a0}[redacted] [redacted]`; `authentication:\u{2009}\r\n\u{2009}jwt:\u{a0}J1` ->
      `authentication:\u{2009}\r\n\u{2009}[redacted]\u{a0}[redacted]`; `authentication:\r\n  password: hunter2` ->
      `authentication:\r\n  [redacted] [redacted]`. The other four rows and the JSON-escaped-newline check keep
      theirs.
    - `scrub_text_wide_stays_linear_on_line_break_shapes`: 5 of its 6 assertions change: `"author:\n".repeat(1 << 17)`
      -> `"author:\n".to_string() + &"[redacted]\n".repeat((1 << 17) - 1)`; the two `authentication:\n  ...` families
      -> `"authentication:\n  [redacted] [redacted]\n".repeat(50_000)`; `"sid:\n".repeat(100_000)` ->
      `"sid:\n".to_string() + &"[redacted]\n".repeat(99_999)`; `sidebar{breaks}=v` -> `sidebar{breaks}=[redacted]`
      (half a million line breaks); the `sid{breaks}=v` assertion is unchanged.
    - `skip_pair_blanks_leaves_only_the_three_line_breaks_to_the_wide_reading` is **deleted** with
      `skip_pair_blanks`.
12. AC12 `[guard]` every other existing `redact` test passes unedited, in particular
    `scrub_text_is_unchanged_on_the_recorded_corpus` (no row of `RECORDED_SCRUB_TEXT` changes; proved on a
    scratch copy of the chosen rule, 65 tests passing), `scrub_text_masks_a_value_on_the_next_line`,
    `scrub_text_survives_hostile_inputs`, every `scrub_text_stays_linear_*`,
    `scrub_text_wide_survives_hostile_inputs_and_stays_linear`, `scrub_text_wide_agrees_with_scrub_text_when_nothing_wide_applies`,
    `scrub_text_wide_masks_everything_scrub_text_masks` and its `_on_every_prefix` twin, the host:port tests.
    `cargo test -p aitm-core --lib redact` runs 65 tests (63 `redact::tests` and 2 `tunnel` tests that match the filter).
13. AC13 `[guard]` mutants killed (Tester, in a scratch copy of the head, each restored): M1 no R2 and no R2' (at least
    16 tests red, a slice panic), M2 `masked_to = value_end` for a quoted value (only AC7 red), M3 the first scan
    of the wide scrub has no wide test inside a masked value (only AC10 red), M4 resume at `value_end` (nine red:
    AC1, AC2, AC3, AC6b, AC8, AC10 and three tests of AC11), M5 the wide scan stops at a line break again (five red: AC9
    and four of AC11), M6 no host:port exemption (four red), M7 the wide key test inside a masked value used by
    `scrub_text` (only AC4 red). M8, R2' removed, **survives by design** (it changes no output; the timing of
    Design 9 I4 is its check): recorded, not a finding.
14. AC14 (review and grep) `grep -n skip_pair_blanks crates/aitm-core/src/redact.rs` prints nothing;
    `sed -n '/^fn mask_secret_pairs/,/^}/p' crates/aitm-core/src/redact.rs | grep -c reading` prints `3` (the
    signature, the key test, the host:port exemption; the word appears in no comment inside the body); `git diff` adds no `unsafe`, no `pub`, and changes no
    `Cargo.toml` or `Cargo.lock`; the doc list of Design 7 items 1 to 7 is done (reading the diff).

Scanner, `crates/aitm-plugin-scanner/src/reproduce.rs` `mod tests` (HEAD: 197 lib tests; after: 201):

15. AC15 `[red]` `scrub_embedded_nested_pair_changes_are_exactly_these`: ten rows, each the new output with the old
    one in a comment: `authentication:\n  password: hunter2` -> `authentication:\n  [redacted] [redacted]`;
    `author:\n  token: abc123` -> `author:\n  [redacted] [redacted]`; `sessions:\n  jwt: J1` ->
    `sessions:\n  [redacted] [redacted]`; `sidebar:\n    api_key: K1` -> `sidebar:\n    [redacted] [redacted]`;
    `authentication:\n  sessionKey: abc123` -> `authentication:\n  [redacted] [redacted]`; `side:\nSid2':C` ->
    `side:\n[redacted]':[redacted]`; `bsid:\rSIDE:'C` -> `bsid:\r[redacted]'[redacted]`; `author:\nJohn` ->
    `author:\n[redacted]`; `sidebar\n:v` -> `sidebar\n:[redacted]`; `sidebar=\u{c}v` -> `sidebar=\u{c}[redacted]`.
    The same ten rows are **removed** from `RECORDED_SCRUB_EMBEDDED` (they were recorded at `15009b2`; they are no
    longer its output), which keeps its other rows, including the five F1 rows that do not change
    (`authentication: {password: hunter2}`, `sidebar=sid="C1"`, `author=password='C2'`, `inside=x?sid\t=\tC9`,
    `Auths:Pwd: C`), and its `>= 80` row assertion.
16. AC16 `[red]` `scrub_embedded_masks_a_nested_credential_under_a_secret_or_a_wide_only_parent`:
    `auth:\n  password: hunter2` -> `auth:\n  [redacted] [redacted]`; `credentials:\r\n\tsecret: S1` ->
    `credentials:\r\n\t[redacted] [redacted]`; `auth:\n  sessionKey: abc123` -> `auth:\n  [redacted] [redacted]`;
    `userSession:\n  S3SS10N9` -> `userSession:\n  [redacted]`; `sidebar:\nS3SS10N9` -> `sidebar:\n[redacted]`;
    `see http://u:pw@host/x\nauth:\n  password: hunter2` -> `see http://host/x\nauth:\n  [redacted] [redacted]`.
17. AC17 `[guard]` `scrub_embedded_keeps_the_output_it_had_for_a_value_that_looks_like_a_pair`:
    `token:\n  YWJj=`, `password:\n  s3cr:et`, `token:\n  AApwdBB=`, `password:\n  sid:abc`, `password:\n  user:pass`,
    `token:\n  dXNlcjpwYXNz` -> `<parent>:\n  [redacted]`; `auth:\n  user: bob` -> `auth:\n  [redacted] bob`;
    `auth:\n  creds:\n    password: hunter2` -> `auth:\n  [redacted]\n    password: [redacted]`.
18. AC18 `[red]` `build_poc_masks_a_credential_nested_under_a_secret_parent`, through the real `build_poc` with
    `flow_with_query` and `flow_with`: url `/go?q=hello&note=auth%3A%0A%20%20password%3A%20URLPW1` -> step url
    `{{target}}/go?q=%3Caitm-canary-0001%3E&note=auth%3A%0A++%5Bredacted%5D+%5Bredacted%5D`; JSON body
    `{"note":"auth:\n  password: JSONPW2","list":["credentials:\r\n\tsecret: JSONSEC9"]}` -> the parsed JSON
    `{"note": "auth:\n  [redacted] [redacted]", "list": ["credentials:\r\n\t[redacted] [redacted]"]}`; form body
    `note=auth%3A%0A++password%3A+FORMPW3&page=2` -> `note=auth%3A%0A++%5Bredacted%5D+%5Bredacted%5D&page=2`; a body
    with no content type `auth:\n  password: RAWPW4` -> `auth:\n  [redacted] [redacted]`. None of the five canaries is in
    the serialized PoC.
19. AC19 `[red]` the existing `build_poc_masks_a_nested_standard_pair_under_a_wide_only_key`, three expectations edited
    and no other: the JSON `note` -> `authentication:\n  [redacted] [redacted]` and `list` ->
    `["author:\n  [redacted] [redacted]"]`; the form `note` -> `authentication:\n  [redacted] [redacted]`; the untyped
    body -> `authentication:\n  [redacted] [redacted]`. The `memo` leaf and the `X-Note` header keep theirs.
20. AC20 `[guard]` the other scanner tests pass unedited, `crawl.rs` and `commands.rs` have an empty diff, and
    `scrub_embedded_deliberate_changes_are_exactly_these` and the name-decision pins of the 2026-10-31 spec
    (`scrub_embedded_and_is_secret_name_agree_on_every_key`) pass: 201 tests after.

aitm-poc, `crates/aitm-poc/tests/builder.rs` (HEAD: 23 tests; after: 24):

21. AC21 `[red]` `build_masks_a_credential_nested_under_a_secret_parent_on_every_surface` through the real
    `StdPocBuilder` with `flow_with` and `basic_spec`: a path `/go?q=hello&note=auth:\n  password: URLPW1` -> step
    url `{{target}}/go?{{param}}=hello&note=auth:\n  [redacted] [redacted]`; the JSON body of AC18 -> the same parsed
    JSON; the body `note=auth:\n  password: FORMPW3&page=2` -> `note=auth:\n  [redacted] [redacted]&page=2`; the body
    `auth:\n  password: RAWPW4` -> `auth:\n  [redacted] [redacted]`.

Everything else:

22. AC22 `[guard]` the suites of `aitm-findings`, `aitm-scan-checks-http`, `aitm-scan-ws`, `aitm-plugins`, `aitm-poc`
    and `aitm-core` pass unedited; `cargo test -p aitm-mcp` passes in the Terminal panel.
23. AC23 the Stage 6 security report records the differential of Design 9 on the head under review: tools and
    scratch layout, seeds, counts per alphabet (the minimums above), I1 (raw and ownership-aware), I2, I3 with the
    TRIG check, I4 with the timings at 1, 2, 4 and 8 MiB, I5, I6, the positive controls firing, the minimal
    reproducers grouped by family (every group within Residual risks 3), and the cleanup of the scratch trees.
24. AC24 `[guard]` the full Rust gate is green. Docs: `grep -rnE "reads a pair on one line|one line by the wide|line break as a boundary|three declared|skip_pair_blanks" crates/aitm-core/src/redact.rs crates/aitm-plugin-scanner/src`
    prints nothing.

## Left to the builder

- The name of the third `Reading` value (`FirstOfWide` above), and whether the first scan of the wide scrub is
  `mask_secret_pairs(&regex_passes(text), ..)` with a private shared helper or an equivalent.
- Where R2' sits and how it is written, provided it changes no output: if the `token="a=a=a=..."` family exceeds 20
  times the old time at 8 MiB without it, keep it.
- The repeat counts of the hostile tests (AC8), provided each family stays at 1 MiB or more and the debug-build run
  finishes; the in-test generator of AC6 (any seeded generator without a dependency).
- Row order, extra rows (never fewer), comment wording, and the task split within Design 12's disjoint files
  (core tests first on `f2b0dae6` for the `[guard]` ones, then the rule, then the `[red]` ones).

## Open questions

Only Matt can answer these; each has a default that stands unless he reverses it.

1. **Close the next-line leak under wide-only keys (drop the wide line-break boundary)?** Default yes: it is the
   brief's "related shape", it puts a credential into a shareable artifact, and with R1 crossing a line break is
   safe (measured I1 0 on the nested alphabet). The cost: 17 pinned core rows, 5 assertions of one hostile test and
   10 scanner rows plus 3 scanner expectations change (AC11, AC15, AC19, all named), a nested pair under a
   wide-only parent reads `[redacted] [redacted]` in a PoC text, and `author:\nJohn` loses `John` in a PoC. The
   alternative keeps the boundary: one assertion changes, 11,487 of 300,000 nested inputs keep a wide-only
   next-line leak.
2. **Accept label churn in chains of secret keys?** Default yes (`sid:\nsid:\nsid:\n` masks the second `sid:`;
   `auth:\n  secret:\n    password: hunter2` masks `password:`; both read as the same rule applied one level
   deeper). The alternative (no label churn, every existing standard row unchanged) was built and rejected because
   a credential that itself reads as a pair (padded base64 holding `pwd`, `Q...pwd...Z==`) is then exposed where
   the old output masked it (Design 4, the fifth variant). Matt may prefer the churn-free variant and the
   residual.
3. **Should a secret parent mask the values of its non-secret children** (`auth:\n  user: bob` keeping `bob`)?
   Default no: the vocabulary decides, a whole-subtree rule needs an indentation model (approaches B and E,
   measured worse) and over-redacts prose.
4. **Read Matt's constraint ("the fix may not weaken what `scrub_text` masks today") ownership-aware?** (Added by
   Amendment 1, S-1.) Read literally it fails on well-formed input in one family (G1): a token that no secret key
   governs, after a quoted value that ends in a key and a separator, was masked by a misparse of a closing quote and
   now stays visible, while the nested secret value the old output left in the clear is masked. Default yes, the
   ownership-aware reading: no value governed by a secret key becomes visible. The alternative is to restore the
   misparse, which is the behaviour guard R2 and AC7 forbid, and which would be a new fix task and a new
   differential, not an amendment.

## Summary

`scrub_text` takes the first token after a secret key's separator as its value, so when that token is itself
`password:` the nested credential after it stays in the clear (`auth:\n  password: hunter2`), and the wide
reading, which stops at line breaks and runs its standard scan first, leaks the next-line and wide-child shapes.
The rule chosen is to keep masking that token exactly as today and resume the scan at the start of the masked
value, so a secret pair that begins inside it is read too, with an exact guard (a nested pair whose value would
start inside the masked text or at its closing quote is skipped) and a cheaper early guard; the wide scrub's first
scan judges a key inside a masked value by the wide vocabulary and the wide scan crosses line breaks. Measured on
real runs: 0 old-masked canaries exposed and 0 secret pairs left on 300,000 nested inputs per reading (old: 61,992
and 89,302 leaking), the 15 hazard rows and 600,000 random padded base64 credentials identical to the old output,
no row of `RECORDED_SCRUB_TEXT` changed, linear time at 12 times the old cost at worst. Approach A (parent keeps an
empty value) exposes what the old output masked on 14 of 15 hazard rows; indentation and whole-line rules expose
or leak thousands per 200,000. Three calls are Matt's: closing the wide next-line leak at the price of 17 named core rows, 10 scanner rows and
a handful of assertions, accepting label churn in chains, and leaving non-secret children readable. Amendment 1
(post-panel) adds a fourth: reading "may not weaken what `scrub_text` masks" as "no value governed by a secret key
becomes visible" (Open question 4), because one well-formed family (G1) exposes a token that no secret key governs
that the old output masked by a misparse; the "0 old-masked canaries exposed" above is a measurement on the Architect's
alphabets, which never reached that family.

## Architect's calls (for Matt to approve or correct)

1. Approach C (resume inside the masked value, skip a nested value that starts inside the masked text), not A, B,
   E, or the revert of PR 171.
2. The old output is never un-masked: the parent's token is masked first, and the nested pair is read inside it
   (so `auth:\n  [redacted] [redacted]`, label included).
3. A non-secret child keeps its value (`auth:\n  user: bob` unchanged); the vocabulary decides.
4. The wide line-break boundary is dropped (Design 3), accepting the named churn (17 pinned core rows, 5
   assertions of one hostile test, 10 scanner rows, 3 scanner expectations) and the over-redaction of
   `author:\nJohn` in a PoC; the named alternative keeps the boundary.
5. `scrub_text_wide` keeps two scans but its first scan judges a key inside a masked value by the wide
   vocabulary; the superset property becomes measured, not by construction.
6. No A-style exception for a nested pair whose next token starts a pair: label churn in chains is accepted over
   exposing a pair-shaped credential.
7. The same-line nested pair (`auth: password: hunter2`) is in scope: it cannot be excluded without a line-break
   condition that reopens it.
8. Ten rows move out of `RECORDED_SCRUB_EMBEDDED` into a new deliberate-changes test rather than being edited in
   place; `RECORDED_SCRUB_TEXT` loses none.
9. The early guard R2' is specified and its mutant survives by design; the timing run is its check.
10. Three tests are renamed or deleted because they name the removed boundary
    (`..._keeps_a_line_break_as_a_boundary`, `..._on_one_line_beside_non_ascii_spaces`,
    `skip_pair_blanks_leaves_only_the_three_line_breaks_to_the_wide_reading`); bodies are otherwise kept.
11. The differential reuses the 2026-10-31 tooling and adds a nested-shape generator with canary ownership; the
    TRIG regex is the oracle of "no change without a nested pair".
12. The Status line stays `draft`; the orchestrator approves.

Added by Amendment 1 (2026-11-01):

13. **S-1: no code change; the invariant is restated ownership-aware** (no value governed by a secret key becomes
    visible on well-formed input). The one fix, restoring the old output on family G1, is the closing-quote misparse
    that guard R2 and AC7 exist to forbid. Flagged for Matt as Open question 4.
14. **G2 and G3 are accepted as Minor residuals** inside Residual risks 3 (interleaved quotes are named, the
    "malformed-quote trigger" now includes them); no test pins any of them.
15. **Design 6 lists classes, not every changed input**; rows 29 and 30 are added, and the one class that goes toward
    less masking (G1) is named in its lead. **No AC25**: the code does not move, the tester's three rows already pin
    row 29, row 30 follows row 21 (AC10, mutant M3), and a pin of G1's visible token would hand the next
    conservative change a red test for no gain.
16. **The docs say "linear" with no number.** Design 7 item 3's "measured bound of Design 9 I4" is superseded: a
    benchmark in a doc comment rots; the bound stays a Stage 6 check.
17. **AC8's 1 MiB floor binds; its repeat counts do not.** Four of its seven families come out under 1 MiB at the
    listed counts. The one AC8 test sizes every family by `mebibyte_copies` and runs both scrubs; the tester's
    duplicate is deleted.
18. **The fix round is comment, doc and test only**, proved mechanically (plan, Fix 1), so the Stage 6 differential
    stands and is not re-run: a narrowing of Fix-task protocol 3 that the orchestrator approves with this amendment.
19. **Q-7's production change and Q-8(b) are accepted** (the orchestrator's dispositions): the `Reading` docs get a
    comment-only sentence; the three `token="sid:"x` rows stay.
20. **Residual risks 10 (array and object values) is named, not fixed**: a next-spec item.
