# T10 PR A — fix round 1 (consolidated panel findings, range f2c9d70b..13580920)

Orchestrator dispositions: **FIX** = fix in this round; **ACCEPT** = accepted as a loopback-only test-target
limitation, recorded in the plan's Review log; **DOCS** = the orchestrator amends the spec/plan text.
Paths are relative to `crates/aitm-testtarget/`. Every FIX item gets a test that fails before and passes after.

## Important

1. **FIX** (security) `src/routes/inject.rs:374-377` `strip_prefix_ci` slices `s[..prefix.len()]` on request-derived text; `GET /ping?host=a;slee%C3%A9` panics on a char boundary. Compare on bytes (`s.as_bytes().get(..n)?.eq_ignore_ascii_case(..)`) and audit every other `&str[..n]` slice in `inject.rs`/`reflect.rs`/`session.rs` for the same hazard. Tests: `;slee\u{e9}` and `;sleép` return 200 in both modes.
2. **FIX** (security) `src/app.rs:673-679` `redirect(location)` puts a request-derived `next` into `Location` and `expect`s the builder; `GET /redirect?next=%0d%0aSet-Cookie:x=y` (V) and `/redirect?next=/%0d%0aX` (P) panic. Validate with `HeaderValue::from_str`; on failure strip CR/LF (keeps the open-redirect seed semantics). Tests for both modes.
3. **FIX** (spec) `/log/conns` stamps an upgraded `/ws` connection closed at the 101: `src/app.rs:152-159`, `src/tls.rs:156` call `close_conn` right after `serve_h1` returns, which hyper does as soon as the upgrade is handed off; `ws::finish` only overwrites later. Add `upgraded: AtomicBool` to `ConnInfo` (`src/log.rs`), set it in `ws::serve_upgrade` when the 101 is produced, make `close_conn` a no-op for an upgraded conn unless called with a `force`/from the ws loop (e.g. `close_conn_upgraded`), and keep `ws::finish` as the only closer. Hermetic test: while `run_frames` is still running the conn's `closed_ms` is `null`; after it ends it is set. Keep last-write-wins or revert it, your call, but the invariant is "no `closed_ms` before the loop ends".
4. **FIX** (quality) accept loops: `src/lib.rs:219-229` and `src/tls.rs:116-127` swallow accept errors and hot-spin; `src/control.rs:43-53` and `src/speakers/driver.rs:449-469` back off 10 ms. One shared `async fn accept_loop<F>(listener, on_conn: F)` (in `app.rs` or a new `listeners.rs`, declared in `lib.rs`) with `match accept { Ok => spawn, Err => sleep(SOCKET_ERROR_BACKOFF) }`; the plain, tls and control binds use it (the driver may keep its select-based loop but must use the same backoff const).
5. **FIX** (quality) `src/ws.rs:279-294` duplicates `html_escape`; delete it and import `crate::app::html_escape`.
6. **FIX** (quality) `src/speakers/driver.rs:435-444`: a speaker that cannot rebind after the window returns silently. On rebind failure write an observable row (`l4_downtime(name, "-", now_ms, u64::MAX, &[])` is acceptable, or a new `dead` list on the service log with the `io::Error` text; if you add a field, add it to `log.rs` `L4Log` and D2's `/log/l4` shape in your report) and `eprintln!` once. Pass `addr` into `run_tcp` so the unreachable `return` at 430-432 disappears. Unit-test the pure decision if possible; the live path cannot be forced in the sandbox.

## Minor, FIX

7. (security) `src/speakers/dns.rs:107-109,163`: a datagram shorter than 12 bytes gets a 12-byte FORMERR (amplification). Return `Step::ProtocolError(Vec::new())` (log, no reply). Test.
8. (security) `src/routes/reflect.rs:172-190`: cap the multipart boundary at 70 bytes (RFC 2046); longer -> 400. Test.
9. (security) unbounded stores: cap comments at 1 000 (drop oldest) in `src/app.rs`, sessions at 10 000 in `src/routes/session.rs` (refuse or evict oldest; say which). Tests.
10. (security) `src/control.rs:88`: `POST /reset` (and every control route) answers 403 `{"error":"cross-origin"}` when the request carries an `Origin` header (browser CSRF guard; the harness never sends one). Test.
11. (security) `src/log.rs:467`: hash a small `x-*` credential denylist like `authorization` (`x-api-key`, `x-auth-token`, `x-csrf-token`, `x-amz-security-token`; names lowercased) into a `x_credential_sha256` map or simply drop them to `"<redacted>"`; pick the simpler and report it (the orchestrator amends D2). Test.
12. (security) `src/ws.rs:497`: drain the receive buffer once per outer read iteration instead of per frame.
13. (spec) one self-signed certificate per process: mint in `TargetBuilder::start` (or `OnceLock`) and pass to both `tls::bind` calls; `src/tls.rs:43-55`. Test: both listeners present the same DER (socket test in `tests/scan_http.rs` may be extended; or a hermetic test that `server_config(alpn, &identity)` reuses the identity).
14. (spec) `src/ws.rs:413-419`: check `alpn == Some("h2")` **before** the key/version check so a plain h2 `GET /ws` answers 400 `websocket requires HTTP/1.1`. Test.
15. (spec) `src/l4.rs` `try_start`: make it `pub(crate)`, drop the `Option` (it is always enabled); simplify `src/lib.rs:156-160`.
16. (spec) stale `32 0A` MQTT literal in `src/manifest.rs:389` -> `32 09`; reword the comment on `src/speakers/mqtt.rs:340-349` (keep the test; it pins that the short vector is `Incomplete`).
17. (quality) `#[allow(dead_code)]` on test-only items (`log.rs:402,534`, `app.rs:619`, `ws.rs:82`): use `#[cfg(test)]` or delete (`Opcode::as_str` can go).
18. (quality) delete stale plan-breadcrumb comments: `speakers/{tlv,dns,udp_payload,mqtt,smtp,ftp}.rs` module docs ("nothing links it yet"), `app.rs:88-89`.
19. (quality) delete `speakers::classify` (`mod.rs:210-219`) and the twin test in `driver.rs:681-695`; `Classified` serialises the token.
20. (quality) response builders: move `json`, `text_plain`, `with_content_type` from `routes/inject.rs:738-752` into `app.rs` beside `html`/`redirect`/`not_found`; make `html`/`json`/`text_plain` take `impl Into<Bytes>`; use them in `routes/session.rs:203-207` and `control.rs:113-119`.
21. (quality) speaker conventions: every `DEF` becomes `pub const` with a named `new_conn`; one `#[cfg(test)] pub(super) fn msg(consumed, verb, step)` helper in `speakers/mod.rs` used by all speaker tests; document on the `Speaker` trait that on `Trigger`/`Fault` the driver hashes the **whole pending buffer** (change `driver.rs` so `trigger_sha256` and the `in` message hash cover `buf` not `buf[..consumed]` for `Crash`/`Fault`), so a cell can match the hash against what it sent; then remove the waiver in `tests/speakers_live.rs:534-541` and assert the exact TCP trigger hash for the single-write cases (tlv `FF FF`, modbus, resp, the 4098-byte lines).
22. (quality) hot-path allocations: `sha256_hex` via `format!("{:x}", Sha256::digest(bytes))`; a private `with_l4(&self, service, f)` helper in `log.rs` replacing the four repeated lock/entry/push blocks; log from `&buf[..consumed]` before draining in `driver.rs:303-304`.
23. (quality) `src/ws.rs:401-412` `handshake_verdict(mode, info: &RequestInfo, session_valid)` instead of nine positional args; drop the clippy allowance.
24. (quality) `src/tls.rs:44` return `io::Error` directly; derive `/services` ALPN names from the byte list (drop `alpn_names`).
25. (quality) visibility: `mod speakers;` private with `pub use speakers::{L4Services, Proto, RunningService};` in `lib.rs` (update `tests/speakers_live.rs` import); drop the `pub(crate)` on `reflect.rs` helpers with no outside caller; rename `_l4` -> `l4`.
26. (quality) `app.rs`: `form_param` delegates to `query_param` over `from_utf8`; `redact_headers` builds `cookie_names` from `parse_cookies(..).keys()` (move `parse_cookies` to `log.rs` or make it `pub(crate)` in `app.rs`; one cookie parser).
27. (quality) `src/app.rs:231-237`: a body that fails mid-read answers 400 and is logged with status 400 (same as the 413 path).
28. (quality) doc nits: `control.rs:4` "six routes" -> seven; `inject.rs:237-238` `pg_sleep` is PostgreSQL.
29. (quality) tests: pin the two literal hash prefixes `5c5fc99ebd5b1b93` / `b937a6fd6074f365` in `log.rs`'s redaction test; drop the 100 ms wall-clock bound in `inject.rs:874-878` (keep the status assertion); `use crate::seed::SeedMode;` in `reflect.rs`; `session.rs` `touch`/`arm` under one lock guard; give `apply` a distinct `Action::Fault` instead of inferring from `CloseReason::Error`.

## ACCEPT (record only)

- (security) no handshake/header/idle/connection-count limits (`tls.rs:139`, `app.rs:173-192`, `driver.rs:403-411`, `ws.rs:516`): loopback test target driven only by the harness; accepted; a 10 s TLS accept timeout is welcome if trivial, otherwise skip.
- (quality) `Stamped<T>` refactor of `seq`/`ts_ms` stamping; `Role`/`Proto` enums on `ServiceInfo`; `tests/common/mod.rs` shared helpers: accepted as-is (churn > value for test support code).

## DOCS (orchestrator)

- D2: `x-*` credential header handling per item 11; `/log/conns` `closed_ms` semantics for upgrades; `/log/l4` `dead` row if item 6 adds one; D1 "one certificate per process" stays; D3 `/logout-after` counts **authenticated `/account` requests** (the implementation; T2's canary replays the newest authenticated GET, which is `/account`); D1 "`l4.rs` unchanged" -> "`l4.rs` gains a `pub(crate) try_start`"; plan A1 strike "`/items` once".

## Added by the orchestrator from the Terminal gate log

30. **FIX** (Important, orchestrator) `src/main.rs` `emit()`: `println!`/`flush` panic with `failed printing to stdout: Broken pipe` when the parent has stopped reading (seen in the workspace gate: the legacy `tests/serve_bin.rs` tests read one line and drop the reader, then the child prints `ready` and dies). Write the stdout lines with `let _ = writeln!(out, ..)`/`let _ = out.flush()` (ignore `EPIPE`; never panic), and have the serve binary keep serving regardless of stdout state. Test: `tests/serve_bin.rs` legacy `start()` already provokes it; add an assertion that the child is still alive (`child.try_wait() == Ok(None)`) after the first request in `serves_vulnerable_target_over_a_real_port` (that test file is yours for this item only).
