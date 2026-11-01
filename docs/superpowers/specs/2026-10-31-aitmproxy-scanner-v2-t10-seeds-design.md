# Scanner v2 track T10 (seeds + e2e) design

**Status:** Approved (T10 session, on Matt's autonomous-approval mandate, 2026-10-31)
**Parent spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved): Constraints, D3, D7, D8.1-D8.5, D11, D12 row T10, Verification, AC T1-1..T10-3.
**Research inputs:** `docs/research/20-scanner-v2-current-state.md` §3.9, `docs/research/18-protocol-fuzzing.md` §3.5/§3.7, `docs/research/19-ws-and-h2-active-scanning.md` §2.
**Code references** (this worktree at `c8cf56a5`): `crates/aitm-testtarget/src/{lib,main,app,seed,manifest,l4,grader}.rs`, `tests/e2e/aitm_e2e/{config,target,bus,core,ws}.py`, `tests/e2e/run.py`, `crates/aitm-proto-l4/src/{config,types}.rs` (L4 YAML keys), `crates/aitm-plugins/src/agent.rs` (`agent.set`).

This is a **child spec**: it is the contract the lane tracks T2..T6 and the UI tracks consume from T10. It pins the test target's process shape, the control origin API, every seed, every L4 speaker, and the harness surface. Decisions the track owner already made are recorded as **T10 calls**; defaults chosen here are **(Architect's call)**.

## Intent

Every scanner v2 track is accepted only by a real scan against a real seeded target observed independently (parent Verification). Today `aitm-testtarget` plants six HTTP vulns over plain HTTP/1 with no request log, no TLS, no WebSocket, no session and two trivial L4 services. T10 turns it into the proving ground: one binary that serves every class T2..T6 need in Vulnerable (V) and Patched (P) modes over plain, TLS-h2 and TLS-h1 listeners, a `/ws` endpoint, nine L4 speakers with a bounded crash window, and a **control origin** on its own port that exposes the target's own logs; plus the Python harness (`scan.py`, the `scanner:` config emitter, the per-verb ledger) and one e2e cell per parent AC.

## Goals

- One `aitm-testtarget-serve` process, flag-selected, serves plain h1, TLS (ALPN `h2, http/1.1`), TLS-h1-only, `/ws`, the control origin and all L4 services; the library builder does the same in-process.
- Every seed in the table below behaves exactly as stated in V and P; the grader-only manifest lists each; nothing served reads the manifest.
- The control origin answers every question a cell asks: which requests arrived (redacted), on which connection, with which ALPN, which WS handshakes/frames, which L4 messages, and when a speaker was down.
- `tests/e2e/scan/` holds one cell per parent AC (T1..T6, T10), each own-core, each SKIP 77 with a loud reason until its lane is live, and `run.py` prints the per-verb ledger.

## Non-goals

- Any scanner, lane or verb code (T1..T6 own those); any UI cell (T7..T9 own `test_t7/8/9_*`).
- Realistic SQL/LDAP/template engines: each seed is a hand-rolled recogniser of the exact payload family named in its row, nothing more.
- A seeded h2-specific positive (parent D8.2 non-goal), MQTT 5, DNS over TCP, FTP data channel, SMTP `DATA` bodies.
- Changing the root `Cargo.toml`, any other crate, or the integration-shared contract lists (T10 adds no verb).

## Anti-goals

- A seed that is dangerous for real: no file read, no shell, no socket opened by a seed; every "command", "file" and "entity" resolves in-process to a virtual constant.
- A control origin reachable from the target origin or linked from `/` (a crawler must never discover it); a raw `Cookie` or `Authorization` value stored in any log.
- A cell that passes on fixture data, on the proxy's own view only, or by hard-coding a verb count.
- A crash window that stays down (a speaker that does not recover in 5 s) or a trigger in P mode that takes the service down.

## Constraints

- **Rust gate** as parent; `#![forbid(unsafe_code)]` already in force via `[lints] workspace = true`; no `unwrap`/`expect` on anything read from a socket. `cargo test -p aitm-testtarget --lib --offline` is hermetic (sandbox); `crates/aitm-testtarget/tests/*.rs` bind ports (Terminal only).
- **Dependencies (T10 call, plus one Architect's call):** only `crates/aitm-testtarget/Cargo.toml` changes. Added: `hyper` feature `http2`; `rustls 0.23` and `tokio-rustls 0.26` with the same features as `crates/aitm-proto-http/Cargo.toml` (`ring, std, tls12, logging` / `ring, tls12, logging`, default-features off); `rcgen 0.14`; `serde_json 1`; `sha1 0.10`; `base64 0.22`; **`sha2 0.10` (Architect's call: the log fields the brief names are SHA-256; `sha2 0.10.9` is in `Cargo.lock`)**. Not added: `tokio-tungstenite` (a hand-rolled RFC 6455 server codec of ~120 lines is smaller and the harness already carries the mirror client in `ws.py`), `tokio-util`, hyper-util `server` features (ALPN is dispatched by hand to `hyper::server::conn::{http1,http2}`). Enabling hyper `http2` adds the edges `h2`, `futures-channel` to hyper's `Cargo.lock` entry; both packages are already locked, so `cargo metadata --offline` passes.
- **Back-compat:** `aitm-testtarget-serve --mode M --port P` prints `listening http://127.0.0.1:P` as its **first** stdout line (`target.py`, `tests/serve_bin.rs`); `TestTarget::start`/`start_on`, `L4Service`/`L4Config`, `manifest()`, `l4_manifest()`, `grade()` keep their signatures; the index `/` is byte-identical in V and P (`index_links_all_seeded_endpoints`).
- **Harness:** pure stdlib Python 3.11+, own-core model, dedicated free ports, tokens never printed; `tests/e2e/aitm_e2e/{bus,core,target,ws,tls,upstream,proxyutil}.py` are not edited.
- **Cross-track pins** (this spec is the source; the T3/T4/T6 child specs must match): issue `class` tokens are T3's list (`sqli, cmdi, ssti, path-traversal, xxe, crlf, nosqli, ldapi, open-redirect, xss, ssrf, cswsh, ws-input-reflection`; the manifest `class` column below uses them for every new row); the L4 `grammar` names are the speaker table's `grammar` column; T3's `HttpSender` must accept the target's self-signed certificate under `ssl_insecure: true`.

## Design

### D1. Process shape (T10 call)

| Item | Pinned |
|---|---|
| Flags | `--mode vulnerable\|patched` (default vulnerable), `--port N` (plain h1; default 0), `--tls-port N` (TLS, ALPN `[h2, http/1.1]`; **present = enabled**, 0 = ephemeral), `--tls-h1-port N` (TLS, ALPN `[http/1.1]` only), `--control-port N`, `--l4` (all L4 services on ephemeral loopback ports; **requires `--control-port`**, else exit 1 with `--l4 needs --control-port`). Absent flag = listener not started. (Architect's call: presence enables, so the legacy invocation starts nothing new.) |
| Stdout | Exactly, in order, one per started listener, then `ready`: `listening http://127.0.0.1:P`, `tls https://127.0.0.1:P`, `tls_h1 https://127.0.0.1:P`, `control http://127.0.0.1:P`, `ready`. L4 addresses are **not** printed; cells read `GET /services`. |
| Bind | Every listener and service binds `127.0.0.1` only. |
| TLS | One self-signed `rcgen` certificate per process for `localhost` + `127.0.0.1`; rustls `ServerConfig` built with the `ring` provider via `builder_with_provider` (no global install); ALPN list per listener as above. After the handshake the negotiated ALPN selects `hyper::server::conn::http2` (`h2`) or `http1` (`http/1.1` or none) and a `tls_handshake` log entry is written. `/ws` over an h2 connection answers 400 `websocket requires HTTP/1.1`. |
| Library | `TestTarget::builder(mode) -> TargetBuilder` with `.port(u16)`, `.tls(u16)`, `.tls_h1(u16)`, `.control(u16)`, `.l4(bool)`, `async fn start(self) -> std::io::Result<TestTarget>`; `TestTarget` gains `tls_url()`, `tls_h1_url()`, `control_url() -> Option<&str>`, `l4_services() -> &[RunningService]`, `mode()`. `start(mode)` = `builder(mode).start().await.expect(..)`; `start_on(mode, port)` = `builder(mode).port(port).start()`. |
| Shared state | One `AppState` per target (mode, comment store, session store, flaky counter, `Arc<ControlLog>`) shared by the plain, TLS and TLS-h1 listeners, so a login over TLS is valid over plain. |
| Module layout | `app.rs` (router, helpers, index, legacy six, `RequestInfo`, `serve_h1/serve_h2`, P headers), `routes/{inject,reflect,session,misc}.rs` (each `pub(crate) async fn route(&RequestInfo, &Arc<AppState>) -> Option<Resp>`), `ws.rs`, `tls.rs`, `log.rs`, `control.rs`, `speakers/{mod,driver,tlv,dns,udp_payload,resp,memcached,modbus,mqtt,smtp,ftp}.rs`, `l4.rs` (legacy, unchanged). |

### D2. Control origin API (T10 call; shapes are Architect's calls)

Own loopback port, hyper h1, JSON only, never linked from `/`, never in the HTTP scope. Every log is a ring of **50 000** entries; a full ring drops the oldest and counts `dropped`. Every entry carries `seq` (one global `AtomicU64`, monotonic across all logs), `ts_ms` (epoch ms) and `conn_id` (`c-<8 hex>` per accepted TCP connection; a UDP datagram's `conn_id` is `u-<peer port>`).

| Route | Response |
|---|---|
| `GET /services` | `{"mode":"vulnerable","services":[{"name":"http","proto":"tcp","addr":"127.0.0.1:P","role":"http","alpn":["http/1.1"]},{"name":"tls",...,"alpn":["h2","http/1.1"]},{"name":"tls_h1",...,"alpn":["http/1.1"]},{"name":"control","proto":"tcp","addr":"...","role":"control"},{"name":"l4-tlv-crash","proto":"tcp","addr":"127.0.0.1:P","role":"l4","grammar":"tlv"},...]}`; roles `http\|control\|l4`; `--l4` also lists the legacy `l4-udp-echo`/`l4-tcp-service` with `"grammar":null`. |
| `GET /log/http` | `{"entries":[E...],"dropped":0}`. `E` is `{"kind":"request","seq","ts_ms","conn_id","listener":"plain\|tls\|tls_h1","version":"h1\|h2","conn_req_index":1,"method","path","query","headers":{...},"cookie_names":["session"],"cookie_sha256":"<16 hex>\|null","auth_sha256":"<16 hex>\|null","body_len":0,"body_sha256":"<64 hex>","status":200}` or `{"kind":"tls_handshake","seq","ts_ms","conn_id","listener","alpn":"h2\|http/1.1\|none"}`. `headers` keeps verbatim only `host, origin, referer, user-agent, content-type, content-length, accept, connection, upgrade, sec-websocket-key, sec-websocket-version, sec-websocket-protocol` and any `x-*`; `cookie`/`authorization` are never stored raw (`cookie_names` sorted; the two hashes are the first 16 hex of SHA-256 over the raw header value). `conn_req_index` is the per-connection 1-based counter (AC T3-3). |
| `GET /log/ws` | `{"entries":[...],"dropped":0}` with `{"kind":"handshake","seq","ts_ms","conn_id","listener","path","origin":"...\|null","sec_websocket_key","cookie_names":[...],"session_valid":bool,"accepted":bool,"status":101\|403}` and `{"kind":"frame","seq","ts_ms","conn_id","dir":"in\|out","opcode":"text\|binary\|ping\|pong\|close","len","sha256":"<64 hex>"}`. |
| `GET /log/l4[?service=NAME]` | `{"services":{"l4-tlv-crash":{"accepts":[{"seq","ts_ms","conn_id","peer"}],"messages":[{"seq","ts_ms","conn_id","dir":"in\|out","len","sha256","verb":"PING\|fc3\|CONNECT\|…\|null","classified":"ok\|protocol_error\|denylisted\|trigger"}],"closes":[{"seq","ts_ms","conn_id","reason":"eof\|quit\|trigger\|oversize\|error","bytes_in","bytes_out"}],"downtime":[{"seq","service","conn_id","down_at_ms","up_at_ms","trigger_sha256"}]},...},"dropped":0}`. UDP services log a `messages` entry per datagram and no `accepts`. `verb` is the parsed command name, Modbus `fc<n>`, MQTT packet type name, DNS `A`/`qtype<n>`, TLV `frame`, or `null` when unparsed (T6: the denylist proof reads `verb` and `classified`). |
| `GET /log/conns` | `{"entries":[{"conn_id","listener","alpn":"h2\|http/1.1\|null","peer","opened_ms","closed_ms":null\|n,"requests":n}]}` for the HTTP listeners (the T3-3 "<= 1 connection per check, <= 8 streams" observer). |
| `POST /reset` | Clears every log and `dropped`; sessions, comments and the flaky counter are kept. `{"reset":true,"seq":<last seq issued before the reset>}`. |
| `GET /mode` | `{"mode":"vulnerable\|patched"}`. |
| anything else | 404 `{"error":"not found"}`; `GET /manifest*` and `GET /<seed id>` are 404 on both origins. |

### D3. HTTP seeds (T10 call; literals are Architect's calls)

All routes are linked from `/` (anchor, form, inline `<script>` fetch, or click-only `onclick` span, column *disc.*). V/P are selected by `SeedMode`; markers live in `seed.rs`; rows in `manifest.rs`. "esc" = HTML-escaped. Class tokens are T3's (the track that emits them; reply of 2026-10-31): every SQLi technique is `sqli`, every reflection kind is `xss`, hyphenated otherwise; the legacy six rows keep their M4 classes because `grader.rs` matches on them.

| id | class | route / kind | V | P | trigger -> observable signal | disc. |
|---|---|---|---|---|---|---|
| `reflected-xss-search-q` | `reflected-xss` | `GET /search?q=` query | raw | esc | existing; `REFLECTED_XSS_MARKER` | a+form |
| `stored-xss-comments` | `stored-xss` | `POST /comments` body_param, `GET /comments` | raw | esc | existing | a+form |
| `ssrf-fetch-preview` | `ssrf` | `GET /fetch?url=` query | in-process metadata | 403 | existing | a |
| `idor-account` | `idor` | `GET /account/{id}` path_segment(numeric) | any id | owner only | existing | a |
| `auth-bypass-admin-role` | `auth-bypass` | `GET /admin` header `X-Role` | trusts header | 403 | existing | a |
| `open-redirect-next` | `open-redirect` | `GET /redirect?next=` query | any `Location` | same-origin only | existing | a |
| `sqli-error-products-id` | `sqli` | `GET /products?id=` query | id containing `'` or `"` -> 500 body `<pre>SQL syntax error near '<id raw>'</pre>`; else 200 `<h1>Product <id esc></h1>` | non-integer id -> 400 `invalid id` | `id=1'` -> `SQL syntax error near` | a |
| `sqli-boolean-items-id` | `sqli` | `GET /items?id=` query | parses `<n>[ AND\|OR <x>=<y>]` (quotes around x/y stripped, trailing `--`/`#`/`'` ignored, case-insensitive): base/AND-true -> item n (`<p>items: 1</p>`), AND-false -> `<p>items: 0</p>`, OR-true -> all five (`<p>items: 5</p>`); anything else -> `items: 0` | integer only, else 400 | `1 AND 1=1` vs `1 AND 1=2` differ; `1 OR 1=1` -> 5 | a |
| `sqli-time-items` | `sqli` | `GET /items?id=` query (same route) | `SLEEP(n)`, `pg_sleep(n)`, `WAITFOR DELAY '0:0:n'` anywhere (case-insensitive) -> sleep `min(n,5)` s then the boolean seed's answer | never sleeps | elapsed >= n s | a |
| `cmdi-ping-host` | `cmdi` | `GET /ping?host=` query | base `<pre>PING <host esc>: 56 data bytes</pre>`; a `;`, `\|`, `&&`, `` ` `` or `$(` introduces a command: `id` appends `uid=0(root) gid=0(root)`; `sleep n` sleeps `min(n,5)` s; other -> `sh: <cmd esc>: command not found` | host must match `^[A-Za-z0-9.-]{1,253}$` else 400 | `;id` -> `CMDI_MARKER`; `;sleep 3` -> >= 3 s | a |
| `ssti-greet-name` | `ssti` | `GET /greet?name=` query | `{{a*b}}` / `${a*b}` (integers) -> product; else raw | esc, never evaluated | `{{7*7}}` -> `<h1>Hello 49</h1>` | a |
| `traversal-static-file` | `path-traversal` | `GET /static?file=` query | decoded value containing `../` (also `..%2f`, `....//`) and ending `etc/passwd` -> `text/plain` `TRAVERSAL_MARKER` (`root:x:0:0:root:/root:/bin/bash`); allowlist `style.css\|app.js\|readme.txt` -> stub content; else 404 | any `..` or `/` -> 400; allowlist only | `../../etc/passwd` -> marker | a |
| `xxe-order-name` | `xxe` | `POST /xml` body `text/xml` xml_value `<name>` | `<!ENTITY e SYSTEM "file:///etc/passwd">` referenced as `&e;` inside `<name>` expands to `TRAVERSAL_MARKER` (only that URI; other SYSTEM URIs -> empty); reply `<p>Order for <name raw></p>` | any `<!DOCTYPE` -> 400 `DTD not allowed`; name esc | marker in body | script |
| `crlf-lang-set` | `crlf` | `GET /lang?set=` query | value split on CRLF; first part -> `Set-Cookie: lang=<v>`; each following `Name: value` line becomes its own response header (token-char names only); body `<p>language set</p>` | CR and LF stripped, one `Set-Cookie` | `en%0d%0aX-Injected:%201` -> header `x-injected: 1` present | a |
| `nosqli-json-login` | `nosqli` | `POST /api/login` JSON `{username,password}` json_value | password a JSON object (e.g. `{"$ne":""}`) -> 200 `{"ok":true,"marker":"NOSQLI-LOGIN-MARKER-4b1d"}`; string == `wonderland` -> `{"ok":true,"user":"alice"}`; else 401 `{"ok":false}` | non-string -> 400 `{"error":"password must be a string"}` | marker | script |
| `ldapi-ldap-user` | `ldapi` | `GET /ldap?user=` query | filter `(uid=<user>)`: `*` -> `alice, bob, carol` + `LDAPI_ALL_USERS_MARKER`; `)(` or unbalanced -> 500 `Bad search filter`; known user -> `uid=<u>`; else `no entries` | RFC 4515 escaping of `* ( ) \ NUL` -> literal lookup | marker or `Bad search filter` | a |
| `header-reflection-whoami` | `xss` | `GET /whoami` header `User-Agent`, `X-Forwarded-For` | `<p>agent: <ua raw></p><p>from: <xff raw></p>` | esc | kind `header` (AC T2-3) | a |
| `cookie-reflection-prefs` | `xss` | `GET /prefs` cookie `theme` | `<body class="<theme raw>">`; no cookie -> `Set-Cookie: theme=light; Path=/` | esc | kind `cookie` (AC T2-3) | a |
| `nested-json-reflection-profile` | `xss` | `POST /api/profile` JSON json_value `profile.address.city` | `text/html` `<div class="city"><city raw></div>` | esc | kind `json_value` path `profile.address.city` (AC T2-2) | script |
| `multipart-reflection-upload` | `xss` | `POST /upload` multipart `file` (filename) + `note` | `<p>uploaded <filename raw> (<n> bytes): <note raw></p>` | esc | `multipart_value`, `multipart_filename` | form |
| `path-segment-docs-slug` | `xss` | `GET /docs/{slug}` path_segment (non-numeric) | `<h1>Doc: <slug raw></h1>` | esc | `path_segment` | a (`/docs/intro`) |
| `path-filename-files` | `xss` | `GET /files/{name}.txt` path_filename | `<p>file <name raw>.txt</p>` | esc | `path_filename` | click-only (`/files/readme.txt`) |
| `auth-only-account-tab` | `xss` | `GET /account?tab=` (exact path) query, session-gated | valid `session` cookie -> `<h2>Account: <tab raw></h2>`; else 302 `/login` | esc; same gate | reachable only with the observed session (AC T2-4) | a (`/account?tab=overview`) |
| `passive-missing-hsts` / `-csp` / `-nosniff` | `missing-hsts` / `missing-csp` / `missing-nosniff` | every response | headers absent | `Strict-Transport-Security: max-age=31536000`, `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options: nosniff` on every response | AC T10-3 | - |

Infrastructure routes (not seeds, mode-independent unless stated): `GET /login` (form `user`,`pass` -> `POST /login`); `POST /login` with `user=alice&pass=wonderland` -> 302 `/account?tab=overview` + `Set-Cookie: session=<32 hex>; HttpOnly; Path=/` (hex = `sha1(nanos || counter || port)[..32]`, inert; Architect's call, no `rand`), else 401; `GET /logout-after?n=N` (needs a valid session) -> `{"armed":N}` and the session is deleted after N further requests that present it (`/logout-after` itself not counted); `GET /flaky` -> 500 `<p>flaky</p>` on every third request per instance (counter % 3 == 0), else 200 `<p>ok</p>`; `GET /slow?ms=N` -> sleep `min(N,5000)` ms then `<p>slept N</p>`. The index links both `/account/1` and `/account/2` (two numeric ids, so the crawler templates `/account/{id}`); its inline `<script>` performs `fetch` POSTs to `/api/profile`, `/api/login`, `/xml` (`<order id="7"><name>pen</name></order>`, an attribute plus element text) and opens `/ws` sending one echo frame, so a browser crawl sees them; the client crawler covers anchors and forms (AC T2-1 split, D8 below).

### D4. `/ws` (T10 call)

| Item | Pinned |
|---|---|
| Handshake | On every HTTP listener (h1 only). Checked in this order: V: any `Origin` accepted; P: `Origin` absent **or equal to `<scheme>://<Host header>`**, else 403 `<p>forbidden origin</p>`. Then the login cookie: `session_valid` = the `session` cookie names a live session; V upgrades either way; P answers 401 `<p>login required</p>` when not `session_valid` (T4: CSWSH and auth-bypass get a positive and a negative). `Sec-WebSocket-Protocol`: V echoes the first requested token back verbatim (accepts any subprotocol); P sends no such header. Both modes log a `handshake` entry. |
| First frame | `{"type":"hello","user":"alice"}` when `session_valid`, else `{"type":"hello","user":"anonymous"}`. |
| Echo | Text `{"type":T,"msg":M}` with `T` in `echo` or `chat` (T4 sends `chat`) -> `{"type":T,"msg":M',"html":"<b>M'</b>"}` where `M'` is `M` raw in V and HTML-escaped in P (so P reflects nothing unencoded in any field; serde_json string escaping applies in both). Other JSON or non-JSON text -> `{"type":"error","error":"bad message"}`. Binary -> echoed as binary. |
| Control | Ping -> pong (same payload); close -> close echoed, connection ends. Payload length > 1 048 576 -> close `1009` without reading it. Continuation frames -> close `1003`. Unmasked client frame -> close `1002`. |
| Codec | Hand-rolled RFC 6455 server codec: `decode_frame(&[u8]) -> Option<(Frame, usize)>`, `encode_frame(opcode, &[u8]) -> Vec<u8>`, `accept_key(&str) -> String` (SHA-1 + base64), pure and unit-tested. |
| Log | Every frame in/out as a `frame` entry (opcode, len, sha256); the handshake entry also carries `subprotocol` (the echoed token or `null`); when the loop ends a `{"kind":"close","seq","ts_ms","conn_id","code":1000\|1009\|…\|null}` entry is written and `close_conn` runs, so `/log/conns` shows the upgraded connection's `opened_ms`/`closed_ms` (T4: "at most 4 concurrent dialer connections" is read from `/log/conns`). |

### D5. L4 speakers (T10 call; byte literals are Architect's calls)

All `127.0.0.1`, ephemeral ports, started together by `--l4`/`.l4(true)`, listed in `/services` and in `l4_manifest()`. One pure `Speaker` per service drives a shared TCP/UDP driver. **Crash window** = 5 s: on a V trigger the driver logs `downtime {down_at_ms, up_at_ms = +5000, trigger_sha256}`, closes the offending connection, **drops the TCP listener and rebinds the same port after the window** (connects are refused meanwhile) or, for UDP, **drops every datagram** for the window, then serves again. In P the same input gets the row's protocol-error reply, the connection closes and the listener stays up. Every message is logged with `classified`.

| service (grammar) | proto | benign exchange (hex / text) | liveness | V trigger -> `Trigger` | P reply (then close) |
|---|---|---|---|---|---|
| `l4-tlv-crash` (`tlv`) | tcp | `00 03 61 62 63` -> same (echo); frame = u16 BE len + payload | `00 00` -> `00 00` | declared len > 4096, or declared len > bytes received after a 200 ms idle | `00 03 45 52 52` (`ERR`) |
| `l4-dns-fault` (`dns`) | udp | A query id `1234` for `example.test` -> header `12 34 81 80`, QD 1 AN 1, question echoed, answer `c0 0c 00 01 00 01 00 00 00 3c 00 04 7f 00 00 01` | A query for `.` (`00 01 01 00 00 01 00 00 00 00 00 00 00 00 01 00 01`) -> A `127.0.0.1` | a label length byte past the datagram end | header `<id> 81 81` + zero counts (FORMERR); non-A qtype -> RCODE 4 |
| `l4-udp-payload-crash` (`raw`) | udp | `61 62 63` -> `61 62 63` (echo) | any datagram echoed | payload starts `DE AD BE EF` and len >= 8 (AC T5-2b) | echo |
| `l4-resp` (`resp`) | tcp | `*1\r\n$4\r\nPING\r\n` or inline `PING\r\n` -> `+PONG\r\n`; `ECHO hi` -> `$2\r\nhi\r\n`; `GET k` -> `$-1\r\n`; `QUIT` -> `+OK\r\n` close; unknown -> `-ERR unknown command '<name>'\r\n` | `PING` | `$N` with N > 1 048 576; `*N` with fewer than N elements after a 200 ms idle | `-ERR Protocol error: invalid bulk length\r\n` / `-ERR Protocol error: incomplete multibulk\r\n` |
| `l4-memcached` (`memcached`) | tcp | `version\r\n` -> `VERSION 1.6.0-aitm\r\n`; `get k\r\n` -> `END\r\n`; `set k 0 0 2\r\nhi\r\n` -> `STORED\r\n`; `quit` closes; unknown -> `ERROR\r\n` | `version` | announced bytes > 1 048 576; a line > 2048 bytes without CRLF | `CLIENT_ERROR bad data chunk\r\n` / `CLIENT_ERROR line too long\r\n` |
| `l4-modbus` (`modbus`) | tcp | `00 01 00 00 00 06 01 03 00 00 00 01` -> `00 01 00 00 00 05 01 03 02 00 00` (fc 3, registers = `addr+i` as u16) | fc 3, addr 0, qty 1 | MBAP length > 260 or < 2 (shorter than unit id + fc) | `<tid> 00 00 00 03 01 83 03` (exception 0x03); protocol id != 0 same |
| `l4-mqtt` (`mqtt`) | tcp | CONNECT `10 0C 00 04 4D 51 54 54 04 02 00 3C 00 00` -> CONNACK `20 02 00 00`; PINGREQ `C0 00` -> `D0 00`; PUBLISH QoS1 `32 09 00 03 61 2F 62 00 01 68 69` -> PUBACK `40 02 00 01`; QoS0 accepted silently; SUBSCRIBE -> SUBACK QoS0; DISCONNECT `E0 00` closes | CONNECT + DISCONNECT | remaining-length varint with a 5th byte, or value > 65 536; reserved flags / type 0 or 15 are `protocol_error` (close, no bytes) | close with no bytes |
| `l4-smtp` (`smtp`) | tcp | banner `220 target.test ESMTP aitm\r\n`; `EHLO x`/`HELO x` -> `250 target.test\r\n`; `MAIL FROM:<a@target.test>` -> `250 OK\r\n`; `RCPT TO:<b@target.test>` -> `250 OK\r\n`; `NOOP` -> `250 OK\r\n`; `DATA` -> `451 not accepted\r\n`; `QUIT` -> `221 bye\r\n` close; unknown -> `500 unknown command\r\n` | `NOOP` | a line > 1024 bytes without CRLF | `500 line too long\r\n` |
| `l4-ftp` (`ftp`) | tcp | banner `220 aitm ftp\r\n`; `USER a` -> `331 password required\r\n`; `PASS b` -> `230 logged in\r\n`; `NOOP` -> `200 ok\r\n`; `PWD` -> `257 "/"\r\n`; `TYPE I` -> `200 ok\r\n`; `QUIT` -> `221 bye\r\n` close; unknown -> `500 unknown command\r\n` | `NOOP` | a line > 1024 bytes without CRLF | `500 line too long\r\n` |

**Denylist observation (AC T6-3/T6-4):** these arrive, are answered and logged `denylisted` so a cell can assert none came: RESP `FLUSHALL FLUSHDB SHUTDOWN CONFIG DEBUG SAVE` -> `-ERR denylisted command\r\n`; memcached `flush_all` -> `CLIENT_ERROR denylisted\r\n`; Modbus fc 5/6/15/16/22/23 and 8 -> exception `<fc|0x80> 01`; MQTT PUBLISH with retain -> accepted silently; SMTP `RCPT TO` outside `@target.test` -> `550 relay denied\r\n`; FTP `DELE STOR APPE RMD RNFR RNTO MKD` -> `550 denied\r\n`. Line speakers cap a line at 1024 bytes (memcached 2048); TLV at 4096; MQTT at 65 536; RESP/memcached data at 1 MiB. A line is over-long when its CRLF lies past the cap **or** no CRLF has arrived within cap + 1 bytes, so a 4096-byte line that arrives complete with its CRLF in one read is the trigger too (T6). The pure trait:

`trait Speaker: Send { fn name(&self) -> &'static str; fn banner(&self) -> Option<Vec<u8>>; fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed; fn on_idle(&mut self, mode: SeedMode, buf: &[u8]) -> Step; fn max_buffer(&self) -> usize; }` with `Parsed::{Incomplete, Message { consumed, step }}` and `Step::{Reply(Vec<u8>), ProtocolError(Vec<u8>), Denylisted(Vec<u8>), Fault(Vec<u8>), Trigger, Close(Option<Vec<u8>>)}` (`ProtocolError` = reply and keep the connection; `Fault` = the P-mode answer to a V trigger: reply, if non-empty, then close with reason `error`, listener stays up; `Trigger` = V crash); `CrashWindow` takes `Instant`s so the state machine is testable with a mocked clock. The legacy `L4Service` (UDP echo + TCP banner) is untouched.

### D6. Manifest (T10 call)

`manifest.rs` stays the single description. `PlantedVuln` rows for every HTTP/WS seed above (incl. `ws-cswsh` class `cswsh` route `/ws` and `ws-input-reflection` class `ws-input-reflection` route `/ws`, and the three passive rows). `L4Asset` gains `grammar: Option<String>` and `trigger: String`; `l4_manifest()` lists the nine services plus the legacy two. New `seed_index() -> &'static [SeedRoute]` with `SeedRoute { id, method, path, discovery: Anchor | Form | Script | Click | Ws }` is what the unit test `index_links_every_seed_route` walks against `app::index()`. Nothing in `app.rs`, `routes/`, `ws.rs`, `tls.rs`, `control.rs` or `speakers/` names `manifest` (the PR A integration task quotes the empty grep).

### D7. Harness surface (T10 call; signatures are Architect's calls)

`tests/e2e/aitm_e2e/config.py`: `CoreConfig.scanner: ScannerSection | None = None` where `@dataclass ScannerSection { allow_agent_active: bool | None, allow_agent_l4_fuzz: bool | None, max_jobs: int | None, history: int | None, check_timeout_s: int | None, default_profile: str | None, ceilings: dict[str, int] = {} }`; only set keys are emitted under `scanner:` (ceilings nested); omitted entirely when `None`. `CoreConfig.l4_scope_entries: list[dict] = []` emitted under `l4:` as `scope:` items with exactly the keys of `crates/aitm-proto-l4/src/types.rs::L4ScopeEntry`: `cidr: {addr, prefix}`, `ports: {lo, hi}`, `interface`, `direction` (`inbound|outbound`), `capability` (`capture|inject|intercept`), `inject_rate: {pps, burst}`; helper `l4_inject_entry(addr="127.0.0.1", prefix=32, lo=1, hi=65535, interface="*", direction="outbound", pps=200, burst=400) -> dict`. Emitting entries forces `l4:` + `enabled: true` lines.

`tests/e2e/aitm_e2e/scan.py` (every scan verb a cell calls goes through here):

| Symbol | Contract |
|---|---|
| `SCAN_VERBS_D3: tuple[str, ...]` | the 18 D3 names, for documentation; never used as the expectation |
| `expected_scan_verbs(client=None) -> list[str]` | `scan.*` names parsed from `crates/aitm/tests/frontends.rs` `EXPECTED_TOOLS` (reuse the regex of `mcp/test_tool_list_complete.py`); with `client`, raises `ContractDrift` unless the set equals live `scan_tools(client)` |
| `scan_tools(client) -> set[str]` | live `tools/list` names starting `scan.` |
| `require_verbs(client, *verbs)` / `require_lane(client, lane)` | `skip(...)` (exit 77) naming the missing verb / the lane with no `scan.checks` entry |
| `scan_call(client, role, verb, args=None) -> Any` / `scan_try(client, role, verb, args=None) -> tuple[str, Any]` | the only call paths; record `(verb, role, outcome, code)` in the ledger; `scan_error_code(msg) -> str \| None` parses `scan: <code>:` |
| `start_job(client, role, *, profile=None, profile_name=None, target=None, overrides=None, confirm=False) -> dict` | `scan.start`; `confirm=True` runs `client.confirm` (L4/intrusive) |
| `map_job(...)` same shape for `scan.map`; `cancel(client, role, job) -> dict` | |
| `wait_terminal(client, role, job, timeout=600.0, poll=0.5) -> dict` | polls `scan.status` until `state in {done, cancelled, failed}`; raises `TimeoutError` |
| `subscribe(client)`; `collect_push(subscriber, job, *, until_terminal=True, timeout=600.0) -> list[dict]` | `flow.subscribe` then drain `notifications/aitm/job` params for `job` |
| `issues(client, role, **filters) -> list[dict]`; `issue(client, role, id) -> dict` | walks `next_cursor` |
| `ScanTarget(mode, *, tls=True, control=True, l4=False, start_timeout=15.0)` | boots `aitm-testtarget-serve` with the D1 flags, parses every stdout line up to `ready`; `.base`, `.tls_base`, `.tls_h1_base`, `.control`, `.authority`, `.tls_authority`, `.tls_h1_authority`, `.services()`, `.service(name)`, `.logs: TargetLogs`, `.stop()`, context manager |
| `TargetLogs(control_url)` | `.http()`, `.ws()`, `.l4(service=None)`, `.conns()`, `.reset() -> int` (seq), `.last_seq() -> int`, `.scanner_requests(since_seq) -> list[dict]` (`kind == request` and `seq > since_seq`; Architect's call: probes carry no job marker, so "since the reset" is the discriminator), `.handshakes(listener=None)`, `.downtime(service)`, `.messages(service, dir=None)` |
| `Canary()` | out-of-scope loopback HTTP listener; `.base`, `.authority`, `.hits: list[dict]`, `.link_html(path)` (the `<a>` a cell posts to `/comments` on V), `.stop()` |
| `ledger_flush()` | `atexit`; writes `$AITM_E2E_LEDGER_DIR/<cell>.json` = `{"cell": "<argv0 stem>", "calls": [{"verb","role","outcome":"ok\|error","code":null\|"<code>"}]}`; a cell run by hand (dir unset) prints one note and writes nothing |

`tests/e2e/run.py`: creates a temp dir, exports `AITM_E2E_LEDGER_DIR`, and after any run whose discovered suites include surface `scan` prints `scan verb ledger (spec D3):` then one line per `expected_scan_verbs()` entry: `  scan.start                operator: t1_start_is_async, t1_cancel | agent: t1_agent_gates` or `  scan.profile.delete       UNCALLED`, then `ledger: N/M scan verbs called by at least one cell`; the exit code and `--list` output are unchanged.

### D8. Cells (T10 call; split and SKIP rules are Architect's calls)

`tests/e2e/scan/test_<track>_<cell>.py`, line 2 `# e2e: tier=T1 surface=scan needs=<http|ws|l4|obscura|redis>[ serial]`. Every cell boots its own target(s) and its own core, connects at the right role, SKIPs 77 via `require_verbs`/`require_lane`, and asserts on the target's own logs, a second subscribed `BusClient`, files on disk, or the kernel (never the proxy's view alone). The 38 cells and their assertions are enumerated in the plan (Tasks B4-B11). Splits: `test_t2_crawl.py` (browser, `needs=obscura`) + `test_t2_crawl_client.py` (`needs=http`), because one exit code cannot half-skip. `test_t1_lane_skip.py` provokes the skip with the first lane of `[ws, l4_stream, l4_packet]` that `scan.checks` reports empty and SKIPs 77 when every lane is live on the build. `test_t1_start_is_async.py` proves the loopback half of "stdio and loopback" (the harness has no stdio client; the stdio half is T1b's Rust test). `test_t10_bundled_passive_regression.py` uses the TLS listener through the proxy (`missing-hsts` fires on `https://` URLs only) and the plain listener for `ws://`.

## Acceptance criteria

Parent AC T10-1, T10-2, T10-3 refined; each observable.

1. S1 (T10-1) `cargo test -p aitm-testtarget` (Terminal) passes; `--lib --offline` passes in the sandbox; every D3 row has a V and a P route test with the literal body/header of its row; every D5 speaker has pure parser tests for the benign exchange, the liveness exchange, the V trigger (`Step::Trigger`) and the P reply; `CrashWindow` has a mocked-clock test (`down` at `t0`, still down at `t0+4999 ms`, up at `t0+5000 ms`).
2. S2 (T10-1) `aitm-testtarget-serve --mode vulnerable --port 0 --tls-port 0 --tls-h1-port 0 --control-port 0 --l4` prints the five D1 lines in order; `curl -k --http2 https://127.0.0.1:TLS/` negotiates `2`, `--http1.1` negotiates `1.1`, the h1-only listener negotiates `1.1` under `--http2`; `/log/http` then holds two `tls_handshake` entries (`alpn: h2`, `alpn: http/1.1`) and `request` entries with `version` `h2`/`h1` and `conn_req_index` 1 (`tests/scan_http.rs`, `test_t10_target_selfcheck.py`).
3. S3 (T10-1) Over one h2 connection, 5 requests yield one `/log/conns` entry with `requests: 5` and `conn_req_index` 1..5 in `/log/http`.
4. S4 (T10-1) `/ws`: V accepts `Origin: http://evil.example` (101, hello `anonymous`), P answers 403; after `POST /login` the hello is `alice`; echo of `<i>` yields `"html":"<b><i></b>"` in V and `"<b>&lt;i&gt;</b>"` in P; a 1 048 577-byte frame is answered with close 1009; `/log/ws` holds the handshake with the client's `sec_websocket_key` and `cookie_names: ["session"]`.
5. S5 (T10-1) For each of the nine services: the benign exchange returns the row's bytes; in V the trigger closes the connection, a connect (TCP) is refused / a datagram (UDP) unanswered for the next 4 s, the benign exchange works again within 6 s, and `/log/l4` holds one `downtime` entry with `up_at_ms - down_at_ms == 5000`; in P the trigger yields the row's protocol-error reply, the next connect succeeds immediately and `downtime` is empty (`tests/speakers_live.rs`, `test_t10_target_selfcheck.py`).
6. S6 (T10-1) `GET /manifest`, `/manifest.yaml` and `/<every seed id>` are 404 on the target and the control origin; `grep -rn manifest src/app.rs src/routes src/ws.rs src/tls.rs src/control.rs src/speakers` is empty; `/log/http` never contains a key `cookie` or `authorization` and a request with `Cookie: session=abc; theme=dark` logs `cookie_names: ["session","theme"]` and a 16-hex `cookie_sha256`.
7. S7 (T10-2) `python3 tests/e2e/run.py --list` lists 38 `scan/test_*.py` cells with the D8 tags; `python3 tests/e2e/run.py scan` ends with the ledger block; every `scan.*` verb of `expected_scan_verbs()` is called by at least one cell at a valid role once the lanes it needs are live (the plan's ledger map assigns each verb a cell); the T10 cells call `scan.profile.list/get/save/delete`, `scan.list`, `scan.status`, `scan.start` so the ledger is non-empty on a T1b-only build.
8. S8 (T10-2) `CoreConfig(scanner=ScannerSection(allow_agent_active=True, ceilings={"probes": 10}, default_profile="standard", max_jobs=1)).to_yaml()` contains exactly the block `scanner:\n  allow_agent_active: true\n  max_jobs: 1\n  default_profile: standard\n  ceilings:\n    probes: 10\n`; a core booted from it accepts `scan.start { target: V }` and the result's `clamped` contains an item with `field == "budget.probes"` and `applied == 10` (`test_t10_harness_config.py`).
9. S9 (T10-2) `CoreConfig(l4_enabled=True, l4_scope_entries=[l4_inject_entry()]).to_yaml()` parses in the core (boot succeeds) and `l4.scope.list` shows one entry with `interface: "*"`, `direction: outbound`, `capability: inject`.
10. S10 (T10-3) With the bundled catalogue loaded and no `scan.*` call, `curl --cacert <ca> -x <proxy> https://127.0.0.1:TLS/` against V plus a `ws://` echo through the proxy produce `script.findings` names `missing-hsts`, `missing-csp`, `ws-cleartext-transport`; the same against P produces none of the three (`test_t10_bundled_passive_regression.py`; the cell's ledger file has `calls: []`).

## Left to the builder

- Internal helper layout inside each `routes/*.rs`, the multipart and XML mini-parsers (bounded, no new crate), the exact stub bodies of `style.css`/`app.js`/`readme.txt`.
- Whether the WS frame loop reads with a fixed 64 KiB buffer or grows to the 1 MiB cap; tokio task structure of the drivers.
- Python internals of `TargetLogs` polling/retry; how `Canary` records hits.
- Wording of SKIP reasons, as long as each names the missing verb, lane, binary or privilege.

## Open questions

None.

## Summary

T10 makes `aitm-testtarget` the scanner v2 proving ground: one flag-selected process with plain, TLS-h2 and TLS-h1 listeners, `/ws`, nine L4 speakers under a 5 s crash window, and a control origin exposing redacted request, WS, L4 and connection logs; 23 HTTP/WS seeds plus three passive seeds in V/P, all linked from `/` and listed in the never-served manifest. The harness gains `scan.py` (typed helpers, `ScanTarget`, `TargetLogs`, `Canary`, the ledger), the `scanner:`/`l4.scope` emitters and the `run.py` ledger; 38 own-core cells cover every parent AC and SKIP loudly until their lane lands.

### T10 calls (recorded from the track owner; not reopened)

1. Only `crates/aitm-testtarget/**` in PR A; dependency allowlist as Constraints; hand-rolled RFC 6455 codec instead of `tokio-tungstenite`.
2. Flags `--tls-port`, `--tls-h1-port`, `--control-port`, `--l4`; first stdout line unchanged; L4 discovered via `/services`.
3. Control origin on its own port with the six routes, redaction rule, 50 000-entry rings, `seq`/`ts_ms`/`conn_id` on every entry, `tls_handshake` entries, `conn_req_index`.
4. The seed list, the session model, `/logout-after`, `/flaky`, `/slow`, P-only HSTS/CSP/nosniff.
5. `/ws` handshake, hello, echo, 1009, logging.
6. Nine speakers with one `Speaker` abstraction and a shared 5 s crash window; denylisted commands answered and logged; `l4-udp-payload-crash` as the packet lane's `raw` oracle; legacy `L4Service` untouched.
7. Manifest stays grader-only with `seed_index()`; `L4Asset` gains `grammar`, `trigger`.
8. Harness: `scan.py` helpers, `CoreConfig.scanner` + `l4_scope_entries`, ledger via `AITM_E2E_LEDGER_DIR`, `run.py` ledger print, one cell per AC, tags, own-core.

### Architect's calls (for the orchestrator to approve or correct)

- C1 `sha2 0.10` added for the SHA-256 log fields (in `Cargo.lock`); `rand` not added, session ids are `sha1(nanos||counter||port)[..32]`.
- C2 Flag presence enables a listener; `--l4` requires `--control-port`; a final `ready` line closes the stdout block.
- C3 ALPN dispatched by hand to hyper `http1`/`http2` (no hyper-util `server-auto`); `/ws` over h2 is 400.
- C4 Log shapes of D2 (`kind`-tagged entries, 16-hex hash prefixes, header allowlist, `requests` on `/log/conns`, `?service=` filter).
- C5 Every literal body, status, reply byte string, cap and error text in D3-D5; the `Speaker` trait shape; UDP `conn_id` = `u-<peer port>`.
- C6 Class tokens follow T3's reply (2026-10-31): `sqli` for every SQLi technique, `xss` for every reflection kind (header/cookie/json/multipart/path/account rows), `cmdi, ssti, path-traversal, xxe, crlf, nosqli, ldapi, open-redirect, cswsh, ws-input-reflection`, passive `missing-hsts, missing-csp, missing-nosniff`; cells tell techniques apart by `check_id` (`sqli-boolean`, `sqli-time`, `sqli`), never by class. The legacy six rows keep their M4 classes (`reflected-xss`, ...) for `grader.rs`.
- C7 Index discovery: inline `<script>` for the JSON/XML POSTs and the WS echo, a click-only span for `/files/readme.txt`, forms for `/search`, `/comments`, `/login`, `/upload`.
- C8 Harness signatures of D7; `scanner_requests(since_seq)` instead of a job marker; `ScannerSection` typed; `l4_inject_entry` defaults `pps 200, burst 400`.
- C9 Cell splits and SKIP rules of D8; `test_t1_contract.py` also exercises the legacy trio (`scan.discover` with `max_pages: 2`, `scan.passive`, `scan.report`) so the ledger covers them.
- C10 Agent policy `All` in cells is set by the operator through `agent.set { policy: "all" }` (verified in `crates/aitm-plugins/src/agent.rs`).
