# T10 PR B (harness + cells) — fix round 1 (panel findings, range 395f9281..2c7a3251)

Dispositions: **FIX** = fix now; **ACCEPT** = accepted (Review log); **DOCS** = orchestrator amends spec/plan.
Everything is pure-stdlib Python under `tests/e2e/aitm_e2e/scan.py`, `tests/e2e/run.py`, `tests/e2e/scan/**`.
The sandbox cannot bind ports: prove with `py_compile`, import dry-runs, and pure-function snippets; the
orchestrator re-runs `run.py scan` in the Terminal (`/tmp/claude/t10-scan-run3.log` is the current baseline).

## Important (spec): `tests/e2e/scan/test_t10_target_selfcheck.py` covers a subset of plan B4 / spec S4-S6

1. **FIX** Every D3 seed row (not one per class): drive each remaining row with its trigger and assert the
   D3 literal signal on V and the patched answer on P: `/items?id=1 AND 1=1` vs `1 AND 1=2` (`items: 1`/`items: 0`;
   P 400), `/orders?id=1 AND SLEEP(2)` (>= 2 s on V, `<p>order …</p>`; P 400 in < 1 s), `/ping?host=localhost;id`
   (`uid=0(root) gid=0(root)`; P 400) and `;sleep 2` (>= 2 s V, < 1 s P), `POST /xml` with the DTD (marker; P 400
   `DTD not allowed`), `/ldap?user=*` (`LDAP-ALL-USERS-MARKER-77c2`; P `no entries`), `/prefs` with
   `Cookie: theme=<m>` (raw vs escaped), `POST /api/profile` nested city (raw vs escaped), `POST /upload`
   multipart filename+note (raw vs escaped), `/docs/<m>`, `/files/<m>.txt` (raw vs escaped), `/redirect?next=
   https://redirect-marker-e2d9.example/` (`Location` honoured on V, `/` on P), `/fetch?url=http://169.254.169.254/`
   (SSRF marker vs 403), `/account/2` (IDOR marker vs 403), `/admin` with `X-Role: admin` (marker vs 403),
   `POST /comments` then `GET /comments` (stored marker raw vs escaped), `/search?q=<m>` (raw vs escaped).
   Table-drive it: one list of `(name, method, path, headers, body, v_predicate, p_predicate)`.
2. **FIX** A `/ws` block over the plain listener with `aitm_e2e.ws.WsClient` (or the cell's own masked client):
   V + `Origin: http://evil.example` -> 101, hello `{"type":"hello","user":"anonymous"}`, echo `<i>` ->
   `"html":"<b><i></b>"`; P + foreign Origin -> 403; P no Origin no cookie -> 401; P no Origin + login cookie -> 101
   and `"html":"<b>&lt;i&gt;</b>"`; V after `POST /login` -> hello `alice`; a frame declaring 1 048 577 bytes ->
   close 1009; `/log/ws` holds the handshake with the client's `sec_websocket_key` and `cookie_names == ["session"]`.
3. **FIX** All nine speakers, table-driven from D5 (benign bytes, liveness bytes, V trigger, P reply):
   V trigger -> TCP connect refused / UDP silent within 500 ms, still down at +4 s, liveness OK by +6 s, one
   `downtime` row with `up_at_ms - down_at_ms == 5000`; P trigger -> the row's reply then the connection closes,
   no downtime. Run the nine V windows concurrently (threads) so the cell stays under ~20 s. Bytes are in the spec
   D5 table and in `crates/aitm-testtarget/tests/speakers_live.rs` (`cases()`), use the corrected MQTT vectors.
4. **FIX** 404 sweep: `/manifest`, `/manifest.yaml` and a fixed list of the 28 manifest ids (copy from
   `crates/aitm-testtarget/src/manifest.rs`; the cell cannot read the manifest at runtime) -> 404 on **both**
   origins (`t.base` and `t.control`).

## Minor (security), FIX

5. Eight cells leak `tempfile.mkdtemp` dirs (`test_t1_agent_gates`, `test_t1_cancel`, `test_t1_catalogue`,
   `test_t1_push`, `test_t1_scope_and_budget`, `test_t1_start_is_async`, `test_t10_harness_config`,
   `test_t4_ws_namespace`): one `work = mkdtemp()` per cell, sub-dirs under it, `shutil.rmtree(work,
   ignore_errors=True)` in `finally`, as the T2 cells do.
6. `scan.py` `Canary._Handler._hit`: record the hit **before** parsing `Content-Length`/reading the body;
   `try/except ValueError`; cap the read at 1 MiB; still answer 200.
7. `scan.py` `_http_json` (and `test_t1_cancel.py` `plant_canary_link`): use a module-level
   `urllib.request.build_opener(urllib.request.ProxyHandler({}))` so `http_proxy`/`HTTPS_PROXY` env vars never
   route control-origin or canary requests off loopback; no redirects followed.

## Minor (spec), FIX

8. `scan.py`: drop the unused `WS_AUTH_BYPASS_CLASS`.
9. `test_t1_agent_gates.py`: after the agent's `scan.map`, one `scan_call(ag, "agent", "scan.status", {"job": …})`
   so the ledger map row holds.
10. `test_t4_points.py`: record the cell's own `Sec-WebSocket-Key` and assert at least one handshake after `seq0`
    carries a different key (the lane really dialled).
11. `test_t10_bundled_passive_regression.py`: poll window 15 s (plan).

## Minor (spec), DOCS (orchestrator)

- Tags: `test_t10_bundled_passive_regression.py` stays `needs=http` (it needs no WS lane and runs today); plan B4
  amended. `serial` on `test_t10_harness_config`/`test_t1_agent_gates` stays (they flip agent policy / write
  `scanner:` cores); plan amended; D7 gains the sentence that `run.py` does not honour `serial` yet (documentation).
- D7: additive signatures (`require_lane(.., role=)`, `scan_call(.., confirm=)`, `subscribe` returns the client,
  `last_seq` = max over the three logs), the extra public names (`ROLES`, `TERMINAL_*`, `JOB_NOTIFICATION_METHOD`,
  `WS_CSWSH_CLASS`, `WS_INJECTION_CLASS`), the ledger's "(not in EXPECTED_TOOLS)" lines, and `SCAN_VERBS_D3`
  usable by `test_t1_contract` for contract completeness (never for the live set).
- Plan B4 bundled cell: attribution by `flow.get(flow_id).authority` for HTTP findings and by host-in-`detail`
  for the WS finding (a WS flow's authority is null); the cell imports `ScanTarget` from `aitm_e2e.scan`.
- Plan B7/B10: cite T2's `session.canary {kind, method, path}` and T5's `lane`, `evidence.l4.sent_hex`,
  `seed_id`, `status.l4.crashes` as those tracks' pinned fields.

## Important (quality)

12. **FIX** `scan.py`: `scan_try(client, role, verb, args=None, *, confirm=False)` shares one body with `scan_call`
    (`client.confirm` when `confirm`, else `client.call`; `ToolError` -> `("error", str(e))` and ledgered; a
    `BusError` propagates). Delete the hand-rolled handshakes in `test_t1_lane_skip.py` (`_confirm` re-send),
    `test_t5_pins_dryrun.py` (`try_start`) and `test_t6_gates.py` (`refusal_code` handshake branch); pass `confirm=True`.
13. **FIX** Move the copied helpers into `aitm_e2e/scan.py` and make the cells use them (you may not edit `ws.py`,
    `bus.py`, `core.py`, `__init__.py`; D12 gives T10 only `scan.py`, `config.py`, `run.py`, `tests/e2e/scan/**`):
    `require_checks(client, *ids, role="operator")`; `brief(issues, limit=12)`; `sitemap(client, role, job, *,
    limit=1024) -> (nodes, points)` walking `next_cursor` like `issues()`; `run_to_terminal(client, role, *,
    timeout=600.0, **start_kwargs) -> (job, status)`; `login(base) -> str` (direct) and `login_via_proxy(proxy_port,
    base) -> str` (32-hex session id, never printed); `l4_endpoint(target, service, grammar=None) -> dict` using
    `urllib.parse.urlsplit("//" + addr)` (IPv6-safe) replacing the eleven `rpartition(":")` copies; `packet_lane_gate
    (client) -> dict` and `read_capture_packets(client, flow_id)` for the T5 cells; an `Expectations` soft-assert
    collector (`expect`, `note`, `finish`) for T5/T6-grammars; `WsClientWithHeaders` (one subclass of
    `aitm_e2e.ws.WsClient` with `extra_headers` and a recorded `key`) replacing the two copies in the T4 cells;
    `boot_target(mode, **kw) -> ScanTarget` that maps `FileNotFoundError` to `skip(...)` (exit 77) and use it in every
    cell, so a missing serve binary is one consistent SKIP (remove the per-cell `except FileNotFoundError` blocks and
    fix the T6 docstring). Keep per-cell wrappers only where the cell truly differs (e.g. grammars_live's
    `[SKIP-PART]`). Add every new public name to `__all__` and to the D7 table note in your report.
14. **ACCEPT with modification** `test_t10_bundled_passive_regression.py`: the FAIL stays a hard `check` (the cell is
    the regression detector for exactly this bug and T1b is fixing it in flight; a SKIP would say "cannot prove"
    which is false). Replace the six-line engine-internals paragraph with one `note:` line: "known: bundled
    ws-cleartext-transport never fires on a live WS flow (aitm-plugin-rhai exposes no request to Rhai hooks on
    WebSocket flows); T1b fix in flight" and keep the `script.list` / `findings by source` diagnostics (two lines).
    The orchestrator records the disposition in the Review log and the PR body.

## Minor (quality), FIX

15. T4 cells: assert `wait_terminal(...)["state"] == "done"` (or use `run_to_terminal`); `test_t4_points.py` walks the
    sitemap cursor via `sitemap()`; `test_t4_ws_namespace.py` 4-handle cap: assert the error path (`status ==
    "error"` and `"handle"` in the message) or a tight regex `r"\b4\b.*handle|handle.*\b4\b"` on a success payload.
16. `scan.py`: `collect_push` re-stashes other jobs' lines (or the docstring says they are discarded; pick re-stash);
    `ROLES` in `__all__`; shape errors raise `RuntimeError` not `ToolError` (also in the two T5 cells); `require_lane`
    calls `require_verbs(client, "scan.checks")`; the `SCAN_VERBS_D3` comment names `test_t1_contract`'s
    contract-completeness use; `_parse_expected_tools` raises `RuntimeError("EXPECTED_TOOLS not found in <path>")`
    when neither regex matches; `ledger_flush` is silent when there are no calls and no dir (the `calls: []` file is
    still written when the dir is set), after which `run.py` drops `atexit.unregister`.
17. `run.py`: wrap `print_ledger`'s body in `try/except Exception as e: print(f"ledger: could not print ({e})")`.
18. Stale/redundant statements: delete the nine-line plan-contradiction note in `test_t5_bounded_clean.py`, the
    `>= CASES` before `== EXPECTED_FRAMES`, `all(n <= 8)` after the exact list in `test_t3_h2_observe.py`, the dead
    `reset()` in `test_t1_push.py`, the explicit default kwargs in the bundled cell; `test_t10_harness_config.py`'s
    `or 200` becomes `fail("standard profile has no crawl.max_pages")`; unreachable statements after `fail()`/
    `skip()` removed (`__init__.py` is not yours; do not annotate `NoReturn` there).
19. Readability: `test_t1_catalogue.py` `status, loaded = op.try_call(...)` then build the list only when `ok`;
    `test_t1_lane_skip.py` `check(isinstance(entry, dict) and entry.get("lane") == dead, ...)`; one `JOB_TIMEOUT`
    constant per cell with a one-line reason where it differs (T2 cells use an inline 900); `test_t6_grammars_live.py`
    `advertises()` matches `id`/`class` tokens split on `-`/`_`, not free text; `test_t6_gates.py` uses `op.call` for
    `agent.set` like `test_t1_agent_gates.py`.
20. Timing: replace fixed sleeps with a deadline poll (`until(pred, timeout)` helper in `scan.py`): `test_t1_record_
    policy.py` 1 s settle, `test_t10_target_selfcheck.py` 0.2 s log waits; its `wait_refused(addr, 0.5)` widens to
    2 s (the window is 5 s) while liveness-by-6 s stays.

## ACCEPT (record only)

- Sharing the `EXPECTED_TOOLS` regex with `tests/e2e/mcp/test_tool_list_complete.py` would edit a file outside T10's
  row; the copy stays with a comment naming its source.
- `TargetLogs.last_seq()` unused by cells but pinned by D7: kept.
- `fail`/`skip` `NoReturn` annotations live in `aitm_e2e/__init__.py` (not T10's); follow-up for the e2e framework owner.

## Already done by the stage-5 tester (commit after 2c7a3251): do not redo
- Item 2 (`/ws` block) and item 4 (28-id 404 sweep on both origins) are implemented in
  `test_t10_target_selfcheck.py` (`check_ws`, `check_manifest_404`); item 1 (all seed rows) and item 3 (nine
  speakers) remain. Keep the tester's helpers; add the missing rows and speakers table-driven beside them.
- `test_t4_points.py` observer, `test_t4_ws_namespace.py` cap assertion, `test_t1_record_policy.py` and
  `test_t6_denylist_real_servers.py` non-vacuity, the bundled cell's P-side attribution closure: done; items 10 and
  15 (cap) are satisfied; still assert `wait_terminal(...)["state"] == "done"` in the T4 cells.
- The tester changed the bundled cell's tag to `needs=ws`; the orchestrator's ruling is `needs=http` (plan B4 amended):
  set it back to `# e2e: tier=T1 surface=scan needs=http`.
