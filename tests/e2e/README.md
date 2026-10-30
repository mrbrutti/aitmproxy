# tests/e2e — REAL end-to-end scenarios

These scenarios boot a **real** `aitm` proxy (dedicated ports, per-run throwaway
dirs, a throwaway CA), a **real** seeded target (`aitm-testtarget-serve`), and, for
the CA cells, a hermetic loopback HTTPS origin. They drive the product the way an
operator or agent does — the one-shot CLI, the loopback-TCP MCP bus, and real
`curl` — and assert on **independent observers** (curl's TLS handshake and received
bytes, findings written to disk, the testtarget's own vuln logic), never the
proxy's own view. This is the standard Matt set after green fixture tests let a
broken app ship: a scenario only passes if the feature works on the wire.

They align with the settled e2e-test-framework convention (PR #110): the layout is
`tests/e2e/<surface>/test_*.py`, each test is run as a subprocess and classified by
**exit code — 0 = PASS, 77 = SKIP (a one-line reason is printed first), anything else
= FAIL**. The aggregate runner exits non-zero iff a required suite FAILs; skips are
loud, never green.

## Layout

- `ca/`, `poc/`, `findings/`, `scripting/` — one Tier-1 `test_*.py` per surface. Each
  is standalone-runnable and honours the exit-code contract above.
- `lib/harness.py` — a thin, self-contained helper these tests use **until the shared
  `tests/e2e/aitm_e2e/` library (PR #110) is on main**: it boots aitm/testtarget/
  HTTPS-origin, a stdlib loopback-TCP MCP client (agent vs operator, `_confirm`), a
  `curl` helper, the reporter, and process-group cleanup (obscura children included —
  never a machine-wide `pkill`). When `aitm_e2e` lands, these imports migrate to
  `Aitm`/`BusClient`/`Upstream`/`CoreConfig`; the surface is intentionally small.
- `run.sh` — a stopgap aggregate runner (same exit-code contract) until the
  framework's `tests/e2e/run.py` is on main.

## Running

```bash
# Build the binaries the suite needs (or point the env vars at prebuilt ones).
cargo build -p aitm -p aitm-testtarget

# All surfaces (stopgap runner; use tests/e2e/run.py once #110 is on main):
tests/e2e/run.sh
tests/e2e/run.sh ca poc          # a subset

# A single test directly (the runner just subprocesses this and reads the exit code):
python3 tests/e2e/ca/test_ca_trust.py
```

Binary discovery: `$AITM_BIN` / `$AITM_TESTTARGET_BIN`, else
`target/{debug,release}/<bin>`. Port binding and a real `security`/`curl` mean these
run outside the Claude Bash sandbox (via the Terminal panel or a normal shell), on
dedicated non-default ports (never 8080/8081/8082 — the app may be running).

### Opt-in cells

- `AITM_E2E_CA_REAL=1` — run the **real OS trust-store** install → curl-without-`-k`
  → uninstall cycle in `t1_ca_trust`. Skipped by default: on macOS a user-scope
  `security add-trusted-cert` needs a GUI authorization dialog (unattended-unsafe);
  on Linux the ca-certificates anchor path runs non-interactively.

## What each scenario proves

| Scenario | Proves (independent observer) |
|---|---|
| `t1_ca_trust` | `ca.export` emits a PEM a real `curl --cacert` accepts through the proxy (HTTP 200 from a MITM'd origin); with **no** trust configured the minted leaf is rejected (curl exit 60); `ca.status` shape; `ca.install --dry_run` lists the real `security` commands; an **agent** `ca.install` is refused by the gate while an **operator** dry-run is allowed; `ca.*` in `tools/list`. The real keychain cycle is a T2 opt-in. |
| `t1_findings_persist_redact` | a recorded finding persists as `<id>.yaml`, lists and gets back; secrets in `notes`/`title`/**`target`** are `[redacted]` in the on-disk file; `findings.remove` is operator/CLI-only (agent refused) and an operator remove deletes the on-disk artifact. |
| `t1_poc_reproduce` | `poc.run` reproduces reflected XSS against the vulnerable target (a `word` matcher on the reflected payload; the patched target fails — parsed from JSON `passed`, not the exit code) and auto-records a finding; `poc.build` from a captured flow is **credential-free** (no query/body/header secret in the artifact). |
| `t1_scripting_live` | a boot-loaded Rhai `on_request` hook injects a header the **upstream** acts on (the `/admin` bypass), an `on_response_headers` hook adds a header the **client** receives, a `reg.add_command` ScriptCommand is callable by an operator and refused for an agent (Sensitive), and deny-by-default refuses filesystem and out-of-scope `http.send`. |

## Notes / findings surfaced by this suite

- **macOS CA install is not a core hang.** `RealExecutor` bounds the `security`
  subprocess (15s read / 180s mutate) and returns a clear `timed out` error. The
  macOS app's *silent* `ca.install` failure is app-side (agent-gating/role, an
  app-side timeout shorter than the OS dialog, or the GUI auth dialog not being
  surfaced), not a core hang. User-scope trust requires that GUI dialog, so the real
  cycle is a T2/attended (or Linux) cell.
- **`ca.status` `trusted` is always `unknown` on macOS** (no reliable CLI trust
  check). The real trust signal is the `curl --cacert`/no-trust pair, which this
  suite uses.
- **Rhai `on_response` cannot mutate the response on the wire.** The response is
  streamed, so the mutation point is `on_response_headers`; `on_response` fires after
  `ResponseComplete` (post-forward) and its response edits are a silent no-op. The
  scripting scenario uses `on_response_headers`. The `rhai.api.json` wording implies
  `on_response` can mutate the client-bound response — a doc/footgun gap to close.
