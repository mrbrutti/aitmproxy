#!/usr/bin/env python3
"""T1: CA export + real-client MITM trust, status, dry-run, and agent gating.

Asserts on INDEPENDENT observers: a real curl TLS handshake through the proxy
against a hermetic HTTPS origin the proxy MITMs, plus the on-disk exported cert.

T1 (always): export a usable PEM; `curl --cacert <exported>` through the proxy -> 200
(proves export + MITM + the minted leaf chains to the exported root); `curl` with NO
trust -> TLS failure (proves the no-trust test is real); ca.status shape; ca.install
--dry_run lists the real `security` commands; an AGENT ca.install is refused by the
gate while an OPERATOR dry-run is allowed; ca.* appear in tools/list.

T2 (opt-in AITM_E2E_CA_REAL=1): the real OS-trust cycle install -> curl-without-k 200
-> uninstall -> curl-without-k fails. SKIPPED by default because on macOS user-scope
`security add-trusted-cert` requires a GUI authorization dialog (unattended-unsafe);
it runs non-interactively on Linux (ca-certificates anchors) or attended on macOS.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from harness import Harness, Reporter, curl  # noqa: E402


def jparse(s: str):
    i, j = s.find("{"), s.rfind("}")
    return json.loads(s[i:j + 1]) if i >= 0 and j > i else None


def main() -> int:
    r = Reporter("t1_ca_trust")
    with Harness("ca") as h:
        h.start_aitm()
        origin = h.start_tls_origin()
        proxy = h.proxy_url()

        # --- ca.status (read-only) ----------------------------------------- #
        rc, out, err = h.run_cli("ca", "status")
        st = jparse(out)
        r.check("status_exists", bool(st) and st.get("exists") is True, f"rc={rc} {err[:200]}")
        if st:
            stores = st.get("stores", {})
            absent = all(s.get("installed") == "absent" for s in stores.values()) if stores else False
            r.check("status_absent_preinstall", absent, f"stores={stores}")

        # --- ca.export -> usable PEM --------------------------------------- #
        exported = h.root / "exported-ca.pem"
        rc, out, err = h.run_cli("ca", "export", "--format", "pem", "--out", str(exported))
        ex = jparse(out)
        r.check("export_ok", rc == 0 and bool(ex) and "BEGIN CERTIFICATE" in (ex.get("certificate") or ""),
                f"rc={rc} {err[:200]}")
        r.check("export_wrote_file", exported.exists() and "BEGIN CERTIFICATE" in exported.read_text())

        # --- the headline: real HTTPS through the proxy, trusting the export - #
        code, http, body = curl(origin, proxy=proxy, cacert=str(exported))
        r.check("mitm_cacert_200", code == 0 and http == 200 and "aitm-e2e-origin-ok" in body,
                f"exit={code} http={http} body={body[:120]!r}")

        # control: with NO trust configured, the MITM leaf must be rejected.
        code, http, body = curl(origin, proxy=proxy)
        r.check("no_trust_rejected", code != 0 and http != 200,
                f"a MITM leaf was accepted with no trusted root (exit={code} http={http})")

        # --- ca.install --dry_run lists the real security commands --------- #
        rc, out, err = h.run_cli("ca", "install", "--dry_run")
        dry = jparse(out)
        cmds = " ".join(dry.get("commands", [])) if dry else ""
        r.check("install_dry_run", rc == 0 and bool(dry) and dry.get("dry_run") is True
                and ("add-trusted-cert" in cmds or "certutil" in cmds or "trust anchor" in cmds
                     or "update-ca-certificates" in cmds),
                f"rc={rc} cmds={cmds[:200]!r}")

        # --- gating over the real bus -------------------------------------- #
        op = h.mcp("operator"); op.initialize()
        agent = h.mcp("agent"); agent.initialize()
        tools = op.tools()
        r.check("tools_present",
                {"ca.export", "ca.status", "ca.install", "ca.uninstall"} <= tools,
                f"ca.*={sorted(t for t in tools if t.startswith('ca.'))}")

        # Agent install (non-dry, flag off) is refused BEFORE any security command runs.
        sc, is_err, text = agent.call("ca.install", {})  # no dry_run, no confirm handshake for agent
        r.check("agent_install_refused", is_err, f"agent ca.install should refuse, text={text[:160]!r}")

        # Operator dry-run is allowed (operator bypasses the agent gate; dry_run skips confirm).
        sc, is_err, text = op.call("ca.install", {"dry_run": True})
        r.check("operator_dry_run_allowed", (not is_err) and bool(sc) and sc.get("dry_run") is True,
                f"isError={is_err} sc={sc}")
        op.close(); agent.close()

        # --- T2: the real OS-trust round trip (opt-in) --------------------- #
        if os.environ.get("AITM_E2E_CA_REAL") == "1":
            rc_i, out_i, err_i = h.run_cli("ca", "install", "--yes", timeout=200)
            code_t, http_t, _ = curl(origin, proxy=proxy)  # no -k, no --cacert
            rc_u, _, _ = h.run_cli("ca", "uninstall", "--yes", timeout=200)
            code_a, _, _ = curl(origin, proxy=proxy)
            r.check("real_install_trusts", rc_i == 0 and code_t == 0 and http_t == 200,
                    f"install rc={rc_i} curl exit={code_t} http={http_t} {err_i[:160]}")
            r.check("real_uninstall_reverses", rc_u == 0 and code_a != 0,
                    f"uninstall rc={rc_u} curl exit={code_a}")
        else:
            r.skip("real_os_trust_cycle", "T2",
                   "set AITM_E2E_CA_REAL=1 to run the real OS-trust install/uninstall; "
                   "on macOS user-scope add-trusted-cert needs a GUI auth dialog "
                   "(unattended-unsafe), it runs non-interactively on Linux")

    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
