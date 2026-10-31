#!/usr/bin/env python3
# e2e: tier=T1 surface=ca
"""CA export + real-client MITM trust, status, dry-run, and agent gating.

Asserts on INDEPENDENT observers: a real curl TLS handshake through the proxy against
a hermetic HTTPS origin the proxy MITMs, plus the on-disk exported cert. T1 (always):
export a PEM a real `curl --cacert` accepts (HTTP 200 from a MITM'd origin), and with
NO trust configured the minted leaf is rejected (the no-trust test is real); ca.status
shape; ca.install --dry_run lists the real `security` commands; an AGENT ca.install is
gate-refused while an OPERATOR dry-run is allowed; ca.* in tools/list. The real
OS-keychain cycle is a T2 opt-in (AITM_E2E_CA_REAL=1) — macOS user-scope trust needs a
GUI dialog, so it is unattended-unsafe there (it runs non-interactively on Linux).
"""
import json
import os
import sys
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))
sys.path.insert(0, str(E2E / "lib"))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e import tls  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from seeded import aitm_cli, curl_code  # noqa: E402


def jparse(s: str):
    i, j = s.find("{"), s.rfind("}")
    return json.loads(s[i:j + 1]) if i >= 0 and j > i else None


def main() -> None:
    cfg = CoreConfig(proxy_port=free_port(), ssl_insecure=True)
    with Aitm.server(cfg) as core:
        proxy = f"http://127.0.0.1:{cfg.proxy_port}"
        crt, key = tls.upstream_cert(core.workdir)
        srv, oport = tls.start_https_echo(crt, key)
        origin = f"https://127.0.0.1:{oport}/"
        try:
            section("ca.status (read-only)")
            rc, out, err = aitm_cli(core, "ca", "status")
            st = jparse(out)
            check(bool(st) and st.get("exists") is True, "ca.status reports the CA exists")
            stores = st.get("stores", {}) if st else {}
            check(bool(stores) and all(s.get("installed") == "absent" for s in stores.values()),
                  "both scopes report absent before install")

            section("ca.export -> a PEM a real curl accepts")
            exported = os.path.join(core.workdir, "exported-ca.pem")
            rc, out, err = aitm_cli(core, "ca", "export", "--format", "pem", "--out", exported)
            ex = jparse(out)
            check(rc == 0 and bool(ex) and "BEGIN CERTIFICATE" in (ex.get("certificate") or ""),
                  "ca.export emits a PEM certificate")
            check(os.path.exists(exported) and "BEGIN CERTIFICATE" in open(exported).read(),
                  "ca.export --out wrote the cert file")

            section("real HTTPS through the proxy, trusting the export")
            rc, code, _ = curl_code(["-x", proxy, "--cacert", exported, origin])
            check(rc == 0 and code == 200, f"curl --cacert through the proxy = 200 (rc={rc} http={code})")
            rc, code, _ = curl_code(["-x", proxy, origin])
            check(rc != 0 and code != 200, f"the MITM leaf is rejected with no trusted root (rc={rc} http={code})")

            section("ca.install --dry_run lists the real security commands")
            rc, out, err = aitm_cli(core, "ca", "install", "--dry_run")
            dry = jparse(out)
            cmds = " ".join(dry.get("commands", [])) if dry else ""
            check(rc == 0 and bool(dry) and dry.get("dry_run") is True and
                  any(k in cmds for k in ("add-trusted-cert", "certutil", "trust anchor", "update-ca-certificates")),
                  "dry_run lists the trust-store commands without running them")

            section("agent gating vs operator over the bus")
            op = BusClient.operator(core)
            agent = BusClient.agent(core)
            check({"ca.export", "ca.status", "ca.install", "ca.uninstall"} <= set(op.tool_names()),
                  "ca.* present in tools/list")
            status, msg = agent.try_call("ca.install", {})
            check(status == "error", f"agent ca.install is gate-refused ({msg[:70]})")
            res = op.call("ca.install", {"dry_run": True})
            check(isinstance(res, dict) and res.get("dry_run") is True,
                  "operator ca.install --dry_run is allowed (bypasses the agent gate)")

            section("real OS trust-store cycle")
            if os.environ.get("AITM_E2E_CA_REAL") == "1":
                rc_i, _, err_i = aitm_cli(core, "ca", "install", "--yes", timeout=200)
                rc_t, code_t, _ = curl_code(["-x", proxy, origin])
                rc_u, _, _ = aitm_cli(core, "ca", "uninstall", "--yes", timeout=200)
                rc_t2, code_t2, _ = curl_code(["-x", proxy, origin])
                check(rc_i == 0 and rc_t == 0 and code_t == 200,
                      f"real install makes curl-without-k succeed (install rc={rc_i} curl={code_t})")
                check(rc_u == 0 and code_t2 != 200, f"real uninstall reverses trust (curl={code_t2})")
            else:
                print("  [skip tier=T2] real_os_trust_cycle: set AITM_E2E_CA_REAL=1 to run the real "
                      "install/uninstall; macOS user-scope add-trusted-cert needs a GUI auth dialog "
                      "(unattended-unsafe), Linux runs it non-interactively", flush=True)

            ok("CA export + real-client trust + gating verified")
        finally:
            srv.shutdown()


if __name__ == "__main__":
    main()
