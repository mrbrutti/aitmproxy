#!/usr/bin/env python3
# e2e: tier=T1 surface=poc
"""poc.run reproduces a real finding against the seeded target, and poc.build
produces a CREDENTIAL-FREE PoC from a captured flow.

Ground truth: the vulnerable-vs-patched verdict from the real target (a `word`
matcher on the reflected payload — raw only when vulnerable) and the exact bytes of
the built PoC. poc.run's exit code never reflects pass/fail, so we parse JSON
`passed`. poc.build reads the LIVE flow store, so it runs over the bus after a real
request is captured; secrets in the query / body / credential headers must NOT appear
in the built artifact (regression guard: crates/aitm-poc/src/builder.rs).
"""
import json
import os
import sys
import tempfile
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))
sys.path.insert(0, str(E2E / "lib"))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from seeded import TestTarget, aitm_cli, curl_code  # noqa: E402

MARKER = "<xss-probe-aitm-e2e>"
POC_YAML = """id: reflected-xss-search-q
info:
  name: Reflected XSS in search q parameter
  severity: high
  cwe: CWE-79
  tags: [xss, reflected]
variables:
  - name: target
    required: true
  - name: param
    default: q
  - name: marker
    default: "%s"
steps:
  - http:
      method: GET
      url: "{{target}}/search?{{param}}={{url_encode(marker)}}"
success:
  all:
    - type: status
      status: 200
    - type: word
      word: "{{marker}}"
""" % MARKER

Q_SECRET = "qSEC-access-token-111"
B_SECRET = "bSEC-password-222"
H_SECRET = "hSEC-bearer-333"
X_SECRET = "xSEC-xauthtoken-444"


def jparse(s: str):
    i, j = s.find("{"), s.rfind("}")
    return json.loads(s[i:j + 1]) if i >= 0 and j > i else None


def main() -> None:
    with TestTarget("vulnerable") as vuln, TestTarget("patched") as patched:
        poc_dir = tempfile.mkdtemp(prefix="aitm-e2e-poc-")
        Path(poc_dir, "reflected-xss.poc.yaml").write_text(POC_YAML)
        cfg = CoreConfig(
            proxy_port=free_port(),
            scope_entries=[vuln.host(), patched.host()],
            poc_dir=poc_dir,
            findings_dir=os.path.join(poc_dir, "findings"),
        )
        with Aitm.server(cfg) as core:
            poc_path = str(Path(poc_dir, "reflected-xss.poc.yaml"))

            section("poc.run reproduces reflected XSS against the seeded target")
            rc, out, err = aitm_cli(core, "poc", "run", "--poc_path", poc_path, "--target", vuln.base_url)
            res = jparse(out)
            check(bool(res) and res.get("passed") is True,
                  f"poc.run passes against the vulnerable target (passed={res.get('passed') if res else None})")
            evaluated = {e.get("assertion"): e.get("matched") for e in (res or {}).get("evaluated", [])}
            check(any("word" in str(k).lower() for k in evaluated),
                  f"the word matcher (not just status) carried the finding ({evaluated})")
            check(bool(res) and bool(res.get("recorded_id")),
                  "a passing poc.run auto-records a finding")

            rc, out, err = aitm_cli(core, "poc", "run", "--poc_path", poc_path, "--target", patched.base_url)
            res_p = jparse(out)
            check(bool(res_p) and res_p.get("passed") is False,
                  "poc.run fails against the patched target (negative control)")

            section("poc.build from a captured flow is credential-free")
            proxy = f"http://127.0.0.1:{cfg.proxy_port}"
            url = f"{vuln.base_url}/search?q={MARKER}&access_token={Q_SECRET}"
            rc, code, _ = curl_code(
                ["-x", proxy, "-X", "POST", "--data", f"password={B_SECRET}",
                 "-H", f"Authorization: Bearer {H_SECRET}", "-H", f"X-Auth-Token: {X_SECRET}", url])
            check(rc == 0, f"a request carrying secrets was proxied + captured (rc={rc})")

            op = BusClient.operator(core)
            flows = op.call("flow.list")
            ids = flows if isinstance(flows, list) else (flows.get("ids", []) if isinstance(flows, dict) else [])
            check(bool(ids), f"the flow was captured over the bus ({ids})")
            last = ids[-1]
            fid = last if isinstance(last, str) else (last.get("id") if isinstance(last, dict) else None)
            built = op.call("poc.build", {"flow_id": fid, "name": "Reflected XSS", "param": "q"})
            yaml_text = built if isinstance(built, str) else json.dumps(built)
            check("steps:" in yaml_text, "poc.build produced a PoC YAML")
            leaked = [s for s in (Q_SECRET, B_SECRET, X_SECRET, H_SECRET) if s in yaml_text]
            check(not leaked, f"the built PoC is credential-free (leaked={leaked})")

            ok("PoC reproduce + credential-free build verified")


if __name__ == "__main__":
    main()
