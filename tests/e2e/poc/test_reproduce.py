#!/usr/bin/env python3
"""T1: poc.run reproduces a real finding against the seeded target, and poc.build
produces a CREDENTIAL-FREE PoC from a captured flow.

Ground-truth observers: the vulnerable-vs-patched verdict from the real target (a
`word` matcher on the reflected payload -- raw only when vulnerable), and the exact
bytes of the built PoC YAML.

Notes proven here: poc.run's exit code never reflects pass/fail, so we parse the JSON
`passed` field; poc.build reads the LIVE flow store, so it is driven over the bus
after a real request is captured; secrets in the query string / body / credential
headers must NOT appear in the built artifact (regression: the builder historically
scrubbed only 4 header names -- see crates/aitm-poc/src/builder.rs).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from harness import Harness, Reporter, curl  # noqa: E402

MARKER = "<xss-probe-aitm-e2e>"
POC_YAML = """\
id: reflected-xss-search-q
info:
  name: Reflected XSS in search q parameter
  severity: high
  cwe: CWE-79
  tags: [xss, reflected]
variables:
  - name: target
    description: Base URL of the target
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

# Distinct secrets, one per leak location, so the assertion pinpoints coverage.
Q_SECRET = "qSEC-access-token-111"
B_SECRET = "bSEC-password-222"
H_SECRET = "hSEC-bearer-333"
X_SECRET = "xSEC-xauthtoken-444"


def jparse(s: str):
    i, j = s.find("{"), s.rfind("}")
    return json.loads(s[i:j + 1]) if i >= 0 and j > i else None


def main() -> int:
    r = Reporter("t1_poc_reproduce")
    with Harness("poc") as h:
        vuln = h.start_testtarget("vulnerable")
        patched = h.start_testtarget("patched")
        host_port = vuln.split("://", 1)[1]
        h.scope_hosts = [host_port, patched.split("://", 1)[1]]
        (h.poc_dir / "reflected-xss.poc.yaml").write_text(POC_YAML)
        h.start_aitm()
        poc_path = str(h.poc_dir / "reflected-xss.poc.yaml")

        # --- poc.run reproduces the finding against the vulnerable target --- #
        rc, out, err = h.run_cli("poc", "run", "--poc_path", poc_path, "--target", vuln)
        res = jparse(out)
        r.check("poc_run_vuln_passes", bool(res) and res.get("passed") is True,
                f"rc={rc} passed={res.get('passed') if res else None} err={err[:200]}")
        # The word leaf (not status) must be what carries it.
        evaluated = {e.get("assertion"): e.get("matched") for e in (res or {}).get("evaluated", [])}
        r.check("poc_run_word_matched", any("word" in str(k).lower() or MARKER in str(k) for k in evaluated),
                f"evaluated={evaluated}")

        # negative control: patched target escapes the payload -> passed:false.
        rc, out, err = h.run_cli("poc", "run", "--poc_path", poc_path, "--target", patched)
        res_p = jparse(out)
        r.check("poc_run_patched_fails", bool(res_p) and res_p.get("passed") is False,
                f"patched passed={res_p.get('passed') if res_p else None}")

        # a passing run with findings.dir configured records a finding.
        if res and res.get("recorded_id"):
            r.ok("poc_run_records_finding", f"recorded_id={res['recorded_id']}")
        else:
            r.fail("poc_run_records_finding", "passing poc.run did not record a finding (findings.dir set)")

        # --- poc.build from a captured flow, credential-free --------------- #
        # Capture one real request through the proxy carrying secrets in every spot.
        url = f"{vuln}/search?q={MARKER}&access_token={Q_SECRET}"
        code, http, _ = curl(
            url, proxy=h.proxy_url(), extra=[
                "-X", "POST", "--data", f"password={B_SECRET}",
                "-H", f"Authorization: Bearer {H_SECRET}",
                "-H", f"X-Auth-Token: {X_SECRET}",
            ])
        r.check("capture_request", code == 0, f"proxied request failed exit={code} http={http}")

        op = h.mcp("operator"); op.initialize()
        flows, _, _ = op.call("flow.list")
        ids = flows if isinstance(flows, list) else (flows or {}).get("ids") if isinstance(flows, dict) else None
        r.check("flow_captured", bool(ids), f"no flow captured: {flows!r}")
        built_ok = False
        yaml_text = ""
        if ids:
            fid = ids[-1] if isinstance(ids[-1], str) else ids[-1].get("id") if isinstance(ids[-1], dict) else None
            sc, is_err, text = op.call("poc.build", {"flow_id": fid, "name": "Reflected XSS", "param": "q"})
            # result is a Str (the YAML) in structuredContent or text.
            yaml_text = sc if isinstance(sc, str) else (text or "")
            built_ok = (not is_err) and "steps:" in yaml_text
        r.check("poc_build_ok", built_ok, f"poc.build failed: {yaml_text[:160]!r}")

        leaked = [s for s in (Q_SECRET, B_SECRET, X_SECRET, H_SECRET) if s in yaml_text]
        r.check("poc_build_credential_free", not leaked,
                f"secrets baked into the built PoC: {leaked} -- see crates/aitm-poc/src/builder.rs")
        op.close()

    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
