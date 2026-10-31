#!/usr/bin/env python3
# e2e: tier=T1 surface=findings
"""findings persist, list, get, remove, and REDACT secrets over a real run.

Drives findings.* over the real loopback-TCP MCP bus and asserts on the ON-DISK
findings store (an independent observer) — never the proxy's own view. Proves a
recorded finding persists as <id>.yaml and lists/gets back; secrets in notes AND in
the target URL are redacted on disk (regression guard: crates/aitm-findings/src/
store.rs scrubs target + client_label, not just title/notes); findings.remove is
operator/CLI-only (agent refused) and an operator remove deletes the artifact.
"""
import os
import sys
import tempfile
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

SECRET = "sk-LEAKED-SECRET-abc123xyz"


def main() -> None:
    work = tempfile.mkdtemp(prefix="aitm-e2e-findings-")
    findings_dir = os.path.join(work, "findings")
    cfg = CoreConfig(proxy_port=free_port(), findings_dir=findings_dir)
    with Aitm.server(cfg) as core:
        op = BusClient.operator(core)
        agent = BusClient.agent(core)

        section("findings.* present")
        names = set(op.tool_names())
        check({"findings.record", "findings.list", "findings.get", "findings.remove"} <= names,
              "findings.record/list/get/remove in tools/list")

        section("record persists with on-disk redaction")
        rec = op.call("findings.record", {
            "title": "Reflected XSS in search q",
            "class": "reflected-xss",
            "severity": "high",
            "target": f"http://127.0.0.1:9/api?api_key={SECRET}&q=1",
            "poc_ref": "reflected-xss-search-q",
            "notes": f"repro used Authorization: Bearer {SECRET}",
        })
        fid = rec["id"]
        ok(f"recorded finding id={fid}")
        yaml_path = Path(findings_dir) / f"{fid}.yaml"
        check(yaml_path.exists(), f"finding persisted as {yaml_path.name}")
        disk = yaml_path.read_text()
        check(f"Bearer {SECRET}" not in disk, "notes secret is redacted on disk")
        check(f"api_key={SECRET}" not in disk, "target-URL secret is redacted on disk")
        check(SECRET not in disk, "no plaintext secret anywhere in the stored finding")
        check("[redacted]" in disk, "[redacted] placeholder present")

        section("list + get read back from disk")
        lst = op.call("findings.list")
        ids = {f.get("id") for f in lst} if isinstance(lst, list) else set()
        check(fid in ids, "findings.list returns the finding")
        got = op.call("findings.get", {"id": fid})
        check(isinstance(got, dict) and got.get("id") == fid, "findings.get returns the full record")

        section("remove is operator/CLI-only")
        status, msg = agent.try_call("findings.remove", {"id": fid})
        check(status == "error", f"agent findings.remove is refused ({msg[:70]})")
        check(yaml_path.exists(), "agent remove did not delete the on-disk finding")
        op.call("findings.remove", {"id": fid})
        check(not yaml_path.exists(), "operator remove deleted <id>.yaml")
        lst2 = op.call("findings.list")
        ids2 = {f.get("id") for f in lst2} if isinstance(lst2, list) else set()
        check(fid not in ids2, "removed finding is gone from findings.list")

        ok("findings persist/redact/remove verified on disk")


if __name__ == "__main__":
    main()
