#!/usr/bin/env python3
"""T1: findings persist, list, get, remove, and REDACT secrets over a real run.

Boots a real aitm, drives findings.* over the real loopback-TCP MCP bus, and asserts
on the ON-DISK findings store (independent observer) -- never the proxy's own view.
Proves:
  * a recorded finding persists as <id>.yaml and lists/gets back;
  * secrets in `notes`/`title` are redacted on disk;
  * secrets in the `target` URL are redacted on disk (regression: historically NOT
    scrubbed -- see crates/aitm-findings/src/store.rs);
  * findings.remove is operator/CLI-only (agent refused), and an operator remove
    deletes the on-disk artifact.

Exit: non-zero iff any required cell FAILs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from harness import Harness, Reporter  # noqa: E402

SECRET = "sk-LEAKED-SECRET-abc123xyz"


def main() -> int:
    r = Reporter("t1_findings_persist_redact")
    with Harness("findings") as h:
        h.start_aitm()
        op = h.mcp("operator")
        op.initialize()
        agent = h.mcp("agent")
        agent.initialize()

        tools = op.tools()
        r.check("tools_present",
                {"findings.record", "findings.list", "findings.get", "findings.remove"} <= tools,
                f"have={sorted(t for t in tools if t.startswith('findings.'))}")

        # --- record a finding carrying secrets in notes AND target ---------- #
        sc, is_err, text = op.call("findings.record", {
            "title": "Reflected XSS in search q",
            "class": "reflected-xss",
            "severity": "high",
            "target": f"http://127.0.0.1:19090/api?api_key={SECRET}&q=1",
            "poc_ref": "reflected-xss-search-q",
            "notes": f"repro used Authorization: Bearer {SECRET}",
        })
        if is_err or not sc or "id" not in sc:
            r.fail("record", f"record failed: isError={is_err} text={text!r}")
            return r.finish()
        fid = sc["id"]
        r.ok("record", f"id={fid}")

        yaml_path = h.findings_dir / f"{fid}.yaml"
        r.check("persist_on_disk", yaml_path.exists(), f"expected {yaml_path}")
        disk = yaml_path.read_text() if yaml_path.exists() else ""

        # list + get come back from disk
        lst, _, _ = op.call("findings.list")
        ids = {f.get("id") for f in (lst or [])} if isinstance(lst, list) else set()
        r.check("list_returns_it", fid in ids, f"ids={ids}")
        got, got_err, _ = op.call("findings.get", {"id": fid})
        r.check("get_returns_it", (not got_err) and bool(got) and got.get("id") == fid)

        # --- redaction assertions on the ON-DISK artifact ------------------- #
        # notes carried "Authorization: Bearer <secret>" -> must be scrubbed.
        r.check("redact_notes", f"Bearer {SECRET}" not in disk,
                "secret leaked through the notes field on disk")
        # target carried "?api_key=<secret>" -> must be scrubbed too (regression:
        # store.rs historically scrubbed only title/notes, not target).
        r.check("redact_target", f"api_key={SECRET}" not in disk,
                "plaintext secret persisted in the target URL on disk -- "
                "see crates/aitm-findings/src/store.rs record()")
        # The whole point: no plaintext secret anywhere on disk.
        r.check("no_plaintext_secret", SECRET not in disk,
                "plaintext secret persisted somewhere in the stored finding")
        r.check("redaction_placeholder_present", "[redacted]" in disk,
                "expected [redacted] placeholder in the stored finding")

        # --- findings.remove is operator/CLI-only --------------------------- #
        _, rm_agent_err, rm_text = agent.call("findings.remove", {"id": fid})
        r.check("remove_agent_refused", rm_agent_err,
                f"agent remove should be refused, got isError={rm_agent_err} {rm_text!r}")
        r.check("remove_agent_no_effect", yaml_path.exists(),
                "agent remove must not delete the on-disk finding")

        _, rm_op_err, _ = op.call("findings.remove", {"id": fid})
        r.check("remove_operator", not rm_op_err, "operator remove should succeed")
        r.check("remove_deletes_on_disk", not yaml_path.exists(),
                "operator remove must delete <id>.yaml")
        lst2, _, _ = op.call("findings.list")
        ids2 = {f.get("id") for f in (lst2 or [])} if isinstance(lst2, list) else set()
        r.check("remove_gone_from_list", fid not in ids2)

        op.close()
        agent.close()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
