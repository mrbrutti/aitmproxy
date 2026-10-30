---
description: List recorded findings, or show one in full, rendered as a table.
argument-hint: "[finding-id] (omit to list all)"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. This command reads the recorded
findings store; it does not create or delete findings.

1. If $ARGUMENTS contains a finding id, call **`findings.get --id <id>`** and
   present the full record: title, class, severity, target, when, reproduction,
   linked flows, artifacts, and notes.
2. Otherwise call **`findings.list`** (optionally `--filter <json-object>` by
   target/class/severity/since if the user asked to filter) and present the
   recorded findings.
3. Render using the **`aitmproxy-rendering`** skill:
   - the list as a table with columns: id, severity, class, title, target, when
     (`discovered_at`);
   - a single finding as a labelled detail block, with the reproduction steps
     quoted.
4. If the store is empty, say so — that means no findings directory is
   configured or none have been recorded yet.

Report findings faithfully from the store; do not embellish severity.
