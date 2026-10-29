---
name: aitmproxy-report
description: Use when recording reproduced aitmproxy findings and rendering the human-friendly report. Covers findings.record and the report.md plus findings.index.json contract.
---

# Record and report

Load the **Record and report** and **report contract** sections of
`${CLAUDE_PLUGIN_ROOT}/../PLAYBOOK.md`.

- `findings.record` — persist each **reproduced** finding, referencing its PoC and
  artifacts and carrying the reproduction outcome (`passed`, `control_passed`).
  This is a separate, audited act; `poc.run` persists nothing on its own.
- Gather artifacts by reference: `poc.get`, `poc.artifact`.
- Read findings back with `findings.list` / `findings.get` and render **both**
  deliverables from them:
  - `report.md` — human-readable markdown, one section per finding (title,
    severity, class/CWE, endpoint, reproduction steps, PoC path, screenshot,
    finding-capture flow id). You write the prose; the tool writes no prose.
  - `findings.index.json` — a machine-readable array for the grader: one object
    per finding with `poc_path`, `target_path`, `class`, `passed`,
    `control_passed`, `finding_capture`, `screenshot_path`.

The report is a rendering of the recorded findings, not a separate source of truth.
