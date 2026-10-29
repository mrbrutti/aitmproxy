# M4 live-agent acceptance (AC-M4-17) — operator-run procedure

**What this proves:** the M4 product thesis — a live AI agent, unaided, drives aitmproxy
over the MCP bus against a real seeded-vulnerable target through a real browser and
finds → reproduces → reports vulnerabilities. This is a signed-off, operator-run demo
gate (it needs a live model), distinct from the deterministic CI gate (AC-M4-16, the
scripted driver + grader, which runs in `cargo test`).

**Reference harness:** Claude (via `agent/claude`). The design is harness-neutral — the
same run works under `agent/openai` (Codex) or `agent/generic`; AC-M4-16b already proves
neutrality deterministically with a non-LLM client. Running a second harness live is
optional (see the M4 spec open question).

## Prerequisites
- A build of `aitm` from `feat/aitmproxy-m4` (or `main` after merge).
- A browser engine available: the embedded obscura engine (default), or external
  Chrome/Firefox. The agent drives through a real browser on aitmproxy's **custom**
  proxy — never the OS proxy.
- The hermetic `aitm-testtarget` (seeded, multi-vuln). Its planted-vuln **manifest is
  grader-only** and must never be given to the agent.

## Procedure
1. **Start the target (vulnerable mode)** on loopback. Note its base URL. Do NOT expose
   or share its manifest.
2. **Start `aitm`** with:
   - the target host added to **scope** (`scope.add`) — the only authorization the agent
     gets; it cannot widen scope (`scope.allow_agent_widen` stays off),
   - MCP loopback-TCP transport with the **agent** token,
   - agent policy set to an autonomous mode: **`Auto`** (recommended default — the agent
     runs the whole testing loop but can take no Sensitive action) or **`All`**.
3. **Attach the live agent** using `agent/claude` (its `.mcp.json` points at the agent
   token; it loads `agent/PLAYBOOK.md`). Give it only: the target base URL and the task
   ("find and reproduce vulnerabilities; report"). **Do not reveal the vuln set.**
4. **Let it run unaided.** It will browse/observe (`flow.subscribe`, `flow.detail`),
   enumerate candidates, test (`flow.replay`/`mutate`/`request.send`/`browser.*`),
   reproduce (`poc.build` + `poc.run` — pass on vulnerable, fail on patched control),
   `findings.record`, and render `report.md` + `findings.index.json`. Every action is in
   the F2 activity log / `notifications/aitm/agent` stream, so the run is fully auditable.
5. **Grade the result.** Run the grader (`grade(...)`) over the agent's recorded findings.

## Pass criterion (adopted default; Matt may adjust)
- Found-and-reproduced **≥ all-but-one** of the enumerated planted vulns, with **zero
  false-positive findings**, and a produced report. (The deterministic gate AC-M4-16
  requires *all* with zero false positives from the scripted driver; the live bar is a
  notch lower for model variance.)
- No action beyond proof-of-reproduction (no exploitation past the marker that proves the
  bug) — verify from the activity log.

## Recording
The operator records the run outcome (grader report + a link to the agent transcript /
activity log) in the M4 plan's Shipped section. This gate is signed off by Matt, not CI.
