---
name: aitmproxy-agent
description: Use when driving aitmproxy over its MCP bus to find, reproduce, and report web vulnerabilities on an authorized, in-scope target. Establishes the observe -> reason -> act -> reproduce -> record -> report loop and the reproduction bar.
---

# Driving aitmproxy

You operate **aitmproxy** entirely through its MCP tool list. The complete,
harness-neutral methodology lives in the portable playbook — read it in full
before you act:

**`${CLAUDE_PLUGIN_ROOT}/../PLAYBOOK.md`**

Everything in this plugin is a thin shell over that file. The per-phase skills
(`aitmproxy-observe`, `aitmproxy-reason`, `aitmproxy-act`, `aitmproxy-reproduce`,
`aitmproxy-report`) each load the matching section; this skill is the entry point.

## The one rule that defines success

A vulnerability is **found** only when `poc.run` returns `passed: true` on the
target and — where a control exists — `passed: false` on the patched control, and
you then call `findings.record`. Nothing else counts as a finding. Prove, do not
exploit: a passing PoC is the terminal action for a candidate.

## The loop

1. **Scope and arm** — `agent.status`, `scope.list`, `proxy.status`, `ca.status`.
2. **Observe** — crawl with `browser.*`, `flow.subscribe`, read `flow.detail`.
3. **Reason** — enumerate candidates from observation only (never an answer key).
4. **Act** — test with `flow.replay` / `flow.mutate` + `flow.resume` /
   `request.send` / `browser.*`; judge from evidence.
5. **Reproduce** — `poc.build` then `poc.run` (target passes, control fails).
6. **Record and report** — `findings.record`, then render `report.md` +
   `findings.index.json` from `findings.list` / `findings.get`.

## Guardrails

- Stay in scope; you cannot widen it yourself. Respect the bus policy
  (`agent.status`); `agent.set` is the operator's, not yours.
- Never print or log the agent token.
- Read the exact input schema for any command from the harness's `tools/list`;
  mind the wire shapes the playbook calls out (`browser.eval` takes `expr`;
  `browser.type` requires a `selector`; `poc.build` returns YAML text).
