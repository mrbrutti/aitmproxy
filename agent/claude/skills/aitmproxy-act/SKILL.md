---
name: aitmproxy-act
description: Use when testing a candidate vulnerability in aitmproxy with the deterministic primitives (replay, mutate/resume, request.send, browser actions) and judging whether the behavior is anomalous.
---

# Act — bounded, deterministic tests

Load the **Act** section of `${CLAUDE_PLUGIN_ROOT}/../PLAYBOOK.md`. Each primitive
is scope/rate/SSRF-gated by the bus; pick the smallest one that answers the
question.

- `flow.replay` — re-send a captured flow unchanged (baseline / idempotence).
- `flow.intercept` to arm, then `flow.mutate` + `flow.resume` — edit a parked
  flow's method/URL/headers/body and let it continue; `flow.kill` drops it.
- `request.send` — compose a fresh request (headers map + body) to sweep payloads.
- `browser.*` — trigger page-rendered effects (DOM XSS, client redirect), then
  read with `browser.get_dom` / `browser.eval` / `browser.screenshot`.

Judge from evidence: diff the mutated response (`flow.detail`) or DOM against the
baseline. One proving byte — your marker reflected unescaped, another object
returned, the redirect followed off-origin — is the anomaly you escalate to the
reproduction phase. Do not push past proof.
