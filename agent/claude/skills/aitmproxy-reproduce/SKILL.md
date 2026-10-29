---
name: aitmproxy-reproduce
description: Use when turning a confirmed anomaly into a reproduced aitmproxy finding — building and running a PoC against the target and the patched control. Defines the reproduction bar.
---

# Reproduce — the finding bar

Load the **Reproduce** section of `${CLAUDE_PLUGIN_ROOT}/../PLAYBOOK.md`. A finding
is reproduced — and only then — when **all** of these hold:

1. `poc.build` produces a PoC. It returns the **PoC YAML as text**; read it back
   and confirm it captures the trigger and a concrete assertion. Keep it
   human-readable.
2. `poc.run` against the target returns `passed: true` and emits its three
   artifacts (finding-capture flow, PoC YAML, screenshot).
3. Where a control exists, `poc.run` against the patched/control path returns
   `passed: false`. A PoC that passes on both proves nothing — drop it as a false
   positive.

`poc.run` is the terminal action for the candidate. Do not escalate further; move
to recording.
