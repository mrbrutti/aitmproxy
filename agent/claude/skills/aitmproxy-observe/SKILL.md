---
name: aitmproxy-observe
description: Use when crawling an in-scope target with aitmproxy to build a working set of flows before enumerating candidates. Covers browsing, subscribing to the push channel, and reading flow detail.
---

# Observe

Load the **Observe** section of `${CLAUDE_PLUGIN_ROOT}/../PLAYBOOK.md`. All passive
— no gating applies to observation.

- Open the push channel with `flow.subscribe` (and `flow.unsubscribe` when done).
- Crawl with a real browser: `browser.navigate`, `browser.click` (`x`/`y` **or** a
  `selector`), `browser.type` (**requires** a `selector`; use `":focus"` for the
  focused element). Read with `browser.get_dom`, `browser.eval` (takes `expr`),
  `browser.screenshot`.
- Survey flows with `flow.list` / `flow.get`; pull full request/response with
  `flow.detail` (page large bodies via `body: range` + `offset`/`length`).
- Mark your working set: `flow.mark` plus `flow.comment` to record why, so the
  operator sees your reasoning.

Build coverage, not conclusions, here. Candidate selection is the next phase.
