---
name: aitmproxy-findings-poc
description: Build reproducible PoCs and record findings in aitmproxy during an AUTHORIZED security test. Use when the user has confirmed a vulnerability in captured/manipulated traffic and wants to turn it into a parameterized YAML PoC, run it with no agent to produce artifacts, and record a human-readable finding. Covers poc.build, poc.run, poc.list/get/artifact, findings.record/list/get, and the operator gate on agent-run PoCs.
---

# aitmproxy findings & PoC

Turn a confirmed issue on your **authorized** engagement into a reproducible PoC
and a recorded finding. A PoC runs deterministically with **no agent** so a
reviewer can re-run it; findings are human-readable YAML records.

## Build a PoC

- **`poc.build --flow_id <flow-id> [--name] [--param <string>]`** builds a
  parameterized, reproducible PoC (YAML) from a captured flow. Start from the flow
  that demonstrates the issue (find it via **aitmproxy-flows-triage**); use
  `--param` to lift the exploited value into a variable so the PoC is re-runnable
  against variants.

## Run a PoC

- **`poc.run --poc_path <path> [--target] [--vars <json-object>]`** runs the PoC
  with no agent and emits the three artifacts. Supply `--target` to point it at the
  authorized host and `--vars` to fill parameters. This is **active egress and
  scope-gated** — the target must be in `scope.list`.

### The agent-run-PoC gate

Running a PoC sends real exploit traffic, so an agent frontend (MCP) may run
`poc.run` **only if the operator opted in** with `poc.allow_agent_run: true` under
`poc:` in `config.yaml` (off by default). Otherwise the call is refused with a
message naming that key, and the operator runs the PoC from the web UI, TUI, macOS
app or the one-shot CLI instead. `poc.run` is a Write-tier command, so the agent
policy (`agent.status`) also applies: under `readonly` or `paused` it does not run
at all. Do not try to bypass the gate — confirm the operator wants the PoC executed
and that the target is in authorized scope.

## Inspect PoCs and artifacts

- **`poc.list`** — the PoCs in the configured PoC directory (id, title, severity,
  path). Empty when no PoC directory is configured.
- **`poc.get --poc_path`** — one PoC's id, title, severity, description and YAML.
- **`poc.artifact --path`** — read a run artifact (YAML copy or screenshot) as
  bytes, confined to the configured output directory.

## Record a finding

After a **passing** `poc.run`:

- **`findings.record --title --class --severity --target --poc_ref [--flows] [--notes] [--passed] [--control_passed] [--run_at] [--finding_capture] [--poc_path] [--screenshot_path]`**
  writes a human-readable YAML record plus a `runs.jsonl` line and returns the
  finding id. Set `severity` to one of critical/high/medium/low/info and link the
  evidence (`--flows`, `--poc_path`, `--screenshot_path`).
- **`findings.list [--filter]`** — recorded findings (id, title, class, severity,
  target, when, reproduction), filterable by target/class/severity/since.
- **`findings.get --id`** — the full record (reproduction, artifacts, flows, notes).
- **`findings.remove --id`** — delete a finding's YAML (operator/CLI only; the
  runs.jsonl history is kept).

## End-to-end

Triage → confirm (optionally manipulate via **aitmproxy-intercept-mutate**) →
`poc.build` → `poc.run` (within authorized scope, past the operator gate) →
`findings.record`. Report only what you demonstrated, against targets you are
authorized to test. Render results with **aitmproxy-rendering** in text hosts.
