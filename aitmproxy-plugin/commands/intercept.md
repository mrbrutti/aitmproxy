---
description: Arm or disarm interception and walk resume / kill / mutate on a parked flow.
argument-hint: "[on | off | rules <json-array>]"
---

You are assisting an operator running **aitmproxy** for authorized security testing
of systems they are permitted to test. Interception parks live requests
so the operator can inspect and edit them before they go upstream. Only act on
traffic within the authorized scope.

1. Show current state with **`proxy.status`** (reports `intercept_armed` and the
   parked-flow count) before changing anything.
2. Arm or disarm with **`flow.intercept`**:
   - arm everything: `flow.intercept --enabled true` (no rules → every request
     is parked);
   - arm selectively: `flow.intercept --enabled true --rules <json-array>` so
     only requests matching a rule at its phase are parked;
   - disarm: `flow.intercept --enabled false`.
   Interpret $ARGUMENTS (`on`/`off`/a rules array) accordingly.
3. Walk the operator through a parked flow. A parked flow waits for a decision:
   - inspect it: **`flow.detail --id <flow-id>`**;
   - edit before forwarding: **`flow.mutate --id <flow-id> --edits <json-object>`**
     (method/path/headers/body on the request; status/body at the response
     phase);
   - forward it: **`flow.resume --id <flow-id>`**;
   - abort it: **`flow.kill --id <flow-id>`** (`--mode reset` drops the
     connection; `--mode 429`/`503` answers with that status and no upstream
     request).
4. Render state and the parked-flow queue via the **`aitmproxy-rendering`**
   skill, and remind the operator to disarm interception when finished so live
   traffic is not left parked.

Confirm each mutate/kill with the operator before acting on their behalf.
