# Glossary

One name per thing, everywhere: buttons, menus, tooltips, errors, stories.

| Term | Means | Not |
| --- | --- | --- |
| Flow | One captured exchange: a request and its response, or a WebSocket connection | request, entry, transaction, row (the row *shows* a flow) |
| Capture | The proxy recording flows; it can be paused and resumed | recording, logging |
| Clear | Drop every flow from the session | reset, delete all |
| Intercept | Parking every new request until the operator acts; armed or disarmed | breakpoint (that is a *rule*), hold |
| Arm / Disarm | Turn intercept on / off (`i`) | enable, start |
| Paused | A flow parked by intercept, waiting for Resume or Kill | held, intercepted (in UI text), blocked |
| Resume | Let a paused flow continue (⌘⏎) | release, continue, forward |
| Apply & Resume | Send the pending edits, then resume | save, submit |
| Kill | Abort a flow; the client sees a reset (⌘\) | drop, abort, cancel |
| Edit | Change a paused request's line, headers or body before it continues | mutate (the bus verb), modify |
| Revert to Original | Discard every edit on a paused request | undo all, reset |
| Rule | A breakpoint rule: which requests pause (URL, method, phase) | filter, breakpoint |
| Replay | Send a captured flow again, unchanged (`r`); the result is a new flow marked ↻ | repeat, resend |
| Edit & Replay | Open a flow in Compose, prefilled | duplicate |
| Compose | Write and send a new request (`n`, ⌘N) | new request, craft |
| Scope | The hosts the operator has authorised; everything else is read-only | allowlist, targets |
| In scope / Out of scope | A flow's host is / is not in Scope; out-of-scope rows are dimmed and their actions disabled | allowed, blocked |
| PoC | A YAML proof-of-concept the proxy can run against a target | exploit, test case, script |
| Finding | One PoC run and its result: passed or failed, capture, screenshot, assertions | result, vulnerability |
| Build PoC | Create a PoC from a flow (`p`) | generate, export PoC |
| Agent | The AI acting over MCP; its policy is Allow All Tools, Read-only or Paused | bot, assistant, AI, MCP client |
| Activity | The log of every command any frontend ran; agent entries in teal | audit, history, events |
| Approve | Allow one gated request from the agent, once | accept, grant |
| Browser | The embedded obscura browser with tabs | webview, obscura (in UI text) |
| Script | A Rhai plugin the proxy runs; on or off | plugin, hook |
| Mark | A colour swatch on a flow (`m`); 11 colours | flag, highlight, tag |
| Comment | A note on a flow (`c`, ⌘L), shown in its own column | note, annotation |
| Pin | Keep a host or app under Working (⇧P) | favourite, star, bookmark |
| Working | The sidebar group for Pinned and Saved | session, favourites |
| Saved session | A capture saved to disk and reopened later | project, archive, export |
| Chip | One content-type quick filter in the bar under the toolbar | tag, pill, tab |
| Filter | A stacked set of field · operator · value rows, or its expression form | search, query |
| Saved filter | A named filter | preset, bookmark |
| Palette | The ⌘K command palette | launcher, spotlight, quick open |
| Auto-select | Follow the newest flow as it arrives | follow, tail, live |
| Density | Row pitch: Dense, Default or Comfortable | compact mode, zoom |
| Inspector | The Request \| Response area under the list | detail, preview, viewer |
| Request pane / Response pane | The two halves of the inspector | left/right side |
| Body viewer | A tab that renders a body: Pretty, Tree, Image, Hex, Raw, Diff | previewer, formatter |
| Quick Look | A floating preview of a body (Space on the list; Flow ▸ Quick Look Body) | peek, popup |
| Import | Read flows from a file into the capture (⌘O, or drop on the window); they carry the `imported` origin | load, open |
| Export Selection | Write the selected flows as HAR (⌘E), CSV or a cURL batch | save as, download |
| Resume All | Release every paused flow (⌥⌘⏎) | continue all, release all |
| Revert to Original | Drop the draft edits of a paused request | reset, discard |
| Copy as | Copy a flow as cURL (⇧⌘C), httpie, Python (requests) or fetch | export code, snippet |
| Diff Selected | Compare two selected flows in the Diff tab (⌘D) | compare |
| Add Host to Scope… | Open Scope with the focused row's host typed in (⇧S) | whitelist, allow host |
| Toggle Sidebar | Show or hide the sidebar (⌃⌘S) | collapse |
| Approve Pending Request | Run the oldest gated agent command (⌥⏎) | accept, allow once |
| Bus | The proxy's command bus the app talks to; connected, connecting or offline | server, backend, MCP server (in UI text) |
| Listening | The proxy's client-facing address, shown in the toolbar pill | endpoint, port |
| Column | A flow-list column; reorder, resize, hide from the header's context menu | field |
| Sort | Order the list by a column; `#` ascending is capture order | arrange, group |
| Apps / Domains | Sidebar groups: flows by client process / by host | clients, sources, hosts |
