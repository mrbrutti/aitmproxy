# aitmproxy MCP Apps widget convention (shared house style)

Every widget under `crates/aitm-mcp/widgets/*.html` is built to THIS convention so
the seven widgets read as one system in ChatGPT and Claude. Read it in full before
authoring your widget. The widget is served as `text/html;profile=mcp-app`
(inlined, self-contained) and rendered inside a sandboxed iframe.

## Hard rules (enforced by widget-lint, AC14)
- **Self-contained.** One `<!DOCTYPE html>` document with everything inlined: no
  external `<script src>`, `<link href>`, `@import`, remote fonts, or network calls
  (the CSP forbids them).
- **No** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`,
  `new Function`, or inline `on*=` attributes. Build the DOM with
  `document.createElement` + `textContent` + `append`; attach handlers with
  `addEventListener`.
- **No literal hex colours** anywhere except inside the one generated token block
  (see below). All colour comes from `var(--color-…)`.

## Document skeleton
```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
/* tokens (generated — do not edit; copied verbatim from crates/aitm-mcp/widgets/tokens.css) */
:root { … }  /* paste the FULL current contents of tokens.css here */
/* /tokens */

/* component styles below use ONLY var(--…) — no hex */
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font-family:var(--font-ui);background:var(--color-ground-page);color:var(--color-text-primary);font-size:var(--font-size-sm,14px)}
main{padding:var(--space-4,16px)}
/* …shared component classes (table, badges, card, empty, mono) exactly as in §Components… */
</style>
</head>
<body>
<main id="app"></main>
<script>
// ——— shared runtime (identical in every widget) ———
const openai = window.openai || {};
function toolOutput(){ return (openai && openai.toolOutput) || {}; }
function applyTheme(){
  const t = (openai && openai.theme) ||
    (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.dataset.theme = (t === 'dark') ? 'dark' : 'light';
}
function el(tag, attrs, ...kids){
  const n = document.createElement(tag);
  if (attrs) for (const k in attrs){ if (k === 'class') n.className = attrs[k]; else if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]); }
  for (const kid of kids) if (kid != null) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return n;
}
function badge(cls, label){ return el('span', { class: 'badge ' + cls, text: label }); }
function empty(msg){ return el('div', { class: 'empty', text: msg }); }
applyTheme();
if (window.matchMedia) matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', applyTheme);
// re-apply on host theme change if the host exposes an event
window.addEventListener?.('openai:set_globals', applyTheme);
// ——— widget render (unique per widget) ———
function render(){
  const app = document.getElementById('app');
  app.replaceChildren();
  const data = toolOutput();
  // …build nodes from `data` using el()/badge()/table()… call empty() when no rows…
}
render();
window.addEventListener?.('openai:set_globals', render);
</script>
</body>
</html>
```

## Components (define these classes identically in every widget)
- **Card:** `.card{background:var(--color-ground-surface);border:1px solid var(--color-line-border);border-radius:var(--radius-md,8px)}`
- **Table:** `.tbl{width:100%;border-collapse:collapse;font-size:var(--font-size-sm,14px)}`
  `.tbl th{text-align:left;padding:var(--space-2,8px) var(--space-3,12px);color:var(--color-text-tertiary);font-weight:var(--font-weight-medium,500);text-transform:uppercase;letter-spacing:.04em;font-size:var(--font-size-xs,12px)}`
  `.tbl td{padding:var(--space-2,8px) var(--space-3,12px);border-top:1px solid var(--color-line-rule)}`
  `.tbl tbody tr:hover{background:var(--color-ground-hover)}`
- **Mono / URLs / code:** `.mono{font-family:var(--font-data)}` link colour `var(--color-text-link)`.
- **Badge base:** `.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:var(--radius-full,999px);font-size:var(--font-size-xs,12px);font-weight:var(--font-weight-medium,500);line-height:1.5}`
- **Method badges** (HTTP method → class): `.m-get{background:var(--color-method-get-bg);color:var(--color-method-get-fg)}` and likewise `m-post`, `m-put`, `m-patch`, `m-delete`, `m-head`, `m-options`, `m-connect`, `m-ws` (→ `--color-method-ws-*`). Lowercase the method to pick the class; unknown → `m-get` fallback styling via `--color-ground-raised`/`--color-text-secondary`.
- **Status badges** (HTTP status → class by class-of-status): 1xx `--color-status-informational`, 2xx `--color-status-success`, 3xx `--color-status-redirect`, 4xx `--color-status-client-error`, 5xx `--color-status-server-error`; pending `--color-status-pending`, killed `--color-status-killed`. Render as coloured text (foreground only is fine) e.g. `.st-2xx{color:var(--color-status-success)}`.
- **Severity badges** (critical/high/medium/low/info): `.sev-high{background:var(--color-severity-high-bg);color:var(--color-severity-high-fg)}` etc.
- **Empty state:** `.empty{padding:var(--space-6,24px);text-align:center;color:var(--color-text-tertiary)}`.
- **Header:** a small title row: widget title in `--color-text-primary`, a count/summary in `--color-text-secondary`.

## Theme
`tokens.css` already emits light values under `:root`, dark under
`[data-theme="dark"]` AND `@media (prefers-color-scheme: dark)`. The runtime sets
`document.documentElement.dataset.theme` from `window.openai.theme` (host) or the
media query, so both ChatGPT (host theme) and Claude (prefers-color-scheme) track.

## The seven widgets — tool, resource URI, and data shape
For each, read the named source file to confirm the EXACT `structuredContent`
field names before coding; do not invent fields.

| Widget file | `ui://` URI | Tool | structuredContent (read source) |
|---|---|---|---|
| `flows.html` | `ui://aitm/flows` | `flow.table` | `{flows:[{id,kind,method?,authority?,path?,status?,duration_ms?,state,marks}]}` — see `crates/aitm-plugins/src/capture.rs` |
| `flow-detail.html` | `ui://aitm/flow-detail` | `flow.detail` | headers/bodies/timing/edit-state — read `crates/aitm-plugins/src/detail.rs` |
| `findings.html` | `ui://aitm/findings` | `findings.list` | top-level array of findings — read `crates/aitm-findings/src/commands.rs` |
| `finding-detail.html` | `ui://aitm/finding-detail` | `findings.get` | one finding record — `crates/aitm-findings/src/commands.rs` |
| `scope.html` | `ui://aitm/scope` | `scope.list` (+ `tls.passthrough.list`) | array of entries — `crates/aitm-plugins/src/scope.rs` |
| `poc-result.html` | `ui://aitm/poc-result` | `poc.run` | run result/artifacts — grep `"poc.run"` for the impl |
| `proxy-status.html` | `ui://aitm/proxy-status` | `proxy.status` | `{listening,address,intercept_armed,paused,capturing,flows}` — `crates/aitm-plugins/src/control.rs` |

`findings.html` and `scope.html` MUST accept BOTH a top-level array and an
object-wrapped shape (`{findings:[…]}` / `{entries:[…]}`), so the MV3 fallback
needs no rework: `const rows = Array.isArray(data) ? data : (data.findings||data.entries||data.flows||[]);`

## Framing
These widgets visualise an AUTHORIZED-security-testing proxy's own captured data
for the operator. No user-facing text should encourage unauthorized use.
