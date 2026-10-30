# MCP widget bundles

Source for the rich MCP Apps widgets served by `aitm-mcp` over `resources/*`.
Each `<widget>.html` is a complete, CSP-clean HTML5 document (inlined `<style>`
and `<script type="module">`, no external assets) and is `include_str!`-ed into
`src/widgets.rs`.

## Palette: `tokens.css`

`tokens.css` is **generated** from the single source of truth,
`docs/design/tokens.json`, and is **committed** so the Rust build never needs
Node. Each widget pastes the `:root` / dark blocks it needs into its own inlined
`<style>`; widgets reference colours only through these CSS custom properties and
never a literal hex.

It defines, per palette group (`method`, `status`, `severity`, `mark`,
`intercept`, `agent`, `accent`, `l4`, `syntax`, plus `ground`/`line`/`text`):

- `:root { … }` — the light values, plus the font families (`--font-ui`,
  `--font-data`) and weights (`--font-weight-*`).
- `[data-theme="dark"] { … }` — the dark values when a theme is pinned.
- `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { … } }`
  — the dark values as the host default.

Colour fg/bg pairs become `--color-<group>-<name>-fg` / `-bg`
(e.g. `--color-method-get-fg`, `--color-severity-high-bg`); single colours become
`--color-<group>-<name>` (e.g. `--color-status-success`, `--color-accent-base`).

## Regenerate

Node stdlib only — no `npm install`, no network:

```bash
node crates/aitm-mcp/widgets/build.mjs
```

This rewrites `crates/aitm-mcp/widgets/tokens.css` in place. The output is
deterministic: re-running reproduces the committed file byte-for-byte. Commit the
result whenever `docs/design/tokens.json` changes.
