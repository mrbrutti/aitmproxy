# Aitmproxy design system

Which token to use when. The parts themselves, with sizes and states, are in
`KIT.md`. Raw values live in `docs/design/tokens.json`; everything in a view
comes through one of the four files below.

## `UI/Tokens.swift` (generated from tokens.json; never edit)

- `Tok.Ground.*` for every fill: `surface` panels and the sidebar, `page`
  behind panels, `raised` chips / wells / status bar / count chips, `active`
  the selected row or sidebar item (never the accent), `hover` row hover
  (never moves selection), `inverse` the primary button only.
- `Tok.Line.*` for every edge: `border` panel edges, splitters, the rule under
  tab bars; `rule` row separators; `control` outlined buttons and inputs;
  `focus` the 2 px ring.
- `Tok.Ink.*` for every text colour: `primary` identity (hosts, values,
  titles), `secondary` labels / column headers / times / icons, `tertiary`
  placeholders, meta, section labels, dimmed out-of-scope rows; `link` the
  URL path; `onAccent` / `onInverse` on those fills. Never `.primary`,
  `.secondary`, fixed greys or white.
- `Tok.Accent.*` is the brand blue as data; views reach the accent only
  through `Palette.accent` / `Palette.accentText` (below) so the Mac's accent
  wins. `Tok.Intercept.*`, `Tok.Agent.*` are the two state hues and are never
  reused for anything else. `Tok.Method`, `Tok.Status`, `Tok.Severity`,
  `Tok.Syntax` colour data only, through the mappings in `TokenMapping.swift`.
- `Tok.Typography.Size.*` (11 / 12 / 13 / 14 / 16 / 20) and `Weight.*` with
  `Tok.Face` (below); `Tok.Space` and `Space` are the same 4 pt steps.
- `Tok.Size.*` for fixed shell dimensions (toolbar 44, chip bar 36, header 28,
  row 28 dense, strip 40, tab bar 36, intercept bar 40, status bar 28, control
  28, badge 18, dot 8, icon 16 / 12 / 18, sidebar 240).
- `Tok.Radius.*`: badge 4, control 6, panel 8, floating 10, `pill` (Capsule)
  only for the listening pill, chips and count chips.
- `Tok.Motion.*`: `press` 120 ms scale 0.97, `hover` 100 ms, `popover` 160,
  `sheet` 220, `rowArrive` 0, `interceptPulse` 1200 (stops under Reduce
  Motion); curves `Tok.Motion.easeOut(_:)` / `easeInOut(_:)`. Nothing enters
  with an animation; keyboard-initiated changes never animate.
- `Tok.Glyph.*` is the only place an SF Symbol name belongs. Flat, monochrome,
  regular weight, `Tok.Ink.secondary`; 16 in bars, 12 inline; never in a
  capsule, disc or glass. A new icon is added to tokens.json first.

## `UI/TokenMapping.swift`

- Domain → token: `HTTPMethod.badge`, `StatusClass.color` / `.pill`,
  `FlowRow.dotColor` / `.statusColor` / `.leftEdge`, `SyntaxKind.color`,
  `MarkColor.color`. A cell or view asks the value for its colour and never
  switches on the domain itself.
- `Tok.Face.ui(size, weight)` for chrome (labels, titles, tabs, buttons) and
  `Tok.Face.data(size, weight)` for every URL, header, body, time, size, id,
  method and status. AppKit cells use `nsUI` / `nsData`. No `.font(.system(`
  in a view, except the two size-less glyph fonts noted in `KIT.md`.
- `Tok.Metric.*` for the dense numbers between the 4 pt steps: chip 22, bar
  button 26, small button 20, count chip 18, switch 26 × 16 / knob 12,
  padInner 10, gapTight 6, gapMeta 14, chipSeparator 14. Add here, never a
  literal in a view.

## `UI/Theme.swift`

- `Palette.accent` the one accent (active tab underline, product mark, focus),
  `Palette.accentText` accent-coloured text, `Palette.onAccent` text on an
  accent fill. `ThemeStore.defaultID` stays `system`: the brand blue shows only
  while the Mac's accent is Multicolor. Budget about 3 % of pixels; never on
  selection, never on data.
- `Color(light:dark:)` / `NSColor.dynamic` are for token files only.

## `UI/Grid.swift`

- `Space.xs 4 · sm 8 · md 12 · lg 16 · xl 20 · xxl 24 · section 32 · margin
  20` for every padding and spacing. Literal 0, 1, 2 are fine; anything else
  is a token or `// grid: ok <why>`, and that comment is only for drawn
  geometry (glyph paths, the 44 gutter, the 20 pt code line).
- `.gridArea` / `.gridProbe` on custom pages and cards; `tools/grid-lint.sh`
  and `tools/check-layout.swift` must print PASS.

## Rules

- Never a hex, `Color(red:)`, system grey or `.white` in a view; never a
  semantic system colour re-purposed (`.separator` as text).
- Hue only on data (method, status, intercept, agent, syntax, marks). Chrome
  is ink on surface; the armed-intercept bar is the one saturated fill.
- Selection is `Ground.active`; hover is `Ground.hover` and never selects.
- Controls are real `Button`s with `PressStyle` or `.plain`; a shape with a
  tap gesture is not a control.
- One primary (inverse) button per bar or sheet, its shortcut printed on it.
- Editorial restraint: typography carries the hierarchy, whitespace comes from
  `Space`, section labels are tracked small caps in `Ink.tertiary`, empty
  states keep the frame and say the trade's words. The flow list stays dense:
  28 pt rows, mono data, no zebra, 1 px `rule` separators.
