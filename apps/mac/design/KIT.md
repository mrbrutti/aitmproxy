# Aitmproxy design kit

The parts of the native macOS operator app, with their sizes and states, as
built. Agents build from this page and review against it. Which token to
use when is in `DESIGN-SYSTEM.md`; the values are in
`docs/design/tokens.json` (generated into `UI/Tokens.swift`, never edited by
hand). The gallery `DesignKit/KitGallery.swift` shows every part below in
every state it can take; `APP_KIT_GALLERY=1` with the snapshot command
captures it light and dark.

## Feel

Three words: **calm, precise, in control**. Like Proxyman's density with the
WebUI's semantics, set in an editorial register.

Two rules from the owner (2026-10-27) override the foundation
(`docs/design/operator-ui-foundation.md` §2) wherever they conflict:

1. **Flat minimal icons.** Monochrome SF Symbols, regular weight, in
   `Ink.secondary`. No glass capsules, no chrome, no bevels, no tinted
   discs, anywhere: toolbar, sidebar, chips, inline. The toolbar items hide
   their shared background (`.sharedBackgroundVisibility(.hidden)`).
2. **Editorial restraint.** Typography carries the hierarchy; whitespace
   comes from `Space`; hue appears only on data (method, status, intercept,
   agent, syntax, marks); chrome and empty states stay calm. The flow list
   stays dense: 28 pt rows.

## Tokens

### Palette (tokens.json hex, light / dark)

Only `UI/Tokens.swift` holds hex. Views never read a hex or a `Color(hex:)`.

| Group | Names | Light | Dark |
| --- | --- | --- | --- |
| ground | page · surface · raised · active · hover · inverse | F7F8FA · FFFFFF · F3F4F6 · E8EEFB · F3F4F6 · 1D1F20 | 161618 · 1E1E20 · 262628 · 2B3344 · 232325 · F5F5F7 |
| line | border · rule · control · focus | E5E7EB · F0F1F3 · D1D5DB · 2563EB | 2E2E31 · 252527 · 45454A · 60A5FA |
| text | primary · secondary · tertiary · link · onAccent · onInverse | 111827 · 4B5563 · 616A78 · 1D4ED8 · FFFFFF · FFFFFF | E6E6E8 · B4B4B8 · 8E8E93 · 7DB2F8 · 0B1220 · 111111 |
| accent | base · deep · tint | 2563EB · 1D4ED8 · DBEAFE | 60A5FA · 3B82F6 · 1E2A44 |
| intercept | base · deep · tint · onBase | D97706 · B45309 · FEF3C7 · 1F1300 | F5A524 · FBBF24 · 3A2E12 · 1F1300 |
| agent | base · deep · tint | 0D9488 · 0F766E · CCFBF1 | 2DD4BF · 5EEAD4 · 113A36 |
| method (fg on bg) | get · post · put · patch · delete · head/options/connect · ws | 1D4ED8/DBEAFE · 15803D/DCFCE7 · B45309/FEF3C7 · C2410C/FFEDD5 · B91C1C/FEE2E2 · 4B5563/F3F4F6 · 6D28D9/EDE9FE | 93C5FD/1E2A44 · 86EFAC/14322A · FCD34D/3A2E12 · FDBA74/3B2516 · FCA5A5/3B1C1C · B4B4B8/2A2A2D · C4B5FD/2E2550 |
| status | informational · success · redirect · clientError · serverError · pending · killed | 6D28D9 · 15803D · 0369A1 · B45309 · B91C1C · B45309 · 616A78 | C4B5FD · 4ADE80 · 7DD3FC · FCD34D · F87171 · F5A524 · 8E8E93 |
| severity (fg on bg) | critical · high · medium · low · info | 7F1D1D/FEE2E2 · B91C1C/FEE2E2 · B45309/FEF3C7 · 1D4ED8/DBEAFE · 4B5563/F3F4F6 | FCA5A5/4C1D1D · F87171/3B1C1C · FCD34D/3A2E12 · 93C5FD/1E2A44 · B4B4B8/2A2A2D |
| syntax | key · string · number · boolean · punct · bracket · lineNumber · currentLine · match | 9D174D · B45309 · 15803D · 6D28D9 · 6B7280 · A16207 · 9CA3AF · F3F4F6 · FDE68A | E58BC9 · E8B86D · 7FD88F · C4B5FD · 8E8E93 · E5C07B · 5C5C62 · 232325 · 6B5312 |

Every text tier holds 4.5:1 or better on its surface in both modes.

### Meaning

| Token | Used for |
| --- | --- |
| `Tok.Ground.surface` | panels, the flow table, inspector panes, the sidebar, the gallery ground |
| `Tok.Ground.page` | window ground behind panels |
| `Tok.Ground.raised` | chips, the listening pill, count chips, monograms, the status bar, the filter field, loading bars |
| `Tok.Ground.active` | selected flow row, selected sidebar item, an on small button; never the accent |
| `Tok.Ground.hover` | flow-row hover; never moves selection |
| `Tok.Ground.inverse` | the primary button fill only |
| `Tok.Line.border` / `.rule` / `.control` / `.focus` | panel edges and splitters / row separators / outlined controls / the focus ring |
| `Tok.Ink.primary` / `.secondary` / `.tertiary` | identity text / labels, times, icons / placeholders, meta, section labels, out-of-scope rows |
| `Tok.Ink.link` | the URL path |
| `Tok.Ink.onAccent` / `.onInverse` | text on an accent fill / on the primary button |
| `Palette.accent` / `.accentText` (Theme.swift) | THE accent in views: product mark, active tab text and underline. Follows the Mac's accent unless Multicolor, then `Tok.Accent.base` |
| `Tok.Intercept.*` | the intercept bar, paused rows' edge and badge, the pending dot, the armed pill dot |
| `Tok.Agent.*` | the Agent toggle, the agent count chip, the agent row edge and tag; shared with nothing |
| `Tok.Method.*` | method badges, via `HTTPMethod.badge`; the summary strip's status pill borrows the same tint by hue (`StatusClass.pill`) |
| `Tok.Status.*` | status text and the row dot, via `StatusClass.color`, `FlowRow.dotColor`, `FlowRow.statusColor` |
| `Tok.Severity.*` | PoC finding pills. TODO (story S-…): no view uses them yet |
| `Tok.Syntax.*` | body viewer runs via `SyntaxKind.color`; header names; line numbers; the current line |

### Scales

| Scale | Values | Where |
| --- | --- | --- |
| `Tok.Typography.Size` | xs 11 · sm 12 · md 13 · base 14 · lg 16 · xl 20 | with `Tok.Face` (below) |
| `Tok.Typography.Weight` | regular 400 · medium 500 · semibold 600 | medium: active tab, selected item, badge text, buttons; semibold: pane titles, the status code, badges |
| `Tok.Typography.LineHeight` | tight 1.25 · text 1.45 · code 1.55 | code: 13 on 20 pt lines |
| `Tok.Space` = `Space` | 4 · 8 · 12 · 16 · 20 · 24 · 32 (`Space.margin` 20) | every padding and spacing |
| `Tok.Size` | toolbar 44 · filterBar 36 · columnHeader 28 · Row.dense 28 / default 32 / comfortable 40 / card 64 · inspectorHeader 40 · tabBar 36 · interceptBar 40 · statusBar 28 · control 28 · controlLg 32 · badge 18 · statusDot 8 · icon 16 / iconInline 12 / iconToolbar 18 · sidebar 240 (200–320) · splitterHit 6 | fixed shell dimensions; `Density` moves row height and body size together (28/13, 32/13, 40/14) |
| `Tok.Radius` | badge 4 · control 6 · panel 8 · floating 10 · pill (Capsule) | pill only for the listening pill, chips, count chips |
| `Tok.Shadow.floating` | y 8, blur 24, 0.12 / 0.5 | menus, popovers, palette, sheets. Nothing that rests |
| `Tok.Motion` | press 120 ms · hover 100 · popover 160 · sheet 220 · rowArrive 0 · interceptPulse 1200; `easeOut` (.23,1,.32,1) · `easeInOut` (.77,0,.175,1) · `pulse` (.42,0,.58,1, Core Animation only: `pulseTiming` on the dot's layer, never a SwiftUI repeatForever); each curve also as `…Timing` | feedback only; no entrances; keyboard actions never animate; `hover`, `popover`, `sheet` are reserved (hover fills snap, popovers and sheets are system) |
| `Tok.Metric` (TokenMapping.swift) | chip 22 · barButton 26 · smallButton 20 · countChip 18 · switch 26 × 16, knob 12 · padInner 10 · gapTight 6 · gapMeta 14 · chipSeparator 14 | the dense numbers between the 4 pt steps |
| `Tok.Face` (TokenMapping.swift) | `ui(size, weight)` SF Pro · `data(size, weight)` SF Mono; `nsUI` / `nsData` for AppKit | chrome / every URL, header, body, time, size, id, method, status |

## Type

Roles are expressed as a face, size and weight; there is no role enum.
Name the role in a comment when it is not obvious.

| Role | Face | Size | Weight | Used for |
| --- | --- | --- | --- | --- |
| title | ui | 20 xl | medium | the empty-state headline ("No flows yet", "Nothing selected") |
| paneTitle | ui | 16 lg | semibold | Request / Response |
| body | ui | 13 md | regular | sidebar items, tabs, intercept text, sidebar filter placeholder |
| bodyStrong | ui | 13 md | medium | the selected sidebar item, the active tab, the wordmark |
| data | data | 13 md | regular | URL, headers, code, header-table rows, the summary URL |
| dataStrong | data | 13 md | medium | the status code in the list, the listen address, summary meta values (12) |
| label | ui | 12 sm | regular / medium | chips, pill text, status bar, Agent label, summary meta; medium on the bar buttons and the active chip |
| meta | data | 12 sm | regular | status bar numbers, throughput |
| badge | data | 11 xs | semibold | method and status badges (uppercase for methods) |
| section | ui | 11 xs | medium, tracking 0.6, uppercase | sidebar group labels, gallery section labels; column headers the same with kern 0.5 |
| micro | ui | 11 xs | regular / medium | count chips, monograms (medium), small buttons, shortcut hints, the version (data) |

Tabular figures belong on every number in a column; TODO (story S-…): not
yet applied through a modifier. The tracking value 0.6 is a literal in two
places; TODO (story S-…): hoist to `Tok.Metric`.

## Icons

Source: SF Symbols by role from `Tok.Glyph` (`icon.glyph.*.mac` in
tokens.json); a new icon is added there first. Views write
`Image(systemName: Tok.Glyph.<role>)` directly; there is no `KitIcon`
indirection on purpose, the glyph table is the indirection.

- Size 16 in bars (`Tok.Size.icon`), 12 inline (`Tok.Size.iconInline`);
  weight regular; colour `Tok.Ink.secondary` (tertiary for the inactive
  layout glyph and the sidebar filter glyph; `Status.clientError` for the
  pinned/failed padlock).
- Flat and monochrome. Never a capsule, disc, glass or bevel behind an icon.
  No filled variant on selection.
- Roles in use: sidebar, record, pause, compose, clear, intercept, resume,
  kill, replay, agent, browser, poc, scope, pin, palette, split, copy, lock,
  lockOpen, mark, search, chevron. Symbols still named inline (not yet in
  `Tok.Glyph`): `tray.full`, `app.badge`,
  `chevron.left.forwardslash.chevron.right`, `rectangle.split.1x2`,
  `chevron.down`, `exclamationmark.triangle`. TODO (story S-…): move them
  into tokens.json.
- Product mark: `›•‹` drawn as a 16 pt `Canvas` glyph in `Palette.accent`
  (`ProductMark`), wordmark 13/500 beside it.

## Window

Title bar: system, unified toolbar, title removed. Default size 1440 × 900,
minimum 1100 × 640. Sidebar | main is an `NSSplitViewController` with a 1 px
`Line.border` divider; the sidebar opens at 240, holds 200–320, remembers its
width, collapses with the toolbar toggle. Everything inside is flat.

## Parts

### Sidebar row (`SidebarView.item`)
Anatomy: glyph 12 in a 16 frame · gap 8 · label (body) · spacer · count chip.
Size: height 28 (`Size.control`), horizontal inset 8, radius 6 (`Radius.control`),
rows inset 8 from the sidebar edge.
| State | Fill | Label | Glyph |
| --- | --- | --- | --- |
| rest | none | primary, regular | secondary |
| selected | `Ground.active` | primary, medium | secondary |
| hover | TODO (story S-…): no hover fill yet | | |
| focused / keyboard | TODO (story S-…): arrow keys and a focus ring | | |

A sub-row (`subItem`: pinned host, client) is 28 tall, inset 28, with a
monogram in place of the glyph and a plain count (label role, secondary).

### Group label (`SidebarView.group`)
Section role: 11/500, uppercase, tracking 0.6, `Ink.tertiary`; padding
top 20, bottom 8, horizontal 8. Three groups: Working · All · aitmproxy.

### Count chip (`SidebarView.countChip`)
Label role 12. Plain count: secondary text, no fill. Queue count (Scope,
Findings): primary text on `Ground.raised` capsule, min 18 × 18, inset 6.
Agent count: `Agent.deep` on `Agent.tint`. Counts sit only on queues.

### Monogram (`Monogram`, `MonogramView`)
16 × 16, radius 4, `Ground.raised` fill (the AppKit one adds a 1 px
`Line.control` stroke), one character 11/500 in `Ink.secondary`. The real
app icon replaces it when the client resolves to one. TODO (story S-…).

### Toolbar
Window toolbar, 44 tall, shared background hidden. Left: sidebar toggle,
record/pause, compose, clear as flat `Label`s. Centre: the listening pill.
Right: Agent toggle, palette, layout switch. Icon buttons have the system's
hover; no custom chrome.

**Listening pill** (`ListeningPill`): dot 8 · gap 8 · `aitmproxy` 12/500
primary · ` · listening ` 12 secondary · address 12/500 mono primary ·
` · HTTP/2`; height 28, leading inset 10, trailing 12, `Ground.raised`
capsule.
| State | Dot | Text |
| --- | --- | --- |
| listening | `Status.success` | as above |
| capture paused | `Ink.tertiary` | "paused" |
| intercept armed | `Intercept.base` | adds " · intercept armed" |

**Agent toggle** (`AgentToggle`): switch 26 × 16 with a 12 knob inset 2 ·
gap 8 · `Agent` 12 primary · count chip 11 `Agent.deep` on `Agent.tint`,
height 16; row height 28, inset 8; a `Menu` with the policy picker.
| State | Switch | Knob | Count |
| --- | --- | --- | --- |
| allow all / read-only | `Agent.base`, knob trailing | white | shown when > 0 |
| paused | `Ink.tertiary`, knob leading | white | hidden at 0 |

**Flat icon button**: glyph 15–16 regular in a 28 × 28 hit area, no fill.
**Layout switch** (`LayoutPicker`): two of them, 4 apart; active in
`Ink.primary`, the other `Ink.tertiary`; `isSelected` trait. No segmented
chrome.

### Chip (`Chip`, `ChipBar`)
Label role 12, horizontal inset 8, height 22 (`Metric.chip`), capsule.
Bar 36 tall, inset 10, chips 2 apart, a 1 × 14 `Line.border` hairline with
6 either side between groups, 1 px `Rule` under the bar.
| State | Fill | Text |
| --- | --- | --- |
| off | none | secondary, regular |
| on | `Ground.raised` | primary, medium |
| hover | TODO (story S-…) | |

### Flow row (`FlowTableView`, `FlowRowView`, `FlowCellView`)
`NSTableView`, 28 pt rows (dense; `Density` gives 32 and 40), mono 13 data,
no zebra, 1 px `Line.rule` under each row, cells inset 8, header 28 with
section-role titles (11/500, kern 0.5, tertiary) and a 1 px `Line.border`
under it; sort shown as a tertiary ↑ / ↓. Columns: dot 24 · # 52 · URL ≥ 200
(host primary, path link, query tertiary) · Client 96 (monogram + name,
ui face) · Method 72 (badge) · Status 72 · Time 124 · Duration 88 ·
Request 80 · Response 80 · SSL 40 · Edited 64 · Origin 72 · Mark 20.
| State | Fill | Dot | Left edge 2 px | Status cell | Else |
| --- | --- | --- | --- | --- | --- |
| normal | `Ground.surface` | class colour | none | code, 13/500 class colour | |
| selected | `Ground.active` (never the accent); cells keep their colours | | | | |
| hover | `Ground.hover`; never selects (not captured in the gallery) | | | | |
| pending | surface | `Intercept.base` | none | `—` in `Status.pending` | duration `…` |
| paused | surface | `Intercept.base` | `Intercept.base` | `Paused` badge, deep on tint | pencil in Edited when mutated |
| killed | surface | `Status.killed` | none | `killed` grey | URL struck through, tertiary |
| failed | surface | `Status.serverError` | none | `error` | |
| replay | | | | | `↻` after # |
| out of scope | surface | | | tertiary | whole row `Ink.tertiary` |
| marked | | | | | 6 × 16 swatch, radius 2, system mark colour |
| agent | | | `Agent.base` (paused wins) | | `agent` tag 11 ui, `Agent.deep` on tint |
| focused / keyboard | TODO (story S-…): ↑↓ Enter and the single-key verbs | | | | |

### Method badge (`Badge`, `BadgeView`)
Text 11/600 mono uppercase, `pair.fg` on `pair.bg`, horizontal inset 6
(12 total in AppKit), height 18, radius 4. One per `HTTPMethod` via
`.badge`; `.other` wears the grey pair.

### Status text / badge
In the list: text, 13/500 mono, `StatusClass.color`; `—` pending
(`Status.pending`), `killed` (`Status.killed`), `error` (`Status.serverError`).
In the summary strip: a `Badge` of `code + reason` in `StatusClass.pill`
(the method tint of the same hue), and the state pills `Paused · request`
(`Intercept.deep` on tint), `Pending` (`Status.pending` on `Intercept.tint`),
`Killed` (`Status.killed` on `Ground.raised`), `Error` (delete pair), all
sentence case. These pairs are built inline in three files; TODO
(story S-…): hoist to `TokenMapping.swift`.

### Intercept bar (`InterceptBar`)
Height 40, horizontal inset 12, items 10 apart, 1 px `Rule` top and bottom.
The one saturated element; hidden when disarmed.
| State | Fill | Text | Content |
| --- | --- | --- | --- |
| armed, nothing paused | `Intercept.tint` | `Intercept.deep` 13 | hand glyph 13 · "Intercept armed — every request pauses here" · Rules… · Disarm i (ghosts in deep) |
| paused | `Intercept.base` | `Intercept.onBase` 13 | dot 8 pulsing 1 → 0.45 over 1200 ms (a Core Animation opacity animation, curve `pulse`; removed under Reduce Motion) · "N paused" semibold · target method + URL mono, 0.9 opacity, middle truncation · Resume ⌘⏎ / Apply & Resume (primary) · Resume all · Kill ⌘\ ▾ · Rules… · Disarm i |

### Primary button (`PrimaryButton`)
Label 12/500 `Ink.onInverse` + optional shortcut at 0.85 opacity, 6 apart;
inset 10; height 26 (`Metric.barButton`); `Ground.inverse` fill, radius 6.
| State | |
| --- | --- |
| rest | as above |
| pressed | scale 0.97, 120 ms `easeOut` (`PressStyle`); not captured |
| hover / focused / disabled | TODO (story S-…) |

### Ghost button (`GhostButton`)
Same metrics; text in `onColor` (default `Intercept.onBase`; `Intercept.deep`
on the tint bar); fill black at 0.12; `menu: true` adds a 9 pt chevron.
States as the primary button.

### Summary strip (`SummaryStrip`)
Height 40 (`Size.inspectorHeader`), inset 12, items 10 apart: method badge ·
status pill · URL 13 mono (host primary, path link, query tertiary; middle
truncation) · copy glyph 12 in a 24 hit area · spacer · meta 12 ui secondary,
14 apart: protocol · TLS · ALPN · `req` size · `resp` size · duration ·
`client` address · "in scope" / "out of scope" (`Intercept.deep`). Meta
values 12/500 mono primary. One per flow state (see Status).

### Pane tabs (`PaneTabs`)
Height 36 (`Size.tabBar`), inset 12, 1 px `Rule` under; title 16/600 primary
with 10 trailing; tabs 13 ui, inset 8, 2 apart; `+` tertiary; trailing slot
(the `editing` hint, the format button + search glyph).
| State | Text | Underline |
| --- | --- | --- |
| rest | secondary, regular | none |
| active | `Palette.accentText`, medium | 2 px `Palette.accent`, inset 8, on the shared rule |
| hover / keyboard | TODO (story S-…) | |

### Code view line (`CodeView`, `CodeLine`)
13 mono on 20 pt lines, number 11 mono in a 44 gutter (right aligned) with
14 trailing, runs coloured by `SyntaxKind.color`, 8 vertical padding on the
block, optional header / footer `Hint` (12 tertiary).
| State | Number | Fill | Edge |
| --- | --- | --- | --- |
| normal | `Syntax.lineNumber` | none | none |
| current | `Ink.secondary` | `Syntax.currentLine` | none |
| edited | as current when both | | 2 px `Intercept.base` at the left |
| match / fold / selection | TODO (story S-…) | | |

### Header table row (`HeaderTable`)
Height ≥ 28, inset 12, name 13 mono `Syntax.key` in a 180 column, value 13
mono primary (selectable), 12 apart, 1 px `Line.rule` under. Empty: `None`
hint.

### Status bar (`StatusBar`) and small button (`SmallButton`)
Bar 28 tall, `Ground.raised`, 1 px `Rule` on top, inset 12, 12 ui secondary;
centre counts 14 apart; right meta 12 mono with the bus dot 8.
Small button: 11 ui, inset 8, height 20, radius 6, 1 px `Line.control` outline.
| State | Fill | Text |
| --- | --- | --- |
| rest | `Ground.surface` | secondary |
| on | `Ground.active` | primary |
| pressed | `PressStyle` scale 0.97; not captured | |
| hover | TODO (story S-…) | |

### Empty state (`EmptyFlows`, `EmptyInspector`, `DiffPlaceholder`)
Title role 20/500 primary · 8 · one line 13 tertiary, centred; keeps the
frame; no illustration, no hue. Words: "No flows yet — Point a client at
host:port or open the browser." / "No flows match — Clear the chip or the
filter to see the capture." / "Nothing selected — Select a flow to inspect
it, or press ↑ ↓." TODO (story S-…): "Nothing paused.", "No findings —
build a PoC from any flow with `p`."

### Loading bars (`LoadingLines`)
Four `Ground.raised` bars 12 tall, radius 4, at 60 / 40 / 50 / 30 % width, 8
apart, inset 12; final layout, no shimmer, no layout shift when data lands.

### Not built yet
Filter bar, command palette, compose sheet, scope sheet, PoC panel,
browser view, script editor, activity log, dialogs: TODO (story S-…), each
from its §2.7 entry with the rules above.
