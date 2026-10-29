# aitmproxy — brand directions (concept gate)

Three distinct directions for the macOS app icon **and** the logo/wordmark.
All live inside the standing rule: **flat, monochrome (brand blue), no
glass / chrome / skeuomorphism, editorial and typography-forward.** Letters
appear only in the wordmark — the icon glyph is always abstract.

Shared system across all three:
- **Color:** one hue. Brand blue `#2563EB` (light) / `#60A5FA` (dark), the same
  token the app UI uses (`Tok.Color` base). Glyph on paper `#F7F8FA` (light) or
  ink `#16161A` (dark). No gradient, no second color.
- **Wordmark:** `aitm` set bold, `proxy` set regular + muted — reads the name as
  *adversary-in-the-middle* + *proxy*. Menlo (SF Mono in the final), lowercase,
  tight tracking — matches the app's mono data face.
- **Previews are flat on purpose** (no OS glass/shadow), to honor the rule.

Preview sheet: `COMPARE.png`. Per-direction assets live in each folder
(`glyph-light.svg`, `glyph-dark.svg`, `lockup-*.svg`, rendered PNGs at 256/64/32/16).

---

## 1 · Midpoint — `→|←`
Two arrows meeting at a central boundary bar. Both parties' traffic
*terminates at the midpoint* — the adversary standing between client and
server. The most literal statement of "in the middle."
- Reads instantly; most abstract/minimal of the three.
- Risk: at 16 px the strokes get thin; slight kinship with a "collapse" glyph.

## 2 · Intercept — node on the wire
A single connection line with a rounded-square node straddling its midpoint,
the flow passing *through* the node (knockout slot + inspected packet). The
clearest picture of an **intercepting proxy** sitting on the connection.
- Strongest, most unambiguous "proxy" read; holds down to 16 px.
- The node/wire motif also scales to a UI mark.

## 3 · Aperture — `[•]`
Terminal/array brackets framing a central node: the inspection frame. Speaks
the language of a developer security tool (mono syntax, logs, `[ ]`), and
says *read / inspect the flow between*.
- Most "brand-y" and typography-forward; pairs tightly with the mono wordmark.
- Distinctive in a Dock; holds at small sizes.

---

**Pick one** (or a hybrid — e.g. Aperture icon + any wordmark). After the pick:
the chosen glyph is built into `apps/mac/Icon/AppIcon.icon` (flat `glass:false`,
compiled with actool, reviewed with ictool in light/dark/mono), and the
wordmark ships as reusable SVG + PNG under `brand/`.
