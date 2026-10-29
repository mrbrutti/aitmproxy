# aitmproxy brand

Direction: **Intercept** — a connection wire entering a node from both sides,
with an aperture slot cut through the node framing the inspected packet. It
states what the app is: an **intercepting proxy** that sits on the wire and
reads the flow between client and server.

Flat and monochrome, no glass / chrome / skeuomorphism, editorial restraint —
per the standing design rule. One hue only.

## Tokens

| | Light | Dark |
|---|---|---|
| Brand blue (mark, `aitm`-accent) | `#2563EB` | `#60A5FA` |
| Surface (icon tile) | `#F7F8FA` paper | `#16161A` ink |
| Wordmark `aitm` | `#16161A` ink | `#F7F8FA` paper |
| Wordmark `proxy` (muted) | `#8A94A6` | `#7E8794` |

Blue matches the app UI accent token (`apps/mac/.../UI/Tokens.swift`).

## Wordmark

`aitm` bold + `proxy` regular/muted — reads the name as *adversary-in-the-middle*
+ *proxy*. Set in **Menlo** (monospace), lowercase, tight tracking, to echo the
app's SF Mono data face. Keep the two-weight split; don't recolor `aitm` away
from ink except on dark surfaces.

## Files

- `mark.svg`, `mark-dark.svg` — the glyph (1024², reusable).
- `wordmark.svg`, `wordmark-dark.svg` — type only.
- `lockup.svg`, `lockup-dark.svg` — mark + wordmark on one line.
- `png/` — rendered raster: `mark-{16..1024}`, `icon-{light,dark}-1024`,
  `wordmark-*-2x`, `lockup-*-2x`.
- `FINAL.png` — overview sheet. `concepts/` — the three explored directions.

## App icon

The glyph ships as the macOS app icon at `apps/mac/Icon/AppIcon.icon`
(`icon.json` + `Assets/mark.svg` + `Assets/mark-dark.svg`), flat
(`glass:false`, no shadow). The aperture is a real transparency hole so every
system look (Default / Dark / Tinted / Clear) stays clean.

Rebuild after editing a layer:

```bash
cd apps/mac && ./tools/make_icon.sh && ./tools/icon_review.sh
```

## Regenerate

```bash
python3 brand/_build_final.py     # rewrites marks + wordmark + lockup SVGs
bash    brand/_render_brand.sh     # rewrites png/ and FINAL.png
```
