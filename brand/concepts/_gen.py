#!/usr/bin/env python3
"""Generate glyph + wordmark SVGs for the three aitmproxy brand directions.

All marks are FLAT and MONOCHROME (brand blue), no glass / chrome / gradient —
per Matt's standing rule. Letters live only in the wordmark, never the icon.
"""
import os, pathlib

BLUE_L = "#2563EB"   # brand blue, light mode
BLUE_D = "#60A5FA"   # brand blue, dark mode
INK    = "#16161A"   # ink (dark tile / dark wordmark)
PAPER  = "#F7F8FA"   # paper (light tile)
MUTE_L = "#8A94A6"   # muted ink, light
MUTE_D = "#7E8794"   # muted ink, dark

ROOT = pathlib.Path(__file__).resolve().parent

def svg(body, w=1024, h=1024, vb="0 0 1024 1024"):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="{vb}">\n{body}\n</svg>\n')

# ---------------------------------------------------------------- glyphs
def glyph_midpoint(c):
    # Two arrows meeting at a central boundary bar:  ->  |  <-
    # Both sides terminate at the midpoint (the adversary in the middle).
    sh = 52                      # shaft thickness
    sy = 512 - sh/2
    bar = f'<rect fill="{c}" x="492" y="344" width="40" height="336" rx="20"/>'
    # left arrow: shaft + head pointing right, tip short of the bar
    l_shaft = f'<rect fill="{c}" x="150" y="{sy}" width="258" height="{sh}" rx="{sh/2}"/>'
    l_head  = f'<path fill="{c}" d="M392 440 L462 512 L392 584 Z"/>'
    # right arrow: mirror
    r_shaft = f'<rect fill="{c}" x="616" y="{sy}" width="258" height="{sh}" rx="{sh/2}"/>'
    r_head  = f'<path fill="{c}" d="M632 440 L562 512 L632 584 Z"/>'
    return svg(f'  {l_shaft}\n  {l_head}\n  {r_shaft}\n  {r_head}\n  {bar}')

def glyph_intercept(c, tile):
    # A full-width connection bar; a central rounded-square node straddles it,
    # with a knockout slot so the flow reads as passing THROUGH the node.
    bar_h = 46
    bar_y = 512 - bar_h/2
    bar = f'<rect fill="{c}" x="118" y="{bar_y}" width="788" height="{bar_h}" rx="{bar_h/2}"/>'
    node = f'<rect fill="{c}" x="368" y="368" width="288" height="288" rx="64"/>'
    # knockout slot (tile color) through the node = traffic read inside
    slot_h = 46
    slot = f'<rect fill="{tile}" x="396" y="{512-slot_h/2}" width="232" height="{slot_h}" rx="{slot_h/2}"/>'
    # a smaller inner mark (the inspected packet) centered in the slot
    pkt = f'<circle fill="{c}" cx="512" cy="512" r="30"/>'
    return svg(f'  {bar}\n  {node}\n  {slot}\n  {pkt}')

def glyph_aperture(c):
    # Terminal/array brackets framing a central node:  [ ● ]
    t = 62           # bracket thickness
    top, bot = 322, 702
    arm = 108        # horizontal arm length
    xL = 300         # left bracket outer x
    xR = 724         # right bracket outer x (mirrored)
    def bracket(x0, direction):
        # direction +1 = opening right '[', -1 = ']'
        ax = x0 + direction*arm
        return (f'<path fill="{c}" d="'
                f'M{x0} {top} L{ax} {top} L{ax} {top+t} L{x0+direction*t} {top+t} '
                f'L{x0+direction*t} {bot-t} L{ax} {bot-t} L{ax} {bot} L{x0} {bot} Z"/>')
    left = bracket(xL, +1)
    right = bracket(xR, -1)
    dot = f'<circle fill="{c}" cx="512" cy="512" r="70"/>'
    return svg(f'  {left}\n  {right}\n  {dot}')

CONCEPTS = {
    "c1-midpoint":  ("Midpoint",  lambda c, tile: glyph_midpoint(c)),
    "c2-intercept": ("Intercept", lambda c, tile: glyph_intercept(c, tile)),
    "c3-aperture":  ("Aperture",  lambda c, tile: glyph_aperture(c)),
}

# ---------------------------------------------------------------- wordmark
def wordmark(fg, mute, bg=None):
    # "aitm" emphasized (the adversary-in-the-middle), "proxy" muted.
    # Menlo, lowercase, tight. Rendered big for crisp downscaling.
    W, H = 1600, 360
    bgrect = f'<rect x="0" y="0" width="{W}" height="{H}" fill="{bg}"/>' if bg else ""
    fs = 150
    y = 232
    txt = (f'<text x="150" y="{y}" font-family="Menlo, monospace" '
           f'font-size="{fs}" letter-spacing="-2">'
           f'<tspan fill="{fg}" font-weight="bold">aitm</tspan>'
           f'<tspan fill="{mute}" font-weight="normal">proxy</tspan></text>')
    return svg(f'  {bgrect}\n  {txt}', w=W, h=H, vb=f"0 0 {W} {H}")

def wordmark_locked(mark_svg_rel, fg, mute, bg=None):
    # mark + wordmark on one line (lockup). mark is embedded via <image>.
    W, H = 2000, 440
    bgrect = f'<rect x="0" y="0" width="{W}" height="{H}" fill="{bg}"/>' if bg else ""
    img = f'<image href="{mark_svg_rel}" x="40" y="40" width="360" height="360"/>'
    fs = 168
    y = 272
    txt = (f'<text x="470" y="{y}" font-family="Menlo, monospace" '
           f'font-size="{fs}" letter-spacing="-3">'
           f'<tspan fill="{fg}" font-weight="bold">aitm</tspan>'
           f'<tspan fill="{mute}" font-weight="normal">proxy</tspan></text>')
    return svg(f'  {bgrect}\n  {img}\n  {txt}', w=W, h=H, vb=f"0 0 {W} {H}")

def main():
    for key, (name, fn) in CONCEPTS.items():
        d = ROOT / key
        d.mkdir(parents=True, exist_ok=True)
        (d / "glyph-light.svg").write_text(fn(BLUE_L, PAPER))
        (d / "glyph-dark.svg").write_text(fn(BLUE_D, INK))
        # wordmark lockups use the light glyph on paper / dark glyph on ink
        (d / "lockup-light.svg").write_text(
            wordmark_locked("glyph-light.svg", INK, MUTE_L, bg=None))
        (d / "lockup-dark.svg").write_text(
            wordmark_locked("glyph-dark.svg", PAPER, MUTE_D, bg=None))
    # standalone wordmark (direction-independent)
    (ROOT / "wordmark-light.svg").write_text(wordmark(INK, MUTE_L))
    (ROOT / "wordmark-dark.svg").write_text(wordmark(PAPER, MUTE_D))
    print("generated SVGs")

if __name__ == "__main__":
    main()
