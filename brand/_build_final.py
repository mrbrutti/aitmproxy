#!/usr/bin/env python3
"""Author the final aitmproxy brand assets (direction: Intercept).

Writes:
  apps/mac/Icon/AppIcon.icon/Assets/mark.svg        (light, brand blue)
  apps/mac/Icon/AppIcon.icon/Assets/mark-dark.svg   (dark, light blue)
  brand/mark.svg / mark-dark.svg                     (reusable glyph)
  brand/wordmark.svg / wordmark-dark.svg             (type only)
  brand/lockup.svg / lockup-dark.svg                 (mark + type)

Flat and monochrome (one hue), no glass/chrome. The aperture is a real
transparency hole (fill-rule evenodd), so every macOS look stays clean.
"""
import pathlib

BLUE_L = "#2563EB"; BLUE_D = "#60A5FA"
INK = "#16161A"; PAPER = "#F7F8FA"; MUTE_L = "#8A94A6"; MUTE_D = "#7E8794"

ROOT = pathlib.Path(__file__).resolve().parent          # brand/
REPO = ROOT.parent                                      # worktree root
ICON = REPO / "apps/mac/Icon/AppIcon.icon/Assets"

def rrect(x, y, w, h, r):
    return (f"M{x+r} {y} h{w-2*r} a{r} {r} 0 0 1 {r} {r} v{h-2*r} "
            f"a{r} {r} 0 0 1 {-r} {r} h{-(w-2*r)} a{r} {r} 0 0 1 {-r} {-r} "
            f"v{-(h-2*r)} a{r} {r} 0 0 1 {r} {-r} z")

def mark(c):
    # Intercept: wire enters a node from both sides; an aperture slot cut
    # through the node (true hole) frames the inspected packet.
    bar_h = 46; by = 512 - bar_h//2
    nx, ny, ns, nr = 368, 368, 288, 64             # node square
    sx, sy, sw, sh, sr = 396, 489, 232, 46, 23      # aperture slot
    left  = f'<rect fill="{c}" x="118" y="{by}" width="250" height="{bar_h}" rx="{bar_h//2}"/>'
    right = f'<rect fill="{c}" x="656" y="{by}" width="250" height="{bar_h}" rx="{bar_h//2}"/>'
    node  = (f'<path fill="{c}" fill-rule="evenodd" d="{rrect(nx,ny,ns,ns,nr)} '
             f'{rrect(sx,sy,sw,sh,sr)}"/>')
    pkt   = f'<circle fill="{c}" cx="512" cy="512" r="30"/>'
    body = f"  {left}\n  {right}\n  {node}\n  {pkt}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" '
            f'viewBox="0 0 1024 1024">\n{body}\n</svg>\n')

def wordmark(fg, mute, w=1600, h=360):
    fs, y = 150, 232
    txt = (f'<text x="150" y="{y}" font-family="Menlo, monospace" font-size="{fs}" '
           f'letter-spacing="-2"><tspan fill="{fg}" font-weight="bold">aitm</tspan>'
           f'<tspan fill="{mute}" font-weight="normal">proxy</tspan></text>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}">\n  {txt}\n</svg>\n')

def lockup(mark_href, fg, mute, w=2000, h=440):
    img = f'<image href="{mark_href}" x="40" y="40" width="360" height="360"/>'
    fs, y = 168, 272
    txt = (f'<text x="470" y="{y}" font-family="Menlo, monospace" font-size="{fs}" '
           f'letter-spacing="-3"><tspan fill="{fg}" font-weight="bold">aitm</tspan>'
           f'<tspan fill="{mute}" font-weight="normal">proxy</tspan></text>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}">\n  {img}\n  {txt}\n</svg>\n')

def main():
    ICON.mkdir(parents=True, exist_ok=True)
    (ICON / "mark.svg").write_text(mark(BLUE_L))
    (ICON / "mark-dark.svg").write_text(mark(BLUE_D))
    (ROOT / "mark.svg").write_text(mark(BLUE_L))
    (ROOT / "mark-dark.svg").write_text(mark(BLUE_D))
    (ROOT / "wordmark.svg").write_text(wordmark(INK, MUTE_L))
    (ROOT / "wordmark-dark.svg").write_text(wordmark(PAPER, MUTE_D))
    (ROOT / "lockup.svg").write_text(lockup("mark.svg", INK, MUTE_L))
    (ROOT / "lockup-dark.svg").write_text(lockup("mark-dark.svg", PAPER, MUTE_D))
    print("wrote marks + wordmark + lockup")

if __name__ == "__main__":
    main()
