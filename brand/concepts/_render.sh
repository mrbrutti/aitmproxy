#!/usr/bin/env bash
# Render flat icon tiles + wordmark lockups + a comparison sheet for the
# three brand directions. No glass/shadow in previews (honors the flat rule).
set -euo pipefail
cd "$(dirname "$0")"

PAPER="#F7F8FA"; INK="#16161A"; HAIR="#E2E6EC"
R_FRAC=0.2234            # macOS squircle corner radius fraction

tile() { # size bg out  -> rounded-rect flat tile
  local s=$1 bg=$2 out=$3
  local r; r=$(python3 -c "print(round($s*$R_FRAC))")
  magick -size "${s}x${s}" xc:none -fill "$bg" \
    -draw "roundrectangle 0,0,$((s-1)),$((s-1)),$r,$r" "$out"
}

icon() { # glyph.svg size bg out  -> tile + glyph composited
  local glyph=$1 s=$2 bg=$3 out=$4
  local t="$TMPDIR/t_$$_$s.png" g="$TMPDIR/g_$$_$s.png"
  tile "$s" "$bg" "$t"
  rsvg-convert -w "$s" -h "$s" "$glyph" -o "$g"
  magick "$t" "$g" -gravity center -compose over -composite "$out"
}

for dir in c1-midpoint c2-intercept c3-aperture; do
  icon "$dir/glyph-light.svg" 256 "$PAPER" "$dir/icon-light-256.png"
  icon "$dir/glyph-dark.svg"  256 "$INK"   "$dir/icon-dark-256.png"
  icon "$dir/glyph-light.svg"  64 "$PAPER" "$dir/icon-light-64.png"
  icon "$dir/glyph-light.svg"  32 "$PAPER" "$dir/icon-light-32.png"
  icon "$dir/glyph-light.svg"  16 "$PAPER" "$dir/icon-light-16.png"
  rsvg-convert -w 1400 "$dir/lockup-light.svg" -o "$dir/lockup-light.png"
  rsvg-convert -w 1400 "$dir/lockup-dark.svg"  -o "$TMPDIR/ld_$$.png"
  magick -size 1400x308 xc:"$INK" "$TMPDIR/ld_$$.png" -gravity center -composite "$dir/lockup-dark.png"
done

# ---- per-concept panel: light256 | dark256 | [64 32 16 stack] | lockups
label() { printf '%s' "$1"; }
for d in c1-midpoint:Midpoint c2-intercept:Intercept c3-aperture:Aperture; do
  dir=${d%%:*}; name=${d##*:}
  # small-size strip on paper
  magick "$dir/icon-light-64.png" "$dir/icon-light-32.png" "$dir/icon-light-16.png" \
    -background white -gravity south +append -bordercolor white -border 12 "$TMPDIR/sm_$$.png"
  # top row: light + dark big
  magick "$dir/icon-light-256.png" "$dir/icon-dark-256.png" \
    -background white +append -bordercolor white -border 10 "$TMPDIR/top_$$.png"
  # lockups stacked
  magick "$dir/lockup-light.png" "$dir/lockup-dark.png" \
    -background white -append -resize 760x "$TMPDIR/lk_$$.png"
  magick \
    \( "$TMPDIR/top_$$.png" "$TMPDIR/sm_$$.png" -background white -gravity west -append \) \
    "$TMPDIR/lk_$$.png" -background white -gravity center +append \
    -bordercolor white -border 24 \
    -font /System/Library/Fonts/Menlo.ttc -pointsize 34 -fill "#16161A" \
    -gravity northwest -annotate +28+6 "$name" \
    "$dir/panel.png"
done

magick c1-midpoint/panel.png c2-intercept/panel.png c3-aperture/panel.png \
  -background "#D7DBE2" -append -bordercolor "#D7DBE2" -border 2 \
  COMPARE.png
echo "wrote COMPARE.png"
identify COMPARE.png
