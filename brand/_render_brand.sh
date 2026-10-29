#!/usr/bin/env bash
# Render reusable raster assets + a brand preview sheet from the final SVGs.
set -euo pipefail
cd "$(dirname "$0")"
export TMPDIR=/tmp/claude/brandtmp MAGICK_TMPDIR=/tmp/claude/brandtmp
mkdir -p "$TMPDIR" png

PAPER="#F7F8FA"; INK="#16161A"; RFRAC=0.2234

tile() { local s=$1 bg=$2 out=$3 r; r=$(python3 -c "print(round($s*$RFRAC))")
  magick -size "${s}x${s}" xc:none -fill "$bg" \
    -draw "roundrectangle 0,0,$((s-1)),$((s-1)),$r,$r" "$out"; }

# --- reusable glyph PNGs (transparent) ---
for s in 1024 512 256 128 64 32 16; do
  rsvg-convert -w "$s" -h "$s" mark.svg      -o "png/mark-$s.png"
  rsvg-convert -w "$s" -h "$s" mark-dark.svg -o "png/mark-dark-$s.png"
done

# --- app-store style flat icon tiles (mark on tile) ---
icon_png() { local glyph=$1 s=$2 bg=$3 out=$4
  tile "$s" "$bg" "$TMPDIR/t.png"
  rsvg-convert -w "$s" -h "$s" "$glyph" -o "$TMPDIR/g.png"
  magick "$TMPDIR/t.png" "$TMPDIR/g.png" -gravity center -composite "$out"; }
icon_png mark.svg      1024 "$PAPER" png/icon-light-1024.png
icon_png mark-dark.svg 1024 "$INK"   png/icon-dark-1024.png

# --- wordmark + lockup PNGs ---
rsvg-convert -w 1600 wordmark.svg      -o png/wordmark-2x.png
rsvg-convert -w 1600 wordmark-dark.svg -o "$TMPDIR/wd.png"
magick -size 1600x360 xc:"$INK" "$TMPDIR/wd.png" -gravity center -composite png/wordmark-dark-2x.png
rsvg-convert -w 2000 lockup.svg      -o png/lockup-2x.png
rsvg-convert -w 2000 lockup-dark.svg -o "$TMPDIR/ld.png"
magick -size 2000x440 xc:"$INK" "$TMPDIR/ld.png" -gravity center -composite png/lockup-dark-2x.png

# --- brand preview sheet ---
icon_png mark.svg      256 "$PAPER" "$TMPDIR/il.png"
icon_png mark-dark.svg 256 "$INK"   "$TMPDIR/id.png"
icon_png mark.svg       64 "$PAPER" "$TMPDIR/s64.png"
icon_png mark.svg       32 "$PAPER" "$TMPDIR/s32.png"
icon_png mark.svg       16 "$PAPER" "$TMPDIR/s16.png"
magick "$TMPDIR/il.png" "$TMPDIR/id.png" -background white +append \
  -bordercolor white -border 16 "$TMPDIR/row1.png"
magick "$TMPDIR/s64.png" "$TMPDIR/s32.png" "$TMPDIR/s16.png" -background white -gravity south +append \
  -bordercolor white -border 16 "$TMPDIR/row2.png"
magick png/lockup-2x.png -resize 820x "$TMPDIR/lk1.png"
magick png/lockup-dark-2x.png -resize 820x "$TMPDIR/lk2.png"
magick \
  \( "$TMPDIR/row1.png" "$TMPDIR/row2.png" -background white -gravity west -append \) \
  \( "$TMPDIR/lk1.png" "$TMPDIR/lk2.png" -background white -gravity center -append \) \
  -background white -gravity center +append -bordercolor white -border 28 \
  FINAL.png
echo "wrote brand/FINAL.png and brand/png/*"
identify FINAL.png
