#!/bin/sh
# Frames from record.mjs -> docs/demo.gif (10 fps, one palette for the whole film).
# sh docs/demo/gif.sh <frames dir>
set -e
sortie="$(cd "$(dirname "$0")/.." && pwd)/demo.gif"
cd "$1"
ffmpeg -loglevel error -y -f concat -i liste.txt -vf "fps=10,palettegen=max_colors=128:stats_mode=diff" palette.png
ffmpeg -loglevel error -y -f concat -i liste.txt -i palette.png \
  -lavfi "fps=10[v];[v][1:v]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" "$sortie"
