#!/usr/bin/env bash
# Render docs/og.png (1200x630) from docs/og/index.html with headless Chrome.
#
#   docs/og/render.sh                      # uses Chrome or Chromium on this machine
#   CHROME=/path/to/chrome docs/og/render.sh
#
# Fonts load from Google Fonts, so this needs network access. The virtual
# time budget gives them time to arrive before the screenshot is taken.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/../og.png"

chrome="${CHROME:-}"
if [ -z "$chrome" ]; then
  for c in \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    google-chrome google-chrome-stable chromium chromium-browser chrome-headless-shell; do
    if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then chrome="$c"; break; fi
  done
fi
[ -n "$chrome" ] || { echo "No Chrome or Chromium found. Set CHROME=/path/to/chrome." >&2; exit 1; }

"$chrome" --headless --disable-gpu --hide-scrollbars \
  --window-size=1200,630 --virtual-time-budget=8000 \
  --screenshot="$out" "file://$here/index.html" >/dev/null 2>&1

# The screenshot must be exactly 1200x630, or social cards crop it.
if command -v file >/dev/null 2>&1; then
  dims="$(file "$out" | grep -o '[0-9]* x [0-9]*' | head -1)"
  [ "$dims" = "1200 x 630" ] || { echo "Expected 1200 x 630, got: $dims" >&2; exit 1; }
fi
echo "wrote $out"
