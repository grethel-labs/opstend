#!/usr/bin/env bash
# Rendert docs/diagrams/src/*.puml mit excaliplant (npm-Paket, in package.json gepinnt)
# nach docs/diagrams/out/{svg,png,excalidraw}.
# Aufruf: docs/diagrams/render.sh [--theme NAME] [src/datei.puml ...]
set -euo pipefail
cd "$(dirname "$0")"
THEME="pastel-light"
if [[ "${1:-}" == "--theme" ]]; then THEME="$2"; shift 2; fi
files=("$@")
[[ ${#files[@]} -eq 0 ]] && files=(src/*.puml)
[[ -x node_modules/.bin/excaliplant ]] || npm ci --ignore-scripts --no-audit --no-fund
XP=node_modules/.bin/excaliplant
mkdir -p out/svg out/png out/excalidraw
for f in "${files[@]}"; do
  name="$(basename "${f%.puml}")"
  echo "== $name"
  "$XP" "$f" -f svg --theme "$THEME" -o "out/svg/$name.svg"
  "$XP" "$f" -f excalidraw --theme "$THEME" -o "out/excalidraw/$name.excalidraw"
  "$XP" "$f" -f png --width 2000 --theme "$THEME" -o "out/png/$name.png"
done
