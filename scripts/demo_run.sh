#!/usr/bin/env bash
set -euo pipefail

FILE_PATH="${1:-}"
if [[ -z "$FILE_PATH" ]]; then
  echo "Usage: demo_run.sh <path-to-file>" >&2
  exit 2
fi

URL="${MIMF_URL:-http://127.0.0.1:8080}"
API_KEY="${MIMF_API_KEY:-devkey}"
OUT_ZIP="${MIMF_OUT_ZIP:-mimf_demo_bundle.zip}"

echo "[demo] health: $URL"
mimf client health --url "$URL" --api-key "$API_KEY"

echo "[demo] inspect"
mimf client inspect "$FILE_PATH" --url "$URL" --api-key "$API_KEY" | head -n 40 || true

echo "[demo] normalize"
mimf client normalize "$FILE_PATH" --url "$URL" --api-key "$API_KEY" | head -n 60 || true

echo "[demo] export bundle -> $OUT_ZIP"
mimf client export-bundle "$FILE_PATH" --out "$OUT_ZIP" --url "$URL" --api-key "$API_KEY"

echo "[demo] verify bundle"
mimf client verify-bundle "$OUT_ZIP" --url "$URL" --api-key "$API_KEY"

echo "[demo] done"
