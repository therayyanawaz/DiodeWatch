#!/usr/bin/env bash
# Build canonical flows + features for every CIC-IDS2017 day (ML corpus).
# Uses the existing ingest/feature CLIs; writes under data/slices/ml/.
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=.venv/Scripts/python.exe
OUT=data/slices/ml
mkdir -p "$OUT"

for f in data/raw/cic2017/*.parquet; do
  day=$(basename "$f" .parquet)
  if [ -f "$OUT/features__$day.parquet" ]; then
    echo "[skip] $day"
    continue
  fi
  echo "[unify] $day"
  "$PY" -m src.ingest.unify --input "$f" --out "$OUT/flows__$day.ndjson"
  echo "[features] $day"
  "$PY" -m src.features.pipeline --input "$OUT/flows__$day.ndjson" \
      --out "$OUT/features__$day.parquet"
  rm "$OUT/flows__$day.ndjson"   # large intermediate; re-buildable
done
echo "[done] features under $OUT/"
