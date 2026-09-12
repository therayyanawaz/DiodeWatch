#!/usr/bin/env bash
# =============================================================================
# DiodeWatch — one-command demo launcher
#
#   bash run_demo.sh
#   bash run_demo.sh --port 8510          # pick a port
#   bash run_demo.sh --pack 02_c2_beacon  # preselect a demo-pack scenario
#   bash run_demo.sh --no-headless        # let Streamlit open the browser
#
# Does, in order:
#   1. verify the .venv (runs setup/setup.sh --check, offers to fix)
#   2. generate the demo pack + demo pcap if missing (offline, seconds)
#   3. launch the analyst dashboard with headless-friendly Streamlit settings
#
# Stop with Ctrl-C.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

IS_WINDOWS=0
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac
PY_BIN="$REPO/.venv/bin/python"
[ "$IS_WINDOWS" = "1" ] && PY_BIN="$REPO/.venv/Scripts/python.exe"

PORT=8501
PACK_KEY=""
HEADLESS=1
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --pack) PACK_KEY="$2"; shift 2 ;;
    --no-headless) HEADLESS=0; shift ;;
    -h|--help) sed -n '3,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

# --- 1. environment ----------------------------------------------------------
if [ ! -x "$PY_BIN" ]; then
  say ".venv missing — running setup"
  bash setup/setup.sh || die "setup failed — fix the error above and re-run"
else
  ok ".venv present"
  if ! bash setup/setup.sh --check >/dev/null 2>&1; then
    warn "venv is missing packages — repairing via setup"
    bash setup/setup.sh || die "setup failed — fix the error above and re-run"
  fi
fi

# --- 2. demo data ------------------------------------------------------------
say "Ensuring demo data (offline, deterministic)"
PACK_DIR="data/pcaps/pack"
if [ ! -f "$PACK_DIR/pack_manifest.json" ]; then
  "$PY_BIN" scripts/generators/make_demo_pack.py >/dev/null \
    || die "demo pack generation failed"
  ok "demo pack generated (6 scenarios + manifest)"
else
  ok "demo pack present"
fi
if [ ! -f "data/pcaps/demo_threats.pcap" ]; then
  "$PY_BIN" scripts/generators/make_demo_pcap.py >/dev/null \
    || die "demo pcap generation failed"
  ok "demo pcap generated (mixed-threat synthetic capture)"
else
  ok "demo pcap present"
fi
mkdir -p models
if [ -z "$(ls models/*.joblib 2>/dev/null)" ] \
   && [ -n "$(ls docs/evaluation/models/*.joblib 2>/dev/null)" ]; then
  cp docs/evaluation/models/*.joblib models/
  ok "restored pinned evaluation models (beacon, DGA) — ML scenarios enabled"
fi
if [ -z "$(ls models/*.joblib 2>/dev/null)" ]; then
  warn "models/ is empty — ML channels (C2 beacon, DGA) will be silent;"
  warn "rule detectors still fire. Train with scripts/checks/check_ml.py (see README)."
fi

# --- 3. launch ---------------------------------------------------------------
URL="http://localhost:$PORT"
say "Launching dashboard on $URL"
[ "$HEADLESS" = "1" ] && ok "headless mode — open $URL in a browser"

ARGS=(run apps/dashboard/app.py --server.port "$PORT")
[ "$HEADLESS" = "1" ] && ARGS+=(--server.headless)

exec "$PY_BIN" -m streamlit "${ARGS[@]}"
