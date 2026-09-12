#!/usr/bin/env bash
# =============================================================================
# DiodeWatch — headless pre-flight
#
#   bash run_rehearsal.sh
#
# Runs scripts/checks/rehearse_demo.py (~10 s): pack presence, rule
# replays, beacon/DGA models, alert schema, evidence store, STIX, report,
# diode monitor. Exit 0 + "demo is GO" = ready to demo.
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

if [ ! -x "$PY_BIN" ]; then
  echo "✗ no venv — run: bash setup/setup.sh" >&2
  exit 1
fi

exec "$PY_BIN" scripts/checks/rehearse_demo.py "$@"
