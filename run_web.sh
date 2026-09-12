#!/usr/bin/env bash
# ===========================================================================
# DiodeWatch - mission-control web UI launcher (Linux / macOS / WSL / Git Bash)
#
#   bash run_web.sh                custom web dashboard on http://localhost:8530
#   bash run_web.sh --port 9000    pick a port
#
# Starts the FastAPI server (apps/mission_control/server.py) which serves apps/mission_control/static and
# streams the live rule-engine replay over WebSocket.
# Stop with Ctrl-C.
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

PORT=8530
if [[ "${1:-}" == "--port" && -n "${2:-}" ]]; then PORT="$2"; fi

if [[ ! -x ".venv/bin/python" && ! -f ".venv/Scripts/python.exe" ]]; then
    echo "[web] .venv missing - running setup first"
    bash setup/setup.sh
fi

PY=".venv/bin/python"
[[ -f "$PY" ]] || PY=".venv/Scripts/python.exe"

echo "[web] Launching mission control on http://localhost:$PORT"
( sleep 2; command -v xdg-open >/dev/null && xdg-open "http://localhost:$PORT" \
  || command -v open >/dev/null && open "http://localhost:$PORT" ) >/dev/null 2>&1 &
exec "$PY" apps/mission_control/server.py --port "$PORT"
