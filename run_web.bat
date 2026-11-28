@echo off
rem ===========================================================================
rem DiodeWatch - mission-control web UI launcher for Windows (double-clickable)
rem
rem   run_web.bat                  custom web dashboard on http://localhost:8530
rem   run_web.bat --port 9000      pick a port
rem
rem Starts the FastAPI server (apps/mission_control/server.py) which serves apps/mission_control/static and
rem streams the live rule-engine replay over WebSocket. The page auto-opens.
rem Stop with Ctrl-C (or close the console window).
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "PORT=8530"
if "%~1"=="--port" set "PORT=%~2"

if not exist ".venv\Scripts\python.exe" (
    echo [web] .venv missing - running setup first
    call setup\setup.bat || exit /b 1
) else (
    echo [web] .venv present
)

echo [web] Launching mission control on http://localhost:%PORT%
start "" http://localhost:%PORT%
.venv\Scripts\python.exe -m apps.mission_control.server --port %PORT%
