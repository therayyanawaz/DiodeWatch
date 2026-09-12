@echo off
rem ===========================================================================
rem DiodeWatch - headless pre-flight for Windows (double-clickable)
rem
rem   run_rehearsal.bat
rem
rem Runs scripts\checks\rehearse_demo.py (~10 s): pack presence, rule
rem replays, beacon/DGA models, alert schema, evidence store, STIX, report,
rem diode monitor. "demo is GO" = ready to demo.
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [rehearsal] no venv - run setup\setup.bat first
    exit /b 1
)

.venv\Scripts\python.exe scripts\checks\rehearse_demo.py %*
exit /b %errorlevel%
