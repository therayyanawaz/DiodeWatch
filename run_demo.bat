@echo off
rem ===========================================================================
rem DiodeWatch - one-command demo launcher for Windows (double-clickable)
rem
rem   run_demo.bat                 dashboard on http://localhost:8501
rem   run_demo.bat --port 8510     pick a port
rem
rem Mirrors run_demo.sh: verifies the venv (auto-runs setup if missing),
rem generates the demo pack + pcap if needed, then starts Streamlit headless.
rem Stop with Ctrl-C (or close the console window).
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "PORT=8501"
if "%~1"=="--port" set "PORT=%~2"

if not exist ".venv\Scripts\python.exe" (
    echo [demo] .venv missing - running setup first
    call setup\setup.bat || exit /b 1
) else (
    echo [demo] .venv present
)

echo [demo] Ensuring demo data (offline, deterministic)
if not exist "data\pcaps\pack\pack_manifest.json" (
    .venv\Scripts\python.exe scripts\generators\make_demo_pack.py >nul || (echo [demo] demo pack generation failed & exit /b 1)
    echo [demo]   demo pack generated ^(6 scenarios + manifest^)
) else (
    echo [demo]   demo pack present
)
if not exist "data\pcaps\demo_threats.pcap" (
    .venv\Scripts\python.exe scripts\generators\make_demo_pcap.py >nul || (echo [demo] demo pcap generation failed & exit /b 1)
    echo [demo]   demo pcap generated ^(mixed-threat synthetic capture^)
) else (
    echo [demo]   demo pcap present
)

if not exist "models" mkdir "models"
dir /b models\*.joblib >nul 2>nul
if errorlevel 1 (
    if exist "docs\evaluation\models\*.joblib" (
        copy /y "docs\evaluation\models\*.joblib" "models\" >nul
        echo [demo]   restored pinned evaluation models ^(ML scenarios enabled^)
    )
)
dir /b models\*.joblib >nul 2>nul
if errorlevel 1 (
    echo [demo] WARNING: models\ is empty - ML channels (C2 beacon, DGA^) silent;
    echo [demo]          rule detectors still fire. Train with scripts\checks\check_ml.py.
)

echo [demo] Launching dashboard on http://localhost:%PORT%
.venv\Scripts\python.exe -m streamlit run apps/dashboard/app.py --server.port %PORT% --server.headless true
