@echo off
rem ===========================================================================
rem DiodeWatch - Windows environment setup (double-clickable, no Git Bash needed)
rem
rem   setup.bat              install .venv + pinned deps (online or offline)
rem   setup.bat --check      verify the environment without changing it
rem   setup.bat --offline    install strictly from setup\wheels\ (air-gapped)
rem
rem Delegates every real step to setup\setup.sh via Git Bash if available,
rem otherwise runs the native-Python fallback below. No step needs admin.
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=--setup"

rem --- find a launcher for the bash script -----------------------------------
rem %~dp0 is this script's dir (setup\) with a trailing backslash; the repo
rem root is one level up.
set "BASH_EXE="
where bash >nul 2>nul && set "BASH_EXE=bash"
if not defined BASH_EXE if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles%\Git\bin\bash.exe"

if defined BASH_EXE (
    pushd "%~dp0.."
    "%BASH_EXE%" setup/setup.sh %MODE%
    set "RC=%errorlevel%"
    popd
    exit /b %RC%
)

rem --- native fallback (no bash anywhere): pure Python ------------------------
echo [setup] bash not found - using native Windows fallback
rem wheelhouse wheels are CPython 3.11 - prefer py -3.11 over newer pythons
set "PY="
py -3.11 -c "import sys" >nul 2>nul && set "PY=py -3.11"
if not defined PY where python3.11 >nul 2>nul && set "PY=python3.11"
if not defined PY where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
    echo [setup] ERROR: no Python found. Install Python 3.11 from python.org
    echo         ^(tick "Add python.exe to PATH"^), then re-run this script.
    exit /b 1
)

if "%MODE%"=="--check" goto :native_check

echo [setup] Creating .venv (user-owned, no admin)
%PY% -m venv .venv || exit /b 1
set "VPY=.venv\Scripts\python.exe"

rem venvs created by `py -m venv` always have pip; uv-style venvs may not
%VPY% -m pip --version >nul 2>nul
if errorlevel 1 (
    echo [setup] venv has no pip - bootstrapping via ensurepip
    %VPY% -m ensurepip --upgrade || exit /b 1
)

if "%MODE%"=="--offline" (
    echo [setup] Installing requirements OFFLINE from setup\wheels\
    %VPY% -m pip install --no-index --find-links setup\wheels -r requirements.txt || exit /b 1
) else (
    echo [setup] Installing requirements from PyPI
    %VPY% -m pip install -r requirements.txt || (
        echo [setup] online install failed - if this machine is air-gapped use: setup.bat --offline
        exit /b 1
    )
)

:native_check
echo [setup] Verifying the toolchain imports
.venv\Scripts\python.exe -c "import importlib.util as u, sys; miss=[m for m in ('pandas','numpy','polars','sklearn','lightgbm','scapy','streamlit','fastapi','pyarrow') if u.find_spec(m) is None]; print('  core imports: ' + ('OK' if not miss else 'MISSING '+str(miss))); sys.exit(1 if miss else 0)"
if errorlevel 1 exit /b 1

echo [setup] Setup complete
echo     python : %CD%\.venv\Scripts\python.exe
echo     next   : run_demo.bat   ^(full demo^)
echo              run_rehearsal.bat   ^(headless pre-flight^)
exit /b 0

exit /b 0
