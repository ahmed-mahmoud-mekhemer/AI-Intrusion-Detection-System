@echo off
REM =============================================================================
REM  setup_env.bat - Ensures a working, correctly-pathed .venv exists.
REM
REM  A Python virtual environment embeds the absolute path of the interpreter
REM  that created it. If this project folder is copied or zipped to another PC
REM  (or another user account) together with .venv, that path no longer exists
REM  and .venv\Scripts\python.exe fails to run - this is what causes
REM  "Backend Offline" when the whole folder (including .venv) is handed off.
REM
REM  This script detects that case and rebuilds .venv using whatever Python
REM  is installed on THIS machine, then reinstalls dependencies.
REM  Safe to call every time; it is a no-op if .venv already works.
REM =============================================================================

cd /d "%~dp0"

set "VENV_PY=.venv\Scripts\python.exe"
set "NEEDS_SETUP=0"

if not exist "%VENV_PY%" (
    set "NEEDS_SETUP=1"
) else (
    "%VENV_PY%" -c "import sys" >nul 2>&1
    if errorlevel 1 set "NEEDS_SETUP=1"
)

if "%NEEDS_SETUP%"=="0" exit /b 0

echo.
echo  ============================================================
echo    First run on this machine - setting up Python environment
echo    (one-time, takes a few minutes)
echo  ============================================================
echo.

if exist ".venv" (
    echo  [setup] Existing .venv was created on a different machine, rebuilding it ...
    rmdir /s /q ".venv"
)

set "BASE_PY="

py -3.11 -c "import sys" >nul 2>&1
if not errorlevel 1 set "BASE_PY=py -3.11"

if not defined BASE_PY (
    py -3 -c "import sys" >nul 2>&1
    if not errorlevel 1 set "BASE_PY=py -3"
)

if not defined BASE_PY (
    python -c "import sys" >nul 2>&1
    if not errorlevel 1 set "BASE_PY=python"
)

if not defined BASE_PY (
    echo  [ERROR] No Python installation found on this machine.
    echo  Install Python 3.11+ from https://www.python.org/ ^(check "Add to PATH"^)
    echo  and run this launcher again.
    pause
    exit /b 1
)

echo  [setup] Using base interpreter: %BASE_PY%
%BASE_PY% -m venv .venv
if errorlevel 1 (
    echo  [ERROR] Failed to create the virtual environment.
    pause
    exit /b 1
)

echo  [setup] Installing dependencies from requirements.txt - please wait ...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo  [ERROR] pip install failed. Check your internet connection and try again.
    pause
    exit /b 1
)

echo  [setup] Environment ready.
echo.
exit /b 0
