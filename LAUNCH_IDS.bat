@echo off
REM =============================================================================
REM  AI-Based Intrusion Detection System - Master Launcher
REM
REM  Double-click this file to start the full IDS application:
REM    1. Opens a new window for the FastAPI backend (uvicorn on port 8000)
REM    2. Waits for the backend to be ready (health-check polling)
REM    3. Opens a new window for the CustomTkinter desktop frontend
REM
REM  To stop the IDS:
REM    - Close both terminal windows that opened, OR
REM    - Run stop_ids.bat for a clean shutdown
REM
REM  Requirements:
REM    - Python 3.11+ available in the .venv folder
REM    - Wireshark / tshark installed (for real-time monitoring)
REM    - Npcap installed (bundled with Wireshark)
REM    - Java installed (for PCAP analysis via CICFlowMeter)
REM    - Run as Administrator if you intend to use real-time packet capture
REM =============================================================================

setlocal
cd /d "%~dp0"

echo.
echo  ============================================================
echo    AI-Based Intrusion Detection System
echo    Starting backend and frontend ...
echo  ============================================================
echo.

REM -- Sanity checks -----------------------------------------------------------
call "%~dp0setup_env.bat"
if errorlevel 1 exit /b 1

if not exist "backend\main.py" (
    echo  [ERROR] backend\main.py not found. Are you running this from the project root?
    pause
    exit /b 1
)

if not exist "frontend\main.py" (
    echo  [ERROR] frontend\main.py not found. Are you running this from the project root?
    pause
    exit /b 1
)

REM -- Launch backend in its own window ----------------------------------------
echo  [1/3] Launching backend in a new window ...
start "IDS Backend (uvicorn)" cmd /k "%~dp0start_backend.bat"

REM -- Wait for backend to be ready ---------------------------------------------
echo  [2/3] Waiting for backend to become ready on port 8000 ...
set /a _retries=0
:wait_backend
timeout /t 1 /nobreak >nul
set /a _retries+=1
curl -s -o nul -w "" http://127.0.0.1:8000/stats/health 2>nul
if %errorlevel% equ 0 goto backend_ready
if %_retries% geq 30 (
    echo  [WARN] Backend did not respond after 30 seconds.
    echo         Check the backend window for errors. Launching frontend anyway.
    goto launch_frontend
)
goto wait_backend

:backend_ready
echo         Backend is up.

:launch_frontend
echo  [3/3] Launching desktop frontend ...
start "IDS Frontend (CustomTkinter)" cmd /k "%~dp0start_frontend.bat"

echo.
echo  ============================================================
echo    Both windows are now running.
echo    Close them or run stop_ids.bat to shut down the system.
echo  ============================================================
echo.

REM Auto-close this launcher window after 5 seconds
timeout /t 5 /nobreak >nul
endlocal
exit /b 0
