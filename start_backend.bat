@echo off
REM =============================================================================
REM  start_backend.bat - Launches the FastAPI backend on http://127.0.0.1:8000
REM
REM  This script is normally invoked by LAUNCH_IDS.bat, but can also be run
REM  standalone if you only want the backend.
REM
REM  Notes:
REM   - Uses the .venv Python interpreter directly (no global activation needed)
REM   - --reload is OFF for delivery (was dev-only; caused duplicate processes)
REM   - Logs are visible in this window. Close it to stop the backend.
REM =============================================================================

cd /d "%~dp0"

echo.
echo  ============================================================
echo    IDS Backend (FastAPI + uvicorn)
echo    Listening on http://127.0.0.1:8000
echo    Docs:        http://127.0.0.1:8000/docs
echo  ============================================================
echo.

call "%~dp0setup_env.bat"
if errorlevel 1 exit /b 1

REM Use the venv's Python directly - avoids any activation issues
".venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

REM If we reach here, uvicorn exited (Ctrl+C, error, or window closed)
echo.
echo  Backend stopped.
pause
