@echo off
REM =============================================================================
REM  start_frontend.bat - Launches the CustomTkinter desktop application.
REM
REM  This script is normally invoked by LAUNCH_IDS.bat, but can also be run
REM  standalone if the backend is already running.
REM
REM  Notes:
REM   - Uses the .venv Python interpreter directly
REM   - The frontend will show "Backend Online" in the bottom-left when ready
REM   - Close the application window to stop the frontend
REM =============================================================================

cd /d "%~dp0"

echo.
echo  ============================================================
echo    IDS Desktop Frontend (CustomTkinter)
echo  ============================================================
echo.

call "%~dp0setup_env.bat"
if errorlevel 1 exit /b 1

".venv\Scripts\python.exe" frontend\main.py

REM If we reach here, the app window was closed
echo.
echo  Frontend stopped.
pause
