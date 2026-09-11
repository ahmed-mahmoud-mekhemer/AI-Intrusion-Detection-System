@echo off
REM =============================================================================
REM  stop_ids.bat - Stops any running IDS backend by killing the process
REM                 listening on port 8000.
REM
REM  Use this if the backend window was closed abnormally and the process is
REM  still holding port 8000. The frontend stops by closing its window.
REM
REM  This script does NOT kill all Python processes - only the one bound to
REM  port 8000, so other Python apps on the system are not affected.
REM =============================================================================

setlocal enabledelayedexpansion

echo.
echo  Looking for IDS backend on port 8000 ...

set _found=0
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo  Stopping PID %%a ...
    taskkill /f /pid %%a >nul 2>&1
    if !errorlevel! equ 0 (
        echo  Stopped.
        set _found=1
    ) else (
        echo  Could not stop PID %%a - try running as Administrator.
    )
)

if %_found% equ 0 (
    echo  No IDS backend was running on port 8000.
)

echo.
echo  If the desktop app is still open, close its window manually.
echo.
pause
endlocal
