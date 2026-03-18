@echo off
setlocal

set "SCRIPT=%~dp0PSDiscoveryProtocol.SingleFile.ps1"

NET SESSION >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

if not exist "%SCRIPT%" (
    echo ERROR: File not found: "%SCRIPT%"
    echo Please run Build-SingleFile.ps1 first.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

if errorlevel 1 (
    echo.
    echo The script exited with an error. See messages above.
)

echo.
pause

endlocal
