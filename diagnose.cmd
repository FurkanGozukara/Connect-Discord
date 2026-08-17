@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

call "%~dp0run_python.cmd" -m discord_bypass --diagnose --no-launch --verbose

:result
set "APP_EXIT=%ERRORLEVEL%"
echo.
if "%APP_EXIT%"=="0" (
    echo All checks passed.
) else (
    echo Diagnostic failed with exit code %APP_EXIT%.
)
pause
exit /b %APP_EXIT%
