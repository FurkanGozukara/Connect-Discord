@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title Connect Discord - DiscordBypass

call "%~dp0run_python.cmd" -m discord_bypass --restart-discord %*
set "APP_EXIT=%ERRORLEVEL%"

:done
if not "%APP_EXIT%"=="0" pause
exit /b %APP_EXIT%
