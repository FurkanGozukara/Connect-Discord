@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

where py.exe >nul 2>nul
if errorlevel 1 goto :try_python_path
py.exe -3 -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>nul
if errorlevel 1 goto :try_python_path
py.exe -3 %*
exit /b %ERRORLEVEL%

:try_python_path
set "PYTHON_EXE="
for /f "delims=" %%I in ('where python.exe 2^>nul') do call :consider_python "%%I"
if defined PYTHON_EXE goto :run_python_path

:try_private_python
set "PYTHON_EXE=%~dp0.runtime\python\python.exe"
if not exist "%PYTHON_EXE%" goto :bootstrap_python
"%PYTHON_EXE%" -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>nul
if not errorlevel 1 goto :run_python_path

:bootstrap_python
where powershell.exe >nul 2>nul
if errorlevel 1 (
    echo Windows PowerShell was not found; private Python cannot be prepared.
    exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap_python.ps1"
if errorlevel 1 exit /b %ERRORLEVEL%
if not exist "%PYTHON_EXE%" (
    echo Private Python setup completed without creating python.exe.
    exit /b 2
)

:run_python_path
"%PYTHON_EXE%" %*
exit /b %ERRORLEVEL%

:consider_python
if defined PYTHON_EXE exit /b 0
if not exist "%~1" exit /b 0
for %%A in ("%~1") do if %%~zA EQU 0 exit /b 0
"%~1" -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>nul
if errorlevel 1 exit /b 0
set "PYTHON_EXE=%~1"
exit /b 0
