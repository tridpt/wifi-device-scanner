@echo off
title Wi-Fi Device Scanner
setlocal
set "APP_DIR=%~dp0"
cd /d "%APP_DIR%"

echo ========================================================
echo        STARTING WI-FI DEVICE SCANNER...
echo ========================================================

:: Prefer a virtual environment inside the cloned repository.
if exist "%APP_DIR%.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%APP_DIR%.venv\Scripts\python.exe"
)

:: Keep compatibility with the original workspace layout.
if not defined PYTHON_EXE if exist "%APP_DIR%..\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%APP_DIR%..\.venv\Scripts\python.exe"
)

if defined PYTHON_EXE (
    echo [OK] Using Python virtual environment...
    "%PYTHON_EXE%" "%APP_DIR%main.py"
    goto end
)

:: Check system Python
where python.exe >nul 2>&1
if not errorlevel 1 (
    echo [OK] Using system Python...
    python "%APP_DIR%main.py"
    goto end
)

echo [ERROR] Python not found.
pause

:end
endlocal
