@echo off
title Wi-Fi Device Scanner
cd /d "%~dp0"

echo ========================================================
echo        STARTING WI-FI DEVICE SCANNER...
echo ========================================================

:: Check Python virtual environment in parent folder d:\App\.venv
if exist "..\.venv\Scripts\python.exe" (
    echo [OK] Using Python virtual environment...
    "..\.venv\Scripts\python.exe" main.py
    goto end
)

:: Check system Python
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Using system Python...
    python main.py
    goto end
)

echo [ERROR] Python not found.
pause

:end
