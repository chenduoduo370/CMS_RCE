@echo off
setlocal enabledelayedexpansion

REM One-click start for Windows (create venv, install deps, run GUI)

set "VENV_DIR=%~dp0.venv"
set "PY=%VENV_DIR%\Scripts\python.exe"

if not exist "%VENV_DIR%\Scripts\python.exe" (
  echo [*] Creating virtual environment: %VENV_DIR%
  py -3 -m venv "%VENV_DIR%"
  if errorlevel 1 (
    echo [!] Failed to create venv. Please ensure Python 3 is installed.
    pause
    exit /b 1
  )
)

echo [*] Upgrading pip
"%PY%" -m pip install --upgrade pip

echo [*] Installing requirements
"%PY%" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo [!] Failed to install dependencies.
  pause
  exit /b 1
)

echo [*] Launching GUI
"%PY%" "%~dp0poc_gui.py"

endlocal
