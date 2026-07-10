@echo off
REM Aegis OSINT AI - Windows Setup Script
REM One-click installation for Windows

REM ============================================
REM ONE-LINE INSTALL (run in PowerShell as Admin):
REM iwr -useb https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/setup.bat -OutFile setup.bat; .\setup.bat
REM ============================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo   Aegis OSINT AI - Setup
echo ========================================
echo.

REM Check Python
echo [1/12] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.10+ from python.org
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo       Python %PYTHON_VERSION% found.

REM Create virtual environment
echo.
echo [2/12] Creating virtual environment...
if not exist ".venv" (
    python -m venv .venv
    echo       Virtual environment created.
) else (
    echo       Virtual environment already exists.
)

REM Upgrade pip
echo.
echo [3/12] Upgrading pip...
call .venv\Scripts\pip.exe install --upgrade pip >nul 2>&1
echo       Pip upgraded.

REM Install Python dependencies
echo.
echo [4/12] Installing Python dependencies...
call .venv\Scripts\pip.exe install -r requirements.txt >nul
if errorlevel 1 (
    echo       ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo       Dependencies installed.

REM Create directories
echo.
echo [5/12] Creating directories...
if not exist "data" mkdir data
if not exist "reports" mkdir reports
echo       Directories created.

REM Create .env from template if missing
echo.
echo [6/12] Setting up configuration...
if not exist ".env" (
    copy config\.env.example .env >nul
    echo       Created .env from template.
) else (
    echo       .env already exists.
)

REM Initialize database
echo.
echo [7/12] Initializing database...
call .venv\Scripts\python.exe -c "
import sys
sys.path.insert(0, '.')
try:
    from backend.main import init_db
    init_db()
    print('      Database initialized.')
except Exception as e:
    print('      WARNING:', e)
" 2>nul
if errorlevel 1 (
    echo       WARNING: Could not initialize database (may be created on first run)
) else (
    echo       Database initialized.
)

REM Verify installation
echo.
echo [8/12] Verifying installation...
call .venv\Scripts\python.exe -c "import fastapi; import sqlalchemy; print('       Core modules OK')" 2>nul
if errorlevel 1 (
    echo       ERROR: Verification failed
    pause
    exit /b 1
)

REM Summary
echo.
echo ========================================
echo   Installation Complete!
echo ========================================
echo.
echo Next steps:
echo   1. Edit .env and add your API keys
echo   2. Run: run.bat
echo   3. Open: http://localhost:8000
echo.
echo Press any key to start the application...
pause >nul

call run.bat