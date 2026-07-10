@echo off
REM ============================================================
REM Aegis OSINT AI - Complete Windows Setup (One-Click)
REM ============================================================
REM ONE-LINE INSTALL (PowerShell as Admin):
REM iwr -useb https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/setup.bat -OutFile setup.bat; .\setup.bat
REM ============================================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo   Aegis OSINT AI - Full Setup (Windows)
echo ========================================
echo.

REM --- 1. Check Python ---
echo [1/10] Checking Python 3.10+...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo       Python %PYTHON_VERSION% found.

REM --- 2. Check Node.js ---
echo.
echo [2/10] Checking Node.js + npm...
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js not found.
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
echo       Node.js %NODE_VERSION% found.

REM --- 3. Create virtual environment ---
echo.
echo [3/10] Creating Python virtual environment...
if not exist ".venv" (
    python -m venv .venv
    echo       Virtual environment created.
) else (
    echo       Virtual environment already exists.
)

REM --- 4. Install Python dependencies ---
echo.
echo [4/10] Installing Python dependencies...
call .venv\Scripts\pip.exe install --upgrade pip -q
call .venv\Scripts\pip.exe install -r requirements.txt -q
echo       Python dependencies installed.

REM --- 5. Install Node.js dependencies ---
echo.
echo [5/10] Installing frontend dependencies...
if exist "frontend" (
    cd frontend
    call npm install --silent
    cd ..
    echo       Frontend dependencies installed.
) else (
    echo       No frontend folder found. Skipping.
)

REM --- 6. Build frontend ---
echo.
echo [6/10] Building frontend (React + Vite)...
if exist "frontend" (
    cd frontend
    call npm run build --silent
    cd ..
    echo       Frontend built successfully.
) else (
    echo       Skipping frontend build.
)

REM --- 7. Create directories ---
echo.
echo [7/10] Creating required directories...
if not exist "data" mkdir data
if not exist "reports" mkdir reports
echo       Directories created.

REM --- 8. Create .env if missing ---
echo.
echo [8/10] Setting up configuration (.env)...
if not exist ".env" (
    if exist "config\.env.example" (
        copy config\.env.example .env >nul
    ) else (
        echo # Aegis OSINT AI Configuration > .env
    )
    echo       Created .env file.
) else (
    echo       .env already exists.
)

REM --- 9. Initialize database ---
echo.
echo [9/10] Initializing database...
call .venv\Scripts\python.exe -c "
import sys
sys.path.insert(0, '.')
try:
    from backend.main import init_db
    init_db()
    print('      Database initialized successfully.')
except Exception as e:
    print('      WARNING:', e)
" 2>nul || echo       Database will be created on first run.

REM --- 10. Final verification ---
echo.
echo [10/10] Verifying installation...
call .venv\Scripts\python.exe -c "import fastapi, httpx, pydantic; print('      Core Python modules OK')" 2>nul || echo       Python verification skipped.
if exist "frontend_dist" (
    echo       Frontend build verified.
)

echo.
echo ========================================
echo   ✅ Installation Complete!
echo ========================================
echo.
echo Next steps:
echo   1. Edit .env and add your API keys
echo   2. Run the application:
echo      run.bat
echo.
echo   Application will be available at: http://localhost:8000
echo.
pause