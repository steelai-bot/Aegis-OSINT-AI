@echo off
REM ============================================================
REM Aegis OSINT AI - Update Script (Windows)
REM ============================================================
REM ONE-LINE UPDATE (PowerShell):
REM iwr -useb https://raw.githubusercontent.com/steelai-bot/Aegis-OSINT-AI/main/update.bat -OutFile update.bat; .\update.bat
REM ============================================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo   Aegis OSINT AI - Update (Windows)
echo ========================================
echo.

REM Check if this is a git repository
if not exist ".git" (
    echo ERROR: This is not a git repository.
    echo Please clone the repository first.
    pause
    exit /b 1
)

REM Pull latest changes
echo [1/5] Pulling latest changes from repository...
git fetch origin
git pull origin main --ff-only 2>nul || git pull origin main
echo       Repository updated.

REM Update Python dependencies
echo.
echo [2/5] Updating Python dependencies...
if exist ".venv" (
    call .venv\Scripts\pip.exe install -r requirements.txt -q
    echo       Python dependencies updated.
) else (
    echo       Virtual environment not found. Skipping.
)

REM Update frontend
echo.
echo [3/5] Checking frontend...
if exist "frontend\package.json" (
    npm --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: frontend\package.json exists, but npm is not installed.
        pause
        exit /b 1
    )
    cd frontend
    echo       Updating frontend dependencies...
    call npm install --silent
    echo       Rebuilding frontend...
    call npm run build --silent
    echo       Frontend rebuilt successfully.
    cd ..
) else if exist "frontend" (
    echo       Legacy static frontend detected; no rebuild required.
) else (
    echo       No frontend directory found.
)

REM Re-initialize database
echo.
echo [4/5] Checking database...
if exist ".venv\Scripts\python.exe" (
    call .venv\Scripts\python.exe -c "
import sys
sys.path.insert(0, '.')
try:
    from backend.main import init_db
    init_db()
    print('      Database schema up to date.')
except:
    print('      Database check skipped.')
" 2>nul || echo       Database check skipped.
)

echo.
echo [5/5] Update complete!
echo.
echo ========================================
echo   ✅ Update finished successfully!
echo ========================================
echo.
echo You can now restart the application with:
echo   run.bat
echo.
pause