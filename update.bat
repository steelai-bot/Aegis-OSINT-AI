@echo off
REM Aegis OSINT AI - Windows Update Script
REM Updates the application while preserving configuration and data

setlocal enabledelayedexpansion

echo.
echo ========================================
echo   Aegis OSINT AI - Update
echo ========================================
echo.

REM Check if .venv exists
if not exist ".venv" (
    echo ERROR: Virtual environment not found.
    echo Please run setup.bat first.
    pause
    exit /b 1
)

REM Backup .env
echo [1/5] Backing up configuration...
if exist ".env" (
    copy .env .env.backup >nul
    echo       Configuration backed up.
) else (
    echo       No .env to backup.
)

REM Git pull
echo.
echo [2/5] Pulling latest changes...
git pull
if errorlevel 1 (
    echo       WARNING: Git pull failed (not a git repo or no changes)
) else (
    echo       Updated from repository.
)

REM Update Python dependencies
echo.
echo [3/5] Updating Python dependencies...
call .venv\Scripts\pip.exe install -r requirements.txt --upgrade >nul
if errorlevel 1 (
    echo       WARNING: Some dependencies may not have updated
) else (
    echo       Dependencies updated.
)

REM Database migration (if needed)
echo.
echo [4/5] Checking database...
if exist "data\aegis.db" (
    echo       Database exists - no migration needed.
) else (
    echo       Database will be created on next run.
)

REM Restore .env
echo.
echo [5/5] Restoring configuration...
if exist ".env.backup" (
    move .env.backup .env >nul
    echo       Configuration restored.
)

echo.
echo ========================================
echo   Update Complete!
echo ========================================
echo.
echo Run: run.bat
echo.

pause