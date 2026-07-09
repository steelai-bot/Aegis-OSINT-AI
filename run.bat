@echo off
REM Aegis OSINT AI - Windows Run Script
REM Starts the backend server and opens the browser

setlocal enabledelayedexpansion

echo.
echo ========================================
echo   Aegis OSINT AI - Starting
echo ========================================
echo.

REM Check if .venv exists
if not exist ".venv" (
    echo ERROR: Virtual environment not found.
    echo Please run setup.bat first.
    pause
    exit /b 1
)

REM Check if .env exists
if not exist ".env" (
    echo WARNING: .env not found. Using default configuration.
)

REM Start backend server
echo.
echo [1/2] Starting backend server...
start "Aegis Backend" /min cmd /c "call .venv\Scripts\python.exe -m backend.main"

REM Wait for server to start
echo [2/2] Waiting for server to be ready...
timeout /t 3 /nobreak >nul

REM Check if server is running
:check_server
curl -s http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    echo       Waiting for server...
    timeout /t 2 /nobreak >nul
    goto check_server
)

echo       Server is running!

REM Open browser
echo.
echo Opening browser...
start http://localhost:8000

echo.
echo ========================================
echo   Aegis OSINT AI is running!
echo ========================================
echo.
echo Backend: http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server.
echo.

REM Keep window open
pause