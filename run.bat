@echo off
REM Run Aegis OSINT AI using local virtual environment
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe -m backend.main
) else (
    echo Local .venv not found. Run setup.bat first.
    pause
    exit /b 1
)
if errorlevel 1 pause
