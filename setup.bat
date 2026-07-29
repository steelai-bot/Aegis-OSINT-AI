@echo off
REM Setup Aegis OSINT AI - creates local .venv and installs dependencies
python install.py %*
if errorlevel 1 pause
