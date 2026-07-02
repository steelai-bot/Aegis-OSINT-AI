#!/usr/bin/env python3
"""
aegis-manager.py — Aegis-OSINT-AI Unified Management Tool

A single entry point for:
- Installation (integrates existing install.py)
- Uninstallation & Cleanup (removes all Aegis-related files and services)
- Automatic Updates (pulls from repo, updates deps, restarts services)
- Service Management (start/stop)
"""

import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path

# ─────────────────────────────────────────────
#  Colour helpers
# ─────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

def c(text, colour):   return f"{colour}{text}{RESET}"
def ok(msg):           print(f"  {c('OK', GREEN)}  {msg}")
def warn(msg):         print(f"  {c('!!', YELLOW)}  {msg}")
def err(msg):          print(f"  {c('XX', RED)}  {msg}")
def info(msg):         print(f"  {c('->', CYAN)}  {msg}")
def section(title):    print(f"\n{BOLD}{CYAN}{'-'*60}{RESET}\n  {BOLD}{title}{RESET}\n{'-'*60}")

def banner():
    print(f"""
{CYAN}{BOLD}
  {'+'}{'='*55}{'+'}
  {'|'}          AEGIS-OSINT-AI  --  Manager                {'|'}
  {'|'}     Unified Lifecycle & Update Tool                 {'|'}
  {'+'}{'='*55}{'+'}
{RESET}""")

# ─────────────────────────────────────────────
#  Core Logic
# ─────────────────────────────────────────────

def run_cmd(cmd, shell=True, capture=False):
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=capture, text=True)
        return result
    except Exception as e:
        err(f"Command failed: {e}")
        return None

def stop_services():
    section("Stopping Services")
    stop_script = Path("scripts/stop.sh")
    if stop_script.exists():
        info("Executing scripts/stop.sh...")
        run_cmd(f"bash {stop_script}")
        ok("Services stopped")
    else:
        warn("scripts/stop.sh not found, skipping")

def start_services():
    section("Starting Services")
    start_script = Path("scripts/start.sh")
    if start_script.exists():
        info("Executing scripts/start.sh...")
        run_cmd(f"bash {start_script} dev")
        ok("Services started in dev mode")
    else:
        err("scripts/start.sh not found")

def install_app():
    section("Installing Application")
    if Path("install.py").exists():
        info("Launching install.py...")
        subprocess.run([sys.executable, "install.py"])
        ok("Installation process completed")
    else:
        err("install.py not found in current directory")

def update_app():
    section("Updating Aegis-OSINT-AI")
    
    # 1. Stop services
    stop_services()

    # 2. Git Update
    info("Updating source code from repository...")
    run_cmd("git stash")
    res = run_cmd("git pull origin main")
    if res and res.returncode == 0:
        ok("Source code updated successfully")
    else:
        err("Git pull failed")
        return

    # 3. Refresh Dependencies
    info("Refreshing Python dependencies...")
    if Path(".venv/bin/pip").exists():
        run_cmd(".venv/bin/pip install --upgrade pip")
        run_cmd(".venv/bin/pip install -r requirements.txt")
        run_cmd(".venv/bin/pip install -r backend/requirements.txt")
        ok("Python dependencies updated")
    else:
        warn("Virtual environment not found, please run 'install' first")

    info("Refreshing Frontend dependencies...")
    if Path("frontend").exists():
        run_cmd("npm install", shell=False, capture=False) # Note: npm install needs cwd
        # Correcting npm install to run in frontend dir
        subprocess.run(["npm", "install"], cwd="frontend")
        ok("Frontend dependencies updated")

    # 4. Restart services
    start_services()
    ok("Update complete!")

def uninstall_app(full_cleanup=False):
    section("Uninstalling Aegis-OSINT-AI")
    
    stop_services()

    # Directories to remove
    dirs_to_remove = [
        ".venv",
        "reports",
        "models",
        "logs",
        "exports",
        "uploads",
    ]
    
    files_to_remove = [".env"]

    for d in dirs_to_remove:
        path = Path(d)
        if path.exists() and path.is_dir():
            info(f"Removing directory {d}...")
            shutil.rmtree(path)
            ok(f"Removed {d}")

    for f in files_to_remove:
        path = Path(f)
        if path.exists():
            info(f"Removing file {f}...")
            path.unlink()
            ok(f"Removed {f}")

    if full_cleanup:
        section("System Cleanup (Optional)")
        info("Removing system-level dependencies via apt...")
        # Only remove things we know we installed
        apt_pkgs = ["tesseract-ocr", "holehe"]
        run_cmd(f"sudo apt remove -y {' '.join(apt_pkgs)}")
        run_cmd("sudo apt autoremove -y")
        ok("System cleanup completed")

    ok("Uninstallation complete. The application has been removed.")

# ─────────────────────────────────────────────
#  CLI Interface
# ─────────────────────────────────────────────

def print_help():
    print(f"""
Usage: python3 aegis-manager.py [command]

Commands:
  install    Run the full installation wizard
  update     Stop services, pull latest code, update deps, and restart
  uninstall  Remove application files and data
  uninstall --full  Remove application files and system apt packages
  start      Start all services
  stop       Stop all services
  help       Show this help message
    """)

def main():
    banner()
    if len(sys.argv) < 2:
        print_help()
        return

    cmd = sys.argv[1].lower()

    if cmd == "install":
        install_app()
    elif cmd == "update":
        update_app()
    elif cmd == "uninstall":
        full = "--full" in sys.argv
        uninstall_app(full)
    elif cmd == "start":
        start_services()
    elif cmd == "stop":
        stop_services()
    elif cmd == "help":
        print_help()
    else:
        err(f"Unknown command: {cmd}")
        print_help()

if __name__ == "__main__":
    main()