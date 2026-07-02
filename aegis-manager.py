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
  {'+'}{'='*55