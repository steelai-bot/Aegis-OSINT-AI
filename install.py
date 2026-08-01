"""Aegis OSINT AI - unified cross-platform installer.

Usage:
    python install.py              # Setup only
    python install.py --run        # Setup + run server
    python install.py --update     # Pull latest code + reinstall dependencies
    python install.py --dev        # Setup with development dependencies
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
VENV_DIR = PROJECT_ROOT / ".venv"
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"
DEV_REQUIREMENTS = PROJECT_ROOT / "requirements-dev.txt"
PACKAGE_LOCK = PROJECT_ROOT / "package-lock.json"

STEPS_SETUP = 9
STEPS_UPDATE = 6

CORE_MODULES = (
    "fastapi",
    "uvicorn",
    "pydantic",
    "pydantic_settings",
    "jinja2",
    "aiosqlite",
    "reportlab",
)


def color(text: str, code: str) -> str:
    codes = {
        "green": "\033[92m",
        "cyan": "\033[96m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    if not sys.stdout.isatty():
        return text
    return f"{codes.get(code, '')}{text}{codes['reset']}"


def step(num: int, total: int, msg: str) -> None:
    print(f"\n{color(f'[{num}/{total}]', 'cyan')} {msg}")


def ok(msg: str = "Done") -> None:
    print(f"  {color('✓', 'green')} {msg}")


def warn(msg: str) -> None:
    print(f"  {color('!', 'yellow')} {msg}")


def fail(msg: str) -> None:
    print(f"  {color('✗', 'red')} {msg}")
    sys.exit(1)


def run(cmd: list[str], cwd: Path | None = None, capture: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd or PROJECT_ROOT),
            capture_output=capture,
            text=True,
            shell=False,
            check=False,
        )
    except FileNotFoundError:
        fail(f"Command not found: {cmd[0]}")


def venv_python() -> str:
    if platform.system() == "Windows":
        return str(VENV_DIR / "Scripts" / "python.exe")
    return str(VENV_DIR / "bin" / "python")


def check_python() -> None:
    step(1, STEPS_SETUP, "Checking Python...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 12):
        fail(
            "Python 3.12+ is required. "
            f"Found {version.major}.{version.minor}.{version.micro}."
        )
    ok(f"Python {version.major}.{version.minor}.{version.micro}")


def create_venv() -> None:
    step(2, STEPS_SETUP, "Creating virtual environment...")
    if VENV_DIR.exists():
        warn("Virtual environment already exists.")
        return

    result = run([sys.executable, "-m", "venv", str(VENV_DIR)])
    if result.returncode != 0:
        fail(f"Failed to create virtual environment:\n{result.stderr}")
    ok("Virtual environment created in .venv.")


def upgrade_pip() -> None:
    step(3, STEPS_SETUP, "Upgrading pip...")
    result = run([venv_python(), "-m", "pip", "install", "--upgrade", "pip"])
    if result.returncode != 0:
        warn("Pip upgrade failed (non-fatal).")
        if result.stderr:
            warn(result.stderr.strip())
        return
    ok("Pip upgraded.")


def install_deps(dev: bool = False, upgrade: bool = False) -> None:
    step(4, STEPS_SETUP, "Installing Python dependencies...")
    if not REQUIREMENTS.exists():
        fail("requirements.txt not found.")

    cmd = [venv_python(), "-m", "pip", "install", "-r", str(REQUIREMENTS)]
    if upgrade:
        cmd.append("--upgrade")
    result = run(cmd)
    if result.returncode != 0:
        fail(f"Failed to install runtime dependencies:\n{result.stderr}")
    ok("Runtime dependencies installed.")

    if dev:
        if not DEV_REQUIREMENTS.exists():
            warn("requirements-dev.txt not found - skipping dev dependencies.")
            return
        result = run([venv_python(), "-m", "pip", "install", "-r", str(DEV_REQUIREMENTS)])
        if result.returncode != 0:
            fail(f"Failed to install dev dependencies:\n{result.stderr}")
        ok("Dev dependencies installed.")


def create_dirs() -> None:
    step(5, STEPS_SETUP, "Creating runtime directories...")
    for directory in ("data", "reports", "data/reports"):
        (PROJECT_ROOT / directory).mkdir(parents=True, exist_ok=True)
    ok("Runtime directories ready.")


def build_css() -> None:
    step(6, STEPS_SETUP, "Building Tailwind CSS...")
    if shutil.which("npm") is None:
        warn("npm not found - skipping Tailwind build. Commit-generated CSS will be used if present.")
        return

    install_cmd = ["npm", "ci"] if PACKAGE_LOCK.exists() else ["npm", "install"]
    result = run(install_cmd)
    if result.returncode != 0 and install_cmd == ["npm", "ci"]:
        warn("npm ci failed - retrying with npm install.")
        result = run(["npm", "install"])
    if result.returncode != 0:
        warn("npm dependency install failed (non-fatal).")
        if result.stderr:
            warn(result.stderr.strip())
        return

    result = run(["npm", "run", "build:css"])
    if result.returncode != 0:
        warn("Tailwind build failed (non-fatal).")
        if result.stderr:
            warn(result.stderr.strip())
        return
    ok("Tailwind CSS built.")


def setup_env() -> None:
    step(7, STEPS_SETUP, "Setting up configuration...")
    env_path = PROJECT_ROOT / ".env"
    example_path = PROJECT_ROOT / "config" / ".env.example"
    if env_path.exists():
        warn(".env already exists.")
        return

    if example_path.exists():
        shutil.copy(str(example_path), str(env_path))
        ok("Created .env from config/.env.example.")
        return

    env_path.write_text("# Aegis OSINT AI Configuration\n", encoding="utf-8")
    warn("No config/.env.example found - created minimal .env.")


def init_database() -> None:
    step(8, STEPS_SETUP, "Initializing database...")
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from backend.main import init_db

        init_db()
        ok("Database initialized.")
    except Exception as exc:  # pragma: no cover - defensive installer path
        warn(f"Database init skipped ({exc}). It will be created on first run.")


def verify() -> None:
    step(9, STEPS_SETUP, "Verifying installation...")
    imports = "; ".join(f"import {module}" for module in CORE_MODULES)
    result = run([venv_python(), "-c", f"{imports}; print('OK')"])
    if result.returncode != 0:
        fail(f"Verification failed:\n{result.stderr}")
    ok("Core modules verified.")


def run_server() -> None:
    print(f"\n{color('Starting Aegis OSINT AI...', 'bold')}")
    result = run([venv_python(), "-m", "backend.main"], capture=False)
    if result.returncode != 0:
        fail("Server exited with error.")


def setup(dev: bool = False, upgrade: bool = False) -> None:
    print(f"\n{color('========================================', 'bold')}")
    print(f"{color('  Aegis OSINT AI - Setup', 'bold')}")
    print(f"{color('========================================', 'bold')}")

    check_python()
    create_venv()
    upgrade_pip()
    install_deps(dev=dev, upgrade=upgrade)
    create_dirs()
    build_css()
    setup_env()
    init_database()
    verify()


def do_update(dev: bool = False) -> None:
    print(f"\n{color('========================================', 'bold')}")
    print(f"{color('  Aegis OSINT AI - Update', 'bold')}")
    print(f"{color('========================================', 'bold')}")

    step(1, STEPS_UPDATE, "Backing up configuration...")
    env_path = PROJECT_ROOT / ".env"
    backup_path = PROJECT_ROOT / ".env.backup"
    if env_path.exists():
        shutil.copy(str(env_path), str(backup_path))
        ok("Configuration backed up to .env.backup.")
    else:
        warn("No .env to backup.")

    step(2, STEPS_UPDATE, "Pulling latest changes...")
    if (PROJECT_ROOT / ".git").exists() and shutil.which("git") is not None:
        result = run(["git", "pull", "--ff-only"])
        if result.returncode == 0:
            ok("Updated from repository.")
        else:
            warn("Git pull failed or local changes require manual resolution.")
            if result.stderr:
                warn(result.stderr.strip())
    else:
        warn("Not a git checkout or git is unavailable - skipping pull.")

    step(3, STEPS_UPDATE, "Updating Python dependencies...")
    if not VENV_DIR.exists():
        warn(".venv not found - creating it first.")
        create_venv()
    install_deps(dev=dev, upgrade=True)

    step(4, STEPS_UPDATE, "Rebuilding Tailwind CSS...")
    build_css()

    step(5, STEPS_UPDATE, "Checking database...")
    if (PROJECT_ROOT / "data" / "aegis.db").exists():
        ok("Database exists.")
    else:
        warn("Database will be created on next run.")

    step(6, STEPS_UPDATE, "Restoring configuration...")
    if backup_path.exists():
        shutil.move(str(backup_path), str(env_path))
        ok("Configuration restored.")
    else:
        warn("No backup to restore.")

    print(f"\n{color('Update complete!', 'green')} Run: python install.py --run")


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis OSINT AI - Unified Installer")
    parser.add_argument("--run", action="store_true", help="Setup + start the server")
    parser.add_argument("--update", action="store_true", help="Update from git + reinstall dependencies")
    parser.add_argument("--dev", action="store_true", help="Install development dependencies")
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)

    if args.update:
        do_update(dev=args.dev)
        return

    setup(dev=args.dev)

    print(f"\n{color('========================================', 'bold')}")
    print(f"{color('  Installation Complete!', 'green')}")
    print(f"{color('========================================', 'bold')}")
    print("\n  Next steps:")
    print(f"   1. Edit {color('.env', 'yellow')} and add your API keys")
    print(f"   2. Run: {color('python install.py --run', 'cyan')}")
    print(f"   3. Open: {color('http://localhost:8000', 'cyan')}")

    if args.run:
        run_server()


if __name__ == "__main__":
    main()
