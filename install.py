"""
Aegis OSINT AI - Unified Cross-Platform Installer
Usage:
    python install.py              # Setup only
    python install.py --run        # Setup + run server
    python install.py --update     # Update from git + reinstall deps
    python install.py --dev        # Setup with dev dependencies (pytest, ruff, mypy)
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def color(text: str, code: str) -> str:
    try:
        import colorama
        colorama.init()
        codes = {"green": "\033[92m", "cyan": "\033[96m", "yellow": "\033[93m", "red": "\033[91m", "bold": "\033[1m", "reset": "\033[0m"}
        return f"{codes.get(code, '')}{text}{codes.get('reset', '')}"
    except ImportError:
        return text


def step(num: int, total: int, msg: str):
    print(f"\n{color(f'[{num}/{total}]', 'cyan')} {msg}")


def ok(msg: str = "Done"):
    print(f"  {color('✓', 'green')} {msg}")


def warn(msg: str):
    print(f"  {color('!', 'yellow')} {msg}")


def fail(msg: str):
    print(f"  {color('✗', 'red')} {msg}")
    sys.exit(1)


def run(cmd: list, cwd: str = None, capture: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=capture, text=True, shell=platform.system() == "Windows")
    except FileNotFoundError:
        fail(f"Command not found: {cmd[0]}")


STEPS_SETUP = 8
STEPS_UPDATE = 5


def check_python():
    step(1, STEPS_SETUP, "Checking Python...")
    v = sys.version_info
    if v.major < 3 or (v.major == 3 and v.minor < 10):
        fail(f"Python 3.10+ required, found {v.major}.{v.minor}.{v.micro}")
    ok(f"Python {v.major}.{v.minor}.{v.micro}")


def create_venv():
    step(2, STEPS_SETUP, "Creating virtual environment...")
    venv_path = Path(".venv")
    if venv_path.exists():
        warn("Virtual environment already exists.")
        return
    result = run([sys.executable, "-m", "venv", ".venv"])
    if result.returncode != 0:
        fail("Failed to create virtual environment.")
    ok("Virtual environment created.")


def get_pip() -> str:
    if platform.system() == "Windows":
        return str(Path(".venv") / "Scripts" / "pip.exe")
    return str(Path(".venv") / "bin" / "pip")


def get_python() -> str:
    if platform.system() == "Windows":
        return str(Path(".venv") / "Scripts" / "python.exe")
    return str(Path(".venv") / "bin" / "python")


def upgrade_pip():
    step(3, STEPS_SETUP, "Upgrading pip...")
    result = run([get_pip(), "install", "--upgrade", "pip"])
    if result.returncode != 0:
        warn("Pip upgrade failed (non-fatal).")
    else:
        ok("Pip upgraded.")


def install_deps(dev: bool = False):
    step(4, STEPS_SETUP, "Installing Python dependencies...")
    result = run([get_pip(), "install", "-r", "requirements.txt"])
    if result.returncode != 0:
        fail(f"Failed to install dependencies:\n{result.stderr}")
    ok("Dependencies installed.")
    if dev:
        dev_pkgs = ["pytest", "pytest-asyncio", "respx", "mypy", "ruff"]
        step(4, STEPS_SETUP, "Installing dev dependencies...")
        result = run([get_pip(), "install"] + dev_pkgs)
        if result.returncode == 0:
            ok("Dev dependencies installed.")
        else:
            warn("Dev dependency install had issues (non-fatal).")


def create_dirs():
    step(5, STEPS_SETUP, "Creating directories...")
    for d in ["data", "reports"]:
        Path(d).mkdir(exist_ok=True)
    ok("Directories created.")


def setup_env():
    step(6, STEPS_SETUP, "Setting up configuration...")
    env_path = Path(".env")
    example_path = Path("config") / ".env.example"
    if env_path.exists():
        warn(".env already exists.")
        return
    if example_path.exists():
        shutil.copy(str(example_path), str(env_path))
        ok("Created .env from config/.env.example.")
    else:
        env_path.write_text("# Aegis OSINT AI Configuration\n", encoding="utf-8")
        warn("No config/.env.example found — created empty .env.")


def init_database():
    step(7, STEPS_SETUP, "Initializing database...")
    sys.path.insert(0, os.getcwd())
    try:
        from backend.main import init_db
        init_db()
        ok("Database initialized.")
    except Exception as e:
        warn(f"Database init skipped ({e}). Will be created on first run.")


def verify():
    step(8, STEPS_SETUP, "Verifying installation...")
    result = run([get_python(), "-c", "import fastapi; import sqlalchemy; print('OK')"])
    if result.returncode == 0:
        ok("Core modules verified.")
    else:
        fail(f"Verification failed:\n{result.stderr}")


def run_server():
    print(f"\n{color('Starting Aegis OSINT AI...', 'bold')}")
    os.chdir(Path(__file__).parent)
    result = run([get_python(), "-m", "backend.main"], capture=False)
    if result.returncode != 0:
        fail("Server exited with error.")


def do_update():
    print(f"\n{color('========================================', 'bold')}")
    print(f"{color('  Aegis OSINT AI - Update', 'bold')}")
    print(f"{color('========================================', 'bold')}")

    # 1. Backup .env
    step(1, STEPS_UPDATE, "Backing up configuration...")
    env_path = Path(".env")
    backup_path = Path(".env.backup")
    if env_path.exists():
        shutil.copy(str(env_path), str(backup_path))
        ok("Configuration backed up to .env.backup.")
    else:
        warn("No .env to backup.")

    # 2. Git pull
    step(2, STEPS_UPDATE, "Pulling latest changes...")
    result = run(["git", "pull"])
    if result.returncode == 0:
        ok("Updated from repository.")
    else:
        warn("Git pull failed (not a git repo or no changes).")

    # 3. Update deps
    step(3, STEPS_UPDATE, "Updating Python dependencies...")
    result = run([get_pip(), "install", "-r", "requirements.txt", "--upgrade"])
    if result.returncode == 0:
        ok("Dependencies updated.")
    else:
        warn("Some dependencies may not have updated.")

    # 4. Check DB
    step(4, STEPS_UPDATE, "Checking database...")
    if Path("data/aegis.db").exists():
        ok("Database exists.")
    else:
        warn("Database will be created on next run.")

    # 5. Restore .env
    step(5, STEPS_UPDATE, "Restoring configuration...")
    if backup_path.exists():
        shutil.move(str(backup_path), str(env_path))
        ok("Configuration restored.")
    else:
        warn("No backup to restore.")

    print(f"\n{color('Update complete!', 'green')} Run: python install.py --run")


def main():
    parser = argparse.ArgumentParser(description="Aegis OSINT AI - Unified Installer")
    parser.add_argument("--run", action="store_true", help="Setup + start server")
    parser.add_argument("--update", action="store_true", help="Update from git + reinstall deps")
    parser.add_argument("--dev", action="store_true", help="Include dev dependencies")
    args = parser.parse_args()

    if args.update:
        do_update()
        return

    print(f"\n{color('========================================', 'bold')}")
    print(f"{color('  Aegis OSINT AI - Setup', 'bold')}")
    print(f"{color('========================================', 'bold')}")

    check_python()
    create_venv()
    upgrade_pip()
    install_deps(dev=args.dev)
    create_dirs()
    setup_env()
    init_database()
    verify()

    print(f"\n{color('========================================', 'bold')}")
    print(f"{color('  Installation Complete!', 'green')}")
    print(f"{color('========================================', 'bold')}")
    print()
    print("  Next steps:")
    print(f"   1. Edit {color('.env', 'yellow')} and add your API keys")
    print(f"   2. Run: {color('python install.py --run', 'cyan')}")
    print(f"   3. Open: {color('http://localhost:8000', 'cyan')}")
    print()

    if args.run:
        run_server()


if __name__ == "__main__":
    main()
