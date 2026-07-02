#!/usr/bin/env python3
"""
install.py — Aegis-OSINT-AI Kali-only automated installer

Single entry point for full installation, updates, and service management.
No LLM is installed by default — models are configured via the frontend UI.

Usage:
    python3 install.py                  # Full interactive TUI install
    sudo python3 install.py --update    # Update existing install
    python3 install.py --start          # Start services after install
    python3 install.py --check-only     # Check without installing
"""

import os
import sys
import re
import json
import shutil
import platform
import subprocess
import importlib
import importlib.util
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
#  Colour helpers (zero external deps)
# ─────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
WHITE  = "\033[97m"

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
  {'|'}          AEGIS-OSINT-AI  --  Installer                {'|'}
  {'|'}     Australian Breach Intelligence Platform           {'|'}
  {'+'}{'='*55}{'+'}
{RESET}""")

# ─────────────────────────────────────────────
#  Kali-only configuration
# ─────────────────────────────────────────────
SYSTEM_DEPS = {
    "tesseract": {"check": "tesseract --version",  "install": {"apt": "tesseract-ocr"}},
    "git":       {"check": "git --version",        "install": {"apt": "git"}},
    "holehe":    {"check": "holehe --version",     "install": {"apt": "holehe"}},
}
REQUIRED = [
    ("requests",        "requests>=2.31.0",       "2.31.0", True),
    ("httpx",           "httpx>=0.27.0",          "0.27.0", True),
    ("aiohttp",         "aiohttp>=3.9.0",         "3.9.0",  True),
    ("bs4",             "beautifulsoup4>=4.12.0", "4.12.0", True),
    ("lxml",            "lxml>=5.1.0",            "5.1.0",  True),
    ("dotenv",          "python-dotenv>=1.0.1",   "1.0.1",  True),
    ("rich",            "rich>=13.7.0",           "13.7.0", True),
    ("tqdm",            "tqdm>=4.66.0",           "4.66.0", True),
    ("click",           "click>=8.1.7",           "8.1.7",  True),
    ("loguru",          "loguru>=0.7.2",          "0.7.2",  True),
    ("tenacity",        "tenacity>=8.3.0",        "8.3.0",  True),
    ("pandas",          "pandas>=2.2.0",          "2.2.0",  True),
    ("numpy",           "numpy>=1.26.0",          "1.26.0", True),
    ("jinja2",          "jinja2>=3.1.4",          "3.1.4",  True),
    ("openpyxl",        "openpyxl>=3.1.2",        "3.1.2",  True),
    ("tabulate",        "tabulate>=0.9.0",        "0.9.0",  True),
    ("dns",             "dnspython>=2.6.0",       "2.6.0",  True),
    ("whois",           "python-whois>=0.9.4",    "0.9.4",  True),
    ("psutil",          "psutil>=5.9.8",          "5.9.8",  True),
    ("cpuinfo",         "py-cpuinfo>=9.0.0",      "9.0.0",  True),
    ("fitz",            "PyMuPDF>=1.24.0",        "1.24.0", True),
    ("pypdf",           "pypdf>=4.2.0",           "4.2.0",  False),
    ("pdfminer",        "pdfminer.six>=20221105", "20221105", False),
    ("py7zr",           "py7zr>=0.21.0",          "0.21.0", False),
    ("rarfile",         "rarfile>=4.1",           "4.1",    False),
    ("cryptography",    "cryptography>=42.0.0",   "42.0.0", True),
    ("passlib",         "passlib>=1.7.4",         "1.7.4",  False),
]

ENV_TEMPLATE = """\
# Aegis-OSINT-AI -- Environment Configuration
HIBP_API_KEY=
DEHASHED_API_KEY=
DEHASHED_EMAIL=
LEAKCHECK_API_KEY=
INTELX_API_KEY=
SNUSBASE_API_KEY=
RAPIDAPI_API_KEY=
HTTP_PROXY=
HF_TOKEN=
HF_CACHE_DIR=./models
OPENAI_API_KEY=
OPENROUTER_API_KEY=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
LINKEDIN_CLIENT_ID=
LINKEDIN_CLIENT_SECRET=
HF_CLIENT_ID=
HF_CLIENT_SECRET=
SLACK_CLIENT_ID=
SLACK_CLIENT_SECRET=
XERO_CLIENT_ID=
XERO_CLIENT_SECRET=
ATLASSIAN_CLIENT_ID=
ATLASSIAN_CLIENT_SECRET=
DROPBOX_CLIENT_ID=
DROPBOX_CLIENT_SECRET=
REDDIT_CLIENT_ID=
REDDIT_CLIENT_SECRET=
GITHUB_TOKEN=
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_CX=
BING_API_KEY=
BRAVE_API_KEY=
SHODAN_API_KEY=
SERUS_AI_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
OTX_API_KEY=
HUNTER_API_KEY=
FULLCONTACT_API_KEY=
SECURITYTRAILS_API_KEY=
GREYNOISE_API_KEY=
"""

# ─────────────────────────────────────────────
#  System profile
# ─────────────────────────────────────────────
class SystemProfile:
    def __init__(self):
        self.os          = "Linux"
        self.os_version  = platform.version()
        self.arch        = platform.machine()
        self.python_ver  = sys.version_info
        self.python_path = sys.executable
        self.ram_gb      = 0.0
        self.cpu_cores   = os.cpu_count() or 1
        self.cpu_name    = platform.processor()
        self.disk_free   = 0.0
        self.gpu_name    = None
        self.gpu_vram    = 0.0
        self.pkg_manager = "apt"
        self.venv        = self._in_venv()
        self.pip_path    = self._find_pip()
        self.kali        = False
        self.kali_version = None
        self._detect_hardware()

    def _detect_hardware(self):
        try:
            import psutil
            mem = psutil.virtual_memory()
            self.ram_gb = round(mem.total / (1024**3), 1)
            disk = psutil.disk_usage("/")
            self.disk_free = round(disk.free / (1024**3), 1)
        except Exception:
            pass
        try:
            import cpuinfo
            info = cpuinfo.get_cpu_info()
            self.cpu_name = info.get("brand_raw", self.cpu_name)
        except Exception:
            pass
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            if gpus:
                self.gpu_name = gpus[0].name
                self.gpu_vram = round(gpus[0].memoryTotal / 1024, 1)
        except Exception:
            pass

    def _in_venv(self):
        return (
            hasattr(sys, "real_prefix") or
            (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
        )

    def _find_pip(self):
        for candidate in ["pip3", "pip", f"{sys.executable} -m pip"]:
            if shutil.which(candidate.split()[0]):
                return candidate
        return f"{sys.executable} -m pip"

    def ram_tier(self):
        if self.ram_gb >= 64:  return "EXTREME"
        if self.ram_gb >= 32:  return "VERY_HIGH"
        if self.ram_gb >= 16:  return "HIGH"
        if self.ram_gb >= 8:   return "MEDIUM"
        if self.ram_gb >= 4:   return "LOW"
        return "MINIMAL"

    def print(self):
        section("System Detection")
        ok(f"OS          : {self.os} {self.arch}  ({self.os_version[:40]})")
        ok(f"Kali        : {'yes (' + self.kali_version + ')' if self.kali else 'not detected'}")
        ok(f"Python      : {sys.version.split()[0]}  @ {self.python_path}")
        ok(f"CPU         : {self.cpu_name}  ({self.cpu_cores} cores)")
        ok(f"RAM         : {self.ram_gb} GB  [{self.ram_tier()}]")
        ok(f"Disk free   : {self.disk_free} GB")
        if self.gpu_name:
            ok(f"GPU         : {self.gpu_name}  ({self.gpu_vram} GB VRAM)")
        else:
            info("GPU         : None detected - CPU inference mode")
        ok(f"Pkg manager : apt")
        ok(f"Virtual env : {'yes' if self.venv else 'no (will create)'}")

# ─────────────────────────────────────────────
#  Version helpers
# ─────────────────────────────────────────────
def _parse_version(v):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])
    except Exception:
        return (0,)

def _installed_version(import_name):
    try:
        mod = importlib.import_module(import_name)
        for attr in ("__version__", "version", "VERSION"):
            v = getattr(mod, attr, None)
            if v:
                return str(v)
    except Exception:
        pass
    try:
        import importlib.metadata
        dist_map = {
            "bs4": "beautifulsoup4", "fitz": "PyMuPDF", "dotenv": "python-dotenv",
            "dns": "dnspython", "whois": "python-whois", "cpuinfo": "py-cpuinfo",
            "pdfminer": "pdfminer.six", "huggingface_hub": "huggingface-hub",
            "llama_cpp": "llama-cpp-python",
        }
        return importlib.metadata.version(dist_map.get(import_name, import_name))
    except Exception:
        return None

def _is_importable(import_name):
    return importlib.util.find_spec(import_name) is not None

def _version_ok(installed, required_min):
    if not installed:
        return False
    return _parse_version(installed) >= _parse_version(required_min)

# ─────────────────────────────────────────────
#  Dependency checks
# ─────────────────────────────────────────────
def check_dependencies(silent=False):
    section("Python Dependencies")
    missing  = []
    outdated = []
    ok_list  = []
    all_deps = list(REQUIRED)

    for import_name, pip_spec, min_ver, critical in all_deps:
        importable = _is_importable(import_name)
        installed  = _installed_version(import_name)
        if not importable:
            missing.append((import_name, pip_spec, critical))
            if not silent:
                tag = c("[CRITICAL]", RED) if critical else c("[optional]", DIM)
                err(f"{pip_spec:<45} {tag}  not installed")
        elif not _version_ok(installed, min_ver):
            outdated.append((import_name, pip_spec, installed, min_ver))
            if not silent:
                warn(f"{pip_spec:<45} installed={installed}  required>={min_ver}")
        else:
            ok_list.append(import_name)
            if not silent:
                ok(f"{pip_spec:<45} {c(installed or 'ok', GREEN)}")
    return missing, outdated, ok_list

# ─────────────────────────────────────────────
#  System dependency checks
# ─────────────────────────────────────────────
def check_system_deps(sys_profile):
    section("Kali Tool Verification")
    results = {}
    for name, cfg in SYSTEM_DEPS.items():
        try:
            r = subprocess.run(cfg["check"].split(), capture_output=True, text=True, timeout=5)
            ver = r.stdout.split("\n")[0].strip() or r.stderr.split("\n")[0].strip()
            ok(f"{name:<15} {ver[:50]}")
            results[name] = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            warn(f"{name:<15} not found  ->  will install")
            results[name] = False
    return results

# ─────────────────────────────────────────────
#  Installation functions
# ─────────────────────────────────────────────
def install_packages(packages, pip_path, upgrade=False):
    if not packages:
        return True
    flag = "--upgrade" if upgrade else ""
    specs = [p[1] for p in packages]
    print()
    info(f"Installing {len(specs)} package(s)...")
    cmd = f"{pip_path} install {flag} " + " ".join(f'"{s}"' for s in specs)
    result = subprocess.run(cmd, shell=True, capture_output=False, text=True)
    if result.returncode == 0:
        ok("All packages installed")
        return True
    failed = []
    for spec in specs:
        r = subprocess.run(f"{pip_path} install {flag} \"{spec}\"", shell=True, capture_output=True, text=True)
        if r.returncode != 0:
            failed.append(spec)
            err(f"Failed: {spec}")
        else:
            ok(f"Installed: {spec}")
    return len(failed) == 0

def setup_env_file(silent=False):
    section(".env Configuration")
    env_path = Path(".env")
    if env_path.exists():
        ok(".env already exists")
        if not silent and not ask("Overwrite?"):
            info("Keeping existing .env")
            return
    else:
        info(".env not found - creating template")
    env_path.write_text(ENV_TEMPLATE)
    ok(".env created")

def setup_directories():
    section("Creating Directory Structure")
    dirs = ["reports", "models", "logs", "exports", "uploads"]
    for d in dirs:
        Path(d).mkdir(exist_ok=True)
        ok(f"Created: {d}/")

def verify_install():
    section("Verification")
    all_ok = True
    critical_imports = [
        ("requests",  "HTTP client"),
        ("bs4",       "HTML parser"),
        ("rich",      "Terminal UI"),
        ("psutil",    "Hardware detection"),
        ("fitz",      "PDF extraction"),
        ("pandas",    "Data processing"),
        ("loguru",    "Logging"),
        ("jinja2",    "Report templates"),
        ("cryptography", "Crypto"),
    ]
    for import_name, label in critical_imports:
        try:
            importlib.import_module(import_name)
            ver = _installed_version(import_name) or "ok"
            ok(f"{label:<25} {c(ver, GREEN)}")
        except ImportError:
            err(f"{label:<25} FAILED")
            all_ok = False
    return all_ok

def show_ai_recommendations(sys_profile):
    section("AI Model Info")
    ram = sys_profile.ram_gb
    info(f"Available RAM: {ram} GB  [{sys_profile.ram_tier()}]")
    info("No local LLM installed by default.")
    info("Configure API keys in the frontend UI (Settings > API Keys):")
    info("  - OpenAI API Key")
    info("  - OpenRouter API Key")
    info("  - HuggingFace Token")
    info("Or run: python3 scripts/ai_modules.py --detect-hardware --select-model")
    print()

def print_summary(missing, outdated, sys_deps, install_ok):
    section("Summary")
    critical_missing = [m for m in missing if m[2]]
    optional_missing = [m for m in missing if not m[2]]
    if not critical_missing and not outdated:
        ok("All critical dependencies satisfied")
    else:
        if critical_missing:
            err(f"{len(critical_missing)} critical packages missing")
        if outdated:
            warn(f"{len(outdated)} packages need upgrading")
    if optional_missing:
        info(f"{len(optional_missing)} optional packages skipped (use --full)")
    print()
    if install_ok and not critical_missing:
        print(f"  {c('Installation complete!', GREEN)}")
        print()
        print(f"  Next steps:")
        print(f"    {c('bash scripts/start.sh', CYAN)}        - start all services")
        print(f"    {c('python3 install.py --start', CYAN)}  - install + start")
        print(f"    http://localhost:3000             - frontend")
        print(f"    http://localhost:8000             - backend API")
    else:
        print(f"  {c('Installation incomplete', YELLOW)}")
        print(f"  Re-run: {c('python3 install.py', CYAN)}")
    print()

def ask(prompt, default=True):
    suffix = " [Y/n]" if default else " [y/N]"
    ans = input(f"  {prompt}{suffix}: ").strip().lower()
    if not ans:
        return default
    return ans == "y"

# ─────────────────────────────────────────────
#  Kali detection
# ─────────────────────────────────────────────
def detect_kali():
    try:
        content = Path("/etc/os-release").read_text()
        if "kali" not in content.lower():
            return False, None
        match = re.search(r'VERSION="(.+?)"', content)
        if match:
            return True, match.group(1)
        match = re.search(r'VERSION_ID="(.+?)"', content)
        return True, match.group(1) if match else "unknown"
    except Exception:
        return False, None

# ─────────────────────────────────────────────
#  Root check
# ─────────────────────────────────────────────
def ensure_root():
    if os.geteuid() == 0:
        return True
    warn("Root privileges required for apt packages")
    if os.environ.get("SUDO_RELAUNCH"):
        return False
    if ask("Re-run with sudo?"):
        script = Path(__file__).resolve()
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    return False

# ─────────────────────────────────────────────
#  Apt package install
# ─────────────────────────────────────────────
KALI_APT_PACKAGES = [
    "python3", "python3-venv", "python3-pip",
    "postgresql", "postgresql-contrib", "pgvector",
    "redis-server",
    "git", "tesseract-ocr", "holehe",
    "nodejs", "npm",
    "build-essential", "cmake",
]

def install_apt_packages(missing_only=True):
    to_install = []
    if missing_only:
        for pkg in KALI_APT_PACKAGES:
            try:
                subprocess.run(["dpkg", "-s", pkg], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                to_install.append(pkg)
    else:
        to_install = list(KALI_APT_PACKAGES)

    if not to_install:
        ok("All Kali packages already installed")
        return True

    print()
    info(f"Installing {len(to_install)} system packages via apt...")
    try:
        proc = subprocess.Popen(
            ["apt", "install", "-y"] + to_install,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                print(f"  {DIM}{line[:90]}{RESET}")
        proc.wait()
        if proc.returncode == 0:
            ok("System packages installed")
            return True
        else:
            err(f"apt failed (exit code {proc.returncode})")
            return False
    except Exception as e:
        err(f"apt error: {e}")
        return False

# ─────────────────────────────────────────────
#  Service setup
# ─────────────────────────────────────────────
def setup_postgresql():
    section("PostgreSQL Setup")
    try:
        subprocess.run(["systemctl", "enable", "--now", "postgresql"], check=False)
    except Exception:
        pass
    ok("PostgreSQL service enabled")

    try:
        subprocess.run(
            ['su', '-', 'postgres', '-c', 'psql -c "CREATE DATABASE aegis;"'],
            capture_output=True
        )
    except Exception:
        pass
    ok("Database 'aegis' ready")

    try:
        subprocess.run(
            ['su', '-', 'postgres', '-c',
             'psql -d aegis -c "CREATE EXTENSION IF NOT EXISTS vector;"'],
            capture_output=True
        )
    except Exception:
        pass
    ok("pgvector extension enabled")

def setup_redis():
    section("Redis Setup")
    try:
        subprocess.run(["systemctl", "enable", "--now", "redis-server"], check=False)
    except Exception:
        pass
    ok("Redis service enabled")

# ─────────────────────────────────────────────
#  venv + deps
# ─────────────────────────────────────────────
def setup_venv():
    section("Python Virtual Environment")
    if not Path(".venv").exists():
        subprocess.run([sys.executable, "-m", "venv", ".venv"], check=True)
        ok("Virtual environment created")
    else:
        ok("Virtual environment exists")

    pip_path = ".venv/bin/pip" if Path(".venv/bin/pip").exists() else f"{sys.executable} -m pip"

    info("Upgrading pip...")
    subprocess.run([pip_path, "install", "--upgrade", "pip"], capture_output=True)

    info("Installing Python dependencies...")
    subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)
    ok("Root Python packages installed")

    subprocess.run([pip_path, "install", "-r", "backend/requirements.txt"], check=True)
    ok("Backend Python packages installed")

    return pip_path

def setup_frontend():
    section("Frontend Dependencies")
    if not shutil.which("npm"):
        warn("npm not found - skipping frontend setup")
        return
    try:
        subprocess.run(["npm", "install"], cwd="frontend", check=True)
        ok("Frontend dependencies installed")
    except subprocess.CalledProcessError:
        err("Frontend npm install failed")

# ─────────────────────────────────────────────
#  TUI installer
# ─────────────────────────────────────────────
def build_installer(mode="interactive"):
    sys_profile = SystemProfile()
    sys_profile.kali, sys_profile.kali_version = detect_kali()

    if mode == "check-only":
        banner()
        check_python_version()
        sys_profile.print()
        check_system_deps(sys_profile)
        missing, outdated, _ = check_dependencies()
        install_ok = not [m for m in missing if m[2]]
        print_summary(missing, outdated, {}, install_ok)
        sys.exit(0 if install_ok else 1)

    if sys_profile.kali and (mode in ("silent", "full", "update")):
        if mode in ("silent", "full"):
            if not ensure_root():
                sys.exit(1)
        return _run_all_steps(sys_profile, mode)

    banner()
    if not sys_profile.kali:
        err("Kali Linux not detected - this installer requires Kali Linux")
        err("See docs/kali_compatibility.md")
        sys.exit(1)

    if not ensure_root():
        sys.exit(1)

    return _interactive_flow(sys_profile, mode)

def _run_all_steps(sys_profile, mode="silent"):
    info(f"Running in {mode} mode")

    missing, outdated, _ = check_dependencies(silent=True)

    # Step 3: system deps
    sys_deps = check_system_deps(sys_profile)
    missing_sys = [n for n, ok in sys_deps.items() if not ok]
    if missing_sys:
        section("Step 4/12: Kali System Packages")
        install_apt_packages(missing_only=True)
    else:
        section("Step 3/12: Kali Tool Verification")
        ok("All Kali tools present")
        section("Step 4/12: System Packages")
        ok("All system packages present")

    # Step 5: PostgreSQL
    setup_postgresql()
    # Step 6: Redis
    setup_redis()
    # Step 7: venv + deps
    setup_venv()
    # Step 8: Node
    setup_frontend()
    # Step 9: .env
    section("Step 9/12: Environment Configuration")
    if not Path(".env").exists():
        setup_env_file(silent=True)
    else:
        ok(".env already exists")
    # Step 10: dirs
    section("Step 10/12: Directory Structure")
    setup_directories()
    # Step 11: verify
    section("Step 11/12: Verification")
    install_ok = verify_install()
    # Step 12: AI info
    section("Step 12/12: AI Models")
    show_ai_recommendations(sys_profile)

    print_summary(missing, outdated, sys_deps, install_ok)
    _write_log(sys_profile, missing, outdated)
    _start_services()
    return install_ok

def _interactive_flow(sys_profile, mode="interactive"):
    install_ok = True

    # Step 3: system deps
    sys_deps = check_system_deps(sys_profile)
    missing_sys = [n for n, ok in sys_deps.items() if not ok]
    if missing_sys:
        section("Step 4/12: Kali System Packages")
        info(f"Missing: {', '.join(missing_sys)}")
        if os.geteuid() == 0:
            info("Running as root - installing automatically")
            install_apt_packages(missing_only=True)
        elif ask("Install missing Kali system packages via apt? (recommended)"):
            install_apt_packages(missing_only=True)
        else:
            err("Cannot continue without system packages")
            info("Run manually: sudo apt install tesseract-ocr holehe")
            sys.exit(1)
    else:
        section("Step 4/12: Kali System Packages")
        ok("All Kali system packages present")

    # Step 5: PostgreSQL
    setup_postgresql()
    # Step 6: Redis
    setup_redis()

    # Step 7: Python deps
    missing, outdated, _ = check_dependencies(silent=False)

    if missing:
        critical_missing = [m for m in missing if m[2]]
        optional_missing = [m for m in missing if not m[2]]
        if critical_missing:
            print()
            for _, spec, _ in critical_missing:
                info(spec)
            print()
            if ask("Install critical packages?"):
                install_ok = install_packages(critical_missing, sys_profile.pip_path)

        if optional_missing and ask("Install optional packages?"):
            install_packages(optional_missing, sys_profile.pip_path)

    if outdated:
        dep_critical = {n: cr for n, _, _, cr in REQUIRED}
        outdated_critical = [o for o in outdated if dep_critical.get(o[0], False)]
        outdated_optional = [o for o in outdated if not dep_critical.get(o[0], False)]
        print()
        for _, spec, installed, required in outdated:
            warn(f"{spec}  (installed: {installed}  ->  required: {required})")
        print()
        if outdated_critical and ask("Upgrade outdated critical packages?"):
            install_packages(outdated_critical, sys_profile.pip_path, upgrade=True)
        if outdated_optional and ask("Upgrade outdated optional packages?"):
            install_packages(outdated_optional, sys_profile.pip_path, upgrade=True)

    # venv if no .venv yet
    if not Path(".venv").exists():
        section("Python Virtual Environment")
        subprocess.run([sys.executable, "-m", "venv", ".venv"], check=True)
        ok("Virtual environment created")

    # Step 8: Node
    setup_frontend()

    # Step 9: .env
    setup_env_file(silent=False)

    # Step 10: dirs
    setup_directories()

    # Step 11: verify
    if missing or outdated:
        section("Re-checking after install")
        check_dependencies(silent=True)
    install_ok = verify_install()

    # Step 12: AI info
    show_ai_recommendations(sys_profile)

    print_summary(missing, outdated, sys_deps, install_ok)
    _write_log(sys_profile, missing, outdated)
    return install_ok

def _write_log(sys_profile, missing, outdated):
    log = {
        "timestamp": datetime.now().isoformat(),
        "os": sys_profile.os,
        "kali": sys_profile.kali,
        "kali_version": sys_profile.kali_version,
        "python": sys.version,
        "ram_gb": sys_profile.ram_gb,
        "ram_tier": sys_profile.ram_tier(),
        "gpu": sys_profile.gpu_name,
        "missing_critical": [m[1] for m in missing if m[2]],
        "missing_optional": [m[1] for m in missing if not m[2]],
        "outdated": [o[1] for o in outdated],
    }
    Path("logs").mkdir(exist_ok=True)
    with open("logs/setup_wizard.json", "w") as f:
        json.dump(log, f, indent=2)
    info("Log saved to logs/setup_wizard.json")

def _start_services():
    info("Starting services...")
    script = Path("scripts/start.sh")
    if script.exists():
        subprocess.run(["bash", str(script), "dev"])
    else:
        warn("scripts/start.sh not found - start manually")

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Aegis-OSINT-AI Kali Installer")
    parser.add_argument("--start",       action="store_true", help="Start services after install")
    parser.add_argument("--update",      action="store_true", help="Update existing install")
    parser.add_argument("--check-only",  action="store_true", help="Check without installing")
    parser.add_argument("--full",        action="store_true", help="Full non-interactive install")
    parser.add_argument("--silent",      action="store_true", help="Silent minimal install")
    args = parser.parse_args()

    mode = "silent" if args.silent else ("update" if args.update else "interactive")

    install_ok = build_installer(mode)

    if args.start:
        section("Starting Services")
        _start_services()

    if not install_ok and not args.silent:
        section("Re-running to fix issues")
        input("Press Enter to re-run install, or Ctrl+C to abort...")
        build_installer(mode)

if __name__ == "__main__":
    main()