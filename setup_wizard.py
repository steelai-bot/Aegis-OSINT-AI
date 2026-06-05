#!/usr/bin/env python3
"""
setup_wizard.py — Aegis-OSINT-AI
Automated installation wizard with system detection,
dependency checking, version validation, and guided setup.

Usage:
    python3 setup_wizard.py
    python3 setup_wizard.py --silent
    python3 setup_wizard.py --check-only
    python3 setup_wizard.py --upgrade
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
#  Colour helpers (no deps required)
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
def ok(msg):           print(f"  {c('✓', GREEN)}  {msg}")
def warn(msg):         print(f"  {c('⚠', YELLOW)}  {msg}")
def err(msg):          print(f"  {c('✗', RED)}  {msg}")
def info(msg):         print(f"  {c('→', CYAN)}  {msg}")
def section(title):    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}\n  {BOLD}{title}{RESET}\n{'─'*60}")
def banner():
    print(f"""
{CYAN}{BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║          AEGIS-OSINT-AI  —  Setup Wizard              ║
  ║     Australian Breach Intelligence Platform           ║
  ╚═══════════════════════════════════════════════════════╝
{RESET}""")


# ─────────────────────────────────────────────
#  Dependency Registry
# ─────────────────────────────────────────────

REQUIRED = [
    # (import_name, pip_name, min_version, critical)
    ("requests",        "requests>=2.31.0",          "2.31.0",  True),
    ("httpx",           "httpx>=0.27.0",              "0.27.0",  True),
    ("aiohttp",         "aiohttp>=3.9.0",             "3.9.0",   True),
    ("bs4",             "beautifulsoup4>=4.12.0",     "4.12.0",  True),
    ("lxml",            "lxml>=5.1.0",                "5.1.0",   True),
    ("dotenv",          "python-dotenv>=1.0.1",       "1.0.1",   True),
    ("rich",            "rich>=13.7.0",               "13.7.0",  True),
    ("tqdm",            "tqdm>=4.66.0",               "4.66.0",  True),
    ("click",           "click>=8.1.7",               "8.1.7",   True),
    ("loguru",          "loguru>=0.7.2",              "0.7.2",   True),
    ("tenacity",        "tenacity>=8.3.0",            "8.3.0",   True),
    ("pandas",          "pandas>=2.2.0",              "2.2.0",   True),
    ("numpy",           "numpy>=1.26.0",              "1.26.0",  True),
    ("jinja2",          "jinja2>=3.1.4",              "3.1.4",   True),
    ("openpyxl",        "openpyxl>=3.1.2",            "3.1.2",   True),
    ("tabulate",        "tabulate>=0.9.0",            "0.9.0",   True),
    ("dns",             "dnspython>=2.6.0",           "2.6.0",   True),
    ("whois",           "python-whois>=0.9.4",        "0.9.4",   True),
    ("psutil",          "psutil>=5.9.8",              "5.9.8",   True),
    ("cpuinfo",         "py-cpuinfo>=9.0.0",          "9.0.0",   True),
    # PDF
    ("fitz",            "PyMuPDF>=1.24.0",            "1.24.0",  True),
    ("pypdf",           "pypdf>=4.2.0",               "4.2.0",   False),
    ("pdfminer",        "pdfminer.six>=20221105",     "20221105",False),
    # Archives
    ("py7zr",           "py7zr>=0.21.0",              "0.21.0",  False),
    ("rarfile",         "rarfile>=4.1",               "4.1",     False),
    # Crypto
    ("cryptography",    "cryptography>=42.0.0",       "42.0.0",  True),
    ("passlib",         "passlib>=1.7.4",             "1.7.4",   False),
    # AI / HuggingFace
    ("transformers",    "transformers>=4.41.0",       "4.41.0",  False),
    ("huggingface_hub", "huggingface-hub>=0.23.0",    "0.23.0",  False),
    ("accelerate",      "accelerate>=0.30.0",         "0.30.0",  False),
    ("safetensors",     "safetensors>=0.4.3",         "0.4.3",   False),
    ("sentencepiece",   "sentencepiece>=0.2.0",       "0.2.0",   False),
    # GPU (optional)
    ("GPUtil",          "GPUtil>=1.4.0",              "1.4.0",   False),
]

SYSTEM_DEPS = {
    "tesseract": {"check": "tesseract --version", "install": {"apt": "tesseract-ocr", "brew": "tesseract", "yum": "tesseract"}},
    "git":       {"check": "git --version", "install": {"apt": "git", "brew": "git", "yum": "git"}},
}

LLAMA_CPP = ("llama_cpp", "llama-cpp-python>=0.2.77", "0.2.77", False)


# ─────────────────────────────────────────────
#  System Detection
# ─────────────────────────────────────────────

class SystemProfile:
    def __init__(self):
        self.os          = platform.system()          # Linux / Darwin / Windows
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
        self.pkg_manager = self._detect_pkg_manager()
        self.venv        = self._in_venv()
        self.pip_path    = self._find_pip()
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

    def _detect_pkg_manager(self):
        for mgr in ["apt", "apt-get", "yum", "dnf", "brew", "pacman"]:
            if shutil.which(mgr):
                return mgr
        return None

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
        ok(f"Python      : {sys.version.split()[0]}  @ {self.python_path}")
        ok(f"CPU         : {self.cpu_name}  ({self.cpu_cores} cores)")
        ok(f"RAM         : {self.ram_gb} GB  [{self.ram_tier()}]")
        ok(f"Disk free   : {self.disk_free} GB")
        if self.gpu_name:
            ok(f"GPU         : {self.gpu_name}  ({self.gpu_vram} GB VRAM)")
        else:
            info("GPU         : None detected — CPU inference mode")
        ok(f"Pkg manager : {self.pkg_manager or 'not detected'}")
        ok(f"Virtual env : {'yes' if self.venv else 'no (consider using one)'}")


# ─────────────────────────────────────────────
#  Python Version Check
# ─────────────────────────────────────────────

def check_python_version():
    section("Python Version")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 10):
        err(f"Python {major}.{minor} detected — Python 3.10+ required")
        print(f"\n  Install Python 3.11: https://www.python.org/downloads/")
        sys.exit(1)
    ok(f"Python {major}.{minor} — OK")


# ─────────────────────────────────────────────
#  Package Version Helpers
# ─────────────────────────────────────────────

def _parse_version(v):
    """Parse version string to comparable tuple."""
    try:
        return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])
    except Exception:
        return (0,)


def _installed_version(import_name):
    """Get installed version of a package."""
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
        # Map import name to dist name
        dist_map = {
            "bs4": "beautifulsoup4", "fitz": "PyMuPDF", "dotenv": "python-dotenv",
            "dns": "dnspython", "whois": "python-whois", "cpuinfo": "py-cpuinfo",
            "pdfminer": "pdfminer.six", "huggingface_hub": "huggingface-hub",
            "llama_cpp": "llama-cpp-python",
        }
        dist_name = dist_map.get(import_name, import_name)
        return importlib.metadata.version(dist_name)
    except Exception:
        return None


def _is_importable(import_name):
    return importlib.util.find_spec(import_name) is not None


def _version_ok(installed, required_min):
    if not installed:
        return False
    return _parse_version(installed) >= _parse_version(required_min)


# ─────────────────────────────────────────────
#  Dependency Checker
# ─────────────────────────────────────────────

def check_dependencies(silent=False):
    """
    Check all dependencies. Returns (missing, outdated, ok_list).
    """
    section("Dependency Check")

    missing  = []   # (import_name, pip_spec, critical)
    outdated = []   # (import_name, pip_spec, installed_ver, required_ver)
    ok_list  = []

    all_deps = REQUIRED + [LLAMA_CPP]

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
#  System Dependency Checker
# ─────────────────────────────────────────────

def check_system_deps(sys_profile):
    section("System Dependencies")
    results = {}
    for name, cfg in SYSTEM_DEPS.items():
        try:
            r = subprocess.run(
                cfg["check"].split(), capture_output=True, text=True, timeout=5
            )
            ver = r.stdout.split("\n")[0].strip() or r.stderr.split("\n")[0].strip()
            ok(f"{name:<15} {ver[:50]}")
            results[name] = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            install_hint = cfg["install"].get(sys_profile.pkg_manager or "apt", "")
            warn(f"{name:<15} not found  →  sudo {sys_profile.pkg_manager or 'apt'} install {install_hint}")
            results[name] = False
    return results


# ─────────────────────────────────────────────
#  Installer
# ─────────────────────────────────────────────

def install_packages(packages, pip_path, upgrade=False):
    """Install or upgrade a list of pip specs."""
    if not packages:
        return True

    flag = "--upgrade" if upgrade else ""
    specs = [p[1] for p in packages]  # pip_spec strings

    print()
    info(f"Installing {len(specs)} package(s)...")

    # Batch install
    cmd = f"{pip_path} install {flag} " + " ".join(f'"{s}"' for s in specs)
    result = subprocess.run(cmd, shell=True, capture_output=False, text=True)

    if result.returncode == 0:
        ok(f"All packages installed successfully")
        return True
    else:
        # Try one by one to identify failures
        failed = []
        for spec in specs:
            r = subprocess.run(
                f"{pip_path} install {flag} \"{spec}\"",
                shell=True, capture_output=True, text=True
            )
            if r.returncode != 0:
                failed.append(spec)
                err(f"Failed: {spec}")
            else:
                ok(f"Installed: {spec}")
        return len(failed) == 0


def install_llama_cpp(sys_profile):
    """Install llama-cpp-python with correct flags for the system."""
    section("llama-cpp-python (CPU Inference)")

    if _is_importable("llama_cpp"):
        v = _installed_version("llama_cpp")
        ok(f"Already installed: {v}")
        return True

    info("llama-cpp-python enables GGUF model inference on CPU")
    info("This may take 5-10 minutes to compile")

    if sys_profile.os == "Darwin":
        # Apple Silicon — Metal acceleration
        env = "CMAKE_ARGS=\"-DLLAMA_METAL=on\""
        info("Detected macOS — enabling Metal GPU acceleration")
    else:
        env = ""
        info("Installing CPU-only build (no CUDA required)")

    cmd = f"{env} {sys_profile.pip_path} install llama-cpp-python --no-cache-dir"
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0


# ─────────────────────────────────────────────
#  .env Setup
# ─────────────────────────────────────────────

ENV_TEMPLATE = """\
# ══════════════════════════════════════════════════════════════
#  Aegis-OSINT-AI — Environment Configuration
#  Generated by setup_wizard.py on {date}
# ══════════════════════════════════════════════════════════════

# ── Breach APIs ──────────────────────────────────────────────
HIBP_API_KEY=
DEHASHED_API_KEY=
DEHASHED_EMAIL=
LEAKCHECK_API_KEY=
INTELX_API_KEY=
SNUSBASE_API_KEY=
RAPIDAPI_KEY=

# ── Telegram ─────────────────────────────────────────────────

# ── Network ──────────────────────────────────────────────────
HTTP_PROXY=

# ── AI / HuggingFace ─────────────────────────────────────────
HF_TOKEN=
HF_CACHE_DIR=./models

# ── OAuth2 Providers ─────────────────────────────────────────
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

# ── Search APIs ───────────────────────────────────────────────
GITHUB_TOKEN=
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_CX=
BING_API_KEY=
BRAVE_API_KEY=
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
OTX_API_KEY=
HUNTER_API_KEY=
FULLCONTACT_API_KEY=
SECURITYTRAILS_API_KEY=
WHOISXML_API_KEY=
GREYNOISE_API_KEY=
"""

def setup_env_file(silent=False):
    section(".env Configuration")
    env_path = Path(".env")

    if env_path.exists():
        ok(".env already exists")
        if not silent:
            ans = input(f"  Overwrite? [y/N]: ").strip().lower()
            if ans != "y":
                info("Keeping existing .env")
                return
    else:
        info(".env not found — creating template")

    env_path.write_text(ENV_TEMPLATE.format(date=datetime.now().strftime("%Y-%m-%d %H:%M")))
    ok(".env created — fill in your API keys")
    info("Edit .env and add your keys before running scans")


# ─────────────────────────────────────────────
#  Directory Setup
# ─────────────────────────────────────────────

def setup_directories():
    section("Directory Structure")
    dirs = ["reports", "models", "logs", "exports", "uploads"]
    for d in dirs:
        Path(d).mkdir(exist_ok=True)
        ok(f"Created: {d}/")


# ─────────────────────────────────────────────
#  Post-Install Verification
# ─────────────────────────────────────────────

def verify_install():
    section("Post-Install Verification")
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


# ─────────────────────────────────────────────
#  AI Model Recommendation
# ─────────────────────────────────────────────

def show_ai_recommendations(sys_profile):
    section("AI Model Recommendations")
    ram = sys_profile.ram_gb

    info(f"Available RAM: {ram} GB  [{sys_profile.ram_tier()}]")
    print()

    models = [
        (64,  "llama-3.1-70b-instruct-GGUF",     "38 GB", "High quality local analysis"),
        (32,  "mixtral-8x7b-instruct-GGUF",      "26 GB", "Large local analysis model"),
        (16,  "mistral-7b-instruct-v0.3-GGUF",    "5 GB", "Fast local analysis"),
        (8,   "openhermes-2.5-mistral-7b-GGUF",   "5 GB", "General local analysis"),
        (4,   "Phi-3-mini-4k-instruct-gguf",      "3 GB", "Minimal footprint"),
        (0,   "tinyllama-1.1b-chat-v1.0-GGUF",   "1 GB", "Last resort, very limited"),
    ]

    print(f"  {'Model':<42} {'RAM':>6}  Description")
    print(f"  {'─'*42} {'─'*6}  {'─'*30}")
    for min_ram, name, size, desc in models:
        fits = ram >= min_ram
        marker = c("✓", GREEN) if fits else c("✗", DIM)
        print(f"  {marker} {name:<40} {size:>6}  {desc}")

    print()
    info("Run: python3 scripts/ai_modules.py --detect-hardware --select-model")


# ─────────────────────────────────────────────
#  Summary Report
# ─────────────────────────────────────────────

def print_summary(missing, outdated, sys_deps, install_ok):
    section("Setup Summary")

    critical_missing = [m for m in missing if m[2]]
    optional_missing = [m for m in missing if not m[2]]

    if not critical_missing and not outdated:
        ok(f"All critical dependencies installed")
    else:
        if critical_missing:
            err(f"{len(critical_missing)} critical packages missing")
        if outdated:
            warn(f"{len(outdated)} packages need upgrading")

    if optional_missing:
        info(f"{len(optional_missing)} optional packages not installed (run with --full to include)")

    info("Quarantined legacy network modules are not part of the v2 runtime")

    print()
    if install_ok and not critical_missing:
        print(f"  {c('✓ Setup complete!', GREEN)}")
        print(f"\n  {c('Quick start:', BOLD)}")
        print(f"  uvicorn backend.api.app:create_app --factory --reload")
        print(f"  python3 scripts/kali_compatibility.py --json")
        print(f"  python3 scripts/ai_modules.py --detect-hardware")
    else:
        print(f"  {c('⚠ Setup incomplete — fix errors above', YELLOW)}")
        print(f"  Re-run: python3 setup_wizard.py")
    print()


# ─────────────────────────────────────────────
#  Interactive Prompt
# ─────────────────────────────────────────────

def ask(prompt, default="y"):
    ans = input(f"  {prompt} [{default.upper() if default=='y' else default}/{default.upper() if default=='n' else default}]: ").strip().lower()
    return ans == "y" or (ans == "" and default == "y")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Aegis-OSINT-AI Setup Wizard")
    parser.add_argument("--silent",     action="store_true", help="Non-interactive mode, install all")
    parser.add_argument("--check-only", action="store_true", help="Check deps without installing")
    parser.add_argument("--upgrade",    action="store_true", help="Upgrade all packages to min versions")
    parser.add_argument("--full",       action="store_true", help="Include optional packages (AI, archives, etc.)")
    parser.add_argument("--no-llama",   action="store_true", help="Skip llama-cpp-python compilation")
    args = parser.parse_args()

    banner()

    # 1. Python version
    check_python_version()

    # 2. System profile
    sys_profile = SystemProfile()
    sys_profile.print()

    # 3. System deps (tesseract, git)
    sys_deps = check_system_deps(sys_profile)

    # 4. Python deps
    missing, outdated, ok_list = check_dependencies(silent=False)

    if args.check_only:
        print_summary(missing, outdated, sys_deps, True)
        sys.exit(0 if not [m for m in missing if m[2]] else 1)

    # 5. Offer to install
    install_ok = True

    critical_missing = [m for m in missing if m[2]]
    optional_missing = [m for m in missing if not m[2]]

    if critical_missing:
        section("Install Missing (Critical)")
        for _, spec, _ in critical_missing:
            info(spec)
        print()
        if args.silent or ask("Install critical packages?"):
            install_ok = install_packages(critical_missing, sys_profile.pip_path)

    if optional_missing and (args.full or args.silent):
        section("Install Missing (Optional)")
        for _, spec, _ in optional_missing:
            info(spec)
        print()
        if args.silent or ask("Install optional packages?"):
            install_packages(optional_missing, sys_profile.pip_path)

    if outdated:
        section("Upgrade Outdated Packages")
        for import_name, spec, installed, required in outdated:
            warn(f"{spec}  (installed: {installed}  →  required: {required})")
        print()
        if args.upgrade or args.silent or ask("Upgrade outdated packages?"):
            install_packages(outdated, sys_profile.pip_path, upgrade=True)

    # 6. llama-cpp-python
    if not args.no_llama:
        section("llama-cpp-python")
        if _is_importable("llama_cpp"):
            ok(f"Already installed: {_installed_version('llama_cpp')}")
        else:
            info("llama-cpp-python enables local GGUF model inference (CPU-only, no GPU needed)")
            if args.silent or ask("Install llama-cpp-python? (may take 5-10 min to compile)"):
                install_llama_cpp(sys_profile)

    # 7. .env setup
    setup_env_file(silent=args.silent)

    # 8. Directories
    setup_directories()

    # 9. Re-check after install
    if critical_missing or outdated:
        section("Re-checking After Install")
        missing2, outdated2, _ = check_dependencies(silent=True)
        install_ok = not [m for m in missing2 if m[2]]

    # 10. Verify
    verify_install()

    # 11. AI recommendations
    show_ai_recommendations(sys_profile)

    # 12. Summary
    print_summary(missing, outdated, sys_deps, install_ok)

    # 13. Save install log
    log = {
        "timestamp": datetime.now().isoformat(),
        "os": sys_profile.os,
        "python": sys.version,
        "ram_gb": sys_profile.ram_gb,
        "ram_tier": sys_profile.ram_tier(),
        "gpu": sys_profile.gpu_name,
        "missing_critical": [m[1] for m in missing if m[2]],
        "missing_optional": [m[1] for m in missing if not m[2]],
        "outdated": [o[1] for o in outdated],
        "sys_deps": sys_deps,
    }
    Path("logs").mkdir(exist_ok=True)
    with open("logs/setup_wizard.json", "w") as f:
        json.dump(log, f, indent=2)
    info("Install log saved to logs/setup_wizard.json")


if __name__ == "__main__":
    main()
