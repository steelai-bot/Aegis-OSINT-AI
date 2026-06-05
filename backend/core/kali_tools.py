"""Kali Linux compatibility and tool discovery metadata.

The registry tracks Kali release tools that Aegis can detect and prepare for
operator-guided workflows. It intentionally does not grant autonomous execution
for offensive tooling.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
import shutil
import subprocess


KALI_MIN_VERSION = "2026.1"
KALI_RELEASE_SOURCE_URLS = (
    "https://www.kali.org/blog/kali-linux-2026-1-release/",
    "https://www.kali.org/blog/kali-linux-2025-4-release/",
)


@dataclass(frozen=True)
class KaliTool:
    """One Kali package that Aegis knows how to discover."""

    name: str
    package: str
    command: str
    release: str
    purpose: str
    aegis_policy: str


KALI_RECENT_TOOLS: tuple[KaliTool, ...] = (
    KaliTool(
        name="AdaptixC2",
        package="adaptixc2",
        command="adaptixc2",
        release="2026.1",
        purpose="Adversary emulation framework.",
        aegis_policy="manual_review_only",
    ),
    KaliTool(
        name="Atomic-Operator",
        package="atomic-operator",
        command="atomic-operator",
        release="2026.1",
        purpose="Runs Atomic Red Team tests across environments.",
        aegis_policy="manual_review_only",
    ),
    KaliTool(
        name="Fluxion",
        package="fluxion",
        command="fluxion",
        release="2026.1",
        purpose="Wireless security auditing and social-engineering research.",
        aegis_policy="manual_review_only",
    ),
    KaliTool(
        name="GEF",
        package="gef",
        command="gef",
        release="2026.1",
        purpose="GDB enhancement framework for debugging and triage.",
        aegis_policy="operator_assisted",
    ),
    KaliTool(
        name="MetasploitMCP",
        package="metasploit-mcp",
        command="metasploit-mcp",
        release="2026.1",
        purpose="MCP server for Metasploit.",
        aegis_policy="disabled_by_default",
    ),
    KaliTool(
        name="SSTImap",
        package="sstimap",
        command="sstimap",
        release="2026.1",
        purpose="Server-side template injection detection.",
        aegis_policy="manual_review_only",
    ),
    KaliTool(
        name="WPProbe",
        package="wpprobe",
        command="wpprobe",
        release="2026.1",
        purpose="WordPress plugin enumeration.",
        aegis_policy="passive_metadata_only",
    ),
    KaliTool(
        name="XSStrike",
        package="xsstrike",
        command="xsstrike",
        release="2026.1",
        purpose="XSS scanner.",
        aegis_policy="manual_review_only",
    ),
    KaliTool(
        name="bpf-linker",
        package="bpf-linker",
        command="bpf-linker",
        release="2025.4",
        purpose="Static linker for BPF programs.",
        aegis_policy="operator_assisted",
    ),
    KaliTool(
        name="evil-winrm-py",
        package="evil-winrm-py",
        command="evil-winrm-py",
        release="2025.4",
        purpose="Python WinRM command execution client.",
        aegis_policy="disabled_by_default",
    ),
    KaliTool(
        name="hexstrike-ai",
        package="hexstrike-ai",
        command="hexstrike-ai",
        release="2025.4",
        purpose="MCP server that lets AI agents run security tools.",
        aegis_policy="disabled_by_default",
    ),
)


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Read Linux os-release metadata without requiring third-party packages."""

    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def detect_kali(os_release: dict[str, str] | None = None) -> dict[str, str | bool | None]:
    """Return a compact Kali compatibility profile."""

    data = os_release if os_release is not None else read_os_release()
    distro_id = (data.get("ID") or "").lower()
    version_id = data.get("VERSION_ID")
    is_kali = distro_id == "kali" or "kali" in (data.get("VERSION_CODENAME") or "").lower()
    return {
        "is_linux": platform.system().lower() == "linux",
        "is_kali": is_kali,
        "version_id": version_id,
        "compatible": bool(is_kali and version_id and version_id >= KALI_MIN_VERSION),
    }


def is_package_installed(package: str) -> bool:
    """Check Debian package installation status when dpkg is available."""

    if shutil.which("dpkg-query") is None:
        return False
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Status}", package],
        capture_output=True,
        text=True,
        check=False,
    )
    return "install ok installed" in result.stdout


def inspect_recent_kali_tools() -> list[dict[str, str | bool]]:
    """Inspect command/package availability for recent Kali release tools."""

    inspected: list[dict[str, str | bool]] = []
    for tool in KALI_RECENT_TOOLS:
        inspected.append(
            {
                "name": tool.name,
                "package": tool.package,
                "command": tool.command,
                "release": tool.release,
                "purpose": tool.purpose,
                "aegis_policy": tool.aegis_policy,
                "command_available": shutil.which(tool.command) is not None,
                "package_installed": is_package_installed(tool.package),
            }
        )
    return inspected


def apt_install_command(tools: tuple[KaliTool, ...] = KALI_RECENT_TOOLS) -> str:
    """Build the documented apt command for the registry."""

    packages = " ".join(tool.package for tool in tools)
    return f"sudo apt update && sudo apt install -y {packages}"
