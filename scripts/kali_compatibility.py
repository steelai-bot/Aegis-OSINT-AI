#!/usr/bin/env python3
"""Check Aegis compatibility with Kali Linux and recent Kali tools."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.core.kali_tools import (  # noqa: E402
    KALI_MIN_VERSION,
    KALI_RECENT_TOOLS,
    KALI_RELEASE_SOURCE_URLS,
    apt_install_command,
    detect_kali,
    inspect_recent_kali_tools,
)


def build_report() -> dict:
    return {
        "kali_min_version": KALI_MIN_VERSION,
        "sources": KALI_RELEASE_SOURCE_URLS,
        "profile": detect_kali(),
        "tools": inspect_recent_kali_tools(),
        "install_command": apt_install_command(KALI_RECENT_TOOLS),
    }


def print_text(report: dict) -> None:
    profile = report["profile"]
    print("Aegis Kali compatibility")
    print(f"  Kali detected: {profile['is_kali']}")
    print(f"  Version: {profile['version_id'] or 'unknown'}")
    print(f"  Compatible target: Kali {report['kali_min_version']}+")
    print(f"  Compatible: {profile['compatible']}")
    print()
    print("Recent Kali tool registry:")
    for tool in report["tools"]:
        available = "yes" if tool["command_available"] or tool["package_installed"] else "no"
        print(
            f"  - {tool['name']} ({tool['package']}, Kali {tool['release']}): "
            f"available={available}, policy={tool['aegis_policy']}"
        )
    print()
    print("Install missing packages on Kali:")
    print(f"  {report['install_command']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()

    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_text(report)


if __name__ == "__main__":
    main()
