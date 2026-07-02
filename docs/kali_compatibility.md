# Kali Linux Compatibility

Aegis v2 is built for Kali Linux 2026.1 or newer only. The project no longer
supports Docker, Windows, or macOS. It runs directly on Kali using native
services and Kali tools.

Authoritative release sources:

- https://www.kali.org/blog/kali-linux-2026-1-release/
- https://www.kali.org/blog/kali-linux-2025-4-release/
- https://www.kali.org/docs/general-use/updating-kali/

## Baseline

- Kali Linux 2026.1 or newer, fully updated
- Python 3.12+
- Project virtual environment for Python dependencies
- PostgreSQL + pgvector
- Redis
- Node.js + npm

Check the host:

```bash
grep VERSION /etc/os-release
uname -r
python3 --version
python3 scripts/kali_compatibility.py
```

## Native Kali Setup

Use the Kali-only setup flow:

```bash
sudo bash scripts/setup-kali.sh
bash scripts/start.sh
```

For updates:

```bash
sudo bash scripts/install_or_update.sh
```

## Recent Kali Tool Registry

The current registry covers the 11 new tools from Kali 2026.1 and Kali 2025.4,
which satisfies the requested "last 10-15" recent Kali updates without relying
on unofficial package lists.

| Tool | Kali release | Package | Aegis policy |
| --- | --- | --- | --- |
| AdaptixC2 | 2026.1 | `adaptixc2` | Manual review only |
| Atomic-Operator | 2026.1 | `atomic-operator` | Manual review only |
| Fluxion | 2026.1 | `fluxion` | Manual review only |
| GEF | 2026.1 | `gef` | Operator assisted |
| MetasploitMCP | 2026.1 | `metasploit-mcp` | Disabled by default |
| SSTImap | 2026.1 | `sstimap` | Manual review only |
| WPProbe | 2026.1 | `wpprobe` | Passive metadata only |
| XSStrike | 2026.1 | `xsstrike` | Manual review only |
| bpf-linker | 2025.4 | `bpf-linker` | Operator assisted |
| evil-winrm-py | 2025.4 | `evil-winrm-py` | Disabled by default |
| hexstrike-ai | 2025.4 | `hexstrike-ai` | Disabled by default |

Install the registry packages on Kali:

```bash
sudo apt update && sudo apt install -y adaptixc2 atomic-operator fluxion gef metasploit-mcp sstimap wpprobe xsstrike bpf-linker evil-winrm-py hexstrike-ai
```

## Safety Boundary

Aegis v2 remains a defensive OSINT framework. The Kali registry is for
compatibility checks, package discovery, and operator-controlled workflows.
Tools that can execute exploitation, post-exploitation, credential access, or
autonomous tool chains must stay disabled by default and require explicit human
approval outside the normal OSINT pipeline.

## Machine-Readable Check

Use JSON output for CI or deployment checks:

```bash
python3 scripts/kali_compatibility.py --json
```

The report includes Kali detection, version compatibility, package/command
availability, release source URLs, and the apt install command.
