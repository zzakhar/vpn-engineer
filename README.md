# VPN Engineer

[🇷🇺 Читать документацию на русском языке](README_RU.md)

Universal Autonomous AI Agent Plugin & Engineering Toolkit for Anti-Censorship VPN Infrastructure.

[![CI](https://github.com/zzakhar/vpn-engineer/actions/workflows/ci.yml/badge.svg)](https://github.com/zzakhar/vpn-engineer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://www.python.org/)

> **Credits:** Built with battle-tested field intelligence and lessons learned.  
> Special shout-out to [zzakhar](https://github.com/zzakhar).

---

![VPN Engineer Banner](assets/banner.png)

## Overview

**VPN Engineer** transforms hard-won, real-world network engineering insights into a standardized, reusable toolset for both human engineers and autonomous AI agents (such as Antigravity, Claude Code, Cursor, Windsurf, and Claude Desktop).

Instead of relying on fragile scripts or random trial-and-error edits, VPN Engineer provides:

1. **Agent Skill (`SKILL.md`):** An intelligent, interactive "Grill-Me" diagnostic playbook that guides AI agents to methodically verify servers, test for DPI/TSPU throttling, and validate solutions.
2. **MCP Server (`mcp_server.py`):** A standard JSON-RPC 2.0 Stdio Model Context Protocol server exposing 10+ typed tools for deep server auditing, firewall rules, automated backups, and configuration repairs.
3. **Unified CLI (`vpn-engineer`):** A command-line utility for human operators and script automation.

---

## Key Capabilities

- **Intelligent 10-Step Diagnostician:** Generates ranked hypotheses with confidence scores instead of guessing. Distinguishes between server outages and regional ISP middlebox throttling.
- **Port 443 Throttling Bypasses:** Multi-port Nginx fronting supporting standard and alternative TLS ports (2053, 8443, 2083, 2087, 2096).
- **UDP / QUIC Port-Hopping:** Automated iptables NAT PREROUTING rules (ports 20000–50000) for Hysteria 2 to defeat stateful mobile operator throttling.
- **Zero-Downtime Safety:** Mandatory syntax pre-checks (`nginx -t`, `xray run -test -conf`), atomic file substitutions, and automated rollback upon detected failures.
- **Client Routing Profiles:** Ready-to-use routing rulesets for v2rayN and NekoBox that keep local domestic traffic direct while routing foreign and AI services through the secure tunnel.

---

## Architecture

```
vpn-engineer/
├── assets/                  # Project imagery and graphics
├── skills/
│   └── vpn-engineer/
│       └── SKILL.md         # Native Agent Skill instructions
├── vpn_engineer/
│   ├── cli.py               # Command line entry point
│   ├── mcp_server.py        # Model Context Protocol stdio server
│   ├── core/
│   │   ├── auditor.py       # Host OS, binaries, ports, and certificates
│   │   ├── backup_manager.py# Versioned configuration snapshots & rollback
│   │   ├── diagnostician.py # Multi-stage diagnostic pipeline
│   │   ├── ip_checker.py    # GeoIP and censorship signature analysis
│   │   ├── repair_engine.py # Atomic remediation and syntax validation
│   │   └── ssh_client.py    # Safe remote SSH execution
│   ├── knowledge/
│   │   ├── battle_log.py    # Distilled field intelligence cases
│   │   └── rulesets.py      # Client-side traffic routing configurations
│   └── protocols/
│       ├── firewall.py      # iptables NAT port-hopping manager
│       ├── hysteria2.py     # Hysteria 2 protocol adapter
│       ├── nginx.py         # Multi-port reverse proxy adapter
│       └── xray.py          # Xray VLESS (gRPC & WebSocket) adapter
├── tests/                   # Automated pytest suite
└── install.py               # Universal 1-click cross-platform installer
```

---

## Quick Start

### 🌟 1-Prompt AI Installation (Recommended)

You don't even need to touch the command line. Just copy and send this prompt to your AI assistant (**Antigravity**, **Claude Code**, **Cursor**, **Windsurf**):

```text
Install and configure this plugin for yourself: https://github.com/zzakhar/vpn-engineer
```

The AI will automatically clone the repository, link the Agent Skill, register the MCP server tools, and immediately interview you to set up or troubleshoot your VPN!

---

### Manual / Local CLI Installation

Run the universal installer to automatically configure the CLI and register the MCP server with detected AI clients:

```bash
# On Linux / macOS
bash install.sh

# On Windows PowerShell
.\install.ps1
```

Or install manually via pip:

```bash
pip install -e .
```

### 2. Command Line Usage

```bash
# Display project banner and version
vpn-engineer version

# Output clean v2rayN client routing rules
vpn-engineer ruleset

# Search the anti-censorship field intelligence log
vpn-engineer case beeline

# Audit a remote VPS
vpn-engineer audit --host 1.2.3.4 --user root --password mypass

# Run the 10-step doctor diagnostic pipeline
vpn-engineer doctor --host 1.2.3.4 --domain mydomain.com

# Create an atomic backup snapshot on the server
vpn-engineer backup --host 1.2.3.4 --reason "Before upgrading Xray"

# Rollback to the previous configuration
vpn-engineer rollback --host 1.2.3.4
```

---

## MCP Server Integration

To use with Claude Desktop or any compatible MCP client, add the following to your configuration file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vpn-engineer": {
      "command": "python",
      "args": ["-m", "vpn_engineer.mcp_server"],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

---

## Testing

Run the automated test suite with pytest:

```bash
pytest tests
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
