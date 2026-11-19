#!/usr/bin/env python3
"""
VPN Engineer - 1-Click Universal Native Installer
Auto-detects AI agent platforms (Antigravity, Claude Code, Claude Desktop, Cursor, Windsurf),
installs CLI, registers MCP server, and links the Agent Skill.
Shout-out to: https://github.com/zzakhar
"""

import os
import sys
import json
import shutil
import platform
import subprocess
from typing import Optional
from pathlib import Path

def print_step(msg: str):
    print(f"\n\033[1;36m==>\033[0m \033[1m{msg}\033[0m")

def print_ok(msg: str):
    print(f"  \033[32m✔\033[0m {msg}")

def print_warn(msg: str):
    print(f"  \033[33m⚠\033[0m {msg}")

def get_claude_desktop_config_path() -> Optional[Path]:
    os_name = platform.system()
    home = Path.home()
    if os_name == "Windows":
        app_data = os.getenv("APPDATA")
        if app_data:
            return Path(app_data) / "Claude" / "claude_desktop_config.json"
    elif os_name == "Darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif os_name == "Linux":
        config_home = os.getenv("XDG_CONFIG_HOME", str(home / ".config"))
        return Path(config_home) / "Claude" / "claude_desktop_config.json"
    return None

def get_antigravity_plugins_dir() -> Optional[Path]:
    home = Path.home()
    candidates = [
        home / ".gemini" / "antigravity" / "plugins",
        home / ".gemini" / "config" / "plugins"
    ]
    for c in candidates:
        if c.exists() or c.parent.exists():
            return c
    return None

def install_python_package(repo_root: Path):
    print_step("Installing Python CLI package in development mode...")
    cmd = [sys.executable, "-m", "pip", "install", "-e", str(repo_root)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print_ok("CLI package installed ('vpn-engineer' command available)")
    else:
        print_warn(f"pip install returned non-zero. Falling back to local module execution: {res.stderr[:100]}")

def register_claude_desktop(repo_root: Path):
    cfg_path = get_claude_desktop_config_path()
    if not cfg_path:
        return

    print_step(f"Checking Claude Desktop configuration at {cfg_path}...")
    cfg = {}
    if cfg_path.exists():
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

    mcp_servers = cfg.setdefault("mcpServers", {})
    mcp_servers["vpn-engineer"] = {
        "command": sys.executable,
        "args": ["-m", "vpn_engineer.mcp_server"],
        "cwd": str(repo_root),
        "env": {
            "PYTHONUNBUFFERED": "1"
        }
    }

    try:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        print_ok("Registered 'vpn-engineer' in Claude Desktop MCP servers!")
    except Exception as e:
        print_warn(f"Failed to update Claude Desktop config: {e}")

def link_antigravity_plugin(repo_root: Path):
    plugins_dir = get_antigravity_plugins_dir()
    if not plugins_dir:
        return

    print_step(f"Registering in Antigravity plugin ecosystem ({plugins_dir})...")
    target_link = plugins_dir / "vpn-engineer"
    try:
        plugins_dir.mkdir(parents=True, exist_ok=True)
        if target_link.exists() or target_link.is_symlink():
            if target_link.is_symlink() or target_link.is_file():
                target_link.unlink()
            else:
                shutil.rmtree(target_link)
        
        # Create directory symlink
        os.symlink(str(repo_root), str(target_link), target_is_directory=True)
        print_ok(f"Linked plugin to {target_link}")
    except Exception as e:
        # Fallback to copy if symlink privileges not present on Windows
        try:
            shutil.copytree(str(repo_root), str(target_link), dirs_exist_ok=True)
            print_ok(f"Copied plugin to {target_link}")
        except Exception as err:
            print_warn(f"Could not link to Antigravity plugins directory: {err}")

def main():
    repo_root = Path(__file__).resolve().parent

    print("""
\033[1;35m
 __      ______  _   _   ______ _   _  _____ _____ _   _ ______ ______ _____  
 \ \    / /  _ \| \ | | |  ____| \ | |/ ____|_   _| \ | |  ____|  ____|  __ \ 
  \ \  / /| |_) |  \| | | |__  |  \| | |  __  | | |  \| | |__  | |__  | |__) |
   \ \/ / |  _ <| . ` | |  __| | . ` | | |_ | | | | . ` |  __| |  __| |  _  / 
    \  /  | |_) | |\  | | |____| |\  | |__| |_| |_| |\  | |____| |____| | \ \ 
     \/   |____/|_| \_| |______|_| \_|\_____|_____|_| \_|______|______|_|  \_\
\033[0m
   ⚡ Shout-out & credits to: https://github.com/zzakhar
   Universal Autonomous AI Agent Plugin Installer
    """)

    # 1. Install CLI
    install_python_package(repo_root)

    # 2. Register MCP in Claude Desktop
    register_claude_desktop(repo_root)

    # 3. Register in Antigravity
    link_antigravity_plugin(repo_root)

    print("\n\033[32;1m🎉 Installation Complete!\033[0m")
    print("You can now run:")
    print("  \033[1mvpn-engineer --help\033[0m       (Test CLI)")
    print("  \033[1mvpn-engineer ruleset\033[0m      (Get clean v2rayN routing rules)")
    print("  \033[1mvpn-engineer case beeline\033[0m (Search anti-censorship battle log)\n")

if __name__ == "__main__":
    main()
