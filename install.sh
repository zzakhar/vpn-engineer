#!/usr/bin/env bash
# VPN Engineer 1-Click Installer for Linux & macOS
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$(which python3 || which python)"

if [ -z "$PYTHON_BIN" ]; then
    echo "[-] Python 3 is required but not found. Please install python3."
    exit 1
fi

"$PYTHON_BIN" "$SCRIPT_DIR/install.py"
