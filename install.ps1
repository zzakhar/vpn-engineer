# VPN Engineer 1-Click Installer for Windows PowerShell
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Get-Command python.exe -ErrorAction SilentlyContinue

if (-not $Python) {
    Write-Error "Python 3 is required but not found in PATH."
    exit 1
}

& python.exe "$ScriptDir\install.py"
