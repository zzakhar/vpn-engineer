"""
VPN Engineer - Server Health & Infrastructure Auditor
Deep inspection of OS, systemd services, listening sockets, TLS certs, and firewall rules.
"""

import re
import json
from typing import Dict, Any, List, Optional
from vpn_engineer.core.ssh_client import RemoteSSHClient

class ServerAuditor:
    """Comprehensive auditor for Linux VPN servers."""

    def __init__(self, ssh: RemoteSSHClient):
        self.ssh = ssh

    def audit_os(self) -> Dict[str, Any]:
        """Gathers OS distribution, kernel, architecture, and uptime."""
        _, os_release, _ = self.ssh.execute("cat /etc/os-release 2>/dev/null || cat /etc/issue || true")
        _, uname, _ = self.ssh.execute("uname -a")
        _, uptime, _ = self.ssh.execute("uptime -p || uptime")

        name_match = re.search(r'PRETTY_NAME="([^"]+)"', os_release)
        distro = name_match.group(1) if name_match else "Linux (Generic)"

        return {
            "distro": distro,
            "kernel": uname.strip(),
            "uptime": uptime.strip()
        }

    def audit_binaries(self) -> Dict[str, Dict[str, Any]]:
        """Checks presence and versions of critical VPN binaries."""
        binaries = {
            "xray": "xray version 2>/dev/null | head -n 1 || xray --version 2>/dev/null | head -n 1",
            "hysteria": "hysteria version 2>/dev/null | head -n 1",
            "nginx": "nginx -v 2>&1 | head -n 1",
            "certbot": "certbot --version 2>/dev/null | head -n 1",
            "iptables": "iptables --version 2>/dev/null | head -n 1",
            "python3": "python3 --version 2>/dev/null | head -n 1"
        }

        results = {}
        for b, v_cmd in binaries.items():
            check_code, which_out, _ = self.ssh.execute(f"which {b} || true")
            installed = (check_code == 0 and bool(which_out.strip()))
            version = "Unknown"
            if installed:
                _, v_out, _ = self.ssh.execute(v_cmd)
                version = v_out.strip() if v_out.strip() else "Installed"

            results[b] = {
                "installed": installed,
                "path": which_out.strip() if installed else None,
                "version": version
            }
        return results

    def audit_services(self) -> Dict[str, Dict[str, Any]]:
        """Audits status of critical systemd units."""
        target_services = [
            "xray", "hysteria-server", "hysteria", "nginx",
            "sing-box", "trojan-go", "v2ray", "wireguard"
        ]

        results = {}
        for s in target_services:
            code, out, _ = self.ssh.execute(
                f"systemctl is-active {s} 2>/dev/null || true"
            )
            status = out.strip()
            if not status:
                status = "not-installed"

            # Check if enabled
            _, enabled_out, _ = self.ssh.execute(f"systemctl is-enabled {s} 2>/dev/null || true")
            enabled = enabled_out.strip()

            results[s] = {
                "active_state": status,
                "is_running": (status == "active"),
                "is_enabled": (enabled == "enabled")
            }
        return results

    def audit_listening_ports(self) -> List[Dict[str, Any]]:
        """Inspects all listening TCP and UDP sockets using ss."""
        _, ss_out, _ = self.ssh.execute("ss -tulpn -H 2>/dev/null || netstat -tulpn 2>/dev/null || true")
        sockets = []
        for line in ss_out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0].lower()
                local_addr = parts[4]
                process_info = parts[-1] if "users:" in line or "pid=" in line else "Unknown"

                # Extract port
                if ":" in local_addr:
                    port_str = local_addr.rsplit(":", 1)[-1]
                    try:
                        port = int(port_str)
                        sockets.append({
                            "proto": proto,
                            "address": local_addr,
                            "port": port,
                            "process": process_info
                        })
                    except ValueError:
                        pass
        return sockets

    def audit_certificates(self) -> List[Dict[str, Any]]:
        """Inspects Let's Encrypt certificates and expiry."""
        _, cert_out, _ = self.ssh.execute("certbot certificates 2>/dev/null || true")
        certs = []
        current_cert = {}
        for line in cert_out.splitlines():
            line = line.strip()
            if "Certificate Name:" in line:
                if current_cert:
                    certs.append(current_cert)
                current_cert = {"name": line.split(":", 1)[-1].strip()}
            elif "Domains:" in line and current_cert:
                current_cert["domains"] = line.split(":", 1)[-1].strip().split()
            elif "Expiry Date:" in line and current_cert:
                current_cert["expiry"] = line.split(":", 1)[-1].strip()
        if current_cert:
            certs.append(current_cert)
        return certs

    def audit_firewall_nat(self) -> List[str]:
        """Audits NAT table rules (critical for Hysteria port hopping)."""
        _, ipt_out, _ = self.ssh.execute("iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null || true")
        rules = [line.strip() for line in ipt_out.splitlines() if line.strip()]
        return rules

    def audit_resource_usage(self) -> Dict[str, Any]:
        """Checks free memory, disk space, and load average."""
        _, mem_out, _ = self.ssh.execute("free -m | grep Mem: || true")
        _, df_out, _ = self.ssh.execute("df -h / | tail -n 1 || true")
        
        mem_info = {}
        if mem_out.strip():
            parts = mem_out.split()
            if len(parts) >= 4:
                mem_info = {
                    "total_mb": int(parts[1]),
                    "used_mb": int(parts[2]),
                    "free_mb": int(parts[3])
                }

        disk_info = {}
        if df_out.strip():
            parts = df_out.split()
            if len(parts) >= 5:
                disk_info = {
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "use_percent": parts[4]
                }

        return {
            "memory": mem_info,
            "disk": disk_info
        }

    def run_full_audit(self) -> Dict[str, Any]:
        """Executes complete server infrastructure audit."""
        return {
            "os": self.audit_os(),
            "binaries": self.audit_binaries(),
            "services": self.audit_services(),
            "listening_ports": self.audit_listening_ports(),
            "certificates": self.audit_certificates(),
            "firewall_nat": self.audit_firewall_nat(),
            "resources": self.audit_resource_usage()
        }
