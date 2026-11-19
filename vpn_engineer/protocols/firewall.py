"""
VPN Engineer - Linux Firewall & Port Hopping Manager
"""

from typing import Dict, Any, List, Tuple
from vpn_engineer.core.ssh_client import RemoteSSHClient

class FirewallManager:
    """Safely manages iptables / NAT redirect rules for anti-censorship port hopping."""

    def __init__(self, ssh: RemoteSSHClient):
        self.ssh = ssh

    def audit_rules(self) -> Dict[str, Any]:
        """Audits current filter and nat tables."""
        _, nat_out, _ = self.ssh.execute("iptables -t nat -L -n -v --line-numbers 2>/dev/null || true")
        _, filter_out, _ = self.ssh.execute("iptables -L -n -v --line-numbers 2>/dev/null || true")

        has_port_hopping = ("REDIRECT" in nat_out and "udp" in nat_out)

        return {
            "has_port_hopping": has_port_hopping,
            "nat_prerouting_lines": [line.strip() for line in nat_out.splitlines() if "REDIRECT" in line or "dpt" in line]
        }

    def setup_udp_port_hopping(self, start_port: int = 20000, end_port: int = 50000, target_port: int = 8443) -> bool:
        """Sets up iptables UDP port hopping and persists it."""
        # 1. Clean old rule if present to avoid duplication
        self.ssh.execute(f"iptables -t nat -D PREROUTING -p udp --dport {start_port}:{end_port} -j REDIRECT --to-ports {target_port} 2>/dev/null || true")
        
        # 2. Append new rule
        code, _, err = self.ssh.execute(f"iptables -t nat -A PREROUTING -p udp --dport {start_port}:{end_port} -j REDIRECT --to-ports {target_port}")
        if code != 0:
            raise RuntimeError(f"Failed to add iptables port hopping: {err}")

        # 3. Persist
        self.ssh.execute("netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true")
        return True
