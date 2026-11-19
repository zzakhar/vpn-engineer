"""
VPN Engineer - Nginx Reverse Proxy & Multi-Port Fronting Adapter
"""

import re
from typing import Dict, Any, List, Tuple
from vpn_engineer.protocols.base import BaseProtocolAdapter
from vpn_engineer.core.ssh_client import RemoteSSHClient

class NginxAdapter(BaseProtocolAdapter):
    @property
    def name(self) -> str:
        return "nginx"

    def is_installed(self) -> bool:
        code, _, _ = self.ssh.execute("which nginx")
        return code == 0

    def audit(self) -> Dict[str, Any]:
        if not self.is_installed():
            return {"installed": False, "status": "not-installed"}

        _, svc_status, _ = self.ssh.execute("systemctl is-active nginx 2>/dev/null || true")
        _, ver_out, _ = self.ssh.execute("nginx -v 2>&1")

        # Extract listening ports from active nginx configs
        _, conf_dump, _ = self.ssh.execute("nginx -T 2>/dev/null | grep -iE 'listen\\s+' || true")
        ports = []
        for line in conf_dump.splitlines():
            line = line.strip()
            match = re.search(r'listen\s+([0-9]+)', line)
            if match:
                ports.append(int(match.group(1)))

        return {
            "installed": True,
            "version": ver_out.strip(),
            "service_active": (svc_status.strip() == "active"),
            "configured_ports": sorted(list(set(ports)))
        }

    def validate_config(self) -> Tuple[bool, str]:
        code, out, err = self.ssh.execute("nginx -t 2>&1")
        output = (out + "\n" + err).strip()
        is_ok = (code == 0 and "syntax is ok" in output.lower())
        return is_ok, output

    def generate_client_uri(self, **kwargs) -> str:
        raise NotImplementedError("Nginx does not generate client URIs directly; use Xray or Hysteria.")
