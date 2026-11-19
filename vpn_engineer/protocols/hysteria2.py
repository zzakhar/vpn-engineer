"""
VPN Engineer - Hysteria 2 Protocol Adapter (UDP, QUIC, Port Hopping)
"""

import urllib.parse
from typing import Dict, Any, Optional, Tuple
from vpn_engineer.protocols.base import BaseProtocolAdapter
from vpn_engineer.core.ssh_client import RemoteSSHClient

class Hysteria2Adapter(BaseProtocolAdapter):
    CONFIG_PATH = "/etc/hysteria/config.yaml"

    @property
    def name(self) -> str:
        return "hysteria2"

    def is_installed(self) -> bool:
        code, _, _ = self.ssh.execute("which hysteria || test -f /usr/local/bin/hysteria || test -f /usr/bin/hysteria")
        return code == 0

    def audit(self) -> Dict[str, Any]:
        installed = self.is_installed()
        if not installed:
            return {"installed": False, "status": "not-installed"}

        _, svc_status, _ = self.ssh.execute(
            "systemctl is-active hysteria-server 2>/dev/null || systemctl is-active hysteria 2>/dev/null || true"
        )
        _, ver_out, _ = self.ssh.execute("hysteria version 2>/dev/null | head -n 1 || true")

        # Check port hopping in iptables
        _, ipt_out, _ = self.ssh.execute("iptables -t nat -L PREROUTING -n 2>/dev/null | grep -i REDIRECT || true")
        has_port_hopping = ("20000" in ipt_out or "REDIRECT" in ipt_out)

        return {
            "installed": True,
            "version": ver_out.strip(),
            "service_active": (svc_status.strip() == "active"),
            "config_exists": self.ssh.remote_file_exists(self.CONFIG_PATH),
            "port_hopping_enabled": has_port_hopping
        }

    def validate_config(self) -> Tuple[bool, str]:
        code, out, err = self.ssh.execute(
            f"python3 -c \"import yaml; yaml.safe_load(open('{self.CONFIG_PATH}'))\" 2>&1 || true"
        )
        output = (out + "\n" + err).strip()
        return (code == 0), output

    def generate_client_uri(
        self,
        auth_secret: str,
        host: str,
        port: int = 8443,
        sni: Optional[str] = None,
        mport_range: str = "20000-50000",
        remarks: str = "QuietVPN Hysteria 2"
    ) -> str:
        target_sni = sni or host
        encoded_remarks = urllib.parse.quote(remarks)
        auth_part = f"{auth_secret}:{auth_secret}" if ":" not in auth_secret else auth_secret

        return (
            f"hysteria2://{auth_part}@{host}:{port}/?"
            f"sni={target_sni}&mport={mport_range}&insecure=0#{encoded_remarks}"
        )
