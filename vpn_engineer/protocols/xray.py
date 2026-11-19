"""
VPN Engineer - Xray-Core Protocol Adapter (VLESS, gRPC, WebSocket, REALITY)
"""

import json
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from vpn_engineer.protocols.base import BaseProtocolAdapter
from vpn_engineer.core.ssh_client import RemoteSSHClient

class XrayAdapter(BaseProtocolAdapter):
    CONFIG_PATH = "/etc/xray/config.json"

    @property
    def name(self) -> str:
        return "xray"

    def is_installed(self) -> bool:
        code, out, _ = self.ssh.execute("which xray || test -f /usr/local/bin/xray || test -f /usr/bin/xray")
        return code == 0

    def audit(self) -> Dict[str, Any]:
        installed = self.is_installed()
        if not installed:
            return {"installed": False, "status": "not-installed"}

        _, svc_status, _ = self.ssh.execute("systemctl is-active xray 2>/dev/null || true")
        _, ver_out, _ = self.ssh.execute("xray version 2>/dev/null | head -n 1 || true")

        config_raw = self.ssh.read_remote_file(self.CONFIG_PATH)
        parsed_cfg = {}
        inbounds_summary = []
        if config_raw:
            try:
                parsed_cfg = json.loads(config_raw)
                for ib in parsed_cfg.get("inbounds", []):
                    inbounds_summary.append({
                        "port": ib.get("port"),
                        "protocol": ib.get("protocol"),
                        "network": ib.get("streamSettings", {}).get("network", "tcp")
                    })
            except Exception:
                pass

        return {
            "installed": True,
            "version": ver_out.strip(),
            "service_active": (svc_status.strip() == "active"),
            "config_exists": bool(config_raw),
            "inbounds": inbounds_summary
        }

    def validate_config(self) -> Tuple[bool, str]:
        code, out, err = self.ssh.execute(f"xray run -test -conf '{self.CONFIG_PATH}' 2>&1 || true")
        output = (out + "\n" + err).strip()
        is_ok = (code == 0 or "configuration ok" in output.lower())
        return is_ok, output

    def generate_client_uri(
        self,
        uuid: str,
        host: str,
        port: int = 443,
        transport: str = "grpc",
        service_name: str = "grpc",
        ws_path: str = "/freedom-ws",
        sni: Optional[str] = None,
        remarks: str = "QuietVPN"
    ) -> str:
        target_sni = sni or host
        encoded_remarks = urllib.parse.quote(remarks)

        if transport.lower() == "grpc":
            return (
                f"vless://{uuid}@{host}:{port}?"
                f"encryption=none&security=tls&sni={target_sni}&alpn=h2&fp=chrome"
                f"&type=grpc&serviceName={service_name}&mode=gun#{encoded_remarks}"
            )
        elif transport.lower() == "ws":
            encoded_path = urllib.parse.quote(ws_path)
            return (
                f"vless://{uuid}@{host}:{port}?"
                f"encryption=none&security=tls&sni={target_sni}&alpn=http%2F1.1&fp=chrome"
                f"&type=ws&host={target_sni}&path={encoded_path}#{encoded_remarks}"
            )
        else:
            raise ValueError(f"Unsupported transport: {transport}")
