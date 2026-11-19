"""
VPN Engineer - Cloudflare CDN Fronting & Clean IP Rescue Module
Bypasses total IP-level BGP blackholing by routing VLESS-WS through Cloudflare CDN edge nodes.
"""

from typing import List, Dict, Any, Optional
import urllib.parse

# Verified Clean Cloudflare IP pools with lowest latency and minimal TSPU packet-drop in RU
CLOUDFLARE_CLEAN_IPS: List[Dict[str, str]] = [
    {"ip": "162.159.153.4", "label": "Clean Anycast Pool #1 (Fastest)", "provider": "Cloudflare CDN"},
    {"ip": "188.114.97.3", "label": "Clean Anycast Pool #2 (Stable)", "provider": "Cloudflare CDN"},
    {"ip": "172.67.182.11", "label": "Clean Anycast Pool #3 (Reserve)", "provider": "Cloudflare CDN"},
    {"ip": "104.21.50.1", "label": "Clean Anycast Pool #4 (Global)", "provider": "Cloudflare CDN"},
]

CLOUDFLARE_SUPPORTED_HTTPS_PORTS: List[int] = [443, 2053, 2083, 2087, 2096, 8443]

class CloudflareRescueManager:
    """Manages Cloudflare CDN fronting when VPS IP is blackholed by censorship authorities."""

    @staticmethod
    def get_clean_ips() -> List[Dict[str, str]]:
        return CLOUDFLARE_CLEAN_IPS

    @staticmethod
    def generate_cloudflare_rescue_links(
        uuid: str,
        domain: str,
        ws_path: str = "/freedom-ws",
        port: int = 443,
        remarks_prefix: str = "QuietVPN • Cloudflare"
    ) -> List[Dict[str, str]]:
        """Generates ready-to-use VLESS-WS links across all verified Clean Cloudflare IPs."""
        links = []
        encoded_path = urllib.parse.quote(ws_path)

        for i, item in enumerate(CLOUDFLARE_CLEAN_IPS, 1):
            clean_ip = item["ip"]
            remarks = urllib.parse.quote(f"{remarks_prefix} Clean #{i}")
            uri = (
                f"vless://{uuid}@{clean_ip}:{port}?"
                f"encryption=none&security=tls&sni={domain}&alpn=http%2F1.1&fp=chrome"
                f"&type=ws&host={domain}&path={encoded_path}#{remarks}"
            )
            links.append({
                "clean_ip": clean_ip,
                "label": item["label"],
                "uri": uri
            })
        return links

    @staticmethod
    def get_setup_guide(domain: str, vps_ip: str) -> Dict[str, Any]:
        """Step-by-step setup guide for configuring Cloudflare dashboard for CDN fronting."""
        return {
            "title": "Cloudflare CDN Anti-Block Rescue Setup",
            "steps": [
                {
                    "step": 1,
                    "action": "Cloudflare DNS Record",
                    "detail": f"In Cloudflare Dashboard -> DNS -> Add 'A' record: Name: '@' (or subdomain), IPv4: '{vps_ip}', Proxy status: PROXIED (Orange Cloud ON)."
                },
                {
                    "step": 2,
                    "action": "SSL/TLS Encryption Mode",
                    "detail": "In Cloudflare Dashboard -> SSL/TLS -> Set encryption mode to 'Full (Strict)' (or 'Full')."
                },
                {
                    "step": 3,
                    "action": "Enable WebSockets",
                    "detail": "In Cloudflare Dashboard -> Network -> Ensure 'WebSockets' toggle is turned ON (enabled by default)."
                },
                {
                    "step": 4,
                    "action": "Disable gRPC proxying (for CDN mode)",
                    "detail": "Note: Cloudflare Free proxy only supports WebSocket and HTTP/2, so use VLESS-WS paths for CDN fronting."
                }
            ]
        }
