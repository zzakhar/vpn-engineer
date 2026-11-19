"""
VPN Engineer - IP & Network Reachability Diagnostics
Checks GeoIP, ASN, latency, and whether an IP is blocked or throttled by regional filters (TSPU/RKN).
"""

import json
import socket
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

class IPDiagnosticEngine:
    """Diagnoses IP attributes, ASN, and regional censorship accessibility."""

    def __init__(self, target_ip: str, domain: Optional[str] = None):
        self.target_ip = target_ip.strip()
        self.domain = domain.strip() if domain else None

    def get_geoip(self) -> Dict[str, Any]:
        """Fetches public GeoIP and ASN details for the target IP."""
        url = f"https://ipinfo.io/{self.target_ip}/json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpn-engineer/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "ip": self.target_ip,
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "postal": data.get("postal"),
                    "timezone": data.get("timezone"),
                    "is_hosting": any(k in data.get("org", "").lower() for k in ["hosting", "cloud", "server", "vps", "digitalocean", "hetzner", "ovh"])
                }
        except Exception as e:
            return {
                "ip": self.target_ip,
                "error": f"GeoIP lookup failed: {e}",
                "country": "Unknown"
            }

    def test_tcp_reachability(self, ports: List[int], timeout: float = 3.0) -> Dict[int, bool]:
        """Tests TCP connect directly from client to target IP across ports."""
        results = {}
        for p in ports:
            try:
                start = time.perf_counter()
                with socket.create_connection((self.target_ip, p), timeout=timeout):
                    elapsed = (time.perf_counter() - start) * 1000
                    results[p] = True
            except (socket.timeout, ConnectionRefusedError, OSError):
                results[p] = False
        return results

    def analyze_block_signatures(self, tcp_results: Dict[int, bool]) -> Dict[str, Any]:
        """
        Analyzes pattern of open/closed ports to detect TSPU censorship signatures:
        - If port 22 (SSH) is OPEN, but port 443 is CLOSED/TIMEOUT -> Classic port-443 throttling.
        - If ALL ports are TIMEOUT -> IP-level border gateway drop (RKN IP ban).
        - If port 2053 or 8443 is OPEN, but 443 is CLOSED -> ISP-specific 443 deep-packet inspection block.
        """
        port_22 = tcp_results.get(22, False)
        port_443 = tcp_results.get(443, False)
        port_2053 = tcp_results.get(2053, False)
        port_8443 = tcp_results.get(8443, False)

        has_any_open = any(tcp_results.values())
        all_closed = not has_any_open

        signature = "UNKNOWN"
        recommendation = ""

        if all_closed:
            signature = "TOTAL_IP_BLOCK"
            recommendation = (
                "IP is completely unreachable on all tested ports. "
                "The IP is likely blocked by border BGP filters. "
                "Solution: Use Cloudflare CDN Clean IP fronting (WebSocket + TLS) or request new VPS IP."
            )
        elif port_22 and not port_443 and (port_2053 or port_8443):
            signature = "PORT_443_TSPU_BLOCK"
            recommendation = (
                "Port 443 is specifically blocked or throttled, while SSH and alternative TLS ports (2053/8443) work. "
                "Solution: Switch client connection to port 2053 or 8443, or deploy Hysteria 2 port hopping (20000-50000)."
            )
        elif port_22 and not port_443 and not port_2053 and not port_8443:
            signature = "WEB_PORTS_FILTERED"
            recommendation = (
                "SSH works, but all standard HTTPS web ports are filtered. "
                "Solution: Deploy Hysteria 2 UDP with random port-hopping or VLESS on high non-standard ports (>10000)."
            )
        elif port_443 and (port_2053 or port_8443):
            signature = "PORTS_ACCESSIBLE"
            recommendation = "Ports are reachable. Proceed to protocol and TLS handshake validation."

        return {
            "signature": signature,
            "ports_tested": tcp_results,
            "recommendation": recommendation
        }

    def run_full_check(self) -> Dict[str, Any]:
        """Executes full diagnostic suite."""
        geoip = self.get_geoip()
        # Test standard critical VPN ports
        ports_to_test = [22, 80, 443, 2053, 8443]
        tcp_status = self.test_tcp_reachability(ports_to_test)
        analysis = self.analyze_block_signatures(tcp_status)

        return {
            "target_ip": self.target_ip,
            "domain": self.domain,
            "geoip": geoip,
            "port_audit": tcp_status,
            "censorship_analysis": analysis
        }
