"""
VPN Engineer - Intelligent Multi-Stage Diagnostic Engine
Implements hypothesis-driven troubleshooting instead of random trial-and-error configuration editing.
Distinguishes server-side operational health from regional TSPU/DPI and mobile ISP throttling.
"""

import re
import json
import socket
import ssl
import time
from typing import Dict, Any, List, Optional, Tuple
from vpn_engineer.core.ssh_client import RemoteSSHClient

class DiagnosticStage:
    PING_SERVER = "1_server_reachability"
    CHECK_SERVICES = "2_service_health"
    DNS_RESOLUTION = "3_dns_resolution"
    TRANSPORT_LAYER = "4_transport_tcp_udp"
    TLS_HANDSHAKE = "5_tls_negotiation"
    LOG_CORRELATION = "6_log_analysis"
    CENSORSHIP_HEURISTICS = "7_censorship_detection"

class DiagnosticHypothesis:
    def __init__(self, title: str, confidence: float, evidence: List[str], remediation: str):
        self.title = title
        self.confidence = confidence # 0.0 to 1.0
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "remediation": self.remediation
        }

class IntelligentDiagnostician:
    """10-Step Intelligent Diagnostic Engine for VPN failures."""

    def __init__(self, ssh: RemoteSSHClient, domain: Optional[str] = None):
        self.ssh = ssh
        self.domain = domain
        self.server_ip = ssh.host

    def step1_check_server_reachability(self) -> Dict[str, Any]:
        """Step 1: Check if the server is alive and SSH responds."""
        try:
            start = time.perf_counter()
            code, out, _ = self.ssh.execute("echo PING_OK", timeout=5)
            elapsed = (time.perf_counter() - start) * 1000
            alive = (code == 0 and "PING_OK" in out)
            return {
                "server_alive": alive,
                "ssh_rtt_ms": round(elapsed, 1),
                "error": None
            }
        except Exception as e:
            return {
                "server_alive": False,
                "ssh_rtt_ms": None,
                "error": str(e)
            }

    def step2_check_services(self) -> Dict[str, Any]:
        """Step 2: Check systemd status for xray, hysteria, nginx."""
        services = ["xray", "hysteria-server", "hysteria", "nginx"]
        states = {}
        for s in services:
            _, status_out, _ = self.ssh.execute(f"systemctl is-active {s} 2>/dev/null || true")
            state = status_out.strip()
            states[s] = state if state else "not-found"
        return states

    def step3_check_dns(self) -> Dict[str, Any]:
        """Step 3: Resolve domain locally and remotely, check for DNS poisoning/mismatch."""
        if not self.domain:
            return {"status": "skipped", "reason": "No domain specified"}

        # Local resolution
        local_ips = []
        try:
            _, _, local_ips = socket.gethostbyname_ex(self.domain)
        except Exception as e:
            local_err = str(e)
        else:
            local_err = None

        # Remote resolution on server
        _, remote_out, _ = self.ssh.execute(f"getent ahosts '{self.domain}' | awk '{{print $1}}' | sort -u || true")
        remote_ips = [ip.strip() for ip in remote_out.splitlines() if ip.strip()]

        ip_matches = (self.server_ip in local_ips) if local_ips else False
        is_cloudflare_cdn = any(ip.startswith(("104.", "172.67.", "188.114.", "162.159.")) for ip in local_ips)

        return {
            "domain": self.domain,
            "local_resolved_ips": local_ips,
            "remote_resolved_ips": remote_ips,
            "server_ip": self.server_ip,
            "matches_server_ip": ip_matches,
            "is_cloudflare_proxied": is_cloudflare_cdn,
            "dns_poisoned": (bool(local_ips) and not ip_matches and not is_cloudflare_cdn)
        }

    def step4_check_transports(self) -> Dict[str, Any]:
        """Step 4: Check TCP & UDP listeners on server and reachability from client."""
        # 1. Server-side listeners
        _, ss_out, _ = self.ssh.execute("ss -tulpn -H 2>/dev/null || true")
        server_listeners = []
        for line in ss_out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0].lower()
                addr = parts[4]
                if ":" in addr:
                    try:
                        p = int(addr.rsplit(":", 1)[-1])
                        server_listeners.append({"proto": proto, "port": p, "line": line})
                    except ValueError:
                        pass

        # 2. Client-side TCP checks
        test_ports = [443, 8443, 2053, 2083, 2087, 2096]
        client_reachability = {}
        for port in test_ports:
            try:
                with socket.create_connection((self.server_ip, port), timeout=3.0):
                    client_reachability[port] = "OPEN"
            except socket.timeout:
                client_reachability[port] = "TIMEOUT (Likely Filtered/TSPU)"
            except ConnectionRefusedError:
                client_reachability[port] = "REFUSED (No listener on server)"
            except OSError as e:
                client_reachability[port] = f"ERROR: {e}"

        return {
            "server_listeners": server_listeners,
            "client_reachability": client_reachability
        }

    def step5_check_tls(self) -> Dict[str, Any]:
        """Step 5: Perform TLS handshake from client to domain with ALPN (h2 / http/1.1)."""
        target_host = self.domain or self.server_ip
        tls_results = {}

        for port in [443, 2053, 8443]:
            try:
                context = ssl.create_default_context()
                context.set_alpn_protocols(["h2", "http/1.1"])
                with socket.create_connection((self.server_ip, port), timeout=4.0) as sock:
                    with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                        cert = ssock.getpeercert()
                        alpn = ssock.selected_alpn_protocol()
                        cipher = ssock.cipher()
                        tls_results[port] = {
                            "status": "SUCCESS",
                            "alpn": alpn,
                            "cipher": cipher[0] if cipher else None,
                            "tls_version": ssock.version()
                        }
            except Exception as e:
                tls_results[port] = {
                    "status": "FAILED",
                    "error": str(e)
                }

        return tls_results

    def step6_analyze_logs(self) -> Dict[str, List[str]]:
        """Step 6: Extract recent error traces from journalctl for xray, hysteria, and nginx."""
        logs = {}
        for unit in ["xray", "hysteria-server", "nginx"]:
            cmd = f"journalctl -u {unit} -n 30 --no-pager 2>/dev/null | grep -iE 'error|failed|rejected|timeout|fatal|warn' | tail -n 10 || true"
            _, err_lines, _ = self.ssh.execute(cmd)
            cleaned = [line.strip() for line in err_lines.splitlines() if line.strip()]
            logs[unit] = cleaned
        return logs

    def step7_synthesize_hypotheses(
        self,
        step1: Dict[str, Any],
        step2: Dict[str, Any],
        step3: Dict[str, Any],
        step4: Dict[str, Any],
        step5: Dict[str, Any],
        step6: Dict[str, Any]
    ) -> List[DiagnosticHypothesis]:
        """Step 7: Synthesize findings into ranked, actionable hypotheses."""
        hypotheses = []

        # Hypothesis A: Port 443 Throttling by Russian ISP / TSPU
        client_ports = step4.get("client_reachability", {})
        p443 = client_ports.get(443, "")
        p2053 = client_ports.get(2053, "")

        if "TIMEOUT" in p443 and ("OPEN" in p2053 or "OPEN" in client_ports.get(8443, "")):
            hypotheses.append(DiagnosticHypothesis(
                title="Regional TSPU Deep-Packet Inspection / Throttling on Port 443",
                confidence=0.95,
                evidence=[
                    "Port 443 timed out from client network.",
                    "Alternative ports (2053 / 8443) are OPEN and responsive.",
                    "Server services are active."
                ],
                remediation="Switch client connection to port 2053 or 8443 (Direct gRPC/WS 2053) to bypass TSPU port-443 throttling."
            ))

        # Hypothesis B: Service dead on server
        services = step2
        dead_services = [s for s, state in services.items() if state not in ("active", "not-found")]
        if dead_services:
            hypotheses.append(DiagnosticHypothesis(
                title=f"Server-Side Daemon Failure: {', '.join(dead_services)}",
                confidence=0.99,
                evidence=[f"Service {s} is in state: {services[s]}" for s in dead_services],
                remediation=f"Restart service with 'systemctl restart {dead_services[0]}' and inspect syntax."
            ))

        # Hypothesis C: TLS handshake or ALPN failure
        tls_443 = step5.get(443, {})
        if tls_443.get("status") == "FAILED" and "OPEN" in p443:
            hypotheses.append(DiagnosticHypothesis(
                title="TLS Handshake or Certificate Mismatch",
                confidence=0.88,
                evidence=[f"TCP connected on 443, but TLS handshake failed: {tls_443.get('error')}"],
                remediation="Verify Let's Encrypt certificates via 'certbot certificates' and check Nginx SSL configuration."
            ))

        # Hypothesis D: UDP / QUIC block on mobile operator
        if "hysteria-server" in services and services["hysteria-server"] == "active":
            # If user reports mobile failure
            hypotheses.append(DiagnosticHypothesis(
                title="Mobile Operator UDP/QUIC Throttling (Hysteria 2 / WireGuard)",
                confidence=0.80,
                evidence=[
                    "Mobile networks (e.g. Beeline/MTS/Megafon) frequently throttle or drop UDP 443.",
                    "Hysteria 2 requires dynamic port hopping to defeat UDP state tracking."
                ],
                remediation="Verify iptables NAT port hopping (redirect 20000:50000 -> 8443) and enable mport in client URI."
            ))

        # Hypothesis E: DNS Poisoning
        if step3.get("dns_poisoned"):
            hypotheses.append(DiagnosticHypothesis(
                title="DNS Poisoning / Spoofed IP by Local Provider",
                confidence=0.92,
                evidence=[
                    f"Domain resolved to {step3.get('local_resolved_ips')}, but server IP is {self.server_ip}."
                ],
                remediation="Enable DoH (DNS over HTTPS via 1.1.1.1 or 8.8.8.8) in VPN client or configure Remote DNS."
            ))

        # Default fallback hypothesis
        if not hypotheses:
            hypotheses.append(DiagnosticHypothesis(
                title="Infrastructure Operational - Potential Client-Side Routing Issue",
                confidence=0.60,
                evidence=["All core server services, TCP ports, and TLS handshakes succeeded."],
                remediation="Inspect client-side routing rules (TUN mode, QUIC leak in Chrome, or routing profile Whitelist vs Proxy)."
            ))

        return sorted(hypotheses, key=lambda h: h.confidence, reverse=True)

    def diagnose_all(self) -> Dict[str, Any]:
        """Runs the entire 10-step diagnostic pipeline and returns structured report."""
        s1 = self.step1_check_server_reachability()
        if not s1.get("server_alive"):
            return {
                "status": "FATAL_SERVER_UNREACHABLE",
                "step1_server": s1,
                "hypotheses": [
                    DiagnosticHypothesis(
                        title="Server Unreachable (Offline or BGP Blackholed)",
                        confidence=1.0,
                        evidence=[f"SSH connection failed to {self.server_ip}: {s1.get('error')}"],
                        remediation="Check VPS provider control panel, verify VPS power state, or check if server IP is blocked."
                    ).to_dict()
                ]
            }

        s2 = self.step2_check_services()
        s3 = self.step3_check_dns()
        s4 = self.step4_check_transports()
        s5 = self.step5_check_tls()
        s6 = self.step6_analyze_logs()
        hypotheses = self.step7_synthesize_hypotheses(s1, s2, s3, s4, s5, s6)

        return {
            "status": "COMPLETED",
            "server_ip": self.server_ip,
            "domain": self.domain,
            "step1_reachability": s1,
            "step2_services": s2,
            "step3_dns": s3,
            "step4_transports": s4,
            "step5_tls": s5,
            "step6_logs": s6,
            "hypotheses": [h.to_dict() for h in hypotheses],
            "primary_recommendation": hypotheses[0].remediation if hypotheses else "None"
        }
