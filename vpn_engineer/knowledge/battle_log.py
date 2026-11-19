"""
VPN Engineer - Battle Log & Field Intelligence Database
Structured knowledge distilled from real-world operations against ISP censorship,
TSPU deep packet inspection, mobile throttling, and hosting platform constraints.
NO sensitive personal secrets, IPs, or credentials.
"""

from typing import List, Dict, Any, Optional

FIELD_LESSONS: List[Dict[str, Any]] = [
    {
        "id": "CASE-001",
        "title": "Port 443 TCP Throttling on Russian Mobile Operators (Beeline / MTS)",
        "symptoms": [
            "User connects on Wi-Fi normally, but completely fails or gets 0-10 Kbps on mobile LTE.",
            "TLS ClientHello packet is transmitted, but connection immediately drops or hangs without response.",
            "SSH on port 22 and web on port 80 still connect."
        ],
        "root_cause": (
            "TSPU (ТСПУ) middleboxes deploy targeted deep-packet inspection filters on standard port 443 "
            "for specific IP subnets, injecting RST packets or dropping window size to zero."
        ),
        "false_hypotheses": [
            "Server is down (False - SSH is alive).",
            "Xray daemon crashed (False - active on server).",
            "VLESS UUID is wrong (False - works on Wi-Fi)."
        ],
        "verified_solution": (
            "Configure Nginx to listen on alternative Cloudflare-compatible TLS ports: 2053, 8443, 2083, 2087, 2096. "
            "Client connects to port 2053 (gRPC/WS) instead of 443. Instant 100 Mbps restore."
        ),
        "severity": "CRITICAL",
        "applicable_protocols": ["vless-grpc", "vless-ws"]
    },
    {
        "id": "CASE-002",
        "title": "UDP/QUIC Throttling Defeated by Dynamic Port Hopping (Hysteria 2)",
        "symptoms": [
            "Hysteria 2 or WireGuard connects on fixed UDP port (443 or 8443) but dies after 30 seconds or drops 80% packets."
        ],
        "root_cause": (
            "ISP DPI tracks long-lived UDP flows on fixed ports and applies algorithmic packet drop penalties to suspected VPNs."
        ),
        "false_hypotheses": [
            "Server bandwidth exceeded.",
            "UDP is completely blocked across the whole ISP."
        ],
        "verified_solution": (
            "Enable iptables NAT PREROUTING port range redirection: 'iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 8443'. "
            "Set client parameter 'mport=20000-50000'. Packets constantly hop across 30,000 ports, rendering flow tracking impossible."
        ),
        "severity": "HIGH",
        "applicable_protocols": ["hysteria2", "tuic"]
    },
    {
        "id": "CASE-003",
        "title": "VLESS-REALITY vs Hosting Provider Abuse Rules (NodeHost / Aeza / Hetzner)",
        "symptoms": [
            "Server receives abuse ticket or immediate suspension for MITM / IP spoofing after configuring Reality with random SNI."
        ],
        "root_cause": (
            "Pointing Reality SNI to 3rd-party domains (e.g. microsoft.com, apple.com) triggers external automated active probing "
            "and SNI-mismatch abuse reports to datacenter NOCs."
        ),
        "false_hypotheses": [
            "Reality is always undetectable and risk-free."
        ],
        "verified_solution": (
            "Use Nginx reverse-proxy fronting with a REAL domain and VALID Let's Encrypt TLS certificate. "
            "Nginx presents a legitimate HTML website to casual visitors and proxies gRPC/WS paths to Xray. 100% compliant with hosting ToS."
        ),
        "severity": "CRITICAL",
        "applicable_protocols": ["vless-reality", "vless-grpc"]
    },
    {
        "id": "CASE-004",
        "title": "Google AI Studio / Gemini 'User location is not supported' Error",
        "symptoms": [
            "Google AI Studio (aistudio.google.com) fails to list models even when user is connected to a European VPN."
        ],
        "root_cause": (
            "1. Chrome HTTP/3 (QUIC/UDP) leak: Windows System Proxy (L7) only proxies TCP; Chrome sends UDP 443 directly via local Russian ISP.\n"
            "2. Swiss/EEA GDPR Free-Tier restriction: Under Swiss revFADP and EU GDPR, Google legally blocks the unpaid Gemini API tier unless a billing account is linked."
        ),
        "false_hypotheses": [
            "Server IP is blacklisted by Google.",
            "VPN routing rules are broken."
        ],
        "verified_solution": (
            "1. Turn on TUN mode in VPN client (or disable QUIC in Chrome via chrome://flags/#enable-quic).\n"
            "2. Link a Cloud Billing account to Swiss/EU Google project, or connect using a US-region Google Account."
        ),
        "severity": "MEDIUM",
        "applicable_protocols": ["client-routing", "tun-mode"]
    },
    {
        "id": "CASE-005",
        "title": "v2rayN Clipboard Routing Import 'invalid' Error",
        "symptoms": [
            "User pastes routing JSON into v2rayN and gets 'invalid' error."
        ],
        "root_cause": (
            "User pasted core settings (guiNConfig.json) or raw rule array into the server import dialog (which expects vless:// links), "
            "or pasted into the outer routing profile manager which expects a full RoutingItem wrapper rather than a List<RulesItem>."
        ),
        "verified_solution": (
            "Open Settings -> Routing Setting -> Double-click active RuleSet -> Click 'Import rules from clipboard' button inside the rules table dialog."
        ),
        "severity": "LOW",
        "applicable_protocols": ["v2rayn-gui"]
    }
]

def get_lesson_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    for c in FIELD_LESSONS:
        if c["id"] == case_id:
            return c
    return None

def find_lessons_by_keyword(keyword: str) -> List[Dict[str, Any]]:
    kw = keyword.lower()
    matches = []
    for c in FIELD_LESSONS:
        content = (c["title"] + " " + c["root_cause"] + " " + c["verified_solution"] + " " + " ".join(c["symptoms"])).lower()
        if kw in content:
            matches.append(c)
    return matches
