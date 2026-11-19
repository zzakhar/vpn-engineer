import pytest
from vpn_engineer.core.diagnostician import IntelligentDiagnostician

class MockSSHClient:
    def __init__(self, host="127.0.0.1"):
        self.host = host

    def execute(self, cmd, timeout=None):
        if "echo PING_OK" in cmd:
            return (0, "PING_OK\n", "")
        if "systemctl is-active" in cmd:
            return (0, "active\n", "")
        if "ss -tulpn" in cmd:
            return (0, "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:2053 0.0.0.0:*\n", "")
        return (0, "", "")

def test_diagnostician_hypotheses_synthesis():
    mock_ssh = MockSSHClient()
    diag = IntelligentDiagnostician(mock_ssh, domain="example.com")

    # Simulate scenario: Port 443 TIMEOUT, port 2053 OPEN
    step1 = {"server_alive": True, "ssh_rtt_ms": 15.0}
    step2 = {"xray": "active", "nginx": "active", "hysteria-server": "active"}
    step3 = {"dns_poisoned": False, "local_resolved_ips": ["127.0.0.1"]}
    step4 = {
        "client_reachability": {
            443: "TIMEOUT (Likely Filtered/TSPU)",
            2053: "OPEN",
            8443: "OPEN"
        }
    }
    step5 = {443: {"status": "FAILED"}}
    step6 = {"xray": [], "nginx": []}

    hypotheses = diag.step7_synthesize_hypotheses(step1, step2, step3, step4, step5, step6)
    assert len(hypotheses) > 0
    top = hypotheses[0]
    assert "Port 443" in top.title or "TSPU" in top.title
    assert top.confidence >= 0.90
    assert "2053" in top.remediation
