"""
VPN Engineer - Model Context Protocol (MCP) Server
Standardized JSON-RPC 2.0 Stdio implementation providing typed tools for autonomous AI agents.
Compatible with Claude Code, Cursor, Windsurf, Antigravity, and Claude Desktop.
"""

import sys
import json
import traceback
from typing import Dict, Any, List, Optional

from vpn_engineer.core.banner import print_banner
from vpn_engineer.core.ssh_client import RemoteSSHClient
from vpn_engineer.core.ip_checker import IPDiagnosticEngine
from vpn_engineer.core.auditor import ServerAuditor
from vpn_engineer.core.diagnostician import IntelligentDiagnostician
from vpn_engineer.core.backup_manager import BackupManager
from vpn_engineer.core.repair_engine import RepairEngine, RepairPlanItem
from vpn_engineer.protocols.xray import XrayAdapter
from vpn_engineer.protocols.hysteria2 import Hysteria2Adapter
from vpn_engineer.protocols.firewall import FirewallManager
from vpn_engineer.protocols.cloudflare import CloudflareRescueManager
from vpn_engineer.knowledge.battle_log import FIELD_LESSONS, find_lessons_by_keyword, get_lesson_by_id
from vpn_engineer.knowledge.rulesets import get_v2rayn_rules_json

TOOLS_METADATA = [
    {
        "name": "check_ip_censorship",
        "description": "Checks GeoIP, ASN, and detects Russian TSPU censorship signatures (Port 443 throttling vs total IP BGP drop).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target VPS IP address."},
                "domain": {"type": "string", "description": "Optional configured domain."}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "audit_server",
        "description": "Performs deep remote Linux audit: OS distro, installed VPN binaries (Xray, Hysteria 2, Nginx), active systemd services, listening TCP/UDP sockets, TLS certs, and firewall NAT rules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Server IP or hostname."},
                "port": {"type": "integer", "default": 22, "description": "SSH port."},
                "username": {"type": "string", "default": "root", "description": "SSH username."},
                "password": {"type": "string", "description": "SSH password (optional)."},
                "key_path": {"type": "string", "description": "Path to SSH private key (optional)."}
            },
            "required": ["host"]
        }
    },
    {
        "name": "diagnose_vpn",
        "description": "Executes 10-step intelligent diagnostic pipeline: tests server alive, systemd state, DNS resolution, client TCP/TLS negotiation, log errors, and returns ranked hypotheses with confidence scores.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Server IP address."},
                "domain": {"type": "string", "description": "Domain name (e.g. quietlinuxlab.xyz)."},
                "port": {"type": "integer", "default": 22},
                "username": {"type": "string", "default": "root"},
                "password": {"type": "string"},
                "key_path": {"type": "string"}
            },
            "required": ["host"]
        }
    },
    {
        "name": "create_backup",
        "description": "Creates an atomic remote configuration snapshot of Xray, Hysteria 2, Nginx, and iptables before making any changes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "default": 22},
                "username": {"type": "string", "default": "root"},
                "password": {"type": "string"},
                "key_path": {"type": "string"},
                "reason": {"type": "string", "default": "Pre-maintenance snapshot"}
            },
            "required": ["host"]
        }
    },
    {
        "name": "rollback_backup",
        "description": "Safely restores remote VPN configuration from a previous snapshot and restarts restored services.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "default": 22},
                "username": {"type": "string", "default": "root"},
                "password": {"type": "string"},
                "key_path": {"type": "string"},
                "snapshot_id": {"type": "string", "description": "Optional snapshot ID (restores latest if omitted)."}
            },
            "required": ["host"]
        }
    },
    {
        "name": "validate_configs",
        "description": "Validates syntax of remote Nginx ('nginx -t') and Xray ('xray run -test -conf') without restarting services.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "default": 22},
                "username": {"type": "string", "default": "root"},
                "password": {"type": "string"},
                "key_path": {"type": "string"}
            },
            "required": ["host"]
        }
    },
    {
        "name": "setup_port_hopping",
        "description": "Deploys iptables UDP port-hopping NAT rules (20000-50000 -> 8443) for Hysteria 2 to bypass stateful UDP throttling.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "default": 22},
                "username": {"type": "string", "default": "root"},
                "password": {"type": "string"},
                "key_path": {"type": "string"},
                "start_port": {"type": "integer", "default": 20000},
                "end_port": {"type": "integer", "default": 50000},
                "target_port": {"type": "integer", "default": 8443}
            },
            "required": ["host"]
        }
    },
    {
        "name": "generate_client_uri",
        "description": "Generates a fully-formed shareable client connection URI (vless:// or hysteria2://) with proper parameters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "protocol": {"type": "string", "enum": ["vless-grpc", "vless-ws", "hysteria2"]},
                "uuid": {"type": "string", "description": "Client UUID or auth secret."},
                "host": {"type": "string", "description": "Server IP or domain."},
                "port": {"type": "integer", "default": 443},
                "sni": {"type": "string"},
                "service_name": {"type": "string", "default": "grpc"},
                "ws_path": {"type": "string", "default": "/freedom-ws"},
                "remarks": {"type": "string", "default": "QuietVPN"}
            },
            "required": ["protocol", "uuid", "host"]
        }
    },
    {
        "name": "get_routing_ruleset",
        "description": "Returns standard, battle-tested client routing rules for v2rayN and NekoBox (domestic RU direct, AI/foreign via proxy, QUIC leak blocked).",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "query_field_case",
        "description": "Searches the field intelligence battle log for verified censorship bypass patterns and solutions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Keyword (e.g. 'beeline', 'quic', 'aistudio', 'port 443')."}
            },
            "required": ["query"]
        }
    },
    {
        "name": "get_cloudflare_rescue",
        "description": "Generates Cloudflare CDN fronting VLESS-WS links with verified Clean IP pools and provides dashboard setup instructions to bypass total IP-level BGP blocking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uuid": {"type": "string", "description": "Client VLESS UUID."},
                "domain": {"type": "string", "description": "Cloudflare-proxied domain name."},
                "vps_ip": {"type": "string", "description": "Real VPS IP address (for DNS instruction)."},
                "ws_path": {"type": "string", "default": "/freedom-ws"},
                "port": {"type": "integer", "default": 443}
            },
            "required": ["uuid", "domain", "vps_ip"]
        }
    }
]

def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Any:
    """Dispatches tool execution to core engine."""
    if name == "check_ip_censorship":
        engine = IPDiagnosticEngine(target_ip=arguments["ip"], domain=arguments.get("domain"))
        return engine.run_full_check()

    elif name == "audit_server":
        ssh = RemoteSSHClient(
            host=arguments["host"],
            port=arguments.get("port", 22),
            username=arguments.get("username", "root"),
            password=arguments.get("password"),
            key_filename=arguments.get("key_path"),
            read_only=True
        )
        try:
            auditor = ServerAuditor(ssh)
            return auditor.run_full_audit()
        finally:
            ssh.close()

    elif name == "diagnose_vpn":
        ssh = RemoteSSHClient(
            host=arguments["host"],
            port=arguments.get("port", 22),
            username=arguments.get("username", "root"),
            password=arguments.get("password"),
            key_filename=arguments.get("key_path"),
            read_only=True
        )
        try:
            diag = IntelligentDiagnostician(ssh, domain=arguments.get("domain"))
            return diag.diagnose_all()
        finally:
            ssh.close()

    elif name == "create_backup":
        ssh = RemoteSSHClient(
            host=arguments["host"],
            port=arguments.get("port", 22),
            username=arguments.get("username", "root"),
            password=arguments.get("password"),
            key_filename=arguments.get("key_path"),
            read_only=False
        )
        try:
            mgr = BackupManager(ssh)
            return mgr.create_snapshot(reason=arguments.get("reason", "Pre-maintenance snapshot"))
        finally:
            ssh.close()

    elif name == "rollback_backup":
        ssh = RemoteSSHClient(
            host=arguments["host"],
            port=arguments.get("port", 22),
            username=arguments.get("username", "root"),
            password=arguments.get("password"),
            key_filename=arguments.get("key_path"),
            read_only=False
        )
        try:
            mgr = BackupManager(ssh)
            return mgr.rollback(snapshot_id=arguments.get("snapshot_id"))
        finally:
            ssh.close()

    elif name == "validate_configs":
        ssh = RemoteSSHClient(
            host=arguments["host"],
            port=arguments.get("port", 22),
            username=arguments.get("username", "root"),
            password=arguments.get("password"),
            key_filename=arguments.get("key_path"),
            read_only=True
        )
        try:
            repair = RepairEngine(ssh)
            nginx_ok, nginx_msg = repair.validate_nginx_syntax()
            xray_ok, xray_msg = repair.validate_xray_syntax()
            return {
                "nginx": {"valid": nginx_ok, "output": nginx_msg},
                "xray": {"valid": xray_ok, "output": xray_msg}
            }
        finally:
            ssh.close()

    elif name == "setup_port_hopping":
        ssh = RemoteSSHClient(
            host=arguments["host"],
            port=arguments.get("port", 22),
            username=arguments.get("username", "root"),
            password=arguments.get("password"),
            key_filename=arguments.get("key_path"),
            read_only=False
        )
        try:
            fw = FirewallManager(ssh)
            ok = fw.setup_udp_port_hopping(
                start_port=arguments.get("start_port", 20000),
                end_port=arguments.get("end_port", 50000),
                target_port=arguments.get("target_port", 8443)
            )
            return {"status": "success", "port_hopping_applied": ok}
        finally:
            ssh.close()

    elif name == "generate_client_uri":
        proto = arguments["protocol"]
        uuid = arguments["uuid"]
        host = arguments["host"]
        port = arguments.get("port", 443)
        sni = arguments.get("sni")
        remarks = arguments.get("remarks", "QuietVPN")

        if proto == "vless-grpc":
            adapter = XrayAdapter(None)
            return {"uri": adapter.generate_client_uri(uuid, host, port=port, transport="grpc", service_name=arguments.get("service_name", "grpc"), sni=sni, remarks=remarks)}
        elif proto == "vless-ws":
            adapter = XrayAdapter(None)
            return {"uri": adapter.generate_client_uri(uuid, host, port=port, transport="ws", ws_path=arguments.get("ws_path", "/freedom-ws"), sni=sni, remarks=remarks)}
        elif proto == "hysteria2":
            adapter = Hysteria2Adapter(None)
            return {"uri": adapter.generate_client_uri(uuid, host, port=port, sni=sni, remarks=remarks)}
        else:
            raise ValueError(f"Unknown protocol: {proto}")

    elif name == "get_routing_ruleset":
        return {"rules": json.loads(get_v2rayn_rules_json())}

    elif name == "query_field_case":
        q = arguments["query"]
        lesson = get_lesson_by_id(q.upper())
        if lesson:
            return {"cases": [lesson]}
        return {"cases": find_lessons_by_keyword(q)}

    elif name == "get_cloudflare_rescue":
        uuid = arguments["uuid"]
        domain = arguments["domain"]
        vps_ip = arguments["vps_ip"]
        ws_path = arguments.get("ws_path", "/freedom-ws")
        port = arguments.get("port", 443)

        links = CloudflareRescueManager.generate_cloudflare_rescue_links(
            uuid=uuid,
            domain=domain,
            ws_path=ws_path,
            port=port
        )
        guide = CloudflareRescueManager.get_setup_guide(domain=domain, vps_ip=vps_ip)
        return {
            "setup_guide": guide,
            "clean_ip_links": links
        }

    else:
        raise ValueError(f"Tool '{name}' not recognized.")

def run_mcp_server():
    """Runs standard JSON-RPC 2.0 Stdio loop."""
    print_banner(sys.stderr)
    sys.stderr.write("[MCP Server] VPN Engineer listening on stdin/stdout...\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except Exception:
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # 1. Initialize
        if method == "initialize":
            res = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "vpn-engineer",
                        "version": "1.0.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        # 2. Tools list
        elif method == "tools/list":
            res = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": TOOLS_METADATA
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        # 3. Call tool
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            try:
                result_data = handle_tool_call(tool_name, tool_args)
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result_data, indent=2, ensure_ascii=False)
                            }
                        ]
                    }
                }
            except Exception as e:
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": str(e),
                        "data": traceback.format_exc()
                    }
                }

            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        # 4. Ping
        elif method == "ping":
            res = {"jsonrpc": "2.0", "id": req_id, "result": {}}
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    run_mcp_server()
