import json
import pytest
from vpn_engineer.mcp_server import handle_tool_call, TOOLS_METADATA
from vpn_engineer.protocols.cloudflare import CloudflareRescueManager

def test_mcp_tools_metadata():
    tool_names = [t["name"] for t in TOOLS_METADATA]
    assert "audit_server" in tool_names
    assert "diagnose_vpn" in tool_names
    assert "create_backup" in tool_names
    assert "rollback_backup" in tool_names
    assert "generate_client_uri" in tool_names
    assert "get_routing_ruleset" in tool_names
    assert "query_field_case" in tool_names
    assert "get_cloudflare_rescue" in tool_names

def test_mcp_routing_tool():
    res = handle_tool_call("get_routing_ruleset", {})
    assert "rules" in res
    assert len(res["rules"]) >= 4

def test_mcp_case_query():
    res = handle_tool_call("query_field_case", {"query": "beeline"})
    assert "cases" in res
    assert len(res["cases"]) >= 1

def test_mcp_cloudflare_rescue():
    res = handle_tool_call("get_cloudflare_rescue", {
        "uuid": "test-uuid-9999",
        "domain": "quietlinuxlab.xyz",
        "vps_ip": "1.2.3.4"
    })
    assert "setup_guide" in res
    assert "clean_ip_links" in res
    assert len(res["clean_ip_links"]) >= 4
    first_link = res["clean_ip_links"][0]["uri"]
    assert "vless://test-uuid-9999@" in first_link
    assert "sni=quietlinuxlab.xyz" in first_link
    assert "type=ws" in first_link
