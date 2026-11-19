import pytest
from vpn_engineer.core.banner import print_banner, SHOUTOUT
from vpn_engineer.knowledge.battle_log import FIELD_LESSONS, get_lesson_by_id, find_lessons_by_keyword
from vpn_engineer.knowledge.rulesets import get_v2rayn_rules_json
from vpn_engineer.protocols.xray import XrayAdapter
from vpn_engineer.protocols.hysteria2 import Hysteria2Adapter

def test_banner_and_shoutout():
    import io
    s = io.StringIO()
    print_banner(s)
    out = s.getvalue()
    assert "https://github.com/zzakhar" in out
    assert "Anti-Censorship" in out

def test_battle_log_queries():
    assert len(FIELD_LESSONS) >= 5
    case = get_lesson_by_id("CASE-001")
    assert case is not None
    assert "Beeline" in case["title"] or "Port 443" in case["title"]

    results = find_lessons_by_keyword("port 443")
    assert len(results) >= 1

def test_ruleset_generation():
    rules_json = get_v2rayn_rules_json()
    assert "domain:google.com" in rules_json
    assert "geoip:ru" in rules_json
    assert "ChatGPT.exe" in rules_json

def test_client_uri_generators():
    xray = XrayAdapter(None)
    uri_grpc = xray.generate_client_uri("test-uuid", "example.com", port=2053, transport="grpc", service_name="mygrpc")
    assert uri_grpc.startswith("vless://test-uuid@example.com:2053?")
    assert "type=grpc" in uri_grpc
    assert "serviceName=mygrpc" in uri_grpc

    hy2 = Hysteria2Adapter(None)
    uri_hy2 = hy2.generate_client_uri("test-auth", "example.com", port=8443, mport_range="20000-50000")
    assert uri_hy2.startswith("hysteria2://test-auth:test-auth@example.com:8443/?")
    assert "mport=20000-50000" in uri_hy2
