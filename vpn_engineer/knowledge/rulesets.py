"""
VPN Engineer - Client Routing Rulesets
Standardized routing rules for v2rayN, NekoBox, Hiddify, and Xray clients.
Optimized for:
1. Keeping domestic Russian services, banks, and marketplaces direct at max speed.
2. Routing foreign, AI, and blocked resources cleanly through proxy.
3. Preventing QUIC/UDP leaks.
"""

import json
from typing import List, Dict, Any

V2RAYN_STANDARD_RULESET: List[Dict[str, Any]] = [
    {
        "port": "443",
        "network": "udp",
        "outboundTag": "block",
        "enabled": True,
        "remarks": "Block UDP 443 (Prevents QUIC/HTTP-3 browser IP leak)"
    },
    {
        "outboundTag": "proxy",
        "process": [
            "ChatGPT.exe",
            "chatgpt.exe",
            "codex.exe",
            "Codex.exe",
            "codex-windows-sandbox-service.exe",
            "codex-computer-use-swift.exe"
        ],
        "enabled": True,
        "remarks": "ChatGPT & Codex Processes"
    },
    {
        "outboundTag": "direct",
        "domain": [
            "geosite:category-ru",
            "domain:ru",
            "domain:su",
            "domain:рф",
            "domain:ozon.ru",
            "domain:wildberries.ru",
            "domain:wb.ru",
            "domain:yandex.ru",
            "domain:yandex.net",
            "domain:ya.ru",
            "domain:kinopoisk.ru",
            "domain:mail.ru",
            "domain:aviasales.ru",
            "domain:deepseek.com",
            "domain:vk.ru",
            "domain:vk.com",
            "domain:gosuslugi.ru",
            "domain:sberbank.ru",
            "domain:tinkoff.ru",
            "domain:tbank.ru",
            "domain:travelata.ru",
            "geosite:private"
        ],
        "enabled": True,
        "remarks": "Direct Russian & CIS domains"
    },
    {
        "outboundTag": "direct",
        "ip": [
            "geoip:private",
            "geoip:ru"
        ],
        "enabled": True,
        "remarks": "Direct Russian & Local IPs"
    },
    {
        "outboundTag": "proxy",
        "domain": [
            "geosite:google",
            "geosite:youtube",
            "geosite:openai",
            "geosite:telegram",
            "domain:google.com",
            "domain:gemini.google.com",
            "domain:aistudio.google.com",
            "domain:deepmind.google",
            "domain:claude.ai",
            "domain:anthropic.com",
            "domain:chatgpt.com",
            "domain:openai.com",
            "domain:telegram.org",
            "domain:api.telegram.org",
            "domain:t.me",
            "domain:instagram.com",
            "domain:twitter.com",
            "domain:x.com",
            "domain:notion.so"
        ],
        "enabled": True,
        "remarks": "Proxy foreign services & AI tools"
    },
    {
        "outboundTag": "proxy",
        "ip": [
            "geoip:telegram"
        ],
        "enabled": True,
        "remarks": "Proxy Telegram IP ranges"
    }
]

def get_v2rayn_rules_json(indent: int = 2) -> str:
    """Returns copyable JSON array for v2rayN clipboard import."""
    return json.dumps(V2RAYN_STANDARD_RULESET, indent=indent, ensure_ascii=False)
