"""
VPN Engineer - Battle-Tested Production Configuration Templates
Parametrized, clean configurations for Nginx multi-port, Xray VLESS, Hysteria 2, and Firewall.
Zero hardcoded personal secrets or IPs.
"""

NGINX_MULTIPORT_CONF = """# Managed by VPN Engineer - Multi-Port Anti-Censorship Reverse Proxy
server {
    listen 80;
    listen [::]:80;
    server_name {DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    # Listen on standard 443 plus Cloudflare-compatible alternative ports to bypass TSPU
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    listen 2053 ssl http2;
    listen [::]:2053 ssl http2;
    listen 2083 ssl http2;
    listen [::]:2083 ssl http2;
    listen 2087 ssl http2;
    listen [::]:2087 ssl http2;
    listen 2096 ssl http2;
    listen [::]:2096 ssl http2;

    server_name {DOMAIN};

    ssl_certificate {CERT_PATH};
    ssl_certificate_key {KEY_PATH};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # gRPC VLESS Proxy Pass
    location /{GRPC_SERVICE_NAME} {
        grpc_pass grpc://127.0.0.1:{XRAY_GRPC_PORT};
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header X-Real-IP $remote_addr;
    }

    # WebSocket VLESS Proxy Pass
    location {WS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:{XRAY_WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 1d;
    }

    # Legitimate Masquerade website fallback
    location / {
        root /var/www/html;
        index index.html;
    }
}
"""

XRAY_VLESS_CONFIG = """{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": {XRAY_GRPC_PORT},
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "{CLIENT_UUID}",
            "email": "user@vpn-engineer"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "{GRPC_SERVICE_NAME}"
        }
      }
    },
    {
      "port": {XRAY_WS_PORT},
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "{CLIENT_UUID}",
            "email": "user-ws@vpn-engineer"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "{WS_PATH}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
"""

HYSTERIA2_SERVER_CONFIG = """# Managed by VPN Engineer - Hysteria 2 Server Configuration
listen: :{HYSTERIA_PORT}

tls:
  cert: {CERT_PATH}
  key: {KEY_PATH}

auth:
  type: userpass
  userpass:
    {CLIENT_UUID}: {CLIENT_PASSWORD}

masquerade:
  type: proxy
  proxy:
    url: https://{DOMAIN}/
    rewriteHost: true

bandwidth:
  up: 100 mbps
  down: 500 mbps

speedTest: true
"""

IPTABLES_PORT_HOPPING_SH = """#!/usr/bin/env bash
# Managed by VPN Engineer - Hysteria 2 UDP Port Hopping Redirect
set -e

# Port range for UDP hopping (evades stateful ISP throttling)
START_PORT=20000
END_PORT=50000
TARGET_PORT={HYSTERIA_PORT}

echo "[*] Setting up UDP Port Hopping redirect: $START_PORT-$END_PORT -> $TARGET_PORT"
iptables -t nat -D PREROUTING -p udp --dport $START_PORT:$END_PORT -j REDIRECT --to-ports $TARGET_PORT 2>/dev/null || true
iptables -t nat -A PREROUTING -p udp --dport $START_PORT:$END_PORT -j REDIRECT --to-ports $TARGET_PORT

# Persist rules across reboot
if which netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
elif which iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
fi
echo "[+] Port hopping active!"
"""
