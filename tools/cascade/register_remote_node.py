#!/usr/bin/env python3
"""
Запускать на удаленном сервере (exit-node).
Генерирует registration-token для вставки в master-панель.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time
import uuid
from pathlib import Path

from cascade_common import b64url_encode, ensure_dir, save_json, sha256_hex


CASCADE_DIR = Path("/opt/hy2-admin/data/cascade")
REMOTE_NODE_JSON = CASCADE_DIR / "remote_node.json"


def detect_host(default_host: str) -> str:
    if default_host:
        return default_host
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate remote-node registration token")
    ap.add_argument("--host", default="", help="Public host/IP of remote node")
    ap.add_argument("--api-port", type=int, default=9443, help="Remote sync API port")
    ap.add_argument("--name", default="", help="Display name for node")
    ap.add_argument("--hy2-server", default="", help="HY2 server host (default: --host)")
    ap.add_argument("--hy2-sni", default="", help="HY2 SNI (default: hy2-server or host)")
    ap.add_argument("--hy2-port", type=int, default=443, help="HY2 port")
    ap.add_argument("--hop-username", default="", help="HY2 hop username (userpass)")
    ap.add_argument("--hop-password", default="", help="HY2 hop password")
    args = ap.parse_args()

    ensure_dir(CASCADE_DIR)
    node_id = str(uuid.uuid4())
    api_secret = secrets.token_urlsafe(48)
    issued_at = int(time.time())
    node_name = args.name.strip() or socket.gethostname()
    host = detect_host(args.host.strip())
    hy2_server = args.hy2_server.strip() or host
    hy2_sni = args.hy2_sni.strip() or hy2_server
    hop_username = args.hop_username.strip()
    hop_password = args.hop_password.strip()

    payload = {
        "node_id": node_id,
        "name": node_name,
        "host": host,
        "api_port": args.api_port,
        "api_secret": api_secret,
        "issued_at": issued_at,
        "role": "exit",
        "hy2_server": hy2_server,
        "hy2_sni": hy2_sni,
        "hy2_port": args.hy2_port,
        "hop_username": hop_username,
        "hop_password": hop_password,
    }
    payload["fingerprint"] = sha256_hex(f"{node_id}:{api_secret}:{host}:{args.api_port}")
    token = b64url_encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    save_json(
        REMOTE_NODE_JSON,
        {
            "node_id": node_id,
            "name": node_name,
            "host": host,
            "api_port": args.api_port,
            "api_secret": api_secret,
            "fingerprint": payload["fingerprint"],
            "issued_at": issued_at,
            "hy2_server": hy2_server,
            "hy2_sni": hy2_sni,
            "hy2_port": args.hy2_port,
            "hop_username": hop_username,
            "hop_password": hop_password,
        },
    )
    os.chmod(REMOTE_NODE_JSON, 0o600)

    print("=== CASCADE REMOTE NODE REGISTRATION ===")
    print(f"node_id      : {node_id}")
    print(f"name         : {node_name}")
    print(f"host         : {host}")
    print(f"api_port     : {args.api_port}")
    print(f"fingerprint  : {payload['fingerprint']}")
    print("")
    print("REGISTRATION_TOKEN (copy to master admin):")
    print(token)
    print("")
    print(f"saved: {REMOTE_NODE_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
