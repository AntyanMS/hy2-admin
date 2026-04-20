#!/usr/bin/env python3
from __future__ import annotations

import json
import secrets
import subprocess
import uuid
from pathlib import Path


CONFIG_PATH = Path("/etc/sing-box/config.json")
TAG = "in-vless-reality"


def gen_reality_keypair() -> tuple[str, str]:
    out = subprocess.check_output(
        ["/usr/bin/sing-box", "generate", "reality-keypair"], text=True
    )
    priv = pub = None
    for line in out.splitlines():
        s = line.strip()
        low = s.lower()
        if low.startswith("privatekey"):
            priv = s.split()[-1]
        elif low.startswith("publickey"):
            pub = s.split()[-1]
    if not priv or not pub:
        raise RuntimeError("Failed to parse sing-box reality-keypair output")
    return priv, pub


def main() -> int:
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    inbounds = cfg.get("inbounds") or []
    if not isinstance(inbounds, list):
        raise RuntimeError("Invalid config: inbounds is not a list")
    inbounds = [x for x in inbounds if not (isinstance(x, dict) and x.get("tag") == TAG)]

    priv, pub = gen_reality_keypair()
    user_uuid = str(uuid.uuid4())
    short_id = secrets.token_hex(8)  # 16 hex chars

    inbounds.append(
        {
            "type": "vless",
            "tag": TAG,
            "listen": "::",
            "listen_port": 443,
            "users": [{"uuid": user_uuid}],
            "tls": {
                "enabled": True,
                "server_name": "www.cloudflare.com",
                "reality": {
                    "enabled": True,
                    "handshake": {"server": "www.cloudflare.com", "server_port": 443},
                    "private_key": priv,
                    "short_id": [short_id],
                },
            },
        }
    )

    cfg["inbounds"] = inbounds
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Print values for the client
    print("UUID=" + user_uuid)
    print("PBK=" + pub)
    print("SID=" + short_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

