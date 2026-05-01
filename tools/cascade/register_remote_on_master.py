#!/usr/bin/env python3
"""
Запускать на master-узле. Добавляет удаленный узел в реестр каскада.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cascade_common import b64url_decode, load_json, save_json


CASCADE_DIR = Path("/opt/hy2-admin/data/cascade")
REMOTE_SERVERS_JSON = CASCADE_DIR / "remote_servers.json"


def parse_token(raw: str) -> dict:
    data = b64url_decode(raw.strip())
    return json.loads(data.decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Register remote cascade node on master")
    ap.add_argument("--token", required=True, help="Token from register_remote_node.py")
    ap.add_argument("--through", action="store_true", help="Mark as active cascade exit route")
    args = ap.parse_args()

    payload = parse_token(args.token)
    required = ("node_id", "name", "host", "api_port", "api_secret", "fingerprint", "issued_at", "role")
    missing = [k for k in required if k not in payload]
    if missing:
        raise SystemExit(f"invalid token: missing {', '.join(missing)}")

    db = load_json(REMOTE_SERVERS_JSON, {"servers": []})
    servers = db.get("servers") or []

    kept = [s for s in servers if s.get("node_id") != payload["node_id"]]
    payload["enabled"] = True
    payload["cascade_exit"] = bool(args.through)
    kept.append(payload)

    if args.through:
        for s in kept:
            if s.get("node_id") != payload["node_id"]:
                s["cascade_exit"] = False

    db["servers"] = kept
    save_json(REMOTE_SERVERS_JSON, db)

    print(f"saved: {REMOTE_SERVERS_JSON}")
    print(f"registered node: {payload['name']} ({payload['host']}:{payload['api_port']})")
    print(f"cascade_exit: {payload['cascade_exit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
