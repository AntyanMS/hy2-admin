#!/usr/bin/env python3
import json
from pathlib import Path

import yaml

HY_PATH = Path("/etc/hysteria/config.yaml")
SB_PATH = Path("/etc/sing-box/config.json")

hy_cfg = yaml.safe_load(HY_PATH.read_text(encoding="utf-8")) or {}
users_map = ((hy_cfg.get("auth") or {}).get("userpass") or {})
desired = [{"name": str(k), "password": str(v)} for k, v in users_map.items()]

sb_cfg = json.loads(SB_PATH.read_text(encoding="utf-8"))
inbounds = sb_cfg.get("inbounds") or []
changed = False
for ib in inbounds:
    if isinstance(ib, dict) and ib.get("tag") == "in-hy2":
        old = ib.get("users") or []
        if old != desired:
            ib["users"] = desired
            changed = True
        break

if changed:
    SB_PATH.write_text(json.dumps(sb_cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("updated users:", len(desired))
else:
    print("no changes")
