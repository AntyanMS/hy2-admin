#!/usr/bin/env python3
"""Включить sniff на всех inbounds sing-box (нужно для маршрутизации по domain / domain_suffix)."""
from __future__ import annotations

import json
from pathlib import Path

CONFIG = Path("/etc/sing-box/config.json")


def main() -> int:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    for ib in cfg.get("inbounds") or []:
        if not isinstance(ib, dict):
            continue
        ib["sniff"] = True
        ib["sniff_override_destination"] = True
    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("OK: sniff=true, sniff_override_destination=true on all inbounds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
