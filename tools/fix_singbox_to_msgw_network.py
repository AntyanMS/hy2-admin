#!/usr/bin/env python3
"""Remove network lock from sing-box hysteria2 outbound to-msgw (restore default udp+tcp)."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    p = Path("/etc/sing-box/config.json")
    cfg = json.loads(p.read_text(encoding="utf-8"))
    for ob in cfg.get("outbounds") or []:
        if isinstance(ob, dict) and ob.get("tag") == "to-msgw":
            ob.pop("network", None)
    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("removed network from to-msgw")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
